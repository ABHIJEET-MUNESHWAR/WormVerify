//! WormVerify — an on-chain Wormhole-style verification core for Solana.
//!
//! This program implements the security-critical heart of a cross-chain bridge:
//!
//! * **Guardian sets** — indexed, immutable sets of Ethereum-style guardian
//!   addresses, with monotonic rotation and TTL-based expiry of superseded sets.
//! * **VAA verification** — parses a canonical Wormhole VAA, recovers each
//!   guardian signature with `secp256k1_recover`, and requires a
//!   `floor(2/3 N)+1` supermajority quorum over `keccak256(keccak256(body))`.
//! * **Replay protection** — the first successful verification of a VAA creates
//!   a PDA seeded by the VAA digest; a replayed VAA fails at account init.
//! * **Message emission** — local programs post outbound messages that off-chain
//!   guardians observe, with per-emitter monotonic sequence numbers.
//! * **Governance** — the configured authority rotates the guardian set.
//!
//! The cryptographic and parsing logic lives in [`vaa`] and [`verify`] so it can
//! be unit-tested without a validator; the instruction handlers below are thin
//! orchestration over that logic plus Anchor account constraints.

use anchor_lang::prelude::*;

pub mod error;
pub mod state;
pub mod vaa;
pub mod verify;

use crate::error::WormError;
use crate::state::{BridgeConfig, ConsumedVaa, GuardianAddress, GuardianSet, PostedMessage};
use crate::vaa::{ParsedVaa, MAX_GUARDIANS, MAX_PAYLOAD_LEN};
use crate::verify::verify_quorum;

declare_id!("9uAEX36Z8sGSFduzHdhBAx185GGpBxCafZ5XSQ8yxBF6");

/// Per-emitter monotonic sequence tracker.
#[account]
pub struct EmitterSequence {
    /// The emitter this counter belongs to.
    pub emitter: Pubkey,
    /// The next sequence number to assign.
    pub sequence: u64,
    /// PDA bump.
    pub bump: u8,
}

impl EmitterSequence {
    pub const SPACE: usize = 8 + 32 + 8 + 1;
}

#[program]
pub mod wormverify_core {
    use super::*;

    /// Initializes the bridge config and the genesis guardian set.
    pub fn initialize(
        ctx: Context<Initialize>,
        chain_id: u16,
        guardian_set_ttl_seconds: u32,
        guardian_set_index: u32,
        initial_guardians: Vec<GuardianAddress>,
    ) -> Result<()> {
        require!(!initial_guardians.is_empty(), WormError::EmptyGuardianSet);
        require!(
            initial_guardians.len() <= MAX_GUARDIANS,
            WormError::GuardianSetTooLarge
        );

        let now = Clock::get()?.unix_timestamp;

        let config = &mut ctx.accounts.config;
        config.governance_authority = ctx.accounts.governance_authority.key();
        config.chain_id = chain_id;
        config.current_guardian_set_index = guardian_set_index;
        config.guardian_set_ttl_seconds = guardian_set_ttl_seconds;
        config.emitter_sequence = 0;
        config.bump = ctx.bumps.config;

        let set = &mut ctx.accounts.guardian_set;
        set.index = guardian_set_index;
        set.keys = initial_guardians;
        set.creation_time = now;
        set.expiration_time = 0; // active set never expires until superseded
        set.bump = ctx.bumps.guardian_set;

        Ok(())
    }

    /// Posts (emits) an outbound message with a per-emitter monotonic sequence.
    pub fn post_message(
        ctx: Context<PostMessage>,
        nonce: u32,
        consistency_level: u8,
        payload: Vec<u8>,
    ) -> Result<()> {
        require!(payload.len() <= MAX_PAYLOAD_LEN, WormError::PayloadTooLarge);
        let now = Clock::get()?.unix_timestamp;

        let tracker = &mut ctx.accounts.emitter_sequence;
        // Initialize the tracker on first use.
        if tracker.emitter == Pubkey::default() {
            tracker.emitter = ctx.accounts.emitter.key();
            tracker.bump = ctx.bumps.emitter_sequence;
        }
        let sequence = tracker.sequence;

        let message = &mut ctx.accounts.message;
        message.emitter = ctx.accounts.emitter.key();
        message.sequence = sequence;
        message.nonce = nonce;
        message.consistency_level = consistency_level;
        message.submission_time = now;
        message.payload = payload;
        message.bump = ctx.bumps.message;

        tracker.sequence = sequence.checked_add(1).ok_or(WormError::Overflow)?;

        emit!(MessagePosted {
            emitter: message.emitter,
            sequence,
            nonce,
        });
        Ok(())
    }

    /// Verifies a VAA against a guardian set and marks it consumed (replay-safe).
    ///
    /// `guardian_set_index` and `vaa_hash` are passed explicitly so they can seed
    /// the guardian-set and replay PDAs; the handler re-derives both from the raw
    /// bytes and rejects any mismatch, so a caller cannot point the instruction at
    /// the wrong set or a forged hash.
    pub fn verify_vaa(
        ctx: Context<VerifyVaa>,
        guardian_set_index: u32,
        vaa_hash: [u8; 32],
        vaa_bytes: Vec<u8>,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let parsed = ParsedVaa::parse(&vaa_bytes)?;

        require!(
            parsed.guardian_set_index == guardian_set_index,
            WormError::GuardianSetMismatch
        );
        require!(parsed.hash == vaa_hash, WormError::InvalidVaa);

        let set = &ctx.accounts.guardian_set;
        require!(
            set.index == guardian_set_index,
            WormError::GuardianSetMismatch
        );
        require!(set.is_active(now), WormError::GuardianSetExpired);

        verify_quorum(&parsed, &set.keys)?;

        let consumed = &mut ctx.accounts.consumed;
        consumed.hash = parsed.hash;
        consumed.sequence = parsed.sequence;
        consumed.bump = ctx.bumps.consumed;

        emit!(VaaVerified {
            emitter_chain: parsed.emitter_chain,
            emitter_address: parsed.emitter_address,
            sequence: parsed.sequence,
            hash: parsed.hash,
        });
        Ok(())
    }

    /// Rotates the guardian set. Only the governance authority may call this.
    ///
    /// The new set index must be exactly one greater than the current index; the
    /// previous set is given a bounded expiry window so in-flight VAAs signed by
    /// it remain verifiable for `guardian_set_ttl_seconds`.
    pub fn upgrade_guardian_set(
        ctx: Context<UpgradeGuardianSet>,
        new_index: u32,
        new_guardians: Vec<GuardianAddress>,
    ) -> Result<()> {
        require!(!new_guardians.is_empty(), WormError::EmptyGuardianSet);
        require!(
            new_guardians.len() <= MAX_GUARDIANS,
            WormError::GuardianSetTooLarge
        );

        let config = &mut ctx.accounts.config;
        require!(
            new_index == config.current_guardian_set_index + 1,
            WormError::InvalidGuardianSetIndex
        );

        let now = Clock::get()?.unix_timestamp;

        // Expire the outgoing set after the TTL window.
        let old = &mut ctx.accounts.old_guardian_set;
        old.expiration_time = now
            .checked_add(i64::from(config.guardian_set_ttl_seconds))
            .ok_or(WormError::Overflow)?;

        let new_set = &mut ctx.accounts.new_guardian_set;
        let size = new_guardians.len() as u8;
        new_set.index = new_index;
        new_set.keys = new_guardians;
        new_set.creation_time = now;
        new_set.expiration_time = 0;
        new_set.bump = ctx.bumps.new_guardian_set;

        config.current_guardian_set_index = new_index;

        emit!(GuardianSetUpgraded {
            old_index: new_index - 1,
            new_index,
            size,
        });
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(chain_id: u16, guardian_set_ttl_seconds: u32, guardian_set_index: u32)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: recorded as the governance authority; no data is read.
    pub governance_authority: UncheckedAccount<'info>,
    #[account(
        init,
        payer = payer,
        space = BridgeConfig::SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, BridgeConfig>,
    #[account(
        init,
        payer = payer,
        space = GuardianSet::SPACE,
        seeds = [b"guardian_set".as_ref(), &guardian_set_index.to_le_bytes()],
        bump
    )]
    pub guardian_set: Account<'info, GuardianSet>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nonce: u32, consistency_level: u8, payload: Vec<u8>)]
pub struct PostMessage<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// The emitter authority (may be a program via CPI-signed PDA).
    pub emitter: Signer<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        space = EmitterSequence::SPACE,
        seeds = [b"emitter".as_ref(), emitter.key().as_ref()],
        bump
    )]
    pub emitter_sequence: Account<'info, EmitterSequence>,
    #[account(
        init,
        payer = payer,
        space = PostedMessage::space(payload.len()),
        seeds = [b"message".as_ref(), emitter.key().as_ref(), &emitter_sequence.sequence.to_le_bytes()],
        bump
    )]
    pub message: Account<'info, PostedMessage>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(guardian_set_index: u32, vaa_hash: [u8; 32])]
pub struct VerifyVaa<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, BridgeConfig>,
    #[account(
        seeds = [b"guardian_set".as_ref(), &guardian_set_index.to_le_bytes()],
        bump = guardian_set.bump
    )]
    pub guardian_set: Account<'info, GuardianSet>,
    #[account(
        init,
        payer = payer,
        space = ConsumedVaa::SPACE,
        seeds = [b"consumed".as_ref(), vaa_hash.as_ref()],
        bump
    )]
    pub consumed: Account<'info, ConsumedVaa>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(new_index: u32)]
pub struct UpgradeGuardianSet<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        constraint = governance_authority.key() == config.governance_authority @ WormError::Unauthorized
    )]
    pub governance_authority: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, BridgeConfig>,
    #[account(
        mut,
        seeds = [b"guardian_set".as_ref(), &config.current_guardian_set_index.to_le_bytes()],
        bump = old_guardian_set.bump
    )]
    pub old_guardian_set: Account<'info, GuardianSet>,
    #[account(
        init,
        payer = payer,
        space = GuardianSet::SPACE,
        seeds = [b"guardian_set".as_ref(), &new_index.to_le_bytes()],
        bump
    )]
    pub new_guardian_set: Account<'info, GuardianSet>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct MessagePosted {
    pub emitter: Pubkey,
    pub sequence: u64,
    pub nonce: u32,
}

#[event]
pub struct VaaVerified {
    pub emitter_chain: u16,
    pub emitter_address: [u8; 32],
    pub sequence: u64,
    pub hash: [u8; 32],
}

#[event]
pub struct GuardianSetUpgraded {
    pub old_index: u32,
    pub new_index: u32,
    pub size: u8,
}
