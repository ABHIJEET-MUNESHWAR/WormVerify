//! On-chain account state for WormVerify.

use anchor_lang::prelude::*;

use crate::vaa::MAX_GUARDIANS;

/// Length of an Ethereum-style guardian address (last 20 bytes of keccak256(pubkey)).
pub const GUARDIAN_ADDRESS_LEN: usize = 20;

/// A guardian address: `keccak256(uncompressed_secp256k1_pubkey[1..])[12..]`.
pub type GuardianAddress = [u8; GUARDIAN_ADDRESS_LEN];

/// Global program configuration and bridge identity.
#[account]
pub struct BridgeConfig {
    /// Governance authority allowed to submit guardian-set upgrades.
    pub governance_authority: Pubkey,
    /// The chain id this deployment represents (Solana == 1 in Wormhole).
    pub chain_id: u16,
    /// Index of the currently-active guardian set.
    pub current_guardian_set_index: u32,
    /// Seconds a superseded guardian set remains valid after rotation.
    pub guardian_set_ttl_seconds: u32,
    /// Monotonic sequence for messages emitted by this bridge's own emitter.
    pub emitter_sequence: u64,
    /// PDA bump.
    pub bump: u8,
}

impl BridgeConfig {
    pub const SPACE: usize = 8 + 32 + 2 + 4 + 4 + 8 + 1;
}

/// An immutable, indexed set of guardian addresses.
#[account]
pub struct GuardianSet {
    /// The set index (monotonically increasing across rotations).
    pub index: u32,
    /// The guardian Ethereum-style addresses.
    pub keys: Vec<GuardianAddress>,
    /// Unix time at which this set was created.
    pub creation_time: i64,
    /// Unix time after which this set is no longer valid (0 == never expires).
    pub expiration_time: i64,
    /// PDA bump.
    pub bump: u8,
}

impl GuardianSet {
    /// Worst-case account size for a full guardian set.
    pub const SPACE: usize = 8 + 4 + (4 + MAX_GUARDIANS * GUARDIAN_ADDRESS_LEN) + 8 + 8 + 1;

    /// Returns true if the set is still valid at `now`.
    #[must_use]
    pub fn is_active(&self, now: i64) -> bool {
        self.expiration_time == 0 || now < self.expiration_time
    }
}

/// A replay-protection marker created the first time a VAA is consumed.
///
/// Its PDA is seeded by the VAA digest, so a second attempt to consume the same
/// VAA fails at account initialization (the account already exists).
#[account]
pub struct ConsumedVaa {
    /// The digest that was consumed.
    pub hash: [u8; 32],
    /// The sequence carried by the consumed VAA (for auditing).
    pub sequence: u64,
    /// PDA bump.
    pub bump: u8,
}

impl ConsumedVaa {
    pub const SPACE: usize = 8 + 32 + 8 + 1;
}

/// A message posted (emitted) by a local program via this bridge.
#[account]
pub struct PostedMessage {
    /// The emitter (a program-derived signer of the posting instruction).
    pub emitter: Pubkey,
    /// Per-emitter sequence number assigned at post time.
    pub sequence: u64,
    /// Nonce chosen by the emitter.
    pub nonce: u32,
    /// Requested finality/consistency level.
    pub consistency_level: u8,
    /// Unix time the message was posted.
    pub submission_time: i64,
    /// The message payload.
    pub payload: Vec<u8>,
    /// PDA bump.
    pub bump: u8,
}

impl PostedMessage {
    /// Account size for a payload of `payload_len` bytes.
    #[must_use]
    pub fn space(payload_len: usize) -> usize {
        8 + 32 + 8 + 4 + 1 + 8 + (4 + payload_len) + 1
    }
}
