//! Wormhole-format VAA (Verified Action Approval) parsing, hashing, and quorum.
//!
//! This module is deliberately free of Anchor account types so it can be unit
//! tested in isolation and reused by CPI callers. The wire format mirrors the
//! canonical Wormhole VAA:
//!
//! ```text
//! header:
//!   version            u8
//!   guardian_set_index u32 (big-endian)
//!   num_signatures     u8
//!   signatures         num_signatures * (guardian_index u8 || rs [u8;64] || recovery_id u8)
//! body (hashed):
//!   timestamp          u32 (big-endian)
//!   nonce              u32 (big-endian)
//!   emitter_chain      u16 (big-endian)
//!   emitter_address    [u8;32]
//!   sequence           u64 (big-endian)
//!   consistency_level  u8
//!   payload            variable
//! ```
//!
//! The message signed by each guardian is `keccak256(keccak256(body))` — the
//! double hash is what makes the digest domain-separated from the raw body.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;

use crate::error::WormError;

/// Only VAA version 1 is supported.
pub const SUPPORTED_VERSION: u8 = 1;

/// Fixed size (in bytes) of one encoded guardian signature entry.
pub const SIGNATURE_ENTRY_LEN: usize = 1 + 64 + 1;

/// Byte length of the fixed portion of the VAA body (everything but payload).
pub const BODY_HEADER_LEN: usize = 4 + 4 + 2 + 32 + 8 + 1;

/// Maximum guardians we will ever hold in a set (bounds account size & CU).
pub const MAX_GUARDIANS: usize = 19;

/// Maximum accepted payload length (bounds compute and account rent).
pub const MAX_PAYLOAD_LEN: usize = 1024;

/// One guardian signature over the VAA digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardianSignature {
    /// Index of the signing guardian within its guardian set.
    pub guardian_index: u8,
    /// The 64-byte `r || s` ECDSA signature.
    pub rs: [u8; 64],
    /// The recovery id (0 or 1) used by `secp256k1_recover`.
    pub recovery_id: u8,
}

/// A fully parsed VAA borrowing its payload from the input buffer.
#[derive(Clone, Debug)]
pub struct ParsedVaa<'a> {
    pub version: u8,
    pub guardian_set_index: u32,
    pub signatures: Vec<GuardianSignature>,
    pub timestamp: u32,
    pub nonce: u32,
    pub emitter_chain: u16,
    pub emitter_address: [u8; 32],
    pub sequence: u64,
    pub consistency_level: u8,
    pub payload: &'a [u8],
    /// `keccak256(keccak256(body))` — the digest guardians actually sign.
    pub hash: [u8; 32],
}

/// Returns the minimum number of guardian signatures required for quorum.
///
/// Wormhole uses a `floor(2/3 * N) + 1` supermajority. For `N = 19` this is 13.
#[must_use]
pub fn quorum(num_guardians: usize) -> usize {
    (num_guardians * 2) / 3 + 1
}

/// Computes the double-keccak digest over an already-isolated body slice.
#[must_use]
pub fn body_digest(body: &[u8]) -> [u8; 32] {
    let first = keccak::hash(body);
    keccak::hash(first.as_ref()).to_bytes()
}

/// Reads a big-endian `u16` at `offset`, advancing nothing.
fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let slice = data.get(offset..offset + 2).ok_or(WormError::InvalidVaa)?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

/// Reads a big-endian `u32` at `offset`.
fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let slice = data.get(offset..offset + 4).ok_or(WormError::InvalidVaa)?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Reads a big-endian `u64` at `offset`.
fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let slice = data.get(offset..offset + 8).ok_or(WormError::InvalidVaa)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(slice);
    Ok(u64::from_be_bytes(buf))
}

impl<'a> ParsedVaa<'a> {
    /// Parses and structurally validates a VAA, computing its signing digest.
    ///
    /// This performs *no* cryptographic verification — it only guarantees the
    /// bytes are well-formed and signatures are strictly ordered by ascending
    /// guardian index (which prevents duplicate-signature quorum inflation).
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let version = *data.first().ok_or(WormError::InvalidVaa)?;
        require!(version == SUPPORTED_VERSION, WormError::UnsupportedVersion);

        let guardian_set_index = read_u32(data, 1)?;
        let num_signatures = *data.get(5).ok_or(WormError::InvalidVaa)? as usize;

        let sigs_start = 6usize;
        let body_start = sigs_start
            .checked_add(num_signatures * SIGNATURE_ENTRY_LEN)
            .ok_or(WormError::Overflow)?;
        require!(data.len() >= body_start, WormError::InvalidVaa);

        let mut signatures = Vec::with_capacity(num_signatures);
        let mut last_index: Option<u8> = None;
        for i in 0..num_signatures {
            let base = sigs_start + i * SIGNATURE_ENTRY_LEN;
            let guardian_index = data[base];
            if let Some(prev) = last_index {
                require!(guardian_index > prev, WormError::SignaturesOutOfOrder);
            }
            last_index = Some(guardian_index);

            let mut rs = [0u8; 64];
            rs.copy_from_slice(&data[base + 1..base + 65]);
            let recovery_id = data[base + 65];
            signatures.push(GuardianSignature {
                guardian_index,
                rs,
                recovery_id,
            });
        }

        let body = data.get(body_start..).ok_or(WormError::InvalidVaa)?;
        require!(body.len() >= BODY_HEADER_LEN, WormError::InvalidVaa);

        let timestamp = read_u32(body, 0)?;
        let nonce = read_u32(body, 4)?;
        let emitter_chain = read_u16(body, 8)?;
        let mut emitter_address = [0u8; 32];
        emitter_address.copy_from_slice(&body[10..42]);
        let sequence = read_u64(body, 42)?;
        let consistency_level = body[50];
        let payload = &body[BODY_HEADER_LEN..];
        require!(payload.len() <= MAX_PAYLOAD_LEN, WormError::PayloadTooLarge);

        let hash = body_digest(body);

        Ok(Self {
            version,
            guardian_set_index,
            signatures,
            timestamp,
            nonce,
            emitter_chain,
            emitter_address,
            sequence,
            consistency_level,
            payload,
            hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a minimal, signature-free VAA body for hashing/parsing tests.
    fn encode_vaa(
        guardian_set_index: u32,
        sigs: &[GuardianSignature],
        emitter_chain: u16,
        sequence: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(SUPPORTED_VERSION);
        v.extend_from_slice(&guardian_set_index.to_be_bytes());
        v.push(sigs.len() as u8);
        for s in sigs {
            v.push(s.guardian_index);
            v.extend_from_slice(&s.rs);
            v.push(s.recovery_id);
        }
        // body
        v.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        v.extend_from_slice(&0u32.to_be_bytes()); // nonce
        v.extend_from_slice(&emitter_chain.to_be_bytes());
        v.extend_from_slice(&[9u8; 32]); // emitter address
        v.extend_from_slice(&sequence.to_be_bytes());
        v.push(1); // consistency level
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn quorum_matches_wormhole_supermajority() {
        assert_eq!(quorum(1), 1);
        assert_eq!(quorum(3), 3);
        assert_eq!(quorum(4), 3);
        assert_eq!(quorum(19), 13);
    }

    #[test]
    fn parse_round_trips_fields() {
        let sig = GuardianSignature {
            guardian_index: 0,
            rs: [7u8; 64],
            recovery_id: 1,
        };
        let bytes = encode_vaa(5, &[sig], 2, 42, b"hello");
        let vaa = ParsedVaa::parse(&bytes).unwrap();
        assert_eq!(vaa.guardian_set_index, 5);
        assert_eq!(vaa.emitter_chain, 2);
        assert_eq!(vaa.sequence, 42);
        assert_eq!(vaa.payload, b"hello");
        assert_eq!(vaa.signatures.len(), 1);
    }

    #[test]
    fn parse_rejects_unsorted_signatures() {
        let a = GuardianSignature {
            guardian_index: 3,
            rs: [1u8; 64],
            recovery_id: 0,
        };
        let b = GuardianSignature {
            guardian_index: 1,
            rs: [2u8; 64],
            recovery_id: 0,
        };
        let bytes = encode_vaa(0, &[a, b], 1, 1, b"x");
        assert!(ParsedVaa::parse(&bytes).is_err());
    }

    #[test]
    fn parse_rejects_truncated_input() {
        let bytes = vec![SUPPORTED_VERSION, 0, 0, 0];
        assert!(ParsedVaa::parse(&bytes).is_err());
    }

    #[test]
    fn digest_is_double_keccak() {
        let body = b"body-bytes";
        let first = keccak::hash(body);
        let expected = keccak::hash(first.as_ref()).to_bytes();
        assert_eq!(body_digest(body), expected);
    }
}
