//! Core domain types for the WormVerify off-chain service.
//!
//! This crate is pure (no I/O). It defines VAA wire types, guardian identity,
//! quorum math, and strongly-typed newtypes for chain/emitter/sequence values.

#![forbid(unsafe_code)]

pub mod error;
pub mod guardian;
pub mod vaa;

pub use error::VaaError;
pub use guardian::{body_digest, keccak256, quorum, GuardianAddress, GUARDIAN_ADDRESS_LEN};
use serde::{Deserialize, Serialize};
pub use vaa::{
    recover_guardian, GuardianSignature, Vaa, VaaBody, BODY_HEADER_LEN, MAX_GUARDIANS,
    MAX_PAYLOAD_LEN, SIGNATURE_ENTRY_LEN, SUPPORTED_VERSION,
};

/// Wormhole chain identifier (e.g. Solana = 1).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct ChainId(pub u16);

/// Monotonic index of a guardian set version.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct GuardianSetIndex(pub u32);

/// Per-emitter monotonically increasing message sequence.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Sequence(pub u64);

/// A 32-byte emitter address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmitterAddress(pub [u8; 32]);

impl EmitterAddress {
    /// Renders the address as lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// A versioned set of guardians with an activation window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianSet {
    pub index: GuardianSetIndex,
    pub keys: Vec<GuardianAddress>,
    /// Unix timestamp at which this set expires; `0` means never.
    pub expiration_time: u64,
}

impl GuardianSet {
    /// Returns true if the set is usable at `now` (unix seconds).
    #[must_use]
    pub fn is_active(&self, now: u64) -> bool {
        self.expiration_time == 0 || now < self.expiration_time
    }

    /// Minimum signatures required for quorum in this set.
    #[must_use]
    pub fn quorum(&self) -> usize {
        quorum(self.keys.len())
    }
}
