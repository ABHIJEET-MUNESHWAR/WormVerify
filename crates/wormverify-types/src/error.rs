//! Error types for VAA parsing and validation.

use thiserror::Error;

/// Errors produced while parsing or validating a VAA.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VaaError {
    #[error("VAA bytes are truncated or malformed")]
    Malformed,
    #[error("unsupported VAA version {0}")]
    UnsupportedVersion(u8),
    #[error("signatures must be strictly ordered by ascending guardian index")]
    SignaturesOutOfOrder,
    #[error("payload of {got} bytes exceeds the maximum of {max}")]
    PayloadTooLarge { got: usize, max: usize },
    #[error("guardian set is empty")]
    EmptyGuardianSet,
    #[error("a signature references guardian index {0} outside the set")]
    GuardianIndexOutOfRange(u8),
    #[error("secp256k1 signature recovery failed")]
    RecoveryFailed,
    #[error("a recovered signer is not the expected guardian at index {0}")]
    InvalidGuardianSignature(u8),
    #[error("only {got} valid signatures; quorum requires {needed}")]
    QuorumNotMet { got: usize, needed: usize },
    #[error("numeric overflow while parsing")]
    Overflow,
}
