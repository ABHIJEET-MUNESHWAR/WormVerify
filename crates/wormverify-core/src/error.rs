//! Engine error types.

use thiserror::Error;
use wormverify_types::VaaError;

/// Errors produced by the aggregation engine and its ports.
#[derive(Debug, Error)]
pub enum EngineError {
    /// A storage/registry adapter failed. Carries an opaque description.
    #[error("storage error: {0}")]
    Store(String),
    /// No pending observation exists for the referenced message.
    #[error("message has not been observed")]
    MessageNotObserved,
    /// The guardian set for the message could not be resolved.
    #[error("guardian set is unavailable")]
    GuardianSetUnavailable,
    /// A signature referenced a guardian index outside the active set.
    #[error("guardian index {0} is out of range for the active set")]
    GuardianIndexOutOfRange(u8),
    /// A signature did not recover to the expected guardian address.
    #[error("signature from guardian {0} is invalid")]
    InvalidSignature(u8),
    /// A guardian submitted a second signature for the same message.
    #[error("guardian {0} has already signed this message")]
    DuplicateSignature(u8),
    /// The assembled VAA failed final verification.
    #[error(transparent)]
    Vaa(#[from] VaaError),
    /// The message already has a completed VAA.
    #[error("a VAA has already been assembled for this message")]
    AlreadyCompleted,
}
