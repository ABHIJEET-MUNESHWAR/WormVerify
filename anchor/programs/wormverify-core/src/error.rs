//! Program error codes for WormVerify.
//!
//! Each variant maps to a stable Anchor error code so off-chain clients can
//! branch on precise failure reasons rather than string-matching logs.

use anchor_lang::prelude::*;

#[error_code]
pub enum WormError {
    #[msg("VAA byte layout is malformed or truncated")]
    InvalidVaa,
    #[msg("VAA version is not supported by this program")]
    UnsupportedVersion,
    #[msg("VAA references a guardian set index this account does not match")]
    GuardianSetMismatch,
    #[msg("the referenced guardian set has expired")]
    GuardianSetExpired,
    #[msg("guardian set must contain at least one guardian")]
    EmptyGuardianSet,
    #[msg("guardian set exceeds the maximum supported size")]
    GuardianSetTooLarge,
    #[msg("a signature references a guardian index outside the set")]
    GuardianIndexOutOfRange,
    #[msg("signatures must be strictly ordered by ascending guardian index")]
    SignaturesOutOfOrder,
    #[msg("secp256k1 signature recovery failed")]
    RecoveryFailed,
    #[msg("a recovered signer does not match the expected guardian address")]
    InvalidGuardianSignature,
    #[msg("not enough valid guardian signatures to reach quorum")]
    QuorumNotMet,
    #[msg("this VAA has already been consumed (replay)")]
    VaaAlreadyConsumed,
    #[msg("payload exceeds the maximum supported length")]
    PayloadTooLarge,
    #[msg("signer is not the configured governance authority")]
    Unauthorized,
    #[msg("governance action targets a different chain")]
    InvalidGovernanceChain,
    #[msg("new guardian set index must be exactly one greater than the current")]
    InvalidGuardianSetIndex,
    #[msg("numeric conversion overflowed")]
    Overflow,
}
