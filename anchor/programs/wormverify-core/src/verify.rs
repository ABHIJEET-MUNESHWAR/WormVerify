//! secp256k1 guardian-signature verification.
//!
//! Each guardian signs `keccak256(keccak256(body))` with an ECDSA secp256k1
//! key. We recover the signing public key with the SVM `secp256k1_recover`
//! syscall, derive its Ethereum-style address, and compare it to the address
//! stored in the guardian set. Reaching a `floor(2/3 N)+1` quorum of *distinct*
//! guardian signatures authenticates the VAA.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;
use anchor_lang::solana_program::secp256k1_recover::secp256k1_recover;

use crate::error::WormError;
use crate::state::{GuardianAddress, GUARDIAN_ADDRESS_LEN};
use crate::vaa::{quorum, ParsedVaa};

/// Derives the 20-byte Ethereum-style address from an uncompressed
/// secp256k1 public key (64 bytes, without the `0x04` prefix).
#[must_use]
pub fn guardian_address_from_pubkey(pubkey: &[u8; 64]) -> GuardianAddress {
    let digest = keccak::hash(pubkey).to_bytes();
    let mut addr = [0u8; GUARDIAN_ADDRESS_LEN];
    addr.copy_from_slice(&digest[32 - GUARDIAN_ADDRESS_LEN..]);
    addr
}

/// Recovers the guardian address that produced one signature over `hash`.
fn recover_address(hash: &[u8; 32], rs: &[u8; 64], recovery_id: u8) -> Result<GuardianAddress> {
    // secp256k1_recover rejects recovery ids > 1 and high-S malleable sigs.
    let pubkey = secp256k1_recover(hash, recovery_id, rs).map_err(|_| WormError::RecoveryFailed)?;
    Ok(guardian_address_from_pubkey(&pubkey.to_bytes()))
}

/// Verifies that a parsed VAA carries a quorum of valid, in-set guardian
/// signatures over its digest.
///
/// Invariants enforced:
/// * every signature's `guardian_index` is within the set,
/// * each recovered address matches the guardian at that index,
/// * signatures are already strictly ordered (checked at parse time), so no
///   guardian can be double-counted,
/// * the count of valid signatures meets the supermajority quorum.
pub fn verify_quorum(vaa: &ParsedVaa, guardian_keys: &[GuardianAddress]) -> Result<()> {
    require!(!guardian_keys.is_empty(), WormError::EmptyGuardianSet);
    let needed = quorum(guardian_keys.len());

    let mut valid = 0usize;
    for sig in &vaa.signatures {
        let idx = sig.guardian_index as usize;
        let expected = guardian_keys
            .get(idx)
            .ok_or(WormError::GuardianIndexOutOfRange)?;
        let recovered = recover_address(&vaa.hash, &sig.rs, sig.recovery_id)?;
        require!(&recovered == expected, WormError::InvalidGuardianSignature);
        valid += 1;
    }

    require!(valid >= needed, WormError::QuorumNotMet);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_derivation_takes_last_20_bytes() {
        let pubkey = [0xABu8; 64];
        let expected = &keccak::hash(&pubkey).to_bytes()[12..];
        assert_eq!(&guardian_address_from_pubkey(&pubkey), expected);
    }
}
