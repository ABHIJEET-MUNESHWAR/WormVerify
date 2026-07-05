//! End-to-end guardian-signature verification with *real* secp256k1 keys.
//!
//! This exercises the exact code path a validator runs: build a VAA body, take
//! its double-keccak digest, sign it with a quorum of guardian keys, encode the
//! canonical VAA, parse it, and verify the quorum via `secp256k1_recover`. It
//! proves the cryptography — not just the byte parsing — is correct.

use libsecp256k1::{Message, PublicKey, RecoveryId, SecretKey, Signature};
use wormverify_core::state::GuardianAddress;
use wormverify_core::vaa::{body_digest, GuardianSignature, ParsedVaa, SUPPORTED_VERSION};
use wormverify_core::verify::{guardian_address_from_pubkey, verify_quorum};

/// A guardian identity used to sign VAAs in tests.
struct Guardian {
    secret: SecretKey,
    address: GuardianAddress,
}

impl Guardian {
    /// Builds a deterministic guardian from a single seed byte.
    fn from_seed(seed: u8) -> Self {
        let mut bytes = [1u8; 32];
        bytes[31] = seed;
        let secret = SecretKey::parse(&bytes).expect("valid secret");
        let public = PublicKey::from_secret_key(&secret);
        // Uncompressed pubkey is 65 bytes with a 0x04 prefix; drop the prefix.
        let uncompressed = public.serialize();
        let mut xy = [0u8; 64];
        xy.copy_from_slice(&uncompressed[1..]);
        let address = guardian_address_from_pubkey(&xy);
        Self { secret, address }
    }

    /// Signs a 32-byte digest, returning the 64-byte r||s and recovery id.
    fn sign(&self, digest: &[u8; 32]) -> ([u8; 64], u8) {
        let message = Message::parse(digest);
        let (sig, rec): (Signature, RecoveryId) = libsecp256k1::sign(&message, &self.secret);
        (sig.serialize(), rec.serialize())
    }
}

/// Encodes a canonical VAA body (no header) for a given payload.
fn encode_body(emitter_chain: u16, sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // timestamp
    body.extend_from_slice(&7u32.to_be_bytes()); // nonce
    body.extend_from_slice(&emitter_chain.to_be_bytes());
    body.extend_from_slice(&[0xEE; 32]); // emitter address
    body.extend_from_slice(&sequence.to_be_bytes());
    body.push(1); // consistency level
    body.extend_from_slice(payload);
    body
}

/// Assembles a full VAA byte string from a body and a set of signatures.
fn encode_vaa(guardian_set_index: u32, signatures: &[GuardianSignature], body: &[u8]) -> Vec<u8> {
    let mut vaa = Vec::new();
    vaa.push(SUPPORTED_VERSION);
    vaa.extend_from_slice(&guardian_set_index.to_be_bytes());
    vaa.push(signatures.len() as u8);
    for s in signatures {
        vaa.push(s.guardian_index);
        vaa.extend_from_slice(&s.rs);
        vaa.push(s.recovery_id);
    }
    vaa.extend_from_slice(body);
    vaa
}

/// Signs `body`'s digest with the guardians at the given indices.
fn sign_with(guardians: &[Guardian], indices: &[u8], body: &[u8]) -> Vec<GuardianSignature> {
    let digest = body_digest(body);
    indices
        .iter()
        .map(|&i| {
            let (rs, recovery_id) = guardians[i as usize].sign(&digest);
            GuardianSignature {
                guardian_index: i,
                rs,
                recovery_id,
            }
        })
        .collect()
}

fn addresses(guardians: &[Guardian]) -> Vec<GuardianAddress> {
    guardians.iter().map(|g| g.address).collect()
}

#[test]
fn quorum_of_real_signatures_verifies() {
    let guardians: Vec<Guardian> = (0..4).map(Guardian::from_seed).collect();
    let keys = addresses(&guardians);
    let body = encode_body(2, 42, b"cross-chain-hello");

    // quorum(4) == 3
    let sigs = sign_with(&guardians, &[0, 1, 2], &body);
    let bytes = encode_vaa(0, &sigs, &body);
    let parsed = ParsedVaa::parse(&bytes).unwrap();

    verify_quorum(&parsed, &keys).expect("valid quorum must verify");
    assert_eq!(parsed.emitter_chain, 2);
    assert_eq!(parsed.sequence, 42);
    assert_eq!(parsed.payload, b"cross-chain-hello");
}

#[test]
fn below_quorum_is_rejected() {
    let guardians: Vec<Guardian> = (0..4).map(Guardian::from_seed).collect();
    let keys = addresses(&guardians);
    let body = encode_body(2, 1, b"x");

    // Only 2 of the required 3 signatures.
    let sigs = sign_with(&guardians, &[0, 1], &body);
    let bytes = encode_vaa(0, &sigs, &body);
    let parsed = ParsedVaa::parse(&bytes).unwrap();

    assert!(verify_quorum(&parsed, &keys).is_err());
}

#[test]
fn signature_over_different_body_fails() {
    let guardians: Vec<Guardian> = (0..4).map(Guardian::from_seed).collect();
    let keys = addresses(&guardians);
    let signed_body = encode_body(2, 1, b"original");
    let sigs = sign_with(&guardians, &[0, 1, 2], &signed_body);

    // Splice the valid signatures onto a tampered body; the digest no longer
    // matches, so recovery yields addresses outside the guardian set.
    let tampered_body = encode_body(2, 1, b"tampered");
    let bytes = encode_vaa(0, &sigs, &tampered_body);
    let parsed = ParsedVaa::parse(&bytes).unwrap();

    assert!(verify_quorum(&parsed, &keys).is_err());
}

#[test]
fn signature_from_foreign_guardian_fails() {
    let guardians: Vec<Guardian> = (0..4).map(Guardian::from_seed).collect();
    let keys = addresses(&guardians);
    let body = encode_body(2, 1, b"x");

    // An outsider signs but claims to be guardian index 2.
    let outsider = Guardian::from_seed(200);
    let digest = body_digest(&body);
    let (rs, recovery_id) = outsider.sign(&digest);
    let mut sigs = sign_with(&guardians, &[0, 1], &body);
    sigs.push(GuardianSignature {
        guardian_index: 2,
        rs,
        recovery_id,
    });

    let bytes = encode_vaa(0, &sigs, &body);
    let parsed = ParsedVaa::parse(&bytes).unwrap();
    assert!(verify_quorum(&parsed, &keys).is_err());
}
