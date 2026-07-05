//! End-to-end verification tests using real secp256k1 signatures.

use libsecp256k1::{sign, Message, PublicKey, SecretKey};
use wormverify_types::guardian::GuardianAddress;
use wormverify_types::vaa::{GuardianSignature, Vaa, VaaBody, SUPPORTED_VERSION};
use wormverify_types::VaaError;

struct Guardian {
    sk: SecretKey,
    address: GuardianAddress,
}

impl Guardian {
    fn new(seed: u8) -> Self {
        let sk = SecretKey::parse(&[seed.max(1); 32]).expect("valid secret key");
        let pk = PublicKey::from_secret_key(&sk);
        let mut pubkey64 = [0u8; 64];
        pubkey64.copy_from_slice(&pk.serialize()[1..]);
        Self {
            sk,
            address: GuardianAddress::from_pubkey(&pubkey64),
        }
    }

    fn sign(&self, index: u8, digest: &[u8; 32]) -> GuardianSignature {
        let (sig, rid) = sign(&Message::parse(digest), &self.sk);
        GuardianSignature {
            guardian_index: index,
            rs: sig.serialize(),
            recovery_id: rid.serialize(),
        }
    }
}

fn body() -> VaaBody {
    VaaBody {
        timestamp: 1_700_000_000,
        nonce: 7,
        emitter_chain: 1,
        emitter_address: [3u8; 32],
        sequence: 12,
        consistency_level: 1,
        payload: b"transfer".to_vec(),
    }
}

fn guardian_set(n: usize) -> Vec<Guardian> {
    (0..n).map(|i| Guardian::new(i as u8 + 1)).collect()
}

fn addresses(gs: &[Guardian]) -> Vec<GuardianAddress> {
    gs.iter().map(|g| g.address).collect()
}

#[test]
fn quorum_of_real_signatures_verifies() {
    let gs = guardian_set(4); // quorum = 3
    let b = body();
    let digest = b.digest();
    let signatures = (0..3u8).map(|i| gs[i as usize].sign(i, &digest)).collect();
    let vaa = Vaa {
        version: SUPPORTED_VERSION,
        guardian_set_index: 0,
        signatures,
        body: b,
    };
    assert!(vaa.verify(&addresses(&gs)).is_ok());
}

#[test]
fn below_quorum_is_rejected() {
    let gs = guardian_set(4); // quorum = 3
    let b = body();
    let digest = b.digest();
    let signatures = (0..2u8).map(|i| gs[i as usize].sign(i, &digest)).collect();
    let vaa = Vaa {
        version: SUPPORTED_VERSION,
        guardian_set_index: 0,
        signatures,
        body: b,
    };
    assert!(matches!(
        vaa.verify(&addresses(&gs)),
        Err(VaaError::QuorumNotMet { got: 2, needed: 3 })
    ));
}

#[test]
fn signature_over_different_body_fails() {
    let gs = guardian_set(4);
    let wrong_digest = body().digest();
    let mut real = body();
    real.sequence = 9999; // signed digest no longer matches this body
    let signatures = (0..3u8)
        .map(|i| gs[i as usize].sign(i, &wrong_digest))
        .collect();
    let vaa = Vaa {
        version: SUPPORTED_VERSION,
        guardian_set_index: 0,
        signatures,
        body: real,
    };
    assert!(vaa.verify(&addresses(&gs)).is_err());
}

#[test]
fn foreign_guardian_signature_fails() {
    let gs = guardian_set(4);
    let outsider = Guardian::new(200);
    let b = body();
    let digest = b.digest();
    let mut signatures: Vec<_> = (0..2u8).map(|i| gs[i as usize].sign(i, &digest)).collect();
    signatures.push(outsider.sign(2, &digest)); // index 2 signed by non-member
    let vaa = Vaa {
        version: SUPPORTED_VERSION,
        guardian_set_index: 0,
        signatures,
        body: b,
    };
    assert!(matches!(
        vaa.verify(&addresses(&gs)),
        Err(VaaError::InvalidGuardianSignature(2))
    ));
}
