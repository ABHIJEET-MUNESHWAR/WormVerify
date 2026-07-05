//! A simulated guardian set for local development, demos, and tests.
//!
//! Real Wormhole guardians run independent nodes with private keys. For a
//! self-contained deployment we deterministically derive a set of secp256k1
//! keys so the service can demonstrate end-to-end VAA assembly without external
//! guardians.

use libsecp256k1::{sign, Message, PublicKey, SecretKey};

use wormverify_types::{GuardianAddress, GuardianSet, GuardianSetIndex, GuardianSignature};

/// A deterministic in-process set of guardians able to sign digests.
pub struct SimulatedGuardians {
    index: u32,
    secret_keys: Vec<SecretKey>,
    addresses: Vec<GuardianAddress>,
}

impl SimulatedGuardians {
    /// Derives `count` guardians for the given set index. Keys are seeded
    /// deterministically from `seed_base` so runs are reproducible.
    ///
    /// # Panics
    /// Panics if `count` is zero or exceeds 254 (seed space).
    #[must_use]
    pub fn derive(index: u32, count: usize, seed_base: u8) -> Self {
        assert!(count > 0 && count < 255, "guardian count out of range");
        let mut secret_keys = Vec::with_capacity(count);
        let mut addresses = Vec::with_capacity(count);
        for i in 0..count {
            let mut seed = [0u8; 32];
            seed[0] = seed_base;
            seed[31] = (i as u8).wrapping_add(1);
            let sk = SecretKey::parse(&seed).expect("valid secret key");
            let pk = PublicKey::from_secret_key(&sk);
            let mut pubkey64 = [0u8; 64];
            pubkey64.copy_from_slice(&pk.serialize()[1..]);
            addresses.push(GuardianAddress::from_pubkey(&pubkey64));
            secret_keys.push(sk);
        }
        Self {
            index,
            secret_keys,
            addresses,
        }
    }

    /// Number of guardians in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secret_keys.len()
    }

    /// Whether the set is empty (always false via [`Self::derive`]).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secret_keys.is_empty()
    }

    /// Produces the public [`GuardianSet`] describing these guardians.
    #[must_use]
    pub fn guardian_set(&self) -> GuardianSet {
        GuardianSet {
            index: GuardianSetIndex(self.index),
            keys: self.addresses.clone(),
            expiration_time: 0,
        }
    }

    /// Signs `digest` as the guardian at `guardian_index`.
    ///
    /// # Errors
    /// Returns `None` if the index is out of range.
    #[must_use]
    pub fn sign(&self, guardian_index: u8, digest: &[u8; 32]) -> Option<GuardianSignature> {
        let sk = self.secret_keys.get(guardian_index as usize)?;
        let (sig, rid) = sign(&Message::parse(digest), sk);
        Some(GuardianSignature {
            guardian_index,
            rs: sig.serialize(),
            recovery_id: rid.serialize(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormverify_types::Vaa;

    #[test]
    fn derived_addresses_match_signatures() {
        let guardians = SimulatedGuardians::derive(0, 4, 7);
        assert_eq!(guardians.len(), 4);
        let set = guardians.guardian_set();
        let digest = [42u8; 32];
        let sig = guardians.sign(1, &digest).unwrap();
        let recovered = wormverify_types::recover_guardian(&digest, &sig).unwrap();
        assert_eq!(recovered, set.keys[1]);
    }

    #[test]
    fn quorum_of_simulated_guardians_produces_valid_vaa() {
        use wormverify_types::VaaBody;
        let guardians = SimulatedGuardians::derive(0, 4, 3);
        let set = guardians.guardian_set();
        let body = VaaBody {
            timestamp: 1,
            nonce: 1,
            emitter_chain: 1,
            emitter_address: [1u8; 32],
            sequence: 1,
            consistency_level: 1,
            payload: vec![1, 2, 3],
        };
        let digest = body.digest();
        let signatures = (0..3u8)
            .map(|i| guardians.sign(i, &digest).unwrap())
            .collect();
        let vaa = Vaa {
            version: wormverify_types::SUPPORTED_VERSION,
            guardian_set_index: 0,
            signatures,
            body,
        };
        assert!(vaa.verify(&set.keys).is_ok());
    }

    #[test]
    fn out_of_range_index_returns_none() {
        let guardians = SimulatedGuardians::derive(0, 2, 1);
        assert!(guardians.sign(5, &[0u8; 32]).is_none());
    }
}
