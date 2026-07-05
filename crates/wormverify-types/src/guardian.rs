//! Guardian identity primitives: keccak hashing, Ethereum-style addresses,
//! and the Wormhole supermajority quorum.

use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

/// Length of an Ethereum-style guardian address.
pub const GUARDIAN_ADDRESS_LEN: usize = 20;

/// A guardian's Ethereum-style address: `keccak256(pubkey64)[12..]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GuardianAddress(#[serde(with = "hex_array20")] pub [u8; GUARDIAN_ADDRESS_LEN]);

impl GuardianAddress {
    /// Derives the address from an uncompressed 64-byte secp256k1 public key
    /// (without the `0x04` prefix).
    #[must_use]
    pub fn from_pubkey(pubkey: &[u8; 64]) -> Self {
        let digest = keccak256(pubkey);
        let mut addr = [0u8; GUARDIAN_ADDRESS_LEN];
        addr.copy_from_slice(&digest[32 - GUARDIAN_ADDRESS_LEN..]);
        Self(addr)
    }

    /// Renders the address as a `0x`-prefixed hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

/// Computes a single keccak256 digest.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

/// Computes the VAA signing digest: `keccak256(keccak256(body))`.
#[must_use]
pub fn body_digest(body: &[u8]) -> [u8; 32] {
    keccak256(&keccak256(body))
}

/// Returns the minimum number of guardian signatures for quorum
/// (`floor(2/3·N)+1`).
#[must_use]
pub fn quorum(num_guardians: usize) -> usize {
    (num_guardians * 2) / 3 + 1
}

/// Serde helper: encode `[u8; 20]` as a hex string.
mod hex_array20 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 20], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 20], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
        let arr: [u8; 20] = v
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 20 bytes"))?;
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_matches_supermajority() {
        assert_eq!(quorum(1), 1);
        assert_eq!(quorum(4), 3);
        assert_eq!(quorum(19), 13);
    }

    #[test]
    fn double_keccak_is_keccak_of_keccak() {
        let body = b"abc";
        assert_eq!(body_digest(body), keccak256(&keccak256(body)));
    }

    #[test]
    fn address_takes_last_20_bytes() {
        let pubkey = [0x11u8; 64];
        let expected = &keccak256(&pubkey)[12..];
        assert_eq!(&GuardianAddress::from_pubkey(&pubkey).0, expected);
    }

    #[test]
    fn address_hex_round_trips_via_serde() {
        let a = GuardianAddress([0xABu8; 20]);
        let json = serde_json::to_string(&a).unwrap();
        let back: GuardianAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}
