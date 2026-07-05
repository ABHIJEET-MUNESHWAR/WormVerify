//! Wormhole VAA (Verifiable Action Approval) parsing, encoding, and
//! signature verification.
//!
//! Wire format:
//! ```text
//! header: version:u8 | guardian_set_index:u32 BE | num_sigs:u8
//!         num_sigs × (guardian_index:u8 | rs:64 | recovery_id:u8)
//! body:   timestamp:u32 BE | nonce:u32 BE | emitter_chain:u16 BE
//!         emitter_address:32 | sequence:u64 BE | consistency_level:u8 | payload
//! ```
//! The signing digest is `keccak256(keccak256(body))`.

use libsecp256k1::{recover, Message, RecoveryId, Signature};
use serde::{Deserialize, Serialize};

use crate::error::VaaError;
use crate::guardian::{body_digest, quorum, GuardianAddress};

/// Supported VAA version byte.
pub const SUPPORTED_VERSION: u8 = 1;
/// Encoded length of a single guardian signature entry.
pub const SIGNATURE_ENTRY_LEN: usize = 66;
/// Fixed portion of a VAA body preceding the variable-length payload.
pub const BODY_HEADER_LEN: usize = 51;
/// Maximum number of guardians a set may contain.
pub const MAX_GUARDIANS: usize = 19;
/// Maximum payload length accepted.
pub const MAX_PAYLOAD_LEN: usize = 1024;

/// A single guardian's signature over the VAA body digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianSignature {
    /// Index of the signing guardian within the guardian set.
    pub guardian_index: u8,
    /// 64-byte compact `r || s` signature.
    #[serde(with = "hex_array64")]
    pub rs: [u8; 64],
    /// secp256k1 recovery id (0 or 1).
    pub recovery_id: u8,
}

/// The signed portion of a VAA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaaBody {
    pub timestamp: u32,
    pub nonce: u32,
    pub emitter_chain: u16,
    #[serde(with = "hex_array32")]
    pub emitter_address: [u8; 32],
    pub sequence: u64,
    pub consistency_level: u8,
    #[serde(with = "hex_vec")]
    pub payload: Vec<u8>,
}

impl VaaBody {
    /// Serializes the body to its canonical byte encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BODY_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.emitter_chain.to_be_bytes());
        out.extend_from_slice(&self.emitter_address);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.push(self.consistency_level);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Returns the `keccak256(keccak256(body))` signing digest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        body_digest(&self.encode())
    }
}

/// A fully assembled VAA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vaa {
    pub version: u8,
    pub guardian_set_index: u32,
    pub signatures: Vec<GuardianSignature>,
    pub body: VaaBody,
}

impl Vaa {
    /// Serializes the VAA to its canonical wire encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.extend_from_slice(&self.guardian_set_index.to_be_bytes());
        out.push(self.signatures.len() as u8);
        for sig in &self.signatures {
            out.push(sig.guardian_index);
            out.extend_from_slice(&sig.rs);
            out.push(sig.recovery_id);
        }
        out.extend_from_slice(&self.body.encode());
        out
    }

    /// Parses a VAA from its wire encoding, enforcing structural invariants.
    pub fn parse(bytes: &[u8]) -> Result<Self, VaaError> {
        let mut cur = 0usize;
        let version = *bytes.first().ok_or(VaaError::Malformed)?;
        if version != SUPPORTED_VERSION {
            return Err(VaaError::UnsupportedVersion(version));
        }
        cur += 1;

        let gsi = read_u32(bytes, &mut cur)?;
        let num_sigs = *bytes.get(cur).ok_or(VaaError::Malformed)? as usize;
        cur += 1;

        let mut signatures = Vec::with_capacity(num_sigs);
        let mut last_index: Option<u8> = None;
        for _ in 0..num_sigs {
            let entry = bytes
                .get(cur..cur + SIGNATURE_ENTRY_LEN)
                .ok_or(VaaError::Malformed)?;
            let guardian_index = entry[0];
            if let Some(prev) = last_index {
                if guardian_index <= prev {
                    return Err(VaaError::SignaturesOutOfOrder);
                }
            }
            last_index = Some(guardian_index);
            let mut rs = [0u8; 64];
            rs.copy_from_slice(&entry[1..65]);
            signatures.push(GuardianSignature {
                guardian_index,
                rs,
                recovery_id: entry[65],
            });
            cur += SIGNATURE_ENTRY_LEN;
        }

        let body_bytes = bytes.get(cur..).ok_or(VaaError::Malformed)?;
        let body = parse_body(body_bytes)?;
        Ok(Self {
            version,
            guardian_set_index: gsi,
            signatures,
            body,
        })
    }

    /// Verifies that a quorum of valid guardian signatures over the body digest
    /// is present for the provided guardian set.
    pub fn verify(&self, guardians: &[GuardianAddress]) -> Result<(), VaaError> {
        if guardians.is_empty() {
            return Err(VaaError::EmptyGuardianSet);
        }
        let digest = self.body.digest();
        let msg = Message::parse(&digest);
        let mut valid = 0usize;
        let mut last_index: Option<u8> = None;

        for sig in &self.signatures {
            if let Some(prev) = last_index {
                if sig.guardian_index <= prev {
                    return Err(VaaError::SignaturesOutOfOrder);
                }
            }
            last_index = Some(sig.guardian_index);

            let expected = guardians
                .get(sig.guardian_index as usize)
                .ok_or(VaaError::GuardianIndexOutOfRange(sig.guardian_index))?;
            let recovered = recover_address(&msg, &sig.rs, sig.recovery_id)?;
            if &recovered != expected {
                return Err(VaaError::InvalidGuardianSignature(sig.guardian_index));
            }
            valid += 1;
        }

        let needed = quorum(guardians.len());
        if valid < needed {
            return Err(VaaError::QuorumNotMet { got: valid, needed });
        }
        Ok(())
    }
}

fn recover_address(
    msg: &Message,
    rs: &[u8; 64],
    recovery_id: u8,
) -> Result<GuardianAddress, VaaError> {
    let sig = Signature::parse_standard_slice(rs).map_err(|_| VaaError::RecoveryFailed)?;
    let rid = RecoveryId::parse(recovery_id).map_err(|_| VaaError::RecoveryFailed)?;
    let pubkey = recover(msg, &sig, &rid).map_err(|_| VaaError::RecoveryFailed)?;
    let ser = pubkey.serialize(); // 65 bytes: 0x04 || X || Y
    let mut pubkey64 = [0u8; 64];
    pubkey64.copy_from_slice(&ser[1..]);
    Ok(GuardianAddress::from_pubkey(&pubkey64))
}

/// Recovers the guardian address that produced `signature` over `digest`.
///
/// # Errors
/// Returns [`VaaError::RecoveryFailed`] if the signature is malformed or cannot
/// be recovered.
pub fn recover_guardian(
    digest: &[u8; 32],
    signature: &GuardianSignature,
) -> Result<GuardianAddress, VaaError> {
    let msg = Message::parse(digest);
    recover_address(&msg, &signature.rs, signature.recovery_id)
}

fn parse_body(bytes: &[u8]) -> Result<VaaBody, VaaError> {
    if bytes.len() < BODY_HEADER_LEN {
        return Err(VaaError::Malformed);
    }
    let mut cur = 0usize;
    let timestamp = read_u32(bytes, &mut cur)?;
    let nonce = read_u32(bytes, &mut cur)?;
    let emitter_chain = read_u16(bytes, &mut cur)?;
    let mut emitter_address = [0u8; 32];
    emitter_address.copy_from_slice(&bytes[cur..cur + 32]);
    cur += 32;
    let sequence = read_u64(bytes, &mut cur)?;
    let consistency_level = bytes[cur];
    cur += 1;
    let payload = bytes[cur..].to_vec();
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(VaaError::PayloadTooLarge {
            got: payload.len(),
            max: MAX_PAYLOAD_LEN,
        });
    }
    Ok(VaaBody {
        timestamp,
        nonce,
        emitter_chain,
        emitter_address,
        sequence,
        consistency_level,
        payload,
    })
}

fn read_u16(bytes: &[u8], cur: &mut usize) -> Result<u16, VaaError> {
    let slice = bytes.get(*cur..*cur + 2).ok_or(VaaError::Malformed)?;
    *cur += 2;
    Ok(u16::from_be_bytes(slice.try_into().unwrap()))
}

fn read_u32(bytes: &[u8], cur: &mut usize) -> Result<u32, VaaError> {
    let slice = bytes.get(*cur..*cur + 4).ok_or(VaaError::Malformed)?;
    *cur += 4;
    Ok(u32::from_be_bytes(slice.try_into().unwrap()))
}

fn read_u64(bytes: &[u8], cur: &mut usize) -> Result<u64, VaaError> {
    let slice = bytes.get(*cur..*cur + 8).ok_or(VaaError::Malformed)?;
    *cur += 8;
    Ok(u64::from_be_bytes(slice.try_into().unwrap()))
}

macro_rules! hex_fixed {
    ($mod:ident, $len:literal) => {
        mod $mod {
            use serde::{Deserialize, Deserializer, Serializer};
            pub fn serialize<S: Serializer>(b: &[u8; $len], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&hex::encode(b))
            }
            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $len], D::Error> {
                let s = String::deserialize(d)?;
                let v =
                    hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
                v.try_into()
                    .map_err(|_| serde::de::Error::custom("unexpected length"))
            }
        }
    };
}

hex_fixed!(hex_array32, 32);
hex_fixed!(hex_array64, 64);

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_body() -> VaaBody {
        VaaBody {
            timestamp: 1_700_000_000,
            nonce: 42,
            emitter_chain: 1,
            emitter_address: [7u8; 32],
            sequence: 99,
            consistency_level: 1,
            payload: b"hello wormhole".to_vec(),
        }
    }

    #[test]
    fn body_encode_len_matches_header_plus_payload() {
        let body = sample_body();
        assert_eq!(body.encode().len(), BODY_HEADER_LEN + body.payload.len());
    }

    #[test]
    fn vaa_round_trips_through_bytes() {
        let vaa = Vaa {
            version: SUPPORTED_VERSION,
            guardian_set_index: 3,
            signatures: vec![GuardianSignature {
                guardian_index: 0,
                rs: [1u8; 64],
                recovery_id: 0,
            }],
            body: sample_body(),
        };
        let bytes = vaa.encode();
        let parsed = Vaa::parse(&bytes).unwrap();
        assert_eq!(parsed, vaa);
    }

    #[test]
    fn parse_rejects_bad_version() {
        let err = Vaa::parse(&[9, 0, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, VaaError::UnsupportedVersion(9));
    }

    #[test]
    fn parse_rejects_unordered_signatures() {
        let vaa = Vaa {
            version: SUPPORTED_VERSION,
            guardian_set_index: 0,
            signatures: vec![
                GuardianSignature {
                    guardian_index: 2,
                    rs: [0u8; 64],
                    recovery_id: 0,
                },
                GuardianSignature {
                    guardian_index: 1,
                    rs: [0u8; 64],
                    recovery_id: 0,
                },
            ],
            body: sample_body(),
        };
        assert_eq!(
            Vaa::parse(&vaa.encode()).unwrap_err(),
            VaaError::SignaturesOutOfOrder
        );
    }

    #[test]
    fn verify_rejects_empty_guardian_set() {
        let vaa = Vaa {
            version: SUPPORTED_VERSION,
            guardian_set_index: 0,
            signatures: vec![],
            body: sample_body(),
        };
        assert_eq!(vaa.verify(&[]).unwrap_err(), VaaError::EmptyGuardianSet);
    }
}
