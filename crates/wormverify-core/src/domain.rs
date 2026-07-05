//! Domain entities and events for the aggregation core.

use serde::{Deserialize, Serialize};
use wormverify_types::{quorum, GuardianSignature, Vaa, VaaBody};

/// Identifier of an observed message: the `keccak256(keccak256(body))` digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub [u8; 32]);

impl MessageId {
    /// Computes the id from a VAA body.
    #[must_use]
    pub fn from_body(body: &VaaBody) -> Self {
        Self(body.digest())
    }

    /// Renders the id as lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses an id from a hex string.
    ///
    /// # Errors
    /// Returns an error if the input is not 32 hex-encoded bytes.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let bytes = hex::decode(s.trim_start_matches("0x")).map_err(|e| e.to_string())?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "expected 32 bytes".to_string())?;
        Ok(Self(arr))
    }
}

/// A message emitted on-chain and observed for guardian attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedMessage {
    pub id: MessageId,
    pub guardian_set_index: u32,
    pub body: VaaBody,
    /// Unix seconds at which the message was first observed.
    pub observed_at: i64,
}

/// A message accumulating guardian signatures until quorum is reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingObservation {
    pub message: ObservedMessage,
    /// Signatures held so far, kept sorted by ascending guardian index.
    pub signatures: Vec<GuardianSignature>,
    /// Number of guardians in the referenced set.
    pub guardian_count: usize,
}

impl PendingObservation {
    /// Creates an empty pending observation for a set of `guardian_count`.
    #[must_use]
    pub fn new(message: ObservedMessage, guardian_count: usize) -> Self {
        Self {
            message,
            signatures: Vec::new(),
            guardian_count,
        }
    }

    /// Minimum signatures required for quorum.
    #[must_use]
    pub fn quorum(&self) -> usize {
        quorum(self.guardian_count)
    }

    /// Whether quorum has been reached.
    #[must_use]
    pub fn quorum_reached(&self) -> bool {
        self.signatures.len() >= self.quorum()
    }

    /// True if the given guardian index already contributed a signature.
    #[must_use]
    pub fn has_guardian(&self, index: u8) -> bool {
        self.signatures.iter().any(|s| s.guardian_index == index)
    }

    /// Inserts a signature, keeping the vector sorted by guardian index.
    pub fn insert_sorted(&mut self, sig: GuardianSignature) {
        let pos = self
            .signatures
            .binary_search_by_key(&sig.guardian_index, |s| s.guardian_index)
            .unwrap_or_else(|e| e);
        self.signatures.insert(pos, sig);
    }
}

/// A completed, quorum-backed VAA record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaaRecord {
    pub id: MessageId,
    pub vaa: Vaa,
    /// Unix seconds at which quorum was reached.
    pub assembled_at: i64,
}

/// Events emitted as the aggregation state advances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainEvent {
    /// A new message was observed and is awaiting signatures.
    MessageObserved { id: MessageId },
    /// A valid guardian signature was collected.
    SignatureCollected {
        id: MessageId,
        guardian_index: u8,
        have: usize,
        needed: usize,
    },
    /// Quorum was reached and a VAA was assembled.
    VaaAssembled { id: MessageId },
}
