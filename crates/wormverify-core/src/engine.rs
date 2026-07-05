//! The VAA aggregation engine: observe messages, collect and validate guardian
//! signatures, and assemble a verified VAA once quorum is reached.

use std::sync::Arc;

use tracing::{debug, info, instrument};
use wormverify_types::{
    recover_guardian, GuardianSetIndex, GuardianSignature, Vaa, VaaBody, SUPPORTED_VERSION,
};

use crate::domain::{DomainEvent, MessageId, ObservedMessage, PendingObservation, VaaRecord};
use crate::error::EngineError;
use crate::ports::{EventSink, GuardianRegistry, MessageStore, VaaStore};

/// Outcome of submitting a guardian signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Signature accepted; quorum not yet reached.
    Collected { have: usize, needed: usize },
    /// Quorum reached; a VAA was assembled and stored.
    Assembled(Box<Vaa>),
}

/// Aggregate statistics for observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineStats {
    pub pending: usize,
    pub completed: u64,
}

/// Provides the current unix timestamp. Injected so the engine stays testable.
pub trait UnixClock: Send + Sync {
    /// Current unix time in seconds.
    fn unix_seconds(&self) -> i64;
}

/// Wall-clock implementation backed by the system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct WallClock;

impl UnixClock for WallClock {
    fn unix_seconds(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
}

/// Orchestrates observation, signature aggregation, and VAA assembly.
pub struct AggregatorEngine<M, V, G, E> {
    messages: Arc<M>,
    vaas: Arc<V>,
    guardians: Arc<G>,
    events: Arc<E>,
    clock: Arc<dyn UnixClock>,
}

impl<M, V, G, E> AggregatorEngine<M, V, G, E>
where
    M: MessageStore,
    V: VaaStore,
    G: GuardianRegistry,
    E: EventSink,
{
    /// Builds an engine from its ports and a clock.
    pub fn new(
        messages: Arc<M>,
        vaas: Arc<V>,
        guardians: Arc<G>,
        events: Arc<E>,
        clock: Arc<dyn UnixClock>,
    ) -> Self {
        Self {
            messages,
            vaas,
            guardians,
            events,
            clock,
        }
    }

    /// Registers a newly observed on-chain message for attestation.
    ///
    /// Returns the message id. If the message was already observed the existing
    /// id is returned idempotently.
    ///
    /// # Errors
    /// Fails if the guardian set is unavailable or a store operation fails.
    #[instrument(skip(self, body), fields(seq = body.sequence, chain = body.emitter_chain))]
    pub async fn observe_message(
        &self,
        guardian_set_index: u32,
        body: VaaBody,
    ) -> Result<MessageId, EngineError> {
        let id = MessageId::from_body(&body);

        if self.vaas.get(&id).await?.is_some() {
            return Err(EngineError::AlreadyCompleted);
        }
        if self.messages.get_pending(&id).await?.is_some() {
            return Ok(id);
        }

        let set = self
            .guardians
            .get(GuardianSetIndex(guardian_set_index))
            .await?
            .ok_or(EngineError::GuardianSetUnavailable)?;

        let message = ObservedMessage {
            id,
            guardian_set_index,
            body,
            observed_at: self.clock.unix_seconds(),
        };
        let pending = PendingObservation::new(message, set.keys.len());
        self.messages.upsert_pending(pending).await?;
        self.events
            .publish(DomainEvent::MessageObserved { id })
            .await;
        info!(id = %id.to_hex(), "message observed");
        Ok(id)
    }

    /// Submits a guardian signature for an observed message.
    ///
    /// The signature is verified against the message's guardian set before being
    /// accepted. When quorum is reached the VAA is assembled, verified, stored,
    /// and the pending observation is cleared.
    ///
    /// # Errors
    /// Fails on unknown message, invalid/duplicate signatures, out-of-range
    /// guardian index, or store errors.
    #[instrument(skip(self, signature), fields(guardian = signature.guardian_index))]
    pub async fn submit_signature(
        &self,
        id: MessageId,
        signature: GuardianSignature,
    ) -> Result<SubmitOutcome, EngineError> {
        let mut pending = self
            .messages
            .get_pending(&id)
            .await?
            .ok_or(EngineError::MessageNotObserved)?;

        let set = self
            .guardians
            .get(GuardianSetIndex(pending.message.guardian_set_index))
            .await?
            .ok_or(EngineError::GuardianSetUnavailable)?;

        let expected = set.keys.get(signature.guardian_index as usize).ok_or(
            EngineError::GuardianIndexOutOfRange(signature.guardian_index),
        )?;

        if pending.has_guardian(signature.guardian_index) {
            return Err(EngineError::DuplicateSignature(signature.guardian_index));
        }

        let recovered = recover_guardian(&id.0, &signature)
            .map_err(|_| EngineError::InvalidSignature(signature.guardian_index))?;
        if &recovered != expected {
            return Err(EngineError::InvalidSignature(signature.guardian_index));
        }

        let guardian_index = signature.guardian_index;
        pending.insert_sorted(signature);
        let have = pending.signatures.len();
        let needed = pending.quorum();
        self.events
            .publish(DomainEvent::SignatureCollected {
                id,
                guardian_index,
                have,
                needed,
            })
            .await;
        debug!(have, needed, "signature collected");

        if !pending.quorum_reached() {
            self.messages.upsert_pending(pending).await?;
            return Ok(SubmitOutcome::Collected { have, needed });
        }

        let vaa = Vaa {
            version: SUPPORTED_VERSION,
            guardian_set_index: pending.message.guardian_set_index,
            signatures: pending.signatures.clone(),
            body: pending.message.body.clone(),
        };
        // Defensive final verification before persisting.
        vaa.verify(&set.keys)?;

        let record = VaaRecord {
            id,
            vaa: vaa.clone(),
            assembled_at: self.clock.unix_seconds(),
        };
        self.vaas.save(record).await?;
        self.messages.remove_pending(&id).await?;
        self.events.publish(DomainEvent::VaaAssembled { id }).await;
        info!(id = %id.to_hex(), "VAA assembled");
        Ok(SubmitOutcome::Assembled(Box::new(vaa)))
    }

    /// Fetches a completed VAA by id.
    ///
    /// # Errors
    /// Propagates store errors.
    pub async fn get_vaa(&self, id: &MessageId) -> Result<Option<VaaRecord>, EngineError> {
        self.vaas.get(id).await
    }

    /// Lists all pending observations.
    ///
    /// # Errors
    /// Propagates store errors.
    pub async fn list_pending(&self) -> Result<Vec<PendingObservation>, EngineError> {
        self.messages.list_pending().await
    }

    /// Returns aggregate statistics.
    ///
    /// # Errors
    /// Propagates store errors.
    pub async fn stats(&self) -> Result<EngineStats, EngineError> {
        Ok(EngineStats {
            pending: self.messages.list_pending().await?.len(),
            completed: self.vaas.count().await?,
        })
    }
}
