//! Hexagonal ports: the driven interfaces the engine depends on.

use async_trait::async_trait;
use wormverify_types::{GuardianSet, GuardianSetIndex};

use crate::domain::{DomainEvent, MessageId, PendingObservation, VaaRecord};
use crate::error::EngineError;

/// Persistence for in-flight (pending) observations.
#[async_trait]
pub trait MessageStore: Send + Sync {
    /// Inserts or replaces a pending observation.
    async fn upsert_pending(&self, pending: PendingObservation) -> Result<(), EngineError>;

    /// Fetches a pending observation by message id.
    async fn get_pending(&self, id: &MessageId) -> Result<Option<PendingObservation>, EngineError>;

    /// Lists all pending observations.
    async fn list_pending(&self) -> Result<Vec<PendingObservation>, EngineError>;

    /// Removes a pending observation once its VAA is completed.
    async fn remove_pending(&self, id: &MessageId) -> Result<(), EngineError>;
}

/// Persistence for completed VAAs.
#[async_trait]
pub trait VaaStore: Send + Sync {
    /// Persists a completed VAA record.
    async fn save(&self, record: VaaRecord) -> Result<(), EngineError>;

    /// Fetches a completed VAA by message id.
    async fn get(&self, id: &MessageId) -> Result<Option<VaaRecord>, EngineError>;

    /// Returns the number of completed VAAs.
    async fn count(&self) -> Result<u64, EngineError>;
}

/// Read access to guardian sets.
#[async_trait]
pub trait GuardianRegistry: Send + Sync {
    /// Returns the currently active guardian set.
    async fn current(&self) -> Result<GuardianSet, EngineError>;

    /// Returns a guardian set by index, if known.
    async fn get(&self, index: GuardianSetIndex) -> Result<Option<GuardianSet>, EngineError>;
}

/// A sink for domain events (e.g. metrics, subscriptions, message bus).
#[async_trait]
pub trait EventSink: Send + Sync {
    /// Publishes a domain event. Implementations must not fail the caller.
    async fn publish(&self, event: DomainEvent);
}
