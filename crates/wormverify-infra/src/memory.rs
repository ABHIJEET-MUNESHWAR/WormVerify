//! In-memory adapter implementations of the core ports.

use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;

use wormverify_core::domain::{MessageId, PendingObservation, VaaRecord};
use wormverify_core::error::EngineError;
use wormverify_core::ports::{GuardianRegistry, MessageStore, VaaStore};
use wormverify_types::{GuardianSet, GuardianSetIndex};

/// Thread-safe in-memory [`MessageStore`].
#[derive(Default)]
pub struct InMemoryMessageStore {
    pending: DashMap<[u8; 32], PendingObservation>,
}

#[async_trait]
impl MessageStore for InMemoryMessageStore {
    async fn upsert_pending(&self, pending: PendingObservation) -> Result<(), EngineError> {
        self.pending.insert(pending.message.id.0, pending);
        Ok(())
    }
    async fn get_pending(&self, id: &MessageId) -> Result<Option<PendingObservation>, EngineError> {
        Ok(self.pending.get(&id.0).map(|e| e.clone()))
    }
    async fn list_pending(&self) -> Result<Vec<PendingObservation>, EngineError> {
        Ok(self.pending.iter().map(|e| e.clone()).collect())
    }
    async fn remove_pending(&self, id: &MessageId) -> Result<(), EngineError> {
        self.pending.remove(&id.0);
        Ok(())
    }
}

/// Thread-safe in-memory [`VaaStore`].
#[derive(Default)]
pub struct InMemoryVaaStore {
    vaas: DashMap<[u8; 32], VaaRecord>,
}

#[async_trait]
impl VaaStore for InMemoryVaaStore {
    async fn save(&self, record: VaaRecord) -> Result<(), EngineError> {
        self.vaas.insert(record.id.0, record);
        Ok(())
    }
    async fn get(&self, id: &MessageId) -> Result<Option<VaaRecord>, EngineError> {
        Ok(self.vaas.get(&id.0).map(|e| e.clone()))
    }
    async fn count(&self) -> Result<u64, EngineError> {
        Ok(self.vaas.len() as u64)
    }
}

/// In-memory [`GuardianRegistry`] tracking a set of guardian versions and the
/// currently active index.
pub struct InMemoryGuardianRegistry {
    sets: DashMap<u32, GuardianSet>,
    current: RwLock<u32>,
}

impl InMemoryGuardianRegistry {
    /// Creates a registry seeded with `set` as the active guardian set.
    #[must_use]
    pub fn new(set: GuardianSet) -> Self {
        let index = set.index.0;
        let sets = DashMap::new();
        sets.insert(index, set);
        Self {
            sets,
            current: RwLock::new(index),
        }
    }

    /// Inserts a new guardian set and marks it as the active one.
    pub fn upgrade(&self, set: GuardianSet) {
        let index = set.index.0;
        self.sets.insert(index, set);
        *self.current.write() = index;
    }
}

#[async_trait]
impl GuardianRegistry for InMemoryGuardianRegistry {
    async fn current(&self) -> Result<GuardianSet, EngineError> {
        let index = *self.current.read();
        self.sets
            .get(&index)
            .map(|e| e.clone())
            .ok_or(EngineError::GuardianSetUnavailable)
    }
    async fn get(&self, index: GuardianSetIndex) -> Result<Option<GuardianSet>, EngineError> {
        Ok(self.sets.get(&index.0).map(|e| e.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormverify_types::GuardianAddress;

    fn set(index: u32) -> GuardianSet {
        GuardianSet {
            index: GuardianSetIndex(index),
            keys: vec![GuardianAddress([index as u8; 20])],
            expiration_time: 0,
        }
    }

    #[tokio::test]
    async fn registry_upgrade_switches_current() {
        let reg = InMemoryGuardianRegistry::new(set(0));
        assert_eq!(reg.current().await.unwrap().index, GuardianSetIndex(0));
        reg.upgrade(set(1));
        assert_eq!(reg.current().await.unwrap().index, GuardianSetIndex(1));
        assert!(reg.get(GuardianSetIndex(0)).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn vaa_store_counts() {
        let store = InMemoryVaaStore::default();
        assert_eq!(store.count().await.unwrap(), 0);
    }
}
