//! End-to-end engine flow tests with in-memory ports and real secp256k1 guardians.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use libsecp256k1::{sign, Message, PublicKey, SecretKey};
use parking_lot::Mutex;

use wormverify_core::domain::{DomainEvent, MessageId, PendingObservation, VaaRecord};
use wormverify_core::engine::{AggregatorEngine, SubmitOutcome, UnixClock};
use wormverify_core::error::EngineError;
use wormverify_core::ports::{EventSink, GuardianRegistry, MessageStore, VaaStore};
use wormverify_types::{
    GuardianAddress, GuardianSet, GuardianSetIndex, GuardianSignature, VaaBody,
};

#[derive(Default)]
struct MemMessages {
    inner: Mutex<HashMap<[u8; 32], PendingObservation>>,
}

#[async_trait]
impl MessageStore for MemMessages {
    async fn upsert_pending(&self, pending: PendingObservation) -> Result<(), EngineError> {
        self.inner.lock().insert(pending.message.id.0, pending);
        Ok(())
    }
    async fn get_pending(&self, id: &MessageId) -> Result<Option<PendingObservation>, EngineError> {
        Ok(self.inner.lock().get(&id.0).cloned())
    }
    async fn list_pending(&self) -> Result<Vec<PendingObservation>, EngineError> {
        Ok(self.inner.lock().values().cloned().collect())
    }
    async fn remove_pending(&self, id: &MessageId) -> Result<(), EngineError> {
        self.inner.lock().remove(&id.0);
        Ok(())
    }
}

#[derive(Default)]
struct MemVaas {
    inner: Mutex<HashMap<[u8; 32], VaaRecord>>,
}

#[async_trait]
impl VaaStore for MemVaas {
    async fn save(&self, record: VaaRecord) -> Result<(), EngineError> {
        self.inner.lock().insert(record.id.0, record);
        Ok(())
    }
    async fn get(&self, id: &MessageId) -> Result<Option<VaaRecord>, EngineError> {
        Ok(self.inner.lock().get(&id.0).cloned())
    }
    async fn count(&self) -> Result<u64, EngineError> {
        Ok(self.inner.lock().len() as u64)
    }
}

struct FixedRegistry {
    set: GuardianSet,
}

#[async_trait]
impl GuardianRegistry for FixedRegistry {
    async fn current(&self) -> Result<GuardianSet, EngineError> {
        Ok(self.set.clone())
    }
    async fn get(&self, index: GuardianSetIndex) -> Result<Option<GuardianSet>, EngineError> {
        Ok((index == self.set.index).then(|| self.set.clone()))
    }
}

#[derive(Default)]
struct CollectingSink {
    events: Mutex<Vec<DomainEvent>>,
}

#[async_trait]
impl EventSink for CollectingSink {
    async fn publish(&self, event: DomainEvent) {
        self.events.lock().push(event);
    }
}

struct FixedClock;
impl UnixClock for FixedClock {
    fn unix_seconds(&self) -> i64 {
        1_700_000_000
    }
}

struct Guardian {
    sk: SecretKey,
    address: GuardianAddress,
}

impl Guardian {
    fn new(seed: u8) -> Self {
        let sk = SecretKey::parse(&[seed.max(1); 32]).unwrap();
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

type Engine = AggregatorEngine<MemMessages, MemVaas, FixedRegistry, CollectingSink>;

fn setup(n: usize) -> (Engine, Vec<Guardian>, Arc<CollectingSink>) {
    let guardians: Vec<Guardian> = (0..n).map(|i| Guardian::new(i as u8 + 1)).collect();
    let set = GuardianSet {
        index: GuardianSetIndex(0),
        keys: guardians.iter().map(|g| g.address).collect(),
        expiration_time: 0,
    };
    let sink = Arc::new(CollectingSink::default());
    let engine = AggregatorEngine::new(
        Arc::new(MemMessages::default()),
        Arc::new(MemVaas::default()),
        Arc::new(FixedRegistry { set }),
        sink.clone(),
        Arc::new(FixedClock),
    );
    (engine, guardians, sink)
}

fn body() -> VaaBody {
    VaaBody {
        timestamp: 1,
        nonce: 2,
        emitter_chain: 1,
        emitter_address: [9u8; 32],
        sequence: 3,
        consistency_level: 1,
        payload: b"payload".to_vec(),
    }
}

#[tokio::test]
async fn full_flow_reaches_quorum_and_assembles_vaa() {
    let (engine, guardians, sink) = setup(4); // quorum 3
    let id = engine.observe_message(0, body()).await.unwrap();

    let out = engine
        .submit_signature(id, guardians[0].sign(0, &id.0))
        .await
        .unwrap();
    assert_eq!(out, SubmitOutcome::Collected { have: 1, needed: 3 });
    engine
        .submit_signature(id, guardians[1].sign(1, &id.0))
        .await
        .unwrap();
    let out = engine
        .submit_signature(id, guardians[2].sign(2, &id.0))
        .await
        .unwrap();
    assert!(matches!(out, SubmitOutcome::Assembled(_)));

    let record = engine.get_vaa(&id).await.unwrap().unwrap();
    assert_eq!(record.vaa.signatures.len(), 3);
    assert!(engine.list_pending().await.unwrap().is_empty());

    let stats = engine.stats().await.unwrap();
    assert_eq!(stats.completed, 1);
    assert_eq!(stats.pending, 0);

    let events = sink.events.lock();
    assert!(events
        .iter()
        .any(|e| matches!(e, DomainEvent::VaaAssembled { .. })));
}

#[tokio::test]
async fn duplicate_signature_is_rejected() {
    let (engine, guardians, _) = setup(4);
    let id = engine.observe_message(0, body()).await.unwrap();
    engine
        .submit_signature(id, guardians[0].sign(0, &id.0))
        .await
        .unwrap();
    let err = engine
        .submit_signature(id, guardians[0].sign(0, &id.0))
        .await
        .unwrap_err();
    assert!(matches!(err, EngineError::DuplicateSignature(0)));
}

#[tokio::test]
async fn foreign_signature_is_rejected() {
    let (engine, _guardians, _) = setup(4);
    let id = engine.observe_message(0, body()).await.unwrap();
    let outsider = Guardian::new(250);
    let err = engine
        .submit_signature(id, outsider.sign(0, &id.0))
        .await
        .unwrap_err();
    assert!(matches!(err, EngineError::InvalidSignature(0)));
}

#[tokio::test]
async fn signature_for_unobserved_message_is_rejected() {
    let (engine, guardians, _) = setup(4);
    let fake = MessageId([1u8; 32]);
    let err = engine
        .submit_signature(fake, guardians[0].sign(0, &fake.0))
        .await
        .unwrap_err();
    assert!(matches!(err, EngineError::MessageNotObserved));
}

#[tokio::test]
async fn observe_is_idempotent() {
    let (engine, _guardians, _) = setup(4);
    let id1 = engine.observe_message(0, body()).await.unwrap();
    let id2 = engine.observe_message(0, body()).await.unwrap();
    assert_eq!(id1, id2);
    assert_eq!(engine.list_pending().await.unwrap().len(), 1);
}

#[tokio::test]
async fn out_of_range_guardian_index_is_rejected() {
    let (engine, guardians, _) = setup(4);
    let id = engine.observe_message(0, body()).await.unwrap();
    let err = engine
        .submit_signature(id, guardians[0].sign(9, &id.0))
        .await
        .unwrap_err();
    assert!(matches!(err, EngineError::GuardianIndexOutOfRange(9)));
}
