//! GraphQL schema: queries, mutations, and subscriptions over the engine.

use async_graphql::{Context, InputObject, Object, Schema, SimpleObject, Subscription};
use futures::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use wormverify_core::domain::{DomainEvent, MessageId};
use wormverify_core::engine::SubmitOutcome;
use wormverify_core::ports::GuardianRegistry;
use wormverify_types::VaaBody;

use crate::state::ServiceState;

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// A completed VAA as exposed over GraphQL.
#[derive(SimpleObject)]
pub struct GqlVaa {
    pub id: String,
    pub version: u8,
    pub guardian_set_index: u32,
    pub num_signatures: usize,
    pub emitter_chain: u16,
    pub sequence: String,
    pub consistency_level: u8,
    pub payload_hex: String,
    pub bytes_hex: String,
    pub assembled_at: i64,
}

/// A pending (not-yet-quorum) observation.
#[derive(SimpleObject)]
pub struct GqlPending {
    pub id: String,
    pub guardian_set_index: u32,
    pub emitter_chain: u16,
    pub sequence: String,
    pub have: usize,
    pub needed: usize,
}

/// The current guardian set.
#[derive(SimpleObject)]
pub struct GqlGuardianSet {
    pub index: u32,
    pub quorum: usize,
    pub addresses: Vec<String>,
}

/// Aggregate service statistics.
#[derive(SimpleObject)]
pub struct GqlStats {
    pub pending: usize,
    pub completed: u64,
}

/// Result of submitting an observation or signature.
#[derive(SimpleObject)]
pub struct GqlSubmitResult {
    pub message_id: String,
    pub assembled: bool,
    pub have: usize,
    pub needed: usize,
    pub vaa_bytes_hex: Option<String>,
}

/// A domain event delivered over the subscription stream.
#[derive(SimpleObject, Clone)]
pub struct GqlEvent {
    pub kind: String,
    pub message_id: String,
    pub guardian_index: Option<u8>,
    pub have: Option<usize>,
    pub needed: Option<usize>,
}

impl From<DomainEvent> for GqlEvent {
    fn from(e: DomainEvent) -> Self {
        match e {
            DomainEvent::MessageObserved { id } => GqlEvent {
                kind: "MESSAGE_OBSERVED".into(),
                message_id: id.to_hex(),
                guardian_index: None,
                have: None,
                needed: None,
            },
            DomainEvent::SignatureCollected {
                id,
                guardian_index,
                have,
                needed,
            } => GqlEvent {
                kind: "SIGNATURE_COLLECTED".into(),
                message_id: id.to_hex(),
                guardian_index: Some(guardian_index),
                have: Some(have),
                needed: Some(needed),
            },
            DomainEvent::VaaAssembled { id } => GqlEvent {
                kind: "VAA_ASSEMBLED".into(),
                message_id: id.to_hex(),
                guardian_index: None,
                have: None,
                needed: None,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

/// Fields describing a message to observe.
#[derive(InputObject)]
pub struct ObservationInput {
    pub guardian_set_index: u32,
    pub timestamp: u32,
    pub nonce: u32,
    pub emitter_chain: u16,
    /// 32-byte emitter address, hex-encoded.
    pub emitter_address_hex: String,
    pub sequence: u64,
    pub consistency_level: u8,
    /// Message payload, hex-encoded.
    pub payload_hex: String,
}

impl ObservationInput {
    fn into_body(self) -> Result<VaaBody, String> {
        let emitter = hex::decode(self.emitter_address_hex.trim_start_matches("0x"))
            .map_err(|e| e.to_string())?;
        let emitter_address: [u8; 32] = emitter
            .try_into()
            .map_err(|_| "emitter_address must be 32 bytes".to_string())?;
        let payload =
            hex::decode(self.payload_hex.trim_start_matches("0x")).map_err(|e| e.to_string())?;
        Ok(VaaBody {
            timestamp: self.timestamp,
            nonce: self.nonce,
            emitter_chain: self.emitter_chain,
            emitter_address,
            sequence: self.sequence,
            consistency_level: self.consistency_level,
            payload,
        })
    }
}

// ---------------------------------------------------------------------------
// Query root
// ---------------------------------------------------------------------------

/// GraphQL query root.
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Liveness probe.
    async fn health(&self) -> bool {
        true
    }

    /// Fetches a completed VAA by its hex message id.
    async fn vaa(&self, ctx: &Context<'_>, id: String) -> async_graphql::Result<Option<GqlVaa>> {
        let state = ctx.data::<ServiceState>()?;
        let mid = MessageId::from_hex(&id).map_err(async_graphql::Error::new)?;
        let record = state.engine.get_vaa(&mid).await.map_err(to_err)?;
        Ok(record.map(|r| {
            let bytes = r.vaa.encode();
            GqlVaa {
                id: r.id.to_hex(),
                version: r.vaa.version,
                guardian_set_index: r.vaa.guardian_set_index,
                num_signatures: r.vaa.signatures.len(),
                emitter_chain: r.vaa.body.emitter_chain,
                sequence: r.vaa.body.sequence.to_string(),
                consistency_level: r.vaa.body.consistency_level,
                payload_hex: hex::encode(&r.vaa.body.payload),
                bytes_hex: hex::encode(bytes),
                assembled_at: r.assembled_at,
            }
        }))
    }

    /// Lists all pending observations awaiting quorum.
    async fn pending_messages(&self, ctx: &Context<'_>) -> async_graphql::Result<Vec<GqlPending>> {
        let state = ctx.data::<ServiceState>()?;
        let pending = state.engine.list_pending().await.map_err(to_err)?;
        Ok(pending
            .into_iter()
            .map(|p| GqlPending {
                id: p.message.id.to_hex(),
                guardian_set_index: p.message.guardian_set_index,
                emitter_chain: p.message.body.emitter_chain,
                sequence: p.message.body.sequence.to_string(),
                have: p.signatures.len(),
                needed: p.quorum(),
            })
            .collect())
    }

    /// Returns the currently active guardian set.
    async fn guardian_set(&self, ctx: &Context<'_>) -> async_graphql::Result<GqlGuardianSet> {
        let state = ctx.data::<ServiceState>()?;
        let set = state.registry.current().await.map_err(to_err)?;
        Ok(GqlGuardianSet {
            index: set.index.0,
            quorum: set.quorum(),
            addresses: set.keys.iter().map(|k| k.to_hex()).collect(),
        })
    }

    /// Returns aggregate statistics.
    async fn stats(&self, ctx: &Context<'_>) -> async_graphql::Result<GqlStats> {
        let state = ctx.data::<ServiceState>()?;
        let stats = state.engine.stats().await.map_err(to_err)?;
        Ok(GqlStats {
            pending: stats.pending,
            completed: stats.completed,
        })
    }
}

// ---------------------------------------------------------------------------
// Mutation root
// ---------------------------------------------------------------------------

/// GraphQL mutation root.
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Registers a newly observed message and returns its hex id.
    async fn submit_observation(
        &self,
        ctx: &Context<'_>,
        input: ObservationInput,
    ) -> async_graphql::Result<String> {
        let state = ctx.data::<ServiceState>()?;
        rate_limit(state)?;
        let gsi = input.guardian_set_index;
        let body = input.into_body().map_err(async_graphql::Error::new)?;
        let id = state
            .engine
            .observe_message(gsi, body)
            .await
            .map_err(to_err)?;
        Ok(id.to_hex())
    }

    /// Signs a message as a simulated guardian and submits the signature.
    async fn sign_as_guardian(
        &self,
        ctx: &Context<'_>,
        message_id: String,
        guardian_index: u8,
    ) -> async_graphql::Result<GqlSubmitResult> {
        let state = ctx.data::<ServiceState>()?;
        rate_limit(state)?;
        let mid = MessageId::from_hex(&message_id).map_err(async_graphql::Error::new)?;
        let signature = state
            .guardians
            .sign(guardian_index, &mid.0)
            .ok_or_else(|| async_graphql::Error::new("guardian index out of range"))?;
        let outcome = state
            .engine
            .submit_signature(mid, signature)
            .await
            .map_err(to_err)?;
        Ok(submit_result(mid, outcome))
    }
}

// ---------------------------------------------------------------------------
// Subscription root
// ---------------------------------------------------------------------------

/// GraphQL subscription root.
pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
    /// Streams domain events as aggregation progresses.
    async fn events(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<impl Stream<Item = GqlEvent>> {
        let state = ctx.data::<ServiceState>()?;
        let rx = state.events.subscribe();
        Ok(BroadcastStream::new(rx).filter_map(|r| r.ok().map(GqlEvent::from)))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_err(e: impl std::fmt::Display) -> async_graphql::Error {
    async_graphql::Error::new(e.to_string())
}

fn rate_limit(state: &ServiceState) -> async_graphql::Result<()> {
    state
        .rate_limiter
        .try_acquire()
        .map_err(|_| async_graphql::Error::new("rate limit exceeded"))
}

fn submit_result(id: MessageId, outcome: SubmitOutcome) -> GqlSubmitResult {
    match outcome {
        SubmitOutcome::Collected { have, needed } => GqlSubmitResult {
            message_id: id.to_hex(),
            assembled: false,
            have,
            needed,
            vaa_bytes_hex: None,
        },
        SubmitOutcome::Assembled(vaa) => {
            let needed = vaa.signatures.len();
            GqlSubmitResult {
                message_id: id.to_hex(),
                assembled: true,
                have: vaa.signatures.len(),
                needed,
                vaa_bytes_hex: Some(hex::encode(vaa.encode())),
            }
        }
    }
}

/// The concrete schema type.
pub type WormVerifySchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

/// Builds the GraphQL schema with `state` injected as shared context.
#[must_use]
pub fn build_schema(state: ServiceState) -> WormVerifySchema {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        .data(state)
        .finish()
}
