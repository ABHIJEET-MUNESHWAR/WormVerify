//! Shared application state wiring the concrete engine, guardian registry,
//! simulated guardians, event bus, and a request rate limiter.

use std::sync::Arc;

use wormverify_core::engine::AggregatorEngine;
use wormverify_infra::{
    BroadcastEventSink, InMemoryGuardianRegistry, InMemoryMessageStore, InMemoryVaaStore,
    SimulatedGuardians,
};
use wormverify_resilience::RateLimiter;

/// The concrete engine used by the GraphQL API.
pub type ConcreteEngine = AggregatorEngine<
    InMemoryMessageStore,
    InMemoryVaaStore,
    InMemoryGuardianRegistry,
    BroadcastEventSink,
>;

/// Immutable, cloneable application state shared across GraphQL resolvers.
#[derive(Clone)]
pub struct ServiceState {
    pub engine: Arc<ConcreteEngine>,
    pub registry: Arc<InMemoryGuardianRegistry>,
    pub guardians: Arc<SimulatedGuardians>,
    pub events: Arc<BroadcastEventSink>,
    pub rate_limiter: Arc<RateLimiter>,
}

impl ServiceState {
    /// Assembles the shared state from its already-constructed components.
    #[must_use]
    pub fn new(
        engine: Arc<ConcreteEngine>,
        registry: Arc<InMemoryGuardianRegistry>,
        guardians: Arc<SimulatedGuardians>,
        events: Arc<BroadcastEventSink>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            engine,
            registry,
            guardians,
            events,
            rate_limiter,
        }
    }
}
