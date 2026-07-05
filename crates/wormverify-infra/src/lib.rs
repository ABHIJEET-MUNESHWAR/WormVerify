//! Driven adapters for the WormVerify off-chain service.

#![forbid(unsafe_code)]

pub mod events;
pub mod memory;
pub mod signer;

#[cfg(feature = "postgres")]
pub mod postgres;

pub use events::BroadcastEventSink;
pub use memory::{InMemoryGuardianRegistry, InMemoryMessageStore, InMemoryVaaStore};
pub use signer::SimulatedGuardians;

#[cfg(feature = "postgres")]
pub use postgres::PgVaaStore;
