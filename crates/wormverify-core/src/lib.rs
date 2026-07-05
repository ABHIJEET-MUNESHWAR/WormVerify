//! Domain core for the WormVerify off-chain aggregation service.
//!
//! Pure hexagonal core: the [`engine::AggregatorEngine`] orchestrates VAA
//! aggregation against the [`ports`] traits, with no direct I/O dependencies.

#![forbid(unsafe_code)]

pub mod domain;
pub mod engine;
pub mod error;
pub mod ports;

pub use domain::{DomainEvent, MessageId, ObservedMessage, PendingObservation, VaaRecord};
pub use engine::{AggregatorEngine, EngineStats, SubmitOutcome, UnixClock, WallClock};
pub use error::EngineError;
pub use ports::{EventSink, GuardianRegistry, MessageStore, VaaStore};
