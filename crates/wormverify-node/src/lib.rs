//! Library surface for the WormVerify node (composition root).

#![forbid(unsafe_code)]

pub mod config;
pub mod demo;
pub mod startup;
pub mod telemetry;

pub use config::{Cli, Command, GuardianArgs, ServeArgs};
