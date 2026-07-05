//! Command-line configuration.

use clap::{Args, Parser, Subcommand};

/// WormVerify off-chain relayer / guardian aggregation service.
#[derive(Debug, Parser)]
#[command(name = "wormverify-node", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub guardians: GuardianArgs,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the GraphQL server (default).
    Serve(ServeArgs),
    /// Run a self-contained end-to-end aggregation demo and exit.
    Demo,
}

/// Guardian-set configuration shared by all commands.
#[derive(Debug, Args, Clone)]
pub struct GuardianArgs {
    /// Number of simulated guardians in the active set.
    #[arg(long, env = "WV_GUARDIAN_COUNT", default_value_t = 4)]
    pub guardian_count: usize,

    /// Deterministic seed base for simulated guardian keys.
    #[arg(long, env = "WV_GUARDIAN_SEED", default_value_t = 1)]
    pub guardian_seed: u8,

    /// Index of the active guardian set.
    #[arg(long, env = "WV_GUARDIAN_SET_INDEX", default_value_t = 0)]
    pub guardian_set_index: u32,
}

/// Options for the `serve` command.
#[derive(Debug, Args, Clone)]
pub struct ServeArgs {
    /// Address the HTTP server binds to.
    #[arg(long, env = "WV_BIND_ADDR", default_value = "0.0.0.0:8080")]
    pub bind_addr: String,

    /// Maximum GraphQL mutations accepted per second.
    #[arg(long, env = "WV_RATE_LIMIT_RPS", default_value_t = 50)]
    pub rate_limit_rps: u32,
}

impl Default for ServeArgs {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".to_string(),
            rate_limit_rps: 50,
        }
    }
}
