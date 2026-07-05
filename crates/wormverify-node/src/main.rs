//! Binary entry point for the WormVerify off-chain relayer.

use clap::Parser;
use wormverify_node::config::{Cli, Command, ServeArgs};
use wormverify_node::{demo, startup, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    telemetry::init_tracing();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Demo) => demo::run(&cli.guardians).await,
        Some(Command::Serve(args)) => startup::serve(&cli.guardians, &args).await,
        None => startup::serve(&cli.guardians, &ServeArgs::default()).await,
    }
}
