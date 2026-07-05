//! A self-contained demonstration of end-to-end VAA aggregation.

use anyhow::{anyhow, Result};
use tracing::info;
use wormverify_core::engine::SubmitOutcome;
use wormverify_types::VaaBody;

use crate::config::GuardianArgs;
use crate::startup::build_state;

/// Observes a sample message, has a quorum of simulated guardians sign it, and
/// prints the assembled VAA.
///
/// # Errors
/// Fails if the engine rejects the observation or signatures.
pub async fn run(guardians: &GuardianArgs) -> Result<()> {
    let state = build_state(guardians, 1000);

    let body = VaaBody {
        timestamp: 1_700_000_000,
        nonce: 7,
        emitter_chain: 1,
        emitter_address: [0x11u8; 32],
        sequence: 1,
        consistency_level: 1,
        payload: b"wormverify-demo".to_vec(),
    };

    let id = state
        .engine
        .observe_message(guardians.guardian_set_index, body)
        .await?;
    info!(id = %id.to_hex(), "observed demo message");

    let set = state.guardians.guardian_set();
    let quorum = set.quorum();

    for index in 0..quorum as u8 {
        let signature = state
            .guardians
            .sign(index, &id.0)
            .ok_or_else(|| anyhow!("failed to sign as guardian {index}"))?;
        match state.engine.submit_signature(id, signature).await? {
            SubmitOutcome::Collected { have, needed } => {
                info!(have, needed, "collected signature");
            }
            SubmitOutcome::Assembled(vaa) => {
                let bytes = vaa.encode();
                info!(
                    signatures = vaa.signatures.len(),
                    "VAA assembled and verified"
                );
                println!("message_id: {}", id.to_hex());
                println!("vaa_bytes:  {}", hex::encode(bytes));
                return Ok(());
            }
        }
    }

    Err(anyhow!("quorum was not reached"))
}
