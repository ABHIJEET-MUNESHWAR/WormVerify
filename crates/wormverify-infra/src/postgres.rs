//! Optional Postgres-backed [`VaaStore`] (enabled with the `postgres` feature).
//!
//! Completed VAAs are persisted to a range-partitioned `vaas` table keyed by the
//! 32-byte message id. The canonical VAA wire bytes are stored so records can be
//! reconstructed exactly on read.

use async_trait::async_trait;
use sqlx::postgres::PgPool;
use sqlx::Row;

use wormverify_core::domain::{MessageId, VaaRecord};
use wormverify_core::error::EngineError;
use wormverify_core::ports::VaaStore;
use wormverify_types::Vaa;

/// Postgres implementation of [`VaaStore`].
pub struct PgVaaStore {
    pool: PgPool,
}

impl PgVaaStore {
    /// Wraps an existing connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn store_err(e: impl std::fmt::Display) -> EngineError {
    EngineError::Store(e.to_string())
}

#[async_trait]
impl VaaStore for PgVaaStore {
    async fn save(&self, record: VaaRecord) -> Result<(), EngineError> {
        let bytes = record.vaa.encode();
        sqlx::query(
            "INSERT INTO vaas \
             (id, guardian_set_index, emitter_chain, sequence, vaa_bytes, assembled_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(record.id.0.as_slice())
        .bind(i64::from(record.vaa.guardian_set_index))
        .bind(i32::from(record.vaa.body.emitter_chain))
        .bind(record.vaa.body.sequence as i64)
        .bind(bytes)
        .bind(record.assembled_at)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn get(&self, id: &MessageId) -> Result<Option<VaaRecord>, EngineError> {
        let row = sqlx::query("SELECT vaa_bytes, assembled_at FROM vaas WHERE id = $1")
            .bind(id.0.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(store_err)?;

        let Some(row) = row else { return Ok(None) };
        let bytes: Vec<u8> = row.try_get("vaa_bytes").map_err(store_err)?;
        let assembled_at: i64 = row.try_get("assembled_at").map_err(store_err)?;
        let vaa = Vaa::parse(&bytes)?;
        Ok(Some(VaaRecord {
            id: *id,
            vaa,
            assembled_at,
        }))
    }

    async fn count(&self) -> Result<u64, EngineError> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM vaas")
            .fetch_one(&self.pool)
            .await
            .map_err(store_err)?;
        let n: i64 = row.try_get("n").map_err(store_err)?;
        Ok(n as u64)
    }
}
