-- WormVerify — completed VAA storage.
--
-- The `vaas` table is RANGE-partitioned by `emitter_chain` so per-chain volume
-- can be pruned or archived independently and queries that filter by chain hit a
-- single partition. Each message id is the 32-byte keccak double-hash digest.

CREATE TABLE IF NOT EXISTS vaas (
    id                 BYTEA       NOT NULL,
    guardian_set_index BIGINT      NOT NULL,
    emitter_chain      INTEGER     NOT NULL,
    sequence           BIGINT      NOT NULL,
    vaa_bytes          BYTEA       NOT NULL,
    assembled_at       BIGINT      NOT NULL,
    PRIMARY KEY (id, emitter_chain)
) PARTITION BY RANGE (emitter_chain);

-- Solana (chain id 1) and a catch-all partition for every other chain.
CREATE TABLE IF NOT EXISTS vaas_solana
    PARTITION OF vaas FOR VALUES FROM (1) TO (2);

CREATE TABLE IF NOT EXISTS vaas_other
    PARTITION OF vaas FOR VALUES FROM (2) TO (65535);

-- Common lookup: recent VAAs for an emitter chain ordered by sequence.
CREATE INDEX IF NOT EXISTS idx_vaas_chain_sequence
    ON vaas (emitter_chain, sequence DESC);

-- Time-ordered scans for backfills and audits.
CREATE INDEX IF NOT EXISTS idx_vaas_assembled_at
    ON vaas (assembled_at DESC);
