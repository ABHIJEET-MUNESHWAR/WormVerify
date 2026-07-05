# WormVerify — Self-Evaluation Against Engineering Guidelines

Status legend: ✅ done · 🟡 partial / by-design-scoped · ⬜ not applicable

WormVerify is a **full stack**: an on-chain Anchor program (`anchor/`) plus a production-grade
off-chain relayer (`crates/`). Guidelines that describe a *client-server service* (GraphQL,
SQL partitioning, rate-limiting, Postman, Tokio, observability) are satisfied by the off-chain
relayer; guidelines about the on-chain security core are satisfied by the Anchor program. Both
are covered below.

| # | Guideline | Status | Where / how |
|---|---|---|---|
| 1 | SOLID principles | ✅ | Program: `vaa`/`verify`/`state`/`error`/`lib` single-responsibility modules. Service: **hexagonal** crates with ports (`MessageStore`, `VaaStore`, `GuardianRegistry`, `EventSink`) inverted from the `AggregatorEngine`. |
| 2 | Microservice pattern (event-driven/CQRS/Saga) | ✅ | Program emits Anchor events per transition. Service is **event-driven**: the engine publishes `DomainEvent`s to a broadcast `EventSink` that feeds GraphQL subscriptions. |
| 3 | Partitioning & sharding | ✅ | On-chain: PDA-per-object sharding. Off-chain: `vaas` table **RANGE-partitioned by emitter chain** with per-chain partitions ([`migrations/0001_init.sql`](./migrations/0001_init.sql)). |
| 4 | Timeouts, retry, fault tolerance | ✅ | `wormverify-resilience`: `with_timeout`, `retry` with capped exponential backoff, three-state circuit breaker (all unit-tested with a manual clock). |
| 5 | Rate limiting & circuit breaker | ✅ | `governor`-backed token-bucket rate limiter guards GraphQL mutations; `CircuitBreaker` guards downstream I/O. |
| 6 | Robust error handling & recovery | ✅ | Program: 17 `WormError` codes. Service: `thiserror` `VaaError` / `EngineError`; every fallible boundary returns `Result`; no `unwrap` on runtime paths. |
| 7 | GraphQL if client-server >5 endpoints | ✅ | `wormverify-api`: `async-graphql` schema — 5 queries, 2 mutations, 1 subscription; axum router with playground + websocket. |
| 8 | Unit + integration coverage | ✅ | Program: 11 tests. Service: **39 tests** (unit + engine flow + real-secp256k1 + end-to-end GraphQL). |
| 9 | Modular reusable components | ✅ | `wormverify-types` is a pure, I/O-free crate reused by every layer and mirroring the on-chain wire format. |
| 10 | 3rd-party crates | ✅ | Canonical stack: `tokio`, `async-graphql`, `axum`, `sqlx`, `governor`, `dashmap`, `tracing`, `metrics`, `criterion`, `libsecp256k1`. |
| 11 | Generative / Agentic AI | ⬜ | Not applicable to a verification/relayer core. |
| 12 | Idiomatic patterns & best practices | ✅ | Newtypes (`ChainId`, `Sequence`, `MessageId`), `#[must_use]`, `#![forbid(unsafe_code)]` on every crate, borrow-based parsing, exhaustive matches. |
| 13 | Generics | ✅ | `AggregatorEngine<M, V, G, E>` is generic over all four ports; `retry` is generic over any `Future`-returning closure. |
| 14 | Anchor framework | ✅ | On-chain program is Anchor 0.30. |
| 15 | README (TOC, diagrams, flows, tests, badges) | ✅ | TOC, badges, mermaid architecture + sequence + service diagrams, component tables, complexity + benchmark tables, real test output. |
| 16 | Performance, reliability, maintainability | ✅ | LTO release profiles; `criterion` benchmarks (verify `O(S)`, ~88 µs/recovery; parse ~48 ns); bounded allocations. |
| 17 | Tokio async runtime | ✅ | Service runs on Tokio; async ports throughout; broadcast channel for events; graceful shutdown on `ctrl_c`. |
| 18 | Parallelism / concurrency / batch | ✅ | `DashMap`-backed lock-striped stores; PDA-per-object on-chain; broadcast fan-out to many subscribers. |
| 19 | Logging & observability | ✅ | `tracing` JSON logs with `#[instrument]` spans; Prometheus recorder exposed at `/metrics`; Anchor events on-chain. |
| 20 | Happy path + edge cases | ✅ | Duplicate/foreign/out-of-range/unobserved-signature rejects, below-quorum, tampered-body, truncated bytes, expired set, overflow. |
| 21 | Composable, extensible architecture | ✅ | Swap any adapter (in-memory ↔ Postgres) without touching the engine; new event types and payloads slot in cleanly. |
| 22 | Interfaces, config, structure | ✅ | `clap`-based config with env fallbacks; clean crate boundaries; `BridgeConfig` on-chain tunables. |
| 23 | Compile-time constraint enforcement | ✅ | Fixed-size byte arrays, typed newtypes, typed Anchor accounts, port traits enforce contracts at compile time. |
| 24 | Benchmarks & complexity | ✅ | `criterion` bench (`crates/wormverify-types/benches/verify.rs`) + complexity/benchmark tables in README. |
| 25 | CI/CD | ✅ | `ci.yml`: separate program & service jobs (fmt + clippy `-D warnings` + test `--all-features`) + `cargo audit`. |
| 26 | Dockerfile | ✅ | `Dockerfile` (multi-stage, non-root service image) + `Dockerfile.anchor` (verifiable BPF build) + `docker-compose.yml`. |
| 27 | Postman collection | ✅ | [`postman/WormVerify.postman_collection.json`](./postman/WormVerify.postman_collection.json) — GraphQL queries/mutations + metrics. |
| 28 | Self-evaluation | ✅ | This document. |

## Honest gaps

- The relayer uses a **simulated guardian set** (deterministic secp256k1 keys) so the end-to-end
  VAA-assembly flow is fully demonstrable and testable without running independent guardian nodes.
  Wiring to a **live on-chain event feed** (RPC watcher over `PostedMessage`) and to real external
  guardians is the next roadmap item.
- A **TypeScript `anchor test`** suite exercising the full transaction path under BPF is on the
  roadmap; current on-chain crypto coverage is via host-side real-signature integration tests.
- The Postgres `VaaStore` is feature-gated and covered by schema; the running node defaults to the
  in-memory store for a zero-dependency demo.
