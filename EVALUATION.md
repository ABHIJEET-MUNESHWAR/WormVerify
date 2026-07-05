# WormVerify — Self-Evaluation Against Engineering Guidelines

Status legend: ✅ done · 🟡 partial / by-design-scoped · ⬜ deferred to the off-chain relayer

WormVerify is, by design, an **on-chain Anchor program**. Several guidelines
(GraphQL, SQL sharding, HTTP rate-limiting, Postman) are properties of a *client-server
service* and are therefore scoped to the planned `wormverify-relayer` off-chain crate
(see the README roadmap), not the program itself. Where a guideline maps onto an on-chain
analogue, that analogue is described.

| # | Guideline | Status | Where / how |
|---|---|---|---|
| 1 | SOLID principles | ✅ | Single-responsibility modules: `vaa` (parse), `verify` (crypto), `state` (accounts), `error` (codes), `lib` (orchestration). Verification depends on the `ParsedVaa` abstraction, not raw bytes. |
| 2 | Microservice pattern (event-driven/CQRS/Saga) | 🟡 | On-chain analogue: **event-sourced** — every state transition emits an Anchor event (`VaaVerified`, `MessagePosted`, `GuardianSetUpgraded`) that off-chain consumers project. Full event-driven relayer ⬜. |
| 3 | Partitioning & sharding | 🟡 | State is **PDA-sharded**: each VAA, message, and guardian set is an independent account keyed by seeds — no shared hot account, fully parallelizable writes. |
| 4 | Timeouts, retry, fault tolerance | 🟡 | On-chain code is deterministic & atomic (a failed ix reverts). Client-side timeout/retry ⬜ (relayer). |
| 5 | Rate limiting & circuit breaker | ⬜ | Belongs to the off-chain relayer submitting transactions. |
| 6 | Robust error handling & recovery | ✅ | 17 explicit `WormError` codes; every fallible step returns `Result`; `checked_add`; no `unwrap` on runtime paths. Replay & mismatch are recoverable, precise errors. |
| 7 | GraphQL if client-server >5 endpoints | ⬜ | N/A to a program; planned for the relayer. |
| 8 | Unit + integration coverage | ✅ | 11 tests: pure-logic units + **real secp256k1** end-to-end (quorum, below-quorum, tampered-body, foreign-guardian). |
| 9 | Modular reusable components | ✅ | `vaa`/`verify` are validator-independent and reusable by CPI callers and off-chain code. |
| 10 | 3rd-party crates | ✅ | `anchor-lang`; tests use `libsecp256k1`, `tiny-keccak`. |
| 11 | Generative / Agentic AI | ⬜ | Not applicable to a verification core; the author's WalletLens/other services showcase AI. |
| 12 | Idiomatic patterns & best practices | ✅ | Newtype-ish typed digests, `#[must_use]`, borrow-based `ParsedVaa<'a>`, exhaustive `match`-free guard rails via `require!`. |
| 13 | Generics | 🟡 | Anchor account generics (`Account<'info, T>`); parsing generic over payload slice lifetime. Program logic is intentionally concrete for CU predictability. |
| 14 | Anchor framework | ✅ | Entire program is Anchor 0.30. |
| 15 | README (TOC, diagrams, flows, tests, badges) | ✅ | README has TOC, badges, mermaid architecture + sequence flow, component tables, complexity, real test output. |
| 16 | Performance, reliability, maintainability | ✅ | Fat-LTO release profile, `overflow-checks=true`, bounded account sizes, `O(S)` verification. |
| 17 | Tokio async runtime | ⬜ | Relayer concern. |
| 18 | Parallelism / concurrency / batch | 🟡 | PDA-per-object model makes on-chain writes independent & parallel across transactions. |
| 19 | Logging & observability | 🟡 | Structured Anchor **events** are the on-chain observability substrate; Prometheus/tracing ⬜ (relayer). |
| 20 | Happy path + edge cases | ✅ | Truncated bytes, unsorted sigs, wrong index/hash, expired set, replay, overflow all covered. |
| 21 | Composable, extensible architecture | ✅ | New payload types & governance actions slot in without touching verification. |
| 22 | Interfaces, config, structure | ✅ | `BridgeConfig` holds tunables (TTL, chain id, authority); clean module boundaries. |
| 23 | Compile-time constraint enforcement | ✅ | Fixed-size `[u8;32]`/`[u8;64]`/`[u8;20]` arrays, typed accounts, seed constraints checked by Anchor at deserialize. |
| 24 | Benchmarks & complexity | ✅ | Complexity table in README; verification is `O(S)` recoveries, each a constant-cost syscall. |
| 25 | CI/CD | ✅ | `.github/workflows/ci.yml`: fmt + clippy `-D warnings` + test + `cargo audit`. |
| 26 | Dockerfile | ✅ | Reproducible verifiable BPF build via `backpackapp/build`. |
| 27 | Postman collection | ⬜ | Applies to the relayer HTTP/GraphQL surface. |
| 28 | Self-evaluation | ✅ | This document. |

## Honest gaps

- The **off-chain relayer** (Tokio + GraphQL + resilience + observability + Postman) is scoped
  but not yet built — guidelines 4/5/7/17/19/27 land there.
- A **TypeScript `anchor test`** suite exercising the full transaction path (including the native
  ed25519 pre-instruction and on-chain `secp256k1_recover` under BPF) is on the roadmap; current
  crypto coverage is via host-side real-signature integration tests.
