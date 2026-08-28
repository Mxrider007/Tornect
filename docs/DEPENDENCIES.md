# Dependencies

Every external crate is pinned in the workspace `Cargo.toml` and justified here
(`docs/PLAN.md` §D.1 rule 4). "Verified" means the version and API were checked
against crates.io / the crate source on that date, not recalled from memory.
Build requirements say what a machine needs beyond a Rust toolchain.

Version note: the plan cites "Arti 2.0" — that is the Arti *project/CLI* version.
The library crates (`arti-client`, `tor-hsservice`, …) use their own 0.x numbering
(`arti-client` 0.45.0 corresponds to the Arti 2.5.x line as of 2026-08-03).

## Milestone 0 (tornect-core, CLI, xtask)

| Crate | Version | Features | Why | Build requirements | Verified | Source |
|---|---|---|---|---|---|---|
| `ed25519-dalek` | 3.0.0 | `zeroize` | Host/device identities, transcript signatures. 3.0 aligns with `rand_core` 0.10 / `sha2` 0.11 (RustCrypto 2026 line). Seeds come from `getrandom`, so the `rand_core` feature is not needed. | none | 2026-08-28 | crates.io API (`/crates/ed25519-dalek/3.0.0/dependencies`) |
| `sha3` | 0.11.x | — | Onion v3 address checksum (`SHA3-256(".onion checksum" ‖ pk ‖ 0x03)`). | none | 2026-08-28 | crates.io; conformance proven by parsing real onion addresses in `id.rs` tests |
| `sha2` | 0.11.0 | — | Device fingerprints; transcript hashes later. | none | 2026-08-28 | crates.io |
| `hmac` / `hkdf` | 0.13.0 | — | Key derivation for M1/M2 (digest 0.11 line). | none | 2026-08-28 | crates.io |
| `data-encoding` | 2.11.1 | — | RFC 4648 base32 for onion addresses and device IDs. | none | 2026-08-28 | crates.io |
| `getrandom` | 0.4.3 | `std`, `sys_rng` | OS RNG for key seeds (`getrandom::fill`). `sys_rng` selects the platform backend in 0.4. | none | 2026-08-28 | crate source `src/lib.rs` |
| `zeroize` | 1.9.0 | `derive` | Wipe seeds/secrets on drop. | none | 2026-08-28 | crates.io |
| `subtle` | 2.6.1 | — | Constant-time comparisons for pinned keys / proofs. | none | 2026-08-28 | crates.io |
| `serde` / `serde_json` | 1.0.229 / 1.0.151 | `derive` | Config, session log, JSON CLI output. | none | 2026-08-28 | crates.io |
| `toml` | 1.1.4 | — | `config.toml`, trusted-devices file. | none | 2026-08-28 | crates.io |
| `thiserror` / `anyhow` | 2.0.20 / 1.0.104 | — | Library errors / binary errors. | none | 2026-08-28 | crates.io |
| `tracing` / `tracing-subscriber` / `tracing-appender` | 0.1.44 / 0.3.23 / 0.2.5 | `env-filter`, `fmt`, `json` | Local logging (no telemetry). | none | 2026-08-28 | crates.io |
| `directories` | 6.0.0 | — | Per-OS base directories (`BaseDirs`). | none | 2026-08-28 | crate source `src/lib.rs` |
| `fs-err` | 3.3.1 | — | I/O errors that include the path. | none | 2026-08-28 | crates.io |
| `time` | 0.3.55 | `formatting`, `parsing`, `macros`, `serde` | RFC 3339 timestamps in `sessions.log`. | none | 2026-08-28 | crates.io |
| `clap` | 4.6.6 | `derive`, `env` | CLI. | none | 2026-08-28 | crates.io |
| `hex` | 0.4.3 | — | Fingerprint rendering. | none | 2026-08-28 | crates.io |
| `tokio` | 1.53.1 | rt, macros, sync, time, net, io-util, fs, signal | Async runtime for M1+ (Arti and quinn both require it). | none | 2026-08-28 | crates.io |
| `bytes` / `parking_lot` | 1.12.1 / 0.12.5 | — | Buffers / locks for M1+. | none | 2026-08-28 | crates.io |
| `tempfile` / `proptest` (dev) | 3.27.0 / 1.11.0 | — | Tests. | none | 2026-08-28 | crates.io |

## Milestone 1+ (verified pins land here as each milestone starts)

See `docs/research/*.md` for the sourced API notes; the consolidated pin table is
`docs/research/SUMMARY.md`. Rows are promoted into this file when the crate enters
the workspace `Cargo.toml`.
