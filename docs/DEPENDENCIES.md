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

## Milestone 1 (tornect-signal: embedded Arti)

All `arti-client` / `tor-*` crates are released in lock-step and are pinned to the
**same exact version** (`=0.45.0`, Arti 2.5.1 line, 2026-08-03); mixing versions
does not type-check (`docs/research/arti.md` §1). The `tor-pow` cargo feature of
`tornect-signal` (default on) adds `arti-client/hs-pow-full` + `tor-hsservice/hs-pow-full`.
Never enable `arti-client` `full`, `experimental`, `native-tls` or `static`.

Build requirements common to the whole group: a C compiler for the bundled
`libsqlite3-sys` (rusqlite `bundled`), `zstd-sys` and `liblzma-sys`, plus `ring`
(precompiled objects ship in the crate, no nasm). No OpenSSL, system sqlite/xz/zstd,
cmake, bindgen or libclang: verified by `cargo tree -i aws-lc-sys` and
`cargo tree -i openssl-sys` both reporting "did not match any packages". On the dev
VM set `TMPDIR` to a directory outside the quota-limited `/tmp` tmpfs or `cc` dies
with "Disk quota exceeded" while compiling zstd (`docs/notes/m1-track1-evidence.md`).

| Crate | Version | Features | Why | Build requirements | Verified | Source |
|---|---|---|---|---|---|---|
| `arti-client` | =0.45.0 | `default-features = false`; `tokio`, `rustls`, `compression`, `flowctl-cc`, `static-sqlite`, `onion-service-service`, `onion-service-client`, `vanguards` (+ `hs-pow-full` via `tor-pow`) | The Tor client: `TorClient`, bootstrap status, `launch_onion_service`, `connect_with_prefs`, `StreamPrefs`, `ErrorKind`. `rustls` instead of the default `native-tls` avoids OpenSSL; `static-sqlite` avoids `libsqlite3-dev`. | C compiler (bundled sqlite/zstd/xz) | 2026-08-28 mx-vm, live network | `docs/research/arti.md` §0–§2, §7, §9; crates.io |
| `tor-hsservice` | =0.45.0 | — (+ `hs-pow-full` via `tor-pow`) | Onion-service types: `RendRequest`/`StreamRequest`, `RunningOnionService`, `OnionServiceStatus`, `HsNickname`, `HsIdKeypairSpecifier`, `TokenBucketConfig`. | none | 2026-08-28 | arti.md §8, `tor-hsservice-0.45.0/src/{lib,req,status,config,keys}.rs` |
| `tor-hscrypto` | =0.45.0 | — | `HsId`, `HsIdKey`, `HsIdKeypair` (identity ↔ address). | none | 2026-08-28 | arti.md §8.2; `tor-hscrypto-0.45.0/src/pk.rs` |
| `tor-llcrypto` | =0.45.0 | — | `ed25519::ExpandedKeypair::from_secret_key_bytes` — the expanded-key form Arti stores (decision M1-1). | none | 2026-08-28 | `tor-llcrypto-0.45.0/src/pk/ed25519.rs` 206–235 |
| `tor-keymgr` | =0.45.0 | `keymgr` | Public keystore API used to install the identity key and to remove it on rotation: `ArtiNativeKeystore::from_path_and_mistrust`, `KeyMgrBuilder`, `KeyMgr::{get,insert}`, `KeystoreSelector`; `KeyMgr::{list_matching,remove_entry}` with `KeyPathPattern::Arti("hss/<nick>/**")` (`forget_identity`). | none | 2026-08-28 | arti.md §11 option 2; `tor-keymgr-0.45.0/src/{mgr.rs,keystore/arti.rs}` |
| `tor-rtcompat` | =0.45.0 | `tokio`, `rustls` | `TokioRustlsRuntime::current()` wraps Tornect's tokio runtime for Arti. | none | 2026-08-28 | arti.md §5; `tor-rtcompat-0.45.0/src/tokio.rs` 207 |
| `tor-cell` | =0.45.0 | — | `relaycell::msg::{Connected, End, EndReason}` for accepting/rejecting stream requests. | none | 2026-08-28 | arti.md §8.3 |
| `tor-proto` | =0.45.0 | — | `stream::IncomingStreamRequest` (`Begin` + port check); `DataStream` tokio I/O impls. | none | 2026-08-28 | arti.md §8.3; `tor-proto-0.45.0/src/stream/incoming.rs`, `client/stream/data.rs` 722–749 |
| `tor-persist` | =0.45.0 | `state-dir` (experimental marker; the same code `tor-hsservice` already compiles in) | `state_dir::StateDirectory::acquire_instance` + `InstanceStateHandle::purge`: takes the very instance lock a running service holds (refusing with `ErrorSource::AlreadyLocked` while it does), then deletes the service's `hss/<nickname>/` state and its lock file, `fs-mistrust`-checked, when an identity is rotated (`forget_identity`, decision M1-6). `HsNickname` implements its `InstanceIdentity` (`kind = "hss"`). | none | 2026-08-28 | `tor-persist-0.45.0/src/state_dir.rs` (`acquire_instance`, `InstanceStateHandle::purge`); `src/hsnickname.rs` 73; `tor-hsservice-0.45.0/src/lib.rs` 312 |
| `safelog` | 0.9 | — | `DisplayRedacted`: `HsId` has no plain `Display`, only `display_unredacted()`. | none | 2026-08-28 | arti.md §13.3 |
| `rustls` | =0.23.43 | `default-features = false`; `ring`, `std` | The one TLS crypto provider for Arti (via `futures-rustls`) and later quinn; installed by `install_crypto_provider()` (decision M1-3). | C compiler for `ring` | 2026-08-28 | `docs/research/quic.md` §1.2–§2 |
| `futures` | 0.3.34 | — | `StreamExt` for Arti's status/request streams. | none | 2026-08-28 | crates.io |

`tor-config` is *not* a direct dependency: `BoolOrAuto` comes from the
`arti_client::config` re-exports (the M1 track-1 tree declared it unused; removed
2026-08-28).

## Fuzzing (`fuzz/`, excluded from the workspace, nightly only)

| Crate | Version | Features | Why | Build requirements | Verified | Source |
|---|---|---|---|---|---|---|
| `libfuzzer-sys` | 0.4.13 | — | `fuzz_target!` for `cargo +nightly fuzz run framing` (`docs/PLAN.md` §D.5: fuzz every wire parser). `fuzz/Cargo.toml` builds `tornect-signal` with `default-features = false` (no `tor-pow` JIT) and has its own lock file. | nightly toolchain (`-Zsanitizer`), C++ compiler for libFuzzer | 2026-08-28 mx-vm | crates.io (`max_version` 0.4.13) |

## Milestone 2+ (verified pins land here as each milestone starts)

See `docs/research/*.md` for the sourced API notes; the consolidated pin table is
`docs/research/SUMMARY.md`. Rows are promoted into this file when the crate enters
the workspace `Cargo.toml`.
