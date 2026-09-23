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
| `arti-client` | =0.45.0 | `default-features = false`; `tokio`, `rustls`, `compression`, `flowctl-cc`, `static-sqlite`, `onion-service-service`, `onion-service-client`, `vanguards`, `pt-client` (2026-09-21, M1-38: implies `bridge-client`, adds `tor-ptmgr` =0.45.0 MIT/Apache-2.0) (+ `hs-pow-full` via `tor-pow`) | The Tor client: `TorClient`, bootstrap status, `launch_onion_service`, `connect_with_prefs`, `StreamPrefs`, `ErrorKind`. `rustls` instead of the default `native-tls` avoids OpenSSL; `static-sqlite` avoids `libsqlite3-dev`. | C compiler (bundled sqlite/zstd/xz) | 2026-08-28 mx-vm, live network | `docs/research/arti.md` §0–§2, §7, §9; crates.io |
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

## Milestone 1 (tornect-signal: envelope protocol, pairing, trusted stores)

| Crate | Version | Features | Why | Build requirements | Verified | Source |
|---|---|---|---|---|---|---|
| `minicbor` (+ `minicbor-derive` 0.19.5, transitive) | =2.3.0 | `std`, `derive` | The §B.3 envelope (`Encoder`/`Decoder` by hand: definite five-item array, `bytes` bodies, `null`/64-byte `sig`) and every §B.8.4.1 body as `#[cbor(map)]` structs with `#[n(k)]` integer keys: unknown keys are skipped on decode, missing `Option`s default to `None` (`minicbor-derive` docs items 2–3), `#[cbor(with = "minicbor::bytes")]` decodes `[u8; N]` with an exact-length check (`bytes.rs` 191–200 `ByteArray::decode`) and `Option<[u8; N]>` as `null`/bytes (467–495). Signatures cover the raw body bytes, so no canonical encoding is needed (decision M1-7). License: **BlueOak-1.0.0** (both crates; permissive, notice-preserving, GPL-3.0-or-later compatible) — allowed in `deny.toml` `[licenses].allow` with a comment naming them (review finding, 2026-08-29). | none | 2026-08-29 mx-vm | crate source `minicbor-2.3.0/src/{decode/decoder.rs,bytes.rs}`, `minicbor-derive-0.19.5/src/lib.rs` |
| `unicode-normalization` | =0.1.25 | — | NFKC-normalizes a peer-declared name before it is pinned as a label (`pairing::normalize_label`; the stripping/bounding half lives in `tornect-core::trusted::sanitize_label`, which has no such dependency). | none | 2026-08-29 mx-vm | crate source `src/lib.rs` (`UnicodeNormalization::nfkc`) |
| `hkdf` / `hmac` / `sha2` / `subtle` / `ed25519-dalek` | as M0 | — | SAS derivation (`Hkdf<Sha256>`, salt `tornect/v1/sas`, info `sas-v1`), transcript hashes and digests, `verify_strict` on every peer signature, constant-time `quic_spki` compare (`ConstantTimeEq` on slices). | none | 2026-08-29 mx-vm | `docs/research/crypto.md` §4, §6, §10 |
| `tokio` (dev) | as M0 | + `test-util` | `tokio::time::pause` / `start_paused` drive every §B.8.4.5 timer in the FSM tests without waiting. | none | 2026-08-29 mx-vm | tokio docs (`time::pause`) |

## Milestone 1 (tornect-core: unattended store, limiter, guard, IPC types)

The `minicbor` and `unicode-normalization` rows above also cover `tornect-core`: the
encrypted store and the IPC message set are `#[cbor(map)]` structs with integer keys
(`grant.rs`, `ipc.rs`; a `zbytes` helper decodes byte strings straight into
`Zeroizing<Vec<u8>>`), the password policy uses `nfc()` and `grant::sanitize_label` `nfkc()`.
`hmac`/`hkdf` 0.13 (M0 rows) derive `K_unatt`/`K_log` and tag the log chain;
`parking_lot` (M0 row) is the store mutex.

| Crate | Version | Features | Why | Build requirements | Verified | Source |
|---|---|---|---|---|---|---|
| `chacha20poly1305` (+ `aead` 0.6.1, `chacha20` 0.10.2, `poly1305` 0.9.1 transitive) | =0.11.0 | `zeroize`; defaults `alloc` + `getrandom` | XChaCha20-Poly1305 AEAD of `unattended.bin` (§B.8.9): `XChaCha20Poly1305::new(&Key)`, `aead::Aead::{encrypt, decrypt}` with `Payload { msg, aad }` (the 37-byte header is the AAD), `XNonce = Array<u8, U24>` built with `From<[u8; 24]>` (`Array::from_slice` is deprecated on the hybrid-array line). U4 flips every byte of a sealed file and asserts `BadTag`. | none | 2026-08-29 mx-vm | crate source `chacha20poly1305-0.11.0/src/lib.rs` 33–140, `aead-0.6.1/src/lib.rs` 131–215, 421–433 |
| `zxcvbn` | =3.1.1 | default (`builder`) | Password strength (§B.8.7.2): `zxcvbn(pw, &[&str]) -> Entropy`, `Entropy::score() -> Score` (`u8::from`, 0–4), `feedback().warning()` for the refusal text. Pulls `fancy-regex` 0.18 and `derive_builder` 0.20; `web-sys` is a wasm-only dependency, not compiled here. | none | 2026-08-29 mx-vm | crate source `zxcvbn-3.1.1/src/lib.rs` 86–149, `scoring.rs` 11–48, `feedback.rs` 137–155 |
| `keyring-core` | =1.0.0 | — (optional; `tornect-core/keyring`) | Keychain abstraction for `K_master` (§B.8.9, `ui.md` §5.9 — never `keyring::Entry`): `CredentialStore::build(service, user, None) -> Entry`, `Entry::{get_secret, set_secret, delete_credential}`, `Error::{NoEntry, NoStorageAccess, …}` (non-exhaustive); `mock::Store::new()` for tests. | none | 2026-08-29 mx-vm | crate source `keyring-core-1.0.0/src/{lib.rs 120–210, api.rs, error.rs, mock.rs 197–215}` |
| `linux-keyutils-keyring-store` (+ `linux-keyutils` 0.2.5) | =1.0.0 | — (optional; Linux only; `tornect-core/keyring`) | The kernel keyutils credential store: `Store::new() -> Result<Arc<Store>>`, descriptions `keyring:<service>@<user>`, `CredentialPersistence::UntilReboot` (in-memory: it can never satisfy the §B.8.9 canary, so it is **test / CI only** — `KeyringSecretStore::new` refuses every store that is not `UntilDelete` (r7 review), `new_volatile()` / `linux_keyutils()` exist for the round-trip test; the file store is the fallback until the M6 backends land). The mx-vm kernel keyring round-trip passed (`--ignored` test `linux_keyutils_roundtrip`). | none | 2026-08-29 mx-vm | crate source `linux-keyutils-keyring-store-1.0.0/src/{lib.rs, store.rs 33–70, cred.rs}` |

## Milestone 1 (tornect-platform: IPC endpoint, OS re-authentication)

| Crate | Version | Features | Why | Build requirements | Verified | Source |
|---|---|---|---|---|---|---|
| `zbus` | =5.19.0 | `default-features = false`; `tokio` | The Linux `ReAuth` backend (§B.8.6.2, §B.8.8, §B.8.14): `Connection::system()` + `call_method` for `org.freedesktop.PolicyKit1.Authority.CheckAuthorization` (in `(sa{sv})sa{ss}us`, out `(bba{ss})`). Pure-Rust D-Bus — no `libdbus`, and **no PAM headers**, because polkit runs the PAM conversation out of process in its setuid `polkit-agent-helper-1` (journal: `polkit-agent-helper-1: pam_unix(polkit-1:auth): conversation failed`). `async-io` off keeps one runtime in the process; `blocking-api` off because `zbus::blocking` would build a second private multi-thread tokio runtime. Called from `spawn_blocking` via `Handle::block_on`; the offline CLI builds a `current_thread` runtime. MSRV 1.87, edition 2024, unifies with the pinned `tokio` 1.53.1. `zvariant` 5.15.0 and friends arrive transitively and need no pin (`zbus::zvariant` re-export); all 17 new transitive crates are MIT or MIT OR Apache-2.0, already allowed in `deny.toml`. | a running D-Bus **system** bus (`/run/dbus/system_bus_socket`); nothing else — no C compiler, no `libdbus-1-dev`, no `pkg-config` | 2026-09-04 mx-vm, built in 30 s and exercised against live polkitd 127 | crate manifest `zbus-5.19.0/Cargo.toml`; crates.io `/api/v1/crates/zbus`; `zbus-5.19.0/README.md` and `src/utils.rs`; live `busctl introspect` + `gdbus introspect` of `org.freedesktop.PolicyKit1` |

| `rustix` | =1.1.4 | `default-features = false`; `std`, `termios`, `stdio` | The echo-off password prompt of `tornect unattended grant|set-password` (§B.8.7.4: "passwords via TTY prompt, never argv"): `termios::{isatty, tcgetattr, tcsetattr}` with `LocalModes::ECHO` cleared and restored on every exit path. Already present in the tree as a transitive dependency at this exact version, so taking it as a direct one adds no crate, no license question and no new build requirement — and it keeps `apps/tornect` free of `libc` and of `unsafe`. API read from the vendored source, not recalled. | none | 2026-09-05 mx-vm | vendored `rustix-1.1.4/src/termios/{tc.rs, tty.rs, types.rs}` and its `Cargo.toml` feature table |

**No `libc` / `nix` / `rustix` pin for the IPC peer check.** `tokio::net::UnixStream::peer_cred() -> io::Result<UCred>` is already available under the `net` feature this workspace pins (tokio 1.53.1 `stream.rs:966`, `cfg(all(unix, feature = "net"))`); `uid()`/`gid()` are `u32` on every Unix, `pid()` is `Option<i32>` and is used for diagnostics only. `tornect-platform` compares the peer's uid against the owner of the socket file it created, so it needs no `getuid()` call and stays `#![forbid(unsafe_code)]`.

**polkit subject kind.** `system-bus-name` with the connection's own unique name, **not** `unix-process` (deprecated upstream for the PID/start-time race behind CVE-2017-7572) and **not** `unix-session` (crashed polkitd 127 on this machine twice, `status=6/ABRT`, from two different clients).

## Bundled binaries (not crates)

| Binary | Version | Source | Why | Verified |
|---|---|---|---|---|
| `lyrebird` / `lyrebird.exe` | 0.8.1 (Tor Browser 15.0.23 tor-expert-bundle) | archive.torproject.org, GPG-verified (Tor Browser Developers `EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290`), SHA-256 pinned in `packaging/pt/SOURCES.md` | The managed pluggable transport for obfs4 **and** Snowflake bridges (M1-38); run by Arti's `tor-ptmgr`, never linked | 2026-09-21 mx-vm: signatures good, hashes match, `lyrebird -version` = 0.8.1, live obfs4 + Snowflake bootstraps (`docs/research/bridges.md` §8) |

## Fuzzing (`fuzz/`, excluded from the workspace, nightly only)

| Crate | Version | Features | Why | Build requirements | Verified | Source |
|---|---|---|---|---|---|---|
| `libfuzzer-sys` | 0.4.13 | — | `fuzz_target!` for `cargo +nightly fuzz run framing` (`docs/PLAN.md` §D.5: fuzz every wire parser). `fuzz/Cargo.toml` builds `tornect-signal` with `default-features = false` (no `tor-pow` JIT) and has its own lock file. | nightly toolchain (`-Zsanitizer`), C++ compiler for libFuzzer | 2026-08-28 mx-vm | crates.io (`max_version` 0.4.13) |
| `tornect-core` (path), `tokio` `test-util` + `time` | — | — | The `envelope` target (F1, §B.8.15) builds fixed host/device identities and in-memory trusted/known-host stores, re-signs fuzzed frames over the running transcript, and runs both FSMs on a paused-time runtime so every §B.8.4.5 timer fires at once when the input ends. | nightly toolchain | 2026-08-29 mx-vm | `fuzz/fuzz_targets/envelope.rs` |
| `arbitrary` | =1.4.2 | — | The F3 target (`fuzz/fuzz_targets/store.rs`, §B.8.15) builds `UnattendedStore` / `FailState` values and `(wall, mono)` clock readings from the fuzzer's bytes with `Unstructured::{arbitrary, int_in_range, ratio}` (`src/unstructured.rs` 86–604 in the crate source); no derive — core types keep no `Arbitrary` impls, the target assembles them field by field. Pinned in the workspace table too (`arbitrary = "=1.4.2"`, unused there until a crate derives it); `minicbor` and `zeroize` in `fuzz/Cargo.toml` reuse the workspace pins. MIT OR Apache-2.0. | nightly (with the fuzz crate) | 2026-08-29 mx-vm | crate source `~/.cargo/registry/src/*/arbitrary-1.4.2/src/unstructured.rs`; `fuzz/Cargo.lock` checksum `c3d036a3…8bf1` |

## Vertical slice (M1-39 / M3-1; pins verified 2026-09-21, `docs/research/slice.md`)

| Crate | Version | Features | Why | Build requirements | Verified | Source |
|---|---|---|---|---|---|---|
| `hmac` / `sha2` / `subtle` (existing pins) | 0.13.0 / 0.11.0 / 2.6.1 | — | `tornect-proto` bind MAC + constant-time check | none | 2026-09-21 (tests) | — |
| `openh264` | =0.9.8 | `source` | Software H.264 encode/decode, always compiled (M0-5); BT.601 converters | C++ compiler (`cc`); nasm optional; on gnullvm `CXXSTDLIB=c++` + `+crt-static` | 2026-09-21 mx-vm: Linux tests + Windows gnullvm link | slice.md §1, §3 |
| `x11rb` | =0.13.2 | `xtest`, `xfixes` | X11 capture (GetImage) and XTEST injection, X11 sessions only | none (pure-Rust connection) | 2026-09-21 build | slice.md §5 |
| `windows-sys` | =0.61.2 | `Win32_Foundation`, `Win32_Graphics_Gdi`, `Win32_UI_WindowsAndMessaging`, `Win32_UI_Input_KeyboardAndMouse`, `Win32_UI_HiDpi` | GDI capture, `SendInput`, DPI awareness | none (raw-dylib) | 2026-09-21 gnullvm check | slice.md §6 |
| `winit` | =0.30.13 | defaults: `rwh_06`, `x11`, `wayland`, `wayland-dlopen`, `wayland-csd-adwaita` (CSD is required on GNOME) | The window's event loop, driven by hand (`apps/tornect/src/ui/app.rs`, D10: never eframe), so the stream window reads `WindowEvent::KeyboardInput` before egui and takes each key's platform scancode from `platform::scancode::PhysicalKeyExtScancode::to_scancode` (Linux: evdev, the X11/Wayland keycode − 8; Windows: Set-1 with E0 in the high byte; `ui/keys.rs`). Its GNOME title bar pulls `ttf-parser` (unmaintained, RUSTSEC-2026-0192, ignored in `deny.toml` with the reason: local system fonts only). Apache-2.0 | none at build time: libwayland, libxkbcommon, Xlib/XCB are `dlopen`ed | 2026-09-23 mx-vm: builds; the window ran under Xvfb (X11) in `tornect gui --preview`; `winit_physical_keys_map_through_their_scancode` on Linux | `winit-0.30.13/src/platform/scancode.rs`, `src/platform_impl/linux/common/xkb/keymap.rs` 290, `src/platform_impl/windows/keyboard.rs` 904; slice.md §2 |
| `egui` | =0.36.2 | defaults (`default_fonts`) | The screens (`ui/view.rs`): home, the question cards, the sharing banner, the stream window's bar; drawn from the model alone (`Context::run_ui`). Its bundled fonts (`epaint_default_fonts`) are OFL-1.1 and Ubuntu-font-1.0, allowed for that crate only in `deny.toml`. MIT OR Apache-2.0 | none | 2026-09-23 mx-vm: `every_screen_state_draws`, `the_stream_window_reports_where_the_picture_is` (no GPU) | `egui-0.36.2/src/context.rs` 794 (`run_ui`), `src/containers/panel.rs` |
| `egui-winit` | =0.36.2 | `default-features = false`; `clipboard`, `wayland`, `x11` (no `links`) | winit events into egui (`State::on_window_event`, `take_egui_input`, `handle_platform_output`); the clipboard for "Copy" the ID. During a control session the stream window keeps keyboard events from it. MIT OR Apache-2.0 | none (arboard and smithay-clipboard are pure Rust over the dlopened display libraries) | 2026-09-23 mx-vm: builds; ran under Xvfb | `egui-winit-0.36.2/src/lib.rs` 138, 264, 295, 1078 |
| `egui-wgpu` | =0.36.2 | **`default-features = false`**; `winit`, `wayland`, `x11` (the defaults turn on every wgpu backend and webgl) | The painter per window (`winit::Painter::new` / `set_window` through `pollster`, `paint_and_update_textures`); the stream window's painter runs on the main window's device (`WgpuSetup::Existing`). The video texture is registered once with `Renderer::register_native_texture` and re-pointed with `update_egui_texture_from_wgpu_texture` on a size change. MIT OR Apache-2.0 | none | 2026-09-23 mx-vm: `pictures_reach_the_texture_on_a_headless_device` (llvmpipe, Vulkan) | `egui-wgpu-0.36.2/src/winit.rs` 61, 189, 476; `src/renderer.rs` 774, 795; `src/setup.rs` |
| `wgpu` | =30.0.1 | `default-features = false`; `std`, `wgsl`, `parking_lot`; backends per target in `apps/tornect/Cargo.toml`: Linux `vulkan`, `gles`; Windows `dx12` (a target with no backend panics in `Instance::new`; macOS has none yet) | One native `Rgba8Unorm` texture per stream, written with `queue.write_texture` and tight rows (`bytes_per_row = 4 × width`; only texture-to-buffer copies need 256-byte rows); a new texture only when the picture's size changes. MIT OR Apache-2.0 | none at build time: Vulkan and EGL/GL are loaded at run time; dx12 on Windows | 2026-09-23 mx-vm: the headless upload test and the Xvfb window both on llvmpipe (Mesa 26.0.3, Vulkan); `cargo check --target x86_64-pc-windows-gnullvm -p tornect` rc 0 (dx12 compiled, not run) | `wgpu-30.0.1/src/api/queue.rs` 253; slice.md §2 |
| `pollster` | =1.0.1 | — | `block_on` for the painter's async `new` and `set_window`, on the UI thread, once per window. Apache-2.0 OR MIT | none | 2026-09-23 mx-vm | slice.md §2 |
| `ashpd` | =0.13.13 | `default-features = false`; `tokio`, `screencast`, `remote_desktop` | The Wayland backend's portal session (`tornect-capture`'s `wayland` module, slice.md §4): one RemoteDesktop session that also selects a ScreenCast monitor (`create_session` → `select_devices(Keyboard\|Pointer, ExplicitlyRevoked, restore token)` → `select_sources(Monitor, Embedded)` → `start` → `open_pipe_wire_remote`), then the `Notify*` input calls; `connect_to_eis` is never called. Pure Rust over the pinned `zbus` 5.19, which it re-exports (`ashpd::zbus`). The session opens a **connection of its own**, because `Proxy::new` would share a process-wide one (`static SESSION: OnceLock`, `src/proxy.rs`) bound to whichever tokio runtime created it first, and it runs on a current-thread runtime on a dedicated thread. Its `tracing` feature stays off: it logs request bodies, which carry the restore token. Every dependency it has was already in the lock (only `ashpd` itself was added). MIT. MSRV 1.87 | at run time a D-Bus session bus and xdg-desktop-portal with a RemoteDesktop backend (GNOME: xdg-desktop-portal-gnome 50 with mutter 50.1 on the dev VM); nothing at build time | 2026-09-22 mx-vm: builds; unit tests (no portal); the live session needs the dialog (docs/VERIFICATION.md) | `ashpd-0.13.13/src/desktop/{remote_desktop,screencast,session,request}.rs`, `src/proxy.rs`; research report §3 |
| `libloading` | =0.8.9 | — | `dlopen("libpipewire-0.3.so.0")` and 20 `dlsym`s for the screen-cast stream (research report §4.1–§4.2), so the Wayland backend needs neither PipeWire headers nor libclang. The library is loaded once per process and never unloaded (PipeWire keeps global state and threads). The same 0.8 line `wgpu-hal` pulls; 0.9.0 exists (MSRV 1.88). ISC | at run time `libpipewire-0.3.so.0` (the mirrored 1.6.2 structs are byte-identical to 1.6.9; `pw_buffer`'s trailing fields are never read, so older 1.x work too); nothing at build time | 2026-09-22 mx-vm: every symbol resolves against PipeWire 1.6.2 (`the_installed_library_has_every_function`) | `libloading-0.8.9/src/safe.rs` 84, 148; `nm -D` of the VM's library |

## Milestone 2+ (verified pins land here as each milestone starts)

See `docs/research/*.md` for the sourced API notes; the consolidated pin table is
`docs/research/SUMMARY.md`. Rows are promoted into this file when the crate enters
the workspace `Cargo.toml`.
