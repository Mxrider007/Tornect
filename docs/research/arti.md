# Research note: embedding Arti (Tor in Rust) in Tornect

Date: 2026-08-28. Verified against crates.io API, the extracted crate sources under
`/tmp/crates-src/<crate>-<version>/` (downloaded from `static.crates.io`), the Tor
Project release blog, and three compile probes plus one live-network run on this VM (`/tmp/probe-arti`, `/tmp/probe-arti-exp`, see §4, §17).
Every claim below cites a URL or a path into the extracted crate source.

---

## 0. TL;DR for implementers

```toml
# crates/tornect-signal/Cargo.toml  (exact pins; all arti sub-crates share one version)
[dependencies]
arti-client   = { version = "=0.45.0", default-features = false, features = [
    "tokio", "rustls", "compression", "flowctl-cc", "static-sqlite",
    "onion-service-service", "onion-service-client", "vanguards",
] }
tor-hsservice = "=0.45.0"   # RendRequest / StreamRequest / handle_rend_requests / HsNickname / status
tor-hscrypto  = "=0.45.0"   # HsId, HsClientDescEncKey
tor-rtcompat  = { version = "=0.45.0", features = ["tokio", "rustls"] }  # TokioRustlsRuntime
tor-cell      = "=0.45.0"   # relaycell::msg::{Connected, End, EndReason}
tor-proto     = "=0.45.0"   # stream::IncomingStreamRequest, client::stream::DataStream
tor-config    = "=0.45.0"   # BoolOrAuto / ExplicitOrAuto (also re-exported by arti_client::config)
safelog       = "0.9"       # DisplayRedacted trait: HsId has NO plain Display impl
rustls        = { version = "0.23", default-features = false, features = ["ring"] }  # or aws-lc-rs
tokio         = { version = "1", features = ["rt-multi-thread", "macros", "io-util", "time"] }
futures       = "0.3"
```

- `rustls` + `tokio`, **no** `native-tls`: compiles and links on this VM with no
  OpenSSL / sqlite / zstd / xz dev headers (verified §4).
- The application **must** call `rustls::crypto::<provider>::default_provider().install_default()`
  once before creating the runtime (tor-rtcompat requirement, §5).
- `onion-service-service` / `onion-service-client` / `vanguards` are **stable** features.
- `hs-pow-full` (PoW) and `restricted-discovery` (client auth) and `experimental-api`
  are **still marked experimental in arti-client 0.45.0** (`__is_experimental`), see §2.
- Onion key persists automatically in `<state_dir>/keystore` via `ArtiNativeKeystore`
  (enabled by default when `keymgr` is on, which `onion-service-service` implies).
- MSRV 1.91, edition 2024 (`arti-client-0.45.0/Cargo.toml` lines 13–14). VM has 1.96.

---

## 1. Versions and the arti ↔ arti-client numbering

| crate | latest stable | published | MSRV | source |
|---|---|---|---|---|
| `arti-client` | **0.45.0** | 2026-08-03 | 1.91 | https://crates.io/api/v1/crates/arti-client |
| `tor-hsservice` | 0.45.0 | 2026-08-03 | 1.91 | https://crates.io/api/v1/crates/tor-hsservice |
| `tor-hscrypto` | 0.45.0 | 2026-08-03 | 1.91 | https://crates.io/api/v1/crates/tor-hscrypto |
| `tor-rtcompat` | 0.45.0 | 2026-08-03 | 1.91 | https://crates.io/api/v1/crates/tor-rtcompat |
| `tor-keymgr` | 0.45.0 | 2026-08-03 | 1.91 | https://crates.io/api/v1/crates/tor-keymgr |
| `tor-cell`, `tor-proto`, `tor-config`, `tor-hsrproxy` | 0.45.0 | 2026-08-03 | 1.91 | crates.io |
| `arti` (CLI binary crate) | **2.5.1** | 2026-08-03 | 1.91 | https://crates.io/api/v1/crates/arti |

All `tor-*` / `arti-client` crates are released in lock-step with identical version
numbers; `arti-client-0.45.0/Cargo.toml` pins every `tor-*` dependency to `0.45.0`
(lines 359–446). **Pin all of them to the same exact version** — mixing 0.44 and
0.45 sub-crates will not type-check.

The Arti *project* version (what the plan calls "Arti 2.0") is the version of the
`arti` CLI crate, not of `arti-client`:

| Arti release | date | `arti-client` | notes |
|---|---|---|---|
| 2.0.0 | 2026-02-02 | 0.39.0 | blog: https://blog.torproject.org/arti_2_0_0_released/ |
| 2.1.0 | 2026-03-03 | 0.40.0 | MSRV→1.89; config system rewritten on `derive-deftly` |
| 2.2.0 | 2026-03-31 | 0.41.0 | HTTP CONNECT; TROVE-2026-005 |
| 2.3.0 | 2026-05-07 | 0.42.0 | announces `TorClient` will be explicitly `Arc`-wrapped next release |
| 2.4.0 | 2026-06-01 | 0.43.0 | "multiple breaking changes to the `TorClient` APIs"; HS client connectivity fixes |
| 2.5.0 | 2026-06-30 | 0.44.0 | MSRV→1.91; flowctl-cc default; TROVE-2026-024/027 (DoS) |
| 2.5.1 | 2026-08-03 | 0.45.0 | HS→unix-socket targets; experimental CC + CGO on HS circuits |

(arti-client version dates from https://crates.io/api/v1/crates/arti-client `versions[]`.)

Repository: `https://gitlab.torproject.org/tpo/core/arti.git/` (Cargo.toml `repository`),
default branch `main`. GitLab returns HTTP 403 to non-browser fetches (raw and
blob), so CHANGELOG.md could not be pulled programmatically; the release blog
posts were used instead (§14). The crate tarballs do not ship CHANGELOG.

---

## 2. Feature flags (verified from `arti-client-0.45.0/Cargo.toml` lines 47–246)

### 2.1 Defaults and what we turn off

```
default = ["tokio", "native-tls", "compression", "flowctl-cc"]
```

`native-tls` → `tor-rtcompat/native-tls` → `native-tls-crate` + `async-native-tls`
→ OpenSSL on Linux (needs `libssl-dev`, absent on this VM). So we use
`default-features = false` and re-add `tokio`, `compression`, `flowctl-cc`
explicitly plus `rustls`.

### 2.2 Feature table

| feature | expands to (Cargo.toml) | status | Tornect |
|---|---|---|---|
| `tokio` | `tor-async-utils/tokio`, `tor-rtcompat/tokio`, `tor-proto/tokio` | stable | **on** |
| `rustls` | `tor-rtcompat/rustls`, `__is_nonadditive` | stable, "not currently included in `full`" (README line 269) | **on** |
| `compression` | `tor-dirmgr/compression` → `tor-dirclient/{xz,zstd}` → `async-compression/{xz,zstd}` | stable; "Requires a C compiler" (README line 250) | **on** (see §4: builds from source, no system libs) |
| `flowctl-cc` | `tor-circmgr/flowctl-cc` | stable since 2.4.0, default since 2.5.0 | on |
| `static-sqlite` | `tor-dirmgr/static` → `rusqlite/bundled` | `__is_nonadditive` build flag | **on** — required here (no `libsqlite3-dev`) |
| `onion-service-service` | `tor-hsservice`, `tor-hscrypto`, `tor-persist/state-dir`, `keymgr` | **stable** (non-experimental since Arti 1.2.0) | **on** |
| `onion-service-client` | `tor-hsclient`, `tor-hscrypto` | **stable** | **on** |
| `keymgr` | `tor-keymgr/keymgr`, `tor-hsclient/keymgr` | stable (implied by service) | on |
| `vanguards` | `tor-guardmgr/vanguards`, `tor-circmgr/vanguards` | stable; "Requires that either onion-service-client or onion-service-service is also enabled" (README 256–258) | **on** |
| `hs-pow-full` | `tor-hsclient?/hs-pow-full`, `tor-hsservice?/hs-pow-full`, **`__is_experimental`** | **experimental** | see §10 |
| `restricted-discovery` | `onion-service-service`, `tor-hsservice/restricted-discovery`, **`__is_experimental`** | **experimental at arti-client level** (but non-experimental in `tor-hsservice`, where it is in `full`) | see §11 |
| `experimental-api` | `__is_experimental` | experimental; unlocks `launch_onion_service_with_hsid`, `generate_service_discovery_key`, `dirmgr()/circmgr()/hs_circ_pool()` | needed only for §11 client-key helpers |
| `full` | all stable additive features incl. `native-tls` **and** `async-std` | — | **never use** (drags in native-tls) |
| `experimental` | everything experimental incl. `smol` | — | never |
| `static` / `static-native-tls` | force native-tls | — | never |
| `accel-openssl`, `accel-sha1-asm` | OpenSSL / asm SHA1 | nonadditive | no |
| `ctor-keystore`, `ephemeral-keystore`, `onion-service-cli-extra`, `hss-negotiate-extensions`, `hsc-negotiate-extensions`, `counter-galois-onion`, `geoip`, `dirfilter`, `bridge-client`, `pt-client`, `rpc` | — | not needed | no |
| `memquota` | `[]` | deprecated no-op (README 320) | omit |

`__is_experimental` / `__is_nonadditive` are pure marker features (no source code
references them: `grep -rn __is_ arti-client-0.45.0/src` is empty). Enabling an
experimental feature compiles fine; the README (lines 295–313) only says those APIs
are "NOT covered by semantic versioning guarantees: we might break them or remove
them between patch versions" — so **pin exactly (`=0.45.0`)**, which we do anyway.

`tor-hsservice-0.45.0/Cargo.toml` features (lines 46–103): `restricted-discovery = []`
(stable there, included in `full`); `hs-pow-full = [tor-hscrypto/hs-pow-full,
tor-netdoc/hs-pow-full, tor-cell/hs-pow-full, arrayvec, equix, num-traits,
tor-checkable, __is_experimental]`.

`tor-rtcompat-0.45.0/Cargo.toml` (lines 46–99): `rustls = [futures-rustls,
dep:rustls-dont-use (=rustls 0.23.21, default-features=false), rustls-pki-types,
rustls-webpki]`; `native-tls = [native-tls-crate, async-native-tls]`;
`default = []`. `futures-rustls` is pulled with `features = ["tls12","logging"]`
and `default-features = false` — the probe's dependency graph contains **no**
`aws-lc-rs` and **no** `ring` (cargo tree, §4), i.e. **no crypto provider is
linked unless the application adds one**.

---

## 3. Compatibility constraints (versions observed in the probe lock file)

From `cargo tree` in `/tmp/probe-arti` (arti-client 0.45.0, features as in §0):

| crate | version(s) in graph | who needs it | implication for Tornect |
|---|---|---|---|
| `rustls` | 0.23.43 `[log,logging,std,tls12]` | tor-rtcompat (via futures-rustls 0.26.0) | quinn 0.11 also uses rustls 0.23 → one copy. Add the provider feature (`ring` or `aws-lc-rs`) **once** in Tornect's own `rustls` dep; the same provider serves quinn. |
| `rustls-webpki` 0.103.x, `rustls-pki-types` 1.15.1 | tor-rtcompat | | fine with quinn/rcgen 0.14 |
| `tokio` | 1.53.1 | | any tokio 1.x |
| `rand` / `rand_core` | **0.10.2 / 0.10.1** (arti public API) **and** 0.8.8 / 0.6.4 (via ed25519-dalek 2.2, x25519-dalek 2.0, curve25519-dalek 4.1, rsa 0.9, merlin) | `tor-llcrypto-0.45.0/Cargo.toml` lines 147–160: `rand = "0.10.1"`, `rand_core = "0.10.1"`, plus a `rand_core_06 = "0.6"` shim | Arti's `KeyMgr::generate(.., rng: &mut dyn KeygenRng, ..)` and `tor_llcrypto::rng::CautiousRng` are **rand_core 0.10**-based. Tornect's own device keys via `ed25519-dalek 2.x` use rand_core 0.6. Both coexist (arti itself does this); just do not try to pass one crate's RNG to the other's API. |
| `ed25519-dalek` 2.2.0, `curve25519-dalek` 4.1.3, `x25519-dalek` 2.0.1 | tor-llcrypto | | Use the **same** majors in tornect-core so key types can convert (`HsId` is a 32-byte ed25519 pubkey, `tor-hscrypto/src/pk.rs` line 34–53). |
| `digest`/`sha2`/`sha3` | 0.10.x (also a `digest 0.11.3` copy from some other dep) | tor-llcrypto `digest = "0.10"`, `sha2 = "0.10"`, `sha3 = "0.10.6"` | Use RustCrypto **0.10** line in Tornect for hashing that interacts with arti types; avoid the 0.11 pre-releases. |
| `getrandom` | 0.2 / 0.3 / 0.4 all present | transitive | none |
| `time` 0.3.55, `derive_builder_fork_arti` 0.11.2, `derive-deftly ~1.11.4` | arti config builders | Builders are generated by `derive-deftly(TorConfig)`; setter names = field names; sub-builders are accessed via `builder.section()` returning `&mut SubBuilder`. |

Total graph: 397 unique crates (`cargo tree -e normal --prefix none | sort -u | wc -l`).

---

## 4. Build requirements — verified on this VM

VM facts: Ubuntu 26.04, rustc/cargo 1.96.0, cmake + gcc/g++ + pkg-config present,
**no** `libsqlite3-dev`, `liblzma-dev`, `libzstd-dev`, `libssl-dev`
(`pkg-config --exists` for sqlite3/liblzma/libzstd/openssl all fail), no nasm, no
libclang headers.

### 4.1 Probe 1: dependency compile (`cargo check`)

`/tmp/probe-arti/Cargo.toml`: arti-client `=0.45.0`, `default-features=false`,
features `tokio, rustls, compression, onion-service-service, onion-service-client,
vanguards, static-sqlite, flowctl-cc` + tor-hsservice/tor-hscrypto/tor-rtcompat
(`tokio`,`rustls`)/tor-cell/tor-proto `=0.45.0`, tokio 1, futures 0.3, anyhow 1.

Result (`/tmp/probe-arti/check1.log`): **`Finished dev profile in 1m 40s`, exit 0**,
`CARGO_BUILD_JOBS=2`. Build scripts that compiled C from bundled sources:
`libsqlite3-sys v0.37.0` (rusqlite 0.39 `bundled`), `zstd-sys 2.0.16`,
`liblzma-sys 0.4.8` (async-compression 0.4.43 `xz`). No bindgen, no cmake, no
nasm, no OpenSSL, no system sqlite/xz/zstd required.

### 4.2 Probe 2: real API usage (`cargo check` + `cargo build`)

`/tmp/probe-arti/src/main.rs` (reproduced in §§6–9) exercises: rustls provider
install, `TokioRustlsRuntime::current()`, `TorClientConfigBuilder::from_directories`
+ keystore + `allow_onion_addrs`, `TorClient::with_runtime(..).config(..)
.bootstrap_behavior(Manual).create_unbootstrapped()`, `bootstrap_events()`,
`bootstrap()`, `OnionServiceConfigBuilder` (`nickname`, `num_intro_points`,
`max_concurrent_streams_per_circuit`), `launch_onion_service`, `onion_address()`,
`status_events()`, `handle_rend_requests`, `StreamRequest::request()/accept()/reject()`,
tokio `AsyncRead/AsyncWrite` on `DataStream`, `StreamPrefs::connect_to_onion_services`,
`connect_with_prefs((&str, u16), &prefs)`. Extra deps: `rustls 0.23 [ring]`, `safelog 0.9`.

Result: **type-checks cleanly** (`cargo check` exit 0, no warnings). `cargo build`
(debug) from a clean target dir: **2 m 44 s** with `CARGO_BUILD_JOBS=2`
(`/home/mx/.cache/tornect-probe-target`, because `/tmp` is a quota-limited tmpfs
on this VM and 2.4 GB of debug artifacts hit "Disk quota exceeded"). The resulting
binary (254 MB debug) links against **only** `libc`, `libm`, `libgcc_s`
(`ldd`), i.e. no runtime system libraries. The run against the live Tor network is
in §17.

### 4.3 What CI needs per OS (inferred from the crate graph)

| dependency | Linux CI | Windows (MSVC) | macOS |
|---|---|---|---|
| `libsqlite3-sys` bundled | cc | MSVC cl | clang |
| `zstd-sys`, `liblzma-sys` (cc-built) | cc | MSVC cl | clang |
| `ring` 0.17.14 (if chosen as provider) | C compiler; crates.io tarball ships prebuilt asm objects | "NASM is not required when building from crates.io" (https://github.com/briansmith/ring/blob/main/BUILDING.md) | clang |
| `aws-lc-rs` (if chosen instead) | cmake + C | **cmake + nasm** (aws-lc-sys) — nasm absent here | cmake |
| bindgen/libclang | not needed | not needed | not needed |

Recommendation: use **`ring`** as the rustls provider for all three OSes (no
cmake/nasm), unless Tornect wants aws-lc-rs' post-quantum hybrid handshake
(tor-rtcompat's stated preference, `tor-rtcompat-0.45.0/src/impls/rustls.rs`
lines 38–44: "We currently recommend the aws-lc-rs provider because ... it appears
to have better performance, and it supports hybrid post-quantum handshakes. It used
to have a problematic license, but this has been fixed since March 2026"). Either
works with quinn; pick one and install it once.

---

## 5. TLS: rustls-only runtime and the crypto provider

`tor-rtcompat-0.45.0/src/impls/rustls.rs` lines 32–36:

> "The application is responsible for calling `CryptoProvider::install_default()`
> before constructing `TlsProvider`. If they do not, rustls will fail, and arti
> will not run."

(Only under `cfg(test)`/`feature = "testing"` does tor-rtcompat auto-install
aws-lc-rs — lines 164–181. Production builds do **not**.)

Runtime types (`tor-rtcompat-0.45.0/src/tokio.rs`): `TokioRustlsRuntime::create()`
(owns a new tokio runtime, line 180) and `TokioRustlsRuntime::current()` (wraps the
running tokio runtime, line 207 — "This function is for Arti *users* who want to
wrap some existing Tokio runtime"). With `native-tls` off and `rustls` on,
`tor_rtcompat::PreferredRuntime` = `TokioRustlsRuntime` (tokio.rs line 24), so
`TorClient::builder()` / `create_bootstrapped()` also resolve to rustls.

```rust
// once, at process start (before any TorClient / quinn endpoint)
rustls::crypto::ring::default_provider()
    .install_default()
    .expect("install rustls provider once");
let runtime = tor_rtcompat::tokio::TokioRustlsRuntime::current()?;   // inside #[tokio::main]
```

Do **not fork** after creating a runtime (`tor-rtcompat-0.45.0/README.md` lines
~100–114: "You may not fork even after that `Runtime` value has been dropped or
shut down. You may use safe facilities like `std::process::Command`").

---

## 6. TorClientConfig: explicit state/cache dirs + keystore

Source: `arti-client-0.45.0/src/config.rs`.

- `TorClientConfigBuilder::from_directories(state_dir, cache_dir)` (lines 792–806):
  "All other configuration options are set to their defaults, except
  `storage.keystore.path`, which is derived from the specified state directory."
- `StorageConfig` (lines 185–222): `cache_dir: CfgPath` (rules of `/var/cache`,
  safe to delete), `state_dir: CfgPath`, `keystore: ArtiKeystoreConfig`
  (`#[cfg(feature = "keymgr")]`), `permissions: Mistrust`.
- Defaults if not overridden: `~/.cache/arti` and `~/.local/share/arti` — shared
  with any other arti user on the box (doc comment lines 163–173) → **always set
  Tornect's own dirs** (plan D13: `~/.config/tornect`… — use a `tor/` subtree of
  the Tornect data dir, e.g. `<data>/tor/state`, `<data>/tor/cache`).
- Keystore location is hard-coded to `<state_dir>/keystore`
  (`arti-client-0.45.0/src/client.rs` lines 323–331:
  `let key_store_dir = state_dir.join("keystore"); ArtiNativeKeystore::from_path_and_mistrust(&key_store_dir, permissions)`).
- `ArtiKeystoreConfig` (`tor-keymgr-0.45.0/src/config.rs`): `enabled: BoolOrAuto`
  (Auto ⇒ `cfg!(feature="keymgr")` = true), `primary: PrimaryKeystoreConfig { kind:
  ExplicitOrAuto<ArtiKeystoreKind> }` (Auto ⇒ `Native`); `ArtiKeystoreKind::Native`
  is the only non-experimental kind. So the on-disk keystore is on **by default**;
  setting it explicitly is belt-and-braces.
- `ClientAddrConfig::allow_onion_addrs: bool` default **true** (config.rs lines 121–123).
- `StreamTimeoutConfig::connect_timeout` default **10 s** (config.rs lines 137–155) —
  applies to `.onion` streams too (`client.rs` line 1571); raise it for onion
  connects (first HS connect = descriptor fetch + intro + rendezvous, often >10 s).
- Filesystem permission checks (`fs-mistrust`): state dir and keystore must not be
  group/world-writable or arti refuses to start; disable with
  `TorClientConfigBuilder.storage().permissions().dangerously_trust_everyone()` only
  for tests (`fs_permissions_checks_disabled_via_env`, config.rs line 843 documents
  the `ARTI_FS_DISABLE_PERMISSION_CHECKS` env var).

```rust
use arti_client::config::{BoolOrAuto, TorClientConfigBuilder};
use arti_client::TorClientConfig;

fn tor_config(app_dir: &Path) -> anyhow::Result<TorClientConfig> {
    let mut b = TorClientConfigBuilder::from_directories(
        app_dir.join("tor-state"), app_dir.join("tor-cache"));
    b.storage().keystore().enabled(BoolOrAuto::Explicit(true));   // <state>/keystore
    b.address_filter().allow_onion_addrs(true);                    // default anyway
    b.stream_timeouts().connect_timeout(Duration::from_secs(45));  // field exists, config.rs:141
    Ok(b.build()?)
}
```
(`connect_timeout` setter is generated by `derive_deftly(TorConfig)` from the field
name; the first two lines are compile-verified in the probe, the third follows the
same generated-setter pattern.)

Persistent on-disk layout under `state_dir` (`tor-hsservice-0.45.0/src/state_dir.md`,
`tor-persist`): `state/state.lock`, `state/guards.json`, `state/circuit_timeouts.json`,
`state/hs_ipts_<nick>.json`, `state/hs_iptpub_<nick>.json`, `keystore/` (KeyMgr),
plus HS IPT replay logs; `cache_dir` holds `dir_blobs/` and `dir.sqlite3`.
Keystore file paths follow `hss/<nickname>/ks_hs_id.expanded_ed25519_private`
style ArtiPaths (`tor-hsservice-0.45.0/src/keys.rs` lines 43–61: prefix `hss`,
role `KS_hs_id`).

---

## 7. Creating and bootstrapping the client; status events

Source: `arti-client-0.45.0/src/client.rs`, `src/builder.rs`, `src/status.rs`.

- `TorClient::create_bootstrapped(config).await -> Result<Arc<TorClient<PreferredRuntime>>>` (client.rs 928).
- `TorClient::builder()` (PreferredRuntime) / `TorClient::with_runtime(rt)` (958, 970)
  → `TorClientBuilder` with `.config(TorClientConfig)`, `.bootstrap_behavior(BootstrapBehavior)`,
  `.local_resource_timeout(Duration)`, `.create_unbootstrapped() -> Result<Arc<TorClient<R>>>`,
  `.create_unbootstrapped_async()`, `.create_bootstrapped().await`, `.create_inert()`
  (builder.rs 105–314). Since Arti 2.4.0 constructors return **`Arc<TorClient>`**
  explicitly (blog 2.3.0 pre-announcement; verified in source).
- `BootstrapBehavior::{OnDemand (default), Manual}` (client.rs 589–601). With
  `Manual`, using the client before `bootstrap()` fails with
  `ErrorKind::BootstrapRequired`.
- `client.bootstrap().await` (1102); `client.bootstrap_status() -> BootstrapStatus`
  (2232); `client.bootstrap_events() -> BootstrapEvents` (2243) — a `Stream<Item =
  BootstrapStatus>` backed by `postage::watch` ("isn't guaranteed to receive every
  change", status.rs 284–286).
- `BootstrapStatus::as_frac() -> f32` (0..1, "0.15 conn + 0.85 dir"),
  `ready_for_traffic() -> bool`, `blocked() -> Option<Blockage>` with
  `Blockage::kind() -> BlockageKind` and `message()` (status.rs 54–110, 145–170) —
  perfect for the UI progress bar.
- `client.isolated_client() -> Arc<TorClient<R>>` (1466) and
  `StreamPrefs::new_isolation_group()` / `set_isolation()` / `isolate_every_stream()`
  (839–875) — use an isolation group per remote peer session.
- `client.set_dormant(DormantMode::Soft)` (2254) to idle background tasks when no
  session is active (mobile-style CPU saving).
- `launch_onion_service` calls `initiate_bootstrap_if_needed` (client.rs 1937–1939):
  the service can be launched **before** bootstrap completes; it starts working once
  the directory is available.

```rust
let client: Arc<TorClient<TokioRustlsRuntime>> = TorClient::with_runtime(runtime.clone())
    .config(cfg)
    .bootstrap_behavior(BootstrapBehavior::Manual)
    .create_unbootstrapped()?;

let mut events = client.bootstrap_events();
tokio::spawn(async move {
    while let Some(st) = events.next().await {   // futures::StreamExt
        ui.set_progress(st.as_frac(), st.ready_for_traffic(), st.blocked().map(|b| b.kind()));
    }
});
client.bootstrap().await?;
```

---

## 8. Running the onion service (host side)

### 8.1 Configuration

`tor-hsservice-0.45.0/src/config.rs` `OnionServiceConfig` fields (lines 29–112),
builder = `arti_client::config::onion_service::OnionServiceConfigBuilder`
(re-export, `arti-client/src/config.rs` line 63–64); setters are named after fields:

| field | type | default | notes |
|---|---|---|---|
| `nickname` | `HsNickname` | **required** | local only, selects keys/state (`HsNickname::new(String)`, `tor-persist/src/hsnickname.rs` 48) |
| `enabled` | bool | true | `launch_onion_service` returns `Ok(None)` if false |
| `num_intro_points` | u8 | 3 | valid range **3..=20** (validate(), lines 292–307) |
| `rate_limit_at_intro` | `Option<TokenBucketConfig>` | None (consensus default) | `TokenBucketConfig::new(rate, burst)` (line 354); sent to intro points as `DOS_PARAMS`; "We do not enforce this limit ourselves" |
| `max_concurrent_streams_per_circuit` | u32 | 65535 | circuit torn down if exceeded — set small (e.g. 8) for Tornect |
| `enable_pow` | bool | false | **build error** `ConfigBuildError::NoCompileTimeSupport` unless `hs-pow-full` (lines 317–323) |
| `pow_rend_queue_depth` | usize | 8192 | ~32 MB max queue when PoW on |
| `restricted_discovery` | `RestrictedDiscoveryConfig` (sub-builder) | disabled | §11 |
| `disable_pow_compilation` | bool | false | use interpreted HashX instead of JIT |

There is **no single-onion-service / anonymity option yet** ("TODO(#727): add support
for single onion services", config.rs 96–107; `Anonymity` enum exists in
`anon_level.rs` but is unused by the config) — every Tornect host is a full
3-hop-anonymous onion service. Fine for us (we only need reachability).

### 8.2 Launch, address, status

`arti-client-0.45.0/src/client.rs` lines 1916–1967:

```rust
pub fn launch_onion_service(
    &self,
    config: tor_hsservice::OnionServiceConfig,
) -> crate::Result<Option<(
    Arc<tor_hsservice::RunningOnionService>,
    impl futures::Stream<Item = tor_hsservice::RendRequest> + use<R>,
)>>
```

Internally it builds `OnionService::builder().config(config).keymgr(keymgr)
.state_dir(state_dir).build()` and calls `.launch(runtime, dirmgr, hs_circ_pool,
path_resolver)`; **it errors with `ErrorDetail::KeystoreRequired` if the keystore
is disabled** (lines 1941–1948). `OnionService::launch` (`tor-hsservice/src/lib.rs`
268–300) calls `maybe_generate_hsid(...)` first, so the identity key is generated
on first launch and read from the keystore afterwards; "Once the
`RunningOnionService` is dropped, the onion service will stop publishing, and stop
accepting new introduction requests. Existing streams and rendezvous circuits will
remain open" (lib.rs 262–266). Keep the `Arc<RunningOnionService>` alive for the
life of the host.

- `RunningOnionService::onion_address() -> Option<HsId>` (lib.rs 571) — `None`
  only if the key is missing from every keystore. (`onion_name()` is deprecated.)
- `HsId` has **no `Display`**; use `safelog::DisplayRedacted`:
  `hsid.display_unredacted().to_string()` → `"<56 base32 chars>.onion"`
  (`tor-hscrypto/src/pk.rs` 123–133). `HsId: FromStr` parses `"xxx.onion"` and
  verifies version byte 3 + checksum (pk.rs 166–207), errors `HsIdParseError::
  {NotOnionDomain, HsIdContainsSubdomain, UnsupportedVersion, WrongChecksum, ..}`.
  `HsId` derefs to a 32-byte ed25519 public key (`pk.rs` 34–53) — this is the
  Tornect ID (plan D3).
- Getting the address **without bootstrapping** (e.g. on the ID-card screen at first
  run): `TorClient::<TokioRustlsRuntime>::create_onion_service(&tor_cfg, svc_cfg)?`
  → `OnionService`; then `svc.onion_address()` or
  `svc.generate_identity_key(KeystoreSelector::Primary)? -> HsId`
  (client.rs 2220–2228; `tor-hsservice/src/lib.rs` 410–453). This is exactly what
  `arti hss onion-address --generate=if-needed` does (`arti-2.5.1/src/subcommands/hss.rs`
  150–212). No `experimental-api` needed.
- `svc.status() -> OnionServiceStatus`, `svc.status_events() -> OnionServiceStatusStream`
  (`Stream<Item = OnionServiceStatus>`, postage watch) (lib.rs 509–521).
  `OnionServiceStatus::state() -> State` where `State ∈ {Shutdown, Bootstrapping,
  DegradedReachable, DegradedUnreachable, Running, Recovering, Broken}` and
  `State::is_fully_reachable()` = `Running | DegradedReachable`
  (`tor-hsservice/src/status.rs`). `current_problem() -> Option<&Problem>` with
  `Problem::{Runtime(FatalError), DescriptorUpload(Vec<DescUploadRetryError>),
  Ipt(Vec<IptError>), Pow(..)}`.
  The publisher reports `Running` only once the descriptor "has been uploaded to
  one or more HsDirs from both HsDir rings (primary and secondary), and none of the
  uploads failed"; `DegradedReachable` if some uploads failed; `Bootstrapping`
  while either ring has no success yet (`publish/reactor.rs` 2050–2080). The combined
  state is the worst of ipt_mgr / publisher (status.rs `state()`).
  **This is the "await reachable" API**: wait on `status_events()` until
  `st.state().is_fully_reachable()`.
- `svc.reconfigure(new_cfg, Reconfigure::WarnOnFailures)` (lib.rs 480) to change
  intro-point count / rate limits / restricted-discovery keys at runtime.

### 8.3 Accepting connections: RendRequest → StreamRequest → DataStream

`tor-hsservice-0.45.0/src/req.rs`:

- `RendRequest::accept(self).await -> Result<impl Stream<Item = StreamRequest> + Unpin, ClientError>`
  (line 209) — completes the rendezvous; `RendRequest::reject(self)` (246) — silently drop.
- `tor_hsservice::handle_rend_requests(rend_requests) -> impl Stream<Item = StreamRequest>`
  (`helpers.rs` 12–26): accepts every RendRequest concurrently (`flat_map_unordered`)
  and flattens; "If you want to reject certain RendRequests, you can use
  `StreamExt::filter`" first.
- `StreamRequest::request(&self) -> &IncomingStreamRequest` (261) — "you should
  typically only accept `BEGIN` messages, and only check the port in those messages.
  If you behave differently, your implementation will be distinguishable."
- `StreamRequest::accept(self, Connected) -> Result<DataStream, ClientError>` (266);
  `reject(self, End)` (279) — "only send back `End` messages with the `DONE` reason";
  `shutdown_circuit(self)` (288) tears down the whole rendezvous circuit.
- `IncomingStreamRequest::Begin(begin)` with `begin.port() -> u16`
  (`tor-proto/src/stream/incoming.rs` 179; `tor-cell/src/relaycell/msg.rs` 235).
- `Connected::new_empty()` (`tor-cell/src/relaycell/msg.rs` 594),
  `End::new_with_reason(EndReason::DONE)` (499).
- `DataStream` (`tor-proto/src/client/stream/data.rs`) implements **both**
  `futures::io::{AsyncRead, AsyncWrite}` (711, 732) and
  `tokio::io::{AsyncRead, AsyncWrite}` (722, 749), and `split(self) -> (DataReader,
  DataWriter)` (665). Re-exported as `arti_client::{DataStream, DataReader, DataWriter}`.
  **Always `flush()`** — "Arti buffers data, so flushing the buffer is usually
  required" (`arti-client/examples/readme.rs`).

Reference implementation to copy from: `tor-hsrproxy-0.45.0/src/proxy.rs` lines
109–209 (`handle_requests`: `handle_rend_requests(requests).fuse()`, `select_biased!`
with a shutdown oneshot, `runtime.spawn(...)` per stream) and 241–295 (`run_action`:
`DestroyCircuit → shutdown_circuit()`, `RejectStream → reject(End::new_with_reason(
EndReason::DONE))`, `IgnoreStream → drop(request)`), 346–408 (`forward_connection`:
`request.accept(Connected::new_empty())`). Host-side driver: `arti-2.5.1/src/onion_proxy.rs`
188–239 (`Proxy::launch_new`: `client.launch_onion_service(svc_cfg)?`, spawn
`handle_requests`, spawn a `status_events()` logger).

Compile-verified Tornect-shaped skeleton (`/tmp/probe-arti/src/main.rs`):

```rust
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::{HsNickname, RunningOnionService, StreamRequest, handle_rend_requests};
use tor_proto::stream::IncomingStreamRequest;
use arti_client::config::onion_service::OnionServiceConfigBuilder;
use safelog::DisplayRedacted as _;
use futures::StreamExt as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const TORNECT_PORT: u16 = 4000;   // virtual port inside the onion service

let svc_cfg = OnionServiceConfigBuilder::default()
    .nickname(HsNickname::new("tornect".to_owned())?)
    .num_intro_points(3)
    .max_concurrent_streams_per_circuit(16)
    .build()?;
let (svc, rend_requests): (Arc<RunningOnionService>, _) =
    client.launch_onion_service(svc_cfg)?.expect("enabled");
let onion: String = svc.onion_address().expect("hsid").display_unredacted().to_string();

let mut status = svc.status_events();
tokio::spawn(async move {
    while let Some(st) = status.next().await {
        // st.state().is_fully_reachable()  => show "Reachable" in the ID card
        // st.current_problem()             => surface DescriptorUpload / Ipt errors
    }
});

let mut stream_requests = Box::pin(handle_rend_requests(rend_requests));
tokio::spawn(async move {
    while let Some(req) = stream_requests.next().await {
        tokio::spawn(async move {
            match req.request() {
                IncomingStreamRequest::Begin(b) if b.port() == TORNECT_PORT => {
                    let mut ds = req.accept(Connected::new_empty()).await?;   // DataStream
                    // ... CBOR signaling over `ds` (tokio AsyncRead/AsyncWrite), remember flush()
                }
                _ => { req.reject(End::new_with_reason(EndReason::DONE)).await?; }
            }
            Ok::<_, anyhow::Error>(())
        });
    }
});
```

Where to put the "accept queue"/rate limiting from plan §B.3: filter the
`RendRequest` stream *before* `handle_rend_requests` (cheap: rejecting a
`RendRequest` does no network work, req.rs 244–249) and bound concurrent accepted
rendezvous with a semaphore; per-circuit stream count is bounded by
`max_concurrent_streams_per_circuit`.

---

## 9. Connecting to a .onion (client side)

`arti-client-0.45.0/src/client.rs` 1539–1665 and `src/address.rs`:

- `client.connect(target)` / `connect_with_prefs(target, &StreamPrefs)` accept any
  `IntoTorAddr`: `&str`, `String`, `(&str, u16)`, `(String, u16)`, `TorAddr`
  (address.rs 481–520). A host ending in `.onion` becomes `Host::Onion` → parsed with
  `HsId::from_str` → `StreamInstructions::Hs` (address.rs 257–271, 423).
- Gate: `prefs.connect_to_onion_services(BoolOrAuto)`; `Auto` defers to
  `address_filter.allow_onion_addrs` (default true) (client.rs 795–810, address.rs 335).
  Otherwise `ErrorKind::InvalidStreamTarget` / `ErrorDetail::OnionAddressDisabled`.
- Path: `wait_for_bootstrap_running` → `netdir(Timely)` → look up
  `HsClientDescEncKeypair` for this hsid in the keymgr (restricted discovery, §11) →
  `hsclient.get_or_launch_tunnel(netdir, hsid, secret_keys, isolation)` →
  `begin_stream(hostname, port)` with hostname/flags suppressed and optimistic data
  disabled (1614–1660). The whole thing is bounded by `connect_timeout`.
- Relevant `ErrorKind`s for UI copy (`tor-error-0.45.0/src/lib.rs`):
  `OnionServiceNotFound` (536, no descriptor = host offline / not yet published),
  `OnionServiceNotRunning` (548, descriptor found but intro points dead),
  `OnionServiceConnectionFailed` (564), `OnionServiceMissingClientAuth` (569),
  `OnionServiceWrongClientAuth` (577), `OnionServiceAddressInvalid` (585),
  `BootstrapRequired` (145), `TorNetworkTimeout` (443), `RemoteStreamClosed` (460).
  Get them via `err.kind()` (`arti_client::HasKind`).

```rust
use arti_client::{StreamPrefs, config::BoolOrAuto};
let mut prefs = StreamPrefs::new();
prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
prefs.new_isolation_group();                    // separate circuits per remote host
let mut ds = client.connect_with_prefs((onion.as_str(), TORNECT_PORT), &prefs).await?;
ds.write_all(&hello_frame).await?; ds.flush().await?;   // tokio traits
```
(compile-verified in `/tmp/probe-arti/src/main.rs`.)

Second stream for the Tor-fallback media tunnel (plan D7): just call `connect`
again with the same prefs/isolation — it reuses the rendezvous circuit
(`get_or_launch_tunnel`), and streams on one circuit share its bandwidth; use a
fresh isolation group if you want a second circuit.

---

## 10. PoW DoS protection (`hs-pow-full`)

- Feature chain: `arti-client/hs-pow-full` → `tor-hsservice/hs-pow-full` (+ tor-hsclient)
  → `equix 0.7.x` (features default `compiler` → `hashx/compiler` → `dynasmrt 5.1`
  JIT) (`tor-hsservice-0.45.0/Cargo.toml` 150–152; crates.io `equix/0.7.1`,
  `hashx/0.9.1` feature lists). Pure Rust — **no C, no system libs**.
- Marked **`__is_experimental`** at both arti-client and tor-hsservice level in
  0.45.0. Without the feature, `enable_pow = true` fails at config build time with
  `NoCompileTimeSupport` (config.rs 317–323) and `pow/v1_stub.rs` is compiled in.
- Semantics: "If true, we will require proof-of-work when we're under heavy load"
  (config.rs 68) — PoW is adaptive, so enabling it costs nothing when idle; clients
  built with `hs-pow-full` on `tor-hsclient` will solve puzzles automatically.
  `disable_pow_compilation` switches HashX to the interpreter (slower verify).
- `OnionServiceStatus` gains a `pow_manager` component and `Problem::Pow` under the
  feature (status.rs).
- **Compile-verified here** (probe 3, `/tmp/probe-arti-exp`, `cargo check` exit 0 in
  1 m 18 s on top of the shared target dir): arti-client features
  `hs-pow-full, restricted-discovery, experimental-api` + `tor-hsservice` features
  `restricted-discovery, hs-pow-full` pull in `equix 0.7.1`, `hashx 0.9.1`,
  `dynasmrt 5.1.0` (406 crates total, +9) and build with no extra system deps.
  Builder calls verified: `.enable_pow(true)`, `.pow_rend_queue_depth(1024)`,
  `.rate_limit_at_intro(Some(tor_hsservice::config::TokenBucketConfig::new(25, 200)))`.
- Recommendation: ship `hs-pow-full` behind a Tornect cargo feature `tor-pow`
  (default **on**), with `enable_pow: true`, `rate_limit_at_intro: Some(TokenBucketConfig::new(25, 200))`
  (example config values, `arti-2.5.1/src/arti-example-config.toml` ~line 730) and
  `max_concurrent_streams_per_circuit` small. Pin `=0.45.0` so "may break between
  patch versions" cannot bite silently.

---

## 11. Restricted discovery (client authorization)

Stabilized in Arti 1.7.0 (2025-11-03, https://blog.torproject.org/arti_1_7_0_released/:
"stabilizes the onion service restricted discovery feature, previously known as
'client authorization'"), non-experimental in `tor-hsservice`, **but the
arti-client feature `restricted-discovery` still carries `__is_experimental`** in
0.45.0 (Cargo.toml 203–207). Functionally it is the same code; treat it as
"stable-ish, pinned".

Service side (`tor-hsservice-0.45.0/src/config/restricted_discovery.rs`,
`.../key_provider.rs`):

- `RestrictedDiscoveryConfig { enabled: bool, watch_configuration: bool,
  key_dirs: DirectoryKeyProviderList, static_keys: StaticKeyProvider }` (191–231).
- `static_keys`: map `HsClientNickname` (a `Slug`, `FromStr`) → `HsClientDescEncKey`;
  builder `StaticKeyProviderBuilder` is a list builder: `b.access().push((nickname, key))`
  (key_provider.rs 34–56). `HsClientDescEncKey: Display/FromStr` in the C-Tor format
  `descriptor:x25519:<BASE32 x25519 pubkey>` (`tor-hscrypto/src/pk.rs` 586–605).
- `key_dirs`: directories of `<nickname>.auth` files in the same format
  (key_provider.rs 95–100); `watch_configuration = true` live-reloads them (module
  docs 27–34).
- Validation: `enabled` without any keys → error; keys without `enabled` → error;
  `enabled` without the cargo feature → `NoCompileTimeSupport` (317–390).
- ≤ **160** clients recommended (`MAX_RESTRICTED_DISCOVERY_CLIENTS`, line 137); the
  descriptor is encrypted per client and must stay under the consensus size cap.
- Caveat (module docs 50–62): removing a client "does **not** guarantee its access
  will be revoked ... Restricted discovery mode is a DoS resistance mechanism, _not_
  a substitute for conventional access control." → Tornect's pairing/device-key
  auth stays the real access control; this is only the "power-user paranoid" mode
  from plan §B.3.

```rust
use tor_hsservice::config::restricted_discovery::HsClientNickname;
use tor_hscrypto::pk::HsClientDescEncKey;
let mut b = OnionServiceConfigBuilder::default();
b.nickname(HsNickname::new("tornect".into())?);
let rd = b.restricted_discovery();                 // &mut RestrictedDiscoveryConfigBuilder
rd.enabled(true);
rd.static_keys().access().push((
    "laptop-of-ana".parse::<HsClientNickname>()?,
    "descriptor:x25519:PU63REQUH4PP464E2Y7AVQ35HBB5DXDH5XEUVUNP3KCPNOXZGIBA".parse::<HsClientDescEncKey>()?,
));
let svc_cfg = b.build()?;
```
**Compile-verified** in `/tmp/probe-arti-exp/src/main.rs` (with the
`restricted-discovery` feature on both `arti-client` and `tor-hsservice`; the
`tor_hsservice::config::restricted_discovery` module is `pub` only under that feature,
config.rs 14–22). Also verified there, under `experimental-api`:
`arti_client::{HsId, KeystoreSelector}` re-exports, `client.generate_service_discovery_key(
KeystoreSelector::Primary, peer_hsid)? -> HsClientDescEncKey`, and the
`HsClientDescEncKey` ↔ `String` round trip (`to_string()` / `parse()`), which is the
value a client device sends to the host at pairing time when restricted mode is on.

Client side: arti-client looks up `HsClientDescEncKeypair` under
`HsClientDescEncKeypairSpecifier::new(hsid)` in the keymgr automatically on every
`.onion` connect (client.rs 1621–1636; specifier in `tor-hsclient/src/keys.rs`
148–159, ArtiPath prefix `client`, role `KS_hsc_desc_enc`). To **create** that key
you need either:

1. `experimental-api` on arti-client:
   `client.generate_service_discovery_key(KeystoreSelector::Primary, hsid)? -> HsClientDescEncKey`,
   `insert_service_discovery_key(selector, hsid, HsClientDescEncSecretKey)`,
   `get_service_discovery_key(hsid)`, `remove_service_discovery_key(selector, hsid)`,
   `rotate_service_discovery_key(..)` (client.rs 2047–2197; impl at 388–420 uses
   `tor_llcrypto::rng::CautiousRng` + `keymgr.generate::<HsClientDescEncKeypair>(&spec,
   selector, &mut rng, false)`); the types `HsClientDescEncKey`, `HsId`,
   `KeystoreSelector` are re-exported from `arti_client` only under that feature
   (lib.rs 87–92). `InertTorClient` (no bootstrap) has the same methods (client.rs
   403–545). This is what `arti hsc key get` does (`arti-2.5.1/src/subcommands/hsc.rs` 218–230).
2. **Without** experimental-api: open the same keystore yourself with the public
   `tor-keymgr` API — `ArtiNativeKeystore::from_path_and_mistrust(state_dir.join("keystore"), &mistrust)`
   (`tor-keymgr/src/keystore/arti.rs` 73–95) → `KeyMgrBuilder::default().primary_store(Box::new(store)).build()?`
   → `keymgr.generate::<HsClientDescEncKeypair>(&HsClientDescEncKeypairSpecifier::new(hsid),
   KeystoreSelector::Primary, &mut rng, false)` (`tor-keymgr/src/mgr.rs` 315–333).
   Do this while no `TorClient` holds the store, or accept that the native keystore
   is plain files with no cross-process lock (state_dir.md notes "*no* lock").

---

## 12. Timing: bootstrap and descriptor publication

Constants in `tor-hsservice-0.45.0/src/publish/reactor.rs`:
`UPLOAD_RATE_LIM_THRESHOLD = 60 s` (line 113: min spacing between descriptor
re-uploads), `OVERALL_UPLOAD_TIMEOUT = 5 min` (130), per-HsDir upload timeout floor
30 s (382); `ipt_establish.rs`: `FAULTY_IPT_THRESHOLD = 15 min`; `ipt_mgr.rs`:
IPT records persist and are reused across restarts (`hs_ipts_<nick>.json`,
"IPT_PUBLISH_UNCERTAIN = 3 h"), so warm restarts republish quickly.

Empirical measurement from running the probe binary on this VM (debug build, 2 CPUs,
VMware NAT): see §17 — cold bootstrap **24 s**, onion service launched → loopback
`.onion` connect succeeded **10 s** later (descriptor upload completed within 8 s of
launch). Plan §A.4's "up to ~2 min once per install" budget is therefore a safe
upper bound, not the typical case; the code path requires 3 intro circuits + one
descriptor upload to ≥1 HsDir on each of 2 rings before `State::Running`.

---

## 13. Gotchas

1. **Crypto provider**: forgetting `install_default()` → arti fails at first TLS
   handshake, not at startup (tor-rtcompat rustls.rs 32–36). Do it in `main` before
   anything else; quinn shares it.
2. **`full` pulls `native-tls` + `async-std`** — never enable `full`/`experimental`
   on arti-client. `static` also forces native-tls; use `static-sqlite` only.
3. **`HsId` has no `Display`** (only `safelog::DisplayRedacted`); `{}` won't compile,
   `{:?}` prints a redacted form (`pk.rs` 123–152). Use `display_unredacted()`.
4. **`launch_onion_service` needs the keystore** (`KeystoreRequired` error) — do not
   disable `storage.keystore`.
5. **`connect_timeout` (10 s default) applies to onion connects** — raise to ~45–60 s.
6. **Two `rand_core` generations** in the graph (0.6 for dalek, 0.10 for arti APIs) —
   don't unify by hand; use `tor_llcrypto::rng::CautiousRng` / `rand 0.10` for arti
   calls and `rand_core 0.6`-compatible RNGs for `ed25519-dalek`.
7. **fs-mistrust** rejects group/world-writable state/keystore dirs (and parents);
   create dirs with 0700 on unix. **On Windows it checks nothing about permissions or
   owners** — `check_permissions` is `#[cfg(target_family = "unix")]` only
   (`fs-mistrust-0.15.1/src/imp.rs` 138–174) and the README states "On Windows, we
   accept all file permissions and owners" (README.md 218); only path types (dir vs
   file, symlinks) are checked there. So the Windows state dir is protected exactly as
   well as `%LOCALAPPDATA%` is (per-user profile ACL) and no more — corrected
   2026-08-29 from the crate source (this note first claimed an ACL check). Test
   suites can set `dangerously_trust_everyone()` or
   `FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS=true` (`src/disable.rs` 27).
8. **Do not fork** after creating the runtime (README). `std::process::Command` is OK.
9. `num_intro_points` must be **3..=20** (validate()).
10. `RunningOnionService` drop = stop publishing; existing circuits stay open. Keep
    the `Arc` in the host state machine; drop it to "go invisible".
11. `RendRequest` stream returned by `launch_onion_service` is `impl Stream +
    use<R>` (not `Unpin`); `Box::pin` it before `.next()`.
12. `handle_rend_requests` swallows accept errors with a `warn_report!` — add your
    own filter/metrics before it if you need rejection accounting.
13. Only accept `BEGIN` and only check the port — anything else makes the service
    fingerprintable (req.rs 257–260, 273–278). For a request that is *not* `BEGIN`
    on a served port, Arti's own reverse proxy destroys the rendezvous circuit:
    `tor-hsrproxy-0.45.0/src/proxy.rs` 225 (non-`BEGIN`) and 236 (`resolve_port_for_begin`
    → `unwrap_or(ProxyAction::DestroyCircuit)`), executed at 248–250 via
    `StreamRequest::shutdown_circuit()` (req.rs 286–291: `on_tunnel.terminate()`).
    Sending `END(DONE)` and keeping the circuit is therefore distinguishable, and
    rejected streams do not count toward `max_concurrent_streams_per_circuit`.
    Dropping the stream returned by `RendRequest::accept` also closes the circuit —
    it owns the rendezvous tunnel (req.rs 233–241). Verified 2026-08-28 from the
    crate tarballs (`static.crates.io`).
14. Default state/cache dirs are `~/.local/share/arti`, `~/.cache/arti` shared with
    the system `arti` — always override.
15. `cache_dir` may be wiped at any time; `state_dir` must persist (guards, IPTs,
    **keystore**). Back up `state_dir/keystore/hss/<nick>/` = the identity.
16. GitLab blocks scripted fetches (403) — docs come from docs.rs
    (https://docs.rs/arti-client/0.45.0) and the crate tarballs.
17. `TorClient` constructors return `Arc<TorClient<R>>` since 2.4.0; `TorClient<R>`
    is generic over the runtime — pick `TokioRustlsRuntime` concretely in Tornect
    types to avoid generic soup.
18. Example TOML for the arti CLI (`arti-2.5.1/src/arti-example-config.toml` 660–790)
    documents the same keys (`num_intro_points`, `rate_limit_at_intro = [25, 200]`,
    `max_concurrent_streams_per_circuit`, `enable_pow`, `pow_rend_queue_depth`,
    `restricted_discovery.{enabled,key_dirs,static_keys}`) — useful if Tornect ever
    exposes a TOML section mirroring arti's.

---

## 14. 2026 changelog items affecting onion services (from release blogs)

- **2.0.0 (2026-02-02)**: semver-driven major bump; "All APIs in the `arti` crate
  marked experimental" (the CLI crate, not arti-client). No HS changes.
  https://blog.torproject.org/arti_2_0_0_released/
- **2.1.0 (2026-03-03)**: config system moved to `derive-deftly` (this is why every
  config builder now has generated setters/sub-builders); MSRV 1.89.
  https://blog.torproject.org/arti_2_1_0_released/
- **2.2.0 (2026-03-31)**: TROVE-2026-005 "low-severity ... would somewhat weaken DoS
  resistance in certain unusual embedded build configurations".
  https://blog.torproject.org/arti_2_2_0_released/
- **2.3.0 (2026-05-07)**: announced explicit `Arc<TorClient>`; macOS min 10.14.
  https://blog.torproject.org/arti_2_3_0_released/
- **2.4.0 (2026-06-01)**: "fixes for a number of bugs affecting onion service client
  connectivity"; "multiple breaking changes to the `TorClient` APIs";
  `use_obsolete_software` removed; flowctl-cc stable.
  https://blog.torproject.org/arti_2_4_0_released/
- **2.5.0 (2026-06-30)**: MSRV 1.91; congestion control default; CGO stable;
  TROVE-2026-024 and TROVE-2026-027 (medium DoS) fixed → do not use < 0.44.0.
  https://blog.torproject.org/arti_2_5_0_released/
- **2.5.1 (2026-08-03)**: onion services can forward to unix sockets; experimental
  congestion control and CGO on onion-service circuits.
  https://blog.torproject.org/arti_2_5_1_released/
- Earlier context: 1.2.0 made `onion-service-service` non-experimental; 1.7.0
  (2025-11) stabilized restricted discovery; 1.8.0 (2025-12) added `arti hsc
  ctor-migrate` for client keys.

---

## 15. Alternative/unused: `tor-hsrproxy`

If Tornect ever wants "forward onion port → localhost TCP" instead of handling
streams in-process, `tor-hsrproxy 0.45.0` (`OnionServiceReverseProxy::new(ProxyConfig)`,
`.handle_requests(runtime, nickname, rend_requests)`) does exactly that; not needed
for v1 because signaling wants the `DataStream` directly.

---

## 16. Open questions

1. `restricted-discovery` and `hs-pow-full` are `__is_experimental` at arti-client
   level but compile fine here (§10/§11). Product decision: enable PoW by default in
   v1 (recommended: yes, it is adaptive and idle-free) — semver risk is neutralized
   by exact pins, but every arti bump must re-run the probe.
2. Whether to use `experimental-api` (for `generate_service_discovery_key`) or the
   direct `tor-keymgr` route (§11 option 2) for client restricted-discovery keys.
   Both compile; option 1 is simpler, option 2 avoids the experimental marker.
3. The measured 10 s launch→reachable (§17) is one sample on one network; the UI
   must still drive its "publishing…" state from `status_events()` / the first
   successful inbound connect, not a timer. Also unverified: whether `State::Running`
   is reported promptly (the probe exited before observing it).
7. PoW has not been exercised end-to-end (only compiled); a client built **without**
   `hs-pow-full` on `tor-hsclient` cannot solve puzzles when the host is under load —
   both Tornect roles must carry the feature.
8. Windows/macOS builds of `ring`, `libsqlite3-sys`(bundled), `zstd-sys`, `liblzma-sys`,
   `dynasmrt` (JIT: W^X / hardened-runtime entitlements on macOS?) are inferred, not
   tested — first CI matrix run should confirm; `disable_pow_compilation = true` is
   the fallback if the HashX JIT is a problem on a platform.
4. `HsClientNickname`/key format for restricted mode should map to Tornect's paired
   device names (Slug rules: `tor-persist::slug`).
5. Whether to run the client-side `TorClient` with `DormantMode::Soft` between
   sessions and what its wake-up latency is.
6. aws-lc-rs vs ring: aws-lc-rs needs cmake+nasm on Windows CI; ring needs neither.
   Decide once for arti + quinn.

---

## 17. Measured: probe run against the live Tor network (2026-08-28, this VM)

Binary: `/home/mx/.cache/tornect-probe-target/debug/probe-arti` (source
`/tmp/probe-arti/src/main.rs`, log `/tmp/probe-arti/run2.log`, `RUST_LOG=info`,
fresh state/cache dirs, VMware NAT, debug build). Timeline (wall clock):

| t | event (from arti tracing + probe prints) |
|---|---|
| 0 s | `tor_dirmgr: Didn't get usable directory from cache.` → "Looking for a consensus" |
| +5 s | "Downloading certificates for consensus (we are missing 9/9)" |
| +6 s | "Downloading microdescriptors (we are missing 10121)" |
| **+24 s** | "Directory is complete", `bootstrap 100% ready=true` — `client.bootstrap()` returns |
| +24 s | `tor_hsservice: Generated a new identity for service tornect: […]sqd.onion` / "Launching onion service" — `launch_onion_service` returned instantly; `onion_address()` = `n4etdaqtiigqaqzt2iw5btauem72ohr3lafr5qlamirhonguw2puusqd.onion` |
| +24 s | `status_events()`: `Shutdown` → `Bootstrapping` (problem `Ipt([])` while IPTs are being established) |
| +26 s | guards confirmed usable |
| +28 s | `hs state=Bootstrapping problem=None` (IPTs up) |
| **+32 s** | `tor_hsservice::publish::reactor: reuploading descriptor in 1h 49m` — first descriptor upload done (8 s after launch) |
| **+34 s** | client-side `connect_with_prefs(("<addr>.onion", 4000))` over a *separate isolation group* succeeded, `BEGIN` accepted by the service, 5-byte round trip OK (`reply: world`) — **10 s after launch** |
| +34 s | process exit, `tor_circmgr: Flushed persistent state at exit.` |

Notes:
- The loopback connect (client → own onion) worked while the status stream still
  showed `Bootstrapping`; the publisher's `Running` transition was not observed
  before exit. Treat `status_events()` as an eventually-consistent indicator for the
  UI, not as a gate for accepting connections (the request stream simply starts
  yielding).
- Second run in the same dirs will reuse `guards.json`, cached consensus/microdescs
  (46 MB `tor-cache`) and the persisted IPT records, so warm starts are faster.
- Persisted layout after the run (all dirs created 0700 by arti):

```
tor-state/
  state/{state.lock, guards.json, circuit_timeouts.json}
  hss/tornect.lock
  hss/tornect/{ipts.json, iptpub.json, iptreplay/<lid>.bin ×3}
  keystore/hss/tornect/ks_hs_id.ed25519_expanded_private          <- THE identity (backup this)
  keystore/hss/tornect/ks_hs_blind_id+<tp>.ed25519_expanded_private ×2 (current + next time period)
  keystore/hss/tornect/ks_hs_desc_sign+<tp>.ed25519_private ×2
  keystore/hss/tornect/ipts/{k_hss_ntor+<lid>.x25519_private, k_sid+<lid>.ed25519_private} ×3
tor-cache/
  dir.lock, dir.sqlite3, dir_blobs/con_microdesc_sha3-256-<hash>
```
(`find /tmp/probe-arti/app -type f`). `tor-state` = 80 KB, `tor-cache` = 46 MB.
- An earlier run (`run1.log`) failed at 45 % with "Unable to finish bootstrapping a
  directory" — root cause was the tmpfs quota being exhausted by a concurrent cargo
  build while arti wrote `dir.sqlite3`; i.e. a full disk surfaces as a bootstrap
  failure, not as an I/O error message. Worth a friendly UI message.
