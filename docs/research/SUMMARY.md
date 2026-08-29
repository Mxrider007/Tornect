# Research consolidation — completeness review

File: `/home/mx/Tornect/docs/research/SUMMARY.md` · Date: 2026-08-28 · Role: completeness critic.

Inputs read in full: `TORNECT_PLAN.md` (== `docs/PLAN.md`, byte-identical) and the nine notes
`docs/research/{arti,ci,codecs,crypto,media-proto,nat,quic,ui,wayland}.md`, plus the workspace
`Cargo.toml`, `Cargo.lock` (566 packages), `deny.toml`, `.github/workflows/ci.yml`,
`docs/DEPENDENCIES.md`, `docs/VERIFICATION.md`, `docs/notes/*.md`, `CLAUDE.md`.
Two things were re-verified against sources here rather than trusted: the quinn QUIC-bit
greasing default (`~/.cargo/registry/src/*/quinn-proto-0.11.17`) and the locked crate versions.

Dev machine: `mx-vm`, Ubuntu 26.04, Rust 1.96.0, gcc/g++/cmake/pkg-config present, **no sudo,
no nasm, no libclang-dev, no libav*/pipewire/alsa/gtk/udev/xkbcommon dev headers**, no GPU
encoder (VMware; lavapipe Vulkan only), `/tmp` is a 3.7 GiB quota-limited tmpfs.

---

## 0. Headline findings (read these first)

1. **QUIC fixed-bit greasing must be disabled, or the single-socket STUN/punch/QUIC demux
   breaks.** nat.md:422 asserts "quinn doesn't grease by default"; quic.md never checked.
   Verified here: `quinn-proto-0.11.17/src/config/mod.rs:63` defaults
   `grease_quic_bit: true`, and `connection/packet_builder.rs:127` does
   `if conn.peer_params.grease_quic_bit && conn.rng.random() { buffer[..] ^= FIXED_BIT }`.
   Two Tornect peers with default configs will both advertise it and randomly clear the
   fixed bit, so short-header packets can start with `0x00..0x3F` — colliding with STUN
   (`0..3`) and our own `0x00` punch probes. Fix: `EndpointConfig::grease_quic_bit(false)`
   on both ends (RFC 9443 requires exactly this) + a demux unit test.
2. **Two M1 blockers are un-researched:** (a) no CBOR crate is evaluated or pinned anywhere
   (plan D4 mandates CBOR; crypto.md:316 used `ciborium` in a probe without a version); the
   signed-transcript design also needs a deterministic-encoding decision (RFC 8949 §4.2).
   (b) `docs/PLAN.md §B.8` (unattended-access protocol) is cited by `CLAUDE.md`,
   `docs/notes/decisions.md` (M0-3), `docs/VERIFICATION.md`, and four agent files — but the
   section does not exist in either copy of the plan (`grep -n "B\.8\|OPAQUE\|PAKE"` → none).
3. **M3's acceptance criteria cannot be met on this VM** and no note says so plainly:
   no hardware encoder, the `pipewire` crate cannot build (no headers), and the only
   locally buildable encoder (`openh264`, measured codecs.md:364) needs 23.4 ms/frame at
   1080p — above the 16.7 ms frame budget. "1080p60 loopback ≥ 30 min, ≤ 35 ms p95,
   CPU < 15 % with hw codec" needs a VM-scoped variant plus `NEEDS-DEVICE(gpu)` rows; the
   Linux CI runner has no GPU either.
4. **Toolchain/MSRV drift:** workspace `rust-version = "1.90"` is below `arti-client`'s
   1.91 (arti.md:40) and `egui 0.36`'s 1.95 (ui.md:35); with `resolver = "3"` (MSRV-aware)
   cargo silently holds non-`=`-pinned dependencies back to 1.90-compatible versions.
   Decision: `rust-version = "1.95"`, add `rust-toolchain.toml` (channel `1.96.0`,
   rustfmt + clippy) so CI (`@stable` = 1.98 today) and the VM agree (ci.md §5).
5. **CI must change before 2026-09-23** (Node 20 removed from runners, ci.md §1.2):
   `actions/checkout@v4` → `@v7`; `deny.toml` fails today on `Unlicense`, `LGPL-3.0-only`,
   RUSTSEC-2023-0071, RUSTSEC-2024-0436 (ci.md §7.3); `ubuntu-latest` = 24.04 = FFmpeg 6.1,
   not the "≥ 7.x" the plan assumes.
6. Conflicts between notes/plan resolved to one decision each (§2): manual winit loop, not
   eframe · `opus 0.4.0`, not `audiopus` · `openh264` always-on software path, libx264 only
   opportunistically via FFmpeg · `stun 0.17.2` sans-IO · `crab_nat`, not `natpmp` ·
   `keyring-core` + stores, not `keyring::Entry` · TLS raw public keys, not X.509/rcgen ·
   RustCrypto 0.11 line for all Tornect code (arti.md:151 is wrong) · no direct `argon2 0.6`,
   only `opaque_ke::argon2` · `sha3` stays `0.11` · `SO_REUSEADDR` off · punch probes
   outside QUIC · Opus in-band FEC off.
7. Claims verified **wrong**: nat.md:422 (grease), nat.md:472 (conntrack stream timeout is
   120 s, not 180 s), arti.md:151 (digest 0.11 is not a pre-release; 0.11.3 is current,
   0.11.0/0.11.1 yanked), arti.md:206/808 (aws-lc-rs "needs cmake + nasm" contradicts the
   aws-lc-rs README quoted in quic.md:109), codecs.md:315 vs media-proto.md:488 (VideoToolbox
   CBR gate stated two incompatible ways, neither sourced). Full list in §3.

---

## 1. Consolidated crate table

Legend — **VM**: builds on mx-vm (verified by a probe or the workspace) · **CI**: needs apt
packages or an OS runner · **x-check**: only `cargo check --target` here (Windows/macOS code)
· **pin**: exact `=` pin recommended (plan §D.1 rule 4; `Cargo.lock` pins everything anyway,
`=` protects `cargo update`). "Decision" is the single consolidated choice where notes or the
plan disagreed.

### 1.1 Already in the workspace (M0/M1) — all build on the VM

| Crate | Pin in `Cargo.toml` | Features | Decision / note |
|---|---|---|---|
| `arti-client` + `tor-{hsservice,hscrypto,cell,proto,config,llcrypto,keymgr,rtcompat}` | `=0.45.0` (lock-step, Arti 2.5.1 line) | `default-features=false`; `tokio, rustls, compression, flowctl-cc, static-sqlite, onion-service-service, onion-service-client, vanguards`; `hs-pow-full` via `tornect-signal/tor-pow` (default on) | Keep. Never `full`/`experimental`/`native-tls`/`static`. `restricted-discovery` (arti.md §11) deferred to a `tor-restricted` feature (M8); use the `tor-keymgr` route already taken in M1-1, so `experimental-api` stays off. Raise `stream_timeouts().connect_timeout` to 45–60 s (arti.md:712; rendezvous measured 6.6–9.0 s, one 60 s timeout in m1 evidence) — the setter is **not yet compile-verified** (arti.md:296–298). |
| `rustls` | `=0.23.43` | `default-features=false`; `ring, std` | Keep; the one provider for Arti + quinn (decision M1-3). CI guard: `cargo tree -i aws-lc-sys` must be empty. |
| `safelog` | `0.9` | — | Keep (`HsId` has no `Display`). |
| `ed25519-dalek` | `3.0.0` | `zeroize` | Keep on 3.x (rand_core 0.10 / sha2 0.11). Add `pkcs8 + alloc` at M2 for `to_public_key_der()` (the 44-byte SPKI pin; hand-building per quic.md §3.2 also works). Add `serde` only if envelope types derive it. `rand_core` stays off (seeds from `getrandom`). Host signatures use Arti's `tor_llcrypto::ExpandedKeypair::sign` (crypto.md §4), not `hazmat`. |
| `sha2` / `hmac` / `hkdf` | `0.11.0` / `0.13.0` / `0.13.0` | — | Keep (digest 0.11 line). |
| `sha3` | `0.11` (locked 0.11.0) | — | **Keep 0.11**, do not follow crypto.md's `=0.12.0`: the lock already shares `sha3 0.11.0` with Arti's `derive-deftly-macros`; 0.12 only removed `Shake*` and would add a third copy. |
| `data-encoding`, `zeroize`, `getrandom` (`std, sys_rng`), `subtle`, `hex`, `fs-err`, `time`, `directories`, `toml`, `serde`, `serde_json`, `clap`, `tracing*`, `anyhow`, `thiserror`, `tokio 1.53.1`, `bytes`, `parking_lot`, `futures 0.3.34`, `tempfile`, `proptest` (dev) | as pinned | — | Keep. `proptest` is the only source of `rand 0.9` today (dev-only). |

### 1.2 Crypto / signaling additions (M1, M8)

| Crate | Pin | Features | VM | Decision / note |
|---|---|---|---|---|
| **CBOR codec** | **UNPINNED — research needed** | — | — | Plan D4 requires CBOR; no note evaluates a crate. Candidates: `ciborium` (serde; used in crypto.md:316 probe), `minicbor` (no serde, deterministic-encoding friendly), `cbor4ii`. Requirement: RFC 8949 §4.2 deterministic encoding for the signed transcript, fuzzable decoder, size limit 64 KiB/frame (§B.3). `research-verifier` task before HELLO signatures land. |
| `opaque-ke` | `=4.0.1` | `default-features=false`; `argon2, ristretto255, serde` | yes | Unattended-access PAKE (CLAUDE.md invariants; crypto.md §8 verified full flow). Carries the old stack (rand 0.8, digest 0.10, argon2 0.5, curve25519-dalek 4, `generic-array =0.14.7`). Wire the raw `serialize()` bytes as CBOR byte strings (serde form is 2.5× bigger). Track opaque-ke 5 for the stack flip (crypto.md §13.1). |
| `sha2` alias `sha2_010 = { package = "sha2", version = "0.10" }` | `0.10` | — | yes | Only inside the PAKE module (opaque-ke's KE hash must be digest-0.10). |
| `rand_core` alias `rand_core_06` | `0.6` | — | yes | Only for the 20-line `Rng06` adapter (crypto.md §3.4) feeding opaque-ke. |
| `rand` / `rand_core` | `=0.10.2` / `=0.10.1` | — | yes | Add only when an API needs a `CryptoRng` (nothing in M0/M1 does; `getrandom::fill` suffices). quinn-proto 0.11.17 already depends on `rand 0.10.1` (verified: its `Cargo.toml:109-110`). |
| `argon2` (direct, 0.6.0) | — | — | yes | **Not added in v1.** The KSF type must be `opaque_ke::argon2::Argon2` (0.5, crypto.md §8.1); nothing needs a PHC string. If a local settings-lock ever wants one, 0.6 can coexist but must never be named as `Ksf`. |
| `x25519-dalek 3.0.0`, `curve25519-dalek 5.0.0`, `ed25519 3`, `signature 3` | — | — | yes | Not needed directly (no ECDH in the protocol; restricted-discovery keys are generated by `tor-keymgr`). Transitive via dalek. |
| `blake3 1.8.7`, `constant_time_eq 0.5.0` | — | — | yes | **Not added.** `subtle` covers ct-compare (crypto.md §10); blake3 only for a future file-transfer hash. |
| `tor-hscrypto::HsId` | (present) | — | yes | Reuse `HsId` inside `tornect-signal`; `tornect-core` (which must stay Arti-free) keeps its own codec — crypto.md §9 verified the stand-alone implementation is byte-identical to `HsId::display_unredacted()`. |

### 1.3 QUIC / TLS (M2, `tornect-net`)

| Crate | Pin | Features | VM | Decision / note |
|---|---|---|---|---|
| `quinn` | `=0.11.11` | `default-features=false`; `rustls-ring, runtime-tokio, log` (+`rustls-log` in debug) | yes (40 s) | `platform-verifier` and `bloom` off. **Set `EndpointConfig::grease_quic_bit(false)`** (§0.1). `TransportConfig` per quic.md §8; Cubic default, BBR (experimental upstream) behind a setting. |
| `rustls-pki-types` | `=1.15.1` | — | yes | Types for `CertificateDer`/`SubjectPublicKeyInfoDer`. |
| `socket2` | `=0.6.5` | none (`all` only if `set_reuse_port` is ever needed) | yes | Build the media socket here, hand the std socket to `Endpoint::new`. **No `SO_REUSEADDR`** on it (nat.md:21/369; quic.md:375 used it only for a loopback probe). |
| `rcgen` / `rustls-webpki` | — | — | yes (probe) | **Rejected for v1**: TLS raw public keys (RFC 7250) verified over quinn (quic.md §3.3); the peer "certificate" is the 44-byte Ed25519 SPKI. Keep the X.509 path documented, not compiled. |
| `noq` / `iroh-quinn` | — | — | — | Plan-B only (QAD/QNT via n0's fork), re-evaluate after M4 (quic.md §10). |

### 1.4 NAT traversal (M2, `tornect-net`)

| Crate | Pin | Features | VM | Decision / note |
|---|---|---|---|---|
| `igd-next` | `=0.17.1` | `default-features=false`; `aio_tokio` | yes; live-tested (router answered 501) | UPnP. Always override the 10 s search timeout (3 s / 2 s). Sync API never from tokio. |
| `crab_nat` | `=0.8.1` | (`tracing` optional) | yes; live-tested (ICMP refused → instant negative) | PCP-first + NAT-PMP fallback. **Chosen over `natpmp 0.5.0`** (no PCP, untimed async read, drags `netdev 0.31`/netlink). |
| `stun` (webrtc-rs) | `=0.17.2` | `default-features=false` | yes; live against Google + Cloudflare | **Chosen** (nat.md TL;DR), used sans-IO on our socket; never its `Client`. Costs: widens tokio features, `webrtc-util`, `rand 0.9`, `md-5 0.10`, `thiserror 1` duplicates (compile-time only). `stun_codec 0.4.0` (adds hmac 0.12/sha1 0.10) and a hand-rolled ~80-line Binding codec are the M7 cleanup candidates once a fuzz corpus exists; `stunclient 0.4.2` rejected (owns the socket). Use `TransactionId::new()`, never `Box::<TransactionId>::default()` (all zeros, nat.md §9.1). |
| `if-addrs` | `=0.15.0` | none (**not** `link-local`) | yes | Host candidates + `IfChangeNotifier` (blocking; absent on macOS → poll). |
| default-gateway discovery (`netdev 0.46.1`) | **UNVERIFIED** | — | — | crab_nat needs the gateway IP and the client IP the gateway sees; `netdev` was not extracted (nat.md §2.2.4/§10.1). Decide at M2 start after `cargo tree` on the three targets; the zero-dep alternative is ~100 lines of per-OS code (`/proc/net/route`, `route -n get default`/`PF_ROUTE`, `GetBestRoute2`). Client IP: `UdpSocket::connect(gateway:5351)` + `local_addr()` (nat.md §9.10). |
| `natpmp`, `stunclient`, `pcp` | — | — | — | **Rejected** (reasons above; `pcp 0.2.0` is from 2016). |

### 1.5 Media protocol, codecs, audio (M3, M5)

| Crate | Pin | Features | VM | Decision / note |
|---|---|---|---|---|
| `raptorq` | `=2.0.1` | `default-features=false`; `std` | yes (round-trip verified) | Per-frame RaptorQ per media-proto.md §7.3 decision table; symbol = round_down(`max_datagram_size()` − 12 − 4, 8) = 1144 B @1200 MTU; derive OTI from (len, symbol) — never transmit it. XOR parity path shares the packetizer. `reed-solomon-erasure` not evaluated (open). |
| `openh264` | `=0.9.8` | `default-features=false`; `source` | **yes** (46 s, no nasm; C++ fallback) | **The always-available software H.264 path** (decision M0-5), both directions, all OSes. Plan's "x264 ultrafast+zerolatency" (§B.5) becomes: libx264 only opportunistically through FFmpeg when the system build has it (GPL-compatible with GPL-3.0-or-later) — it gives 4:4:4 text mode; openh264 is 4:2:0 only. CI adds `nasm` for ~3× speed. Patent posture (source vs Cisco blob via `libloading`) = M8 legal decision (codecs.md §11.1). |
| `ffmpeg-next` / `ffmpeg-sys-next` | `=9.0.0` | `default-features=false`; `codec, software-scaling, non-exhaustive-enums` | **no** (no libav headers/libclang) → `tornect-codec/ffmpeg`, CI | Hardware layer (decision M0-6). Builds against FFmpeg 6.1–9.0; target the **8.x API**, gate 8-only symbols on the `ffmpeg_8_0` cfg; media CI matrix `[ubuntu-24.04 (6.1), ubuntu-26.04 (8.0.1, continue-on-error while preview)]`. hw device/frames contexts are raw `ffi` only (no safe wrapper); the §2.4 glue is **not compiled anywhere yet**. ABI: ship FFmpeg with releases (M8). |
| `opus` → `opusic-sys` (bundled libopus 1.6.1) | `=0.4.0` | default (`bundled`) | yes (cmake) | **Chosen over `audiopus`/`audiopus_sys`** (stale since 2021). `Application::LowDelay`, 48 kHz, 10 ms, `set_inband_fec(false)` (§2.9). M5. |
| `cpal` | `=0.18.2` | `default-features=false` (+`pipewire` on Linux, CI) | **no** (`alsa-sys` needs `libasound2-dev`) → `tornect-audio/cpal`, CI | M5. Pins `windows 0.62` — aligned with ours. |
| `rav1e`, `rav1d`, `dav1d` | — | — | (rav1e builds) | **Rejected**: rav1e measured 0.65 s/frame at 1080p (codecs.md §4.2); no pure-Rust AV1 decoder with a Rust API. AV1 = hardware only in v1; software AV1, if ever, via FFmpeg `libsvtav1`. Plan §B.5 "svt-av1 p12 potato mode" and "dav1d" are dropped from v1. |

### 1.6 Linux/Wayland capture + input (M3 capture on the dev OS, M5 input)

| Crate | Pin | Features | VM | Decision / note |
|---|---|---|---|---|
| `ashpd` | `=0.13.13` | `default-features=false`; `tokio, screencast, remote_desktop, clipboard` | **yes**; live portal probe (RD v2, SC v5, Clipboard v1 on GNOME 50) | Never `pipewire`, `wayland`, `gtk4`, `raw_handle`, `async-io`. **One `RemoteDesktop` session** for capture + input; persistence/restore token **only** on `SelectDevicesOptions` (spec; plan §B.5 wording is wrong). `identifier: None` in v1. |
| `reis` | `=0.7.1` | `tokio` | yes (pure Rust; EIS handshake compiled) | libei client for injection (M5). `ei_text` needs libeis ≥ 1.6 (VM has 1.5.0). **Do not apt-install `libei-dev`** (ci.yml does — remove). |
| `enumflags2`, `futures-util` | `0.7`, (use `futures`) | — | yes | Shared bitflag type; `futures 0.3` already in workspace covers `StreamExt`. |
| `pipewire` / `libspa` | `=0.10.1` | `v1_0_0` (max that builds on `ubuntu-latest` = libpipewire 1.0.5) | **no** (`libspa-sys` build.rs: no headers) → `tornect-capture/pipewire`, CI | `MainLoopBox` on a dedicated std thread (the `ThreadLoopBox` ctor is `unsafe` with an unfinished safety doc). DMA-BUF modifier pods must be hand-built (`property!` cannot express `Long` or flags). cpal's `pipewire` feature (`v0_3_53`) unifies under `v1_0_0`. |
| `xkbcommon` | `=0.9.0` | `default-features=false`, `wayland` (for `new_from_fd`) | **no** (links `-lxkbcommon`; no dev symlink) → feature `linux-xkb`, CI | Only for keysym→keycode reverse mapping (M5). |
| `wayland-client` | — | — | no (`libwayland-dev`) | **Not needed** in v1 (only for parented dialogs). |

### 1.7 Windows / macOS (M6; cross-checked now)

| Crate | Pin | Features | VM | Decision / note |
|---|---|---|---|---|
| `windows` / `windows-core` | `=0.62.2` | `Foundation, Graphics_Capture, Graphics_DirectX, Graphics_DirectX_Direct3D11, Win32_Foundation, Win32_Graphics_Direct3D, Win32_Graphics_Direct3D11, Win32_Graphics_Dxgi, Win32_Graphics_Dxgi_Common, Win32_Graphics_Gdi, Win32_System_WinRT, Win32_System_WinRT_Direct3D11, Win32_System_WinRT_Graphics_Capture, Win32_Media_Audio, Win32_System_Com, Win32_System_Com_StructuredStorage, Win32_System_Variant, Win32_UI_Input_KeyboardAndMouse, Win32_UI_WindowsAndMessaging` (+`Foundation_Metadata` for the DirtyRegions capability probe) | x-check green (ci.md §8.1) | Declare **once** in `[workspace.dependencies]` with the union of features (capture + WASAPI + SendInput crates unify). Gotchas: `D3D11CreateDevice` `software: HMODULE`; `IMMDevice::Activate` needs `Win32_System_Com_StructuredStorage` + `Win32_System_Variant`. `windows-sys 0.52/0.59/0.60/0.61` duplicates already exist in the lock — compile-time only. |
| `objc2` | `=0.6.4` | — | x-check green (ci.md §8.2) | |
| `objc2-foundation`, `objc2-screen-capture-kit`, `objc2-core-graphics`, `objc2-core-foundation`, `objc2-core-media` | `=0.3.2` | per ci.md §8.2 (`NSEnumerator` needed for `NSArray::iter`) | x-check green | SCKit capture, CGEvent injection. |
| `block2`, `dispatch2` | `0.6`, `0.3` | — | x-check | |

### 1.8 UI / desktop integration (M3 stream window; M4/M8 app)

| Crate | Pin | Features | VM | Decision / note |
|---|---|---|---|---|
| `egui`, `egui-wgpu`, `egui-winit`, `epaint` | `=0.36.1` | egui-wgpu: `winit, wayland, x11`; egui-winit: defaults minus `winit/default` (set on our own `winit`) | **yes** (builds, links, runs on GNOME/lavapipe) | MSRV **1.95** → workspace bump (§0.4). `Context::run_ui` replaced `run`; `RawInput.modifiers` removed in 0.36. |
| `eframe` | — | — | (probe built) | **Not used** (plan D10 amended): the app owns the winit 0.30 loop (ui.md §4/§5.3 skeleton compiled). Reasons: one event loop per process, eframe exposes no raw winit events, egui-winit drops unmapped keys (PrintScreen, NumLock, media keys…), and `winit/default` cannot be enabled from a dependent's feature list. Avoids an M5 rewrite. |
| `wgpu` | `=30.0.1` | `default-features=false`; `std, wgsl, vulkan, gles, dx12, metal` | yes | One copy (with egui-wgpu's `wgpu = "30.0"`). Env `WGPU_BACKEND=vulkan` + `force_fallback_adapter` for headless CI (lavapipe). wgpu 30 API deltas in ui.md §7.4. |
| `winit` | `=0.30.13` | defaults (`rwh_06, x11, wayland, wayland-dlopen, wayland-csd-adwaita`) | yes | Do not track 0.31 betas. Pointer lock: `Locked` → `Confined` fallback; unlock on `Focused(false)`. |
| `egui_extras` | `=0.36.1` | `default-features=false`, `image` | yes | Only if URI/bytes image loading is used; the QR path needs neither it nor `image`. |
| `pollster`, `bytemuck` | pin at M3 from `cargo tree` | — | yes | Versions not recorded by ui.md (`pollster 0.4` via rfd, `1.0` via eframe). |
| `qrcode` | `=0.14.1` | `default-features=false` | yes | `to_colors()` → `ColorImage::from_gray`. |
| `image` | `=0.25.10` | `default-features=false`; `png` | yes | Icons only; never `nasm`/`avif`. |
| `rfd` | `=0.17.2` | `default-features=false`; `xdg-portal` | yes (dlopen libdbus / zenity) | No `tokio` feature exists in 0.17. Use egui modals, not `MessageDialog`. |
| `arboard` | `=3.6.1` | `default-features=false`; `image-data, wayland-data-control` | yes | GNOME Mutter lacks `ext/wlr-data-control` → X11 fallback (verified log). Host clipboard on Wayland goes through the portal Clipboard (best-effort, v1). |
| `notify-rust` | `=4.18.0` | `default-features=false`; `z-with-tokio` | yes | `show()` blocks on D-Bus — never on the winit thread. |
| `keyring-core` + stores | `=1.0.0`; `linux-keyutils-keyring-store =1.0.0`, `zbus-secret-service-keyring-store =1.0.0` (`rt-tokio-crypto-rust`), `apple-native-keyring-store =1.0.2` (`keychain`), `windows-native-keyring-store =1.1.0` | — | yes (keyutils store; Secret Service needs a daemon) | **Chosen over `keyring 4.1.6`**: its `Entry` v1 shim force-installs the Secret Service store (ui.md §5.9). Keep the M0 file keystore (0600) as the fallback. Plan D13 wording ("`keyring` crate") amended. |
| `tray-icon` (+`muda`) | `=0.24.2` | — | **no** (GTK3/appindicator/libxdo headers) → feature `tray`, default on for Windows/macOS, CI on Linux | GNOME shows no tray without an AppIndicator extension → Linux tray is best-effort. |
| `gilrs` | `=0.11.2` | defaults | **no** (`libudev.pc`) → feature `gamepad`, CI | M5. |
| `directories 6.0.0`, `clap 4.6.6`, `toml 1.1.4`, `tracing-subscriber 0.3.23`, `tracing-appender 0.2.5` | (present) | — | yes | Keep. |

### 1.9 Tooling and CI pins (ci.md §1, §6, §7)

| Item | Pin | Note |
|---|---|---|
| Toolchain | `rust-toolchain.toml`: `1.96.0` + `rustfmt, clippy`; `rust-version = "1.95"` | CI `dtolnay/rust-toolchain@master` honours the file; nightly `nightly-2026-08-28` pinned for the ASan fuzz job only. |
| `actions/checkout` / `upload-artifact` / `download-artifact` / `cache` | `@v7` (7.0.1) / `@v7` (7.0.1) / `@v8` (8.0.1) / `@v6` (6.1.0) | Node 24; SHAs in ci.md §1. `ci.yml` currently uses `checkout@v4` (Node 20). |
| `Swatinem/rust-cache` | `@v2` (2.9.2) | separate `shared-key` for the nightly job. |
| `taiki-e/install-action` | `@v2` (2.87.0) with `tool: cargo-nextest@0.9.143` / `cargo-deny@0.20.2` / `cargo-fuzz@0.13.2` (via binstall) | no `@cargo-fuzz` tag exists. |
| `EmbarkStudios/cargo-deny-action` | `@v2` (2.1.1, bundles cargo-deny 0.20.2) | pass `arguments: --workspace` (default is `--all-features`); Linux only (Docker). |
| `softprops/action-gh-release` | `@v3` (3.0.2) | `permissions: contents: write`. |
| `cargo-fuzz` / `libfuzzer-sys` | `0.13.2` / `0.4.13` | `-s none` works on stable (verified); ASan needs nightly; `fuzz/` excluded from the workspace. |
| `cargo-deny` config | `deny.toml` delta in ci.md §7.3 | add `Unlicense`, `LGPL-3.0-only`; ignore RUSTSEC-2023-0071 (rsa via `ssh-key-fork-arti`) and RUSTSEC-2024-0436 (`paste`) with reasons; drop the dead `LGPL-3.0` id. |
| apt (Linux media job) | `pkg-config cmake nasm clang libclang-dev libavcodec-dev libavutil-dev libswscale-dev libpipewire-0.3-dev libspa-0.2-dev libopus-dev libasound2-dev libxkbcommon-dev libgtk-3-dev libayatana-appindicator3-dev libxdo-dev libudev-dev` | drop `libei-dev`, `libavformat/avfilter/avdevice-dev`, `libdbus-1-dev`, `libwayland-dev`, `libvulkan-dev` from `ci.yml` (unused). |

---

## 2. Version-alignment conflicts and resolutions

### 2.1 `rand_core` — three generations, by design

| Generation | Who | Source |
|---|---|---|
| 0.10 (`rand 0.10.2`, `rand_core 0.10.1`, `getrandom 0.4.3`) | Tornect code, `ed25519-dalek 3`, Arti's public RNG API (`tor-llcrypto` `rand_core = "0.10.1"`), `igd-next`, `crab_nat`, **`quinn-proto 0.11.17`** (`rand = "0.10.1"`, verified in its `Cargo.toml:109`) | crypto.md §0–§3, arti.md:149, nat.md:69 |
| 0.9 | `stun 0.17.2` (M2); today only `proptest` (dev) | nat.md:71, `Cargo.lock` |
| 0.6 (`rand 0.8`) | `ed25519-dalek 2.2` / `curve25519-dalek 4` inside `tor-llcrypto` (`rand_core_06` shim), `opaque-ke 4.0.1`, `voprf 0.5` | arti.md:149/713, crypto.md §2 |

**Resolution.** Tornect code uses **only** rand_core 0.10 traits (`Rng`/`TryRng`/`CryptoRng`,
renamed from `RngCore`/`TryRngCore`; `OsRng` is gone → `getrandom::SysRng` in
`rand_core::UnwrapErr`, or `getrandom::fill`). RNGs never cross generations: opaque-ke gets
the `Rng06` adapter (crypto.md §3.4, the same trick Arti uses), Arti's `KeyMgr::generate`
gets a rand_core-0.10 `CryptoRng`. Duplicates are accepted (`deny.toml`
`multiple-versions = "warn"`); do not try to unify or patch.

### 2.2 `digest` line — arti.md vs crypto.md (real contradiction)

arti.md:151 says "Use RustCrypto 0.10 line in Tornect for hashing that interacts with arti
types; avoid the 0.11 pre-releases." crypto.md §0/§6 (later, probe-verified) says the 0.11
line for everything Tornect writes; `digest 0.11.3` is a release (0.11.0/0.11.1 yanked). The
workspace already builds on `sha2 0.11.0`/`hmac 0.13`/`hkdf 0.13`, and the lock shows the
0.10 copies (`digest 0.10.7`, `sha2 0.10.9`, `sha3 0.10.9`, `hmac 0.12.1`, `hkdf 0.12.4`)
coming only from Arti.

**Resolution: crypto.md wins.** Digest 0.11 line for all Tornect code; interop with Arti
through byte arrays only (`HsId: From<[u8;32]>`/`Into<[u8;32]>`, `to_bytes()`/`from_bytes()`),
never through `Digest`/`Output` types; the single exception is the PAKE module's
`sha2_010` alias for opaque-ke's KE hash. `sha3` stays on `0.11.0` (shared with
`derive-deftly-macros`; crypto.md's `=0.12.0` would add a third copy). Old-generation copies
from `stun` (`md-5 0.10`), `secret-service` (`sha2 0.10`, `hkdf 0.12`) and `openh264`'s
`libloading` feature (`sha2 0.10`; avoided by using `source`) are tolerated.

### 2.3 `rustls` / crypto provider — all notes agree on `ring`, two notes disagree on facts

- Workspace: `rustls =0.23.43` (`ring, std`); quinn `rustls-ring`; `tor-rtcompat`'s `rustls`
  feature pulls rustls with **no provider** (arti.md §2.2) → the app installs ring once
  (`tornect_signal::install_crypto_provider()`, decision M1-3). Both `tor-rtcompat`'s
  source comment (prefers aws-lc-rs, arti.md:210) and rustls' own default
  (`aws_lc_rs + prefer-post-quantum`, quic.md:88) are overridden.
- Contradiction: arti.md:206 and :808 say aws-lc-rs needs "cmake + nasm on Windows";
  quic.md:109 quotes the aws-lc-rs README: "CMake is never required", nasm only through the
  optional `prebuilt-nasm` feature. Moot (ring chosen), but arti.md is the stale one.
- Rule: **no crate in the workspace may enable rustls default features** (both providers
  compiled ⇒ `CryptoProvider` panic, quic.md §12.1). CI guard: `cargo tree -i aws-lc-sys`
  and `-i openssl-sys` empty (already in `docs/notes/m1-track1-evidence.md`).
- `stun 0.17.2` pulls `ring 0.17.14` — the same version; `rustls-webpki`/`rcgen` only in the
  rejected X.509 path. `stun`'s `ring` is a second reason to stay on ring.

### 2.4 `wgpu` / `winit` / `raw-window-handle` — one copy each, plan text amended

ui.md §2 proves a single `wgpu 30.0.1`, `winit 0.30.13`, `raw-window-handle 0.6.2`,
`zbus 5.19.0`, `arboard 3.6.1` in the probe lock. No other note introduces these crates
(codecs.md §8, wayland.md §5 confirm no coupling). The conflict is architectural: plan D10
("egui/eframe … streaming window = winit + wgpu") vs ui.md §4 (own the loop). **Resolution:
no `eframe` dependency; manual winit loop from M3** (§1.8). Related alignments: `cpal 0.18`
→ `objc2 0.6` and `windows 0.62` match ours; `zbus` must be driven by tokio (`ashpd/tokio`,
`notify-rust/z-with-tokio`, keyring store `rt-tokio-crypto-rust`; never `async-io`).
Unknown/unverified: HDR (`Rgba16Float`) surface support and Windows/macOS builds of the UI
stack (ui.md §8 "not probed").

### 2.5 `argon2` — opaque-ke's 0.5 vs direct 0.6

`opaque-ke 4.0.1`'s `impl Ksf for argon2::Argon2` is for **argon2 0.5** (re-exported as
`opaque_ke::argon2`, crypto.md §8.1); `argon2 0.6.0` (2026-08-27) is the new-stack crate.
Both coexist (probe), but naming the 0.6 type as `Ksf` will not compile. CLAUDE.md's
security invariants already fix the design: unattended access = OPAQUE with an Argon2id KSF
bound to the signed transcript + `session_token`. **Resolution: v1 depends on
`opaque-ke` only; the KSF is `opaque_ke::argon2::Argon2::new(Argon2id, V0x13,
Params::new(64*1024, 3, 1, None))` (client-side cost, ~0.1–0.3 s — unmeasured); no direct
`argon2` dependency; plan §B.6's "Argon2id-hashed password" is read as this.** Also fixes the
`use opaque_ke::*` shadowing of `rand` (crypto.md §12.4): never glob-import it.

### 2.6 MSRV / toolchain

Facts: workspace `rust-version = "1.90"` (`Cargo.toml`, `CLAUDE.md:94`); `arti-client` MSRV
1.91 (arti.md:40); `egui 0.36` 1.95 (ui.md:35); `rcgen 0.14.9` 1.88; `ffmpeg-sys-next 9.0.0`
≥ 1.88 (let-chains); VM 1.96.0; CI `@stable` 1.98.0. `resolver = "3"` is MSRV-aware and
will pick older patch versions of non-`=` deps to satisfy 1.90. ui.md:35 states "Workspace
`rust-version = "1.95"`" as if it were already true; ci.md:238 records the real 1.90.
**Resolution:** `rust-version = "1.95"` now; `rust-toolchain.toml` = `1.96.0` (ci.md §5
option b); update `CLAUDE.md:94`; bump deliberately with `rustup update`.

### 2.7 `socket2` / `SO_REUSEADDR`

quic.md:375 (`sock.set_reuse_address(true)`) vs nat.md:21, :369, :537 (never on the media
socket; Windows port-hijack semantics; not needed for UDP punching). **Resolution: off.** The
quic probe needed it only to rebind quickly on loopback.

### 2.8 QUIC fixed-bit greasing (new; verified) — see §0.1

`EndpointConfig::grease_quic_bit(false)` on both roles; demux test asserting `byte0 & 0x40`
on every quinn transmit; STUN demux via `stun::message::is_message` (magic cookie), not the
first byte alone.

### 2.9 Opus in-band FEC and application mode

Plan §B.4 "FEC-in-band (Opus LBRR)" vs codecs.md §5.3 ("keep `set_inband_fec(true)` … cheap")
vs media-proto.md §5.6 (`set_inband_fec(false)`). All agree LBRR exists only in SILK/hybrid
and never fires in `RESTRICTED_LOWDELAY`/CELT. **Resolution:** `Application::LowDelay`,
`set_inband_fec(false)`, `set_packet_loss_perc(0)`, 10 ms frames, previous-frame
redundancy in the next datagram + PLC (media-proto.md §5.6); amend §B.4.

### 2.10 Datagram header size / MTU

Plan §B.4 "12–20 bytes", "~1200 B payload"; codecs.md:513 "~10 B"; media-proto.md §2.3 "12 B".
**Resolution:** 12-byte header + 4-byte RaptorQ PayloadId; payload = live
`Connection::max_datagram_size()` (1162 @1200, 1414 @1452), re-read per frame; symbol
1144/1392 B. Amend §B.4.

### 2.11 Punch mechanics

Plan §B.2 "paced bidirectional QUIC Initial+padding to all candidate pairs" vs quic.md §12.14
and nat.md §5.5 (STUN-style probes on the demuxed socket, ICE pacing Ta = 50 ms, RTO ≥ 500 ms
doubling, then one `connect_with()` from the deterministic client = lower device pubkey).
**Resolution: probes outside QUIC, single dial.** Amend §B.2; `draft-seemann` is an expired
individual draft with no pacing text (nat.md §4) — structure only.

### 2.12 Wayland persistence location, minimum GNOME, lock screen

Plan §B.5 puts `persist_mode`/restore token on the ScreenCast `SelectSources`; the portal
spec forbids that on a RemoteDesktop session (wayland.md §2.5). **Resolution:** token on
`SelectDevicesOptions` only; minimum GNOME 45 (portal RemoteDesktop v2) added to the
minimum-targets decision (M0-4 says only "xdg-desktop-portal ≥ 1.17"); the locked screen
terminates every portal session on GNOME (wayland.md §7) → new honest constraint in §A.4.

### 2.13 FFmpeg majors / PipeWire feature level / `windows` crate

FFmpeg: plan "≥ 7.x"; `ubuntu-latest` 6.1; VM/26.04 8.0.1; crate 9.0.0 → §1.5 decision.
PipeWire: `v1_0_0` everywhere (cpal's `v0_3_53` unifies upward). `windows`: `=0.62.2`
(ci.md) = cpal's `0.62`; winit/if-addrs/wgpu bring `windows-sys` duplicates — accepted.

### 2.14 TLS identity format

Plan §B.2/§B.6 "self-signed certs whose SPKI must match", "`quic_server_cert_fp`" vs quic.md
§3.3 (raw public keys). **Resolution: RPK**; the pinned value is the 44-byte SPKI DER; the
signaling field becomes `quic_spki` (or is dropped entirely: the pins already come from
pairing). Amend §B.2/§B.6.

---

## 3. Claims without a source, or that read as memory rather than verification

Status: **WRONG** = contradicted by a source checked here or in another note; **UNSOURCED** =
plausible but no citation; **ESTIMATE** = author's guess presented as a number; **SELF-FLAGGED**
= the note itself says it is unverified (listed so it is not forgotten).

| # | File:line | Claim | Status | Action |
|---|---|---|---|---|
| 1 | nat.md:422 | "quinn doesn't grease by default; quic.md §7" | **WRONG** — `quinn-proto-0.11.17/src/config/mod.rs:63` `grease_quic_bit: true`; `packet_builder.rs:127` randomizes the fixed bit | `grease_quic_bit(false)`; test |
| 2 | nat.md:472 | conntrack UDP defaults "30 s unreplied / 180 s stream" | **WRONG** — kernel `nf_conntrack_proto_udp.c`: unreplied 30 s, replied/stream **120 s** | fix harness comment; read `sysctl` in CI |
| 3 | arti.md:151 | "avoid the 0.11 pre-releases" (digest) | **WRONG** — `digest 0.11.3` is a release (crypto.md:88); 0.11.0/0.11.1 yanked | §2.2 |
| 4 | arti.md:206, :808 | aws-lc-rs "cmake + nasm (aws-lc-sys) — nasm absent here"; "needs cmake+nasm on Windows CI" | **WRONG** vs aws-lc-rs README quoted at quic.md:109 ("CMake is never required", nasm only via `prebuilt-nasm`) | moot (ring) |
| 5 | codecs.md:315 vs media-proto.md:488 | VideoToolbox `constant_bit_rate=1`: "Apple Silicon only; falls back to VBR" vs "macOS 13+" | **CONTRADICTORY, both UNSOURCED** | check `videotoolboxenc.c` gating; try/fallback at runtime |
| 6 | ui.md:35 | "Workspace `rust-version = "1.95"`" | **WRONG as stated** (it is 1.90; ci.md:238) — a recommendation phrased as fact | §2.6 |
| 7 | ci.md:178 | "FFmpeg 8-only APIs (`AV_HWDEVICE_TYPE_AMF`, D3D12VA, Vulkan encode…) are absent on 24.04" | UNSOURCED version attribution (D3D12VA landed in 7.0; AMF device type / Vulkan encode in 7.1 per memory) | check `doc/APIchanges`; the conclusion (absent on 6.1) still holds |
| 8 | arti.md:105, :769–771 | "non-experimental since Arti 1.2.0"; "1.8.0 (2025-12) added `arti hsc ctor-migrate`" | UNSOURCED (no URL; other releases cite blogs) | cite release posts |
| 9 | arti.md:296–298 | `b.stream_timeouts().connect_timeout(..)` setter | SELF-FLAGGED (not compile-verified) | compile in `tornect-signal` |
| 10 | ci.md:239, codecs.md:526 | `ffmpeg-sys-next 9.0.0` "needs ≥ 1.88 (let-chains)" | UNSOURCED inference (crate has no `rust-version`) | fine under 1.95; note as inference |
| 11 | ci.md:306 | "Windows is unsupported by libFuzzer per README" | UNSOURCED (quote not reproduced) | irrelevant: fuzz on Linux only |
| 12 | codecs.md:232 | zero-copy `AVFrame` layouts: DRM_PRIME `data[0]` = `AVDRMFrameDescriptor`, D3D11 `data[0]`/`data[1]`, VIDEOTOOLBOX `data[3]` | UNSOURCED (from memory; correct per `pixfmt.h`/`hwcontext_*.h` docs) | cite headers before M7 |
| 13 | codecs.md:256 | `h264_cuvid` outputs CUDA frames "no hwaccel negotiation" | UNSOURCED | verify in `cuviddec.c` |
| 14 | codecs.md:275 | x264 `tune=zerolatency` expansion (bframes 0, rc-lookahead 0, sync-lookahead 0, sliced-threads, no mbtree) | UNSOURCED (x264 `base.c` `x264_param_apply_tune`) | cite |
| 15 | codecs.md:296 | "`d3d11va` device works with NVENC on Windows" | UNSOURCED | verify `nvenc.c` pix_fmt list |
| 16 | codecs.md:311 | `low_power=1` "(VDENC)", `quality=7` "(Intel: higher = faster)" | UNSOURCED | driver docs |
| 17 | codecs.md:313 | AMF "works on Linux via Vulkan too" | UNSOURCED | `hwcontext_amf.c` / AMF README |
| 18 | codecs.md:425 | "~3–5× for nasm asm and a faster desktop CPU"; "SVT-AV1 preset 12" | ESTIMATE | keep as estimate |
| 19 | codecs.md:430 | FFmpeg's "built-in `av1` decoder already uses libdav1d" | IMPRECISE — native `av1` (hwaccel) and `libdav1d` are separate decoders; which `find(Id::AV1)` returns depends on registration order | check `decoder::find(Id::AV1).name()` in CI |
| 20 | codecs.md:475–476 | "5 ms increases overhead (~+20 %)"; DRED "speech-only" | ESTIMATE / UNSOURCED | opus 1.5 release notes |
| 21 | crypto.md:461 | Argon2 m=64 MiB,t=3 "~0.1–0.3 s on a laptop" | ESTIMATE | measure in the PAKE tests |
| 22 | media-proto.md:393 | consumer clocks "≤ ±100 ppm ⇒ ≤ 6 ms/min" | UNSOURCED general claim | fine; cite a reference or measure drift |
| 23 | media-proto.md:606 | `ApiInformation::IsPropertyPresent("…Direct3D11CaptureFrame","DirtyRegions")` | UNSOURCED API name | verify `windows` crate `Foundation_Metadata` |
| 24 | nat.md:36 | natpmp "unmaintained since 2024-11" | INFERENCE from last release date | wording |
| 25 | nat.md:378 | Google STUN "no published ToS … de-facto public server for 10+ years" | OPINION/UNSOURCED | keep as opinion |
| 26 | nat.md:399; plan:55 | "iroh 1.0 (June 2026)" ships a NAT-traversal extension; "press coverage" | UNSOURCED (no URL anywhere; quic.md:604 cites only iroh 1.1.0 on crates.io) | cite or drop the date |
| 27 | nat.md:468, :491 | `--random-fully` = `NF_NAT_RANGE_PROTO_RANDOM_FULLY`; MASQUERADE + conntrack ≈ port-restricted, `--random-fully` ≈ symmetric | UNSOURCED (author asks for an RFC 5780 check) | verify in the harness |
| 28 | quic.md:138 | ring `from_pkcs8_maybe_unchecked` accepts PKCS#8 v1 or v2 | UNSOURCED (v1 implicitly verified by the probe) | fine |
| 29 | ui.md:454 | keyutils store: "session keyring only (lost at logout)" | UNSOURCED | read the store's README |
| 30 | wayland.md:404 | "GNOME hands out separate virtual devices per capability" | UNSOURCED (mutter behaviour) | confirm in the interactive probe |
| 31 | wayland.md:408 | `ei_keyboard.key` takes evdev codes "= xkb keycode − 8" | UNSOURCED (standard, libei docs) | cite |
| 32 | arti.md:689–690 | `IPT_PUBLISH_UNCERTAIN = 3 h` etc. | file cited without lines | fine |
| 33 | codecs.md §2.4 (179–230), §11.3 | hw device/frames glue "not compiled here" | SELF-FLAGGED | compile in the CI `ffmpeg` job (M3) |
| 34 | nat.md §2.2.4, §10.1 | `netdev 0.46.1` "not extracted/verified" | SELF-FLAGGED | §1.4 |
| 35 | nat.md:380–381, §10.5 | Twilio / Nextcloud STUN "not verified live", terms unclear | SELF-FLAGGED | before 1.0 |
| 36 | wayland.md:580, §9.5 | KDE / wlroots lock-screen and `ConnectToEIS` behaviour | SELF-FLAGGED | M6 |
| 37 | ui.md §8 "Not probed" | Windows/macOS builds of the UI stack; interactive pointer lock | SELF-FLAGGED | cross-check at M3 |
| 38 | arti.md:797–803 (Q7/Q8) | PoW never exercised under load; `dynasmrt` JIT on macOS hardened runtime / Windows | SELF-FLAGGED | M1 load test; M6 |

Plan (`TORNECT_PLAN.md`) claims that **no note verified** (all read as memory; several are
load-bearing for product copy):

| Plan line | Claim | Note |
|---|---|---|
| 41–46 | Arti 2.0.0 "biggest release … stable onion service support"; "removes the historical blocker" | Date right, framing off: HS services were stable since 1.2.0 and 2.0.0 had "No HS changes" (arti.md:748); `arti-client` is 0.45.0 |
| 55–57 | iroh 1.0 June 2026; "docs explicitly note the transport wire can be swapped (they name Tor)" | unsourced (see #26) |
| 61 | str0m "production-proven as an SFU, P2P/ICE less battle-tested" | unsourced |
| 66–67 | MoQT "draft-18 (May 2026)", "known cross-draft incompatibility" | unsourced |
| 77–80 | "since xdg-desktop-portal 1.17 hands the app a libei connection", "libei 1.0 since 2023", "Xwayland ≥ 23.2 bridges XTEST" | wayland.md verifies RemoteDesktop v2 `ConnectToEIS`, not these version numbers |
| 94–99 | codec table incl. "Apple AV1 decode-only (M3+)", "Intel Arc/Gen12.5+ AV1" | media-proto.md §9 verifies chroma/bit-depth, not these generations |
| 104–106 | "FFmpeg ≥ 7.x … hw-frames zero-copy (d3d11va → NVENC/AMF/QSV …)" | see §1.5; the D3D11→QSV/AMF interop is unverified |
| 110 | "Sunshine+Moonlight (GPL, 40k+ ★)" | unsourced |
| 146 | "industry direct-connect rates roughly 80–90 %" | unsourced |
| 638 | "Windows 10 20H1+ (WGC needs it)" | WGC exists since 1803; 20H1 attribution unsourced |

---

## 4. Topics M0–M3 need that no note covers

### M1 (in progress) — `tornect-signal`

1. **CBOR crate + deterministic encoding** (§0.2a): pick the crate; define the exact bytes
   that go into the transcript hash (canonical CBOR of each envelope, or the raw length-
   prefixed frames as received — the latter needs no canonicalization and is simpler).
2. **§B.8 text** (§0.2b): the unattended-access protocol (OPAQUE identifiers/context binding,
   grant storage, lockout counters, dummy-record anti-enumeration, indicator rules) must be
   written into `docs/PLAN.md`/`TORNECT_PLAN.md` (kept identical by `xtask verify`).
   crypto.md §8 provides every primitive and measured sizes.
3. **SAS definition**: crypto.md:394 gives `u32::from_be_bytes(HKDF(th, "tornect v1 sas")[..4]) % 1_000_000`
   — the plan only says "derived from transcript hash". Fix the label, hash choice, and which
   messages are in the transcript (HELLO…SESSION_ACCEPT).
4. **Abuse controls' concrete form**: accept-queue semaphore size, per-pk token bucket, temp-ban
   persistence file format (§B.3) — arti.md §8.3 says where (filter `RendRequest`s before
   `handle_rend_requests`), not what.
5. **PoW under load** and the `connect_timeout` raise (arti.md Q7, :296) — unexercised.
6. **Fuzz job on stable** (`-s none`, ci.md §6) and the `fuzz/` workspace exclusion — not yet
   in `ci.yml`; VERIFICATION says "nightly toolchain" only.
7. **Second real machine** for the M1 acceptance (VERIFICATION row OPEN).

### M2 — `tornect-net`

1. **Default-gateway / client-IP discovery** (§1.4) — a hard dependency of crab_nat.
2. **`grease_quic_bit(false)`** (§0.1) and the demux `AsyncUdpSocket` design: our STUN/punch
   sends must go through the same `quinn_udp::UdpSocketState` (GSO `Transmit.segment_size`
   semantics) — quic.md §9 describes the shape, nothing is written or probed.
3. **Tor-fallback transport**: nobody designed the multiplexing of `ctrl`/`input`/media over
   one Arti `DataStream` (framing, priority, backpressure vs Arti's stream window), nor
   **measured onion-stream throughput/latency from this VM** — the plan's "1–6 Mbit/s" is an
   assumption. Also decide: media on the same rendezvous circuit (`connect` again, shared
   bandwidth) or a second isolation group (arti.md §9).
4. **Signaling mock** for the netem harness (`tests/integration/… localhost-tor mocks`, plan
   §B.1) — a `SignalChannel` trait with a TCP-localhost impl; trivial but unplanned.
5. **IPv6 / dual-stack policy** (nat.md Q6, quic.md §12.8): one v6 socket with `only_v6(false)`
   vs two sockets; Windows wildcard v6 is not dual-stack.
6. **Cross-target `cargo check`** of quinn/socket2/if-addrs/igd-next/crab_nat/stun on
   `x86_64-pc-windows-msvc` and `aarch64-apple-darwin` — ci.md cross-checked only the
   `windows`/`objc2` probes; `cross-check` in CI will catch it, but nobody ran it.
7. **STUN list config format** (hostnames, A+AAAA resolution, per-server transaction ids,
   `SOFTWARE = "Tornect/<ver>"`), empty-list behaviour, and the CGNAT diagnostic
   (`mapped_ip ∈ 100.64/10`) — nat.md §3/§6 give the policy, not the schema.
8. **Keepalive/idle budget** with the Tor circuit as heartbeat: quinn `keep_alive_interval` 2 s /
   `max_idle_timeout` 10 s (quic.md §8) vs NAT 15–25 s keepalive (nat.md §5.7) — reconcile.
9. **Role tie-break + `Incoming::accept_with` per-peer pins + mandatory accept loop**
   (quic.md §5, §12.2) — decisions documented in notes, not in the plan.
10. **Local punch-success statistics** format (plan Part E) — unspecified.

### M3 — `tornect-proto`, `tornect-capture`, `tornect-codec`, stream window

1. **VM-scoped acceptance** (§0.3): define what "M3 green on mx-vm" means (e.g. synthetic
   source → openh264 → in-proc → openh264 → wgpu at 1080p30 or 720p60, latency ≤ 35 ms p95)
   and mark 1080p60/hw-codec/CPU<15 % as `NEEDS-DEVICE(gpu)`. The Linux CI runner has no
   GPU either, so the hw path stays `NEEDS-DEVICE` until a real box is available.
2. **Synthetic capture source** and the **`--headless-stats` JSON schema** (consumed by the
   netem harness, `xtask soak`, and the HUD) — CLAUDE.md names both; no note specifies them.
3. **RGB(A)→NV12/I420 conversion cost**: PipeWire/WGC/SCKit deliver BGRx/BGRA; every encoder
   wants YUV. Options exist (`openh264` `YUVBuffer::read_rgb8` with `wide` SIMD, `swscale`,
   a wgpu compute shader) but no note measures 1080p60 cost or picks one; the GPU route also
   needs DMA-BUF→wgpu import (M7, ui.md Q1).
4. **Parameter-set repetition**: never set `codec::Flags::GLOBAL_HEADER` (codecs.md:116 lists
   it as available); SPS/PPS must accompany every IDR for late join/recovery (x264 default,
   NVENC `repeatSPSPPS` when no global header, openh264 `SpsPpsStrategy`) — unverified.
5. **Runtime bitrate reconfiguration** per backend (the ABR needs it every frame): FFmpeg has no
   safe setter (codecs.md §10.1: raw `av_opt_set_int` on `priv_data` / `bit_rate` field),
   openh264 needs `raw_api().set_option(ENCODER_OPTION_BITRATE)` — neither verified.
6. **Cursor path**: metadata cursor mode (wayland.md §4.4 `MetaCursor`) implies shipping
   cursor shape/position over `ctrl` and compositing in the wgpu overlay — not designed.
7. **Packetizer wire header** exact bit layout (12 B, flags/frame_id/frag/rtp_ts/stream_id),
   per-frame symbol size carried in the first datagram (media-proto.md §14.1) — spec needed.
8. **FEC on tiny K** (media-proto.md Q2): XOR vs RaptorQ +2 floor vs `reed-solomon-erasure`
   (not evaluated).
9. **ABR simulation harness** before netem (media-proto.md Q1) — trendline vs Kalman choice
   needs a deterministic simulator; feedback transport (datagram vs `stats` stream, Q7).
10. **Glass-to-glass measurement method** in a loopback without a camera (timestamps at
    capture/present, `Frame.ts` stages) — define the proxy the §B.7 gate actually checks.
11. **Restore-token portability**: M3 capture-only may create a ScreenCast session while M5
    needs the combined RemoteDesktop session; whether a ScreenCast restore token is reusable
    for a RemoteDesktop session is unknown — start with the RemoteDesktop session in M3 or
    accept one extra consent dialog at M5.
12. **wgpu HDR/P010 surface formats** and Windows/macOS builds of the render window (ui.md
    Q2, §8) — unverified.
13. **Datagram receive-path throughput** at 100k pps through `quinn::Connection::read_datagram`
    (quic.md Q6) — measure; fallback is driving `quinn-proto` sans-IO.

### Cross-cutting (documentation and CI)

- Update `.github/workflows/ci.yml` per ci.md §10 before 2026-09-23; apply the `deny.toml`
  delta; add `rust-toolchain.toml`; bump `rust-version`; run `gh auth refresh -s workflow`
  so the workflow can be pushed at all (VERIFICATION M0).
- Promote §1.3–§1.8 rows into `docs/DEPENDENCIES.md` as each crate enters `Cargo.toml`.
- Plan amendments to apply (keep both copies identical): §A.2 FFmpeg version; §A.4 add "Linux
  host must be unlocked (GNOME)"; §B.2 punch mechanics + `quic_spki`; §B.4 Opus FEC, MTU/header;
  §B.5 Wayland persist location, no x264-first, no rav1e/svt-av1/dav1d; §B.6 RPK; D9 `opus`
  crate; D10 no eframe; D13 `keyring-core`; M2 "`stun-client`" → `stun`; write **§B.8**.
- Later-milestone items already visible: FFmpeg redistribution/`xtask ffmpeg-fetch` (M6/M8),
  OpenH264 patent posture (M8), `dynasmrt` JIT vs macOS hardened runtime (M6), tray on
  GNOME (M8), KDE/wlroots portal coverage (M6).