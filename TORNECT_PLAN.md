# TORNECT — Master Engineering Plan

**Decentralized remote desktop & game streaming. Tor onion v3 for identity + rendezvous, direct P2P QUIC for media. No servers to run, no port forwarding, no accounts.**

> This document is the single source of truth for building Tornect with Claude Code.
> It contains: the research findings and technology decisions (Part A), the full system
> architecture and protocol design (Part B), the milestone roadmap with acceptance
> criteria (Part C), and the Claude Code execution kit — agents, workflows, prompts
> (Part D). Drop this file and `CLAUDE.md` into an empty repo and start with the
> Milestone 0 kickoff prompt in §D.6.

**Plan date:** 2026-08-28. Versions cited were verified via web research on this date.
Claude Code MUST re-verify exact crate/SDK versions against crates.io and vendor docs
before pinning dependencies (see the `research-verifier` agent in §D.3).

Revision: 2026-09-27 r7 — sections touched: §A.2, D8, D10, §B.1 (new §B.1.1), §B.2 (new §B.2.1), §B.5, §B.6 (new
§B.6.1), §B.8.1, §B.8.2 (T9), §B.8.4.1, §B.8.6.2–3, §B.8.7.1, §B.8.7.3–5, §B.8.8, §B.8.9 (new §B.8.9.1), §B.8.10,
§B.8.13, §B.8.17, Part C (M3, the desktop release, the backlog), D.3, Part E, Part F.6–8, Part G — the desktop
amendment for Linux and Windows (session levels and administrator access on Windows, product modes, saved devices and
device words, the vendor codec APIs, egui everywhere, Android to the roadmap) with the internal security review's
changes folded in; decisions M1-56 … M1-67, itemised in Part G (M1-67: the F4-1 amendment of 2026-10-01: §B.2.1, §B.8.2,
§B.8.4.1–2, §B.8.6.1–2, §B.8.7.1–2, §B.8.7.4, §B.8.9, §B.8.9.1, §B.8.10, §B.8.13, §B.8.15–17, Part C rows 7 and 10, Part
G).

r6: 2026-08-29 — sections touched: §A.2, §A.4, §B.1, §B.2, §B.4, §B.5, §B.6, §B.8.1–2 (T1/T2/T12, B.8.2.1), §B.8.4.1–2/4.5–4.6, §B.8.5.1/5.3, §B.8.6.2–3, §B.8.7.3–5, §B.8.8, §B.8.9, §B.8.10, §B.8.12–17, Part C M1–M4/M6–M8, D.1, D.3, D.4, D5/D6/D9/D10/D12/D13, Part E, Part F.6, Part G — itemised there (runtime-monotonic decay/clock rules; the local *Suspend* reason `Suspended{Local{by}}`; UI plan adopted; research-audit amendments; the r6 review passes). r5: Part G execution status added; Part F decisions recorded (r4: §B.8 Unattended access, second review pass).

---

## Part A — Research findings & technology decisions

### A.1 The problem Tornect solves

Existing tools, and why each fails the "just works, free, private" test:

| Tool | Discovery / NAT traversal | Weakness for our use case |
|---|---|---|
| Sunshine + Moonlight | None — LAN mDNS only; WAN needs manual port-forward or VPN | Best-in-class streaming quality (the reference to beat), but remote access setup is exactly the pain point: port forwarding, DDNS, or Tailscale/VPN required |
| RustDesk | Central rendezvous (`hbbs`) + relay (`hbbr`) servers | Free tier depends on RustDesk's public servers; self-hosting means running a server — which we explicitly refuse |
| AnyDesk / TeamViewer / Parsec | Vendor cloud brokers | Proprietary, account-based, commercial-use restrictions, vendor can see metadata |
| Tailscale + anything | DERP relays + coordination server | Excellent, but adds an account + third-party coordination plane |

**Tornect's thesis:** the Tor network is a free, volunteer-run, globally available
rendezvous system that nobody has to operate. An onion v3 address is simultaneously
(1) a stable, NAT-independent way to reach a machine, (2) a self-authenticating
cryptographic identity (the address *is* the ed25519 public key), and (3) an
encrypted signaling channel. Use Tor only for the handshake; stream media over a
direct, hole-punched QUIC connection. Fall back to streaming over Tor itself when
punching fails — degraded, but it *always* works.

### A.2 Verified state of the art (Aug 2026)

**Tor / Arti.** Arti — the Tor Project's official Rust implementation — reached
**2.0.0 (Feb 2026)**, described by the Tor Project as its biggest release, with
**stable onion ("hidden") service support** and a design intended for embedding as a
library. `arti-client` exposes cargo features `onion-service-client` and
`onion-service-service`. This removes the historical blocker (bundling and driving a
C `tor` daemon). Tornect embeds Arti in-process. Consequences we design around:
onion service descriptor publication takes ~30–120 s after cold start; signaling RTT
through a full onion circuit is typically 0.4–1.5 s (fine for handshakes, useless for
media); onion services have built-in DoS defenses (PoW-based intro protection,
vanguards) we should enable.

**NAT traversal.** The industry has converged on *coordinated UDP hole punching with
a fallback relay*, increasingly expressed **inside QUIC** rather than as a separate
ICE layer: IETF `draft-seemann-quic-nat-traversal` (an expired individual draft — -02,
2024-03-03, never adopted by the QUIC WG, no probe-pacing text; upstream `quinn` implements
none of it, so Tornect punches *outside* QUIC and hands the validated socket to quinn, §B.2;
docs/research/nat.md §4, quic.md §0), implemented as a variant by
**iroh** (via its `noq` fork; iroh 1.1.0, quic.md §10) — a Rust library that dials peers by
ed25519 public key, hole-punches QUIC via a NAT-traversal extension it "does not expect to
follow exactly" (nat.md §4), and falls back to relays; the earlier claims of a June 2026 "iroh 1.0"
and of docs that let the transport wire be swapped (naming Tor) are unsourced (SUMMARY.md §3 #26)
and carry no weight here. iroh validates our exact architecture: *public-key dialing + punched QUIC*. We differ
in one deliberate way: our rendezvous/coordination channel is a Tor onion circuit
instead of iroh's relay servers, so there is no third-party coordination plane.
str0m (sans-IO Rust WebRTC, production-proven as an SFU, P2P/ICE less battle-tested)
and webrtc-rs/rtc remain credible alternatives if browser interop ever becomes a
goal; for a native-only v1, WebRTC's SDP/DTLS-SRTP machinery is dead weight compared
to bare QUIC.

**Media transport.** Media-over-QUIC (MoQT) is at IETF draft-18 (May 2026), not yet
an RFC, with known cross-draft incompatibility; it targets relay/CDN fan-out, not
1:1 remote desktop. Verdict: borrow its *ideas* (datagrams for latency-critical
media, streams for control, partial reliability) in a small custom protocol over
`quinn`; do not adopt MoQT itself in v1.

**Capture & input, per platform (the parts that make or break "native" support):**

- **Linux/Wayland** — capture via the **xdg-desktop-portal ScreenCast** interface
  delivering **PipeWire** streams, with **DMA-BUF** buffers for zero-copy GPU frames;
  session **restore tokens** avoid re-prompting the user every launch. Input
  injection via the **RemoteDesktop portal**, which since xdg-desktop-portal 1.17
  hands the app a **libei** (Emulated Input, 1.0 since 2023) connection —
  compositor-mediated, works unprivileged and inside Flatpak, integrated in
  GNOME/KDE; Xwayland ≥ 23.2 even bridges XTEST through it. This stack is the
  correct, modern answer — no uinput root hacks. Rust bindings: `ashpd` (portals),
  `pipewire` crate, `reis` (libei).
- **Windows** — capture via **Windows.Graphics.Capture** (D3D11 textures,
  per-monitor, HDR-capable) through the `windows` crate; input via `SendInput`;
  audio loopback via WASAPI. (DXGI Desktop Duplication remains a fallback for
  older/edge configs.)
- **macOS** — capture + system audio via **ScreenCaptureKit** (the only sanctioned
  modern API; old CGDisplayStream paths are deprecated), Metal/IOSurface textures;
  input via CGEvent posting (requires Accessibility permission); Screen Recording
  TCC permission required. Rust: `objc2` + `objc2-screen-capture-kit` bindings.

**Hardware codecs (encode ~1–5 ms/frame at 1080p60 on current silicon):**

| Vendor | API (Win) | API (Linux) | H.264 | HEVC | AV1 encode |
|---|---|---|---|---|---|
| NVIDIA | NVENC | NVENC (via CUDA) | ✅ | ✅ | RTX 40 (Ada)+ |
| AMD | AMF | **VA-API** (Mesa) | ✅ | ✅ | RDNA3 (RX 7000)+ |
| Intel | Quick Sync (libvpl) | **VA-API** | ✅ | ✅ | Arc / Gen12.5+ iGPU |
| Apple | — | — (VideoToolbox on macOS) | ✅ | ✅ (+ Main10 HDR) | decode-only (M3+) |

Practical codec ladder: negotiate **AV1 > HEVC > H.264** by mutual capability;
low-latency tuning everywhere (CBR-ish rate control, zero B-frames, infinite GOP +
**intra-refresh** instead of periodic IDR spikes, ≤1 frame lookahead).
FFmpeg (`libavcodec`) exposes every encoder above through one API with
hw-frames zero-copy (`d3d11va` → NVENC/AMF/QSV on Windows, `vaapi` + `cuda` on
Linux, `videotoolbox` on macOS) — that uniformity is why it's our v1 encode/decode
layer, with per-vendor native SDK backends as a v2 optimization behind the same
trait. **r7 inverts this (D8, decision M1-56):** v1 uses the OS and vendor codec APIs directly — Media Foundation and
NVENC on Windows, OpenH264 everywhere, VA-API designed but not shipped — and no FFmpeg, because FFmpeg does not build on
the dev VM (codecs.md §0) and its ABI changes between majors (below), so it would have to ship with every release, while
Media Foundation is part of Windows and the NVENC runtime comes with the driver; v1 sends H.264 Constrained Baseline
only (§B.5), and the codec ladder above waits for a decoder-capability negotiation (roadmap M-CODEC-5). The FFmpeg facts
below are kept as the research record. Versions (r6): the bindings are `ffmpeg-next`/`ffmpeg-sys-next` **9.0.0**, which
build against any FFmpeg **6.1–9.0** (bindgen from the installed headers; upstream CI matrix
6.1/7.0/7.1/8.0/8.1/9.0); `ubuntu-latest` (24.04) ships **6.1**, Ubuntu 26.04 and this dev VM
**8.0.1**; FFmpeg 9.0 (Aug 2026) broke ABI across all seven libraries. We target the **8.x
API**, gate 8-only symbols on the `ffmpeg_8_0` cfg the build script emits (for its own crate — `tornect-codec/build.rs`
re-derives it from the `DEP_FFMPEG_*` variables `ffmpeg-sys-next` exports, codecs.md §10 item 13: `tornect-codec` lists
`ffmpeg-sys-next` directly — Cargo passes `DEP_FFMPEG_*` only to immediate dependents — and emits
`cargo:rustc-cfg=feature="ffmpeg_8_0"` plus the matching `cargo:rustc-check-cfg`, without which `-D warnings` trips
`unexpected_cfgs`), run the media CI job
on `[ubuntu-24.04 (6.1), ubuntu-26.04 (8.0.1, continue-on-error while preview)]`, and ship
FFmpeg with releases (M8) rather than depend on the distro's major (docs/research/codecs.md
§2.1, ci.md §3).

**Reference quality bar:** Sunshine+Moonlight (GPL, 40k+ ★, the de-facto standard
self-hosted stack in 2026) achieves single-digit-ms added latency on LAN and 4K60
HDR on capable hardware. Tornect must match their media pipeline quality while
deleting their setup pain (pairing PINs on a web UI, port forwarding, VPNs).

### A.3 Decision record (what we're building with, and why)

| # | Decision | Choice | Why | Rejected alternatives |
|---|---|---|---|---|
| D1 | Language | **Rust** (edition 2024, stable toolchain) | Arti is Rust-native; quinn/wgpu/windows-rs/objc2/ashpd give first-class OS coverage; memory safety in a network-facing app; single language for all 3 platforms | C++ (Sunshine's choice — mature but unsafe, and no Arti); Go (weak GPU/FFI story) |
| D2 | Tor integration | **Embed `arti-client`** with `onion-service-service` + `onion-service-client` | In-process, no daemon to ship/manage; per-app state dir; stable since Arti 2.0 | Bundling C tor + control port (fragile, heavyweight) |
| D3 | Identity | **Onion v3 address = host identity**; separate per-device ed25519 keys for client devices, pinned at pairing | Self-authenticating, zero-infrastructure, human-shareable (56 chars, QR) | Custom PKI (needs infrastructure); iroh EndpointIds (ties identity to iroh) |
| D4 | Signaling | Length-prefixed **CBOR** messages over an onion stream (versioned envelope) | Tor circuit is already E2E-encrypted+authenticated to the onion key; CBOR = compact, schema-evolvable, great serde support | JSON (fine, fatter); protobuf (codegen friction for little gain here) |
| D5 | Media transport | **QUIC via `quinn`**: unreliable **datagrams** for A/V, reliable streams for control/input/clipboard/files; TLS 1.3 with both ends pinning the peer's Tornect keys (no CA; RFC 7250 raw public keys, §B.6) | One connection, E2E-encrypted, congestion-controlled, punchable; matches iroh/MoQ direction | str0m WebRTC (keep as documented plan-B; needed only for future browser client); raw UDP + custom crypto (reinventing TLS) |
| D6 | NAT traversal | ICE-style candidate gathering (host addrs + **UPnP/NAT-PMP/PCP** port mapping + server-reflexive via a **user-editable public STUN list**), exchange over Tor, simultaneous-open punch (STUN-style probes outside QUIC on the media socket, §B.2), then QUIC | Maximizes direct-connect rate with zero owned infra; STUN is stateless free public infrastructure and is *optional* | Own STUN/TURN (violates "no servers"); iroh as connectivity backend (excellent, but pulls in n0's relay/discovery plane by default — keep as an optional feature-flagged backend for de-risking) |
| D7 | Fallback path | **Stream over the Tor circuit itself** (TCP-like onion stream): capped preset ~1–6 Mbit/s, H.264, aggressive downscale, "relayed via Tor" badge | Guarantees Tornect *always* connects — the killer differentiator; also doubles as "paranoid mode" (peers never learn each other's IP) | TURN (needs servers); giving up (Moonlight's answer) |
| D8 | Video pipeline | Capture→encode zero-copy on GPU per §A.2; **the OS and vendor codec APIs directly behind `tornect-codec`'s trait** (r7, decision M1-56): Media Foundation + NVENC on Windows, **OpenH264 always**, VA-API designed behind the same trait but not shipped in v1, **no FFmpeg in v1**; one wire format, H.264 Constrained Baseline (§B.5); decode→render via **wgpu** (Vulkan/Metal/D3D12) with NV12/P010 shaders | Nothing codec-related ships (Media Foundation comes with Windows, the NVENC runtime with the driver); FFmpeg does not build on the dev VM and breaks ABI between majors (§A.2); Constrained Baseline keeps every existing viewer compatible; wgpu = one renderer for all OSes | GStreamer (capable, but heavy runtime dependency + plugin hell for end-users); FFmpeg in v1 (r6's choice: build, ABI, shipping and licence surface — r7); AMD AMF and Intel VPL directly (reached through Media Foundation on Windows; no test machine) |
| D9 | Audio | **Opus** 48 kHz, 10 ms frames (`Application::LowDelay`, in-band FEC off, previous-frame redundancy — §B.4), in QUIC datagrams; WASAPI loopback / ScreenCaptureKit audio / PipeWire capture | The only sane real-time audio codec; `libopus` 1.6.1 bundled by the **`opus` crate** (`=0.4.0` → `opusic-sys`, built with cmake, no pkg-config/bindgen), round-trip verified on the dev VM (docs/research/codecs.md §5) | `audiopus`/`audiopus_sys` (stale since 2021) |
| D10 | UI toolkit | **egui everywhere (v1, Linux and Windows; r7, decision M1-59):** egui 0.36 through `egui-winit` + `egui-wgpu` (wgpu 30) on **one manual `winit` 0.30 event loop** (`ApplicationHandler`), **no `eframe`**, for the shell, the trust surfaces and the stream window alike — the video as a full-rect wgpu pass, the HUD in egui on top; consent sheets, the indicator and dialogs hang off the same loop; Iced is not used in v1. Process model: the app process owns `tornect-session` (both roles) and every window on its single loop, so decoded frames never cross a process boundary; the host indicator runs **in the app process** (decision M1-50; a deviation from r6's separate indicator process): a crash ends the session with the indicator (fails closed), a hang leaves the indicator visible with a dead Stop, for which `tornect panic` is the path that does not depend on the UI thread (Part E); the panic hotkey and the control channel never run on the UI thread (M-FEAT-5); a UI-thread watchdog that ends any session when the UI misses heartbeats is recommended; a separate indicator process is not a release item | Pure Rust, and what exists: the window of decision M1-50 was built this way and the UI foundation (`3aa1072`, Part G) landed the design system on it. winit allows one event loop per process, `eframe` exposes no raw winit events, and `egui-winit` drops physical keys it cannot map (PrintScreen, NumLock, media keys…) while a remote-desktop client must forward every scancode — owning the loop avoids a rewrite (docs/research/ui.md §4). An internal comparison scored the options out of 100: egui everywhere 75.6, egui on the desktop with Compose on Android 75.6, Flutter + Rust 70.8, Slint 62.2, Tauri 2 53.0, Dioxus 47.6; about 40 of the 58 UI tests are bound to egui, and a switch would cost one to two more weeks, and every trust surface would need a new internal security review. Costs kept honestly: a custom-drawn look, basic IME. `docs/UI_PLAN.md`'s Iced shell sections are superseded (the UI plan itself is not edited; Part G) | Iced 0.14 shell (r6's choice, never built; superseded by r7); `eframe` (the reasons left); Tauri 2 (webview + IPC between UI and stream window); Qt/Slint (C++/licensing or smaller ecosystem) |
| D11 | Input model | Client captures via winit raw events (+ gamepad via `gilrs`); host injects via SendInput / CGEvent / RemoteDesktop-portal-libei (`reis`) | Per §A.2 — the sanctioned path on each OS | uinput on Linux (root, bypasses lockscreen isolation — rejected) |
| D12 | Serialization on the wire (media) | Hand-rolled fixed headers (bitfields) for datagram payloads; CBOR for control | Datagram headers are hot-path; the 12-byte header of §B.4 matters at 100k pps | — |
| D13 | Config/state | `~/.config/tornect` (XDG) / `%APPDATA%\Tornect` / `~/Library/Application Support/Tornect`; TOML config; keys in OS keychain where available (**`keyring-core` 1.0.0** + per-OS stores — Linux: `zbus-secret-service-keyring-store` (`rt-tokio-crypto-rust`) first, `linux-keyutils-keyring-store` (session keyring, lost at logout) as the fallback before the file keystore; `apple-native-keyring-store` (`keychain`); `windows-native-keyring-store`; never `keyring::Entry`, whose v1 shim force-installs the Secret Service store — docs/research/ui.md §5.9), file-based with 0600 otherwise (the M0 file keystore stays the fallback) | Boring and correct | — |

### A.4 Honest constraints & how we message them

1. **Signaling latency**: connecting takes ~1–4 s through Tor (circuit + consent).
   Fine — this is session setup, shown with progress states.
2. **First host start**: onion descriptor publication can take up to ~2 min once per
   install (key is persistent; subsequent starts are fast). UI must message this.
3. **Server-reflexive discovery**: with *zero* third parties, a double-NAT pair
   cannot learn their public addresses. Default config ships a public STUN list
   (user-editable, can be emptied); with STUN disabled we still try UPnP/NAT-PMP/PCP
   + LAN + Tor fallback. This trade-off is documented in-app ("Network" settings).
4. **Direct mode reveals IPs to each other** (that's what "direct" means). Paranoid
   mode = force Tor relay path, media quality capped. Explicit toggle, clear copy.
5. **CGNAT + symmetric NAT both sides**: punch success will fail for some pairs
   (industry direct-connect rates are roughly 80–90 %); those users live on the Tor
   fallback until we ship optional user-hosted relay ("bring your own relay") in v2.
6. **A Linux (GNOME) host must be unlocked.** When the screen locks, gnome-shell
   inhibits mutter remote access: every portal ScreenCast/RemoteDesktop session is
   terminated and `CreateSession` is refused ("Session creation inhibited") until
   someone unlocks locally — restore tokens do not help, so remote unlock through the
   portal path is impossible by design. Tornect treats the closed session as a
   recoverable *Locked* state (`HOST_NOT_READY{locked}` / `BYE{HOST_LOCKED}`, §B.8.8)
   and says so in the client copy (that "<host>" is offline, asleep or locked); Tornect cannot
   wake or unlock it; KDE/wlroots lock behaviour is unverified (`NEEDS-DEVICE`).
   (docs/research/wayland.md §7)

---

## Part B — System architecture

### B.1 Component overview

Single binary, two roles (any machine can be host, client, or both):

```
┌────────────────────────────── tornect (app) ──────────────────────────────┐
│  UI (egui everywhere, D10): onboarding · ID/QR · consent · indicator      │
├───────────────────────────────────────────────────────────────────────────┤
│ session (orchestrator)                                                    │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────────────────┐ │
│  │ signal      │  │ net          │  │ media                             │ │
│  │ arti onion  │  │ candidates   │  │ capture HAL   encode HAL          │ │
│  │ svc+client, │→ │ UPnP/PCP,    │→ │ WGC | SCKit | audio (opus)        │ │
│  │ CBOR proto, │  │ STUN, punch, │  │ PipeWire     decode HAL           │ │
│  │ pairing     │  │ quinn QUIC,  │  │ input inject render (wgpu)        │ │
│  │             │  │ Tor fallback │  │ proto: pace·FEC·jitter·ABR        │ │
│  └─────────────┘  └──────────────┘  └───────────────────────────────────┘ │
├───────────────────────────────────────────────────────────────────────────┤
│ core: TornectId, device keys, config, keystore, logging, metrics          │
└───────────────────────────────────────────────────────────────────────────┘
```

Cargo workspace:

```
tornect/
├── Cargo.toml                  # workspace
├── CLAUDE.md                   # Claude Code operating manual (companion file)
├── crates/
│   ├── tornect-core/           # ids, keys, config, errors, telemetry, sessions.log,
│   │                           #   encrypted unattended grant store + MutationGuard/ReAuth
│   │                           #   entry point + ReadinessSnapshot (§B.8.9, §B.8.6.2, §B.8.14)
│   │                           #   + the IPC message types/CBOR codec (unattended::ipc, no I/O; §B.8.7.4)
│   ├── tornect-signal/         # arti embedding, onion service, CBOR signaling, pairing,
│   │                           #   unattended PAKE auth + attempt limiter + the HELLO…ACCEPT host
│   │                           #   FSM behind BlockWindow/LocalAllow traits (§B.8.4–B.8.5, §B.8.14)
│   ├── tornect-net/            # candidate gathering, UPnP/NAT-PMP/PCP, STUN, hole punch,
│   │                           #   quinn endpoint w/ key-pinned TLS, tor-relay transport
│   ├── tornect-proto/          # media wire format, packetizer/depacketizer, FEC,
│   │                           #   jitter buffer, pacer, ABR controller, stats
│   ├── tornect-capture/        # trait VideoCaptureSource + wgc/ sckit/ pipewire/ backends
│   ├── tornect-codec/          # trait Encoder/Decoder + Media Foundation and NVENC backends
│   │                           #   (Windows, M-CODEC-2/3), VA-API designed, not shipped (Linux),
│   │                           #   + the always-compiled openh264, both directions (D8, r7: no FFmpeg)
│   ├── tornect-audio/          # capture (wasapi/sckit/pipewire), opus enc/dec, playback (cpal)
│   ├── tornect-input/          # client-side event mapping; host-side inject backends
│   ├── tornect-ui-kit/         # design tokens/themes/widgets/l10n (docs/UI_PLAN.md §4); created at `u1`, Part F.6
│   ├── tornect-platform/       # OS session services (§B.8.8): presence, lock state, keep-awake,
│   │                           #   autostart, OS re-auth, hotkeys, readiness probes, owner-only
│   │                           #   local IPC endpoint + peer check only (not a network socket;
│   │                           #   the message types are tornect-core's); FFI per module
│   └── tornect-session/        # host & client state machines wiring everything; unattended: the
│                               #   UI-backed BlockWindow/LocalAllow impls + Candidates onward (§B.8.14)
├── apps/
│   └── tornect/                # app: egui shell (pages, consent sheets, settings) + the stream
│                               #   window on one manual winit/wgpu loop, the indicator in the same process (D10, r7); host-role IPC
│                               #   dispatch loop (decodes with the core codec, dispatches to the
│                               #   MutationGuard, §B.8.7.4)
├── xtask/                      # cargo xtask: dist, pt-fetch, packaging, lint-all
├── fuzz/                       # cargo-fuzz targets (§D.5); excluded from the workspace
└── tests/
    ├── integration/            # loopback e2e, signaling-over-localhost-tor mocks,
    │                           #   unattended adversarial suite (§B.8.15)
    └── netem/                  # scripted latency/loss/jitter harness (linux netns)
```

### B.1.1 Product modes (r7; decisions M1-58, M1-65; milestone M-FEAT-6)

Tornect runs in one of two modes on Linux and Windows. Both keep state in the same per-user places (D13, B.8.9:
`%LOCALAPPDATA%` / `%APPDATA%\Tornect`, the XDG directories), so switching modes keeps pairings and grants, and one host
runs per home (`state/host.lock`, M1-46).

- **Standalone.** The released executable runs from any folder and installs nothing: no Start-menu entry, no
  administrator component. "Start Tornect when I sign in" stays available for an executable inside the user's profile
  (M1-53 rule (i)), which makes it a per-user installation, still without administrator level. **No portable state
  directory** beside the executable: Windows already refuses a home outside the profile (M1-53 (10)), removable media
  usually carry no ACLs, so the owner-only guarantees of D13/B.8.9 would not hold, and the identity key would travel on
  the stick. Attended sessions offer every level except administrator (§B.2.1); unattended grants are served while the
  app runs, without administrator level. **No administrator access from the standalone app** (the operator's ruling of
  2026-09-27, decision M1-65): elevating an executable in a user-writable folder lets any program of that user replace
  it, or put a DLL beside it, before the Windows prompt appears.
- **Installed** (planned, M-FEAT-6). Windows: `tornect install` — an access-increasing guard operation (re-auth, no
  remote session in the last 60 s, logged; §B.8.6.2) followed by UAC — will copy the executable into Program Files (the
  folder resolved from `FOLDERID_ProgramFiles`, never from the environment), check after the copy that the folder and
  the executable carry no write, delete or owner-change entry for a non-administrator principal, add a Start-menu entry
  and an Apps-and-features uninstall entry (written under HKLM by the installed, checked executable in a second UAC step; its command is the quoted absolute
  path of the installed executable with a fixed argument), and offer "Start Tornect when I sign in" (asked as "Start Tornect when I sign in? [y/N]", where Enter is no; the at-logon task of
  M1-53). `tornect uninstall` reverses all of it the same way; on Windows it is refused, pointing to `tornect unattended set-level <device> none`, while a grant holds the administrator level (naming those devices) or while the administrator helper task is registered, and it is refused while Tornect cannot read its grants. Both are refused while Tornect runs in this account ("Close Tornect before installing or removing it."). Run from the installed copy (as Apps and features runs it), `tornect uninstall` removes the uninstall entry, the Start-menu entry, the start at sign-in and any other file in the folder at once; that copy then, in a second UAC step, marks itself and its folder for removal at the next restart of Windows and ends, so no elevated program keeps running after Tornect exits, and the command says so; until that restart the folder stays, and nothing in this account starts it. `tornect install` is refused while Tornect is installed ("Tornect is already installed in <folder>. Run tornect uninstall first."): until M8 packaging (MSI, winget) brings an in-place upgrade, an upgrade is `tornect uninstall` then `tornect install`, and as uninstall is refused while a device holds administrator access, those grants are lowered first. `tornect install` is also refused, and says to restart first, while Windows still holds the removal of Tornect's folder for the next restart (or while Tornect cannot read whether it does); after that restart it goes on. The folder, the uninstall entry's key, its DisplayName and the Start-menu entry are named "Tornect", with DisplayVersion the build's version and no Publisher; no icon ships (Windows shows its default program icon). MSI/winget stay M8 packaging. Linux: a per-user install
  without root — the executable in `~/.local/bin` (it passes M1-53's ownership rule), a `.desktop` entry and "Start
  Tornect when I sign in" (the entry `~/.local/share/applications/tornect.desktop` holds `Type`, `Name` and `Exec` only). On a Linux with no `systemctl` at `/usr/bin` or `/bin`, `tornect uninstall` cannot remove these files, as it cannot tell whether an older `tornect-host.service` is still registered.

**What starts at sign-in will be the app, not the headless host** (decision M1-58; a deviation from M1-53's F2-1 rule,
for the app only). The autostart will launch `tornect --background`: the window host with its window minimised (on
GNOME Wayland a normal window where the compositor ignores the minimise request, NEEDS-DEVICE(gnome)), the consent
sheet, the sharing banner and the always-on-top indicator. It serves attended requests (the sheet raises attention and
mirrors an OS notification, never a toast alone, B.8.7.3) and unattended grants, under these gates (MUST): unattended
sessions only once M-FEAT-5's block window is in and a readiness row "indicator shown" passes before the first unattended
start after each sign-in (on Wayland, with no topmost window, the compositor's screen-sharing indicator of §B.8.8 is the
fallback); the headless `tornect host` without a terminal stays pings-only (M1-53, the operator's ruling "Pings only
when headless", M1-54); a second launch brings the running window forward (`IpcOp::Show`, §B.8.7.4) instead of failing
on `host.lock`, and that only raises the window — it never answers, dismisses or re-orders a sheet, and it re-arms any
sheet (§B.2.1). A `--background` start that finds Tornect running ends at once without raising the window. A window host whose unattended store did not open refuses `Show`, so a second launch then opens a second window, whose host stops on `host.lock`. In background mode, pairing from new devices stays on (the operator's ruling of 2026-10-03, decision
M1-68): a new device can start pairing while the window is minimised, and the request raises the window as any request
does. On Linux the app's autostart will be an XDG
autostart entry (`~/.config/autostart/`), which inherits the graphical session's environment — a deviation from M1-53's
"no XDG-autostart fallback", which concerned the headless host's unit; whether such an entry runs inside the logind
session (the polkit revocation of §B.2.1 and the portal's restore token depend on it) is NEEDS-DEVICE(gnome, kde),
checked at the build VM console. The setting's copy says that starting at sign-in means a Tor connection at every
sign-in, visible to the local network and the provider as Tor use. The window's "Start Tornect when I sign in" shows, before it acts: "Starting at sign-in means a Tor connection at every sign-in: your local network and your internet provider can see that this computer uses Tor. While Tornect runs, devices you gave unattended access can connect, new devices can ask to pair, and anyone with this computer's Tornect ID can see that it is online." It then runs the same guard operation as `tornect service install|uninstall` with no host running, in the window's own process (re-authentication, no remote session for 60 s, `AutostartChanged{by: ui}`, M-UI-5); the control channel still refuses an install sent to a running host.

**"Starts with the computer", stated plainly (v1).** Windows: Tornect starts when you sign in; with Windows automatic
sign-in — the owner's choice, never configured by Tornect; a pre-boot disk PIN still needs a person at every boot — that
is at boot. Before sign-in, on the lock screen and on Windows permission prompts the computer cannot be seen or
controlled; the client says "Couldn't reach "<host>": it may be off or offline, or Tor may be slow. The password was not tried." when nothing answers there (before sign-in Tornect is not running), and that "<host>" is offline, asleep or locked when Tornect there refuses the session as not ready. Linux: Tornect starts when you sign in to
the desktop; before sign-in nothing can be shared (no user session; the greeter runs its own), and GNOME's lock screen
closes remote access by design (§A.4 item 6). Reaching the Windows sign-in screen, lock screen and permission prompts
needs a SYSTEM service: roadmap M-SVC-W, after the initial release (decision M1-61, Part C). Linux before sign-in is not
planned: a pings-only presence at boot through `loginctl enable-linger` would say only "online, nobody signed in", needs
the identity key readable without the keyring, and keeps user processes alive after logout; sign-in-screen access is a
root/greeter matter (D11 rejects a root host).

Platform truth: the at-logon task and the Linux user unit are built (M1-53; the unit's round trip verified on the build
VM); UAC for `tornect install`, the minimised start, `ask_attention` and the notification for a request in background mode (`Shell_NotifyIconW`) on Windows, XDG autostart and minimise on
GNOME/KDE: NEEDS-DEVICE.

### B.2 Connection lifecycle (the user's flow, made precise)

Roles: **Host** = machine being controlled/streamed. **Client** = machine connecting.

```
Host                          Tor network                       Client
────                          ───────────                       ──────
[first run] gen ed25519 id
publish onion svc  ────────►  descriptor stored
show "Tornect ID" (56-char onion + QR)
                                              ◄──── user enters/scans Tornect ID
                              ◄─── rendezvous ─────  open onion stream
◄── HELLO{v_max, client_nonce, client_device_pk, name, feats}         (signed by device key)
HELLO_ACK{v chosen, host_nonce} ──►                                   (signed by onion key, §B.8.4)
   ┌─ if unpaired device: PAIR_REQUEST
   │  ┌──────────────────────────────┐
   │  │  CONSENT POPUP on host:      │   both screens show same 6-digit SAS
   │  │  "Laptop-of-Ana wants to     │   (derived from transcript hash) —
   │  │   pair. Code: 481 923"       │   user verifies + clicks Allow
   │  └──────────────────────────────┘
   │  PAIR_ACCEPT{host_device_pk} ──►      client pins host key; host pins client key
   └─ else: device already trusted
◄── SESSION_REQUEST{caps: codecs, max_res, hdr, monitors_wanted, unattended?}  (signed)
   ┌──────────────────────────────────────┐
   │ SESSION POPUP on host (§B.2.1):      │  (never skippable — no "always allow";
   │ Deny / View only / Allow / Allow as  │   link "Set up unattended access…" opens
   │ administrator… (Windows, installed)  │   the local §B.8 enable flow)
   └──────────────────────────────────────┘
   └─ unattended branch (§B.8.4), no popup: AUTH_CHALLENGE{ke2} ──►  ◄── AUTH_RESPONSE{ke3}
      pinned device key + per-grant password (OPAQUE) replace the click; block window
      with [Block] on the host; indicator + log unchanged
SESSION_ACCEPT{caps chosen, session_token | token_confirm, quic_spki, session_type, mode, elevation? (r7, §B.2.1)}
◄── CANDIDATES{[]}  ──── both sides gather in parallel ────  CANDIDATES{[]} ──►
        host: local addrs, UPnP/NAT-PMP mapped, STUN reflexive (if enabled)
punch: STUN-style probes *outside QUIC*, both sides at once on the shared media socket
       (ICE pacing: one probe per Ta = 50 ms, RTO ≥ 500 ms doubling; the checklist is pruned to ≈ 20 pairs by the
       RFC 8445 §6.1.2.3 pair-priority ordering — ICE's 100 default is far above what 4 s at Ta = 50 ms can sweep
       with ~3 retransmits, nat.md §5.3 — and ≤ 8 pairs are in flight at once; trickle ok);
       the first pair validated in both directions is nominated, then exactly one QUIC dial:
       the side with the numerically lower device public key is the QUIC client
       (`connect_with`, per-peer pin) and the other only accepts — no concurrent Initials,
       no duplicate connections (docs/research/nat.md §5, quic.md §5, §12.14; one-socket demux
       needs `EndpointConfig::grease_quic_bit(false)` on both ends, RFC 9443)
═══════ direct QUIC established (TLS 1.3 raw public keys, both SPKIs pinned) ════════
        first frame on ctrl, both directions: BIND{mac} over the TLS exporter keyed by session_token
        (§B.8.4.3); nothing else is accepted, and capture never starts, before a valid BIND
        └─ if no pair succeeds within 4 s: TOR_FALLBACK{} → open second onion
           stream and carry the same QUIC connection (and thus the BIND check)
           over a length-framed tunnel (transport choice pending §B.8.17 item 7, decided at M2)
media flows (datagrams) + control/input (streams); Tor circuit kept as low-rate
heartbeat + renegotiation channel; teardown on BYE or circuit loss
```

Key properties: for attended sessions the consent popup **always** runs on the host
before any capture starts; the only popup-less path is an unattended session (§B.8:
pinned device key *and* per-grant password, never a toggle or "always allow"), which
still gets a block window, the indicator and the log; capture begins only after
SESSION_ACCEPT (for an unattended session it is sent only once the block window has
elapsed without Block, §B.8.4.5); a persistent
on-screen session indicator + tray state shows "screen is being shared" with one-click kill.

### B.2.1 Session levels (r7; decisions M1-64, M1-65, M1-57; milestones M-FEAT-2, M-UI-3, M-FEAT-3)

Built at `3aa1072`: the attended sheet answers Deny · View only · Allow control (`SessionDecision { AllowOnce,
AllowOnceViewOnly, Deny }`), Deny first, every accept pointer-only and armed after the sheet has been still for 1 s
(M1-50). The levels below are planned.

The attended sheet will read "**<name> wants to connect to this computer**", where <name> is the saved name only when
the requester's 32-byte device key equals a pinned key, and otherwise its device words, labelled as such (§B.6.1).
Answers, in this order — Deny first in screen, Tab and screen-reader order; every accept pointer-only, armed only after
the sheet has been still for 1 s and re-armed on return (M1-50, unchanged):

| Answer | Level (mode, elevation) | Line under it |
|---|---|---|
| **Deny** | — | — |
| **View only** | (view, none) | "They see this screen. They cannot type or click." |
| **Allow** | (control, none) | Windows: "They can type and click as you. Programs running as administrator ignore their input." Linux: the Linux sentence of the table below |
| **Allow as administrator…** (Windows, where the table below offers it) | (control, admin) | "Windows asks you to confirm next. They can change anything on this computer, including Tornect's settings and its log, and the changes stay after the session." |

Four answers on Windows (fewer on the rows below that say so), three on Linux, View only kept (the operator's ruling of
2026-09-27, decision M1-64).
`SessionDecision` gains `AllowOnceAdmin`; `SESSION_ACCEPT` gains the optional signed key `elevation` and, for unattended
sessions, `grant_reach` (§B.8.4.1, decision M1-67), shown
in the client HUD as "Control · administrator"; view-only never carries elevation. **A level the host cannot deliver is
not shown** — no greyed button; one sentence under the buttons says why:

| Host state | Buttons | Sentence |
|---|---|---|
| Windows, installed in Program Files, UAC on (standard or administrator account) | Deny · View only · Allow · Allow as administrator… | — |
| Windows, standalone (run from any other folder, §B.1.1; decision M1-65) | Deny · View only · Allow; on an administrator account where control is administrator access in effect (UAC off, the built-in Administrator without Admin Approval Mode, or elevation without prompting): Deny · View only | "Administrator access needs Tornect installed on this computer."; UAC off or the built-in Administrator: "Windows runs every program on this account as administrator, so control always includes administrator access. Administrator access needs Tornect installed on this computer."; elevation without prompting: "Programs on this account can become administrator without a prompt, so control here would be administrator access, and administrator access needs Tornect installed on this computer." |
| Windows, installed, UAC off (`EnableLUA` 0) or the built-in Administrator without Admin Approval Mode (`FilterAdministratorToken` 0) | Deny · View only · **Allow as administrator** (no "…"; a Tornect confirmation follows) | "Windows runs every program on this account as administrator, so control always includes administrator access." |
| Windows, standard account where policy denies elevation (`ConsentPromptBehaviorUser` 0) | Deny · View only · Allow | "This computer's policy does not let administrator access be given here." |
| Windows, installed, administrator account set to elevate without prompting (`ConsentPromptBehaviorAdmin` 0): any program there can become administrator without a prompt, so control is administrator access in effect (the operator's ruling of 2026-09-29) | Deny · View only · **Allow as administrator** (no "…"; a Tornect confirmation follows) — no plain Allow; without the administrator helper, Deny · View only | the administrator line without its first sentence; without the helper: "Administrator access is not available in this version of Tornect." |
| Windows, the host itself started elevated while UAC is on | none: the host refuses to open the onion service | "Start Tornect normally; administrator access is given per session." |
| Linux (every desktop) | Deny · View only · Allow | "On Linux, Tornect never runs as administrator. They can do what you can do without a password; when the system asks for a password, they see that window and can type into it." |

When readiness reads `PromptOnSecureDesktop` 0, the sheet adds at every level: "Windows permission prompts appear on the
shared screen here." (the remote sees them; a credential prompt shows the account name). If the Windows test shows that
a medium-integrity `SendInput` can answer such a prompt (NEEDS-DEVICE(windows)), those machines join the UAC-off row.

After **Allow as administrator…** the host asks Windows to start the administrator helper (§B.8.7.5); Windows shows its
own prompt, on the secure desktop by default: consent for an administrator account, an administrator's user name and
password for a standard account ("Prompt for credentials" is the default for standard users). If that prompt is
cancelled or fails, the sheet stays open with the other answers and the line "Administrator access was not given"; the
popup timeout keeps running (`POPUP_TIMEOUT`, B.8.4.6). The session never starts silently at a lower level after an
administrator answer: the person at the computer answers again. Arming (MUST): where no Windows prompt follows, "Allow
as administrator" opens a Tornect confirmation (Deny first, armed after 1 s, the administrator line); the administrator
answer is never adjacent to Allow; the return from a Windows prompt, a window raise (`IpcOp::Show`) and a restore from
minimised re-arm the sheet. The level is fixed at `SESSION_ACCEPT`: a helper that arrives after the 5 s budget is
terminated, never attached, so no session rises to administrator midway. A new device still sees two sheets in sequence
(pairing, then this one): the pairing answer pins a key and never grants a session (B.8.4.5 strict alternation); sheets
are never shown during a live remote session (B.8.6.2). Recommended: for a device paired moments before, the
administrator answer carries the wizard's scam line (T10), and the help text says that Tornect shows a Windows prompt
only right after "Allow as administrator…" is clicked.

**What "administrator access" is, per platform.**
- **Windows: a per-session elevation**, answered by the person at the computer at accept time. It starts one elevated
  input helper for that session only, while the network-facing host (Tor, CBOR, the FSM, capture) stays at the user's
  normal (medium) integrity. It gives exactly one thing: the remote's input reaches windows of elevated programs. It
  never reaches the secure desktop (UAC prompts, the Ctrl+Alt+Del screen, lock and sign-in screens): only a SYSTEM
  service with a per-session process would (M-SVC-W, roadmap). Unattended sessions cannot use a prompt; their elevation
  is authorised at setup (§B.8.7.1).
- **Windows, "Allow" is enforced by Windows**, not by Tornect: SendInput "is subject to UIPI. Applications are permitted
  to inject input only into applications that are at an equal or lesser integrity level", and "neither GetLastError nor
  the return value will indicate the failure was caused by UIPI blocking" (Microsoft's SendInput documentation, read
  2026-09-27). On a standard account that is a real boundary (an administrator's password in a prompt the remote cannot
  reach); on an administrator account UAC is not a security boundary (UNVERIFIED citation; the release notes already say
  so), so "Allow" stops casual administrator use, not a determined controller. Because UIPI fails silently, the client
  will say "Some windows here run as administrator; your clicks cannot reach them in this session." when the host's first PONG of a Control session says so (bit 0x02 of its `notice`, §B.8.4.1: a Windows host, the session not at the administrator level; M-UI-4). On a host where an
  admin grant exists, T9 (§B.8.2) applies.
- **Linux: no administrator level exists to give.** The host runs as the signed-in user and never as root (D11). "Without
  administrator access" cannot be enforced beyond the system's own password dialogs: many administrator-class actions
  ask for no password in an active local session (polkit actions with `allow_active` `yes`, a `sudo` timestamp cached in
  an open terminal), portal-injected input is the session's own input, and no public interface found tells a session
  process that an authentication dialog is on screen (UNVERIFIED; NEEDS-DEVICE(gnome, kde): confirm that injected keys
  reach the authentication dialog). What Tornect will do (M-FEAT-2): revoke the session's polkit remembered approvals when every
  Control session starts and whenever the authority reports a change during it — "pkcheck --revoke-temp will revoke all
  temporary authorizations for the current session" (pkcheck(1), read on the build VM); the D-Bus method it wraps is
  UNVERIFIED by name, the "authority changed" semantics are UNVERIFIED, and "current session" depends on the process
  context the app runs in (NEEDS-DEVICE(gnome, kde) under XDG autostart, §B.1.1). It only makes the local person type a
  password again: the Linux help discloses it and never describes it as enforcement. Not reachable: a `sudo` credential
  cached in an open terminal (stated in the Linux help).

Platform truth: the per-session UAC helper path, the standard-account credential path (the helper then runs as the
administrator whose password was typed, on the user's desktop), WGC/GDI capture of elevated windows at medium integrity
and the `PromptOnSecureDesktop` 0 case: NEEDS-DEVICE(windows).

### B.3 Signaling protocol (`tornect-signal`)

Envelope (CBOR, over onion stream, u32-BE length prefix, max 64 KiB/frame):

```
Envelope { v: u8, msg_id: u64, kind: Kind, body: bytes, sig: Option<bytes> }
  wire form = CBOR array [v, msg_id, kind, body, sig]   (positional; sig = null when absent)
Kind = CBOR unsigned integer:
       HELLO=1 | HELLO_ACK=2 | PAIR_REQUEST=3 | PAIR_ACCEPT=4 | PAIR_REJECT=5
     | SESSION_REQUEST=6 | SESSION_ACCEPT=7 | SESSION_REJECT=8
     | AUTH_CHALLENGE=9 | AUTH_RESPONSE=10 | ADMIN_RESULT=11
     | CANDIDATES=12 | CANDIDATES_DONE=13 | TOR_FALLBACK=14
     | PING=15 | PONG=16 | BYE=17 | ERROR=18
```

Rules: consecutive per-direction `msg_id` (`prev+1`, §B.8.4.5); unknown `Kind` ⇒ ERROR + close;
protocol version negotiated in HELLO (host replies with the chosen `v` and a fresh nonce
in HELLO_ACK); every attended session gets a fresh random 32-byte `session_token`
binding the QUIC connection to this signaling exchange (proven by the `BIND` frame each
side sends first on `ctrl`, keyed by the QUIC TLS exporter over `session_token`,
§B.8.4.3); an unattended session derives it from the PAKE `session_key` instead
(§B.8.4.3). Signing: client HELLO and SESSION_REQUEST, host HELLO_ACK, SESSION_ACCEPT
and ADMIN_RESULT carry ed25519 signatures over the transcript hash (envelope-level,
§B.8.4.3) so device keys are bound to the channel (defense-in-depth on top of Tor's
own crypto; and it is what makes the SAS code sound: `SAS = u32::from_be_bytes(HKDF-SHA256(ikm =
th_after(HELLO_ACK) || sas_nonce, salt = "tornect/v1/sas", info = "sas-v1")[0..4]) % 1_000_000`, rendered
as two zero-padded three-digit groups — `481 923` — and computable by both sides as soon as
`PAIR_REQUEST` is sent / received, because `th_after(HELLO_ACK)` already commits to the dialed onion pk,
the client device pk, both nonces and both signatures; decision M1-8, revised r7. **The SAS input is
commit-then-reveal and carries no attacker-chosen bytes.** `HELLO` (signed) publishes
`sas_commit = SHA-256("tornect/v1/sas-commit\0" || sas_nonce)`; `PAIR_REQUEST` reveals `sas_nonce`;
the host recomputes the commitment and closes with `E_BAD_LEN` on a mismatch, before any pairing popup.
Both properties are load-bearing and neither is sufficient alone. Deriving from `th_after(PAIR_REQUEST)`
instead — the r6 construction — is **broken**: a proxying MITM grinds `host_nonce` toward the client and
the unsigned `PAIR_REQUEST` (whose `client_auth_pk` the host discards, and whose unknown CBOR keys the
decoder ignores) toward the host, so ~2^10 candidates per side meet on the 20-bit code by the birthday
bound and both screens show the same digits in wall-clock milliseconds — well inside the 20 s
`HELLO_ACK` timeout. Committing the nonce removes the client-side grind, because the MITM must fix its
`host_nonce` before it learns `sas_nonce`; keeping the SAS input free of `PAIR_REQUEST` bytes removes
the host-side grind. Signing `PAIR_REQUEST` would **not** be sufficient on its own — the MITM holds its
own device key and re-signs each candidate). `AUTH_CHALLENGE` and
`AUTH_RESPONSE` exist only between `SESSION_REQUEST{unattended}` and
`SESSION_ACCEPT`/`SESSION_REJECT` — as does `ADMIN_RESULT`, which terminates an
admin-intent exchange in place of `SESSION_ACCEPT`/`SESSION_REJECT` — inside the strictly
alternating HELLO…ACCEPT window of §B.8.4.5; the unattended reject codes are listed in
§B.8.4.6, the `BYE` reasons and `ERROR` codes in §B.8.4.1. `HELLO` is sent with envelope
`v = 1`, the lowest version the client supports; the host answers with the chosen `v` and
both sides use it from `HELLO_ACK` on.

Host side listens as an onion service with **PoW DoS protection enabled** and a
small accept queue; unauthenticated peers get exactly one in-flight PAIR_REQUEST and
a token-bucket rate limit; repeated rejects ⇒ temp-ban list persisted per client pk.
Optional **restricted mode**: onion service client-authorization so only devices
possessing a pre-shared x25519 key can even *discover* the service (power users).

### B.4 Media wire protocol (`tornect-proto`, over quinn)

Streams (reliable, per-purpose): `ctrl` (CBOR: caps renegotiation, bitrate hints,
IDR requests, monitor switch, cursor shape), `input` (fixed 16-byte packed events —
never in datagrams: input loss is unacceptable), `clip` (clipboard), `file`
(transfer, v2), `stats` (1 Hz telemetry both ways).

Datagrams (unreliable) — video & audio:

```
VideoDatagram {                 // 12-byte header, hand-packed (D12)
  u8  flags        // keyframe, fec, last_fragment, codec_bits
  u8  stream_id    // stream + codec id (rounds the header to 12 B)
  u16 frame_id     // wrapping
  u16 frag_idx / frag_count
  u32 rtp_ts       // 90 kHz
  ... payload      // with RaptorQ: 4-byte PayloadId, then one symbol
}
whole datagram ≤ the live `Connection::max_datagram_size()` — 1162 B at the 1200 B
initial MTU (1414 B once DPLPMTUD reaches the 1452 B upper bound; back to 1162 after a
black hole), re-read on every frame packetize, never hard-coded. RaptorQ symbol =
round_down(max_datagram_size − 12 − 4, 8) = 1144 B @1200 / 1392 B @1452; the per-frame
symbol size travels in the frame's first datagram (or is derived from frame_len/frag_count
— layout fixed at M3). (docs/research/media-proto.md §2.2–§2.3, §14; quic.md §7)
```

- **Fragmentation**: encoder output split to ≤ datagram size; reassembly window of
  3 frames; any missing fragment past window ⇒ frame drop + decoder conceal/skip.
- **FEC**: XOR parity per frame block at loss<2 %, switch to RaptorQ (`raptorq`
  crate) for keyframes / >2 % loss; overhead adaptive 5–30 %.
- **Recovery ladder**: conceal → NACK-less (we don't retransmit video datagrams) →
  request **intra-refresh acceleration** on `ctrl` → full IDR only as last resort.
- **Jitter buffer**: client-side target = max(1 frame, p95 inter-arrival jitter),
  clamped 0–3 frames; "prefer latency" and "prefer smoothness" user modes.
- **Pacer**: host paces packets across the frame interval (no 4 KB bursts).
- **ABR**: delay-gradient controller (GCC-style): receiver reports arrival deltas +
  loss on `stats`; controller targets 85 % of estimated capacity, min 500 kbit/s,
  max user cap; drives encoder rate control per-frame; resolution/fps ladder shifts
  when bitrate floor is hit (e.g. 4K→1440p→1080p→720p before dropping below 30 fps).
- **Audio**: Opus 48 kHz, `Application::LowDelay` (CELT-only, 2.5 ms lookahead), 10 ms
  frames (480 samples ⇒ rtp_ts += 480), 128 kbit/s default (64–256 user range),
  complexity 8; **in-band FEC off** (`set_inband_fec(false)`, `set_packet_loss_perc(0)`:
  Opus LBRR exists only in SILK/hybrid modes and never fires in `RESTRICTED_LOWDELAY`/CELT,
  so it would buy nothing for desktop audio); loss protection = the previous Opus frame
  piggy-backed in every datagram (`{hdr 12 B, ts48k u32, seq u16, cur_frame, prev_frame}`:
  two consecutive losses to lose a frame, +1× audio bitrate, zero added latency) + PLC on
  holes, RaptorQ over 4 frames only at loss > 5 %; independent tiny jitter buffer (2 frames);
  A/V sync via shared rtp_ts and a small (<60 ms) lip-sync window — video never blocks
  audio (docs/research/media-proto.md §5.2, §5.6, §7.3; SUMMARY.md §2.9, which resolves codecs.md §5.3 —
  it recommends keeping in-band FEC on — against media-proto.md §5.2/§5.6).
- Everything already E2E-encrypted by QUIC TLS; no extra SRTP layer.

### B.5 Media pipeline (`tornect-capture` / `tornect-codec` / render)

Host per-frame path (targets in §B.7):

```
[Compositor/OS] → capture backend → GPU texture (DMABUF | D3D11Texture2D | IOSurface)
   → (same-GPU map, no download) → encoder (Windows: NVENC / Media Foundation MFT; OpenH264 everywhere; r7)
   → bitstream → packetizer → FEC → pacer → quinn datagrams
```

Capture backends (trait `VideoCaptureSource`: `next_frame() -> Frame{texture|cpu,
ts, dirty_rects?, cursor}`):

- `wgc` (Windows): `Windows.Graphics.Capture` free-threaded frame pool, per-monitor
  and per-window items, DirtyRegions where available, HDR (`R16G16B16A16Float`)
  pass-through to P010 for HEVC-Main10; cursor composited by API (config toggle).
- `sckit` (macOS): `SCStream` display filter, IOSurface frames, `SCContentFilter`
  per-display; queue depth 2; capture-includes-cursor toggle; audio via
  `SCStreamConfiguration.capturesAudio`.
- `pw` (Linux/Wayland): **one `ashpd` RemoteDesktop portal session** for capture and
  input (`RemoteDesktop::create_session` → `select_devices` → `Screencast::select_sources`
  on the *same* session → `RemoteDesktop::start`; then `open_pipe_wire_remote` +
  `connect_to_eis`; portal RemoteDesktop v2 / GNOME ≥ 45). `persist_mode=ExplicitlyRevoked`
  and the restore token go **only on `SelectDevicesOptions`** — the portal spec forbids the
  ScreenCast `SelectSources` persistence options on a RemoteDesktop session; the single-use
  token returned by `Start` is stored per monitor selection and replaced on every use
  (docs/research/wayland.md §2.4–§2.5) → PipeWire stream negotiated for
  DMA-BUF with modifier list from the encoder device; SHM fallback; cursor mode
  "metadata" preferred (send position separately; render client-side) with
  "embedded" fallback. The lock screen closes the session (§A.4 item 6).
- `x11` backend explicitly out of v1 scope (document; Wayland-first per product).

**Encoders and decoders (v1; r7, decision M1-56 — replaces r6's FFmpeg route; milestones M-CODEC-1…3).** Windows:
Media Foundation hardware encoder MFTs (vendor-neutral: NVIDIA, AMD and Intel through their drivers; to be tested on
NVIDIA only) and **NVENC directly** (NVIDIA: `nvEncodeAPI64.dll` from the driver, loaded from System32 by absolute path,
never from the application folder or a search path; the NVENC function table's struct versions checked against the
driver's maximum supported version before use, else OpenH264; the header's licence is UNVERIFIED — the notice inside
the header decides and is recorded in the third-party notices before it is vendored; nothing NVIDIA ships in the zips);
decode through the Media Foundation H.264 decoder with D3D11/DXVA. Linux: OpenH264 both ways; VA-API (Intel iHD, AMD
radeonsi) and NVENC over CUDA are designed behind the same trait and built in CI, **not shipped enabled** until a test
machine exists (roadmap M-CODEC-6; the operator's ruling "Software on Linux, hardware on Windows"). Everywhere: OpenH264
always compiled — the fallback and the reference decoder for conformance. **One wire format:** every hardware encoder is
configured for H.264 **Constrained Baseline**, Annex-B, SPS/PPS before every IDR, no B-frames, infinite GOP with an IDR
only on request or join (intra refresh where offered), CBR at the session bitrate — wire codec 1, which every existing
viewer decodes; the host may fall back to OpenH264 mid-session with an IDR and the viewer never notices. No wire change;
High profile, HEVC and AV1 wait for a decoder-capability negotiation (roadmap M-CODEC-5). Selection: probe in order
[NVENC, MF hardware, OpenH264] on Windows, [OpenH264] on Linux; any failure falls back to OpenH264 with an IDR and is
logged; `tornect doctor` prints one line per direction naming the GPU vendor and the encoder's friendly name, never
serials or UUIDs. Encoder FFI stays in the host process (its input is the host's own screen), in per-backend modules
that confine `unsafe` with `// SAFETY:` notes. Hardware codecs are NEEDS-DEVICE(windows-nvidia); AMD and Intel on
Windows are designed through Media Foundation and untested (NEEDS-DEVICE(windows-amd), NEEDS-DEVICE(windows-intel)).

**The parser gate (MUST; M-CODEC-1).** Every client enforces it on receive — a hostile host chooses what it sends: a
pure-Rust NAL/SPS/PPS parser (`forbid(unsafe_code)`, fuzzed) checks every access unit before any hardware decoder sees
it. It accepts NAL types 1, 5, 7 and 8 (9 if needed) and drops everything else before the decoder, SEI included;
requires `profile_idc` 66 with `constraint_set1_flag` 1, one slice group, no redundant pictures,
`frame_mbs_only_flag` 1, `level_idc` ≤ a fixed cap, an SPS picture size equal to the size the session announced and
never above a fixed maximum, `max_num_ref_frames` ≤ a small cap, SPS/PPS ids in range and sane slice headers
(`first_mb_in_slice` inside the picture, I and P slices only); and caps the bytes per access unit. A rejection or a
decoder error requests an IDR at most N times, then ends the session — never a crash, never a retry loop. The fuzz
corpus and the Windows hostile-corpus run exercise it. The gate applies to every later decoder too (MediaCodec,
M-CODEC-4). An out-of-process decoder with a restricted token is on the roadmap (recommended).

Software path: **`openh264`** (`=0.9.8`, `source` feature — Cisco's source compiled by `cc`, C++
fallback when `nasm` is absent) is the always-compiled H.264 path, **both directions, all
OSes**, and the only real-time video codec this dev VM can build and run (rav1e builds but is not
real-time, codecs.md §4.2; FFmpeg does not build here at all, codecs.md §0; 4:2:0 only; measured here 23.4 ms/frame
encode, 5.4 ms decode at 1080p without asm — CI installs `nasm` for ~3×; CI additionally
exercises FFmpeg's software paths — libx264, the native h264/hevc decoders, `libdav1d` — through
`libavcodec-dev`, but no hardware backend: codecs.md §2.1–§2.2, ci.md §3; an r6 job — no FFmpeg in v1 since r7). libx264 is not used in v1 (it came only through FFmpeg; r7). **No `rav1e`/`svt-av1` "potato mode" and no `dav1d` crate in v1**:
rav1e measured 0.65 s/frame at 1080p on this VM; AV1 waits for the decoder-capability negotiation
(roadmap M-CODEC-5, r7). Patent posture (source build vs Cisco's blob via
`libloading`) is an M8 legal decision. (docs/research/codecs.md §0, §3, §4.2–§4.3, §11.1;
SUMMARY.md §1.5)

Client render: `winit` window → the parser gate → decode (r7 — Windows: the Media Foundation H.264 decoder with
D3D11/DXVA; everywhere: `openh264` → map to wgpu texture when same-API, else NV12 CPU upload path first,
zero-copy interop as M7 optimization) → wgpu YUV→RGB(A) shader (planned, M-CODEC-1; at `3aa1072` the viewer
converts YUV→RGB on the CPU) → present with
mailbox/immediate mode; frame pacing: present-on-arrival with optional vsync-aligned
"smooth" mode.

Input path: winit events (+`gilrs` gamepads, raw mouse deltas with pointer-lock for
gaming mode) → normalized events → `input` stream → host inject backend:
`SendInput`(Win, absolute+relative modes, XInput emulation via ViGEm **optional**
later) · `CGEventPost`(macOS; requires Accessibility grant, guided in onboarding) ·
`reis`/RemoteDesktop portal (Wayland; keyboard keysyms + pointer + scroll; clipboard
via portal too). Keyboard strategy: send **both** scancode and keysym; host prefers
scancode for games, keysym for typing (per-app heuristic toggle in HUD).

### B.6 Security & privacy model

- **Host identity = onion v3 key** (ed25519). Compromise of the host key = identity
  compromise; stored in OS keychain when available. "Rotate ID" button regenerates
  (invalidates all pairings and unattended grants, by design).
- **Client device identity** = per-device ed25519, generated at install.
- **Pairing** = mutual key pinning gated by human consent + 6-digit SAS derived from
  the signed transcript (blocks a MITM who somehow proxied the onion rendezvous —
  belt-and-suspenders; Tor already authenticates the service side).
- **Session transport**: QUIC TLS 1.3 with **raw public keys (RFC 7250) — no X.509 at
  all**: each side presents its Ed25519 SubjectPublicKeyInfo (44-byte DER) as its
  "certificate" (`AlwaysResolves{Server,Client}RawPublicKeys`), and the custom mutual
  verifiers (`requires_raw_public_keys()`, Ed25519 only) constant-time-compare the presented
  SPKI with the pinned device keys; `SESSION_ACCEPT.quic_spki` carries the host's SPKI
  regardless of which side becomes the QUIC client (§B.2 tie-break) and must equal the
  pairing pin — it never replaces it; the self-signed X.509 path (`rcgen`) stays documented,
  not compiled (docs/research/quic.md §3.3, verified over quinn) — plus the `BIND` exchange
  (§B.8.4.3: an HMAC over the TLS exporter keyed by `session_token`, sent first on `ctrl` by
  both sides, labelled by Tornect role — "client" = the device that dialed the onion service, "server" =
  the host — never by QUIC handshake role, which the §B.2 tie-break may swap; nothing else is accepted
  before it verifies). No CAs, no certificate parser in
  the security boundary, no clock-dependent validity.
- **Consent & abuse resistance** (non-negotiable product rules): capture starts only
  after explicit accept — or, for an unattended session, after the two-factor
  authentication and block window of §B.8; persistent visible indicator + tray while
  sharing; one-keystroke panic disconnect on host (default Ctrl+Alt+End); "view-only"
  session type; unattended access is **opt-in per device** and fully specified in
  §B.8 — invariants: grants are created only locally, after SAS pairing, behind OS
  re-authentication (no protocol message can create or widen one; a lockout can be
  cleared remotely only by an admin request from a Control grant of the *My machines*
  preset, §B.8.6.2); every unattended start needs the pinned device key *and* a
  per-grant password proven with OPAQUE (Argon2id-stretched; with suite 1 the host
  stores no password-equivalent — the SPAKE2 fallback suite does, §B.8.4.7); there is
  no password-less auto-accept; lockouts persist; indicator, panic key and log apply
  unchanged; all session starts/ends logged locally (`sessions.log`).
- **Privacy modes**: Default (signaling via Tor, media direct — peers see each
  other's IP, stated in UI) · **Paranoid** (everything via Tor, quality capped) ·
  LAN-only toggle.
- **No telemetry.** Crash dumps opt-in, written locally.
- Threats explicitly *out of scope* v1: compromised endpoints, Tor global passive
  adversary deanonymization, side-channels in shared GPU environments.

### B.6.1 Names people read (r7; decision M1-63; milestone M-FEAT-1)

Built at `3aa1072`: the sheet shows a 16-hex device fingerprint (64 bits of SHA-256, unstretched), and the redesign's
identicon is drawn from it. Planned:

1. The **saved name** is the trust anchor and appears only when all 32 bytes of the key equal a pinned key; an alias is
   never shown where the pinned label is the trust anchor on a consent sheet.
2. **Device words**, for recognition only: `h = Argon2id(key32, salt = "tornect/v1/words/" || role, 8-byte output)` with
   Argon2id version 0x13, **m = 64 MiB, t = 1, p = 1**, `role` ∈ {`onion`, `device`}; the first 44 bits of `h` as four
   BIP39-English indices, shown `amber · crisp · lantern · orbit`; cached per entry; computed for an unknown key only for
   the sheet on screen, off the network task, after the rate limiter admits the request, one sheet at a time and at most
   one derivation per second per host; golden vectors for both roles are committed. **Frozen** (the operator's ruling of
   2026-09-27): the derivation and these parameters bind every later client, Android included. The only change allowed
   before the first release is m = 32 MiB (t = 1), and only if the phone benchmark exceeds 500 ms
   (NEEDS-DEVICE(android)); never lower; after the release a change needs a new salt.
3. **Strength, stated:** 44 bits, stretched; the GPU rate at these parameters is UNVERIFIED, and a full look-alike of one
   saved device is within reach of a rented GPU fleet in hours to weeks (an estimate, UNVERIFIED). That is adequate for
   recognition and never an authenticator: for a known key the saved name decides (the look-alike gets "not yet
   trusted", and the closer it is, the surer the alarm fires); at first contact the 6-digit commit-reveal code decides
   (10^-6 per attempt, rate-limited).
4. **The look-alike alarm** (machine-run, on host sheets and on the client's connect field) fires on: the same first
   word; ≥ 2 shared words in any position; the same identicon; a declared name confusable with a saved name (Unicode
   skeleton); or a word equal to a word of a saved name or alias (case-folded). On the host a fired alarm turns the
   pairing accept into typing the other device's 6 digits, checked by the host against its own code (no wire change). On
   the client a pasted address that is not in the book but meets these thresholds against a saved entry, or shares its
   first or last four characters with one, shows "Looks like your saved "<name>", but it is a different address", and
   Connect then needs a second, deliberate click.
5. **Which words a person reads:** the host's sheet names the requester's *device* key, whose words differ from its
   onion address's words. The home card leads with "When you connect to another computer, it shows: <device words>";
   the address's own words, if shown at all, sit under the address, labelled "this address". One set per machine is a
   wire change (roadmap).
6. **One short form only** (a deviation from §B.8.7.3): the 16-hex fingerprint leaves every surface; duplicate labels
   get a numeric suffix at pin time ("Laptop (2)"); the identicon is drawn from `h` and shown **only next to a saved
   name, never beside an unpinned key**.
7. **Wording.** A sheet may say "<saved name> wants to connect" (exact key match only), show the words labelled "device
   words", and say "not yet trusted · compare the code". It may not say "verified", "known", "trusted" or "your device"
   for an unpinned key, put words in the name slot or style them as a name, call device-role words an "ID" or
   "address", or hint that words are a password or a check. Help: "Device words help you recognise a device. They do
   not prove who it is; the code does."
8. **The words never authenticate:** no lookup, selection, unlock, grant, pin, auto-fill or connect by words, identicon,
   `h` or a partial address; address-book search may match words to list entries, never act on one. Connecting stays
   the full address, QR, link or paste.
9. **Privacy:** the words are a stable pseudonym — never sent, never in logs, window titles, notifications, diagnostics
   or crash reports.

**M-FEAT-1 MUST** (any one failing fails the milestone's security check): W-B1 no decision (pin, grant, saved-name
display, connect) keyed on words, identicon, `h` or a partial address; W-B2 no saved name or alias for a key that is not
an exact 32-byte match of the pinned key; W-B3 no fired alarm reaches a pairing accept without the typed digits checked
by the host against its own code; W-B4 no words, `h` or identicon seed on the wire, in logs, window titles,
notifications, diagnostics or crash reports; W-B5 no Argon2id for unknown keys outside one sheet at a time and one per
second, or before the rate limiter; W-B6 no platform whose words differ from the golden vectors, and no parameter change
after the release without a new salt; W-B7 no second key-derived short form (hex fingerprint) on the same surface; W-B8
no identicon beside an unpinned key.

### B.7 Latency & quality budgets (acceptance targets, 1080p60 direct path)

| Stage | Target | Hard cap |
|---|---|---|
| Capture (frame available → our hands) | ≤ 4 ms | 8 |
| Convert/map + encode (hw) | ≤ 5 ms | 10 |
| Packetize+FEC+pace (spread, first-packet-out) | ≤ 2 ms | 4 |
| Network (LAN / same-city WAN) | 1–2 / 5–25 ms | — |
| Jitter buffer | 0–1 frame | 3 frames |
| Decode (hw) | ≤ 4 ms | 8 |
| Render/present | ≤ 3 ms | 1 vsync |
| **Glass-to-glass added latency (LAN)** | **≤ 35 ms** | 50 ms |

Quality gates: 1080p60 @ 10–20 Mbit/s HEVC/AV1 visually clean on desktop content;
4K60 supported on capable hw; text-mode (4:4:4 where encoder supports) for remote
work; Tor-fallback mode: 720p30 @ ≤4 Mbit/s, usable for admin tasks.
Instrumentation from day one: every stage stamps `Frame.ts`; `stats` stream +
in-HUD latency overlay (like Moonlight's) + `tracing` spans.

### B.8 Unattended access

> Normative for the popup-less path. Depends on §B.2, §B.3, §B.6 and Part C (M1–M8). Hard
> rules: **(1)** the only popup-less session is an unattended session authenticated by *both* a
> paired device key and a per-grant password (OPAQUE, Argon2id KSF) — no password-less
> auto-accept, no "always allow"; **(2)** grants exist only on the host, only for SAS-paired
> devices; no protocol message can create or widen one, and a lockout can be cleared remotely
> only by an admin request from a Control grant of the *My machines* preset (B.8.6.2);
> **(3)** indicator, panic key and `sessions.log` apply unchanged. Crate facts:
> `docs/research/crypto.md` §8, `wayland.md` §7, `ui.md` §5.9, `arti.md` §9/§11
> (`research-verifier` re-pins at M1).

#### B.8.1 Definitions, scope, user stories

| Term | Meaning |
|---|---|
| Attended session | The person at the host answers the §B.2 popup: at `3aa1072` *Allow once* / *Allow once (view-only)*; from r7 (§B.2.1) *View only*, *Allow* or — Windows, installed — *Allow as administrator…* |
| Unattended session | Started with no click. Requires **F1** possession of a SAS-pinned device key (fresh signature in this stream) *and* **F2** knowledge of that grant's password (PAKE). Nothing else opens this path. |
| Grant | Host-local record `{device_pk, mode, schedule, expiry, limits, auth record, fail state}` for one paired device. One grant per `device_pk`. Created/widened only locally, with OS re-authentication — by the UI or the CLI through the running host, or, with no host running, by the CLI holding the store lock and running the same `MutationGuard` + `ReAuth` code (B.8.6.2, B.8.14); unlocked locally the same way or by an admin request from a Control grant of the *My machines* preset (B.8.6.2). |
| Grant password | Chosen per grant at enable time, typed on the host once (host runs both OPAQUE roles in-process, then zeroizes it) and on the client at login. Never transmitted at login; with suite 1 never stored on the host (the SPAKE2 fallback suite stores a wrapped password-equivalent, B.8.4.7). Blast radius of a leaked password = one device. |
| `ServerSetup` | Host-wide OPAQUE secret (OPRF seed + static AKE key), created lazily — together with `K_master` and the store — at the first unattended enable, inside the re-auth flow where the keychain is interactive (never at host start, B.8.9); kept across off/on cycles; wiped only by *Rotate ID*. |
| Block window | Fixed per-grant delay (0–30 s, disclosed only in the signed `SESSION_ACCEPT`, never before F2) before `SESSION_ACCEPT` during which a local Tornect window with one button, **Block**, is shown. Elapsing is not consent; it is a veto opportunity. Constant duration regardless of idle state. |
| Hard lock | Grant refuses all challenges until unlocked locally (re-auth) or by an admin request from another *My machines* Control grant (B.8.6.2). Unlock resets `FailState` (a remote `unlock(pk)` also clears `Suspended{Admin}`); `Suspended{LocalBlock\|Panic\|Local}` needs a local *Resume* with re-auth (B.8.6.3). |
| Admin request | Post-PAKE, reduce-only (plus *unlock*) command from a granted device in `Active` state; its scope depends on the requester's grant (B.8.4.1); never starts media. |

**Scope (v1):** hosts inside a logged-in, unlocked desktop session on Windows, macOS, GNOME ≥ 45
/ KDE Plasma 6 (`wayland.md` §9.5); direct, Paranoid and LAN-only transports; control or
view-only. **Non-goals (v1):** remote grant creation or password reset (no message exists);
login screens, the Windows secure desktop, the GNOME lock shield, pre-boot disk unlock (Windows: roadmap M-SVC-W
after the release, B.8.8, Part C); waking sleeping hosts (WoL backlog); multi-user hosts; mobile clients (Android:
the roadmap entry of Part C and Part F.7).

| Story | Preset | Defaults | Notes |
|---|---|---|---|
| Home PC from my laptop | *My machines* | Control · block window 3 s · expiry 90 d auto-renewed on use · lock-on-disconnect off | Password may be remembered in the laptop keychain (risk copy, B.8.10). |
| Headless media/gaming box | *Headless box* | Control · block window 0 (explicit acknowledgement) · hard lock after 10 · keep-awake on (host-wide, B.8.7.5) · autostart required · file keystore likely ⇒ zxcvbn ≥ 4 or generated passphrase, expiry ≤ 90 d | Auto-login is the owner's OS choice; the wizard states that anyone who powers the box on gets the desktop, that an empty OS account password (detected by readiness) makes OS re-authentication nominal, and that Tornect cannot judge the strength of a non-empty one (static advisory, B.8.7.1 ⑥). Virtual display driver is post-v1. |
| Helping a relative | *Helping someone* | View-only · expiry 7 d · schedule optional · block window 10 s (min 5) · hard lock after 10 · "Ask before starting" on · grant active 12 h after creation · max session 4 h · admin requests limited to its own session/grant (B.8.4.1) | Scam-call defence: the 12 h cooling-off and the OS re-auth gate; attended sessions work meanwhile. |
| Admin of own machines | *My machines* | as above · `tornect unattended` CLI over local IPC · `sessions.log` | Distinct passwords per host recommended; a stolen host store must not unlock the others. |

#### B.8.2 Threat model (unattended-specific)

Inherited: Tor authenticates the host to the client (address = key); the pinned device key
authenticates the client; endpoint compromise, Tor GPA and shared-GPU side channels are out of
scope (§B.6). New: the human is removed from the loop, so F1+F2 carry the whole consent
decision, and a **Control session is the logged-in OS user** — schedules, expiry, indicator
and log bound an *honest* or *stolen* device, not a hostile controller who is already inside.

| # | Attacker holds | Can | Cannot | Controls |
|---|---|---|---|---|
| T1 | Stolen client, password not remembered | Pass HELLO/SESSION_REQUEST; learn that a grant exists for *this* device (not its block window or ask policy — signed into `SESSION_ACCEPT` only, after F2); read in `hosts.toml` which hosts last said, or did not say, that this device's access reaches administrator access (`reach`, `administrator`) and which grants are Control (`control`), B.8.9; per local unlock ≤ 60 guesses plus ≈ 52/year of decay at most (B.8.5.1), at ≤ 24/day in steady state (≈ 33 on the first day when `hard_lock_after = 0`) and ≤ 20 consecutive (B.8.2.1, B.8.5) | Log in; attack offline (no record on the device; KE2 tests exactly one guess) | Lockout ladder, hard lock, notifications, log, revoke; owner's other *My machines* Control devices can `revoke` via admin request |
| T2 | Stolen client, password remembered, device unlockable | Full impersonation of that grant until revoked; if the grant is a *My machines* Control grant: deny-direction admin requests against the owner's other grants (`suspend`/`revoke`/`revoke_all`/`master_off`/`end_session` — a DoS countered only by the stop code or the local UI) and `unlock` of them (lets a thief who also holds another of the owner's devices keep guessing at ladder rate) | Through Tornect's own surfaces: widen its grant, create grants, change settings without OS re-auth; clear a local Block/panic/local suspension (`Suspended{LocalBlock\|Panic\|Local}`) remotely; suppress the indicator, the per-start notification or the log line of its own sessions for an owner who looks (a Control grant additionally inherits T9's endpoint-level powers) | "Remember" off by default, and never kept for a password whose signed answer gives administrator access through Tornect (`grant_reach`, B.8.9.1); a grant whose own reach rises gets a new generated password, and a password the host's session accept answered with 0 never reaches the administrator level (B.8.6.1); one session per grant; per-start notification; remote `revoke`/`master_off` from another *My machines* Control device; emergency stop code; view-only default for helpers (no cross-grant admin scope) |
| T3a | Copy of the state dir, `K_master` in an unlocked-only OS keychain (Windows DPAPI, macOS Keychain, Secret Service) | Read pairing metadata and the session log — `trusted-devices.toml`, `hosts.toml` and `sessions.log` are plaintext (pinned labels, device and grant ids, session times, transport kinds; no secrets); `hosts.toml` also shows the `reach`, `administrator` and `control` flags of each host (B.8.9); file sizes/mtimes | Read records/`ServerSetup`; impersonate the host | AEAD store under `K_unatt`; those files stay readable by design (the log must remain inspectable) and are named in the SECURITY.md threat model (M8) |
| T3b | Copy of the state dir on a **file-keystore host** (headless Linux, no Secret Service) or a home-dir backup/sync + cracked OS login password | = T4 | — | Stated honestly in readiness ("weaker keystore"); zxcvbn ≥ 4 or generated passphrase enforced; expiry capped at 90 d; TPM-sealed keystore is post-v1 |
| T4 | State dir + `K_master` | Offline dictionary attack per record at Argon2id cost (B.8.2.2); impersonate the host | Log in without cracking (OPAQUE record ≠ password-equivalent) | Argon2id 64 MiB/t=3, strength policy, distinct passwords per host |
| T5 | Online guessing, no paired key | Nothing: unpaired pk ⇒ byte-identical §B.2 PAIR path, no PAKE, no distinguishable timing; `HELLO_ACK.feats` is host-wide | Learn whether unattended exists, or whether a pk is paired here (a bad `HELLO` signature is `E_BAD_SIG` for pinned and unpinned pks alike, B.8.4.2) | §B.3 PoW, token bucket, temp-ban; restricted discovery hides the descriptor |
| T6 | Recorded transcript | — | Replay (client nonce in HELLO and host nonce in HELLO_ACK make both signatures fresh from either side's view; per-stream KE1/KE2; `msg_id`); reflect (roles asymmetric) | B.8.4.3 |
| T7 | Phishing host (user dials attacker's onion) | Receive HELLO (incl. a `stop_token` bound to its own pk, useless at the real host, B.8.7.4) and KE1 (blinded, useless) | Relay to the real host: `context`/`identifiers` embed the dialed onion pk; KE3 MAC fails; with suite 1 the client emits nothing password-derived before KE2 verifies; with suite 2 it gets one online guess per stream and no offline oracle (`pA` blinded by `x`, `cA` verifiable only for the guess embedded in `pB`) | PAKE (B.8.4.7 for the fallback suite) |
| T8 | Downgrade | Ask for an attended session (strictly safer) | Force a weaker suite/KSF (suite fixed per grant and a build-time constant on the client — never derived from `HELLO_ACK.feats` when suite 1 is compiled in, B.8.4.2; KSF constants inside the suite; suite byte in signed transcript + context) | B.8.4.4 |
| T9 | Malicious or compromised **granted Control** device | Everything the OS user can: read keys, start scripts, edit files, delete logs — including reading `K_master` from the user keychain (readable without presence, which is what autostart requires) and therefore rewriting the store, the generation anchor and the log chain, then restarting the host. On a Windows host (r7, §B.2.1, B.8.7.5): a session answered *Allow as administrator* and a Control session of an admin grant are administrator sessions; **while any admin grant exists, any program running as the user can start the administrator helper, so every Control session on that host can reach administrator windows** (also while the helper task outlives the last admin grant, until the next local presence removes it; a Control grant whose password is marked — a session accept answered it with `grant_reach = 0`, chosen, or older than the mark — is then served View only, §B.8.6.1); on a host with no admin grant, Windows keeps other sessions out of administrator windows (UIPI) — on an administrator account that is not a security boundary. Until M-FEAT-3 replaces it, a host started from the whole-host elevated task of M1-53 makes every Control session an administrator session | Use Tornect's *own* surfaces (UI, IPC, CLI) to create/widen/unlock grants or rebind the panic key without the OS credential: there, mutations need OS re-auth and no active session, and popups are never shown during a remote session. Re-auth and the mutation guard raise the bar for misuse through those surfaces and make changes visible (banner, notifications); they do not stop an endpoint-level rewrite, which is endpoint compromise — out of scope per §B.6 and the reason presets default helpers to view-only | Least-privilege presets (view-only default for helpers — the real control), block window, panic key, remote revoke; the log chain detects tampering only by parties without `K_master` (macOS Keychain code-signing ACLs partially mitigate; presence-gated policy signing is backlog, B.8.9) |
| T10 | Coercion / support scam | Talk the owner through pairing + granting | Do it remotely, silently or instantly (12 h cooling-off for helpers; re-auth; scam step in the wizard) | B.8.7.1 |
| T11 | Lockout-as-DoS | Burn the grant of a key it holds (incl. a cloned key) | Lock other grants (counters per grant; global limits only answer `UA_BUSY`, and uncharged `HelloVerified` streams never occupy them, B.8.5.2) | Remote unlock via another *My machines* Control device; `fail_summary` in `SESSION_ACCEPT` |
| T12 | Clock manipulation (local or NTP) | By a forward wall-clock jump **across a store load** (a host restart or a keystore recovery, B.8.5.1 — which a pre-authentication attacker cannot force; a live Control session (T9) can): shorten a *persisted* lock and decay the *persisted* counters — `consecutive` by one per 24 h of jump (uncapped), `since_unlock` by at most one step per load (B.8.5.1; a keychain that locks on sleep — a macOS option — makes each wake a load: still ≤ 1 lifetime step, and the consecutive steps follow the real elapsed time unless the wall clock was also stepped); a jump beyond Tor's directory tolerance also takes the host offline | Shorten a running lock or decay a counter **at runtime** (both monotonic-clock based — a runtime NTP step is deferred, not ignored: invisible to the running limiter until the next load, where a forward step is bounded as on the left and a backward step is detected because `last_seen` is monotone, B.8.5.3); shorten any lock by rollback; revive expired grants or schedules (rollback ⇒ fail closed at load *and* at every runtime schedule/expiry check, B.8.5.3); re-open a hard-locked grant by decay (decay never clears `hard_locked`); exceed the hard-lock budget without loads (the per-load lifetime-decay cap bounds the rest) | B.8.5.1, B.8.5.3 |

**B.8.2.1 Online economics (host-enforced).** Per grant, consecutive failures: 20 challenges
take 10 h 53 min 40 s at the earliest (table B.8.5.1), then hard lock; the lifetime budget (60
failures per unlock) stops reset-on-success farming by a cloned key. `hard_lock_after = 0`
disables the *consecutive* hard lock only (warned); the lifetime budget always applies, so even
then an attacker gets at most 60 guesses per local unlock. Until that budget is spent the ladder
alone (60 min per failure from n ≥ 10) caps the steady state at 24 guesses/day/grant — for an
attacker without owner-driven resets and with an honest clock; a cloned key that watches the owner
log in gets 2 free + a few cheap guesses per owner login, bounded by the lifetime budget and the
notifications. Net, **per local unlock: ≤ 60 failures plus ≈ 52/year of decay at most (a host that is off for more than two
weeks forfeits the excess — one step per load, B.8.5.1), at ≤ 24/day in steady state (≈ 33 on the first day when `hard_lock_after = 0`: 10 inside 53 min 40 s, then one per
hour) and ≤ 20 consecutive (10 h 53 min 40 s to reach the 20th)**; only if hard locks were cleared
indefinitely would the ladder rate alone govern — a uniform 10 k-word list would then need ≈ 208
days expected (417 max), 1 M words ≈ 57 years expected — and every failure from the second onward
notifies.
Policy (B.8.7.2, zxcvbn ≥ 3 ⇒ ≥ 10⁸ guesses) makes "in the top 20" negligible. Tor adds ≥ 1
onion RTT per stream (0.4–1.5 s); circuits are reused across streams, so pacing comes from the
ladder, not from Tor.

**B.8.2.2 Offline economics (requires T3b/T4).** Assumptions: Argon2id 64 MiB, t = 3, p = 1
≈ 0.2–0.3 s per guess per CPU core; one high-end GPU ≈ 10³ guesses/s (memory-bound; order
of magnitude — `research-verifier` records a measured figure in `docs/research/crypto.md` at
M1). Full-search costs (expected ≈ half): 10⁸ guesses (zxcvbn score 3 floor) ≈ 1.2 GPU-days;
10¹⁰ (score 4) ≈ 4 GPU-months; 5-word EFF passphrase (≈ 64.6 bits ≈ 2.8 × 10¹⁹) ≈ 9 × 10⁸
GPU-years. The enable flow shows the expected figures and pre-fills the generator.

#### B.8.3 Design decisions

| ID | Decision | Why |
|---|---|---|
| UA1 | **OPAQUE-3DH** (`opaque-ke` 4.0.1, ristretto255 / SHA-512 / Argon2id 64 MiB, t=3, p=1) — the host stores `ServerSetup` + one `ServerRegistration` per grant | Password is typed on the host once at enable time and never transmitted at login (suite 1; the fallback suite differs, B.8.4.7); offline attack needs host secrets *and* Argon2id; KSF cost is on the client, host cost ≈ 4 scalar mults (DoS-friendly) |
| UA2 | One record **per grant**, `credential_identifier = device_pk`, password chosen per grant | Blast radius of one leaked password = one device; rotation touches one device; helpers never share the owner's secret |
| UA3 | Paired-but-not-granted (incl. disabled, expired, master off) ⇒ `NOT_GRANTED`, suspended ⇒ `SUSPENDED`, **before** any PAKE; unpaired ⇒ byte-identical PAIR path | Refusing the PAKE removes the guessing oracle for every non-grantee; the "you have a grant" bit is only revealed to the holder of that device's key, who learns it from the UX anyway; uniform dummy responses would punish the owner's own devices during pause/off (self-lockout) |
| UA4 | Freshness: host `HELLO_ACK{nonce}`; client signs `SESSION_REQUEST` over the transcript; counter charged (write-ahead, fsynced) after that signature verifies and before KE2 is written | HELLO alone is a static, replayable blob; nothing password-related happens before a fresh proof of `dev_sk` |
| UA5 | `session_token` for unattended sessions is **derived** from the PAKE `session_key`; `SESSION_ACCEPT` carries a confirmation MAC, not the token; attended sessions keep the random token | The §B.6 exporter check then transitively proves PAKE completion; `tornect-net` API unchanged |
| UA6 | KSF parameters are **constants of the suite**, not wire fields; `export_key` unused; the client pins `server_s_pk` (TOFU) | Removes the hostile-host OOM/CPU vector; changing parameters = new suite id = re-registration; a 32-bit human fingerprint bought nothing |
| UA7 | Every access-increasing mutation needs *no remote session (+60 s)* **and** OS re-authentication, through the running host (UI, IPC/CLI alike) or — with no host running — the CLI holding the store lock and running the same `MutationGuard` + `ReAuth` code; policy lives in the AEAD store, never in `config.toml` | A Control session is the OS user; only a credential the controller lacks can gate Tornect's own surfaces (endpoint-level rewrites with `K_master` are T9, out of scope; an empty OS account password makes re-auth nominal — readiness detects that case and otherwise advises that Tornect cannot judge the OS password's strength, B.8.7.1 ⑥) |
| UA8 | Fallback suite = **SPAKE2** (the RFC 9382 construction over ristretto255 with Tornect constants, B.8.4.7) over an Argon2id-stretched password, compiled only under `pake-fallback`, decided by `research-verifier` at M1 | A balanced PAKE keeps phishing hosts to one online guess per stream; plain HMAC challenge-response would hand any dialed host an offline oracle |

#### B.8.4 Protocol (`tornect-signal`, protocol v1 — nothing ships before M1, so no v2)

**B.8.4.1 Envelope, kinds, bodies.** Signatures move to the envelope so that verifiers never
re-serialize CBOR: `Envelope { v: u8, msg_id: u64, kind: Kind, body: bytes, sig: Option<bytes[64]> }`.
Bodies are CBOR maps; receivers ignore unknown keys; missing optional keys take the documented
defaults. `Kind` gains `HELLO_ACK | AUTH_CHALLENGE | AUTH_RESPONSE | ADMIN_RESULT`.

```
HELLO            (client, signed)  += { v_max: u8, client_nonce: bytes[32], sas_commit: bytes[32] /* SHA-256("tornect/v1/sas-commit\0" || sas_nonce); the nonce itself is withheld until PAIR_REQUEST (§B.3) */, feats: [tstr] /* "ua1" | "ua2": the PAKE suites this build supports (a build-time constant, B.8.4.2) */, stop_token: Option<bytes[32]> /* SHA-256("tornect/v1/stop\0" || dialed_host_onion_pk || stop_code), never the code (B.8.7.4) */ }
HELLO_ACK        (host, signed)     { v: u8 /* chosen */, host_nonce: bytes[32], feats: [tstr] /* host-wide, independent of the peer (T5); no host_name — unauthenticated fingerprinting surface before F1; the client shows the paired label instead */ }
PAIR_ACCEPT      (host)            += { host_name: tstr }   /* unpaired peers learn the name here, after consent, never before */
SESSION_REQUEST  (client, signed)  += { unattended: Option<{ suite: u8 /* 1 = OPAQUE-3DH-r255-SHA512-Argon2id(64MiB,3,1) · 2 = SPAKE2 fallback (B.8.4.7) */,
                                        ke1: Option<bytes[96]> /* required iff suite = 1 */, want_mode: u8 /* 0 control, 1 view-only */, want_elevation: Option<u8> /* r7, M-FEAT-2: 0 none · 1 admin; absent = 0 */,
                                        intent: u8 /* 0 session, 1 admin */, admin: Option<AdminCmd> /* required iff intent = 1, else E_BAD_LEN */ }> }
AUTH_CHALLENGE   (host)             { suite: u8, ke2: Option<bytes[320]> /* iff suite = 1 */, salt: Option<bytes[16]>, pB: Option<bytes[32]> /* iff suite = 2 */ }
                                        /* no grant policy here: block_window_s / ask_before_start travel only in the signed SESSION_ACCEPT, after F2 (T1 must not learn a veto-less target) */
AUTH_RESPONSE    (client)           { ke3: Option<bytes[64]> /* iff suite = 1 */, pA: Option<bytes[32]>, cA: Option<bytes[32]> /* iff suite = 2 */ }
SESSION_ACCEPT   (host, signed)    += { session_type: u8 /* 0 attended, 1 unattended */, mode: u8, elevation: Option<u8> /* r7, M-FEAT-2: 0 none · 1 admin (Windows); absent = 0; never ≠ 0 with mode = 1 */,
                                        transport_policy: u8 /* 0 any, 1 tor_only, 2 lan_only */,
                                        quic_spki: bytes[44] /* the host's Ed25519 SubjectPublicKeyInfo DER (§B.2, §B.6) — must equal the pinned pairing key, constant-time compare (B.8.4.2, B.8.16); exact length asserted by F1 */,
                                        session_token: Option<bytes[32]> /* attended only; MUST be absent when session_type = 1 */,
                                        token_confirm: Option<bytes[32]> /* unattended only */,
                                        block_window_s: u8, ask_before_start: bool /* grant policy, disclosed only here (signed), after F2 */,
                                        ends_at: Option<u64>, fail_summary: Option<{ since_success: u32, last_fail_at: Option<u64> /* Some whenever since_success > 0 */ }> /* the snapshot returned by settle(ok) with this stream's own charge excluded; None when since_success == 0 (B.8.5.1) */, grant_reach: Option<u8> /* key 12; M1-67: what the password just proven can reach through Tornect on this host, whatever was asked: 2 = this grant holds the administrator level and its password is not marked, 1 = Control here can reach it through the host, or an administrator grant whose password is marked (B.8.6.1), 0 = neither (B.8.4.1); unattended only — sent, 0 included, by every host that knows it; absent on an unattended accept = unknown */ }
SESSION_REJECT   (host)             { reason: u16, cause: Option<u8> /* HOST_NOT_READY: 1 capture_permission · 2 input_permission · 3 locked · 4 other_user_active · SUSPENDED: 1 local (LocalBlock · Panic · Local) · 2 admin — the holder of that device's key learns which of its own suspensions applies, consistent with UA3; drives the B.8.10 copy */,
                                        retry_after_s: Option<u32> /* LOCKED_OUT, COOLDOWN; never SUSPENDED (no timer: cleared only per B.8.6.3) */, next_open_in_s: Option<u32>, detail: Option<tstr ≤ 120> }
ADMIN_RESULT     (host, signed)     { ok: bool, detail: Option<tstr ≤ 120>, grant_reach: Option<u8> /* key 2; M1-67: as in SESSION_ACCEPT, for the requester's grant as loaded before the command, on every result */ }
AdminCmd = { op: u8 /* 1 revoke(pk) · 2 revoke_all · 3 master_off · 4 unlock(pk) · 5 suspend(pk) · 6 end_session */, device_pk: Option<bytes[32]> }
BYE              (either)           { reason: u16, detail: Option<tstr ≤ 120> }
  reason: 0x01 USER · 0x02 REVOKED · 0x03 MASTER_OFF · 0x04 EXPIRED · 0x05 SCHEDULE_END · 0x06 MAX_SESSION · 0x07 HOST_LOCKED · 0x08 PANIC
        · 0x09 NO_LAN_PATH · 0x0A ADMIN_END · 0x0B EMERGENCY_STOP · 0x0C CLIENT_AUTH_ABORT (KE2 MAC failed) · 0x0D ORPHANED · 0x0E REPLACED
        · 0x0F PAUSED · 0x10 SUSPENDED   /* deny-direction change → BYE reason mapping in B.8.6.1 */
ERROR            (either)           { code: u16 /* 0x0001 E_BAD_STATE · 0x0002 E_BAD_SIG · 0x0003 E_BAD_MSG_ID · 0x0004 E_TOO_LARGE · 0x0005 E_UNKNOWN_KIND · 0x0006 E_VERSION · 0x0007 E_BAD_LEN */, detail: Option<tstr> }
PING             (client, after SESSION_ACCEPT; a PING from the host is answered too) { nonce: u64 }
PONG             (either)           { nonce: u64 /* the PING's */, notice: Option<u8> /* key 1 (planned in M-UI-4, decision M1-70): sent only by the host of a Control session, always in its first PONG (0 included) and again only when the value changes; bits: 0x01 the host runs Windows · 0x02 the session is not at the administrator level on a Windows host, so its input cannot reach administrator windows (UIPI, §B.2.1) · 0x04 a secure Windows screen is showing (§B.8.8); other bits reserved, ignored; a number, never text: the viewer says its own fixed sentences; absent = nothing new */ }
```
`ke1/ke2/ke3` carry raw `serialize()` bytes (exact lengths 96/320/64 checked before
deserialization); a suite-specific field missing for the negotiated suite, or present for the
other one, ⇒ `E_BAD_LEN`. `want_mode` is clamped host-side to the more restrictive of the two —
`max(grant.mode, want_mode)` under this encoding (`SessionMode::most_restrictive(a, b)`; a view-only
grant plus `want_mode = 0` yields view-only, never Control) — never a reject. `want_elevation` (r7) is clamped the
same way, to the more restrictive of the grant's `elevation` and the request — lower is the safe direction, never a
reject — so an owner can connect without administrator rights on an admin grant; an attended session takes its level
from the §B.2.1 answer. The level is fixed at `SESSION_ACCEPT` and never raised during a session. An old client ignores
`elevation` (receivers ignore unknown keys), so the host's indicator and banner, not the client HUD, are the authority
for the person at the computer; a separate optional key, not a mode value 2, keeps mode and level independent.
`grant_reach` (decision M1-67) is not the session's level. It says what the password just proven can reach through
Tornect on this host, whatever was asked, so the client can decide whether a keychain may hold it (B.8.9.1, DA-14). On
Windows it is 2 when the grant's own `elevation` is administrator, whatever its mode, unless its password is marked as
below. It is 1 when the grant is Control and some grant in the store holds administrator (whatever its state), or the
administrator helper task is registered or cannot be read, or this account's settings make control administrator access
(on an administrator account: UAC off, the built-in Administrator without Admin Approval Mode, elevation without
prompting; a setting that cannot be read counts as making it so), installed or standalone. It is also 1 for an
administrator grant whose password is marked. Otherwise it is 0, and on Linux it is always 0. The host computes it, and
the grant level the clamp uses, from one read of the account settings and of the administrator helper task's presence
(one that cannot be read counts as registered), taken after the session is reserved, and one read of the store under its
lock, right before the accept is signed; that read refuses a password whose grant got a new password after its PAKE
began (`AUTH_FAILED`), and a grant no longer eligible (`NOT_GRANTED`), and it never raises the session. `want_mode`,
`want_elevation`, the helper's arrival and the master switch never lower it; the clamp never reads it, and it never
raises a session. A host that can sign `elevation = 1` on an unattended accept, or that lets a grant hold the level,
MUST send it. The client refuses with `E_BAD_LEN` a value above 2, the key on an attended accept, and an unattended
accept with `elevation = 1` without `grant_reach = 2`. It is covered by the body signature and so bound to the
transcript and the PAKE of this stream. It does not describe what the host's account can do without a password (§B.2.1:
polkit or `sudo` on Linux; T9 on a Windows administrator account). It tells a Control holder that something on the host
gives Control the administrator level, at every answer, including an admin command that runs nothing, with no session;
every `ADMIN_RESULT` is therefore logged on the host (B.8.13).
`stop_token` (B.8.7.4)
may come from any peer; it is `SHA-256("tornect/v1/stop\0" || dialed_host_onion_pk || stop_code)`,
never the code itself; the host compares it in constant time against the value it stored at enable
time (computed with its own pk) and otherwise ignores the field, so the unpaired path stays
byte-identical.
Attended sessions: `block_window_s = 0`, `ask_before_start = false`, `elevation` from the §B.2.1 answer (r7), `transport_policy` = host
privacy mode (Paranoid ⇒ `tor_only`, LAN-only ⇒ `lan_only`, else `any`), `ends_at = None`,
`fail_summary = None`.
**Admin scope:** `unlock(pk)`, `suspend(pk ≠ self)`, `revoke(pk ≠ self)`, `revoke_all` and
`master_off` require the requester's grant to have `mode = Control`, `preset = MyMachines` and
state `Active`; every other grant (helpers, view-only) may only `end_session` (its own session)
and `revoke` (its own pk). Out-of-scope ops ⇒ `ADMIN_RESULT{ok: false}`, no state change, logged
(`AdminRequest`, refused). `unlock(pk)` resets the target's `FailState` and clears
`Suspended{Admin}` (set by a remote `suspend(pk)`); it never clears `Suspended{LocalBlock|Panic|Local}`,
which needs a local *Resume* with re-auth (B.8.6.3). `suspend(pk)` moves an `Active` grant to
`Suspended{Admin}` and leaves an already suspended grant untouched — the local reasons outrank `Admin`
(`ADMIN_RESULT{ok: true}`, `AdminRequest` logged, state unchanged; B.8.6.3), so a `suspend(pk)` followed by an
`unlock(pk)` can never clear a local Block, panic or local suspension.

**B.8.4.2 Sequence (happy path; Tor RTT 0.4–1.5 s per arrow pair).**
```
Client                                                             Host
prompt password (or keychain) → ClientLogin::start(pw) → ke1
HELLO{v_max, client_nonce, sas_commit, device_pk, name, feats, sig} ─►  verify sig vs HELLO's own pk (proof of possession) and, if pinned, pk == pinned key;
                                                                    bad sig ⇒ E_BAD_SIG for pinned and unpinned alike; unpaired ⇒ §B.2 PAIR path, unchanged
◄──────────────────────────── HELLO_ACK{v, host_nonce, feats, sig}  (signed with the onion identity key; client verifies vs dialed address)
SESSION_REQUEST{caps, unattended:{suite, ke1, want_mode, intent}, sig} ►  verify sig over th (fresh: covers host_nonce) — F1
                                                                    grant lookup: none/disabled/expired/master-off ⇒ REJECT{NOT_GRANTED}
                                                                    suite unsupported by this build or ≠ grant.suite ⇒ REJECT{UNSUPPORTED_SUITE}; now < active_from (or a clock rollback, now < last_seen: next_open_in_s = last_seen − now, B.8.5.3) ⇒ REJECT{NOT_YET_ACTIVE, next_open_in_s}
                                                                       (both pre-PAKE, uncharged; evaluated after the grant lookup and before the suspension/lock/budget checks)
                                                                    suspended (LocalBlock · Panic · Admin · Local) ⇒ REJECT{SUSPENDED}   (no timer; cleared per B.8.6.3)
                                                                    locked ⇒ REJECT{LOCKED_OUT|HARD_LOCKED, retry_after_s}
                                                                    in-flight/global budget ⇒ REJECT{UA_BUSY 0x0013}   (in flight = charged AwaitKe3 streams only, B.8.5.2; none of these run a PAKE)
                                                                    limiter.charge(grant) → fsync (write-ahead; error ⇒ no KE2)
                                                                    ServerLogin::start(setup, record, ke1, device_pk, {context, identifiers}) → ke2
◄──────────── AUTH_CHALLENGE{suite, ke2}   (no grant policy before F2)          timer 30 s for AUTH_RESPONSE
ClientLogin::finish(pw, ke2, {context, identifiers, ksf})  (Argon2id ≈ 0.3 s, off the UI thread)
  server MAC fails ⇒ BYE{CLIENT_AUTH_ABORT} (wrong password / tampered) — no KE3    server_s_pk ≠ pinned ⇒ abort "host's unattended setup changed"
AUTH_RESPONSE{ke3} ────────────────────────────────────────────►  ServerLogin::finish(ke3, {context, identifiers}) — F2
                                                                    fail ⇒ REJECT{AUTH_FAILED}; close
                                                                    ok ⇒ limiter.settle(ok) → FailSummary; PolicyReceipt: schedule · mode (clamp) · transport · readiness · busy · concurrency · fail_summary
                                                                    intent = admin ⇒ grant Active? op in scope (B.8.4.1)? ⇒ execute → ADMIN_RESULT{ok}; close
                                                                                   (schedule · readiness · transport · busy · concurrency gates skipped)
                                                                    session_token = HKDF(session_key, th); [ask_before_start ⇒ Allow/Deny popup, 60 s ⇒ REJECT{DENIED}];
                                                                    block window (Tornect window + chime)
◄── SESSION_ACCEPT{caps, quic_spki, session_type:1, mode, transport_policy, token_confirm, block_window_s, ask_before_start, ends_at, fail_summary, elevation?, grant_reach, sig}
verify sig; token_confirm == own derivation (ct); quic_spki == pinned host key (ct, §B.6); session_type matches request; grant policy read from here only; then, before `CANDIDATES`, the remembered password is kept or deleted from this accept's `grant_reach` alone (B.8.9.1)       host: sessions.log start; indicator ON
CANDIDATES … punch … QUIC (exporter check on the derived token) … media — unchanged from §B.2 (tor_only: no CANDIDATES, immediate TOR_FALLBACK);
  the Tor fallback tunnels the same QUIC connection, so the exporter/token check applies unchanged on both transports (transport choice pending §B.8.17 item 7, decided at M2)
```
Capture and injection start only after the block window elapses without Block. Local candidate
gathering (UPnP/PCP, STUN) may start during the window; the `CANDIDATES` exchange and punching
begin only after `SESSION_ACCEPT`. Suite choice is a **build-time constant on the client**: a
build that compiles suite 1 always requests suite 1; suite 2 is selectable only in a build where
suite 1 is absent (`pake-fallback` alone). The suite is never derived from `HELLO_ACK.feats` when
suite 1 is compiled in (a phishing host advertising suite 2 must not buy itself an online guess).
`feats` tokens: `"ua1"` = suite 1 supported, `"ua2"` = suite 2 supported (the host advertises
its compiled suites host-wide; the client lists its own in `HELLO.feats`). A host that lacks the
client's suite (or whose grant for that device was registered under another suite) answers
`UNSUPPORTED_SUITE` pre-PAKE, uncharged; that, or a `suite` mismatch in `AUTH_CHALLENGE`, is
surfaced to the user and never auto-retried with another suite (the suite recorded in `hosts.toml`
at the first success, B.8.9, serves the pin and the UX only).

**B.8.4.3 Transcript, signatures, key binding (both sides, SHA-256).**
```
th_0  = H("tornect/v1/transcript\0" || host_onion_pk[32])         // client: pk of the address the user dialed, never a host-sent value
th_i  = H(th_{i-1} || wire_frame_i)                                // exact bytes incl. u32-BE length, in protocol order (B.8.4.5)
sig   = Ed25519.sign(sk, "tornect/v1/sig/" || kind_name || "\0" || th_{i-1} || digest)
digest    = SHA-256(u8 v || u64-BE msg_id || u8 kind || body bytes)   // kind = the §B.3 integer; kind_name = its upper-case ASCII name, e.g. "SESSION_ACCEPT"
        client: dev_sk on HELLO, SESSION_REQUEST · host: onion identity key (expanded key per decision M1-1 in `docs/notes/decisions.md`) on HELLO_ACK, SESSION_ACCEPT, ADMIN_RESULT
credential_identifier = client_device_pk[32]
identifiers = Identifiers { client: Some(client_device_pk[32]), server: Some(host_onion_pk[32]) }   // identical at registration and login
context     = "tornect/v1/unattended/ctx\0" || th_after(SESSION_REQUEST) || u8(suite) || u8(intent)
session_token = HKDF-SHA256(ikm = session_key, salt = "tornect/v1/unattended/st", info = "token\0" || th_after(AUTH_RESPONSE))[0..32]   // ikm = the suite's key: OPAQUE session_key (64 B, suite 1) or SPAKE2 Ke (32 B, suite 2)
confirm_key   = HKDF-SHA256(ikm = session_key, salt = "tornect/v1/unattended/confirm-key", info = th_after(AUTH_RESPONSE))[0..32]   // never the token itself (key separation from the QUIC exporter context)
token_confirm = HMAC-SHA256(confirm_key, "tornect/v1/unattended/confirm\0" || th_after(AUTH_RESPONSE))   // suite 2: cB keyed by KcB instead (B.8.4.7)
proof_fp      = HKDF-SHA256(session_key, salt = "tornect/v1/unattended/proof-fp", info = "")[0..8]   // ConsentProof only
QUIC binding  = BIND exchange (§B.6; same code path as attended): immediately after the QUIC handshake each side sends on ctrl
                BIND { mac = HMAC-SHA256(exporter("EXPORTER-tornect/v1/session-binding", context = session_token, 32), "client" | "server") }
                "client" = the device that dialed the onion service, "server" = the host — Tornect roles, fixed by signaling, independent of
                which side becomes the QUIC client under the §B.2 tie-break (the exporter is certificate-type independent, RFC 8446 §7.5;
                quic.md §6 verified it over raw public keys); the golden vector of B.8.14 M1 fixes both MACs
                (a differing exporter context never fails the handshake by itself); the peer verifies constant-time and closes with an
                error code on mismatch; no other stream or datagram is accepted, and capture/injection never starts, before a valid BIND is received
```
*What binds what:* the signed `SESSION_REQUEST` proves F1 freshly (it covers `host_nonce`);
`context` chains the PAKE to that signed transcript (dialed host pk, device pk, caps, suite,
intent); KE2/KE3 MACs cover `context` + `identifiers` + fresh ephemerals, so `session_key`
exists only if the same device-transcript and password met in this stream; `SESSION_ACCEPT`'s
signature covers the whole AUTH exchange. Invariants: the host builds `context`/`identifiers`
from the signature-verified pk, never from a later body field; registration is bound via
`identifiers` only (OPAQUE has no registration context); fresh `ClientLogin::start` per stream.

**B.8.4.4 OPAQUE suite and calls (types verified in `crypto.md` §8.2–8.4).**
```rust
// Cargo: opaque-ke = { version = "=4.0.1", default-features = false, features = ["ristretto255", "argon2", "serde"] }
//        sha2_010 = { package = "sha2", version = "0.10" }   // opaque-ke is on digest 0.10 / rand 0.8 / argon2 0.5 (adapter: crypto.md §3.4)
pub struct TornectOpaque;
impl opaque_ke::CipherSuite for TornectOpaque {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_010::Sha512>;
    type Ksf = opaque_ke::argon2::Argon2<'static>;                       // argon2 0.5 via the re-export; never `argon2 0.6` here
}
pub const KSF: (u32, u32, u32) = (64 * 1024, 3, 1);                     // suite constant; `ksf: None` (19 MiB, t=2 default) is forbidden
fn ksf() -> opaque_ke::argon2::Argon2<'static> { Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(KSF.0, KSF.1, KSF.2, None).expect("const")) }
// enable flow (host plays both roles in-process; pw: Zeroizing<String>, NFC-normalized)
let setup = load_or_create_server_setup(&keystore);                     // ServerSetup::new(rng) once per host, 128 B, AEAD store
let c  = ClientRegistration::<TornectOpaque>::start(&mut rng, pw)?;
let s  = ServerRegistration::<TornectOpaque>::start(&setup, c.message, device_pk)?;
let f  = c.state.finish(&mut rng, pw, s.message, ClientRegistrationFinishParameters::new(ids, Some(&ksf())))?;
let record = ServerRegistration::<TornectOpaque>::finish(f.message);   // 192 B → AuthRecord::Opaque; f.export_key, states, pw zeroized here
// login: client  ClientLogin::start(rng, pw) → ke1 ; finish(rng, pw, ke2, ClientLoginFinishParameters::new(Some(&ctx), ids, Some(&ksf())))
//                → { ke3, session_key, server_s_pk, export_key }: the client drops/zeroizes export_key (64 B, password-derived, identical
//                across logins) in the same scope as finish, never persists or logs it (A14); server_s_pk is checked against the hosts.toml pin (B.8.9)
//        host    ServerLogin::start(rng, &setup, Some(record), ke1, device_pk, ServerLoginParameters{context, identifiers}) → ke2
//                st.finish(ke3, ServerLoginParameters{context, identifiers}) → session_key   (parameters on BOTH host calls)
```
`ServerLogin::start(.., None, ..)` (dummy record) is deliberately unused (UA3). All states are
`Zeroizing`/`!Clone` and dropped on every error path.

**B.8.4.5 Ordering rules and state machine.** `msg_id` is per direction, starts at 1, every
frame incl. `ERROR`/`BYE` consumes one; `n ≠ prev+1` ⇒ `E_BAD_MSG_ID` + close. From `HELLO` to
`SESSION_ACCEPT`/`SESSION_REJECT`/`ADMIN_RESULT` the stream is **strictly alternating** in the
order of B.8.4.2 (PAIR exchange included when unpaired); any other kind in that window
(`PING`, `CANDIDATES`, …) ⇒ `E_BAD_STATE` + close, no additional charge (an existing `AwaitKe3`
charge stands and is settled as fail); `th` absorbs exactly those
frames (own frame when sent, peer's when received); `ERROR`/`BYE` are never absorbed; frames in
`Closing` are dropped silently. One `SESSION_REQUEST` per stream (attended fallback after
`NOT_GRANTED` opens a new stream). Timeouts: host closes streams without `SESSION_REQUEST` 60 s
after `HELLO` (uncharged; the timer restarts at `PAIR_ACCEPT`/`PAIR_REJECT`, so a human comparing
the SAS code — governed by the PAIR popup's own timeout — is never cut off) and waits 30 s for
`AUTH_RESPONSE` (charged); client waits 20 s for `HELLO_ACK`, 30 s for `AUTH_CHALLENGE`, and the
fixed maximum `30 + 60 + 20 s = 110 s` for `SESSION_ACCEPT` (grant policy is not disclosed before
it; the client shows a generic "someone at *Host* can still block" until accept); no `CANDIDATES`
(or, under `tor_only`, no `TOR_FALLBACK`) within 15 s of `SESSION_ACCEPT` ⇒ torn down
(`BYE{ORPHANED}`); only a *post-F2 success* from the same pk pre-empts it earlier (`BYE{REPLACED}`
semantics, B.8.6.4) — a bare `HELLO` from that pk never does.
Version: `HELLO.v_max`; the `HELLO` envelope itself carries `v = 1` (the lowest version the client
supports); host picks `v ≤ v_max` in `HELLO_ACK` and both sides use it from `HELLO_ACK` on.

| Host state | Event | Action → next |
|---|---|---|
| `HelloVerified` | `SESSION_REQUEST{unattended}` with valid sig | gate, in this order (all pre-PAKE, uncharged): grant lookup (`NOT_GRANTED`) · suite unsupported by this build or ≠ `grant.suite` ⇒ `UNSUPPORTED_SUITE` · `now < active_from` — or a clock rollback, `now < last_seen` (B.8.5.3) — ⇒ `NOT_YET_ACTIVE{next_open_in_s}` · state: suspended ⇒ `SUSPENDED` · lock · budget ⇒ reject+close (no PAKE), or charge → `ServerLogin::start` → `AUTH_CHALLENGE` → `AwaitKe3` (30 s) |
| `HelloVerified` | `SESSION_REQUEST{unattended}` with valid sig while the same pk has a charged `AwaitKe3` handshake in flight | pre-emption requires freshness: this stream's own signed `SESSION_REQUEST` (verified under the new `host_nonce`, F1) cancels the stale handshake (already charged; settled as fail; closed with `PREEMPTED`, B.8.4.6) and this stream continues through the gate above. A bare verified `HELLO` never cancels anything (`HELLO` is replayable by design — its signature covers only `th_0` and a client-chosen nonce): the in-flight handshake stands and times out in ≤ 30 s anyway. If the older stream's charge is still being persisted (between F1 and KE2 written) the newer stream is answered pre-PAKE `UA_BUSY` instead. A *live session* (or a still-orphaned accept) from this pk ⇒ decided post-F2 (the older session gets `BYE{REPLACED}`, B.8.6.4; intent = session only — an admin stream never replaces a live session) |
| `AwaitKe3` | `AUTH_RESPONSE` valid | `settle(ok)`; `PolicyReceipt`; intent admin ⇒ scope check → `ADMIN_RESULT` → `Closing`; else post-F2 reject, or `ask_before_start` ⇒ `AwaitLocalAllow`, else block window → `Accepting` |
| `AwaitKe3` | invalid KE3 / timeout / circuit loss / `BYE` / any `ERROR`-class violation (`E_BAD_STATE`/`E_BAD_MSG_ID`/`E_BAD_LEN`) / cancelled by a newer stream | `settle(fail)` → `AUTH_FAILED` (if the stream is alive; a stream cancelled by a newer one is closed with `PREEMPTED` `0x002A` instead — transport-class on the client, never a password failure, B.8.4.6) → `Closing`; notify + log |
| `AwaitLocalAllow` | Allow clicked · Deny clicked or 60 s elapsed | Allow ⇒ block window → `Accepting`; Deny/timeout ⇒ `SESSION_REJECT{DENIED}` → `Closing` |
| `Accepting` | Block clicked | `SESSION_REJECT{BLOCKED_BY_LOCAL_USER}`; grant → `Suspended{LocalBlock}` (cleared only by a local *Resume*, never by a remote `unlock`) → `Closing` |
| `Accepting` | window elapsed | `SESSION_ACCEPT` (signed) → `Candidates` (existing); `last_used`; `session_started` logged |
| any | revoke / master off / expiry / schedule end / `end_session` admin | `BYE{reason}` + QUIC close ≤ 1 s; `session_ended{reason}` |

**B.8.4.6 Reject reasons** (u16; attended codes `0x0001 DENIED`, `0x0002 POPUP_TIMEOUT`,
`0x0003 BUSY` are fixed in M1). Pre-PAKE (safe to disclose to a key holder): `0x0010
NOT_GRANTED` (no grant · disabled · expired · master off · paused · keystore locked at start,
B.8.9 — deliberately merged), `0x0011 LOCKED_OUT` (`retry_after_s`, rounded **up** to the next
10 s — the ladder, not the display, is the control), `0x0012 HARD_LOCKED`, `0x0013 UA_BUSY`
(in-flight/global budget, B.8.5.2 — distinct from the attended `0x0003 BUSY`),
`0x0014 UNSUPPORTED_SUITE`, `0x0015 NOT_YET_ACTIVE` (cooling-off; `next_open_in_s` — also the answer of a rollback-closed grant, with `next_open_in_s = last_seen − now`, B.8.5.3), `0x0016
SUSPENDED` (`Suspended{LocalBlock|Panic|Admin|Local}`; `cause` 1 local · 2 admin, B.8.4.1; no `retry_after_s` — cleared only per B.8.6.3, so
no PAKE runs for a suspended grant). PAKE
failure: `0x0020 AUTH_FAILED` (bad KE3 — the password was *not* proven). Cancellation: `0x002A
PREEMPTED` (a charged `AwaitKe3` stream cancelled by a newer verified `SESSION_REQUEST` from the
same pk, B.8.4.5) — transport-class for the client, never a password failure: the remembered
password is not marked stale (B.8.9). Post-PAKE only
(password proven ⇒ the device is a grantee): `0x0021 OUTSIDE_SCHEDULE` (`next_open_in_s`),
`0x0022 BLOCKED_BY_LOCAL_USER`, `0x0023 HOST_NOT_READY` (`cause`: capture_permission ·
input_permission · locked · other_user_active), `0x0024 ALREADY_CONNECTED` (reserved; v1 replaces
the older session instead, B.8.6.4), `0x0025` (reserved; was SUSPENDED, now pre-PAKE `0x0016`),
`0x0026 SESSION_ACTIVE` (another remote session is live), `0x0027 TRANSPORT_UNAVAILABLE` (grant
requires Tor-only media but the host config forbids it), `0x0028 LOCAL_USER_PRESENT`
(`require_absent`), `0x0029 COOLDOWN` (`retry_after_s`; reconnect cooldown after
`max_session_secs`, B.8.6.4). A client that did
not send `unattended` MUST abort on `session_type = 1`, and vice versa; `detail` is rendered as
untrusted text; `retry_after_s` display is capped at 24 h. Unattended rejects never feed the
§B.3 temp-ban list (the ladder is the control); `ERROR`-class violations do. After a reject the
host closes the stream (and the rendezvous circuit where Arti exposes that for an accepted
stream — `research-verifier`, M1); a new stream costs one RTT and the ladder still governs.

**B.8.4.7 Fallback suite 2 — SPAKE2 per the RFC 9382 construction over ristretto255, over
Argon2id.** Not an RFC ciphersuite (RFC 9382 defines `M`/`N` only for the NIST curves, edwards25519
and edwards448): `M, N = hash-to-ristretto255` of the fixed seeds `"tornect/v1/spake2/M"` /
`"tornect/v1/spake2/N"`, with the Tornect transcript and key schedule below; `research-verifier`
pins the crate and the constants at M1. Compiled only
with feature `pake-fallback`; used only if `research-verifier` rules opaque-ke unusable at M1
(decision recorded in `docs/research/crypto.md`). Enable flow: `salt = rand(16)`, `w =
Scalar::from_bytes_mod_order_wide(Argon2id(pw_nfc, salt, 64 MiB, 3, 1, 64))` (64-byte output
reduced wide, RFC 9382 §3.2 — a 32-byte output reduced mod the order would be biased) stored
wrapped under `K_unatt`. Wire (the suite-2
`Option` fields of B.8.4.1): `SESSION_REQUEST.unattended{suite: 2}` (`ke1` absent) →
`AUTH_CHALLENGE{salt, pB}` → client derives `w`, `pA`, then per RFC 9382 §4 `Ke || Ka =
SHA-512(TT)` (32 B each; `TT` uses the RFC 9382 §3.3 length-prefixed layout with `Context =
context`, `A = client_device_pk`, `B = host_onion_pk`, then `pA`, `pB`, the shared group element
and `w`) and `KcA || KcB = HKDF-SHA256(salt = ∅, ikm = Ka, info = "tornect/v1/spake2/confirm")[0..64]`;
`cA = HMAC-SHA256(KcA, "tornect/v1/unattended/client\0" || th_after(AUTH_CHALLENGE))` →
`AUTH_RESPONSE{pA, cA}` → host verifies `cA` (ct) →
`SESSION_ACCEPT.token_confirm` carries `cB = HMAC-SHA256(KcB, "tornect/v1/unattended/server\0" ||
th_after(AUTH_RESPONSE))` (replacing the B.8.4.3 `confirm_key` MAC for this suite); `Ke` is the
`session_key` ikm of the token HKDF (B.8.4.3). Weaknesses vs suite 1: the host holds a
password-equivalent `w` (a T3b/T4 attacker logs
in without cracking; F1 still required); no `server_s_pk` pin. Kept: no offline oracle for a
phishing host (one online guess per stream), same limiter, timeouts, transcript and token
derivation; `cA` is emitted only after `pB` arrived; `pA`/`pB` are fresh per stream.

#### B.8.5 Rate limiting and lockout (host, per grant)

**B.8.5.1 Consecutive-failure ladder.** The counter is charged (fsynced, write-ahead) after
the signed `SESSION_REQUEST` verifies and *before* `AUTH_CHALLENGE` is written, because KE2 is
itself a one-guess oracle (the client verifies the envelope locally and may vanish). A stream
that dies before KE2 is written is not charged. Precisely: `charge` ⇒ `consecutive += 1`,
`since_unlock += 1`, `pending = true`, arm the lock for the new n, persist (fsync) before KE2;
`settle(ok)` ⇒ first revert this stream's own charge (`consecutive -= 1`, `since_unlock -= 1` —
the successful stream is not a failure), then snapshot `FailSummary { since_success: consecutive,
last_fail_at }` (`None` when `since_success == 0`, else `last_fail_at` is `Some`; it is the return
value, carried in `PolicyReceipt.fail_summary` into `SESSION_ACCEPT.fail_summary` — an owner with
zero prior failures sees no "failed attempts" notice), then `consecutive = 0`, `pending = false`,
`locked_until` cleared, `hard_locked` cleared when this very charge armed it (i.e. after the revert
and reset `consecutive = 0` and `since_unlock < 60` — an owner whose 20th attempt succeeds after 19
Tor hiccups is not hard-locked next time), `last_used` set;
`settle(fail)`, timeout, circuit
loss, `BYE` or cancellation by a newer stream ⇒ `pending = false`, counters kept (the charge
already stands), log/notify; on store load `pending == true` ⇒ treated as settled-fail. Success
is the only reset of the consecutive counter and reverts only its own charge. Decay never clears
`hard_locked`: only a local unlock or `admin unlock(pk)` does — a hard-locked grant stays refused
whatever its counters decay to.

| n (consecutive) | Lock after the n-th challenge | Earliest n-th challenge | n | Lock | Earliest |
|---|---|---|---|---|---|
| 1, 2 | none | 0 | 7 | 5 min | 3 min 40 s |
| 3 | 10 s | 0 | 8 | 15 min | 8 min 40 s |
| 4 | 30 s | 10 s | 9 | 30 min | 23 min 40 s |
| 5 | 1 min | 40 s | ≥ 10 | 60 min each | 53 min 40 s (n = 10) … 9 h 53 min 40 s (n = 19) |
| 6 | 2 min | 1 min 40 s | 20 (`hard_lock_after`) | **hard lock** | 10 h 53 min 40 s |

`hard_lock_after` is per grant (`UnattendedGrant.hard_lock_after`), default 20; *Helping
someone* and *Headless box* use 10; 0 disables the **consecutive** hard lock only (warned); the
lifetime budget below always applies, and between owner logins the ladder alone caps guessing at
24/day in steady state (B.8.2.1). The consecutive counter decays by one per 24 h without
attempts (an owner's Tor hiccups do not accumulate for months). **Lifetime budget:**
`since_unlock` counts settled failures only (a success reverts its own charge, so 60 successful
logins never lock); it is never reset by success, decays by one per 7 days without failures
(bounded extra ≈ 52 guesses/year for a grant that lives for years) and 60 ⇒ hard lock (defeats
reset-on-success farming by a cloned key). Both are count-based. **Decay bookkeeping:**
`FailState.decay_anchor` (consecutive, period 24 h; set to `now` at every charge and every
`settle(fail)`) and `FailState.lifetime_decay_anchor` (`since_unlock`, period 7 d; set to `now` at
every `settle(fail)`) — two anchors, because advancing one anchor by 24 h steps would starve the
7-day decay; each is also advanced (by whole periods: `anchor := anchor + steps × period`, unclamped)
whenever a decay step is applied to its counter, and every `:= now` anchor write is clamped monotone
(`max(stored, now)`, B.8.5.3). On load the `pending` charge is settled first (as fail: anchors `:=
max(stored, now)`, `credit := 0`), then decay is applied — a crash-abandoned attempt restarts both decay
periods, conservative; decay is also applied before each charge. A **load** is a successful
`UnattendedStore` decode by the host — exactly at host start and at the `keystore_locked` → readable
transition of B.8.9 (a keystore lock/unlock cycle is therefore one load, like a restart); the 10-min
readiness re-run never re-decodes a store that is loaded — between loads the in-memory limiter is
authoritative; the offline CLI (B.8.6.2) never applies or persists decay — the only `FailState` write
it performs is the reset of a local *Unlock* (anchors `:= max(stored, now)`, counters 0, `hard_locked`
cleared). **On load** — the only wall-clock evaluation of decay: `steps = (now − anchor) / period`,
subtract `steps` (saturating at 0), advance the anchor by `steps × period`; the lifetime counter
takes **at most one step per load** (`since_unlock −= min(steps, 1)` while its anchor still
advances by the full `steps × period`: the extra steps are forfeited, never deferred, the residual
is preserved and every anchor moves by whole periods only — so a forward jump across a load, T12,
buys at most one lifetime guess per load); an anchor in the future (`now < anchor`) yields `steps = 0`
and keeps the anchor — a saturating rule of the formula, not a second rollback test: the rollback test
is `now < last_seen` alone (B.8.5.3), which subsumes it because `last_seen` is raised to both anchors at
every store write.
**At runtime** the limiter never reads the wall clock for decay: each anchor carries its own (twin,
`credit`) pair — a monotonic twin (`Clock::mono`, B.8.5.3), set at load together with `credit = (now −
anchor) mod period` (the residual carried toward the first runtime step; `credit = 0` after a rollback
at load); before each charge `steps = (credit + twin.elapsed()) / period`, applied in full to both
counters — the `min(steps, 1)` cap is a load-time rule only, because only the wall clock can be forged —
and an applied step advances the persisted anchor by `steps × period`, sets `credit := credit +
twin.elapsed() − steps × period` (the new residual) and resets the twin; whenever an anchor is set to
`now` (charge, `settle(fail)`, the `pending` settlement at load) `credit := 0` and the twin is reset.
Invariant: `credit + twin.elapsed()` ≤ the wall-clock time since the persisted anchor, with equality
whenever no backward step intervened since that anchor was written (after a rollback at load, or a
`:= now` write clamped to a larger stored value, the deficit only defers decay — conservative), so the
runtime step is the load-time formula evaluated on the monotonic clock (without the lifetime cap) and
the on-disk state stays consistent. A
runtime NTP step therefore neither decays a counter nor shortens a lock; a suspend (the monotonic
clock pauses, B.8.5.3) lengthens a running lock and defers runtime decay — conservative, reconciled
at the next load.

**B.8.5.2 Global limits (never a lock, never touch attended sessions):** *in flight* = charged
`AwaitKe3` streams only; `HelloVerified` streams (uncharged) never count toward the per-pk,
host-wide or per-minute unattended budgets and are bounded solely by the §B.3 accept queue and
per-peer limits (A17: 50 bare `HELLO`s from random keys leave a granted device's login unaffected).
≤ 1 in-flight handshake per pk (a newer stream's *verified* `SESSION_REQUEST` cancels the stale
one — a bare `HELLO` never does, B.8.4.5), ≤ 4 in flight
host-wide, ≤ 10 `AUTH_CHALLENGE`/min host-wide; excess ⇒ `UA_BUSY`. A hard-locked grant's pk is
answered at most once per minute (`HARD_LOCKED`, rate-aggregated in the log); further streams
from that pk inside the minute are closed without any frame (no `E_*`, nothing charged). There is no
global breaker: two burned devices must never block a third device's login.

**B.8.5.3 Persistence and clocks.** `FailState` lives in the encrypted store, written before
each response (single writer, `spawn_blocking`; these writes bump only the in-file generation,
never the keychain anchor — B.8.9). **Clocks:** `AttemptLimiter`, the decay twins and the
schedule/`active_from`/`expires_at` checks are generic over a `Clock` trait defined in
`tornect-core::unattended` (`wall() -> u64` unix seconds, `mono() -> Duration`, `Instant`-like;
B.8.14) — production uses the OS clocks (`SystemTime` + `std::time::Instant`; `Instant` does not
advance across a suspend on Linux/macOS, accepted as conservative per B.8.5.1 — a suspend-aware
clock from `tornect-platform` is an M6 option), U1–U7 a scripted `FakeClock` that steps each
independently, and the F3 fuzz loaders take the same trait. In-process timers use `mono()`; on disk
the store keeps `lock_remaining_s` + `flushed_at`; on load `locked_until = now + max(0,
lock_remaining_s − max(0, now − flushed_at))`. **Monotone wall-clock fields:** `last_seen_unix`
is monotone in memory and on disk (`last_seen := max(last_seen, now, decay_anchor,
lifetime_decay_anchor)` at every store write, so `now < last_seen` subsumes an anchor in the future),
and every persisted wall-clock field (`decay_anchor`, `lifetime_decay_anchor`, `flushed_at`) never
decreases: the `:= now` writes (charge, `settle(fail)`, the `pending` settlement at load, `flushed_at`,
`last_seen`) are clamped to `max(stored, now)`; a decay step writes `anchor + steps × period` unclamped
— ≥ stored by construction, and allowed to exceed the wall clock after a backward step, which the load
rule "anchor in the future ⇒ `steps = 0`" (B.8.5.1) already tolerates — so a backward step at runtime
can never be laundered into a forward jump at the next load. **Rollback** — `now < last_seen` — is
checked at every wall-clock evaluation, not only at load: at load, locks are re-armed in full and decay
is skipped; at load *and* at every runtime schedule/`active_from`/`expires_at` check the grant fails
closed until the clock passes `last_seen` — a rollback-closed grant is answered at the `active_from`
gate of B.8.4.5, pre-PAKE and uncharged, with `NOT_YET_ACTIVE{next_open_in_s = last_seen − now}`
(copy in B.8.10); `ClockAnomaly` is logged (rate-aggregated). A forward jump cannot shorten a running lock
(monotonic-clock based); it shortens a persisted lock only across a load (host restart or keystore
recovery, B.8.5.1), which a pre-authentication attacker cannot force (a live Control session, T9,
can); the count-based budgets are touched only through the per-load lifetime-decay cap of B.8.5.1
(≤ 1 step per load) and the 24 h consecutive decay. A missing or undecodable store ⇒ unattended off +
notification (never "counters start at zero").

#### B.8.6 Grants, mutations, presence, sessions

**B.8.6.1 Grant lifecycle.** Precondition: SAS-paired *and* ≥ 1 completed attended session
from that device (waivable with an explicit warning; *Headless box* auto-waives on the command line, and the window's wizard asks the waiver for it too). Presets set
mode, schedule, expiry, block window, `max_session_secs`, `active_from` (12 h cooling-off for
*Helping someone*), `require_tor_only`, `lock_on_disconnect`, `require_absent`. Expiry
default 90 d auto-renewed on successful use for own devices ("never" is an explicit choice
with a warning; on file-keystore hosts expiry is capped at 90 d and "never" is refused — T3b);
7 d for helpers. Expired grants are `NOT_GRANTED`; their `AuthRecord` is
zeroized and pruned 30 d after expiry. **Disabled** grants (`GrantState::Disabled{since, by}`,
set by backup import (`by: Import`, B.8.9), by the machine-id mismatch of a moved state dir
(`by: Restore`, B.8.12) or by a local *Disable* (`by: Ui|Cli` — deny-direction, no re-auth; the
auth record is kept, so re-enabling needs no new password; B.8.7.3/B.8.7.4)) are refused pre-PAKE
with `NOT_GRANTED` (B.8.4.6) and return to `Active` only through *enable* — an access-increasing
mutation (B.8.6.2). Unpairing deletes the grant and the device's
restricted-discovery key in one atomic write; "Remove device" = unpair + revoke; "Revoke
unattended only" keeps the pairing. Every deny-direction change (revoke, revoke-all, disable,
master off, pause, suspend, expiry, schedule end) terminates matching live sessions within 1 s
with the matching `BYE` reason (`REVOKED` — for revoke and disable alike: the client cannot tell
a disabled grant from a revoked one, both are `NOT_GRANTED` · `MASTER_OFF` · `PAUSED` ·
`SUSPENDED` · `EXPIRED` ·
`SCHEDULE_END`, B.8.4.1; `end_session` ⇒ `ADMIN_END`, panic ⇒ `PANIC`, stop code ⇒ `EMERGENCY_STOP`).

**The "answered 0" mark (decision M1-67).** Before the host signs a `SESSION_ACCEPT` whose `grant_reach` is 0, it marks
the grant's current password, in a policy write. A grant is marked unless its current password was generated and has not
yet been answered 0: a grant stored without the mark's key, a grant given a chosen password, and grants loaded by backup
import or a restore are marked (a restore is recognised by the machine id; a store that adopts this machine's id is
marked whole, and a host that cannot read its id recognises no restore). The mark is cleared only when the grant gets a
new password that the owner's wizard or CLI registered as generated (`generated`, §B.8.7.4). While it is set, the grant
gets no session that can reach the administrator level: the clamp uses none as the grant's level, and wherever another
admin grant, the helper task or the account's settings would let Control reach it (§B.8.4.1), the session is View only,
from the next answer on; the receipt minted at the gate already applies it, so no administrator helper is started for a
marked password. A grant that holds the administrator level is enabled while it is marked only once a new generated
password has cleared its mark, whatever disabled it; until then *enable* is refused with `G_NEEDS_PASSWORD`. The host's
address book says "View only until it gets a new password" where a new password restores control, and, on the account
settings that make control administrator access, "View only: this computer's account settings make control administrator
access, so control needs administrator access for <device>". Both lines are on that device's card in the host's list of the devices that can connect here (the address book's Devices tab, M-UI-5). The card also counts that device's admin commands that ran nothing (decision M1-67): its `AdminRequest` lines with `ok` false (a refused command, an unknown one included) and its `end_session` commands logged while it had no session open (no `SessionStarted` of that device without its `SessionEnded`), read from `sessions.log` and its rotated files; nothing new is logged, and a command refused before its grant is read writes no line and is not counted. A command answered `ok` that changed nothing (a repeated suspend, an unlock of a grant that was not locked) is not counted: its line cannot be told from one that acted.

**B.8.6.2 Mutation policy (one enforcement point — `tornect-core::unattended::MutationGuard`,
B.8.14 — in the host process; UI, IPC and CLI all pass through it).**

| Class | Operations | Allowed when | Requires |
|---|---|---|---|
| Deny-direction | master off, pause (12 h / until re-enabled; until 08:00 OPEN until a zone source exists, ruling of 2026-10-09), revoke, revoke-all, Rotate ID (every grant wiped, B.8.12), disable (`Active` → `Disabled{by: Ui\|Cli}`, B.8.6.1), suspend (`Active`\|`Suspended{Admin}` → `Suspended{Local{by: Ui\|Cli}}`; no-op on `LocalBlock`/`Panic`, B.8.6.3), end session, an admin grant's `elevation` → none (M1-67), emergency stop | always — during remote sessions, from tray, CLI, panic key, admin request or stop code | nothing |
| Access-increasing | master on, create grant, enable grant (`Disabled` → `Active`, B.8.6.1), set/change password, unlock, resume (clears any `Suspended{…}`, B.8.6.3), extend expiry, widen schedule, mode → Control, an admin grant's `elevation` → administrator (r7, Windows only — elsewhere `G_UNSUPPORTED`, B.8.7.1; also UAC for the helper task, B.8.7.5) — either, when it raises the grant's own `grant_reach` (B.8.4.1), only together with a new generated password for that grant in the same operation (`RegFinish` with `generated`; `set_options` refuses it with `G_NEEDS_PASSWORD`); creating a grant with that reach only with a generated password; enabling a marked grant that holds the administrator level, whatever disabled it, only after a new generated password cleared its mark (*enable* refuses it before with `G_NEEDS_PASSWORD`, B.8.6.1; M1-67), lower block window, disable "Ask before starting", identity-key view/backup (S8 *Identity* of `docs/UI_PLAN.md` — the onion identity key leaves the keystore only behind re-auth), change notification/panic-key/keep-awake/autostart settings (autostart via `tornect service install\|uninstall` = `IpcOp::ServiceInstall\|ServiceUninstall`, B.8.7.4), backup import, backup export (it writes `K_master` + `ServerSetup` + every auth record, B.8.9; `BackupExported{by, path}` logged, banner raised), `tornect install\|uninstall` (r7, §B.1.1; also UAC) | no remote session active for ≥ 60 s | **OS re-authentication** (B.8.8 table) in a fresh dialog per operation (a two-message IPC registration is one operation: re-auth at `RegStart`, `reg_txn` at `RegFinish`, B.8.7.4) |
| Remote admin (B.8.4.1) | from a *My machines* Control grant: revoke(pk), revoke_all, master_off, suspend(pk), end_session, unlock(pk) — the only remote path that clears a lockout; from any other grant: end_session (own session) and revoke (own pk) only | after F1 + F2 from a grant in `Active` state (`Suspended`/hard-locked grants cannot; `NOT_YET_ACTIVE` still applies); schedule, readiness, transport, busy and concurrency gates are skipped, so it works even while another session is live | the requester's own two factors; out-of-scope ops ⇒ `ADMIN_RESULT{ok: false}`; logged with the requester's device; unlock resets `FailState` and clears `Suspended{Admin}`, never `Suspended{LocalBlock\|Panic\|Local}` |

The CLI never edits files while the host runs: it talks to the host over the local IPC
endpoint (B.8.7.4) and runs the OPAQUE client role itself for registration, so the password
never crosses IPC; with no host running it takes the store lock and runs the same `MutationGuard`
+ `ReAuth` code (B.8.14) — the only offline path, under identical rules.
Consent popups (PAIR/SESSION) are **not presented while a remote session is active** (answered
with the attended `BUSY` `0x0003` — not the pre-PAKE `UA_BUSY` `0x0013` of B.8.4.6 — owner notified
afterwards, `popup_suppressed_remote_session` logged). An in-app banner
"N devices can connect without asking — last change <when> by <ui|cli|import>" stays until
acknowledged with re-auth after any grant creation, widening or backup export.

**Store-less host (decision M1-46; operator ruling 2026-09-22).** A host that started without its
unattended store (another command held the store lock) holds `state/host.lock`, serves no
unattended session, and its control channel answers `tornect panic` only, refusing every other
operation with the reason; no CLI command runs the guard offline beside it, and an offline command
already running when it starts refuses its write (decision M1-49). Such a host must be stopped
(Ctrl-C or panic) before deny-direction commands run: `tornect panic` ends every session it serves,
and Ctrl-C in its terminal ends the host, after which the command runs offline or through a host
restarted with its store. This is an exception to "always" in the deny-direction row above. A host
with no control channel at all (every Windows host until the M6 named pipe, or one whose socket
failed to bind) blocks the same commands, and Ctrl-C in its terminal is then its only kill path
(M1-46).

**B.8.6.3 Block window and presence.** A Tornect-owned always-on-top window (best-effort on
Wayland: focused window + `notify-rust` action + chime) with exactly one control, **Block**, no
close/dismiss, re-asserted every 500 ms, on every captured monitor, lasting exactly
`block_window_s` whether or not anyone is present (no presence oracle). A request whose block window could not be shown is refused: when no block window drew its first frame (on Linux, nor was its notification shown) before its seconds ended, the window host refuses with `HOST_NOT_READY` without a `cause`, logs `HostNotReady`, and leaves the grant as it was; the terminal host, whose block line could not be written or whose terminal closed, refuses as a Block does. Block ⇒
`BLOCKED_BY_LOCAL_USER` and grant `Suspended{LocalBlock}` until a local *Resume* (re-auth; a
remote `unlock` never clears it) — no whack-a-mole. Clearing rules: `Suspended{Admin}` (set by a
remote `suspend(pk)`) is cleared by a local *Resume* (re-auth) or by a remote `unlock(pk)` from a
*My machines* Control grant; `Suspended{LocalBlock|Panic|Local}` only by a local *Resume*. A local
*Suspend* (manager button, `tornect unattended suspend`, `IpcOp::Suspend` — deny-direction, no
re-auth) sets `Suspended{Local{by: Ui|Cli}}` and, like a Block, is never cleared remotely. Precedence:
the local reasons (`LocalBlock` · `Panic` · `Local`) outrank `Admin` — a remote `suspend(pk)` against an
already suspended grant changes nothing (`ADMIN_RESULT{ok: true}`, `AdminRequest` logged, state
untouched); a local *Suspend* on `Suspended{Admin}` replaces the reason with `Local{by}` (the grant can
then no longer be resumed remotely) and is a no-op on `LocalBlock`/`Panic`; *Disable* is allowed from any
`Suspended` state (deny-direction) and a later *Enable* (re-auth, B.8.6.1) returns the grant to `Active`.
A suspended grant is refused pre-PAKE (`SUSPENDED`, B.8.4.6). Presence detection (physical input only —
Tornect subtracts its own injections: `LLKHF_INJECTED`, macOS event-source PID, Wayland injection
timestamps ± 250 ms) drives only the "While you were away" card and the optional
`require_absent` reject; unknown ⇒ present. "Ask before starting" (default on for *Helping
someone*) layers the Allow/Deny popup (60 s ⇒ `DENIED`) on top of the PAKE: host state
`AwaitLocalAllow` between F2 and the block window (B.8.4.5); the client does not learn
`ask_before_start` (nor `block_window_s`) before the signed `SESSION_ACCEPT` and waits the fixed
110 s maximum (B.8.4.5). For an admin grant (r7) that popup reads "<name> wants to connect as administrator" and keeps
Deny / Allow only: the level comes from the grant (B.8.7.1). The terminal host shows no such popup: a grant with "Ask before starting" is refused there with `DENIED`.

**B.8.6.4 Sessions.** One remote session per host at a time in v1 (`SESSION_ACTIVE`
post-F2; admin requests exempt); one live session per grant: a post-F2 success from a pk that
already has a live session ends the older one (`BYE{REPLACED}`) and starts the new one, with
"already connected from this device" shown on the host and both clients — the cheapest clone
detector, without locking the owner out after a client crash or link loss.
Sessions end at schedule-window end and at expiry (`SessionEndingSoon{in_s, reason}` on
`ctrl` at −2 min, then `BYE`), at `max_session_secs` (then a 10 min reconnect cooldown for
*Helping someone*: post-F2 `REJECT{COOLDOWN, retry_after_s}`), on revoke/off/pause, on host lock (`BYE{HOST_LOCKED}`), on panic.
**View-only** = video (+ audio, off by default for helpers); `input`, `clip` (both
directions) and `file` streams are refused at the QUIC layer; `ctrl` accepts only
bitrate/IDR/cursor-shape; the mode is signed into `SESSION_ACCEPT` and enforced host-side from
the `PolicyReceipt`. **Transport policy** (signed): `tor_only` ⇒ neither side sends
`CANDIDATES`, host sends `TOR_FALLBACK` immediately (the relative never learns the owner's
IP); `lan_only` ⇒ link-local candidates only, no Tor media fallback, failure ⇒
`BYE{NO_LAN_PATH}`; signaling always traverses Tor in v1.

#### B.8.7 Host-side UX

**B.8.7.1 Enable flow** (Settings → Unattended access → *Turn on for a device…*; local,
re-auth first): ① explanation + scam step ("Did someone call and ask you to set this up? Hang
up.") + this OS's limits (B.8.8) + what is kept and who learns what (M-UI-5): "This computer keeps, for each device you give access: when it last connected, how and for how long, its failed attempts, and log lines of its attempts (repeated refusals are summed into one line). That device keeps a line for each time it connected here, and may remember the password, never for administrator access." "Before it gives the password, that device can learn whether its access here is locked, suspended or not yet active, and how long it must wait after this computer's clock went back. With the password, it can also learn whether someone is signed in or using this computer, whether another remote session is running, and when its next allowed time starts." "It learns how long you have to stop a connection, and whether you are asked first, only when a connection is accepted." "A device with control under My machines can unlock another device's access here by its ID, and so learns whether that ID has access." "The log keeps the name you give that device here: use a description of the device, such as "Office laptop", not a person's name." "If it remembers the password, anyone who can use that device can connect here as it until you revoke it."; ② pick a paired device with ≥ 1 attended session; ③ preset;
④ password: generator pre-filled (5 EFF-long-list words, ≈ 65 bits, shown once, not copyable),
"use my own" secondary with the live meter and the B.8.2.2 offline estimate; "use my own" is absent when the grant's
`grant_reach` is or becomes 1 or 2 (B.8.4.1; M1-67), and a chosen password never clears the "answered 0" mark (B.8.6.1);
registration runs
in-process; ⑤ options: mode, schedule (OPEN until a zone source exists, ruling of 2026-10-09; when built: host-local weekly windows; wrap past midnight; DST gap ⇒
inside if either side is, overlap ⇒ first occurrence; TZ snapshot, warned on change), expiry,
block window, `hard_lock_after` (0 = consecutive hard lock off — warned: guessing is then bounded
only by the lifetime budget — ≤ 60 failures per local unlock plus ≈ 52/year of decay at most (B.8.5.1), at ≤ 24/day in
steady state, ≈ 33 on the first day — and the notifications, B.8.2.1), "Ask before starting", `require_absent`, `require_tor_only`,
keep-awake (host-wide, B.8.7.5),
lock-on-disconnect (refused with *Headless box*; warned on Windows/GNOME), "Prevent idle lock
while unattended access is on" (default off; whether `ES_DISPLAY_REQUIRED` overrides an
`InactivityTimeoutSecs` policy lock is NEEDS-DEVICE(windows) — the copy claims only what the
readiness probe confirms);
⑤a (r7; Windows only; planned, M-FEAT-5 and M-UI-5) **Administrator access** — "let <device> also use programs that
run as administrator when it connects without asking": off in every preset; *Helping someone* refuses it; *My
machines* and *Headless box* may turn it on (the block window and "Ask before starting" stay the owner's choice; the
step shows the grant's block window). Its warning (the operator accepted the residual with it, decision M1-62): "An
unattended administrator session can change anything on this computer, including Tornect's own settings and its log.
While this is on, any device with control of this computer can reach programs that run as administrator, not only
<device>." Authority: the guard's re-auth (the user's own password, M1-53) **and** an administrator account (M1-53's
`--elevated` check: `TokenElevationType`, linked token, `CheckTokenMembership`) **and** UAC to register the
administrator helper task (B.8.7.5) — two dialogs, one guard operation, logged `GrantCreated|Changed{elevation}`; a
standard account cannot create an admin grant; admin grants exist only in the installed mode (§B.1.1). On Linux the
step is absent (the guard answers `G_UNSUPPORTED`) and the wizard says: "On Linux, Tornect runs as you. An unattended
session can do what you can do without a password; when the system asks for a password, they see that window and can
type into it." Linux setup keeps `auth_self`;
**Administrator access and passwords (decision M1-67).** A new grant with the administrator level, under ④: "An
up-to-date Tornect on <device> does not keep this password; type it in the Tornect window there each time." Raising a
grant to the level: ⑤a's warning, then "Administrator access needs a new password for <device>. The current password stops working when you
finish, also where it is remembered.", then the line above; buttons **Cancel** (first) · **Continue**. Mode → Control
where Control reaches programs that run as administrator (§B.8.4.1): "Control here can reach programs that run as
administrator, so <device> needs a new password. The current password stops working when you finish, also where it is
remembered." Enabling a marked grant at the level (an imported or restored one): "Administrator access for <device>
needs a new password after a restore or an import. The old one stops working when you finish." When a change makes the
other Control grants reach the level (an admin grant created, raised, imported or enabled, or the helper task
registered), the step lists them by pinned label under "These devices have control of this computer: <labels>. From now
on their control can reach programs that run as administrator here.", with "Give them new passwords now" ticked;
unticked, it names only the devices whose password is marked (§B.8.6.1): "<labels> get view only until you give each one
a new password: their current passwords may be kept on those devices, were chosen, or are older than this version of
Tornect." Turning the level off: "Administrator access is off for <device>. A session of <device> running as
administrator ends now."; when <device> has control and another admin grant exists or the helper task stays registered, add: "<device> keeps
control of this computer. While <another device has administrator access | the administrator helper is still registered:
Tornect removes it the next time you sign in here>, control can still reach programs that run as administrator. To stop
that now, disable <device>." Each new password is its own registration, and Windows asks for the password once
per device. If one prompt is cancelled, the step lists again the devices that still have their old password. Linux:
unchanged.
⑥ **Readiness**: capture + input permissions/restore tokens, autostart, auto-login state (never
configured by Tornect; the pre-boot disk-unlock trade-off stated), keystore persistent and
unlockable at autostart (canary entry), empty OS account password (detected — red:
"re-authentication cannot protect settings on this account") plus the static advisory "Tornect
cannot judge the strength of your OS password; unattended access is only as safe as it" (Tornect
can detect only the empty case), idle-lock policy (`InactivityTimeoutSecs` /
`askForPassword` / `lock-enabled`) + current lock state, console ownership, Tor self-connect,
panic key bound, tray, administrator helper registered (r7, Windows, while an admin grant exists), indicator shown (r7, §B.1.1); red rows need "Enable anyway — it will not work until fixed"; ⑦ summary +
stop-code card. Readiness re-runs at host start and every 10 min (macOS 15+ periodic
screen-recording re-consent, Wayland token loss) ⇒ sticky in-app badge + `HOST_NOT_READY`.

**B.8.7.2 Password policy (normative).** UTF-8, NFC-normalized on both sides
(`unicode-normalization`), never trimmed (warn on leading/trailing whitespace); 12–128 chars;
runs of whitespace/hyphens between passphrase words normalized to one space on both sides;
`zxcvbn` score ≥ 3 with `user_inputs` = {host name, device labels, onion address, OS user
name, "tornect"}, **≥ 4 when the host keystore is file-based** (where expiry is also capped at
90 d and "never" refused, B.8.6.1); distinct passwords per host
recommended in copy. Change = new registration for that grant (re-auth). While the grant's `grant_reach` is 1 or 2 the
new password is generated, never chosen; a password the host's session accept answered with 0, or a chosen one, stays
marked until a generated one replaces it (§B.8.6.1, M1-67). All intermediates in
`Zeroizing`; UI password fields cleared incl. undo state (egui widgets, D10); no clipboard copy of password fields.

**B.8.7.3 Manager, notifications, indicator.** Main-screen badge "N devices can connect
without asking". Per grant: pinned label (never the HELLO name; NFKC, bidi/control characters
stripped, ≤ 64 chars, duplicates get a numeric suffix given at pin time, e.g. "Laptop (2)" — r7, §B.6.1), device words (r7: the one short form; the 16-hex fingerprint leaves this surface, §B.6.1), created-by, last used,
state (Active / Not yet active / Disabled{by} / Suspended{reason} / Locked{until} / Hard-locked / Expired),
`failures_since_unlock`, *Unlock* (re-auth), *Change password*, *Suspend* (`Active`|`Suspended{Admin}` →
`Suspended{Local{by: Ui}}`, deny-direction, no re-auth; no-op on `LocalBlock`/`Panic`, B.8.6.3) and *Resume* (re-auth; clears any
`Suspended{…}`, B.8.6.3), *Disable* (`Active` →
`Disabled{by: Ui}`, no re-auth; the matching *Enable* needs re-auth, B.8.6.1), *Revoke unattended*, *Remove
device*; header: master toggle, *Pause*, *Revoke all*. Notifications are in-app windows
mirrored to OS toasts (never toasts alone — DND/Focus hide them; GNOME has no tray without an
extension): session starting (with Block), session ended, every failure from the second onward, lock/hard lock
(sticky; *Unlock* routes through the manager + re-auth), not-ready, "While you were away: …"
on the first physical input after an unacknowledged session. Indicator: OS-enforced indicators
where they exist (macOS SCK, GNOME/KDE screencast icon) plus the §B.6 pill "**Unattended** ·
Laptop-of-Ana · Control · [End]", re-asserted every 500 ms, un-closable, on every captured monitor. For an
administrator session (r7) the pill, the banner and the client HUD read "control · administrator" (M1-50's row order
kept).

**B.8.7.4 Panic key, CLI, IPC, emergency stop.** Panic (`security.panic_key`, default
Ctrl+Alt+End) ends any session and, if it was unattended, suspends that grant; pressed **twice
within 2 s** ⇒ master off (persisted) + toast (hold-to-disable is NEEDS-DEVICE where key-up is
unavailable). Detection uses physical events only (Windows low-level hook filtering
`LLKHF_INJECTED`; macOS `CGEventTap` with source-PID filter; Wayland GlobalShortcuts portal bound
in the wizard, readiness row "Panic key: bound / unavailable"); the indicator's End button, the
tray item and `tornect panic` always work; rebinding needs re-auth. **CLI:** `tornect unattended
status|on|off|pause|grant <device> [--preset …] [--waive-attended-check] [--administrator]|enable <device>|disable <device>|revoke <device>|--all|unlock <device>|suspend
<device>|resume <device>|set-password
<device> [--administrator]|set-level <device> none|readiness|log`, `tornect service install|uninstall|status`, `tornect install|uninstall` (r7, §B.1.1), `tornect input-helper` (r7; internal — started only by the host, B.8.7.5), `tornect install-entry` (internal — run elevated only by `tornect install` on Windows, as the installed copy; it takes no argument and writes only Tornect's uninstall entry, §B.1.1), `tornect remove-at-restart` (internal — run elevated only by `tornect uninstall` on Windows, as the installed copy; it takes no argument, removes any other file in its folder and marks that copy and its folder for removal at the next restart, §B.1.1),
`tornect panic`, `tornect
backup export|import` (`--waive-attended-check` maps to `GrantOptions.waive_attended_precondition`,
warned and logged; `backup export` is access-increasing, B.8.6.2; `disable` is deny-direction,
`IpcOp::Disable`; `set-level <device> none` is deny-direction, `IpcOp::SetLevelNone`; `suspend` is deny-direction, `IpcOp::Suspend` (→ `Suspended{Local{by: Cli}}`, B.8.6.3);
`resume` is access-increasing, `IpcOp::Resume` (re-auth, B.8.6.2); `service install|uninstall` = `IpcOp::ServiceInstall|ServiceUninstall` through
the guard — an autostart change is access-increasing, B.8.6.2, and with no host running the CLI
runs the guard offline like any other mutation); passwords via TTY prompt, never argv.

`grant --administrator` creates an admin grant, and `set-password --administrator` raises one. Each is a single guard
operation with a generated password printed once; nothing raises the level, or turns a grant to Control where Control
reaches it, without a new password. `grant --administrator` first prints ⑤a's warning (§B.8.7.1), as the wizard's
Administrator step shows it (M-UI-5); that step and the command line are the two ways to create an admin grant (the operator's ruling
of 2026-10-02); `set-password --administrator` prints the same warning before it raises a grant (the same ruling).
When such a change makes other Control grants reach the level, the command prints
the heading of the ⑤a offer (§B.8.7.1) and the devices, then asks "Give them new passwords now? [Y/n]" and runs one
*Change password* per device. This is a new default-yes question on every platform: Enter is yes; end of input, a read
error or an input that is not a terminal is no, and the mark applies (§B.8.6.1). The built yes/no question, which
defaults to no, keeps its current uses. A generated password is printed on standard output only when it is a terminal;
otherwise the command refuses before `RegStart`, so nothing is registered. The line after it says: "Write it down now:
Tornect does not show it again and keeps no copy." `set-level none` lowers the level (deny-direction) and prints the
turn-off sentence, with its condition; on a grant without the level (on Linux, every grant) it changes nothing, logs and writes nothing, and answers "no administrator access; unchanged". Refusals of the `--administrator` forms: "Administrator access does not exist on Linux: Tornect runs as you.",
"Administrator access needs Tornect installed on this computer.", "Only an administrator account can give administrator
access.", "A grant for helping someone cannot include administrator access." (M1-67)

**IPC:** `<state_dir>/ipc.sock`
(0600, `SO_PEERCRED` check) / `\\.\pipe\tornect-ctl-<32 hex digits>`, a name drawn from 128 random bits at each host start and written, once the pipe exists, into `<state_dir>\ipc.pipe`, a file only this account can read, from which the command line takes it (the name is never computed from the path, so another account can neither predict it nor create it first; a missing or malformed file means no host; a name file left by a host that did not stop cleanly is trusted only for a pipe of this account) (owner-only DACL,
`PIPE_REJECT_REMOTE_CLIENTS`; each end checks the other's account, the SID of the process at the other end read from its PID, which keeps out other accounts but not a program already running as this account, which can pose as the host to the command line, or hide the host from it by removing the name file (T9); r7: an explicit DACL, never the default descriptor, and exactly one first instance, `FILE_FLAG_FIRST_PIPE_INSTANCE`; up to 17 instances (16 connections served at once and one waiting for the next), so that a deny-direction command such as `tornect panic` never waits behind an open re-authentication dialog, and as the DACL admits only this account, only a program running as this account can add one — M-FEAT-5 builds the Windows pipe), owned by `tornect-platform::ipc`; the
host holds an advisory store lock, and `state/host.lock` for its whole life (decision M1-46: one
host per home; a host that started without its store answers `tornect panic` only, B.8.6.2).
**Emergency stop code:** 16 random bytes shown once at enable
time (printable card); the host stores only `stop_token = SHA-256("tornect/v1/stop\0" ||
host_onion_pk || stop_code)` (its own pk, computed at enable time), never the code. Any peer
presenting the same token in `HELLO.stop_token` (the client computes it with the pk of the
address it dialed; constant-time compare) triggers master off + revoke-all + session kill +
`emergency_stop`; the code is single-use — rotated on use and on every re-enable (`EmergencyStop`
logged; the new card is shown after re-auth). The phishing case is covered by the pk binding: a
code presented to a phishing host (or a mistyped/scam onion) yields a token bound to *that*
host's pk, useless at the real host; misuse is at worst a DoS by a code holder.

**IPC messages** (M1 deliverable; the types and their CBOR codec live in
`tornect-core::unattended::ipc`, no I/O — fuzz target F4 exercises that codec; the socket / pipe
endpoint is `tornect-platform::ipc`'s and the dispatch loop `apps/tornect`'s, B.8.14 *Ownership*).
Framing = §B.3 (u32-BE length + CBOR, max
frame 64 KiB). The peer identity from `SO_PEERCRED` / the pipe client SID must equal the host's
uid, else the connection is dropped before any frame is read.
```
IpcRequest  { id: u64, op: IpcOp }
IpcResponse { id: u64, ok: bool, code: u16 /* 0 = ok; else an E_* code of B.8.4.1 or a mutation-guard code G_* (0x01xx, below) */, detail: Option<tstr>, payload: Option<bytes> /* CBOR, per op below; ≤ 60 KiB */ }
IpcOp = Status | On | Off | Pause { until: u64 } | Revoke { device: DeviceId } | RevokeAll | Unlock { device }
      | Suspend { device } /* Active|Suspended{Admin} → Suspended{Local{by: Cli}} (by: Ui when the manager calls the guard directly; no-op on LocalBlock/Panic, B.8.6.3); deny-direction: no re-auth, a live session of that grant gets BYE{SUSPENDED}; UnattendedSuspended{reason: Local, by} logged (B.8.6.3) */
      | Resume { device } /* clears any Suspended{…}; access-increasing: re-auth, no remote session ≥ 60 s (B.8.6.2); UnattendedResumed{by} logged */
      | Enable { device } /* Disabled → Active; access-increasing (B.8.6.2) */
      | Disable { device } /* Active → Disabled{by: Ui|Cli}; deny-direction: no re-auth, a live session of that grant gets BYE{REVOKED}; GrantDisabled{by} logged (B.8.6.1) */
      | SetLevelNone { device } /* tornect unattended set-level <device> none: GrantOptions.elevation → None, no other field sent (B.8.7.1); deny-direction: no re-auth, allowed during a remote session (B.8.6.2); a live session of that device at the administrator level ends (B.8.6.2), a session below the level goes on; GrantChanged logged; a grant without the level is left unchanged; every ok answer carries the condition of the turn-off sentence (B.8.7.1 ⑤a) as its payload, below */
      | ServiceInstall { elevated: bool /* at `3aa1072` the Windows whole-host elevated task (M1-53); r7: replaced by the administrator helper task, registered with the first admin grant and removed with the last (B.8.7.5) */ } | ServiceUninstall /* tornect service install|uninstall: an autostart change is access-increasing (B.8.6.2) — re-auth, no remote session ≥ 60 s; no store write; AutostartChanged{by} logged */
      | Show /* r7 (§B.1.1): raise the running window only — never answers, dismisses or re-orders a sheet; re-arms any sheet */
      | Readiness | Log { filter: tstr, after: Option<u64> } | Panic | BackupExport { path: tstr } /* access-increasing: re-auth, no remote session ≥ 60 s, BackupExported logged */ | BackupImport { path: tstr }
      | PolicyInputs                                                          → payload = { user_inputs: [tstr], min_score: u8 }   /* B.8.7.2 inputs; the CLI runs zxcvbn locally and refuses weak passwords itself */
      | RegStart  { device, reg_request: bytes[32], raise: bool, generated: bool }                          → payload = { reg_response: bytes[64], reg_txn: bytes[16] }   /* a CBOR map like every payload; re-auth happens here (a raising RegStart — one that creates a grant whose grant_reach is not 0, or raises one — asks with its own wording naming administrator access (the window's inline re-authentication uses the same raising wording); raise and generated are kept with the txn, and a RegFinish that does not match them is refused with G_NEEDS_PASSWORD; M1-67); txn single-use, ≤ 120 s, bound to device */
      | RegFinish { device, reg_txn: bytes[16], upload: bytes[192], preset: u8, options: GrantOptions, generated: bool }   /* grant (no grant yet) / set-password (grant exists): the CLI runs ClientRegistration itself; `generated`: the password came from the passphrase generator, never set for a chosen one — the only way the host learns it, since the password never crosses IPC (M1-67); re-checks RemoteSessionActivity before applying (below) */
payload per op: Status → StatusReport { enabled: bool, paused_until: Option<u64>, grants: [GrantSummary /* id, device, label, preset, mode, state, expires_at, last_used, failures_since_unlock */],
                                        readiness: ReadinessSnapshot, keystore_kind: u8 /* 0 os_keychain · 1 file */ }
                Readiness → ReadinessSnapshot (B.8.14) · Log → { lines: [tstr], next: Option<u64> } /* paged: ≤ 60 KiB per response, `next` is the cursor for the following Log{after} */ · SetLevelNone → { keeps: u8 /* 0 nothing · 1 another admin grant exists · 2 the administrator helper task stays registered */ }
                every other op → payload absent
GrantOptions = { label, mode, schedule, expires_at, auto_renew, max_session_secs, block_window_s, ask_before_start, require_absent,
                 require_tor_only, lock_on_disconnect, hard_lock_after, waive_attended_precondition: bool,
                 elevation /* r7: None | Admin — Windows only, access-increasing to set (B.8.7.1) */ }   /* the policy subset of UnattendedGrant (B.8.9); also the argument type of MutationGuard::create_grant / set_options (B.8.14) */
G_* codes: 0x0100 G_REAUTH_FAILED · 0x0101 G_REMOTE_SESSION_ACTIVE · 0x0102 G_PRECONDITION · 0x0103 (reserved; was G_WEAK_PASSWORD — the host never sees the password, the CLI enforces B.8.7.2 via PolicyInputs)
           · 0x0104 G_KEYSTORE_LOCKED · 0x0105 G_STORE_LOCKED · 0x0106 G_NO_TXN (RegFinish without a live reg_txn)
           · 0x0107 G_UNSUPPORTED (r7: an operation this platform cannot honour, e.g. an admin grant on Linux; the detail says why) · 0x0108 G_NEEDS_PASSWORD (M1-67: a creation or change that gives a grant its own `grant_reach` without a new generated password, a RegFinish that does not match its RegStart, or the enable of a marked admin grant whose mark no generated password has cleared)
```
The host performs the OS re-auth dialog itself on every access-increasing op (the CLI never
receives or forwards a credential) and routes every op through the B.8.6.2 mutation guard;
unknown op ⇒ `code = E_UNKNOWN_KIND`; the password never crosses IPC (only OPAQUE registration
messages do), so the B.8.7.2 policy is enforced by the CLI itself: it fetches `PolicyInputs`
(`user_inputs`, `min_score` — 4 on a file-keystore host) and runs `zxcvbn` locally before
`RegStart`. A registration is one re-auth: `RegStart` runs the dialog and returns a single-use
`reg_txn` (≤ 120 s, bound to `device`) that `RegFinish` must present — without a live txn it is
refused and logged (`GrantMutationRefused`, `G_NO_TXN`), so an un-gated `RegStart` never becomes
an OPRF-evaluation oracle for that credential id. Because up to 120 s may pass between the two
messages and an unattended session can start meanwhile, `RegFinish` re-evaluates
`RemoteSessionActivity` before applying the upload: `session_live()` or a session ended < 60 s ago
⇒ `G_REMOTE_SESSION_ACTIVE`, the txn consumed and `GrantMutationRefused` logged. `RegFinish` for a device that already has a
grant is *set-password*: it replaces the auth record and may not widen `options` except through the guard (widening is
access-increasing), except the widening that B.8.6.2 allows only together with a new generated password, which rides in
set-password's `options` and is applied in the same write (M1-67); for a device without a grant it is *grant*.
`BackupExport` is access-increasing (B.8.6.2): refused while a remote session is live or ended
< 60 s ago, `BackupExported{by, path}` logged, in-app banner raised.

**B.8.7.5 Autostart, sleep, wake.** `tornect service install` (through the guard: re-auth,
`AutostartChanged{by}` logged, B.8.7.4) registers a user-level
autostart (Task Scheduler "At log on"; `SMAppService` / LaunchAgent; `systemd --user` `tornect-host.service` with
`WantedBy=graphical-session.target` or XDG autostart / Background portal for Flatpak). All start *after* login;
readiness states the auto-login dependency. r7 (§B.1.1, decision M1-58): the autostart will start the app
(`tornect --background`), not the headless host — on Linux through an XDG autostart entry; `service install` removes an existing `tornect-host.service` before it writes that entry.

**The elevated task.** Built at `3aa1072` (M1-53): `service install --elevated` registers the whole host at
`HighestAvailable` — strictly opt-in, refused to a standard account, not startable on demand (F1-5) — with the wizard
copy "Running the host elevated makes every remote Control session an administrator session" (T9). **r7 replaces it
with the administrator helper** (decision M1-57, the operator's ruling of 2026-09-27; M-FEAT-3): nothing network-facing
runs elevated any more, and the elevated code shrinks to one input loop.

**The administrator helper (planned, M-FEAT-3).** `tornect input-helper` is the only elevated component. Attended: the
host starts it through `ShellExecuteEx` after *Allow as administrator…* (UAC, §B.2.1). Unattended: a task `\Tornect
admin helper` (a per-user name) — principal = this user, `HighestAvailable`, **no trigger**, `AllowStartOnDemand`
**true** (reversing F1-5 for this task only) — which the host starts (`IRegisteredTask::Run`) only when an admin-level
unattended session has passed F1, F2 and the block window. If the helper is not connected within 5 s the session starts
at `elevation = 0`, stays at 0, and both sides say "administrator access unavailable at <host>".
- **Task lifetime (MUST):** registered with the first admin grant and deleted with the last (through UAC when needed,
  F1-1's elevated delete), disabled while the master switch is off, never present while no active admin grant exists;
  readiness shows "administrator helper registered".
- **Registration (MUST):** the executable's absolute path from `FOLDERID_ProgramFiles` — never `%ProgramFiles%` or any
  `%` variable (the Task Scheduler expands `%VAR%` in the command field and there is no escape for it; the built
  `task_command` refuses `%`, F1-4); read back and compared after registration (principal SID, run level, command,
  arguments, exactly one action — M1-53 (9), F1-2); the install folder and the executable carry no write, delete or
  owner-change entry for a non-administrator principal, checked at registration and before each `Run`, and a failed
  check refuses and logs; its own guard operation with "administrator" in the dialog (F1-3 carried).
- **DLL loading (MUST):** every elevated component loads DLLs from System32 and its own folder only (the dependent-load
  decision of M1-51 becomes mandatory here).
- **Migration (MUST):** at upgrade and at `service uninstall`, an existing whole-host elevated task (M1-53) is found and
  removed through UAC (F1-1's path). The built `--elevated` stays until the helper passes its Windows test, is removed
  before the tag, and the two never ship together.
- **Channel (MUST):** the host creates the pipe with an explicit DACL (the user's SID, plus Administrators for the
  standard-account path; never the default descriptor), `nMaxInstances` 1 with `FILE_FLAG_FIRST_PIPE_INSTANCE` (a failed
  creation means "administrator access unavailable", never "use the pipe that exists"), `PIPE_REJECT_REMOTE_CLIENTS`,
  and an unguessable per-session name (≥ 128 random bits) handed to the helper on its command line (attended) or through
  the task's run parameters (unattended; the `IRegisteredTask::Run` detail is UNVERIFIED). The host accepts exactly one
  client and checks it (attended: the PID `ShellExecuteEx` returned; unattended: the registered Program Files image, an
  elevated token, the host's session id); the helper checks the server (attended: the PID it was given; both: the
  Program Files image, the same session). Frames are the fixed 16-byte input events, `ReleaseAll`, `Stop` and
  `Heartbeat`; any other byte sequence ends the helper. It has no launch, file, clipboard, registry or window operation
  and no network, reads no config and no environment-derived path, and initialises no Tor, codec or UI.
- **Lifetime and panic (MUST):** the helper exits — after `ReleaseAll` — on pipe close, on host exit (it waits on the
  host's process handle), on `Stop`, on a missed heartbeat (≤ 2 s) and at a hard cap (the session maximum, or 12 h). It
  watches for the physical panic chord itself (injected events ignored; it matches only the chord and keeps no
  keystroke) and on it sends `ReleaseAll`, stops injecting, tells the host and exits — whether the host's
  medium-integrity low-level hook sees physical keys while an elevated window has focus is UNVERIFIED. Master off and
  the stop code end the session through the host, which closes the pipe. A test on the operator's Windows PC with an
  elevated window focused covers the panic key, Stop and `tornect panic`, in an attended administrator session and in
  an admin-grant session (NEEDS-DEVICE(windows)).
- **Residual:** whatever lets the host start the on-demand task lets every program of that user start it, and a PID or
  image check tells which binary sits at the other end of the pipe, not who drives it; so the checks keep out other
  users and foreign binaries, not same-user code. T9 (§B.8.2) states the consequence; the operator accepted it with the
  wizard warning (decision M1-62). It is still narrower than the built whole-host task: no pre-authentication network
  parsing runs elevated and no configuration steers the elevated code.

**M-FEAT-3 MUST** (any one failing fails the milestone's security check): H1 the helper accepts nothing beyond the fixed
input frames, `ReleaseAll`, `Stop` and `Heartbeat`; H2 it reads no config, environment-derived path or user-writable
file, and loads no DLL from outside System32 and its own folder; H3 it never survives host exit, pipe close, `Stop`,
panic or a missed heartbeat, and never attaches to a session midway; H4 the pipe never uses the default security
descriptor, more than one instance or a predictable name; H5 every elevation level is signed in `SESSION_ACCEPT` and
shown by the host's indicator and banner; H6 the helper task is never registered with an environment-variable path,
outside Program Files or without the read-back; H7 the helper task is never registered while no active admin grant
exists; H8 view-only never carries `elevation` ≠ 0.

**Sleep and wake.** Keep-awake (host-wide, default on: active while any grant is `Active`;
presets may only turn it on, never off): `SetThreadExecutionState(ES_CONTINUOUS |
ES_SYSTEM_REQUIRED)`, `IOPMAssertionCreateWithName(kIOPMAssertionTypePreventUserIdleSystemSleep)`
(does not survive lid close), Inhibit portal `Suspend` (logind `Inhibit("sleep")` fallback). On
resume (`PBT_APMRESUMEAUTOMATIC` / `NSWorkspace.didWakeNotification` / logind
`PrepareForSleep(false)`) the host checks `OnionServiceStatus` and, if not reachable within 60 s,
drops and re-launches the `RunningOnionService`. The limiter is not reconciled on resume: the
monotonic clock did not advance during the suspend, so running locks are lengthened and runtime
decay deferred — conservative, reconciled at the next load (B.8.5.1, B.8.5.3). Lock-on-disconnect (default off) fires only on
session teardown (BYE, panic, QUIC close after the reconnect window), never on transient circuit
loss. Client copy: "Couldn't reach "<host>": it may be off or offline, or Tor may be slow. The password was not tried." when the host does not answer, and that "<host>" is offline, asleep or locked when it refuses as not ready (Tornect cannot wake or unlock it).

#### B.8.8 Platform realities (v1 honesty table; every claim not sourced is NEEDS-DEVICE)

| OS / state | Capture | Input | Remote unlock | Source / status |
|---|---|---|---|---|
| Windows, session unlocked | WGC ✅ | SendInput ✅ (UIPI: not into elevated windows or UAC prompts, and the failure is silent — verified in the SendInput documentation; at `3aa1072` a host started from the whole-host elevated task of M1-53 makes every remote Control session an administrator session, which r7 replaces with the per-session administrator helper, §B.2.1, B.8.7.5; the secure-desktop switch is detected via `OpenInputDesktop` once a second during a Control session (M-FEAT-3): the host's window, its terminal and its log say "The computer is showing a secure Windows screen; the person there must answer it", and the viewer will say the same from bit 0x04 of the host's `PONG` `notice` (§B.8.4.1), within one ping, about 10 s (M-UI-4, planned)) | n/a | — |
| Windows, locked (Winlogon secure desktop) / logged out | ❌ | ❌ | **No** — needs a SYSTEM service + secure-desktop agent (roadmap M-SVC-W, after the release; Ctrl+Alt+Del also needs the SendSAS policy) | `WTSRegisterSessionNotification` ⇒ `HOST_NOT_READY{locked}` / `BYE{HOST_LOCKED}` |
| GNOME ≥ 45, unlocked, RemoteDesktop restore token valid (one combined session, §B.5) | PipeWire ✅ | libei ✅ | n/a | `wayland.md` §2.4–§2.5; the token checked by readiness; portal `Start` budget 5 s then `Request.Close()` so no dialog blocks an empty room |
| GNOME, locked | ❌ (mutter inhibits remote access: sessions closed, `CreateSession` refused) | ❌ | **No** by design | `wayland.md` §7 (sourced); backends treat `Closed` as recoverable *Locked* |
| KDE Plasma 6 | portal ✅ | ConnectToEIS ✅ | NEEDS-DEVICE(kde) | lock policy and RemoteDesktop token persistence unverified |
| wlroots/Hyprland | ScreenCast only | no RemoteDesktop portal | — | out of v1 (view-only at best) |
| GDM/SDDM login screen | no session | — | No | — |
| macOS 13+, unlocked | SCK ✅ (TCC bound to the signing identity; macOS 15+ periodic re-consent ⇒ readiness self-test) | CGEvent ✅ (Accessibility) | n/a | signed + notarized builds required for persistent grants |
| macOS, locked / screensaver / login window / FileVault pre-boot | lock UI at best | unreliable (Secure Input) | NEEDS-DEVICE(macos); pre-boot never | lock mechanism NEEDS-DEVICE (`CGSession -suspend` is a user switch, `SACLockScreenImmediate` is private) |

| Capability | Windows | macOS | Linux (GNOME / KDE) |
|---|---|---|---|
| OS re-authentication (only as strong as the OS credential — readiness detects an empty account password and shows the static strength advisory, B.8.7.1 ⑥) | `CredUIPromptForWindowsCredentials` with `CREDUIWIN_SECURE_PROMPT` (secure desktop) + `LogonUser`, or Windows Hello (`KeyCredentialManager`) | `LAContext.evaluatePolicy(.deviceOwnerAuthentication)` | polkit actions `org.tornect.{grant,enable,autostart,export,settings}` (`auth_self`; text agent over SSH). **No separate PAM backend**: polkit runs the PAM conversation itself, out of process, in its setuid `polkit-agent-helper-1`, so a direct PAM path would duplicate it and would need `libpam` headers and root or setuid to be useful (verified 2026-09-04 against polkitd 127). One action per operation class, not per operation, because an unprivileged caller may not pass a `details` map to `CheckAuthorization` — polkit refuses the whole call — so the operation name cannot reach the dialog as data. A host with no policy file installed gets `Unavailable`, never `Denied`. Headless with no agent at all: §B.8.17 item 5 |
| Physical-input presence | `GetLastInputInfo` minus injected (`LLKHF_INJECTED`) | `CGEventSourceSecondsSinceLastEventType(HIDSystemState)` minus own events | `org.gnome.Mutter.IdleMonitor.GetIdletime` / `org.freedesktop.ScreenSaver.GetSessionIdleTime` (KDE); `ext-idle-notify-v1` behind `linux-wayland-idle`; logind `IdleHint` last resort |
| Lock state / lock / console owner | `WTS_SESSION_LOCK` / `LockWorkStation()` / `WTSGetActiveConsoleSessionId` | `CGSessionCopyCurrentDictionary` (undocumented) / NEEDS-DEVICE | logind `Session.LockedHint` / `login1.Session.Lock` on `session/auto` (`org.gnome.ScreenSaver`, `org.freedesktop.ScreenSaver.Lock` fallbacks) / logind `Active` |
| Prevent idle lock (opt-in) | `ES_DISPLAY_REQUIRED` | `PreventUserIdleDisplaySleep` | Inhibit portal `Idle` |
| Administrator level (r7, §B.2.1) | per-session elevation through the administrator helper (installed mode only; M-FEAT-3); the secure desktop stays out of reach | — | none: the host never runs as root; polkit's remembered approvals revoked at every Control session start (`pkcheck --revoke-temp` semantics — the man page read on the build VM; the D-Bus method name UNVERIFIED; the process context under XDG autostart NEEDS-DEVICE(gnome, kde)); never described as enforcement |
| Always-on-top block/indicator | ✅ re-asserted (exclusive fullscreen may cover it — tray + chime) | ✅ | no topmost API for clients on Wayland: compositor screencast icon + focused window + chime |

**Service mode (roadmap):** Windows — M-SVC-W, after the initial release (decision M1-61; Part C): a SYSTEM service
+ a per-session process + secure-desktop handling (SendSAS) for lock/login-screen control; macOS LaunchDaemon +
login-window agent and a Linux system-session daemon (gnome-remote-desktop "system" mode) stay unplanned. Out of v1;
the wizard says so in one line.

#### B.8.9 Storage (`tornect-core`)

`K_master[32]` is a `SecretStore` entry `unattended-master.key`: OS keychain via `keyring-core`
+ per-OS stores (`ui.md` §5.9; never `keyring::Entry`) when the readiness canary proves it
persistent and unlockable at autostart, else the existing `FileSecretStore` (0600) with the
"weaker keystore" badge; the host never blocks on a keyring prompt (a host that never enabled
unattended has no `K_master` and nothing to read): `K_master` unreadable at
start or at the 10-min readiness re-run ⇒ readiness state `keystore_locked` ⇒ unattended off
(pre-PAKE `NOT_GRANTED`) + the sticky badge, re-checked every 10 min; the re-run only probes
readability — a store already loaded is never re-decoded (the loaded limiter stays authoritative), and
the `keystore_locked` → readable transition is the one recovery load (B.8.5.1). `K_unatt = HKDF-SHA256(ikm
= K_master, salt = "tornect/v1/keystore", info = "unattended-store", 32)`. Anti-rollback anchor:
the keystore entry `unattended-master.key` holds `K_master[32] || u64be store_generation`. Store
writes fall into exactly two classes. **(a) Runtime-state writes** — `FailState` (charge/settle,
decay, `pending` settlement at load), `last_used`, an auto-renewed `expires_at`, `log_chain_head`
and `last_seen_unix` — bump only the in-file generation under the AEAD tag, never the anchor, so a
handshake never implies a keychain write. **(b) Policy writes** — every access-increasing *and*
every deny-direction mutation of B.8.6.2 (create/enable/disable/change/revoke/revoke-all/prune a
grant, every `state` change incl. `Suspended`/`Disabled`, `enabled`, `paused_until`, `stop_token`,
`server_setup`, host-wide settings, tombstones), whether performed by the `MutationGuard`, a remote
admin request, the panic key, the stop code or the machine-id check below — bump the in-file
generation **and** the keychain anchor. A policy write records its generation as `pending_anchor`
inside the file (same atomic write, so the owed bump survives a crash), then raises the anchor to
it; when the keychain is unwritable at that moment (locked collection; a remote admin request or
panic at night) the bump stays owed and is applied — `anchor := max(anchor, pending_anchor)` — at
the next start or mutation where the keychain is writable. File `state/unattended.bin` (0600, atomic temp +
fsync + rename): `"TNUA" || u8 fmt || u64be generation || nonce[24] || XChaCha20-Poly1305(K_unatt,
nonce, CBOR(UnattendedStore), aad = header)`. Write order: store file, then anchor. Load: an owed
bump found in the file is applied first (when writable); then a file generation ≥ anchor is
accepted; an older generation than the anchor, an anchor
without a file, a newer `schema_version`, a bad tag or a missing key ⇒ **fail closed**
(unattended off + notification), never a silent reset. After a successful load `machine_id_hash`
(`SHA-256("tornect/v1/machine-id\0" || id)`, `id` = `/etc/machine-id` · `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
· `IOPlatformUUID`) is compared with this machine's: a mismatch ⇒ every grant `Disabled{by:
Restore}`, the field rewritten in that policy write, and a notification (a moved state dir —
reinstall or migration; hygiene, not a security control, B.8.12); an unavailable id (`None`, e.g.
some containers) skips the check. Consequence: a store older than the last policy write — a
revocation, disable, suspension, master off or emergency stop included — fails closed, so
"tombstones survive restores" is enforced by the anchor, not by the file (which carries the
tombstones and can be rolled back together with them); a state-dir writer without `K_master` can
roll back **runtime state only** (a restored file at or above the anchor differs from the latest
one solely in class-(a) fields), which is accepted and bounded by the ladder. Honest limit: while a
bump is still owed (`pending_anchor > anchor`) a rollback to the pre-mutation file goes undetected;
the window closes at the next start or mutation with a writable keychain — on an OS keychain
normally at the write itself. Bootstrap: `K_master`, the store and `ServerSetup` are
created lazily at the first unattended enable, inside the re-auth flow where the keychain is
interactive — never at host start, so a fresh install triggers no keyring prompt; they persist
across off/on cycles and are wiped only by *Rotate ID*. No anchor *and* no file is the
attended-only state (log lines carry `tag = null`, B.8.13); at that first enable ⇒ create both
(generation 1 — the first policy write: `pending_anchor = 1`, `machine_id_hash` set, `ServerSetup`
generated). Honest limit: `K_master`
must be readable without user presence for autostart to work, so any process running as the OS
user — including a hostile Control session (T9) — can read it, rewrite the store and re-tag the
log; the AEAD store, the anchor and the log chain protect against parties *without* `K_master`
(T3a, backups, other users). macOS Keychain code-signing ACLs partially mitigate. Backlog (next
to TPM sealing): split the store into runtime state (`FailState`, generation) under `K_unatt`
and a policy blob signed by a user-presence-gated key (Windows Hello `KeyCredentialManager` /
Secure Enclave `.userPresence` / TPM) so that policy changes need presence even for the OS user
— v1 where a platform makes it cheap, otherwise the existing "weaker keystore" badge. Windows
state stays under `%LOCALAPPDATA%` (`Paths::state_dir`); keychain entries use
`CRED_PERSIST_LOCAL_MACHINE`.

```rust
pub struct UnattendedStore {                       // everything policy-relevant is here; config.toml has no [unattended] table
    pub schema_version: u16,                       // 1
    pub enabled: bool, pub paused_until: Option<u64>,
    pub server_setup: Zeroizing<Vec<u8>>,          // opaque-ke ServerSetup::serialize() (128 B); created at the first unattended enable, kept across off/on
    pub stop_token: Option<[u8; 32]>,              // SHA-256("tornect/v1/stop\0" || host_onion_pk || stop_code), B.8.7.4 — never the code
    pub default_hard_lock_after: u32 /* wizard default, 20 */, pub keep_awake: bool /* host-wide, B.8.7.5 */, pub prevent_idle_lock: bool, pub notify: bool,
    pub grants: Vec<UnattendedGrant>, pub tombstones: Vec<(DeviceId, u64)>,   // revocations survive imports (merged); against a restored file the anchor rule, not this list, is the guarantee (B.8.9)
    pub log_chain_head: [u8; 32], pub last_seen_unix: u64,   // monotone: max(stored, now) at every write (B.8.5.3)
    pub pending_anchor: u64,                       // generation of the last policy write; the keychain anchor is raised to it at that write or, if the keychain was unwritable then, at the next start/mutation (B.8.9)
    pub machine_id_hash: Option<[u8; 32]>,         // SHA-256("tornect/v1/machine-id\0" || OS machine id); mismatch at load ⇒ every grant Disabled{by: Restore} (B.8.12); None = id unavailable, check skipped
}
pub struct UnattendedGrant {
    pub id: GrantId,                               // [u8; 8], random at creation; hex in logs (distinct from `device`)
    pub device: DeviceId,                          // must exist in trusted-devices.toml; unpair cascades
    pub label: String, pub created_by: Actor /* Ui | Cli | Import — never Restore: a restore only disables (state.by), B.8.12 */, pub created_at: u64, pub active_from: u64,
    pub preset: Preset /* MyMachines | HeadlessBox | HelpingSomeone */,   // decides the admin scope (B.8.4.1)
    pub suite: u8, pub auth: AuthRecord,           // Opaque { record: Vec<u8> /* 192 B */ } | Spake2 { salt: [u8;16], wrapped_w: Vec<u8> }
    pub mode: SessionMode, pub schedule: Option<Vec<Window /* { days: u8 bitmask, start_min: u16, end_min: u16, tz: String } */>>,
    pub elevation: Elevation,                      // r7: None | Admin — Windows only (Linux: G_UNSUPPORTED), default None; setting Admin is access-increasing and replaces `auth` in the same write (B.8.7.1, M1-67); store key 24; key 25: `unmarked`, set only by the write that registers a password sent as generated (`RegFinish`'s `generated`, §B.8.7.4) and cleared by the "answered 0" mark (§B.8.6.1), absent = marked; schema version unchanged: a build without them reads none and marked, and its rewrite drops both
    pub expires_at: Option<u64>, pub auto_renew: bool, pub max_session_secs: Option<u32>, pub reconnect_cooldown_s: u32,
    pub block_window_s: u8, pub ask_before_start: bool, pub require_absent: bool, pub require_tor_only: bool, pub lock_on_disconnect: bool,
    pub hard_lock_after: u32,                      // 20; 10 for Helping someone / Headless box; 0 = no consecutive hard lock (warned; the lifetime budget still applies)
    pub state: GrantState /* Active | Suspended { reason: LocalBlock | Panic | Admin | Local { by: Actor /* Ui | Cli: a local Suspend, B.8.6.3 */ }, since: u64 } | Disabled { since: u64, by: Actor /* Import (backup import) | Restore (machine-id mismatch at load, B.8.12) | Ui | Cli (local Disable, B.8.6.1) */ } */,   // Expired / NotYetActive derived; Disabled ⇒ pre-PAKE NOT_GRANTED, leaves only via `enable` (B.8.6.1); clearing rules B.8.6.3
    pub last_used: Option<LastUsed /* { at, transport: TransportKind, duration_secs } */>,
    pub fail: FailState /* { consecutive: u32, since_unlock: u32, pending: bool /* charged, not yet settled */, last_fail_at: Option<u64>, lock_remaining_s: u32, flushed_at: u64, hard_locked: bool,
                            decay_anchor: u64 /* consecutive, 24 h */, lifetime_decay_anchor: u64 /* since_unlock, 7 d */ /* B.8.5.1 decay bookkeeping; anchors and flushed_at never decrease — `:= now` writes clamped to max(stored, now), decay advances by whole periods, B.8.5.3 */ } */,
}
```
Client side (`hosts.toml` at `Paths::hosts_file()`, M1, + keychain): per host
`{ remember, stale, reach, administrator, control, server_s_pk_pin, suite: Option<u8>, ua_worked_before }`
(`server_s_pk_pin` is set at the first `SESSION_ACCEPT` and checked in `ClientLogin::finish` on every later login,
B.8.4.2/A16; `suite` records the build-time suite of B.8.4.2 at the first successful `SESSION_ACCEPT` — a later mismatch
is surfaced, never negotiated, B.8.10; `ua_worked_before` ≡ `suite.is_some()`; `stale`: the remembered password was
refused and deleted, which the prompt says until the next success; `reach`: the last signed unattended answer of this
host did not say `grant_reach = 0`, or did not say it, or was refused, and `administrator`: that answer said 2 (B.8.4.1,
decision M1-67) — both are set and cleared at each such answer, and they only draw the prompt, never deciding what is
kept (§B.8.9.1); `control`: the last signed accept was Control, so the host card offers the admin commands that need
it); the remembered password lives only in an OS keychain entry named `tornect/u/<32 hex>` — the first 16 bytes of
SHA-256(`"tornect/v1/cred"` ‖ this device's public key ‖ the host's onion public key) in lower-case hex, computed at
use, never read from a file, carrying no address, name or label (§B.8.9.1) — (no keychain Tornect uses asks the person
before a read; copy: "any program running as you can read it" on Windows and Linux), marked stale on `AUTH_FAILED` or on
this side's own check of the host's PAKE reply (KE2) — never on `PREEMPTED`, a transport error, or a refused
`SESSION_ACCEPT` or `ADMIN_RESULT`, which deletes without marking stale (B.8.4.6, B.8.9.1). **Rotate ID** wipes grants,
`ServerSetup`, tombstones, restricted-discovery keys and the stop code after a dialog naming the
N grants. `tornect backup export|import` (M8): Argon2id (64 MiB, t=3) + XChaCha20-Poly1305,
versioned header, generated passphrase, includes `K_master`; export is an access-increasing
mutation (OS re-auth, no remote session for ≥ 60 s, `BackupExported{by, path}` logged, banner —
B.8.6.2); import loads every grant
**disabled** (`GrantState::Disabled{by: Import}`, re-enabled one by one with re-auth) and merges
tombstones. Memory hygiene: `Zeroizing` decode buffers, `mlock`/
`VirtualLock` for `K_master`/`ServerSetup`, crash-dump filter excludes store buffers, hibernation
inhibit requested (best effort — the OS may ignore it on low battery; `K_master`/`ServerSetup`
are mlocked and zeroized on sleep where the OS allows).

**B.8.9.1 Address book and saved credentials (r7; milestones M-UI-2, M-FEAT-4).** Tornect has **no account**: the
"local account" is an address book on this computer, never synced, never sent (§A.1; no cloud accounts, no presence
dots). Files, all 0600 under `Paths::state_dir`, written atomically:
- `known-hosts.toml` — **the pin store**, built (`KnownHosts`: label, `host_device_pk`, `paired_at`, `last_seen`;
  decision M1-12), written by pairing, Forget and the handshake's `last_seen`;
- `hosts.toml` — the unattended per-host record (above);
- `address-book.toml` (M-UI-2) — per saved computer: the saved name (a local rename, never sent) bound to the key it was
  given against, notes, the device-words cache and when it was added and seen; an entry without a pin is a *saved
  address*, shown "not paired yet". Its `later` table is an **allowlist** — a `remembered` flag, the words cache,
  display preferences — never a password, stop code, backup passphrase, token, PAKE message or key; unknown keys are
  kept for forward compatibility but never interpreted;
- `recent.toml` (M-UI-2) — the recent connections, with the level of each (r7), written only while history is on (off by default, the operator's ruling of 2026-09-28);
  Clear deletes it.

**Saved credentials** (M-FEAT-4; decision M1-67): a remembered unattended password lives only in an OS keychain through
`keyring-core`, never in the file keystore, a TOML file or an export. **Windows:** Credential Manager, a generic
credential whose target is the entry name, with no user name or comment, stored with local-machine persistence, which a
roaming profile does not carry to other computers (whether a Windows backup or sync feature copies it is not verified:
NEEDS-DEVICE); it stays across sign-out and restart until it is deleted, and any program running as the user can read
it, as can an administrator of the computer, or anyone holding the user's Windows sign-in secrets and a copy of the
disk. **Linux:** the kernel keyrings (keyutils), used only where the kernel gives the user a persistent keyring (without
one, the prompt says the computer has no usable keychain). The key is linked into the user's persistent keyring and
stays until a restart, or until that keyring expires — by default about three days after it was last opened; every use
of Tornect on the account renews it, also without reading this password, and so does any other program of the account
that opens that keyring; a timer or service of the account that runs after sign-out keeps it — and while the sign-in
that last used it stays open. Any program running as the user, in any session (a terminal, SSH, a timer), can read it,
and so can root. The Secret Service is not built. The prompt names the stores "Windows Credential Manager" and "the
kernel keyring of your account", and on Linux adds: "It stays on this account until a restart, or for a few days after you sign
out." The entry name (B.8.9) is derived at use, **never read from a file**:
a name read from a file that any program of the user can edit could point one host's entry at another host's password.
Without a usable keychain the box is absent and the prompt says "This computer has no system keychain Tornect can use,
so the password cannot be remembered." Stale as in B.8.9. **Administrator access (DA-14, F4-1):** the client keeps a
password only after a verified unattended `SESSION_ACCEPT`, on the same stream, that says `grant_reach = 0` (B.8.4.1);
an `ADMIN_RESULT` never leads to a kept password, because the host marks a password only before it signs an accept
(§B.8.6.1). An answer that says 1 or 2, that leaves the key out, or that the client refuses deletes the remembered
password, at every unattended `SESSION_ACCEPT` and every `ADMIN_RESULT`, before QUIC, whatever was asked; the deletion
comes first and does not wait on `hosts.toml`. Before it writes an entry, the client deletes any entry under the same
name. No keychain Tornect uses asks the person before a read, so no client keeps a password that Tornect would let reach
the administrator level; a presence-gated store would need a plan change first (§B.8.17 item 5). The host never lets a
password its `SESSION_ACCEPT` answered with 0 reach that level (§B.8.6.1). `grant_reach` does not describe what the
host's account can do without a password: on Linux, `sudo` or polkit without a password; on a Windows administrator
account, paths where UAC is not a boundary (T9). A remembered Control password keeps that reach. `hosts.toml`'s `reach`
and `administrator` flags only draw the prompt, and tell anyone who can read the state directory which hosts last said,
or did not say, that this device's access reaches administrator access (T1, T3a). **What deletes an entry:** Forget (the
derived entry is deleted before `hosts.toml` is read, so an unreadable file does not stop it; then the host's record);
*Revoke this device* answered `ok`; a refused password; an answer that says 1 or 2, leaves the key out or is refused; a
failed `hosts.toml` save right after the entry was written (the entry is deleted again); Rotate ID (the derived entry of
every host in `hosts.toml` and `known-hosts.toml`, whatever its flags). On Linux a deletion reaches the key in the
persistent keyring and in this sign-in; a copy that another open sign-in still holds after its persistent keyring
expired stays until that sign-in ends. If the keychain refuses the delete, Forget says so ("The password remembered for
<host> could not be deleted from <keychain>; Rotate ID deletes it later.") and keeps the host's record
with `remember` set, so the check when the prompt opens, or Rotate ID, deletes it. **What Forget
leaves:** the client's `sessions.log` lines of past unattended connections to that host (B.8.10, B.8.13): the log of
your unattended connections is always kept and never sent. Tests: a known password saved through Remember appears in no
file under the state directory (M-FEAT-4). New, for the fix round or M-FEAT-5 (F4-5, F4-L2): Rotate ID deletes an entry
whose flag was lost; Forget deletes the entry while `hosts.toml` cannot be read; an answer of 1 deletes the entry while
`hosts.toml` cannot be read; on Linux, a write in a second sign-in followed by a delete leaves no readable key in either
sign-in. Presence gating is not built; the keyutils lifetime is documented kernel behaviour, not tested (D13). Every save of `hosts.toml` holds an OS file lock beside it, so the window and a command line never save over each other; the lock orders the saves, not the answers: of two answers settled at the same moment, the older one settled last still wins, bounded by the host's mark on a password it answered 0 for (§B.8.6.1).

**Trust rules:** the pinned key is the identity; a saved name or alias only on a full-key match; device words are
recognition only (§B.6.1); an alias is never shown where the pinned label is the trust anchor on a consent sheet;
import never creates a pin.

**History off** means no `recent.toml` writes **and no `last_seen` updates**. At `3aa1072` two writers keep
`last_seen` whatever the user chose: `KnownHosts::touch` writes it into `known-hosts.toml` at every completed handshake
(`crates/tornect-core/src/trusted.rs`, called from `tornect-signal`'s pairing code), and the host's
`TrustedDeviceStore::touch` writes it into `trusted-devices.toml` on every signed `SESSION_REQUEST`; the history switch
must stop both (M-UI-2). Not history, and never switched off: `sessions.log` records connection attempts in both directions — on the host every pairing and session request, attended and unattended (the §B.6 audit), on the client every unattended connect and admin command of this device (`UnattendedConnect`, B.8.10, B.8.13). The first-run line, the Recent tab's Off text, Forget and the Privacy page name it: the log of your unattended connections, always kept, never sent (the operator's ruling on F4-M1); where they say what is recorded, they say: "connection attempts to this computer, and the unattended connections and admin commands of this device, are always recorded in the session log; the history switch governs only the address book's recent list."

**Export/import** (`tornect book export|import`, beside B.8.12): names, addresses, notes and the pinned host keys as
*expected* keys; never passwords, never this device's identity key; encrypted like the B.8.9 backup (Argon2id +
XChaCha20-Poly1305, generated passphrase), because the list says whom you connect to. Export needs no re-auth (it
reveals no secret, and same-user code can read the TOML files anyway) but is refused while a remote session is live or
ended < 60 s ago, like `BackupExport`. Import never creates a pin: the new computer pairs with each host (the host pins
device keys), and an expected key that differs at pairing raises the pin-change warning.

#### B.8.10 Client-side UX

Host card: **Connect** (unattended) is primary after the first success (`ua_worked_before`),
**Knock** (attended) otherwise. Password prompt (masked, reveal toggle, "View only this time",
"Remember on this device" off by default with the two-part risk copy) runs *before* dialing;
one PAKE attempt per explicit user action, never auto-retried after a transport error (copy
separates "couldn't reach the host" from "wrong password"); the suite is the build-time constant
of B.8.4.2 (never taken from `HELLO_ACK.feats` when suite 1 is compiled in), and a suite mismatch /
`UNSUPPORTED_SUITE` is shown, never retried with another suite; remaining guesses and
`retry_after` shown before submitting. Progress: reaching host → checking password (Argon2id,
off-thread) → "someone at *Host* can still block (or must allow)" (generic, no countdown — the
grant's block window and ask policy are disclosed only in the signed `SESSION_ACCEPT`, B.8.4.5) →
finding a direct path →
streaming. Every reject
code of B.8.4.6 has plain copy, e.g. "locked until the owner unlocks it at *Host* — or from
another of your devices", "suspended at *Host* until the owner resumes it there" (`SUSPENDED`;
for an admin suspension also "— or from another of your devices"), "outside allowed hours (next
Mon 09:00 host time)", "*Host*'s clock was set back — try again in N" (`NOT_YET_ACTIVE` from a
rollback, B.8.5.3), "*Host* is
offline, asleep or locked", and on a `server_s_pk` pin change "*Host*'s unattended setup was
re-created since you last connected — if that wasn't you, revoke devices there" (blocks until
confirmed). HUD badge "Unattended · Control/View"; `fail_summary` surfaces as "3 failed attempts
since your last login"; a client-side `sessions.log` records every unattended connect. Admin
actions (*Revoke this device*, *Turn unattended off at host*, *Unlock my other laptop*, *End the
session at host*) live in the host card and use `intent = admin`; the cross-grant ones (*Unlock…*,
*Turn off…*, revoking *another* device) are offered only for *My machines* Control grants
(B.8.4.1 scope) — every other grant sees *Revoke this device* and *End the session* only. r7: the HUD shows the
signed level ("Control · administrator", §B.2.1); "Remember on this device" is absent without a usable keychain and for
a host whose last signed answer did not say `grant_reach = 0`; in that second case the prompt says "A password that can
reach administrator access on <host>, or that <host> did not rule out, is never remembered." Elsewhere it is shown with
"If <host> lets your access use administrator access through Tornect, the password is not remembered.", and a tick is
honoured only if this stream's signed `SESSION_ACCEPT` says `grant_reach = 0`; an admin command never keeps a password
(B.8.9.1, M1-67). After the answer, the window says: at 2, "The password was not remembered: <host> lets your access use
administrator access through Tornect."; at 1, "The password was not remembered: <host> says your access there can reach
administrator access through Tornect, or could not rule it out."; when a remembered password is deleted at 1 or 2, "The
password remembered for <host> was deleted: <host> now says your access there can reach administrator access through
Tornect, or could not rule it out.", followed by "Type it each time." only when the signed mode was Control; without the
key, "<host> runs an older Tornect that does not say what your access can reach there, so the password is not
remembered." (when one was remembered: "…so the password remembered for it was deleted."); at a refused answer, "<host>
sent an answer this device could not check; the password remembered for it was deleted."; when the delete fails, "The
password remembered for <host> could not be deleted from <keychain>. Tornect tries again when you next connect; Forget
<host> also deletes it." When Control was asked and the signed answer gives View only with `grant_reach` not 0, the
window says "<host> gave this session view only. Its owner can bring control back, for example by giving this device a
new password." "Ask for administrator access" is offered only for a host whose last answer said 2 for a Control grant,
so never before a first answer; the connect field runs the look-alike check (§B.6.1); the
client's `sessions.log` line carries `elevation`.

#### B.8.11 Privacy modes and restricted discovery

| Combo | Behaviour |
|---|---|
| Unattended + Paranoid / per-grant `require_tor_only` | `transport_policy = tor_only`: no candidates either way, media over the Tor tunnel (720p30 cap); the other party never learns your IP. |
| Unattended + LAN-only | `lan_only`: link-local candidates only, no Tor media fallback; remote clients get `BYE{NO_LAN_PATH}` post-auth. |
| Unattended + restricted discovery (optional, power-user; `tor.restricted_discovery`) | The client generates its x25519 client-auth keypair (Arti keymgr) and sends the public key in `PAIR_REQUEST.client_auth_pk`; the host stores it with the pairing and rebuilds the descriptor on revoke. Pairing a new device needs local **Pairing mode** (re-auth; unrestricted descriptor for 10 min; logged). Caveats shown in-app: ≤ 160 clients, removal not guaranteed until descriptor rotation (~3 h), arti-client feature still `__is_experimental` (pinned; Part E). |

"Stealth unattended" (one-click recommendation card, not a preset default) = restricted discovery
+ onion PoW + grants + optional Paranoid; honest claim: unauthorized peers cannot *fetch* the descriptor.

#### B.8.12 Recovery flows

| Situation | Flow |
|---|---|
| Forgot password | Local only (re-auth): *Change password* on that grant = new registration; no remote reset exists. Clients with a stale keychain entry see "wrong password" and re-enter. |
| Lost/stolen client device | Host: *Remove device* (unpair + revoke + client-auth key + tombstone). Away: `admin revoke(pk)` / `master_off` from another *My machines* Control device (any other grant can only revoke itself), or the emergency stop code from any device (the wizard recommends a second granted device or the code card for single-device owners). |
| Locked out legitimately | Wait the ladder; local *Unlock* (re-auth); or `admin unlock(pk)` from another *My machines* Control device (resets `FailState` and clears an admin suspension — a Block/panic/local suspension needs a local *Resume*). |
| Host reinstall / migration / state-dir restore / older store generation | Detection is the `machine_id_hash` of B.8.9 (`/etc/machine-id` · `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` · `IOPlatformUUID`): a mismatch at load — the state dir was moved to another machine, or the OS was reinstalled and regenerated its id — ⇒ every grant **disabled** (`GrantState::Disabled{by: Restore}`) + notification, re-enabled one by one (*enable*, re-auth, B.8.6.2); a hygiene measure, not a security control (a `K_master` holder rewrites the field, T4/T9). A same-machine snapshot restore is byte-indistinguishable from a normal start and is governed by the anchor rule alone: a store older than the last policy write (a rolled-back generation), a missing `K_master` or an anchor without a store file ⇒ fail closed + notification "unattended store was replaced — re-enable to continue"; a store at or above the anchor loads as-is (runtime-state rollback only, B.8.9). Grants are recreated locally. |
| Rotate ID | Everything unattended wiped (B.8.9) by the guard's rotate operation (deny-direction: no re-authentication), which logs `HostIdRotated`; the window asks first for the typed word ROTATE in a dialog that names the grants it wipes, and `tornect rotate-id --yes` runs the same operation; the command line refuses while a host holds the unattended store, and the window closes after the rotation, so the new ID is served from the next start (M-UI-5); re-pair, re-enable. |

#### B.8.13 Logging / audit (`sessions.log`, JSON Lines, 0600, `Paths::sessions_log()`)

Extends the shipped `SessionRecord`/`SessionEvent` (`tornect-core::session_log`: `unattended:
bool`, `mode`, `transport`, `peer_device` as base32 `DeviceId`; `peer_name` = the **pinned
pairing label**). Shipped (`tornect-core::session_log`): `UnattendedLockout` → renamed
`UnattendedHardLock`; `UnattendedAuthFailed`/`UnattendedAuthSucceeded` kept as the
per-attempt post-PAKE lines. New
`SessionEvent` variants: `UnattendedRejected` (the pre-PAKE reject line, rate-aggregated: one line
per reason per device per 60 s with `count`), `UnattendedChallengeIssued`,
`UnattendedUnlock`, `UnattendedSuspended{reason: LocalBlock|Panic|Admin|Local, by?: Actor /* Local only */}`, `UnattendedResumed`,
`UnattendedBlockedByLocalUser`, `GrantCreated|Changed|Enabled|Disabled|Revoked|Expired|Pruned`
(`GrantDisabled{by}` is the per-grant *Disable* of B.8.6.1; master off stays `UnattendedDisabled`),
`AutostartChanged` (`by`, B.8.7.4), `Installed` and `Uninstalled` (`by`, §B.1.1), `PanicDisconnect` (the panic key's suspend of a grant, B.8.7.4),
`UnattendedEnabled|Disabled|Paused`, `PasswordSet`, `AdminRequest` (written for every `ADMIN_RESULT`, an unknown command included: `op` `unknown`; M1-67), `EmergencyStop`, `BackupExported`,
`PopupSuppressedRemoteSession`, `GrantMutationRefused`, `StoreLoadFailed`, `ClockAnomaly`,
`HostNotReady`, `SessionEndingSoon`, (r7, M-FEAT-3) `AdminHelperStarted|Stopped|Failed` (`reason`; `Failed`: the helper could not be started or attached, so the session got no administrator access), and (r7, M-FEAT-4, client side) `UnattendedConnect` (one line per unattended connect or admin command of this device: the host's pinned device and label, the outcome as `reason`, and for a session its id, mode and `elevation`, for a command `op` and `ok`). New optional fields: `elevation` (r7; written only at the administrator level, so a line at none keeps its old bytes), `grant`, `by: Actor`, `reason`,
`failures`, `lock_secs`, `count`, `block: elapsed|blocked|skipped`, `ended_by`,
`during_remote_session`, `prev` (SHA-256 of the previous line; for the first line of a new file
the SHA-256 of the last line of the rotated file), `tag = HMAC-SHA256(K_log, line_without_tag)`
with `K_log = HKDF-SHA256(ikm = K_master, salt = "tornect/v1/keystore", info = "log", 32)`; lines
written while no `K_master` exists (attended-only installs) carry `prev` and `tag = null`, and
verification starts at the first tagged line; the chain head is written into the store
(`log_chain_head`) at every unattended/grant event. The log append and the store-head write cannot
be one atomic operation, so the order is fixed: append + fsync the log line first, then write the
store head (a `kill -9` in between, A6, therefore leaves at most one validly tagged line beyond the
head, never a head pointing past the file). Verifier (startup): walk the file verifying `prev`
links and tags; the stored head must equal the hash of some line; every line after it must carry a
valid tag (only `K_master` holders can produce one) and is then accepted, after which the head is
advanced (a runtime-state store write, B.8.9 — the keychain is not involved); a missing
head with a valid chain is accepted with a warning badge; anything else ⇒ "log modified or
truncated at line N" badge (detects tampering only by parties without `K_master`, B.8.9).
Rotation 10 MiB × 10 (M1). Never logged: passwords, KE bytes, `session_key`, `export_key`, tokens,
the stop code, IPs beyond `transport`. The Sessions page (M-UI-5) shows, newest first, what the session lines hold: the time, the pinned label, the mode, attended or unattended, and how the session ended (a fixed list of endings; any other detail reads "ended"); no duration or direction column, and never a device key, words, grant id, path, transport detail or other free text; while this screen is shared it is hidden. Viewing it writes nothing. "Open log folder" shows the folder's path.
```
{"ts":"2026-08-28T12:04:31Z","event":"session_started","session_id":"9e…","peer_device":"<base32>","peer_name":"Laptop-of-Ana",
 "mode":"control","unattended":true,"transport":"direct","grant":"7f…","block":"elapsed","prev":"…","tag":"…"}
```

#### B.8.14 Implementation plan (milestone → crate → work → acceptance; M0 is closed and gets nothing)

| MS | Crate(s) | Work | Accept |
|---|---|---|---|
| M1 | `tornect-core` | `UnattendedStore`/`Grant`/`FailState` + AEAD codec + generation anchor + migrations; `K_master`/`K_unatt`; `keyring-core` backend behind a feature with file fallback; `SessionEvent` variants, hash chain, rotation; `Paths::unattended_store()`; fix the `trusted_devices_file` doc (pairings there, grants in the store); `unattended::{GrantStore, MutationGuard}` with the `ReAuth` and `RemoteSessionActivity` traits **defined here** (`MutationGuard::new(store, reauth: Arc<dyn ReAuth>, activity: Arc<dyn RemoteSessionActivity>)`, *Ownership* below — `tornect-platform` depends on core, so core cannot import them from platform; B.8.6.2 — the single entry point for UI, IPC and CLI); `ReadinessSnapshot`/`Probe` types with the all-unknown M1 stub (field list in the Rust block below); the `Presence` trait (M1 stub: `Unknown` ⇒ present; OS impls in `tornect-platform` at M6); `unattended::ipc` — the B.8.7.4 IPC message types + CBOR codec, no I/O (fuzz target F4); client-side `hosts.toml` per-host record `{remember, server_s_pk_pin, suite, ua_worked_before}` + `Paths::hosts_file()` (`server_s_pk` pin set at the first `SESSION_ACCEPT`, checked in `ClientLogin::finish`; the keychain-remembered password stays M8) | round-trip, tamper, rollback and permission tests; guard refuses without re-auth / during a remote session (A8 store/IPC parts); pin change ⇒ client abort (A16); `cargo check` on all targets |
| M1 | `tornect-signal`, `apps/tornect` (CLI), `tornect-platform` (scaffold only) | `research-verifier` note (`docs/research/crypto.md` §8 re-pin, suite decision, sizes, Argon2 timing, GPU figure, circuit-teardown API); envelope `sig`; kinds/bodies; strict-alternation transcript; `HELLO_ACK`; signed `SESSION_REQUEST`; one envelope/transcript golden vector (B.8.4.3) committed; `OpaqueAuthenticator` (+ `Spake2Authenticator` under `pake-fallback`); `AttemptLimiter` with persistence (charge/settle/pending, B.8.5.1), generic over the `tornect-core::unattended::Clock` trait (`wall()`/`mono()`, B.8.5.3; production = OS clocks, tests = a scripted `FakeClock`, the F3 loaders take the same trait); `ConsentProof`/`PolicyReceipt` (private constructors) and `SessionAccept::build(ConsentProof, …)` as the **only** constructor; admin intent + scope; `tornect unattended` CLI (`apps/tornect`) + the host-role IPC dispatch loop over the B.8.7.4 message set (types + codec in `tornect-core::unattended::ipc`, *Ownership* below); M1 scaffolds `tornect-platform` with two modules only — `ipc` (Unix socket / named pipe per B.8.7.4) and `reauth`, the OS implementation of the `tornect-core::unattended::ReAuth` trait (M1: polkit on the Linux dev machine — **not** PAM, which polkit already runs out of process, B.8.8 — plus a debug-build-only `TORNECT_DEV_REAUTH=allow` escape, refused in release builds; M6: the Windows/macOS backends of the B.8.8 table); the B.8.4.5 host FSM (`HelloVerified` … `Accepting`/`Closing`) behind the injected `BlockWindow`/`LocalAllow` traits with headless defaults (see *Ownership* below); `fuzz/` targets F1–F4 added to the existing workspace-excluded fuzz crate + `tests/integration` workspace member; property + adversarial suite | headless unattended handshake ending in `SESSION_ACCEPT` over the localhost-Tor mock and between two machines; U1–U7, P1–P4, F1–F4 green; adversarial A1–A6, A8 (store/IPC parts), A13, A14, A15, A16, A17 and the signaling half of A7 green; I1, I8, I10, I11 (signaling half), I12 green; fuzz 10 min clean; counters survive `kill -9` |
| M2 | `tornect-net` | the `BIND` exchange of B.8.4.3 (first frame on `ctrl` both ways: HMAC over the TLS exporter keyed by `session_token`, labelled by Tornect role — dialer = "client", host = "server" — not by QUIC role; constant-time verify, close on mismatch; no other stream/datagram accepted before it) consumes the derived token; `transport_policy` honoured by candidate gathering; the Tor fallback tunnels the *same* QUIC connection, so the `BIND` check applies unchanged on both transports (transport choice pending §B.8.17 item 7, decided at M2) | token mismatch ⇒ `BIND` fails and the connection is closed before any media, on the direct path and over the Tor tunnel alike (I7 sub-case); `tor_only` sends zero candidates; I7 green |
| M4 | `tornect-session`, app (minimal) | UI-backed `BlockWindow`/`LocalAllow` implementations for the `tornect-signal` FSM (incl. the `AwaitLocalAllow` popup) and the host FSM from the `Candidates` state on; block window (CLI / the minimal shell of Part C M4) + Block; indicator copy; `sessions.log` events; session-end semantics (revoke/off/expiry/schedule/lock); one-session rules (`BYE{REPLACED}`); `Presence` (the `tornect-core::unattended` trait, M1 stub) wired into the away card and `require_absent` | WAN, nobody present, block window 0/3 s ⇒ first frame ≤ 8 s p50 / 12 s p95 from Connect; Block ends the session before the first frame; A7 (live-session replacement), A8 (post-session timing), A10, A12 green; I3–I5, I11 (live kill) green |
| M5 | `tornect-input`, `tornect-session` | view-only enforced at the inject and stream layers (`input`/`clip`/`file` refused); panic-key semantics (end + suspend; double-press ⇒ master off) via physical events | a view-only session injects zero events, clip/file streams refused; panic ⇒ session gone < 100 ms, grant suspended; A11, I2 green |
| M6 | **`tornect-platform`** (OS backends; crate scaffolded in M1) | presence (the `tornect-core::unattended::Presence` impls), lock state/lock, idle-lock probe, keep-awake/idle inhibit, autostart installers, wake hooks, OS re-auth backends of the B.8.8 table, global hotkey (incl. GlobalShortcuts portal), capture-excluded windows, IPC endpoint per OS, readiness probes; B.8.8 rows → `PLATFORM_MATRIX.md` (columns: OS/compositor, portal restore token (RemoteDesktop session, §B.5), lock-screen capture, lock-screen input, presence source, lock mechanism, re-auth mechanism, hotkey) | reboot with auto-login configured ⇒ dialog-free unattended session ≤ 3 min per OS (NEEDS-DEVICE recipes); readiness rows truthful; A9 (platform half: injected input ignored, panic fires, indicator re-asserted), I6, I9 green |
| M7 | `tests/`, qa | limiter under 1 k scripted attempts; lockout persistence; descriptor re-publish after a simulated Arti restart (CI); 24 h soak with 6 sleep/wake cycles as `NEEDS-DEVICE(<os>)` via `xtask soak --unattended` | soak report committed |
| M8 | `apps/tornect`, docs | enable flow, manager, notifications/banners, client prompt + keychain + admin actions, log viewer filters, backup export/import, SECURITY.md threat model (this section), README "honest limits" | a non-developer enables unattended and connects from a second machine in < 5 min following README; B.8.16 checklist green; A9 (UI half: popups suppressed, in-app banner survives DND) green |

**Ownership (normative; mirrored in the §B.1 crate comments).** The `HELLO` … `SESSION_ACCEPT` /
`SESSION_REJECT` / `ADMIN_RESULT` state machine of B.8.4.5 lives entirely in `tornect-signal` (M1)
behind two injected traits, `BlockWindow` and `LocalAllow`, with headless M1 defaults (timer-only
window; `ask_before_start` ⇒ Deny); `tornect-session` (M4) supplies the UI-backed implementations
and everything from the `Candidates` state on. `tornect-core::unattended::{GrantStore,
MutationGuard}` own B.8.9 and B.8.6.2 and are the single entry point for UI, IPC and CLI. The two
traits the guard consumes — `ReAuth` and `RemoteSessionActivity` (`last_session_ended_at() ->
Option<Instant>` / `session_live() -> bool`) — are **defined in `tornect-core::unattended`** next
to `MutationGuard::new(store, reauth: Arc<dyn ReAuth>, activity: Arc<dyn RemoteSessionActivity>)`;
`tornect-platform::reauth` provides the OS implementations (M1: polkit on Linux, which runs PAM itself; M6:
Windows/macOS) and `tornect-session` the `RemoteSessionActivity` one (the offline CLI passes a
"no session" stub) — `tornect-platform` depends on `tornect-core`, never the reverse. `Presence`
(B.8.6.3) follows the same rule: defined in `tornect-core::unattended` next to `ReAuth` with an M1
stub (`Unknown` ⇒ present), implemented by `tornect-platform` at M6 and consumed by
`tornect-session` for the away card and `require_absent`. The IPC message types and their CBOR
codec (`IpcRequest`, `IpcResponse`, `IpcOp`, `StatusReport`, `GrantSummary`, `GrantOptions`, the
`G_*` codes) live in `tornect-core::unattended::ipc` (no I/O) — `GrantOptions`, the policy subset
of `UnattendedGrant`, is also the argument type of `MutationGuard::create_grant` / `set_options`;
`tornect-platform::ipc` owns only the socket / pipe endpoint and the peer check; `apps/tornect`
(host role) owns the dispatch loop, which decodes with the core codec and dispatches to the guard;
fuzz target F4 fuzzes the core codec. `ReadinessSnapshot` is defined in `tornect-core` with
an all-unknown M1 stub (the `tornect-platform` probes fill it from M6), so `tornect-signal` never
depends on `tornect-platform`; over IPC it travels as a CBOR map keyed by field name and decoders
ignore unknown keys, so M6 may add probes without an IPC schema bump. Readiness rule for the
post-F2 `HOST_NOT_READY` gate: `Unknown`
never blocks (fail-open with a badge) in M1; `Fail` on `capture` / `input` / `lock_state` /
`console_owner` (sourced per B.8.8: `WTSGetActiveConsoleSessionId` / logind `Active`) blocks
with `HOST_NOT_READY` (`cause` 1 / 2 / 3 / 4); in background mode (§B.1.1) a host gate beside these rows refuses every unattended session with `HOST_NOT_READY` without a `cause` until an indicator window drawn at the background start has shown its first frame (the row "indicator shown" warns meanwhile); every other `Fail` or `Warn` row raises the badge only.

```rust
pub type GrantId = [u8; 8];                                   // `UnattendedGrant.id`: random at creation, hex in logs
// tornect-core::unattended — the guard and the two traits it consumes (OS impls in tornect-platform::reauth; session impl in tornect-session)
pub trait ReAuth: Send + Sync { fn reauthenticate(&self, op: &str) -> Result<(), ReAuthError>; }   // blocking OS dialog, run on spawn_blocking; a fresh dialog per operation
pub trait RemoteSessionActivity: Send + Sync { fn last_session_ended_at(&self) -> Option<Instant>; fn session_live(&self) -> bool; }
impl MutationGuard { pub fn new(store: GrantStore, reauth: Arc<dyn ReAuth>, activity: Arc<dyn RemoteSessionActivity>) -> Self { /* B.8.6.2 */ } }
// MutationGuard::create_grant(device, preset, options: GrantOptions, upload) / set_options(grant, options: GrantOptions) take the IPC
// GrantOptions type (tornect-core::unattended::ipc, B.8.7.4); widening inside `options` is access-increasing (B.8.6.2)
pub enum PresenceState { Present, Absent { since: Instant }, Unknown /* treated as present */ }
pub trait Presence: Send + Sync { fn state(&self) -> PresenceState; }   // B.8.6.3, physical input only; M1 stub returns Unknown; OS impls in tornect-platform (M6)
pub trait Clock: Send + Sync { fn wall(&self) -> u64; fn mono(&self) -> Duration; }   // B.8.5.3: unix seconds + an Instant-like monotonic reading; production SystemClock (SystemTime + Instant), tests FakeClock; consumed by AttemptLimiter, the decay twins and the schedule/expiry checks
pub enum Probe { Ok, Warn(String), Fail(String), Unknown }
pub struct ReadinessSnapshot { capture: Probe, input: Probe, autostart: Probe, auto_login: Probe, keystore: Probe, os_password: Probe, idle_lock: Probe, lock_state: Probe,
                               console_owner: Probe, tor_self_connect: Probe, panic_key: Probe, consent_indicator: Probe /* indicator + tray row of B.8.7.1 ⑥ */ }   // one field per B.8.7.1 ⑥ row; M1 stub: all Unknown
   // gate rule (Ownership above): Unknown never blocks (fail-open + badge) in M1; Fail on capture / input / lock_state / console_owner ⇒ HOST_NOT_READY{cause 1 / 2 / 3 / 4}; other rows ⇒ badge only
   // IPC form: CBOR map keyed by field name, unknown keys ignored on decode — M6 may add probes without an IPC schema bump
// tornect-signal — seams filled by tornect-session (M4); headless M1 defaults: timer-only window, ask ⇒ false (Deny)
// Boxed `Send` futures, never bare `async fn` in trait: the FSM holds `Arc<dyn BlockWindow>` / `Arc<dyn LocalAllow>` (dyn-compatible)
// and its task crosses `tokio::spawn`; `#[async_trait]` (crate `async-trait`, pinned by `research-verifier` at M1) expands to exactly this shape
pub trait BlockWindow: Send + Sync { fn run<'a>(&'a self, secs: u8, who: &'a GrantId, label: &'a str) -> Pin<Box<dyn Future<Output = BlockOutcome> + Send + 'a>>; }
pub trait LocalAllow: Send + Sync { fn ask<'a>(&'a self, who: &'a GrantId, label: &'a str, timeout: Duration) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>; }
pub struct PolicyReceipt {                                    // minted only by the AwaitKe3 handler, after ServerLogin::finish
    grant: GrantId, mode: SessionMode /* most_restrictive(grant.mode, want_mode) */, transport: TransportPolicy /* Any | TorOnly | LanOnly */,
    ends_at: Option<u64>, block_window_s: u8, ask_before_start: bool, readiness: ReadinessSnapshot, minted_at: Instant,
    fail_summary: Option<FailSummary>,                        // session intent only; the snapshot returned by settle(ok) with the own charge excluded (B.8.5.1)
}   // private constructor `PolicyReceipt::mint(..)` is pub(crate) and has exactly one call site
pub enum BlockOutcome { Passed(WindowPassed), Blocked }                // returned by BlockWindow::run; Blocked ⇒ SESSION_REJECT{BLOCKED_BY_LOCAL_USER} and never reaches build
pub enum WindowPassed { Elapsed, Skipped /* block_window_s = 0 */ }    // the only block evidence a ConsentProof can carry
pub struct DerivedToken { session_token: [u8; 32], token_confirm: [u8; 32] }   // unattended: HKDF of the PAKE session_key (B.8.4.3); pub(crate) constructor in the AwaitKe3 handler
pub enum PopupChoice { AllowOnce, AllowOnceViewOnly }
pub enum ConsentProof { HumanClick { choice: PopupChoice, at: Instant, token: [u8; 32] /* fresh random session_token, attended */ },
                        Unattended { grant: GrantId, proof_fp: [u8; 8], policy: PolicyReceipt, block: WindowPassed, token: DerivedToken } }
impl SessionAccept { pub fn build(proof: ConsentProof, caps: ChosenCaps /* negotiated §B.2 caps */) -> Self { /* only constructor; infallible because a Blocked window or a token of the wrong kind is unrepresentable */ } }
```

#### B.8.15 Test matrix

| ID | Type | Scenario | Expected | MS |
|---|---|---|---|---|
| U1–U7 | unit | ladder incl. decay + lifetime budget; schedule (DST gap/overlap, wrap, TZ change); password policy (NFC, whitespace, score, file keystore ⇒ 4); store codec/migration/generation (incl. revoke → restore the pre-revoke store file → load fails closed with `StoreLoadFailed`, while a restored file that differs only in `FailState` loads: runtime-state rollback, B.8.9); clock rollback + forward jump, driven through the `FakeClock` of B.8.5.3 (a runtime forward jump or a suspend — wall clock advanced, monotonic clock untouched, indistinguishable to the process — decays nothing and shortens no lock, and the next load reconciles it; across a load it shortens only the persisted lock and decays `consecutive` by one per 24 h of jump (uncapped) and `since_unlock` by ≤ 1 step, the extra lifetime steps forfeited; a rollback at load re-arms locks in full, applies no decay and fails schedule/expiry closed; a rollback at runtime — wall clock stepped back, monotonic untouched — fails every schedule/`active_from`/`expires_at` check closed until the clock passes `last_seen` (pre-PAKE `NOT_YET_ACTIVE{next_open_in_s = last_seen − now}`, `ClockAnomaly` logged), and nothing written after it can shorten a lock or decay a counter at the next load because `last_seen`, the anchors and `flushed_at` are written monotone; decay never clears `hard_locked`); transcript/signature/HKDF golden vectors; limiter charge/settle: 60 consecutive successful logins ⇒ no lock and `since_unlock` stays 0, abandon after KE2 + `kill -9` ⇒ `since_unlock` persisted as 1 (`pending` settled as fail on load, before decay: `consecutive = 3` with `pending` set and a 2-day gap ⇒ the settlement moves both anchors to `now` first, so `consecutive` stays 3 and no step is applied); a success on the charge that armed the hard lock (20th consecutive / 60th since unlock) clears `hard_locked` and returns `since_success = 19` (the own charge excluded) / `since_unlock` back at 59; a success with zero prior failures returns `fail_summary = None`; decay anchors advance by whole periods only, at load and at runtime alike; 21 d of uptime without failures then a charge ⇒ `since_unlock` −3 and the lifetime anchor +21 d (the `min(steps, 1)` cap is load-time only); `credit + twin.elapsed()` ≤ the wall-clock time since the persisted anchor, with equality whenever no backward step intervened since that anchor was written (the deficit only defers decay) | exact per spec | M1 |
| P1–P4 | property | random interleavings incl. PING at every position ⇒ identical `th` on both sides or clean `E_BAD_STATE` (no additional charge: an existing `AwaitKe3` charge stands and is settled as fail); per-direction `msg_id`; any single-byte mutation before `SESSION_ACCEPT` ⇒ abort; unknown CBOR keys round-trip | no panic; ≤ 1 charge per stream | M1 |
| F1–F4 | fuzz | `HELLO`/`HELLO_ACK`/`SESSION_REQUEST.unattended`/`AUTH_*`/`ADMIN_RESULT` bodies into both FSMs; KE1/KE2/KE3 deserializers; store + limiter loaders (through the `Clock` trait of B.8.5.3, with fuzzed clock readings); IPC messages | no panic/UB, bounded time and allocation | M1 |
| I1–I12 | integration (Tor mock + netem) | happy path (suite 1; suite 2 in fallback builds); view-only stream refusal; block elapsed / Block; schedule-end `BYE` with warning; `max_session_secs` + cooldown (`COOLDOWN{retry_after_s}`); lock-on-disconnect only on teardown (link flap ⇒ no lock); `tor_only`/`lan_only` (incl. a token mismatch over the Tor tunnel ⇒ QUIC handshake fails); restricted discovery on/off; `HOST_NOT_READY` when a token is revoked mid-run; canary fails at readiness ⇒ file keystore + badge, keyring locked at runtime ⇒ `NOT_GRANTED` + badge; admin `end_session`/`revoke` from a second device; orphaned accept pre-empted only by a post-F2 success from that pk (a bare `HELLO` does not) | as specified | M1: I1, I8, I10, I11 (signaling), I12 · M2: I7 · M4: I3–I5, I11 (live kill) · M5: I2 · M6: I6, I9 |
| A1 | adversarial | right password, unpaired key | PAIR path, byte-identical, no `AUTH_CHALLENGE` | M1 |
| A2 | adversarial | paired; no / expired / disabled grant | `NOT_GRANTED`, zero OPRF evaluations (counter assert) | M1 |
| A3 | adversarial | replayed HELLO + SESSION_REQUEST from a recording; replayed `AUTH_RESPONSE`; whole transcript on a fresh stream; relay via a phishing host | `E_BAD_SIG` (host nonce), nothing charged; MAC failure at KE3; client emits nothing password-derived (both suites) | M1 |
| A4 | adversarial | abandon after KE2 × 20; 60 lifetime failures with successes in between | hard lock; no KE2 afterwards; ≤ 1 `HARD_LOCKED`/min | M1 |
| A5 | adversarial | suite byte altered; unrequested `session_type`; forged `token_confirm`; `session_token` present on an unattended accept; `block_window_s`/`ask_before_start` injected into `AUTH_CHALLENGE` | `UNSUPPORTED_SUITE` / client abort before QUIC; injected policy keys ignored (unknown keys), the client's wait stays the fixed 110 s | M1 |
| A6 | adversarial | `kill -9` between charge and reject; `kill -9` between the log append and the store-head write; clock −24 h; store replaced by a generation older than the anchor | counter persisted; the validly tagged line beyond the head is accepted and the head advanced (B.8.13); lock not shortened; fail closed + notice | M1 |
| A7 | adversarial | 5 concurrent handshakes from 5 pks; two from one pk (the second with a fresh signed `SESSION_REQUEST`); a recorded `HELLO` replayed from that pk while its KE3 is pending; second success while a session is live | 5th `UA_BUSY`; stale cancelled only by the verified `SESSION_REQUEST` (closed with `PREEMPTED`, not `AUTH_FAILED`); the replayed `HELLO` leaves the in-flight handshake untouched (its KE3 still succeeds, nothing charged); older session `BYE{REPLACED}`, new one accepted + notification | M1 (signaling half) · M4 (live session) |
| A8 | adversarial | scheduled `grant`/`on`/IPC mutation 5 min after a Control session; IPC `BackupExport` during / 5 min after a Control session; `RegFinish` without a live `reg_txn`; `config.toml` `enabled=true`; direct store edit without `K_master` | refused without re-auth; refused without re-auth, logged; refused (`G_NO_TXN`), logged; ignored; fail closed — all logged | M1 (store/IPC parts) · M4 (post-session timing) |
| A9 | adversarial | remote controller opens PAIR/SESSION popups, clicks Block/Unlock, covers or closes the indicator, jams the panic key with injected key-ups, enables DND | popups suppressed; injected input ignored; indicator re-asserted; panic fires; in-app banner survives DND (UI harness with a fullscreen game running) | M6 (platform half) · M8 (UI half) |
| A10 | adversarial | presence timing: idle vs active host | identical `SESSION_ACCEPT` timing (± jitter); `require_absent` only affects the reject | M4 |
| A11 | adversarial | view-only session opens `input`, `clip`, `file`; `want_mode = 0` (Control) on a view-only grant | refused at QUIC; `PolicyReceipt.mode == ViewOnly` and `SESSION_ACCEPT.mode == 1` (clamp monotone toward view-only) | M5 |
| A12 | adversarial | revoke / off / expiry / schedule end / lock during a live session | `BYE` + QUIC closed ≤ 1 s; logged | M4 |
| A13 | adversarial | HELLO with random / correct `stop_token` from an unpaired peer; a stop token captured by a phishing host (computed with the phisher's pk) replayed at the real host; fallback build: phishing host, malformed salt/`pB`, `pA` replay | random: byte-identical PAIR path; correct: master off + revoke-all + kill + log; phishing-host token useless at the real host (pk-bound, no state change); one online guess per stream, `E_BAD_LEN`, MAC failure | M1 |
| A14 | adversarial | grep: no password/KE/`session_key`/`export_key` bytes in logs, TOML, IPC traces, core dumps (zeroize-on-drop tests) | clean | M1 (re-run at every milestone) |
| A15 | adversarial | `unlock(pk)` / `revoke_all` / `master_off` / `suspend(other)` from a view-only or *Helping someone* grant; `unlock(pk)` of a grant in `Suspended{LocalBlock}` from a *My machines* Control grant; `unlock(pk)` of a grant in `Suspended{Admin}` from a *My machines* Control grant; `unlock(pk)` of a grant in `Suspended{Local{by: Cli}}` (set by `tornect unattended suspend`) from a *My machines* Control grant; `suspend(pk)` then `unlock(pk)` against a grant in `Suspended{LocalBlock}`, both from a *My machines* Control grant | `ADMIN_RESULT{ok: false}`, no state change, logged (`AdminRequest`, refused); second case: `FailState` reset but the grant stays `Suspended{LocalBlock}` (its next `SESSION_REQUEST` gets pre-PAKE `SUSPENDED`) — remote unlock never clears a local Block; third case: `FailState` reset and the grant returns to `Active`; fourth case: as the second — `FailState` reset, the grant stays `Suspended{Local}` until a local *Resume*; fifth case: the state stays `Suspended{LocalBlock}` throughout — the `suspend(pk)` changes nothing (`ADMIN_RESULT{ok: true}`, logged) and the `unlock(pk)` resets `FailState` only (B.8.6.3 precedence) | M1 |
| A16 | adversarial | host `ServerSetup` recreated (Rotate ID + re-pair, or a replaced store) after the client pinned `server_s_pk` | client aborts before KE3 with the "unattended identity of this host changed" message (nothing password-derived emitted beyond KE1); re-pair / re-register clears the pin | M1 |
| A17 | adversarial | 50 bare `HELLO`s from random keys held open (no `SESSION_REQUEST`), then a granted device logs in | the granted device still receives `AUTH_CHALLENGE`: uncharged `HelloVerified` streams never occupy the per-pk, host-wide or per-minute budgets (B.8.5.2) | M1 |
| A20 | adversarial | Windows fixture, grant at administrator, Remember ticked: (a) no level asked, (b) view only, (c) level asked, helper late, (d) admin command executed, (e) admin command refused incl. "unknown admin command"; then an entry planted for that host; then hosts.toml edited to reach = false, remember = true; then a QUIC failure forced right after the accept | every answer says 2; no entry after any case; the planted entry deleted at the first answer, before QUIC, and still gone after the failure; the edits change only the prompt; an AdminRequest line for (e) "unknown"; the same cases on a grant at none on a host without admin grants: (a)–(c) keep the typed password; (d)–(e) write no entry and leave an already remembered one in place, in the window and the CLI; fails when the client rule is removed | M-FEAT-5 |
| A21 | adversarial | plain Control grant where (a) another grant holds administrator (Active, then Disabled, then Suspended, then expired), (b) no admin grant but the helper task registered (also after the last admin grant was deleted), then its query failing, (c) UAC off installed, (d) UAC off standalone, (e) CPBA 0 installed, (f) CPBA 0 standalone, (g) CPBA set to 0 after host start, before an answer and during a live Control session of a marked password, (h) a UAC value or the token that cannot be read; a view-only grant at none in (a); a view-only grant at administrator; Linux, and Linux with the root check unable to read `/proc/self` | 1 in (a)–(h), 2 for the view-only grant at administrator, 0 for the view-only grant at none; (c)–(h) also served View only (F-12); (g) the live session goes on until it ends and the next answer says 1; (h) the predicate gets "unreadable", never the probe's default facts; Linux always 0, and the host that cannot rule out root does not serve | M-FEAT-5 |
| A22 | adversarial | P remembered on a grant at none; raise via set_options; raise via RegFinish; mode → Control where Control reaches the administrator level (grant_reach 1, §B.8.4.1); a chosen password offered at a raise, Change password and creation with the level; a raise in the window (its inline re-authentication); an imported and a restored admin grant, and one Disabled{Ui} before the restore: enable, then a generated Change password, then enable; RegFinish without generated: on a marked grant at reach 0, carrying a raise, and creating a grant with the level or a Control grant where Control reaches the administrator level; a RegFinish that raises after a RegStart that did not declare it, and one whose generated differs from its RegStart's; the CLI grant --administrator with other Control grants; a second rise after Control stopped reaching the administrator level; the window's set_password carrying the level; a chosen password given to a marked grant at reach 0 | set_options and enable of each still-marked admin grant (the Disabled{Ui} one included) ⇒ G_NEEDS_PASSWORD (0x0108), logged, nothing changed; after the generated Change password the enable applies; RegFinish without generated leaves the grant marked, and with a raise or a creation with reach ⇒ G_NEEDS_PASSWORD, nothing written; the RegFinish not matching its RegStart ⇒ G_NEEDS_PASSWORD; a raising RegStart, and a raise in the window, show the raising wording; the window path raises in one write; the chosen password leaves the grant marked; after a raise P ⇒ AUTH_FAILED and the client deletes it as stale; no "use my own"; the CLI lists the other devices and offers new passwords; the second rise offers again; no path sets the level without replacing auth in the same write, or enables a marked admin grant before a generated password replaced its auth; the remote unlock of a Suspended{Admin} admin grant applies without a new auth (CA-3) | M-FEAT-5 (guard, CLI) · M-UI-5 (wizard) |
| A23 | adversarial | unattended accept with elevation = 1 and grant_reach absent, 0, 1; grant_reach = 3; grant_reach on an attended accept; key 12 stripped from an elevation = 1 accept, and flipped 0↔1 on one without it, after signing; key 12 duplicated, and null; accept and ADMIN_RESULT without the key (older-host fixture); a refused HELLO_ACK; attended vector 3 | E_BAD_LEN ×3, E_BAD_LEN, E_BAD_LEN, E_BAD_LEN for the strip and E_BAD_SIG for the flip, each deleting the remembered password (not stale); duplicate: the last value read, null: absent; without the key: no Remember, the entry deleted, the session goes on; the refused HELLO_ACK stays Inconclusive and deletes nothing; vector 3 unchanged | M-FEAT-5 |
| A24 | adversarial | hosts.toml: reach cleared, set; remember set for a host never remembered; rolled back after a deletion; unreadable at an answer of 1; a keychain delete that fails; a crash between the accept and the save; on Linux, a write in a second sign-in then a delete; a reject after F2 (COOLDOWN) with a remembered entry, then an answer of 0 to a recalled password; Forget while the keychain refuses the delete | cleared: Remember shown, nothing kept after an answer of 1; set: no write; remember: recall reads only that host's entry; rollback: nothing reappears; unreadable: the entry still deleted and the note says the file failed; failed delete: remember stays set and the entry is deleted at the next prompt open; crash: nothing kept for an answer of 1; Linux: no readable key in either sign-in; the reject and the 0 keep the entry and both flags; Forget says the delete failed and keeps the record with remember set, and a later Forget deletes the entry | M-FEAT-5 |
| A25 | adversarial | the "answered 0" mark: P answered 0 (marked), then (a) another grant raised to administrator, (b) the helper task registered, (c) a raise with a new password during P's AwaitKe3, popup, block window or helper wait, (d) a lowering during an administrator request's block window, (e) the store rolled back to before the mark, with the anchor written and with the bump owed, (f) the mark write failing, (g) a backup taken before the mark imported, (h) *Change password* during P's block window, (i) a store written by an M-FEAT-4 build, and one rewritten by it after an M-FEAT-5 build marked it, (j) an admin command with P after a raise, (k) each access-increasing guard operation (create_grant, set_password, RegFinish, set_options, enable, resume, local unlock, set_settings) with P's reservation taken between its last unlocked check and its commit, (l) an admin command refused under the lock for each early reason, (m) P's grant suspended, expired, hard-locked or Pruned, and unattended access turned off or paused, during its block window, (n) P marked at the level asking for it, and a request served View only by F-12, (o) a store that adopts a machine id, (p) revoke, disable, suspend and a lowering with P's session reserved and with it live | (a)(b) P's sessions View only and answered 1; a new generated password clears the mark and restores Control; (c)(h)(j) P refused with AUTH_FAILED, no session, no command, nothing marked, the new password unmarked; (d) the accept carries no elevation = 1; (e) fails closed with the anchor written, not while the bump is owed; (f) refused with NOT_GRANTED, nothing signed at 0; (g) imported grants arrive marked; (i) every grant reads as marked, and level none after the rewrite; (k) G_REMOTE_SESSION_ACTIVE, no deadlock, the refusal logged once, the chain verifier passes; (l) answered, logged, no deadlock; (m) NOT_GRANTED, nothing marked; (n) the helper is never started; (o) every grant marked; (p) the session ends within 1 s with BYE{SUSPENDED} for the suspend and BYE{REVOKED} for the others, and the other device's session goes on | M-FEAT-5 |

A18 and A19 are used in docs/VERIFICATION.md.

#### B.8.16 Security-reviewer checklist additions (§D.3)

- `SessionAccept::build(ConsentProof, …)` is the only constructor; `PolicyReceipt` is minted only after `ServerLogin::finish`; the account settings and the administrator helper task's presence behind `grant_reach` and F-12 are read at each answer, outside the store lock, never cached from start; a password whose `SESSION_ACCEPT` says 0 is marked before that accept is signed, and one replaced since its PAKE is refused (M1-67).
- Charge (`pending = true`) + fsync precede KE2; no KE2 while locked/suspended/expired/disabled; success is the only consecutive reset and reverts only its own charge; the lifetime budget is never reset by success (7-day decay only, ≤ 1 step per load; for decay and locks the wall clock is read only at load — runtime wall-clock reads are limited to monotone stamping (`:= now` clamped to `max(stored, now)`) and the schedule/`active_from`/`expires_at` gates, which fail closed on rollback; runtime decay uses the twins/`credit` of B.8.5.1, locks use `mono()` deadlines, both through the `Clock` trait; `last_seen` and every persisted clock field never decrease (`:= now` writes clamped, decay advances anchors by whole periods), and a rollback fails schedule/expiry closed at runtime as well as at load; decay never clears `hard_locked`); `pending` at load ⇒ settled-fail; unattended rejects never feed the temp-ban; global limits never lock; no global breaker.
- Host derives `credential_identifier`, `context`, `identifiers` from the signature-verified pk; `context` includes `th_after(SESSION_REQUEST)`, suite, intent; both host OPAQUE calls pass `ServerLoginParameters`; `ksf` never `None`; sizes 96/320/64 asserted.
- Client: fresh `ClientLogin::start` per stream; `HELLO_ACK` verified against the dialed address; `server_s_pk` pinned (`hosts.toml`, checked in `ClientLogin::finish`); the suite is a build-time constant, never taken from `HELLO_ACK.feats` when suite 1 is compiled in; `export_key` dropped/zeroized in the same scope as `finish`, never persisted or logged; aborts on `session_type` mismatch, `AUTH_CHALLENGE.suite ≠ requested`, `session_token` present for unattended, `token_confirm` mismatch (constant time), `quic_spki` ≠ the pinned host SPKI (constant time, §B.6); grant policy (`block_window_s`, `ask_before_start`) is read only from the signed `SESSION_ACCEPT`, never from `AUTH_CHALLENGE`; never auto-retries (nor with another suite); the remembered password is kept only after this stream's signed `SESSION_ACCEPT` with `grant_reach = 0`, never after an `ADMIN_RESULT`, and is deleted (first, whatever `hosts.toml` holds), before QUIC, at an answer of 1 or 2, at an unattended answer without the key, or at a refused answer; the `hosts.toml` flags never decide a keychain write (M1-67).
- Strict-alternation window enforced (`PING` during auth ⇒ `E_BAD_STATE`, no additional charge — an `AwaitKe3` charge is settled as fail); a bare `HELLO` never cancels an in-flight `AwaitKe3` handshake — only a verified `SESSION_REQUEST` from the same pk does (B.8.4.5); `HelloVerified` streams never count as in flight (B.8.5.2); `th` hashes exact wire bytes; signatures cover envelope fields, never re-serialized CBOR; every `HELLO` signature is verified against the `HELLO`'s own pk (proof of possession) and, when pinned, the pk must equal the pinned key — a bad signature is `E_BAD_SIG` for pinned and unpinned peers alike, byte-identical; `HELLO_ACK.feats` is host-wide.
- One mutation guard consulted by UI, IPC, CLI and startup reload; re-auth is a fresh OS dialog per operation; deny-direction paths need nothing and kill sessions ≤ 1 s; popups suppressed during remote sessions; policy never read from `config.toml`; admin scope (B.8.4.1) enforced from the requester's grant, and a remote `unlock` clears `Suspended{Admin}` but never `Suspended{LocalBlock|Panic|Local}`; backup export is access-increasing; `RegFinish` needs the live `reg_txn` from a re-authenticated `RegStart`.
- Store: AEAD with header AAD, generation anchor (bumped by every policy write — access-increasing and deny-direction alike, revocations included — never by runtime-state writes; an owed bump is carried as `pending_anchor` while the keychain is unwritable; store ≥ anchor accepted, older ⇒ fail closed, so a pre-revocation store never loads), `machine_id_hash` mismatch ⇒ grants `Disabled{by: Restore}`, fail closed on every load error — a guarantee against parties without `K_master` (T9 is out of scope), atomic writes, single writer, 0600/ACL, tombstones merged on import, `Zeroizing` buffers.
- Indicator/panic/block window: physical-input-only detection, re-assertion, un-closable, DND-independent in-app surface; view-only refuses `input`/`clip`/`file` at the QUIC layer; the mode clamp is monotone toward view-only (`SessionMode::most_restrictive`).
- Logs: pinned label only, rate-aggregated rejects, hash chain + tag with the head in the store (append + fsync before the head write; tagged lines beyond the head accepted and the head advanced, B.8.13), no secrets; client log present. Emergency stop: only the pk-bound `stop_token` is stored and compared (constant time), single-use. Restricted discovery: client-generated keys, pairing-mode window logged, caveats shown.
- Fallback build: `pA`/`cA` only after a host message; constant-time compares; `w` wrapped and reduced wide from a 64-byte Argon2id output; `M`/`N` from the fixed seeds; `cA`/`cB` keyed by `KcA`/`KcB`, the token HKDF by `Ke`; suite fixed per grant, never two records for one grant.

#### B.8.17 Open questions

1. Per-grant passwords are the model — should the wizard offer "same password as <other own device>" (re-typed, separate record)? (M8 UX test.)
2. `hard_lock_after` 20 / lifetime 60 — confirm against real Tor failure rates from the M1/M7 soaks.
3. Wayland: which compositors provide `ext-idle-notify-v1` and a usable GlobalShortcuts portal; fallback "present" + focused window confirmed (M6).
4. Argon2id 64 MiB on future mobile clients ⇒ new suite id with re-registration, not a negotiation; decide when a mobile client exists.
5. Keychain user-presence gating (Touch ID / Windows Hello) for the remembered password — v1 where `keyring-core` stores expose it cheaply, else post-v1; headless Linux re-auth without a polkit agent (PAM vs a weaker Tornect-only passphrase) decided at M6. A presence-gated store would not by itself allow keeping a password whose `grant_reach` is 1 or 2; that needs a plan change (decision M1-67).
6. Service mode: Windows is roadmap M-SVC-W, after the initial release (decision M1-61), with its own threat model before any code — a LocalSystem service parsing network input in session 0, per-session processes through `CreateProcessAsUser`, the Winlogon desktop, `SendSAS`, keys in machine scope, OS re-auth as "an administrator of this PC", multi-user hosts, its update path; other OSes unscoped. Also whether lock-on-disconnect should default on wherever the M6 matrix proves remote unlock.
7. Tor fallback transport: the same QUIC connection over a length-framed onion-stream tunnel (uniform `BIND`/exporter check — §B.2, B.8.4.2, Part C M2) vs. the session protocol directly over the onion stream (quic.md §0/§9: double congestion control, wasted 1200 B Initial padding and DPLPMTUD probes, extra handshake RTTs over 0.5–1.5 s circuits) — decide at M2 with a measured onion-stream throughput; if direct, define the `BIND` equivalent over the onion stream (e.g. an HMAC over `th` + `session_token`, both directions, before any media) so the token check stays uniform. Also a Part E row.
8. The administrator helper's residual (r7): while an admin grant exists, any program running as the user can start the helper task, so every Control session on that host can reach administrator windows (T9, B.8.7.5). Accepted for v1 with the wizard warning (decision M1-62); administrator access in attended sessions only stays the alternative if the Windows tests show more.

---

## Part C — Roadmap: milestones with acceptance criteria

Ordering rationale: prove the two risky, novel layers first (Tor signaling; hole
punch), then build the media pipeline on the developer's primary OS, then fan out
across platforms **in parallel with subagents**, then harden. Every milestone ends
green: `cargo clippy -D warnings && cargo test` + a runnable demo + a git tag.

**M0 — Bootstrap (≈1 session)**
Workspace scaffolding per §B.1; `tornect-core` (TornectId newtype, config
load/save, key generation + keystore, `tracing` setup); CI skeleton (GitHub Actions:
lint+test on linux/windows/macos runners); `xtask dist` stub; CLAUDE.md + agents
committed. ✅ Accept: `cargo run -p tornect -- id` prints a freshly generated .onion
ID on all 3 OSes (CI).

**M1 — Signaling over Tor (the moment Tornect becomes real)**
Embed Arti; host publishes onion service (persistent key, state dir); client
connects by onion addr; full HELLO/PAIR/SESSION envelope state machines with
property tests; CLI consent prompt (y/n + SAS display) before the UI shell exists (`u1`, Part F.6);
PoW DoS defense + rate limits on. Unattended protocol per §B.8.4–B.8.5 and §B.8.9:
`HELLO_ACK`, signed `SESSION_REQUEST`, `AUTH_CHALLENGE`/`AUTH_RESPONSE`/`ADMIN_RESULT`,
OPAQUE suite (`opaque-ke` 4.0.1; suite decision by `research-verifier`, SPAKE2 fallback
behind `pake-fallback`), persisted attempt limiter, encrypted grant store + keystore
key, `ConsentProof`/`PolicyReceipt` + `SessionAccept::build` as the only constructor,
`tornect unattended` CLI (`apps/tornect`) over the local IPC endpoint (§B.8.7.4 message
set), `fuzz/` targets F1–F4 in the existing workspace-excluded fuzz crate + the
`tests/integration` workspace member, one envelope/transcript golden vector
(§B.8.4.3), the client-side `hosts.toml` record with the `server_s_pk` pin (§B.8.9). M1
scaffolds `tornect-platform` with two modules only — `ipc` (Unix socket / named pipe per
§B.8.7.4) and `reauth`, the OS implementation of the `ReAuth` trait that `tornect-core::unattended`
defines next to `MutationGuard` (§B.8.14 *Ownership*): polkit on the Linux dev machine plus a
debug-build-only `TORNECT_DEV_REAUTH=allow` escape (refused in release builds); M6 adds the
Windows/macOS backends of the §B.8.8 table. ✅ Accept: two machines on different
NATs pair and exchange PING/PONG round-trips via Tor with only an onion string shared;
kill/restart host ⇒ same ID; `tornect-signal` fuzz target runs clean 10 min; a
password-authenticated unattended handshake reaches `SESSION_ACCEPT` between the two
machines with no prompt on the host, and the §B.8.15 rows owned by M1 are green
(adversarial A1–A6, A8 store/IPC parts, A13, A14, A15, A16, A17 and the signaling half of A7;
U1–U7, P1–P4, F1–F4; integration I1, I8, I10, I11 signaling half, I12).

**M2 — Direct connectivity (hole punch + QUIC)**
Candidate gathering (`if-addrs`, `igd-next` UPnP + `crab_nat` PCP/NAT-PMP, the **`stun`**
crate (webrtc-rs 0.17, used sans-IO on the media socket — never its `Client`; not
`stun-client`) against the configurable list; default-gateway/client-IP discovery for `crab_nat`
decided at M2 start — `netdev` vs ~100 lines of per-OS code, SUMMARY.md §1.4); CANDIDATES over Tor; paced simultaneous-open
punch per §B.2 (STUN-style probes outside QUIC, ICE pacing, one `connect_with` dial by the
lower-pubkey side, `grease_quic_bit(false)` + a demux unit test); quinn endpoint with the
RFC 7250 raw-public-key mutual verifiers pinning both SPKIs (§B.6) + the `session_token`
`BIND` exchange (first frame on
`ctrl` both ways, an HMAC over the TLS exporter labelled by Tornect role — dialer = "client", host =
"server", independent of the QUIC-role tie-break; nothing else accepted before it verifies — the
PAKE-derived token of unattended sessions feeds the same check, §B.8.4.3); `transport_policy`
(`tor_only`/`lan_only`, §B.8.6.4) honoured by candidate gathering; Tor-tunnel
fallback transport implementing the same `SessionTransport` trait (transport choice pending §B.8.17
item 7, decided at M2); connection
health/migration (Wi-Fi→ethernet). ✅ Accept: matrix test — LAN, one-sided NAT,
double NAT (netem/netns harness simulating port-restricted + symmetric) — direct
established where theoretically possible, Tor fallback engages within 4 s otherwise;
1 GiB transferred over punched QUIC with checksum; measured punch success logged;
a mismatched unattended token fails the `BIND` exchange and closes the connection before any
media (on the direct path and over the Tor tunnel alike — the tunnel carries the same QUIC
connection) and `tor_only` sends zero candidates.

**M3 — Video pipeline, single platform (pick the OS Claude Code is running on)**
*r7:* the FFmpeg wrappers below leave v1 (D8, decision M1-56); hardware encode and decode are M-CODEC-1…3 of
the desktop release below; the rest of M3 stands.
Capture backend for dev OS (+ a synthetic source — the `pipewire` crate needs headers this
VM lacks, so the PipeWire backend builds only in CI); `openh264` software encode+decode
(always compiled); FFmpeg hw encode+decode wrappers with runtime probe behind the `ffmpeg`
feature (compiled and smoke-tested in the Linux CI media job — a `vaapi`/`cuda` device
create that returns `ENOENT`/`ENOSYS` still validates linking and struct layouts);
packetizer/FEC/jitter/pacer from §B.4; wgpu render window (lavapipe on the VM); loopback
demo (`tornect demo --loopback`) capture→encode→(in-proc channel)→decode→render.
✅ Accept — **VM-scoped** (this dev machine and the Linux CI runner have no GPU encoder;
`openh264` measured 23.4 ms/frame encode + 5.4 ms decode at 1080p here, above the 16.7 ms
60 fps budget): synthetic source → `openh264` → in-proc → `openh264` → wgpu, loopback ≥ 30 min at
**720p60 with added latency ≤ 35 ms p95**, and at **1080p30 with added latency ≤ 50 ms p95** (the
§B.7 hard cap — openh264's 23.4 + 5.4 ms already consume most of the 35 ms target at 1080p) plus
codec-excluded pipeline latency (capture → packetize → jitter → present, encode/decode subtracted)
≤ 9 ms p95 — the §B.7 stage sum capture ≤ 4 + packetize ≤ 2 + render ≤ 3, measured with the synthetic
source (≈ 0 ms capture) and the jitter buffer pinned to 0 frames on loopback; ≤ 6 ms is the stretch figure
(HUD overlay numbers), zero validation errors, the `--headless-stats` output of both
runs — total and codec-excluded p95 — pasted into `docs/VERIFICATION.md`.
✅ Accept — **`NEEDS-DEVICE(gpu)`** rows in `docs/VERIFICATION.md`, each with an exact
recipe: 1080p60 loopback ≥ 30 min, added latency ≤ 35 ms p95, CPU < 15 % with a hardware
codec; and a **`NEEDS-DEVICE(linux)`** row — the PipeWire capture backend end-to-end on a
GNOME ≥ 45 desktop with `libpipewire-0.3-dev` (recipe: `-p tornect-capture --features pipewire`,
a RemoteDesktop portal session, 30-min loopback) — it needs a Linux desktop, not a GPU: this VM
lacks the headers and CI lacks a portal session. (docs/research/SUMMARY.md §0.3, §4 M3;
codecs.md §3.2, §11.3)

**M4 — End-to-end streaming (M1+M2+M3 glued by `tornect-session`)**
Host & client session state machines; ctrl stream (IDR request, bitrate hint);
UI: the `u1` shell of Part F.6 (ID card + connect field + consent/pairing popups, already
delivered — D10: egui everywhere since r7) wired to the M3 stream window end-to-end — `u2` = U2 of
`docs/UI_PLAN.md` §11 (S3 connecting stages, HUD v1 + latency overlay, disconnect/reconnect UX), tagged
at the M4 Accept (Part F.6). Unattended
gating in the host FSM (`ConsentProof::Unattended`, §B.8.14), block window with
[Block], indicator copy, `sessions.log` events, session-end semantics
(revoke/off/expiry/schedule/lock, §B.8.6.4), one-session rules, the core `Presence` stub wired in.
✅ Accept: two real machines over WAN: enter onion ID → popup → approve → live
desktop ≤ 8 s from request; unplug router mid-session ⇒ reconnect or clean error;
unattended: with nobody present (block window 0/3 s) first frame ≤ 8 s p50 / 12 s p95
from Connect, and [Block] ends the session before the first frame.

**M5 — Input + audio (remote *control*, not just viewing)**
Input capture/inject for dev OS + one more; Opus audio path both ends; clipboard
text sync; gaming mode (pointer lock, raw deltas, gamepad); host-side view-only
enforcement (`input`/`clip`/`file` refused at the QUIC layer) and panic-key semantics
for unattended sessions (end + suspend grant; double-press ⇒ master off; physical
events only — §B.8.6.4, §B.8.7.4). ✅ Accept: type a
paragraph remotely with zero dropped/duplicated keys (scripted 10k-event test);
audio-video sync within ±60 ms; play a 2D game tolerably over LAN; a view-only
unattended session injects zero events; panic ⇒ session gone < 100 ms.

**M6 — Cross-platform parity (heavy parallel-subagent phase, §D.4)**
Remaining capture/input/audio backends: `wgc`+SendInput+WASAPI ·
`sckit`+CGEvent+SCK-audio(+TCC onboarding flows) · `pw`+`reis`+PipeWire-audio
(+portal restore tokens, Flatpak manifest). Encoder matrix validation
NVIDIA/AMD/Intel/Apple, 4:4:4 + 10-bit probes. `tornect-platform` per OS (§B.8.8:
presence, lock state, keep-awake/idle inhibit, autostart installers, wake hooks, OS
re-authentication, global hotkey incl. GlobalShortcuts portal, readiness probes,
local IPC endpoint). ✅ Accept: full 3×3 host↔client
matrix streams with input+audio; CI builds artifacts for all OSes; a
`PLATFORM_MATRIX.md` records tested GPU/driver/compositor combos plus the unattended
rows of §B.8.8; reboot with auto-login configured ⇒ dialog-free unattended session
≤ 3 min per OS (`NEEDS-DEVICE` recipes); readiness rows truthful. `u3` = U3 of `docs/UI_PLAN.md`
§11 (settings, devices, permission walkthroughs, notifications + indicator on all three platforms, tray)
follows M6 serially, before M7 (Part F.6).

**M7 — Resilience & performance hardening**
ABR controller tuned on netem profiles (3 canned: "fiber", "flaky wifi", "hotel");
FEC adaptivity; Tor-fallback UX (badge, quality preset — `u4` = U4 of `docs/UI_PLAN.md` §11, tagged at
the M7 Accept, Part F.6); zero-copy decode-render
interop; multi-monitor select/switch; HDR (HEVC Main10/AV1-10) behind flag;
unattended limiter/lockout under 1 k scripted attempts and lockout persistence (CI),
descriptor re-publish after a simulated Arti restart (CI), 24 h unattended soak with
sleep/wake cycles as `NEEDS-DEVICE(<os>)` (§B.8.14).
✅ Accept: scripted netem suite passes quality gates (§B.7 table + fallback gate);
30-min soak at 5 % loss without session drop; perf report committed.

**M8 — Product polish & ship v0.1**
Full app shell per D10 (U5 of `docs/UI_PLAN.md` §11 = `u5`, tagged at the M8 Accept, Part F.6): onboarding (permissions walkthroughs per OS), settings, trusted
devices manager, session log viewer, unattended-access UI per §B.8.7/§B.8.10 (enable
flow with readiness and scam step, grants manager, notifications/banners, client
prompt + keychain + admin actions, `tornect service` docs, backup export/import),
paranoid/LAN modes; packaging (`xtask dist`): MSI/winget, notarized .dmg (document
signing steps even if certs pending), AppImage + Flatpak; auto-update check
(GitHub releases, off by default); README/website copy incl. the §B.8.8 "honest
limits"; SECURITY.md + threat model doc (§B.8.2); license decision (recommend GPLv3,
matching Sunshine — decide in M0).
✅ Accept: a non-developer follows README on two fresh machines and is streaming in
< 10 min; a non-developer enables unattended access and connects from a second
machine in < 5 min following README; §B.8.16 checklist green; release artifacts on
a tagged GitHub release.

**The desktop release (Linux + Windows; r7).** The operator's requirements of 2026-09-27 — unattended access with
administrator access, saved devices, a request sheet with a readable name and levels, a standalone app or an installed
one that starts with the computer, hardware encoding and decoding — for the initial release on Linux and Windows
(Part F.7). Efforts are days of implementation work, estimates, UNVERIFIED; "Windows PC" is the operator's Windows PC
with an NVIDIA GPU. Every milestone keeps the existing test set green unchanged and passes `cargo xtask verify`;
Security is mandatory for every trust surface, elevation path, credential store, parser and FFI; Privacy for the
address book, history, the device words and logs. M-UI-1 (the foundation) is done (`3aa1072`, Part G).

| # | Milestone | Scope | Tests | Effort | Mandatory checks | NEEDS-DEVICE (Windows PC unless noted) |
|---|---|---|---|---|---|---|
| 0 | Plan r7 | this revision (merged after M-UI-2) | `xtask verify` doc checks | 0.5–1 | Security confirms its changes are in | — |
| 1 | **M-FEAT-1** Device words | `tornect-core::words` (Argon2id, BIP39 list, golden vectors), identicon from `h` beside saved names only, the look-alike alarm on host sheets and the client's connect field, typed-code pairing when it fires (the host checks its own digits; no wire change), one derivation per second (§B.6.1) | golden vectors; alarm thresholds; a fired alarm never reaches an accept without the digits; the rate bound; W-B1…W-B8 | 2–3 | **Security mandatory** + Privacy | optional: Argon2id timing on a phone before the freeze |
| 2 | **M-UI-2** Home + address book (the redesign's scope, adjusted) | + `address-book.toml` with the `later` allowlist, `recent.toml`, history off stops both `last_seen` writers, words on cards, "not paired yet" entries, `tornect book export\|import` (§B.8.9.1) | round trips; Clear; history off writes nothing (incl. `known-hosts.toml` and `trusted-devices.toml`); export holds no password; import creates no pin | 3–4 | **Security mandatory** (export crypto, no password in any file, the alias rule, import creates no pin, the `later` allowlist) + Privacy | a Windows run of the pages |
| 3 | **M-FEAT-2** Session levels | `SessionDecision::AllowOnceAdmin`; `SESSION_ACCEPT.elevation`, `want_elevation` with golden vectors; the availability probe (location, `EnableLUA`, `FilterAdministratorToken`, `ConsentPromptBehaviorUser`/`Admin`, `PromptOnSecureDesktop`); the refusal to serve when started elevated with UAC on; the Linux polkit revocation; the client HUD level (§B.2.1) | the new keys' vectors; clamp to the most restrictive; view-only never elevated; an unavailable level ⇒ no button | 2–3 | **Security mandatory** (a wire change) | registry probes; the `PromptOnSecureDesktop` 0 prompt test; the polkit revocation at the build VM console |
| 4 | **M-UI-3** Trust surfaces + connect flow (adjusted) | + the four/three-answer sheet with the unavailable-level sentences, "wants to connect to this computer", words + alarm line, the typed-code pairing layout, the Tornect confirmation where Windows shows no prompt, the administrator answer never adjacent to Allow, re-arming after a Windows prompt, a raise or a restore | every E1-1/E1-2/N-1/M1-50 test unchanged; Deny first; accepts pointer-only, armed 1 s; an administrator answer never downgrades silently | 3–4 | **Security mandatory** (trust surfaces); copy | the sheet on Windows |
| 5 | **M-FEAT-3** Windows administrator helper | `tornect input-helper`, its pipe protocol, the UAC launch (attended), the on-demand helper task replacing `--elevated` (decision M1-57) with its hardened registration, lifetime and migration, the helper's own panic watch and exits, the `OpenInputDesktop` secure-desktop notice (B.8.7.5, B.8.8) | fake Task Scheduler + fake pipe unit tests; the helper refuses a wrong server and exits on close, host exit, `Stop` and a missed heartbeat; H1…H8 | 4–5 | **Security mandatory** (elevation path) | all of it: UAC (administrator and standard account), UIPI with and without the helper, the on-demand task, the secure-desktop notice, the panic key with an elevated window focused |
| 6 | **M-FEAT-4** Unattended client + saved credentials | GUI and CLI unattended connect (`Intent::Unattended`, the B.8.10 prompt), Remember in the keychain (Windows store, Secret Service, keyutils), presence gating where cheap, the admin-grant rule, the derived entry name (B.8.9.1) | never auto-retried; stale only on `AUTH_FAILED`; no password in any file | 3–4 | **Security mandatory** + Privacy | Credential Manager; Windows Hello if used |
| 7 | **M-FEAT-5** Unattended host completeness | **first, before any grant can hold the level:** a verified EFF long word list with its checksum, so that the passphrase generator works (the later track of decision M1-19); then the F4-1 closure (M1-67) — `grant_reach` in `SESSION_ACCEPT` and in every `ADMIN_RESULT` (the requester's grant re-loaded and checked inside the guard's admin operation, under the store lock that applies the command, and before the early refusals; an `AdminRequest` line for the early refusals; the admin call takes the receipt's digest and returns `grant_reach` or a reject, the guard gets a source of the account settings and the helper task's presence, revoke, revoke-all and master-off get locked variants); after the reservation, a read of the account settings and the helper task's presence outside the store lock (a presence that cannot be read counts as registered), then one store operation that checks the proven `auth` (the receipt keeps SHA-256 of the cloned stored `auth` record, a new receipt field never logged, sent or printed) and refuses a grant no longer eligible, reads the store, feeds the clamp, `grant_reach`, the mark and F-12, and only lowers (a new `UnattendedHook` method after `Reserved::take`, never called under the live-session lock, a new public core call); the gate's receipt applying the mark and F-12 so that no helper starts for a session the read lowers; the last no-session check of every access-increasing guard operation inside the store operation that commits it, a refusal logged after the lock or through the locked logger after any rollback and the head write; `control_is_administrator` from the facts, installed or standalone, read at each answer from a platform read that reports the facts or that they could not be read, a failed read counting as true; the "answered 0" mark (store key 25 `unmarked`, absent = marked, a policy write before the accept is signed; restore, import and a store that adopts a machine id mark); a per-device session end, ≤ 1 s, for revoke, disable, suspend and a lowering (§B.8.4's host table), tested with a session reserved and with one live; golden vectors; the client's decision at the verified answer before QUIC (`Attempt::Accepted{elevation, grant_reach}`, `Attempt::AnswerRefused` from a new error that names a refused `SESSION_ACCEPT` or `ADMIN_RESULT`, the admin settle, every `Attempt::Accepted` call site, the delete before `hosts.toml`, the delete before a write, the `reach` flag, the admin settle taking no password to keep, the View-only note, the CLI's host-naming notes through the terminal-only gate); the raise through set-password's `options` (`RegFinish` and the window's `set_password`), `generated` on `RegFinish`, `create_grant` and `set_password`, `raise` and `generated` declared at `RegStart` with its own wording, with `set_options` refusing the raise, a creation with reach refused without `generated`, and *enable* refusing a still-marked admin grant whatever disabled it (`G_NEEDS_PASSWORD`); the Linux root check from the effective user, failing closed; a default-yes console question on every platform; generated passwords printed only to a terminal; the lowering, including an accept being prepared; store key 24; the host CLI forms of B.8.7.4; then the block window (B.8.6.3) and "Ask before starting" with the level; the "N devices can connect without asking" badge; admin grants (field, guard, `G_UNSUPPORTED` on Linux, the wizard warning); the readiness probes the wizard needs (incl. "indicator shown", "administrator helper registered"); the Windows named-pipe control channel (the M6 item) so `tornect panic` and the CLI work; the panic hotkey (Windows low-level hook; GNOME GlobalShortcuts where available, else "not bound"), never on the UI thread; F-12's rule on the same predicate; the prompt's keyutils name; keyutils unusable without a persistent keyring | the U/A rows of §B.8.15 touched; Block ⇒ no capture; panic < 100 ms; A20–A25; the seven new `grant_reach` golden vectors 4 to 10 of `docs/notes/m1-golden-vector.md` (unattended accepts: Control with `elevation` absent at reach 0, 1 and 2, Control with `elevation` 1 at reach 2, View only at reach 2; `ADMIN_RESULT` ok at reach 0 and refused at reach 1) and every existing vector unchanged; two accepts that differ only in `grant_reach` compare unequal; F-8's test still fails with the client check removed; `settle` never reads the cache flags; the host value over `want_mode` × `want_elevation` × helper on time or late × each fact and the mark; the release coupling; the four guard invariants of M1-67 (B.8.6.1–2: no grant at administrator becomes `Active` or raised without a new `auth`, except creation, *enable* of an unmarked `Disabled{Ui\|Cli}` grant, *resume* and the remote *unlock*; no marked password reaches the level; the release coupling; every access-increasing operation while a session is reserved is refused and logged once, without a deadlock); the store key 24/25 decode test; `an_administrator_grant_keeps_no_password_without_a_presence_gate`, `remember_is_offered_only_with_a_keychain_and_never_for_administrator_without_a_gate` and `the_prompt_offers_remember_only_where_it_may` rewritten for the new rule; `docs/notes/m1-golden-vector.md` regenerated and the fuzz seeds kept matched | 6–8 | **Security mandatory** (a wire change, a credential rule) + Privacy (the copy) | pipe, hook, readiness, a reboot + automatic sign-in + an unattended session; **MUST:** before the first admin grant exists on the Windows test machine, every client device used against it runs an M-FEAT-5 build (an M-FEAT-4 client ignores `grant_reach` and keeps a password at 1 and 2; the operator stated on 2026-10-01 that no build made since M-FEAT-4 left the build machine); an admin grant used without the level, Remember ticked: no entry in `cmdkey /list`; CPBA set to 0 while the host runs: the next answer says 1 and the session is View only; UAC at the raise; the helper task's presence query |
| 8 | **M-UI-4** Viewer toolbar (adjusted) | + the level chip ("Control · administrator"; "control", "view only" and the unattended badge as built), the UIPI line and the secure-screen notice from the host's PONG notice (§B.8.4.1); the local chord Ctrl+Alt+Shift+M (ReleaseAll first, never forwarded; it takes the keyboard back and shows the toolbar, named in its help line); Send keys in control sessions only: Ctrl+Alt+Del is sent only to a host that says it does not run Windows, greyed "not possible on Windows computers" on one that says it does, and greyed without a note until the host says. Defaults (the operator, 2026-10-07): screenshots to Pictures/Tornect as "Tornect screenshot <date time>.png", never the host's name, the saved-path toast hidden while this screen is shared; End session in one click; the toolbar hides after 2.5 s (a constant until the settings page; the pin is not stored); the window closes at the session's end | view-only sends nothing; send-keys only in control; the chord sends `ReleaseAll` | 2–3 | **Security mandatory** (input gating); Privacy (screenshots) | the Ctrl+Alt+Del copy on Windows |
| 9 | **M-FEAT-6** Product modes | `tornect install\|uninstall` (Windows: guard + UAC, Program Files, the ACL check, Start menu, uninstall entry); the Linux per-user install + `.desktop`; `--background`; the at-logon task and an XDG autostart entry start the app (decision M1-58); `IpcOp::Show`; the "indicator shown" gate (§B.1.1) | fake installers; the headless host stays pings-only; a second launch shows the first | 3–4 | **Security mandatory** (install and autostart); Privacy (the Tor-at-sign-in copy) | install, reboot, sign-in, minimised start; GNOME minimise and the XDG entry's session (build VM console) |
| 9a | Panic suspend | after the host-wide kill, the panic key and `tornect panic` suspend the grant of each device whose unattended session they ended, live or past its PAKE (`Suspended{Panic}`, cleared only by a local *Resume*, §B.8.6.3, B.8.7.4); the kill stays first; the double press stays master off | the kill first and < 100 ms; the suspended device refused until resumed; an attended session suspends nothing | 0.5 | **Security mandatory** | panic during an unattended session from the Windows PC |
| 10 | **M-UI-5** Settings + Sessions (adjusted) | + the wizard's Administrator step (Windows) with its warning, the Linux explanation, "Start Tornect when I sign in" and the install state, the history switch covering both `last_seen` writers; ⑤a's password rule (generator only while `grant_reach` is or becomes non-zero; a chosen password leaves the mark; only the generator path sends `generated`), the raise, mode → Control and restore steps, the ⑤a offer with its unticked line naming the marked devices, the turn-off line with its condition, the address book's two View-only lines (§B.8.6.1), the host card's count of admin commands from a device that ran nothing, with no new logged data, the Privacy page line "For each computer you connect to unattended, this device keeps whether a password is remembered and whether your access there is control or reaches administrator access; Forget removes it.", and the prompt sentences of B.8.10 (M1-67); as the operator ruled on 2026-10-07: General shows the name others see (the neutral default), the theme (Dark, Light or Match the system; Dark by default), the install state with the command that installs (no install button) and "Start Tornect when I sign in"; no language row, no Test connection, no incoming-requests switch, no new stop code outside a re-enable or a use; reduce motion is M-UI-6's; backup export and import stay on the command line; Pause offers 12 h and until re-enabled (until 08:00 OPEN until a zone source exists, ruling of 2026-10-09); the history switch stays in the address book's Recent tab and the Privacy page mirrors it (one setting); the screenshots folder is a line of text; the first-run name prompt comes before the first pairing or connection sends the name; the diagnostics view is the doctor report without IDs, the device name, user paths, onion addresses and labels; Display and quality keeps the viewer's defaults (picture size, fullscreen at open, the toolbar's hiding, the badge) | every access-increasing op through the guard with a fake re-authentication; never instant-apply; zeroized fields; the raise cannot finish without the new password; no "use my own" while `grant_reach` is non-zero; the unticked line shown; a cancelled prompt lists the remaining devices; the card's count rises for an admin command that ran nothing | 6–7 | **Security mandatory**, also for ⑤a's password path (the guard trusts the wizard's `generated` flag, §B.8.7.4) + Privacy (the copy) | the wizard on Windows |
| 11 | **M-UI-6** Polish | as the redesign | snapshot × scale | 1–2 | **Security mandatory** (confirms no trust-surface change); UX | — |
| 12 | **M-CODEC-1** Abstraction + conformance | traits, registry, fallback, `doctor` lines, the parser gate (§B.5), the GPU YUV→RGB shader, a golden stream | unit, property, fuzz, golden CRCs | 2–3 | **Security mandatory** (parser); Architecture | — (build VM) |
| 13 | **M-CODEC-2** Windows Media Foundation | the async hardware MFT encoder (BGRA→NV12, Constrained Baseline, CBR, forced IDR) + the MF decoder behind the gate | cross-check; conformance | 3–4 | **Security mandatory** (COM/FFI, DLL loading, hostile decode); Performance | conformance, the hostile corpus, ms/frame |
| 14 | **M-CODEC-3** NVENC (Windows) | own bindings (struct versions checked against the driver's maximum), a D3D11 device, system-memory input first | as above | 3–4 | **Security mandatory** (driver FFI); Performance | as above; fps over Tor |
| 15 | Release-range security pass | slices as D–G over everything above; fixes | a regression test per finding | 3–5 | **Security mandatory** | — |
| 15a | Final Windows pass (with a standard account) | after row 15, before the tag: attended administrator on an administrator account and on a second, standard Windows account; UAC cancelled, then the sheet re-armed; unattended administrator through the task; the task removed with the last admin grant and at uninstall; the old whole-host task removed at upgrade; panic, Stop and `tornect panic` with an elevated window focused; the secure-desktop notice; `PromptOnSecureDesktop` 0; the M-UI-4/M-UI-5 surfaces and every row-15 fix | a written checklist | 0.5–1 | **Security mandatory** (its checklist) | yes |
| 16 | Pre-tag docs pass | Part G rows; README honest limits (the plain statements of §B.1.1, B.8.8, the release's limits below); SECURITY.md (the helper, T9); the release notes and the release README, whose lines on the whole-host elevated task (incl. "cannot be started on demand") are rewritten; VERIFICATION rows; the code-signing decision (Part F.8) | `xtask verify` doc checks | 1–2 | Security reads the security statements | — |
| 17 | Console check | the GUI over real Tor, build VM ↔ Windows PC: pairing with words, the four answers incl. UAC, an unattended administrator session, codecs, the start after a reboot | Security's written checklist | 0.5–1 (the operator present) | Security (checklist) | yes, both machines |
| 18 | Dist + tag | `cargo xtask dist` at the tagged head; the operator's go | reproducible zips; Security reads the manifest (no NVIDIA file, licence texts present) | 0.5–1 | Security (manifest) | — |

Total ≈ 49–69 days (UI 15–20, features 20–27, codecs 8–11, plan, Windows pass and release 6–11). Order: row 0 →
M-FEAT-1 → M-UI-2/M-UI-3 (words and levels on screen) → M-FEAT-3/4/5/6 → the panic suspend (row 9a) → M-UI-4/5/6, with the codec track (rows 12–14)
beside it. The Windows PC is needed in batches: after M-FEAT-3 (elevation), after M-FEAT-5/6 (unattended, autostart),
after M-CODEC-3 (codecs), the final pass (row 15a), then the console check.

**The release's limits** (stated in the README and the release notes): every session is relayed through Tor (decision
M1-60), and the 20-unit ack window caps any encoder at about **16 fps** at 1.2 s round trips (13.2 fps measured for the
1280×720 test card, M1-47); hardware encoding lifts large desktops toward that cap and frees the host CPU but does not
raise it — direct connections (M2, next after the release) do; AMD and Intel on Windows are designed through Media
Foundation and untested (NEEDS-DEVICE(windows-amd), NEEDS-DEVICE(windows-intel)); Linux has software encoding only;
"starts with the computer" means starts at sign-in (§B.1.1); code signing is open until the pre-tag pass (Part F.8).
**Not in this release:** direct connections (Part C M2 — next, decision M1-60), Windows service mode (M-SVC-W, after the
release, decision M1-61), Android (backlog).

**Post-v1 backlog (tracked, not planned here):** file transfer UI · Android (entry below) · "bring your
own relay" · per-app window streaming · virtual display driver (headless hosts) ·
H.265 4:4:4 / AV1 SCC tuning · Wake-on-LAN via a second LAN device · iroh backend
feature flag · MoQT alignment once RFC · Windows service mode M-SVC-W (entry below) · TPM-sealed keystore for headless hosts (§B.8.2 T3b).

Roadmap entries of r7:
- **Direct connections (M2)** — next after the desktop release (decision M1-60); they expose IP addresses to the peer
  and change the threat model, so they get their own security pass.
- **M-SVC-W, Windows service mode** — after the initial release (decision M1-61): a LocalSystem service started at boot
  hosts the onion service in session 0; a per-session process is launched into the active console session
  (`WTSGetActiveConsoleSessionId`, a SYSTEM token given that session id, `CreateProcessAsUser`) and follows the input
  desktop (Default ↔ Winlogon) for capture and input, with `SendSAS` for Ctrl+Alt+Del. That reaches the sign-in
  screen, the lock screen and UAC prompts, and survives a reboot without automatic sign-in. Which capture API works on
  the Winlogon desktop is UNVERIFIED. Consequences: the identity key, grants and `K_master` move from the user's DPAPI
  scope to machine scope (a B.8.9 rewrite); OS re-auth becomes "an administrator of this PC"; multi-user hosts must be
  decided; network parsing inside a SYSTEM process is the largest privilege Tornect would ever hold, so its own threat
  model comes before any code (§B.8.17 item 6). Estimate 15–25 days, NEEDS-DEVICE(windows) throughout.
- **Codecs:** M-CODEC-4 MediaCodec (with Android, behind the §B.5 parser gate); M-CODEC-5 a decoder-capability
  negotiation for High profile, HEVC and AV1; M-CODEC-6 VA-API and NVENC over CUDA on Linux, enabled once a test machine
  exists; an out-of-process decoder with a restricted token (recommended).
- **One set of device words per machine** (the client proving its onion key at pairing) — a wire change (§B.6.1).
- **Android** (decision M1-66, Part F.7) — after the desktop release. The client is feasible; the host is feasible **as
  an attended host only**: Android 14 and later need a person at the system capture dialog for every session, so
  unattended hosting could only be faked. First the client and a view-only host; the host on Android 14+, the client
  on Android 12+; no pluggable transports in the first Android build; "Allow as administrator" does not exist on a
  phone. The release signing key is generated on the build machine and handed to the operator, and its certificate
  fingerprint is published. Backup policy: no cloud backup and no device transfer of keys or pairings, and the release
  build is not debuggable. Device words are identifiers there too: never in notifications or the release log. The UI
  question (egui with a thin Kotlin shell, gated by a 2–3 day spike; Compose for the Android UI only as the fallback)
  is decided when Android starts. Carried constraints: the device-word parameters are frozen by the desktop release
  (§B.6.1); a phone client needs a new PAKE suite id if 64 MiB Argon2id is too heavy (§B.8.17 item 4). Milestones
  M-AND-0…8. Toolchain: JDK 17, the Android SDK, an LTS NDK, the `aarch64-linux-android` Rust target, `cargo-ndk`, and
  Gradle with AndroidX GameActivity — pinned when M-AND-0 starts.

---

## Part D — Claude Code execution kit

This part is the operating manual for building Tornect *with Claude Code as the
engineering team*: one orchestrating session + specialized subagents, verification
loops, and per-milestone kickoff prompts. Companion file `CLAUDE.md` (repo root)
carries the always-in-context rules; this section carries the process.

### D.1 Ground rules for the build

1. **Milestones are sacred.** One milestone per Claude Code "epic"; never start
   M(n+1) with M(n) red. Tag `m0`…`m8` — and `u1`…`u5` for the UI milestones of
   `docs/UI_PLAN.md` §11 (Part F.6) — on completion.
2. **Plan mode first** for every milestone: read this plan's relevant sections,
   produce a task DAG, identify what can run in parallel, get user sign-off.
3. **Verify like a hostile QA.** Every task ends with: `cargo fmt --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test
   --workspace`, plus the milestone's runtime demo. Claude Code must *run* things,
   not assume. Media code additionally: run the loopback demo and read the HUD
   stats it prints to stdout in `--headless-stats` mode (build this flag in M3
   precisely so agents can self-verify without eyes).
4. **Reality beats memory.** Any new dependency, OS API, or FFmpeg detail:
   `research-verifier` agent checks current docs/crates.io first. Pin exact
   versions; record rationale in `docs/DEPENDENCIES.md`.
5. **Platform code needs platform machines.** Claude Code can only *run* the OS
   it's on. Cross-platform milestones: write + `cargo check --target` everything,
   but mark runtime verification as `NEEDS-DEVICE(<os>)` in `VERIFICATION.md`; the
   user (or a Claude Code session on that machine) clears them. CI cross-compiles
   keep honesty.
6. **Small PRs, real commits.** Conventional commits; every commit compiles; git
   worktrees for parallel subagent tracks (`git worktree add ../tornect-wgc m6-wgc`).

### D.2 Repository control files to create in M0

```
CLAUDE.md                        # companion file provided with this plan
docs/PLAN.md                     # THIS document, committed verbatim
docs/DEPENDENCIES.md             # dep → version → why → verified-on date
docs/VERIFICATION.md             # NEEDS-DEVICE ledger + soak/netem results
.claude/agents/*.md              # subagents from §D.3
.claude/commands/milestone.md    # /milestone <n> → loads Part C entry + D.6 prompt
.claude/commands/verify.md       # /verify → runs the full gate + demo for cwd crate
.claude/commands/research.md     # /research <topic> → invokes research-verifier
.claude/settings.json            # permissions: allow cargo/git/rustup; deny
                                 #   destructive (rm -rf outside target/, curl|sh);
                                 #   hooks: PostToolUse Edit→rustfmt on touched file;
                                 #   PreCommit→clippy -D warnings
```

### D.3 Subagent roster (`.claude/agents/`)

| Agent | Model tier | Charter (1-liner) | Tools |
|---|---|---|---|
| `architect` | most capable | Owns §B invariants; reviews designs & cross-crate APIs before implementation; plan-mode partner | read-only + web |
| `research-verifier` | fast | Verifies versions/APIs against live docs before any dep or OS-API usage; outputs a sourced note into docs/DEPENDENCIES.md | web + read/write docs only |
| `net-engineer` | most capable | tornect-signal, tornect-net: Arti, punching, quinn, fallback | full |
| `media-engineer` | most capable | tornect-capture/codec/audio/proto: per-OS capture, Media Foundation / NVENC / OpenH264 (D8, r7), FEC/ABR | full |
| `platform-{windows,macos,wayland}` | capable | The three M6 parallel tracks; each owns its capture+input+audio backend end-to-end | full, own worktree |
| `ui-engineer` | capable | egui shell + stream window on one manual winit loop (D10, r7), sheets, indicator, onboarding, HUD | full |
| `security-reviewer` | most capable | Adversarial review at each milestone close: §B.6 checklist, unsafe-block audit, fuzz targets, "how would I abuse this popup flow?"; the §B.8.16 checklist on any diff touching unattended access, PAKE, grants, the keystore or the mutation guard | read-only + test-run |
| `qa-engineer` | capable | Integration/netem harnesses, soak scripts, PLATFORM_MATRIX.md, keeps §B.7 gates executable | full |

Example agent file (create the rest in this shape):

```markdown
---
name: media-engineer
description: Implements and optimizes Tornect's capture→encode→transport→decode→render
  pipeline (crates tornect-capture, tornect-codec, tornect-audio, tornect-proto).
  Use proactively for any media-path task.
tools: Read, Edit, Write, Bash, Grep, Glob, WebSearch, WebFetch
---
You are Tornect's media pipeline engineer.
Authoritative context: docs/PLAN.md §A.2, §B.4, §B.5, §B.7. Read them before acting.
Non-negotiables:
- Zero-copy GPU path is the goal; any CPU download of a frame needs a `// PERF:` note
  and an issue.
- Low-latency encoder config always: no B-frames, intra-refresh, ≤1 lookahead, CBR.
- Every frame carries timestamps; every stage records into the stats pipeline; the
  loopback demo's --headless-stats output is your acceptance instrument — run it.
- Codec API use (Media Foundation, NVENC) must be verified against the vendor's
  documentation (delegate to research-verifier when unsure).
- unsafe only at FFI edges, each block commented with safety invariants.
Definition of done: clippy-clean, tests green, loopback demo meets §B.7 numbers on
this machine, DEPENDENCIES.md updated if deps changed.
```

### D.4 Orchestration patterns (when to parallelize)

- **Serial** (main session, agents as consultants): M0–M1, `u1`, M2–M4 — the layers stack;
  `u2`/`u4`/`u5` are interleaved inside M4/M7/M8 and `u3` runs serially after M6 (Part F.6).
- **Parallel worktrees**: M6 — `platform-windows|macos|wayland` implement against
  the frozen traits from M3–M5 simultaneously; `architect` freezes trait signatures
  first; merge order: wayland (dev machine verifiable) → windows → macos.
  Also M8: `ui-engineer` ∥ `qa-engineer` ∥ packaging.
- **Fan-out research**: at each milestone start, orchestrator may launch 2–4
  `research-verifier` tasks concurrently (e.g. M2: "current public STUN etiquette /
  igd-next status / quinn datagram MTU guidance / draft-seemann punch pacing").
- **Review gate**: `security-reviewer` runs at every milestone close *and* on any
  diff touching signal/net/pairing/consent/unattended (PAKE, grants, keystore, mutation
  guard); findings become blocking tasks.
- **Context hygiene**: long milestone? Have the orchestrator write
  `docs/notes/m<N>-state.md` (what's done, what's next, gotchas) before /clear;
  next session resumes from it.

### D.5 Verification harness (build in M0–M3, then it guards everything)

- `xtask verify` = fmt+clippy+test+doc-tests, then per-crate extras.
- `tests/netem/run.sh <profile>`: Linux netns pair with tc netem (delay/jitter/loss
  per profile), runs headless host+client, asserts §B.7 gates from stats JSON.
- Fuzzing: `cargo-fuzz` targets for envelope parsing, datagram reassembly, input
  event decode, the §B.8 messages (`HELLO_ACK`, `SESSION_REQUEST.unattended`,
  `AUTH_CHALLENGE`, `AUTH_RESPONSE`, `ADMIN_RESULT`) into both state machines, the
  KE1/KE2/KE3 deserializers, the unattended store and limiter loaders and the IPC
  messages (security-reviewer owns corpus).
- Soak: `xtask soak --minutes 30` wraps loopback with leak checks (RSS slope) —
  media code is where leaks live.
- CI (GH Actions): lint+test on 3 OS runners; cross-`cargo check` all targets;
  netem suite on Linux; artifact build on tags.

### D.6 Kickoff prompt — paste this to start Milestone 0 in Claude Code

```
Read docs/PLAN.md fully (it's the Tornect master plan) and CLAUDE.md.
We are executing Milestone 0 (Part C). Enter plan mode: produce the M0 task list,
then implement it. Follow Part D ground rules strictly — especially the
verification gate and creating the .claude/ control files exactly as §D.2/§D.3
specify (write all eight agent files using the provided template's shape, adapted
per the roster table). Ask me only for: (1) license choice [default GPLv3],
(2) which OS this machine runs [detect and confirm], (3) GitHub repo URL for CI.
Finish by tagging m0 and printing the M1 kickoff prompt.
```

Per-milestone kickoffs follow the same shape: *"Read docs/PLAN.md Part C entry M<n>
+ referenced §B sections; plan mode; identify parallelizable tracks per §D.4;
implement; run §D.5 gates + the milestone's Accept demo; update VERIFICATION.md;
tag."* — `/milestone <n>` (created in M0) expands to exactly this.

---

## Part E — Risk register

| Risk | L×I | Mitigation |
|---|---|---|
| Arti API churn / embedding edge cases | M×H | Pin minor version; wrap all Arti in `tornect-signal` behind our trait; research-verifier watches release notes; worst case: external `arti` process mode behind same trait |
| Punch success below expectations (CGNAT-heavy regions like BR mobile ISPs) | M×M | Tor fallback is first-class UX, not an error; collect (local-only) success stats; v2 BYO-relay |
| Wayland portal/compositor variance (GNOME vs KDE vs wlroots quirks, token invalidation on session change) | H×M | `platform-wayland` maintains a compositor quirk table; SHM fallback; test on GNOME+KDE+Hyprland in M6 |
| macOS TCC + notarization friction | M×M | Onboarding walks Screen Recording + Accessibility grants with live status checks; document notarization in xtask even before certs exist |
| Hardware encoder behaviour differs per vendor and driver (r7; replaces r6's FFmpeg interop row) | M×M | The conformance harness (M-CODEC-1), a per-backend deny list, one wire format (Constrained Baseline), OpenH264 always compiled in |
| The on-demand administrator helper task (r7): while an admin grant exists, same-user code can start it and every Control session can reach administrator windows (T9) | M×H | The task exists only while an admin grant exists; hardened registration, the helper's own panic watch and exits (B.8.7.5); the wizard warning; accepted by the operator (decision M1-62) |
| In-process indicator (r7): a hung UI thread also hangs the indicator's Stop | L×M | A crash ends the session with the indicator (fails closed); `tornect panic` and the panic hotkey do not depend on the UI thread (M-FEAT-5); a UI-thread watchdog is recommended |
| Latency regressions creeping in | H×M | §B.7 gates are executable (netem suite in CI-linux + headless-stats), regressions fail the build |
| Scope creep (it's a fun project) | H×M | Post-v1 backlog exists precisely to say "later"; milestones gate features |
| Abuse of remote-access software | L×H | §B.6 consent architecture: no silent sessions, persistent indicator, panic key, local session log — these are requirements, not options |
| Unattended-access abuse or lockout DoS (stolen/cloned device keys, coached relatives, a hostile Control session, the owner locking themselves out, keychain unusable at autostart, lock-screen dead ends) | M×H | §B.8: two factors + per-grant OPAQUE; count-based ladder with lifetime budget, per-grant scope, no global breaker; remote revoke/unlock from another *My machines* Control device + emergency stop code; OS re-authentication for every access-increasing change through Tornect's own surfaces (endpoint-level rewrites by a Control session are out of scope, T9); file-keystore fallback with a stricter password policy; honest per-OS readiness (§B.8.8); the adversarial A-suite is cumulative — each milestone's rows are listed in §B.8.14 and gate it |
| Tor fallback transport contradicts the research: §B.2/§B.8.4.2/M2 tunnel the same QUIC connection through the onion stream for a uniform `BIND` check, while quic.md §0/§9 argues for the session protocol directly over the onion stream (double congestion control, wasted Initial padding/DPLPMTUD probes, extra handshake RTTs) | M×M | §B.8.17 item 7: decide at M2 with a measured onion-stream throughput; if direct, a `BIND` equivalent over the onion stream (HMAC over `th` + `session_token`) keeps the token check uniform; the M2 accept row for the Tor tunnel is then re-worded, not dropped |

## Part F — Open product decisions (answer before/at M0)

1. License — recommend **GPLv3** (ecosystem-compatible with Sunshine; protects
   against proprietary forks). **Decided (2026-08-28, M0-1): GPL-3.0-or-later.**
2. Primary dev OS for M3–M5 (whatever your daily machine + GPU is — say it and the
   plan adapts; Wayland machine recommended since it's the trickiest stack).
   **Decided (2026-08-28, M0-2): Linux/Wayland — GNOME on Ubuntu 26.04 (the build VM,
   VMware virtual GPU: no hardware encoder, so hw-codec gates are `NEEDS-DEVICE(gpu)`).**
3. Unattended access in v1 (M8) or push to post-v1? **Decided (2026-08-28): v1,
   opt-in per device, per §B.8** — protocol M1, session gating M4, platform M6, UI M8.
4. Minimum supported targets: Windows 10 20H1+ (WGC needs it) / macOS 13+
   (ScreenCaptureKit maturity) / xdg-desktop-portal ≥ 1.17 distros. **Decided
   (2026-08-28, M0-4): confirmed; GNOME ≥ 45 added by §B.8.1 for the RemoteDesktop v2 portal.**
5. Name/branding check: "Tornect" — quick trademark/collision search before public
   release (research-verifier task in M8).
6. UI-foundation milestone placement (Part G, UI plan adopted). **Decided (2026-08-29, r6
   review): `u1` = U0 + U1 of `docs/UI_PLAN.md` §11, executed right after M1 and before M2 —
   serially (D.1 rule 1, D.4), never interleaved; Accept = the U0 and U1 rows, the two-machine
   pairing part `NEEDS-DEVICE`; tags `u1`…`u5` (D.1); M2 starts only after `u1` is green; `u2` = U2 inside
   the M4 epic (tag `u2` before `m4`), `u3` = U3 serial after M6 (tag `u3` before M7 starts), `u4` = U4
   inside M7 (tag `u4` before `m7`), `u5` = U5 inside M8 (tag `u5` before `m8`) — a UI tag hosted by an M
   epic is cut at that milestone's Accept, and every UI tag counts as red for D.1 rule 1;
   `research-verifier` pins `iced`, `tray-icon`, `notify-rust`, `fluent` and the AccessKit
   integrations first.** (r7: `iced` leaves the list — egui everywhere, D10.) The owner may swap `u1` and M2 by amending this item.
7. Platforms of the initial release. **Decided (2026-09-27, decision M1-66): Linux and Windows first; Android on the
   roadmap** (the operator: "focus on linux and windows versions, android we can add to the roadmap"). Android, when it
   starts (Part C backlog): an attended-only host; the client and a view-only host first; the host on Android 14+, the
   client on Android 12+; no pluggable transports in the first Android build; the release signing key generated on the
   build machine and handed to the operator, its certificate fingerprint published; no cloud backup and no device
   transfer of keys or pairings, and no debuggable release build. Toolchain: JDK 17, the Android SDK, an LTS NDK, the
   `aarch64-linux-android` Rust target, `cargo-ndk`, Gradle with AndroidX GameActivity.
8. Code signing (Windows). **Open — the operator decides at the pre-tag pass** (Part C, the desktop release, row 16).
   Without a code-signing certificate every Windows administrator prompt names "Unknown publisher" for `tornect.exe`,
   which trains people to accept unknown prompts, the habit the support scam of T10 exploits. Options: obtain a
   certificate before the tag (cost and identity checks are the operator's), or ship unsigned and say so in the README.

---

## Part G — Execution status (kept current at every session hand-off)

Last update: **2026-09-27** (plan r7 and the UI foundation; before them the sessions of 2026-09-23 and 2026-09-24). Repository: https://github.com/Mxrider420z/Tornect (private,
branch `main`). Per-milestone detail lives in `docs/notes/m<N>-state.md`; every acceptance
check with its real status is in `docs/VERIFICATION.md`; every deviation from this plan is a
numbered row in `docs/notes/decisions.md`.

| Milestone | Status | Evidence / where |
|---|---|---|
| M0 Bootstrap | **Done**, tag `m0` (commit `5c7a52d`) | Workspace, `tornect-core` (onion-v3 `TornectId` proven against real addresses, identities, 0600 keystore, config, paths, tracing, `sessions.log`), CLI `id/rotate-id/paths/config/doctor`, `xtask verify`, Claude Code kit, GPLv3, README. CI file written but not yet pushed (see pending actions). |
| Research | **Done** (commit `36a5b0f`) | `docs/research/{arti,quic,crypto,nat,wayland,codecs,ui,ci,media-proto}.md` + `SUMMARY.md` audit — verified against crates.io, crate sources and live probes; all pins in `Cargo.toml` come from these. |
| Plan §B.8 | **Done** (r4 → r6); two items deferred to r7 | Unattended access specified end-to-end (r4, commit `c515f0d`); the two r5 findings of `docs/notes/m1-state.md` (runtime decay monotonicity; local Suspend reason `Suspended{Local{by}}`) applied in r6 and tightened by the r6 review pass (`credit`/`Clock` rules, monotone `last_seen`, Suspend/Resume surfaces) — ticked off in that note. Deferred to **r7** by the M1 implementation review (decisions M1-31/M1-32): whether `PAIR_REQUEST`/`PAIR_ACCEPT` carry signatures (§B.3 lists `PAIR_ACCEPT` unsigned, so a pairing-only exchange has no signed frame), and whether `quic_spki` binds the pairing-pinned `host_device_pk` instead of the onion identity key (M1 implements the onion key; §B.6 requires it to equal the pairing pin). |
| M1 Signaling over Tor | **In progress — track 1 + phase-2 part 1 done** (commits `0e568d8`, `cd878f3`) | Arti embedded (`tornect-signal::tor`), `tornect host` / `tornect ping` verified live over Tor (same ID after restart, 0.5–1.1 s RTT, PoW-aware admission). Phase-2 part 1: `tornect-core::unattended` (store + generation anchor, `Clock` + `AttemptLimiter`, `MutationGuard` + `ReAuth`/`RemoteSessionActivity`/`Presence`, `ReadinessSnapshot`, IPC types + codec, log chain, password policy) and `tornect-signal` (CBOR envelope, messages, transcript + golden vectors, pairing/SAS, attended host/client FSMs, `SessionAccept::build`), fuzz targets F1/F3/F4; `cargo xtask verify` green with 152 core + 116 signal tests; decisions M1-7…M1-36. Round 3 done 2026-09-04 (`5391f76`, `7762849`, `3ee4943`): 38 raw findings → 3 confirmed (the grindable SAS of decision M1-37, a locked-keystore log-chain break, an untested password escalation), all fixed with regressions; gate green at 271 tests. Track C done 2026-09-04 (`08d391a`, `324b4d4`, `fc48e24`): the OPAQUE-3DH authenticator and the B.8.4.3 key schedule, the host branch with the full B.8.4.5 ordering and the B.8.5.2 budgets, the client branch with the `server_s_pk` TOFU pin, and a headless end-to-end unattended session over a duplex pipe; gate green at 286 tests. Track D done 2026-09-05 (`fbc7a31`, `be58ea6`, `48ca97e`): admin intent + scope wired to `MutationGuard::admin` through a new `AdminAuthority` seam, the §B.8.7.4 emergency stop wired to `StopTokenCheck`, and a §B.8.4.2 ordering defect fixed — the admin branch ran *after* `post_f2`, so the schedule / transport / cooldown gates the spec says are skipped for an admin request were being applied, refusing `revoke`, `revoke_all`, `master_off` and `end_session` outside a grant's schedule window; pinned by a regression that fails against the pre-fix ordering. `crates/tornect-platform` created with the two §B.8.14 M1 modules: `ipc` (owner-only Unix endpoint, `SO_PEERCRED` compared against the socket's own owner, no `libc` and no `unsafe`) and `reauth` (polkit over the system D-Bus, verified against live polkitd 127; `zbus` =5.19.0 pinned, `packaging/polkit/org.tornect.policy` shipped for the operator to install). PAM is not used and does not need to be — polkit runs the PAM conversation itself out of process, which is why §B.8.8 and the §B.8.14 M1 row above were amended. The `tornect unattended|devices|panic|service|backup` CLI and the host-role IPC dispatch loop landed with it, one dispatch behind both the socket and offline routes; gate green at 320 tests, and the CLI exercised by hand including a pty-driven `grant`. **`serve_host` is wired into `tornect host` (2026-09-21, decision M1-42).** The host answers the FSM and the pairing-free ping on one port, `tornect connect` pairs and runs attended sessions, `tornect panic` ends them, and the guard sees them; pairing plus attended sessions are verified live over Tor on one VM. **Remaining:** an unattended client CLI (`Intent::Unattended` is test-only), `tests/integration`, the adversarial sweep, the `security-reviewer` milestone close, live unattended and two-machine verification, then tag `m1`. Detail: `docs/notes/m1-state.md`. |
| M1 session 2026-09-21 | **Bridges done; track D reviewed, survivors unfixed** (commit `213e7d9`) | Censorship circumvention (decision M1-38): direct → obfs4 → Snowflake ladder, a fresh Arti client per rung, `ready_for_traffic` only, last good rung remembered; Tor Browser 15.0.23 built-in bridges; lyrebird 0.8.1 (serves obfs4 and Snowflake) from the GPG-verified expert bundle, pinned in `packaging/pt/SOURCES.md`; live direct 14.3 s / obfs4 78.2 s / Snowflake 16.2 s (`docs/research/bridges.md`). Track D hostile review re-run: 105/105 agents, 33 raw → 12 survivors (8 distinct, one HIGH verified by hand) — fixes are the next item (`docs/notes/CONTINUATION.md`). Media port 4001 + same-circuit `connect_on` (M1-39). `serve_host` is still not wired into `tornect host`. |
| M1 session 2026-09-21 (2) | **Track D fixed; slice range reviewed and hardened** (commits `5523fcc` … `81da800`, gate 368 tests) | All 8 distinct track D survivors were fixed, each re-verified first. S1/S2/S3 have regression tests that fail on the old code: the IPC answer outlives the polkit dialog and an undelivered stop code is undone; deny-direction ops no longer queue behind a dialog; the admin effect no longer depends on the answer or a post-commit log line; the offline CLI uses `LoadMode::Offline`; the polkit policy uses `auth_self` for SSH; the password is read unbuffered; zxcvbn gets the device labels. Review of `7697823..efe75fa` (3 read-only sub-agents; 0 critical, 0 high). It led to decision M1-40: private bridges replace the built-ins, and lyrebird is SHA-256-pinned with no `PATH` lookup (live obfs4 check 47.6 s). Also decision M1-41 (HKDF media bind key), system power keys refused, cargo-deny in `xtask verify`. Detail: `docs/notes/m1-state.md`, `docs/VERIFICATION.md`. |
| Vertical slice (operator ruling 2026-09-21) | **In progress** — Tor transport, media crates, host FSM wired, **session layer done: video verified live over Tor** (test card), **Wayland desktop capture and input verified live** (2026-09-22); **the window, the sharing indicator, the Windows build, start at login and the release zips built** (2026-09-23/24, the rows below); the window's live check over Tor NOT PERFORMED | Operator scope: a working Linux↔Windows session before QUIC (decisions M1-39, M3-1; `docs/research/slice.md`). Done: `tornect-proto` (Tor media framing + bind MAC), `tornect-input` (16-byte event, Chromium-derived USB key table, XTEST, SendInput), `tornect-codec` (OpenH264, BT.601); Windows cross-build for `x86_64-pc-windows-gnullvm` with llvm-mingw (OpenH264 C++ links). The kill switch no longer latches (`94dfe64`), and `SessionSink` hands live sessions to the session layer (`34f4723`). `serve_host` runs in `tornect host`, with `tornect connect` as its client (decision M1-42; verified live, `docs/notes/m1-serve-host-evidence.md`). `tornect-capture` has begun: the `VideoSource` trait, a synthetic test card that carries its frame index, the X11 backend (verified under Xvfb), the GDI backend (lint-clean for gnullvm; runtime `NEEDS-DEVICE`) and the Wayland backend (RemoteDesktop portal + PipeWire over `dlopen`, decision M1-48; verified live at the console and over Tor). `tornect-session` serves the Tor media stream (decision M1-43). Capture starts only after a verified bind, is driven by an ack window, gives view-only no injector, and is ended by any kill at once. Verified live over Tor between two instances: 146/146 test-card pictures in order at 1280×720, 6.3 fps at the 8-unit window, then 13.2 and 13.0 fps at 20 units (M1-47; `docs/notes/m1-media-evidence.md`); the Wayland desktop at 3538×1918 with 0 errors at 2.7–3.1 fps, where the software encode of 6.8 MP is the likely limit (M1-48). Open: the console check of the window over real Tor (no input has crossed Tor yet), anything at run time on Windows and the Linux ↔ Windows session, the frame rate of large desktops (downscaling before the encode), and a hostile review of `5ba8f11..73e9314`. m2–m6 stay untagged until their full acceptance. |
| M1 session 2026-09-21 (5) | **Session layer; range `efe75fa..510b6cb` reviewed and its mediums fixed** (commits `be28c64` … `7d3668a`, gate 424 tests) | `tornect-session` (M1-43) plus `tornect host --capture` and media in `tornect connect`, verified live over Tor. Review A′ of `efe75fa..510b6cb` (3 read-only sub-agents): 0 critical, 0 high, 4 medium. Three mediums are fixed failing-first (M1-44): the session now ends before any write to the peer, a kill or a live session refuses a pending accept, and unattended requests get `SESSION_ACTIVE`. **B2-2 is open:** a host whose store was locked at start has no control channel, and a Windows host never has one (fixed in session 7, decision M1-46). Detail: `docs/notes/m1-state.md`. |
| M1 session 2026-09-22 (6) | **The gate stops fighting plain `cargo`; B2-7 and B3-7 fixed; the slice-C review did not run** (commits `4201269` … `68f690e`, gate 428 tests) | Decision M1-45. `xtask`'s `cargo()` removes the variables `cargo run` gave it, so the gate, plain `cargo` and the pre-commit hook share fingerprints: a switch costs 0.6 s and 0.3 s with nothing rebuilt, against 33 s and a `ring` + `rustls` rebuild before, and the whole gate takes 41 s. B2-7: `y`/`yes` at the session question no longer grants control. B3-7: the X11 grab sizes its buffer in checked `usize` under a 2^27-pixel cap, before `GetImage` (in `u32` the product wrapped to 0). Each fix has a test that fails on the old code. The review of `510b6cb..5f1ae84` died on the account's weekly usage limit with no report; it ran in session 7. Detail: `docs/notes/m1-state.md`. |
| M1 session 2026-09-22 (7) | **Slice-C review; B2-2, C1-1, C2-1 and B2-8 fixed; 13 fps over Tor** (commits `94255c2` … `5ba8f11`, gate 437 tests) | Review A′ of `510b6cb..5f1ae84` (3 read-only threat modelers): 0 critical, 0 high, 2 medium, 6 low, 13 info. Decision M1-46 (B2-2): `tornect host` holds `state/host.lock`, its control channel is up even without a store (it then answers `tornect panic` only), and the terminal names only a kill path that works. Decision M1-47: reading a media `Bind` takes no slot (C1-1); Ctrl-C in `tornect connect` is heard on its own task (C2-1); `bye` waits for the host's close, within 3 s (B2-8); the ack window goes from 8 to 20 units, and the test card ran at **13.2 and 13.0 fps** over Tor, against 6.3. The live media check passed all 10 checks. The slice-D review later found the unfixed halves of B2-2 (a command already offline when a host starts) and B2-8 (host `PING`s); both were fixed in session 8. Detail: `docs/notes/m1-state.md`. |
| M1 session 2026-09-22 (8) | **Wayland capture and input verified live; slice-D review; the open slice-C lows and the slice-D findings fixed** (commits `4451d14` … `ad55279` and this hand-off, gate 480 passed, 4 ignored) | Decision M1-48: one RemoteDesktop portal session with ScreenCast sources, PipeWire over `dlopen` with mirrored structs and the 232-byte EnumFormat pod, input through the portal's `Notify*` calls (not libei, §B.5/D11), the pointer mapped over the encoded region, and a kept restore token (0600, never logged; deleting `<state>/portal-restore-token` revokes it, and `tornect doctor` says so). Live on the build VM: the portal check at the console (3538×1919, 19 fps of capture while dragging, five injected pointer moves each seen in a new picture), and the desktop over real Tor at 3538×1918 with 0 errors in two runs (run 2 passed all 10 checks; 2.7–3.1 fps at 6.8 MP, the software encoder being the likely limit); `tornect panic` ended media within about 100 ms. No input crossed Tor: there is no GUI yet. Hostile review of `5f1ae84..5ba8f11` ("slice D", run in full): 18 raw findings → 8 survived → 5 distinct defects, all LOW (D1 by the operator's ruling), no BLOCK. Decision M1-49: D1–D3, the six open slice-C lows (C1-2 by mapping on X11 and `SendInput`), C3-5, the media-end wording and the §10 hardening, each code fix failing-first; the viewer now pings when idle, and the first Ctrl-C ends a pending media open. Operator ruling: the store-less host keeps M1-46, with a note in §B.8.6.2. Unreviewed by a hostile review: everything after `5ba8f11`, including `pipewire.rs`'s unsafe FFI. Detail: `docs/notes/m1-state.md`. |
| The window (2026-09-23/24, decision M1-50) | **Built; its live check over Tor NOT PERFORMED three times** (commits `d6ef5ba` … `981f556`; the slice-E fixes `746a628` … `7e9f2cc`; N-1 `3ed9515`; the signals `40a89ce`, N-4 `30f510e`, P2-I4 `1051f92`; T-1 `ede20d0`) | `tornect` with no subcommand opens a manual winit loop driving egui-winit and egui-wgpu (no eframe): the home screen (ID, Tor status, hosting, Connect), inline pairing and session cards, the client's code card, the stream window, and the first-run Wayland grant as a setup step (the operator's ruling). Input goes by physical scancode and only for a control grant (`sends_input`). The slice-E review's Medium E1-1 (keys typed for another program answered a card) is fixed by the operator's "pointer-only Allow": the accepts answer only a mouse click, are never focusable and arm after 1 s; Deny comes first. SIGINT and SIGTERM end every session with a goodbye, the hosted ones first. Verified by unit tests (an egui harness, the real FSM over a pipe, a headless GPU device) and preview runs under Xvfb. The console check over real Tor was NOT PERFORMED on 2026-09-23 (02:27, 22:53) and 2026-09-24 (01:14): the windows up, both hosts `REACHABLE`, nobody at the VM screen. Detail: `docs/notes/m1-state.md` |
| The sharing indicator (2026-09-23, M1-50) | **Built** (`9eb9e54`, `93a5d56`; E1-2 `f9a1a3e`) | An always-on-top, undecorated window "Tornect: sharing" that opens without taking the focus, beside the in-window banner and in the same process (not D10's separate indicator process). One row per shared session: SHARING or UNATTENDED, the mode, the clock, then the label (an order that departs from §B.8.7.3's pill, M1-50), and Stop, the host-wide kill. Verified by unit tests, and under Xvfb the level request reaches the X server; the level on a real X11 window manager, on Windows and on GNOME is NEEDS-DEVICE. Not built: re-assertion every 500 ms, one per captured monitor, the tray, and the badge "N devices can connect without asking" (E1-5) |
| The Windows build (2026-09-23/24, M1-51) | **Links and runs under Wine; never run on Windows** (`cb46b4d`, `7bbb51c`, `b7ef5a9`, `fa92538`; E2-4 `c2ecce4`) | `x86_64-pc-windows-gnullvm` with llvm-mingw 20260908: `result_large_err` fixed by boxing, every C and C++ object built with the stack protector, libc++ linked statically, so `tornect.exe` imports only DLLs Windows ships; the 13 test binaries build. DLLs loaded at run time come from the system directory only, and CredUI is loaded at run time; the linker's dependent-load flag, which would cover seven load-time imports, waits for the operator. Under Wine 10.0: `--version`, `id`, `doctor` and four test binaries pass. Every Windows run-time row of `docs/VERIFICATION.md` is NEEDS-DEVICE(windows) |
| Start at login (2026-09-23/24, M1-53) | **Built; the slice-F review's findings fixed** (`66c2442`, `b4e8dd4`, `176e9de`; the fixes listed in M1-53) | `tornect service install`, `uninstall` and `status`: a systemd user unit on Linux, a Task Scheduler task registered from XML on Windows, each change through the guard with OS re-authentication (polkit; on Windows the secure credential prompt and `LogonUserW`). The Linux start-at-login host answers pings only (F2-1); the operator's three defaults and the refusal of `--elevated` to a standard account are in. Live on Linux with the debug build's re-authentication escape (polkit not exercised); the Windows path is unit-tested over a fake Task Scheduler and linted, and Task Scheduler, CredUI and UAC are NEEDS-DEVICE |
| The pre-release `v0.1.0-slice.1` (2026-09-23/24, M1-52, M1-54) | **Prepared, not tagged** (tooling `95c96d7` … `3ca4094`; release preparation `b580203` … `5b698e4`; notes `a80ac5f`) | `cargo xtask pt-fetch` (lyrebird 0.8.1, pinned and signature-checked) and `cargo xtask dist` (both zips, reproducible on one machine; `BUILD-INFO.txt` names the advisory database and the ignored advisories; `THIRD_PARTY_LICENSES.txt` in each zip); the gate fails without cargo-deny (B3-6). The advisory refresh found RUSTSEC-2026-0285, fixed by rustls 0.23.45. Reviews: slice E (`73e9314..3ca4094`), slice F (`3ca4094..176e9de`), the fix-closure check and the release-preparation review, up to `e0b7ae4`: no Critical or High, every Medium fixed; `5ba8f11..73e9314` has had no hostile review. Gate 634 passed, 0 failed, 5 ignored at `ede20d0`. Waiting: the final `dist` at the head that the tag names, then the operator's go for the tag and the GitHub pre-release; the window's console check (or the operator's decision to publish with it NOT PERFORMED); the dependent-load flag (or its disclosure, which the notes already carry). Process: `docs/RELEASING.md`; notes: `packaging/release/NOTES-v0.1.0-slice.1.md` |
| The UI foundation, M-UI-1 of the redesign (2026-09-27) | **Done** (`572a3f8` … `3aa1072`) | Design tokens with dark and light themes, the embedded Manrope and JetBrains Mono fonts and a Lucide icon subset with their licences, widget helpers, the sidebar and the pages over the existing backend, and the neutral device-name default ("Linux PC" / "Windows PC", never the host name). No trust-surface behaviour changed: the existing trust-surface tests pass with their source unchanged. Checks in `docs/VERIFICATION.md` ("The UI foundation"): the gate green at 663 passed at `2b11950`; the window on a Windows or Wayland desktop at 125–200 % scale is NEEDS-DEVICE. An internal security review of the foundation found no blocking issue; two Low items are carried. |
| Plan r7, the desktop amendment (2026-09-27) | **Specified** (this revision) | The operator's requirements for Linux and Windows: session levels with administrator access on Windows (§B.2.1); a per-session administrator helper replacing the whole-host elevated task (§B.8.7.5 — decision M1-53 amended, F1-5 reversed for the helper task only, T9's residual accepted with the wizard warning, M1-57/M1-62); product modes, with the app, not the headless host, started at sign-in (§B.1.1 — M1-53's F2-1 rule amended for the app only, M1-58); saved devices and device words (§B.6.1, §B.8.9.1; M1-63); the vendor codec APIs with the parser gate (D8, §B.5; M1-56); egui everywhere with the indicator in process (D10; M1-59); the popup answers and no administrator access from the standalone app (M1-64, M1-65); a Tor-relayed release with direct connections next and Windows service mode after it (M1-60, M1-61); Android to the roadmap (Part F.7; M1-66); the desktop release milestones (Part C). An internal security review of the draft found no blocking issue; its 5 Medium, 9 Low and 5 Info findings are folded in, six milestone rows are Security-mandatory, and a final Windows pass with a standard account precedes the tag. Code signing stays open until the pre-tag pass (Part F.8). `docs/UI_PLAN.md`'s Iced shell sections are superseded by D10 (the UI plan itself is not edited). |
| Plan r7, the F4-1 amendment (2026-10-01) | **Specified** | `grant_reach` (0/1/2) in the unattended `SESSION_ACCEPT` and every `ADMIN_RESULT`; the client keeps a password only after an accept that says 0, never after an admin command, and deletes it otherwise; a grant's own reach rises only with a new generated password; a password a session accept answered 0 is marked and never reaches the level; B.8.9/B.8.9.1 corrected to the built store (decision M1-67). |
| The desktop release (Part C, r7) | **Planned**; M-UI-1 done (above); later rows record progress | M-FEAT-1…6, M-UI-2…6 and M-CODEC-1…3, then the release-range security pass, the final Windows pass with a standard account, the pre-tag docs pass, the console check, dist and the tag (Part C, the desktop release). |
| M2–M8 | Not started | Research decisions already made for M2 (raw-public-key TLS, punch outside QUIC, `grease_quic_bit(false)`, `stun` 0.17 / `crab_nat` / `igd-next`), M3 (`openh264` software path; hw codecs `NEEDS-DEVICE(gpu)`, through Media Foundation and NVENC since r7, D8; VM-scoped acceptance defined in Part C M3, r6), M5 (`opus` 0.4, in-band FEC off), UI (egui everywhere on a manual winit loop, no eframe, the indicator in process — D10 as amended in r7; wgpu 30 / winit 0.30 / egui 0.36; `u1` placement per Part F.6). |

**Verified-on-hardware honesty.** Everything above was run on one Ubuntu 26.04 VM (GNOME/
Wayland, no GPU encoder, no sudo, no second machine). Windows is cross-built and linked, and run
under Wine only; macOS is `cargo check`-ed only; "two machines on different NATs" (M1 accept) is `NEEDS-DEVICE`.

**Pending actions for the owner.** (1) `gh auth refresh -h github.com -s workflow`, then commit
and push `.github/workflows/ci.yml` (kept local because the token lacks the `workflow` scope).
(2) Copy `.claude/settings.recommended.json` to `.claude/settings.json` after review (the harness
refuses to let the model install its own permission/hook config). (3) Optional: a second
machine for the M1/M2 two-NAT acceptance rows.

**UI plan (adopted 2026-08-29).** `docs/UI_PLAN.md` (byte-identical to `TORNECT_UI_PLAN.md` at the
repo root; `cargo xtask verify` compares them) refines D10: an Iced 0.14 shell, the winit/wgpu/egui
stream surface, a separate always-on-top indicator window, `tornect-ui-kit` design tokens, a
preview/snapshot harness and a `ux-reviewer` agent. This plan stays authoritative; reconciliation:
(1) its schedule (U0 with M0, U1 with M1) is **not** retrofitted — M0 is closed and M1 keeps the
CLI consent prompt of Part C; U0 + U1 form the first UI milestone `u1`, scheduled right after M1 and
before M2 (Part F.6 — serial per D.1/D.4, never interleaved), with `research-verifier` pinning `iced`,
`tray-icon`, `notify-rust`, `fluent` and the AccessKit integrations first (nothing UI-related is
pinned yet); U2–U5 keep their hosting milestones as `u2` (inside M4), `u3` (serial after M6), `u4` (inside
M7) and `u5` (inside M8), Part F.6; (2) its consent dialog's "Always allow this device" checkbox (§6.1) and the
"Always allow / Ask / View-only / Unattended" device badge (S2) contradict §B.2/§B.6/§B.8 (no "always
allow"; the only popup-less path is an unattended grant; no persistent per-device attended policy —
view-only exists per session and as a grant mode) and are replaced by the §B.2 link "Set up
unattended access…" and the §B.8.7 manager; S8's "per-device trust level" (the same persistent attended
policy) is replaced by the grant's mode in the §B.8.7 manager; the Wayland indicator contract is the
compositor's screencast icon + focused window + chime + the in-app surface (B.8.8, B.8.7.3) — the tray is
an enhancement, GNOME has none without an extension, so §6.3/§12's "our tray red state carries the
guarantee" does not hold; the S4 pairing variant of §6.2 resolves `PAIR_ACCEPT` on its own click and the
session dialog follows `SESSION_REQUEST` (§B.2, B.8.4.5 strict alternation — the requested mode is unknown
at PAIR time), never one click for both; the §8 degraded banner shows no [Retry direct] when
`SESSION_ACCEPT.transport_policy = tor_only` (Paranoid / `require_tor_only`, B.8.6.4) — the copy says
"Relayed by policy"; its auto-deny countdown is kept but its duration and
answer follow the master where fixed (60 s ⇒ `DENIED` for the ask-before-start popup of B.8.4.5 —
the client's fixed 110 s budget assumes it; an attended popup timeout answers `POPUP_TIMEOUT`,
B.8.4.6); its consent invariant (§6.1 "capture starts only after an affirmative click", §10 item 4)
reads in this plan: attended = click, unattended = F1 + F2 and the block window elapsed without
Block (B.8.1 — elapsing is a veto opportunity, not consent); its §6.1 words "never on timeout" do not
hold for the block window (elapsing without Block starts capture, B.8.4.5), and §10 item 4 gains the
unattended twin: `Blocked` ⇒ never `StartCapture`, `Elapsed` ⇒ `StartCapture` only through
`ConsentProof::Unattended` (B.8.14); the §B.8.6.3 Block window (one button,
no close, re-asserted every 500 ms, every captured monitor), the `AwaitLocalAllow` Allow/Deny popup,
the "**Unattended** · <label> · Control · [End]" indicator variant and the in-app notification
windows of §B.8.7.3 are added to its screen inventory at M4/M5 (before U5), and its indicator (§6.3)
inherits un-closable / re-asserted / on every captured monitor; its "instant-apply" settings (S8)
never apply to the access-increasing operations of §B.8.6.2 (panic key, launch at login =
`tornect service install`, keep-awake/notification settings, the identity-key view/backup of S8
*Identity* and the unattended `backup export` — both listed in B.8.6.2 — per-device grant
policy — OS re-auth, no remote session ≥ 60 s); its S3 wait stage shows the dialed address or the
paired label, never a host-sent name, until `PAIR_ACCEPT` (B.8.4.1: `HELLO_ACK` carries no
`host_name`); its OS toasts / portal notifications mirror, never replace, the in-app window
(§B.8.7.3, A9 — DND/Focus hide toasts); (3) the egui-everywhere fallback remains the risk floor;
(4) errata for the UI plan's next revision (the UI plan itself is not edited): §11 U3 "S6 devices
management" (S6 is the stream window; devices live in S2/S8), S8 "strength meter, argon2" (the meter
is zxcvbn, B.8.7.2; Argon2id is the OPAQUE KSF), S2 "Accept incoming requests" must not be confused
with the unattended master toggle of B.8.7.3, §6.3's "Indicator process outlives shell crashes
(separate task; watchdog)" is the separate *process* of D10's process model (§3 already says a dedicated
window), `crates/tornect-ui-kit` enters §B.1 (listed there as created at `u1`) and the CLAUDE.md map at
`u1`, and the UI plan's `apps/tornect/src/platform/` is tray/notification/deep-link glue only — autostart,
hotkeys and the IPC endpoint stay in `tornect-platform` (B.8.14). Verified pins for every UI crate — and `research-verifier` confirmation of
the §2 claims the adoption rests on (Iced 0.14's release and its headless-testing/hot-reload
features, COSMIC as the production Wayland proof, the `iced_winit` integration path of D10; the UI
plan's table cites no sources) — are a precondition of that milestone.

**Plan amendments applied in r6** (2026-08-29, from `docs/research/SUMMARY.md` "Cross-cutting";
one line per item, section touched first):
- §A.2 — FFmpeg versions: bindings 9.0.0 build against FFmpeg 6.1–9.0; `ubuntu-latest` ships 6.1,
  the VM 8.0.1; target the 8.x API, gate on `ffmpeg_8_0`, two-image media CI matrix (codecs.md §2.1,
  ci.md §3). Also `draft-seemann-quic-nat-traversal` recorded as an expired individual draft (nat.md §4).
- §A.4 — new item 6 "A Linux (GNOME) host must be unlocked": the lock screen terminates every portal
  session and refuses new ones; recoverable *Locked* state per §B.8.8 (wayland.md §7).
- §B.2 — punch mechanics: STUN-style probes outside QUIC, ICE pacing (Ta 50 ms, RTO ≥ 500 ms), one
  `connect_with` dial by the lower-device-pubkey side, `grease_quic_bit(false)`; `quic_server_cert_fp`
  → `quic_spki` (also added to §B.8.4.2's SESSION_ACCEPT line); the transport line reads "TLS 1.3 raw
  public keys, both SPKIs pinned" (nat.md §5, quic.md §5, §12.14). D6 cross-references it.
- §B.4 — 12-byte header (`stream_id` added), whole datagram ≤ live `max_datagram_size()` (1162 B @1200,
  1414 B @1452), RaptorQ symbol 1144/1392 B; Opus `LowDelay`, in-band FEC off, previous-frame
  redundancy + PLC (media-proto.md §2, §5.6, §7.3; SUMMARY.md §2.9 resolving codecs.md §5.3 vs media-proto.md §5.2). D12 now says "12-byte header".
- §B.5 — `pw` backend = one RemoteDesktop session, persistence/restore token only on
  `SelectDevicesOptions` (wayland.md §2.4–§2.5); `openh264` is the always-on software codec, libx264
  only opportunistically via FFmpeg, no rav1e/svt-av1/dav1d in v1 (codecs.md §3, §4); client software
  decode stated. §B.1 tree comment updated to match.
- §B.6 — session transport = TLS raw public keys (RFC 7250): 44-byte Ed25519 SPKI pinned by custom
  mutual verifiers, X.509/`rcgen` documented-not-compiled (quic.md §3.3). D5 cross-references it.
- D9 — `opus` crate `=0.4.0` (bundled libopus 1.6.1), `audiopus` rejected (codecs.md §5).
- D10 — app shell Iced 0.14 per `docs/UI_PLAN.md` (pins pending at the first UI milestone); stream
  surface = manual winit loop, no `eframe`; egui-everywhere fallback kept (ui.md §4). §B.1 box/tree,
  the `apps/tornect` comment, the `ui-engineer` row of the §D.3 table and the framework lines of
  `.claude/agents/ui-engineer.md` updated to match (the charter's full rewrite is `u1` work).
- D13 — `keyring-core` + per-OS stores, never `keyring::Entry`; file keystore fallback kept (ui.md §5.9).
- Part C M2 — `stun` crate (webrtc-rs, sans-IO; not `stun-client`), `crab_nat`, punch per §B.2,
  raw-public-key verifiers.
- Part C M3 — VM-scoped acceptance (synthetic → `openh264` → wgpu at 1080p30/720p60) + `NEEDS-DEVICE(gpu)`
  rows for 1080p60 / hw codec / CPU < 15 % and a `NEEDS-DEVICE(linux)` row for the PipeWire backend
  (SUMMARY.md §0.3, §4 M3; codecs.md §3.2).

**Review pass on r6** (2026-08-29, applied in place, no revision bump): §B.8.5.1/§B.8.5.3 — `credit`
update rule, one definition of *load*, lifetime cap = `min(steps, 1)` with the anchor advanced by whole
periods (no "set to now"), decay never clears `hard_locked`, `Clock` trait (`wall()`/`mono()`,
`FakeClock` for U1–U7/F3), monotone `last_seen`/anchors/`flushed_at`, rollback checked at runtime,
suspend accepted as conservative (B.8.7.5); T12/T2/U1–U7/B.8.16 aligned; §B.8.7.3 *Suspend*/*Resume*,
§B.8.7.4 `IpcOp` annotations, `UnattendedSuspended{reason, by?}`, `SESSION_REJECT.cause` for
`SUSPENDED`; `quic_spki` check in B.8.4.2/B.8.16; §B.4 citation → SUMMARY.md §2.9; §B.5 CI wording;
§A.2 `DEP_FFMPEG_*`; Part C M3 gates (720p60 ≤ 35 ms, 1080p30 ≤ 50 ms + codec-excluded ≤ 9 ms, 6 ms stretch,
PipeWire under `NEEDS-DEVICE(linux)`), M1/M4/M8 shell wording; D10 Iced caveat + process model; Part F.6,
D.1/D.4 `u1`; §B.8.17 item 7 + Part E row; this paragraph and the §B.8 status row.

Seen while applying r6 and settled by the review pass: quic.md §0/§9 argues for running the session
protocol directly over the onion stream instead of tunnelling the same QUIC connection through Tor,
which §B.2, §B.8.4.2, the §B.8.14 M2 row and Part C M2 currently require for the uniform `BIND` check —
now §B.8.17 item 7 and a Part E row, decided at M2; Part C M4/M8 no longer say "minimal egui"/"full egui
app" (shell per D10, `u1` per Part F.6). Also settled: §B.8.8's former "both tokens" wording (a separate
ScreenCast restore token next to the RemoteDesktop one) is corrected to the single RemoteDesktop token of
§B.5 — an unattended host always needs input, so it always holds exactly one; SUMMARY.md §4 M3.11 asks a
different question (whether a capture-only ScreenCast token could be reused for the combined session at
M5), which Part C M3 resolves by starting with the combined RemoteDesktop session.

**Second review pass on r6** (2026-08-29, applied in place, no revision bump): `BIND` labels are Tornect
roles (§B.8.4.3, §B.6, §B.8.14 M2, Part C M2); §B.2 checklist ≈ 20 pairs / ≤ 8 in flight; §B.5 "only
real-time video codec"; §A.2 `ffmpeg_8_0` check-cfg + direct `ffmpeg-sys-next` dependency, iroh claim
re-sourced; D13 store order + `keychain` feature; `quic_spki: bytes[44]`; M2 gateway discovery; the
Tor-tunnel pointer to §B.8.17 item 7 at §B.2/§B.8.4.2/§B.8.14; §B.8.5.1/5.3 — clamped `:= now` writes vs
unclamped whole-period advances, `pending` settled before decay at load, the lifetime cap load-time only,
the `credit` invariant as ≤, one definition of *load* vs the readiness re-run, offline *Unlock*, `last_seen`
raised to the anchors, rollback ⇒ `NOT_YET_ACTIVE{last_seen − now}` (B.8.4.2/4.5/4.6, B.8.10); suspension
precedence (B.8.6.3, B.8.4.1, B.8.6.2, B.8.7.3/7.4, A15); B.8.8 single restore token + M6 columns; M3
codec-excluded gate ≤ 9 ms (6 ms stretch); `u2`…`u5` placement (F.6, D.4, Part C M4/M6/M7/M8, Part G);
UI-plan reconciliation items (S8 trust level, Wayland tray, S4 pairing click, "never on timeout", [Retry
direct], `tornect-ui-kit`, `apps/tornect/src/platform/`); T12 keychain-on-sleep; B.8.2.1 "two weeks".
