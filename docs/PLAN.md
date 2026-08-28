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
ICE layer: IETF `draft-seemann-quic-nat-traversal`, implemented in production by
**iroh 1.0 (June 2026)** — a Rust library that dials peers by ed25519 public key,
hole-punches QUIC via a NAT-traversal extension, and falls back to relays; iroh's
docs explicitly note the transport wire can be swapped (they name Tor as an option).
iroh validates our exact architecture: *public-key dialing + punched QUIC*. We differ
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
FFmpeg ≥ 7.x (`libavcodec`) exposes every encoder above through one API with
hw-frames zero-copy (`d3d11va` → NVENC/AMF/QSV on Windows, `vaapi` + `cuda` on
Linux, `videotoolbox` on macOS) — that uniformity is why it's our v1 encode/decode
layer, with per-vendor native SDK backends as a v2 optimization behind the same
trait.

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
| D5 | Media transport | **QUIC via `quinn`**: unreliable **datagrams** for A/V, reliable streams for control/input/clipboard/files; TLS 1.3 with both ends pinning the peer's Tornect keys (no CA) | One connection, E2E-encrypted, congestion-controlled, punchable; matches iroh/MoQ direction | str0m WebRTC (keep as documented plan-B; needed only for future browser client); raw UDP + custom crypto (reinventing TLS) |
| D6 | NAT traversal | ICE-style candidate gathering (host addrs + **UPnP/NAT-PMP/PCP** port mapping + server-reflexive via a **user-editable public STUN list**), exchange over Tor, simultaneous-open punch, then QUIC | Maximizes direct-connect rate with zero owned infra; STUN is stateless free public infrastructure and is *optional* | Own STUN/TURN (violates "no servers"); iroh as connectivity backend (excellent, but pulls in n0's relay/discovery plane by default — keep as an optional feature-flagged backend for de-risking) |
| D7 | Fallback path | **Stream over the Tor circuit itself** (TCP-like onion stream): capped preset ~1–6 Mbit/s, H.264, aggressive downscale, "relayed via Tor" badge | Guarantees Tornect *always* connects — the killer differentiator; also doubles as "paranoid mode" (peers never learn each other's IP) | TURN (needs servers); giving up (Moonlight's answer) |
| D8 | Video pipeline | Capture→encode zero-copy on GPU per §A.2; **FFmpeg hw contexts** as the unified codec layer v1; decode→render via **wgpu** (Vulkan/Metal/D3D12) with NV12/P010 shaders | One codec API across 4 vendor stacks; wgpu = one renderer for all OSes | GStreamer (capable, but heavy runtime dependency + plugin hell for end-users); per-vendor SDKs first (do later as optimization) |
| D9 | Audio | **Opus** 48 kHz, 5–10 ms frames, in QUIC datagrams; WASAPI loopback / ScreenCaptureKit audio / PipeWire capture | The only sane real-time audio codec; `libopus` via `audiopus`/`opus` crate | — |
| D10 | UI toolkit | **egui/eframe** for control UI + consent popups + tray (`tray-icon`, `rfd`); streaming window = `winit` + wgpu surface with egui overlay | Pure Rust, tiny, one toolkit everywhere incl. the GPU-rendered stream window; fastest path for Claude Code to iterate | Tauri 2 (nicer chrome, but webview + IPC between UI and stream window adds friction); Qt/Slint (C++/licensing or smaller ecosystem) |
| D11 | Input model | Client captures via winit raw events (+ gamepad via `gilrs`); host injects via SendInput / CGEvent / RemoteDesktop-portal-libei (`reis`) | Per §A.2 — the sanctioned path on each OS | uinput on Linux (root, bypasses lockscreen isolation — rejected) |
| D12 | Serialization on the wire (media) | Hand-rolled fixed headers (bitfields) for datagram payloads; CBOR for control | Datagram headers are hot-path; 12–20 bytes/packet matters at 100k pps | — |
| D13 | Config/state | `~/.config/tornect` (XDG) / `%APPDATA%\Tornect` / `~/Library/Application Support/Tornect`; TOML config; keys in OS keychain where available (`keyring` crate), file-based with 0600 otherwise | Boring and correct | — |

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

---

## Part B — System architecture

### B.1 Component overview

Single binary, two roles (any machine can be host, client, or both):

```
┌────────────────────────────── tornect (app) ──────────────────────────────┐
│  egui UI: onboarding · ID card/QR · consent popup · session HUD · tray    │
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
│   ├── tornect-core/           # ids, keys, config, errors, telemetry
│   ├── tornect-signal/         # arti embedding, onion service, CBOR signaling, pairing
│   ├── tornect-net/            # candidate gathering, UPnP/NAT-PMP/PCP, STUN, hole punch,
│   │                           #   quinn endpoint w/ key-pinned TLS, tor-relay transport
│   ├── tornect-proto/          # media wire format, packetizer/depacketizer, FEC,
│   │                           #   jitter buffer, pacer, ABR controller, stats
│   ├── tornect-capture/        # trait VideoCaptureSource + wgc/ sckit/ pipewire/ backends
│   ├── tornect-codec/          # trait Encoder/Decoder + ffmpeg-hw backend (nvenc/amf/
│   │                           #   qsv/vaapi/videotoolbox/software x264|dav1d fallback)
│   ├── tornect-audio/          # capture (wasapi/sckit/pipewire), opus enc/dec, playback (cpal)
│   ├── tornect-input/          # client-side event mapping; host-side inject backends
│   └── tornect-session/        # host & client state machines wiring everything
├── apps/
│   └── tornect/                # eframe app (tray, popups, settings, stream window)
├── xtask/                      # cargo xtask: dist, packaging, ffmpeg fetch, lint-all
└── tests/
    ├── integration/            # loopback e2e, signaling-over-localhost-tor mocks
    └── netem/                  # scripted latency/loss/jitter harness (linux netns)
```

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
◄── HELLO{proto_vers, client_device_pk, name, pairing_state}
   ┌─ if unpaired device: PAIR_REQUEST
   │  ┌──────────────────────────────┐
   │  │  CONSENT POPUP on host:      │   both screens show same 6-digit SAS
   │  │  "Laptop-of-Ana wants to     │   (derived from transcript hash) —
   │  │   pair. Code: 481 923"       │   user verifies + clicks Allow
   │  └──────────────────────────────┘
   │  PAIR_ACCEPT{host_device_pk} ──►      client pins host key; host pins client key
   └─ else: device already trusted
◄── SESSION_REQUEST{caps: codecs, max_res, hdr, monitors_wanted}
   ┌──────────────────────────────────────┐
   │ SESSION POPUP on host: Allow once /  │  (skippable per-device if user chose
   │ Always for this device / View-only / │   "always allow" at pairing)
   │ Deny                                 │
   └──────────────────────────────────────┘
SESSION_ACCEPT{caps chosen, session_token, quic_server_cert_fp}
◄── CANDIDATES{[]}  ──── both sides gather in parallel ────  CANDIDATES{[]} ──►
        host: local addrs, UPnP/NAT-PMP mapped, STUN reflexive (if enabled)
punch: paced bidirectional QUIC Initial+padding to all candidate pairs (trickle ok)
════════════ direct QUIC established (TLS1.3, both certs pinned) ═════════════
        └─ if no pair succeeds within 4 s: TOR_FALLBACK{} → open second onion
           stream, run the same session protocol over a length-framed tunnel
media flows (datagrams) + control/input (streams); Tor circuit kept as low-rate
heartbeat + renegotiation channel; teardown on BYE or circuit loss
```

Key properties: the consent popup **always** runs on the host before any capture
starts; capture begins only after SESSION_ACCEPT; a persistent on-screen session
indicator + tray state shows "screen is being shared" with one-click kill.

### B.3 Signaling protocol (`tornect-signal`)

Envelope (CBOR, over onion stream, u32-BE length prefix, max 64 KiB/frame):

```
Envelope { v: u8, msg_id: u64, kind: Kind, body: bytes }
Kind = HELLO | PAIR_REQUEST | PAIR_ACCEPT | PAIR_REJECT
     | SESSION_REQUEST | SESSION_ACCEPT | SESSION_REJECT
     | CANDIDATES | CANDIDATES_DONE | TOR_FALLBACK
     | PING | PONG | BYE | ERROR
```

Rules: strict monotonically increasing `msg_id`; unknown `Kind` ⇒ ERROR + close;
protocol version negotiated in HELLO (server replies with chosen `v`); every session
gets a fresh 32-byte `session_token` binding the QUIC connection to this signaling
exchange (echoed inside the QUIC TLS exporter check). Signing: client HELLO and
host SESSION_ACCEPT carry ed25519 signatures over the transcript hash so device keys
are bound to the channel (defense-in-depth on top of Tor's own crypto; and it is
what makes the SAS code sound).

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
VideoDatagram {
  u8  flags        // keyframe, fec, last_fragment, codec_bits
  u16 frame_id     // wrapping
  u16 frag_idx / frag_count
  u32 rtp_ts       // 90 kHz
  ... payload (fits datagram MTU ~1200 B)
}
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
- **Audio**: Opus 48 kHz, 10 ms frames, FEC-in-band (Opus LBRR) + one datagram
  redundancy at loss; independent tiny jitter buffer; A/V sync via shared rtp_ts
  and a small (<60 ms) lip-sync window — video never blocks audio.
- Everything already E2E-encrypted by QUIC TLS; no extra SRTP layer.

### B.5 Media pipeline (`tornect-capture` / `tornect-codec` / render)

Host per-frame path (targets in §B.7):

```
[Compositor/OS] → capture backend → GPU texture (DMABUF | D3D11Texture2D | IOSurface)
   → (same-GPU map, no download) → FFmpeg hw frame → encoder (NVENC/AMF/QSV/VAAPI/VT)
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
- `pw` (Linux/Wayland): `ashpd` ScreenCast portal (persist_mode=ExplicitlyRevoked +
  restore token stored per monitor selection) → PipeWire stream negotiated for
  DMA-BUF with modifier list from the encoder device; SHM fallback; cursor mode
  "metadata" preferred (send position separately; render client-side) with
  "embedded" fallback.
- `x11` backend explicitly out of v1 scope (document; Wayland-first per product).

Encoder selection at runtime: probe in order [platform-native pref list per vendor
from §A.2], score by (codec ≥ requested, 4:4:4 support, 10-bit support, measured
encode ms on a 3-frame warmup), pick best; expose override in settings. Software
fallback: `x264` (ultrafast+zerolatency) and `svt-av1` p12 for potato-mode, `dav1d`
/ `openh264`-free decode via FFmpeg on the client when no hw decode.

Client render: `winit` window → decode (FFmpeg hwaccel: D3D11VA/VideoToolbox/VAAPI
→ map to wgpu texture when same-API, else NV12/P010 CPU upload path first, zero-copy
interop as M7 optimization) → wgpu YUV→RGB(A)/tonemap shader → present with
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
  (invalidates all pairings, by design).
- **Client device identity** = per-device ed25519, generated at install.
- **Pairing** = mutual key pinning gated by human consent + 6-digit SAS derived from
  the signed transcript (blocks a MITM who somehow proxied the onion rendezvous —
  belt-and-suspenders; Tor already authenticates the service side).
- **Session transport**: QUIC TLS 1.3, self-signed certs whose SPKI must match the
  pinned device keys, plus tls-exporter check binding `session_token`. No CAs, no
  clock-dependent validity.
- **Consent & abuse resistance** (non-negotiable product rules): capture starts only
  after explicit accept; persistent visible indicator + tray while sharing;
  one-keystroke panic disconnect on host (default Ctrl+Alt+End); "view-only"
  session type; unattended access is **opt-in per device**, protected by an
  Argon2id-hashed password *and* still shows the on-screen indicator; all session
  starts/ends logged locally (`sessions.log`).
- **Privacy modes**: Default (signaling via Tor, media direct — peers see each
  other's IP, stated in UI) · **Paranoid** (everything via Tor, quality capped) ·
  LAN-only toggle.
- **No telemetry.** Crash dumps opt-in, written locally.
- Threats explicitly *out of scope* v1: compromised endpoints, Tor global passive
  adversary deanonymization, side-channels in shared GPU environments.

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
property tests; CLI consent prompt (y/n + SAS display) before egui exists;
PoW DoS defense + rate limits on. ✅ Accept: two machines on different NATs pair and
exchange PING/PONG round-trips via Tor with only an onion string shared; kill/restart
host ⇒ same ID; `tornect-signal` fuzz target runs clean 10 min.

**M2 — Direct connectivity (hole punch + QUIC)**
Candidate gathering (if-addrs, `igd-next` UPnP + NAT-PMP/PCP, `stun-client` against
configurable list); CANDIDATES over Tor; paced simultaneous-open punch; quinn
endpoint with pinned-key TLS verifier + session_token exporter binding; Tor-tunnel
fallback transport implementing the same `SessionTransport` trait; connection
health/migration (Wi-Fi→ethernet). ✅ Accept: matrix test — LAN, one-sided NAT,
double NAT (netem/netns harness simulating port-restricted + symmetric) — direct
established where theoretically possible, Tor fallback engages within 4 s otherwise;
1 GiB transferred over punched QUIC with checksum; measured punch success logged.

**M3 — Video pipeline, single platform (pick the OS Claude Code is running on)**
Capture backend for dev OS; FFmpeg hw encode+decode wrappers with runtime probe;
packetizer/FEC/jitter/pacer from §B.4; wgpu render window; loopback demo
(`tornect demo --loopback`) capture→encode→(in-proc channel)→decode→render.
✅ Accept: 1080p60 loopback ≥ 30 min, added latency ≤ 35 ms p95 (HUD overlay
numbers), zero validation errors, CPU < 15 % with hw codec.

**M4 — End-to-end streaming (M1+M2+M3 glued by `tornect-session`)**
Host & client session state machines; ctrl stream (IDR request, bitrate hint);
minimal egui: ID card + connect field + consent popup + stream window.
✅ Accept: two real machines over WAN: enter onion ID → popup → approve → live
desktop ≤ 8 s from request; unplug router mid-session ⇒ reconnect or clean error.

**M5 — Input + audio (remote *control*, not just viewing)**
Input capture/inject for dev OS + one more; Opus audio path both ends; clipboard
text sync; gaming mode (pointer lock, raw deltas, gamepad). ✅ Accept: type a
paragraph remotely with zero dropped/duplicated keys (scripted 10k-event test);
audio-video sync within ±60 ms; play a 2D game tolerably over LAN.

**M6 — Cross-platform parity (heavy parallel-subagent phase, §D.4)**
Remaining capture/input/audio backends: `wgc`+SendInput+WASAPI ·
`sckit`+CGEvent+SCK-audio(+TCC onboarding flows) · `pw`+`reis`+PipeWire-audio
(+portal restore tokens, Flatpak manifest). Encoder matrix validation
NVIDIA/AMD/Intel/Apple, 4:4:4 + 10-bit probes. ✅ Accept: full 3×3 host↔client
matrix streams with input+audio; CI builds artifacts for all OSes; a
`PLATFORM_MATRIX.md` records tested GPU/driver/compositor combos.

**M7 — Resilience & performance hardening**
ABR controller tuned on netem profiles (3 canned: "fiber", "flaky wifi", "hotel");
FEC adaptivity; Tor-fallback UX (badge, quality preset); zero-copy decode-render
interop; multi-monitor select/switch; HDR (HEVC Main10/AV1-10) behind flag.
✅ Accept: scripted netem suite passes quality gates (§B.7 table + fallback gate);
30-min soak at 5 % loss without session drop; perf report committed.

**M8 — Product polish & ship v0.1**
Full egui app: onboarding (permissions walkthroughs per OS), settings, trusted
devices manager, session log viewer, unattended-access flow (password + warnings),
paranoid/LAN modes; packaging (`xtask dist`): MSI/winget, notarized .dmg (document
signing steps even if certs pending), AppImage + Flatpak; auto-update check
(GitHub releases, off by default); README/website copy; SECURITY.md + threat model
doc; license decision (recommend GPLv3, matching Sunshine — decide in M0).
✅ Accept: a non-developer follows README on two fresh machines and is streaming in
< 10 min; release artifacts on a tagged GitHub release.

**Post-v1 backlog (tracked, not planned here):** file transfer UI · mobile clients
(Android first; would motivate str0m/WebRTC or WebTransport revisit) · "bring your
own relay" · per-app window streaming · virtual display driver (headless hosts) ·
H.265 4:4:4 / AV1 SCC tuning · Wake-on-LAN via a second LAN device · iroh backend
feature flag · MoQT alignment once RFC.

---

## Part D — Claude Code execution kit

This part is the operating manual for building Tornect *with Claude Code as the
engineering team*: one orchestrating session + specialized subagents, verification
loops, and per-milestone kickoff prompts. Companion file `CLAUDE.md` (repo root)
carries the always-in-context rules; this section carries the process.

### D.1 Ground rules for the build

1. **Milestones are sacred.** One milestone per Claude Code "epic"; never start
   M(n+1) with M(n) red. Tag `m0`…`m8` on completion.
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
| `media-engineer` | most capable | tornect-capture/codec/audio/proto: per-OS capture, FFmpeg hw, FEC/ABR | full |
| `platform-{windows,macos,wayland}` | capable | The three M6 parallel tracks; each owns its capture+input+audio backend end-to-end | full, own worktree |
| `ui-engineer` | capable | eframe app, popups, tray, onboarding, HUD | full |
| `security-reviewer` | most capable | Adversarial review at each milestone close: §B.6 checklist, unsafe-block audit, fuzz targets, "how would I abuse this popup flow?" | read-only + test-run |
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
- FFmpeg API use must be verified against the pinned FFmpeg major version docs
  (delegate to research-verifier when unsure).
- unsafe only at FFI edges, each block commented with safety invariants.
Definition of done: clippy-clean, tests green, loopback demo meets §B.7 numbers on
this machine, DEPENDENCIES.md updated if deps changed.
```

### D.4 Orchestration patterns (when to parallelize)

- **Serial** (main session, agents as consultants): M0–M4 — the layers stack.
- **Parallel worktrees**: M6 — `platform-windows|macos|wayland` implement against
  the frozen traits from M3–M5 simultaneously; `architect` freezes trait signatures
  first; merge order: wayland (dev machine verifiable) → windows → macos.
  Also M8: `ui-engineer` ∥ `qa-engineer` ∥ packaging.
- **Fan-out research**: at each milestone start, orchestrator may launch 2–4
  `research-verifier` tasks concurrently (e.g. M2: "current public STUN etiquette /
  igd-next status / quinn datagram MTU guidance / draft-seemann punch pacing").
- **Review gate**: `security-reviewer` runs at every milestone close *and* on any
  diff touching signal/net/pairing/consent; findings become blocking tasks.
- **Context hygiene**: long milestone? Have the orchestrator write
  `docs/notes/m<N>-state.md` (what's done, what's next, gotchas) before /clear;
  next session resumes from it.

### D.5 Verification harness (build in M0–M3, then it guards everything)

- `xtask verify` = fmt+clippy+test+doc-tests, then per-crate extras.
- `tests/netem/run.sh <profile>`: Linux netns pair with tc netem (delay/jitter/loss
  per profile), runs headless host+client, asserts §B.7 gates from stats JSON.
- Fuzzing: `cargo-fuzz` targets for envelope parsing, datagram reassembly, input
  event decode (security-reviewer owns corpus).
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
| FFmpeg hw-frames interop bugs across drivers | M×H | Runtime probe with warmup scoring + per-encoder denylist config; software fallback always compiled in |
| Latency regressions creeping in | H×M | §B.7 gates are executable (netem suite in CI-linux + headless-stats), regressions fail the build |
| Scope creep (it's a fun project) | H×M | Post-v1 backlog exists precisely to say "later"; milestones gate features |
| Abuse of remote-access software | L×H | §B.6 consent architecture: no silent sessions, persistent indicator, panic key, local session log — these are requirements, not options |

## Part F — Open product decisions (answer before/at M0)

1. License — recommend **GPLv3** (ecosystem-compatible with Sunshine; protects
   against proprietary forks). Confirm.
2. Primary dev OS for M3–M5 (whatever your daily machine + GPU is — say it and the
   plan adapts; Wayland machine recommended since it's the trickiest stack).
3. Unattended access in v1 (M8) or push to post-v1? Plan assumes v1, opt-in.
4. Minimum supported targets: Windows 10 20H1+ (WGC needs it) / macOS 13+
   (ScreenCaptureKit maturity) / xdg-desktop-portal ≥ 1.17 distros. Confirm.
5. Name/branding check: "Tornect" — quick trademark/collision search before public
   release (research-verifier task in M8).
