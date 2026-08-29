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

Revision: 2026-08-29 r5 — Part G execution status added; Part F decisions recorded (r4: §B.8 Unattended access, second review pass).

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
│   ├── tornect-codec/          # trait Encoder/Decoder + ffmpeg-hw backend (nvenc/amf/
│   │                           #   qsv/vaapi/videotoolbox/software x264|dav1d fallback)
│   ├── tornect-audio/          # capture (wasapi/sckit/pipewire), opus enc/dec, playback (cpal)
│   ├── tornect-input/          # client-side event mapping; host-side inject backends
│   ├── tornect-platform/       # OS session services (§B.8.8): presence, lock state, keep-awake,
│   │                           #   autostart, OS re-auth, hotkeys, readiness probes, owner-only
│   │                           #   local IPC endpoint + peer check only (not a network socket;
│   │                           #   the message types are tornect-core's); FFI per module
│   └── tornect-session/        # host & client state machines wiring everything; unattended: the
│                               #   UI-backed BlockWindow/LocalAllow impls + Candidates onward (§B.8.14)
├── apps/
│   └── tornect/                # eframe app (tray, popups, settings, stream window); host-role IPC
│                               #   dispatch loop (decodes with the core codec, dispatches to the
│                               #   MutationGuard, §B.8.7.4)
├── xtask/                      # cargo xtask: dist, packaging, ffmpeg fetch, lint-all
├── fuzz/                       # cargo-fuzz targets (§D.5); excluded from the workspace
└── tests/
    ├── integration/            # loopback e2e, signaling-over-localhost-tor mocks,
    │                           #   unattended adversarial suite (§B.8.15)
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
   │ SESSION POPUP on host: Allow once /  │  (never skippable — no "always allow";
   │ Allow once (view-only) / Deny        │   link "Set up unattended access…" opens
   └──────────────────────────────────────┘   the local §B.8 enable flow)
   └─ unattended branch (§B.8.4), no popup: AUTH_CHALLENGE{ke2} ──►  ◄── AUTH_RESPONSE{ke3}
      pinned device key + per-grant password (OPAQUE) replace the click; block window
      with [Block] on the host; indicator + log unchanged
SESSION_ACCEPT{caps chosen, session_token | token_confirm, quic_server_cert_fp, session_type, mode}
◄── CANDIDATES{[]}  ──── both sides gather in parallel ────  CANDIDATES{[]} ──►
        host: local addrs, UPnP/NAT-PMP mapped, STUN reflexive (if enabled)
punch: paced bidirectional QUIC Initial+padding to all candidate pairs (trickle ok)
════════════ direct QUIC established (TLS1.3, both certs pinned) ═════════════
        first frame on ctrl, both directions: BIND{mac} over the TLS exporter keyed by session_token
        (§B.8.4.3); nothing else is accepted, and capture never starts, before a valid BIND
        └─ if no pair succeeds within 4 s: TOR_FALLBACK{} → open second onion
           stream and carry the same QUIC connection (and thus the BIND check)
           over a length-framed tunnel
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
own crypto; and it is what makes the SAS code sound). `AUTH_CHALLENGE` and
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
  (invalidates all pairings and unattended grants, by design).
- **Client device identity** = per-device ed25519, generated at install.
- **Pairing** = mutual key pinning gated by human consent + 6-digit SAS derived from
  the signed transcript (blocks a MITM who somehow proxied the onion rendezvous —
  belt-and-suspenders; Tor already authenticates the service side).
- **Session transport**: QUIC TLS 1.3, self-signed certs whose SPKI must match the
  pinned device keys, plus the `BIND` exchange (§B.8.4.3: an HMAC over the TLS exporter
  keyed by `session_token`, sent first on `ctrl` by both sides; nothing else is accepted
  before it verifies). No CAs, no clock-dependent validity.
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
| Attended session | A human on the host clicks *Allow once* / *Allow once (view-only)* in the §B.2 popup. |
| Unattended session | Started with no click. Requires **F1** possession of a SAS-pinned device key (fresh signature in this stream) *and* **F2** knowledge of that grant's password (PAKE). Nothing else opens this path. |
| Grant | Host-local record `{device_pk, mode, schedule, expiry, limits, auth record, fail state}` for one paired device. One grant per `device_pk`. Created/widened only locally, with OS re-authentication — by the UI or the CLI through the running host, or, with no host running, by the CLI holding the store lock and running the same `MutationGuard` + `ReAuth` code (B.8.6.2, B.8.14); unlocked locally the same way or by an admin request from a Control grant of the *My machines* preset (B.8.6.2). |
| Grant password | Chosen per grant at enable time, typed on the host once (host runs both OPAQUE roles in-process, then zeroizes it) and on the client at login. Never transmitted at login; with suite 1 never stored on the host (the SPAKE2 fallback suite stores a wrapped password-equivalent, B.8.4.7). Blast radius of a leaked password = one device. |
| `ServerSetup` | Host-wide OPAQUE secret (OPRF seed + static AKE key), created lazily — together with `K_master` and the store — at the first unattended enable, inside the re-auth flow where the keychain is interactive (never at host start, B.8.9); kept across off/on cycles; wiped only by *Rotate ID*. |
| Block window | Fixed per-grant delay (0–30 s, disclosed only in the signed `SESSION_ACCEPT`, never before F2) before `SESSION_ACCEPT` during which a local Tornect window with one button, **Block**, is shown. Elapsing is not consent; it is a veto opportunity. Constant duration regardless of idle state. |
| Hard lock | Grant refuses all challenges until unlocked locally (re-auth) or by an admin request from another *My machines* Control grant (B.8.6.2). Unlock resets `FailState` (a remote `unlock(pk)` also clears `Suspended{Admin}`); `Suspended{LocalBlock\|Panic}` needs a local *Resume* with re-auth (B.8.6.3). |
| Admin request | Post-PAKE, reduce-only (plus *unlock*) command from a granted device in `Active` state; its scope depends on the requester's grant (B.8.4.1); never starts media. |

**Scope (v1):** hosts inside a logged-in, unlocked desktop session on Windows, macOS, GNOME ≥ 45
/ KDE Plasma 6 (`wayland.md` §9.5); direct, Paranoid and LAN-only transports; control or
view-only. **Non-goals (v1):** remote grant creation or password reset (no message exists);
login screens, the Windows secure desktop, the GNOME lock shield, pre-boot disk unlock (v2
"service mode", B.8.8); waking sleeping hosts (WoL backlog); multi-user hosts; mobile clients.

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
| T1 | Stolen client, password not remembered | Pass HELLO/SESSION_REQUEST; learn that a grant exists for *this* device (not its block window or ask policy — signed into `SESSION_ACCEPT` only, after F2); per local unlock ≤ 60 guesses plus ≈ 52/year of decay, at ≤ 24/day in steady state (≈ 33 on the first day when `hard_lock_after = 0`) and ≤ 20 consecutive (B.8.2.1, B.8.5) | Log in; attack offline (no record on the device; KE2 tests exactly one guess) | Lockout ladder, hard lock, notifications, log, revoke; owner's other *My machines* Control devices can `revoke` via admin request |
| T2 | Stolen client, password remembered, device unlockable | Full impersonation of that grant until revoked; if the grant is a *My machines* Control grant: deny-direction admin requests against the owner's other grants (`suspend`/`revoke`/`revoke_all`/`master_off`/`end_session` — a DoS countered only by the stop code or the local UI) and `unlock` of them (lets a thief who also holds another of the owner's devices keep guessing at ladder rate) | Through Tornect's own surfaces: widen its grant, create grants, change settings without OS re-auth; clear a local Block/panic suspension remotely; suppress the indicator, the per-start notification or the log line of its own sessions for an owner who looks (a Control grant additionally inherits T9's endpoint-level powers) | "Remember" off by default; keychain use requires OS user presence where the platform offers it; one session per grant; per-start notification; remote `revoke`/`master_off` from another *My machines* Control device; emergency stop code; view-only default for helpers (no cross-grant admin scope) |
| T3a | Copy of the state dir, `K_master` in an unlocked-only OS keychain (Windows DPAPI, macOS Keychain, Secret Service) | Read pairing metadata and the session log — `trusted-devices.toml`, `hosts.toml` and `sessions.log` are plaintext (pinned labels, device and grant ids, session times, transport kinds; no secrets); file sizes/mtimes | Read records/`ServerSetup`; impersonate the host | AEAD store under `K_unatt`; those files stay readable by design (the log must remain inspectable) and are named in the SECURITY.md threat model (M8) |
| T3b | Copy of the state dir on a **file-keystore host** (headless Linux, no Secret Service) or a home-dir backup/sync + cracked OS login password | = T4 | — | Stated honestly in readiness ("weaker keystore"); zxcvbn ≥ 4 or generated passphrase enforced; expiry capped at 90 d; TPM-sealed keystore is post-v1 |
| T4 | State dir + `K_master` | Offline dictionary attack per record at Argon2id cost (B.8.2.2); impersonate the host | Log in without cracking (OPAQUE record ≠ password-equivalent) | Argon2id 64 MiB/t=3, strength policy, distinct passwords per host |
| T5 | Online guessing, no paired key | Nothing: unpaired pk ⇒ byte-identical §B.2 PAIR path, no PAKE, no distinguishable timing; `HELLO_ACK.feats` is host-wide | Learn whether unattended exists, or whether a pk is paired here (a bad `HELLO` signature is `E_BAD_SIG` for pinned and unpinned pks alike, B.8.4.2) | §B.3 PoW, token bucket, temp-ban; restricted discovery hides the descriptor |
| T6 | Recorded transcript | — | Replay (client nonce in HELLO and host nonce in HELLO_ACK make both signatures fresh from either side's view; per-stream KE1/KE2; `msg_id`); reflect (roles asymmetric) | B.8.4.3 |
| T7 | Phishing host (user dials attacker's onion) | Receive HELLO (incl. a `stop_token` bound to its own pk, useless at the real host, B.8.7.4) and KE1 (blinded, useless) | Relay to the real host: `context`/`identifiers` embed the dialed onion pk; KE3 MAC fails; with suite 1 the client emits nothing password-derived before KE2 verifies; with suite 2 it gets one online guess per stream and no offline oracle (`pA` blinded by `x`, `cA` verifiable only for the guess embedded in `pB`) | PAKE (B.8.4.7 for the fallback suite) |
| T8 | Downgrade | Ask for an attended session (strictly safer) | Force a weaker suite/KSF (suite fixed per grant and a build-time constant on the client — never derived from `HELLO_ACK.feats` when suite 1 is compiled in, B.8.4.2; KSF constants inside the suite; suite byte in signed transcript + context) | B.8.4.4 |
| T9 | Malicious or compromised **granted Control** device | Everything the OS user can: read keys, start scripts, edit files, delete logs — including reading `K_master` from the user keychain (readable without presence, which is what autostart requires) and therefore rewriting the store, the generation anchor and the log chain, then restarting the host; on a Windows host started from the opt-in elevated autostart task (B.8.7.5) every Control session is additionally an administrator session | Use Tornect's *own* surfaces (UI, IPC, CLI) to create/widen/unlock grants or rebind the panic key without the OS credential: there, mutations need OS re-auth and no active session, and popups are never shown during a remote session. Re-auth and the mutation guard raise the bar for misuse through those surfaces and make changes visible (banner, notifications); they do not stop an endpoint-level rewrite, which is endpoint compromise — out of scope per §B.6 and the reason presets default helpers to view-only | Least-privilege presets (view-only default for helpers — the real control), block window, panic key, remote revoke; the log chain detects tampering only by parties without `K_master` (macOS Keychain code-signing ACLs partially mitigate; presence-gated policy signing is backlog, B.8.9) |
| T10 | Coercion / support scam | Talk the owner through pairing + granting | Do it remotely, silently or instantly (12 h cooling-off for helpers; re-auth; scam step in the wizard) | B.8.7.1 |
| T11 | Lockout-as-DoS | Burn the grant of a key it holds (incl. a cloned key) | Lock other grants (counters per grant; global limits only answer `UA_BUSY`, and uncharged `HelloVerified` streams never occupy them, B.8.5.2) | Remote unlock via another *My machines* Control device; `fail_summary` in `SESSION_ACCEPT` |
| T12 | Clock manipulation (local or NTP) | Shorten a *persisted* lock by a forward wall-clock jump across a host restart (which a pre-authentication attacker cannot force; a live Control session (T9) can, and is bounded by the count-based budgets) | Shorten a running lock (`Instant`-based) or shorten any lock by rollback; revive expired grants or schedules (rollback ⇒ fail closed); exceed the hard-lock budget (count-based budgets are unaffected) | B.8.5.3 |

**B.8.2.1 Online economics (host-enforced).** Per grant, consecutive failures: 20 challenges
take 10 h 53 min 40 s at the earliest (table B.8.5.1), then hard lock; the lifetime budget (60
failures per unlock) stops reset-on-success farming by a cloned key. `hard_lock_after = 0`
disables the *consecutive* hard lock only (warned); the lifetime budget always applies, so even
then an attacker gets at most 60 guesses per local unlock. Until that budget is spent the ladder
alone (60 min per failure from n ≥ 10) caps the steady state at 24 guesses/day/grant — for an
attacker without owner-driven resets and with an honest clock; a cloned key that watches the owner
log in gets 2 free + a few cheap guesses per owner login, bounded by the lifetime budget and the
notifications. Net, **per local unlock: ≤ 60 failures plus ≈ 52/year of decay, at ≤ 24/day in
steady state (≈ 33 on the first day when `hard_lock_after = 0`: 10 inside 53 min 40 s, then one per
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
HELLO            (client, signed)  += { v_max: u8, client_nonce: bytes[32], feats: [tstr] /* "ua1" | "ua2": the PAKE suites this build supports (a build-time constant, B.8.4.2) */, stop_token: Option<bytes[32]> /* SHA-256("tornect/v1/stop\0" || dialed_host_onion_pk || stop_code), never the code (B.8.7.4) */ }
HELLO_ACK        (host, signed)     { v: u8 /* chosen */, host_nonce: bytes[32], feats: [tstr] /* host-wide, independent of the peer (T5); no host_name — unauthenticated fingerprinting surface before F1; the client shows the paired label instead */ }
PAIR_ACCEPT      (host)            += { host_name: tstr }   /* unpaired peers learn the name here, after consent, never before */
SESSION_REQUEST  (client, signed)  += { unattended: Option<{ suite: u8 /* 1 = OPAQUE-3DH-r255-SHA512-Argon2id(64MiB,3,1) · 2 = SPAKE2 fallback (B.8.4.7) */,
                                        ke1: Option<bytes[96]> /* required iff suite = 1 */, want_mode: u8 /* 0 control, 1 view-only */,
                                        intent: u8 /* 0 session, 1 admin */, admin: Option<AdminCmd> /* required iff intent = 1, else E_BAD_LEN */ }> }
AUTH_CHALLENGE   (host)             { suite: u8, ke2: Option<bytes[320]> /* iff suite = 1 */, salt: Option<bytes[16]>, pB: Option<bytes[32]> /* iff suite = 2 */ }
                                        /* no grant policy here: block_window_s / ask_before_start travel only in the signed SESSION_ACCEPT, after F2 (T1 must not learn a veto-less target) */
AUTH_RESPONSE    (client)           { ke3: Option<bytes[64]> /* iff suite = 1 */, pA: Option<bytes[32]>, cA: Option<bytes[32]> /* iff suite = 2 */ }
SESSION_ACCEPT   (host, signed)    += { session_type: u8 /* 0 attended, 1 unattended */, mode: u8,
                                        transport_policy: u8 /* 0 any, 1 tor_only, 2 lan_only */,
                                        session_token: Option<bytes[32]> /* attended only; MUST be absent when session_type = 1 */,
                                        token_confirm: Option<bytes[32]> /* unattended only */,
                                        block_window_s: u8, ask_before_start: bool /* grant policy, disclosed only here (signed), after F2 */,
                                        ends_at: Option<u64>, fail_summary: Option<{ since_success: u32, last_fail_at: Option<u64> /* Some whenever since_success > 0 */ }> /* the snapshot returned by settle(ok) with this stream's own charge excluded; None when since_success == 0 (B.8.5.1) */ }
SESSION_REJECT   (host)             { reason: u16, cause: Option<u8> /* HOST_NOT_READY: 1 capture_permission · 2 input_permission · 3 locked · 4 other_user_active */,
                                        retry_after_s: Option<u32> /* LOCKED_OUT, COOLDOWN; never SUSPENDED (no timer: cleared only per B.8.6.3) */, next_open_in_s: Option<u32>, detail: Option<tstr ≤ 120> }
ADMIN_RESULT     (host, signed)     { ok: bool, detail: Option<tstr ≤ 120> }
AdminCmd = { op: u8 /* 1 revoke(pk) · 2 revoke_all · 3 master_off · 4 unlock(pk) · 5 suspend(pk) · 6 end_session */, device_pk: Option<bytes[32]> }
BYE              (either)           { reason: u16, detail: Option<tstr ≤ 120> }
  reason: 0x01 USER · 0x02 REVOKED · 0x03 MASTER_OFF · 0x04 EXPIRED · 0x05 SCHEDULE_END · 0x06 MAX_SESSION · 0x07 HOST_LOCKED · 0x08 PANIC
        · 0x09 NO_LAN_PATH · 0x0A ADMIN_END · 0x0B EMERGENCY_STOP · 0x0C CLIENT_AUTH_ABORT (KE2 MAC failed) · 0x0D ORPHANED · 0x0E REPLACED
        · 0x0F PAUSED · 0x10 SUSPENDED   /* deny-direction change → BYE reason mapping in B.8.6.1 */
ERROR            (either)           { code: u16 /* 0x0001 E_BAD_STATE · 0x0002 E_BAD_SIG · 0x0003 E_BAD_MSG_ID · 0x0004 E_TOO_LARGE · 0x0005 E_UNKNOWN_KIND · 0x0006 E_VERSION · 0x0007 E_BAD_LEN */, detail: Option<tstr> }
```
`ke1/ke2/ke3` carry raw `serialize()` bytes (exact lengths 96/320/64 checked before
deserialization); a suite-specific field missing for the negotiated suite, or present for the
other one, ⇒ `E_BAD_LEN`. `want_mode` is clamped host-side to the more restrictive of the two —
`max(grant.mode, want_mode)` under this encoding (`SessionMode::most_restrictive(a, b)`; a view-only
grant plus `want_mode = 0` yields view-only, never Control) — never a reject. `stop_token` (B.8.7.4)
may come from any peer; it is `SHA-256("tornect/v1/stop\0" || dialed_host_onion_pk || stop_code)`,
never the code itself; the host compares it in constant time against the value it stored at enable
time (computed with its own pk) and otherwise ignores the field, so the unpaired path stays
byte-identical.
Attended sessions: `block_window_s = 0`, `ask_before_start = false`, `transport_policy` = host
privacy mode (Paranoid ⇒ `tor_only`, LAN-only ⇒ `lan_only`, else `any`), `ends_at = None`,
`fail_summary = None`.
**Admin scope:** `unlock(pk)`, `suspend(pk ≠ self)`, `revoke(pk ≠ self)`, `revoke_all` and
`master_off` require the requester's grant to have `mode = Control`, `preset = MyMachines` and
state `Active`; every other grant (helpers, view-only) may only `end_session` (its own session)
and `revoke` (its own pk). Out-of-scope ops ⇒ `ADMIN_RESULT{ok: false}`, no state change, logged
(`AdminRequest`, refused). `unlock(pk)` resets the target's `FailState` and clears
`Suspended{Admin}` (set by a remote `suspend(pk)`); it never clears `Suspended{LocalBlock|Panic}`,
which needs a local *Resume* with re-auth (B.8.6.3).

**B.8.4.2 Sequence (happy path; Tor RTT 0.4–1.5 s per arrow pair).**
```
Client                                                             Host
prompt password (or keychain) → ClientLogin::start(pw) → ke1
HELLO{v_max, client_nonce, device_pk, name, feats, sig} ────────►  verify sig vs HELLO's own pk (proof of possession) and, if pinned, pk == pinned key;
                                                                    bad sig ⇒ E_BAD_SIG for pinned and unpinned alike; unpaired ⇒ §B.2 PAIR path, unchanged
◄──────────────────────────── HELLO_ACK{v, host_nonce, feats, sig}  (signed with the onion identity key; client verifies vs dialed address)
SESSION_REQUEST{caps, unattended:{suite, ke1, want_mode, intent}, sig} ►  verify sig over th (fresh: covers host_nonce) — F1
                                                                    grant lookup: none/disabled/expired/master-off ⇒ REJECT{NOT_GRANTED}
                                                                    suite unsupported by this build or ≠ grant.suite ⇒ REJECT{UNSUPPORTED_SUITE}; now < active_from ⇒ REJECT{NOT_YET_ACTIVE, next_open_in_s}
                                                                       (both pre-PAKE, uncharged; evaluated after the grant lookup and before the suspension/lock/budget checks)
                                                                    suspended (LocalBlock · Panic · Admin) ⇒ REJECT{SUSPENDED}   (no timer; cleared per B.8.6.3)
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
◄── SESSION_ACCEPT{caps, session_type:1, mode, transport_policy, token_confirm, block_window_s, ask_before_start, ends_at, fail_summary, sig}
verify sig; token_confirm == own derivation (ct); session_type matches request; grant policy read from here only       host: sessions.log start; indicator ON
CANDIDATES … punch … QUIC (exporter check on the derived token) … media — unchanged from §B.2 (tor_only: no CANDIDATES, immediate TOR_FALLBACK);
  the Tor fallback tunnels the same QUIC connection, so the exporter/token check applies unchanged on both transports
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
| `HelloVerified` | `SESSION_REQUEST{unattended}` with valid sig | gate, in this order (all pre-PAKE, uncharged): grant lookup (`NOT_GRANTED`) · suite unsupported by this build or ≠ `grant.suite` ⇒ `UNSUPPORTED_SUITE` · `now < active_from` ⇒ `NOT_YET_ACTIVE{next_open_in_s}` · state: suspended ⇒ `SUSPENDED` · lock · budget ⇒ reject+close (no PAKE), or charge → `ServerLogin::start` → `AUTH_CHALLENGE` → `AwaitKe3` (30 s) |
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
`0x0014 UNSUPPORTED_SUITE`, `0x0015 NOT_YET_ACTIVE` (cooling-off; `next_open_in_s`), `0x0016
SUSPENDED` (`Suspended{LocalBlock|Panic|Admin}`; no `retry_after_s` — cleared only per B.8.6.3, so
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
is the only reset of the consecutive counter and reverts only its own charge.

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
`FailState.decay_anchor` (consecutive, period 24 h; set to now at every charge and every
`settle(fail)`) and `FailState.lifetime_decay_anchor` (`since_unlock`, period 7 d; set to now at
every `settle(fail)`) — two anchors, because advancing one anchor by 24 h steps would starve the
7-day decay; each is also set whenever a decay step is applied to its counter. Decay is applied on
load and before each charge: `steps = (now − anchor) / period`, subtract `steps` (saturating at
0), advance the anchor by `steps × period`; a rollback (`now < anchor`) applies no decay (B.8.5.3).

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
never the keychain anchor — B.8.9). In-process timers use `Instant`; on disk the
store keeps `lock_remaining_s` + `flushed_at`; on load `locked_until = now + max(0,
lock_remaining_s − max(0, now − flushed_at))`. If `now < last_seen` (rollback) locks are re-armed
in full, schedule/expiry fail closed until the clock passes `last_seen`, and `clock_anomaly` is
logged. A forward jump cannot shorten a running lock (`Instant`-based); it shortens a persisted
lock only across a host restart, which a pre-authentication attacker cannot force (a live Control
session, T9, can — and is bounded by the count-based budgets); count-based budgets are
unaffected. A missing or
undecodable store ⇒ unattended off + notification (never "counters start at zero").

#### B.8.6 Grants, mutations, presence, sessions

**B.8.6.1 Grant lifecycle.** Precondition: SAS-paired *and* ≥ 1 completed attended session
from that device (waivable with an explicit warning; *Headless box* auto-waives). Presets set
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

**B.8.6.2 Mutation policy (one enforcement point — `tornect-core::unattended::MutationGuard`,
B.8.14 — in the host process; UI, IPC and CLI all pass through it).**

| Class | Operations | Allowed when | Requires |
|---|---|---|---|
| Deny-direction | master off, pause (12 h / until 08:00 / until re-enabled), revoke, revoke-all, disable (`Active` → `Disabled{by: Ui\|Cli}`, B.8.6.1), suspend, end session, emergency stop | always — during remote sessions, from tray, CLI, panic key, admin request or stop code | nothing |
| Access-increasing | master on, create grant, enable grant (`Disabled` → `Active`, B.8.6.1), set/change password, unlock/unsuspend, extend expiry, widen schedule, mode → Control, lower block window, disable "Ask before starting", change notification/panic-key/keep-awake/autostart settings (autostart via `tornect service install\|uninstall` = `IpcOp::ServiceInstall\|ServiceUninstall`, B.8.7.4), backup import, backup export (it writes `K_master` + `ServerSetup` + every auth record, B.8.9; `BackupExported{by, path}` logged, banner raised) | no remote session active for ≥ 60 s | **OS re-authentication** (B.8.8 table) in a fresh dialog per operation (a two-message IPC registration is one operation: re-auth at `RegStart`, `reg_txn` at `RegFinish`, B.8.7.4) |
| Remote admin (B.8.4.1) | from a *My machines* Control grant: revoke(pk), revoke_all, master_off, suspend(pk), end_session, unlock(pk) — the only remote path that clears a lockout; from any other grant: end_session (own session) and revoke (own pk) only | after F1 + F2 from a grant in `Active` state (`Suspended`/hard-locked grants cannot; `NOT_YET_ACTIVE` still applies); schedule, readiness, transport, busy and concurrency gates are skipped, so it works even while another session is live | the requester's own two factors; out-of-scope ops ⇒ `ADMIN_RESULT{ok: false}`; logged with the requester's device; unlock resets `FailState` and clears `Suspended{Admin}`, never `Suspended{LocalBlock\|Panic}` |

The CLI never edits files while the host runs: it talks to the host over the local IPC
endpoint (B.8.7.4) and runs the OPAQUE client role itself for registration, so the password
never crosses IPC; with no host running it takes the store lock and runs the same `MutationGuard`
+ `ReAuth` code (B.8.14) — the only offline path, under identical rules.
Consent popups (PAIR/SESSION) are **not presented while a remote session is active** (answered
with the attended `BUSY` `0x0003` — not the pre-PAKE `UA_BUSY` `0x0013` of B.8.4.6 — owner notified
afterwards, `popup_suppressed_remote_session` logged). An in-app banner
"N devices can connect without asking — last change <when> by <ui|cli|import>" stays until
acknowledged with re-auth after any grant creation, widening or backup export.

**B.8.6.3 Block window and presence.** A Tornect-owned always-on-top window (best-effort on
Wayland: focused window + `notify-rust` action + chime) with exactly one control, **Block**, no
close/dismiss, re-asserted every 500 ms, on every captured monitor, lasting exactly
`block_window_s` whether or not anyone is present (no presence oracle). Block ⇒
`BLOCKED_BY_LOCAL_USER` and grant `Suspended{LocalBlock}` until a local *Resume* (re-auth; a
remote `unlock` never clears it) — no whack-a-mole. Clearing rules: `Suspended{Admin}` (set by a
remote `suspend(pk)`) is cleared by a local *Resume* (re-auth) or by a remote `unlock(pk)` from a
*My machines* Control grant; `Suspended{LocalBlock|Panic}` only by a local *Resume*. A suspended
grant is refused pre-PAKE (`SUSPENDED`, B.8.4.6). Presence detection (physical input only —
Tornect subtracts its own injections: `LLKHF_INJECTED`, macOS event-source PID, Wayland injection
timestamps ± 250 ms) drives only the "While you were away" card and the optional
`require_absent` reject; unknown ⇒ present. "Ask before starting" (default on for *Helping
someone*) layers the Allow/Deny popup (60 s ⇒ `DENIED`) on top of the PAKE: host state
`AwaitLocalAllow` between F2 and the block window (B.8.4.5); the client does not learn
`ask_before_start` (nor `block_window_s`) before the signed `SESSION_ACCEPT` and waits the fixed
110 s maximum (B.8.4.5).

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
up.") + this OS's limits (B.8.8); ② pick a paired device with ≥ 1 attended session; ③ preset;
④ password: generator pre-filled (5 EFF-long-list words, ≈ 65 bits, shown once, not copyable),
"use my own" secondary with the live meter and the B.8.2.2 offline estimate; registration runs
in-process; ⑤ options: mode, schedule (host-local weekly windows; wrap past midnight; DST gap ⇒
inside if either side is, overlap ⇒ first occurrence; TZ snapshot, warned on change), expiry,
block window, `hard_lock_after` (0 = consecutive hard lock off — warned: guessing is then bounded
only by the lifetime budget — ≤ 60 failures per local unlock plus ≈ 52/year of decay, at ≤ 24/day in
steady state, ≈ 33 on the first day — and the notifications, B.8.2.1), "Ask before starting", `require_absent`, `require_tor_only`,
keep-awake (host-wide, B.8.7.5),
lock-on-disconnect (refused with *Headless box*; warned on Windows/GNOME), "Prevent idle lock
while unattended access is on" (default off; whether `ES_DISPLAY_REQUIRED` overrides an
`InactivityTimeoutSecs` policy lock is NEEDS-DEVICE(windows) — the copy claims only what the
readiness probe confirms);
⑥ **Readiness**: capture + input permissions/restore tokens, autostart, auto-login state (never
configured by Tornect; the pre-boot disk-unlock trade-off stated), keystore persistent and
unlockable at autostart (canary entry), empty OS account password (detected — red:
"re-authentication cannot protect settings on this account") plus the static advisory "Tornect
cannot judge the strength of your OS password; unattended access is only as safe as it" (Tornect
can detect only the empty case), idle-lock policy (`InactivityTimeoutSecs` /
`askForPassword` / `lock-enabled`) + current lock state, console ownership, Tor self-connect,
panic key bound, tray; red rows need "Enable anyway — it will not work until fixed"; ⑦ summary +
stop-code card. Readiness re-runs at host start and every 10 min (macOS 15+ periodic
screen-recording re-consent, Wayland token loss) ⇒ sticky in-app badge + `HOST_NOT_READY`.

**B.8.7.2 Password policy (normative).** UTF-8, NFC-normalized on both sides
(`unicode-normalization`), never trimmed (warn on leading/trailing whitespace); 12–128 chars;
runs of whitespace/hyphens between passphrase words normalized to one space on both sides;
`zxcvbn` score ≥ 3 with `user_inputs` = {host name, device labels, onion address, OS user
name, "tornect"}, **≥ 4 when the host keystore is file-based** (where expiry is also capped at
90 d and "never" refused, B.8.6.1); distinct passwords per host
recommended in copy. Change = new registration for that grant (re-auth). All intermediates in
`Zeroizing`; egui fields cleared incl. undo state; no clipboard copy of password fields.

**B.8.7.3 Manager, notifications, indicator.** Main-screen badge "N devices can connect
without asking". Per grant: pinned label (never the HELLO name; NFKC, bidi/control characters
stripped, ≤ 64 chars, duplicates get a fingerprint suffix), fingerprint, created-by, last used,
state (Active / Not yet active / Disabled{by} / Suspended{reason} / Locked{until} / Hard-locked / Expired),
`failures_since_unlock`, *Unlock* (re-auth), *Change password*, *Disable* (`Active` →
`Disabled{by: Ui}`, no re-auth; the matching *Enable* needs re-auth, B.8.6.1), *Revoke unattended*, *Remove
device*; header: master toggle, *Pause*, *Revoke all*. Notifications are in-app windows
mirrored to OS toasts (never toasts alone — DND/Focus hide them; GNOME has no tray without an
extension): session starting (with Block), session ended, every failure from the second onward, lock/hard lock
(sticky; *Unlock* routes through the manager + re-auth), not-ready, "While you were away: …"
on the first physical input after an unacknowledged session. Indicator: OS-enforced indicators
where they exist (macOS SCK, GNOME/KDE screencast icon) plus the §B.6 pill "**Unattended** ·
Laptop-of-Ana · Control · [End]", re-asserted every 500 ms, un-closable, on every captured monitor.

**B.8.7.4 Panic key, CLI, IPC, emergency stop.** Panic (`security.panic_key`, default
Ctrl+Alt+End) ends any session and, if it was unattended, suspends that grant; pressed **twice
within 2 s** ⇒ master off (persisted) + toast (hold-to-disable is NEEDS-DEVICE where key-up is
unavailable). Detection uses physical events only (Windows low-level hook filtering
`LLKHF_INJECTED`; macOS `CGEventTap` with source-PID filter; Wayland GlobalShortcuts portal bound
in the wizard, readiness row "Panic key: bound / unavailable"); the indicator's End button, the
tray item and `tornect panic` always work; rebinding needs re-auth. **CLI:** `tornect unattended
status|on|off|pause|grant <device> [--preset …] [--waive-attended-check]|enable <device>|disable <device>|revoke <device>|--all|unlock <device>|suspend
<device>|resume <device>|set-password
<device>|readiness|log`, `tornect service install|uninstall|status`, `tornect panic`, `tornect
backup export|import` (`--waive-attended-check` maps to `GrantOptions.waive_attended_precondition`,
warned and logged; `backup export` is access-increasing, B.8.6.2; `disable` is deny-direction,
`IpcOp::Disable`; `service install|uninstall` = `IpcOp::ServiceInstall|ServiceUninstall` through
the guard — an autostart change is access-increasing, B.8.6.2, and with no host running the CLI
runs the guard offline like any other mutation); passwords via TTY prompt, never argv. **IPC:** `<state_dir>/ipc.sock`
(0600, `SO_PEERCRED` check) / `\\.\pipe\tornect-<hash(state_dir)>` (owner-only DACL,
`PIPE_REJECT_REMOTE_CLIENTS`, server SID/PID verified), owned by `tornect-platform::ipc`; the
host holds an advisory store lock. **Emergency stop code:** 16 random bytes shown once at enable
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
IpcOp = Status | On | Off | Pause { until: u64 } | Revoke { device: DeviceId } | RevokeAll | Unlock { device } | Suspend { device } | Resume { device }
      | Enable { device } /* Disabled → Active; access-increasing (B.8.6.2) */
      | Disable { device } /* Active → Disabled{by: Ui|Cli}; deny-direction: no re-auth, a live session of that grant gets BYE{REVOKED}; GrantDisabled{by} logged (B.8.6.1) */
      | ServiceInstall { elevated: bool /* Windows opt-in elevated task, B.8.7.5 */ } | ServiceUninstall /* tornect service install|uninstall: an autostart change is access-increasing (B.8.6.2) — re-auth, no remote session ≥ 60 s; no store write; AutostartChanged{by} logged */
      | Readiness | Log { filter: tstr, after: Option<u64> } | Panic | BackupExport { path: tstr } /* access-increasing: re-auth, no remote session ≥ 60 s, BackupExported logged */ | BackupImport { path: tstr }
      | PolicyInputs                                                          → payload = { user_inputs: [tstr], min_score: u8 }   /* B.8.7.2 inputs; the CLI runs zxcvbn locally and refuses weak passwords itself */
      | RegStart  { device, reg_request: bytes[32] }                          → payload = { reg_response: bytes[64], reg_txn: bytes[16] }   /* a CBOR map like every payload; re-auth happens here; txn single-use, ≤ 120 s, bound to device */
      | RegFinish { device, reg_txn: bytes[16], upload: bytes[192], preset: u8, options: GrantOptions }   /* grant (no grant yet) / set-password (grant exists): the CLI runs ClientRegistration itself; re-checks RemoteSessionActivity before applying (below) */
payload per op: Status → StatusReport { enabled: bool, paused_until: Option<u64>, grants: [GrantSummary /* id, device, label, preset, mode, state, expires_at, last_used, failures_since_unlock */],
                                        readiness: ReadinessSnapshot, keystore_kind: u8 /* 0 os_keychain · 1 file */ }
                Readiness → ReadinessSnapshot (B.8.14) · Log → { lines: [tstr], next: Option<u64> } /* paged: ≤ 60 KiB per response, `next` is the cursor for the following Log{after} */
                every other op → payload absent
GrantOptions = { label, mode, schedule, expires_at, auto_renew, max_session_secs, block_window_s, ask_before_start, require_absent,
                 require_tor_only, lock_on_disconnect, hard_lock_after, waive_attended_precondition: bool }   /* the policy subset of UnattendedGrant (B.8.9); also the argument type of MutationGuard::create_grant / set_options (B.8.14) */
G_* codes: 0x0100 G_REAUTH_FAILED · 0x0101 G_REMOTE_SESSION_ACTIVE · 0x0102 G_PRECONDITION · 0x0103 (reserved; was G_WEAK_PASSWORD — the host never sees the password, the CLI enforces B.8.7.2 via PolicyInputs)
           · 0x0104 G_KEYSTORE_LOCKED · 0x0105 G_STORE_LOCKED · 0x0106 G_NO_TXN (RegFinish without a live reg_txn)
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
grant is *set-password*: it replaces the auth record and may not widen `options` except through
the guard (widening is access-increasing); for a device without a grant it is *grant*.
`BackupExport` is access-increasing (B.8.6.2): refused while a remote session is live or ended
< 60 s ago, `BackupExported{by, path}` logged, in-app banner raised.

**B.8.7.5 Autostart, sleep, wake.** `tornect service install` (through the guard: re-auth,
`AutostartChanged{by}` logged, B.8.7.4) registers a user-level
autostart (Task Scheduler "At log on"; an elevated task — needed only to inject into elevated
windows past UIPI — is strictly **opt-in** for admins, with the wizard copy "Running the host
elevated makes every remote Control session an administrator session" (T9, B.8.8); `SMAppService`
/ LaunchAgent; `systemd --user` `tornect-host.service` with `WantedBy=graphical-session.target`
or XDG autostart / Background portal for Flatpak). All start *after* login; readiness states the
auto-login dependency. Keep-awake (host-wide, default on: active while any grant is `Active`;
presets may only turn it on, never off): `SetThreadExecutionState(ES_CONTINUOUS |
ES_SYSTEM_REQUIRED)`, `IOPMAssertionCreateWithName(kIOPMAssertionTypePreventUserIdleSystemSleep)`
(does not survive lid close), Inhibit portal `Suspend` (logind `Inhibit("sleep")` fallback). On
resume (`PBT_APMRESUMEAUTOMATIC` / `NSWorkspace.didWakeNotification` / logind
`PrepareForSleep(false)`) the host checks `OnionServiceStatus` and, if not reachable within 60 s,
drops and re-launches the `RunningOnionService`. Lock-on-disconnect (default off) fires only on
session teardown (BYE, panic, QUIC close after the reconnect window), never on transient circuit
loss. Client copy: "Host is offline, asleep, or locked — Tornect cannot wake or unlock it."

#### B.8.8 Platform realities (v1 honesty table; every claim not sourced is NEEDS-DEVICE)

| OS / state | Capture | Input | Remote unlock | Source / status |
|---|---|---|---|---|
| Windows, session unlocked | WGC ✅ | SendInput ✅ (UIPI: not into elevated windows/UAC unless the host runs from the opt-in elevated task of B.8.7.5, which makes every remote Control session an administrator session; secure-desktop switch detected via `OpenInputDesktop` ⇒ `ctrl` notice) | n/a | — |
| Windows, locked (Winlogon secure desktop) / logged out | ❌ | ❌ | **No** — needs a SYSTEM service + secure-desktop agent (v2; Ctrl+Alt+Del also needs the SendSAS policy) | `WTSRegisterSessionNotification` ⇒ `HOST_NOT_READY{locked}` / `BYE{HOST_LOCKED}` |
| GNOME ≥ 45, unlocked, ScreenCast + RemoteDesktop restore tokens valid | PipeWire ✅ | libei ✅ | n/a | `wayland.md` §2.4; both tokens checked by readiness; portal `Start` budget 5 s then `Request.Close()` so no dialog blocks an empty room |
| GNOME, locked | ❌ (mutter inhibits remote access: sessions closed, `CreateSession` refused) | ❌ | **No** by design | `wayland.md` §7 (sourced); backends treat `Closed` as recoverable *Locked* |
| KDE Plasma 6 | portal ✅ | ConnectToEIS ✅ | NEEDS-DEVICE(kde) | lock policy and RemoteDesktop token persistence unverified |
| wlroots/Hyprland | ScreenCast only | no RemoteDesktop portal | — | out of v1 (view-only at best) |
| GDM/SDDM login screen | no session | — | No | — |
| macOS 13+, unlocked | SCK ✅ (TCC bound to the signing identity; macOS 15+ periodic re-consent ⇒ readiness self-test) | CGEvent ✅ (Accessibility) | n/a | signed + notarized builds required for persistent grants |
| macOS, locked / screensaver / login window / FileVault pre-boot | lock UI at best | unreliable (Secure Input) | NEEDS-DEVICE(macos); pre-boot never | lock mechanism NEEDS-DEVICE (`CGSession -suspend` is a user switch, `SACLockScreenImmediate` is private) |

| Capability | Windows | macOS | Linux (GNOME / KDE) |
|---|---|---|---|
| OS re-authentication (only as strong as the OS credential — readiness detects an empty account password and shows the static strength advisory, B.8.7.1 ⑥) | `CredUIPromptForWindowsCredentials` with `CREDUIWIN_SECURE_PROMPT` (secure desktop) + `LogonUser`, or Windows Hello (`KeyCredentialManager`) | `LAContext.evaluatePolicy(.deviceOwnerAuthentication)` | polkit action `org.tornect.unattended.modify` (`auth_self`; text agent over SSH); PAM fallback for headless |
| Physical-input presence | `GetLastInputInfo` minus injected (`LLKHF_INJECTED`) | `CGEventSourceSecondsSinceLastEventType(HIDSystemState)` minus own events | `org.gnome.Mutter.IdleMonitor.GetIdletime` / `org.freedesktop.ScreenSaver.GetSessionIdleTime` (KDE); `ext-idle-notify-v1` behind `linux-wayland-idle`; logind `IdleHint` last resort |
| Lock state / lock / console owner | `WTS_SESSION_LOCK` / `LockWorkStation()` / `WTSGetActiveConsoleSessionId` | `CGSessionCopyCurrentDictionary` (undocumented) / NEEDS-DEVICE | logind `Session.LockedHint` / `login1.Session.Lock` on `session/auto` (`org.gnome.ScreenSaver`, `org.freedesktop.ScreenSaver.Lock` fallbacks) / logind `Active` |
| Prevent idle lock (opt-in) | `ES_DISPLAY_REQUIRED` | `PreventUserIdleDisplaySleep` | Inhibit portal `Idle` |
| Always-on-top block/indicator | ✅ re-asserted (exclusive fullscreen may cover it — tray + chime) | ✅ | no topmost API for clients on Wayland: compositor screencast icon + focused window + chime |

**v2 backlog "service mode":** Windows SYSTEM service + secure-desktop helper (SendSAS), macOS
LaunchDaemon + login-window agent, Linux system-session daemon (gnome-remote-desktop "system"
mode) for lock/login-screen control. Out of v1; the wizard says so in one line.

#### B.8.9 Storage (`tornect-core`)

`K_master[32]` is a `SecretStore` entry `unattended-master.key`: OS keychain via `keyring-core`
+ per-OS stores (`ui.md` §5.9; never `keyring::Entry`) when the readiness canary proves it
persistent and unlockable at autostart, else the existing `FileSecretStore` (0600) with the
"weaker keystore" badge; the host never blocks on a keyring prompt (a host that never enabled
unattended has no `K_master` and nothing to read): `K_master` unreadable at
start or at the 10-min readiness re-run ⇒ readiness state `keystore_locked` ⇒ unattended off
(pre-PAKE `NOT_GRANTED`) + the sticky badge, re-checked every 10 min. `K_unatt = HKDF-SHA256(ikm
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
    pub log_chain_head: [u8; 32], pub last_seen_unix: u64,
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
    pub expires_at: Option<u64>, pub auto_renew: bool, pub max_session_secs: Option<u32>, pub reconnect_cooldown_s: u32,
    pub block_window_s: u8, pub ask_before_start: bool, pub require_absent: bool, pub require_tor_only: bool, pub lock_on_disconnect: bool,
    pub hard_lock_after: u32,                      // 20; 10 for Helping someone / Headless box; 0 = no consecutive hard lock (warned; the lifetime budget still applies)
    pub state: GrantState /* Active | Suspended { reason: LocalBlock | Panic | Admin, since: u64 } | Disabled { since: u64, by: Actor /* Import (backup import) | Restore (machine-id mismatch at load, B.8.12) | Ui | Cli (local Disable, B.8.6.1) */ } */,   // Expired / NotYetActive derived; Disabled ⇒ pre-PAKE NOT_GRANTED, leaves only via `enable` (B.8.6.1); clearing rules B.8.6.3
    pub last_used: Option<LastUsed /* { at, transport: TransportKind, duration_secs } */>,
    pub fail: FailState /* { consecutive: u32, since_unlock: u32, pending: bool /* charged, not yet settled */, last_fail_at: Option<u64>, lock_remaining_s: u32, flushed_at: u64, hard_locked: bool,
                            decay_anchor: u64 /* consecutive, 24 h */, lifetime_decay_anchor: u64 /* since_unlock, 7 d */ /* B.8.5.1 decay bookkeeping */ } */,
}
```
Client side (`hosts.toml` at `Paths::hosts_file()`, M1, + keychain): per host `{ remember,
server_s_pk_pin, suite: Option<u8>, ua_worked_before }` (`server_s_pk_pin` is set at the first
`SESSION_ACCEPT` and checked in `ClientLogin::finish` on every later login, B.8.4.2/A16; `suite`
records the build-time suite of B.8.4.2 at the first successful `SESSION_ACCEPT` — a later mismatch
is surfaced, never negotiated, B.8.10; `ua_worked_before` ≡ `suite.is_some()`);
the remembered password lives only in the OS keychain entry `tornect/unattended/<onion>` (use
gated by Windows Hello / Touch ID / OS password where available; copy: "any program running as
you can read it" on Windows/Linux), marked stale on `AUTH_FAILED` only — never on `PREEMPTED` or a
transport error (B.8.4.6). **Rotate ID** wipes grants,
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
Mon 09:00 host time)", "*Host* is
offline, asleep or locked", and on a `server_s_pk` pin change "*Host*'s unattended setup was
re-created since you last connected — if that wasn't you, revoke devices there" (blocks until
confirmed). HUD badge "Unattended · Control/View"; `fail_summary` surfaces as "3 failed attempts
since your last login"; a client-side `sessions.log` records every unattended connect. Admin
actions (*Revoke this device*, *Turn unattended off at host*, *Unlock my other laptop*, *End the
session at host*) live in the host card and use `intent = admin`; the cross-grant ones (*Unlock…*,
*Turn off…*, revoking *another* device) are offered only for *My machines* Control grants
(B.8.4.1 scope) — every other grant sees *Revoke this device* and *End the session* only.

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
| Locked out legitimately | Wait the ladder; local *Unlock* (re-auth); or `admin unlock(pk)` from another *My machines* Control device (resets `FailState` and clears an admin suspension — a Block/panic suspension needs a local *Resume*). |
| Host reinstall / migration / state-dir restore / older store generation | Detection is the `machine_id_hash` of B.8.9 (`/etc/machine-id` · `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` · `IOPlatformUUID`): a mismatch at load — the state dir was moved to another machine, or the OS was reinstalled and regenerated its id — ⇒ every grant **disabled** (`GrantState::Disabled{by: Restore}`) + notification, re-enabled one by one (*enable*, re-auth, B.8.6.2); a hygiene measure, not a security control (a `K_master` holder rewrites the field, T4/T9). A same-machine snapshot restore is byte-indistinguishable from a normal start and is governed by the anchor rule alone: a store older than the last policy write (a rolled-back generation), a missing `K_master` or an anchor without a store file ⇒ fail closed + notification "unattended store was replaced — re-enable to continue"; a store at or above the anchor loads as-is (runtime-state rollback only, B.8.9). Grants are recreated locally. |
| Rotate ID | Everything unattended wiped (B.8.9); re-pair, re-enable. |

#### B.8.13 Logging / audit (`sessions.log`, JSON Lines, 0600, `Paths::sessions_log()`)

Extends the shipped `SessionRecord`/`SessionEvent` (`tornect-core::session_log`: `unattended:
bool`, `mode`, `transport`, `peer_device` as base32 `DeviceId`; `peer_name` = the **pinned
pairing label**). Shipped (`tornect-core::session_log`): `UnattendedLockout` → renamed
`UnattendedHardLock`; `UnattendedAuthFailed`/`UnattendedAuthSucceeded` kept as the
per-attempt post-PAKE lines. New
`SessionEvent` variants: `UnattendedRejected` (the pre-PAKE reject line, rate-aggregated: one line
per reason per device per 60 s with `count`), `UnattendedChallengeIssued`,
`UnattendedUnlock`, `UnattendedSuspended`, `UnattendedResumed`,
`UnattendedBlockedByLocalUser`, `GrantCreated|Changed|Enabled|Disabled|Revoked|Expired|Pruned`
(`GrantDisabled{by}` is the per-grant *Disable* of B.8.6.1; master off stays `UnattendedDisabled`),
`AutostartChanged` (`by`, B.8.7.4),
`UnattendedEnabled|Disabled|Paused`, `PasswordSet`, `AdminRequest`, `EmergencyStop`, `BackupExported`,
`PopupSuppressedRemoteSession`, `GrantMutationRefused`, `StoreLoadFailed`, `ClockAnomaly`,
`HostNotReady`, `SessionEndingSoon`. New optional fields: `grant`, `by: Actor`, `reason`,
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
the stop code, IPs beyond `transport`.
```
{"ts":"2026-08-28T12:04:31Z","event":"session_started","session_id":"9e…","peer_device":"<base32>","peer_name":"Laptop-of-Ana",
 "mode":"control","unattended":true,"transport":"direct","grant":"7f…","block":"elapsed","prev":"…","tag":"…"}
```

#### B.8.14 Implementation plan (milestone → crate → work → acceptance; M0 is closed and gets nothing)

| MS | Crate(s) | Work | Accept |
|---|---|---|---|
| M1 | `tornect-core` | `UnattendedStore`/`Grant`/`FailState` + AEAD codec + generation anchor + migrations; `K_master`/`K_unatt`; `keyring-core` backend behind a feature with file fallback; `SessionEvent` variants, hash chain, rotation; `Paths::unattended_store()`; fix the `trusted_devices_file` doc (pairings there, grants in the store); `unattended::{GrantStore, MutationGuard}` with the `ReAuth` and `RemoteSessionActivity` traits **defined here** (`MutationGuard::new(store, reauth: Arc<dyn ReAuth>, activity: Arc<dyn RemoteSessionActivity>)`, *Ownership* below — `tornect-platform` depends on core, so core cannot import them from platform; B.8.6.2 — the single entry point for UI, IPC and CLI); `ReadinessSnapshot`/`Probe` types with the all-unknown M1 stub (field list in the Rust block below); the `Presence` trait (M1 stub: `Unknown` ⇒ present; OS impls in `tornect-platform` at M6); `unattended::ipc` — the B.8.7.4 IPC message types + CBOR codec, no I/O (fuzz target F4); client-side `hosts.toml` per-host record `{remember, server_s_pk_pin, suite, ua_worked_before}` + `Paths::hosts_file()` (`server_s_pk` pin set at the first `SESSION_ACCEPT`, checked in `ClientLogin::finish`; the keychain-remembered password stays M8) | round-trip, tamper, rollback and permission tests; guard refuses without re-auth / during a remote session (A8 store/IPC parts); pin change ⇒ client abort (A16); `cargo check` on all targets |
| M1 | `tornect-signal`, `apps/tornect` (CLI), `tornect-platform` (scaffold only) | `research-verifier` note (`docs/research/crypto.md` §8 re-pin, suite decision, sizes, Argon2 timing, GPU figure, circuit-teardown API); envelope `sig`; kinds/bodies; strict-alternation transcript; `HELLO_ACK`; signed `SESSION_REQUEST`; one envelope/transcript golden vector (B.8.4.3) committed; `OpaqueAuthenticator` (+ `Spake2Authenticator` under `pake-fallback`); `AttemptLimiter` with persistence (charge/settle/pending, B.8.5.1); `ConsentProof`/`PolicyReceipt` (private constructors) and `SessionAccept::build(ConsentProof, …)` as the **only** constructor; admin intent + scope; `tornect unattended` CLI (`apps/tornect`) + the host-role IPC dispatch loop over the B.8.7.4 message set (types + codec in `tornect-core::unattended::ipc`, *Ownership* below); M1 scaffolds `tornect-platform` with two modules only — `ipc` (Unix socket / named pipe per B.8.7.4) and `reauth`, the OS implementation of the `tornect-core::unattended::ReAuth` trait (M1: PAM/polkit on the Linux dev machine plus a debug-build-only `TORNECT_DEV_REAUTH=allow` escape, refused in release builds; M6: the Windows/macOS backends of the B.8.8 table); the B.8.4.5 host FSM (`HelloVerified` … `Accepting`/`Closing`) behind the injected `BlockWindow`/`LocalAllow` traits with headless defaults (see *Ownership* below); `fuzz/` targets F1–F4 added to the existing workspace-excluded fuzz crate + `tests/integration` workspace member; property + adversarial suite | headless unattended handshake ending in `SESSION_ACCEPT` over the localhost-Tor mock and between two machines; U1–U7, P1–P4, F1–F4 green; adversarial A1–A6, A8 (store/IPC parts), A13, A14, A15, A16, A17 and the signaling half of A7 green; I1, I8, I10, I11 (signaling half), I12 green; fuzz 10 min clean; counters survive `kill -9` |
| M2 | `tornect-net` | the `BIND` exchange of B.8.4.3 (first frame on `ctrl` both ways: HMAC over the TLS exporter keyed by `session_token`; constant-time verify, close on mismatch; no other stream/datagram accepted before it) consumes the derived token; `transport_policy` honoured by candidate gathering; the Tor fallback tunnels the *same* QUIC connection, so the `BIND` check applies unchanged on both transports | token mismatch ⇒ `BIND` fails and the connection is closed before any media, on the direct path and over the Tor tunnel alike (I7 sub-case); `tor_only` sends zero candidates; I7 green |
| M4 | `tornect-session`, app (minimal) | UI-backed `BlockWindow`/`LocalAllow` implementations for the `tornect-signal` FSM (incl. the `AwaitLocalAllow` popup) and the host FSM from the `Candidates` state on; block window (CLI/egui minimal) + Block; indicator copy; `sessions.log` events; session-end semantics (revoke/off/expiry/schedule/lock); one-session rules (`BYE{REPLACED}`); `Presence` (the `tornect-core::unattended` trait, M1 stub) wired into the away card and `require_absent` | WAN, nobody present, block window 0/3 s ⇒ first frame ≤ 8 s p50 / 12 s p95 from Connect; Block ends the session before the first frame; A7 (live-session replacement), A8 (post-session timing), A10, A12 green; I3–I5, I11 (live kill) green |
| M5 | `tornect-input`, `tornect-session` | view-only enforced at the inject and stream layers (`input`/`clip`/`file` refused); panic-key semantics (end + suspend; double-press ⇒ master off) via physical events | a view-only session injects zero events, clip/file streams refused; panic ⇒ session gone < 100 ms, grant suspended; A11, I2 green |
| M6 | **`tornect-platform`** (OS backends; crate scaffolded in M1) | presence (the `tornect-core::unattended::Presence` impls), lock state/lock, idle-lock probe, keep-awake/idle inhibit, autostart installers, wake hooks, OS re-auth backends of the B.8.8 table, global hotkey (incl. GlobalShortcuts portal), capture-excluded windows, IPC endpoint per OS, readiness probes; B.8.8 rows → `PLATFORM_MATRIX.md` (columns: OS/compositor, ScreenCast token, RemoteDesktop token, lock-screen capture, lock-screen input, presence source, lock mechanism, re-auth mechanism, hotkey) | reboot with auto-login configured ⇒ dialog-free unattended session ≤ 3 min per OS (NEEDS-DEVICE recipes); readiness rows truthful; A9 (platform half: injected input ignored, panic fires, indicator re-asserted), I6, I9 green |
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
`tornect-platform::reauth` provides the OS implementations (M1: PAM/polkit on Linux; M6:
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
with `HOST_NOT_READY` (`cause` 1 / 2 / 3 / 4); every other `Fail` or `Warn` row raises the badge only.

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
| U1–U7 | unit | ladder incl. decay + lifetime budget; schedule (DST gap/overlap, wrap, TZ change); password policy (NFC, whitespace, score, file keystore ⇒ 4); store codec/migration/generation (incl. revoke → restore the pre-revoke store file → load fails closed with `StoreLoadFailed`, while a restored file that differs only in `FailState` loads: runtime-state rollback, B.8.9); clock rollback + forward jump; transcript/signature/HKDF golden vectors; limiter charge/settle: 60 consecutive successful logins ⇒ no lock and `since_unlock` stays 0, abandon after KE2 + `kill -9` ⇒ `since_unlock` persisted as 1 (`pending` settled as fail on load); a success on the charge that armed the hard lock (20th consecutive / 60th since unlock) clears `hard_locked` and returns `since_success = 19` (the own charge excluded) / `since_unlock` back at 59; a success with zero prior failures returns `fail_summary = None`; decay anchors advance by whole periods only | exact per spec | M1 |
| P1–P4 | property | random interleavings incl. PING at every position ⇒ identical `th` on both sides or clean `E_BAD_STATE` (no additional charge: an existing `AwaitKe3` charge stands and is settled as fail); per-direction `msg_id`; any single-byte mutation before `SESSION_ACCEPT` ⇒ abort; unknown CBOR keys round-trip | no panic; ≤ 1 charge per stream | M1 |
| F1–F4 | fuzz | `HELLO`/`HELLO_ACK`/`SESSION_REQUEST.unattended`/`AUTH_*`/`ADMIN_RESULT` bodies into both FSMs; KE1/KE2/KE3 deserializers; store + limiter loaders; IPC messages | no panic/UB, bounded time and allocation | M1 |
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
| A15 | adversarial | `unlock(pk)` / `revoke_all` / `master_off` / `suspend(other)` from a view-only or *Helping someone* grant; `unlock(pk)` of a grant in `Suspended{LocalBlock}` from a *My machines* Control grant; `unlock(pk)` of a grant in `Suspended{Admin}` from a *My machines* Control grant | `ADMIN_RESULT{ok: false}`, no state change, logged (`AdminRequest`, refused); second case: `FailState` reset but the grant stays `Suspended{LocalBlock}` (its next `SESSION_REQUEST` gets pre-PAKE `SUSPENDED`) — remote unlock never clears a local Block; third case: `FailState` reset and the grant returns to `Active` | M1 |
| A16 | adversarial | host `ServerSetup` recreated (Rotate ID + re-pair, or a replaced store) after the client pinned `server_s_pk` | client aborts before KE3 with the "unattended identity of this host changed" message (nothing password-derived emitted beyond KE1); re-pair / re-register clears the pin | M1 |
| A17 | adversarial | 50 bare `HELLO`s from random keys held open (no `SESSION_REQUEST`), then a granted device logs in | the granted device still receives `AUTH_CHALLENGE`: uncharged `HelloVerified` streams never occupy the per-pk, host-wide or per-minute budgets (B.8.5.2) | M1 |

#### B.8.16 Security-reviewer checklist additions (§D.3)

- `SessionAccept::build(ConsentProof, …)` is the only constructor; `PolicyReceipt` is minted only after `ServerLogin::finish`.
- Charge (`pending = true`) + fsync precede KE2; no KE2 while locked/suspended/expired/disabled; success is the only consecutive reset and reverts only its own charge; the lifetime budget is never reset by success (7-day decay only); `pending` at load ⇒ settled-fail; unattended rejects never feed the temp-ban; global limits never lock; no global breaker.
- Host derives `credential_identifier`, `context`, `identifiers` from the signature-verified pk; `context` includes `th_after(SESSION_REQUEST)`, suite, intent; both host OPAQUE calls pass `ServerLoginParameters`; `ksf` never `None`; sizes 96/320/64 asserted.
- Client: fresh `ClientLogin::start` per stream; `HELLO_ACK` verified against the dialed address; `server_s_pk` pinned (`hosts.toml`, checked in `ClientLogin::finish`); the suite is a build-time constant, never taken from `HELLO_ACK.feats` when suite 1 is compiled in; `export_key` dropped/zeroized in the same scope as `finish`, never persisted or logged; aborts on `session_type` mismatch, `AUTH_CHALLENGE.suite ≠ requested`, `session_token` present for unattended, `token_confirm` mismatch (constant time); grant policy (`block_window_s`, `ask_before_start`) is read only from the signed `SESSION_ACCEPT`, never from `AUTH_CHALLENGE`; never auto-retries (nor with another suite).
- Strict-alternation window enforced (`PING` during auth ⇒ `E_BAD_STATE`, no additional charge — an `AwaitKe3` charge is settled as fail); a bare `HELLO` never cancels an in-flight `AwaitKe3` handshake — only a verified `SESSION_REQUEST` from the same pk does (B.8.4.5); `HelloVerified` streams never count as in flight (B.8.5.2); `th` hashes exact wire bytes; signatures cover envelope fields, never re-serialized CBOR; every `HELLO` signature is verified against the `HELLO`'s own pk (proof of possession) and, when pinned, the pk must equal the pinned key — a bad signature is `E_BAD_SIG` for pinned and unpinned peers alike, byte-identical; `HELLO_ACK.feats` is host-wide.
- One mutation guard consulted by UI, IPC, CLI and startup reload; re-auth is a fresh OS dialog per operation; deny-direction paths need nothing and kill sessions ≤ 1 s; popups suppressed during remote sessions; policy never read from `config.toml`; admin scope (B.8.4.1) enforced from the requester's grant, and a remote `unlock` clears `Suspended{Admin}` but never `Suspended{LocalBlock|Panic}`; backup export is access-increasing; `RegFinish` needs the live `reg_txn` from a re-authenticated `RegStart`.
- Store: AEAD with header AAD, generation anchor (bumped by every policy write — access-increasing and deny-direction alike, revocations included — never by runtime-state writes; an owed bump is carried as `pending_anchor` while the keychain is unwritable; store ≥ anchor accepted, older ⇒ fail closed, so a pre-revocation store never loads), `machine_id_hash` mismatch ⇒ grants `Disabled{by: Restore}`, fail closed on every load error — a guarantee against parties without `K_master` (T9 is out of scope), atomic writes, single writer, 0600/ACL, tombstones merged on import, `Zeroizing` buffers.
- Indicator/panic/block window: physical-input-only detection, re-assertion, un-closable, DND-independent in-app surface; view-only refuses `input`/`clip`/`file` at the QUIC layer; the mode clamp is monotone toward view-only (`SessionMode::most_restrictive`).
- Logs: pinned label only, rate-aggregated rejects, hash chain + tag with the head in the store (append + fsync before the head write; tagged lines beyond the head accepted and the head advanced, B.8.13), no secrets; client log present. Emergency stop: only the pk-bound `stop_token` is stored and compared (constant time), single-use. Restricted discovery: client-generated keys, pairing-mode window logged, caveats shown.
- Fallback build: `pA`/`cA` only after a host message; constant-time compares; `w` wrapped and reduced wide from a 64-byte Argon2id output; `M`/`N` from the fixed seeds; `cA`/`cB` keyed by `KcA`/`KcB`, the token HKDF by `Ke`; suite fixed per grant, never two records for one grant.

#### B.8.17 Open questions

1. Per-grant passwords are the model — should the wizard offer "same password as <other own device>" (re-typed, separate record)? (M8 UX test.)
2. `hard_lock_after` 20 / lifetime 60 — confirm against real Tor failure rates from the M1/M7 soaks.
3. Wayland: which compositors provide `ext-idle-notify-v1` and a usable GlobalShortcuts portal; fallback "present" + focused window confirmed (M6).
4. Argon2id 64 MiB on future mobile clients ⇒ new suite id with re-registration, not a negotiation; decide when a mobile client exists.
5. Keychain user-presence gating (Touch ID / Windows Hello) for the remembered password — v1 where `keyring-core` stores expose it cheaply, else post-v1; headless Linux re-auth without a polkit agent (PAM vs a weaker Tornect-only passphrase) decided at M6.
6. v2 service-mode scoping per OS, and whether lock-on-disconnect should default on wherever the M6 matrix proves remote unlock.

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
defines next to `MutationGuard` (§B.8.14 *Ownership*): PAM/polkit on the Linux dev machine plus a
debug-build-only `TORNECT_DEV_REAUTH=allow` escape (refused in release builds); M6 adds the
Windows/macOS backends of the §B.8.8 table. ✅ Accept: two machines on different
NATs pair and exchange PING/PONG round-trips via Tor with only an onion string shared;
kill/restart host ⇒ same ID; `tornect-signal` fuzz target runs clean 10 min; a
password-authenticated unattended handshake reaches `SESSION_ACCEPT` between the two
machines with no prompt on the host, and the §B.8.15 rows owned by M1 are green
(adversarial A1–A6, A8 store/IPC parts, A13, A14, A15, A16, A17 and the signaling half of A7;
U1–U7, P1–P4, F1–F4; integration I1, I8, I10, I11 signaling half, I12).

**M2 — Direct connectivity (hole punch + QUIC)**
Candidate gathering (if-addrs, `igd-next` UPnP + NAT-PMP/PCP, `stun-client` against
configurable list); CANDIDATES over Tor; paced simultaneous-open punch; quinn
endpoint with pinned-key TLS verifier + the `session_token` `BIND` exchange (first frame on
`ctrl` both ways, an HMAC over the TLS exporter; nothing else accepted before it verifies — the
PAKE-derived token of unattended sessions feeds the same check, §B.8.4.3); `transport_policy`
(`tor_only`/`lan_only`, §B.8.6.4) honoured by candidate gathering; Tor-tunnel
fallback transport implementing the same `SessionTransport` trait; connection
health/migration (Wi-Fi→ethernet). ✅ Accept: matrix test — LAN, one-sided NAT,
double NAT (netem/netns harness simulating port-restricted + symmetric) — direct
established where theoretically possible, Tor fallback engages within 4 s otherwise;
1 GiB transferred over punched QUIC with checksum; measured punch success logged;
a mismatched unattended token fails the `BIND` exchange and closes the connection before any
media (on the direct path and over the Tor tunnel alike — the tunnel carries the same QUIC
connection) and `tor_only` sends zero candidates.

**M3 — Video pipeline, single platform (pick the OS Claude Code is running on)**
Capture backend for dev OS; FFmpeg hw encode+decode wrappers with runtime probe;
packetizer/FEC/jitter/pacer from §B.4; wgpu render window; loopback demo
(`tornect demo --loopback`) capture→encode→(in-proc channel)→decode→render.
✅ Accept: 1080p60 loopback ≥ 30 min, added latency ≤ 35 ms p95 (HUD overlay
numbers), zero validation errors, CPU < 15 % with hw codec.

**M4 — End-to-end streaming (M1+M2+M3 glued by `tornect-session`)**
Host & client session state machines; ctrl stream (IDR request, bitrate hint);
minimal egui: ID card + connect field + consent popup + stream window. Unattended
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
≤ 3 min per OS (`NEEDS-DEVICE` recipes); readiness rows truthful.

**M7 — Resilience & performance hardening**
ABR controller tuned on netem profiles (3 canned: "fiber", "flaky wifi", "hotel");
FEC adaptivity; Tor-fallback UX (badge, quality preset); zero-copy decode-render
interop; multi-monitor select/switch; HDR (HEVC Main10/AV1-10) behind flag;
unattended limiter/lockout under 1 k scripted attempts and lockout persistence (CI),
descriptor re-publish after a simulated Arti restart (CI), 24 h unattended soak with
sleep/wake cycles as `NEEDS-DEVICE(<os>)` (§B.8.14).
✅ Accept: scripted netem suite passes quality gates (§B.7 table + fallback gate);
30-min soak at 5 % loss without session drop; perf report committed.

**M8 — Product polish & ship v0.1**
Full egui app: onboarding (permissions walkthroughs per OS), settings, trusted
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

**Post-v1 backlog (tracked, not planned here):** file transfer UI · mobile clients
(Android first; would motivate str0m/WebRTC or WebTransport revisit) · "bring your
own relay" · per-app window streaming · virtual display driver (headless hosts) ·
H.265 4:4:4 / AV1 SCC tuning · Wake-on-LAN via a second LAN device · iroh backend
feature flag · MoQT alignment once RFC · unattended "service mode" (lock/login-screen
control, §B.8.8) · TPM-sealed keystore for headless hosts (§B.8.2 T3b).

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
| FFmpeg hw-frames interop bugs across drivers | M×H | Runtime probe with warmup scoring + per-encoder denylist config; software fallback always compiled in |
| Latency regressions creeping in | H×M | §B.7 gates are executable (netem suite in CI-linux + headless-stats), regressions fail the build |
| Scope creep (it's a fun project) | H×M | Post-v1 backlog exists precisely to say "later"; milestones gate features |
| Abuse of remote-access software | L×H | §B.6 consent architecture: no silent sessions, persistent indicator, panic key, local session log — these are requirements, not options |
| Unattended-access abuse or lockout DoS (stolen/cloned device keys, coached relatives, a hostile Control session, the owner locking themselves out, keychain unusable at autostart, lock-screen dead ends) | M×H | §B.8: two factors + per-grant OPAQUE; count-based ladder with lifetime budget, per-grant scope, no global breaker; remote revoke/unlock from another *My machines* Control device + emergency stop code; OS re-authentication for every access-increasing change through Tornect's own surfaces (endpoint-level rewrites by a Control session are out of scope, T9); file-keystore fallback with a stricter password policy; honest per-OS readiness (§B.8.8); the adversarial A-suite is cumulative — each milestone's rows are listed in §B.8.14 and gate it |

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

---

## Part G — Execution status (kept current at every session hand-off)

Last update: **2026-08-29**. Repository: https://github.com/Mxrider420z/Tornect (private,
branch `main`). Per-milestone detail lives in `docs/notes/m<N>-state.md`; every acceptance
check with its real status is in `docs/VERIFICATION.md`; every deviation from this plan is a
numbered row in `docs/notes/decisions.md`.

| Milestone | Status | Evidence / where |
|---|---|---|
| M0 Bootstrap | **Done**, tag `m0` (commit `5c7a52d`) | Workspace, `tornect-core` (onion-v3 `TornectId` proven against real addresses, identities, 0600 keystore, config, paths, tracing, `sessions.log`), CLI `id/rotate-id/paths/config/doctor`, `xtask verify`, Claude Code kit, GPLv3, README. CI file written but not yet pushed (see pending actions). |
| Research | **Done** (commit `36a5b0f`) | `docs/research/{arti,quic,crypto,nat,wayland,codecs,ui,ci,media-proto}.md` + `SUMMARY.md` audit — verified against crates.io, crate sources and live probes; all pins in `Cargo.toml` come from these. |
| Plan §B.8 | **Done** (r4, commit `c515f0d`) | Unattended access specified end-to-end; two medium text findings still to apply (listed in `docs/notes/m1-state.md`). |
| M1 Signaling over Tor | **In progress — track 1 of 4 done** (commit `0e568d8`) | Arti embedded (`tornect-signal::tor`), `tornect host` / `tornect ping` verified live over Tor: onion service published from the M0 seed (same ID after restart), pings 0.5–1.1 s RTT, PoW-aware admission with backpressure, 43 signal + 26 core tests. Remaining: CBOR envelope + pairing/SAS + attended FSM, OPAQUE unattended FSM, CLI/IPC/`tornect-platform` scaffold, adversarial suite, live pair/connect verification, tag `m1`. Workflow script prepared: `docs/notes/m1-phase2-plan.md`. |
| M2–M8 | Not started | Research decisions already made for M2 (raw-public-key TLS, punch outside QUIC, `grease_quic_bit(false)`, `stun` 0.17 / `crab_nat` / `igd-next`), M3 (`openh264` software path; hw codecs `NEEDS-DEVICE(gpu)`; VM-scoped acceptance to define), M5 (`opus` 0.4, in-band FEC off), UI (manual winit loop, no eframe; wgpu 30 / winit 0.30 / egui 0.36). |

**Verified-on-hardware honesty.** Everything above was run on one Ubuntu 26.04 VM (GNOME/
Wayland, no GPU encoder, no sudo, no second machine). Windows/macOS are `cargo check`-ed via
installed targets only; "two machines on different NATs" (M1 accept) is `NEEDS-DEVICE`.

**Pending actions for the owner.** (1) `gh auth refresh -h github.com -s workflow`, then commit
and push `.github/workflows/ci.yml` (kept local because the token lacks the `workflow` scope).
(2) Copy `.claude/settings.recommended.json` to `.claude/settings.json` after review (the harness
refuses to let the model install its own permission/hook config). (3) Optional: a second
machine for the M1/M2 two-NAT acceptance rows.

**Plan amendments queued for r6** (from `docs/research/SUMMARY.md`): §A.2 FFmpeg versions
(ubuntu-latest ships 6.1; crate supports 6.1–9.0); §A.4 "Linux host must be unlocked (GNOME
closes portal sessions on lock)"; §B.2 punch mechanics (probes outside QUIC, single dial, role
tie-break) and `quic_spki` instead of `quic_server_cert_fp`; §B.4 Opus in-band FEC off + datagram
payload = live `max_datagram_size()` (1162 B at 1200 MTU) with a 12-byte header; §B.5 Wayland
restore token on `SelectDevices`, `openh264` as the always-on software codec (no x264-first,
no rav1e/svt-av1/dav1d in v1); §B.6 TLS raw public keys (RFC 7250) rather than X.509; D9 `opus`
crate; D10 own winit loop instead of eframe; D13 `keyring-core`; M2 `stun` crate (not
`stun-client`); M3 VM-scoped acceptance + `NEEDS-DEVICE(gpu)` rows.
