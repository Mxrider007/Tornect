# Tornect

**Decentralized remote desktop & game streaming. No servers to run, no port
forwarding, no accounts.**

Tornect uses the Tor network as a free, volunteer-run rendezvous system: every host
gets a Tor onion v3 address that is simultaneously its stable reachable name, its
cryptographic identity (the address *is* the public key) and an encrypted signaling
channel. Tor is used only for the handshake — media then flows over a direct,
hole-punched QUIC connection. When punching fails, Tornect streams through Tor
itself: slower, but it *always* connects.

> **Status: pre-alpha, under active development; no one has audited it.** Today's
> build is the vertical slice: pairing with a code to compare, the consent question,
> screen sharing with remote control (software H.264), the window with its sharing
> banner and Stop, unattended access, and Linux and Windows builds. **When the two
> computers can reach each other, on the same local network or across the internet
> through ordinary home routers, the pictures travel over a direct QUIC connection**
> (M2: both device keys pinned, and only after the host accepts; the other computer
> then learns this computer's local and internet addresses, which the host is told
> when it decides; one public STUN server per session sees this computer's IP address
> and when the session starts, and the router is asked to open one UDP port for it).
> **Otherwise everything, the pictures included, travels over the Tor circuit.** The
> internet half has run only in simulation so far (an in-memory NAT matrix); the runs
> between real networks and routers are pending. `network.paranoid = true`, or the
> "Allow direct connections" switch in Settings > Connection, keeps every session on
> Tor. See the roadmap below and
> [`docs/VERIFICATION.md`](docs/VERIFICATION.md) for what has actually been verified,
> and on which machines.

## Why

| Tool | Discovery / NAT traversal | Pain |
|---|---|---|
| Sunshine + Moonlight | LAN only; WAN needs port-forward or VPN | Best streaming quality, worst remote setup |
| RustDesk | Central rendezvous + relay servers | Public servers or self-hosting |
| AnyDesk / TeamViewer / Parsec | Vendor cloud | Accounts, proprietary, metadata visible to vendor |
| Tailscale + anything | Coordination server + DERP relays | Another account and control plane |

Tornect's thesis: an onion address gives you identity, reachability and an encrypted
channel with zero infrastructure of your own. Pair once with a 6-digit code, then
connect from anywhere with a 56-character ID (or a QR code).

## How it works

```
Host                          Tor network                       Client
  gen ed25519 identity  ───►  publish onion service
  show Tornect ID (56 chars + QR)
                                          ◄────  enter / scan the ID
                        ◄── rendezvous ──────    open onion stream
  HELLO · PAIR (6-digit SAS on both screens) · SESSION_REQUEST
  consent popup on host: Allow once / View-only / Deny
  CANDIDATES exchanged over Tor ── UDP hole punch ── direct QUIC (TLS 1.3, keys pinned)
        └─ no punch within 4 s → stream over the Tor circuit instead
  video+audio in QUIC datagrams · input/clipboard/control on reliable streams
```

- **Identity:** onion v3 address = host's ed25519 key. Client devices have their own
  keys, pinned at pairing. No CAs, no registry.
- **Consent:** a popup on the host precedes every session; a persistent on-screen
  indicator and tray state show when the screen is shared; one keystroke kills the
  session. Unattended access is opt-in per device and protected by a password
  (augmented PAKE — the host never stores the password).
- **Media:** hardware encode (NVENC / AMF / Quick Sync / VA-API / VideoToolbox via
  FFmpeg) with AV1 > HEVC > H.264 negotiation, Opus audio, FEC + adaptive bitrate,
  wgpu rendering. Target: ≤ 35 ms added glass-to-glass latency on LAN at 1080p60.
- **Capture & input, the modern way:** Windows.Graphics.Capture + SendInput;
  ScreenCaptureKit + CGEvent; xdg-desktop-portal ScreenCast/PipeWire + libei on
  Wayland. No root, no kernel hacks.
- **Privacy modes:** default (signaling via Tor, media direct — peers see each
  other's IP), *paranoid* (everything via Tor), LAN-only.
- **No telemetry.** Session events are logged locally only.

The full design — research, decision record, protocol, milestones — is in
[`docs/PLAN.md`](docs/PLAN.md).

## Download

Download Tornect only from https://github.com/Mxrider007/Tornect/releases, the one place
its release zips and their `SHA256SUMS` are published. A copy offered anywhere else, or a
download link someone sends with a Tornect ID, may not be Tornect.

## Building from source

Requirements: Rust stable ≥ 1.90 (edition 2024), a C/C++ compiler, `cmake`,
`pkg-config`. The default feature set is pure Rust plus vendored C sources and
builds without any system media libraries.

```bash
git clone https://github.com/Mxrider007/Tornect.git
cd Tornect
cargo run -p tornect -- id        # generates and prints this machine's Tornect ID
cargo run -p tornect -- doctor    # environment report
cargo xtask verify                # fmt + clippy + tests + docs
```

Optional backends (feature flags, see each crate's `Cargo.toml`):

| Feature | Needs (Debian/Ubuntu package names) |
|---|---|
| `tornect-codec/ffmpeg` (hardware codecs) | `libavcodec-dev libavformat-dev libavutil-dev libavfilter-dev libswscale-dev libclang-dev` |
| `tornect-capture/pipewire` (Wayland capture) | `libpipewire-0.3-dev libspa-0.2-dev libclang-dev` |
| `tornect-audio/cpal` (audio playback) | `libasound2-dev` |

State lives in `~/.config/tornect` + `~/.local/share/tornect` (Linux),
`~/Library/Application Support/Tornect` (macOS), `%APPDATA%\Tornect` +
`%LOCALAPPDATA%\Tornect` (Windows). Set `TORNECT_HOME=<dir>` to keep everything in
one directory — handy for running a host and a client on the same machine.

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M0 | Workspace, identities, config, keystore, CI, Claude Code kit | ✅ done |
| M1 | Signaling over Tor: embedded Arti onion service, pairing with SAS, unattended PAKE auth | in progress: built, acceptance runs open |
| M2 | Direct connectivity: candidates, UPnP/NAT-PMP/PCP, STUN, hole punch, key-pinned QUIC, Tor fallback | in progress: both halves built and the internet half on; the dev-VM runs (checkpoint `m2a`), the live STUN check, real networks and routers, and the close (final decisions, security review) still to come |
| M3 | Video pipeline on Linux/Wayland: capture, codecs, packetizer/FEC/jitter/pacer, wgpu render, loopback demo | |
| M4 | End-to-end streaming between two machines with the minimal GUI | |
| M5 | Input + audio: remote *control*, clipboard, gaming mode | |
| M6 | Windows and macOS parity | |
| M7 | Resilience & performance hardening (netem suite, ABR tuning, HDR) | |
| M8 | Product polish, unattended-access UI, packaging, v0.1 release | |

The vertical slice built parts of M3–M5 (capture, software video, the window, input) ahead of
M2, so that two machines hold a real session over Tor first; only `m0` is tagged so far.

## Security

Threat model, consent architecture and the unattended-access design are specified
in `docs/PLAN.md` §B.6 and §B.8. To report a vulnerability, use GitHub's private
vulnerability reporting, never a public issue: [`SECURITY.md`](SECURITY.md) says how,
and what is in scope. There is no bug bounty.

## Development with Claude Code

This repository is built with Claude Code as the engineering team. `CLAUDE.md` holds
the operating rules; `.claude/agents/` the specialist subagents; `/milestone <n>`,
`/verify` and `/research <topic>` the workflow commands. Enable the pre-commit gate
once per clone:

```bash
git config core.hooksPath .githooks
```

Recommended Claude Code permissions/hooks are in
`.claude/settings.recommended.json` (copy to `.claude/settings.json` after review).

## License

GPL-3.0-or-later — see [`LICENSE`](LICENSE).
