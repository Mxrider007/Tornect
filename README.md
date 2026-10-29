# Tornect

**Remote desktop like AnyDesk, without servers.** See and control another computer, or let
someone help you on yours, with no account, no server to run or trust and no port forwarding.

Each computer's Tornect ID is its Tor onion address, which is also its public key. **Tor finds
the other computer and checks that it is the one you paired with.** Once the person there
accepts, **the two computers connect directly when they can reach each other**, on the same
local network or across the internet (QUIC, both keys pinned), which is much faster. When they
cannot, the session stays on Tor: slower, but it connects. Linux and Windows.

> **Status: pre-release, and no one has audited it.** Do not rely on it to protect anything yet.
> Much of it has not yet run on a real desktop, between two real networks or on Windows at all:
> the [release notes](packaging/release/NOTES-v0.1.0-slice.2.md) and
> [`docs/VERIFICATION.md`](docs/VERIFICATION.md) say what was checked, and how.

## Features

- **Remote view and control:** the person at the other computer answers each session with Deny,
  View only or Allow control; Windows and Linux (Wayland and X11) computers can be shared.
- **Pairing by comparing a code:** the first connection shows the same 6-digit code on both
  screens, and each side keeps the other's key from then on.
- **Always visible, always stoppable:** a banner and a small "Tornect: sharing" window with Stop
  while your screen is shared, the panic key (Ctrl+Alt+End) and `tornect panic`.
- **Easy to share:** Copy invitation, a QR code and `tornect://` links; a link fills the Connect
  field and never connects by itself.
- **Direct connections:** on the same network or across the internet (STUN, UPnP/NAT-PMP/PCP,
  UDP hole punching), with Tor as the fallback; off with one switch.
- **Quality presets:** Best quality, Balanced or Best performance; a large desktop is scaled to
  fit, never cropped.
- **Several screens:** pick the other computer's screen, or all of them (Windows and X11 hosts).
- **Chat, clipboard text and files:** in the session window, each one switchable on the shared
  computer.
- **Unattended access:** opt-in per device, with a password the host never stores (OPAQUE) and an
  emergency stop code.
- **Saved computers:** the computers you paired with stay on Home, with Knock and Check if
  reachable; the list of recent connections is off by default.
- **Works where Tor is blocked:** obfs4 and Snowflake bridges through the bundled lyrebird.
- **Optional install and start at sign-in**, and a command line for everything.
- **No telemetry.** Every pairing and session is written to a log on your own computer only.

## Quick start

1. **Download** the zip for your system from https://github.com/Mxrider007/Tornect/releases and
   check it against `SHA256SUMS` (see *Download* below).
2. **Unzip and run it:** `./tornect` on Linux, or double-click `tornect.exe` on Windows. No
   install is needed.
3. **Share your ID:** Home shows your Tornect ID. Press **Copy invitation** (or **Show QR code**)
   and send it to the other person over a channel you trust.
4. **Connect:** paste the other computer's ID, `tornect://` link or whole invitation into the
   Connect field and press Connect. Finding the other computer over Tor takes from a few seconds
   to a minute.
5. **Pair:** the first time, both screens show the same code. Compare it (by phone, say) and
   confirm on both sides only if it matches.
6. **The session question:** the other side chooses Deny, View only or Allow control. The picture
   opens in its own window; End session there, or Stop on the shared side, ends it.

`README-release.md` in the zip covers the rest: the Wayland screen-sharing grant, the Windows
console, unattended access, installing, start at sign-in and the command line.

## Platforms and limits

| | |
|---|---|
| **Linux** | x86_64 with glibc 2.43 or newer (Ubuntu 26.04; not Ubuntu 24.04 or Debian 13). Wayland with xdg-desktop-portal 1.17+ and PipeWire (GNOME tested), or X11 |
| **Windows** | Windows 10 20H1 or newer, or 11, 64-bit. Not yet run on a real Windows machine, only under Wine |
| **macOS, Android, iOS** | not yet (macOS is planned; Android is on the roadmap) |

This version has no sound, software H.264 only (no GPU encoding; over Tor about 16 pictures a
second at most, a few for a large desktop), no session recording, printing or Wake-on-LAN, no
tray icon and no self-update, and it cannot show the Windows sign-in screen, UAC prompts or
Ctrl+Alt+Del. A Wayland computer shares the one screen picked in its desktop's dialog and, by
default, no clipboard. The release notes list every limit.

## Privacy

- **No servers, no accounts, no telemetry.** Tornect has no server of its own; Tor's volunteer
  network finds the other computer. Settings, pairings and the session log stay on your
  computer, and the list of recent connections is off unless you switch it on.
- **What the other computer learns on a direct session:** a computer you accept, a view-only one
  included, learns your IP addresses (local, public IPv4 and one IPv6), and so does a computer you
  connect to. One public STUN server per session sees your IP address and when the session
  starts, never with whom; your router is asked to open one UDP port for the session; your
  internet provider may recognise the direct traffic as Tornect. You are told before you
  accept. A computer that is refused, or never paired, learns nothing.
- **Staying on Tor:** switch off "Allow direct connections" in Settings › Connection (or set
  `paranoid = true` under `[network]`): the computers you meet then never learn your IP
  address, and no STUN server or router is asked. Direct connections are also off while Tor
  uses a bridge, unless `direct_with_bridges = true` is set under `[network]`.

## Security

The threat model, the consent rules and the unattended-access design are in
[`docs/PLAN.md`](docs/PLAN.md) §B.6 and §B.8. To report a vulnerability, use GitHub's private
vulnerability reporting, never a public issue: [`SECURITY.md`](SECURITY.md) says how, and what is
in scope. There is no bug bounty. The release notes name the security reviews each part has had;
no external audit has been done.

## Download

Download Tornect only from https://github.com/Mxrider007/Tornect/releases, the one place
its release zips and their `SHA256SUMS` are published. A copy offered anywhere else, or a
download link someone sends with a Tornect ID, may not be Tornect.

Each release has its notes on that page; the notes of the next pre-release are
[`packaging/release/NOTES-v0.1.0-slice.2.md`](packaging/release/NOTES-v0.1.0-slice.2.md), and
the guide inside every zip is [`packaging/release/README-release.md`](packaging/release/README-release.md).

## How it works

```
Host                          Tor network                       Viewer
  ed25519 identity  ───►  publish onion service (the Tornect ID)
  show the ID, an invitation, a QR code
                                          ◄────  paste the ID, link or invitation
                        ◄── rendezvous ──────    open an onion stream
  HELLO · PAIR (6-digit code on both screens) · SESSION_REQUEST
  question on the host: Deny / View only / Allow control
  after the accept: CANDIDATES over Tor ── STUN, router port, UDP hole punch ── QUIC (TLS 1.3, both keys pinned)
        └─ no direct path within 4 s → the session stays on the Tor circuit
  video, input, chat, clipboard and files over the chosen path
```

- **Identity:** the onion v3 address is the host's ed25519 key. Each device has its own key,
  pinned at pairing. No certificate authorities, no registry.
- **Consent:** a question on the host precedes every attended session, nothing is captured
  before it, and the sharing banner, the "Tornect: sharing" window and the panic key show and
  stop every session. Unattended access is opt-in per device and protected by a password the
  host never stores (augmented PAKE).
- **Media:** software H.264 (OpenH264) with host-side scaling and three quality presets.
  Hardware encoding, audio and gaming mode are on the roadmap.

The full design (research, decision record, protocol, milestones) is in
[`docs/PLAN.md`](docs/PLAN.md).

## Why

| Tool | Discovery / NAT traversal | Pain |
|---|---|---|
| Sunshine + Moonlight | LAN only; WAN needs port-forward or VPN | Best streaming quality, worst remote setup |
| RustDesk | Central rendezvous + relay servers | Public servers or self-hosting |
| AnyDesk / TeamViewer / Parsec | Vendor cloud | Accounts, proprietary, metadata visible to vendor |
| Tailscale + anything | Coordination server + DERP relays | Another account and control plane |

Tornect's thesis: an onion address gives you identity, reachability and an encrypted
channel with zero infrastructure of your own.

## Building from source

Requirements: Rust stable ≥ 1.90 (edition 2024), a C/C++ compiler, `cmake`,
`pkg-config`. The default feature set is pure Rust plus vendored C sources and
builds without any system media libraries.

```bash
git clone https://github.com/Mxrider007/Tornect.git
cd Tornect
cargo run -p tornect              # the window
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
Release zips are made with `cargo xtask dist` ([`docs/RELEASING.md`](docs/RELEASING.md)).

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M0 | Workspace, identities, config, keystore, CI, the development kit | ✅ done |
| M1 | Signaling over Tor: embedded Arti onion service, pairing with SAS, unattended PAKE auth | in progress: built, acceptance runs open |
| M2 | Direct connectivity: candidates, UPnP/NAT-PMP/PCP, STUN, hole punch, key-pinned QUIC, Tor fallback | in progress: both halves built and the internet half on; the close done (final decisions, a security review of the whole feature); still to come: the dev-VM runs (checkpoint `m2a`), the owner's call on the default STUN servers and their live check, real networks and routers |
| M3 | Video pipeline on Linux/Wayland: capture, codecs, packetizer/FEC/jitter/pacer, wgpu render, loopback demo | |
| M4 | End-to-end streaming between two machines with the minimal GUI | |
| M5 | Input + audio: remote *control*, clipboard, gaming mode | |
| M6 | Windows and macOS parity | |
| M7 | Resilience & performance hardening (netem suite, ABR tuning, HDR) | |
| M8 | Product polish, unattended-access UI, packaging, v0.1 release | |

The vertical slice built parts of M3–M5 (capture, software video, the window, input, chat,
clipboard text and files) ahead of the milestones, so that two machines hold a real session
first; only `m0` is tagged so far.

## Development

`CLAUDE.md` holds the project's development instructions (the rules, the commands and the
security invariants), and `.claude/` the helper definitions and workflow commands that go with
them (`/milestone <n>`, `/verify`, `/research <topic>`); `docs/notes/` keeps the hand-off notes.
Enable the pre-commit gate once per clone:

```bash
git config core.hooksPath .githooks
```

Recommended permissions and hooks for the development tools are in
`.claude/settings.recommended.json` (copy to `.claude/settings.json` after review).

## License

GPL-3.0-or-later — see [`LICENSE`](LICENSE).
