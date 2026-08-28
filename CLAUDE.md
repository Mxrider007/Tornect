# CLAUDE.md — Tornect operating manual

Tornect is a decentralized remote-desktop and game-streaming app: Tor onion v3 for
identity + rendezvous, direct hole-punched QUIC for media, Tor itself as the
always-works fallback. No servers, no accounts, no port forwarding. Rust, one
binary, Linux/Wayland + Windows + macOS.

**`docs/PLAN.md` is the single source of truth** (research → architecture →
milestones → execution kit). This file is the always-in-context digest of the
rules; when in doubt, open the plan section cited.

## Repository map

```
Cargo.toml                  workspace: pins + lints for every crate (docs/DEPENDENCIES.md explains each)
crates/tornect-core         ids (onion v3), ed25519 identities, file keystore, config, paths, tracing, sessions.log
crates/tornect-signal       Arti onion service + CBOR envelope protocol + pairing/SAS + unattended PAKE   (M1)
crates/tornect-net          candidates, UPnP/NAT-PMP/PCP, STUN, hole punch, key-pinned quinn, Tor tunnel  (M2)
crates/tornect-proto        media wire format, packetizer, FEC, jitter buffer, pacer, ABR, stats            (M3)
crates/tornect-capture      VideoCaptureSource + pipewire | wgc | sckit backends + synthetic source         (M3/M6)
crates/tornect-codec        Encoder/Decoder + ffmpeg hw backends + software fallback                        (M3)
crates/tornect-audio        capture, Opus, playback                                                          (M5)
crates/tornect-input        16-byte input events, client capture, host inject backends                      (M5)
crates/tornect-session      host/client state machines gluing everything                                    (M4)
apps/tornect                CLI now; eframe app + stream window later                                       (M4/M8)
xtask                       cargo xtask verify | lint-all | dist | ffmpeg-fetch | soak
docs/PLAN.md                the plan (verbatim copy of TORNECT_PLAN.md at repo root)
docs/DEPENDENCIES.md        dependency → version → why → build requirements → verified-on
docs/VERIFICATION.md        acceptance ledger: VERIFIED / CI / NEEDS-DEVICE(os) / OPEN
docs/research/*.md          sourced API notes the implementers code from
docs/notes/m<N>-state.md    per-milestone hand-off notes (write before /clear)
.claude/agents/*.md         subagent roster (§D.3); .claude/commands/{milestone,verify,research}.md
.githooks/pre-commit        fmt + clippy gate (enable: git config core.hooksPath .githooks)
```

Dependency direction: `core → {signal, net, proto, capture, codec, audio, input} → session → app`.
Never upward. Only `tornect-signal` imports Arti; only `tornect-net` touches sockets/quinn.

## Commands

```bash
cargo xtask verify                 # fmt --check, clippy -D warnings (all targets), test, doc (-D warnings)
cargo xtask lint-all               # fmt + clippy only
cargo run -p tornect -- id         # M0 acceptance: prints this machine's Tornect ID (56-char .onion)
cargo run -p tornect -- doctor     # environment report
TORNECT_HOME=/tmp/h1 cargo run -p tornect -- id    # isolated instance (use two for host+client on one box)
cargo check --target x86_64-pc-windows-msvc -p tornect-core   # cross-check (targets installed on the dev VM)
cargo check --target aarch64-apple-darwin -p tornect-core
```

Milestone workflow: `/milestone <n>` (plan mode → task DAG → implement → gates →
Accept demo → VERIFICATION.md → security review → `docs/notes/m<n>-state.md` → tag `m<n>`).

## Ground rules (docs/PLAN.md §D.1 — non-negotiable)

1. **Milestones are sacred.** Never start M(n+1) with M(n) red. Tags `m0`…`m8`.
2. **Plan mode first** for every milestone; produce the task DAG; identify parallel tracks (§D.4).
3. **Verify like hostile QA.** Every task ends with `cargo xtask verify` **and** the
   milestone's runtime demo actually executed. Media code additionally runs
   `tornect demo --loopback --headless-stats` and reads the numbers against §B.7.
   Never report a failure as a pass; paste real output.
4. **Reality beats memory.** New dependency / OS API / FFmpeg detail ⇒ `research-verifier`
   first (`/research <topic>`); pin exact versions; row in `docs/DEPENDENCIES.md`.
5. **Platform code needs platform machines.** This dev machine can run only Linux/Wayland.
   Windows/macOS code: write + `cargo check --target`, mark runtime checks
   `NEEDS-DEVICE(<os>)` in `docs/VERIFICATION.md` with an exact recipe. CI keeps everyone honest.
6. **Small PRs, real commits.** Conventional commits (`feat(signal): …`, `fix(core): …`,
   `docs: …`, `chore(ci): …`); every commit compiles; parallel tracks use
   `git worktree add ../tornect-<track> m<N>-<track>`.

## Dev machine facts (mx-vm)

Ubuntu 26.04 LTS, GNOME on **Wayland** (`XDG_SESSION_TYPE=wayland`), VMware virtual GPU
(no hardware encoder; lavapipe Vulkan + Mesa GL available for wgpu), 4 vCPU, 7 GiB, Rust
stable 1.96, gcc/g++ 15, cmake, pkg-config, **no nasm, no sudo**. Missing dev headers:
FFmpeg (libav*), PipeWire, ALSA, libei, libclang-dev, GTK. Consequences:

- FFmpeg / PipeWire / cpal / tray backends live behind cargo features and are compiled +
  tested in the **Linux CI job** (which apt-installs everything). Locally they are `NEEDS-DEVICE`.
- The pure-Rust stack (Arti, quinn, ashpd, reis, egui/wgpu, the `openh264` software codec
  built from source with `cc`) builds and runs here — that is the default feature set.
- No root ⇒ no netns/tc netem locally; `tests/netem/run.sh` runs in CI.
- Outbound Tor works from this VM (directory authorities reachable); M1 can be verified live.
- The GitHub remote uses HTTPS with the `gh` credential helper (`gh auth setup-git`).

## Coding conventions

- Edition 2024, `rust-version = 1.90`. Workspace lints: `clippy::all` warn (CI runs `-D warnings`),
  `clippy::undocumented_unsafe_blocks` **deny**, `unsafe_code` warn (FFI crates opt in per module
  with `#![allow(unsafe_code)]` and a `// SAFETY:` comment on every block; `core`, `signal`,
  `net`, `proto`, `session` are `#![forbid(unsafe_code)]`).
- Libraries: `thiserror` errors, no `println!`/`eprintln!` (clippy `print_stdout` warns), `tracing`
  for logs, `#![warn(missing_docs)]` on `tornect-core` (extend as crates mature). Binaries: `anyhow`.
- Secrets: `zeroize` on drop, redacted `Debug` impls, never in logs or error strings.
- Tests live next to the code; property tests with `proptest` for anything parsed from the wire;
  fuzz targets (`cargo-fuzz`, nightly) for envelope parsing, datagram reassembly, input decode, auth messages.
- Wire formats: CBOR (`docs/PLAN.md` §B.3) for control, hand-packed fixed headers (§B.4) for media
  datagrams and input events. Every format has round-trip tests.
- Timestamps on every media frame; every pipeline stage reports into stats (§B.7 instrumentation).
- Comments state constraints the code cannot show (invariants, spec references), not narration.

## Security invariants (docs/PLAN.md §B.6, §B.8 — requirements, not options)

- Consent popup always precedes capture; capture starts only after SESSION_ACCEPT.
- Persistent "screen is being shared" indicator + tray state + one-click kill, always — including
  unattended sessions. Panic key (default Ctrl+Alt+End) always works host-side.
- Unattended access: opt-in **per device**, granted only locally on the host, requires prior SAS
  pairing, authenticated with an augmented PAKE (OPAQUE, Argon2id KSF) bound to the signed
  transcript and `session_token`; there is no password-less auto-accept. Lockouts persist.
- All pairing/session/auth events appended to `sessions.log`. No telemetry. Crash dumps opt-in.
- QUIC TLS 1.3 with both certificates pinned to the peers' Tornect keys; no CAs.

## Decisions taken at M0 (docs/PLAN.md Part F)

1. License: **GPL-3.0-or-later** (`LICENSE`).
2. Primary dev OS for M3–M5: **Linux/Wayland (GNOME)** — this machine.
3. Unattended access: **in v1**, opt-in, per §B.8.
4. Minimum targets: Windows 10 20H1+, macOS 13+, xdg-desktop-portal ≥ 1.17 distros.
5. Branding/trademark check: research-verifier task scheduled for M8.

## Agents (`.claude/agents/`)

`architect` · `research-verifier` · `net-engineer` · `media-engineer` ·
`platform-windows` · `platform-macos` · `platform-wayland` · `ui-engineer` ·
`security-reviewer` · `qa-engineer` — charters in the files; roster in docs/PLAN.md §D.3.
`security-reviewer` runs at every milestone close and on any diff touching
signal / net / pairing / consent / unattended / key storage.
