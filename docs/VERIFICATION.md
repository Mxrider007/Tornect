# Verification ledger

Every acceptance check from `docs/PLAN.md` Part C lives here with its real status.
Statuses: **VERIFIED** (machine, date, evidence) · **CI** (verified by the named CI
job) · **NEEDS-DEVICE(os/hw)** (written and `cargo check`-ed, runtime not yet
exercised — the user or a Claude Code session on that machine clears it) · **OPEN**.

Dev machine for this ledger unless stated otherwise: `mx-vm` — Ubuntu 26.04 LTS,
GNOME on Wayland, VMware virtual GPU (no hardware encoder), 4 vCPU / 7 GiB,
Rust stable 1.96. No sudo: FFmpeg / PipeWire / ALSA dev headers are unavailable
locally, so those backends are compiled and tested by the Linux CI job instead.

## M0 — Bootstrap

| Check | Status | Evidence / notes |
|---|---|---|
| Workspace scaffolding per §B.1 (9 crates, `apps/tornect`, `xtask`) | VERIFIED mx-vm 2026-08-28 | `cargo build --workspace` green; crate graph `core → … → session → app` |
| `tornect-core`: `TornectId` newtype (onion v3), config load/save, key generation + keystore, tracing | VERIFIED mx-vm 2026-08-28 | 26 unit/property tests; onion checksum conformance proven by parsing three real public onion addresses (DuckDuckGo, Tor Project, Facebook) |
| `cargo xtask verify` (fmt, clippy `-D warnings` all targets, tests, docs `-D warnings`) | VERIFIED mx-vm 2026-08-28 | `verify: all gates green` |
| `cargo run -p tornect -- id` prints a fresh .onion ID | VERIFIED mx-vm 2026-08-28 | `k2oizt5hhkw2idx6uq4r6cqcwli7djthhmeeowtkkmytvwk4sd7x7vad.onion`; second run returns `created:false` with the same ID |
| Keystore files private | VERIFIED mx-vm 2026-08-28 | `state/keys/` is `0700`, `*.secret` are `0600` (tested + inspected) |
| `rotate-id` invalidation path + `sessions.log` record | VERIFIED mx-vm 2026-08-28 | `host_id_rotated` JSON line written; refuses without `--yes` (exit 2) |
| `cargo check --workspace --target x86_64-pc-windows-msvc` | VERIFIED mx-vm 2026-08-28 | green (1m23s cold) |
| `cargo check --workspace --target aarch64-apple-darwin` | VERIFIED mx-vm 2026-08-28 | green |
| `tornect id` on Windows and macOS runners | CI (pending) | jobs `windows`, `macos` in `.github/workflows/ci.yml`. The workflow file could not be pushed yet: the `gh` OAuth token lacks the `workflow` scope (`refusing to allow an OAuth App to create or update workflow`). Fix: `gh auth refresh -h github.com -s workflow`, then `git add .github/workflows/ci.yml && git commit -m "ci: add GitHub Actions workflow" && git push` |
| CI skeleton: lint + test on Linux with all media system libs installed; cross-check job; cargo-deny | CI (pending) | `.github/workflows/ci.yml` written and kept locally until the scope above is granted |
| `.claude/` control files (§D.2, §D.3): 10 agents, 3 commands, hooks | VERIFIED mx-vm 2026-08-28 | `.claude/settings.json` could not be written by Claude Code itself (harness refuses model-authored permission config) → shipped as `.claude/settings.recommended.json`; git pre-commit hook enforces fmt + clippy instead |
| License decision recorded | VERIFIED 2026-08-28 | GPL-3.0-or-later (`LICENSE`, `Cargo.toml`, `deny.toml`) |
| `docs/PLAN.md` == `TORNECT_PLAN.md` | VERIFIED | `cargo xtask verify` compares them byte-for-byte |

## M1 — Signaling over Tor

| Check | Status | Evidence / notes |
|---|---|---|
| Host publishes onion service with persistent key; restart ⇒ same ID | OPEN | Tor directory authorities reachable from mx-vm (TCP to moria1:9131 OK) |
| Client connects by onion address; HELLO/PAIR/SESSION state machines + property tests | OPEN | |
| Unattended auth messages (§B.8) + PAKE round-trip tests | OPEN | |
| CLI consent prompt with SAS before egui exists | OPEN | |
| PoW DoS defense + rate limits on | OPEN | |
| Two machines on different NATs pair and PING/PONG via Tor | OPEN | needs a second machine; same-machine two-instance recipe: `TORNECT_HOME=/tmp/h1` host + `TORNECT_HOME=/tmp/h2` client |
| `tornect-signal` fuzz target 10 min clean | OPEN | nightly toolchain |

## Netem / soak harness

| Profile | Status | Evidence / notes |
|---|---|---|
| `tests/netem/run.sh lan` | OPEN | needs root for netns (not available on mx-vm); Linux CI job |
