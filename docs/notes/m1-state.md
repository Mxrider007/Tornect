# M1 state — signaling over Tor (hand-off, 2026-08-29)

Milestone 1 is **partially done**: track 1 (Arti embedding) is implemented, reviewed and
verified live; tracks 2–4 (envelope protocol + pairing/SAS, unattended OPAQUE FSM, CLI/IPC/
platform scaffold) are specified and scripted but not started. `m1` is **not** tagged.

## Done (commit `0e568d8`, plan `c515f0d`)

- `tornect-signal::tor`: `TorNode` (rustls/ring provider install, unbootstrapped create +
  bootstrap progress watch, `publish`, `connect` with fresh isolation group, `SignalError`
  mapping from `ErrorKind`), `OnionListener` (accepts only `BEGIN` on `SIGNALING_PORT = 4000`,
  32-handshake / 64-circuit budgets; **backpressure** into Arti's effort-ordered PoW queue when
  PoW is on, drain-and-drop when off — decision M1-4), `OnionStream` (tokio AsyncRead/Write),
  identity derivation seed → RFC 8032 expanded key → `HsIdKeypair` installed via `tor-keymgr`
  (decision M1-1; nickname `tornect-<first 8 chars>`; rotate-id purges `hss/<nick>` — M1-6),
  `framing` (u32-BE, 64 KiB), interim `ping` protocol, `tests/live.rs` (`--ignored`).
- CLI: `tornect host [--once] [--pow|--no-pow]`, `tornect ping <onion> [--count N]`.
- Gates: `cargo xtask verify` (plan sync, forbidden deps aws-lc/openssl, fmt, clippy, tests,
  docs) green; 26 core + 43 signal tests; `fuzz/` crate (workspace-excluded) with a framing target.
- Live evidence (`docs/notes/m1-track1-evidence.md`): cold bootstrap 10–20 s; onion reachable
  73 s (first run) … up to ~5 min under HSDir upload timeouts; ping RTT 0.5–1.1 s; identical
  ID after SIGINT + restart; warm bootstrap ≈ 1 s.
- Plan r4 (`TORNECT_PLAN.md` == `docs/PLAN.md`, 1696 lines) with §B.8 Unattended access.
- Research notes `docs/research/*.md` + `SUMMARY.md` (audit) — code from these, not memory.

## Open findings to apply at the start of the next session (plan text, medium)

1. §B.8.2 T12 / §B.8.5.1 / §B.8.5.3: decay bookkeeping is wall-clock based, so a forward
   clock jump at runtime would decay counters; fix = `Instant` twins for runtime decay, cap
   steps at load, reword T12 honestly, add a U-row.
2. §B.8.9 `GrantState::Suspended{reason}`: a *local* suspend (CLI/IPC/UI) has no reason
   variant; add `Local{by: Actor}`, state that a remote `unlock` never clears it, extend A15.

Plus the plan amendments the research audit lists (`docs/research/SUMMARY.md` "Cross-cutting"):
§A.2 FFmpeg version, §A.4 GNOME lock-screen constraint, §B.2 punch mechanics + `quic_spki`,
§B.4 Opus FEC / MTU / header sizes, §B.5 Wayland token placement + codec fallbacks, §B.6 RPK,
D9 `opus`, D10 no eframe, D13 `keyring-core`, M2 `stun` crate — bump to r6 when applied.

## Next: M1 phase 2 (script ready)

Workflow script: `~/.claude/projects/-home-mx-Tornect/<session>/workflows/scripts/tornect-m1-phase2.js`
(copy of the design lives in this note's sibling `m1-phase2-plan.md` if the session dir is gone).
Before launching:
1. Add `pub mod unattended;` and `pub mod trusted;` stubs to `crates/tornect-core/src/lib.rs`
   (tracks A and B both touch core; pre-creating the module lines avoids a lost update).
2. Bump `rust-version = "1.95"` in `Cargo.toml` + `clippy.toml msrv`, add `rust-toolchain.toml`
   (`channel = "1.96.0"`, components rustfmt + clippy) — arti-client needs 1.91, egui 0.36 needs 1.95.
3. Apply the two open plan findings above (or hand them to the plan-fix step).
Tracks (each implement → security + correctness review → fix): A core store/limiter/guard/log
chain (§B.8.5/6.2/9/13), B envelope/transcript/pairing/SAS/attended FSM (§B.3, §B.8.4), then
C OPAQUE unattended FSM (§B.8.4–6), then D CLI + IPC + `tornect-platform` scaffold (§B.8.7.4),
then E adversarial/fuzz sweep (§B.8.15 M1 rows), security review, live verification
(pair + attended + unattended over real Tor with two `TORNECT_HOME` instances), then tag `m1`.

## Gotchas (dev VM mx-vm)

- Build with `CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp`; `/tmp` is a 3.7 GiB quota tmpfs
  (zstd-sys fails there); Tor state under `target/tornect-test/<name>`, never `/tmp`.
- A full `cargo run -p tornect` rebuild of the Arti graph takes ~2–3 min; the pre-commit hook
  runs clippy (≈ 35 s warm).
- Arti's `status_events()` is eventually consistent: clients connect while the host still
  reports `Bootstrapping`; `REACHABLE` may take minutes (HSDir upload timeouts). Tor transients
  happen — the CLI retries; scripted verification should retry `ping` up to 3×.
- PoW manager threads cannot observe runtime shutdown; `shutdown_runtime` mutes that one tokio
  message (documented in listener.rs; worth reporting upstream).
- `.github/workflows/ci.yml` is written but excluded (`.git/info/exclude`) until the `gh` token
  has the `workflow` scope: `gh auth refresh -h github.com -s workflow`, then
  `git add -f .github/workflows/ci.yml && git commit -m "ci: add GitHub Actions workflow" && git push`.
- `.claude/settings.json` must be created by the user from `.claude/settings.recommended.json`.
