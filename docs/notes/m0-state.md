# M0 state — bootstrap (2026-08-28)

## Done

- Cargo workspace (edition 2024, resolver 3, workspace-wide pins + lints, dev/release/dist profiles).
- `tornect-core`: `TornectId` (onion v3 encode/parse/checksum, serde, grouped display),
  `DeviceId` (+ fingerprint), `HostIdentity`/`DeviceIdentity` (ed25519, zeroized seeds,
  redacted Debug), `SecretStore` trait + `FileSecretStore` (0600/0700, atomic writes),
  `Config` (TOML, defaults, validation, unknown keys tolerated), `Paths` (per-OS +
  `TORNECT_HOME`), `telemetry::init`, `SessionLog` (JSON lines, `sessions.log`).
- `apps/tornect` CLI: `id [--json]`, `rotate-id --yes`, `paths`, `config {show|path|init}`, `doctor`.
- `xtask`: `verify | lint-all | dist | ffmpeg-fetch | soak` (last two are placeholders) +
  plan-sync check (`TORNECT_PLAN.md` == `docs/PLAN.md`).
- Skeleton crates with crate-level docs and feature flags declared: signal, net, proto,
  capture (`pipewire|wgc|sckit`), codec (`ffmpeg`), audio (`cpal`), input (`libei|sendinput|cgevent`), session.
- Claude Code kit: `CLAUDE.md`, 10 agents, `/milestone` `/verify` `/research`,
  `.claude/settings.recommended.json` (+ rustfmt hook script), `.githooks/pre-commit`.
- CI: Linux full (apt installs media libs), Windows + macOS core tests, cross-check, cargo-deny.
  **Not yet pushed**: the `gh` token lacks the `workflow` scope, so GitHub rejects
  `.github/workflows/ci.yml`. Run `gh auth refresh -h github.com -s workflow`, then commit
  and push the file (it is excluded via `.git/info/exclude` until then).
- Docs: `README.md`, `LICENSE` (GPLv3), `docs/DEPENDENCIES.md`, `docs/VERIFICATION.md`,
  `docs/research/*.md` (sourced API notes from the research workflow).

## Decisions (see also docs/notes/decisions.md)

- Part F answered: GPLv3 · dev OS Linux/Wayland · unattended access in v1 (§B.8) · min targets confirmed.
- `arti-client` is 0.45.x (library numbering), not "2.0" — the plan's number is the Arti project version.
- Media software fallback that needs no system libraries: `openh264` (built from source via `cc`)
  so the loopback demo and CI run everywhere; FFmpeg stays the hardware layer behind `--features ffmpeg`.
- `.claude/settings.json` cannot be authored by the model → recommended template committed instead.

## Dev-machine constraints (mx-vm)

No sudo ⇒ no FFmpeg/PipeWire/ALSA/libclang headers, no nasm, no netns. Pure-Rust +
vendored-C stack builds; heavy backends verified in Linux CI. Tor reachable.

## Next: M1

Read `docs/research/arti.md`, `crypto.md`, and `docs/PLAN.md` §B.3 + §B.8 (final r2 text).
Build `tornect-signal`: Arti embedding behind traits, onion service with the host seed
(derive `HsIdKeypair` from the ed25519 seed or let Arti own the key — decide from the
research note), CBOR envelope + state machines + property tests + fuzz target, pairing
with SAS, unattended OPAQUE auth + grants + lockouts in core/signal, CLI `host` / `connect`
/ `ping` with a y/n consent prompt, PoW + rate limits. Verify live over Tor with two
`TORNECT_HOME` instances on this VM, then tag `m1`.
