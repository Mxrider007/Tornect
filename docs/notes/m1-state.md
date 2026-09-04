# M1 state — signaling over Tor (hand-off, 2026-09-04)

Milestone 1 is **about half done**: track 1 (Arti embedding) and phase-2 part 1 (tracks A + B:
the unattended storage/limiter/guard/IPC types in `tornect-core`, and the CBOR envelope,
transcript, pairing/SAS and attended FSM in `tornect-signal`) are implemented, reviewed twice
and green. The unattended PAKE branch (track C), the CLI/IPC/`tornect-platform` surface
(track D), the adversarial + fuzz sweep (track E), the milestone security review and the live
verification are **not started**. `m1` is **not** tagged.

## Done

**Track 1 — Arti (commit `0e568d8`).** `tornect-signal::tor`: `TorNode`, `OnionListener`
(PoW-aware admission with backpressure, handshake/circuit budgets), `OnionStream`, identity
derivation seed → Arti keystore so `tornect id` == the published address, `framing`, the interim
`ping` protocol, `tests/live.rs`. CLI `tornect host` / `tornect ping`. Verified live over Tor
twice (evidence: `docs/notes/m1-track1-evidence.md`).

**Toolchain + plan (commits `d90e795`, `879f461`).** `rust-toolchain.toml` pins 1.96.0
(rustfmt, clippy, the two cross targets); `rust-version`/`clippy.toml msrv` 1.95. Plan
**r6**: the two r5 findings applied (monotonic decay/clock with a `Clock` trait; local
`Suspended{Local{by}}`), the research-audit amendments applied (§A.2, §A.4, §B.2 punch +
`quic_spki`, §B.4, §B.5, §B.6 raw public keys, D5/D6/D9/D10/D12/D13, Part C M2/M3), and the
user's `TORNECT_UI_PLAN.md` adopted as `docs/UI_PLAN.md` (byte-identical, gated by
`xtask verify`) and reconciled in Part G + Part F.6 — UI milestone `u1` (= UI plan U0 + U1)
runs **after M1, before M2**; the UI plan's "Always allow" checkbox/badge is rejected per
§B.2/§B.8. Two adversarial review passes were applied to r6 in place.

**Phase-2 part 1 (commit `cd878f3`, ~3 200 changed lines + ~21 000 new lines incl. tests).**

- `tornect-core::unattended::{store, grant, schedule, codec, limiter, clock, guard, readiness,
  ipc, password, hosts, keyring}` — `UnattendedStore`/`UnattendedGrant`/`FailState` per §B.8.9,
  XChaCha20-Poly1305 store with the generation anchor + `pending_anchor`, fail-closed load
  rules, machine-id check, `GrantStore` with an advisory lock, `hosts.toml` (`server_s_pk`
  pin); `Clock`/`FakeClock` + `AttemptLimiter` (`charge`/`settle`/`gate`/`post_f2`) with the
  r6 decay semantics; `MutationGuard` as the single enforcement point with `ReAuth`,
  `RemoteSessionActivity`, `Presence`, `AttendedHistory` defined here, all three mutation
  classes and the `reg_txn` flow (`G_NO_TXN`); `ReadinessSnapshot`/`Probe` (all-Unknown M1
  stub); the §B.8.7.4 IPC types + CBOR codec; `session_log` §B.8.13 events + hash chain +
  rotation + startup verifier; the §B.8.7.2 password policy.
- `tornect-signal::{envelope, messages, transcript, pairing, consent, fsm}` — the §B.3
  positional CBOR envelope with the `E_*` rules, every message body (including the
  `AUTH_*`/`ADMIN_RESULT` types the next track fills with behaviour), the §B.8.4.3 transcript
  and domain-separated Ed25519 signatures with two committed golden vectors, pairing +
  `tornect-core::trusted` (`TrustedDevices`/`KnownHosts`, token bucket, temp-ban) and the SAS
  definition (now normative in plan §B.3, decision M1-8), and the attended host/client state
  machines over any `AsyncRead + AsyncWrite` with strict alternation, every §B.8.4.5 timeout
  and the `Consent`/`ClientPairingUi`/`StopTokenCheck`/`UnattendedHook`/`BlockWindow`/
  `LocalAllow` seams. `SessionAccept::build(ConsentProof, caps)` is the only constructor.
- Fuzz: `fuzz/fuzz_targets/{envelope, store, ipc}.rs` (F1, F3, F4) next to `framing`, with
  minimized corpora committed.
- Gate: `cargo xtask verify` green — fmt, clippy `-D warnings` (all targets), **152
  `tornect-core` + 116 `tornect-signal` tests**, docs; `cargo deny check` green after
  allowing `BlueOak-1.0.0` (minicbor). Decisions `M1-7 … M1-36`; ~62 VERIFIED rows in
  `docs/VERIFICATION.md`.

## Open / next (in order)

1. **The third review round of tracks A and B never ran** — the workflow's confirmation pass
   died on a model usage limit after the round-2 fixes were applied. Those fixes are green
   but unreviewed. Re-run a review-only pass over `crates/tornect-core/src/unattended/**` and
   `crates/tornect-signal/src/{envelope,messages,transcript,pairing,consent,fsm}` before the
   milestone security review (or fold it into that review).
2. **Track C — the unattended branch** (`tornect-signal::auth`): OPAQUE-3DH authenticator
   (`opaque-ke` 4.0.1 per `docs/research/crypto.md` §8), the key schedule of §B.8.4.3,
   the host `AwaitKe3` FSM branch wired to `AttemptLimiter` + `MutationGuard`, the client
   branch with the `server_s_pk` TOFU pin, admin intent + scope, the stop token.
3. **Track D — CLI/IPC/platform**: `tornect pair|connect|unattended …|panic|devices`, the
   host-role IPC dispatch loop, and the `tornect-platform` scaffold (`ipc`, `reauth`).
4. **Track E — adversarial + fuzz sweep**, then the `security-reviewer` milestone close, then
   **live verification** (pair + attended + unattended over real Tor with two `TORNECT_HOME`
   instances), then tag `m1`.

Cross-track notes left by the tracks: the CLI track must send `TOR_FALLBACK{}` after the accept
(or set `orphan_timeout = None`) and use `fsm::HostAudit::new(Arc<SessionLog>)` as
`HostDeps::audit`; `apps/tornect`'s `rotate-id` appends its own `HostIdRotated` and must stop
once it is wired to the guard.

**Deferred to plan r7** (decisions M1-31/M1-32 carry the options): whether `PAIR_REQUEST` /
`PAIR_ACCEPT` should be signed (§B.3 lists `PAIR_ACCEPT` unsigned, so a pairing-only exchange has
no signed frame), and whether `quic_spki` should bind the pairing-pinned `host_device_pk` rather
than the onion identity key (M1 implements the onion key; §B.6 says it must equal the pairing pin).

**OPEN rows in `docs/VERIFICATION.md`** worth knowing: the EFF passphrase generator (M8 — no
word list is vendored), `mlock`/`VirtualLock` memory hygiene (M6), the keyring canary and the
persistent OS backends (M6 — the M1 `keyring` feature is test/CI-only), the §B.8.5.2 host-wide
budgets (owned by the signal FSM, land with track C), and grant preconditions reading
unauthenticated inputs (`SessionLogHistory` / `FilePairedDevices`).

## Gotchas (dev VM mx-vm)

- Build with `CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp`; `/tmp` is a 3.7 GiB quota tmpfs
  (zstd-sys fails there); Tor state under `target/tornect-test/<name>`, never `/tmp`.
- A cold Arti rebuild is 2–5 min; the pre-commit hook runs fmt + clippy
  (`TORNECT_SKIP_HOOKS=1` for docs-only commits).
- If a worktree ever shares `target/`, `target/debug/xtask` embeds *that* worktree's root and
  `cargo xtask verify` will silently verify the wrong tree — `touch xtask/src/main.rs` first,
  or give the worktree its own `CARGO_TARGET_DIR`.
- Arti's status stream is eventually consistent: clients connect while the host still reports
  `Bootstrapping`; `REACHABLE` can take minutes; retry `tornect ping` up to 3× on transients.
- Parallel tracks must not share files: pre-create module stubs and give each track an explicit
  ownership list; shared docs (`DEPENDENCIES.md`, `VERIFICATION.md`, `decisions.md`) get
  small targeted insertions only, re-read immediately before each edit.
- `.github/workflows/ci.yml` is written but excluded (`.git/info/exclude`) until the `gh` token
  has the `workflow` scope; `.claude/settings.json` must be created by the user from
  `.claude/settings.recommended.json`.
