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

1. ~~The third review round of tracks A and B~~ — **done 2026-09-04** (commits `5391f76`,
   `7762849`, `3ee4943`). See *Round 3* below. It does **not** replace the milestone
   `security-reviewer` close, which still has to run over the finished M1.
2. ~~Track C — the unattended branch~~ — **done 2026-09-04** (`08d391a`, `324b4d4`,
   `fc48e24`). See *Track C* below. Two pieces of its B.8.14 row are **not** done and
   are carried into track D: **admin intent + scope** (the branch reaches `ADMIN_RESULT`
   but answers `ok: false, "not implemented at M1"` — the scope rules of §B.8.4.1,
   `unlock(pk)` / `suspend(pk ≠ self)` / `revoke(pk ≠ self)` / `revoke_all`, are
   unimplemented) and the **stop token** (`HELLO.stop_token` is observed by the existing
   seam but nothing in the unattended path consults it yet).
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

## Track C — the unattended branch (2026-09-04)

Three commits, each gated:

- **`08d391a` — the crypto core (`tornect-signal::auth`).** OPAQUE-3DH over ristretto255
  with Argon2id (64 MiB / t=3 / p=1) and the whole §B.8.4.3 schedule (`context`,
  `identifiers`, `session_token`, `confirm_key`, `token_confirm`, `proof_fp`). No wire and
  no store dependencies: `HostLogin` / `ClientLogin` are pure state machines over the byte
  strings `AUTH_CHALLENGE` / `AUTH_RESPONSE` already carried. Both `crypto.md` traps are
  handled explicitly — the KE hash is `sha2_010::Sha512` (digest 0.10, not the workspace
  sha2 0.11) and the KSF is named through `opaque_ke::argon2` (0.5, not the workspace 0.6);
  `OpaqueRng` feeds `getrandom` to opaque-ke's rand-0.8 API instead of vendoring a second
  `rand`. Nine tests, including one that is functional rather than declarative: a record
  registered under the suite KSF **cannot** be opened by a login that omits it, so a silent
  regression to the crate's 19 MiB / t=2 default cannot pass.
- **`324b4d4` — the host branch (`tornect-signal::unattended`).** `UnattendedAuth` is the
  real `UnattendedHook`, replacing the `NOT_GRANTED` stub with the full §B.8.4.5 path. The
  charge is write-ahead and fsynced before KE2 is written, and every exit path settles it;
  a transport failure settles as the matching `FailKind` and returns the `HandshakeError`
  unchanged so `serve_host` reports the documented code. The §B.8.5.2 budgets are held by
  an `InFlight` guard that releases on drop. `OpaqueServerSetupSource` fills the
  `ServerSetupSource` seam core declares but cannot implement.
- **`fc48e24` — the client branch + end-to-end.** `Intent::Unattended` drives the exchange;
  the accept checks mirror the attended ones (session type 1, `session_token` absent,
  `token_confirm` present and verified in constant time). The `hosts.toml` TOFU pin enters
  as a `ServerKeyPin` seam; a mismatch aborts **before** KE3 (A16) and the key is recorded
  only after the host's `token_confirm` verified.

`fsm::tests::unattended_session_end_to_end_over_a_duplex_pipe` is a real `connect()`
against a real `serve_host` running the real hook — no stub at any layer — reaching
`SESSION_ACCEPT` with a derived token and zero popups. That is the B.8.14 M1 acceptance
shape minus the Tor transport; live verification over Tor stays in track E.

Gate after track C: `cargo xtask verify` green, **286 tests**.

**Harness notes for whoever writes the next tests.** A grant needs the master switch on
(`MutationGuard::master_on`, off by default — §B.8 opt-in) and a preset that waives the
"prior attended session" precondition (`Preset::HeadlessBox`); the OPAQUE registration must
run against the `ServerSetup` the store ends up holding, so bootstrap the store first and
read `server_setup()` back rather than generating one locally.

## Round 3 (2026-09-04)

Twelve hostile reviewers over the ~20 k unreviewed lines of tracks A and B, each finding then
attacked by three perspective-diverse refuters (correctness / security / spec) with
majority-refute killing it: **38 raw findings → 3 confirmed, 35 refuted.** Full report,
including the refuted set so a later pass does not re-litigate it, in
`kore_project_V3/agents/security/reports/2026-09-04_tornect_m1_round3_review.md`.

- **HIGH — the SAS was grindable (`3ee4943`, decision M1-37, supersedes M1-8).** The r6 input
  `th_after(PAIR_REQUEST)` is attacker-malleable on *both* sides after the peer's contribution
  is visible, against a ~2^20 code: a MITM grinds `host_nonce` toward the client and the
  unsigned `PAIR_REQUEST` toward the host (`client_auth_pk` is parsed and discarded but still
  absorbed; unknown CBOR keys are ignored by design). Reproduced: ~1500 candidates per side,
  collision at 323, both screens `034 057`, ~60 ms of signing — inside the 20 s `HELLO_ACK`
  timeout. §B.3 amended to commit-then-reveal (`HELLO.sas_commit`, `PAIR_REQUEST.sas_nonce`,
  `SAS = HKDF(th_after(HELLO_ACK) || sas_nonce)`); both golden vectors and the envelope fuzz
  seeds regenerated; `client_random()` scripts a second value. Note for r7: this **partly
  answers M1-31** — signing `PAIR_REQUEST` alone would not have fixed it, since the attacker
  re-signs each candidate with its own key.
- **MEDIUM — a locked keystore permanently broke the log chain (`5391f76`).** Untagged lines
  written while `K_master` exists but is unreadable land after the key epoch and past
  `log_chain_head`, so `verify_chain` returns `Broken` forever after the recovery load: a
  standing tamper badge with nothing tampered, clearable only by `reset_store`. Now buffered
  and flushed tagged.
- **LOW — the file-keystore password escalation was never tested (`7762849`).** Its only
  discriminating assertion sat in a dead branch, while `VERIFICATION.md` recorded U3 as
  VERIFIED on the strength of it; a mutation deleting the escalation left the suite green.

Both fixes are pinned by regressions that fail against the pre-fix code (verified by
mutation / by reverting the single file). Gate after the round: `cargo xtask verify` green,
**271 tests** (153 core + 118 signal).

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
