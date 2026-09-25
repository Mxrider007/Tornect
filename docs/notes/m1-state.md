# M1 state — signaling over Tor (hand-off, 2026-09-04)

Milestone 1 is **most of the way done**: track 1 (Arti embedding), phase-2 part 1 (tracks A + B),
track C (the unattended PAKE branch) and now track D (CLI / IPC / `tornect-platform`) are
implemented and green at 320 tests. Track E (the adversarial + fuzz sweep), the milestone
`security-reviewer` close and the live verification over real Tor are **not done**, and `m1` is
**not** tagged.

**Update 2026-09-21 (fourth session): `serve_host` is wired into `tornect host`** (decision
M1-42; see *Session 2026-09-21 (4)* below). The host answers the handshake FSM and the
pairing-free ping on one port, `tornect connect` drives the attended path, and `tornect panic`
ends live sessions. What still stands between here and the §B.8.14 M1 acceptance ("headless
unattended handshake ending in `SESSION_ACCEPT` … between two machines"): the client side of an
**unattended** connection has no CLI yet (`Intent::Unattended` is reachable only from tests),
and there is no second machine.

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
3. ~~Track D — CLI/IPC/platform~~ — **done 2026-09-05** (`fbc7a31`, `be58ea6`, `48ca97e`).
   See *Track D* below. Admin intent + scope and the stop token, carried in from track C, are
   both delivered.
4. ~~Wire `serve_host` into `tornect host`~~ — **done 2026-09-21, fourth session** (decision
   M1-42). Every seam below is filled, `HostDeps::sessions`/`activity` come from one
   `LiveSessions` tracker that also feeds the guard, and `tornect connect` sends
   `TOR_FALLBACK{}` after the accept. `rotate-id`'s own `HostIdRotated` append is still open.
   The seams as they were listed: `HostDeps::unattended` = `UnattendedAuth` (with
   `.with_admin_authority(GuardAdmin)`), `HostDeps::stop_token` = `EmergencyStop`,
   `HostDeps::audit` = `fsm::HostAudit::new(Arc<SessionLog>)`, `HostDeps::trusted` = the real
   `TrustedDeviceStore`, `HostDeps::consent` = a CLI prompt, and `HostDeps::kill` shared with
   the IPC context so `tornect panic` and a remote `master_off` reach live handshakes. The CLI
   must also send `TOR_FALLBACK{}` after the accept or set `orphan_timeout = None`, and
   `rotate-id`'s own `HostIdRotated` append must stop once it goes through the guard.
5. **Track E — adversarial + fuzz sweep**, then the `security-reviewer` milestone close, then
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

**Track C review (2026-09-04, `3d468f1`).** Six hostile reviewers over the new code, each
finding attacked by three refuters: **26 raw findings → 3 confirmed, 23 refuted**; full report
in `kore_project_V3/agents/security/reports/2026-09-04_tornect_track_c_review.md`. All three
fixed:

- **MEDIUM — `export_key` / `session_key` dropped, not zeroized.** `opaque-ke`'s `*FinishResult`
  types are `derive_where(Clone)` only; unlike the state types they are **not** `ZeroizeOnDrop`.
  The doc comment claimed otherwise, which is worse than saying nothing. All four sites now wipe
  explicitly. The §B.8.15 A14 core-dump sweep is still OPEN.
- **MEDIUM — pre-emption unimplemented.** §B.8.4.5 makes cancellation the rule and `UA_BUSY` the
  narrow case; only the narrow case existed, so `PREEMPTED` was emitted nowhere and a client whose
  circuit died was locked out for the full 30 s `AwaitKe3` timeout. Also: the in-flight slot was
  held for the whole handler although §B.8.5.2 counts `AwaitKe3` only, so four accepted sessions
  in their block windows could `UA_BUSY` a fifth device.
- **LOW — no `BYE{CLIENT_AUTH_ABORT}`** from the client on a failed server MAC (§B.8.4.2).

The §B.8.5.2 budgets had **no test at all** before this; two were added, both verified to fail
against the pre-fix code.

Gate after track C and its review: `cargo xtask verify` green, **289 tests**.

**Harness notes for whoever writes the next tests.** A grant needs the master switch on
(`MutationGuard::master_on`, off by default — §B.8 opt-in) and a preset that waives the
"prior attended session" precondition (`Preset::HeadlessBox`); the OPAQUE registration must
run against the `ServerSetup` the store ends up holding, so bootstrap the store first and
read `server_setup()` back rather than generating one locally.

## Track D — CLI / IPC / platform (2026-09-05)

Track D was framed by the previous hand-off as "wiring plus a new crate". Reading the
tree first changed the estimate in both directions: the §B.8.4.1 **scope matrix was
already implemented** in `MutationGuard::admin`, `AdminOp::from_wire`, `AdminEffect` and
`guard::{stop_token, emergency_stop}` — so admin intent and the stop token were seams to
fill, not logic to write — but `crates/tornect-platform` **did not exist at all**, and
`serve_host` **is still not wired into `tornect host`** (see *Still open* below).

**`fbc7a31` — admin intent, the emergency stop, and an ordering fix.**

- `AdminAuthority` is the seam; `GuardAdmin` wraps `MutationGuard::admin`; `RefuseAdmin`
  is the default, so a host wired without an authority refuses rather than pretending to
  have run the command. `UnattendedVerdict::Admin` now carries the resulting
  `AdminEffect`, applied by `serve_host` because that is where the kill switch lives.
  The two host-wide effects (`master_off`, `revoke_all`) fire it; the two per-device ones
  cannot with an M1 host-wide switch and are documented as an M4 gap rather than
  approximated — the store mutation has already happened, so the revoked device's *next*
  handshake fails its grant lookup regardless.
- `EmergencyStop` implements `StopTokenCheck`: a constant-time match turns the master
  switch off, revokes every grant, fires `BYE{EMERGENCY_STOP}` and clears the stored
  token, so the printed card is single-use. A failed apply leaves the token in place —
  a stop that did not happen must not look like one that did.
- **Ordering defect fixed.** The admin branch sat *after* `post_f2`, so §B.8.4.2's
  "schedule · readiness · transport · busy · concurrency gates skipped" for an admin
  request did not hold: a grant whose schedule window was shut, or whose reconnect
  cooldown was running, answered `SESSION_REJECT{OUTSIDE_SCHEDULE}` instead of executing.
  The commands affected are `revoke`, `revoke_all`, `master_off` and `end_session` — the
  deny-direction ones a user reaches for in an emergency. Requester eligibility is
  unchanged; `MutationGuard::admin` still re-checks state, expiry, `active_from`, the
  hard lock and the clock-rollback rule. `admin_runs_even_when_the_schedule_window_is_shut`
  fails against the pre-fix ordering (verified by reverting the branch: reject 33).

**`crates/tornect-platform` — the M1 scaffold (§B.8.14: two modules, no more).**

- `ipc` — the owner-only endpoint. `<state_dir>/ipc.sock` at 0600 inside an already-0700
  directory, and the decisive check: the peer's `SO_PEERCRED` uid must equal the uid that
  owns the socket file *this process created*. Comparing against the socket's own owner
  rather than a `getuid()` call keeps the crate on `#![forbid(unsafe_code)]` with no
  `libc`/`nix`/`rustix` pin — `tokio::net::UnixStream::peer_cred()` is already available
  under the `net` feature. A stale socket left by a crashed host is replaced only after a
  connect attempt proves nothing is listening; a live one refuses with `AlreadyRunning`.
  Connections are served one at a time, deliberately: every op behind the handler is a
  guard call against a store with a single advisory lock. Framing is the §B.3 shape,
  implemented locally because the crate direction forbids depending on `tornect-signal`
  and `tornect-core` carries no async runtime.
  Windows is a compile-checked scaffold that returns `Unsupported`: §B.8.7.4's owner-only
  DACL, `PIPE_REJECT_REMOTE_CLIENTS` and client-SID check need a Win32 binding that
  cannot be verified here, and §B.8.14 schedules "IPC endpoint per OS" at M6 anyway. A
  pipe without the DACL would be worse than none, because it would look like it worked.
- `reauth` — `PolkitReAuth` over the system D-Bus, plus the debug-build-only
  `TORNECT_DEV_REAUTH=allow` escape and a `RefuseReAuth` default. Verified against live
  polkitd 127 on this machine, including the unregistered-action path.

**Research that changed the design** (full record:
`kore_project_V3/agents/devops/reports/sub/2026-09-04_SUB_RESEARCH_VERIFIER_reauth_ipc.md`,
synthesised in `agents/devops/reports/dependency_status.md`):

1. **PAM was never the blocker.** This machine has no `libpam` headers and no sudo, which
   looked fatal to §B.8.14's "PAM/polkit on the Linux dev machine". polkit *runs* the PAM
   conversation itself, out of process, in setuid `polkit-agent-helper-1` (journal:
   `pam_unix(polkit-1:auth): conversation failed`). A direct PAM backend is redundant and
   unbuildable here. **§B.8.14's M1 row and §B.8.8's "PAM fallback for headless" want a
   footnote saying so.**
2. **`op` cannot reach the dialog.** An unprivileged caller may not pass a `details` map —
   polkit refuses the whole call. This contradicts `guard.rs`'s "a fresh dialog per
   operation (`op` names it)". Resolved with **five action ids by operation class**;
   `every_guard_operation_maps_to_a_registered_action` pins every `op` string the guard
   emits to one of the five the policy file declares, and an unknown op deliberately
   lands on the strongest wording.
3. **"Fresh dialog per operation" rests on the policy file**, not the client:
   `ALWAYS_CHECK` does not bypass a retained authorization. `packaging/polkit/org.tornect.policy`
   uses `auth_self` and carries a **READ BEFORE EDITING** comment, because changing it to
   `auth_self_keep` would weaken the model with no code change and no failing test.
4. **An unregistered action is `Unavailable`, never `Denied`** — telling an operator
   "wrong password" when the real problem is a missing policy file sends them chasing the
   wrong thing. Pinned by a test that needs neither polkit nor a human.
5. **`unix-session` crashes polkitd 127** (reproduced twice) and `unix-process` carries
   the CVE-2017-7572 race. The subject is `system-bus-name`.

**Honest limit, in the module's own docs:** polkit cannot defend against same-uid code
execution — anyone running as this user can ptrace the process or run their own build
against the same state dir. What it buys is proof a human is at the host, which is exactly
the §B.8 adversary: a remote peer with a device key and the grant password and no way to
answer a dialog.

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

## Session 2026-09-21 — bridges, track D review, vertical-slice crates

**Operator direction:** finish the app — functional on Linux and Windows, Tor with automatic
obfs4 bridges when Tor is blocked and Snowflake when obfs4 fails, Windows cross-compile.
Scope ruling: **vertical slice first** (M1-39, M3-1; `docs/notes/CONTINUATION.md`).

Done:
- **Track D review re-run** (first thing, frozen worktree `/home/mx/tornect-review-trackd` @
  `7697823`): 105/105 agents completed, 33 raw → 12 survivors → 8 distinct; S1 (HIGH, IPC
  30 s answer timeout vs 120 s polkit dialog ⇒ `unattended on` commits after the CLI reported
  failure, stop code lost) verified by hand. **Unfixed** — first item next session.
  Report: `kore_project_V3/agents/security/reports/2026-09-21_tornect_track_d_review.md`.
- **Bridge ladder (M1-38)**, commit `213e7d9`: `tor::bridges` (Rung, Ladder, Transport,
  built-in bridge lines, lyrebird discovery, last-good memory), `TorNode::start_auto` (fresh
  client per rung on its own runtime, `ready_for_traffic` only, stall/cap policy),
  `tornect tor-check`, `--bridges`, doctor line. Live: direct 14.3 s / obfs4 78.2 s /
  Snowflake 16.2 s. lyrebird 0.8.1 from the GPG-verified tor-expert-bundle 15.0.23.
- **Media port (M1-39):** listener accepts BEGIN on 4000 and 4001; `OnionStream::port()`;
  `TorNode::connect_on` + `Isolation` (same rendezvous circuit).
- **Slice crates:** `tornect-proto` (Tor media framing + bind MAC, 5 tests), `tornect-input`
  (16-byte event, Chromium-derived USB key table, `Tracked`, XTEST, SendInput; 7 tests),
  `tornect-codec` (OpenH264, 3 tests).
- **Windows cross-build:** llvm-mingw 20260908 + `x86_64-pc-windows-gnullvm`, `+crt-static`,
  `CXXSTDLIB=c++`; OpenH264's C++ links for Windows.

Not done: capture, session layer, GUI, `serve_host` in `tornect host`, the whole-app Windows
build, packaging — the app is not yet functional end to end.

## Session 2026-09-21 (2) — track D fixed, slice-range review, hardening

Commits, all pushed: `5523fcc` (track D), `c868e71` (proto/input), `38c8de5` (bridge ladder +
lyrebird pin), `110b774` (cargo-deny in the gate), `81da800` (a flaky test). The gate is green at
**368 tests**, and `cargo deny --offline check` now runs inside `cargo xtask verify`.

- **Track D: all 8 distinct survivors fixed** (`5523fcc`). Each was re-verified against the
  code first. S1, S2 and S3/S10 have regression tests that fail on the old code.
  - S1/S4 (HIGH): the CLI waits `RESPONSE_TIMEOUT` = 150 s, and an undelivered `On` turns
    access back off and clears the token.
  - S6: the endpoint serves connections concurrently; at most one polkit dialog is open.
  - S2: the admin effect fires even if the answer cannot be sent.
  - S3/S10: post-commit log lines are best-effort.
  - S5: the offline CLI uses `LoadMode::Offline`.
  - S7: the polkit policy uses `auth_self` everywhere, and `is_challenge` is reported as
    "no authentication agent".
  - S8/S12: the password is read unbuffered, and secret buffers are wiped.
  - S9/S11: device labels are passed to zxcvbn, and warnings are shown.

  Checked under a real PTY (`on` → `grant` → `status`) and over the host IPC socket.
  **Residual:** zxcvbn still scores "Laptop-of-Ana tornect 2026" at 4, even with the label.
- **Review of `7697823..efe75fa`** (A′: 3 read-only sub-agents; no ≈ 100-agent refuted
  review, because it was not approved at that size): 0 critical, 0 high. The fixes:
  - M1-40: private bridge lines replace the built-ins; `auto` does not probe direct Tor when
    private lines are set, and direct goes last after a bridge was needed.
  - lyrebird is SHA-256-pinned and never taken from `PATH`. Checked live: obfs4 was ready in
    47.6 s, and a tampered copy was refused.
  - M1-41: the media bind key is HKDF-derived.
  - Power, Sleep, WakeUp and Eject are refused by the injector.
  - cargo-deny runs in `verify`, and `deny.toml` covers gnullvm.

  Report: `kore_project_V3/agents/security/reports/2026-09-21_tornect_slice_review.md`.
- **Not done:** everything after `serve_host` (below). The app is still **not functional end
  to end**.

Requirements the session layer inherits from the review (SLICE-A2 / A1 G3):
- the view-only gate before any `Input` decode;
- single-use `Bind`, with a deadline for it;
- one media stream per session;
- an input rate cap and a bounded video ack window;
- the viewer sizes frames from `DecodedFrame`, never from `BindOk`;
- no unbound 4001 stream may keep a circuit alive.

Also latent: `KillSwitch` latches — nothing resets it after one kill. It must become per-session,
or be reset, when `serve_host` is wired. — **FIXED 2026-09-21 in `94dfe64`; see the session
below.**

## Session 2026-09-21 (3) — kill switch unlatched, SessionSink seam

Resumed at `51458f7`. Two commits, **not pushed**; gate green at **370 tests**.

- **`94dfe64` `fix(signal)`: the kill switch is per-session.** `KillSwitch` held one
  `watch<Option<u16>>` for the host's lifetime, so the first kill latched `Some(reason)`
  for good; `established()` polls it first in a biased `select!`, so every session accepted
  after a master-off / revoke-all / panic / emergency stop was `BYE`d on entry — one kill
  disabled hosting until the process restarted. It now carries a **generation counter**;
  `serve_host` calls `KillSwitch::arm()` **at accept time** and the returned `KillGuard` fires
  only for a kill with a newer generation. Arming at accept (not in `established()`) keeps a
  kill fired *during* a handshake effective, so the panic key still reaches a session that has
  not got to `Established`. Refusing *new* access after a master-off stays the grant store's
  job, so dropping the latch does not widen what is accepted. Failing-first proven: the
  regression test fails on the old code with `Frame(Io(Kind(BrokenPipe)))`.
- **`34f4723` `feat(signal)`: the `SessionSink` seam.** `HostDeps.sessions: Arc<dyn SessionSink>`.
  `on_start(&LiveSession)` after `SESSION_ACCEPT` and `th_final` (device, label, session id,
  **session token** — the M1-41 `Bind` key input — `th_final`, mode, `unattended`);
  `on_end(session_id, Option<&SessionEnd>)` as soon as `established` returns and **before the
  error propagates**. Exactly one `on_end` per `on_start`, so capture can hang off the pair as
  acquire/release. `NoSessionSink` is the default — M1 behaviour unchanged.
- **`serve_host` is still NOT wired into `tornect host`**, blocked on one operator decision:
  the FSM needs pairing, so the zero-setup `tornect ping` liveness check cannot survive
  unchanged. The options and the recommendation are at the top of `docs/notes/CONTINUATION.md`.
  Until the wiring lands, the panic key and IPC `Panic` still do not end live sessions.
- Lints that bit new code: `collapsible_if` (use an edition-2024 let-chain) and
  `type_complexity` (a 5-tuple in a test recorder → named struct). Both surfaced only at the
  gate's clippy step, after a `cargo check` had been clean.

## Session 2026-09-21 (4) — `serve_host` in `tornect host`, `tornect connect`

Resumed at `84f00f9`. The three commits of session 3 were pushed at the start, after the gate
re-ran green (370 tests). The operator answered the blocking question: **"Keep ping, add
connect"** (decision M1-42).

- **`tornect_signal::dispatch`.** The host routes each signaling stream by its first frame:
  exactly `TORNECT-PING/1 ‖ nonce` goes to the ping protocol, anything else to the FSM. The
  first frame is read whole, under the FSM's `HELLO` deadline (30 s, statically equal to the
  ping protocol's frame deadline) and its 8 KiB handshake cap, then replayed (`Replay<S>`,
  zeroized once consumed — a `HELLO` can carry the stop token). The FSM therefore answers every
  first frame byte for byte as before, and no peer holds a stream longer than the FSM allows.
- **`LiveSessions`** (`fsm::host`). Fed by `SessionSink`, it answers both `SessionActivity`
  (the FSM's `BUSY`) and the guard's `RemoteSessionActivity` (no access-increasing change during
  a session or its 60 s cool-down), so the two cannot disagree. **One live session at a time**:
  while one runs, every pairing and session request is `BUSY` (§B.8.16).
- **`apps/tornect/src/host.rs`** — `wire()` fills every seam of the old seam list:
  - the trusted-device store;
  - terminal consent;
  - `EmergencyStop` and `UnattendedAuth` + `GuardAdmin` over the host's guard, with a `UTC`
    zone snapshot (no path in this build creates a grant schedule; decision M1-15);
  - `HostAudit` on **the grant store's own `sessions.log` handle** — the log is a keyed hash
    chain whose lock lives in the handle, so a second handle could fork it;
  - **one `KillSwitch` and one `LiveSessions` shared with the IPC context**, so `tornect panic`
    and `unattended off/pause/revoke-all` end live sessions and the guard sees them.

  If the unattended store cannot open, the host still serves attended sessions and refuses
  unattended ones.
- **`apps/tornect/src/prompt.rs`.** The host's popups and the client's SAS confirmation are
  terminal questions, answered only on a TTY: with stdin not a terminal, the host denies
  everything and the client confirms nothing. One stdin reader thread starts at the first
  question, so a backgrounded host that only answers pings never touches the terminal.
  Questions queue, and lines typed before a question is shown are discarded.
- **`tornect connect <id> [--pair-only] [--forget] [--pings N]`.** It pairs (the user compares
  the code, 50 s), asks for a session, sends `TOR_FALLBACK`, then keeps the session alive with a
  `PING` every 10 s. Between pings it waits on the stream, so a host `BYE` is reported at once.
- **Tests: 370 → 388** for the wiring (capture then added 9 more on Linux), `cargo xtask verify` green. Failing-first was proven three times:
  - an unshared kill switch fails the Panic test (`Timeout("session frame")`);
  - a guard told that no session runs lets `On` through to the polkit dialog;
  - the old keep-alive loop reports a host panic as `Lost(BrokenPipe)`.
- **Live over Tor on the build VM: PASS 8/8** (`docs/notes/m1-serve-host-evidence.md`): ping, the same
  code on both screens (a re-pair via `--forget`), a control session, a view-only session with
  no second pairing, `unattended on` refused mid-session, `tornect panic` ending the session on
  both ends in 0.6 s, and a clean Ctrl-C. Runs 1–3 are recorded too. Run 3 found the one real
  bug of the session (a panicked session reported as "connection lost"), fixed before run 4.

- **`tornect-capture` begun (vertical slice, not M1).** The `VideoSource` trait (a pull with a
  timeout; tight BGRx `Frame`s), a synthetic `TestCard` that writes its frame index into a
  32-block strip (large enough to survive H.264, so a viewer can check order and loss), the X11
  backend (`GetImage` + the XFIXES cursor, refused unless `XDG_SESSION_TYPE=x11`; verified under
  `xvfb-run`) and the GDI backend (every GDI object lives inside one `next_frame`; per-monitor-v2
  DPI awareness set once; lint-clean for gnullvm, runtime `NEEDS-DEVICE(windows)` with a
  cross-built test recipe in `docs/VERIFICATION.md`). On rootless Xwayland, `GetImage` on the
  root answers `BadMatch`.

**Not done, and honestly so:**
- **No Wayland capture.** The RemoteDesktop portal + PipeWire backend, which a GNOME or KDE Linux
  host needs, is not written. It adds `ashpd` and `libloading` to the lockfile (expect a full
  Arti rebuild), and the portal dialog needs a human click.
- **No unattended client CLI.** `Intent::Unattended` is reachable only from tests, so the
  §B.8.14 M1 acceptance (headless unattended handshake between two machines) still cannot be
  shown end to end.
- **The kill switch is host-wide** (M1 scope): `unattended off`, `pause` and `revoke-all` also
  end *attended* sessions.
- The panic key does not suspend the grant behind an unattended session (M4).
- No session layer or GUI; no Windows whole-app build; `m1` untagged; CI has never run.
- `rotate-id`'s own `HostIdRotated` append is still open.

## Session 2026-09-21 (5) — the session layer: media over Tor

**Commits** (gate green at **424 tests**, cargo-deny ok):
- `be28c64` `feat(proto)`: the 64-byte client frame cap; `BindOk` documented as a hint.
- `bc85abe` `feat(session)`: `MediaHost` + `MediaViewer`, decision M1-43.
- `fd672b7` `feat(tornect)`: `tornect host --capture`, the media stream in `tornect connect`.
- `764f74f` `fix(signal)`: the M1-44 review fixes.
- `7d3668a` `fix(tornect)`: the media-end wording.

**What exists now.**
- `tornect-session` serves the Tor media stream of M1-39.
  - **Bind:** fixed size, 10 s, at most 8 waiting, single use.
  - **Capture:** only after the bind, one picture per credit from an 8-unit / 512 KiB ack window.
  - **Input:** view-only gets no injector; control goes through `Tracked` and a 250/s bucket.
  - **Kill:** a watcher ends all media on any kill.
- `tornect host --capture desktop|test-card` shares X11 on an X11 session or GDI on Windows. On
  this Wayland VM it can share only the test card.
- `tornect connect` opens the media stream on the signaling circuit, decodes and acknowledges.
  It prints `MEDIA BOUND`, a progress line every 5 s, and `MEDIA OK|EMPTY`. A test card is checked
  frame by frame (`MEDIA CARD first=… last=… in-order`). `--no-video` keeps the old
  signaling-only session.
- **Verified live over real Tor** (two homes, `docs/notes/m1-media-evidence.md`):
  - 146 of 146 card pictures arrived in order with 0 decode errors, at 1280×720 and 6.3 fps;
  - the media stream opened about 1 s after the accept;
  - `tornect panic` ended media and session on both ends.

**Review of `efe75fa..510b6cb`** (KORE A′: 3 read-only threat modelers; the synthesis is at
`/home/mx/kore_project_V3/agents/security/reports/2026-09-21_tornect_slice_b_review.md`).
- Totals: 0 critical, 0 high, 4 medium; 106 candidates refuted.
- Fixed failing-first (M1-44): B1-2 ⊕ B2-1, B1-3 ⊕ B2-5, B1-1 and B1-4. B3-12 (a doc fix) too.
- **Open, the one medium left: B2-2.** A host whose store was locked at start has no control
  channel, and a Windows host never has one.
- The low findings are listed there with next steps. B2-7 (`yes` grants control) and B3-7 (an X11
  `u32` overflow) are one-line fixes.

**Not done, and honestly so:**
- **The frame rate over Tor is 6–7 fps.** The 8-unit window caps it at this RTT (M1-43 notes
  ~20 units for 15 fps), and it has not been tuned.
- **No Wayland capture** (next item). No GUI. No whole-app Windows build. No second machine.
- The live driver's final check failed on client wording only; that is fixed but not re-run live.
- Input over the media stream is wired host-side, but no client sends any yet (that is the GUI).
- `m1` is untagged, and CI has never run.

## Session 2026-09-22 (6) — the gate stops fighting cargo; two quick wins; a review that did not run

**The review of `510b6cb..5f1ae84` did NOT run.** Three read-only threat modelers were launched
first, on a frozen worktree at `5f1ae84`, and all three died within ~15 minutes on the account's
**weekly** usage limit, with no report written. That whole range — the `tornect-session` crate,
the CLI media path and the M1-44 fixes — is **unreviewed**. The frozen worktree
`/home/mx/tornect-review-slice-c` is kept for the re-launch; the limit resets 2026-09-24 17:00 -03.
Record: `/home/mx/kore_project_V3/agents/security/reports/2026-09-22_tornect_slice_c_review_NOT_RUN.md`.

**What landed** (decision M1-45; gate green at **428 tests**, cargo-deny ok):
- **The xtask environment fix.** `cargo()` removes the variables `cargo run` gave xtask before
  spawning cargo, so the gate, plain `cargo` and the pre-commit hook share fingerprints again:
  0.6 s and 0.3 s with nothing rebuilt, where the same switch used to cost 33 s and a `ring`
  rebuild. Two tests, one of which fails on the old `cargo()`. The whole gate is now 41 s.
  - One-time cost, already paid here: the first test-profile build after the fix rebuilt the Tor
    stack once, because those fingerprints had been recorded under the old environment.
- **B2-7:** `y`/`yes` at the session question no longer grants control (only `a`/`allow`, `v`/`view`).
- **B3-7:** the X11 grab sizes its buffer with checked `usize` arithmetic under a 2^27-pixel cap,
  before `GetImage`. The old `u32` product wrapped to **0** at 32768×32768, so an empty reply
  would have passed for a one-gigapixel picture; a debug build panicked on it instead.

**Not done:** B2-8 (it needs a silent-but-open host in the harness; today's app tests drive a real
`serve_host` over a duplex, which always reads), B2-2, Wayland capture, the frame-rate tuning and
the live re-run.

## Session 2026-09-22 (7) — the slice-C review ran; B2-2, two review mediums and B2-8 fixed

**Gate: green at 437 tests** (428 at the start), cargo-deny ok, 22–66 s. Everything is pushed.

- **The review of `510b6cb..5f1ae84` ran** (three read-only threat modelers on the frozen
  worktree, ≈ 0.91 M tokens, ≈ 21 min each): 0 critical, 0 high, 2 medium, 6 low, 13 info, 90
  candidates refuted. Synthesis and dispositions:
  `/home/mx/kore_project_V3/agents/security/reports/2026-09-22_tornect_slice_c_review.md`.
- **B2-2 (M1-46, `94255c2`).** `tornect host` holds `state/host.lock`. Its control channel is up
  even without a store, and then serves `tornect panic` only. No command runs offline beside a host
  that does not answer (one already running offline when the host started still could, until
  `d60df98` in session 8). The kill path the terminal names is always one that works. The real binary
  was checked in three situations: store locked at start, socket path unbindable, and normal.
- **C1-1 (M1-47, `326fd72`).** Reading a media `Bind` takes no slot, so squatting streams can no
  longer deny every session its picture.
- **C2-1 + B2-8 (M1-47, `65463d6`).**
  - Ctrl-C in `tornect connect` is heard on its own task, and a second press quits at once.
  - The viewer yields after every message.
  - `bye` gives up after 3 s (`timeouts::BYE`), and pings run to a fixed deadline (for M2 frames;
    host `PING`s still restarted the wait until `820c839` in session 8).
- **C1-5, C1-6, C3-4 (`2ee219c`).** The `i32::MIN` wheel delta is refused; `watch_kill` arms
  before it sweeps; `tornect panic` names its home.
- **Frame rate (M1-47, `7317e0d`).** `MediaLimits::window_frames` goes from 8 to 20. Over Tor that
  gave **13.2 and 13.0 fps** in two live runs, against 6.3 at 8, with 0 errors and the card in
  order.
- **The client's `BYE` could be lost (`c641ae6`).** In live run 1 the client shut Tor down right
  after a flushed `BYE`, and the host logged the end as `io`. `bye` now waits for the host's close,
  within 3 s.
- **Live media check, run 2: all 10 checks pass**, including `tornect panic` ending media and
  session and a clean host exit. The documented driver asked for 11 results from its 10 checks, so
  it could never say PASS; fixed.
- **A flake, fixed:** `a_bind_is_single_use` failed 2/25 under load. A vanished viewer can show
  up as a broken pipe on a frame write before the reader sees EOF, and the test now accepts
  either.

**Still open from the review (claims; the lows were all fixed in session 8, M1-49):**
- **Lows:**
  - C1-2: clicks are mapped over the whole desktop while the viewer sees a crop (B3-19 now live).
  - C1-3: a vanished viewer's held key stays down for up to 90 s.
  - C2-2 (b): a stalled viewer write delays the stop.
  - C3-1: the one-session gate is check-then-act across the accept write.
  - C3-2: `fail()` writes in `established()` are not raced against the kill.
  - C3-3: `$DISPLAY` can name a forwarded or remote X server.
- **Infos:** C1-4, C1-5 (b) (the input bucket counts frames, not OS events), C1-7, C2-3 to C2-7,
  C3-5, C3-7.

**Unreviewed by a hostile review:** everything after `5f1ae84`, including this session's fixes
(the range `5f1ae84..5ba8f11` was reviewed in session 8: slice D).

## Session 2026-09-22 (8) — Wayland capture live; the slice-D review; the slice-C lows and the slice-D fixes

**Gate: green at 480 passed, 0 failed, 4 ignored** (437 at the start, 458 after the Wayland
backend), cargo-deny ok. `5ba8f11..1e6966c` is pushed; `1e6966c..ad55279` and this hand-off were
local when it was written, for push 2.

- **Wayland capture and input (M1-48; `4451d14`, `6bf62c9`, `95a08a5`, `4c603a5`).**
  - `tornect-capture`'s `wayland` module: one RemoteDesktop portal session with ScreenCast
    sources, on a thread with its own runtime and zbus connection; PipeWire over `dlopen` with
    LP64 mirrors and the 232-byte EnumFormat pod; frames copied on damage (`Ok(None)` otherwise);
    input through the portal's `Notify*` calls, never `connect_to_eis`; the pointer mapped over the
    encoded region.
  - The restore token is kept in `<state>/portal-restore-token` (0600, never logged), so the
    desktop asks once. Deleting the file revokes the grant.
  - `tornect host --capture desktop` shares the Wayland desktop through the session layer.
  - No full Arti rebuild: the lock gained only `ashpd` and `libloading`. Tests 437 → 458.
- **Verified live on the build VM** (rows in `docs/VERIFICATION.md`):
  - **At the console**, portal check run 2: 3538×1919 at scale 1; a first picture of a still
    screen after 0.31 s, unprompted; five pointer moves, each followed by a new picture; 19 fps
    while dragging; the token kept. Run 1 was answered with the dialog's "Allow Remote
    Interaction" switch left off (it starts off), and the injector was refused as designed.
  - **Over real Tor**, two homes, the token restoring the session with no dialog: 3538×1918,
    0 errors, 2.7–3.1 fps at 6.8 MP. Capture alone reached 19 fps, so the software encoder is the
    likely limit, and downscaling before the encode is the lever. Run 2 passed all 10 checks;
    `tornect panic` closed PipeWire 62–100 ms and the portal session 90–172 ms after the kill.
    Run 1 labelled the media end `MEDIA FAILED: … Circuit closed` (fixed below; OPEN until a
    live run).
  - **No input crossed Tor**: `tornect connect` sends none, and no key was injected live at all.
- **The slice-D review of `5f1ae84..5ba8f11` ran in full** (62/62 agents, 8 finder
  dimensions and 3 refuters per raw finding, 47.8 min): 18 raw → 8 survived →
  **5 distinct defects, all LOW, no BLOCK**; 10 refuted. D1 was raised at MEDIUM and taken at LOW
  by the parent; **the operator ruled LOW**. D4 and D5 were ledger and plan drift, fixed by this
  hand-off. Its §10 addendum on the Wayland policy: keep the persisted grant, under three
  conditions (M1-48), and do not grow the waits. Synthesis:
  `/home/mx/kore_project_V3/agents/security/reports/2026-09-22_tornect_slice_d_review.md`.
- **Fixed, each code fix failing-first (M1-49; 21 commits `820c839` … `ad55279`; tests 458 → 480):**
  - D2 (`820c839`): host `PING`s no longer restart `next_event`'s wait.
  - D1 (`d60df98`): an offline command refuses its write once a host has started beside it.
  - D3 (`0fcb48b`): the C1-1 test holds every waiting slot.
  - C3-1 (`963f487`): the one-session slot is reserved in the same step as its check.
  - C3-2 (`d64bc87`): a violation ends the session before its `ERROR` is written.
  - C2-2 (b) (`5e323c1`): the viewer's writes race its stop.
  - C1-3 (`af7d956`): held keys are released after 3 s of silence, and **the viewer pings once a
    second when idle**; not while a picture or `Pong` write was stuck, until `04fd0c6` (slice-G
    G2-1).
  - C1-2 (`3b90cd2`): X11 and `SendInput` map the pointer over the encoded region (a mapping, not
    a refusal); the X11 half used the root size read at connect (slice-G G2-2), fixed in `9604760`.
  - C3-3 (`2ac8ffd`): a `DISPLAY` with a host part is refused.
  - C3-5 (`f769365`): doctor and the banner name the capture backend truthfully.
  - The media-end wording (`33ad8c9`, client side).
  - The §10 hardening: a pending portal open ends with its session (`82d1692`; an end that came
    before the open had stored its cancel was lost until `c285e98`, slice-G G1-1); a view-only
    session drops its input handle (`ea9db5d`); doctor names the grant file and how to revoke it
    (`73b87cb`); the token's path is out of log lines (`f9e96f5`; `remember_token`'s failures still
    named it until `08295b6`, slice-G G1-2).
  - The zbus warning filter (`3ad3473`); the R9, R5 ≡ R8 and R7 test tightenings (`1790746`,
    `9d6b4b2`, `6c0646b`); the O2 comment (`4009dbc`); R2: **the first Ctrl-C ends a pending
    media open** (`ad55279`).
- **Windows:** `cargo check --target x86_64-pc-windows-gnullvm -p tornect-session -p
  tornect-capture` is clean, 0 warnings (6 min; the first gnullvm check of the Arti stack here).
- **Operator rulings:** D1 is LOW; the store-less host keeps M1-46, and §B.8.6.2 now carries the
  note that such a host must be stopped (Ctrl-C or panic) before deny-direction commands run.

**Still open:**
- **C1-5 (b)** (INFO, on no list until now): the input bucket charges one token per frame, not per
  OS event; one wheel frame can make up to 400 XTest requests.
- Slice-C infos: C1-4 (X11 and `SendInput`; the Wayland injector bounds its own calls), C1-7,
  C2-3 to C2-7, C3-7.
- Left from the fixes: item 9's extras (an `SSH_CONNECTION` warning; the resolved display in the
  banner); gnullvm clippy on `tornect-session`; R7's other half (a control task that ends or is
  aborted leaves `control` up; only at shutdown today).
- OPEN: the media-end row until one live panic run; keys over Tor (the GUI); the first-run dialog
  during a remote session; C2-1 under a real flood; `SendInput` at run time (NEEDS-DEVICE).
- UNVERIFIED: GNOME dismissing the dialog on `Session.Close`; C1-3 at run time (XTest
  autorepeat, Arti's dead-circuit detection); `SystemBackend::view_only` (read, not tested); the
  first picture of a fully static screen; the runtime default of "Remember This Selection"; how a
  non-Flatpak token binds to the app id; whether zbus logs message bodies at trace level; O1 (a
  store-less host's untagged `sessions.log` lines) and the cross-process log race.
- Before unattended connects on Wayland: the §B.8.8 5 s dialog budget, no dialog without a valid
  token, and (M4) the block window and indicator.

**Unreviewed by a hostile review:** everything after `5ba8f11`, including `pipewire.rs`'s unsafe
FFI, the portal and token handling, the idle ping and this session's fixes. (Reviewed since: the
slice-G review of 2026-09-24 covered `5ba8f11..73e9314`; its outcome is in the last session's
"Still open".)

## Sessions 2026-09-23/24 — the window, the indicator, the Windows build, packaging, start at login; three reviews and their fixes; the pre-release prepared

**Gate: green at 634 passed, 0 failed, 5 ignored** at `681bc51` (480 at `ad55279`), cargo-deny ok against the
RustSec database `1931a145168d` of 2026-09-23. `origin/main` is `8df9123`; everything after it (`cfa7237` …
`681bc51` and the documentation commits of 2026-09-24) was local when this was written. **Not tagged.** The fifth
ignored test is the systemd round trip.

- **The window (M1-50; `d6ef5ba`, `ba811fc`, `c7129be`, `981f556`).** `tornect` with no subcommand opens a manual
  winit loop driving egui-winit and egui-wgpu: the home screen, inline pairing and session cards, the client's
  code card, the stream window with input by physical scancode (sent only for a control grant), the sharing
  banner, the first-run Wayland grant as a setup step, and a hidden `--preview`. `--no-host` makes a
  connect-only window.
- **The sharing indicator (M1-50; `9eb9e54`, `93a5d56`).** An always-on-top, undecorated window "Tornect:
  sharing" that opens without the focus, in the same process as the window; one row per shared session, with
  Stop. Its line puts the label last (E1-2), which departs from §B.8.7.3's word order.
- **The Windows build (M1-51; `cb46b4d`, `7bbb51c`, `b7ef5a9`, `fa92538`, `c3cc2e8`).** `result_large_err` fixed
  by boxing the TOML error; every C and C++ object built with the stack protector; libc++ linked statically, so
  `tornect.exe` imports only DLLs Windows ships (the first link needed `libc++.dll`); the 13 test binaries build.
  The `a14` flake (about 1 run in 300) fixed. Under Wine 10.0: `--version`, `id`, `doctor` and four test
  binaries pass.
- **pt-fetch, dist and B3-6 (M1-52; `95c96d7`, `acbc75d`, `bc4793e`, `3ca4094`).** lyrebird fetched, pinned and
  signature-checked; both zips from one clean commit, reproducible on this machine (two builds from scratch,
  bit-identical executables); the gate fails without cargo-deny. The Linux executable needs glibc 2.43 or newer.
- **Start at login (M1-53; `66c2442`, `b4e8dd4`, `176e9de`).** `tornect service install`, `uninstall` and `status`:
  a systemd user unit or a Task Scheduler task from XML, through the guard with OS re-authentication (polkit;
  CredUI's secure prompt and `LogonUserW` on Windows).
- **The slice-E review** of `73e9314..3ca4094` (a threat-model review without a refuter pass): 1 Medium, 11 Low, 6 Info
  plus P-1, no BLOCK. Fixed: **E1-1 ≡ E2-1** (the Medium: keys typed for another program answered a card) by the
  operator's "pointer-only Allow" (`746a628`), E1-6 (`9ca0496`), E1-4 and E1-3 (`a4d5f72`), E1-2 (`f9a1a3e`), E1-5's
  sentence (`7e9f2cc`), E2-3 (`a69a7d2`), E2-2's interim rule (`cfa7237`), E2-4 and P-2 (`82a618c`; PARTIAL without
  the linker flag), E2-7 (`4e6a42f`, its flaky test fixed in `081cc08` and `94d68a6`). E3-1 and E3-3 are met by
  `dist` and the gate.
- **The slice-F review** of `3ca4094..176e9de` (the same form): 2 Medium, 4 Low, 6 Info plus P-1 and P-2, no
  BLOCK. Fixed: **F2-1** (the Linux start-at-login host answers pings only, `2b5c4c8`), **F1-1** (a failed task query
  is never "not registered", `5227322`), F1-3 (`a93aeb2`), F2-2 with F1-4 and F2-6's characters (`8df9123`), F2-3
  (`6c9e512`), F2-4 (`61f2e40`, and the manual removal step `d2be07e`), F1-2 and F1-5 (`2171aed`), default 3 and N-2 in
  the README (`44944b7`), and the operator's `--elevated` refusal for a standard account (`c127a60`).
- **The fix-closure check** (phase 2a at `8df9123`: 13 of 13 claims closed, new N-1 LOW and N-2 INFO; phase 2b at
  `025da8c`: 9 of 11, E2-4 PARTIAL, new N-3 INFO and N-4 LOW) and **the release-preparation review** (phase 2c, four
  parts up to `b6897b7`: L-1, L-2 and Infos), no BLOCK anywhere. Fixed: N-1 (`2587bbe`), N-3 (`6a0eedb`), N-4
  (`8836cd8`), L-1 (`e24b6a0`), L-2 (`c6aed2f`), I-2 (`9628054`), I-3 (`42e12a7`), P2-I1 (`94d68a6`), P2-I2
  (`3cee64a`), P2-I3 (`b6897b7`), P2-I4 (`2cf4b04`), the build VM's host name out of the code (`4c66c47`) and the docs
  (`c4e3cf7` and the documentation commits of 2026-09-24). P3-I1 … P3-I3 are disclosed, not fixed.
- **The release preparation (M1-52).** `cargo deny fetch` (2026-09-24 03:01) moved the RustSec database from
  2026-08-29 to 2026-09-23, and the gate then failed on **RUSTSEC-2026-0285** (rustls 0.23.43): rustls 0.23.45
  (`1298bc6`). The database is named in the gate and in `BUILD-INFO.txt` (`0b020b9`, with its ignores `42e12a7` and
  the 7-day limit `9628054`); `THIRD_PARTY_LICENSES.txt` goes into each zip (`427499a`, `1150702`); `pt.rs:620`
  (`7aa8522`); `docs/RELEASING.md` (`8d05ae7`). A dist check run at `427499a` built both zips and passed the smoke
  tests (Wine with the home inside the profile); its zips were deleted.
- **Release verification at `b6897b7`:** the gate three times (633 / 0 / 5), the `tornect-signal` binary 40 of 40,
  Xvfb 59 passed, five failing-first spot checks, gnullvm clippy clean. **T-1** (LOW, test strength: the
  view-only mapping was pinned by no test) is fixed in `681bc51` (634 / 0 / 5).
- **Live on the build VM, 2026-09-24:** start at login with the debug build's re-auth escape (install; `systemctl
  --user start` as the login stand-in, whose journal shows the pings-only line; F2-3's refusal through the live
  control channel; a graceful stop; uninstall; nothing left enabled). The Windows release executable under Wine:
  33 imports and no `credui.dll`, `--version`, `id`, `doctor`, the E2-2 refusals.
- **The console check of the window over real Tor was NOT PERFORMED three times:** 2026-09-23 02:27–02:50 (at
  `981f556`) and 22:53–23:38 (at `a69a7d2`), 2026-09-24 01:14–01:20 (at `8df9123`, behind a 5-minute presence
  gate). Each time the windows were up and both hosts `REACHABLE`, and nobody was at the VM screen. Its polkit part
  was never reached.
- **Operator rulings:** decision M1-54 (each with its date).

**Still open:**
- The console check (the window over real Tor with a person at the screen, keys over Tor, the polkit path live).
- E2-4's load-time residual: the linker's dependent-load flag is set in `312748e`; the final `dist` checks
  `DependentLoadFlags: 0x800` on the release exe; the loader's effect NEEDS-DEVICE(windows).
- Everything at run time on Windows (NEEDS-DEVICE), and the Linux ↔ Windows session.
- Carried to M6 or later: E2-2's DACL, E2-5, E2-6, E2-8, E3-2, E3-4 (before 2026-10-26), E3-5, slice-E P-1
  (CFG/CET), F1-6, F2-5, F2-6's readiness, slice-F P-1, F1-2's residuals, N-2, N-3's extras (the trigger's
  `<UserId>`; only a SID or a qualified name as the principal), P3-I1 … P3-I3; the §B.8.7.3 indicator extras and
  the E1-5 badge; the unattended client CLI; the withdrawn-card questions (a withdrawn pairing card counts toward
  the temp-ban; a withdrawn session card answers `DENIED`, not `BUSY`); a held key on a Windows host types once
  (no key repeats are forwarded).
- Cosmetic: a long IPC refusal is cut at 256 characters mid-word; the pings-only host still prints its "sharing:
  this desktop …" line.
- **Reviewed 2026-09-24, slice G** (`5ba8f11..73e9314`: the Wayland backend, `pipewire.rs`'s unsafe FFI, the
  portal and token handling, the idle ping, the slice-D fixes; two threat modelers and the Security parent, no
  refuter pass): 0 Critical, 0 High, 0 Medium, **six Lows, all fixed**: G1-2 `08295b6`, G1-1 `c285e98`, G1-3
  `4448c58` (test `c02ae7a`), G2-1 `04fd0c6`, G1-4 `9d9442e` + `04ae195`, G2-2 `9604760`; one Info, G2-3 (the 3 s
  quiet release can let go of a live viewer's drag in a Tor stall; disclosed in the notes). The closure check's
  round 1 verified G1-2, G1-1 and G1-3 closed and filed an Info (its N-2, the order of owed releases: fixed in
  `72d9a76`). Round 2 (no BLOCK, nothing above Low open) verified G2-1, G1-4 and G2-2 closed in code (G2-2's live
  RandR change NEEDS-DEVICE(x11)), found `9d9442e` and `c02ae7a` sound, and found the two fixes from the fifth
  console check sound on the security side: the code card that outlives the host's wait (`a98733c`, decision M1-55)
  and the host's `PairedOnly` on a timeout after its accept (`54dbe3b`, `fsm/host.rs:883-889`, an outcome label
  only). Its one Info, R2-I1 (a late yes read "Paired" whatever the error), is fixed in `8ee5afc`.
- The slice-G live and device items: G2-1 over real Tor (a vanished viewer's held key, timed), the quiet release
  and G1-4's releases through the Wayland portal, whether GNOME lets go of a RemoteDesktop session's held keys and
  dismisses its dialog on `Session.Close`, `Closed` on "Stop sharing" and screen lock, G2-2 with a real RandR change
  (NEEDS-DEVICE(x11)), and how often onion circuits stall for 3 s or more (G2-3).
- **Unreviewed by a hostile review:** `8ee5afc` (R2-I1's fix) and the documentation commits after `b6897b7` (round 1
  read `e278bfb`).

## Gotchas (the build VM)

- **The gate/plain-`cargo` rebuild ping-pong is fixed** (M1-45, 2026-09-22). `cargo xtask` runs
  through `cargo run`, which put `CARGO_PKG_NAME`, `CARGO_MANIFEST_DIR` and the rest into xtask's
  environment; `ring`'s build script watches exactly those (`rerun-if-env-changed`), so every
  switch between the gate and a plain `cargo` (or the pre-commit hook) re-ran `ring` and rebuilt
  everything above it. `xtask`'s `cargo()` now strips them — **if it ever comes back, look there
  first.** It was not the whole story, though: `cargo test -p <crate>` and
  `cargo test --workspace --lib` still select a different dev-dependency set, which re-unifies
  features and rebuilds the Tor stack (session 8: 1.8 GB of `deps` before it was stopped). Run
  filtered tests as `cargo test --workspace -- <filter>`, and ignored ones as
  `cargo test --workspace -- --ignored <filter>`.
- Build with `TMPDIR=$PWD/target/tmp`; `/tmp` is a 3.7 GiB quota tmpfs (zstd-sys fails there);
  Tor state under `target/tornect-test/<name>`, never `/tmp`. **systemd-oomd kills the terminal's whole
  process group under memory pressure** (twice on 2026-09-23): run every heavy cargo command in its
  own scope, `systemd-run --user --scope --quiet -- env CARGO_BUILD_JOBS=2 TMPDIR=$PWD/target/tmp cargo …`.
- The gate's advisory check is offline: fetch the RustSec database first
  (`target/tools/cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny fetch`, network). The gate and
  `dist` refuse two database copies (L-2), and `dist` one older than 7 days.
- For the Windows target, lint with `--workspace` (`-p tornect --all-targets` alone fails: `start_paused`
  needs tokio's `test-util`, which only the workspace build unifies), with llvm-mingw's `bin` on `PATH`.
  nasm 3.01 is installed since 2026-09-23, so OpenH264's x86 assembly is built on both targets.
- Under Wine a `--home` must lie inside the Wine user's profile (E2-2): `wine cmd /v:on /c 'tornect.exe
  --home %USERPROFILE%\<dir> id & echo exit !ERRORLEVEL!'` (`%ERRORLEVEL%` would be read before the
  command runs).
- A console check with the operator needs presence first: one visible action on the VM's screen,
  watched for within a few minutes (the first-run grant counts). A remote answer does not prove presence at
  the VM screen, and three attempts ended with nobody at it.
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
- The GNOME portal dialog's "Allow Remote Interaction" switch starts **off**: whoever answers it
  must turn it on, or the host shares the screen and injects nothing. The kept token
  (`<state>/portal-restore-token`) spares later dialogs; delete it to revoke the grant. The portal
  needs the console session's environment (`XDG_RUNTIME_DIR`, `WAYLAND_DISPLAY`,
  `DBUS_SESSION_BUS_ADDRESS`, `XDG_SESSION_TYPE=wayland`).
- Never run an injection test against `DISPLAY=:0` here (the live Xwayland): the X11 input test
  runs only with `XDG_SESSION_TYPE=x11`, under Xvfb.
- Disk: 89 % (11 G free) on 2026-09-24. `target/debug/incremental` is safe to delete and regrows
  (3–9 G each time); `target/dist/cargo` (dist's build cache, 5.6 G) makes the next dist take seconds and
  is safe to delete; never prune `target/debug/deps` by atime.
