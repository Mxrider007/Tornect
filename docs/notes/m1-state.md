# M1 state — signaling over Tor (hand-off, 2026-09-04)

Milestone 1 is **most of the way done**: track 1 (Arti embedding), phase-2 part 1 (tracks A + B),
track C (the unattended PAKE branch) and now track D (CLI / IPC / `tornect-platform`) are
implemented and green at 320 tests. Track E (the adversarial + fuzz sweep), the milestone
`security-reviewer` close and the live verification over real Tor are **not done**, and `m1` is
**not** tagged.

**The largest remaining gap, which earlier hand-offs did not name:** `serve_host` — the §B.8.4.5
host FSM that tracks A, B and C built — **is not wired into `tornect host`**, which still serves
only the interim ping protocol of track 1. Every unattended test to date drives the FSM
in process. Until the CLI hosts it, the §B.8.14 M1 acceptance ("headless unattended handshake
ending in `SESSION_ACCEPT` … between two machines") cannot be demonstrated end to end over Tor,
however green the in-process suite is. Seam list in *Still open* below.

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
4. **Wire `serve_host` into `tornect host`** — not previously listed, and now the critical path
   to the M1 acceptance. The seams to fill: `HostDeps::unattended` = `UnattendedAuth` (with
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
or be reset, when `serve_host` is wired.

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
