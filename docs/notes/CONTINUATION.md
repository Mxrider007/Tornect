# Tornect — continuation report (2026-09-05, session close)

Paste the block under **HAND-OFF** into a new session.

---

## HAND-OFF

Continue building Tornect from `/home/mx/Tornect` (private repo
https://github.com/Mxrider420z/Tornect, branch `main`, tree clean, pushed).

Read in this order before doing anything: `CLAUDE.md`, `docs/notes/m1-state.md`,
`docs/PLAN.md` Part G, then §B.8.4.1, §B.8.4.2 and §B.8.7.4 (normative for the
work in flight). Then run
`CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo xtask verify` to confirm green
(expect **320 tests**: 153 core + 145 signal + 12 platform + 10 app).

### STATE (2026-09-05)

Commits this session, all pushed:
`fbc7a31` (admin intent + emergency stop + the B.8.4.2 ordering fix) →
`be58ea6` (tornect-platform: IPC endpoint + polkit reauth; OPAQUE registration
split) → `48ca97e` (the unattended CLI + host-role IPC dispatch) → `ee20242`
(docs) → the plan resync.

- M0 done, tagged `m0`. **M1 is most of the way done and NOT tagged.**
- Tracks 1, A, B, C were done in earlier sessions. **Track D is done this
  session** — see `docs/notes/m1-state.md` § *Track D*.

**What track D delivered.** Admin intent + scope (the §B.8.4.1 matrix was
already in `MutationGuard::admin`; this wired it through a new `AdminAuthority`
seam, with `RefuseAdmin` as the default so an unwired host refuses rather than
pretending). The §B.8.7.4 emergency stop (`EmergencyStop` implementing
`StopTokenCheck`: constant-time match → master off + revoke-all +
`BYE{EMERGENCY_STOP}` + token cleared, so the card is single-use; a failed apply
leaves the token in place). `crates/tornect-platform`, which did not exist:
`ipc` (owner-only Unix endpoint; `SO_PEERCRED` compared against the uid owning
the socket file this process created, which needs no `libc` and keeps the crate
`forbid(unsafe_code)`) and `reauth` (polkit over the system D-Bus). The
`tornect unattended|devices|panic|service|backup` CLI and the host-role dispatch
loop, with **one dispatch behind both routes** — over the socket when a host is
running, in-process against the same guard when not.

**One real defect found and fixed.** The admin branch ran *after* `post_f2`, so
§B.8.4.2's "schedule · readiness · transport · busy · concurrency gates skipped
for an admin request" did not hold: a grant whose schedule window was shut, or
whose reconnect cooldown was running, answered
`SESSION_REJECT{OUTSIDE_SCHEDULE}` instead of executing — and the commands
affected are `revoke`, `revoke_all`, `master_off`, `end_session`, the ones
reached for in an emergency. `admin_runs_even_when_the_schedule_window_is_shut`
fails against the pre-fix ordering (verified by reverting the branch: reject 33).

**Research that corrected the plan.** PAM was never the blocker: polkit runs the
PAM conversation itself, out of process, in setuid `polkit-agent-helper-1`, so a
direct PAM backend is redundant *and* unbuildable here. §B.8.8, §B.8.14's M1 row
and the Ownership paragraph were amended. Also: an unprivileged caller may not
pass a `details` map to `CheckAuthorization` at all (polkit refuses the whole
call), so the operation name cannot reach the dialog as data — hence five action
ids by operation class; `unix-session` crashes polkitd 127 (reproduced twice)
and `unix-process` carries the CVE-2017-7572 race, so the subject is
`system-bus-name`; "a fresh dialog per operation" rests on `auth_self` in the
shipped policy file, not on the client's `ALWAYS_CHECK` flag. Full record:
`kore_project_V3/agents/devops/reports/sub/2026-09-04_SUB_RESEARCH_VERIFIER_reauth_ipc.md`,
synthesised in `agents/devops/reports/dependency_status.md`.

### NEXT, in order

1. **Wire `serve_host` into `tornect host`.** This is the critical path and
   earlier hand-offs did not name it: `tornect host` still serves only the
   interim ping protocol of track 1, so the §B.8.14 M1 acceptance ("headless
   unattended handshake ending in `SESSION_ACCEPT` … between two machines")
   cannot be demonstrated over Tor however green the in-process suite is. Seams
   to fill: `HostDeps::unattended` = `UnattendedAuth::new(..)
   .with_admin_authority(Arc::new(GuardAdmin::new(guard)))`,
   `HostDeps::stop_token` = `EmergencyStop::new(guard, kill)`,
   `HostDeps::audit` = `fsm::HostAudit::new(Arc<SessionLog>)`,
   `HostDeps::trusted` = the real `TrustedDeviceStore`, `HostDeps::consent` = a
   CLI prompt, and **`HostDeps::kill` shared with the IPC `HostContext`** so
   `tornect panic` and a remote `master_off` reach live handshakes (today
   `HostContext.kill` is `None` and both say so honestly). Also: send
   `TOR_FALLBACK{}` after the accept or set `orphan_timeout = None`; stop
   `rotate-id` appending its own `HostIdRotated` once it goes through the guard;
   wire `ServerKeyPin` to the real `hosts.toml` on the client side.
2. **`tests/integration`** — listed as an M1 workspace member in both
   `CLAUDE.md` and the §B.8.14 M1 row, and it does not exist. The §B.8.15
   adversarial rows currently live inside the crates' own test modules.
3. **Track E** — the adversarial + fuzz sweep, then the `security-reviewer`
   milestone close, then **live verification** (pair + attended + unattended
   over real Tor, two `TORNECT_HOME` instances), then tag `m1`.
4. Then **u1** (UI plan U0+U1), then M2.

### THE TRACK D REVIEW HAS NOT RUN — DO IT FIRST

A six-dimension hostile review of `5ea5b22..HEAD` (3 725 added lines) was
launched and **every agent died on a usage limit before doing any work**. The
workflow returned `raw: 0, confirmed: []`. **That is not a clean bill of
health — it is no review at all.** The script is preserved and re-runnable:

```
Workflow({scriptPath: '<scratchpad>/review_run.js', args: {range: '5ea5b22..HEAD'}})
```

Its six dimensions are admin scope, the emergency stop, the IPC endpoint, the
polkit backend, the OPAQUE registration split, and secrets/spec conformance,
each finding attacked by three perspective-diverse refuters. Re-run it against
the range that includes whatever lands next. Budget ~1.5–2 h; concurrency on
this box is 2.

### STILL OPEN / UNTESTED (do not mark these done)

- Everything the previous hand-off listed is still open: the §B.8.15 **A14
  core-dump sweep**, §B.8.5.2's **per-minute and host-wide caps**, plan **r7**
  (decisions M1-31 / M1-32), the EFF word list (M8), `mlock`/`VirtualLock` (M6),
  the keyring canary (M6).
- **Three new NEEDS-DEVICE / OPEN rows** in `docs/VERIFICATION.md`: the IPC
  foreign-uid rejection has no second account on this machine to test with; the
  polkit *grant* path needs the policy file installed once as root
  (`sudo install -m 0644 packaging/polkit/org.tornect.policy
  /usr/share/polkit-1/actions/ && sudo systemctl restart polkit`, then
  `cargo test -p tornect-platform -- --ignored live_polkit`); `tornect panic`
  cannot end sessions until item 1 above is done.
- Autostart install/uninstall (M6) and backup export/import (M8) authorise
  through the guard and log, then report that nothing was applied.
- The Windows named-pipe endpoint returns `Unsupported`: §B.8.7.4's owner-only
  DACL, `PIPE_REJECT_REMOTE_CLIENTS` and client-SID check need a Win32 binding
  that cannot be verified here, and §B.8.14 puts it at M6.

### TWO JUDGEMENT CALLS, EASILY REVERSED

Both were made without a spec instruction and flagged to the operator:

1. **Five polkit action ids by operation class** (grant / enable / autostart /
   export / settings) rather than one fixed message or ~15 ids. One file plus
   one match arm to change.
2. **The emergency stop card travels in a new `MasterOnPayload`**, not in
   `IpcResponse.detail` — `detail` is a human-readable string that reaches logs
   and error messages, and this is a 16-byte secret. Schema-additive.

### GOTCHAS

Everything in the previous hand-off still applies. Additions:

- **`docs/PLAN.md` and `TORNECT_PLAN.md` must stay byte-identical** —
  `cargo xtask verify` compares them. Editing only one fails the gate; this
  session hit it.
- The workspace lints deny `print_stderr` **in tests too**; a test that prints
  diagnostics needs `#[allow(clippy::print_stderr)]` on the module.
- `cargo doc` runs with `-D warnings`, so an intra-doc link to an item that is
  not in scope at that path (inside a `mod imp`, or a renamed function) fails
  the gate after everything else has passed. Cheap to check early:
  `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`.
- Changing the workspace `Cargo.toml` forces a full rebuild of the Arti tree —
  about 15 minutes here. Batch dependency changes.
- Disk: cleaned `target/debug/incremental` (9.9 G) and `target/doc` mid-session;
  ended at 82 % with 18 G free.

### PENDING USER ACTIONS

Unchanged from the previous hand-off (CI has still never run; `.claude/settings.json`;
the `framing` fuzz corpus; a second machine), plus:

5. `sudo install -m 0644 packaging/polkit/org.tornect.policy
   /usr/share/polkit-1/actions/org.tornect.policy && sudo systemctl restart polkit`
   — until then every access-increasing operation refuses with "polkit action …
   is not registered", which is fail-closed and loud but not usable. The
   debug-build escape `TORNECT_DEV_REAUTH=allow` is the development workaround.

Work autonomously per the CLAUDE.md ground rules (verify like hostile QA, never
start M(n+1) with M(n) red, `security-reviewer` at milestone close). Commits
carry **no AI references**. End the session with this same kind of report plus
memory, Part G and `docs/notes/m1-state.md` updates.

---

## What this session did

Finished track D. Found and fixed one real protocol defect (the admin-intent
ordering against §B.8.4.2) with a mutation-verified regression. Created
`crates/tornect-platform` with an owner-only IPC endpoint and a polkit re-auth
backend proven against live polkitd 127, not mocked. Split the OPAQUE
registration so the password stays on the CLI side. Built the whole
`tornect unattended` surface with one dispatch behind both the socket and
offline routes, and exercised it by hand — including a pty-driven `grant` that
refused a weak password twice and then created a real grant whose stored record
a real `HostLogin` can open. Corrected the plan's "PAM/polkit" wording and added
18 verification rows, three of them deliberately not VERIFIED.

**Honest limits:** `m1` is not tagged; **the track D review never ran** (usage
limit, zero agents completed); `serve_host` is still not wired into
`tornect host`, so no unattended session has ever crossed real Tor;
`tests/integration` does not exist; track E is untouched; CI has still never run.
