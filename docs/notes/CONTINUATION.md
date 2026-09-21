# Tornect — continuation report (2026-09-21, third session close)

Paste the block under **HAND-OFF** into a new session.

---

## HAND-OFF

Continue building Tornect from `/home/mx/Tornect` (private repo
https://github.com/Mxrider420z/Tornect, branch `main`, **committed at `34f4723`, NOT yet
pushed** — `51458f7` is what the remote has).

The operator's goal for this run:
- **A functional app on Linux and Windows.** The operator will test with one Linux and one
  Windows machine.
- **Tor with automatic obfs4 bridges when Tor is blocked, and Snowflake when obfs4 fails.**
- **The code cross-compiling for Windows.**

Scope ruling (operator, 2026-09-21): **"vertical slice first"**. That means a real Linux↔Windows
remote session end to end: Tor transport, software H.264, one capture and input backend per OS,
a minimal egui window with the consent popup, the sharing indicator and the kill switch, a
cross-built Windows binary, and packaged zips. QUIC hole punching is deferred, and m2–m6 stay
untagged until their full acceptance runs.

Read in this order before doing anything:
1. `CLAUDE.md`
2. this file
3. `docs/notes/m1-state.md` (§ *Session 2026-09-21 (3)*)
4. `docs/research/slice.md`
5. `docs/notes/decisions.md` M1-38 … M1-41 and M3-1
6. the slice review
   `/home/mx/kore_project_V3/agents/security/reports/2026-09-21_tornect_slice_review.md`

Then run `CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo xtask verify`. Expect **370 tests**
and `cargo deny check (offline; advisory DB 2026-08-29)` ok.

### ⚠ START HERE: one operator decision is blocking the critical path

`serve_host` is **still not wired into `tornect host`** — not for lack of the seams, which are
now in place, but because wiring it changes what the signaling port speaks and the operator was
asked to choose and ended the session first. **Get this answer, then the wiring is
straightforward.**

The FSM requires pairing (SAS on both ends) before a session, so today's zero-setup
`tornect ping` liveness check cannot survive unchanged. The options put to the operator:

| # | Option | What it means |
|---|---|---|
| 1 | **Keep ping, add `tornect connect`** (recommended) | The host answers both, dispatching on the first frame — ping frames start with the magic `TORNECT-PING/1`, FSM frames are CBOR envelopes, so the dispatch is ~10 lines. `tornect ping <id>` keeps working with no pairing, so on the two-machine test a Tor problem can be told apart from a pairing problem. A new `tornect connect <id>` drives the real FSM: pair → SAS → host consent → session `PING`s. `CLAUDE.md`'s command list and the M1 acceptance recipe stay intact. |
| 2 | FSM only, migrate `tornect ping` | The signaling port speaks only the handshake FSM; `tornect ping` becomes an FSM client and needs pairing plus a consent prompt on the host. Smaller surface, and it retires the interim protocol the way `ping.rs`'s own doc intends — but the zero-setup reachability check is gone and `docs/VERIFICATION.md` rows churn mid-slice. |
| 3 | FSM only, drop `tornect ping` | Replace it outright with `tornect connect`. Cleanest end state, most doc churn now, no simple liveness check while capture/session/GUI are missing. |

**Why 1 is recommended:** the app is still not functional end to end, so the operator's next
real activity is a two-machine bring-up. A liveness check that does not need pairing is the
cheapest way to isolate "is Tor reachable?" from "is pairing working?", and option 1 keeps it
for ~10 lines that are deleted later.

### STATE (2026-09-21, third session)

Pushed commits: none this session. **Local commits ahead of `origin/main`:**

| Commit | What |
|---|---|
| `94dfe64` | `fix(signal)`: the kill switch is per-session and no longer latches |
| `34f4723` | `feat(signal)`: the `SessionSink` seam on the host FSM |

1. **`KillSwitch` latch: FIXED (`94dfe64`).** This was the blocker the previous hand-off put
   ahead of `serve_host`.
   - It held one `watch<Option<u16>>` for the host's lifetime, so the first kill left
     `Some(reason)` in the channel for good. `established()` polls it first in a biased
     `select!`, so **every session accepted after a master-off, revoke-all, panic key or
     emergency stop was sent `BYE` and closed on entry** — one kill disabled hosting until the
     process restarted.
   - The switch now carries a **generation counter** beside the reason. A stream snapshots it
     in `serve_host` **at accept time** (`KillSwitch::arm`) and its `KillGuard` fires only for a
     kill with a newer generation.
   - Arming at accept rather than in `established()` is deliberate: a kill fired *during* a
     handshake still ends that session, so the panic key stays effective against a session that
     has not reached `Established` yet.
   - Refusing *new* access after a master-off or emergency stop remains the grant store's job
     (the master switch and revoked grants make `UnattendedAuth` reject; attended sessions still
     need the consent popup), so dropping the latch does **not** widen what the host accepts.
   - `fired()` still reports the most recent reason for status and tests.
   - Failing-first verified: on the old code the regression test fails with
     `host answers ping, not BYE on entry: Frame(Io(Kind(BrokenPipe)))`.
2. **`SessionSink` seam: ADDED (`34f4723`).** `HostDeps` gained `sessions: Arc<dyn SessionSink>`.
   - `on_start(&LiveSession)` fires once `SESSION_ACCEPT` is sent and `th_final` is fixed — the
     first point §B.6 allows capture to begin. It carries device, label, session id, **session
     token** (what the media layer derives the `Bind` key from, M1-41), `th_final`, mode and
     `unattended`.
   - `on_end(session_id, Option<&SessionEnd>)` fires as soon as `established` returns and
     **before the error is propagated**, so a session ending in a protocol error still releases
     what the sink acquired. **Every `on_start` is followed by exactly one `on_end`** — a sink
     may treat the pair as acquire/release for capture.
   - `NoSessionSink` is the default, so M1 behaviour is unchanged: nothing runs a session yet.
   - The test asserts the pairing and that the sink gets the same `th_final` **and session
     token the client holds** (both verified equal across the two sides).
3. **Unchanged from the previous hand-off:** track D closed (`5523fcc`); the slice review
   (`7697823..efe75fa`, A′, 0 critical / 0 high) and its fixes `38c8de5`, `c868e71`, `110b774`,
   `81da800`; bridges live-verified (direct 14.3 s, obfs4 78.2 s, Snowflake 16.2 s cold); media
   port 4001 and `connect_on`; the `tornect-proto` / `tornect-input` / `tornect-codec` crates;
   the Windows cross-build route (llvm-mingw 20260908, `x86_64-pc-windows-gnullvm`, OpenH264's
   C++ links).

### NEXT, in order

1. **Answer the decision above, then wire `serve_host` into `tornect host`.** Everything else
   is ready for it. The accept loop is `run_host` in `apps/tornect/src/tor_cmd.rs` (it currently
   calls `ping::serve` on `SIGNALING_PORT`). Seams and where the real implementations live:
   - `signer` = the `HostIdentity` (`impl HostSigner for HostIdentity`, `transcript.rs:127`)
   - `trusted` = the real `TrustedDeviceStore`
   - `consent` = a CLI prompt — `Consent::pairing` (peer + SAS → Allow/label/Deny) and
     `Consent::session` (peer + summary → Allow once / view-only / Deny), `pairing.rs:167`
   - `stop_token` = `EmergencyStop::new(guard, kill)`
   - `unattended` = `UnattendedAuth::new(limiter, tz, host_transport)` `.with_admin(GuardAdmin::new(guard))`
   - `audit` = `HostAudit::new(log)`
   - `sessions` = the new `SessionSink`
   - `activity` = whether a session is live (drive it from the sink; it gates the BUSY rejects)
   - `kill` = **shared with the IPC `HostContext`** — `host_context()` in
     `apps/tornect/src/unattended.rs:572`, whose own doc says it "gains `kill` — and with it a
     working `Panic` — when the host FSM is wired into `tornect host`". **Until this is done the
     panic key and IPC `Panic` still do nothing to live sessions.**
   - Note `HostDeps` has **no struct literals** outside its own definition; everything goes
     through `HostDeps::headless(...)` and then assigns fields, so adding seams is cheap.
   - Client side: `connect` → `send_tor_fallback` → `connect_on(MEDIA_PORT, same Isolation)` →
     `Bind`, then keep signaling alive with `PING`s (host idle timeout 90 s).
2. **`tornect-capture`:**
   - a `VideoSource` trait (blocking `next_frame`, tight BGRx), plus a synthetic test card;
   - X11: GetImage + XFIXES cursor;
   - Wayland: one RemoteDesktop portal session with ScreenCast sources (`ashpd`), PipeWire via
     **dlopen**. The layouts and the 232-byte EnumFormat pod are in `docs/research/slice.md` §4;
     Mutter offers only BGRx/BGRA; always requeue buffers. The portal session also yields the
     input sink.
   - Windows: GDI `BitBlt`.
3. **`tornect-session`.** It must meet the review's requirements (SLICE-A2 A2-3/A2-4/A2-6, A1 G3):
   - the view-only gate before `Input` is even decoded;
   - single-use `Bind` with a deadline;
   - one media stream per session;
   - an input rate cap and a bounded ack window (~8 frames / 512 KiB);
   - the viewer sizes from `DecodedFrame`, never from `BindOk`;
   - release-all at session end;
   - `KeyframeRequest` on a decode error.
   - `SessionSink::on_start` / `on_end` is the seam this hangs off; the acquire/release pairing
     is guaranteed, so capture start/stop can be tied to it directly.
4. **GUI:** a manual winit loop + egui (`slice.md` §2), containing:
   - the ID and Tor status;
   - a connect field;
   - the client SAS confirm;
   - the **host consent popup (Allow / View-only / Deny)**;
   - a persistent **"screen is being shared with X" banner with Stop**;
   - the viewer, with keys by physical scancode.
5. **Windows build of the whole app.**
   - First fix the pre-existing Windows-only `clippy::result_large_err` in `tornect-core`: 88
     errors on gnullvm, because `GuardError`/`StoreError` are large there. The gate lints only
     the host target, so this has gone unnoticed.
   - Arti's ring, bundled SQLite and zstd on gnullvm are untested.
   - Try `CXXFLAGS_x86_64_pc_windows_gnullvm=-fstack-protector-strong` for OpenH264 (SLICE-A3 F4)
     and check that it links.
6. **`xtask pt-fetch` and `xtask dist`:**
   - `pt-fetch` implements `packaging/pt/SOURCES.md`: download, gpgv, member hash.
   - `dist` produces a Linux tarball and a Windows zip containing `lyrebird(.exe)`,
     `lyrebird.txt`, `THIRD_PARTY_NOTICES.md` and a README.
   - Pin toolchain hashes, and set `LZMA_API_STATIC=1` (SLICE-A3 F7).
7. **Security review of the slice diff.** Launch it as soon as the diff is frozen, and **ask the
   operator whether to run it at full size**: the refuted review is about 100 agents; the last
   one ran as A′ because that size was not approved. Then hand the operator the two packages
   with a test recipe.

### STILL OPEN / UNTESTED (do not mark these done)

- **Still open from the 2026-09-05 hand-off:**
  - the §B.8.15 A14 core-dump sweep;
  - the §B.8.5.2 per-minute and host-wide caps;
  - plan r7 (M1-31/M1-32);
  - the EFF word list;
  - `mlock`/`VirtualLock`;
  - the keyring canary;
  - `tests/integration` (missing);
  - the polkit policy install;
  - CI has never run.
- **Needs a device, or open:**
  - the fallback under real censorship;
  - onion-service hosting over bridges;
  - lyrebird's console behaviour on Windows;
  - polkit over SSH with `pkttyagent` (new row in `docs/VERIFICATION.md`).
- **Review items left for later:**
  - A1-8: `config show` and derived `Debug` print bridge lines.
  - A2-1: in-process OpenH264 decode of host-supplied video (sandbox at a later milestone).
  - F5: `multiple-versions = "deny"` policy.
  - F9/F10: read the Arti 0.46.0 and rustls 0.23.44/45 notes before tagging.
- **S9 residual:** zxcvbn still scores "Laptop-of-Ana tornect 2026" at 4, even with the label.
- **No capture, no session, no GUI yet: the app is not functional end to end.**
- **The panic key and IPC `Panic` still do not end live sessions** — they will once `kill` is
  shared with `host_context` in step 1. The latch fix removed the bug that made a *second*
  session impossible after one kill; it did not by itself connect the kill to the host.

### GOTCHAS

- **The gate now runs cargo-deny.** If `target/` is ever cleaned, `target/tools/` goes with it,
  and the step then says SKIPPED; restore the prebuilt binary (cargo-deny 0.20.2 musl).
- **Gate failures surface late and in order:** plan-sync → forbidden deps → cargo-deny → fmt →
  clippy → test → doc. This session lost two full runs to a `fmt` break and a `clippy` break
  that a `cargo check` had not shown. Run `cargo fmt --all` and
  `cargo clippy -p <crate> --all-targets -- -D warnings` before the gate.
  - Two clippy lints hit new code here: `collapsible_if` (use a let-chain — edition 2024) and
    `type_complexity` (a 5-tuple in a test recorder; use a named struct).
- **Disk:**
  - The root disk is at 89 % with ~12 G free. `target/debug/deps` holds ~22 G of stale
    artifacts.
  - Deleting artifacts by atime is **unsafe**: a missing proc-macro or low-level artifact makes
    cargo rebuild everything above it.
- **Per-package test runs rebuild.** `cargo test -p <crate>` rebuilds the tokio/rustls/Arti
  stack under a different feature unification (~2 min here); prefer `--workspace` or the gate.
- **`.githooks` is active** (`core.hooksPath`), so every commit runs fmt + clippy (~30 s).
- rustdoc fails on a public doc linking to a `pub` item of a private module unless it is
  re-exported (`tor::bridges::LYREBIRD_SHA256`).

### PENDING USER ACTIONS

These are unchanged:
- Grant the `gh` token the `workflow` scope, then push CI.
- Create `.claude/settings.json`.
- Decide on the `framing` fuzz corpus.
- Arrange a second machine.
- Install the polkit policy.

Carried: decide whether `tornect host` should *refuse* Snowflake rather than warn (A1-7).
Snowflake volunteer proxies learn the host's IP, but refusing it breaks hosting where obfs4 is
blocked.

**New and blocking:** the ping-vs-FSM decision at the top of this file.

**Also new:** these two commits are **not pushed**. `git push` when you want them on the remote.

Work autonomously per the CLAUDE.md ground rules. Commits carry **no AI references**. End the
session with this same kind of report plus memory, Part G and `docs/notes/m1-state.md` updates.

---

## What this session did

- Resumed at `51458f7` with the KORE V3 MODE B bootstrap; structure verified by check
  (PASS, 0 defects, 34/34 definition checksums identical), registry empty.
- Fixed the `KillSwitch` latch — the item the previous hand-off named as the prerequisite for
  `serve_host` — and proved the regression test fails on the old code before fixing it.
- Added the `SessionSink` seam so `serve_host` has somewhere to hand a live session, with the
  acquire/release guarantee the capture layer needs.
- Ran the full gate to green three times (370 tests, cargo-deny ok).
- Stopped at the ping-vs-FSM decision rather than guessing, because it changes the operator's
  own two-machine test recipe.

**Honest limits:**
- **`serve_host` is still not wired into `tornect host`.** That remains the critical path, and
  it is now blocked only on the decision above.
- The app is **not yet functional end to end**: no capture, no session layer, no GUI.
- The whole Windows binary has not been built. `m1` is not tagged. CI has still never run.
- Nothing was pushed this session.
- No live-Tor run was performed this session; the changes are covered by the FSM's in-process
  duplex tests, not by a new over-Tor exercise.
