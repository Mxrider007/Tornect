# Tornect — continuation report (2026-09-21, fourth session close)

Paste the block under **HAND-OFF** into a new session.

---

## HAND-OFF

Continue building Tornect from `/home/mx/Tornect` (private repo
https://github.com/Mxrider420z/Tornect, branch `main`). Everything is committed and **pushed**:
`origin/main` = `main` at this hand-off's commit.

The operator's goal for this run:
- **A functional app on Linux and Windows.** The operator will test with one Linux and one
  Windows machine.
- **Tor with automatic obfs4 bridges when Tor is blocked, and Snowflake when obfs4 fails.**
- **The code cross-compiling for Windows.**

Scope ruling (operator, 2026-09-21): **"vertical slice first"** — a real Linux↔Windows remote
session end to end: Tor transport, software H.264, one capture and input backend per OS, a
minimal egui window with the consent popup, the sharing indicator and the kill switch, a
cross-built Windows binary, and packaged zips. QUIC hole punching is deferred; m2–m6 stay
untagged until their full acceptance runs.

Read in this order before doing anything:
1. `CLAUDE.md`
2. this file
3. `docs/notes/m1-state.md` (§ *Session 2026-09-21 (4)*)
4. `docs/research/slice.md` — **§4 is the next piece of work**
5. `docs/notes/decisions.md` M1-38 … M1-42 and M3-1
6. `docs/notes/m1-serve-host-evidence.md` — how the live two-home Tor check runs (driver script
   in its appendix)

Then run `CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo xtask verify`. Expect **396 tests**
and `cargo deny check (offline; advisory DB 2026-08-29)` ok.

### STATE (2026-09-21, fourth session)

Commits this session, all pushed:

| Commit | What |
|---|---|
| `09ae14b` | `feat(signal)`: first-frame dispatch on the signaling port + the `LiveSessions` tracker |
| `17e10dc` | `feat(tornect)`: `serve_host` in `tornect host`, `tornect connect` |
| `d9b1b72` | `docs`: decision M1-42, the live evidence, Part G |
| `8872a2d` | `feat(capture)`: `VideoSource`, the synthetic `TestCard`, the X11 and GDI backends |
| (this one) | `docs`: capture rows, Part G, this hand-off |

The three commits of session 3 (`94dfe64`, `34f4723`, `84f00f9`) were pushed at the start of
this session.

1. **`serve_host` is wired into `tornect host`** (decision M1-42, the operator's ruling "Keep
   ping, add connect").
   - The host answers the pairing-free `tornect ping` and the handshake FSM on one port, routed
     by the first frame (`tornect_signal::dispatch`). That frame is read whole under the FSM's
     own deadline and cap, then replayed, so the FSM's answers are unchanged.
   - Every seam is real. The consent popups are **terminal questions, answered only on a TTY**:
     with stdin not a terminal, the host refuses everything and the client confirms nothing.
   - One `KillSwitch` and one `LiveSessions` are shared with the IPC context, so `tornect panic`
     and `unattended off|pause|revoke-all` **end live sessions**, and the guard refuses
     access-increasing changes during a session and for 60 s after.
   - The FSM audits through the grant store's own `sessions.log` handle (a keyed hash chain).
2. **`tornect connect <id> [--pair-only] [--forget] [--pings N]`.** It pairs (both users
   compare the code), asks for a session, sends `TOR_FALLBACK`, and pings every 10 s. Between
   pings it waits on the stream, so a host `BYE` is reported as the host's.
3. **Verified live over real Tor on mx-vm: PASS 8/8** (two homes, PTY-driven, the codes compared
   by the driver). This covered:
   - ping;
   - the same code on both screens (the M1-32 re-pair path);
   - control and view-only sessions;
   - `unattended on` refused mid-session;
   - `tornect panic` ending the session on both ends in 0.6 s;
   - a clean Ctrl-C.

   The third of the four runs found one real bug (a panicked session reported as "connection
   lost"); it was fixed failing-first before the passing run.
4. **`tornect-capture` has begun:**
   - `VideoSource` (a pull with a timeout, tight BGRx `Frame`s);
   - `TestCard`, which carries its frame index in the picture (`read_index`);
   - the X11 backend, verified under `xvfb-run`;
   - the GDI backend, lint-clean for gnullvm; its runtime check is `NEEDS-DEVICE(windows)`, with
     a cross-built test recipe in `docs/VERIFICATION.md`.
5. **Tests 370 → 396.** Failing-first proven four times: an unshared kill switch; a guard blind
   to sessions; the old keep-alive loop; and, in session 3, the latch.

### NEXT, in order

1. **Wayland capture: RemoteDesktop portal + PipeWire via dlopen** (`docs/research/slice.md` §4).
   - This is the backend a GNOME or KDE Linux host needs.
   - It adds `ashpd` and `libloading` to the lockfile. Expect one full Arti rebuild (~15 min),
     and batch any other dependency change into the same edit.
   - The struct mirrors (`pw_stream_events` v2, `spa_hook`, `pw_buffer`, `spa_buffer`,
     `spa_data`, `spa_chunk`) and the 232-byte EnumFormat pod are in the sub-report named at the
     top of `slice.md`. Mutter offers BGRx/BGRA only; read the size from the negotiated `Format`;
     always requeue buffers; frames come only on damage (hence `VideoSource`'s timeout).
   - The portal session also yields the input sink (`notify_*`, evdev codes). **Never call
     `connect_to_eis`.**
   - The runtime check needs a click on the portal dialog: run it at the VM's console, or mark it
     `NEEDS-DEVICE`.
2. **`tornect-session`.** It must meet the review's requirements (SLICE-A2 A2-3/A2-4/A2-6, A1 G3):
   - the view-only gate before `Input` is even decoded;
   - a single-use `Bind` with a deadline;
   - one media stream per session;
   - an input rate cap and a bounded ack window (~8 frames / 512 KiB);
   - the viewer sizes from `DecodedFrame`, never from `BindOk`;
   - release-all at session end;
   - `KeyframeRequest` on a decode error.

   Where it plugs in:
   - It hangs off `SessionSink::on_start` / `on_end`. The app's `CliSessions` sink in
     `apps/tornect/src/host.rs` is where to plug it; the start/end pairing is guaranteed.
   - Host: `VideoSource` → `H264Encoder` → `tornect-proto` over `connect_on(MEDIA_PORT)` with the
     M1-41 `Bind` key from `LiveSession::token`.
   - Client: `tornect connect` gains the media stream.
   - `TestCard` + `read_index` allow an end-to-end test here: over a duplex first, then live
     over Tor.
3. **GUI** — a manual winit loop + egui (`slice.md` §2): the ID and Tor status; a connect field;
   the client SAS confirm; the host consent popup (Allow / View-only / Deny); a persistent
   "screen is being shared with X" banner with Stop; the viewer, with keys by physical scancode.
   It replaces `apps/tornect/src/prompt.rs` behind the same `Consent` / `ClientPairingUi` seams.
4. **Windows build of the whole app.**
   - First fix `tornect-core`'s 88 gnullvm-only `clippy::result_large_err` errors. Until then,
     lint Windows code with `-A clippy::result_large_err`.
   - Arti's ring, bundled SQLite and zstd on gnullvm are untested.
   - Try `CXXFLAGS_x86_64_pc_windows_gnullvm=-fstack-protector-strong` for OpenH264 (SLICE-A3 F4).
5. **`xtask pt-fetch` and `xtask dist`.** `pt-fetch` implements `packaging/pt/SOURCES.md`. `dist`
   produces a Linux tarball and a Windows zip containing `lyrebird(.exe)`, `lyrebird.txt`,
   `THIRD_PARTY_NOTICES.md` and a README. Pin toolchain hashes and set `LZMA_API_STATIC=1`
   (SLICE-A3 F7).
6. **Security review of the slice diff.** Freeze the range on a worktree and launch it first.
   **Ask the operator whether to run it at full size** (≈ 100 agents). The range since the last
   review (`efe75fa`) now includes the host wiring, the dispatch, `tornect connect` and capture.
7. The operator's two-machine test (recipe in `docs/VERIFICATION.md`).

M1, outside the slice: an **unattended client CLI** (`tornect connect --unattended`: a password
prompt and a `hosts.toml`-backed `ServerKeyPin`). The §B.8.14 M1 acceptance needs it.

### STILL OPEN / UNTESTED (do not mark these done)

- **Carried from earlier hand-offs:**
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
  - polkit over SSH with `pkttyagent`;
  - X11 capture on a real Xorg desktop;
  - GDI capture and `SendInput` at runtime.
- **Review items left for later:**
  - A1-8: `config show` and derived `Debug` print bridge lines.
  - A2-1: in-process OpenH264 decode, to be sandboxed at a later milestone.
  - F5: `multiple-versions = "deny"`.
  - F9/F10: read the Arti 0.46.0 and rustls notes before tagging.
- **New this session:**
  - The kill switch is host-wide (M1 scope): `unattended off`, `pause` and `revoke-all` also end
    **attended** sessions.
  - The panic key does not yet suspend the grant behind an unattended session (M4).
  - `rotate-id`'s own `HostIdRotated` append must stop once it goes through the guard.
  - There is no unattended client CLI.
- **S9 residual:** zxcvbn still scores "Laptop-of-Ana tornect 2026" at 4, even with the label.
- **No session layer or GUI yet, and no Wayland capture: the app is not functional end to end.**

### GOTCHAS

- **Gate order:** plan-sync → forbidden deps → cargo-deny → fmt → clippy → test → doc; it stops
  at the first failure. Run `cargo fmt --all` and clippy before the gate.
- **rustdoc fails on an intra-doc link to a per-OS module.** This session, a `` [`gdi`] `` link
  failed on Linux. Write per-OS module names as plain code spans.
- **X11 grab test:**
  `xvfb-run -a -s "-screen 0 1280x720x24" env XDG_SESSION_TYPE=x11 cargo test --workspace -- x11::tests`
  (Xvfb is installed). On the VM's rootless Xwayland, `GetImage` on the root answers `BadMatch`.
- **Live Tor check:** do not wait on `REACHABLE`. Arti's status can sit at `Bootstrapping` for
  5+ minutes while the host already serves. Search driver output from a marker.
- **The pre-commit hook lints the working tree, not the staged snapshot.** A split commit is only
  as good as its own reasoning or a separate check.
- **An unclean VM restart leaves corrupt incremental artifacts.** rustc warns and deletes them;
  no action is needed.
- **Disk:** 91 % used, ~9 G free. Never prune `target/debug/deps` by atime.
- `.githooks` is active: every commit runs fmt + clippy (~30 s). Use `TORNECT_SKIP_HOOKS=1` for
  docs-only commits.
- `cargo test -p <crate>` rebuilds under another feature unification; prefer `--workspace`.

### PENDING USER ACTIONS

- Grant the `gh` token the `workflow` scope, then push CI.
- Create `.claude/settings.json`.
- Decide on the `framing` fuzz corpus.
- Arrange a second machine.
- Install the polkit policy.
- Click the portal dialog for the Wayland capture check (next session).
- Carried: decide whether `tornect host` should *refuse* Snowflake rather than warn (A1-7).

Work autonomously per the CLAUDE.md ground rules. Commits carry **no AI references**. End the
session with this same kind of report plus memory, Part G and `docs/notes/m1-state.md` updates.

---

## What this session did

- Resumed at `84f00f9` with the KORE V3 MODE B bootstrap. The structure was verified by check
  (PASS, 34/34). The operator answered four questions: resume in MODE C; keep ping and add
  connect; push once the gate is green; lift DISC-1.
- Re-ran the gate (370 green) and pushed the three session-3 commits.
- Wired `serve_host` into `tornect host`, added `tornect connect`, and proved the wiring by
  mutation. Verified it live over Tor (8/8 on the fourth run).
- Started `tornect-capture` (trait, test card, X11, GDI).
- The VM was restarted by accident near the end. Only the session scratchpad (tmpfs) was lost,
  and everything in it had already been committed or copied into the tree. The capture work was
  re-verified afterwards: a gnullvm lint and a full gate (396 green).

**Honest limits:**
- The app is **not functional end to end**: no Wayland capture, no session layer, no GUI.
- There is no Windows build of the whole app, and no second machine; nothing was run on Windows.
- The M1 unattended path cannot be driven from the CLI yet.
- `m1` is not tagged, and CI has never run.
