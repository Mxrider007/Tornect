# Tornect — continuation report (2026-09-22, eighth session close)

Paste the block under **HAND-OFF** into a new session.

---

## HAND-OFF

Continue building Tornect from `/home/mx/Tornect` (the private GitHub repository is the remote
`origin`; branch `main`). Everything is committed. **Push state when this was written:**
`origin/main` = `1e6966c` (push 1 of session 8); `820c839` … `ad55279` and this hand-off's commit
were local, due for push 2 once the gate re-ran green. Check `git status -sb` first, and push once
green.

The operator's goal for this run:
- **A functional app on Linux and Windows.** The operator will test with one Linux and one
  Windows machine.
- **Tor with automatic obfs4 bridges when Tor is blocked, and Snowflake when obfs4 fails.**
- **The code cross-compiling for Windows.**

Scope ruling (operator, 2026-09-21): **"vertical slice first"**. That means a real Linux↔Windows
remote session end to end:
- Tor transport, software H.264, and one capture and one input backend per OS;
- a minimal egui window with the consent popup, the sharing indicator and the kill switch;
- a cross-built Windows binary and packaged zips.

QUIC hole punching is deferred; m2–m6 stay untagged until their full acceptance runs.

Read in this order before doing anything:
1. `CLAUDE.md`
2. this file
3. `docs/notes/m1-state.md` (§ *Session 2026-09-22 (8)*, *(7)* and *(6)*)
4. `docs/notes/decisions.md` M1-48 (Wayland capture and input) and M1-49 (the slice-D and slice-C
   fixes, the operator's rulings); M1-43 to M1-47 for the session layer and the earlier fixes
5. `docs/research/slice.md` §2, for the GUI (NEXT 1)
6. `docs/notes/m1-media-evidence.md`: how the live media check runs (driver in its appendix)
7. the review syntheses:
   `/home/mx/kore_project_V3/agents/security/reports/2026-09-22_tornect_slice_d_review.md` (the
   latest: D1–D5, the refuted list, and §10 on the Wayland policy) and
   `…/2026-09-22_tornect_slice_c_review.md` (the open infos; the slice-D corrections are appended
   at its end)

Then run `CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo xtask verify`. Expect **480 passed,
0 failed, 4 ignored** and `cargo deny check (offline; advisory DB 2026-08-29)` ok.

### STATE (2026-09-22, eighth session)

**Gate: green at 480 passed, 0 failed, 4 ignored** (437 at the start), cargo-deny ok.

- **Wayland capture and input are built and verified live** (decision M1-48).
  - One RemoteDesktop portal session with ScreenCast sources; PipeWire over `dlopen` with
    mirrored structs and the 232-byte EnumFormat pod; input through the portal's `Notify*` calls;
    the pointer mapped over the encoded region.
  - A restore token (0600, never logged) spares every dialog after the first. Deleting
    `<state>/portal-restore-token` revokes the grant, and `tornect doctor` says so.
  - At the console: 3538×1919, 19 fps of capture while dragging, five injected pointer moves each
    seen in a new picture.
  - Over real Tor: the desktop at 3538×1918 with 0 errors in two runs; run 2 passed all 10 checks.
    **2.7–3.1 fps at 6.8 MP**: the software encoder is the likely limit. `tornect panic` ended
    media within about 100 ms.
  - **No input crossed Tor** (no GUI yet), and no key was injected live at all.
- **The slice-D review of `5f1ae84..5ba8f11` ran in full**: 62/62 agents, 18 raw → 8 survived
  → 5 distinct defects, all LOW, no BLOCK. Its §10 addendum confirmed the Wayland policy under
  three conditions, now recorded in M1-48.
- **Every open slice-C low and every slice-D defect is fixed**, each code fix failing-first (M1-49;
  21 commits `820c839` … `ad55279`). C1-2 is met in code on every backend by mapping, not refusal.
- **New client behaviours, for the next review:** the viewer pings once a second when it has
  nothing else to say (the host releases held keys after 3 s of silence), and the first Ctrl-C now
  ends a pending media open.
- **Operator rulings:** D1 is LOW; the store-less host keeps M1-46, and §B.8.6.2 now notes that
  such a host must be stopped (Ctrl-C or panic) before deny-direction commands run.
- **Windows:** `cargo check --target x86_64-pc-windows-gnullvm -p tornect-session -p tornect-capture`
  is clean, 0 warnings. Nothing was linked or run on Windows.

Earlier sessions are in `docs/notes/m1-state.md`: (7) the slice-C review, B2-2 and 13 fps over
Tor; (6) the xtask fix; (5) the session layer.

### NEXT, in order

1. **GUI**: a manual winit loop + egui (`slice.md` §2).
   - The ID and Tor status; a connect field; the client SAS confirm; the host consent popup;
     a persistent "screen is being shared with X" banner with Stop.
   - The viewer draws `DecodedFrame`s through the `FrameSink` seam and sends input as `Msg::Input`
     (keys by physical scancode). Gate input on `ClientSession::accept().mode()`, never on
     `BindOk.mode` (SLICE-C2 C2-6).
   - It replaces `apps/tornect/src/prompt.rs` behind the `Consent` / `ClientPairingUi` seams.
     Withdraw open popups on a kill or a session start (the B1-3/B2-5 residual).
   - It is what first sends input over Tor: then run the desktop live check with keys as well as
     the pointer.
2. **Windows build of the whole app.**
   - First fix `tornect-core`'s 88 gnullvm-only `clippy::result_large_err`, then run gnullvm
     clippy on `tornect-session` (not run yet).
   - Apply A3-F4's `CXXFLAGS` (stack protector) for OpenH264: the decoder is in every client
     (SLICE-C2 C2-3).
   - The Arti stack type-checks for gnullvm now, but nothing is linked or run: ring, bundled
     SQLite and zstd are unlinked. The Windows paths of `backend.rs` (GDI, and `SendInput` with its
     new region mapping) are compiled only.
3. **`xtask pt-fetch` and `xtask dist`** (`packaging/pt/SOURCES.md`; `LZMA_API_STATIC=1`;
   pin the toolchain hashes).
4. **Hostile review of everything after `5ba8f11`.**
   - Scope: the Wayland backend (`4451d14` … `1e6966c`), including **`pipewire.rs`'s unsafe FFI**,
     which no review has read (§10 assessed the policy only); the portal and token handling;
     **the viewer's new idle ping**; the first-Ctrl-C media path; the 21 fix commits
     `820c839` … `ad55279`.
   - Freeze the range on a worktree and launch it first. **Ask the operator what size to run, and
     whether the week's budget carries it.**
5. **The operator's two-machine test** (recipe in `docs/VERIFICATION.md`, `serve_host` table).
6. **M5 items:**
   - a ScreenCast-only portal session for view-only sessions (its own token and first-run
     dialog; Security §10 Q2), unless the operator decides otherwise;
   - the fps lever for large desktops: downscale before the encode.

M1, outside the slice: an **unattended client CLI** (`tornect connect --unattended`: a password
prompt and a `hosts.toml`-backed `ServerKeyPin`). The §B.8.14 M1 acceptance needs it.
**Before unattended connects are wired on Wayland** (Security §10, M1-48):
- the §B.8.8 budget: a 5 s dialog, and no dialog at all without a valid token (`HOST_NOT_READY`);
- at M4, the block window and the indicator closing their M1 gaps.

### STILL OPEN / UNTESTED (do not mark these done)

- **Open slice-C findings** (infos; `2026-09-22_tornect_slice_c_review.md` §3):
  - C1-4: injector calls are neither bounded nor raced against the end, on X11 and `SendInput`
    (the Wayland injector queues and bounds its calls, M1-48);
  - **C1-5 (b)**: the input bucket charges one token per frame, not per OS event (one wheel frame
    can make up to 400 XTest requests); it was on no list until now;
  - C1-7, C2-3 to C2-7, C3-7. C2-6 is a contract for the GUI (NEXT 1).
- **Left from this session's fixes:**
  - item 9's extras (C3-3): an `SSH_CONNECTION` warning, and the resolved display in the banner;
  - gnullvm clippy on `tornect-session`;
  - R7's other half: a control task that ends, or is aborted, leaves `control` up (only at host
    shutdown today); the test covers the failed bind only;
  - the media-end row: fixed in code (`33ad8c9`), **OPEN until one live panic run**;
  - **GNOME dismissing the dialog on `Session.Close`** is UNVERIFIED (no fake portal was built);
  - `SystemBackend::view_only` is covered by reading only;
  - C1-3 at run time: XTest autorepeat and Arti's dead-circuit detection are UNVERIFIED.
- **Wayland, UNVERIFIED** (Security §10): the runtime default of the dialog's "Remember This
  Selection"; how a non-Flatpak restore token is bound to the app id; whether zbus logs message
  bodies at trace level; the first picture of a fully static screen; all of `pipewire.rs`'s
  unsafe code.
- **Wayland, open by design:**
  - no input has crossed Tor, and no key was injected live at all (the GUI);
  - the first-run dialog during a remote session must be answered, with "Allow Remote
    Interaction" on, within the client's 30 s wait (both live Tor runs restored the token);
  - a keyframe request on a still screen is served at the next damage;
  - the monitor is picked in the portal dialog only.
- **Slice-D, for a later pass:** O1 (a store-less host writes untagged `sessions.log` lines; once
  the §B.8.13 startup verifier is wired, one such run would leave a standing tamper badge;
  UNVERIFIED) and the cross-process `sessions.log` append race (UNVERIFIED, pre-existing).
- **Open slice-B findings** (synthesis §5). The lows:
  - B1-5: a remote `master_off` waits on its own answer.
  - B1-6: the lyrebird pin is check-then-exec.
  - B1-7: private bridge edge cases.
  - B1-8: `panic` does not suspend an unattended grant.
  - B2-3: typed-ahead input answers a process's first question.
  - B2-4: queued questions are invisible.
  - B2-6: SIGTTIN stops a backgrounded host.
  - B3-1: `On` can stay ON unseen.
  - B3-2: deny-direction ops fail entirely when a write fails.
  - B3-3: the re-auth dialog is not bound to its requester.
  - B3-4: 16 held IPC connections block `panic`.
  - B3-5: zxcvbn inputs are a snapshot.
  - B3-8: forbidden deps are checked on default features only.
  - B3-6 is an operator decision (see pending actions).
- **Contracts for later milestones:** `ends_at` enforcement; per-device kills (a per-device revoke
  or suspend leaves a live desktop-and-input stream running, B3-10/B1-9); same-device session
  replacement; a `u2`-era popup withdrawal. Input over the encoded region (B3-19, C1-2) is now met
  in code on every backend.
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
  - X11 capture and XTEST on a real Xorg desktop, through the session layer (the region mapping
    is verified under Xvfb only);
  - GDI capture and `SendInput` (with its region mapping) at run time;
  - C2-1 under a real flood from a hostile host.
- **Review items left for later:** A1-8 (bridge lines in `config show`), A2-1 (sandboxed decode),
  F5, F9/F10 (read the Arti 0.46.0 and rustls notes before tagging).
- **Also open:**
  - the kill switch is host-wide (M1 scope);
  - `rotate-id`'s own `HostIdRotated` append;
  - there is no unattended client CLI;
  - the S9 residual.
- **The app is still not functional end to end** for the operator: Wayland capture works, but
  there is no GUI (so no input reaches a host) and no Windows build.

### GOTCHAS

- **`cargo test -p <crate>` (or `--lib`) rebuilds the Tor stack**: it selects a different
  dev-dependency set, which re-unifies features (session 8: 1.8 GB before it was stopped). Run
  filtered tests as `cargo test --workspace -- <filter>`, and ignored ones as
  `cargo test --workspace -- --ignored <filter>`.
- **Gate order:** plan-sync → forbidden deps → cargo-deny → fmt → clippy → test → doc; it stops
  at the first failure. Run `cargo fmt --all` and clippy before the gate.
- **The GNOME dialog's "Allow Remote Interaction" switch starts off.** Whoever answers the dialog
  must turn it on, or the host shares the screen and injects nothing (the injector is refused, with
  the reason).
- **To revoke the remembered desktop grant, delete `<state>/portal-restore-token`**
  (`tornect doctor` names it); the desktop asks again at the next session. The home
  `target/tornect-test/s61-host` holds a live token, so runs on it show no dialog.
- **The portal needs the console session's environment:** `XDG_RUNTIME_DIR=/run/user/1000
  WAYLAND_DISPLAY=wayland-0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
  XDG_SESSION_TYPE=wayland`. The live portal check:
  `TORNECT_HOME=$PWD/target/tornect-test/s61-host cargo test --workspace -- --ignored --nocapture wayland::tests::live`.
- **Live media check:** the appendix of `docs/notes/m1-media-evidence.md` (the test card); the
  desktop variant is `target/tornect-test/wl_live_check.py` (untracked). Homes
  `s61-host`/`s61-client`. Do not wait on `REACHABLE`, and search output from a marker. The first
  ping may fail while the descriptor propagates; the driver retries.
- **Never run an injection test against `DISPLAY=:0` here** (the live Xwayland). The X11 tests run
  only under Xvfb:
  `xvfb-run -a -s "-screen 0 1280x720x24" env XDG_SESSION_TYPE=x11 cargo test --workspace -- x11::tests`.
- **OpenH264 prints a warning on the host terminal** at encoder start (`bEnableFrameSkip = 0 …`).
  It is harmless but noisy on the consent terminal. zbus's five portal warnings are now filtered.
- **rustdoc fails on an intra-doc link to a per-OS module.** Write per-OS module names as plain
  code spans.
- **The Windows check** needs llvm-mingw on `PATH`
  (`~/.local/opt/llvm-mingw-20260908-ucrt-ubuntu-22.04-x86_64/bin`). A cold gnullvm check of the
  Arti stack took 6 min and grew `target/x86_64-pc-windows-gnullvm` to 688 M.
- **The pre-commit hook lints the working tree, not the staged snapshot.**
- **Disk: 93 % used, 7.2 G free.** `target/debug/incremental` is safe to delete and regrows
  (4.7–4.8 G each time this session). Never prune `target/debug/deps` by atime.
- `.githooks` is active: every commit runs fmt + clippy. Use `TORNECT_SKIP_HOOKS=1` for
  docs-only commits.

### PENDING USER ACTIONS

- Grant the `gh` token the `workflow` scope, then push CI.
- Create `.claude/settings.json`.
- Decide on the `framing` fuzz corpus.
- Arrange a second machine.
- Install the polkit policy.
- Decide whether `cargo xtask verify` must **fail** when cargo-deny is missing (B3-6), rather than
  pass with "SKIPPED".
- Carried: decide whether `tornect host` should *refuse* Snowflake rather than warn (A1-7).
- **New:** should the first-run OS grant (the desktop's dialog) move to a local setup step, with
  the owner at the desk (for example `tornect host` asking once at start, before Tor), instead of
  appearing during a remote session? (Security §10 Q3)
- **New:** at M5, keep one RemoteDesktop token for both modes, or give view-only sessions a
  ScreenCast-only portal session (a second token and a second first-run dialog)? (Security §10 Q2)
- **New:** remove the frozen review worktree `/home/mx/tornect-review-slice-c` (detached at
  `5ba8f11`, clean), or keep it to re-freeze for the next review?

Work autonomously per the CLAUDE.md ground rules. Commits carry **no AI references**. End the
session with this same kind of report plus memory, Part G and `docs/notes/m1-state.md` updates.

---

## What this session did (eighth, 2026-09-22)

- Resumed at `5ba8f11`. The operator chose: Wayland first; a full refuted review; push once
  green. The operator was at the console for the portal dialog.
- **The slice-D review ran first**, on the frozen worktree moved to `5ba8f11`, while the Wayland
  backend was written: 62/62 agents in 47.8 min, then the parent synthesis and a §10 addendum on
  the Wayland policy.
- **Wayland capture landed** (`4451d14` … `4c603a5`; gate 458) and was verified at the console and
  over Tor (`1e6966c`). Push 1: `5ba8f11..1e6966c`.
- **The operator ruled:** D1 is LOW; keep M1-46 and add the plan note (docs only).
- **The lows and the slice-D fixes:** 21 commits, `820c839` … `ad55279`; gate 458 → **480**.
- **This hand-off:** decisions M1-48 and M1-49, the ledger (the rows that sat outside any table
  now have headers), Part G rows for sessions 6–8, the §B.8.6.2 note and the §B.8.7.4 pointer.

**Honest limits:**
- The app is **not functional end to end** for the operator: no GUI, so no input reaches a host,
  and no Windows build of the whole app. Nothing ran on Windows.
- No input crossed Tor, and no key was injected live at all.
- Nothing was run live after the fixes. The media-end fix and the pending-open cancel are proven
  by scripted tests only.
- Everything after `5ba8f11` is unreviewed by a hostile review, including `pipewire.rs`'s unsafe
  FFI.
- `m1` is not tagged, and CI has never run.
