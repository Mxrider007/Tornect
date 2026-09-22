# Tornect — continuation report (2026-09-22, seventh session close)

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

Scope ruling (operator, 2026-09-21): **"vertical slice first"**. That means a real Linux↔Windows
remote session end to end:
- Tor transport, software H.264, and one capture and one input backend per OS;
- a minimal egui window with the consent popup, the sharing indicator and the kill switch;
- a cross-built Windows binary and packaged zips.

QUIC hole punching is deferred; m2–m6 stay untagged until their full acceptance runs.

Read in this order before doing anything:
1. `CLAUDE.md`
2. this file
3. `docs/notes/m1-state.md` (§ *Session 2026-09-22 (7)*, *(6)* and *2026-09-21 (5)*)
4. `docs/notes/decisions.md` M1-43 (the session layer), M1-44 (the review fixes), M1-45 (the
   xtask environment fix, B2-7, B3-7), M1-46 (B2-2) and M1-47 (the slice-C fixes, the 20-unit
   window)
5. `docs/notes/m1-media-evidence.md`: how the live media check runs (driver in its appendix)
6. `docs/research/slice.md` §4, for Wayland capture
7. the review syntheses:
   `/home/mx/kore_project_V3/agents/security/reports/2026-09-22_tornect_slice_c_review.md` (the
   latest: open findings and their dispositions) and `…/2026-09-21_tornect_slice_b_review.md`

Then run `CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo xtask verify`. Expect **437 tests**
and `cargo deny check (offline; advisory DB 2026-08-29)` ok.

### STATE (2026-09-22, seventh session)

**Gate: green at 437 tests**, cargo-deny ok. `main` = `origin/main` at this hand-off's commit.

- **The slice-C review ran** (it had died on the weekly limit the session before): 0 critical,
  0 high, 2 medium, 6 low, 13 info. Both mediums are fixed.
- **B2-2 is fixed** (M1-46). A host keeps a kill path with no store and with no control channel,
  and the terminal only ever names a kill path that works. On Windows that path is Ctrl-C until
  the M6 named pipe.
- **C1-1** (a squatter could deny every session its picture), **C2-1** (a flooding host swallowed
  Ctrl-C in `tornect connect`) and **B2-8** (an unbounded `bye`) are fixed, all failing-first (M1-47).
- **The ack window is 20 units**; over Tor the test card went from 6.3 to **13.2 and 13.0 fps** in two live
  runs. Run 2 passed all 10 live checks. `bye` now waits for the host to close: run 1 had lost the
  client's `BYE` to its own immediate Tor shutdown.

### STATE (2026-09-22, sixth session)

**Gate: green at 428 tests**, cargo-deny ok. `main` = `origin/main` at this hand-off's commit.

**This session (decision M1-45):**
- **The gate no longer fights plain `cargo`.** `xtask`'s `cargo()` removes the variables
  `cargo run` gave it (`CARGO_PKG_*`, `CARGO`, `CARGO_MANIFEST_DIR`/`_PATH`, `CARGO_CRATE_NAME`,
  `CARGO_BIN_NAME`, `CARGO_PRIMARY_PACKAGE`, `CARGO_TARGET_TMPDIR`, `CARGO_RUSTC_CURRENT_DIR`) and
  keeps user settings. `ring`'s build script watches those, so every switch between the gate and a
  plain `cargo` or the hook used to rebuild the Tor stack. Measured after: 0.6 s and 0.3 s with
  nothing rebuilt (before: 33 s and a `ring` + `rustls` rebuild). The whole gate now takes 41 s.
- **B2-7:** the host's session question accepts only `a`/`allow` and `v`/`view`. `y`/`yes` — the
  reflex answer to the pairing question — no longer grants control.
- **B3-7:** the X11 grab computes its buffer size with `checked_mul` in `usize` under a
  2^27-pixel cap, before `GetImage`. In `u32` the product wrapped to 0 at 32768×32768, so an empty
  reply passed for a one-gigapixel picture.
- Each fix has a test that fails on the old code.

**THE REVIEW OF `510b6cb..5f1ae84` DID NOT RUN.** Three read-only threat modelers were launched
first, on the frozen worktree `/home/mx/tornect-review-slice-c` @ `5f1ae84`, and all three died on
the account's **weekly** usage limit within ~15 minutes, with no report written. The session
layer, the CLI media path and the M1-44 fixes have had only inline and self review. The worktree
is kept, clean and detached, for the re-launch; the limit resets **2026-09-24 17:00 -03**. Scopes
and focus questions: `/home/mx/kore_project_V3/agents/agentcheck/reports/activation_plan.md`;
record: `.../agents/security/reports/2026-09-22_tornect_slice_c_review_NOT_RUN.md`.

### STATE (2026-09-21, fifth session)

Commits this session, all pushed:

| Commit | What |
|---|---|
| `be28c64` | `feat(proto)`: the host reads the client's direction with a 64-byte frame cap; `BindOk` documented as a hint |
| `bc85abe` | `feat(session)`: `MediaHost` and `MediaViewer`, the Tor media session layer (M1-43) |
| `fd672b7` | `feat(tornect)`: `tornect host --capture desktop\|test-card`; `tornect connect` receives the screen |
| `764f74f` | `fix(signal)`: the session ends before any goodbye; a pending accept is re-checked (M1-44) |
| `7d3668a` | `fix(tornect)`: a media end the host caused is reported as the host's |
| (this one) | `docs`: evidence, decisions M1-43/M1-44, ledger rows, Part G, this hand-off |

1. **The session layer exists** (`crates/tornect-session`, decision M1-43).
   - **Host (`MediaHost`, a `SessionSink`).** It serves a media-port stream only after a `Bind`.
     The bind is read at its fixed size within 10 s, with at most 8 streams waiting. It is single
     use, and a wrong MAC does not burn the session.
   - **Capture** opens only then. It runs on a blocking thread, one picture per credit, and
     credits come from an ack window of 8 units / 512 KiB.
   - **Input.** A view-only session has no injector, so its input is dropped undecoded. A control
     session injects through `Tracked` and a 250/s bucket.
   - **Kills.** `watch_kill` ends every session's media on any kill, without waiting for the FSM.
   - **Viewer (`MediaViewer`).** It binds, decodes, acknowledges every unit, sizes each picture
     from what it decodes, and asks for a keyframe after a decode error.
2. **The CLI uses it.**
   - `tornect host --capture desktop` shares X11 on an X11 session, or GDI on Windows. On Wayland
     it says capture is not built. `--capture test-card` shares the synthetic card, which never
     injects.
   - `tornect connect` opens the media stream in the signaling stream's isolation group, so it
     rides the same circuit. It prints `MEDIA BOUND`, `video: …` every 5 s, `MEDIA OK|EMPTY …`,
     and `MEDIA CARD first=… last=… in-order` for a card. `--no-video` keeps signaling only.
3. **Verified live over real Tor** (two homes on mx-vm, test card):
   - 146 of 146 pictures arrived in order, with 0 decode errors, at 1280×720 and 6.3 fps;
   - `tornect panic` ended media and session on both ends.

   The driver's last check failed on wording only. That is fixed (`7d3668a`) but not re-run.
   Evidence: `docs/notes/m1-media-evidence.md`.
4. **Review of `efe75fa..510b6cb`** (KORE A′: 3 read-only threat modelers).
   - Totals: 0 critical, 0 high, 4 medium, 24 low, 14 info; 106 candidates refuted.
   - Fixed failing-first (M1-44), each test failing on the old code:
     - B1-2 ⊕ B2-1: the kill no longer waits on writes to a stuck peer;
     - B1-3 ⊕ B2-5: a kill, or a session gone live, refuses a pending accept;
     - B1-1: unattended requests get `SESSION_ACTIVE`;
     - B1-4: a panicking sink still releases the session.
   - **Open: B2-2** (see NEXT) and the low findings listed in the synthesis.
5. **Tests 396 → 424.**

### NEXT, in order

1. **Wayland capture: RemoteDesktop portal + PipeWire via dlopen** (`docs/research/slice.md` §4).
   - It adds `ashpd` and `libloading` to the lockfile. Expect one full Arti rebuild, and batch any
     other dependency change into the same edit.
   - Implement it as a `VideoSource` plus an `InputSink` (`notify_*`, evdev codes; **never
     `connect_to_eis`**) behind `SystemBackend`'s `Source::Desktop` on Wayland.
   - The struct mirrors and the 232-byte EnumFormat pod are in the sub-report named at the top of
     `slice.md`.
   - Frames come only on damage (the source returns `Ok(None)`), and buffers must always be
     requeued. Map input over the **encoded** region from the start (SLICE-C1 C1-2).
   - The runtime check needs a click on the portal dialog: run it at the VM's console, or mark it
     `NEEDS-DEVICE`.
2. **The review's open lows, by value** (claims until checked; details in the slice-C synthesis):
   - **C3-1:** the one-session gate is check-then-act across the `SESSION_ACCEPT` write. Reserve
     the slot atomically in `LiveSessions`.
   - **C1-2 interim:** refuse an injector when the source is larger than the encoder's
     3840×2160.
   - **C1-3:** release held keys when the viewer goes quiet (≈ 3 s).
   - **C3-2:** race the `fail()` writes in `established()` against the kill.
   - **C3-3:** refuse a `DISPLAY` with a host part.
   - **C2-2 (b):** a stalled viewer write delays the stop.
3. **GUI**: a manual winit loop + egui (`slice.md` §2).
   - The ID and Tor status; a connect field; the client SAS confirm; the host consent popup;
     a persistent "screen is being shared with X" banner with Stop.
   - The viewer draws `DecodedFrame`s through the `FrameSink` seam and sends input as `Msg::Input`
     (keys by physical scancode). Gate input on `ClientSession::accept().mode()`, never on
     `BindOk.mode` (SLICE-C2 C2-6).
   - It replaces `apps/tornect/src/prompt.rs` behind the `Consent` / `ClientPairingUi` seams.
     Withdraw open popups on a kill or a session start (the B1-3/B2-5 residual).
4. **Windows build of the whole app.** First fix `tornect-core`'s 88 gnullvm-only
   `clippy::result_large_err`. Apply A3-F4's `CXXFLAGS` (stack protector) for OpenH264: the decoder
   is now in every client (SLICE-C2 C2-3). Arti's ring, bundled SQLite and zstd on gnullvm are
   untested; the Windows paths of `backend.rs` (GDI, `SendInput`) are compiled only by inspection.
5. **`xtask pt-fetch` and `xtask dist`** (`packaging/pt/SOURCES.md`; `LZMA_API_STATIC=1`;
   pin the toolchain hashes).
6. **Security review of everything after `5f1ae84`.** Freeze the range on a worktree and launch it
   first. **Ask the operator what size to run, and whether the week's budget carries it.**
7. The operator's two-machine test (recipe in `docs/VERIFICATION.md`).

M1, outside the slice: an **unattended client CLI** (`tornect connect --unattended`: a password
prompt and a `hosts.toml`-backed `ServerKeyPin`). The §B.8.14 M1 acceptance needs it.

### STILL OPEN / UNTESTED (do not mark these done)

- **Open slice-C findings** (`2026-09-22_tornect_slice_c_review.md` §3): the lows C1-2, C1-3,
  C2-2 (b), C3-1, C3-2 and C3-3 (NEXT item 2), and the infos C1-4, C1-7, C2-3 to C2-7, C3-5, C3-7.
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
- **Contracts for later milestones:** `ends_at` enforcement, per-device kills, same-device session
  replacement, input mapped over the encoded region (B3-19, now live as SLICE-C1 C1-2), and a
  `u2`-era popup withdrawal.
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
  - X11 capture on a real Xorg desktop, through the session layer;
  - GDI capture and `SendInput` at runtime.
- **Review items left for later:** A1-8 (bridge lines in `config show`), A2-1 (sandboxed decode),
  F5, F9/F10 (read the Arti 0.46.0 and rustls notes before tagging).
- **Also open:**
  - the kill switch is host-wide (M1 scope);
  - `rotate-id`'s own `HostIdRotated` append;
  - there is no unattended client CLI;
  - the S9 residual.
- **The app is still not functional end to end** for the operator: no Wayland capture, no GUI, no
  Windows build.

### GOTCHAS

- **The gate and plain `cargo` rebuild each other's Tor stack**, because of the `CARGO_PKG_*`
  environment of `cargo xtask`. This costs several minutes per switch for tests, and about 30 s
  for the hook's clippy. Fix it first (NEXT 0).
- **Gate order:** plan-sync → forbidden deps → cargo-deny → fmt → clippy → test → doc; it stops
  at the first failure. Run `cargo fmt --all` and clippy before the gate.
- **Live media check:** `docs/notes/m1-media-evidence.md` appendix; homes `s61-host`/`s61-client`.
  Do not wait on `REACHABLE`, and search output from a marker. The first ping may fail while the
  descriptor propagates; the driver retries.
- **OpenH264 prints a warning on the host terminal** at encoder start (`bEnableFrameSkip = 0 …`).
  It is harmless but noisy on the consent terminal; consider the encoder's trace level.
- **rustdoc fails on an intra-doc link to a per-OS module.** Write per-OS module names as plain
  code spans.
- **X11 grab test:**
  `xvfb-run -a -s "-screen 0 1280x720x24" env XDG_SESSION_TYPE=x11 cargo test --workspace -- x11::tests`.
- **The pre-commit hook lints the working tree, not the staged snapshot.**
- **Disk:** 92 % used, 8.5 G free. Never prune `target/debug/deps` by atime.
  `target/debug/incremental` is safe to delete (it freed 6.6 G this session).
- `.githooks` is active: every commit runs fmt + clippy. Use `TORNECT_SKIP_HOOKS=1` for
  docs-only commits.

### PENDING USER ACTIONS

- Grant the `gh` token the `workflow` scope, then push CI.
- Create `.claude/settings.json`.
- Decide on the `framing` fuzz corpus.
- Arrange a second machine.
- Install the polkit policy.
- Click the portal dialog for the Wayland capture check (next session).
- Decide whether `cargo xtask verify` must **fail** when cargo-deny is missing (B3-6), rather than
  pass with "SKIPPED".
- Carried: decide whether `tornect host` should *refuse* Snowflake rather than warn (A1-7).

Work autonomously per the CLAUDE.md ground rules. Commits carry **no AI references**. End the
session with this same kind of report plus memory, Part G and `docs/notes/m1-state.md` updates.

---

## What this session did (seventh, 2026-09-22)

- Resumed at `68f690e` with the KORE V3 MODE B bootstrap. The structure check passed 34/34. The
  operator answered three questions:
  - resume in MODE C;
  - launch the review now (the week had room);
  - push once green.
- **The slice-C review ran first** (three threat modelers on the frozen worktree, ≈ 21 min each)
  and completed. Its synthesis is in KORE: 2 medium, 6 low, 13 info.
- Fixed failing-first, one commit each:
  - B2-2 (`94255c2`);
  - C1-1 (`326fd72`);
  - C2-1 with B2-8 (`65463d6`);
  - C1-5, C1-6 and C3-4 (`2ee219c`);
  - the 20-unit window (`7317e0d`, measured live);
  - the lost `BYE` the live run exposed (`c641ae6`).
- The gate went from 428 to **437**. A flaky test (`a_bind_is_single_use`) was found and fixed on
  the way.
- **Live over Tor:**
  - 13.2 and 13.0 fps, 0 errors, the card in order;
  - run 2 passed all 10 checks;
  - the documented driver could never say PASS (11 results asked for, 10 checks), now fixed.

**Honest limits:**
- The app is **not functional end to end** for the operator: no Wayland capture on this VM, no
  GUI, and no Windows build of the whole app. Nothing ran on Windows.
- On Windows, `tornect panic` cannot reach a host until M6. The host names Ctrl-C instead. That
  Windows path is compiled by inspection only (NEEDS-DEVICE).
- C2-1's fix was proven on a transport that is always ready. No flood from a hostile host has
  been run live.
- The fixed ping deadline has no failing-first test.
- Everything after `5f1ae84` is unreviewed by a hostile review, including this session's fixes.
- `m1` is not tagged, and CI has never run.
