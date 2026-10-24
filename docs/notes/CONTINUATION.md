# Tornect — continuation report (2026-09-24, the pre-release prepared)

Paste the block under **HAND-OFF** into a new session.

---

## HAND-OFF

Continue building Tornect from this repository (branch `main`; the remote `origin` is the private GitHub
repository). **Push state when this was written:** `origin/main` = `6b0da44`; the 33 commits `b09d919` …
`51f4be3` and the documentation commits of 2026-09-24 (this file's among them) were local, due for a push
**without a tag**. Check `git status -sb` and `git log --oneline origin/main..` first.

The operator's goal for this run:
- **A functional app on Linux and Windows.** The operator will test with one Linux and one Windows machine.
- **Tor with automatic obfs4 bridges when Tor is blocked, and Snowflake when obfs4 fails.**
- **The code cross-compiling for Windows.**

Scope ruling (operator, 2026-09-21): **"vertical slice first"**: a real Linux↔Windows session end to end
before QUIC. It is built: Tor transport with the bridge ladder, software H.264, one capture and one input
backend per OS, the window with the consent cards, the sharing banner and indicator and Stop, a Windows build,
packaged zips, and start at login. **The pre-release `v0.1.0-slice.1` is prepared and not tagged:** the tag and
the GitHub pre-release wait for the operator's go (decision M1-54). m1–m6 stay untagged until their full
acceptance runs.

Read in this order before doing anything:
1. `CLAUDE.md`
2. this file
3. `docs/notes/m1-state.md` (§ *Sessions 2026-09-23/24*, then *(8)*)
4. `docs/notes/decisions.md` M1-50 (the window), M1-51 (the Windows build), M1-52 (packaging and the release),
   M1-53 (start at login) and M1-54 (the operator's rulings of 2026-09-23 and 2026-09-24)
5. `docs/RELEASING.md` and `packaging/release/NOTES-v0.1.0-slice.1.md` (the notes, with the fields the final
   `dist` run fills)
6. `docs/VERIFICATION.md`: the closing section *The pre-release `v0.1.0-slice.1`*, the window's rows (*The
   window*, *The sharing indicator window*), and *The slice-E review fixes*
7. the review syntheses, in the project's review archive outside this repository: the slice-E and slice-F
   reviews (2026-09-23), the fix-closure check (phases 2a and 2b) and the release-preparation review (phase 2c,
   parts 1–4) of 2026-09-24. Their "open and disclosed" lists are what the notes disclose.

Then run the gate, in its own scope (systemd-oomd kills the terminal's builds otherwise):
`systemd-run --user --scope --quiet -- env CARGO_BUILD_JOBS=2 TMPDIR=$PWD/target/tmp cargo xtask verify`.
Expect **634 passed, 0 failed, 5 ignored** and `cargo deny check (offline; advisory DB 1931a145168d of
2026-09-23 21:20:53 UTC)` ok (a later `cargo deny fetch` moves the date; `dist` refuses a database more than 7
days old).

### STATE (2026-09-24)

**Gate: green at 634 passed, 0 failed, 5 ignored** at `51f4be3`, cargo-deny ok. The 5 ignored tests need a
person, the network or the user's systemd: the live portal check, the polkit round trip, the systemd round trip
and the two live Tor tests.

- **The window (M1-50):** `tornect` with no subcommand; inline cards whose accepts answer only a mouse click, are
  never focusable and arm after 1 s (the operator's "pointer-only Allow" for review finding E1-1); the first-run
  Wayland grant as a setup step; input by physical scancode, sent only for a control grant; SIGINT and SIGTERM
  end every session with a goodbye, the hosted ones first. The sharing banner plus an always-on-top window
  "Tornect: sharing" in the same process, whose line puts the label last (it departs from §B.8.7.3's word order).
- **The Windows build (M1-51):** `x86_64-pc-windows-gnullvm` with llvm-mingw; static libc++, the stack
  protector, run-time DLL loads from System32 only, CredUI loaded at run time. Under Wine only; never run on
  Windows.
- **Packaging (M1-52):** `cargo xtask pt-fetch` and `cargo xtask dist`; `THIRD_PARTY_LICENSES.txt` in each zip;
  the advisory database named in the gate and in `BUILD-INFO.txt`, with its ignores and a 7-day limit;
  RUSTSEC-2026-0285 fixed by rustls 0.23.45.
- **Start at login (M1-53):** `tornect service install`, `uninstall` and `status` (a systemd user unit; a Task
  Scheduler task from XML); the Linux start-at-login host answers pings only; the operator's three defaults and
  the `--elevated` refusal for standard accounts.
- **Reviews:** slice E (`0e3afea..2480dfb`), slice F (`2480dfb..75f6df8`), the fix-closure check and the
  release-preparation review, up to `bd8178a`: no Critical or High, every Medium fixed. **Unreviewed:**
  `d1ef55b..0e3afea` (the Wayland backend with `pipewire.rs`'s unsafe FFI), and everything after `bd8178a`
  (`51f4be3`, a test, and the documentation).
- **Release verification** at `bd8178a`: all PASS; its one finding, T-1, is fixed in `51f4be3`.
- **Not verified, honestly:** the window over real Tor with a person at the screen (**NOT PERFORMED three
  times**: 2026-09-23 02:27 and 22:53, 2026-09-24 01:14, each time the windows up, both hosts `REACHABLE`,
  nobody at the VM screen); keys over Tor, and any input over Tor in a live run; the polkit path live; anything on
  a Windows machine; a Linux ↔ Windows session.

### NEXT, in order

1. **The GUI console check, behind a presence gate.**
   - Presence first: ask the operator for one visible action on the VM's screen and watch for its effect
     within about 5 minutes. The cleanest one is the first step itself: **Grant screen sharing** in the Wayland
     host's window writes `<home>/state/portal-restore-token`. A remote answer does not prove presence at the VM
     screen; three attempts ended with nobody at the screen. Run the check early in a session, while the operator is
     available.
   - Rebuild first (`cargo build -p tornect` in a scope, about 2–3 min): the relaunch kit
     (`target/tornect-test/phase_b3/relaunch.sh`) runs the `6b0da44` build, which predates the signal handling,
     N-1, N-4, P2-I4 and T-1. No other build beside the check.
   - The windows: a Wayland host, a `--no-host` client, and a second host whose capture and XTEST run on a
     private Xvfb `:99` holding a zenity entry box (two windows are titled "Tornect": tell them apart by the ID
     they show). The steps: grant (turn **Allow Remote Interaction** on); wait for `REACHABLE` (0.5–4 min); Copy,
     paste, Connect; compare the codes and mouse-click the accepts after their second; **Allow control** → the
     banner and the indicator; move the pointer over the picture (the inputs count grows); **Stop sharing**;
     connect again → **View only** (inputs stay 0); connect again → click an empty spot of the host window, Tab,
     Enter → must end **denied**; the X11 host: Allow control, type `hello tornect` and two Backspaces into the
     zenity field through the viewer.
   - Part 3 needs the operator's `sudo`: install `packaging/polkit/org.tornect.policy` and restart polkit, then
     `TORNECT_TEST_POLKIT_ACTION=org.tornect.autostart cargo test --workspace -- --ignored --nocapture
     live_polkit_round_trip` and a real `tornect service install` through polkit's dialog; uninstall it and
     confirm `systemctl --user is-enabled tornect-host.service` says `not-found`.
   - Record the results in the NOT PERFORMED rows of `docs/VERIFICATION.md` (the window's rows, the polkit grant
     row, the service row, the E1-1 row).
2. **The operator's two-machine test from the release zips** (Linux ↔ Windows; the Linux machine needs glibc
   2.43 or newer): the `serve_host` table's Linux ↔ Windows row, *The Windows zip on a Windows machine*, the 13
   test binaries, and the Windows recipes of the slice-E and slice-F rows (E1-1, N-1, E2-2, E2-4, `--elevated`,
   F1-1, F1-2, F1-5).
3. **The dependent-load flag** (M1-51), which needs the operator's own yes: the edit of `.cargo/config.toml` waits
   for the operator's explicit approval. With the yes: add
   `"-C", "link-arg=-Wl,--dependent-load-flag=0x800"` to `[target.x86_64-pc-windows-gnullvm] rustflags`; then
   `llvm-readobj --coff-load-config tornect.exe` must show `DependentLoadFlags: 0x800` and `--coff-imports` only
   System32 DLLs and `api-ms-win-*` sets; the Wine smoke test (`docs/RELEASING.md` step 4); then the E2-4 row of
   `docs/VERIFICATION.md` and the E2-4 item of the notes, and a new `dist`. Without it, the notes already carry the
   disclosure.
4. **The tag and the GitHub pre-release** (`docs/RELEASING.md` steps 5–7), on the operator's go only: the final
   `dist` at the commit the tag names, its filled copy of the notes (outside the repository), `gh release create
   v0.1.0-slice.1 --prerelease …`, then download the three assets and run `sha256sum -c SHA256SUMS` again. It
   stays blocked on (1), or on the operator's decision to publish with the console check NOT PERFORMED.
5. **The §B.8.7.3 indicator extras:** the manager badge "N devices can connect without asking" (review finding
   **E1-5**'s badge; it reads the guard's store), re-assertion every 500 ms (on Windows `SetWindowPos`: winit's
   `set_window_level` acts only on a change), one indicator per captured monitor, a window Windows cannot minimize
   (E2-5), a remembered position, the tray state; and the operator's word on the indicator's word order (M1-50).
6. **Carried to M6:** E2-2's DACL (an owner + SYSTEM DACL in `create_private_dir`/`write_private_file`) with the
   Windows named pipe (M1-46); E2-5; E2-6 (the Windows console's close, logoff and shutdown events); E2-8 (a notice
   for an elevated host); F1-6 (a per-user task name and a principal compare); F2-5 (a per-home unit name); F2-6's
   readiness (`systemctl --user show -p LoadState` and the target's state); slice-F P-1 (a cool-down read from
   `sessions.log`); F1-2's residuals (a DACL and a held handle, or COM registration with no file); N-2 (ACLs and
   junctions in the location checks); N-3's extras (the trigger's `<UserId>`; only a SID or a qualified name as the
   principal); slice-E P-1 (CFG and CET); E3-2; E3-4 (bounded 2026-10-24 by the signature's date: `EXPKEYSIG`
   counts only for a signature dated before the expiry; the backdating limitation remains, since that date is
   the signer's claim; refresh the key file with the next Tor Browser bump); E3-5; P3-I1 … P3-I3.
7. **The unattended client CLI** (`tornect connect --unattended`: a password prompt and a `hosts.toml`-backed
   `ServerKeyPin`); the §B.8.14 M1 acceptance needs it. Before unattended connects are wired on Wayland (Security
   §10, M1-48): the §B.8.8 budget (a 5 s dialog, and no dialog at all without a valid token: `HOST_NOT_READY`),
   and at M4 the block window and the indicator closing their gaps.
8. **A hostile review of `d1ef55b..0e3afea`** (the Wayland backend, `pipewire.rs`'s unsafe FFI, the portal and
   token handling, the idle ping, the slice-D fixes). Freeze the range on a worktree and start the review first; ask
   the operator what size to run, and when.
9. **M5 items:** a ScreenCast-only portal session for view-only sessions (ruled for M5), and downscaling before
   the encode for large desktops.

### STILL OPEN / UNTESTED (do not mark these done)

- **The window:** never used by a person over real Tor (NEXT 1). Open questions of its first build: a withdrawn
  pairing card counts toward that device's temp-ban like a refusal, and a withdrawn session card answers `DENIED`,
  not `BUSY` (the `Consent` seam has no "withdrawn"); winit's key repeats are not forwarded, so a held key on a
  Windows host types once; quitting while Tor still bootstraps leaves the ladder task to the runtime's 5 s bound.
- **Windows at run time, NEEDS-DEVICE:** GDI capture, `SendInput`, the DX12 window, winit's Set-1 scancodes, Arti
  and the onion service, the state directory's ACL, the indicator's `HWND_TOPMOST`, `lyrebird.exe`'s console
  behaviour, the restricted DLL search with a real GPU driver, CredUI's run-time load on the secure desktop,
  `is_administrator` on a real split token, what `schtasks /Query /XML` prints (the principal's form, the XML
  declaration), `AllowStartOnDemand`, the window's Ctrl-C and Ctrl-Break, whether a background `SW_RESTORE` raises
  the window (E1-1, N-1), and `%ERRORLEVEL%` after `tornect.exe --version` (under Wine, started straight from a
  Linux shell, it sometimes ends with status 137 after printing: a Wine oddity).
- **E2-4's load-time residual** until the flag lands (NEXT 3).
- **Linux:** the polkit path live; a real login starting the unit; capture under the unit; X11 capture and XTEST
  on a real Xorg desktop; the bridge fallback on a network that really blocks Tor.
- **The glibc floor:** the Linux zip needs glibc 2.43 or newer (ruled: it ships as built). A build against an
  older glibc needs a container or cargo-zigbuild, neither installed.
- **Cosmetic:** a long IPC refusal is cut at 256 characters mid-word (seen under Wine); the pings-only host still
  prints its "sharing: this desktop …" line.
- **Earlier lists that stay valid** (the eighth session's hand-off, in git history at `ece3752`): the open
  slice-C infos (C1-4, C1-5 (b), C1-7, C2-3 to C2-7, C3-7); the slice-B lows; the Wayland UNVERIFIED items
  (GNOME dismissing the dialog on `Session.Close`, "Remember This Selection", the token's app-id binding, zbus
  trace logging, the first picture of a static screen, `pipewire.rs`'s unsafe code); O1 and the cross-process
  `sessions.log` race; the contracts for later milestones (`ends_at`, per-device kills, same-device replacement);
  the carried items (the §B.8.15 A14 core-dump sweep, the §B.8.5.2 caps, plan r7 (M1-31/M1-32), the EFF word list,
  `mlock`/`VirtualLock`, the keyring canary, `tests/integration`); the review items A1-8, A2-1, F5, F9/F10.
- **CI has never run**, and `m1` is not tagged.

### GOTCHAS

- **Every heavy cargo command in its own scope, 2 jobs:** `systemd-run --user --scope --quiet -- env
  CARGO_BUILD_JOBS=2 TMPDIR=$PWD/target/tmp cargo …`. systemd-oomd kills the terminal's whole process group
  under memory pressure (twice on 2026-09-23).
- **`cargo test -p <crate>` (or `--lib`) rebuilds the Tor stack.** Run filtered tests as `cargo test
  --workspace -- <filter>`, and ignored ones as `cargo test --workspace -- --ignored <filter>`.
- **Gate order:** plan-sync → forbidden deps → cargo-deny → fmt → clippy → test → doc; it stops at the first
  failure. The advisory check is offline: `target/tools/cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny
  fetch` (network) refreshes the RustSec database; the gate and `dist` refuse two copies, and `dist` one older
  than 7 days (`--allow-old-advisory-db`, then say so in the notes).
- **The Windows lint:** `cargo clippy --target x86_64-pc-windows-gnullvm --workspace --all-targets -- -D
  warnings` with llvm-mingw's `bin` on `PATH` (`~/.local/opt/llvm-mingw-20260908-ucrt-ubuntu-22.04-x86_64/bin`);
  `-p tornect` alone fails (`start_paused` needs tokio's `test-util`).
- **Under Wine the `--home` goes inside the Wine profile** (E2-2): `wine cmd /v:on /c 'tornect.exe --home
  %USERPROFILE%\<dir> id & echo exit !ERRORLEVEL!'`; `%ERRORLEVEL%` would be read before the command runs.
- **The GNOME dialog's "Allow Remote Interaction" switch starts off.** To revoke the remembered grant, delete
  `<state>/portal-restore-token` (`tornect doctor` names it) or press Revoke in the window.
- **The portal and the window need the console session's environment:** `XDG_RUNTIME_DIR`, `WAYLAND_DISPLAY`,
  `DBUS_SESSION_BUS_ADDRESS`, `XDG_SESSION_TYPE=wayland`.
- **Never run an injection test against `DISPLAY=:0`** (the live Xwayland); the X11 tests run only under Xvfb:
  `xvfb-run -a -s "-screen 0 1280x720x24" env XDG_SESSION_TYPE=x11 cargo test --workspace -- x11::tests ui::`.
  The window's tests need no display.
- **Stopping the console-check processes:** SIGTERM the windows, then zenity **before** its `dbus-run-session`,
  then Xvfb; afterwards look for orphaned `dbus-daemon --nofork --print-address` processes too.
- **The pre-commit hook lints the working tree, not the staged snapshot**; `TORNECT_SKIP_HOOKS=1` for docs-only
  commits. Commit messages carry no trailers.
- **Never type the build machine's host name** into a command, a file or a test: the docs call it "the build
  VM", and the test data uses `build-vm`.
- **Disk: 89 % used, 11 G free** (2026-09-24). `target/debug/incremental` is safe to delete and regrows;
  `target/dist/cargo` (5.6 G, dist's build cache) makes the next `dist` take seconds and is safe to delete;
  never prune `target/debug/deps` by atime.
- **rustdoc fails on an intra-doc link to a per-OS module**: write per-OS module names as plain code spans.

### PENDING USER ACTIONS

- **Be at the VM's screen for the console check** (NEXT 1), and install the polkit policy with `sudo` there.
- **The dependent-load flag:** yes or no (NEXT 3).
- **The go for the tag and the GitHub pre-release** (NEXT 4), after the final `dist`.
- **The two-machine test** (NEXT 2).
- The indicator's word order against §B.8.7.3: confirm or amend (M1-50).
- The withdrawn-card semantics (temp-ban; `DENIED` rather than `BUSY`): confirm or change.
- Carried: grant the `gh` token the `workflow` scope, then push CI; create `.claude/settings.json`; decide on the
  `framing` fuzz corpus; a second machine; keep or remove the frozen review worktree; optionally `systemctl
  disable --now systemd-oomd` (sudo).
- Already ruled, not to be asked again (M1-54): B3-6 (the gate fails without cargo-deny), A1-7 (Snowflake
  hosting warns), the first-run grant as a setup step, ScreenCast-only sessions at M5, the worktree kept, the pushed
  history not rewritten, glibc 2.43, the licence texts, the advisory refresh, E2-4 and E2-2 fixed
  now, the pointer-only accepts, pings only when headless, the three defaults, the `--elevated` refusal.

Work autonomously per the CLAUDE.md ground rules. End the session with this same kind of report, plus Part G
and `docs/notes/m1-state.md` updates.

---

## What the sessions of 2026-09-23 and 2026-09-24 did

- **2026-09-23:** the window (`9b61b17` … `d370207`) and its first console attempt (02:27, NOT PERFORMED); the
  sharing indicator (`f509f7c`, `164461b`); the Windows build of the whole app (`bd3ef35` … `10090a3`); `pt-fetch`,
  `dist` and B3-6 (`0135ddd` … `2480dfb`); start at login (`8a7ddbb`, `95f455e`, `75f6df8`); the slice-E review;
  its fixes (`49e29f7` … `dea1f35`); the second console attempt (22:53, NOT PERFORMED); the slice-F review and its
  two Mediums fixed (`e7c83bd`, `22aa1ce`) with F1-3 and F2-2 (`7242cad`, `6b0da44`). Push 5: `origin/main` =
  `6b0da44`.
- **2026-09-24:** the third console attempt (01:14, NOT PERFORMED, behind a presence gate); the fix-closure check
  (phase 2a: 13 of 13 closed); the remaining fixes (`b09d919` … `3259031`: E2-2, E2-4, the `--elevated` refusal,
  F2-3, F2-4, F1-2, F1-5, default 3, N-1, E2-7, the window's signals); phase 2b; the release preparation
  (`00bc286` … `bd9a095`: RUSTSEC-2026-0285, the advisory database in the gate and `BUILD-INFO.txt`, the licence
  texts); phase 2c and its fixes (`fe7e02e` … `bd8178a`: N-3, N-4, L-1, L-2, I-2, I-3, P2-I1 … P2-I4, the host name
  out of the code); the release verification and T-1 (`51f4be3`); these documentation commits (decisions M1-50 …
  M1-54, Part G, the ledger, the release notes, `CLAUDE.md`, the host name out of every doc).

**Honest limits:**
- No person has used the window over real Tor, no input has crossed Tor in a live run, and no key has been
  injected live.
- Nothing has run on a Windows machine: Wine only.
- The polkit path has not run live; the start-at-login run used the debug build's re-authentication escape.
- `d1ef55b..0e3afea` has had no hostile review.
- The pre-release is not tagged; its notes' fields stay unfilled until the final `dist`. `m1` is not tagged,
  and CI has never run.
