<!-- Template: the final dist run fills the marked fields in a copy outside the repository; this committed file keeps the markers. -->
# Tornect 0.1.0, slice pre-release 1 (`v0.1.0-slice.1`)

**A pre-release, for testing between two machines you control, one Linux and one Windows.** It is the first
packaged build of Tornect's vertical slice, not a milestone release: `m1` (signaling over Tor) is not tagged,
and its remaining acceptance runs are open. No one has audited Tornect: do not rely on it to protect anything
yet. It collects no telemetry. Read `README-release.md` in the zip first.

## What Tornect is

Tornect shares one computer's screen with another over Tor. A computer's Tornect ID is its Tor onion v3
address (Arti, embedded in the program), so there is no server, no account and no port forwarding.

- **Pairing** shows the same code on both screens; the two people compare it. The sharing side then answers
  each session with **Deny**, **View only** or **Allow control**, and nothing is captured before that answer.
- **Pictures and input travel over the Tor circuit:** software H.264 (OpenH264, built from source), with one
  capture and one input backend per operating system.
- **Where Tor is blocked**, Tornect tries obfs4 bridges, then Snowflake, through the bundled lyrebird 0.8.1
  (unmodified from Tor Browser 15.0.23), and runs only the lyrebird whose SHA-256 it has compiled in.
- **The window:** this machine's ID and Tor status, a Connect field, the pairing and session questions, the
  picture in its own window, and, while this screen is shared, a banner and a small "Tornect: sharing" window,
  each with **Stop**. A question's "Allow control", "View only" and "codes match" buttons answer only a mouse
  click, and only once the question has been on screen for a second; keys typed for another program never
  answer them.
- **The command line:** `host`, `connect`, `ping`, `panic`, `doctor`, `id`, `tor-check`, `devices`, `paths`,
  the `unattended` commands, and `service install`, `uninstall` and `status` (start at login).

## What works, and how it was checked

Everything below ran on one machine, the build VM: Ubuntu 26.04, GNOME on Wayland, a VMware virtual GPU. Two
Tornect homes on that machine talked to each other over the real Tor network; no second machine was used.

**Linux (x86_64)**

| What | Evidence |
|---|---|
| Tor directly (14.3 s), through obfs4 bridges (47–78 s) and through Snowflake (16.2 s) | live, 2026-09-21 (bridges forced; no network that really blocks Tor) |
| A host reached over Tor: ping, pairing with matching codes, an attended session, `tornect panic` ending it on both ends | live over Tor, the command line, 2026-09-21 |
| Media over Tor: the test card at 1280×720 and 13 fps; the real Wayland desktop at 3538×1918 and 2.7–3.1 fps with 0 decode errors; `tornect panic` ending the media in about 100 ms | live over Tor, the command line (`tornect host --capture …`, `tornect connect`), 2026-09-22 |
| Wayland capture and pointer injection through the desktop's RemoteDesktop portal (19 fps of capture) | live at the console, 2026-09-22 |
| X11 capture and XTEST input | under Xvfb only, not on a real X11 desktop |
| The window: every screen, the questions, the banner, the "Tornect: sharing" window | unit tests and preview runs under Xvfb; live on 2026-09-24 (the fifth console check): a pairing crossed Tor from one window to the other and the host accepted it, and the first-run grant was verified; a session between the windows over Tor is **not yet performed** (below) |
| Start at login: the systemd user unit, installed, started, stopped and removed; the start-at-login host answers pings only | live, 2026-09-24, with a development build's re-authentication escape: polkit's dialog was not exercised |
| This zip, unpacked: `--version`, `id`, `doctor` (it accepts the bundled `pt/lyrebird`) | live on the build VM, by the release run (`docs/RELEASING.md` step 4) |

**Windows (x86_64)**

| What | Evidence |
|---|---|
| Cross-built with llvm-mingw 20260908; `tornect.exe` imports only DLLs Windows ships | read from the import table |
| This zip, unpacked: `tornect.exe --version`, `id` and `doctor` (it accepts the bundled `pt\lyrebird.exe`); a `--home` outside the user folder refused | **under Wine 10.0 only**, which is not Windows: the release run (`docs/RELEASING.md` step 4) and the check runs of 2026-09-24 |
| Four of the workspace's test binaries (core 157, codec 3, proto 7, input 11 tests) | under Wine 10.0, built 2026-09-23 and not rebuilt since |
| GDI capture, `SendInput`, the DirectX 12 window, Arti and the onion service, the console, the "Tornect: sharing" window, Task Scheduler, the secure credential prompt, UAC, the restricted DLL search | NEEDS-DEVICE: **never run on a Windows machine** |

## Not verified

- **The window over real Tor with a person at the screen.** The console check (grant screen sharing, connect,
  compare the code, allow control, pointer and keys in the viewer, Stop; then view only; then a keyboard answer
  that must end denied) was **NOT PERFORMED four times** (2026-09-23 02:27 and 22:53, 2026-09-24 01:14 and
  16:12): each time the windows were up and the hosts reachable over Tor, and no step was taken at the VM's
  screen. The fifth attempt (2026-09-24, 19:39–20:07) verified the first-run grant live (19:44:08), and the
  pairing crossed Tor (the host accepted at 19:43:57), but the client's 50 s code check ran out unanswered
  (19:44:47), so the client pinned nothing; fixed since (`a4887c2`, `f4bced7`): the window's code check now stays
  up for up to 10 minutes. Everything after the pairing (control, pointer and keys, Stop, view only, the keyboard
  answer) is **NOT PERFORMED**, paused pending a re-run. No input has crossed Tor in a live run, and no key has
  been injected live.
- **The polkit path live:** `service install`, `unattended on` and `grant` through polkit's password dialog.
- **Anything on a real Windows machine**, and any session between a Linux and a Windows machine.
- A real X11 desktop, a real login starting the unit, and the bridge fallback on a network that really blocks
  Tor.
- **The input fixes of the slice-G review on a live desktop:** a vanished viewer's held key let go of over real
  Tor while a picture is being sent (G2-1), and through the Wayland portal; a Stop or `tornect panic` while the
  portal is slow to take input (G1-4); whether GNOME lets go of the keys a closed remote-desktop session held and
  takes its dialog down when the session closes; GNOME's "Stop sharing" and the screen lock ending the session;
  where a click lands after a display scale change; clicks after a screen-size change on a real X11 desktop
  (G2-2).
- How often onion circuits stall for 3 s or more (G2-3).

## Requirements

- **Linux:** x86_64 with **glibc 2.43 or newer** (`ldd --version`): Ubuntu 26.04 has it; Ubuntu 24.04 and
  Debian 13 do not, and there the program stops at once with `version 'GLIBC_2.43' not found`. The window needs
  a Vulkan or OpenGL driver. To share the desktop: a Wayland session with xdg-desktop-portal 1.17 or newer and
  PipeWire (GNOME is the tested one), or an X11 session.
- **Windows:** Windows 10 (20H1 or later) or 11, 64-bit (x64).

## Files and checks

| File | Bytes | SHA-256 |
|---|---|---|
| `tornect-0.1.0-linux-x86_64.zip` | @@SIZE_LINUX@@ | `@@SHA256_LINUX@@` |
| `tornect-0.1.0-windows-x86_64.zip` | @@SIZE_WINDOWS@@ | `@@SHA256_WINDOWS@@` |

With both zips and `SHA256SUMS` in one folder, `sha256sum -c SHA256SUMS` must print `OK` twice (with one zip:
`sha256sum --ignore-missing -c SHA256SUMS`; on Windows, `Get-FileHash <zip>` in PowerShell, compared with the
line in `SHA256SUMS`). Inside each zip, `BUILD-INFO.txt` names the commit, the toolchain, the build flags and
the checks run before the build, and lists the SHA-256 of every other file; lyrebird's equals the pin compiled
into Tornect. Nothing is signed: not the zips, not `SHA256SUMS`, not the programs (Windows may warn).

Built by `cargo xtask dist` at commit `@@COMMIT@@`, with rustc 1.96.0 (LLVM 22.1.2), llvm-mingw 20260908
(clang 23.1.1) for Windows, Ubuntu's gcc 15.2.0 for the C code on Linux, and nasm 3.01. Two builds from scratch
at one commit on the build VM gave bit-identical programs and byte-identical zips; no second machine has tried.

**The advisory check,** cargo-deny 0.20.2, offline, run by `dist` before the build:

@@ADVISORY_DB_LINE@@

<!-- If the final dist needed --allow-old-advisory-db, say so here. -->
Advisories that `deny.toml` ignores, each with its reason:

@@IGNORED_ADVISORIES@@

**RUSTSEC-2026-0285** (GHSA-2mjx-qc3c-rqvc) was found by the refresh of that database and fixed before this
release: rustls 0.23.43 accepted TLS 1.3 handshake messages across a key change within one record (CVSS 3.1
5.3). Tornect reached it through Arti's TLS client on every Tor channel, with no practical impact, since Tor
authenticates relays in its own link handshake. rustls is now 0.23.45 (commit `00bc286`).

**Licences:** each zip carries `THIRD_PARTY_LICENSES.txt`, generated offline from the locally pinned sources:
every crate built into the program with its version, licence and licence texts, the C libraries, the fonts, the
Rust standard library's notices, and on Windows llvm-mingw's runtime. It carries the texts; nobody has reviewed
it legally. Tornect itself is GPL-3.0-or-later (`LICENSE`); lyrebird's licences are in `pt/lyrebird.txt`.

## Two things to know first

**Sharing a Wayland desktop: the grant** (as the zipped README says it). On Wayland, the desktop, not Tornect,
decides what may be shared. The first time, GNOME shows its screen-sharing dialog: pick the screen and turn on
**Allow Remote Interaction** (it starts off; without it the other side can watch but not use the mouse and
keyboard), then Share. Tornect keeps the grant, so later sessions start without the dialog. Do it ahead, in the
window's "Screen sharing on this desktop" card (**Grant screen sharing**); otherwise the dialog appears when a
viewer's picture starts, and someone at this screen must answer it within 30 s. `tornect doctor` names the file
that holds the grant; **Revoke** in the window, or deleting that file, takes it back.

**Windows: the console and Ctrl-C** (as the zipped README says it). Double-clicking `tornect.exe` opens the
window **and a console window**: `tornect.exe` is a console program. Ctrl-C (or Ctrl-Break) in that console
closes Tornect as the main window's close button does, ending every session with a goodbye to the other side;
closing the console window itself ends Tornect at once, without it (neither yet tried on Windows). `tornect
panic` cannot reach a running Windows host yet (its control channel is still to come) and says so. To end every
session at once, press **Ctrl-C in the console where `tornect.exe host` runs**, or press Stop on the banner or
the "Tornect: sharing" window when you use the window.

## Known limitations

By the identifiers of the security reviews that found them.

**Windows**
- **E2-4, the DLL search:** `tornect.exe` restricts the DLLs it loads while it runs to Windows' system folder.
  The seven DLLs it imports at start (bcrypt, bcryptprimitives, dwmapi, dxgi, pdh, powrprof, uxtheme) are marked
  in the executable to be taken from the system folder too (the linker's dependent-load flag), but whether
  Windows honours that mark has not been checked on a Windows machine. Until it is, **keep `tornect.exe` in the
  folder the zip unpacks to, never in a folder other accounts can write to** (a shared Downloads folder, say),
  and never copy it alone into Downloads or onto the Desktop.
  <!-- The final dist run checks DependentLoadFlags: 0x800 on the release exe (llvm-readobj --coff-load-config).
       If it does not show, say instead that these seven DLLs are looked up in tornect.exe's own folder first. -->
- **E2-2:** Tornect gives its directories no access list of its own on Windows yet (M6), so it takes a
  `--home` or `TORNECT_HOME` directory only inside your user folder.
- **E2-5:** the "Tornect: sharing" window can be minimised (also by a viewer with control) and is not brought
  back; it shows on the primary monitor only, while the whole desktop is shared.
- **E2-6:** closing the console window, logging off or shutting down ends Tornect at once: keys the viewer held
  may stay pressed, and `sessions.log` gets no end record. Use Stop, the window's close button, or Ctrl-C.
- **E2-8:** a `tornect.exe` started as administrator while User Account Control is on refuses to accept
  connections: start it normally, administrator access is given per session. Where User Account Control is
  off, every program runs as administrator, so a session with control is administrator access: Tornect offers
  it only as "Allow as administrator", after its own confirmation (a copy run from outside Program Files offers
  View only there).
- **F1-5:** no start-at-login task runs elevated: `service install` registers only the normal task, and first
  removes one that an earlier version registered elevated, through Windows' prompt (a cancelled or failed
  removal fails the install).
- **F-13:** administrator access for a session comes from a separate helper that Windows starts with its own
  prompt, for that session only, and this build keeps the helper switched off. On an administrator account set
  to elevate without prompting, a session with control could make itself administrator unasked, so this build
  shares View only there.
- **F1-1:** `service status` and `uninstall` tell a missing start-at-login task from one this account cannot
  read by looking in the Task Scheduler's folder. That removal path is untested on a Windows machine, like all
  of Task Scheduler, the secure credential prompt and UAC. If either seems wrong, check in an administrator
  console with `schtasks /Query /TN Tornect` and remove the task there with `schtasks /Delete /TN Tornect /F`.
- **F1-6:** one task name, `\Tornect`, per PC: a second Windows account cannot register its own, sees the first
  account's `\Tornect` task, and can remove it through UAC.
- **F1-2's residuals:** after registering, Tornect reads the task back and removes it if it is not the one it
  wrote; it cannot compare a task this account cannot read back, and the task file
  (written under your local application data folder and deleted after registration) has no access list of its
  own.
- **Default 3:** an account that signs in only with Windows Hello (a PIN, a face or a fingerprint), or a
  passwordless Microsoft account, has no password to type in the secure prompt, so it cannot make any change
  that widens access (`service install` and `uninstall`, `unattended on`, `grant`): Tornect refuses them.
- **P-1 (review of the window and the Windows build):** Control Flow Guard is effectively off in `tornect.exe`,
  and it is not marked CET-compatible.

**Linux**
- The start-at-login host answers pings only and refuses every session, because it has no window or terminal to
  show one.
- `service install`, `unattended on` and `grant` need polkit's `org.tornect.policy`, installed from the source
  tree (`packaging/polkit/`). It is not in the zip, so without it they are refused.
- **F2-5:** one start-at-login unit per user: `service install` or `uninstall` with `--home` or `TORNECT_HOME`
  replaces it, and the live-session check then covers only that home.
- **F2-6:** a readiness of `ok` does not prove that the unit starts. Desktops that never start
  `graphical-session.target` (possibly XFCE, MATE, i3; unverified) leave it unstarted: `systemctl --user status
  tornect-host` shows what really happened.

**Both**
- **N-2:** the location checks of `service install` read owners, permission bits and folder names, not access
  lists or junctions. Run it from a folder only you can change, and not from a folder you shared with other
  accounts, even inside your home or user folder.
- **P-1 (review of start at login):** a start-at-login or unattended change made while no host runs does not
  wait the 60 s after a session's end that a running host enforces.
- **G2-3:** when a viewer with control says nothing for 3 s (a Tor stall counts), or keeps sending for 6 s while
  this computer cannot get a picture through to it, this computer lets go of the keys and buttons it holds; a drag
  then ends where the pointer last was.
- No client in this build asks for an unattended session, so an unattended grant cannot yet be used.
- Everything travels over Tor: a few frames per second for a large desktop, and a connection takes from
  seconds to minutes to set up. Direct QUIC with hole punching comes later.
- On GNOME the "Tornect: sharing" window cannot stay above other windows (Wayland does not let it); GNOME shows
  its own screen-sharing icon.

**The build process** (nothing here changes the shipped bytes today)
- **E3-2:** inputs from outside the repository (a user cargo configuration, `CARGO_TARGET_*`, `RUSTC_WRAPPER`,
  `CC`/`CFLAGS`, the host compiler's defaults) would reach the release build unrecorded.
- **E3-5:** `BUILD-INFO.txt`'s Windows lines ("all Windows' own", "UCRT", llvm-mingw's asset hash) rest on a
  deny-list of three name prefixes and a clang version line.
- **P3-I1:** the `deny.toml` checks read line prefixes, so another spelling of the same setting would pass them.
- **P3-I2:** `--allow-old-advisory-db` leaves no mark in the zip.
- **P3-I3:** two xtask tests use predictable folder names in the shared temporary directory.

## Security reviews

The window, the viewer's input, the "Tornect: sharing" window, the Windows build, the packaging and start at
login were reviewed in two ranges (`0e3afea..2480dfb` and `2480dfb..75f6df8`, threat modeling without a
refuter pass). Every fix since was checked against the finding it claims to close, and the release preparation
was reviewed, up to commit `bd8178a`. No Critical or High finding; the three Mediums (a question answered by
keys typed for another program; a start-at-login host that served unattended sessions nobody saw; a failed task
query read as "not registered") and RUSTSEC-2026-0285 are fixed; what is still open is listed above.
The Wayland backend (`d1ef55b..0e3afea`: the unsafe code that talks to PipeWire, the portal and grant handling,
the idle ping and the fixes of that session) was reviewed on 2026-09-24 (slice G: two threat modelers and the
Security parent, read-only, threat modeling without a refuter pass): 0 Critical, 0 High, 0 Medium; six Lows,
fixed in `717d77a`, `79a06b1`, `996e6db`, `4f12573`, `602d0f9` with `117fb34`, and `3379655`; one Info (G2-3,
above). A closure check in three rounds verified all six fixes closed in code (a screen-size change on a real
X11 desktop still needs one, as "Not verified" says) and found the later changes sound (the viewer's code
question, `a4887c2`, and the host's report of a device it paired that then says nothing, `f4bced7`, which only
relabels an outcome). It filed two new Infos, both fixed: N-2, the order in which owed key releases were sent
(`339f785`), and R2-I1, a code-question message that could say "Paired" when nothing had been pinned (`a024c32`,
verified closed in the third round). The third round also read the documentation after `bd8178a` for its security
statements and found none false; nothing above Low is open.
