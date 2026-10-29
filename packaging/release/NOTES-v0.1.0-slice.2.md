<!-- Template: the final dist run fills the marked fields in a copy outside the repository; this committed file keeps the markers.
     Named for the next pre-release after v0.1.0-slice.1 (docs/RELEASING.md, "Tag form"); the owner picks the tag and
     may rename the file and the title. v0.1.0-slice.1 was prepared and never tagged or published.
     Before publishing (each is a row of docs/VERIFICATION.md or docs/notes/m2-state.md):
     - the m2-state blockers: the owner's call on the default STUN servers' published terms, the `live_stun` run and the
       Accept demo on the dev VM ("No zip from `cargo xtask dist` goes to users ... before all three");
     - the dist run at the commit the tag names, both platforms, with the smoke tests of docs/RELEASING.md step 4;
     - the console check of the window over real Tor, or the owner's decision to publish with it NOT PERFORMED;
     - the owner's ruling on the Windows install's lyrebird (decision M1-88 (2));
     - GitHub's private vulnerability reporting turned on (SECURITY.md; ledger row "`SECURITY.md`: how to report a
       vulnerability privately", OPEN);
     - every @@…@@ marker filled from that run (BUILD-INFO.txt, SHA256SUMS, dist's last lines). -->
# Tornect 0.1.0, slice pre-release 2 (`v0.1.0-slice.2`)

**A pre-release, for testing between two machines you control, one Linux and one Windows.** It is not a
milestone release: `m1` (signaling over Tor) and `m2` (direct connections) are not tagged, and their acceptance
runs are open. The pre-release `v0.1.0-slice.1` was prepared in September 2026 and never published, so this is
the first published build. No one has audited Tornect: do not rely on it to protect anything yet. It collects no
telemetry. Read `README-release.md` in the zip first.

## What Tornect is

Tornect lets you see and control another computer, like AnyDesk, without any server of its own. A computer's
Tornect ID is its Tor onion v3 address (Arti, embedded in the program): **Tor finds the other computer and checks
that it is the one you paired with**, so there is no account, no server to trust and no port forwarding. After
the other side accepts, **the two computers connect directly when they can reach each other** (QUIC with both
keys pinned, on the same local network or across the internet), and otherwise the session stays on Tor.

- **Pairing** shows the same 6-digit code on both screens; the two people compare it. The sharing side then
  answers each session with **Deny**, **View only** or **Allow control**, and nothing is captured before that
  answer.
- **While a screen is shared**, a banner and a small "Tornect: sharing" window show it, each with Stop; the panic
  key (Ctrl+Alt+End) and `tornect panic` end every session.
- **Invitations:** Copy invitation, a QR code and `tornect://` links; a link fills the Connect field and never
  connects by itself.
- **Direct connections** on the same network or across the internet (STUN, UPnP/NAT-PMP/PCP, UDP hole punching),
  with Tor as the fallback within 4 seconds.
- **Quality presets** (Best quality, Balanced, Best performance), a large desktop scaled whole, and **switching
  screens** on Windows and X11 hosts.
- **Chat, clipboard text and files** in the session window, each switchable on the shared computer.
- **Unattended access**, opt-in per device, with a password the host never stores (OPAQUE) and an emergency stop
  code.
- **Where Tor is blocked**, obfs4 bridges, then Snowflake, through the bundled lyrebird 0.8.1 (unmodified from
  Tor Browser 15.0.23); Tornect runs only the lyrebird whose SHA-256 it has compiled in.
- **The command line** does everything the window does, and `tornect install`, `service install` and the
  `unattended` commands set Tornect up.

## What is new since slice.1

Each feature below was built after slice.1's preparation (2026-09-24) and checked in the ways its line says.
"VERIFIED (unit)" means unit, property and in-process tests (the window through an egui test harness, the direct
path through an in-memory network, Windows logic under Wine where it runs there); **none of it has run live yet**:
not between two machines, not over real Tor, not at a real desktop and not on Windows. Each NEEDS-DEVICE check has
a row and a recipe in `docs/VERIFICATION.md`.

| Feature | What it does | How it was checked |
|---|---|---|
| The redesigned window (M-UI-1 to M-UI-5) | Home with the ID, saved computers, Knock and Check if reachable; Settings (General, Connection, Security, Sharing, Display and quality, Privacy, About); past sessions; the picture window's toolbar; the list of recent connections off by default | VERIFIED (unit, egui harness) and drawn under Xvfb; NEEDS-DEVICE(linux console), NEEDS-DEVICE(windows) |
| Device words and session levels (M-FEAT-1, M-FEAT-2) | the names people read for a device; what each answer gives (view, control, administrator) | VERIFIED (unit); NEEDS-DEVICE(linux console, windows) |
| Invitations and `tornect://` links (decision M1-73) | Copy invitation, Show QR code, `tornect id --invitation`; an ID, link or whole invitation in the Connect field, `connect` and `ping`; links never act; `tornect install` registers the link handler | VERIFIED (unit, CLI run) 2026-10-24; links in Firefox, Chrome and Edge and the GNOME/KDE handler NEEDS-DEVICE |
| Quality presets (M1-74) | three presets per route (Tor and direct), host-side scaling above 3840×2160 instead of a crop, `connect --quality` | VERIFIED (unit) 2026-10-24 and the loopback demo in one process; the sizes and rates are provisional until measured over real Tor (QUAL-1 … QUAL-6, NEEDS-DEVICE) |
| Switching screens (M1-75, part 1) | the Screens menu and `connect --screen <1..16\|all>` on Windows (GDI) and X11 hosts; the default view is the primary screen | VERIFIED (unit) 2026-10-25, X11 under Xvfb, the Windows logic under Wine 10.0; NEEDS-DEVICE(x11), NEEDS-DEVICE(windows), and over live Tor. The Wayland part is deferred |
| Chat, clipboard text and files (M1-76) | four switches in Settings › Sharing (all on by default; "Let them see and copy files" gives a viewer with control read access to any file the user can open), the banner's "Turn off clipboard and files", files into Downloads › Tornect | VERIFIED (unit) 2026-10-25/26, the Wayland portal part on a fake portal over a private D-Bus; over Tor, on GNOME's portal and on Windows NEEDS-DEVICE (the step 29 live rows) |
| Direct connections (M1-77 to M1-87) | after the accept: candidates over Tor, STUN, router port mapping, hole punching, QUIC with both keys pinned; Tor within 4 s otherwise; `paranoid`, `--tor-only`, the grant's Tor-only switch, `lan_only`, off over a bridge | VERIFIED (unit) 2026-10-26 … 28: property tests, the in-memory NAT matrix, loopback sessions, the redaction end to end; 10-minute coverage-guided fuzz runs without ASan. Live on the dev VM, between two machines, through real routers, CGNAT, IPv6, a VPN and on Windows NEEDS-DEVICE; the default STUN servers' live check NEEDS-DEVICE |
| Unattended access end to end (M-FEAT-4, M-FEAT-5, M-UI-5) | the grant wizard in Settings › Security, the window's Connect without asking, `tornect connect --unattended` (Linux), passwords remembered in the system keychain, the emergency stop code | VERIFIED (unit, and the real host over a pipe); a live unattended session over Tor is OPEN; polkit's dialog and Windows' secure prompt NEEDS-DEVICE |
| The Windows control channel (M-FEAT-5, `53efbaf1`) | `tornect panic` and the `unattended` commands reach a Windows host through a named pipe only this account can open | VERIFIED (unit) for the rules that need no Windows, type-checked for Windows; NEEDS-DEVICE(windows) |
| A Windows window without a console (`da36aba9`) | double-clicking opens no console; command-line runs use `start /wait` | type-checked only; NEEDS-DEVICE(windows) |
| Install, uninstall and start at sign-in (M-FEAT-6, M1-58, M1-69, M1-88) | `tornect install` into `~/.local/bin` (with the pinned lyrebird) or `C:\Program Files\Tornect`; the start at sign-in runs the window in the background | VERIFIED (unit); NEEDS-DEVICE(linux-desktop) with polkit's policy file, NEEDS-DEVICE(windows). The Windows install carries no lyrebird (OPEN, decision M1-88) |
| The code audit of 2026-10-22 (findings B01 to B32) and the final audit before this release (F1 to F9) | each fixed with a test that fails without it, except the open items under *Known limitations* | VERIFIED (unit); the Windows and desktop halves NEEDS-DEVICE as their rows say |
| Logs | a release build writes warnings and errors only; `--log debug` for a bug report | VERIFIED (unit); a release binary NEEDS-DEVICE(the build VM) |

## What works live, and how it was checked

The only live runs so far were made before slice.1's preparation, on the slice's code, on one machine, the build
VM (Ubuntu 26.04, GNOME on Wayland, a VMware virtual GPU). Two Tornect homes on that machine talked to each other
over the real Tor network; no second machine was used.

**Linux (x86_64)**

| What | Evidence |
|---|---|
| Tor directly (14.3 s), through obfs4 bridges (47–78 s) and through Snowflake (16.2 s) | live, 2026-09-21 (bridges forced; no network that really blocks Tor) |
| A host reached over Tor: ping, pairing with matching codes, an attended session, `tornect panic` ending it on both ends | live over Tor, the command line, 2026-09-21 |
| Media over Tor: the test card at 1280×720 and 13 fps; the real Wayland desktop at 3538×1918 and 2.7–3.1 fps with 0 decode errors; `tornect panic` ending the media in about 100 ms | live over Tor, the command line, 2026-09-22 |
| Wayland capture and pointer injection through the desktop's RemoteDesktop portal (19 fps of capture) | live at the console, 2026-09-22 |
| A pairing between two windows over Tor, and the first-run screen-sharing grant | live, 2026-09-24 (the fifth console check); a session between the windows is **not yet performed** |
| X11 capture and XTEST input | under Xvfb only, not on a real X11 desktop |
| This zip, unpacked: `--version`, `id`, `doctor` (it accepts the bundled `pt/lyrebird`) | on the build VM, by the release run (`docs/RELEASING.md` step 4) |

**Windows (x86_64)**

| What | Evidence |
|---|---|
| Cross-built with llvm-mingw 20260908; `tornect.exe` imports only DLLs Windows ships | read from the import table by `dist` |
| This zip, unpacked: `tornect.exe --version`, `id` and `doctor` (it accepts the bundled `pt\lyrebird.exe`); a `--home` outside the user folder refused | **under Wine only**, which is not Windows: the release run (`docs/RELEASING.md` step 4) |
| Parts of the workspace's tests (the Windows logic of capture, input, the session's services, monitor switching) | under Wine 9.0 and 10.0 |
| The window, GDI capture, `SendInput`, Arti and the onion service, the named pipe, the "Tornect: sharing" window, the firewall prompt, the install in Program Files, Task Scheduler, the secure credential prompt, UAC, the restricted DLL search | NEEDS-DEVICE: **never run on a Windows machine** |

## Not verified

- **The window over real Tor with a person at the screen.** The console check (grant screen sharing, connect,
  compare the code, allow control, pointer and keys, Stop; then view only; then a keyboard answer that must end
  denied) was **NOT PERFORMED** four times in September; the fifth attempt verified the first-run grant and paired
  over Tor, then stopped after the pairing. No input has crossed Tor in a live run, and no key has been injected
  live.
- **Anything on a real Windows machine**, and any session between a Linux and a Windows machine.
- **Everything new since slice.1 live** (the table above): direct connections between two machines and through
  real routers, the default STUN servers, unattended access between two machines, chat, clipboard and files over
  Tor, the presets' rates over Tor, switching screens on a real desktop, links from a browser, the install at a real
  desktop.
- **polkit's dialog** (`install`, `service install`, `unattended on`, `grant`) and the start at sign-in at a real
  login.
- A real X11 desktop, KDE, and the bridge fallback on a network that really blocks Tor.
- The 10-minute `cargo-fuzz` campaigns with ASan on this code. `framing`, `envelope`, `store` and `ipc` had
  theirs in August, on older code; since then `stun`, `candidates`, `probe`, `framing`, `envelope`, `media`,
  `services` and `ledger` had coverage-guided 10-minute runs without ASan, and `invite` has only been built.

## Requirements

- **Linux:** x86_64 with **glibc 2.43 or newer** (`ldd --version`): Ubuntu 26.04 has it; Ubuntu 24.04 and
  Debian 13 do not, and there the program stops at once with `version 'GLIBC_2.43' not found`. The window needs
  a Vulkan or OpenGL driver. To share the desktop: a Wayland session with xdg-desktop-portal 1.17 or newer and
  PipeWire (GNOME is the tested one), or an X11 session. Changes that widen access need polkit's policy file,
  which is not in the zip (the zipped README's "The password dialog on Linux").
- **Windows:** Windows 10 (20H1 or later) or 11, 64-bit (x64).

**How the glibc floor was measured.** A Linux executable needs the newest symbol version it was linked against,
and it links against the glibc of the machine that builds it. `objdump -T` on the release executable that
`cargo xtask dist` built on the build VM (Ubuntu 26.04, glibc 2.43) in September 2026 showed libm's `acosf`,
`acoshf`, `asinf`, `atan2f`, `coshf` and `sinhf` at `GLIBC_2.43` and the standard library's `pidfd_spawnp` and
`pidfd_getpid` at `GLIBC_2.39`, all required (`docs/VERIFICATION.md`, row "The Linux executable runs on older
distributions"). On 2026-10-29 a debug build of this branch, made in a container with glibc 2.39, needed at most
`GLIBC_2.39` and took those libm functions at `GLIBC_2.2.5`: so the floor follows the build machine, and the
owner's `dist` run on the build VM decides it. Its `BUILD-INFO.txt` says, for this release:

    @@NEWEST_VERSIONS_LINUX@@

<!-- Copy BUILD-INFO.txt's "newest versions" line of the Linux zip here. If its GLIBC_ is not 2.43, change the
     Requirements above, the zipped README's Linux section and README.md's platform table to match. -->

## Files and checks

Download Tornect only from https://github.com/Mxrider007/Tornect/releases, the one place its zips and
`SHA256SUMS` are published, and the one an invitation names. A copy offered anywhere else, or a download link
someone sends with a Tornect ID, may not be Tornect.

| File | Bytes | SHA-256 |
|---|---|---|
| `tornect-0.1.0-linux-x86_64.zip` | @@SIZE_LINUX@@ | `@@SHA256_LINUX@@` |
| `tornect-0.1.0-windows-x86_64.zip` | @@SIZE_WINDOWS@@ | `@@SHA256_WINDOWS@@` |

With both zips and `SHA256SUMS` in one folder, `sha256sum -c SHA256SUMS` must print `OK` twice (with one zip:
`sha256sum --ignore-missing -c SHA256SUMS`; on Windows, `Get-FileHash <zip>` in PowerShell, compared with the
line in `SHA256SUMS`). Inside each zip, `BUILD-INFO.txt` names the commit, the toolchain, the build flags and
the checks run before the build, and lists the SHA-256 of every other file; lyrebird's equals the pin compiled
into Tornect. Nothing is signed: not the zips, not `SHA256SUMS`, not the programs (Windows may warn).

Built by `cargo xtask dist` at commit `@@COMMIT@@`, with rustc 1.96.0 (`rust-toolchain.toml`), llvm-mingw
20260908 for Windows, and the build machine's C compiler and nasm (`BUILD-INFO.txt` names each version). In
September two builds from scratch at one commit on the build VM gave bit-identical programs and byte-identical
zips; this commit's build has not been repeated, and no second machine has tried.

**The advisory check,** cargo-deny 0.20.2, offline, run by `dist` before the build:

@@ADVISORY_DB_LINE@@

<!-- If the final dist needed --allow-old-advisory-db, say so here. -->
Advisories that `deny.toml` ignores, each with its reason:

@@IGNORED_ADVISORIES@@

**Licences:** each zip carries `THIRD_PARTY_LICENSES.txt`, generated offline from the locally pinned sources:
every crate built into the program with its version, licence and licence texts, the C libraries, the fonts, the
Rust standard library's notices, and on Windows llvm-mingw's runtime. It carries the texts; nobody has reviewed
it legally. Tornect itself is GPL-3.0-or-later (`LICENSE`); lyrebird's licences are in `pt/lyrebird.txt`.

## Things to know first

**Direct connections show your IP address.** After you accept a session, the other computer (a view-only one
included) learns this computer's local and public IP addresses, and so does a computer you connect to. One
public STUN server per session (by default from Cloudflare, Google, Twilio or Nextcloud) sees this computer's IP
address and when the session starts, never with whom when both computers use the same list; the router is asked
to open one UDP port for the session; the internet provider may recognise the traffic as Tornect. The window's
question says so before you decide. "Allow direct connections" in Settings › Connection, `paranoid = true` under
`[network]`, `tornect connect --tor-only` or a grant's "Pictures and input through Tor only" keeps sessions on
Tor; direct connections are off while Tor uses a bridge.

**A viewer with control can copy your files by default.** Settings › Sharing's four switches are on by default,
and "Let them see and copy files" lets a session with control see and copy any file you can open on this computer
(Tornect's own folders excepted). Turn off what you do not want before you accept.

**Sharing a Wayland desktop: the grant.** On Wayland, the desktop, not Tornect, decides what may be shared. The
first time, GNOME shows its screen-sharing dialog: pick the screen and turn on **Allow Remote Interaction** (it
starts off; without it the other side can watch but not use the mouse and keyboard), then Share. Do it ahead, in
the window's **Grant screen sharing**; otherwise someone at this screen must answer the dialog within 30 s.

**Windows: the window, the console and Ctrl-C.** Double-clicking `tornect.exe` opens the window, with no console
window. From `cmd`, start each command with `start /wait` (`start /wait tornect.exe host`). Ctrl-C in that
console ends a `tornect.exe host` with a goodbye to the other side; Ctrl-Break, or closing the console window,
ends it at once, without one. `start /wait tornect.exe panic` in a second console ends every session through the
host's named pipe (none of this yet tried on Windows).

**Linux: polkit's policy file.** `tornect install`, `service install`, `unattended on`, `grant` and the other
changes that widen access are refused until `packaging/polkit/org.tornect.policy`, taken from the source at the
commit `BUILD-INFO.txt` names, is installed into `/usr/share/polkit-1/actions/` (the zipped README gives the two
commands).

## Known limitations

- **No sound:** the other computer's audio is not sent (planned, M5).
- **No macOS version yet** (planned, M6).
- A Wayland host shares the one screen picked in its dialog (no Screens menu), and no clipboard (`[services]
  wayland_clipboard`, off until checked on GNOME).
- **Software H.264 only** (OpenH264): no hardware encoding yet (planned, M3); a large desktop over Tor gets a few
  pictures a second. The presets' sizes and rates are provisional until measured over real Tor and real direct
  paths.
- Unless the two computers can reach each other directly, everything travels over Tor: at most about 16 pictures
  a second, and files and clipboard text at about 200 KB/s. Direct connections across the internet have run only
  in simulation.
- An unattended session has not yet been run between two machines over Tor. The Windows command line cannot ask
  for an unattended password: give grants in the window there, and `connect --unattended` uses only a password
  remembered in the window.
- The Windows install (`tornect install`) carries no lyrebird: the copy in `C:\Program Files\Tornect` cannot use
  obfs4 or Snowflake bridges (decision M1-88, open). Where Tor is blocked, run the unpacked copy.
- **B01:** a Windows host that locks keeps its sessions, the picture standing still, for up to a minute before
  capture ends, instead of ending them at once.
- A `config.toml` setting whose value this build does not know (a later version's value, or a typo) stops
  Tornect from starting, with "cannot parse configuration" and the file, line and setting. Correct that line or
  delete it: a deleted setting takes its default.

By the identifiers of the security reviews that found them:

**Windows**
- **E2-4, the DLL search:** `tornect.exe` restricts the DLLs it loads while it runs to Windows' system folder.
  The DLLs it imports at start are marked in the executable to be taken from the system folder too (the
  linker's dependent-load flag), but whether Windows honours that mark has not been checked on a Windows machine.
  Until it is, **keep `tornect.exe` in the folder the zip unpacks to, never in a folder other accounts can write
  to** (a shared Downloads folder, say), and never copy it alone into Downloads or onto the Desktop.
  <!-- The final dist run checks DependentLoadFlags: 0x800 on the release exe (llvm-readobj --coff-load-config).
       If it does not show, say instead that these DLLs are looked up in tornect.exe's own folder first. -->
- **E2-2:** Tornect gives its directories no access list of its own on Windows yet (M6), so it takes a
  `--home` or `TORNECT_HOME` directory only inside your user folder.
- **E2-5:** the "Tornect: sharing" window can be minimised (also by a viewer with control) and is not brought
  back.
- **E2-6:** closing the console window of a command-line `tornect.exe host` (started with `start /wait`),
  Ctrl-Break in it, logging off or shutting down ends Tornect at once: keys the viewer held may stay pressed, and
  `sessions.log` gets no end record. Use Stop, the window's close button, or Ctrl-C. The double-clicked window has
  no console.
- **E2-8:** a `tornect.exe` started as administrator while User Account Control is on refuses to accept
  connections: start it normally. Where User Account Control is off, every program runs as administrator, so a
  session with control is administrator access: Tornect offers it only as "Allow as administrator", after its
  own confirmation (a copy run from outside Program Files offers View only there).
- **F-13:** administrator access for a session comes from a separate helper that Windows starts with its own
  prompt, and this build keeps the helper switched off. On an administrator account set to elevate without
  prompting, a session with control could make itself administrator unasked, so this build shares View only
  there.
- **F1-1, F1-2, F1-5, F1-6:** the start-at-sign-in task `\Tornect` is one per PC, never elevated, read back
  after registering; Task Scheduler, the secure credential prompt and UAC are untested on a Windows machine. If
  `service status` or `uninstall` seems wrong, check in an administrator console with `schtasks /Query /TN
  Tornect` and remove the task with `schtasks /Delete /TN Tornect /F`.
- **Default 3:** an account that signs in only with Windows Hello (a PIN, a face or a fingerprint), or a
  passwordless Microsoft account, has no password to type in the secure prompt, so it cannot make any change
  that widens access: Tornect refuses them.
- **P-1 (review of the window and the Windows build):** Control Flow Guard is effectively off in `tornect.exe`,
  and it is not marked CET-compatible.

**Both**
- **N-2:** the location checks of `service install` read owners, permission bits and folder names, not access
  lists or junctions. Run it from a folder only you can change.
- **G2-3:** when a viewer with control says nothing for 3 s (a Tor stall counts), or keeps sending for 6 s while
  this computer cannot get a picture through to it, this computer lets go of the keys and buttons it holds; a drag
  then ends where the pointer last was.
- On GNOME the "Tornect: sharing" window cannot stay above other windows (Wayland does not let it); GNOME shows
  its own screen-sharing icon. A screen locker that does not tell logind (xscreensaver, swaylock) does not pause
  files and the clipboard.
- **LOW-1 (invitations):** another program's machine-wide registration of `tornect:` links on Windows
  (`HKLM\Software\Classes\tornect`) is not looked at, and the per-user one `tornect install` writes takes priority
  for this user (the owner's decision, open).

**The build process** (nothing here changes the shipped bytes today)
- **E3-2:** inputs from outside the repository (a user cargo configuration, `CARGO_TARGET_*`, `RUSTC_WRAPPER`,
  `CC`/`CFLAGS`, the host compiler's defaults) would reach the release build unrecorded.
- **E3-4:** since 2026-10-26, when the Tor Browser signing subkey expired, the lyrebird check accepts an
  expired-key signature only when it is dated before the expiry. That date is the signer's own claim; the
  SHA-256 pins still decide what ships.
- **E3-5:** `BUILD-INFO.txt`'s Windows lines rest on a deny-list of three name prefixes and a clang version line.
- **P3-I1, P3-I2, P3-I3:** the `deny.toml` checks read line prefixes; `--allow-old-advisory-db` leaves no mark in
  the zip; two xtask tests use predictable folder names in the shared temporary directory.

## Not in this version

- Sound: the other computer's audio is not sent.
- Session recording: not available (Save a screenshot saves single pictures).
- Remote printing: not available.
- Wake-on-LAN: a sleeping or switched-off computer cannot be woken from Tornect.
- Remote restart and automatic reconnect: not available; after a dropped session press Try again.
- TCP tunnelling, VPN and remote shell: not available.
- Phones and tablets: no Android or iOS app yet (Android is on the roadmap).
- macOS: not supported in this version.
- Privacy mode (black screen) and blocking the remote person's keyboard and mouse: not available.
- Whiteboard (drawing on the other screen): not available.
- Switch sides: not available; the other person connects to you instead.
- Short IDs and aliases: the Tornect ID is 56 characters; share it with Copy invitation, a `tornect://` link or
  the QR code.
- Connection speed: finding the other computer over Tor takes 5–30 seconds (up to a minute), and a computer that
  just started Tornect is reachable after one to a few minutes.
- Before sign-in: Tornect cannot show the Windows sign-in or lock screen, UAC prompts or Ctrl+Alt+Del, and after
  a restart a computer is unreachable until someone signs in.
- Several screens on a Wayland (GNOME) computer: only the screen chosen in the desktop's sharing dialog is shown;
  switching needs a Windows or X11 host.
- Clipboard: plain text only, in control sessions; a GNOME/Wayland computer shares none unless `[services]
  wayland_clipboard` is turned on.
- File transfer: files one by one, never a folder (up to two each way at once, the rest queued), into Downloads ›
  Tornect, started from the viewing computer in control sessions; drag and drop not on Wayland.
- Address book: no online status, no groups or tags, kept on this computer only (use Check if reachable to see
  whether a computer answers).
- One session at a time: you view one computer at a time, and a computer being viewed refuses other requests
  until that session ends.
- Tray icon: none; closing the window stops Tornect (minimise it to stay reachable).
- Updates: Tornect does not update itself; download new versions from the releases page.
- Video: software H.264 only (no GPU encoding); over Tor about 16 pictures a second at most.
- Linux: needs glibc 2.43 or newer (Ubuntu 26.04); Ubuntu 24.04, Debian 13 and older are not supported by this
  build.
- Signing: the programs are not code-signed; Windows SmartScreen may warn before the first start.
- Local network discovery: not available; every computer is reached by its Tornect ID.
- Lock on session end: the computer is not locked automatically when a session ends.
- Installing: no installer yet; unzip, then run `tornect install` in a terminal to add the menu entry and
  `tornect://` links.

## Security reviews

**No external audit has been done.** Every review below was made within the project: reviewers reading the code
and its tests against the plan's threat model (`docs/PLAN.md` §B.6, §B.8), not an outside firm. No review found a
Critical or High issue; every Medium was fixed.

- **Up to slice.1** (unchanged): the window, the viewer's input, the "Tornect: sharing" window, the Windows build,
  the packaging and start at login (`0e3afea..2480dfb`, `2480dfb..75f6df8`), the Wayland backend
  (`d1ef55b..0e3afea`), the fix-closure checks and the release preparation up to `bd8178a`: three Mediums, all
  fixed; RUSTSEC-2026-0285 (rustls) fixed by rustls 0.23.45 (`00bc286`).
- **The redesign and unattended access** (2026-09-27 to 2026-10-09): reviewed in rounds whose findings were fixed
  or recorded before the tag (`docs/VERIFICATION.md`, the sections *Before the tag: …*).
- **The code audit of 2026-10-22** (findings B01 to B32, *Audit fixes*): each fixed with a test, or open as listed
  above.
- **Invitations** (M1-73): a self-review (one Low open, LOW-1 above) and an independent security and correctness
  review of `4929ae57..8e9b954b` (0 blocker, 0 major, 11 minor; 10 fixed, one recorded). **The fixes after it
  (`8e9b954b..0cb245d5`) have had no security review of their own** (OPEN).
- **Quality presets** (M1-74): a security reviewer's run per part, and final security and correctness reviews of
  `9af40339..d2c453fe` (security: 6 minor; correctness: 2 major, 5 minor), each finding fixed or answered.
- **Switching screens** (M1-75): a security review of the whole feature (`d1eb85d4..fdb072d0`) by a session that
  wrote none of it, and a final security and correctness review of `d1eb85d4..904904e9`: six minor findings, fixed.
- **Chat, clipboard and files** (M1-76): security reviews of its steps, a security review of the services diffs
  (`c6a40bb2..d7a329db`: one Medium, fixed in `d7a329db`) and a final security and correctness review of
  `c6a40bb2..96b67647`: five minor findings, fixed.
- **Direct connections** (M1-77 to M1-87): reviews of each step, a security review of the whole feature (step C2:
  no code defect, one coverage gap closed) and a final security and correctness review of `cc918b56..1aeaea49`:
  three minor findings, fixed in `0ac8dd03`, `625aabdc` and `03cbfc95`.
- **The final audit before this release** (2026-10-28): two major and seven minor findings, fixed in `66c03834`,
  `81c17944`, `9a64b5f9`, `0a503bd1` and `5a507b1f`, except the Windows half of F1/F4 (decision M1-88, open).

**Not reviewed:** the final audit's fixes above, the documentation since them, and the commits between the last
review and `@@COMMIT@@` that the owner's release run adds.
