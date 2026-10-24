# Tornect: a pre-release build (the vertical slice)

Tornect shares one computer's screen with another over Tor. A computer's
Tornect ID is its Tor onion address, so it needs no server, no account and no
port forwarding. This is a **pre-release** for testing between two machines
you control, one Linux and one Windows. No one has audited it: do not rely on it
to protect anything yet. It collects no telemetry.

## What is in this zip

| File | What it is |
|---|---|
| `tornect` (`tornect.exe` on Windows) | the program: the window, and the command line |
| `pt/lyrebird` (`pt/lyrebird.exe`) | lyrebird 0.8.1, the Tor Project's pluggable transport for obfs4 and Snowflake bridges, unmodified from Tor Browser 15.0.23 |
| `pt/lyrebird.txt` | lyrebird's licences |
| `LICENSE` | Tornect's licence, GPL-3.0-or-later |
| `THIRD_PARTY_NOTICES.md` | what else Tornect's own source contains, and under which licences |
| `THIRD_PARTY_LICENSES.txt` | every third-party part built into the program (each crate with its version and licence, the C libraries, the fonts, the Rust standard library) and their licence texts |
| `BUILD-INFO.txt` | the commit, toolchain and flags of this build, the advisory database it was checked against, and each file's SHA-256 |

Keep `pt/` next to the program. Tornect needs lyrebird only when Tor is blocked
where you are, and it runs the copy in `pt/` only if its SHA-256 is the one
compiled into Tornect.

## Check the download first

Download Tornect only from https://github.com/Mxrider007/Tornect/releases, the
one place its zips and `SHA256SUMS` are published, and the one an invitation
names. A copy offered anywhere else, or a download link someone sends with a
Tornect ID, may not be Tornect.

The release page lists each zip's SHA-256 in `SHA256SUMS`. With the zip and
`SHA256SUMS` in one folder:

    sha256sum --ignore-missing -c SHA256SUMS                  (Linux)
    Get-FileHash .\tornect-<version>-windows-x86_64.zip       (Windows PowerShell)

`sha256sum` must print `OK`; on Windows, compare the hash it prints with the
line in `SHA256SUMS`. Neither the zips nor the programs are signed.

## Linux

You need x86_64 Linux with **glibc 2.43 or newer**: `ldd --version` shows
yours. Ubuntu 26.04 has it; Ubuntu 24.04 and Debian 13 do not, and there this
build stops at once with "version `GLIBC_2.43' not found" (`BUILD-INFO.txt`
names the exact versions). The window needs a Vulkan or OpenGL driver. To
share this desktop you need either a Wayland session with xdg-desktop-portal
1.17 or newer and PipeWire (GNOME is the tested one), or an X11 session.

    unzip tornect-<version>-linux-x86_64.zip
    cd tornect-<version>-linux-x86_64
    ./tornect doctor

`tornect doctor` reports the session type, how this desktop would be shared,
Tornect's directories, and on the `tor:` line the lyrebird it found: that must
be `…/pt/lyrebird`. If the line says `UNAVAILABLE`, see the reason it gives. A
tool that did not keep the file modes needs `chmod 755 tornect pt/lyrebird`,
and Tornect refuses a lyrebird that other users can write to.

**The window:** `./tornect` with nothing after it. It shows this machine's
Tornect ID (give it to the other person over a channel you trust) and whether
Tor is connected, which takes from a few seconds to a few minutes. To reach the
other machine, paste its Tornect ID and press Connect. The first time, both
screens show the same code: compare them (by phone, say), then press "Yes, the
codes match" on the side that connects and "The codes match: pair" on the side
that shares. The sharing side then asks "Deny", "View only" or "Allow control".
Only a mouse click answers "Allow control", "View only" and the two "codes
match" buttons, and only once the question has been on screen for a second:
keys typed for another program never answer it. Deny also works from the keyboard.
The picture opens in its own window; "End the session" or closing that window
ends it. While your screen is shared, a banner and a small "Tornect: sharing"
window show it, each with **Stop**. `./tornect gui --no-host` only connects to
others, publishing no ID and answering no one. Ctrl-C in the terminal that
started the window, or a `kill`, closes it the same way, ending every session
with a goodbye.

**The command line** does the same, one role per terminal:

    ./tornect host              # share this desktop; answer pairing and session questions here
    ./tornect connect <ID>      # connect to a host; compare the code, then wait for its answer
    ./tornect ping <ID>         # is that host reachable over Tor? (no pairing needed)
    ./tornect panic             # end every session the running host serves

`tornect host` prints `Tornect ID: …` at once (on a terminal, or with
`--evidence`) and `REACHABLE` once the address is published, typically one to a
few minutes later. For a new device it shows
the code and asks you to type `yes` if it matches the other screen; for each
session it asks for `a` (allow control) or `v` (view only). Anything else, or no
answer within 60 s, refuses.
`tornect connect` shows no picture (use the window for that): it pairs, asks for
the session and reports what it receives until Ctrl-C. `--capture test-card`
(for `host` and `gui`) shares a synthetic picture instead of the desktop.
`./tornect --help` lists everything, including `--bridges`, `tor-check`,
`devices` and `paths`.

**Sharing a Wayland desktop: the grant.** On Wayland, the desktop, not
Tornect, decides what may be shared. The first time, GNOME shows its
screen-sharing dialog: pick the screen and turn on **Allow Remote Interaction**
(it starts off; without it the other side can watch but not use the mouse and
keyboard), then Share. Tornect keeps the grant, so later sessions start without
the dialog. Do it ahead, in the window's "Screen sharing on this desktop" card
(**Grant screen sharing**); otherwise the dialog appears when a viewer's picture
starts, and someone at this screen must answer it within 30 s. `tornect doctor`
names the file that holds the grant; **Revoke** in the window, or deleting that
file, takes it back.

## Windows

You need Windows 10 (version 20H1 or later) or 11, 64-bit. Right-click the zip,
Extract All, and keep `pt\` beside `tornect.exe`. Windows may warn that the
program is not recognised: it is not code-signed.

Double-clicking `tornect.exe` opens the window **and a console window**:
`tornect.exe` is a console program. Ctrl-C (or Ctrl-Break) in that console
closes Tornect as the main window's close button does, ending every session with
a goodbye to the other side; closing the console window itself ends Tornect at
once, without it (neither yet tried on Windows). The window works as on Linux
above; Windows asks for no grant.

From a console in the folder (`cmd` or PowerShell):

    .\tornect.exe doctor
    .\tornect.exe host
    .\tornect.exe connect <ID>

**Ending sessions on Windows: Ctrl-C.** `tornect panic` cannot reach a running
Windows host yet (its control channel is still to come) and says so. To end
every session at once, press **Ctrl-C in the console where `tornect.exe host`
runs**, or press Stop on the banner or the "Tornect: sharing" window when you
use the window.

## Start at logon

`tornect service install` registers Tornect (this executable) to start after
you log in; `tornect service status` shows what is registered; `tornect service
uninstall` removes it. Started at login, Tornect runs in the background with
its window minimised where the desktop allows it; a request raises the window.
Unattended sessions wait until its sharing indicator has been shown. Starting
at sign-in means a Tor connection at every sign-in: your local network and your
internet provider can see that this computer uses Tor. Installing and removing
ask for your OS password (the change widens access) and are refused while a
remote session is live or ended less than a minute ago. Nothing starts before a
login: Tornect never turns on automatic login, so after a reboot the computer
stays unreachable until someone logs in. Run `service install` from a folder
only you can change, and not from a folder you shared with other accounts, even
inside your home or user folder: the check reads owners, permission bits and
folder names, not access lists. A `tornect host` started without a terminal (by
a script, or by the systemd user unit an earlier version registered) is another
matter: the host answers pings only and refuses every session, because it has
no window or terminal to show one.

- **Linux:** an XDG autostart entry, `~/.config/autostart/tornect.desktop`,
  which your desktop runs when your graphical session starts
  (`tornect --background`). `service install` removes the systemd user unit an
  earlier version registered (`tornect-host.service`), and `service status`
  names one that is still there. `service install` is refused while a Tornect
  host runs for this home: close its window, or stop it with Ctrl-C in its
  terminal (`systemctl --user stop tornect-host` for a host that the older unit
  started), so that what is registered is the `tornect` you run. Keep `tornect`
  in a folder only you (or root) can change: `service install` refuses a
  `tornect` another account could replace (under `/tmp` or a shared folder, or
  owned by another account) and a path with `$`, quotes or backslashes. The
  password dialog is polkit's `org.tornect.autostart` action, so
  `packaging/polkit/org.tornect.policy` must be installed. Remove it with
  `tornect service uninstall` (or by deleting the file). Whether GNOME or KDE
  minimise the window, and whether the entry runs inside your login session, is
  not yet checked.
- **Windows:** a Task Scheduler task `\Tornect` that runs
  `tornect.exe --background` when you log on: Tornect's window, minimised. The
  password dialog is Windows' secure credential prompt: choose your password,
  not a PIN. An account that signs in only with Windows Hello (a PIN, a face or
  a fingerprint) or a passwordless Microsoft account has no password to type
  there, so it cannot make any change that widens access (`service install` and
  `uninstall`, `unattended on`, `grant`): Tornect refuses them. `service
  install` refuses a `tornect.exe` outside your user folder or
  `C:\Program Files`, where another account could replace it. The task never
  runs elevated (one that an earlier version registered elevated is removed
  first, through Windows' prompt). Administrator access is given per session,
  by a separate helper that Windows starts with its own prompt, and this build
  keeps that helper switched off. On an administrator account set to elevate
  without prompting, a session with control could make itself administrator
  unasked, so this build shares View only there. Where User Account Control is
  off, every program runs as administrator: a session with control is then
  administrator access, offered only as "Allow as administrator" after
  Tornect's own confirmation (a copy not under `C:\Program Files` offers View
  only there). A `--home` or `TORNECT_HOME` directory is refused on Windows.
  Close a running Tornect (or press Ctrl-C in the console of a
  `tornect.exe host`) before `tornect service uninstall`; `schtasks /Delete /TN
  Tornect /F` also removes it. Not yet tried on Windows.

## Where Tornect keeps its state

`tornect paths` prints the directories: the keys of this machine's Tornect ID,
the paired devices, `config.toml` and `sessions.log` (every pairing and session,
kept on this machine). `--home <dir>` (or `TORNECT_HOME`) puts all of it
elsewhere, so two copies can run side by side on one machine. On Windows that
directory must be inside your user folder (`C:\Users\<you>`), and Tornect
refuses one elsewhere: it does not yet give its directories permissions of their
own, and anywhere else other accounts on the PC could read and change its keys.

## Known limitations of this build

- Tested on one Linux machine (GNOME on Wayland) only. **Nothing has run on a
  real Windows machine yet**: only under Wine, which is not Windows. The window
  has not yet been used by a person for a whole session between two machines.
- Everything travels over Tor: pictures are slow (a few frames per second for a
  large desktop), and a connection takes from seconds to minutes to set up.
- On GNOME, the "Tornect: sharing" window cannot stay above other windows
  (Wayland does not let it); GNOME shows its own screen-sharing icon.
- The zips and the programs are not signed.

## Licences and source

Tornect is free software under the GNU General Public License, version 3 or
later (`LICENSE`); `BUILD-INFO.txt` names the commit this build came from.
The program also contains other people's code under their own licences:
`THIRD_PARTY_LICENSES.txt` names every part, with its version and licence, and
holds their licence texts. lyrebird is BSD-2-Clause and contains
GPL-3.0-or-later code; its source is the tag `lyrebird-0.8.1` at
https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird
(`THIRD_PARTY_NOTICES.md`).
