# Tornect: a pre-release build

Tornect lets you see and control another computer, like AnyDesk or
TeamViewer, without any server of its own. A computer's Tornect ID is its Tor
onion address: Tor finds the other computer and checks that it is the one you
paired with, so there is no account, no server to trust and no port to
forward. After the other side accepts, the two computers connect directly
when they can reach each other (on the same local network or across the
internet), which is much faster; otherwise the session goes over Tor
("Direct connections" below).

This is a **pre-release** for testing between two machines you control, one
Linux and one Windows. No one has audited it: do not rely on it to protect
anything yet. It collects no telemetry. Much of it has not yet run on a real
desktop, between two real networks or on Windows at all ("What has been tried,
and where" below).

## What is in this zip

| File | What it is |
|---|---|
| `tornect` (`tornect.exe` on Windows) | the program: the window, and the command line |
| `pt/lyrebird` (`lyrebird.exe` beside `tornect.exe` on Windows) | lyrebird 0.8.1, the Tor Project's pluggable transport for obfs4 and Snowflake bridges, unmodified from Tor Browser 15.0.23 |
| `pt/lyrebird.txt` (`lyrebird.txt` on Windows) | lyrebird's licences |
| `polkit/org.tornect.policy` (Linux only) | polkit's policy file, which the password dialog on Linux needs ("The password dialog on Linux" below) |
| `LICENSE` | Tornect's licence, GPL-3.0-or-later |
| `THIRD_PARTY_NOTICES.md` | what else Tornect's own source contains, and under which licences |
| `THIRD_PARTY_LICENSES.txt` | every third-party part built into the program (each crate with its version and licence, the C libraries, the fonts, the Rust standard library) and their licence texts |
| `BUILD-INFO.txt` | the commit, toolchain and flags of this build, the advisory database it was checked against, and each file's SHA-256 |

Keep `pt/` next to the program (on Windows, `lyrebird.exe` beside
`tornect.exe`). Tornect needs lyrebird only when Tor is blocked where you are,
and it runs that copy only if its SHA-256 is the one compiled into Tornect.

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
Tornect's directories, whether direct connections are on, and on the `tor:`
line the lyrebird it found: that must be `…/pt/lyrebird`. If the line says
`UNAVAILABLE`, see the reason it gives. A tool that did not keep the file modes
needs `chmod 755 tornect pt/lyrebird`, and Tornect refuses a lyrebird that
other users can write to. `./tornect` with nothing after it opens the window
("Using the window" below).

**The password dialog on Linux.** Every change that widens access asks for
your password through polkit: `tornect install` and `uninstall`, `service
install` and `uninstall`, unattended access (`unattended on`, `grant`,
`set-password`, `enable`, `resume`, `unlock`, and the window's Unattended access
section, including the acknowledgement of its banner) and `backup export` and
`import`. polkit needs Tornect's policy file, `polkit/org.tornect.policy` in
this zip. Install it once as root, from the unpacked folder:

    sudo install -m 0644 polkit/org.tornect.policy /usr/share/polkit-1/actions/
    sudo systemctl restart polkit

Until it is installed, those changes are refused with "polkit action
`org.tornect.…` is not registered on this host". Sharing, connecting and
pairing do not need it. polkit's dialog has not yet been tried with this
build.

**Sharing a Wayland desktop: the grant.** On Wayland, the desktop, not
Tornect, decides what may be shared. The first time, GNOME shows its
screen-sharing dialog: pick the screen and turn on **Allow Remote Interaction**
(it starts off; without it the other side can watch but not use the mouse and
keyboard), then Share. Tornect keeps the grant, so later sessions start without
the dialog. Do it ahead, in the window's "Screen sharing on this desktop" card
(**Grant screen sharing**); otherwise the dialog appears when a viewer's picture
starts, and someone at this screen must answer it within 30 s. `tornect doctor`
names the file that holds the grant; **Revoke** in the window, or deleting that
file, takes it back. A Wayland desktop shares the one screen picked in that
dialog.

## Windows

You need Windows 10 (version 20H1 or later) or 11, 64-bit. Right-click the zip,
Extract All, and keep `lyrebird.exe` beside `tornect.exe`. Windows may warn
that the program is not recognised: it is not code-signed.

Double-clicking `tornect.exe` opens the window, with no console window
(`tornect.exe` is a window program). Its close button ends every session with a
goodbye to the other side. The window works as "Using the window" below says;
Windows asks for no grant.

From a console in the folder (`cmd`), start each command with `start /wait`.
Without it `cmd` gives its prompt back at once, and the questions of `tornect
host` then share the console with `cmd`:

    start /wait tornect.exe doctor
    start /wait tornect.exe host
    start /wait tornect.exe connect <ID>

In PowerShell, type `cmd` first and use the same lines. Ctrl-C in that console
ends a `tornect.exe host` with a goodbye to the other side. Ctrl-Break, or
closing the console window, ends it at once, without one (none of this yet
tried on Windows). `tornect.exe doctor > doctor.txt` writes the report to a
file; on its `tor:` line it names the lyrebird it found, which must be the
`lyrebird.exe` beside `tornect.exe`.

**Ending sessions on Windows.** `start /wait tornect.exe panic`, run in a
second console, ends every session of the Tornect running for this home (the
default one, or the one `--home` names). It goes through Tornect's control
channel, a named pipe that only this Windows account can open (not yet tried
on Windows). Stop on the banner or on the "Tornect: sharing" window, the
window's close button, and Ctrl-C in the console where `start /wait tornect.exe
host` runs end them too.

## Using the window

**Your ID and invitations.** Home shows this computer's Tornect ID, with
**Copy ID**, **Copy invitation** and **Show QR code**. Send the invitation (the
ID, a `tornect://` link and where to download Tornect) to the other person over
a channel you trust; `tornect id --invitation` prints it too. Home also says
whether Tor is connected and whether this ID is reachable, which takes from a
few seconds to a few minutes after Tornect starts.

**Connecting.** Paste the other computer's Tornect ID, its `tornect://` link or
its whole invitation into the Connect field and press Connect. A link only
fills the field: it never connects by itself. The first time, both screens show
the same code: compare them (by phone, say), then press "Yes, the codes match"
on the side that connects and "The codes match: pair" on the side that shares.
The sharing side then asks "Deny", "View only" or "Allow control". Only a mouse
click answers "Allow control", "View only" and the two "codes match" buttons,
and only once the question has been on screen for a second: keys typed for
another program never answer it. Deny also works from the keyboard. A computer
you paired with stays on Home: **Knock** asks for a session again (the person
there answers), and **Check if reachable** asks whether it answers.

**The session.** The picture opens in its own window, with a toolbar:
**Quality** (Best quality, Balanced, Best performance; Settings › Display and
quality sets the default), **Screens** where the other computer has several and
shares them (Windows and X11), **Chat**, **Files**, the **Clipboard** switch,
**Send keys** (key combinations, in a control session), Pause my input, Save a
screenshot, Fullscreen and **End session**. Closing that
window ends the session too. The window says whether the picture comes
directly (local network or internet) or is relayed through Tor.

**While your screen is shared**, a banner and a small "Tornect: sharing" window
show it, each with a Stop button. The panic key, Ctrl+Alt+End by default
(`panic_key` under `[security]`), ends every session: on Windows through a
keyboard hook, on Linux where the desktop offers its global-shortcuts portal
(the desktop may ask you to confirm the key; neither yet tried on a real
desktop). `./tornect gui --no-host` only connects to
others, publishing no ID and answering no one. On Linux, Ctrl-C in the terminal
that started the window, or a `kill`, closes it the same way, ending every
session with a goodbye.

## Chat, clipboard and files

The picture window's toolbar has **Chat**, **Files** and a **Clipboard**
switch. What someone connected to *this* computer may use is set in Settings ›
Sharing, and every switch there is on by default:

- **Chat**: they can write to you, and you to them, in any session.
- **Clipboard**: when they control this computer, text copied here during the
  session can be pasted there, and the other way round. Text a password
  manager marks as private is not shared.
- **Receive files**: when they control this computer, they can send files.
  Files go to Downloads › Tornect and never replace a file there.
- **Let them see and copy files**: when they control this computer, they can
  see and copy **any file you can open here**. Tornect's own folders are never
  shown.

Turn off what you do not want before you accept: a change applies to sessions
that start afterwards. During a session, **Turn off clipboard and files** under
the session's line in the banner takes them away for the rest of that session
(chat stays). The clipboard and files need input that actually reaches this
desktop: a View only session gets chat only, and so does a control session
whose input reaches nothing here (on a Wayland desktop, a grant made without
**Allow Remote Interaction**). Files and the clipboard pause while this computer
is locked (on Linux only with a screen locker that tells the system, as GNOME's
and KDE's do; xscreensaver and swaylock do not pause them), and up to a second
of access can follow a lock.

Limits (`[services]` in `config.toml`): each file up to 2 GiB (`max_file_mib`);
up to 8 GiB (`session_quota_mib`) and 1,000 files received in one session; 1 GiB
of the disk always kept free (`keep_free_mib`). Files go one by one, never a
folder. Files you download from the other computer go to your Downloads ›
Tornect. A file dropped on the picture window is sent, on Windows and X11 (not
on Wayland).

Your own clipboard goes to the computer you view only while **Share my
clipboard** (Settings › Sharing, `[viewer] clipboard_sync`, off by default) or
the picture window's Clipboard switch is on; in the first session with a
computer you just paired with, only the window's switch turns it on. In the
same way, text the viewer copies reaches this computer only while the viewer's
own switch is on.

On a Wayland desktop this computer shares no clipboard while `[services]
wayland_clipboard` is off, as it is by default. Turning it on makes the
desktop's screen-sharing dialog ask again (that grant is kept apart, in
`portal-restore-token-2`), and it is not yet tested on GNOME. Over Tor, files
and clipboard text move at about 200 KB/s. `tornect host` on the command line
offers none of these: its sessions carry the picture and input only.

## The command line

The command line can host and connect too, one role per terminal (on Windows,
`start /wait tornect.exe …` as above):

    ./tornect host              # share this desktop; answer pairing and session questions here
    ./tornect connect <ID>      # connect to a host; compare the code, then wait for its answer
    ./tornect ping <ID>         # is that host reachable over Tor? (no pairing needed)
    ./tornect panic             # end every session the running host serves
    ./tornect id --invitation   # print this computer's invitation

`connect` and `ping` also take a `tornect://` link, or a whole invitation in
quotes, in place of the ID. `tornect host` prints `Tornect ID: …` at once (on a
terminal, or with `--evidence`) and `REACHABLE` once the address is published,
typically one to a few minutes later. For a new device it shows the code and
asks you to type `yes` if it matches the other screen; for each session it asks
for `a` (allow control) or `v` (view only). Anything else, or no answer within
60 s, refuses. `tornect connect` shows no picture (use the window for that): it
pairs, asks for the session and reports what it receives until Ctrl-C;
`--quality best-quality|balanced|best-performance` picks the quality and
`--screen <1..16|all>` the other computer's screen. `--capture test-card` (for
`host` and `gui`) shares a synthetic picture instead of the desktop.
`./tornect --help` lists everything, including `--bridges`, `tor-check`,
`devices` and `paths`. For a bug report, add `--log debug`: without it this
build writes only warnings and errors.

## Direct connections

After the sharing side accepts a session, the two computers try to connect
straight to each other, which is much faster than Tor: on the same local
network, or across the internet when their routers let them. The picture,
input, chat, clipboard text and files then go over that connection, which is
encrypted (QUIC, each computer checking the other's key). Tor still finds the
other computer, checks who it is and carries the question, and the two
computers exchange their addresses over Tor only after the accept. When no
direct path is ready within 4 seconds, the session goes over Tor as before.
`tornect connect` prints which way the picture went: `ROUTE direct lan` or
`ROUTE direct internet` (each with `ipv6` after it over IPv6), or `ROUTE tor
<reason>`; `tornect host` prints `SESSION ROUTE <session> lan`, `direct` or
`tor`.

**What a direct connection reveals.** A computer you accept, a view-only one
included, learns this computer's IP addresses: its local-network address, its
public IPv4 address (the one your router shows the internet) and one global
IPv6 address (a temporary one where the system has one). A computer you
connect to learns yours in the same way. A computer that is refused, or never
paired, learns nothing. Two other parties take part:

- **A public STUN server.** To find this computer's public address, each
  computer asks one public STUN server per session (a second only when the
  first does not answer), by default from Cloudflare, Google, Twilio or
  Nextcloud; the list is `stun_servers` under `[network]` in `config.toml`.
  That server sees this computer's IP address and when a session starts, never
  which computer it connects to (when both computers use the same list, as with
  the default) and never the picture. Tornect looks these servers' names up
  once Tor is connected and every 10 minutes, so the DNS resolver this computer
  uses can tell that Tornect runs with direct connections on.
- **This network's router.** Each computer asks its router (PCP or NAT-PMP
  first, UPnP otherwise) to open one UDP port for the session. A UPnP opening
  shows as "Tornect" in the router's settings; Tornect's PCP and NAT-PMP
  requests carry no name, so the router lists those under its own label or
  none. The opening is closed when the session ends; if Tornect stops first, most
  routers drop it within 10 minutes, and Tornect removes it at its next start.

Your internet provider can see that the two computers exchange encrypted
traffic directly, and may recognise it as Tornect. The sharing side is told
before it decides: the window's question says that accepting also lets the
other computer learn this computer's internet address, and `tornect host`
adds a `note:` line saying so to its question; once Tor is connected it
also prints `NOTICE direct connections are on: …`. The window shows a one-time
notice with the switch; until you press OK there, it keeps unattended sessions
on Tor.

**Keeping sessions on Tor.** Switch off "Allow direct connections (faster;
the other computer learns your IP address)" in Settings › Connection, or set
`paranoid = true` under `[network]` in `config.toml`: every session then goes
over Tor, and computers you connect to never learn your IP address. `tornect
connect --tor-only` does the same for one session, and "Pictures and input
through Tor only" in an unattended grant for that device. Under the switch,
"Use public STUN servers" and "Ask this network's router to open a port (UPnP,
NAT-PMP, PCP)" turn those two off; the other computer then still learns this
computer's internet address from the direct connection itself. `lan_only =
true` under `[network]` keeps sessions on the local network in both
directions: no STUN server or router is asked, and a session that cannot
connect directly ends instead of going through Tor. A session without a
picture (`tornect connect --no-video`) is the exception: it is kept from any
network, over Tor, and carries no picture, input or files. Direct connections are off
while Tor reaches the network through a bridge, because they would show that
network that Tornect is in use (`direct_with_bridges = true` under `[network]`
allows them anyway). `tornect doctor` says whether direct connections are on,
whether STUN servers and the router are asked, and which kinds of address this
computer has, never the addresses themselves.

**Firewalls and routers.** A direct connection is UDP. On Windows, the first
direct connection may make Windows ask whether Tornect may communicate on your
networks: choose "Allow access". If you cancel, or this Windows account cannot
change the firewall, sessions go over Tor. When the other computer's probes
arrive but none of this computer's is answered, `tornect connect` prints
`ROUTE tor no-path-firewall` and the window says that the other computer's
firewall may be blocking Tornect. Tornect picks a new UDP port for each
session; `direct_port = <port>` under `[network]` (1024 or above) fixes it, for
a firewall rule or a port forwarded by hand. Behind some routers and
carrier-grade NATs no direct path can be found: the session then goes over
Tor.

## Where Tor is blocked

Tornect finds its own way to Tor. By default (**Automatic** under "How to
reach Tor" in Settings › Connection, `bridges = "auto"` under `[tor]` in
`config.toml`) it tries Tor directly, then the built-in obfs4 bridges, then
Snowflake, both through the bundled lyrebird, starting with whichever worked
last time; once a bridge was needed, Tor directly is tried last. "Tor without
bridges", "obfs4 bridges" and "Snowflake" use that one way only, and
`--bridges auto|off|obfs4|snowflake` picks the way for one run. Where the
built-in bridges are blocked too, get private bridge lines (obfs4, webtunnel or
snowflake) from bridges.torproject.org and paste them under **Private
bridges** in Settings › Connection (`bridge_lines` under `[tor]`): they replace
the built-in bridges of their kind (obfs4 and webtunnel lines the obfs4 ones,
snowflake lines the Snowflake ones), and Automatic no longer tries Tor
directly. A line that does not parse is named by its line number only. Both
choices apply the next time Tornect starts; `tornect tor-check` reports which
way reached Tor. While Tor uses a bridge, direct connections are off ("Keeping
sessions on Tor" above). The built-in bridges have reached Tor on the build
machine, each one forced, but not yet on a network that really blocks Tor;
private bridge lines have been tried only in tests.

## Unattended access

Unattended access lets a device you paired connect to this computer without
anyone here answering, for example to reach your own computer from elsewhere.
It is off until you turn it on, and you give it to each device yourself, with a
password, on this computer only.

1. Pair with the device you will connect from, and hold one ordinary session
   with it that you accept here. (The Headless box preset, or `tornect
   unattended grant --waive-attended-check`, skips that, and the waiver is
   logged.)
2. On Linux, install polkit's policy file first ("The password dialog on
   Linux" above). On Wayland, give the screen-sharing grant ahead (**Grant
   screen sharing**): nobody will be here to answer the desktop's dialog.
3. In the window, open Settings › Security › Unattended access, choose **Turn
   on for a device…**, pick the device and a preset (My machines: control, with
   3 s for someone here to press Block; Helping someone: view only, asks before
   starting; Headless box: control, with no block window), and confirm with
   your OS password. The window shows the device's password, five words, once:
   write it down.

On Linux the command line does the same: `tornect unattended on`, then
`tornect unattended grant <device> [--preset my-machines|headless-box|helping-someone]`,
which asks you to type the password twice; it is never taken from the command
line. On Windows, give access in the window: the Windows command line cannot ask
for a password yet. Turning unattended access on shows an **emergency stop
code** once: write it down and keep it away from this computer. Given from
another of your devices, it turns unattended access off here and removes every
grant.

From the other device, press **Connect with password** on that computer's card
on Home and type the password; once that has worked, the card's **Connect** does
it, and **Knock** asks for an ordinary session. Depending on the access's
setting ("Ask before starting", on for Helping someone), someone there is asked
first or can block the session. On Linux, `tornect connect
--unattended <ID>` does the same from a terminal, without a picture; on Windows
that command works only with a password remembered in the window. An unattended
session shows the sharing banner and the "Tornect: sharing" window like any
other, and Stop or `tornect panic` ends it. A Tornect started at sign-in serves
unattended sessions only once its sharing indicator has been shown.

`tornect unattended status` lists the grants and what is not ready, `tornect
unattended revoke <device>` removes one, and `tornect unattended off` (or Turn
off in Settings › Security) turns unattended access off and ends its sessions;
the grants are kept. `tornect panic` pressed twice within 2 s turns it off too.
An unattended session between two machines over Tor has not yet been run, only
tests.

## Installing (optional)

Tornect runs from the unpacked folder and needs no install. To keep a copy where
it stays, and to make `tornect://` links open Tornect, close Tornect, open a
terminal in the unpacked folder and run `./tornect install` (`start /wait
tornect.exe install` on Windows): the copy that is not installed is not on your
`PATH` yet. Like `service install`, it asks for your OS password first, and it is
refused while a remote session is live or ended less than a minute ago. At the
end it asks "Start Tornect when I sign in? [y/N]"; a yes asks for the password
again. `tornect uninstall` removes the start at sign-in, the link registration,
the menu entries and the copy; your pairings, grants and settings stay.

- **Linux:** the program goes to `~/.local/bin/tornect`, with a menu entry and
  the handler of `tornect://` links (`~/.config/mimeapps.list` is changed only
  where no other program handles those links, and the install says what it
  did), and lyrebird, checked against the SHA-256 compiled into Tornect, to
  `~/.local/bin/pt/lyrebird`, where the installed copy finds it. Install from
  the unpacked folder: a copy with no `pt/lyrebird` beside it installs without
  lyrebird, says so, and its installed copy cannot use obfs4 or Snowflake
  bridges. The password dialog needs polkit's policy file ("The password dialog
  on Linux" above).
- **Windows:** the program goes to `C:\Program Files\Tornect\tornect.exe`, with
  a Start-menu entry and an Apps-and-features entry: your password, then two
  Windows administrator prompts. The first copies `tornect.exe` and
  `lyrebird.exe` together; lyrebird is checked against the SHA-256 compiled into
  Tornect before that prompt and kept open, so that nothing can change it, until
  the install ends, and the copy in Program Files is checked again before
  anything points at it. Install from the unpacked folder: a copy with no
  `lyrebird.exe` beside it installs without lyrebird, says so, and its installed
  copy cannot use obfs4 or Snowflake bridges. It is refused with `--home` or
  `TORNECT_HOME`, and over an earlier install. `tornect uninstall` is refused
  while a device has administrator access; run from the installed copy, or from
  Apps and features, it leaves the folder to be removed at the next restart.

To upgrade, run `tornect uninstall`, then `./tornect install` from the new
release's folder (on Windows, after the restart the uninstall may ask for).
Without installing, `tornect://` links do not open Tornect: paste the invitation
into the Connect field instead. Not yet tried at a real Linux desktop or on
Windows.

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
  password dialog is polkit's `org.tornect.autostart` action, so polkit's
  policy file must be installed first ("The password dialog on Linux" above).
  Remove it with `tornect service uninstall` (or by deleting the file). Whether
  GNOME or KDE minimise the window, and whether the entry runs inside your login
  session, is not yet checked.
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
  `start /wait tornect.exe host`) before `tornect service uninstall`; `schtasks /Delete /TN
  Tornect /F` also removes it. Not yet tried on Windows.

## Where Tornect keeps its state

`tornect paths` prints the directories: the keys of this machine's Tornect ID,
the paired devices, `config.toml` and `sessions.log` (every pairing and session,
kept on this machine). The settings this README names under `[network]`,
`[tor]`, `[services]` and the like go in `config.toml`: `tornect config path`
prints where it is, `tornect config init` writes one with every default where
there is none, and `tornect config show` prints the settings in effect. `--home <dir>` (or `TORNECT_HOME`) puts all of it
elsewhere, so two copies can run side by side on one machine. On Windows that
directory must be inside your user folder (`C:\Users\<you>`), and Tornect
refuses one elsewhere: it does not yet give its directories permissions of their
own, and anywhere else other accounts on the PC could read and change its keys.

## A new Tornect ID

Settings › Security › **Rotate ID…** gives this computer a new Tornect ID and
deletes the old one's keys. Every pairing stops working (each device pairs
again, with the new ID), unattended access is removed for every device, and
the unattended passwords this computer remembers for others are deleted. The
dialog names the devices that lose access and asks you to type ROTATE; Tornect
then ends every session, closes, and shows the new ID when you start it again.
`tornect rotate-id --yes` does the same from a terminal while Tornect is
closed. The command line's rotation ran on the build machine in August, on
older code; Rotate ID in the window has run only in tests.

## What has been tried, and where

Everything in this build has unit and in-process tests (`docs/VERIFICATION.md`
in the source lists each one). What has run live:

- **Linux** (one machine: Ubuntu 26.04, GNOME on Wayland, a virtual GPU, in
  September 2026): Tor directly and through obfs4 and Snowflake bridges;
  pairing, an attended session and `tornect panic` from the command line over
  real Tor between two Tornect homes on that machine; the Wayland desktop's
  picture over Tor at about 3 pictures a second, and its pointer injection at
  the console; a pairing between two windows over Tor and the first-run grant.
  **Not yet:** a whole session in the window with a person at the screen, keys
  over Tor, polkit's dialog, `tornect install` and the start at sign-in at a
  real desktop, a real X11 desktop, KDE, and everything added since September:
  invitations and `tornect://` links in a browser, the quality presets over
  Tor, switching screens, chat, clipboard and files, unattended access between
  two machines, and direct connections between two machines, through real
  routers, over IPv6 or through a VPN.
- **Windows:** **nothing has run on a real Windows machine yet**, only under
  Wine, which is not Windows (the program starts, `doctor` accepts the bundled
  lyrebird, part of the tests pass). The window, capture and input, the
  console behaviour, the control channel, the firewall prompt, the install in
  Program Files, Task Scheduler and the secure credential prompt are untested.

## Known limitations of this build

- Unless the two computers can reach each other directly, everything travels
  over Tor: at most about 16 pictures a second, and a few a second for a large
  desktop. Either way, Tor takes from
  seconds to minutes to find the other computer.
- Direct connections across the internet are new in this build and have run
  only in simulation: not yet between two real homes, through real routers or
  carrier NATs, over IPv6, through a VPN, or on Windows.
- The quality presets' sizes and rates are provisional until measured over
  real Tor and real direct paths. Video is software H.264 only (no GPU
  encoding), and there is no sound.
- A Wayland host shares the one screen picked in its dialog (no Screens menu),
  and no clipboard (`[services] wayland_clipboard`, off until checked on
  GNOME).
- Over Tor, files and clipboard text move at about 200 KB/s.
- An unattended session has not yet been run between two machines over Tor
  (only in tests), and polkit's password dialog has not yet been tried.
- On GNOME, the "Tornect: sharing" window cannot stay above other windows
  (Wayland does not let it); GNOME shows its own screen-sharing icon.
- The zips and the programs are not signed.
- No tray icon: closing the window stops Tornect (minimise it to stay
  reachable). Tornect does not update itself.
- For a bug report, run with `--log debug`: without it this build writes only
  warnings and errors. Fields that name someone stay redacted unless
  `--log-identifiers` is given.

## Licences and source

Tornect is free software under the GNU General Public License, version 3 or
later (`LICENSE`); `BUILD-INFO.txt` names the commit this build came from.
The program also contains other people's code under their own licences:
`THIRD_PARTY_LICENSES.txt` names every part, with its version and licence, and
holds their licence texts. lyrebird is BSD-2-Clause and contains
GPL-3.0-or-later code; its source is the tag `lyrebird-0.8.1` at
https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird
(`THIRD_PARTY_NOTICES.md`).
