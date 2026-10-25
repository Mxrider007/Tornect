# Research: session services (design `services`, revision 2)

The design's research items before its steps: **R1 (GNOME clipboard portal, before step 8)**, **R2 (Windows
APIs, before step 7)**, R3 (logind `LockedHint`, before step 10) and R4 (Arti flow control on onion-service
circuits, before step 29). R3 and R4 are not here yet; each lands with its step. Decision: M1-76 (the design
calls it M1-73; that number and the two after it were taken by earlier features).

## R1. The GNOME clipboard portal (for design steps 8 and 9)

**Status:** verified 2026-10-25 in the build container (not the dev VM, which has the desktop) against source:
ashpd 0.13.13 and zvariant 5.15.0 in the cargo registry; mutter and xdg-desktop-portal-gnome from their GitHub
mirrors of GNOME's GitLab, branch `gnome-50` (GNOME 50, the dev VM's desktop) and `main` (51), fetched the same
day; the portal's interface documentation (`doc-org.freedesktop.portal.Clipboard.html`) fetched the same day. The
xdg-desktop-portal frontend's source could not be fetched here. Nothing below was run against a desktop: gates G1
and G2 (design §11) and the rest of §R1.7 are NEEDS-DEVICE(gnome-wayland) rows of `docs/VERIFICATION.md`, and
the coordinator's switch `[services] wayland_clipboard` (default off) keeps the portal request as it was until
they pass.

### R1.1 The request and the restore token (gate G1, from source)

- **Order.** "This request must be made before the session starts" (RequestClipboard); whether access was
  granted "is reported in the `clipboard_enabled` result of the session's `Start()` response". Every other
  method "may only be called if clipboard access was given after starting the session", and the signals reach
  only such a session. ashpd: `Clipboard::request(&session, RequestClipboardOptions)`; `SelectedDevices::
  is_clipboard_enabled()` reads `clipboard_enabled` (`remote_desktop.rs` 263–293); `IsClipboardSession for
  RemoteDesktop` (762–763) behind the feature `clipboard`.
- **portal-gnome 50.** `handle_request_clipboard` only marks the session `clipboard_requested`
  (`src/clipboard.c` 107–149). `start_done` (`src/remotedesktop.c` 556–636) calls mutter's `EnableClipboard`
  only when it was requested (570–600), and answers `clipboard_enabled` from the session's
  `clipboard.clipboard_enabled`, which is the dialog's choice or, on a restore, the stored one.
- **The token stores the clipboard choice.** The restore data holds `clipboard_enabled`
  (`serialize_session_as_restore_data`, 519–553), and `restore_from_data` (738–780) restores it without a dialog,
  whatever the new request asks. So a token made **without** `RequestClipboard` restores with
  `clipboard_enabled = false` and no dialog: the clipboard is never offered on it. That is why a host that asks
  for the clipboard keeps its grant in a file of its own (`Paths::portal_restore_token_for(true)`,
  `state/portal-restore-token-2`): its first session or grant shows the dialog once, with the clipboard choice,
  and the token that follows restores that choice. With the switch off the request and the file stay as they
  were, so no dialog appears that would not have appeared before.
- **main (51) differs.** `start_done` enables the clipboard whenever the session's (dialog or restored) choice
  says so, requested or not (`src/remotedesktop.c` 537–561 on `main`). Tornect's request is constant per token
  file, so both behave the same for it.

### R1.2 The owner already there at enable (gate G2, from source)

- mutter 50 `handle_enable_clipboard` (`src/backends/meta-remote-desktop-session.c` 1353–1420): with no
  `mime-types` option it emits `SelectionOwnerChanged` for the current owner, if there is one, during the
  `EnableClipboard` call (`main` moved this to `meta-clipboard-session.c` `meta_clipboard_session_enable`,
  287–322, unchanged in effect).
- portal-gnome 50 connects its handlers to mutter's proxy, calls `EnableClipboard` synchronously, then completes
  `Start` (570–636). GDBus hands a proxy's signal to the main loop only after the synchronous call returns, so the
  relayed announcement of the owner from before the session leaves portal-gnome **after** the `Start` results;
  the app sees it shortly after the `Start` response, not before. The design's `BASELINE_GRACE` (2 s after
  `Start` returned, no owner change reported) covers it unless it is relayed later than that: G2 measures the
  delay on the desktop (the live test prints it).
- The app must subscribe to the signals **before** `Start`, or the announcement can be missed; the backend
  subscribes just before `RequestClipboard`, after `SelectSources` (the design said at `Start`).

### R1.3 The signals

- `SelectionOwnerChanged(o session_handle, a{sv} options)`: `mime_types` (`as`) and `session_is_owner` (`b`).
  mutter sends both only when there is an owner (`generate_owner_changed_variant`, 1276–1291); when the owner
  went away it sends an empty dict, which portal-gnome relays as an empty dict (`src/clipboard.c` 42–100).
  `session_is_owner` is true exactly for the session's own `SetSelection` source (`is_own_source`).
- `SelectionTransfer(o session_handle, s mime_type, u serial)`: someone pastes what this session set.
- ashpd's `receive_selection_owner_changed` builds a `Session` proxy for every signal (a property round trip
  each) and keeps its object path private (`clipboard.rs` 169–210, `session.rs` 87–89). The backend therefore
  subscribes on the `Clipboard`'s own zbus proxy and compares the signal's object path with its session's path,
  which the session serialises as (`Serialize for Session`, `session.rs` 92–102).

### R1.4 Reading and writing (the file descriptors)

- **Read.** `SelectionRead(session, mime)` returns the read end of a pipe mutter made with `g_unix_open_pipe`
  and made non-blocking (1886–1900): a FIFO, which `tokio::net::unix::pipe::Receiver::from_owned_fd` accepts
  (`tokio-1.53.1` `net/unix/pipe.rs` 967; zvariant's `OwnedFd` converts into `std::os::fd::OwnedFd`,
  `zvariant-5.15.0` `src/fd.rs` 227). mutter refuses a read of the session's own selection ("Tried to read own
  selection", 1874) and a read while an earlier read's pipe is still open ("Tried to read in parallel", 1882;
  `is_pipe_broken` looks for an error on the earlier pipe, 1759–1780). So reads go one at a time, and a read
  given up closes its end at once.
- **The read is of the owner at read time.** Nothing ties a read to the owner change that prompted it; an owner
  change racing a read can be announced after the read's answer (portal-gnome answers mutter's synchronous
  calls before it relays the signals queued meanwhile). The backend drops a read when a newer owner change is
  already queued once it returns; a change announced later still is a residual (R1.7).
- **Write.** A paste of the session's selection arrives as `SelectionTransfer`. `SelectionWrite(session,
  serial)` returns the write end of a pipe (1639–1700) and completes the paste with its read end, so the pasting
  application reads what is written until it is closed; `SelectionWriteDone(session, serial, success)` only
  answers (1733–1757). The interface says "If the request is not handled, the caller should respond by setting
  `success` to 'false'", but mutter keeps an unanswered paste waiting until its 15 s cleanup
  (`TRANSFER_REQUEST_CLEANUP_TIMEOUT_MS`, 52). The backend therefore refuses a paste by `SelectionWrite`, closing
  the pipe unwritten (the application reads nothing at once), and `SelectionWriteDone(false)`.
- `SetSelection` without `mime_types` drops the session's selection (`reset_current_selection_source`,
  1586); with them it makes the session the owner of those types.

### R1.5 mutter's own clipboard manager

`src/core/meta-clipboard-manager.c` (the same in `gnome-50` and `main`):
- on every new owner it drops its saved copy first (111), then copies the new owner's best type of its list
  (images, then `text/plain`, then `text/plain;charset=utf-8`, text up to 4 MiB; 26–45, 88–150);
- when the owner goes away it takes the selection over with a memory source that offers **only that one type**
  (157–175), without the owner's other types.

Consequences for the backend:
- **The password hint does not survive a takeover.** A KeePassXC copy (`x-kde-passwordManagerHint` offered)
  whose owner quits comes back as an owner offering only `text/plain;charset=utf-8`. The backend recognises a
  takeover (an owner with exactly one of those two types announced right after "no owner") and gives it the
  verdict of the owner before: not read when that one was private, this session's own, from before the
  activation, or unknown.
- **Text the session set outlives it.** The manager copies what Tornect sets and serves it after the portal
  session ends. To clear the clipboard when it still holds our text (the backend contract), the backend makes
  itself the owner of one Tornect-only type, `application/x-tornect-cleared`: the manager drops its copy (a new
  owner) and keeps none (no type it copies), so nothing is left when the session goes. A desktop that ends the
  session itself (a lock) leaves no chance to do this: residual.
- Received text is set with `text/plain;charset=utf-8`, `text/plain` and `x-kde-passwordManagerHint`
  (`secret`), as the X11 backend sets it (R2.3), so clipboard managers that honour the hint keep no copy;
  mutter's own does not look at it.

### R1.6 Version and features

- ashpd feature `clipboard` (`=0.13.13`, no new crate: the module uses only what the enabled features use).
  Portal interface version 1 on the VM (`docs/research/wayland.md` §2.6).
- xdg-desktop-portal-gnome 50.0: "Make the Clipboard portal return errors instead of succeeding" (NEWS). A
  failed `Clipboard` proxy, `RequestClipboard` or subscription leaves the session without a clipboard, never
  without the screen.

### R1.7 Needs the GNOME desktop

- G1: the dialog's clipboard choice; a restore with `RequestClipboard` starts without a dialog with
  `clipboard_enabled == true`; a view-only session's restore (the same request) starts without a dialog.
- G2: the delay between the `Start` response and the announcement of the owner already there.
- The `SelectionRead`/`SelectionWrite` fds are FIFOs; pastes into Xwayland applications; a KeePassXC copy is not
  sent, and not after KeePassXC quits; text received is pasteable, not listed by a clipboard extension that
  honours the hint, and gone after the session ends; the residual race of R1.4 (a copy right after another).
- KDE (xdg-desktop-portal-kde) is not covered by this note: NEEDS-DEVICE(kde-wayland).

## R2. Windows APIs, and the arboard clipboard on Windows and X11

**Status:** verified 2026-10-25 in the build container (not the dev VM) against the crate sources in the cargo
registry (arboard 3.6.1, clipboard-win 5.4.1, x11rb 0.13.2 with x11rb-protocol 0.13.2, windows-sys 0.61.2), a run
against Xvfb (xorg-server 21.1.12, Ubuntu package `2:21.1.12-1ubuntu1.9`), the password managers' sources and
release notes, and Microsoft Learn pages fetched the same day. What needs a Windows desktop is listed in §R2.7
and is a NEEDS-DEVICE(windows) row of `docs/VERIFICATION.md`.

### R2.1 The clipboard sequence number

- `GetClipboardSequenceNumber()`: "The system keeps a serial number for the clipboard for each window station.
  This number is incremented whenever the contents of the clipboard change or the clipboard is emptied. … If
  clipboard rendering is delayed, the sequence number is not incremented until the changes are rendered." It
  returns zero without `WINSTA_ACCESSCLIPBOARD` access
  ([GetClipboardSequenceNumber](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclipboardsequencenumber)).
- Consequences for the host backend: a change is "the number differs from the one seen last"; the activation
  baseline is the number at activation (and, since step 7's review, the text's fingerprint: see below); our own set is recognised by reading the number right after the set
  returns (arboard closes the clipboard before it returns, so every format of that set is counted). A zero
  reading means no access: the backend treats the clipboard as unavailable.
- **Delayed rendering (added at step 7's review).** An owner may announce a format with no data and render it
  only when asked: `WM_RENDERFORMAT` is "sent to the clipboard owner if it has delayed rendering a specific
  clipboard format and if an application has requested data in that format", and `WM_RENDERALLFORMATS` is "sent
  to the clipboard owner before it is destroyed, if the clipboard owner has delayed rendering one or more
  clipboard formats" ([WM_RENDERFORMAT](https://learn.microsoft.com/en-us/windows/win32/dataxchg/wm-renderformat),
  [WM_RENDERALLFORMATS](https://learn.microsoft.com/en-us/windows/win32/dataxchg/wm-renderallformats)). With the
  sentence quoted above, the number then moves although the content did not: when the text from before the
  session is first pasted, or when its owner quits. So a number change is not new text, and the activation
  baseline keeps the text's fingerprint as well: in one opening, the private formats are checked and, unless they
  mark it, `GetClipboardData(CF_UNICODETEXT)` is read (which has the owner render it now) and fingerprinted; the
  number is read after closing. The fingerprint decodes the block as arboard's read does (`WideCharToMultiByte`
  to UTF-8, up to the first NUL, `clipboard-win-5.4.1/src/raw.rs` 526–553), so a later read of the same text
  matches.
- **Read races.** The exclusion check (R2.2) and the text read are two clipboard openings (arboard opens the
  clipboard itself for `get_text`, `arboard-3.6.1/src/platform/windows.rs` 539–568, 585–607). A password manager can copy
  between them, so a read is kept only when the sequence number before the check equals the one after the read;
  otherwise it is retried at the next poll. The same bracket serves the viewer's read through egui-winit.
- **Clearing at the end.** With the clipboard open no other process can change it, so "clear if the number still
  equals our own last set" is exact when done as `OpenClipboard(NULL)`, compare, `EmptyClipboard`,
  `CloseClipboard` (`windows-sys-0.61.2/src/Windows/Win32/System/DataExchange/mod.rs` 5, 44, 55, 72).
  arboard's `Clear` cannot do it: it empties without comparing (`windows.rs` 892–895). The number of our set is
  read after arboard's set returns, so a set by another process in that instant would be taken for ours; the
  backend therefore also compares the `CF_UNICODETEXT` text (its fingerprint, read with `GlobalLock` inside the
  same opening) before emptying.

### R2.2 The private-text formats and their values

Microsoft documents three registered formats
([Clipboard formats, "Cloud Clipboard and Clipboard History Formats"](https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-formats)):

| Format (registered name) | Meaning | Private when |
|---|---|---|
| `ExcludeClipboardContentFromMonitorProcessing` | "Place any data on the clipboard in this format to prevent all clipboard formats being included in the clipboard history or synchronized" | present, any data |
| `CanIncludeInClipboardHistory` | "a serialized DWORD value of zero … to prevent … the clipboard history, or … one instead to explicitly request" it | present with DWORD 0 |
| `CanUploadToCloudClipboard` | "a serialized DWORD value of zero … to prevent … synchronized to the user's other devices, or … one" to request it | present with DWORD 0 |

and the older convention `Clipboard Viewer Ignore` (present, any data), which CopyQ documents as one of the
Windows formats password managers set, together with the three above
([CopyQ, "Security"](https://copyq-de.readthedocs.io/de/stable/security.html)).

- **The DWORD formats are not "present means private".** A value of 1 explicitly asks to be kept in history, so
  the check reads the value: `GetClipboardData(fmt)` → `GlobalSize` ≥ 4 → `GlobalLock` → the first four bytes
  (little-endian, as the DWORD is "serialized"; KeePassXC writes four zero bytes, arboard `0u32.to_ne_bytes()`).
  A present format whose data cannot be read or is shorter than four bytes counts as private (fail closed).
- **Who sets what:**
  - **KeePassXC** (`src/gui/Clipboard.cpp`, `setText`, develop branch): on Windows
    `ExcludeClipboardContentFromMonitorProcessing` = `"1"`, `CanIncludeInClipboardHistory` and
    `CanUploadToCloudClipboard` = four zero bytes; on other Unix systems (X11 and Wayland)
    `x-kde-passwordManagerHint` = `"secret"`; on macOS `application/x-nspasteboard-concealed-type`.
  - **KeePass 2.x**: 2.41 "Added option 'Do not store data in the Windows clipboard history and the cloud
    clipboard'" (on by default) ([2.41 notes](https://keepass.info/news/n190109_2.41.html)); 2.44: "The option to
    use the 'Clipboard Viewer Ignore' clipboard format is now turned on by default" and "KeePass now additionally
    excludes its clipboard contents from processing by Windows' internal ClipboardMonitor component"
    ([2.44 notes](https://keepass.info/news/n200120_2.44.html)).
  - **Bitwarden desktop** (`apps/desktop/desktop_native/core/src/clipboard/arboard_backend.rs`, main branch): with
    `hide_from_history` arboard's `exclude_from_cloud().exclude_from_history()` on Windows (the two DWORD formats
    at 0) and `exclude_from_history()` (the KDE hint) on Linux; `hide_from_history` is `!allowHistory`, false
    by default, so copies are private unless the caller allows history
    (`apps/desktop/src/platform/services/electron-platform-utils.service.ts`, `copyToClipboard`). The browser
    extension writes through the web clipboard and sets no hint (a residual of the design's §12).
- **Why every check counts.** `ExcludeClipboardContentFromMonitorProcessing` alone already covers KeePass and
  KeePassXC; Bitwarden sets only the two DWORD formats, so the DWORD reads are what catch it.
- **Our own sets.** arboard's `Set::text` puts `CF_UNICODETEXT` first and then, with the clipboard still open,
  each requested exclusion format with the DWORD 0 (`windows.rs` 674–686, 798–843:
  `exclude_from_cloud` → `CanUploadToCloudClipboard`, `exclude_from_history` → `CanIncludeInClipboardHistory`).
  Text Tornect receives is therefore private by these rules: the host's own check would skip it even if the
  sequence-number guard did not, and a Windows viewer's next read skips text it was given.
- **Size before reading.** UTF-8 text of at most 262 144 bytes is at most 262 144 UTF-16 units (a UTF-8 sequence
  of n bytes is one or two units, never more than n), so a `CF_UNICODETEXT` block larger than 2 × (262 144 + 1)
  bytes (with its terminator) is over the cap and is not read at all (`GlobalSize` inside the same opening).

### R2.3 arboard 3.6.1

- **Pin.** `arboard = { version = "=3.6.1", default-features = false }`. It is already in `Cargo.lock` through
  egui-winit (`egui-winit-0.36.2/Cargo.toml` 144–148, with `image-data`), and its Windows backend takes
  `windows-sys` `>=0.52.0, <0.61.0` (0.60.2 in the lock) and `clipboard-win` 5.4.1; tornect-input alone pulls no
  image code. Nothing new enters the lock.
- **Windows.** `Clipboard` is a shim; every operation opens the clipboard, retrying five times 5 ms apart, and
  closes it again (`windows.rs` 509–568). arboard warns that "executing multiple clipboard operations in parallel
  might fail with a `ClipboardOccupied` error" (`lib.rs` 44–69), hence one owning thread per session.
- **X11 is process-global.** `Clipboard::new()` returns a handle to one static context: one connection, one
  window and one serving thread per process (`linux/x11.rs` 58, 915–933). The host's thread and egui-winit's
  clipboard (the main window and the stream window) share it. Consequences:
  - dropping the host thread's `Clipboard` does not release the selection while another handle lives; the
    design's "the selection vanishes with the thread's `Clipboard`" holds only for the last handle;
  - so the backend releases the selection itself at the end when it still holds our text (R2.4);
  - a read while the process owns the selection is answered from arboard's own store without a round trip
    (`x11.rs` 296–312), so the backend's own set reads back immediately.
- **X11 history exclusion.** `SetExtLinux::exclude_from_history` adds `x-kde-passwordManagerHint` = `secret` to
  the offered targets ("the most widely adopted convention on Linux", `linux/mod.rs` 361–366, 17–18), and when the
  last handle drops, hinted data is never handed to a clipboard manager: arboard sets the owner to `None` instead
  of the `SAVE_TARGETS` handover (`x11.rs` 711–760). Unhinted data is handed over, so it outlives the session in
  the manager. The host backend therefore sets received text with the hint on X11, as it sets it with the
  history exclusions on Windows.
- **X11 reads.** `get_text` asks a foreign owner over a fresh connection and waits up to 4 s
  (`LONG_TIMEOUT_DUR`, `x11.rs` 101, 313–410), trying `UTF8_STRING`, `text/plain;charset=utf-8`,
  `text/plain;charset=UTF-8`, `STRING` (Latin-1), `TEXT`, `text/plain`. It reads the whole selection (INCR
  included) before the caller can apply a cap. Since step 7's review the backend does not read through it: it
  converts `CLIPBOARD` to `UTF8_STRING` itself on its own connection (R2.4), once, within 2 s, and takes one
  property of at most 256 KiB. arboard serves what it set in one property, never with `INCR`
  (`handle_selection_request`, `x11.rs` 592–700), so the backend's own text reads back that way too.
- **X11 clear.** `Clear` sets the owner to `None` at `CurrentTime` without checking who owns the selection
  (`x11.rs` 222–236), so it could clear another application's selection. The backend does not use it (R2.4).
- **Copies of the text.** arboard keeps a copy of set text in its store (X11) and Windows keeps it in the
  clipboard's global memory; neither is wiped. Tornect's own copies are `Zeroizing`. Stated as a residual.

### R2.4 X11 change events, the private hint and the release (x11rb 0.13.2)

- **Events.** `xfixes_query_version` then `xfixes_select_selection_input(window, CLIPBOARD,
  SelectionEventMask::SET_SELECTION_OWNER)` on a separate connection with a 1×1 `InputOnly` window
  (`x11rb-0.13.2/src/protocol/xfixes.rs` 554–562; `x11rb-protocol-0.13.2/src/protocol/xfixes.rs` 451–514). Each
  `XfixesSelectionNotify` carries `owner`, `selection`, `timestamp` and `selection_timestamp`
  (`xfixes.rs` 563–572). No polling: reading the selection on a timer would make every owner serve it.
- **Activation baseline.** `sync()` (a `GetInputFocus` round trip, `x11rb-0.13.2/src/wrapper.rs` 89–99) and then
  draining the queued events: every owner change the server processed before the round trip is queued by then
  and dropped; what follows is after activation.
- **The hint on X11.** KeePassXC sets `x-kde-passwordManagerHint` on X11 too (R2.2), and so does Bitwarden through
  arboard. The design lists the hint for the Wayland portal only; the X11 backend checks it as well: before
  reading, it converts `CLIPBOARD` to `TARGETS` on its own window (`ConvertSelection`, then the
  `SelectionNotify`, then `GetProperty`; the window and its property are destroyed after) and skips the change when the list holds the hint, when the
  owner refuses `TARGETS` or when the list does not fit 1024 atoms (fail closed). ICCCM §2.6.2 makes `TARGETS`
  mandatory for owners.
- **Content baseline (added at step 7's review).** Owner changes are not content: a clipboard manager that takes
  the selection over from an owner that quits (a `SAVE_TARGETS` handover, or a manager that re-owns what it saw)
  raises an owner change with the same text. At each activation the backend therefore also reads the text, unless
  the `TARGETS` mark it private, cannot be had or do not list `UTF8_STRING`, and keeps its fingerprint; the
  engine never reports that text while the activation lasts.
- **Bounded reads (added at step 7's review).** Each `ConvertSelection` (`TARGETS`, then `UTF8_STRING`) goes to a
  window made for it and waits at most 2 s, the deadline checked on every pass, so a client that sets the
  selection again and again cannot hold the thread. The text property is read with `GetProperty` `long_length` =
  65 537 units (256 KiB and one unit) and not deleted: `bytes_after` ≠ 0 means over the cap; an `INCR` reply
  (its value is "a lower bound" of the size, and the requestor starts the transfer when it deletes the property,
  ICCCM §2.5 and §2.7.2, as summed up in [Making use of the ICCCM](https://cscene.sourceforge.net/CS7/CS7-06.html))
  is not followed.
- **Read races.** An owner change between the `TARGETS` check and the text read shows up as another
  `XfixesSelectionNotify`; after the read the backend syncs and, if one arrived, drops what it read and reads
  again at the next turn.
- **Release.** At the end the backend clears the selection only when it still holds our text (the hint is
  listed and the text's fingerprint is our last set) and then with `SetSelectionOwner(None, CLIPBOARD, t)` where
  `t` is the `selection_timestamp` of the newest change it saw: the X server ignores a `SetSelectionOwner` whose
  time is earlier than the selection's last-change time, so an owner that took the selection after `t` keeps it
  (X11 protocol, `SetSelectionOwner`).

### R2.5 Free space, drive types (for design steps 10 and 14)

- `GetDiskFreeSpaceExW(lpDirectoryName, …)`: "This parameter does not have to specify the root directory on a
  disk"; `lpFreeBytesAvailableToCaller` is "the total number of free bytes on a disk that are available to the
  user who is associated with the calling thread … If per-user quotas are being used, this value may be less than
  the total number of free bytes" ([GetDiskFreeSpaceExW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw)).
  `disk::available` must use the caller's figure, not the disk's.
- `GetDriveTypeW(lpRootPathName)`: "A trailing backslash is required"; `DRIVE_FIXED` = 3 ("fixed media; for
  example, a hard disk drive or flash drive"), `DRIVE_REMOVABLE` 2, `DRIVE_REMOTE` 4, `DRIVE_CDROM` 5,
  `DRIVE_RAMDISK` 6 ([GetDriveTypeW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew)).
  Note "flash drive" under fixed media: a USB disk that reports fixed media is listed as a place.

### R2.6 `std::fs::canonicalize` on Windows and the Mark-of-the-Web (for design steps 14 and 16)

- `canonicalize` "corresponds to … the `CreateFile` and `GetFinalPathNameByHandle` functions on Windows" and
  "converts the path to use extended length path syntax"
  ([std::fs::canonicalize](https://doc.rust-lang.org/std/fs/fn.canonicalize.html)). With `VOLUME_NAME_DOS`
  (the default) the result "uses the `\\?\` syntax"; a volume GUID path looks like `\\?\Volume{…}\`
  ([GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)).
  So a file on a lettered drive is `\\?\C:\…`, a share `\\?\UNC\server\share\…`; the design's
  `windows_drive_root` accepts the first form only. Which forms VSS snapshots, mapped drives, volume mount points
  and junctions produce is NEEDS-DEVICE(windows) (§R2.7), and the refusal is a pure string check either way.
- The Mark-of-the-Web is the `Zone.Identifier` alternate data stream, `[ZoneTransfer]` then `ZoneId=3`
  ([IZoneIdentifier2](https://learn.microsoft.com/id-id/previous-versions/windows/internet-explorer/ie-developer/platform-apis/mt243886(v=vs.85)),
  [NCC Group](https://www.nccgroup.com/research/how-microsoft-office-knows-a-document-came-from-the-internet-and-might-be-dangerous/)).
  That the stream moves with a rename on NTFS and that writing it fails on FAT/exFAT is for the device (§R2.7).

### R2.7 Needs a Windows desktop

Sequence-number polling and the own-set skip; each password manager's copy skipped (KeePass 2.x, KeePassXC,
Bitwarden desktop) on the host and by a viewer; `exclude_from_history` (Win+V does not list received text);
the end-of-session clear; `GetDiskFreeSpaceExW`, `GetDriveTypeW` on a USB disk; the `canonicalize` forms of a VSS
snapshot, a share, a mapped drive, a volume mount point and a junction; the Mark-of-the-Web across the rename
and on FAT/exFAT. Wine runs the clipboard code but is not Windows' clipboard; its runs are smoke tests.
