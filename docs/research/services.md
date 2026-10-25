# Research: session services (design `services`, revision 2)

The design's research items before its steps: R1 (GNOME clipboard portal, before step 8), **R2 (Windows APIs,
before step 7; this note)**, R3 (logind `LockedHint`, before step 10) and R4 (Arti flow control on onion-service
circuits, before step 29). R1, R3 and R4 are not here yet; each lands with its step. Decision: M1-76 (the design
calls it M1-73; that number and the two after it were taken by earlier features).

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
