# `tornect:` links — sourced research note (verified 2026-10-24)

Scope: step 1 of the invitation-links design (`/mnt/project-files/designs/invite.md` §10): how a
`tornect://<ID>` link reaches Tornect on Linux (Desktop Entry `Exec`/`%u`/`NoDisplay`/`MimeType`,
the MIME Applications spec, the lookups of GIO, KService, generic `xdg-open`, snapd and the portal
`OpenURI`) and on Windows (the `URL Protocol` keys under `HKCU`, `RegDeleteTreeW`), how browsers
pass and escape external-protocol URLs, and CVE-2018-1000006 with its `--` mitigation.

Where each claim was checked:

- **Here** = the cloud container this note was written in: Ubuntu 24.04.5, GLib/gio **2.80.0**
  (`libglib2.0-bin 2.80.0-6ubuntu3.9`), Wine **9.0** (`wine-9.0 (Ubuntu 9.0~repack-4build3)`),
  llvm-mingw 20260908, Rust 1.96.0. No desktop session, no D-Bus session bus, no browser.
  **Absent here:** `xdg-mime`, `xdg-open`, `update-desktop-database`, `kde-open`, `kde-open5`,
  `kioclient5`, `gtk-launch`, `desktop-file-validate` (`command -v` finds none of them). The
  xdg-utils scripts were taken from the Ubuntu packages without installing them (below).
- **Source** = upstream source read on 2026-10-24 (path and version given per claim).
- **Docs** = a vendor or freedesktop.org page (URL given).
- **NEEDS-DEVICE** = could not be checked here; the recipe is in `docs/VERIFICATION.md`
  ("Invitation links").

---

## 0. Findings that change or sharpen the design

1. **Generic `xdg-open` cannot run an entry whose `Exec` items are quoted** (VERIFIED here with
   the scripts of xdg-utils **1.1.3** (Ubuntu 24.04) and **1.2.1** (`1.2.1-2ubuntu2`, the Ubuntu
   archive)). Its generic path splits `Exec` with `read first rest` ("This handles backslashes but
   not quote marks", `xdg-open` 1.2.1 lines 165 and 615), so `"/…/tornect" "open-link" "--" %u`
   becomes the program name `"/…/tornect"` with its quotes: 1.1.3 ends with
   `xdg-open: 811: : Permission denied` (exit 4), 1.2.1 with
   `xdg-open: no method available for opening …` (exit 3), and the program is never run. The same
   entry with bare items (`/…/tornect open-link -- %u`) runs, and the URL arrives as one argument
   (`[open-link] [--] [tornect://abc" --home /x]`). The generic path is what `xdg-open` takes when
   neither `XDG_CURRENT_DESKTOP` nor its older session probes name a desktop it knows (§2.3; for
   example many tiling compositors), so **step 9 should write each `Exec` item of the link entry
   bare when it holds no reserved character** (Desktop Entry spec §7: space, tab, newline, `"`,
   `'`, `\`, `>`, `<`, `~`, `|`, `&`, `;`, `$`, `*`, `?`, `#`, `(`, `)`, `` ` ``; a literal `%` is
   always written `%%`) and quote only the items that need it. The usual
   `/home/<user>/.local/bin/tornect` and the literal `open-link` and `--` need no quotes; a `--home`
   path with a space still needs them, and generic `xdg-open` will then not open links (pasting
   works). GIO and KService parse both forms. The menu and autostart entries are started by the
   desktop's own launcher, not by `xdg-open`, so their quoting is unaffected.
2. **GIO does not append the URI to an `Exec` without a field code.** It appends `%f`
   (`gio/gdesktopappinfo.c` 2.80.0, `expand_application_parameters`: "If there is no macro default
   to %f. This is also what KDE does"), and `%f` of a non-file URI expands to nothing
   (`expand_macro_single`: `g_file_get_path` is NULL). VERIFIED here: with the `%u` removed, `gio
   open 'tornect://abc def'` ran the program with argv `[open-link] [--]`, no URI. The design's
   reason for a **separate** link entry still holds, for other reasons: the link must run
   `open-link --` (not the hosting window), and the link entry is `NoDisplay=true` so it never
   shows in menus.
3. **Inside one `mimeapps.list`, GIO lets `[Added Associations]` win over
   `[Removed Associations]`** for the same entry, and a `[Default Applications]` line is honoured
   even when `[Removed Associations]` lists the same entry (VERIFIED here, cases `removed`,
   `removed-default`, `removed-added-default` in §2.1). The MIME Applications spec calls listing
   an application in both groups "invalid". So the design's `TurnedOff` rule (when Removed lists
   `tornect-link.desktop`, write nothing at all) is necessary: writing either group would silently
   override the user's removal.
4. **Keys are matched case-sensitively, and generic `xdg-mime` needs `key=` with no space.**
   GIO ignored `X-Scheme-Handler/Tornect=tornect-link.desktop;` (VERIFIED here, case `upper-key`);
   KService takes `x-scheme-handler/` keys verbatim (`kmimeassociations.cpp`
   `parseAddedAssociations`); `xdg-mime`'s `check_mimeapps_list` matches
   `index($0, mimetype "=") == 1`, so `x-scheme-handler/tornect = …` (spaces) is invisible to it,
   although GIO accepts it (case `spaces`). **Steps 10–11 must write exactly**
   `x-scheme-handler/tornect=tornect-link.desktop;` (lowercase key, no spaces). The design's
   ASCII-case-insensitive *matching* stays conservative: removal also cleans case variants, and a
   case-variant `[Default Applications]` key makes `add` report `OtherDefault` and leave it, even
   though GIO would not read that key.
5. **Both groups are needed, for different readers.** `[Default Applications]` alone makes GIO
   choose Tornect but lists it under "No registered applications / No recommended applications"
   (VERIFIED here, case `default`). The portal's `OpenURI` skips its app chooser for a custom scheme
   only when exactly one *recommended* handler exists or the user chose one 3 times
   (`xdg-desktop-portal` 1.20.0 `src/open-uri.c`, `find_recommended_choices` and the
   `skip_app_chooser` rules), and a Snap Firefox user's custom scheme opened only after adding the
   scheme under both `[Added Associations]` and `[Default Applications]`
   ([snapcraft forum, 2024-04-20](https://forum.snapcraft.io/t/open-external-application-with-a-url-scheme-in-firefox-snap-version/39820?page=2)).
   `[Added Associations]` gives the recommended entry; `[Default Applications]` makes Tornect the
   default where another program also claims the scheme in a lower-precedence place.
6. **`RegDeleteTreeW(HKCU, "Software\\Classes\\tornect")` deletes the named key itself**, so the
   design's following `RegDeleteKeyW` normally answers `ERROR_FILE_NOT_FOUND` (2), which
   `remove_url_handler` must count as success (the design already does). Microsoft's page does not
   say so explicitly; Wine 9.0's implementation does it (`dlls/kernelbase/registry.c`
   `RegDeleteTreeW`: "Delete the key itself" when `subkey` is non-empty) and a probe run under Wine
   here confirmed it (§4.3). On real Windows: NEEDS-DEVICE(windows).
7. **An unescaped `"` in a Windows link splits the command line, and everything lands after
   `--`.** VERIFIED here under Wine 9.0 with a Rust 1.96 `std::env::args_os` printer started with
   the registered template (`"<exe>" open-link -- "%1"`, `%1` replaced literally as `ShellExecute`
   does): `tornect://abc" --home C:\x` arrives as `[open-link] [--] [tornect://abc] [--home]
   [C:\x]` (§4.4). With `--` in the template, `--home` is a positional, and clap refuses the extra
   positionals: this is the case step 6's clap test `open-link -- L --home /x` must pin.

## 1. Desktop Entry: `Exec`, `%u`, `NoDisplay`, `MimeType` (Docs + Source)

- Quoting ([Desktop Entry spec 1.5, "The Exec key"](https://specifications.freedesktop.org/desktop-entry/1.5/exec-variables.html)):
  "Quoting must be done by enclosing the argument between double quotes" and escaping the double
  quote, backtick, dollar sign and backslash; "Reserved characters are space (" "), tab, newline,
  double quote, single quote, …"; "Field codes must not be used inside a quoted argument" (the
  result is undefined). This is why the design puts ` %u` unquoted after the quoted items.
  VERIFIED here: GIO refused to launch with `"%u"` and a URL containing `"`
  (`Text ended before matching quote was found for '`, exit 2).
- `%u`: "A single URL. Local files may either be passed as file: URLs or as file path."
- `NoDisplay` ([recognized keys](https://specifications.freedesktop.org/desktop-entry/1.5/recognized-keys.html)):
  "this application exists, but don't display it in the menus", useful "to e.g. associate this
  application with MIME types … without having a menu entry for it". VERIFIED here: every GIO
  case below used `NoDisplay=true`, and lookups and launches were unaffected. KService skips an
  entry only when `showInCurrentDesktop()` is false (OnlyShowIn/NotShowIn), not for `NoDisplay`
  (`kbuildservicefactory.cpp` `populateServiceTypes`).
- `MimeType`: "The MIME type(s) supported by this application"
  ([§10](https://specifications.freedesktop.org/desktop-entry/1.5/mime-types.html)); the spec says
  nothing of `x-scheme-handler/`, `mimeinfo.cache` or `update-desktop-database`. The
  `x-scheme-handler/<scheme>` convention is GIO's: `g_app_info_get_default_for_uri_scheme`
  lower-cases the scheme and looks up `x-scheme-handler/<scheme>` (`gdesktopappinfo.c` 2.80.0).
- `TryExec`/`Exec` existence: GIO drops an entry whose `Exec` program cannot be found
  (`g_desktop_app_info_load_from_keyfile` calls `g_find_program_for_path(argv[0])` and returns
  FALSE when it is NULL). VERIFIED here (case `missing-exec`): "No default applications".

## 2. MIME Applications spec and the four lookups

### 2.1 GIO (GLib 2.80.0) — VERIFIED here

Spec ([MIME Applications Associations 1.0.1, 2014-09-07](https://specifications.freedesktop.org/mime-apps/latest-single)):
lookup order `$XDG_CONFIG_HOME/$desktop-mimeapps.list`, `$XDG_CONFIG_HOME/mimeapps.list` ("user
overrides (recommended location for user configuration GUIs)"), `$XDG_CONFIG_DIRS/…`,
`$XDG_DATA_HOME/applications/…` ("for compatibility, deprecated"), `$XDG_DATA_DIRS/applications/…`;
"the desktop-specific files can only be used for specifying the default application"; removals in a
file apply to that level and lower ones; "If the application is no longer installed, the next
application in the list is attempted". GLib follows this (`desktop_file_dir_unindexed_read_mimeapps_lists`:
desktop-specific files first with Added/Removed refused, then `mimeapps.list`, then for data dirs
`defaults.list` and `mimeinfo.cache`; `g_app_info_get_default_for_type` collects every directory's
defaults first, then the associations, and returns the first one that is installed).

Probe: `/bin/sh` script, one isolated tree per case: `HOME`, `XDG_DATA_HOME`, `XDG_CONFIG_HOME`,
`XDG_DATA_DIRS`, `XDG_CONFIG_DIRS`, `XDG_RUNTIME_DIR` under a fresh directory,
`XDG_CURRENT_DESKTOP=` (empty), `DBUS_SESSION_BUS_ADDRESS=disabled:`, `GIO_USE_VFS=local`; the link
entry of design §4.5 at `$XDG_DATA_HOME/applications/tornect-link.desktop` with
`Exec="<stub>" "open-link" "--" %u`, where `<stub>` is a `#!/bin/sh` script that writes each argv
item as `[item]`; then `gio mime x-scheme-handler/tornect` and
`gio open tornect://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwd`.

| Case | Files besides the entry | `gio mime` default / registered | `gio open` argv |
|---|---|---|---|
| `alone` | none | "No default applications" | not run ("Operation not supported", exit 2) |
| `added` | `mimeapps.list`: `[Added Associations]` line | `tornect-link.desktop` / registered + recommended | `[open-link] [--] [tornect://…]` |
| `default` | `[Default Applications]` line only | default; **no registered, no recommended** | runs |
| `cache` | `$XDG_DATA_HOME/applications/mimeinfo.cache` line | default, registered, recommended | runs |
| `data-dir-list` | `[Added…]` in `$XDG_DATA_HOME/applications/mimeapps.list` (deprecated place) | default | runs |
| `missing-exec` | `[Added…]`; `Exec` names a missing file | "No default applications" | not run |
| `quote` | `[Added…]`; URL `tornect://abc" --home /x` | default | `[open-link] [--] [tornect://abc" --home /x]` (one element) |
| `upper-scheme` | `[Added…]`; URL `TORNECT://ABC…` | default | runs, URI passed unchanged in upper case |
| `crlf` | `[Added…]` file with CRLF line ends and a comment | default | runs |
| `spaces` | `x-scheme-handler/tornect = tornect-link.desktop;` | default | runs |
| `upper-key` | `X-Scheme-Handler/Tornect=tornect-link.desktop;` | "No default applications" | not run |
| `removed` | `[Added…]` and `[Removed…]` both naming us, same file | default, registered | runs |
| `removed-default` | `[Default…]` and `[Removed…]` naming us, same file | default | runs |
| `removed-cache` | `mimeinfo.cache` line + `[Removed…]` in `$XDG_CONFIG_HOME/mimeapps.list` | "No default applications" | not run |
| `dangling` | `[Default…]`: `gone.desktop;tornect-link.desktop;` | `tornect-link.desktop` (missing one skipped) | runs |
| `other-default` | `[Default…]`: `other.desktop;` + `[Added…]` us | `other.desktop`; we are registered | `other.desktop` runs, not us |
| `desktop-specific` | `mimeapps.list` default us; `gnome-mimeapps.list` default `other.desktop`; `XDG_CURRENT_DESKTOP=GNOME` | `other.desktop` | not us |
| `nofield` | `[Added…]`; `Exec` without `%u` | default | `[open-link] [--]` (no URI) |
| `quoted-field` | `[Added…]`; `Exec … "%u"`; URL with `"` | default | refused by GIO's shell parser |
| `bare` | `[Added…]`; `Exec=<stub> open-link -- %u` (no quotes); URL with `"` | default | `[open-link] [--] [tornect://abc" --home /x]` |

Rows `alone`, `added`, `default`, `cache`, `missing-exec` and `quote` reproduce the six container
claims at the top of the design (GLib 2.80.0 as there); the other rows are new. Note on `%u` with GVfs running (not the case here, `GIO_USE_VFS=local`):
GIO first tries a FUSE path for `%u` and falls back to the URI when there is none
(`expand_macro`: `force_file_uri_macro = 'f'`); a `tornect:` URI has no local path, so the URI is
passed. The GNOME console check (NEEDS-DEVICE(gnome)) must still show the `tornect://` URI in the
argv, not a `/run/user/…/gvfs/…` path.

### 2.2 KService (KDE) — Source; runtime NEEDS-DEVICE(kde)

`KDE/kservice` master as fetched on 2026-10-24 (`src/sycoca/kmimeassociations.cpp`,
`src/sycoca/kbuildservicefactory.cpp`):
- ksycoca reads `MimeType=` itself: for an `x-scheme-handler/…` type unknown to the MIME database
  it creates the type on demand and adds the service as an offer (`populateServiceTypes`), so on
  KDE the link entry alone registers the handler.
- `mimeapps.list` files are read from `GenericConfigLocation` then `ApplicationsLocation`
  ("XDG_CONFIG_HOME, XDG_CONFIG_DIRS, XDG_DATA_HOME, XDG_DATA_DIRS"); `[Added Associations]` and
  `[Removed Associations]` only from files named `mimeapps.list`; "Default Applications is
  preferred over Added Associations" (preference + 25). `x-scheme-handler/` keys are used verbatim.
- `kde-open` resolves the preferred service through this database (not re-read here).

### 2.3 Generic `xdg-open` / `xdg-mime` (xdg-utils 1.1.3 and 1.2.1) — VERIFIED here

Scripts from `xdg-utils_1.1.3-4.1ubuntu3_all.deb` (`apt-get download`) and
`xdg-utils_1.2.1-2ubuntu2_all.deb` (`archive.ubuntu.com/ubuntu/pool/main/x/xdg-utils/`), extracted
with `dpkg-deb -x`, run with `PATH` pointing at them, `DISPLAY=:99`, `BROWSER=/bin/false`.
- `xdg-open` picks a desktop from `XDG_CURRENT_DESKTOP` (`GNOME*` → `gio open`, `KDE` → `kde-open`
  /`kde-open5` in 1.1.3, `XFCE` → `exo-open`, then `gio open`; `X-Generic` → generic). An unknown
  value falls through to older session probes (`KDE_FULL_SESSION`, `GNOME_DESKTOP_SESSION_ID`,
  GNOME's session manager on D-Bus, `xprop`, `DESKTOP_SESSION`) and then to generic (`detectDE`).
- Generic: `open_generic_xdg_x_scheme_handler` → `xdg-mime query default x-scheme-handler/<scheme>`
  → `search_desktop_file`, which runs `Exec` with `%f %F %u %U` each replaced by `"$target"` as one
  argument (injection-safe; VERIFIED with `tornect://abc" --home /x`) but splits `Exec` without
  understanding quotes (finding 1).
- `xdg-mime query default` (generic, also used on GNOME by 1.2.1: only `lxqt` and KDE < 6 differ):
  `[Default Applications]` of each `mimeapps.list` (exact `key=` at the line start), then
  `defaults.list` / `mimeinfo.cache`, then a scan of `MimeType=` in desktop files
  (`defapp_fallback`). VERIFIED (both versions, `XDG_CURRENT_DESKTOP=GNOME`): with
  `[Default Applications]` only, with `[Added Associations]` only, and with no `mimeapps.list` at
  all, it answers `tornect-link.desktop` (the last two through the `MimeType=` scan, since it never
  reads `[Added Associations]`). It never reads `[Removed Associations]` either.
- `xdg-mime default` (what the design does not run) writes through a symlinked `mimeapps.list` to
  its target (`make_default_generic`: `xdg_realpath`); the design refuses symlinks instead.

### 2.4 Snap and Flatpak browsers — Source; runtime NEEDS-DEVICE(gnome)

- Portal: `xdg-desktop-portal` 1.20.0 `src/open-uri.c`. `SchemeSupported` answers
  `g_app_info_get_default_for_uri_scheme(scheme) != NULL`. `OpenURI` for a scheme outside
  `http https ftp mailto webcal calendar` shows the app chooser unless exactly one recommended
  handler exists (`g_app_info_get_recommended_for_type`, falling back to `get_all_for_type`) or the
  user picked the same one at least 3 times (`DEFAULT_THRESHOLD 3`); an `ask` option or the
  user's "always ask" forces the chooser. So a `tornect://` link opened through the portal skips the
  chooser when Tornect is the only recommended handler, which our `[Added Associations]` line makes
  it on a system where nothing else claims the scheme, or once the user has picked it 3 times.
- snapd: a confined snap's `xdg-open` goes to `io.snapcraft.Launcher.OpenURL`
  (`canonical/snapd` master `usersession/userd/launcher.go`): a scheme outside the allow list is
  allowed only when `xdg-mime query default x-scheme-handler/<scheme>` prints a valid desktop file
  name (`schemeHasHandler`), and then `xdg-open <url>` runs outside the sandbox. A Launchpad comment
  of 2022-03-08 (bug 1963861) says the portal is tried first and this launcher is the fallback.
  Firefox gained a `SchemeSupported` check (bug 1618094, commit title only; the page needed
  JavaScript).

## 3. Browsers: prompts, escaping, how the URL is passed — Source/Docs; Windows runtime NEEDS-DEVICE

- **Chromium (Chrome, Edge).** `ExternalProtocolHandler::GetBlockState` blocks a deny list
  (`file`, `javascript`, `data`, …) and single-letter schemes, allows `mailto news snews`, and
  prompts for anything else (`external_protocol_handler.cc` at commit `57504b7d`). Before launching
  it runs `net::EscapeExternalHandlerValue(url.spec())` ("Escape the input scheme to be sure that the
  command does not have parameters unexpected by the external program"), which "%XX everything
  except alphanumerics and -_.!~*'() and the restricted characters (;/?:@&=+$,#[]) and a valid
  percent escape sequence (%XX)" (`base/strings/escape.h`, googleurl master): a `"` or a space
  reaches the handler as `%22` / `%20`, which `parse_link` refuses (`LinkExtras`/`NotAlphabet`).
  On Linux it runs `xdg-open <url>` with the URL as one argv element
  (`chrome/browser/platform_util_linux.cc` at 74.0.3705.1: `argv.push_back(command);
  argv.push_back(arg);`). Since Chromium/Edge 84 the prompt offers "Always allow <hostname> to open
  links of this type in the associated app", stored per scheme **and** per origin, secure origins
  only ([Eric Law, 2020-02-20](https://textslashplain.com/2020/02/20/bypassing-appprotocol-prompts/)).
- **Firefox.** Since Firefox 84 a permission dialog precedes an external protocol handler and
  "always allow" is a per-site permission ([bug 1565574](https://bugzilla.mozilla.org/show_bug.cgi?id=1565574)).
  Firefox once passed spaces and `"` unescaped to external programs
  ([MFSA 2007-27, CVE-2007-3845](https://www.mozilla.org/security/advisories/mfsa2007-27/), fixed
  in 2.0.0.6). How current Firefox escapes a `"` in a `tornect://` URL on Windows is **UNVERIFIED**
  here; L-3 makes the answer harmless (finding 7).
- **Windows itself.** "When ShellExecute executes the pluggable protocol handler with a string on
  the command line, any non-encoded spaces, quotes, and backslashes in the URI will be interpreted
  as part of the command line"; mitigation: avoid them and "Quote the %1 in the registration";
  "avoidance doesn't completely solve the problem of quotes in the URI or a backslash at the end of
  the URI"; handlers "should assume that any parameters on the command line could come from
  malicious parties" ([Registering an Application to a URI Scheme, archived, 2016-07-13](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa767914(v=vs.85)?redirectedfrom=MSDN)).

## 4. Windows: the HKCU `URL Protocol` registration

### 4.1 Layout — Docs

The documented layout (same page): `HKEY_CLASSES_ROOT\alert` with `(Default) = "URL:Alert
Protocol"`, `URL Protocol = ""`, optional `DefaultIcon`, and `shell\open\command (Default) =
"C:\Program Files\Alert\alert.exe" "%1"`. The design's §4.5 keys follow it under
`HKCU\Software\Classes\tornect`. Per-user keys take part in `HKEY_CLASSES_ROOT`: "The merged view
includes all subkeys of the HKEY_CURRENT_USER\Software\Classes key" and "does not include the
HKEY_LOCAL_MACHINE contents of duplicate subkeys" ([Merged View of HKEY_CLASSES_ROOT](https://learn.microsoft.com/en-us/windows/win32/sysinfo/merged-view-of-hkey-classes-root)),
so an HKCU `tornect` key wins over an HKLM one, and writing it needs no elevation.

### 4.2 API facts — Docs + `windows-sys =0.61.2`

- `RegDeleteTreeW` ([docs](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletetreea?redirectedfrom=MSDN)):
  "Deletes the subkeys and values of the specified key recursively"; `lpSubKey`: "If this parameter
  is NULL, the subkeys and values of hKey are deleted"; hKey needs `DELETE`,
  `KEY_ENUMERATE_SUB_KEYS`, `KEY_QUERY_VALUE` (and `KEY_SET_VALUE` if it has values), or a
  predefined key such as `HKEY_CURRENT_USER`; Windows Vista+. Whether a non-NULL `lpSubKey` key is
  itself deleted is not stated; `RegDeleteKeyEx`'s page says "To delete keys recursively, use the
  RegDeleteTree or SHDeleteKey function".
- All the design's calls exist in `windows-sys-0.61.2/src/Windows/Win32/System/Registry/mod.rs`
  under the workspace's `Win32_System_Registry` feature: `RegCreateKeyExW` (line 13),
  `RegDeleteKeyW` (26), `RegDeleteTreeW` (28), `RegGetValueW` (45), `RegOpenKeyExW` (56),
  `RegSetValueExW` (90), `HKEY_CURRENT_USER` (150), `REG_CREATED_NEW_KEY = 1` (1017),
  `REG_OPENED_EXISTING_KEY = 2` (1038), `RRF_RT_REG_SZ = 2` (1087); `ERROR_FILE_NOT_FOUND = 2` in
  `Win32/Foundation`. No Cargo change.

### 4.3 Probe under Wine 9.0 — VERIFIED (Wine), real Windows NEEDS-DEVICE(windows)

A C probe built with `x86_64-w64-mingw32-clang` and run in a fresh `WINEPREFIX`, on
`HKCU\Software\Classes\tornectprobe`:

| Call | Result |
|---|---|
| `RegOpenKeyExW` of the absent key | 2 (`ERROR_FILE_NOT_FOUND`) |
| `RegCreateKeyExW` first / second time | disposition 1 `REG_CREATED_NEW_KEY` / 2 `REG_OPENED_EXISTING_KEY` |
| `RegGetValueW(hkey, L"shell\\open\\command", NULL, RRF_RT_REG_SZ, …)` size call, then read | 0, 114 bytes (56 UTF-16 units + NUL), `"C:\Program Files\Tornect\tornect.exe" open-link -- "%1"` |
| the same with `shell` deleted | 2 → the design's `UrlKey::Other` |
| `RegDeleteTreeW(HKCU, key)` | 0, and the key itself is **gone** (open → 2) |
| `RegDeleteTreeW` / `RegDeleteKeyW` on the absent key | 2 / 2 |
| `RegDeleteTreeW(hkey, NULL)` | 0, the key **stays** (values and subkeys gone) |

Wine's source agrees (`wine-9.0/dlls/kernelbase/registry.c`, `RegDeleteTreeW`: subkeys recursively,
then "Delete the key itself" via `RegDeleteKeyExW(hkey, L"", 0, 0)` when `subkey` is non-empty;
with NULL only the values go).

### 4.4 Argument splitting of a hostile link — VERIFIED (Wine)

A launcher expanded `"<exe>" open-link -- "%1"` literally and started a Rust 1.96
`std::env::args_os` printer (`x86_64-pc-windows-gnullvm`) with `CreateProcessW`:

| `%1` | argv after the program name |
|---|---|
| `tornect://<56 chars>` | `[open-link] [--] [tornect://<56 chars>]` |
| `tornect://abc" --home C:\x` | `[open-link] [--] [tornect://abc] [--home] [C:\x]` |
| `tornect://abc" --home "C:\x` | `[open-link] [--] [tornect://abc] [--home] [C:\x]` |
| `tornect://abc\` | `[open-link] [--] [tornect://abc"]` |
| `tornect://abc\" open-link -- "x` | `[open-link] [--] [tornect://abc" open-link -- x]` |
| `tornect://a b` | `[open-link] [--] [tornect://a b]` |

Every injected word arrives after `--`, so clap reads it as a positional, never as `--home`, `--log`
or a subcommand; one positional is allowed, so the extra ones are an error (design L-3), and the
remaining single-argument forms are refused by `parse_link`.

## 5. CVE-2018-1000006 and the `--` mitigation — Docs

"A remote code execution vulnerability has been discovered affecting Electron apps that use custom
protocol handlers"; affected: "Electron apps designed to run on Windows that register themselves as
the default handler"; "macOS and Linux are not vulnerable". The fix recommended appending `--` to
the registered arguments, which "prevents Chromium from parsing further options"; fixed in 1.8.2-beta.5,
1.7.12 and 1.6.17 ([Electron blog, 2018-01-22](https://electronjs.org/blog/protocol-handler-fix)).
The mechanism matches §4.4: a `"` in the URL ends the quoted `%1` and the rest became Chromium
switches. Tornect's registration puts `--` before `"%1"`, and `open-link` takes exactly one
positional, so the same URL is a clap error, not an option.

## 6. Not verified here (each has a NEEDS-DEVICE row)

- GNOME at the console: `xdg-open`, the GNOME notification on a warm launch, Snap Firefox through
  the portal (does the chooser appear?), Chrome through `xdg-open`; GVfs's `%u` handling.
- KDE: `kde-open tornect://<id>` with only the link entry, then with the `mimeapps.list` lines.
- A generic desktop (`XDG_CURRENT_DESKTOP` unknown): `xdg-open` with the step-9 `Exec` form.
- Windows 10/11: `RegDeleteTreeW` deleting the named key, the `REG_OPENED_EXISTING_KEY` race check,
  and how Edge, Chrome and Firefox escape a `"` in a clicked `tornect://` link.
