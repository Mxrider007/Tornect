# Research: monitor switching (design `monitors`, Part 1)

**Status:** verified 2026-10-24 for the design's step 1, in the build container (not the dev VM), against
the crate sources in the cargo registry (winit 0.30.13, x11rb 0.13.2 and x11rb-protocol 0.13.2,
windows-sys 0.61.2), a probe run against Xvfb (xorg-server 21.1.12, Ubuntu package
`2:21.1.12-1ubuntu1.9`), and Microsoft Learn pages fetched the same day. Decision: M1-75.

Part 2's research (the design's step 21: the GNOME RemoteDesktop dialog with `multiple`, a repeated
`OpenPipeWireRemote`, a new consumer of a still screen, per-stream `NotifyPointerMotionAbsolute`, restoring a
token issued under `multiple = false`) is **not** here: it needs the GNOME session of the dev VM.

## 1. Windows: monitor rectangles under per-monitor v2 DPI awareness

- **Enumeration.** `EnumDisplayMonitors(NULL, NULL, proc, data)` "Enumerates all display monitors. The callback
  function receives a NULL HDC", and then the callback's rectangle "is the display monitor rectangle. The
  rectangle coordinates are virtual-screen coordinates". The callback returns TRUE to continue and FALSE to stop
  ([EnumDisplayMonitors](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumdisplaymonitors),
  [MonitorEnumProc](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nc-winuser-monitorenumproc)).
  The order is not documented, so the capture sorts by `(x, y)` (design §5.4.3).
- **`MONITORINFO`.** `rcMonitor` is "the display monitor rectangle, expressed in virtual-screen coordinates. Note
  that if the monitor is not the primary display monitor, some of the rectangle's coordinates may be negative
  values"; `dwFlags & MONITORINFOF_PRIMARY` marks the primary
  ([MONITORINFO](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-monitorinfo)). That is the
  space of `SM_XVIRTUALSCREEN`/`SM_YVIRTUALSCREEN` and of the screen DC `GetDC(NULL)`, which the GDI capture
  already `BitBlt`s from at a negative origin, so a monitor's rectangle is grabbed by the same blit at
  `rcMonitor`'s corner.
- **DPI.** Microsoft does not list which APIs are virtualized: "When an HWND or process is running as either DPI
  unaware or system DPI aware … Windows scales and converts DPI-sensitive information from some APIs to the
  coordinate space of the calling thread" and "if you call any system API from a DPI-unaware or
  system-DPI-aware thread context, the return value might be virtualized"; a per-monitor v2 process sees "the raw
  pixels of each display"
  ([High DPI desktop application development](https://learn.microsoft.com/en-us/windows/win32/hidpi/high-dpi-desktop-application-development-on-windows)).
  So every process that measures monitors or the virtual desktop must set
  `SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)` before its first call. Today the CLI
  host does it in `GdiCapture::open` (`tornect-capture/src/gdi.rs`), the GUI gets it from winit (§4), and the
  **administrator helper does not**: `helper_cmd.rs` makes no DPI call and the repository has no application
  manifest (`grep -r dpiAware` finds nothing). `tornect doctor` opens no capture and no window, so it must call it
  itself too (design §5.4.6).
- **windows-sys 0.61.2** (read in the registry source): `EnumDisplayMonitors(hdc: HDC, lprcclip: *const RECT,
  lpfnenum: MONITORENUMPROC, dwdata: LPARAM)`, `GetMonitorInfoW(hmonitor, *mut MONITORINFO)`, `MONITORINFO
  { cbSize, rcMonitor, rcWork, dwFlags }`, `MONITORINFOEXW { monitorInfo, szDevice: [u16; 32] }` and
  `MONITORENUMPROC` are in `Win32::Graphics::Gdi` (`Graphics/Gdi/mod.rs:95, 194, 3206–3231`);
  `MONITORINFOF_PRIMARY: u32 = 1` is in `Win32::UI::WindowsAndMessaging` (`mod.rs:2328`);
  `SetProcessDpiAwarenessContext` is in `Win32::UI::HiDpi`. The workspace pin already enables all three features,
  and the pin is shared by `tornect-input`, so moving `become_dpi_aware` there (design §5.2) needs no manifest
  change.

## 2. `SendInput` with `MOUSEEVENTF_VIRTUALDESK` against the caller's DPI awareness

- **What is documented.** "If MOUSEEVENTF_ABSOLUTE value is specified, dx and dy contain normalized absolute
  coordinates between 0 and 65,535 … Coordinate (0,0) maps onto the upper-left corner of the display surface;
  coordinate (65535,65535) maps onto the lower-right corner", and "If MOUSEEVENTF_VIRTUALDESK is specified, the
  coordinates map to the entire virtual desktop"
  ([MOUSEINPUT](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-mouseinput)). The page says
  nothing about DPI, and Windows' own rounding of a normalized coordinate to a pixel is not documented.
- **A field report.** [LanternOps/breeze #5599](https://github.com/LanternOps/breeze/pull/5599): a system-aware
  remote-desktop helper whose monitor offsets came from DXGI (physical pixels) clicked about one scale factor off
  on a secondary monitor whose scale differed from the primary's, because `SendInput` with absolute virtual-desk
  coordinates, `SetCursorPos`, `GetCursorInfo` and the `GetSystemMetrics` virtual-screen metrics were virtualized
  in that mode; the fix was per-monitor v2 awareness. The PR itself says it was not verified on a two-monitor
  rig, so this corroborates the rule above; it does not prove it.
- **For the design.** Under per-monitor v2 the virtual desktop the injector addresses is the physical one the
  capture grabs, and the existing `normalize`/`denormalize` pair (0 is pixel 0, 65535 is pixel `size − 1`) maps
  linearly over it. A DPI-unaware or system-aware process on a mixed-DPI desktop sees a virtual desktop that is
  **not** a uniform scale of the physical one, so no normalization can be exact there: the helper must become
  per-monitor v2 before it builds its sink (design step 5). The corner clicks on a mixed-DPI rig (150 % and
  100 %, the second monitor left of the primary, so with negative x), through the host's own sink and through
  the helper, stay NEEDS-DEVICE(windows) (design §8, Windows item 4).

## 3. Xvfb and RandR 1.5 `SetMonitor` (probe run here)

A throwaway program (x11rb 0.13.2 with `randr`, built in the scratch directory, not committed) asked for RandR
1.6, listed the CRTCs and `GetMonitors(root, get_active = true)`, set two monitors, set one again under the same
name, deleted both, and deleted an unknown name, under
`xvfb-run -a -s "-screen 0 2304x768x24"`. Output with monitor A claiming the server's one output and B none
(the timestamps and the errors' sequence and opcode fields left out):

```text
root 2304x768
randr 1.6
crtcs [59] outputs [60] primary output 0
  crtc 59: 2304x768+0+0 outputs [60]
before: 1 monitors
  name="screen" primary=false automatic=true 2304x768+0+0 mm=610x203 outputs=[60]
set A: Ok(())
set B: Ok(())
after set: 2 monitors
  name="TORNECT-TEST-A" primary=true automatic=false 1280x720+0+0 mm=0x0 outputs=[60]
  name="TORNECT-TEST-B" primary=false automatic=false 1024x768+1280+0 mm=0x0 outputs=[]
set A again: Err(X11Error { error_kind: Value, error_code: 2, bad_value: 229, extension_name: Some("RANDR"), request_name: Some("SetMonitor"), .. })
delete A: Ok(())
delete B: Ok(())
after delete: 1 monitors
  name="screen" primary=false automatic=true 2304x768+0+0 mm=610x203 outputs=[60]
delete unknown: Err(X11Error { error_kind: Value, error_code: 2, extension_name: Some("RANDR"), request_name: Some("DeleteMonitor"), .. })
```

1. **Xvfb takes `SetMonitor`.** It answers QueryVersion with 1.6 (a client asking for 1.5 gets 1.5), so the
   design's Xvfb test can run as written; its fallback (skip, and a `trait Monitors` seam test) is not needed.
2. **Without user monitors** there is one automatic monitor per active CRTC, here "screen" 2304×768+0+0 for the
   one CRTC, and it is **not primary**: Xvfb sets no primary output (`GetOutputPrimary` gives 0). The chooser's
   "no primary means monitor 1" rule is the one that runs under Xvfb by default.
3. **A user monitor with no outputs is added beside the automatic one**: with both A and B set with `outputs = []`
   the list held three monitors, the automatic "screen" spanning both. Only when a user monitor claims the
   CRTC's output (A with `outputs = [60]` above) does the automatic one go. The Xvfb test therefore gives its first
   monitor the root's output.
4. **A name already in use is refused** with `BadValue`, although the protocol says the existing monitor is
   replaced ([xorg-server MR 1113](https://gitlab.freedesktop.org/xorg/xserver/-/merge_requests/1113) removes that
   check; 21.1.12 still has it), and deleting an unknown name is `BadValue` too. The test deletes before it sets
   again, and its cleanup tolerates `BadValue`.
5. **User monitors belong to the server, not the client**: they outlive the connection that set them. The test
   deletes them at the end (design §7), and `xvfb-run -a` gives each run its own server anyway.
6. The geometry is `x: i16, y: i16, width: u16, height: u16` in root pixels, so the capture's `Found` rectangles
   fit `Rect` without loss.

x11rb 0.13.2 (read in the registry source): `randr_query_version(major, minor)`,
`randr_get_monitors(window, get_active)`, `randr_set_monitor(window, MonitorInfo)` and
`randr_delete_monitor(window, name)` (`x11rb/src/protocol/randr.rs:720, 882–890`), and
`MonitorInfo { name, primary, automatic, x, y, width, height, width_in_millimeters, height_in_millimeters,
outputs }` (`x11rb-protocol/src/protocol/randr.rs:6675`). The app's build already compiles x11rb with `randr`
and `render`, through winit (`cargo tree -p tornect -e features -i x11rb`), so the workspace pin gaining
`randr` (design §5.4.1) adds nothing to the app; it adds the module to `tornect-capture`'s and
`tornect-input`'s own builds.

## 4. winit's monitor positions against GDI and RandR

- **Windows** (`winit-0.30.13/src/platform_impl/windows/monitor.rs`): `available_monitors()` is
  `EnumDisplayMonitors(0, null, ..)` in enumeration order; `position()` is `rcMonitor.left/top` and `size()` is
  `rcMonitor`'s width and height, both read through `GetMonitorInfoW` with a `MONITORINFOEXW`; `primary_monitor()`
  is `MonitorFromPoint((0, 0), MONITOR_DEFAULTTOPRIMARY)`. winit's event loop sets per-monitor v2 awareness
  (falling back to v1) unless told not to (`dpi.rs::become_dpi_aware`, `event_loop.rs:199`). So in the GUI
  process winit's monitors **are** the GDI enumeration's rectangles, in physical virtual-screen coordinates, and
  the indicator (design step 19) can compare a session's shown rectangle with winit's `PhysicalPosition` and
  `PhysicalSize` directly.
- **X11** (`platform_impl/linux/x11/monitor.rs::query_monitor_list`): winit lists **CRTCs**
  (`GetScreenResourcesCurrent` + `GetCrtcInfo`), skipping those with no size or no output; the position is the
  CRTC's `x, y` and the size its `width, height` in root pixels; a CRTC is primary when its first output is
  `GetOutputPrimary`'s, and when none is, winit marks the first CRTC primary. The list is cached and re-read on
  RandR events (`CRTC_CHANGE | OUTPUT_PROPERTY | SCREEN_CHANGE`). RandR 1.5 `GetMonitors` gives one automatic
  monitor per active CRTC (§3, finding 2), so on a plain Xorg setup winit's monitors and the capture's coincide.
  They differ when user monitors exist (`xrandr --setmonitor`, for a split ultrawide or a tiled 5K panel: RandR
  lists them, winit still lists CRTCs) and for a mirrored CRTC whose primary output is not its first. Both are
  rectangles in the same root space, so the indicator's largest-overlap rule (design §5.7 `monitor_for`) still
  picks the CRTC under the shown monitor, and with no overlap it falls back to the primary.

## 5. What this changes in the design

1. **Wire codes.** The quality feature took 0x50–0x52 (decision M1-74 (4)); this feature takes the next free pair,
   **0x53 `SelectMonitor`** and **0x54 `Monitors`** (design §3: "use the next free pair").
2. **The X11 test** (design step 14) gives its first RandR monitor the root's output, deletes before it sets a
   name again, and tolerates `BadValue` when it cleans up (§3).
3. **The administrator helper** becomes per-monitor v2 before it reads the virtual desktop or injects (design
   step 5; §1 and §2).
4. **The indicator** compares rectangles in physical virtual-screen coordinates on Windows and root coordinates on
   X11 (§4).
5. **The codec part** (design §5.1, steps 2 and 3) is the quality feature's scaler, which landed first (design
   §10: "whichever spec lands first owns them"): see decision M1-75.

## 6. Still open

| What | Where |
|---|---|
| `rcMonitor` at 150 % and 100 % with a monitor at negative x; the corner clicks through `SendInput` and through the helper | NEEDS-DEVICE(windows), design §8 |
| `GetMonitors` on a real Xorg with two outputs and a primary set; `xrandr --output X --off` during a session | NEEDS-DEVICE(x11), design §8 |
| Part 2's portal and PipeWire questions (design step 21) | NEEDS-DEVICE(linux dev VM, GNOME) |
