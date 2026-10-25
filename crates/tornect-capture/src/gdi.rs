//! Windows capture through GDI (`docs/research/slice.md` §6): `BitBlt` of the
//! monitor shown, or of all of them, out of the virtual desktop into a
//! top-down 32-bit DIB section, with the cursor drawn by `DrawIconEx`. DXGI
//! Desktop Duplication is the step after the slice.
//!
//! **Monitors** (decision M1-75, the monitors design §5.4.6). Every grab
//! lists the desktop's monitors (`EnumDisplayMonitors`, `GetMonitorInfoW`'s
//! `rcMonitor`, virtual-screen coordinates, physical pixels once the process
//! is per-monitor aware) and grabs only the even rectangle of the one shown,
//! or the monitors' bounding box for all of them; a session opens on the
//! primary of two or more. A monitor is held by its device name (`szDevice`,
//! `\\.\DISPLAY1`), which stays in memory: it is never logged or sent.
//!
//! The picture's [`View`](crate::View) places that rectangle on the virtual
//! desktop from `SM_XVIRTUALSCREEN` / `SM_YVIRTUALSCREEN`, the space
//! `tornect-input`'s `SendInput` addresses with `MOUSEEVENTF_VIRTUALDESK`, so
//! the host's `Viewport` maps the viewer's pointer onto exactly the monitor
//! the picture shows.
//!
//! Every GDI object is created and released inside one `next_frame` call: GDI
//! handles are raw pointers (not `Send`), and a capture that owns none across
//! calls can move between threads freely.
//!
//! Limits (Windows by design): the secure desktop (UAC prompt, Ctrl+Alt+Del,
//! lock screen) cannot be captured from a user-session process. A grab that
//! fails then is waited out (`outage.rs`): `next_frame` says there is no
//! new picture, the viewer keeps the last one (in a control session the
//! host's secure-screen notice tells it why), and capture ends only when the
//! screen stays unreadable for a minute.
#![allow(unsafe_code)]

use std::ptr::{null, null_mut};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{LPARAM, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleDC, CreateDIBSection,
    DIB_RGB_COLORS, DeleteDC, DeleteObject, EnumDisplayMonitors, GdiFlush, GetDC, GetMonitorInfoW,
    HBITMAP, HDC, HGDIOBJ, HMONITOR, MONITORINFO, MONITORINFOEXW, ROP_CODE, ReleaseDC, SRCCOPY,
    SelectObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CURSOR_SHOWING, CURSORINFO, DI_NORMAL, DrawIconEx, GetCursorInfo, GetIconInfo,
    GetSystemMetrics, ICONINFO, MONITORINFOF_PRIMARY, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN,
    SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};
use windows_sys::core::BOOL;

use crate::monitors::{Chooser, Found, Resolved, listed};
use crate::outage::Outage;
use crate::{CaptureError, Frame, Layout, MAX_MONITORS, Monitor, Rect, Selection, VideoSource};

/// A monitor's device name (`MONITORINFOEXW::szDevice`, `\\.\DISPLAY1`,
/// NUL-padded): what the viewer's choice is held by. In memory only.
type Device = [u16; 32];

/// The most monitors one enumeration collects. Above [`MAX_MONITORS`], so
/// that on a desktop of more the chooser keeps the first 16 by position, as
/// a layout promises, whatever order Windows enumerates them in; bounded,
/// so the callback's list stays small whatever the enumeration does.
const MAX_FOUND: usize = 4 * MAX_MONITORS;

/// Grabs the monitor of this user session's desktop the viewer chose, or
/// all of them.
#[derive(Default)]
pub struct GdiCapture {
    /// The spell of failed grabs under way, if any.
    outage: Outage,
    /// The viewer's choice, held by device name.
    chooser: Chooser<Device>,
    /// The monitors of the latest picture and what it showed: what a
    /// selection is taken against.
    resolved: Option<Resolved<Device>>,
    /// What the picture returned last shows.
    layout: Option<Layout>,
}

impl std::fmt::Debug for GdiCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Resolved`'s own `Debug` leaves the device names out.
        f.debug_struct("GdiCapture")
            .field("outage", &self.outage)
            .field("resolved", &self.resolved)
            .finish_non_exhaustive()
    }
}

/// The raster operation of every grab: a plain copy, without `CAPTUREBLT`.
/// With that flag Windows hides the pointer and shows it again around each
/// blit, so the host's own pointer flickers at the capture rate for as long
/// as a session lasts (Mozilla bug 1053264, which dropped it wherever DWM
/// composes). The flag only added layered windows, and DWM, always on since
/// Windows 8 and so on every supported target (Windows 10 20H1+), composes
/// them into the screen DC already. The cursor is drawn by `DrawIconEx`
/// either way: a blit never copies it.
const RASTER_OP: ROP_CODE = SRCCOPY;

/// The virtual desktop: its origin and size, in physical pixels under
/// per-monitor awareness. What every grab is cut from and the injector
/// addresses; `None` when it has no size (a service session has no desktop).
fn virtual_desktop() -> Option<Rect> {
    // SAFETY: `GetSystemMetrics` has no preconditions and only reads.
    let (x, y, width, height) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    };
    desktop_rect(x, y, width, height)
}

/// The rectangle of a virtual desktop whose metrics read `x`, `y`, `width`
/// and `height`; `None` for a size that is not above zero.
fn desktop_rect(x: i32, y: i32, width: i32, height: i32) -> Option<Rect> {
    let width = u32::try_from(width).ok().filter(|&w| w > 0)?;
    let height = u32::try_from(height).ok().filter(|&h| h > 0)?;
    Some(Rect::new(x, y, width, height))
}

/// The desktop's monitors as Windows lists them, keyed by device name, in
/// the order of the enumeration (the chooser sorts them), at most
/// [`MAX_FOUND`]. None when the enumeration fails: the virtual desktop is
/// then the one monitor.
fn monitors() -> Vec<Found<Device>> {
    let mut found: Vec<Found<Device>> = Vec::with_capacity(MAX_FOUND);
    // SAFETY: a null DC and a null clip rectangle enumerate every monitor of
    // the virtual desktop. `collect` runs only inside this call, on this
    // thread, with `data` the address of `found`, which outlives the call
    // and is not otherwise touched until it returns.
    let enumerated = unsafe {
        EnumDisplayMonitors(
            null_mut(),
            null(),
            Some(collect),
            (&raw mut found) as LPARAM,
        )
    };
    if enumerated == 0 {
        tracing::debug!(
            error = %std::io::Error::last_os_error(),
            "EnumDisplayMonitors failed: the virtual desktop is the one monitor"
        );
        found.clear();
    }
    found
}

/// `EnumDisplayMonitors`' callback: reads one monitor into the list `data`
/// points at, and says whether to go on.
///
/// # Safety
/// `data` is the address of a live `Vec<Found<Device>>` that nothing else
/// borrows while the enumeration runs (`monitors` passes its own list).
unsafe extern "system" fn collect(
    monitor: HMONITOR,
    _dc: HDC,
    _rect: *mut RECT,
    data: LPARAM,
) -> BOOL {
    // SAFETY: per this function's contract `data` is the address of a live
    // vector borrowed by nothing else until `EnumDisplayMonitors` returns,
    // which calls this function only before it does.
    let found = unsafe { &mut *(data as *mut Vec<Found<Device>>) };
    let mut info = MONITORINFOEXW {
        monitorInfo: MONITORINFO {
            cbSize: size_of::<MONITORINFOEXW>() as u32,
            ..Default::default()
        },
        szDevice: [0; 32],
    };
    // SAFETY: `monitor` is the handle the enumeration hands this callback;
    // `info` is a writable `MONITORINFOEXW` whose `cbSize` says so, which
    // `GetMonitorInfoW` takes through a pointer to its first field and fills
    // with the device name too.
    let read = unsafe { GetMonitorInfoW(monitor, (&raw mut info).cast::<MONITORINFO>()) } != 0;
    BOOL::from(gather(found, read.then_some(&info)))
}

/// Adds the monitor `info` describes (`None`: one that could not be read,
/// such as one unplugged during the enumeration) to `found`, and says
/// whether the enumeration goes on: until `found` holds [`MAX_FOUND`].
fn gather(found: &mut Vec<Found<Device>>, info: Option<&MONITORINFOEXW>) -> bool {
    if found.len() < MAX_FOUND
        && let Some(monitor) = info.and_then(found_of)
    {
        found.push(monitor);
    }
    found.len() < MAX_FOUND
}

/// The monitor `info` describes: `rcMonitor` (virtual-screen coordinates,
/// negative left of or above the primary), the primary flag and the device
/// name; `None` for a rectangle with no area.
fn found_of(info: &MONITORINFOEXW) -> Option<Found<Device>> {
    let r = info.monitorInfo.rcMonitor;
    let side = |from: i32, to: i32| {
        u32::try_from(i64::from(to) - i64::from(from))
            .ok()
            .filter(|&len| len > 0)
    };
    Some(Found {
        key: info.szDevice,
        rect: Rect::new(
            r.left,
            r.top,
            side(r.left, r.right)?,
            side(r.top, r.bottom)?,
        ),
        primary: info.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0,
    })
}

/// The monitors of this Windows desktop, numbered as a session's layout
/// lists them (`tornect doctor`): every monitor `EnumDisplayMonitors`
/// lists, cut to the virtual desktop. Makes the process per-monitor aware
/// first, so a process with no window reads physical pixels, as the
/// capture and the injector do; one that cannot be says so in its log.
pub fn desktop_monitors() -> Result<Vec<Monitor>, CaptureError> {
    if !tornect_input::windows::become_dpi_aware() {
        tracing::warn!(
            "this process is not per-monitor DPI aware: on a high-DPI desktop the monitors \
             are listed in scaled units"
        );
    }
    let space = virtual_desktop().ok_or_else(no_desktop)?;
    Ok(listed(monitors(), space))
}

fn no_desktop() -> CaptureError {
    CaptureError::Unavailable("no desktop to capture (a service session has none)".to_owned())
}

impl GdiCapture {
    /// A capture of the interactive desktop.
    pub fn open() -> Result<Self, CaptureError> {
        // Measure in physical pixels, as the injector addresses them: without
        // per-monitor awareness Windows reports a scaled desktop and `BitBlt`
        // copies a scaled, partial picture on a high-DPI monitor. A process
        // whose awareness was fixed otherwise still captures; the injector
        // says so in the log too.
        if !tornect_input::windows::become_dpi_aware() {
            tracing::warn!(
                "this process is not per-monitor DPI aware: on a high-DPI desktop the \
                 picture can be scaled or partial"
            );
        }
        virtual_desktop().ok_or_else(no_desktop)?;
        Ok(Self::default())
    }
}

/// Releases GDI objects when the grab returns, whichever way it returns.
struct Gdi {
    screen: HDC,
    memory: HDC,
    bitmap: HBITMAP,
    previous: HGDIOBJ,
}

impl Drop for Gdi {
    fn drop(&mut self) {
        // SAFETY: each handle was created in `grab` and is released exactly once,
        // in reverse order: the bitmap is deselected before it is deleted, and
        // the screen DC goes back to the window it came from (the desktop, null).
        unsafe {
            if !self.previous.is_null() {
                SelectObject(self.memory, self.previous);
            }
            if !self.bitmap.is_null() {
                DeleteObject(self.bitmap);
            }
            if !self.memory.is_null() {
                DeleteDC(self.memory);
            }
            if !self.screen.is_null() {
                ReleaseDC(null_mut(), self.screen);
            }
        }
    }
}

fn gdi_failed(what: &str) -> CaptureError {
    CaptureError::Failed(format!(
        "{what} failed: {}",
        std::io::Error::last_os_error()
    ))
}

/// A picture of `rect` of the virtual desktop (a monitor's even rectangle,
/// or the bounding box of all of them), the cursor drawn in.
fn grab(rect: Rect) -> Result<Frame, CaptureError> {
    let (x, y, width, height) = (rect.x, rect.y, rect.width, rect.height);
    let (Ok(w), Ok(h)) = (i32::try_from(width), i32::try_from(height)) else {
        return Err(CaptureError::Failed(format!(
            "a grab of {width}x{height} is out of range"
        )));
    };
    if w <= 0 || h <= 0 {
        return Err(CaptureError::Failed("the desktop has no size".to_owned()));
    }
    let mut gdi = Gdi {
        screen: null_mut(),
        memory: null_mut(),
        bitmap: null_mut(),
        previous: null_mut(),
    };
    let mut bits: *mut core::ffi::c_void = null_mut();
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            // Negative height: a top-down DIB, row 0 is the top of the screen.
            biHeight: -h,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..Default::default()
        },
        ..Default::default()
    };
    // From the screen DC through the copy and the pad bytes: the grab's own
    // cost, timed outside the `unsafe` blocks.
    let started = Instant::now();
    // SAFETY: every call gets handles created just above and checked for null;
    // `info` lives across `CreateDIBSection`, which writes the DIB's address to
    // `bits`. `Gdi`'s drop releases every object, on every path.
    unsafe {
        gdi.screen = GetDC(null_mut());
        if gdi.screen.is_null() {
            return Err(gdi_failed("GetDC"));
        }
        gdi.memory = CreateCompatibleDC(gdi.screen);
        if gdi.memory.is_null() {
            return Err(gdi_failed("CreateCompatibleDC"));
        }
        gdi.bitmap = CreateDIBSection(gdi.memory, &info, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
        if gdi.bitmap.is_null() || bits.is_null() {
            return Err(gdi_failed("CreateDIBSection"));
        }
        gdi.previous = SelectObject(gdi.memory, gdi.bitmap);
        if BitBlt(gdi.memory, 0, 0, w, h, gdi.screen, x, y, RASTER_OP) == 0 {
            return Err(gdi_failed("BitBlt"));
        }
        draw_cursor(gdi.memory, x, y);
        GdiFlush();
    }
    let captured_at = Instant::now();
    let len = (width as usize) * (height as usize) * 4;
    // SAFETY: the DIB section is a top-down 32-bit bitmap of exactly w × h
    // pixels, so `bits` points at `len` initialised bytes owned by `gdi.bitmap`,
    // which lives (and is flushed) until the copy below is done.
    let mut bgrx = unsafe { std::slice::from_raw_parts(bits.cast::<u8>(), len) }.to_vec();
    drop(gdi);
    // GDI leaves the fourth byte undefined (zero, usually).
    for px in bgrx.chunks_exact_mut(4) {
        px[3] = 0xff;
    }
    Ok(Frame {
        width,
        height,
        bgrx,
        captured_at,
        grab: started.elapsed(),
    })
}

/// Draw the cursor, if one is showing, at its place on the virtual desktop
/// whose top-left corner is `(x, y)` and whose picture `dc` holds.
///
/// # Safety
/// `dc` must be a valid memory DC with the capture's bitmap selected.
unsafe fn draw_cursor(dc: HDC, x: i32, y: i32) {
    let mut ci = CURSORINFO {
        cbSize: size_of::<CURSORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `ci` is a correctly sized, writable CURSORINFO.
    if unsafe { GetCursorInfo(&mut ci) } == 0 || (ci.flags & CURSOR_SHOWING) == 0 {
        return;
    }
    let mut ii = ICONINFO::default();
    // SAFETY: `ii` is writable; the call creates two bitmaps we delete below.
    if unsafe { GetIconInfo(ci.hCursor, &mut ii) } == 0 {
        return;
    }
    let (hx, hy) = (ii.xHotspot as i32, ii.yHotspot as i32);
    // SAFETY: `dc` is valid per this function's contract; the icon handle came
    // from `GetCursorInfo`; the two bitmaps are ours to delete (null is skipped).
    unsafe {
        DrawIconEx(
            dc,
            ci.ptScreenPos.x - x - hx,
            ci.ptScreenPos.y - y - hy,
            ci.hCursor,
            0,
            0,
            0,
            null_mut(),
            DI_NORMAL,
        );
        if !ii.hbmMask.is_null() {
            DeleteObject(ii.hbmMask);
        }
        if !ii.hbmColor.is_null() {
            DeleteObject(ii.hbmColor);
        }
    }
}

impl VideoSource for GdiCapture {
    fn name(&self) -> &'static str {
        "gdi"
    }

    /// Polls: every call lists the monitors and copies the one shown, or
    /// all of them. A copy that fails (a secure screen shows) waits
    /// `timeout` and answers `Ok(None)`, for up to a minute in a row; the
    /// layout then stays the last picture's.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let chooser = &mut self.chooser;
        let mut shown = None;
        let frame = self.outage.poll(timeout, || {
            // Asked every time: a monitor can be plugged, unplugged, moved or
            // given another mode between two pictures.
            let space = virtual_desktop()
                .ok_or_else(|| CaptureError::Failed("the desktop has no size".to_owned()))?;
            let resolved = chooser.resolve(monitors(), space);
            let frame = grab(resolved.grab)?;
            shown = Some(resolved);
            Ok(frame)
        })?;
        if let Some(resolved) = shown {
            self.layout = Some(resolved.layout());
            self.resolved = Some(resolved);
        }
        Ok(frame)
    }

    fn layout(&self) -> Option<Layout> {
        self.layout.clone()
    }

    /// Instant: the next grab shows `selection`, taken against the monitors
    /// of the latest picture (none before the first).
    fn select(&mut self, selection: Selection, _stop: &AtomicBool) -> Result<(), CaptureError> {
        match &self.resolved {
            Some(last) => self.chooser.select(selection, last),
            None => Err(CaptureError::NoMonitor(match selection {
                Selection::All => 0,
                Selection::Monitor(id) => id,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::View;

    /// `name` as `szDevice` holds it: UTF-16, NUL-padded.
    fn device(name: &str) -> Device {
        let mut device = [0; 32];
        for (slot, unit) in device.iter_mut().zip(name.encode_utf16()) {
            *slot = unit;
        }
        device
    }

    /// What `GetMonitorInfoW` fills in for a monitor at `rcMonitor`
    /// `(left, top, right, bottom)` named `name`, with a taskbar 40 px high
    /// cut from its work area.
    fn info(rc: (i32, i32, i32, i32), primary: bool, name: &str) -> MONITORINFOEXW {
        let (left, top, right, bottom) = rc;
        MONITORINFOEXW {
            monitorInfo: MONITORINFO {
                cbSize: size_of::<MONITORINFOEXW>() as u32,
                rcMonitor: RECT {
                    left,
                    top,
                    right,
                    bottom,
                },
                rcWork: RECT {
                    left,
                    top,
                    right,
                    bottom: bottom.saturating_sub(40),
                },
                dwFlags: if primary { MONITORINFOF_PRIMARY } else { 0 },
            },
            szDevice: device(name),
        }
    }

    /// A monitor is its whole `rcMonitor` (not the work area), at a
    /// negative x when it lies left of the primary, with the primary flag
    /// and the device name as its key; a rectangle with no area is none.
    #[test]
    fn a_monitor_is_read_from_its_rectangle_flag_and_name() {
        let left = found_of(&info((-1920, 0, 0, 1080), false, r"\\.\DISPLAY2")).unwrap();
        assert_eq!(left.rect, Rect::new(-1920, 0, 1920, 1080));
        assert!(!left.primary);
        assert_eq!(left.key, device(r"\\.\DISPLAY2"));
        let main = found_of(&info((0, 0, 2560, 1440), true, r"\\.\DISPLAY1")).unwrap();
        assert_eq!(main.rect, Rect::new(0, 0, 2560, 1440));
        assert!(main.primary);
        assert_ne!(main.key, left.key);
        for rc in [
            (0, 0, 0, 1080),
            (0, 0, 1920, 0),
            (100, 0, 0, 1080),
            (0, 100, 1920, 0),
        ] {
            assert!(found_of(&info(rc, false, "none")).is_none(), "{rc:?}");
        }
        // The widest rectangle a RECT holds is measured, not wrapped (the
        // chooser cuts it to the virtual desktop).
        let widest = found_of(&info((i32::MIN, i32::MIN, i32::MAX, i32::MAX), false, "w")).unwrap();
        assert_eq!(
            widest.rect,
            Rect::new(i32::MIN, i32::MIN, u32::MAX, u32::MAX)
        );
    }

    /// One enumeration collects monitors until it holds [`MAX_FOUND`] and
    /// then stops, skipping one that could not be read; of those the
    /// layout lists the first 16 by position, whatever order Windows
    /// enumerated them in.
    #[test]
    fn the_enumeration_stops_once_its_list_is_full() {
        let mut found = Vec::new();
        assert!(gather(&mut found, None));
        assert!(found.is_empty());
        let count = MAX_FOUND as i32 + 5;
        let infos: Vec<MONITORINFOEXW> = (0..count)
            .rev()
            .map(|i| info((i * 100, 0, i * 100 + 100, 100), false, "m"))
            .collect();
        let went_on: Vec<bool> = infos.iter().map(|i| gather(&mut found, Some(i))).collect();
        assert_eq!(found.len(), MAX_FOUND);
        assert!(went_on[..MAX_FOUND - 1].iter().all(|&on| on));
        assert!(went_on[MAX_FOUND - 1..].iter().all(|&on| !on));
        let list = listed(found, Rect::new(0, 0, 100 * count as u32, 100));
        assert_eq!(list.len(), MAX_MONITORS);
        // Collected: x from 100 · (count - 1) down to 500; listed: from 500 on.
        assert_eq!(list[0].rect, Rect::new(500, 0, 100, 100));
        assert_eq!(list[15].rect, Rect::new(2000, 0, 100, 100));
    }

    /// A virtual desktop is one with a size above zero, at any origin.
    #[test]
    fn a_virtual_desktop_needs_a_size() {
        assert_eq!(
            desktop_rect(-1920, -200, 4480, 1440),
            Some(Rect::new(-1920, -200, 4480, 1440))
        );
        for (w, h) in [(0, 1080), (1920, 0), (-1, 1080), (1920, -5)] {
            assert_eq!(desktop_rect(0, 0, w, h), None, "{w}x{h}");
        }
    }

    /// Before its first picture a capture lists no monitors, so every
    /// selection names a monitor it does not have; after it, a selection is
    /// taken against that picture's monitors.
    #[test]
    fn a_selection_is_taken_against_the_last_pictures_monitors() {
        let stop = AtomicBool::new(false);
        let mut capture = GdiCapture::default();
        assert!(matches!(
            capture.select(Selection::Monitor(1), &stop),
            Err(CaptureError::NoMonitor(1))
        ));
        assert!(matches!(
            capture.select(Selection::All, &stop),
            Err(CaptureError::NoMonitor(0))
        ));
        let found = vec![
            found_of(&info((0, 0, 1920, 1080), true, r"\\.\DISPLAY1")).unwrap(),
            found_of(&info((-1280, 0, 0, 1024), false, r"\\.\DISPLAY2")).unwrap(),
        ];
        let space = Rect::new(-1280, 0, 3200, 1080);
        let resolved = capture.chooser.resolve(found.clone(), space);
        assert_eq!(resolved.shown, Selection::Monitor(2));
        capture.resolved = Some(resolved);
        capture.select(Selection::Monitor(1), &stop).unwrap();
        assert!(matches!(
            capture.select(Selection::Monitor(3), &stop),
            Err(CaptureError::NoMonitor(3))
        ));
        let next = capture.chooser.resolve(found, space);
        assert_eq!(next.shown, Selection::Monitor(1));
        assert_eq!(next.grab, Rect::new(-1280, 0, 1280, 1024));
    }

    /// The device names stay out of `Debug`: a capture's description never
    /// carries one into a log.
    #[test]
    fn the_device_names_stay_out_of_debug() {
        let mut capture = GdiCapture::default();
        let found = vec![
            found_of(&info((0, 0, 1920, 1080), true, r"\\.\DISPLAY1")).unwrap(),
            found_of(&info((1920, 0, 3840, 1080), false, r"\\.\DISPLAY2")).unwrap(),
        ];
        capture.resolved = Some(capture.chooser.resolve(found, Rect::new(0, 0, 3840, 1080)));
        let shown = format!("{capture:?}");
        // `\\.\DI`, as `Debug` of the key's code units would print it.
        assert!(!shown.contains("92, 92, 46, 92, 68, 73"), "{shown}");
        assert!(shown.contains("grab"), "{shown}");
    }

    /// Runs only on Windows, with a desktop (Wine's will do). Cross-build
    /// the binary with
    /// `cargo test --target x86_64-pc-windows-gnullvm -p tornect-capture --no-run`
    /// and run it on a Windows desktop, or under Wine.
    ///
    /// The first picture shows the primary of two or more (else monitor 1),
    /// over its even rectangle on the virtual desktop; each monitor in turn
    /// and all of them are grabbed at their size; `doctor`'s listing is the
    /// layout's. With `--nocapture` it reports the layout it saw.
    #[test]
    #[allow(clippy::print_stderr)] // the live test reports what it saw
    fn grabs_the_monitor_it_shows() {
        let mut capture = GdiCapture::open().unwrap();
        assert_eq!(capture.name(), "gdi");
        assert_eq!(capture.layout(), None);
        let frame = capture.next_frame(Duration::ZERO).unwrap().unwrap();
        let layout = capture.layout().unwrap();
        // Rectangles only: the device names stay out of a layout.
        eprintln!("GDI layout of the first picture: {layout:?}");
        let View::Rect { shown, space } = layout.view else {
            panic!("a GDI picture lies on the virtual desktop: {layout:?}");
        };
        assert_eq!(Some(space), virtual_desktop());
        assert!(space.contains(&shown), "{shown:?} in {space:?}");
        assert_eq!((frame.width, frame.height), (shown.width, shown.height));
        assert_eq!(frame.bgrx.len(), (frame.width * frame.height * 4) as usize);
        assert!(frame.bgrx.chunks_exact(4).all(|p| p[3] == 0xff));
        assert_eq!(layout.monitors, desktop_monitors().unwrap());
        let ids: Vec<u8> = layout.monitors.iter().map(|m| m.id).collect();
        assert_eq!(ids, (1..=layout.monitors.len() as u8).collect::<Vec<_>>());
        assert!(layout.monitors.iter().filter(|m| m.primary).count() <= 1);
        assert_eq!(layout.all, layout.monitors.len() >= 2);
        let default = match &layout.monitors[..] {
            [_, _, ..] => layout
                .monitors
                .iter()
                .find(|m| m.primary)
                .map_or(1, |m| m.id),
            _ => 1,
        };
        assert_eq!(layout.shown, Selection::Monitor(default));

        let even = |r: Rect| Rect::new(r.x, r.y, r.width & !1, r.height & !1);
        let stop = AtomicBool::new(false);
        for monitor in &layout.monitors {
            capture
                .select(Selection::Monitor(monitor.id), &stop)
                .unwrap();
            let frame = capture.next_frame(Duration::ZERO).unwrap().unwrap();
            let now = capture.layout().unwrap();
            assert_eq!(now.shown, Selection::Monitor(monitor.id));
            assert_eq!(
                now.view,
                View::Rect {
                    shown: even(monitor.rect),
                    space,
                }
            );
            assert_eq!(
                (frame.width, frame.height),
                (monitor.rect.width & !1, monitor.rect.height & !1)
            );
        }
        match capture.select(Selection::All, &stop) {
            Ok(()) => {
                assert!(layout.all);
                capture.next_frame(Duration::ZERO).unwrap().unwrap();
                let now = capture.layout().unwrap();
                assert_eq!(now.shown, Selection::All);
                let View::Rect { shown, .. } = now.view else {
                    panic!("{now:?}");
                };
                for monitor in &now.monitors {
                    assert!(shown.width >= monitor.rect.width & !1, "{monitor:?}");
                }
            }
            Err(CaptureError::NoMonitor(0)) => assert!(!layout.all),
            Err(e) => panic!("{e}"),
        }
        assert!(matches!(
            capture.select(Selection::Monitor(17), &stop),
            Err(CaptureError::NoMonitor(17))
        ));
    }

    /// Every grab is a plain copy: `CAPTUREBLT` would make the host's own
    /// pointer flicker for the whole session.
    #[test]
    fn the_grab_copies_without_captureblt() {
        use windows_sys::Win32::Graphics::Gdi::CAPTUREBLT;
        assert_eq!(RASTER_OP, SRCCOPY);
        assert_eq!(RASTER_OP & CAPTUREBLT, 0);
    }
}
