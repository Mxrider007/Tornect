//! Windows capture through GDI (`docs/research/slice.md` §6): `BitBlt` of the
//! whole virtual desktop into a top-down 32-bit DIB section, with the cursor
//! drawn by `DrawIconEx`. DXGI Desktop Duplication is the step after the slice.
//!
//! The picture spans the virtual desktop from `SM_XVIRTUALSCREEN` /
//! `SM_YVIRTUALSCREEN`, the space `tornect-input`'s `SendInput` addresses with
//! `MOUSEEVENTF_VIRTUALDESK`, so normalized positions pass through unchanged.
//!
//! Every GDI object is created and released inside one `next_frame` call: GDI
//! handles are raw pointers (not `Send`), and a capture that owns none across
//! calls can move between threads freely.
//!
//! Limits (Windows by design): the secure desktop (UAC prompt, lock screen)
//! cannot be captured from a user-session process.
#![allow(unsafe_code)]

use std::ptr::null_mut;
use std::sync::Once;
use std::time::{Duration, Instant};

use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleDC, CreateDIBSection,
    DIB_RGB_COLORS, DeleteDC, DeleteObject, GdiFlush, GetDC, HBITMAP, HDC, HGDIOBJ, ROP_CODE,
    ReleaseDC, SRCCOPY, SelectObject,
};
use windows_sys::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CURSOR_SHOWING, CURSORINFO, DI_NORMAL, DrawIconEx, GetCursorInfo, GetIconInfo,
    GetSystemMetrics, ICONINFO, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
    SM_YVIRTUALSCREEN,
};

use crate::{CaptureError, Frame, VideoSource};

/// Grabs the virtual desktop of this user session.
#[derive(Debug, Default)]
pub struct GdiCapture {
    _private: (),
}

static DPI_AWARE: Once = Once::new();

/// The raster operation of every grab: a plain copy, without `CAPTUREBLT`.
/// With that flag Windows hides the pointer and shows it again around each
/// blit, so the host's own pointer flickers at the capture rate for as long
/// as a session lasts (Mozilla bug 1053264, which dropped it wherever DWM
/// composes). The flag only added layered windows, and DWM, always on since
/// Windows 8 and so on every supported target (Windows 10 20H1+), composes
/// them into the screen DC already. The cursor is drawn by `DrawIconEx`
/// either way: a blit never copies it.
const RASTER_OP: ROP_CODE = SRCCOPY;

/// Measure in physical pixels. Without per-monitor awareness Windows reports a
/// scaled desktop and `BitBlt` copies a scaled, partial picture on a high-DPI
/// monitor. winit sets this for GUI processes; the CLI host has no window.
fn become_dpi_aware() {
    DPI_AWARE.call_once(|| {
        // SAFETY: plain call with a documented constant. It fails (FALSE) when
        // the awareness was already set, by a manifest or by winit, which is fine.
        unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    });
}

/// The virtual desktop's origin and size, in physical pixels.
fn virtual_desktop() -> (i32, i32, i32, i32) {
    // SAFETY: `GetSystemMetrics` has no preconditions and only reads.
    unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    }
}

impl GdiCapture {
    /// A capture of the interactive desktop.
    pub fn open() -> Result<Self, CaptureError> {
        become_dpi_aware();
        let (_, _, w, h) = virtual_desktop();
        if w <= 0 || h <= 0 {
            return Err(CaptureError::Unavailable(
                "no desktop to capture (a service session has none)".to_owned(),
            ));
        }
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

fn grab() -> Result<Frame, CaptureError> {
    let (x, y, w, h) = virtual_desktop();
    if w <= 0 || h <= 0 {
        return Err(CaptureError::Failed("the desktop has no size".to_owned()));
    }
    let (width, height) = (w as u32, h as u32);
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

    /// Polls: every call copies the whole virtual desktop.
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        grab().map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs only on Windows. Cross-build the binary with
    /// `cargo test --target x86_64-pc-windows-gnullvm -p tornect-capture --no-run`
    /// and run it on a Windows desktop.
    #[test]
    fn grabs_the_virtual_desktop() {
        let mut capture = GdiCapture::open().unwrap();
        let (_, _, w, h) = virtual_desktop();
        let frame = capture.next_frame(Duration::ZERO).unwrap().unwrap();
        assert_eq!((frame.width, frame.height), (w as u32, h as u32));
        assert_eq!(frame.bgrx.len(), (frame.width * frame.height * 4) as usize);
        assert!(frame.bgrx.chunks_exact(4).all(|p| p[3] == 0xff));
        assert_eq!(capture.name(), "gdi");
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
