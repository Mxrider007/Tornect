//! X11 capture (`docs/research/slice.md` §5): `GetImage` of the root window,
//! with the XFIXES cursor image drawn in (the grab itself has no cursor).
//!
//! Only on an X11 session. Under Wayland the X server is Xwayland, whose root
//! shows X11 windows only, so [`X11Capture::open`] refuses unless
//! `XDG_SESSION_TYPE=x11`. The Wayland backend is the portal + PipeWire one.

use std::time::{Duration, Instant};

use x11rb::connection::Connection as _;
use x11rb::protocol::xfixes::ConnectionExt as _;
use x11rb::protocol::xproto::{self, ConnectionExt as _, ImageFormat, ImageOrder, VisualClass};
use x11rb::rust_connection::RustConnection;

use crate::cursor::{CursorImage, blend};
use crate::{CaptureError, Frame, VideoSource};

/// Grabs the root window of the display named by `$DISPLAY`.
pub struct X11Capture {
    conn: RustConnection,
    root: xproto::Window,
    /// XFIXES answered, so the cursor can be drawn in.
    cursor: bool,
}

impl std::fmt::Debug for X11Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X11Capture")
            .field("root", &self.root)
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

fn failed(e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Failed(e.to_string())
}

/// A root window no desktop has. 2^27 pixels is 512 MiB of BGRx; eight 4K
/// screens side by side are half that. The cap keeps the byte count clear of
/// `usize` overflow on a 32-bit target, and keeps a server that answers
/// `GetGeometry` with nonsense from being asked for an enormous `GetImage`.
const MAX_PIXELS: usize = 1 << 27;

/// Bytes a `width`×`height` BGRx picture occupies — in `usize`, checked, and
/// refused rather than wrapped. The old check multiplied in `u32`: a server
/// answering `GetGeometry` with 32768×32768 made the product exactly 2^32, so it
/// wrapped to **0** and an empty `GetImage` reply passed for a one-gigapixel
/// picture (SLICE-B3 B3-7).
fn frame_bytes(width: u32, height: u32) -> Result<usize, CaptureError> {
    let pixels = (width as usize)
        .checked_mul(height as usize)
        .filter(|&px| px > 0 && px <= MAX_PIXELS)
        .ok_or_else(|| {
            failed(format!(
                "root window geometry {width}x{height} is out of range"
            ))
        })?;
    // `MAX_PIXELS * 4` fits a 32-bit `usize`, so this cannot overflow.
    Ok(pixels * 4)
}

fn unavailable(e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Unavailable(e.to_string())
}

/// Whether a root-window grab shows the desktop in a session of this type.
fn grab_shows_the_desktop(session_type: Option<&str>) -> bool {
    session_type == Some("x11")
}

/// Whether `display` (the value of `$DISPLAY`) names an X server on this
/// machine, the one whose desktop "this desktop" means: `:N[.S]`, `unix:N`,
/// `unix/:N` or a socket path. A host part is another machine's screen (SSH
/// X forwarding sets `localhost:10.0`) or one reached over TCP, which must
/// never be shared or driven as this desktop (SLICE-C3 C3-3).
#[must_use]
pub fn display_is_local(display: Option<&str>) -> bool {
    let Some(display) = display else {
        return false;
    };
    // A socket path, as launchd sets it (`/private/tmp/…/org.xquartz:0`).
    if display.starts_with('/') {
        return true;
    }
    let Some((host, number)) = display.rsplit_once(':') else {
        return false;
    };
    let host = host.strip_prefix("unix/").unwrap_or(host);
    let display_number = number.split('.').next().unwrap_or_default();
    (host.is_empty() || host == "unix")
        && !display_number.is_empty()
        && display_number.bytes().all(|b| b.is_ascii_digit())
}

impl X11Capture {
    /// Connect to `$DISPLAY` and check that its root window is the one layout
    /// this reads without conversion: TrueColor, 32 bits per pixel, blue in the
    /// low byte, least significant byte first — BGRx in memory.
    pub fn open() -> Result<Self, CaptureError> {
        let session = std::env::var("XDG_SESSION_TYPE").ok();
        if !grab_shows_the_desktop(session.as_deref()) {
            return Err(unavailable(format!(
                "not an X11 session (XDG_SESSION_TYPE={}): an X11 grab would show only X11 windows",
                session.as_deref().unwrap_or("unset")
            )));
        }
        let display = std::env::var("DISPLAY").ok();
        if !display_is_local(display.as_deref()) {
            return Err(unavailable(format!(
                "DISPLAY={} is not this machine's own display (a host part means SSH X \
                 forwarding or TCP): only the desktop Tornect runs on is shared",
                display.as_deref().unwrap_or("unset")
            )));
        }
        Self::connect()
    }

    /// [`Self::open`] without the session check.
    fn connect() -> Result<Self, CaptureError> {
        let (conn, screen_num) = x11rb::connect(None).map_err(unavailable)?;
        let setup = conn.setup();
        let screen = setup
            .roots
            .get(screen_num)
            .ok_or_else(|| unavailable("X server reported no screen"))?;
        let format = setup
            .pixmap_formats
            .iter()
            .find(|f| f.depth == screen.root_depth);
        let visual = screen
            .allowed_depths
            .iter()
            .flat_map(|d| d.visuals.iter())
            .find(|v| v.visual_id == screen.root_visual);
        let bgrx = setup.image_byte_order == ImageOrder::LSB_FIRST
            && format.is_some_and(|f| f.bits_per_pixel == 32 && f.scanline_pad == 32)
            && visual.is_some_and(|v| {
                v.class == VisualClass::TRUE_COLOR
                    && (v.red_mask, v.green_mask, v.blue_mask) == (0xff_0000, 0xff00, 0xff)
            });
        if !bgrx {
            return Err(unavailable(format!(
                "root window is depth {} in a layout other than 32-bit BGRx",
                screen.root_depth
            )));
        }
        let root = screen.root;
        let cursor = conn
            .xfixes_query_version(4, 0)
            .map_err(failed)?
            .reply()
            .is_ok();
        Ok(Self { conn, root, cursor })
    }

    fn grab(&self) -> Result<Frame, CaptureError> {
        // Asked every time: RandR can resize the root between two pictures.
        let geometry = self
            .conn
            .get_geometry(self.root)
            .map_err(failed)?
            .reply()
            .map_err(failed)?;
        let (w, h) = (geometry.width, geometry.height);
        let (width, height) = (u32::from(w), u32::from(h));
        // Checked before the request: `GetImage` of a geometry no desktop has
        // would have the server build a reply that size (SLICE-B3 B3-7).
        let expected = frame_bytes(width, height)?;
        let image = self
            .conn
            .get_image(ImageFormat::Z_PIXMAP, self.root, 0, 0, w, h, !0)
            .map_err(failed)?
            .reply()
            .map_err(failed)?;
        let captured_at = Instant::now();
        let mut bgrx = image.data;
        if bgrx.len() != expected {
            return Err(failed(format!(
                "GetImage returned {} bytes for {width}x{height}",
                bgrx.len()
            )));
        }
        // Servers leave whatever they like in the pad byte.
        for px in bgrx.chunks_exact_mut(4) {
            px[3] = 0xff;
        }
        if self.cursor
            && let Ok(cookie) = self.conn.xfixes_get_cursor_image()
            && let Ok(c) = cookie.reply()
        {
            let image = CursorImage {
                pixels: &c.cursor_image,
                width: u32::from(c.width),
                height: u32::from(c.height),
                x: i32::from(c.x) - i32::from(c.xhot),
                y: i32::from(c.y) - i32::from(c.yhot),
            };
            blend(&mut bgrx, width, height, &image);
        }
        Ok(Frame {
            width,
            height,
            bgrx,
            captured_at,
        })
    }
}

impl VideoSource for X11Capture {
    fn name(&self) -> &'static str {
        "x11"
    }

    /// Polls: every call grabs the screen, whatever changed.
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        self.grab().map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server answers `GetGeometry`, so the geometry is its number, not ours,
    /// and it also chooses how many bytes `GetImage` returns. In `u32`,
    /// 32768×32768×4 is exactly 2^32 and wraps to 0: the old check then accepted
    /// an **empty** reply as a one-gigapixel picture, which the cursor blend
    /// indexes past the end of (SLICE-B3 B3-7). In a debug build the same
    /// multiplication panics instead; only a release build wraps silently.
    #[test]
    fn a_geometry_no_desktop_has_is_refused_rather_than_wrapped() {
        assert_eq!(32_768u32.wrapping_mul(32_768).wrapping_mul(4), 0);
        assert!(frame_bytes(32_768, 32_768).is_err());
        assert!(frame_bytes(65_535, 65_535).is_err());
        assert!(frame_bytes(0, 1080).is_err());
        assert!(frame_bytes(1920, 0).is_err());
        assert_eq!(frame_bytes(1920, 1080).unwrap(), 1920 * 1080 * 4);
        // Eight 4K screens side by side still pass.
        assert_eq!(frame_bytes(30_720, 2160).unwrap(), 30_720 * 2160 * 4);
    }

    /// SLICE-C3 C3-3: a `DISPLAY` with a host part is another machine's screen
    /// (SSH X forwarding sets `localhost:10.0`) or one reached over TCP, and is
    /// never shared or driven as this desktop.
    #[test]
    fn only_this_machines_own_display_is_the_desktop() {
        for local in [
            ":0",
            ":1",
            ":0.0",
            ":12.1",
            "unix:0",
            "unix/:0",
            "/private/tmp/launchd-1/org.x:0",
        ] {
            assert!(display_is_local(Some(local)), "{local}");
        }
        for remote in [
            "localhost:10.0",
            "127.0.0.1:0",
            "desk.example:0",
            "tcp/localhost:0",
            "tcp/:0",
            "[::1]:0",
            "host::0",
            "",
            ":",
            ":x",
            "0",
        ] {
            assert!(!display_is_local(Some(remote)), "{remote}");
        }
        assert!(!display_is_local(None));
    }

    #[test]
    fn only_an_x11_session_is_grabbed() {
        assert!(grab_shows_the_desktop(Some("x11")));
        for other in [Some("wayland"), Some("tty"), Some(""), None] {
            assert!(!grab_shows_the_desktop(other), "{other:?}");
        }
    }

    /// The grab path itself, on whatever X server `$DISPLAY` names (skipped when
    /// none is reachable). Under an X server with a real root (Xorg, Xvfb) it is
    /// a full BGRx picture. Rootless Xwayland's root is not viewable, and
    /// `GetImage` answers `BadMatch` — seen on the dev VM, and one more reason
    /// `open` refuses under Wayland.
    /// With `XDG_SESSION_TYPE=x11` the grab must succeed, so a run under Xvfb
    /// (`xvfb-run -s "-screen 0 1280x720x24" env XDG_SESSION_TYPE=x11 cargo test`)
    /// proves it rather than skipping.
    #[test]
    fn the_grab_path_against_any_reachable_display() {
        let session = std::env::var("XDG_SESSION_TYPE").ok();
        let x11_session = session.as_deref() == Some("x11");
        let mut capture = match X11Capture::connect() {
            Ok(capture) => capture,
            Err(_) if !x11_session => return,
            Err(e) => panic!("an X11 session must be grabbable: {e}"),
        };
        match capture.next_frame(Duration::ZERO) {
            Ok(Some(frame)) => {
                assert!(frame.width > 0 && frame.height > 0);
                assert_eq!(frame.bgrx.len(), (frame.width * frame.height * 4) as usize);
                assert!(frame.bgrx.chunks_exact(4).all(|p| p[3] == 0xff));
            }
            Err(CaptureError::Failed(why))
                if session.as_deref() == Some("wayland") && why.contains("Match") => {}
            other => panic!("{other:?}"),
        }
    }

    /// On a real X11 session the grab is a full-screen BGRx picture. Elsewhere
    /// (this dev VM runs Wayland) opening refuses, and says why.
    #[test]
    fn a_grab_or_an_honest_refusal() {
        match X11Capture::open() {
            Ok(mut capture) => {
                let frame = capture.next_frame(Duration::ZERO).unwrap().unwrap();
                assert_eq!(frame.bgrx.len(), (frame.width * frame.height * 4) as usize);
                assert!(frame.bgrx.chunks_exact(4).all(|p| p[3] == 0xff));
            }
            Err(CaptureError::Unavailable(why)) => assert!(!why.is_empty()),
            Err(e) => panic!("{e}"),
        }
    }
}
