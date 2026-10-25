//! X11 capture (`docs/research/slice.md` §5): `GetImage` of the root window,
//! with the XFIXES cursor image drawn in (the grab itself has no cursor).
//!
//! **Monitors** (decision M1-75, the monitors design §5.4.5). With RandR 1.5 or
//! later, every grab lists the root's active monitors (`GetMonitors`) and
//! grabs only the rectangle of the one shown, or the monitors' bounding box
//! for all of them; a session opens on the primary of two or more. A monitor
//! is held by its RandR name atom, which stays in memory: it is never logged
//! or sent. Without RandR 1.5 the root is the one monitor. Either way the
//! grab is the even part of that rectangle, all a picture shows (decision
//! M1-74), and the picture's [`View`](crate::View) is it on the root, which
//! the XTEST injector addresses.
//!
//! Only on an X11 session. Under Wayland the X server is Xwayland, whose root
//! shows X11 windows only, so [`X11Capture::open`] refuses unless
//! `XDG_SESSION_TYPE=x11`. The Wayland backend is the portal + PipeWire one.

use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use x11rb::connection::Connection as _;
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::xfixes::ConnectionExt as _;
use x11rb::protocol::xproto::{self, ConnectionExt as _, ImageFormat, ImageOrder, VisualClass};
use x11rb::rust_connection::RustConnection;

use crate::cursor::{CursorImage, blend};
use crate::monitors::{Chooser, Found, Resolved, listed};
use crate::{CaptureError, Frame, Layout, Monitor, Rect, Selection, VideoSource};

/// Grabs the root window of the display named by `$DISPLAY`, or the monitor
/// of it the viewer chose.
pub struct X11Capture {
    conn: RustConnection,
    root: xproto::Window,
    /// XFIXES answered, so the cursor can be drawn in.
    cursor: bool,
    /// RandR 1.5 or later answered, so `GetMonitors` lists the monitors.
    randr: bool,
    /// The viewer's choice, held by RandR name atom.
    chooser: Chooser<xproto::Atom>,
    /// The monitors of the latest grab and what it showed: what a selection
    /// is taken against.
    resolved: Option<Resolved<xproto::Atom>>,
    /// What the picture returned last shows.
    layout: Option<Layout>,
}

impl std::fmt::Debug for X11Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Resolved`'s own `Debug` leaves the name atoms out.
        f.debug_struct("X11Capture")
            .field("root", &self.root)
            .field("cursor", &self.cursor)
            .field("randr", &self.randr)
            .field("resolved", &self.resolved)
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
        .ok_or_else(|| failed(format!("a grab of {width}x{height} is out of range")))?;
    // `MAX_PIXELS * 4` fits a 32-bit `usize`, so this cannot overflow.
    Ok(pixels * 4)
}

fn unavailable(e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Unavailable(e.to_string())
}

/// `Ok` when `$DISPLAY` is this machine's own X11 desktop: an X11 session
/// (under Wayland the root shows X11 windows only), on a local display.
fn this_desktop() -> Result<(), CaptureError> {
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
    Ok(())
}

/// The monitors of this X11 desktop, numbered as a session's layout lists
/// them (`tornect doctor`): RandR's active monitors, or the root as the one
/// monitor without RandR 1.5. Refused as [`X11Capture::open`] refuses, on a
/// session that is not X11 and on a display that is not this machine's.
pub fn desktop_monitors() -> Result<Vec<Monitor>, CaptureError> {
    this_desktop()?;
    let (conn, screen_num) = x11rb::connect(None).map_err(unavailable)?;
    let root = conn
        .setup()
        .roots
        .get(screen_num)
        .ok_or_else(|| unavailable("X server reported no screen"))?
        .root;
    let randr = lists_monitors(&conn);
    let space = root_space(&conn, root)?;
    Ok(listed(found(&conn, root, randr)?, space))
}

/// Whether the server's RandR is 1.5 or later, the version that lists
/// monitors (`GetMonitors`); `false` without RandR.
fn lists_monitors(conn: &RustConnection) -> bool {
    conn.randr_query_version(1, 5)
        .ok()
        .and_then(|cookie| cookie.reply().ok())
        .is_some_and(|v| (v.major_version, v.minor_version) >= (1, 5))
}

/// The root's rectangle: what a grab is cut from and the injector addresses.
fn root_space(conn: &RustConnection, root: xproto::Window) -> Result<Rect, CaptureError> {
    let geometry = conn
        .get_geometry(root)
        .map_err(failed)?
        .reply()
        .map_err(failed)?;
    Ok(Rect::new(
        0,
        0,
        u32::from(geometry.width),
        u32::from(geometry.height),
    ))
}

/// The root's active monitors as RandR lists them, keyed by name atom; none
/// without RandR 1.5 (the root is then the one monitor).
fn found(
    conn: &RustConnection,
    root: xproto::Window,
    randr: bool,
) -> Result<Vec<Found<xproto::Atom>>, CaptureError> {
    if !randr {
        return Ok(Vec::new());
    }
    let reply = conn
        .randr_get_monitors(root, true)
        .map_err(failed)?
        .reply()
        .map_err(failed)?;
    Ok(reply
        .monitors
        .into_iter()
        .map(|m| Found {
            key: m.name,
            rect: Rect::new(
                i32::from(m.x),
                i32::from(m.y),
                u32::from(m.width),
                u32::from(m.height),
            ),
            primary: m.primary,
        })
        .collect())
}

/// `grab` as `GetImage` takes it: a corner in `i16` and a size in `u16`. A
/// rectangle beyond them (a root wider than 32 767 px) is refused rather
/// than wrapped.
fn image_rect(grab: Rect) -> Result<(i16, i16, u16, u16), CaptureError> {
    let out_of_range = || {
        failed(format!(
            "monitor rectangle {}x{}+{}+{} is out of the X11 range",
            grab.width, grab.height, grab.x, grab.y
        ))
    };
    Ok((
        i16::try_from(grab.x).map_err(|_| out_of_range())?,
        i16::try_from(grab.y).map_err(|_| out_of_range())?,
        u16::try_from(grab.width).map_err(|_| out_of_range())?,
        u16::try_from(grab.height).map_err(|_| out_of_range())?,
    ))
}

/// Where the cursor image's top-left corner lies on a picture of `grab`: the
/// pointer at root `(x, y)`, less its hotspot, less the grab's corner.
fn cursor_origin(x: i16, y: i16, xhot: u16, yhot: u16, grab: Rect) -> (i32, i32) {
    (
        i32::from(x) - i32::from(xhot) - grab.x,
        i32::from(y) - i32::from(yhot) - grab.y,
    )
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
        this_desktop()?;
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
        let randr = lists_monitors(&conn);
        Ok(Self {
            conn,
            root,
            cursor,
            randr,
            chooser: Chooser::default(),
            resolved: None,
            layout: None,
        })
    }

    fn grab(&mut self) -> Result<Frame, CaptureError> {
        // Asked every time: RandR can resize the root, or change its monitors,
        // between two pictures.
        let space = root_space(&self.conn, self.root)?;
        let resolved = self
            .chooser
            .resolve(found(&self.conn, self.root, self.randr)?, space);
        let grab = resolved.grab;
        let (width, height) = (grab.width, grab.height);
        // Checked before the request: `GetImage` of a geometry no desktop has
        // would have the server build a reply that size (SLICE-B3 B3-7).
        let expected = frame_bytes(width, height)?;
        let (x, y, w, h) = image_rect(grab)?;
        let started = Instant::now();
        let image = self
            .conn
            .get_image(ImageFormat::Z_PIXMAP, self.root, x, y, w, h, !0)
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
            let (x, y) = cursor_origin(c.x, c.y, c.xhot, c.yhot, grab);
            let image = CursorImage {
                pixels: &c.cursor_image,
                width: u32::from(c.width),
                height: u32::from(c.height),
                x,
                y,
            };
            blend(&mut bgrx, width, height, &image);
        }
        self.layout = Some(resolved.layout());
        self.resolved = Some(resolved);
        Ok(Frame {
            width,
            height,
            bgrx,
            captured_at,
            grab: started.elapsed(),
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

    fn layout(&self) -> Option<Layout> {
        self.layout.clone()
    }

    /// Instant: the next grab shows `selection`, taken against the monitors
    /// of the latest grab (none before the first).
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
    use tornect_input::x11::XTestSink;
    use tornect_input::{InputEvent, InputSink as _, Viewport};
    use x11rb::protocol::randr::MonitorInfo;

    use super::*;
    use crate::View;

    /// A grab rectangle goes to `GetImage` as it is, and one beyond its
    /// `i16` corner or `u16` size is refused rather than wrapped onto
    /// another part of the root.
    #[test]
    fn a_grab_outside_the_x11_range_is_refused() {
        assert_eq!(
            image_rect(Rect::new(1280, 0, 1024, 768)).unwrap(),
            (1280, 0, 1024, 768)
        );
        assert_eq!(
            image_rect(Rect::new(32_767, 32_767, 65_535, 65_535)).unwrap(),
            (32_767, 32_767, 65_535, 65_535)
        );
        for beyond in [
            Rect::new(32_768, 0, 2, 2),
            Rect::new(0, 32_768, 2, 2),
            Rect::new(0, 0, 65_536, 2),
            Rect::new(0, 0, 2, 65_536),
        ] {
            assert!(image_rect(beyond).is_err(), "{beyond:?}");
        }
    }

    /// The cursor is drawn where the pointer is on the picture: its root
    /// position, less the hotspot, less the corner of the rectangle grabbed.
    #[test]
    fn the_cursor_is_placed_on_the_monitor_grabbed() {
        let second = Rect::new(1280, 0, 1024, 768);
        assert_eq!(cursor_origin(1380, 50, 1, 2, second), (99, 48));
        assert_eq!(
            cursor_origin(1380, 50, 1, 2, Rect::new(0, 0, 2304, 768)),
            (1379, 48)
        );
        // On the monitor left of it: off the picture, so nothing is drawn.
        assert_eq!(cursor_origin(100, 50, 0, 0, second), (-1180, 50));
        // A monitor at negative coordinates.
        assert_eq!(
            cursor_origin(-100, -10, 4, 4, Rect::new(-1920, -1080, 1920, 1080)),
            (1816, 1066)
        );
    }

    /// RandR monitors a test set on the X server, deleted when the test ends,
    /// on a failure too: they belong to the server, not to the connection
    /// that set them (`docs/research/monitors.md` §3).
    struct SetMonitors<'a> {
        conn: &'a RustConnection,
        root: xproto::Window,
        names: Vec<xproto::Atom>,
    }

    impl SetMonitors<'_> {
        fn delete(&self) {
            for &name in &self.names {
                // `BadValue` once it is gone.
                if let Ok(cookie) = self.conn.randr_delete_monitor(self.root, name) {
                    let _ = cookie.check();
                }
            }
        }
    }

    impl Drop for SetMonitors<'_> {
        fn drop(&mut self) {
            self.delete();
        }
    }

    /// `rect` of `frame`, row by row.
    fn cut(frame: &Frame, rect: Rect) -> Vec<u8> {
        let stride = frame.width as usize * 4;
        let (x, w) = (rect.x as usize * 4, rect.width as usize * 4);
        (rect.y as usize..(rect.y as usize + rect.height as usize))
            .flat_map(|row| {
                frame.bgrx[row * stride + x..row * stride + x + w]
                    .iter()
                    .copied()
            })
            .collect()
    }

    /// The monitors design's X11 test (§7; `docs/research/monitors.md` §3):
    /// on its own connection the test sets two RandR 1.5 monitors, 1280×720
    /// at the corner (holding the root's output, so the automatic monitor
    /// goes) and 1024×768 right of it, made primary. The grab lists both,
    /// opens on the primary and switches as asked: each monitor's picture
    /// is exactly its rectangle of the picture of all of them, the cursor
    /// included, which lies on the second monitor; moved off it, the
    /// second's picture changes. `desktop_monitors` lists the same two, and
    /// XTEST behind a viewport retargeted to the second monitor's view puts
    /// the pointer on that monitor's corners. With both monitors deleted
    /// the root is the one monitor again.
    ///
    /// It sets monitors only on Xvfb (the root's one output is named
    /// "screen"), never on a real desktop, whose windows they would
    /// rearrange while it runs; skipped without a reachable X server. Under
    /// `XDG_SESSION_TYPE=x11` it must run: `xvfb-run -a -s "-screen 0
    /// 2304x768x24" env XDG_SESSION_TYPE=x11 cargo test -p tornect-capture
    /// -- x11::`.
    #[test]
    fn randr_monitors_are_listed_and_grabbed_one_at_a_time() {
        let x11_session = std::env::var("XDG_SESSION_TYPE").ok().as_deref() == Some("x11");
        let mut capture = match X11Capture::connect() {
            Ok(capture) => capture,
            Err(_) if !x11_session => return,
            Err(e) => panic!("an X11 session must be grabbable: {e}"),
        };
        let (conn, screen_num) = x11rb::connect(None).unwrap();
        let root = conn.setup().roots[screen_num].root;
        let resources = conn
            .randr_get_screen_resources_current(root)
            .unwrap()
            .reply()
            .unwrap();
        let [output] = resources.outputs[..] else {
            return;
        };
        let info = conn
            .randr_get_output_info(output, resources.config_timestamp)
            .unwrap()
            .reply()
            .unwrap();
        if info.name != b"screen" {
            // Not Xvfb: a real desktop's monitors are left alone.
            return;
        }
        let space = root_space(&conn, root).unwrap();
        assert!(
            capture.randr && space.width >= 2304 && space.height >= 768,
            "needs RandR 1.5 and a root of at least 2304x768, not {space:?}: \
             xvfb-run -a -s \"-screen 0 2304x768x24\""
        );
        let stop = AtomicBool::new(false);
        assert!(matches!(
            capture.select(Selection::Monitor(1), &stop),
            Err(CaptureError::NoMonitor(1))
        ));

        let names: Vec<xproto::Atom> = ["TORNECT-TEST-A", "TORNECT-TEST-B"]
            .iter()
            .map(|name| {
                conn.intern_atom(false, name.as_bytes())
                    .unwrap()
                    .reply()
                    .unwrap()
                    .atom
            })
            .collect();
        let set = SetMonitors {
            conn: &conn,
            root,
            names: names.clone(),
        };
        // Left by a run that ended before its cleanup: a name in use is
        // refused.
        set.delete();
        let monitor = |name, primary, x, width, height, outputs| MonitorInfo {
            name,
            primary,
            automatic: false,
            x,
            y: 0,
            width,
            height,
            width_in_millimeters: 0,
            height_in_millimeters: 0,
            outputs,
        };
        for info in [
            monitor(names[0], false, 0, 1280, 720, vec![output]),
            monitor(names[1], true, 1280, 1024, 768, Vec::new()),
        ] {
            conn.randr_set_monitor(root, info).unwrap().check().unwrap();
        }
        let warp = |x, y| {
            conn.warp_pointer(x11rb::NONE, root, 0, 0, 0, 0, x, y)
                .unwrap()
                .check()
                .unwrap();
        };
        warp(1280 + 200, 300);

        let first = Rect::new(0, 0, 1280, 720);
        let second = Rect::new(1280, 0, 1024, 768);
        let listed = [
            Monitor {
                id: 1,
                primary: false,
                rect: first,
            },
            Monitor {
                id: 2,
                primary: true,
                rect: second,
            },
        ];
        let grab = |capture: &mut X11Capture| {
            let frame = capture.next_frame(Duration::ZERO).unwrap().unwrap();
            assert_eq!(frame.bgrx.len(), (frame.width * frame.height * 4) as usize);
            frame
        };
        let primary = grab(&mut capture);
        assert_eq!((primary.width, primary.height), (1024, 768));
        assert_eq!(
            capture.layout(),
            Some(Layout {
                monitors: listed.to_vec(),
                all: true,
                shown: Selection::Monitor(2),
                view: View::Rect {
                    shown: second,
                    space,
                },
            })
        );

        capture.select(Selection::All, &stop).unwrap();
        let all = grab(&mut capture);
        assert_eq!((all.width, all.height), (2304, 768));
        let layout = capture.layout().unwrap();
        assert_eq!(layout.shown, Selection::All);
        assert_eq!(
            layout.view,
            View::Rect {
                shown: Rect::new(0, 0, 2304, 768),
                space,
            }
        );
        assert!(
            cut(&all, second) == primary.bgrx,
            "the second monitor's picture is its part of all"
        );

        capture.select(Selection::Monitor(1), &stop).unwrap();
        let one = grab(&mut capture);
        assert_eq!((one.width, one.height), (1280, 720));
        assert!(
            cut(&all, first) == one.bgrx,
            "the first monitor's picture is its part of all"
        );
        assert_eq!(capture.layout().unwrap().shown, Selection::Monitor(1));

        capture.select(Selection::Monitor(2), &stop).unwrap();
        let two = grab(&mut capture);
        assert_eq!((two.width, two.height), (1024, 768));
        assert!(
            two.bgrx == primary.bgrx,
            "the second monitor again, as before"
        );
        assert!(matches!(
            capture.select(Selection::Monitor(3), &stop),
            Err(CaptureError::NoMonitor(3))
        ));

        // The cursor was on the second monitor's picture, where the pointer is.
        warp(100, 100);
        let away = grab(&mut capture);
        assert!(
            away.bgrx != primary.bgrx,
            "no cursor drawn on the second monitor"
        );

        if x11_session && display_is_local(std::env::var("DISPLAY").ok().as_deref()) {
            assert_eq!(desktop_monitors().unwrap(), listed);
        }

        // The view the grab reports is where XTEST puts the pointer, through
        // the host's viewport: the picture's corners land on the second
        // monitor's first and last pixels.
        let mut injector = Viewport::new(XTestSink::connect().unwrap());
        injector.retarget(&capture.layout().unwrap().view).unwrap();
        for ((x, y), want) in [((0, 0), (1280, 0)), ((u16::MAX, u16::MAX), (2303, 767))] {
            injector.inject(&InputEvent::PointerMove { x, y }).unwrap();
            // The move is on the injector's own connection: read until it
            // has been handled.
            let since = Instant::now();
            loop {
                let at = conn.query_pointer(root).unwrap().reply().unwrap();
                if (at.root_x, at.root_y) == want {
                    break;
                }
                assert!(
                    since.elapsed() < Duration::from_secs(2),
                    "({x}, {y}) landed on ({}, {}), not {want:?}",
                    at.root_x,
                    at.root_y
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        // Both gone, the root is the one monitor again, and the view falls
        // back to it.
        drop(set);
        let root = grab(&mut capture);
        assert_eq!(
            (root.width, root.height),
            (space.width & !1, space.height & !1)
        );
        let layout = capture.layout().unwrap();
        assert_eq!((layout.monitors.len(), layout.all), (1, false));
        assert_eq!(layout.shown, Selection::Monitor(1));
    }

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
    /// (`xvfb-run -a -s "-screen 0 2304x768x24" env XDG_SESSION_TYPE=x11 cargo
    /// test`, the size the RandR test below needs) proves it rather than
    /// skipping.
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
