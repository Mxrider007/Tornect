//! X11 host injection through XTEST (`docs/research` media report §5): only
//! meaningful on an X11 session; under Xwayland XTEST reaches X11 clients only,
//! so `tornect-capture` selects this backend when `XDG_SESSION_TYPE=x11`.

use x11rb::connection::Connection as _;
use x11rb::protocol::xproto::{self, ConnectionExt as _};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use crate::{
    Button, InputError, InputEvent, InputSink, Region, WheelAccumulator, keymap, place, whole,
};

/// Injects into the X display named by `$DISPLAY`.
pub struct XTestSink(Injector<Display>);

fn err(e: impl std::fmt::Display) -> InputError {
    InputError::Inject(e.to_string())
}

impl XTestSink {
    /// Connect to `$DISPLAY` and check that XTEST is available.
    pub fn connect() -> Result<Self, InputError> {
        let (conn, screen_num) = x11rb::connect(None).map_err(err)?;
        let root = conn
            .setup()
            .roots
            .get(screen_num)
            .ok_or_else(|| err("X server reported no screen"))?
            .root;
        conn.xtest_get_version(2, 2)
            .map_err(err)?
            .reply()
            .map_err(|e| err(format!("XTEST unavailable: {e}")))?;
        Ok(Self(Injector::new(Display { conn, root })))
    }

    /// Map the viewer's pointer over `region` of the root, the part of the
    /// screen the viewer sees (SLICE-C1 C1-2). The default is the whole root.
    #[must_use]
    pub fn over(mut self, region: Region) -> Self {
        self.0.region = region;
        self
    }
}

impl InputSink for XTestSink {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        self.0.inject(event)
    }
}

/// What the injector asks of the X server: a seam, so that the pointer
/// mapping is tested without a server whose root can be resized.
trait Server {
    /// The root window's size now. It is asked at every move, as capture asks
    /// at every picture: RandR can resize the root during a session, and a
    /// size kept from connect skewed every later click (slice-G G2-2).
    fn root_size(&mut self) -> Result<(u32, u32), InputError>;
    /// One XTEST event on the root.
    fn fake(&mut self, kind: u8, detail: u8, x: i16, y: i16) -> Result<(), InputError>;
    /// Send what is queued.
    fn flush(&mut self) -> Result<(), InputError>;
}

/// The display named by `$DISPLAY`.
struct Display {
    conn: RustConnection,
    root: xproto::Window,
}

impl Server for Display {
    fn root_size(&mut self) -> Result<(u32, u32), InputError> {
        let geometry = self
            .conn
            .get_geometry(self.root)
            .map_err(err)?
            .reply()
            .map_err(err)?;
        Ok((u32::from(geometry.width), u32::from(geometry.height)))
    }

    fn fake(&mut self, kind: u8, detail: u8, x: i16, y: i16) -> Result<(), InputError> {
        self.conn
            .xtest_fake_input(kind, detail, x11rb::CURRENT_TIME, self.root, x, y, 0)
            .map_err(err)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), InputError> {
        self.conn.flush().map_err(err)
    }
}

/// The injection itself, over any [`Server`].
struct Injector<S> {
    server: S,
    region: Region,
    wheel: WheelAccumulator,
}

impl<S: Server> Injector<S> {
    fn new(server: S) -> Self {
        Self {
            server,
            region: whole,
            wheel: WheelAccumulator::default(),
        }
    }

    fn click(&mut self, detail: u8, times: i32) -> Result<(), InputError> {
        for _ in 0..times.unsigned_abs().min(100) {
            self.server.fake(xproto::BUTTON_PRESS_EVENT, detail, 0, 0)?;
            self.server
                .fake(xproto::BUTTON_RELEASE_EVENT, detail, 0, 0)?;
        }
        Ok(())
    }

    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        match *event {
            InputEvent::PointerMove { x, y } => {
                let size = self.server.root_size()?;
                let (px, py) = place(x, y, size, self.region);
                let px = i16::try_from(px).unwrap_or(i16::MAX);
                let py = i16::try_from(py).unwrap_or(i16::MAX);
                self.server.fake(xproto::MOTION_NOTIFY_EVENT, 0, px, py)?;
            }
            InputEvent::PointerButton { button, pressed } => {
                let detail = match button {
                    Button::Left => 1,
                    Button::Middle => 2,
                    Button::Right => 3,
                    Button::Back => 8,
                    Button::Forward => 9,
                };
                let kind = if pressed {
                    xproto::BUTTON_PRESS_EVENT
                } else {
                    xproto::BUTTON_RELEASE_EVENT
                };
                self.server.fake(kind, detail, 0, 0)?;
            }
            InputEvent::Wheel { dx, dy } => {
                let (nx, ny) = self.wheel.add(dx, dy);
                // X11 wheel buttons: 4 up, 5 down, 6 left, 7 right.
                self.click(if ny > 0 { 4 } else { 5 }, ny)?;
                self.click(if nx > 0 { 7 } else { 6 }, nx)?;
            }
            InputEvent::Key { usb, pressed } => {
                let key = keymap::by_usb(usb).ok_or(InputError::UnknownKey(usb))?;
                if key.evdev == 0 {
                    return Err(InputError::UnknownKey(usb));
                }
                // X keycode = evdev + 8 under the evdev keymap.
                let keycode =
                    u8::try_from(key.evdev + 8).map_err(|_| InputError::UnknownKey(usb))?;
                let kind = if pressed {
                    xproto::KEY_PRESS_EVENT
                } else {
                    xproto::KEY_RELEASE_EVENT
                };
                self.server.fake(kind, keycode, 0, 0)?;
            }
            InputEvent::ReleaseAll => {}
        }
        self.server.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SLICE-C1 C1-2: the viewer's pointer covers the part of the screen it
    /// sees, the top-left crop the encoder sends, and not the whole root. Runs
    /// only on an X11 session, so never against a live Xwayland desktop:
    /// `xvfb-run -a -s "-screen 0 1280x720x24" env XDG_SESSION_TYPE=x11 cargo
    /// test --workspace -- x11::tests`.
    #[test]
    fn the_pointer_spans_the_region_the_viewer_sees() {
        if std::env::var("XDG_SESSION_TYPE").as_deref() != Ok("x11") {
            return;
        }
        let crop = |w: u32, h: u32| (w.min(1000), h.min(600));
        let mut sink = XTestSink::connect()
            .expect("an X11 session has XTEST")
            .over(crop);
        let display = &mut sink.0.server;
        let (width, height) = display.root_size().unwrap();
        assert!(
            width > 1000 && height > 600,
            "needs a screen above 1000x600"
        );
        for (x, y, want) in [
            (65535, 65535, (999, 599)),
            (0, 0, (0, 0)),
            (32768, 32768, (500, 300)),
        ] {
            sink.inject(&InputEvent::PointerMove { x, y }).unwrap();
            let display = &sink.0.server;
            let at = display
                .conn
                .query_pointer(display.root)
                .unwrap()
                .reply()
                .unwrap();
            let got = (u32::from(at.root_x as u16), u32::from(at.root_y as u16));
            assert_eq!(got, want, "({x}, {y}) on a {width}x{height} root");
        }
    }

    /// An X server whose root the test resizes; it records the XTEST events.
    struct Resizable {
        size: (u32, u32),
        sent: Vec<(u8, u8, i16, i16)>,
    }

    impl Server for Resizable {
        fn root_size(&mut self) -> Result<(u32, u32), InputError> {
            Ok(self.size)
        }

        fn fake(&mut self, kind: u8, detail: u8, x: i16, y: i16) -> Result<(), InputError> {
            self.sent.push((kind, detail, x, y));
            Ok(())
        }

        fn flush(&mut self) -> Result<(), InputError> {
            Ok(())
        }
    }

    /// Where a move to `(x, y)` lands.
    fn move_to(injector: &mut Injector<Resizable>, x: u16, y: u16) -> (i16, i16) {
        injector.inject(&InputEvent::PointerMove { x, y }).unwrap();
        let (kind, _, px, py) = *injector.server.sent.last().unwrap();
        assert_eq!(kind, xproto::MOTION_NOTIFY_EVENT);
        (px, py)
    }

    /// Slice-G G2-2: a pointer move lands on the root as it is at that move.
    /// RandR can resize the root during a session (a monitor plugged in, a
    /// resolution changed); the injector mapped every move over the size it
    /// read at connect, so every later click was skewed or clamped. This
    /// machine's Xvfb cannot resize its root, so a fake server stands in; the
    /// live resize is NEEDS-DEVICE(x11).
    #[test]
    fn the_pointer_follows_a_resized_root() {
        let mut injector = Injector::new(Resizable {
            size: (1280, 720),
            sent: Vec::new(),
        });
        assert_eq!(move_to(&mut injector, 32768, 32768), (640, 360));
        injector.server.size = (1000, 600);
        assert_eq!(
            move_to(&mut injector, 32768, 32768),
            (500, 300),
            "after the root shrank to 1000x600"
        );
        // Over a crop too: a root shrunk below the region the encoder sends.
        injector.region = |w, h| (w.min(1000), h.min(600));
        injector.server.size = (800, 500);
        assert_eq!(
            move_to(&mut injector, 65535, 65535),
            (799, 499),
            "after the root shrank to 800x500"
        );
    }
}
