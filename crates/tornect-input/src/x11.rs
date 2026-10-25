//! X11 host injection through XTEST (`docs/research` media report §5): only
//! meaningful on an X11 session; under Xwayland XTEST reaches X11 clients only,
//! so `tornect-capture` selects this backend when `XDG_SESSION_TYPE=x11`.
//!
//! Positions are placed over the root as it is at each move (slice-G G2-2).
//! Once retargeted ([`InputSink::retarget`]) they arrive normalized over the
//! whole root, since the session's [`Viewport`](crate::Viewport) has placed
//! the viewer's pointer onto the monitor the picture shows (decision M1-75),
//! and a move onto a root of another size than the view's is refused until
//! the next picture brings a new view. Before any retarget the picture shows
//! the whole root but for an odd last column or row (decision M1-74), and
//! positions are placed over that part.

use x11rb::connection::Connection as _;
use x11rb::protocol::xproto::{self, ConnectionExt as _};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use crate::{
    Button, InputError, InputEvent, InputSink, Rect, View, WheelAccumulator, cannot_follow,
    denormalize, keymap, over_even_part,
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
}

impl InputSink for XTestSink {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        self.0.inject(event)
    }

    fn retarget(&mut self, view: &View) -> Result<(), InputError> {
        self.0.retarget(view)
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
    /// The root's size the session's view addresses, once retargeted.
    expected_root: Option<(u32, u32)>,
    wheel: WheelAccumulator,
}

impl<S: Server> Injector<S> {
    fn new(server: S) -> Self {
        Self {
            server,
            expected_root: None,
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
}

impl<S: Server + Send> InputSink for Injector<S> {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        match *event {
            InputEvent::PointerMove { x, y } => {
                let (width, height) = self.server.root_size()?;
                let (x, y) = match self.expected_root {
                    Some(expected) if expected != (width, height) => {
                        return Err(InputError::Inject(
                            "the screen's size changed; moves wait for the next picture".to_owned(),
                        ));
                    }
                    Some(_) => (x, y),
                    None => over_even_part(x, y, Rect::new(0, 0, width, height)),
                };
                let (px, py) = (denormalize(x, width), denormalize(y, height));
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

    /// Keeps the root's size a rectangle view addresses, for the check at
    /// every move; the mapping itself is the `Viewport`'s. The root always
    /// starts at 0, 0, so a space that does not is not this display's.
    fn retarget(&mut self, view: &View) -> Result<(), InputError> {
        match view {
            View::Rect { space, .. } if space.x == 0 && space.y == 0 => {
                self.expected_root = Some((space.width, space.height));
                Ok(())
            }
            View::Rect { .. } => Err(InputError::BadView("the X11 root starts at 0, 0")),
            View::Stream { .. } => Err(cannot_follow()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Viewport;

    /// SLICE-C1 C1-2, now through a `Viewport` (decision M1-75): the viewer's
    /// pointer covers the rectangle the picture shows, here the root's top-left
    /// 1000×600, and not the whole root. Runs only on an X11 session, so never
    /// against a live Xwayland desktop:
    /// `xvfb-run -a -s "-screen 0 1280x720x24" env XDG_SESSION_TYPE=x11 cargo
    /// test --workspace -- x11::tests`.
    #[test]
    fn the_pointer_spans_the_region_the_viewer_sees() {
        if std::env::var("XDG_SESSION_TYPE").as_deref() != Ok("x11") {
            return;
        }
        let mut sink = XTestSink::connect().expect("an X11 session has XTEST");
        let (width, height) = sink.0.server.root_size().unwrap();
        assert!(
            width > 1000 && height > 600,
            "needs a screen above 1000x600"
        );
        let mut sink = Viewport::new(sink);
        sink.retarget(&View::Rect {
            shown: Rect::new(0, 0, 1000, 600),
            space: Rect::new(0, 0, width, height),
        })
        .unwrap();
        for (x, y, want) in [
            (65535, 65535, (999, 599)),
            (0, 0, (0, 0)),
            (32768, 32768, (500, 300)),
        ] {
            sink.inject(&InputEvent::PointerMove { x, y }).unwrap();
            let display = &sink.inner.0.server;
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

    fn resizable(width: u32, height: u32) -> Injector<Resizable> {
        Injector::new(Resizable {
            size: (width, height),
            sent: Vec::new(),
        })
    }

    /// The last XTEST event, which must be a motion.
    fn last_motion(injector: &Injector<Resizable>) -> (i16, i16) {
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
        let mut injector = resizable(1280, 720);
        injector
            .inject(&InputEvent::PointerMove { x: 32768, y: 32768 })
            .unwrap();
        assert_eq!(last_motion(&injector), (640, 360));
        injector.server.size = (1000, 600);
        injector
            .inject(&InputEvent::PointerMove { x: 32768, y: 32768 })
            .unwrap();
        assert_eq!(
            last_motion(&injector),
            (500, 300),
            "after the root shrank to 1000x600"
        );
        injector
            .inject(&InputEvent::PointerMove { x: 65535, y: 65535 })
            .unwrap();
        assert_eq!(last_motion(&injector), (999, 599));
        // Before any retarget the picture shows the root's even part
        // (decision M1-74): an odd root's last column and row are not reached.
        injector.server.size = (1921, 1081);
        injector
            .inject(&InputEvent::PointerMove { x: 65535, y: 65535 })
            .unwrap();
        assert_eq!(last_motion(&injector), (1919, 1079), "an odd root");
    }

    /// Decision M1-75: through a `Viewport` retargeted onto the second of two
    /// monitors (1280×720 and 1024×768 side by side on a 2304×768 root), the
    /// picture's corners are that monitor's corners.
    #[test]
    fn a_move_lands_on_the_monitor_the_picture_shows() {
        let mut sink = Viewport::new(resizable(2304, 768));
        let space = Rect::new(0, 0, 2304, 768);
        sink.retarget(&View::Rect {
            shown: Rect::new(1280, 0, 1024, 768),
            space,
        })
        .unwrap();
        assert_eq!(sink.inner.expected_root, Some((2304, 768)));
        for (x, y, want) in [
            (0, 0, (1280, 0)),
            (65535, 65535, (2303, 767)),
            (32768, 32768, (1280 + 512, 384)),
        ] {
            sink.inject(&InputEvent::PointerMove { x, y }).unwrap();
            assert_eq!(last_motion(&sink.inner), want, "({x}, {y})");
        }
        // Back to the first: its corner, not the second's.
        sink.retarget(&View::Rect {
            shown: Rect::new(0, 0, 1280, 720),
            space,
        })
        .unwrap();
        sink.inject(&InputEvent::PointerMove { x: 65535, y: 65535 })
            .unwrap();
        assert_eq!(last_motion(&sink.inner), (1279, 719));
    }

    /// Decision M1-75 (the design's §4): once retargeted, a root resized
    /// after the view was taken (`xrandr --output X --off`) refuses moves
    /// until the next picture's retarget; keys and buttons still go. A view
    /// of a space not at 0, 0 or of a stream is not this display's.
    #[test]
    fn a_resized_root_refuses_moves_until_the_next_retarget() {
        let mut sink = Viewport::new(resizable(2304, 768));
        let view = |w, h| View::Rect {
            shown: Rect::new(0, 0, 1024, 600),
            space: Rect::new(0, 0, w, h),
        };
        sink.retarget(&view(2304, 768)).unwrap();
        sink.inner.server.size = (1280, 720);
        let refused = sink.inject(&InputEvent::PointerMove { x: 1, y: 1 });
        assert!(
            matches!(&refused, Err(InputError::Inject(why)) if why.contains("size changed")),
            "{refused:?}"
        );
        assert!(sink.inner.server.sent.is_empty(), "nothing faked");
        sink.inject(&InputEvent::PointerButton {
            button: Button::Left,
            pressed: true,
        })
        .unwrap();
        assert_eq!(sink.inner.server.sent.len(), 1);
        sink.retarget(&view(1280, 720)).unwrap();
        sink.inject(&InputEvent::PointerMove { x: 65535, y: 65535 })
            .unwrap();
        assert_eq!(last_motion(&sink.inner), (1023, 599));

        let mut injector = resizable(2304, 768);
        let offset = View::Rect {
            shown: Rect::new(-1920, 0, 1920, 1080),
            space: Rect::new(-1920, 0, 4224, 1080),
        };
        assert!(matches!(
            injector.retarget(&offset),
            Err(InputError::BadView(_))
        ));
        let stream = View::Stream {
            node: 7,
            pixels: (1920, 1080),
            ratio: None,
        };
        assert!(injector.retarget(&stream).is_err());
        assert_eq!(injector.expected_root, None, "neither was kept");
    }
}
