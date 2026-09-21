//! X11 host injection through XTEST (`docs/research` media report §5): only
//! meaningful on an X11 session; under Xwayland XTEST reaches X11 clients only,
//! so `tornect-capture` selects this backend when `XDG_SESSION_TYPE=x11`.

use x11rb::connection::Connection as _;
use x11rb::protocol::xproto;
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use crate::{Button, InputError, InputEvent, InputSink, WheelAccumulator, denormalize, keymap};

/// Injects into the X display named by `$DISPLAY`.
pub struct XTestSink {
    conn: RustConnection,
    root: xproto::Window,
    width: u32,
    height: u32,
    wheel: WheelAccumulator,
}

fn err(e: impl std::fmt::Display) -> InputError {
    InputError::Inject(e.to_string())
}

impl XTestSink {
    /// Connect to `$DISPLAY` and check that XTEST is available.
    pub fn connect() -> Result<Self, InputError> {
        let (conn, screen_num) = x11rb::connect(None).map_err(err)?;
        let screen = conn
            .setup()
            .roots
            .get(screen_num)
            .ok_or_else(|| err("X server reported no screen"))?;
        let (root, width, height) = (
            screen.root,
            u32::from(screen.width_in_pixels),
            u32::from(screen.height_in_pixels),
        );
        conn.xtest_get_version(2, 2)
            .map_err(err)?
            .reply()
            .map_err(|e| err(format!("XTEST unavailable: {e}")))?;
        Ok(Self {
            conn,
            root,
            width,
            height,
            wheel: WheelAccumulator::default(),
        })
    }

    fn fake(&self, kind: u8, detail: u8, x: i16, y: i16) -> Result<(), InputError> {
        self.conn
            .xtest_fake_input(kind, detail, x11rb::CURRENT_TIME, self.root, x, y, 0)
            .map_err(err)?;
        Ok(())
    }

    fn click(&self, detail: u8, times: i32) -> Result<(), InputError> {
        for _ in 0..times.unsigned_abs().min(100) {
            self.fake(xproto::BUTTON_PRESS_EVENT, detail, 0, 0)?;
            self.fake(xproto::BUTTON_RELEASE_EVENT, detail, 0, 0)?;
        }
        Ok(())
    }
}

impl InputSink for XTestSink {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        match *event {
            InputEvent::PointerMove { x, y } => {
                let px = i16::try_from(denormalize(x, self.width)).unwrap_or(i16::MAX);
                let py = i16::try_from(denormalize(y, self.height)).unwrap_or(i16::MAX);
                self.fake(xproto::MOTION_NOTIFY_EVENT, 0, px, py)?;
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
                self.fake(kind, detail, 0, 0)?;
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
                self.fake(kind, keycode, 0, 0)?;
            }
            InputEvent::ReleaseAll => {}
        }
        self.conn.flush().map_err(err)?;
        Ok(())
    }
}
