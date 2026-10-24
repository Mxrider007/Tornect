//! Windows host injection through `SendInput` (media report §6.4).
//!
//! Positions arrive normalized over the shared picture. The GDI capture takes
//! it from the whole virtual desktop, the space
//! `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` addresses, and the host
//! scales that desktop whole into the picture, without an odd last column or
//! row (`tornect_codec::scale::shown_region`, decision M1-74), so a position is
//! mapped over that region first ([`SendInputSink::over`], SLICE-C1 C1-2). Keys are injected by scancode (`KEYEVENTF_SCANCODE`),
//! independent of the host's keyboard layout, except Pause and NumLock, whose
//! scancodes are irregular and go by virtual-key code.
//!
//! Limits (Windows by design, stated in the UI): input into an **elevated**
//! window is silently dropped (UIPI), and the secure desktop (UAC prompt, lock
//! screen) cannot be reached from a user-session process.
#![allow(unsafe_code)]

use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL,
    MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP,
    MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK,
    MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, SendInput,
};

use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN,
};

use crate::{Button, InputError, InputEvent, InputSink, Region, keymap, normalize, place, whole};

/// `VK_PAUSE` / `VK_NUMLOCK` (irregular scancodes, injected by VK).
const VK_PAUSE: u16 = 0x13;
const VK_NUMLOCK: u16 = 0x90;
/// `XBUTTON1` / `XBUTTON2` for `mouseData`.
const XBUTTON1: i32 = 1;
const XBUTTON2: i32 = 2;

/// Injects into the interactive desktop of this user session.
#[derive(Debug)]
pub struct SendInputSink {
    region: Region,
}

impl Default for SendInputSink {
    fn default() -> Self {
        Self::new()
    }
}

impl SendInputSink {
    /// A new injector, mapping the pointer over the whole virtual desktop.
    #[must_use]
    pub fn new() -> Self {
        Self { region: whole }
    }

    /// Map the viewer's pointer over `region` of the virtual desktop, the part
    /// the viewer sees (SLICE-C1 C1-2).
    #[must_use]
    pub fn over(mut self, region: Region) -> Self {
        self.region = region;
        self
    }

    /// `(x, y)`, normalized over the region the viewer sees, as the absolute
    /// coordinates `MOUSEEVENTF_VIRTUALDESK` takes, normalized over the whole
    /// virtual desktop. Its size is read at every move, so a display change
    /// keeps the mapping true.
    fn absolute(&self, x: u16, y: u16) -> (i32, i32) {
        // SAFETY: `GetSystemMetrics` has no preconditions and only reads.
        let (w, h) = unsafe {
            (
                GetSystemMetrics(SM_CXVIRTUALSCREEN),
                GetSystemMetrics(SM_CYVIRTUALSCREEN),
            )
        };
        let (Ok(w), Ok(h)) = (u32::try_from(w), u32::try_from(h)) else {
            return (i32::from(x), i32::from(y));
        };
        let (px, py) = place(x, y, (w, h), self.region);
        (
            i32::from(normalize(f64::from(px), f64::from(w))),
            i32::from(normalize(f64::from(py), f64::from(h))),
        )
    }
}

fn mouse(dx: i32, dy: i32, data: i32, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data as _,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn key(vk: u16, scan: u16, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn send(inputs: &[INPUT]) -> Result<(), InputError> {
    let n =
        u32::try_from(inputs.len()).map_err(|_| InputError::Inject("too many inputs".into()))?;
    // SAFETY: `inputs` is a valid slice of initialised `INPUT` structs for the
    // duration of the call and `cbsize` is exactly `size_of::<INPUT>()`, as
    // SendInput requires.
    let sent = unsafe { SendInput(n, inputs.as_ptr(), size_of::<INPUT>() as i32) };
    if sent == n {
        Ok(())
    } else {
        Err(InputError::Inject(format!(
            "SendInput injected {sent} of {n} events (input blocked by another desktop?)"
        )))
    }
}

impl InputSink for SendInputSink {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        match *event {
            InputEvent::PointerMove { x, y } => {
                let (ax, ay) = self.absolute(x, y);
                send(&[mouse(
                    ax,
                    ay,
                    0,
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                )])
            }
            InputEvent::PointerButton { button, pressed } => {
                let (flags, data) = match (button, pressed) {
                    (Button::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
                    (Button::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
                    (Button::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
                    (Button::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
                    (Button::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
                    (Button::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                    (Button::Back, true) => (MOUSEEVENTF_XDOWN, XBUTTON1),
                    (Button::Back, false) => (MOUSEEVENTF_XUP, XBUTTON1),
                    (Button::Forward, true) => (MOUSEEVENTF_XDOWN, XBUTTON2),
                    (Button::Forward, false) => (MOUSEEVENTF_XUP, XBUTTON2),
                };
                send(&[mouse(0, 0, data, flags)])
            }
            InputEvent::Wheel { dx, dy } => {
                if dy != 0 {
                    send(&[mouse(0, 0, dy, MOUSEEVENTF_WHEEL)])?;
                }
                if dx != 0 {
                    send(&[mouse(0, 0, dx, MOUSEEVENTF_HWHEEL)])?;
                }
                Ok(())
            }
            InputEvent::Key { usb, pressed } => {
                let k = keymap::by_usb(usb).ok_or(InputError::UnknownKey(usb))?;
                let up = if pressed { 0 } else { KEYEVENTF_KEYUP };
                match k.code {
                    "Pause" => send(&[key(VK_PAUSE, 0, up)]),
                    "NumLock" => send(&[key(VK_NUMLOCK, 0, up | KEYEVENTF_EXTENDEDKEY)]),
                    _ => {
                        if k.win == 0 {
                            return Err(InputError::UnknownKey(usb));
                        }
                        let extended = if k.win & 0xff00 == 0xe000 {
                            KEYEVENTF_EXTENDEDKEY
                        } else {
                            0
                        };
                        send(&[key(0, k.win & 0xff, KEYEVENTF_SCANCODE | extended | up)])
                    }
                }
            }
            InputEvent::ReleaseAll => Ok(()),
        }
    }
}
