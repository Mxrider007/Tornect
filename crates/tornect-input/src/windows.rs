//! Windows host injection through `SendInput` (media report §6.4).
//!
//! `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` addresses the whole
//! virtual desktop. Once retargeted ([`InputSink::retarget`]) positions arrive
//! normalized over it and pass through unchanged, since the session's
//! [`Viewport`](crate::Viewport) has placed the viewer's pointer onto the
//! monitor the picture shows (decision M1-75); at every move the sink checks
//! that the virtual desktop is still the one the view addresses, and after a
//! display change it refuses moves until the next picture brings a new view.
//! Before any retarget the picture shows the whole virtual desktop but for an
//! odd last column or row (decision M1-74), and positions are placed over
//! that part.
//!
//! The administrator helper's sink ([`SendInputSink::placed`]) is never
//! retargeted (the design's §12, response 3): its moves arrive placed by the
//! host's `Viewport` and pass through with no check, so its residual window is
//! at most one capture interval after a display change, until the host's
//! barrier holds input back.
//!
//! Both processes must be per-monitor v2 DPI aware ([`become_dpi_aware`]):
//! otherwise Windows virtualizes the virtual desktop on a mixed-DPI desktop
//! and no normalization is exact (`docs/research/monitors.md` §2).
//!
//! Keys are injected by scancode (`KEYEVENTF_SCANCODE`), independent of the
//! host's keyboard layout, except Pause and NumLock, whose scancodes are
//! irregular and go by virtual-key code.
//!
//! Limits (Windows by design, stated in the UI): input into an **elevated**
//! window is silently dropped (UIPI), and the secure desktop (UAC prompt, lock
//! screen) cannot be reached from a user-session process.
#![allow(unsafe_code)]

use std::sync::Once;

use windows_sys::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL,
    MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP,
    MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK,
    MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, SendInput,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

use crate::{
    Button, InputError, InputEvent, InputSink, Rect, View, cannot_follow, keymap, over_even_part,
};

/// `VK_PAUSE` / `VK_NUMLOCK` (irregular scancodes, injected by VK).
const VK_PAUSE: u16 = 0x13;
const VK_NUMLOCK: u16 = 0x90;
/// `XBUTTON1` / `XBUTTON2` for `mouseData`.
const XBUTTON1: i32 = 1;
const XBUTTON2: i32 = 2;

static DPI_AWARE: Once = Once::new();

/// Make this process per-monitor v2 DPI aware, once. Monitor rectangles, the
/// virtual desktop's metrics, GDI's blits and `SendInput`'s virtual-desk
/// coordinates are then all physical pixels; without it Windows virtualizes
/// them on a high-DPI or mixed-DPI desktop, and the picture, the monitor list
/// and the pointer disagree (`docs/research/monitors.md` §1–§2). winit sets it
/// for GUI processes; the CLI host's capture, `doctor` and the administrator
/// helper have no window and must call this before they measure or inject.
pub fn become_dpi_aware() {
    DPI_AWARE.call_once(|| {
        // SAFETY: plain call with a documented constant. It fails (FALSE) when
        // the awareness was already set, by a manifest or by winit, which is fine.
        unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    });
}

/// Injects into the interactive desktop of this user session.
#[derive(Debug, Default)]
pub struct SendInputSink {
    /// The virtual desktop the session's view addresses, once retargeted.
    expected: Option<Rect>,
    /// Positions arrive placed on the whole virtual desktop by the host's
    /// `Viewport`, before any retarget too (the administrator helper).
    placed: bool,
}

impl SendInputSink {
    /// The host's own injector: until a retarget, positions are placed over
    /// the part of the virtual desktop the picture shows.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The administrator helper's injector: every position arrives already
    /// placed on the whole virtual desktop by the host's `Viewport`, and
    /// passes through.
    #[must_use]
    pub fn placed() -> Self {
        Self {
            expected: None,
            placed: true,
        }
    }

    /// `(x, y)` as the absolute coordinates `MOUSEEVENTF_VIRTUALDESK` takes,
    /// normalized over the whole virtual desktop.
    fn absolute(&self, x: u16, y: u16) -> Result<(u16, u16), InputError> {
        place_on(self.expected, self.placed, x, y, virtual_desktop)
    }
}

/// The virtual desktop now: its origin and size, in physical pixels under
/// per-monitor v2 awareness.
fn virtual_desktop() -> Rect {
    // SAFETY: `GetSystemMetrics` has no preconditions and only reads.
    let (x, y, width, height) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    };
    Rect::new(
        x,
        y,
        u32::try_from(width).unwrap_or(0),
        u32::try_from(height).unwrap_or(0),
    )
}

/// Where a move goes, normalized over the `live` virtual desktop. Once
/// retargeted, only onto the desktop the view addresses: after a display
/// change the positions the viewer sends are normalized over a desktop that is
/// gone. A `placed` sink's positions pass through; before any retarget the
/// host's own sink places them over the desktop's even part.
fn place_on(
    expected: Option<Rect>,
    placed: bool,
    x: u16,
    y: u16,
    live: impl FnOnce() -> Rect,
) -> Result<(u16, u16), InputError> {
    match expected {
        Some(space) => {
            if space == live() {
                Ok((x, y))
            } else {
                Err(InputError::Inject(
                    "the desktop's layout changed; moves wait for the next picture".to_owned(),
                ))
            }
        }
        None if placed => Ok((x, y)),
        None => Ok(over_even_part(x, y, live())),
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
                let (x, y) = self.absolute(x, y)?;
                send(&[mouse(
                    i32::from(x),
                    i32::from(y),
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

    /// Keeps the space a rectangle view addresses, for the check at every
    /// move; the mapping itself is the `Viewport`'s.
    fn retarget(&mut self, view: &View) -> Result<(), InputError> {
        match view {
            View::Rect { space, .. } => {
                self.expected = Some(*space);
                Ok(())
            }
            View::Stream { .. } => Err(cannot_follow()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESKTOP: Rect = Rect::new(-1920, 0, 4480, 1440);

    /// Decision M1-75 (the design's §4): once retargeted, a move goes only
    /// onto the virtual desktop the view addresses, unchanged, since the
    /// `Viewport` placed it. A display change between two pictures (a monitor
    /// unplugged, a resolution changed) leaves moves normalized over a desktop
    /// that is gone, so they wait for the next picture's view.
    #[test]
    fn a_move_waits_for_the_next_picture_after_a_display_change() {
        for placed in [false, true] {
            assert_eq!(
                place_on(Some(DESKTOP), placed, 7, 9, || DESKTOP).unwrap(),
                (7, 9)
            );
            for changed in [
                Rect::new(0, 0, 2560, 1440),
                Rect::new(-1920, 0, 4480, 1600),
                Rect::new(-1280, 0, 3840, 1440),
            ] {
                let refused = place_on(Some(DESKTOP), placed, 7, 9, || changed);
                assert!(
                    matches!(&refused, Err(InputError::Inject(why)) if why.contains("layout changed")),
                    "{changed:?}: {refused:?}"
                );
            }
        }
    }

    /// Before any retarget the host's own sink places a position over the part
    /// of the desktop the picture shows: the whole of it but for an odd last
    /// column or row (decision M1-74). The helper's moves arrive placed by the
    /// host and pass through unchecked (the design's §12, response 3).
    #[test]
    fn before_a_retarget_the_host_places_and_the_helper_passes_through() {
        let odd = Rect::new(-1920, 0, 4481, 1441);
        let (x, y) = place_on(None, false, 65535, 65535, || odd).unwrap();
        assert_eq!(
            (crate::denormalize(x, 4481), crate::denormalize(y, 1441)),
            (4479, 1439)
        );
        assert_eq!(
            place_on(None, false, 65535, 65535, || DESKTOP).unwrap(),
            (65535, 65535)
        );
        assert_eq!(
            place_on(None, true, 65535, 65535, || panic!("not read")).unwrap(),
            (65535, 65535)
        );
        assert!(SendInputSink::placed().placed);
        assert!(!SendInputSink::new().placed);
    }

    /// The sink keeps a rectangle view's space and cannot follow a stream.
    /// Nothing is injected here.
    #[test]
    fn a_retarget_keeps_the_space_and_refuses_a_stream() {
        let mut sink = SendInputSink::new();
        assert_eq!(sink.expected, None);
        sink.retarget(&View::Rect {
            shown: Rect::new(-1920, 0, 1920, 1080),
            space: DESKTOP,
        })
        .unwrap();
        assert_eq!(sink.expected, Some(DESKTOP));
        let stream = View::Stream {
            node: 1,
            pixels: (1920, 1080),
            ratio: None,
        };
        assert!(sink.retarget(&stream).is_err());
        assert_eq!(sink.expected, Some(DESKTOP));
    }
}
