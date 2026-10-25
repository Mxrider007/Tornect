//! Windows host injection through `SendInput` (media report §6.4).
//!
//! `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` addresses the whole
//! virtual desktop. Once retargeted ([`InputSink::retarget`]) positions arrive
//! normalized over it and pass through unchanged, since the session's
//! [`Viewport`](crate::Viewport) has placed the viewer's pointer onto the
//! monitor the picture shows (decision M1-75). Before every event that acts
//! where the pointer is (a move, a wheel turn, a press) the sink checks that
//! the virtual desktop is still the one the view addresses: after a display
//! change Windows may have moved the pointer onto another monitor, so these
//! wait for the next picture's view, and wheels and presses then wait for a
//! move to place the pointer again. Keys and releases always go. Before any
//! retarget the picture shows the whole virtual desktop but for an odd last
//! column or row (decision M1-74), and positions are placed over that part.
//!
//! The administrator helper's sink ([`SendInputSink::placed`]) is never
//! retargeted (the design's §12, response 3): its moves arrive placed by the
//! host's `Viewport` and pass through with no check, so its residual window is
//! at most one capture interval after a display change, until the host's
//! barrier holds input back.
//!
//! A pixel goes to `SendInput` as the centre of its cell under Windows' own
//! conversion (`virtual_desk_coordinate`, `docs/research/monitors.md` §2),
//! which differs from the `0..=65535` scale the rest of the chain uses.
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
    Button, InputError, InputEvent, InputSink, Rect, View, cannot_follow, denormalize, keymap,
    over_even_part, virtual_desk_coordinate,
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
    /// An event was refused because the desktop changed, and no move has
    /// been injected since: the pointer is wherever Windows put it, which no
    /// picture showed the viewer, so a wheel turn or a press waits for a move.
    unplaced: bool,
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
            placed: true,
            ..Self::default()
        }
    }

    /// Inject `event`, reading the virtual desktop with `live` and handing
    /// what Windows is to inject to `send`: the seam the tests drive.
    fn inject_with(
        &mut self,
        event: &InputEvent,
        live: impl Fn() -> Rect,
        mut send: impl FnMut(&[INPUT]) -> Result<(), InputError>,
    ) -> Result<(), InputError> {
        let desktop = self.check(event, &live)?;
        match *event {
            InputEvent::PointerMove { x, y } => {
                let desktop = desktop.unwrap_or_else(&live);
                let (x, y) = match self.expected {
                    Some(_) => (x, y),
                    None if self.placed => (x, y),
                    None => over_even_part(x, y, desktop),
                };
                let dx = virtual_desk_coordinate(denormalize(x, desktop.width), desktop.width);
                let dy = virtual_desk_coordinate(denormalize(y, desktop.height), desktop.height);
                send(&[mouse(
                    dx,
                    dy,
                    0,
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                )])?;
                self.unplaced = false;
                Ok(())
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

    /// Whether `event` may go now; for one that acts where the pointer is,
    /// the live virtual desktop when it was read. Once retargeted, such an
    /// event goes only onto the desktop the view addresses: after a display
    /// change the viewer's positions are normalized over a desktop that is
    /// gone, and Windows may have moved the pointer onto a monitor the viewer
    /// was not shown, where a press or a wheel turn would act. Keys and
    /// releases always go, so nothing stays held.
    fn check(
        &mut self,
        event: &InputEvent,
        live: &impl Fn() -> Rect,
    ) -> Result<Option<Rect>, InputError> {
        if !event.lands_at_pointer() {
            return Ok(None);
        }
        let Some(space) = self.expected else {
            return Ok(None);
        };
        let desktop = live();
        if desktop != space {
            self.unplaced = true;
            return Err(InputError::Inject(
                "the desktop's layout changed; the pointer waits for the next picture".to_owned(),
            ));
        }
        if self.unplaced && !matches!(event, InputEvent::PointerMove { .. }) {
            return Err(InputError::Inject(
                "the desktop changed since the pointer was placed; a move goes first".to_owned(),
            ));
        }
        Ok(Some(desktop))
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
        self.inject_with(event, virtual_desktop, send)
    }

    /// Keeps the space a rectangle view addresses, for the check before
    /// every event that acts where the pointer is; the mapping itself is the
    /// `Viewport`'s.
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
    use crate::tests::windows_pixel;

    const DESKTOP: Rect = Rect::new(-1920, 0, 4480, 1440);

    /// What reached `send`, read back.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Sent {
        /// A mouse input: its coordinates or wheel data, and its flags.
        Mouse {
            dx: i32,
            dy: i32,
            data: u32,
            flags: u32,
        },
        /// A key.
        Key,
    }

    fn read(input: &INPUT) -> Sent {
        if input.r#type == INPUT_MOUSE {
            // SAFETY: `mouse()` built every `INPUT_MOUSE` input, whose union
            // holds `mi`.
            let mi = unsafe { input.Anonymous.mi };
            Sent::Mouse {
                dx: mi.dx,
                dy: mi.dy,
                data: mi.mouseData,
                flags: mi.dwFlags,
            }
        } else {
            Sent::Key
        }
    }

    /// `event` through `sink` on a virtual desktop that is `desktop` now;
    /// nothing reaches Windows.
    fn drive(
        sink: &mut SendInputSink,
        event: InputEvent,
        desktop: Rect,
    ) -> (Result<(), InputError>, Vec<Sent>) {
        let mut sent = Vec::new();
        let result = sink.inject_with(
            &event,
            || desktop,
            |inputs| {
                sent.extend(inputs.iter().map(read));
                Ok(())
            },
        );
        (result, sent)
    }

    /// The desktop pixel a move put the pointer on, under Windows' rule.
    fn landed(sent: &[Sent], desktop: Rect) -> (i64, i64) {
        let [Sent::Mouse { dx, dy, flags, .. }] = sent else {
            panic!("one mouse input: {sent:?}");
        };
        assert_eq!(
            *flags,
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK
        );
        (
            i64::from(desktop.x) + i64::from(windows_pixel(*dx, desktop.width)),
            i64::from(desktop.y) + i64::from(windows_pixel(*dy, desktop.height)),
        )
    }

    fn retargeted(space: Rect) -> SendInputSink {
        let mut sink = SendInputSink::default();
        sink.retarget(&View::Rect {
            shown: space,
            space,
        })
        .unwrap();
        sink
    }

    fn press() -> InputEvent {
        InputEvent::PointerButton {
            button: Button::Left,
            pressed: true,
        }
    }

    /// Decision M1-75 (the design's §4, as amended at the review of steps 4
    /// and 5): once retargeted, nothing that acts where the pointer is goes
    /// onto a virtual desktop other than the view's. After a display change
    /// (a monitor unplugged, a resolution changed) the viewer's positions are
    /// normalized over a desktop that is gone, and Windows may have moved the
    /// pointer onto a monitor the viewer was not shown: a press or a wheel
    /// turn there would act on it. They all wait for the next picture's view;
    /// keys and releases go, so nothing stays held. Through `Tracked` the
    /// refused press is still counted as held, so the viewer's button-up
    /// later reaches `SendInput` for a button that is up, which it takes and
    /// which holds nothing.
    #[test]
    fn every_positional_event_waits_for_the_next_picture_after_a_display_change() {
        let release = InputEvent::PointerButton {
            button: Button::Left,
            pressed: false,
        };
        let key = |pressed| InputEvent::Key {
            usb: 0x07_0004,
            pressed,
        };
        let wheel = InputEvent::Wheel { dx: 0, dy: 120 };
        let corner = InputEvent::PointerMove { x: 65535, y: 65535 };

        let mut sink = retargeted(DESKTOP);
        let (moved, sent) = drive(&mut sink, corner, DESKTOP);
        moved.unwrap();
        assert_eq!(landed(&sent, DESKTOP), (2559, 1439));
        for event in [press(), wheel, release, key(true), key(false)] {
            let (result, sent) = drive(&mut sink, event, DESKTOP);
            result.unwrap();
            assert_eq!(sent.len(), 1, "{event:?}");
        }

        for changed in [
            Rect::new(0, 0, 2560, 1440),
            Rect::new(-1920, 0, 4480, 1600),
            Rect::new(-1280, 0, 3840, 1440),
        ] {
            let mut sink = retargeted(DESKTOP);
            for event in [corner, press(), wheel] {
                let (refused, sent) = drive(&mut sink, event, changed);
                assert!(
                    matches!(&refused, Err(InputError::Inject(why)) if why.contains("layout changed")),
                    "{changed:?} {event:?}: {refused:?}"
                );
                assert!(sent.is_empty(), "{event:?} reached Windows");
            }
            for event in [release, key(true), key(false)] {
                let (result, sent) = drive(&mut sink, event, changed);
                result.unwrap();
                assert_eq!(sent.len(), 1, "{event:?} goes");
            }

            // The desktop comes back as it was, with no new view: the pointer
            // is still where Windows put it, so a press or a wheel turn waits
            // for a move to place it.
            for event in [press(), wheel] {
                let (refused, sent) = drive(&mut sink, event, DESKTOP);
                assert!(
                    matches!(&refused, Err(InputError::Inject(why)) if why.contains("a move goes first")),
                    "{event:?}: {refused:?}"
                );
                assert!(sent.is_empty());
            }
            let (moved, sent) = drive(&mut sink, corner, DESKTOP);
            moved.unwrap();
            assert_eq!(landed(&sent, DESKTOP), (2559, 1439));
            for event in [press(), wheel] {
                let (result, sent) = drive(&mut sink, event, DESKTOP);
                result.unwrap();
                assert_eq!(sent.len(), 1, "{event:?} after the move");
            }

            // The next picture's view of the changed desktop: moves map
            // again, and a press still waits for one.
            let (refused, _) = drive(&mut sink, press(), changed);
            assert!(refused.is_err());
            sink.retarget(&View::Rect {
                shown: changed,
                space: changed,
            })
            .unwrap();
            let (refused, sent) = drive(&mut sink, press(), changed);
            assert!(refused.is_err() && sent.is_empty(), "{refused:?}");
            let (moved, sent) = drive(&mut sink, InputEvent::PointerMove { x: 0, y: 0 }, changed);
            moved.unwrap();
            assert_eq!(landed(&sent, changed), (i64::from(changed.x), 0));
            let (pressed, sent) = drive(&mut sink, press(), changed);
            pressed.unwrap();
            assert_eq!(sent.len(), 1);
        }
    }

    /// Before any retarget the host's own sink places a position over the part
    /// of the desktop the picture shows: the whole of it but for an odd last
    /// column or row (decision M1-74). The helper's moves arrive placed by the
    /// host and pass through unchecked (the design's §12, response 3). Neither
    /// checks the desktop before a press.
    #[test]
    fn before_a_retarget_the_host_places_and_the_helper_passes_through() {
        let corner = InputEvent::PointerMove { x: 65535, y: 65535 };
        let odd = Rect::new(-1920, 0, 4481, 1441);
        let mut host = SendInputSink::default();
        let (moved, sent) = drive(&mut host, corner, odd);
        moved.unwrap();
        assert_eq!(landed(&sent, odd), (2559, 1439), "the even part's corner");
        let (moved, sent) = drive(&mut host, corner, DESKTOP);
        moved.unwrap();
        assert_eq!(landed(&sent, DESKTOP), (2559, 1439));

        let mut helper = SendInputSink {
            placed: true,
            ..SendInputSink::default()
        };
        let (moved, sent) = drive(&mut helper, corner, odd);
        moved.unwrap();
        assert_eq!(landed(&sent, odd), (2560, 1440), "as the host placed it");

        for sink in [&mut host, &mut helper] {
            let mut sent = Vec::new();
            sink.inject_with(
                &press(),
                || panic!("not read"),
                |inputs| {
                    sent.extend(inputs.iter().map(read));
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(sent.len(), 1);
        }
        assert!(SendInputSink::placed().placed);
        assert!(!SendInputSink::new().placed);
    }

    /// The review's finding on Windows' own rounding (`docs/research/monitors.md`
    /// §2): on a virtual desktop of 1280 + 3440 + 7680 pixels, the first
    /// column of Screen 2 landed on the last of Screen 1. Through a view of
    /// each monitor, both columns at every seam, and the virtual desktop's
    /// first pixel, land where the view meant, never through coordinate 0.
    #[test]
    fn the_columns_at_every_seam_land_on_their_own_monitor() {
        let space = Rect::new(-1280, 0, 1280 + 3440 + 7680, 2160);
        let monitors = [
            Rect::new(-1280, 0, 1280, 1024),
            Rect::new(0, 0, 3440, 1440),
            Rect::new(3440, 0, 7680, 2160),
        ];
        let mut sink = retargeted(space);
        for shown in monitors {
            for (x, y, want) in [
                (0, 0, (shown.x, shown.y)),
                (
                    65535,
                    65535,
                    (
                        shown.x + i32::try_from(shown.width).unwrap() - 1,
                        shown.y + i32::try_from(shown.height).unwrap() - 1,
                    ),
                ),
            ] {
                let (x, y) = crate::remap(x, y, shown, space);
                let (moved, sent) = drive(&mut sink, InputEvent::PointerMove { x, y }, space);
                moved.unwrap();
                assert_eq!(
                    landed(&sent, space),
                    (i64::from(want.0), i64::from(want.1)),
                    "{shown:?}"
                );
                let [Sent::Mouse { dx, dy, .. }] = sent[..] else {
                    unreachable!()
                };
                assert!(dx >= 1 && dy >= 1);
            }
        }
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
