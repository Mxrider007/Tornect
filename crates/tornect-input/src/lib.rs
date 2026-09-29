//! Tornect input (`docs/PLAN.md` §B.4 `input` stream): the fixed 16-byte event,
//! the USB-HID key table, and the host-side injectors.
//!
//! The wire carries **physical** keys as USB HID usages ([`keymap`]), so a
//! Windows viewer drives a Linux host (and the reverse) without either side
//! knowing the other's scancodes. Pointer positions are normalized to
//! `0..=65535` over the shared picture, so the viewer needs no host geometry.
//!
//! ```text
//! offset  0   u8   kind        1 move · 2 button · 3 wheel · 4 key · 5 release-all
//!         1   u8   flags       bit 0 = pressed (button, key)
//!         2   u16  reserved    0
//!         4   u32  code        button (1 left, 2 right, 3 middle, 4 back, 5 forward) · USB usage
//!         8   i32  a           x (0..=65535) · wheel dx (1/120 notch, + = right)
//!        12   i32  b           y (0..=65535) · wheel dy (1/120 notch, + = up / away)
//! ```
//! All fields big-endian.
//!
//! **Host-side policy lives with the caller**: a view-only session must never
//! reach an injector (`tornect-session` drops input frames before decoding
//! them), and every injector is wrapped in [`Tracked`], which releases whatever
//! the viewer still holds when the session ends.

#![warn(missing_docs)]

pub mod helper;
pub mod keymap;
#[cfg(windows)]
pub mod windows;
#[cfg(target_os = "linux")]
pub mod x11;

use std::collections::BTreeSet;

/// Wheel units per notch (Windows `WHEEL_DELTA`).
pub const WHEEL_NOTCH: i32 = 120;

/// Keys no injector passes on (USB usages, [`keymap`]): they power off, suspend
/// or wake the host, or eject its media. That ends the session and needs
/// someone at the machine to recover, and it has no remote-control use
/// (SLICE-A2 A2-5). [`Tracked`], which wraps every injector, refuses them.
pub const SYSTEM_KEYS: &[u32] = &[
    0x01_0082, // Sleep
    0x01_0083, // WakeUp
    0x07_0066, // Power
    0x0c_00b8, // Eject
];

/// A pointer button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Button {
    /// Primary.
    Left,
    /// Secondary.
    Right,
    /// Wheel click.
    Middle,
    /// Browser back (X1).
    Back,
    /// Browser forward (X2).
    Forward,
}

impl Button {
    const fn code(self) -> u32 {
        match self {
            Self::Left => 1,
            Self::Right => 2,
            Self::Middle => 3,
            Self::Back => 4,
            Self::Forward => 5,
        }
    }

    const fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            1 => Self::Left,
            2 => Self::Right,
            3 => Self::Middle,
            4 => Self::Back,
            5 => Self::Forward,
            _ => return None,
        })
    }
}

/// One input event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    /// Absolute pointer position, normalized over the shared picture.
    PointerMove {
        /// 0 = left edge, 65535 = right edge.
        x: u16,
        /// 0 = top edge, 65535 = bottom edge.
        y: u16,
    },
    /// A button went down or up.
    PointerButton {
        /// Which.
        button: Button,
        /// Down (`true`) or up.
        pressed: bool,
    },
    /// Scrolling, in 1/120 notches.
    Wheel {
        /// Horizontal, positive = right.
        dx: i32,
        /// Vertical, positive = up (away from the user).
        dy: i32,
    },
    /// A physical key went down or up.
    Key {
        /// USB HID usage (`keymap::Key::usb`).
        usb: u32,
        /// Down (`true`) or up.
        pressed: bool,
    },
    /// Release everything the viewer holds (it lost focus).
    ReleaseAll,
}

/// Decoding and injection errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InputError {
    /// The 16 bytes are not a valid event.
    #[error("malformed input event: {0}")]
    Malformed(&'static str),
    /// A key this build has no mapping for.
    #[error("unknown key usage 0x{0:06x}")]
    UnknownKey(u32),
    /// The platform refused or failed the injection.
    #[error("input injection failed: {0}")]
    Inject(String),
    /// A key the host never injects ([`SYSTEM_KEYS`]).
    #[error("key usage 0x{0:06x} is a system power key and is not injected")]
    Refused(u32),
}

impl InputEvent {
    /// Whether this lets go of something held: a key-up, a button-up or
    /// [`InputEvent::ReleaseAll`]. Such an event must never be dropped on the
    /// way (a queue or a budget), or the key stays down on the host (SLICE-E
    /// E1-6); [`Tracked`] injects one only for what it holds.
    #[must_use]
    pub fn is_release(&self) -> bool {
        matches!(
            self,
            Self::Key { pressed: false, .. }
                | Self::PointerButton { pressed: false, .. }
                | Self::ReleaseAll
        )
    }

    /// Encode to the 16-byte wire form.
    #[must_use]
    pub fn encode(&self) -> [u8; 16] {
        let (kind, flags, code, a, b): (u8, u8, u32, i32, i32) = match *self {
            Self::PointerMove { x, y } => (1, 0, 0, i32::from(x), i32::from(y)),
            Self::PointerButton { button, pressed } => (2, u8::from(pressed), button.code(), 0, 0),
            Self::Wheel { dx, dy } => (3, 0, 0, dx, dy),
            Self::Key { usb, pressed } => (4, u8::from(pressed), usb, 0, 0),
            Self::ReleaseAll => (5, 0, 0, 0, 0),
        };
        let mut out = [0u8; 16];
        out[0] = kind;
        out[1] = flags;
        out[4..8].copy_from_slice(&code.to_be_bytes());
        out[8..12].copy_from_slice(&a.to_be_bytes());
        out[12..16].copy_from_slice(&b.to_be_bytes());
        out
    }

    /// Decode the 16-byte wire form, bounding every field.
    pub fn decode(bytes: &[u8; 16]) -> Result<Self, InputError> {
        let flags = bytes[1];
        if flags & !1 != 0 || bytes[2] != 0 || bytes[3] != 0 {
            return Err(InputError::Malformed("reserved bits set"));
        }
        let pressed = flags & 1 == 1;
        // Only buttons and keys have a pressed state; a set bit elsewhere is as
        // malformed as a set reserved bit (SLICE-A2 A2-8).
        if pressed && !matches!(bytes[0], 2 | 4) {
            return Err(InputError::Malformed("pressed bit on a kind without one"));
        }
        let code = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let a = i32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let b = i32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        match bytes[0] {
            1 => {
                let x = u16::try_from(a).map_err(|_| InputError::Malformed("x out of range"))?;
                let y = u16::try_from(b).map_err(|_| InputError::Malformed("y out of range"))?;
                Ok(Self::PointerMove { x, y })
            }
            2 => Button::from_code(code)
                .map(|button| Self::PointerButton { button, pressed })
                .ok_or(InputError::Malformed("unknown button")),
            3 => {
                // Far beyond any real device; bounds the injector's loop.
                // `unsigned_abs`, because `i32::MIN.abs()` overflows (SLICE-C1 C1-5).
                const MAX: u32 = 100 * WHEEL_NOTCH.unsigned_abs();
                if a.unsigned_abs() > MAX || b.unsigned_abs() > MAX {
                    return Err(InputError::Malformed("wheel delta out of range"));
                }
                Ok(Self::Wheel { dx: a, dy: b })
            }
            4 => {
                if keymap::by_usb(code).is_none() {
                    return Err(InputError::UnknownKey(code));
                }
                Ok(Self::Key { usb: code, pressed })
            }
            5 => Ok(Self::ReleaseAll),
            _ => Err(InputError::Malformed("unknown kind")),
        }
    }
}

/// A host-side injector.
pub trait InputSink: Send {
    /// Inject one event. [`InputEvent::ReleaseAll`] is handled by [`Tracked`]
    /// and never reaches an inner sink.
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError>;
}

/// Wraps an injector and remembers what is held down, so that
/// [`InputEvent::ReleaseAll`], a repeated press, and dropping the wrapper
/// (session end, panic key) never leave a key or button stuck on the host.
///
/// A release the injector refuses (the Wayland portal's queue can be full) is
/// owed, not forgotten: it is sent again before the next event and by every
/// release of everything, until the injector takes it (slice-G G1-3). Owed
/// releases go out in the order they were refused (slice-G N-2).
pub struct Tracked<S: InputSink> {
    inner: S,
    keys: BTreeSet<u32>,
    buttons: BTreeSet<Button>,
    /// Releases refused, oldest first; a key or button is owed at most once.
    owed: Vec<Owed>,
}

/// A release still owed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owed {
    Key(u32),
    Button(Button),
}

impl<S: InputSink> Tracked<S> {
    /// Track `inner`.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            keys: BTreeSet::new(),
            buttons: BTreeSet::new(),
            owed: Vec::new(),
        }
    }

    /// Release every key and button still held, and every release still owed.
    pub fn release_all(&mut self) {
        self.settle();
        for usb in std::mem::take(&mut self.keys) {
            let _ = self.release_key(usb);
        }
        for button in std::mem::take(&mut self.buttons) {
            let _ = self.release_button(button);
        }
    }

    /// Send the releases still owed, in the order they were refused; one
    /// refused again stays owed, in the same order.
    fn settle(&mut self) {
        for owed in std::mem::take(&mut self.owed) {
            let _ = match owed {
                Owed::Key(usb) => self.release_key(usb),
                Owed::Button(button) => self.release_button(button),
            };
        }
    }

    /// Let go of `usb`, no longer held; owed if the injector refuses.
    fn release_key(&mut self, usb: u32) -> Result<(), InputError> {
        let released = self.inner.inject(&InputEvent::Key {
            usb,
            pressed: false,
        });
        if let Err(e) = &released {
            tracing::debug!(error = %e, "releasing a key failed; it is sent again later");
            self.owed.push(Owed::Key(usb));
        }
        released
    }

    /// Let go of `button`, no longer held; owed if the injector refuses.
    fn release_button(&mut self, button: Button) -> Result<(), InputError> {
        let released = self.inner.inject(&InputEvent::PointerButton {
            button,
            pressed: false,
        });
        if let Err(e) = &released {
            tracing::debug!(error = %e, "releasing a button failed; it is sent again later");
            self.owed.push(Owed::Button(button));
        }
        released
    }
}

impl<S: InputSink> InputSink for Tracked<S> {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        self.settle();
        match *event {
            InputEvent::ReleaseAll => {
                self.release_all();
                return Ok(());
            }
            InputEvent::Key { usb, .. } if SYSTEM_KEYS.contains(&usb) => {
                return Err(InputError::Refused(usb));
            }
            // Held again: its next release, not the one owed, lets it go.
            InputEvent::Key { usb, pressed: true } => {
                self.owed.retain(|owed| *owed != Owed::Key(usb));
                self.keys.insert(usb);
            }
            // A release for a key the host never saw pressed is dropped: some
            // compositors reject it ("Invalid key event").
            InputEvent::Key {
                usb,
                pressed: false,
            } => {
                return if self.keys.remove(&usb) {
                    self.release_key(usb)
                } else {
                    Ok(())
                };
            }
            InputEvent::PointerButton {
                button,
                pressed: true,
            } => {
                self.owed.retain(|owed| *owed != Owed::Button(button));
                self.buttons.insert(button);
            }
            InputEvent::PointerButton {
                button,
                pressed: false,
            } => {
                return if self.buttons.remove(&button) {
                    self.release_button(button)
                } else {
                    Ok(())
                };
            }
            InputEvent::PointerMove { .. } | InputEvent::Wheel { .. } => {}
        }
        self.inner.inject(event)
    }
}

impl<S: InputSink> Drop for Tracked<S> {
    fn drop(&mut self) {
        self.release_all();
    }
}

/// Split a wheel delta into whole notches, keeping the remainder for later
/// (X11 buttons 4-7 and the portal's discrete axis only take whole notches).
#[derive(Debug, Default, Clone, Copy)]
pub struct WheelAccumulator {
    dx: i32,
    dy: i32,
}

impl WheelAccumulator {
    /// Add a delta; returns whole notches `(dx, dy)` ready to inject.
    pub fn add(&mut self, dx: i32, dy: i32) -> (i32, i32) {
        self.dx = self.dx.saturating_add(dx);
        self.dy = self.dy.saturating_add(dy);
        let nx = self.dx / WHEEL_NOTCH;
        let ny = self.dy / WHEEL_NOTCH;
        self.dx -= nx * WHEEL_NOTCH;
        self.dy -= ny * WHEEL_NOTCH;
        (nx, ny)
    }
}

/// The part of a `width`×`height` screen the viewer sees, as the size of its
/// top-left corner: the encoder's crop (`tornect_codec::encoded_size`), which
/// the session layer passes in, since this crate does not see the codec.
pub type Region = fn(u32, u32) -> (u32, u32);

/// The whole screen: the [`Region`] of a picture that is not cropped.
#[must_use]
pub fn whole(width: u32, height: u32) -> (u32, u32) {
    (width, height)
}

/// The pixel of a `size` screen that a position normalized over its visible
/// `region` points at, so that the viewer's pointer covers what it sees and not
/// a desktop wider than the encoder sends (SLICE-C1 C1-2).
#[must_use]
pub fn place(x: u16, y: u16, size: (u32, u32), region: Region) -> (u32, u32) {
    let (width, height) = region(size.0, size.1);
    (
        denormalize(x, width.min(size.0)),
        denormalize(y, height.min(size.1)),
    )
}

/// Map a normalized `0..=65535` coordinate onto `0..size` pixels.
#[must_use]
pub fn denormalize(v: u16, size: u32) -> u32 {
    if size <= 1 {
        return 0;
    }
    ((u64::from(v) * u64::from(size - 1) + 32_767) / 65_535) as u32
}

/// Map a pixel position inside `0..size` to the normalized `0..=65535` range.
#[must_use]
pub fn normalize(pos: f64, size: f64) -> u16 {
    if size <= 1.0 || !pos.is_finite() {
        return 0;
    }
    ((pos / (size - 1.0)).clamp(0.0, 1.0) * 65_535.0).round() as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder(Vec<InputEvent>);

    impl InputSink for Recorder {
        fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
            self.0.push(*event);
            Ok(())
        }
    }

    #[test]
    fn every_event_round_trips_through_16_bytes() {
        for ev in [
            InputEvent::PointerMove { x: 0, y: 65535 },
            InputEvent::PointerButton {
                button: Button::Forward,
                pressed: true,
            },
            InputEvent::Wheel { dx: -240, dy: 120 },
            InputEvent::Key {
                usb: 0x070004,
                pressed: false,
            },
            InputEvent::ReleaseAll,
        ] {
            assert_eq!(InputEvent::decode(&ev.encode()).unwrap(), ev);
        }
    }

    /// SLICE-A2 A2-5: power, sleep, wake and eject never reach an injector, and
    /// are never tracked as held.
    #[test]
    fn system_power_keys_are_refused() {
        for &usb in SYSTEM_KEYS {
            assert!(keymap::by_usb(usb).is_some(), "0x{usb:06x} is in the table");
            let mut sink = Tracked::new(Recorder(Vec::new()));
            let err = sink
                .inject(&InputEvent::Key { usb, pressed: true })
                .unwrap_err();
            assert!(matches!(err, InputError::Refused(u) if u == usb), "{err}");
            assert!(sink.inner.0.is_empty(), "nothing reached the injector");
            assert!(sink.keys.is_empty());
        }
    }

    /// SLICE-A2 A2-8: the pressed bit is rejected on kinds that have no pressed
    /// state, like a set reserved bit.
    #[test]
    fn a_pressed_bit_on_a_move_is_malformed() {
        let mut bytes = InputEvent::PointerMove { x: 1, y: 2 }.encode();
        bytes[1] = 1;
        assert!(matches!(
            InputEvent::decode(&bytes),
            Err(InputError::Malformed(_))
        ));
        let mut bytes = InputEvent::ReleaseAll.encode();
        bytes[1] = 1;
        assert!(InputEvent::decode(&bytes).is_err());
    }

    #[test]
    fn hostile_bytes_are_rejected_not_trusted() {
        let mut move_out = InputEvent::PointerMove { x: 1, y: 1 }.encode();
        move_out[8..12].copy_from_slice(&70_000i32.to_be_bytes());
        assert!(InputEvent::decode(&move_out).is_err());
        let mut key = InputEvent::Key {
            usb: 0x070004,
            pressed: true,
        }
        .encode();
        key[4..8].copy_from_slice(&0x00ff_ffffu32.to_be_bytes());
        assert!(matches!(
            InputEvent::decode(&key),
            Err(InputError::UnknownKey(_))
        ));
        let mut reserved = InputEvent::ReleaseAll.encode();
        reserved[2] = 1;
        assert!(InputEvent::decode(&reserved).is_err());
        let mut wheel = InputEvent::Wheel { dx: 0, dy: 0 }.encode();
        wheel[12..16].copy_from_slice(&i32::MAX.to_be_bytes());
        assert!(InputEvent::decode(&wheel).is_err());
        assert!(InputEvent::decode(&[9; 16]).is_err());
    }

    #[test]
    fn tracked_releases_what_is_held_on_release_all_and_on_drop() {
        let mut t = Tracked::new(Recorder(Vec::new()));
        t.inject(&InputEvent::Key {
            usb: 0x0700e1,
            pressed: true,
        })
        .unwrap();
        t.inject(&InputEvent::PointerButton {
            button: Button::Left,
            pressed: true,
        })
        .unwrap();
        t.inject(&InputEvent::ReleaseAll).unwrap();
        let released: Vec<_> = t.inner.0[2..].to_vec();
        assert_eq!(
            released,
            vec![
                InputEvent::Key {
                    usb: 0x0700e1,
                    pressed: false
                },
                InputEvent::PointerButton {
                    button: Button::Left,
                    pressed: false
                },
            ]
        );
        // A stray release is not forwarded.
        t.inject(&InputEvent::Key {
            usb: 0x070004,
            pressed: false,
        })
        .unwrap();
        assert_eq!(t.inner.0.len(), 4);
    }

    /// Refuses the first release it is given, as the Wayland portal's full
    /// queue does, and records everything else.
    #[derive(Default)]
    struct RefusesOneRelease {
        seen: Vec<InputEvent>,
        refused: bool,
    }

    impl InputSink for RefusesOneRelease {
        fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
            if !self.refused && event.is_release() {
                self.refused = true;
                return Err(InputError::Inject("the queue is full".to_owned()));
            }
            self.seen.push(*event);
            Ok(())
        }
    }

    /// Slice-G G1-3: a release the injector refused is sent again, by the next
    /// `ReleaseAll` (the quiet release and the session's end take that path
    /// too) and before the next event. Before, `Tracked` had already struck
    /// the key from what is held, so nothing ever let it go.
    #[test]
    fn a_release_the_sink_refused_is_sent_again() {
        let key = |pressed| InputEvent::Key {
            usb: 0x07_0004,
            pressed,
        };
        let button = |pressed| InputEvent::PointerButton {
            button: Button::Left,
            pressed,
        };
        let moved = InputEvent::PointerMove { x: 1, y: 2 };

        let mut t = Tracked::new(RefusesOneRelease::default());
        t.inject(&key(true)).unwrap();
        t.inject(&button(true)).unwrap();
        assert!(t.inject(&key(false)).is_err());
        t.inject(&InputEvent::ReleaseAll).unwrap();
        assert_eq!(
            t.inner.seen,
            [key(true), button(true), key(false), button(false)]
        );

        for (press, release) in [(key(true), key(false)), (button(true), button(false))] {
            let mut t = Tracked::new(RefusesOneRelease::default());
            t.inject(&press).unwrap();
            assert!(t.inject(&release).is_err());
            t.inject(&moved).unwrap();
            assert_eq!(t.inner.seen, [press, release, moved], "{release:?}");
            // Nothing is owed or held any more.
            t.release_all();
            assert_eq!(t.inner.seen.len(), 3);
        }
    }

    /// Slice-G G1-3, the direct path: the quiet release and the drop call
    /// `release_all()` itself, not `inject(&ReleaseAll)`, so `release_all()`
    /// sends what is owed on its own; and a release it cannot send is owed
    /// too, and goes out before the next event.
    #[test]
    fn release_all_sends_what_is_owed_and_owes_what_it_cannot_send() {
        let key = |pressed| InputEvent::Key {
            usb: 0x07_0004,
            pressed,
        };
        let moved = InputEvent::PointerMove { x: 1, y: 2 };

        let mut t = Tracked::new(RefusesOneRelease::default());
        t.inject(&key(true)).unwrap();
        assert!(t.inject(&key(false)).is_err());
        t.release_all();
        assert_eq!(t.inner.seen, [key(true), key(false)], "the owed key-up");

        let mut t = Tracked::new(RefusesOneRelease::default());
        t.inject(&key(true)).unwrap();
        t.release_all();
        t.inject(&moved).unwrap();
        assert_eq!(
            t.inner.seen,
            [key(true), key(false), moved],
            "the key-up release_all could not send"
        );
    }

    /// Refuses every event while `full`, as the portal's full queue does, and
    /// records the rest.
    #[derive(Default)]
    struct Stalls {
        seen: Vec<InputEvent>,
        full: bool,
    }

    impl InputSink for Stalls {
        fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
            if self.full {
                return Err(InputError::Inject("the queue is full".to_owned()));
            }
            self.seen.push(*event);
            Ok(())
        }
    }

    /// Slice-G N-2: owed releases go out in the order they were refused. A
    /// Ctrl-drag that ends while the portal stalls (the button up, then Ctrl
    /// up) drops with Ctrl still down, as the viewer did it. Before, owed keys
    /// went out before owed buttons, so the drop came without Ctrl: a move
    /// instead of a copy.
    #[test]
    fn owed_releases_go_out_in_the_order_they_were_refused() {
        let ctrl = |pressed| InputEvent::Key {
            usb: 0x07_00e0,
            pressed,
        };
        let left = |pressed| InputEvent::PointerButton {
            button: Button::Left,
            pressed,
        };
        let moved = InputEvent::PointerMove { x: 1, y: 2 };
        let mut t = Tracked::new(Stalls::default());
        t.inject(&ctrl(true)).unwrap();
        t.inject(&left(true)).unwrap();
        t.inner.full = true;
        assert!(t.inject(&left(false)).is_err());
        assert!(t.inject(&ctrl(false)).is_err());
        t.inner.full = false;
        t.inject(&moved).unwrap();
        assert_eq!(
            t.inner.seen,
            [ctrl(true), left(true), left(false), ctrl(false), moved]
        );
    }

    /// SLICE-C1 C1-5: `i32::MIN` has no absolute value in `i32`. The old range
    /// check overflowed on it: a panic in a debug build, and in a release
    /// build a delta that passed the check.
    /// SLICE-E E1-6: what may never be dropped on the way to the host.
    #[test]
    fn releases_are_key_ups_button_ups_and_release_all() {
        let releases = [
            InputEvent::Key {
                usb: 0x07_0004,
                pressed: false,
            },
            InputEvent::PointerButton {
                button: Button::Right,
                pressed: false,
            },
            InputEvent::ReleaseAll,
        ];
        let others = [
            InputEvent::Key {
                usb: 0x07_0004,
                pressed: true,
            },
            InputEvent::PointerButton {
                button: Button::Right,
                pressed: true,
            },
            InputEvent::PointerMove { x: 1, y: 2 },
            InputEvent::Wheel { dx: 0, dy: 120 },
        ];
        assert!(releases.iter().all(InputEvent::is_release));
        assert!(!others.iter().any(InputEvent::is_release));
    }

    #[test]
    fn the_most_negative_wheel_delta_is_refused() {
        for (dx, dy) in [(i32::MIN, 0), (0, i32::MIN)] {
            let wheel = InputEvent::Wheel { dx, dy }.encode();
            assert!(
                matches!(InputEvent::decode(&wheel), Err(InputError::Malformed(_))),
                "{dx} {dy}"
            );
        }
    }

    #[test]
    fn wheel_accumulates_to_whole_notches() {
        let mut acc = WheelAccumulator::default();
        assert_eq!(acc.add(0, 60), (0, 0));
        assert_eq!(acc.add(0, 60), (0, 1));
        assert_eq!(acc.add(-250, 0), (-2, 0));
        assert_eq!(acc.add(-10, 0), (0, 0));
        assert_eq!(acc.add(-100, 0), (-1, 0));
    }

    #[test]
    fn a_position_over_the_visible_region_lands_inside_it() {
        let crop = |w: u32, h: u32| ((w & !1).min(3840), (h & !1).min(2160));
        // Two 4K screens side by side: the viewer sees the left 3840x2160.
        assert_eq!(place(65535, 65535, (7680, 2160), crop), (3839, 2159));
        assert_eq!(place(0, 0, (7680, 2160), crop), (0, 0));
        assert_eq!(place(32768, 0, (7680, 2160), crop), (1920, 0));
        // An odd screen loses its last column and row, as the encoder does.
        assert_eq!(place(65535, 65535, (1921, 1081), crop), (1919, 1079));
        assert_eq!(place(65535, 65535, (1920, 1080), whole), (1919, 1079));
        // A region larger than the screen is the screen.
        assert_eq!(
            place(65535, 65535, (800, 600), |_, _| (4000, 4000)),
            (799, 599)
        );
    }

    #[test]
    fn coordinates_map_edge_to_edge() {
        assert_eq!(denormalize(0, 1920), 0);
        assert_eq!(denormalize(65535, 1920), 1919);
        assert_eq!(normalize(0.0, 1920.0), 0);
        assert_eq!(normalize(1919.0, 1920.0), 65535);
        assert_eq!(normalize(5000.0, 1920.0), 65535);
        assert_eq!(normalize(f64::NAN, 1920.0), 0);
        let mid = normalize(959.5, 1920.0);
        assert!((denormalize(mid, 1920) as i64 - 960).abs() <= 1);
    }
}
