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
pub struct Tracked<S: InputSink> {
    inner: S,
    keys: BTreeSet<u32>,
    buttons: BTreeSet<Button>,
}

impl<S: InputSink> Tracked<S> {
    /// Track `inner`.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            keys: BTreeSet::new(),
            buttons: BTreeSet::new(),
        }
    }

    /// Release every key and button still held.
    pub fn release_all(&mut self) {
        for usb in std::mem::take(&mut self.keys) {
            if let Err(e) = self.inner.inject(&InputEvent::Key {
                usb,
                pressed: false,
            }) {
                tracing::debug!(error = %e, "releasing a held key failed");
            }
        }
        for button in std::mem::take(&mut self.buttons) {
            if let Err(e) = self.inner.inject(&InputEvent::PointerButton {
                button,
                pressed: false,
            }) {
                tracing::debug!(error = %e, "releasing a held button failed");
            }
        }
    }
}

impl<S: InputSink> InputSink for Tracked<S> {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        match *event {
            InputEvent::ReleaseAll => {
                self.release_all();
                return Ok(());
            }
            InputEvent::Key { usb, .. } if SYSTEM_KEYS.contains(&usb) => {
                return Err(InputError::Refused(usb));
            }
            InputEvent::Key { usb, pressed } => {
                // A release for a key the host never saw pressed is dropped:
                // some compositors reject it ("Invalid key event").
                let changed = if pressed {
                    self.keys.insert(usb)
                } else {
                    self.keys.remove(&usb)
                };
                if !changed && !pressed {
                    return Ok(());
                }
            }
            InputEvent::PointerButton { button, pressed } => {
                let changed = if pressed {
                    self.buttons.insert(button)
                } else {
                    self.buttons.remove(&button)
                };
                if !changed && !pressed {
                    return Ok(());
                }
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

    /// SLICE-C1 C1-5: `i32::MIN` has no absolute value in `i32`. The old range
    /// check overflowed on it: a panic in a debug build, and in a release
    /// build a delta that passed the check.
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
