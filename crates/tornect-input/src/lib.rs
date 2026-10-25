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
//!
//! **Where a position lands** (decision M1-75): a desktop injector addresses
//! its whole space (the Windows virtual desktop, the X11 root), and a
//! [`Viewport`] in front of it rewrites each position, normalized over the
//! picture, onto the rectangle that picture shows ([`View::Rect`], [`remap`]).
//! When the picture moves to another screen the host retargets the chain
//! ([`InputSink::retarget`]) before it handles any later input.

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
    /// A [`View`] no position can be mapped onto ([`Viewport`]).
    #[error("the picture cannot be mapped onto the desktop: {0}")]
    BadView(&'static str),
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

    /// Whether this acts where the host's pointer is: a move, a wheel turn or
    /// a button press. Across a change of the shown screen such an event can
    /// land on a screen the viewer was not shown, so the host holds these back
    /// at its barrier (decision M1-75); a release never acts at a new place
    /// and always goes through.
    #[must_use]
    pub fn lands_at_pointer(&self) -> bool {
        matches!(
            self,
            Self::PointerMove { .. }
                | Self::Wheel { .. }
                | Self::PointerButton { pressed: true, .. }
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

    /// Follow the picture to what `view` shows; every later event is meant for
    /// it. A sink that cannot must refuse, and the host then ends the
    /// session's input rather than mis-map a click (decision M1-75).
    ///
    /// The default suits a sink that addresses a whole [`View::Rect`] space
    /// and is fed by a [`Viewport`], which does the mapping: it accepts any
    /// [`View::Rect`] and refuses a [`View::Stream`], which it cannot address.
    fn retarget(&mut self, view: &View) -> Result<(), InputError> {
        match view {
            View::Rect { .. } => Ok(()),
            View::Stream { .. } => Err(cannot_follow()),
        }
    }
}

/// A boxed sink is a sink: it forwards both calls, so a wrapper that holds
/// one (the host's `Tracked<Viewport<Box<dyn InputSink>>>`) never falls back
/// to the trait's default [`InputSink::retarget`], which would take a view the
/// boxed sink refuses (the Wayland injector) or never hand one to the live
/// check that needs it (the Windows and X11 sinks).
impl<S: InputSink + ?Sized> InputSink for Box<S> {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        (**self).inject(event)
    }

    fn retarget(&mut self, view: &View) -> Result<(), InputError> {
        (**self).retarget(view)
    }
}

/// What a sink answers to a [`View`] it cannot address.
pub(crate) fn cannot_follow() -> InputError {
    InputError::Inject("this injector cannot follow the picture to another screen".to_owned())
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

    /// Settles what is owed and lets go of every held button before the
    /// picture moves, so no drag carries over to another screen; a button-up
    /// the injector refuses stays owed, as at any release. Held keys stay
    /// down, so a modifier the viewer holds survives the switch.
    fn retarget(&mut self, view: &View) -> Result<(), InputError> {
        self.settle();
        for button in std::mem::take(&mut self.buttons) {
            let _ = self.release_button(button);
        }
        self.inner.retarget(view)
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

/// The largest side of a [`View::Rect`] space, in pixels: up to it a pixel
/// survives being normalized and placed again exactly ([`remap`]).
pub const MAX_SPACE: u32 = 65_536;

/// A rectangle of a desktop, in the desktop's own units: physical pixels of
/// the Windows virtual desktop (per-monitor v2 awareness), pixels of the X11
/// root. `x` and `y` can be negative (a Windows monitor left of the primary).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Rect {
    /// Left edge.
    pub x: i32,
    /// Top edge.
    pub y: i32,
    /// Width; the right edge is `x + width`, exclusive.
    pub width: u32,
    /// Height; the bottom edge is `y + height`, exclusive.
    pub height: u32,
}

impl Rect {
    /// The rectangle at `(x, y)` of `width`×`height`.
    #[must_use]
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// Whether `other` lies wholly inside this rectangle.
    #[must_use]
    pub fn contains(&self, other: &Rect) -> bool {
        let (left, top, right, bottom) = self.edges();
        let (o_left, o_top, o_right, o_bottom) = other.edges();
        o_left >= left && o_top >= top && o_right <= right && o_bottom <= bottom
    }

    /// The area this rectangle shares with `other`; 0 when they only touch or
    /// do not meet.
    #[must_use]
    pub fn area_overlap(&self, other: &Rect) -> u64 {
        let (left, top, right, bottom) = self.edges();
        let (o_left, o_top, o_right, o_bottom) = other.edges();
        let width = right.min(o_right) - left.max(o_left);
        let height = bottom.min(o_bottom) - top.max(o_top);
        match (u64::try_from(width), u64::try_from(height)) {
            (Ok(width), Ok(height)) => width.saturating_mul(height),
            _ => 0,
        }
    }

    /// Left, top, right and bottom, exclusive, without overflow.
    fn edges(&self) -> (i64, i64, i64, i64) {
        let (x, y) = (i64::from(self.x), i64::from(self.y));
        (x, y, x + i64::from(self.width), y + i64::from(self.height))
    }
}

/// How a Wayland stream's pixels relate to the compositor's logical units,
/// measured once, at the stream's first negotiation (decision M1-75, the
/// design's Part 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ratio {
    /// The stream's logical size, as the portal gave it.
    pub logical: (u32, u32),
    /// The pixel size first negotiated for it.
    pub pixels: (u32, u32),
}

/// What the picture shows, as an injector must address it (decision M1-75).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// A rectangle of a desktop the injector addresses whole: a [`Viewport`]
    /// maps every position onto `shown`, normalized over `space`.
    Rect {
        /// The rectangle the picture shows, inside `space`; capture makes its
        /// width and height even.
        shown: Rect,
        /// What the injector addresses: the Windows virtual desktop in
        /// physical pixels, the X11 root.
        space: Rect,
    },
    /// A Wayland portal stream (the design's Part 2), at the picture's size.
    Stream {
        /// The stream's PipeWire node.
        node: u32,
        /// The picture's size in pixels.
        pixels: (u32, u32),
        /// Logical units per pixel; `None` when they could not be measured,
        /// and moves on this stream are refused.
        ratio: Option<Ratio>,
    },
}

/// A position normalized over the picture, as the same pixel normalized over
/// `space`: the picture shows `shown`, which lies inside `space`. The pixel is
/// clamped into `space`; for a `shown` inside it nothing is clamped, so the
/// position lands inside `shown`.
///
/// Exact for spaces up to [`MAX_SPACE`] on a side: the injector's
/// `denormalize(remap(..), space)` is `shown`'s pixel under the pointer,
/// offset from `space`'s corner (`remap_is_exact`).
#[must_use]
pub fn remap(x: u16, y: u16, shown: Rect, space: Rect) -> (u16, u16) {
    (
        remap_axis(x, shown.x, shown.width, space.x, space.width),
        remap_axis(y, shown.y, shown.height, space.y, space.height),
    )
}

/// [`remap`] along one axis.
fn remap_axis(v: u16, shown_at: i32, shown_len: u32, space_at: i32, space_len: u32) -> u16 {
    if space_len <= 1 {
        return 0;
    }
    let pixel = i64::from(shown_at) - i64::from(space_at) + i64::from(denormalize(v, shown_len));
    let pixel = pixel.clamp(0, i64::from(space_len - 1));
    normalize_pixel(u32::try_from(pixel).unwrap_or(0), space_len)
}

/// A position normalized over a picture that shows `space` whole, as the same
/// pixel normalized over `space`: what a desktop sink does before any
/// retarget. The picture then shows the whole even part of the desktop
/// (decision M1-74), so the odd last column or row, which no picture shows,
/// is never reached (SLICE-C1 C1-2).
pub(crate) fn over_even_part(x: u16, y: u16, space: Rect) -> (u16, u16) {
    let shown = Rect::new(space.x, space.y, space.width & !1, space.height & !1);
    remap(x, y, shown, space)
}

/// Pixel `pos` of `0..size` as the normalized `0..=65535` the injectors take,
/// rounded to the nearest: the integer counterpart of [`normalize`], so the
/// host's mapping uses no floating point.
pub(crate) fn normalize_pixel(pos: u32, size: u32) -> u16 {
    if size <= 1 {
        return 0;
    }
    let last = u64::from(size - 1);
    let n = (u64::from(pos).min(last) * 65_535 + last / 2) / last;
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// Maps the viewer's pointer onto what the picture shows, in front of an
/// injector that addresses a whole space (decision M1-75; this replaces the
/// SLICE-C1 C1-2 crop mapping, since the picture now shows the whole even
/// part of what capture grabbed).
///
/// Without a view it passes every event through. With a [`View::Rect`] it
/// rewrites each [`InputEvent::PointerMove`] with [`remap`]; other events
/// carry no position and pass unchanged. A [`View::Stream`] is the inner
/// sink's to map, so nothing is rewritten.
///
/// A view is kept only once the inner sink took it. After a refused
/// [`InputSink::retarget`] the picture shows what no view here describes, and
/// the host's pointer is on no screen the viewer was shown, so every event
/// that acts where the pointer is ([`InputEvent::lands_at_pointer`]: moves,
/// wheel turns, presses) is refused until a retarget succeeds; keys and
/// releases still go, so nothing stays held.
pub struct Viewport<S: InputSink> {
    inner: S,
    target: Target,
}

/// What a [`Viewport`] maps onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// Never retargeted: positions pass through.
    Whole,
    /// The view the inner sink last took.
    View(View),
    /// The last retarget was refused.
    Lost,
}

impl<S: InputSink> Viewport<S> {
    /// A viewport with no view in front of `inner`.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            target: Target::Whole,
        }
    }

    /// The view moves are mapped onto, if one was taken and still holds.
    #[must_use]
    pub fn view(&self) -> Option<&View> {
        match &self.target {
            Target::View(view) => Some(view),
            Target::Whole | Target::Lost => None,
        }
    }

    /// Why a [`View::Rect`] cannot be mapped onto, if it cannot.
    fn check(shown: &Rect, space: &Rect) -> Result<(), InputError> {
        if shown.width == 0 || shown.height == 0 || space.width == 0 || space.height == 0 {
            return Err(InputError::BadView("an empty rectangle"));
        }
        if space.width > MAX_SPACE || space.height > MAX_SPACE {
            return Err(InputError::BadView(
                "the desktop is wider or taller than 65536 pixels",
            ));
        }
        if !space.contains(shown) {
            return Err(InputError::BadView(
                "the picture shows a rectangle outside the desktop",
            ));
        }
        Ok(())
    }
}

impl<S: InputSink> InputSink for Viewport<S> {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        match (self.target, *event) {
            (Target::View(View::Rect { shown, space }), InputEvent::PointerMove { x, y }) => {
                let (x, y) = remap(x, y, shown, space);
                self.inner.inject(&InputEvent::PointerMove { x, y })
            }
            (Target::Lost, event) if event.lands_at_pointer() => Err(InputError::Inject(
                "the pointer could not follow the picture to its screen".to_owned(),
            )),
            _ => self.inner.inject(event),
        }
    }

    fn retarget(&mut self, view: &View) -> Result<(), InputError> {
        let taken = match view {
            View::Rect { shown, space } => Self::check(shown, space),
            View::Stream { .. } => Ok(()),
        }
        .and_then(|()| self.inner.retarget(view));
        self.target = match taken {
            Ok(()) => Target::View(*view),
            Err(_) => Target::Lost,
        };
        taken
    }
}

/// Pixel `pos` of a `size`-pixel axis of the Windows virtual desktop, as the
/// coordinate `SendInput` takes with `MOUSEEVENTF_ABSOLUTE |
/// MOUSEEVENTF_VIRTUALDESK`.
///
/// Windows does not document how it turns that coordinate into a pixel. Both
/// Microsoft's UI Automation proxies and Chromium encode for `pixel =
/// floor(d · size / 65536)`, a cell of `65536 / size` per pixel, not for the
/// `0 = first, 65535 = last` scale [`denormalize`] inverts, which under that
/// rule lands a pixel near the left or top one short, onto the neighbouring
/// monitor at a seam (`docs/research/monitors.md` §2). This takes the centre of
/// the pixel's cell, rounded so that the rule gives `pos` back for every size
/// up to 65 535 and for every pixel of 65 536 but the first; it is never 0,
/// which Windows 10 1709 and later no longer move the pointer to.
#[cfg(any(windows, test))]
pub(crate) fn virtual_desk_coordinate(pos: u32, size: u32) -> i32 {
    let size = u64::from(size.max(1));
    let pos = u64::from(pos).min(size - 1);
    let centre = ((2 * pos + 1) * 32_768 + (size - 1) / 2) / size;
    i32::try_from(centre.clamp(1, 65_535)).unwrap_or(65_535)
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

    /// Where a position lands on the desktop: what `remap` gives, placed
    /// over `space` as a desktop injector places it.
    fn lands(x: u16, y: u16, shown: Rect, space: Rect) -> (i64, i64) {
        let (x, y) = remap(x, y, shown, space);
        (
            i64::from(space.x) + i64::from(denormalize(x, space.width)),
            i64::from(space.y) + i64::from(denormalize(y, space.height)),
        )
    }

    /// Decision M1-75: a position normalized over the picture lands on the
    /// pixel of the shown rectangle under the viewer's pointer, in the
    /// desktop's own coordinates, whatever part of the space that is.
    #[test]
    fn a_position_lands_on_the_screen_the_picture_shows() {
        // Two screens side by side, 1280×720 (main) and 1024×768.
        let space = Rect::new(0, 0, 2304, 768);
        let second = Rect::new(1280, 0, 1024, 768);
        assert_eq!(lands(0, 0, second, space), (1280, 0));
        assert_eq!(lands(65535, 65535, second, space), (2303, 767));
        assert_eq!(lands(32768, 32768, second, space), (1280 + 512, 384));
        let first = Rect::new(0, 0, 1280, 720);
        assert_eq!(lands(65535, 65535, first, space), (1279, 719));
        // A Windows monitor left of the primary has negative coordinates;
        // the virtual desktop starts at its left edge.
        let space = Rect::new(-1920, 0, 1920 + 2560, 1440);
        let left = Rect::new(-1920, 0, 1920, 1080);
        let primary = Rect::new(0, 0, 2560, 1440);
        assert_eq!(lands(0, 0, primary, space), (0, 0));
        assert_eq!(lands(65535, 65535, primary, space), (2559, 1439));
        assert_eq!(lands(0, 0, left, space), (-1920, 0));
        assert_eq!(lands(65535, 65535, left, space), (-1, 1079));
    }

    /// The property the SLICE-C1 C1-2 crop mapping protected, kept by
    /// `remap` (decision M1-75): nothing outside what the picture shows can
    /// be addressed. The picture shows the whole even part of the desktop,
    /// scaled down when it is large (decision M1-74).
    #[test]
    fn a_position_never_leaves_the_shown_rectangle() {
        let whole = |w, h| Rect::new(0, 0, w, h);
        let even = |w: u32, h: u32| Rect::new(0, 0, w & !1, h & !1);
        // Two 4K screens shown together: the far corner is the right screen's,
        // the middle the seam.
        let space = whole(7680, 2160);
        assert_eq!(lands(65535, 65535, even(7680, 2160), space), (7679, 2159));
        assert_eq!(lands(0, 0, even(7680, 2160), space), (0, 0));
        assert_eq!(lands(32768, 0, even(7680, 2160), space), (3840, 0));
        // An upright screen is shown whole: its bottom row is in reach.
        for (w, h) in [(1440, 2560), (2160, 3840), (2400, 4000)] {
            let far = (i64::from(w) - 1, i64::from(h) - 1);
            assert_eq!(lands(65535, 65535, even(w, h), whole(w, h)), far);
        }
        // An odd desktop loses its last column and row, as the picture does.
        assert_eq!(
            lands(65535, 65535, even(1921, 1081), whole(1921, 1081)),
            (1919, 1079)
        );
        assert_eq!(
            lands(65535, 65535, even(2401, 3001), whole(2401, 3001)),
            (2399, 2999)
        );
        // A rectangle smaller than the space still bounds the pointer.
        let half = Rect::new(0, 0, 3840, 2160);
        assert_eq!(lands(65535, 65535, half, space), (3839, 2159));
        // A rectangle reaching past the space (which a `Viewport` refuses) is
        // clamped into it.
        let past = Rect::new(1000, 500, 4000, 4000);
        assert_eq!(lands(65535, 65535, past, whole(1920, 1080)), (1919, 1079));
        let past = Rect::new(0, 0, 4000, 4000);
        assert_eq!(lands(65535, 65535, past, whole(800, 600)), (799, 599));
        // A space of one pixel has only that pixel.
        assert_eq!(remap(65535, 65535, whole(1, 1), whole(1, 1)), (0, 0));
    }

    /// Before any retarget a desktop sink places a position over the whole
    /// even part of its space, as the picture shows it (decision M1-74): the
    /// odd last column and row are never reached.
    #[test]
    fn without_a_view_a_position_stays_on_the_even_part() {
        let placed = |x, y, space: Rect| {
            let (x, y) = over_even_part(x, y, space);
            (denormalize(x, space.width), denormalize(y, space.height))
        };
        let odd = Rect::new(-1921, 0, 1921 + 2560, 1081);
        assert_eq!(placed(65535, 65535, odd), (4479, 1079));
        assert_eq!(placed(0, 0, odd), (0, 0));
        let even = Rect::new(0, 0, 1280, 720);
        assert_eq!(placed(65535, 65535, even), (1279, 719));
        assert_eq!(placed(32768, 32768, even), (640, 360));
        // Degenerate spaces have only their first pixel.
        assert_eq!(placed(65535, 65535, Rect::new(0, 0, 1, 1)), (0, 0));
        assert_eq!(placed(65535, 65535, Rect::new(0, 0, 0, 0)), (0, 0));
        for width in 1..300 {
            let space = Rect::new(0, 0, width, 1);
            assert_eq!(
                placed(65535, 0, space).0,
                (width & !1).saturating_sub(1),
                "{width}"
            );
        }
    }

    #[test]
    fn rectangles_contain_and_overlap() {
        let space = Rect::new(-1920, 0, 4480, 1440);
        assert!(space.contains(&Rect::new(-1920, 0, 1920, 1080)));
        assert!(space.contains(&space));
        assert!(!space.contains(&Rect::new(-1921, 0, 10, 10)));
        assert!(!space.contains(&Rect::new(2550, 0, 11, 10)));
        assert!(!space.contains(&Rect::new(0, 1439, 10, 2)));
        let primary = Rect::new(0, 0, 2560, 1440);
        let left = Rect::new(-1920, 0, 1920, 1080);
        assert_eq!(primary.area_overlap(&left), 0, "touching edges");
        assert_eq!(
            Rect::new(-100, -100, 200, 200).area_overlap(&primary),
            100 * 100
        );
        assert_eq!(primary.area_overlap(&primary), 2560 * 1440);
        assert_eq!(primary.area_overlap(&Rect::new(5000, 5000, 1, 1)), 0);
        let huge = Rect::new(i32::MIN, i32::MIN, u32::MAX, u32::MAX);
        assert_eq!(huge.area_overlap(&huge), u64::from(u32::MAX).pow(2));
    }

    /// Records what reaches it, takes or refuses views, and remembers them.
    #[derive(Default)]
    struct Log {
        seen: Vec<InputEvent>,
        views: Vec<View>,
        refuse_views: bool,
    }

    impl InputSink for Log {
        fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
            self.seen.push(*event);
            Ok(())
        }

        fn retarget(&mut self, view: &View) -> Result<(), InputError> {
            if self.refuse_views {
                return Err(InputError::Inject("no".to_owned()));
            }
            self.views.push(*view);
            Ok(())
        }
    }

    const SPACE: Rect = Rect::new(0, 0, 2304, 768);
    const SECOND: Rect = Rect::new(1280, 0, 1024, 768);
    const ON_SECOND: View = View::Rect {
        shown: SECOND,
        space: SPACE,
    };
    const STREAM: View = View::Stream {
        node: 42,
        pixels: (1920, 1080),
        ratio: None,
    };

    fn others() -> [InputEvent; 4] {
        [
            InputEvent::PointerButton {
                button: Button::Left,
                pressed: true,
            },
            InputEvent::Wheel { dx: 0, dy: 120 },
            InputEvent::Key {
                usb: 0x07_0004,
                pressed: true,
            },
            InputEvent::ReleaseAll,
        ]
    }

    #[test]
    fn a_viewport_rewrites_moves_only_and_only_under_a_rect_view() {
        let corner = InputEvent::PointerMove { x: 65535, y: 65535 };
        // No view: everything passes as it came.
        let mut viewport = Viewport::new(Log::default());
        assert_eq!(viewport.view(), None);
        viewport.inject(&corner).unwrap();
        for event in others() {
            viewport.inject(&event).unwrap();
        }
        let mut want = vec![corner];
        want.extend(others());
        assert_eq!(viewport.inner.seen, want);

        // Onto the second screen: the move is rewritten onto its corner, and
        // nothing else changes.
        let mut viewport = Viewport::new(Log::default());
        viewport.retarget(&ON_SECOND).unwrap();
        assert_eq!(viewport.inner.views, [ON_SECOND], "the inner sink is told");
        assert_eq!(viewport.view(), Some(&ON_SECOND));
        viewport.inject(&corner).unwrap();
        for event in others() {
            viewport.inject(&event).unwrap();
        }
        let InputEvent::PointerMove { x, y } = viewport.inner.seen[0] else {
            panic!("{:?}", viewport.inner.seen[0]);
        };
        assert_eq!((denormalize(x, 2304), denormalize(y, 768)), (2303, 767));
        assert_eq!(viewport.inner.seen[1..], others());

        // A stream is the inner sink's to map: forwarded, kept, not rewritten.
        let mut viewport = Viewport::new(Log::default());
        viewport.retarget(&STREAM).unwrap();
        assert_eq!(viewport.inner.views, [STREAM]);
        assert_eq!(viewport.view(), Some(&STREAM));
        viewport.inject(&corner).unwrap();
        assert_eq!(viewport.inner.seen, [corner]);
    }

    /// Everything a viewer sends, a release of each kind included.
    fn every_kind() -> [InputEvent; 7] {
        [
            InputEvent::PointerMove { x: 1, y: 1 },
            InputEvent::PointerButton {
                button: Button::Left,
                pressed: true,
            },
            InputEvent::Wheel { dx: 0, dy: 120 },
            InputEvent::PointerButton {
                button: Button::Left,
                pressed: false,
            },
            InputEvent::Key {
                usb: 0x07_0004,
                pressed: true,
            },
            InputEvent::Key {
                usb: 0x07_0004,
                pressed: false,
            },
            InputEvent::ReleaseAll,
        ]
    }

    /// After a refused retarget: what acts where the pointer is (a move, a
    /// wheel turn, a press) is refused, since the host's pointer is on no
    /// screen the viewer was shown; keys and releases go. What reached
    /// `sink` is exactly the latter.
    fn only_keys_and_releases_go<S: InputSink>(
        viewport: &mut Viewport<S>,
        seen: impl Fn(&S) -> Vec<InputEvent>,
    ) {
        for event in every_kind() {
            let sent = viewport.inject(&event);
            assert_eq!(
                sent.is_err(),
                event.lands_at_pointer(),
                "{event:?}: {sent:?}"
            );
        }
        let kept: Vec<_> = every_kind()
            .into_iter()
            .filter(|event| !event.lands_at_pointer())
            .collect();
        assert_eq!(
            seen(&viewport.inner),
            kept,
            "no move, wheel or press reached the sink"
        );
    }

    /// A view no position can be mapped onto is refused before the inner
    /// sink hears of it, and so is one the inner sink refuses. Neither is
    /// kept, and the view before it is dropped too, since the picture no
    /// longer shows it: moves, wheel turns and presses are refused until a
    /// retarget succeeds, while keys and releases still go.
    #[test]
    fn a_viewport_keeps_no_view_it_or_its_sink_refused() {
        let bad = [
            (Rect::new(1281, 0, 1024, 768), SPACE),
            (Rect::new(1280, -1, 1024, 768), SPACE),
            (Rect::new(-4, 0, 8, 8), SPACE),
            (Rect::new(0, 0, 0, 768), SPACE),
            (Rect::new(0, 0, 8, 0), SPACE),
            (Rect::new(0, 0, 8, 8), Rect::new(0, 0, 0, 0)),
            (Rect::new(0, 0, 8, 8), Rect::new(0, 0, MAX_SPACE + 1, 8)),
            (Rect::new(0, 0, 8, 8), Rect::new(0, 0, 8, MAX_SPACE + 1)),
        ];
        for (shown, space) in bad {
            let mut viewport = Viewport::new(Log::default());
            viewport.retarget(&ON_SECOND).unwrap();
            let refused = viewport.retarget(&View::Rect { shown, space });
            assert!(
                matches!(refused, Err(InputError::BadView(_))),
                "{shown:?} in {space:?}: {refused:?}"
            );
            assert_eq!(viewport.inner.views, [ON_SECOND], "never forwarded");
            assert_eq!(viewport.view(), None, "{shown:?} in {space:?}");
            only_keys_and_releases_go(&mut viewport, |log| log.seen.clone());
        }
        // The largest space there is maps.
        let mut viewport = Viewport::new(Log::default());
        let largest = Rect::new(0, 0, MAX_SPACE, MAX_SPACE);
        viewport
            .retarget(&View::Rect {
                shown: largest,
                space: largest,
            })
            .unwrap();

        // The inner sink refuses: not kept either.
        let mut viewport = Viewport::new(Log::default());
        viewport.retarget(&ON_SECOND).unwrap();
        viewport.inner.refuse_views = true;
        let first = View::Rect {
            shown: Rect::new(0, 0, 1280, 720),
            space: SPACE,
        };
        assert!(viewport.retarget(&first).is_err());
        assert_eq!(viewport.view(), None);
        // Not mapped onto the second screen any more, and no click there.
        only_keys_and_releases_go(&mut viewport, |log| log.seen.clone());
        // Taken the next time: moves map again, and presses go.
        viewport.inner.refuse_views = false;
        viewport.inner.seen.clear();
        viewport.retarget(&first).unwrap();
        assert_eq!(viewport.view(), Some(&first));
        viewport
            .inject(&InputEvent::PointerMove { x: 65535, y: 65535 })
            .unwrap();
        let InputEvent::PointerMove { x, y } = viewport.inner.seen[0] else {
            panic!("{:?}", viewport.inner.seen);
        };
        assert_eq!((denormalize(x, 2304), denormalize(y, 768)), (1279, 719));
        let press = InputEvent::PointerButton {
            button: Button::Left,
            pressed: true,
        };
        viewport.inject(&press).unwrap();
        assert_eq!(viewport.inner.seen[1..], [press]);
    }

    /// Takes every view and shares what it took.
    struct Shares(std::sync::Arc<std::sync::Mutex<Vec<View>>>);

    impl InputSink for Shares {
        fn inject(&mut self, _: &InputEvent) -> Result<(), InputError> {
            Ok(())
        }

        fn retarget(&mut self, view: &View) -> Result<(), InputError> {
            self.0.lock().unwrap().push(*view);
            Ok(())
        }
    }

    /// A boxed sink forwards a retarget, so a wrapper over one (the host's
    /// injector chain) hands every view to the sink inside and hears its
    /// refusal, rather than the trait's default taking any rectangle.
    #[test]
    fn a_boxed_sink_forwards_the_view_and_its_refusal() {
        let mut boxed: Box<dyn InputSink> = Box::new(Log::default());
        boxed.retarget(&ON_SECOND).unwrap();
        boxed.inject(&InputEvent::ReleaseAll).unwrap();

        // A sink that refuses every view, as the Wayland injector does, seen
        // through the host's chain: the refusal reaches the caller and the
        // viewport keeps nothing.
        let refusing: Box<dyn InputSink> = Box::new(Log {
            refuse_views: true,
            ..Log::default()
        });
        let mut chain = Tracked::new(Viewport::new(refusing));
        assert!(chain.retarget(&ON_SECOND).is_err());
        assert_eq!(chain.inner.view(), None);
        assert!(
            chain
                .inject(&InputEvent::PointerMove { x: 1, y: 1 })
                .is_err()
        );

        // One that takes it: the view reaches the sink inside the box.
        let views = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let taking: Box<dyn InputSink> = Box::new(Shares(std::sync::Arc::clone(&views)));
        let mut chain = Tracked::new(Viewport::new(taking));
        chain.retarget(&ON_SECOND).unwrap();
        chain.retarget(&STREAM).unwrap();
        assert_eq!(*views.lock().unwrap(), [ON_SECOND, STREAM]);
    }

    /// The default `retarget`, for a sink that addresses a whole space behind
    /// a `Viewport`: it takes any rectangle and refuses a stream.
    #[test]
    fn the_default_retarget_takes_a_rect_and_refuses_a_stream() {
        let mut sink = Recorder(Vec::new());
        sink.retarget(&ON_SECOND).unwrap();
        assert!(matches!(
            sink.retarget(&STREAM),
            Err(InputError::Inject(why)) if why.contains("cannot follow")
        ));
        let mut viewport = Viewport::new(Recorder(Vec::new()));
        assert!(viewport.retarget(&STREAM).is_err());
        assert_eq!(viewport.view(), None);
    }

    /// Decision M1-75: no drag carries over to another screen. A retarget
    /// first sends what is owed, then lets go of every held button, and only
    /// then moves the injector; held keys stay down, so a modifier survives.
    #[test]
    fn a_retarget_lets_go_of_buttons_and_keeps_keys() {
        let ctrl = |pressed| InputEvent::Key {
            usb: 0x07_00e0,
            pressed,
        };
        let button = |button, pressed| InputEvent::PointerButton { button, pressed };
        let mut t = Tracked::new(Log::default());
        t.inject(&ctrl(true)).unwrap();
        t.inject(&button(Button::Right, true)).unwrap();
        t.inject(&button(Button::Left, true)).unwrap();
        t.retarget(&ON_SECOND).unwrap();
        assert_eq!(t.inner.views, [ON_SECOND]);
        assert_eq!(
            t.inner.seen[3..],
            [button(Button::Left, false), button(Button::Right, false)]
        );
        // The viewer's own button-up later is not sent twice; its Ctrl-up is.
        t.inject(&button(Button::Left, false)).unwrap();
        t.inject(&ctrl(false)).unwrap();
        assert_eq!(t.inner.seen[5..], [ctrl(false)]);

        // A release owed from before goes out first.
        let key = |pressed| InputEvent::Key {
            usb: 0x07_0004,
            pressed,
        };
        let mut t = Tracked::new(RefusesOneRelease::default());
        t.inject(&key(true)).unwrap();
        t.inject(&button(Button::Left, true)).unwrap();
        assert!(t.inject(&key(false)).is_err());
        t.retarget(&ON_SECOND).unwrap();
        assert_eq!(
            t.inner.seen,
            [
                key(true),
                button(Button::Left, true),
                key(false),
                button(Button::Left, false)
            ]
        );

        // A button-up the injector refuses during the retarget stays owed.
        let mut t = Tracked::new(Stalls::default());
        t.inject(&button(Button::Middle, true)).unwrap();
        t.inner.full = true;
        t.retarget(&ON_SECOND).unwrap();
        t.inner.full = false;
        let moved = InputEvent::PointerMove { x: 1, y: 2 };
        t.inject(&moved).unwrap();
        assert_eq!(
            t.inner.seen,
            [
                button(Button::Middle, true),
                button(Button::Middle, false),
                moved
            ]
        );

        // A refused retarget is the caller's to act on.
        let mut t = Tracked::new(Log {
            refuse_views: true,
            ..Log::default()
        });
        assert!(t.retarget(&ON_SECOND).is_err());
    }

    /// What the host holds back at its barrier (decision M1-75): what acts
    /// where the pointer is. Releases never are.
    #[test]
    fn moves_wheels_and_presses_land_at_the_pointer() {
        let lands = [
            InputEvent::PointerMove { x: 1, y: 2 },
            InputEvent::Wheel { dx: 0, dy: -120 },
            InputEvent::PointerButton {
                button: Button::Back,
                pressed: true,
            },
        ];
        let not = [
            InputEvent::PointerButton {
                button: Button::Back,
                pressed: false,
            },
            InputEvent::Key {
                usb: 0x07_0004,
                pressed: true,
            },
            InputEvent::Key {
                usb: 0x07_0004,
                pressed: false,
            },
            InputEvent::ReleaseAll,
        ];
        assert!(lands.iter().all(InputEvent::lands_at_pointer));
        assert!(!not.iter().any(InputEvent::lands_at_pointer));
    }

    /// The pixel Windows moves the pointer to for virtual-desk coordinate
    /// `d` on a `size`-pixel axis, under the rule Microsoft's UI Automation
    /// proxies and Chromium encode for (`docs/research/monitors.md` §2).
    pub(crate) fn windows_pixel(d: i32, size: u32) -> u32 {
        let d = u64::try_from(d).expect("a coordinate SendInput takes");
        u32::try_from(d * u64::from(size) / 65_536).unwrap()
    }

    /// Every pixel of a virtual desktop up to 65 535 wide is reached exactly
    /// under Windows' rule, and never through coordinate 0. Every width up to
    /// 4096 and the wide layouts below are checked whole here; every width up
    /// to 65 536 was checked whole once (docs/VERIFICATION.md).
    #[test]
    fn every_pixel_of_the_virtual_desk_is_reached() {
        let widths = (1..=4096).chain([
            4480, 7680, 12_400, 15_360, 17_408, 23_040, 32_767, 32_768, 32_769, 65_534, 65_535,
        ]);
        for size in widths {
            for pos in 0..size {
                let d = virtual_desk_coordinate(pos, size);
                assert!((1..=65_535).contains(&d), "{pos} of {size}: {d}");
                assert_eq!(windows_pixel(d, size), pos, "{pos} of {size}");
            }
        }
        // 65 536 wide: every pixel but the first, which only coordinate 0
        // reaches, and Windows no longer moves there; its neighbour is next.
        for pos in 1..MAX_SPACE {
            assert_eq!(
                windows_pixel(virtual_desk_coordinate(pos, MAX_SPACE), MAX_SPACE),
                pos
            );
        }
        assert_eq!(virtual_desk_coordinate(0, MAX_SPACE), 1);
        // Past the axis is its last pixel; an empty axis has only pixel 0.
        assert_eq!(
            windows_pixel(virtual_desk_coordinate(5000, 1920), 1920),
            1919
        );
        assert_eq!(windows_pixel(virtual_desk_coordinate(3, 0), 1), 0);
    }

    /// The rounding this replaces: `normalize_pixel`'s 0-to-65535 scale, which
    /// `denormalize` inverts, lands a pixel near the left edge one short under
    /// Windows' rule, so Screen 2's first column at a seam was Screen 1's
    /// last. The cases the review found, then the same seams through the
    /// whole chain (`remap` onto each monitor, the sink's coordinate), every
    /// column of every monitor of two wide layouts.
    #[test]
    fn a_seam_column_lands_on_its_own_monitor() {
        let old = |pos, size| windows_pixel(i32::from(normalize_pixel(pos, size)), size);
        assert_eq!(old(1280, 12_400), 1279, "1280 + 3440 + 7680");
        assert_eq!(old(1024, 17_408), 1023, "1024 + 1024 + 7680 + 7680");
        assert_eq!(old(2048, 17_408), 2047);
        for (pos, size) in [(1280, 12_400), (1024, 17_408), (2048, 17_408)] {
            assert_eq!(windows_pixel(virtual_desk_coordinate(pos, size), size), pos);
        }

        for widths in [&[1280, 3440, 7680][..], &[1024, 1024, 7680, 7680]] {
            // Side by side, the leftmost one left of the primary.
            let total: u32 = widths.iter().sum();
            let space = Rect::new(-i32::try_from(widths[0]).unwrap(), 0, total, 2160);
            let mut x = space.x;
            for &width in widths {
                let shown = Rect::new(x, 0, width, 2160);
                for column in 0..width {
                    let at = normalize_pixel(column, width);
                    let (sx, _) = remap(at, 0, shown, space);
                    let px = denormalize(sx, space.width);
                    let landed =
                        windows_pixel(virtual_desk_coordinate(px, space.width), space.width);
                    assert_eq!(
                        i64::from(space.x) + i64::from(landed),
                        i64::from(x) + i64::from(column),
                        "column {column} of the monitor at {x} in {widths:?}"
                    );
                }
                x += i32::try_from(width).unwrap();
            }
        }
    }

    /// The bounds of the exactness below: the largest spaces, every pixel.
    #[test]
    fn every_pixel_of_the_largest_spaces_survives_normalizing() {
        for size in [MAX_SPACE, MAX_SPACE - 1, MAX_SPACE - 2, 2, 1] {
            for pos in 0..size {
                assert_eq!(denormalize(normalize_pixel(pos, size), size), pos, "{size}");
                assert_eq!(
                    denormalize(normalize(f64::from(pos), f64::from(size)), size),
                    pos,
                    "{size}"
                );
            }
        }
    }

    mod props {
        use proptest::prelude::*;

        use super::super::{
            MAX_SPACE, Rect, denormalize, normalize, normalize_pixel, remap,
            virtual_desk_coordinate,
        };

        /// A space up to `MAX_SPACE` on a side and a non-empty rectangle
        /// inside it.
        fn shown_in_space() -> impl Strategy<Value = (Rect, Rect)> {
            (
                -1_000_000i32..1_000_000,
                -1_000_000i32..1_000_000,
                1u32..=MAX_SPACE,
                1u32..=MAX_SPACE,
            )
                .prop_flat_map(|(x, y, w, h)| (Just(Rect::new(x, y, w, h)), 0..w, 0..h))
                .prop_flat_map(|(space, dx, dy)| {
                    (
                        Just(space),
                        Just((dx, dy)),
                        1..=space.width - dx,
                        1..=space.height - dy,
                    )
                })
                .prop_map(|(space, (dx, dy), w, h)| {
                    let shown = Rect::new(
                        space.x + i32::try_from(dx).unwrap(),
                        space.y + i32::try_from(dy).unwrap(),
                        w,
                        h,
                    );
                    (shown, space)
                })
        }

        proptest! {
            /// Decision M1-75: through `remap`, an injector over `space`
            /// reaches exactly the pixel of `shown` the position points at.
            #[test]
            fn remap_is_exact((shown, space) in shown_in_space(), x: u16, y: u16) {
                prop_assert!(space.contains(&shown));
                let (rx, ry) = remap(x, y, shown, space);
                let want_x = i64::from(shown.x) - i64::from(space.x)
                    + i64::from(denormalize(x, shown.width));
                let want_y = i64::from(shown.y) - i64::from(space.y)
                    + i64::from(denormalize(y, shown.height));
                prop_assert_eq!(i64::from(denormalize(rx, space.width)), want_x);
                prop_assert_eq!(i64::from(denormalize(ry, space.height)), want_y);
            }

            /// Through the Windows sink's coordinate, `SendInput` reaches the
            /// pixel `remap` meant, under Windows' rule, on any virtual
            /// desktop up to 65 535 wide (the first pixel of a 65 536-wide
            /// one is the test above's).
            #[test]
            fn the_virtual_desk_reaches_the_shown_pixel(
                (shown, space) in shown_in_space(),
                x: u16,
            ) {
                prop_assume!(space.width < MAX_SPACE);
                let (rx, _) = remap(x, 0, shown, space);
                let px = denormalize(rx, space.width);
                let d = virtual_desk_coordinate(px, space.width);
                prop_assert!((1..=65_535).contains(&d));
                prop_assert_eq!(super::windows_pixel(d, space.width), px);
            }

            /// A pixel normalized over a space up to `MAX_SPACE` and placed
            /// again is the same pixel, by the host's integer mapping and by
            /// the viewer's floating-point one.
            #[test]
            fn a_pixel_survives_normalizing(size in 1u32..=MAX_SPACE, at in 0.0f64..1.0) {
                let pos = (f64::from(size - 1) * at) as u32;
                prop_assert_eq!(denormalize(normalize_pixel(pos, size), size), pos);
                prop_assert_eq!(
                    denormalize(normalize(f64::from(pos), f64::from(size)), size),
                    pos
                );
            }
        }
    }
}
