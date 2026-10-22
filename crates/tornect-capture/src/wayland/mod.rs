//! Wayland capture and input (`docs/research/slice.md` §4): one RemoteDesktop
//! portal session casts a monitor through PipeWire and takes the viewer's
//! keyboard and pointer, under one consent dialog on the desktop.
//!
//! - [`WaylandSource`] is the [`VideoSource`]. The compositor sends a picture
//!   only when the screen changes, so `next_frame` answers `Ok(None)` when
//!   nothing new came within its timeout; the cursor is drawn into the picture
//!   by the compositor.
//! - [`WaylandInjector`] is the `InputSink`, built from the [`WaylandInput`]
//!   the source hands out. It maps the viewer's pointer over the part of the
//!   picture the encoder sends, never over the whole desktop (SLICE-C1 C1-2),
//!   and speaks evdev codes to the portal's `Notify*` methods.
//! - The session's restore token, kept in a 0600 file, lets later sessions
//!   start without the dialog until the user revokes the permission.
//!
//! Built for LP64 Linux only: the PipeWire structures are mirrored for it.

mod pipewire;
mod portal;

use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tornect_input::{
    Button, InputError, InputEvent, InputSink, WheelAccumulator, denormalize, keymap,
};

use self::pipewire::{PwCapture, Shared};
pub use self::portal::Bus;
use self::portal::{Call, Portal, ScrollAxis, Setup};
use crate::{CaptureError, Frame, VideoSource};

/// How long [`WaylandOptions::new`] gives the user to answer the dialog: about
/// what `tornect connect` waits for the host's first picture.
pub const DIALOG_WAIT: Duration = Duration::from_secs(30);

/// How long PipeWire may take, once the portal has started, to agree on a
/// picture format.
const NEGOTIATE_WAIT: Duration = Duration::from_secs(10);

/// How a [`WaylandSource`] is opened.
#[derive(Debug, Clone)]
pub struct WaylandOptions {
    /// Where the portal's restore token is kept (a 0600 file). `None` keeps
    /// nothing: the desktop asks at every session.
    pub restore_token: Option<PathBuf>,
    /// How long the user has to answer the desktop's dialog.
    pub dialog_wait: Duration,
    /// The D-Bus the portal is reached on.
    pub bus: Bus,
    /// Turns `true` when the session the source is for ends before the open
    /// does: the portal session is closed, which takes its dialog down, and no
    /// restore token is kept for it.
    pub cancel: Option<tokio::sync::watch::Receiver<bool>>,
}

impl WaylandOptions {
    /// The session bus and [`DIALOG_WAIT`], keeping the token in
    /// `restore_token`.
    #[must_use]
    pub fn new(restore_token: Option<PathBuf>) -> Self {
        Self {
            restore_token,
            dialog_wait: DIALOG_WAIT,
            bus: Bus::Session,
            cancel: None,
        }
    }
}

/// The desktop as the RemoteDesktop portal shares it.
pub struct WaylandSource {
    // Declared first, so it is dropped first: the stream ends before the
    // portal session does.
    capture: PwCapture,
    portal: Arc<Portal>,
}

impl std::fmt::Debug for WaylandSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WaylandSource")
            .field("size", &self.capture.shared().pixel_size())
            .field("portal", &self.portal)
            .finish_non_exhaustive()
    }
}

impl WaylandSource {
    /// Start a portal session and its PipeWire stream. Unless the stored
    /// restore token still holds, this shows the desktop's dialog and blocks
    /// until the user answers or `options.dialog_wait` runs out.
    ///
    /// Returns the source and what an injector for the same session is built
    /// from. Nothing is shown to the user when PipeWire cannot be loaded.
    pub fn open(options: &WaylandOptions) -> Result<(Self, WaylandInput), CaptureError> {
        // A machine that could not show the stream is refused before any dialog.
        pipewire::api()?;
        let (portal, opened) = Portal::open(Setup {
            bus: options.bus.clone(),
            token_file: options.restore_token.clone(),
            dialog_wait: options.dialog_wait,
            cancel: options.cancel.clone(),
        })?;
        let portal = Arc::new(portal);
        let capture = PwCapture::connect(opened.fd, opened.node_id)?;
        let format = capture.shared().wait_negotiated(NEGOTIATE_WAIT)?;
        tracing::info!(
            node = opened.node_id,
            width = format.width,
            height = format.height,
            logical = ?opened.logical,
            input = opened.input,
            "Wayland screen cast negotiated"
        );
        let input = WaylandInput {
            portal: Arc::downgrade(&portal),
            shared: Arc::clone(capture.shared()),
            logical: opened.logical,
            granted: opened.input,
        };
        Ok((Self { capture, portal }, input))
    }
}

/// What [`grant`] got from the desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Granted {
    /// Keyboard and pointer were granted too (the dialog's remote-interaction
    /// switch was on). Without them a session shares the screen and injects
    /// nothing.
    pub input: bool,
    /// The desktop returned a restore token, and it is kept in the options'
    /// file: later sessions start without the dialog.
    pub remembered: bool,
}

/// The first-run setup step (the operator's decision of 2026-09-23): ask the
/// desktop now, with its owner at the desk, for the grant a shared session
/// needs, keep the restore token it returns, and close the session at once.
///
/// It opens the same portal session a shared session does (keyboard, pointer
/// and one monitor, persisted until revoked), so the token restores exactly
/// what a session asks for, and a later session never shows the dialog inside
/// a viewer's wait. Deleting the token file revokes the grant, as before.
/// Blocks until the dialog is answered or `options.dialog_wait` runs out.
/// Nothing is shown when PipeWire cannot be loaded, since no session could
/// use the grant.
pub fn grant(options: &WaylandOptions) -> Result<Granted, CaptureError> {
    pipewire::api()?;
    let (portal, opened) = Portal::open(Setup {
        bus: options.bus.clone(),
        token_file: options.restore_token.clone(),
        dialog_wait: options.dialog_wait,
        cancel: options.cancel.clone(),
    })?;
    let input = opened.input;
    // The PipeWire remote goes first, then the session: no picture is taken.
    drop(opened);
    drop(portal);
    let remembered = options
        .restore_token
        .as_deref()
        .is_some_and(|file| portal::read_token(file).is_some());
    tracing::info!(
        input,
        remembered,
        "the desktop's screen-sharing grant was asked for ahead of any session"
    );
    Ok(Granted { input, remembered })
}

impl VideoSource for WaylandSource {
    fn name(&self) -> &'static str {
        "wayland"
    }

    /// The newest picture since the last call, waiting at most `timeout`;
    /// `Ok(None)` if the screen did not change meanwhile.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        if self.portal.is_over() {
            return Err(CaptureError::Failed(
                "the desktop ended the screen-sharing session".to_owned(),
            ));
        }
        self.capture.shared().next(timeout)
    }
}

/// What an injector for a [`WaylandSource`]'s session is built from. It holds
/// the session only weakly: once the source is gone, no injector can be built.
pub struct WaylandInput {
    portal: Weak<Portal>,
    shared: Arc<Shared>,
    logical: Option<(u32, u32)>,
    granted: bool,
}

impl std::fmt::Debug for WaylandInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WaylandInput")
            .field("logical", &self.logical)
            .field("granted", &self.granted)
            .finish_non_exhaustive()
    }
}

impl WaylandInput {
    /// An injector into the source's session. `region` gives, for a picture of
    /// the source's size, the part the encoder sends (its top-left crop); the
    /// viewer's pointer is mapped over that part, which is exactly what the
    /// viewer sees, even when the desktop is larger than the encoder allows.
    ///
    /// Refused when the source is gone, when the desktop did not grant input
    /// (the dialog's remote-control switch), or when the portal gave no
    /// logical size, without which no position could be placed exactly.
    pub fn injector(
        &self,
        region: fn(u32, u32) -> (u32, u32),
    ) -> Result<WaylandInjector, CaptureError> {
        let portal = self
            .portal
            .upgrade()
            .filter(|p| !p.is_over())
            .ok_or_else(|| {
                CaptureError::Unavailable("the screen-sharing session has ended".to_owned())
            })?;
        if !self.granted {
            return Err(CaptureError::Unavailable(
                "the desktop did not allow remote control (the dialog's remote interaction \
                 switch was off)"
                    .to_owned(),
            ));
        }
        let logical = self.logical.ok_or_else(|| {
            CaptureError::Unavailable(
                "the portal gave no logical size for the screen, so pointer positions cannot be \
                 placed exactly"
                    .to_owned(),
            )
        })?;
        let pixels = self.shared.pixel_size().ok_or_else(|| {
            CaptureError::Unavailable("no picture size has been negotiated".to_owned())
        })?;
        let map = PointerMap::new(logical, pixels).ok_or_else(|| {
            CaptureError::Unavailable(format!(
                "cannot map a {}x{} picture onto a {}x{} logical screen",
                pixels.0, pixels.1, logical.0, logical.1
            ))
        })?;
        Ok(WaylandInjector {
            portal,
            shared: Arc::clone(&self.shared),
            map,
            region,
            wheel: WheelAccumulator::default(),
        })
    }
}

/// Injects the viewer's input into the portal session (`Notify*`, evdev codes).
///
/// It never blocks: each event is queued for the portal's own thread, which
/// makes the D-Bus calls in order. Wrap it in `tornect_input::Tracked`, which
/// releases held keys and buttons when the session ends. When the last handle
/// goes, the thread drops what is still queued and lets go of what its own
/// calls hold down, since a stalled portal can refuse those releases.
pub struct WaylandInjector {
    portal: Arc<Portal>,
    shared: Arc<Shared>,
    map: PointerMap,
    region: fn(u32, u32) -> (u32, u32),
    wheel: WheelAccumulator,
}

impl std::fmt::Debug for WaylandInjector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WaylandInjector")
            .field("map", &self.map)
            .finish_non_exhaustive()
    }
}

impl InputSink for WaylandInjector {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        let (map, region) = (self.map, self.region);
        let pixels = self.shared.pixel_size();
        let calls = translate(event, &mut self.wheel, |x, y| {
            map.place(x, y, pixels?, region)
        })?;
        for call in calls.into_iter().flatten() {
            self.portal.send(call)?;
        }
        Ok(())
    }
}

/// From the viewer's normalized pointer position to the portal's logical
/// coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
struct PointerMap {
    /// Logical units per pixel, measured when the injector was built. A mode
    /// change alters pixels and logical units alike, so the ratio holds.
    scale_x: f64,
    scale_y: f64,
}

impl PointerMap {
    fn new(logical: (u32, u32), pixels: (u32, u32)) -> Option<Self> {
        if logical.0 == 0 || logical.1 == 0 || pixels.0 == 0 || pixels.1 == 0 {
            return None;
        }
        Some(Self {
            scale_x: f64::from(logical.0) / f64::from(pixels.0),
            scale_y: f64::from(logical.1) / f64::from(pixels.1),
        })
    }

    /// Where `(x, y)`, normalized over the encoded region of a `pixels`-sized
    /// picture, lies in logical coordinates. The region is the picture's
    /// top-left `region(pixels)`; the result stays strictly inside the screen's
    /// logical size (`0 <= x < width`), as the portal requires.
    fn place(
        &self,
        x: u16,
        y: u16,
        pixels: (u32, u32),
        region: fn(u32, u32) -> (u32, u32),
    ) -> Option<(f64, f64)> {
        let (width, height) = region(pixels.0, pixels.1);
        let (width, height) = (width.min(pixels.0), height.min(pixels.1));
        if width == 0 || height == 0 {
            return None;
        }
        let px = denormalize(x, width);
        let py = denormalize(y, height);
        Some((f64::from(px) * self.scale_x, f64::from(py) * self.scale_y))
    }
}

/// The evdev code of a pointer button (`linux/input-event-codes.h`).
const fn evdev_button(button: Button) -> i32 {
    match button {
        Button::Left => 0x110,    // BTN_LEFT
        Button::Right => 0x111,   // BTN_RIGHT
        Button::Middle => 0x112,  // BTN_MIDDLE
        Button::Back => 0x113,    // BTN_SIDE
        Button::Forward => 0x114, // BTN_EXTRA
    }
}

/// The evdev code of a key, by its USB usage.
fn evdev_key(usb: u32) -> Result<i32, InputError> {
    match keymap::by_usb(usb) {
        Some(key) if key.evdev != 0 => Ok(i32::from(key.evdev)),
        _ => Err(InputError::UnknownKey(usb)),
    }
}

/// The portal calls one event becomes. `place` maps a normalized pointer
/// position to logical coordinates (`None` when it cannot).
fn translate(
    event: &InputEvent,
    wheel: &mut WheelAccumulator,
    place: impl FnOnce(u16, u16) -> Option<(f64, f64)>,
) -> Result<[Option<Call>; 2], InputError> {
    Ok(match *event {
        InputEvent::PointerMove { x, y } => {
            let (x, y) = place(x, y).ok_or_else(|| {
                InputError::Inject("the picture's size is not known yet".to_owned())
            })?;
            [Some(Call::Motion { x, y }), None]
        }
        InputEvent::PointerButton { button, pressed } => [
            Some(Call::Button {
                code: evdev_button(button),
                pressed,
            }),
            None,
        ],
        InputEvent::Wheel { dx, dy } => {
            // Whole notches only; the discrete axis takes no zero step. The
            // wire's positive dy is up, the portal's positive steps go down
            // (mutter `meta-remote-desktop-session.c` 912–956).
            let (nx, ny) = wheel.add(dx, dy);
            [
                (ny != 0).then_some(Call::Scroll {
                    axis: ScrollAxis::Vertical,
                    steps: ny.saturating_neg(),
                }),
                (nx != 0).then_some(Call::Scroll {
                    axis: ScrollAxis::Horizontal,
                    steps: nx,
                }),
            ]
        }
        InputEvent::Key { usb, pressed } => [
            Some(Call::Key {
                code: evdev_key(usb)?,
                pressed,
            }),
            None,
        ],
        // `Tracked` turns this into releases before it reaches a sink.
        InputEvent::ReleaseAll => [None, None],
    })
}

#[cfg(test)]
#[allow(clippy::print_stderr)] // the live test reports what it saw
mod tests {
    use super::*;

    /// `tornect_codec::encoded_size`, which the session layer passes in: even
    /// sizes, at most 3840×2160 wide and 2160×3840 upright.
    fn encoded(w: u32, h: u32) -> (u32, u32) {
        let (w, h) = (w & !1, h & !1);
        if h > w {
            (w.min(2160), h.min(3840))
        } else {
            (w.min(3840), h.min(2160))
        }
    }

    fn whole(w: u32, h: u32) -> (u32, u32) {
        (w, h)
    }

    #[test]
    fn buttons_keys_and_the_wheel_become_evdev_calls() {
        let mut wheel = WheelAccumulator::default();
        let no_place = |_: u16, _: u16| -> Option<(f64, f64)> { None };
        for (button, code) in [
            (Button::Left, 0x110),
            (Button::Right, 0x111),
            (Button::Middle, 0x112),
            (Button::Back, 0x113),
            (Button::Forward, 0x114),
        ] {
            for pressed in [true, false] {
                let calls = translate(
                    &InputEvent::PointerButton { button, pressed },
                    &mut wheel,
                    no_place,
                )
                .unwrap();
                assert_eq!(calls, [Some(Call::Button { code, pressed }), None]);
            }
        }
        // Keys by USB usage to evdev: KeyA 30, Enter 28, NumpadEnter 96,
        // MetaLeft 125, ArrowUp 103.
        for (usb, code) in [
            (0x07_0004, 30),
            (0x07_0028, 28),
            (0x07_0058, 96),
            (0x07_00e3, 125),
            (0x07_0052, 103),
        ] {
            let calls = translate(
                &InputEvent::Key { usb, pressed: true },
                &mut wheel,
                no_place,
            )
            .unwrap();
            assert_eq!(
                calls,
                [
                    Some(Call::Key {
                        code,
                        pressed: true
                    }),
                    None
                ],
                "0x{usb:06x}"
            );
        }
        // A key the table has no evdev code for, and one it does not know.
        let no_evdev = keymap::KEYS.iter().find(|k| k.evdev == 0).map(|k| k.usb);
        for usb in no_evdev.into_iter().chain([0x07_ffff]) {
            assert!(matches!(
                translate(&InputEvent::Key { usb, pressed: true }, &mut wheel, no_place),
                Err(InputError::UnknownKey(u)) if u == usb
            ));
        }
        // The wheel: + dy is up on the wire and a negative step at the portal;
        // half notches wait for their other half; zero steps are never sent.
        let scroll = |w: &mut WheelAccumulator, dx, dy| {
            translate(&InputEvent::Wheel { dx, dy }, w, no_place).unwrap()
        };
        let v = |steps| {
            Some(Call::Scroll {
                axis: ScrollAxis::Vertical,
                steps,
            })
        };
        let h = |steps| {
            Some(Call::Scroll {
                axis: ScrollAxis::Horizontal,
                steps,
            })
        };
        assert_eq!(scroll(&mut wheel, 0, 120), [v(-1), None]);
        assert_eq!(scroll(&mut wheel, 0, -360), [v(3), None]);
        assert_eq!(scroll(&mut wheel, 240, 0), [None, h(2)]);
        assert_eq!(scroll(&mut wheel, -60, 60), [None, None]);
        assert_eq!(scroll(&mut wheel, -60, 60), [v(-1), h(-1)]);
        assert_eq!(scroll(&mut wheel, 0, 0), [None, None]);
        assert_eq!(
            translate(&InputEvent::ReleaseAll, &mut wheel, no_place).unwrap(),
            [None, None]
        );
        // A move before any picture size is refused, not guessed.
        assert!(
            translate(
                &InputEvent::PointerMove { x: 1, y: 1 },
                &mut wheel,
                no_place
            )
            .is_err()
        );
    }

    /// SLICE-C1 C1-2: the viewer sees the encoder's crop, so its corners are
    /// the crop's corners, not the desktop's.
    #[test]
    fn the_pointer_spans_the_encoded_region_edge_to_edge() {
        // A 5K desktop at 200 %: 5120×2880 pixels, 2560×1440 logical; the
        // encoder sends the top-left 3840×2160.
        let map = PointerMap::new((2560, 1440), (5120, 2880)).unwrap();
        let place = |x, y| map.place(x, y, (5120, 2880), encoded).unwrap();
        assert_eq!(place(0, 0), (0.0, 0.0));
        assert_eq!(place(65535, 65535), (3839.0 * 0.5, 2159.0 * 0.5));
        let (x, y) = place(32768, 32768);
        assert!(
            (x - 960.0).abs() <= 0.5 && (y - 540.0).abs() <= 0.5,
            "{x} {y}"
        );
        // Mapped over the whole desktop instead, the far corner would land
        // outside what the viewer sees.
        assert!(map.place(65535, 65535, (5120, 2880), whole).unwrap().0 > 1919.5);
        // Unscaled, odd-sized: 1921×1081 is encoded 1920×1080, and the far
        // corner is the last pixel the viewer sees.
        let map = PointerMap::new((1921, 1081), (1921, 1081)).unwrap();
        assert_eq!(
            map.place(65535, 65535, (1921, 1081), encoded),
            Some((1919.0, 1079.0))
        );
        // A rotated 4K monitor at 200 %: 2160×3840 pixels, 1080×1920
        // logical, sent whole, so the far corner is the screen's own.
        let map = PointerMap::new((1080, 1920), (2160, 3840)).unwrap();
        assert_eq!(
            map.place(65535, 65535, (2160, 3840), encoded),
            Some((2159.0 * 0.5, 3839.0 * 0.5))
        );
        // Fractional scaling (125 %): 2560×1600 pixels, 2048×1280 logical.
        let map = PointerMap::new((2048, 1280), (2560, 1600)).unwrap();
        let (x, y) = map.place(65535, 65535, (2560, 1600), encoded).unwrap();
        assert!((x - 2559.0 * 0.8).abs() < 1e-9 && (y - 1599.0 * 0.8).abs() < 1e-9);
        // Every position is strictly inside the logical screen, at any size.
        for (logical, pixels) in [
            ((2560, 1440), (5120, 2880)),
            ((1280, 800), (1280, 800)),
            ((1, 1), (2, 2)),
            ((3000, 2000), (2000, 1000)),
            ((1440, 2560), (1440, 2560)),
            ((1440, 2560), (2880, 5120)),
        ] {
            let map = PointerMap::new(logical, pixels).unwrap();
            for (x, y) in [(0, 0), (65535, 65535), (65535, 0), (12345, 54321)] {
                let (lx, ly) = map.place(x, y, pixels, encoded).unwrap();
                assert!(
                    (0.0..f64::from(logical.0)).contains(&lx),
                    "{logical:?} {pixels:?} x {lx}"
                );
                assert!(
                    (0.0..f64::from(logical.1)).contains(&ly),
                    "{logical:?} {pixels:?} y {ly}"
                );
            }
        }
        // Nothing to map onto.
        assert_eq!(PointerMap::new((0, 1080), (1920, 1080)), None);
        assert_eq!(PointerMap::new((1920, 1080), (1920, 0)), None);
        let map = PointerMap::new((1920, 1080), (1920, 1080)).unwrap();
        assert_eq!(
            map.place(1, 1, (1, 1), encoded),
            None,
            "a 1×1 picture encodes to nothing"
        );
    }

    fn input(
        portal: &Arc<Portal>,
        shared: &Arc<Shared>,
        logical: Option<(u32, u32)>,
        granted: bool,
    ) -> WaylandInput {
        WaylandInput {
            portal: Arc::downgrade(portal),
            shared: Arc::clone(shared),
            logical,
            granted,
        }
    }

    /// A portal handle with no thread behind it, whose calls land in `rx`.
    fn fake_portal() -> (Arc<Portal>, tokio::sync::mpsc::Receiver<Call>) {
        let (portal, rx) = Portal::detached(8);
        (Arc::new(portal), rx)
    }

    #[test]
    fn an_injector_is_refused_unless_every_fact_it_needs_is_known() {
        let (portal, mut rx) = fake_portal();
        let shared = Arc::new(Shared::new());
        let refused = |input: &WaylandInput| match input.injector(encoded) {
            Err(CaptureError::Unavailable(why)) => why,
            Ok(_) => panic!("built"),
            Err(e) => panic!("{e}"),
        };
        // No picture size negotiated yet.
        assert!(
            refused(&input(&portal, &shared, Some((1280, 800)), true)).contains("no picture size")
        );
        shared.set_format(Ok(Some(pipewire::VideoFormat {
            pixel: pipewire::PixelFormat::Bgrx,
            width: 1280,
            height: 800,
        })));
        // Input not granted at the dialog; no logical size from the portal.
        assert!(
            refused(&input(&portal, &shared, Some((1280, 800)), false)).contains("remote control")
        );
        assert!(refused(&input(&portal, &shared, None, true)).contains("logical size"));
        // Everything known: the injector maps and queues.
        let mut injector = input(&portal, &shared, Some((1280, 800)), true)
            .injector(encoded)
            .unwrap();
        injector
            .inject(&InputEvent::PointerMove { x: 65535, y: 0 })
            .unwrap();
        injector
            .inject(&InputEvent::Key {
                usb: 0x07_0004,
                pressed: true,
            })
            .unwrap();
        assert_eq!(rx.try_recv().unwrap(), Call::Motion { x: 1279.0, y: 0.0 });
        assert_eq!(
            rx.try_recv().unwrap(),
            Call::Key {
                code: 30,
                pressed: true
            }
        );
        // The source gone: no new injector, and the old one's session is over.
        let weak = input(&portal, &shared, Some((1280, 800)), true);
        drop(injector);
        drop(portal);
        assert!(refused(&weak).contains("ended"));
    }

    /// Slice-G G1-4: a kill during a portal stall lets go of what the portal
    /// session holds, and makes nothing the viewer queued. The injector's own
    /// releases (`Tracked`'s drop) find the queue full then, so the thread
    /// lets go of what its own calls pressed. Before, it made every queued call
    /// (up to 1024, at up to 1 s each) before it closed the session, and the
    /// refused key-up was never made at all.
    #[tokio::test(start_paused = true)]
    async fn a_kill_in_a_stall_still_lets_go_of_what_the_portal_holds() {
        use super::portal::{PassedOn, pass_on};

        let (portal, mut calls) = Portal::detached(2);
        let closing = portal.closing();
        let portal = Arc::new(portal);
        let shared = Arc::new(Shared::new());
        shared.set_format(Ok(Some(pipewire::VideoFormat {
            pixel: pipewire::PixelFormat::Bgrx,
            width: 1280,
            height: 800,
        })));
        let mut viewer = tornect_input::Tracked::new(
            input(&portal, &shared, Some((1280, 800)), true)
                .injector(encoded)
                .unwrap(),
        );
        let key = |pressed| Call::Key { code: 30, pressed };
        viewer
            .inject(&InputEvent::Key {
                usb: 0x07_0004,
                pressed: true,
            })
            .unwrap();
        viewer
            .inject(&InputEvent::PointerMove { x: 0, y: 0 })
            .unwrap();
        // The portal thread: it makes the key-down, then stalls on the move.
        let made = Arc::new(std::sync::Mutex::new(Vec::new()));
        let thread = tokio::spawn({
            let made = Arc::clone(&made);
            async move {
                let mut closed = None::<futures::stream::Pending<()>>;
                pass_on(&mut calls, &closing, &mut closed, move |call| {
                    made.lock().unwrap().push(call);
                    let stalls = matches!(call, Call::Motion { .. });
                    async move {
                        if stalls {
                            std::future::pending::<()>().await;
                        }
                        Ok::<(), ashpd::Error>(())
                    }
                })
                .await
            }
        });
        while made.lock().unwrap().len() < 2 {
            tokio::task::yield_now().await;
        }
        // The queue fills up behind the stalled call.
        while viewer
            .inject(&InputEvent::PointerMove { x: 65535, y: 65535 })
            .is_ok()
        {}
        // The kill: the viewer's key-up finds the queue full, and the last
        // handle goes with the source.
        drop(viewer);
        drop(portal);
        assert_eq!(thread.await.unwrap(), PassedOn::HandlesGone);
        assert_eq!(
            *made.lock().unwrap(),
            [key(true), Call::Motion { x: 0.0, y: 0.0 }, key(false)]
        );
    }

    /// The live check (`docs/VERIFICATION.md`): a real RemoteDesktop session on
    /// this desktop. **It shows the portal dialog** unless the stored restore
    /// token still holds; someone must answer it within three minutes. Run at
    /// the desktop's console, with its session environment:
    ///
    /// ```text
    /// TORNECT_HOME=$PWD/target/tornect-test/s61-host \
    ///   cargo test --workspace -- --ignored --nocapture wayland::tests::live
    /// ```
    ///
    /// `--workspace` on purpose: `-p` or `--lib` select other dev-dependencies,
    /// which re-unify features and rebuild the Tor stack. With `TORNECT_HOME` set, the restore token is kept in that home's state
    /// directory, so a `tornect host` on the same home needs no second dialog.
    #[test]
    #[ignore = "opens a real portal session: the desktop shows a dialog someone must answer"]
    fn live_portal_session_shares_the_screen_and_takes_the_pointer() {
        let token = std::env::var_os(tornect_core::paths::HOME_ENV)
            .map(|home| tornect_core::Paths::from_home(PathBuf::from(home)).portal_restore_token());
        let had_token = token.as_ref().is_some_and(|t| t.exists());
        eprintln!("restore token file: {token:?} (present before: {had_token})");
        let options = WaylandOptions {
            dialog_wait: Duration::from_secs(180),
            ..WaylandOptions::new(token.clone())
        };
        let started = std::time::Instant::now();
        let (mut source, input) = WaylandSource::open(&options).expect("the portal session starts");
        eprintln!(
            "session started in {:.1} s: {source:?} {input:?}",
            started.elapsed().as_secs_f64()
        );
        let kept = token.as_ref().is_some_and(|t| t.exists());
        eprintln!("restore token kept after the start: {kept}");
        // The host's first-picture deadline is 10 s, and nothing moves here:
        // the compositor must send a first picture of a still screen by itself.
        let asked = std::time::Instant::now();
        let first = next(&mut source, Duration::from_secs(10));
        match &first {
            Some(frame) => {
                eprintln!(
                    "first picture after {:.2} s, unprompted: {}x{} ({} bytes)",
                    asked.elapsed().as_secs_f64(),
                    frame.width,
                    frame.height,
                    frame.bgrx.len()
                );
                assert_eq!(frame.bgrx.len(), (frame.width * frame.height * 4) as usize);
            }
            None => eprintln!("NO first picture within 10 s of a still screen"),
        }
        // Pictures only on damage: count what arrives in 5 s untouched.
        let quiet = count(&mut source, Duration::from_secs(5));
        eprintln!("pictures in 5 s with nothing moved: {quiet}");
        let injector = input
            .injector(encoded)
            .expect("an injector (allow remote interaction in the dialog)");
        let mut injector = tornect_input::Tracked::new(injector);
        let mut moved = 0;
        for (x, y) in [
            (16384, 16384),
            (49152, 16384),
            (49152, 49152),
            (16384, 49152),
            (32768, 32768),
        ] {
            let _ = count(&mut source, Duration::from_millis(300));
            injector
                .inject(&InputEvent::PointerMove { x, y })
                .expect("queued");
            match next(&mut source, Duration::from_secs(3)) {
                Some(frame) => {
                    moved += 1;
                    eprintln!(
                        "pointer to ({x}, {y}): a new picture {}x{}",
                        frame.width, frame.height
                    );
                }
                None => eprintln!("pointer to ({x}, {y}): no new picture within 3 s"),
            }
        }
        // A burst of moves, as a viewer dragging would send: the rate the
        // pictures come at is the compositor's, before any encoder pacing.
        let burst = std::time::Instant::now();
        let mut pictures = 0;
        for i in 0..100u16 {
            injector
                .inject(&InputEvent::PointerMove {
                    x: 16384 + i * 300,
                    y: 32768,
                })
                .expect("queued");
            pictures += count(&mut source, Duration::from_millis(20));
        }
        pictures += count(&mut source, Duration::from_millis(200));
        let secs = burst.elapsed().as_secs_f64();
        eprintln!(
            "pointer drag: {pictures} pictures in {secs:.1} s = {:.1} fps",
            f64::from(pictures) / secs
        );
        drop(injector);
        drop(source);
        eprintln!(
            "LIVE PORTAL CHECK first_picture={} moves_with_a_picture={moved}/5 \
             drag_pictures={pictures} token_kept={kept}",
            first.is_some()
        );
        assert!(first.is_some(), "no first picture of a still screen");
        assert!(moved >= 4, "pointer moves produced pictures {moved}/5");
    }

    fn next(source: &mut WaylandSource, within: Duration) -> Option<Frame> {
        let deadline = std::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match source.next_frame(left.min(Duration::from_millis(100))) {
                Ok(Some(frame)) => return Some(frame),
                Ok(None) if left.is_zero() => return None,
                Ok(None) => {}
                Err(e) => panic!("capture failed: {e}"),
            }
        }
    }

    fn count(source: &mut WaylandSource, within: Duration) -> u32 {
        let deadline = std::time::Instant::now() + within;
        let mut n = 0;
        while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
            match source.next_frame(left.min(Duration::from_millis(50))) {
                Ok(Some(_)) => n += 1,
                Ok(None) => {}
                Err(e) => panic!("capture failed: {e}"),
            }
        }
        n
    }
}
