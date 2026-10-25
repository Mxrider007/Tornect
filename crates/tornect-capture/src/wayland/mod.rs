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
//!   desktop the picture shows (SLICE-C1 C1-2): all of it but an odd last
//!   column or row, which the host scales into the picture (decision M1-74).
//!   It speaks evdev codes to the portal's `Notify*` methods.
//! - The session's restore token, kept in a 0600 file, lets later sessions
//!   start without the dialog until the user revokes the permission.
//! - With [`WaylandOptions::clipboard`] (`[services] wayland_clipboard`) the
//!   session also asks for the desktop's clipboard, and [`WaylandClipboard`]
//!   hands out its [`ClipboardLink`] (design `services` §4.2).
//!
//! Built for LP64 Linux only: the PipeWire structures are mirrored for it.

mod clip;
#[cfg(test)]
mod fake_bus;
mod pipewire;
mod portal;

use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tornect_input::clipboard::ClipboardLink;
use tornect_input::{
    Button, InputError, InputEvent, InputSink, View, WheelAccumulator, denormalize, keymap,
};

use self::pipewire::{PwCapture, Shared};
pub use self::portal::Bus;
use self::portal::{Call, Opened, Portal, ScrollAxis, Setup};
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
    /// The most pictures a second the stream asks the compositor for (its
    /// `maxFramerate`, held to 1 to 120), so that the PipeWire thread copies
    /// no picture the encoder would drop. `None` asks for no cap: the
    /// compositor delivers at its own rate. A desktop that fails the stream
    /// with the cap gets it once more without (on a second PipeWire remote
    /// the portal opens for that), so a cap never costs the picture.
    pub max_fps: Option<u32>,
    /// Ask the desktop for its clipboard too (`[services] wayland_clipboard`,
    /// off by default; design `services` §4.2): `RequestClipboard` before
    /// `Start`, in every session and in [`grant`] alike, so the restore token
    /// covers what each session asks for. A token restores the request that
    /// made it, so `restore_token` must be the file of this request
    /// (`tornect_core::Paths::portal_restore_token_for`). Off, the portal
    /// request is the one made before the switch existed, call for call.
    pub clipboard: bool,
}

impl WaylandOptions {
    /// The session bus and [`DIALOG_WAIT`], keeping the token in
    /// `restore_token`, without the clipboard.
    #[must_use]
    pub fn new(restore_token: Option<PathBuf>) -> Self {
        Self {
            restore_token,
            dialog_wait: DIALOG_WAIT,
            bus: Bus::Session,
            cancel: None,
            max_fps: None,
            clipboard: false,
        }
    }

    /// What the portal thread is given for these options.
    fn setup(&self, spare_remote: bool) -> Setup {
        Setup {
            bus: self.bus.clone(),
            token_file: self.restore_token.clone(),
            dialog_wait: self.dialog_wait,
            cancel: self.cancel.clone(),
            spare_remote,
            clipboard: self.clipboard,
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
        let (portal, opened) = Portal::open(options.setup(options.max_fps.is_some()))?;
        let portal = Arc::new(portal);
        let Opened {
            node_id,
            logical,
            input,
            fd,
            spare,
            clipboard,
        } = opened;
        let cancelled = || options.cancel.as_ref().is_some_and(|c| *c.borrow());
        let (capture, format) =
            connect_capped(options.max_fps, fd, spare, cancelled, |fd, max_fps| {
                let capture = PwCapture::connect(fd, node_id, max_fps)?;
                let format = capture.shared().wait_negotiated(NEGOTIATE_WAIT)?;
                Ok((capture, format))
            })?;
        tracing::info!(
            node = node_id,
            width = format.width,
            height = format.height,
            max_framerate = ?format.max_framerate,
            logical = ?logical,
            input,
            "Wayland screen cast negotiated"
        );
        let input = WaylandInput {
            portal: Arc::downgrade(&portal),
            shared: Arc::clone(capture.shared()),
            logical,
            granted: input,
            clipboard,
        };
        Ok((Self { capture, portal }, input))
    }
}

/// Connects the cast's stream on `fd` asking for at most `max_fps`
/// pictures a second. If that fails with a cap asked for, a `spare` remote
/// at hand and the session not over (`cancelled`), it is connected once
/// more, on the spare, with no cap: a desktop that refuses the property
/// (the quality design's R2) still shares, at its own rate, which the
/// encoder paces anyway. The spare goes unused otherwise.
fn connect_capped<Fd, T>(
    max_fps: Option<u32>,
    fd: Fd,
    spare: Option<Fd>,
    cancelled: impl Fn() -> bool,
    mut connect: impl FnMut(Fd, Option<u32>) -> Result<T, CaptureError>,
) -> Result<T, CaptureError> {
    match (connect(fd, max_fps), spare) {
        (Err(e), Some(spare)) if max_fps.is_some() && !cancelled() => {
            tracing::warn!(
                error = %e,
                ?max_fps,
                "the screen cast did not start with a frame-rate cap; trying once without it"
            );
            connect(spare, None)
        }
        (result, _) => result,
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
    /// The desktop shares its clipboard under the grant (asked for only with
    /// [`WaylandOptions::clipboard`]).
    pub clipboard: bool,
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
    let (portal, opened) = Portal::open(options.setup(false))?;
    let input = opened.input;
    let clipboard = opened.clipboard;
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
    Ok(Granted {
        input,
        remembered,
        clipboard,
    })
}

/// Delete the restore tokens the portal request this host makes never
/// restores (`tornect_core::Paths::retired_portal_tokens`), at host start: a
/// token is a bearer grant of the screen and input, and one made for another
/// request is never used again. With the clipboard switch off there are none.
/// Returns how many there were; the desktop then asks once more, at the
/// first-run grant or the next session.
pub fn forget_retired_tokens(paths: &tornect_core::Paths, clipboard: bool) -> usize {
    paths
        .retired_portal_tokens(clipboard)
        .iter()
        .filter(|file| file.exists())
        .inspect(|file| portal::forget_token(file))
        .count()
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

    /// The buffer goes back to the PipeWire slot, to pack a later picture
    /// into; once the stream is closed it is dropped.
    fn recycle(&mut self, bgrx: Vec<u8>) {
        self.capture.shared().recycle(bgrx);
    }
}

/// What an injector for a [`WaylandSource`]'s session is built from. It holds
/// the session only weakly: once the source is gone, no injector can be built.
pub struct WaylandInput {
    portal: Weak<Portal>,
    shared: Arc<Shared>,
    logical: Option<(u32, u32)>,
    granted: bool,
    /// The session started with the desktop's clipboard.
    clipboard: bool,
}

impl std::fmt::Debug for WaylandInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WaylandInput")
            .field("logical", &self.logical)
            .field("granted", &self.granted)
            .field("clipboard", &self.clipboard)
            .finish_non_exhaustive()
    }
}

impl WaylandInput {
    /// The session's clipboard: `Some` only when the session asked for it
    /// ([`WaylandOptions::clipboard`]) and the desktop shares it
    /// (`clipboard_enabled` in the `Start` results), while the source lives.
    #[must_use]
    pub fn clipboard(&self) -> Option<WaylandClipboard> {
        if !self.clipboard {
            return None;
        }
        self.portal
            .upgrade()
            .filter(|p| !p.is_over())
            .map(|_| WaylandClipboard {
                portal: Weak::clone(&self.portal),
            })
    }

    /// An injector into the source's session. The viewer's pointer is mapped
    /// over the part of the stream the picture shows, the whole of it but for
    /// an odd last column or row (decision M1-74), scaled down or not.
    ///
    /// Refused when the source is gone, when the desktop did not grant input
    /// (the dialog's remote-control switch), or when the portal gave no
    /// logical size, without which no position could be placed exactly.
    pub fn injector(&self) -> Result<WaylandInjector, CaptureError> {
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
            wheel: WheelAccumulator::default(),
        })
    }
}

/// The desktop's clipboard on a [`WaylandSource`]'s portal session, held
/// weakly like [`WaylandInput`]. Its [`ClipboardLink`] keeps the backend
/// contract of `tornect_input::clipboard`: nothing is read or set while the
/// link is inactive, text copied before an activation never crosses, nor text
/// a password manager marks private, and text the link set is cleared from
/// the clipboard when the session ends.
#[derive(Debug)]
pub struct WaylandClipboard {
    portal: Weak<Portal>,
}

impl WaylandClipboard {
    /// The link to the clipboard's loop, once per session: refused when it
    /// was taken already or the source is gone. Dropping it ends the sharing
    /// while the screen may still be shared: the loop clears the clipboard if
    /// it still holds text the link set, reads nothing from it any more, and
    /// until the session ends only takes the clipboard's signals off the bus
    /// (unread, they would stall the session's input), answering a paste
    /// with nothing.
    pub fn link(self) -> Result<ClipboardLink, CaptureError> {
        let portal = self
            .portal
            .upgrade()
            .filter(|p| !p.is_over())
            .ok_or_else(|| {
                CaptureError::Unavailable("the screen-sharing session has ended".to_owned())
            })?;
        portal.take_clip_link().ok_or_else(|| {
            CaptureError::Unavailable("the session's clipboard is in use already".to_owned())
        })
    }

    /// How long after the desktop's `Start` answer it first announced the
    /// clipboard's owner, once it has: what gate G2 measures against the
    /// loop's baseline grace.
    #[must_use]
    pub fn announced_after_start(&self) -> Option<Duration> {
        self.portal
            .upgrade()
            .and_then(|portal| portal.announced_after_start())
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
        let map = self.map;
        let pixels = self.shared.pixel_size();
        let calls = translate(event, &mut self.wheel, |x, y| map.place(x, y, pixels?))?;
        for call in calls.into_iter().flatten() {
            self.portal.send(call)?;
        }
        Ok(())
    }

    /// The injector addresses the one stream this source shows, at its live
    /// size, and no rectangle of a desktop: a [`View::Rect`] would have a
    /// `Viewport` place positions over a space the portal does not take. The
    /// source describes no layout until the design's Part 2 (decision M1-75),
    /// which follows a [`View::Stream`] here; until then every view is
    /// refused, and the host ends input rather than mis-map a click.
    fn retarget(&mut self, view: &View) -> Result<(), InputError> {
        Err(InputError::Inject(match view {
            View::Rect { .. } => "the portal session takes no desktop rectangle".to_owned(),
            View::Stream { .. } => {
                "this injector cannot follow the picture to another screen".to_owned()
            }
        }))
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

    /// Where `(x, y)`, normalized over the picture of a `pixels`-sized stream,
    /// lies in logical coordinates. The picture shows the stream's even part,
    /// all of it but for an odd last column or row (decision M1-74), so the
    /// pointer never reaches what no picture shows; the result stays strictly
    /// inside the screen's logical size (`0 <= x < width`), as the portal
    /// requires.
    fn place(&self, x: u16, y: u16, pixels: (u32, u32)) -> Option<(f64, f64)> {
        let (width, height) = (pixels.0 & !1, pixels.1 & !1);
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
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    /// The options a caller does not set ask the compositor for no frame-rate
    /// cap: the stream's pod is then the report's, byte for byte
    /// (`pipewire::tests::the_enum_format_pod_is_the_232_bytes_of_the_report`).
    #[test]
    fn options_ask_for_no_frame_rate_cap_unless_given_one() {
        let options = WaylandOptions::new(None);
        assert_eq!(options.max_fps, None);
        assert_eq!(
            pipewire::enum_format_pod(options.max_fps).bytes().len(),
            232
        );
        let capped = WaylandOptions {
            max_fps: Some(20),
            ..WaylandOptions::new(None)
        };
        assert_eq!(pipewire::enum_format_pod(capped.max_fps).bytes().len(), 288);
    }

    /// A remote that records when it is let go of.
    struct Remote(&'static str, Rc<RefCell<Vec<String>>>);

    impl Drop for Remote {
        fn drop(&mut self) {
            self.1.borrow_mut().push(format!("closed {}", self.0));
        }
    }

    /// The stream is connected with the cap first; only when that fails, a
    /// spare is at hand and the session goes on, once more on the spare
    /// without it. Whatever is not used is let go of, and the result is the
    /// last attempt's.
    #[test]
    fn a_refused_frame_rate_cap_is_retried_once_without_it_on_the_spare() {
        type Script = Vec<Result<&'static str, &'static str>>;
        let run = |max_fps: Option<u32>, spare: bool, cancelled: bool, mut script: Script| {
            let log = Rc::new(RefCell::new(Vec::new()));
            let fd = Remote("first", Rc::clone(&log));
            let spare = spare.then(|| Remote("spare", Rc::clone(&log)));
            let result = connect_capped(
                max_fps,
                fd,
                spare,
                || cancelled,
                |remote: Remote, fps: Option<u32>| {
                    log.borrow_mut()
                        .push(format!("connect {} {fps:?}", remote.0));
                    drop(remote);
                    script
                        .remove(0)
                        .map_err(|why| CaptureError::Unavailable(why.to_owned()))
                },
            );
            let result = result.map_err(|e| e.to_string());
            let log = log.borrow().clone();
            (result, log)
        };
        let failed = |why: &str| Err(format!("capture unavailable: {why}"));

        let (result, log) = run(Some(20), true, false, vec![Ok("capped")]);
        assert_eq!(result, Ok("capped"));
        assert_eq!(
            log,
            ["connect first Some(20)", "closed first", "closed spare"]
        );

        let (result, log) = run(Some(20), true, false, vec![Err("refused"), Ok("uncapped")]);
        assert_eq!(result, Ok("uncapped"));
        assert_eq!(
            log,
            [
                "connect first Some(20)",
                "closed first",
                "connect spare None",
                "closed spare"
            ]
        );

        let (result, log) = run(Some(20), true, false, vec![Err("refused"), Err("again")]);
        assert_eq!(result, failed("again"), "the last attempt's error");
        assert_eq!(log.len(), 4);

        // No cap asked for, no spare, or a session already over: one try.
        for (max_fps, spare, cancelled) in [
            (None, true, false),
            (Some(20), false, false),
            (Some(20), true, true),
        ] {
            let (result, log) = run(max_fps, spare, cancelled, vec![Err("refused")]);
            assert_eq!(result, failed("refused"), "{max_fps:?} {spare} {cancelled}");
            assert_eq!(log[0], format!("connect first {max_fps:?}"));
            assert!(
                !log.iter().any(|line| line.starts_with("connect spare")),
                "{log:?}"
            );
        }
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

    /// SLICE-C1 C1-2, decision M1-74: the picture shows the stream's even
    /// part, so its corners are that part's corners, and an odd last column
    /// or row, which no picture shows, is never reached.
    #[test]
    fn the_pointer_spans_the_even_part_edge_to_edge() {
        // A 5K desktop at 200 %: 5120×2880 pixels, 2560×1440 logical; the
        // host scales all of it into the picture, so the far corner is the
        // desktop's own.
        let map = PointerMap::new((2560, 1440), (5120, 2880)).unwrap();
        let place = |x, y| map.place(x, y, (5120, 2880)).unwrap();
        assert_eq!(place(0, 0), (0.0, 0.0));
        assert_eq!(place(65535, 65535), (5119.0 * 0.5, 2879.0 * 0.5));
        let (x, y) = place(32768, 32768);
        assert!(
            (x - 1280.0).abs() <= 0.5 && (y - 720.0).abs() <= 0.5,
            "{x} {y}"
        );
        // Odd-sized: 1921×1081 shows 1920×1080, and the far corner is the
        // last pixel the viewer sees, not the dropped column and row.
        let map = PointerMap::new((1921, 1081), (1921, 1081)).unwrap();
        assert_eq!(
            map.place(65535, 65535, (1921, 1081)),
            Some((1919.0, 1079.0))
        );
        // An odd height only: 3538×1919 shows 3538×1918.
        let map = PointerMap::new((3538, 1919), (3538, 1919)).unwrap();
        assert_eq!(
            map.place(65535, 65535, (3538, 1919)),
            Some((3537.0, 1917.0))
        );
        assert_eq!(map.place(0, 0, (3538, 1919)), Some((0.0, 0.0)));
        // A rotated 4K monitor at 200 %: 2160×3840 pixels, 1080×1920
        // logical, sent whole, so the far corner is the screen's own.
        let map = PointerMap::new((1080, 1920), (2160, 3840)).unwrap();
        assert_eq!(
            map.place(65535, 65535, (2160, 3840)),
            Some((2159.0 * 0.5, 3839.0 * 0.5))
        );
        // Fractional scaling (125 %): 2560×1600 pixels, 2048×1280 logical.
        let map = PointerMap::new((2048, 1280), (2560, 1600)).unwrap();
        let (x, y) = map.place(65535, 65535, (2560, 1600)).unwrap();
        assert!((x - 2559.0 * 0.8).abs() < 1e-9 && (y - 1599.0 * 0.8).abs() < 1e-9);
        // Every position is strictly inside the logical screen, at any size.
        for (logical, pixels) in [
            ((2560, 1440), (5120, 2880)),
            ((1280, 800), (1280, 800)),
            ((1, 1), (2, 2)),
            ((3000, 2000), (2000, 1000)),
            ((1440, 2560), (1440, 2560)),
            ((1440, 2560), (2880, 5120)),
            ((3538, 1919), (3538, 1919)),
        ] {
            let map = PointerMap::new(logical, pixels).unwrap();
            for (x, y) in [(0, 0), (65535, 65535), (65535, 0), (12345, 54321)] {
                let (lx, ly) = map.place(x, y, pixels).unwrap();
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
        assert_eq!(map.place(1, 1, (1, 1)), None, "a 1×1 desktop shows nothing");
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
            clipboard: false,
        }
    }

    /// The clipboard switch is off unless a caller turns it on, and the
    /// portal thread is given what the options say. Off, the session's calls
    /// are the ones made before the switch existed
    /// (`portal::tests::fake_bus_without_the_switch_no_clipboard_call_is_made`
    /// checks them on a bus).
    #[test]
    fn the_clipboard_is_asked_for_only_with_the_switch_on() {
        let options = WaylandOptions::new(Some(PathBuf::from("token")));
        assert!(!options.clipboard);
        let setup = options.setup(false);
        assert!(!setup.clipboard);
        assert_eq!(setup.token_file, Some(PathBuf::from("token")));
        assert!(!setup.spare_remote);
        let on = WaylandOptions {
            clipboard: true,
            ..WaylandOptions::new(None)
        };
        let setup = on.setup(true);
        assert!(setup.clipboard);
        assert!(setup.spare_remote);
    }

    /// At host start the switch on deletes the token made without the
    /// clipboard (it would restore a grant without it), and keeps its own;
    /// the switch off deletes nothing.
    #[test]
    fn retired_tokens_are_deleted_only_with_the_switch_on() {
        let dir = tempfile::tempdir().unwrap();
        let paths = tornect_core::Paths::from_home(dir.path().join("home"));
        paths.ensure().unwrap();
        let without = paths.portal_restore_token_for(false);
        let with = paths.portal_restore_token_for(true);
        portal::remember_token(&without, Some("without-the-clipboard"));
        portal::remember_token(&with, Some("with-the-clipboard"));
        assert_eq!(forget_retired_tokens(&paths, false), 0);
        assert!(without.exists() && with.exists());
        assert_eq!(forget_retired_tokens(&paths, true), 1);
        assert!(!without.exists());
        assert!(with.exists());
        assert_eq!(forget_retired_tokens(&paths, true), 0);
    }

    /// The clipboard is handed out only for a session the desktop shares it
    /// with, while the source lives, and its link once.
    #[test]
    fn the_clipboard_link_is_handed_out_once_and_only_when_shared() {
        let (portal, _rx) = Portal::detached(8);
        let (portal, _ends) = portal.with_clip_link();
        let portal = Arc::new(portal);
        let shared = Arc::new(Shared::new());
        let mut shared_input = input(&portal, &shared, None, true);
        assert!(
            shared_input.clipboard().is_none(),
            "the session does not share the clipboard"
        );
        shared_input.clipboard = true;
        let first = shared_input.clipboard().unwrap();
        let second = shared_input.clipboard().unwrap();
        assert!(first.announced_after_start().is_none());
        let link = first.link().unwrap();
        assert!(!*link.active.borrow(), "a new link is inactive");
        match second.link() {
            Err(CaptureError::Unavailable(why)) => assert!(why.contains("in use"), "{why}"),
            other => panic!("{other:?}"),
        }
        let late = shared_input.clipboard().unwrap();
        drop(portal);
        assert!(shared_input.clipboard().is_none(), "the source is gone");
        match late.link() {
            Err(CaptureError::Unavailable(why)) => assert!(why.contains("ended"), "{why}"),
            other => panic!("{other:?}"),
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
        let refused = |input: &WaylandInput| match input.injector() {
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
            max_framerate: None,
        })));
        // Input not granted at the dialog; no logical size from the portal.
        assert!(
            refused(&input(&portal, &shared, Some((1280, 800)), false)).contains("remote control")
        );
        assert!(refused(&input(&portal, &shared, None, true)).contains("logical size"));
        // Everything known: the injector maps and queues.
        let mut injector = input(&portal, &shared, Some((1280, 800)), true)
            .injector()
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

    /// Decision M1-74: the injector maps over the even part of the stream's
    /// live size, here an odd 3538×1919 stream at 100 % and then the same
    /// monitor after a mode change to an odd 7077×3839 (logical units per
    /// pixel, measured once, hold across a mode change). Decision M1-75: it
    /// follows no view in this build, neither a desktop rectangle nor a
    /// stream, so the host ends input rather than mis-map a click.
    #[test]
    fn the_injector_maps_over_the_live_even_part_and_follows_no_view() {
        let (portal, mut rx) = fake_portal();
        let shared = Arc::new(Shared::new());
        let format = |width, height| {
            Ok(Some(pipewire::VideoFormat {
                pixel: pipewire::PixelFormat::Bgrx,
                width,
                height,
                max_framerate: None,
            }))
        };
        shared.set_format(format(3538, 1919));
        let mut injector = input(&portal, &shared, Some((3538, 1919)), true)
            .injector()
            .unwrap();
        let corner = InputEvent::PointerMove { x: 65535, y: 65535 };
        injector.inject(&corner).unwrap();
        assert_eq!(
            rx.try_recv().unwrap(),
            Call::Motion {
                x: 3537.0,
                y: 1917.0
            }
        );
        shared.set_format(format(7077, 3839));
        injector.inject(&corner).unwrap();
        assert_eq!(
            rx.try_recv().unwrap(),
            Call::Motion {
                x: 7075.0,
                y: 3837.0
            },
            "the far corner of the new mode's even part"
        );

        let rect = tornect_input::Rect::new(0, 0, 3538, 1918);
        for view in [
            View::Rect {
                shown: rect,
                space: rect,
            },
            View::Stream {
                node: 7,
                pixels: (3538, 1919),
                ratio: None,
            },
        ] {
            assert!(injector.retarget(&view).is_err(), "{view:?}");
            let mut viewport = tornect_input::Viewport::new(
                input(&portal, &shared, Some((3538, 1919)), true)
                    .injector()
                    .unwrap(),
            );
            assert!(viewport.retarget(&view).is_err(), "{view:?}");
            assert!(viewport.inject(&corner).is_err(), "no move after a refusal");
        }
        assert!(rx.try_recv().is_err(), "nothing more was sent");
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
            max_framerate: None,
        })));
        let mut viewer = tornect_input::Tracked::new(
            input(&portal, &shared, Some((1280, 800)), true)
                .injector()
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
        let token = std::env::var_os(tornect_core::paths::HOME_ENV).map(|home| {
            tornect_core::Paths::from_home(PathBuf::from(home)).portal_restore_token_for(false)
        });
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
            .injector()
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

    /// The live clipboard check (gates G1 and G2, `docs/VERIFICATION.md`): a
    /// real RemoteDesktop session with the clipboard, on this desktop. **It
    /// shows the portal dialog** unless the clipboard request's restore token
    /// (`portal-restore-token-2`) still holds; someone must answer it, copy
    /// text when asked and paste when asked. Copy some text before the run, so
    /// the desktop has an owner to announce. Run it twice: the first run asks
    /// and keeps the token, the second must start with no dialog and the
    /// clipboard still shared (G1). Each run prints how long after `Start` the
    /// desktop announced the owner from before the session (G2) and the
    /// length of what was copied, never the text:
    ///
    /// ```text
    /// TORNECT_HOME=$PWD/target/tornect-test/clip-host \
    ///   cargo test --workspace -- --ignored --nocapture wayland::tests::live_portal_clipboard
    /// ```
    #[test]
    #[ignore = "opens a real portal session with the clipboard: the desktop shows a dialog someone must answer"]
    fn live_portal_clipboard_is_shared_restored_and_announced() {
        use tornect_input::clipboard::ClipText;

        let token = std::env::var_os(tornect_core::paths::HOME_ENV).map(|home| {
            tornect_core::Paths::from_home(PathBuf::from(home)).portal_restore_token_for(true)
        });
        let had_token = token.as_ref().is_some_and(|t| t.exists());
        eprintln!("clipboard restore token present before: {had_token}");
        let options = WaylandOptions {
            dialog_wait: Duration::from_secs(180),
            clipboard: true,
            ..WaylandOptions::new(token.clone())
        };
        let started = std::time::Instant::now();
        let (source, input) = WaylandSource::open(&options).expect("the portal session starts");
        eprintln!(
            "session started in {:.1} s (a restored grant takes well under 2 s)",
            started.elapsed().as_secs_f64()
        );
        let clipboard = input.clipboard();
        eprintln!("clipboard_enabled: {}", clipboard.is_some());
        let clipboard = clipboard.expect("the desktop shares its clipboard (G1)");
        std::thread::sleep(Duration::from_secs(5));
        let announced = clipboard.announced_after_start();
        eprintln!(
            "the owner from before the session was announced {announced:?} after Start (the \
             baseline grace is {:?})",
            clip::BASELINE_GRACE
        );
        let mut link = clipboard.link().expect("the clipboard's link");
        link.active.send_replace(true);
        eprintln!("COPY some new text on this desktop within 30 s");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut copied = None;
        while std::time::Instant::now() < deadline {
            if link.from_desktop.has_changed().unwrap_or(false) {
                copied = link
                    .from_desktop
                    .borrow_and_update()
                    .as_ref()
                    .map(ClipText::byte_len);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        eprintln!("copied text that crossed: {copied:?} bytes");
        let text = "Tornect clipboard check";
        link.to_desktop
            .send_replace(Some(ClipText::new(text.to_owned()).unwrap()));
        eprintln!("PASTE into an editor within 30 s: it pastes {text:?}");
        std::thread::sleep(Duration::from_secs(30));
        drop(link);
        eprintln!("the link is gone: a paste now gives nothing (the clipboard was cleared)");
        std::thread::sleep(Duration::from_secs(10));
        drop(input);
        drop(source);
        let kept = token.as_ref().is_some_and(|t| t.exists());
        eprintln!(
            "LIVE CLIPBOARD CHECK clipboard_enabled=true announced={announced:?} \
             copied_bytes={copied:?} token_kept={kept} token_before={had_token}"
        );
        assert!(copied.is_some(), "no copied text crossed within 30 s");
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
