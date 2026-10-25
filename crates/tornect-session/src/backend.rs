//! What this build captures and injects with, per OS (decision M3-1): the
//! RemoteDesktop portal and PipeWire on a Wayland session, X11 on an X11
//! session, GDI and `SendInput` on Windows, and the synthetic test card and
//! test screens everywhere.

use std::path::PathBuf;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use std::sync::{Mutex, PoisonError};

use tokio::sync::watch;
use tornect_capture::{CaptureError, TestCard, TestScreens, VideoSource};
use tornect_input::InputSink;
use tornect_input::clipboard::ClipboardLink;

use crate::host::{MediaBackend, SourceRequest};

/// Size and rate of the shared test card: enough for the index strip to
/// survive the encoder, small enough for a Tor circuit. The rate is held to
/// the request's ([`card_fps`]).
const CARD: (u32, u32, u32) = (1280, 720, 15);

/// The sizes of the synthetic test screens, side by side from the left, the
/// first primary (the monitors design §5.5); they run at the card's rate.
pub const TEST_SCREENS: [(u32, u32); 2] = [(1280, 720), (1024, 768)];

/// The test card's rate for `request`: its own, never above the request's,
/// at least 1.
fn card_fps(request: SourceRequest) -> u32 {
    CARD.2.min(request.max_fps).max(1)
}

/// What a host shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Source {
    /// The desktop, with this OS's backend.
    #[default]
    Desktop,
    /// The synthetic test card. No desktop is shared, and the viewer's input
    /// goes nowhere: there is nothing behind the card to control.
    TestCard,
    /// Two synthetic screens side by side ([`TEST_SCREENS`]) the viewer can
    /// switch between, or see at once. No desktop is shared, and the
    /// viewer's input goes nowhere, as with the card.
    TestScreens,
}

/// The backends this build has.
#[derive(Debug)]
pub struct SystemBackend {
    source: Source,
    /// Where the Wayland portal's restore token is kept.
    #[cfg_attr(
        not(all(target_os = "linux", target_pointer_width = "64")),
        allow(dead_code)
    )]
    restore_token: Option<PathBuf>,
    /// Ask the Wayland portal for the desktop's clipboard too
    /// (`[services] wayland_clipboard`).
    #[cfg_attr(
        not(all(target_os = "linux", target_pointer_width = "64")),
        allow(dead_code)
    )]
    wayland_clipboard: bool,
    /// What an injector into the last Wayland source's portal session is
    /// built from. `open_injector` has no other way to reach the session
    /// `open_source` opened; the media host asks the two in that order for
    /// one session, and M1 serves one session at a time. It holds the session
    /// weakly, so it keeps nothing open once capture stops, and the picture
    /// slot it shares with the source lets go of the picture when the stream
    /// closes; it is dropped when the injector is built, when the session
    /// turns out view-only, and when the session ends.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    wayland_input: Mutex<Option<Box<dyn PortalInput>>>,
    /// The desktop's clipboard on the last Wayland source's portal session,
    /// taken from its input handle when the injector is built, and only when
    /// it is: the clipboard goes with the viewer's input the desktop granted,
    /// never to a session without it (the services design §2.1, §6.4). It
    /// holds the session weakly, as the input handle does. `open_clipboard`
    /// takes it; it is dropped when the session turns out view-only, when it
    /// ends, and when another source opens.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    portal_clipboard: Mutex<Option<Box<dyn PortalClipboard>>>,
}

/// What the backend keeps of a portal session between its open and its
/// injector: [`tornect_capture::wayland::WaylandInput`] (a fake in tests).
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
trait PortalInput: Send + std::fmt::Debug {
    /// The injector into the session; refused when the desktop did not
    /// grant the viewer's input or the session is over.
    fn sink(&self) -> Result<Box<dyn InputSink>, CaptureError>;

    /// The session's clipboard, when it was asked for and the desktop
    /// shares it.
    fn clip(&self) -> Option<Box<dyn PortalClipboard>>;
}

/// A portal session's clipboard:
/// [`tornect_capture::wayland::WaylandClipboard`] (a fake in tests).
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
trait PortalClipboard: Send + std::fmt::Debug {
    /// The link to it, once per portal session.
    fn link(self: Box<Self>) -> Result<ClipboardLink, CaptureError>;
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl PortalInput for tornect_capture::wayland::WaylandInput {
    fn sink(&self) -> Result<Box<dyn InputSink>, CaptureError> {
        Ok(Box::new(self.injector()?))
    }

    fn clip(&self) -> Option<Box<dyn PortalClipboard>> {
        self.clipboard()
            .map(|clipboard| Box::new(clipboard) as Box<dyn PortalClipboard>)
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl PortalClipboard for tornect_capture::wayland::WaylandClipboard {
    fn link(self: Box<Self>) -> Result<ClipboardLink, CaptureError> {
        tornect_capture::wayland::WaylandClipboard::link(*self)
    }
}

impl SystemBackend {
    /// Share `source`. On Wayland the desktop asks at every session; see
    /// [`SystemBackend::with_restore_token`].
    #[must_use]
    pub fn new(source: Source) -> Self {
        Self {
            source,
            restore_token: None,
            wayland_clipboard: false,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            wayland_input: Mutex::new(None),
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            portal_clipboard: Mutex::new(None),
        }
    }

    /// The Wayland portal request this host makes, and its restore token:
    /// with `clipboard` (`[services] wayland_clipboard`) every portal session
    /// asks for the desktop's clipboard too and keeps its grant in a file of
    /// its own, since a token restores only the request that made it; without
    /// it, the request and the file are the ones from before the switch
    /// ([`tornect_core::Paths::portal_restore_token_for`]).
    #[must_use]
    pub fn with_portal(mut self, paths: &tornect_core::Paths, clipboard: bool) -> Self {
        self.restore_token = Some(paths.portal_restore_token_for(clipboard));
        self.wayland_clipboard = clipboard;
        self
    }

    /// Keep the Wayland portal's restore token in `file`
    /// (`tornect_core::Paths::portal_restore_token`): once the user allows
    /// sharing at the desktop's dialog, later sessions start without asking
    /// again, until the permission is revoked or the file deleted.
    #[must_use]
    pub fn with_restore_token(mut self, file: PathBuf) -> Self {
        self.restore_token = Some(file);
        self
    }
}

impl MediaBackend for SystemBackend {
    /// On Wayland `cancel` ends the wait on the desktop's dialog: the portal
    /// session is closed, which takes the dialog down, and no restore token is
    /// kept for a session that is over. The other sources do not wait. The
    /// card and the Wayland stream run at most at `request`'s rate (the
    /// stream asks the compositor for that `maxFramerate`); X11 and GDI
    /// deliver at their own, and the encoder paces every source to the
    /// preset's rate.
    fn open_source(
        &self,
        request: SourceRequest,
        cancel: watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError> {
        match self.source {
            Source::TestCard => {
                let (width, height, _) = CARD;
                Ok(Box::new(TestCard::new(width, height, card_fps(request))))
            }
            Source::TestScreens => Ok(Box::new(TestScreens::new(&TEST_SCREENS, card_fps(request)))),
            Source::Desktop => self.desktop_source(request, cancel),
        }
    }

    fn open_injector(&self) -> Option<Box<dyn InputSink>> {
        match self.source {
            Source::TestCard | Source::TestScreens => None,
            Source::Desktop => self.desktop_injector(),
        }
    }

    /// Drops the Wayland portal session's input handle: the session still
    /// holds the desktop's keyboard-and-pointer grant, and nothing may build
    /// an injector into it for a view-only viewer.
    fn view_only(&self) {
        self.forget_input();
    }

    /// Drops the Wayland input handle a session that never got its injector
    /// left behind (its viewer left, or the session ended, between the open
    /// and the injector), and the portal clipboard its services never took:
    /// nothing is kept for a session that is over. One session is served at
    /// a time, so what is kept is that session's.
    fn session_ended(&self, _session_id: &str) {
        self.forget_input();
    }

    /// The test card and screens share no clipboard. The desktop's is the
    /// portal's on Wayland, and only for a session whose injector was built
    /// there; it is arboard's on an X11 session under the X11 injector's own
    /// gate (this machine's own display), and on Windows (the services
    /// design §6.4). One session is served at a time, so what is kept is
    /// that session's.
    fn open_clipboard(&self, _session_id: &str) -> Option<ClipboardLink> {
        match self.source {
            Source::TestCard | Source::TestScreens => None,
            Source::Desktop => self.desktop_clipboard(),
        }
    }
}

impl SystemBackend {
    /// Let go of the last Wayland source's input handle and portal
    /// clipboard, if they are still kept.
    fn forget_input(&self) {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        {
            self.wayland_input
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            self.portal_clipboard
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
        }
    }
}

/// The link of the X11 and Windows clipboard backend, or `None` and why
/// (said at WARN, which carries no clipboard text).
#[cfg(any(target_os = "linux", windows))]
fn arboard_or_none(
    arboard: impl FnOnce() -> Result<ClipboardLink, tornect_input::clipboard::ClipboardError>,
) -> Option<ClipboardLink> {
    match arboard() {
        Ok(link) => Some(link),
        Err(e) => {
            tracing::warn!(error = %e, "this computer's clipboard is not shared");
            None
        }
    }
}

/// The desktop backend a Linux session of this type gets.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Desktop {
    /// The RemoteDesktop portal and PipeWire.
    Wayland,
    /// The X11 grab and XTEST, which see the desktop only on a real X11
    /// session; anywhere else they refuse and say why.
    X11,
}

#[cfg(target_os = "linux")]
fn desktop_for(session_type: Option<&str>) -> Desktop {
    if session_type == Some("wayland") {
        Desktop::Wayland
    } else {
        Desktop::X11
    }
}

#[cfg(target_os = "linux")]
impl SystemBackend {
    fn desktop_source(
        &self,
        request: SourceRequest,
        cancel: watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError> {
        match desktop_for(session_type().as_deref()) {
            Desktop::Wayland => self.wayland_source(request, cancel),
            Desktop::X11 => Ok(Box::new(tornect_capture::x11::X11Capture::open()?)),
        }
    }

    fn desktop_injector(&self) -> Option<Box<dyn InputSink>> {
        let session = session_type();
        match desktop_for(session.as_deref()) {
            Desktop::Wayland => self.wayland_injector(),
            // XTEST reaches only X11 clients under Xwayland, so input is
            // injected only where capture shows the X11 desktop, never into
            // another machine's display (SLICE-C3 C3-3). The sink addresses
            // the whole root; the host's `Viewport` places the pointer onto
            // what the picture shows (decision M1-75).
            Desktop::X11 if session.as_deref() == Some("x11") => {
                let display = std::env::var("DISPLAY").ok();
                if !tornect_capture::x11::display_is_local(display.as_deref()) {
                    tracing::warn!(
                        "DISPLAY is not this machine's own display: the viewer's input is dropped"
                    );
                    return None;
                }
                match tornect_input::x11::XTestSink::connect() {
                    Ok(sink) => Some(Box::new(sink)),
                    Err(e) => {
                        tracing::warn!(error = %e, "XTEST is unavailable: the viewer's input is dropped");
                        None
                    }
                }
            }
            Desktop::X11 => None,
        }
    }

    fn desktop_clipboard(&self) -> Option<ClipboardLink> {
        self.clipboard_on(
            session_type().as_deref(),
            std::env::var("DISPLAY").ok().as_deref(),
            tornect_input::clipboard::arboard_link,
        )
    }

    /// The clipboard on a session of type `session` whose `DISPLAY` is
    /// `display`, with `arboard` the X11 backend's link.
    fn clipboard_on(
        &self,
        session: Option<&str>,
        display: Option<&str>,
        arboard: impl FnOnce() -> Result<ClipboardLink, tornect_input::clipboard::ClipboardError>,
    ) -> Option<ClipboardLink> {
        match desktop_for(session) {
            // The portal's clipboard or none: under GNOME Wayland `DISPLAY`
            // names Xwayland, whose clipboard mirrors the desktop's without
            // the portal's grant (the services design §4.2), so the X11
            // backend is never tried here, whether or not the portal shares
            // its clipboard or `[services] wayland_clipboard` asked for it.
            Desktop::Wayland => self.wayland_clipboard_link(),
            // The X11 injector's gate (SLICE-C3 C3-3): a real X11 session,
            // on this machine's own display, never another machine's.
            Desktop::X11 if session == Some("x11") => {
                if !tornect_capture::x11::display_is_local(display) {
                    tracing::warn!(
                        "DISPLAY is not this machine's own display: the clipboard is not shared"
                    );
                    return None;
                }
                arboard_or_none(arboard)
            }
            Desktop::X11 => None,
        }
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl SystemBackend {
    /// Opens the portal session: the desktop's dialog, unless the restore
    /// token still holds, until `cancel` turns `true`. The stream asks the
    /// compositor for at most `request`'s rate, which comes from the host's
    /// config and never from the viewer; a desktop that fails the stream
    /// with that cap gets it once more without (`WaylandOptions::max_fps`).
    fn wayland_source(
        &self,
        request: SourceRequest,
        cancel: watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError> {
        let options = self.wayland_options(request, cancel.clone());
        let (source, input) = tornect_capture::wayland::WaylandSource::open(&options)?;
        self.keep_portal(Box::new(input), *cancel.borrow());
        Ok(Box::new(source))
    }

    /// What is kept of the portal session just opened: its input handle,
    /// unless its session ended while the open finished (`cancelled`: its
    /// source is dropped unread, and `session_ended` may have run already);
    /// never an earlier portal session's clipboard.
    fn keep_portal(&self, input: Box<dyn PortalInput>, cancelled: bool) {
        self.portal_clipboard
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if !cancelled {
            *self
                .wayland_input
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(input);
        }
    }

    /// What a portal session is opened with.
    fn wayland_options(
        &self,
        request: SourceRequest,
        cancel: watch::Receiver<bool>,
    ) -> tornect_capture::wayland::WaylandOptions {
        let mut options = tornect_capture::wayland::WaylandOptions::new(self.restore_token.clone());
        options.cancel = Some(cancel);
        options.max_fps = Some(request.max_fps);
        options.clipboard = self.wayland_clipboard;
        options
    }

    /// The injector into the session `wayland_source` opened, mapping the
    /// viewer's pointer over the part of the stream the picture shows
    /// (SLICE-C1 C1-2, decision M1-74). The session's clipboard is kept
    /// for `open_clipboard` when the injector is built, and only then: the
    /// input handle it comes from is dropped here.
    fn wayland_injector(&self) -> Option<Box<dyn InputSink>> {
        let input = self
            .wayland_input
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()?;
        let (injector, clipboard) = match input.sink() {
            Ok(injector) => (Some(injector), input.clip()),
            Err(e) => {
                tracing::warn!(error = %e, "the viewer's input is dropped");
                (None, None)
            }
        };
        *self
            .portal_clipboard
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = clipboard;
        injector
    }

    /// The link to the clipboard `wayland_injector` kept, once.
    fn wayland_clipboard_link(&self) -> Option<ClipboardLink> {
        let clipboard = self
            .portal_clipboard
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()?;
        match clipboard.link() {
            Ok(link) => Some(link),
            Err(e) => {
                tracing::warn!(error = %e, "the desktop's clipboard is not shared");
                None
            }
        }
    }
}

#[cfg(all(target_os = "linux", not(target_pointer_width = "64")))]
impl SystemBackend {
    fn wayland_source(
        &self,
        _request: SourceRequest,
        _cancel: watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError> {
        Err(CaptureError::Unavailable(
            "Wayland capture is built for 64-bit Linux only".to_owned(),
        ))
    }

    fn wayland_injector(&self) -> Option<Box<dyn InputSink>> {
        None
    }

    fn wayland_clipboard_link(&self) -> Option<ClipboardLink> {
        None
    }
}

#[cfg(windows)]
impl SystemBackend {
    fn desktop_source(
        &self,
        _request: SourceRequest,
        _cancel: watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError> {
        Ok(Box::new(tornect_capture::gdi::GdiCapture::open()?))
    }

    /// Addresses the whole virtual desktop; the host's `Viewport` places the
    /// pointer onto what the picture shows (decision M1-75).
    fn desktop_injector(&self) -> Option<Box<dyn InputSink>> {
        Some(Box::new(tornect_input::windows::SendInputSink::new()))
    }

    fn desktop_clipboard(&self) -> Option<ClipboardLink> {
        arboard_or_none(tornect_input::clipboard::arboard_link)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
impl SystemBackend {
    fn desktop_source(
        &self,
        _request: SourceRequest,
        _cancel: watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError> {
        Err(CaptureError::Unavailable(
            "this build has no screen capture for this OS yet".to_owned(),
        ))
    }

    fn desktop_injector(&self) -> Option<Box<dyn InputSink>> {
        None
    }

    fn desktop_clipboard(&self) -> Option<ClipboardLink> {
        None
    }
}

#[cfg(target_os = "linux")]
fn session_type() -> Option<String> {
    std::env::var("XDG_SESSION_TYPE").ok()
}

/// The backend `Source::Desktop` would capture and inject with on this
/// machine, found without opening anything: what `tornect doctor` reports and
/// the host's banner says (SLICE-C3 C3-5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopBackend {
    /// The RemoteDesktop portal and PipeWire.
    Wayland,
    /// The X11 grab and XTEST, on this machine's own display.
    X11,
    /// GDI and `SendInput`.
    Gdi,
    /// No desktop can be shared here, and why.
    Unavailable(String),
}

impl DesktopBackend {
    /// This machine's.
    #[must_use]
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            linux_backend(
                session_type().as_deref(),
                std::env::var("DISPLAY").ok().as_deref(),
            )
        }
        #[cfg(windows)]
        {
            Self::Gdi
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            Self::Unavailable("this build has no screen capture for this OS yet".to_owned())
        }
    }

    /// Its short name: `wayland`, `x11`, `gdi` or `none`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Wayland => "wayland",
            Self::X11 => "x11",
            Self::Gdi => "gdi",
            Self::Unavailable(_) => "none",
        }
    }
}

/// The same choices [`SystemBackend`] makes when it opens the desktop, and the
/// same refusals, as a verdict.
#[cfg(target_os = "linux")]
fn linux_backend(session_type: Option<&str>, display: Option<&str>) -> DesktopBackend {
    match desktop_for(session_type) {
        Desktop::Wayland if cfg!(target_pointer_width = "64") => DesktopBackend::Wayland,
        Desktop::Wayland => {
            DesktopBackend::Unavailable("Wayland capture is built for 64-bit Linux only".to_owned())
        }
        Desktop::X11 if session_type != Some("x11") => DesktopBackend::Unavailable(format!(
            "not a Wayland or X11 session (XDG_SESSION_TYPE={})",
            session_type.unwrap_or("unset")
        )),
        Desktop::X11 if !tornect_capture::x11::display_is_local(display) => {
            DesktopBackend::Unavailable(format!(
                "DISPLAY={} is not this machine's own display",
                display.unwrap_or("unset")
            ))
        }
        Desktop::X11 => DesktopBackend::X11,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// The card is what `--capture test-card` shares, and it never offers an
    /// injector: nothing behind it can be controlled.
    #[test]
    fn the_test_card_shares_a_card_and_injects_nothing() {
        let backend = SystemBackend::new(Source::TestCard);
        let mut source = backend
            .open_source(SourceRequest::new(20), watch::channel(false).1)
            .unwrap();
        assert_eq!(source.name(), "synthetic");
        let frame = source.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!((frame.width, frame.height), (CARD.0, CARD.1));
        assert!(backend.open_injector().is_none());
    }

    /// The test screens are what `--capture test-screens` shares: 1280×720
    /// (main) and 1024×768 side by side, opening on the first, switchable,
    /// at the card's rate, and they never offer an injector.
    #[test]
    fn the_test_screens_share_two_screens_and_inject_nothing() {
        use std::sync::atomic::AtomicBool;
        use tornect_capture::{Rect, Selection, View};
        let backend = SystemBackend::new(Source::TestScreens);
        let mut source = backend
            .open_source(SourceRequest::new(20), watch::channel(false).1)
            .unwrap();
        assert_eq!(source.name(), "synthetic screens");
        let frame = source.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!((frame.width, frame.height), TEST_SCREENS[0]);
        let layout = source.layout().unwrap();
        let rects: Vec<(u8, bool, Rect)> = layout
            .monitors
            .iter()
            .map(|m| (m.id, m.primary, m.rect))
            .collect();
        assert_eq!(
            rects,
            [
                (1, true, Rect::new(0, 0, 1280, 720)),
                (2, false, Rect::new(1280, 0, 1024, 768)),
            ]
        );
        assert!(layout.all);
        source
            .select(Selection::Monitor(2), &AtomicBool::new(false))
            .unwrap();
        let frame = source.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!((frame.width, frame.height), TEST_SCREENS[1]);
        assert_eq!(
            source.layout().unwrap().view,
            View::Rect {
                shown: Rect::new(1280, 0, 1024, 768),
                space: Rect::new(0, 0, 2304, 768),
            }
        );
        assert!(backend.open_injector().is_none());
        // At most at the request's rate, as the card.
        let mut slow = backend
            .open_source(SourceRequest::new(2), watch::channel(false).1)
            .unwrap();
        assert!(slow.next_frame(Duration::from_secs(1)).unwrap().is_some());
        assert!(
            slow.next_frame(Duration::from_millis(100))
                .unwrap()
                .is_none()
        );
    }

    /// The card runs at its own 15 fps under the host's capture rate (20 on
    /// Tor), and at the request's when that is lower: at 2 fps no second
    /// picture comes within 100 ms, at 15 one comes within the second.
    #[test]
    fn the_test_card_runs_at_most_at_the_requested_rate() {
        assert_eq!(card_fps(SourceRequest::new(20)), 15);
        assert_eq!(card_fps(SourceRequest::new(15)), 15);
        assert_eq!(card_fps(SourceRequest::new(2)), 2);
        assert_eq!(card_fps(SourceRequest::new(0)), 1);
        let backend = SystemBackend::new(Source::TestCard);
        let mut slow = backend
            .open_source(SourceRequest::new(2), watch::channel(false).1)
            .unwrap();
        assert!(slow.next_frame(Duration::from_secs(1)).unwrap().is_some());
        assert!(
            slow.next_frame(Duration::from_millis(100))
                .unwrap()
                .is_none()
        );
        let mut card = backend
            .open_source(SourceRequest::new(20), watch::channel(false).1)
            .unwrap();
        assert!(card.next_frame(Duration::from_secs(1)).unwrap().is_some());
        assert!(card.next_frame(Duration::from_secs(1)).unwrap().is_some());
    }

    /// A Wayland session shares through the portal; every other session type
    /// goes to the X11 backend, which grabs only a real X11 session and
    /// otherwise refuses with the reason.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_wayland_session_gets_the_portal_and_any_other_the_x11_backend() {
        assert_eq!(desktop_for(Some("wayland")), Desktop::Wayland);
        for other in [Some("x11"), Some("tty"), Some(""), None] {
            assert_eq!(desktop_for(other), Desktop::X11, "{other:?}");
        }
    }

    /// SLICE-C3 C3-5: what `doctor` and the banner name is what opening the
    /// desktop would do, refusals included.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn the_desktop_backend_is_named_as_opening_it_would_go() {
        assert_eq!(
            linux_backend(Some("wayland"), Some(":0")),
            DesktopBackend::Wayland
        );
        assert_eq!(linux_backend(Some("x11"), Some(":0")), DesktopBackend::X11);
        for (session, display) in [
            (Some("x11"), Some("localhost:10.0")),
            (Some("x11"), None),
            (Some("tty"), Some(":0")),
            (None, Some(":0")),
        ] {
            let backend = linux_backend(session, display);
            assert!(
                matches!(&backend, DesktopBackend::Unavailable(why) if !why.is_empty()),
                "{session:?} {display:?}: {backend:?}"
            );
            assert_eq!(backend.name(), "none");
        }
    }

    /// Off Wayland the desktop source grabs X11 or refuses honestly. On
    /// Wayland (this dev VM) opening it would show the desktop's dialog, so
    /// only the live check exercises it.
    #[cfg(target_os = "linux")]
    #[test]
    fn off_wayland_the_desktop_source_grabs_x11_or_refuses_honestly() {
        if desktop_for(session_type().as_deref()) == Desktop::Wayland {
            return;
        }
        match SystemBackend::new(Source::Desktop)
            .open_source(SourceRequest::new(20), watch::channel(false).1)
        {
            Ok(source) => assert_eq!(source.name(), "x11"),
            Err(CaptureError::Unavailable(why)) => assert!(!why.is_empty()),
            Err(e) => panic!("{e}"),
        }
    }

    /// The portal request follows `[services] wayland_clipboard`: off (the
    /// default, and a backend built without `with_portal`), no clipboard is
    /// asked for and the restore token is the file from before the switch;
    /// on, the clipboard is asked for and its grant kept apart.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn the_portal_asks_for_the_clipboard_only_with_the_switch() {
        let paths = tornect_core::Paths::from_home(PathBuf::from("/nonexistent/tornect-home"));
        let cancel = watch::channel(false).1;
        let options = SystemBackend::new(Source::Desktop)
            .wayland_options(SourceRequest::new(20), cancel.clone());
        assert!(!options.clipboard);
        assert_eq!(options.restore_token, None);
        let off = tornect_core::Config::default().services.wayland_clipboard;
        assert!(!off, "the switch is off by default");
        let options = SystemBackend::new(Source::Desktop)
            .with_portal(&paths, off)
            .wayland_options(SourceRequest::new(20), cancel.clone());
        assert!(!options.clipboard);
        assert_eq!(options.restore_token, Some(paths.portal_restore_token()));
        assert_eq!(options.max_fps, Some(20));
        let options = SystemBackend::new(Source::Desktop)
            .with_portal(&paths, true)
            .wayland_options(SourceRequest::new(20), cancel);
        assert!(options.clipboard);
        assert_eq!(
            options.restore_token,
            Some(paths.portal_restore_token_for(true))
        );
        assert_ne!(options.restore_token, Some(paths.portal_restore_token()));
    }

    /// No Wayland source was opened, so there is no session to inject into.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn without_an_open_portal_session_there_is_no_wayland_injector() {
        let backend =
            SystemBackend::new(Source::Desktop).with_restore_token(PathBuf::from("unused"));
        assert!(backend.wayland_injector().is_none());
    }

    /// SLICE-C3 C3-3 at its call sites: on an X11 session whose `DISPLAY` has
    /// a host part, the desktop backend neither captures nor injects, nor
    /// shares that display's clipboard (the services design §6.4), and never
    /// connects to that display. A child run of this test gets that
    /// environment; here a listener plays the other machine's X server, and
    /// nothing may reach it.
    #[cfg(target_os = "linux")]
    #[test]
    fn another_machines_display_is_neither_captured_nor_driven() {
        const CHILD: &str = "TORNECT_TEST_REMOTE_DISPLAY_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let backend = SystemBackend::new(Source::Desktop);
            let refused = backend
                .open_source(SourceRequest::new(20), watch::channel(false).1)
                .err()
                .expect("captured another machine's display");
            assert!(
                refused
                    .to_string()
                    .contains("is not this machine's own display"),
                "{refused}"
            );
            assert!(backend.open_injector().is_none());
            assert!(backend.open_clipboard("s").is_none());
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        // X display N is TCP port 6000 + N.
        let number = listener.local_addr().unwrap().port().checked_sub(6000);
        let display = format!("127.0.0.1:{}", number.expect("a port above 6000"));
        let exe = std::env::current_exe().unwrap();
        let child = std::thread::spawn(move || {
            std::process::Command::new(exe)
                .args([
                    "--exact",
                    "backend::tests::another_machines_display_is_neither_captured_nor_driven",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("XDG_SESSION_TYPE", "x11")
                .env("DISPLAY", display)
                .output()
                .unwrap()
        });
        // A connection is dropped at once, so a child that connects cannot hang.
        let mut reached = 0;
        loop {
            let finished = child.is_finished();
            while listener.accept().is_ok() {
                reached += 1;
            }
            if finished {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let out = child.join().unwrap();
        let said = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            reached, 0,
            "the backend connected to another machine's display"
        );
        assert!(
            out.status.success() && said.contains("1 passed"),
            "the child run: {said}{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A test source has no desktop behind it, and so no clipboard.
    #[test]
    fn the_test_sources_share_no_clipboard() {
        for source in [Source::TestCard, Source::TestScreens] {
            assert!(SystemBackend::new(source).open_clipboard("s").is_none());
        }
    }

    /// A portal session as the backend keeps it: whether the desktop granted
    /// the viewer's input, whether it shares its clipboard, and whether the
    /// session is over; it counts the links its clipboard made.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[derive(Debug, Clone, Default)]
    struct FakePortal {
        granted: bool,
        clipboard: bool,
        over: bool,
        links: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    impl FakePortal {
        fn granted(clipboard: bool) -> Self {
            Self {
                granted: true,
                clipboard,
                ..Self::default()
            }
        }

        fn links(&self) -> usize {
            self.links.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    impl PortalInput for FakePortal {
        fn sink(&self) -> Result<Box<dyn InputSink>, CaptureError> {
            if self.over || !self.granted {
                return Err(CaptureError::Unavailable("no remote interaction".into()));
            }
            Ok(Box::new(NoSink))
        }

        fn clip(&self) -> Option<Box<dyn PortalClipboard>> {
            self.clipboard
                .then(|| Box::new(self.clone()) as Box<dyn PortalClipboard>)
        }
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    impl PortalClipboard for FakePortal {
        fn link(self: Box<Self>) -> Result<ClipboardLink, CaptureError> {
            if self.over {
                return Err(CaptureError::Unavailable("the session has ended".into()));
            }
            self.links.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(ClipboardLink::pair().0)
        }
    }

    /// Injects nothing.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    struct NoSink;

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    impl InputSink for NoSink {
        fn inject(
            &mut self,
            _: &tornect_input::InputEvent,
        ) -> Result<(), tornect_input::InputError> {
            Ok(())
        }
    }

    /// The X11 backend's link, which a Wayland host must never open.
    #[cfg(target_os = "linux")]
    fn no_arboard() -> Result<ClipboardLink, tornect_input::clipboard::ClipboardError> {
        panic!("arboard_link was opened")
    }

    /// The clipboard a Wayland session of this backend shares.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    fn wayland_clipboard(backend: &SystemBackend) -> Option<ClipboardLink> {
        backend.clipboard_on(Some("wayland"), Some(":0"), no_arboard)
    }

    /// The services design §6.4 and its test 16: the portal's clipboard goes
    /// with the viewer's input and only with it. It is kept when the
    /// injector is built, before its input handle is dropped, and never when
    /// the desktop left remote interaction off; it links once; a view-only
    /// session, the session's end and the next portal session drop it.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn the_portal_clipboard_goes_with_the_viewers_input_only() {
        let backend = SystemBackend::new(Source::Desktop);
        let portal = FakePortal::granted(true);
        backend.keep_portal(Box::new(portal.clone()), false);
        assert!(wayland_clipboard(&backend).is_none(), "before the injector");
        assert!(backend.wayland_injector().is_some());
        assert!(wayland_clipboard(&backend).is_some());
        assert!(wayland_clipboard(&backend).is_none(), "once");
        assert_eq!(portal.links(), 1);

        // Remote interaction off: no injector, and so no clipboard.
        let portal = FakePortal {
            clipboard: true,
            ..FakePortal::default()
        };
        backend.keep_portal(Box::new(portal.clone()), false);
        assert!(backend.wayland_injector().is_none());
        assert!(wayland_clipboard(&backend).is_none());
        assert_eq!(portal.links(), 0);

        // The clipboard not asked for (`[services] wayland_clipboard` off),
        // or not shared by the desktop: input, and no clipboard.
        backend.keep_portal(Box::new(FakePortal::granted(false)), false);
        assert!(backend.wayland_injector().is_some());
        assert!(wayland_clipboard(&backend).is_none());

        // View-only: neither.
        let portal = FakePortal::granted(true);
        backend.keep_portal(Box::new(portal.clone()), false);
        backend.view_only();
        assert!(backend.wayland_injector().is_none());
        assert!(wayland_clipboard(&backend).is_none());

        // The session ends before its services take the clipboard.
        backend.keep_portal(Box::new(portal.clone()), false);
        assert!(backend.wayland_injector().is_some());
        backend.session_ended("s");
        assert!(wayland_clipboard(&backend).is_none());

        // The next portal session opens: the last one's clipboard is not
        // its. One that ended while it opened keeps nothing.
        backend.keep_portal(Box::new(portal.clone()), false);
        assert!(backend.wayland_injector().is_some());
        let next = FakePortal::granted(true);
        backend.keep_portal(Box::new(next.clone()), true);
        assert!(wayland_clipboard(&backend).is_none());
        assert!(backend.wayland_injector().is_none());
        assert_eq!((portal.links(), next.links()), (0, 0));

        // A portal session over by the time its clipboard is asked for.
        let over = FakePortal {
            over: true,
            ..FakePortal::granted(true)
        };
        backend.keep_portal(Box::new(FakePortal::granted(true)), false);
        assert!(backend.wayland_injector().is_some());
        *backend.portal_clipboard.lock().unwrap() = over.clip();
        assert!(wayland_clipboard(&backend).is_none());
    }

    /// A Wayland host never opens the X11 clipboard backend, whatever its
    /// `DISPLAY` (GNOME's names Xwayland) and whether or not the portal
    /// shares its clipboard or `[services] wayland_clipboard` asked for it
    /// (the services design §4.2): `no_arboard` would panic.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn a_wayland_host_never_opens_the_x11_clipboard() {
        let paths = tornect_core::Paths::from_home(PathBuf::from("/nonexistent/tornect-home"));
        for switch in [false, true] {
            let backend = SystemBackend::new(Source::Desktop).with_portal(&paths, switch);
            for display in [Some(":0"), Some(":1"), Some("localhost:10.0"), None] {
                let on = |backend: &SystemBackend| {
                    backend.clipboard_on(Some("wayland"), display, no_arboard)
                };
                assert!(on(&backend).is_none(), "no portal session");
                backend.keep_portal(Box::new(FakePortal::granted(false)), false);
                assert!(backend.wayland_injector().is_some());
                assert!(on(&backend).is_none(), "the portal shares none");
                backend.keep_portal(Box::new(FakePortal::granted(true)), false);
                assert!(backend.wayland_injector().is_some());
                assert!(on(&backend).is_some(), "the portal's");
            }
        }
    }

    /// The X11 clipboard opens under the X11 injector's gate and nowhere
    /// else: an X11 session on this machine's own display, never another
    /// machine's, never a session that is neither X11 nor Wayland; a backend
    /// that does not open shares nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_x11_clipboard_opens_only_where_the_x11_injector_would() {
        let calls = std::cell::Cell::new(0);
        let arboard = || {
            calls.set(calls.get() + 1);
            Ok(ClipboardLink::pair().0)
        };
        let backend = SystemBackend::new(Source::Desktop);
        assert!(
            backend
                .clipboard_on(Some("x11"), Some(":0"), arboard)
                .is_some()
        );
        assert_eq!(calls.get(), 1);
        for (session, display) in [
            (Some("x11"), Some("localhost:10.0")),
            (Some("x11"), Some("otherhost:0")),
            (Some("x11"), None),
            (Some("tty"), Some(":0")),
            (Some(""), Some(":0")),
            (None, Some(":0")),
        ] {
            assert!(
                backend.clipboard_on(session, display, arboard).is_none(),
                "{session:?} {display:?}"
            );
        }
        assert_eq!(calls.get(), 1, "opened outside the gate");
        let refused = || {
            Err(tornect_input::clipboard::ClipboardError::Unavailable(
                "no X display",
            ))
        };
        assert!(
            backend
                .clipboard_on(Some("x11"), Some(":0"), refused)
                .is_none()
        );
    }

    /// The wiring to the real X11 backend: on an X11 session on this
    /// machine's own display, the desktop's clipboard is arboard's link, new
    /// and inactive. Under an X server: `xvfb-run -a env XDG_SESSION_TYPE=x11
    /// cargo test -p tornect-session --lib backend::tests::on_an_x11 --
    /// --ignored`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs an X server (Xvfb)"]
    fn on_an_x11_session_the_desktop_clipboard_is_arboards() {
        assert_eq!(
            std::env::var("XDG_SESSION_TYPE").as_deref(),
            Ok("x11"),
            "run under `env XDG_SESSION_TYPE=x11`"
        );
        let link = SystemBackend::new(Source::Desktop)
            .open_clipboard("s")
            .expect("arboard's link on this display");
        assert!(!*link.active.borrow(), "a new link is inactive");
    }
}
