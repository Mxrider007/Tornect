//! What this build captures and injects with, per OS (decision M3-1): the
//! RemoteDesktop portal and PipeWire on a Wayland session, X11 on an X11
//! session, GDI and `SendInput` on Windows, and the synthetic test card
//! everywhere.

use std::path::PathBuf;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use std::sync::{Mutex, PoisonError};

use tornect_capture::{CaptureError, TestCard, VideoSource};
use tornect_input::InputSink;

use crate::host::MediaBackend;

/// Size and rate of the shared test card: enough for the index strip to
/// survive the encoder, small enough for a Tor circuit.
const CARD: (u32, u32, u32) = (1280, 720, 15);

/// What a host shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Source {
    /// The desktop, with this OS's backend.
    #[default]
    Desktop,
    /// The synthetic test card. No desktop is shared, and the viewer's input
    /// goes nowhere: there is nothing behind the card to control.
    TestCard,
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
    /// What an injector into the last Wayland source's portal session is
    /// built from. `open_injector` has no other way to reach the session
    /// `open_source` opened; the media host asks the two in that order for
    /// one session, and M1 serves one session at a time. It holds the session
    /// weakly, so it keeps nothing open once capture stops.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    wayland_input: Mutex<Option<tornect_capture::wayland::WaylandInput>>,
    /// Ends the Wayland open in flight: set while `open_source` waits on the
    /// portal (and its dialog), taken by `cancel_open`.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    opening: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
}

impl SystemBackend {
    /// Share `source`. On Wayland the desktop asks at every session; see
    /// [`SystemBackend::with_restore_token`].
    #[must_use]
    pub fn new(source: Source) -> Self {
        Self {
            source,
            restore_token: None,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            wayland_input: Mutex::new(None),
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            opening: Mutex::new(None),
        }
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
    fn open_source(&self) -> Result<Box<dyn VideoSource>, CaptureError> {
        match self.source {
            Source::TestCard => {
                let (width, height, fps) = CARD;
                Ok(Box::new(TestCard::new(width, height, fps)))
            }
            Source::Desktop => self.desktop_source(),
        }
    }

    fn open_injector(&self) -> Option<Box<dyn InputSink>> {
        match self.source {
            Source::TestCard => None,
            Source::Desktop => self.desktop_injector(),
        }
    }

    /// Drops the Wayland portal session's input handle: the session still
    /// holds the desktop's keyboard-and-pointer grant, and nothing may build
    /// an injector into it for a view-only viewer.
    fn view_only(&self) {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        self.wayland_input
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    /// Ends a Wayland open that waits on the desktop's dialog: the portal
    /// session is closed, which takes the dialog down, and no restore token
    /// is kept for a session that is over.
    fn cancel_open(&self) {
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        if let Some(cancel) = self
            .opening
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            cancel.send_replace(true);
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
    fn desktop_source(&self) -> Result<Box<dyn VideoSource>, CaptureError> {
        match desktop_for(session_type().as_deref()) {
            Desktop::Wayland => self.wayland_source(),
            Desktop::X11 => Ok(Box::new(tornect_capture::x11::X11Capture::open()?)),
        }
    }

    fn desktop_injector(&self) -> Option<Box<dyn InputSink>> {
        let session = session_type();
        match desktop_for(session.as_deref()) {
            Desktop::Wayland => self.wayland_injector(),
            // XTEST reaches only X11 clients under Xwayland, so input is
            // injected only where capture shows the X11 desktop, and over the
            // part of it the encoder sends (SLICE-C1 C1-2); never into another
            // machine's display (SLICE-C3 C3-3).
            Desktop::X11 if session.as_deref() == Some("x11") => {
                let display = std::env::var("DISPLAY").ok();
                if !tornect_capture::x11::display_is_local(display.as_deref()) {
                    tracing::warn!(
                        "DISPLAY is not this machine's own display: the viewer's input is dropped"
                    );
                    return None;
                }
                match tornect_input::x11::XTestSink::connect() {
                    Ok(sink) => Some(Box::new(sink.over(tornect_codec::encoded_size))),
                    Err(e) => {
                        tracing::warn!(error = %e, "XTEST is unavailable: the viewer's input is dropped");
                        None
                    }
                }
            }
            Desktop::X11 => None,
        }
    }
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl SystemBackend {
    /// Opens the portal session: the desktop's dialog, unless the restore
    /// token still holds.
    fn wayland_source(&self) -> Result<Box<dyn VideoSource>, CaptureError> {
        use tornect_capture::wayland::{WaylandOptions, WaylandSource};
        let (cancel, cancelled) = tokio::sync::watch::channel(false);
        *self.opening.lock().unwrap_or_else(PoisonError::into_inner) = Some(cancel);
        let mut options = WaylandOptions::new(self.restore_token.clone());
        options.cancel = Some(cancelled);
        let opened = WaylandSource::open(&options);
        self.opening
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let (source, input) = opened?;
        *self
            .wayland_input
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(input);
        Ok(Box::new(source))
    }

    /// The injector into the session `wayland_source` opened, mapping the
    /// viewer's pointer over what the encoder sends (SLICE-C1 C1-2).
    fn wayland_injector(&self) -> Option<Box<dyn InputSink>> {
        let input = self
            .wayland_input
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()?;
        match input.injector(tornect_codec::encoded_size) {
            Ok(injector) => Some(Box::new(injector)),
            Err(e) => {
                tracing::warn!(error = %e, "the viewer's input is dropped");
                None
            }
        }
    }
}

#[cfg(all(target_os = "linux", not(target_pointer_width = "64")))]
impl SystemBackend {
    fn wayland_source(&self) -> Result<Box<dyn VideoSource>, CaptureError> {
        Err(CaptureError::Unavailable(
            "Wayland capture is built for 64-bit Linux only".to_owned(),
        ))
    }

    fn wayland_injector(&self) -> Option<Box<dyn InputSink>> {
        None
    }
}

#[cfg(windows)]
impl SystemBackend {
    fn desktop_source(&self) -> Result<Box<dyn VideoSource>, CaptureError> {
        Ok(Box::new(tornect_capture::gdi::GdiCapture::open()?))
    }

    /// Over the part of the virtual desktop the encoder sends (SLICE-C1 C1-2).
    fn desktop_injector(&self) -> Option<Box<dyn InputSink>> {
        Some(Box::new(
            tornect_input::windows::SendInputSink::new().over(tornect_codec::encoded_size),
        ))
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
impl SystemBackend {
    fn desktop_source(&self) -> Result<Box<dyn VideoSource>, CaptureError> {
        Err(CaptureError::Unavailable(
            "this build has no screen capture for this OS yet".to_owned(),
        ))
    }

    fn desktop_injector(&self) -> Option<Box<dyn InputSink>> {
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
        let mut source = backend.open_source().unwrap();
        assert_eq!(source.name(), "synthetic");
        let frame = source.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!((frame.width, frame.height), (CARD.0, CARD.1));
        assert!(backend.open_injector().is_none());
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
        match SystemBackend::new(Source::Desktop).open_source() {
            Ok(source) => assert_eq!(source.name(), "x11"),
            Err(CaptureError::Unavailable(why)) => assert!(!why.is_empty()),
            Err(e) => panic!("{e}"),
        }
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
    /// a host part, the desktop backend neither captures nor injects, and
    /// never connects to that display. A child run of this test gets that
    /// environment; here a listener plays the other machine's X server, and
    /// nothing may reach it.
    #[cfg(target_os = "linux")]
    #[test]
    fn another_machines_display_is_neither_captured_nor_driven() {
        const CHILD: &str = "TORNECT_TEST_REMOTE_DISPLAY_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let backend = SystemBackend::new(Source::Desktop);
            let refused = backend
                .open_source()
                .err()
                .expect("captured another machine's display");
            assert!(
                refused
                    .to_string()
                    .contains("is not this machine's own display"),
                "{refused}"
            );
            assert!(backend.open_injector().is_none());
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
}
