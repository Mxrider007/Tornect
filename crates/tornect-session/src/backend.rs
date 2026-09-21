//! What this build captures and injects with, per OS (decision M3-1): X11 on
//! an X11 session, GDI and `SendInput` on Windows, and the synthetic test card
//! everywhere. The Wayland backend (RemoteDesktop portal + PipeWire) comes next.

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
#[derive(Debug, Clone, Copy)]
pub struct SystemBackend {
    source: Source,
}

impl SystemBackend {
    /// Share `source`.
    #[must_use]
    pub fn new(source: Source) -> Self {
        Self { source }
    }
}

impl MediaBackend for SystemBackend {
    fn open_source(&self) -> Result<Box<dyn VideoSource>, CaptureError> {
        match self.source {
            Source::TestCard => {
                let (width, height, fps) = CARD;
                Ok(Box::new(TestCard::new(width, height, fps)))
            }
            Source::Desktop => desktop_source(),
        }
    }

    fn open_injector(&self) -> Option<Box<dyn InputSink>> {
        match self.source {
            Source::TestCard => None,
            Source::Desktop => desktop_injector(),
        }
    }
}

#[cfg(target_os = "linux")]
fn desktop_source() -> Result<Box<dyn VideoSource>, CaptureError> {
    match tornect_capture::x11::X11Capture::open() {
        Ok(capture) => Ok(Box::new(capture)),
        Err(CaptureError::Unavailable(why)) if session_type().as_deref() == Some("wayland") => {
            Err(CaptureError::Unavailable(format!(
                "{why}; Wayland capture (the RemoteDesktop portal) is not built yet, so this \
                 host can share only the test card (`tornect host --capture test-card`)"
            )))
        }
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn desktop_source() -> Result<Box<dyn VideoSource>, CaptureError> {
    Ok(Box::new(tornect_capture::gdi::GdiCapture::open()?))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn desktop_source() -> Result<Box<dyn VideoSource>, CaptureError> {
    Err(CaptureError::Unavailable(
        "this build has no screen capture for this OS yet".to_owned(),
    ))
}

/// XTEST reaches only X11 clients under Xwayland, so input is injected only
/// where capture shows the X11 desktop.
#[cfg(target_os = "linux")]
fn desktop_injector() -> Option<Box<dyn InputSink>> {
    if session_type().as_deref() != Some("x11") {
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

#[cfg(windows)]
fn desktop_injector() -> Option<Box<dyn InputSink>> {
    Some(Box::new(tornect_input::windows::SendInputSink::new()))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn desktop_injector() -> Option<Box<dyn InputSink>> {
    None
}

#[cfg(target_os = "linux")]
fn session_type() -> Option<String> {
    std::env::var("XDG_SESSION_TYPE").ok()
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

    /// On a Wayland desktop (this dev VM) the desktop source refuses and says
    /// what works instead; on X11 it grabs.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_desktop_source_grabs_x11_or_refuses_honestly() {
        match SystemBackend::new(Source::Desktop).open_source() {
            Ok(source) => assert_eq!(source.name(), "x11"),
            Err(CaptureError::Unavailable(why)) => {
                if session_type().as_deref() == Some("wayland") {
                    assert!(why.contains("--capture test-card"), "{why}");
                }
            }
            Err(e) => panic!("{e}"),
        }
    }
}
