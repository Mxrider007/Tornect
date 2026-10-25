//! Tornect screen capture (`docs/PLAN.md` §B.5): the [`VideoSource`] trait, a
//! synthetic test card that runs anywhere, and the vertical slice's backends
//! (decision M3-1, `docs/research/slice.md` §4–§6), each compiled only on its
//! OS: `wayland` (the RemoteDesktop portal and PipeWire, input included) on a
//! Wayland session, `x11` on an X11 session, and `gdi` on Windows.
//!
//! Every source hands out tightly packed BGRx pictures, the format
//! `tornect-codec` encodes without a conversion. `unsafe` is allowed only at
//! FFI edges, each block with a `// SAFETY:` comment.
//!
//! A source that can show one of several monitors describes them in a
//! [`Layout`] and switches with [`VideoSource::select`] (decision M1-75, the
//! monitors design §5.4): the layout says which monitor the picture shows,
//! and its [`View`] where that picture lies on the desktop the injector
//! addresses, so the host maps the viewer's pointer onto exactly that.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

// Only the X11 grab lacks a cursor; GDI draws its own with `DrawIconEx`.
#[cfg(any(target_os = "linux", test))]
mod cursor;
#[cfg(windows)]
pub mod gdi;
// Which monitor a source shows; pure logic, on every system.
mod monitors;
// GDI's way through a secure Windows screen; tested on every system.
#[cfg(any(windows, test))]
mod outage;
pub mod synthetic;
// The PipeWire structures are mirrored for LP64 only.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod wayland;
#[cfg(target_os = "linux")]
pub mod x11;

pub use synthetic::{TestCard, TestScreens};
pub use tornect_input::{Ratio, Rect, View};

/// The most monitors a [`Layout`] lists (the media stream's
/// `tornect_proto::MAX_MONITORS`).
pub const MAX_MONITORS: usize = 16;

/// One monitor a source can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Monitor {
    /// `1..=n`, in the order of the layout: by x, then by y.
    pub id: u8,
    /// The desktop's primary monitor (at most one in a layout).
    pub primary: bool,
    /// Where it lies on the desktop, in the desktop's units: physical pixels
    /// of the Windows virtual desktop, pixels of the X11 root, logical
    /// pixels on Wayland (a size of 0×0 when it is not known).
    pub rect: Rect,
}

/// What a source is asked to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// Every monitor at once, in one picture.
    All,
    /// The monitor with this [`Monitor::id`].
    Monitor(u8),
}

/// What a source's monitors are and what its picture shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The monitors, numbered 1..n by position; at most [`MAX_MONITORS`].
    pub monitors: Vec<Monitor>,
    /// The source can show all of them at once (only with two or more).
    pub all: bool,
    /// What the picture shows.
    pub shown: Selection,
    /// Where that picture lies, for the injector: on GDI and X11 a
    /// [`View::Rect`] whose `shown` is the even rectangle the picture shows.
    pub view: View,
}

/// One captured picture: tightly packed BGRx rows, `4 × width × height` bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// B, G, R, X per pixel, row after row, no padding.
    pub bgrx: Vec<u8>,
    /// When the picture was taken.
    pub captured_at: Instant,
    /// The source's own cost to produce this picture (the copy, the pack,
    /// the grab, the render), not the time spent waiting for one.
    pub grab: Duration,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("bytes", &self.bgrx.len())
            .field("grab", &self.grab)
            .finish_non_exhaustive()
    }
}

/// Capture failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaptureError {
    /// This source cannot work here (wrong session type, no display, …).
    #[error("capture unavailable: {0}")]
    Unavailable(String),
    /// The source failed while running.
    #[error("capture failed: {0}")]
    Failed(String),
    /// A selection named a monitor the source does not have, or all of them
    /// (0) where it cannot show them at once.
    #[error("no monitor {0} to show (0 stands for all of them)")]
    NoMonitor(u8),
}

/// A source of screen pictures.
///
/// The session layer pulls: it asks for the next picture at the pace it can
/// encode and send. A source that learns about changes (PipeWire delivers
/// frames only on damage) answers `Ok(None)` when nothing new arrived within
/// `timeout`; a polling source (X11, GDI) grabs the screen on every call.
pub trait VideoSource: Send {
    /// A short name for logs (`"synthetic"`, `"x11"`, `"wayland"`, `"gdi"`).
    fn name(&self) -> &'static str;

    /// The next picture, waiting at most `timeout`.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError>;

    /// The consumer is done with `bgrx`, the buffer of a picture this source
    /// gave out: a source may keep it to put a later picture in, rather than
    /// allocate one per picture. The default lets go of it.
    fn recycle(&mut self, _bgrx: Vec<u8>) {}

    /// The monitors, and what the picture [`Self::next_frame`] returned last
    /// shows; `None` for a source with nothing to choose (the default).
    fn layout(&self) -> Option<Layout> {
        None
    }

    /// Show `selection` from the next picture on: after `Ok`, the next
    /// picture [`Self::next_frame`] returns is of the new selection.
    /// [`CaptureError::NoMonitor`] for a monitor the last layout does not
    /// list, or all of them where it does not offer that. It may block, at
    /// most 10 s, and returns within 100 ms of `stop` being set. The default
    /// refuses: the source shows one picture.
    fn select(&mut self, _selection: Selection, _stop: &AtomicBool) -> Result<(), CaptureError> {
        Err(CaptureError::Unavailable(
            "this source shows one picture".to_owned(),
        ))
    }
}
