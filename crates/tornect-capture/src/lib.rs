//! Tornect screen capture (`docs/PLAN.md` §B.5): the [`VideoSource`] trait, a
//! synthetic test card that runs anywhere, and the vertical slice's backends
//! (decision M3-1, `docs/research/slice.md` §4–§6), each compiled only on its
//! OS: `wayland` (the RemoteDesktop portal and PipeWire, input included) on a
//! Wayland session, `x11` on an X11 session, and `gdi` on Windows.
//!
//! Every source hands out tightly packed BGRx pictures, the format
//! `tornect-codec` encodes without a conversion. `unsafe` is allowed only at
//! FFI edges, each block with a `// SAFETY:` comment.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::time::{Duration, Instant};

// Only the X11 grab lacks a cursor; GDI draws its own with `DrawIconEx`.
#[cfg(any(target_os = "linux", test))]
mod cursor;
#[cfg(windows)]
pub mod gdi;
pub mod synthetic;
// The PipeWire structures are mirrored for LP64 only.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod wayland;
#[cfg(target_os = "linux")]
pub mod x11;

pub use synthetic::TestCard;

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
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("bytes", &self.bgrx.len())
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
}
