//! Tornect session orchestration (`docs/PLAN.md` §B.1, §B.2): what runs a
//! session once the handshake on the signaling stream has reached
//! `SESSION_ACCEPT`.
//!
//! In the vertical slice (decisions M1-39, M3-1) media travels on a second
//! onion stream, `tornect_signal::MEDIA_PORT`, in `tornect-proto`'s format:
//!
//! - [`MediaHost`] is the host half. It is a
//!   [`SessionSink`](tornect_signal::fsm::host::SessionSink), so the handshake
//!   FSM tells it which sessions are live. It serves a media stream only after
//!   the stream proves with a `Bind` that it belongs to one of them. Capture
//!   starts only after that proof (§B.6) and stops when the session ends,
//!   however it ends.
//! - [`MediaViewer`] is the client half. It binds, then decodes and
//!   acknowledges.
//!
//! The slice review (SLICE-A2 A2-3, A2-4, A2-6; SLICE-A1 G3) placed these
//! requirements on this layer:
//!
//! | Requirement | Where it is met |
//! |---|---|
//! | a `Bind` deadline; no unbound stream holds a circuit open for long | [`MediaLimits::bind_deadline`], [`MediaLimits::max_waiting`] |
//! | a single-use `Bind`: one media stream per session | [`MediaHost`]'s registry |
//! | view-only input is never decoded or injected | a view-only session has no injector |
//! | an input rate cap | [`flow::TokenBucket`] |
//! | bounded reads, and a bounded window of unacknowledged video | `tornect_proto::MAX_CLIENT_FRAME`, [`flow::AckWindow`] |
//! | the viewer sizes pictures from what it decodes, never from `BindOk` | [`FrameSink::picture`] |
//! | everything held is released when the session ends | `tornect_input::Tracked`, dropped on every exit path |
//! | a keyframe after a decode error | [`MediaViewer`]; the host bounds the rate with [`flow::KeyframeLimiter`] |
//!
//! Consent gating is structural. A media stream is served only for a session
//! the FSM accepted, and only to a peer that holds that session's token.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod flow;
pub mod host;
pub mod quality;
pub mod viewer;

pub use backend::{DesktopBackend, Source, SystemBackend};
pub use host::{
    CaptureStarted, MediaBackend, MediaEnd, MediaHost, MediaLimits, MediaObserver, MediaOutcome,
    MediaReport, NoObserver,
};
pub use viewer::{
    Binding, BoundStream, FrameSink, MediaViewer, ViewerEnd, ViewerError, ViewerStats,
};

#[cfg(test)]
mod tests;
