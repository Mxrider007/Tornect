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
//! | on a direct connection, a `Bind` binds only the link's own session, from its pinned peer, under a MAC over the connection's exporter; the host proves itself with `BindProof` before capture opens; one claim per session across both paths, published; the signed transport policy decides which paths may claim (the direct design §6.6) | [`MediaHost::serve_direct`], [`MediaHost::claimed`] |
//! | the host binds nothing before the viewer's first `CANDIDATES`, nothing for a `tor_only` session or for its own device, at most one link per session; the link closes on the viewer's fallback, the onion path's claim, a kill, a refused `Bind`, the linger and the session's end; a `lan_only` session with no direct path ends `BYE{NO_LAN_PATH}` (the direct design §4, §8.5) | [`DirectHost`] |
//! | the viewer decides a session's path from its signed accept alone: no media, an old host, its own device and every `tor_only` cell send `TOR_FALLBACK` with no call to the network; a try is capped at `punch_timeout` from the accept, closes its link before its `TOR_FALLBACK`, takes at most 6 `CANDIDATES` and one `DONE` from the host and none above its scope; a `lan_only` session with no same-site path ends `BYE{NO_LAN_PATH}`; the caller's stop ends it within one poll, a host `PING` included (the direct design §4, §8.5) | [`decide`], [`ViewerDirect::choose_path`] |
//! | on a direct connection, the viewer reads nothing from the host, decodes no picture and sends no input before the host's `BindProof` checks in constant time; after its `Bind` it falls back to the onion path only when a TLS alert closed the connection before any host byte (the direct design §6.6, DIRECT-2) | [`Binding::direct`], [`MediaViewer::bind`], [`direct::after_bind_close`] |
//! | view-only input is never decoded or injected | a view-only session has no injector |
//! | an input rate cap | [`flow::TokenBucket`] |
//! | bounded reads, and a bounded window of unacknowledged video | `tornect_proto::MAX_CLIENT_FRAME`, [`flow::AckWindow`] |
//! | the viewer sizes pictures from what it decodes, never from `BindOk` | [`FrameSink::picture`] |
//! | everything held is released when the session ends | `tornect_input::Tracked`, dropped on every exit path |
//! | a keyframe after a decode error | [`MediaViewer`]; the host bounds the rate with [`flow::KeyframeLimiter`] |
//! | capture opens at the host's own rate, whatever preset the viewer names (the quality design §5) | [`SourceRequest`], [`quality::capture_fps`] |
//! | the viewer's quality picks are bounded by the host's table and cannot multiply its work (the quality design §5) | [`quality::settings`], [`flow::QualityGate`] and the [`flow::KeyframeLimiter`] that `KeyframeRequest` shares |
//! | what the host says it applies and its means are display-only, and a host that repeats them cannot flood the viewer's display (the quality design §5.12) | [`FrameSink::quality`] (only changes), [`FrameSink::host_stats`] (at most one per 900 ms) |
//! | a host of another version is said to be one (the quality design §4.7) | [`ViewerError::Version`] |
//! | input made against an earlier picture never lands on a remapped screen (the monitors design's H5) | the `VideoAck` barrier in [`MediaHost`]; an injector that cannot follow the picture ends the session's input (`notice::INPUT_LOST`) |
//! | a viewer's choice of screen costs the host one switch at a time, and the viewer never waits on it for good (the monitors design's H2, V1, V3) | the host's budget and `switch_answer`; [`MediaViewer::run_with`] sends one request at a time and gives it up after [`SWITCH_WAIT`] |
//! | a session's services follow its capture: nothing before its first picture, files and the clipboard only while the viewer's input reaches the desktop, nothing once capture stops, however it stops (the services design §2.2, §6.2) | [`CaptureState`], which [`MediaHost`] publishes from the media stream (`Stopped` by a drop guard on every exit, a panic included) |
//! | one services stream per session, bound with its own MAC, never with the media stream's (the services design §3.3) | [`MediaHost`]'s registry |
//! | no services frame is decoded for a cap the session was never granted: view-only gets chat at most (the services design §3.2) | the services reader's gate ([`services::ServicesHost`], `tornect_proto::services::ty::gate`) |
//! | no `Welcome` before capture is live; services end when capture stops (the services design §2.2) | [`services::ServicesHost`], which follows [`CaptureState`] |
//! | files and the clipboard need a Control session whose input reaches the desktop, and go for good when that input is lost (the services design §2.1) | [`services::eligible`], [`services::granted`], and [`services::ServicesHost`] on `INPUT_LOST` |
//! | a chat line never waits behind file data, and a viewer that stops reading cannot make the host queue without bound (the services design §3.4) | the services writer's queues |
//! | clipboard text crosses only while the viewer's switch is on: the host's link is active only then, and text received becomes clipboard text only through `ClipText::from_peer` (control characters removed, NUL refused), at a bounded rate and within the bulk window (the services design §2.4, §3.4, §4) | `services::clip`, behind [`services::ServicesHost`] and [`services::ServicesViewer`] |
//! | chat text is shown plain, without control, bidi or invisible characters, at a bounded rate (the services design §3.4, §6.1) | [`services::sanitize_peer_text`], [`services::CHAT_RATE`] |
//! | Tornect's own files are never listed or sent, by either end: only files under a place, never under Tornect's folders, another Tornect home (its private marker) or a part file, judged on the canonical path, which is the one opened (the services design §5.2) | [`services::Access`], which the viewer applies to every file it sends |
//! | the viewer never names a path of the host's: it lists and copies by the handles the host gave out, each judged again by the host's [`services::Access`] at its `List` or `Get`; a folder comes one page per `List` the viewer sent, so a large one cannot fill the stream (the services design §3.5, §5.2) | [`services::ServicesHost`]'s listings and downloads |
//!
//! Consent gating is structural. A media stream is served only for a session
//! the FSM accepted, and only to a peer that holds that session's token.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod direct;
pub mod flow;
pub mod host;
pub mod quality;
pub mod services;
pub mod viewer;

pub use backend::{DesktopBackend, Source, SystemBackend, TEST_SCREENS};
pub use direct::{
    AfterBind, DIRECT_DRAIN, Decision, DirectBindFailed, DirectHost, DirectHostStats, DirectMedia,
    DirectOptions, DirectSettings, DirectStream, FallbackWhy, HOST_DIRECT_LINGER, INTERNET_DIRECT,
    Mine, OnMedia, PathChoice, PathEnd, SecondStream, TorWhy, ViewerDirect, ViewerDirectStats,
    after_bind_close, decide, from_wire, to_wire,
};
pub use host::{
    CaptureChanged, CaptureStarted, CaptureState, MediaBackend, MediaEnd, MediaHost, MediaLimits,
    MediaObserver, MediaOutcome, MediaReport, NoObserver, SourceRequest,
};
pub use tornect_net::QuicStream;
pub use viewer::{
    Binding, BoundStream, FrameSink, MediaViewer, SWITCH_WAIT, Screens, ScreensNews,
    ViewerChannels, ViewerEnd, ViewerError, ViewerRequest, ViewerStats,
};

#[cfg(test)]
mod tests;
