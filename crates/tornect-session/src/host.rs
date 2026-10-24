//! The host half of the media layer: which sessions may bind a media stream,
//! and the pipeline that serves one.
//!
//! A media stream is served in three steps.
//!
//! 1. **Bind.** The first frame must be a `Bind`. It must arrive complete
//!    within [`MediaLimits::bind_deadline`], and it is read at its fixed size,
//!    so an unbound peer holds nothing for long and costs the host 50 bytes.
//!    The session must be live and not yet bound, and the MAC must verify
//!    under that session's token and `th_final` (`tornect_proto::bind_mac_ok`,
//!    constant time). Reading a `Bind` takes no slot: a live session's viewer
//!    is claimed as soon as its `Bind` arrives, and only a `Bind` for a session
//!    not registered yet waits, [`MediaLimits::max_waiting`] at a time. Streams
//!    that squat the slots therefore cannot starve a real viewer (SLICE-C1
//!    C1-1); how many streams are open at once is the caller's bound (the
//!    listener's: 4 per circuit).
//! 2. **Capture.** Only now is the source opened (§B.6), for the host's own
//!    capture rate ([`SourceRequest`]), whatever preset the viewer named. A
//!    capture thread makes one picture per credit, and credits come from the
//!    ack window, so nothing is captured that could not be sent.
//! 3. **Serve**, until the session ends (the FSM's `on_end`: `BYE`, the kill
//!    switch, a timeout), the viewer leaves, or something breaks. The viewer's
//!    frames (input, acks, pings, quality picks, `Close`) are handled by one
//!    code path, also while a write to the viewer waits on flow control. Every
//!    exit path stops capture and drops the injector, which releases whatever
//!    the viewer still holds.
//!
//! The stream runs the preset its `Bind` names ([`quality::settings`], every
//! number from the host's table under its `[media]` caps), and the viewer may
//! pick another with `SetQuality` at any time. A pick costs a store; the host
//! acts on the latest at most once per [`MediaLimits::quality_interval`]
//! ([`QualityGate`]), and a rebuild of the encoder, an IDR, also spends the
//! turn of the keyframe limiter that `KeyframeRequest` uses. Each change of
//! settings or of picture size is said in a `Quality` before the first picture
//! it covers, and the per-stage means go out in a `Stats` about once per
//! [`MediaLimits::stats_every`], before a picture (the quality design §6.6).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Notify, Semaphore, mpsc, watch};
use tornect_capture::{CaptureError, Frame, VideoSource};
use tornect_codec::H264Encoder;
use tornect_codec::scale::Scaler;
use tornect_core::config::{Media, QualityPreset};
use tornect_core::levels::Elevation;
use tornect_core::session_log::SessionMode;
use tornect_input::{InputError, InputEvent, InputSink, Tracked};
use tornect_proto::{
    BIND_TYPE, MAX_CLIENT_FRAME, MAX_FRAME, Msg, ProtoError, SESSION_ID_LEN, codec, read_msg_max,
    reason, video_flags, write_msg,
};
use tornect_signal::consent::{SessionToken, mode_code};
use tornect_signal::fsm::host::{KillSwitch, LiveSession, SessionEnd, SessionSink};
use tornect_signal::messages::notice;

use crate::flow::{AckWindow, KeyframeLimiter, QualityGate, StageTimes, StatsWindow, TokenBucket};
use crate::quality::{self, QualityCaps, Route, StreamSettings};

/// How often the capture thread checks its stop flag, and a quality change,
/// while it waits.
pub(crate) const POLL: Duration = Duration::from_millis(100);
/// How long the host waits, at the end, for the capture thread to exit.
const STOP_WAIT: Duration = Duration::from_secs(5);
/// Bound on the last frame (a refusal, a `Close`) written to a peer that may
/// not be reading.
const LAST_WRITE: Duration = Duration::from_secs(5);
/// Client frames queued between the reader and the session loop. Beyond that
/// the reader stops reading, and Tor's flow control holds the client back.
const INBOUND_DEPTH: usize = 64;
/// `Ping`s answered per second on average; more are ignored.
const PINGS_PER_SEC: u32 = 5;
/// `Ping`s answered at once.
const PING_BURST: u32 = 10;
/// A `Bind` frame: the type byte, the session id, the MAC, the preset.
const BIND_LEN: usize = 1 + SESSION_ID_LEN + 32 + 1;
/// What a `Video` frame adds to its access unit: the type byte, `seq`,
/// `flags` and `ts_ms`. An access unit longer than `MAX_FRAME` less this
/// cannot be framed.
const VIDEO_OVERHEAD: usize = 1 + 4 + 1 + 4;

/// The host's bounds on media streams.
#[derive(Debug, Clone, Copy)]
pub struct MediaLimits {
    /// How long a new media stream has to deliver its `Bind` and find its
    /// session. An unbound stream holds its rendezvous circuit open, so it
    /// must not linger (SLICE-A1 G3).
    pub bind_deadline: Duration,
    /// `Bind`s waiting at once for a session the FSM has not registered yet
    /// (it registers just after `SESSION_ACCEPT`, and a fast viewer can beat
    /// it). One beyond that is refused at once.
    pub max_waiting: usize,
    /// How long capture may take, after the bind, to deliver its first picture.
    pub first_frame_deadline: Duration,
    /// The most access units in flight before the host waits for a
    /// `VideoAck`. Each preset's window is derived from its frame rate
    /// ([`quality::window`]) and held to this.
    pub window_frames: usize,
    /// The most bytes in flight before the host waits for a `VideoAck`. Each
    /// preset's window is derived from its bitrate ([`quality::window`]) and
    /// held to this.
    pub window_bytes: usize,
    /// Input events a control viewer may inject per second, on average.
    /// Releases (key-up, button-up, `ReleaseAll`) do not count and are never
    /// dropped (SLICE-E E1-6).
    pub input_rate: u32,
    /// Input events a control viewer may inject at once (releases aside).
    pub input_burst: u32,
    /// Least time between two keyframes forced by `KeyframeRequest`.
    pub keyframe_interval: Duration,
    /// How long a control viewer may say nothing (no input, ack or ping)
    /// before the keys and buttons it holds are released (SLICE-C1 C1-3),
    /// counted from the last frame read, also while a write to the viewer
    /// waits (slice-G G2-1).
    pub viewer_quiet: Duration,
    /// The host's bounds on every preset, from its `[media]`
    /// ([`MediaLimits::with_media`]).
    pub caps: QualityCaps,
    /// Least time between two actions on the viewer's quality picks (an
    /// encoder rebuild, or saying again what applies).
    pub quality_interval: Duration,
    /// How often the host sends the viewer its per-stage means (`Stats`).
    pub stats_every: Duration,
}

impl Default for MediaLimits {
    fn default() -> Self {
        Self {
            bind_deadline: Duration::from_secs(10),
            max_waiting: 8,
            first_frame_deadline: Duration::from_secs(10),
            // Caps on the derived windows (the quality design §3.1): Best
            // performance's 20 fps over a 1.5 s span needs 30 in flight, Best
            // quality's 4 Mbit/s 750 000 bytes. (At 8 in flight, a Tor round
            // trip of 1.0–1.3 s held the test card to 6.3 fps, live run of
            // 2026-09-21.)
            window_frames: 32,
            window_bytes: 1024 * 1024,
            input_rate: 250,
            input_burst: 500,
            keyframe_interval: Duration::from_secs(1),
            // The viewer pings every second when it has nothing else to say.
            viewer_quiet: Duration::from_secs(3),
            caps: QualityCaps::default(),
            quality_interval: Duration::from_secs(2),
            stats_every: Duration::from_secs(1),
        }
    }
}

impl MediaLimits {
    /// The defaults, with the preset caps of the host's `[media]`. A value
    /// out of its range is held to it, and said once at warn: the config
    /// still loads, as it did before the presets.
    #[must_use]
    pub fn with_media(media: &Media) -> Self {
        let (caps, notes) = QualityCaps::from_media(media);
        for note in &notes {
            tracing::warn!("{note}");
        }
        Self {
            caps,
            ..Self::default()
        }
    }
}

/// What a source is opened for ([`MediaBackend::open_source`]). It comes from
/// the host's config and the stream's route only, never from anything the
/// viewer sent: every preset opens capture alike, and a preset change never
/// reopens it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRequest {
    /// The highest rate to capture at ([`quality::capture_fps`]); the
    /// encoder paces each preset's own, which is never higher.
    pub max_fps: u32,
}

impl SourceRequest {
    /// Capture at `max_fps` at most.
    #[must_use]
    pub const fn new(max_fps: u32) -> Self {
        Self { max_fps }
    }
}

/// What a bound session captures, and where its input goes. It is asked only
/// after a verified `Bind`, which is how capture follows the accept (§B.6).
pub trait MediaBackend: Send + Sync {
    /// Open the picture source for `request`. It may block: it runs on a
    /// blocking thread.
    ///
    /// `cancel` turns `true` when the session ends, or its stream is dropped,
    /// before the open is done. The Wayland open waits on the desktop's
    /// dialog, which must not stay up, nor leave a remembered grant, for a
    /// session that is over: it ends its wait then. The value latches, and it
    /// can be `true` before this is even called (slice-G G1-1). A source that
    /// does not wait ignores it.
    fn open_source(
        &self,
        request: SourceRequest,
        cancel: watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError>;

    /// The injector for a control session, acting on what the source shows;
    /// `None` when this host cannot inject there (the viewer's input is then
    /// dropped). A view-only session never calls this.
    fn open_injector(&self) -> Option<Box<dyn InputSink>>;

    /// The injector for the control session `session_id` at the
    /// administrator level `elevation` signed in its accept (r7, §B.2.1).
    /// The default is [`Self::open_injector`]; the app's backend routes an
    /// administrator session's input through its administrator helper
    /// (§B.8.7.5).
    fn open_session_injector(
        &self,
        session_id: &str,
        elevation: Elevation,
    ) -> Option<Box<dyn InputSink>> {
        let _ = (session_id, elevation);
        self.open_injector()
    }

    /// The source just opened is for a view-only session: let go of anything
    /// kept for building its injector, so that no path can reach the desktop's
    /// input for it. The default keeps nothing.
    fn view_only(&self) {}

    /// The session `session_id` ended (its `on_end`): let go of anything kept
    /// for it that its injector never took (the app's administrator helper,
    /// §B.8.7.5). The default keeps nothing.
    fn session_ended(&self, session_id: &str) {
        let _ = session_id;
    }
}

/// Where the host reports capture starting and stopping. This is the source
/// of truth for the §B.6 sharing indicator.
pub trait MediaObserver: Send + Sync {
    /// The first picture of a session went out.
    fn capture_started(&self, started: &CaptureStarted<'_>);

    /// Capture has stopped and the source is closed.
    fn capture_stopped(&self, session_id: &str, report: &MediaReport, end: &MediaEnd);
}

/// Observes nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoObserver;

impl MediaObserver for NoObserver {
    fn capture_started(&self, _: &CaptureStarted<'_>) {}
    fn capture_stopped(&self, _: &str, _: &MediaReport, _: &MediaEnd) {}
}

/// What [`MediaObserver::capture_started`] is told.
#[derive(Debug)]
pub struct CaptureStarted<'a> {
    /// The session.
    pub session_id: &'a str,
    /// The viewer's pinned label.
    pub label: &'a str,
    /// The source ([`VideoSource::name`]).
    pub source: &'static str,
    /// Size of the first encoded picture.
    pub width: u32,
    /// Size of the first encoded picture.
    pub height: u32,
    /// Control or view-only.
    pub mode: SessionMode,
    /// Whether the viewer's input reaches this machine.
    pub input: bool,
}

/// What one media stream did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaReport {
    /// Access units sent.
    pub frames_sent: u64,
    /// Bytes of video sent.
    pub bytes_sent: u64,
    /// Keyframes among them.
    pub keyframes_sent: u64,
    /// `KeyframeRequest`s received.
    pub keyframe_requests: u64,
    /// Keyframes forced for them (at most one per [`MediaLimits::keyframe_interval`]).
    pub keyframes_forced: u64,
    /// Input events injected.
    pub input_injected: u64,
    /// Input events dropped: view-only, over the rate, no injector, or refused.
    pub input_dropped: u64,
    /// `SetQuality`s received.
    pub quality_requests: u64,
    /// Changes of preset that reached the viewer (a `Quality` naming another
    /// preset than the pictures before it).
    pub quality_changes: u64,
    /// Pictures among those sent that encode the last one again after a
    /// quality change (nothing new was captured for them).
    pub repeats: u64,
    /// `VideoAck`s that acknowledged a picture in flight.
    pub acks: u64,
    /// Sum of the source's own cost to produce each fresh picture sent
    /// (`Frame.grab`), µs; repeats have none.
    pub grab_us: u64,
    /// Sum of the time each picture sent took to fit under its cap, µs.
    pub scale_us: u64,
    /// Sum of each picture's BGRx → I420 conversion, µs.
    pub convert_us: u64,
    /// Sum of each picture's encode, µs.
    pub encode_us: u64,
    /// Sum, over the pictures sent, of the time from encoded to fully
    /// written (the queue and the stream's flow control), µs.
    pub send_us: u64,
    /// Sum, over the acks, of the time from a picture fully written to its
    /// `VideoAck`, µs.
    pub ack_us: u64,
}

/// Why a bound media stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaEnd {
    /// The session ended on the signaling stream (the viewer was sent
    /// `Close{reason}` if the stream was between frames).
    SessionOver(u16),
    /// The viewer sent `Close` or closed the stream.
    ViewerLeft,
    /// The viewer broke the protocol (`Close{PROTOCOL}` was sent).
    Protocol,
    /// Capture or encoding failed (`Close{reason}` was sent).
    Pipeline(u16),
    /// Writing to the viewer failed: it stalled or reset the stream.
    Io,
}

/// How [`MediaHost::serve`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaOutcome {
    /// Refused at once: its session is not registered, and
    /// [`MediaLimits::max_waiting`] binds were already waiting for theirs.
    Busy,
    /// No valid `Bind` in time. A `BindRefused` was sent if a frame arrived.
    NotBound,
    /// Bound, but no picture went out (capture failed, or the session ended
    /// first); `BindRefused` was sent.
    NotStarted(MediaEnd),
    /// Served until `end`.
    Served {
        /// The session.
        session_id: String,
        /// What was sent and received.
        report: MediaReport,
        /// Why it ended.
        end: MediaEnd,
    },
}

/// A session the FSM accepted, as the media layer keeps it.
struct Registered {
    token: SessionToken,
    th_final: [u8; 32],
    mode: SessionMode,
    /// The level signed in the accept.
    elevation: Elevation,
    label: String,
    bound: bool,
    /// A control session whose stream is served with no injector: its
    /// viewer's input reaches nothing here.
    no_input: bool,
    /// Set to the `Close` reason when the session ends.
    end: watch::Sender<Option<u16>>,
}

/// A successful bind.
struct Claimed {
    mode: SessionMode,
    elevation: Elevation,
    label: String,
    end: watch::Receiver<Option<u16>>,
}

enum Lookup {
    Bound(Claimed),
    Refused,
    Unknown,
}

/// The host half of the media layer.
///
/// Feed it the FSM's sessions (it is a [`SessionSink`]; forward `on_start`
/// and `on_end` to it), and hand it every stream accepted on
/// `tornect_signal::MEDIA_PORT` ([`MediaHost::serve`]).
pub struct MediaHost {
    sessions: Mutex<HashMap<String, Registered>>,
    registered: Notify,
    waiting: Arc<Semaphore>,
    backend: Arc<dyn MediaBackend>,
    observer: Arc<dyn MediaObserver>,
    limits: MediaLimits,
}

impl std::fmt::Debug for MediaHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaHost")
            .field("sessions", &self.live())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl MediaHost {
    /// A media host that captures with `backend` and reports to `observer`.
    #[must_use]
    pub fn new(
        backend: Arc<dyn MediaBackend>,
        observer: Arc<dyn MediaObserver>,
        limits: MediaLimits,
    ) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            registered: Notify::new(),
            waiting: Arc::new(Semaphore::new(limits.max_waiting.max(1))),
            backend,
            observer,
            limits,
        }
    }

    /// Sessions accepted and not yet over.
    #[must_use]
    pub fn live(&self) -> usize {
        self.lock().len()
    }

    /// End the media of every session as soon as `kill` fires.
    ///
    /// This does not wait for the FSM's `on_end`. The FSM calls `on_end` only
    /// after writing its `BYE`, and a peer that withholds flow-control credit
    /// can hold that write for the whole stall bound (SLICE-B1 B1-2); capture
    /// must not run on meanwhile. The M1 kill switch is host-wide, and so is
    /// this. The guard is armed before this returns, so a kill fired right
    /// after the call is not missed. Abort the returned task at shutdown.
    pub fn watch_kill(self: &Arc<Self>, kill: KillSwitch) -> tokio::task::JoinHandle<()> {
        let host = Arc::downgrade(self);
        let mut guard = kill.arm();
        tokio::spawn(async move {
            loop {
                guard.killed().await;
                // Armed before the sweep, so a kill during it fires again
                // instead of being folded into this one (SLICE-C1 C1-6).
                let next = kill.arm();
                let Some(host) = host.upgrade() else {
                    return;
                };
                for session in host.lock().values() {
                    session.end.send_replace(Some(reason::ENDED_BY_HOST));
                }
                guard = next;
            }
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Registered>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `code`, the notice code the host tells the viewer of session
    /// `session_id` (decision M1-70, §B.8.4.1), with what the media layer
    /// knows added: [`notice::NO_INPUT`] once the session's control stream is
    /// served with nothing to inject into. A session told nothing (`None`, a
    /// view-only one) stays told nothing. The hosts' session sinks answer
    /// [`SessionSink::notice`] with it, so the viewer of a control session
    /// whose clicks go nowhere hears why at its next `PING`.
    #[must_use]
    pub fn viewer_notice(&self, session_id: &str, code: Option<u8>) -> Option<u8> {
        let code = code?;
        let no_input = self.lock().get(session_id).is_some_and(|s| s.no_input);
        Some(if no_input {
            code | notice::NO_INPUT
        } else {
            code
        })
    }

    /// Serve one stream accepted on the onion service's media port, from its
    /// `Bind` to its end: [`Self::serve_on`] over [`Route::Tor`].
    pub async fn serve<S>(&self, stream: S) -> MediaOutcome
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_on(stream, Route::Tor).await
    }

    /// Serve one stream accepted on `route`'s listener, from its `Bind` to
    /// its end. The route is the host's: the listener that accepted the
    /// stream says it, never the viewer.
    pub async fn serve_on<S>(&self, stream: S, route: Route) -> MediaOutcome
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let deadline = tokio::time::Instant::now() + self.limits.bind_deadline;
        // The viewer's preset is read, and a code this version does not know
        // refused with the malformed binds below, before any look-up.
        let (session_id, mac, preset) = match tokio::time::timeout_at(deadline, read_bind(&mut rd))
            .await
        {
            Ok(Ok(bind)) => bind,
            Ok(Err(ProtoError::Io(e))) => {
                tracing::debug!(error = %e, "media stream closed before its bind");
                return MediaOutcome::NotBound;
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "media stream opened with something other than a bind");
                refuse(&mut wr, reason::PROTOCOL).await;
                return MediaOutcome::NotBound;
            }
            Err(_) => {
                tracing::debug!("media stream sent no bind in time");
                return MediaOutcome::NotBound;
            }
        };
        let claimed = match self.try_claim(&session_id, &mac) {
            Lookup::Bound(claimed) => Some(claimed),
            Lookup::Refused => None,
            // Its session may simply not be registered yet. Only `max_waiting`
            // binds wait for that at once, and the slot is let go before any
            // refusal is written.
            Lookup::Unknown => {
                let Ok(_waiting) = Arc::clone(&self.waiting).try_acquire_owned() else {
                    tracing::warn!(
                        max = self.limits.max_waiting,
                        "media bind refused: too many are waiting for their session"
                    );
                    refuse(&mut wr, reason::BAD_BIND).await;
                    return MediaOutcome::Busy;
                };
                tokio::time::timeout_at(deadline, self.claim(&session_id, &mac))
                    .await
                    .ok()
                    .flatten()
            }
        };
        let Some(claimed) = claimed else {
            tracing::info!(session = %session_id, "media bind refused");
            refuse(&mut wr, reason::BAD_BIND).await;
            return MediaOutcome::NotBound;
        };
        self.run(session_id, claimed, Stream { route, preset }, rd, wr)
            .await
    }

    /// Bind `session_id` with `mac`. A session the FSM has not registered yet
    /// is waited for: it registers just after sending `SESSION_ACCEPT`, and a
    /// fast viewer can bind in between. The caller bounds the wait.
    async fn claim(&self, session_id: &str, mac: &[u8; 32]) -> Option<Claimed> {
        loop {
            let registered = self.registered.notified();
            tokio::pin!(registered);
            // Armed before the look-up, so an `on_start` in between still wakes us.
            registered.as_mut().enable();
            match self.try_claim(session_id, mac) {
                Lookup::Bound(claimed) => return Some(claimed),
                Lookup::Refused => return None,
                Lookup::Unknown => registered.await,
            }
        }
    }

    fn try_claim(&self, session_id: &str, mac: &[u8; 32]) -> Lookup {
        let mut sessions = self.lock();
        let Some(session) = sessions.get_mut(session_id) else {
            return Lookup::Unknown;
        };
        // One media stream per session (SLICE-A1 G3, A2-3), and none for a
        // session already ended by a kill whose `on_end` has not come yet.
        if session.bound || session.end.borrow().is_some() {
            return Lookup::Refused;
        }
        // A wrong MAC leaves the session unbound: a peer that knows a session
        // id but not its token cannot lock the real viewer out.
        if !tornect_proto::bind_mac_ok(session.token.bytes(), &session.th_final, mac) {
            return Lookup::Refused;
        }
        session.bound = true;
        Lookup::Bound(Claimed {
            mode: session.mode,
            elevation: session.elevation,
            label: session.label.clone(),
            end: session.end.subscribe(),
        })
    }

    /// A bound stream: capture, serve, tear down.
    async fn run<R, W>(
        &self,
        session_id: String,
        claimed: Claimed,
        stream: Stream,
        rd: R,
        mut wr: W,
    ) -> MediaOutcome
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send,
    {
        let Claimed {
            mode,
            elevation,
            label,
            mut end,
        } = claimed;
        let Stream { route, preset } = stream;

        // Capture starts here, after a verified bind (§B.6, decision M1-39).
        // The open's cancel is made before the open, and belongs to it alone:
        // an end that comes before the blocking thread has even started still
        // reaches it (slice-G G1-1). What it is opened for comes from this
        // host's config and the route alone, whatever preset the viewer named.
        let caps = self.limits.caps;
        let request = SourceRequest::new(quality::capture_fps(route, &caps));
        let (cancel, cancelled) = watch::channel(false);
        let ends_the_open = EndsTheOpen(cancel);
        let backend = Arc::clone(&self.backend);
        let opened = tokio::select! {
            biased;
            _ = end.changed() => None,
            opened = tokio::task::spawn_blocking(move || backend.open_source(request, cancelled)) => {
                Some(opened)
            }
        };
        // The session is over, or the open is done and nothing waits on it.
        drop(ends_the_open);
        let source = match opened {
            None => {
                return not_started(&mut wr, MediaEnd::SessionOver(end_reason(&end))).await;
            }
            Some(Ok(Ok(source))) => source,
            Some(Ok(Err(e))) => {
                tracing::warn!(error = %e, session = %session_id, "screen capture could not start");
                return not_started(&mut wr, MediaEnd::Pipeline(reason::CAPTURE_FAILED)).await;
            }
            Some(Err(e)) => {
                tracing::warn!(error = %e, session = %session_id, "the capture backend failed");
                return not_started(&mut wr, MediaEnd::Pipeline(reason::CAPTURE_FAILED)).await;
            }
        };
        // A view-only session never asks for an injector (below); the backend
        // also lets go of what one could be built from, as soon as the source
        // that came with it is open.
        if !matches!(mode, SessionMode::Control) {
            self.backend.view_only();
        }
        let source_name = source.name();
        // The preset the viewer bound with, every number from this host's
        // table under its caps.
        let initial = quality::settings(preset, route, &caps);
        let mut pipeline = Pipeline::start(source, initial, route, caps, self.limits.window_frames);
        pipeline.credit();
        let first = tokio::select! {
            biased;
            _ = end.changed() => First::Ended,
            first = tokio::time::timeout(self.limits.first_frame_deadline, pipeline.next()) => {
                First::Frame(first.ok().flatten())
            }
        };
        let mut first = match first {
            First::Frame(Some(Ok(frame))) => frame,
            First::Ended => {
                pipeline.stop().await;
                return not_started(&mut wr, MediaEnd::SessionOver(end_reason(&end))).await;
            }
            First::Frame(Some(Err(e))) => {
                tracing::warn!(error = %e, session = %session_id, "screen capture failed");
                pipeline.stop().await;
                return not_started(&mut wr, MediaEnd::Pipeline(e.reason())).await;
            }
            First::Frame(None) => {
                tracing::warn!(session = %session_id, "screen capture delivered no picture in time");
                pipeline.stop().await;
                return not_started(&mut wr, MediaEnd::Pipeline(reason::CAPTURE_FAILED)).await;
            }
        };

        // `BindOk` says what the first picture was encoded with, and its exact
        // size: the bind's preset, unless a change was taken before that
        // picture (its announcement, which `BindOk` then says instead of a
        // `Quality`).
        let applied = first.announce.take().map_or(initial, |a| a.settings);
        let bind_ok = Msg::BindOk {
            width: first.width,
            height: first.height,
            codec: codec::H264,
            mode: mode_code(mode),
            quality: applied.info(),
        };
        if let Err(stop) = send(&mut wr, &bind_ok, &mut end, None).await {
            pipeline.stop().await;
            return MediaOutcome::NotStarted(stop.end);
        }

        // A view-only session never gets an injector: its input is dropped
        // below, undecoded (SLICE-A2 A2-3).
        let injector = if matches!(mode, SessionMode::Control) {
            let backend = Arc::clone(&self.backend);
            let id = session_id.clone();
            tokio::task::spawn_blocking(move || backend.open_session_injector(&id, elevation))
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let injector = injector.map(|sink| Tracked::new(Boxed(sink)));
        // A control session left without an injector says so to its viewer,
        // which still sends what the signed accept allows (SLICE-C2 C2-6).
        if matches!(mode, SessionMode::Control) && injector.is_none() {
            tracing::warn!(
                session = %session_id,
                "control session with no injector: its viewer's input reaches nothing here"
            );
            if let Some(session) = self.lock().get_mut(&session_id) {
                session.no_input = true;
            }
        }
        self.observer.capture_started(&CaptureStarted {
            session_id: &session_id,
            label: &label,
            source: source_name,
            width: first.width,
            height: first.height,
            mode,
            input: injector.is_some(),
        });

        let (inbound_tx, mut inbound) = mpsc::channel(INBOUND_DEPTH);
        let (heard_tx, heard) = watch::channel(tokio::time::Instant::now());
        let reader = tokio::spawn(read_client(rd, inbound_tx, heard_tx));
        let epoch = Instant::now();
        let window_caps = (self.limits.window_frames, self.limits.window_bytes);
        let (window_frames, window_bytes) = quality::window(&applied, window_caps.0, window_caps.1);
        let mut served = Served {
            injector,
            quiet: Quiet::new(self.limits.viewer_quiet, heard),
            inbound: &mut inbound,
            inputs: TokenBucket::new(self.limits.input_rate, self.limits.input_burst, epoch),
            pings: TokenBucket::new(PINGS_PER_SEC, PING_BURST, epoch),
            keyframes: KeyframeLimiter::new(self.limits.keyframe_interval),
            pipeline: &mut pipeline,
            window: AckWindow::new(window_frames, window_bytes),
            window_caps,
            quality: QualityState {
                gate: QualityGate::new(self.limits.quality_interval),
                target: applied.preset,
                applied,
                size: (first.width, first.height),
            },
            stats: StatsWindow::new(self.limits.stats_every, epoch),
            report: MediaReport::default(),
            pong_owed: None,
            session_id: &session_id,
        };
        let mut seq: u32 = 0;
        let mut pending = Some(first);
        let mut torn = false;

        let ended = 'serve: loop {
            // The viewer's latest pick, at the gate's turn, before anything
            // else is written: a rebuild, or the answer that the preset it
            // named already applies. Taken on every turn of the loop, not
            // only when the select below finds nothing else to do: on a
            // stream the link limits, each write outlasts the frame interval
            // and the acks taken while it waits have the next picture encoded
            // before it ends, so a picture is ready at every select and a
            // pick behind it would never be acted on. Before the turn this
            // changes nothing, and the turn comes at most once per
            // `quality_interval`, so it never holds pictures back.
            if let Some(answer) = served.quality_due(Instant::now())
                && let Err(stop) = send(&mut wr, &answer, &mut end, Some(&mut served)).await
            {
                torn = stop.torn;
                break stop.end;
            }
            if let Some(frame) = pending.take() {
                // Said before the picture it covers: a change of settings or
                // of size (the quality design §4.1), then the means, when due.
                let quality = served.announce(&frame);
                let now = Instant::now();
                let stats = served
                    .stats
                    .due(now)
                    .then(|| Msg::Stats(served.stats.take(now, frame.source)));
                for msg in [quality, stats].into_iter().flatten() {
                    if let Err(stop) = send(&mut wr, &msg, &mut end, Some(&mut served)).await {
                        torn = stop.torn;
                        break 'serve stop.end;
                    }
                }
                let Encoded {
                    data,
                    keyframe,
                    captured_at,
                    times,
                    ready_at,
                    repeat,
                    ..
                } = frame;
                let len = data.len();
                let msg = Msg::Video {
                    seq,
                    flags: if keyframe { video_flags::KEYFRAME } else { 0 },
                    // A wrapping millisecond clock (the wire field is 32 bits).
                    ts_ms: captured_at.saturating_duration_since(epoch).as_millis() as u32,
                    data,
                };
                // In flight from the start of its write: the viewer's acks are
                // taken while the write waits and may credit the next picture,
                // so the window must already hold this one (SLICE-A2 A2-6).
                // A failed write ends the stream, so nothing is left counted.
                served.window.sent(seq, len, Instant::now());
                if let Err(stop) = send(&mut wr, &msg, &mut end, Some(&mut served)).await {
                    torn = stop.torn;
                    break stop.end;
                }
                let written = Instant::now();
                // Its round trip counts from here: the viewer can acknowledge
                // it only once it has all of it.
                served.window.written(seq, written);
                served.report.frames_sent += 1;
                served.report.bytes_sent += len as u64;
                served.report.keyframes_sent += u64::from(keyframe);
                served.picture_sent(&times, repeat, written.saturating_duration_since(ready_at));
                seq = seq.wrapping_add(1);
                if served.window.has_room() {
                    served.pipeline.credit();
                }
            }
            // The `Ping` taken last, answered once nothing else is being
            // written; pings taken while this `Pong` waits owe another.
            while let Some(nonce) = served.pong_owed.take() {
                if let Err(stop) =
                    send(&mut wr, &Msg::Pong { nonce }, &mut end, Some(&mut served)).await
                {
                    torn = stop.torn;
                    break 'serve stop.end;
                }
            }

            let quiet_at = served.quiet_deadline();
            let quality_at = served.quality_deadline();
            let event = tokio::select! {
                biased;
                _ = end.changed() => Event::Ended,
                msg = served.inbound.recv() => Event::Client(msg),
                frame = served.pipeline.next() => Event::Frame(frame),
                () = tokio::time::sleep_until(quiet_at.unwrap_or_else(tokio::time::Instant::now)),
                    if quiet_at.is_some() => Event::Quiet,
                () = tokio::time::sleep_until(quality_at.unwrap_or_else(tokio::time::Instant::now)),
                    if quality_at.is_some() => Event::Quality,
            };
            match event {
                Event::Ended => break MediaEnd::SessionOver(end_reason(&end)),
                // A viewer that pings when it has nothing else to say has gone
                // quiet: it may be gone, and a key it holds would repeat on the
                // host until the session's idle timeout (SLICE-C1 C1-3).
                Event::Quiet => {
                    if served.lapse() {
                        tracing::debug!(session = %session_id, "viewer quiet: released what it held");
                    }
                }
                // The gate's turn came while nothing else happened: it is
                // taken at the top of the loop.
                Event::Quality => {}
                Event::Frame(Some(Ok(frame))) => pending = Some(frame),
                Event::Frame(Some(Err(e))) => {
                    tracing::warn!(error = %e, session = %session_id, "screen capture stopped");
                    break MediaEnd::Pipeline(e.reason());
                }
                Event::Frame(None) => break MediaEnd::Pipeline(reason::CAPTURE_FAILED),
                Event::Client(msg) => {
                    if let Handled::End(why) = served.on_client(msg, Instant::now()) {
                        break why;
                    }
                }
            }
        };

        // Release what the viewer holds first, then stop capture: both before
        // anything is said about the end.
        let Served {
            injector, report, ..
        } = served;
        drop(injector);
        pipeline.stop().await;
        reader.abort();
        let close = match ended {
            MediaEnd::SessionOver(reason) | MediaEnd::Pipeline(reason) => Some(reason),
            MediaEnd::Protocol => Some(reason::PROTOCOL),
            MediaEnd::ViewerLeft | MediaEnd::Io => None,
        };
        // After a cut-short frame the viewer could not parse a `Close`.
        if let Some(reason) = close.filter(|_| !torn) {
            let _ =
                tokio::time::timeout(LAST_WRITE, write_msg(&mut wr, &Msg::Close { reason })).await;
        }
        let _ = tokio::time::timeout(LAST_WRITE, wr.shutdown()).await;
        self.observer.capture_stopped(&session_id, &report, &ended);
        MediaOutcome::Served {
            session_id,
            report,
            end: ended,
        }
    }
}

impl SessionSink for MediaHost {
    fn on_start(&self, session: &LiveSession<'_>) {
        let (end, _) = watch::channel(None);
        self.lock().insert(
            session.session_id.to_owned(),
            Registered {
                token: session.token.clone(),
                th_final: session.th_final,
                mode: session.mode,
                elevation: session.elevation,
                label: session.label.to_owned(),
                bound: false,
                no_input: false,
                end,
            },
        );
        self.registered.notify_waiters();
    }

    fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
        let reason = match end {
            Some(SessionEnd::Killed(_)) => reason::ENDED_BY_HOST,
            _ => reason::SESSION_OVER,
        };
        if let Some(session) = self.lock().remove(session_id) {
            session.end.send_replace(Some(reason));
        }
        self.backend.session_ended(session_id);
    }
}

/// What a `Bind` carries: the session id, the MAC and the viewer's preset.
type Bound = (String, [u8; 32], QualityPreset);

/// How a bound stream is served: the route its listener says, and the preset
/// its `Bind` names.
#[derive(Debug, Clone, Copy)]
struct Stream {
    route: Route,
    preset: QualityPreset,
}

/// The first frame of a media stream, read without trusting its length prefix:
/// a `Bind` is exactly [`BIND_LEN`] bytes, so that is all an unbound peer can
/// make the host read. Returns the session id, the MAC and the viewer's
/// preset (a code `tornect_proto::quality` does not know is malformed).
async fn read_bind<R: AsyncRead + Unpin>(r: &mut R) -> Result<Bound, ProtoError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len != BIND_LEN {
        // A viewer of another Tornect version sends a `Bind` of another
        // length (the quality design, §4.7). One more byte, the frame's type,
        // tells it from anything else, so the host's log can say why the
        // stream is refused; a frame longer than any client frame is refused
        // unread.
        if (1..=MAX_CLIENT_FRAME).contains(&len) {
            let mut ty = [0u8; 1];
            r.read_exact(&mut ty).await?;
            if ty[0] == BIND_TYPE {
                tracing::info!(
                    "a media bind of {len} bytes: the viewer may run a different Tornect version"
                );
            }
        }
        return Err(ProtoError::Size(len));
    }
    let mut frame = [0u8; BIND_LEN];
    r.read_exact(&mut frame).await?;
    match Msg::decode(&frame)? {
        Msg::Bind {
            session_id,
            mac,
            quality,
        } => quality::preset(quality)
            .map(|preset| (session_id, mac, preset))
            .ok_or(ProtoError::Malformed("Bind")),
        _ => Err(ProtoError::Malformed("Bind")),
    }
}

/// Read the client's frames into `tx` until it closes the stream or breaks
/// the protocol, stamping `heard` as each one is read and before it is
/// queued, so that a frame the loop takes is always one the stamp has seen.
/// Every client message is small, hence the cap.
async fn read_client<R: AsyncRead + Unpin>(
    mut rd: R,
    tx: mpsc::Sender<Result<Msg, ProtoError>>,
    heard: watch::Sender<tokio::time::Instant>,
) {
    loop {
        let msg = match read_msg_max(&mut rd, MAX_CLIENT_FRAME).await {
            Ok(Some(msg)) => {
                heard.send_replace(tokio::time::Instant::now());
                Ok(msg)
            }
            Ok(None) => return,
            Err(e) => Err(e),
        };
        let last = msg.is_err();
        if tx.send(msg).await.is_err() || last {
            return;
        }
    }
}

/// Refuse a bind (or say why it could not be served) and close.
async fn refuse<W: AsyncWrite + Unpin>(wr: &mut W, reason: u16) {
    let _ = tokio::time::timeout(LAST_WRITE, write_msg(wr, &Msg::BindRefused { reason })).await;
    let _ = tokio::time::timeout(LAST_WRITE, wr.shutdown()).await;
}

async fn not_started<W: AsyncWrite + Unpin>(wr: &mut W, end: MediaEnd) -> MediaOutcome {
    let reason = match end {
        MediaEnd::SessionOver(reason) | MediaEnd::Pipeline(reason) => reason,
        MediaEnd::Protocol => reason::PROTOCOL,
        MediaEnd::ViewerLeft | MediaEnd::Io => reason::ENDED_BY_VIEWER,
    };
    refuse(wr, reason).await;
    MediaOutcome::NotStarted(end)
}

/// Ends a source's open when dropped: when its session ends first, and when
/// the stream's task is dropped mid-open (a host that stops), so that no
/// dialog stays up and no grant is kept for a stream that is gone. Once the
/// open is done nothing reads it, so it is dropped then too.
struct EndsTheOpen(watch::Sender<bool>);

impl Drop for EndsTheOpen {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

/// The `Close` reason for a session that ended: what `on_end` set, or
/// `SESSION_OVER` when the media host itself went away.
fn end_reason(end: &watch::Receiver<Option<u16>>) -> u16 {
    end.borrow().unwrap_or(reason::SESSION_OVER)
}

/// Why a write did not happen, and whether it may have been cut short.
struct Stop {
    end: MediaEnd,
    torn: bool,
}

/// Write `msg` unless the session ends first. A write can stall for as long as
/// the viewer withholds Tor flow-control credit, and a session end must not
/// wait for that: capture stops as soon as the session does.
///
/// With `served`, the viewer's frames are handled while the write waits, by
/// the same [`Served::on_client`] as between writes: its input is injected
/// under the same rules (a view-only session's dropped undecoded, releases
/// never budgeted), its acks and keyframe requests are taken, a `Ping` is
/// owed its `Pong` until the write is done, and its `Close` or a broken frame
/// ends the stream at once. The quiet release keeps its deadline too, since a
/// viewer that vanished is what stalls a write, and the key it holds must not
/// repeat until the stall ends the stream (slice-G G2-1). `BindOk` is written
/// without it: nothing is served before it.
async fn send<W: AsyncWrite + Unpin>(
    wr: &mut W,
    msg: &Msg,
    end: &mut watch::Receiver<Option<u16>>,
    mut served: Option<&mut Served<'_>>,
) -> Result<(), Stop> {
    if end.has_changed().unwrap_or(true) {
        return Err(Stop {
            end: MediaEnd::SessionOver(end_reason(end)),
            torn: false,
        });
    }
    // The write is polled first, so a write that can complete does; only one
    // stalled on flow control is cut short, and only by an end: the session's
    // ahead of anything the viewer sends, then the viewer's own. The quiet
    // release lets go of the viewer's keys and the write goes on.
    let write = write_msg(wr, msg);
    tokio::pin!(write);
    loop {
        let quiet_at = served.as_mut().and_then(|served| served.quiet_deadline());
        tokio::select! {
            biased;
            written = &mut write => {
                return written.map_err(|e| {
                    tracing::debug!(error = %e, "media stream write failed");
                    Stop {
                        end: MediaEnd::Io,
                        torn: true,
                    }
                });
            }
            _ = end.changed() => {
                return Err(Stop {
                    end: MediaEnd::SessionOver(end_reason(end)),
                    torn: true,
                });
            }
            msg = next_client(&mut served) => {
                if let Some(served) = served.as_mut()
                    && let Handled::End(why) = served.on_client(msg, Instant::now())
                {
                    return Err(Stop {
                        end: why,
                        torn: true,
                    });
                }
            }
            () = tokio::time::sleep_until(quiet_at.unwrap_or_else(tokio::time::Instant::now)),
                if quiet_at.is_some() =>
            {
                if served.as_mut().is_some_and(|served| served.lapse()) {
                    tracing::debug!("viewer quiet while a write waits: released what it held");
                }
            }
        }
    }
}

/// The viewer's next frame for [`send`] to handle; with nothing served (the
/// `BindOk`), never.
async fn next_client(served: &mut Option<&mut Served<'_>>) -> Option<Result<Msg, ProtoError>> {
    match served {
        Some(served) => served.inbound.recv().await,
        None => std::future::pending().await,
    }
}

enum First {
    Ended,
    Frame(Option<Result<Encoded, PipelineError>>),
}

enum Event {
    Ended,
    Client(Option<Result<Msg, ProtoError>>),
    Frame(Option<Result<Encoded, PipelineError>>),
    /// The viewer has said nothing for [`MediaLimits::viewer_quiet`].
    Quiet,
    /// The quality gate's turn came: the loop wakes to take it at its top.
    Quality,
}

/// The quiet release's clock (SLICE-C1 C1-3). The viewer counts as heard when
/// the reader reads one of its frames, not when the loop takes it: frames that
/// wait in the queue until the loop handles them were heard all the same
/// (slice-G G2-1).
struct Quiet {
    after: Duration,
    /// The reader's stamp: when it last read a frame.
    heard: watch::Receiver<tokio::time::Instant>,
    /// The stamp last taken in.
    seen: tokio::time::Instant,
    /// When to let go, unless the viewer is heard first.
    at: tokio::time::Instant,
    /// Let go of since the viewer was last heard: nothing to watch until it
    /// is heard again.
    released: bool,
}

impl Quiet {
    fn new(after: Duration, heard: watch::Receiver<tokio::time::Instant>) -> Self {
        let seen = *heard.borrow();
        Self {
            after,
            heard,
            seen,
            at: seen + after,
            released: false,
        }
    }

    /// Take in the reader's stamp: a viewer heard since gets a new deadline,
    /// and what it holds is watched again.
    fn refresh(&mut self) {
        let stamp = *self.heard.borrow();
        if stamp != self.seen {
            self.seen = stamp;
            self.at = stamp + self.after;
            self.released = false;
        }
    }

    /// When to let go of what a control viewer holds; `None` when there is
    /// nothing to watch (no injector, or let go of already).
    fn deadline(&mut self, control: bool) -> Option<tokio::time::Instant> {
        self.refresh();
        (control && !self.released).then_some(self.at)
    }

    /// The deadline came: whether to let go now; not if the viewer was heard
    /// meanwhile. While its frames fill the queue, the reader waits on the
    /// loop and cannot hear anything newer: a viewer that busy counts as heard
    /// for one more quiet period after its last frame read, and no longer, so
    /// a viewer that vanished right after a burst is still let go of.
    fn due(&mut self, queue_full: bool) -> bool {
        self.refresh();
        let now = tokio::time::Instant::now();
        if self.released || now < self.at {
            return false;
        }
        // With inbound drained while writes wait, the queue fills only if
        // handling falls behind the reader (an injector call that blocks); the
        // branch keeps a busy viewer from being let go of at the first
        // deadline in that case.
        let busy_until = self.seen + self.after.saturating_mul(2);
        if queue_full && now < busy_until {
            self.at = busy_until;
            return false;
        }
        self.released = true;
        true
    }
}

/// A bound stream while it is served: everything a frame from the viewer can
/// change. The main loop owns it and lends it to [`send`] while a write waits,
/// so that [`Served::on_client`] is the one code path for every frame the
/// viewer sends, whether the host is idle or stuck writing to it.
struct Served<'a> {
    /// `None`: a view-only session, or a control session with nothing to
    /// inject into. Dropped first at the end, which releases what it holds.
    injector: Option<Tracked<Boxed>>,
    quiet: Quiet,
    inbound: &'a mut mpsc::Receiver<Result<Msg, ProtoError>>,
    inputs: TokenBucket,
    pings: TokenBucket,
    keyframes: KeyframeLimiter,
    pipeline: &'a mut Pipeline,
    window: AckWindow,
    /// The host's caps on every preset's window (`MediaLimits::window_frames`
    /// and `window_bytes`).
    window_caps: (usize, usize),
    quality: QualityState,
    stats: StatsWindow,
    report: MediaReport,
    /// The nonce of a `Ping` taken and not answered yet: the main loop writes
    /// its `Pong` once the write under way is done. Pings are coalesced while a
    /// write waits: only the latest nonce is answered. The viewer's pings are
    /// liveness probes and it ignores `Pong` (`viewer.rs`), and the tests'
    /// `sync` sends one ping at a time.
    pong_owed: Option<u64>,
    session_id: &'a str,
}

/// Where the viewer's quality picks stand (the quality design §6.6).
struct QualityState {
    /// The viewer's latest pick not acted on yet, and the bound on actions.
    gate: QualityGate,
    /// The preset last handed to the pipeline (at first, the bind's).
    target: QualityPreset,
    /// What the pictures written last were encoded with.
    applied: StreamSettings,
    /// The size of the picture written last.
    size: (u32, u32),
}

/// What [`Served::on_client`] made of a frame.
enum Handled {
    Continue,
    End(MediaEnd),
}

impl Served<'_> {
    /// Handle what the reader delivered: a frame, its error, or `None` once
    /// the viewer closed the stream.
    fn on_client(&mut self, msg: Option<Result<Msg, ProtoError>>, now: Instant) -> Handled {
        let msg = match msg {
            None => return Handled::End(MediaEnd::ViewerLeft),
            Some(Err(ProtoError::Io(e))) => {
                tracing::debug!(error = %e, "media stream read failed");
                return Handled::End(MediaEnd::ViewerLeft);
            }
            Some(Err(e)) => {
                tracing::info!(error = %e, session = %self.session_id, "viewer broke the media protocol");
                return Handled::End(MediaEnd::Protocol);
            }
            Some(Ok(msg)) => msg,
        };
        match msg {
            Msg::VideoAck { seq } => {
                if let Some(rtt) = self.window.ack(seq, now) {
                    self.stats.acked(rtt);
                    self.report.acks += 1;
                    add_us(&mut self.report.ack_us, rtt);
                    if self.window.has_room() {
                        self.pipeline.credit();
                    }
                }
            }
            Msg::Input(bytes) => {
                // No injector: view-only (then the bytes are never even
                // decoded), or nothing to inject into.
                let Some(sink) = self.injector.as_mut() else {
                    self.report.input_dropped += 1;
                    return Handled::Continue;
                };
                let Ok(event) = InputEvent::decode(&bytes) else {
                    return Handled::End(MediaEnd::Protocol);
                };
                // A release never spends the budget, so it is never dropped: a
                // lost key-up would leave the key down on this desktop
                // (SLICE-E E1-6). `Tracked` injects one only for what it holds,
                // so a flood of them injects nothing.
                if !event.is_release() && !self.inputs.take(now) {
                    self.report.input_dropped += 1;
                    return Handled::Continue;
                }
                match sink.inject(&event) {
                    Ok(()) => self.report.input_injected += 1,
                    Err(e) => {
                        self.report.input_dropped += 1;
                        tracing::debug!(error = %e, "input event not injected");
                    }
                }
            }
            Msg::KeyframeRequest => {
                self.report.keyframe_requests += 1;
                if self.keyframes.allow(now) {
                    self.report.keyframes_forced += 1;
                    self.pipeline.force_keyframe();
                }
            }
            Msg::Ping { nonce } => {
                if self.pings.take(now) {
                    self.pong_owed = Some(nonce);
                }
            }
            Msg::Pong { .. } => {}
            // Legal in control and view-only sessions alike, and it costs a
            // count and a store: the gate acts on the latest pick in its own
            // time ([`Self::quality_due`]). Never logged per message.
            Msg::SetQuality { quality } => {
                self.report.quality_requests += 1;
                self.quality.gate.request(quality);
            }
            Msg::Close { .. } => return Handled::End(MediaEnd::ViewerLeft),
            Msg::Bind { .. }
            | Msg::BindOk { .. }
            | Msg::BindRefused { .. }
            | Msg::Video { .. }
            | Msg::Quality { .. }
            | Msg::Stats(_) => {
                return Handled::End(MediaEnd::Protocol);
            }
        }
        Handled::Continue
    }

    /// When to let go of what the viewer holds, if it stays quiet.
    fn quiet_deadline(&mut self) -> Option<tokio::time::Instant> {
        self.quiet.deadline(self.injector.is_some())
    }

    /// When the gate may act on the viewer's latest pick; `None` with no
    /// pick waiting. A pick of another preset than the one the pipeline was
    /// last given is a rebuild, an IDR, so it also waits for the keyframe
    /// limiter's turn: forced keyframes from both stay at one per
    /// [`MediaLimits::keyframe_interval`] (the quality design §5.3).
    fn quality_deadline(&self) -> Option<tokio::time::Instant> {
        let wanted = self.quality.gate.wanted()?;
        let mut at = self.quality.gate.ready_at();
        if wanted != quality::code(self.quality.target) {
            // `None` is "now", which `Option`'s order puts first.
            at = at.max(self.keyframes.ready_at());
        }
        Some(at.map_or_else(tokio::time::Instant::now, tokio::time::Instant::from_std))
    }

    /// The gate's turn at `now` (see [`Self::quality_deadline`]): act on the
    /// viewer's latest pick, at most once per interval. Another preset than
    /// the pipeline's is handed to it, spending the keyframe limiter's turn,
    /// and its first picture is announced ([`Self::announce`]). The preset
    /// in force is answered with a `Quality` saying so, returned for the
    /// caller to write, with no encoder work. The one on its way to the
    /// pipeline is left to that change's announcement. Before the turn,
    /// nothing changes.
    fn quality_due(&mut self, now: Instant) -> Option<Msg> {
        let wanted = self.quality.gate.wanted()?;
        if self.quality.gate.ready_at().is_some_and(|at| now < at) {
            return None;
        }
        let Some(preset) = quality::preset(wanted) else {
            // `SetQuality` decodes only the codes of a preset.
            self.quality.gate.take(now);
            return None;
        };
        if preset != self.quality.target {
            if !self.keyframes.allow(now) {
                return None;
            }
            self.quality.gate.take(now);
            self.pipeline.set_quality(wanted);
            self.quality.target = preset;
            tracing::debug!(session = %self.session_id, %preset, "quality change");
            return None;
        }
        self.quality.gate.take(now);
        (preset == self.quality.applied.preset).then(|| Msg::Quality {
            width: self.quality.size.0,
            height: self.quality.size.1,
            quality: self.quality.applied.info(),
        })
    }

    /// `frame` is next to be written: the `Quality` to write before it when
    /// its settings or its size changed since the picture before. A change
    /// of preset resizes the ack window to the new preset's; a smaller one
    /// admits nothing until acks drain it.
    fn announce(&mut self, frame: &Encoded) -> Option<Msg> {
        self.quality.size = (frame.width, frame.height);
        let settings = frame.announce?.settings;
        if settings.preset != self.quality.applied.preset {
            self.report.quality_changes += 1;
            let (frames, bytes) =
                quality::window(&settings, self.window_caps.0, self.window_caps.1);
            self.window.set_limits(frames, bytes);
        }
        self.quality.applied = settings;
        Some(Msg::Quality {
            width: frame.width,
            height: frame.height,
            quality: settings.info(),
        })
    }

    /// A picture whose stages took `times` went out, `send` after it was
    /// encoded; `repeat` when it encodes the last one again (no grab).
    fn picture_sent(&mut self, times: &StageTimes, repeat: bool, send: Duration) {
        self.stats.sent(send);
        self.stats.frame(times, !repeat);
        let report = &mut self.report;
        report.repeats += u64::from(repeat);
        if !repeat {
            add_us(&mut report.grab_us, times.grab);
        }
        add_us(&mut report.scale_us, times.scale);
        add_us(&mut report.convert_us, times.convert);
        add_us(&mut report.encode_us, times.encode);
        add_us(&mut report.send_us, send);
    }

    /// The deadline came: let go of what the viewer holds, if it is due.
    /// Whether it let go.
    fn lapse(&mut self) -> bool {
        let Some(sink) = self.injector.as_mut() else {
            return false;
        };
        if !self.quiet.due(self.inbound.capacity() == 0) {
            return false;
        }
        sink.release_all();
        true
    }
}

/// Add `d` to `sum` in microseconds, saturating.
fn add_us(sum: &mut u64, d: Duration) {
    *sum = sum.saturating_add(u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
}

/// `Tracked` wants a sized sink.
struct Boxed(Box<dyn InputSink>);

impl InputSink for Boxed {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        self.0.inject(event)
    }
}

/// One encoded picture.
struct Encoded {
    data: Vec<u8>,
    keyframe: bool,
    width: u32,
    height: u32,
    captured_at: Instant,
    /// The captured picture's size, before it was fitted.
    source: (u32, u32),
    /// What each stage took; a repeat has no grab and no age.
    times: StageTimes,
    /// When the encode was done.
    ready_at: Instant,
    /// The last picture encoded again after a quality change: the viewer
    /// already has it, at another size.
    repeat: bool,
    /// What to say before this picture (`Quality`): set when the settings or
    /// the encoded size changed since the picture before it. The first
    /// picture has none unless the settings changed before it (`BindOk`
    /// says the rest).
    announce: Option<Announce>,
}

/// The settings a picture and those after it are encoded with; its size is
/// the picture's.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Announce {
    settings: StreamSettings,
}

#[derive(Debug, thiserror::Error)]
enum PipelineError {
    #[error(transparent)]
    Capture(CaptureError),
    #[error("H.264 encoder: {0}")]
    Encoder(String),
}

impl PipelineError {
    fn reason(&self) -> u16 {
        match self {
            Self::Capture(_) => reason::CAPTURE_FAILED,
            Self::Encoder(_) => reason::ENCODER_FAILED,
        }
    }
}

#[derive(Default)]
struct Control {
    stop: AtomicBool,
    keyframe: AtomicBool,
    /// The preset code to change to (`tornect_proto::quality`); 0 for none.
    /// The latest wins.
    quality: AtomicU8,
}

/// Capture and encoding, on a blocking thread that owns the source: when the
/// thread returns, capture has stopped.
struct Pipeline {
    control: Arc<Control>,
    credits: std::sync::mpsc::Sender<()>,
    frames: mpsc::Receiver<Result<Encoded, PipelineError>>,
    thread: Option<tokio::task::JoinHandle<()>>,
    /// A credit given and its picture not received yet (at most one).
    waiting: bool,
}

impl Pipeline {
    /// Capture from `source` and encode with `settings`; a quality change
    /// takes its settings from the table for `route` under `caps`. At most
    /// `depth` pictures wait to be taken.
    fn start(
        source: Box<dyn VideoSource>,
        settings: StreamSettings,
        route: Route,
        caps: QualityCaps,
        depth: usize,
    ) -> Self {
        let control = Arc::new(Control::default());
        let (credits, credit_rx) = std::sync::mpsc::channel();
        let (frame_tx, frames) = mpsc::channel(depth.max(1));
        let ctl = Arc::clone(&control);
        let thread = tokio::task::spawn_blocking(move || {
            encode_loop(
                source,
                Settings {
                    current: settings,
                    route,
                    caps,
                },
                &credit_rx,
                &frame_tx,
                &ctl,
            );
        });
        Self {
            control,
            credits,
            frames,
            thread: Some(thread),
            waiting: false,
        }
    }

    /// Ask for the next picture, unless one is already on its way.
    fn credit(&mut self) {
        if !self.waiting && self.credits.send(()).is_ok() {
            self.waiting = true;
        }
    }

    /// The next picture; cancel-safe.
    async fn next(&mut self) -> Option<Result<Encoded, PipelineError>> {
        let frame = self.frames.recv().await;
        if frame.is_some() {
            self.waiting = false;
        }
        frame
    }

    fn force_keyframe(&self) {
        self.control.keyframe.store(true, Ordering::SeqCst);
    }

    /// Change to the preset of wire code `code` (`tornect_proto::quality`;
    /// another code is ignored). The capture thread takes it at its next
    /// turn, within [`POLL`] while it waits for a picture: a new encoder,
    /// whose first picture is an IDR, and on a still screen the last picture
    /// encoded again. The caller bounds how often (the quality gate and the
    /// keyframe limiter).
    fn set_quality(&self, code: u8) {
        self.control.quality.store(code, Ordering::SeqCst);
    }

    /// Stop, and wait for the capture thread to let go of the source.
    async fn stop(&mut self) {
        self.control.stop.store(true, Ordering::SeqCst);
        self.frames.close();
        if let Some(thread) = self.thread.take()
            && tokio::time::timeout(STOP_WAIT, thread).await.is_err()
        {
            tracing::warn!("the capture thread did not stop in time");
        }
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        self.control.stop.store(true, Ordering::SeqCst);
    }
}

/// What the capture thread encodes with, and where a quality change takes
/// its settings from.
struct Settings {
    current: StreamSettings,
    route: Route,
    caps: QualityCaps,
}

/// The time between two pictures at `settings`' frame rate.
fn interval(settings: &StreamSettings) -> Duration {
    Duration::from_secs(1) / settings.fps()
}

/// The capture thread: one picture per credit, paced to the current
/// settings' frame rate, until told to stop or its channels close. Each
/// desktop is fitted under the settings' cap before it is encoded: scaled
/// whole when it is larger, never cropped, so the picture shows the
/// `shown_region` the injectors map the viewer's pointer over
/// (`backend.rs`).
///
/// The last fresh picture is kept: a quality change, taken on every [`POLL`]
/// turn while the thread waits for a picture, builds a new encoder and, on a
/// still screen, encodes that picture again at once (the design's §6.6). Its
/// buffer goes back to the source (`VideoSource::recycle`) when a newer
/// picture replaces it. A keyframe request still waits for the next picture,
/// as before.
fn encode_loop(
    mut source: Box<dyn VideoSource>,
    mut settings: Settings,
    credits: &std::sync::mpsc::Receiver<()>,
    out: &mpsc::Sender<Result<Encoded, PipelineError>>,
    control: &Control,
) {
    let mut encoder = match H264Encoder::new(settings.current.encoder) {
        Ok(encoder) => encoder,
        Err(e) => {
            let _ = out.blocking_send(Err(PipelineError::Encoder(e.to_string())));
            return;
        }
    };
    let mut scaler = Scaler::default();
    // When the last picture was taken, for the pacing.
    let mut paced: Option<Instant> = None;
    let mut last: Option<Frame> = None;
    // The size of the last picture encoded; `None` before the first.
    let mut size: Option<(u32, u32)> = None;
    // The settings changed since the last picture encoded.
    let mut changed = false;
    loop {
        loop {
            if control.stop.load(Ordering::SeqCst) {
                return;
            }
            match credits.recv_timeout(POLL) {
                Ok(()) => break,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
        if let Some(due) = paced.map(|at| at + interval(&settings.current)) {
            let now = Instant::now();
            if due > now {
                std::thread::sleep(due - now);
            }
        }
        let (frame, repeat) = loop {
            if control.stop.load(Ordering::SeqCst) {
                return;
            }
            if let Some(preset) = quality::preset(control.quality.swap(0, Ordering::SeqCst)) {
                settings.current = quality::settings(preset, settings.route, &settings.caps);
                encoder = match H264Encoder::new(settings.current.encoder) {
                    Ok(encoder) => encoder,
                    Err(e) => {
                        let _ = out.blocking_send(Err(PipelineError::Encoder(e.to_string())));
                        return;
                    }
                };
                changed = true;
                if let Some(frame) = last.take() {
                    break (frame, true);
                }
            }
            match source.next_frame(POLL) {
                Ok(Some(frame)) => break (frame, false),
                // A damage-driven source had nothing new.
                Ok(None) => {}
                Err(e) => {
                    let _ = out.blocking_send(Err(PipelineError::Capture(e)));
                    return;
                }
            }
        };
        paced = Some(Instant::now());
        if control.keyframe.swap(false, Ordering::SeqCst) {
            encoder.force_keyframe();
        }
        let started = Instant::now();
        let fitted = scaler
            .fit(&frame.bgrx, frame.width, frame.height, settings.current.cap)
            .and_then(|fitted| {
                let (scale, width, height) = (fitted.took, fitted.width, fitted.height);
                encoder
                    .encode(fitted.bgrx, width, height)
                    .map(|au| (au, scale, width, height))
            });
        let encoded = match fitted {
            Err(e) => Err(PipelineError::Encoder(e.to_string())),
            // It could not be framed (`Msg::encode` would refuse it): the
            // stream ends `ENCODER_FAILED` rather than with a broken frame.
            Ok((au, ..)) if au.data.len() > MAX_FRAME - VIDEO_OVERHEAD => Err(
                PipelineError::Encoder(format!("access unit too large ({} bytes)", au.data.len())),
            ),
            Ok((au, scale, width, height)) => {
                let resized = size.is_some_and(|size| size != (width, height));
                size = Some((width, height));
                let announce = (changed || resized).then_some(Announce {
                    settings: settings.current,
                });
                changed = false;
                Ok(Encoded {
                    data: au.data,
                    keyframe: au.keyframe,
                    width,
                    height,
                    captured_at: frame.captured_at,
                    source: (frame.width, frame.height),
                    times: StageTimes {
                        // Nothing new was captured for a repeat.
                        grab: if repeat { Duration::ZERO } else { frame.grab },
                        age: if repeat {
                            Duration::ZERO
                        } else {
                            started.saturating_duration_since(frame.captured_at)
                        },
                        scale,
                        convert: au.convert,
                        encode: au.encode,
                    },
                    ready_at: Instant::now(),
                    repeat,
                    announce,
                })
            }
        };
        // The picture is kept for a quality change to encode again; the one
        // it replaces goes back for the source to fill again.
        if let Some(old) = last.replace(frame) {
            source.recycle(old.bgrx);
        }
        let failed = encoded.is_err();
        if out.blocking_send(encoded).is_err() || failed {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Quiet::due`'s queue-full branch, which PR-A's draining of the queue
    /// while writes wait leaves reachable only when handling falls behind the
    /// reader: a viewer whose frames fill the queue is not let go of at its
    /// first deadline, but one quiet period after its last frame read, and no
    /// later; with room in the queue it is let go of at the deadline; heard
    /// again, it is watched again from then.
    #[tokio::test(start_paused = true)]
    async fn a_full_queue_holds_the_quiet_release_for_one_more_quiet_period() {
        let after = Duration::from_secs(3);
        let ms = Duration::from_millis(1);
        let t0 = tokio::time::Instant::now();
        let (heard_tx, heard) = watch::channel(t0);
        let mut quiet = Quiet::new(after, heard);
        assert_eq!(quiet.deadline(true), Some(t0 + after));
        assert_eq!(quiet.deadline(false), None, "no injector: nothing to watch");

        tokio::time::advance(after - ms).await;
        assert!(!quiet.due(true) && !quiet.due(false), "before the deadline");
        tokio::time::advance(ms).await;
        assert!(!quiet.due(true), "the queue is full at the deadline");
        assert_eq!(
            quiet.deadline(true),
            Some(t0 + after * 2),
            "held one more quiet period after the last frame read"
        );
        tokio::time::advance(after - ms).await;
        assert!(!quiet.due(true));
        tokio::time::advance(ms).await;
        assert!(quiet.due(true), "let go of then, full queue or not");
        assert_eq!(quiet.deadline(true), None, "let go of: nothing to watch");
        assert!(!quiet.due(true) && !quiet.due(false), "once");

        // Heard again: a new deadline, watched again; with room in the queue
        // it is let go of at that deadline.
        let t1 = tokio::time::Instant::now();
        heard_tx.send_replace(t1);
        assert_eq!(quiet.deadline(true), Some(t1 + after));
        tokio::time::advance(after).await;
        assert!(
            quiet.due(false),
            "room in the queue: let go of at the deadline"
        );
    }

    /// The message of every event logged while it is the thread's subscriber.
    struct Lines(Arc<Mutex<Vec<String>>>);

    struct Message<'a>(&'a mut String);

    impl tracing::field::Visit for Message<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                *self.0 = format!("{value:?}");
            }
        }
    }

    impl tracing::Subscriber for Lines {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut line = String::new();
            event.record(&mut Message(&mut line));
            self.0.lock().unwrap().push(line);
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// `read_bind` over `bytes`, with what it logged and how many bytes it read.
    fn read_bind_of(bytes: &[u8]) -> (Result<Bound, ProtoError>, Vec<String>, u64) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut cursor = std::io::Cursor::new(bytes);
        let read = tracing::subscriber::with_default(Lines(Arc::clone(&lines)), || {
            runtime.block_on(read_bind(&mut cursor))
        });
        let lines = lines.lock().unwrap().clone();
        (read, lines, cursor.position())
    }

    fn bind(quality: u8) -> Msg {
        Msg::Bind {
            session_id: "0123456789abcdef".into(),
            mac: [7; 32],
            quality,
        }
    }

    /// The quality design §4.1: a `Bind` is 50 bytes and carries the
    /// viewer's preset, which `read_bind` returns; an unknown code is a
    /// malformed bind, refused like any other before a look-up.
    #[test]
    fn a_bind_carries_the_viewers_preset() {
        for (code, preset) in [
            (
                tornect_proto::quality::BEST_QUALITY,
                QualityPreset::BestQuality,
            ),
            (tornect_proto::quality::BALANCED, QualityPreset::Balanced),
            (
                tornect_proto::quality::BEST_PERFORMANCE,
                QualityPreset::BestPerformance,
            ),
        ] {
            let frame = bind(code).encode();
            assert_eq!(frame.len(), 4 + BIND_LEN);
            let (read, lines, at) = read_bind_of(&frame);
            assert_eq!(
                read.unwrap(),
                ("0123456789abcdef".to_owned(), [7; 32], preset)
            );
            assert!(lines.is_empty(), "{lines:?}");
            assert_eq!(at, frame.len() as u64);
        }
        for code in [0, 4, 9, 255] {
            let (read, lines, _) = read_bind_of(&bind(code).encode());
            assert!(
                matches!(read, Err(ProtoError::Malformed("Bind"))),
                "preset {code}: {read:?}"
            );
            assert!(lines.is_empty(), "{lines:?}");
        }
    }

    /// The quality design §4.7: a `Bind` of another length (an older
    /// viewer's 49 bytes, a later one's) is refused and logged at info as a
    /// version mismatch, after one more byte (its type); a first frame of
    /// another type is refused without that line, and one longer than any
    /// client frame is refused at its length prefix, unread.
    #[test]
    fn a_bind_of_another_length_is_logged_as_another_version() {
        let mut old = 49u32.to_be_bytes().to_vec();
        old.push(BIND_TYPE);
        old.extend_from_slice(b"0123456789abcdef");
        old.extend_from_slice(&[7; 32]);
        let mut longer = bind(tornect_proto::quality::BALANCED).encode();
        longer[3] += 1;
        longer.push(0);
        for (frame, len) in [(old, 49), (longer, 51)] {
            let (read, lines, at) = read_bind_of(&frame);
            assert!(
                matches!(read, Err(ProtoError::Size(n)) if n == len),
                "{read:?}"
            );
            assert_eq!(
                lines,
                [format!(
                    "a media bind of {len} bytes: the viewer may run a different Tornect version"
                )]
            );
            assert_eq!(at, 5, "the length prefix and the type byte only");
        }

        let ping = Msg::Ping { nonce: 1 }.encode();
        let (read, lines, at) = read_bind_of(&ping);
        assert!(matches!(read, Err(ProtoError::Size(9))), "{read:?}");
        assert!(lines.is_empty(), "{lines:?}");
        assert_eq!(at, 5);

        let mut huge = (8u32 << 20).to_be_bytes().to_vec();
        huge.push(BIND_TYPE);
        let (read, lines, at) = read_bind_of(&huge);
        assert!(
            matches!(read, Err(ProtoError::Size(n)) if n == 8 << 20),
            "{read:?}"
        );
        assert!(lines.is_empty(), "{lines:?}");
        assert_eq!(at, 4, "refused at its length prefix");
    }

    /// `BindOk`'s `QualityInfo` says what the stream applies: until the
    /// design's step 12, Balanced from the host's table under its caps (the
    /// 1080p cap, 15 fps, 1500 kbit/s); and any settings, even ones out of
    /// every range, give a `QualityInfo` the viewer accepts.
    #[test]
    fn bind_ok_says_what_the_stream_applies() {
        let applied = quality::settings(
            QualityPreset::Balanced,
            Route::Tor,
            &MediaLimits::default().caps,
        );
        assert_eq!(
            applied.info(),
            tornect_proto::QualityInfo {
                preset: tornect_proto::quality::BALANCED,
                max_fps: 15,
                kbps: 1500,
                max_long: 1920,
                max_short: 1080,
            }
        );
        for (max_fps, bitrate_bps, fps, kbps) in [
            (0.5, 999, 1, 1),
            (f32::NAN, 0, 1, 1),
            (1000.0, u32::MAX, 255, u32::MAX / 1000),
        ] {
            let info = StreamSettings {
                encoder: tornect_codec::EncoderSettings {
                    max_fps,
                    bitrate_bps,
                    ..applied.encoder
                },
                ..applied
            }
            .info();
            assert_eq!((info.max_fps, info.kbps), (fps, kbps));
            let ok = Msg::BindOk {
                width: 1,
                height: 1,
                codec: codec::H264,
                mode: 0,
                quality: info,
            };
            assert_eq!(Msg::decode(&ok.encode()[4..]).unwrap(), ok);
        }
    }

    /// `[media]` reaches the presets through `with_media`: its caps, each
    /// value out of range held (and logged once at warn, with the note's
    /// text), every other limit the default.
    #[test]
    fn the_limits_take_their_caps_from_the_media_config() {
        let media = Media {
            max_fps: 10,
            min_bitrate_kbps: 5000,
            encoder_threads: 2,
            ..Media::default()
        };
        let lines = Arc::new(Mutex::new(Vec::new()));
        let limits = tracing::subscriber::with_default(Lines(Arc::clone(&lines)), || {
            MediaLimits::with_media(&media)
        });
        assert_eq!(
            limits.caps,
            QualityCaps {
                max_fps: 10,
                tor_max_kbps: 4000,
                min_kbps: 4000,
                encoder_threads: 2,
            }
        );
        assert_eq!(
            *lines.lock().unwrap(),
            [
                "media.min_bitrate_kbps (5000) is above media.tor_fallback_max_kbps (4000): \
              presets use 4000"
            ]
        );
        let defaults = MediaLimits::default();
        assert_eq!(
            (limits.window_frames, limits.window_bytes),
            (defaults.window_frames, defaults.window_bytes)
        );
        assert_eq!(
            (defaults.window_frames, defaults.window_bytes),
            (32, 1 << 20)
        );
        assert_eq!(
            (limits.quality_interval, limits.stats_every),
            (Duration::from_secs(2), Duration::from_secs(1))
        );
        assert_eq!(
            MediaLimits::with_media(&Media::default()).caps,
            defaults.caps
        );
    }

    /// The longest access unit a `Video` frame carries: one byte more and the
    /// frame would be over `MAX_FRAME`, which the viewer refuses; the
    /// pipeline ends the stream `ENCODER_FAILED` above it instead.
    #[tokio::test]
    async fn the_access_unit_bound_is_the_longest_video_frame() {
        let longest = MAX_FRAME - VIDEO_OVERHEAD;
        let video = |len: usize| Msg::Video {
            seq: 1,
            flags: video_flags::KEYFRAME,
            ts_ms: 2,
            data: vec![0x5a; len],
        };
        let frame = video(longest).encode();
        assert_eq!(frame.len(), 4 + MAX_FRAME);
        let read = tornect_proto::read_msg(&mut frame.as_slice())
            .await
            .unwrap();
        assert_eq!(read, Some(video(longest)));
        let mut over = (u32::try_from(MAX_FRAME).unwrap() + 1)
            .to_be_bytes()
            .to_vec();
        over.push(0x10);
        assert!(matches!(
            tornect_proto::read_msg(&mut over.as_slice()).await,
            Err(ProtoError::Size(_))
        ));
        assert_eq!(
            PipelineError::Encoder("access unit too large".into()).reason(),
            reason::ENCODER_FAILED
        );
    }

    /// Pictures of the sizes queued, then nothing (a still screen); counts
    /// the buffers given back.
    struct Script {
        sizes: Arc<Mutex<std::collections::VecDeque<(u32, u32)>>>,
        index: u32,
        recycled: Arc<Mutex<Vec<usize>>>,
    }

    impl VideoSource for Script {
        fn name(&self) -> &'static str {
            "script"
        }

        fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
            let Some((width, height)) = self.sizes.lock().unwrap().pop_front() else {
                std::thread::sleep(timeout);
                return Ok(None);
            };
            self.index += 1;
            Ok(Some(Frame {
                width,
                height,
                bgrx: tornect_capture::TestCard::render(width, height, self.index),
                captured_at: Instant::now(),
                grab: Duration::from_micros(700),
            }))
        }

        fn recycle(&mut self, bgrx: Vec<u8>) {
            self.recycled.lock().unwrap().push(bgrx.len());
        }
    }

    /// A pipeline over a [`Script`] at Balanced: the queue of sizes it will
    /// capture, and the lengths of the buffers it gave back.
    type Scripted = (
        Pipeline,
        Arc<Mutex<std::collections::VecDeque<(u32, u32)>>>,
        Arc<Mutex<Vec<usize>>>,
    );

    fn scripted(sizes: &[(u32, u32)]) -> Scripted {
        let queue = Arc::new(Mutex::new(sizes.iter().copied().collect()));
        let recycled = Arc::new(Mutex::new(Vec::new()));
        let source = Script {
            sizes: Arc::clone(&queue),
            index: 0,
            recycled: Arc::clone(&recycled),
        };
        let caps = QualityCaps::default();
        let initial = quality::settings(QualityPreset::Balanced, Route::Tor, &caps);
        let pipeline = Pipeline::start(Box::new(source), initial, Route::Tor, caps, 4);
        (pipeline, queue, recycled)
    }

    /// The next picture, after a credit.
    async fn picture(pipeline: &mut Pipeline) -> Encoded {
        pipeline.credit();
        tokio::time::timeout(Duration::from_secs(10), pipeline.next())
            .await
            .expect("a picture in time")
            .expect("the pipeline runs")
            .expect("encoded")
    }

    /// No picture within `wait` of a credit.
    async fn no_picture(pipeline: &mut Pipeline, wait: Duration) {
        pipeline.credit();
        assert!(
            tokio::time::timeout(wait, pipeline.next()).await.is_err(),
            "a picture came"
        );
    }

    fn decoded_size(au: &[u8]) -> (u32, u32) {
        let mut decoder = tornect_codec::H264Decoder::new().unwrap();
        let frame = decoder.decode(au).unwrap().expect("a picture");
        (frame.width, frame.height)
    }

    /// The design §6.6 step 2 on a still screen: a quality change is taken
    /// while the thread waits for a picture, and the last picture is encoded
    /// again at once with a new encoder: an IDR at the new preset's size,
    /// announced with its settings, the same capture (no grab, no age), and
    /// decoded at that size. Back to Balanced, the same.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_quality_change_on_a_still_screen_encodes_the_last_picture_again() {
        let (mut pipeline, _, recycled) = scripted(&[(1920, 1080)]);
        let first = picture(&mut pipeline).await;
        assert!(first.keyframe && !first.repeat);
        assert!(first.announce.is_none(), "BindOk says the first");
        assert_eq!((first.width, first.height), (1920, 1080));
        assert_eq!(first.source, (1920, 1080));
        assert_eq!(first.times.grab, Duration::from_micros(700));
        no_picture(&mut pipeline, Duration::from_millis(300)).await;

        let caps = QualityCaps::default();
        let asked = Instant::now();
        pipeline.set_quality(tornect_proto::quality::BEST_PERFORMANCE);
        let again = tokio::time::timeout(Duration::from_secs(10), pipeline.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            asked.elapsed() < POLL + Duration::from_millis(500),
            "taken within a poll: {:?}",
            asked.elapsed()
        );
        assert!(again.repeat && again.keyframe);
        assert_eq!((again.width, again.height), (1280, 720));
        assert_eq!(again.source, (1920, 1080));
        assert_eq!(again.captured_at, first.captured_at, "the same capture");
        assert_eq!(
            (again.times.grab, again.times.age),
            (Duration::ZERO, Duration::ZERO)
        );
        let best_performance = quality::settings(QualityPreset::BestPerformance, Route::Tor, &caps);
        assert_eq!(
            again.announce,
            Some(Announce {
                settings: best_performance
            })
        );
        assert_eq!(decoded_size(&again.data), (1280, 720));

        pipeline.set_quality(tornect_proto::quality::BALANCED);
        let back = picture(&mut pipeline).await;
        assert!(back.repeat && back.keyframe);
        assert_eq!((back.width, back.height), (1920, 1080));
        assert_eq!(
            back.announce.map(|a| a.settings.preset),
            Some(QualityPreset::Balanced)
        );
        assert_eq!(decoded_size(&back.data), (1920, 1080));
        assert!(
            recycled.lock().unwrap().is_empty(),
            "the one picture is kept, never given back while it is the last"
        );
        pipeline.stop().await;
    }

    /// A change taken before any picture applies to the first one, which
    /// then carries it; a code no preset has changes nothing (no new
    /// encoder, no picture on a still screen); a keyframe request on a still
    /// screen waits for the next picture, as before the presets.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_a_known_preset_changes_the_encoder() {
        let (mut pipeline, queue, _) = scripted(&[]);
        pipeline.set_quality(tornect_proto::quality::BEST_QUALITY);
        no_picture(&mut pipeline, Duration::from_millis(300)).await;
        queue.lock().unwrap().push_back((640, 360));
        let first = tokio::time::timeout(Duration::from_secs(10), pipeline.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!first.repeat && first.keyframe);
        assert_eq!(
            first.announce.map(|a| a.settings.preset),
            Some(QualityPreset::BestQuality),
            "changed before the first picture"
        );

        for code in [0, 4, 9, 255] {
            pipeline.set_quality(code);
            no_picture(&mut pipeline, Duration::from_millis(250)).await;
        }
        pipeline.force_keyframe();
        assert!(
            tokio::time::timeout(Duration::from_millis(400), pipeline.next())
                .await
                .is_err(),
            "a keyframe request on a still screen waits for a picture"
        );
        queue.lock().unwrap().push_back((640, 360));
        let next = tokio::time::timeout(Duration::from_secs(10), pipeline.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!next.repeat && next.keyframe, "the forced keyframe");
        assert!(next.announce.is_none(), "nothing changed");
        pipeline.stop().await;
    }

    /// A source that changes size is announced at its first picture of the
    /// new size, with the settings in force, and only then; each picture's
    /// buffer goes back when a newer one replaces it, never the last.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_source_resize_is_announced_and_replaced_pictures_go_back() {
        let sizes = [(640, 360), (640, 360), (800, 600), (800, 600), (2560, 1440)];
        let (mut pipeline, _, recycled) = scripted(&sizes);
        let mut seen = Vec::new();
        for _ in sizes {
            let p = picture(&mut pipeline).await;
            assert!(!p.repeat);
            seen.push((
                (p.width, p.height),
                p.announce.map(|a| a.settings.preset),
                p.keyframe,
            ));
        }
        let bal = Some(QualityPreset::Balanced);
        assert_eq!(
            seen,
            [
                ((640, 360), None, true),
                ((640, 360), None, false),
                ((800, 600), bal, true),
                ((800, 600), None, false),
                // Scaled under Balanced's 1080p cap: a new encoded size.
                ((1920, 1080), bal, true),
            ]
        );
        assert_eq!(
            *recycled.lock().unwrap(),
            [640 * 360 * 4, 640 * 360 * 4, 800 * 600 * 4, 800 * 600 * 4],
            "every picture but the last given back, in order"
        );
        pipeline.stop().await;
    }

    /// Pacing follows the settings in force: Balanced's 15 fps, Best
    /// performance's 20, Best quality's 12.
    #[test]
    fn pictures_are_paced_at_the_current_presets_rate() {
        let caps = QualityCaps::default();
        let ms = |p| interval(&quality::settings(p, Route::Tor, &caps)).as_micros();
        assert_eq!(ms(QualityPreset::Balanced), 66_666);
        assert_eq!(ms(QualityPreset::BestPerformance), 50_000);
        assert_eq!(ms(QualityPreset::BestQuality), 83_333);
    }

    /// The code the pipeline was handed and the capture thread has not taken
    /// yet (0 for none), taken as the thread would.
    fn handed(served: &Served<'_>) -> u8 {
        served.pipeline.control.quality.swap(0, Ordering::SeqCst)
    }

    /// `Served::quality_due` at explicit instants, each branch of the gate's
    /// turn (the quality design §6.6), over a pipeline that is never given a
    /// credit, so its capture thread takes no change by itself:
    /// - a pick of another preset than the pipeline's waits for the gate's
    ///   and the keyframe limiter's turns, then is handed over and spends both;
    /// - a pick of the preset on its way to the pipeline takes the gate's turn
    ///   and nothing else: no `Quality` (Balanced still applies, the new
    ///   preset does not yet), no second hand-over, which would be a rebuild
    ///   only the gate bounds, and the limiter's turn kept;
    /// - a pick of the preset in force is answered with what applies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_gates_turn_acts_by_what_the_pipeline_holds() {
        let interval = Duration::from_millis(300);
        let keyframes = Duration::from_secs(1);
        let caps = QualityCaps::default();
        let balanced = quality::settings(QualityPreset::Balanced, Route::Tor, &caps);
        let fast = quality::settings(QualityPreset::BestPerformance, Route::Tor, &caps);
        let (mut pipeline, _, _) = scripted(&[]);
        let (_frames, mut inbound) = mpsc::channel(1);
        let (_heard, heard) = watch::channel(tokio::time::Instant::now());
        let t0 = Instant::now();
        let at = |d: Duration| tokio::time::Instant::from_std(t0 + d);
        let mut served = Served {
            injector: None,
            quiet: Quiet::new(Duration::from_secs(3), heard),
            inbound: &mut inbound,
            inputs: TokenBucket::new(250, 500, t0),
            pings: TokenBucket::new(PINGS_PER_SEC, PING_BURST, t0),
            keyframes: KeyframeLimiter::new(keyframes),
            pipeline: &mut pipeline,
            window: AckWindow::new(23, 281_250),
            window_caps: (32, 1024 * 1024),
            quality: QualityState {
                gate: QualityGate::new(interval),
                target: QualityPreset::Balanced,
                applied: balanced,
                size: (1920, 1080),
            },
            stats: StatsWindow::new(Duration::from_secs(1), t0),
            report: MediaReport::default(),
            pong_owed: None,
            session_id: "s",
        };
        let code = tornect_proto::quality::BEST_PERFORMANCE;

        // The first pick acts at once: handed over, both turns spent.
        served.quality.gate.request(code);
        assert!(
            served
                .quality_deadline()
                .is_some_and(|due| due <= tokio::time::Instant::now()),
            "at once"
        );
        assert_eq!(served.quality_due(t0), None);
        assert_eq!(served.quality.target, QualityPreset::BestPerformance);
        assert_eq!(handed(&served), code, "taken by the capture thread");
        assert_eq!(served.keyframes.ready_at(), Some(t0 + keyframes));

        // The same pick again, on its way: due at the gate's turn alone.
        served.quality.gate.request(code);
        assert_eq!(served.quality_deadline(), Some(at(interval)));
        assert_eq!(served.quality_due(t0 + interval / 2), None);
        assert_eq!(served.quality.gate.wanted(), Some(code), "before the turn");
        assert_eq!(served.quality_due(t0 + interval), None, "no Quality");
        assert_eq!(served.quality.gate.wanted(), None, "the turn is taken");
        assert_eq!(served.quality_deadline(), None);
        assert_eq!(handed(&served), 0, "not handed over again");
        assert_eq!(served.keyframes.ready_at(), Some(t0 + keyframes));
        assert_eq!(served.quality.applied, balanced);

        // Its first picture is announced; a pick of it now is answered.
        let first = Encoded {
            data: Vec::new(),
            keyframe: true,
            width: 1280,
            height: 720,
            captured_at: t0,
            source: (1920, 1080),
            times: StageTimes::default(),
            ready_at: t0,
            repeat: true,
            announce: Some(Announce { settings: fast }),
        };
        let said = Msg::Quality {
            width: 1280,
            height: 720,
            quality: fast.info(),
        };
        assert_eq!(served.announce(&first), Some(said.clone()));
        assert_eq!(served.report.quality_changes, 1);
        served.quality.gate.request(code);
        assert_eq!(served.quality_due(t0 + interval * 2), Some(said));
        assert_eq!(handed(&served), 0, "no encoder work");

        // Another preset waits for the limiter's turn too.
        let best = tornect_proto::quality::BEST_QUALITY;
        served.quality.gate.request(best);
        assert_eq!(served.quality_deadline(), Some(at(keyframes)));
        assert_eq!(served.quality_due(t0 + interval * 3), None);
        assert_eq!(
            served.quality.gate.wanted(),
            Some(best),
            "the limiter's turn"
        );
        assert_eq!(handed(&served), 0);
        assert_eq!(served.quality_due(t0 + keyframes), None);
        assert_eq!(served.quality.target, QualityPreset::BestQuality);
        assert_eq!(handed(&served), best);
        assert_eq!(served.keyframes.ready_at(), Some(t0 + keyframes * 2));
        assert_eq!(served.report.quality_changes, 1, "counted when announced");
        drop(served);
        pipeline.stop().await;
    }
}
