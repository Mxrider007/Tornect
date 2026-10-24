//! The host half of the media layer: which sessions may bind a media stream,
//! and the pipeline that serves one.
//!
//! A media stream is served in three steps.
//!
//! 1. **Bind.** The first frame must be a `Bind`. It must arrive complete
//!    within [`MediaLimits::bind_deadline`], and it is read at its fixed size,
//!    so an unbound peer holds nothing for long and costs the host 49 bytes.
//!    The session must be live and not yet bound, and the MAC must verify
//!    under that session's token and `th_final` (`tornect_proto::bind_mac_ok`,
//!    constant time). Reading a `Bind` takes no slot: a live session's viewer
//!    is claimed as soon as its `Bind` arrives, and only a `Bind` for a session
//!    not registered yet waits, [`MediaLimits::max_waiting`] at a time. Streams
//!    that squat the slots therefore cannot starve a real viewer (SLICE-C1
//!    C1-1); how many streams are open at once is the caller's bound (the
//!    listener's: 4 per circuit).
//! 2. **Capture.** Only now is the source opened (§B.6). A capture thread makes
//!    one picture per credit, and credits come from the ack window, so nothing
//!    is captured that could not be sent.
//! 3. **Serve**, until the session ends (the FSM's `on_end`: `BYE`, the kill
//!    switch, a timeout), the viewer leaves, or something breaks. The viewer's
//!    frames (input, acks, pings, `Close`) are handled by one code path, also
//!    while a write to the viewer waits on flow control. Every exit path stops
//!    capture and drops the injector, which releases whatever the viewer
//!    still holds.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Notify, Semaphore, mpsc, watch};
use tornect_capture::{CaptureError, VideoSource};
use tornect_codec::{EncoderSettings, H264Encoder};
use tornect_core::levels::Elevation;
use tornect_core::session_log::SessionMode;
use tornect_input::{InputError, InputEvent, InputSink, Tracked};
use tornect_proto::{
    MAX_CLIENT_FRAME, Msg, ProtoError, SESSION_ID_LEN, codec, read_msg_max, reason, video_flags,
    write_msg,
};
use tornect_signal::consent::{SessionToken, mode_code};
use tornect_signal::fsm::host::{KillSwitch, LiveSession, SessionEnd, SessionSink};
use tornect_signal::messages::notice;

use crate::flow::{AckWindow, KeyframeLimiter, TokenBucket};

/// How often the capture thread checks its stop flag while it waits.
const POLL: Duration = Duration::from_millis(100);
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
/// A `Bind` frame: the type byte, the session id, the MAC.
const BIND_LEN: usize = 1 + SESSION_ID_LEN + 32;

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
    /// Access units in flight before the host waits for a `VideoAck`.
    pub window_frames: usize,
    /// Bytes in flight before the host waits for a `VideoAck`.
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
    /// The encoder. Its frame rate also paces capture.
    pub encoder: EncoderSettings,
}

impl Default for MediaLimits {
    fn default() -> Self {
        Self {
            bind_deadline: Duration::from_secs(10),
            max_waiting: 8,
            first_frame_deadline: Duration::from_secs(10),
            // At 8, a Tor round trip of 1.0–1.3 s held the test card to 6.3 fps
            // (live run, 2026-09-21); 15 fps needs about 20 in flight. The byte
            // cap still bounds what can queue.
            window_frames: 20,
            window_bytes: 512 * 1024,
            input_rate: 250,
            input_burst: 500,
            keyframe_interval: Duration::from_secs(1),
            // The viewer pings every second when it has nothing else to say.
            viewer_quiet: Duration::from_secs(3),
            encoder: EncoderSettings::default(),
        }
    }
}

/// What a bound session captures, and where its input goes. It is asked only
/// after a verified `Bind`, which is how capture follows the accept (§B.6).
pub trait MediaBackend: Send + Sync {
    /// Open the picture source. It may block: it runs on a blocking thread.
    ///
    /// `cancel` turns `true` when the session ends, or its stream is dropped,
    /// before the open is done. The Wayland open waits on the desktop's
    /// dialog, which must not stay up, nor leave a remembered grant, for a
    /// session that is over: it ends its wait then. The value latches, and it
    /// can be `true` before this is even called (slice-G G1-1). A source that
    /// does not wait ignores it.
    fn open_source(
        &self,
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

    /// Serve one stream accepted on the media port, from its `Bind` to its end.
    pub async fn serve<S>(&self, stream: S) -> MediaOutcome
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let deadline = tokio::time::Instant::now() + self.limits.bind_deadline;
        let (session_id, mac) = match tokio::time::timeout_at(deadline, read_bind(&mut rd)).await {
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
        self.run(session_id, claimed, rd, wr).await
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

        // Capture starts here, after a verified bind (§B.6, decision M1-39).
        // The open's cancel is made before the open, and belongs to it alone:
        // an end that comes before the blocking thread has even started still
        // reaches it (slice-G G1-1).
        let (cancel, cancelled) = watch::channel(false);
        let ends_the_open = EndsTheOpen(cancel);
        let backend = Arc::clone(&self.backend);
        let opened = tokio::select! {
            biased;
            _ = end.changed() => None,
            opened = tokio::task::spawn_blocking(move || backend.open_source(cancelled)) => {
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
        let mut pipeline = Pipeline::start(source, self.limits.encoder, self.limits.window_frames);
        pipeline.credit();
        let first = tokio::select! {
            biased;
            _ = end.changed() => First::Ended,
            first = tokio::time::timeout(self.limits.first_frame_deadline, pipeline.next()) => {
                First::Frame(first.ok().flatten())
            }
        };
        let first = match first {
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

        let bind_ok = Msg::BindOk {
            width: first.width,
            height: first.height,
            codec: codec::H264,
            mode: mode_code(mode),
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
        let mut served = Served {
            injector,
            quiet: Quiet::new(self.limits.viewer_quiet, heard),
            inbound: &mut inbound,
            inputs: TokenBucket::new(self.limits.input_rate, self.limits.input_burst, epoch),
            pings: TokenBucket::new(PINGS_PER_SEC, PING_BURST, epoch),
            keyframes: KeyframeLimiter::new(self.limits.keyframe_interval),
            pipeline: &mut pipeline,
            window: AckWindow::new(self.limits.window_frames, self.limits.window_bytes),
            report: MediaReport::default(),
            pong_owed: None,
            session_id: &session_id,
        };
        let mut seq: u32 = 0;
        let mut pending = Some(first);
        let mut torn = false;

        let ended = 'serve: loop {
            if let Some(frame) = pending.take() {
                let len = frame.data.len();
                let msg = Msg::Video {
                    seq,
                    flags: if frame.keyframe {
                        video_flags::KEYFRAME
                    } else {
                        0
                    },
                    // A wrapping millisecond clock (the wire field is 32 bits).
                    ts_ms: frame
                        .captured_at
                        .saturating_duration_since(epoch)
                        .as_millis() as u32,
                    data: frame.data,
                };
                // In flight from the start of its write: the viewer's acks are
                // taken while the write waits and may credit the next picture,
                // so the window must already hold this one (SLICE-A2 A2-6).
                // A failed write ends the stream, so nothing is left counted.
                served.window.sent(seq, len);
                if let Err(stop) = send(&mut wr, &msg, &mut end, Some(&mut served)).await {
                    torn = stop.torn;
                    break stop.end;
                }
                served.report.frames_sent += 1;
                served.report.bytes_sent += len as u64;
                served.report.keyframes_sent += u64::from(frame.keyframe);
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
            let event = tokio::select! {
                biased;
                _ = end.changed() => Event::Ended,
                msg = served.inbound.recv() => Event::Client(msg),
                frame = served.pipeline.next() => Event::Frame(frame),
                () = tokio::time::sleep_until(quiet_at.unwrap_or_else(tokio::time::Instant::now)),
                    if quiet_at.is_some() => Event::Quiet,
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

/// The first frame of a media stream, read without trusting its length prefix:
/// a `Bind` is exactly [`BIND_LEN`] bytes, so that is all an unbound peer can
/// make the host read.
async fn read_bind<R: AsyncRead + Unpin>(r: &mut R) -> Result<(String, [u8; 32]), ProtoError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len != BIND_LEN {
        return Err(ProtoError::Size(len));
    }
    let mut frame = [0u8; BIND_LEN];
    r.read_exact(&mut frame).await?;
    match Msg::decode(&frame)? {
        Msg::Bind { session_id, mac } => Ok((session_id, mac)),
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
    report: MediaReport,
    /// The nonce of a `Ping` taken and not answered yet: the main loop writes
    /// its `Pong` once the write under way is done. Pings are coalesced while a
    /// write waits: only the latest nonce is answered. The viewer's pings are
    /// liveness probes and it ignores `Pong` (`viewer.rs`), and the tests'
    /// `sync` sends one ping at a time.
    pong_owed: Option<u64>,
    session_id: &'a str,
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
                if self.window.ack(seq) && self.window.has_room() {
                    self.pipeline.credit();
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
            Msg::Close { .. } => return Handled::End(MediaEnd::ViewerLeft),
            Msg::Bind { .. } | Msg::BindOk { .. } | Msg::BindRefused { .. } | Msg::Video { .. } => {
                return Handled::End(MediaEnd::Protocol);
            }
        }
        Handled::Continue
    }

    /// When to let go of what the viewer holds, if it stays quiet.
    fn quiet_deadline(&mut self) -> Option<tokio::time::Instant> {
        self.quiet.deadline(self.injector.is_some())
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
    fn start(source: Box<dyn VideoSource>, settings: EncoderSettings, depth: usize) -> Self {
        let control = Arc::new(Control::default());
        let (credits, credit_rx) = std::sync::mpsc::channel();
        let (frame_tx, frames) = mpsc::channel(depth.max(1));
        let ctl = Arc::clone(&control);
        let thread = tokio::task::spawn_blocking(move || {
            encode_loop(source, settings, &credit_rx, &frame_tx, &ctl);
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

/// The capture thread: one picture per credit, paced to the encoder's frame
/// rate, until told to stop or its channels close.
fn encode_loop(
    mut source: Box<dyn VideoSource>,
    settings: EncoderSettings,
    credits: &std::sync::mpsc::Receiver<()>,
    out: &mpsc::Sender<Result<Encoded, PipelineError>>,
    control: &Control,
) {
    let mut encoder = match H264Encoder::new(settings) {
        Ok(encoder) => encoder,
        Err(e) => {
            let _ = out.blocking_send(Err(PipelineError::Encoder(e.to_string())));
            return;
        }
    };
    let interval = Duration::from_secs_f32(1.0 / settings.max_fps.max(1.0));
    let mut last: Option<Instant> = None;
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
        if let Some(due) = last.map(|last| last + interval) {
            let now = Instant::now();
            if due > now {
                std::thread::sleep(due - now);
            }
        }
        let frame = loop {
            if control.stop.load(Ordering::SeqCst) {
                return;
            }
            match source.next_frame(POLL) {
                Ok(Some(frame)) => break frame,
                // A damage-driven source had nothing new.
                Ok(None) => {}
                Err(e) => {
                    let _ = out.blocking_send(Err(PipelineError::Capture(e)));
                    return;
                }
            }
        };
        last = Some(Instant::now());
        if control.keyframe.swap(false, Ordering::SeqCst) {
            encoder.force_keyframe();
        }
        let encoded = encoder
            .encode(&frame.bgrx, frame.width, frame.height)
            .map(|au| {
                let (width, height) = encoder.size();
                Encoded {
                    data: au.data,
                    keyframe: au.keyframe,
                    width,
                    height,
                    captured_at: frame.captured_at,
                }
            })
            .map_err(|e| PipelineError::Encoder(e.to_string()));
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
}
