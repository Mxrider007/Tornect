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
//!    switch, a timeout), the viewer leaves, or something breaks. Every exit
//!    path stops capture and drops the injector, which releases whatever the
//!    viewer still holds.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Notify, Semaphore, mpsc, watch};
use tornect_capture::{CaptureError, VideoSource};
use tornect_codec::{EncoderSettings, H264Encoder};
use tornect_core::session_log::SessionMode;
use tornect_input::{InputError, InputEvent, InputSink, Tracked};
use tornect_proto::{
    MAX_CLIENT_FRAME, Msg, ProtoError, SESSION_ID_LEN, codec, read_msg_max, reason, video_flags,
    write_msg,
};
use tornect_signal::consent::{SessionToken, mode_code};
use tornect_signal::fsm::host::{KillSwitch, LiveSession, SessionEnd, SessionSink};

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
    /// before the keys and buttons it holds are released (SLICE-C1 C1-3).
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

    /// The source just opened is for a view-only session: let go of anything
    /// kept for building its injector, so that no path can reach the desktop's
    /// input for it. The default keeps nothing.
    fn view_only(&self) {}
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
    label: String,
    bound: bool,
    /// Set to the `Close` reason when the session ends.
    end: watch::Sender<Option<u16>>,
}

/// A successful bind.
struct Claimed {
    mode: SessionMode,
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
        if let Err(stop) = send(&mut wr, &bind_ok, &mut end).await {
            pipeline.stop().await;
            return MediaOutcome::NotStarted(stop.end);
        }

        // A view-only session never gets an injector: its input is dropped
        // below, undecoded (SLICE-A2 A2-3).
        let injector = if matches!(mode, SessionMode::Control) {
            let backend = Arc::clone(&self.backend);
            tokio::task::spawn_blocking(move || backend.open_injector())
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let mut injector = injector.map(|sink| Tracked::new(Boxed(sink)));
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
        let reader = tokio::spawn(read_client(rd, inbound_tx));
        let epoch = Instant::now();
        let mut report = MediaReport::default();
        let mut window = AckWindow::new(self.limits.window_frames, self.limits.window_bytes);
        let mut inputs = TokenBucket::new(self.limits.input_rate, self.limits.input_burst, epoch);
        let mut pings = TokenBucket::new(PINGS_PER_SEC, PING_BURST, epoch);
        let mut keyframes = KeyframeLimiter::new(self.limits.keyframe_interval);
        let mut seq: u32 = 0;
        let mut pending = Some(first);
        let mut torn = false;
        // When the viewer last said anything, and whether what it holds has
        // been let go since (SLICE-C1 C1-3).
        let mut heard = tokio::time::Instant::now();
        let mut released = false;

        let ended = loop {
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
                if let Err(stop) = send(&mut wr, &msg, &mut end).await {
                    torn = stop.torn;
                    break stop.end;
                }
                window.sent(seq, len);
                report.frames_sent += 1;
                report.bytes_sent += len as u64;
                report.keyframes_sent += u64::from(frame.keyframe);
                seq = seq.wrapping_add(1);
                if window.has_room() {
                    pipeline.credit();
                }
            }

            let quiet_at = heard + self.limits.viewer_quiet;
            let watch_quiet = injector.is_some() && !released;
            let event = tokio::select! {
                biased;
                _ = end.changed() => Event::Ended,
                msg = inbound.recv() => Event::Client(msg),
                frame = pipeline.next() => Event::Frame(frame),
                () = tokio::time::sleep_until(quiet_at), if watch_quiet => Event::Quiet,
            };
            if let Event::Client(Some(Ok(_))) = event {
                heard = tokio::time::Instant::now();
                released = false;
            }
            match event {
                Event::Ended => break MediaEnd::SessionOver(end_reason(&end)),
                // A viewer that pings when it has nothing else to say has gone
                // quiet: it may be gone, and a key it holds would repeat on the
                // host until the session's idle timeout (SLICE-C1 C1-3).
                Event::Quiet => {
                    if let Some(sink) = injector.as_mut() {
                        sink.release_all();
                    }
                    released = true;
                    tracing::debug!(session = %session_id, "viewer quiet: released what it held");
                }
                Event::Frame(Some(Ok(frame))) => pending = Some(frame),
                Event::Frame(Some(Err(e))) => {
                    tracing::warn!(error = %e, session = %session_id, "screen capture stopped");
                    break MediaEnd::Pipeline(e.reason());
                }
                Event::Frame(None) => break MediaEnd::Pipeline(reason::CAPTURE_FAILED),
                Event::Client(None) => break MediaEnd::ViewerLeft,
                Event::Client(Some(Err(ProtoError::Io(e)))) => {
                    tracing::debug!(error = %e, "media stream read failed");
                    break MediaEnd::ViewerLeft;
                }
                Event::Client(Some(Err(e))) => {
                    tracing::info!(error = %e, session = %session_id, "viewer broke the media protocol");
                    break MediaEnd::Protocol;
                }
                Event::Client(Some(Ok(msg))) => match msg {
                    Msg::VideoAck { seq } => {
                        if window.ack(seq) && window.has_room() {
                            pipeline.credit();
                        }
                    }
                    Msg::Input(bytes) => {
                        // No injector: view-only (then the bytes are never
                        // even decoded), or nothing to inject into.
                        let Some(sink) = injector.as_mut() else {
                            report.input_dropped += 1;
                            continue;
                        };
                        let Ok(event) = InputEvent::decode(&bytes) else {
                            break MediaEnd::Protocol;
                        };
                        // A release never spends the budget, so it is never
                        // dropped: a lost key-up would leave the key down on
                        // this desktop (SLICE-E E1-6). `Tracked` injects one
                        // only for what it holds, so a flood of them injects
                        // nothing.
                        if !event.is_release() && !inputs.take(Instant::now()) {
                            report.input_dropped += 1;
                            continue;
                        }
                        match sink.inject(&event) {
                            Ok(()) => report.input_injected += 1,
                            Err(e) => {
                                report.input_dropped += 1;
                                tracing::debug!(error = %e, "input event not injected");
                            }
                        }
                    }
                    Msg::KeyframeRequest => {
                        report.keyframe_requests += 1;
                        if keyframes.allow(Instant::now()) {
                            report.keyframes_forced += 1;
                            pipeline.force_keyframe();
                        }
                    }
                    Msg::Ping { nonce } => {
                        if pings.take(Instant::now())
                            && let Err(stop) = send(&mut wr, &Msg::Pong { nonce }, &mut end).await
                        {
                            torn = stop.torn;
                            break stop.end;
                        }
                    }
                    Msg::Pong { .. } => {}
                    Msg::Close { .. } => break MediaEnd::ViewerLeft,
                    Msg::Bind { .. }
                    | Msg::BindOk { .. }
                    | Msg::BindRefused { .. }
                    | Msg::Video { .. } => break MediaEnd::Protocol,
                },
            }
        };

        // Release what the viewer holds first, then stop capture: both before
        // anything is said about the end.
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
                label: session.label.to_owned(),
                bound: false,
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
/// the protocol. Every client message is small, hence the cap.
async fn read_client<R: AsyncRead + Unpin>(mut rd: R, tx: mpsc::Sender<Result<Msg, ProtoError>>) {
    loop {
        let msg = match read_msg_max(&mut rd, MAX_CLIENT_FRAME).await {
            Ok(Some(msg)) => Ok(msg),
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
async fn send<W: AsyncWrite + Unpin>(
    wr: &mut W,
    msg: &Msg,
    end: &mut watch::Receiver<Option<u16>>,
) -> Result<(), Stop> {
    if end.has_changed().unwrap_or(true) {
        return Err(Stop {
            end: MediaEnd::SessionOver(end_reason(end)),
            torn: false,
        });
    }
    // The write is polled first, so a write that can complete does; only one
    // stalled on flow control is cut short.
    let written = tokio::select! {
        biased;
        written = write_msg(wr, msg) => Some(written),
        _ = end.changed() => None,
    };
    match written {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => {
            tracing::debug!(error = %e, "media stream write failed");
            Err(Stop {
                end: MediaEnd::Io,
                torn: true,
            })
        }
        None => Err(Stop {
            end: MediaEnd::SessionOver(end_reason(end)),
            torn: true,
        }),
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
