//! The viewer's half of a session's direct path (the direct design §4,
//! §8.5): [`ViewerDirect::choose_path`], run once per session right after
//! its `SESSION_ACCEPT`, and what it hands back ([`PathChoice`],
//! [`DirectMedia`]).
//!
//! The rules it keeps, each pinned by a test in `tests/direct_path.rs`:
//!
//! - the decision comes from the accept alone ([`decide`]): no media, an
//!   old host, this same device and every `tor_only` cell send their
//!   `TOR_FALLBACK` with no call to the network at all, and a `lan_only`
//!   session that can have no same-site path ends with nothing revealed;
//! - the path phase ends with exactly one of: a direct stream for the
//!   caller's `Bind`, this side's `TOR_FALLBACK{reason}` (its link closed
//!   first), or the session's end;
//! - `punch_timeout` from the accept caps every wait of an attempt up to
//!   an open stream (the host's frames, the link's news, `open_stream`),
//!   and it is checked before each wait, so host frames already buffered
//!   cannot postpone it; the reason then says what was heard by then
//!   ([`FallbackWhy`]). The link's start before it is raced against the
//!   caller's `interrupted` only; its interface read is bounded on its own
//!   (`tornect_net::local::IFACE_READ_TIMEOUT`, 1 s, on the real network).
//!   The cap does not bound the Tor writes on the way (this side's
//!   `CANDIDATES` and `CANDIDATES_DONE`, an owed `PONG`, the
//!   `TOR_FALLBACK`): those are bounded only by the caller's `interrupted`
//!   (the design's §4 write rule (a)), and the link's close before the
//!   `TOR_FALLBACK` by [`CLOSE_WAIT`]. A host that stops reading its Tor
//!   stream therefore holds the call past the cap until the caller stops
//!   it, and the fallback can leave up to [`CLOSE_WAIT`] after the cap;
//! - the link is shut before the `TOR_FALLBACK` is written, so no QUIC
//!   connection can complete after the host has read it
//!   ([`ViewerDirectStats::links_open`] is 0 by then);
//! - at most [`MAX_PATH_CANDIDATES`] `CANDIDATES` and one `CANDIDATES_DONE`
//!   are taken from the host, and a frame whose scope is above this side's
//!   is dropped; both are counted, never answered;
//! - every `select!` races only cancel-safe futures, the only writes are
//!   raced against the caller's `interrupted`, and a host `PING` is
//!   answered on the way ([`ClientSession::flush_owed`]): `interrupted`
//!   always ends the call within one poll.
//!
//! [`CLOSE_WAIT`]: tornect_net::link::CLOSE_WAIT

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;
use tornect_core::DeviceIdentity;
use tornect_net::{
    CandidateKind, DirectFail, DirectLink, DirectParams, Established, LinkNews, LinkStats,
    LocalBatch, NetEnv, QuicStream, Route, Scope, TornectRole,
};
use tornect_signal::HandshakeError;
use tornect_signal::consent::SessionToken;
use tornect_signal::fsm::client::{ClientSession, SessionEvent};
use tornect_signal::fsm::host::MAX_PATH_CANDIDATES;
use tornect_signal::messages::{bye, fallback, feats};
use zeroize::Zeroizing;

use super::decide::{Decision, FallbackWhy, Mine, PathEnd, TorWhy, decide};
use super::{AfterBind, DirectSettings, after_bind_close, from_wire, to_wire};
use crate::{Binding, MediaViewer, ViewerError};

/// The quinn priority of the media stream (the direct design §6.7: media
/// 1, services 0).
const MEDIA_PRIORITY: i32 = 1;

/// The viewer's half of the direct path (the direct design §8.5), shared by
/// every session the viewer opens: [`ViewerDirect::choose_path`] runs one
/// session's path phase. Clones share the counters.
#[derive(Clone)]
pub struct ViewerDirect {
    identity: Arc<DeviceIdentity>,
    settings: DirectSettings,
    env: Arc<dyn NetEnv>,
    counters: Arc<Counters>,
}

/// The direct viewer's counters: counts only, never an address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ViewerDirectStats {
    /// Links started (one per session at most).
    pub links_started: u64,
    /// Links of path phases still running: started, and neither shut yet
    /// (closed, or dropped, which shuts the endpoint) nor handed over with
    /// an open media stream ([`PathChoice::Direct`]). The count drops only
    /// after the link is shut.
    pub links_open: u64,
    /// Sessions whose link could not start (no address, no socket).
    pub start_failed: u64,
    /// The host's path frames dropped: `CANDIDATES` beyond
    /// [`MAX_PATH_CANDIDATES`], a second `CANDIDATES_DONE`, and a session
    /// event this build does not know (a future [`SessionEvent`] variant).
    /// An envelope kind with no place after the accept is not dropped: it
    /// is a fault, answered `ERROR` ([`PathChoice::Broken`]).
    pub frames_dropped: u64,
    /// The host's `CANDIDATES` frames dropped because their scope is above
    /// this side's (the direct design §4).
    pub frames_out_of_scope: u64,
}

#[derive(Default)]
struct Counters {
    links_started: AtomicU64,
    links_open: AtomicU64,
    start_failed: AtomicU64,
    frames_dropped: AtomicU64,
    frames_out_of_scope: AtomicU64,
}

impl Counters {
    fn count(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// The session's link while its path phase holds it, counted in
/// [`ViewerDirectStats::links_open`]. The fields drop in order: the link
/// first (a drop shuts it when nothing else holds it), then the count.
struct Live {
    link: DirectLink,
    _open: OpenCount,
}

/// One in [`ViewerDirectStats::links_open`], given back on drop.
struct OpenCount(Arc<Counters>);

impl Drop for OpenCount {
    fn drop(&mut self) {
        self.0.links_open.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Live {
    fn new(link: DirectLink, counters: &Arc<Counters>) -> Self {
        Counters::count(&counters.links_started);
        Counters::count(&counters.links_open);
        Self {
            link,
            _open: OpenCount(Arc::clone(counters)),
        }
    }

    /// [`DirectLink::close`]: shut at once, then at most [`CLOSE_WAIT`]
    /// for the endpoint to drain; the count drops after both. Dropped
    /// early (the caller's stop), it has shut the link already, or its
    /// drop does.
    ///
    /// [`CLOSE_WAIT`]: tornect_net::link::CLOSE_WAIT
    async fn close(self) {
        let Self { link, _open: open } = self;
        link.close().await;
        drop(open);
    }
}

/// How a session's path phase ended ([`ViewerDirect::choose_path`]).
#[derive(Debug)]
pub enum PathChoice {
    /// The direct stream is open: the caller writes the `Bind` on it
    /// ([`DirectMedia::bind`]), the commit point (decision M1-79).
    Direct(Box<DirectMedia>),
    /// `TOR_FALLBACK` was sent: the caller binds the onion media stream.
    Tor {
        /// Why.
        why: TorWhy,
        /// From the accept to the fallback (the CLI's `PATH` line).
        elapsed: Duration,
    },
    /// The session carries no media; `TOR_FALLBACK{NO_MEDIA}` was sent.
    NoMedia,
    /// The session must end: the caller sends `BYE{code}`. Only
    /// `NO_LAN_PATH` for now: a `lan_only` session with no same-site path
    /// (decision M1-85).
    End(u16),
    /// The host ended the session (`BYE` or `ERROR`) during the path phase.
    HostEnded(SessionEvent),
    /// The session's Tor stream broke, or the host broke the protocol (an
    /// `ERROR` was sent as far as it could be).
    Broken(HandshakeError),
    /// The caller's `interrupted` fired. Nothing more was written; the
    /// link, if any, is shut.
    Interrupted,
}

impl PathChoice {
    /// How the session's media path ended, for the window and the CLI;
    /// `None` when the session itself ended.
    #[must_use]
    pub fn path_end(&self) -> Option<PathEnd> {
        match self {
            Self::Direct(media) => Some(PathEnd::Direct(media.route)),
            Self::Tor { why, .. } => Some(PathEnd::Tor(*why)),
            Self::NoMedia => Some(PathEnd::NoMedia),
            Self::End(bye::NO_LAN_PATH) => Some(PathEnd::LanRefused),
            Self::End(_) | Self::HostEnded(_) | Self::Broken(_) | Self::Interrupted => None,
        }
    }
}

/// A session's open direct media stream, ready for the `Bind` (the direct
/// design §8.5 `DirectMedia`; the services stream joins at step B10).
pub struct DirectMedia {
    /// The media stream, opened at priority 1. The host sees it once the
    /// `Bind` is written.
    pub stream: QuicStream,
    /// The direct binding: its `Bind` MAC and the `BindProof` it expects
    /// cover this connection's exporter output.
    pub binding: Binding,
    /// The path's route label.
    pub route: Route,
    /// The kind of the host candidate the connection runs to (the CLI's
    /// `PATH` line).
    pub winner: CandidateKind,
    /// From the accept to the open stream.
    pub elapsed: Duration,
    /// The connection: [`after_bind_close`] reads it when the bind fails.
    pub link: Established,
}

impl fmt::Debug for DirectMedia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectMedia")
            .field("binding", &self.binding)
            .field("route", &self.route)
            .field("winner", &self.winner)
            .field("elapsed", &self.elapsed)
            .finish_non_exhaustive()
    }
}

/// A direct `Bind` that failed ([`DirectMedia::bind`]), and what the viewer
/// does next ([`after_bind_close`]).
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct DirectBindFailed {
    /// Why the bind failed.
    pub error: ViewerError,
    /// [`AfterBind::Fallback`]: send `TOR_FALLBACK{QUIC}` and bind the onion
    /// media stream; [`AfterBind::End`]: the session's media ends.
    pub after: AfterBind,
}

impl DirectMedia {
    /// Write the `Bind` and wait up to `wait` for the host's `BindProof`
    /// and `BindOk` ([`MediaViewer::bind`]; the caller's bind wait, never
    /// the punch window). On failure the connection is dropped, and
    /// [`DirectBindFailed::after`] says whether the session may still use
    /// the onion path (decision M1-79's one exception).
    ///
    /// # Errors
    ///
    /// [`DirectBindFailed`], as above.
    pub async fn bind(self, wait: Duration) -> Result<MediaViewer<QuicStream>, DirectBindFailed> {
        let Self {
            stream,
            binding,
            link,
            ..
        } = self;
        match MediaViewer::bind(stream, &binding, wait).await {
            Ok(viewer) => Ok(viewer),
            Err(error) => Err(DirectBindFailed {
                error,
                after: after_bind_close(&link),
            }),
        }
    }
}

/// One direct attempt's state, from its link's start to its end.
struct Attempt {
    accepted: Instant,
    deadline: Instant,
    scope: Scope,
    lan_only: bool,
    token: SessionToken,
    /// A path frame came from the host.
    heard_frame: bool,
    /// The host's `CANDIDATES` frames taken.
    candidates_in: usize,
    /// The host's `CANDIDATES_DONE` came.
    done_in: bool,
    /// This side's `CANDIDATES` frames written.
    candidates_out: usize,
}

/// How a wait in the attempt's loop ended.
enum Wake {
    Stop,
    Event(Result<(), HandshakeError>),
    News(Box<LinkNews>),
    Deadline,
}

/// What one wake leaves the attempt with.
enum Step {
    /// Wait again.
    Go,
    /// The media stream is open.
    Open(Box<DirectMedia>),
    /// The session ended, broke or the caller stopped: close the link and
    /// hand this back.
    Done(PathChoice),
    /// The attempt failed: close the link, then fall back (or end, under
    /// `lan_only`).
    GiveUp(TorWhy),
    /// The host broke the protocol: shut the link, then answer `ERROR`.
    Fault(HandshakeError),
}

impl ViewerDirect {
    /// The viewer's half for this device (`identity`), the direct path's
    /// `settings` (read once per session) and the network (`env`).
    #[must_use]
    pub fn new(
        identity: Arc<DeviceIdentity>,
        settings: DirectSettings,
        env: Arc<dyn NetEnv>,
    ) -> Self {
        Self {
            identity,
            settings,
            env,
            counters: Arc::default(),
        }
    }

    /// The counters.
    #[must_use]
    pub fn stats(&self) -> ViewerDirectStats {
        let c = &self.counters;
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        ViewerDirectStats {
            links_started: get(&c.links_started),
            links_open: get(&c.links_open),
            start_failed: get(&c.start_failed),
            frames_dropped: get(&c.frames_dropped),
            frames_out_of_scope: get(&c.frames_out_of_scope),
        }
    }

    /// Run `session`'s path phase (the direct design §4, §8.5
    /// `choose_path`), called at once after the accept: that call is `T0`,
    /// from which `punch_timeout` runs.
    ///
    /// `mine` is this computer's effective policy ([`Mine::from_knob`], or
    /// `tor_only` for `--tor-only`), `media` whether the session carries
    /// media. The host's policy is the one its accept signed (verified by
    /// `connect`, which refuses an unknown code). [`decide`] picks what to
    /// do; then:
    ///
    /// - a Tor decision writes its `TOR_FALLBACK` (`TOR_FALLBACK{}` to an
    ///   old host) and touches nothing else;
    /// - a try starts the session's one link, writes this side's
    ///   `CANDIDATES` (each with the scope), and waits for the host's
    ///   frames, the link's news and the hard cap. Success is the open
    ///   media stream ([`PathChoice::Direct`]); a failure closes the link,
    ///   then writes `TOR_FALLBACK{reason}`, or, under `lan_only`, returns
    ///   [`PathChoice::End`]`(NO_LAN_PATH)` for the caller's `BYE`.
    ///
    /// `interrupted` (the caller's stop: the window closed, the panic key)
    /// is raced against every wait and every write: once it fires the call
    /// returns [`PathChoice::Interrupted`] within one poll, with the link
    /// shut and nothing more written. It is not polled after it fired.
    pub async fn choose_path<S, F>(
        &self,
        session: &mut ClientSession<S>,
        mine: Mine,
        media: bool,
        interrupted: F,
    ) -> PathChoice
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        F: Future<Output = ()>,
    {
        let accepted = Instant::now();
        let mut stop = std::pin::pin!(interrupted);
        let own_pk = self.identity.verifying_key().to_bytes();
        let decision = decide(
            session.transport_policy(),
            mine,
            media,
            session.host_has(feats::DIR1),
            session.host_device_pk() == own_pk,
        );
        tracing::debug!(?decision, "direct path decided");
        match decision {
            Decision::NoMedia => {
                match race(
                    &mut stop,
                    session.send_tor_fallback(Some(fallback::NO_MEDIA)),
                )
                .await
                {
                    None => PathChoice::Interrupted,
                    Some(Err(e)) => PathChoice::Broken(e),
                    Some(Ok(())) => PathChoice::NoMedia,
                }
            }
            Decision::Tor { reason, why } => {
                send_fallback(session, &mut stop, reason, why, accepted).await
            }
            Decision::LanRefused => PathChoice::End(bye::NO_LAN_PATH),
            Decision::Try { scope, lan_only } => {
                let deadline = accepted + self.settings.get().punch_timeout;
                let attempt = Attempt {
                    accepted,
                    deadline,
                    scope,
                    lan_only,
                    token: session.session_token().clone(),
                    heard_frame: false,
                    candidates_in: 0,
                    done_in: false,
                    candidates_out: 0,
                };
                self.attempt(session, &mut stop, attempt).await
            }
        }
    }

    /// The `Try` decision: the link, the exchange and the hard cap.
    async fn attempt<S, F>(
        &self,
        session: &mut ClientSession<S>,
        stop: &mut Pin<&mut F>,
        mut at: Attempt,
    ) -> PathChoice
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        F: Future<Output = ()>,
    {
        let options = self.settings.get();
        let params = DirectParams {
            me: TornectRole::Viewer,
            identity: Arc::clone(&self.identity),
            peer_pk: session.host_device_pk(),
            session_token: Zeroizing::new(*at.token.bytes()),
            direct_port: options.direct_port,
            scope: at.scope,
            gather: options.gather(TornectRole::Viewer),
        };
        let Some(started) = race(stop, DirectLink::start(params, Arc::clone(&self.env))).await
        else {
            return PathChoice::Interrupted;
        };
        let (link, offered) = match started {
            Ok(started) => started,
            Err(fail) => {
                Counters::count(&self.counters.start_failed);
                let why = match fail {
                    DirectFail::NoAddresses => TorWhy::Fallback(FallbackWhy::HereNoAddresses),
                    DirectFail::SameKey => TorWhy::SameDevice,
                    _ => TorWhy::Fallback(FallbackWhy::HereSocket),
                };
                return give_up(session, stop, None, &at, why).await;
            }
        };
        let mut link = Live::new(link, &self.counters);
        if let Err(choice) = send_batch(session, stop, &mut at, &offered).await {
            return end(link, choice);
        }
        loop {
            // The cap is checked before every wait: the select below polls
            // the host's frames before the deadline, so frames already
            // buffered (or a write that outlasted the cap) must not keep
            // the attempt going.
            let wake = if Instant::now() >= at.deadline {
                Wake::Deadline
            } else {
                tokio::select! {
                    biased;
                    () = stop.as_mut() => Wake::Stop,
                    ready = session.event_ready() => Wake::Event(ready),
                    news = link.link.next_news() => Wake::News(Box::new(news)),
                    () = tokio::time::sleep_until(at.deadline) => Wake::Deadline,
                }
            };
            let step = match wake {
                Wake::Stop => Step::Done(PathChoice::Interrupted),
                Wake::Deadline => Step::GiveUp(TorWhy::Fallback(timeout_reason(
                    at.heard_frame,
                    &link.link.stats(),
                ))),
                Wake::Event(Err(e)) => Step::Done(PathChoice::Broken(e)),
                Wake::Event(Ok(())) => match self.host_frame(session, &link.link, &mut at) {
                    Step::Go if session.owes() => match race(stop, session.flush_owed()).await {
                        None => Step::Done(PathChoice::Interrupted),
                        Some(Err(e)) => Step::Done(PathChoice::Broken(e)),
                        Some(Ok(())) => Step::Go,
                    },
                    step => step,
                },
                Wake::News(news) => link_news(session, stop, &mut at, &link.link, *news).await,
            };
            match step {
                Step::Go => {}
                Step::Open(media) => {
                    // The stream and the connection hold the link's socket;
                    // its driver is over.
                    drop(link);
                    return PathChoice::Direct(media);
                }
                Step::Done(choice) => return end(link, choice),
                Step::GiveUp(why) => return give_up(session, stop, Some(link), &at, why).await,
                Step::Fault(e) => {
                    drop(link);
                    return match race(stop, session.fail_bounded(e)).await {
                        None => PathChoice::Interrupted,
                        Some(e) => PathChoice::Broken(e),
                    };
                }
            }
        }
    }

    /// The one frame [`ClientSession::event_ready`] announced, taken
    /// without waiting or writing ([`ClientSession::take_event`]).
    fn host_frame<S>(
        &self,
        session: &mut ClientSession<S>,
        link: &DirectLink,
        at: &mut Attempt,
    ) -> Step
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let event = match session.take_event() {
            Ok(Some(event)) => event,
            // A host `PING` (its `PONG` is owed) or no whole frame yet.
            Ok(None) => return Step::Go,
            Err(e @ HandshakeError::Violation { .. }) => return Step::Fault(e),
            Err(e) => return Step::Done(PathChoice::Broken(e)),
        };
        match event {
            SessionEvent::Candidates(frame) => {
                at.heard_frame = true;
                if at.candidates_in >= MAX_PATH_CANDIDATES {
                    Counters::count(&self.counters.frames_dropped);
                    return Step::Go;
                }
                at.candidates_in += 1;
                let (batch, scope) = from_wire(&frame);
                if scope > at.scope {
                    Counters::count(&self.counters.frames_out_of_scope);
                } else {
                    link.add_remote(batch, scope);
                }
                Step::Go
            }
            SessionEvent::CandidatesDone => {
                at.heard_frame = true;
                if at.done_in {
                    Counters::count(&self.counters.frames_dropped);
                } else {
                    at.done_in = true;
                    link.remote_done();
                }
                Step::Go
            }
            SessionEvent::TorFallback(reason) => Step::GiveUp(TorWhy::from_host_reason(reason)),
            event @ (SessionEvent::Bye { .. } | SessionEvent::Error { .. }) => {
                Step::Done(PathChoice::HostEnded(event))
            }
            _ => {
                Counters::count(&self.counters.frames_dropped);
                Step::Go
            }
        }
    }
}

/// `fut`, unless `stop` fires first (`None`). `stop` is polled first.
async fn race<F, T>(stop: &mut Pin<&mut F>, fut: impl Future<Output = T>) -> Option<T>
where
    F: Future<Output = ()>,
{
    tokio::select! {
        biased;
        () = stop.as_mut() => None,
        out = fut => Some(out),
    }
}

/// The link's news: this side's next batch or the end of gathering (each
/// written to the host), or its connection, whose media stream is opened
/// before the hard cap.
async fn link_news<S, F>(
    session: &mut ClientSession<S>,
    stop: &mut Pin<&mut F>,
    at: &mut Attempt,
    link: &DirectLink,
    news: LinkNews,
) -> Step
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    F: Future<Output = ()>,
{
    match news {
        LinkNews::Local(LocalBatch::More(batch)) => {
            match send_batch(session, stop, at, &batch).await {
                Ok(()) => Step::Go,
                Err(choice) => Step::Done(choice),
            }
        }
        LinkNews::Local(LocalBatch::Done) => match race(stop, session.send_candidates_done()).await
        {
            None => Step::Done(PathChoice::Interrupted),
            Some(Err(e)) => Step::Done(PathChoice::Broken(e)),
            Some(Ok(())) => Step::Go,
        },
        LinkNews::Connection(Ok(established)) => {
            let opened = tokio::select! {
                biased;
                () = stop.as_mut() => return Step::Done(PathChoice::Interrupted),
                opened = established.open_stream(MEDIA_PRIORITY) => opened.ok(),
                () = tokio::time::sleep_until(at.deadline) => None,
            };
            let ekm = established.binding_secret(at.token.bytes());
            let (Some(stream), Ok(ekm)) = (opened, ekm) else {
                return Step::GiveUp(TorWhy::Fallback(FallbackWhy::Quic));
            };
            let binding = Binding::direct(&at.token, &session.th(), &ekm);
            let elapsed = at.accepted.elapsed();
            // Counts only (decision M1-83): the device rows of the direct
            // design §13 read `dual_stack` and the send counters here.
            tracing::debug!(
                ms = elapsed.as_millis(),
                winner = ?established.winner(),
                route = ?established.route(),
                stats = ?established.stats(),
                "direct path open"
            );
            Step::Open(Box::new(DirectMedia {
                stream,
                binding,
                route: established.route(),
                winner: established.winner(),
                elapsed,
                link: established,
            }))
        }
        LinkNews::Connection(Err(fail)) => {
            let why = match fail {
                DirectFail::NoPath { heard } => FallbackWhy::NoPath { heard },
                DirectFail::Quic => FallbackWhy::Quic,
                _ => timeout_reason(at.heard_frame, &link.stats()),
            };
            Step::GiveUp(TorWhy::Fallback(why))
        }
    }
}

/// Writes `batch` as `CANDIDATES` frames with the attempt's scope, at most
/// [`MAX_PATH_CANDIDATES`] frames per session (the rest are not sent).
async fn send_batch<S, F>(
    session: &mut ClientSession<S>,
    stop: &mut Pin<&mut F>,
    at: &mut Attempt,
    batch: &[tornect_net::Candidate],
) -> Result<(), PathChoice>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    F: Future<Output = ()>,
{
    for frame in to_wire(batch, at.scope) {
        if at.candidates_out >= MAX_PATH_CANDIDATES {
            tracing::debug!("own candidates beyond the frame limit not sent");
            break;
        }
        match race(stop, session.send_candidates(&frame)).await {
            None => return Err(PathChoice::Interrupted),
            Some(Err(e)) => return Err(PathChoice::Broken(e)),
            Some(Ok(())) => at.candidates_out += 1,
        }
    }
    Ok(())
}

/// Why a direct attempt ended without a connection at its hard cap (the
/// direct design §8.5 "Timeout reason"): nothing heard from the host (no
/// path frame, no probe) is [`FallbackWhy::HostSilent`]; else a validated
/// address is [`FallbackWhy::Quic`]; else [`FallbackWhy::NoPath`].
fn timeout_reason(heard_frame: bool, stats: &LinkStats) -> FallbackWhy {
    if !heard_frame && !stats.heard {
        FallbackWhy::HostSilent
    } else if stats.validated > 0 {
        FallbackWhy::Quic
    } else {
        FallbackWhy::NoPath { heard: stats.heard }
    }
}

/// The attempt failed: close the link (when there is one), then
/// `TOR_FALLBACK{reason}`, or `End(NO_LAN_PATH)` under `lan_only`. The
/// order is the design's (§4 "Who does what"): no QUIC connection can
/// complete after the host has read the fallback.
async fn give_up<S, F>(
    session: &mut ClientSession<S>,
    stop: &mut Pin<&mut F>,
    link: Option<Live>,
    at: &Attempt,
    why: TorWhy,
) -> PathChoice
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    F: Future<Output = ()>,
{
    if let Some(link) = link {
        tracing::debug!(stats = ?link.link.stats(), reason = why.cli_name(), "direct path failed");
        // Dropped on a stop, the close has shut the link already.
        if race(stop, link.close()).await.is_none() {
            return PathChoice::Interrupted;
        }
    }
    if at.lan_only {
        tracing::debug!(reason = why.cli_name(), "no same-site path");
        return PathChoice::End(bye::NO_LAN_PATH);
    }
    send_fallback(session, stop, why.code(), why, at.accepted).await
}

/// The session ended, broke or the caller stopped during the attempt: the
/// link is shut at once (no endpoint drain to wait for, since nothing more
/// is sent on the session), then `choice` is handed back.
fn end(link: Live, choice: PathChoice) -> PathChoice {
    drop(link);
    choice
}

/// Writes `TOR_FALLBACK{reason}`: the session's media goes over Tor.
async fn send_fallback<S, F>(
    session: &mut ClientSession<S>,
    stop: &mut Pin<&mut F>,
    reason: Option<u32>,
    why: TorWhy,
    accepted: Instant,
) -> PathChoice
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    F: Future<Output = ()>,
{
    match race(stop, session.send_tor_fallback(reason)).await {
        None => PathChoice::Interrupted,
        Some(Err(e)) => PathChoice::Broken(e),
        Some(Ok(())) => {
            let elapsed = accepted.elapsed();
            tracing::debug!(
                reason = why.cli_name(),
                code = reason.map(fallback::name),
                ms = elapsed.as_millis(),
                "media over Tor"
            );
            PathChoice::Tor { why, elapsed }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The timeout reason of the direct design §8.5: nothing heard is
    /// `host-silent`, a validated address `quic`, else `no-path` with
    /// whether the host's probes arrived.
    #[test]
    fn the_timeout_reason_says_what_was_heard() {
        let stats = |heard, validated| LinkStats {
            heard,
            validated,
            ..LinkStats::default()
        };
        assert_eq!(
            timeout_reason(false, &stats(false, 0)),
            FallbackWhy::HostSilent
        );
        assert_eq!(
            timeout_reason(true, &stats(false, 0)),
            FallbackWhy::NoPath { heard: false }
        );
        assert_eq!(
            timeout_reason(false, &stats(true, 0)),
            FallbackWhy::NoPath { heard: true }
        );
        assert_eq!(timeout_reason(true, &stats(true, 1)), FallbackWhy::Quic);
        assert_eq!(timeout_reason(false, &stats(true, 2)), FallbackWhy::Quic);
    }

    /// `path_end` is the window's and the CLI's reading of a choice: the
    /// session's own end has none, `NO_LAN_PATH` is the `lan_only` end.
    #[test]
    fn a_choice_has_a_path_end_unless_the_session_ended() {
        let tor = PathChoice::Tor {
            why: TorWhy::OldHost,
            elapsed: Duration::ZERO,
        };
        assert_eq!(tor.path_end(), Some(PathEnd::Tor(TorWhy::OldHost)));
        assert_eq!(PathChoice::NoMedia.path_end(), Some(PathEnd::NoMedia));
        assert_eq!(
            PathChoice::End(bye::NO_LAN_PATH).path_end(),
            Some(PathEnd::LanRefused)
        );
        assert_eq!(PathChoice::End(bye::USER).path_end(), None);
        assert_eq!(PathChoice::Interrupted.path_end(), None);
        assert_eq!(PathChoice::Broken(HandshakeError::Closed).path_end(), None);
        let bye = SessionEvent::Bye {
            reason: bye::USER,
            detail: None,
        };
        assert_eq!(PathChoice::HostEnded(bye).path_end(), None);
    }
}
