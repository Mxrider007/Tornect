//! The host's half of a session's direct path (the direct design §4, §8.5):
//! [`DirectHost`], the [`PathExchange`] the host FSM hands each accepted
//! session's path frames to.
//!
//! The rules it keeps, each pinned by a test in `tests/direct_host.rs`:
//!
//! - the session's policy is the one its `SESSION_ACCEPT` signed
//!   ([`LiveSession::transport`]), never the host's current knob: a
//!   `tor_only` session, and a viewer that is this same device, are answered
//!   `TOR_FALLBACK{OFF}` and nothing else happens, with no call to the
//!   network at all;
//! - the viewer goes first: nothing is bound before its first `CANDIDATES`,
//!   and nothing ever when its `TOR_FALLBACK` comes first;
//! - one link per session, never bound again once closed;
//! - the link closes on the viewer's `TOR_FALLBACK` before a claim, on the
//!   onion path's claim (whether or not a `TOR_FALLBACK` came), on a kill or
//!   an end of the viewer's device (at once; a media stream live on the link
//!   first ends through its own teardown, as on the onion path, within
//!   [`DIRECT_DRAIN`]), on a refused direct `Bind`, on
//!   the [`HOST_DIRECT_LINGER`] without a direct claim, and at the session's
//!   end (after the media stream's last frames, bounded by [`DIRECT_DRAIN`]);
//! - a `TOR_FALLBACK` after a direct claim is ignored (counted);
//! - a `lan_only` session with no direct path left ends `BYE{NO_LAN_PATH}`;
//! - the session's `sessions.log` end line says how its path went
//!   ([`PathSummary`]): words, a kind and a time, never an address.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tornect_core::session_log::{PathSummary, TransportKind};
use tornect_core::{DeviceId, DeviceIdentity};
use tornect_net::{
    BoxFuture, Candidate, CandidateKind, DialFailure, DirectFail, DirectLink, DirectParams,
    Established, LinkNews, LocalBatch, NetEnv, Scope, TornectRole,
};
use tornect_signal::consent::TransportPolicy;
use tornect_signal::fsm::host::{KillGuard, KillSwitch, LiveSession, MAX_PATH_CANDIDATES};
use tornect_signal::fsm::{PATH_INBOX, PathExchange, PathFrame, PathPort, PathRecord};
use tornect_signal::messages::{self, bye, fallback};
use zeroize::Zeroizing;

use super::{DIRECT_DRAIN, DirectSettings, HOST_DIRECT_LINGER, INTERNET_DIRECT, SecondStream};
use super::{from_wire, to_wire};
use crate::{MediaHost, MediaOutcome};

/// What the host's owner hears of each direct media stream once it ended
/// ([`MediaHost::serve_direct`]'s outcome), as the onion acceptor hears
/// [`MediaHost::serve`]'s: its lines and its window.
pub type OnMedia = Arc<dyn Fn(&MediaOutcome) + Send + Sync>;

/// The outbox's room: the host writes at most [`MAX_PATH_CANDIDATES`]
/// `CANDIDATES`, one `CANDIDATES_DONE` and one `TOR_FALLBACK` or end, so it
/// is never full (a frame that finds it full is dropped and counted).
const PATH_OUTBOX: usize = MAX_PATH_CANDIDATES + 4;

/// The host's half of the direct path (the direct design §8.5), shared by
/// every session: [`PathExchange::open`] starts one task per session that
/// takes part, [`PathExchange::outcome`] reads how it went.
pub struct DirectHost {
    media: Arc<MediaHost>,
    second: Option<Arc<dyn SecondStream>>,
    identity: Arc<DeviceIdentity>,
    settings: DirectSettings,
    env: Arc<dyn NetEnv>,
    kill: KillSwitch,
    on_media: OnMedia,
    shared: Arc<Shared>,
    /// Internet scope may be offered: [`INTERNET_DIRECT`], or a test's
    /// choice ([`DirectHost::with_internet`]).
    internet: bool,
}

/// The direct host's counters: counts only, never an address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectHostStats {
    /// Links started (one per session at most).
    pub links_started: u64,
    /// Links open now.
    pub links_open: u64,
    /// Sessions whose link could not start (no address, no socket).
    pub start_failed: u64,
    /// The viewer's `TOR_FALLBACK`s after a direct claim, ignored.
    pub late_fallbacks: u64,
    /// The viewer's `CANDIDATES` and `CANDIDATES_DONE` that came when the
    /// session's link could no longer be started or was closed, ignored.
    pub frames_ignored: u64,
    /// Outbox frames dropped because the outbox was full or closed.
    pub outbox_dropped: u64,
}

#[derive(Default)]
struct Shared {
    /// Each open session's path, by session id, until the FSM reads its
    /// outcome.
    records: Mutex<HashMap<String, Record>>,
    links_started: AtomicU64,
    links_open: AtomicU64,
    start_failed: AtomicU64,
    late_fallbacks: AtomicU64,
    frames_ignored: AtomicU64,
    outbox_dropped: AtomicU64,
}

impl Shared {
    fn records(&self) -> MutexGuard<'_, HashMap<String, Record>> {
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes session `id`'s record, if the FSM has not read it yet.
    fn note(&self, id: &str, change: impl FnOnce(&mut Record)) {
        if let Some(record) = self.records().get_mut(id) {
            change(record);
        }
    }

    fn count(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// How one session's path went so far, as its summary is made from it.
/// Each `ms` is from the session's accept (its [`PathExchange::open`]).
#[derive(Debug, Clone, Copy)]
struct Record {
    accepted: Instant,
    /// The viewer did not announce `dir1`.
    old_viewer: bool,
    /// The host's own `TOR_FALLBACK` code (or, under `lan_only`, what made
    /// it end the session): the session's policy, this device, no address,
    /// no socket.
    declined: Option<(u32, u32)>,
    /// The viewer's first `TOR_FALLBACK` reason.
    viewer_fallback: Option<(Option<u32>, u32)>,
    /// The link's connection: its winning candidate's kind and family.
    connected: Option<(CandidateKind, bool)>,
    /// When the direct claim was seen.
    claimed: Option<u32>,
    /// A direct `Bind` was refused.
    bind_refused: Option<u32>,
    /// A TLS pin refused a handshake of the link.
    pin_refused: Option<u32>,
    /// The linger closed the link.
    lingered: Option<u32>,
}

impl Record {
    fn new(accepted: Instant) -> Self {
        Self {
            accepted,
            old_viewer: false,
            declined: None,
            viewer_fallback: None,
            connected: None,
            claimed: None,
            bind_refused: None,
            pin_refused: None,
            lingered: None,
        }
    }

    /// The summary for a session whose media bound on `route` (none: no
    /// media bound). A direct claim says `direct`; otherwise the first of a
    /// refused `Bind`, a refused pin, the host's own reason, the viewer's
    /// reason, the linger and an old viewer.
    fn summary(&self, route: Option<TransportKind>) -> Option<PathSummary> {
        let plain = |outcome: &str, ms: u32| PathSummary {
            outcome: outcome.to_owned(),
            winner: None,
            ipv6: false,
            ms,
        };
        if matches!(route, Some(TransportKind::Lan | TransportKind::Direct)) {
            return Some(PathSummary {
                outcome: "direct".to_owned(),
                winner: self.connected.map(|(kind, _)| kind.name().to_owned()),
                ipv6: self.connected.is_some_and(|(_, ipv6)| ipv6),
                ms: self.claimed.unwrap_or_else(|| ms_since(self.accepted)),
            });
        }
        if let Some(ms) = self.bind_refused {
            return Some(plain("bind-refused", ms));
        }
        if let Some(ms) = self.pin_refused {
            return Some(plain("pin-refused", ms));
        }
        if let Some((code, ms)) = self.declined {
            return Some(plain(fallback::name(code), ms));
        }
        if let Some((reason, ms)) = self.viewer_fallback {
            return Some(plain(reason.map_or("unknown", fallback::name), ms));
        }
        if let Some(ms) = self.lingered {
            return Some(plain(fallback::name(fallback::NO_PATH), ms));
        }
        self.old_viewer.then(|| plain("old-viewer", 0))
    }
}

/// Milliseconds since `t0`, saturating.
fn ms_since(t0: Instant) -> u32 {
    u32::try_from(t0.elapsed().as_millis()).unwrap_or(u32::MAX)
}

impl DirectHost {
    /// The direct host of `media`'s sessions: `identity` is this device's
    /// key (the link's QUIC key, and how a viewer that is this same device
    /// is recognised), `settings` the `[network]` options, `env` the
    /// network, `kill` the host-wide kill switch, `on_media` what hears each
    /// direct media stream's end. `second` serves the connection's second
    /// stream ([`SecondStream`]); `None` until the services layer
    /// implements it.
    #[must_use]
    pub fn new(
        media: Arc<MediaHost>,
        second: Option<Arc<dyn SecondStream>>,
        identity: Arc<DeviceIdentity>,
        settings: DirectSettings,
        env: Arc<dyn NetEnv>,
        kill: KillSwitch,
        on_media: OnMedia,
    ) -> Self {
        Self {
            media,
            second,
            identity,
            settings,
            env,
            kill,
            on_media,
            shared: Arc::default(),
            internet: INTERNET_DIRECT,
        }
    }

    /// The same host with internet scope on or off, whatever
    /// [`INTERNET_DIRECT`] says: the NAT matrix (the direct design §12.4)
    /// runs in internet scope before step B12 turns it on.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_internet(mut self, on: bool) -> Self {
        self.internet = on;
        self
    }

    /// The counters.
    #[must_use]
    pub fn stats(&self) -> DirectHostStats {
        let s = &self.shared;
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        DirectHostStats {
            links_started: get(&s.links_started),
            links_open: get(&s.links_open),
            start_failed: get(&s.start_failed),
            late_fallbacks: get(&s.late_fallbacks),
            frames_ignored: get(&s.frames_ignored),
            outbox_dropped: get(&s.outbox_dropped),
        }
    }
}

impl fmt::Debug for DirectHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectHost")
            .field("stats", &self.stats())
            .field("second", &self.second.is_some())
            .finish_non_exhaustive()
    }
}

/// A port whose outbox holds `frame` and then closes; the viewer's frames
/// are dropped and counted by the FSM (no inbox).
fn answered(frame: PathFrame) -> PathPort {
    let (tx, rx) = mpsc::channel(1);
    // Cannot fail: a fresh channel with room.
    let _ = tx.try_send(frame);
    PathPort {
        outbox: Some(rx),
        inbox: None,
    }
}

impl PathExchange for DirectHost {
    fn open(&self, session: &LiveSession<'_>) -> PathPort {
        let accepted = Instant::now();
        let id = session.session_id.to_owned();
        let lan_only = session.transport == TransportPolicy::LanOnly;
        let mut record = Record::new(accepted);
        // Under `lan_only` there is no fallback: a session that cannot go
        // direct ends (decision M1-85).
        let decline = |code: u32| {
            if lan_only {
                answered(PathFrame::End(bye::NO_LAN_PATH))
            } else {
                answered(PathFrame::TorFallback(Some(code)))
            }
        };
        if !session.viewer_dir1 {
            record.old_viewer = true;
            self.shared.records().insert(id, record);
            return if lan_only {
                answered(PathFrame::End(bye::NO_LAN_PATH))
            } else {
                PathPort::default()
            };
        }
        let claimed = self.media.claimed(session.session_id);
        let runtime = tokio::runtime::Handle::try_current();
        let refusal = if session.transport == TransportPolicy::TorOnly
            || session.device == self.identity.id()
        {
            Some(fallback::OFF)
        } else if claimed.is_none() {
            // No media registered for the session here: nothing to serve.
            tracing::warn!(session = %id, "a session without media reached the direct host");
            Some(fallback::OFF)
        } else if runtime.is_err() {
            Some(fallback::SOCKET)
        } else {
            None
        };
        let (Some(claimed), Ok(runtime), None) = (claimed, runtime, refusal) else {
            let code = refusal.unwrap_or(fallback::OFF);
            record.declined = Some((code, 0));
            self.shared.records().insert(id, record);
            return decline(code);
        };

        let (inbox_tx, inbox) = mpsc::channel(PATH_INBOX);
        let (outbox, outbox_rx) = mpsc::channel(PATH_OUTBOX);
        // Armed now, so a kill from here on is seen even while the task
        // waits for the viewer's first frame; an end of the viewer's device
        // too.
        let mut kill = self.kill.arm();
        kill.watch_device(session.device);
        let task = Task {
            id: id.clone(),
            device: session.device,
            token: Zeroizing::new(*session.token.bytes()),
            lan_only,
            policy: session.transport,
            internet: self.internet,
            media: Arc::clone(&self.media),
            second: self.second.clone(),
            identity: Arc::clone(&self.identity),
            settings: self.settings.clone(),
            env: Arc::clone(&self.env),
            on_media: Arc::clone(&self.on_media),
            shared: Arc::clone(&self.shared),
            accepted,
            inbox,
            inbox_open: true,
            outbox,
            candidates_sent: 0,
            claimed,
            claim_open: true,
            kill,
            link: None,
            may_bind: true,
            remote_done: false,
            direct_claim: false,
            ended: false,
        };
        self.shared.records().insert(id, record);
        runtime.spawn(task.run());
        PathPort {
            outbox: Some(outbox_rx),
            inbox: Some(inbox_tx),
        }
    }

    fn outcome(&self, session_id: &str) -> PathRecord {
        let transport = self.media.route(session_id);
        let record = self.shared.records().remove(session_id);
        PathRecord {
            transport,
            path: record.and_then(|r| r.summary(transport)),
        }
    }
}

/// A session's open link and what runs on it.
struct Open {
    link: DirectLink,
    /// The scope the link was started with: the lower of this side's and
    /// the viewer's.
    scope: Scope,
    /// When the linger closes the link; none once the media was claimed on
    /// it.
    linger_at: Option<Instant>,
    /// The connection, once it passed the peer check.
    conn: Option<Established>,
    /// The media stream: accepted, then served ([`MediaHost::serve_direct`]);
    /// `None` when no stream came.
    serving: Option<BoxFuture<'static, Option<MediaOutcome>>>,
    /// The second stream ([`SecondStream`]), once the media was claimed.
    second: Option<BoxFuture<'static, ()>>,
    /// The media stream was served to its end: the link closes once the
    /// viewer closed the connection, or at this time.
    drain_until: Option<Instant>,
}

/// One session's direct path (the direct design §8.5 steps 1–9).
struct Task {
    id: String,
    device: DeviceId,
    token: Zeroizing<[u8; 32]>,
    lan_only: bool,
    policy: TransportPolicy,
    /// Internet scope may be offered (the direct host's `internet`).
    internet: bool,
    media: Arc<MediaHost>,
    second: Option<Arc<dyn SecondStream>>,
    identity: Arc<DeviceIdentity>,
    settings: DirectSettings,
    env: Arc<dyn NetEnv>,
    on_media: OnMedia,
    shared: Arc<Shared>,
    accepted: Instant,
    inbox: mpsc::Receiver<PathFrame>,
    inbox_open: bool,
    outbox: mpsc::Sender<PathFrame>,
    candidates_sent: usize,
    claimed: watch::Receiver<Option<TransportKind>>,
    claim_open: bool,
    kill: KillGuard,
    link: Option<Open>,
    /// No link was started yet, and nothing has ruled one out.
    may_bind: bool,
    /// The viewer's `CANDIDATES_DONE` came before the link started.
    remote_done: bool,
    /// The session's media was claimed on this session's link.
    direct_claim: bool,
    /// The session was ended through the outbox.
    ended: bool,
}

/// What woke a session's task.
enum Woke {
    Killed,
    Frame(Option<PathFrame>),
    /// The claim changed (`true`) or its channel closed.
    Claim(bool),
    News(LinkNews),
    Served(Option<MediaOutcome>),
    SecondOver,
    Drained,
    Linger,
}

impl Task {
    async fn run(mut self) {
        loop {
            // Every branch is cancel safe: the kill guard, channel and watch
            // receives, the link's news, boxed futures polled in place, a
            // connection's close and sleeps.
            let woke = tokio::select! {
                biased;
                _ = self.kill.killed() => Woke::Killed,
                frame = self.inbox.recv(), if self.inbox_open => Woke::Frame(frame),
                changed = self.claimed.changed(), if self.claim_open => Woke::Claim(changed.is_ok()),
                woke = link_news(&mut self.link) => woke,
            };
            match woke {
                Woke::Killed => {
                    self.media_goodbye().await;
                    self.close_link().await;
                    return;
                }
                Woke::Frame(Some(frame)) => self.on_frame(frame).await,
                Woke::Frame(None) => {
                    self.session_over().await;
                    return;
                }
                Woke::Claim(true) => {
                    let claim = *self.claimed.borrow_and_update();
                    self.on_claim(claim).await;
                }
                Woke::Claim(false) => self.claim_open = false,
                Woke::News(LinkNews::Local(batch)) => self.on_local(batch),
                Woke::News(LinkNews::Connection(result)) => self.on_connection(result).await,
                Woke::Served(outcome) => self.on_served(outcome).await,
                Woke::SecondOver => {
                    if let Some(open) = self.link.as_mut() {
                        open.second = None;
                    }
                }
                Woke::Drained => self.close_link().await,
                Woke::Linger => self.on_linger().await,
            }
        }
    }

    async fn on_frame(&mut self, frame: PathFrame) {
        match frame {
            PathFrame::Candidates(candidates) => {
                if let Some(open) = &self.link {
                    let (batch, scope) = from_wire(&candidates);
                    open.link.add_remote(batch, scope.min(open.scope));
                } else if self.may_bind && !self.ended {
                    self.start(&candidates).await;
                } else {
                    Shared::count(&self.shared.frames_ignored);
                }
            }
            PathFrame::Done => {
                if let Some(open) = &self.link {
                    open.link.remote_done();
                } else if self.may_bind {
                    self.remote_done = true;
                } else {
                    Shared::count(&self.shared.frames_ignored);
                }
            }
            PathFrame::TorFallback(reason) => {
                let ms = ms_since(self.accepted);
                self.shared.note(&self.id, |r| {
                    r.viewer_fallback.get_or_insert((reason, ms));
                });
                if self.direct_claim || self.claimed_here() {
                    // After the commit the viewer never falls back (decision M1-79):
                    // the direct media stands.
                    Shared::count(&self.shared.late_fallbacks);
                    return;
                }
                self.close_link().await;
                if self.lan_only {
                    self.end(bye::NO_LAN_PATH);
                }
            }
            // The FSM never passes one in.
            PathFrame::End(_) => {}
        }
    }

    /// The viewer's first `CANDIDATES`: start the session's one link.
    async fn start(&mut self, first: &messages::Candidates) {
        self.may_bind = false;
        let (remote, viewer_scope) = from_wire(first);
        let own = if self.internet && self.policy == TransportPolicy::Any {
            Scope::Internet
        } else {
            Scope::SameSite
        };
        let scope = own.min(viewer_scope);
        let options = self.settings.get();
        let params = DirectParams {
            me: TornectRole::Host,
            identity: Arc::clone(&self.identity),
            peer_pk: *self.device.public_key_bytes(),
            session_token: self.token.clone(),
            direct_port: options.direct_port,
            scope,
            gather: options.gather(TornectRole::Host),
        };
        let started = tokio::select! {
            biased;
            // The kill fires again in the loop, which ends the task.
            _ = self.kill.killed() => return,
            started = DirectLink::start(params, Arc::clone(&self.env)) => started,
        };
        let (link, offered) = match started {
            Ok(started) => started,
            Err(fail) => {
                Shared::count(&self.shared.start_failed);
                let code = match fail {
                    DirectFail::NoAddresses => fallback::NO_ADDRESSES,
                    DirectFail::SameKey => fallback::OFF,
                    _ => fallback::SOCKET,
                };
                tracing::info!(
                    session = %self.id,
                    why = fallback::name(code),
                    "no direct link for the session"
                );
                let ms = ms_since(self.accepted);
                self.shared
                    .note(&self.id, |r| r.declined = Some((code, ms)));
                if self.lan_only {
                    self.end(bye::NO_LAN_PATH);
                } else {
                    self.send(PathFrame::TorFallback(Some(code)));
                }
                return;
            }
        };
        Shared::count(&self.shared.links_started);
        Shared::count(&self.shared.links_open);
        self.send_candidates(&offered, scope);
        link.add_remote(remote, scope);
        if self.remote_done {
            link.remote_done();
        }
        self.link = Some(Open {
            link,
            scope,
            linger_at: Some(Instant::now() + HOST_DIRECT_LINGER),
            conn: None,
            serving: None,
            second: None,
            drain_until: None,
        });
    }

    fn on_local(&mut self, batch: LocalBatch) {
        match batch {
            LocalBatch::More(batch) => {
                if let Some(scope) = self.link.as_ref().map(|open| open.scope) {
                    self.send_candidates(&batch, scope);
                }
            }
            LocalBatch::Done => self.send(PathFrame::Done),
        }
    }

    async fn on_connection(&mut self, result: Result<Established, DirectFail>) {
        match result {
            Ok(conn) => {
                let route = conn.route();
                let won = (conn.winner(), route.ipv6);
                self.shared.note(&self.id, |r| r.connected = Some(won));
                let serving = self.serve(conn.clone());
                if let Some(open) = self.link.as_mut() {
                    open.serving = Some(serving);
                    open.conn = Some(conn);
                }
            }
            // Advice: the link goes on, and the viewer decides.
            Err(DirectFail::NoPath { .. }) => {}
            // The link's driver is over: the one dial failed, or the link
            // closed under it.
            Err(_) => {
                self.close_link().await;
                if self.lan_only {
                    self.end(bye::NO_LAN_PATH);
                }
            }
        }
    }

    /// The media stream of `conn`: the first stream the viewer opens, served
    /// with the key the connection's TLS proved and its exporter output.
    fn serve(&self, conn: Established) -> BoxFuture<'static, Option<MediaOutcome>> {
        let media = Arc::clone(&self.media);
        let id = self.id.clone();
        let token = self.token.clone();
        Box::pin(async move {
            let stream = conn.accept_stream().await.ok()?;
            let ekm = conn.binding_secret(&token).ok()?;
            let peer = DeviceId::from_bytes(conn.peer_key());
            let route = if conn.route().same_site {
                TransportKind::Lan
            } else {
                TransportKind::Direct
            };
            Some(media.serve_direct(stream, &id, peer, ekm, route).await)
        })
    }

    async fn on_served(&mut self, outcome: Option<MediaOutcome>) {
        if let Some(open) = self.link.as_mut() {
            open.serving = None;
        }
        if let Some(outcome) = &outcome {
            (self.on_media)(outcome);
        }
        match outcome {
            Some(MediaOutcome::Served { .. } | MediaOutcome::NotStarted(_)) => {
                if let Some(open) = self.link.as_mut() {
                    open.drain_until = Some(Instant::now() + DIRECT_DRAIN);
                }
            }
            refused => {
                if matches!(refused, Some(MediaOutcome::NotBound)) {
                    let ms = ms_since(self.accepted);
                    self.shared.note(&self.id, |r| {
                        r.bind_refused.get_or_insert(ms);
                    });
                }
                // The refusal was flushed before the stream's future ended
                // (the direct design §6.5); nothing else binds on this link.
                self.close_link().await;
                if self.lan_only {
                    self.end(bye::NO_LAN_PATH);
                }
            }
        }
    }

    async fn on_claim(&mut self, claim: Option<TransportKind>) {
        match claim {
            Some(TransportKind::TorRelay) => {
                // The onion path won: the link closes at once, and none is
                // ever started (the direct design §8.5 step 5).
                self.close_link().await;
            }
            Some(TransportKind::Lan | TransportKind::Direct) => self.on_direct_claim(),
            None => {}
        }
    }

    /// The session's media was claimed on its link: the link stays for it,
    /// and the second stream may come.
    fn on_direct_claim(&mut self) {
        if self.direct_claim {
            return;
        }
        self.direct_claim = true;
        let ms = ms_since(self.accepted);
        self.shared.note(&self.id, |r| {
            r.claimed.get_or_insert(ms);
        });
        let Some(open) = self.link.as_mut() else {
            return;
        };
        open.linger_at = None;
        if let (Some(second), Some(conn)) = (&self.second, &open.conn) {
            let (second, conn) = (Arc::clone(second), conn.clone());
            let (id, token) = (self.id.clone(), self.token.clone());
            open.second = Some(Box::pin(async move {
                let Ok(stream) = conn.accept_stream().await else {
                    return;
                };
                let Ok(ekm) = conn.binding_secret(&token) else {
                    return;
                };
                second.serve(stream, id, ekm).await;
            }));
        }
    }

    /// Whether the session's media is claimed on the direct path, read from
    /// the media host itself (a claim its watch has not told yet).
    fn claimed_here(&self) -> bool {
        matches!(
            self.media.route(&self.id),
            Some(TransportKind::Lan | TransportKind::Direct)
        )
    }

    /// Whether the session's media was bound on this link: a claim seen,
    /// or one the watch holds and has not told yet. The watch keeps the
    /// claim after the session ended, when [`Self::claimed_here`] no longer
    /// finds it.
    fn media_on_link(&self) -> bool {
        self.direct_claim
            || matches!(
                *self.claimed.borrow(),
                Some(TransportKind::Lan | TransportKind::Direct)
            )
    }

    /// A kill, or an end of the viewer's device, while the session's media
    /// streams on this link (the direct design §9.1 invariants 2 and 10).
    /// The session's media end is set here first (the media host's kill
    /// watch may not have run yet, and it never hears a device's end), so
    /// [`MediaHost::serve_direct`] returns through its own teardown, as on
    /// the onion path: capture stops, the observer hears `capture_stopped`,
    /// the outcome is handed on, and the viewer is told
    /// `Close{ENDED_BY_HOST}`. That goodbye is bounded: the stream's end and
    /// then the viewer's close of the connection are waited for until
    /// [`DIRECT_DRAIN`] after the kill, and the link then closes whatever
    /// is left (a stream still running is dropped, which stops its capture
    /// too). A stream not bound on this link (still before its `Bind`, or
    /// flushing a refusal) and the drain after a stream's end are not waited
    /// for: the link closes at once.
    async fn media_goodbye(&mut self) {
        if !self.media_on_link() {
            return;
        }
        let Some(open) = self.link.as_mut() else {
            return;
        };
        let Some(serving) = open.serving.take() else {
            return;
        };
        self.media.end_by_host(&self.id);
        let deadline = Instant::now() + DIRECT_DRAIN;
        let Ok(Some(outcome)) = tokio::time::timeout_at(deadline, serving).await else {
            return;
        };
        (self.on_media)(&outcome);
        if let Some(conn) = &open.conn {
            let _ = tokio::time::timeout_at(deadline, conn.closed()).await;
        }
    }

    async fn on_linger(&mut self) {
        if self.claimed_here() {
            self.on_direct_claim();
            return;
        }
        let ms = ms_since(self.accepted);
        self.shared.note(&self.id, |r| {
            r.lingered.get_or_insert(ms);
        });
        self.close_link().await;
        if self.lan_only {
            self.end(bye::NO_LAN_PATH);
        }
    }

    /// The session is over (the FSM let go of its port). A direct media
    /// stream is let finish (the session's end ends it) and its last frames
    /// reach the viewer, each wait bounded by [`DIRECT_DRAIN`] and cut short
    /// by a kill; then the link closes.
    async fn session_over(&mut self) {
        self.inbox_open = false;
        if let Some(open) = self.link.as_mut()
            && self.direct_claim
        {
            if let Some(serving) = open.serving.take() {
                let served = tokio::select! {
                    biased;
                    _ = self.kill.killed() => None,
                    served = tokio::time::timeout(DIRECT_DRAIN, serving) => served.ok().flatten(),
                };
                if let Some(outcome) = &served {
                    (self.on_media)(outcome);
                    open.drain_until = Some(Instant::now() + DIRECT_DRAIN);
                }
            }
            if let (Some(conn), Some(until)) = (&open.conn, open.drain_until) {
                tokio::select! {
                    biased;
                    _ = self.kill.killed() => {}
                    () = conn.closed() => {}
                    () = tokio::time::sleep_until(until) => {}
                }
            }
        }
        self.close_link().await;
    }

    /// Closes the session's link, if open, and rules out any other: what
    /// runs on it is dropped first, then the endpoint closes.
    async fn close_link(&mut self) {
        self.may_bind = false;
        let Some(open) = self.link.take() else {
            return;
        };
        let stats = open.link.stats();
        // Counts only (decision M1-83): the whole session's socket counters
        // for the device rows of the direct design §13.
        tracing::debug!(session = %self.id, ?stats, "direct link closed");
        if stats.handshakes_refused > 0 || stats.dial_failed == Some(DialFailure::Crypto) {
            let ms = ms_since(self.accepted);
            self.shared.note(&self.id, |r| {
                r.pin_refused.get_or_insert(ms);
            });
        }
        self.shared.links_open.fetch_sub(1, Ordering::Relaxed);
        let Open {
            link,
            serving,
            second,
            conn,
            ..
        } = open;
        drop((serving, second, conn));
        link.close().await;
    }

    /// Ends the session with `BYE{reason}`, once.
    fn end(&mut self, reason: u16) {
        if !self.ended {
            self.ended = true;
            self.send(PathFrame::End(reason));
        }
    }

    /// This side's candidates, in frames echoing `scope`, within the
    /// session's [`MAX_PATH_CANDIDATES`].
    fn send_candidates(&mut self, batch: &[Candidate], scope: Scope) {
        for frame in to_wire(batch, scope) {
            if self.candidates_sent >= MAX_PATH_CANDIDATES {
                Shared::count(&self.shared.outbox_dropped);
                continue;
            }
            self.candidates_sent += 1;
            self.send(PathFrame::Candidates(frame));
        }
    }

    fn send(&self, frame: PathFrame) {
        if self.outbox.try_send(frame).is_err() {
            Shared::count(&self.shared.outbox_dropped);
        }
    }
}

/// The next thing a session's open link has: its news, its media stream's
/// end, its second stream's end, the end of the drain, the linger. Never
/// resolves without a link.
async fn link_news(link: &mut Option<Open>) -> Woke {
    let Some(open) = link.as_mut() else {
        return std::future::pending().await;
    };
    let Open {
        link,
        serving,
        second,
        conn,
        drain_until,
        linger_at,
        ..
    } = open;
    tokio::select! {
        biased;
        served = poll_some(serving) => Woke::Served(served),
        () = poll_some(second) => Woke::SecondOver,
        news = link.next_news() => Woke::News(news),
        () = drained(conn.as_ref(), *drain_until) => Woke::Drained,
        () = sleep_until_opt(*linger_at) => Woke::Linger,
    }
}

/// Polls `future` in place; never resolves without one. The caller clears
/// it once it resolved.
async fn poll_some<T>(future: &mut Option<BoxFuture<'static, T>>) -> T {
    match future {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

/// The connection closed, or `until` passed; never without a drain.
async fn drained(conn: Option<&Established>, until: Option<Instant>) {
    let Some(until) = until else {
        return std::future::pending().await;
    };
    match conn {
        Some(conn) => tokio::select! {
            () = conn.closed() => {}
            () = tokio::time::sleep_until(until) => {}
        },
        None => tokio::time::sleep_until(until).await,
    }
}

async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// The end line's summary (the direct design §8.5 `outcome()`): a
    /// direct claim says `direct` with its winner, family and time, whatever
    /// else happened; otherwise a refused `Bind`, then a refused pin, then
    /// the host's own reason, the viewer's reason, the linger, an old
    /// viewer, in that order; a session whose path never began has none.
    #[tokio::test(start_paused = true)]
    async fn the_summary_takes_the_strongest_fact() {
        let mut r = Record::new(Instant::now());
        assert_eq!(r.summary(None), None);
        r.old_viewer = true;
        assert_eq!(r.summary(None).unwrap().outcome, "old-viewer");
        r.lingered = Some(20_000);
        assert_eq!(r.summary(None).unwrap().outcome, "no-path");
        r.viewer_fallback = Some((None, 900));
        assert_eq!(r.summary(None).unwrap().outcome, "unknown");
        r.viewer_fallback = Some((Some(fallback::QUIC), 900));
        let viewer = r.summary(Some(TransportKind::TorRelay)).unwrap();
        assert_eq!((viewer.outcome.as_str(), viewer.ms), ("quic", 900));
        r.declined = Some((fallback::NO_ADDRESSES, 3));
        assert_eq!(r.summary(None).unwrap().outcome, "no-addresses");
        r.pin_refused = Some(950);
        assert_eq!(r.summary(None).unwrap().outcome, "pin-refused");
        r.bind_refused = Some(960);
        let refused = r.summary(None).unwrap();
        assert_eq!(
            (refused.outcome.as_str(), refused.ms),
            ("bind-refused", 960)
        );
        assert_eq!((refused.winner, refused.ipv6), (None, false));

        r.connected = Some((CandidateKind::Host, true));
        r.claimed = Some(612);
        for route in [TransportKind::Lan, TransportKind::Direct] {
            assert_eq!(
                r.summary(Some(route)),
                Some(PathSummary {
                    outcome: "direct".to_owned(),
                    winner: Some("host".to_owned()),
                    ipv6: true,
                    ms: 612,
                })
            );
        }
        // A claim the task had not seen yet is timed when it is read.
        r.claimed = None;
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(r.summary(Some(TransportKind::Lan)).unwrap().ms, 700);
    }
}
