//! The direct link of one session (design `direct` §8.3 `link.rs`, §6.5,
//! §7.5; decisions M1-79, M1-80, M1-83): this side's candidates, the session
//! socket, the checklist and the one QUIC connection, wired together.
//!
//! [`DirectLink::start`] reads this computer's addresses, binds the session
//! socket ([`NetEnv::bind`]) and spawns the link's driver, which
//!
//! - feeds every probe the socket's tee took to the [`Checklist`] and sends
//!   the probes it asks for through [`PunchSocket::send_raw`], on the
//!   checklist's own clock (tokio's, so tests run on paused time);
//! - on the controlled side (the higher device key) accepts the dial with
//!   [`quic::accept`], whose gate is the checklist's validated set (the
//!   [`ProbeGate`]); on the controlling side dials once, to the address the
//!   checklist nominated ([`quic::dial`]); both end in [`quic::check_peer`];
//! - reports the connection, or the checklist's early failure, through
//!   [`DirectLink::established`].
//!
//! The caller (the session's path phase) exchanges candidates over Tor:
//! it sends the host candidates [`DirectLink::start`] returns and the
//! batches of [`DirectLink::next_local`], and hands the peer's to
//! [`DirectLink::add_remote`] and [`DirectLink::remote_done`]. In Phase A
//! the host candidates are all of this side's (same-site gathering), so
//! `next_local` says `Done` at once; Phase B adds the mapped and
//! server-reflexive batches (design §7.5).
//!
//! **Lifetime.** The link, every [`Established`] and every [`QuicStream`]
//! share one inner value; the last of them to go closes the connection and
//! the endpoint and stops the driver, so a session that holds only its media
//! stream keeps exactly what that stream needs. [`DirectLink::close`] closes
//! at once whatever else still holds the link, so after it no QUIC
//! connection can complete (the viewer's fallback, design §4). The runtime
//! the link starts on is captured: the driver runs on it, and Phase B
//! releases the router mapping through it (design §7.4 "Release").
//!
//! Nothing here logs. Every type has a redacted `Debug` (decision M1-83),
//! and [`LinkStats`] holds counts only.

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use quinn::VarInt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tornect_core::DeviceIdentity;
use zeroize::Zeroizing;

use crate::addr::{AddrClass, Candidate, CandidateKind, RemoteFilter, Scope, canon, canon_ip};
use crate::checklist::{Action, Checklist, PunchRole, PunchStats};
use crate::env::NetEnv;
use crate::local;
use crate::probe::ProbeKey;
use crate::quic::{self, QuicError, QuicIdentity};
use crate::udp::{ProbeGate, PunchCounters, PunchSocket, Tees, V6Sources};
use crate::{BoxFuture, TornectRole};

/// The longest [`DirectLink::close`] waits for the endpoint to drain.
pub const CLOSE_WAIT: Duration = Duration::from_millis(200);

/// The application close code of a link its owner closed (the session
/// ended, fell back to Tor, was killed); like [`quic::PEER_REFUSED`], no
/// Tornect reason applies.
pub const LINK_CLOSED: u32 = 0;

/// How many candidate batches and `CANDIDATES_DONE`s wait for the driver;
/// the signalling side sends at most 6 batches and one `DONE` (design §4
/// "Frame limits"), so a full queue means a caller beyond them.
const COMMAND_QUEUE: usize = 16;

/// The least time between two timer turns of the driver, a guard against a
/// clock that does not move.
const MIN_TICK: Duration = Duration::from_millis(1);

/// What a direct link is started with (design §8.3 `DirectParams`). The
/// fields of Phase B's gathering (the STUN partition, the router protocols)
/// join at step B6.
pub struct DirectParams {
    /// This side's role in the session.
    pub me: TornectRole,
    /// This device's identity: its key is the QUIC raw public key.
    pub identity: Arc<DeviceIdentity>,
    /// The peer's device public key, pinned through Tor (the viewer pins the
    /// host's `SESSION_ACCEPT.quic_spki`, the host the paired device).
    pub peer_pk: [u8; 32],
    /// The Tor-borne session token: the probe key is derived from it.
    pub session_token: Zeroizing<[u8; 32]>,
    /// `network.direct_port`: the session socket's port when it is free.
    pub direct_port: Option<u16>,
    /// How far this side's candidates reach (the scope the two sides agreed
    /// on, design §4).
    pub scope: Scope,
}

impl fmt::Debug for DirectParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectParams")
            .field("me", &self.me)
            .field("direct_port", &self.direct_port.is_some())
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// Why a direct link did not give a connection (design §8.3). No message
/// names an address or a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DirectFail {
    /// This side has no address in scope (or the interface read failed);
    /// nothing was bound.
    #[error("no network address a direct connection can use")]
    NoAddresses,
    /// The session socket could not be bound, or quinn could not start on
    /// it.
    #[error("no network port could be opened for a direct connection")]
    Socket,
    /// The peer's key is this device's own: a device never connects
    /// directly to itself (decision M1-80). Nothing was read or bound.
    #[error("a device does not connect directly to itself")]
    SameKey,
    /// The checklist has no target left that can validate (its early
    /// failure). Advice: answers, learning and the accept go on, and a
    /// further [`DirectLink::established`] waits for what comes next.
    #[error("no direct path was validated")]
    NoPath {
        /// An authenticated probe request from the peer arrived.
        heard: bool,
    },
    /// The one dial failed: the handshake, the pins or [`quic::check_peer`].
    #[error("the direct QUIC connection failed")]
    Quic,
    /// The link was closed, or its driver ended.
    #[error("the direct link is closed")]
    Closed,
}

/// A batch of this side's own candidates for the peer, in the order they
/// are gathered (design §7.5), then the end of gathering.
#[derive(Clone, PartialEq, Eq)]
pub enum LocalBatch {
    /// More candidates (one `CANDIDATES` frame).
    More(Vec<Candidate>),
    /// Gathering is over (`CANDIDATES_DONE`).
    Done,
}

impl fmt::Debug for LocalBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::More(batch) => f.debug_tuple("More").field(&batch.len()).finish(),
            Self::Done => f.write_str("Done"),
        }
    }
}

/// What the connection's path is, for the route label (design §3.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Route {
    /// The remote is on this side's site: inside one of our on-link
    /// prefixes or our ULA /48, or a private address behind our own public
    /// IPv4 (the same NAT). Never inferred from the class alone.
    pub same_site: bool,
    /// The path is IPv6.
    pub ipv6: bool,
}

/// A direct link's counters: counts only, never an address (decision
/// M1-83).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// This side dials (the lower device key); otherwise it accepts.
    pub controlling: bool,
    /// The session socket carries IPv4 as v4-mapped IPv6 (design §13 row
    /// 2's `dual_stack`).
    pub dual_stack: bool,
    /// Host candidates offered.
    pub offered: usize,
    /// Of those, global addresses (design §13 row 11's `globals_offered`).
    pub globals_offered: usize,
    /// The checklist's counters.
    pub punch: PunchStats,
    /// The session socket's counters.
    pub socket: PunchCounters,
    /// An authenticated probe request from the peer arrived.
    pub heard: bool,
    /// Addresses a round trip validated.
    pub validated: usize,
    /// The controlling side nominated an address.
    pub nominated: bool,
    /// The controlling side dialled.
    pub dialled: bool,
    /// The dial failed; `crypto` when it ended with a TLS alert.
    pub dial_failed: Option<DialFailure>,
    /// The accepting side's handshakes that ended with a TLS alert: a pin
    /// refused the dialler's key, or the dialler refused this side's.
    pub handshakes_refused: u64,
    /// A connection passed [`quic::check_peer`].
    pub established: bool,
    /// Candidate batches dropped because their scope is above this side's
    /// (design §4).
    pub frames_out_of_scope: u64,
    /// Candidate batches and `DONE`s dropped because the driver's queue was
    /// full or gone.
    pub commands_dropped: u64,
}

/// How the one dial failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialFailure {
    /// The handshake ended with a TLS alert ([`quic::is_crypto_close`]):
    /// a pin refused.
    Crypto,
    /// Any other failure: no answer, the peer check, a refused dial.
    Other,
}

/// What the link and its driver share.
#[derive(Default)]
struct Shared {
    stats: Mutex<LinkStats>,
    /// Stream bytes read on this link's connection.
    received: AtomicU64,
}

impl Shared {
    fn update(&self, change: impl FnOnce(&mut LinkStats)) {
        change(&mut self.stats.lock().unwrap_or_else(PoisonError::into_inner));
    }

    fn snapshot(&self) -> LinkStats {
        *self.stats.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What the link, its connection and its streams hold together; the last
/// holder's drop closes everything (see the module documentation).
struct LinkInner {
    endpoint: quinn::Endpoint,
    socket: Arc<PunchSocket>,
    driver: tokio::task::AbortHandle,
    shared: Arc<Shared>,
    /// The runtime the link started on: the driver runs there, and step B4
    /// releases the router mapping through it (design §7.4 "Release").
    _runtime: tokio::runtime::Handle,
}

impl LinkInner {
    /// Stops the driver and closes the endpoint with every connection on
    /// it; no new connection can start or complete afterwards. Needs no
    /// runtime context, so a drop anywhere closes.
    fn shut(&self) {
        self.driver.abort();
        self.endpoint.close(VarInt::from_u32(LINK_CLOSED), b"");
    }

    fn stats(&self) -> LinkStats {
        LinkStats {
            socket: self.socket.counters(),
            ..self.shared.snapshot()
        }
    }
}

impl Drop for LinkInner {
    fn drop(&mut self) {
        self.shut();
    }
}

/// What the driver tells the link.
enum LinkEvent {
    /// The checklist's early failure (advice).
    Failed { heard: bool },
    /// A connection passed the peer check.
    Established {
        conn: quinn::Connection,
        route: Route,
        winner: CandidateKind,
    },
    /// The driver ended without a connection.
    Dead(DirectFail),
}

/// What the link tells the driver.
enum Command {
    Remote(Vec<Candidate>),
    RemoteDone,
}

/// The direct link of one session (see the module documentation).
pub struct DirectLink {
    inner: Arc<LinkInner>,
    peer_pk: [u8; 32],
    scope: Scope,
    commands: mpsc::Sender<Command>,
    events: mpsc::Receiver<LinkEvent>,
    local: mpsc::Receiver<LocalBatch>,
    local_over: bool,
    /// A final connection result was given ([`DirectLink::next_news`]).
    connection_over: bool,
}

/// What a direct link has next for its owner ([`DirectLink::next_news`]).
#[derive(Debug)]
pub enum LinkNews {
    /// A batch of this side's candidates, or the end of gathering, as
    /// [`DirectLink::next_local`] gives them.
    Local(LocalBatch),
    /// The connection, or why there is none yet, as
    /// [`DirectLink::established`] gives it.
    Connection(Result<Established, DirectFail>),
}

impl DirectLink {
    /// Starts the direct link of a session (design §8.3):
    ///
    /// 1. refuses the peer's key when it is this device's own
    ///    ([`DirectFail::SameKey`]), before any call to `env`;
    /// 2. reads this computer's addresses and route sources and selects the
    ///    host candidates of `params.scope` ([`local::select_host_candidates`]);
    ///    none ([`DirectFail::NoAddresses`]) binds nothing;
    /// 3. binds the session socket ([`DirectFail::Socket`]), offers only the
    ///    candidates its family can carry, pins the IPv6 sources to the
    ///    offered addresses, and builds the remote filter, the checklist and
    ///    quinn's endpoint (with the server configuration on the controlled
    ///    side);
    /// 4. spawns the driver on the current runtime.
    ///
    /// Returns the link and the host candidates to send to the peer (each
    /// on the socket's port).
    ///
    /// # Errors
    ///
    /// [`DirectFail::SameKey`], [`DirectFail::NoAddresses`],
    /// [`DirectFail::Socket`], or [`DirectFail::Quic`] if the QUIC
    /// configuration could not be built (never with ring).
    pub async fn start(
        params: DirectParams,
        env: Arc<dyn NetEnv>,
    ) -> Result<(Self, Vec<Candidate>), DirectFail> {
        let quic_id = QuicIdentity::new(Arc::clone(&params.identity));
        let punch =
            PunchRole::of(&quic_id.public_key(), &params.peer_pk).ok_or(DirectFail::SameKey)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| DirectFail::Socket)?;

        let addrs = env
            .interfaces()
            .await
            .map_err(|_| DirectFail::NoAddresses)?;
        let sources = env.route_sources();
        let vpn = local::vpn_mode(&addrs, &sources);
        if local::select_host_candidates(&addrs, &sources, 0, params.scope, vpn).is_empty() {
            return Err(DirectFail::NoAddresses);
        }

        let bound = env
            .bind(params.direct_port)
            .map_err(|_| DirectFail::Socket)?;
        let port = bound
            .inner
            .local_addr()
            .map_err(|_| DirectFail::Socket)?
            .port();
        let dual_stack = bound.dual_stack;
        let offered: Vec<Candidate> =
            local::select_host_candidates(&addrs, &sources, port, params.scope, vpn)
                .into_iter()
                .filter(|c| dual_stack || c.addr.is_ipv4())
                .collect();
        if offered.is_empty() {
            return Err(DirectFail::NoAddresses);
        }
        let filter = local::remote_filter(
            params.scope,
            &addrs,
            &sources,
            &offered,
            dual_stack,
            vpn,
            env.admit_loopback(),
        );
        let v6 = v6_sources(&offered);

        let gate = ProbeGate::new();
        let (socket, tees) = PunchSocket::new(bound, gate.clone());
        socket.set_sources(v6);
        let (server, client) = match punch {
            PunchRole::Controlled => (
                Some(
                    quic_id
                        .server_config(&params.peer_pk, params.me)
                        .map_err(|_| DirectFail::Quic)?,
                ),
                None,
            ),
            PunchRole::Controlling => (
                None,
                Some(
                    quic_id
                        .client_config(&params.peer_pk, params.me)
                        .map_err(|_| DirectFail::Quic)?,
                ),
            ),
        };
        let endpoint = quic::endpoint(&socket, server).map_err(|_| DirectFail::Socket)?;

        let key = ProbeKey::derive(&params.session_token);
        let mut checklist = Checklist::new(punch, params.me, key, filter.clone(), gate.clone(), v6);
        // Phase A gathers nothing beyond the host candidates (design §7.5).
        checklist.local_done();

        let shared = Arc::new(Shared::default());
        shared.update(|s| {
            s.controlling = punch == PunchRole::Controlling;
            s.dual_stack = dual_stack;
            s.offered = offered.len();
            s.globals_offered = offered
                .iter()
                .filter(|c| crate::addr::class(canon_ip(c.addr.ip())) == AddrClass::Global)
                .count();
        });
        let (commands_tx, commands) = mpsc::channel(COMMAND_QUEUE);
        let (events_tx, events) = mpsc::channel(4);
        let (local_tx, local) = mpsc::channel(4);
        // Cannot fail: a fresh channel with room.
        let _ = local_tx.try_send(LocalBatch::Done);

        let driver = Driver {
            checklist,
            socket: Arc::clone(&socket),
            endpoint: endpoint.clone(),
            filter,
            gate,
            peer_pk: params.peer_pk,
            dual_stack,
            client,
            commands,
            events: events_tx,
            _local: local_tx,
            tees,
            shared: Arc::clone(&shared),
            floor: None,
        };
        let driver = runtime.spawn(driver.run()).abort_handle();
        let inner = Arc::new(LinkInner {
            endpoint,
            socket,
            driver,
            shared,
            _runtime: runtime,
        });
        Ok((
            Self {
                inner,
                peer_pk: params.peer_pk,
                scope: params.scope,
                commands: commands_tx,
                events,
                local,
                local_over: false,
                connection_over: false,
            },
            offered,
        ))
    }

    /// The next batch of this side's own candidates, then
    /// [`LocalBatch::Done`] once; after that it never returns. Cancel safe
    /// (a channel receive).
    pub async fn next_local(&mut self) -> LocalBatch {
        recv_local(&mut self.local, &mut self.local_over).await
    }

    /// [`Self::next_local`] and [`Self::established`] in one wait, for an
    /// owner that must hear both while it also waits on other things (a
    /// `select!` cannot hold both borrows). A ready batch comes first.
    /// After a final connection result (`Ok`, [`DirectFail::Quic`],
    /// [`DirectFail::Closed`]) only batches come, and once gathering is
    /// over too it never returns. Cancel safe (channel receives).
    pub async fn next_news(&mut self) -> LinkNews {
        enum Got {
            Local(LocalBatch),
            Event(Option<LinkEvent>),
        }
        let got = tokio::select! {
            biased;
            batch = recv_local(&mut self.local, &mut self.local_over) => Got::Local(batch),
            event = self.events.recv(), if !self.connection_over => Got::Event(event),
        };
        match got {
            Got::Local(batch) => LinkNews::Local(batch),
            Got::Event(event) => LinkNews::Connection(self.connection(event)),
        }
    }

    /// The peer's candidates of one `CANDIDATES` frame, whose scope is
    /// `scope`. A frame above this side's scope is dropped whole and
    /// counted (design §4); otherwise each candidate passes the remote
    /// filter in the checklist. Never waits.
    pub fn add_remote(&self, batch: Vec<Candidate>, scope: Scope) {
        if scope > self.scope {
            self.inner
                .shared
                .update(|s| s.frames_out_of_scope = s.frames_out_of_scope.saturating_add(1));
            return;
        }
        self.command(Command::Remote(batch));
    }

    /// The peer said `CANDIDATES_DONE`. Never waits.
    pub fn remote_done(&self) {
        self.command(Command::RemoteDone);
    }

    fn command(&self, command: Command) {
        if self.commands.try_send(command).is_err() {
            self.inner
                .shared
                .update(|s| s.commands_dropped = s.commands_dropped.saturating_add(1));
        }
    }

    /// The connection once it passed [`quic::check_peer`], or why there is
    /// none yet. Cancel safe (a channel receive).
    ///
    /// [`DirectFail::NoPath`] is the checklist's early failure, given once:
    /// the link goes on (a later answer may still validate), and a further
    /// call waits for what comes next. After `Ok`, [`DirectFail::Quic`] or
    /// [`DirectFail::Closed`] the link's driver is over, and a further call
    /// returns [`DirectFail::Closed`] at once.
    ///
    /// # Errors
    ///
    /// As above.
    pub async fn established(&mut self) -> Result<Established, DirectFail> {
        let event = self.events.recv().await;
        self.connection(event)
    }

    /// A driver event as the owner hears it; a final one is remembered.
    fn connection(&mut self, event: Option<LinkEvent>) -> Result<Established, DirectFail> {
        let result = match event {
            Some(LinkEvent::Established {
                conn,
                route,
                winner,
            }) => Ok(Established {
                inner: Arc::clone(&self.inner),
                conn,
                route,
                winner,
                peer_pk: self.peer_pk,
            }),
            Some(LinkEvent::Failed { heard }) => Err(DirectFail::NoPath { heard }),
            Some(LinkEvent::Dead(fail)) => Err(fail),
            None => Err(DirectFail::Closed),
        };
        if !matches!(result, Err(DirectFail::NoPath { .. })) {
            self.connection_over = true;
        }
        result
    }

    /// The link's counters.
    #[must_use]
    pub fn stats(&self) -> LinkStats {
        self.inner.stats()
    }

    /// Closes the link: the driver stops and the endpoint closes with every
    /// connection on it, whoever else still holds the link, so no QUIC
    /// connection can complete afterwards. Then waits at most
    /// [`CLOSE_WAIT`] for the endpoint to drain.
    pub async fn close(self) {
        let inner = Arc::clone(&self.inner);
        drop(self);
        inner.shut();
        let _ = tokio::time::timeout(CLOSE_WAIT, inner.endpoint.wait_idle()).await;
    }
}

impl fmt::Debug for DirectLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectLink")
            .field("scope", &self.scope)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

/// The next of a link's own batches, then [`LocalBatch::Done`] once; after
/// that it never returns. Cancel safe (a channel receive).
async fn recv_local(local: &mut mpsc::Receiver<LocalBatch>, over: &mut bool) -> LocalBatch {
    if *over {
        return std::future::pending().await;
    }
    match local.recv().await {
        Some(LocalBatch::More(batch)) => LocalBatch::More(batch),
        Some(LocalBatch::Done) | None => {
            *over = true;
            LocalBatch::Done
        }
    }
}

/// The IPv6 addresses an IPv6 datagram may leave from: the first offered
/// global and the first offered unique-local candidate (the one whose /48
/// the remote filter takes).
fn v6_sources(offered: &[Candidate]) -> V6Sources {
    let first = |class: AddrClass| {
        offered.iter().find_map(|c| match canon_ip(c.addr.ip()) {
            IpAddr::V6(v6) if crate::addr::class_v6(v6) == class => Some(v6),
            _ => None,
        })
    };
    V6Sources {
        global: first(AddrClass::Global),
        ula: first(AddrClass::UniqueLocal),
    }
}

/// A direct connection that passed [`quic::check_peer`] (design §8.3
/// `Established`). Clones share the connection.
#[derive(Clone)]
pub struct Established {
    inner: Arc<LinkInner>,
    conn: quinn::Connection,
    route: Route,
    winner: CandidateKind,
    peer_pk: [u8; 32],
}

impl Established {
    /// Opens the media stream (the viewer), at `priority` (quinn's: higher
    /// is sent first; media 1, services 0, design §6.7). The peer sees it
    /// once the first byte is written.
    ///
    /// # Errors
    ///
    /// [`DirectFail::Closed`] if the connection is gone.
    pub async fn open_stream(&self, priority: i32) -> Result<QuicStream, DirectFail> {
        let (send, recv) = self.conn.open_bi().await.map_err(|_| DirectFail::Closed)?;
        let _ = send.set_priority(priority);
        Ok(self.stream(send, recv))
    }

    /// Accepts the next stream the viewer opened (the host).
    ///
    /// # Errors
    ///
    /// [`DirectFail::Closed`] if the connection is gone.
    pub async fn accept_stream(&self) -> Result<QuicStream, DirectFail> {
        let (send, recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|_| DirectFail::Closed)?;
        Ok(self.stream(send, recv))
    }

    fn stream(&self, send: quinn::SendStream, recv: quinn::RecvStream) -> QuicStream {
        QuicStream {
            send,
            recv,
            conn: self.conn.clone(),
            inner: Arc::clone(&self.inner),
        }
    }

    /// The keying material the direct `Bind` and `BindProof` MACs cover
    /// (design §6.6): [`quic::exporter`] with `session_token` as context,
    /// equal on both ends of this connection only.
    ///
    /// # Errors
    ///
    /// [`DirectFail::Quic`] if the exporter refused (never once the
    /// handshake completed).
    pub fn binding_secret(
        &self,
        session_token: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, DirectFail> {
        quic::exporter(&self.conn, session_token).map_err(|_| DirectFail::Quic)
    }

    /// The peer's device key, which [`quic::check_peer`] verified.
    #[must_use]
    pub fn peer_key(&self) -> [u8; 32] {
        self.peer_pk
    }

    /// The path's route label.
    #[must_use]
    pub fn route(&self) -> Route {
        self.route
    }

    /// The kind of the remote candidate the connection runs to (`PATH host
    /// …`); a source learned from the peer's probes reads as
    /// [`CandidateKind::Prflx`] unless the peer also signalled it.
    #[must_use]
    pub fn winner(&self) -> CandidateKind {
        self.winner
    }

    /// Whether the connection ended with a TLS alert (QUIC `CRYPTO_ERROR`,
    /// [`quic::is_crypto_close`]): the peer refused this side's key. With
    /// no stream byte received ([`stream_bytes_received`] 0) the peer never
    /// completed its handshake (decision M1-79's one fallback after the
    /// viewer's commit point).
    ///
    /// [`stream_bytes_received`]: Self::stream_bytes_received
    #[must_use]
    pub fn closed_by_crypto(&self) -> bool {
        self.conn
            .close_reason()
            .is_some_and(|e| quic::is_crypto_close(&e))
    }

    /// Stream bytes read on this connection so far.
    #[must_use]
    pub fn stream_bytes_received(&self) -> u64 {
        self.inner.shared.received.load(Ordering::Relaxed)
    }

    /// Waits until the connection is closed, by either side or by the idle
    /// timeout.
    pub async fn closed(&self) {
        let _ = self.conn.closed().await;
    }

    /// The host's refusal of a `Bind` on `stream` (design §6.5):
    /// [`QuicStream::refuse`].
    pub async fn refuse(&self, stream: QuicStream, frame: &[u8], code: u16) {
        stream.refuse(frame, code).await;
    }

    /// The link's counters.
    #[must_use]
    pub fn stats(&self) -> LinkStats {
        self.inner.stats()
    }

    /// Closes the connection with the application `code` and `reason`, as
    /// a peer of another build may (this build's own closes carry no
    /// reason): for tests of where a peer's close reason could reach.
    #[cfg(any(test, feature = "test-support"))]
    pub fn close_with_reason(&self, code: u32, reason: &[u8]) {
        self.conn.close(VarInt::from_u32(code), reason);
    }
}

impl fmt::Debug for Established {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Established")
            .field("route", &self.route)
            .field("winner", &self.winner)
            .finish_non_exhaustive()
    }
}

/// One bidirectional QUIC stream of a direct link, as the session's media
/// and services protocols use it: `AsyncRead + AsyncWrite`. It holds the
/// link, so the connection lives as long as the stream (see the module
/// documentation). Dropping it finishes its sending half. Its I/O errors
/// carry quinn's kind in fixed words and no source: nothing
/// the peer wrote into its close reaches them.
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    conn: quinn::Connection,
    inner: Arc<LinkInner>,
}

impl QuicStream {
    /// The host's refusal (design §6.5, [`quic::refuse`]): writes `frame`
    /// (an encoded `BindRefused`), finishes the stream, waits at most
    /// [`quic::REFUSAL_FLUSH`] for the viewer to take it, then closes the
    /// connection with `code` (a `tornect_proto::reason` code). Dropping
    /// the future closes at once with `code`.
    pub async fn refuse(self, frame: &[u8], code: u16) {
        let Self { send, conn, .. } = self;
        quic::refuse(&conn, send, frame, code).await;
    }

    /// Changes the stream's priority (higher is sent first).
    pub fn set_priority(&self, priority: i32) {
        let _ = self.send.set_priority(priority);
    }
}

impl fmt::Debug for QuicStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicStream").finish_non_exhaustive()
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf);
        let read = buf.filled().len().saturating_sub(before) as u64;
        if read > 0 {
            self.inner
                .shared
                .received
                .fetch_add(read, Ordering::Relaxed);
        }
        polled.map_err(sealed)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf).map_err(sealed)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx).map_err(sealed)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx).map_err(sealed)
    }
}

/// A stream error as a [`QuicStream`] hands it on: quinn's kind, in fixed
/// words, and nothing else (design `direct` §5.5, decision M1-83). quinn's own
/// error value is never passed on: its `ConnectionError` writes the peer's
/// close reason (any bytes, terminal control sequences included) through
/// its `Display`, and an `io::Error` built on it hands that error on as its
/// `source()`, which an error chain printed with `{:#}` or `{:?}` shows.
fn sealed(e: io::Error) -> io::Error {
    let kind = e.kind();
    let words = match kind {
        io::ErrorKind::NotConnected => "the direct connection closed",
        io::ErrorKind::ConnectionReset => "the direct stream was reset",
        io::ErrorKind::InvalidInput => "the direct stream was read out of order",
        _ => "the direct stream failed",
    };
    io::Error::new(kind, words)
}

/// A dial or an accept in progress.
type Handshake = BoxFuture<'static, Result<quinn::Connection, QuicError>>;

/// What woke the driver.
enum Woke {
    Command(Command),
    Connected(Result<quinn::Connection, QuicError>),
    Probe(crate::udp::TeedProbe),
    Timer,
}

/// The task that runs a link's checklist and handshake (see the module
/// documentation). It never holds the link's inner value, so the link's
/// last holder can stop it.
struct Driver {
    checklist: Checklist,
    socket: Arc<PunchSocket>,
    endpoint: quinn::Endpoint,
    filter: RemoteFilter,
    gate: ProbeGate,
    peer_pk: [u8; 32],
    dual_stack: bool,
    /// The controlling side's dial configuration, taken by the one dial.
    client: Option<quinn::ClientConfig>,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<LinkEvent>,
    /// Phase B sends the mapped and server-reflexive batches here.
    _local: mpsc::Sender<LocalBatch>,
    tees: Tees,
    shared: Arc<Shared>,
    /// The earliest next timer turn after one that found nothing due.
    floor: Option<Instant>,
}

/// The time on tokio's clock, as the checklist takes it.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

async fn handshake(pending: &mut Option<Handshake>) -> Result<quinn::Connection, QuicError> {
    match pending {
        Some(handshake) => handshake.await,
        None => std::future::pending().await,
    }
}

impl Driver {
    async fn run(mut self) {
        // A fresh socket reads as not writable until the runtime has seen it
        // (`PunchSocket::writable`); probes sent before would be dropped.
        if self.socket.writable().await.is_err() {
            let _ = self.events.try_send(LinkEvent::Dead(DirectFail::Socket));
            return;
        }
        let mut accept: Option<Handshake> = self.client.is_none().then(|| {
            let endpoint = self.endpoint.clone();
            let gate = self.gate.clone();
            let peer_pk = self.peer_pk;
            let filter = self.filter.clone();
            let shared = Arc::clone(&self.shared);
            Box::pin(async move {
                let refused = || {
                    shared
                        .update(|s| s.handshakes_refused = s.handshakes_refused.saturating_add(1));
                };
                quic::accept_noting(
                    &endpoint,
                    |from| gate.admits(from),
                    &peer_pk,
                    &filter,
                    refused,
                )
                .await
            }) as Handshake
        });
        let mut dial: Option<Handshake> = None;
        let mut probes_open = true;
        let actions = self.checklist.poll(now());
        self.act(actions, &mut dial);
        loop {
            self.publish();
            let wake = match (self.checklist.next_wakeup(), self.floor) {
                (Some(at), Some(floor)) => Some(at.max(floor)),
                (at, _) => at,
            };
            let woke = tokio::select! {
                biased;
                command = self.commands.recv() => match command {
                    Some(command) => Woke::Command(command),
                    // The link is gone (its last holder stopped this task
                    // already, or is about to).
                    None => return,
                },
                done = handshake(&mut accept) => Woke::Connected(done),
                done = handshake(&mut dial) => Woke::Connected(done),
                probe = self.tees.probes.recv(), if probes_open => match probe {
                    Some(probe) => Woke::Probe(probe),
                    None => {
                        probes_open = false;
                        continue;
                    }
                },
                () = sleep_until(wake) => Woke::Timer,
            };
            let at = now();
            let actions = match woke {
                Woke::Command(Command::Remote(batch)) => {
                    for candidate in batch {
                        self.checklist.add_remote(candidate);
                    }
                    self.checklist.poll(at)
                }
                Woke::Command(Command::RemoteDone) => {
                    self.checklist.remote_done();
                    self.checklist.poll(at)
                }
                Woke::Probe(probe) => {
                    let mut actions =
                        self.checklist
                            .on_datagram(probe.from, probe.dst_ip, &probe.bytes, at);
                    actions.extend(self.checklist.poll(at));
                    actions
                }
                Woke::Timer => {
                    let actions = self.checklist.poll(at);
                    self.floor = (actions.is_empty()
                        && self.checklist.next_wakeup().is_some_and(|next| next <= at))
                    .then(|| at + MIN_TICK);
                    actions
                }
                Woke::Connected(Ok(conn)) => {
                    self.connected(conn);
                    return;
                }
                Woke::Connected(Err(error)) => {
                    self.lost(error);
                    return;
                }
            };
            self.act(actions, &mut dial);
        }
    }

    /// Carries out the checklist's actions: probes go out through the
    /// socket's raw path, the nomination starts the one dial, the early
    /// failure is reported.
    fn act(&mut self, actions: Vec<Action>, dial: &mut Option<Handshake>) {
        for action in actions {
            match action {
                Action::Send { to, src, bytes } => {
                    // A probe the socket cannot take is counted there
                    // (`raw_blocked`, `no_source`); the schedule goes on.
                    let _ = self.socket.send_raw(to, &bytes, src);
                }
                Action::Nominate(to) => {
                    if dial.is_none()
                        && let Some(config) = self.client.take()
                    {
                        let endpoint = self.endpoint.clone();
                        let filter = self.filter.clone();
                        let peer_pk = self.peer_pk;
                        let dual_stack = self.dual_stack;
                        *dial = Some(Box::pin(async move {
                            quic::dial(&endpoint, config, to, dual_stack, &peer_pk, &filter).await
                        }));
                        self.shared.update(|s| s.dialled = true);
                    }
                }
                Action::Failed => {
                    let heard = self.checklist.heard_from_peer();
                    let _ = self.events.try_send(LinkEvent::Failed { heard });
                }
            }
        }
    }

    /// The connection passed the peer check: its route and winning
    /// candidate, from the checklist that validated its address.
    fn connected(&mut self, conn: quinn::Connection) {
        let remote = canon(conn.remote_address());
        let route = Route {
            same_site: self.checklist.same_site(remote),
            ipv6: remote.is_ipv6(),
        };
        let winner = self
            .checklist
            .kind_of(remote)
            .unwrap_or(CandidateKind::Prflx);
        self.publish();
        self.shared.update(|s| s.established = true);
        let _ = self.events.try_send(LinkEvent::Established {
            conn,
            route,
            winner,
        });
    }

    /// The dial failed, or the endpoint closed under the accept.
    fn lost(&mut self, error: QuicError) {
        self.publish();
        let fail = match error {
            QuicError::Closed => DirectFail::Closed,
            other => {
                let failure = if matches!(other, QuicError::Handshake { crypto: true }) {
                    DialFailure::Crypto
                } else {
                    DialFailure::Other
                };
                self.shared.update(|s| s.dial_failed = Some(failure));
                DirectFail::Quic
            }
        };
        let _ = self.events.try_send(LinkEvent::Dead(fail));
    }

    /// Copies the checklist's state into the link's counters.
    fn publish(&self) {
        let punch = self.checklist.stats();
        let heard = self.checklist.heard_from_peer();
        let validated = self.checklist.validated().len();
        let nominated = self.checklist.nominated().is_some();
        self.shared.update(|s| {
            s.punch = punch;
            s.heard = heard;
            s.validated = validated;
            s.nominated = nominated;
        });
    }
}

#[cfg(test)]
mod tests;
