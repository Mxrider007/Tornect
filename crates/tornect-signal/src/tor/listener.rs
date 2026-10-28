//! The host's onion service ([`OnionListener`]) and peer streams ([`OnionStream`])
//! (docs/research/arti.md §8.2–§8.3).
//!
//! Resource bounds — the "small accept queue" of `docs/PLAN.md` §B.3, decision
//! M1-4 ([`RendezvousLimits`]). Every network wait on the host side, reads *and*
//! writes, has a deadline, so a peer that goes silent — or stops accepting
//! data — can hold a slot for a bounded time only:
//!
//! * [`MAX_CONCURRENT_HANDSHAKES`] rendezvous handshakes in flight, each bounded
//!   by [`RENDEZVOUS_TIMEOUT`]. The permit covers only `RendRequest::accept`
//!   (building the circuit to the client's rendezvous point), not the circuit's life.
//! * [`MAX_LIVE_CIRCUITS`] established rendezvous circuits. A circuit with no open
//!   signaling stream for [`CIRCUIT_IDLE_TIMEOUT`] is dropped, which closes it:
//!   the stream `RendRequest::accept` returns owns the rendezvous tunnel
//!   (`tor-hsservice-0.45.0/src/req.rs` 233–241).
//! * A request that is not `BEGIN` on one of the three served ports —
//!   [`SIGNALING_PORT`], [`MEDIA_PORT`] (a session's media stream) and
//!   [`SERVICES_PORT`] (its services stream) — destroys its circuit
//!   (`StreamRequest::shutdown_circuit`), exactly what Arti's own reverse proxy
//!   does for an unmatched port (`tor-hsrproxy-0.45.0/src/proxy.rs` 225–250).
//!   Rejected streams never count toward `max_concurrent_streams_per_circuit`, so
//!   without this one circuit could probe every virtual port. The media and
//!   services ports are accepted like signaling (the listener has no peer
//!   identity to check): nothing is served on them until the peer proves a
//!   live session's token in its first frame, within a deadline. A session
//!   uses all three, which leaves one of the circuit's four streams
//!   (`super::MAX_STREAMS_PER_CIRCUIT`).
//! * [`ACCEPT_QUEUE_LEN`] accepted streams waiting for [`OnionListener::accept`].
//!   When the queue is full a `BEGIN` is refused with `END(DONE)` *before* being
//!   accepted, which is what the reverse proxy sends when its target is
//!   unreachable; accepting and then dropping would show `CONNECTED` followed
//!   by `END(MISC)`, a Tornect-specific pattern. Accepting and refusing are each
//!   bounded by [`ACCEPT_TIMEOUT`].
//! * Writes on an [`OnionStream`], host or client side, fail with `TimedOut`
//!   after [`STREAM_WRITE_TIMEOUT`] without progress. Arti sends stream data
//!   only while the peer's flow-control window is open
//!   (`tor-proto-0.45.0/src/stream/flow_ctrl/window/state.rs` `can_send`,
//!   `client/reactor/circuit/circhop.rs` 127–137), so a peer that withholds
//!   `SENDME`s would otherwise pin the writing task — and, on the host, through
//!   the stream's guard the circuit's slot — forever. Every protocol on the
//!   stream inherits the bound.
//!
//! What happens to a rendezvous request that arrives while every slot is busy
//! is the [`Admission`] policy, derived from whether Arti enforces
//! proof-of-work for the service (never configurable on its own):
//!
//! * **PoW on — [`Admission::Backpressure`]**: the accept loop reserves a slot
//!   *before* it polls Arti's request stream, so the overflow stays in Arti's
//!   own queue. That queue is effort-ordered (highest proof-of-work first,
//!   oldest first among equals, `tor-hsservice-0.45.0/src/pow/v1.rs` 782–803),
//!   bounded by `pow_rend_queue_depth` (the lowest-effort entry is dropped when
//!   it is full, 1169–1177) and expired after `hs_pow_v1_service_intro_timeout`
//!   (300 s, 1200–1248). Its occupancy is also the only load signal Arti's
//!   control loop has: the suggested effort published in the descriptor can rise
//!   only for periods in which the queue was non-empty (`update_suggested_effort`,
//!   968–1036, every 300 s; a request leaves the queue exactly when the consumer
//!   polls `next()`, 1254–1272). A loop that drained the queue eagerly and
//!   dropped the overflow itself would therefore keep the effort at zero and
//!   hand admission to first-come budgets with no effort ordering (third
//!   security review, high). An Arti client whose attempt *fails* retries with
//!   a proof of work of at least effort 8 (`tor-hsclient-0.45.0/src/pow/v1.rs`
//!   30, 73–80, `connect.rs` 1093), which is dequeued before every request
//!   without one — but only inside one connect attempt series: the
//!   `HsPowClient` is created per series from the descriptor's suggested
//!   effort (`connect.rs` 929), and a request that merely sits in the queue is
//!   not failed, it is unanswered, which the client notices only after its
//!   rendezvous-completion timeout (`connect.rs` 1481–1518). What that means
//!   for Tornect's own client is in the residual exposure below.
//! * **PoW off — [`Admission::Drop`]**: Arti's queue is then an unbounded FIFO
//!   (`queue_pow_disabled`, 853, 1189), so the loop drains it eagerly and drops
//!   what finds no slot. Rejecting a `RendRequest` is free (arti.md §8.3).
//!
//! What these bounds do **not** do: an unauthenticated peer that keeps talking
//! within every deadline keeps its slot for as long as the protocol on top lets
//! it. The listener has no peer identity to account against before the
//! envelope's signed `HELLO`, so the bound on a chatty peer is the application's
//! job — `ping::serve` caps a session's length and ping count and the CLI caps
//! concurrent sessions — until the envelope track promotes authenticated streams
//! out of the unauthenticated budget and adds the per-device temp-ban list
//! (`docs/PLAN.md` §B.3). A chatty attacker therefore costs one rendezvous per
//! slot per session budget, not one rendezvous per host lifetime.
//!
//! Residual exposure, stated. The handshake budget is the tighter choke point:
//! a request whose rendezvous point is dead or slow holds a handshake permit
//! until Arti's circuit-build attempts give up (`hs_service_rendezvous_failures_max`
//! = 2) or [`RENDEZVOUS_TIMEOUT`] fires, so ≈ [`MAX_CONCURRENT_HANDSHAKES`] /
//! [`RENDEZVOUS_TIMEOUT`] ≈ 1 such introduction per second keeps it full — far
//! below the 25/s introduction rate limit — and the circuit budget needs ≈ 0.5
//! rendezvous per second (64 per 120 s session budget). Without proof-of-work
//! that is a lockout of every later client, which is why `tor.pow_defense` is
//! on by default and refused rather than ignored when it cannot be honoured
//! (decision M1-5). With it, the same flood only fills the slots: everything
//! behind them waits in Arti's queue where effort decides the order and the
//! published effort rises at the next update, so a client that *pays* effort
//! is served before a flood that pays none. Whether a client pays is the
//! client's business, and Tornect's own client cannot yet on the path that
//! matters (fourth security review, medium). A queued request is unanswered,
//! not refused, and the Arti client gives up on an unanswered request only
//! after `rpt_ipt_timeout` (`connect.rs` 1481–1518): three
//! `BuildCircuit { length: 5 }` estimates plus one one-way transit, which its
//! Pareto estimator answers with the 60 s `cbtinitialtimeout` fallback scaled
//! by circuit length — 3 × 150 s + ≈ 40 s, ≈ 8 min — until its persisted
//! history holds `cbtmincircs` = 100 build times
//! (`tor-circmgr-0.45.0/src/timeouts/pareto.rs` 524–533, 617–638; the nine
//! logged `tornect ping` runs of the evidence note left 55 in
//! `target/tornect-test/h2`). `super::CONNECT_TIMEOUT` (60 s) bounds the whole
//! `TorNode::connect`, the CLI does not retry a `Timeout`, and every `connect`
//! uses a fresh isolation group, so Arti starts it from a blank per-service
//! record and a new `HsPowClient` at the descriptor's suggested effort
//! (`tor-hsclient-0.45.0/src/state.rs` 561, `connect.rs` 929): the effort
//! resets on every call. The effort ≥ 8 retry therefore fires only when an
//! attempt fails *fast* inside one `connect` (a stale intro point's
//! `NOT_RECOGNIZED`, seen live) or once the estimator is warm enough for the
//! rendezvous wait to end inside the 60 s. Meanwhile an honest effort-0
//! request is the youngest of its effort class — behind every older no-PoW
//! request, and the first displaced when the 1024-deep queue overflows
//! (`pop_first`, `pow/v1.rs` 1169–1177) — so a cold client sees `Timeout` for
//! as long as the flood lasts, without ever solving (unless *other* clients'
//! proofs lift the published effort above zero — only PoW-bearing arrivals
//! count, `pow/v1.rs` 1150–1158 — which a fresh `connect` then solves at on
//! its first attempt). The listener cannot fix this: it takes what Arti hands
//! it, in effort order. The fix is client-side
//! and tracked in decision M1-4 for the envelope track: retries under a longer
//! deadline inside `TorNode::connect` when the descriptor carries
//! `pow-params`, or an effort floor carried across calls, which needs Arti to
//! accept one. The cost the host cannot avoid is one circuit build per
//! admitted request, paid also for a request whose client stopped waiting
//! while it queued: a `RendRequest` carries no receive time (`req.rs` 25–47),
//! so the listener cannot tell a stale request from a live one before
//! `accept`; Arti's 300 s expiry bounds its age and [`RENDEZVOUS_TIMEOUT`]
//! what it costs. While the budget is saturated the accept loop logs
//! `rendezvous budget full` once per admitted request — the host's only view
//! of the overflow.
//!
//! Deviations from a stock Arti reverse-proxy service, accepted (decision M1-2):
//! a rendezvous circuit with no stream is torn down after [`CIRCUIT_IDLE_TIMEOUT`]
//! (Arti keeps it), a fifth concurrent stream tears the circuit down
//! (`max_concurrent_streams_per_circuit` = 4 instead of 65535, Arti's
//! `RequestFilter`, `rend_handshake.rs` 231), and `tornect host` closes its
//! 65th session after `CONNECTED`. Anyone holding the address can identify a
//! Tornect host by speaking its protocol on port 4000 regardless, so these are
//! DoS trade-offs, not a loss of anonymity; the anti-discovery control is
//! restricted discovery, which fails closed until implemented.
//!
//! Every task the listener spawns is owned by it: dropping the listener aborts
//! the accept loop, whose `JoinSet` aborts every circuit task in turn, and each
//! aborted circuit task drops its request stream, closing the circuit.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use arti_client::DataStream;
use futures::{Stream, StreamExt as _};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Sleep;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::status::{OnionServiceStatus, Problem, State};
use tor_hsservice::{RendRequest, RunningOnionService, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tornect_core::TornectId;

use super::{MEDIA_PORT, SERVICES_PORT, SIGNALING_PORT};

/// Rendezvous handshakes completed at once; what a request that finds them all
/// busy meets is the [`Admission`] policy. The permit is released as soon as
/// the rendezvous circuit is up; established circuits are bounded separately by
/// [`MAX_LIVE_CIRCUITS`]. Each handshake costs one circuit build, so 32 keeps a
/// burst of honest clients moving while Arti's effort ramps, without letting
/// the host build circuits faster than it can afford.
pub const MAX_CONCURRENT_HANDSHAKES: usize = 32;

/// Upper bound on one rendezvous handshake (`RendRequest::accept`). Arti already
/// bounds it by `hs_service_rendezvous_failures_max` (= 2) circuit-build
/// attempts (`tor-hsservice-0.45.0/src/rend_handshake.rs` 322–345), but a
/// build attempt can wait the circuit timeout estimator's full initial 60 s.
/// A handshake still running after 30 s has a client at or past its own 60 s
/// connect budget (`super::CONNECT_TIMEOUT`, which also covers its descriptor
/// fetch and introduction), so cutting it frees the permit for a live client;
/// measured handshakes take 1–3 s host-side (docs/notes/m1-track1-evidence.md).
pub const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);

/// Established rendezvous circuits kept at once.
pub const MAX_LIVE_CIRCUITS: usize = 64;

/// How long a rendezvous circuit may exist with no open signaling stream —
/// right after the handshake, or after the peer closed its last stream —
/// before the host drops it.
pub const CIRCUIT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Accepted streams waiting for [`OnionListener::accept`]; beyond this, `BEGIN`
/// requests are refused with `END(DONE)` and their circuit is kept.
pub const ACCEPT_QUEUE_LEN: usize = 32;

/// Upper bound on answering one `BEGIN` with `CONNECTED` or `END(DONE)`
/// (`StreamRequest::{accept,reject}`), defense in depth: the cell goes out
/// through the circuit reactor's control channel, not the data path, so it
/// should never wait.
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a write on an [`OnionStream`] may make no progress before it fails
/// with `TimedOut`. A peer reading normally grants credit within a round trip
/// (~1 s over Tor); one that has not for 30 s is not reading.
pub const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// What the accept loop does with a rendezvous request that arrives while every
/// slot is busy (module docs). Chosen by [`Admission::for_pow`] from the
/// onion-service configuration, never on its own: each policy is sound only
/// with the matching Arti queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Leave it in Arti's effort-ordered, bounded, expiring queue until a slot
    /// frees up; the accept loop polls Arti only while it holds a slot. Sound
    /// only with `enable_pow`.
    Backpressure,
    /// Take it at once and drop it. Required without `enable_pow`, when Arti's
    /// queue is an unbounded FIFO.
    Drop,
}

impl Admission {
    /// The policy for an onion service with (`true`) or without proof-of-work.
    #[must_use]
    pub const fn for_pow(enable_pow: bool) -> Self {
        if enable_pow {
            Self::Backpressure
        } else {
            Self::Drop
        }
    }
}

/// The host-side rendezvous bounds (module docs). [`RendezvousLimits::default`]
/// is what `tornect host` runs with; tests use smaller values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RendezvousLimits {
    /// Rendezvous handshakes in flight at once ([`MAX_CONCURRENT_HANDSHAKES`]).
    pub max_handshakes: usize,
    /// Established rendezvous circuits kept at once ([`MAX_LIVE_CIRCUITS`]).
    pub max_live_circuits: usize,
    /// How long a circuit may have no open signaling stream ([`CIRCUIT_IDLE_TIMEOUT`]).
    pub circuit_idle_timeout: Duration,
}

impl Default for RendezvousLimits {
    fn default() -> Self {
        Self {
            max_handshakes: MAX_CONCURRENT_HANDSHAKES,
            max_live_circuits: MAX_LIVE_CIRCUITS,
            circuit_idle_timeout: CIRCUIT_IDLE_TIMEOUT,
        }
    }
}

/// Where publishing the service stands, in the words a user is told
/// (the final audit before the release): Arti's states, grouped. The
/// window says these; Arti's own names and problems go to the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnionPhase {
    /// Launched, its descriptor not out yet: `Shutdown` (the state a service
    /// reports as it launches) or `Bootstrapping`. A listener that really
    /// stops is no longer watched, so `Shutdown` is never its end here.
    #[default]
    Starting,
    /// `Running` or `DegradedReachable`: clients can reach it.
    Reachable,
    /// `DegradedUnreachable` or `Recovering`, and any state a later Arti
    /// adds: not reachable, and Tor keeps trying.
    Trying,
    /// `Broken`: Arti gave up on it.
    Broken,
}

impl OnionPhase {
    /// The phase of Arti's `state`.
    #[must_use]
    pub fn of(state: State) -> Self {
        match state {
            State::Shutdown | State::Bootstrapping => Self::Starting,
            State::Running | State::DegradedReachable => Self::Reachable,
            State::Broken => Self::Broken,
            // `DegradedUnreachable`, `Recovering`, and what the
            // non-exhaustive enum may add.
            _ => Self::Trying,
        }
    }
}

/// Reachability of the published service, driven from Arti's status stream.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OnionStatus {
    /// `true` once the descriptor is on both HsDir rings and intro points are up
    /// (`Running` or `DegradedReachable`).
    pub reachable: bool,
    /// Arti's state, grouped as a user is told it.
    pub phase: OnionPhase,
    /// Arti's state name: `Shutdown`, `Bootstrapping`, `Running`,
    /// `DegradedReachable`, `DegradedUnreachable`, `Recovering`, `Broken`.
    /// For the log and diagnostics, not for the window's words.
    pub state: String,
    /// The most severe current problem, if any (descriptor upload, intro points…).
    pub problem: Option<String>,
}

impl OnionStatus {
    fn from_arti(status: &OnionServiceStatus) -> Self {
        let state = status.state();
        Self {
            reachable: state.is_fully_reachable(),
            phase: OnionPhase::of(state),
            state: format!("{state:?}"),
            problem: status.current_problem().and_then(describe_problem),
        }
    }
}

/// Compact, secret-free description of an Arti problem report. Arti reports
/// empty error lists while components start up; those are not problems.
fn describe_problem(problem: &Problem) -> Option<String> {
    match problem {
        Problem::Runtime(e) => Some(format!("fatal: {e}")),
        Problem::DescriptorUpload(errors) if errors.is_empty() => None,
        Problem::Ipt(errors) if errors.is_empty() => None,
        Problem::DescriptorUpload(errors) => Some(format!(
            "descriptor upload failed ({} attempt(s))",
            errors.len()
        )),
        Problem::Ipt(errors) => Some(format!("introduction point errors ({})", errors.len())),
        other => Some(format!("{other:?}")),
    }
}

/// A published onion service.
///
/// Dropping it stops publishing and aborts every task it spawned: the accept
/// loop and, through it, each rendezvous circuit that has no accepted stream
/// handed out yet. Streams already returned by [`OnionListener::accept`] stay
/// open until their owner drops them.
pub struct OnionListener {
    /// Held only to keep the service alive: Arti stops publishing when the last
    /// `Arc<RunningOnionService>` is dropped (docs/research/arti.md §8.2).
    _service: Arc<RunningOnionService>,
    address: TornectId,
    admission: Admission,
    limits: RendezvousLimits,
    incoming: mpsc::Receiver<OnionStream>,
    status: watch::Receiver<OnionStatus>,
    tasks: Vec<JoinHandle<()>>,
}

impl fmt::Debug for OnionListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnionListener")
            .field("address", &self.address)
            .field("admission", &self.admission)
            .field("limits", &self.limits)
            .field("status", &*self.status.borrow())
            .finish_non_exhaustive()
    }
}

impl OnionListener {
    pub(crate) fn new<S>(
        service: Arc<RunningOnionService>,
        rend_requests: S,
        address: TornectId,
        admission: Admission,
        limits: RendezvousLimits,
    ) -> Self
    where
        S: Stream<Item = RendRequest> + Send + 'static,
    {
        let mut last = OnionStatus::from_arti(&service.status());
        let (status_tx, status) = watch::channel(last.clone());
        let mut status_events = Box::pin(service.status_events());
        let status_task = tokio::spawn(async move {
            while let Some(st) = status_events.next().await {
                let status = OnionStatus::from_arti(&st);
                // Arti re-emits on every internal event; only changes are news.
                if status == last {
                    continue;
                }
                tracing::info!(
                    state = %status.state,
                    reachable = status.reachable,
                    problem = status.problem.as_deref().unwrap_or("-"),
                    "onion service status"
                );
                last = status.clone();
                status_tx.send_replace(status);
            }
        });

        let (incoming_tx, incoming) = mpsc::channel(ACCEPT_QUEUE_LEN);
        let accept_task = tokio::spawn(accept_loop(
            Box::pin(rend_requests),
            incoming_tx,
            admission,
            limits,
        ));

        Self {
            _service: service,
            address,
            admission,
            limits,
            incoming,
            status,
            tasks: vec![status_task, accept_task],
        }
    }

    /// The published address — always equal to the host's Tornect ID.
    #[must_use]
    pub fn onion_address(&self) -> TornectId {
        self.address
    }

    /// How rendezvous requests beyond the budgets are treated (module docs).
    #[must_use]
    pub fn admission(&self) -> Admission {
        self.admission
    }

    /// The rendezvous budgets in force.
    #[must_use]
    pub fn limits(&self) -> RendezvousLimits {
        self.limits
    }

    /// Live reachability view (`changed().await` wakes on updates).
    #[must_use]
    pub fn status(&self) -> watch::Receiver<OnionStatus> {
        self.status.clone()
    }

    /// Whether the service is currently reachable from the Tor network.
    #[must_use]
    pub fn is_reachable(&self) -> bool {
        self.status.borrow().reachable
    }

    /// Next accepted signaling stream; `None` once the listener has shut down.
    pub async fn accept(&mut self) -> Option<OnionStream> {
        self.incoming.recv().await
    }
}

impl Drop for OnionListener {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        tracing::info!(address = %self.address, "onion service stopped");
        // `self._service` is dropped right after this, which stops publishing.
    }
}

/// The two budgets of [`RendezvousLimits`] as semaphores; a [`Slot`] is one
/// rendezvous' share of both.
struct Slots {
    handshakes: Arc<Semaphore>,
    circuits: Arc<Semaphore>,
}

/// Permits for one rendezvous: the handshake permit is released once the
/// circuit is up ([`serve_rendezvous`]), the circuit permit when the circuit
/// closes.
struct Slot {
    handshake: OwnedSemaphorePermit,
    circuit: OwnedSemaphorePermit,
}

impl Slots {
    fn new(limits: &RendezvousLimits) -> Self {
        Self {
            handshakes: Arc::new(Semaphore::new(limits.max_handshakes)),
            circuits: Arc::new(Semaphore::new(limits.max_live_circuits)),
        }
    }

    /// Wait until both budgets have room. Cancel-safe: a permit taken by a
    /// dropped `reserve` goes back. `None` only if a semaphore was closed,
    /// which nothing here does.
    async fn reserve(&self) -> Option<Slot> {
        let circuit = Arc::clone(&self.circuits).acquire_owned().await.ok()?;
        let handshake = Arc::clone(&self.handshakes).acquire_owned().await.ok()?;
        Some(Slot { handshake, circuit })
    }

    /// Take a slot only if both budgets have room now; `Err` names the budget
    /// that is full.
    fn try_reserve(&self) -> Result<Slot, &'static str> {
        let circuit = Arc::clone(&self.circuits)
            .try_acquire_owned()
            .map_err(|_| "live rendezvous circuits")?;
        let handshake = Arc::clone(&self.handshakes)
            .try_acquire_owned()
            .map_err(|_| "rendezvous handshakes in flight")?;
        Ok(Slot { handshake, circuit })
    }
}

/// Accept rendezvous requests under the budgets and serve each circuit in its
/// own task. Equivalent to `tor_hsservice::handle_rend_requests` plus the
/// bounds, and with every circuit task owned by this future.
async fn accept_loop(
    rend_requests: Pin<Box<dyn Stream<Item = RendRequest> + Send>>,
    incoming: mpsc::Sender<OnionStream>,
    admission: Admission,
    limits: RendezvousLimits,
) {
    let slots = Slots::new(&limits);
    let idle = limits.circuit_idle_timeout;
    supervise(rend_requests, admission, &slots, move |request, slot| {
        serve_rendezvous(request, slot, incoming.clone(), idle)
    })
    .await;
    tracing::debug!("rendezvous request stream ended");
}

/// Drive `requests` to completion under `admission`, spawning the task `spawn`
/// returns for each admitted item into a `JoinSet`. Finished children are
/// reaped as they complete, and dropping this future (the listener aborting its
/// accept task) aborts every child still running.
///
/// Under [`Admission::Backpressure`] a [`Slot`] is reserved *before* the stream
/// is polled, so a request that would find no slot is never taken out of it
/// (Arti's queue keeps, orders and expires it); under [`Admission::Drop`] the
/// stream is polled eagerly and a request that finds no slot is dropped.
async fn supervise<S, F, Fut>(mut requests: S, admission: Admission, slots: &Slots, mut spawn: F)
where
    S: Stream + Unpin,
    F: FnMut(S::Item, Slot) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut children = JoinSet::new();
    loop {
        let reserved = match admission {
            Admission::Backpressure => match slots.try_reserve() {
                Ok(slot) => Some(slot),
                Err(budget) => {
                    // Once per admitted request while saturated (≈ 1/s at most,
                    // the rate the handshake budget cycles): the host's only
                    // load signal, since the overflow is invisible from here.
                    tracing::info!(
                        budget,
                        "rendezvous budget full; further requests wait in Tor's \
                         proof-of-work queue until a slot frees"
                    );
                    loop {
                        tokio::select! {
                            slot = slots.reserve() => match slot {
                                Some(slot) => break Some(slot),
                                None => return,
                            },
                            Some(_) = children.join_next(), if !children.is_empty() => {}
                        }
                    }
                }
            },
            Admission::Drop => None,
        };
        let request = loop {
            tokio::select! {
                request = requests.next() => break request,
                Some(_) = children.join_next(), if !children.is_empty() => {}
            }
        };
        let Some(request) = request else { break };
        let slot = match reserved {
            Some(slot) => slot,
            None => match slots.try_reserve() {
                Ok(slot) => slot,
                Err(budget) => {
                    // `request` is dropped here: rejecting costs nothing.
                    tracing::warn!(budget, "rendezvous request dropped: budget exhausted");
                    continue;
                }
            },
        };
        children.spawn(spawn(request, slot));
    }
}

/// Complete one rendezvous handshake and serve the resulting circuit.
async fn serve_rendezvous(
    request: RendRequest,
    slot: Slot,
    incoming: mpsc::Sender<OnionStream>,
    idle: Duration,
) {
    let Slot {
        handshake,
        circuit: _circuit,
    } = slot;
    let accepted = tokio::time::timeout(RENDEZVOUS_TIMEOUT, request.accept()).await;
    drop(handshake);
    let stream_requests = match accepted {
        Ok(Ok(stream_requests)) => stream_requests,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "rendezvous failed");
            return;
        }
        Err(_) => {
            tracing::warn!(
                timeout_s = RENDEZVOUS_TIMEOUT.as_secs(),
                "rendezvous handshake timed out"
            );
            return;
        }
    };
    tracing::debug!("rendezvous established");
    let end = serve_circuit(stream_requests, &incoming, idle).await;
    tracing::debug!(reason = ?end, "rendezvous circuit closed");
}

/// Why a circuit's per-rendezvous loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitEnd {
    /// The peer or the network closed the circuit.
    Closed,
    /// No signaling stream was open for the idle deadline; dropping the request
    /// stream closes the circuit.
    Idle,
    /// A request that was not `BEGIN` on a served port ([`admitted_port`]);
    /// the circuit was destroyed.
    Rejected,
}

/// What became of one stream request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamOutcome {
    /// Accepted and handed to the listener.
    Accepted,
    /// Not `BEGIN` on a served port; the circuit has been destroyed.
    Rejected,
    /// Refused with `END(DONE)` (accept queue full), or accepting failed; the
    /// circuit stays.
    Failed,
}

/// Serve every stream request of one rendezvous circuit until it closes,
/// idles out, or a foreign request destroys it.
async fn serve_circuit<S>(
    stream_requests: S,
    incoming: &mpsc::Sender<OnionStream>,
    idle: Duration,
) -> CircuitEnd
where
    S: Stream<Item = StreamRequest> + Unpin,
{
    let (live_tx, live_rx) = watch::channel(0usize);
    let live_tx = Arc::new(live_tx);
    drive_circuit(stream_requests, idle, live_rx, |request| {
        let incoming = incoming.clone();
        let live_tx = Arc::clone(&live_tx);
        async move { handle_stream_request(request, &incoming, &live_tx).await }
    })
    .await
}

/// The per-circuit loop, generic so the deadline logic is testable without Arti:
/// `live` counts the circuit's open accepted streams (see [`StreamGuard`]); the
/// idle deadline runs only while that count is zero.
async fn drive_circuit<S, F, Fut>(
    mut requests: S,
    idle: Duration,
    live: watch::Receiver<usize>,
    mut handle: F,
) -> CircuitEnd
where
    S: Stream + Unpin,
    F: FnMut(S::Item) -> Fut,
    Fut: Future<Output = StreamOutcome>,
{
    let idle = idle_expired(live, idle);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            request = requests.next() => match request {
                None => return CircuitEnd::Closed,
                Some(request) => match handle(request).await {
                    StreamOutcome::Accepted | StreamOutcome::Failed => {}
                    StreamOutcome::Rejected => return CircuitEnd::Rejected,
                },
            },
            () = &mut idle => return CircuitEnd::Idle,
        }
    }
}

/// Resolves once `live` has been zero for `idle` in a row (the clock restarts
/// whenever the last open stream closes).
async fn idle_expired(mut live: watch::Receiver<usize>, idle: Duration) {
    loop {
        if live.wait_for(|open| *open == 0).await.is_err() {
            return;
        }
        tokio::select! {
            () = tokio::time::sleep(idle) => return,
            reopened = live.wait_for(|open| *open > 0) => {
                if reopened.is_err() {
                    return;
                }
            }
        }
    }
}

/// Keeps its circuit's open-stream count raised for as long as the accepted
/// [`OnionStream`] exists, so the idle deadline does not fire under a live session.
struct StreamGuard(Arc<watch::Sender<usize>>);

impl StreamGuard {
    fn new(live: &Arc<watch::Sender<usize>>) -> Self {
        live.send_modify(|open| *open += 1);
        Self(Arc::clone(live))
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.send_modify(|open| *open = open.saturating_sub(1));
    }
}

/// The ports a peer may open a stream on: signaling, a session's media
/// stream and its services stream. Every other port destroys the circuit.
const SERVED_PORTS: [u16; 3] = [SIGNALING_PORT, MEDIA_PORT, SERVICES_PORT];

/// The port of a stream request the listener accepts: `BEGIN` on one of
/// [`SERVED_PORTS`]. `None` for anything else (another port, `BEGIN_DIR`,
/// `RESOLVE`), which destroys the circuit.
fn admitted_port(request: &IncomingStreamRequest) -> Option<u16> {
    match request {
        IncomingStreamRequest::Begin(begin) if SERVED_PORTS.contains(&begin.port()) => {
            Some(begin.port())
        }
        _ => None,
    }
}

/// Accept `BEGIN` on a served port ([`admitted_port`]); anything else destroys
/// the circuit.
async fn handle_stream_request(
    request: StreamRequest,
    incoming: &mpsc::Sender<OnionStream>,
    live: &Arc<watch::Sender<usize>>,
) -> StreamOutcome {
    let Some(port) = admitted_port(request.request()) else {
        tracing::debug!("stream request is not BEGIN on a served port; destroying circuit");
        if let Err(e) = request.shutdown_circuit() {
            tracing::debug!(error = %e, "destroying circuit failed");
        }
        return StreamOutcome::Rejected;
    };
    // Refuse before accepting when nobody can take the stream: the peer then
    // sees END(DONE), as from Arti's reverse proxy with an unreachable target,
    // rather than CONNECTED followed by END(MISC). `try_send` below still
    // covers the race with other circuits filling the queue meanwhile.
    if incoming.is_closed() || incoming.capacity() == 0 {
        tracing::warn!(
            limit = ACCEPT_QUEUE_LEN,
            "accept queue full or listener gone; refusing stream with END(DONE)"
        );
        let rejected = tokio::time::timeout(
            ACCEPT_TIMEOUT,
            request.reject(End::new_with_reason(EndReason::DONE)),
        );
        match rejected.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::debug!(error = %e, "refusing stream failed"),
            Err(_) => tracing::warn!(
                timeout_s = ACCEPT_TIMEOUT.as_secs(),
                "refusing stream timed out; dropping the request"
            ),
        }
        return StreamOutcome::Failed;
    }
    let accepted = tokio::time::timeout(ACCEPT_TIMEOUT, request.accept(Connected::new_empty()));
    match accepted.await {
        Ok(Ok(stream)) => {
            let stream = OnionStream::served(stream, StreamGuard::new(live), port);
            match incoming.try_send(stream) {
                Ok(()) => StreamOutcome::Accepted,
                Err(_) => {
                    tracing::warn!("accept queue filled up meanwhile; dropping stream");
                    StreamOutcome::Failed
                }
            }
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "accepting stream failed");
            StreamOutcome::Failed
        }
        Err(_) => {
            tracing::warn!(
                timeout_s = ACCEPT_TIMEOUT.as_secs(),
                "accepting stream timed out; dropping the request"
            );
            StreamOutcome::Failed
        }
    }
}

/// Fails a write that has made no progress for a deadline: the timer arms on
/// the first `Pending`, resets on any `Ready`, and turns a `Pending` past the
/// deadline into `TimedOut`. Both the inner I/O and the timer register the
/// task's waker, so whichever fires first is polled.
struct StallTimer {
    deadline: Duration,
    stalled: Option<Pin<Box<Sleep>>>,
}

impl StallTimer {
    fn new(deadline: Duration) -> Self {
        Self {
            deadline,
            stalled: None,
        }
    }

    fn bound<T>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match poll {
            Poll::Pending => {
                let deadline = self.deadline;
                let sleep = self
                    .stalled
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(deadline)));
                match sleep.as_mut().poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(()) => {
                        self.stalled = None;
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "peer stopped accepting data (stream write stalled)",
                        )))
                    }
                }
            }
            ready => {
                self.stalled = None;
                ready
            }
        }
    }
}

/// A stream over a Tor rendezvous circuit.
///
/// Implements tokio `AsyncRead` + `AsyncWrite`. Arti buffers writes: call
/// `flush()` (the [`crate::framing`] helpers do) or the peer sees nothing.
/// `shutdown()` closes our send side; Arti then emits `END(MISC)`, which the
/// peer's `OnionStream` reports as a clean EOF. A write, flush or shutdown that
/// makes no progress for [`STREAM_WRITE_TIMEOUT`] fails with `TimedOut`, on
/// either side (see the module docs): a host that withholds flow-control credit
/// cannot pin a client in `shutdown()` any more than the reverse.
pub struct OnionStream {
    inner: DataStream,
    /// Present on host-side streams: keeps the circuit's idle deadline paused.
    _guard: Option<StreamGuard>,
    /// The write deadline.
    stall: StallTimer,
    /// The virtual port: [`SIGNALING_PORT`], [`MEDIA_PORT`] or [`SERVICES_PORT`].
    port: u16,
}

impl OnionStream {
    /// A client-side stream (`TorNode::connect`) to `port`.
    pub(crate) fn new(inner: DataStream, port: u16) -> Self {
        Self::with_guard(inner, None, port)
    }

    /// A host-side stream: `guard` ties it to its circuit's idle deadline.
    fn served(inner: DataStream, guard: StreamGuard, port: u16) -> Self {
        Self::with_guard(inner, Some(guard), port)
    }

    fn with_guard(inner: DataStream, guard: Option<StreamGuard>, port: u16) -> Self {
        Self {
            inner,
            _guard: guard,
            stall: StallTimer::new(STREAM_WRITE_TIMEOUT),
            port,
        }
    }

    /// The virtual port this stream was opened on: [`SIGNALING_PORT`] for the
    /// envelope protocol, [`MEDIA_PORT`] for a session's Tor media stream,
    /// [`SERVICES_PORT`] for its services stream (chat, clipboard, files). A
    /// host-side stream is on one of these three; the accept loop dispatches by
    /// it.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    fn bound<T>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        self.stall.bound(cx, poll)
    }
}

impl fmt::Debug for OnionStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OnionStream")
    }
}

impl AsyncRead for OnionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_read(cx, buf) {
            // Arti closes a dropped or shut-down stream with END(MISC), which the
            // reader reports as an error; for Tornect that is simply the peer hanging up.
            Poll::Ready(Err(e)) if peer_closed(&e) => Poll::Ready(Ok(())),
            other => other,
        }
    }
}

/// Whether a read error means the peer ended the stream (as opposed to a
/// circuit collapse or a local fault): Arti's `END` with reason `MISC` (what a
/// dropped or shut-down `DataStream` sends) or `DONE`.
fn peer_closed(e: &io::Error) -> bool {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<tor_proto::Error>())
        .is_some_and(|inner| match inner {
            tor_proto::Error::EndReceived(reason) => {
                *reason == EndReason::MISC || *reason == EndReason::DONE
            }
            _ => false,
        })
}

impl AsyncWrite for OnionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.bound(cx, poll)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_flush(cx);
        this.bound(cx, poll)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.bound(cx, poll)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use futures::channel::mpsc::unbounded;
    use futures::stream;
    use tokio::sync::Notify;

    use super::*;

    const SHORT: Duration = Duration::from_millis(50);
    const PATIENCE: Duration = Duration::from_secs(10);

    #[test]
    fn end_misc_and_done_are_peer_closes_but_collapses_are_not() {
        let misc = io::Error::from(tor_proto::Error::EndReceived(EndReason::MISC));
        let done = io::Error::from(tor_proto::Error::EndReceived(EndReason::DONE));
        let reset = io::Error::from(tor_proto::Error::EndReceived(EndReason::CONNRESET));
        let collapse = io::Error::from(tor_proto::Error::CircuitClosed);
        let plain = io::Error::other("something else");
        assert!(peer_closed(&misc));
        assert!(peer_closed(&done));
        assert!(!peer_closed(&reset));
        assert!(!peer_closed(&collapse));
        assert!(!peer_closed(&plain));
    }

    /// The final audit before the release: the window says the phase, so
    /// each of Arti's states falls in the group a user is told. `Shutdown`
    /// is the launch-time state, never a failure.
    #[test]
    fn each_onion_service_state_has_its_phase() {
        for (state, phase) in [
            (State::Shutdown, OnionPhase::Starting),
            (State::Bootstrapping, OnionPhase::Starting),
            (State::Running, OnionPhase::Reachable),
            (State::DegradedReachable, OnionPhase::Reachable),
            (State::DegradedUnreachable, OnionPhase::Trying),
            (State::Recovering, OnionPhase::Trying),
            (State::Broken, OnionPhase::Broken),
        ] {
            assert_eq!(OnionPhase::of(state), phase, "{state:?}");
            assert_eq!(
                phase == OnionPhase::Reachable,
                state.is_fully_reachable(),
                "{state:?}"
            );
        }
        assert_eq!(OnionStatus::default().phase, OnionPhase::Starting);
    }

    #[test]
    fn empty_problem_lists_are_not_problems() {
        assert!(describe_problem(&Problem::Ipt(Vec::new())).is_none());
        assert!(describe_problem(&Problem::DescriptorUpload(Vec::new())).is_none());
    }

    #[tokio::test]
    async fn stall_timer_fails_a_write_with_no_progress_and_resets_on_progress() {
        // Generous unit so the "still pending" checks cannot flake on a slow runner.
        const STALL: Duration = Duration::from_millis(200);
        let cx = &mut Context::from_waker(futures::task::noop_waker_ref());

        // A write that never progresses fails once the deadline passes.
        let mut timer = StallTimer::new(STALL);
        let started = Instant::now();
        let err = futures::future::poll_fn(|cx| timer.bound::<usize>(cx, Poll::Pending))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= STALL);

        // Progress disarms the timer; the next stall gets a full deadline again.
        let mut timer = StallTimer::new(STALL);
        assert!(timer.bound::<()>(cx, Poll::Pending).is_pending());
        tokio::time::sleep(STALL / 2).await;
        assert!(matches!(
            timer.bound(cx, Poll::Ready(Ok(1usize))),
            Poll::Ready(Ok(1))
        ));
        let rearmed = Instant::now();
        assert!(timer.bound::<()>(cx, Poll::Pending).is_pending());
        tokio::time::sleep(STALL * 3 / 4).await;
        // The original timer would have fired by now; the re-armed one has not.
        assert!(timer.bound::<()>(cx, Poll::Pending).is_pending());
        tokio::time::sleep(STALL / 2).await;
        let Poll::Ready(Err(err)) = timer.bound::<()>(cx, Poll::Pending) else {
            panic!("the re-armed timer must fire")
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(rearmed.elapsed() >= STALL);
        // And an error is a completed poll too: it passes through and disarms.
        assert!(matches!(
            timer.bound::<()>(cx, Poll::Ready(Err(io::Error::other("x")))),
            Poll::Ready(Err(_))
        ));
        assert!(timer.stalled.is_none());
    }

    #[tokio::test]
    async fn silent_circuit_is_dropped_after_the_idle_deadline() {
        // A peer that completes the rendezvous and never sends BEGIN.
        let (_live_tx, live_rx) = watch::channel(0usize);
        let started = Instant::now();
        let end = tokio::time::timeout(
            PATIENCE,
            drive_circuit(stream::pending::<()>(), SHORT, live_rx, |()| async {
                StreamOutcome::Accepted
            }),
        )
        .await
        .expect("idle deadline must fire");
        assert_eq!(end, CircuitEnd::Idle);
        assert!(started.elapsed() >= SHORT);
    }

    #[tokio::test]
    async fn open_stream_pauses_the_idle_deadline_until_it_closes() {
        let (live_tx, live_rx) = watch::channel(0usize);
        let live_tx = Arc::new(live_tx);
        let (tx, rx) = unbounded::<()>();
        let guards: Mutex<Vec<StreamGuard>> = Mutex::new(Vec::new());
        let drive = drive_circuit(rx, SHORT, live_rx, |()| {
            guards.lock().unwrap().push(StreamGuard::new(&live_tx));
            async { StreamOutcome::Accepted }
        });
        tokio::pin!(drive);

        tx.unbounded_send(()).unwrap();
        // With a stream open, several idle periods pass without the loop ending.
        assert!(
            tokio::time::timeout(SHORT * 4, &mut drive).await.is_err(),
            "open stream must keep the circuit alive"
        );
        // The peer closes its stream: the idle clock starts now.
        guards.lock().unwrap().clear();
        let closed_at = Instant::now();
        let end = tokio::time::timeout(PATIENCE, &mut drive)
            .await
            .expect("idle deadline must fire after the last stream closes");
        assert_eq!(end, CircuitEnd::Idle);
        assert!(closed_at.elapsed() >= SHORT);
        drop(tx);
    }

    #[tokio::test]
    async fn foreign_request_ends_the_circuit_immediately() {
        let (_live_tx, live_rx) = watch::channel(0usize);
        let (tx, rx) = unbounded::<u16>();
        tx.unbounded_send(80).unwrap();
        let end = tokio::time::timeout(
            PATIENCE,
            drive_circuit(rx, Duration::from_secs(3600), live_rx, |port| async move {
                if port == SIGNALING_PORT {
                    StreamOutcome::Accepted
                } else {
                    StreamOutcome::Rejected
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(end, CircuitEnd::Rejected);
    }

    fn begin(port: u16) -> IncomingStreamRequest {
        let flags = tor_cell::relaycell::msg::BeginFlags::from(0_u32);
        IncomingStreamRequest::Begin(tor_cell::relaycell::msg::Begin::new("", port, flags).unwrap())
    }

    #[test]
    fn only_begin_on_the_signaling_media_and_services_ports_is_admitted() {
        assert_eq!(
            (SIGNALING_PORT, MEDIA_PORT, SERVICES_PORT),
            (4000, 4001, 4002)
        );
        for port in [SIGNALING_PORT, MEDIA_PORT, SERVICES_PORT] {
            assert_eq!(admitted_port(&begin(port)), Some(port));
        }
        // Every other port destroys the circuit: one more served port would be
        // one more way to probe, and an old peer's port must stay refused.
        for port in 0..=u16::MAX {
            assert_eq!(
                admitted_port(&begin(port)).is_some(),
                (4000..=4002).contains(&port),
                "port {port}"
            );
        }
        // Not BEGIN: refused whatever it names.
        let dir = IncomingStreamRequest::BeginDir(tor_cell::relaycell::msg::BeginDir::default());
        assert_eq!(admitted_port(&dir), None);
        let resolve =
            IncomingStreamRequest::Resolve(tor_cell::relaycell::msg::Resolve::new("tornect.onion"));
        assert_eq!(admitted_port(&resolve), None);
    }

    #[tokio::test]
    async fn a_sessions_three_streams_keep_the_circuit_and_a_fourth_port_ends_it() {
        // The decision `handle_stream_request` takes, over one circuit's requests:
        // signaling, media and services are accepted; a BEGIN on 4003 then
        // destroys the circuit, and nothing after it is looked at.
        let (_live_tx, live_rx) = watch::channel(0usize);
        let (tx, rx) = unbounded::<IncomingStreamRequest>();
        for port in [
            SIGNALING_PORT,
            MEDIA_PORT,
            SERVICES_PORT,
            4003,
            SIGNALING_PORT,
        ] {
            tx.unbounded_send(begin(port)).unwrap();
        }
        let seen = Mutex::new(Vec::new());
        let end = tokio::time::timeout(
            PATIENCE,
            drive_circuit(rx, Duration::from_secs(3600), live_rx, |request| {
                let admitted = admitted_port(&request);
                seen.lock().unwrap().push(admitted);
                async move {
                    if admitted.is_some() {
                        StreamOutcome::Accepted
                    } else {
                        StreamOutcome::Rejected
                    }
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(end, CircuitEnd::Rejected);
        assert_eq!(
            *seen.lock().unwrap(),
            [Some(4000), Some(4001), Some(4002), None]
        );
        drop(tx);
    }

    #[tokio::test]
    async fn closed_request_stream_ends_the_circuit() {
        let (_live_tx, live_rx) = watch::channel(0usize);
        let end = drive_circuit(
            stream::empty::<()>(),
            Duration::from_secs(3600),
            live_rx,
            |()| async { StreamOutcome::Accepted },
        )
        .await;
        assert_eq!(end, CircuitEnd::Closed);
    }

    /// Counts drops, standing in for a circuit task's request stream.
    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn wait_until(counter: &AtomicUsize, expected: usize) {
        tokio::time::timeout(PATIENCE, async {
            while counter.load(Ordering::SeqCst) < expected {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "expected {expected}, got {}",
                counter.load(Ordering::SeqCst)
            )
        });
    }

    fn limits(max_handshakes: usize, max_live_circuits: usize) -> RendezvousLimits {
        RendezvousLimits {
            max_handshakes,
            max_live_circuits,
            circuit_idle_timeout: SHORT,
        }
    }

    #[tokio::test]
    async fn aborting_the_accept_loop_aborts_every_circuit_task() {
        // What `OnionListener::drop` relies on: the accept task owns the circuit tasks.
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = unbounded::<()>();
        let supervisor = tokio::spawn({
            let started = Arc::clone(&started);
            let dropped = Arc::clone(&dropped);
            async move {
                let slots = Slots::new(&limits(3, 3));
                supervise(rx, Admission::Drop, &slots, move |(), slot| {
                    let started = Arc::clone(&started);
                    let owned = DropCounter(Arc::clone(&dropped));
                    async move {
                        let _owned = owned;
                        let _slot = slot;
                        started.fetch_add(1, Ordering::SeqCst);
                        // A circuit whose peer never hangs up.
                        futures::future::pending::<()>().await;
                    }
                })
                .await;
            }
        });
        for _ in 0..3 {
            tx.unbounded_send(()).unwrap();
        }
        wait_until(&started, 3).await;
        assert_eq!(dropped.load(Ordering::SeqCst), 0);

        supervisor.abort();
        assert!(supervisor.await.unwrap_err().is_cancelled());
        wait_until(&dropped, 3).await;
        // `tx` outlived the supervisor: the children ended because of the abort,
        // not because the request stream closed.
        drop(tx);
    }

    /// Counts how often it is polled, standing in for Arti's rendezvous request
    /// stream: a poll is what takes a request out of Arti's effort-ordered queue.
    struct Polled<S> {
        inner: S,
        polls: Arc<AtomicUsize>,
    }

    impl<S: Stream + Unpin> Stream for Polled<S> {
        type Item = S::Item;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<S::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Pin::new(&mut self.inner).poll_next(cx)
        }
    }

    /// A supervisor over a one-slot budget whose circuit tasks hold their slot
    /// (and their request) until `release` is notified, once per task.
    struct Harness {
        polls: Arc<AtomicUsize>,
        started: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
        release: Arc<Notify>,
        tx: futures::channel::mpsc::UnboundedSender<DropCounter>,
        supervisor: JoinHandle<()>,
    }

    impl Harness {
        fn start(admission: Admission) -> Self {
            let polls = Arc::new(AtomicUsize::new(0));
            let started = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let release = Arc::new(Notify::new());
            let (tx, rx) = unbounded::<DropCounter>();
            let supervisor = tokio::spawn({
                let polls = Arc::clone(&polls);
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                async move {
                    let slots = Slots::new(&limits(1, 1));
                    let requests = Polled { inner: rx, polls };
                    supervise(requests, admission, &slots, move |request, slot| {
                        let started = Arc::clone(&started);
                        let release = Arc::clone(&release);
                        async move {
                            let _request = request;
                            let _slot = slot;
                            started.fetch_add(1, Ordering::SeqCst);
                            release.notified().await;
                        }
                    })
                    .await;
                }
            });
            Self {
                polls,
                started,
                dropped,
                release,
                tx,
                supervisor,
            }
        }

        fn request(&self) {
            self.tx
                .unbounded_send(DropCounter(Arc::clone(&self.dropped)))
                .unwrap();
        }

        fn polls(&self) -> usize {
            self.polls.load(Ordering::SeqCst)
        }

        async fn finish(self) {
            drop(self.tx);
            tokio::time::timeout(PATIENCE, self.supervisor)
                .await
                .expect("supervisor must end once the request stream closes")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn backpressure_does_not_poll_the_request_stream_while_the_budget_is_full() {
        let h = Harness::start(Admission::Backpressure);
        h.request();
        wait_until(&h.started, 1).await;
        let polls_with_slot_taken = h.polls();

        // The one slot is taken: the second request must stay in the stream —
        // for Arti, in its effort-ordered queue — not be pulled and dropped.
        h.request();
        tokio::time::sleep(SHORT * 4).await;
        assert_eq!(h.started.load(Ordering::SeqCst), 1);
        assert_eq!(h.dropped.load(Ordering::SeqCst), 0);
        assert_eq!(
            h.polls(),
            polls_with_slot_taken,
            "the request stream was polled while the budget was full"
        );

        // The first circuit ends: its slot goes to the waiting request.
        h.release.notify_one();
        wait_until(&h.started, 2).await;
        assert!(h.polls() > polls_with_slot_taken);
        h.release.notify_one();
        h.finish().await;
    }

    #[tokio::test]
    async fn drop_policy_takes_every_request_and_drops_the_overflow() {
        let h = Harness::start(Admission::Drop);
        h.request();
        wait_until(&h.started, 1).await;

        // The one slot is taken: the second request is pulled out of the
        // stream at once and dropped (rejected), so nothing queues up in Arti's
        // unbounded PoW-off FIFO.
        h.request();
        wait_until(&h.dropped, 1).await;
        assert_eq!(h.started.load(Ordering::SeqCst), 1);

        // Nothing was deferred: freeing the slot starts no second task...
        h.release.notify_one();
        wait_until(&h.dropped, 2).await;
        tokio::time::sleep(SHORT * 4).await;
        assert_eq!(h.started.load(Ordering::SeqCst), 1);
        // ...but a request arriving with the slot free is served.
        h.request();
        wait_until(&h.started, 2).await;
        h.release.notify_one();
        h.finish().await;
    }

    #[test]
    fn admission_follows_the_pow_setting_and_defaults_match_the_constants() {
        assert_eq!(Admission::for_pow(true), Admission::Backpressure);
        assert_eq!(Admission::for_pow(false), Admission::Drop);
        assert_eq!(
            RendezvousLimits::default(),
            RendezvousLimits {
                max_handshakes: MAX_CONCURRENT_HANDSHAKES,
                max_live_circuits: MAX_LIVE_CIRCUITS,
                circuit_idle_timeout: CIRCUIT_IDLE_TIMEOUT,
            }
        );
        let slots = Slots::new(&limits(1, 1));
        let held = slots.try_reserve().unwrap();
        assert_eq!(slots.try_reserve().err(), Some("live rendezvous circuits"));
        drop(held);
        assert!(slots.try_reserve().is_ok());
    }
}
