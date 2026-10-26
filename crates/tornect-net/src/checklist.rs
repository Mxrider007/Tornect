//! The checklist (design `direct` §7.6, §7.7; decisions M1-80, M1-81): which
//! remote addresses this side probes, when, and which ones a round trip
//! validated, without any I/O. The link feeds it the probes the session
//! socket teed and the clock; it answers with the datagrams to send, the
//! address to dial and an early failure.
//!
//! - **Targets** are remote addresses: up to [`MAX_REMOTE_CANDIDATES`] the
//!   peer signalled and up to [`MAX_PRFLX`] peer-reflexive ones learned from
//!   its authenticated requests, so at most [`MAX_TARGETS`], the capacity of
//!   the [`ProbeGate`]. Every one passed the [`RemoteFilter`].
//! - **Pacing.** A new target starts at least [`TA`] after the previous one
//!   and only while fewer than [`MAX_IN_FLIGHT`] are in flight; a target is
//!   in flight until its last scheduled request is sent. Each follows one of
//!   two schedules ([`SAME_SITE_SCHEDULE`], [`INTERNET_SCHEDULE`]) chosen by
//!   its [`Rank`] when it starts; the best-ranked waiting target starts
//!   first.
//! - **Validation.** A target is validated by a round trip of this side's
//!   own: a response carrying the txid of a request still outstanding, from
//!   exactly the address the request went to, taken once. Only then does
//!   its address enter the gate, so the gate set is always the validated
//!   set; nothing else adds to it.
//! - **Answers.** A request is answered only if its tag verifies, its
//!   source passes the remote filter, it reached an offered address (IPv6),
//!   its txid was never answered, and at most [`MAX_RESPONSES_PER_SOURCE`]
//!   responses went to that source and [`MAX_RESPONSES`] in all. A response
//!   has the request's size.
//! - **Peer-reflexive targets.** An answered request from an unknown
//!   source teaches its address, and each answered request from a learned
//!   address draws at most one triggered check, never retransmitted on a
//!   timer.
//! - **Nomination.** The controlling side (the lower device key) nominates
//!   the best-ranked validated address [`nomination_grace`] after the first
//!   validation, once; then it starts no more targets.
//! - **Failure.** [`Action::Failed`] is given once the peer's candidates
//!   are done, this side's gathering is done, and every target failed (at
//!   once when there is none; a learned address counts as failed when no
//!   check to it is outstanding). It is advice for the caller's deadline:
//!   answers, learning, validation and the nomination go on.
//!
//! The budgets that follow (design §7.7) are the security properties of
//! this module, and its proptests check them over arbitrary inputs: at most
//! [`MAX_REQUESTS_PER_TARGET`] requests to any address and
//! [`MAX_RESPONSES_PER_SOURCE`] responses to it, so at most
//! [`MAX_UNVALIDATED_BYTES`] to any address; at most [`MAX_PROBE_BYTES`] in
//! a session; and per authenticated request received, at most one response
//! and one triggered check of the same size, so a spoofer draws at most two
//! bytes per byte it sends. Tag checks are limited to
//! [`TAG_CHECKS_PER_SECOND`].
//!
//! Every method takes the time as a [`std::time::Instant`] the caller reads
//! from tokio's clock (`tokio::time::Instant::now().into_std()`), so tests
//! run on paused time. No address is ever logged: the `Debug` of every type
//! here is redacted and [`PunchStats`] holds counts only.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::TornectRole;
use crate::addr::{
    AddrClass, Candidate, CandidateKind, Count, Redacted, RedactedIp, RemoteFilter, canon,
    canon_ip, class,
};
use crate::probe::{ProbeDrop, ProbeKey, Txid};
use crate::udp::{PROBE_LEN, ProbeGate, V6Sources, is_probe};

/// The pacing interval: the least time between the starts of two targets.
pub const TA: Duration = Duration::from_millis(20);

/// The most targets in flight at once (started, last request not yet sent).
pub const MAX_IN_FLIGHT: usize = 8;

/// The most remote candidates the checklist keeps, across all of the
/// peer's `CANDIDATES` frames.
pub const MAX_REMOTE_CANDIDATES: usize = 16;

/// The most peer-reflexive addresses it learns.
pub const MAX_PRFLX: usize = 4;

/// The most targets: every one can validate, and the gate holds them all.
pub const MAX_TARGETS: usize = ProbeGate::CAPACITY;

const _: () = assert!(MAX_REMOTE_CANDIDATES + MAX_PRFLX == MAX_TARGETS);

/// The most requests sent to one target, scheduled and triggered alike.
pub const MAX_REQUESTS_PER_TARGET: usize = 4;

/// The most responses sent to one source address.
pub const MAX_RESPONSES_PER_SOURCE: usize = 8;

/// The most responses sent in a session.
pub const MAX_RESPONSES: usize = 64;

/// The most tag checks per second; probes beyond are dropped and counted.
pub const TAG_CHECKS_PER_SECOND: u32 = 200;

/// The shortest nomination grace.
pub const GRACE_MIN: Duration = Duration::from_millis(100);

/// The longest nomination grace.
pub const GRACE_MAX: Duration = Duration::from_millis(600);

/// The most probe bytes a side sends in a session: every target's requests
/// and every response.
pub const MAX_PROBE_BYTES: usize =
    (MAX_TARGETS * MAX_REQUESTS_PER_TARGET + MAX_RESPONSES) * PROBE_LEN;

/// The most probe bytes a side sends to any one address.
pub const MAX_UNVALIDATED_BYTES: usize =
    (MAX_REQUESTS_PER_TARGET + MAX_RESPONSES_PER_SOURCE) * PROBE_LEN;

const _: () = assert!(MAX_PROBE_BYTES == 5760 && MAX_UNVALIDATED_BYTES == 480);

/// When a target's requests go out, counted from its start, and when it
/// fails without a round trip. Its txids stay outstanding until it fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// The offsets of its requests.
    pub sends: [Duration; MAX_REQUESTS_PER_TARGET],
    /// The offset at which it fails.
    pub fail: Duration,
}

/// The schedule of a same-site target (and of a private address behind the
/// same NAT): requests at 0, 200, 400 and 800 ms, failure at 1200 ms.
pub const SAME_SITE_SCHEDULE: Schedule = Schedule {
    sends: [
        Duration::from_millis(0),
        Duration::from_millis(200),
        Duration::from_millis(400),
        Duration::from_millis(800),
    ],
    fail: Duration::from_millis(1200),
};

/// The schedule of every other target: requests at 0, 500, 1000 and
/// 2000 ms, failure at 3000 ms.
pub const INTERNET_SCHEDULE: Schedule = Schedule {
    sends: [
        Duration::from_millis(0),
        Duration::from_millis(500),
        Duration::from_millis(1000),
        Duration::from_millis(2000),
    ],
    fail: Duration::from_millis(3000),
};

/// Which side dials the QUIC connection (decision M1-80): the one with the
/// lower device public key controls and nominates; the other accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PunchRole {
    /// Nominates a validated address and dials it.
    Controlling,
    /// Accepts the dial from a validated address.
    Controlled,
}

impl PunchRole {
    /// The role of the side whose device key is `mine`, against `peer`:
    /// the lower key (compared as bytes) controls. `None` for equal keys: a
    /// device never connects directly to itself.
    #[must_use]
    pub fn of(mine: &[u8; 32], peer: &[u8; 32]) -> Option<Self> {
        match mine.cmp(peer) {
            std::cmp::Ordering::Less => Some(Self::Controlling),
            std::cmp::Ordering::Greater => Some(Self::Controlled),
            std::cmp::Ordering::Equal => None,
        }
    }
}

/// How much a target is worth trying (design §7.6), best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rank {
    /// A private address inside one of our on-link IPv4 prefixes, or a ULA
    /// inside our own /48 (unless both sides know public addresses and they
    /// differ: two sites that use the same private range).
    SameSite = 1,
    /// A global IPv6 host candidate (only admitted when we offered one).
    GlobalV6Host = 2,
    /// A public IPv4 host candidate, or a private IPv4 address behind the
    /// same public IPv4 as ours (the same NAT).
    PublicV4Host = 3,
    /// A router mapping.
    Mapped = 4,
    /// A server-reflexive or peer-reflexive address.
    Reflexive = 5,
    /// Any other private address (internet scope only).
    OtherPrivate = 6,
}

/// What the checklist asks of the link.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Send this probe (40 bytes) to `to` with
    /// [`PunchSocket::send_raw`](crate::PunchSocket::send_raw); `src` is the
    /// address a request reached, for its response (IPv6).
    Send {
        /// The destination, in canonical form.
        to: SocketAddr,
        /// The source address, for an IPv6 response.
        src: Option<IpAddr>,
        /// The probe.
        bytes: [u8; PROBE_LEN],
    },
    /// Dial this validated address (the controlling side, once).
    Nominate(SocketAddr),
    /// No target can validate any more (once).
    Failed,
}

impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send { to, src, .. } => f
                .debug_struct("Send")
                .field("to", &Redacted(to))
                .field("src", &src.map(RedactedIp))
                .finish_non_exhaustive(),
            Self::Nominate(to) => f.debug_tuple("Nominate").field(&Redacted(to)).finish(),
            Self::Failed => f.write_str("Failed"),
        }
    }
}

/// The checklist's counters: counts only, never an address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PunchStats {
    /// Requests sent, scheduled and triggered.
    pub requests_sent: u64,
    /// Of those, triggered checks to peer-reflexive addresses.
    pub triggered_sent: u64,
    /// Responses sent.
    pub responses_sent: u64,
    /// Targets a round trip validated.
    pub validated: u64,
    /// Targets whose schedule ended without a round trip.
    pub failed_targets: u64,
    /// Remote candidates the remote filter refused (or of a kind the peer
    /// cannot send).
    pub candidates_refused: u64,
    /// Remote candidates beyond [`MAX_REMOTE_CANDIDATES`].
    pub candidates_dropped: u64,
    /// Remote candidates already listed.
    pub candidates_duplicate: u64,
    /// Teed datagrams that are not probe-shaped.
    pub malformed: u64,
    /// Probes dropped beyond [`TAG_CHECKS_PER_SECOND`].
    pub rate_limited: u64,
    /// Probes whose tag did not verify.
    pub bad_tag: u64,
    /// Probes claiming this side's own role (reflections).
    pub own_role: u64,
    /// Authenticated requests received.
    pub requests_received: u64,
    /// Requests from a source the remote filter refuses (not answered).
    pub sources_refused: u64,
    /// IPv6 requests that reached an address this side did not offer (not
    /// answered).
    pub not_offered: u64,
    /// Requests whose txid was already answered.
    pub replayed: u64,
    /// Requests not answered because a response cap was reached.
    pub responses_capped: u64,
    /// Responses with no outstanding txid from their source.
    pub unexpected_responses: u64,
    /// Peer-reflexive addresses learned.
    pub prflx_learned: u64,
    /// Unknown sources not learned ([`MAX_PRFLX`] reached).
    pub prflx_dropped: u64,
    /// Probes not sent for want of OS randomness.
    pub no_randomness: u64,
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// The nomination grace after a first validated round trip of `rtt`
/// (design §4): `1.5 × rtt`, at least [`GRACE_MIN`], at most [`GRACE_MAX`].
#[must_use]
pub fn nomination_grace(rtt: Duration) -> Duration {
    (rtt * 3 / 2).clamp(GRACE_MIN, GRACE_MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// From the peer's `CANDIDATES`.
    Signalled,
    /// Learned from one of the peer's requests.
    Prflx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Signalled, not started.
    Waiting,
    /// Its schedule runs; `next` is the index of its next request.
    Checking {
        started: Instant,
        schedule: Schedule,
        next: usize,
    },
    /// Learned: checked only in reaction to its requests.
    Learned,
    /// A round trip of ours came back.
    Validated { at: Instant },
    /// Its schedule ended with no round trip.
    Failed,
}

struct Target {
    /// Canonical form.
    addr: SocketAddr,
    kind: CandidateKind,
    origin: Origin,
    phase: Phase,
    /// Requests sent to it, scheduled and triggered.
    requests: usize,
    /// Insertion order: the tie-break between equal ranks.
    seq: usize,
}

impl Target {
    fn in_flight(&self) -> bool {
        matches!(self.phase, Phase::Checking { next, .. } if next < MAX_REQUESTS_PER_TARGET)
    }
}

struct Outstanding {
    txid: Txid,
    /// Canonical form.
    to: SocketAddr,
    sent: Instant,
    expires: Instant,
}

/// The checklist of one direct link (see the module documentation).
pub struct Checklist {
    punch: PunchRole,
    me: TornectRole,
    key: ProbeKey,
    filter: RemoteFilter,
    gate: ProbeGate,
    offered: V6Sources,
    targets: Vec<Target>,
    next_seq: usize,
    remote_count: usize,
    prflx_count: usize,
    outstanding: Vec<Outstanding>,
    answered: Vec<Txid>,
    answered_to: Vec<(SocketAddr, usize)>,
    remote_done: bool,
    local_done: bool,
    local_public: Vec<IpAddr>,
    last_start: Option<Instant>,
    clock: Option<Instant>,
    first_validated: Option<(Instant, Duration)>,
    nominated: Option<SocketAddr>,
    failed: bool,
    heard: bool,
    tokens: u32,
    refilled: Option<Instant>,
    stats: PunchStats,
}

impl Checklist {
    /// The checklist of a link: this side is `me` and plays `punch`;
    /// probes are sealed and checked with `key`; every remote address
    /// passes `filter`; validated addresses go into `gate`, which must be
    /// empty and which nothing else fills; `offered` are the IPv6 addresses
    /// this side offered, the only ones an IPv6 request may reach.
    #[must_use]
    pub fn new(
        punch: PunchRole,
        me: TornectRole,
        key: ProbeKey,
        filter: RemoteFilter,
        gate: ProbeGate,
        offered: V6Sources,
    ) -> Self {
        debug_assert!(
            gate.is_empty(),
            "the gate holds only what this checklist validates"
        );
        Self {
            punch,
            me,
            key,
            filter,
            gate,
            offered,
            targets: Vec::new(),
            next_seq: 0,
            remote_count: 0,
            prflx_count: 0,
            outstanding: Vec::new(),
            answered: Vec::new(),
            answered_to: Vec::new(),
            remote_done: false,
            local_done: false,
            local_public: Vec::new(),
            last_start: None,
            clock: None,
            first_validated: None,
            nominated: None,
            failed: false,
            heard: false,
            tokens: TAG_CHECKS_PER_SECOND,
            refilled: None,
            stats: PunchStats::default(),
        }
    }

    /// Adds a candidate the peer signalled (canonicalised). Refused (and
    /// counted) unless the remote filter admits it; a peer-reflexive kind
    /// is refused too, since a peer never signals one. Beyond
    /// [`MAX_REMOTE_CANDIDATES`] candidates, or for an address already
    /// listed, it is dropped. An address already learned as peer-reflexive
    /// takes the signalled kind and joins the schedule (if not validated).
    /// The caller polls afterwards.
    pub fn add_remote(&mut self, candidate: Candidate) {
        let addr = canon(candidate.addr);
        if candidate.kind == CandidateKind::Prflx || !self.filter.admit(addr) {
            bump(&mut self.stats.candidates_refused);
            return;
        }
        if let Some(i) = self.index(addr) {
            if self.targets[i].origin == Origin::Signalled {
                bump(&mut self.stats.candidates_duplicate);
                return;
            }
            if self.remote_count >= MAX_REMOTE_CANDIDATES {
                bump(&mut self.stats.candidates_dropped);
                return;
            }
            let target = &mut self.targets[i];
            target.origin = Origin::Signalled;
            target.kind = candidate.kind;
            if target.phase == Phase::Learned {
                target.phase = Phase::Waiting;
            }
            self.prflx_count -= 1;
            self.remote_count += 1;
            return;
        }
        if self.remote_count >= MAX_REMOTE_CANDIDATES {
            bump(&mut self.stats.candidates_dropped);
            return;
        }
        self.push(addr, candidate.kind, Origin::Signalled, Phase::Waiting);
        self.remote_count += 1;
    }

    /// The peer said `CANDIDATES_DONE`.
    pub fn remote_done(&mut self) {
        self.remote_done = true;
    }

    /// This side's gathering is done (or was skipped).
    pub fn local_done(&mut self) {
        self.local_done = true;
    }

    /// This side's public IPv4 addresses (a global host candidate, the
    /// server-reflexive and the mapped address), for the ranks of §7.6.
    pub fn set_local_public(&mut self, ips: &[IpAddr]) {
        self.local_public = ips
            .iter()
            .map(|ip| canon_ip(*ip))
            .filter(|ip| ip.is_ipv4() && class(*ip) == AddrClass::Global)
            .collect();
        self.local_public.sort_unstable();
        self.local_public.dedup();
    }

    /// A datagram the session socket's probe tee took: from `from`, having
    /// reached `dst_ip` (as the socket reported it). Returns the response
    /// and the triggered check it draws, if any.
    pub fn on_datagram(
        &mut self,
        from: SocketAddr,
        dst_ip: Option<IpAddr>,
        bytes: &[u8],
        now: Instant,
    ) -> Vec<Action> {
        self.tick(now);
        let from = canon(from);
        if !is_probe(bytes) {
            bump(&mut self.stats.malformed);
            return Vec::new();
        }
        if !self.take_token(now) {
            bump(&mut self.stats.rate_limited);
            return Vec::new();
        }
        let probe = match self.key.decode(self.me, bytes) {
            Ok(probe) => probe,
            Err(ProbeDrop::Shape) => {
                bump(&mut self.stats.malformed);
                return Vec::new();
            }
            Err(ProbeDrop::Tag) => {
                bump(&mut self.stats.bad_tag);
                return Vec::new();
            }
            Err(ProbeDrop::OwnRole) => {
                bump(&mut self.stats.own_role);
                return Vec::new();
            }
        };
        if probe.response {
            self.on_response(from, &probe.txid, now);
            Vec::new()
        } else {
            self.on_request(from, dst_ip, &probe.txid, now)
        }
    }

    /// Runs the timers: failures, retransmissions, the next start, the
    /// nomination and the early failure.
    pub fn poll(&mut self, now: Instant) -> Vec<Action> {
        self.tick(now);
        let mut out = Vec::new();
        self.retransmit(now, &mut out);
        self.start(now, &mut out);
        self.nominate(now, &mut out);
        self.check_failed(&mut out);
        out
    }

    /// When [`poll`](Self::poll) has something to do next, if anything:
    /// the next scheduled request, failure or expiry, the next start, or
    /// the nomination. After [`add_remote`](Self::add_remote) and the
    /// other inputs the caller polls at once.
    #[must_use]
    pub fn next_wakeup(&self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let mut at = |t: Instant| next = Some(next.map_or(t, |n| n.min(t)));
        for target in &self.targets {
            if let Phase::Checking {
                started,
                schedule,
                next: slot,
            } = target.phase
            {
                if slot < MAX_REQUESTS_PER_TARGET {
                    at(started + schedule.sends[slot]);
                }
                at(started + schedule.fail);
            }
        }
        for o in &self.outstanding {
            at(o.expires);
        }
        if self.can_start() {
            match self.last_start {
                Some(last) => at(last + TA),
                None => {
                    if let Some(clock) = self.clock {
                        at(clock);
                    }
                }
            }
        }
        if let Some(deadline) = self.nomination_deadline() {
            at(deadline);
        }
        next
    }

    /// This side's role in the punch.
    #[must_use]
    pub fn punch_role(&self) -> PunchRole {
        self.punch
    }

    /// The validated addresses, in canonical form, in the order they
    /// validated.
    #[must_use]
    pub fn validated(&self) -> Vec<SocketAddr> {
        let mut out: Vec<(Instant, usize, SocketAddr)> = self
            .targets
            .iter()
            .filter_map(|t| match t.phase {
                Phase::Validated { at } => Some((at, t.seq, t.addr)),
                _ => None,
            })
            .collect();
        out.sort_unstable_by_key(|(at, seq, _)| (*at, *seq));
        out.into_iter().map(|(_, _, addr)| addr).collect()
    }

    /// Whether a round trip of ours validated `addr` (either family form).
    #[must_use]
    pub fn is_validated(&self, addr: SocketAddr) -> bool {
        self.index(canon(addr))
            .is_some_and(|i| matches!(self.targets[i].phase, Phase::Validated { .. }))
    }

    /// Whether an authenticated request from the peer arrived (the viewer's
    /// "the other computer's firewall may be blocking" hint).
    #[must_use]
    pub fn heard_from_peer(&self) -> bool {
        self.heard
    }

    /// The address the controlling side nominated.
    #[must_use]
    pub fn nominated(&self) -> Option<SocketAddr> {
        self.nominated
    }

    /// The kind of the nominated target (`PATH host …`). A peer-reflexive
    /// address the peer later signalled reads as the signalled kind.
    #[must_use]
    pub fn winner_kind(&self) -> Option<CandidateKind> {
        self.nominated.and_then(|addr| self.kind_of(addr))
    }

    /// The kind of the target at `addr`, if it is one.
    #[must_use]
    pub fn kind_of(&self, addr: SocketAddr) -> Option<CandidateKind> {
        self.index(canon(addr)).map(|i| self.targets[i].kind)
    }

    /// Whether `addr` is on this side's site (the route label of design
    /// §3.1): rank [`Rank::SameSite`], or a private address behind the same
    /// public IPv4 as ours. Never inferred from the class alone.
    #[must_use]
    pub fn same_site(&self, addr: SocketAddr) -> bool {
        let addr = canon(addr);
        let kind = self
            .index(addr)
            .map_or(CandidateKind::Host, |i| self.targets[i].kind);
        self.place(addr, kind).1
    }

    /// The rank of `addr` as a target of `kind` (design §7.6).
    #[must_use]
    pub fn rank(&self, addr: SocketAddr, kind: CandidateKind) -> Rank {
        self.place(canon(addr), kind).0
    }

    /// The counters.
    #[must_use]
    pub fn stats(&self) -> PunchStats {
        self.stats
    }

    fn index(&self, addr: SocketAddr) -> Option<usize> {
        self.targets.iter().position(|t| t.addr == addr)
    }

    fn push(&mut self, addr: SocketAddr, kind: CandidateKind, origin: Origin, phase: Phase) {
        self.targets.push(Target {
            addr,
            kind,
            origin,
            phase,
            requests: 0,
            seq: self.next_seq,
        });
        self.next_seq += 1;
    }

    /// Keeps the latest time seen, ends the schedules whose failure time
    /// passed and drops the txids that expired.
    fn tick(&mut self, now: Instant) {
        self.clock = Some(self.clock.map_or(now, |c| c.max(now)));
        for target in &mut self.targets {
            if let Phase::Checking {
                started, schedule, ..
            } = target.phase
                && now >= started + schedule.fail
            {
                target.phase = Phase::Failed;
                bump(&mut self.stats.failed_targets);
            }
        }
        self.outstanding.retain(|o| o.expires > now);
    }

    /// The rank of `addr` (canonical) as a target of `kind`, and whether it
    /// is on this side's site.
    fn place(&self, addr: SocketAddr, kind: CandidateKind) -> (Rank, bool) {
        let ip = addr.ip();
        if self.filter.on_site(ip) {
            return if self.publics_differ() {
                (Rank::OtherPrivate, false)
            } else {
                (Rank::SameSite, true)
            };
        }
        match (class(ip), ip, kind) {
            (AddrClass::Global, IpAddr::V6(_), CandidateKind::Host) => (Rank::GlobalV6Host, false),
            (AddrClass::Global, IpAddr::V4(_), CandidateKind::Host) => (Rank::PublicV4Host, false),
            (AddrClass::Private, IpAddr::V4(_), _) if self.same_nat() => (Rank::PublicV4Host, true),
            (_, _, CandidateKind::Mapped) => (Rank::Mapped, false),
            (_, _, CandidateKind::Srflx | CandidateKind::Prflx) => (Rank::Reflexive, false),
            (_, _, CandidateKind::Host) => (Rank::OtherPrivate, false),
        }
    }

    /// The peer's public IPv4 addresses, from its signalled candidates.
    fn remote_public(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.targets.iter().filter_map(|t| {
            let ip = t.addr.ip();
            let public = ip.is_ipv4()
                && class(ip) == AddrClass::Global
                && t.origin == Origin::Signalled
                && matches!(
                    t.kind,
                    CandidateKind::Host | CandidateKind::Srflx | CandidateKind::Mapped
                );
            public.then_some(ip)
        })
    }

    fn same_nat(&self) -> bool {
        !self.local_public.is_empty()
            && self
                .remote_public()
                .any(|ip| self.local_public.contains(&ip))
    }

    fn publics_differ(&self) -> bool {
        !self.local_public.is_empty()
            && self.remote_public().next().is_some()
            && !self
                .remote_public()
                .any(|ip| self.local_public.contains(&ip))
    }

    fn schedule_for(&self, addr: SocketAddr, kind: CandidateKind) -> Schedule {
        if self.place(addr, kind).1 {
            SAME_SITE_SCHEDULE
        } else {
            INTERNET_SCHEDULE
        }
    }

    fn can_start(&self) -> bool {
        self.nominated.is_none()
            && self.targets.iter().filter(|t| t.in_flight()).count() < MAX_IN_FLIGHT
            && self.targets.iter().any(|t| t.phase == Phase::Waiting)
    }

    fn nomination_deadline(&self) -> Option<Instant> {
        if self.punch != PunchRole::Controlling || self.nominated.is_some() {
            return None;
        }
        self.first_validated
            .map(|(at, rtt)| at + nomination_grace(rtt))
    }

    /// Sends a request to target `i`, outstanding until `expires`; nothing
    /// once it had [`MAX_REQUESTS_PER_TARGET`].
    fn request(
        &mut self,
        i: usize,
        now: Instant,
        expires: Instant,
        triggered: bool,
        out: &mut Vec<Action>,
    ) {
        if self.targets[i].requests >= MAX_REQUESTS_PER_TARGET {
            return;
        }
        let Some((txid, bytes)) = self.key.request(self.me) else {
            bump(&mut self.stats.no_randomness);
            return;
        };
        let to = self.targets[i].addr;
        self.targets[i].requests += 1;
        self.outstanding.push(Outstanding {
            txid,
            to,
            sent: now,
            expires,
        });
        bump(&mut self.stats.requests_sent);
        if triggered {
            bump(&mut self.stats.triggered_sent);
        }
        out.push(Action::Send {
            to,
            src: None,
            bytes,
        });
    }

    /// The scheduled requests that are due. A late poll sends one request
    /// for all the slots it missed, not one for each: the schedule's later
    /// slots keep their times.
    fn retransmit(&mut self, now: Instant, out: &mut Vec<Action>) {
        for i in 0..self.targets.len() {
            let Phase::Checking {
                started,
                schedule,
                next,
            } = self.targets[i].phase
            else {
                continue;
            };
            if next >= MAX_REQUESTS_PER_TARGET || now < started + schedule.sends[next] {
                continue;
            }
            let mut last = next;
            while last + 1 < MAX_REQUESTS_PER_TARGET && now >= started + schedule.sends[last + 1] {
                last += 1;
            }
            self.targets[i].phase = Phase::Checking {
                started,
                schedule,
                next: last + 1,
            };
            self.request(i, now, started + schedule.fail, false, out);
        }
    }

    /// Starts the best-ranked waiting target, if pacing and the in-flight
    /// cap allow.
    fn start(&mut self, now: Instant, out: &mut Vec<Action>) {
        if !self.can_start() || self.last_start.is_some_and(|last| now < last + TA) {
            return;
        }
        let Some(i) = self
            .targets
            .iter()
            .enumerate()
            .filter(|(_, t)| t.phase == Phase::Waiting)
            .min_by_key(|(_, t)| (self.place(t.addr, t.kind).0, t.seq))
            .map(|(i, _)| i)
        else {
            return;
        };
        let (addr, kind) = (self.targets[i].addr, self.targets[i].kind);
        let schedule = self.schedule_for(addr, kind);
        self.targets[i].phase = Phase::Checking {
            started: now,
            schedule,
            next: 1,
        };
        self.last_start = Some(now);
        self.request(i, now, now + schedule.fail, false, out);
    }

    fn nominate(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self
            .nomination_deadline()
            .is_none_or(|deadline| now < deadline)
        {
            return;
        }
        let best = self
            .targets
            .iter()
            .filter_map(|t| match t.phase {
                Phase::Validated { at } => Some((self.place(t.addr, t.kind).0, at, t.seq, t.addr)),
                _ => None,
            })
            .min();
        if let Some((_, _, _, addr)) = best {
            self.nominated = Some(addr);
            out.push(Action::Nominate(addr));
        }
    }

    fn check_failed(&mut self, out: &mut Vec<Action>) {
        if self.failed || !self.remote_done || !self.local_done {
            return;
        }
        let settled = self.targets.iter().all(|t| match t.phase {
            Phase::Failed => true,
            Phase::Learned => !self.outstanding.iter().any(|o| o.to == t.addr),
            Phase::Waiting | Phase::Checking { .. } | Phase::Validated { .. } => false,
        });
        if settled {
            self.failed = true;
            out.push(Action::Failed);
        }
    }

    /// One token per tag check, [`TAG_CHECKS_PER_SECOND`] a second, at most
    /// that many saved.
    fn take_token(&mut self, now: Instant) -> bool {
        let refill = Duration::from_secs(1) / TAG_CHECKS_PER_SECOND;
        match self.refilled {
            None => self.refilled = Some(now),
            Some(at) if now > at => {
                let gained = (now - at).as_micros() / refill.as_micros();
                if gained >= u128::from(TAG_CHECKS_PER_SECOND) {
                    self.tokens = TAG_CHECKS_PER_SECOND;
                    self.refilled = Some(now);
                } else if gained > 0 {
                    let gained = u32::try_from(gained).unwrap_or(TAG_CHECKS_PER_SECOND);
                    self.tokens = (self.tokens + gained).min(TAG_CHECKS_PER_SECOND);
                    self.refilled = Some(at + refill * gained);
                }
            }
            Some(_) => {}
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// A response: it validates its target only if its txid is outstanding
    /// and went to exactly `from`; the txid is taken once.
    fn on_response(&mut self, from: SocketAddr, txid: &Txid, now: Instant) {
        let Some(k) = self
            .outstanding
            .iter()
            .position(|o| &o.txid == txid && o.to == from)
        else {
            bump(&mut self.stats.unexpected_responses);
            return;
        };
        let sent = self.outstanding.swap_remove(k).sent;
        let Some(i) = self.index(from) else {
            bump(&mut self.stats.unexpected_responses);
            return;
        };
        self.outstanding.retain(|o| o.to != from);
        self.targets[i].phase = Phase::Validated { at: now };
        // Cannot fail: the gate holds MAX_TARGETS addresses, only this
        // checklist adds to it, and only one per target.
        let admitted = self.gate.admit(from);
        debug_assert!(admitted, "the gate holds every target");
        bump(&mut self.stats.validated);
        if self.first_validated.is_none() {
            self.first_validated = Some((now, now - sent));
        }
    }

    /// The source of the response to a request from `from` that reached
    /// `dst_ip`: none for IPv4 (the kernel's); for IPv6 the address it
    /// reached, which must be one this side offered (or loopback, only where
    /// the filter admits loopback: test environments). `None` when it may
    /// not be answered.
    fn response_source(&self, from: SocketAddr, dst_ip: Option<IpAddr>) -> Option<Option<IpAddr>> {
        if from.is_ipv4() {
            return Some(None);
        }
        match dst_ip.map(canon_ip) {
            Some(IpAddr::V6(ip))
                if self.offered.offers(ip) || (ip.is_loopback() && self.filter.admit_loopback) =>
            {
                Some(Some(IpAddr::V6(ip)))
            }
            _ => None,
        }
    }

    /// An authenticated request: answered under the rules of the module
    /// documentation; an answered request from an unknown source teaches
    /// it, and one from a learned source draws a triggered check.
    fn on_request(
        &mut self,
        from: SocketAddr,
        dst_ip: Option<IpAddr>,
        txid: &Txid,
        now: Instant,
    ) -> Vec<Action> {
        self.heard = true;
        bump(&mut self.stats.requests_received);
        if !self.filter.admit(from) {
            bump(&mut self.stats.sources_refused);
            return Vec::new();
        }
        let Some(src) = self.response_source(from, dst_ip) else {
            bump(&mut self.stats.not_offered);
            return Vec::new();
        };
        if self.answered.contains(txid) {
            bump(&mut self.stats.replayed);
            return Vec::new();
        }
        let to_source = self.answered_to.iter().position(|(addr, _)| *addr == from);
        let sent_to_source = to_source.map_or(0, |k| self.answered_to[k].1);
        if self.answered.len() >= MAX_RESPONSES || sent_to_source >= MAX_RESPONSES_PER_SOURCE {
            bump(&mut self.stats.responses_capped);
            return Vec::new();
        }
        let Some(bytes) = self.key.response(self.me, txid) else {
            bump(&mut self.stats.no_randomness);
            return Vec::new();
        };
        self.answered.push(*txid);
        match to_source {
            Some(k) => self.answered_to[k].1 += 1,
            None => self.answered_to.push((from, 1)),
        }
        bump(&mut self.stats.responses_sent);
        let mut out = vec![Action::Send {
            to: from,
            src,
            bytes,
        }];
        self.learn_and_trigger(from, now, &mut out);
        out
    }

    /// Learns `from` (admitted) if it is unknown and there is room, and
    /// sends one triggered check to it if it is a learned address that has
    /// not validated.
    fn learn_and_trigger(&mut self, from: SocketAddr, now: Instant, out: &mut Vec<Action>) {
        let i = match self.index(from) {
            Some(i) => i,
            None if self.prflx_count < MAX_PRFLX && self.targets.len() < MAX_TARGETS => {
                self.push(from, CandidateKind::Prflx, Origin::Prflx, Phase::Learned);
                self.prflx_count += 1;
                bump(&mut self.stats.prflx_learned);
                self.targets.len() - 1
            }
            None => {
                bump(&mut self.stats.prflx_dropped);
                return;
            }
        };
        if self.targets[i].phase != Phase::Learned {
            return;
        }
        let schedule = self.schedule_for(from, CandidateKind::Prflx);
        self.request(i, now, now + schedule.fail, true, out);
    }
}

impl fmt::Debug for Checklist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Checklist")
            .field("punch", &self.punch)
            .field("me", &self.me)
            .field("targets", &Count(self.targets.len(), "targets"))
            .field("validated", &Count(self.validated().len(), "addresses"))
            .field("nominated", &self.nominated.is_some())
            .field("failed", &self.failed)
            .field("heard", &self.heard)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
