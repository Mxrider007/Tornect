//! Gathering the candidates beyond this computer's own addresses (design
//! `direct` §7.3–§7.5, §5.3; decisions M1-81, M1-83, M1-86): the plan of a
//! session's gathering, the task that runs it beside the link, the STUN
//! client that learns the server-reflexive candidate, and [`StunDns`], the
//! cache of the STUN servers' addresses it reads.
//!
//! - **The plan** ([`plan`]): nothing beyond the host candidates in
//!   same-site scope. In internet scope, the router is asked for one port
//!   ([`MapTarget`]) when a protocol is on, outside VPN mode, without a
//!   global IPv4 host candidate, from a private or shared (carrier-grade
//!   NAT) IPv4 route source toward that interface's gateway; a STUN server
//!   when `enable_stun` is on, this side's part of the list is not empty
//!   and [`stun_base`] allows it. With both, STUN waits for the router,
//!   [`MAPPING_HEAD_START`] at most: a mapping with a global address by
//!   then skips it, and a router that answered without one starts it at
//!   once.
//! - **The task** (started by [`DirectLink::start`](crate::DirectLink)
//!   when the plan asks anything): the mapped candidate as it lands, then
//!   the server-reflexive one, each its own batch and only when it is new,
//!   then `Done` once both finished or were skipped, or at
//!   [`GATHER_BUDGET`] from the bind. It then holds the mapping and renews
//!   it ([`Mapping::keep_renewed`]) until the link closes, which drops it
//!   and so releases it on the link's runtime.
//!
//! The app starts the names' refresh when the internet direct path is on
//! (steps B11, B12); until then only tests ask a server.
//!
//! - **Who is asked** (§5.3, decision M1-81): the servers of this side's
//!   part of the list ([`stun::partition`]), one at a time. The first,
//!   chosen at random, at once; a second (of another operator where the
//!   part has one) only when the first gave nothing acceptable by
//!   [`STUN_SECOND`] after it was asked; never more than [`STUN_SERVERS_PER_SESSION`] servers or
//!   [`STUN_REQUESTS_PER_SESSION`] requests, and nothing at or after the
//!   deadline. Each server gets one retransmission, [`STUN_RTO`] after its
//!   first request (RFC 8489 §6.2.1's floor).
//! - **Where to** (§5.3): an address [`StunFilter`] admits: global IPv4,
//!   none of this computer's, any port but 0. A DNS answer can therefore
//!   never aim a request at the LAN, and an IP literal in the list is
//!   checked the same way. In VPN mode ([`StunAsk::tunnel`]), only a server
//!   whose own route leaves from the tunnel's address: a split tunnel that
//!   excludes a server's prefix would send the request, and show this
//!   computer's physical public address, outside the tunnel (§7.2, §9.3).
//! - **What is sent**: the 20-byte Binding request
//!   ([`stun::binding_request`]) from the session socket, with a fresh
//!   random transaction ID per server, which its retransmission reuses.
//! - **What is taken** (§7.3): a reply the socket teed, only from the exact
//!   address asked, only under that server's transaction ID, and once:
//!   whatever the server answers ends it. The mapped address must be global
//!   IPv4 with a port (loopback too in test environments); one equal to a
//!   host candidate means there is no NAT, and no srflx candidate.
//! - **DNS** (§5.3): names are resolved in the background, at start and
//!   every [`DNS_REFRESH`] ± [`DNS_JITTER`] ([`StunDns::run`]); a session
//!   reads them through [`NetEnv::resolve`], which on the real machine
//!   answers from the cache. Once a refresh round has completed
//!   ([`StunDns::refreshed`]) a name the cache lacks is an error at once,
//!   so the resolver never learns when a session starts; only a cold cache
//!   (no round completed yet, as for the one-shot `connect`) is looked up
//!   at session time, and the session waits [`DNS_TIMEOUT`] at most.
//! - **Logs**: none here; the report is counts and a redacted candidate
//!   (decision M1-83).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{Instant, Timeout};

use crate::BoxFuture;
use crate::addr::{
    AddrClass, Candidate, CandidateKind, RedactedIp, Scope, StunFilter, canon, canon_ip, class,
    class_v4,
};
use crate::env::NetEnv;
use crate::link::LocalBatch;
use crate::local::{IfaceAddr, RouteSources, global_families, owner};
use crate::mapping::{MAP_LEASE, MapFail, MapProtocols, MapRequest, MapVia, Mapping};
use crate::stun::{self, StunReply, StunTxid, TXID_LEN, binding_request, parse_response};
use crate::udp::{PunchSocket, RawSend, TeedStun};

/// How long a side gathers, from its bind (design §4 "Gathering"): the STUN
/// client's deadline is at most this after the bind.
pub const GATHER_BUDGET: Duration = Duration::from_millis(1500);

/// The retransmission timeout of a STUN request (RFC 8489 §6.2.1's floor,
/// design §4): each server is asked again once, this long after its first
/// request.
pub const STUN_RTO: Duration = Duration::from_millis(500);

/// How long after the first server was asked a second one is (design §5.3,
/// §7.3), when the first gave nothing acceptable by then.
pub const STUN_SECOND: Duration = Duration::from_millis(750);

/// The most STUN servers one side asks in one session (design §7.3).
pub const STUN_SERVERS_PER_SESSION: usize = 2;

/// The requests each server gets: the first and one retransmission.
const SENDS_PER_SERVER: u8 = 2;

/// The most STUN requests one side sends in one session (design §7.3).
pub const STUN_REQUESTS_PER_SESSION: usize = STUN_SERVERS_PER_SESSION * SENDS_PER_SERVER as usize;

/// The longest a session waits for a STUN server's name, which it looks up
/// only while the cache is cold (design §4: "used only when the cache is
/// empty"; §7.3).
pub const DNS_TIMEOUT: Duration = Duration::from_millis(500);

/// The background refresh of the STUN servers' names (design §4, §5.3):
/// every 10 minutes, give or take [`DNS_JITTER`].
pub const DNS_REFRESH: Duration = Duration::from_secs(600);

/// The jitter of [`DNS_REFRESH`], drawn uniformly each round.
pub const DNS_JITTER: Duration = Duration::from_secs(60);

/// The longest the background refresh, or a cold cache's lookup, waits for
/// one name: no session waits on it, but a resolver that never answers
/// must not stop the refresh or hold a task forever.
pub const PREFETCH_TIMEOUT: Duration = Duration::from_secs(5);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The host and port of a `stun_servers` entry (`host:port`, an IPv6
/// literal in brackets); `None` without a port, or with port 0.
#[must_use]
pub fn server_name(entry: &str) -> Option<(&str, u16)> {
    let (host, port) = entry.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    (!host.is_empty()).then_some((host, port))
}

/// A name lookup the background refresh (and a cold cache) makes: the
/// system resolver for [`RealNet`](crate::RealNet), a table in tests.
pub type Resolver =
    Arc<dyn Fn(&str, u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> + Send + Sync>;

type Key = (String, u16);

fn key(host: &str, port: u16) -> Key {
    (host.trim_end_matches('.').to_ascii_lowercase(), port)
}

/// The addresses of the STUN servers' names (design §5.3, §8.3 `StunDns`),
/// filled by the background refresh so that a session never waits on DNS
/// and the resolver never sees a lookup at session time: once a round has
/// completed ([`StunDns::refreshed`]), a session reads this cache only.
/// Clones share the cache. Its `Debug` prints the number of names and
/// whether a round has completed, never a name or an address.
#[derive(Clone, Default)]
pub struct StunDns {
    cache: Arc<Mutex<Cache>>,
}

#[derive(Default)]
struct Cache {
    names: HashMap<Key, Vec<SocketAddr>>,
    /// A refresh round has completed since the cache was made or last
    /// cleared.
    refreshed: bool,
}

impl StunDns {
    /// An empty, cold cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The cached addresses of `host` (any case, with or without its final
    /// dot) at `port`.
    #[must_use]
    pub fn get(&self, host: &str, port: u16) -> Option<Vec<SocketAddr>> {
        lock(&self.cache).names.get(&key(host, port)).cloned()
    }

    /// Caches `addrs` as `host`'s at `port`; an empty answer changes nothing.
    pub fn put(&self, host: &str, port: u16, addrs: Vec<SocketAddr>) {
        if !addrs.is_empty() {
            lock(&self.cache).names.insert(key(host, port), addrs);
        }
    }

    /// How many names are cached.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.cache).names.len()
    }

    /// Whether no name is cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether a refresh round has completed since the cache was made or
    /// last [cleared](Self::clear) (design §5.3). From then on a session
    /// never triggers a lookup: a name the cache lacks (it failed in the
    /// round, or was listed after it) waits for the next round. Before,
    /// the cache is cold, and a session may look a name up (the one-shot
    /// `connect`, whose session can start before the first round ends).
    #[must_use]
    pub fn refreshed(&self) -> bool {
        lock(&self.cache).refreshed
    }

    /// Forgets every name, and that a round completed: the cache is cold
    /// again, as when it was made.
    pub fn clear(&self) {
        let mut cache = lock(&self.cache);
        cache.names.clear();
        cache.refreshed = false;
    }

    /// One refresh round over `entries` (`host:port`): each name is looked
    /// up with `lookup`, one after the other, waiting [`PREFETCH_TIMEOUT`]
    /// at most; an answer replaces the cached addresses, a failure keeps
    /// them (a resolver that is down for a moment does not empty the cache).
    /// Names no longer listed are forgotten. IP literals and entries without
    /// a valid port are not looked up. Once the round is over the cache is
    /// [refreshed](Self::refreshed), whatever answered. Returns how many
    /// names answered.
    pub async fn refresh(&self, entries: &[String], lookup: &Resolver) -> usize {
        let mut listed = Vec::new();
        let mut answered = 0;
        for entry in entries {
            let Some((host, port)) = server_name(entry) else {
                continue;
            };
            if host.parse::<IpAddr>().is_ok() {
                continue;
            }
            listed.push(key(host, port));
            let found = tokio::time::timeout(PREFETCH_TIMEOUT, lookup(host, port)).await;
            if let Ok(Ok(addrs)) = found
                && !addrs.is_empty()
            {
                self.put(host, port, addrs);
                answered += 1;
            }
        }
        let mut cache = lock(&self.cache);
        cache.names.retain(|k, _| listed.contains(k));
        cache.refreshed = true;
        answered
    }

    /// The background refresh (design §5.3): a round over `entries()` at
    /// once, then one every [`refresh_delay`]. `entries` is read at each
    /// round, so it can follow the settings: an empty list (STUN off, the
    /// internet direct path off, a bridge in use) asks nothing and
    /// [clears](Self::clear) the cache, which is then cold until the next
    /// round with a list. Runs until its task is aborted.
    pub async fn run(self, entries: impl Fn() -> Vec<String> + Send + Sync, lookup: Resolver) {
        loop {
            let list = entries();
            if list.is_empty() {
                self.clear();
            } else {
                self.refresh(&list, &lookup).await;
            }
            tokio::time::sleep(refresh_delay(random_u64())).await;
        }
    }
}

impl fmt::Debug for StunDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cache = lock(&self.cache);
        f.debug_struct("StunDns")
            .field("names", &cache.names.len())
            .field("refreshed", &cache.refreshed)
            .finish()
    }
}

/// The wait before the next refresh round for a random `draw`:
/// [`DNS_REFRESH`] − [`DNS_JITTER`] to [`DNS_REFRESH`] + [`DNS_JITTER`],
/// to the millisecond, so that the lookups of a computer do not mark a
/// fixed beat.
#[must_use]
pub fn refresh_delay(draw: u64) -> Duration {
    let span = u64::try_from(DNS_JITTER.as_millis() * 2).unwrap_or(u64::MAX);
    DNS_REFRESH - DNS_JITTER + Duration::from_millis(draw % (span + 1))
}

/// A draw from the OS's random source; 0 when it fails (the round is then
/// [`DNS_REFRESH`] − [`DNS_JITTER`] away).
fn random_u64() -> u64 {
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes).map_or(0, |()| u64::from_le_bytes(bytes))
}

/// The IPv4 address this side's STUN requests leave from, when this
/// computer may ask a STUN server at all (design §7.3 "When it runs", the
/// parts that are the machine's):
///
/// - the IPv4 route source is private, shared (carrier-grade NAT,
///   `100.64/10`: a valid base whose srflx is the carrier's public address)
///   or global; loopback too where `admit_loopback` (test environments);
/// - in VPN mode, the IPv4 route leaves through the tunnel
///   ([`global_families`]), so no request leaves the physical interface;
/// - no host candidate is a global IPv4 address: such a computer is
///   reachable at it, and a server would only repeat it.
///
/// The rest of the rule (internet scope, `enable_stun`, a non-empty part of
/// the list, no global router mapping by the head start) is the gathering
/// [`plan`]'s and its task's, which in VPN mode also pass this address as
/// [`StunAsk::tunnel`], so that each server's own route is checked too.
#[must_use]
pub fn stun_base(
    addrs: &[IfaceAddr],
    sources: &RouteSources,
    vpn: bool,
    hosts: &[SocketAddr],
    admit_loopback: bool,
) -> Option<Ipv4Addr> {
    let base = sources.v4?;
    let usable = match class_v4(base) {
        AddrClass::Private | AddrClass::SharedCgnat | AddrClass::Global => true,
        AddrClass::Loopback => admit_loopback,
        _ => false,
    };
    (usable && !public_v4_host(hosts) && (!vpn || global_families(addrs, sources, vpn).0))
        .then_some(base)
}

/// Whether one of `hosts` is a global IPv4 address: such a computer is
/// reachable at it, and needs neither a STUN server nor the router.
fn public_v4_host(hosts: &[SocketAddr]) -> bool {
    hosts.iter().any(|h| {
        let h = canon(*h);
        h.is_ipv4() && class(h.ip()) == AddrClass::Global
    })
}

/// A draw from the OS's random source for [`StunAsk::draw`]; 0 when it
/// fails.
#[must_use]
pub fn draw() -> u64 {
    random_u64()
}

/// The order a side asks the servers of its part in: the entry `draw`
/// picks (decision M1-81: the first server is chosen at random), then the
/// first entry of each other operator in list order, then the rest. A
/// second server of another operator is likelier to answer when the first
/// operator is down.
fn ask_order(servers: &[String], draw: u64) -> Vec<&str> {
    if servers.is_empty() {
        return Vec::new();
    }
    let len = u64::try_from(servers.len()).unwrap_or(u64::MAX);
    let first = &servers[usize::try_from(draw % len).unwrap_or(0)];
    let mut order = vec![first.as_str()];
    let mut seen = vec![stun::operator(first)];
    for entry in servers {
        let op = stun::operator(entry);
        if !seen.contains(&op) {
            order.push(entry.as_str());
            seen.push(op);
        }
    }
    for entry in servers {
        if !order.contains(&entry.as_str()) {
            order.push(entry.as_str());
        }
    }
    order
}

/// What the STUN client is asked to do.
pub struct StunAsk<'a> {
    /// This side's part of the list ([`stun::partition`]), `host:port`.
    pub servers: &'a [String],
    /// The servers' addresses must pass it ([`crate::local::stun_filter`]);
    /// its `admit_loopback` also admits a loopback mapped address.
    pub filter: &'a StunFilter,
    /// This side's host candidates: a mapped address equal to one means
    /// there is no NAT.
    pub hosts: &'a [SocketAddr],
    /// When the client stops, on tokio's clock
    /// (`tokio::time::Instant::now().into_std()`): at most
    /// [`GATHER_BUDGET`] after the bind.
    pub deadline: std::time::Instant,
    /// Picks the first server: entry `draw % servers.len()` of the part.
    /// The gathering passes [`draw()`], a random one; tests pass 0 (the
    /// first entry).
    pub draw: u64,
    /// In VPN mode, the tunnel's IPv4 route source ([`stun_base`]'s
    /// answer); `None` otherwise. A server is then asked only when the
    /// route toward it ([`NetEnv::route_source_to`]) leaves from this
    /// address too: a split tunnel whose default route is the tunnel may
    /// still exclude the server's prefix, and a request over the physical
    /// interface would show the server, and the peer through the srflx it
    /// returns, this computer's physical public address (design §7.2,
    /// §9.3). Such a server counts as unresolved.
    pub tunnel: Option<Ipv4Addr>,
}

impl fmt::Debug for StunAsk<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StunAsk")
            .field("servers", &self.servers.len())
            .field("filter", self.filter)
            .field("hosts", &self.hosts.len())
            .field("tunnel", &self.tunnel.is_some())
            .finish_non_exhaustive()
    }
}

/// What the STUN client learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunOutcome {
    /// A server saw this side at a global address that is none of its host
    /// candidates: the server-reflexive candidate (printed redacted).
    Srflx(Candidate),
    /// A server saw this side at one of its host candidates: there is no
    /// NAT, and no second server is asked.
    NoNat,
    /// No server gave an acceptable answer by the deadline.
    Nothing,
}

/// The STUN client's counts (design §5.5: counts only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StunStats {
    /// Servers asked.
    pub servers: u8,
    /// Requests handed to the OS.
    pub requests: u8,
    /// Requests the socket did not take ([`RawSend`] other than `Sent`).
    pub unsent: u8,
    /// [`NetEnv::resolve`] calls (an IP literal needs none).
    pub resolves: u8,
    /// Entries that gave no address the filter admits (a malformed entry, a
    /// name the refreshed cache lacks, a failed or slow lookup, or only
    /// refused addresses).
    pub unresolved: u8,
    /// Error responses.
    pub errors: u8,
    /// Success responses whose mapped address was refused (not global
    /// IPv4, or port 0).
    pub refused: u8,
    /// Teed datagrams that answered nothing asked: another source, another
    /// transaction ID, malformed, or after their server's answer.
    pub ignored: u16,
}

/// The outcome and the counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunReport {
    /// What the client learned.
    pub outcome: StunOutcome,
    /// Its counts.
    pub stats: StunStats,
}

/// A server asked in this session.
struct Asked {
    /// Its address (canonical), as the filter admitted it.
    addr: SocketAddr,
    txid: StunTxid,
    /// When its first request was due.
    at: Instant,
    /// Requests sent (or tried).
    sent: u8,
    /// It answered (anything) and is not listened to any more.
    over: bool,
}

struct Client<'a> {
    ask: &'a StunAsk<'a>,
    asked: Vec<Asked>,
    outcome: Option<StunOutcome>,
    stats: StunStats,
}

impl Client<'_> {
    /// Takes the first address of `addrs` the filter admits (and, in VPN
    /// mode, that `env` routes through the tunnel) as the next server,
    /// asked from `now`; without one, the next entry is tried at once.
    fn take(
        &mut self,
        env: &dyn NetEnv,
        addrs: &[SocketAddr],
        now: Instant,
        next: &mut Option<Instant>,
    ) {
        let tunnel = self.ask.tunnel;
        let found = addrs.iter().map(|a| canon(*a)).find(|a| {
            self.ask.filter.admit(*a)
                && !self.asked.iter().any(|s| s.addr == *a)
                && tunnel.is_none_or(|t| env.route_source_to(*a) == Some(IpAddr::V4(t)))
        });
        let Some(addr) = found else {
            self.stats.unresolved = self.stats.unresolved.saturating_add(1);
            *next = Some(now);
            return;
        };
        let mut txid = [0; TXID_LEN];
        if getrandom::fill(&mut txid).is_err() {
            // No transaction ID nobody can guess: ask nobody.
            *next = None;
            return;
        }
        self.asked.push(Asked {
            addr,
            txid,
            at: now,
            sent: 0,
            over: false,
        });
        self.stats.servers = self.stats.servers.saturating_add(1);
        *next =
            (self.asked.len() < STUN_SERVERS_PER_SESSION).then(|| self.asked[0].at + STUN_SECOND);
    }

    /// Sends every request due by `now` and before `deadline`.
    fn send_due(&mut self, socket: &PunchSocket, now: Instant, deadline: Instant) {
        for server in &mut self.asked {
            if server.over || server.sent >= SENDS_PER_SERVER {
                continue;
            }
            let due = server.at + STUN_RTO * u32::from(server.sent);
            if due > now || due >= deadline {
                continue;
            }
            server.sent += 1;
            match socket.send_raw(server.addr, &binding_request(&server.txid), None) {
                RawSend::Sent => self.stats.requests = self.stats.requests.saturating_add(1),
                _ => self.stats.unsent = self.stats.unsent.saturating_add(1),
            }
        }
    }

    /// When the next request is due, if before `deadline`.
    fn next_send(&self, deadline: Instant) -> Option<Instant> {
        self.asked
            .iter()
            .filter(|s| !s.over && s.sent < SENDS_PER_SERVER)
            .map(|s| s.at + STUN_RTO * u32::from(s.sent))
            .filter(|at| *at < deadline)
            .min()
    }

    fn on_reply(&mut self, teed: &TeedStun) {
        let Some(server) = self
            .asked
            .iter_mut()
            .find(|s| !s.over && s.sent > 0 && s.addr == teed.from)
        else {
            self.stats.ignored = self.stats.ignored.saturating_add(1);
            return;
        };
        match parse_response(&teed.bytes, &server.txid) {
            None => self.stats.ignored = self.stats.ignored.saturating_add(1),
            Some(StunReply::ErrorResponse) => {
                server.over = true;
                self.stats.errors = self.stats.errors.saturating_add(1);
            }
            Some(StunReply::Mapped(mapped)) => {
                server.over = true;
                let mapped = canon(mapped);
                let usable = mapped.port() != 0
                    && match mapped.ip() {
                        IpAddr::V4(v4) => match class_v4(v4) {
                            AddrClass::Global => true,
                            AddrClass::Loopback => self.ask.filter.admit_loopback,
                            _ => false,
                        },
                        IpAddr::V6(_) => false,
                    };
                if !usable {
                    self.stats.refused = self.stats.refused.saturating_add(1);
                } else if self.ask.hosts.iter().any(|h| canon(*h) == mapped) {
                    self.outcome = Some(StunOutcome::NoNat);
                } else {
                    self.outcome = Some(StunOutcome::Srflx(Candidate {
                        kind: CandidateKind::Srflx,
                        addr: mapped,
                    }));
                }
            }
        }
    }

    fn report(self) -> StunReport {
        StunReport {
            outcome: self.outcome.unwrap_or(StunOutcome::Nothing),
            stats: self.stats,
        }
    }
}

type Lookup = Pin<Box<Timeout<BoxFuture<'static, io::Result<Vec<SocketAddr>>>>>>;

/// The name lookup in flight, if any.
async fn looked_up(lookup: &mut Option<Lookup>) -> Vec<SocketAddr> {
    match lookup {
        Some(lookup) => match lookup.as_mut().await {
            Ok(Ok(addrs)) => addrs,
            _ => Vec::new(),
        },
        None => std::future::pending().await,
    }
}

enum Woke {
    Reply(TeedStun),
    Resolved(Vec<SocketAddr>),
    Timer,
}

/// The STUN client (design §7.3; see the module documentation): asks the
/// servers of `ask.servers` from `socket` and reads their answers from
/// `replies` (the socket's STUN tee, which fills only while quinn's
/// endpoint driver polls the socket). A name is resolved through `env`
/// (the real machine answers from [`StunDns`], and looks a name up only
/// while that cache is cold), waiting [`DNS_TIMEOUT`] at most; an IP
/// literal is never resolved. Returns at the
/// first acceptable answer, at the deadline, or once every server asked has
/// answered and no other may be.
pub async fn ask_stun(
    socket: &PunchSocket,
    replies: &mut mpsc::Receiver<TeedStun>,
    env: &dyn NetEnv,
    ask: &StunAsk<'_>,
) -> StunReport {
    let deadline = Instant::from_std(ask.deadline);
    let mut client = Client {
        ask,
        asked: Vec::new(),
        outcome: None,
        stats: StunStats::default(),
    };
    let mut order: VecDeque<&str> = ask_order(ask.servers, ask.draw).into();
    if order.is_empty() {
        return client.report();
    }
    // A fresh socket reads as not writable until the runtime has seen it
    // (`PunchSocket::writable`); a request sent before would be dropped.
    if !matches!(
        tokio::time::timeout_at(deadline, socket.writable()).await,
        Ok(Ok(()))
    ) {
        return client.report();
    }
    let mut next_server = Some(Instant::now());
    let mut lookup: Option<Lookup> = None;
    loop {
        let now = Instant::now();
        if client.outcome.is_some() || now >= deadline {
            break;
        }
        if lookup.is_none()
            && client.asked.len() < STUN_SERVERS_PER_SESSION
            && next_server.is_some_and(|at| at <= now)
        {
            let Some(entry) = order.pop_front() else {
                next_server = None;
                continue;
            };
            let Some((host, port)) = server_name(entry) else {
                client.stats.unresolved = client.stats.unresolved.saturating_add(1);
                continue;
            };
            if let Ok(ip) = host.parse::<IpAddr>() {
                client.take(env, &[SocketAddr::new(ip, port)], now, &mut next_server);
            } else {
                client.stats.resolves = client.stats.resolves.saturating_add(1);
                let wait = (now + DNS_TIMEOUT).min(deadline);
                lookup = Some(Box::pin(tokio::time::timeout_at(
                    wait,
                    env.resolve(host, port),
                )));
            }
            continue;
        }
        client.send_due(socket, now, deadline);
        if lookup.is_none() && next_server.is_none() && client.asked.iter().all(|s| s.over) {
            break;
        }
        let wake = client
            .next_send(deadline)
            .into_iter()
            .chain(next_server.filter(|_| lookup.is_none()))
            .fold(deadline, Instant::min);
        let woke = tokio::select! {
            biased;
            Some(teed) = replies.recv() => Woke::Reply(teed),
            addrs = looked_up(&mut lookup) => Woke::Resolved(addrs),
            () = tokio::time::sleep_until(wake) => Woke::Timer,
        };
        match woke {
            Woke::Reply(teed) => client.on_reply(&teed),
            Woke::Resolved(addrs) => {
                lookup = None;
                client.take(env, &addrs, Instant::now(), &mut next_server);
            }
            Woke::Timer => {}
        }
    }
    client.report()
}

// ---------------------------------------------------------------------------
// The plan of one session's gathering and the task that runs it.

/// How long STUN waits for the router when both are planned (design §4
/// "Gathering", §5.3): a mapping with a global address by then makes the
/// STUN request needless, and no server learns of the session.
pub const MAPPING_HEAD_START: Duration = Duration::from_millis(250);

/// What one side may gather beyond its host candidates (design §8.3
/// `GatherConfig`): the user's `[network]` settings, for this side's role.
/// The default asks nobody.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct GatherConfig {
    /// This side's part of `network.stun_servers` ([`stun::partition`]),
    /// `host:port` entries.
    pub stun_partition: Arc<[String]>,
    /// `network.enable_stun`.
    pub use_stun: bool,
    /// The router protocols `network.upnp`, `network.nat_pmp` and
    /// `network.pcp` allow.
    pub map: MapProtocols,
}

impl fmt::Debug for GatherConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatherConfig")
            .field("stun_servers", &self.stun_partition.len())
            .field("use_stun", &self.use_stun)
            .field("map", &self.map)
            .finish()
    }
}

/// The STUN part of a [`GatherPlan`].
#[derive(Clone, PartialEq, Eq)]
pub struct StunPlan {
    /// The servers that may be asked: this side's part of the list.
    pub servers: Arc<[String]>,
    /// The IPv4 address the requests leave from ([`stun_base`]); in VPN
    /// mode the tunnel's, which the client passes as [`StunAsk::tunnel`].
    pub base: Ipv4Addr,
}

impl fmt::Debug for StunPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StunPlan")
            .field("servers", &self.servers.len())
            .field("base", &RedactedIp(IpAddr::V4(self.base)))
            .finish()
    }
}

/// The router part of a [`GatherPlan`] (design §7.4 "Preconditions").
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MapTarget {
    /// The IPv4 gateway of the route-source interface.
    pub gateway: Ipv4Addr,
    /// The IPv4 route source: this computer's address toward the gateway.
    pub client: Ipv4Addr,
    /// The protocols the settings allow.
    pub protocols: MapProtocols,
}

impl fmt::Debug for MapTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapTarget")
            .field("gateway", &RedactedIp(IpAddr::V4(self.gateway)))
            .field("client", &RedactedIp(IpAddr::V4(self.client)))
            .field("protocols", &self.protocols)
            .finish()
    }
}

/// What one side gathers in a session beyond its host candidates (design
/// §8.3 `GatherPlan`, §7.3, §7.4), as [`plan`] decides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatherPlan {
    /// The session's scope.
    pub scope: Scope,
    /// This computer is in VPN mode ([`crate::local::vpn_mode`]).
    pub vpn: bool,
    /// The STUN client runs (unless the router answers first).
    pub stun: Option<StunPlan>,
    /// The router is asked for a port.
    pub map: Option<MapTarget>,
    /// How long STUN waits for the router: [`MAPPING_HEAD_START`] when both
    /// are planned, otherwise none.
    pub head_start: Duration,
    /// Gathering ends this long after the bind at the latest
    /// ([`GATHER_BUDGET`]).
    pub budget: Duration,
}

impl GatherPlan {
    /// Whether anything beyond the host candidates is gathered. Without,
    /// gathering is over at the bind and nothing is asked of the
    /// environment beyond the interfaces and the socket.
    #[must_use]
    pub fn gathers(&self) -> bool {
        self.stun.is_some() || self.map.is_some()
    }
}

/// The plan of one side's gathering (design §7.3 "When it runs", §7.4
/// "Preconditions", §5.3 "STUN is skipped entirely when"): `config` is the
/// side's settings, `addrs` and `sources` this computer's addresses and
/// route sources, `vpn` its VPN mode, `hosts` its host candidates (any
/// port), `admit_loopback` true only in test environments (a loopback
/// route source, gateway and STUN base then count as private).
///
/// - Same-site scope gathers nothing.
/// - The router is asked when a protocol is on, outside VPN mode, without
///   a global IPv4 host candidate, from an IPv4 route source of class
///   private or shared (`100.64/10`), toward the IPv4 gateway of that
///   source's interface ([`IfaceAddr::gateway_v4`]) of the same classes.
/// - STUN runs when `use_stun` is on, the part of the list is not empty,
///   and [`stun_base`] gives a base (no global IPv4 host candidate; in VPN
///   mode only with the IPv4 route through the tunnel).
#[must_use]
pub fn plan(
    config: &GatherConfig,
    scope: Scope,
    addrs: &[IfaceAddr],
    sources: &RouteSources,
    vpn: bool,
    hosts: &[SocketAddr],
    admit_loopback: bool,
) -> GatherPlan {
    let mut plan = GatherPlan {
        scope,
        vpn,
        stun: None,
        map: None,
        head_start: Duration::ZERO,
        budget: GATHER_BUDGET,
    };
    if scope != Scope::Internet {
        return plan;
    }
    if config.use_stun && !config.stun_partition.is_empty() {
        plan.stun = stun_base(addrs, sources, vpn, hosts, admit_loopback).map(|base| StunPlan {
            servers: Arc::clone(&config.stun_partition),
            base,
        });
    }
    if config.map.any() && !vpn && !public_v4_host(hosts) {
        plan.map = map_target(addrs, sources, admit_loopback).map(|(gateway, client)| MapTarget {
            gateway,
            client,
            protocols: config.map,
        });
    }
    if plan.stun.is_some() && plan.map.is_some() {
        plan.head_start = MAPPING_HEAD_START;
    }
    plan
}

/// The gateway and the client of a mapping: the IPv4 route source and its
/// interface's gateway, both private or shared (design §7.4: PCP is made
/// for carrier NATs, and a global gateway is no home router).
fn map_target(
    addrs: &[IfaceAddr],
    sources: &RouteSources,
    admit_loopback: bool,
) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let fits = |ip: Ipv4Addr| match class_v4(ip) {
        AddrClass::Private | AddrClass::SharedCgnat => true,
        AddrClass::Loopback => admit_loopback,
        _ => false,
    };
    let client = sources.v4.filter(|c| fits(*c))?;
    let gateway = owner(addrs, IpAddr::V4(client))?
        .gateway_v4
        .filter(|g| fits(*g))?;
    Some((gateway, client))
}

/// Whether `external`, a router's mapped address, may be offered: global
/// IPv4 with a port (loopback too in test environments). [`RealMapper`]
/// refuses any other; this checks every mapper.
///
/// [`RealMapper`]: crate::RealMapper
fn offerable_mapping(external: SocketAddr, admit_loopback: bool) -> bool {
    let ip = canon_ip(external.ip());
    external.port() != 0
        && ip.is_ipv4()
        && match class(ip) {
            AddrClass::Global => true,
            AddrClass::Loopback => admit_loopback,
            _ => false,
        }
}

/// The gathering's counters (design §5.5: counts and kinds only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GatherStats {
    /// The plan asks a STUN server.
    pub stun_planned: bool,
    /// The plan asks the router.
    pub map_planned: bool,
    /// The router granted a mapping that was offered, by this protocol.
    pub mapped: Option<MapVia>,
    /// The router gave no mapping, or one that could not be offered
    /// ([`MapFail::NotGlobal`]).
    pub map_failed: Option<MapFail>,
    /// The STUN client ran.
    pub stun_ran: bool,
    /// STUN was skipped: the router gave a global address within the head
    /// start.
    pub stun_skipped: bool,
    /// The STUN client's counts.
    pub stun: StunStats,
    /// A server-reflexive candidate was learned.
    pub srflx: bool,
    /// A server saw this side at a host candidate (no NAT).
    pub no_nat: bool,
    /// Batches of gathered candidates handed to the owner.
    pub batches: u8,
    /// A gathered candidate equal to one already offered, not offered
    /// again.
    pub duplicates: u8,
    /// Gathering was cut at the budget with the router or STUN still
    /// running.
    pub cut_at_budget: bool,
    /// Gathering is over: the owner has been told.
    pub done: bool,
}

/// What the gathering tells the link's checklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gathered {
    /// A public IPv4 address of this side (mapped or server-reflexive),
    /// for the ranks of design §7.6.
    Public(IpAddr),
    /// Gathering is over.
    Done,
}

/// The gathering of one link (see the module documentation), spawned by
/// [`DirectLink::start`](crate::DirectLink) on the link's runtime.
pub(crate) struct Gatherer {
    /// What to gather; it gathers something ([`GatherPlan::gathers`]).
    pub plan: GatherPlan,
    pub env: Arc<dyn NetEnv>,
    pub socket: Arc<PunchSocket>,
    /// The session socket's STUN tee.
    pub replies: mpsc::Receiver<TeedStun>,
    /// The filter STUN servers' addresses pass.
    pub filter: StunFilter,
    /// The host candidates offered (at the socket's port).
    pub hosts: Vec<SocketAddr>,
    /// The session socket's port.
    pub port: u16,
    /// When the session socket was bound: the budget runs from here.
    pub bound: Instant,
    pub admit_loopback: bool,
    /// The owner's batches ([`DirectLink::next_local`](crate::DirectLink::next_local)).
    pub out: mpsc::Sender<LocalBatch>,
    /// The link's driver.
    pub driver: mpsc::Sender<Gathered>,
    pub stats: Arc<Mutex<GatherStats>>,
}

/// Where STUN stands in a gathering.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StunStep {
    /// Due at this time (the head start).
    Due(Instant),
    /// Asking.
    Running,
    /// Done, skipped or not planned.
    Over,
}

/// The router's answer in flight, if any.
async fn mapped(
    pending: &mut Option<BoxFuture<'static, Result<Mapping, MapFail>>>,
) -> Result<Mapping, MapFail> {
    match pending {
        Some(pending) => pending.await,
        None => std::future::pending().await,
    }
}

async fn due(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

impl Gatherer {
    /// Gathers, says `Done` to the owner and the driver, then renews the
    /// mapping (if any) until the link aborts this task, which drops the
    /// mapping and so releases it.
    pub(crate) async fn run(self) {
        let out = self.out.clone();
        let driver = self.driver.clone();
        let stats = Arc::clone(&self.stats);
        let mapping = self.gather().await;
        lock(&stats).done = true;
        let _ = out.try_send(LocalBatch::Done);
        let _ = driver.try_send(Gathered::Done);
        drop((out, driver));
        if let Some(mut mapping) = mapping {
            let _ = mapping.keep_renewed().await;
        }
    }

    /// The router and STUN, each batch handed on as it lands, until both
    /// are over or the budget ends; returns the mapping offered.
    async fn gather(self) -> Option<Mapping> {
        let Self {
            plan,
            env,
            socket,
            mut replies,
            filter,
            hosts,
            port,
            bound,
            admit_loopback,
            out,
            driver,
            stats,
        } = self;
        let note = |change: &dyn Fn(&mut GatherStats)| change(&mut lock(&stats));
        note(&|s| {
            s.stun_planned = plan.stun.is_some();
            s.map_planned = plan.map.is_some();
        });
        let deadline = bound + plan.budget;
        let mut offered: Vec<SocketAddr> = hosts.iter().map(|h| canon(*h)).collect();
        let mut offer = |candidate: Candidate| {
            let addr = canon(candidate.addr);
            if offered.contains(&addr) {
                note(&|s| s.duplicates = s.duplicates.saturating_add(1));
                return;
            }
            offered.push(addr);
            note(&|s| s.batches = s.batches.saturating_add(1));
            // Cannot be full: at most two batches and `Done` on a queue of
            // four.
            let _ = out.try_send(LocalBatch::More(vec![Candidate { addr, ..candidate }]));
            let _ = driver.try_send(Gathered::Public(addr.ip()));
        };

        let mut router = match (plan.map, NonZeroU16::new(port)) {
            (Some(target), Some(internal_port)) => Some(env.mapper().map(MapRequest {
                gateway: target.gateway,
                client: target.client,
                internal_port,
                lease: MAP_LEASE,
                protocols: target.protocols,
                deadline: deadline.into_std(),
            })),
            _ => None,
        };
        let servers = plan
            .stun
            .as_ref()
            .map(|s| Arc::clone(&s.servers))
            .unwrap_or_default();
        let ask = StunAsk {
            servers: &servers,
            filter: &filter,
            hosts: &hosts,
            deadline: deadline.into_std(),
            draw: draw(),
            tunnel: plan.stun.as_ref().filter(|_| plan.vpn).map(|s| s.base),
        };
        let client = ask_stun(&socket, &mut replies, &*env, &ask);
        tokio::pin!(client);
        let mut stun = if plan.stun.is_some() {
            StunStep::Due(bound + plan.head_start)
        } else {
            StunStep::Over
        };
        let mut mapping: Option<Mapping> = None;

        enum Woke {
            Router(Result<Mapping, MapFail>),
            StunDue,
            Stun(StunReport),
            Budget,
        }
        while router.is_some() || stun != StunStep::Over {
            let due_at = match stun {
                StunStep::Due(at) => Some(at),
                _ => None,
            };
            let woke = tokio::select! {
                biased;
                answer = mapped(&mut router) => Woke::Router(answer),
                () = due(due_at) => Woke::StunDue,
                report = &mut client, if stun == StunStep::Running => Woke::Stun(report),
                () = tokio::time::sleep_until(deadline) => Woke::Budget,
            };
            match woke {
                Woke::Router(answer) => {
                    router = None;
                    match answer {
                        Ok(granted)
                            if offerable_mapping(
                                SocketAddr::V4(granted.external),
                                admit_loopback,
                            ) =>
                        {
                            let via = granted.via;
                            note(&|s| s.mapped = Some(via));
                            offer(Candidate {
                                kind: CandidateKind::Mapped,
                                addr: SocketAddr::V4(granted.external),
                            });
                            mapping = Some(granted);
                        }
                        // Dropped, so released.
                        Ok(_) => note(&|s| s.map_failed = Some(MapFail::NotGlobal)),
                        Err(fail) => note(&|s| s.map_failed = Some(fail)),
                    }
                    // The router answered within the head start: a global
                    // mapping skips STUN, anything else starts it now
                    // rather than at the end of a wait for nothing.
                    if matches!(stun, StunStep::Due(_)) {
                        stun = if mapping.is_some() {
                            note(&|s| s.stun_skipped = true);
                            StunStep::Over
                        } else {
                            note(&|s| s.stun_ran = true);
                            StunStep::Running
                        };
                    }
                }
                Woke::StunDue => {
                    if mapping.is_some() {
                        note(&|s| s.stun_skipped = true);
                        stun = StunStep::Over;
                    } else {
                        note(&|s| s.stun_ran = true);
                        stun = StunStep::Running;
                    }
                }
                Woke::Stun(report) => {
                    stun = StunStep::Over;
                    note(&|s| s.stun = report.stats);
                    match report.outcome {
                        StunOutcome::Srflx(candidate) => {
                            note(&|s| s.srflx = true);
                            offer(candidate);
                        }
                        StunOutcome::NoNat => note(&|s| s.no_nat = true),
                        StunOutcome::Nothing => {}
                    }
                }
                Woke::Budget => {
                    note(&|s| s.cut_at_budget = true);
                    break;
                }
            }
        }
        mapping
    }
}

#[cfg(test)]
mod tests;
