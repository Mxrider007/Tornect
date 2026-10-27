//! Gathering the candidates beyond this computer's own addresses (design
//! `direct` §7.3, §5.3; decisions M1-81, M1-83, M1-86): the STUN client
//! that learns the server-reflexive candidate, and [`StunDns`], the cache
//! of the STUN servers' addresses it reads.
//!
//! Step B3 holds the client ([`ask_stun`]), the cache and its background
//! refresh, and [`stun_base`], the part of "when STUN runs" that is this
//! computer's. The plan of a session's gathering (scope, `enable_stun`, the
//! router mapping and its head start, the trickled batches) is step B6's,
//! and the app starts the refresh when the internet direct path is on
//! (steps B11, B12); until then only tests call the client.
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
//!   checked the same way.
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
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{Instant, Timeout};

use crate::BoxFuture;
use crate::addr::{AddrClass, Candidate, CandidateKind, StunFilter, canon, class, class_v4};
use crate::env::NetEnv;
use crate::local::{IfaceAddr, RouteSources, global_families};
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
/// plan's (step B6).
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
    let public_host = hosts.iter().any(|h| {
        let h = canon(*h);
        h.is_ipv4() && class(h.ip()) == AddrClass::Global
    });
    (usable && !public_host && (!vpn || global_families(addrs, sources, vpn).0)).then_some(base)
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
}

impl fmt::Debug for StunAsk<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StunAsk")
            .field("servers", &self.servers.len())
            .field("filter", self.filter)
            .field("hosts", &self.hosts.len())
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
    /// Takes the first address of `addrs` the filter admits as the next
    /// server, asked from `now`; without one, the next entry is tried at
    /// once.
    fn take(&mut self, addrs: &[SocketAddr], now: Instant, next: &mut Option<Instant>) {
        let found = addrs
            .iter()
            .map(|a| canon(*a))
            .find(|a| self.ask.filter.admit(*a) && !self.asked.iter().any(|s| s.addr == *a));
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
                client.take(&[SocketAddr::new(ip, port)], now, &mut next_server);
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
                client.take(&addrs, Instant::now(), &mut next_server);
            }
            Woke::Timer => {}
        }
    }
    client.report()
}

#[cfg(test)]
mod tests;
