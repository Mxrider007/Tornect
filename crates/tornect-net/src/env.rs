//! The seam between a direct link and the machine it runs on (design
//! `direct` §8.3): every call a link makes to the OS goes through
//! [`NetEnv`], so the privacy rules ("a `tor_only` side reads no interface
//! and binds nothing", design §5.2) are counted in tests, and the in-memory
//! network of the later steps replaces the machine.
//!
//! The calls that read this computer's addresses (step A7) and bind the
//! session socket (step A8) are here, and since step B1 the two that STUN
//! and router mapping need: [`NetEnv::resolve`] (the STUN servers' names,
//! answered from the [`StunDns`] cache that [`RealNet::prefetch`] keeps
//! filled, step B3) and [`NetEnv::mapper`] (the router protocols of
//! [`RealNet::with_router`], steps B4 and B5).

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::task::{AbortHandle, JoinHandle};

use crate::gather::{PREFETCH_TIMEOUT, Resolver, StunDns};
use crate::local::{self, IfaceAddr, RouteSources};
use crate::mapping::{
    MapEvents, MappingLedger, NoMapper, PortMapper, RealMapper, ReleaseTracker, Router, SWEEP_CAP,
    SweepReport,
};
use crate::socket::bind_media_socket;
use crate::udp::BoundUdp;
use crate::{BoxFuture, NetError};

/// What a direct link asks of the machine.
pub trait NetEnv: Send + Sync {
    /// This computer's addresses (design §7.1), read on the blocking pool
    /// under [`local::IFACE_READ_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// [`NetError::InterfacesTimedOut`] or [`NetError::InterfacesLost`];
    /// the link reads either as "no addresses".
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>>;

    /// The source address of each family's default route; no packet.
    fn route_sources(&self) -> RouteSources;

    /// The source address the OS picks toward `to` (no packet), or `None`
    /// without a route. It differs from the family's
    /// [`route_sources`](NetEnv::route_sources) where a more specific route
    /// serves `to`: a split tunnel that excludes the prefix of a STUN
    /// server, which the STUN client checks in VPN mode (design §7.2,
    /// §9.3). The default is the family's route source, for environments
    /// without such routes.
    fn route_source_to(&self, to: SocketAddr) -> Option<IpAddr> {
        let sources = self.route_sources();
        match to {
            SocketAddr::V4(_) => sources.v4.map(IpAddr::V4),
            SocketAddr::V6(_) => sources.v6.map(IpAddr::V6),
        }
    }

    /// Binds the session's one UDP socket (design §6.3): `port` when it is
    /// free (`network.direct_port`), any port otherwise. Called on the
    /// tokio runtime the link runs on.
    ///
    /// # Errors
    ///
    /// The OS refused every bind; the link reads it as "could not open a
    /// network port".
    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp>;

    /// The addresses of `host` (a STUN server's name from the user's list)
    /// with `port` (design §7.3). The real machine answers from the
    /// [`StunDns`] its background refresh fills and never asks the resolver
    /// per session, except while that cache is cold (no refresh round has
    /// completed since it was made or emptied: the one-shot `connect`,
    /// design §5.3). The caller bounds the wait
    /// ([`DNS_TIMEOUT`](crate::gather::DNS_TIMEOUT)).
    ///
    /// # Errors
    ///
    /// The name does not resolve, the refreshed cache lacks it, or the
    /// environment resolves no names. The error's text is the resolver's
    /// and is never shown or logged.
    fn resolve(&self, host: &str, port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>>;

    /// The router mapper of this machine (design §7.4).
    fn mapper(&self) -> Arc<dyn PortMapper>;

    /// Whether loopback remotes pass the filters: test environments only.
    fn admit_loopback(&self) -> bool {
        false
    }
}

/// The IPv4 default gateway of the interface with an OS index: the
/// lookup [`RealNet::with_gateway_lookup`] takes.
pub type GatewayLookup = Arc<dyn Fn(u32) -> Option<Ipv4Addr> + Send + Sync>;

/// The real machine. Dropping it stops its background refresh
/// ([`RealNet::prefetch`]).
pub struct RealNet {
    gateway: Option<GatewayLookup>,
    mapper: Arc<dyn PortMapper>,
    /// The router protocols, once [`RealNet::with_router`] gave a ledger.
    router: Option<RealMapper>,
    releases: ReleaseTracker,
    dns: StunDns,
    /// [`system_lookup`]; a table in this crate's tests.
    lookup: Resolver,
    prefetch: Mutex<Option<AbortHandle>>,
}

impl Default for RealNet {
    fn default() -> Self {
        Self {
            gateway: None,
            mapper: Arc::new(NoMapper),
            router: None,
            releases: ReleaseTracker::new(),
            dns: StunDns::new(),
            lookup: Arc::new(system_lookup),
            prefetch: Mutex::new(None),
        }
    }
}

/// The system resolver (`getaddrinfo` on tokio's blocking pool); a literal
/// is answered without a query.
fn system_lookup(host: &str, port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
    let host = host.to_owned();
    Box::pin(async move {
        Ok(tokio::net::lookup_host((host.as_str(), port))
            .await?
            .collect())
    })
}

impl RealNet {
    /// The machine this process runs on. Every value shares one interface
    /// read in flight ([`local::read_interfaces`]). Its mapper is
    /// [`NoMapper`] until [`with_router`](Self::with_router) gives it a
    /// ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The machine, with `lookup` filling the IPv4 gateway of every
    /// interface netdev reported none for ([`local::fill_gateways`]).
    /// Windows passes `tornect_platform::route::default_gateway_v4`
    /// (`GetBestRoute2`, a route lookup that sends nothing), since netdev's
    /// own Windows gateway read may send ARP and is never compiled (design
    /// §7.1). Linux and macOS need none: netdev reads the gateway from the
    /// kernel's tables there.
    #[must_use]
    pub fn with_gateway_lookup(
        mut self,
        lookup: impl Fn(u32) -> Option<Ipv4Addr> + Send + Sync + 'static,
    ) -> Self {
        self.gateway = Some(Arc::new(lookup));
        self
    }

    /// The machine with the router protocols ([`RealMapper`], design §7.4):
    /// the ledger of its requests in `dir`
    /// (`tornect_core::Paths::router_ports_dir`), every mapping that opens
    /// or closes reported to `events` (the session log's `router_port`
    /// lines), mappings dropped unreleased released through
    /// [`releases`](Self::releases).
    #[must_use]
    pub fn with_router(mut self, dir: impl Into<PathBuf>, events: Arc<dyn MapEvents>) -> Self {
        let router = RealMapper::new(MappingLedger::new(dir), events, self.releases.clone());
        self.mapper = Arc::new(router.clone());
        self.router = Some(router);
        self
    }

    /// The releases of dropped mappings still running: the app's shutdown
    /// waits for them, at most
    /// [`SHUTDOWN_RELEASE_WAIT`](crate::SHUTDOWN_RELEASE_WAIT).
    #[must_use]
    pub fn releases(&self) -> ReleaseTracker {
        self.releases.clone()
    }

    /// Starts the removal of the router mappings an earlier run left
    /// ([`RealMapper::sweep`]) on the current tokio runtime, bounded by
    /// [`SWEEP_CAP`]; the app calls it at start (GUI, `host`, `connect`),
    /// whatever the direct-path policy, since it only removes exposure.
    /// Nothing is read beyond the ledger's directory, and nothing is sent,
    /// unless an earlier run left mappings; only the router in use now is
    /// contacted. `None` without a router ledger or outside a runtime.
    pub fn sweep_leftovers(&self) -> Option<JoinHandle<SweepReport>> {
        let router = self.router.clone()?;
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        let interfaces = self.interfaces();
        Some(runtime.spawn(async move {
            let here = async move {
                let client = local::route_sources().v4?;
                let addrs = interfaces.await.ok()?;
                let gateway = addrs
                    .iter()
                    .find(|a| a.ip == IpAddr::V4(client))?
                    .gateway_v4?;
                Some(Router { gateway, client })
            };
            tokio::time::timeout(SWEEP_CAP, router.sweep(here))
                .await
                .unwrap_or_default()
        }))
    }

    /// The cache [`NetEnv::resolve`] answers from.
    #[must_use]
    pub fn stun_dns(&self) -> &StunDns {
        &self.dns
    }

    /// The machine with `lookup` in place of the system resolver, for the
    /// refresh and a cold cache alike: the seam this crate's tests count
    /// lookups through.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_resolver(mut self, lookup: Resolver) -> Self {
        self.lookup = lookup;
        self
    }

    /// Starts the background refresh of the STUN servers' names on the
    /// current tokio runtime (design §5.3; [`StunDns::run`]): a round now,
    /// then one every 10 min ± 1 min, through the system resolver. `entries`
    /// is read at each round and returns the list to resolve, or nothing
    /// when the refresh is not allowed now (it is only while the internet
    /// direct path is on, the effective policy allows direct paths, STUN is
    /// on and no bridge is in use); the app calls this at start (GUI, `host`,
    /// `connect`). A refresh already running is replaced. Returns false
    /// outside a tokio runtime, where nothing starts.
    pub fn prefetch(&self, entries: impl Fn() -> Vec<String> + Send + Sync + 'static) -> bool {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return false;
        };
        let task = runtime.spawn(self.dns.clone().run(entries, Arc::clone(&self.lookup)));
        let previous = self
            .prefetch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(task.abort_handle());
        if let Some(previous) = previous {
            previous.abort();
        }
        true
    }
}

impl Drop for RealNet {
    fn drop(&mut self) {
        let running = self
            .prefetch
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(running) = running {
            running.abort();
        }
    }
}

impl fmt::Debug for RealNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealNet")
            .field("gateway_lookup", &self.gateway.is_some())
            .field("router", &self.router)
            .field("dns", &self.dns)
            .finish_non_exhaustive()
    }
}

impl NetEnv for RealNet {
    /// [`local::read_interfaces`], then the gateway lookup, if any: one
    /// route-table query per interface, as quick as the route sources'
    /// UDP `connect()`.
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        let lookup = self.gateway.clone();
        Box::pin(async move {
            let mut addrs = local::read_interfaces().await?;
            if let Some(lookup) = lookup {
                local::fill_gateways(&mut addrs, &*lookup);
            }
            Ok(addrs)
        })
    }

    fn route_sources(&self) -> RouteSources {
        local::route_sources()
    }

    /// [`local::route_source_to`]: the kernel's own route lookup.
    fn route_source_to(&self, to: SocketAddr) -> Option<IpAddr> {
        local::route_source_to(to)
    }

    /// [`bind_media_socket`] (dual-stack where the OS has IPv6) under
    /// [`QuietUdp`](crate::QuietUdp).
    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp> {
        BoundUdp::quiet(bind_media_socket(port)?)
    }

    /// A literal address without a query; a cached name from the cache.
    /// Once a refresh round has completed ([`StunDns::refreshed`]), any
    /// other name is `NotFound` at once, without a query: a session never
    /// tells the resolver when it starts (design §5.3, §9.3), and a name
    /// that failed in the round waits for the next one. Only a cold cache
    /// (a session that starts before the first round has completed, as the
    /// one-shot `connect` may, or while the refresh has emptied the cache)
    /// asks the OS resolver (`getaddrinfo` on tokio's blocking pool), on a
    /// task of its own so that the answer is cached even when the session
    /// has stopped waiting.
    fn resolve(&self, host: &str, port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            let addr = SocketAddr::new(ip, port);
            return Box::pin(async move { Ok(vec![addr]) });
        }
        if let Some(cached) = self.dns.get(host, port) {
            return Box::pin(async move { Ok(cached) });
        }
        if self.dns.refreshed() {
            return Box::pin(async { Err(io::ErrorKind::NotFound.into()) });
        }
        let dns = self.dns.clone();
        let lookup = Arc::clone(&self.lookup);
        let host = host.to_owned();
        Box::pin(async move {
            let task = tokio::spawn(async move {
                let addrs = tokio::time::timeout(PREFETCH_TIMEOUT, lookup(&host, port))
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
                dns.put(&host, port, addrs.clone());
                Ok(addrs)
            });
            task.await
                .map_err(|_| io::Error::from(io::ErrorKind::Interrupted))?
        })
    }

    fn mapper(&self) -> Arc<dyn PortMapper> {
        Arc::clone(&self.mapper)
    }

    /// Never, whatever the build: loopback is admitted only by test
    /// environments.
    fn admit_loopback(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// The real machine through the seam, as a link holds it: never
    /// loopback, and the same reads as the functions it wraps.
    #[tokio::test]
    async fn the_real_machine_admits_no_loopback_and_reads_through_the_seam() {
        let env: Arc<dyn NetEnv> = Arc::new(RealNet::new());
        assert!(!env.admit_loopback());
        let through = env.interfaces().await.expect("the interface list");
        let direct = local::read_interfaces().await.expect("the interface list");
        assert_eq!(
            through
                .iter()
                .map(|a| (a.iface_index, a.iface_kind))
                .collect::<Vec<_>>(),
            direct
                .iter()
                .map(|a| (a.iface_index, a.iface_kind))
                .collect::<Vec<_>>()
        );
        assert_eq!(env.route_sources(), local::route_sources());
    }

    /// The real machine asks the kernel for the source toward each address:
    /// the IPv4 route source toward the probe address of `route_sources`,
    /// and loopback toward a loopback address (a route more specific than
    /// the default one), with no packet sent.
    #[test]
    fn the_real_machine_reads_the_route_toward_an_address() {
        let env = RealNet::new();
        let probe: SocketAddr = "192.0.2.1:9".parse().unwrap();
        assert_eq!(
            env.route_source_to(probe),
            env.route_sources().v4.map(IpAddr::V4)
        );
        assert_eq!(
            env.route_source_to("127.0.0.1:9".parse().unwrap()),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }

    /// The seam binds the session socket as `bind_media_socket` does, behind
    /// the quiet wrapper, and each call gets its own socket.
    #[tokio::test]
    async fn the_real_machine_binds_one_quiet_socket_per_call() {
        let env: Arc<dyn NetEnv> = Arc::new(RealNet::new());
        let first = env.bind(None).expect("a session socket");
        let second = env.bind(None).expect("a second session socket");
        let a = first.inner.local_addr().expect("its address");
        let b = second.inner.local_addr().expect("its address");
        assert_ne!(a.port(), 0);
        assert_ne!(a.port(), b.port());
        assert!(a.ip().is_unspecified());
        assert_eq!(a.is_ipv6(), first.dual_stack);
        assert_eq!((first.errors.other(), first.errors.too_large()), (0, 0));
        let held = a.port();
        let third = env.bind(Some(held)).expect("a busy port is retried");
        assert_ne!(third.inner.local_addr().expect("its address").port(), held);
    }

    /// A literal resolves without a query; the real machine's mapper asks
    /// no router until it is given a ledger.
    #[tokio::test]
    async fn the_real_machine_resolves_literals_and_maps_nothing_yet() {
        let env: Arc<dyn NetEnv> = Arc::new(RealNet::new());
        assert_eq!(
            env.resolve("192.0.2.7", 3478).await.expect("a literal"),
            vec!["192.0.2.7:3478".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            env.resolve("2001:db8::7", 19302).await.expect("a literal"),
            vec!["[2001:db8::7]:19302".parse::<SocketAddr>().unwrap()]
        );
        let request = crate::MapRequest {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            client: Ipv4Addr::new(192, 168, 1, 20),
            internal_port: std::num::NonZeroU16::new(50_000).unwrap(),
            lease: crate::MAP_LEASE,
            protocols: crate::MapProtocols::ALL,
            deadline: std::time::Instant::now(),
        };
        assert_eq!(
            env.mapper()
                .map(request)
                .await
                .expect_err("no router protocol yet"),
            crate::MapFail::NoGateway
        );
    }

    /// With a router ledger the machine maps through [`RealMapper`] (which
    /// still asks nothing outside its preconditions), and the start-up
    /// sweep of an empty ledger contacts nothing and leaves nothing behind;
    /// without one there is no sweep, and outside a runtime none starts.
    #[test]
    fn the_router_ledger_gives_a_mapper_and_a_sweep() {
        struct Quiet;
        impl MapEvents for Quiet {
            fn on_event(&self, ev: crate::MapEvent) {
                panic!("no event expected: {ev:?}");
            }
        }
        let home = tempfile::tempdir().expect("a temporary directory");
        let dir = home.path().join("router-ports");
        let net = RealNet::new().with_router(&dir, Arc::new(Quiet));
        assert!(net.sweep_leftovers().is_none(), "no runtime, no sweep");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        rt.block_on(async {
            assert!(RealNet::new().sweep_leftovers().is_none(), "no ledger");
            let report = net
                .sweep_leftovers()
                .expect("a sweep starts")
                .await
                .expect("it ends");
            assert_eq!(report, SweepReport::default());
            let request = crate::MapRequest {
                gateway: Ipv4Addr::new(198, 51, 100, 1),
                client: Ipv4Addr::new(192, 168, 1, 20),
                internal_port: std::num::NonZeroU16::new(50_000).unwrap(),
                lease: crate::MAP_LEASE,
                protocols: crate::MapProtocols::ALL,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(1),
            };
            assert_eq!(
                net.mapper()
                    .map(request)
                    .await
                    .expect_err("not a LAN gateway"),
                crate::MapFail::NoGateway
            );
            assert!(net.releases().wait(std::time::Duration::ZERO).await);
        });
        assert!(!dir.exists(), "nothing was written");
    }

    /// Design §5.3: a name the cache holds is answered from it, in any case
    /// and with or without its final dot, and the resolver is not asked
    /// (an `.invalid` name, RFC 6761 §6.4, resolves nowhere); an IP literal
    /// is not cached.
    #[tokio::test]
    async fn the_real_machine_answers_names_from_its_cache() {
        let env = RealNet::new();
        let addr: SocketAddr = "64.0.0.10:3478".parse().unwrap();
        env.stun_dns().put("stun.example.invalid", 3478, vec![addr]);
        for name in ["stun.example.invalid", "STUN.Example.Invalid."] {
            assert_eq!(env.resolve(name, 3478).await.expect("cached"), vec![addr]);
        }
        env.resolve("64.0.0.11", 3478).await.expect("a literal");
        assert_eq!(env.stun_dns().len(), 1);
        assert!(format!("{env:?}").contains("names: 1"), "{env:?}");
    }

    /// A resolver that notes every lookup: `ok.example` answers at once,
    /// `slow.example` after a second, any other name fails.
    fn noting(calls: &Arc<Mutex<Vec<String>>>) -> Resolver {
        let calls = Arc::clone(calls);
        Arc::new(move |host: &str, port: u16| {
            calls.lock().unwrap().push(host.to_owned());
            let host = host.to_owned();
            Box::pin(async move {
                match host.as_str() {
                    "ok.example" => Ok(vec![SocketAddr::new([64, 0, 0, 20].into(), port)]),
                    "slow.example" => {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        Ok(vec![SocketAddr::new([64, 0, 0, 21].into(), port)])
                    }
                    _ => Err(io::ErrorKind::NotFound.into()),
                }
            })
        })
    }

    /// The answer of `lookup` if it is ready at its first poll: it waits on
    /// nothing, no resolver and no timer.
    fn at_once<T>(mut lookup: BoxFuture<'static, T>) -> Option<T> {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match lookup.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(answer) => Some(answer),
            std::task::Poll::Pending => None,
        }
    }

    /// Design §5.3 ("a session uses the cache and never triggers a lookup
    /// unless the cache is empty"), §4 (`DNS_TIMEOUT` is used only then) and
    /// §9.3 (the resolver operator cannot time sessions): after a refresh
    /// round, a name that failed in it and a name it never listed are
    /// `NotFound` at once, and the resolver is asked nothing; a cached name
    /// is answered at once. Emptied, the cache is cold again.
    #[tokio::test(start_paused = true)]
    async fn after_a_refresh_round_a_session_asks_no_resolver() {
        let calls = Arc::default();
        let env = RealNet::new().with_resolver(noting(&calls));
        assert!(env.prefetch(|| vec!["ok.example:3478".into(), "down.example:3478".into()]));
        for _ in 0..100 {
            if env.stun_dns().refreshed() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(env.stun_dns().refreshed(), "{env:?}");
        assert_eq!(*calls.lock().unwrap(), ["ok.example", "down.example"]);
        for name in ["down.example", "Down.Example.", "unlisted.example"] {
            let answer = at_once(env.resolve(name, 3478)).expect("answered at once");
            assert_eq!(
                answer.expect_err("not cached").kind(),
                io::ErrorKind::NotFound,
                "{name}"
            );
        }
        let cached = at_once(env.resolve("ok.example", 3478)).expect("answered at once");
        assert_eq!(cached.expect("cached"), ["64.0.0.20:3478".parse().unwrap()]);
        assert_eq!(calls.lock().unwrap().len(), 2, "no lookup at session time");

        env.stun_dns().clear();
        assert!(!env.stun_dns().refreshed());
        env.resolve("down.example", 3478)
            .await
            .expect_err("it fails");
        assert_eq!(calls.lock().unwrap().len(), 3, "a cold cache looks up");
    }

    /// Design §5.3: a cold cache (no round has completed: the one-shot
    /// `connect`) looks a name up once and keeps the answer, so the next
    /// session reads the cache; the answer is kept even when the session
    /// stopped waiting for it (`DNS_TIMEOUT`).
    #[tokio::test(start_paused = true)]
    async fn a_cold_cache_looks_a_name_up_once_and_keeps_the_answer() {
        use crate::gather::DNS_TIMEOUT;
        let calls = Arc::default();
        let env = RealNet::new().with_resolver(noting(&calls));
        assert!(!env.stun_dns().refreshed());
        let ok: SocketAddr = "64.0.0.20:3478".parse().unwrap();
        assert_eq!(env.resolve("ok.example", 3478).await.expect("found"), [ok]);
        assert_eq!(calls.lock().unwrap().len(), 1, "exactly one lookup");
        let again = at_once(env.resolve("ok.example", 3478)).expect("answered at once");
        assert_eq!(again.expect("cached"), [ok]);
        assert_eq!(calls.lock().unwrap().len(), 1);

        let given_up = tokio::time::timeout(DNS_TIMEOUT, env.resolve("slow.example", 3478)).await;
        assert!(given_up.is_err(), "the session stops waiting");
        assert_eq!(env.stun_dns().get("slow.example", 3478), None);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(
            env.stun_dns().get("slow.example", 3478),
            Some(vec!["64.0.0.21:3478".parse().unwrap()])
        );
        assert_eq!(*calls.lock().unwrap(), ["ok.example", "slow.example"]);
        assert!(!env.stun_dns().refreshed(), "a lookup is not a round");
    }

    /// The background refresh needs a runtime to start on.
    #[test]
    fn the_prefetch_needs_a_runtime() {
        assert!(!RealNet::new().prefetch(Vec::new));
    }

    /// Design §5.3: the refresh runs on the runtime and reads its list at
    /// each round; an empty list (the refresh is not allowed now) asks no
    /// resolver and empties the cache. A second call replaces the first
    /// refresh, and dropping the machine stops the last one (each task's
    /// list closure is dropped with it).
    #[tokio::test]
    async fn the_prefetch_runs_on_the_runtime_and_stops_with_the_machine() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        async fn until(what: impl Fn() -> bool) {
            for _ in 0..500 {
                if what() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            panic!("not within a second");
        }
        let env = RealNet::new();
        env.stun_dns().put(
            "stun.example.invalid",
            3478,
            vec!["64.0.0.10:3478".parse().unwrap()],
        );
        let first = Arc::new(AtomicUsize::new(0));
        let rounds = Arc::clone(&first);
        assert!(env.prefetch(move || {
            rounds.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        }));
        until(|| first.load(Ordering::SeqCst) == 1 && env.stun_dns().is_empty()).await;

        let second = Arc::new(AtomicUsize::new(0));
        let rounds = Arc::clone(&second);
        assert!(env.prefetch(move || {
            rounds.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        }));
        until(|| second.load(Ordering::SeqCst) == 1).await;
        until(|| Arc::strong_count(&first) == 1).await;
        assert_eq!(first.load(Ordering::SeqCst), 1, "replaced, not run again");
        drop(env);
        until(|| Arc::strong_count(&second) == 1).await;
    }

    /// The gateway lookup fills what netdev left empty, once per
    /// interface, and never a loopback interface's; netdev's own reading
    /// stays.
    #[tokio::test]
    async fn the_gateway_lookup_fills_the_reading() {
        use std::sync::Mutex;
        let asked = Arc::new(Mutex::new(Vec::new()));
        let noted = Arc::clone(&asked);
        let env = RealNet::new().with_gateway_lookup(move |index| {
            noted.lock().unwrap().push(index);
            Some(Ipv4Addr::new(10, 9, 8, 7))
        });
        assert!(format!("{env:?}").contains("gateway_lookup: true"));
        let plain = local::read_interfaces().await.expect("the interface list");
        let filled = env.interfaces().await.expect("the interface list");
        assert_eq!(plain.len(), filled.len());
        let asked = asked.lock().unwrap().clone();
        let mut once = asked.clone();
        once.sort_unstable();
        once.dedup();
        assert_eq!(
            once.len(),
            asked.len(),
            "one lookup per interface: {asked:?}"
        );
        for (p, f) in plain.iter().zip(&filled) {
            assert_eq!((p.ip, p.iface_index), (f.ip, f.iface_index));
            match (p.iface_kind, p.gateway_v4) {
                (local::IfaceKind::Loopback, None) => assert_eq!(f.gateway_v4, None),
                (_, Some(read)) => assert_eq!(f.gateway_v4, Some(read)),
                (_, None) => {
                    assert_eq!(f.gateway_v4, Some(Ipv4Addr::new(10, 9, 8, 7)));
                    assert!(asked.contains(&f.iface_index));
                }
            }
        }
    }
}
