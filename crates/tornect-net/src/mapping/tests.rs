use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::fake::{FakeIgd, FakePcp, IgdAnswer, IgdConfig, IgdHeard, PcpHeard, PcpMode};
use super::*;

fn request() -> MapRequest {
    MapRequest {
        gateway: Ipv4Addr::new(192, 168, 77, 1),
        client: Ipv4Addr::new(192, 168, 77, 203),
        internal_port: NonZeroU16::new(50_417).unwrap(),
        lease: MAP_LEASE,
        protocols: MapProtocols::ALL,
        deadline: Instant::now() + Duration::from_millis(1500),
    }
}

/// A handle that grants `grants` in turn and counts its releases.
struct Scripted {
    grants: Vec<Result<Duration, MapFail>>,
    released: Arc<AtomicUsize>,
}

impl MappingHandle for Scripted {
    fn renew(&mut self) -> BoxFuture<'_, Result<Duration, MapFail>> {
        let next = self.grants.remove(0);
        Box::pin(async move { next })
    }

    fn release(self: Box<Self>) -> BoxFuture<'static, ()> {
        let released = Arc::clone(&self.released);
        Box::pin(async move {
            released.fetch_add(1, Ordering::SeqCst);
        })
    }
}

#[tokio::test]
async fn no_mapper_answers_no_gateway() {
    let mapper: Arc<dyn PortMapper> = Arc::new(NoMapper);
    assert_eq!(
        mapper.map(request()).await.expect_err("no router"),
        MapFail::NoGateway
    );
}

/// A renewal's grant replaces the last one; a failed renewal keeps it;
/// the release runs only when its future does, after the mapping is
/// gone.
#[tokio::test]
async fn a_mapping_renews_through_its_handle_and_releases_once() {
    let released = Arc::new(AtomicUsize::new(0));
    let mut mapping = Mapping::new(
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 50_417),
        MapVia::Pcp,
        Duration::from_secs(120),
        Box::new(Scripted {
            grants: vec![Ok(MAP_LEASE), Err(MapFail::Timeout)],
            released: Arc::clone(&released),
        }),
    );
    assert_eq!(mapping.renew().await, Ok(MAP_LEASE));
    assert_eq!(mapping.granted, MAP_LEASE);
    assert_eq!(mapping.renew().await, Err(MapFail::Timeout));
    assert_eq!(mapping.granted, MAP_LEASE);
    let release = mapping.release();
    assert_eq!(released.load(Ordering::SeqCst), 0);
    release.await;
    assert_eq!(released.load(Ordering::SeqCst), 1);
}

#[test]
fn events_become_router_port_lines_with_the_protocol_only() {
    for (event, line) in [
        (MapEvent::Opened(MapVia::Pcp), "opened pcp"),
        (MapEvent::Closed(MapVia::NatPmp), "closed nat-pmp"),
        (MapEvent::CloseFailed(MapVia::Upnp), "close-failed upnp"),
        (
            MapEvent::LeftoverRemoved(MapVia::Pcp),
            "leftover-removed pcp",
        ),
    ] {
        assert_eq!(event.router_port().detail(), line);
    }
}

#[test]
fn protocols_any() {
    assert!(!MapProtocols::NONE.any());
    assert!(MapProtocols::ALL.any());
    assert!(
        MapProtocols {
            nat_pmp: true,
            ..MapProtocols::NONE
        }
        .any()
    );
    assert_eq!(MapProtocols::default(), MapProtocols::NONE);
}

/// Decision M1-83: neither a request nor a mapping prints an address
/// or a port, and no failure names one.
#[test]
fn no_debug_or_message_prints_an_address_or_a_port() {
    let mapping = Mapping::new(
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 50_417),
        MapVia::Upnp,
        MAP_LEASE,
        Box::new(Scripted {
            grants: Vec::new(),
            released: Arc::default(),
        }),
    );
    let mut text = format!("{:?} {:#?} {mapping:?} {mapping:#?}", request(), request());
    for fail in [
        MapFail::NoGateway,
        MapFail::Timeout,
        MapFail::Refused,
        MapFail::PermanentOnly,
        MapFail::NotGlobal,
        MapFail::Io,
    ] {
        text.push_str(&format!(" {fail} {fail:?}"));
    }
    for piece in ["192", "168", "77", "203", "113", "50417", "50_417"] {
        assert!(!text.contains(piece), "\"{piece}\" in {text}");
    }
    for said in ["v4 private", "v4 unusable", "Upnp", "600s"] {
        assert!(text.contains(said), "\"{said}\" missing in {text}");
    }
}

/// Renewal fires at half the grant, within 30 s and 300 s.
#[test]
fn renewal_waits_half_the_grant_within_bounds() {
    let s = Duration::from_secs;
    assert_eq!(renewal_delay(s(120)), s(60));
    assert_eq!(renewal_delay(s(600)), s(300));
    assert_eq!(renewal_delay(s(7200)), s(300));
    assert_eq!(renewal_delay(s(40)), s(30));
    assert_eq!(renewal_delay(Duration::ZERO), s(30));
}

/// A handle that records when each renewal was asked for.
struct Timed {
    grants: Vec<Result<Duration, MapFail>>,
    asked: Arc<Mutex<Vec<Duration>>>,
    start: tokio::time::Instant,
}

impl MappingHandle for Timed {
    fn renew(&mut self) -> BoxFuture<'_, Result<Duration, MapFail>> {
        self.asked.lock().unwrap().push(self.start.elapsed());
        let next = if self.grants.is_empty() {
            Ok(MAP_LEASE)
        } else {
            self.grants.remove(0)
        };
        Box::pin(async move { next })
    }

    fn release(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }
}

/// Design §12.2: a 120 s grant renews at 60 s; a 600 s grant 300 s later;
/// a failed renewal is tried again 30 s later; the mapping never lapses.
#[tokio::test(start_paused = true)]
async fn keep_renewed_follows_each_grant() {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let start = tokio::time::Instant::now();
    let mut mapping = Mapping::new(
        SocketAddrV4::new(Ipv4Addr::new(64, 0, 0, 9), 50_417),
        MapVia::Pcp,
        Duration::from_secs(120),
        Box::new(Timed {
            grants: vec![
                Ok(Duration::from_secs(120)),
                Ok(MAP_LEASE),
                Err(MapFail::Timeout),
                Ok(MAP_LEASE),
            ],
            asked: Arc::clone(&asked),
            start,
        }),
    );
    let _ = tokio::time::timeout(Duration::from_secs(800), mapping.keep_renewed()).await;
    let s = Duration::from_secs;
    assert_eq!(
        *asked.lock().unwrap(),
        [s(60), s(120), s(420), s(450), s(750)]
    );
    assert_eq!(mapping.granted, MAP_LEASE);
}

/// A mapping released on drop with no runtime anywhere spawns nothing and
/// does not panic; one released explicitly no longer releases on drop.
#[test]
fn a_mapping_without_a_runtime_releases_nothing_on_drop() {
    let released = Arc::new(AtomicUsize::new(0));
    let tracker = ReleaseTracker::new();
    let mapping = Mapping::new(
        SocketAddrV4::new(Ipv4Addr::new(64, 0, 0, 9), 50_417),
        MapVia::Pcp,
        MAP_LEASE,
        Box::new(Scripted {
            grants: Vec::new(),
            released: Arc::clone(&released),
        }),
    )
    .release_on_drop(None, tracker.clone());
    drop(mapping);
    assert_eq!(released.load(Ordering::SeqCst), 0);
    assert_eq!(tracker.running(), 0);
}

/// A release that hangs is cut at [`MAP_RELEASE_CAP`]; `wait` returns as
/// soon as none runs, and reports one still running past its bound.
#[tokio::test(start_paused = true)]
async fn releases_are_capped_and_waited_for() {
    let tracker = ReleaseTracker::new();
    assert!(tracker.wait(Duration::ZERO).await);
    let rt = Handle::current();
    tracker.spawn(&rt, Box::pin(tokio::time::sleep(Duration::from_secs(3600))));
    assert_eq!(tracker.running(), 1);
    assert!(!tracker.wait(Duration::from_millis(500)).await);
    let start = tokio::time::Instant::now();
    assert!(tracker.wait(Duration::from_secs(5)).await);
    assert!(start.elapsed() <= MAP_RELEASE_CAP);
    assert_eq!(tracker.running(), 0);
}

// --- The real mapper against fake routers on loopback addresses. ---

/// A loopback address of its own for each test's fakes (crab_nat always
/// sends to port 5351).
fn loopback() -> Ipv4Addr {
    static NEXT: AtomicU8 = AtomicU8::new(40);
    Ipv4Addr::new(127, 0, 0, NEXT.fetch_add(1, Ordering::SeqCst))
}

/// A public address (`64.0.0.0/8` is unicast and global).
fn public(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(64, 0, 0, last)
}

const PORT: u16 = 50_417;

#[derive(Default)]
struct Events(Mutex<Vec<MapEvent>>);

impl MapEvents for Events {
    fn on_event(&self, ev: MapEvent) {
        self.0.lock().unwrap().push(ev);
    }
}

impl Events {
    fn seen(&self) -> Vec<MapEvent> {
        self.0.lock().unwrap().clone()
    }
}

/// A mapper on `dir` whose UPnP search asks `igd` (unicast) and
/// `multicast`, trusting `trusted`.
fn mapper_with(
    dir: &Path,
    events: &Arc<Events>,
    ssdp_port: u16,
    multicast: SocketAddr,
    trusted: Vec<IpAddr>,
) -> RealMapper {
    let sink: Arc<dyn MapEvents> = Arc::clone(events) as _;
    RealMapper::new(MappingLedger::new(dir), sink, ReleaseTracker::new())
        .on_loopback(ssdp_port, multicast, trusted)
}

/// A mapper for PCP and NAT-PMP only.
fn nat_mapper(dir: &Path, events: &Arc<Events>) -> RealMapper {
    mapper_with(
        dir,
        events,
        9,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        Vec::new(),
    )
}

fn nat_only() -> MapProtocols {
    MapProtocols {
        upnp: false,
        ..MapProtocols::ALL
    }
}

fn upnp_only() -> MapProtocols {
    MapProtocols {
        upnp: true,
        ..MapProtocols::NONE
    }
}

fn ask(gateway: Ipv4Addr, protocols: MapProtocols, within: Duration) -> MapRequest {
    MapRequest {
        gateway,
        client: Ipv4Addr::LOCALHOST,
        internal_port: NonZeroU16::new(PORT).unwrap(),
        lease: MAP_LEASE,
        protocols,
        deadline: Instant::now() + within,
    }
}

fn pcp_maps(heard: &[PcpHeard]) -> Vec<(u32, [u32; 3])> {
    heard
        .iter()
        .filter_map(|h| match h {
            PcpHeard::Map {
                lifetime, nonce, ..
            } => Some((*lifetime, *nonce)),
            _ => None,
        })
        .collect()
}

/// PCP grants a public mapping: the nonce on the wire is the one the
/// ledger holds (written before the request), the lease asked is 600 s,
/// and the release deletes it by that nonce and forgets the entry.
#[tokio::test]
async fn pcp_maps_a_public_port_with_our_nonce_and_releases_it() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = loopback();
    let router = FakePcp::start(
        gw,
        PcpMode::Pcp {
            external: public(7),
            max_lifetime: 3600,
        },
    )
    .await
    .expect("a fake PCP router");
    let mapper = nat_mapper(home.path(), &events);
    let mapping = mapper
        .map(ask(gw, nat_only(), Duration::from_secs(3)))
        .await
        .expect("a PCP mapping");
    assert_eq!(mapping.external, SocketAddrV4::new(public(7), PORT));
    assert_eq!(mapping.via, MapVia::Pcp);
    assert_eq!(mapping.granted, MAP_LEASE);
    let entries = mapper.ledger().entries();
    assert_eq!(entries.len(), 1);
    let nonce = entries[0].pcp_nonce.expect("a PCP entry names its nonce");
    assert_eq!(entries[0].via, MapVia::Pcp);
    assert_eq!(entries[0].gateway, gw);
    assert_eq!(entries[0].internal_port, PORT);
    assert_eq!(pcp_maps(&router.heard()), [(600, nonce)]);
    assert_eq!(events.seen(), [MapEvent::Opened(MapVia::Pcp)]);

    mapping.release().await;
    assert_eq!(pcp_maps(&router.heard()), [(600, nonce), (0, nonce)]);
    assert!(mapper.ledger().entries().is_empty());
    assert_eq!(
        events.seen(),
        [MapEvent::Opened(MapVia::Pcp), MapEvent::Closed(MapVia::Pcp)]
    );
}

/// A router whose own address is private (it sits behind another NAT):
/// the mapping is released at once and the request fails `NotGlobal`.
#[tokio::test]
async fn a_private_external_address_is_released_as_not_global() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = loopback();
    let router = FakePcp::start(
        gw,
        PcpMode::Pcp {
            external: Ipv4Addr::new(100, 64, 3, 4),
            max_lifetime: 600,
        },
    )
    .await
    .unwrap();
    let mapper = nat_mapper(home.path(), &events);
    assert_eq!(
        mapper
            .map(ask(gw, nat_only(), Duration::from_secs(3)))
            .await
            .expect_err("not public"),
        MapFail::NotGlobal
    );
    assert!(mapper.releases().wait(Duration::from_secs(1)).await);
    let maps = pcp_maps(&router.heard());
    assert_eq!(maps.len(), 2, "{maps:?}");
    assert_eq!((maps[0].0, maps[1].0), (600, 0));
    assert_eq!(maps[0].1, maps[1].1, "deleted by its nonce");
    assert!(mapper.ledger().entries().is_empty());
    assert_eq!(
        events.seen(),
        [MapEvent::Opened(MapVia::Pcp), MapEvent::Closed(MapVia::Pcp)]
    );
}

/// A NAT-PMP-only router answers PCP with "unsupported version": NAT-PMP
/// is asked for the external address, then the mapping; dropped inside a
/// runtime, the mapping deletes its own port (never every port) within a
/// second.
#[tokio::test]
async fn a_nat_pmp_router_maps_after_pcp_and_releases_on_drop() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = loopback();
    let router = FakePcp::start(
        gw,
        PcpMode::NatPmpOnly {
            external: public(8),
            max_lifetime: 7200,
        },
    )
    .await
    .unwrap();
    let mapper = nat_mapper(home.path(), &events);
    let mapping = mapper
        .map(ask(gw, nat_only(), Duration::from_secs(3)))
        .await
        .expect("a NAT-PMP mapping");
    assert_eq!(mapping.via, MapVia::NatPmp);
    assert_eq!(mapping.external, SocketAddrV4::new(public(8), PORT));
    assert_eq!(mapping.granted, MAP_LEASE);
    let heard = router.heard();
    assert!(matches!(heard[0], PcpHeard::Map { lifetime: 600, .. }));
    assert_eq!(
        heard[1..],
        [
            PcpHeard::NatPmpAddress,
            PcpHeard::NatPmpMap {
                lifetime: 600,
                internal_port: PORT,
                external_port: PORT
            }
        ]
    );
    assert_eq!(mapper.ledger().entries()[0].via, MapVia::NatPmp);

    drop(mapping);
    assert!(mapper.releases().wait(Duration::from_secs(1)).await);
    assert_eq!(
        router.heard().last(),
        Some(&PcpHeard::NatPmpMap {
            lifetime: 0,
            internal_port: PORT,
            external_port: 0
        })
    );
    assert!(mapper.ledger().entries().is_empty());
    assert_eq!(
        events.seen(),
        [
            MapEvent::Opened(MapVia::NatPmp),
            MapEvent::Closed(MapVia::NatPmp)
        ]
    );
}

/// A refusal is an answer: no mapping, no entry left, nothing more asked.
#[tokio::test]
async fn a_refusal_leaves_no_entry() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = loopback();
    let router = FakePcp::start(gw, PcpMode::Refuse(2)).await.unwrap();
    let mapper = nat_mapper(home.path(), &events);
    assert_eq!(
        mapper
            .map(ask(gw, nat_only(), Duration::from_secs(3)))
            .await
            .expect_err("refused"),
        MapFail::Refused
    );
    assert_eq!(router.heard().len(), 1);
    assert!(mapper.ledger().entries().is_empty());
    assert!(events.seen().is_empty());
}

/// A PCP request that gets no answer leaves its entry (written before
/// it) for the next start; that start's sweep deletes it from the router
/// in use by its nonce, reports `LeftoverRemoved`, and leaves nothing.
#[tokio::test]
async fn a_silent_router_leaves_its_entry_for_the_next_sweep() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = loopback();
    let router = FakePcp::start(gw, PcpMode::Silent).await.unwrap();
    let mapper = nat_mapper(home.path(), &events);
    assert_eq!(
        mapper
            .map(ask(gw, nat_only(), Duration::from_secs(3)))
            .await
            .expect_err("no answer"),
        MapFail::Timeout
    );
    let entries = mapper.ledger().entries();
    assert_eq!(entries.len(), 1);
    let nonce = entries[0].pcp_nonce.unwrap();
    drop(mapper);

    router.set_mode(PcpMode::Pcp {
        external: public(9),
        max_lifetime: 600,
    });
    let next = nat_mapper(home.path(), &events);
    let here = Router {
        gateway: gw,
        client: Ipv4Addr::LOCALHOST,
    };
    let report = next.sweep(async move { Some(here) }).await;
    assert_eq!(
        report,
        SweepReport {
            removed: 1,
            ..SweepReport::default()
        }
    );
    assert_eq!(pcp_maps(&router.heard()).last(), Some(&(0, nonce)));
    assert_eq!(events.seen(), [MapEvent::LeftoverRemoved(MapVia::Pcp)]);
    assert_eq!(MappingLedger::leftovers(home.path()), 0);
    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
}

/// A renewal asks for the full lease again, with the same nonce and the
/// external address granted, whatever the router granted last time.
#[tokio::test]
async fn a_renewal_asks_for_the_full_lease_again() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = loopback();
    let router = FakePcp::start(
        gw,
        PcpMode::Pcp {
            external: public(10),
            max_lifetime: 120,
        },
    )
    .await
    .unwrap();
    let mapper = nat_mapper(home.path(), &events);
    let mut mapping = mapper
        .map(ask(gw, nat_only(), Duration::from_secs(3)))
        .await
        .unwrap();
    assert_eq!(mapping.granted, Duration::from_secs(120));
    assert_eq!(renewal_delay(mapping.granted), Duration::from_secs(60));
    assert_eq!(mapping.renew().await, Ok(Duration::from_secs(120)));
    let heard = router.heard();
    let PcpHeard::Map { nonce, .. } = heard[0] else {
        panic!("{heard:?}")
    };
    assert_eq!(
        heard[1],
        PcpHeard::Map {
            lifetime: 600,
            nonce,
            internal_port: PORT,
            suggested_port: PORT,
            suggested_ip: public(10),
        }
    );
    mapping.release().await;
}

/// A crash (the mapping never released, the process gone) leaves the
/// ledger; a sweep while the owner still runs takes nothing; the sweep of
/// the next start keeps what belongs to another router and removes the
/// rest.
#[tokio::test]
async fn a_crash_leaves_the_ledger_for_the_next_start() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = loopback();
    let router = FakePcp::start(
        gw,
        PcpMode::Pcp {
            external: public(11),
            max_lifetime: 600,
        },
    )
    .await
    .unwrap();
    let mapper = nat_mapper(home.path(), &events);
    let mapping = mapper
        .map(ask(gw, nat_only(), Duration::from_secs(3)))
        .await
        .unwrap();
    let here = Router {
        gateway: gw,
        client: Ipv4Addr::LOCALHOST,
    };
    let other = nat_mapper(home.path(), &events);
    assert_eq!(
        other.sweep(async move { Some(here) }).await,
        SweepReport::default(),
        "a running owner's mappings are never swept"
    );
    mapper.ledger().abandon();
    std::mem::forget(mapping);
    drop(mapper);
    assert_eq!(MappingLedger::leftovers(home.path()), 1);

    let elsewhere = Router {
        gateway: Ipv4Addr::new(192, 168, 9, 1),
        client: Ipv4Addr::LOCALHOST,
    };
    let report = other.sweep(async move { Some(elsewhere) }).await;
    assert_eq!(report.kept, 1, "{report:?}");
    assert_eq!(
        pcp_maps(&router.heard()).len(),
        1,
        "no other router is asked"
    );
    assert_eq!(MappingLedger::leftovers(home.path()), 1);

    let report = other.sweep(async move { Some(here) }).await;
    assert_eq!(report.removed, 1, "{report:?}");
    assert_eq!(pcp_maps(&router.heard()).last().map(|m| m.0), Some(0));
    assert_eq!(MappingLedger::leftovers(home.path()), 0);
    assert_eq!(
        events.seen(),
        [
            MapEvent::Opened(MapVia::Pcp),
            MapEvent::LeftoverRemoved(MapVia::Pcp)
        ]
    );
}

/// A mapping dropped on a thread outside any runtime context releases on
/// the runtime it was made on, within a second.
#[test]
fn a_mapping_dropped_outside_the_runtime_releases_on_its_own() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = loopback();
    let (router, mapper, mapping) = rt.block_on(async {
        let router = FakePcp::start(
            gw,
            PcpMode::Pcp {
                external: public(12),
                max_lifetime: 600,
            },
        )
        .await
        .unwrap();
        let mapper = nat_mapper(home.path(), &events);
        let mapping = mapper
            .map(ask(gw, nat_only(), Duration::from_secs(3)))
            .await
            .unwrap();
        (router, mapper, mapping)
    });
    assert!(Handle::try_current().is_err());
    let start = Instant::now();
    drop(mapping);
    assert!(rt.block_on(mapper.releases().wait(Duration::from_secs(2))));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(pcp_maps(&router.heard()).last().map(|m| m.0), Some(0));
    assert_eq!(
        events.seen(),
        [MapEvent::Opened(MapVia::Pcp), MapEvent::Closed(MapVia::Pcp)]
    );
    drop(router);
}

/// Nothing is sent without a protocol, or when the gateway or the client
/// is not a private address (the real wire admits no loopback).
#[tokio::test]
async fn no_router_is_asked_outside_the_preconditions() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = loopback();
    let router = FakePcp::start(
        gw,
        PcpMode::Pcp {
            external: public(13),
            max_lifetime: 600,
        },
    )
    .await
    .unwrap();
    let on_loopback = nat_mapper(home.path(), &events);
    assert_eq!(
        on_loopback
            .map(ask(gw, MapProtocols::NONE, Duration::from_secs(3)))
            .await
            .expect_err("no protocol"),
        MapFail::NoGateway
    );
    let sink: Arc<dyn MapEvents> = Arc::clone(&events) as _;
    let real = RealMapper::new(MappingLedger::new(home.path()), sink, ReleaseTracker::new());
    for (gateway, client) in [
        (gw, Ipv4Addr::new(192, 168, 1, 20)),
        (public(1), Ipv4Addr::new(192, 168, 1, 20)),
        (Ipv4Addr::new(192, 168, 1, 1), public(2)),
    ] {
        let mut req = ask(gateway, MapProtocols::ALL, Duration::from_secs(3));
        req.client = client;
        assert_eq!(
            real.map(req).await.expect_err("not admitted"),
            MapFail::NoGateway
        );
    }
    assert!(router.heard().is_empty());
    assert!(real.ledger().entries().is_empty());
    assert!(events.seen().is_empty());
}

// --- UPnP-IGD against FakeIgd. ---

/// A mapper whose unicast search asks `gw` and whose multicast one
/// reaches `multicast` (an unused port when `None`).
fn upnp_mapper(
    dir: &Path,
    events: &Arc<Events>,
    gw: &FakeIgd,
    multicast: Option<&FakeIgd>,
) -> RealMapper {
    let mut trusted = vec![IpAddr::V4(gw.ip())];
    let to = match multicast {
        Some(other) => {
            trusted.push(IpAddr::V4(other.ip()));
            other.ssdp()
        }
        None => SocketAddr::from((gw.ip(), 9)),
    };
    mapper_with(dir, events, gw.ssdp_port(), to, trusted)
}

fn controls(heard: &[IgdHeard]) -> Vec<IgdHeard> {
    heard
        .iter()
        .filter(|h| !matches!(h, IgdHeard::Search | IgdHeard::Describe))
        .cloned()
        .collect()
}

fn add_port(external_port: u16) -> IgdHeard {
    IgdHeard::AddPort {
        external_port,
        internal_port: PORT,
        lease: 600,
        description: "Tornect".to_owned(),
    }
}

/// `AddPortMapping` for the same port with a 600 s lease, the external
/// address checked, and a `DeletePortMapping` of it when the mapping is
/// dropped; the gateway is asked by unicast, so the other responder on the
/// network hears nothing at all.
#[tokio::test]
async fn upnp_maps_by_unicast_and_deletes_on_drop() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = FakeIgd::start(loopback(), IgdConfig::granting(public(20)))
        .await
        .unwrap();
    let bystander = FakeIgd::start(loopback(), IgdConfig::granting(public(21)))
        .await
        .unwrap();
    let mapper = upnp_mapper(home.path(), &events, &gw, Some(&bystander));
    let mapping = mapper
        .map(ask(gw.ip(), upnp_only(), Duration::from_secs(3)))
        .await
        .expect("a UPnP mapping");
    assert_eq!(mapping.via, MapVia::Upnp);
    assert_eq!(mapping.external, SocketAddrV4::new(public(20), PORT));
    assert_eq!(mapping.granted, MAP_LEASE);
    assert_eq!(
        controls(&gw.heard()),
        [add_port(PORT), IgdHeard::ExternalIp]
    );
    assert!(bystander.heard().is_empty(), "{:?}", bystander.heard());
    let entries = mapper.ledger().entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        (entries[0].via, entries[0].external_port),
        (MapVia::Upnp, Some(PORT))
    );

    drop(mapping);
    assert!(mapper.releases().wait(Duration::from_secs(1)).await);
    assert_eq!(
        controls(&gw.heard()).last(),
        Some(&IgdHeard::DeletePort {
            external_port: PORT
        })
    );
    assert!(mapper.ledger().entries().is_empty());
    assert_eq!(
        events.seen(),
        [
            MapEvent::Opened(MapVia::Upnp),
            MapEvent::Closed(MapVia::Upnp)
        ]
    );
}

/// The port taken (718): `AddAnyPortMapping`, whose port the ledger learns
/// and the release deletes.
#[tokio::test]
async fn a_taken_port_falls_back_to_any_port() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let mut config = IgdConfig::granting(public(22));
    config.add_port = IgdAnswer::Fault(718);
    config.any_port = 50_999;
    let gw = FakeIgd::start(loopback(), config).await.unwrap();
    let mapper = upnp_mapper(home.path(), &events, &gw, None);
    let mapping = mapper
        .map(ask(gw.ip(), upnp_only(), Duration::from_secs(3)))
        .await
        .expect("a UPnP mapping on another port");
    assert_eq!(mapping.external, SocketAddrV4::new(public(22), 50_999));
    assert_eq!(
        controls(&gw.heard()),
        [
            add_port(PORT),
            IgdHeard::AddAnyPort {
                internal_port: PORT,
                lease: 600
            },
            IgdHeard::ExternalIp
        ]
    );
    assert_eq!(mapper.ledger().entries()[0].external_port, Some(50_999));
    mapping.release().await;
    assert_eq!(
        controls(&gw.heard()).last(),
        Some(&IgdHeard::DeletePort {
            external_port: 50_999
        })
    );
    assert!(mapper.ledger().entries().is_empty());
}

/// A router that grants only permanent mappings (725), to
/// `AddPortMapping` or to `AddAnyPortMapping`: no mapping, and lease 0 is
/// never asked for.
#[tokio::test]
async fn permanent_only_routers_get_no_mapping_and_no_lease_zero() {
    for (add, any) in [
        (IgdAnswer::Fault(725), Some(IgdAnswer::Ok)),
        (IgdAnswer::Fault(718), Some(IgdAnswer::Fault(725))),
    ] {
        let home = tempfile::tempdir().unwrap();
        let events = Arc::new(Events::default());
        let mut config = IgdConfig::granting(public(23));
        config.add_port = add;
        config.add_any_port = any;
        let gw = FakeIgd::start(loopback(), config).await.unwrap();
        let mapper = upnp_mapper(home.path(), &events, &gw, None);
        assert_eq!(
            mapper
                .map(ask(gw.ip(), upnp_only(), Duration::from_secs(3)))
                .await
                .expect_err("permanent only"),
            MapFail::PermanentOnly
        );
        let heard = controls(&gw.heard());
        assert!(!heard.is_empty());
        for h in &heard {
            match h {
                IgdHeard::AddPort { lease, .. } | IgdHeard::AddAnyPort { lease, .. } => {
                    assert_eq!(*lease, 600, "{heard:?}");
                }
                other => panic!("unexpected {other:?} in {heard:?}"),
            }
        }
        assert_eq!(
            heard.len(),
            if add == IgdAnswer::Fault(725) { 1 } else { 2 }
        );
        assert!(mapper.ledger().entries().is_empty());
        assert!(events.seen().is_empty());
    }
}

/// The gateway does not answer the unicast search; the multicast one
/// finds another device: its description is read, but it is not the
/// gateway, so it gets no control request and the request fails.
#[tokio::test]
async fn a_responder_that_is_not_the_gateway_is_never_used() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let mut config = IgdConfig::granting(public(24));
    config.answer_search = false;
    let gw = FakeIgd::start(loopback(), config).await.unwrap();
    let impostor = FakeIgd::start(loopback(), IgdConfig::granting(public(25)))
        .await
        .unwrap();
    let mapper = upnp_mapper(home.path(), &events, &gw, Some(&impostor));
    assert_eq!(
        mapper
            .map(ask(gw.ip(), upnp_only(), Duration::from_secs(3)))
            .await
            .expect_err("no gateway"),
        MapFail::NoGateway
    );
    assert!(gw.heard().iter().all(|h| *h == IgdHeard::Search));
    assert!(!gw.heard().is_empty(), "the gateway was asked first");
    let heard = impostor.heard();
    assert!(heard.contains(&IgdHeard::Search), "{heard:?}");
    assert!(controls(&heard).is_empty(), "{heard:?}");
    assert!(mapper.ledger().entries().is_empty());
}

/// A UPnP router whose own address is private: the mapping is deleted
/// again and the request fails `NotGlobal`.
#[tokio::test]
async fn a_private_upnp_address_is_released_as_not_global() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = FakeIgd::start(
        loopback(),
        IgdConfig::granting(Ipv4Addr::new(192, 168, 0, 2)),
    )
    .await
    .unwrap();
    let mapper = upnp_mapper(home.path(), &events, &gw, None);
    assert_eq!(
        mapper
            .map(ask(gw.ip(), upnp_only(), Duration::from_secs(3)))
            .await
            .expect_err("not public"),
        MapFail::NotGlobal
    );
    assert!(mapper.releases().wait(Duration::from_secs(1)).await);
    assert_eq!(
        controls(&gw.heard()),
        [
            add_port(PORT),
            IgdHeard::ExternalIp,
            IgdHeard::DeletePort {
                external_port: PORT
            }
        ]
    );
    assert!(mapper.ledger().entries().is_empty());
}

/// PCP and UPnP at once: a public PCP mapping wins, and the UPnP router
/// gets no control request; with PCP silent, the UPnP router maps.
#[tokio::test]
async fn pcp_wins_and_upnp_maps_only_without_it() {
    for silent in [false, true] {
        let home = tempfile::tempdir().unwrap();
        let events = Arc::new(Events::default());
        let ip = loopback();
        let mode = if silent {
            PcpMode::Silent
        } else {
            PcpMode::Pcp {
                external: public(26),
                max_lifetime: 600,
            }
        };
        let pcp = FakePcp::start(ip, mode).await.unwrap();
        let igd = FakeIgd::start(ip, IgdConfig::granting(public(27)))
            .await
            .unwrap();
        let mapper = upnp_mapper(home.path(), &events, &igd, None);
        let mapping = mapper
            .map(ask(ip, MapProtocols::ALL, Duration::from_secs(3)))
            .await
            .expect("a mapping");
        if silent {
            assert_eq!(mapping.via, MapVia::Upnp);
            assert_eq!(
                controls(&igd.heard()),
                [add_port(PORT), IgdHeard::ExternalIp]
            );
        } else {
            assert_eq!(mapping.via, MapVia::Pcp);
            assert!(controls(&igd.heard()).is_empty(), "{:?}", igd.heard());
        }
        assert_eq!(pcp_maps(&pcp.heard()).len(), if silent { 2 } else { 1 });
        mapping.release().await;
    }
}

/// A UPnP mapping left by a crash is removed by the next start's sweep
/// from the gateway in use, found by unicast.
#[tokio::test]
async fn the_sweep_removes_a_upnp_leftover() {
    let home = tempfile::tempdir().unwrap();
    let events = Arc::new(Events::default());
    let gw = FakeIgd::start(loopback(), IgdConfig::granting(public(28)))
        .await
        .unwrap();
    let mapper = upnp_mapper(home.path(), &events, &gw, None);
    let mapping = mapper
        .map(ask(gw.ip(), upnp_only(), Duration::from_secs(3)))
        .await
        .unwrap();
    mapper.ledger().abandon();
    std::mem::forget(mapping);
    drop(mapper);
    let next = upnp_mapper(home.path(), &events, &gw, None);
    let here = Router {
        gateway: gw.ip(),
        client: Ipv4Addr::LOCALHOST,
    };
    let report = next.sweep(async move { Some(here) }).await;
    assert_eq!(report.removed, 1, "{report:?}");
    assert_eq!(
        controls(&gw.heard()).last(),
        Some(&IgdHeard::DeletePort {
            external_port: PORT
        })
    );
    assert_eq!(
        events.seen(),
        [
            MapEvent::Opened(MapVia::Upnp),
            MapEvent::LeftoverRemoved(MapVia::Upnp)
        ]
    );
    assert_eq!(MappingLedger::leftovers(home.path()), 0);
}

/// Decision M1-83: the router and sweep values print no address.
#[test]
fn router_values_print_no_address() {
    let here = Router {
        gateway: Ipv4Addr::new(192, 168, 77, 1),
        client: Ipv4Addr::new(192, 168, 77, 203),
    };
    let text = format!("{here:?} {here:#?} {:?}", SweepReport::default());
    for piece in ["192", "168", "77", "203"] {
        assert!(!text.contains(piece), "\"{piece}\" in {text}");
    }
}
