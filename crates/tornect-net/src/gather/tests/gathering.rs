//! A link's internet gathering on [`MemNet`] in paused time (design §7.3,
//! §7.4, §7.5, §5.2 rows 6–7, §12.3): the router's head start, the
//! trickled batches and their order, the budget, renewal and release, the
//! calls a link that gathers nothing never makes, the VPN rule, a side with
//! no host candidate, and (step B7) the ranks the gathered public addresses
//! give the checklist, through two links.
//!
//! The router is scripted ([`Scripted`]); the in-memory NATs and routers of
//! step B8 are not needed for what is tested here: a STUN server that
//! answers a fixed external address stands for a NAT.

use super::*;

use std::net::SocketAddrV4;

use tornect_core::DeviceIdentity;
use zeroize::Zeroizing;

use crate::link::{DirectFail, DirectLink, DirectParams, Established, LocalBatch};
use crate::mapping::{MappingHandle, ReleaseTracker};
use crate::mem::{EnvCalls, Fate, MemAddr};

const TOKEN: [u8; 32] = [0x5a; 32];

fn device(seed: u8) -> Arc<DeviceIdentity> {
    Arc::new(DeviceIdentity::from_seed(&[seed; 32]))
}

fn pk(seed: u8) -> [u8; 32] {
    device(seed).verifying_key().to_bytes()
}

fn v4(text: &str) -> Ipv4Addr {
    text.parse().expect("an IPv4 address")
}

/// Internet-scope parameters of `me` (device `mine`) toward device `peer`.
fn params(me: TornectRole, mine: u8, peer: u8, gather: GatherConfig) -> DirectParams {
    DirectParams {
        me,
        identity: device(mine),
        peer_pk: pk(peer),
        session_token: Zeroizing::new(TOKEN),
        direct_port: None,
        scope: Scope::Internet,
        gather,
    }
}

/// STUN over `servers` (none: off) and the router `map` protocols.
fn config(servers: &[String], map: MapProtocols) -> GatherConfig {
    GatherConfig {
        stun_partition: servers.to_vec().into(),
        use_stun: !servers.is_empty(),
        map,
    }
}

// ---------------------------------------------------------------------------
// A scripted router.

/// How the scripted router answers.
#[derive(Debug, Clone, Copy)]
enum RouterAnswer {
    /// A mapping at `external` for `granted`, `after` the request.
    Grant {
        after: Duration,
        external: SocketAddrV4,
        granted: Duration,
    },
    /// `fail`, `after` the request.
    Fail { after: Duration, fail: MapFail },
    /// Nothing, ever.
    Silent,
}

/// What a scripted router saw.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Asked {
        at: Instant,
        gateway: Ipv4Addr,
        client: Ipv4Addr,
        port: u16,
        lease: Duration,
        protocols: MapProtocols,
        deadline: std::time::Instant,
    },
    Renewed(Instant),
    Released(Instant),
}

/// A router that answers as told, logging every request, renewal and
/// release; its mappings release themselves when dropped, through
/// `releases`.
struct Scripted {
    answer: RouterAnswer,
    seen: Arc<Mutex<Vec<Seen>>>,
    releases: ReleaseTracker,
}

impl Scripted {
    fn new(answer: RouterAnswer) -> Arc<Self> {
        Arc::new(Self {
            answer,
            seen: Arc::default(),
            releases: ReleaseTracker::new(),
        })
    }

    fn seen(&self) -> Vec<Seen> {
        lock(&self.seen).clone()
    }

    fn renewals(&self) -> Vec<Instant> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Renewed(at) => Some(at),
                _ => None,
            })
            .collect()
    }

    fn releases(&self) -> usize {
        self.seen()
            .iter()
            .filter(|s| matches!(s, Seen::Released(_)))
            .count()
    }

    /// Waits until a release ran and none is still running: a dropped
    /// mapping's release is spawned when the task that held it is dropped,
    /// a moment after the abort.
    async fn released(&self) {
        within(async {
            while self.releases() == 0 {
                tokio::time::sleep(ms(1)).await;
            }
        })
        .await;
        assert!(self.releases.wait(Duration::from_secs(1)).await);
    }
}

struct ScriptedHandle {
    seen: Arc<Mutex<Vec<Seen>>>,
    granted: Duration,
}

impl MappingHandle for ScriptedHandle {
    fn renew(&mut self) -> BoxFuture<'_, Result<Duration, MapFail>> {
        lock(&self.seen).push(Seen::Renewed(Instant::now()));
        let granted = self.granted;
        Box::pin(async move { Ok(granted) })
    }

    fn release(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            lock(&self.seen).push(Seen::Released(Instant::now()));
        })
    }
}

impl PortMapper for Scripted {
    fn map(&self, req: MapRequest) -> BoxFuture<'static, Result<Mapping, MapFail>> {
        lock(&self.seen).push(Seen::Asked {
            at: Instant::now(),
            gateway: req.gateway,
            client: req.client,
            port: req.internal_port.get(),
            lease: req.lease,
            protocols: req.protocols,
            deadline: req.deadline,
        });
        let answer = self.answer;
        let seen = Arc::clone(&self.seen);
        let releases = self.releases.clone();
        Box::pin(async move {
            match answer {
                RouterAnswer::Grant {
                    after,
                    external,
                    granted,
                } => {
                    tokio::time::sleep(after).await;
                    let handle = Box::new(ScriptedHandle { seen, granted });
                    Ok(Mapping::new(external, MapVia::Pcp, granted, handle)
                        .release_on_drop(None, releases))
                }
                RouterAnswer::Fail { after, fail } => {
                    tokio::time::sleep(after).await;
                    Err(fail)
                }
                RouterAnswer::Silent => std::future::pending().await,
            }
        })
    }
}

/// A [`MemHost`] whose route-source interface reports `gateway`, with the
/// scripted `router`; it resolves no names.
struct Routed {
    inner: MemHost,
    gateway: Option<Ipv4Addr>,
    router: Arc<Scripted>,
}

impl NetEnv for Routed {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        let read = self.inner.interfaces();
        let source = self.inner.route_sources().v4.map(IpAddr::V4);
        let gateway = self.gateway;
        Box::pin(async move {
            let mut addrs = read.await?;
            for a in &mut addrs {
                if Some(a.ip) == source {
                    a.gateway_v4 = gateway;
                }
            }
            Ok(addrs)
        })
    }

    fn route_sources(&self) -> RouteSources {
        self.inner.route_sources()
    }

    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp> {
        self.inner.bind(port)
    }

    fn resolve(&self, _host: &str, _port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
    }

    fn mapper(&self) -> Arc<dyn PortMapper> {
        Arc::clone(&self.router) as Arc<dyn PortMapper>
    }
}

impl World {
    /// A machine on the home LAN at `cidr` behind the router at
    /// 192.168.1.1 that answers as `answer`.
    fn routed(
        &self,
        cidr: &str,
        answer: RouterAnswer,
    ) -> (Arc<CountingEnv<Routed>>, Arc<Scripted>) {
        self.routed_spec(
            MachineSpec::on(self.home, cidr),
            Some(v4("192.168.1.1")),
            answer,
        )
    }

    fn routed_spec(
        &self,
        spec: MachineSpec,
        gateway: Option<Ipv4Addr>,
        answer: RouterAnswer,
    ) -> (Arc<CountingEnv<Routed>>, Arc<Scripted>) {
        let router = Scripted::new(answer);
        let env = CountingEnv::new(Routed {
            inner: self.net.machine(spec),
            gateway,
            router: Arc::clone(&router),
        });
        (env, router)
    }
}

/// The router's mapping in these tests.
const MAPPED: &str = "81.2.3.9:50000";

fn grant(after: u64) -> RouterAnswer {
    RouterAnswer::Grant {
        after: ms(after),
        external: MAPPED.parse().expect("an IPv4 socket address"),
        granted: Duration::from_secs(600),
    }
}

fn mapped(addr: &str) -> Candidate {
    Candidate {
        kind: CandidateKind::Mapped,
        addr: at(addr),
    }
}

fn reflexive(addr: &str) -> Candidate {
    Candidate {
        kind: CandidateKind::Srflx,
        addr: at(addr),
    }
}

/// A link's batches until `Done`, each with when it came (from `t0`).
async fn batches(link: &mut DirectLink, t0: Instant) -> Vec<(Duration, LocalBatch)> {
    let mut out = Vec::new();
    loop {
        let batch = within(link.next_local()).await;
        let done = batch == LocalBatch::Done;
        out.push((t0.elapsed(), batch));
        if done {
            return out;
        }
    }
}

/// The STUN datagrams a machine at `from` sent.
fn stun_sent(world: &World, from: &str, t0: Instant) -> Vec<(Duration, SocketAddr)> {
    world.requests(ip(from), t0)
}

// ---------------------------------------------------------------------------
// Head start, batches, budget.

/// Design §7.3, §7.5, §5.3: a router that grants a global mapping within
/// the head start skips STUN (no server hears of the session); the mapped
/// candidate is a batch of its own as it lands, then `Done` at once. The
/// request asks the route-source interface's gateway for the session
/// socket's port, for 600 s, by the budget's end.
#[tokio::test(start_paused = true)]
async fn a_mapping_within_the_head_start_skips_stun() {
    let world = World::new();
    let server = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let (env, router) = world.routed("192.168.1.20/24", grant(100));
    let t0 = Instant::now();
    let (mut link, offered) = DirectLink::start(
        params(
            TornectRole::Viewer,
            1,
            2,
            config(&[server.entry()], MapProtocols::ALL),
        ),
        env.clone(),
    )
    .await
    .expect("a link");
    let port = offered[0].addr.port();
    assert_eq!(
        offered,
        vec![Candidate {
            kind: CandidateKind::Host,
            addr: SocketAddr::new(ip("192.168.1.20"), port),
        }]
    );
    assert_eq!(
        batches(&mut link, t0).await,
        vec![
            (ms(100), LocalBatch::More(vec![mapped(MAPPED)])),
            (ms(100), LocalBatch::Done),
        ]
    );
    assert!(server.heard().is_empty());
    assert!(stun_sent(&world, "192.168.1.20", t0).is_empty());
    assert_eq!(
        router.seen(),
        vec![Seen::Asked {
            at: t0,
            gateway: v4("192.168.1.1"),
            client: v4("192.168.1.20"),
            port,
            lease: MAP_LEASE,
            protocols: MapProtocols::ALL,
            deadline: (t0 + GATHER_BUDGET).into_std(),
        }]
    );
    let stats = link.stats().gather;
    assert_eq!(
        stats,
        GatherStats {
            stun_planned: true,
            map_planned: true,
            mapped: Some(MapVia::Pcp),
            stun_skipped: true,
            batches: 1,
            done: true,
            ..GatherStats::default()
        }
    );
    let calls = env.calls();
    assert_eq!((calls.mappers, calls.resolves), (1, 0));
}

/// Design §7.3, §7.5: a router slower than the head start lets STUN start
/// at 250 ms; each candidate is its own batch in the order it lands
/// (server-reflexive first here), and `Done` follows the last.
#[tokio::test(start_paused = true)]
async fn a_slow_router_lets_stun_start_at_the_head_start() {
    let world = World::new();
    let server = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let (env, _router) = world.routed("192.168.1.20/24", grant(600));
    let t0 = Instant::now();
    let (mut link, _) = DirectLink::start(
        params(
            TornectRole::Host,
            2,
            1,
            config(&[server.entry()], MapProtocols::ALL),
        ),
        env.clone(),
    )
    .await
    .expect("a link");
    let got = batches(&mut link, t0).await;
    let sent = stun_sent(&world, "192.168.1.20", t0);
    assert_eq!(sent.len(), 1, "one request, answered");
    assert_eq!(sent[0], (MAPPING_HEAD_START, server.addr));
    assert_eq!(
        got,
        vec![
            (ms(290), LocalBatch::More(vec![reflexive(NAT)])),
            (ms(600), LocalBatch::More(vec![mapped(MAPPED)])),
            (ms(600), LocalBatch::Done),
        ]
    );
    let stats = link.stats().gather;
    assert!(stats.stun_ran && stats.srflx && !stats.stun_skipped);
    assert_eq!(stats.mapped, Some(MapVia::Pcp));
    assert_eq!((stats.batches, stats.duplicates), (2, 0));
}

/// A router that answers without a mapping before the head start starts
/// STUN at once, rather than at the end of a wait for nothing.
#[tokio::test(start_paused = true)]
async fn a_router_that_refuses_starts_stun_at_once() {
    let world = World::new();
    let server = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let (env, _router) = world.routed(
        "192.168.1.20/24",
        RouterAnswer::Fail {
            after: ms(50),
            fail: MapFail::Refused,
        },
    );
    let t0 = Instant::now();
    let (mut link, _) = DirectLink::start(
        params(
            TornectRole::Viewer,
            1,
            2,
            config(&[server.entry()], MapProtocols::ALL),
        ),
        env,
    )
    .await
    .expect("a link");
    let got = batches(&mut link, t0).await;
    assert_eq!(stun_sent(&world, "192.168.1.20", t0)[0].0, ms(50));
    assert_eq!(
        got,
        vec![
            (ms(90), LocalBatch::More(vec![reflexive(NAT)])),
            (ms(90), LocalBatch::Done),
        ]
    );
    let stats = link.stats().gather;
    assert_eq!(stats.map_failed, Some(MapFail::Refused));
    assert_eq!(stats.mapped, None);
}

/// Design §7.5: with the router and the server both silent, `Done` comes
/// at the budget, 1500 ms after the bind, and nothing was gathered.
#[tokio::test(start_paused = true)]
async fn gathering_ends_at_the_budget() {
    let world = World::new();
    let server = world.server("64.0.0.10/24", Answer::Silent);
    let (env, _router) = world.routed("192.168.1.20/24", RouterAnswer::Silent);
    let t0 = Instant::now();
    let (mut link, _) = DirectLink::start(
        params(
            TornectRole::Viewer,
            1,
            2,
            config(&[server.entry()], MapProtocols::ALL),
        ),
        env,
    )
    .await
    .expect("a link");
    assert_eq!(
        batches(&mut link, t0).await,
        vec![(GATHER_BUDGET, LocalBatch::Done)]
    );
    // The one server: its request at the head start, the retransmission
    // one RTO later.
    let sent: Vec<Duration> = stun_sent(&world, "192.168.1.20", t0)
        .into_iter()
        .map(|(at, _)| at)
        .collect();
    assert_eq!(sent, vec![ms(250), ms(750)]);
    let stats = link.stats().gather;
    assert!(stats.cut_at_budget && stats.done && stats.stun_ran);
    assert_eq!(
        (stats.mapped, stats.map_failed, stats.batches),
        (None, None, 0)
    );
}

/// Design §7.4: a mapping whose external address is not global is not
/// offered; it is released at once, and STUN starts.
#[tokio::test(start_paused = true)]
async fn a_mapping_that_is_not_global_is_released_and_not_offered() {
    let world = World::new();
    let server = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let (env, router) = world.routed(
        "192.168.1.20/24",
        RouterAnswer::Grant {
            after: ms(50),
            external: "100.64.9.9:50000".parse().unwrap(),
            granted: Duration::from_secs(600),
        },
    );
    let t0 = Instant::now();
    let (mut link, _) = DirectLink::start(
        params(
            TornectRole::Viewer,
            1,
            2,
            config(&[server.entry()], MapProtocols::ALL),
        ),
        env,
    )
    .await
    .expect("a link");
    assert_eq!(
        batches(&mut link, t0).await,
        vec![
            (ms(90), LocalBatch::More(vec![reflexive(NAT)])),
            (ms(90), LocalBatch::Done),
        ]
    );
    router.released().await;
    assert_eq!(router.releases(), 1);
    assert_eq!(link.stats().gather.map_failed, Some(MapFail::NotGlobal));
}

/// Design §7.4 "Renewal" and "Release": the link renews its mapping at
/// half the grant for as long as it lives, and its end releases it, by
/// `close` or by the last holder's drop, without anyone awaiting the
/// release.
#[tokio::test(start_paused = true)]
async fn the_mapping_is_renewed_with_the_link_and_released_at_its_end() {
    for close in [true, false] {
        let world = World::new();
        let (env, router) = world.routed(
            "192.168.1.20/24",
            RouterAnswer::Grant {
                after: ms(10),
                external: MAPPED.parse().unwrap(),
                granted: Duration::from_secs(120),
            },
        );
        let t0 = Instant::now();
        let (mut link, _) = DirectLink::start(
            params(TornectRole::Host, 2, 1, config(&[], MapProtocols::ALL)),
            env,
        )
        .await
        .expect("a link");
        assert_eq!(
            batches(&mut link, t0).await,
            vec![
                (ms(10), LocalBatch::More(vec![mapped(MAPPED)])),
                (ms(10), LocalBatch::Done),
            ]
        );
        tokio::time::sleep(Duration::from_secs(150)).await;
        assert_eq!(
            router.renewals(),
            vec![
                t0 + ms(10) + Duration::from_secs(60),
                t0 + ms(10) + Duration::from_secs(120)
            ],
            "every 60 s from the grant"
        );
        assert_eq!(router.releases(), 0, "not while the link lives");
        if close {
            link.close().await;
        } else {
            drop(link);
        }
        router.released().await;
        assert_eq!(router.releases(), 1, "close: {close}");
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert_eq!(router.renewals().len(), 2, "no renewal after the end");
    }
}

// ---------------------------------------------------------------------------
// What a link that gathers nothing never does.

/// Design §5.2, §12.3 "zero contact": same-site scope with every switch on,
/// and internet scope with every switch off, ask no router and no server,
/// resolve no name, and say `Done` at the bind; the environment sees the
/// interface read, the route sources, the bind and the loopback question,
/// once each.
#[tokio::test(start_paused = true)]
async fn a_link_that_gathers_nothing_asks_nobody() {
    let named = strings(&["stun.example.net:3478", "64.0.0.10:3478"]);
    for (scope, gather) in [
        (Scope::SameSite, config(&named, MapProtocols::ALL)),
        (Scope::Internet, config(&[], MapProtocols::NONE)),
        (Scope::Internet, GatherConfig::default()),
    ] {
        let world = World::new();
        let server = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
        let (env, router) = world.routed("192.168.1.20/24", grant(10));
        let t0 = Instant::now();
        let (mut link, _) = DirectLink::start(
            DirectParams {
                scope,
                ..params(TornectRole::Viewer, 1, 2, gather)
            },
            env.clone(),
        )
        .await
        .expect("a link");
        assert_eq!(
            batches(&mut link, t0).await,
            vec![(ms(0), LocalBatch::Done)]
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            env.calls(),
            EnvCalls {
                interfaces: 1,
                route_sources: 1,
                binds: 1,
                admit_loopback: 1,
                ..EnvCalls::default()
            },
            "{scope:?}"
        );
        assert!(router.seen().is_empty());
        assert!(server.heard().is_empty());
        assert!(world.net.wire().is_empty(), "not one datagram");
        assert_eq!(link.stats().gather, GatherStats::default());
    }
}

/// Design §7.2, §5.2 row 6: in VPN mode the router is never asked (zero
/// `mapper` calls) and no global host candidate is offered; STUN leaves
/// from the tunnel's address, through the tunnel.
#[tokio::test(start_paused = true)]
async fn vpn_mode_asks_no_router_and_stuns_through_the_tunnel() {
    let world = World::new();
    let tunnel = world.net.segment(LinkSpec::LAN);
    world.net.link(
        tunnel,
        world.internet,
        LinkSpec {
            latency: ms(20),
            loss: 0.0,
        },
    );
    let server = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let spec = MachineSpec {
        addrs: vec![
            MemAddr::new(world.home, "192.168.1.20/24"),
            MemAddr::new(world.home, "2a01:4f8:1:2::20/64"),
            MemAddr {
                kind: IfaceKind::Tunnel,
                ..MemAddr::new(tunnel, "10.8.0.2/24")
            },
        ],
        sources: Some(RouteSources {
            v4: Some(v4("10.8.0.2")),
            v6: Some("2a01:4f8:1:2::20".parse().unwrap()),
        }),
        ..MachineSpec::default()
    };
    let (env, router) = world.routed_spec(spec, Some(v4("10.8.0.1")), grant(10));
    let t0 = Instant::now();
    let (mut link, offered) = DirectLink::start(
        params(
            TornectRole::Viewer,
            1,
            2,
            config(&[server.entry()], MapProtocols::ALL),
        ),
        env.clone(),
    )
    .await
    .expect("a link");
    assert!(
        offered.iter().all(|c| c.addr.ip() == ip("192.168.1.20")),
        "only the LAN's private address"
    );
    assert_eq!(
        batches(&mut link, t0).await,
        vec![
            (ms(40), LocalBatch::More(vec![reflexive(NAT)])),
            (ms(40), LocalBatch::Done),
        ]
    );
    assert_eq!(env.calls().mappers, 0);
    assert!(router.seen().is_empty());
    let heard = server.heard();
    assert_eq!(heard.len(), 1);
    assert_eq!(heard[0].from.ip(), ip("10.8.0.2"), "through the tunnel");
    assert_eq!(link.stats().globals_offered, 0);
}

/// Design §7.1 "Without host candidates": a computer whose only address is
/// a carrier-grade NAT one offers no host candidate and still takes part
/// with its server-reflexive one; with nothing to gather it is
/// `NoAddresses`, and nothing is bound.
#[tokio::test(start_paused = true)]
async fn a_side_behind_a_carrier_gathers_or_has_no_address() {
    let world = World::new();
    let server = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let cgnat = |world: &World| {
        world.routed_spec(
            MachineSpec::on(world.home, "100.64.7.9/10"),
            Some(v4("100.64.0.1")),
            RouterAnswer::Fail {
                after: ms(5),
                fail: MapFail::Timeout,
            },
        )
    };
    let (env, _router) = cgnat(&world);
    let t0 = Instant::now();
    let (mut link, offered) = DirectLink::start(
        params(
            TornectRole::Viewer,
            1,
            2,
            config(&[server.entry()], MapProtocols::ALL),
        ),
        env,
    )
    .await
    .expect("a link without host candidates");
    assert!(offered.is_empty());
    assert_eq!(
        batches(&mut link, t0).await,
        vec![
            (ms(45), LocalBatch::More(vec![reflexive(NAT)])),
            (ms(45), LocalBatch::Done),
        ]
    );
    assert_eq!(link.stats().offered, 0);

    for scope in [Scope::Internet, Scope::SameSite] {
        let (env, router) = cgnat(&world);
        let gather = if scope == Scope::Internet {
            GatherConfig::default()
        } else {
            config(&[server.entry()], MapProtocols::ALL)
        };
        let fail = DirectLink::start(
            DirectParams {
                scope,
                ..params(TornectRole::Viewer, 1, 2, gather)
            },
            env.clone(),
        )
        .await
        .expect_err("nothing to offer");
        assert_eq!(fail, DirectFail::NoAddresses);
        assert_eq!(env.calls().binds, 0);
        assert_eq!(env.inner().inner.counters().binds, 0);
        assert!(router.seen().is_empty());
    }
}

/// A server-reflexive address equal to the mapped one (a router that kept
/// the port) is offered once.
#[tokio::test(start_paused = true)]
async fn a_gathered_address_is_offered_once() {
    let world = World::new();
    let server = world.server("64.0.0.10/24", Answer::Fixed(at(MAPPED)));
    let (env, _router) = world.routed("192.168.1.20/24", grant(600));
    let t0 = Instant::now();
    let (mut link, _) = DirectLink::start(
        params(
            TornectRole::Viewer,
            1,
            2,
            config(&[server.entry()], MapProtocols::ALL),
        ),
        env,
    )
    .await
    .expect("a link");
    assert_eq!(
        batches(&mut link, t0).await,
        vec![
            (ms(290), LocalBatch::More(vec![reflexive(MAPPED)])),
            (ms(600), LocalBatch::Done),
        ]
    );
    let stats = link.stats().gather;
    assert_eq!((stats.batches, stats.duplicates), (1, 1));
}

// ---------------------------------------------------------------------------
// Two links in internet scope (step B7 through the link).

/// Two links that have both finished gathering, each holding every
/// candidate of the other, so that the ranks are the final ones before the
/// first probe.
struct Pair {
    viewer: DirectLink,
    host: DirectLink,
}

impl Pair {
    async fn start(
        viewer_env: Arc<dyn NetEnv>,
        viewer_gather: GatherConfig,
        host_env: Arc<dyn NetEnv>,
        host_gather: GatherConfig,
    ) -> Self {
        let t0 = Instant::now();
        let (mut viewer, mut from_viewer) =
            DirectLink::start(params(TornectRole::Viewer, 1, 2, viewer_gather), viewer_env)
                .await
                .expect("the viewer's link");
        let (mut host, mut from_host) =
            DirectLink::start(params(TornectRole::Host, 2, 1, host_gather), host_env)
                .await
                .expect("the host's link");
        for (link, all) in [(&mut viewer, &mut from_viewer), (&mut host, &mut from_host)] {
            for (_, batch) in batches(link, t0).await {
                if let LocalBatch::More(more) = batch {
                    all.extend(more);
                }
            }
        }
        host.add_remote(from_viewer, Scope::Internet);
        host.remote_done();
        viewer.add_remote(from_host, Scope::Internet);
        viewer.remote_done();
        Self { viewer, host }
    }

    async fn established(&mut self) -> (Established, Established) {
        let (v, h) = tokio::join!(connected(&mut self.viewer), connected(&mut self.host));
        (v, h)
    }
}

/// The connection, past the checklist's early-failure advice.
async fn connected(link: &mut DirectLink) -> Established {
    loop {
        match within(link.established()).await {
            Ok(conn) => return conn,
            Err(DirectFail::NoPath { .. }) => {}
            Err(fail) => panic!("no connection: {fail}"),
        }
    }
}

/// Design §7.6, §3.1, §12.4 "same NAT, two subnets, no hairpin": both
/// sides' server-reflexive addresses share one public IPv4, so each side's
/// private address off the other's link is ranked like a public host and
/// checked on the same-site schedule, and the route is same-site.
#[tokio::test(start_paused = true)]
async fn the_same_public_address_promotes_a_private_path_to_same_site() {
    let world = World::new();
    let other_lan = world.net.segment(LinkSpec::LAN);
    world.net.link(world.home, other_lan, LinkSpec::LAN);
    world.net.link(
        other_lan,
        world.internet,
        LinkSpec {
            latency: ms(20),
            loss: 0.0,
        },
    );
    let for_viewer = world.server("64.0.0.10/24", Answer::Fixed(at("81.2.3.4:40001")));
    let for_host = world.server("64.0.1.10/24", Answer::Fixed(at("81.2.3.4:40002")));
    let viewer = world
        .net
        .machine(MachineSpec::on(world.home, "192.168.1.10/24"));
    let host = world
        .net
        .machine(MachineSpec::on(other_lan, "10.0.2.20/24"));
    let mut pair = Pair::start(
        Arc::new(viewer),
        config(&[for_viewer.entry()], MapProtocols::NONE),
        Arc::new(host),
        config(&[for_host.entry()], MapProtocols::NONE),
    )
    .await;
    let (v, h) = pair.established().await;
    assert!(v.route().same_site && h.route().same_site);
    assert!(!v.route().ipv6);
    assert_eq!(
        (v.winner(), h.winner()),
        (CandidateKind::Host, CandidateKind::Host)
    );
    for side in [&v, &h] {
        let gather = side.stats().gather;
        assert!(gather.srflx, "each side learned its public address");
    }
}

/// Design §7.6 rank 1's demotion, §12.4 "both 192.168.1.0/24 at different
/// sites": when the two sides' public addresses differ, the other side's
/// address inside our own prefix is no longer taken for our site; the
/// route is not same-site.
#[tokio::test(start_paused = true)]
async fn different_public_addresses_demote_an_on_link_address() {
    for (viewer_public, host_public, same_site) in [
        ("81.2.3.4:40001", "81.2.3.99:40002", false),
        ("81.2.3.4:40001", "81.2.3.4:40002", true),
    ] {
        let world = World::new();
        let for_viewer = world.server("64.0.0.10/24", Answer::Fixed(at(viewer_public)));
        let for_host = world.server("64.0.1.10/24", Answer::Fixed(at(host_public)));
        let viewer = world
            .net
            .machine(MachineSpec::on(world.home, "192.168.1.10/24"));
        let host = world
            .net
            .machine(MachineSpec::on(world.home, "192.168.1.20/24"));
        let mut pair = Pair::start(
            Arc::new(viewer),
            config(&[for_viewer.entry()], MapProtocols::NONE),
            Arc::new(host),
            config(&[for_host.entry()], MapProtocols::NONE),
        )
        .await;
        let (v, h) = pair.established().await;
        assert_eq!(
            (v.route().same_site, h.route().same_site),
            (same_site, same_site),
            "{viewer_public} {host_public}"
        );
        assert_eq!(v.winner(), CandidateKind::Host);
    }
}

/// Design §7.1, §5.2 row 7 (`V6Sources` for globals): in internet scope a
/// side offers the temporary global IPv6 of its route-source interface, not
/// the stable route source, and every IPv6 datagram of the session leaves
/// from it; two such sides connect over IPv6, and the route is not
/// same-site.
#[tokio::test(start_paused = true)]
async fn global_ipv6_paths_leave_from_the_offered_address() {
    let world = World::new();
    let side = |segment, stable: &str, temporary: &str| MachineSpec {
        addrs: vec![
            MemAddr::new(segment, stable),
            MemAddr {
                temporary: true,
                ..MemAddr::new(segment, temporary)
            },
        ],
        ..MachineSpec::default()
    };
    let viewer = world.net.machine(side(
        world.home,
        "2a01:4f8:1:1::10/64",
        "2a01:4f8:1:1:aaaa::10/64",
    ));
    let host = world.net.machine(side(
        world.internet,
        "2a02:8:2:2::20/64",
        "2a02:8:2:2:bbbb::20/64",
    ));
    let (mut viewer_link, viewer_offered) = DirectLink::start(
        params(TornectRole::Viewer, 1, 2, GatherConfig::default()),
        Arc::new(viewer.clone()),
    )
    .await
    .expect("the viewer's link");
    let (mut host_link, host_offered) = DirectLink::start(
        params(TornectRole::Host, 2, 1, GatherConfig::default()),
        Arc::new(host.clone()),
    )
    .await
    .expect("the host's link");
    assert_eq!(viewer_offered.len(), 1);
    assert_eq!(viewer_offered[0].addr.ip(), ip("2a01:4f8:1:1:aaaa::10"));
    assert_eq!(host_offered[0].addr.ip(), ip("2a02:8:2:2:bbbb::20"));
    assert_eq!(viewer_link.stats().globals_offered, 1);
    host_link.add_remote(viewer_offered, Scope::Internet);
    host_link.remote_done();
    viewer_link.add_remote(host_offered, Scope::Internet);
    viewer_link.remote_done();
    let (v, h) = tokio::join!(connected(&mut viewer_link), connected(&mut host_link));
    assert!(v.route().ipv6 && h.route().ipv6);
    assert!(!v.route().same_site && !h.route().same_site);
    let wire = world.net.wire();
    assert!(!wire.is_empty());
    for w in &wire {
        assert!(
            [ip("2a01:4f8:1:1:aaaa::10"), ip("2a02:8:2:2:bbbb::20")].contains(&w.from.ip()),
            "a datagram from a stable address: {:?}",
            w.kind
        );
        assert_ne!(w.fate, Fate::Unroutable);
    }
}
