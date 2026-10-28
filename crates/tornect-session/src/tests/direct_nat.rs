//! Step B9: the direct design §12.4 NAT matrix, end to end. Each row is a
//! whole session through both FSMs (the host's [`DirectHost`] behind the
//! real handshake FSM, the viewer's [`ViewerDirect::choose_path`]) over a
//! signalling pipe 500 ms one way ([`lagged_duplex`]), on a `MemNet` whose
//! homes sit behind `NatBox`es on an internet segment, with a `MemStun` per
//! side and the boxes' routers as `MemMapper`s. Both halves run in internet
//! scope ([`ViewerDirect::with_internet`], [`DirectHost::with_internet`]),
//! as step B12 will turn on. Every row asserts the route, the time, the
//! host's `PathSummary` and the `CountingEnv` counts. Paused time.
//!
//! A direct row binds its media to see the host's claim: the test backend's
//! source cannot open, so the bind is refused after the claim
//! (`CAPTURE_FAILED`), and the session's end line still says `direct`.
//!
//! The viewer's punch timeout `T0` is its receipt of the accept; the host's
//! summary counts from its own accept, one signalling delay earlier.
//!
//! Where a row does not come out as the design's table says, the test pins
//! what happens and says so; `docs/VERIFICATION.md` keeps the row open.

use std::future::pending;
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use quinn::AsyncUdpSocket as _;
use quinn::udp::{RecvMeta, Transmit};
use tokio::sync::mpsc;
use tornect_core::session_log::{PathSummary, TransportKind};
use tornect_net::checklist::{
    GRACE_MAX, MAX_PROBE_BYTES, MAX_REQUESTS_PER_TARGET, MAX_RESPONSES_PER_SOURCE,
    MAX_UNVALIDATED_BYTES,
};
use tornect_net::link::CLOSE_WAIT;
use tornect_net::mem::{
    CountingEnv, EnvCalls, Fate, LaggedDuplex, LinkSpec, MachineSpec, MapperMode, MemAddr, MemHost,
    MemNat, MemNet, MemStun, MemUdp, NatBox, NatFiltering, NatMapping, RouterSeen, Segment,
    StunMode, WireKind, WireRecord, lagged_duplex,
};
use tornect_net::udp::PROBE_LEN;
use tornect_net::{
    AddrClass, Candidate, CandidateKind, GATHER_BUDGET, IfaceKind, MAP_LEASE, MapProtocols,
    ProbeKey, QuicIdentity, Route, RouteSources, Scope, TornectRole, class, endpoint_config,
};
use tornect_signal::HandshakeError;
use tornect_signal::consent::{TransportKnob, TransportPolicy};
use tornect_signal::fsm::client::ClientSession;
use tornect_signal::fsm::{PathExchange, PathFrame, PathPort, PathRecord};
use tornect_signal::messages::{self, fallback, feats, scope};

use super::direct_host::{Ends, key, keys_by_order, until};
use super::direct_path::Tap;
use super::*;

const ANY: TransportPolicy = TransportPolicy::Any;

/// The signalling pipe's one-way delay (the direct design §12.4
/// `LaggedDuplex`): about what a Tor circuit adds.
const ONE_WAY: Duration = Duration::from_millis(500);

/// The default punch window (`network.punch_timeout_ms`).
const PUNCH: Duration = Duration::from_secs(4);

/// The app's bind wait for the media stream (`MEDIA_BIND_WAIT`).
const BIND_WAIT: Duration = Duration::from_secs(30);

/// The design's bound for a home × home session (§12.4 row 1).
const HOME_BOUND: Duration = Duration::from_millis(2500);

/// The internet between the homes: 10 ms each way, no loss.
const INTERNET: LinkSpec = LinkSpec {
    latency: Duration::from_millis(10),
    loss: 0.0,
};

/// The viewer's home's public address, and the host's.
const VIEWER_PUBLIC: &str = "81.2.3.4";
const HOST_PUBLIC: &str = "82.2.3.4";

/// The STUN servers of each side's part of the list (decision M1-81: no
/// operator in both parts).
const VIEWER_STUN: &str = "stun-v.test";
const HOST_STUN: &str = "stun-h.test";

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn ip(s: &str) -> IpAddr {
    s.parse().expect("an address")
}

fn at(s: &str) -> SocketAddr {
    s.parse().expect("an address and port")
}

/// The two key orders: the viewer dials (its key is the lower), then the
/// host does.
fn orders() -> [(u8, u8); 2] {
    let [low, _, high] = keys_by_order();
    [(low, high), (high, low)]
}

/// An internet segment with one honest STUN server per side, named in the
/// network's table, and whatever homes a row adds.
struct Lab {
    net: MemNet,
    internet: Segment,
    /// The viewer's server, then the host's.
    stun: [MemStun; 2],
}

impl Lab {
    fn new(seed: u64) -> Self {
        Self::with_internet(seed, INTERNET)
    }

    fn with_internet(seed: u64, spec: LinkSpec) -> Self {
        let net = MemNet::new(seed);
        let internet = net.segment(spec);
        let stun =
            [(VIEWER_STUN, "64.0.0.10/24"), (HOST_STUN, "64.0.0.11/24")].map(|(name, cidr)| {
                let server = MemStun::start(&net, internet, cidr, StunMode::Honest);
                net.name(name, &[server.addr().ip()]);
                server
            });
        Self {
            net,
            internet,
            stun,
        }
    }

    /// A machine with a public address on the internet itself, no NAT.
    fn public(&self, cidr: &str) -> MachineSpec {
        MachineSpec::on(self.internet, cidr)
    }

    /// A home: the LAN `lan.0/24` behind a box at `public` on the internet
    /// (a home router as [`NatBox::home`] makes it, its inside address
    /// `lan.1`, then as `shape` changes it), and the machine `lan.n` on it,
    /// whose gateway the box is.
    fn home(
        &self,
        lan: &str,
        n: u8,
        public: &str,
        shape: impl FnOnce(NatBox) -> NatBox,
    ) -> (MachineSpec, MemNat) {
        let segment = self.net.segment(LinkSpec::LAN);
        let gateway = format!("{lan}.1");
        let nat = self.net.nat(shape(NatBox {
            lan: Some(gateway.parse().expect("an IPv4 gateway")),
            ..NatBox::home(segment, self.internet, public)
        }));
        let machine = MachineSpec::on(segment, &format!("{lan}.{n}/24")).gateway(&gateway);
        (machine, nat)
    }

    /// The viewer's home (`192.168.1.10` behind [`VIEWER_PUBLIC`]).
    fn viewer_home(&self, shape: impl FnOnce(NatBox) -> NatBox) -> (MachineSpec, MemNat) {
        self.home("192.168.1", 10, VIEWER_PUBLIC, shape)
    }

    /// The host's home (`192.168.2.20` behind [`HOST_PUBLIC`]).
    fn host_home(&self, shape: impl FnOnce(NatBox) -> NatBox) -> (MachineSpec, MemNat) {
        self.home("192.168.2", 20, HOST_PUBLIC, shape)
    }

    /// A machine on a carrier-grade NAT only (`100.64.0.10/10`, the
    /// carrier's box at [`VIEWER_PUBLIC`] its gateway), and that box.
    fn carrier_only(&self) -> (MachineSpec, MemNat) {
        let carrier = self.net.segment(LinkSpec::LAN);
        let nat = self.net.nat(NatBox {
            lan: Some(Ipv4Addr::new(100, 64, 0, 1)),
            ..NatBox::home(carrier, self.internet, VIEWER_PUBLIC)
        });
        let machine = MachineSpec::on(carrier, "100.64.0.10/10").gateway("100.64.0.1");
        (machine, nat)
    }

    /// The datagrams the machines with `ips` sent, as the wire logged them.
    fn sent_by(&self, ips: &[IpAddr]) -> Vec<WireRecord> {
        self.net
            .wire()
            .into_iter()
            .filter(|w| ips.contains(&w.from.ip()))
            .collect()
    }
}

/// A box with this mapping and filtering, otherwise a home router.
fn shaped(mapping: NatMapping, filtering: NatFiltering) -> impl FnOnce(NatBox) -> NatBox {
    move |b| NatBox {
        mapping,
        filtering,
        ..b
    }
}

/// A home router whose own router answers as `mode`.
fn router(mode: MapperMode) -> impl FnOnce(NatBox) -> NatBox {
    move |b| NatBox {
        router: Some(mode),
        ..b
    }
}

/// The `[network]` options of a lab session: each side's part of the STUN
/// list is its own server, STUN and every router protocol on.
fn options() -> DirectOptions {
    DirectOptions {
        direct_port: None,
        punch_timeout: PUNCH,
        stun_partition_viewer: Arc::from([format!("{VIEWER_STUN}:3478")]),
        stun_partition_host: Arc::from([format!("{HOST_STUN}:3478")]),
        enable_stun: true,
        map: MapProtocols {
            upnp: true,
            nat_pmp: true,
            pcp: true,
        },
    }
}

/// How a lab session is set up.
struct NatOpts {
    viewer: u8,
    host: u8,
    one_way: Duration,
    host_policy: TransportPolicy,
    mine: Mine,
    viewer_options: DirectOptions,
    host_options: DirectOptions,
}

impl NatOpts {
    fn new(viewer: u8, host: u8) -> Self {
        Self {
            viewer,
            host,
            one_way: ONE_WAY,
            host_policy: ANY,
            mine: Mine::of(ANY),
            viewer_options: options(),
            host_options: options(),
        }
    }

    /// STUN off on both sides (`network.enable_stun = false`).
    fn without_stun(mut self) -> Self {
        self.viewer_options.enable_stun = false;
        self.host_options.enable_stun = false;
        self
    }
}

/// A path exchange that records the viewer's frames as the host FSM hands
/// them on ([`Tap`]) and the host's as its half writes them.
struct Taps {
    inner: Arc<dyn PathExchange>,
    from_viewer: Arc<Mutex<Vec<PathFrame>>>,
    from_host: Arc<Mutex<Vec<PathFrame>>>,
}

impl PathExchange for Taps {
    fn open(&self, session: &LiveSession<'_>) -> PathPort {
        let mut port = Tap {
            inner: Arc::clone(&self.inner),
            frames: Arc::clone(&self.from_viewer),
        }
        .open(session);
        if let Some(mut outbox) = port.outbox.take() {
            let (written, read) = mpsc::channel::<PathFrame>(64);
            let frames = Arc::clone(&self.from_host);
            tokio::spawn(async move {
                while let Some(frame) = outbox.recv().await {
                    frames.lock().unwrap().push(frame.clone());
                    if written.send(frame).await.is_err() {
                        return;
                    }
                }
            });
            port.outbox = Some(read);
        }
        port
    }

    fn outcome(&self, session_id: &str) -> PathRecord {
        self.inner.outcome(session_id)
    }

    fn heard(&self, session_id: &str, frame: &PathFrame) {
        self.inner.heard(session_id, frame);
    }
}

/// One accepted session through the real FSMs over a lagged pipe, both
/// halves of its path in internet scope on the lab's network.
struct NatFx {
    session: ClientSession<LaggedDuplex>,
    viewer: ViewerDirect,
    viewer_env: Arc<CountingEnv<MemHost>>,
    host_env: Arc<CountingEnv<MemHost>>,
    /// The viewer's path frames as the host FSM handed them on.
    from_viewer: Arc<Mutex<Vec<PathFrame>>>,
    /// The host's path frames as its half wrote them.
    from_host: Arc<Mutex<Vec<PathFrame>>>,
    ends: Arc<Ends>,
    fsm: JoinHandle<Result<(), HandshakeError>>,
    _rig: Rig,
    _tmp: tempfile::TempDir,
}

async fn nat_fixture(
    lab: &Lab,
    viewer_spec: MachineSpec,
    host_spec: MachineSpec,
    opts: &NatOpts,
) -> NatFx {
    let tmp = tempfile::tempdir().unwrap();
    let onion = Arc::new(HostIdentity::from_seed(&[0x52; 32]));
    let trusted = Arc::new(TrustedDeviceStore::with(
        tmp.path().join("trusted-devices.toml"),
        tornect_core::trusted::TrustedDevices::default(),
    ));
    let consent = Arc::new(ScriptedConsent::new());
    consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let mut deps = HostDeps::headless(onion.clone(), trusted);
    deps.consent = consent;
    let host_env = CountingEnv::new(lab.net.machine(host_spec));
    let (taps, ends, rig) = host_half(&mut deps, &host_env, opts);
    let mut cfg = HostConfig::new("Desk", key(opts.host).verifying_key().to_bytes());
    cfg.transport = TransportKnob::fixed(opts.host_policy);
    cfg.feats.push(feats::DIR1.to_owned());
    let (client_end, host_end) = lagged_duplex(64 * 1024, opts.one_way);
    let fsm = tokio::spawn(async move { serve_host(host_end, &cfg, &deps).await.map(|_| ()) });

    let known = Arc::new(KnownHostStore::with(
        tmp.path().join("known-hosts.toml"),
        tornect_core::trusted::KnownHosts::default(),
    ));
    let mut client_deps = ClientDeps::headless(known);
    client_deps.ui = Arc::new(ScriptedClientUi::new(true));
    let device = DeviceIdentity::from_seed(&[opts.viewer; 32]);
    let mut ccfg = ClientConfig::new(onion.id(), "Laptop");
    ccfg.feats.push(feats::DIR1.to_owned());
    let ClientOutcome::Session(session) =
        client::connect(client_end, &ccfg, &device, &client_deps, Intent::Session)
            .await
            .unwrap()
    else {
        panic!("no session");
    };
    let viewer_env = CountingEnv::new(lab.net.machine(viewer_spec));
    let viewer = ViewerDirect::new(
        key(opts.viewer),
        DirectSettings::new(opts.viewer_options.clone()),
        viewer_env.clone(),
    )
    .with_internet(true);
    NatFx {
        session: *session,
        viewer,
        viewer_env,
        host_env,
        from_viewer: taps.from_viewer,
        from_host: taps.from_host,
        ends,
        fsm,
        _rig: rig,
        _tmp: tmp,
    }
}

/// The host's half on `env` in `deps`, in internet scope, its frames both
/// ways recorded; its media layer's source never opens. The taps, where
/// the session's end line lands, and the media layer.
fn host_half(
    deps: &mut HostDeps,
    env: &Arc<CountingEnv<MemHost>>,
    opts: &NatOpts,
) -> (Taps, Arc<Ends>, Rig) {
    let rig = rig_with(
        TestBackend {
            fail: true,
            ..TestBackend::default()
        },
        MediaLimits::default(),
    );
    deps.sessions = rig.host.clone();
    let ends = Arc::new(Ends::default());
    deps.audit = ends.clone();
    let direct = Arc::new(
        DirectHost::new(
            rig.host.clone(),
            None,
            key(opts.host),
            DirectSettings::new(opts.host_options.clone()),
            env.clone(),
            deps.kill.clone(),
            Arc::new(|_: &MediaOutcome| {}),
        )
        .with_internet(true),
    );
    let taps = Taps {
        inner: direct as Arc<dyn PathExchange>,
        from_viewer: Arc::default(),
        from_host: Arc::default(),
    };
    deps.paths = Arc::new(Taps {
        inner: Arc::clone(&taps.inner),
        from_viewer: Arc::clone(&taps.from_viewer),
        from_host: Arc::clone(&taps.from_host),
    });
    (taps, ends, rig)
}

/// What a side asked of its network: interface reads, binds, name
/// look-ups and port mappers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Asked {
    interfaces: usize,
    binds: usize,
    resolves: usize,
    mappers: usize,
}

impl Asked {
    const NOTHING: Self = Self::of(0, 0, 0, 0);

    const fn of(interfaces: usize, binds: usize, resolves: usize, mappers: usize) -> Self {
        Self {
            interfaces,
            binds,
            resolves,
            mappers,
        }
    }

    fn from(calls: EnvCalls) -> Self {
        Self::of(calls.interfaces, calls.binds, calls.resolves, calls.mappers)
    }
}

/// A side that read its interfaces once, bound once, looked its STUN
/// server up and took the mapper once.
const GATHERED: Asked = Asked::of(1, 1, 1, 1);

impl NatFx {
    /// The session's path phase, nothing to interrupt it.
    async fn choose(&mut self, mine: Mine) -> PathChoice {
        self.viewer
            .choose_path(&mut self.session, mine, true, pending())
            .await
    }

    /// What each side asked of its network: the viewer's, the host's.
    fn asked(&self) -> (Asked, Asked) {
        (
            Asked::from(self.viewer_env.calls()),
            Asked::from(self.host_env.calls()),
        )
    }

    /// No send of either machine was refused for its family, its source or
    /// its route.
    fn sent_cleanly(&self) {
        for env in [&self.viewer_env, &self.host_env] {
            let c = env.inner().counters();
            assert_eq!(
                (c.invalid_input, c.bad_source, c.no_route),
                (0, 0, 0),
                "{c:?}"
            );
        }
    }

    /// The viewer ends the session with `BYE{reason}`; the host's end line.
    async fn end(self, reason: u16) -> (Option<TransportKind>, Option<PathSummary>) {
        self.session.bye(reason).await.unwrap();
        let line = self.ends.line().await;
        self.fsm.await.unwrap().unwrap();
        line
    }
}

/// What the viewer's path phase came to.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Went {
    Direct {
        route: Route,
        winner: CandidateKind,
        elapsed: Duration,
    },
    Tor {
        why: TorWhy,
        elapsed: Duration,
    },
}

/// A lab session's outcome, seen from both ends.
struct Ran {
    went: Went,
    /// What each side asked of its network by the end of the path phase.
    asked: (Asked, Asked),
    /// The host's end line.
    transport: Option<TransportKind>,
    summary: PathSummary,
    from_viewer: Vec<PathFrame>,
    from_host: Vec<PathFrame>,
}

impl Ran {
    fn direct(&self) -> (Route, CandidateKind, Duration) {
        match self.went {
            Went::Direct {
                route,
                winner,
                elapsed,
            } => (route, winner, elapsed),
            Went::Tor { .. } => panic!("not direct: {:?}", self.went),
        }
    }

    fn tor(&self) -> (TorWhy, Duration) {
        match self.went {
            Went::Tor { why, elapsed } => (why, elapsed),
            Went::Direct { .. } => panic!("not Tor: {:?}", self.went),
        }
    }

    /// The summary's facts: its outcome, its winner (the kind of the
    /// viewer's candidate the host's connection runs to) and its family.
    fn says(&self) -> (&str, Option<&str>, bool) {
        (
            self.summary.outcome.as_str(),
            self.summary.winner.as_deref(),
            self.summary.ipv6,
        )
    }

    /// The candidates the viewer offered, with each frame's scope.
    fn offered(&self) -> Vec<(Candidate, Scope)> {
        offered(&self.from_viewer)
    }
}

/// The candidates in `frames`, with each frame's scope.
fn offered(frames: &[PathFrame]) -> Vec<(Candidate, Scope)> {
    frames
        .iter()
        .filter_map(|f| match f {
            PathFrame::Candidates(c) => Some(from_wire(c)),
            _ => None,
        })
        .flat_map(|(batch, scope)| batch.into_iter().map(move |c| (c, scope)))
        .collect()
}

/// One lab session, its path phase run to its end: a direct path binds
/// (the host claims it, then refuses the bind as its source cannot open)
/// and the viewer ends the session; a Tor fallback ends the session once
/// the host's half has the viewer's reason.
async fn run(lab: &Lab, viewer: MachineSpec, host: MachineSpec, opts: &NatOpts) -> Ran {
    run_with(lab, viewer, host, opts, |_| ()).await.0
}

/// [`run`], with `before` called on the session just before its path phase
/// starts.
async fn run_with<T>(
    lab: &Lab,
    viewer: MachineSpec,
    host: MachineSpec,
    opts: &NatOpts,
    before: impl FnOnce(&NatFx) -> T,
) -> (Ran, T) {
    let mut fx = nat_fixture(lab, viewer, host, opts).await;
    let early = before(&fx);
    let choice = fx.choose(opts.mine).await;
    let asked = fx.asked();
    fx.sent_cleanly();
    let went = match choice {
        PathChoice::Direct(media) => {
            let went = Went::Direct {
                route: media.route,
                winner: media.winner,
                elapsed: media.elapsed,
            };
            let failed = media
                .bind(BIND_WAIT)
                .await
                .expect_err("the test source never opens");
            assert!(
                matches!(failed.error, ViewerError::Refused(r) if r == reason::CAPTURE_FAILED),
                "{failed:?}"
            );
            went
        }
        // The viewer's `BYE` follows its `TOR_FALLBACK` at once: the host
        // FSM tells its half of the fallback as it reads it, so the end line
        // still names the viewer's reason.
        PathChoice::Tor { why, elapsed } => Went::Tor { why, elapsed },
        other => panic!("neither direct nor Tor: {other:?}"),
    };
    let from_viewer = Arc::clone(&fx.from_viewer);
    let from_host = Arc::clone(&fx.from_host);
    let (transport, summary) = fx.end(bye::USER).await;
    let ran = Ran {
        went,
        asked,
        transport,
        summary: summary.expect("a path summary"),
        from_viewer: from_viewer.lock().unwrap().clone(),
        from_host: from_host.lock().unwrap().clone(),
    };
    (ran, early)
}

/// The internet route over IPv4.
const INTERNET_V4: Route = Route {
    same_site: false,
    ipv6: false,
};

/// Whether `ip` is a global unicast address.
fn global(ip: IpAddr) -> bool {
    class(ip) == AddrClass::Global
}

/// A direct summary's time: the host's claim, which follows the viewer's
/// open stream by about one signalling delay (the host's accept was that
/// much earlier) plus the bind's round trip.
fn claimed_ms(elapsed: Duration, one_way: Duration) -> std::ops::RangeInclusive<u32> {
    let start = u32::try_from((elapsed + one_way).as_millis()).unwrap();
    start..=start + 200
}

/// A fallback summary's time: the viewer's `TOR_FALLBACK` reaches the host
/// one signalling delay after it left, and the host's accept was one
/// earlier than the viewer's `T0`.
fn fallback_ms(elapsed: Duration, one_way: Duration) -> std::ops::RangeInclusive<u32> {
    let start = u32::try_from((elapsed + 2 * one_way).as_millis()).unwrap();
    start..=start + u32::try_from(CLOSE_WAIT.as_millis()).unwrap() + 20
}

/// §12.4 "EIM/APDF (home) × EIM/APDF (home) → Direct internet via srflx,
/// ≤ T0+2.5 s", with either side dialling: each side asks its silent
/// router for a port (no answer), then its STUN server, and offers the
/// server-reflexive candidate; the two punch through both boxes' filters
/// and the viewer's media stream opens on the internet route within 2.5 s
/// of the accept. The host's summary names the viewer's srflx candidate.
/// Each side read its interfaces once, bound once, looked one name up and
/// took one mapper.
#[tokio::test(start_paused = true)]
async fn home_and_home_go_direct_through_stun() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let (v, _) = lab.viewer_home(|b| b);
        let (h, _) = lab.host_home(|b| b);
        let opts = NatOpts::new(viewer, host);
        let ran = run(&lab, v, h, &opts).await;
        let (route, winner, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert_eq!(PathEnd::Direct(route).route_words(), "direct internet");
        assert_eq!(winner, CandidateKind::Srflx);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.transport, Some(TransportKind::Direct));
        assert_eq!(ran.says(), ("direct", Some("srflx"), false));
        assert!(
            claimed_ms(elapsed, opts.one_way).contains(&ran.summary.ms),
            "{:?}",
            ran.summary
        );
        assert_eq!(ran.asked, (GATHERED, GATHERED));
    }
}

/// §12.4 "EIM/EIF × EIM/APDF → Direct": the viewer's open filter lets the
/// host's first probes in before the host's `CANDIDATES` arrive, so the
/// viewer learns the host's mapping as peer-reflexive and its connection
/// runs there; the host's runs to the viewer's srflx candidate.
#[tokio::test(start_paused = true)]
async fn an_open_viewer_nat_goes_direct() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let (v, _) = lab.viewer_home(shaped(NatMapping::Eim, NatFiltering::Eif));
        let (h, _) = lab.host_home(|b| b);
        let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
        let (route, winner, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert_eq!(winner, CandidateKind::Prflx);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.says(), ("direct", Some("srflx"), false));
        assert_eq!(ran.asked, (GATHERED, GATHERED));
    }
}

/// §12.4 "public v4 host (no NAT) × EIM/APDF → Direct, no STUN on the
/// viewer": a viewer whose own address is global asks no STUN server and
/// no router (it has no gateway); its STUN server hears nothing and no
/// STUN datagram leaves it. The host's punch reaches the viewer's own
/// address before its mapping head start ends, so the host never looks its
/// server up either.
#[tokio::test(start_paused = true)]
async fn a_public_viewer_goes_direct_without_stun() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let v = lab.public("83.0.0.10/24");
        let (h, _) = lab.host_home(|b| b);
        let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
        let (route, _, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.says(), ("direct", Some("host"), false));
        assert_eq!(ran.asked, (Asked::of(1, 1, 0, 0), Asked::of(1, 1, 0, 1)));
        assert!(lab.stun[0].heard().is_empty());
        assert!(
            lab.sent_by(&[ip("83.0.0.10")])
                .iter()
                .all(|w| w.kind != WireKind::Stun)
        );
    }
}

/// §12.4 "APDM (symmetric) × EIM/EIF → Direct via prflx" and "APDM ×
/// EIM/ADF → Direct via prflx and triggered check": the viewer's box maps
/// its socket anew toward the host, so the srflx port its STUN server saw
/// is not the one the host hears from. The host learns that address from
/// the viewer's request and its connection runs there: the summary's
/// winner is `prflx`. A target counts as validated only by a round trip of
/// the host's own request, and the host never had that address but from
/// the request, so it sent a triggered check there.
#[tokio::test(start_paused = true)]
async fn a_symmetric_viewer_goes_direct_via_prflx() {
    for filtering in [NatFiltering::Eif, NatFiltering::Adf] {
        for (viewer, host) in orders() {
            let lab = Lab::new(1);
            let (v, _) = lab.viewer_home(shaped(NatMapping::Apdm, NatFiltering::Apdf));
            let (h, _) = lab.host_home(shaped(NatMapping::Eim, filtering));
            let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
            let (route, winner, elapsed) = ran.direct();
            assert_eq!(route, INTERNET_V4, "{filtering:?}");
            assert_eq!(winner, CandidateKind::Srflx, "{filtering:?}");
            assert!(elapsed <= HOME_BOUND, "{filtering:?}: {elapsed:?}");
            assert_eq!(
                ran.says(),
                ("direct", Some("prflx"), false),
                "{filtering:?}"
            );
            assert_eq!(ran.asked, (GATHERED, GATHERED), "{filtering:?}");
        }
    }
}

/// §12.4 "APDM × EIM/APDF → `Tor(NoPath)`, fallback at T0+4.0 s" and
/// "APDM × APDM → `Tor(NoPath)` ≤ T0+4.0 s": no address validates, nothing
/// of the host's gets through to the viewer, no QUIC datagram is ever sent,
/// and the viewer falls back at its punch timeout; the host's summary says
/// `no-path`.
#[tokio::test(start_paused = true)]
async fn a_symmetric_viewer_and_a_filtering_host_fall_back_at_the_cap() {
    let hosts = [
        (NatMapping::Eim, NatFiltering::Apdf),
        (NatMapping::Apdm, NatFiltering::Apdf),
    ];
    for (mapping, filtering) in hosts {
        for (viewer, host) in orders() {
            let row = format!("{mapping:?}/{filtering:?}");
            let lab = Lab::new(1);
            let (v, _) = lab.viewer_home(shaped(NatMapping::Apdm, NatFiltering::Apdf));
            let (h, _) = lab.host_home(shaped(mapping, filtering));
            let opts = NatOpts::new(viewer, host);
            let ran = run(&lab, v, h, &opts).await;
            let (why, elapsed) = ran.tor();
            assert_eq!(
                why,
                TorWhy::Fallback(FallbackWhy::NoPath { heard: false }),
                "{row}"
            );
            assert_eq!(elapsed, PUNCH, "{row}");
            assert_eq!(ran.transport, None, "{row}");
            assert_eq!(ran.says(), ("no-path", None, false), "{row}");
            assert!(
                fallback_ms(elapsed, opts.one_way).contains(&ran.summary.ms),
                "{row}: {:?}",
                ran.summary
            );
            assert_eq!(ran.asked, (GATHERED, GATHERED), "{row}");
            assert!(
                lab.net.wire().iter().all(|w| w.kind != WireKind::Other),
                "{row}: QUIC sent"
            );
        }
    }
}

/// §12.4 "CGNAT only (100.64/10, EIM/APDF) behind home EIM/APDF × home →
/// srflx gathered; Direct": a home LAN behind the carrier's box, and a
/// machine on the carrier's network alone. The viewer's shared-address
/// route source still asks its gateway's router (which says nothing), its
/// STUN server sees the carrier's public address, and the session goes
/// direct through both boxes.
#[tokio::test(start_paused = true)]
async fn carrier_grade_nat_gathers_srflx_and_goes_direct() {
    for double in [true, false] {
        for (viewer, host) in orders() {
            let lab = Lab::new(1);
            let v = if double {
                let (carrier_only, _) = lab.carrier_only();
                let carrier = carrier_only.addrs[0].segment;
                let home = lab.net.segment(LinkSpec::LAN);
                let _home_box = lab.net.nat(NatBox {
                    lan: Some(Ipv4Addr::new(192, 168, 1, 1)),
                    ..NatBox::home(home, carrier, "100.64.0.2")
                });
                MachineSpec::on(home, "192.168.1.10/24").gateway("192.168.1.1")
            } else {
                lab.carrier_only().0
            };
            let (h, _) = lab.host_home(|b| b);
            let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
            let (route, winner, elapsed) = ran.direct();
            assert_eq!(route, INTERNET_V4, "double {double}");
            assert_eq!(winner, CandidateKind::Srflx, "double {double}");
            assert!(elapsed <= HOME_BOUND, "double {double}: {elapsed:?}");
            assert_eq!(ran.says(), ("direct", Some("srflx"), false));
            assert_eq!(ran.asked, (GATHERED, GATHERED), "double {double}");
            let heard = lab.stun[0].heard();
            assert!(!heard.is_empty());
            assert!(heard.iter().all(|h| h.from.ip() == ip(VIEWER_PUBLIC)));
        }
    }
}

/// §12.4 "APDM × home with router mapping Ok → Direct via mapped; release
/// seen at session end": the host's router maps its port within the head
/// start, so the host skips STUN and offers the mapped address, which no
/// filter stands in front of; the viewer's connection runs to it. Once the
/// session ends, the host's link releases the mapping: the router hears it
/// and the forward is gone.
#[tokio::test(start_paused = true)]
async fn a_router_mapping_carries_a_symmetric_viewer_and_is_released() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let (v, _) = lab.viewer_home(shaped(NatMapping::Apdm, NatFiltering::Apdf));
        let (h, host_box) = lab.host_home(router(MapperMode::Ok));
        let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
        let (route, winner, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert_eq!(winner, CandidateKind::Mapped);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.says(), ("direct", Some("prflx"), false));
        assert_eq!(ran.asked, (GATHERED, Asked::of(1, 1, 0, 1)));
        until("the host's mapping released", || {
            host_box.forwards().is_empty()
        })
        .await;
        let log = host_box.router_log();
        assert!(
            matches!(
                log.as_slice(),
                [RouterSeen::Map { lease, .. }, RouterSeen::Release { .. }] if *lease == MAP_LEASE
            ),
            "{log:?}"
        );
    }
}

/// §12.4 "home, mapper `Grant(120 s)` × home": the viewer's router grants
/// 120 s whatever it is asked; the mapping arrives within the head start,
/// so the viewer asks no STUN server, and the host's connection runs to the
/// mapped address. The router hears one request for the 600 s lease, and
/// the release once the session is over. (The renewal every 60 s and the
/// mapping's survival over ten minutes are the link's, pinned in
/// `tornect-net`'s `a_short_grant_is_renewed_through_a_ten_minute_link`.)
#[tokio::test(start_paused = true)]
async fn a_short_grant_maps_and_is_released() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let (v, viewer_box) = lab.viewer_home(router(MapperMode::Grant(Duration::from_secs(120))));
        let (h, _) = lab.host_home(|b| b);
        let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
        let (route, _, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.says(), ("direct", Some("mapped"), false));
        assert_eq!(ran.asked.0, Asked::of(1, 1, 0, 1));
        until("the viewer's mapping released", || {
            viewer_box.forwards().is_empty()
        })
        .await;
        let log = viewer_box.router_log();
        assert!(
            matches!(
                log.as_slice(),
                [RouterSeen::Map { lease, .. }, RouterSeen::Release { .. }] if *lease == MAP_LEASE
            ),
            "{log:?}"
        );
    }
}

/// §12.4 "home, mapper `Lie(10.0.0.1)` × home → mapping released
/// (`NotGlobal`); srflx used": the router installs a forward but names a
/// private external address. The viewer releases the mapping during its
/// gathering (before its path phase is over), never offers it, and goes on
/// with STUN; the host's connection runs to the srflx candidate.
#[tokio::test(start_paused = true)]
async fn a_lying_router_is_released_and_srflx_is_used() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let (v, viewer_box) = lab.viewer_home(router(MapperMode::Lie(Ipv4Addr::new(10, 0, 0, 1))));
        let (h, _) = lab.host_home(|b| b);
        let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
        let (route, _, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.says(), ("direct", Some("srflx"), false));
        assert_eq!(ran.asked, (GATHERED, GATHERED));
        assert!(
            ran.offered()
                .iter()
                .all(|(c, _)| c.kind != CandidateKind::Mapped)
        );
        let log = viewer_box.router_log();
        let [
            RouterSeen::Map { at: mapped, .. },
            RouterSeen::Release { at: released },
        ] = log.as_slice()
        else {
            panic!("{log:?}");
        };
        assert!(
            released.saturating_duration_since(*mapped) < GATHER_BUDGET,
            "released during the gathering"
        );
        assert!(viewer_box.forwards().is_empty());
    }
}

/// §12.4 "home, mapper PermanentOnly × home → no mapping; srflx used; zero
/// lease-0 requests": the router grants only permanent mappings, and the
/// viewer never asks for one; it goes on with STUN.
#[tokio::test(start_paused = true)]
async fn a_permanent_only_router_gets_no_lease_zero_request() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let (v, viewer_box) = lab.viewer_home(router(MapperMode::PermanentOnly));
        let (h, _) = lab.host_home(|b| b);
        let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
        let (route, _, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.says(), ("direct", Some("srflx"), false));
        assert_eq!(ran.asked, (GATHERED, GATHERED));
        assert!(
            ran.offered()
                .iter()
                .all(|(c, _)| c.kind != CandidateKind::Mapped)
        );
        let log = viewer_box.router_log();
        assert!(!log.is_empty());
        assert!(
            log.iter()
                .all(|seen| matches!(seen, RouterSeen::Map { lease, .. } if *lease == MAP_LEASE)),
            "{log:?}"
        );
        assert!(viewer_box.forwards().is_empty());
    }
}

/// §12.4 "same NAT, two subnets, no hairpin → Direct via private
/// (same-NAT rule), `same_site: true`": one box with two LANs behind it,
/// and no hairpin. The host's punch reaches the viewer's private address
/// through the box at once, so the session goes direct over the two
/// private addresses: the host, which has both public addresses by then,
/// labels the route same-site (its end line says `Lan`, its summary
/// `host`). The viewer connects before the host's `CANDIDATES` arrive
/// (its peer-reflexive host address, its own srflx known, the host's not
/// yet), so its label is `internet`: the same-NAT rule needs the peer's
/// public address, never the class alone. An open residual of the design's
/// row, pinned here.
#[tokio::test(start_paused = true)]
async fn one_nat_with_two_subnets_goes_direct_over_private_addresses() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let a = lab.net.segment(LinkSpec::LAN);
        let b = lab.net.segment(LinkSpec::LAN);
        let _box = lab.net.nat(NatBox {
            inside: vec![a, b],
            ..NatBox::home(a, lab.internet, VIEWER_PUBLIC)
        });
        let v = MachineSpec::on(a, "192.168.1.10/24");
        let h = MachineSpec::on(b, "192.168.2.20/24");
        let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
        let (route, winner, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert_eq!(winner, CandidateKind::Prflx);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.transport, Some(TransportKind::Lan));
        assert_eq!(ran.says(), ("direct", Some("host"), false));
        assert_eq!(ran.asked, (Asked::of(1, 1, 1, 0), Asked::of(1, 1, 1, 0)));
        assert!(
            lab.net
                .wire()
                .iter()
                .all(|w| w.kind != WireKind::Other || !global(w.to.ip())),
            "QUIC over the public address"
        );
    }
}

/// §12.4 "both 192.168.1.0/24 at different sites → private targets
/// demoted; srflx wins; ≤ 4 stray probes per private target; `same_site:
/// false`": each side's private address lies in the other's own prefix,
/// but their public addresses differ, so neither takes it for its site.
/// What each sends to the other's private address (which reaches a machine
/// that is not there) stays within the requests of one target.
#[tokio::test(start_paused = true)]
async fn the_same_prefix_at_two_sites_is_demoted() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let (v, _) = lab.home("192.168.1", 10, VIEWER_PUBLIC, |b| b);
        let (h, _) = lab.home("192.168.1", 20, HOST_PUBLIC, |b| b);
        let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
        let (route, winner, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert_eq!(winner, CandidateKind::Srflx);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.transport, Some(TransportKind::Direct));
        assert_eq!(ran.says(), ("direct", Some("srflx"), false));
        assert_eq!(ran.asked, (GATHERED, GATHERED));
        for (from, to) in [
            ("192.168.1.10", "192.168.1.20"),
            ("192.168.1.20", "192.168.1.10"),
        ] {
            let strays = lab
                .sent_by(&[ip(from)])
                .iter()
                .filter(|w| w.to.ip() == ip(to))
                .count();
            assert!(strays <= MAX_REQUESTS_PER_TARGET, "{from} → {to}: {strays}");
        }
    }
}

/// An IPv6-only machine on its own LAN behind a stateful firewall (a
/// `NatBox` that does not translate, filtering by address and port), with a
/// stable global address, its route source, and a temporary one.
fn behind_a_firewall(lab: &Lab, stable: &str, temporary: &str) -> MachineSpec {
    let lan = lab.net.segment(LinkSpec::LAN);
    let _firewall = lab.net.nat(NatBox {
        filtering: NatFiltering::Apdf,
        ..NatBox::firewall(lan, lab.internet)
    });
    let stable = MemAddr::new(lan, stable);
    MachineSpec {
        sources: Some(RouteSources {
            v4: None,
            v6: Some(match stable.ip {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(_) => unreachable!("an IPv6 address"),
            }),
        }),
        addrs: vec![
            stable,
            MemAddr {
                temporary: true,
                ..MemAddr::new(lan, temporary)
            },
        ],
        ..MachineSpec::default()
    }
}

/// §12.4 "IPv6 both, `NatBox{translate: false, Apdf}` → Direct internet
/// ipv6; every v6 source is the offered temporary" and "a host whose route
/// source is stable and whose offered v6 is temporary → all v6 datagrams
/// leave from the temporary": both sides offer their temporary address
/// only, punch through both firewalls, and every datagram either sends
/// leaves from it, though the route source is the stable address. No IPv4,
/// so no STUN and no router.
#[tokio::test(start_paused = true)]
async fn ipv6_firewalls_go_direct_from_the_temporary_address() {
    const V: (&str, &str) = ("2a01:4f8:1:1::10", "2a01:4f8:1:1:aaaa::10");
    const H: (&str, &str) = ("2a02:8:2:2::20", "2a02:8:2:2:bbbb::20");
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let v = behind_a_firewall(&lab, &format!("{}/64", V.0), &format!("{}/64", V.1));
        let h = behind_a_firewall(&lab, &format!("{}/64", H.0), &format!("{}/64", H.1));
        let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
        let (route, winner, elapsed) = ran.direct();
        assert_eq!(
            route,
            Route {
                same_site: false,
                ipv6: true
            }
        );
        assert_eq!(winner, CandidateKind::Host);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.says(), ("direct", Some("host"), true));
        assert_eq!(ran.asked, (Asked::of(1, 1, 0, 0), Asked::of(1, 1, 0, 0)));
        let offered: Vec<IpAddr> = ran.offered().iter().map(|(c, _)| c.addr.ip()).collect();
        assert_eq!(offered, [ip(V.1)]);
        for (stable, temporary) in [V, H] {
            let sent = lab.sent_by(&[ip(stable), ip(temporary)]);
            assert!(!sent.is_empty());
            assert!(
                sent.iter().all(|w| w.from.ip() == ip(temporary)),
                "{stable}"
            );
        }
    }
}

/// §12.4 "20 % loss, home × home → Direct", over eight seeds of a lossy
/// internet. Not met as the design states it: with half a second of Tor
/// each way the punch starts about 1 s after `T0`, and a QUIC handshake
/// with its Retry needs several clean flights; on some seeds the deadline
/// comes first. What holds on every seed: a direct path opens before the
/// punch timeout, or the viewer falls back at it (plus at most
/// `CLOSE_WAIT`, decision M1-79) with a named reason, and the host's
/// summary agrees. Measured: 4 of 8 seeds direct (2.4–2.8 s); the row stays
/// open in the ledger.
#[tokio::test(start_paused = true)]
async fn twenty_percent_loss_between_homes() {
    let lossy = LinkSpec {
        latency: ms(10),
        loss: 0.2,
    };
    let [low, _, high] = keys_by_order();
    let mut direct = 0;
    for seed in 1..=8 {
        let lab = Lab::with_internet(seed, lossy);
        let (v, _) = lab.viewer_home(|b| b);
        let (h, _) = lab.host_home(|b| b);
        let opts = NatOpts::new(low, high);
        let ran = run(&lab, v, h, &opts).await;
        match ran.went {
            Went::Direct { route, elapsed, .. } => {
                direct += 1;
                assert_eq!(route, INTERNET_V4, "seed {seed}");
                assert!(elapsed < PUNCH, "seed {seed}: {elapsed:?}");
                assert_eq!(ran.says().0, "direct", "seed {seed}");
            }
            Went::Tor { why, elapsed } => {
                assert!(elapsed >= PUNCH, "seed {seed}: {elapsed:?}");
                assert!(elapsed <= PUNCH + CLOSE_WAIT, "seed {seed}: {elapsed:?}");
                let name = match why {
                    TorWhy::Fallback(FallbackWhy::Quic) => "quic",
                    TorWhy::Fallback(FallbackWhy::NoPath { .. }) => "no-path",
                    other => panic!("seed {seed}: {other:?}"),
                };
                assert_eq!(ran.says(), (name, None, false), "seed {seed}");
            }
        }
        assert_eq!(ran.asked, (GATHERED, GATHERED), "seed {seed}");
    }
    assert!(direct >= 3, "{direct} of 8 seeds direct");
}

/// The viewer's home with a VPN: its physical address behind the home box,
/// and a tunnel interface (`10.8.0.2`) whose exit is a box at `185.0.0.1`
/// on the internet; the IPv4 route source is the tunnel. Its physical LAN
/// segment, for a firewall to stand in front of.
fn with_a_vpn(lab: &Lab, v6: Option<&str>) -> (MachineSpec, Segment) {
    let (mut v, _) = lab.viewer_home(|b| b);
    let home = v.addrs[0].segment;
    let tunnel = lab.net.segment(LinkSpec::LAN);
    let _exit = lab.net.nat(NatBox::home(tunnel, lab.internet, "185.0.0.1"));
    v.addrs.push(MemAddr {
        kind: IfaceKind::Tunnel,
        ..MemAddr::new(tunnel, "10.8.0.2/24")
    });
    let v6 = v6.map(|cidr| {
        let addr = MemAddr::new(home, cidr);
        let IpAddr::V6(v6) = addr.ip else {
            unreachable!("an IPv6 address");
        };
        v.addrs.push(addr);
        v6
    });
    v.sources = Some(RouteSources {
        v4: Some(Ipv4Addr::new(10, 8, 0, 2)),
        v6,
    });
    (v, home)
}

/// §12.4 "viewer VPN (`ProprietaryVirtual` default route) × home → zero
/// mapper calls; no global offered or contacted; srflx = tunnel exit": in
/// VPN mode the viewer asks no router, offers no global host address, and
/// sends nothing to a global address from its physical one; its STUN
/// server and the host see the tunnel's exit.
#[tokio::test(start_paused = true)]
async fn a_vpn_viewer_asks_no_router_and_offers_no_global() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let (v, _) = with_a_vpn(&lab, None);
        let (h, _) = lab.host_home(|b| b);
        let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
        let (route, _, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.says(), ("direct", Some("srflx"), false));
        assert_eq!(ran.asked, (Asked::of(1, 1, 1, 0), GATHERED));
        for (c, _) in ran.offered() {
            match c.kind {
                CandidateKind::Srflx => assert_eq!(c.addr.ip(), ip("185.0.0.1")),
                _ => assert!(!global(c.addr.ip()), "{c:?}"),
            }
        }
        assert!(
            lab.stun[0]
                .heard()
                .iter()
                .all(|h| h.from.ip() == ip("185.0.0.1"))
        );
        assert!(
            lab.sent_by(&[ip("192.168.1.10")])
                .iter()
                .all(|w| !global(w.to.ip())),
            "a global address contacted from the physical one"
        );
    }
}

/// §12.4 "viewer v4 through tunnel, v6 physical (split) × home → VPN mode;
/// no global v6 offered or contacted": the viewer's physical global IPv6
/// address is neither offered nor used, though the host offers its own
/// global IPv6 address; the session goes direct over IPv4 through the
/// tunnel.
#[tokio::test(start_paused = true)]
async fn a_split_tunnel_viewer_offers_no_global_ipv6() {
    const VIEWER_V6: &str = "2a01:4f8:1:1::10";
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let (v, home) = with_a_vpn(&lab, Some(&format!("{VIEWER_V6}/64")));
        let _firewall = lab.net.nat(NatBox::firewall(home, lab.internet));
        let (mut h, _) = lab.host_home(|b| b);
        let host_lan = h.addrs[0].segment;
        let _host_firewall = lab.net.nat(NatBox::firewall(host_lan, lab.internet));
        h.addrs.push(MemAddr::new(host_lan, "2a02:8:2:2::20/64"));
        let ran = run(&lab, v, h, &NatOpts::new(viewer, host)).await;
        let (route, _, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.says(), ("direct", Some("srflx"), false));
        assert_eq!(ran.asked, (Asked::of(1, 1, 1, 0), GATHERED));
        assert!(ran.offered().iter().all(|(c, _)| c.addr.is_ipv4()));
        assert!(
            offered(&ran.from_host)
                .iter()
                .any(|(c, _)| c.addr.is_ipv6()),
            "the host offered its IPv6 address"
        );
        assert!(lab.sent_by(&[ip(VIEWER_V6)]).is_empty());
    }
}

/// §12.4 "STUN off on both, home × home → zero resolves; `Tor(NoPath)`
/// unless a mapping or public host exists": with STUN off neither side
/// looks a name up; two homes behind filtering boxes fall back at the punch
/// timeout, while a host whose router maps its port, or a viewer with a
/// public address, still goes direct.
#[tokio::test(start_paused = true)]
async fn stun_off_falls_back_unless_a_mapping_or_a_public_side() {
    let [low, _, high] = keys_by_order();
    let opts = NatOpts::new(low, high).without_stun();
    // Two homes: nothing to offer but private addresses.
    let lab = Lab::new(1);
    let (v, _) = lab.viewer_home(|b| b);
    let (h, _) = lab.host_home(|b| b);
    let ran = run(&lab, v, h, &opts).await;
    let (why, elapsed) = ran.tor();
    assert!(
        matches!(why, TorWhy::Fallback(FallbackWhy::NoPath { .. })),
        "{why:?}"
    );
    assert_eq!(elapsed, PUNCH);
    assert_eq!(ran.says(), ("no-path", None, false));
    assert_eq!(ran.asked, (Asked::of(1, 1, 0, 1), Asked::of(1, 1, 0, 1)));
    // The host's router maps its port.
    let lab = Lab::new(1);
    let (v, _) = lab.viewer_home(|b| b);
    let (h, _) = lab.host_home(router(MapperMode::Ok));
    let ran = run(&lab, v, h, &opts).await;
    let (route, winner, _) = ran.direct();
    assert_eq!((route, winner), (INTERNET_V4, CandidateKind::Mapped));
    assert_eq!(ran.asked, (Asked::of(1, 1, 0, 1), Asked::of(1, 1, 0, 1)));
    // The viewer is public.
    let lab = Lab::new(1);
    let v = lab.public("83.0.0.10/24");
    let (h, _) = lab.host_home(|b| b);
    let ran = run(&lab, v, h, &opts).await;
    let (route, _, _) = ran.direct();
    assert_eq!(route, INTERNET_V4);
    assert_eq!(ran.says(), ("direct", Some("host"), false));
    assert_eq!(ran.asked, (Asked::of(1, 1, 0, 0), Asked::of(1, 1, 0, 1)));
    for server in &lab.stun {
        assert!(server.heard().is_empty());
    }
}

/// §12.4 "`LanOnly` viewer × `Any` host → scope same-site on both (echoed);
/// zero resolve/mapper on both": the viewer asks for the same-site scope,
/// the host's frames echo it, neither side looks a name up or takes its
/// mapper, and the session goes direct on the LAN. The host probes the
/// viewer's addresses as soon as the first `CANDIDATES` arrives, so on a LAN
/// its probes reach the viewer a Tor one-way before its own `CANDIDATES`
/// do: the viewer learns the host's address peer-reflexive (its winner is
/// `Prflx`), while the host's summary names the viewer's host candidate.
#[tokio::test(start_paused = true)]
async fn a_lan_only_viewer_keeps_both_sides_on_the_site() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let (v, _) = lab.viewer_home(|b| b);
        let lan = v.addrs[0].segment;
        let h = MachineSpec::on(lan, "192.168.1.20/24").gateway("192.168.1.1");
        let mut opts = NatOpts::new(viewer, host);
        opts.mine = Mine::of(TransportPolicy::LanOnly);
        let ran = run(&lab, v, h, &opts).await;
        let (route, winner, _) = ran.direct();
        assert_eq!(
            route,
            Route {
                same_site: true,
                ipv6: false
            }
        );
        assert_eq!(winner, CandidateKind::Prflx);
        assert_eq!(ran.transport, Some(TransportKind::Lan));
        assert_eq!(ran.says(), ("direct", Some("host"), false));
        assert_eq!(ran.asked, (Asked::of(1, 1, 0, 0), Asked::of(1, 1, 0, 0)));
        for frames in [&ran.from_viewer, &ran.from_host] {
            let scopes: Vec<u32> = frames
                .iter()
                .filter_map(|f| match f {
                    PathFrame::Candidates(c) => Some(c.scope_code()),
                    _ => None,
                })
                .collect();
            assert!(!scopes.is_empty());
            assert!(scopes.iter().all(|s| *s == scope::SAME_SITE), "{scopes:?}");
        }
    }
}

/// Settles the direct design's open residual of step B6 (decision M1-87):
/// a viewer with no host candidate in scope (an address on a carrier-grade
/// NAT only) whose gathering finds nothing (its STUN server silent, its
/// gateway's router too) used to send only `CANDIDATES_DONE` and wait for
/// its punch timeout. It now falls back as
/// soon as its gathering is over, with `NO_ADDRESSES`: at the gathering
/// budget, the one frame it writes is `TOR_FALLBACK{NO_ADDRESSES}`, and the
/// host, which starts its link at the first `CANDIDATES`, asks its network
/// nothing at all.
#[tokio::test(start_paused = true)]
async fn a_viewer_that_gathers_nothing_falls_back_at_once() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        lab.stun[0].set_mode(StunMode::Silent);
        let (v, _) = lab.carrier_only();
        let (h, _) = lab.host_home(|b| b);
        let opts = NatOpts::new(viewer, host);
        let ran = run(&lab, v, h, &opts).await;
        let (why, elapsed) = ran.tor();
        assert_eq!(why, TorWhy::Fallback(FallbackWhy::HereNoAddresses));
        assert_eq!(elapsed, GATHER_BUDGET);
        assert_eq!(
            ran.from_viewer,
            [PathFrame::TorFallback(Some(fallback::NO_ADDRESSES))]
        );
        assert!(ran.from_host.is_empty(), "{:?}", ran.from_host);
        assert_eq!(ran.says(), ("no-addresses", None, false));
        assert!(
            fallback_ms(elapsed, opts.one_way).contains(&ran.summary.ms),
            "{:?}",
            ran.summary
        );
        assert_eq!(ran.asked, (GATHERED, Asked::NOTHING));
    }
}

/// §12.4 "`LaggedDuplex` 1.5 s one way, home × home → Direct or
/// `Tor(HostSilent)` exactly at T0+4.0 s; nomination grace ≤ 600 ms". With
/// three times the delay the host's candidates reach the viewer 3 s after
/// `T0`. Where the punch completes (the host dials) the session is direct
/// just inside the timeout; where the viewer dials, its handshake is still
/// running at the timeout, so it falls back with `Quic` (the host's probes
/// did arrive, so not `HostSilent`), its fallback leaving after the link's
/// close (at most `CLOSE_WAIT`, decision M1-79): the design's row, as the
/// code reads it. The dialling side's first QUIC datagram follows the
/// first probe that reached it by at most the nomination grace and a round
/// trip.
#[tokio::test(start_paused = true)]
async fn a_one_and_a_half_second_signalling_delay() {
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let (v, _) = lab.viewer_home(|b| b);
        let (h, _) = lab.host_home(|b| b);
        let mut opts = NatOpts::new(viewer, host);
        opts.one_way = ms(1500);
        let ran = run(&lab, v, h, &opts).await;
        match ran.went {
            Went::Direct { route, elapsed, .. } => {
                assert_eq!(route, INTERNET_V4);
                assert!(elapsed < PUNCH, "{elapsed:?}");
                assert_eq!(ran.says().0, "direct");
            }
            Went::Tor { why, elapsed } => {
                assert_eq!(why, TorWhy::Fallback(FallbackWhy::Quic));
                assert!(
                    elapsed >= PUNCH && elapsed <= PUNCH + CLOSE_WAIT,
                    "{elapsed:?}"
                );
                assert_eq!(ran.says(), ("quic", None, false));
                assert!(
                    fallback_ms(PUNCH, opts.one_way).contains(&ran.summary.ms),
                    "{:?}",
                    ran.summary
                );
            }
        }
        let (dialler, other) = if viewer == keys_by_order()[0] {
            ("192.168.1.10", "192.168.2.20")
        } else {
            ("192.168.2.20", "192.168.1.10")
        };
        let first_quic = lab
            .sent_by(&[ip(dialler)])
            .into_iter()
            .filter(|w| w.kind == WireKind::Other)
            .map(|w| w.at)
            .min()
            .expect("the dialler sent QUIC");
        let first_probe = lab
            .sent_by(&[ip(other)])
            .into_iter()
            .filter(|w| w.kind == WireKind::Probe && w.fate == Fate::Delivered)
            .map(|w| w.at)
            .min()
            .expect("a probe reached the dialler");
        let grace = first_quic.saturating_duration_since(first_probe);
        assert!(grace <= GRACE_MAX + ms(100), "{grace:?}");
        assert_eq!(ran.asked, (GATHERED, GATHERED));
    }
}

/// The datagrams a victim's listener received.
type Heard = Arc<Mutex<Vec<Vec<u8>>>>;

/// A machine on the internet that only listens on `port`: every datagram
/// that reached it.
fn listening(lab: &Lab, cidr: &str, port: u16) -> (SocketAddr, Heard) {
    let machine = lab.net.machine(lab.public(cidr));
    let socket = machine.bind_udp(Some(port)).expect("a fresh port");
    let got: Heard = Arc::default();
    let heard = Arc::clone(&got);
    tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        loop {
            let mut meta = [RecvMeta::default()];
            let read = std::future::poll_fn(|cx| {
                let mut bufs = [IoSliceMut::new(&mut buf)];
                socket.poll_recv(cx, &mut bufs, &mut meta)
            })
            .await;
            if read.is_err() {
                return;
            }
            heard.lock().unwrap().push(buf[..meta[0].len].to_vec());
        }
    });
    (SocketAddr::new(machine.addrs()[0], port), got)
}

/// Sends `bytes` to `to` from `socket`, forged as coming from `from` (a
/// dual-stack socket takes an IPv4 destination v4-mapped, as the OS does).
fn forge(socket: &MemUdp, from: SocketAddr, to: SocketAddr, bytes: &[u8]) {
    socket.spoof_as(Some(from));
    let destination = match to.ip() {
        IpAddr::V4(v4) if socket.dual_stack() => {
            SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), to.port())
        }
        _ => to,
    };
    socket
        .try_send(&Transmit {
            destination,
            ecn: None,
            contents: bytes,
            segment_size: None,
            src_ip: None,
        })
        .expect("a forged datagram leaves");
}

/// The host's next `CANDIDATES`, read by a viewer played by hand.
async fn host_candidates(session: &mut ClientSession<LaggedDuplex>) -> Vec<Candidate> {
    loop {
        match session.next_event(Duration::from_secs(10)).await {
            Ok(Some(SessionEvent::Candidates(c))) => return from_wire(&c).0,
            Ok(Some(_)) => {}
            other => panic!("no CANDIDATES from the host: {other:?}"),
        }
    }
}

/// §12.4 "malicious peer lists 16 victim addresses + spoofs → ≤ 480 B per
/// victim, ≤ 5 760 B total, ≤ 2:1, zero QUIC bytes to victims, zero
/// responses to unadmitted sources". A viewer played by hand lists 16
/// public victims as its candidates; then, knowing the session's probe key,
/// it forges a dozen requests from each victim to the host, and some from
/// sources the host must not answer (a privileged port, the SSDP, PCP,
/// mDNS and LLMNR ports, a multicast address). What reached the victims,
/// read at their sockets and on the wire: at most four requests and eight
/// responses each (480 B), at most 5 760 B of probes from the host in all,
/// at most two bytes per forged byte, no QUIC datagram; nothing at all to
/// the refused sources. The host offered its own address, asked no STUN
/// server and no router, and its summary says `no-path`.
#[tokio::test(start_paused = true)]
async fn a_peer_listing_victims_and_forging_requests_draws_bounded_probes() {
    let [low, _, high] = keys_by_order();
    let lab = Lab::new(1);
    let host_ip = ip("84.0.0.20");
    let opts = NatOpts::new(high, low);
    let mut fx = nat_fixture(
        &lab,
        lab.public("83.0.0.10/24"),
        lab.public("84.0.0.20/24"),
        &opts,
    )
    .await;
    let victims: Vec<(SocketAddr, Heard)> = (1..=16_u16)
        .map(|n| listening(&lab, &format!("90.0.0.{n}/24"), 40_000 + n))
        .collect();
    let listed: Vec<Candidate> = victims
        .iter()
        .map(|(addr, _)| Candidate {
            kind: CandidateKind::Host,
            addr: *addr,
        })
        .collect();
    for frame in to_wire(&listed, Scope::Internet) {
        fx.session.send_candidates(&frame).await.unwrap();
    }
    fx.session.send_candidates_done().await.unwrap();
    let host_addr = host_candidates(&mut fx.session)
        .await
        .into_iter()
        .find(|c| c.addr.ip() == host_ip)
        .expect("the host offers its own address")
        .addr;

    let key = ProbeKey::derive(fx.session.session_token().bytes());
    let spoofer = lab.net.machine(lab.public("66.0.0.66/24"));
    let socket = spoofer.bind_udp(Some(40_666)).unwrap();
    let refused = [
        SocketAddr::new(victims[0].0.ip(), 53),
        SocketAddr::new(victims[0].0.ip(), 1900),
        SocketAddr::new(victims[0].0.ip(), 5351),
        SocketAddr::new(victims[0].0.ip(), 5353),
        SocketAddr::new(victims[0].0.ip(), 5355),
        at("224.0.0.251:5353"),
    ];
    let mut forged = 0_usize;
    for _ in 0..12 {
        for (victim, _) in &victims {
            let (_, request) = key.request(TornectRole::Viewer).expect("randomness");
            forge(&socket, *victim, host_addr, &request);
            forged += request.len();
        }
        for source in refused {
            let (_, request) = key.request(TornectRole::Viewer).expect("randomness");
            forge(&socket, source, host_addr, &request);
            forged += request.len();
        }
        tokio::time::sleep(ms(50)).await;
    }
    tokio::time::sleep(Duration::from_secs(8)).await;
    fx.session
        .send_tor_fallback(Some(fallback::NO_PATH))
        .await
        .unwrap();
    let host_asked = Asked::from(fx.host_env.calls());
    let (transport, summary) = fx.end(bye::USER).await;
    let summary = summary.expect("a path summary");
    assert_eq!(transport, None);
    assert_eq!(summary.outcome, "no-path");
    assert_eq!(host_asked, Asked::of(1, 1, 0, 0));

    let from_host: Vec<WireRecord> = lab.sent_by(&[host_ip]);
    let to_victims: Vec<&WireRecord> = from_host
        .iter()
        .filter(|w| victims.iter().any(|(v, _)| v.ip() == w.to.ip()))
        .collect();
    assert!(!to_victims.is_empty());
    assert!(
        to_victims.iter().all(|w| w.kind == WireKind::Probe),
        "QUIC to a victim"
    );
    let probe_bytes: usize = from_host
        .iter()
        .filter(|w| w.kind == WireKind::Probe)
        .map(|w| w.len)
        .sum();
    assert!(probe_bytes <= MAX_PROBE_BYTES, "{probe_bytes}");
    let victim_bytes: usize = to_victims.iter().map(|w| w.len).sum();
    assert!(
        victim_bytes <= 2 * forged,
        "{victim_bytes} out for {forged} forged"
    );
    let mut responses = 0;
    for (victim, got) in &victims {
        let bytes: usize = to_victims
            .iter()
            .filter(|w| w.to.ip() == victim.ip())
            .map(|w| w.len)
            .sum();
        assert!(bytes <= MAX_UNVALIDATED_BYTES, "{bytes} B to a victim");
        let got = got.lock().unwrap();
        let read: Vec<bool> = got
            .iter()
            .map(|d| {
                assert_eq!(d.len(), PROBE_LEN);
                key.decode(TornectRole::Viewer, d)
                    .expect("a probe")
                    .response
            })
            .collect();
        let answered = read.iter().filter(|r| **r).count();
        assert!(answered <= MAX_RESPONSES_PER_SOURCE, "{answered} responses");
        assert!(read.len() - answered <= MAX_REQUESTS_PER_TARGET);
        responses += answered;
    }
    assert!(responses > 0, "the forged requests reached the host");
    for source in refused {
        assert!(
            from_host.iter().all(|w| w.to != source),
            "a datagram to a refused source"
        );
    }
}

/// §12.4 "off-path spoofer races an Initial from the validated address →
/// Direct still established; the spoofed connection never completes": both
/// sides public on fixed ports, and from the start of the path phase an
/// off-path machine forges QUIC Initials from the dialling side's address
/// to the listening side every 25 ms. Each attempt's Retry goes to the
/// real dialler, so none of them completes; the real connection is
/// established, the session goes direct, and nothing is ever sent to the
/// spoofer's own address.
#[tokio::test(start_paused = true)]
async fn a_spoofed_initial_never_completes_and_the_path_still_opens() {
    let viewer_addr = at("83.0.0.10:50000");
    let host_addr = at("84.0.0.20:50001");
    let [low, _, _] = keys_by_order();
    for (viewer, host) in orders() {
        let lab = Lab::new(1);
        let mut opts = NatOpts::new(viewer, host);
        opts.viewer_options.direct_port = Some(viewer_addr.port());
        opts.host_options.direct_port = Some(host_addr.port());
        let (dialler, listener, listener_seed, role) = if viewer == low {
            (viewer_addr, host_addr, host, TornectRole::Viewer)
        } else {
            (host_addr, viewer_addr, viewer, TornectRole::Host)
        };
        let spoofer = lab.net.machine(lab.public("66.0.0.66/24"));
        let socket = spoofer.bind_udp(Some(40_666)).unwrap();
        socket.spoof_as(Some(dialler));
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config(),
            None,
            socket as Arc<dyn quinn::AsyncUdpSocket>,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let config = QuicIdentity::new(Arc::new(DeviceIdentity::from_seed(&[0x99; 32])))
            .client_config(&key(listener_seed).verifying_key().to_bytes(), role)
            .unwrap();
        let (ran, attempts) = run_with(
            &lab,
            lab.public("83.0.0.10/24"),
            lab.public("84.0.0.20/24"),
            &opts,
            |_| {
                tokio::spawn(async move {
                    let mut tries = Vec::new();
                    for _ in 0..120 {
                        let connecting = endpoint
                            .connect_with(config.clone(), listener, "tornect")
                            .expect("an attempt starts");
                        tries.push(tokio::spawn(async move {
                            tokio::time::timeout(Duration::from_secs(15), connecting).await
                        }));
                        tokio::time::sleep(ms(25)).await;
                    }
                    let mut completed = 0;
                    for attempt in tries {
                        if matches!(attempt.await, Ok(Ok(Ok(_)))) {
                            completed += 1;
                        }
                    }
                    (completed, endpoint)
                })
            },
        )
        .await;
        let (route, _, elapsed) = ran.direct();
        assert_eq!(route, INTERNET_V4);
        assert!(elapsed <= HOME_BOUND, "{elapsed:?}");
        assert_eq!(ran.says(), ("direct", Some("host"), false));
        let (completed, _endpoint) = attempts.await.unwrap();
        assert_eq!(completed, 0, "a spoofed connection completed");
        assert!(
            lab.net.wire().iter().all(|w| w.to.ip() != ip("66.0.0.66")),
            "a reply reached the spoofer's own address"
        );
    }
}

/// §12.4 "unattended `require_tor_only`, host knob `Any`, viewer sends
/// CANDIDATES → zero host `NetEnv` calls; outbox only `TOR_FALLBACK{OFF}`"
/// (the policy-source test end to end, design §9.2): a paired viewer
/// authenticates with its unattended password to a host whose own knob
/// allows direct paths, under a grant that requires Tor. The accept signs
/// `tor_only`; the viewer, played by hand, sends `CANDIDATES` all the same.
/// The host's half writes `TOR_FALLBACK{OFF}` and nothing else, and its
/// network is never touched, then or 40 s later.
#[tokio::test(start_paused = true)]
async fn an_unattended_grant_that_requires_tor_starts_nothing_at_the_host() {
    use tornect_core::keystore::FileSecretStore;
    use tornect_core::levels::{Elevation, FixedFacts};
    use tornect_core::paths::Paths;
    use tornect_core::session_log::{Actor, SessionLog};
    use tornect_core::unattended::clock::SystemClock;
    use tornect_core::unattended::grant::Preset;
    use tornect_core::unattended::guard::{
        AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
    };
    use tornect_core::unattended::ipc::GrantOptions;
    use tornect_core::unattended::limiter::{AttemptLimiter, HostTransport};
    use tornect_core::unattended::schedule::FixedOffset;
    use tornect_core::unattended::store::GrantStore;
    use tornect_signal::auth;
    use tornect_signal::fsm::client::UnattendedIntent;
    use tornect_signal::unattended::{GuardAdmin, OpaqueServerSetupSource, UnattendedAuth};
    use zeroize::Zeroizing;

    const PW: &str = "quiet verdant otter lantern zephyr";
    let [low, _, high] = keys_by_order();
    let opts = NatOpts::new(high, low);
    let lab = Lab::new(1);
    let tmp = tempfile::tempdir().unwrap();
    let onion = Arc::new(HostIdentity::from_seed(&[0x52; 32]));
    let host_onion_pk = *onion.id().public_key_bytes();
    let device = DeviceIdentity::from_seed(&[opts.viewer; 32]);
    let device_id = device.id();
    let trusted = Arc::new(TrustedDeviceStore::with(
        tmp.path().join("trusted-devices.toml"),
        tornect_core::trusted::TrustedDevices::default(),
    ));
    trusted.pin(device_id, "Laptop").unwrap();
    let host_device_pk = key(opts.host).verifying_key().to_bytes();

    let paths = Paths::from_home(tmp.path().join("host-home"));
    std::fs::create_dir_all(paths.keys_dir()).unwrap();
    let facts: Arc<dyn tornect_core::levels::FactsSource> = Arc::new(FixedFacts::linux());
    let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
    let store = GrantStore::open(
        &paths,
        secrets,
        Arc::new(SystemClock::default()),
        SessionLog::new(paths.sessions_log()),
    )
    .unwrap();
    let guard = Arc::new(
        MutationGuard::new(
            store,
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::clone(&facts),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(OpaqueServerSetupSource)),
    );
    let requires_tor = GrantOptions {
        require_tor_only: Some(true),
        ..GrantOptions::default()
    };
    guard.master_on(Actor::Cli, &host_onion_pk).unwrap();
    guard
        .create_grant(
            Actor::Cli,
            &device_id,
            Preset::HeadlessBox,
            &requires_tor,
            &[0u8; 192],
            false,
        )
        .unwrap();
    let setup = auth::parse_server_setup(&guard.store().server_setup().unwrap()).unwrap();
    let record = auth::register_locally(
        &setup,
        PW,
        device_id.public_key_bytes(),
        auth::identifiers(device_id.public_key_bytes(), &host_onion_pk),
    )
    .unwrap();
    guard
        .set_password(Actor::Cli, &device_id, &record, &requires_tor, false)
        .unwrap();
    assert_eq!(
        guard.store().grant(&device_id).map(|g| g.require_tor_only),
        Some(true)
    );

    let mut deps = HostDeps::headless(onion.clone(), trusted);
    deps.unattended = Arc::new(
        UnattendedAuth::new(
            AttemptLimiter::new(guard.store().clone()),
            Arc::new(FixedOffset::utc()),
            HostTransport::default(),
            facts,
        )
        .with_admin_authority(Arc::new(GuardAdmin::new(Arc::clone(&guard))))
        .with_block_guard(Arc::clone(&guard)),
    );
    let host_env = CountingEnv::new(lab.net.machine(lab.public("84.0.0.20/24")));
    let (taps, ends, _rig) = host_half(&mut deps, &host_env, &opts);
    let mut cfg = HostConfig::new("Desk", host_device_pk);
    cfg.transport = TransportKnob::fixed(ANY);
    cfg.feats = vec![feats::UA1.to_owned(), feats::DIR1.to_owned()];
    let (client_end, host_end) = lagged_duplex(64 * 1024, opts.one_way);
    let fsm = tokio::spawn(async move { serve_host(host_end, &cfg, &deps).await.map(|_| ()) });

    let known = Arc::new(KnownHostStore::with(
        tmp.path().join("known-hosts.toml"),
        tornect_core::trusted::KnownHosts::default(),
    ));
    known.pin(onion.id(), "Desk", host_device_pk).unwrap();
    let mut client_deps = ClientDeps::headless(known);
    client_deps.ui = Arc::new(ScriptedClientUi::new(true));
    let mut ccfg = ClientConfig::new(onion.id(), "Laptop");
    ccfg.feats = vec![feats::UA1.to_owned(), feats::DIR1.to_owned()];
    let intent = Intent::Unattended(UnattendedIntent {
        password: Zeroizing::new(PW.to_owned()),
        want_mode: messages::mode::CONTROL,
        want_elevation: Elevation::None,
    });
    let ClientOutcome::Session(session) =
        client::connect(client_end, &ccfg, &device, &client_deps, intent)
            .await
            .unwrap()
    else {
        panic!("no session");
    };
    let mut session = *session;
    assert!(session.unattended());
    assert_eq!(session.transport_policy(), TransportPolicy::TorOnly);
    let viewer_candidate = Candidate {
        kind: CandidateKind::Srflx,
        addr: at("83.0.0.10:50000"),
    };
    for frame in to_wire(&[viewer_candidate], Scope::Internet) {
        session.send_candidates(&frame).await.unwrap();
    }
    session.send_candidates_done().await.unwrap();
    let event = session.next_event(Duration::from_secs(10)).await.unwrap();
    assert!(
        matches!(event, Some(SessionEvent::TorFallback(Some(fallback::OFF)))),
        "{event:?}"
    );
    tokio::time::sleep(Duration::from_secs(40)).await;
    assert_eq!(
        *taps.from_host.lock().unwrap(),
        [PathFrame::TorFallback(Some(fallback::OFF))]
    );
    assert_eq!(Asked::from(host_env.calls()), Asked::NOTHING);
    assert!(lab.net.wire().is_empty(), "the host's network was used");
    session.bye(bye::USER).await.unwrap();
    let (transport, summary) = ends.line().await;
    fsm.await.unwrap().unwrap();
    assert_eq!(transport, None);
    assert_eq!(summary.map(|s| s.outcome), Some("off".to_owned()));
}
