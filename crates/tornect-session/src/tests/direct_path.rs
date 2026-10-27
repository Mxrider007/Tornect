//! Step A17: the viewer's half of the direct path
//! ([`ViewerDirect::choose_path`]) against the real host FSM and its
//! [`DirectHost`] on in-memory networks (`MemNet`), and against hosts played
//! by hand: the viewer's cells of the direct design §12.3's MemNet table,
//! every decision-table cell's frames with no network call on either side,
//! the frame limits, and the viewer's kill liveness. Paused time, except
//! where a capture has to open.

use std::future::pending;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tornect_core::session_log::{PathSummary, TransportKind};
use tornect_net::mem::{
    CountingEnv, EnvCalls, Fate, InboundRule, LinkSpec, MachineSpec, MemHost, MemNet, Segment,
};
use tornect_net::{Candidate, CandidateKind, Route, Scope};
use tornect_signal::HandshakeError;
use tornect_signal::Kind;
use tornect_signal::consent::{TransportKnob, TransportPolicy};
use tornect_signal::fsm::client::ClientSession;
use tornect_signal::fsm::{
    Channel, NoPaths, PATH_INBOX, PathExchange, PathFrame, PathPort, PathRecord, harness,
};
use tornect_signal::messages::{self, decode_body, encode_body, fallback, feats, scope, transport};

use super::direct_host::{Ends, key, keys_by_order, until};
use super::*;

const ANY: TransportPolicy = TransportPolicy::Any;
const TOR: TransportPolicy = TransportPolicy::TorOnly;
const LAN: TransportPolicy = TransportPolicy::LanOnly;

/// The app's bind wait for the media stream (`MEDIA_BIND_WAIT`, the direct
/// design §4 "Constants"): what the caller gives [`DirectMedia::bind`].
const BIND_WAIT: Duration = Duration::from_secs(30);

/// The default punch window (`network.punch_timeout_ms`).
const PUNCH: Duration = Duration::from_secs(4);

/// A path exchange that records the viewer's frames as the host FSM hands
/// them on, then passes them to the host's own half (when it has an inbox).
struct Tap {
    inner: Arc<dyn PathExchange>,
    frames: Arc<Mutex<Vec<PathFrame>>>,
}

impl PathExchange for Tap {
    fn open(&self, session: &LiveSession<'_>) -> PathPort {
        let mut port = self.inner.open(session);
        let inner = port.inbox.take();
        let (inbox, mut frames_in) = mpsc::channel::<PathFrame>(PATH_INBOX);
        let frames = Arc::clone(&self.frames);
        tokio::spawn(async move {
            while let Some(frame) = frames_in.recv().await {
                frames.lock().unwrap().push(frame.clone());
                if let Some(inner) = &inner {
                    let _ = inner.try_send(frame);
                }
            }
        });
        port.inbox = Some(inbox);
        port
    }

    fn outcome(&self, session_id: &str) -> PathRecord {
        self.inner.outcome(session_id)
    }
}

/// What the host runs for the session's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostHalf {
    /// [`DirectHost`] on the host machine.
    Direct,
    /// Nothing: a host that announces `dir1` and never answers.
    Silent,
}

/// The viewer's and the host's machines, given the test LAN and a second
/// segment linked to nothing.
type Machines = Box<dyn Fn(Segment, Segment) -> (MachineSpec, MachineSpec)>;

/// How a test session is set up.
struct Opts {
    host_policy: TransportPolicy,
    host_dir1: bool,
    half: HostHalf,
    /// The session's viewer device key.
    viewer: u8,
    /// The viewer's link key, when it is not the session's (a pin the host
    /// refuses).
    link_key: Option<u8>,
    host: u8,
    seed: u64,
    lan: LinkSpec,
    machines: Machines,
    punch: Duration,
    backend: fn() -> TestBackend,
}

impl Opts {
    fn new(viewer: u8, host: u8) -> Self {
        Self {
            host_policy: ANY,
            host_dir1: true,
            half: HostHalf::Direct,
            viewer,
            link_key: None,
            host,
            seed: 7,
            lan: LinkSpec::LAN,
            machines: on_the_lan(MachineSpec::default()),
            punch: PUNCH,
            backend: TestBackend::default,
        }
    }
}

/// Both machines on the test LAN (`192.168.1.10` the viewer, `.20` the
/// host), the host's spec otherwise `host`.
fn on_the_lan(host: MachineSpec) -> Machines {
    Box::new(move |lan, _| {
        (
            MachineSpec::on(lan, "192.168.1.10/24"),
            MachineSpec {
                addrs: MachineSpec::on(lan, "192.168.1.20/24").addrs,
                ..host.clone()
            },
        )
    })
}

/// One accepted session through the real FSMs over a pipe, the host's half
/// of its path behind a [`Tap`], the viewer's [`ViewerDirect`] on the same
/// `MemNet`.
struct Fx {
    session: ClientSession<DuplexStream>,
    session_id: String,
    viewer: ViewerDirect,
    viewer_env: Arc<CountingEnv<MemHost>>,
    host_env: Arc<CountingEnv<MemHost>>,
    /// The host's half, when it runs one.
    direct: Option<Arc<DirectHost>>,
    rig: Rig,
    frames: Arc<Mutex<Vec<PathFrame>>>,
    ends: Arc<Ends>,
    fsm: JoinHandle<Result<(), HandshakeError>>,
    net: MemNet,
    _tmp: tempfile::TempDir,
}

async fn fixture(opts: &Opts) -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let onion = Arc::new(HostIdentity::from_seed(&[0x52; 32]));
    let trusted = Arc::new(TrustedDeviceStore::with(
        tmp.path().join("trusted-devices.toml"),
        tornect_core::trusted::TrustedDevices::default(),
    ));
    let consent = Arc::new(ScriptedConsent::new());
    consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let rig = rig_with((opts.backend)(), MediaLimits::default());
    let mut deps = HostDeps::headless(onion.clone(), trusted);
    deps.consent = consent;
    deps.sessions = rig.host.clone();
    let ends = Arc::new(Ends::default());
    deps.audit = ends.clone();

    let net = MemNet::new(opts.seed);
    let lan = net.segment(opts.lan);
    let away = net.segment(LinkSpec::LAN);
    let (viewer_spec, host_spec) = (opts.machines)(lan, away);
    let viewer_env = CountingEnv::new(net.machine(viewer_spec));
    let host_env = CountingEnv::new(net.machine(host_spec));
    let host_key = key(opts.host);
    let direct = (opts.half == HostHalf::Direct).then(|| {
        Arc::new(DirectHost::new(
            rig.host.clone(),
            None,
            Arc::clone(&host_key),
            DirectSettings::default(),
            host_env.clone(),
            deps.kill.clone(),
            Arc::new(|_: &MediaOutcome| {}),
        ))
    });
    let inner: Arc<dyn PathExchange> = match &direct {
        Some(direct) => direct.clone(),
        None => Arc::new(NoPaths),
    };
    let frames = Arc::default();
    deps.paths = Arc::new(Tap {
        inner,
        frames: Arc::clone(&frames),
    });
    let mut cfg = HostConfig::new("Desk", host_key.verifying_key().to_bytes());
    cfg.transport = TransportKnob::fixed(opts.host_policy);
    if opts.host_dir1 {
        cfg.feats.push(feats::DIR1.to_owned());
    }
    let (client_end, host_end) = duplex(64 * 1024);
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
    let session = *session;
    let session_id = session.session_token().session_id();
    let settings = DirectSettings::new(DirectOptions {
        direct_port: None,
        punch_timeout: opts.punch,
    });
    let viewer = ViewerDirect::new(
        key(opts.link_key.unwrap_or(opts.viewer)),
        settings,
        viewer_env.clone(),
    );
    Fx {
        session,
        session_id,
        viewer,
        viewer_env,
        host_env,
        direct,
        rig,
        frames,
        ends,
        fsm,
        net,
        _tmp: tmp,
    }
}

impl Fx {
    /// The session's path phase, with nothing to interrupt it.
    async fn choose(&mut self, mine: Mine, media: bool) -> PathChoice {
        self.viewer
            .choose_path(&mut self.session, mine, media, pending())
            .await
    }

    /// The viewer's path frames as the host FSM handed them on, once at
    /// least `n` have.
    async fn frames(&self, n: usize) -> Vec<PathFrame> {
        until("the viewer's frames", || {
            self.frames.lock().unwrap().len() >= n
        })
        .await;
        self.frames.lock().unwrap().clone()
    }

    /// Neither side called the network.
    fn no_network_call(&self, what: &str) {
        assert_eq!(
            self.viewer_env.calls(),
            EnvCalls::default(),
            "viewer: {what}"
        );
        assert_eq!(self.host_env.calls(), EnvCalls::default(), "host: {what}");
    }

    /// No send of either machine was refused for its family, its source or
    /// its route (the direct design §12.3 "zero `InvalidInput`").
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

    /// The datagrams the viewer's machine sent so far.
    fn viewer_sent(&self) -> u64 {
        self.viewer_env.inner().counters().sent
    }

    /// The viewer ends the session with `BYE{reason}`; the host's end line.
    async fn end(self, reason: u16) -> (Option<TransportKind>, Option<PathSummary>) {
        self.session.bye(reason).await.unwrap();
        let line = self.ends.line().await;
        self.fsm.await.unwrap().unwrap();
        line
    }
}

fn direct(choice: PathChoice) -> Box<DirectMedia> {
    match choice {
        PathChoice::Direct(media) => media,
        other => panic!("not direct: {other:?}"),
    }
}

fn tor(choice: &PathChoice) -> (TorWhy, Duration) {
    match choice {
        PathChoice::Tor { why, elapsed } => (*why, *elapsed),
        other => panic!("not Tor: {other:?}"),
    }
}

fn fell_back(why: FallbackWhy) -> TorWhy {
    TorWhy::Fallback(why)
}

/// The viewer's first `CANDIDATES` (same-site scope) and its `DONE`, then
/// `rest`.
fn exchanged_then(frames: &[PathFrame], rest: &[PathFrame]) {
    assert!(frames.len() >= 2, "{frames:?}");
    let PathFrame::Candidates(first) = &frames[0] else {
        panic!("{frames:?}");
    };
    assert_eq!(first.scope, Some(scope::SAME_SITE));
    assert_eq!(frames[1], PathFrame::Done, "{frames:?}");
    assert_eq!(&frames[2..], rest, "{frames:?}");
}

/// The direct design §12.3 "same segment", "host `Stateful` → Direct" and
/// "dual-stack `MemUdp` on both sides → Direct with zero `InvalidInput`",
/// through both FSMs: with either side dialling, and behind a stateful host
/// firewall, `choose_path` opens the media stream on the same-site route
/// within a second of the accept. The host was sent one `CANDIDATES`
/// (same-site scope) and `DONE`, nothing else; each side read its
/// interfaces once and bound once, and no send was refused.
#[tokio::test(start_paused = true)]
async fn the_viewer_goes_direct_on_a_lan() {
    let [low, _, high] = keys_by_order();
    for (viewer, host, inbound) in [
        (low, high, InboundRule::Open),
        (high, low, InboundRule::Open),
        (low, high, InboundRule::Stateful),
    ] {
        let mut opts = Opts::new(viewer, host);
        opts.machines = on_the_lan(MachineSpec {
            inbound,
            ..MachineSpec::default()
        });
        let mut fx = fixture(&opts).await;
        let media = direct(fx.choose(Mine::of(ANY), true).await);
        assert_eq!(
            media.route,
            Route {
                same_site: true,
                ipv6: false
            }
        );
        assert_eq!(PathEnd::Direct(media.route).route_words(), "direct lan");
        assert_eq!(media.winner, CandidateKind::Host);
        assert!(
            media.elapsed < Duration::from_secs(1),
            "{:?}",
            media.elapsed
        );
        assert!(media.binding.is_direct());
        assert!(media.link.stats().dual_stack);
        exchanged_then(&fx.frames(2).await, &[]);
        for env in [&fx.viewer_env, &fx.host_env] {
            let calls = env.calls();
            assert_eq!((calls.interfaces, calls.binds), (1, 1), "{calls:?}");
        }
        fx.sent_cleanly();
        assert_eq!(
            fx.viewer.stats(),
            ViewerDirectStats {
                links_started: 1,
                ..ViewerDirectStats::default()
            }
        );
        drop(media);
        fx.end(bye::USER).await;
    }
}

/// §12.3 "20 % loss": the punch and the handshake ride out a lossy LAN.
#[tokio::test(start_paused = true)]
async fn twenty_percent_loss_still_goes_direct() {
    let [viewer, _, host] = keys_by_order();
    let mut lost = 0;
    for seed in 1..=4 {
        let mut opts = Opts::new(viewer, host);
        opts.seed = seed;
        opts.lan = LinkSpec {
            latency: Duration::from_millis(2),
            loss: 0.2,
        };
        let mut fx = fixture(&opts).await;
        let media = direct(fx.choose(Mine::of(ANY), true).await);
        assert!(media.elapsed < PUNCH, "seed {seed}: {:?}", media.elapsed);
        lost += fx
            .net
            .wire()
            .iter()
            .filter(|w| w.fate == Fate::Lost)
            .count();
        drop(media);
        fx.end(bye::USER).await;
    }
    assert!(lost > 0);
}

/// §12.3 "ULA on both → an IPv6 route", at the session level.
#[tokio::test(start_paused = true)]
async fn ula_on_both_sides_goes_direct_over_ipv6() {
    let [viewer, _, host] = keys_by_order();
    let mut opts = Opts::new(viewer, host);
    opts.machines = Box::new(|lan, _| {
        (
            MachineSpec::on(lan, "fd12:3456:789a:1::10/64"),
            MachineSpec::on(lan, "fd12:3456:789a:1::20/64"),
        )
    });
    let mut fx = fixture(&opts).await;
    let media = direct(fx.choose(Mine::of(ANY), true).await);
    assert_eq!(
        media.route,
        Route {
            same_site: true,
            ipv6: true
        }
    );
    assert_eq!(
        PathEnd::Direct(media.route).route_words(),
        "direct lan ipv6"
    );
    fx.sent_cleanly();
    drop(media);
    fx.end(bye::USER).await;
}

/// §12.3 "different segments → `Tor(NoPath)` ≤ T0+4 s": the same private
/// range at two sites. The early failure ends the attempt before the cap;
/// the link is closed before `TOR_FALLBACK{NO_PATH}` is written, and no
/// datagram leaves the viewer afterwards.
#[tokio::test(start_paused = true)]
async fn different_segments_fall_back_early_with_no_path() {
    let [viewer, _, host] = keys_by_order();
    let mut opts = Opts::new(viewer, host);
    opts.machines = Box::new(|here, there| {
        (
            MachineSpec::on(here, "192.168.1.10/24"),
            MachineSpec::on(there, "192.168.1.20/24"),
        )
    });
    let mut fx = fixture(&opts).await;
    let choice = fx.choose(Mine::of(ANY), true).await;
    let (why, elapsed) = tor(&choice);
    assert_eq!(why, fell_back(FallbackWhy::NoPath { heard: false }));
    assert_eq!(choice.path_end().unwrap().route_words(), "tor no-path");
    assert!(elapsed < PUNCH, "{elapsed:?}");
    exchanged_then(
        &fx.frames(3).await,
        &[PathFrame::TorFallback(Some(fallback::NO_PATH))],
    );
    let sent = fx.viewer_sent();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(fx.viewer_sent(), sent, "the link was closed");
    assert!(fx.net.wire().iter().all(|w| w.fate == Fate::Unroutable));
    fx.sent_cleanly();
    fx.end(bye::USER).await;
}

/// §12.3 "host `Blocked` → `Tor(NoPath{heard: true})`": the host's probes
/// reach the viewer, nothing reaches the host; the reason names the
/// firewall.
#[tokio::test(start_paused = true)]
async fn a_blocked_host_is_heard_and_named_a_firewall() {
    let [viewer, _, host] = keys_by_order();
    let mut opts = Opts::new(viewer, host);
    opts.machines = on_the_lan(MachineSpec {
        inbound: InboundRule::Blocked,
        ..MachineSpec::default()
    });
    let mut fx = fixture(&opts).await;
    let choice = fx.choose(Mine::of(ANY), true).await;
    let (why, elapsed) = tor(&choice);
    assert_eq!(why, fell_back(FallbackWhy::NoPath { heard: true }));
    assert_eq!(why.cli_name(), "no-path-firewall");
    assert!(elapsed < PUNCH, "{elapsed:?}");
    exchanged_then(
        &fx.frames(3).await,
        &[PathFrame::TorFallback(Some(fallback::NO_PATH))],
    );
    fx.end(bye::USER).await;
}

/// §12.3 "host silent → `Tor(HostSilent)` at T0+4 s": a host that
/// announced `dir1` and never answers, neither a frame nor a probe. The
/// fallback comes exactly at the punch timeout from the accept, with the
/// `PEER_SILENT` reason; a 1 s setting moves it to 1 s.
#[tokio::test(start_paused = true)]
async fn a_silent_host_falls_back_at_the_punch_timeout() {
    let [viewer, _, host] = keys_by_order();
    for punch in [PUNCH, Duration::from_secs(1)] {
        let mut opts = Opts::new(viewer, host);
        opts.half = HostHalf::Silent;
        opts.punch = punch;
        let mut fx = fixture(&opts).await;
        let choice = fx.choose(Mine::of(ANY), true).await;
        let (why, elapsed) = tor(&choice);
        assert_eq!(why, fell_back(FallbackWhy::HostSilent));
        assert_eq!(elapsed, punch);
        exchanged_then(
            &fx.frames(3).await,
            &[PathFrame::TorFallback(Some(fallback::PEER_SILENT))],
        );
        assert_eq!(fx.host_env.calls(), EnvCalls::default());
        fx.end(bye::USER).await;
    }
}

/// §12.3 "host bind fails → `Tor(HostSocket)`", and a host without an
/// address: the host's own `TOR_FALLBACK` names its reason, which the
/// viewer keeps (`host-no-addresses`, `host-socket`) and answers
/// `TOR_FALLBACK{PEER_OFF}` after closing its link. Under the viewer's
/// `lan_only` the session ends instead, with no `TOR_FALLBACK`.
#[tokio::test(start_paused = true)]
async fn a_host_that_cannot_take_part_is_named() {
    let [viewer, _, host] = keys_by_order();
    let no_address: fn(Segment, Segment) -> (MachineSpec, MachineSpec) = |lan, _| {
        (
            MachineSpec::on(lan, "192.168.1.10/24"),
            MachineSpec::default(),
        )
    };
    let no_socket: fn(Segment, Segment) -> (MachineSpec, MachineSpec) = |lan, _| {
        (
            MachineSpec::on(lan, "192.168.1.10/24"),
            MachineSpec {
                fail_bind: true,
                ..MachineSpec::on(lan, "192.168.1.20/24")
            },
        )
    };
    for (machines, want) in [
        (no_address, FallbackWhy::HostNoAddresses),
        (no_socket, FallbackWhy::HostSocket),
    ] {
        for mine in [ANY, LAN] {
            let mut opts = Opts::new(viewer, host);
            opts.machines = Box::new(machines);
            let mut fx = fixture(&opts).await;
            let choice = fx.choose(Mine::of(mine), true).await;
            if mine == LAN {
                assert!(
                    matches!(choice, PathChoice::End(bye::NO_LAN_PATH)),
                    "{choice:?}"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                exchanged_then(&fx.frames(2).await, &[]);
                fx.end(bye::NO_LAN_PATH).await;
            } else {
                assert_eq!(tor(&choice).0, fell_back(want));
                exchanged_then(
                    &fx.frames(3).await,
                    &[PathFrame::TorFallback(Some(fallback::PEER_OFF))],
                );
                fx.end(bye::USER).await;
            }
        }
    }
}

/// §12.3 "no address → `NO_ADDRESSES` with zero binds", on the viewer: it
/// reads its interfaces once, binds nothing and says
/// `TOR_FALLBACK{NO_ADDRESSES}`; the host, which goes second, calls
/// nothing. A viewer whose bind fails says `TOR_FALLBACK{SOCKET}`.
#[tokio::test(start_paused = true)]
async fn a_viewer_that_cannot_take_part_says_why_with_no_bind() {
    let [viewer, _, host] = keys_by_order();
    let no_address: fn(Segment, Segment) -> (MachineSpec, MachineSpec) = |lan, _| {
        (
            MachineSpec::default(),
            MachineSpec::on(lan, "192.168.1.20/24"),
        )
    };
    let no_socket: fn(Segment, Segment) -> (MachineSpec, MachineSpec) = |lan, _| {
        (
            MachineSpec {
                fail_bind: true,
                ..MachineSpec::on(lan, "192.168.1.10/24")
            },
            MachineSpec::on(lan, "192.168.1.20/24"),
        )
    };
    for (machines, why, code, binds) in [
        (
            no_address,
            FallbackWhy::HereNoAddresses,
            fallback::NO_ADDRESSES,
            0,
        ),
        (no_socket, FallbackWhy::HereSocket, fallback::SOCKET, 1),
    ] {
        let mut opts = Opts::new(viewer, host);
        opts.machines = Box::new(machines);
        let mut fx = fixture(&opts).await;
        let choice = fx.choose(Mine::of(ANY), true).await;
        assert_eq!(tor(&choice), (fell_back(why), Duration::ZERO));
        assert_eq!(
            fx.frames(1).await,
            [PathFrame::TorFallback(Some(code))],
            "{why:?}"
        );
        let calls = fx.viewer_env.calls();
        assert_eq!((calls.interfaces, calls.binds), (1, binds), "{why:?}");
        assert_eq!(fx.host_env.calls(), EnvCalls::default());
        assert_eq!(fx.viewer.stats().start_failed, 1);
        assert_eq!(fx.viewer.stats().links_started, 0);
        fx.end(bye::USER).await;
    }
}

/// §12.3 "`LanOnly` viewer with no path → `BYE{NO_LAN_PATH}` and
/// `PathEnd::LanRefused`", and the same for a `lan_only` host's session: no
/// `TOR_FALLBACK` is written; the caller's `BYE{NO_LAN_PATH}` ends the
/// session, which never bound media.
#[tokio::test(start_paused = true)]
async fn a_lan_only_session_with_no_path_ends() {
    let [viewer, _, host] = keys_by_order();
    for (host_policy, mine) in [(ANY, LAN), (LAN, ANY), (LAN, LAN)] {
        let mut opts = Opts::new(viewer, host);
        opts.host_policy = host_policy;
        opts.machines = Box::new(|here, there| {
            (
                MachineSpec::on(here, "192.168.1.10/24"),
                MachineSpec::on(there, "192.168.1.20/24"),
            )
        });
        let mut fx = fixture(&opts).await;
        let t0 = Instant::now();
        let choice = fx.choose(Mine::of(mine), true).await;
        assert!(
            matches!(choice, PathChoice::End(bye::NO_LAN_PATH)),
            "{choice:?}"
        );
        assert_eq!(choice.path_end(), Some(PathEnd::LanRefused));
        assert_eq!(PathEnd::LanRefused.route_words(), "none no-lan-path");
        assert!(t0.elapsed() < PUNCH, "{:?}", t0.elapsed());
        tokio::time::sleep(Duration::from_secs(1)).await;
        exchanged_then(&fx.frames(2).await, &[]);
        let (transport, _) = fx.end(bye::NO_LAN_PATH).await;
        assert_eq!(transport, None);
    }
}

/// One cell of the decision table: the host's signed policy, this side's,
/// whether the session carries media, whether the viewer is the host's own
/// device, whether the host is too old for `dir1`.
struct Cell {
    host_policy: TransportPolicy,
    mine: Mine,
    media: bool,
    same_device: bool,
    old_host: bool,
}

/// The direct design §4's decision table and rules 1–3, every cell through
/// both FSMs with `DirectHost` (§5.2 rule 3, §12.3 "each decision-table
/// cell with its exact frames and `CountingEnv` counts"): the one frame the
/// viewer writes at the accept, or none, and not one network call on
/// either side, then or 20 s later.
#[tokio::test(start_paused = true)]
async fn each_decision_cell_writes_its_frame_and_touches_no_network() {
    let [viewer, _, host] = keys_by_order();
    let bridged = Mine {
        policy: TOR,
        bridged: true,
    };
    let off = |code| vec![PathFrame::TorFallback(Some(code))];
    let cell = |host_policy, mine, media, same_device, old_host| Cell {
        host_policy,
        mine,
        media,
        same_device,
        old_host,
    };
    let cells = [
        (
            cell(ANY, Mine::of(TOR), true, false, false),
            PathEnd::Tor(TorWhy::HereOff),
            off(fallback::OFF),
        ),
        (
            cell(ANY, bridged, true, false, false),
            PathEnd::Tor(TorWhy::Bridge),
            off(fallback::OFF),
        ),
        (
            cell(TOR, Mine::of(ANY), true, false, false),
            PathEnd::Tor(TorWhy::HostPolicy),
            off(fallback::PEER_OFF),
        ),
        (
            cell(TOR, Mine::of(TOR), true, false, false),
            PathEnd::Tor(TorWhy::HostPolicy),
            off(fallback::OFF),
        ),
        (
            cell(TOR, Mine::of(LAN), true, false, false),
            PathEnd::LanRefused,
            vec![],
        ),
        (
            cell(LAN, Mine::of(TOR), true, false, false),
            PathEnd::LanRefused,
            vec![],
        ),
        (
            cell(ANY, Mine::of(ANY), false, false, false),
            PathEnd::NoMedia,
            off(fallback::NO_MEDIA),
        ),
        (
            cell(TOR, Mine::of(LAN), false, false, false),
            PathEnd::NoMedia,
            off(fallback::NO_MEDIA),
        ),
        (
            cell(ANY, Mine::of(ANY), true, true, false),
            PathEnd::Tor(TorWhy::SameDevice),
            off(fallback::OFF),
        ),
        (
            cell(ANY, Mine::of(LAN), true, true, false),
            PathEnd::LanRefused,
            vec![],
        ),
        (
            cell(ANY, Mine::of(ANY), true, false, true),
            PathEnd::Tor(TorWhy::OldHost),
            vec![PathFrame::TorFallback(None)],
        ),
        (
            cell(ANY, Mine::of(LAN), true, false, true),
            PathEnd::LanRefused,
            vec![],
        ),
    ];
    for (
        Cell {
            host_policy,
            mine,
            media,
            same_device,
            old_host,
        },
        want,
        frames,
    ) in cells
    {
        let cell =
            format!("{host_policy:?} {mine:?} media {media} same {same_device} old {old_host}");
        let mut opts = Opts::new(if same_device { host } else { viewer }, host);
        opts.host_policy = host_policy;
        opts.host_dir1 = !old_host;
        let mut fx = fixture(&opts).await;
        let choice = fx.choose(mine, media).await;
        assert_eq!(choice.path_end(), Some(want), "{cell}");
        if let PathChoice::Tor { elapsed, .. } = choice {
            assert_eq!(elapsed, Duration::ZERO, "{cell}");
        }
        assert_eq!(fx.frames(frames.len()).await, frames, "{cell}");
        fx.no_network_call(&cell);
        // The caller ends a refused session at once; any other goes on, and
        // its path still makes no call later.
        let reason = if want == PathEnd::LanRefused {
            bye::NO_LAN_PATH
        } else {
            tokio::time::sleep(HOST_DIRECT_LINGER).await;
            assert_eq!(fx.frames(0).await, frames, "{cell}");
            fx.no_network_call(&cell);
            bye::USER
        };
        assert_eq!(fx.viewer.stats(), ViewerDirectStats::default(), "{cell}");
        let (transport, _) = fx.end(reason).await;
        assert_eq!(transport, None, "{cell}");
    }
}

/// A refused direct `Bind` ends the session, with no fallback (the direct
/// design §4 "A refused direct Bind ends the session", §12.3): the bind
/// fails `BindRefused{BAD_BIND}`, [`DirectMedia::bind`] says
/// [`AfterBind::End`], nothing opened at the host, and its end line says
/// `bind-refused`.
#[tokio::test(start_paused = true)]
async fn a_refused_direct_bind_ends_the_session() {
    let [viewer, _, host] = keys_by_order();
    let mut fx = fixture(&Opts::new(viewer, host)).await;
    let mut media = direct(fx.choose(Mine::of(ANY), true).await);
    media.binding = Binding::direct(fx.session.session_token(), &fx.session.th(), &[0x5a; 32]);
    let failed = media.bind(WAIT).await.unwrap_err();
    assert!(
        matches!(failed.error, ViewerError::Refused(r) if r == reason::BAD_BIND),
        "{failed:?}"
    );
    assert_eq!(failed.after, AfterBind::End);
    assert_eq!(fx.rig.backend.sources.load(Ordering::SeqCst), 0);
    exchanged_then(&fx.frames(2).await, &[]);
    // The caller's `BYE` crosses Tor in about half a second; by then the
    // host has seen the connection close (here the pipe has no delay).
    let host = fx.direct.clone().expect("a direct host");
    until("the host's link closed", || host.stats().links_open == 0).await;
    let (transport, path) = fx.end(bye::USER).await;
    assert_eq!(transport, None);
    assert_eq!(path.expect("a summary").outcome, "bind-refused");
}

/// DIRECT-2's one exception, through the caller: the viewer's link
/// presents another key than the session's, so the host's TLS refuses it
/// after the viewer's handshake completed. The `Bind` fails before any
/// host byte, [`DirectMedia::bind`] says [`AfterBind::Fallback`], and the
/// caller's `TOR_FALLBACK{QUIC}` reaches the host, whose end line says
/// `pin-refused`.
#[tokio::test(start_paused = true)]
async fn a_pin_the_host_refuses_leaves_the_onion_fallback_open() {
    let [viewer, other, host] = keys_by_order();
    let mut opts = Opts::new(viewer, host);
    opts.link_key = Some(other);
    let mut fx = fixture(&opts).await;
    let media = direct(fx.choose(Mine::of(ANY), true).await);
    let failed = media.bind(WAIT).await.unwrap_err();
    assert_eq!(failed.after, AfterBind::Fallback, "{:?}", failed.error);
    fx.session
        .send_tor_fallback(Some(fallback::QUIC))
        .await
        .unwrap();
    exchanged_then(
        &fx.frames(3).await,
        &[PathFrame::TorFallback(Some(fallback::QUIC))],
    );
    let (transport, path) = fx.end(bye::USER).await;
    assert_eq!(transport, None);
    assert_eq!(path.expect("a summary").outcome, "pin-refused");
}

/// Revision 1 blocker 1 through the caller (the direct design §4
/// "Constants", §12.1): `choose_path` hands over an open stream well inside
/// the 4 s punch window, and the caller's bind wait (30 s) covers the host's
/// 5 s source open: the session binds directly, the host claims the LAN
/// route, one source opened. The same session bound with the punch window
/// as its wait would have timed out at 4 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_five_second_dialog_binds_through_the_caller() {
    let [viewer, _, host] = keys_by_order();
    let mut opts = Opts::new(viewer, host);
    opts.backend = || TestBackend {
        open_for: Some(Duration::from_secs(5)),
        ..TestBackend::default()
    };
    let (mut patient, mut hasty) = tokio::join!(fixture(&opts), fixture(&opts));
    let (bound, cut_short) = tokio::join!(
        bind_through(&mut patient, BIND_WAIT),
        bind_through(&mut hasty, PUNCH)
    );
    let (bound, took) = bound;
    let bound = bound.expect("the direct bind outlasts the dialog");
    assert!(took >= Duration::from_secs(5), "{took:?}");
    assert_eq!(
        patient.rig.host.route(&patient.session_id),
        Some(TransportKind::Lan)
    );
    assert_eq!(patient.rig.backend.sources.load(Ordering::SeqCst), 1);
    let (cut_short, took) = cut_short;
    let failed = cut_short.expect_err("a 4 s wait cannot outlast a 5 s dialog");
    assert!(
        matches!(failed.error, ViewerError::Timeout(_)),
        "{failed:?}"
    );
    assert_eq!(failed.after, AfterBind::End);
    assert!(took >= PUNCH && took < Duration::from_secs(5), "{took:?}");
    drop(bound);
    let (transport, path) = patient.end(bye::USER).await;
    assert_eq!(transport, Some(TransportKind::Lan));
    assert_eq!(path.expect("a summary").outcome, "direct");
    hasty.end(bye::USER).await;
}

/// `choose_path` then the direct bind with `wait`: the bind's result and
/// the time from the call.
async fn bind_through(
    fx: &mut Fx,
    wait: Duration,
) -> (Result<MediaViewer<QuicStream>, DirectBindFailed>, Duration) {
    let t0 = Instant::now();
    let media = direct(fx.choose(Mine::of(ANY), true).await);
    assert!(media.elapsed < PUNCH, "{:?}", media.elapsed);
    let bound = media.bind(wait).await;
    (bound, t0.elapsed())
}

/// A client end whose writes can be frozen (a host that withholds credit).
struct Freezable {
    inner: DuplexStream,
    frozen: Arc<AtomicBool>,
}

impl AsyncRead for Freezable {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Freezable {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.frozen.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.frozen.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.frozen.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A session with a host played by hand ([`harness::raw_session_with`]):
/// the host's signed `feats` and policy as given, its device key the
/// harness's. The viewer's half runs on a LAN machine of its own.
struct Raw<S> {
    session: ClientSession<S>,
    host: Channel<DuplexStream>,
    viewer: ViewerDirect,
    env: Arc<CountingEnv<MemHost>>,
    _net: MemNet,
}

async fn raw<S>(client_end: S, host_end: DuplexStream, host_feats: &[&str], policy: u8) -> Raw<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (session, host) = harness::raw_session_with(client_end, host_end, host_feats, policy).await;
    let net = MemNet::new(5);
    let lan = net.segment(LinkSpec::LAN);
    let env = CountingEnv::new(net.machine(MachineSpec::on(lan, "192.168.1.10/24")));
    let viewer = ViewerDirect::new(key(0x31), DirectSettings::default(), env.clone());
    Raw {
        session,
        host,
        viewer,
        env,
        _net: net,
    }
}

async fn raw_duplex(host_feats: &[&str], policy: u8) -> Raw<DuplexStream> {
    let (client_end, host_end) = duplex(64 * 1024);
    raw(client_end, host_end, host_feats, policy).await
}

/// The viewer's next frame, as the host reads it.
async fn viewer_frame(host: &mut Channel<DuplexStream>) -> (Kind, Vec<u8>) {
    let rx = host
        .recv(WAIT, "the viewer's frame")
        .await
        .unwrap()
        .expect("a frame");
    (rx.env.kind, rx.env.body.clone())
}

/// A host candidate on the test LAN at `port`, where nothing listens.
fn theirs(port: u16) -> Candidate {
    Candidate {
        kind: CandidateKind::Host,
        addr: SocketAddr::from(([192, 168, 1, 20], port)),
    }
}

/// §12.3 "old host (no `dir1`) → `TOR_FALLBACK{}` bytes `A0` at T0, zero
/// viewer `NetEnv` calls" (rule 2), exactly as M1 sent it; a `lan_only`
/// viewer instead ends the session having written nothing.
#[tokio::test(start_paused = true)]
async fn an_old_host_is_sent_the_m1_bytes_at_once() {
    let mut fx = raw_duplex(&[], transport::ANY).await;
    let choice = fx
        .viewer
        .choose_path(&mut fx.session, Mine::of(ANY), true, pending())
        .await;
    assert_eq!(tor(&choice), (TorWhy::OldHost, Duration::ZERO));
    assert_eq!(choice.path_end().unwrap().route_words(), "tor old-host");
    let (kind, body) = viewer_frame(&mut fx.host).await;
    assert_eq!((kind, body), (Kind::TorFallback, vec![0xA0]));
    assert_eq!(fx.env.calls(), EnvCalls::default());

    let mut fx = raw_duplex(&[], transport::ANY).await;
    let choice = fx
        .viewer
        .choose_path(&mut fx.session, Mine::of(LAN), true, pending())
        .await;
    assert!(
        matches!(choice, PathChoice::End(bye::NO_LAN_PATH)),
        "{choice:?}"
    );
    let nothing = fx.host.recv(Duration::from_secs(1), "nothing").await;
    assert!(
        matches!(nothing, Err(HandshakeError::Timeout(_))),
        "{nothing:?}"
    );
    assert_eq!(fx.env.calls(), EnvCalls::default());
}

/// The direct design §4 "Frame limits" and "Scope", on the viewer: of the
/// host's frames it takes at most 6 `CANDIDATES` and one `DONE` (the rest
/// are dropped and counted, never answered), and drops (and counts) a frame
/// whose scope is above its own; the host's `TOR_FALLBACK{OFF}` then ends
/// the attempt as the host's policy, answered `PEER_OFF` after the link
/// closed. The viewer's own frames carry its scope.
#[tokio::test(start_paused = true)]
async fn the_hosts_frames_are_limited_and_scoped() {
    let mut fx = raw_duplex(&[feats::DIR1], transport::ANY).await;
    let host = &mut fx.host;
    let script = async {
        let (kind, body) = viewer_frame(host).await;
        assert_eq!(kind, Kind::Candidates);
        let ours: messages::Candidates = decode_body(&body).unwrap();
        assert_eq!(ours.scope, Some(scope::SAME_SITE));
        assert_eq!(viewer_frame(host).await.0, Kind::CandidatesDone);
        let internet = to_wire(&[theirs(40_000)], Scope::Internet).remove(0);
        host.send(&internet, None).await.unwrap();
        for port in 40_001..=40_006 {
            let frame = to_wire(&[theirs(port)], Scope::SameSite).remove(0);
            host.send(&frame, None).await.unwrap();
        }
        for _ in 0..2 {
            host.send(&messages::CandidatesDone {}, None).await.unwrap();
        }
        let off = messages::TorFallback {
            reason: Some(fallback::OFF),
        };
        host.send(&off, None).await.unwrap();
        let (kind, body) = viewer_frame(host).await;
        assert_eq!(kind, Kind::TorFallback);
        decode_body::<messages::TorFallback>(&body).unwrap().reason
    };
    let (choice, answered) = tokio::join!(
        fx.viewer
            .choose_path(&mut fx.session, Mine::of(ANY), true, pending()),
        script
    );
    assert_eq!(tor(&choice).0, TorWhy::HostPolicy);
    assert_eq!(answered, Some(fallback::PEER_OFF));
    assert_eq!(
        fx.viewer.stats(),
        ViewerDirectStats {
            links_started: 1,
            start_failed: 0,
            frames_dropped: 2,
            frames_out_of_scope: 1,
        }
    );
}

/// A host frame that does not parse ends the path phase as a broken
/// session: the viewer answers `ERROR` (bounded) and closes its link. A
/// host `BYE` during the punch is handed back as the session's end.
#[tokio::test(start_paused = true)]
async fn a_host_fault_or_bye_during_the_punch_ends_the_path_phase() {
    for bye_instead in [false, true] {
        let mut fx = raw_duplex(&[feats::DIR1], transport::ANY).await;
        let host = &mut fx.host;
        let script = async {
            assert_eq!(viewer_frame(host).await.0, Kind::Candidates);
            assert_eq!(viewer_frame(host).await.0, Kind::CandidatesDone);
            if bye_instead {
                let end = messages::Bye {
                    reason: bye::USER,
                    detail: None,
                };
                host.send(&end, None).await.unwrap();
                None
            } else {
                let garbage = encode_body(&messages::Ping { nonce: 1 });
                host.send_kind(Kind::Candidates, garbage, None)
                    .await
                    .unwrap();
                Some(viewer_frame(host).await.0)
            }
        };
        let sent_before = fx.env.inner().counters().sent;
        let (choice, answer) = tokio::join!(
            fx.viewer
                .choose_path(&mut fx.session, Mine::of(ANY), true, pending()),
            script
        );
        if bye_instead {
            assert!(
                matches!(
                    choice,
                    PathChoice::HostEnded(SessionEvent::Bye {
                        reason: bye::USER,
                        ..
                    })
                ),
                "{choice:?}"
            );
        } else {
            assert!(
                matches!(choice, PathChoice::Broken(HandshakeError::Violation { .. })),
                "{choice:?}"
            );
            assert_eq!(answer, Some(Kind::Error));
        }
        assert_eq!(choice.path_end(), None);
        assert!(fx.env.inner().counters().sent >= sent_before);
        let sent = fx.env.inner().counters().sent;
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(fx.env.inner().counters().sent, sent, "the link was closed");
    }
}

/// A host `PING` during the punch is answered on the way (the direct design
/// §4 "the select loop with `flush_owed`"): its `PONG` comes back before the
/// host has said anything else, and the silent host still gets its
/// `TOR_FALLBACK{PEER_SILENT}` exactly at the punch timeout (a `PING` is
/// not a path frame, so the host was not heard).
#[tokio::test(start_paused = true)]
async fn a_host_ping_is_answered_while_punching() {
    let mut fx = raw_duplex(&[feats::DIR1], transport::ANY).await;
    let host = &mut fx.host;
    let script = async {
        assert_eq!(viewer_frame(host).await.0, Kind::Candidates);
        assert_eq!(viewer_frame(host).await.0, Kind::CandidatesDone);
        tokio::time::sleep(Duration::from_secs(1)).await;
        host.send(&messages::Ping { nonce: 7 }, None).await.unwrap();
        let sent = Instant::now();
        let (kind, body) = viewer_frame(host).await;
        assert_eq!(kind, Kind::Pong);
        assert_eq!(decode_body::<messages::Pong>(&body).unwrap().nonce, 7);
        assert_eq!(Instant::now(), sent, "answered without waiting");
        let (kind, body) = viewer_frame(host).await;
        assert_eq!(kind, Kind::TorFallback);
        decode_body::<messages::TorFallback>(&body).unwrap().reason
    };
    let (choice, reason) = tokio::join!(
        fx.viewer
            .choose_path(&mut fx.session, Mine::of(ANY), true, pending()),
        script
    );
    assert_eq!(
        tor(&choice),
        (TorWhy::Fallback(FallbackWhy::HostSilent), PUNCH)
    );
    assert_eq!(reason, Some(fallback::PEER_SILENT));
    assert!(!fx.session.owes());
}

/// The viewer's kill liveness in `choose_path` (the direct design §4
/// "Cancel safety and kill liveness", §12.3; the step A3 row's
/// `choose_path` form): a host `PING` arrives while the viewer punches and
/// its window is full, so the owed `PONG` cannot be written. The caller's
/// stop ends the call at once — `PathChoice::Interrupted` within one poll,
/// the `PONG` still owed, never awaited — and the link is shut: nothing
/// more leaves the viewer's machine.
#[tokio::test(start_paused = true)]
async fn a_stop_beats_a_pong_owed_while_punching() {
    let (client_end, host_end) = duplex(64 * 1024);
    let frozen = Arc::new(AtomicBool::new(false));
    let stream = Freezable {
        inner: client_end,
        frozen: Arc::clone(&frozen),
    };
    let mut fx = raw(stream, host_end, &[feats::DIR1], transport::ANY).await;
    let (stop, stopped) = oneshot::channel::<()>();
    let host = &mut fx.host;
    let script = async {
        assert_eq!(viewer_frame(host).await.0, Kind::Candidates);
        assert_eq!(viewer_frame(host).await.0, Kind::CandidatesDone);
        frozen.store(true, Ordering::SeqCst);
        host.send(&messages::Ping { nonce: 9 }, None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let at = Instant::now();
        stop.send(()).unwrap();
        at
    };
    let interrupted = async {
        let _ = stopped.await;
    };
    let (choice, stopped_at) = tokio::time::timeout(WAIT, async {
        tokio::join!(
            fx.viewer
                .choose_path(&mut fx.session, Mine::of(ANY), true, interrupted),
            script
        )
    })
    .await
    .expect("the stop ended the path phase");
    assert!(matches!(choice, PathChoice::Interrupted), "{choice:?}");
    assert_eq!(Instant::now(), stopped_at, "within one poll of the stop");
    assert!(fx.session.owes(), "the PONG was not awaited");
    let sent = fx.env.inner().counters().sent;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(fx.env.inner().counters().sent, sent, "the link is shut");
    drop(fx.session);
    let seen = fx.host.recv(Duration::from_secs(1), "the close").await;
    assert!(matches!(seen, Ok(None)), "the host saw a frame: {seen:?}");
}
