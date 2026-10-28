//! Step A16: the host's half of the direct path ([`DirectHost`]) behind the
//! real handshake FSM, on in-memory networks (`MemNet`), with the viewer's
//! half played by hand until step A17's path chooser (the direct design
//! §8.5, and the host half of §12.3's MemNet table). Without media the
//! tests run on paused time; the ones that stream pictures run in real time.

use std::future::pending;

use tornect_core::levels::Elevation;
use tornect_core::session_log::{PathSummary, TransportKind};
use tornect_net::mem::{
    CountingEnv, EnvCalls, InboundRule, LinkSpec, MachineSpec, MemHost, MemNet, Segment,
};
use tornect_net::{
    Candidate, CandidateKind, DirectFail, DirectLink, DirectParams, Established, LinkNews, Scope,
    TornectRole,
};
use tornect_signal::consent::{TransportKnob, TransportPolicy};
use tornect_signal::fsm::client::ClientSession;
use tornect_signal::fsm::host::{HandshakeStats, KillSwitch};
use tornect_signal::fsm::{AuditEvent, HandshakeAudit, PathExchange, PathFrame, PathPort};
use tornect_signal::messages::{fallback, feats, scope};
use zeroize::Zeroizing;

use super::*;

/// Three device-key seeds, lowest public key first: of a pair, the lower
/// key dials the direct connection and the higher accepts.
pub(super) fn keys_by_order() -> [u8; 3] {
    let mut seeds = [101, 102, 103];
    seeds.sort_by_key(|seed| key(*seed).verifying_key().to_bytes());
    seeds
}

pub(super) fn key(seed: u8) -> Arc<DeviceIdentity> {
    Arc::new(DeviceIdentity::from_seed(&[seed; 32]))
}

/// Each session's end line: its media route and its path summary.
#[derive(Default)]
pub(super) struct Ends(Mutex<Vec<(Option<TransportKind>, Option<PathSummary>)>>);

impl HandshakeAudit for Ends {
    fn record(&self, event: AuditEvent) {
        if let AuditEvent::SessionEnded {
            transport, path, ..
        } = event
        {
            self.0.lock().unwrap().push((transport, path));
        }
    }
}

impl Ends {
    /// The one session's end line, once written.
    pub(super) async fn line(&self) -> (Option<TransportKind>, Option<PathSummary>) {
        until("the session's end line", || {
            !self.0.lock().unwrap().is_empty()
        })
        .await;
        let lines = self.0.lock().unwrap();
        assert_eq!(lines.len(), 1);
        lines[0].clone()
    }
}

/// Waits until `check` holds.
pub(super) async fn until(what: &str, check: impl Fn() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} in time"));
}

/// How a test session is set up.
struct Opts {
    policy: TransportPolicy,
    viewer: u8,
    host: u8,
    dir1: bool,
    /// The host machine on the test LAN.
    host_machine: fn(Segment) -> MachineSpec,
}

impl Opts {
    fn new(policy: TransportPolicy, viewer: u8, host: u8) -> Self {
        Self {
            policy,
            viewer,
            host,
            dir1: true,
            host_machine: |lan| MachineSpec::on(lan, "192.168.1.20/24"),
        }
    }
}

/// The host side: its media layer, its direct host and what they report.
struct Host {
    rig: Rig,
    direct: Arc<DirectHost>,
    env: Arc<CountingEnv<MemHost>>,
    kill: KillSwitch,
    ends: Arc<Ends>,
    stats: Arc<HandshakeStats>,
    media: Arc<Mutex<Vec<MediaOutcome>>>,
}

impl Host {
    fn links_open(&self) -> u64 {
        self.direct.stats().links_open
    }

    fn media_seen(&self) -> Vec<MediaOutcome> {
        self.media.lock().unwrap().clone()
    }
}

/// One accepted session through the real FSMs over a pipe, its host's
/// direct path on a `MemNet` LAN.
struct Fixture {
    host: Host,
    session: ClientSession<DuplexStream>,
    session_id: String,
    fsm: JoinHandle<Result<(), tornect_signal::fsm::HandshakeError>>,
    net: MemNet,
    lan: Segment,
    _tmp: tempfile::TempDir,
}

async fn fixture(opts: &Opts) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let onion = Arc::new(HostIdentity::from_seed(&[0x51; 32]));
    let trusted = Arc::new(TrustedDeviceStore::with(
        tmp.path().join("trusted-devices.toml"),
        tornect_core::trusted::TrustedDevices::default(),
    ));
    let consent = Arc::new(ScriptedConsent::new());
    consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let rig = rig(MediaLimits::default());
    let mut deps = HostDeps::headless(onion.clone(), trusted);
    deps.consent = consent;
    deps.sessions = rig.host.clone();
    let ends = Arc::new(Ends::default());
    deps.audit = ends.clone();

    let net = MemNet::new(7);
    let lan = net.segment(LinkSpec::LAN);
    let env = CountingEnv::new(net.machine((opts.host_machine)(lan)));
    let media = Arc::new(Mutex::new(Vec::new()));
    let heard = Arc::clone(&media);
    let host_key = key(opts.host);
    let direct = Arc::new(DirectHost::new(
        rig.host.clone(),
        None,
        Arc::clone(&host_key),
        DirectSettings::default(),
        env.clone(),
        deps.kill.clone(),
        Arc::new(move |outcome: &MediaOutcome| heard.lock().unwrap().push(outcome.clone())),
    ));
    deps.paths = direct.clone();
    let kill = deps.kill.clone();
    let stats = deps.stats.clone();
    let mut cfg = HostConfig::new("Desk", host_key.verifying_key().to_bytes());
    cfg.transport = TransportKnob::fixed(opts.policy);
    cfg.feats.push(feats::DIR1.to_owned());
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
    if opts.dir1 {
        ccfg.feats.push(feats::DIR1.to_owned());
    }
    let ClientOutcome::Session(session) =
        client::connect(client_end, &ccfg, &device, &client_deps, Intent::Session)
            .await
            .unwrap()
    else {
        panic!("no session");
    };
    let session = *session;
    let session_id = session.session_token().session_id();
    Fixture {
        host: Host {
            rig,
            direct,
            env,
            kill,
            ends,
            stats,
            media,
        },
        session,
        session_id,
        fsm,
        net,
        lan,
        _tmp: tmp,
    }
}

impl Fixture {
    /// The viewer's link with device key `identity` on `machine` (the
    /// session's own key, or another one for a pin the host refuses).
    async fn viewer_link(
        &self,
        identity: Arc<DeviceIdentity>,
        machine: &MemHost,
    ) -> (DirectLink, Vec<Candidate>) {
        let params = DirectParams {
            me: TornectRole::Viewer,
            identity,
            peer_pk: self.session.host_device_pk(),
            session_token: Zeroizing::new(*self.session.session_token().bytes()),
            direct_port: None,
            scope: Scope::SameSite,
            gather: tornect_net::GatherConfig::default(),
        };
        DirectLink::start(params, Arc::new(machine.clone()))
            .await
            .expect("the viewer's link")
    }

    /// A viewer machine on the test LAN.
    fn viewer_machine(&self) -> MemHost {
        self.net
            .machine(MachineSpec::on(self.lan, "192.168.1.10/24"))
    }

    /// The direct `Binding` over `ekm`.
    fn binding(&self, ekm: &[u8; 32]) -> Binding {
        Binding::direct(self.session.session_token(), &self.session.th(), ekm)
    }

    /// The viewer's `CANDIDATES` (one frame) and `CANDIDATES_DONE`.
    async fn send_candidates(&mut self, offered: &[Candidate]) {
        for frame in to_wire(offered, Scope::SameSite) {
            self.session.send_candidates(&frame).await.unwrap();
        }
        self.session.send_candidates_done().await.unwrap();
    }

    /// The next session event within `wait`.
    async fn event(&mut self, wait: Duration) -> Option<SessionEvent> {
        self.session.next_event(wait).await.unwrap()
    }

    /// No session event comes for `wait` (a host `PING` is answered on the
    /// way).
    async fn quiet(&mut self, wait: Duration) {
        let deadline = tokio::time::Instant::now() + wait;
        while let Ok(ready) = tokio::time::timeout_at(deadline, self.session.event_ready()).await {
            ready.unwrap();
            if let Some(event) = self.session.take_event().unwrap() {
                panic!("unexpected {event:?}");
            }
            if self.session.owes() {
                self.session.flush_owed().await.unwrap();
            }
        }
    }
}

/// The viewer's half of the path frames, by hand (step A17 writes the real
/// one): sends `offered` and `CANDIDATES_DONE`, then gives the host's frames
/// to `link` until the link's connection comes. Returns it and the host's
/// path frames.
async fn exchange(
    session: &mut ClientSession<DuplexStream>,
    link: &mut DirectLink,
    offered: &[Candidate],
) -> (Established, Vec<SessionEvent>) {
    for frame in to_wire(offered, Scope::SameSite) {
        session.send_candidates(&frame).await.unwrap();
    }
    session.send_candidates_done().await.unwrap();
    let mut heard = Vec::new();
    loop {
        tokio::select! {
            ready = session.event_ready() => {
                ready.unwrap();
                if let Some(event) = session.take_event().unwrap() {
                    match &event {
                        SessionEvent::Candidates(frame) => {
                            let (batch, scope) = from_wire(frame);
                            link.add_remote(batch, scope);
                        }
                        SessionEvent::CandidatesDone => link.remote_done(),
                        other => panic!("unexpected {other:?}"),
                    }
                    heard.push(event);
                }
                if session.owes() {
                    session.flush_owed().await.unwrap();
                }
            }
            news = link.next_news() => match news {
                LinkNews::Local(_) | LinkNews::Connection(Err(DirectFail::NoPath { .. })) => {}
                LinkNews::Connection(Ok(conn)) => return (conn, heard),
                LinkNews::Connection(Err(fail)) => panic!("{fail:?}"),
            },
        }
    }
}

/// A candidate on the test LAN that nothing answers.
fn silent_candidate() -> Candidate {
    Candidate {
        kind: CandidateKind::Host,
        addr: "192.168.1.10:50000".parse().unwrap(),
    }
}

/// The whole path through the real FSM (the direct design §8.5 steps 1–6):
/// the host binds on the viewer's first `CANDIDATES` and answers with its
/// own (the same-site scope echoed) and `CANDIDATES_DONE`; the viewer dials,
/// binds directly and gets pictures from a capture that opened only after
/// the bind; a `TOR_FALLBACK` after the claim is ignored and the media
/// goes on; when the viewer ends the session, the media's `Close` still
/// reaches it before the link closes (the drain), and the host's end line
/// says `direct`, `host`, IPv4, with the LAN route. One bind, one link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_goes_direct_through_the_real_fsm() {
    let [viewer, _, host] = keys_by_order();
    let mut fx = fixture(&Opts::new(TransportPolicy::Any, viewer, host)).await;
    let machine = fx.viewer_machine();
    let (mut link, offered) = fx.viewer_link(key(viewer), &machine).await;
    assert_eq!(
        fx.host.env.calls(),
        EnvCalls::default(),
        "nothing before CANDIDATES"
    );
    let (conn, heard) = tokio::time::timeout(WAIT, exchange(&mut fx.session, &mut link, &offered))
        .await
        .expect("connected in time");
    let SessionEvent::Candidates(first) = &heard[0] else {
        panic!("{heard:?}");
    };
    assert_eq!(first.scope, Some(scope::SAME_SITE));
    assert!(heard.contains(&SessionEvent::CandidatesDone));
    assert!(conn.route().same_site);
    assert_eq!(fx.host.rig.backend.sources.load(Ordering::SeqCst), 0);

    let ekm = conn
        .binding_secret(fx.session.session_token().bytes())
        .unwrap();
    let stream = conn.open_stream(1).await.unwrap();
    let viewer_media = MediaViewer::bind(stream, &fx.binding(&ekm), WAIT)
        .await
        .unwrap();
    let media = fx.host.rig.host.clone();
    let id = fx.session_id.clone();
    assert_eq!(media.route(&id), Some(TransportKind::Lan));

    let (mut pictures, enough) = Pictures::wanting(3);
    let mut session = fx.session;
    let direct = Arc::clone(&fx.host.direct);
    let ender = tokio::spawn(async move {
        let _ = enough.await;
        session
            .send_tor_fallback(Some(fallback::QUIC))
            .await
            .unwrap();
        until("the late fallback", || direct.stats().late_fallbacks == 1).await;
        let after = (direct.stats().links_open, media.route(&id));
        session.bye(bye::USER).await.unwrap();
        after
    });
    let mut stats = ViewerStats::default();
    let end = viewer_media
        .run(&mut pictures, &mut stats, pending())
        .await
        .unwrap();
    let (links_open, route) = ender.await.unwrap();
    assert_eq!((links_open, route), (1, Some(TransportKind::Lan)));
    assert!(pictures.indices.len() >= 3);
    assert_eq!(
        end,
        ViewerEnd::Host(reason::SESSION_OVER),
        "the media's Close reached the viewer before the link closed"
    );

    let (transport, path) = fx.host.ends.line().await;
    assert_eq!(transport, Some(TransportKind::Lan));
    let path = path.expect("a path summary");
    assert_eq!(path.outcome, "direct");
    assert_eq!(path.winner.as_deref(), Some("host"));
    assert!(!path.ipv6);
    until("the link closed", || fx.host.links_open() == 0).await;
    assert_eq!(fx.host.env.calls().binds, 1);
    assert_eq!(fx.host.direct.stats().links_started, 1);
    assert!(matches!(
        fx.host.media_seen()[..],
        [MediaOutcome::Served { .. }]
    ));
    fx.fsm.await.unwrap().unwrap();
    drop((conn, link));
}

/// A session registered as the FSM registers it, for [`DirectHost::open`]
/// called directly.
struct Lone {
    rig: Rig,
    direct: DirectHost,
    env: Arc<CountingEnv<MemHost>>,
    identity: Arc<DeviceIdentity>,
    _net: MemNet,
}

fn lone() -> Lone {
    let net = MemNet::new(3);
    let lan = net.segment(LinkSpec::LAN);
    let env = CountingEnv::new(net.machine(MachineSpec::on(lan, "192.168.1.20/24")));
    let rig = rig(MediaLimits::default());
    let identity = key(0x77);
    let direct = DirectHost::new(
        rig.host.clone(),
        None,
        Arc::clone(&identity),
        DirectSettings::default(),
        env.clone(),
        KillSwitch::new(),
        Arc::new(|_: &MediaOutcome| {}),
    );
    Lone {
        rig,
        direct,
        env,
        identity,
        _net: net,
    }
}

impl Lone {
    /// Opens the path of a session of `device` under `transport`, after the
    /// media layer registered it.
    fn open(
        &self,
        device: DeviceId,
        transport: TransportPolicy,
        viewer_dir1: bool,
    ) -> (String, PathPort) {
        let token = SessionToken::new([0x61; 32]);
        let id = token.session_id();
        let live = LiveSession {
            device,
            label: "Laptop",
            session_id: &id,
            token: &token,
            th_final: [0x62; 32],
            mode: SessionMode::Control,
            elevation: Elevation::None,
            unattended: false,
            transport,
            viewer_dir1,
        };
        self.rig.host.on_start(&live);
        let port = self.direct.open(&live);
        (id, port)
    }
}

/// The outbox's frames until it closes.
async fn answered(port: &mut PathPort) -> Vec<PathFrame> {
    let mut outbox = port.outbox.take().expect("an outbox");
    let mut frames = Vec::new();
    while let Some(frame) = outbox.recv().await {
        frames.push(frame);
    }
    frames
}

/// The policy-source test's direct-host half (the direct design §8.5
/// `open()`, §9.2): the session's signed policy and this same device are
/// all it takes. A `tor_only` session and the host's own device are
/// answered `TOR_FALLBACK{OFF}` (a `lan_only` session of this device ends
/// `BYE{NO_LAN_PATH}`), the viewer's frames have nowhere to go (no inbox:
/// the FSM drops and counts them), and in 40 s nothing calls the network
/// at all. The end line says `off`.
#[tokio::test(start_paused = true)]
async fn a_tor_only_session_and_this_same_device_are_answered_off_with_no_network_call() {
    let other = DeviceId::from_bytes([7; 32]);
    for (policy, same_device, want) in [
        (
            TransportPolicy::TorOnly,
            false,
            PathFrame::TorFallback(Some(fallback::OFF)),
        ),
        (
            TransportPolicy::Any,
            true,
            PathFrame::TorFallback(Some(fallback::OFF)),
        ),
        (
            TransportPolicy::LanOnly,
            true,
            PathFrame::End(bye::NO_LAN_PATH),
        ),
    ] {
        let lone = lone();
        let device = if same_device {
            lone.identity.id()
        } else {
            other
        };
        let (id, mut port) = lone.open(device, policy, true);
        assert!(port.inbox.is_none(), "{policy:?}");
        assert_eq!(answered(&mut port).await, [want]);
        tokio::time::sleep(HOST_DIRECT_LINGER * 2).await;
        assert_eq!(lone.env.calls(), EnvCalls::default(), "{policy:?}");
        let record = lone.direct.outcome(&id);
        assert_eq!(record.path.expect("a summary").outcome, "off");
        assert_eq!(record.transport, None);
        assert_eq!(lone.direct.stats(), DirectHostStats::default());
    }
}

/// The same through the real FSM: a host whose signed policy is `tor_only`
/// answers a viewer that sends `CANDIDATES` anyway with
/// `TOR_FALLBACK{OFF}` and nothing else; the viewer's frames are dropped
/// and counted, no call reaches the network, and the end line says `off`.
#[tokio::test(start_paused = true)]
async fn a_tor_only_host_answers_off_through_the_fsm_and_binds_nothing() {
    let [viewer, _, host] = keys_by_order();
    let mut fx = fixture(&Opts::new(TransportPolicy::TorOnly, viewer, host)).await;
    fx.send_candidates(&[silent_candidate()]).await;
    assert_eq!(
        fx.event(WAIT).await,
        Some(SessionEvent::TorFallback(Some(fallback::OFF)))
    );
    fx.quiet(Duration::from_secs(5)).await;
    assert_eq!(fx.host.stats.path_frames_dropped.load(Ordering::Relaxed), 2);
    assert_eq!(fx.host.env.calls(), EnvCalls::default());
    fx.session.bye(bye::USER).await.unwrap();
    let (transport, path) = fx.host.ends.line().await;
    assert_eq!(transport, None);
    assert_eq!(path.expect("a summary").outcome, "off");
    fx.fsm.await.unwrap().unwrap();
}

/// A viewer without `dir1` takes no part (the direct design §5.2): no
/// port, no call, its `TOR_FALLBACK{}` dropped, and its end line says
/// `old-viewer`. Under `lan_only` such a session can never have its LAN
/// path: it ends `BYE{NO_LAN_PATH}` at once.
#[tokio::test(start_paused = true)]
async fn an_old_viewer_takes_no_part() {
    let [viewer, _, host] = keys_by_order();
    let mut opts = Opts::new(TransportPolicy::Any, viewer, host);
    opts.dir1 = false;
    let mut fx = fixture(&opts).await;
    fx.session.send_tor_fallback(None).await.unwrap();
    tokio::time::sleep(HOST_DIRECT_LINGER).await;
    assert_eq!(fx.host.env.calls(), EnvCalls::default());
    fx.session.bye(bye::USER).await.unwrap();
    let (_, path) = fx.host.ends.line().await;
    assert_eq!(path.expect("a summary").outcome, "old-viewer");
    fx.fsm.await.unwrap().unwrap();

    opts.policy = TransportPolicy::LanOnly;
    let mut fx = fixture(&opts).await;
    let t0 = tokio::time::Instant::now();
    assert_eq!(
        fx.event(WAIT).await,
        Some(SessionEvent::Bye {
            reason: bye::NO_LAN_PATH,
            detail: None
        })
    );
    assert!(t0.elapsed() < Duration::from_millis(100));
    assert_eq!(fx.host.env.calls(), EnvCalls::default());
    fx.fsm.await.unwrap().unwrap();
}

/// The viewer goes first (the direct design §4 "Who does what"): nothing is
/// bound while it is silent, nor after a `TOR_FALLBACK` that comes first,
/// whatever follows it; the end line carries the viewer's reason. Through
/// the FSM (which drops what follows a fallback), and at the inbox itself.
#[tokio::test(start_paused = true)]
async fn nothing_binds_before_the_viewers_candidates_or_after_its_fallback() {
    let [viewer, _, host] = keys_by_order();
    let mut fx = fixture(&Opts::new(TransportPolicy::Any, viewer, host)).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(fx.host.env.calls(), EnvCalls::default());
    fx.session
        .send_tor_fallback(Some(fallback::NO_PATH))
        .await
        .unwrap();
    fx.send_candidates(&[silent_candidate()]).await;
    tokio::time::sleep(HOST_DIRECT_LINGER).await;
    assert_eq!(fx.host.env.calls(), EnvCalls::default());
    fx.session.bye(bye::USER).await.unwrap();
    let (_, path) = fx.host.ends.line().await;
    let path = path.expect("a summary");
    assert_eq!(path.outcome, "no-path");
    assert!((5000..5100).contains(&path.ms), "{}", path.ms);
    fx.fsm.await.unwrap().unwrap();

    let lone = lone();
    let (id, port) = lone.open(DeviceId::from_bytes([7; 32]), TransportPolicy::Any, true);
    let inbox = port.inbox.clone().expect("an inbox");
    inbox
        .try_send(PathFrame::TorFallback(Some(fallback::NO_PATH)))
        .unwrap();
    let frame = to_wire(&[silent_candidate()], Scope::SameSite).remove(0);
    inbox.try_send(PathFrame::Candidates(frame)).unwrap();
    inbox.try_send(PathFrame::Done).unwrap();
    until("the frames ignored", || {
        lone.direct.stats().frames_ignored == 2
    })
    .await;
    assert_eq!(lone.env.calls(), EnvCalls::default());
    drop((inbox, port));
    assert_eq!(
        lone.direct.outcome(&id).path.expect("a summary").outcome,
        "no-path"
    );
}

/// The viewer's `TOR_FALLBACK` and its `BYE` in the same breath: the host's
/// FSM reads both before the direct host's task runs, yet the end line
/// carries the viewer's reason, because the FSM tells the direct host of the
/// frame as it admits it (`PathExchange::heard`). The link closes all the
/// same.
#[tokio::test(start_paused = true)]
async fn a_bye_right_behind_the_fallback_keeps_the_viewers_reason() {
    let [viewer, _, host] = keys_by_order();
    for reason in [Some(fallback::QUIC), None] {
        let mut fx = fixture(&Opts::new(TransportPolicy::Any, viewer, host)).await;
        fx.send_candidates(&[silent_candidate()]).await;
        assert!(matches!(
            fx.event(WAIT).await,
            Some(SessionEvent::Candidates(_))
        ));
        assert_eq!(fx.event(WAIT).await, Some(SessionEvent::CandidatesDone));
        assert_eq!(fx.host.links_open(), 1);
        tokio::time::sleep(Duration::from_millis(700)).await;
        fx.session.send_tor_fallback(reason).await.unwrap();
        fx.session.bye(bye::USER).await.unwrap();
        let (transport, path) = fx.host.ends.line().await;
        assert_eq!(transport, None);
        let path = path.expect("a summary");
        assert_eq!(
            path.outcome,
            reason.map_or("unknown", fallback::name),
            "{reason:?}"
        );
        assert!((700..800).contains(&path.ms), "{}", path.ms);
        fx.fsm.await.unwrap().unwrap();
        until("the link closed", || fx.host.links_open() == 0).await;
    }
}

/// The linger (the direct design §4): a link with no direct claim closes
/// 20 s after its bind, and the session goes on; the end line says
/// `no-path`. Under `lan_only` the session then ends `BYE{NO_LAN_PATH}`.
#[tokio::test(start_paused = true)]
async fn the_linger_closes_an_unclaimed_link_and_ends_a_lan_only_session() {
    let [viewer, _, host] = keys_by_order();
    for policy in [TransportPolicy::Any, TransportPolicy::LanOnly] {
        let mut fx = fixture(&Opts::new(policy, viewer, host)).await;
        fx.send_candidates(&[silent_candidate()]).await;
        assert!(matches!(
            fx.event(WAIT).await,
            Some(SessionEvent::Candidates(_))
        ));
        let bound = tokio::time::Instant::now();
        assert_eq!(fx.event(WAIT).await, Some(SessionEvent::CandidatesDone));
        assert_eq!(fx.host.links_open(), 1);
        assert_eq!(fx.host.env.calls().binds, 1);
        tokio::time::sleep_until(bound + HOST_DIRECT_LINGER - Duration::from_millis(100)).await;
        assert_eq!(fx.host.links_open(), 1, "{policy:?}: still listening");
        if policy == TransportPolicy::LanOnly {
            assert_eq!(
                fx.event(WAIT).await,
                Some(SessionEvent::Bye {
                    reason: bye::NO_LAN_PATH,
                    detail: None
                })
            );
            let at = bound.elapsed();
            assert!(
                at >= HOST_DIRECT_LINGER - Duration::from_millis(100),
                "{at:?}"
            );
            assert!(
                at < HOST_DIRECT_LINGER + Duration::from_millis(100),
                "{at:?}"
            );
        } else {
            fx.quiet(Duration::from_secs(1)).await;
            assert_eq!(
                fx.host.links_open(),
                0,
                "closed at the linger while the session goes on"
            );
            fx.session.bye(bye::USER).await.unwrap();
        }
        assert_eq!(fx.host.links_open(), 0);
        let (_, path) = fx.host.ends.line().await;
        assert_eq!(path.expect("a summary").outcome, "no-path");
        assert_eq!(fx.host.env.calls().binds, 1);
        fx.fsm.await.unwrap().unwrap();
    }
}

/// Under `lan_only` there is no Tor fallback (decision M1-85): a viewer's
/// `TOR_FALLBACK` closes the link and ends the session `BYE{NO_LAN_PATH}`
/// at once.
#[tokio::test(start_paused = true)]
async fn a_lan_only_fallback_ends_the_session_at_once() {
    let [viewer, _, host] = keys_by_order();
    let mut fx = fixture(&Opts::new(TransportPolicy::LanOnly, viewer, host)).await;
    fx.send_candidates(&[silent_candidate()]).await;
    assert!(matches!(
        fx.event(WAIT).await,
        Some(SessionEvent::Candidates(_))
    ));
    assert_eq!(fx.event(WAIT).await, Some(SessionEvent::CandidatesDone));
    fx.session
        .send_tor_fallback(Some(fallback::NO_PATH))
        .await
        .unwrap();
    let t0 = tokio::time::Instant::now();
    assert_eq!(
        fx.event(WAIT).await,
        Some(SessionEvent::Bye {
            reason: bye::NO_LAN_PATH,
            detail: None
        })
    );
    assert!(t0.elapsed() < Duration::from_millis(100));
    assert_eq!(fx.host.links_open(), 0);
    let (_, path) = fx.host.ends.line().await;
    assert_eq!(path.expect("a summary").outcome, "no-path");
    fx.fsm.await.unwrap().unwrap();
}

/// A host that cannot take part says why (the direct design §4): no
/// address in scope → `TOR_FALLBACK{NO_ADDRESSES}` with nothing bound; a
/// bind that fails → `TOR_FALLBACK{SOCKET}`; under `lan_only` either ends
/// the session `BYE{NO_LAN_PATH}`. Further `CANDIDATES` start nothing (one
/// try per session). The end line names the host's reason.
#[tokio::test(start_paused = true)]
async fn a_host_that_cannot_take_part_says_why() {
    let [viewer, _, host] = keys_by_order();
    let no_address: fn(Segment) -> MachineSpec = |_| MachineSpec::default();
    let no_socket: fn(Segment) -> MachineSpec = |lan| MachineSpec {
        fail_bind: true,
        ..MachineSpec::on(lan, "192.168.1.20/24")
    };
    for (machine, code, binds) in [
        (no_address, fallback::NO_ADDRESSES, 0),
        (no_socket, fallback::SOCKET, 1),
    ] {
        for policy in [TransportPolicy::Any, TransportPolicy::LanOnly] {
            let mut opts = Opts::new(policy, viewer, host);
            opts.host_machine = machine;
            let mut fx = fixture(&opts).await;
            fx.send_candidates(&[silent_candidate()]).await;
            let want = if policy == TransportPolicy::LanOnly {
                SessionEvent::Bye {
                    reason: bye::NO_LAN_PATH,
                    detail: None,
                }
            } else {
                SessionEvent::TorFallback(Some(code))
            };
            assert_eq!(fx.event(WAIT).await, Some(want));
            if policy == TransportPolicy::Any {
                // One link per session: a viewer that sends more binds
                // nothing more.
                fx.send_candidates(&[silent_candidate()]).await;
                until("the frames ignored", || {
                    fx.host.direct.stats().frames_ignored == 2
                })
                .await;
            }
            let calls = fx.host.env.calls();
            assert_eq!(calls.binds, binds, "{policy:?}");
            assert_eq!(calls.interfaces, 1);
            assert_eq!(fx.host.direct.stats().start_failed, 1);
            assert_eq!(fx.host.links_open(), 0);
            if policy == TransportPolicy::Any {
                fx.session.bye(bye::USER).await.unwrap();
            }
            let (_, path) = fx.host.ends.line().await;
            assert_eq!(path.expect("a summary").outcome, fallback::name(code));
            fx.fsm.await.unwrap().unwrap();
        }
    }
}

/// One link per session, and the onion path's claim closes it at once
/// (the direct design §8.5 steps 5 and 9): two `CANDIDATES` bind once; the
/// viewer's onion `Bind` claims the media, the link closes without any
/// `TOR_FALLBACK`, and later `CANDIDATES` bind nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_onion_claim_closes_the_link_and_nothing_binds_again() {
    let [viewer, _, host] = keys_by_order();
    let mut fx = fixture(&Opts::new(TransportPolicy::Any, viewer, host)).await;
    let frame = to_wire(&[silent_candidate()], Scope::SameSite).remove(0);
    fx.session.send_candidates(&frame).await.unwrap();
    fx.session.send_candidates(&frame).await.unwrap();
    assert!(matches!(
        fx.event(WAIT).await,
        Some(SessionEvent::Candidates(_))
    ));
    assert_eq!(fx.event(WAIT).await, Some(SessionEvent::CandidatesDone));
    assert_eq!(fx.host.links_open(), 1);
    assert_eq!(fx.host.env.calls().binds, 1);

    let binding = Binding::new(fx.session.session_token(), &fx.session.th());
    let (onion, served) = connect(&fx.host.rig.host);
    let onion = MediaViewer::bind(onion, &binding, WAIT).await.unwrap();
    assert_eq!(
        fx.host.rig.host.route(&fx.session_id),
        Some(TransportKind::TorRelay)
    );
    until("the link closed", || fx.host.links_open() == 0).await;

    fx.session.send_candidates(&frame).await.unwrap();
    until("the frame ignored", || {
        fx.host.direct.stats().frames_ignored == 1
    })
    .await;
    assert_eq!(fx.host.env.calls().binds, 1);
    assert_eq!(fx.host.direct.stats().links_started, 1);
    drop(onion);
    let _ = served.await;
    fx.session.bye(bye::USER).await.unwrap();
    let (transport, _) = fx.host.ends.line().await;
    assert_eq!(transport, Some(TransportKind::TorRelay));
    fx.fsm.await.unwrap().unwrap();
}

/// A kill closes the link at once (the direct design §8.5 step 8, §9.1
/// invariant 10), here with the host dialling: the connection is up and
/// waiting for its stream; the panic key leaves no link open within a
/// millisecond, the viewer's connection closes, and the session ends
/// `BYE{PANIC}`.
#[tokio::test(start_paused = true)]
async fn a_kill_closes_the_link_at_once() {
    let [host, _, viewer] = keys_by_order();
    let mut fx = fixture(&Opts::new(TransportPolicy::Any, viewer, host)).await;
    let machine = fx.viewer_machine();
    let (mut link, offered) = fx.viewer_link(key(viewer), &machine).await;
    let (conn, _) = tokio::time::timeout(WAIT, exchange(&mut fx.session, &mut link, &offered))
        .await
        .expect("connected in time");
    assert_eq!(fx.host.links_open(), 1);
    let t0 = tokio::time::Instant::now();
    fx.host.kill.kill(bye::PANIC);
    until("the link closed", || fx.host.links_open() == 0).await;
    assert!(
        t0.elapsed() <= Duration::from_millis(5),
        "{:?}",
        t0.elapsed()
    );
    tokio::time::timeout(WAIT, conn.closed())
        .await
        .expect("the viewer's connection closed");
    assert_eq!(
        fx.event(WAIT).await,
        Some(SessionEvent::Bye {
            reason: bye::PANIC,
            detail: None
        })
    );
    assert!(fx.host.media_seen().is_empty());
    fx.fsm.await.unwrap().unwrap();
}

/// A kill while direct media is live (the direct design §9.1 invariants 2
/// and 10): the media's own teardown runs, as on the onion path. Capture
/// stops well within the kill's bounded goodbye ([`DIRECT_DRAIN`]), the
/// observer hears `capture_stopped`, the outcome is handed on with
/// `ENDED_BY_HOST`, the viewer reads `Close{ENDED_BY_HOST}`, the link
/// closes and the session ends `BYE{PANIC}`. The same with the media host's
/// kill watch running and without it: the direct host ends the session's
/// media itself, whichever task hears the kill first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kill_ends_live_direct_media_through_its_teardown() {
    for watched in [true, false] {
        let [viewer, _, host] = keys_by_order();
        let mut fx = fixture(&Opts::new(TransportPolicy::Any, viewer, host)).await;
        let watcher = watched.then(|| fx.host.rig.host.watch_kill(fx.host.kill.clone()));
        let machine = fx.viewer_machine();
        let (mut link, offered) = fx.viewer_link(key(viewer), &machine).await;
        let (conn, _) = tokio::time::timeout(WAIT, exchange(&mut fx.session, &mut link, &offered))
            .await
            .expect("connected in time");
        let ekm = conn
            .binding_secret(fx.session.session_token().bytes())
            .unwrap();
        let stream = conn.open_stream(1).await.unwrap();
        let viewer_media = MediaViewer::bind(stream, &fx.binding(&ekm), WAIT)
            .await
            .unwrap();
        assert_eq!(
            fx.host.rig.host.route(&fx.session_id),
            Some(TransportKind::Lan)
        );

        let (mut pictures, enough) = Pictures::wanting(3);
        let kill = fx.host.kill.clone();
        let backend = Arc::clone(&fx.host.rig.backend);
        let killer = tokio::spawn(async move {
            let _ = enough.await;
            let live = !backend.closed.load(Ordering::SeqCst);
            kill.kill(bye::PANIC);
            (live, tokio::time::Instant::now())
        });
        let mut stats = ViewerStats::default();
        let end = viewer_media
            .run(&mut pictures, &mut stats, pending())
            .await
            .unwrap();
        let (live, t0) = killer.await.unwrap();
        assert!(live, "watched {watched}: capture was live at the kill");
        assert_eq!(
            end,
            ViewerEnd::Host(reason::ENDED_BY_HOST),
            "watched {watched}"
        );
        assert!(fx.host.rig.backend.closed.load(Ordering::SeqCst));
        assert!(
            t0.elapsed() < DIRECT_DRAIN,
            "watched {watched}: {:?}",
            t0.elapsed()
        );
        let stopped = format!("stopped {:?}", MediaEnd::SessionOver(reason::ENDED_BY_HOST));
        assert_eq!(
            fx.host
                .rig
                .seen
                .lines()
                .iter()
                .filter(|line| line.starts_with("stopped"))
                .collect::<Vec<_>>(),
            [&stopped],
            "watched {watched}"
        );
        until("the media outcome", || !fx.host.media_seen().is_empty()).await;
        assert!(
            matches!(
                fx.host.media_seen()[..],
                [MediaOutcome::Served {
                    end: MediaEnd::SessionOver(r),
                    ..
                }] if r == reason::ENDED_BY_HOST
            ),
            "watched {watched}: {:?}",
            fx.host.media_seen()
        );
        // The viewer read the `Close` and lets go: the link closes at once.
        drop((conn, link));
        until("the link closed", || fx.host.links_open() == 0).await;
        assert_eq!(
            fx.event(WAIT).await,
            Some(SessionEvent::Bye {
                reason: bye::PANIC,
                detail: None
            }),
            "watched {watched}"
        );
        let (transport, path) = fx.host.ends.line().await;
        assert_eq!(transport, Some(TransportKind::Lan));
        assert_eq!(path.expect("a path summary").outcome, "direct");
        fx.fsm.await.unwrap().unwrap();
        if let Some(watcher) = watcher {
            watcher.abort();
        }
    }
}

/// A refused direct `Bind` closes the link (the direct design §4, §6.5):
/// the viewer reads `BindRefused{BAD_BIND}`, nothing opens, the outcome is
/// handed on, no link stays open, and the end line says `bind-refused`.
#[tokio::test(start_paused = true)]
async fn a_refused_direct_bind_closes_the_link() {
    let [viewer, _, host] = keys_by_order();
    let mut fx = fixture(&Opts::new(TransportPolicy::Any, viewer, host)).await;
    let machine = fx.viewer_machine();
    let (mut link, offered) = fx.viewer_link(key(viewer), &machine).await;
    let (conn, _) = tokio::time::timeout(WAIT, exchange(&mut fx.session, &mut link, &offered))
        .await
        .expect("connected in time");
    let stream = conn.open_stream(1).await.unwrap();
    let failed = MediaViewer::bind(stream, &fx.binding(&[0x5a; 32]), WAIT)
        .await
        .unwrap_err();
    assert!(
        matches!(failed, ViewerError::Refused(r) if r == reason::BAD_BIND),
        "{failed:?}"
    );
    until("the link closed", || fx.host.links_open() == 0).await;
    assert_eq!(fx.host.media_seen(), [MediaOutcome::NotBound]);
    assert_eq!(fx.host.rig.backend.sources.load(Ordering::SeqCst), 0);
    assert_eq!(fx.host.rig.host.route(&fx.session_id), None);
    fx.session.bye(bye::USER).await.unwrap();
    let (transport, path) = fx.host.ends.line().await;
    assert_eq!(transport, None);
    assert_eq!(path.expect("a summary").outcome, "bind-refused");
    fx.fsm.await.unwrap().unwrap();
    drop((conn, link));
}

/// The kill during the refusal's flush (the step A9 row's caller test,
/// design §9.1 invariant 10): the viewer receives nothing more, so the
/// host's refusal would wait its whole 500 ms flush; a kill 100 ms into it
/// drops the refusal and closes the link at once, and the dropped media
/// stream reports nothing.
#[tokio::test(start_paused = true)]
async fn a_kill_during_the_refusal_flush_closes_at_once() {
    let [viewer, _, host] = keys_by_order();
    let mut fx = fixture(&Opts::new(TransportPolicy::Any, viewer, host)).await;
    let machine = fx.viewer_machine();
    let (mut link, offered) = fx.viewer_link(key(viewer), &machine).await;
    let (conn, _) = tokio::time::timeout(WAIT, exchange(&mut fx.session, &mut link, &offered))
        .await
        .expect("connected in time");
    let stream = conn.open_stream(1).await.unwrap();
    machine.set_inbound(InboundRule::Blocked);
    let binding = fx.binding(&[0x5a; 32]);
    let bind = tokio::spawn(async move { MediaViewer::bind(stream, &binding, WAIT).await.err() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fx.host.links_open(), 1, "the refusal is still flushing");
    let t0 = tokio::time::Instant::now();
    fx.host.kill.kill(bye::PANIC);
    until("the link closed", || fx.host.links_open() == 0).await;
    assert!(
        t0.elapsed() <= Duration::from_millis(5),
        "{:?}",
        t0.elapsed()
    );
    assert!(fx.host.media_seen().is_empty());
    assert_eq!(fx.host.rig.backend.sources.load(Ordering::SeqCst), 0);
    bind.abort();
    fx.fsm.await.unwrap().unwrap();
    drop((conn, link));
}

/// A pin the host refuses (the direct design §6.5 "Pin refused by the
/// host's TLS"): the viewer's link presents another device's key than the
/// session's. Its handshake completes and is then closed with a TLS alert
/// before any host byte; the viewer falls back (`TOR_FALLBACK{QUIC}`), the
/// host closes its link, and the end line says `pin-refused`.
#[tokio::test(start_paused = true)]
async fn a_pin_the_host_refuses_is_recorded() {
    let [viewer, other, host] = keys_by_order();
    let mut fx = fixture(&Opts::new(TransportPolicy::Any, viewer, host)).await;
    let machine = fx.viewer_machine();
    let (mut link, offered) = fx.viewer_link(key(other), &machine).await;
    let (conn, _) = tokio::time::timeout(WAIT, exchange(&mut fx.session, &mut link, &offered))
        .await
        .expect("the viewer's handshake completes first");
    tokio::time::timeout(WAIT, conn.closed()).await.unwrap();
    assert!(conn.closed_by_crypto());
    assert_eq!(after_bind_close(&conn), AfterBind::Fallback);
    fx.session
        .send_tor_fallback(Some(fallback::QUIC))
        .await
        .unwrap();
    until("the link closed", || fx.host.links_open() == 0).await;
    fx.session.bye(bye::USER).await.unwrap();
    let (transport, path) = fx.host.ends.line().await;
    assert_eq!(transport, None);
    assert_eq!(path.expect("a summary").outcome, "pin-refused");
    fx.fsm.await.unwrap().unwrap();
    drop((conn, link));
}

/// The orphan timer with a direct host (the direct design §12.3): a `dir1`
/// viewer that sends no path frame is ended `BYE{ORPHANED}` by the FSM's
/// timer, and its path made no call to the network.
#[tokio::test(start_paused = true)]
async fn the_orphan_timer_ends_a_silent_viewer_with_no_network_call() {
    let [viewer, _, host] = keys_by_order();
    let mut fx = fixture(&Opts::new(TransportPolicy::Any, viewer, host)).await;
    assert_eq!(
        fx.event(Duration::from_secs(60)).await,
        Some(SessionEvent::Bye {
            reason: bye::ORPHANED,
            detail: None
        })
    );
    assert_eq!(fx.host.env.calls(), EnvCalls::default());
    let (transport, path) = fx.host.ends.line().await;
    assert_eq!((transport, path), (None, None));
    fx.fsm.await.unwrap().unwrap();
}
