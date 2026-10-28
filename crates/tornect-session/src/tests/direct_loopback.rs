//! Step A22: whole direct sessions on real loopback sockets
//! ([`LoopbackNet`], real time): both FSMs over a pipe that stands for the
//! onion circuit, [`DirectHost`] on the host and
//! [`ViewerDirect::choose_path`] on the viewer, the media bound and
//! pictures decoded over the pinned QUIC connection (the direct design
//! §12.2 "Loopback e2e"). On top of it, the redaction e2e (§12.4 end) and
//! the `direct_loopback_stats` stand-in for the loopback demo (decision
//! M1-82).

use std::fmt::Write as _;
use std::future::pending;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::process::Command;

use tokio::time::Instant;
use tornect_core::session_log::TransportKind;
use tornect_core::telemetry::{IDENTIFIERS_ENV, LogOptions};
use tornect_net::mapping::fake::{FakeIgd, FakePcp, IgdConfig, IgdHeard, PcpHeard, PcpMode};
use tornect_net::mem::LoopbackNet;
use tornect_net::udp::BoundUdp;
use tornect_net::{
    BoxFuture, IfaceAddr, MAP_LEASE, MapEvent, MapEvents, MapProtocols, MapRequest, MapVia,
    MappingLedger, NetEnv, NetError, PortMapper, RealMapper, ReleaseTracker, Route, RouteSources,
};
use tornect_signal::HandshakeError;
use tornect_signal::consent::{TransportKnob, TransportPolicy};
use tornect_signal::fsm::client::ClientSession;
use tornect_signal::messages::feats;

use super::direct_host::{Ends, key, keys_by_order, until};
use super::*;

/// The app's bind wait for the media stream (`MEDIA_BIND_WAIT`).
const BIND_WAIT: Duration = Duration::from_secs(30);

/// A loopback machine that notes the address of every socket it binds, so
/// a test knows the ports a log must not name.
struct Noting {
    inner: LoopbackNet,
    bound: Mutex<Vec<SocketAddr>>,
}

impl Noting {
    fn new(x: u8) -> Arc<Self> {
        Arc::new(Self {
            inner: LoopbackNet::new(x),
            bound: Mutex::default(),
        })
    }

    fn bound(&self) -> Vec<SocketAddr> {
        self.bound.lock().unwrap().clone()
    }
}

impl NetEnv for Noting {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        self.inner.interfaces()
    }

    fn route_sources(&self) -> RouteSources {
        self.inner.route_sources()
    }

    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp> {
        let bound = self.inner.bind(port)?;
        self.bound.lock().unwrap().push(bound.inner.local_addr()?);
        Ok(bound)
    }

    fn resolve(&self, host: &str, port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        self.inner.resolve(host, port)
    }

    fn mapper(&self) -> Arc<dyn PortMapper> {
        self.inner.mapper()
    }

    fn admit_loopback(&self) -> bool {
        self.inner.admit_loopback()
    }
}

/// One accepted session through the real FSMs over a pipe, each side's
/// half of the path on its own loopback machine.
struct Lx {
    session: ClientSession<DuplexStream>,
    session_id: String,
    viewer: ViewerDirect,
    rig: Rig,
    ends: Arc<Ends>,
    fsm: JoinHandle<Result<(), HandshakeError>>,
    viewer_env: Arc<Noting>,
    host_env: Arc<Noting>,
    viewer_key: [u8; 32],
    host_key: [u8; 32],
    /// When the viewer read the `SESSION_ACCEPT` (the start of the path
    /// phase's clock, decision M1-82).
    accepted: Instant,
    _tmp: tempfile::TempDir,
}

/// The session between the viewer on `127.0.0.{viewer_x}` and the host on
/// `127.0.0.{host_x}`, accepted and about to choose its path.
async fn on_loopback(viewer_x: u8, host_x: u8) -> Lx {
    let [viewer_seed, _, host_seed] = keys_by_order();
    let tmp = tempfile::tempdir().unwrap();
    let onion = Arc::new(HostIdentity::from_seed(&[0x53; 32]));
    let trusted = Arc::new(TrustedDeviceStore::with(
        tmp.path().join("trusted-devices.toml"),
        tornect_core::trusted::TrustedDevices::default(),
    ));
    let consent = Arc::new(ScriptedConsent::new());
    consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let rig = rig_with(TestBackend::default(), MediaLimits::default());
    let mut deps = HostDeps::headless(onion.clone(), trusted);
    deps.consent = consent;
    deps.sessions = rig.host.clone();
    let ends = Arc::new(Ends::default());
    deps.audit = ends.clone();

    let viewer_env = Noting::new(viewer_x);
    let host_env = Noting::new(host_x);
    let host_identity = key(host_seed);
    let host_key = host_identity.verifying_key().to_bytes();
    deps.paths = Arc::new(DirectHost::new(
        rig.host.clone(),
        None,
        Arc::clone(&host_identity),
        DirectSettings::default(),
        host_env.clone(),
        deps.kill.clone(),
        Arc::new(|_: &MediaOutcome| {}),
    ));
    let mut cfg = HostConfig::new("Desk", host_key);
    cfg.transport = TransportKnob::fixed(TransportPolicy::Any);
    cfg.feats.push(feats::DIR1.to_owned());
    let (client_end, host_end) = duplex(64 * 1024);
    let fsm = tokio::spawn(async move { serve_host(host_end, &cfg, &deps).await.map(|_| ()) });

    let known = Arc::new(KnownHostStore::with(
        tmp.path().join("known-hosts.toml"),
        tornect_core::trusted::KnownHosts::default(),
    ));
    let mut client_deps = ClientDeps::headless(known);
    client_deps.ui = Arc::new(ScriptedClientUi::new(true));
    let device = DeviceIdentity::from_seed(&[viewer_seed; 32]);
    let mut ccfg = ClientConfig::new(onion.id(), "Laptop");
    ccfg.feats.push(feats::DIR1.to_owned());
    let ClientOutcome::Session(session) =
        client::connect(client_end, &ccfg, &device, &client_deps, Intent::Session)
            .await
            .unwrap()
    else {
        panic!("no session");
    };
    let accepted = Instant::now();
    let session = *session;
    let session_id = session.session_token().session_id();
    let viewer_identity = key(viewer_seed);
    let viewer_key = viewer_identity.verifying_key().to_bytes();
    let viewer = ViewerDirect::new(
        viewer_identity,
        DirectSettings::default(),
        viewer_env.clone(),
    );
    Lx {
        session,
        session_id,
        viewer,
        rig,
        ends,
        fsm,
        viewer_env,
        host_env,
        viewer_key,
        host_key,
        accepted,
        _tmp: tmp,
    }
}

/// What one whole loopback session measured.
#[derive(Debug)]
struct Measured {
    /// From the accept to the open media stream (`choose_path`).
    to_stream: Duration,
    /// From the accept to the verified `BindOk` (`DirectMedia::bind`).
    to_bind_ok: Duration,
    /// From the accept to the first decoded picture.
    to_first_picture: Duration,
    /// How long pictures were received after the first.
    receiving: Duration,
    stats: ViewerStats,
}

/// A sink that counts the pictures and notes when the first one came.
struct Counting {
    first: Option<Instant>,
    pictures: u64,
    want: u64,
    done: Option<oneshot::Sender<()>>,
}

impl FrameSink for Counting {
    fn picture(&mut self, _seq: u32, _frame: &DecodedFrame) {
        self.first.get_or_insert_with(Instant::now);
        self.pictures += 1;
        if self.pictures >= self.want
            && let Some(done) = self.done.take()
        {
            let _ = done.send(());
        }
    }
}

impl Lx {
    /// The path phase, the direct bind, pictures until `want` decoded and
    /// at least `at_least` passed since the first, then the viewer's
    /// `BYE{USER}`; checks the route on both sides and the host's end line
    /// (the direct design §12.2 "Loopback e2e").
    async fn run(mut self, want: u64, at_least: Duration) -> (Measured, Ended) {
        let choice = self
            .viewer
            .choose_path(
                &mut self.session,
                Mine::of(TransportPolicy::Any),
                true,
                pending(),
            )
            .await;
        let PathChoice::Direct(media) = choice else {
            panic!("not direct: {choice:?}");
        };
        let to_stream = self.accepted.elapsed();
        assert_eq!(
            media.route,
            Route {
                same_site: true,
                ipv6: false
            }
        );
        assert_eq!(media.winner, tornect_net::CandidateKind::Host);
        assert!(media.binding.is_direct());
        let viewer_media = media
            .bind(BIND_WAIT)
            .await
            .expect("BindProof verified, BindOk read");
        let to_bind_ok = self.accepted.elapsed();
        assert_eq!(
            self.rig.host.route(&self.session_id),
            Some(TransportKind::Lan)
        );

        let (done, enough) = oneshot::channel();
        let mut sink = Counting {
            first: None,
            pictures: 0,
            want,
            done: Some(done),
        };
        let mut stats = ViewerStats::default();
        let stop = async {
            let _ = enough.await;
        };
        let stop = async move {
            stop.await;
            tokio::time::sleep(at_least).await;
        };
        let end = tokio::time::timeout(
            at_least + WAIT,
            viewer_media.run(&mut sink, &mut stats, stop),
        )
        .await
        .expect("pictures in time")
        .expect("the media ran");
        assert_eq!(end, ViewerEnd::Stopped);
        let first = sink.first.expect("a picture");
        let measured = Measured {
            to_stream,
            to_bind_ok,
            to_first_picture: first - self.accepted,
            receiving: first.elapsed(),
            stats,
        };
        self.session.bye(bye::USER).await.unwrap();
        let (transport, path) = self.ends.line().await;
        assert_eq!(transport, Some(TransportKind::Lan));
        let path = path.expect("a path summary");
        assert_eq!(path.outcome, "direct");
        assert_eq!(path.winner.as_deref(), Some("host"));
        self.fsm.await.unwrap().unwrap();
        let ended = Ended {
            viewer_bound: self.viewer_env.bound(),
            host_bound: self.host_env.bound(),
            viewer_key: self.viewer_key,
            host_key: self.host_key,
        };
        assert_eq!(ended.viewer_bound.len(), 1, "{ended:?}");
        assert_eq!(ended.host_bound.len(), 1, "{ended:?}");
        until("the host's capture stopped", || {
            self.rig.backend.closed.load(Ordering::SeqCst)
        })
        .await;
        (measured, ended)
    }
}

/// What a finished session leaves for the redaction check: the sockets
/// both machines bound and both device keys.
#[derive(Debug)]
struct Ended {
    viewer_bound: Vec<SocketAddr>,
    host_bound: Vec<SocketAddr>,
    viewer_key: [u8; 32],
    host_key: [u8; 32],
}

/// The direct design §12.2 "Loopback e2e": a whole session on loopback
/// sockets goes direct, proves the host (`BindProof`), reads `BindOk`,
/// decodes pictures, and both the media host's route and the end line say
/// `lan`, with a `direct` path summary.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_whole_session_goes_direct_on_loopback_sockets() {
    let (measured, ended) = on_loopback(30, 31).await.run(3, Duration::ZERO).await;
    assert!(measured.stats.decoded >= 3, "{measured:?}");
    assert_eq!(measured.stats.decode_errors, 0, "{measured:?}");
    assert!(measured.to_stream < Duration::from_secs(4), "{measured:?}");
    assert_eq!(ended.host_bound[0].ip().to_string(), "127.0.0.31");
    assert_eq!(ended.viewer_bound[0].ip().to_string(), "127.0.0.30");
}

/// Decision M1-82's stand-in for `tornect demo --loopback
/// --headless-stats` on the direct path: time to the open stream, to
/// `BindOk` and to the first picture, then 10 s of the test card's
/// pictures: their rate and bytes, to read against `docs/PLAN.md` §B.7.
/// `cargo test -p tornect-session --release --lib
/// tests::direct_loopback::direct_loopback_stats -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "10 s of real time: the checkpoint's measurement (step A22)"]
#[allow(clippy::print_stderr)] // the numbers are the evidence
async fn direct_loopback_stats() {
    let (m, _) = on_loopback(40, 41)
        .await
        .run(1, Duration::from_secs(10))
        .await;
    let secs = m.receiving.as_secs_f64();
    let decoded = m.stats.decoded;
    eprintln!(
        "direct_loopback_stats: stream {} ms, BindOk {} ms, first picture {} ms after the \
         accept; {decoded} pictures in {secs:.1} s ({:.1} fps), {} access units, {} \
         keyframes, {} bytes ({:.0} kbit/s), {} decode errors, decode {:.2} ms/picture",
        m.to_stream.as_millis(),
        m.to_bind_ok.as_millis(),
        m.to_first_picture.as_millis(),
        decoded as f64 / secs,
        m.stats.access_units,
        m.stats.keyframes,
        m.stats.bytes,
        m.stats.bytes as f64 * 8.0 / 1000.0 / secs,
        m.stats.decode_errors,
        m.stats.decode_us as f64 / 1000.0 / decoded.max(1) as f64,
    );
    assert!(decoded > 0);
    assert_eq!(m.stats.decode_errors, 0);
}

/// The child's directory for its log files and its record of what the log
/// must not name; set only by the redaction e2e.
const CHILD_DIR: &str = "TORNECT_REDACTION_E2E_DIR";
/// `1`: the child logs JSON lines on stderr.
const CHILD_JSON: &str = "TORNECT_REDACTION_E2E_JSON";

/// The destination of the forced `sendmsg` failure: an IPv6 address on an
/// IPv4 socket, which the OS refuses with no packet sent.
const FORCED: &str = "[2001:db8::77]:50417";

/// quinn-udp's own send, as quinn's default socket calls it, made to fail:
/// it writes the failed send's destination at `WARN` under its target
/// `quinn_udp` (`quinn-udp-0.5.16` `log_sendmsg_error`). Tornect's sockets
/// never call it (`QuietUdp` uses `try_send`); the log layers must drop it
/// all the same.
fn force_a_sendmsg_warning() {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let state = quinn::udp::UdpSocketState::new((&sock).into()).unwrap();
    let transmit = quinn::udp::Transmit {
        destination: FORCED.parse().unwrap(),
        ecn: None,
        contents: &[0; 64],
        segment_size: None,
        src_ip: None,
    };
    // Swallowed after the warning, as quinn-udp swallows every error but
    // `WouldBlock` and `EMSGSIZE`.
    state.send((&sock).into(), &transmit).unwrap();
}

/// Where the redaction e2e's mapper reports: one line of ours per event,
/// with the session log's fixed words.
struct LoggedEvents;

impl MapEvents for LoggedEvents {
    fn on_event(&self, ev: MapEvent) {
        let detail = ev.router_port().detail();
        tracing::info!(target: "tornect_session::e2e", "e2e: router port {detail}");
    }
}

/// The fake UPnP-IGD router's address in the redaction e2e: igd-next
/// names it in its own `DEBUG` lines.
const IGD_GATEWAY: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 172);

/// The routers of the redaction e2e (step B9): [`FakePcp`] and [`FakeIgd`]
/// on loopback addresses of their own, and the real mapper pointed at
/// them. PCP (crab_nat) and then UPnP-IGD (igd-next: the SSDP search, the
/// description, the control requests) each grant a mapping that is renewed
/// once and released. Returns what the log must not name: both routers'
/// addresses, the SSDP port, the external addresses and ports, and the
/// internal port.
async fn map_through_fake_routers(dir: &Path) -> Vec<(&'static str, String)> {
    const INTERNAL: u16 = 50_123;
    let pcp_gateway = Ipv4Addr::new(127, 0, 0, 171);
    let igd_gateway = IGD_GATEWAY;
    let pcp_external = Ipv4Addr::new(81, 2, 3, 4);
    let igd_external = Ipv4Addr::new(82, 5, 6, 7);
    let pcp = FakePcp::start(
        pcp_gateway,
        PcpMode::Pcp {
            external: pcp_external,
            max_lifetime: 3600,
        },
    )
    .await
    .expect("a fake PCP router");
    let igd = FakeIgd::start(igd_gateway, IgdConfig::granting(igd_external))
        .await
        .expect("a fake UPnP-IGD router");
    let mapper = RealMapper::new(
        MappingLedger::new(dir.join("router-ports")),
        Arc::new(LoggedEvents),
        ReleaseTracker::new(),
    )
    .on_loopback(igd.ssdp_port(), igd.ssdp(), vec![IpAddr::V4(igd_gateway)]);
    let ask = |gateway: Ipv4Addr, protocols: MapProtocols| MapRequest {
        gateway,
        client: Ipv4Addr::LOCALHOST,
        internal_port: NonZeroU16::new(INTERNAL).expect("a port"),
        lease: MAP_LEASE,
        protocols,
        deadline: (Instant::now() + Duration::from_secs(3)).into_std(),
    };
    let mut secrets = vec![
        ("ip", pcp_gateway.to_string()),
        ("ip", igd_gateway.to_string()),
        ("ip", pcp_external.to_string()),
        ("ip", igd_external.to_string()),
        ("port", INTERNAL.to_string()),
        ("port", igd.ssdp_port().to_string()),
    ];
    for (gateway, protocols, via) in [
        (
            pcp_gateway,
            MapProtocols {
                upnp: false,
                ..MapProtocols::ALL
            },
            MapVia::Pcp,
        ),
        (
            igd_gateway,
            MapProtocols {
                upnp: true,
                ..MapProtocols::NONE
            },
            MapVia::Upnp,
        ),
    ] {
        let mut mapping = mapper
            .map(ask(gateway, protocols))
            .await
            .expect("a mapping");
        assert_eq!(mapping.via, via);
        secrets.push(("port", mapping.external.port().to_string()));
        mapping.renew().await.expect("a renewal");
        mapping.release().await;
    }
    let pcp_lifetimes: Vec<u32> = pcp
        .heard()
        .iter()
        .filter_map(|h| match h {
            PcpHeard::Map { lifetime, .. } => Some(*lifetime),
            _ => None,
        })
        .collect();
    assert_eq!(pcp_lifetimes, [600, 600, 0], "map, renew, delete");
    let igd_heard = igd.heard();
    assert!(
        igd_heard
            .iter()
            .any(|h| matches!(h, IgdHeard::AddPort { .. })),
        "{igd_heard:?}"
    );
    assert!(
        igd_heard
            .iter()
            .any(|h| matches!(h, IgdHeard::DeletePort { .. })),
        "{igd_heard:?}"
    );
    assert!(mapper.ledger().entries().is_empty());
    secrets
}

/// The redaction e2e's child: in a process of its own, the real log
/// layers at `trace` with identifiers as the parent set them, a forced
/// quinn-udp warning, a whole direct session on loopback sockets (the
/// QUIC handshake, so rustls and quinn log), then the real mapper against
/// a fake PCP router and a fake UPnP-IGD one. It writes what the log must
/// not name to `secrets` in its directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "the redaction e2e runs it in a process of its own"]
async fn redaction_child() {
    let Some(dir) = std::env::var_os(CHILD_DIR).map(PathBuf::from) else {
        return;
    };
    let guard = tornect_core::telemetry::init(LogOptions {
        filter: Some("trace".to_owned()),
        file_dir: Some(dir.join("logs")),
        json: std::env::var(CHILD_JSON).as_deref() == Ok("1"),
        identifiers: false,
    })
    .unwrap();
    tracing::trace!(target: "tornect_session::e2e", "e2e: a trace line of ours");
    force_a_sendmsg_warning();
    let (_, ended) = on_loopback(20, 21).await.run(3, Duration::ZERO).await;
    tracing::info!(target: "tornect_session::e2e", "e2e: the direct session is over");
    let mapped = map_through_fake_routers(&dir).await;
    tracing::info!(target: "tornect_session::e2e", "e2e: the routers' ports are closed");
    let mut secrets = String::new();
    for (kind, value) in mapped {
        writeln!(secrets, "{kind} {value}").unwrap();
    }
    for addr in ended.viewer_bound.iter().chain(&ended.host_bound) {
        writeln!(secrets, "ip {}", addr.ip()).unwrap();
        writeln!(secrets, "port {}", addr.port()).unwrap();
    }
    writeln!(secrets, "ip 2001:db8::77").unwrap();
    writeln!(secrets, "port 50417").unwrap();
    for key in [ended.viewer_key, ended.host_key] {
        for form in key_forms(&key) {
            writeln!(secrets, "key {form}").unwrap();
        }
    }
    std::fs::write(dir.join("secrets"), secrets).unwrap();
    drop(guard);
}

/// The forms a device key takes in a line: hex (both cases, whole and its
/// first 8 bytes, a fingerprint's length), base32 (both cases, whole and
/// its first 16 characters) and the decimal byte list `Debug` writes (its
/// first 8 bytes, with and without spaces).
fn key_forms(key: &[u8; 32]) -> Vec<String> {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let base32 = base32(key);
    let bytes: Vec<String> = key[..8].iter().map(u8::to_string).collect();
    vec![
        hex.clone(),
        hex.to_uppercase(),
        hex[..16].to_owned(),
        hex[..16].to_uppercase(),
        base32.clone(),
        base32.to_uppercase(),
        base32[..16].to_owned(),
        base32[..16].to_uppercase(),
        bytes.join(", "),
        bytes.join(","),
    ]
}

/// RFC 4648 base32, lowercase, without padding.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Whether `text` holds the number `token` with no digit on either side.
fn has_number(text: &str, token: &str) -> bool {
    text.match_indices(token).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + token.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_digit()) && !after.is_some_and(|c| c.is_ascii_digit())
    })
}

/// What one child run left: its stderr, its file log and its secrets.
struct ChildRun {
    stderr: String,
    file_log: String,
    secrets: Vec<(String, String)>,
}

fn run_child(dir: &Path, json: bool, identifiers: bool) -> ChildRun {
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "tests::direct_loopback::redaction_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_DIR, dir)
        .env(CHILD_JSON, if json { "1" } else { "0" })
        .env_remove("RUST_LOG")
        .env_remove("TORNECT_LOG")
        .env_remove(IDENTIFIERS_ENV);
    if identifiers {
        child.env(IDENTIFIERS_ENV, "1");
    }
    let out = child.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "the child failed: {stdout}\n{}",
        tail(&stderr)
    );
    let mut file_log = String::new();
    for entry in std::fs::read_dir(dir.join("logs")).unwrap() {
        file_log.push_str(&std::fs::read_to_string(entry.unwrap().path()).unwrap());
    }
    let secrets = std::fs::read_to_string(dir.join("secrets"))
        .unwrap()
        .lines()
        .map(|line| {
            let (kind, value) = line.split_once(' ').unwrap();
            (kind.to_owned(), value.to_owned())
        })
        .collect();
    ChildRun {
        stderr,
        file_log,
        secrets,
    }
}

/// The last lines of a long capture, for a failure message.
fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

/// The secret a log names, if any.
fn named<'a>(log: &str, secrets: &'a [(String, String)]) -> Option<&'a (String, String)> {
    secrets.iter().find(|(kind, value)| match kind.as_str() {
        "port" => has_number(log, value),
        _ => log.contains(value.as_str()),
    })
}

/// The redaction e2e (the direct design §12.4 end, decision
/// M1-83), Phase A's half: a child process installs the real log layers
/// with every target at `trace` and identifiers off, forces quinn-udp's
/// `sendmsg` warning through a raw `UdpSocketState::send`, and completes a
/// whole direct session on loopback sockets, so quinn, quinn-proto and
/// rustls (through the `log` bridge) all log. Neither its stderr (text,
/// then JSON) nor its file log names an address or port either machine
/// bound, the forced destination, or either device key as hex, base32 or a
/// decimal byte list, while Tornect's own lines get through (the viewer's
/// `direct path open` with the link's counters among them). With
/// identifiers opted in, the same run's stderr does name them: the capture
/// would see a leak. The file log never does. Phase B's half (step B9):
/// after the session the same child maps a port through the real mapper
/// with a fake PCP router (crab_nat) and a fake UPnP-IGD one (igd-next's
/// SSDP search, description and control requests), renews and releases
/// both, and neither log names either router's address, the SSDP port, an
/// external address or port, or the internal port, while the mapper's
/// `router port` lines of ours get through; opted in, igd-next's own lines
/// name the UPnP router's address.
#[test]
fn a_direct_session_logs_no_address_port_or_key() {
    for (json, identifiers) in [(false, false), (true, false), (false, true)] {
        let tmp = tempfile::tempdir().unwrap();
        let run = run_child(tmp.path(), json, identifiers);
        let case = format!("json {json}, identifiers {identifiers}");
        assert!(run.secrets.len() > 4, "{case}: {:?}", run.secrets);
        for said in [
            "e2e: a trace line of ours",
            "e2e: the direct session is over",
            "e2e: router port opened pcp",
            "e2e: router port closed pcp",
            "e2e: router port opened upnp",
            "e2e: router port closed upnp",
            "e2e: the routers' ports are closed",
        ] {
            assert!(run.stderr.contains(said), "{case}: {said:?} missing");
        }
        // The viewer's debug line carries the link's counters (the device
        // rows of design §13 read them), and the checks below find no
        // address in it. The host's `direct link closed` comes from a task
        // that may outlive the child's end, so it is not waited for.
        assert!(
            run.stderr
                .lines()
                .any(|l| l.contains("direct path open") && l.contains("v4_mapped_sends")),
            "{case}: no counters on the viewer's `direct path open` line"
        );
        assert!(
            run.file_log.contains("e2e: the direct session is over"),
            "{case}: the file log holds our lines"
        );
        if let Some(secret) = named(&run.file_log, &run.secrets) {
            panic!("{case}: the file log names {secret:?}");
        }
        if identifiers {
            let igd = IGD_GATEWAY.to_string();
            for said in [
                "sendmsg error",
                "2001:db8::77",
                "rustls::",
                "quinn_proto",
                "igd_next::",
                igd.as_str(),
            ] {
                assert!(
                    run.stderr.contains(said),
                    "{case}: the opted-in capture lacks {said:?}: the e2e would miss a leak"
                );
            }
            assert!(
                named(&run.stderr, &run.secrets).is_some(),
                "{case}: the opted-in capture names nothing"
            );
        } else {
            if let Some(secret) = named(&run.stderr, &run.secrets) {
                let at = run.stderr.find(secret.1.as_str()).unwrap_or(0);
                let start = run.stderr[..at].rfind('\n').map_or(0, |n| n + 1);
                let end = run.stderr[at..]
                    .find('\n')
                    .map_or(run.stderr.len(), |n| at + n);
                panic!(
                    "{case}: stderr names {secret:?}: {}",
                    &run.stderr[start..end]
                );
            }
            for quiet in ["sendmsg", "quinn_udp", "quinn_proto", "rustls", "igd_next"] {
                assert!(!run.stderr.contains(quiet), "{case}: {quiet:?} on stderr");
            }
        }
    }
}
