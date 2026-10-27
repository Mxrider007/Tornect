//! The STUN client and its cache (design §7.3, §5.3, §12.1–§12.3): the
//! request schedule and acceptance on [`MemNet`] in paused time (a NAT is
//! a fake server that answers a fixed external address; the NATs of step
//! B8 are not needed for the client), the cache and its refresh, and, in
//! `fake_stun`, fake servers on loopback with real sockets.

use super::*;

use std::future::Future;
use std::io::IoSliceMut;

use quinn::AsyncUdpSocket;
use quinn::udp::{RecvMeta, Transmit};

use crate::local::{IfaceKind, stun_filter};
use crate::mapping::PortMapper;
use crate::mem::{CountingEnv, LinkSpec, MachineSpec, MemHost, MemNet, MemUdp, Segment, WireKind};
use crate::quic;
use crate::stun::{BINDING_ERROR, BINDING_SUCCESS, attr};
use crate::udp::{BoundUdp, ProbeGate, STUN_COOKIE, Tees};
use crate::{NetError, TornectRole};

mod fake_stun;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn at(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// `what`, within a minute of time: a regression fails instead of waiting
/// forever.
async fn within<T>(what: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(60), what)
        .await
        .expect("in time")
}

// ---------------------------------------------------------------------------
// Fake servers.

/// A (XOR-)MAPPED-ADDRESS attribute of `addr` under `txid`.
fn address_attr(addr: SocketAddr, txid: &StunTxid, xor: bool) -> Vec<u8> {
    let (family, mut raw) = match addr.ip() {
        IpAddr::V4(v4) => (1_u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => (2_u8, v6.octets().to_vec()),
    };
    let mut port = addr.port();
    if xor {
        port ^= 0x2112;
        let mask = STUN_COOKIE.iter().chain(txid.iter());
        for (b, m) in raw.iter_mut().zip(mask) {
            *b ^= m;
        }
    }
    let kind = if xor {
        attr::XOR_MAPPED_ADDRESS
    } else {
        attr::MAPPED_ADDRESS
    };
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&u16::try_from(4 + raw.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&[0, family]);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&raw);
    out
}

/// ERROR-CODE 420 (Unknown Attribute), padded.
fn error_attr() -> Vec<u8> {
    let mut out = vec![0x00, 0x09, 0x00, 0x09, 0, 0, 4, 20];
    out.extend_from_slice(b"Stale\0\0\0");
    out
}

/// SOFTWARE of `len` bytes (a multiple of 4).
fn software(len: usize) -> Vec<u8> {
    let mut out = vec![0x80, 0x22];
    out.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    out.extend(std::iter::repeat_n(b'x', len));
    out
}

fn message(kind: u16, txid: &StunTxid, attrs: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&STUN_COOKIE);
    out.extend_from_slice(txid);
    out.extend_from_slice(attrs);
    out
}

/// How a fake server answers a Binding request.
#[derive(Debug, Clone, Copy)]
enum Answer {
    /// The address the request came from (honest, no NAT on the way).
    Echo,
    /// A fixed address: a NAT's external address, or a lie.
    Fixed(SocketAddr),
    /// A fixed address as a MAPPED-ADDRESS only (an RFC 3489 server).
    Plain(SocketAddr),
    /// An error response.
    Error,
    /// Nothing.
    Silent,
    /// A success response of more than 548 bytes.
    Oversized(SocketAddr),
    /// A success response under another transaction ID.
    OtherTxid(SocketAddr),
    /// A success response from another port of the server.
    OtherPort(SocketAddr),
}

/// The reply of `answer` to `request` from `from`.
fn reply(answer: Answer, request: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    let mut txid = [0; TXID_LEN];
    txid.copy_from_slice(&request[8..20]);
    let success = |addr: SocketAddr, txid: &StunTxid| {
        message(BINDING_SUCCESS, txid, &address_attr(addr, txid, true))
    };
    match answer {
        Answer::Echo => Some(success(from, &txid)),
        Answer::Fixed(addr) | Answer::OtherPort(addr) => Some(success(addr, &txid)),
        Answer::Plain(addr) => Some(message(
            BINDING_SUCCESS,
            &txid,
            &address_attr(addr, &txid, false),
        )),
        Answer::Error => Some(message(BINDING_ERROR, &txid, &error_attr())),
        Answer::Silent => None,
        Answer::Oversized(addr) => {
            let mut attrs = address_attr(addr, &txid, true);
            attrs.extend(software(560));
            Some(message(BINDING_SUCCESS, &txid, &attrs))
        }
        Answer::OtherTxid(addr) => {
            let mut other = txid;
            other[0] ^= 0xff;
            Some(success(addr, &other))
        }
    }
}

/// A request a fake server heard.
#[derive(Debug, Clone)]
struct Heard {
    at: Instant,
    from: SocketAddr,
    bytes: Vec<u8>,
}

type Ears = Arc<Mutex<Vec<Heard>>>;

/// Every request is the bare 20-byte Binding request (design §6.4: no
/// SOFTWARE, no FINGERPRINT); each server saw one transaction ID, the one
/// its retransmission reuses.
fn bare_requests(heard: &[Heard]) -> Option<StunTxid> {
    let mut txid = None;
    for h in heard {
        assert_eq!(h.bytes.len(), 20, "{h:?}");
        assert_eq!(&h.bytes[..4], &[0, 1, 0, 0]);
        assert_eq!(&h.bytes[4..8], &STUN_COOKIE);
        let mut this = [0; TXID_LEN];
        this.copy_from_slice(&h.bytes[8..]);
        assert_eq!(*txid.get_or_insert(this), this, "one txid per server");
    }
    txid
}

/// A fake STUN server on a [`MemNet`]: an IPv4 machine at `cidr` whose
/// port 3478 answers as `answer` (port 3479 is its "other port").
struct MemServer {
    addr: SocketAddr,
    heard: Ears,
}

impl MemServer {
    fn new(net: &MemNet, segment: Segment, cidr: &str, answer: Answer) -> Self {
        let machine = net.machine(MachineSpec {
            dual_stack: false,
            ..MachineSpec::on(segment, cidr)
        });
        let socket = machine.bind_udp(Some(3478)).expect("port 3478");
        let other = machine.bind_udp(Some(3479)).expect("port 3479");
        let heard = Ears::default();
        tokio::spawn(serve_mem(socket, other, answer, Arc::clone(&heard)));
        Self {
            addr: SocketAddr::new(machine.addrs()[0], 3478),
            heard,
        }
    }

    fn entry(&self) -> String {
        self.addr.to_string()
    }

    fn heard(&self) -> Vec<Heard> {
        lock(&self.heard).clone()
    }
}

async fn serve_mem(socket: Arc<MemUdp>, other: Arc<MemUdp>, answer: Answer, heard: Ears) {
    let mut buf = [0_u8; 2048];
    loop {
        let mut meta = [RecvMeta::default()];
        let got = std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut buf)];
            socket.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await;
        if got.is_err() {
            return;
        }
        let from = meta[0].addr;
        let request = buf[..meta[0].len].to_vec();
        lock(&heard).push(Heard {
            at: Instant::now(),
            from,
            bytes: request.clone(),
        });
        if let Some(bytes) = reply(answer, &request, from) {
            let out = if matches!(answer, Answer::OtherPort(_)) {
                &other
            } else {
                &socket
            };
            let _ = out.try_send(&Transmit {
                destination: from,
                ecn: None,
                contents: &bytes,
                segment_size: None,
                src_ip: None,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// The asking side.

/// A machine whose resolver answers from a table, each name after its own
/// delay; every other call is the wrapped machine's.
struct Named<E> {
    inner: E,
    names: Vec<(&'static str, Vec<IpAddr>, Duration)>,
}

impl<E: NetEnv> NetEnv for Named<E> {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        self.inner.interfaces()
    }

    fn route_sources(&self) -> RouteSources {
        self.inner.route_sources()
    }

    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp> {
        self.inner.bind(port)
    }

    fn resolve(&self, host: &str, port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        let found = self.names.iter().find(|(name, _, _)| *name == host);
        let delay = found.map_or(Duration::ZERO, |(_, _, delay)| *delay);
        let addrs = found.map(|(_, ips, _)| {
            ips.iter()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect::<Vec<_>>()
        });
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            addrs.ok_or_else(|| io::ErrorKind::NotFound.into())
        })
    }

    fn mapper(&self) -> Arc<dyn PortMapper> {
        self.inner.mapper()
    }

    fn admit_loopback(&self) -> bool {
        self.inner.admit_loopback()
    }
}

/// A side's session socket with quinn's endpoint driver polling it (the
/// STUN tee fills only then), its filter and its host candidates (every
/// IPv4 address of the machine at the socket's port).
struct Asker {
    socket: Arc<PunchSocket>,
    tees: Tees,
    _endpoint: quinn::Endpoint,
    filter: StunFilter,
    hosts: Vec<SocketAddr>,
}

impl Asker {
    async fn new(env: &dyn NetEnv) -> Self {
        let addrs = env.interfaces().await.expect("the interfaces");
        let sources = env.route_sources();
        let bound = env.bind(None).expect("a session socket");
        let (socket, tees) = PunchSocket::new(bound, ProbeGate::new());
        let endpoint = quic::endpoint(&socket, None).expect("an endpoint");
        let port = socket.local_addr().expect("its address").port();
        let hosts = addrs
            .iter()
            .filter(|a| a.ip.is_ipv4())
            .map(|a| SocketAddr::new(a.ip, port))
            .collect();
        Self {
            filter: stun_filter(&addrs, &sources, env.admit_loopback()),
            socket,
            tees,
            _endpoint: endpoint,
            hosts,
        }
    }

    fn port(&self) -> u16 {
        self.socket.local_addr().expect("its address").port()
    }

    /// The client over `servers`, `budget` from now, with these host
    /// candidates.
    async fn ask_with(
        &mut self,
        env: &dyn NetEnv,
        servers: &[String],
        hosts: &[SocketAddr],
        budget: Duration,
    ) -> StunReport {
        let ask = StunAsk {
            servers,
            filter: &self.filter,
            hosts,
            deadline: (Instant::now() + budget).into_std(),
            draw: 0,
            tunnel: None,
        };
        within(ask_stun(&self.socket, &mut self.tees.stun, env, &ask)).await
    }

    /// The client over `servers` with the first server `draw` picks.
    async fn ask_drawn(&mut self, env: &dyn NetEnv, servers: &[String], draw: u64) -> StunReport {
        let ask = StunAsk {
            servers,
            filter: &self.filter,
            hosts: &self.hosts,
            deadline: (Instant::now() + GATHER_BUDGET).into_std(),
            draw,
            tunnel: None,
        };
        within(ask_stun(&self.socket, &mut self.tees.stun, env, &ask)).await
    }

    /// The client over `servers` in VPN mode, `tunnel` being the tunnel's
    /// IPv4 route source.
    async fn ask_tunnelled(
        &mut self,
        env: &dyn NetEnv,
        servers: &[String],
        tunnel: Ipv4Addr,
    ) -> StunReport {
        let ask = StunAsk {
            servers,
            filter: &self.filter,
            hosts: &self.hosts,
            deadline: (Instant::now() + GATHER_BUDGET).into_std(),
            draw: 0,
            tunnel: Some(tunnel),
        };
        within(ask_stun(&self.socket, &mut self.tees.stun, env, &ask)).await
    }

    /// [`Self::ask_with`] its own host candidates, [`GATHER_BUDGET`].
    async fn ask(&mut self, env: &dyn NetEnv, servers: &[String]) -> StunReport {
        let hosts = self.hosts.clone();
        self.ask_with(env, servers, &hosts, GATHER_BUDGET).await
    }
}

/// A home LAN behind a 20 ms (one way) link to the internet segment.
struct World {
    net: MemNet,
    home: Segment,
    internet: Segment,
}

impl World {
    fn new() -> Self {
        let net = MemNet::new(7);
        let home = net.segment(LinkSpec::LAN);
        let internet = net.segment(LinkSpec {
            latency: ms(20),
            loss: 0.0,
        });
        net.link(
            home,
            internet,
            LinkSpec {
                latency: ms(20),
                loss: 0.0,
            },
        );
        Self {
            net,
            home,
            internet,
        }
    }

    /// A machine on the home LAN at `cidr`, its resolver answering `names`.
    fn asker(
        &self,
        cidr: &str,
        names: Vec<(&'static str, Vec<IpAddr>, Duration)>,
    ) -> Arc<CountingEnv<Named<MemHost>>> {
        CountingEnv::new(Named {
            inner: self.net.machine(MachineSpec::on(self.home, cidr)),
            names,
        })
    }

    fn server(&self, cidr: &str, answer: Answer) -> MemServer {
        MemServer::new(&self.net, self.internet, cidr, answer)
    }

    /// The STUN requests `from` put on the wire: when (from `t0`) and to
    /// whom.
    fn requests(&self, from: IpAddr, t0: Instant) -> Vec<(Duration, SocketAddr)> {
        self.net
            .wire()
            .iter()
            .filter(|w| w.at >= t0 && w.kind == WireKind::Stun && w.from.ip() == from)
            .map(|w| (w.at - t0, w.to))
            .collect()
    }
}

/// The external address the fake NAT reports.
const NAT: &str = "81.2.3.4:40000";

fn srflx(addr: &str) -> StunOutcome {
    StunOutcome::Srflx(Candidate {
        kind: CandidateKind::Srflx,
        addr: at(addr),
    })
}

// ---------------------------------------------------------------------------
// The client on MemNet (paused time).

/// Design §7.3: behind a NAT, the first server's answer is the srflx
/// candidate, one round trip after the one request; the request is the
/// bare 20-byte header from the session socket's port; no name was
/// resolved for a literal.
#[tokio::test(start_paused = true)]
async fn a_server_behind_a_nat_gives_the_srflx_at_its_first_answer() {
    let world = World::new();
    let env = world.asker("192.168.1.20/24", Vec::new());
    let s1 = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let mut asker = Asker::new(&*env).await;
    let t0 = Instant::now();
    let report = asker.ask(&*env, &[s1.entry()]).await;
    assert_eq!(report.outcome, srflx(NAT));
    assert_eq!(t0.elapsed(), ms(40), "one round trip");
    assert_eq!(
        report.stats,
        StunStats {
            servers: 1,
            requests: 1,
            ..StunStats::default()
        }
    );
    assert_eq!(
        world.requests(ip("192.168.1.20"), t0),
        vec![(Duration::ZERO, s1.addr)]
    );
    let heard = s1.heard();
    assert_eq!(heard.len(), 1);
    assert_eq!(heard[0].from, at(&format!("192.168.1.20:{}", asker.port())));
    assert!(bare_requests(&heard).is_some());
    assert_eq!(env.calls().resolves, 0);
    assert_eq!(asker.socket.counters().stun_sent, 1);
}

/// Design §7.3 and §4: with both servers silent, the requests leave at 0
/// and 500 ms (the first server, one transaction ID) and at 750 and 1250 ms
/// (the second, another), the client stops at the budget, and a third
/// server is never asked: 4 requests, 2 servers.
#[tokio::test(start_paused = true)]
async fn the_schedule_is_0_500_750_1250_ms_and_stops_at_the_budget() {
    let world = World::new();
    let env = world.asker("192.168.1.20/24", Vec::new());
    let s1 = world.server("64.0.0.10/24", Answer::Silent);
    let s2 = world.server("64.1.0.10/24", Answer::Silent);
    let s3 = world.server("64.2.0.10/24", Answer::Fixed(at(NAT)));
    let mut asker = Asker::new(&*env).await;
    let t0 = Instant::now();
    let report = asker
        .ask(&*env, &[s1.entry(), s2.entry(), s3.entry()])
        .await;
    assert_eq!(report.outcome, StunOutcome::Nothing);
    assert_eq!(t0.elapsed(), GATHER_BUDGET);
    assert_eq!(
        world.requests(ip("192.168.1.20"), t0),
        vec![
            (ms(0), s1.addr),
            (ms(500), s1.addr),
            (ms(750), s2.addr),
            (ms(1250), s2.addr),
        ]
    );
    assert_eq!((report.stats.servers, report.stats.requests), (2, 4));
    assert_eq!(
        usize::from(report.stats.requests),
        STUN_REQUESTS_PER_SESSION
    );
    let first = bare_requests(&s1.heard()).expect("asked");
    let second = bare_requests(&s2.heard()).expect("asked");
    assert_ne!(first, second, "a transaction ID per server");
    assert!(s3.heard().is_empty(), "never a third server");
}

/// The deadline cuts the schedule: nothing is sent at or after it, and the
/// client returns at it.
#[tokio::test(start_paused = true)]
async fn nothing_is_sent_at_or_after_the_deadline() {
    for (budget, sends) in [
        (ms(1), vec![0]),
        (ms(500), vec![0]),
        (ms(501), vec![0, 500]),
        (ms(750), vec![0, 500]),
        (ms(1000), vec![0, 500, 750]),
        (ms(1250), vec![0, 500, 750]),
        (ms(5000), vec![0, 500, 750, 1250]),
    ] {
        let world = World::new();
        let env = world.asker("192.168.1.20/24", Vec::new());
        let s1 = world.server("64.0.0.10/24", Answer::Silent);
        let s2 = world.server("64.1.0.10/24", Answer::Silent);
        let mut asker = Asker::new(&*env).await;
        let hosts = asker.hosts.clone();
        let t0 = Instant::now();
        let report = asker
            .ask_with(&*env, &[s1.entry(), s2.entry()], &hosts, budget)
            .await;
        assert_eq!(report.outcome, StunOutcome::Nothing);
        assert_eq!(t0.elapsed(), budget, "{budget:?}");
        let times: Vec<u64> = world
            .requests(ip("192.168.1.20"), t0)
            .iter()
            .map(|(t, _)| u64::try_from(t.as_millis()).unwrap())
            .collect();
        assert_eq!(times, sends, "{budget:?}");
    }
}

/// Design §5.3: a silent first server hands over to the second at 750 ms,
/// whose answer ends the client; the second's retransmission is never
/// needed.
#[tokio::test(start_paused = true)]
async fn a_silent_first_server_hands_over_at_750_ms() {
    let world = World::new();
    let env = world.asker("192.168.1.20/24", Vec::new());
    let s1 = world.server("64.0.0.10/24", Answer::Silent);
    let s2 = world.server("64.1.0.10/24", Answer::Fixed(at(NAT)));
    let mut asker = Asker::new(&*env).await;
    let t0 = Instant::now();
    let report = asker.ask(&*env, &[s1.entry(), s2.entry()]).await;
    assert_eq!(report.outcome, srflx(NAT));
    assert_eq!(t0.elapsed(), ms(790));
    assert_eq!(
        world.requests(ip("192.168.1.20"), t0),
        vec![(ms(0), s1.addr), (ms(500), s1.addr), (ms(750), s2.addr)]
    );
    assert_eq!(report.stats.requests, 3);
}

/// Decision M1-81: the first server asked is the one the draw picks; the
/// others wait for their turn.
#[tokio::test(start_paused = true)]
async fn the_draw_picks_the_first_server() {
    let world = World::new();
    let env = world.asker("192.168.1.20/24", Vec::new());
    let s1 = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let s2 = world.server("64.1.0.10/24", Answer::Fixed(at("81.2.3.5:40001")));
    let s3 = world.server("64.2.0.10/24", Answer::Fixed(at(NAT)));
    let mut asker = Asker::new(&*env).await;
    let t0 = Instant::now();
    let report = asker
        .ask_drawn(&*env, &[s1.entry(), s2.entry(), s3.entry()], 4)
        .await;
    assert_eq!(report.outcome, srflx("81.2.3.5:40001"));
    assert_eq!(
        world.requests(ip("192.168.1.20"), t0),
        vec![(Duration::ZERO, s2.addr)]
    );
    assert!(s1.heard().is_empty() && s3.heard().is_empty());
}

/// Design §7.3: the first server's transaction stays outstanding after the
/// second was asked, so its late answer (400 ms each way) is still taken,
/// once.
#[tokio::test(start_paused = true)]
async fn a_late_answer_of_the_first_server_still_counts() {
    let world = World::new();
    let far = world.net.segment(LinkSpec::LAN);
    world.net.link(
        world.home,
        far,
        LinkSpec {
            latency: ms(400),
            loss: 0.0,
        },
    );
    let env = world.asker("192.168.1.20/24", Vec::new());
    let s1 = MemServer::new(&world.net, far, "64.0.0.10/24", Answer::Fixed(at(NAT)));
    let s2 = world.server("64.1.0.10/24", Answer::Silent);
    let mut asker = Asker::new(&*env).await;
    let t0 = Instant::now();
    let report = asker.ask(&*env, &[s1.entry(), s2.entry()]).await;
    assert_eq!(report.outcome, srflx(NAT));
    assert_eq!(t0.elapsed(), ms(800));
    assert_eq!(report.stats.requests, 3);
    assert_eq!(report.stats.ignored, 0);
}

/// Design §7.3: whatever a server answers ends it, so an error response or
/// a mapped address that is not global IPv4 with a port gets no
/// retransmission; the second server is still asked at 750 ms. A
/// MAPPED-ADDRESS-only answer (RFC 3489) is taken.
#[tokio::test(start_paused = true)]
async fn an_error_or_a_refused_mapping_ends_that_server() {
    for (answer, errors, refused) in [
        (Answer::Error, 1, 0),
        (Answer::Fixed(at("192.168.9.9:5000")), 0, 1),
        (Answer::Fixed(at("100.64.1.1:5000")), 0, 1),
        (Answer::Fixed(at("203.0.113.5:5000")), 0, 1),
        (Answer::Fixed(at("127.0.0.1:5000")), 0, 1),
        (Answer::Fixed(at("[2a00:1450::1]:5000")), 0, 1),
        (Answer::Fixed(at("81.2.3.4:0")), 0, 1),
        (Answer::Plain(at("10.0.0.1:5000")), 0, 1),
    ] {
        let world = World::new();
        let env = world.asker("192.168.1.20/24", Vec::new());
        let s1 = world.server("64.0.0.10/24", answer);
        let s2 = world.server("64.1.0.10/24", Answer::Fixed(at(NAT)));
        let mut asker = Asker::new(&*env).await;
        let t0 = Instant::now();
        let report = asker.ask(&*env, &[s1.entry(), s2.entry()]).await;
        assert_eq!(report.outcome, srflx(NAT), "{answer:?}");
        assert_eq!(
            world.requests(ip("192.168.1.20"), t0),
            vec![(ms(0), s1.addr), (ms(750), s2.addr)],
            "{answer:?}"
        );
        assert_eq!(
            (report.stats.errors, report.stats.refused),
            (errors, refused),
            "{answer:?}"
        );
    }

    let world = World::new();
    let env = world.asker("192.168.1.20/24", Vec::new());
    let s1 = world.server("64.0.0.10/24", Answer::Plain(at(NAT)));
    let mut asker = Asker::new(&*env).await;
    assert_eq!(asker.ask(&*env, &[s1.entry()]).await.outcome, srflx(NAT));
}

/// With one server, an error ends the client when the second would have
/// been due (750 ms), not at the budget.
#[tokio::test(start_paused = true)]
async fn a_lone_server_that_errs_ends_the_client_at_750_ms() {
    let world = World::new();
    let env = world.asker("192.168.1.20/24", Vec::new());
    let s1 = world.server("64.0.0.10/24", Answer::Error);
    let mut asker = Asker::new(&*env).await;
    let t0 = Instant::now();
    let report = asker.ask(&*env, &[s1.entry()]).await;
    assert_eq!(report.outcome, StunOutcome::Nothing);
    assert_eq!(t0.elapsed(), STUN_SECOND);
    assert_eq!((report.stats.requests, report.stats.errors), (1, 1));
}

/// Design §7.3: only the address asked, under its transaction ID, is
/// heard. An answer under another transaction ID, or from another port of
/// the server, or from a stranger, is ignored (and the server is asked
/// again); an answer over 548 bytes never reaches the client.
#[tokio::test(start_paused = true)]
async fn only_the_server_asked_under_its_transaction_id_is_heard() {
    for (answer, ignored) in [
        (Answer::OtherTxid(at(NAT)), 4),
        (Answer::OtherPort(at(NAT)), 4),
        (Answer::Oversized(at(NAT)), 0),
    ] {
        let world = World::new();
        let env = world.asker("192.168.1.20/24", Vec::new());
        let s1 = world.server("64.0.0.10/24", answer);
        let s2 = world.server("64.1.0.10/24", answer);
        let mut asker = Asker::new(&*env).await;
        let t0 = Instant::now();
        let report = asker.ask(&*env, &[s1.entry(), s2.entry()]).await;
        assert_eq!(report.outcome, StunOutcome::Nothing, "{answer:?}");
        assert_eq!(t0.elapsed(), GATHER_BUDGET, "{answer:?}");
        assert_eq!(report.stats.requests, 4, "{answer:?}");
        assert_eq!(report.stats.ignored, ignored, "{answer:?}");
    }

    // A stranger on the internet answers first, with the srflx it would
    // like this side to offer; it cannot know the transaction ID.
    let world = World::new();
    let env = world.asker("192.168.1.20/24", Vec::new());
    let s1 = world.server("64.0.0.10/24", Answer::Silent);
    let stranger = world
        .net
        .machine(MachineSpec {
            dual_stack: false,
            ..MachineSpec::on(world.internet, "64.9.0.66/24")
        })
        .bind_udp(Some(3478))
        .expect("a socket");
    let mut asker = Asker::new(&*env).await;
    let to = SocketAddr::new(ip("192.168.1.20"), asker.port());
    let forged = message(
        BINDING_SUCCESS,
        &[7; TXID_LEN],
        &address_attr(at(NAT), &[7; TXID_LEN], true),
    );
    let servers = [s1.entry()];
    let ask = asker.ask(&*env, &servers);
    let forge = async {
        tokio::time::sleep(ms(100)).await;
        stranger
            .try_send(&Transmit {
                destination: to,
                ecn: None,
                contents: &forged,
                segment_size: None,
                src_ip: None,
            })
            .expect("sent");
    };
    let (report, ()) = tokio::join!(ask, forge);
    assert_eq!(report.outcome, StunOutcome::Nothing);
    assert_eq!(report.stats.ignored, 1);
}

/// Design §7.3: a mapped address equal to a host candidate means no NAT:
/// no srflx, and no second server. Without that host candidate the same
/// global address is the srflx.
#[tokio::test(start_paused = true)]
async fn the_server_seeing_a_host_candidate_means_no_nat() {
    let world = World::new();
    let env = CountingEnv::new(Named {
        inner: world
            .net
            .machine(MachineSpec::on(world.internet, "64.5.0.20/24")),
        names: Vec::new(),
    });
    let s1 = world.server("64.0.0.10/24", Answer::Echo);
    let s2 = world.server("64.1.0.10/24", Answer::Fixed(at(NAT)));
    let mut asker = Asker::new(&*env).await;
    let report = asker.ask(&*env, &[s1.entry(), s2.entry()]).await;
    assert_eq!(report.outcome, StunOutcome::NoNat);
    assert!(s2.heard().is_empty());

    let own = format!("64.5.0.20:{}", asker.port());
    let report = asker
        .ask_with(&*env, &[s1.entry()], &[], GATHER_BUDGET)
        .await;
    assert_eq!(report.outcome, srflx(&own));
}

/// Design §7.3 "a CGNAT base": a computer whose route source is in the
/// shared space 100.64/10 may ask, and the carrier NAT's global address is
/// its srflx.
#[tokio::test(start_paused = true)]
async fn a_cgnat_base_gets_its_srflx() {
    let world = World::new();
    let env = world.asker("100.64.0.2/10", Vec::new());
    let addrs = env.interfaces().await.expect("the interfaces");
    let sources = env.route_sources();
    assert_eq!(
        stun_base(&addrs, &sources, false, &[], false),
        Some(Ipv4Addr::new(100, 64, 0, 2))
    );
    let s1 = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let mut asker = Asker::new(&*env).await;
    assert!(asker.filter.admit(s1.addr));
    let report = asker
        .ask_with(&*env, &[s1.entry()], &[], GATHER_BUDGET)
        .await;
    assert_eq!(report.outcome, srflx(NAT));
    assert_eq!(s1.heard()[0].from.ip(), ip("100.64.0.2"));
}

/// A machine on a split tunnel: its IPv4 default route is the tunnel
/// ([`TUNNEL`]), but `excluded` is routed over the physical interface
/// ([`PHYSICAL`]), as a VPN's excluded prefixes are. Every other call is
/// the wrapped machine's.
struct SplitTunnel<E> {
    inner: E,
    excluded: IpAddr,
}

const TUNNEL: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
const PHYSICAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);

impl<E: NetEnv> NetEnv for SplitTunnel<E> {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        self.inner.interfaces()
    }

    fn route_sources(&self) -> RouteSources {
        self.inner.route_sources()
    }

    fn route_source_to(&self, to: SocketAddr) -> Option<IpAddr> {
        let source = if to.ip() == self.excluded {
            PHYSICAL
        } else {
            TUNNEL
        };
        Some(IpAddr::V4(source))
    }

    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp> {
        self.inner.bind(port)
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

/// Design §7.2 ("STUN only if the v4 route source is on the tunnel") and
/// §9.3 (a VPN user's physical identity), per server (the review of steps
/// B2 and B3): in VPN mode a server whose own route leaves outside the
/// tunnel (a split tunnel's excluded prefix) is never sent a request and
/// counts as unresolved, and the next server, routed through the tunnel,
/// is asked at once. Outside VPN mode no route is looked up and the first
/// server is asked.
#[tokio::test(start_paused = true)]
async fn in_vpn_mode_a_server_routed_outside_the_tunnel_is_never_asked() {
    let world = World::new();
    let outside = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let inside = world.server("64.0.0.20/24", Answer::Fixed(at(NAT)));
    let env = CountingEnv::new(SplitTunnel {
        inner: world
            .net
            .machine(MachineSpec::on(world.home, "192.168.1.20/24")),
        excluded: outside.addr.ip(),
    });
    let mut asker = Asker::new(&*env).await;
    let servers = [outside.entry(), inside.entry()];

    let t0 = Instant::now();
    let report = asker.ask_tunnelled(&*env, &servers, TUNNEL).await;
    assert_eq!(report.outcome, srflx(NAT));
    assert!(outside.heard().is_empty(), "nothing outside the tunnel");
    assert_eq!(inside.heard().len(), 1);
    assert_eq!(
        world.requests(ip("192.168.1.20"), t0),
        vec![(Duration::ZERO, inside.addr)]
    );
    assert_eq!((report.stats.servers, report.stats.unresolved), (1, 1));
    assert_eq!(env.calls().route_source_to, 2);

    let report = asker.ask(&*env, &servers).await;
    assert_eq!(report.outcome, srflx(NAT));
    assert_eq!(outside.heard().len(), 1, "not in VPN mode: asked first");
    assert_eq!(env.calls().route_source_to, 2, "no route looked up");

    let report = asker.ask_tunnelled(&*env, &servers[..1], TUNNEL).await;
    assert_eq!(report.outcome, StunOutcome::Nothing);
    assert_eq!((report.stats.requests, report.stats.unresolved), (0, 1));
    assert_eq!(outside.heard().len(), 1);
}

/// Design §5.3, §7.3: a name is resolved through the environment (which
/// answers from the cache on the real machine); only its first IPv4
/// address the filter admits is asked, so DNS cannot aim a request at the
/// LAN or at IPv6. A lookup slower than 500 ms is given up and the next
/// entry asked at once; a name with no admissible address, an unknown name
/// and a malformed entry are skipped.
#[tokio::test(start_paused = true)]
async fn names_are_resolved_once_filtered_and_bounded() {
    let world = World::new();
    let s1 = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let env = world.asker(
        "192.168.1.20/24",
        vec![
            (
                "stun.fast.example",
                vec![
                    ip("2a00:1450::1"),
                    ip("192.168.1.1"),
                    ip("64.0.0.10"),
                    ip("64.0.0.11"),
                ],
                ms(10),
            ),
            ("stun.slow.example", vec![ip("64.0.0.10")], ms(2000)),
            (
                "stun.lan.example",
                vec![ip("192.168.1.1"), ip("10.0.0.1"), ip("127.0.0.1")],
                ms(5),
            ),
        ],
    );
    let mut asker = Asker::new(&*env).await;

    let t0 = Instant::now();
    let report = asker
        .ask(&*env, &strings(&["stun.fast.example:3478"]))
        .await;
    assert_eq!(report.outcome, srflx(NAT));
    assert_eq!(
        world.requests(ip("192.168.1.20"), t0),
        vec![(ms(10), s1.addr)]
    );
    assert_eq!(report.stats.resolves, 1);

    let t0 = Instant::now();
    let report = asker
        .ask(
            &*env,
            &strings(&[
                "stun.slow.example:3478",
                "stun.lan.example:3478",
                "stun.unknown.example:3478",
                "no-port",
                "stun.zero.example:0",
                "64.0.0.10:3478",
            ]),
        )
        .await;
    assert_eq!(report.outcome, srflx(NAT));
    assert_eq!(
        world.requests(ip("192.168.1.20"), t0),
        vec![(ms(505), s1.addr)],
        "500 ms for the slow name, 5 ms for the LAN one"
    );
    assert_eq!(report.stats.resolves, 3);
    assert_eq!(report.stats.unresolved, 5);
    assert_eq!(env.calls().resolves, 4);
}

/// Design §5.2 rules 4 and 5 for the client: with nothing to ask (an empty
/// part, or only malformed or refused entries) it sends nothing, resolves
/// nothing and returns at once.
#[tokio::test(start_paused = true)]
async fn nothing_to_ask_means_no_traffic() {
    let world = World::new();
    let env = world.asker("192.168.1.20/24", Vec::new());
    let mut asker = Asker::new(&*env).await;
    for servers in [
        Vec::new(),
        strings(&["no-port", "x:0", "192.168.1.1:3478", "[2a00::1]:3478"]),
    ] {
        let t0 = Instant::now();
        let report = asker.ask(&*env, &servers).await;
        assert_eq!(report.outcome, StunOutcome::Nothing);
        assert_eq!(t0.elapsed(), Duration::ZERO, "{servers:?}");
        assert_eq!(report.stats.requests, 0);
    }
    assert!(world.net.wire().is_empty());
    assert_eq!(env.calls().resolves, 0);
}

/// Decision M1-83: the report and the request print no address.
#[tokio::test(start_paused = true)]
async fn no_debug_prints_an_address() {
    let world = World::new();
    let env = world.asker("192.168.1.20/24", Vec::new());
    let s1 = world.server("64.0.0.10/24", Answer::Fixed(at(NAT)));
    let mut asker = Asker::new(&*env).await;
    let servers = [s1.entry()];
    let report = asker.ask(&*env, &servers).await;
    let ask = StunAsk {
        servers: &servers,
        filter: &asker.filter,
        hosts: &asker.hosts,
        deadline: Instant::now().into_std(),
        draw: 1,
        tunnel: Some(Ipv4Addr::new(10, 8, 0, 2)),
    };
    let dns = StunDns::new();
    dns.put("stun.example.org", 3478, vec![s1.addr]);
    for text in [
        format!("{report:?}"),
        format!("{ask:?}"),
        format!("{dns:?}"),
    ] {
        for needle in ["81.2", "40000", "64.0", "192.168", "10.8", "stun.example"] {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
    }
}

// ---------------------------------------------------------------------------
// This machine: when it may ask, in what order.

fn iface(ip: &str, kind: IfaceKind, index: u32) -> IfaceAddr {
    let ip: IpAddr = ip.parse().unwrap();
    IfaceAddr {
        ip,
        prefix_len: if ip.is_ipv4() { 24 } else { 64 },
        class: class(ip),
        temporary: false,
        deprecated: false,
        tentative: false,
        duplicated: false,
        eui64: false,
        iface_index: index,
        iface_kind: kind,
        up: true,
        gateway_v4: None,
    }
}

/// Design §7.3 "When it runs", this machine's part: a private, shared or
/// global IPv4 route source (loopback only in test environments); in VPN
/// mode only through the tunnel; never with a global IPv4 host candidate.
#[test]
fn stun_base_follows_the_route_source_the_vpn_rule_and_the_hosts() {
    let v4 = |s: &str| -> Option<Ipv4Addr> { Some(s.parse().unwrap()) };
    let sources = |s: &str| RouteSources {
        v4: v4(s),
        v6: None,
    };
    let physical = |s: &str| vec![iface(s, IfaceKind::Physical, 1)];
    for (source, kind, vpn, hosts, admit_loopback, base) in [
        (
            "192.168.1.20",
            IfaceKind::Physical,
            false,
            vec![],
            false,
            true,
        ),
        ("10.1.2.3", IfaceKind::Physical, false, vec![], false, true),
        (
            "100.64.0.2",
            IfaceKind::Physical,
            false,
            vec![],
            false,
            true,
        ),
        ("64.5.0.20", IfaceKind::Physical, false, vec![], false, true),
        (
            "64.5.0.20",
            IfaceKind::Physical,
            false,
            vec![at("64.5.0.20:50000")],
            false,
            false,
        ),
        (
            "192.168.1.20",
            IfaceKind::Physical,
            false,
            vec![at("192.168.1.20:50000"), at("[2a00::5]:50000")],
            false,
            true,
        ),
        (
            "127.0.0.2",
            IfaceKind::Physical,
            false,
            vec![],
            false,
            false,
        ),
        ("127.0.0.2", IfaceKind::Physical, false, vec![], true, true),
        (
            "169.254.3.4",
            IfaceKind::Physical,
            false,
            vec![],
            false,
            false,
        ),
        (
            "192.0.2.5",
            IfaceKind::Physical,
            false,
            vec![],
            false,
            false,
        ),
        (
            "192.168.1.20",
            IfaceKind::Physical,
            true,
            vec![],
            false,
            false,
        ),
        ("10.8.0.2", IfaceKind::Tunnel, true, vec![], false, true),
    ] {
        let addrs = vec![iface(source, kind, 1)];
        let got = stun_base(&addrs, &sources(source), vpn, &hosts, admit_loopback);
        assert_eq!(got.is_some(), base, "{source} {kind:?} vpn {vpn} {hosts:?}");
        if base {
            assert_eq!(got, v4(source));
        }
    }
    let none = RouteSources::default();
    assert_eq!(
        stun_base(&physical("192.168.1.20"), &none, false, &[], false),
        None
    );
}

/// The first server is the one the draw picks (decision M1-81: at random);
/// the second is of another operator when the part has one.
#[test]
fn the_ask_order_puts_another_operator_second() {
    let servers = strings(&[
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun.cloudflare.com:3478",
        "global.stun.twilio.com:3478",
        "stun.cloudflare.com:3478",
    ]);
    assert_eq!(
        ask_order(&servers, 0),
        [
            "stun.l.google.com:19302",
            "stun.cloudflare.com:3478",
            "global.stun.twilio.com:3478",
            "stun1.l.google.com:19302",
        ]
    );
    assert_eq!(
        ask_order(&servers, 6),
        [
            "stun1.l.google.com:19302",
            "stun.cloudflare.com:3478",
            "global.stun.twilio.com:3478",
            "stun.l.google.com:19302",
        ]
    );
    assert_eq!(
        ask_order(&servers, 3),
        [
            "global.stun.twilio.com:3478",
            "stun.l.google.com:19302",
            "stun.cloudflare.com:3478",
            "stun1.l.google.com:19302",
        ]
    );
    assert!(ask_order(&[], 5).is_empty());
    let list = tornect_core::config::Network::default().stun_servers;
    for role in [TornectRole::Viewer, TornectRole::Host] {
        let part = stun::partition(&list, role);
        let [a, b] = [part[0].as_str(), part[1].as_str()];
        assert_eq!(ask_order(&part, 0), [a, b]);
        assert_eq!(ask_order(&part, 1), [b, a]);
        assert_eq!(ask_order(&part, u64::MAX), [b, a]);
    }
    // Both entries get picked: the draw is the OS's.
    let part = stun::partition(&list, TornectRole::Viewer);
    let firsts: std::collections::HashSet<&str> =
        (0..64).map(|_| ask_order(&part, draw())[0]).collect();
    assert_eq!(firsts.len(), 2);
}

#[test]
fn entries_name_a_host_and_a_port() {
    for (entry, name) in [
        (
            "stun.cloudflare.com:3478",
            Some(("stun.cloudflare.com", 3478)),
        ),
        ("192.0.2.1:19302", Some(("192.0.2.1", 19302))),
        ("[2001:db8::1]:3478", Some(("2001:db8::1", 3478))),
        ("stun.example.org", None),
        ("stun.example.org:0", None),
        ("stun.example.org:65536", None),
        (":3478", None),
        ("[]:3478", None),
    ] {
        assert_eq!(server_name(entry), name, "{entry}");
    }
}

// ---------------------------------------------------------------------------
// The cache and its refresh.

/// The cache keys a name by its lowercase form without the final dot, and
/// by port; an empty answer changes nothing.
#[test]
fn the_cache_keys_names_by_case_and_port() {
    let dns = StunDns::new();
    assert!(dns.is_empty());
    assert!(!dns.refreshed(), "a new cache is cold");
    let a = vec![at("64.0.0.10:3478")];
    dns.put("Stun.Example.ORG.", 3478, a.clone());
    assert_eq!(dns.get("stun.example.org", 3478), Some(a.clone()));
    assert_eq!(dns.get("stun.example.org", 3479), None);
    dns.put("stun.example.org", 3478, Vec::new());
    assert_eq!(dns.get("STUN.example.org", 3478), Some(a));
    assert!(!dns.refreshed(), "a name put is not a round");
    let shared = dns.clone();
    shared.clear();
    assert!(dns.is_empty(), "clones share the cache");
}

type Calls = Arc<Mutex<Vec<String>>>;

/// A table resolver that notes every lookup: `ok.example` answers,
/// `down.example` fails, `hung.example` never answers.
fn table(calls: &Calls) -> Resolver {
    let calls = Arc::clone(calls);
    Arc::new(
        move |host: &str, port: u16| -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
            lock(&calls).push(host.to_owned());
            let host = host.to_owned();
            Box::pin(async move {
                match host.as_str() {
                    "ok.example" => Ok(vec![SocketAddr::new(ip("64.0.0.20"), port)]),
                    "hung.example" => std::future::pending().await,
                    _ => Err(io::ErrorKind::NotFound.into()),
                }
            })
        },
    )
}

/// Design §5.3: a refresh round answers each listed name, keeps what a
/// failing or hanging lookup had (giving up after five seconds), forgets
/// names no longer listed, and never looks up a literal or a malformed
/// entry.
#[tokio::test(start_paused = true)]
async fn a_refresh_round_replaces_keeps_and_forgets() {
    let dns = StunDns::new();
    dns.put("down.example", 3478, vec![at("64.0.0.30:3478")]);
    dns.put("gone.example", 3478, vec![at("64.0.0.40:3478")]);
    let calls = Calls::default();
    let t0 = Instant::now();
    assert!(!dns.refreshed());
    let answered = dns
        .refresh(
            &strings(&[
                "ok.example:3478",
                "down.example:3478",
                "hung.example:3478",
                "64.0.0.50:3478",
                "[2001:db8::1]:3478",
                "no-port",
            ]),
            &table(&calls),
        )
        .await;
    assert_eq!(answered, 1);
    assert_eq!(t0.elapsed(), PREFETCH_TIMEOUT, "the hung lookup");
    assert_eq!(
        *lock(&calls),
        ["ok.example", "down.example", "hung.example"]
    );
    assert_eq!(
        dns.get("ok.example", 3478),
        Some(vec![at("64.0.0.20:3478")])
    );
    assert_eq!(
        dns.get("down.example", 3478),
        Some(vec![at("64.0.0.30:3478")])
    );
    assert_eq!(dns.get("hung.example", 3478), None);
    assert_eq!(dns.get("gone.example", 3478), None);
    assert_eq!(dns.len(), 2);
    assert!(dns.refreshed(), "a round completed, whatever answered");
}

/// Design §4: the next round is 10 minutes ± 1 minute away, to the
/// millisecond.
#[test]
fn the_refresh_is_ten_minutes_give_or_take_one() {
    let min = Duration::from_secs(9 * 60);
    let max = Duration::from_secs(11 * 60);
    assert_eq!(refresh_delay(0), min);
    assert_eq!(refresh_delay(120_000), max);
    assert_eq!(refresh_delay(120_001), min);
    assert_eq!(refresh_delay(60_000), DNS_REFRESH);
    for draw in [1, 7, 119_999, u64::MAX, u64::MAX / 3] {
        let delay = refresh_delay(draw);
        assert!((min..=max).contains(&delay), "{draw}: {delay:?}");
    }
}

/// Design §5.3: the refresh runs a round at once and the next within 9 to
/// 11 minutes, reading its list each time; an empty list asks no resolver
/// and empties the cache.
#[tokio::test(start_paused = true)]
async fn the_refresh_runs_rounds_and_follows_its_list() {
    let dns = StunDns::new();
    let calls = Calls::default();
    let allowed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let list = Arc::clone(&allowed);
    let task = tokio::spawn(dns.clone().run(
        move || {
            if list.load(std::sync::atomic::Ordering::SeqCst) {
                strings(&["ok.example:3478"])
            } else {
                Vec::new()
            }
        },
        table(&calls),
    ));
    tokio::time::sleep(ms(1)).await;
    assert_eq!(lock(&calls).len(), 1);
    assert_eq!(dns.len(), 1);
    assert!(dns.refreshed());
    tokio::time::sleep(Duration::from_secs(9 * 60) - ms(2)).await;
    assert_eq!(lock(&calls).len(), 1, "not before nine minutes");
    allowed.store(false, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(2 * 60) + ms(2)).await;
    assert_eq!(lock(&calls).len(), 1, "an empty list asks nothing");
    assert!(dns.is_empty(), "and empties the cache");
    assert!(!dns.refreshed(), "which is cold again");
    task.abort();
}

/// A machine whose names are resolved as the real machine resolves them
/// ([`RealNet`]'s `NetEnv::resolve`, its resolver a table); every other
/// call is the wrapped machine's.
struct RealNames<E> {
    inner: E,
    real: crate::RealNet,
}

impl<E: NetEnv> NetEnv for RealNames<E> {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        self.inner.interfaces()
    }

    fn route_sources(&self) -> RouteSources {
        self.inner.route_sources()
    }

    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp> {
        self.inner.bind(port)
    }

    fn resolve(&self, host: &str, port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        self.real.resolve(host, port)
    }

    fn mapper(&self) -> Arc<dyn PortMapper> {
        self.inner.mapper()
    }

    fn admit_loopback(&self) -> bool {
        self.inner.admit_loopback()
    }
}

/// Design §5.3 ("a session uses the cache and never triggers a lookup
/// unless the cache is empty"), §4 and §9.3 (the resolver operator cannot
/// time sessions), through the client: after a round in which two names
/// failed, a session walks past them and a name the round never listed
/// without one lookup or one millisecond of DNS wait, and asks the cached
/// server at once.
#[tokio::test(start_paused = true)]
async fn after_a_refresh_round_a_session_looks_no_name_up() {
    let world = World::new();
    let s1 = world.server("64.0.0.20/24", Answer::Fixed(at(NAT)));
    let calls = Calls::default();
    let real = crate::RealNet::new().with_resolver(table(&calls));
    let dns = real.stun_dns().clone();
    let listed = strings(&["down.example:3478", "hung.example:3478", "ok.example:3478"]);
    assert_eq!(dns.refresh(&listed, &table(&calls)).await, 1);
    assert!(dns.refreshed());
    let looked_up = lock(&calls).len();
    assert_eq!(looked_up, 3);

    let env = CountingEnv::new(RealNames {
        inner: world
            .net
            .machine(MachineSpec::on(world.home, "192.168.1.20/24")),
        real,
    });
    let mut asker = Asker::new(&*env).await;
    let t0 = Instant::now();
    let report = asker
        .ask(
            &*env,
            &strings(&[
                "down.example:3478",
                "hung.example:3478",
                "new.example:3478",
                "ok.example:3478",
            ]),
        )
        .await;
    assert_eq!(report.outcome, srflx(NAT));
    assert_eq!(
        world.requests(ip("192.168.1.20"), t0),
        vec![(Duration::ZERO, s1.addr)]
    );
    assert_eq!((report.stats.resolves, report.stats.unresolved), (4, 3));
    assert_eq!(env.calls().resolves, 4);
    assert_eq!(lock(&calls).len(), looked_up, "no lookup at session time");
}
