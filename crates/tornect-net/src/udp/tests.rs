use super::*;

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::Waker;
use std::time::Duration;

use proptest::prelude::*;

use crate::env::{NetEnv, RealNet};
use crate::socket::bind_media_socket;

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

fn ip6(text: &str) -> Ipv6Addr {
    text.parse().expect("an IPv6 address")
}

/// A probe-shaped datagram (lead byte inside 0x04..=0x3F).
fn probe() -> [u8; PROBE_LEN] {
    let mut bytes = [0x5a; PROBE_LEN];
    bytes[0] = 0x17;
    bytes
}

/// A STUN-shaped datagram of `len` bytes (a Binding success header).
fn stun(len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    bytes[..2].copy_from_slice(&[0x01, 0x01]);
    bytes[4..8].copy_from_slice(&STUN_COOKIE);
    bytes
}

/// A QUIC-shaped datagram: a short header with the fixed bit set.
fn quic(len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    bytes[0] = 0x41;
    bytes
}

/// A 1200-byte long-header packet of a version quinn does not speak; a
/// server answers it with Version Negotiation (RFC 9000 §6).
fn unknown_version() -> Vec<u8> {
    let mut bytes = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8];
    bytes.extend([1; 8]);
    bytes.push(8);
    bytes.extend([2; 8]);
    bytes.resize(1200, 0);
    bytes
}

/// What a fake socket was asked to send.
#[derive(Clone, Debug)]
struct Sent {
    destination: SocketAddr,
    src_ip: Option<IpAddr>,
    contents: Vec<u8>,
}

const CREATE_IO_POLLER: usize = 0;
const TRY_SEND: usize = 1;
const POLL_RECV: usize = 2;
const LOCAL_ADDR: usize = 3;
const MAX_TRANSMIT_SEGMENTS: usize = 4;
const MAX_RECEIVE_SEGMENTS: usize = 5;
const MAY_FRAGMENT: usize = 6;

/// An in-memory socket under the punch socket: datagrams are delivered by
/// the test and every send is recorded. A dual-stack fake is strict: it
/// refuses an IPv4 destination with `InvalidInput`, as Windows and macOS
/// refuse an `AF_INET` destination on an `AF_INET6` socket.
struct Fake {
    local: SocketAddr,
    strict: bool,
    inbox: Mutex<VecDeque<(RecvMeta, Vec<u8>)>>,
    waker: Mutex<Option<Waker>>,
    sent: Mutex<Vec<Sent>>,
    blocked: AtomicBool,
    failing: AtomicBool,
    refused: AtomicUsize,
    calls: [AtomicUsize; 7],
}

impl Fake {
    fn v4() -> Arc<Self> {
        Self::with(addr("0.0.0.0:4000"), false)
    }

    fn dual_stack() -> Arc<Self> {
        Self::with(addr("[::]:4000"), true)
    }

    fn with(local: SocketAddr, strict: bool) -> Arc<Self> {
        Arc::new(Self {
            local,
            strict,
            inbox: Mutex::default(),
            waker: Mutex::default(),
            sent: Mutex::default(),
            blocked: AtomicBool::new(false),
            failing: AtomicBool::new(false),
            refused: AtomicUsize::new(0),
            calls: Default::default(),
        })
    }

    fn bound(self: &Arc<Self>) -> BoundUdp {
        BoundUdp {
            inner: Arc::clone(self) as Arc<dyn AsyncUdpSocket>,
            dual_stack: self.strict,
            errors: Arc::default(),
        }
    }

    /// Queues one receive entry: `data` from `from`, `stride` bytes apart.
    fn deliver(&self, from: SocketAddr, dst_ip: Option<IpAddr>, stride: usize, data: Vec<u8>) {
        let meta = RecvMeta {
            addr: from,
            len: data.len(),
            stride,
            dst_ip,
            ..RecvMeta::default()
        };
        self.inbox
            .lock()
            .expect("the inbox")
            .push_back((meta, data));
        if let Some(waker) = self.waker.lock().expect("the waker").take() {
            waker.wake();
        }
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().expect("the send log").clone()
    }

    fn calls(&self, method: usize) -> usize {
        self.calls[method].load(Ordering::SeqCst)
    }

    fn call(&self, method: usize) {
        self.calls[method].fetch_add(1, Ordering::SeqCst);
    }
}

impl fmt::Debug for Fake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fake").finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for Fake {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.call(CREATE_IO_POLLER);
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.call(TRY_SEND);
        if self.blocked.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if self.failing.load(Ordering::SeqCst) || (self.strict && transmit.destination.is_ipv4()) {
            self.refused.fetch_add(1, Ordering::SeqCst);
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.sent.lock().expect("the send log").push(Sent {
            destination: transmit.destination,
            src_ip: transmit.src_ip,
            contents: transmit.contents.to_vec(),
        });
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.call(POLL_RECV);
        let mut inbox = self.inbox.lock().expect("the inbox");
        if inbox.is_empty() {
            *self.waker.lock().expect("the waker") = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            let Some((m, data)) = inbox.pop_front() else {
                break;
            };
            let len = data.len().min(bufs[n].len());
            bufs[n][..len].copy_from_slice(&data[..len]);
            meta[n] = RecvMeta { len, ..m };
            n += 1;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.call(LOCAL_ADDR);
        Ok(self.local)
    }

    fn max_transmit_segments(&self) -> usize {
        self.call(MAX_TRANSMIT_SEGMENTS);
        3
    }

    fn max_receive_segments(&self) -> usize {
        self.call(MAX_RECEIVE_SEGMENTS);
        4
    }

    fn may_fragment(&self) -> bool {
        self.call(MAY_FRAGMENT);
        false
    }
}

/// One `poll_recv` of up to four entries, as quinn's driver makes it; the
/// entries as quinn would see them (length and source after the gate).
fn recv_now(socket: &PunchSocket) -> Vec<(RecvMeta, Vec<u8>)> {
    let mut storage = vec![vec![0; 4096]; 4];
    let mut metas = [RecvMeta::default(); 4];
    let n = {
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        let mut cx = Context::from_waker(Waker::noop());
        match socket.poll_recv(&mut cx, &mut bufs, &mut metas) {
            Poll::Ready(Ok(n)) => n,
            other => panic!("nothing to receive: {other:?}"),
        }
    };
    (0..n)
        .map(|i| (metas[i], storage[i][..metas[i].len].to_vec()))
        .collect()
}

fn transmit(destination: SocketAddr, contents: &[u8], src_ip: Option<IpAddr>) -> Transmit<'_> {
    Transmit {
        destination,
        ecn: None,
        contents,
        segment_size: None,
        src_ip,
    }
}

/// Waits until `fake` recorded at least `n` sends.
async fn wait_sent(fake: &Fake, n: usize) -> Vec<Sent> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let sent = fake.sent();
            if sent.len() >= n {
                return sent;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the sends within 10 s")
}

/// Lets quinn's endpoint driver handle what was delivered.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// quinn's endpoint with the QUIC bit never greased, as the session's
/// endpoint will be (design §6.3: every QUIC packet has `0x40` set).
fn endpoint_config() -> quinn::EndpointConfig {
    let mut config = quinn::EndpointConfig::default();
    config.grease_quic_bit(false);
    config
}

/// A server that never completes a handshake (it has no certificate):
/// enough for quinn to answer unknown versions and to queue an incoming
/// connection, which is all the gate tests need. The session's pinned
/// configurations are step A9's.
fn server_config() -> quinn::ServerConfig {
    #[derive(Debug)]
    struct NoCertificate;

    impl quinn::rustls::server::ResolvesServerCert for NoCertificate {
        fn resolve(
            &self,
            _: quinn::rustls::server::ClientHello<'_>,
        ) -> Option<Arc<quinn::rustls::sign::CertifiedKey>> {
            None
        }
    }

    let provider = Arc::new(quinn::rustls::crypto::ring::default_provider());
    let tls = quinn::rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NoCertificate));
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("a QUIC server config");
    quinn::ServerConfig::with_crypto(Arc::new(crypto))
}

/// A client that trusts nobody: its Initial is real, its handshake never
/// completes.
fn client_config() -> quinn::ClientConfig {
    let provider = Arc::new(quinn::rustls::crypto::ring::default_provider());
    let tls = quinn::rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(quinn::rustls::RootCertStore::empty())
        .with_no_client_auth();
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("a QUIC client config");
    quinn::ClientConfig::new(Arc::new(crypto))
}

fn endpoint(socket: &Arc<PunchSocket>, server: bool) -> quinn::Endpoint {
    quinn::Endpoint::new_with_abstract_socket(
        endpoint_config(),
        server.then(server_config),
        Arc::clone(socket) as Arc<dyn AsyncUdpSocket>,
        Arc::new(quinn::TokioRuntime),
    )
    .expect("an endpoint")
}

#[test]
fn probes_and_stun_are_told_apart_from_quic() {
    assert!(is_probe(&probe()));
    for lead in [0x04, 0x3f] {
        let mut p = probe();
        p[0] = lead;
        assert!(is_probe(&p), "lead {lead:#x}");
    }
    for lead in [0x00, 0x03, 0x40, 0x41, 0x80, 0xc0, 0xff] {
        let mut p = probe();
        p[0] = lead;
        assert!(!is_probe(&p), "lead {lead:#x}");
    }
    assert!(!is_probe(&probe()[..39]));
    assert!(!is_probe(&[0x17; 41]));

    for len in [20, 32, 548] {
        assert!(is_stun(&stun(len)), "{len} bytes");
    }
    assert!(!is_stun(&stun(548)[..19]));
    assert!(!is_stun(&[stun(548), vec![0]].concat()));
    let mut wrong_cookie = stun(32);
    wrong_cookie[7] ^= 1;
    assert!(!is_stun(&wrong_cookie));
    for lead in [0x04, 0x40, 0xc0] {
        let mut s = stun(32);
        s[0] = lead;
        assert!(!is_stun(&s), "lead {lead:#x}");
    }
    assert!(!is_probe(&unknown_version()) && !is_stun(&unknown_version()));
}

proptest! {
    /// Nothing quinn sends with its bit ungreased (byte 0 has `0x40`) is
    /// taken for a probe or STUN, and no datagram is both.
    #[test]
    fn quic_is_never_teed_and_the_tees_are_disjoint(
        bytes in proptest::collection::vec(any::<u8>(), 0..700),
    ) {
        if bytes.first().is_some_and(|b| b & 0x40 != 0) {
            prop_assert!(!is_probe(&bytes));
            prop_assert!(!is_stun(&bytes));
        }
        prop_assert!(!(is_probe(&bytes) && is_stun(&bytes)));
    }
}

/// The gate holds at most twenty addresses, in canonical form.
#[test]
fn the_gate_holds_twenty_canonical_addresses() {
    let gate = ProbeGate::new();
    assert!(gate.is_empty());
    let peer = addr("192.168.1.20:50000");
    assert!(!gate.admits(peer));
    assert!(gate.admit(to_socket_family(peer, true)));
    assert!(gate.admits(peer));
    assert!(gate.admits(to_socket_family(peer, true)));
    assert!(!gate.admits(addr("192.168.1.20:50001")));
    assert!(gate.admit(peer), "admitting twice is harmless");
    assert_eq!(gate.len(), 1);
    for port in 1..ProbeGate::CAPACITY as u16 {
        assert!(gate.admit(SocketAddr::from(([10, 0, 0, 1], 40_000 + port))));
    }
    assert_eq!(gate.len(), ProbeGate::CAPACITY);
    assert!(
        !gate.admit(addr("10.0.0.2:40000")),
        "a full gate admits nothing new"
    );
    assert!(!gate.admits(addr("10.0.0.2:40000")));
    assert!(gate.admit(peer), "a held address still passes");
    let shared = gate.clone();
    assert!(shared.admits(peer), "clones share one set");
    assert_eq!(format!("{gate:?}"), "ProbeGate(20 addresses)");
}

/// All seven methods reach the socket underneath (design §12.1
/// "delegation").
#[test]
fn the_punch_socket_delegates_the_seven_methods() {
    let fake = Fake::dual_stack();
    let (punch, _tees) = PunchSocket::new(fake.bound(), ProbeGate::new());
    assert_eq!(punch.local_addr().expect("local_addr"), addr("[::]:4000"));
    assert_eq!(punch.max_transmit_segments(), 3);
    assert_eq!(punch.max_receive_segments(), 4);
    assert!(!punch.may_fragment());
    let mut poller = Arc::clone(&punch).create_io_poller();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        poller.as_mut().poll_writable(&mut cx),
        Poll::Ready(Ok(()))
    ));
    let peer = addr("[fd12:3456:789a::20]:50000");
    punch.gate().admit(peer);
    punch.set_sources(V6Sources {
        global: None,
        ula: Some(ip6("fd12:3456:789a::5")),
    });
    punch
        .try_send(&transmit(peer, &quic(1200), None))
        .expect("try_send");
    fake.deliver(peer, None, 1200, quic(1200));
    assert_eq!(recv_now(&punch).len(), 1);
    for method in [
        CREATE_IO_POLLER,
        TRY_SEND,
        POLL_RECV,
        LOCAL_ADDR,
        MAX_TRANSMIT_SEGMENTS,
        MAX_RECEIVE_SEGMENTS,
        MAY_FRAGMENT,
    ] {
        assert_eq!(fake.calls(method), 1, "method {method}");
    }
}

/// GRO hands several datagrams of one source in one entry, `stride` bytes
/// apart: quinn gets every QUIC segment from a validated source untouched,
/// the tees get every probe and STUN segment from any source, and an
/// unvalidated entry reaches quinn as length 0 (design §12.1 "coalesced
/// input").
#[test]
fn coalesced_datagrams_reach_quinn_and_the_tees_segment_by_segment() {
    let fake = Fake::v4();
    let gate = ProbeGate::new();
    let (punch, mut tees) = PunchSocket::new(fake.bound(), gate.clone());
    let peer = addr("192.168.1.20:50000");
    let stranger = addr("192.168.1.30:50001");
    let server = addr("198.51.100.7:3478");
    gate.admit(peer);
    let here = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
    let from_peer = [quic(1200), quic(1200), probe().to_vec()].concat();
    fake.deliver(peer, here, 1200, from_peer.clone());
    fake.deliver(stranger, here, PROBE_LEN, probe().repeat(3));
    fake.deliver(server, here, 32, stun(32));
    fake.deliver(stranger, here, 1200, quic(1200));

    let got = recv_now(&punch);
    assert_eq!(got.len(), 4);
    assert_eq!(got[0].0.addr, peer, "the source is never rewritten");
    assert_eq!(got[0].0.len, from_peer.len());
    assert_eq!(got[0].0.stride, 1200);
    assert_eq!(got[0].1, from_peer);
    for (meta, _) in &got[1..] {
        assert_eq!(meta.len, 0, "an unvalidated entry reached quinn");
    }

    let mut teed = Vec::new();
    while let Ok(p) = tees.probes.try_recv() {
        teed.push(p);
    }
    assert_eq!(teed.len(), 4);
    assert_eq!(teed[0].from, peer);
    assert!(teed[1..].iter().all(|p| p.from == stranger));
    assert!(teed.iter().all(|p| p.bytes == probe() && p.dst_ip == here));
    let s = tees.stun.try_recv().expect("the STUN reply");
    assert_eq!((s.from, s.bytes), (server, stun(32)));
    assert!(tees.stun.try_recv().is_err());

    let counters = punch.counters();
    assert_eq!(
        counters.gated, 5,
        "three probes, one STUN reply, one QUIC packet"
    );
    assert_eq!(counters.teed_dropped, 0);
}

/// The side channels are bounded; overflow and a closed channel are dropped
/// and counted, never blocking the receive.
#[test]
fn full_or_closed_tees_drop_and_count() {
    let fake = Fake::v4();
    let (punch, tees) = PunchSocket::new(fake.bound(), ProbeGate::new());
    let stranger = addr("192.168.1.30:50001");
    fake.deliver(stranger, None, PROBE_LEN, probe().repeat(PROBE_TEE + 6));
    fake.deliver(stranger, None, 20, stun(20).repeat(STUN_TEE + 2));
    let mut storage = vec![vec![0; 4096]; 2];
    let mut metas = [RecvMeta::default(); 2];
    let mut bufs: Vec<IoSliceMut<'_>> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        punch.poll_recv(&mut cx, &mut bufs, &mut metas),
        Poll::Ready(Ok(2))
    ));
    assert_eq!(punch.counters().teed_dropped, 8);
    assert_eq!(tees.probes.len(), PROBE_TEE);
    assert_eq!(tees.stun.len(), STUN_TEE);
    drop(tees);
    fake.deliver(stranger, None, PROBE_LEN, probe().to_vec());
    let _ = recv_now(&punch);
    assert_eq!(punch.counters().teed_dropped, 9);
}

/// quinn never hears an unvalidated source: a 1200-byte packet of an
/// unknown version draws no Version Negotiation (design §12.1 "receive
/// gate"). The same packet from a validated source does, so the silence is
/// the gate's.
#[tokio::test]
async fn unvalidated_sources_draw_no_version_negotiation() {
    let fake = Fake::v4();
    let gate = ProbeGate::new();
    let (punch, _tees) = PunchSocket::new(fake.bound(), gate.clone());
    let _server = endpoint(&punch, true);
    let stranger = addr("192.168.1.30:50001");
    fake.deliver(stranger, None, 1200, unknown_version());
    settle().await;
    assert!(
        fake.sent().is_empty(),
        "quinn answered an unvalidated source"
    );
    // Not even an answer the send gate stopped: quinn never saw the packet.
    assert_eq!(punch.counters().send_gated, 0, "quinn handled the packet");
    assert_eq!(punch.counters().gated, 1);

    gate.admit(stranger);
    fake.deliver(stranger, None, 1200, unknown_version());
    let sent = wait_sent(&fake, 1).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].destination, stranger);
    assert_eq!(
        sent[0].contents[1..5],
        [0; 4],
        "a Version Negotiation packet"
    );
}

/// A real QUIC Initial from an unvalidated source never becomes a
/// connection attempt and draws no byte; from a validated source it does
/// (design §12.1 "receive gate", §6.5: an off-path Initial cannot reach
/// quinn).
#[tokio::test]
async fn an_initial_from_an_unvalidated_source_never_reaches_quinn() {
    let target = addr("192.168.1.20:50000");
    let client_fake = Fake::v4();
    let client_gate = ProbeGate::new();
    client_gate.admit(target);
    let (client_punch, _client_tees) = PunchSocket::new(client_fake.bound(), client_gate);
    let client = endpoint(&client_punch, false);
    let _dial = client
        .connect_with(client_config(), target, "tornect")
        .expect("a dial");
    let initial = wait_sent(&client_fake, 1).await.remove(0);
    assert_eq!(initial.destination, target);
    assert!(initial.contents.len() >= 1200);
    assert_ne!(initial.contents[0] & 0x40, 0, "the QUIC bit is not greased");

    let server_fake = Fake::v4();
    let server_gate = ProbeGate::new();
    let (server_punch, _server_tees) = PunchSocket::new(server_fake.bound(), server_gate.clone());
    let server = endpoint(&server_punch, true);
    let spoofer = addr("192.168.1.31:50001");
    let len = initial.contents.len();
    server_fake.deliver(spoofer, None, len, initial.contents.clone());
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.accept())
            .await
            .is_err(),
        "an unvalidated Initial became a connection attempt"
    );
    assert!(server_fake.sent().is_empty());
    assert_eq!(server_punch.counters().send_gated, 0);

    let dialler = addr("192.168.1.30:50000");
    server_gate.admit(dialler);
    server_fake.deliver(dialler, None, len, initial.contents);
    let incoming = tokio::time::timeout(Duration::from_secs(5), server.accept())
        .await
        .expect("the validated Initial within 5 s")
        .expect("an incoming connection");
    assert_eq!(incoming.remote_address(), dialler);
    incoming.ignore();
    assert_eq!(server_punch.counters().gated, 1);
}

/// quinn reaches only validated destinations (design §12.1 "send gate"):
/// a dial to an unvalidated address sends nothing until the gate opens.
#[tokio::test(start_paused = true)]
async fn quinn_reaches_only_validated_destinations() {
    let fake = Fake::v4();
    let gate = ProbeGate::new();
    let (punch, _tees) = PunchSocket::new(fake.bound(), gate.clone());
    let client = endpoint(&punch, false);
    let target = addr("192.168.1.20:50000");
    let _dial = client
        .connect_with(client_config(), target, "tornect")
        .expect("a dial");
    settle().await;
    assert!(
        fake.sent().is_empty(),
        "quinn reached an unvalidated address"
    );
    assert!(punch.counters().send_gated >= 1);

    gate.admit(target);
    // quinn retransmits its Initial after the probe timeout (about 1 s).
    let sent = wait_sent(&fake, 1).await;
    assert!(sent.iter().all(|s| s.destination == target));
}

/// On a dual-stack socket quinn sees an IPv4 peer as the socket reports it
/// (v4-mapped), the tables see the IPv4 form, and every send to an IPv4
/// peer leaves v4-mapped: zero refusals from a socket that refuses plain
/// IPv4 destinations, over raw sends, quinn's transmits and a quinn dial
/// (design §6.3 "address family rule", §12.1 "family").
#[tokio::test]
async fn a_dual_stack_socket_keeps_quinns_family_and_maps_every_ipv4_send() {
    let fake = Fake::dual_stack();
    let gate = ProbeGate::new();
    let (punch, mut tees) = PunchSocket::new(fake.bound(), gate.clone());
    assert!(punch.dual_stack());
    let peer = addr("192.168.1.20:50000");
    let mapped = to_socket_family(peer, true);
    assert_eq!(mapped, addr("[::ffff:192.168.1.20]:50000"));
    // The strictness is real: a plain IPv4 destination is refused below.
    assert_eq!(
        fake.try_send(&transmit(peer, &probe(), None))
            .expect_err("refused")
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let refused_before = fake.refused.load(Ordering::SeqCst);

    gate.admit(peer);
    fake.deliver(mapped, None, 1200, quic(1200));
    fake.deliver(mapped, None, PROBE_LEN, probe().to_vec());
    let got = recv_now(&punch);
    assert_eq!(got[0].0.addr, mapped, "quinn sees the socket's own form");
    assert_eq!(got[0].0.len, 1200);
    assert_eq!(got[1].0.addr, mapped);
    assert_eq!(tees.probes.try_recv().expect("the probe").from, peer);

    assert_eq!(punch.send_raw(peer, &probe(), None), RawSend::Sent);
    assert_eq!(punch.send_raw(mapped, &stun(20), None), RawSend::Sent);
    punch
        .try_send(&transmit(peer, &quic(1200), None))
        .expect("a plain IPv4 transmit");
    punch
        .try_send(&transmit(mapped, &quic(1200), None))
        .expect("a v4-mapped transmit");
    let client = endpoint(&punch, false);
    let _plain = client
        .connect_with(client_config(), peer, "tornect")
        .expect("a dial to the IPv4 form");
    let _socket_family = client
        .connect_with(client_config(), mapped, "tornect")
        .expect("a dial to the socket's form");
    let sent = wait_sent(&fake, 6).await;
    assert!(
        sent.iter().all(|s| s.destination == mapped),
        "every IPv4 send is v4-mapped"
    );
    assert_eq!(fake.refused.load(Ordering::SeqCst), refused_before);
    let counters = punch.counters();
    assert_eq!(counters.inner_errors, 0);
    assert_eq!(counters.v4_mapped_sends as usize, sent.len());
}

/// An IPv4-only socket keeps IPv4 as it is and sends no IPv6 at all.
#[test]
fn an_ipv4_socket_sends_no_ipv6() {
    let fake = Fake::v4();
    let (punch, _tees) = PunchSocket::new(fake.bound(), ProbeGate::new());
    assert!(!punch.dual_stack());
    let peer = addr("192.168.1.20:50000");
    assert_eq!(punch.send_raw(peer, &probe(), None), RawSend::Sent);
    let v6 = addr("[fd12:3456:789a::20]:50000");
    punch.set_sources(V6Sources {
        global: None,
        ula: Some(ip6("fd12:3456:789a::5")),
    });
    assert_eq!(punch.send_raw(v6, &probe(), None), RawSend::NoSource);
    punch.gate().admit(v6);
    punch
        .try_send(&transmit(v6, &quic(1200), None))
        .expect("dropped quietly");
    let sent = fake.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].destination, peer);
    let counters = punch.counters();
    assert_eq!((counters.no_source, counters.v4_mapped_sends), (2, 0));
}

/// Every IPv6 datagram leaves from an offered address: a global
/// destination from the offered global, a unique-local one from the offered
/// ULA, a probe response from the address its request reached, and nothing
/// without an offered source of the class (design §5.2 rule 7, §6.3, §12.1
/// "v6 source").
#[test]
fn ipv6_datagrams_leave_only_from_offered_addresses() {
    let fake = Fake::dual_stack();
    let gate = ProbeGate::new();
    let (punch, _tees) = PunchSocket::new(fake.bound(), gate.clone());
    let global_peer = addr("[2a01:4f8::20]:50000");
    let ula_peer = addr("[fd12:3456:789a::20]:50000");
    let link_local = addr("[fe80::20]:50000");
    let temporary = ip6("2a02:810:1:2:9d3c:61a7:11b2:4e05");
    let stable = ip6("2a02:810:1:2:3c11:2aff:fe08:1234");
    let ula = ip6("fd12:3456:789a::5");

    assert_eq!(
        punch.send_raw(global_peer, &probe(), None),
        RawSend::NoSource,
        "nothing offered: nothing leaves"
    );
    punch.set_sources(V6Sources {
        global: Some(temporary),
        ula: Some(ula),
    });
    assert_eq!(punch.sources().global, Some(temporary));
    assert_eq!(punch.send_raw(global_peer, &probe(), None), RawSend::Sent);
    assert_eq!(punch.send_raw(ula_peer, &probe(), None), RawSend::Sent);
    assert_eq!(
        punch.send_raw(ula_peer, &probe(), Some(IpAddr::V6(ula))),
        RawSend::Sent,
        "a response from the address its request reached"
    );
    assert_eq!(
        punch.send_raw(global_peer, &probe(), Some(IpAddr::V6(stable))),
        RawSend::NoSource,
        "a request that reached an address we did not offer gets no response"
    );
    assert_eq!(
        punch.send_raw(global_peer, &probe(), Some(IpAddr::V4(Ipv4Addr::LOCALHOST))),
        RawSend::NoSource
    );
    assert_eq!(
        punch.send_raw(link_local, &probe(), None),
        RawSend::NoSource
    );

    gate.admit(global_peer);
    gate.admit(ula_peer);
    for (dst, src) in [
        (global_peer, None),
        (ula_peer, None),
        (global_peer, Some(IpAddr::V6(temporary))),
        (global_peer, Some(IpAddr::V6(ula))),
        (global_peer, Some(IpAddr::V6(stable))),
    ] {
        punch
            .try_send(&transmit(dst, &quic(1200), src))
            .expect("quinn's send");
    }

    punch.set_sources(V6Sources {
        global: None,
        ula: Some(ula),
    });
    assert_eq!(
        punch.send_raw(global_peer, &probe(), None),
        RawSend::NoSource
    );
    assert_eq!(punch.send_raw(ula_peer, &probe(), None), RawSend::Sent);

    let sent = fake.sent();
    let expected = [
        (global_peer, temporary),
        (ula_peer, ula),
        (ula_peer, ula),
        (global_peer, temporary),
        (ula_peer, ula),
        (global_peer, temporary),
        (global_peer, ula),
        (ula_peer, ula),
    ];
    assert_eq!(sent.len(), expected.len());
    for (s, (dst, src)) in sent.iter().zip(expected) {
        assert_eq!(s.destination, dst);
        assert_eq!(s.src_ip, Some(IpAddr::V6(src)));
    }
    assert!(
        sent.iter()
            .all(|s| s.src_ip.is_some_and(|ip| ip != IpAddr::V6(stable)))
    );
    assert_eq!(punch.counters().no_source, 6);
}

/// A loopback destination never leaves the machine: it keeps the kernel's
/// source or a loopback one (the filters admit loopback only in test
/// environments).
#[test]
fn loopback_ipv6_keeps_a_loopback_source() {
    let fake = Fake::dual_stack();
    let (punch, _tees) = PunchSocket::new(fake.bound(), ProbeGate::new());
    let peer = addr("[::1]:50000");
    let loopback = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(punch.send_raw(peer, &probe(), None), RawSend::Sent);
    assert_eq!(punch.send_raw(peer, &probe(), loopback), RawSend::Sent);
    punch.set_sources(V6Sources {
        global: Some(ip6("2a02:810::1")),
        ula: None,
    });
    assert_eq!(
        punch.send_raw(peer, &probe(), Some(IpAddr::V6(ip6("2a02:810::1")))),
        RawSend::NoSource
    );
    let sources: Vec<_> = fake.sent().iter().map(|s| s.src_ip).collect();
    assert_eq!(sources, [None, loopback]);
}

/// The only other way out takes probes and STUN requests, counts them, and
/// drops what the socket cannot take now; quinn's own sends wait on a full
/// buffer and survive a refused one.
#[test]
fn raw_sends_take_probes_and_stun_requests_only() {
    let fake = Fake::v4();
    let (punch, _tees) = PunchSocket::new(fake.bound(), ProbeGate::new());
    let peer = addr("192.168.1.20:50000");
    for len in [0, 19, 21, 39, 41, 1200] {
        assert_eq!(
            punch.send_raw(peer, &vec![0x17; len], None),
            RawSend::WrongLength,
            "{len} bytes"
        );
    }
    assert_eq!(punch.send_raw(peer, &probe(), None), RawSend::Sent);
    assert_eq!(punch.send_raw(peer, &stun(20), None), RawSend::Sent);
    fake.blocked.store(true, Ordering::SeqCst);
    assert_eq!(punch.send_raw(peer, &probe(), None), RawSend::Blocked);
    punch.gate().admit(peer);
    assert_eq!(
        punch
            .try_send(&transmit(peer, &quic(1200), None))
            .expect_err("quinn waits for writability")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    fake.blocked.store(false, Ordering::SeqCst);
    fake.failing.store(true, Ordering::SeqCst);
    assert_eq!(punch.send_raw(peer, &probe(), None), RawSend::Failed);
    punch
        .try_send(&transmit(peer, &quic(1200), None))
        .expect("a refused send never ends quinn's driver");
    let counters = punch.counters();
    assert_eq!(counters.probes_sent, 1);
    assert_eq!(counters.stun_sent, 1);
    assert_eq!(counters.raw_blocked, 1);
    assert_eq!(counters.inner_errors, 2);
    assert_eq!(fake.sent().len(), 2);
}

/// No `Debug` of this module prints an address or a port (decision M1-83).
#[test]
fn no_debug_prints_an_address() {
    let fake = Fake::dual_stack();
    let gate = ProbeGate::new();
    let peer = addr("[fd12:3456:789a::20]:50123");
    gate.admit(peer);
    let (punch, tees) = PunchSocket::new(fake.bound(), gate.clone());
    punch.set_sources(V6Sources {
        global: Some(ip6("2a02:810:1:2:9d3c:61a7:11b2:4e05")),
        ula: Some(ip6("fd12:3456:789a::5")),
    });
    let teed = TeedProbe {
        from: addr("192.168.1.20:50123"),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))),
        bytes: probe(),
    };
    let stun_teed = TeedStun {
        from: addr("198.51.100.7:3478"),
        bytes: stun(32),
    };
    let printed = format!(
        "{punch:?} {punch:#?} {gate:?} {teed:?} {stun_teed:?} {tees:?} {:?} {:?}",
        punch.sources(),
        fake.bound()
    );
    for piece in [
        "192", "168", "50123", "fd12", "3456", "2a02", "810", "9d3c", "198", "3478",
    ] {
        assert!(!printed.contains(piece), "{piece} in {printed}");
    }
    assert!(printed.contains("v4 private"));
    assert!(printed.contains("dual_stack"));
}

/// The real socket through the seam on IPv4 loopback: a probe from an
/// unvalidated peer is teed and hidden from quinn, a raw send reaches the
/// peer, and once the peer is validated quinn hears it.
#[tokio::test]
async fn real_sockets_tee_gate_and_send_on_ipv4_loopback() {
    let bound = RealNet::new().bind(None).expect("a session socket");
    let port = bound.inner.local_addr().expect("its address").port();
    let me = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let gate = ProbeGate::new();
    let (punch, mut tees) = PunchSocket::new(bound, gate.clone());
    let peer = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a peer socket");
    let peer_addr = peer.local_addr().expect("its address");

    peer.send_to(&probe(), me).await.expect("a probe");
    let (meta, _) = recv_real(&punch).await;
    assert_eq!(meta.len, 0, "an unvalidated probe reached quinn");
    let teed = tees.probes.try_recv().expect("the teed probe");
    assert_eq!(teed.from, peer_addr);
    assert_eq!(teed.bytes, probe());

    punch.writable().await.expect("writable");
    assert_eq!(punch.send_raw(peer_addr, &probe(), None), RawSend::Sent);
    let mut buf = [0; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .expect("the probe within 5 s")
        .expect("a receive");
    assert_eq!((&buf[..n], from.port()), (&probe()[..], port));

    gate.admit(peer_addr);
    peer.send_to(&quic(1200), me).await.expect("a QUIC packet");
    let (meta, bytes) = recv_real(&punch).await;
    assert_eq!(canon(meta.addr), peer_addr);
    assert_eq!(bytes, quic(1200));
    let counters = punch.counters();
    assert_eq!((counters.gated, counters.probes_sent), (1, 1));
    assert_eq!((counters.os_errors, counters.os_too_large), (0, 0));
}

/// The receive gate end to end on real sockets: quinn's endpoint on the
/// session socket answers an unknown version only once its source is
/// validated.
#[tokio::test]
async fn on_real_sockets_quinn_answers_only_validated_sources() {
    let bound = RealNet::new().bind(None).expect("a session socket");
    let port = bound.inner.local_addr().expect("its address").port();
    let me = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let gate = ProbeGate::new();
    let (punch, _tees) = PunchSocket::new(bound, gate.clone());
    let _server = endpoint(&punch, true);
    let peer = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a peer socket");
    let mut buf = [0; 1500];

    peer.send_to(&unknown_version(), me)
        .await
        .expect("a packet");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buf))
            .await
            .is_err(),
        "quinn answered an unvalidated source"
    );
    assert_eq!(punch.counters().send_gated, 0, "quinn handled the packet");
    gate.admit(peer.local_addr().expect("its address"));
    peer.send_to(&unknown_version(), me)
        .await
        .expect("a packet");
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .expect("Version Negotiation within 5 s")
        .expect("a receive");
    assert!(n > 5 && buf[0] & 0x80 != 0);
    assert_eq!(buf[1..5], [0; 4], "a Version Negotiation packet");
    assert_eq!(punch.counters().gated, 1);
}

/// One receive entry of a real session socket, as quinn's driver would
/// poll it.
async fn recv_real(socket: &PunchSocket) -> (RecvMeta, Vec<u8>) {
    let mut buf = vec![0; 65_536];
    let mut metas = [RecvMeta::default()];
    let n = tokio::time::timeout(Duration::from_secs(5), async {
        let mut bufs = [IoSliceMut::new(&mut buf)];
        std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut metas)).await
    })
    .await
    .expect("a datagram within 5 s")
    .expect("a receive");
    assert_eq!(n, 1);
    let meta = metas[0];
    (meta, buf[..meta.len].to_vec())
}

/// The dual-stack socket on a machine with IPv6 (design §12.2 "dual-stack",
/// gate [VM]/[CI]): an IPv4 peer arrives v4-mapped for quinn and as IPv4 in
/// the tee, a raw send to its IPv4 form reaches it, and `::1` works on the
/// same socket. Skipped, with the reason printed, where the OS has no
/// IPv6 (this container); with `TORNECT_REQUIRE_IPV6` set (the dev VM and
/// CI recipe), a skip is a failure instead.
#[tokio::test]
#[allow(clippy::print_stderr)] // the skip says why
async fn the_dual_stack_socket_carries_ipv4_and_ipv6() {
    let bound = bind_media_socket(None).expect("a session socket");
    let required = std::env::var_os("TORNECT_REQUIRE_IPV6").is_some();
    if !bound.dual_stack {
        assert!(!required, "TORNECT_REQUIRE_IPV6: no dual-stack socket");
        eprintln!(
            "skipped: no IPv6 socket on this machine (no AF_INET6), so the session socket \
             is IPv4 only; this test runs on the dev VM and in CI"
        );
        return;
    }
    let port = bound.sock.local_addr().expect("its address").port();
    let gate = ProbeGate::new();
    let (punch, mut tees) = PunchSocket::new(BoundUdp::quiet(bound).expect("quiet"), gate);
    let v4 = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("an IPv4 peer");
    let v4_addr = v4.local_addr().expect("its address");
    v4.send_to(&probe(), (Ipv4Addr::LOCALHOST, port))
        .await
        .expect("a probe");
    let (meta, _) = recv_real(&punch).await;
    assert_eq!(meta.addr, to_socket_family(v4_addr, true), "quinn's form");
    assert_eq!(tees.probes.try_recv().expect("teed").from, v4_addr);
    punch.writable().await.expect("writable");
    assert_eq!(punch.send_raw(v4_addr, &probe(), None), RawSend::Sent);
    let mut buf = [0; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), v4.recv_from(&mut buf))
        .await
        .expect("the probe within 5 s")
        .expect("a receive");
    assert_eq!(
        (n, from),
        (PROBE_LEN, SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    );
    let counters = punch.counters();
    assert_eq!(counters.v4_mapped_sends, 1);
    assert_eq!((counters.os_errors, counters.inner_errors), (0, 0));

    let Ok(v6) = tokio::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await else {
        assert!(!required, "TORNECT_REQUIRE_IPV6: no IPv6 loopback address");
        eprintln!("skipped the ::1 half: no IPv6 loopback address on this machine");
        return;
    };
    let v6_addr = v6.local_addr().expect("its address");
    v6.send_to(&probe(), (Ipv6Addr::LOCALHOST, port))
        .await
        .expect("a probe");
    let (meta, _) = recv_real(&punch).await;
    assert_eq!(meta.addr, v6_addr);
    let teed = tees.probes.try_recv().expect("teed");
    assert_eq!(teed.from, v6_addr);
    assert_eq!(
        punch.send_raw(v6_addr, &probe(), teed.dst_ip),
        RawSend::Sent
    );
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), v6.recv_from(&mut buf))
        .await
        .expect("the probe within 5 s")
        .expect("a receive");
    assert_eq!(
        (n, from),
        (PROBE_LEN, SocketAddr::from((Ipv6Addr::LOCALHOST, port)))
    );
    assert_eq!(punch.counters().os_errors, 0);
}
