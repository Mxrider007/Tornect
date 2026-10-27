use super::*;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn at(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

fn send(socket: &MemUdp, to: SocketAddr, bytes: &[u8], src: Option<IpAddr>) -> io::Result<()> {
    socket.try_send(&Transmit {
        destination: to,
        ecn: None,
        contents: bytes,
        segment_size: None,
        src_ip: src,
    })
}

/// `what`, within a minute of (paused) time: a regression fails instead
/// of waiting forever.
async fn within<T>(what: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(60), what)
        .await
        .expect("in time")
}

/// The next datagram, as quinn reads it: its source as the socket reports
/// it, its `dst_ip` and its bytes.
async fn next(socket: &MemUdp) -> (SocketAddr, Option<IpAddr>, Vec<u8>) {
    let mut buf = [0_u8; 2048];
    let mut meta = [RecvMeta::default()];
    let n = std::future::poll_fn(|cx| {
        let mut bufs = [IoSliceMut::new(&mut buf)];
        socket.poll_recv(cx, &mut bufs, &mut meta)
    })
    .await
    .expect("a datagram");
    assert_eq!(n, 1);
    (meta[0].addr, meta[0].dst_ip, buf[..meta[0].len].to_vec())
}

/// [`next`], within a minute.
async fn recv(socket: &MemUdp) -> (SocketAddr, Option<IpAddr>, Vec<u8>) {
    within(next(socket)).await
}

/// Whether nothing arrives within `wait`.
async fn silent(socket: &MemUdp, wait: Duration) -> bool {
    tokio::time::timeout(wait, next(socket)).await.is_err()
}

fn fates(net: &MemNet) -> Vec<Fate> {
    net.wire().iter().map(|w| w.fate).collect()
}

/// Design §6.3 "Address family rule", modelled as Windows and macOS
/// behave: a dual-stack socket refuses a plain IPv4 destination and
/// reports IPv4 peers v4-mapped; an IPv4 socket refuses IPv6. `dst_ip` is
/// the IPv4 address, as quinn-udp reports `IP_PKTINFO`.
#[tokio::test(start_paused = true)]
async fn a_dual_stack_socket_sees_ipv4_v4_mapped_and_refuses_plain_ipv4() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let a = net.machine(MachineSpec::on(lan, "192.168.1.10/24"));
    let b = net.machine(MachineSpec {
        dual_stack: false,
        ..MachineSpec::on(lan, "192.168.1.20/24")
    });
    let sa = a.bind_udp(None).expect("a socket");
    let sb = b.bind_udp(None).expect("a socket");
    assert!(sa.dual_stack() && !sb.dual_stack());
    assert_eq!(
        sa.local_addr().expect("its address"),
        SocketAddr::new(ip("::"), sa.port())
    );
    assert_eq!(
        sb.local_addr().expect("its address"),
        SocketAddr::new(ip("0.0.0.0"), sb.port())
    );

    let plain = SocketAddr::new(ip("192.168.1.20"), sb.port());
    let refused = send(&sa, plain, b"one", None).expect_err("a plain IPv4 destination");
    assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(a.counters().invalid_input, 1);
    assert!(net.wire().is_empty());

    let mapped = to_socket_family(plain, true);
    send(&sa, mapped, b"two", None).expect("a v4-mapped destination");
    let (from, dst_ip, bytes) = recv(&sb).await;
    assert_eq!(from, SocketAddr::new(ip("192.168.1.10"), sa.port()));
    assert_eq!(dst_ip, Some(ip("192.168.1.20")));
    assert_eq!(bytes, b"two");

    send(&sb, from, b"three", None).expect("an IPv4 destination");
    let (from, dst_ip, bytes) = recv(&sa).await;
    assert_eq!(from, at(&format!("[::ffff:192.168.1.20]:{}", sb.port())));
    assert_eq!(dst_ip, Some(ip("192.168.1.10")));
    assert_eq!(bytes, b"three");

    let v6 = SocketAddr::new(ip("fd00::1"), 50_000);
    let refused = send(&sb, v6, b"four", None).expect_err("IPv6 on an IPv4 socket");
    assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(b.counters().invalid_input, 1);

    let wire = net.wire();
    assert_eq!(wire.len(), 2);
    assert_eq!(wire[0].from, SocketAddr::new(ip("192.168.1.10"), sa.port()));
    assert_eq!(wire[0].to, plain);
    assert!(wire.iter().all(|w| w.fate == Fate::Delivered));
    assert_eq!((a.counters().sent, a.counters().received), (1, 1));
    assert_eq!((b.counters().sent, b.counters().received), (1, 1));
}

/// `src_ip` is honoured when it is the machine's own address of the
/// destination's family and refused otherwise; without it the kernel's
/// choice is the on-link address, then the route source; `dst_ip` is the
/// address the datagram reached.
#[tokio::test(start_paused = true)]
async fn src_ip_is_honoured_and_dst_ip_reported() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let a = net.machine(MachineSpec::on(lan, "fd00:1:2:3::a/64").and(lan, "2a02:1:2:3::a/64"));
    let b = net.machine(MachineSpec::on(lan, "fd00:1:2:3::b/64").and(lan, "2a02:1:2:3::b/64"));
    let sa = a.bind_udp(None).expect("a socket");
    let sb = b.bind_udp(None).expect("a socket");
    let b_ula = SocketAddr::new(ip("fd00:1:2:3::b"), sb.port());
    let b_global = SocketAddr::new(ip("2a02:1:2:3::b"), sb.port());

    send(&sa, b_ula, b"kernel", None).expect("a send");
    let (from, dst_ip, _) = recv(&sb).await;
    assert_eq!(from.ip(), ip("fd00:1:2:3::a"));
    assert_eq!(dst_ip, Some(ip("fd00:1:2:3::b")));

    send(&sa, b_ula, b"pinned", Some(ip("2a02:1:2:3::a"))).expect("a send");
    let (from, dst_ip, _) = recv(&sb).await;
    assert_eq!(from.ip(), ip("2a02:1:2:3::a"));
    assert_eq!(dst_ip, Some(ip("fd00:1:2:3::b")));

    send(&sa, b_global, b"global", None).expect("a send");
    let (from, dst_ip, _) = recv(&sb).await;
    assert_eq!(from.ip(), ip("2a02:1:2:3::a"));
    assert_eq!(dst_ip, Some(ip("2a02:1:2:3::b")));

    for src in [ip("fd00:9::1"), ip("192.168.1.10")] {
        let refused = send(&sa, b_ula, b"foreign", Some(src)).expect_err("not ours");
        assert_eq!(refused.kind(), io::ErrorKind::AddrNotAvailable);
    }
    assert_eq!(a.counters().bad_source, 2);

    // Off-link: the route source (the first global), whether or not
    // anything is there.
    let away = SocketAddr::new(ip("2a02:9::1"), 50_000);
    send(&sa, away, b"away", None).expect("a send");
    let last = *net.wire().last().expect("a datagram");
    assert_eq!(last.from.ip(), ip("2a02:1:2:3::a"));
    assert_eq!(last.fate, Fate::Unroutable);

    // A ULA-only machine has no IPv6 route source: off-link is unreachable.
    let c = net.machine(MachineSpec::on(lan, "fd00:1:2:3::c/64"));
    let sc = c.bind_udp(None).expect("a socket");
    let refused =
        send(&sc, SocketAddr::new(ip("fd99::1"), 50_000), b"x", None).expect_err("no route");
    assert_eq!(refused.kind(), io::ErrorKind::NetworkUnreachable);
    assert_eq!(c.counters().no_route, 1);
}

/// Delivery runs on tokio's clock: a datagram arrives exactly one latency
/// after it was sent, and datagrams keep their spacing and order.
#[tokio::test(start_paused = true)]
async fn delivery_follows_tokio_time() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec {
        latency: Duration::from_millis(50),
        loss: 0.0,
    });
    let a = net.machine(MachineSpec::on(lan, "192.168.1.10/24"));
    let b = net.machine(MachineSpec::on(lan, "192.168.1.20/24"));
    let sa = a.bind_udp(None).expect("a socket");
    let sb = b.bind_udp(None).expect("a socket");
    let to = to_socket_family(SocketAddr::new(ip("192.168.1.20"), sb.port()), true);

    let t0 = Instant::now();
    send(&sa, to, b"first", None).expect("a send");
    assert!(silent(&sb, Duration::from_millis(49)).await);
    let (_, _, bytes) = recv(&sb).await;
    assert_eq!(bytes, b"first");
    assert_eq!(t0.elapsed(), Duration::from_millis(50));

    let t1 = Instant::now();
    send(&sa, to, b"a", None).expect("a send");
    tokio::time::sleep(Duration::from_millis(10)).await;
    send(&sa, to, b"b", None).expect("a send");
    assert_eq!(recv(&sb).await.2, b"a");
    assert_eq!(t1.elapsed(), Duration::from_millis(50));
    assert_eq!(recv(&sb).await.2, b"b");
    assert_eq!(t1.elapsed(), Duration::from_millis(60));
}

/// A datagram reaches the holder of its destination on the sender's
/// segment first, then on a linked segment (with the link's latency); an
/// unlinked segment is unreachable, and a port with no socket drops it.
#[tokio::test(start_paused = true)]
async fn segments_and_links_route() {
    let net = MemNet::new(1);
    let one = net.segment(LinkSpec::LAN);
    let two = net.segment(LinkSpec::LAN);
    let three = net.segment(LinkSpec::LAN);
    net.link(
        one,
        two,
        LinkSpec {
            latency: Duration::from_millis(20),
            loss: 0.0,
        },
    );
    let a = net.machine(MachineSpec::on(one, "192.168.1.10/24"));
    let here = net.machine(MachineSpec::on(one, "192.168.1.20/24"));
    let there = net.machine(MachineSpec::on(two, "192.168.1.20/24"));
    let routed = net.machine(MachineSpec::on(two, "10.0.2.10/24"));
    let isolated = net.machine(MachineSpec::on(three, "10.0.3.10/24"));
    let sa = a.bind_udp(Some(50_000)).expect("a socket");
    let s_here = here.bind_udp(Some(50_000)).expect("a socket");
    let s_there = there.bind_udp(Some(50_000)).expect("a socket");
    let s_routed = routed.bind_udp(Some(50_000)).expect("a socket");
    let _s_isolated = isolated.bind_udp(Some(50_000)).expect("a socket");
    let mapped = |text: &str| to_socket_family(at(text), true);

    // The same private address at two sites: the sender's own segment wins.
    send(&sa, mapped("192.168.1.20:50000"), b"lan", None).expect("a send");
    assert_eq!(recv(&s_here).await.2, b"lan");
    assert!(silent(&s_there, Duration::from_millis(100)).await);

    // Off-link, through the route source and the link.
    let t0 = Instant::now();
    send(&sa, mapped("10.0.2.10:50000"), b"routed", None).expect("a send");
    assert_eq!(recv(&s_routed).await.2, b"routed");
    assert_eq!(t0.elapsed(), Duration::from_millis(20));

    send(&sa, mapped("10.0.3.10:50000"), b"isolated", None).expect("a send");
    send(&sa, mapped("192.168.1.20:50001"), b"closed", None).expect("a send");
    assert_eq!(
        fates(&net),
        [
            Fate::Delivered,
            Fate::Delivered,
            Fate::Unroutable,
            Fate::NoSocket
        ]
    );
}

/// Loss is drawn from the network's seed: the same seed loses the same
/// datagrams, another seed others, at about the share asked for.
#[tokio::test(start_paused = true)]
async fn loss_is_drawn_from_the_seed() {
    let run = |seed: u64| {
        let net = MemNet::new(seed);
        let lan = net.segment(LinkSpec {
            latency: Duration::from_millis(1),
            loss: 0.2,
        });
        let a = net.machine(MachineSpec::on(lan, "192.168.1.10/24"));
        let b = net.machine(MachineSpec::on(lan, "192.168.1.20/24"));
        let sa = a.bind_udp(None).expect("a socket");
        let sb = b.bind_udp(None).expect("a socket");
        let to = to_socket_family(SocketAddr::new(ip("192.168.1.20"), sb.port()), true);
        for _ in 0..1000 {
            send(&sa, to, b"x", None).expect("a send");
        }
        fates(&net)
    };
    let first = run(7);
    assert_eq!(first, run(7));
    assert_ne!(first, run(8));
    let lost = first.iter().filter(|f| **f == Fate::Lost).count();
    assert!((150..=250).contains(&lost), "{lost} of 1000 lost");
    assert!(
        first
            .iter()
            .all(|f| matches!(f, Fate::Lost | Fate::Delivered))
    );
}

/// The host firewall (design §3.7): `Blocked` drops everything inbound
/// but lets the machine send; `Stateful` admits only addresses its socket
/// sent to within `STATEFUL_TIMEOUT`, each flow on its own.
#[tokio::test(start_paused = true)]
async fn inbound_rules_filter_what_arrives() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let a = net.machine(MachineSpec::on(lan, "192.168.1.10/24"));
    let b = net.machine(MachineSpec {
        inbound: InboundRule::Blocked,
        ..MachineSpec::on(lan, "192.168.1.20/24")
    });
    let c = net.machine(MachineSpec::on(lan, "192.168.1.30/24"));
    let sa = a.bind_udp(Some(50_000)).expect("a socket");
    let sb = b.bind_udp(Some(50_000)).expect("a socket");
    let sc = c.bind_udp(Some(50_000)).expect("a socket");
    let to = |text: &str| to_socket_family(at(text), true);

    send(&sb, to("192.168.1.10:50000"), b"out", None).expect("a send");
    assert_eq!(recv(&sa).await.2, b"out");
    send(&sa, to("192.168.1.20:50000"), b"in", None).expect("a send");
    assert!(silent(&sb, Duration::from_millis(100)).await);

    b.set_inbound(InboundRule::Stateful);
    send(&sc, to("192.168.1.20:50000"), b"unsolicited", None).expect("a send");
    send(&sb, to("192.168.1.10:50000"), b"punch", None).expect("a send");
    send(&sa, to("192.168.1.20:50000"), b"answer", None).expect("a send");
    assert_eq!(recv(&sb).await.2, b"answer");
    send(&sc, to("192.168.1.20:50000"), b"still unsolicited", None).expect("a send");
    assert!(silent(&sb, Duration::from_millis(100)).await);
    tokio::time::sleep(STATEFUL_TIMEOUT).await;
    send(&sa, to("192.168.1.20:50000"), b"expired", None).expect("a send");
    assert!(silent(&sb, Duration::from_millis(100)).await);

    let fates = fates(&net);
    assert_eq!(
        fates,
        [
            Fate::Delivered,
            Fate::Filtered,
            Fate::Filtered,
            Fate::Delivered,
            Fate::Delivered,
            Fate::Filtered,
            Fate::Filtered
        ]
    );
}

/// A fixed port is taken when free, any port from `FIRST_PORT` otherwise;
/// a dropped socket frees its port; a failing machine binds nothing.
#[tokio::test(start_paused = true)]
async fn ports_follow_the_binds() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let a = net.machine(MachineSpec::on(lan, "192.168.1.10/24"));
    let fixed = a.bind_udp(Some(5_000)).expect("a socket");
    assert_eq!(fixed.port(), 5_000);
    let busy = a.bind_udp(Some(5_000)).expect("a socket");
    assert_eq!(busy.port(), FIRST_PORT);
    let any = a.bind(None).expect("a socket");
    assert_eq!(
        any.inner.local_addr().expect("its address").port(),
        FIRST_PORT + 1
    );
    assert!(any.dual_stack);
    drop(fixed);
    assert_eq!(a.bind_udp(Some(5_000)).expect("a socket").port(), 5_000);
    assert_eq!(a.counters().binds, 4);

    let failing = net.machine(MachineSpec {
        fail_bind: true,
        ..MachineSpec::on(lan, "192.168.1.20/24")
    });
    let refused = failing.bind(None).expect_err("no bind");
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(failing.counters().binds, 0);
}

/// A machine reads as its spec: one physical interface per segment, the
/// classes of its addresses, its route sources (the first IPv4 and the
/// first global IPv6 unless given), a failing read, no loopback.
#[tokio::test(start_paused = true)]
async fn a_machine_reads_as_its_spec() {
    let net = MemNet::new(1);
    let one = net.segment(LinkSpec::LAN);
    let two = net.segment(LinkSpec::LAN);
    let spec = MachineSpec::on(one, "192.168.1.10/24")
        .and(one, "fd00:1:2:3::a/64")
        .and(two, "2a02:1:2:3::a/64")
        .and(two, "10.0.0.10/8");
    let host = net.machine(spec.clone());
    let read = host.interfaces().await.expect("the interfaces");
    let seen: Vec<(IpAddr, u8, AddrClass, u32)> = read
        .iter()
        .map(|a| (a.ip, a.prefix_len, a.class, a.iface_index))
        .collect();
    assert_eq!(
        seen,
        [
            (ip("192.168.1.10"), 24, AddrClass::Private, 1),
            (ip("fd00:1:2:3::a"), 64, AddrClass::UniqueLocal, 1),
            (ip("2a02:1:2:3::a"), 64, AddrClass::Global, 2),
            (ip("10.0.0.10"), 8, AddrClass::Private, 2),
        ]
    );
    assert!(
        read.iter()
            .all(|a| a.usable() && a.iface_kind == IfaceKind::Physical)
    );
    assert_eq!(
        host.route_sources(),
        RouteSources {
            v4: Some(Ipv4Addr::new(192, 168, 1, 10)),
            v6: Some("2a02:1:2:3::a".parse().expect("an address")),
        }
    );
    assert!(!host.admit_loopback());
    assert_eq!(host.addrs().len(), 4);

    let given = RouteSources {
        v4: Some(Ipv4Addr::new(10, 0, 0, 10)),
        v6: None,
    };
    let routed = net.machine(MachineSpec {
        sources: Some(given),
        ..spec.clone()
    });
    assert_eq!(routed.route_sources(), given);

    let failing = net.machine(MachineSpec {
        fail_interfaces: true,
        ..spec
    });
    assert_eq!(
        failing.interfaces().await.expect_err("a failed read"),
        NetError::InterfacesTimedOut
    );
}

/// `CountingEnv` counts every call and passes it through.
#[tokio::test(start_paused = true)]
async fn counting_env_counts_every_call() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let env = CountingEnv::new(net.machine(MachineSpec::on(lan, "192.168.1.10/24")));
    assert_eq!(env.calls(), EnvCalls::default());
    assert_eq!(env.interfaces().await.expect("a read").len(), 1);
    let _ = env.route_sources();
    let _ = env.route_sources();
    assert_eq!(
        env.route_source_to("64.0.0.1:3478".parse().unwrap()),
        Some("192.168.1.10".parse().unwrap()),
        "a machine without routes of its own: the family's route source"
    );
    let bound = env.bind(Some(50_000)).expect("a socket");
    assert_eq!(
        bound.inner.local_addr().expect("its address").port(),
        50_000
    );
    assert!(!env.admit_loopback());
    let resolved = env.resolve("stun.example.net", 3478).await;
    assert_eq!(
        resolved.expect_err("no names").kind(),
        io::ErrorKind::NotFound
    );
    let request = crate::MapRequest {
        gateway: Ipv4Addr::new(192, 168, 1, 1),
        client: Ipv4Addr::new(192, 168, 1, 10),
        internal_port: std::num::NonZeroU16::new(50_000).unwrap(),
        lease: crate::MAP_LEASE,
        protocols: crate::MapProtocols::ALL,
        deadline: Instant::now().into_std(),
    };
    assert_eq!(
        env.mapper().map(request).await.expect_err("no router yet"),
        crate::MapFail::NoGateway
    );
    assert_eq!(
        env.calls(),
        EnvCalls {
            interfaces: 1,
            route_sources: 2,
            route_source_to: 1,
            binds: 1,
            resolves: 1,
            mappers: 1,
            admit_loopback: 1,
        }
    );
    assert_eq!(env.calls().total(), 8);
    assert_eq!(env.inner().counters().binds, 1);
    let loopback = CountingEnv::new(LoopbackNet::new(2));
    assert!(loopback.admit_loopback());
    assert_eq!(loopback.calls().total(), 1);
}

/// A socket that is not read holds at most `INBOX_LIMIT` datagrams.
#[tokio::test(start_paused = true)]
async fn a_full_queue_drops() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let a = net.machine(MachineSpec::on(lan, "192.168.1.10/24"));
    let b = net.machine(MachineSpec::on(lan, "192.168.1.20/24"));
    let sa = a.bind_udp(None).expect("a socket");
    let sb = b.bind_udp(None).expect("a socket");
    let to = to_socket_family(SocketAddr::new(ip("192.168.1.20"), sb.port()), true);
    for _ in 0..=INBOX_LIMIT {
        send(&sa, to, b"x", None).expect("a send");
    }
    let fates = fates(&net);
    assert_eq!(fates.len(), INBOX_LIMIT + 1);
    assert!(fates[..INBOX_LIMIT].iter().all(|f| *f == Fate::Delivered));
    assert_eq!(fates[INBOX_LIMIT], Fate::Overflow);
    assert_eq!(b.counters().received, INBOX_LIMIT as u64);
}

/// Design §12.4 `LaggedDuplex`: each direction arrives one delay after it
/// was written, keeping its spacing.
#[tokio::test(start_paused = true)]
async fn lagged_duplex_delays_each_direction() {
    let lag = Duration::from_millis(500);
    let (mut a, mut b) = lagged_duplex(1 << 16, lag);
    let t0 = Instant::now();
    a.write_all(b"hello").await.expect("a write");
    let mut got = [0; 5];
    within(b.read_exact(&mut got)).await.expect("a read");
    assert_eq!(&got, b"hello");
    assert_eq!(t0.elapsed(), lag);
    b.write_all(b"world").await.expect("a write");
    within(a.read_exact(&mut got)).await.expect("a read");
    assert_eq!(&got, b"world");
    assert_eq!(t0.elapsed(), 2 * lag);

    let t1 = Instant::now();
    a.write_all(b"x").await.expect("a write");
    tokio::time::sleep(Duration::from_millis(100)).await;
    a.write_all(b"y").await.expect("a write");
    let mut one = [0; 1];
    within(b.read_exact(&mut one)).await.expect("a read");
    assert_eq!((&one, t1.elapsed()), (b"x", lag));
    within(b.read_exact(&mut one)).await.expect("a read");
    assert_eq!(
        (&one, t1.elapsed()),
        (b"y", lag + Duration::from_millis(100))
    );
}

/// Like `tokio::io::duplex`: a shut-down end gives its peer the end of the
/// stream (after the delay and after its data) and cannot write again; a
/// dropped end does the same and breaks its peer's writes.
#[tokio::test(start_paused = true)]
async fn lagged_duplex_ends_like_a_duplex() {
    let lag = Duration::from_millis(200);
    let (mut a, mut b) = lagged_duplex(1 << 16, lag);
    let t0 = Instant::now();
    a.write_all(b"last").await.expect("a write");
    a.shutdown().await.expect("a shutdown");
    let broken = a
        .write_all(b"more")
        .await
        .expect_err("written after shutdown");
    assert_eq!(broken.kind(), io::ErrorKind::BrokenPipe);
    let mut all = Vec::new();
    within(b.read_to_end(&mut all)).await.expect("the stream");
    assert_eq!(all, b"last");
    assert_eq!(t0.elapsed(), lag);

    let t1 = Instant::now();
    drop(b);
    let broken = a.write_all(b"gone").await.expect_err("the reader is gone");
    assert_eq!(broken.kind(), io::ErrorKind::BrokenPipe);
    let mut rest = Vec::new();
    within(a.read_to_end(&mut rest)).await.expect("the stream");
    assert!(rest.is_empty());
    assert_eq!(t1.elapsed(), lag);
}

/// At most `max_buf` bytes are in flight each way; a writer beyond it
/// waits until the reader takes some.
#[tokio::test(start_paused = true)]
async fn lagged_duplex_bounds_what_is_in_flight() {
    let lag = Duration::from_millis(100);
    let (mut a, mut b) = lagged_duplex(4, lag);
    assert_eq!(a.write(&[1; 10]).await.expect("a write"), 4);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), a.write(&[2]))
            .await
            .is_err()
    );
    let mut got = [0; 4];
    within(b.read_exact(&mut got)).await.expect("a read");
    assert_eq!(got, [1; 4]);
    assert_eq!(a.write(&[2; 10]).await.expect("a write"), 4);
}
