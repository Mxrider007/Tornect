use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tracing_subscriber::layer::SubscriberExt;

/// The family `bind_media_socket` chose, as its address shows.
fn assert_family(bound: &BoundSocket) {
    let addr = bound.sock.local_addr().expect("its address");
    assert_ne!(addr.port(), 0);
    if bound.dual_stack {
        assert_eq!(addr.ip(), Ipv6Addr::UNSPECIFIED);
        assert!(
            !socket2::SockRef::from(&bound.sock)
                .only_v6()
                .expect("IPV6_V6ONLY")
        );
    } else {
        assert_eq!(addr.ip(), Ipv4Addr::UNSPECIFIED);
    }
}

/// Dual-stack `[::]` where the OS has IPv6, otherwise `0.0.0.0`; never both
/// half-ways (design §6.3). This container has no `AF_INET6`, so here it is
/// the IPv4 socket; the dual-stack half runs where IPv6 exists (the udp
/// tests' dual-stack test).
#[test]
fn the_session_socket_binds_dual_stack_or_ipv4_alone() {
    let bound = bind_media_socket(None).expect("a session socket");
    assert_family(&bound);
    let ipv6 = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).is_ok_and(|s| {
        s.set_only_v6(false).is_ok()
            && s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
                .is_ok()
    });
    assert_eq!(bound.dual_stack, ipv6);
    assert_family(&bind_media_socket(Some(0)).expect("port 0 is any port"));
}

/// `network.direct_port` is taken when free; a busy one falls back to any
/// port, in the same family.
#[test]
fn a_busy_fixed_port_is_retried_with_any_port() {
    let held = bind_media_socket(None).expect("a session socket");
    let port = held.sock.local_addr().expect("its address").port();
    let retried = bind_media_socket(Some(port)).expect("the retry with any port");
    assert_family(&retried);
    assert_eq!(retried.dual_stack, held.dual_stack);
    assert_ne!(retried.sock.local_addr().expect("its address").port(), port);

    let free = {
        let probe = bind_media_socket(None).expect("a session socket");
        probe.sock.local_addr().expect("its address").port()
    };
    let fixed = bind_media_socket(Some(free)).expect("the free port");
    assert_eq!(fixed.sock.local_addr().expect("its address").port(), free);
}

/// No `SO_REUSEADDR` (no other socket shares the port), non-blocking (tokio
/// requires it), and the receive buffer as large as the OS grants a socket
/// that asks for `RECV_BUFFER`.
#[test]
fn the_socket_shares_no_port_never_blocks_and_asks_for_a_large_buffer() {
    let bound = bind_media_socket(None).expect("a session socket");
    let sock = socket2::SockRef::from(&bound.sock);
    assert!(!sock.reuse_address().expect("SO_REUSEADDR"));
    let mut buf = [0; 16];
    assert_eq!(
        bound
            .sock
            .recv(&mut buf)
            .expect_err("nothing was sent")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let domain = if bound.dual_stack {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let reference = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).expect("a socket");
    reference
        .set_recv_buffer_size(RECV_BUFFER)
        .expect("SO_RCVBUF");
    assert_eq!(
        sock.recv_buffer_size().expect("SO_RCVBUF"),
        reference.recv_buffer_size().expect("SO_RCVBUF")
    );
}

/// A loopback IPv4 socket for the quiet wrapper (the session socket binds
/// the unspecified address; a test peer needs a destination).
fn loopback() -> std::net::UdpSocket {
    std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback socket")
}

/// One `poll_recv` of `socket`, with a deadline.
async fn recv_one(socket: &QuietUdp) -> (RecvMeta, Vec<u8>) {
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

/// All seven methods of quinn's socket trait (design §6.3 item 2), each
/// answering as quinn-udp's own state for the same socket does.
#[tokio::test]
async fn quiet_udp_delegates_the_seven_methods() {
    let a_sock = loopback();
    let reference = UdpSocketState::new((&a_sock).into()).expect("quinn-udp's state");
    let a_addr = a_sock.local_addr().expect("its address");
    let a = Arc::new(QuietUdp::new(a_sock).expect("the quiet socket"));
    let b_sock = loopback();
    let b_addr = b_sock.local_addr().expect("its address");
    let b = QuietUdp::new(b_sock).expect("the quiet socket");

    assert_eq!(a.local_addr().expect("local_addr"), a_addr);
    assert_eq!(a.max_transmit_segments(), reference.max_gso_segments());
    assert_eq!(a.max_receive_segments(), reference.gro_segments());
    assert_eq!(a.may_fragment(), reference.may_fragment());

    let mut poller = Arc::clone(&a).create_io_poller();
    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
        .await
        .expect("an idle socket is writable");
    // A poller is reused after each readiness.
    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
        .await
        .expect("still writable");

    let datagram = [0x41; 120];
    a.try_send(&Transmit {
        destination: b_addr,
        ecn: None,
        contents: &datagram,
        segment_size: None,
        src_ip: None,
    })
    .expect("try_send");
    let (meta, bytes) = recv_one(&b).await;
    assert_eq!(meta.addr, a_addr);
    assert_eq!(bytes, datagram);
    assert_eq!((a.errors().other(), a.errors().too_large()), (0, 0));
}

/// Counts every event any layer would see.
struct CountEvents(Arc<AtomicUsize>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CountEvents {
    fn on_event(&self, _: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A failed send is counted by kind and swallowed, and nothing is logged:
/// quinn's own path (`UdpSocketState::send`) logs both addresses at WARN
/// for the same failure (decision M1-83, design §6.3 item 1).
#[tokio::test]
async fn failed_sends_are_counted_and_never_logged() {
    let socket = Arc::new(QuietUdp::new(loopback()).expect("the quiet socket"));
    let errors = socket.errors();
    // tokio knows the socket is writable once the reactor said so; quinn
    // waits on the poller before its first send, as here.
    let mut poller = Arc::clone(&socket).create_io_poller();
    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
        .await
        .expect("an idle socket is writable");
    let v6 = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 9));
    let too_large = vec![0x41; 65_508];
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    let events = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(CountEvents(Arc::clone(&events)));
    tracing::subscriber::with_default(subscriber, || {
        // An IPv6 destination on an IPv4 socket: refused by the OS.
        let refused = Transmit {
            destination: v6,
            ecn: None,
            contents: &[0x41; 40],
            segment_size: None,
            src_ip: None,
        };
        socket.try_send(&refused).expect("swallowed");
        socket.try_send(&refused).expect("swallowed");
        // Larger than any IPv4 datagram: EMSGSIZE.
        socket
            .try_send(&Transmit {
                destination: peer,
                ecn: None,
                contents: &too_large,
                segment_size: None,
                src_ip: None,
            })
            .expect("swallowed");
    });
    assert_eq!(errors.other(), 2);
    assert_eq!(errors.too_large(), 1);
    assert_eq!(events.load(Ordering::SeqCst), 0, "the quiet socket logged");

    // The control: quinn-udp's logging send of the same failure is seen by
    // the same capture, so the zero above is not a deaf subscriber.
    let plain = loopback();
    let state = UdpSocketState::new((&plain).into()).expect("quinn-udp's state");
    let seen = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(CountEvents(Arc::clone(&seen)));
    tracing::subscriber::with_default(subscriber, || {
        state
            .send(
                (&plain).into(),
                &Transmit {
                    destination: v6,
                    ecn: None,
                    contents: &[0x41; 40],
                    segment_size: None,
                    src_ip: None,
                },
            )
            .expect("quinn-udp swallows it too, after logging");
    });
    assert!(
        seen.load(Ordering::SeqCst) >= 1,
        "quinn-udp's WARN was not seen"
    );
}

/// Outside a runtime the wrapper refuses instead of panicking in tokio.
#[test]
fn quiet_udp_needs_the_runtime() {
    let error = QuietUdp::new(loopback()).expect_err("no runtime");
    assert_eq!(error.kind(), io::ErrorKind::Other);
}

/// No `Debug` here prints the bound address (decision M1-83): tokio's own
/// socket `Debug` would.
#[tokio::test]
async fn no_debug_prints_the_bound_address() {
    let bound = bind_media_socket(None).expect("a session socket");
    let port = bound
        .sock
        .local_addr()
        .expect("its address")
        .port()
        .to_string();
    let printed = format!("{bound:?} {bound:#?}");
    assert!(!printed.contains(&port), "{printed}");
    assert!(printed.contains("dual_stack"));

    let sock = loopback();
    let port = sock.local_addr().expect("its address").port().to_string();
    let quiet = QuietUdp::new(sock).expect("the quiet socket");
    let poller = Arc::new(QuietUdp::new(loopback()).expect("the quiet socket")).create_io_poller();
    let printed = format!("{quiet:?} {quiet:#?} {poller:?}");
    assert!(!printed.contains(&port), "{printed}");
    assert!(!printed.contains("127"), "{printed}");
}
