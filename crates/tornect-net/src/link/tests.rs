use super::*;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::NetError;
use crate::local::{IfaceAddr, IfaceKind, RouteSources};
use crate::mapping::{NoMapper, PortMapper};
use crate::mem::LoopbackNet;
use crate::udp::BoundUdp;

const TOKEN: [u8; 32] = [0x42; 32];

fn device(seed: u8) -> Arc<DeviceIdentity> {
    Arc::new(DeviceIdentity::from_seed(&[seed; 32]))
}

fn pk(seed: u8) -> [u8; 32] {
    device(seed).verifying_key().to_bytes()
}

fn params(me: TornectRole, mine: u8, peer: u8) -> DirectParams {
    DirectParams {
        me,
        identity: device(mine),
        peer_pk: pk(peer),
        session_token: Zeroizing::new(TOKEN),
        direct_port: None,
        scope: Scope::SameSite,
        gather: GatherConfig::default(),
    }
}

async fn within<T>(secs: u64, what: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(secs), what)
        .await
        .expect("in time")
}

/// Both links of one session, started as the session starts them: the
/// viewer first, the host on the viewer's candidates; each side then has
/// the other's candidates and their end.
struct Pair {
    viewer: DirectLink,
    host: DirectLink,
    viewer_offered: Vec<Candidate>,
    host_offered: Vec<Candidate>,
}

async fn start_pair(
    viewer_env: Arc<dyn NetEnv>,
    host_env: Arc<dyn NetEnv>,
    seeds: (u8, u8),
) -> Pair {
    let (viewer_seed, host_seed) = seeds;
    let (mut viewer, viewer_offered) = DirectLink::start(
        params(TornectRole::Viewer, viewer_seed, host_seed),
        viewer_env,
    )
    .await
    .expect("the viewer's link");
    let (mut host, host_offered) =
        DirectLink::start(params(TornectRole::Host, host_seed, viewer_seed), host_env)
            .await
            .expect("the host's link");
    host.add_remote(viewer_offered.clone(), Scope::SameSite);
    assert_eq!(viewer.next_local().await, LocalBatch::Done);
    host.remote_done();
    viewer.add_remote(host_offered.clone(), Scope::SameSite);
    assert_eq!(host.next_local().await, LocalBatch::Done);
    viewer.remote_done();
    Pair {
        viewer,
        host,
        viewer_offered,
        host_offered,
    }
}

/// Waits for both connections.
async fn both_established(pair: &mut Pair) -> (Established, Established) {
    let (viewer, host) = within(5, async {
        tokio::join!(pair.viewer.established(), pair.host.established())
    })
    .await;
    (
        viewer.expect("the viewer's connection"),
        host.expect("the host's connection"),
    )
}

/// The viewer opens the media stream and writes its first bytes; the host
/// accepts it and reads them.
async fn media_stream(viewer: &Established, host: &Established) -> (QuicStream, QuicStream) {
    let mut viewer_stream = viewer.open_stream(1).await.expect("the media stream");
    viewer_stream.write_all(b"bind").await.expect("a write");
    let mut host_stream = within(5, host.accept_stream())
        .await
        .expect("the media stream");
    let mut first = [0; 4];
    host_stream
        .read_exact(&mut first)
        .await
        .expect("the first bytes");
    assert_eq!(&first, b"bind");
    (viewer_stream, host_stream)
}

/// The deterministic byte at offset `i` of a transfer.
fn pattern(i: u64) -> u8 {
    (i.wrapping_mul(2_654_435_761) >> 13) as u8
}

/// Sends `total` bytes from `from` to `to` in 1 MiB chunks and returns
/// the SHA-256 of what was sent and of what arrived.
async fn transfer(from: &mut QuicStream, to: &mut QuicStream, total: u64) -> ([u8; 32], [u8; 32]) {
    const CHUNK: u64 = 1 << 20;
    let send = async {
        let mut hash = Sha256::new();
        let mut at = 0;
        while at < total {
            let len = CHUNK.min(total - at);
            let chunk: Vec<u8> = (at..at + len).map(pattern).collect();
            hash.update(&chunk);
            from.write_all(&chunk).await.expect("a write");
            at += len;
        }
        from.shutdown().await.expect("finished");
        <[u8; 32]>::from(hash.finalize())
    };
    let receive = async {
        let mut hash = Sha256::new();
        let mut buf = vec![0; 64 << 10];
        let mut got = 0;
        loop {
            let n = to.read(&mut buf).await.expect("a read");
            if n == 0 {
                break;
            }
            hash.update(&buf[..n]);
            got += n as u64;
        }
        assert_eq!(got, total);
        <[u8; 32]>::from(hash.finalize())
    };
    tokio::join!(send, receive)
}

fn no_send_failed(stats: &LinkStats) {
    let socket = stats.socket;
    assert_eq!(
        (
            socket.os_errors,
            socket.os_too_large,
            socket.inner_errors,
            socket.no_source,
            socket.send_gated,
        ),
        (0, 0, 0, 0, 0),
        "{stats:?}"
    );
}

/// The loopback pair (design §12.2 "Loopback e2e", the link half; step
/// A12): two machines on `127.0.0.x` with real UDP sockets, each role
/// dialling once (the two seed orders give each side the lower key once).
/// Both connect within the same-site schedule, the route is same-site
/// IPv4 through a host candidate, the binding secrets agree, 16 MiB cross
/// the media stream intact, and no send fails.
#[tokio::test]
async fn a_loopback_pair_connects_and_carries_16_mib() {
    let mut roles = Vec::new();
    for (round, seeds) in [(1_u8, 2_u8), (2, 1)].into_iter().enumerate() {
        let x = 2 + 2 * u8::try_from(round).expect("two rounds");
        let mut pair = start_pair(
            Arc::new(LoopbackNet::new(x)),
            Arc::new(LoopbackNet::new(x + 1)),
            seeds,
        )
        .await;
        assert_eq!(pair.viewer_offered.len(), 1);
        assert_eq!(pair.host_offered.len(), 1);
        assert_eq!(
            pair.viewer_offered[0].addr.ip(),
            IpAddr::V4(LoopbackNet::new(x).ip())
        );
        assert_eq!(pair.viewer_offered[0].kind, CandidateKind::Host);
        let started = tokio::time::Instant::now();
        let (viewer, host) = both_established(&mut pair).await;
        assert!(started.elapsed() < Duration::from_secs(2));
        for side in [&viewer, &host] {
            assert_eq!(
                side.route(),
                Route {
                    same_site: true,
                    ipv6: false
                }
            );
            assert_eq!(side.winner(), CandidateKind::Host);
            assert!(!side.closed_by_crypto());
        }
        assert_eq!(viewer.peer_key(), pk(seeds.1));
        assert_eq!(host.peer_key(), pk(seeds.0));
        assert_eq!(
            *viewer.binding_secret(&TOKEN).expect("a secret"),
            *host.binding_secret(&TOKEN).expect("a secret")
        );
        assert_ne!(
            *viewer.binding_secret(&TOKEN).expect("a secret"),
            *viewer.binding_secret(&[0x43; 32]).expect("a secret")
        );

        let (mut viewer_stream, mut host_stream) = media_stream(&viewer, &host).await;
        let (sent, received) =
            within(60, transfer(&mut host_stream, &mut viewer_stream, 16 << 20)).await;
        assert_eq!(sent, received);
        assert_eq!(viewer.stream_bytes_received(), 16 << 20);
        assert_eq!(host.stream_bytes_received(), 4);

        let (viewer_stats, host_stats) = (pair.viewer.stats(), pair.host.stats());
        assert_ne!(viewer_stats.controlling, host_stats.controlling);
        roles.push(viewer_stats.controlling);
        for stats in [&viewer_stats, &host_stats] {
            assert!(stats.established, "{stats:?}");
            assert_eq!(stats.offered, 1);
            assert_eq!(stats.globals_offered, 0);
            assert!(!stats.dual_stack);
            assert!(stats.validated >= 1, "{stats:?}");
            assert!(stats.socket.probes_sent >= 1, "{stats:?}");
            assert_eq!(stats.dial_failed, None);
            no_send_failed(stats);
        }
        let controlling = if viewer_stats.controlling {
            viewer_stats
        } else {
            host_stats
        };
        assert!(controlling.nominated && controlling.dialled);
    }
    assert_eq!(roles.len(), 2);
    assert_ne!(roles[0], roles[1], "each role dialled once");
}

/// Two instances on one computer with real sockets (decision M1-82's
/// deviation from design §12.5; the MemNet rows
/// `two_links_on_one_machine_find_no_path` and
/// `two_links_on_one_machine_meet_only_through_a_hairpinning_router`):
/// both links bind on the same `127.0.0.x`, at two ports. Each refuses the
/// other's candidate as one of its own addresses, sends nothing and fails
/// at once, having heard nothing.
#[tokio::test]
async fn two_links_on_one_loopback_address_find_no_path() {
    let machine = LoopbackNet::new(70);
    let mut pair = start_pair(Arc::new(machine), Arc::new(machine), (1, 2)).await;
    let (viewer_at, host_at) = (pair.viewer_offered[0].addr, pair.host_offered[0].addr);
    assert_eq!(viewer_at.ip(), IpAddr::V4(machine.ip()));
    assert_eq!(host_at.ip(), IpAddr::V4(machine.ip()));
    assert_ne!(viewer_at.port(), host_at.port());
    let started = tokio::time::Instant::now();
    let (viewer, host) = within(5, async {
        tokio::join!(pair.viewer.established(), pair.host.established())
    })
    .await;
    assert_eq!(
        viewer.expect_err("no path for the viewer"),
        DirectFail::NoPath { heard: false }
    );
    assert_eq!(
        host.expect_err("no path for the host"),
        DirectFail::NoPath { heard: false }
    );
    assert!(started.elapsed() < crate::checklist::SAME_SITE_SCHEDULE.fail);
    for stats in [pair.viewer.stats(), pair.host.stats()] {
        assert_eq!(stats.punch.candidates_refused, 1, "{stats:?}");
        assert_eq!(stats.punch.requests_sent, 0, "{stats:?}");
        assert_eq!(stats.socket.probes_sent, 0, "{stats:?}");
        assert!(!stats.heard && !stats.established, "{stats:?}");
    }
}

/// The 1 GiB transfer of design §12.2, with a checksum, at the checkpoint
/// gate (step A22): `cargo test -p tornect-net --release --lib
/// link::tests::a_loopback_pair_carries_1_gib -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "1 GiB over loopback QUIC: run at the checkpoint gate (step A22)"]
#[allow(clippy::print_stderr)] // the throughput is the evidence
async fn a_loopback_pair_carries_1_gib() {
    let mut pair = start_pair(
        Arc::new(LoopbackNet::new(10)),
        Arc::new(LoopbackNet::new(11)),
        (1, 2),
    )
    .await;
    let (viewer, host) = both_established(&mut pair).await;
    let (mut viewer_stream, mut host_stream) = media_stream(&viewer, &host).await;
    let started = Instant::now();
    let (sent, received) = within(
        1800,
        transfer(&mut host_stream, &mut viewer_stream, 1 << 30),
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(sent, received);
    no_send_failed(&pair.viewer.stats());
    no_send_failed(&pair.host.stats());
    eprintln!(
        "1 GiB in {:.1} s ({:.0} Mbit/s)",
        elapsed.as_secs_f64(),
        8.0 * 1024.0 / elapsed.as_secs_f64()
    );
}

/// An environment that must not be touched: every call fails the test.
struct Untouchable;

impl NetEnv for Untouchable {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        panic!("the interfaces were read")
    }

    fn route_sources(&self) -> RouteSources {
        panic!("the route sources were read")
    }

    fn bind(&self, _port: Option<u16>) -> io::Result<BoundUdp> {
        panic!("a socket was bound")
    }

    fn resolve(&self, _host: &str, _port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        panic!("a name was resolved")
    }

    fn mapper(&self) -> Arc<dyn PortMapper> {
        panic!("the router mapper was asked for")
    }
}

/// Decision M1-80: a device never connects directly to itself; the link
/// refuses before it reads an interface or binds a socket.
#[tokio::test]
async fn the_same_key_is_refused_before_any_call() {
    let fail = DirectLink::start(params(TornectRole::Viewer, 1, 1), Arc::new(Untouchable))
        .await
        .expect_err("the same key");
    assert_eq!(fail, DirectFail::SameKey);
}

/// A machine whose interfaces are `addrs` and whose binds `bind` answers,
/// counting the binds.
struct Scripted {
    addrs: Result<Vec<IfaceAddr>, NetError>,
    sources: RouteSources,
    bind: fn() -> io::Result<BoundUdp>,
    binds: AtomicUsize,
}

impl NetEnv for Scripted {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        let addrs = self.addrs.clone();
        Box::pin(async move { addrs })
    }

    fn route_sources(&self) -> RouteSources {
        self.sources
    }

    fn bind(&self, _port: Option<u16>) -> io::Result<BoundUdp> {
        self.binds.fetch_add(1, Ordering::SeqCst);
        (self.bind)()
    }

    fn resolve(&self, _host: &str, _port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
    }

    fn mapper(&self) -> Arc<dyn PortMapper> {
        Arc::new(NoMapper)
    }
}

fn never_bound() -> io::Result<BoundUdp> {
    panic!("a socket was bound")
}

fn refused() -> io::Result<BoundUdp> {
    Err(io::ErrorKind::PermissionDenied.into())
}

/// An address of a physical interface, up and usable.
fn iface(ip: &str, prefix_len: u8, kind: IfaceKind) -> IfaceAddr {
    let ip: IpAddr = ip.parse().expect("an address");
    IfaceAddr {
        ip,
        prefix_len,
        class: crate::addr::class(ip),
        temporary: false,
        deprecated: false,
        tentative: false,
        duplicated: false,
        eui64: false,
        iface_index: 2,
        iface_kind: kind,
        up: true,
        gateway_v4: None,
    }
}

/// Design §8.3: no address in scope (here: only a public address, a
/// tunnel's private one, and a failed read) gives `NoAddresses` with
/// nothing bound.
#[tokio::test]
async fn no_address_in_scope_binds_nothing() {
    let cases = [
        Ok(Vec::new()),
        Ok(vec![iface("203.0.114.7", 24, IfaceKind::Physical)]),
        Ok(vec![iface("10.8.0.2", 24, IfaceKind::Tunnel)]),
        Ok(vec![iface("172.17.0.1", 16, IfaceKind::Virtual)]),
        Err(NetError::InterfacesTimedOut),
    ];
    for addrs in cases {
        let env = Arc::new(Scripted {
            addrs,
            sources: RouteSources::default(),
            bind: never_bound,
            binds: AtomicUsize::new(0),
        });
        let fail = DirectLink::start(
            params(TornectRole::Viewer, 1, 2),
            Arc::clone(&env) as Arc<dyn NetEnv>,
        )
        .await
        .expect_err("no address");
        assert_eq!(fail, DirectFail::NoAddresses);
        assert_eq!(env.binds.load(Ordering::SeqCst), 0);
    }
}

/// A refused bind is `Socket` (the `here-socket` reason), after one try.
#[tokio::test]
async fn a_refused_bind_is_a_socket_failure() {
    let env = Arc::new(Scripted {
        addrs: Ok(vec![iface("192.168.1.20", 24, IfaceKind::Physical)]),
        sources: RouteSources::default(),
        bind: refused,
        binds: AtomicUsize::new(0),
    });
    let fail = DirectLink::start(
        params(TornectRole::Host, 1, 2),
        Arc::clone(&env) as Arc<dyn NetEnv>,
    )
    .await
    .expect_err("no socket");
    assert_eq!(fail, DirectFail::Socket);
    assert_eq!(env.binds.load(Ordering::SeqCst), 1);
}

/// Design §4 "Scope": a candidate frame above this side's scope is
/// dropped whole and counted; one at or below it is taken. `next_local`
/// says `Done` once (same-site gathering is the host candidates) and then
/// never returns.
#[tokio::test]
async fn frames_above_the_scope_are_dropped_and_gathering_ends_once() {
    let (mut link, offered) = DirectLink::start(
        params(TornectRole::Viewer, 1, 2),
        Arc::new(LoopbackNet::new(20)),
    )
    .await
    .expect("a link");
    let peer = Candidate {
        kind: CandidateKind::Host,
        addr: SocketAddr::new(IpAddr::V4(LoopbackNet::new(21).ip()), 50_000),
    };
    link.add_remote(vec![peer], Scope::Internet);
    assert_eq!(link.stats().frames_out_of_scope, 1);
    link.add_remote(vec![peer], Scope::SameSite);
    assert_eq!(link.stats().frames_out_of_scope, 1);
    assert_eq!(link.next_local().await, LocalBatch::Done);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), link.next_local())
            .await
            .is_err()
    );
    // The taken candidate is probed: the same-site schedule starts.
    within(2, async {
        while link.stats().socket.probes_sent == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert_eq!(offered.len(), 1);
}

/// Design §4: the viewer's fallback closes its link first, and after
/// `close` no QUIC can complete. Here the pair connected; the viewer's
/// close ends the host's connection, a new stream fails on both ends, and
/// `close` returns within `CLOSE_WAIT` and a little.
#[tokio::test]
async fn close_ends_the_connection_on_both_sides() {
    let mut pair = start_pair(
        Arc::new(LoopbackNet::new(30)),
        Arc::new(LoopbackNet::new(31)),
        (1, 2),
    )
    .await;
    let (viewer, host) = both_established(&mut pair).await;
    let started = tokio::time::Instant::now();
    pair.viewer.close().await;
    assert!(started.elapsed() <= CLOSE_WAIT + Duration::from_millis(100));
    within(5, host.closed()).await;
    assert!(viewer.open_stream(1).await.is_err());
    assert!(host.accept_stream().await.is_err());
    assert!(!host.closed_by_crypto());
}

/// Design §4 for a link someone else still holds: the viewer's failed
/// direct bind shuts its link while a clone of its connection (a services
/// binding, a stream) is still alive. The clone sees the link shut, its
/// driver stops, a new stream fails, and the host's connection ends; a
/// second shut changes nothing.
#[tokio::test]
async fn shut_ends_the_link_whoever_else_holds_it() {
    let mut pair = start_pair(
        Arc::new(LoopbackNet::new(80)),
        Arc::new(LoopbackNet::new(81)),
        (1, 2),
    )
    .await;
    let (viewer, host) = both_established(&mut pair).await;
    let (_viewer_stream, _host_stream) = media_stream(&viewer, &host).await;
    let held = viewer.clone();
    assert!(!held.is_shut());
    viewer.shut();
    assert!(held.is_shut());
    within(1, async {
        while !held.inner.driver.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    within(5, host.closed()).await;
    assert!(held.open_stream(0).await.is_err());
    assert!(!host.closed_by_crypto());
    viewer.shut();
    assert!(held.is_shut());
}

/// Design §6.5 and §6.7: a connection lets the viewer open the media
/// stream only; [`Established::allow_second_stream`] on the host's end
/// lets a second open (the services stream), and no third.
#[tokio::test]
async fn a_second_stream_opens_only_once_the_host_allows_it() {
    let mut pair = start_pair(
        Arc::new(LoopbackNet::new(90)),
        Arc::new(LoopbackNet::new(91)),
        (1, 2),
    )
    .await;
    let (viewer, host) = both_established(&mut pair).await;
    let (_viewer_media, _host_media) = media_stream(&viewer, &host).await;
    let waits = Duration::from_millis(300);
    assert!(
        tokio::time::timeout(waits, viewer.open_stream(0))
            .await
            .is_err(),
        "a second stream before the host allowed it"
    );
    host.allow_second_stream();
    let mut services = within(5, viewer.open_stream(0))
        .await
        .expect("the services stream");
    services.write_all(b"svc").await.expect("a write");
    let mut host_services = within(5, host.accept_stream())
        .await
        .expect("the services stream");
    let mut first = [0; 3];
    host_services
        .read_exact(&mut first)
        .await
        .expect("the first bytes");
    assert_eq!(&first, b"svc");
    assert!(
        tokio::time::timeout(waits, viewer.open_stream(0))
            .await
            .is_err(),
        "a third stream"
    );
}

/// Every message of `e` and of each error under it, and its `Debug`.
fn error_texts(e: &(dyn std::error::Error + 'static)) -> Vec<String> {
    let mut texts = vec![format!("{e:?}")];
    let mut next = Some(e);
    while let Some(e) = next {
        texts.push(e.to_string());
        next = e.source();
    }
    texts
}

/// Design §5.5 (decision M1-83): a peer whose key is pinned can still close its
/// connection with any reason, control sequences included. A stream's read
/// and write errors carry quinn's kind in fixed words, with no error under
/// them: neither their text, nor their `Debug`, nor any source names what
/// the peer wrote.
#[tokio::test]
async fn a_peers_close_reason_never_reaches_a_stream_error() {
    const REASON: &[u8] = b"\x1b[2Jpwned: run this \x07";
    let mut pair = start_pair(
        Arc::new(LoopbackNet::new(70)),
        Arc::new(LoopbackNet::new(71)),
        (1, 2),
    )
    .await;
    let (viewer, host) = both_established(&mut pair).await;
    let (mut viewer_stream, _host_stream) = media_stream(&viewer, &host).await;
    host.close_with_reason(0x0abc, REASON);
    within(5, viewer.closed()).await;
    let mut byte = [0; 1];
    let read = viewer_stream
        .read_exact(&mut byte)
        .await
        .expect_err("the connection is closed");
    let wrote = viewer_stream
        .write_all(b"more")
        .await
        .expect_err("the connection is closed");
    for e in [&read, &wrote] {
        assert_eq!(e.kind(), io::ErrorKind::NotConnected, "{e:?}");
        assert_eq!(e.to_string(), "the direct connection closed");
        assert!(std::error::Error::source(e).is_none(), "{e:?}");
        for text in error_texts(e) {
            assert!(!text.contains("pwned"), "{text}");
            assert!(!text.chars().any(char::is_control), "{text:?}");
        }
    }
}

/// A link that never reaches its peer: `close` still returns in time, and
/// its driver is stopped.
#[tokio::test]
async fn a_closed_link_reports_closed() {
    let (link, _) = DirectLink::start(
        params(TornectRole::Viewer, 1, 2),
        Arc::new(LoopbackNet::new(40)),
    )
    .await
    .expect("a link");
    let started = tokio::time::Instant::now();
    let inner = Arc::clone(&link.inner);
    link.close().await;
    assert!(started.elapsed() <= CLOSE_WAIT + Duration::from_millis(100));
    within(1, async {
        while !inner.driver.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

/// The last holder closes the link even from a thread outside any
/// runtime (Phase B releases its router mapping the same way, through the
/// captured runtime): the peer's connection ends.
#[tokio::test]
async fn the_last_holder_closes_the_link_from_any_thread() {
    let mut pair = start_pair(
        Arc::new(LoopbackNet::new(50)),
        Arc::new(LoopbackNet::new(51)),
        (2, 1),
    )
    .await;
    let (viewer, host) = both_established(&mut pair).await;
    let Pair { viewer: link, .. } = pair;
    std::thread::spawn(move || {
        drop(viewer);
        drop(link);
    })
    .join()
    .expect("the dropping thread");
    within(5, host.closed()).await;
}

/// Decision M1-83: no `Debug` of the link's types prints an address or a
/// port (the loopback addresses, the ports the sockets got).
#[tokio::test]
async fn no_debug_prints_an_address() {
    let mut pair = start_pair(
        Arc::new(LoopbackNet::new(60)),
        Arc::new(LoopbackNet::new(61)),
        (1, 2),
    )
    .await;
    let (viewer, host) = both_established(&mut pair).await;
    let (viewer_stream, host_stream) = media_stream(&viewer, &host).await;
    let ports: Vec<String> = pair
        .viewer_offered
        .iter()
        .chain(&pair.host_offered)
        .map(|c| c.addr.port().to_string())
        .collect();
    let texts = [
        format!("{:?} {:#?}", pair.viewer, pair.host),
        format!("{viewer:?} {host:#?}"),
        format!("{viewer_stream:?} {host_stream:?}"),
        format!("{:?}", LocalBatch::More(pair.viewer_offered.clone())),
        format!(
            "{:?}",
            DirectParams {
                direct_port: Some(50_123),
                ..params(TornectRole::Host, 1, 2)
            }
        ),
        format!(
            "{:?} {:?}",
            pair.viewer.stats(),
            DirectFail::NoPath { heard: true }
        ),
        DirectFail::NoAddresses.to_string(),
    ];
    for text in texts {
        for piece in ports.iter().map(String::as_str).chain(["127.0", "50123"]) {
            assert!(!text.contains(piece), "{piece} in {text}");
        }
    }
}

mod memnet;
mod nat;
