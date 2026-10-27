//! Direct links between [`MemNet`] machines on paused time (design §12.3,
//! step A13): the link half of the MemNet table. The session half (the
//! Tor fallback, `LanOnly`, the decision-table frames) runs with both FSMs
//! from step A17 on.

use super::*;

use crate::checklist::{MAX_REQUESTS_PER_TARGET, SAME_SITE_SCHEDULE};
use crate::mem::{
    CountingEnv, EnvCalls, Fate, InboundRule, LinkSpec, MachineSpec, MemHost, MemNet, WireKind,
};

fn env(machine: &MemHost) -> Arc<dyn NetEnv> {
    Arc::new(machine.clone())
}

/// A viewer and a host machine on one segment of `spec`.
fn one_segment(seed: u64, spec: LinkSpec, viewer: &str, host: &str) -> (MemNet, MemHost, MemHost) {
    let net = MemNet::new(seed);
    let lan = net.segment(spec);
    let viewer = net.machine(MachineSpec::on(lan, viewer));
    let host = net.machine(MachineSpec::on(lan, host));
    (net, viewer, host)
}

/// No send of either machine was refused for its family, its source or
/// its route (design §12.3 "zero `InvalidInput`"), and no link socket send
/// failed.
fn sent_cleanly(pair: &Pair, machines: [&MemHost; 2]) {
    for machine in machines {
        let c = machine.counters();
        assert_eq!(
            (c.invalid_input, c.bad_source, c.no_route),
            (0, 0, 0),
            "{c:?}"
        );
    }
    no_send_failed(&pair.viewer.stats());
    no_send_failed(&pair.host.stats());
}

/// Both sides' early failure, each given once as advice.
async fn both_fail(pair: &mut Pair) -> (DirectFail, DirectFail) {
    let (viewer, host) = within(10, async {
        tokio::join!(pair.viewer.established(), pair.host.established())
    })
    .await;
    (
        viewer.expect_err("no path for the viewer"),
        host.expect_err("no path for the host"),
    )
}

/// Same segment (design §12.3): both seed orders on dual-stack sockets and
/// one on IPv4 sockets connect through host candidates on the same-site
/// schedule, the route is same-site IPv4, 1 MiB crosses, and no send is
/// refused: every IPv4 destination is v4-mapped on a dual-stack socket
/// ("dual-stack `MemUdp` on both sides → Direct with zero
/// `InvalidInput`").
#[tokio::test(start_paused = true)]
async fn a_pair_on_one_segment_connects_on_paused_time() {
    for (seeds, dual_stack) in [((1, 2), true), ((2, 1), true), ((1, 2), false)] {
        let net = MemNet::new(1);
        let lan = net.segment(LinkSpec::LAN);
        let viewer = net.machine(MachineSpec {
            dual_stack,
            ..MachineSpec::on(lan, "192.168.1.10/24")
        });
        let host = net.machine(MachineSpec {
            dual_stack,
            ..MachineSpec::on(lan, "192.168.1.20/24")
        });
        let t0 = tokio::time::Instant::now();
        let mut pair = start_pair(env(&viewer), env(&host), seeds).await;
        let (v, h) = both_established(&mut pair).await;
        // One round trip on a 1 ms LAN, the minimum nomination grace, then
        // the handshake with its Retry.
        let took = t0.elapsed();
        assert!(took >= GRACE, "{took:?}");
        assert!(took <= GRACE + Duration::from_millis(20), "{took:?}");
        for side in [&v, &h] {
            assert_eq!(
                side.route(),
                Route {
                    same_site: true,
                    ipv6: false
                }
            );
            assert_eq!(side.winner(), CandidateKind::Host);
        }
        assert_eq!(
            *v.binding_secret(&TOKEN).expect("a secret"),
            *h.binding_secret(&TOKEN).expect("a secret")
        );
        let (mut viewer_stream, mut host_stream) = media_stream(&v, &h).await;
        let (sent, received) =
            within(60, transfer(&mut host_stream, &mut viewer_stream, 1 << 20)).await;
        assert_eq!(sent, received);

        sent_cleanly(&pair, [&viewer, &host]);
        for stats in [pair.viewer.stats(), pair.host.stats()] {
            assert_eq!(stats.dual_stack, dual_stack);
            assert_eq!(stats.socket.v4_mapped_sends > 0, dual_stack, "{stats:?}");
            assert!(stats.established);
        }
        let wire = net.wire();
        assert!(wire.iter().all(|w| w.fate == Fate::Delivered));
        let offered: Vec<SocketAddr> = pair
            .viewer_offered
            .iter()
            .chain(&pair.host_offered)
            .map(|c| c.addr)
            .collect();
        assert!(wire.iter().all(|w| offered.contains(&w.from)));
        assert!(wire.iter().any(|w| w.kind == WireKind::Probe));
    }
}

/// The least nomination grace (`checklist::GRACE_MIN`).
const GRACE: Duration = crate::checklist::GRACE_MIN;

/// 20 % loss on the segment (design §12.3): over eight seeds every pair
/// still connects before the viewer's 4 s fallback deadline, and 256 KiB
/// cross intact.
#[tokio::test(start_paused = true)]
async fn twenty_percent_loss_still_connects() {
    let lossy = LinkSpec {
        latency: Duration::from_millis(2),
        loss: 0.2,
    };
    let mut lost = 0;
    for seed in 1..=8 {
        let (net, viewer, host) = one_segment(seed, lossy, "192.168.1.10/24", "192.168.1.20/24");
        let t0 = tokio::time::Instant::now();
        let mut pair = start_pair(env(&viewer), env(&host), (1, 2)).await;
        let (v, h) = both_established(&mut pair).await;
        assert!(t0.elapsed() < Duration::from_secs(4), "seed {seed}");
        let (mut viewer_stream, mut host_stream) = media_stream(&v, &h).await;
        let (sent, received) = within(
            60,
            transfer(&mut host_stream, &mut viewer_stream, 256 << 10),
        )
        .await;
        assert_eq!(sent, received, "seed {seed}");
        sent_cleanly(&pair, [&viewer, &host]);
        lost += net.wire().iter().filter(|w| w.fate == Fate::Lost).count();
    }
    assert!(lost > 0);
}

/// Different segments (design §12.3 "different segments"): the same
/// private range at two sites passes both filters, but nothing arrives.
/// Each side's checklist gives up on the same-site schedule, having heard
/// nothing; no target got more than its four requests.
#[tokio::test(start_paused = true)]
async fn unlinked_segments_find_no_path() {
    let net = MemNet::new(1);
    let here = net.segment(LinkSpec::LAN);
    let there = net.segment(LinkSpec::LAN);
    let viewer = net.machine(MachineSpec::on(here, "192.168.1.10/24"));
    let host = net.machine(MachineSpec::on(there, "192.168.1.20/24"));
    let t0 = tokio::time::Instant::now();
    let mut pair = start_pair(env(&viewer), env(&host), (1, 2)).await;
    let (viewer_fail, host_fail) = both_fail(&mut pair).await;
    assert_eq!(viewer_fail, DirectFail::NoPath { heard: false });
    assert_eq!(host_fail, DirectFail::NoPath { heard: false });
    assert!(t0.elapsed() >= SAME_SITE_SCHEDULE.fail);
    assert!(t0.elapsed() < Duration::from_secs(4));

    let wire = net.wire();
    assert!(!wire.is_empty());
    assert!(
        wire.iter()
            .all(|w| w.fate == Fate::Unroutable && w.kind == WireKind::Probe)
    );
    for target in pair.viewer_offered.iter().chain(&pair.host_offered) {
        let requests = wire.iter().filter(|w| w.to == target.addr).count();
        assert!(requests <= MAX_REQUESTS_PER_TARGET, "{requests}");
    }
    for stats in [pair.viewer.stats(), pair.host.stats()] {
        assert!(!stats.heard && stats.validated == 0 && !stats.dialled);
    }
    sent_cleanly(&pair, [&viewer, &host]);
}

/// A host whose firewall blocks every inbound datagram (design §12.3 "host
/// `Blocked`"): its requests reach the viewer, which hears it and answers,
/// but no answer and no request gets in. The viewer fails having heard the
/// host; the host, having heard nothing.
#[tokio::test(start_paused = true)]
async fn a_blocked_host_is_heard_but_never_reached() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let viewer = net.machine(MachineSpec::on(lan, "192.168.1.10/24"));
    let host = net.machine(MachineSpec {
        inbound: InboundRule::Blocked,
        ..MachineSpec::on(lan, "192.168.1.20/24")
    });
    let mut pair = start_pair(env(&viewer), env(&host), (1, 2)).await;
    let (viewer_fail, host_fail) = both_fail(&mut pair).await;
    assert_eq!(viewer_fail, DirectFail::NoPath { heard: true });
    assert_eq!(host_fail, DirectFail::NoPath { heard: false });

    let host_ip = ip_of(&pair.host_offered);
    let wire = net.wire();
    assert!(
        wire.iter()
            .filter(|w| w.to.ip() == host_ip)
            .all(|w| w.fate == Fate::Filtered)
    );
    assert!(
        wire.iter()
            .filter(|w| w.from.ip() == host_ip)
            .all(|w| w.fate == Fate::Delivered)
    );
    assert!(pair.viewer.stats().punch.responses_sent > 0);
    assert_eq!(pair.host.stats().validated, 0);
    assert_eq!(pair.viewer.stats().validated, 0);
}

fn ip_of(offered: &[Candidate]) -> IpAddr {
    offered.first().expect("an offered candidate").addr.ip()
}

/// Stateful host firewalls (design §12.3 "host `Stateful` → Direct"): an
/// outbound probe opens the way, on the host alone and on both sides.
#[tokio::test(start_paused = true)]
async fn a_stateful_firewall_lets_the_punch_through() {
    for (viewer_rule, host_rule) in [
        (InboundRule::Open, InboundRule::Stateful),
        (InboundRule::Stateful, InboundRule::Stateful),
    ] {
        let net = MemNet::new(1);
        let lan = net.segment(LinkSpec::LAN);
        let viewer = net.machine(MachineSpec {
            inbound: viewer_rule,
            ..MachineSpec::on(lan, "192.168.1.10/24")
        });
        let host = net.machine(MachineSpec {
            inbound: host_rule,
            ..MachineSpec::on(lan, "192.168.1.20/24")
        });
        let mut pair = start_pair(env(&viewer), env(&host), (2, 1)).await;
        let (v, h) = both_established(&mut pair).await;
        assert!(v.route().same_site && h.route().same_site);
        let (mut viewer_stream, mut host_stream) = media_stream(&v, &h).await;
        let (sent, received) =
            within(60, transfer(&mut host_stream, &mut viewer_stream, 64 << 10)).await;
        assert_eq!(sent, received);
        sent_cleanly(&pair, [&viewer, &host]);
    }
}

/// ULAs on both sides (design §12.3 "ULA on both → an IPv6 route"): an
/// IPv6-only LAN connects over IPv6, every datagram leaving from an offered
/// ULA. With IPv4 beside the ULAs the pair connects too, with no refused
/// send either way.
#[tokio::test(start_paused = true)]
async fn ula_on_both_sides_gives_an_ipv6_route() {
    let (net, viewer, host) = one_segment(
        1,
        LinkSpec::LAN,
        "fd12:3456:789a:1::10/64",
        "fd12:3456:789a:1::20/64",
    );
    let mut pair = start_pair(env(&viewer), env(&host), (1, 2)).await;
    let (v, h) = both_established(&mut pair).await;
    for side in [&v, &h] {
        assert_eq!(
            side.route(),
            Route {
                same_site: true,
                ipv6: true
            }
        );
        assert_eq!(side.winner(), CandidateKind::Host);
    }
    let (mut viewer_stream, mut host_stream) = media_stream(&v, &h).await;
    let (sent, received) =
        within(60, transfer(&mut host_stream, &mut viewer_stream, 64 << 10)).await;
    assert_eq!(sent, received);
    let offered = [ip_of(&pair.viewer_offered), ip_of(&pair.host_offered)];
    assert!(offered.iter().all(IpAddr::is_ipv6));
    let wire = net.wire();
    assert!(
        wire.iter()
            .all(|w| offered.contains(&w.from.ip()) && w.fate == Fate::Delivered)
    );
    for stats in [pair.viewer.stats(), pair.host.stats()] {
        assert_eq!(stats.socket.v4_mapped_sends, 0);
        assert_eq!(stats.globals_offered, 0);
    }
    sent_cleanly(&pair, [&viewer, &host]);

    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let viewer =
        net.machine(MachineSpec::on(lan, "192.168.1.10/24").and(lan, "fd12:3456:789a:1::10/64"));
    let host =
        net.machine(MachineSpec::on(lan, "192.168.1.20/24").and(lan, "fd12:3456:789a:1::20/64"));
    let mut pair = start_pair(env(&viewer), env(&host), (2, 1)).await;
    assert_eq!(pair.viewer_offered.len(), 2);
    let (v, h) = both_established(&mut pair).await;
    assert!(v.route().same_site && h.route().same_site);
    assert_eq!(v.route().ipv6, h.route().ipv6);
    sent_cleanly(&pair, [&viewer, &host]);
}

/// Design §8.3 and §12.3 "no address → zero binds": a machine with only a
/// public address, or whose interface read fails, gives `NoAddresses`
/// after reading its interfaces and route sources once, and binds nothing.
#[tokio::test(start_paused = true)]
async fn no_address_in_scope_makes_no_bind() {
    let net = MemNet::new(1);
    let wan = net.segment(LinkSpec::LAN);
    for spec in [
        MachineSpec::on(wan, "81.2.69.142/24"),
        MachineSpec {
            fail_interfaces: true,
            ..MachineSpec::on(wan, "192.168.1.10/24")
        },
    ] {
        let machine = net.machine(spec);
        let counted = CountingEnv::new(machine.clone());
        let fail = DirectLink::start(params(TornectRole::Viewer, 1, 2), counted.clone())
            .await
            .expect_err("no address");
        assert_eq!(fail, DirectFail::NoAddresses);
        assert_eq!(counted.calls().binds, 0);
        assert!(counted.calls().interfaces == 1 && counted.calls().admit_loopback == 0);
        assert_eq!(machine.counters().binds, 0);
    }
}

/// A host whose bind fails (design §12.3 "host bind fails"): `Socket`,
/// after one bind call.
#[tokio::test(start_paused = true)]
async fn a_failed_bind_is_a_socket_failure_on_memnet() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let counted = CountingEnv::new(net.machine(MachineSpec {
        fail_bind: true,
        ..MachineSpec::on(lan, "192.168.1.20/24")
    }));
    let fail = DirectLink::start(params(TornectRole::Host, 2, 1), counted.clone())
        .await
        .expect_err("no socket");
    assert_eq!(fail, DirectFail::Socket);
    assert_eq!(counted.calls().binds, 1);
}

/// Decision M1-80 with `CountingEnv`: the same key makes no call at all.
#[tokio::test(start_paused = true)]
async fn the_same_key_makes_no_call() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let counted = CountingEnv::new(net.machine(MachineSpec::on(lan, "192.168.1.10/24")));
    let fail = DirectLink::start(params(TornectRole::Viewer, 3, 3), counted.clone())
        .await
        .expect_err("the same key");
    assert_eq!(fail, DirectFail::SameKey);
    assert_eq!(counted.calls(), EnvCalls::default());
}

/// Design §12.3 "a private remote outside our on-link prefixes in SameSite
/// scope → refused": two routed LANs with different private prefixes. Each
/// side refuses the other's candidate, so not one datagram is sent, and
/// both fail at once, having heard nothing.
#[tokio::test(start_paused = true)]
async fn a_private_remote_off_link_is_refused_in_same_site_scope() {
    let net = MemNet::new(1);
    let office = net.segment(LinkSpec::LAN);
    let lab = net.segment(LinkSpec::LAN);
    net.link(office, lab, LinkSpec::LAN);
    let viewer = net.machine(MachineSpec::on(office, "192.168.1.10/24"));
    let host = net.machine(MachineSpec::on(lab, "10.0.0.20/24"));
    let t0 = tokio::time::Instant::now();
    let mut pair = start_pair(env(&viewer), env(&host), (1, 2)).await;
    let (viewer_fail, host_fail) = both_fail(&mut pair).await;
    assert_eq!(viewer_fail, DirectFail::NoPath { heard: false });
    assert_eq!(host_fail, DirectFail::NoPath { heard: false });
    assert!(t0.elapsed() < SAME_SITE_SCHEDULE.fail);
    assert!(net.wire().is_empty());
    for stats in [pair.viewer.stats(), pair.host.stats()] {
        assert_eq!(stats.punch.candidates_refused, 1);
        assert_eq!(stats.punch.requests_sent, 0);
    }
}

/// On paused time the viewer's close returns within `CLOSE_WAIT` and ends
/// the host's connection; no further stream opens.
#[tokio::test(start_paused = true)]
async fn close_ends_the_connection_on_paused_time() {
    let (_net, viewer, host) = one_segment(1, LinkSpec::LAN, "192.168.1.10/24", "192.168.1.20/24");
    let mut pair = start_pair(env(&viewer), env(&host), (1, 2)).await;
    let (v, h) = both_established(&mut pair).await;
    let t0 = tokio::time::Instant::now();
    pair.viewer.close().await;
    assert!(t0.elapsed() <= CLOSE_WAIT);
    within(5, h.closed()).await;
    assert!(v.open_stream(1).await.is_err());
    assert!(!h.closed_by_crypto());
}

/// Design §6.5 "Pin refused by the host's TLS": the accepting host is
/// pinned to another device. The dialling viewer's handshake completes
/// (TLS 1.3 lets the client finish first) and then ends with the host's
/// alert; the host's link counts the refused handshake, establishes
/// nothing and records no dial failure of its own. A link whose pins
/// agree counts none.
#[tokio::test(start_paused = true)]
async fn a_handshake_the_accepting_pin_refuses_is_counted() {
    let mut seeds = [1u8, 2, 3];
    seeds.sort_by_key(|seed| pk(*seed));
    let [viewer_seed, other_seed, host_seed] = seeds;
    let (_net, viewer, host) = one_segment(1, LinkSpec::LAN, "192.168.1.10/24", "192.168.1.20/24");
    let (mut viewer_link, viewer_offered) = DirectLink::start(
        params(TornectRole::Viewer, viewer_seed, host_seed),
        env(&viewer),
    )
    .await
    .expect("the viewer's link");
    let (host_link, host_offered) =
        DirectLink::start(params(TornectRole::Host, host_seed, other_seed), env(&host))
            .await
            .expect("the host's link");
    host_link.add_remote(viewer_offered, Scope::SameSite);
    host_link.remote_done();
    viewer_link.add_remote(host_offered, Scope::SameSite);
    viewer_link.remote_done();
    let v = within(5, viewer_link.established())
        .await
        .expect("the viewer's handshake completes first");
    within(5, v.closed()).await;
    assert!(v.closed_by_crypto());
    let stats = host_link.stats();
    assert!(stats.handshakes_refused >= 1, "{stats:?}");
    assert!(!stats.established);
    assert_eq!(stats.dial_failed, None);
    assert_eq!(viewer_link.stats().handshakes_refused, 0);

    let mut pair = start_pair(env(&viewer), env(&host), (viewer_seed, host_seed)).await;
    let _ = both_established(&mut pair).await;
    assert_eq!(pair.host.stats().handshakes_refused, 0);
    assert_eq!(pair.viewer.stats().handshakes_refused, 0);
}

/// `next_news` gives the end of gathering first, then the connection, then
/// nothing more: after a final connection result it waits for good (both
/// ends of a pair on one segment, the connection's own wait included).
#[tokio::test(start_paused = true)]
async fn news_brings_the_batches_then_the_connection_once() {
    let (_net, viewer, host) = one_segment(1, LinkSpec::LAN, "192.168.1.10/24", "192.168.1.20/24");
    let (mut viewer_link, viewer_offered) =
        DirectLink::start(params(TornectRole::Viewer, 1, 2), env(&viewer))
            .await
            .expect("the viewer's link");
    let (mut host_link, host_offered) =
        DirectLink::start(params(TornectRole::Host, 2, 1), env(&host))
            .await
            .expect("the host's link");
    for link in [&mut viewer_link, &mut host_link] {
        assert!(matches!(
            within(1, link.next_news()).await,
            LinkNews::Local(LocalBatch::Done)
        ));
    }
    host_link.add_remote(viewer_offered, Scope::SameSite);
    host_link.remote_done();
    viewer_link.add_remote(host_offered, Scope::SameSite);
    viewer_link.remote_done();
    for link in [&mut viewer_link, &mut host_link] {
        let news = within(5, link.next_news()).await;
        assert!(matches!(&news, LinkNews::Connection(Ok(_))), "{news:?}");
    }
    for link in [&mut viewer_link, &mut host_link] {
        assert!(
            tokio::time::timeout(Duration::from_secs(30), link.next_news())
                .await
                .is_err(),
            "nothing after the connection"
        );
    }
}
