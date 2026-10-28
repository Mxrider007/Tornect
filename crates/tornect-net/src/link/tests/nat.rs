//! A link behind an in-memory NAT whose router grants short leases (design
//! §7.4 "Renewal", §12.4 "home, mapper `Grant(120 s)` × home: renewal at
//! 60 s; the mapping survives a 10-minute session"). The session half of
//! that row (mapping within the head start, the host's connection to the
//! mapped address, the release at the end) runs with both FSMs in
//! `tornect-session`; the ten minutes are the link's, here.

use super::*;

use tokio::time::Instant;

use crate::gather::GatherConfig;
use crate::mapping::{MAP_LEASE, MapProtocols};
use crate::mem::{
    Fate, LinkSpec, MachineSpec, MapperMode, MemNet, NatBox, NatFiltering, NatMapping, RouterSeen,
    WireKind,
};

/// The public address of the viewer's router.
const PUBLIC: &str = "81.2.3.4";

/// What the router grants, whatever it is asked.
const GRANT: Duration = Duration::from_secs(120);

/// Internet-scope parameters of `me` (device `mine`) toward device `peer`.
fn internet(me: TornectRole, mine: u8, peer: u8, map: MapProtocols) -> DirectParams {
    DirectParams {
        scope: Scope::Internet,
        gather: GatherConfig {
            map,
            ..GatherConfig::default()
        },
        ..params(me, mine, peer)
    }
}

/// A link's candidates until its gathering is over.
async fn gathered(link: &mut DirectLink, mut offered: Vec<Candidate>) -> Vec<Candidate> {
    loop {
        match within(10, link.next_local()).await {
            LocalBatch::More(more) => offered.extend(more),
            LocalBatch::Done => return offered,
        }
    }
}

/// The connection, past the checklist's early-failure advice.
async fn connected(link: &mut DirectLink) -> Established {
    loop {
        match within(10, link.established()).await {
            Ok(conn) => return conn,
            Err(DirectFail::NoPath { .. }) => {}
            Err(fail) => panic!("no connection: {fail}"),
        }
    }
}

/// 4 KiB each way on the open media stream, every byte `round`: the
/// connection still carries data.
async fn exchange(viewer: &mut QuicStream, host: &mut QuicStream, round: u8) {
    const LEN: usize = 4 << 10;
    let sent = vec![round; LEN];
    let mut got = vec![0; LEN];
    viewer.write_all(&sent).await.expect("a write");
    host.read_exact(&mut got).await.expect("a read");
    assert_eq!(got, sent);
    host.write_all(&sent).await.expect("a write");
    viewer.read_exact(&mut got).await.expect("a read");
    assert_eq!(got, sent);
}

/// The viewer behind a home router (symmetric mapping and filtering, no
/// port preservation, so nothing but the router's forward lets the host
/// in) whose router grants 120 s; the host public. Both seed orders (each
/// side dials once). The viewer's link maps its port, offers the mapped
/// address, and the host's connection runs to it. For ten minutes the
/// link renews the mapping every 60 s, asking 600 s each time; the forward
/// never lapses, every datagram of the viewer still reaches the host from
/// the mapped address, and every minute the media stream carries 4 KiB
/// each way. The link's close releases the mapping.
#[tokio::test(start_paused = true)]
async fn a_short_grant_is_renewed_through_a_ten_minute_link() {
    for (viewer_seed, host_seed) in [(1, 2), (2, 1)] {
        let net = MemNet::new(7);
        let home = net.segment(LinkSpec::LAN);
        let wide = net.segment(LinkSpec {
            latency: Duration::from_millis(10),
            loss: 0.0,
        });
        let nat = net.nat(NatBox {
            lan: Some("192.168.1.1".parse().unwrap()),
            mapping: NatMapping::Apdm,
            filtering: NatFiltering::Apdf,
            port_preservation: false,
            router: Some(MapperMode::Grant(GRANT)),
            ..NatBox::home(home, wide, PUBLIC)
        });
        let viewer_machine =
            net.machine(MachineSpec::on(home, "192.168.1.10/24").gateway("192.168.1.1"));
        let host_machine = net.machine(MachineSpec::on(wide, "82.2.3.4/24"));
        let host_ip: IpAddr = "82.2.3.4".parse().unwrap();

        let (mut viewer, from_viewer) = DirectLink::start(
            internet(
                TornectRole::Viewer,
                viewer_seed,
                host_seed,
                MapProtocols::ALL,
            ),
            Arc::new(viewer_machine.clone()),
        )
        .await
        .expect("the viewer's link");
        let (mut host, from_host) = DirectLink::start(
            internet(
                TornectRole::Host,
                host_seed,
                viewer_seed,
                MapProtocols::NONE,
            ),
            Arc::new(host_machine.clone()),
        )
        .await
        .expect("the host's link");
        let from_viewer = gathered(&mut viewer, from_viewer).await;
        let from_host = gathered(&mut host, from_host).await;
        let mapped = from_viewer
            .iter()
            .find(|c| c.kind == CandidateKind::Mapped)
            .expect("the viewer offers its mapping")
            .addr;
        assert_eq!(mapped.ip().to_string(), PUBLIC);
        assert_eq!(nat.forwards().len(), 1);
        host.add_remote(from_viewer, Scope::Internet);
        host.remote_done();
        viewer.add_remote(from_host, Scope::Internet);
        viewer.remote_done();
        let (v, h) = tokio::join!(connected(&mut viewer), connected(&mut host));
        assert_eq!(h.winner(), CandidateKind::Mapped);
        assert_eq!(v.winner(), CandidateKind::Host);
        let (mut viewer_stream, mut host_stream) = media_stream(&v, &h).await;
        within(10, exchange(&mut viewer_stream, &mut host_stream, 0)).await;
        let t0 = Instant::now();
        for minute in 1..=10 {
            tokio::time::sleep(Duration::from_secs(60)).await;
            assert_eq!(nat.forwards().len(), 1, "lapsed by minute {minute}");
            within(10, exchange(&mut viewer_stream, &mut host_stream, minute)).await;
        }

        let late = t0 + Duration::from_secs(540);
        let from_viewer_late: Vec<_> = net
            .wire()
            .into_iter()
            .filter(|w| w.at >= late && w.to.ip() == host_ip)
            .collect();
        assert!(!from_viewer_late.is_empty());
        for w in &from_viewer_late {
            assert_eq!(w.fate, Fate::Delivered, "{w:?}");
            assert_eq!(w.seen_from, Some(mapped), "{w:?}");
        }
        let renewals: Vec<(Instant, Duration)> = nat
            .router_log()
            .iter()
            .filter_map(|seen| match seen {
                RouterSeen::Renew { at, lease } => Some((*at, *lease)),
                _ => None,
            })
            .collect();
        assert!(renewals.len() >= 10, "{renewals:?}");
        assert!(renewals.iter().all(|(_, lease)| *lease == MAP_LEASE));
        for pair in renewals.windows(2) {
            let gap = pair[1].0 - pair[0].0;
            assert!(
                gap >= Duration::from_secs(60) && gap <= Duration::from_millis(60_010),
                "{gap:?}"
            );
        }

        drop((v, h));
        viewer.close().await;
        host.close().await;
        let tracker = viewer_machine
            .mapper()
            .release_tracker()
            .expect("a tracker");
        assert!(tracker.wait(Duration::from_secs(1)).await);
        assert!(nat.forwards().is_empty());
        assert!(
            matches!(
                nat.router_log().as_slice(),
                [RouterSeen::Map { lease, .. }, .., RouterSeen::Release { .. }] if *lease == MAP_LEASE
            ),
            "{:?}",
            nat.router_log()
        );
    }
}

/// Two instances on one computer behind its router, in internet scope
/// (decision M1-82's deviation from design §12.5): each link refuses the
/// other's host candidate as one of its own addresses, so only the router
/// can join them. Each maps its port and offers the mapping. A router that
/// hairpins loops each probe back in from the sender's mapping, which is
/// not an address of this computer: both validate the other's mapping and
/// connect on the internet route through it. A router that does not
/// hairpin drops every probe at the box: neither side hears anything, and
/// no address of this computer is ever probed.
#[tokio::test(start_paused = true)]
async fn two_links_on_one_machine_meet_only_through_a_hairpinning_router() {
    for hairpin in [true, false] {
        let net = MemNet::new(7);
        let home = net.segment(LinkSpec::LAN);
        let wide = net.segment(LinkSpec {
            latency: Duration::from_millis(10),
            loss: 0.0,
        });
        let nat = net.nat(NatBox {
            lan: Some("192.168.1.1".parse().unwrap()),
            hairpin,
            router: Some(MapperMode::Ok),
            ..NatBox::home(home, wide, PUBLIC)
        });
        let machine = net.machine(MachineSpec::on(home, "192.168.1.10/24").gateway("192.168.1.1"));
        let machine_ip: IpAddr = "192.168.1.10".parse().unwrap();

        let (mut viewer, from_viewer) = DirectLink::start(
            internet(TornectRole::Viewer, 1, 2, MapProtocols::ALL),
            Arc::new(machine.clone()),
        )
        .await
        .expect("the viewer's link");
        let (mut host, from_host) = DirectLink::start(
            internet(TornectRole::Host, 2, 1, MapProtocols::ALL),
            Arc::new(machine.clone()),
        )
        .await
        .expect("the host's link");
        let from_viewer = gathered(&mut viewer, from_viewer).await;
        let from_host = gathered(&mut host, from_host).await;
        for offered in [&from_viewer, &from_host] {
            assert_eq!(offered.len(), 2, "{offered:?}");
            assert!(
                offered
                    .iter()
                    .any(|c| c.kind == CandidateKind::Host && c.addr.ip() == machine_ip)
            );
            assert!(
                offered
                    .iter()
                    .any(|c| c.kind == CandidateKind::Mapped && c.addr.ip().to_string() == PUBLIC)
            );
        }
        assert_eq!(nat.forwards().len(), 2);
        host.add_remote(from_viewer, Scope::Internet);
        host.remote_done();
        viewer.add_remote(from_host, Scope::Internet);
        viewer.remote_done();

        if hairpin {
            let (v, h) = tokio::join!(connected(&mut viewer), connected(&mut host));
            for side in [&v, &h] {
                assert_eq!(
                    side.route(),
                    Route {
                        same_site: false,
                        ipv6: false
                    }
                );
                assert_eq!(side.winner(), CandidateKind::Mapped);
            }
            let (mut viewer_stream, mut host_stream) = media_stream(&v, &h).await;
            within(10, exchange(&mut viewer_stream, &mut host_stream, 1)).await;
            drop((v, h));
            let wire = net.wire();
            assert!(wire.iter().any(|w| w.kind == WireKind::Probe));
            for w in wire.iter().filter(|w| w.fate == Fate::Delivered) {
                let seen = w.seen_from.expect("a delivered datagram's source");
                assert_eq!(seen.ip().to_string(), PUBLIC, "{w:?}");
            }
        } else {
            let (v, h) = within(10, async {
                tokio::join!(viewer.established(), host.established())
            })
            .await;
            assert_eq!(
                v.expect_err("no path for the viewer"),
                DirectFail::NoPath { heard: false }
            );
            assert_eq!(
                h.expect_err("no path for the host"),
                DirectFail::NoPath { heard: false }
            );
            let wire = net.wire();
            assert!(!wire.is_empty());
            assert!(
                wire.iter()
                    .all(|w| w.kind == WireKind::Probe && w.fate == Fate::NoHairpin),
                "{wire:?}"
            );
        }
        assert!(net.wire().iter().all(|w| w.to.ip() != machine_ip));
        for stats in [viewer.stats(), host.stats()] {
            assert_eq!(stats.punch.candidates_refused, 1, "{stats:?}");
            assert_eq!(stats.established, hairpin, "{stats:?}");
        }
        viewer.close().await;
        host.close().await;
    }
}
