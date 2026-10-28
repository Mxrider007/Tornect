//! Step B8: the boxes and servers of a [`MemNet`] (design §12.4): each
//! mapping and filtering behaviour of [`NatBox`], hairpinning, port
//! preservation, forwards, the timeout, a firewall (`translate: false`), two
//! boxes in a row, [`MemStun`] and [`MemMapper`]. Paused time.

use std::num::NonZeroU16;

use super::*;
use crate::mapping::{MAP_LEASE, MapFail, MapProtocols, MapRequest, MapVia, renewal_delay};
use crate::stun::{StunReply, binding_request, parse_response};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

const PUBLIC: &str = "81.2.3.4";

/// A home LAN (1 ms) behind one box on an internet segment (10 ms): the
/// inside machine `192.168.1.10` with a socket at 50000, and two outside
/// machines, `64.0.0.1` and `64.0.0.2`, each with sockets at 3478 and 3479.
struct Lab {
    net: MemNet,
    home: Segment,
    internet: Segment,
    nat: MemNat,
    inside: MemHost,
    socket: Arc<MemUdp>,
    outside: Vec<[Arc<MemUdp>; 2]>,
}

impl Lab {
    fn new(nat: impl FnOnce(Segment, Segment) -> NatBox) -> Self {
        let net = MemNet::new(3);
        let home = net.segment(LinkSpec::LAN);
        let internet = net.segment(LinkSpec {
            latency: ms(10),
            loss: 0.0,
        });
        let nat = net.nat(nat(home, internet));
        let inside = net.machine(MachineSpec {
            dual_stack: false,
            ..MachineSpec::on(home, "192.168.1.10/24")
        });
        let socket = inside.bind_udp(Some(50_000)).expect("a socket");
        let outside = ["64.0.0.1/24", "64.0.0.2/24"]
            .iter()
            .map(|cidr| {
                let m = net.machine(MachineSpec {
                    dual_stack: false,
                    ..MachineSpec::on(internet, cidr)
                });
                [
                    m.bind_udp(Some(3478)).expect("a socket"),
                    m.bind_udp(Some(3479)).expect("a socket"),
                ]
            })
            .collect();
        Self {
            net,
            home,
            internet,
            nat,
            inside,
            socket,
            outside,
        }
    }

    /// Outside machine `m`'s socket `p` (0: 3478, 1: 3479) and its address.
    fn out(&self, m: usize, p: usize) -> (&MemUdp, SocketAddr) {
        let socket = &self.outside[m][p];
        let addr = SocketAddr::new(ip(&format!("64.0.0.{}", m + 1)), socket.port());
        (socket, addr)
    }

    /// The inside machine sends to outside socket (`m`, `p`); the source
    /// that socket sees.
    async fn out_to(&self, m: usize, p: usize) -> SocketAddr {
        let (socket, addr) = self.out(m, p);
        send(&self.socket, addr, b"out", None).expect("a send");
        let (from, _, bytes) = recv(socket).await;
        assert_eq!(bytes, b"out");
        from
    }

    /// Outside socket (`m`, `p`) sends to `to`; the fate.
    fn in_from(&self, m: usize, p: usize, to: SocketAddr) -> Fate {
        let (socket, _) = self.out(m, p);
        send(socket, to, b"in", None).expect("a send");
        self.net.wire().last().expect("a datagram").fate
    }
}

fn mapped(port: u16) -> SocketAddr {
    SocketAddr::new(ip(PUBLIC), port)
}

fn boxed(mapping: NatMapping, filtering: NatFiltering) -> impl FnOnce(Segment, Segment) -> NatBox {
    move |home, internet| NatBox {
        mapping,
        filtering,
        ..NatBox::home(home, internet, PUBLIC)
    }
}

/// RFC 4787 §4.1 endpoint-independent mapping: one external port for every
/// destination, the internal one kept (port preservation); a second inside
/// address on the same port gets another. Outbound takes one LAN hop and
/// one internet hop.
#[tokio::test(start_paused = true)]
async fn eim_keeps_one_port_for_every_destination() {
    let lab = Lab::new(boxed(NatMapping::Eim, NatFiltering::Apdf));
    let t0 = Instant::now();
    assert_eq!(lab.out_to(0, 0).await, mapped(50_000));
    assert_eq!(t0.elapsed(), ms(11));
    assert_eq!(lab.out_to(0, 1).await, mapped(50_000));
    assert_eq!(lab.out_to(1, 0).await, mapped(50_000));
    assert_eq!(
        lab.nat.flows(),
        [NatFlow {
            internal: at("192.168.1.10:50000"),
            external: 50_000
        }]
    );
    let other = lab.net.machine(MachineSpec {
        dual_stack: false,
        ..MachineSpec::on(lab.home, "192.168.1.11/24")
    });
    let socket = other.bind_udp(Some(50_000)).expect("a socket");
    let (out, addr) = lab.out(0, 0);
    send(&socket, addr, b"x", None).expect("a send");
    let (from, _, _) = recv(out).await;
    assert_eq!(from, mapped(30_000), "the port is taken: the next free one");
    let wire = lab.net.wire();
    assert!(wire.iter().all(|w| w.fate == Fate::Delivered));
    assert_eq!(
        wire[0].from,
        at("192.168.1.10:50000"),
        "the wire logs the inside source"
    );
    assert_eq!(wire[0].seen_from, Some(mapped(50_000)));
}

/// Address-dependent mapping: one port per destination address, whatever
/// its port.
#[tokio::test(start_paused = true)]
async fn adm_maps_once_per_destination_address() {
    let lab = Lab::new(boxed(NatMapping::Adm, NatFiltering::Apdf));
    assert_eq!(lab.out_to(0, 0).await, mapped(50_000));
    assert_eq!(lab.out_to(0, 1).await, mapped(50_000));
    assert_eq!(lab.out_to(1, 0).await, mapped(30_000));
    assert_eq!(lab.out_to(1, 1).await, mapped(30_000));
    assert_eq!(lab.nat.flows().len(), 2);
}

/// Address-and-port-dependent ("symmetric") mapping: one port per
/// destination address and port; only the first keeps the internal port.
/// Without port preservation, not even the first does.
#[tokio::test(start_paused = true)]
async fn apdm_maps_once_per_destination_address_and_port() {
    let lab = Lab::new(boxed(NatMapping::Apdm, NatFiltering::Apdf));
    assert_eq!(lab.out_to(0, 0).await, mapped(50_000));
    assert_eq!(lab.out_to(0, 1).await, mapped(30_000));
    assert_eq!(lab.out_to(1, 0).await, mapped(30_001));
    assert_eq!(
        lab.out_to(0, 0).await,
        mapped(50_000),
        "the same destination"
    );
    assert_eq!(lab.nat.flows().len(), 3);

    let lab = Lab::new(|home, internet| NatBox {
        port_preservation: false,
        ..NatBox::home(home, internet, PUBLIC)
    });
    assert_eq!(lab.out_to(0, 0).await, mapped(30_000));
}

/// Endpoint-independent filtering: once a mapping exists anyone reaches it;
/// before, nothing does (`NoMapping`).
#[tokio::test(start_paused = true)]
async fn eif_lets_anyone_in_at_a_mapping() {
    let lab = Lab::new(boxed(NatMapping::Eim, NatFiltering::Eif));
    assert_eq!(lab.in_from(1, 1, mapped(50_000)), Fate::NoMapping);
    lab.out_to(0, 0).await;
    for (m, p) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
        assert_eq!(lab.in_from(m, p, mapped(50_000)), Fate::Delivered);
        let (from, dst_ip, bytes) = recv(&lab.socket).await;
        assert_eq!(
            (from, dst_ip, bytes.as_slice()),
            (lab.out(m, p).1, Some(ip("192.168.1.10")), &b"in"[..])
        );
    }
    assert_eq!(
        lab.in_from(1, 1, mapped(50_001)),
        Fate::NoMapping,
        "another port"
    );
}

/// Address-dependent filtering: from an address the mapping sent to, any
/// port; from another address, `NatFiltered`.
#[tokio::test(start_paused = true)]
async fn adf_lets_in_the_addresses_sent_to() {
    let lab = Lab::new(boxed(NatMapping::Eim, NatFiltering::Adf));
    lab.out_to(0, 0).await;
    assert_eq!(lab.in_from(0, 0, mapped(50_000)), Fate::Delivered);
    assert_eq!(lab.in_from(0, 1, mapped(50_000)), Fate::Delivered);
    assert_eq!(lab.in_from(1, 0, mapped(50_000)), Fate::NatFiltered);
    lab.out_to(1, 1).await;
    assert_eq!(lab.in_from(1, 0, mapped(50_000)), Fate::Delivered);
}

/// Address-and-port-dependent filtering: only from the address and port
/// the mapping sent to.
#[tokio::test(start_paused = true)]
async fn apdf_lets_in_only_the_address_and_port_sent_to() {
    let lab = Lab::new(boxed(NatMapping::Eim, NatFiltering::Apdf));
    lab.out_to(0, 0).await;
    assert_eq!(lab.in_from(0, 0, mapped(50_000)), Fate::Delivered);
    assert_eq!(lab.in_from(0, 1, mapped(50_000)), Fate::NatFiltered);
    assert_eq!(lab.in_from(1, 0, mapped(50_000)), Fate::NatFiltered);
}

/// A mapping and each destination it admits live 30 s after their last
/// datagram: an admitted inbound one keeps the mapping alive; 30 s of
/// silence end it, and the next outbound datagram makes a new one.
#[tokio::test(start_paused = true)]
async fn a_mapping_lives_thirty_seconds_after_its_last_datagram() {
    let lab = Lab::new(boxed(NatMapping::Eim, NatFiltering::Apdf));
    lab.out_to(0, 0).await;
    tokio::time::sleep(NAT_TIMEOUT - ms(20)).await;
    assert_eq!(lab.in_from(0, 0, mapped(50_000)), Fate::Delivered);
    recv(&lab.socket).await;
    tokio::time::sleep(NAT_TIMEOUT - ms(20)).await;
    assert_eq!(lab.nat.flows().len(), 1, "the inbound datagram kept it");
    assert_eq!(
        lab.in_from(0, 0, mapped(50_000)),
        Fate::NatFiltered,
        "the destination's own entry is older than 30 s"
    );
    tokio::time::sleep(NAT_TIMEOUT).await;
    assert!(lab.nat.flows().is_empty());
    assert_eq!(lab.in_from(0, 0, mapped(50_000)), Fate::NoMapping);
    assert_eq!(lab.out_to(0, 0).await, mapped(50_000));
}

/// Two machines behind one box reach each other at their mappings only
/// when it hairpins; otherwise the datagram dies at the box. Hairpinned,
/// it comes in from the sender's mapping, filtered as from outside, at
/// LAN speed.
#[tokio::test(start_paused = true)]
async fn only_a_hairpinning_box_loops_back_to_its_public_address() {
    for hairpin in [false, true] {
        let lab = Lab::new(|home, internet| NatBox {
            hairpin,
            ..NatBox::home(home, internet, PUBLIC)
        });
        let other = lab.net.machine(MachineSpec {
            dual_stack: false,
            ..MachineSpec::on(lab.home, "192.168.1.11/24")
        });
        let peer = other.bind_udp(Some(50_001)).expect("a socket");
        lab.out_to(0, 0).await;
        send(&peer, lab.out(0, 0).1, b"out", None).expect("a send");
        recv(&lab.outside[0][0]).await;
        // Each one's mapping: 50000 and 50001.
        send(&lab.socket, mapped(50_001), b"hp", None).expect("a send");
        let first = *lab.net.wire().last().expect("a datagram");
        if !hairpin {
            assert_eq!(first.fate, Fate::NoHairpin);
            continue;
        }
        assert_eq!(first.fate, Fate::NatFiltered, "50001 never sent to 50000");
        send(&peer, mapped(50_000), b"hp", None).expect("a send");
        let t0 = Instant::now();
        send(&lab.socket, mapped(50_001), b"hp", None).expect("a send");
        let (from, dst_ip, _) = recv(&peer).await;
        assert_eq!(from, mapped(50_000));
        assert_eq!(dst_ip, Some(ip("192.168.1.11")));
        assert_eq!(t0.elapsed(), ms(2));
    }
}

/// A static forward lets everyone in at its port, and its inside address
/// leaves from that port.
#[tokio::test(start_paused = true)]
async fn a_forward_lets_everyone_in() {
    let lab = Lab::new(|home, internet| NatBox {
        forwards: vec![(6000, at("192.168.1.10:50000"))],
        ..NatBox::home(home, internet, PUBLIC)
    });
    assert_eq!(lab.in_from(1, 1, mapped(6000)), Fate::Delivered);
    let (from, _, _) = recv(&lab.socket).await;
    assert_eq!(from, lab.out(1, 1).1);
    assert_eq!(lab.out_to(0, 0).await, mapped(6000));
    assert_eq!(lab.nat.forwards(), [(6000, at("192.168.1.10:50000"))]);
}

/// `translate: false`: a stateful IPv6 firewall keeps addresses and ports;
/// nothing gets in before an inside address sent out, then only from the
/// address and port it sent to. It carries no IPv4.
#[tokio::test(start_paused = true)]
async fn a_firewall_keeps_addresses_and_admits_only_replies() {
    let net = MemNet::new(1);
    let home = net.segment(LinkSpec::LAN);
    let internet = net.segment(LinkSpec {
        latency: ms(10),
        loss: 0.0,
    });
    let fw = net.nat(NatBox::firewall(home, internet));
    let inside =
        net.machine(MachineSpec::on(home, "2a01:4f8:1:1::10/64").and(home, "192.168.1.10/24"));
    let outside = net.machine(MachineSpec::on(internet, "2a02:8:2:2::20/64"));
    let a = inside.bind_udp(Some(50_000)).expect("a socket");
    let b = outside.bind_udp(Some(50_000)).expect("a socket");
    let b2 = outside.bind_udp(Some(50_001)).expect("a socket");
    let a_addr = at("[2a01:4f8:1:1::10]:50000");
    let b_addr = at("[2a02:8:2:2::20]:50000");

    send(&b, a_addr, b"early", None).expect("a send");
    assert_eq!(net.wire().last().unwrap().fate, Fate::NoMapping);
    send(&a, b_addr, b"out", None).expect("a send");
    let (from, _, _) = recv(&b).await;
    assert_eq!(from, a_addr, "no translation");
    send(&b, a_addr, b"reply", None).expect("a send");
    let (from, dst_ip, _) = recv(&a).await;
    assert_eq!((from, dst_ip), (b_addr, Some(ip("2a01:4f8:1:1::10"))));
    send(&b2, a_addr, b"other port", None).expect("a send");
    assert_eq!(net.wire().last().unwrap().fate, Fate::NatFiltered);
    assert_eq!(fw.flows().len(), 1);

    let v4 = to_socket_family(at("64.0.0.1:3478"), true);
    send(&a, v4, b"v4", None).expect("a send");
    assert_eq!(net.wire().last().unwrap().fate, Fate::Unroutable);
}

/// Two boxes in a row (a home router whose outside is a carrier NAT's
/// inside, `100.64/10`): outbound is translated twice, and the answer finds
/// its way back through both; the carrier's public address is what the
/// far end sees.
#[tokio::test(start_paused = true)]
async fn two_boxes_in_a_row_translate_twice() {
    let net = MemNet::new(1);
    let home = net.segment(LinkSpec::LAN);
    let isp = net.segment(LinkSpec {
        latency: ms(3),
        loss: 0.0,
    });
    let internet = net.segment(LinkSpec {
        latency: ms(10),
        loss: 0.0,
    });
    let _home_nat = net.nat(NatBox {
        public: "100.64.7.2".parse().unwrap(),
        ..NatBox::home(home, isp, PUBLIC)
    });
    let _cgn = net.nat(NatBox::home(isp, internet, "81.9.9.9"));
    let inside = net.machine(MachineSpec::on(home, "192.168.1.10/24"));
    let far = net.machine(MachineSpec::on(internet, "64.0.0.1/24"));
    let a = inside.bind_udp(Some(50_000)).expect("a socket");
    let b = far.bind_udp(Some(3478)).expect("a socket");
    let t0 = Instant::now();
    send(
        &a,
        to_socket_family(at("64.0.0.1:3478"), true),
        b"out",
        None,
    )
    .expect("a send");
    let (from, _, _) = recv(&b).await;
    assert_eq!(canon(from), at("81.9.9.9:50000"));
    assert_eq!(t0.elapsed(), ms(14));
    send(&b, from, b"back", None).expect("a send");
    let (from, _, bytes) = recv(&a).await;
    assert_eq!(
        (canon(from), bytes.as_slice()),
        (at("64.0.0.1:3478"), &b"back"[..])
    );
}

/// A box routes between the segments behind it, untranslated.
#[tokio::test(start_paused = true)]
async fn a_box_routes_between_its_inside_segments() {
    let net = MemNet::new(1);
    let one = net.segment(LinkSpec::LAN);
    let two = net.segment(LinkSpec::LAN);
    let internet = net.segment(LinkSpec::LAN);
    let _nat = net.nat(NatBox {
        inside: vec![one, two],
        ..NatBox::home(one, internet, PUBLIC)
    });
    let a = net.machine(MachineSpec::on(one, "192.168.1.10/24"));
    let b = net.machine(MachineSpec::on(two, "192.168.2.20/24"));
    let sa = a.bind_udp(None).expect("a socket");
    let sb = b.bind_udp(None).expect("a socket");
    let to = to_socket_family(SocketAddr::new(ip("192.168.2.20"), sb.port()), true);
    send(&sa, to, b"x", None).expect("a send");
    let (from, _, _) = recv(&sb).await;
    assert_eq!(canon(from), SocketAddr::new(ip("192.168.1.10"), sa.port()));
}

/// A spoofing socket's datagrams carry the forged source, which the
/// receiver sees and answers.
#[tokio::test(start_paused = true)]
async fn a_spoofing_socket_forges_its_source() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let a = net.machine(MachineSpec::on(lan, "192.168.1.10/24"));
    let b = net.machine(MachineSpec::on(lan, "192.168.1.20/24"));
    let sa = a.bind_udp(None).expect("a socket");
    let sb = b.bind_udp(None).expect("a socket");
    let forged = at("192.168.1.99:4242");
    sa.spoof_as(Some(forged));
    let to = to_socket_family(SocketAddr::new(ip("192.168.1.20"), sb.port()), true);
    send(&sa, to, b"forged", None).expect("a send");
    let (from, _, _) = recv(&sb).await;
    assert_eq!(canon(from), forged);
    assert_eq!(net.wire()[0].from, forged);
    assert_eq!(a.counters().bad_source, 0);
}

/// A STUN client's view of one server: its answer to one Binding request
/// from `socket`.
async fn ask(socket: &MemUdp, server: SocketAddr) -> Option<StunReply> {
    let txid = [7; 12];
    send(
        socket,
        to_socket_family(server, socket.dual_stack()),
        &binding_request(&txid),
        None,
    )
    .expect("a send");
    let answer = tokio::time::timeout(Duration::from_secs(1), next(socket))
        .await
        .ok()?;
    parse_response(&answer.2, &txid)
}

/// `MemStun`: honest, it answers the source as the boxes on the way made
/// it; lying, a fixed address; silent, nothing. It notes each request.
#[tokio::test(start_paused = true)]
async fn mem_stun_answers_honestly_lies_or_keeps_silent() {
    let lab = Lab::new(boxed(NatMapping::Eim, NatFiltering::Apdf));
    let stun = MemStun::start(&lab.net, lab.internet, "64.0.0.10/24", StunMode::Honest);
    assert_eq!(stun.entry(), "64.0.0.10:3478");
    assert_eq!(
        ask(&lab.socket, stun.addr()).await,
        Some(StunReply::Mapped(mapped(50_000)))
    );
    stun.set_mode(StunMode::Lying(at("81.0.0.1:1234")));
    assert_eq!(
        ask(&lab.socket, stun.addr()).await,
        Some(StunReply::Mapped(at("81.0.0.1:1234")))
    );
    stun.set_mode(StunMode::Silent);
    assert_eq!(ask(&lab.socket, stun.addr()).await, None);
    let heard = stun.heard();
    assert_eq!(heard.len(), 3);
    assert!(heard.iter().all(|h| h.from == mapped(50_000)));
}

/// Names resolve from the network's table; others are `NotFound`.
#[tokio::test(start_paused = true)]
async fn names_resolve_from_the_networks_table() {
    let lab = Lab::new(boxed(NatMapping::Eim, NatFiltering::Apdf));
    lab.net.name("stun.test", &[ip("64.0.0.10")]);
    let found = lab.inside.resolve("stun.test", 3478).await.expect("a name");
    assert_eq!(found, [at("64.0.0.10:3478")]);
    let missing = lab.inside.resolve("other.test", 3478).await;
    assert_eq!(
        missing.expect_err("no such name").kind(),
        io::ErrorKind::NotFound
    );
}

/// A home with a router: the inside machine's gateway is the box's inside
/// address.
fn routed(mode: Option<MapperMode>) -> Lab {
    Lab::new(|home, internet| NatBox {
        lan: Some("192.168.1.1".parse().unwrap()),
        router: mode,
        ..NatBox::home(home, internet, PUBLIC)
    })
}

fn map_request(protocols: MapProtocols) -> MapRequest {
    MapRequest {
        gateway: "192.168.1.1".parse().unwrap(),
        client: "192.168.1.10".parse().unwrap(),
        internal_port: NonZeroU16::new(50_000).unwrap(),
        lease: MAP_LEASE,
        protocols,
        deadline: (Instant::now() + ms(1500)).into_std(),
    }
}

/// `MapperMode::Ok`: one LAN round trip; the lease asked for at the public
/// address and the internal port, a forward that lets everyone in; a
/// renewal asks 600 s again; the release removes the forward. Dropped, a
/// mapping releases itself through the machine's tracker.
#[tokio::test(start_paused = true)]
async fn mem_mapper_ok_installs_a_forward_and_releases_it() {
    let lab = routed(Some(MapperMode::Ok));
    let mapper = lab.inside.mapper();
    let t0 = Instant::now();
    let mut mapping = mapper
        .map(map_request(MapProtocols::ALL))
        .await
        .expect("a mapping");
    assert_eq!(t0.elapsed(), ms(2));
    assert_eq!(mapping.external, "81.2.3.4:50000".parse().unwrap());
    assert_eq!((mapping.via, mapping.granted), (MapVia::Pcp, MAP_LEASE));
    assert_eq!(lab.nat.forwards(), [(50_000, at("192.168.1.10:50000"))]);
    assert_eq!(lab.in_from(1, 1, mapped(50_000)), Fate::Delivered);
    recv(&lab.socket).await;
    assert_eq!(mapping.renew().await, Ok(MAP_LEASE));
    mapping.release().await;
    assert!(lab.nat.forwards().is_empty());
    assert_eq!(lab.in_from(1, 1, mapped(50_000)), Fate::NoMapping);
    let log = lab.nat.router_log();
    assert!(
        matches!(
            log.as_slice(),
            [
                RouterSeen::Map { lease, internal_port: 50_000, .. },
                RouterSeen::Renew { lease: renewed, .. },
                RouterSeen::Release { .. },
            ] if *lease == MAP_LEASE && *renewed == MAP_LEASE
        ),
        "{log:?}"
    );

    let dropped = mapper
        .map(map_request(MapProtocols::ALL))
        .await
        .expect("a mapping");
    assert_eq!(lab.nat.forwards().len(), 1);
    drop(dropped);
    let tracker = mapper.release_tracker().expect("a tracker");
    assert_eq!(tracker.running(), 1);
    assert!(tracker.wait(Duration::from_secs(1)).await);
    assert!(lab.nat.forwards().is_empty());
}

/// `Grant(120 s)`: the mapping says 120 s; kept renewed, it is renewed every
/// 60 s with 600 s asked each time, and over ten minutes the forward never
/// lapses. Not renewed, it lapses at 120 s.
#[tokio::test(start_paused = true)]
async fn a_short_grant_renews_at_half_and_never_lapses() {
    let grant = Duration::from_secs(120);
    let lab = routed(Some(MapperMode::Grant(grant)));
    let mapper = lab.inside.mapper();
    let mut mapping = mapper
        .map(map_request(MapProtocols::ALL))
        .await
        .expect("a mapping");
    assert_eq!(mapping.granted, grant);
    assert_eq!(renewal_delay(grant), Duration::from_secs(60));
    let granted_at = Instant::now();
    {
        let renewing = mapping.keep_renewed();
        tokio::pin!(renewing);
        for _ in 0..600 {
            tokio::select! {
                _ = &mut renewing => unreachable!(),
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
            assert_eq!(
                lab.nat.forwards().len(),
                1,
                "lapsed at {:?}",
                granted_at.elapsed()
            );
        }
    }
    let renewals: Vec<_> = lab
        .nat
        .router_log()
        .iter()
        .filter_map(|seen| match seen {
            RouterSeen::Renew { at, lease } => Some((*at - granted_at, *lease)),
            _ => None,
        })
        .collect();
    assert_eq!(renewals.len(), 9, "{renewals:?}");
    for (n, (at, lease)) in renewals.iter().enumerate() {
        // Each renewal waits 60 s from the last answer, and reaches the
        // router one LAN hop later.
        let n = u32::try_from(n).unwrap();
        assert_eq!(*at, Duration::from_secs(60) * (n + 1) + ms(1) * (2 * n + 1));
        assert_eq!(*lease, MAP_LEASE);
    }
    drop(mapping);

    let lab = routed(Some(MapperMode::Grant(grant)));
    let lapsing = lab
        .inside
        .mapper()
        .map(map_request(MapProtocols::ALL))
        .await
        .expect("a mapping");
    tokio::time::sleep(grant - ms(5)).await;
    assert_eq!(lab.nat.forwards().len(), 1);
    tokio::time::sleep(ms(5)).await;
    assert!(lab.nat.forwards().is_empty(), "not renewed: lapsed");
    drop(lapsing);
}

/// `Lie`: the forward is installed, but the mapping names the lie (a
/// router behind another NAT). `Refuse` and `PermanentOnly` map nothing; a
/// router that is off answers nothing until the deadline; no box at the
/// gateway, or no protocol, is `NoGateway` at once. No request asks for a
/// lease of 0.
#[tokio::test(start_paused = true)]
async fn mem_mapper_lies_refuses_or_stays_silent() {
    let lab = routed(Some(MapperMode::Lie("10.0.0.1".parse().unwrap())));
    let mapping = lab
        .inside
        .mapper()
        .map(map_request(MapProtocols::ALL))
        .await
        .expect("a mapping");
    assert_eq!(mapping.external, "10.0.0.1:50000".parse().unwrap());
    assert_eq!(lab.nat.forwards().len(), 1);
    mapping.release().await;

    for (mode, fail) in [
        (MapperMode::Refuse, MapFail::Refused),
        (MapperMode::PermanentOnly, MapFail::PermanentOnly),
    ] {
        let lab = routed(Some(mode));
        let got = lab
            .inside
            .mapper()
            .map(map_request(MapProtocols::ALL))
            .await;
        assert_eq!(got.expect_err("no mapping"), fail);
        assert!(lab.nat.forwards().is_empty());
        let log = lab.nat.router_log();
        assert_eq!(log.len(), 1);
        assert!(matches!(log[0], RouterSeen::Map { lease, .. } if lease == MAP_LEASE));
    }

    let lab = routed(None);
    let t0 = Instant::now();
    let got = lab
        .inside
        .mapper()
        .map(map_request(MapProtocols::ALL))
        .await;
    assert_eq!(got.expect_err("silence"), MapFail::Timeout);
    assert_eq!(t0.elapsed(), ms(1500));
    assert!(lab.nat.router_log().is_empty());

    let lab = routed(Some(MapperMode::Ok));
    let t0 = Instant::now();
    let none = lab
        .inside
        .mapper()
        .map(map_request(MapProtocols::NONE))
        .await;
    assert_eq!(none.expect_err("no protocol"), MapFail::NoGateway);
    let mut elsewhere = map_request(MapProtocols::ALL);
    elsewhere.gateway = "192.168.9.1".parse().unwrap();
    let got = lab.inside.mapper().map(elsewhere).await;
    assert_eq!(got.expect_err("no box there"), MapFail::NoGateway);
    assert_eq!(t0.elapsed(), Duration::ZERO);
    assert!(lab.nat.router_log().is_empty());
}

/// A machine's gateway reaches its interface read.
#[tokio::test(start_paused = true)]
async fn a_gateway_reaches_the_interface_read() {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec::LAN);
    let m = net.machine(MachineSpec::on(lan, "192.168.1.10/24").gateway("192.168.1.1"));
    let read = m.interfaces().await.expect("a read");
    assert_eq!(read[0].gateway_v4, Some("192.168.1.1".parse().unwrap()));
}
