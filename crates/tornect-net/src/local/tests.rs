use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use netdev::interface::ipv6_addr_flags::Ipv6AddrFlags;
use netdev::ipnet::{Ipv4Net, Ipv6Net};

/// The flags of an interface that is up and running.
fn up_flags() -> u32 {
    #[cfg(unix)]
    {
        (netdev::interface::flags::IFF_UP | netdev::interface::flags::IFF_RUNNING) as u32
    }
    #[cfg(windows)]
    {
        netdev::interface::flags::IFF_UP
    }
}

fn p2p_flag() -> u32 {
    #[cfg(unix)]
    {
        netdev::interface::flags::IFF_POINTOPOINT as u32
    }
    #[cfg(windows)]
    {
        netdev::interface::flags::IFF_POINTOPOINT
    }
}

fn iface(name: &str, if_type: InterfaceType) -> netdev::Interface {
    let mut i = netdev::Interface::dummy();
    i.name = name.to_owned();
    i.if_type = if_type;
    i.flags = up_flags();
    i
}

fn described(name: &str, if_type: InterfaceType, description: &str) -> netdev::Interface {
    let mut i = iface(name, if_type);
    i.description = Some(description.to_owned());
    i.friendly_name = Some("Ethernet 2".to_owned());
    i
}

/// Design §7.1 "IfaceKind", with the cases of §12.1.
#[test]
fn interfaces_are_classed_by_type_flags_and_names() {
    use IfaceKind::*;
    use InterfaceType as T;
    let mut p2p_ethernet = iface("ptp0", T::Ethernet);
    p2p_ethernet.flags |= p2p_flag();
    for (i, want) in [
        (iface("lo", T::Loopback), Loopback),
        (iface("eth0", T::Ethernet), Physical),
        (iface("enp3s0", T::GigabitEthernet), Physical),
        (iface("wlan0", T::Wireless80211), Physical),
        (iface("wwan0", T::Wwan), Physical),
        (iface("rmnet0", T::Wwanpp), Physical),
        (iface("x", T::FastEthernetT), Physical),
        (iface("y", T::Ethernet3Megabit), Physical),
        // Windows: Wintun and WireGuard-NT are IF_TYPE 53 with no
        // point-to-point flag.
        (
            described(
                "{6B29FC40-CA47-1067-B31D-00DD010662DA}",
                T::ProprietaryVirtual,
                "WireGuard Tunnel",
            ),
            Tunnel,
        ),
        (
            described("{0}", T::ProprietaryVirtual, "Some Virtual Adapter"),
            Tunnel,
        ),
        (
            described("{1}", T::Ethernet, "Wintun Userspace Tunnel"),
            Tunnel,
        ),
        // TAP adapters report Ethernet: only the markers catch them.
        (
            described("{2}", T::Ethernet, "TAP-Windows Adapter V9"),
            Tunnel,
        ),
        (
            described("{3}", T::Ethernet, "TAP-Win32 Adapter OAS"),
            Tunnel,
        ),
        (
            described(
                "{4}",
                T::Ethernet,
                "Fortinet SSL VPN Virtual Ethernet Adapter",
            ),
            Tunnel,
        ),
        (
            described("{5}", T::Ethernet, "Intel(R) Ethernet Connection"),
            Physical,
        ),
        (iface("wg0", T::UnknownWithValue(65534)), Tunnel),
        (iface("wg0", T::Ethernet), Tunnel),
        (iface("tun0", T::UnknownWithValue(65534)), Tunnel),
        (iface("tap0", T::Ethernet), Tunnel),
        (iface("utun3", T::Tunnel), Tunnel),
        (iface("tailscale0", T::UnknownWithValue(65534)), Tunnel),
        (iface("ztabcdef12", T::Ethernet), Tunnel),
        (iface("nordlynx", T::UnknownWithValue(65534)), Tunnel),
        (iface("ipsec0", T::Ethernet), Tunnel),
        (iface("ppp0", T::Ppp), Tunnel),
        (iface("x0", T::Ppp), Tunnel),
        (iface("x1", T::Tunnel), Tunnel),
        (p2p_ethernet, Tunnel),
        // Unknown types fail closed.
        (iface("x2", T::Unknown), Tunnel),
        (iface("sit0", T::UnknownWithValue(776)), Tunnel),
        (iface("bridge0", T::Bridge), Tunnel),
        (iface("awdl0", T::PeerToPeerWireless), Tunnel),
        // Bridges and container interfaces report Ethernet.
        (iface("docker0", T::Ethernet), Virtual),
        (iface("br-1a2b3c4d5e6f", T::Ethernet), Virtual),
        (iface("virbr0", T::Ethernet), Virtual),
        (iface("veth9f2c1d0", T::Ethernet), Virtual),
        (iface("vmnet8", T::Ethernet), Virtual),
        (iface("vboxnet0", T::Ethernet), Virtual),
        (iface("lxcbr0", T::Ethernet), Virtual),
        (iface("lxdbr0", T::Ethernet), Virtual),
        (iface("cni0", T::Ethernet), Virtual),
        (iface("flannel.1", T::Ethernet), Virtual),
        (iface("podman0", T::Ethernet), Virtual),
        (iface("kube-bridge", T::Ethernet), Virtual),
        (
            described("{6}", T::Ethernet, "Hyper-V Virtual Ethernet Adapter"),
            Virtual,
        ),
        (
            described("{7}", T::Ethernet, "VirtualBox Host-Only Ethernet Adapter"),
            Virtual,
        ),
        (
            described(
                "{8}",
                T::Ethernet,
                "VMware Virtual Ethernet Adapter for VMnet1",
            ),
            Virtual,
        ),
        // A Linux `br0` is not on the list: it is judged by its type.
        (iface("br0", T::Ethernet), Physical),
    ] {
        assert_eq!(iface_kind(&i, false), want, "{:?} {:?}", i.name, i.if_type);
    }
}

/// "An interface that carries a route source is never Virtual": a Hyper-V
/// external switch or a bridge with the default route is judged by its type.
#[test]
fn a_route_source_interface_is_never_virtual() {
    use InterfaceType as T;
    for i in [
        iface("docker0", T::Ethernet),
        iface("br-1a2b", T::Ethernet),
        iface("virbr0", T::Ethernet),
        iface("veth9", T::Ethernet),
        described("{6}", T::Ethernet, "Hyper-V Virtual Ethernet Adapter #2"),
    ] {
        assert_eq!(iface_kind(&i, false), IfaceKind::Virtual, "{}", i.name);
        assert_eq!(iface_kind(&i, true), IfaceKind::Physical, "{}", i.name);
    }
    // The route source does not lift a tunnel, a loopback or an unknown type.
    assert_eq!(
        iface_kind(&iface("wg0", T::Ethernet), true),
        IfaceKind::Tunnel
    );
    assert_eq!(
        iface_kind(&iface("lo", T::Loopback), true),
        IfaceKind::Loopback
    );
    assert_eq!(
        iface_kind(&iface("docker0", T::Unknown), true),
        IfaceKind::Tunnel
    );
}

fn flags6(temporary: bool, deprecated: bool, tentative: bool, duplicated: bool) -> Ipv6AddrFlags {
    Ipv6AddrFlags {
        deprecated,
        temporary,
        tentative,
        duplicated,
        permanent: false,
    }
}

#[test]
fn interface_addresses_carry_their_flags_and_classes() {
    let mut i = iface("wlan0", InterfaceType::Wireless80211);
    i.index = 3;
    i.ipv4 = vec!["192.168.77.203/24".parse::<Ipv4Net>().unwrap()];
    i.ipv6 = vec![
        "2001:470:1:2:a1b2:c3d4:e5f6:7788/64"
            .parse::<Ipv6Net>()
            .unwrap(),
        "2001:470:1:2:21b:21ff:fe3c:4d5e/64".parse().unwrap(),
        "fd12:3456:789a:1::203/64".parse().unwrap(),
    ];
    i.ipv6_addr_flags = vec![
        flags6(true, false, false, false),
        flags6(false, true, false, false),
        flags6(false, false, true, true),
    ];
    let addrs = iface_addrs(&i, IfaceKind::Physical);
    assert_eq!(addrs.len(), 4);
    assert_eq!(addrs[0].class, AddrClass::Private);
    assert_eq!(addrs[0].prefix_len, 24);
    assert!(addrs[0].up && addrs[0].usable());
    assert!(
        addrs
            .iter()
            .all(|a| a.iface_index == 3 && a.gateway_v4.is_none())
    );
    assert!(addrs[1].temporary && !addrs[1].eui64 && addrs[1].usable());
    assert_eq!(addrs[1].class, AddrClass::Global);
    assert!(addrs[2].deprecated && addrs[2].eui64 && !addrs[2].usable());
    assert!(addrs[3].tentative && addrs[3].duplicated && !addrs[3].usable());
    assert_eq!(addrs[3].class, AddrClass::UniqueLocal);
    // Flags netdev could not pair with the addresses: the IPv6 addresses go.
    i.ipv6_addr_flags.pop();
    assert_eq!(iface_addrs(&i, IfaceKind::Physical).len(), 1);
    // Down (or not running) interfaces' addresses are not usable.
    i.flags = 0;
    assert!(
        iface_addrs(&i, IfaceKind::Physical)
            .iter()
            .all(|a| !a.up && !a.usable())
    );
}

#[test]
fn a_snapshot_lifts_the_route_source_bridge_out_of_virtual() {
    let mut br = iface("docker0", InterfaceType::Ethernet);
    br.index = 5;
    br.ipv4 = vec!["172.17.0.1/16".parse().unwrap()];
    let mut eth = iface("eth0", InterfaceType::Ethernet);
    eth.index = 2;
    eth.ipv4 = vec!["192.168.77.203/24".parse().unwrap()];
    let ifaces = [br, eth];
    let on_eth = RouteSources {
        v4: Some("192.168.77.203".parse().unwrap()),
        v6: None,
    };
    let kinds = |s: &RouteSources| -> Vec<IfaceKind> {
        snapshot(&ifaces, s).iter().map(|a| a.iface_kind).collect()
    };
    // Ordered by interface index, whatever order the OS listed them in.
    assert_eq!(kinds(&on_eth), [IfaceKind::Physical, IfaceKind::Virtual]);
    let reversed = [ifaces[1].clone(), ifaces[0].clone()];
    assert_eq!(snapshot(&reversed, &on_eth), snapshot(&ifaces, &on_eth));
    assert_eq!(
        snapshot(&ifaces, &on_eth)
            .iter()
            .map(|a| a.iface_index)
            .collect::<Vec<_>>(),
        [2, 5]
    );
    let on_bridge = RouteSources {
        v4: Some("172.17.0.1".parse().unwrap()),
        v6: None,
    };
    assert_eq!(
        kinds(&on_bridge),
        [IfaceKind::Physical, IfaceKind::Physical]
    );
}

/// An address for the selection tables.
fn a(ip: &str, prefix_len: u8, iface_index: u32, iface_kind: IfaceKind) -> IfaceAddr {
    let ip: IpAddr = ip.parse().unwrap();
    IfaceAddr {
        ip,
        prefix_len,
        class: class(ip),
        temporary: false,
        deprecated: false,
        tentative: false,
        duplicated: false,
        eui64: match ip {
            IpAddr::V6(v6) => is_eui64(v6),
            IpAddr::V4(_) => false,
        },
        iface_index,
        iface_kind,
        up: true,
        gateway_v4: None,
    }
}

fn temp(mut x: IfaceAddr) -> IfaceAddr {
    x.temporary = true;
    x
}

fn sources(v4: Option<&str>, v6: Option<&str>) -> RouteSources {
    RouteSources {
        v4: v4.map(|s| s.parse().unwrap()),
        v6: v6.map(|s| s.parse().unwrap()),
    }
}

/// Design §7.2 "VPN mode", the table of §12.1.
#[test]
fn vpn_mode_follows_the_route_sources() {
    use IfaceKind::*;
    let addrs = [
        a("192.168.77.203", 24, 2, Physical),
        a("2001:470:1:2:a1b2:c3d4:e5f6:7788", 64, 2, Physical),
        a("10.66.0.2", 32, 7, Tunnel),
        a("fd00:6666::2", 128, 7, Tunnel),
        a("192.168.88.20", 24, 3, Physical),
        a("2001:470:9:9::20", 64, 3, Physical),
        a("172.17.0.1", 16, 5, Virtual),
    ];
    for (v4, v6, want) in [
        (None, None, false),
        (Some("192.168.77.203"), None, false),
        (None, Some("2001:470:1:2:a1b2:c3d4:e5f6:7788"), false),
        (
            Some("192.168.77.203"),
            Some("2001:470:1:2:a1b2:c3d4:e5f6:7788"),
            false,
        ),
        // A route source on a tunnel.
        (Some("10.66.0.2"), None, true),
        (Some("10.66.0.2"), Some("fd00:6666::2"), true),
        (None, Some("fd00:6666::2"), true),
        // Split families: v4 through the tunnel, v6 physical.
        (
            Some("10.66.0.2"),
            Some("2001:470:1:2:a1b2:c3d4:e5f6:7788"),
            true,
        ),
        // The families leave by two different physical interfaces.
        (Some("192.168.77.203"), Some("2001:470:9:9::20"), true),
        // A route source on no listed interface.
        (Some("192.168.99.9"), None, true),
        (Some("192.168.77.203"), Some("2001:470:dead::1"), true),
        // On an interface classed Virtual (a read raced a route change).
        (Some("172.17.0.1"), None, true),
    ] {
        assert_eq!(vpn_mode(&addrs, &sources(v4, v6)), want, "{v4:?} {v6:?}");
    }
    // With no interface at all, any route source means VPN mode.
    assert!(vpn_mode(&[], &sources(Some("192.168.77.203"), None)));
    assert!(!vpn_mode(&[], &sources(None, None)));
}

#[test]
fn global_families_keep_public_traffic_on_the_tunnel() {
    use IfaceKind::*;
    let addrs = [
        a("192.168.77.203", 24, 2, Physical),
        a("2001:470:1:2:a1b2:c3d4:e5f6:7788", 64, 2, Physical),
        a("10.66.0.2", 32, 7, Tunnel),
        a("fd00:6666::2", 128, 7, Tunnel),
    ];
    let both = sources(
        Some("192.168.77.203"),
        Some("2001:470:1:2:a1b2:c3d4:e5f6:7788"),
    );
    assert_eq!(global_families(&addrs, &both, false), (true, true));
    assert_eq!(
        global_families(&addrs, &sources(Some("192.168.77.203"), None), false),
        (true, false)
    );
    let split = sources(Some("10.66.0.2"), Some("2001:470:1:2:a1b2:c3d4:e5f6:7788"));
    assert!(vpn_mode(&addrs, &split));
    assert_eq!(global_families(&addrs, &split, true), (true, false));
    let tunnel = sources(Some("10.66.0.2"), Some("fd00:6666::2"));
    assert_eq!(global_families(&addrs, &tunnel, true), (true, true));
    let lost = sources(Some("192.168.99.9"), None);
    assert_eq!(global_families(&addrs, &lost, true), (false, false));
}

/// A home computer: Wi-Fi with a private IPv4, a temporary and a stable
/// global IPv6, an EUI-64 one and a ULA; Ethernet with another private
/// IPv4 and ULA; a docker bridge, a WireGuard tunnel and loopback.
fn home() -> Vec<IfaceAddr> {
    use IfaceKind::*;
    vec![
        a("127.0.0.1", 8, 1, Loopback),
        a("::1", 128, 1, Loopback),
        a("192.168.88.20", 24, 3, Physical),
        a("fd12:3456:789a:2::20", 64, 3, Physical),
        a("192.168.77.203", 24, 2, Physical),
        a("2001:470:1:2:21b:21ff:fe3c:4d5e", 64, 2, Physical),
        a("2001:470:1:2:5555:6666:7777:8888", 64, 2, Physical),
        temp(a("2001:470:1:2:a1b2:c3d4:e5f6:7788", 64, 2, Physical)),
        a("fd12:3456:789a:1::203", 64, 2, Physical),
        temp(a("fd12:3456:789a:1:9:9:9:9", 64, 2, Physical)),
        a("169.254.7.7", 16, 2, Physical),
        a("172.17.0.1", 16, 5, Virtual),
        a("10.66.0.2", 32, 7, Tunnel),
        a("fd00:6666::2", 128, 7, Tunnel),
    ]
}

fn ips(c: &[Candidate]) -> Vec<String> {
    c.iter().map(|c| c.addr.ip().to_string()).collect()
}

#[test]
fn same_site_candidates_are_private_v4_and_ula_of_physical_interfaces() {
    let src = sources(
        Some("192.168.77.203"),
        Some("2001:470:1:2:5555:6666:7777:8888"),
    );
    let picked = select_host_candidates(&home(), &src, 50417, Scope::SameSite, false);
    // The route source's interface first; one ULA per interface, temporary
    // first; no global, no tunnel, docker, loopback or link-local address.
    assert_eq!(
        ips(&picked),
        [
            "192.168.77.203",
            "192.168.88.20",
            "fd12:3456:789a:1:9:9:9:9",
            "fd12:3456:789a:2::20"
        ]
    );
    assert!(
        picked
            .iter()
            .all(|c| c.kind == CandidateKind::Host && c.addr.port() == 50417)
    );
    // VPN mode keeps the same-site candidates (the same LAN).
    assert_eq!(
        select_host_candidates(&home(), &src, 50417, Scope::SameSite, true),
        picked
    );
    // In internet scope with a private IPv4 the ULAs stay home, and the
    // globals come from the route-source interfaces only.
    let wide = select_host_candidates(&home(), &src, 50417, Scope::Internet, false);
    assert_eq!(
        ips(&wide),
        [
            "192.168.77.203",
            "192.168.88.20",
            "2001:470:1:2:a1b2:c3d4:e5f6:7788"
        ]
    );
    // In VPN mode no global host candidate at all.
    assert_eq!(
        ips(&select_host_candidates(
            &home(),
            &src,
            50417,
            Scope::Internet,
            true
        )),
        ["192.168.77.203", "192.168.88.20"]
    );
}

#[test]
fn skipped_addresses_are_never_offered() {
    use IfaceKind::*;
    let mut down = a("192.168.10.10", 24, 4, Physical);
    down.up = false;
    let mut deprecated = a("fd12:3456:789a:4::1", 64, 4, Physical);
    deprecated.deprecated = true;
    let mut tentative = a("fd12:3456:789a:5::1", 64, 6, Physical);
    tentative.tentative = true;
    let mut duplicated = a("192.168.11.11", 24, 8, Physical);
    duplicated.duplicated = true;
    let addrs = [
        down,
        deprecated,
        tentative,
        duplicated,
        a("fd12:3456:789a:6:21b:21ff:fe3c:4d5e", 64, 9, Physical),
        a("100.64.1.2", 10, 10, Physical),
        a("169.254.1.2", 16, 10, Physical),
        a("192.0.2.4", 24, 10, Physical),
        a("192.168.12.12", 24, 11, Virtual),
        a("192.168.13.13", 24, 12, Tunnel),
    ];
    for scope in [Scope::SameSite, Scope::Internet] {
        let src = sources(Some("100.64.1.2"), None);
        assert!(
            select_host_candidates(&addrs, &src, 50417, scope, false).is_empty(),
            "{scope:?}"
        );
    }
}

/// Design §7.1: at most four private IPv4, two ULAs (one per interface),
/// eight in all.
#[test]
fn host_candidates_are_capped() {
    use IfaceKind::*;
    let mut addrs: Vec<IfaceAddr> = (0..6u8)
        .map(|i| {
            a(
                &format!("192.168.{}.20", 100 + i),
                24,
                u32::from(i) + 10,
                Physical,
            )
        })
        .collect();
    addrs.extend((0..4u8).map(|i| {
        a(
            &format!("fd12:3456:789a:{i}::20"),
            64,
            u32::from(i) + 10,
            Physical,
        )
    }));
    addrs.push(a("fd12:3456:789a:7::21", 64, 10, Physical));
    let src = sources(Some("192.168.105.20"), None);
    let picked = select_host_candidates(&addrs, &src, 50417, Scope::SameSite, false);
    assert_eq!(picked.len(), MAX_PRIVATE_V4 + MAX_ULA);
    assert_eq!(picked[0].addr.ip().to_string(), "192.168.105.20");
    let v4 = picked.iter().filter(|c| c.addr.is_ipv4()).count();
    assert_eq!(v4, MAX_PRIVATE_V4);
    let v6: Vec<_> = picked.iter().filter(|c| c.addr.is_ipv6()).collect();
    assert_eq!(v6.len(), MAX_ULA);
    assert!(picked.len() <= MAX_HOST_CANDIDATES);
}

/// Design §7.1 "Internet scope, not VPN mode": one global IPv4 and one
/// global IPv6, each only from its family's route-source interface; the
/// IPv6 one temporary first (the route source itself when it is one),
/// else the route source when it is not EUI-64, else none; ULA only when
/// no private IPv4 is offered.
#[test]
fn internet_globals_come_from_the_route_source_interfaces() {
    use IfaceKind::*;
    let addrs = vec![
        a("203.0.113.9", 24, 2, Physical),
        a("8.8.4.4", 24, 2, Physical),
        a("9.9.9.9", 24, 3, Physical),
        a("2001:470:1:2:5555:6666:7777:8888", 64, 2, Physical),
        temp(a("2001:470:1:2:a1b2:c3d4:e5f6:7788", 64, 2, Physical)),
        temp(a("2001:470:9:9::20", 64, 3, Physical)),
        a("fd12:3456:789a:1::203", 64, 2, Physical),
    ];
    let src = sources(Some("8.8.4.4"), Some("2001:470:1:2:5555:6666:7777:8888"));
    // No private IPv4: the ULA is offered; the v4 route source itself; the
    // temporary v6 of the route-source interface, never the other one's.
    assert_eq!(
        ips(&select_host_candidates(
            &addrs,
            &src,
            50417,
            Scope::Internet,
            false
        )),
        [
            "fd12:3456:789a:1::203",
            "8.8.4.4",
            "2001:470:1:2:a1b2:c3d4:e5f6:7788"
        ]
    );
    // The route source is itself temporary: it wins.
    let mut second = addrs.clone();
    second.push(temp(a("2001:470:1:2:1:2:3:4", 64, 2, Physical)));
    let src2 = sources(Some("8.8.4.4"), Some("2001:470:1:2:1:2:3:4"));
    assert_eq!(
        ips(&select_host_candidates(
            &second,
            &src2,
            50417,
            Scope::Internet,
            false
        ))[2],
        "2001:470:1:2:1:2:3:4"
    );
    // No temporary address: the stable route source (RFC 7217).
    let stable: Vec<IfaceAddr> = addrs
        .iter()
        .map(|x| IfaceAddr {
            temporary: false,
            ..*x
        })
        .collect();
    assert_eq!(
        ips(&select_host_candidates(
            &stable,
            &src,
            50417,
            Scope::Internet,
            false
        ))[2],
        "2001:470:1:2:5555:6666:7777:8888"
    );
    // An EUI-64 route source and no temporary address: no global IPv6.
    let eui = vec![
        a("8.8.4.4", 24, 2, Physical),
        a("2001:470:1:2:21b:21ff:fe3c:4d5e", 64, 2, Physical),
    ];
    let src3 = sources(Some("8.8.4.4"), Some("2001:470:1:2:21b:21ff:fe3c:4d5e"));
    assert_eq!(
        ips(&select_host_candidates(
            &eui,
            &src3,
            50417,
            Scope::Internet,
            false
        )),
        ["8.8.4.4"]
    );
    // A deprecated temporary address is not preferred.
    let mut old = addrs.clone();
    old[4].deprecated = true;
    assert_eq!(
        ips(&select_host_candidates(
            &old,
            &src,
            50417,
            Scope::Internet,
            false
        ))[2],
        "2001:470:1:2:5555:6666:7777:8888"
    );
    // Without a route source of a family, no global of that family.
    assert_eq!(
        ips(&select_host_candidates(
            &addrs,
            &sources(None, None),
            50417,
            Scope::Internet,
            false
        )),
        ["fd12:3456:789a:1::203"]
    );
    // Same-site scope never offers a global.
    assert_eq!(
        ips(&select_host_candidates(
            &addrs,
            &src,
            50417,
            Scope::SameSite,
            false
        )),
        ["fd12:3456:789a:1::203"]
    );
}

/// Design §7.1 "Without host candidates": a computer whose only IPv4 is in
/// the shared CGNAT space offers no host candidate, and its IPv4 route
/// source is still there as a srflx and mapping base (the gatherer of
/// step B6 uses it).
#[test]
fn a_cgnat_only_computer_offers_no_host_candidate_but_keeps_its_route_source() {
    let addrs = [a("100.64.1.2", 10, 2, IfaceKind::Physical)];
    let src = sources(Some("100.64.1.2"), None);
    assert!(select_host_candidates(&addrs, &src, 50417, Scope::Internet, false).is_empty());
    assert!(!vpn_mode(&addrs, &src));
    assert_eq!(class(IpAddr::V4(src.v4.unwrap())), AddrClass::SharedCgnat);
    let stun = stun_filter(&addrs, &src, false);
    assert!(stun.have_v4);
}

#[test]
fn the_remote_filter_is_built_from_what_was_offered() {
    let src = sources(
        Some("192.168.77.203"),
        Some("2001:470:1:2:5555:6666:7777:8888"),
    );
    let offered = select_host_candidates(&home(), &src, 50417, Scope::SameSite, false);
    let f = remote_filter(Scope::SameSite, &home(), &src, &offered, true, false, false);
    assert_eq!(f.scope, Scope::SameSite);
    assert_eq!(f.on_link.len(), 4);
    assert_eq!(
        f.own_ula48,
        Some("fd12:3456:789a::/48".parse::<Ipv6Net>().unwrap())
    );
    assert!(f.have_v4 && !f.have_v6 && f.dual_stack);
    assert_eq!(f.global_families, (true, true));
    // Every address of every interface is ours, the route sources too.
    assert_eq!(f.own.len(), home().len());
    // The docker bridge's prefix is not on-link, but its broadcast address
    // is still refused.
    assert!(f.admit("192.168.77.20:50417".parse().unwrap()));
    assert!(f.admit("192.168.88.30:50417".parse().unwrap()));
    assert!(!f.admit("172.17.0.2:50417".parse().unwrap()));
    assert!(!f.admit("192.168.77.203:50417".parse().unwrap()));
    assert!(f.admit("[fd12:3456:789a:ee::1]:50417".parse().unwrap()));
    let wide = remote_filter(Scope::Internet, &home(), &src, &offered, true, false, false);
    assert_eq!(
        wide.check("172.17.255.255:50417".parse().unwrap()),
        Err(crate::Refusal::NetworkOrBroadcast)
    );
    assert!(wide.admit("172.17.0.2:50417".parse().unwrap()));
    // Without a dual-stack socket no IPv6 at all.
    let v4_only = remote_filter(
        Scope::SameSite,
        &home(),
        &src,
        &offered,
        false,
        false,
        false,
    );
    assert!(v4_only.own_ula48.is_none());
    assert!(!v4_only.admit("[fd12:3456:789a:ee::1]:50417".parse().unwrap()));
    // An offered global IPv6 is what lets a global IPv6 remote in.
    let globals = select_host_candidates(&home(), &src, 50417, Scope::Internet, false);
    let wide = remote_filter(Scope::Internet, &home(), &src, &globals, true, false, false);
    assert!(wide.have_v6);
    assert!(wide.admit("[2606:4700:4700::1111]:50417".parse().unwrap()));
    // Nothing offered, same-site: no family to send from.
    let none = remote_filter(Scope::SameSite, &home(), &src, &[], true, false, false);
    assert!(!none.have_v4 && none.on_link.is_empty() && none.own_ula48.is_none());
    assert!(!none.admit("192.168.77.20:50417".parse().unwrap()));
}

/// Pieces of the test addresses that must not appear in a `Debug` text
/// (decision M1-83).
const PIECES: [&str; 10] = [
    "192", "168", "77", "203", "fd12", "3456", "789a", "2001", "470", "a1b2",
];

#[test]
fn interface_types_debug_without_addresses() {
    let mut gw = a("192.168.77.203", 24, 3, IfaceKind::Physical);
    gw.gateway_v4 = Some("192.168.77.1".parse().unwrap());
    let src = sources(
        Some("192.168.77.203"),
        Some("2001:470:1:2:a1b2:c3d4:e5f6:7788"),
    );
    let text = format!(
        "{gw:?} {gw:#?} {:?} {:?} {src:?} {src:#?}",
        temp(a("fd12:3456:789a:1::203", 64, 3, IfaceKind::Physical)),
        a("2001:470:1:2:a1b2:c3d4:e5f6:7788", 64, 3, IfaceKind::Tunnel),
    );
    for piece in PIECES {
        assert!(!text.contains(piece), "\"{piece}\" in {text}");
    }
    for said in [
        "v4 private",
        "v6 unique-local",
        "v6 global",
        "temporary",
        "Tunnel",
        "up",
    ] {
        assert!(text.contains(said), "\"{said}\" missing in {text}");
    }
}

#[tokio::test]
async fn a_slow_read_times_out_and_the_next_caller_joins_it() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let wait = Mutex::new(wait);
    let counted = Arc::clone(&calls);
    let reader = IfaceReader::new(
        Arc::new(move || {
            if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                // The first read hangs until the test lets it go.
                let _ = wait.lock().unwrap().recv();
            }
            vec![a("192.168.77.203", 24, 2, IfaceKind::Physical)]
        }),
        Duration::from_millis(50),
    );
    let started = std::time::Instant::now();
    assert_eq!(reader.read().await, Err(NetError::InterfacesTimedOut));
    assert!(started.elapsed() >= Duration::from_millis(50));
    // A second caller while the first read still hangs joins it: no second
    // OS call, and the same timeout.
    let (one, two) = tokio::join!(reader.read(), reader.read());
    assert_eq!(one, Err(NetError::InterfacesTimedOut));
    assert_eq!(two, Err(NetError::InterfacesTimedOut));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Once it ends, the slot is free and the next caller reads afresh.
    release.send(()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(addrs) = reader.read().await {
            assert_eq!(addrs.len(), 1);
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the read never came back"
        );
    }
    assert!(calls.load(Ordering::SeqCst) <= 2);
}

#[tokio::test]
async fn a_read_that_panics_is_lost_and_the_next_one_reads_again() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let reader = IfaceReader::new(
        Arc::new(move || {
            assert!(
                counted.fetch_add(1, Ordering::SeqCst) != 0,
                "the first read fails"
            );
            Vec::new()
        }),
        Duration::from_secs(10),
    );
    assert_eq!(reader.read().await, Err(NetError::InterfacesLost));
    assert_eq!(reader.read().await, Ok(Vec::new()));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// The real read on this machine (the build container: `lo` and `eth0`).
/// Nothing about the machine's addresses is asserted beyond their kinds.
#[tokio::test]
async fn this_machines_interfaces_and_route_sources_read() {
    let addrs = read_interfaces().await.expect("the interface list");
    for x in &addrs {
        if x.ip.is_loopback() {
            assert_eq!(x.iface_kind, IfaceKind::Loopback, "{x:?}");
        }
    }
    let src = route_sources();
    for ip in [src.v4.map(IpAddr::V4), src.v6.map(IpAddr::V6)]
        .into_iter()
        .flatten()
    {
        assert!(!ip.is_unspecified() && !ip.is_loopback());
        assert!(
            addrs.iter().any(|x| x.ip == ip),
            "{src:?} not among {addrs:?}"
        );
    }
    // A second read while none is in flight reads again and agrees on the
    // kinds.
    let again = read_interfaces().await.expect("the interface list");
    assert_eq!(
        again.iter().map(|x| x.iface_kind).collect::<Vec<_>>(),
        addrs.iter().map(|x| x.iface_kind).collect::<Vec<_>>()
    );
}

/// The device check of `docs/VERIFICATION.md` (the netdev rows): what this
/// computer's reading and the selection make of it, addresses redacted to
/// their family and class. Map an `iface_index` to its name with `ip -o
/// link` (Linux), `Get-NetAdapter -IncludeHidden | ft ifIndex,Name,
/// InterfaceDescription` (Windows) or `ifconfig -v` (macOS).
#[tokio::test]
#[ignore = "device check: prints this computer's reading"]
#[allow(clippy::print_stderr)] // the device check reports what it read
async fn print_this_machines_reading() {
    let addrs = read_interfaces().await.expect("the interface list");
    let src = route_sources();
    let vpn = vpn_mode(&addrs, &src);
    for x in &addrs {
        eprintln!("{x:?}");
    }
    eprintln!(
        "{src:?} vpn_mode={vpn} global_families={:?}",
        global_families(&addrs, &src, vpn)
    );
    for scope in [Scope::SameSite, Scope::Internet] {
        eprintln!(
            "{scope:?}: {:?}",
            select_host_candidates(&addrs, &src, 50_000, scope, vpn)
        );
    }
}

/// Step B1: netdev's gateway (Linux and macOS) reaches every address of
/// its interface, the first usable IPv4 one; an unspecified next hop or a
/// gateway with only IPv6 addresses is none.
#[cfg(not(windows))]
#[test]
fn the_netdev_gateway_reaches_every_address_of_its_interface() {
    let mut i = iface("wlan0", InterfaceType::Wireless80211);
    i.index = 3;
    i.ipv4 = vec!["192.168.77.203/24".parse::<Ipv4Net>().unwrap()];
    i.ipv6 = vec!["fd12:3456:789a:1::203/64".parse::<Ipv6Net>().unwrap()];
    i.ipv6_addr_flags = vec![flags6(false, false, false, false)];
    let mut device = netdev::NetworkDevice::new();
    device.ipv4 = vec![Ipv4Addr::UNSPECIFIED, "192.168.77.1".parse().unwrap()];
    device.ipv6 = vec!["fe80::1".parse().unwrap()];
    i.gateway = Some(device.clone());
    let addrs = iface_addrs(&i, IfaceKind::Physical);
    assert_eq!(addrs.len(), 2);
    assert!(
        addrs
            .iter()
            .all(|a| a.gateway_v4 == Some("192.168.77.1".parse().unwrap()))
    );
    device.ipv4 = vec![Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST];
    i.gateway = Some(device.clone());
    assert!(
        iface_addrs(&i, IfaceKind::Physical)
            .iter()
            .all(|a| a.gateway_v4.is_none())
    );
    device.ipv4.clear();
    i.gateway = Some(device);
    assert!(
        iface_addrs(&i, IfaceKind::Physical)
            .iter()
            .all(|a| a.gateway_v4.is_none())
    );
    i.gateway = None;
    assert!(
        iface_addrs(&i, IfaceKind::Physical)
            .iter()
            .all(|a| a.gateway_v4.is_none())
    );
}

#[test]
fn only_a_unicast_address_is_a_gateway() {
    for usable in ["192.168.1.1", "10.0.0.138", "100.64.0.1", "169.254.1.1"] {
        assert!(usable_gateway(usable.parse().unwrap()), "{usable}");
    }
    for unusable in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"] {
        assert!(!usable_gateway(unusable.parse().unwrap()), "{unusable}");
    }
}

/// Step B1 (design §7.1, the Windows gateway): the lookup is asked once
/// per interface that has no gateway yet, never for a loopback interface;
/// a gateway already read stays, and an unusable answer is none.
#[test]
fn the_gateway_lookup_fills_each_interface_once() {
    let mut read = a("192.168.77.203", 24, 5, IfaceKind::Physical);
    read.gateway_v4 = Some("192.168.77.1".parse().unwrap());
    let mut addrs = vec![
        a("127.0.0.1", 8, 1, IfaceKind::Loopback),
        a("192.168.50.20", 24, 3, IfaceKind::Physical),
        a("fd12:3456:789a:1::20", 64, 3, IfaceKind::Physical),
        read,
        a("10.8.0.2", 24, 7, IfaceKind::Tunnel),
        a("172.17.0.1", 16, 9, IfaceKind::Virtual),
    ];
    let asked = Mutex::new(Vec::new());
    fill_gateways(&mut addrs, &|index| {
        asked.lock().unwrap().push(index);
        match index {
            3 => Some("192.168.50.1".parse().unwrap()),
            7 => Some(Ipv4Addr::UNSPECIFIED),
            9 => Some("172.17.0.254".parse().unwrap()),
            _ => Some("198.51.100.1".parse().unwrap()),
        }
    });
    assert_eq!(*asked.lock().unwrap(), vec![3, 7, 9]);
    let gateways: Vec<Option<Ipv4Addr>> = addrs.iter().map(|a| a.gateway_v4).collect();
    assert_eq!(
        gateways,
        vec![
            None,
            Some("192.168.50.1".parse().unwrap()),
            Some("192.168.50.1".parse().unwrap()),
            Some("192.168.77.1".parse().unwrap()),
            None,
            Some("172.17.0.254".parse().unwrap()),
        ]
    );
}
