use super::*;

use proptest::prelude::*;

fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse().unwrap())
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse().unwrap())
}

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

/// Design §7.1 "v4 non-Global", every block of the IANA IPv4 Special-Purpose
/// Address Registry with its first and last address, and the addresses just
/// outside each block.
#[test]
fn every_special_purpose_v4_block_is_classed() {
    use AddrClass::*;
    for (ip, want) in [
        ("0.0.0.0", Unusable),
        ("0.255.255.255", Unusable),
        ("1.0.0.0", Global),
        ("9.255.255.255", Global),
        ("10.0.0.0", Private),
        ("10.255.255.255", Private),
        ("11.0.0.0", Global),
        ("100.63.255.255", Global),
        ("100.64.0.0", SharedCgnat),
        ("100.127.255.255", SharedCgnat),
        ("100.128.0.0", Global),
        ("126.255.255.255", Global),
        ("127.0.0.0", Loopback),
        ("127.0.0.1", Loopback),
        ("127.255.255.255", Loopback),
        ("128.0.0.0", Global),
        ("169.253.255.255", Global),
        ("169.254.0.0", LinkLocal),
        ("169.254.255.255", LinkLocal),
        ("169.255.0.0", Global),
        ("172.15.255.255", Global),
        ("172.16.0.0", Private),
        ("172.31.255.255", Private),
        ("172.32.0.0", Global),
        ("191.255.255.255", Global),
        ("192.0.0.0", Unusable),
        ("192.0.0.9", Unusable),
        ("192.0.0.10", Unusable),
        ("192.0.0.255", Unusable),
        ("192.0.1.0", Global),
        ("192.0.2.0", Unusable),
        ("192.0.2.255", Unusable),
        ("192.0.3.0", Global),
        ("192.31.196.0", Unusable),
        ("192.31.196.255", Unusable),
        ("192.31.197.0", Global),
        ("192.52.193.0", Unusable),
        ("192.52.193.255", Unusable),
        ("192.52.194.0", Global),
        ("192.88.99.0", Unusable),
        ("192.88.99.255", Unusable),
        ("192.88.100.0", Global),
        ("192.167.255.255", Global),
        ("192.168.0.0", Private),
        ("192.168.255.255", Private),
        ("192.169.0.0", Global),
        ("192.175.48.0", Unusable),
        ("192.175.48.255", Unusable),
        ("192.175.49.0", Global),
        ("198.17.255.255", Global),
        ("198.18.0.0", Unusable),
        ("198.19.255.255", Unusable),
        ("198.20.0.0", Global),
        ("198.51.100.0", Unusable),
        ("198.51.100.255", Unusable),
        ("198.51.101.0", Global),
        ("203.0.112.255", Global),
        ("203.0.113.0", Unusable),
        ("203.0.113.255", Unusable),
        ("203.0.114.0", Global),
        ("223.255.255.255", Global),
        ("224.0.0.0", Unusable),
        ("239.255.255.250", Unusable),
        ("239.255.255.255", Unusable),
        ("240.0.0.0", Unusable),
        ("255.255.255.254", Unusable),
        ("255.255.255.255", Unusable),
        ("8.8.8.8", Global),
        ("1.1.1.1", Global),
    ] {
        assert_eq!(class(v4(ip)), want, "{ip}");
    }
}

/// Design §7.1 "v6 Global" and "v6 non-Global": all of `2001::/23`
/// (2001::/32 Teredo, 2001:1::1 PCP anycast, 2001:1::2 TURN anycast,
/// 2001:2::/48 benchmarking, 2001:3::/32 AMT, 2001:4:112::/48 AS112,
/// 2001:20::/28 ORCHIDv2), `2001:db8::/32`, 6to4, NAT64, `3fff::/20`, and the
/// space outside `2000::/3`.
#[test]
fn every_special_purpose_v6_block_is_classed() {
    use AddrClass::*;
    for (ip, want) in [
        ("::", Unusable),
        ("::1", Loopback),
        ("::2", Unusable),
        ("::ffff:192.168.1.20", Unusable),
        ("::ffff:8.8.8.8", Unusable),
        ("::c0a8:114", Unusable),
        ("64:ff9b::808:808", Unusable),
        ("64:ff9b:1::1", Unusable),
        ("64:ff9b:1:ffff::1", Unusable),
        ("100::", Unusable),
        ("100::ffff:ffff:ffff:ffff", Unusable),
        ("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Unusable),
        ("2000::", Global),
        ("2000::1", Global),
        ("2001::", Unusable),
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", Unusable),
        ("2001:1::1", Unusable),
        ("2001:1::2", Unusable),
        ("2001:1::3", Unusable),
        ("2001:2::", Unusable),
        ("2001:2:0:ffff::1", Unusable),
        ("2001:3::", Unusable),
        ("2001:3:ffff::1", Unusable),
        ("2001:4:112::1", Unusable),
        ("2001:10::1", Unusable),
        ("2001:20::", Unusable),
        ("2001:2f:ffff::1", Unusable),
        ("2001:30::1", Unusable),
        ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", Unusable),
        ("2001:200::", Global),
        ("2001:470::1", Global),
        ("2001:4860:4860::8888", Global),
        ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", Global),
        ("2001:db8::", Unusable),
        ("2001:db8::1", Unusable),
        ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", Unusable),
        ("2001:db9::", Global),
        ("2001:ffff::1", Global),
        ("2002::", Unusable),
        ("2002:c000:204::1", Unusable),
        ("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Unusable),
        ("2003::1", Global),
        ("2606:4700:4700::1111", Global),
        ("2a00:1450:4001::200e", Global),
        ("3ffe::1", Global),
        ("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Global),
        ("3fff::", Unusable),
        ("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", Unusable),
        ("3fff:1000::", Global),
        ("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Global),
        ("4000::", Unusable),
        ("5f00::1", Unusable),
        ("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Unusable),
        ("fc00::", UniqueLocal),
        ("fd12:3456:789a::1", UniqueLocal),
        ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", UniqueLocal),
        ("fe00::1", Unusable),
        ("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Unusable),
        ("fe80::", LinkLocal),
        ("fe80::1", LinkLocal),
        ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", LinkLocal),
        ("fec0::1", Unusable),
        ("ff00::", Unusable),
        ("ff02::1", Unusable),
        ("ff02::fb", Unusable),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Unusable),
    ] {
        assert_eq!(class(v6(ip)), want, "{ip}");
    }
}

#[test]
fn canon_and_socket_family_convert_only_v4_mapped_addresses() {
    let mapped = sa("[::ffff:192.168.77.203]:50417");
    assert_eq!(canon(mapped), sa("192.168.77.203:50417"));
    assert_eq!(
        canon(sa("192.168.77.203:50417")),
        sa("192.168.77.203:50417")
    );
    assert_eq!(canon(sa("[fd12::7]:50417")), sa("[fd12::7]:50417"));
    // `::a.b.c.d` (IPv4-compatible, deprecated) is not v4-mapped.
    assert_eq!(canon(sa("[::c0a8:4dcb]:50417")), sa("[::c0a8:4dcb]:50417"));
    assert_eq!(to_socket_family(sa("192.168.77.203:50417"), true), mapped);
    assert_eq!(
        to_socket_family(sa("192.168.77.203:50417"), false),
        sa("192.168.77.203:50417")
    );
    assert_eq!(
        to_socket_family(sa("[fd12::7]:50417"), true),
        sa("[fd12::7]:50417")
    );
    assert_eq!(canon_ip(v6("::ffff:10.1.2.3")), v4("10.1.2.3"));
}

#[test]
fn eui64_is_the_ff_fe_in_the_interface_id() {
    assert!(is_eui64("fe80::21b:21ff:fe3c:4d5e".parse().unwrap()));
    assert!(is_eui64("2001:470:1:2:21b:21ff:fe3c:4d5e".parse().unwrap()));
    assert!(!is_eui64(
        "2001:470:1:2:a1b2:c3d4:e5f6:7788".parse().unwrap()
    ));
    assert!(!is_eui64("2001:470:1:2::ff:fe".parse().unwrap()));
}

/// A same-site filter of a computer on 192.168.77.0/24 (offered) with a
/// docker bridge 172.17.0.0/16 (not offered) and the ULA fd12:3456:789a:1::/64.
fn same_site() -> RemoteFilter {
    RemoteFilter {
        scope: Scope::SameSite,
        on_link: vec![net("192.168.77.0/24"), net("fd12:3456:789a:1::/64")],
        own_ula48: Some("fd12:3456:789a::/48".parse().unwrap()),
        local_nets: vec![
            net("192.168.77.0/24"),
            net("172.17.0.0/16"),
            net("fd12:3456:789a:1::/64"),
            net("127.0.0.0/8"),
        ],
        have_v4: true,
        have_v6: false,
        dual_stack: true,
        global_families: (true, true),
        own: vec![
            v4("192.168.77.203"),
            v4("172.17.0.1"),
            v6("fd12:3456:789a:1::203"),
            v4("127.0.0.1"),
        ],
        admit_loopback: false,
    }
}

fn internet() -> RemoteFilter {
    RemoteFilter {
        scope: Scope::Internet,
        have_v6: true,
        own: {
            let mut own = same_site().own;
            own.push(v6("2001:470:1:2:a1b2:c3d4:e5f6:7788"));
            own
        },
        ..same_site()
    }
}

/// Design §7.7: in same-site scope only a private IPv4 address inside our
/// on-link prefixes and a ULA inside our own /48 pass; in internet scope
/// other private, other ULA and global addresses pass too.
#[test]
fn the_remote_filter_admits_by_scope() {
    let same = same_site();
    let wide = internet();
    for (addr, same_want, wide_want) in [
        ("192.168.77.20:50417", Ok(()), Ok(())),
        ("192.168.1.20:50417", Err(Refusal::Scope), Ok(())),
        ("10.0.0.7:50417", Err(Refusal::Scope), Ok(())),
        ("172.17.0.2:50417", Err(Refusal::Scope), Ok(())),
        ("[fd12:3456:789a:1::20]:50417", Ok(()), Ok(())),
        ("[fd12:3456:789a:ff::20]:50417", Ok(()), Ok(())),
        ("[fd12:3456:789b::20]:50417", Err(Refusal::Scope), Ok(())),
        ("[fd99::20]:50417", Err(Refusal::Scope), Ok(())),
        ("8.8.8.8:50417", Err(Refusal::Scope), Ok(())),
        ("[2606:4700:4700::1111]:50417", Err(Refusal::Scope), Ok(())),
        // Classes no scope admits.
        ("100.64.1.2:50417", Err(Refusal::Class), Err(Refusal::Class)),
        (
            "169.254.7.7:50417",
            Err(Refusal::Class),
            Err(Refusal::Class),
        ),
        ("127.0.0.7:50417", Err(Refusal::Class), Err(Refusal::Class)),
        ("[::1]:50417", Err(Refusal::Class), Err(Refusal::Class)),
        ("[fe80::7]:50417", Err(Refusal::Class), Err(Refusal::Class)),
        (
            "224.0.0.251:50417",
            Err(Refusal::Class),
            Err(Refusal::Class),
        ),
        ("[ff02::fb]:50417", Err(Refusal::Class), Err(Refusal::Class)),
        (
            "[64:ff9b::808:808]:50417",
            Err(Refusal::Class),
            Err(Refusal::Class),
        ),
        ("192.0.2.7:50417", Err(Refusal::Class), Err(Refusal::Class)),
        (
            "198.51.100.7:50417",
            Err(Refusal::Class),
            Err(Refusal::Class),
        ),
        (
            "203.0.113.7:50417",
            Err(Refusal::Class),
            Err(Refusal::Class),
        ),
        (
            "[2001:db8::7]:50417",
            Err(Refusal::Class),
            Err(Refusal::Class),
        ),
        ("[2001::7]:50417", Err(Refusal::Class), Err(Refusal::Class)),
        (
            "[2002:c000:204::1]:50417",
            Err(Refusal::Class),
            Err(Refusal::Class),
        ),
        ("[3fff::7]:50417", Err(Refusal::Class), Err(Refusal::Class)),
        ("0.0.0.0:50417", Err(Refusal::Class), Err(Refusal::Class)),
        (
            "255.255.255.255:50417",
            Err(Refusal::Class),
            Err(Refusal::Class),
        ),
    ] {
        assert_eq!(same.check(sa(addr)), same_want, "same-site {addr}");
        assert_eq!(wide.check(sa(addr)), wide_want, "internet {addr}");
        assert_eq!(same.admit(sa(addr)), same_want.is_ok());
    }
    // A v4-mapped remote is judged as its IPv4 address.
    assert_eq!(same.check(sa("[::ffff:192.168.77.20]:50417")), Ok(()));
    assert_eq!(
        same.check(sa("[::ffff:192.168.1.20]:50417")),
        Err(Refusal::Scope)
    );
}

/// Design §7.7: our own addresses, and the network and broadcast addresses
/// of every prefix of ours (offered or not), are refused.
#[test]
fn own_network_and_broadcast_addresses_are_refused() {
    let wide = internet();
    for addr in [
        "192.168.77.203:50417",
        "[::ffff:192.168.77.203]:50417",
        "172.17.0.1:50417",
        "[fd12:3456:789a:1::203]:50417",
        "[2001:470:1:2:a1b2:c3d4:e5f6:7788]:50417",
    ] {
        assert_eq!(wide.check(sa(addr)), Err(Refusal::Own), "{addr}");
    }
    for addr in [
        "192.168.77.0:50417",
        "192.168.77.255:50417",
        "172.17.0.0:50417",
        "172.17.255.255:50417",
        "[fd12:3456:789a:1::]:50417",
    ] {
        assert_eq!(
            wide.check(sa(addr)),
            Err(Refusal::NetworkOrBroadcast),
            "{addr}"
        );
    }
    assert_eq!(wide.check(sa("172.17.255.254:50417")), Ok(()));
    // A /31 has neither a network nor a broadcast address (RFC 3021).
    let p2p = RemoteFilter {
        local_nets: vec![net("10.9.9.0/31")],
        on_link: vec![net("10.9.9.0/31")],
        own: vec![v4("10.9.9.0")],
        ..same_site()
    };
    assert_eq!(p2p.check(sa("10.9.9.1:50417")), Ok(()));
}

/// Design §7.7: port ≥ 1024 and never SSDP, PCP/NAT-PMP, mDNS or LLMNR.
#[test]
fn the_remote_filter_refuses_privileged_and_service_ports() {
    let same = same_site();
    for port in [0, 1, 53, 80, 443, 1023, 1900, 5351, 5353, 5355] {
        let addr = SocketAddr::new(v4("192.168.77.20"), port);
        assert_eq!(same.check(addr), Err(Refusal::Port), "{port}");
    }
    for port in [1024, 1901, 3478, 5350, 5352, 5354, 5356, 50417, 65535] {
        let addr = SocketAddr::new(v4("192.168.77.20"), port);
        assert_eq!(same.check(addr), Ok(()), "{port}");
    }
}

/// Design §7.2 and §7.7: a global IPv6 remote needs an offered global IPv6
/// (`have_v6`), and the VPN rule's `global_families` keeps global remotes
/// of a family off; IPv6 needs a dual-stack socket and a ULA remote an
/// offered ULA.
#[test]
fn the_remote_filter_follows_families_and_the_vpn_rule() {
    let g4 = sa("8.8.8.8:50417");
    let g6 = sa("[2606:4700:4700::1111]:50417");
    let wide = internet();
    assert_eq!(wide.check(g4), Ok(()));
    assert_eq!(wide.check(g6), Ok(()));
    let no_v6 = RemoteFilter {
        have_v6: false,
        ..internet()
    };
    assert_eq!(no_v6.check(g6), Err(Refusal::Family));
    assert_eq!(no_v6.check(sa("[fd99::20]:50417")), Ok(()));
    let v4_tunnel = RemoteFilter {
        global_families: (true, false),
        ..internet()
    };
    assert_eq!(v4_tunnel.check(g4), Ok(()));
    assert_eq!(v4_tunnel.check(g6), Err(Refusal::Vpn));
    let v6_tunnel = RemoteFilter {
        global_families: (false, true),
        ..internet()
    };
    assert_eq!(v6_tunnel.check(g4), Err(Refusal::Vpn));
    assert_eq!(v6_tunnel.check(g6), Ok(()));
    // Private and ULA remotes are not global: the VPN rule leaves them.
    let neither = RemoteFilter {
        global_families: (false, false),
        ..internet()
    };
    assert_eq!(neither.check(sa("10.0.0.7:50417")), Ok(()));
    assert_eq!(neither.check(sa("[fd99::20]:50417")), Ok(()));
    let v4_socket = RemoteFilter {
        dual_stack: false,
        ..internet()
    };
    assert_eq!(v4_socket.check(g6), Err(Refusal::Family));
    assert_eq!(
        v4_socket.check(sa("[fd12:3456:789a:1::20]:50417")),
        Err(Refusal::Family)
    );
    assert_eq!(v4_socket.check(g4), Ok(()));
    let no_ula = RemoteFilter {
        own_ula48: None,
        ..internet()
    };
    assert_eq!(
        no_ula.check(sa("[fd12:3456:789a:1::20]:50417")),
        Err(Refusal::Family)
    );
    let no_v4 = RemoteFilter {
        have_v4: false,
        ..internet()
    };
    assert_eq!(no_v4.check(g4), Err(Refusal::Family));
    assert_eq!(no_v4.check(sa("192.168.77.20:50417")), Err(Refusal::Family));
}

/// `admit_loopback` (test environments only) lets a loopback remote pass on
/// the port and own-address rules, in either scope.
#[test]
fn loopback_passes_only_where_the_environment_admits_it() {
    let lo = RemoteFilter {
        admit_loopback: true,
        own: vec![v4("127.0.0.2")],
        local_nets: vec![],
        ..same_site()
    };
    assert_eq!(lo.check(sa("127.0.0.3:50417")), Ok(()));
    assert_eq!(lo.check(sa("[::1]:50417")), Ok(()));
    assert_eq!(lo.check(sa("127.0.0.2:50417")), Err(Refusal::Own));
    assert_eq!(lo.check(sa("127.0.0.3:1023")), Err(Refusal::Port));
    assert_eq!(lo.check(sa("169.254.0.3:50417")), Err(Refusal::Class));
    assert_eq!(
        same_site().check(sa("127.0.0.3:50417")),
        Err(Refusal::Class)
    );
}

#[test]
fn on_site_is_on_link_private_or_own_ula48_never_the_class_alone() {
    let f = internet();
    assert!(f.on_site(v4("192.168.77.20")));
    assert!(f.on_site(v6("::ffff:192.168.77.20")));
    assert!(!f.on_site(v4("192.168.1.20")));
    assert!(!f.on_site(v4("10.0.0.7")));
    assert!(f.on_site(v6("fd12:3456:789a:ff::1")));
    assert!(!f.on_site(v6("fd99::1")));
    assert!(!f.on_site(v4("8.8.8.8")));
    // A global prefix in `on_link` does not make a global remote same-site.
    let public_lan = RemoteFilter {
        on_link: vec![net("8.8.8.0/24")],
        ..internet()
    };
    assert!(!public_lan.on_site(v4("8.8.8.9")));
}

/// Design §5.3: global IPv4 with any port but 0 (`:443` and `:3478` both
/// pass), never a private, own or loopback address (unless the test
/// environment admits loopback), never IPv6.
#[test]
fn the_stun_filter_admits_global_v4_servers_on_any_port() {
    let f = StunFilter {
        have_v4: true,
        own: vec![v4("192.168.77.203"), v4("8.8.4.4")],
        admit_loopback: false,
    };
    assert_eq!(f.check(sa("162.159.207.0:3478")), Ok(()));
    assert_eq!(f.check(sa("74.125.250.129:19302")), Ok(()));
    assert_eq!(f.check(sa("74.125.250.129:443")), Ok(()));
    assert_eq!(f.check(sa("74.125.250.129:53")), Ok(()));
    assert_eq!(f.check(sa("[::ffff:74.125.250.129]:3478")), Ok(()));
    assert_eq!(f.check(sa("74.125.250.129:0")), Err(Refusal::Port));
    assert_eq!(f.check(sa("192.168.77.1:3478")), Err(Refusal::Class));
    assert_eq!(f.check(sa("10.0.0.1:3478")), Err(Refusal::Class));
    assert_eq!(f.check(sa("100.64.0.1:3478")), Err(Refusal::Class));
    assert_eq!(f.check(sa("127.0.0.1:3478")), Err(Refusal::Class));
    assert_eq!(f.check(sa("192.0.2.1:3478")), Err(Refusal::Class));
    assert_eq!(f.check(sa("8.8.4.4:3478")), Err(Refusal::Own));
    assert_eq!(
        f.check(sa("[2001:4860:4864:5:8000::1]:3478")),
        Err(Refusal::Family)
    );
    let no_v4 = StunFilter {
        have_v4: false,
        ..f.clone()
    };
    assert_eq!(no_v4.check(sa("162.159.207.0:3478")), Err(Refusal::Family));
    let lo = StunFilter {
        admit_loopback: true,
        ..f
    };
    assert_eq!(lo.check(sa("127.0.0.1:3478")), Ok(()));
    assert!(lo.admit(sa("127.0.0.1:3478")));
}

/// Pieces of the test addresses that must not appear in any `Debug` or
/// `Display` text (decision M1-83, design §12.1 "Telemetry").
const PIECES: [&str; 12] = [
    "192", "168", "77", "203", "50417", "c0a8", "4dcb", "fd12", "3456", "789a", "2606", "4700",
];

fn assert_redacted(text: &str) {
    for piece in PIECES {
        assert!(!text.contains(piece), "\"{piece}\" in {text}");
    }
}

#[test]
fn redacted_output_names_the_family_and_class_only() {
    for (addr, want) in [
        ("192.168.77.203:50417", "v4 private"),
        ("[::ffff:192.168.77.203]:50417", "v4 private"),
        ("[fd12:3456:789a:1::203]:50417", "v6 unique-local"),
        ("[2606:4700:4700::1111]:50417", "v6 global"),
        ("203.0.113.77:50417", "v4 unusable"),
    ] {
        let addr = sa(addr);
        assert_eq!(Redacted(&addr).to_string(), want);
        assert_eq!(format!("{:?}", Redacted(&addr)), want);
        assert_eq!(RedactedIp(addr.ip()).to_string(), want);
        assert_redacted(&format!("{} {:?}", Redacted(&addr), RedactedIp(addr.ip())));
    }
}

#[test]
fn types_that_carry_addresses_debug_without_them() {
    for addr in [
        "192.168.77.203:50417",
        "[fd12:3456:789a:1::203]:50417",
        "[2606:4700:4700::1111]:50417",
    ] {
        let c = Candidate {
            kind: CandidateKind::Host,
            addr: sa(addr),
        };
        let text = format!("{c:?} {c:#?}");
        assert_redacted(&text);
        assert!(text.contains("Host"), "{text}");
    }
    let text = format!("{:?} {:#?}", internet(), internet());
    assert_redacted(&text);
    assert!(
        text.contains("Internet") && text.contains("5 addresses"),
        "{text}"
    );
    let stun = StunFilter {
        have_v4: true,
        own: vec![v4("192.168.77.203")],
        admit_loopback: false,
    };
    let text = format!("{stun:?}");
    assert_redacted(&text);
    assert!(text.contains("1 addresses"), "{text}");
}

#[test]
fn scope_orders_same_site_below_internet() {
    assert!(Scope::SameSite < Scope::Internet);
    assert_eq!(Scope::SameSite.min(Scope::Internet), Scope::SameSite);
    assert_eq!(
        [
            CandidateKind::Host,
            CandidateKind::Srflx,
            CandidateKind::Mapped,
            CandidateKind::Prflx
        ]
        .map(CandidateKind::name),
        ["host", "srflx", "mapped", "prflx"]
    );
}

fn any_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<u32>().prop_map(|n| IpAddr::V4(Ipv4Addr::from(n))),
        any::<u128>().prop_map(|n| IpAddr::V6(Ipv6Addr::from(n))),
        // Addresses near the interesting prefixes, so the rules are hit.
        (0u8..8, any::<u16>()).prop_map(|(i, low)| {
            let [a, b] = low.to_be_bytes();
            let ip = match i {
                0 => [192, 168, 77, a],
                1 => [192, 168, a, b],
                2 => [10, a, b, 7],
                3 => [100, 64 + (a & 63), b, 1],
                4 => [172, 17, a, b],
                5 => [127, 0, a, b],
                6 => [169, 254, a, b],
                _ => [8, 8, a, b],
            };
            IpAddr::V4(Ipv4Addr::from(ip))
        }),
        (0u8..6, any::<u64>()).prop_map(|(i, low)| {
            let high: u64 = match i {
                0 => 0xfd12_3456_789a_0001,
                1 => 0xfd12_3456_789b_0000,
                2 => 0x2606_4700_4700_0000,
                3 => 0x2001_0db8_0000_0000,
                4 => 0xfe80_0000_0000_0000,
                _ => 0x0000_0000_0000_0000,
            };
            IpAddr::V6(Ipv6Addr::from((u128::from(high) << 64) | u128::from(low)))
        }),
        any::<u32>().prop_map(|n| IpAddr::V6(Ipv4Addr::from(n).to_ipv6_mapped())),
    ]
}

fn any_port() -> impl Strategy<Value = u16> {
    prop_oneof![
        any::<u16>(),
        Just(1900u16),
        Just(5351),
        Just(5353),
        Just(5355),
        0u16..1100
    ]
}

proptest! {
    /// Whatever a peer sends, an admitted address has an allowed port, is
    /// not ours, has a class the scope admits, is on site in same-site
    /// scope, and is never loopback, link-local, CGNAT or unusable.
    #[test]
    fn an_admitted_remote_keeps_every_rule(ip in any_ip(), port in any_port(), wide in any::<bool>()) {
        let filter = if wide { internet() } else { same_site() };
        let addr = SocketAddr::new(ip, port);
        if filter.admit(addr) {
            let c = canon(addr);
            prop_assert!(c.port() >= MIN_REMOTE_PORT);
            prop_assert!(!REFUSED_PORTS.contains(&c.port()));
            prop_assert!(!filter.own.iter().any(|own| canon_ip(*own) == c.ip()));
            let class = class(c.ip());
            prop_assert!(matches!(class, AddrClass::Private | AddrClass::UniqueLocal | AddrClass::Global));
            if !wide {
                prop_assert!(filter.on_site(c.ip()));
            }
        }
    }

    #[test]
    fn canon_inverts_the_socket_family(ip in any_ip(), port in any::<u16>(), dual in any::<bool>()) {
        let addr = canon(SocketAddr::new(ip, port));
        prop_assert_eq!(canon(to_socket_family(addr, dual)), addr);
        prop_assert_eq!(canon(canon(addr)), addr);
        if dual {
            prop_assert!(to_socket_family(addr, dual).is_ipv6());
        } else {
            prop_assert_eq!(to_socket_family(addr, dual), addr);
        }
    }

    #[test]
    fn redacted_text_holds_no_digit_beyond_the_family(ip in any_ip(), port in any::<u16>()) {
        let addr = SocketAddr::new(ip, port);
        let text = Redacted(&addr).to_string();
        let digits: String = text.chars().filter(char::is_ascii_digit).collect();
        prop_assert!(digits == "4" || digits == "6", "{}", text);
    }
}
