//! The gathering plan as a table (design §7.3 "When it runs", §7.4
//! "Preconditions", §5.3 "STUN is skipped entirely when", §7.2): pure, no
//! runtime.

use super::*;

use crate::local::vpn_mode;

/// An address of an up, usable interface `index` of `kind`, with
/// `gateway` as its IPv4 gateway.
fn addr_on(
    ip: &str,
    prefix_len: u8,
    index: u32,
    kind: IfaceKind,
    gateway: Option<&str>,
) -> IfaceAddr {
    let ip: IpAddr = ip.parse().expect("an address");
    IfaceAddr {
        ip,
        prefix_len,
        class: class(ip),
        temporary: false,
        deprecated: false,
        tentative: false,
        duplicated: false,
        eui64: false,
        iface_index: index,
        iface_kind: kind,
        up: true,
        gateway_v4: gateway.map(|g| g.parse().expect("an IPv4 address")),
    }
}

fn v4(text: &str) -> Ipv4Addr {
    text.parse().expect("an IPv4 address")
}

fn sources(v4_src: Option<&str>, v6_src: Option<&str>) -> RouteSources {
    RouteSources {
        v4: v4_src.map(v4),
        v6: v6_src.map(|s| s.parse().expect("an IPv6 address")),
    }
}

fn everything() -> GatherConfig {
    GatherConfig {
        stun_partition: strings(&["stun.example.net:3478", "198.51.7.1:3478"]).into(),
        use_stun: true,
        map: MapProtocols::ALL,
    }
}

/// One machine: its addresses and route sources.
struct Machine {
    addrs: Vec<IfaceAddr>,
    sources: RouteSources,
}

impl Machine {
    fn vpn(&self) -> bool {
        vpn_mode(&self.addrs, &self.sources)
    }

    /// Its host candidates in `scope` (port 0), as the link passes them.
    fn hosts(&self, scope: Scope) -> Vec<SocketAddr> {
        crate::local::select_host_candidates(&self.addrs, &self.sources, 0, scope, self.vpn())
            .into_iter()
            .map(|c| c.addr)
            .collect()
    }

    fn plan(&self, config: &GatherConfig, scope: Scope, admit_loopback: bool) -> GatherPlan {
        plan(
            config,
            scope,
            &self.addrs,
            &self.sources,
            self.vpn(),
            &self.hosts(scope),
            admit_loopback,
        )
    }
}

/// A home computer behind a router: 192.168.1.20 on Wi-Fi, gateway
/// 192.168.1.1, with a global IPv6 on the same interface.
fn home() -> Machine {
    Machine {
        addrs: vec![
            addr_on(
                "192.168.1.20",
                24,
                2,
                IfaceKind::Physical,
                Some("192.168.1.1"),
            ),
            addr_on("2a01:4f8:1:2::20", 64, 2, IfaceKind::Physical, None),
        ],
        sources: sources(Some("192.168.1.20"), Some("2a01:4f8:1:2::20")),
    }
}

/// What a plan asks, in one line of the table: (STUN base, map target,
/// head start in ms).
fn asks(plan: &GatherPlan) -> (Option<Ipv4Addr>, Option<(Ipv4Addr, Ipv4Addr)>, u64) {
    (
        plan.stun.as_ref().map(|s| s.base),
        plan.map.map(|m| (m.gateway, m.client)),
        u64::try_from(plan.head_start.as_millis()).unwrap(),
    )
}

/// The plan, case by case.
#[test]
fn the_plan_follows_the_design_table() {
    let all = everything();
    let stun_only = GatherConfig {
        map: MapProtocols::NONE,
        ..everything()
    };
    let map_only = GatherConfig {
        use_stun: false,
        ..everything()
    };
    let no_servers = GatherConfig {
        stun_partition: Arc::from(Vec::<String>::new()),
        map: MapProtocols::NONE,
        ..everything()
    };
    let pcp_only = GatherConfig {
        map: MapProtocols {
            upnp: false,
            nat_pmp: false,
            pcp: true,
        },
        ..everything()
    };
    let home_router = Some((v4("192.168.1.1"), v4("192.168.1.20")));
    let base = Some(v4("192.168.1.20"));
    let cgnat = Machine {
        addrs: vec![addr_on(
            "100.64.7.9",
            10,
            3,
            IfaceKind::Physical,
            Some("100.64.0.1"),
        )],
        sources: sources(Some("100.64.7.9"), None),
    };
    let public_v4 = Machine {
        addrs: vec![addr_on(
            "81.2.69.142",
            24,
            2,
            IfaceKind::Physical,
            Some("81.2.69.1"),
        )],
        sources: sources(Some("81.2.69.142"), None),
    };
    let global_gateway = Machine {
        addrs: vec![addr_on(
            "192.168.1.20",
            24,
            2,
            IfaceKind::Physical,
            Some("81.2.69.1"),
        )],
        sources: sources(Some("192.168.1.20"), None),
    };
    let no_gateway = Machine {
        addrs: vec![addr_on("192.168.1.20", 24, 2, IfaceKind::Physical, None)],
        sources: sources(Some("192.168.1.20"), None),
    };
    let v6_only = Machine {
        addrs: vec![addr_on(
            "2a01:4f8:1:2::20",
            64,
            2,
            IfaceKind::Physical,
            None,
        )],
        sources: sources(None, Some("2a01:4f8:1:2::20")),
    };
    // A full tunnel: both families leave through it.
    let full_tunnel = Machine {
        addrs: vec![
            addr_on(
                "192.168.1.20",
                24,
                2,
                IfaceKind::Physical,
                Some("192.168.1.1"),
            ),
            addr_on("10.8.0.2", 24, 9, IfaceKind::Tunnel, Some("10.8.0.1")),
        ],
        sources: sources(Some("10.8.0.2"), None),
    };
    // Split families: IPv4 through the tunnel, IPv6 physical.
    let v4_tunnel = Machine {
        addrs: vec![
            addr_on(
                "192.168.1.20",
                24,
                2,
                IfaceKind::Physical,
                Some("192.168.1.1"),
            ),
            addr_on("2a01:4f8:1:2::20", 64, 2, IfaceKind::Physical, None),
            addr_on("10.8.0.2", 24, 9, IfaceKind::Tunnel, Some("10.8.0.1")),
        ],
        sources: sources(Some("10.8.0.2"), Some("2a01:4f8:1:2::20")),
    };
    // Split families the other way: IPv6 through the tunnel, IPv4 physical.
    let v6_tunnel = Machine {
        addrs: vec![
            addr_on(
                "192.168.1.20",
                24,
                2,
                IfaceKind::Physical,
                Some("192.168.1.1"),
            ),
            addr_on("fd00:8::2", 64, 9, IfaceKind::Tunnel, None),
        ],
        sources: sources(Some("192.168.1.20"), Some("fd00:8::2")),
    };
    let loopback = Machine {
        addrs: vec![addr_on(
            "127.0.0.1",
            8,
            1,
            IfaceKind::Physical,
            Some("127.0.0.53"),
        )],
        sources: sources(Some("127.0.0.1"), None),
    };

    let table: [(&str, &Machine, &GatherConfig, Scope, bool, _); 20] = [
        (
            "same-site scope asks nobody",
            &home(),
            &all,
            Scope::SameSite,
            false,
            (None, None, 0),
        ),
        (
            "both, the router first",
            &home(),
            &all,
            Scope::Internet,
            false,
            (base, home_router, 250),
        ),
        (
            "STUN alone waits for nothing",
            &home(),
            &stun_only,
            Scope::Internet,
            false,
            (base, None, 0),
        ),
        (
            "the router alone",
            &home(),
            &map_only,
            Scope::Internet,
            false,
            (None, home_router, 0),
        ),
        (
            "one protocol is enough",
            &home(),
            &pcp_only,
            Scope::Internet,
            false,
            (base, home_router, 250),
        ),
        (
            "an empty part of the list",
            &home(),
            &no_servers,
            Scope::Internet,
            false,
            (None, None, 0),
        ),
        (
            "a carrier-grade NAT base and gateway",
            &cgnat,
            &all,
            Scope::Internet,
            false,
            (
                Some(v4("100.64.7.9")),
                Some((v4("100.64.0.1"), v4("100.64.7.9"))),
                250,
            ),
        ),
        (
            "a public IPv4 host needs neither",
            &public_v4,
            &all,
            Scope::Internet,
            false,
            (None, None, 0),
        ),
        (
            "a global gateway is no home router",
            &global_gateway,
            &all,
            Scope::Internet,
            false,
            (base, None, 0),
        ),
        (
            "no gateway read",
            &no_gateway,
            &all,
            Scope::Internet,
            false,
            (base, None, 0),
        ),
        (
            "no IPv4 route",
            &v6_only,
            &all,
            Scope::Internet,
            false,
            (None, None, 0),
        ),
        (
            "a full tunnel: STUN from the tunnel, no router",
            &full_tunnel,
            &all,
            Scope::Internet,
            false,
            (Some(v4("10.8.0.2")), None, 0),
        ),
        (
            "IPv4 through the tunnel: STUN from it, no router",
            &v4_tunnel,
            &all,
            Scope::Internet,
            false,
            (Some(v4("10.8.0.2")), None, 0),
        ),
        (
            "IPv4 outside the tunnel: neither",
            &v6_tunnel,
            &all,
            Scope::Internet,
            false,
            (None, None, 0),
        ),
        (
            "a loopback base outside tests",
            &loopback,
            &all,
            Scope::Internet,
            false,
            (None, None, 0),
        ),
        (
            "a loopback base in a test environment",
            &loopback,
            &all,
            Scope::Internet,
            true,
            (
                Some(v4("127.0.0.1")),
                Some((v4("127.0.0.53"), v4("127.0.0.1"))),
                250,
            ),
        ),
        (
            "same-site scope in a test environment",
            &loopback,
            &all,
            Scope::SameSite,
            true,
            (None, None, 0),
        ),
        (
            "same-site scope behind a carrier",
            &cgnat,
            &all,
            Scope::SameSite,
            false,
            (None, None, 0),
        ),
        (
            "same-site scope in a tunnel",
            &full_tunnel,
            &all,
            Scope::SameSite,
            false,
            (None, None, 0),
        ),
        (
            "nothing on",
            &home(),
            &GatherConfig::default(),
            Scope::Internet,
            false,
            (None, None, 0),
        ),
    ];
    for (case, machine, config, scope, admit, want) in table {
        let plan = machine.plan(config, scope, admit);
        assert_eq!(asks(&plan), want, "{case}");
        assert_eq!(
            plan.gathers(),
            want.0.is_some() || want.1.is_some(),
            "{case}"
        );
        assert_eq!(plan.scope, scope, "{case}");
        assert_eq!(plan.vpn, machine.vpn(), "{case}");
        assert_eq!(plan.budget, GATHER_BUDGET, "{case}");
        if let Some(stun) = &plan.stun {
            assert_eq!(&*stun.servers, &*config.stun_partition, "{case}");
        }
        if let Some(map) = plan.map {
            assert_eq!(map.protocols, config.map, "{case}");
        }
    }
}

/// Design §7.2 "Structural rule": in internet scope the global host
/// candidates come only from their family's route-source interface and
/// never in VPN mode, so a split tunnel cannot offer the physical
/// interface's global IPv6.
#[test]
fn global_host_candidates_follow_the_route_sources_and_the_vpn_rule() {
    let globals = |m: &Machine| -> Vec<IpAddr> {
        m.hosts(Scope::Internet)
            .into_iter()
            .map(|h| h.ip())
            .filter(|ip| class(*ip) == AddrClass::Global)
            .collect()
    };
    assert_eq!(globals(&home()), vec![ip("2a01:4f8:1:2::20")]);
    assert!(home().hosts(Scope::SameSite).iter().all(|h| h.is_ipv4()));

    // A second physical interface's global addresses are never offered.
    let two_nics = Machine {
        addrs: vec![
            addr_on(
                "192.168.1.20",
                24,
                2,
                IfaceKind::Physical,
                Some("192.168.1.1"),
            ),
            addr_on("81.2.69.142", 24, 3, IfaceKind::Physical, None),
            addr_on("2a01:4f8:9:9::5", 64, 3, IfaceKind::Physical, None),
        ],
        sources: sources(Some("192.168.1.20"), None),
    };
    assert!(globals(&two_nics).is_empty());

    // VPN mode, either way round: no global host at all.
    let v4_tunnel = Machine {
        addrs: vec![
            addr_on(
                "192.168.1.20",
                24,
                2,
                IfaceKind::Physical,
                Some("192.168.1.1"),
            ),
            addr_on("2a01:4f8:1:2::20", 64, 2, IfaceKind::Physical, None),
            addr_on("10.8.0.2", 24, 9, IfaceKind::Tunnel, None),
        ],
        sources: sources(Some("10.8.0.2"), Some("2a01:4f8:1:2::20")),
    };
    assert!(v4_tunnel.vpn());
    assert!(globals(&v4_tunnel).is_empty());
    // The physical LAN's private address is still offered.
    assert_eq!(v4_tunnel.hosts(Scope::Internet), vec![at("192.168.1.20:0")]);

    // The families leave by different physical interfaces: VPN mode too.
    let split = Machine {
        addrs: vec![
            addr_on(
                "192.168.1.20",
                24,
                2,
                IfaceKind::Physical,
                Some("192.168.1.1"),
            ),
            addr_on("2a01:4f8:9:9::5", 64, 3, IfaceKind::Physical, None),
        ],
        sources: sources(Some("192.168.1.20"), Some("2a01:4f8:9:9::5")),
    };
    assert!(split.vpn());
    assert!(globals(&split).is_empty());

    // The public IPv4 of the route source's interface.
    let public = Machine {
        addrs: vec![addr_on(
            "81.2.69.142",
            24,
            2,
            IfaceKind::Physical,
            Some("81.2.69.1"),
        )],
        sources: sources(Some("81.2.69.142"), None),
    };
    assert_eq!(globals(&public), vec![ip("81.2.69.142")]);
    assert!(public.hosts(Scope::SameSite).is_empty());
}

/// Decision M1-83: a plan, its parts and the settings print classes and
/// counts, never an address or a server's name.
#[test]
fn no_plan_prints_an_address() {
    let plan = home().plan(&everything(), Scope::Internet, false);
    assert!(plan.stun.is_some() && plan.map.is_some());
    let printed = format!("{plan:?} {:?} {:?}", everything(), GatherStats::default());
    for secret in ["192.168", "2a01", "stun.example", "198.51", "3478"] {
        assert!(!printed.contains(secret), "{secret} in {printed}");
    }
}
