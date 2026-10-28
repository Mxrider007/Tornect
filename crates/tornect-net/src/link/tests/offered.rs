//! Design §5.2 rule 7 and §7.1: the IPv6 host candidates a link offers are
//! the addresses its socket sends from (the step A12 finding of the second
//! unique-local address, settled at the feature's close).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use proptest::prelude::*;
use proptest::sample::Index;

use super::*;
use crate::addr::{class, is_eui64};
use crate::local::{IfaceAddr, IfaceKind, MAX_ULA, RouteSources};

fn addr(ip: IpAddr, prefix_len: u8, iface_index: u32, temporary: bool) -> IfaceAddr {
    IfaceAddr {
        ip,
        prefix_len,
        class: class(ip),
        temporary,
        deprecated: false,
        tentative: false,
        duplicated: false,
        eui64: match ip {
            IpAddr::V6(v6) => is_eui64(v6),
            IpAddr::V4(_) => false,
        },
        iface_index,
        iface_kind: IfaceKind::Physical,
        up: true,
        gateway_v4: None,
    }
}

/// One address of up to four physical interfaces: a private IPv4 on one of
/// three /24s, a unique-local address in one of three /48s (two /64s
/// each), or a global IPv6 on one of two /64s; temporary or not.
fn arb_addr() -> impl Strategy<Value = IfaceAddr> {
    let v4 = (0u8..3, 1u8..250)
        .prop_map(|(net, host)| (IpAddr::V4(Ipv4Addr::new(192, 168, net, host)), 24, false));
    let ula = (0u16..3, 0u16..2, 1u16..5, any::<bool>()).prop_map(|(site, subnet, host, temp)| {
        let ip = Ipv6Addr::new(0xfd12, 0x3456, 0x7800 + site, subnet, 0, 0, 0, host);
        (IpAddr::V6(ip), 64, temp)
    });
    let global = (0u16..2, 1u16..5, any::<bool>()).prop_map(|(net, host, temp)| {
        let ip = Ipv6Addr::new(0x2001, 0x470, 1, net, 0, 0, 0, host);
        (IpAddr::V6(ip), 64, temp)
    });
    (prop_oneof![v4, ula, global], 1u32..5)
        .prop_map(|((ip, len, temp), iface)| addr(ip, len, iface, temp))
}

/// The route sources: one address of each family from the set, or none.
fn pick(addrs: &[IfaceAddr], v4: bool, which: Option<Index>) -> Option<IpAddr> {
    let family: Vec<IpAddr> = addrs
        .iter()
        .map(|a| a.ip)
        .filter(|ip| ip.is_ipv4() == v4)
        .collect();
    which
        .filter(|_| !family.is_empty())
        .map(|i| family[i.index(family.len())])
}

proptest! {
    /// Whatever the interfaces, the route sources and the scope: at most
    /// [`MAX_ULA`] unique-local candidates; every offered IPv6 candidate is
    /// one of the socket's sources ([`V6Sources::offers`]), the one a
    /// datagram to its class leaves from; and every offered unique-local
    /// one lies in the /48 the remote filter takes as this side's own. As
    /// [`DirectLink::start`] composes them, on a dual-stack socket.
    #[test]
    fn every_offered_ipv6_candidate_is_one_the_link_sends_from(
        addrs in proptest::collection::vec(arb_addr(), 0..10),
        v4 in proptest::option::of(any::<Index>()),
        v6 in proptest::option::of(any::<Index>()),
        internet in any::<bool>(),
    ) {
        let sources = RouteSources {
            v4: pick(&addrs, true, v4).and_then(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            }),
            v6: pick(&addrs, false, v6).and_then(|ip| match ip {
                IpAddr::V6(v6) => Some(v6),
                IpAddr::V4(_) => None,
            }),
        };
        let scope = if internet { Scope::Internet } else { Scope::SameSite };
        let vpn = local::vpn_mode(&addrs, &sources);
        let offered = local::select_host_candidates(&addrs, &sources, 50417, scope, vpn);
        let lookup: crate::RouteLookup = Arc::new(|_: SocketAddr| None);
        let filter = local::remote_filter(
            scope,
            &addrs,
            &sources,
            &offered,
            true,
            vpn.then_some(lookup),
            false,
        );
        let v6 = v6_sources(&offered);

        let ulas: Vec<Ipv6Addr> = offered
            .iter()
            .filter_map(|c| match c.addr.ip() {
                IpAddr::V6(ip) if class(c.addr.ip()) == AddrClass::UniqueLocal => Some(ip),
                _ => None,
            })
            .collect();
        prop_assert!(ulas.len() <= MAX_ULA);
        for ula in &ulas {
            prop_assert!(filter.own_ula48.is_some_and(|own| own.contains(ula)));
        }
        for c in &offered {
            if let IpAddr::V6(ip) = c.addr.ip() {
                prop_assert!(v6.offers(ip));
                prop_assert_eq!(v6.for_destination(ip), Some(ip));
            }
        }
    }
}

/// The step A12 finding as it was: Wi-Fi and Ethernet each with a
/// unique-local address of its own /48. Both were offered while only the
/// first could be a source or in the filter's /48; one is offered now, the
/// route source interface's temporary one.
#[test]
fn two_interfaces_with_their_own_ula_offer_only_the_route_sources() {
    let wifi = Ipv6Addr::new(0xfd12, 0x3456, 0x7801, 1, 0, 0, 0, 9);
    let ethernet = Ipv6Addr::new(0xfd34, 0x5678, 0x9a02, 2, 0, 0, 0, 7);
    let addrs = [
        addr(
            IpAddr::V6(Ipv6Addr::new(0xfd12, 0x3456, 0x7801, 1, 0, 0, 0, 3)),
            64,
            2,
            false,
        ),
        addr(IpAddr::V6(wifi), 64, 2, true),
        addr(IpAddr::V6(ethernet), 64, 3, true),
    ];
    let sources = RouteSources {
        v4: None,
        v6: Some(Ipv6Addr::new(0xfd12, 0x3456, 0x7801, 1, 0, 0, 0, 3)),
    };
    for scope in [Scope::SameSite, Scope::Internet] {
        let offered = local::select_host_candidates(&addrs, &sources, 50417, scope, false);
        let ips: Vec<IpAddr> = offered.iter().map(|c| c.addr.ip()).collect();
        assert_eq!(ips, [IpAddr::V6(wifi)], "{scope:?}");
        let filter = local::remote_filter(scope, &addrs, &sources, &offered, true, None, false);
        assert!(filter.own_ula48.is_some_and(|own| own.contains(&wifi)));
        assert!(!filter.own_ula48.is_some_and(|own| own.contains(&ethernet)));
        let v6 = v6_sources(&offered);
        assert!(v6.offers(wifi) && !v6.offers(ethernet));
    }
}
