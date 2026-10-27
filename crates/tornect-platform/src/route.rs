//! The IPv4 default gateway of a network interface: the router a port
//! mapping is asked of (design `direct` §7.1, §7.4, §8.6; decision M1-81).
//!
//! On Windows it comes from `GetBestRoute2`, a lookup in the IP routing
//! table. netdev's own Windows gateway read may send ARP through `SendARP`
//! (`netdev-0.46.3/src/os/windows/interface.rs`), so `tornect-net` never
//! compiles it there and the app hands `default_gateway_v4` (Windows only,
//! so not linked from the documentation built elsewhere) to its `RealNet`
//! instead. On Linux and macOS `tornect-net` reads the gateway
//! through netdev, which takes it from the kernel's tables; only the rule
//! of [`usable_gateway`] is shared. docs/research/nat-traversal.md §1.6
//! and §5.

use std::net::Ipv4Addr;

#[cfg(windows)]
pub use crate::route_windows::default_gateway_v4;

/// The destination whose best route names the gateway: TEST-NET-1
/// (RFC 5737), which no network routes, so the route found for it is the
/// interface's default route. The same address the route-source lookup
/// of `tornect-net` connects to.
pub const ROUTE_PROBE_DEST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// `next_hop` when it can be a router: not unspecified (a route to the
/// local link has no next hop and reports all zeros), loopback, multicast
/// or broadcast.
#[must_use]
pub fn usable_gateway(next_hop: Ipv4Addr) -> Option<Ipv4Addr> {
    let unusable = next_hop.is_unspecified()
        || next_hop.is_loopback()
        || next_hop.is_multicast()
        || next_hop.is_broadcast();
    (!unusable).then_some(next_hop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_unicast_next_hop_is_a_gateway() {
        for usable in ["192.168.1.1", "10.0.0.138", "100.64.0.1", "169.254.1.1"] {
            let ip: Ipv4Addr = usable.parse().unwrap();
            assert_eq!(usable_gateway(ip), Some(ip), "{usable}");
        }
        for unusable in [
            "0.0.0.0",
            "127.0.0.1",
            "127.255.0.9",
            "224.0.0.1",
            "239.255.255.250",
            "255.255.255.255",
        ] {
            let ip: Ipv4Addr = unusable.parse().unwrap();
            assert_eq!(usable_gateway(ip), None, "{unusable}");
        }
    }

    #[test]
    fn the_probe_destination_is_test_net_1() {
        assert_eq!(ROUTE_PROBE_DEST.octets(), [192, 0, 2, 1]);
        assert!(ROUTE_PROBE_DEST.is_documentation());
    }
}
