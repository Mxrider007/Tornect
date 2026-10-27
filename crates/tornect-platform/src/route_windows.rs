//! The Win32 call behind [`crate::route::default_gateway_v4`]:
//! `GetBestRoute2` (`netioapi.h`, `iphlpapi.dll`, Windows Vista and later;
//! docs/research/nat-traversal.md §5). It reads the IP routing table and
//! sends nothing. What counts as a gateway is decided in
//! [`crate::route::usable_gateway`], tested on every OS.
#![allow(unsafe_code)]

use std::net::Ipv4Addr;
use std::ptr::null;

use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_INET,
};

use crate::route::{ROUTE_PROBE_DEST, usable_gateway};

/// The IPv4 default gateway of the interface with index `if_index`: the
/// next hop of that interface's best route to [`ROUTE_PROBE_DEST`], when it
/// is an IPv4 router address. `None` for index 0 (no interface), for an
/// interface Windows does not know or that has no IPv4 route, and for a
/// route to the local link (its next hop is all zeros).
#[must_use]
pub fn default_gateway_v4(if_index: u32) -> Option<Ipv4Addr> {
    if if_index == 0 {
        return None;
    }
    let destination = SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(ROUTE_PROBE_DEST.octets()),
                },
            },
            sin_zero: [0; 8],
        },
    };
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: `GetBestRoute2` reads `destination` (a valid IPv4
    // `SOCKADDR_INET`) and writes `route` and `source`, all live locals of
    // the right types for the whole call; the LUID and source pointers may
    // be null (the index names the interface; any source). It keeps no
    // pointer. The reads afterwards are of plain integer fields of the
    // `NextHop` union: every member is plain old data and the union was
    // zero-initialised, so each read is of initialised bytes whatever
    // member the call wrote; the family says which member to trust.
    let (status, family, s_addr) = unsafe {
        let status = GetBestRoute2(
            null(),
            if_index,
            null(),
            &destination,
            0,
            &mut route,
            &mut source,
        );
        (
            status,
            route.NextHop.si_family,
            route.NextHop.Ipv4.sin_addr.S_un.S_addr,
        )
    };
    if status != NO_ERROR || family != AF_INET {
        return None;
    }
    usable_gateway(Ipv4Addr::from(s_addr.to_ne_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Index 0 is no interface and is never asked; an index no adapter has
    /// fails the lookup (`ERROR_FILE_NOT_FOUND`) and reads as no gateway.
    #[test]
    fn no_interface_has_no_gateway() {
        assert_eq!(default_gateway_v4(0), None);
        assert_eq!(default_gateway_v4(u32::MAX - 7), None);
    }

    /// The device check of `docs/VERIFICATION.md` (NEEDS-DEVICE(windows)):
    /// the gateway of every interface index that has one, to compare with
    /// `Get-NetRoute -DestinationPrefix 0.0.0.0/0 | ft ifIndex,NextHop`
    /// (`Get-NetAdapter -IncludeHidden | ft ifIndex,Name` names the index).
    /// The address is printed whole for that comparison; it goes to this
    /// terminal only, never to a log.
    #[test]
    #[ignore = "device check: prints this computer's gateways"]
    #[allow(clippy::print_stderr)] // the device check reports what it read
    fn print_this_machines_gateways() {
        for index in 1..=512 {
            if let Some(gateway) = default_gateway_v4(index) {
                eprintln!("interface {index}: gateway {gateway}");
            }
        }
    }
}
