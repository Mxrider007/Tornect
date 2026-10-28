//! This computer's own addresses: the interface list, the route sources,
//! the VPN rule, the host candidates and the filters built from them
//! (design `direct` §7.1, §7.2; decision M1-81).
//!
//! Only [`read_interfaces`] and [`route_sources`] touch the OS; everything
//! else is a pure function of their results, so the tables are tested
//! without a network. Neither sends a packet. netdev's `gateway` feature
//! (step B1) is compiled only off Windows, where it reads each interface's
//! default gateway from the kernel's tables (a netlink route and neighbour
//! dump on Linux, a routing sysctl on macOS); its Windows path may send ARP
//! through `SendARP`, so Windows fills the gateway through a route lookup
//! the app hands in ([`fill_gateways`]). The route sources come from a UDP
//! `connect()` to documentation addresses, which only asks the kernel for a
//! route. docs/research/nat-traversal.md §1.6 and §5.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Duration;

use netdev::interface::types::InterfaceType;
use netdev::ipnet::{IpNet, Ipv6Net};
use tokio::sync::watch;

use crate::NetError;
use crate::addr::{
    AddrClass, Candidate, CandidateKind, RedactedIp, RemoteFilter, RouteLookup, Scope, StunFilter,
    TunnelRoute, canon_ip, class, is_eui64,
};

/// How long [`read_interfaces`] waits for the OS's interface list.
pub const IFACE_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// The most host candidates a side offers: one `CANDIDATES` frame.
pub const MAX_HOST_CANDIDATES: usize = 8;

/// The most private IPv4 host candidates.
pub const MAX_PRIVATE_V4: usize = 4;

/// The most unique-local IPv6 host candidates (at most one per interface).
pub const MAX_ULA: usize = 2;

/// Lowercased pieces of an interface's name, friendly name or description
/// that make it a tunnel (VPN clients; TAP adapters report Ethernet on
/// Windows and Linux, so only these catch them).
pub const TUNNEL_MARKERS: [&str; 13] = [
    "wintun",
    "wireguard",
    "tap-windows",
    "tap-win32",
    "openvpn",
    "tailscale",
    "zerotier",
    "nordlynx",
    "mullvad",
    "proton",
    "fortinet",
    "anyconnect",
    "globalprotect",
];

/// Lowercased name prefixes of tunnel interfaces.
pub const TUNNEL_PREFIXES: [&str; 9] = [
    "tun",
    "tap",
    "wg",
    "ppp",
    "utun",
    "ipsec",
    "tailscale",
    "zt",
    "nordlynx",
];

/// Lowercased name prefixes of virtual bridges and container or VM
/// interfaces, whose addresses are never offered.
pub const VIRTUAL_PREFIXES: [&str; 12] = [
    "docker", "br-", "virbr", "veth", "vmnet", "vboxnet", "lxcbr", "lxdbr", "cni", "flannel",
    "podman", "kube",
];

/// Lowercased pieces of a Windows adapter description that make it virtual
/// (Hyper-V and VirtualBox switches, VMware's host-only and NAT adapters,
/// whose Windows names are GUIDs).
pub const VIRTUAL_DESCRIPTIONS: [&str; 3] = [
    "hyper-v virtual ethernet",
    "virtualbox host-only",
    "vmware virtual ethernet",
];

/// Where the IPv4 route probe "connects" (TEST-NET-1, port 9 discard): the
/// kernel picks the source of the default route; nothing is sent.
const V4_ROUTE_PROBE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);

/// The IPv6 route probe's destination (`2001:db8::1`, documentation).
const V6_ROUTE_PROBE: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
    9,
);

/// What an interface is, for the VPN rule and the candidate selection
/// (design §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IfaceKind {
    /// Ethernet, Wi-Fi or mobile broadband, and none of the rules below.
    Physical,
    /// A VPN or other tunnel; also every interface of an unknown type
    /// (fail closed).
    Tunnel,
    /// A virtual bridge or a container or VM interface that carries no
    /// route source.
    Virtual,
    /// The loopback interface.
    Loopback,
}

/// The kind of `iface` (design §7.1). `route_source`: the interface carries
/// a route source, which makes it never [`IfaceKind::Virtual`] (a Hyper-V
/// external switch, a Linux `br0` with the default route); it is then
/// judged by its type like any other.
#[must_use]
pub fn iface_kind(iface: &netdev::Interface, route_source: bool) -> IfaceKind {
    if iface.if_type == InterfaceType::Loopback || iface.is_loopback() {
        return IfaceKind::Loopback;
    }
    let name = iface.name.to_lowercase();
    let texts = [
        Some(name.clone()),
        iface.friendly_name.as_deref().map(str::to_lowercase),
        iface.description.as_deref().map(str::to_lowercase),
    ];
    let marked = texts
        .iter()
        .flatten()
        .any(|text| TUNNEL_MARKERS.iter().any(|m| text.contains(m)));
    if matches!(
        iface.if_type,
        InterfaceType::Tunnel | InterfaceType::Ppp | InterfaceType::ProprietaryVirtual
    ) || iface.is_point_to_point()
        || marked
        || TUNNEL_PREFIXES.iter().any(|p| name.starts_with(p))
    {
        return IfaceKind::Tunnel;
    }
    let description = iface
        .description
        .as_deref()
        .map(str::to_lowercase)
        .unwrap_or_default();
    let virtual_named = VIRTUAL_PREFIXES.iter().any(|p| name.starts_with(p))
        || VIRTUAL_DESCRIPTIONS.iter().any(|d| description.contains(d));
    if virtual_named && !route_source {
        return IfaceKind::Virtual;
    }
    match iface.if_type {
        InterfaceType::Ethernet
        | InterfaceType::Ethernet3Megabit
        | InterfaceType::FastEthernetT
        | InterfaceType::FastEthernetFx
        | InterfaceType::GigabitEthernet
        | InterfaceType::Wireless80211
        | InterfaceType::Wwan
        | InterfaceType::Wwanpp
        | InterfaceType::Wwanpp2 => IfaceKind::Physical,
        _ => IfaceKind::Tunnel,
    }
}

/// One address of one interface (design §7.1).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IfaceAddr {
    /// The address.
    pub ip: IpAddr,
    /// Its prefix length.
    pub prefix_len: u8,
    /// [`class`] of the address.
    pub class: AddrClass,
    /// IPv6: a temporary (privacy) address, RFC 8981.
    pub temporary: bool,
    /// IPv6: past its preferred lifetime.
    pub deprecated: bool,
    /// IPv6: still in duplicate address detection.
    pub tentative: bool,
    /// IPv6: duplicate address detection failed.
    pub duplicated: bool,
    /// IPv6: the interface ID is a modified EUI-64 (hardware-derived).
    pub eui64: bool,
    /// The OS's index of the interface.
    pub iface_index: u32,
    /// What the interface is.
    pub iface_kind: IfaceKind,
    /// The interface is up and running.
    pub up: bool,
    /// The interface's IPv4 default gateway, when known: the router a port
    /// mapping asks (design §7.1, §7.4). From netdev's `gateway` feature on
    /// Linux and macOS, from the lookup [`fill_gateways`] is given on
    /// Windows; only a [`usable_gateway`]. The same on every address of the
    /// interface.
    pub gateway_v4: Option<Ipv4Addr>,
}

impl IfaceAddr {
    /// The address with its prefix, truncated to the network.
    #[must_use]
    pub fn net(&self) -> Option<IpNet> {
        IpNet::new(self.ip, self.prefix_len).ok().map(|n| n.trunc())
    }

    /// Up, and neither deprecated, tentative, duplicated nor (IPv6) EUI-64.
    #[must_use]
    pub fn usable(&self) -> bool {
        self.up
            && !self.deprecated
            && !self.tentative
            && !self.duplicated
            && (self.ip.is_ipv4() || !self.eui64)
    }
}

impl fmt::Debug for IfaceAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        for (on, name) in [
            (self.up, "up"),
            (self.temporary, "temporary"),
            (self.deprecated, "deprecated"),
            (self.tentative, "tentative"),
            (self.duplicated, "duplicated"),
            (self.eui64, "eui64"),
        ] {
            if on {
                flags.push(name);
            }
        }
        f.debug_struct("IfaceAddr")
            .field("ip", &RedactedIp(self.ip))
            .field("prefix_len", &self.prefix_len)
            .field("iface_index", &self.iface_index)
            .field("iface_kind", &self.iface_kind)
            .field("flags", &flags)
            .field(
                "gateway_v4",
                &self.gateway_v4.map(|g| RedactedIp(IpAddr::V4(g))),
            )
            .finish()
    }
}

/// The source address of each family's default route (design §7.1), or
/// `None` where the family has no route.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteSources {
    /// The IPv4 route source.
    pub v4: Option<Ipv4Addr>,
    /// The IPv6 route source.
    pub v6: Option<Ipv6Addr>,
}

impl fmt::Debug for RouteSources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteSources")
            .field("v4", &self.v4.map(|ip| RedactedIp(IpAddr::V4(ip))))
            .field("v6", &self.v6.map(|ip| RedactedIp(IpAddr::V6(ip))))
            .finish()
    }
}

/// The route sources, from a UDP `connect()` to `192.0.2.1:9` and
/// `[2001:db8::1]:9` and the socket's `local_addr()` ([`route_source_to`]).
#[must_use]
pub fn route_sources() -> RouteSources {
    RouteSources {
        v4: match route_source_to(V4_ROUTE_PROBE) {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        },
        v6: match route_source_to(V6_ROUTE_PROBE) {
            Some(IpAddr::V6(ip)) => Some(ip),
            _ => None,
        },
    }
}

/// The source address the OS picks toward `to`, from a UDP `connect()` and
/// the socket's `local_addr()`; `None` without a route. A UDP connect
/// sends nothing; the socket is never bound explicitly (the connect binds
/// it to the route's source), so no wildcard listener exists even for a
/// moment. It differs from the family's [`route_sources`] where a more
/// specific route serves `to`, as a split tunnel's excluded prefix does.
#[must_use]
pub fn route_source_to(to: SocketAddr) -> Option<IpAddr> {
    let domain = socket2::Domain::for_address(to);
    let socket =
        socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP)).ok()?;
    socket.connect(&to.into()).ok()?;
    let local = socket.local_addr().ok()?.as_socket()?;
    let ip = canon_ip(local.ip());
    (!ip.is_unspecified()).then_some(ip)
}

/// The addresses of `iface`, each with `kind`. IPv6 addresses whose flags
/// netdev could not pair with them (the two lists differ in length) are
/// left out: unknown flags never read as "stable and safe".
#[must_use]
pub fn iface_addrs(iface: &netdev::Interface, kind: IfaceKind) -> Vec<IfaceAddr> {
    let up = iface.is_up() && iface.is_running();
    let gateway_v4 = netdev_gateway_v4(iface);
    let base = |ip: IpAddr, prefix_len: u8| IfaceAddr {
        ip,
        prefix_len,
        class: class(ip),
        temporary: false,
        deprecated: false,
        tentative: false,
        duplicated: false,
        eui64: false,
        iface_index: iface.index,
        iface_kind: kind,
        up,
        gateway_v4,
    };
    let mut out: Vec<IfaceAddr> = iface
        .ipv4
        .iter()
        .map(|net| base(IpAddr::V4(net.addr()), net.prefix_len()))
        .collect();
    if iface.ipv6.len() == iface.ipv6_addr_flags.len() {
        out.extend(
            iface
                .ipv6
                .iter()
                .zip(&iface.ipv6_addr_flags)
                .map(|(net, flags)| IfaceAddr {
                    temporary: flags.temporary,
                    deprecated: flags.deprecated,
                    tentative: flags.tentative,
                    duplicated: flags.duplicated,
                    eui64: is_eui64(net.addr()),
                    ..base(IpAddr::V6(net.addr()), net.prefix_len())
                }),
        );
    }
    out
}

/// `ip` when it can be a router to ask for a port mapping: not
/// unspecified (a route to the local link has no next hop), loopback,
/// multicast or broadcast. `tornect_platform::route::usable_gateway` is the
/// same rule on the Windows side.
#[must_use]
pub fn usable_gateway(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast())
}

/// The first usable IPv4 gateway netdev read for `iface`.
#[cfg(not(windows))]
fn netdev_gateway_v4(iface: &netdev::Interface) -> Option<Ipv4Addr> {
    let device = iface.gateway.as_ref()?;
    device.ipv4.iter().copied().find(|ip| usable_gateway(*ip))
}

/// None: netdev's Windows gateway read is never compiled (it may send ARP).
#[cfg(windows)]
fn netdev_gateway_v4(_iface: &netdev::Interface) -> Option<Ipv4Addr> {
    None
}

/// Fills [`IfaceAddr::gateway_v4`] of every address whose interface has
/// none from `lookup`, asked once per interface index and never for a
/// loopback interface; an answer that is not a [`usable_gateway`] counts as
/// none. A gateway already read is kept.
pub fn fill_gateways(addrs: &mut [IfaceAddr], lookup: &dyn Fn(u32) -> Option<Ipv4Addr>) {
    let mut asked: Vec<(u32, Option<Ipv4Addr>)> = Vec::new();
    for addr in addrs
        .iter_mut()
        .filter(|a| a.gateway_v4.is_none() && a.iface_kind != IfaceKind::Loopback)
    {
        let gateway = match asked.iter().find(|(index, _)| *index == addr.iface_index) {
            Some(&(_, gateway)) => gateway,
            None => {
                let gateway = lookup(addr.iface_index).filter(|ip| usable_gateway(*ip));
                asked.push((addr.iface_index, gateway));
                gateway
            }
        };
        addr.gateway_v4 = gateway;
    }
}

/// Every address of `ifaces`, each interface's kind decided with whether
/// it carries one of `sources`, ordered by interface index and, within an
/// interface, in the OS's order. netdev returns the interfaces in no fixed
/// order; sorting keeps two reads of an unchanged computer, and so the
/// host candidates chosen from them, identical.
#[must_use]
pub fn snapshot(ifaces: &[netdev::Interface], sources: &RouteSources) -> Vec<IfaceAddr> {
    let source_ips = [sources.v4.map(IpAddr::V4), sources.v6.map(IpAddr::V6)];
    let mut out: Vec<IfaceAddr> = ifaces
        .iter()
        .flat_map(|iface| {
            let carries = source_ips.iter().flatten().any(|src| {
                iface.ipv4.iter().any(|n| IpAddr::V4(n.addr()) == *src)
                    || iface.ipv6.iter().any(|n| IpAddr::V6(n.addr()) == *src)
            });
            iface_addrs(iface, iface_kind(iface, carries))
        })
        .collect();
    out.sort_by_key(|a| a.iface_index);
    out
}

type Reading = watch::Receiver<Option<Vec<IfaceAddr>>>;

/// One interface read in flight at a time, shared by every caller that
/// asks while it runs (design §7.1: a second caller joins it, so a stuck
/// OS call never piles up blocking threads).
pub(crate) struct IfaceReader {
    slot: Arc<Mutex<Option<Reading>>>,
    read: Arc<dyn Fn() -> Vec<IfaceAddr> + Send + Sync>,
    timeout: Duration,
}

/// The blocking read's end of a reading. Dropped when the read ends, also
/// by a panic: it empties the reader's slot first and only then closes the
/// channel, so a caller woken by the close never joins the finished read.
struct InFlight {
    slot: Arc<Mutex<Option<Reading>>>,
    done: Option<watch::Sender<Option<Vec<IfaceAddr>>>>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = None;
        drop(self.done.take());
    }
}

impl IfaceReader {
    pub(crate) fn new(
        read: Arc<dyn Fn() -> Vec<IfaceAddr> + Send + Sync>,
        timeout: Duration,
    ) -> Self {
        Self {
            slot: Arc::new(Mutex::new(None)),
            read,
            timeout,
        }
    }

    /// The read in flight, or a new one on the blocking pool; then its
    /// result, or [`NetError::InterfacesTimedOut`] after the timeout (the
    /// read goes on, and the next caller joins it).
    pub(crate) async fn read(&self) -> Result<Vec<IfaceAddr>, NetError> {
        let mut reading = {
            let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
            match &*slot {
                Some(reading) => reading.clone(),
                None => {
                    let (done, reading) = watch::channel(None);
                    *slot = Some(reading.clone());
                    let read = Arc::clone(&self.read);
                    let in_flight = InFlight {
                        slot: Arc::clone(&self.slot),
                        done: Some(done),
                    };
                    drop(tokio::task::spawn_blocking(move || {
                        let addrs = read();
                        if let Some(done) = &in_flight.done {
                            done.send_replace(Some(addrs));
                        }
                        drop(in_flight);
                    }));
                    reading
                }
            }
        };
        match tokio::time::timeout(self.timeout, reading.wait_for(Option::is_some)).await {
            Ok(Ok(addrs)) => Ok(addrs.clone().unwrap_or_default()),
            Ok(Err(_)) => Err(NetError::InterfacesLost),
            Err(_) => Err(NetError::InterfacesTimedOut),
        }
    }
}

/// This computer's addresses, read with netdev on the blocking pool under
/// [`IFACE_READ_TIMEOUT`], one read per process at a time.
///
/// # Errors
///
/// [`NetError::InterfacesTimedOut`] when the OS takes longer than
/// [`IFACE_READ_TIMEOUT`], [`NetError::InterfacesLost`] when the read
/// panicked. A direct link reads either as "no addresses".
pub async fn read_interfaces() -> Result<Vec<IfaceAddr>, NetError> {
    static READER: LazyLock<IfaceReader> = LazyLock::new(|| {
        IfaceReader::new(
            Arc::new(|| snapshot(&netdev::get_interfaces(), &route_sources())),
            IFACE_READ_TIMEOUT,
        )
    });
    READER.read().await
}

/// The address of `addrs` that is `ip`, if any.
pub(crate) fn owner(addrs: &[IfaceAddr], ip: IpAddr) -> Option<&IfaceAddr> {
    addrs.iter().find(|a| canon_ip(a.ip) == canon_ip(ip))
}

/// Whether the VPN rule is on (design §7.2): a route source lies on an
/// interface that is not Physical, or on no listed interface, or the two
/// families leave by different interfaces.
#[must_use]
pub fn vpn_mode(addrs: &[IfaceAddr], sources: &RouteSources) -> bool {
    let owners = [sources.v4.map(IpAddr::V4), sources.v6.map(IpAddr::V6)]
        .map(|src| src.map(|ip| owner(addrs, ip)));
    if owners
        .iter()
        .flatten()
        .any(|o| o.is_none_or(|a| a.iface_kind != IfaceKind::Physical))
    {
        return true;
    }
    match owners {
        [Some(Some(v4)), Some(Some(v6))] => v4.iface_index != v6.iface_index,
        _ => false,
    }
}

/// The families (IPv4, IPv6) whose global remotes may be sent to (design
/// §7.2): outside VPN mode, each family that has a route source; in VPN
/// mode, only a family whose route source lies on a tunnel, so nothing
/// leaves the physical interface toward a public address.
#[must_use]
pub fn global_families(addrs: &[IfaceAddr], sources: &RouteSources, vpn: bool) -> (bool, bool) {
    let routed = |src: Option<IpAddr>| match src {
        None => false,
        Some(_) if !vpn => true,
        Some(ip) => owner(addrs, ip).is_some_and(|a| a.iface_kind == IfaceKind::Tunnel),
    };
    (
        routed(sources.v4.map(IpAddr::V4)),
        routed(sources.v6.map(IpAddr::V6)),
    )
}

/// The host candidates of a side (design §7.1), all on `port`:
///
/// - only usable addresses of Physical interfaces (never loopback, tunnel
///   or virtual; never deprecated, tentative, duplicated or EUI-64);
/// - up to [`MAX_PRIVATE_V4`] private IPv4 addresses, the IPv4 route
///   source's interface first;
/// - up to [`MAX_ULA`] unique-local addresses, at most one per interface,
///   temporary first; in internet scope only when no private IPv4 is
///   offered;
/// - internet scope outside VPN mode: one global IPv4 and one global IPv6,
///   each only from its family's route-source interface; the IPv6 one a
///   temporary address (the route source itself if it is one), else the
///   route source when it is not EUI-64, else none;
/// - at most [`MAX_HOST_CANDIDATES`] in all.
#[must_use]
pub fn select_host_candidates(
    addrs: &[IfaceAddr],
    sources: &RouteSources,
    port: u16,
    scope: Scope,
    vpn: bool,
) -> Vec<Candidate> {
    let eligible: Vec<&IfaceAddr> = addrs
        .iter()
        .filter(|a| a.iface_kind == IfaceKind::Physical && a.usable())
        .collect();
    let route_iface =
        |src: Option<IpAddr>| src.and_then(|ip| owner(addrs, ip)).map(|a| a.iface_index);
    let v4_iface = route_iface(sources.v4.map(IpAddr::V4));
    let v6_iface = route_iface(sources.v6.map(IpAddr::V6));

    let mut private: Vec<&IfaceAddr> = eligible
        .iter()
        .copied()
        .filter(|a| a.ip.is_ipv4() && a.class == AddrClass::Private)
        .collect();
    private.sort_by_key(|a| Some(a.iface_index) != v4_iface);
    private.truncate(MAX_PRIVATE_V4);

    let mut picked: Vec<IpAddr> = private.iter().map(|a| a.ip).collect();

    if scope == Scope::SameSite || private.is_empty() {
        let mut ula: Vec<&IfaceAddr> = eligible
            .iter()
            .copied()
            .filter(|a| a.class == AddrClass::UniqueLocal)
            .collect();
        ula.sort_by_key(|a| {
            (
                Some(a.iface_index) != v6_iface && Some(a.iface_index) != v4_iface,
                !a.temporary,
            )
        });
        let mut seen = Vec::new();
        for a in ula {
            if seen.len() == MAX_ULA {
                break;
            }
            if !seen.contains(&a.iface_index) {
                seen.push(a.iface_index);
                picked.push(a.ip);
            }
        }
    }

    if scope == Scope::Internet && !vpn {
        if let (Some(src), Some(index)) = (sources.v4, v4_iface) {
            let global: Vec<&IfaceAddr> = eligible
                .iter()
                .copied()
                .filter(|a| {
                    a.iface_index == index && a.ip.is_ipv4() && a.class == AddrClass::Global
                })
                .collect();
            if let Some(a) = global
                .iter()
                .find(|a| a.ip == IpAddr::V4(src))
                .or_else(|| global.first())
            {
                picked.push(a.ip);
            }
        }
        if let (Some(src), Some(index)) = (sources.v6, v6_iface) {
            let global: Vec<&IfaceAddr> = eligible
                .iter()
                .copied()
                .filter(|a| {
                    a.iface_index == index && a.ip.is_ipv6() && a.class == AddrClass::Global
                })
                .collect();
            let source = global.iter().find(|a| a.ip == IpAddr::V6(src));
            let choice = source
                .filter(|a| a.temporary)
                .or_else(|| global.iter().find(|a| a.temporary))
                .or(source);
            if let Some(a) = choice {
                picked.push(a.ip);
            }
        }
    }

    picked.truncate(MAX_HOST_CANDIDATES);
    picked
        .into_iter()
        .map(|ip| Candidate {
            kind: CandidateKind::Host,
            addr: SocketAddr::new(ip, port),
        })
        .collect()
}

/// VPN mode's per-address rule (design §7.2): the tunnel's route source of
/// each family [`global_families`] admits, and `lookup`, the environment's
/// route toward one address.
#[must_use]
pub fn tunnel_route(
    addrs: &[IfaceAddr],
    sources: &RouteSources,
    lookup: RouteLookup,
) -> TunnelRoute {
    let (v4, v6) = global_families(addrs, sources, true);
    TunnelRoute {
        v4: sources.v4.filter(|_| v4),
        v6: sources.v6.filter(|_| v6),
        lookup,
    }
}

/// The [`RemoteFilter`] of a session (design §7.7), from this side's
/// addresses, its route sources and the host candidates it offered. `vpn`
/// is VPN mode ([`vpn_mode`]) with the environment's route lookup
/// (`NetEnv::route_source_to`): in VPN mode a global remote passes only for
/// a family whose route source lies on the tunnel, and only when its own
/// route leaves from that source ([`tunnel_route`]); `None` outside VPN
/// mode.
#[must_use]
pub fn remote_filter(
    scope: Scope,
    addrs: &[IfaceAddr],
    sources: &RouteSources,
    offered: &[Candidate],
    dual_stack: bool,
    vpn: Option<RouteLookup>,
    admit_loopback: bool,
) -> RemoteFilter {
    let offered_addrs: Vec<&IfaceAddr> = offered
        .iter()
        .filter(|c| c.kind == CandidateKind::Host)
        .filter_map(|c| owner(addrs, c.addr.ip()))
        .collect();
    let on_link = offered_addrs.iter().filter_map(|a| a.net()).collect();
    let own_ula48 = offered_addrs
        .iter()
        .find_map(|a| match a.ip {
            IpAddr::V6(v6) if a.class == AddrClass::UniqueLocal => Ipv6Net::new(v6, 48).ok(),
            _ => None,
        })
        .map(|n| n.trunc())
        .filter(|_| dual_stack);
    let mut local_nets: Vec<IpNet> = addrs.iter().filter_map(IfaceAddr::net).collect();
    local_nets.sort_unstable();
    local_nets.dedup();
    let mut own: Vec<IpAddr> = addrs.iter().map(|a| canon_ip(a.ip)).collect();
    own.extend(sources.v4.map(IpAddr::V4));
    own.extend(sources.v6.map(IpAddr::V6));
    own.sort_unstable();
    own.dedup();
    let offers = |v6: bool, global: bool| {
        offered.iter().any(|c| {
            canon_ip(c.addr.ip()).is_ipv6() == v6
                && (!global || class(canon_ip(c.addr.ip())) == AddrClass::Global)
        })
    };
    RemoteFilter {
        scope,
        on_link,
        own_ula48,
        local_nets,
        have_v4: offers(false, false) || (scope == Scope::Internet && sources.v4.is_some()),
        have_v6: dual_stack && offers(true, true),
        dual_stack,
        global_families: global_families(addrs, sources, vpn.is_some()),
        tunnel_route: vpn.map(|lookup| tunnel_route(addrs, sources, lookup)),
        own,
        admit_loopback,
    }
}

/// The [`StunFilter`] of this computer (design §5.3).
#[must_use]
pub fn stun_filter(
    addrs: &[IfaceAddr],
    sources: &RouteSources,
    admit_loopback: bool,
) -> StunFilter {
    let mut own: Vec<IpAddr> = addrs.iter().map(|a| canon_ip(a.ip)).collect();
    own.extend(sources.v4.map(IpAddr::V4));
    own.sort_unstable();
    own.dedup();
    StunFilter {
        have_v4: sources.v4.is_some(),
        own,
        admit_loopback,
    }
}

#[cfg(test)]
mod tests;
