//! Address classes, the scope of a session's candidates, and the two filters
//! every address passes before a datagram goes to it (design `direct` §7.1,
//! §7.7; decisions M1-80, M1-83).
//!
//! Peer-supplied addresses (candidates, the sources of probe requests,
//! `Incoming` sources, a connection's remote address) pass [`RemoteFilter`];
//! config-supplied STUN servers pass [`StunFilter`]. Tables here use the
//! canonical form of an address ([`canon`]: a v4-mapped IPv6 address is its
//! IPv4 address); quinn keeps seeing addresses in the socket's own family
//! ([`to_socket_family`]).
//!
//! No address is ever written to a log or an error: [`Redacted`] and
//! [`RedactedIp`] print the family and the class, and every type here that
//! carries an address has a hand-written `Debug` that prints the same.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use netdev::ipnet::{IpNet, Ipv6Net};

/// How far a session's candidates reach (design §4 "Scope"). `SameSite <
/// Internet`: the scope two sides agree on is the lower of theirs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// On-link private IPv4 and our own ULA /48 only; no third party is
    /// asked and no global address is offered or admitted.
    SameSite,
    /// Same-site plus public IPv4, one global IPv6, srflx and mapped
    /// candidates (Phase B, behind `INTERNET_DIRECT`).
    Internet,
}

/// Where a candidate address came from (design §7.5, §7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateKind {
    /// An address of one of this computer's interfaces.
    Host,
    /// The address a public STUN server saw (server reflexive).
    Srflx,
    /// The external address of a router port mapping (PCP, NAT-PMP, UPnP).
    Mapped,
    /// A source learned from an authenticated probe request (peer
    /// reflexive); local only, never sent.
    Prflx,
}

impl CandidateKind {
    /// The kind's name in `sessions.log` and on the CLI (`PATH host 412 ms`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Srflx => "srflx",
            Self::Mapped => "mapped",
            Self::Prflx => "prflx",
        }
    }
}

/// One candidate address: a kind and a socket address in canonical form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Candidate {
    /// Where the address came from.
    pub kind: CandidateKind,
    /// The address, IPv4 as `V4` (never v4-mapped).
    pub addr: SocketAddr,
}

impl fmt::Debug for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("kind", &self.kind)
            .field("addr", &Redacted(&self.addr))
            .finish()
    }
}

/// The class of an address, from the IANA special-purpose address
/// registries of both families (design §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrClass {
    /// `127/8`, `::1`.
    Loopback,
    /// `169.254/16`, `fe80::/10`.
    LinkLocal,
    /// RFC 1918: `10/8`, `172.16/12`, `192.168/16`.
    Private,
    /// RFC 6598 shared address space `100.64/10` (carrier-grade NAT): a
    /// valid srflx base, never an offered or admitted candidate.
    SharedCgnat,
    /// `fc00::/7`.
    UniqueLocal,
    /// Globally reachable unicast.
    Global,
    /// Everything else: unspecified, documentation, benchmarking,
    /// protocol assignments, 6to4, Teredo, NAT64, multicast, reserved,
    /// v4-mapped, and IPv6 outside `2000::/3`.
    Unusable,
}

impl AddrClass {
    /// The class's name in redacted output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::Private => "private",
            Self::SharedCgnat => "shared-cgnat",
            Self::UniqueLocal => "unique-local",
            Self::Global => "global",
            Self::Unusable => "unusable",
        }
    }
}

/// The class of `ip` (a v4-mapped IPv6 address is [`AddrClass::Unusable`]:
/// callers classify [`canon_ip`] of what a socket reports).
#[must_use]
pub fn class(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) => class_v4(v4),
        IpAddr::V6(v6) => class_v6(v6),
    }
}

/// The class of an IPv4 address. Every block of the IANA IPv4
/// Special-Purpose Address Registry that is not globally reachable is
/// non-Global; the registry's globally reachable entries inside
/// `192.0.0/24` (PCP and TURN anycast) are never a peer's address, so the
/// whole /24 is unusable.
#[must_use]
pub fn class_v4(ip: Ipv4Addr) -> AddrClass {
    let [a, b, c, _] = ip.octets();
    match (a, b, c) {
        (10, _, _) | (172, 16..=31, _) | (192, 168, _) => AddrClass::Private,
        (100, 64..=127, _) => AddrClass::SharedCgnat,
        (127, _, _) => AddrClass::Loopback,
        (169, 254, _) => AddrClass::LinkLocal,
        (0, _, _)
        | (192, 0, 0)
        | (192, 0, 2)
        | (192, 31, 196)
        | (192, 52, 193)
        | (192, 88, 99)
        | (192, 175, 48)
        | (198, 18..=19, _)
        | (198, 51, 100)
        | (203, 0, 113)
        | (224..=255, _, _) => AddrClass::Unusable,
        _ => AddrClass::Global,
    }
}

/// The class of an IPv6 address. Global is `2000::/3` minus `2001::/23`
/// (all IETF protocol assignments: Teredo, PCP and TURN anycast,
/// benchmarking, AMT, AS112, ORCHID), `2001:db8::/32` and `3fff::/20`
/// (documentation) and `2002::/16` (6to4).
#[must_use]
pub fn class_v6(ip: Ipv6Addr) -> AddrClass {
    let s = ip.segments();
    if ip.is_loopback() {
        AddrClass::Loopback
    } else if s[0] & 0xffc0 == 0xfe80 {
        AddrClass::LinkLocal
    } else if s[0] & 0xfe00 == 0xfc00 {
        AddrClass::UniqueLocal
    } else if s[0] & 0xe000 == 0x2000 {
        let protocol = s[0] == 0x2001 && s[1] < 0x0200;
        let documentation = (s[0] == 0x2001 && s[1] == 0x0db8) || (s[0] == 0x3fff && s[1] < 0x1000);
        let six_to_four = s[0] == 0x2002;
        if protocol || documentation || six_to_four {
            AddrClass::Unusable
        } else {
            AddrClass::Global
        }
    } else {
        // `::`, `::ffff:0:0/96`, `64:ff9b::/96`, `64:ff9b:1::/48`, `100::/64`,
        // `ff00::/8`, and the rest of the space outside 2000::/3.
        AddrClass::Unusable
    }
}

/// `ip` with a v4-mapped IPv6 address (`::ffff:a.b.c.d`) turned into its
/// IPv4 address; anything else unchanged.
#[must_use]
pub fn canon_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// `addr` in the canonical form of Tornect's own tables ([`canon_ip`] of the
/// address, the port kept). Never what quinn is given: quinn sees the form
/// the socket reports.
#[must_use]
pub fn canon(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canon_ip(addr.ip()), addr.port())
}

/// `addr` in the family of the session's socket: an IPv4 address
/// v4-mapped on a dual-stack socket (quinn stores a dial target that way,
/// and Windows and macOS refuse an `AF_INET` destination on an `AF_INET6`
/// socket), anything else unchanged.
#[must_use]
pub fn to_socket_family(addr: SocketAddr, dual_stack: bool) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) if dual_stack => {
            SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
        }
        other => other,
    }
}

/// Whether an IPv6 address's interface ID is a modified EUI-64 (`ff:fe` in
/// its middle), which is derived from the hardware address and is never
/// offered (design §7.1).
#[must_use]
pub fn is_eui64(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    o[11] == 0xff && o[12] == 0xfe
}

/// A socket address as it may appear in a log: its family and class, never
/// its bytes or its port (`v4 private`, `v6 global`).
#[derive(Clone, Copy)]
pub struct Redacted<'a>(pub &'a SocketAddr);

impl fmt::Display for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&RedactedIp(self.0.ip()), f)
    }
}

impl fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An IP address as it may appear in a log: [`Redacted`] without a port.
#[derive(Clone, Copy)]
pub struct RedactedIp(pub IpAddr);

impl fmt::Display for RedactedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ip = canon_ip(self.0);
        let family = if ip.is_ipv4() { "v4" } else { "v6" };
        write!(f, "{family} {}", class(ip).name())
    }
}

impl fmt::Debug for RedactedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The lowest port a peer-supplied address may have.
pub const MIN_REMOTE_PORT: u16 = 1024;

/// Ports at or above [`MIN_REMOTE_PORT`] that a peer-supplied address may
/// still not have: SSDP, PCP/NAT-PMP, mDNS and LLMNR, whose listeners a
/// probe must never reach.
pub const REFUSED_PORTS: [u16; 4] = [1900, 5351, 5353, 5355];

/// Why a filter refused an address; counted, never logged with the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// A port below [`MIN_REMOTE_PORT`], one of [`REFUSED_PORTS`], or (STUN)
    /// port 0.
    Port,
    /// A family this side cannot send to, or has no offered address of.
    Family,
    /// One of this computer's own addresses.
    Own,
    /// The network or broadcast address of one of this computer's prefixes.
    NetworkOrBroadcast,
    /// A class no scope admits (loopback, link-local, shared CGNAT space,
    /// unusable ranges).
    Class,
    /// A class the session's scope does not admit (a global address in
    /// same-site scope, a private address outside our on-link prefixes).
    Scope,
    /// A global address of a family the VPN rule keeps off the physical
    /// interface (design §7.2).
    Vpn,
}

/// What a peer-supplied address must pass before any datagram goes to it
/// or any request from it is answered (design §7.7). Built per session from
/// this side's interfaces and offered candidates (`local::remote_filter`).
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteFilter {
    /// The session's scope.
    pub scope: Scope,
    /// The prefixes of this side's offered host candidates: a private IPv4
    /// remote inside one of them is on the same site.
    pub on_link: Vec<IpNet>,
    /// The /48 of this side's offered unique-local address: a ULA remote
    /// inside it is on the same site, and without it no ULA remote is
    /// admitted (no source to send from).
    pub own_ula48: Option<Ipv6Net>,
    /// Every prefix of every interface of this computer, whose network and
    /// broadcast addresses are refused.
    pub local_nets: Vec<IpNet>,
    /// This side can send IPv4 in this scope (an offered IPv4 candidate, or
    /// in internet scope the IPv4 route source).
    pub have_v4: bool,
    /// This side offered a global IPv6 candidate; a global IPv6 remote needs
    /// it (every IPv6 datagram leaves from an offered address).
    pub have_v6: bool,
    /// The session's socket is dual-stack; without it no IPv6 remote.
    pub dual_stack: bool,
    /// The families (IPv4, IPv6) whose global remotes the VPN rule allows
    /// (`local::global_families`).
    pub global_families: (bool, bool),
    /// Every address of this computer.
    pub own: Vec<IpAddr>,
    /// Test environments only: a loopback remote passes on the port and
    /// own-address rules alone.
    pub admit_loopback: bool,
}

impl RemoteFilter {
    /// Whether `addr` may be probed, answered or dialled.
    #[must_use]
    pub fn admit(&self, addr: SocketAddr) -> bool {
        self.check(addr).is_ok()
    }

    /// [`admit`](Self::admit) with the reason of a refusal, for the counters.
    ///
    /// # Errors
    ///
    /// The first rule `addr` breaks, in the order port, family, own address,
    /// network or broadcast, class, scope, VPN.
    pub fn check(&self, addr: SocketAddr) -> Result<(), Refusal> {
        let addr = canon(addr);
        let ip = addr.ip();
        if addr.port() < MIN_REMOTE_PORT || REFUSED_PORTS.contains(&addr.port()) {
            return Err(Refusal::Port);
        }
        let reachable = match ip {
            IpAddr::V4(_) => self.have_v4,
            IpAddr::V6(_) => self.dual_stack,
        };
        if !reachable {
            return Err(Refusal::Family);
        }
        if self.own.iter().any(|own| canon_ip(*own) == ip) {
            return Err(Refusal::Own);
        }
        if is_network_or_broadcast(&self.local_nets, ip)
            || is_network_or_broadcast(&self.on_link, ip)
        {
            return Err(Refusal::NetworkOrBroadcast);
        }
        match (class(ip), ip) {
            (AddrClass::Loopback, _) if self.admit_loopback => Ok(()),
            (AddrClass::Private, IpAddr::V4(v4)) => {
                if self.scope == Scope::Internet || self.on_link_v4(v4) {
                    Ok(())
                } else {
                    Err(Refusal::Scope)
                }
            }
            (AddrClass::UniqueLocal, IpAddr::V6(v6)) => match self.own_ula48 {
                None => Err(Refusal::Family),
                Some(own) if self.scope == Scope::Internet || own.contains(&v6) => Ok(()),
                Some(_) => Err(Refusal::Scope),
            },
            (AddrClass::Global, _) if self.scope == Scope::SameSite => Err(Refusal::Scope),
            (AddrClass::Global, IpAddr::V4(_)) => {
                if self.global_families.0 {
                    Ok(())
                } else {
                    Err(Refusal::Vpn)
                }
            }
            (AddrClass::Global, IpAddr::V6(_)) => {
                if !self.have_v6 {
                    Err(Refusal::Family)
                } else if !self.global_families.1 {
                    Err(Refusal::Vpn)
                } else {
                    Ok(())
                }
            }
            _ => Err(Refusal::Class),
        }
    }

    /// Whether `ip` is a private IPv4 address inside one of our on-link
    /// prefixes.
    #[must_use]
    pub fn on_link_v4(&self, ip: Ipv4Addr) -> bool {
        class_v4(ip) == AddrClass::Private
            && self.on_link.iter().any(|net| match net {
                IpNet::V4(net) => net.contains(&ip),
                IpNet::V6(_) => false,
            })
    }

    /// Whether `ip` is on this side's site: a private IPv4 address inside
    /// one of our on-link prefixes, or a unique-local address inside our
    /// own /48. Never inferred from the class alone (design §3.1).
    #[must_use]
    pub fn on_site(&self, ip: IpAddr) -> bool {
        match canon_ip(ip) {
            IpAddr::V4(v4) => self.on_link_v4(v4),
            IpAddr::V6(v6) => {
                class_v6(v6) == AddrClass::UniqueLocal
                    && self.own_ula48.is_some_and(|own| own.contains(&v6))
            }
        }
    }
}

impl fmt::Debug for RemoteFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteFilter")
            .field("scope", &self.scope)
            .field("on_link", &Count(self.on_link.len(), "prefixes"))
            .field("own_ula48", &self.own_ula48.is_some())
            .field("local_nets", &Count(self.local_nets.len(), "prefixes"))
            .field("have_v4", &self.have_v4)
            .field("have_v6", &self.have_v6)
            .field("dual_stack", &self.dual_stack)
            .field("global_families", &self.global_families)
            .field("own", &Count(self.own.len(), "addresses"))
            .field("admit_loopback", &self.admit_loopback)
            .finish()
    }
}

/// What a config-supplied STUN server's address must pass (design §5.3):
/// global, a port other than 0 (no floor: the user or the config chose the
/// server, `:443` included), IPv4 (STUN is IPv4 only, design §1
/// non-goals), not one of our own addresses. It guards against a name that
/// resolves into the LAN.
#[derive(Clone, PartialEq, Eq)]
pub struct StunFilter {
    /// This side has an IPv4 route source to send from.
    pub have_v4: bool,
    /// Every address of this computer.
    pub own: Vec<IpAddr>,
    /// Test environments only: a loopback server is admitted as if global.
    pub admit_loopback: bool,
}

impl StunFilter {
    /// Whether a STUN request may go to `addr`.
    #[must_use]
    pub fn admit(&self, addr: SocketAddr) -> bool {
        self.check(addr).is_ok()
    }

    /// [`admit`](Self::admit) with the reason of a refusal.
    ///
    /// # Errors
    ///
    /// The first rule `addr` breaks, in the order port, family, own
    /// address, class.
    pub fn check(&self, addr: SocketAddr) -> Result<(), Refusal> {
        let addr = canon(addr);
        if addr.port() == 0 {
            return Err(Refusal::Port);
        }
        let IpAddr::V4(v4) = addr.ip() else {
            return Err(Refusal::Family);
        };
        if !self.have_v4 {
            return Err(Refusal::Family);
        }
        if self.own.iter().any(|own| canon_ip(*own) == IpAddr::V4(v4)) {
            return Err(Refusal::Own);
        }
        match class_v4(v4) {
            AddrClass::Global => Ok(()),
            AddrClass::Loopback if self.admit_loopback => Ok(()),
            _ => Err(Refusal::Class),
        }
    }
}

impl fmt::Debug for StunFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StunFilter")
            .field("have_v4", &self.have_v4)
            .field("own", &Count(self.own.len(), "addresses"))
            .field("admit_loopback", &self.admit_loopback)
            .finish()
    }
}

/// Whether `ip` is the network or the broadcast address of one of `nets`:
/// both for an IPv4 prefix up to /30 (a /31 and a /32 have neither,
/// RFC 3021), the subnet-router anycast (all-zero interface ID) for an
/// IPv6 prefix up to /126.
fn is_network_or_broadcast(nets: &[IpNet], ip: IpAddr) -> bool {
    nets.iter().any(|net| match (net, ip) {
        (IpNet::V4(net), IpAddr::V4(v4)) => {
            net.prefix_len() <= 30 && (v4 == net.network() || v4 == net.broadcast())
        }
        (IpNet::V6(net), IpAddr::V6(v6)) => net.prefix_len() <= 126 && v6 == net.network(),
        _ => false,
    })
}

/// A count in a redacted `Debug`: `3 addresses`.
pub(crate) struct Count(pub(crate) usize, pub(crate) &'static str);

impl fmt::Debug for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.1)
    }
}

#[cfg(test)]
mod tests;
