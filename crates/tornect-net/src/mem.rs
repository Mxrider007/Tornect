//! Test environments for direct links (design `direct` §8.3 `mem.rs`,
//! §12.2, §12.3): machines a [`NetEnv`] can stand for without a real
//! network, built only for tests (`cfg(test)`) and for other crates' tests
//! through the `test-support` feature, which only dev-dependencies enable.
//! `cargo xtask dist` is to check that no release build carries it (design
//! §8.8; the check lands at step A22).
//!
//! - [`LoopbackNet`]: real UDP sockets on `127.0.0.x`, presented as one
//!   physical interface whose `127.0.0.0/8` counts as the private on-link
//!   prefix. It is the classification override a loopback session needs,
//!   since the loopback class is never offered or admitted on a real
//!   machine: it admits loopback remotes ([`NetEnv::admit_loopback`]), and
//!   only test environments do (`RealNet` never does).
//! - [`MemNet`]: an in-memory network of segments (each one LAN with its
//!   own latency and loss) joined by links, on tokio's clock, so its tests
//!   run on paused time (quinn's `TokioRuntime` reads the same clock). Its
//!   machines ([`MemHost`], a [`NetEnv`]) have the addresses a test gives
//!   them and a host firewall ([`InboundRule`]); their session sockets
//!   ([`MemUdp`]) model the strictest OS (design §6.3 "Address family
//!   rule"): a dual-stack socket reports IPv4 peers v4-mapped and refuses a
//!   plain IPv4 destination with `InvalidInput`, as Windows and macOS do,
//!   and an IPv4 socket refuses IPv6. Every datagram is logged with its
//!   fate ([`MemNet::wire`]).
//! - [`CountingEnv`]: counts every call a link makes to the environment it
//!   wraps, for the privacy rules' "zero calls" (design §5.2).
//! - [`LaggedDuplex`]: an in-memory byte pipe with a one-way delay, the
//!   signalling stream of a session over a slow circuit (design §12.4).
//! - [`NatBox`]: a NAT (endpoint-independent, address-dependent or
//!   address-and-port-dependent mapping and filtering, hairpinning, port
//!   preservation, forwards, a 30 s timeout) or, with `translate: false`, a
//!   stateful IPv6 firewall, between the segments behind it and the one
//!   outside (design §12.4).
//! - [`MemStun`]: a STUN server on a segment, honest, lying or silent.
//! - [`MemMapper`]: the mapper of a machine whose gateway is a [`NatBox`]
//!   with a router ([`MapperMode`]): a granted mapping is a forward on that
//!   box, renewed and released through the router.
//!
//! Names resolve from the network's own table ([`MemNet::name`]).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use netdev::ipnet::IpNet;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

use crate::addr::{self, AddrClass, canon, canon_ip, to_socket_family};
use crate::env::NetEnv;
use crate::local::{IfaceAddr, IfaceKind, RouteSources};
use crate::mapping::{NoMapper, PortMapper, ReleaseTracker};
use crate::socket::{BoundSocket, RECV_BUFFER};
use crate::udp::{BoundUdp, is_probe, is_stun};
use crate::{BoxFuture, NetError};

mod nat;
mod servers;

pub use nat::{MemNat, NAT_TIMEOUT, NatBox, NatFiltering, NatFlow, NatMapping};
pub use servers::{MapperMode, MemMapper, MemStun, RouterSeen, StunHeard, StunMode};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A machine on the loopback interface (design §8.3 `LoopbackNet`): its one
/// address is `127.0.0.x`, reported as a private address of a physical
/// interface with prefix /8, and its session sockets are real UDP sockets
/// bound to that address (IPv4 only). Two values with different `x` are two
/// computers on one LAN. Linux and Windows route all of `127/8` to the
/// loopback interface; macOS has only `127.0.0.1` unless more are aliased
/// (`ifconfig lo0 alias 127.0.0.2`).
#[derive(Debug, Clone, Copy)]
pub struct LoopbackNet {
    ip: Ipv4Addr,
}

impl LoopbackNet {
    /// The machine at `127.0.0.x`.
    #[must_use]
    pub fn new(x: u8) -> Self {
        Self {
            ip: Ipv4Addr::new(127, 0, 0, x),
        }
    }

    /// Its address.
    #[must_use]
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// Its one interface address.
    fn iface(&self) -> IfaceAddr {
        IfaceAddr {
            ip: IpAddr::V4(self.ip),
            prefix_len: 8,
            class: AddrClass::Private,
            temporary: false,
            deprecated: false,
            tentative: false,
            duplicated: false,
            eui64: false,
            iface_index: 1,
            iface_kind: IfaceKind::Physical,
            up: true,
            gateway_v4: None,
        }
    }

    fn bind_once(&self, port: u16) -> io::Result<std::net::UdpSocket> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let _ = sock.set_recv_buffer_size(RECV_BUFFER);
        sock.set_nonblocking(true)?;
        sock.bind(&SocketAddr::new(IpAddr::V4(self.ip), port).into())?;
        Ok(sock.into())
    }
}

impl NetEnv for LoopbackNet {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        let iface = self.iface();
        Box::pin(async move { Ok(vec![iface]) })
    }

    fn route_sources(&self) -> RouteSources {
        RouteSources {
            v4: Some(self.ip),
            v6: None,
        }
    }

    /// A real UDP socket on `127.0.0.x:port` (a busy `port` is retried
    /// with any port), under [`QuietUdp`](crate::QuietUdp).
    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp> {
        let fixed = port.unwrap_or(0);
        let sock = match self.bind_once(fixed) {
            Err(e) if fixed != 0 && e.kind() == io::ErrorKind::AddrInUse => self.bind_once(0),
            other => other,
        }?;
        BoundUdp::quiet(BoundSocket {
            sock,
            dual_stack: false,
        })
    }

    /// No name resolves here (the loopback STUN servers of step B3 are
    /// given as addresses).
    fn resolve(&self, _host: &str, _port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        Box::pin(async { Err(io::ErrorKind::NotFound.into()) })
    }

    /// No router: [`NoMapper`].
    fn mapper(&self) -> Arc<dyn PortMapper> {
        Arc::new(NoMapper)
    }

    fn admit_loopback(&self) -> bool {
        true
    }
}

/// [`LoopbackNet`] behind the seam, as a link holds it.
#[must_use]
pub fn loopback(x: u8) -> Arc<dyn NetEnv> {
    Arc::new(LoopbackNet::new(x))
}

/// How a segment carries datagrams between its machines, or a link between
/// two segments.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkSpec {
    /// The one-way delay.
    pub latency: Duration,
    /// The share of datagrams lost, from 0.0 to 1.0, drawn from the
    /// network's seeded generator.
    pub loss: f64,
}

impl LinkSpec {
    /// A home LAN: 1 ms one way, no loss.
    pub const LAN: Self = Self {
        latency: Duration::from_millis(1),
        loss: 0.0,
    };
}

impl Default for LinkSpec {
    fn default() -> Self {
        Self::LAN
    }
}

/// One segment (one LAN) of a [`MemNet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Segment(usize);

/// What a machine's host firewall does with the datagrams that reach it
/// (design §3.7 "Open question": whether punched flows pass under the
/// operating systems' block rules is a device question; these cover both
/// answers).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InboundRule {
    /// Every datagram arrives.
    #[default]
    Open,
    /// A datagram arrives only from an address the receiving socket sent to
    /// within [`STATEFUL_TIMEOUT`] (a stateful firewall: an outbound probe
    /// opens the way for its peer's answers and requests).
    Stateful,
    /// No datagram arrives; the machine's own sends still leave (an
    /// application its firewall blocks inbound).
    Blocked,
}

/// How long a [`InboundRule::Stateful`] firewall keeps a flow open after
/// its last datagram.
pub const STATEFUL_TIMEOUT: Duration = Duration::from_secs(30);

/// The first port a [`MemHost`] gives a socket bound to any port.
pub const FIRST_PORT: u16 = 49_152;

/// How many datagrams wait in one [`MemUdp`]'s receive queue; more are
/// dropped ([`Fate::Overflow`]), as a full socket buffer drops them.
pub const INBOX_LIMIT: usize = 8_192;

/// An address of a [`MemHost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemAddr {
    /// The segment it is on; its interface is that segment's.
    pub segment: Segment,
    /// The address.
    pub ip: IpAddr,
    /// Its prefix length (its on-link prefix).
    pub prefix_len: u8,
    /// The kind of its interface.
    pub kind: IfaceKind,
    /// IPv6: a temporary (privacy) address.
    pub temporary: bool,
    /// The IPv4 default gateway of its interface ([`IfaceAddr::gateway_v4`]):
    /// the inside address of a [`NatBox`] ([`NatBox::lan`]) whose router
    /// its [`MemMapper`] asks.
    pub gateway_v4: Option<Ipv4Addr>,
}

impl MemAddr {
    /// `cidr` (`"192.168.1.10/24"`, `"fd12:3456:789a:1::10/64"`) on the
    /// physical interface of `segment`.
    ///
    /// # Panics
    ///
    /// If `cidr` is not an address with a prefix length.
    #[must_use]
    pub fn new(segment: Segment, cidr: &str) -> Self {
        let net: IpNet = cidr.parse().expect("an address with its prefix length");
        Self {
            segment,
            ip: net.addr(),
            prefix_len: net.prefix_len(),
            kind: IfaceKind::Physical,
            temporary: false,
            gateway_v4: None,
        }
    }

    fn on_link(&self, ip: IpAddr) -> bool {
        IpNet::new(self.ip, self.prefix_len).is_ok_and(|net| net.contains(&ip))
    }

    fn iface(&self) -> IfaceAddr {
        IfaceAddr {
            ip: self.ip,
            prefix_len: self.prefix_len,
            class: addr::class(self.ip),
            temporary: self.temporary,
            deprecated: false,
            tentative: false,
            duplicated: false,
            eui64: false,
            iface_index: u32::try_from(self.segment.0 + 1).unwrap_or(u32::MAX),
            iface_kind: self.kind,
            up: true,
            gateway_v4: self.gateway_v4,
        }
    }
}

/// What a [`MemHost`] is.
#[derive(Debug, Clone)]
pub struct MachineSpec {
    /// Its addresses, in the order its interface read lists them.
    pub addrs: Vec<MemAddr>,
    /// Its route sources; `None`: its first IPv4 address and its first
    /// global IPv6 address.
    pub sources: Option<RouteSources>,
    /// Its session sockets are dual-stack (the default, as on a machine
    /// with IPv6); otherwise IPv4 only.
    pub dual_stack: bool,
    /// Its host firewall.
    pub inbound: InboundRule,
    /// Every bind fails.
    pub fail_bind: bool,
    /// The interface read fails.
    pub fail_interfaces: bool,
}

impl Default for MachineSpec {
    /// No address, dual-stack sockets, an open firewall.
    fn default() -> Self {
        Self {
            addrs: Vec::new(),
            sources: None,
            dual_stack: true,
            inbound: InboundRule::Open,
            fail_bind: false,
            fail_interfaces: false,
        }
    }
}

impl MachineSpec {
    /// A machine with one address, `cidr` on `segment` ([`MemAddr::new`]).
    #[must_use]
    pub fn on(segment: Segment, cidr: &str) -> Self {
        Self::default().and(segment, cidr)
    }

    /// The same machine with one more address.
    #[must_use]
    pub fn and(mut self, segment: Segment, cidr: &str) -> Self {
        self.addrs.push(MemAddr::new(segment, cidr));
        self
    }

    /// The same machine, its last address's interface reporting `gateway`
    /// as its IPv4 default gateway ([`MemAddr::gateway_v4`]).
    ///
    /// # Panics
    ///
    /// If the machine has no address yet, or `gateway` is not an IPv4
    /// address.
    #[must_use]
    pub fn gateway(mut self, gateway: &str) -> Self {
        let last = self.addrs.last_mut().expect("an address to give a gateway");
        last.gateway_v4 = Some(gateway.parse().expect("an IPv4 gateway"));
        self
    }

    fn route_sources(&self) -> RouteSources {
        self.sources.unwrap_or_else(|| RouteSources {
            v4: self.addrs.iter().find_map(|a| match a.ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            }),
            v6: self.addrs.iter().find_map(|a| match a.ip {
                IpAddr::V6(v6) if addr::class_v6(v6) == AddrClass::Global => Some(v6),
                _ => None,
            }),
        })
    }
}

/// What became of one datagram on a [`MemNet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fate {
    /// It reached a socket's receive queue.
    Delivered,
    /// The segment or link lost it.
    Lost,
    /// No machine with its destination address is reachable from its
    /// source's segment.
    Unroutable,
    /// No socket is bound to its destination port (or the socket there is
    /// IPv4 and the datagram IPv6).
    NoSocket,
    /// The receiving machine's firewall ([`InboundRule`]) dropped it.
    Filtered,
    /// The receiving socket's queue was full ([`INBOX_LIMIT`]).
    Overflow,
    /// A [`NatBox`] had nothing for it: no mapping and no forward at its
    /// destination port (a firewall: no flow of its destination address).
    NoMapping,
    /// A [`NatBox`]'s filtering refused its source ([`NatFiltering`]).
    NatFiltered,
    /// It was sent from inside a [`NatBox`] to that box's own public
    /// address, and the box does not hairpin.
    NoHairpin,
}

/// What a datagram on the wire looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireKind {
    /// A punch probe's shape ([`is_probe`]).
    Probe,
    /// A STUN message's shape ([`is_stun`]).
    Stun,
    /// Anything else (QUIC).
    Other,
}

/// One datagram on a [`MemNet`], as [`MemNet::wire`] lists it. Test-only:
/// unlike the link's own types it holds addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireRecord {
    /// When it was sent.
    pub at: Instant,
    /// Its source (canonical).
    pub from: SocketAddr,
    /// Its destination (canonical).
    pub to: SocketAddr,
    /// Its size.
    pub len: usize,
    /// Its shape.
    pub kind: WireKind,
    /// What became of it.
    pub fate: Fate,
    /// Delivered: its source as the receiver saw it, after the
    /// [`NatBox`]es on its way translated it.
    pub seen_from: Option<SocketAddr>,
}

/// A machine's socket counters, over all its sockets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemCounters {
    /// Sockets bound.
    pub binds: u64,
    /// Datagrams sent onto the wire.
    pub sent: u64,
    /// Datagrams delivered to its sockets.
    pub received: u64,
    /// Sends refused for their destination's family: a plain IPv4
    /// destination on a dual-stack socket, an IPv6 one on an IPv4 socket.
    pub invalid_input: u64,
    /// Sends refused because their `src_ip` is not an address of this
    /// machine of the destination's family.
    pub bad_source: u64,
    /// Sends refused because no address of this machine can reach the
    /// destination (no on-link prefix holds it and no route source of its
    /// family).
    pub no_route: u64,
}

/// An in-memory network (see the module documentation). Clones share the
/// network.
#[derive(Clone)]
pub struct MemNet {
    net: Arc<Net>,
}

struct Net {
    state: Mutex<NetState>,
}

struct NetState {
    rng: u64,
    seq: u64,
    segments: Vec<LinkSpec>,
    links: Vec<(Segment, Segment, LinkSpec)>,
    machines: Vec<Machine>,
    nats: Vec<nat::Nat>,
    names: HashMap<String, Vec<IpAddr>>,
    wire: Vec<WireRecord>,
}

struct Machine {
    spec: MachineSpec,
    sockets: Vec<(u16, Weak<MemUdp>)>,
    counters: MemCounters,
    /// Counts the releases of the mappings its [`MemMapper`] made.
    releases: ReleaseTracker,
}

/// The most boxes a datagram crosses (a loop in a test's topology ends
/// there as [`Fate::Unroutable`]).
const MAX_HOPS: usize = 8;

/// The next step of a datagram from a segment toward an address.
enum Hop {
    /// To a machine holding the address, over this spec.
    Machine(usize, LinkSpec),
    /// Into a [`NatBox`] from its outside (to its public address, or to an
    /// address behind a firewall), over this spec.
    Inbound(usize, LinkSpec),
    /// Out through the [`NatBox`] behind which the segment is, over the
    /// segment.
    Outbound(usize, LinkSpec),
}

/// Where a datagram arrives: the machine, its source and destination as
/// the machine sees them, the latency of the hops before the last, and the
/// last hop's spec.
struct Arrives {
    machine: usize,
    from: SocketAddr,
    to: SocketAddr,
    before: Duration,
    last: LinkSpec,
}

impl NetState {
    /// xorshift64 (Marsaglia), seeded through splitmix64.
    fn next(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    fn lost(&mut self, loss: f64) -> bool {
        if loss <= 0.0 {
            return false;
        }
        let draw = (self.next() >> 11) as f64 / (1_u64 << 53) as f64;
        draw < loss
    }

    /// The machines holding `ip` on `segment`, in order.
    fn holders(&self, segment: Segment, ip: IpAddr) -> impl Iterator<Item = usize> + '_ {
        self.machines
            .iter()
            .enumerate()
            .filter(move |(_, m)| {
                m.spec
                    .addrs
                    .iter()
                    .any(|a| a.ip == ip && a.segment == segment)
            })
            .map(|(id, _)| id)
    }

    /// Whether `segment` holds `ip`: a machine's address, or the public
    /// address of a translating [`NatBox`] outside on it.
    fn has(&self, segment: Segment, ip: IpAddr) -> bool {
        self.holders(segment, ip).next().is_some()
            || self
                .nats
                .iter()
                .any(|n| n.spec.outside == segment && n.public_is(ip))
    }

    /// The [`NatBox`] outside on `segment` that takes a datagram to `ip`
    /// in: a translating one at its public address, a firewall when a
    /// segment behind it holds `ip`.
    fn inbound_at(&self, segment: Segment, ip: IpAddr) -> Option<usize> {
        self.nats.iter().position(|n| {
            n.spec.outside == segment
                && if n.spec.translate {
                    n.public_is(ip)
                } else {
                    ip.is_ipv6() && n.spec.inside.iter().any(|s| self.has(*s, ip))
                }
        })
    }

    /// The link between `a` and `b`, if any.
    fn link_between(&self, a: Segment, b: Segment) -> Option<LinkSpec> {
        self.links
            .iter()
            .find(|(x, y, _)| (*x == a && *y == b) || (*x == b && *y == a))
            .map(|(_, _, spec)| *spec)
    }

    /// The next hop from `segment` toward `ip`: a machine holding it on
    /// the segment, a box taking it in there, then the same on a linked
    /// segment, then a machine on another segment behind the same box, then
    /// out through the box the segment is behind (IPv4 through a
    /// translating box, IPv6 through a firewall).
    fn hop(&self, segment: Segment, ip: IpAddr) -> Option<Hop> {
        let here = self.segments[segment.0];
        if let Some(id) = self.holders(segment, ip).next() {
            return Some(Hop::Machine(id, here));
        }
        if let Some(n) = self.inbound_at(segment, ip) {
            return Some(Hop::Inbound(n, here));
        }
        let linked = self.machines.iter().enumerate().find_map(|(id, m)| {
            m.spec
                .addrs
                .iter()
                .filter(|a| a.ip == ip)
                .find_map(|a| self.link_between(segment, a.segment))
                .map(|spec| Hop::Machine(id, spec))
        });
        if linked.is_some() {
            return linked;
        }
        for (a, b, spec) in &self.links {
            let other = if *a == segment {
                *b
            } else if *b == segment {
                *a
            } else {
                continue;
            };
            if let Some(n) = self.inbound_at(other, ip) {
                return Some(Hop::Inbound(n, *spec));
            }
        }
        let behind = |n: &nat::Nat| n.spec.inside.contains(&segment);
        for n in self.nats.iter().filter(|n| behind(n)) {
            for inside in &n.spec.inside {
                if let Some(id) = self.holders(*inside, ip).next() {
                    return Some(Hop::Machine(id, here));
                }
            }
        }
        self.nats
            .iter()
            .position(|n| behind(n) && n.carries(ip))
            .map(|n| Hop::Outbound(n, here))
    }

    /// The segment behind box `n` that holds `ip` (its first otherwise).
    fn inside_toward(&self, n: usize, ip: IpAddr) -> Segment {
        let inside = &self.nats[n].spec.inside;
        inside
            .iter()
            .copied()
            .find(|s| self.has(*s, ip))
            .unwrap_or(inside[0])
    }

    /// The way of a datagram from `from` on `segment` to `to` (both
    /// canonical) through the boxes on its way: where it arrives, or why
    /// it does not. The hops through boxes draw their loss here; the last
    /// hop's is drawn by the caller, after the receiving socket and its
    /// firewall, as before there were boxes.
    fn route(
        &mut self,
        segment: Segment,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Arrives, Fate> {
        let (mut segment, mut from, mut to) = (segment, from, to);
        let mut before = Duration::ZERO;
        for _ in 0..MAX_HOPS {
            match self.hop(segment, to.ip()).ok_or(Fate::Unroutable)? {
                Hop::Machine(machine, last) => {
                    return Ok(Arrives {
                        machine,
                        from,
                        to,
                        before,
                        last,
                    });
                }
                Hop::Inbound(n, spec) => {
                    if self.lost(spec.loss) {
                        return Err(Fate::Lost);
                    }
                    before += spec.latency;
                    to = self.nats[n].inbound(from, to, now)?;
                    segment = self.inside_toward(n, to.ip());
                }
                Hop::Outbound(n, spec) => {
                    if self.lost(spec.loss) {
                        return Err(Fate::Lost);
                    }
                    before += spec.latency;
                    let nat = &mut self.nats[n];
                    let hairpin = nat.spec.translate && nat.public_is(to.ip());
                    if hairpin && !nat.spec.hairpin {
                        return Err(Fate::NoHairpin);
                    }
                    from = nat.outbound(from, to, now);
                    if hairpin {
                        to = nat.inbound(from, to, now)?;
                        segment = self.inside_toward(n, to.ip());
                    } else {
                        segment = nat.spec.outside;
                    }
                }
            }
        }
        Err(Fate::Unroutable)
    }
}

impl MemNet {
    /// An empty network whose losses are drawn from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        // splitmix64 of the seed, never zero (xorshift's fixed point).
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        Self {
            net: Arc::new(Net {
                state: Mutex::new(NetState {
                    rng: z | 1,
                    seq: 0,
                    segments: Vec::new(),
                    links: Vec::new(),
                    machines: Vec::new(),
                    nats: Vec::new(),
                    names: HashMap::new(),
                    wire: Vec::new(),
                }),
            }),
        }
    }

    /// A new segment whose machines reach each other with `spec`.
    #[must_use]
    pub fn segment(&self, spec: LinkSpec) -> Segment {
        let mut state = lock(&self.net.state);
        state.segments.push(spec);
        Segment(state.segments.len() - 1)
    }

    /// Routes between segments `a` and `b` with `spec` (both ways).
    pub fn link(&self, a: Segment, b: Segment, spec: LinkSpec) {
        lock(&self.net.state).links.push((a, b, spec));
    }

    /// A new machine.
    #[must_use]
    pub fn machine(&self, spec: MachineSpec) -> MemHost {
        let mut state = lock(&self.net.state);
        state.machines.push(Machine {
            spec,
            sockets: Vec::new(),
            counters: MemCounters::default(),
            releases: ReleaseTracker::new(),
        });
        MemHost {
            net: Arc::clone(&self.net),
            id: state.machines.len() - 1,
        }
    }

    /// A new [`NatBox`] between its inside segments and its outside one.
    ///
    /// # Panics
    ///
    /// If `spec` has no inside segment.
    #[must_use]
    pub fn nat(&self, spec: NatBox) -> MemNat {
        assert!(!spec.inside.is_empty(), "a box with a segment behind it");
        let mut state = lock(&self.net.state);
        state.nats.push(nat::Nat::new(spec));
        MemNat {
            net: Arc::clone(&self.net),
            id: state.nats.len() - 1,
        }
    }

    /// `host` resolves to `ips` for every machine of the network, from now
    /// on.
    pub fn name(&self, host: &str, ips: &[IpAddr]) {
        lock(&self.net.state)
            .names
            .insert(host.to_owned(), ips.to_vec());
    }

    /// Every datagram sent so far, in order.
    #[must_use]
    pub fn wire(&self) -> Vec<WireRecord> {
        lock(&self.net.state).wire.clone()
    }
}

impl fmt::Debug for MemNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.net.state);
        f.debug_struct("MemNet")
            .field("segments", &state.segments.len())
            .field("machines", &state.machines.len())
            .field("nats", &state.nats.len())
            .field("datagrams", &state.wire.len())
            .finish()
    }
}

/// A machine on a [`MemNet`]: a [`NetEnv`] whose sockets are [`MemUdp`].
/// Clones are the same machine.
#[derive(Clone)]
pub struct MemHost {
    net: Arc<Net>,
    id: usize,
}

impl MemHost {
    /// Its socket counters.
    #[must_use]
    pub fn counters(&self) -> MemCounters {
        lock(&self.net.state).machines[self.id].counters
    }

    /// Changes its firewall.
    pub fn set_inbound(&self, rule: InboundRule) {
        lock(&self.net.state).machines[self.id].spec.inbound = rule;
    }

    /// Its addresses.
    #[must_use]
    pub fn addrs(&self) -> Vec<IpAddr> {
        lock(&self.net.state).machines[self.id]
            .spec
            .addrs
            .iter()
            .map(|a| a.ip)
            .collect()
    }

    /// Binds a socket at `port` when it is free, at the next free port from
    /// [`FIRST_PORT`] otherwise.
    ///
    /// # Errors
    ///
    /// The machine's binds fail ([`MachineSpec::fail_bind`]), or every port
    /// is taken.
    pub fn bind_udp(&self, port: Option<u16>) -> io::Result<Arc<MemUdp>> {
        let mut state = lock(&self.net.state);
        let machine = &mut state.machines[self.id];
        if machine.spec.fail_bind {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        machine.sockets.retain(|(_, s)| s.strong_count() > 0);
        let taken = |p: u16| machine.sockets.iter().any(|(at, _)| *at == p);
        let port = match port {
            Some(p) if p != 0 && !taken(p) => p,
            _ => (FIRST_PORT..=u16::MAX)
                .find(|p| !taken(*p))
                .ok_or(io::ErrorKind::AddrInUse)?,
        };
        let socket = Arc::new(MemUdp {
            net: Arc::clone(&self.net),
            machine: self.id,
            port,
            dual_stack: machine.spec.dual_stack,
            spoof: Mutex::new(None),
            state: Mutex::default(),
        });
        machine.sockets.push((port, Arc::downgrade(&socket)));
        machine.counters.binds += 1;
        Ok(socket)
    }
}

impl NetEnv for MemHost {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        let state = lock(&self.net.state);
        let spec = &state.machines[self.id].spec;
        let read = if spec.fail_interfaces {
            Err(NetError::InterfacesTimedOut)
        } else {
            Ok(spec.addrs.iter().map(MemAddr::iface).collect())
        };
        Box::pin(async move { read })
    }

    fn route_sources(&self) -> RouteSources {
        lock(&self.net.state).machines[self.id].spec.route_sources()
    }

    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp> {
        let socket = self.bind_udp(port)?;
        Ok(BoundUdp {
            dual_stack: socket.dual_stack,
            inner: socket,
            errors: Arc::default(),
        })
    }

    /// The network's table ([`MemNet::name`]), at once; a name it lacks
    /// is `NotFound`.
    fn resolve(&self, host: &str, port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        let found = lock(&self.net.state).names.get(host).map(|ips| {
            ips.iter()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect::<Vec<_>>()
        });
        Box::pin(async move { found.ok_or_else(|| io::ErrorKind::NotFound.into()) })
    }

    /// The machine's [`MemMapper`]: it asks the router of the [`NatBox`]
    /// whose inside address is the request's gateway.
    fn mapper(&self) -> Arc<dyn PortMapper> {
        let releases = lock(&self.net.state).machines[self.id].releases.clone();
        Arc::new(MemMapper::new(Arc::clone(&self.net), self.id, releases))
    }
}

impl fmt::Debug for MemHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemHost").field("id", &self.id).finish()
    }
}

/// A session socket on a [`MemNet`] (see the module documentation): bound
/// to every address of its machine at one port, always writable, and
/// delivering on tokio's clock. It reports `dst_ip` (canonical, as
/// quinn-udp reports `IP_PKTINFO`) on every datagram and sends from
/// `src_ip` when given, which must be one of its machine's addresses.
pub struct MemUdp {
    net: Arc<Net>,
    machine: usize,
    port: u16,
    dual_stack: bool,
    /// The source every datagram carries instead of this machine's own
    /// ([`MemUdp::spoof_as`]).
    spoof: Mutex<Option<SocketAddr>>,
    state: Mutex<UdpState>,
}

#[derive(Default)]
struct UdpState {
    inbox: BTreeMap<(Instant, u64), Arrival>,
    waker: Option<Waker>,
    sleep: Option<Pin<Box<Sleep>>>,
    /// The last time this socket sent to each address (the stateful
    /// firewall's flows).
    sent_to: HashMap<SocketAddr, Instant>,
}

struct Arrival {
    from: SocketAddr,
    dst_ip: IpAddr,
    bytes: Vec<u8>,
}

impl MemUdp {
    /// The port it is bound to.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether it is dual-stack.
    #[must_use]
    pub fn dual_stack(&self) -> bool {
        self.dual_stack
    }

    /// From now on, every datagram this socket sends carries `from` as its
    /// source (an off-path attacker's forged datagrams), leaving from the
    /// segment of the machine's first address; `None` ends it. The wire
    /// records the forged source.
    pub fn spoof_as(&self, from: Option<SocketAddr>) {
        *lock(&self.spoof) = from.map(canon);
    }

    fn count(&self, change: impl FnOnce(&mut MemCounters)) {
        change(&mut lock(&self.net.state).machines[self.machine].counters);
    }

    /// The source address of a datagram to `dst` (canonical): `src` when it
    /// is an address of this machine of the same family; otherwise the
    /// kernel's choice, an address whose on-link prefix holds `dst`, else
    /// the route source of that family.
    fn source(&self, dst: IpAddr, src: Option<IpAddr>) -> io::Result<IpAddr> {
        let mut state = lock(&self.net.state);
        let machine = &mut state.machines[self.machine];
        let same_family = |ip: IpAddr| ip.is_ipv4() == dst.is_ipv4();
        if let Some(src) = src {
            if same_family(src) && machine.spec.addrs.iter().any(|a| a.ip == src) {
                return Ok(src);
            }
            machine.counters.bad_source += 1;
            return Err(io::ErrorKind::AddrNotAvailable.into());
        }
        let sources = machine.spec.route_sources();
        let routed = match dst {
            IpAddr::V4(_) => sources.v4.map(IpAddr::V4),
            IpAddr::V6(_) => sources.v6.map(IpAddr::V6),
        };
        let chosen = machine
            .spec
            .addrs
            .iter()
            .find(|a| same_family(a.ip) && a.on_link(dst))
            .map(|a| a.ip)
            .or(routed.filter(|ip| machine.spec.addrs.iter().any(|a| a.ip == *ip)));
        chosen.ok_or_else(|| {
            machine.counters.no_route += 1;
            io::ErrorKind::NetworkUnreachable.into()
        })
    }

    /// Whether this socket sent to `from` within [`STATEFUL_TIMEOUT`]; a
    /// datagram that passes keeps the flow open.
    fn solicited(&self, from: SocketAddr, now: Instant) -> bool {
        let mut state = lock(&self.state);
        match state.sent_to.get_mut(&from) {
            Some(last) if now.saturating_duration_since(*last) <= STATEFUL_TIMEOUT => {
                *last = now;
                true
            }
            _ => false,
        }
    }

    /// Queues a datagram for `at`; false when the queue is full.
    fn arrive(
        &self,
        at: Instant,
        seq: u64,
        from: SocketAddr,
        dst_ip: IpAddr,
        bytes: &[u8],
    ) -> bool {
        let mut state = lock(&self.state);
        if state.inbox.len() >= INBOX_LIMIT {
            return false;
        }
        state.inbox.insert(
            (at, seq),
            Arrival {
                from: to_socket_family(from, self.dual_stack),
                dst_ip,
                bytes: bytes.to_vec(),
            },
        );
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
        true
    }

    /// Puts one datagram on the wire from `from` on `segment` (this
    /// machine's, unless spoofed) to `to` (both canonical) and logs its
    /// fate.
    fn carry(
        &self,
        segment: Option<Segment>,
        from: SocketAddr,
        to: SocketAddr,
        bytes: &[u8],
        now: Instant,
    ) {
        let mut state = lock(&self.net.state);
        state.machines[self.machine].counters.sent += 1;
        let routed = match segment {
            None => Err(Fate::Unroutable),
            Some(segment) => state.route(segment, from, to, now),
        };
        let mut seen_from = None;
        let fate = match routed {
            Err(fate) => fate,
            Ok(arrives) => {
                let target = arrives.machine;
                let socket = state.machines[target]
                    .sockets
                    .iter()
                    .find(|(port, _)| *port == arrives.to.port())
                    .and_then(|(_, socket)| socket.upgrade())
                    .filter(|socket| socket.dual_stack || arrives.to.is_ipv4());
                match socket {
                    None => Fate::NoSocket,
                    Some(socket) => {
                        let admitted = match state.machines[target].spec.inbound {
                            InboundRule::Open => true,
                            InboundRule::Stateful => socket.solicited(arrives.from, now),
                            InboundRule::Blocked => false,
                        };
                        if !admitted {
                            Fate::Filtered
                        } else if state.lost(arrives.last.loss) {
                            Fate::Lost
                        } else {
                            state.seq += 1;
                            let seq = state.seq;
                            let at = now + arrives.before + arrives.last.latency;
                            if socket.arrive(at, seq, arrives.from, arrives.to.ip(), bytes) {
                                state.machines[target].counters.received += 1;
                                seen_from = Some(arrives.from);
                                Fate::Delivered
                            } else {
                                Fate::Overflow
                            }
                        }
                    }
                }
            }
        };
        let kind = if is_probe(bytes) {
            WireKind::Probe
        } else if is_stun(bytes) {
            WireKind::Stun
        } else {
            WireKind::Other
        };
        state.wire.push(WireRecord {
            at: now,
            from,
            to,
            len: bytes.len(),
            kind,
            fate,
            seen_from,
        });
    }
}

impl fmt::Debug for MemUdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemUdp")
            .field("dual_stack", &self.dual_stack)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for MemUdp {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if self.dual_stack == transmit.destination.is_ipv4() {
            self.count(|c| c.invalid_input += 1);
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let to = canon(transmit.destination);
        let spoofed = *lock(&self.spoof);
        let (from, segment) = match spoofed {
            Some(forged) => {
                let state = lock(&self.net.state);
                let first = state.machines[self.machine].spec.addrs.first();
                (forged, first.map(|a| a.segment))
            }
            None => {
                let src = self.source(to.ip(), transmit.src_ip.map(canon_ip))?;
                let state = lock(&self.net.state);
                let segment = state.machines[self.machine]
                    .spec
                    .addrs
                    .iter()
                    .find(|a| a.ip == src)
                    .map(|a| a.segment);
                (SocketAddr::new(src, self.port), segment)
            }
        };
        let now = Instant::now();
        lock(&self.state).sent_to.insert(to, now);
        let size = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        for chunk in transmit.contents.chunks(size) {
            self.carry(segment, from, to, chunk, now);
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let now = Instant::now();
        let mut state = lock(&self.state);
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            let Some(entry) = state.inbox.first_entry() else {
                break;
            };
            if entry.key().0 > now {
                break;
            }
            let arrival = entry.remove();
            let len = arrival.bytes.len().min(bufs[n].len());
            bufs[n][..len].copy_from_slice(&arrival.bytes[..len]);
            meta[n] = RecvMeta {
                addr: arrival.from,
                len,
                stride: len,
                dst_ip: Some(arrival.dst_ip),
                ..RecvMeta::default()
            };
            n += 1;
        }
        if n > 0 {
            return Poll::Ready(Ok(n));
        }
        state.waker = Some(cx.waker().clone());
        let next = state.inbox.first_key_value().map(|((at, _), _)| *at);
        if let Some(at) = next {
            let sleep = state
                .sleep
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            sleep.as_mut().reset(at);
            if sleep.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        let ip = if self.dual_stack {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        Ok(SocketAddr::new(ip, self.port))
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// The calls a [`CountingEnv`] saw.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EnvCalls {
    /// [`NetEnv::interfaces`].
    pub interfaces: usize,
    /// [`NetEnv::route_sources`].
    pub route_sources: usize,
    /// [`NetEnv::route_source_to`].
    pub route_source_to: usize,
    /// [`NetEnv::bind`].
    pub binds: usize,
    /// [`NetEnv::resolve`].
    pub resolves: usize,
    /// [`NetEnv::mapper`].
    pub mappers: usize,
    /// [`NetEnv::admit_loopback`].
    pub admit_loopback: usize,
}

impl EnvCalls {
    /// Every call.
    #[must_use]
    pub fn total(&self) -> usize {
        self.interfaces
            + self.route_sources
            + self.route_source_to
            + self.binds
            + self.resolves
            + self.mappers
            + self.admit_loopback
    }
}

/// A [`NetEnv`] that counts every call to the one it wraps (design §8.3
/// `CountingEnv`). The STUN requests a link sends are not environment
/// calls: they are read from the link's socket counters.
#[derive(Debug)]
pub struct CountingEnv<E> {
    inner: E,
    interfaces: AtomicUsize,
    route_sources: AtomicUsize,
    route_source_to: AtomicUsize,
    binds: AtomicUsize,
    resolves: AtomicUsize,
    mappers: AtomicUsize,
    admit_loopback: AtomicUsize,
}

impl<E: NetEnv> CountingEnv<E> {
    /// Wraps `inner`.
    #[must_use]
    pub fn new(inner: E) -> Arc<Self> {
        Arc::new(Self {
            inner,
            interfaces: AtomicUsize::new(0),
            route_sources: AtomicUsize::new(0),
            route_source_to: AtomicUsize::new(0),
            binds: AtomicUsize::new(0),
            resolves: AtomicUsize::new(0),
            mappers: AtomicUsize::new(0),
            admit_loopback: AtomicUsize::new(0),
        })
    }

    /// The calls so far.
    #[must_use]
    pub fn calls(&self) -> EnvCalls {
        EnvCalls {
            interfaces: self.interfaces.load(Ordering::SeqCst),
            route_sources: self.route_sources.load(Ordering::SeqCst),
            route_source_to: self.route_source_to.load(Ordering::SeqCst),
            binds: self.binds.load(Ordering::SeqCst),
            resolves: self.resolves.load(Ordering::SeqCst),
            mappers: self.mappers.load(Ordering::SeqCst),
            admit_loopback: self.admit_loopback.load(Ordering::SeqCst),
        }
    }

    /// The wrapped environment.
    #[must_use]
    pub fn inner(&self) -> &E {
        &self.inner
    }
}

impl<E: NetEnv> NetEnv for CountingEnv<E> {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        self.interfaces.fetch_add(1, Ordering::SeqCst);
        self.inner.interfaces()
    }

    fn route_sources(&self) -> RouteSources {
        self.route_sources.fetch_add(1, Ordering::SeqCst);
        self.inner.route_sources()
    }

    fn route_source_to(&self, to: SocketAddr) -> Option<IpAddr> {
        self.route_source_to.fetch_add(1, Ordering::SeqCst);
        self.inner.route_source_to(to)
    }

    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp> {
        self.binds.fetch_add(1, Ordering::SeqCst);
        self.inner.bind(port)
    }

    fn resolve(&self, host: &str, port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        self.resolves.fetch_add(1, Ordering::SeqCst);
        self.inner.resolve(host, port)
    }

    fn mapper(&self) -> Arc<dyn PortMapper> {
        self.mappers.fetch_add(1, Ordering::SeqCst);
        self.inner.mapper()
    }

    fn admit_loopback(&self) -> bool {
        self.admit_loopback.fetch_add(1, Ordering::SeqCst);
        self.inner.admit_loopback()
    }
}

/// Two ends of an in-memory byte pipe whose bytes arrive `one_way` after
/// they were written, on tokio's clock; each direction holds at most
/// `max_buf` bytes in flight (a writer beyond it waits). Like
/// `tokio::io::duplex`: a shut-down or dropped end gives its peer's reads
/// the end of the stream (after the delay), and writes toward a dropped end
/// fail with `BrokenPipe`.
#[must_use]
pub fn lagged_duplex(max_buf: usize, one_way: Duration) -> (LaggedDuplex, LaggedDuplex) {
    let a_to_b = Arc::new(Mutex::new(Pipe::default()));
    let b_to_a = Arc::new(Mutex::new(Pipe::default()));
    let end = |read: &Arc<Mutex<Pipe>>, write: &Arc<Mutex<Pipe>>| LaggedDuplex {
        read: Arc::clone(read),
        write: Arc::clone(write),
        one_way,
        max_buf: max_buf.max(1),
        sleep: None,
    };
    (end(&b_to_a, &a_to_b), end(&a_to_b, &b_to_a))
}

/// One end of [`lagged_duplex`].
pub struct LaggedDuplex {
    read: Arc<Mutex<Pipe>>,
    write: Arc<Mutex<Pipe>>,
    one_way: Duration,
    max_buf: usize,
    sleep: Option<Pin<Box<Sleep>>>,
}

#[derive(Default)]
struct Pipe {
    /// Written bytes and when they arrive, in order.
    chunks: VecDeque<(Instant, Vec<u8>)>,
    /// Bytes of the first chunk already read.
    consumed: usize,
    /// Bytes written and not yet read.
    buffered: usize,
    /// When the end of the stream arrives (the writer shut down or went).
    eof_at: Option<Instant>,
    /// The reading end is gone.
    reader_gone: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

impl Pipe {
    fn wake_reader(&mut self) {
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
    }

    fn wake_writer(&mut self) {
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
    }
}

impl LaggedDuplex {
    /// Waits for `at` on this end's timer: `Ready` if it already passed.
    fn wait_until(&mut self, at: Instant, cx: &mut Context<'_>) -> Poll<()> {
        let sleep = self
            .sleep
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
        sleep.as_mut().reset(at);
        sleep.as_mut().poll(cx)
    }
}

impl fmt::Debug for LaggedDuplex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaggedDuplex")
            .field("one_way", &self.one_way)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for LaggedDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let now = Instant::now();
        let next = {
            let mut pipe = lock(&self.read);
            let mut copied = 0;
            while buf.remaining() > 0 {
                let (at, len) = match pipe.chunks.front() {
                    Some((at, chunk)) => (*at, chunk.len()),
                    None => break,
                };
                if at > now {
                    break;
                }
                let start = pipe.consumed;
                let n = (len - start).min(buf.remaining());
                buf.put_slice(&pipe.chunks[0].1[start..start + n]);
                copied += n;
                if start + n == len {
                    pipe.chunks.pop_front();
                    pipe.consumed = 0;
                } else {
                    pipe.consumed = start + n;
                }
            }
            if copied > 0 {
                pipe.buffered -= copied;
                pipe.wake_writer();
                return Poll::Ready(Ok(()));
            }
            if pipe.chunks.is_empty() && pipe.eof_at.is_some_and(|at| at <= now) {
                return Poll::Ready(Ok(()));
            }
            pipe.reader = Some(cx.waker().clone());
            pipe.chunks.front().map(|(at, _)| *at).or(pipe.eof_at)
        };
        if let Some(at) = next
            && self.wait_until(at, cx).is_ready()
        {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl AsyncWrite for LaggedDuplex {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut pipe = lock(&self.write);
        if pipe.reader_gone || pipe.eof_at.is_some() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let room = self.max_buf.saturating_sub(pipe.buffered);
        if room == 0 {
            pipe.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(data.len());
        pipe.chunks
            .push_back((Instant::now() + self.one_way, data[..n].to_vec()));
        pipe.buffered += n;
        pipe.wake_reader();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut pipe = lock(&self.write);
        if pipe.eof_at.is_none() {
            pipe.eof_at = Some(Instant::now() + self.one_way);
        }
        pipe.wake_reader();
        Poll::Ready(Ok(()))
    }
}

impl Drop for LaggedDuplex {
    fn drop(&mut self) {
        {
            let mut pipe = lock(&self.write);
            if pipe.eof_at.is_none() {
                pipe.eof_at = Some(Instant::now() + self.one_way);
            }
            pipe.wake_reader();
        }
        let mut pipe = lock(&self.read);
        pipe.reader_gone = true;
        pipe.wake_writer();
    }
}

#[cfg(test)]
mod tests;
