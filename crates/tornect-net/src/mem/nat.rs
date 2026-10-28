//! The NATs and firewalls of a [`MemNet`] (design `direct` §12.4
//! `NatBox`): the translation and filtering one box applies to the
//! datagrams that cross it, and its forwards, which its router installs
//! ([`MemMapper`](super::MemMapper)) or a test sets up. The routing that
//! takes a datagram through the boxes on its way is the network's
//! (`NetState::route`).
//!
//! The behaviours are RFC 4787's: a mapping is endpoint-independent (one
//! external port per internal address and port), address-dependent (one
//! per destination address) or address-and-port-dependent (one per
//! destination address and port); the filtering lets in, at a mapping's
//! external port, anything, what comes from an address the mapping sent
//! to, or what comes from an address and port it sent to. A mapping, and
//! each destination it sent to, lives [`NAT_TIMEOUT`] after its last
//! datagram (outbound, or inbound and admitted).

use super::*;

/// How long a mapping of a [`NatBox`] lives after its last datagram, and
/// how long a destination it sent to stays admitted (RFC 4787 REQ-5 asks
/// for at least two minutes; home routers commonly keep 30 s for UDP, the
/// case the punch must survive).
pub const NAT_TIMEOUT: Duration = Duration::from_secs(30);

/// The first port a [`NatBox`] gives a mapping that cannot keep its
/// internal port.
const FIRST_NAT_PORT: u16 = 30_000;

/// How a [`NatBox`] picks the external port of an outbound flow (RFC 4787
/// §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatMapping {
    /// Endpoint-independent: one external port per internal address and
    /// port, whatever the destination.
    Eim,
    /// Address-dependent: one per internal address and port and
    /// destination address.
    Adm,
    /// Address-and-port-dependent ("symmetric"): one per destination
    /// address and port.
    Apdm,
}

/// Which datagrams from outside a [`NatBox`] passes to a mapping (RFC 4787
/// §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatFiltering {
    /// Endpoint-independent: any.
    Eif,
    /// Address-dependent: from an address the mapping sent to.
    Adf,
    /// Address-and-port-dependent: from an address and port the mapping
    /// sent to.
    Apdf,
}

/// A NAT, or a stateful IPv6 firewall, between segments of a [`MemNet`]
/// (design §12.4 `NatBox`), made with [`MemNet::nat`]: the segments behind
/// it reach anything beyond only through it.
#[derive(Debug, Clone, PartialEq)]
pub struct NatBox {
    /// The segments behind it. It routes between them; their datagrams to
    /// anywhere else leave through it, IPv4 through a translating box and
    /// IPv6 through a firewall.
    pub inside: Vec<Segment>,
    /// The segment its outside is on.
    pub outside: Segment,
    /// A translating box's public address on `outside` (unused by a
    /// firewall).
    pub public: Ipv4Addr,
    /// Its address on the inside: what the machines behind it report as
    /// their gateway ([`MachineSpec::gateway`]), and where its router
    /// answers.
    pub lan: Option<Ipv4Addr>,
    /// How it maps.
    pub mapping: NatMapping,
    /// How it filters.
    pub filtering: NatFiltering,
    /// A datagram from inside to its own public address comes back in, as
    /// if from outside; otherwise it is dropped ([`Fate::NoHairpin`]).
    pub hairpin: bool,
    /// A new mapping keeps its internal port as its external one when no
    /// other mapping or forward has it.
    pub port_preservation: bool,
    /// Static forwards, external port to inside address and port: they let
    /// every datagram in, and the forwarded address leaves from that port.
    pub forwards: Vec<(u16, SocketAddr)>,
    /// How long a mapping lives after its last datagram ([`NAT_TIMEOUT`]).
    pub timeout: Duration,
    /// It translates (NAT44). `false`: a stateful IPv6 firewall, which
    /// keeps addresses and ports and filters as `filtering` says.
    pub translate: bool,
    /// What its port-mapping router answers ([`MemMapper`]); `None`: the
    /// protocols are off, and a request goes unanswered.
    pub router: Option<MapperMode>,
}

impl NatBox {
    /// A home router: `inside` behind `public` on `outside`, endpoint-
    /// independent mapping with address-and-port-dependent filtering, port
    /// preservation, no hairpinning, [`NAT_TIMEOUT`], no forwards and no
    /// router protocols.
    ///
    /// # Panics
    ///
    /// If `public` is not an IPv4 address.
    #[must_use]
    pub fn home(inside: Segment, outside: Segment, public: &str) -> Self {
        Self {
            inside: vec![inside],
            outside,
            public: public.parse().expect("an IPv4 public address"),
            lan: None,
            mapping: NatMapping::Eim,
            filtering: NatFiltering::Apdf,
            hairpin: false,
            port_preservation: true,
            forwards: Vec::new(),
            timeout: NAT_TIMEOUT,
            translate: true,
            router: None,
        }
    }

    /// A stateful IPv6 firewall between `inside` and `outside`: it lets
    /// in only what comes from an address and port an inside address sent
    /// to.
    #[must_use]
    pub fn firewall(inside: Segment, outside: Segment) -> Self {
        Self {
            public: Ipv4Addr::UNSPECIFIED,
            translate: false,
            ..Self::home(inside, outside, "0.0.0.0")
        }
    }
}

/// One live mapping of a [`NatBox`], as [`MemNat::flows`] lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatFlow {
    /// The inside address and port.
    pub internal: SocketAddr,
    /// Its external port (a firewall's: the internal port).
    pub external: u16,
}

/// A box's state.
pub(super) struct Nat {
    pub(super) spec: NatBox,
    flows: Vec<Flow>,
    forwards: Vec<Forward>,
    next_port: u16,
    next_lease: u64,
    pub(super) log: Vec<RouterSeen>,
}

struct Flow {
    internal: SocketAddr,
    /// The destination it is for, as the mapping keys it: `None` for any
    /// (and a firewall's), the address with port 0 when address-dependent.
    key: Option<SocketAddr>,
    external: u16,
    last: Instant,
    /// The destinations it sent to, and when last.
    sent_to: HashMap<SocketAddr, Instant>,
}

struct Forward {
    /// `None`: a static forward.
    lease: Option<u64>,
    external: u16,
    internal: SocketAddr,
    /// When a router's lease ends; `None` never.
    until: Option<Instant>,
}

impl Nat {
    pub(super) fn new(spec: NatBox) -> Self {
        let forwards = spec
            .forwards
            .iter()
            .map(|(external, internal)| Forward {
                lease: None,
                external: *external,
                internal: canon(*internal),
                until: None,
            })
            .collect();
        Self {
            spec,
            flows: Vec::new(),
            forwards,
            next_port: FIRST_NAT_PORT,
            next_lease: 0,
            log: Vec::new(),
        }
    }

    /// Whether `ip` is this box's public address (a translating box).
    pub(super) fn public_is(&self, ip: IpAddr) -> bool {
        self.spec.translate && ip == IpAddr::V4(self.spec.public)
    }

    /// Whether a datagram to `ip` from behind leaves through this box.
    pub(super) fn carries(&self, ip: IpAddr) -> bool {
        if self.spec.translate {
            ip.is_ipv4()
        } else {
            ip.is_ipv6()
        }
    }

    /// Forgets the mappings and forwards whose time is over.
    fn expire(&mut self, now: Instant) {
        let timeout = self.spec.timeout;
        self.flows
            .retain(|f| now.saturating_duration_since(f.last) <= timeout);
        self.forwards.retain(|f| f.until.is_none_or(|t| now < t));
    }

    /// Whether `port` is taken: by a forward, or by a mapping (for a
    /// router lease, one of another inside address: a lease may share the
    /// port of its own address's mapping).
    fn taken(&self, port: u16, internal: SocketAddr, lease: bool) -> bool {
        port == 0
            || self.forwards.iter().any(|f| f.external == port)
            || self
                .flows
                .iter()
                .any(|f| f.external == port && !(lease && f.internal == internal))
    }

    /// An external port for `internal`: `preferred` when `keep` and it is
    /// not taken, else the next free one.
    fn alloc(&mut self, internal: SocketAddr, preferred: u16, keep: bool, lease: bool) -> u16 {
        if keep && !self.taken(preferred, internal, lease) {
            return preferred;
        }
        loop {
            let port = self.next_port;
            self.next_port = if port == u16::MAX {
                FIRST_NAT_PORT
            } else {
                port + 1
            };
            if !self.taken(port, internal, false) {
                return port;
            }
        }
    }

    /// A datagram from `from` (inside) to `to` leaves: its source outside.
    pub(super) fn outbound(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> SocketAddr {
        self.expire(now);
        if self.spec.translate
            && let Some(forward) = self.forwards.iter().find(|f| f.internal == from)
        {
            return SocketAddr::new(IpAddr::V4(self.spec.public), forward.external);
        }
        let key = match (self.spec.translate, self.spec.mapping) {
            (false, _) | (true, NatMapping::Eim) => None,
            (true, NatMapping::Adm) => Some(SocketAddr::new(to.ip(), 0)),
            (true, NatMapping::Apdm) => Some(to),
        };
        let at = match self
            .flows
            .iter()
            .position(|f| f.internal == from && f.key == key)
        {
            Some(at) => at,
            None => {
                let external = if self.spec.translate {
                    let keep = self.spec.port_preservation;
                    self.alloc(from, from.port(), keep, false)
                } else {
                    from.port()
                };
                self.flows.push(Flow {
                    internal: from,
                    key,
                    external,
                    last: now,
                    sent_to: HashMap::new(),
                });
                self.flows.len() - 1
            }
        };
        let flow = &mut self.flows[at];
        flow.last = now;
        flow.sent_to.insert(to, now);
        if self.spec.translate {
            SocketAddr::new(IpAddr::V4(self.spec.public), flow.external)
        } else {
            from
        }
    }

    /// A datagram from `from` (outside) to `to` arrives at the box: its
    /// destination inside, or why it is dropped.
    pub(super) fn inbound(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<SocketAddr, Fate> {
        self.expire(now);
        if self.spec.translate
            && let Some(forward) = self.forwards.iter().find(|f| f.external == to.port())
        {
            return Ok(forward.internal);
        }
        let (filtering, timeout) = (self.spec.filtering, self.spec.timeout);
        let fresh = |t: &Instant| now.saturating_duration_since(*t) <= timeout;
        let admits = |flow: &Flow| match filtering {
            NatFiltering::Eif => true,
            NatFiltering::Adf => flow
                .sent_to
                .iter()
                .any(|(a, t)| a.ip() == from.ip() && fresh(t)),
            NatFiltering::Apdf => flow.sent_to.get(&from).is_some_and(fresh),
        };
        let translate = self.spec.translate;
        let mut matching = self.flows.iter_mut().filter(|f| {
            if translate {
                f.external == to.port()
            } else {
                f.internal == to
            }
        });
        let mut any = false;
        for flow in matching.by_ref() {
            any = true;
            if admits(flow) {
                flow.last = now;
                return Ok(flow.internal);
            }
        }
        Err(if any {
            Fate::NatFiltered
        } else {
            Fate::NoMapping
        })
    }

    /// A router lease: a forward from an external port (`internal`'s own
    /// when free) to `internal` until `until`; its id and the port.
    pub(super) fn lease(
        &mut self,
        internal: SocketAddr,
        until: Instant,
        now: Instant,
    ) -> (u64, u16) {
        self.expire(now);
        let internal = canon(internal);
        let external = self.alloc(internal, internal.port(), true, true);
        self.next_lease += 1;
        let lease = self.next_lease;
        self.forwards.push(Forward {
            lease: Some(lease),
            external,
            internal,
            until: Some(until),
        });
        (lease, external)
    }

    /// Extends lease `id` to `until`; false when it is gone (lapsed or
    /// released).
    pub(super) fn renew(&mut self, id: u64, until: Instant, now: Instant) -> bool {
        self.expire(now);
        match self.forwards.iter_mut().find(|f| f.lease == Some(id)) {
            Some(forward) => {
                forward.until = Some(until);
                true
            }
            None => false,
        }
    }

    /// Removes lease `id`.
    pub(super) fn release(&mut self, id: u64) {
        self.forwards.retain(|f| f.lease != Some(id));
    }

    fn flows(&mut self, now: Instant) -> Vec<NatFlow> {
        self.expire(now);
        self.flows
            .iter()
            .map(|f| NatFlow {
                internal: f.internal,
                external: f.external,
            })
            .collect()
    }

    fn forwards(&mut self, now: Instant) -> Vec<(u16, SocketAddr)> {
        self.expire(now);
        self.forwards
            .iter()
            .map(|f| (f.external, f.internal))
            .collect()
    }
}

/// A [`NatBox`] on a [`MemNet`]. Clones are the same box.
#[derive(Clone)]
pub struct MemNat {
    pub(super) net: Arc<Net>,
    pub(super) id: usize,
}

impl MemNat {
    /// Its public address.
    #[must_use]
    pub fn public(&self) -> Ipv4Addr {
        lock(&self.net.state).nats[self.id].spec.public
    }

    /// Its live mappings, oldest first.
    #[must_use]
    pub fn flows(&self) -> Vec<NatFlow> {
        lock(&self.net.state).nats[self.id].flows(Instant::now())
    }

    /// Its live forwards (static ones and its router's leases): external
    /// port and inside address.
    #[must_use]
    pub fn forwards(&self) -> Vec<(u16, SocketAddr)> {
        lock(&self.net.state).nats[self.id].forwards(Instant::now())
    }

    /// What its router heard, in order.
    #[must_use]
    pub fn router_log(&self) -> Vec<RouterSeen> {
        lock(&self.net.state).nats[self.id].log.clone()
    }

    /// Changes what its router answers from now on (`None`: silent).
    pub fn set_router(&self, mode: Option<MapperMode>) {
        lock(&self.net.state).nats[self.id].spec.router = mode;
    }
}

impl fmt::Debug for MemNat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemNat").field("id", &self.id).finish()
    }
}
