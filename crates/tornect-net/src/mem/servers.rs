//! The servers of a [`MemNet`] (design `direct` §12.4): [`MemStun`], a
//! STUN server on a segment, and [`MemMapper`], a machine's port mapper,
//! which asks the router of the [`NatBox`] that is its gateway.

use std::net::SocketAddrV4;

use tokio::runtime::Handle;

use super::*;
use crate::mapping::{MAP_LEASE, MapFail, MapRequest, MapVia, Mapping, MappingHandle};
use crate::stun::{BINDING_REQUEST, BINDING_SUCCESS, HEADER_LEN, attr};
use crate::udp::STUN_COOKIE;

/// The port a [`MemStun`] answers on.
const STUN_PORT: u16 = 3478;

/// How long a renewal waits for a silent router.
const RENEW_WAIT: Duration = Duration::from_secs(1);

/// How a [`MemStun`] answers a Binding request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunMode {
    /// With the address and port the request came from, as the boxes on
    /// its way translated it.
    Honest,
    /// With this address, whatever the request came from.
    Lying(SocketAddr),
    /// Not at all.
    Silent,
}

/// A Binding request a [`MemStun`] heard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunHeard {
    /// When it arrived.
    pub at: Instant,
    /// Its source as the server saw it.
    pub from: SocketAddr,
}

/// A STUN server on a [`MemNet`] (design §12.4 `MemStun`): a machine whose
/// port 3478 answers every Binding request as its [`StunMode`] says (a
/// success response with one XOR-MAPPED-ADDRESS) and notes it. Its task
/// runs on the runtime it was started on until it is dropped.
pub struct MemStun {
    addr: SocketAddr,
    machine: MemHost,
    heard: Arc<Mutex<Vec<StunHeard>>>,
    mode: Arc<Mutex<StunMode>>,
    task: tokio::task::JoinHandle<()>,
}

impl MemStun {
    /// A server at `cidr` on `segment` answering as `mode` says.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime, or if `cidr` is not an address with its
    /// prefix length.
    #[must_use]
    pub fn start(net: &MemNet, segment: Segment, cidr: &str, mode: StunMode) -> Self {
        let addr = MemAddr::new(segment, cidr);
        let machine = net.machine(MachineSpec {
            dual_stack: addr.ip.is_ipv6(),
            ..MachineSpec::on(segment, cidr)
        });
        let socket = machine
            .bind_udp(Some(STUN_PORT))
            .expect("a fresh machine's port 3478");
        let heard = Arc::default();
        let mode = Arc::new(Mutex::new(mode));
        let task = tokio::spawn(serve(socket, Arc::clone(&heard), Arc::clone(&mode)));
        Self {
            addr: SocketAddr::new(addr.ip, STUN_PORT),
            machine,
            heard,
            mode,
            task,
        }
    }

    /// Its address and port.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Its `host:port` entry, as `network.stun_servers` lists a server.
    #[must_use]
    pub fn entry(&self) -> String {
        self.addr.to_string()
    }

    /// Its machine.
    #[must_use]
    pub fn machine(&self) -> &MemHost {
        &self.machine
    }

    /// The requests it heard, in order.
    #[must_use]
    pub fn heard(&self) -> Vec<StunHeard> {
        lock(&self.heard).clone()
    }

    /// Answers as `mode` says from now on.
    pub fn set_mode(&self, mode: StunMode) {
        *lock(&self.mode) = mode;
    }
}

impl Drop for MemStun {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl fmt::Debug for MemStun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemStun")
            .field("mode", &*lock(&self.mode))
            .finish_non_exhaustive()
    }
}

async fn serve(socket: Arc<MemUdp>, heard: Arc<Mutex<Vec<StunHeard>>>, mode: Arc<Mutex<StunMode>>) {
    let mut buf = [0_u8; 2048];
    loop {
        let mut meta = [RecvMeta::default()];
        let got = std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut buf)];
            socket.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await;
        if got.is_err() {
            return;
        }
        let request = &buf[..meta[0].len];
        if request.len() < HEADER_LEN
            || request[..2] != BINDING_REQUEST.to_be_bytes()
            || request[4..8] != STUN_COOKIE
        {
            continue;
        }
        let from = canon(meta[0].addr);
        lock(&heard).push(StunHeard {
            at: Instant::now(),
            from,
        });
        let mapped = match *lock(&mode) {
            StunMode::Honest => from,
            StunMode::Lying(addr) => addr,
            StunMode::Silent => continue,
        };
        let reply = binding_success(&request[8..HEADER_LEN], mapped);
        let _ = socket.try_send(&Transmit {
            destination: to_socket_family(from, socket.dual_stack()),
            ecn: None,
            contents: &reply,
            segment_size: None,
            src_ip: None,
        });
    }
}

/// A Binding success response under `txid` with one XOR-MAPPED-ADDRESS of
/// `mapped` (RFC 8489 §14.2).
fn binding_success(txid: &[u8], mapped: SocketAddr) -> Vec<u8> {
    let mapped = canon(mapped);
    let (family, mut raw) = match mapped.ip() {
        IpAddr::V4(v4) => (1_u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => (2_u8, v6.octets().to_vec()),
    };
    for (b, m) in raw.iter_mut().zip(STUN_COOKIE.iter().chain(txid)) {
        *b ^= m;
    }
    let port = mapped.port() ^ 0x2112;
    let value_len = u16::try_from(4 + raw.len()).unwrap_or(u16::MAX);
    let mut out = BINDING_SUCCESS.to_be_bytes().to_vec();
    out.extend_from_slice(&(value_len + 4).to_be_bytes());
    out.extend_from_slice(&STUN_COOKIE);
    out.extend_from_slice(txid);
    out.extend_from_slice(&attr::XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&value_len.to_be_bytes());
    out.extend_from_slice(&[0, family]);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&raw);
    out
}

/// What the router of a [`NatBox`] answers ([`MemMapper`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapperMode {
    /// Grants the lease asked for at the box's public address and the
    /// internal port (when free), and installs the forward.
    Ok,
    /// Refuses ([`MapFail::Refused`]), and refuses renewals.
    Refuse,
    /// Installs the forward but reports this external address (a router
    /// behind another NAT).
    Lie(Ipv4Addr),
    /// Grants only permanent mappings ([`MapFail::PermanentOnly`]).
    PermanentOnly,
    /// Grants this lease, whatever was asked, at the request and at every
    /// renewal.
    Grant(Duration),
}

impl MapperMode {
    fn granted(self, asked: Duration) -> Duration {
        match self {
            Self::Grant(lease) => lease,
            _ => asked,
        }
    }
}

/// What the router of a [`NatBox`] heard ([`MemNat::router_log`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterSeen {
    /// A mapping request.
    Map {
        /// When it arrived.
        at: Instant,
        /// The address it asked a port for.
        client: Ipv4Addr,
        /// Its internal port.
        internal_port: u16,
        /// The lease it asked for.
        lease: Duration,
    },
    /// A renewal, which asks for [`MAP_LEASE`] again.
    Renew {
        /// When it arrived.
        at: Instant,
        /// The lease it asked for.
        lease: Duration,
    },
    /// A release.
    Release {
        /// When it arrived.
        at: Instant,
    },
}

/// The port mapper of a machine on a [`MemNet`] (design §12.4
/// `MemMapper`), as [`MemHost::mapper`](NetEnv::mapper) gives it: a request
/// goes to the [`NatBox`] behind which the request's client address is and
/// whose inside address ([`NatBox::lan`]) is the request's gateway, one
/// segment latency each way. With no such box, or no protocol allowed, it
/// is [`MapFail::NoGateway`] at once; a box whose router is off answers
/// nothing, so the request ends [`MapFail::Timeout`] at its deadline.
/// Otherwise the box's [`MapperMode`] answers; a granted mapping (always
/// [`MapVia::Pcp`]) is a forward on the box until its lease ends, renewed
/// and released through the router, and released when dropped through the
/// machine's [`ReleaseTracker`].
pub struct MemMapper {
    net: Arc<Net>,
    machine: usize,
    releases: ReleaseTracker,
}

impl MemMapper {
    pub(super) fn new(net: Arc<Net>, machine: usize, releases: ReleaseTracker) -> Self {
        Self {
            net,
            machine,
            releases,
        }
    }
}

impl fmt::Debug for MemMapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemMapper")
            .field("machine", &self.machine)
            .finish_non_exhaustive()
    }
}

/// The box a machine's request reaches, and the one-way latency to it.
fn router_of(net: &Net, machine: usize, req: &MapRequest) -> Option<(usize, Duration)> {
    let state = lock(&net.state);
    let segment = state.machines[machine]
        .spec
        .addrs
        .iter()
        .find(|a| a.ip == IpAddr::V4(req.client))?
        .segment;
    let nat = state
        .nats
        .iter()
        .position(|n| n.spec.lan == Some(req.gateway) && n.spec.inside.contains(&segment))?;
    Some((nat, state.segments[segment.0].latency))
}

impl PortMapper for MemMapper {
    fn map(&self, req: MapRequest) -> BoxFuture<'static, Result<Mapping, MapFail>> {
        let net = Arc::clone(&self.net);
        let found = router_of(&net, self.machine, &req);
        let releases = self.releases.clone();
        Box::pin(async move {
            let Some((nat, one_way)) = found.filter(|_| req.protocols.any()) else {
                return Err(MapFail::NoGateway);
            };
            let deadline = Instant::from_std(req.deadline);
            tokio::time::sleep(one_way).await;
            let internal = SocketAddr::new(IpAddr::V4(req.client), req.internal_port.get());
            let answer = {
                let mut state = lock(&net.state);
                let now = Instant::now();
                let router = &mut state.nats[nat];
                router.spec.router.map(|mode| {
                    router.log.push(RouterSeen::Map {
                        at: now,
                        client: req.client,
                        internal_port: req.internal_port.get(),
                        lease: req.lease,
                    });
                    match mode {
                        MapperMode::Refuse => Err(MapFail::Refused),
                        MapperMode::PermanentOnly => Err(MapFail::PermanentOnly),
                        MapperMode::Ok | MapperMode::Grant(_) | MapperMode::Lie(_) => {
                            let granted = mode.granted(req.lease);
                            let (id, port) = router.lease(internal, now + granted, now);
                            let ip = match mode {
                                MapperMode::Lie(ip) => ip,
                                _ => router.spec.public,
                            };
                            Ok((id, SocketAddrV4::new(ip, port), granted))
                        }
                    }
                })
            };
            let Some(answer) = answer else {
                tokio::time::sleep_until(deadline).await;
                return Err(MapFail::Timeout);
            };
            tokio::time::sleep(one_way).await;
            let (id, external, granted) = answer?;
            let lease = Lease {
                net,
                nat,
                id,
                one_way,
            };
            Ok(
                Mapping::new(external, MapVia::Pcp, granted, Box::new(lease))
                    .release_on_drop(Handle::try_current().ok(), releases),
            )
        })
    }

    fn release_tracker(&self) -> Option<ReleaseTracker> {
        Some(self.releases.clone())
    }
}

/// One lease of a box's router, renewed and released through it.
struct Lease {
    net: Arc<Net>,
    nat: usize,
    id: u64,
    one_way: Duration,
}

impl MappingHandle for Lease {
    fn renew(&mut self) -> BoxFuture<'_, Result<Duration, MapFail>> {
        Box::pin(async move {
            tokio::time::sleep(self.one_way).await;
            let answer = {
                let mut state = lock(&self.net.state);
                let now = Instant::now();
                let router = &mut state.nats[self.nat];
                router.spec.router.map(|mode| {
                    router.log.push(RouterSeen::Renew {
                        at: now,
                        lease: MAP_LEASE,
                    });
                    match mode {
                        MapperMode::Refuse | MapperMode::PermanentOnly => Err(MapFail::Refused),
                        MapperMode::Ok | MapperMode::Grant(_) | MapperMode::Lie(_) => {
                            let granted = mode.granted(MAP_LEASE);
                            if router.renew(self.id, now + granted, now) {
                                Ok(granted)
                            } else {
                                Err(MapFail::Refused)
                            }
                        }
                    }
                })
            };
            match answer {
                None => {
                    tokio::time::sleep(RENEW_WAIT).await;
                    Err(MapFail::Timeout)
                }
                Some(answer) => {
                    tokio::time::sleep(self.one_way).await;
                    answer
                }
            }
        })
    }

    fn release(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            tokio::time::sleep(self.one_way).await;
            let mut state = lock(&self.net.state);
            let now = Instant::now();
            let router = &mut state.nats[self.nat];
            if router.spec.router.is_some() {
                router.log.push(RouterSeen::Release { at: now });
                router.release(self.id);
            }
        })
    }
}
