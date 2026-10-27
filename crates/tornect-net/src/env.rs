//! The seam between a direct link and the machine it runs on (design
//! `direct` §8.3): every call a link makes to the OS goes through
//! [`NetEnv`], so the privacy rules ("a `tor_only` side reads no interface
//! and binds nothing", design §5.2) are counted in tests, and the in-memory
//! network of the later steps replaces the machine.
//!
//! The calls that read this computer's addresses (step A7) and bind the
//! session socket (step A8) are here, and since step B1 the two that STUN
//! and router mapping need: [`NetEnv::resolve`] (the STUN servers' names;
//! the cache in front of it is step B3's) and [`NetEnv::mapper`] (the real
//! router protocols are steps B4 and B5).

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::local::{self, IfaceAddr, RouteSources};
use crate::mapping::{NoMapper, PortMapper};
use crate::socket::bind_media_socket;
use crate::udp::BoundUdp;
use crate::{BoxFuture, NetError};

/// What a direct link asks of the machine.
pub trait NetEnv: Send + Sync {
    /// This computer's addresses (design §7.1), read on the blocking pool
    /// under [`local::IFACE_READ_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// [`NetError::InterfacesTimedOut`] or [`NetError::InterfacesLost`];
    /// the link reads either as "no addresses".
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>>;

    /// The source address of each family's default route; no packet.
    fn route_sources(&self) -> RouteSources;

    /// Binds the session's one UDP socket (design §6.3): `port` when it is
    /// free (`network.direct_port`), any port otherwise. Called on the
    /// tokio runtime the link runs on.
    ///
    /// # Errors
    ///
    /// The OS refused every bind; the link reads it as "could not open a
    /// network port".
    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp>;

    /// The addresses of `host` (a STUN server's name from the user's list)
    /// with `port` (design §7.3 `StunDns`). Called at start and on the
    /// jittered refresh, never per session; the caller bounds the wait.
    ///
    /// # Errors
    ///
    /// The name does not resolve, or the environment resolves no names. The
    /// error's text is the resolver's and is never shown or logged.
    fn resolve(&self, host: &str, port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>>;

    /// The router mapper of this machine (design §7.4).
    fn mapper(&self) -> Arc<dyn PortMapper>;

    /// Whether loopback remotes pass the filters: test environments only.
    fn admit_loopback(&self) -> bool {
        false
    }
}

/// The IPv4 default gateway of the interface with an OS index: the
/// lookup [`RealNet::with_gateway_lookup`] takes.
pub type GatewayLookup = Arc<dyn Fn(u32) -> Option<Ipv4Addr> + Send + Sync>;

/// The real machine.
pub struct RealNet {
    gateway: Option<GatewayLookup>,
    mapper: Arc<dyn PortMapper>,
}

impl Default for RealNet {
    fn default() -> Self {
        Self {
            gateway: None,
            mapper: Arc::new(NoMapper),
        }
    }
}

impl RealNet {
    /// The machine this process runs on. Every value shares one interface
    /// read in flight ([`local::read_interfaces`]). Its mapper is
    /// [`NoMapper`] until the router protocols land (steps B4 and B5).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The machine, with `lookup` filling the IPv4 gateway of every
    /// interface netdev reported none for ([`local::fill_gateways`]).
    /// Windows passes `tornect_platform::route::default_gateway_v4`
    /// (`GetBestRoute2`, a route lookup that sends nothing), since netdev's
    /// own Windows gateway read may send ARP and is never compiled (design
    /// §7.1). Linux and macOS need none: netdev reads the gateway from the
    /// kernel's tables there.
    #[must_use]
    pub fn with_gateway_lookup(
        mut self,
        lookup: impl Fn(u32) -> Option<Ipv4Addr> + Send + Sync + 'static,
    ) -> Self {
        self.gateway = Some(Arc::new(lookup));
        self
    }
}

impl fmt::Debug for RealNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealNet")
            .field("gateway_lookup", &self.gateway.is_some())
            .finish_non_exhaustive()
    }
}

impl NetEnv for RealNet {
    /// [`local::read_interfaces`], then the gateway lookup, if any: one
    /// route-table query per interface, as quick as the route sources'
    /// UDP `connect()`.
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        let lookup = self.gateway.clone();
        Box::pin(async move {
            let mut addrs = local::read_interfaces().await?;
            if let Some(lookup) = lookup {
                local::fill_gateways(&mut addrs, &*lookup);
            }
            Ok(addrs)
        })
    }

    fn route_sources(&self) -> RouteSources {
        local::route_sources()
    }

    /// [`bind_media_socket`] (dual-stack where the OS has IPv6) under
    /// [`QuietUdp`](crate::QuietUdp).
    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp> {
        BoundUdp::quiet(bind_media_socket(port)?)
    }

    /// The OS resolver (`getaddrinfo` on tokio's blocking pool); a literal
    /// address is returned without a query.
    fn resolve(&self, host: &str, port: u16) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        let host = host.to_owned();
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host.as_str(), port))
                .await?
                .collect())
        })
    }

    fn mapper(&self) -> Arc<dyn PortMapper> {
        Arc::clone(&self.mapper)
    }

    /// Never, whatever the build: loopback is admitted only by test
    /// environments.
    fn admit_loopback(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// The real machine through the seam, as a link holds it: never
    /// loopback, and the same reads as the functions it wraps.
    #[tokio::test]
    async fn the_real_machine_admits_no_loopback_and_reads_through_the_seam() {
        let env: Arc<dyn NetEnv> = Arc::new(RealNet::new());
        assert!(!env.admit_loopback());
        let through = env.interfaces().await.expect("the interface list");
        let direct = local::read_interfaces().await.expect("the interface list");
        assert_eq!(
            through
                .iter()
                .map(|a| (a.iface_index, a.iface_kind))
                .collect::<Vec<_>>(),
            direct
                .iter()
                .map(|a| (a.iface_index, a.iface_kind))
                .collect::<Vec<_>>()
        );
        assert_eq!(env.route_sources(), local::route_sources());
    }

    /// The seam binds the session socket as `bind_media_socket` does, behind
    /// the quiet wrapper, and each call gets its own socket.
    #[tokio::test]
    async fn the_real_machine_binds_one_quiet_socket_per_call() {
        let env: Arc<dyn NetEnv> = Arc::new(RealNet::new());
        let first = env.bind(None).expect("a session socket");
        let second = env.bind(None).expect("a second session socket");
        let a = first.inner.local_addr().expect("its address");
        let b = second.inner.local_addr().expect("its address");
        assert_ne!(a.port(), 0);
        assert_ne!(a.port(), b.port());
        assert!(a.ip().is_unspecified());
        assert_eq!(a.is_ipv6(), first.dual_stack);
        assert_eq!((first.errors.other(), first.errors.too_large()), (0, 0));
        let held = a.port();
        let third = env.bind(Some(held)).expect("a busy port is retried");
        assert_ne!(third.inner.local_addr().expect("its address").port(), held);
    }

    /// A literal resolves without a query; the real machine's mapper asks
    /// no router before step B4.
    #[tokio::test]
    async fn the_real_machine_resolves_literals_and_maps_nothing_yet() {
        let env: Arc<dyn NetEnv> = Arc::new(RealNet::new());
        assert_eq!(
            env.resolve("192.0.2.7", 3478).await.expect("a literal"),
            vec!["192.0.2.7:3478".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            env.resolve("2001:db8::7", 19302).await.expect("a literal"),
            vec!["[2001:db8::7]:19302".parse::<SocketAddr>().unwrap()]
        );
        let request = crate::MapRequest {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            client: Ipv4Addr::new(192, 168, 1, 20),
            internal_port: std::num::NonZeroU16::new(50_000).unwrap(),
            lease: crate::MAP_LEASE,
            protocols: crate::MapProtocols::ALL,
            deadline: std::time::Instant::now(),
        };
        assert_eq!(
            env.mapper()
                .map(request)
                .await
                .expect_err("no router protocol yet"),
            crate::MapFail::NoGateway
        );
    }

    /// The gateway lookup fills what netdev left empty, once per
    /// interface, and never a loopback interface's; netdev's own reading
    /// stays.
    #[tokio::test]
    async fn the_gateway_lookup_fills_the_reading() {
        use std::sync::Mutex;
        let asked = Arc::new(Mutex::new(Vec::new()));
        let noted = Arc::clone(&asked);
        let env = RealNet::new().with_gateway_lookup(move |index| {
            noted.lock().unwrap().push(index);
            Some(Ipv4Addr::new(10, 9, 8, 7))
        });
        assert!(format!("{env:?}").contains("gateway_lookup: true"));
        let plain = local::read_interfaces().await.expect("the interface list");
        let filled = env.interfaces().await.expect("the interface list");
        assert_eq!(plain.len(), filled.len());
        let asked = asked.lock().unwrap().clone();
        let mut once = asked.clone();
        once.sort_unstable();
        once.dedup();
        assert_eq!(
            once.len(),
            asked.len(),
            "one lookup per interface: {asked:?}"
        );
        for (p, f) in plain.iter().zip(&filled) {
            assert_eq!((p.ip, p.iface_index), (f.ip, f.iface_index));
            match (p.iface_kind, p.gateway_v4) {
                (local::IfaceKind::Loopback, None) => assert_eq!(f.gateway_v4, None),
                (_, Some(read)) => assert_eq!(f.gateway_v4, Some(read)),
                (_, None) => {
                    assert_eq!(f.gateway_v4, Some(Ipv4Addr::new(10, 9, 8, 7)));
                    assert!(asked.contains(&f.iface_index));
                }
            }
        }
    }
}
