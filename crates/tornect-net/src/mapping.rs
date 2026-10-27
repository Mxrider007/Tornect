//! Router port mapping (design `direct` §7.4; decisions M1-81, M1-83): the
//! seam through which a direct link asks the default gateway for one IPv4
//! UDP port, and the values that cross it.
//!
//! A [`PortMapper`] answers a [`MapRequest`] with a [`Mapping`] or a
//! [`MapFail`]; a mapping is renewed and released through the
//! [`MappingHandle`] it carries, and every mapping that opens or closes is
//! reported as a [`MapEvent`] (protocol only) for the session log's
//! `router_port` line. No type here prints an address or a port, and no
//! failure carries a third-party error value: routers return free text.
//!
//! Step B1 holds the types and [`NoMapper`]. The router protocols
//! (`RealMapper`: PCP and NAT-PMP through crab_nat, UPnP-IGD through
//! igd-next; docs/research/nat-traversal.md §3 and §4), the ledger of
//! mappings to remove after a crash and the release tracker follow at steps
//! B4 and B5, the in-memory router at step B8.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::time::{Duration, Instant};

use tornect_core::session_log::{PortChange, PortVia, RouterPort};

use crate::BoxFuture;
use crate::addr::{Redacted, RedactedIp};

/// The lease every mapping asks for (design §7.4 "Leases", decision M1-81):
/// short enough that a crashed Tornect's port closes on its own soon, long
/// enough that a session renews it rarely. Never 0, which some routers read
/// as "permanent".
pub const MAP_LEASE: Duration = Duration::from_secs(600);

/// What a direct link asks of the router: one UDP port on `gateway` that
/// forwards to `client:internal_port`.
pub struct MapRequest {
    /// The IPv4 default gateway of the route-source interface (design
    /// §7.1, `IfaceAddr::gateway_v4`).
    pub gateway: Ipv4Addr,
    /// This computer's address toward the gateway: the IPv4 route source.
    pub client: Ipv4Addr,
    /// The session socket's port; the same external port is asked for.
    pub internal_port: NonZeroU16,
    /// The lease asked for ([`MAP_LEASE`]).
    pub lease: Duration,
    /// The protocols the user's settings allow.
    pub protocols: MapProtocols,
    /// When the whole call gives up: what remains of the gathering budget,
    /// on tokio's clock (`tokio::time::Instant::now().into_std()`), as the
    /// checklist reads it.
    pub deadline: Instant,
}

impl fmt::Debug for MapRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MapRequest")
            .field("gateway", &RedactedIp(IpAddr::V4(self.gateway)))
            .field("client", &RedactedIp(IpAddr::V4(self.client)))
            .field("lease", &self.lease)
            .field("protocols", &self.protocols)
            .finish_non_exhaustive()
    }
}

/// The router protocols a mapping may use (`network.upnp`,
/// `network.nat_pmp`, `network.pcp`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct MapProtocols {
    /// UPnP-IGD (`WANIPConnection` / `WANPPPConnection`).
    pub upnp: bool,
    /// NAT-PMP (RFC 6886), the fallback of a router that does not speak
    /// PCP.
    pub nat_pmp: bool,
    /// The Port Control Protocol (RFC 6887).
    pub pcp: bool,
}

impl MapProtocols {
    /// None: no router is asked anything.
    pub const NONE: Self = Self {
        upnp: false,
        nat_pmp: false,
        pcp: false,
    };

    /// All three.
    pub const ALL: Self = Self {
        upnp: true,
        nat_pmp: true,
        pcp: true,
    };

    /// Whether any protocol may be used.
    #[must_use]
    pub fn any(self) -> bool {
        self.upnp || self.nat_pmp || self.pcp
    }
}

/// The protocol a mapping was made with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapVia {
    /// The Port Control Protocol.
    Pcp,
    /// NAT-PMP.
    NatPmp,
    /// UPnP-IGD.
    Upnp,
}

impl From<MapVia> for PortVia {
    fn from(via: MapVia) -> Self {
        match via {
            MapVia::Pcp => Self::Pcp,
            MapVia::NatPmp => Self::NatPmp,
            MapVia::Upnp => Self::Upnp,
        }
    }
}

/// Why no mapping was made, or a renewal failed. No variant carries text
/// or an address (decision M1-83).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum MapFail {
    /// There is no gateway to ask, or no protocol may be used.
    #[error("there is no router to ask for a port")]
    NoGateway,
    /// The router did not answer before the deadline.
    #[error("the router did not answer in time")]
    Timeout,
    /// The router answered and refused (not authorized, no resources, the
    /// port taken twice, an unsupported request).
    #[error("the router refused the port mapping")]
    Refused,
    /// A UPnP router that grants only permanent mappings (error 725):
    /// Tornect never asks for one (design §16.3, E7).
    #[error("the router grants only permanent port mappings, which Tornect never asks for")]
    PermanentOnly,
    /// The router's external address is not a public one (it sits behind
    /// another NAT), so the mapping would not help and was released.
    #[error("the router's external address is not public")]
    NotGlobal,
    /// A local socket or I/O error.
    #[error("the port mapping request could not be sent or read")]
    Io,
}

/// Renews and releases one mapping; the router protocol's state (the PCP
/// nonce, the UPnP control URL) stays inside it.
pub trait MappingHandle: Send {
    /// Asks the router for the lease again ([`MAP_LEASE`], not what it
    /// granted last time) and returns the new grant.
    fn renew(&mut self) -> BoxFuture<'_, Result<Duration, MapFail>>;

    /// Removes the mapping from the router. The future owns what it needs,
    /// so it can run after the link that held the mapping is gone.
    fn release(self: Box<Self>) -> BoxFuture<'static, ()>;
}

/// A port the router opened for this session.
pub struct Mapping {
    /// The router's external address and port: the `Mapped` candidate.
    pub external: SocketAddrV4,
    /// How it was made.
    pub via: MapVia,
    /// The lease the router granted.
    pub granted: Duration,
    handle: Box<dyn MappingHandle>,
}

impl Mapping {
    /// A mapping at `external` made with `via` for `granted`, renewed and
    /// released through `handle`.
    #[must_use]
    pub fn new(
        external: SocketAddrV4,
        via: MapVia,
        granted: Duration,
        handle: Box<dyn MappingHandle>,
    ) -> Self {
        Self {
            external,
            via,
            granted,
            handle,
        }
    }

    /// Renews the lease; the router's new grant replaces
    /// [`granted`](Self::granted).
    ///
    /// # Errors
    ///
    /// The router's refusal or silence ([`MapFail`]); `granted` is kept.
    pub async fn renew(&mut self) -> Result<Duration, MapFail> {
        let granted = self.handle.renew().await?;
        self.granted = granted;
        Ok(granted)
    }

    /// Releases the mapping. The returned future is independent of `self`.
    #[must_use = "the mapping is released only when the returned future runs"]
    pub fn release(self) -> BoxFuture<'static, ()> {
        self.handle.release()
    }
}

impl fmt::Debug for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mapping")
            .field("external", &Redacted(&SocketAddr::V4(self.external)))
            .field("via", &self.via)
            .field("granted", &self.granted)
            .finish_non_exhaustive()
    }
}

/// What happened to a mapping, for the session log's `router_port` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapEvent {
    /// The router granted a mapping.
    Opened(MapVia),
    /// A mapping was released.
    Closed(MapVia),
    /// Releasing a mapping failed; it lapses with its lease.
    CloseFailed(MapVia),
    /// A mapping an earlier run left was removed at start.
    LeftoverRemoved(MapVia),
}

impl MapEvent {
    /// The session log's facts of this event.
    #[must_use]
    pub fn router_port(self) -> RouterPort {
        let (change, via) = match self {
            Self::Opened(via) => (PortChange::Opened, via),
            Self::Closed(via) => (PortChange::Closed, via),
            Self::CloseFailed(via) => (PortChange::CloseFailed, via),
            Self::LeftoverRemoved(via) => (PortChange::LeftoverRemoved, via),
        };
        RouterPort {
            change,
            via: via.into(),
        }
    }
}

/// Where a mapper reports its [`MapEvent`]s.
pub trait MapEvents: Send + Sync {
    /// One event; called from the mapper's task, so it must not block.
    fn on_event(&self, ev: MapEvent);
}

/// Asks the router for a port.
pub trait PortMapper: Send + Sync {
    /// At most one mapping for `req`, within `req.deadline`.
    fn map(&self, req: MapRequest) -> BoxFuture<'static, Result<Mapping, MapFail>>;
}

/// A mapper with no router behind it: every request is
/// [`MapFail::NoGateway`] at once, and nothing is sent. The in-memory and
/// loopback machines use it until step B8 gives the in-memory network
/// routers, and the real machine until step B4.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMapper;

impl PortMapper for NoMapper {
    fn map(&self, _req: MapRequest) -> BoxFuture<'static, Result<Mapping, MapFail>> {
        Box::pin(async { Err(MapFail::NoGateway) })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn request() -> MapRequest {
        MapRequest {
            gateway: Ipv4Addr::new(192, 168, 77, 1),
            client: Ipv4Addr::new(192, 168, 77, 203),
            internal_port: NonZeroU16::new(50_417).unwrap(),
            lease: MAP_LEASE,
            protocols: MapProtocols::ALL,
            deadline: Instant::now() + Duration::from_millis(1500),
        }
    }

    /// A handle that grants `grants` in turn and counts its releases.
    struct Scripted {
        grants: Vec<Result<Duration, MapFail>>,
        released: Arc<AtomicUsize>,
    }

    impl MappingHandle for Scripted {
        fn renew(&mut self) -> BoxFuture<'_, Result<Duration, MapFail>> {
            let next = self.grants.remove(0);
            Box::pin(async move { next })
        }

        fn release(self: Box<Self>) -> BoxFuture<'static, ()> {
            let released = Arc::clone(&self.released);
            Box::pin(async move {
                released.fetch_add(1, Ordering::SeqCst);
            })
        }
    }

    #[tokio::test]
    async fn no_mapper_answers_no_gateway() {
        let mapper: Arc<dyn PortMapper> = Arc::new(NoMapper);
        assert_eq!(
            mapper.map(request()).await.expect_err("no router"),
            MapFail::NoGateway
        );
    }

    /// A renewal's grant replaces the last one; a failed renewal keeps it;
    /// the release runs only when its future does, after the mapping is
    /// gone.
    #[tokio::test]
    async fn a_mapping_renews_through_its_handle_and_releases_once() {
        let released = Arc::new(AtomicUsize::new(0));
        let mut mapping = Mapping::new(
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 50_417),
            MapVia::Pcp,
            Duration::from_secs(120),
            Box::new(Scripted {
                grants: vec![Ok(MAP_LEASE), Err(MapFail::Timeout)],
                released: Arc::clone(&released),
            }),
        );
        assert_eq!(mapping.renew().await, Ok(MAP_LEASE));
        assert_eq!(mapping.granted, MAP_LEASE);
        assert_eq!(mapping.renew().await, Err(MapFail::Timeout));
        assert_eq!(mapping.granted, MAP_LEASE);
        let release = mapping.release();
        assert_eq!(released.load(Ordering::SeqCst), 0);
        release.await;
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn events_become_router_port_lines_with_the_protocol_only() {
        for (event, line) in [
            (MapEvent::Opened(MapVia::Pcp), "opened pcp"),
            (MapEvent::Closed(MapVia::NatPmp), "closed nat-pmp"),
            (MapEvent::CloseFailed(MapVia::Upnp), "close-failed upnp"),
            (
                MapEvent::LeftoverRemoved(MapVia::Pcp),
                "leftover-removed pcp",
            ),
        ] {
            assert_eq!(event.router_port().detail(), line);
        }
    }

    #[test]
    fn protocols_any() {
        assert!(!MapProtocols::NONE.any());
        assert!(MapProtocols::ALL.any());
        assert!(
            MapProtocols {
                nat_pmp: true,
                ..MapProtocols::NONE
            }
            .any()
        );
        assert_eq!(MapProtocols::default(), MapProtocols::NONE);
    }

    /// Decision M1-83: neither a request nor a mapping prints an address
    /// or a port, and no failure names one.
    #[test]
    fn no_debug_or_message_prints_an_address_or_a_port() {
        let mapping = Mapping::new(
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 50_417),
            MapVia::Upnp,
            MAP_LEASE,
            Box::new(Scripted {
                grants: Vec::new(),
                released: Arc::default(),
            }),
        );
        let mut text = format!("{:?} {:#?} {mapping:?} {mapping:#?}", request(), request());
        for fail in [
            MapFail::NoGateway,
            MapFail::Timeout,
            MapFail::Refused,
            MapFail::PermanentOnly,
            MapFail::NotGlobal,
            MapFail::Io,
        ] {
            text.push_str(&format!(" {fail} {fail:?}"));
        }
        for piece in ["192", "168", "77", "203", "113", "50417", "50_417"] {
            assert!(!text.contains(piece), "\"{piece}\" in {text}");
        }
        for said in ["v4 private", "v4 unusable", "Upnp", "600s"] {
            assert!(text.contains(said), "\"{said}\" missing in {text}");
        }
    }
}
