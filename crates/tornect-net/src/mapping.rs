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
//! [`RealMapper`] speaks PCP and NAT-PMP through crab_nat and UPnP-IGD
//! through igd-next (docs/research/nat-traversal.md §3 and §4). It records
//! every request in the [`MappingLedger`] before sending it, so that the
//! next start removes what a crash left ([`RealMapper::sweep`]), and a
//! mapping dropped without [`Mapping::release`] is released on the runtime
//! it was made on through the [`ReleaseTracker`]. [`NoMapper`] asks no
//! router; the in-memory network's routers answer through `mem::MemMapper`
//! (tests and the `test-support` feature only).

use std::convert::Infallible;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::time::{Duration, Instant};

use tokio::runtime::Handle;
use tornect_core::session_log::{PortChange, PortVia, RouterPort};

use crate::BoxFuture;
use crate::addr::{Redacted, RedactedIp};

#[cfg(any(test, feature = "test-support"))]
pub mod fake;
mod ledger;
mod nat;
mod real;
mod release;
mod upnp;

pub use ledger::{
    EntryId, LEDGER_MAX_AGE, LedgerEntry, Leftover, MAX_LEDGER_BYTES, MAX_LEDGER_ENTRIES,
    MAX_LEDGER_OWNERS, MappingLedger, decode_list, encode_list, unix_now,
};
pub use real::{RealMapper, Router, SWEEP_CAP, SweepReport};
pub(crate) use release::ReleaseHold;
pub use release::{MAP_RELEASE_CAP, ReleaseTracker, SHUTDOWN_RELEASE_WAIT};

/// The lease every mapping asks for (design §7.4 "Leases", decision M1-81):
/// short enough that a crashed Tornect's port closes on its own soon, long
/// enough that a session renews it rarely. Never 0, which some routers read
/// as "permanent".
pub const MAP_LEASE: Duration = Duration::from_secs(600);

/// The longest a mapping waits before its next renewal (design §7.4
/// "Renewal").
pub const RENEW_AT_MOST: Duration = Duration::from_secs(300);

/// The shortest a mapping waits before its next renewal, and the wait
/// before a renewal that failed is tried again.
pub const RENEW_AT_LEAST: Duration = Duration::from_secs(30);

/// When the next renewal of a mapping granted `granted` fires:
/// `min(300 s, granted / 2)`, never sooner than 30 s.
#[must_use]
pub fn renewal_delay(granted: Duration) -> Duration {
    (granted / 2).clamp(RENEW_AT_LEAST, RENEW_AT_MOST)
}

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
///
/// A mapping made by [`RealMapper`] releases itself when dropped without
/// [`release`](Self::release): on the runtime it was made on (or, made
/// outside one, the runtime current at the drop), through its
/// [`ReleaseTracker`], capped at [`MAP_RELEASE_CAP`] and never awaited by
/// the dropper. With no runtime at all, nothing is spawned and the router's
/// lease ends the mapping.
pub struct Mapping {
    /// The router's external address and port: the `Mapped` candidate.
    pub external: SocketAddrV4,
    /// How it was made.
    pub via: MapVia,
    /// The lease the router granted.
    pub granted: Duration,
    handle: Option<Box<dyn MappingHandle>>,
    on_drop: Option<DropRelease>,
}

/// Where a dropped mapping's release runs.
struct DropRelease {
    rt: Option<Handle>,
    releases: ReleaseTracker,
}

impl Mapping {
    /// A mapping at `external` made with `via` for `granted`, renewed and
    /// released through `handle`. Dropped without
    /// [`release`](Self::release), it releases nothing until
    /// [`release_on_drop`](Self::release_on_drop) says where.
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
            handle: Some(handle),
            on_drop: None,
        }
    }

    /// The mapping, released when dropped: on `rt` (the runtime it was made
    /// on), or without one on the runtime current at the drop, through
    /// `releases`.
    #[must_use]
    pub fn release_on_drop(mut self, rt: Option<Handle>, releases: ReleaseTracker) -> Self {
        self.on_drop = Some(DropRelease { rt, releases });
        self
    }

    /// Renews the lease; the router's new grant replaces
    /// [`granted`](Self::granted).
    ///
    /// # Errors
    ///
    /// The router's refusal or silence ([`MapFail`]); `granted` is kept.
    pub async fn renew(&mut self) -> Result<Duration, MapFail> {
        let Some(handle) = self.handle.as_mut() else {
            return Err(MapFail::Io);
        };
        let granted = handle.renew().await?;
        self.granted = granted;
        Ok(granted)
    }

    /// Renews the mapping for as long as the returned future is polled: the
    /// next renewal after [`renewal_delay`] of the last grant, each one
    /// asking for [`MAP_LEASE`] again, and after a failed one a retry
    /// after [`RENEW_AT_LEAST`]. The holder runs it beside the session and
    /// drops it with the mapping.
    pub async fn keep_renewed(&mut self) -> Infallible {
        let mut wait = renewal_delay(self.granted);
        loop {
            tokio::time::sleep(wait).await;
            wait = match self.renew().await {
                Ok(granted) => renewal_delay(granted),
                Err(_) => RENEW_AT_LEAST,
            };
        }
    }

    /// Releases the mapping. The returned future is independent of `self`;
    /// the mapping no longer releases itself on drop.
    #[must_use = "the mapping is released only when the returned future runs"]
    pub fn release(mut self) -> BoxFuture<'static, ()> {
        match self.handle.take() {
            Some(handle) => handle.release(),
            None => Box::pin(async {}),
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let (Some(handle), Some(on_drop)) = (self.handle.take(), self.on_drop.take()) else {
            return;
        };
        let rt = on_drop.rt.or_else(|| Handle::try_current().ok());
        if let Some(rt) = rt {
            on_drop.releases.spawn(&rt, handle.release());
        }
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

    /// The tracker that counts the releases of the mappings this mapper
    /// makes (they release themselves through it when dropped); `None` for
    /// a mapper whose mappings release nothing on drop. A link that shuts
    /// counts its mapping's release there from the moment it shuts
    /// (design §7.4 "Release", §8.5).
    fn release_tracker(&self) -> Option<ReleaseTracker> {
        None
    }
}

/// A mapper with no router behind it: every request is
/// [`MapFail::NoGateway`] at once, and nothing is sent. The loopback
/// machines use it, and the real machine until [`RealNet::with_router`]
/// gives it a ledger.
///
/// [`RealNet::with_router`]: crate::RealNet::with_router
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMapper;

impl PortMapper for NoMapper {
    fn map(&self, _req: MapRequest) -> BoxFuture<'static, Result<Mapping, MapFail>> {
        Box::pin(async { Err(MapFail::NoGateway) })
    }
}

#[cfg(test)]
mod tests;
