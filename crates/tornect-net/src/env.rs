//! The seam between a direct link and the machine it runs on (design
//! `direct` §8.3): every call a link makes to the OS goes through
//! [`NetEnv`], so the privacy rules ("a `tor_only` side reads no interface
//! and binds nothing", design §5.2) are counted in tests, and the in-memory
//! network of the later steps replaces the machine.
//!
//! This step defines the calls that read this computer's addresses. The
//! session socket's `bind` joins with the UDP wrapper (step A8); `resolve`
//! and `mapper` join with STUN and router mapping (Phase B, step B1).

use crate::local::{self, IfaceAddr, RouteSources};
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

    /// Whether loopback remotes pass the filters: test environments only.
    fn admit_loopback(&self) -> bool {
        false
    }
}

/// The real machine.
#[derive(Debug, Default)]
pub struct RealNet {
    _private: (),
}

impl RealNet {
    /// The machine this process runs on. Every value shares one interface
    /// read in flight ([`local::read_interfaces`]).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl NetEnv for RealNet {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        Box::pin(local::read_interfaces())
    }

    fn route_sources(&self) -> RouteSources {
        local::route_sources()
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
}
