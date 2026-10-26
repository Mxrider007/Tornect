//! Tornect connectivity for direct connections (`docs/PLAN.md` §A.3 D5–D7,
//! §B.2; design `direct` revision 4, decisions M1-78 to M1-86): this
//! computer's addresses and the filters every remote address passes, the
//! session's one UDP socket with its source gates, then (in the following
//! steps) hole punching, STUN, router port mapping and quinn QUIC with both
//! device keys pinned.
//!
//! Nothing outside this crate may touch sockets or quinn. It never names
//! `tornect-signal`: the wire forms of candidates are converted in
//! `tornect-session`. No address is ever logged (decision M1-83): every type
//! that carries one prints [`addr::Redacted`] classes and counts.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::future::Future;
use std::pin::Pin;

pub mod addr;
pub mod env;
pub mod local;
pub mod socket;
pub mod udp;

pub use addr::{
    AddrClass, Candidate, CandidateKind, Redacted, RedactedIp, Refusal, RemoteFilter, Scope,
    StunFilter, canon, canon_ip, class, to_socket_family,
};
pub use env::{NetEnv, RealNet};
pub use local::{IfaceAddr, IfaceKind, RouteSources};
pub use socket::{BoundSocket, QuietUdp, SendErrors, bind_media_socket};
pub use udp::{
    BoundUdp, ProbeGate, PunchCounters, PunchSocket, RawSend, TeedProbe, TeedStun, Tees, V6Sources,
};

/// A boxed, sendable future: the return type of the [`NetEnv`] calls that
/// wait.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What can go wrong in this crate. No message names an address, a port or
/// a key (decision M1-83); third-party error values are never carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// The OS did not return the interface list within
    /// [`local::IFACE_READ_TIMEOUT`].
    #[error("reading the network interfaces took longer than one second")]
    InterfacesTimedOut,
    /// The interface read stopped before it finished (it panicked, or the
    /// runtime is shutting down).
    #[error("the network interface read stopped before it finished")]
    InterfacesLost,
}
