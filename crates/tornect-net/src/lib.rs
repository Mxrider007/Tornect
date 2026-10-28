//! Tornect connectivity for direct connections (`docs/PLAN.md` §A.3 D5–D7,
//! §B.2; design `direct` revision 4, decisions M1-78 to M1-86): this
//! computer's addresses and the filters every remote address passes, the
//! session's one UDP socket with its source gates, quinn QUIC with both
//! device keys pinned, the authenticated punch probes and the checklist
//! that validates paths with them, and the direct link that wires them
//! together; the STUN codec and client with the cache of the servers'
//! names, router port mapping with its ledger, and the plan and task of a
//! session's internet gathering (Phase B).
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
pub mod checklist;
pub mod env;
pub mod gather;
pub mod link;
pub mod local;
pub mod mapping;
#[cfg(any(test, feature = "test-support"))]
pub mod mem;
pub mod probe;
pub mod quic;
pub mod socket;
pub mod stun;
pub mod udp;

pub use addr::{
    AddrClass, Candidate, CandidateKind, Redacted, RedactedIp, Refusal, RemoteFilter, RouteLookup,
    Scope, StunFilter, TunnelRoute, canon, canon_ip, class, to_socket_family,
};
pub use checklist::{Action, Checklist, PunchRole, PunchStats, Rank};
pub use env::{NetEnv, RealNet};
pub use gather::{
    GATHER_BUDGET, GatherConfig, GatherPlan, GatherStats, MAPPING_HEAD_START, MapTarget, StunAsk,
    StunDns, StunOutcome, StunPlan, StunReport, StunStats, ask_stun, plan, stun_base,
};
pub use link::{
    DialFailure, DirectFail, DirectLink, DirectParams, Established, LinkNews, LinkStats,
    LocalBatch, QuicStream, Route,
};
pub use local::{IfaceAddr, IfaceKind, RouteSources};
pub use mapping::{
    LedgerEntry, MAP_LEASE, MAP_RELEASE_CAP, MapEvent, MapEvents, MapFail, MapProtocols,
    MapRequest, MapVia, Mapping, MappingHandle, MappingLedger, NoMapper, PortMapper, RealMapper,
    ReleaseTracker, Router, SHUTDOWN_RELEASE_WAIT, SWEEP_CAP, SweepReport, renewal_delay,
};
pub use probe::{Probe, ProbeDrop, ProbeKey, Txid};
pub use quic::{
    DeviceKeySigner, PeerRefusal, PinnedVerifier, QuicError, QuicIdentity, check_peer,
    endpoint_config, exporter, is_crypto_close, transport,
};
pub use socket::{BoundSocket, QuietUdp, SendErrors, bind_media_socket};
pub use stun::{StunReply, StunTxid, binding_request, parse_response, partition};
pub use udp::{
    BoundUdp, ProbeGate, PunchCounters, PunchSocket, RawSend, TeedProbe, TeedStun, Tees, V6Sources,
};

/// Which end of a session this side is: the viewer asked for the session
/// and opens its streams, the host shares its screen. Either may be the
/// side that dials the direct connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TornectRole {
    /// The side that asked for the session and shows the picture.
    Viewer,
    /// The side that accepted the session and shares its screen.
    Host,
}

/// A boxed, sendable future: the return type of the [`NetEnv`] calls that
/// wait and of the [`PortMapper`] and [`MappingHandle`] calls.
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
