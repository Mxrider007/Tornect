//! Tornect signaling (`docs/PLAN.md` §B.3): embedded Arti onion service, CBOR
//! envelope protocol, pairing with SAS, and unattended-access authentication (§B.8).
//!
//! Milestone 1, track 1 ships the Tor layer:
//!
//! * [`tor`] — the embedded Arti node ([`TorNode`]), the host's onion service
//!   ([`OnionListener`]) and client streams ([`OnionStream`]). This module is the
//!   **only** place in the workspace that imports Arti; its public API exposes
//!   Tornect types and tokio I/O traits only.
//! * [`framing`] — `u32`-BE length-prefixed frames shared by every protocol on an
//!   onion stream.
//! * [`ping`] — the interim liveness protocol behind `tornect ping`, replaced by
//!   the CBOR envelope `PING`/`PONG` once that lands.
//!
//! Call [`install_crypto_provider`] once at process start, before the first
//! [`TorNode`] (and before any QUIC endpoint in later milestones).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod framing;
pub mod ping;
pub mod tor;

pub use error::SignalError;
pub use tor::{
    BootstrapProgress, ForgottenIdentity, OnionListener, OnionStatus, OnionStream, SIGNALING_PORT,
    TorNode, forget_identity, install_crypto_provider, shutdown_runtime,
};
pub use tornect_core::PROTOCOL_VERSION;
