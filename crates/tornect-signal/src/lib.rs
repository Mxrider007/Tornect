//! Tornect signaling (`docs/PLAN.md` §B.3): embedded Arti onion service, CBOR
//! envelope protocol, pairing with SAS, and unattended-access authentication (§B.8).
//!
//! Layers, bottom up:
//!
//! * [`tor`] — the embedded Arti node ([`TorNode`]), the host's onion service
//!   ([`OnionListener`]) and client streams ([`OnionStream`]). This module is the
//!   **only** place in the workspace that imports Arti; its public API exposes
//!   Tornect types and tokio I/O traits only.
//! * [`framing`] — `u32`-BE length-prefixed frames shared by every protocol on an
//!   onion stream.
//! * [`envelope`] — the positional CBOR envelope `[v, msg_id, kind, body, sig]`
//!   and the `ERROR` codes; [`messages`] — every body with its bounds and the
//!   reject / `BYE` code tables; [`transcript`] — the `th` chain, digests and
//!   envelope signatures (§B.8.4.3).
//! * [`pairing`] — the SAS, the [`pairing::Consent`] seam, the host pairing
//!   policy and the trusted-device / known-host stores; [`consent`] — the
//!   consent evidence behind the only `SESSION_ACCEPT` constructor and the
//!   `BlockWindow` / `LocalAllow` seams.
//! * [`fsm`] — the host and client handshake state machines over any tokio
//!   stream ([`fsm::host::serve_host`], [`fsm::client::connect`]).
//! * [`ping`] — the interim liveness protocol behind `tornect ping`; the CLI
//!   track replaces it with the envelope `PING` / `PONG`.
//!
//! Call [`install_crypto_provider`] once at process start, before the first
//! [`TorNode`] (and before any QUIC endpoint in later milestones).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod consent;
pub mod envelope;
pub mod error;
pub mod framing;
pub mod fsm;
pub mod messages;
pub mod pairing;
pub mod ping;
pub mod tor;
pub mod transcript;
pub mod unattended;

pub use envelope::{Envelope, Kind};
pub use error::SignalError;
pub use fsm::HandshakeError;
pub use pairing::{Consent, Sas};
pub use tor::{
    BootstrapProgress, ForgottenIdentity, Isolation, Ladder, LadderEvent, MEDIA_PORT,
    OnionListener, OnionStatus, OnionStream, Rung, SIGNALING_PORT, TorNode, forget_identity,
    install_crypto_provider, shutdown_runtime,
};
pub use tornect_core::PROTOCOL_VERSION;
pub use transcript::{HostSigner, Transcript};
