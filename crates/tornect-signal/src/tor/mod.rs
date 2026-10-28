//! Embedded Tor via Arti (`docs/research/arti.md` is the verified API note this
//! module is coded from).
//!
//! * [`TorNode`] — one Arti client per role, bootstrapped in the background.
//! * [`OnionListener`] — the host's onion service; yields [`OnionStream`]s.
//! * [`OnionStream`] — a stream to/from a peer; tokio `AsyncRead` + `AsyncWrite`.
//! * [`install_crypto_provider`] — must run once before any Tor or QUIC use.
//!
//! Nothing here leaks Arti types: the public surface is `tornect-core` types,
//! `std`/`tokio` types and this crate's own structs. Arti's errors are mapped to
//! [`SignalError`] by the crate-private `map_arti_error` using their `ErrorKind`.

mod bridges;
mod config;
mod crypto_provider;
mod identity;
mod listener;
mod node;

use arti_client::{ErrorKind, HasKind as _};

pub use bridges::{
    BUILTIN_OBFS4, BUILTIN_SNOWFLAKE, LYREBIRD, LYREBIRD_SHA256, Ladder, PT_DIR_ENV, PtSource,
    Rung, RungPolicy, Transport, bundled_lyrebird, bundled_lyrebird_in, find_lyrebird, last_good,
};
pub use config::{
    CONNECT_TIMEOUT, INTRO_RATE_LIMIT, MAX_STREAMS_PER_CIRCUIT, NUM_INTRO_POINTS,
    POW_REND_QUEUE_DEPTH, pow_supported,
};
pub use crypto_provider::install_crypto_provider;
/// RFC 8032 seed expansion, shared with the envelope signature test that proves
/// Arti's expanded key signs exactly like ed25519-dalek from the seed (M1-11).
#[cfg(test)]
pub(crate) use identity::expand_seed as identity_expand_seed;
pub use identity::{ForgottenIdentity, forget_identity, onion_address_for};
pub use listener::{
    ACCEPT_QUEUE_LEN, ACCEPT_TIMEOUT, Admission, CIRCUIT_IDLE_TIMEOUT, MAX_CONCURRENT_HANDSHAKES,
    MAX_LIVE_CIRCUITS, OnionListener, OnionPhase, OnionStatus, OnionStream, RENDEZVOUS_TIMEOUT,
    RendezvousLimits, STREAM_WRITE_TIMEOUT,
};
pub use node::{BootstrapProgress, Isolation, LadderEvent, TorNode, shutdown_runtime};

use crate::error::{SignalError, error_chain};

/// Virtual port inside the onion service that carries Tornect signaling
/// (decision M1-2). Only `BEGIN` requests for this port, [`MEDIA_PORT`] and
/// [`SERVICES_PORT`] are accepted; any other request destroys its rendezvous
/// circuit, exactly as Arti's own reverse proxy does for an unmatched port, so
/// the service is neither fingerprintable by port probing nor cheaply
/// port-scannable (docs/research/arti.md §13.13).
pub const SIGNALING_PORT: u16 = 4000;

/// Virtual port of a session's Tor media stream (decision M1-39): the second
/// stream on the signaling stream's rendezvous circuit, opened after
/// `SESSION_ACCEPT` + `TOR_FALLBACK`. Nothing is served on it until the peer
/// proves the session token (`tornect-proto` `Bind`); the envelope protocol
/// stays on [`SIGNALING_PORT`], where the kill switch and `BYE` still apply.
pub const MEDIA_PORT: u16 = 4001;

/// Virtual port of a session's services stream (chat, clipboard text and files;
/// decision M1-76): the third stream on the signaling stream's rendezvous
/// circuit, opened by the viewer after the media stream's `BindOk`, and only
/// when the host's signed `HELLO_ACK.feats` holds
/// [`crate::messages::feats::SVC1`] — a host built before this port destroys
/// the whole circuit, media included, on a `BEGIN` for it. Nothing is served
/// on it until the peer proves the session token with the services `Bind`
/// (`tornect-proto` `services`), whose MAC is domain-separated from the media
/// one. Signaling, media and services make three streams per session, so
/// [`MAX_STREAMS_PER_CIRCUIT`] (4) leaves one.
pub const SERVICES_PORT: u16 = 4002;

/// Translate an Arti error into the Tornect error vocabulary using its `ErrorKind`
/// (docs/research/arti.md §9).
pub(crate) fn map_arti_error(err: &arti_client::Error) -> SignalError {
    let message = error_chain(err);
    match err.kind() {
        ErrorKind::OnionServiceNotFound => SignalError::HostOffline,
        ErrorKind::OnionServiceNotRunning => SignalError::HostNotRunning,
        ErrorKind::OnionServiceConnectionFailed | ErrorKind::OnionServiceProtocolViolation => {
            SignalError::HostUnreachable(message)
        }
        ErrorKind::OnionServiceAddressInvalid | ErrorKind::InvalidStreamTarget => {
            SignalError::InvalidAddress(message)
        }
        ErrorKind::TorNetworkTimeout | ErrorKind::RemoteNetworkTimeout | ErrorKind::ExitTimeout => {
            SignalError::Timeout("waiting for the Tor network")
        }
        ErrorKind::BootstrapRequired => SignalError::NotBootstrapped,
        ErrorKind::TorDirectoryUnusable | ErrorKind::TorDirectoryError | ErrorKind::ClockSkew => {
            SignalError::Bootstrap(message)
        }
        ErrorKind::KeystoreAccessFailed | ErrorKind::KeystoreCorrupted => {
            SignalError::Keystore(message)
        }
        ErrorKind::InvalidConfig | ErrorKind::InvalidConfigTransition => {
            SignalError::Config(message)
        }
        ErrorKind::ArtiShuttingDown | ErrorKind::ReactorShuttingDown => SignalError::Shutdown,
        kind => SignalError::Tor {
            kind: kind.to_string(),
            message,
        },
    }
}
