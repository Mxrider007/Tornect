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

mod config;
mod crypto_provider;
mod identity;
mod listener;
mod node;

use arti_client::{ErrorKind, HasKind as _};

pub use config::{
    CONNECT_TIMEOUT, INTRO_RATE_LIMIT, MAX_STREAMS_PER_CIRCUIT, NUM_INTRO_POINTS,
    POW_REND_QUEUE_DEPTH, pow_supported,
};
pub use crypto_provider::install_crypto_provider;
pub use identity::{ForgottenIdentity, forget_identity, onion_address_for};
pub use listener::{
    ACCEPT_QUEUE_LEN, ACCEPT_TIMEOUT, Admission, CIRCUIT_IDLE_TIMEOUT, MAX_CONCURRENT_HANDSHAKES,
    MAX_LIVE_CIRCUITS, OnionListener, OnionStatus, OnionStream, RENDEZVOUS_TIMEOUT,
    RendezvousLimits, STREAM_WRITE_TIMEOUT,
};
pub use node::{BootstrapProgress, TorNode, shutdown_runtime};

use crate::error::{SignalError, error_chain};

/// Virtual port inside the onion service that carries Tornect signaling
/// (decision M1-2). Only `BEGIN` requests for this port are accepted; any other
/// request destroys its rendezvous circuit, exactly as Arti's own reverse proxy
/// does for an unmatched port, so the service is neither fingerprintable by
/// port probing nor cheaply port-scannable (docs/research/arti.md §13.13).
pub const SIGNALING_PORT: u16 = 4000;

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
