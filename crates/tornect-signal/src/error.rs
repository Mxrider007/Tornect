//! Error type shared by the signaling crate.
//!
//! Arti's own error types never cross this crate's boundary: they are mapped to
//! [`SignalError`] variants (via `arti_client::HasKind`) so the UI can show a
//! meaningful message — "host offline" vs "host not running" vs "timeout" — and
//! so that no Arti type appears in Tornect's public API.

/// Errors produced by `tornect-signal`.
///
/// Messages are safe to show to users and never contain key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignalError {
    /// No onion-service descriptor exists for the Tornect ID: the host is
    /// offline, or has not finished publishing its address yet.
    #[error("host is offline (no onion-service descriptor found for that Tornect ID)")]
    HostOffline,

    /// The descriptor exists but the host cannot be introduced to: it stopped
    /// after publishing, or all of its introduction points went away.
    #[error("host is not running (its address is published but it is not reachable right now)")]
    HostNotRunning,

    /// The descriptor was found but the rendezvous with the host failed.
    #[error("could not reach the host over Tor: {0}")]
    HostUnreachable(String),

    /// The Tornect ID is not an address Tor accepts.
    #[error("invalid Tornect ID: {0}")]
    InvalidAddress(String),

    /// A step exceeded its deadline; the payload says which one.
    #[error("timed out while {0}")]
    Timeout(&'static str),

    /// An unauthenticated peer used up the work the host grants one session;
    /// the payload says which budget.
    #[error("peer budget exhausted: {0}")]
    BudgetExhausted(&'static str),

    /// Tor could not bootstrap (offline, filtered network, clock skew, full disk…).
    #[error("Tor bootstrap failed: {0}")]
    Bootstrap(String),

    /// The operation needs a bootstrapped Tor client.
    #[error("Tor is not bootstrapped yet")]
    NotBootstrapped,

    /// Building the Tor or onion-service configuration failed.
    #[error("Tor configuration error: {0}")]
    Config(String),

    /// Arti's keystore could not be opened, read or written.
    #[error("Tor keystore error: {0}")]
    Keystore(String),

    /// The onion service could not be launched.
    #[error("cannot launch onion service: {0}")]
    Launch(String),

    /// The address Arti derived from the installed key is not the Tornect ID.
    /// This is a bug guard: the two derivations must always agree.
    #[error("onion address mismatch: Tor derived {tor} but Tornect expected {expected}")]
    IdentityMismatch {
        /// Address computed by Arti from the keystore.
        tor: String,
        /// Address computed by `tornect-core` from the seed.
        expected: String,
    },

    /// Any other Tor-side failure, with Arti's error kind for diagnostics.
    #[error("Tor error ({kind}): {message}")]
    Tor {
        /// Arti's `ErrorKind`, rendered.
        kind: String,
        /// Human-readable message (no secrets).
        message: String,
    },

    /// Local I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Frame-level protocol violation.
    #[error(transparent)]
    Frame(#[from] crate::framing::FrameError),

    /// The peer spoke something other than the expected protocol.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Error from `tornect-core` (keystore, paths, ids).
    #[error(transparent)]
    Core(#[from] tornect_core::CoreError),

    /// The node or listener has been shut down.
    #[error("Tor node is shut down")]
    Shutdown,
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, SignalError>;

/// Render an error together with its `source()` chain, `a: b: c`.
///
/// Arti's `Display` impls only print the outermost layer; the chain is where the
/// useful detail ("connection refused", "no consensus") lives.
pub(crate) fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut cur = err.source();
    while let Some(e) = cur {
        out.push_str(": ");
        out.push_str(&e.to_string());
        cur = e.source();
    }
    out
}
