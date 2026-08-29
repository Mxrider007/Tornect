//! rustls crypto-provider selection.
//!
//! Arti's rustls runtime installs no provider — "the application is responsible
//! for calling `CryptoProvider::install_default()`" (docs/research/arti.md §5) —
//! and rustls refuses to pick one when several are compiled in
//! (docs/research/quic.md §1.3). Tornect therefore installs `ring` exactly once,
//! process-wide; the quinn endpoint of Milestone 2 shares it (decision M1-3).

use std::sync::Once;

/// Install `rustls::crypto::ring` as the process-wide default provider.
///
/// **Required before the first [`super::TorNode`] and before any QUIC endpoint.**
/// Idempotent: repeated calls are fine. A provider installed earlier by someone
/// else stays in force — rustls allows exactly one — and is reported at `warn`
/// with its name, because in this binary that must not happen: `ring` is the
/// only provider compiled in (every `rustls`-naming dependency uses
/// `default-features = false`, and `cargo xtask verify` fails if `aws-lc-rs`
/// enters the graph), so anything else means a dependency installed its own.
/// Forgetting the call does not fail at startup but at Arti's first TLS
/// handshake (docs/research/arti.md §13.1), which is why `TorNode::start`
/// calls it too.
pub fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            tracing::warn!(
                active = active_provider_name().as_deref().unwrap_or("unknown"),
                "a rustls crypto provider was already installed by another component; \
                 keeping it (expected `Ring`)"
            );
        } else {
            tracing::debug!("installed rustls `ring` crypto provider");
        }
    });
}

/// Name of the installed provider's key provider (`Ring`, `AwsLcRs`, …):
/// rustls providers carry no name, but their key-loading backend's `Debug`
/// output identifies them.
fn active_provider_name() -> Option<String> {
    rustls::crypto::CryptoProvider::get_default().map(|p| format!("{:?}", p.key_provider))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_is_idempotent_and_ring_is_the_provider_in_force() {
        install_crypto_provider();
        install_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
        // Not just "a" provider: the one this build is verified with.
        assert_eq!(active_provider_name().as_deref(), Some("Ring"));
    }
}
