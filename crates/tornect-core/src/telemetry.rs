//! `tracing` setup shared by the CLI, the app and the test harnesses.
//!
//! There is no telemetry in the product sense (`docs/PLAN.md` §B.6: "No
//! telemetry"); this module only configures local logging.

use std::io::IsTerminal as _;
use std::path::PathBuf;

use tracing_subscriber::{
    EnvFilter, Layer as _, layer::SubscriberExt as _, util::SubscriberInitExt as _,
};

use crate::error::Result;

/// Default filter when neither `TORNECT_LOG` nor `RUST_LOG` is set.
///
/// `zbus::proxy=error`: zbus warns five times at every Wayland portal start
/// that it could not cache the properties of the portal's request objects,
/// which is harmless and lands on the host's consent terminal.
pub const DEFAULT_FILTER: &str = "info,tornect=debug,tornect_core=debug,tornect_signal=debug,\
tornect_net=debug,tornect_proto=debug,tornect_session=debug,arti=warn,tor=warn,zbus::proxy=error";

/// The fields whose values name a person, a device or a computer: a peer's
/// fingerprint or key, a pinned label or declared name, a Tornect ID or its
/// prefix, an onion address, a keystore nickname. Under the default filter
/// the log writes `<redacted>` in their place (`docs/PLAN.md` §B.6: no
/// identifier in logs by default); a filter set on purpose (`TORNECT_LOG`,
/// `RUST_LOG`, `--log`) writes them as they are.
pub const SENSITIVE_FIELDS: [&str; 10] = [
    "peer",
    "device",
    "fingerprint",
    "label",
    "name",
    "host_name",
    "declared",
    "host",
    "address",
    "nickname",
];

/// How the log writes an event's fields under the default filter: as the
/// default formatter does, but with the value of every field of
/// [`SENSITIVE_FIELDS`] replaced by `<redacted>`.
#[must_use]
pub fn redacting_fields()
-> impl for<'w> tracing_subscriber::fmt::FormatFields<'w> + Send + Sync + 'static {
    use tracing_subscriber::field::MakeExt as _;
    tracing_subscriber::fmt::format::debug_fn(|writer, field, value| {
        let name = field.name();
        if name == "message" {
            write!(writer, "{value:?}")
        } else if SENSITIVE_FIELDS.contains(&name) {
            write!(writer, "{name}=<redacted>")
        } else {
            write!(writer, "{name}={value:?}")
        }
    })
    .delimited(" ")
}

/// Whether an event may be written in full under the default filter where
/// fields cannot be redacted (the JSON lines): not when it carries a field
/// of [`SENSITIVE_FIELDS`] below `WARN`.
fn names_nobody(meta: &tracing::Metadata<'_>) -> bool {
    *meta.level() <= tracing::Level::WARN
        || !meta
            .fields()
            .iter()
            .any(|f| SENSITIVE_FIELDS.contains(&f.name()))
}

/// Logging options.
#[derive(Debug, Clone, Default)]
pub struct LogOptions {
    /// Filter directive (same syntax as `RUST_LOG`); `None` = env or [`DEFAULT_FILTER`].
    pub filter: Option<String>,
    /// If set, also write daily-rotated `tornect.log` files into this directory.
    pub file_dir: Option<PathBuf>,
    /// Emit JSON lines on stderr instead of human-readable text.
    pub json: bool,
}

/// Keeps the background log writer alive; drop it at the very end of `main`.
#[derive(Debug, Default)]
pub struct LogGuard {
    _file: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Install the global subscriber. Calling it twice is harmless (the second call
/// is a no-op that still returns a guard).
pub fn init(opts: LogOptions) -> Result<LogGuard> {
    let chosen = std::env::var("TORNECT_LOG")
        .ok()
        .or_else(|| std::env::var("RUST_LOG").ok())
        .or(opts.filter)
        .filter(|f| EnvFilter::try_new(f).is_ok());
    // Only a filter set on purpose writes names and IDs.
    let redact = chosen.is_none();
    let filter = chosen.map_or_else(|| EnvFilter::new(DEFAULT_FILTER), EnvFilter::new);

    let ansi = std::io::stderr().is_terminal();
    let text_layer = (!opts.json && !redact).then(|| {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(ansi)
            .with_target(true)
    });
    let redacted_text_layer = (!opts.json && redact).then(|| {
        tracing_subscriber::fmt::layer()
            .fmt_fields(redacting_fields())
            .with_writer(std::io::stderr)
            .with_ansi(ansi)
            .with_target(true)
    });
    let json_layer = opts.json.then(|| {
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .with_target(true)
            .with_filter(tracing_subscriber::filter::filter_fn(move |meta| {
                !redact || names_nobody(meta)
            }))
    });

    let mut guard = LogGuard::default();
    let file_layer = match opts.file_dir {
        Some(dir) => {
            crate::keystore::create_private_dir(&dir)?;
            let appender = tracing_appender::rolling::daily(dir, "tornect.log");
            let (writer, g) = tracing_appender::non_blocking(appender);
            guard._file = Some(g);
            Some(
                tracing_subscriber::fmt::layer()
                    .fmt_fields(redacting_fields())
                    .with_writer(writer)
                    .with_ansi(false)
                    .with_target(true)
                    .with_filter(EnvFilter::new(DEFAULT_FILTER)),
            )
        }
        None => None,
    };

    // A second init (e.g. from tests) fails harmlessly.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(text_layer)
        .with(redacted_text_layer)
        .with(json_layer)
        .with(file_layer)
        .try_init();
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_twice_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let _g1 = init(LogOptions {
            filter: Some("debug".to_owned()),
            file_dir: Some(dir.path().join("logs")),
            json: false,
        })
        .unwrap();
        let _g2 = init(LogOptions::default()).unwrap();
        tracing::info!("hello from the telemetry test");
        assert!(dir.path().join("logs").is_dir());
    }

    /// The Wayland portal's zbus proxies print "Failed to populate properties
    /// cache via GetAll" (zbus 5.19, `src/proxy/mod.rs`, the only `warn!` of
    /// target `zbus::proxy`) five times at every portal start, onto the host's
    /// consent terminal. The default filter drops that target's warnings and
    /// keeps every other zbus warning, and our own debug lines.
    #[test]
    fn the_default_filter_drops_only_the_zbus_proxy_cache_warning() {
        use std::sync::{Arc, Mutex};

        struct Seen(Arc<Mutex<Vec<String>>>);

        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Seen {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                let target = event.metadata().target().to_owned();
                self.0.lock().unwrap().push(target);
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new(DEFAULT_FILTER))
            .with(Seen(Arc::clone(&seen)));
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: "zbus::proxy", "Failed to populate properties cache via GetAll");
            tracing::warn!(target: "zbus::connection", "a connection warning");
            tracing::debug!(target: "tornect_session::host", "ours");
        });
        assert_eq!(
            *seen.lock().unwrap(),
            ["zbus::connection", "tornect_session::host"]
        );
    }

    /// Under the default filter the log names nobody: the lines that carry a
    /// peer's fingerprint, a pinned label, a declared name, a Tornect ID's
    /// prefix, an onion address or a keystore nickname (the host's accepted
    /// session and pairing, the client's pairing and session, the Tor
    /// stream, the onion service's stop) are written with those values
    /// redacted, and still say what happened.
    #[test]
    fn the_default_log_names_nobody() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer(Arc::new(Mutex::new(Vec::new())));
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new(DEFAULT_FILTER))
            .with(
                tracing_subscriber::fmt::layer()
                    .fmt_fields(redacting_fields())
                    .with_writer(move || writer.clone())
                    .with_ansi(false),
            );
        tracing::subscriber::with_default(subscriber, || {
            let device = "DeviceId(3f2a91c077de0b14)";
            tracing::info!(target: "tornect_signal::fsm::host", peer = ?device, label = %"Laptop", session = %"5e55", "session accepted");
            tracing::info!(target: "tornect_signal::fsm::host", peer = ?device, label = %"Laptop", "device paired");
            tracing::debug!(target: "tornect_signal::fsm::host", peer = ?device, paired = true, "HELLO verified");
            tracing::info!(target: "tornect_signal::fsm::client", host = %"abcdefgh", host_name = %"Office PC", "host paired");
            tracing::info!(target: "tornect_signal::fsm::client", host = %"abcdefgh", session = %"5e55", "session accepted");
            tracing::info!(target: "tornect_signal::tor::node", host = %"abcdefgh", port = 1, "connecting to host over Tor");
            tracing::info!(target: "tornect_signal::tor::listener", address = %"abcdefghijklmnop.onion", "onion service stopped");
            tracing::info!(target: "tornect_signal::tor::identity", nickname = %"tornect-host-abcdefgh", "installing host identity into Arti keystore");
        });
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        for said in [
            "session accepted",
            "device paired",
            "HELLO verified",
            "host paired",
            "connecting to host over Tor",
            "label=<redacted>",
            "peer=<redacted>",
            "session=5e55",
            "port=1",
        ] {
            assert!(text.contains(said), "\"{said}\" missing:\n{text}");
        }
        for secret in ["3f2a91c0", "Laptop", "abcdefgh", "Office PC", ".onion"] {
            assert!(!text.contains(secret), "\"{secret}\" in the log:\n{text}");
        }
    }
}
