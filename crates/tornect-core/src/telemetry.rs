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
pub const DEFAULT_FILTER: &str = "info,tornect=debug,tornect_core=debug,tornect_signal=debug,\
tornect_net=debug,tornect_proto=debug,tornect_session=debug,arti=warn,tor=warn";

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
    let filter = std::env::var("TORNECT_LOG")
        .ok()
        .or_else(|| std::env::var("RUST_LOG").ok())
        .or(opts.filter)
        .map_or_else(
            || EnvFilter::new(DEFAULT_FILTER),
            |f| EnvFilter::try_new(f).unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER)),
        );

    let ansi = std::io::stderr().is_terminal();
    let text_layer = (!opts.json).then(|| {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(ansi)
            .with_target(true)
    });
    let json_layer = opts.json.then(|| {
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .with_target(true)
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
}
