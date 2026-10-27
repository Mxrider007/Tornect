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
/// prefix, an onion address, a keystore nickname, a file or directory path
/// (under the home directory it names the account; a keystore path holds a
/// Tornect ID's prefix, FR2R-I6). The log writes `<redacted>` in their place
/// under every filter (`docs/PLAN.md` §B.6: no identifier in logs by
/// default; U3-L3: a filter set for more detail, `TORNECT_LOG`, `RUST_LOG`
/// or `--log`, keeps it); only the explicit opt-in
/// ([`LogOptions::identifiers`], [`IDENTIFIERS_ENV`]) writes them as they
/// are.
pub const SENSITIVE_FIELDS: [&str; 12] = [
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
    "path",
    "state_dir",
];

/// The environment variable that writes identifiers into the log when it is
/// `1`, as `--log-identifiers` does (U3-L3).
pub const IDENTIFIERS_ENV: &str = "TORNECT_LOG_IDENTIFIERS";

/// The log targets of the third-party network crates, whose own lines carry
/// IP addresses, ports, connection IDs or certificates (decision M1-83,
/// design `direct` §5.5): quinn-udp writes a failed send's destination
/// and source at `WARN`; quinn-proto remote addresses and connection IDs at
/// `DEBUG`/`TRACE`; rustls both certificates at `TRACE`, which with raw public
/// keys are the two device keys; the netlink crates, igd-next, crab_nat, the
/// HTTP stack and the XML parsers of the router protocols the same kind of
/// detail. Without the identifier opt-in every layer drops their events,
/// whatever the filter (`--log trace` included); fields cannot be redacted
/// inside a message text, so the events go whole.
///
/// `log`-crate events (rustls, the netlink crates, igd-next) reach tracing
/// through the `tracing-log` bridge that `init` installs, under their own
/// target, so the same rule drops them. A crate that touches the network
/// joins this list in the change that pins it (`docs/DEPENDENCIES.md`, the
/// "Logs addresses or keys?" column).
pub const QUIET_TARGETS: [&str; 13] = [
    "quinn",
    "quinn_proto",
    "quinn_udp",
    "rustls",
    "netdev",
    "netlink_",
    "igd_next",
    "crab_nat",
    "hyper",
    "hyper_util",
    "h2",
    "xmltree",
    "xml",
];

/// Whether `target` belongs to one of [`QUIET_TARGETS`]: the target itself,
/// a module below it (`rustls::client::tls13`), or, for the one entry that
/// ends in `_`, any target that starts with it (`netlink_sys`,
/// `netlink_packet_route`). `rustlsx` or `h2o` are not quiet.
#[must_use]
pub fn is_quiet_target(target: &str) -> bool {
    QUIET_TARGETS.iter().any(|quiet| {
        if quiet.ends_with('_') {
            target.starts_with(quiet)
        } else {
            target
                .strip_prefix(quiet)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
        }
    })
}

/// [`is_quiet_target`] of an event's or a span's target.
fn quiet(meta: &tracing::Metadata<'_>) -> bool {
    is_quiet_target(meta.target())
}

/// How the log writes an event's fields without the identifier opt-in: as
/// the default formatter does, but with the value of every field of
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

/// Whether an event may be written in full without the identifier opt-in
/// where fields cannot be redacted (the JSON lines): not when it carries a
/// field of [`SENSITIVE_FIELDS`] below `WARN`.
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
    /// Write the fields of [`SENSITIVE_FIELDS`] as they are
    /// (`--log-identifiers`; [`IDENTIFIERS_ENV`] = `1` does the same). Off,
    /// they are redacted whatever the filter.
    pub identifiers: bool,
}

/// Keeps the background log writer alive; drop it at the very end of `main`.
#[derive(Debug, Default)]
pub struct LogGuard {
    _file: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Install the global subscriber. Calling it twice is harmless (the second call
/// is a no-op that still returns a guard).
pub fn init(opts: LogOptions) -> Result<LogGuard> {
    let ansi = std::io::stderr().is_terminal();
    let (subscriber, guard) = subscriber(
        opts,
        &|name| std::env::var(name).ok(),
        std::io::stderr,
        ansi,
    )?;
    // A second init (e.g. from tests) fails harmlessly.
    let _ = subscriber.try_init();
    Ok(guard)
}

/// What [`init`] installs, its lines written through `stderr` and the
/// environment read through `env`: the filter (`TORNECT_LOG`, else
/// `RUST_LOG`, else [`LogOptions::filter`], else [`DEFAULT_FILTER`]; an
/// invalid one counts as unset) decides which events are written, never
/// whether they name anyone: that takes [`LogOptions::identifiers`] or
/// [`IDENTIFIERS_ENV`] = `1` (U3-L3). Without it, every stderr layer also
/// drops the events and spans of [`QUIET_TARGETS`]; the file layer, which
/// redacts its fields even with the opt-in, always drops them.
fn subscriber<W>(
    opts: LogOptions,
    env: &dyn Fn(&str) -> Option<String>,
    stderr: W,
    ansi: bool,
) -> Result<(impl tracing::Subscriber + Send + Sync + 'static, LogGuard)>
where
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Clone + Send + Sync + 'static,
{
    let chosen = env("TORNECT_LOG")
        .or_else(|| env("RUST_LOG"))
        .or(opts.filter)
        .filter(|f| EnvFilter::try_new(f).is_ok());
    let redact = !(opts.identifiers || env(IDENTIFIERS_ENV).as_deref() == Some("1"));
    let filter = chosen.map_or_else(|| EnvFilter::new(DEFAULT_FILTER), EnvFilter::new);

    let text_layer = (!opts.json && !redact).then(|| {
        tracing_subscriber::fmt::layer()
            .with_writer(stderr.clone())
            .with_ansi(ansi)
            .with_target(true)
    });
    let redacted_text_layer = (!opts.json && redact).then(|| {
        tracing_subscriber::fmt::layer()
            .fmt_fields(redacting_fields())
            .with_writer(stderr.clone())
            .with_ansi(ansi)
            .with_target(true)
            .with_filter(tracing_subscriber::filter::filter_fn(|meta| !quiet(meta)))
    });
    let json_layer = opts.json.then(|| {
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(stderr)
            .with_target(true)
            .with_filter(tracing_subscriber::filter::filter_fn(move |meta| {
                !redact || (names_nobody(meta) && !quiet(meta))
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
                    .with_filter(EnvFilter::new(DEFAULT_FILTER))
                    .with_filter(tracing_subscriber::filter::filter_fn(|meta| !quiet(meta))),
            )
        }
        None => None,
    };

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(text_layer)
        .with(redacted_text_layer)
        .with(json_layer)
        .with(file_layer);
    Ok((subscriber, guard))
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
            identifiers: false,
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

    /// U3-L3: over the layers [`init`] installs, a filter chosen for more
    /// detail (`--log`, `TORNECT_LOG`, `RUST_LOG`, even `info`) keeps the
    /// redaction; only the identifier opt-in (`--log-identifiers`, or
    /// `TORNECT_LOG_IDENTIFIERS=1`) writes names and addresses.
    #[test]
    fn a_chosen_filter_still_names_nobody() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
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

        let logged = |opts: LogOptions, env: &[(&str, &str)]| -> String {
            let buffer = Buffer::default();
            let writer = buffer.clone();
            let env: Vec<(String, String)> = env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            let lookup = |name: &str| env.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
            let (subscriber, _guard) =
                subscriber(opts, &lookup, move || writer.clone(), false).unwrap();
            tracing::subscriber::with_default(subscriber, || {
                tracing::callsite::rebuild_interest_cache();
                tracing::info!(target: "tornect_signal::fsm::host", peer = ?"DeviceId(3f2a91c077de0b14)", label = %"Laptop", "session accepted");
                tracing::info!(target: "tornect_signal::tor::listener", address = %"abcdefghijklmnop.onion", "onion service stopped");
            });
            String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
        };
        let filter = |f: &str| LogOptions {
            filter: Some(f.to_owned()),
            ..LogOptions::default()
        };
        for (opts, env) in [
            (filter("info"), vec![]),
            (filter("debug"), vec![]),
            (LogOptions::default(), vec![("TORNECT_LOG", "info")]),
            (LogOptions::default(), vec![("RUST_LOG", "trace")]),
            (filter("tornect_signal=trace"), vec![(IDENTIFIERS_ENV, "0")]),
            (LogOptions::default(), vec![]),
        ] {
            let text = logged(opts.clone(), &env);
            for said in [
                "session accepted",
                "label=<redacted>",
                "onion service stopped",
            ] {
                assert!(
                    text.contains(said),
                    "{opts:?} {env:?}: \"{said}\" missing:\n{text}"
                );
            }
            for secret in ["3f2a91c0", "Laptop", ".onion"] {
                assert!(
                    !text.contains(secret),
                    "{opts:?} {env:?}: \"{secret}\" in:\n{text}"
                );
            }
        }
        for (opts, env) in [
            (
                LogOptions {
                    identifiers: true,
                    ..filter("info")
                },
                vec![],
            ),
            (LogOptions::default(), vec![(IDENTIFIERS_ENV, "1")]),
        ] {
            let text = logged(opts.clone(), &env);
            for said in ["3f2a91c0", "Laptop", "abcdefghijklmnop.onion"] {
                assert!(
                    text.contains(said),
                    "{opts:?} {env:?}: \"{said}\" missing:\n{text}"
                );
            }
        }
    }

    /// FR2R-I6: a path in a log field (under the home directory it names the
    /// account; a keystore path holds a Tornect ID's prefix) reads
    /// `<redacted>` under the default and a chosen filter, as the other
    /// identifying fields do, and the line still says what happened; a JSON
    /// line below WARN that carries one is left out. Only the identifier
    /// opt-in writes it as it is.
    #[test]
    fn a_path_field_is_redacted_without_the_opt_in() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
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

        const HOME: &str = "/home/account";
        let logged = |opts: LogOptions, env: &[(&str, &str)]| -> String {
            let buffer = Buffer::default();
            let writer = buffer.clone();
            let lookup = |name: &str| {
                env.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_owned())
            };
            let (subscriber, _guard) =
                subscriber(opts, &lookup, move || writer.clone(), false).unwrap();
            tracing::subscriber::with_default(subscriber, || {
                tracing::callsite::rebuild_interest_cache();
                tracing::info!(target: "tornect_core::session_log", path = %"/home/account/.local/state/tornect/sessions.log", "rotated sessions.log");
                tracing::debug!(target: "tornect_signal::tor::identity", path = %"/home/account/.local/state/tornect/arti/keystore/hss/tornect-abcdefgh/ks_hs_id.ed25519_expanded_private", "removing unrecognized keystore file");
                tracing::info!(target: "tornect_signal::tor::node", state_dir = %"/home/account/.local/state/tornect/arti", "Tor client created");
            });
            String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
        };
        for (opts, env) in [
            (LogOptions::default(), vec![]),
            (
                LogOptions {
                    filter: Some("trace".to_owned()),
                    ..LogOptions::default()
                },
                vec![],
            ),
            (LogOptions::default(), vec![("TORNECT_LOG", "debug")]),
        ] {
            let text = logged(opts.clone(), &env);
            for said in [
                "rotated sessions.log",
                "removing unrecognized keystore file",
                "Tor client created",
                "path=<redacted>",
                "state_dir=<redacted>",
            ] {
                assert!(
                    text.contains(said),
                    "{opts:?} {env:?}: \"{said}\" missing:\n{text}"
                );
            }
            for secret in [HOME, "abcdefgh"] {
                assert!(
                    !text.contains(secret),
                    "{opts:?} {env:?}: \"{secret}\" in:\n{text}"
                );
            }
        }
        let json = logged(
            LogOptions {
                json: true,
                ..LogOptions::default()
            },
            &[],
        );
        assert!(!json.contains(HOME), "{json}");
        for (opts, env) in [
            (
                LogOptions {
                    identifiers: true,
                    ..LogOptions::default()
                },
                vec![],
            ),
            (LogOptions::default(), vec![(IDENTIFIERS_ENV, "1")]),
            (
                LogOptions {
                    json: true,
                    identifiers: true,
                    ..LogOptions::default()
                },
                vec![],
            ),
        ] {
            let text = logged(opts.clone(), &env);
            for said in [
                "/home/account/.local/state/tornect/sessions.log",
                "tornect-abcdefgh",
                "/home/account/.local/state/tornect/arti",
            ] {
                assert!(
                    text.contains(said),
                    "{opts:?} {env:?}: \"{said}\" missing:\n{text}"
                );
            }
        }
    }

    #[test]
    fn quiet_targets_are_the_crates_and_their_modules() {
        for target in [
            "quinn",
            "quinn::endpoint",
            "quinn_proto::connection",
            "quinn_udp",
            "rustls::client::tls13",
            "rustls::server::tls13",
            "netdev",
            "netlink_sys",
            "netlink_packet_route::link",
            "netlink_packet_core",
            "igd_next::search",
            "crab_nat",
            "hyper::proto::h1",
            "hyper_util::client::legacy",
            "h2::codec",
            "xmltree",
            "xml::reader",
        ] {
            assert!(is_quiet_target(target), "{target} must be quiet");
        }
        for target in [
            "tornect_net::link",
            "tornect_signal::tor::node",
            "rustlsx",
            "quinnx::a",
            "h2o",
            "xmlsec",
            "netlink",
            "tor_proto::channel",
            "arti_client",
            "log",
            "",
        ] {
            assert!(!is_quiet_target(target), "{target} must not be quiet");
        }
    }

    /// Decision M1-83 (design `direct` §12.1 "Telemetry"): under `--log
    /// trace` and every other filter, without the identifier opt-in, the
    /// stderr layers (text and JSON) drop every event of [`QUIET_TARGETS`],
    /// `log`-crate records of rustls and igd-next sent through the
    /// `tracing-log` bridge included; Tornect's own lines still pass. With
    /// the opt-in they are kept.
    #[test]
    fn third_party_network_lines_are_dropped_without_the_opt_in() {
        use std::sync::{Arc, Mutex};
        use tracing_log::log::{self, Log as _};

        #[derive(Clone, Default)]
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

        const PEER: &str = "203.0.113.77:50417";
        const KEY: &str = "3f2a91c077de0b14";
        let logged = |opts: LogOptions, env: &[(&str, &str)]| -> String {
            let buffer = Buffer::default();
            let writer = buffer.clone();
            let lookup = |name: &str| {
                env.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_owned())
            };
            let (subscriber, _guard) =
                subscriber(opts, &lookup, move || writer.clone(), false).unwrap();
            tracing::subscriber::with_default(subscriber, || {
                tracing::callsite::rebuild_interest_cache();
                tracing::warn!(target: "quinn_udp", "sendmsg error: Transmit: {{ destination: {PEER} }}");
                tracing::trace!(target: "quinn_proto::connection", "remote {PEER} cid {KEY}");
                tracing::debug!(target: "quinn::endpoint", "incoming from {PEER}");
                tracing::warn!(target: "netlink_packet_route::link", "unknown attribute of {PEER}");
                tracing::info!(target: "h2::codec", "frame from {PEER}");
                tracing::info!(target: "xml::reader", "element {PEER}");
                // The span's own fields never reach a line of ours either.
                let span = tracing::info_span!(target: "quinn", "connection", remote = %PEER);
                span.in_scope(|| tracing::info!(target: "tornect_net::link", "ours inside"));
                let bridge = tracing_log::LogTracer::new();
                for target in ["rustls::client::tls13", "igd_next::search"] {
                    bridge.log(
                        &log::Record::builder()
                            .target(target)
                            .level(log::Level::Trace)
                            .args(format_args!("certificate {KEY} from {PEER}"))
                            .build(),
                    );
                }
                bridge.log(
                    &log::Record::builder()
                        .target("tornect_net::bridged")
                        .level(log::Level::Info)
                        .args(format_args!("a bridged line of ours"))
                        .build(),
                );
                tracing::info!(target: "tornect_net::link", "direct path ready");
            });
            String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
        };
        let filter = |f: &str| LogOptions {
            filter: Some(f.to_owned()),
            ..LogOptions::default()
        };
        for (opts, env) in [
            (filter("trace"), vec![]),
            (LogOptions::default(), vec![("RUST_LOG", "trace")]),
            (
                LogOptions::default(),
                vec![("TORNECT_LOG", "quinn=trace,rustls=trace,trace")],
            ),
            (filter("trace"), vec![(IDENTIFIERS_ENV, "0")]),
            (LogOptions::default(), vec![]),
            (
                LogOptions {
                    json: true,
                    ..filter("trace")
                },
                vec![],
            ),
        ] {
            let text = logged(opts.clone(), &env);
            for said in ["direct path ready", "ours inside", "a bridged line of ours"] {
                assert!(
                    text.contains(said),
                    "{opts:?} {env:?}: \"{said}\" missing:\n{text}"
                );
            }
            for secret in ["203.0.113.77", "50417", KEY, "certificate", "sendmsg"] {
                assert!(
                    !text.contains(secret),
                    "{opts:?} {env:?}: \"{secret}\" in:\n{text}"
                );
            }
        }
        for (opts, env) in [
            (
                LogOptions {
                    identifiers: true,
                    ..filter("trace")
                },
                vec![],
            ),
            (filter("trace"), vec![(IDENTIFIERS_ENV, "1")]),
            (
                LogOptions {
                    identifiers: true,
                    json: true,
                    ..filter("trace")
                },
                vec![],
            ),
        ] {
            let text = logged(opts.clone(), &env);
            for said in [
                "sendmsg error",
                "cid 3f2a91c077de0b14",
                "incoming from",
                "unknown attribute",
                "frame from",
                "element",
                "direct path ready",
            ] {
                assert!(
                    text.contains(said),
                    "{opts:?} {env:?}: \"{said}\" missing:\n{text}"
                );
            }
            assert_eq!(
                text.matches("certificate 3f2a91c077de0b14 from").count(),
                2,
                "{opts:?} {env:?}: both bridged records kept:\n{text}"
            );
        }
    }

    /// The file log redacts its fields even with the identifier opt-in, so
    /// it drops the [`QUIET_TARGETS`] lines with and without it: a `WARN` of
    /// `quinn_udp` passes its `info` filter and would otherwise name the
    /// peer in the message text.
    #[test]
    fn the_file_log_never_keeps_third_party_network_lines() {
        for identifiers in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let logs = dir.path().join("logs");
            let (subscriber, guard) = subscriber(
                LogOptions {
                    filter: Some("trace".to_owned()),
                    file_dir: Some(logs.clone()),
                    json: false,
                    identifiers,
                },
                &|_| None,
                std::io::sink,
                false,
            )
            .unwrap();
            tracing::subscriber::with_default(subscriber, || {
                tracing::callsite::rebuild_interest_cache();
                tracing::warn!(target: "quinn_udp", "sendmsg error to 203.0.113.77:50417");
                tracing::warn!(target: "netlink_sys", "socket error near 203.0.113.77");
                tracing::warn!(target: "tornect_net::link", "a warning of ours");
            });
            drop(guard);
            let mut text = String::new();
            for entry in std::fs::read_dir(&logs).unwrap() {
                text.push_str(&std::fs::read_to_string(entry.unwrap().path()).unwrap());
            }
            assert!(text.contains("a warning of ours"), "{identifiers}: {text}");
            assert!(!text.contains("203.0.113.77"), "{identifiers}: {text}");
        }
    }
}
