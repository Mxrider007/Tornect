//! Arti configuration derived from Tornect's [`Paths`] and [`Tor`] settings
//! (docs/research/arti.md §6, §8.1, §10).

use std::time::Duration;

use arti_client::TorClientConfig;
use arti_client::config::onion_service::{OnionServiceConfig, OnionServiceConfigBuilder};
use arti_client::config::{BoolOrAuto, TorClientConfigBuilder};
use tor_hsservice::HsNickname;
use tor_hsservice::config::TokenBucketConfig;
use tornect_core::Paths;
use tornect_core::config::Tor;
use tornect_core::keystore::create_private_dir;

use super::bridges::Transport;
use crate::error::{Result, SignalError};

/// Timeout for opening a stream to an onion service. The first connect to a host
/// fetches its descriptor, then builds introduction and rendezvous circuits,
/// which routinely exceeds Arti's 10 s default (docs/research/arti.md §6, §13.5).
/// Shorter than Arti's own wait for an *unanswered* rendezvous on a cold
/// circuit-timeout estimator (≈ 8 min; `tor::listener` module docs), so under
/// proof-of-work backpressure a cold client times out here before Arti retries
/// with effort — the client-side follow-up of decision M1-4.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Introduction points the host establishes (Arti accepts 3..=20).
pub const NUM_INTRO_POINTS: u8 = 3;

/// Introduction rate limit sent to the intro points as `DOS_PARAMS`:
/// `(requests per second, burst)`; the values Arti's example config ships.
pub const INTRO_RATE_LIMIT: (u32, u32) = (25, 200);

/// Streams one rendezvous circuit may hold before Arti tears the circuit down.
/// Signaling needs one, the Tor media fallback a second and the session
/// services (`super::SERVICES_PORT`) a third; 4 leaves one for a reconnect in
/// flight while capping one circuit's footprint (each open stream costs a
/// host-side task and Arti's per-stream buffers) at what a session needs plus
/// that one.
pub const MAX_STREAMS_PER_CIRCUIT: u32 = 4;

/// Introduction requests Arti queues while proof-of-work is being enforced.
/// Arti's default is 8192 entries ≈ 32 MB (docs/research/arti.md §8.1); a host
/// that keeps at most `tor::listener::MAX_LIVE_CIRCUITS` (64) rendezvous
/// circuits has no use for a backlog that large, so it is capped at ≈ 4 MB.
/// Requests beyond it are dropped, which is what the queue is for.
pub const POW_REND_QUEUE_DEPTH: usize = 1024;

/// Build the client configuration: Tornect-owned state and cache directories,
/// keystore explicitly on, `.onion` targets allowed, long connect timeout, and
/// `transport` (direct, or bridges through `lyrebird`, decision M1-38).
///
/// Every directory is created `0700` before Arti sees it: `fs-mistrust` refuses
/// group- or world-writable state and keystore directories, and a plain
/// `create_dir_all` would apply the umask.
pub(crate) fn tor_client_config(paths: &Paths, transport: &Transport) -> Result<TorClientConfig> {
    paths.ensure()?;
    let state_dir = paths.arti_state_dir();
    let cache_dir = paths.arti_cache_dir();
    create_private_dir(&state_dir)?;
    create_private_dir(&cache_dir)?;

    let mut builder = TorClientConfigBuilder::from_directories(&state_dir, &cache_dir);
    builder
        .storage()
        .keystore()
        .enabled(BoolOrAuto::Explicit(true));
    builder.address_filter().allow_onion_addrs(true);
    builder.stream_timeouts().connect_timeout(CONNECT_TIMEOUT);
    transport.apply(&mut builder)?;
    builder
        .build()
        .map_err(|e| SignalError::Config(e.to_string()))
}

/// Build the onion-service configuration for `nickname` from the user's Tor settings.
///
/// Security settings fail closed: a knob this build cannot honour refuses to
/// launch with [`SignalError::Config`] rather than silently running without it.
/// `tor.restricted_discovery` is not implemented yet (docs/research/arti.md §11),
/// and `tor.pow_defense` needs the `tor-pow` cargo feature (Arti rejects
/// `enable_pow` at build time without it, arti.md §10).
pub(crate) fn onion_service_config(nickname: HsNickname, tor: &Tor) -> Result<OnionServiceConfig> {
    if tor.restricted_discovery {
        return Err(SignalError::Config(
            "tor.restricted_discovery is not supported by this build yet; \
             set it to false in config.toml"
                .to_owned(),
        ));
    }
    if tor.pow_defense && !pow_supported() {
        return Err(SignalError::Config(
            "tor.pow_defense is on but this build lacks the `tor-pow` feature; \
             rebuild with it, set tor.pow_defense = false, or pass --no-pow"
                .to_owned(),
        ));
    }
    let mut builder = OnionServiceConfigBuilder::default();
    builder
        .nickname(nickname)
        .num_intro_points(NUM_INTRO_POINTS)
        .rate_limit_at_intro(Some(TokenBucketConfig::new(
            INTRO_RATE_LIMIT.0,
            INTRO_RATE_LIMIT.1,
        )))
        .max_concurrent_streams_per_circuit(MAX_STREAMS_PER_CIRCUIT)
        // The field exists in every build; it only matters with PoW on.
        .pow_rend_queue_depth(POW_REND_QUEUE_DEPTH);
    #[cfg(feature = "tor-pow")]
    if tor.pow_defense {
        builder.enable_pow(true);
    }
    builder
        .build()
        .map_err(|e| SignalError::Config(e.to_string()))
}

/// Whether this build can enforce proof-of-work introduction defense.
#[must_use]
pub const fn pow_supported() -> bool {
    cfg!(feature = "tor-pow")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_builds_and_creates_private_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let cfg = tor_client_config(&paths, &Transport::direct()).unwrap();
        assert!(paths.arti_state_dir().is_dir());
        assert!(paths.arti_cache_dir().is_dir());
        // Keystore location is derived from the state dir by Arti; it must be enabled.
        assert!(cfg.keystore().is_enabled());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for dir in [paths.arti_state_dir(), paths.arti_cache_dir()] {
                let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o700, "{}", dir.display());
            }
        }
        // Building twice over the same directories is fine (restart path).
        tor_client_config(&paths, &Transport::direct()).unwrap();
    }

    #[test]
    fn onion_service_config_builds_with_and_without_pow() {
        let nick = HsNickname::new("tornect-test".to_owned()).unwrap();
        let mut tor = Tor::default();
        assert!(tor.pow_defense, "plan §B.3: PoW on by default");
        if pow_supported() {
            let cfg = onion_service_config(nick.clone(), &tor).unwrap();
            assert_eq!(cfg.nickname(), &nick);
            assert!(*cfg.enable_pow());
            // Every bound reaches Arti, not just the PoW switch.
            assert_eq!(*cfg.pow_rend_queue_depth(), POW_REND_QUEUE_DEPTH);
            assert_eq!(
                *cfg.max_concurrent_streams_per_circuit(),
                MAX_STREAMS_PER_CIRCUIT
            );
            assert_eq!(*cfg.num_intro_points(), NUM_INTRO_POINTS);
        } else {
            // Fail closed: never run without a defense the user asked for.
            let err = onion_service_config(nick.clone(), &tor).unwrap_err();
            assert!(
                matches!(&err, SignalError::Config(m) if m.contains("pow_defense")),
                "{err}"
            );
        }

        tor.pow_defense = false;
        let cfg = onion_service_config(nick.clone(), &tor).unwrap();
        assert_eq!(cfg.nickname(), &nick);
        assert!(!*cfg.enable_pow());
    }

    #[test]
    fn restricted_discovery_is_refused_until_implemented() {
        let nick = HsNickname::new("tornect-test".to_owned()).unwrap();
        let tor = Tor {
            restricted_discovery: true,
            pow_defense: false,
            ..Tor::default()
        };
        let err = onion_service_config(nick, &tor).unwrap_err();
        assert!(
            matches!(&err, SignalError::Config(m) if m.contains("restricted_discovery")),
            "{err}"
        );
    }
}
