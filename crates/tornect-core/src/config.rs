//! User configuration (`config.toml`).
//!
//! Every field has a default so a missing file or a partial file is valid; unknown
//! keys are ignored so newer configs still load in older builds. Security-relevant
//! behaviour that `docs/PLAN.md` §B.6 makes mandatory (persistent sharing
//! indicator, session logging of consent decisions) is deliberately *not*
//! configurable here.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

/// Current on-disk config schema version.
pub const CONFIG_VERSION: u32 = 1;

/// Top-level configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Schema version (for migrations).
    pub version: u32,
    /// Naming and startup.
    pub general: General,
    /// Connectivity and privacy mode (`docs/PLAN.md` §A.4, §B.6).
    pub network: Network,
    /// Tor / onion-service options (§B.3).
    pub tor: Tor,
    /// Streaming quality and codec preferences (§B.4, §B.7).
    pub media: Media,
    /// Host-side safety controls (§B.6).
    pub security: Security,
}

/// Naming and startup.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct General {
    /// Name shown to peers in consent popups and device lists.
    pub device_name: String,
    /// Start the host service at login (needed for unattended access).
    pub autostart: bool,
}

/// Connectivity and privacy mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Network {
    /// Public STUN servers used for server-reflexive candidates. May be emptied.
    pub stun_servers: Vec<String>,
    /// Whether to query the STUN list at all.
    pub enable_stun: bool,
    /// Try UPnP-IGD port mapping.
    pub upnp: bool,
    /// Try NAT-PMP port mapping.
    pub nat_pmp: bool,
    /// Try PCP port mapping.
    pub pcp: bool,
    /// Only accept/offer LAN candidates (no STUN, no Tor fallback for media).
    pub lan_only: bool,
    /// Paranoid mode: media always relayed through Tor; peers never learn IPs.
    pub paranoid: bool,
    /// How long to hole-punch before falling back to Tor (`docs/PLAN.md` §B.2: 4 s).
    pub punch_timeout_ms: u32,
    /// Fixed UDP port for direct connections (`None` = ephemeral).
    pub direct_port: Option<u16>,
}

/// Tor / onion-service options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tor {
    /// Enable proof-of-work introduction defense on the onion service.
    pub pow_defense: bool,
    /// Restricted discovery: only clients holding a pre-shared key can find the service.
    pub restricted_discovery: bool,
    /// Give up bootstrapping after this long.
    pub bootstrap_timeout_secs: u32,
    /// How to reach the Tor network when a direct connection is blocked
    /// (decision M1-38): `auto` tries direct Tor, then obfs4 bridges, then
    /// Snowflake, starting from whichever worked last time. Once a bridge was
    /// needed, direct Tor is tried last; with `bridge_lines` set it is not tried.
    pub bridges: BridgeMode,
    /// Private bridge lines (`obfs4 IP:PORT FINGERPRINT cert=… iat-mode=0`,
    /// `webtunnel …`, `snowflake …`) from <https://bridges.torproject.org>.
    /// They **replace** the public built-in bridges of their transport, as in
    /// Tor Browser: mixing them would let a censor that lists the public ones
    /// find the private one by correlation. Lines that do not parse are skipped
    /// and reported by position only, never by content.
    pub bridge_lines: Vec<String>,
    /// The `lyrebird` pluggable-transport binary, as an absolute path; it may be
    /// a build this release does not pin (logged). Unset: the copy bundled next
    /// to the executable (or in its `pt/` directory), else `$TORNECT_PT_DIR`,
    /// and it must match the pinned SHA-256. `PATH` is never searched.
    pub pt_path: Option<PathBuf>,
}

/// How the Tor client reaches the network (`[tor] bridges = "…"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BridgeMode {
    /// Direct Tor first; if it is blocked, obfs4 bridges, then Snowflake.
    #[default]
    Auto,
    /// Direct Tor only (never use bridges).
    Off,
    /// obfs4 bridges only.
    Obfs4,
    /// Snowflake only.
    Snowflake,
}

/// Video codec identifiers, in negotiation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Codec {
    /// AV1.
    Av1,
    /// H.265 / HEVC.
    Hevc,
    /// H.264 / AVC.
    H264,
}

/// Jitter-buffer preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LatencyMode {
    /// Smallest possible glass-to-glass delay; accepts occasional judder.
    PreferLatency,
    /// Larger jitter buffer for smoother playback.
    PreferSmoothness,
}

/// Streaming quality and codec preferences.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Media {
    /// Upper bitrate cap for the ABR controller (kbit/s).
    pub max_bitrate_kbps: u32,
    /// Lower bitrate floor before the resolution ladder steps down (kbit/s).
    pub min_bitrate_kbps: u32,
    /// Frame-rate cap.
    pub max_fps: u32,
    /// Codec ladder, best first.
    pub codec_preference: Vec<Codec>,
    /// Jitter-buffer preference.
    pub latency_mode: LatencyMode,
    /// Bitrate cap when media is relayed through Tor (kbit/s).
    pub tor_fallback_max_kbps: u32,
    /// Negotiate HDR (HEVC Main10 / AV1 10-bit) when both ends support it.
    pub hdr: bool,
    /// Prefer 4:4:4 chroma for text-heavy desktop work when the encoder supports it.
    pub text_mode_444: bool,
}

/// Host-side safety controls.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Security {
    /// Panic disconnect hotkey on the host.
    pub panic_key: String,
    /// New sessions default to view-only unless the popup grants control.
    pub view_only_default: bool,
    /// Write crash dumps locally (never uploaded).
    pub crash_dumps: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            general: General::default(),
            network: Network::default(),
            tor: Tor::default(),
            media: Media::default(),
            security: Security::default(),
        }
    }
}

impl Default for General {
    fn default() -> Self {
        Self {
            device_name: default_device_name(),
            autostart: false,
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Self {
            stun_servers: vec![
                "stun.l.google.com:19302".to_owned(),
                "stun1.l.google.com:19302".to_owned(),
                "stun.cloudflare.com:3478".to_owned(),
            ],
            enable_stun: true,
            upnp: true,
            nat_pmp: true,
            pcp: true,
            lan_only: false,
            paranoid: false,
            punch_timeout_ms: 4000,
            direct_port: None,
        }
    }
}

impl Default for Tor {
    fn default() -> Self {
        Self {
            pow_defense: true,
            restricted_discovery: false,
            bootstrap_timeout_secs: 180,
            bridges: BridgeMode::Auto,
            bridge_lines: Vec::new(),
            pt_path: None,
        }
    }
}

impl Default for Media {
    fn default() -> Self {
        Self {
            max_bitrate_kbps: 20_000,
            min_bitrate_kbps: 500,
            max_fps: 60,
            codec_preference: vec![Codec::Av1, Codec::Hevc, Codec::H264],
            latency_mode: LatencyMode::PreferLatency,
            tor_fallback_max_kbps: 4_000,
            hdr: false,
            text_mode_444: false,
        }
    }
}

impl Default for Security {
    fn default() -> Self {
        Self {
            panic_key: "Ctrl+Alt+End".to_owned(),
            view_only_default: false,
            crash_dumps: false,
        }
    }
}

/// The name peers see until the user picks one: neutral, from the operating
/// system alone ("Linux PC", "Windows PC"), never this machine's network
/// name, which every device it pairs with and every computer it connects to
/// would otherwise be sent and keep. It reads nothing: no variable, no file.
/// A config file that stores a name keeps it.
#[must_use]
pub fn default_device_name() -> String {
    const NEUTRAL: &str = if cfg!(windows) {
        "Windows PC"
    } else if cfg!(target_os = "macos") {
        "Mac"
    } else if cfg!(target_os = "android") {
        "Android device"
    } else if cfg!(target_os = "linux") {
        "Linux PC"
    } else {
        "Tornect device"
    };
    NEUTRAL.to_owned()
}

impl Config {
    /// Load from `path`; a missing file yields the defaults.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match fs_err::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        let cfg: Self = toml::from_str(&text).map_err(|source| CoreError::ConfigParse {
            path: path.to_path_buf(),
            source: Box::new(crate::error::TomlError::new(&text, &source)),
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load from `path`, writing the defaults there first if it does not exist.
    ///
    /// Returns the config and whether the file was created.
    pub fn load_or_init(path: &Path) -> Result<(Self, bool)> {
        if path.exists() {
            Ok((Self::load(path)?, false))
        } else {
            let cfg = Self::default();
            cfg.save(path)?;
            Ok((cfg, true))
        }
    }

    /// Serialize to `path` (creating parent directories).
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            crate::keystore::create_private_dir(parent)?;
        }
        let body = toml::to_string_pretty(self)?;
        let text = format!(
            "# Tornect configuration — https://github.com/Mxrider420z/Tornect\n# Every key is optional; delete a key to restore its default.\n\n{body}"
        );
        crate::keystore::write_private_file(path, text.as_bytes())?;
        Ok(())
    }

    /// Check ranges and formats.
    pub fn validate(&self) -> Result<()> {
        let m = &self.media;
        if m.min_bitrate_kbps == 0 || m.min_bitrate_kbps > m.max_bitrate_kbps {
            return Err(CoreError::ConfigInvalid(format!(
                "media.min_bitrate_kbps ({}) must be > 0 and <= media.max_bitrate_kbps ({})",
                m.min_bitrate_kbps, m.max_bitrate_kbps
            )));
        }
        if !(1..=240).contains(&m.max_fps) {
            return Err(CoreError::ConfigInvalid(format!(
                "media.max_fps ({}) must be between 1 and 240",
                m.max_fps
            )));
        }
        if m.codec_preference.is_empty() {
            return Err(CoreError::ConfigInvalid(
                "media.codec_preference must list at least one codec".to_owned(),
            ));
        }
        if self.network.punch_timeout_ms == 0 || self.network.punch_timeout_ms > 60_000 {
            return Err(CoreError::ConfigInvalid(
                "network.punch_timeout_ms must be between 1 and 60000".to_owned(),
            ));
        }
        for s in &self.network.stun_servers {
            let Some((host, port)) = s.rsplit_once(':') else {
                return Err(CoreError::ConfigInvalid(format!(
                    "network.stun_servers entry {s:?} must be host:port"
                )));
            };
            if host.is_empty() || port.parse::<u16>().is_err() {
                return Err(CoreError::ConfigInvalid(format!(
                    "network.stun_servers entry {s:?} must be host:port"
                )));
            }
        }
        if self.network.lan_only && self.network.paranoid {
            return Err(CoreError::ConfigInvalid(
                "network.lan_only and network.paranoid are mutually exclusive".to_owned(),
            ));
        }
        if self.general.device_name.trim().is_empty() || self.general.device_name.len() > 64 {
            return Err(CoreError::ConfigInvalid(
                "general.device_name must be 1..=64 characters".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_roundtrip() {
        let cfg = Config::default();
        cfg.validate().unwrap();
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn partial_file_fills_defaults_and_ignores_unknown_keys() {
        let text = r#"
[media]
max_fps = 30

[network]
stun_servers = []
future_key = "ignored"
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        assert_eq!(cfg.media.max_fps, 30);
        assert!(cfg.network.stun_servers.is_empty());
        assert!(cfg.network.upnp);
        assert_eq!(cfg.security.panic_key, "Ctrl+Alt+End");
    }

    /// A8 (§B.8.15): policy never lives in `config.toml` — an `[unattended]` table is
    /// ignored, not honoured (§B.8.6.2 UA7).
    #[test]
    fn a8_config_ignores_an_unattended_table() {
        let text = r#"
[unattended]
enabled = true
grants = ["everyone"]

[security]
panic_key = "Ctrl+Alt+End"
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        assert_eq!(cfg, Config::default());
        let dumped = toml::to_string_pretty(&cfg).unwrap();
        assert!(!dumped.contains("unattended"));
    }

    #[test]
    fn load_or_init_creates_file_then_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg").join("config.toml");
        let (cfg, created) = Config::load_or_init(&path).unwrap();
        assert!(created);
        assert_eq!(cfg, Config::default());
        let (cfg2, created) = Config::load_or_init(&path).unwrap();
        assert!(!created);
        assert_eq!(cfg2, cfg);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# Tornect configuration"));
    }

    #[test]
    fn missing_file_is_defaults_but_bad_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Config::load(&dir.path().join("nope.toml")).unwrap(),
            Config::default()
        );
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "this is = not [valid").unwrap();
        assert!(matches!(
            Config::load(&bad),
            Err(CoreError::ConfigParse { .. })
        ));
    }

    /// The name others see (accepted decision 5): a fresh config names this
    /// computer by its operating system alone and never by its network name,
    /// and a config file written with a name, a host name included, keeps it.
    /// The host name here is invented; the default reads no variable and no
    /// file, so no host name can reach it.
    #[test]
    fn the_default_device_name_is_neutral_and_a_stored_name_is_kept() {
        let invented_host = "quillmere-desk-4821";
        let neutral = if cfg!(windows) {
            "Windows PC"
        } else if cfg!(target_os = "linux") {
            "Linux PC"
        } else {
            return;
        };
        assert_eq!(default_device_name(), neutral);
        assert_eq!(Config::default().general.device_name, neutral);
        let fresh: Config = toml::from_str("[general]\nautostart = false\n").unwrap();
        assert_eq!(fresh.general.device_name, neutral);
        assert!(!fresh.general.device_name.contains(invented_host));

        let stored: Config =
            toml::from_str(&format!("[general]\ndevice_name = \"{invented_host}\"\n")).unwrap();
        stored.validate().unwrap();
        assert_eq!(stored.general.device_name, invented_host);
    }

    #[test]
    fn validation_catches_bad_values() {
        let mut cfg = Config::default();
        cfg.media.max_fps = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = Config::default();
        cfg.network.stun_servers = vec!["no-port".to_owned()];
        assert!(cfg.validate().is_err());

        let mut cfg = Config::default();
        cfg.network.lan_only = true;
        cfg.network.paranoid = true;
        assert!(cfg.validate().is_err());

        let mut cfg = Config::default();
        cfg.media.min_bitrate_kbps = cfg.media.max_bitrate_kbps + 1;
        assert!(cfg.validate().is_err());
    }
}
