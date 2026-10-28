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

/// The most `[media] encoder_threads` may ask for: OpenH264 runs at most 4.
pub const MAX_ENCODER_THREADS: u8 = 4;

/// Bytes in a MiB, the unit of the `[services]` limits.
pub const MIB: u64 = 1 << 20;

/// The largest `[services] max_file_mib`: 1 TiB, the largest file the
/// services stream announces (`tornect_proto::services::MAX_FILE`).
pub const MAX_FILE_MIB: u64 = 1 << 20;

/// The largest `[services] session_quota_mib` and `keep_free_mib`: the most
/// MiB whose byte count a `u64` still holds exactly.
pub const MAX_LIMIT_MIB: u64 = u64::MAX / MIB;

/// The least `[network] punch_timeout_ms` (decision M1-79): the viewer's
/// direct attempt gets at least one second.
pub const PUNCH_TIMEOUT_MIN_MS: u32 = 1000;

/// The most `[network] punch_timeout_ms` (decision M1-79): 10 s below the
/// 20 s a host keeps a session's direct link open without a `Bind`, so the
/// host still listens while the viewer tries.
pub const PUNCH_TIMEOUT_MAX_MS: u32 = 10_000;

/// The least `[network] direct_port`: peers refuse a direct candidate on a
/// lower port (`tornect_net::addr::MIN_REMOTE_PORT`).
pub const MIN_DIRECT_PORT: u16 = 1024;

/// The default `[network] stun_servers` (design `direct` §5.4): one server
/// of each of four operators, so the viewer's partition (Cloudflare,
/// Twilio) and the host's (Google, Nextcloud) never share an operator
/// (`tornect_net::stun::partition`).
pub const DEFAULT_STUN: [&str; 4] = [
    "stun.cloudflare.com:3478",
    "stun.l.google.com:19302",
    "global.stun.twilio.com:3478",
    "stun.nextcloud.com:443",
];

/// The default `[network] stun_servers` before the internet direct path
/// (design §5.4 "Migration"): a saved list equal to it is read as
/// [`DEFAULT_STUN`] ([`Network::migrate_defaults`]). It named Google twice.
pub const OLD_DEFAULT_STUN: [&str; 3] = [
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// The most `[network] stun_servers` entries (design §8.1): a session asks
/// at most two, and the list is walked in full by the partition.
pub const MAX_STUN_SERVERS: usize = 16;

/// The longest host name of a `[network] stun_servers` entry, in bytes: a
/// DNS name's limit (RFC 1035 §2.3.4, without the root's dot).
pub const MAX_STUN_HOST_LEN: usize = 253;

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
    /// The stream window's defaults when a session opens.
    pub viewer: Viewer,
    /// What someone connected to this computer may use beside the picture
    /// and input: chat, the clipboard and files (design `services` §2.6).
    pub services: Services,
}

/// Naming and startup.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct General {
    /// Name shown to peers in consent popups and device lists.
    pub device_name: String,
    /// Start the host service at login (needed for unattended access).
    pub autostart: bool,
    /// The window's colours (the settings page's General section).
    pub theme: Theme,
    /// The window has shown its one-time notice that direct connections
    /// are on (design `direct` §3.6) and its OK was pressed. A saved
    /// `network.paranoid = false` cannot be told apart from a deliberate
    /// choice, so the notice asks once, then never again.
    pub direct_notice_seen: bool,
}

/// The window's colours (`[general] theme = "…"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    /// Light text on a dark background (the default).
    #[default]
    Dark,
    /// Dark text on a light background.
    Light,
    /// Whichever of the two the operating system uses.
    System,
}

/// The stream window's defaults when a session opens (`[viewer]`); each
/// default is what the window did before it could be chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Viewer {
    /// The picture fitted to the window, or at its own size.
    pub picture: Picture,
    /// The window opens full screen.
    pub fullscreen_at_open: bool,
    /// When the toolbar hides after the pointer last moved.
    pub toolbar_hides: ToolbarHides,
    /// The toolbar shows the connection's badge (the frame rate and size).
    pub show_badge: bool,
    /// The picture quality a session opens with; the stream window's
    /// Quality menu changes it during a session.
    pub quality: QualityPreset,
    /// The stream window's Clipboard switch starts on: text copied here
    /// during a session is offered to the other computer when its window is
    /// used again, and its text comes here (design `services` §4.3). Off
    /// unless the person turns it on (`docs/PLAN.md` §B.6, the cross-feature
    /// rule of decision M1-73; decision M1-76): nothing of this computer's
    /// goes to a host the person did not choose it for. Even on, the switch
    /// starts off in the first session with a computer paired in that
    /// connection (the app's `clipboard_starts_on`).
    pub clipboard_sync: bool,
}

/// What someone connected to this computer may use beside the picture and
/// input (`[services]`, design `services` §2.6). Chat is offered in every
/// session; the clipboard and files only in a Control session whose input
/// reaches this desktop, and they pause while this computer is locked.
/// Changes apply to later sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Services {
    /// They can write to this computer's user, and the user to them.
    pub chat: bool,
    /// Text copied on either computer during the session can be pasted on
    /// the other.
    pub clipboard: bool,
    /// They can send files into `Tornect` in this computer's Downloads
    /// folder.
    pub receive_files: bool,
    /// They can see and copy any file this computer's user can open, except
    /// Tornect's own folders.
    pub browse_files: bool,
    /// The largest file, either way, in MiB (1 to [`MAX_FILE_MIB`]).
    pub max_file_mib: u64,
    /// The most this computer receives in one session, in MiB (at least
    /// `max_file_mib`).
    pub session_quota_mib: u64,
    /// Receiving stops before the disk has less than this free, in MiB.
    pub keep_free_mib: u64,
    /// Ask the Wayland screen-sharing portal for its clipboard as well (the
    /// design's §4.2). Off by default until gates G1 and G2 pass on a GNOME
    /// desktop: while it is off the portal request, the restore-token file
    /// and everything the desktop shows are what they were before services
    /// existed, and a Wayland host offers no clipboard. Turning it on makes
    /// the desktop ask once more (its grant is kept in a file of its own,
    /// [`crate::Paths::portal_restore_token_for`]).
    pub wayland_clipboard: bool,
}

impl Services {
    /// `max_file_mib` in bytes.
    #[must_use]
    pub const fn max_file_bytes(&self) -> u64 {
        self.max_file_mib.saturating_mul(MIB)
    }

    /// `session_quota_mib` in bytes.
    #[must_use]
    pub const fn session_quota_bytes(&self) -> u64 {
        self.session_quota_mib.saturating_mul(MIB)
    }

    /// `keep_free_mib` in bytes.
    #[must_use]
    pub const fn keep_free_bytes(&self) -> u64 {
        self.keep_free_mib.saturating_mul(MIB)
    }
}

/// The picture quality the viewer asks for (`[viewer] quality = "…"`): the
/// host maps it to a picture size, a frame rate and a bitrate, each bounded
/// by its own `[media]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualityPreset {
    /// The sharpest picture; needs the fastest link.
    BestQuality,
    /// A sharp picture at a steady pace (the default).
    #[default]
    Balanced,
    /// The quickest response; a smaller picture.
    BestPerformance,
}

impl QualityPreset {
    /// Every preset, sharpest first.
    pub const ALL: [Self; 3] = [Self::BestQuality, Self::Balanced, Self::BestPerformance];

    /// Its name in `config.toml` and on the command line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BestQuality => "best-quality",
            Self::Balanced => "balanced",
            Self::BestPerformance => "best-performance",
        }
    }
}

impl std::fmt::Display for QualityPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for QualityPreset {
    type Err = String;

    /// One of [`QualityPreset::as_str`]'s names, exactly.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|preset| preset.as_str() == s)
            .ok_or_else(|| {
                format!("{s:?} is not a quality: use best-quality, balanced or best-performance")
            })
    }
}

/// How the stream window shows the picture (`[viewer] picture = "…"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Picture {
    /// Fitted to the window.
    #[default]
    Fit,
    /// At its own size, with scroll bars.
    OneToOne,
}

/// When the stream window's toolbar hides (`[viewer] toolbar_hides = "…"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ToolbarHides {
    /// 2.5 seconds after the pointer last moved.
    #[default]
    #[serde(rename = "after-2.5s")]
    After2_5s,
    /// 5 seconds after the pointer last moved.
    #[serde(rename = "after-5s")]
    After5s,
    /// Never: the toolbar stays.
    #[serde(rename = "never")]
    Never,
}

impl ToolbarHides {
    /// How long after the pointer last moved the toolbar hides; `None`:
    /// never.
    #[must_use]
    pub const fn after(self) -> Option<std::time::Duration> {
        match self {
            Self::After2_5s => Some(std::time::Duration::from_millis(2500)),
            Self::After5s => Some(std::time::Duration::from_secs(5)),
            Self::Never => None,
        }
    }
}

/// Connectivity and privacy mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Network {
    /// Public STUN servers (`host:port`, at most [`MAX_STUN_SERVERS`]) that
    /// tell a side its public address on the internet direct path (design
    /// `direct` §5.3). The list is split by operator (the registrable domain)
    /// between the two roles: the viewer asks the operators at even places
    /// in the order they first appear, the host those at odd places. When
    /// both computers use the same list, as with the default, no operator
    /// sees both ends of a session. Each computer splits its own list, so a
    /// list edited on one computer only (an entry added, removed or moved)
    /// can put an operator in both computers' parts, and that operator may
    /// then see both ends. Each side asks one server per session, and a
    /// second of its own part only when the first stays silent. A list of
    /// one operator is used by both sides, and that operator then sees
    /// both. May be emptied (no STUN).
    pub stun_servers: Vec<String>,
    /// Whether to ask a STUN server at all (the Settings STUN switch). Off:
    /// no server is asked and no name is resolved; only router mapping and
    /// this computer's own addresses remain.
    pub enable_stun: bool,
    /// Try UPnP-IGD port mapping. The Settings router switch ("Ask this
    /// network's router to open a port") shows on only while `upnp`,
    /// `nat_pmp` and `pcp` are all on, and sets all three.
    pub upnp: bool,
    /// Try NAT-PMP port mapping (the router switch, with `upnp` and `pcp`).
    pub nat_pmp: bool,
    /// Try PCP port mapping (the router switch, with `upnp` and `nat_pmp`).
    pub pcp: bool,
    /// Direct connections on this network only, in both roles (decisions
    /// M1-79 and M1-85): this computer offers and admits same-site
    /// candidates only (its on-link RFC 1918 prefixes and its own ULA /48),
    /// never asks a STUN server or the router, and a session that finds no
    /// direct path ends instead of relaying its media through Tor. Config
    /// only; it cannot be set together with `paranoid`.
    pub lan_only: bool,
    /// Every session's media relayed through Tor; the computers this one
    /// meets never learn its addresses. The Settings switch "Allow direct
    /// connections" is its opposite.
    pub paranoid: bool,
    /// How long the viewer tries the direct path, from the host's accept,
    /// before relaying the session's media through Tor (`docs/PLAN.md` §B.2:
    /// 4 s; decision M1-79): [`PUNCH_TIMEOUT_MIN_MS`] to
    /// [`PUNCH_TIMEOUT_MAX_MS`], under the 20 s the host keeps listening.
    pub punch_timeout_ms: u32,
    /// Fixed UDP port for direct connections (`None` = ephemeral), at least
    /// [`MIN_DIRECT_PORT`].
    pub direct_port: Option<u16>,
    /// Allow direct connections while Tor reaches the network through a
    /// bridge (decision M1-86). Off by default: a direct path would show the
    /// network that hides Tor use that Tornect is in use. Config only; `lan_only`
    /// is unaffected by the bridge rule either way.
    pub direct_with_bridges: bool,
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

/// Limits on what this computer sends when it is shared: the viewer picks a
/// quality preset, and these bound every number of it. A limit out of its
/// range is held to it where it is used, with a warning, so a config that
/// loaded before still loads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Media {
    /// No preset on a direct path exceeds it (Best quality there runs at
    /// 12 000 or this, the lower), kbit/s.
    pub max_bitrate_kbps: u32,
    /// No preset goes below it, kbit/s.
    pub min_bitrate_kbps: u32,
    /// No preset and no capture exceeds it, frames a second.
    pub max_fps: u32,
    /// Reserved: not used yet (M3). The codec ladder, best first.
    pub codec_preference: Vec<Codec>,
    /// Reserved: not used yet (M3). The jitter-buffer preference.
    pub latency_mode: LatencyMode,
    /// Bitrate of Best quality over Tor; no preset there exceeds it, kbit/s.
    pub tor_fallback_max_kbps: u32,
    /// Reserved: not used yet (M3). HDR (HEVC Main10 / AV1 10-bit) when
    /// both ends support it.
    pub hdr: bool,
    /// Reserved: not used yet (M3). 4:4:4 chroma for text-heavy desktop
    /// work when the encoder supports it.
    pub text_mode_444: bool,
    /// Encoder threads: 1 (the default) is one thread; 0 picks from this
    /// computer's cores (one fewer than it has, 1 to 4); 2 to 4 is that many.
    pub encoder_threads: u8,
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
            viewer: Viewer::default(),
            services: Services::default(),
        }
    }
}

impl Default for Services {
    fn default() -> Self {
        Self {
            chat: true,
            clipboard: true,
            receive_files: true,
            browse_files: true,
            max_file_mib: 2048,
            session_quota_mib: 8192,
            keep_free_mib: 1024,
            wayland_clipboard: false,
        }
    }
}

impl Default for General {
    fn default() -> Self {
        Self {
            device_name: default_device_name(),
            autostart: false,
            theme: Theme::Dark,
            direct_notice_seen: false,
        }
    }
}

impl Default for Viewer {
    fn default() -> Self {
        Self {
            picture: Picture::Fit,
            fullscreen_at_open: false,
            toolbar_hides: ToolbarHides::After2_5s,
            show_badge: true,
            quality: QualityPreset::Balanced,
            clipboard_sync: false,
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Self {
            stun_servers: DEFAULT_STUN.map(str::to_owned).to_vec(),
            enable_stun: true,
            upnp: true,
            nat_pmp: true,
            pcp: true,
            lan_only: false,
            paranoid: false,
            punch_timeout_ms: 4000,
            direct_port: None,
            direct_with_bridges: false,
        }
    }
}

impl Network {
    /// Replaces a `stun_servers` list equal to [`OLD_DEFAULT_STUN`] (the
    /// earlier default, never edited) with [`DEFAULT_STUN`]; any other list
    /// is the user's and stays as it is (design §5.4 "Migration"). Called by
    /// [`Config::load`]; the next [`Config::save`] writes the new list.
    /// Returns whether the list changed.
    pub fn migrate_defaults(&mut self) -> bool {
        let old = self.stun_servers.len() == OLD_DEFAULT_STUN.len()
            && self
                .stun_servers
                .iter()
                .zip(OLD_DEFAULT_STUN)
                .all(|(s, o)| s == o);
        if old {
            self.stun_servers = DEFAULT_STUN.map(str::to_owned).to_vec();
        }
        old
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
            encoder_threads: 1,
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
    /// Load from `path`; a missing file yields the defaults. An earlier
    /// default the file still holds is read as today's
    /// ([`Network::migrate_defaults`]).
    pub fn load(path: &Path) -> Result<Self> {
        let text = match fs_err::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        let mut cfg: Self = toml::from_str(&text).map_err(|source| CoreError::ConfigParse {
            path: path.to_path_buf(),
            source: Box::new(crate::error::TomlError::new(&text, &source)),
        })?;
        cfg.network.migrate_defaults();
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

    /// Serialize to `path` (creating parent directories). The file is replaced
    /// atomically ([`crate::keystore::write_private_file_atomic`]): every settings
    /// change rewrites the whole file, and one cut short by a crash or a kill would
    /// otherwise leave it empty (every setting, the bridges included, silently back
    /// to its default) or unparseable (the window refuses to start).
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            crate::keystore::create_private_dir(parent)?;
        }
        let body = toml::to_string_pretty(self)?;
        let text = format!("{}{body}", header());
        crate::keystore::write_private_file_atomic(path, text.as_bytes())?;
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
        if m.encoder_threads > MAX_ENCODER_THREADS {
            return Err(CoreError::ConfigInvalid(format!(
                "media.encoder_threads ({}) must be between 0 and {MAX_ENCODER_THREADS}",
                m.encoder_threads
            )));
        }
        if m.codec_preference.is_empty() {
            return Err(CoreError::ConfigInvalid(
                "media.codec_preference must list at least one codec".to_owned(),
            ));
        }
        if !(PUNCH_TIMEOUT_MIN_MS..=PUNCH_TIMEOUT_MAX_MS).contains(&self.network.punch_timeout_ms) {
            return Err(CoreError::ConfigInvalid(format!(
                "network.punch_timeout_ms ({}) must be between {PUNCH_TIMEOUT_MIN_MS} and \
                 {PUNCH_TIMEOUT_MAX_MS}",
                self.network.punch_timeout_ms
            )));
        }
        if let Some(port) = self.network.direct_port
            && port < MIN_DIRECT_PORT
        {
            return Err(CoreError::ConfigInvalid(format!(
                "network.direct_port ({port}) must be {MIN_DIRECT_PORT} or above"
            )));
        }
        if self.network.stun_servers.len() > MAX_STUN_SERVERS {
            return Err(CoreError::ConfigInvalid(format!(
                "network.stun_servers lists {} servers; at most {MAX_STUN_SERVERS}",
                self.network.stun_servers.len()
            )));
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
            if host.len() > MAX_STUN_HOST_LEN
                || !host.is_ascii()
                || host.chars().any(char::is_whitespace)
            {
                return Err(CoreError::ConfigInvalid(format!(
                    "network.stun_servers entry {s:?} must name its host in at most \
                     {MAX_STUN_HOST_LEN} ASCII characters without spaces"
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
        self.services.validate()
    }
}

impl Services {
    /// Check the `[services]` ranges.
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_FILE_MIB).contains(&self.max_file_mib) {
            return Err(CoreError::ConfigInvalid(format!(
                "services.max_file_mib ({}) must be between 1 and {MAX_FILE_MIB}",
                self.max_file_mib
            )));
        }
        if !(self.max_file_mib..=MAX_LIMIT_MIB).contains(&self.session_quota_mib) {
            return Err(CoreError::ConfigInvalid(format!(
                "services.session_quota_mib ({}) must be between services.max_file_mib ({}) \
                 and {MAX_LIMIT_MIB}",
                self.session_quota_mib, self.max_file_mib
            )));
        }
        if self.keep_free_mib > MAX_LIMIT_MIB {
            return Err(CoreError::ConfigInvalid(format!(
                "services.keep_free_mib ({}) must be at most {MAX_LIMIT_MIB}",
                self.keep_free_mib
            )));
        }
        Ok(())
    }
}

/// The comment lines [`Config::save`] writes above the settings. The link is
/// the workspace's `repository` (Cargo.toml), so it follows the repository
/// when it moves instead of naming an old one (audit finding B32).
fn header() -> String {
    format!(
        "# Tornect configuration — {}\n# Every key is optional; delete a key to restore its \
         default.\n\n",
        env!("CARGO_PKG_REPOSITORY")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B32: the header links the repository the release is published from,
    /// and the settings still load from a file that starts with it.
    #[test]
    fn the_header_links_the_published_repository() {
        assert_eq!(
            env!("CARGO_PKG_REPOSITORY"),
            "https://github.com/Mxrider007/Tornect"
        );
        assert_eq!(
            header(),
            "# Tornect configuration — https://github.com/Mxrider007/Tornect\n# Every key is \
             optional; delete a key to restore its default.\n\n"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        Config::default().save(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(&header()), "{text}");
        assert!(!text.contains("Mxrider420z"), "{text}");
        assert_eq!(Config::load(&path).unwrap(), Config::default());
    }

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

    /// Decision M1-86: `network.direct_with_bridges` is off unless a file
    /// sets it, an older file without the key reads as off, and the key
    /// round-trips.
    #[test]
    fn direct_with_bridges_is_off_unless_the_file_sets_it() {
        assert!(!Config::default().network.direct_with_bridges);
        let old: Config = toml::from_str("[network]\nlan_only = false\n").unwrap();
        assert!(!old.network.direct_with_bridges);
        let set: Config = toml::from_str("[network]\ndirect_with_bridges = true\n").unwrap();
        assert!(set.network.direct_with_bridges);
        set.validate().unwrap();
        let text = toml::to_string_pretty(&set).unwrap();
        assert!(text.contains("direct_with_bridges = true"), "{text}");
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back, set);
    }

    /// Design `direct` §3.6: the one-time notice is unseen unless a file
    /// says it was seen, an older file without the key reads as unseen
    /// (an upgrade is asked once), and the key round-trips.
    #[test]
    fn the_direct_notice_is_unseen_until_the_file_says_seen() {
        assert!(!Config::default().general.direct_notice_seen);
        let old: Config = toml::from_str("[general]\ndevice_name = \"Desk\"\n").unwrap();
        assert!(!old.general.direct_notice_seen);
        let seen: Config = toml::from_str("[general]\ndirect_notice_seen = true\n").unwrap();
        assert!(seen.general.direct_notice_seen);
        seen.validate().unwrap();
        let text = toml::to_string_pretty(&seen).unwrap();
        assert!(text.contains("direct_notice_seen = true"), "{text}");
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back, seen);
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

    /// B14: a save replaces the file whole. Until the new text is complete and
    /// synced, `config.toml` keeps the old one: a save that fails before its
    /// rename (here the temporary path is taken by a directory) leaves it
    /// byte-identical and loadable, where the old in-place write had already
    /// truncated it. A save that goes through leaves no temporary file, keeps
    /// the file owner-only and, on Unix, is a new file (a rename), never the
    /// old one rewritten.
    #[test]
    fn a_save_replaces_the_file_whole_or_not_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg").join("config.toml");
        let mut cfg = Config::default();
        cfg.general.device_name = "Before".to_owned();
        cfg.save(&path).unwrap();
        let before = std::fs::read(&path).unwrap();

        let tmp = path.with_file_name("config.toml.tmp");
        std::fs::create_dir(&tmp).unwrap();
        let mut changed = cfg.clone();
        changed.general.device_name = "After".to_owned();
        assert!(
            changed.save(&path).is_err(),
            "the temporary file cannot be written"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "the old file is untouched"
        );
        assert_eq!(Config::load(&path).unwrap(), cfg);
        std::fs::remove_dir(&tmp).unwrap();

        // A stale temporary file of an earlier crash is simply overwritten.
        std::fs::write(&tmp, "half a sett").unwrap();
        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(&path).unwrap().ino()
        };
        changed.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap(), changed);
        assert!(!tmp.exists(), "no temporary file is left");
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            let meta = std::fs::metadata(&path).unwrap();
            assert_ne!(
                meta.ino(),
                inode,
                "replaced by a rename, not rewritten in place"
            );
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
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

    /// The theme and the stream window's defaults: a config file that names
    /// none of them gets what the window did before they could be chosen
    /// (dark; the picture fitted, not full screen at open, the toolbar
    /// hiding 2.5 s after the pointer last moved, the badge shown), and a
    /// file that names them keeps them.
    #[test]
    fn the_theme_and_viewer_defaults_are_the_built_ones() {
        let built = Viewer {
            picture: Picture::Fit,
            fullscreen_at_open: false,
            toolbar_hides: ToolbarHides::After2_5s,
            show_badge: true,
            quality: QualityPreset::Balanced,
            clipboard_sync: false,
        };
        for cfg in [
            Config::default(),
            toml::from_str("").unwrap(),
            toml::from_str("[general]\ndevice_name = \"Desk\"\n\n[viewer]\n").unwrap(),
        ] {
            assert_eq!(cfg.general.theme, Theme::Dark);
            assert_eq!(cfg.viewer, built);
        }
        assert_eq!(
            ToolbarHides::After2_5s.after(),
            Some(std::time::Duration::from_millis(2500))
        );
        assert_eq!(
            ToolbarHides::After5s.after(),
            Some(std::time::Duration::from_secs(5))
        );
        assert_eq!(ToolbarHides::Never.after(), None);

        let chosen: Config = toml::from_str(
            "[general]\ntheme = \"system\"\n\n[viewer]\npicture = \"one-to-one\"\n\
             fullscreen_at_open = true\ntoolbar_hides = \"never\"\nshow_badge = false\n",
        )
        .unwrap();
        assert_eq!(chosen.general.theme, Theme::System);
        assert_eq!(
            chosen.viewer,
            Viewer {
                picture: Picture::OneToOne,
                fullscreen_at_open: true,
                toolbar_hides: ToolbarHides::Never,
                show_badge: false,
                quality: QualityPreset::Balanced,
                clipboard_sync: false,
            }
        );
        let text = toml::to_string_pretty(&chosen).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back, chosen);
        assert!(text.contains("toolbar_hides = \"never\""), "{text}");
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

    /// Decision M1-79: `punch_timeout_ms` is 1–10 s (10 s under the host's
    /// 20 s linger), and a fixed `direct_port` is one a peer admits (1024
    /// or above); the defaults pass, and so does no fixed port.
    #[test]
    fn the_direct_knobs_are_validated() {
        for (ms, ok) in [
            (0, false),
            (1, false),
            (999, false),
            (PUNCH_TIMEOUT_MIN_MS, true),
            (4000, true),
            (PUNCH_TIMEOUT_MAX_MS, true),
            (10_001, false),
            (60_000, false),
        ] {
            let mut cfg = Config::default();
            cfg.network.punch_timeout_ms = ms;
            let got = cfg.validate();
            assert_eq!(got.is_ok(), ok, "{ms}: {got:?}");
            if let Err(e) = got {
                assert!(e.to_string().contains("between 1000 and 10000"), "{e}");
            }
        }
        for (port, ok) in [
            (None, true),
            (Some(1), false),
            (Some(1023), false),
            (Some(MIN_DIRECT_PORT), true),
            (Some(50_000), true),
            (Some(u16::MAX), true),
        ] {
            let mut cfg = Config::default();
            cfg.network.direct_port = port;
            let got = cfg.validate();
            assert_eq!(got.is_ok(), ok, "{port:?}: {got:?}");
        }
        assert_eq!(Config::default().network.punch_timeout_ms, 4000);
        assert!(Config::default().network.direct_port.is_none());
        let text = "[network]\npunch_timeout_ms = 500\n";
        let cfg: Config = toml::from_str(text).unwrap();
        assert!(cfg.validate().is_err(), "a file below the floor is refused");
    }

    /// Design §5.4: the default list is four servers of four operators
    /// (their registrable domains, the last two labels here), each on a
    /// port the STUN filter admits (any but 0), and it no longer names
    /// Google twice. `tornect_net::stun` tests that its partition gives the
    /// viewer Cloudflare and Twilio and the host Google and Nextcloud.
    #[test]
    fn the_default_stun_list_has_four_operators() {
        let list = Config::default().network.stun_servers;
        assert_eq!(list, DEFAULT_STUN.map(str::to_owned).to_vec());
        let mut operators = Vec::new();
        for entry in &list {
            let (host, port) = entry.rsplit_once(':').expect("host:port");
            assert_ne!(port.parse::<u16>().expect("a port"), 0, "{entry}");
            let labels: Vec<&str> = host.split('.').collect();
            operators.push(labels[labels.len() - 2..].join("."));
        }
        assert_eq!(
            operators,
            [
                "cloudflare.com",
                "google.com",
                "twilio.com",
                "nextcloud.com"
            ]
        );
        assert!(!list.iter().any(|s| s.starts_with("stun1.")), "{list:?}");
        assert!(Config::default().network.enable_stun);
    }

    /// Design §5.4 "Migration": a file that still holds the earlier
    /// default, untouched, loads with today's list, and the next save
    /// writes it; the function reports the change once.
    #[test]
    fn an_untouched_old_stun_default_is_migrated_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut old = Config::default();
        old.network.stun_servers = OLD_DEFAULT_STUN.map(str::to_owned).to_vec();
        let text = toml::to_string_pretty(&old).unwrap();
        std::fs::write(&path, &text).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(
            loaded.network.stun_servers,
            DEFAULT_STUN.map(str::to_owned).to_vec()
        );
        assert_eq!(loaded, Config::default());
        loaded.save(&path).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains("global.stun.twilio.com:3478"), "{saved}");
        assert!(!saved.contains("stun1.l.google.com"), "{saved}");

        let mut network = old.network.clone();
        assert!(network.migrate_defaults());
        assert!(!network.migrate_defaults(), "today's default stays");
        assert_eq!(network, Network::default());
    }

    /// Design §5.4: any list but the exact earlier default is the user's
    /// and is kept, however close it is: reordered, cut, extended, with
    /// another case or port, emptied.
    #[test]
    fn an_edited_stun_list_is_kept() {
        let old: Vec<String> = OLD_DEFAULT_STUN.map(str::to_owned).to_vec();
        let mut reordered = old.clone();
        reordered.reverse();
        let mut extended = old.clone();
        extended.push("stun.example.org:3478".to_owned());
        let mut cased = old.clone();
        cased[0] = cased[0].to_uppercase();
        let mut ported = old.clone();
        ported[2] = "stun.cloudflare.com:53".to_owned();
        for list in [
            reordered,
            old[..2].to_vec(),
            extended,
            cased,
            ported,
            vec![old[0].clone(), old[0].clone(), old[2].clone()],
            Vec::new(),
        ] {
            let mut network = Network {
                stun_servers: list.clone(),
                ..Network::default()
            };
            assert!(!network.migrate_defaults(), "{list:?}");
            assert_eq!(network.stun_servers, list);

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("config.toml");
            let mut cfg = Config::default();
            cfg.network.stun_servers = list.clone();
            cfg.save(&path).unwrap();
            assert_eq!(Config::load(&path).unwrap().network.stun_servers, list);
        }
    }

    /// Design §8.1: at most 16 entries, and each host at most 253 bytes of
    /// ASCII with no whitespace; an IPv6 literal in brackets passes.
    #[test]
    fn the_stun_list_is_bounded() {
        let entries = |n: usize| -> Vec<String> {
            (0..n)
                .map(|i| format!("stun{i}.example.org:3478"))
                .collect()
        };
        for (n, ok) in [(0, true), (1, true), (MAX_STUN_SERVERS, true), (17, false)] {
            let mut cfg = Config::default();
            cfg.network.stun_servers = entries(n);
            let got = cfg.validate();
            assert_eq!(got.is_ok(), ok, "{n}: {got:?}");
            if let Err(e) = got {
                assert!(e.to_string().contains("at most 16"), "{e}");
            }
        }
        let long = |len: usize| format!("{}.org:3478", "a".repeat(len - 4));
        for (entry, ok) in [
            (long(MAX_STUN_HOST_LEN), true),
            (long(MAX_STUN_HOST_LEN + 1), false),
            ("stün.example.org:3478".to_owned(), false),
            ("stun example.org:3478".to_owned(), false),
            ("stun.example.org\t:3478".to_owned(), false),
            (" stun.example.org:3478".to_owned(), false),
            ("[2001:db8::1]:3478".to_owned(), true),
            ("192.0.2.1:3478".to_owned(), true),
            (":3478".to_owned(), false),
            ("stun.example.org:65536".to_owned(), false),
        ] {
            let mut cfg = Config::default();
            cfg.network.stun_servers = vec![entry.clone()];
            let got = cfg.validate();
            assert_eq!(got.is_ok(), ok, "{entry:?}: {got:?}");
        }
    }

    /// The quality design §6.1: `[viewer] quality` is written and read in
    /// kebab-case, every preset round-trips through the file and the command
    /// line's names, and a name this version does not know is refused (a
    /// parse error for the file, a message naming the three for the command
    /// line).
    #[test]
    fn the_viewer_quality_round_trips_in_kebab_case() {
        let names = ["best-quality", "balanced", "best-performance"];
        assert_eq!(QualityPreset::ALL.map(QualityPreset::as_str), names);
        for (preset, name) in QualityPreset::ALL.into_iter().zip(names) {
            let mut cfg = Config::default();
            cfg.viewer.quality = preset;
            let text = toml::to_string_pretty(&cfg).unwrap();
            assert!(text.contains(&format!("quality = \"{name}\"")), "{text}");
            let back: Config = toml::from_str(&text).unwrap();
            assert_eq!(back.viewer.quality, preset);
            assert_eq!(name.parse::<QualityPreset>(), Ok(preset));
            assert_eq!(preset.to_string(), name);
        }
        for bad in ["fast", "Balanced", "best_quality", ""] {
            let text = format!("[viewer]\nquality = \"{bad}\"\n");
            assert!(toml::from_str::<Config>(&text).is_err(), "{bad:?}");
            let refused = bad.parse::<QualityPreset>().unwrap_err();
            assert!(
                refused.contains("best-quality, balanced or best-performance"),
                "{refused}"
            );
        }
    }

    /// The quality design §6.1: a config written before the presets loads
    /// Balanced and one encoder thread; `encoder_threads` takes 0 to 4 and
    /// nothing else; and no existing key gets a new rule, so a
    /// `min_bitrate_kbps` above `tor_fallback_max_kbps` still validates (the
    /// host clamps it where it uses it).
    #[test]
    fn the_quality_keys_default_and_only_encoder_threads_is_checked() {
        let old: Config =
            toml::from_str("[media]\nmax_fps = 30\n\n[viewer]\nshow_badge = false\n").unwrap();
        old.validate().unwrap();
        assert_eq!(old.viewer.quality, QualityPreset::Balanced);
        assert_eq!(old.media.encoder_threads, 1);
        assert_eq!(Config::default().media.encoder_threads, 1);

        for threads in 0..=4 {
            let mut cfg = Config::default();
            cfg.media.encoder_threads = threads;
            cfg.validate().unwrap();
        }
        for threads in [5, u8::MAX] {
            let mut cfg = Config::default();
            cfg.media.encoder_threads = threads;
            let err = cfg.validate().unwrap_err().to_string();
            assert!(
                err.contains(&format!(
                    "media.encoder_threads ({threads}) must be between 0 and 4"
                )),
                "{err}"
            );
        }

        let mut cfg = Config::default();
        cfg.media.min_bitrate_kbps = 5000;
        assert!(cfg.media.min_bitrate_kbps > cfg.media.tor_fallback_max_kbps);
        cfg.validate().unwrap();
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back, cfg);
    }

    /// The design's §2.6: a config written before services loads them all
    /// on, 2 GiB per file, 8 GiB a session, 1 GiB kept free, and the Wayland
    /// portal clipboard off; the viewer's clipboard switch off (the plan's
    /// cross-feature rule, decision M1-76, where the design had it on); a
    /// file that names some keys keeps them and fills the rest; every key
    /// round-trips.
    #[test]
    fn the_services_defaults_are_the_designs() {
        let want = Services {
            chat: true,
            clipboard: true,
            receive_files: true,
            browse_files: true,
            max_file_mib: 2048,
            session_quota_mib: 8192,
            keep_free_mib: 1024,
            wayland_clipboard: false,
        };
        let old: Config =
            toml::from_str("[general]\ndevice_name = \"Desk\"\n\n[viewer]\nshow_badge = false\n")
                .unwrap();
        old.validate().unwrap();
        for cfg in [
            Config::default(),
            old,
            toml::from_str("[services]\n").unwrap(),
        ] {
            assert_eq!(cfg.services, want);
            assert!(!cfg.viewer.clipboard_sync);
            assert!(!cfg.services.wayland_clipboard);
        }
        assert_eq!(want.max_file_bytes(), 2 << 30);
        assert_eq!(want.session_quota_bytes(), 8 << 30);
        assert_eq!(want.keep_free_bytes(), 1 << 30);

        let chosen: Config = toml::from_str(
            "[services]\nchat = false\nbrowse_files = false\nmax_file_mib = 10\n\
             session_quota_mib = 10\nkeep_free_mib = 0\nwayland_clipboard = true\n\
             future_key = 1\n\n[viewer]\nclipboard_sync = true\n",
        )
        .unwrap();
        chosen.validate().unwrap();
        assert_eq!(
            chosen.services,
            Services {
                chat: false,
                browse_files: false,
                max_file_mib: 10,
                session_quota_mib: 10,
                keep_free_mib: 0,
                wayland_clipboard: true,
                ..want
            }
        );
        assert!(chosen.viewer.clipboard_sync);
        let text = toml::to_string_pretty(&chosen).unwrap();
        assert!(text.contains("[services]"), "{text}");
        assert!(text.contains("wayland_clipboard = true"), "{text}");
        assert!(text.contains("clipboard_sync = true"), "{text}");
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back, chosen);

        // Saved and loaded as a file, the largest limits included.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut largest = Config::default();
        largest.services.max_file_mib = MAX_FILE_MIB;
        largest.services.session_quota_mib = MAX_LIMIT_MIB;
        largest.services.keep_free_mib = MAX_LIMIT_MIB;
        largest.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap(), largest);
        assert_eq!(largest.services.max_file_bytes(), 1 << 40);
        assert_eq!(largest.services.session_quota_bytes(), MAX_LIMIT_MIB * MIB);
    }

    /// The design's §2.6 ranges: a file of 1 MiB to 1 TiB, a session quota
    /// of at least one file, and limits whose byte counts a `u64` holds;
    /// out of range, `validate` (and so `load` and `save`) refuses with the
    /// key's name.
    #[test]
    fn the_services_ranges_are_checked() {
        let check = |change: &dyn Fn(&mut Services)| {
            let mut cfg = Config::default();
            change(&mut cfg.services);
            cfg.validate().map_err(|e| e.to_string())
        };
        for good in [
            &(|s: &mut Services| s.max_file_mib = 1) as &dyn Fn(&mut Services),
            &|s| s.max_file_mib = 8192,
            &|s| {
                s.max_file_mib = MAX_FILE_MIB;
                s.session_quota_mib = MAX_FILE_MIB;
            },
            &|s| s.session_quota_mib = s.max_file_mib,
            &|s| s.session_quota_mib = MAX_LIMIT_MIB,
            &|s| s.keep_free_mib = 0,
            &|s| s.keep_free_mib = MAX_LIMIT_MIB,
            &|s| {
                s.chat = false;
                s.clipboard = false;
                s.receive_files = false;
                s.browse_files = false;
            },
        ] {
            check(good).unwrap();
        }
        for (bad, key) in [
            (
                &(|s: &mut Services| s.max_file_mib = 0) as &dyn Fn(&mut Services),
                "services.max_file_mib (0) must be between 1 and 1048576",
            ),
            (
                &|s| {
                    s.max_file_mib = MAX_FILE_MIB + 1;
                    s.session_quota_mib = MAX_LIMIT_MIB;
                },
                "services.max_file_mib (1048577)",
            ),
            (
                &|s| s.session_quota_mib = 2047,
                "services.session_quota_mib (2047) must be between services.max_file_mib (2048)",
            ),
            (
                &|s| s.session_quota_mib = MAX_LIMIT_MIB + 1,
                "services.session_quota_mib",
            ),
            (
                &|s| s.keep_free_mib = MAX_LIMIT_MIB + 1,
                "services.keep_free_mib",
            ),
        ] {
            let err = check(bad).unwrap_err();
            assert!(err.contains(key), "{err}");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[services]\nmax_file_mib = 0\n").unwrap();
        assert!(matches!(
            Config::load(&path),
            Err(CoreError::ConfigInvalid(_))
        ));
        let mut cfg = Config::default();
        cfg.services.session_quota_mib = 1;
        assert!(cfg.save(&path).is_err());
    }
}
