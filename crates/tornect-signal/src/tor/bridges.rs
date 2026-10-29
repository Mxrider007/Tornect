//! Reaching Tor where it is blocked (decision M1-38, `docs/research/bridges.md`):
//! the direct → obfs4 → Snowflake ladder, Tor Browser's built-in bridge lines,
//! and finding the `lyrebird` pluggable transport that serves both.
//!
//! One rung is one fresh Arti client on its own tokio runtime
//! ([`super::TorNode::start_auto`]): a failed rung is torn down completely
//! before the next starts, because a bridged client that cannot take the state
//! lock a lingering direct client still holds fails for good with
//! `NoLock("bridges configured")` (bridges.md §1.11). The rung that reached
//! `ready_for_traffic` is remembered and tried first next time.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BoolOrAuto, BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use tornect_core::Paths;
use tornect_core::config::{BridgeMode, Tor};

use crate::error::{Result, SignalError};

/// Environment variable naming a directory that holds `lyrebird`.
pub const PT_DIR_ENV: &str = "TORNECT_PT_DIR";

/// File name of the pluggable-transport binary on this platform.
pub const LYREBIRD: &str = if cfg!(windows) {
    "lyrebird.exe"
} else {
    "lyrebird"
};

/// SHA-256 of the `lyrebird` this build runs: lyrebird 0.8.1 from the
/// GPG-verified tor-expert-bundle 15.0.23 (`packaging/pt/SOURCES.md`, decision
/// M1-38). A bundled or `$TORNECT_PT_DIR` binary that does not match is refused,
/// so a planted or swapped file is never launched; only an explicit
/// `tor.pt_path` may run another build, and that is logged.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const LYREBIRD_SHA256: Option<&str> =
    Some("ee13ec155cf9b131a3e1b87bd6d697a10c42d04f2eaaeab6b1590c9971d41421");
/// See the Linux x86_64 definition.
#[cfg(all(windows, target_arch = "x86_64"))]
pub const LYREBIRD_SHA256: Option<&str> =
    Some("6e218e85f9a7ae2481f5402ded822471a9a9d0c7e66b05db3842b93fa5c1f02e");
/// No `lyrebird` is pinned for this platform; only an explicit `tor.pt_path` runs one.
#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
)))]
pub const LYREBIRD_SHA256: Option<&str> = None;

/// Where a `lyrebird` binary came from, which decides what a hash mismatch means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtSource {
    /// `tor.pt_path`: the owner chose this binary, so another build may run (logged).
    Configured,
    /// Next to the executable, or in its `pt/` directory: what a release ships.
    Bundled,
    /// `$TORNECT_PT_DIR`: the developer override.
    DevOverride,
}

/// Tor Browser's built-in obfs4 bridges, verbatim from tor-browser-build
/// `projects/tor-expert-bundle/pt_config.json` at tag `tbb-15.0.23-build1`
/// (Tor Browser 15.0.23), cross-checked byte for byte against the
/// `pt_config.json` inside the GPG-verified tor-expert-bundle 15.0.23.
/// They are public, so censors can list them; private bridges go in
/// `tor.bridge_lines` and replace these (see [`Ladder`]).
pub const BUILTIN_OBFS4: &[&str] = &[
    "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
    "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
    "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
    "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
    "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
    "obfs4 212.83.43.95:443 BFE712113A72899AD685764B211FACD30FF52C31 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=1",
    "obfs4 212.83.43.74:443 39562501228A4D5E27FCA4C0C81A01EE23AE3EE4 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=1",
];

/// Tor Browser's built-in Snowflake bridge lines, same source as
/// [`BUILTIN_OBFS4`]. The addresses are placeholders by design: Snowflake
/// reaches the bridge through a domain-fronted broker and WebRTC proxies.
pub const BUILTIN_SNOWFLAKE: &[&str] = &[
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
];

/// Transports `lyrebird` serves that a user bridge line may name.
const LYREBIRD_PROTOCOLS: &[&str] = &["obfs4", "webtunnel", "snowflake"];

/// One way of reaching the Tor network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rung {
    /// Plain Tor: guards reached directly.
    Direct,
    /// obfs4 bridges (and any user `webtunnel` bridges) through `lyrebird`.
    Obfs4,
    /// Snowflake through `lyrebird`.
    Snowflake,
}

impl Rung {
    /// Every rung, in ladder order.
    pub const ALL: [Rung; 3] = [Rung::Direct, Rung::Obfs4, Rung::Snowflake];

    /// The persisted / CLI name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Obfs4 => "obfs4",
            Self::Snowflake => "snowflake",
        }
    }

    /// Human wording for progress lines.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Direct => "direct Tor",
            Self::Obfs4 => "obfs4 bridges",
            Self::Snowflake => "Snowflake",
        }
    }

    /// Whether this rung needs the pluggable-transport binary.
    #[must_use]
    pub const fn needs_pt(self) -> bool {
        !matches!(self, Self::Direct)
    }

    /// How long one attempt may take in a multi-rung ladder, and how long it
    /// may go without bootstrap progress before the next rung is tried.
    ///
    /// Not measured under censorship (bridges.md §3.4): Arti cannot report a
    /// blockage before 60 s and six attempts, and a warm directory cache shows
    /// ≈ 85 % even when the network is blocked, so the stall timer is what
    /// ends a blocked rung early; the cap bounds a slow-but-moving one.
    #[must_use]
    pub const fn policy(self) -> RungPolicy {
        match self {
            Self::Direct => RungPolicy {
                cap: Duration::from_secs(75),
                stall: Some(Duration::from_secs(40)),
            },
            Self::Obfs4 => RungPolicy {
                cap: Duration::from_secs(120),
                stall: Some(Duration::from_secs(60)),
            },
            Self::Snowflake => RungPolicy {
                cap: Duration::from_secs(180),
                stall: Some(Duration::from_secs(90)),
            },
        }
    }
}

impl fmt::Display for Rung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Rung {
    type Err = SignalError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "direct" => Ok(Self::Direct),
            "obfs4" => Ok(Self::Obfs4),
            "snowflake" => Ok(Self::Snowflake),
            other => Err(SignalError::Config(format!(
                "unknown Tor transport {other:?} (expected direct, obfs4 or snowflake)"
            ))),
        }
    }
}

/// Time limits for one rung (see [`Rung::policy`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RungPolicy {
    /// Give up after this long.
    pub cap: Duration,
    /// Give up after this long without bootstrap progress; `None` waits for the cap.
    pub stall: Option<Duration>,
}

/// A rung ready to apply to an Arti configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transport {
    /// Which rung.
    pub rung: Rung,
    /// Bridge lines (empty for [`Rung::Direct`]).
    pub bridges: Vec<String>,
    /// The `lyrebird` binary (`None` for [`Rung::Direct`]).
    pub lyrebird: Option<PathBuf>,
}

impl Transport {
    /// Plain Tor, no bridges.
    #[must_use]
    pub const fn direct() -> Self {
        Self {
            rung: Rung::Direct,
            bridges: Vec::new(),
            lyrebird: None,
        }
    }

    /// Configure `builder` for this transport.
    pub(crate) fn apply(&self, builder: &mut TorClientConfigBuilder) -> Result<()> {
        if self.rung == Rung::Direct {
            builder.bridges().enabled(BoolOrAuto::Explicit(false));
            return Ok(());
        }
        let lyrebird = self.lyrebird.as_ref().ok_or_else(|| {
            SignalError::Config(format!(
                "{} need the `{LYREBIRD}` pluggable transport, which was not found",
                self.rung.describe()
            ))
        })?;
        if self.bridges.is_empty() {
            return Err(SignalError::Config(format!(
                "no bridge lines for {}",
                self.rung.describe()
            )));
        }
        let mut protocols: Vec<&str> = Vec::new();
        for line in &self.bridges {
            // Arti's parse error quotes the offending token, which can be part of a
            // private bridge; `Ladder` has already dropped lines that do not parse.
            let bridge: BridgeConfigBuilder = line.parse().map_err(|_| {
                SignalError::Config("a bridge line could not be parsed (not shown)".to_owned())
            })?;
            builder.bridges().bridges().push(bridge);
            if let Some(protocol) = transport_of(line)
                && !protocols.contains(&protocol)
            {
                protocols.push(protocol);
            }
        }
        // One lyrebird process serves every protocol of the rung; Arti then
        // requires a CMETHOD for each before `CMETHODS DONE` (bridges.md §1.6).
        let names = protocols
            .iter()
            .map(|p| {
                p.parse()
                    .map_err(|e| SignalError::Config(format!("transport {p:?}: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut pt = TransportConfigBuilder::default();
        // `new_literal`: an absolute path, no `~` or `${…}` expansion.
        pt.protocols(names).path(CfgPath::new_literal(lyrebird));
        builder.bridges().transports().push(pt);
        builder.bridges().enabled(BoolOrAuto::Explicit(true));
        Ok(())
    }
}

/// The first token of a bridge line when it names a transport `lyrebird`
/// serves (`obfs4 …`, `webtunnel …`, `snowflake …`; a leading `Bridge` is skipped).
fn transport_of(line: &str) -> Option<&'static str> {
    let mut words = line.split_whitespace();
    let mut first = words.next()?;
    if first.eq_ignore_ascii_case("bridge") {
        first = words.next()?;
    }
    LYREBIRD_PROTOCOLS
        .iter()
        .copied()
        .find(|p| first.eq_ignore_ascii_case(p))
}

/// Why a non-blank bridge line is not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineFault {
    /// Its transport is not one `lyrebird` serves.
    NotLyrebird,
    /// A line of this transport that does not parse.
    Unparsed(&'static str),
}

/// A trimmed, non-blank bridge line's transport, or why it is not used: the
/// one check that the ladder and [`Ladder::rejected_lines`] both make.
fn check_line(line: &str) -> std::result::Result<&'static str, LineFault> {
    let kind = transport_of(line).ok_or(LineFault::NotLyrebird)?;
    // Parsed here rather than first in `Transport::apply`, so a bad line
    // costs only itself, not its whole rung.
    let parses = line
        .parse::<BridgeConfigBuilder>()
        .ok()
        .and_then(|b| b.build().ok())
        .is_some();
    if parses {
        Ok(kind)
    } else {
        Err(LineFault::Unparsed(kind))
    }
}

/// The ordered transports one start will try, plus what was left out and why.
#[derive(Debug, Clone)]
pub struct Ladder {
    /// Rungs to try, in order.
    pub rungs: Vec<Transport>,
    /// Rungs left out (no `lyrebird`, no usable bridge lines), with the reason.
    pub skipped: Vec<(Rung, String)>,
    /// User bridge lines that were ignored, with the reason.
    pub rejected_lines: Vec<String>,
    /// Timeout for a ladder of one rung (`tor.bootstrap_timeout_secs`), which
    /// has nowhere to fall back to and so is not cut short by the stall timer.
    single_rung_timeout: Duration,
    /// Whether the rung that works is remembered: only in `auto` mode. A forced
    /// run (`--bridges off tor-check`) must not rewrite what `auto` starts from.
    learns: bool,
}

impl Ladder {
    /// The ladder for `tor.bridges`, starting from the last rung that worked
    /// when the mode is `auto`.
    #[must_use]
    pub fn from_config(paths: &Paths, tor: &Tor) -> Self {
        Self::build(
            paths,
            tor,
            tor.bridges,
            find_lyrebird(tor.pt_path.as_deref()),
        )
    }

    /// The numbers (from 1) of the lines of `lines` that a ladder would leave
    /// out: a transport `lyrebird` does not serve, or a line that does not
    /// parse; a blank line is never among them. A bad line is named by this
    /// number only, never by its content: a private bridge is useful only
    /// while a censor does not know it.
    #[must_use]
    pub fn rejected_lines(lines: &[String]) -> Vec<usize> {
        lines
            .iter()
            .map(|l| l.trim())
            .enumerate()
            .filter(|(_, line)| !line.is_empty() && check_line(line).is_err())
            .map(|(i, _)| i + 1)
            .collect()
    }

    /// As [`Ladder::from_config`] with `mode` instead of `tor.bridges`
    /// (the CLI's `--bridges` override).
    #[must_use]
    pub fn with_mode(paths: &Paths, tor: &Tor, mode: BridgeMode) -> Self {
        Self::build(paths, tor, mode, find_lyrebird(tor.pt_path.as_deref()))
    }

    fn build(
        paths: &Paths,
        tor: &Tor,
        mode: BridgeMode,
        lyrebird: std::result::Result<PathBuf, String>,
    ) -> Self {
        let mut rejected_lines = Vec::new();
        let mut user_obfs4 = Vec::new();
        let mut user_snowflake = Vec::new();
        // Set even when every line of the transport is dropped: the owner asked
        // for private bridges there, so its public built-ins must not stand in.
        let (mut private_obfs4, mut private_snowflake) = (false, false);
        for (i, line) in tor.bridge_lines.iter().map(|l| l.trim()).enumerate() {
            if line.is_empty() {
                continue;
            }
            let n = i + 1;
            // Lines are named by their position only: a private bridge is useful
            // only while the censor does not know it, and for a vanilla line the
            // first token *is* its address (SLICE-A1 A1-5).
            let (kind, parses) = match check_line(line) {
                Ok(kind) => (kind, true),
                Err(LineFault::Unparsed(kind)) => (kind, false),
                Err(LineFault::NotLyrebird) => {
                    rejected_lines.push(format!(
                        "bridge line {n}: not an obfs4, webtunnel or snowflake bridge line"
                    ));
                    continue;
                }
            };
            if kind == "snowflake" {
                private_snowflake = true;
            } else {
                private_obfs4 = true;
            }
            if !parses {
                rejected_lines.push(format!("bridge line {n} ({kind}): could not be parsed"));
                continue;
            }
            if kind == "snowflake" {
                user_snowflake.push(line.to_owned());
            } else {
                user_obfs4.push(line.to_owned());
            }
        }
        let order: Vec<Rung> = match mode {
            BridgeMode::Off => vec![Rung::Direct],
            BridgeMode::Obfs4 => vec![Rung::Obfs4],
            BridgeMode::Snowflake => vec![Rung::Snowflake],
            BridgeMode::Auto => auto_order(private_obfs4 || private_snowflake, last_good(paths)),
        };
        let mut rungs = Vec::new();
        let mut skipped = Vec::new();
        for rung in order {
            let pt = match (&lyrebird, rung.needs_pt()) {
                (_, false) => None,
                (Ok(path), true) => Some(path.clone()),
                (Err(reason), true) => {
                    skipped.push((rung, reason.clone()));
                    continue;
                }
            };
            // Private lines *replace* the public built-ins of their transport, as
            // in Tor Browser. Mixed, Arti contacts the public bridges too, and a
            // censor that lists them can find the private one by correlation
            // (SLICE-A1 A1-1).
            let bridges: Vec<String> = match rung {
                Rung::Direct => Vec::new(),
                Rung::Obfs4 if private_obfs4 => user_obfs4.clone(),
                Rung::Obfs4 => BUILTIN_OBFS4.iter().map(|l| (*l).to_owned()).collect(),
                Rung::Snowflake if private_snowflake => user_snowflake.clone(),
                Rung::Snowflake => BUILTIN_SNOWFLAKE.iter().map(|l| (*l).to_owned()).collect(),
            };
            if rung != Rung::Direct && bridges.is_empty() {
                skipped.push((
                    rung,
                    "none of the configured private bridge lines could be used".to_owned(),
                ));
                continue;
            }
            rungs.push(Transport {
                rung,
                bridges,
                lyrebird: pt,
            });
        }
        Self {
            rungs,
            skipped,
            rejected_lines,
            single_rung_timeout: Duration::from_secs(u64::from(tor.bootstrap_timeout_secs)),
            learns: mode == BridgeMode::Auto,
        }
    }

    /// Whether the rung that works should be remembered (`auto` mode only).
    #[must_use]
    pub fn learns(&self) -> bool {
        self.learns
    }

    /// The time limits for `rung` in this ladder.
    #[must_use]
    pub fn policy(&self, rung: Rung) -> RungPolicy {
        if self.rungs.len() <= 1 {
            RungPolicy {
                cap: self.single_rung_timeout,
                stall: None,
            }
        } else {
            rung.policy()
        }
    }
}

/// The `auto` order (decision M1-38, amended after SLICE-A1 A1-2): direct Tor,
/// obfs4, Snowflake — except that
/// - with private bridge lines configured, direct Tor is not tried at all: the
///   owner has said Tor is blocked here, and a direct attempt would show the
///   network Tor handshakes from this address;
/// - the rung that worked last goes first, and once a bridge was needed, direct
///   Tor goes last, so a newly blocked bridge falls back to the other bridge
///   before revealing Tor use.
fn auto_order(private_lines: bool, last: Option<Rung>) -> Vec<Rung> {
    let mut order: Vec<Rung> = Rung::ALL
        .iter()
        .copied()
        .filter(|r| !(private_lines && *r == Rung::Direct))
        .collect();
    if let Some(last) = last
        && order.contains(&last)
    {
        order.retain(|r| *r != last);
        order.insert(0, last);
        if last != Rung::Direct
            && let Some(i) = order.iter().position(|r| *r == Rung::Direct)
        {
            let direct = order.remove(i);
            order.push(direct);
        }
    }
    order
}

/// Find and check the `lyrebird` binary (decision M1-38; SLICE-A1 A1-3/A1-4).
///
/// `tor.pt_path` if set (and nothing else); otherwise the copy bundled next to
/// the executable or in its `pt/` directory; otherwise `$TORNECT_PT_DIR`. Never
/// `PATH`, and never a relative path: either would let the current directory or
/// any user-writable `PATH` entry choose what runs. A bundled or override binary
/// must match [`LYREBIRD_SHA256`] and, on Unix, must not be writable by group or
/// others; one that fails those checks is passed over for the next candidate,
/// each checked the same way (an installed copy's `~/.local/bin` may hold the
/// user's own unpinned `lyrebird` beside the pinned `pt/lyrebird` its install
/// wrote). `Err` carries the reason the bridged rungs are unavailable: every
/// candidate's reason, or that none was found.
pub fn find_lyrebird(explicit: Option<&Path>) -> std::result::Result<PathBuf, String> {
    let env_dir = std::env::var_os(PT_DIR_ENV)
        .filter(|d| !d.is_empty())
        .map(PathBuf::from);
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    find_lyrebird_in(
        explicit,
        exe_dir.as_deref(),
        env_dir.as_deref(),
        LYREBIRD_SHA256,
    )
}

fn find_lyrebird_in(
    explicit: Option<&Path>,
    exe_dir: Option<&Path>,
    env_dir: Option<&Path>,
    pin: Option<&str>,
) -> std::result::Result<PathBuf, String> {
    let (path, source) = match explicit {
        Some(path) => {
            if !path.is_absolute() {
                return Err(format!(
                    "tor.pt_path must be an absolute path to `{LYREBIRD}`"
                ));
            }
            if !path.is_file() {
                return Err(format!("tor.pt_path names no `{LYREBIRD}` file"));
            }
            (path.to_path_buf(), PtSource::Configured)
        }
        None => {
            let mut candidates: Vec<(PathBuf, PtSource)> = Vec::new();
            if let Some(dir) = exe_dir {
                candidates.push((dir.join(LYREBIRD), PtSource::Bundled));
                candidates.push((dir.join("pt").join(LYREBIRD), PtSource::Bundled));
            }
            if let Some(dir) = env_dir {
                candidates.push((dir.join(LYREBIRD), PtSource::DevOverride));
            }
            let mut refused: Vec<String> = Vec::new();
            for (path, source) in candidates
                .into_iter()
                .filter(|(p, _)| p.is_absolute() && p.is_file())
            {
                match check_lyrebird(&path, source, pin) {
                    Ok(()) => return Ok(path),
                    Err(why) => {
                        tracing::debug!(%why, "passing over a lyrebird candidate");
                        if !refused.contains(&why) {
                            refused.push(why);
                        }
                    }
                }
            }
            return Err(if refused.is_empty() {
                lyrebird_not_found()
            } else {
                refused.join("; ")
            });
        }
    };
    check_lyrebird(&path, source, pin)?;
    Ok(path)
}

/// Why no `lyrebird` runs when none was found.
fn lyrebird_not_found() -> String {
    format!(
        "`{LYREBIRD}` not found (put it next to the tornect executable, or set tor.pt_path; \
         developers: {PT_DIR_ENV})"
    )
}

/// The largest `lyrebird` [`bundled_lyrebird`] reads (lyrebird 0.8.1 is
/// about 10 MB on either platform).
const LYREBIRD_MAX: u64 = 64 * 1024 * 1024;

/// The running copy's own bundled `lyrebird`, for `tornect install` to put
/// beside the installed copy (the final audit before the release): where
/// [`find_lyrebird`] finds it with no `tor.pt_path` (beside the executable,
/// then its `pt/` folder, a candidate that fails a check passed over for
/// the next as there), never `$TORNECT_PT_DIR` or a configured path, and
/// only while this build pins one. Each candidate is opened once, on Unix
/// without waiting (`O_NONBLOCK`: a FIFO put at the name opens at once and
/// is refused by its type); every check is made on that handle (a regular
/// file, on Unix not writable by group or others, at most 64 MiB by its
/// size before anything is read), at most 64 MiB and one byte are read from
/// it, and those bytes must have the pinned SHA-256. Its path and bytes, or
/// why there is none to install.
pub fn bundled_lyrebird() -> std::result::Result<(PathBuf, Vec<u8>), String> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    bundled_lyrebird_in(exe_dir.as_deref(), LYREBIRD_SHA256)
}

/// [`bundled_lyrebird`] for the executable's folder `exe_dir` and the pin
/// `pin`.
pub fn bundled_lyrebird_in(
    exe_dir: Option<&Path>,
    pin: Option<&str>,
) -> std::result::Result<(PathBuf, Vec<u8>), String> {
    let Some(pin) = pin else {
        return Err(format!("this build pins no `{LYREBIRD}` for this platform"));
    };
    let Some(dir) = exe_dir.filter(|dir| dir.is_absolute()) else {
        return Err(lyrebird_not_found());
    };
    let mut refused: Vec<String> = Vec::new();
    for path in [dir.join(LYREBIRD), dir.join("pt").join(LYREBIRD)] {
        match read_pinned(&path, pin) {
            Ok(Some(bytes)) => return Ok((path, bytes)),
            Ok(None) => {}
            Err(why) => refused.push(why),
        }
    }
    Err(if refused.is_empty() {
        lyrebird_not_found()
    } else {
        refused.join("; ")
    })
}

/// The bytes of the `lyrebird` at `path`, read as [`bundled_lyrebird`]
/// reads a candidate: `None` when nothing is there, `Err` with the reason
/// when what is there fails a check.
fn read_pinned(path: &Path, pin: &str) -> std::result::Result<Option<Vec<u8>>, String> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    let at = path.display();
    let file = match open_no_wait(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot open `{LYREBIRD}` at {at}: {e}")),
    };
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot inspect `{LYREBIRD}` at {at}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("`{LYREBIRD}` at {at} is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o022 != 0 {
            return Err(format!("`{LYREBIRD}` at {at} is writable by other users"));
        }
    }
    if meta.len() > LYREBIRD_MAX {
        return Err(format!("`{LYREBIRD}` at {at} is larger than 64 MiB"));
    }
    let mut bytes = Vec::new();
    file.take(LYREBIRD_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read `{LYREBIRD}` at {at}: {e}"))?;
    if bytes.len() as u64 > LYREBIRD_MAX {
        return Err(format!("`{LYREBIRD}` at {at} is larger than 64 MiB"));
    }
    if hex::encode(Sha256::digest(&bytes)) != pin {
        return Err(format!(
            "`{LYREBIRD}` at {at} is not the pinned lyrebird 0.8.1 (SHA-256 mismatch)"
        ));
    }
    Ok(Some(bytes))
}

/// Open `path` for reading, on Unix without waiting (`O_NONBLOCK`: a FIFO
/// opens at once instead of waiting for a writer, and is then refused by
/// its type) and never as a controlling terminal. A link at `path` is
/// followed, as the bridges' lookup follows it: every check is made on the
/// handle, so it is what was opened that is checked. Reads of a regular
/// file are not changed by `O_NONBLOCK`.
fn open_no_wait(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        Ok(std::fs::File::from(rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?))
    }
    #[cfg(not(unix))]
    {
        std::fs::File::open(path)
    }
}

/// The integrity checks of [`find_lyrebird`].
fn check_lyrebird(
    path: &Path,
    source: PtSource,
    pin: Option<&str>,
) -> std::result::Result<(), String> {
    #[cfg(unix)]
    if source != PtSource::Configured {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .map_err(|e| format!("cannot inspect `{LYREBIRD}`: {e}"))?
            .permissions()
            .mode();
        if mode & 0o022 != 0 {
            return Err(format!(
                "`{LYREBIRD}` at {} is writable by other users; refusing to run it",
                path.display()
            ));
        }
    }
    let digest = sha256_file(path).map_err(|e| format!("cannot read `{LYREBIRD}`: {e}"))?;
    match (pin, source) {
        (Some(pin), _) if digest == pin => Ok(()),
        (_, PtSource::Configured) => {
            tracing::warn!(
                path = %path.display(),
                sha256 = %digest,
                "tor.pt_path names a lyrebird this build does not pin; running it because \
                 it was configured explicitly"
            );
            Ok(())
        }
        (Some(_), _) => Err(format!(
            "`{LYREBIRD}` at {} is not the pinned lyrebird 0.8.1 (SHA-256 mismatch); \
             refusing to run it",
            path.display()
        )),
        (None, _) => Err(format!(
            "this build pins no `{LYREBIRD}` for this platform; set tor.pt_path to use one"
        )),
    }
}

/// Lowercase hex SHA-256 of a file.
fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// The rung that last reached `ready_for_traffic`, if one was recorded.
#[must_use]
pub fn last_good(paths: &Paths) -> Option<Rung> {
    std::fs::read_to_string(paths.tor_transport_file())
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Record `rung` as the one to try first next time. Best effort: failing to
/// write only costs the next start its shortcut.
pub(crate) fn remember(paths: &Paths, rung: Rung) {
    let file = paths.tor_transport_file();
    let tmp = file.with_extension("tmp");
    let written = std::fs::write(&tmp, rung.as_str()).and_then(|()| std::fs::rename(&tmp, &file));
    if let Err(e) = written {
        tracing::debug!(error = %e, "could not record the Tor transport that worked");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> (tempfile::TempDir, Paths) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        paths.ensure().unwrap();
        (tmp, paths)
    }

    /// A stand-in binary, owner-only, with known contents.
    fn fake_lyrebird(dir: &Path) -> PathBuf {
        let path = dir.join(LYREBIRD);
        std::fs::write(&path, b"not really lyrebird").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn pin_of(path: &Path) -> String {
        sha256_file(path).unwrap()
    }

    const PRIVATE_OBFS4: &str =
        "obfs4 198.51.100.7:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0";

    #[test]
    fn every_builtin_line_parses_as_an_arti_bridge() {
        for line in BUILTIN_OBFS4.iter().chain(BUILTIN_SNOWFLAKE) {
            let parsed: std::result::Result<BridgeConfigBuilder, _> = line.parse();
            assert!(parsed.is_ok(), "{line}: {:?}", parsed.err());
        }
        assert_eq!(BUILTIN_OBFS4.len(), 7);
        assert_eq!(BUILTIN_SNOWFLAKE.len(), 2);
        assert!(
            BUILTIN_OBFS4
                .iter()
                .all(|l| transport_of(l) == Some("obfs4"))
        );
        assert!(
            BUILTIN_SNOWFLAKE
                .iter()
                .all(|l| transport_of(l) == Some("snowflake"))
        );
    }

    #[test]
    fn auto_ladder_is_direct_then_obfs4_then_snowflake() {
        let (tmp, paths) = paths();
        let lyrebird = fake_lyrebird(tmp.path());
        let ladder = Ladder::build(&paths, &Tor::default(), BridgeMode::Auto, Ok(lyrebird));
        let order: Vec<Rung> = ladder.rungs.iter().map(|t| t.rung).collect();
        assert_eq!(order, vec![Rung::Direct, Rung::Obfs4, Rung::Snowflake]);
        assert!(ladder.skipped.is_empty());
        assert_eq!(ladder.rungs[1].bridges.len(), BUILTIN_OBFS4.len());
        assert_eq!(ladder.rungs[2].bridges.len(), BUILTIN_SNOWFLAKE.len());
        // A multi-rung ladder uses the per-rung policy, stall timer included.
        assert_eq!(ladder.policy(Rung::Direct), Rung::Direct.policy());
        assert!(ladder.learns());
    }

    /// SLICE-A1 A1-2: the rung that worked goes first, and once a bridge was
    /// needed, direct Tor goes last rather than second.
    #[test]
    fn the_last_rung_that_worked_goes_first_and_direct_goes_last() {
        let (tmp, paths) = paths();
        let lyrebird = fake_lyrebird(tmp.path());
        remember(&paths, Rung::Snowflake);
        assert_eq!(last_good(&paths), Some(Rung::Snowflake));
        let ladder = Ladder::build(&paths, &Tor::default(), BridgeMode::Auto, Ok(lyrebird));
        let order: Vec<Rung> = ladder.rungs.iter().map(|t| t.rung).collect();
        assert_eq!(order, vec![Rung::Snowflake, Rung::Obfs4, Rung::Direct]);
    }

    /// SLICE-A1 A1-2: the `auto` order rules in one place.
    #[test]
    fn auto_order_rules() {
        use Rung::{Direct as D, Obfs4 as O, Snowflake as S};
        assert_eq!(auto_order(false, None), vec![D, O, S]);
        assert_eq!(auto_order(false, Some(D)), vec![D, O, S]);
        assert_eq!(auto_order(false, Some(O)), vec![O, S, D]);
        // Private lines: the owner said Tor is blocked, so no direct probe at all.
        assert_eq!(auto_order(true, None), vec![O, S]);
        assert_eq!(auto_order(true, Some(D)), vec![O, S]);
        assert_eq!(auto_order(true, Some(S)), vec![S, O]);
    }

    #[test]
    fn without_lyrebird_only_direct_remains_and_the_gap_is_reported() {
        let (_tmp, paths) = paths();
        let ladder = Ladder::build(
            &paths,
            &Tor::default(),
            BridgeMode::Auto,
            Err("`lyrebird` not found".to_owned()),
        );
        assert_eq!(ladder.rungs.len(), 1);
        assert_eq!(ladder.rungs[0].rung, Rung::Direct);
        let skipped: Vec<Rung> = ladder.skipped.iter().map(|(r, _)| *r).collect();
        assert_eq!(skipped, vec![Rung::Obfs4, Rung::Snowflake]);
        assert!(ladder.skipped[0].1.contains("not found"));
        // One rung left: nowhere to fall back to, so no stall cut-off.
        assert_eq!(ladder.policy(Rung::Direct).stall, None);
    }

    /// Forced modes have one rung and, SLICE-A1 A1-2, never rewrite the rung
    /// `auto` starts from.
    #[test]
    fn forced_modes_have_one_rung_and_do_not_learn() {
        let (tmp, paths) = paths();
        let lyrebird = fake_lyrebird(tmp.path());
        for (mode, rung) in [
            (BridgeMode::Off, Rung::Direct),
            (BridgeMode::Obfs4, Rung::Obfs4),
            (BridgeMode::Snowflake, Rung::Snowflake),
        ] {
            let ladder = Ladder::build(&paths, &Tor::default(), mode, Ok(lyrebird.clone()));
            assert_eq!(ladder.rungs.len(), 1, "{mode:?}");
            assert_eq!(ladder.rungs[0].rung, rung);
            let policy = ladder.policy(rung);
            assert_eq!(policy.stall, None);
            assert_eq!(policy.cap, Duration::from_secs(180));
            assert!(!ladder.learns(), "{mode:?}");
        }
    }

    /// SLICE-A1 A1-1: private lines *replace* the built-ins of their transport
    /// (and only of their transport), and a line that is not a bridge line is
    /// named by its position, never by its content (A1-5).
    #[test]
    fn private_lines_replace_the_builtins_of_their_transport() {
        let (tmp, paths) = paths();
        let lyrebird = fake_lyrebird(tmp.path());
        let tor = Tor {
            bridge_lines: vec![
                PRIVATE_OBFS4.to_owned(),
                "meek_lite 192.0.2.20:80 url=https://example.invalid".to_owned(),
                "   ".to_owned(),
                "198.51.100.9:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413".to_owned(),
            ],
            ..Tor::default()
        };
        let ladder = Ladder::build(&paths, &tor, BridgeMode::Auto, Ok(lyrebird));
        let order: Vec<Rung> = ladder.rungs.iter().map(|t| t.rung).collect();
        assert_eq!(order, vec![Rung::Obfs4, Rung::Snowflake], "no direct probe");
        assert_eq!(ladder.rungs[0].bridges, vec![PRIVATE_OBFS4.to_owned()]);
        assert_eq!(ladder.rungs[1].bridges.len(), BUILTIN_SNOWFLAKE.len());
        assert_eq!(ladder.rejected_lines.len(), 2);
        for line in &ladder.rejected_lines {
            assert!(
                !line.contains("192.0.2.20") && !line.contains("198.51"),
                "{line}"
            );
        }
        assert!(ladder.rejected_lines[1].starts_with("bridge line 4:"));
    }

    /// SLICE-A1 A1-6: a line that does not parse costs only itself and is not
    /// quoted; if it was the only private line of its transport, that rung is
    /// skipped rather than silently falling back to the public built-ins.
    #[test]
    fn an_unparsable_private_line_is_dropped_without_quoting_it() {
        let (tmp, paths) = paths();
        let lyrebird = fake_lyrebird(tmp.path());
        let secretish = "obfs4 198.51.100.7:443 NOTAFINGERPRINT cert=SECRETCERT iat-mode=0";
        let tor = Tor {
            bridge_lines: vec![secretish.to_owned()],
            ..Tor::default()
        };
        let ladder = Ladder::build(&paths, &tor, BridgeMode::Auto, Ok(lyrebird));
        assert_eq!(ladder.rejected_lines.len(), 1);
        let msg = &ladder.rejected_lines[0];
        assert!(msg.contains("could not be parsed"), "{msg}");
        assert!(
            !msg.contains("SECRETCERT") && !msg.contains("198.51"),
            "{msg}"
        );
        let order: Vec<Rung> = ladder.rungs.iter().map(|t| t.rung).collect();
        assert_eq!(order, vec![Rung::Snowflake]);
        assert!(ladder.skipped.iter().any(|(r, _)| *r == Rung::Obfs4));
    }

    /// SLICE-A1 A1-3: a bundled binary runs only if it matches the pin, and is
    /// preferred over the developer override.
    #[test]
    fn a_bundled_lyrebird_runs_only_if_it_matches_the_pin() {
        let exe = tempfile::tempdir().unwrap();
        let dev = tempfile::tempdir().unwrap();
        let bundled = fake_lyrebird(exe.path());
        fake_lyrebird(dev.path());
        let pin = pin_of(&bundled);
        assert_eq!(
            find_lyrebird_in(None, Some(exe.path()), Some(dev.path()), Some(&pin)),
            Ok(bundled.clone())
        );
        let wrong = "0".repeat(64);
        let err = find_lyrebird_in(None, Some(exe.path()), None, Some(&wrong)).unwrap_err();
        assert!(err.contains("not the pinned lyrebird"), "{err}");
        let err = find_lyrebird_in(None, Some(exe.path()), None, None).unwrap_err();
        assert!(err.contains("pins no"), "{err}");
    }

    /// The final audit before the release: what `tornect install` copies is
    /// the running copy's own pinned lyrebird (beside it, or in its `pt/`
    /// folder), read from one handle: never the developers' folder, never
    /// one that is not the pin, never one others can write to, and none
    /// from a build that pins none.
    #[test]
    fn the_lyrebird_to_install_is_the_running_copys_pinned_one() {
        let exe = tempfile::tempdir().unwrap();
        let pt = exe.path().join("pt");
        std::fs::create_dir(&pt).unwrap();
        let bundled = fake_lyrebird(&pt);
        let pin = pin_of(&bundled);
        assert_eq!(
            bundled_lyrebird_in(Some(exe.path()), Some(&pin)),
            Ok((bundled.clone(), b"not really lyrebird".to_vec()))
        );
        let wrong = "0".repeat(64);
        let err = bundled_lyrebird_in(Some(exe.path()), Some(&wrong)).unwrap_err();
        assert!(err.contains("not the pinned lyrebird"), "{err}");
        let err = bundled_lyrebird_in(Some(exe.path()), None).unwrap_err();
        assert!(err.contains("pins no"), "{err}");
        // A developers' copy is not the running copy's: nothing to install.
        let bare = tempfile::tempdir().unwrap();
        let err = bundled_lyrebird_in(Some(bare.path()), Some(&pin)).unwrap_err();
        assert!(err.contains("not found"), "{err}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&bundled, std::fs::Permissions::from_mode(0o770)).unwrap();
            let err = bundled_lyrebird_in(Some(exe.path()), Some(&pin)).unwrap_err();
            assert!(err.contains("writable by other users"), "{err}");
        }
    }

    /// The security review of the final pass: a bundled candidate that fails
    /// its checks is passed over for the next, each checked the same way, by
    /// the bridges' lookup and by what `tornect install` carries alike: an
    /// installed copy's `~/.local/bin` may hold the user's own unpinned
    /// `lyrebird` beside the pinned `pt/lyrebird` its install wrote, which
    /// before was shadowed and every bridged rung refused. With no candidate
    /// passing, each reason is given.
    #[test]
    fn a_bundled_lyrebird_that_fails_is_passed_over_for_the_next() {
        let exe = tempfile::tempdir().unwrap();
        let pt = exe.path().join("pt");
        std::fs::create_dir(&pt).unwrap();
        let pinned = fake_lyrebird(&pt);
        let pin = pin_of(&pinned);
        let own = exe.path().join(LYREBIRD);
        std::fs::write(&own, b"the user's own build").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(
            find_lyrebird_in(None, Some(exe.path()), None, Some(&pin)),
            Ok(pinned.clone())
        );
        assert_eq!(
            bundled_lyrebird_in(Some(exe.path()), Some(&pin)),
            Ok((pinned.clone(), b"not really lyrebird".to_vec()))
        );
        let wrong = "0".repeat(64);
        for err in [
            find_lyrebird_in(None, Some(exe.path()), None, Some(&wrong)).unwrap_err(),
            bundled_lyrebird_in(Some(exe.path()), Some(&wrong)).unwrap_err(),
        ] {
            assert!(err.contains(&own.display().to_string()), "{err}");
            assert!(err.contains(&pinned.display().to_string()), "{err}");
        }
        // A build that pins none says so once, not once per candidate.
        let err = find_lyrebird_in(None, Some(exe.path()), None, None).unwrap_err();
        assert_eq!(err.matches("pins no").count(), 1, "{err}");
    }

    /// The security review of the final pass: what `tornect install` reads
    /// is opened once and checked on that handle, its size before anything
    /// is read (before, the whole file was hashed by path first, with no
    /// cap), and a FIFO at the name is opened without waiting and passed
    /// over, never waited on.
    #[cfg(unix)]
    #[test]
    fn the_lyrebird_to_install_is_size_checked_before_it_is_read_and_never_waited_on() {
        use rustix::fs::{CWD, FileType, Mode};
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::mpsc;
        fn in_time<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || tx.send(f()));
            rx.recv_timeout(Duration::from_secs(10))
                .expect("it waited on a FIFO")
        }
        let exe = tempfile::tempdir().unwrap();
        let huge = exe.path().join(LYREBIRD);
        let file = std::fs::File::create(&huge).unwrap();
        file.set_len(LYREBIRD_MAX + 1).unwrap();
        drop(file);
        std::fs::set_permissions(&huge, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pin = "0".repeat(64);
        let err = bundled_lyrebird_in(Some(exe.path()), Some(&pin)).unwrap_err();
        assert!(err.contains("larger than 64 MiB"), "{err}");

        std::fs::remove_file(&huge).unwrap();
        rustix::fs::mknodat(CWD, &huge, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
        let dir = exe.path().to_path_buf();
        let err =
            in_time(move || bundled_lyrebird_in(Some(&dir), Some(&"0".repeat(64)))).unwrap_err();
        assert!(err.contains("is not a regular file"), "{err}");
        let pt = exe.path().join("pt");
        std::fs::create_dir(&pt).unwrap();
        let pinned = fake_lyrebird(&pt);
        let pin = pin_of(&pinned);
        let dir = exe.path().to_path_buf();
        assert_eq!(
            in_time(move || bundled_lyrebird_in(Some(&dir), Some(&pin))),
            Ok((pinned, b"not really lyrebird".to_vec()))
        );
    }

    /// SLICE-A1 A1-4: relative candidates are never used — they would resolve
    /// against whatever directory Tornect was started from.
    #[test]
    fn relative_lyrebird_paths_are_never_used() {
        let err = find_lyrebird_in(Some(Path::new("lyrebird")), None, None, None).unwrap_err();
        assert!(err.contains("absolute"), "{err}");
        let err = find_lyrebird_in(None, None, Some(Path::new("relative/dir")), None).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    /// SLICE-A1 A1-3: a binary other users can modify is refused.
    #[cfg(unix)]
    #[test]
    fn a_lyrebird_writable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let exe = tempfile::tempdir().unwrap();
        let bundled = fake_lyrebird(exe.path());
        let pin = pin_of(&bundled);
        std::fs::set_permissions(&bundled, std::fs::Permissions::from_mode(0o775)).unwrap();
        let err = find_lyrebird_in(None, Some(exe.path()), None, Some(&pin)).unwrap_err();
        assert!(err.contains("writable by other users"), "{err}");
    }

    /// An explicit `tor.pt_path` is used alone, and may run a build this
    /// binary does not pin (the owner chose it; the mismatch is logged).
    #[test]
    fn explicit_pt_path_is_used_alone_and_may_be_unpinned() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tempfile::tempdir().unwrap();
        let present = fake_lyrebird(tmp.path());
        let bundled = fake_lyrebird(exe.path());
        let wrong = "0".repeat(64);
        assert_eq!(
            find_lyrebird_in(Some(&present), Some(exe.path()), None, Some(&wrong)),
            Ok(present.clone())
        );
        assert_ne!(present, bundled);
        let missing = tmp.path().join("nope").join(LYREBIRD);
        assert!(find_lyrebird_in(Some(&missing), Some(exe.path()), None, None).is_err());
    }

    #[test]
    fn rung_names_round_trip() {
        for rung in Rung::ALL {
            assert_eq!(rung.as_str().parse::<Rung>().unwrap(), rung);
        }
        assert!("meek".parse::<Rung>().is_err());
    }

    #[test]
    fn transports_apply_to_an_arti_config() {
        let tmp = tempfile::tempdir().unwrap();
        let lyrebird = fake_lyrebird(tmp.path());
        for rung in Rung::ALL {
            let mut builder = TorClientConfigBuilder::from_directories(
                tmp.path().join("s"),
                tmp.path().join("c"),
            );
            let transport = match rung {
                Rung::Direct => Transport::direct(),
                Rung::Obfs4 => Transport {
                    rung,
                    bridges: BUILTIN_OBFS4.iter().map(|l| (*l).to_owned()).collect(),
                    lyrebird: Some(lyrebird.clone()),
                },
                Rung::Snowflake => Transport {
                    rung,
                    bridges: BUILTIN_SNOWFLAKE.iter().map(|l| (*l).to_owned()).collect(),
                    lyrebird: Some(lyrebird.clone()),
                },
            };
            transport.apply(&mut builder).unwrap();
            builder.build().unwrap_or_else(|e| panic!("{rung}: {e}"));
        }
        // A bridged rung without the binary is a config error, not a silent direct fallback.
        let mut builder =
            TorClientConfigBuilder::from_directories(tmp.path().join("s"), tmp.path().join("c"));
        let err = Transport {
            rung: Rung::Obfs4,
            bridges: vec![BUILTIN_OBFS4[0].to_owned()],
            lyrebird: None,
        }
        .apply(&mut builder)
        .unwrap_err();
        assert!(matches!(err, SignalError::Config(_)), "{err}");
    }

    /// The settings page's check is the builder's: the numbers it gives are
    /// exactly the lines the ladder leaves out, by position (a transport
    /// `lyrebird` does not serve, a line that does not parse), blank lines
    /// never among them.
    #[test]
    fn rejected_lines_agrees_with_the_builder() {
        let (tmp, paths) = paths();
        let lyrebird = fake_lyrebird(tmp.path());
        let lines = vec![
            PRIVATE_OBFS4.to_owned(),
            "meek_lite 192.0.2.20:80 url=https://example.invalid".to_owned(),
            "   ".to_owned(),
            "obfs4 198.51.100.7:443 NOTAFINGERPRINT cert=SECRETCERT iat-mode=0".to_owned(),
            "198.51.100.9:443 4352E58420E68F5E40BF7C74FADDCCD9D1349413".to_owned(),
            BUILTIN_SNOWFLAKE[0].to_owned(),
        ];
        let tor = Tor {
            bridge_lines: lines.clone(),
            ..Tor::default()
        };
        let ladder = Ladder::build(&paths, &tor, BridgeMode::Auto, Ok(lyrebird));
        let built: Vec<usize> = ladder
            .rejected_lines
            .iter()
            .map(|message| {
                let rest = message.strip_prefix("bridge line ").expect(message);
                let digits = rest.split(|c: char| !c.is_ascii_digit()).next().unwrap();
                digits.parse().unwrap()
            })
            .collect();
        assert_eq!(built, [2, 4, 5]);
        assert_eq!(Ladder::rejected_lines(&lines), built);
        assert!(Ladder::rejected_lines(&[]).is_empty());
        assert!(Ladder::rejected_lines(&["  ".to_owned()]).is_empty());
    }
}
