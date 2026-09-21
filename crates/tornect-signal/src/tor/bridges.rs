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

/// Tor Browser's built-in obfs4 bridges, verbatim from tor-browser-build
/// `projects/tor-expert-bundle/pt_config.json` at tag `tbb-15.0.23-build1`
/// (Tor Browser 15.0.23), cross-checked byte for byte against the
/// `pt_config.json` inside the GPG-verified tor-expert-bundle 15.0.23.
/// They are public, so censors can list them; private bridges go in
/// `tor.bridge_lines` and are tried first.
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
            let bridge: BridgeConfigBuilder = line
                .parse()
                .map_err(|e| SignalError::Config(format!("bad bridge line: {e}")))?;
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

    /// As [`Ladder::from_config`] with `mode` instead of `tor.bridges`
    /// (the CLI's `--bridges` override).
    #[must_use]
    pub fn with_mode(paths: &Paths, tor: &Tor, mode: BridgeMode) -> Self {
        Self::build(paths, tor, mode, find_lyrebird(tor.pt_path.as_deref()))
    }

    fn build(paths: &Paths, tor: &Tor, mode: BridgeMode, lyrebird: Option<PathBuf>) -> Self {
        let mut rejected_lines = Vec::new();
        let mut user_obfs4 = Vec::new();
        let mut user_snowflake = Vec::new();
        for line in tor
            .bridge_lines
            .iter()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
        {
            match transport_of(line) {
                Some("snowflake") => user_snowflake.push(line.to_owned()),
                Some(_) => user_obfs4.push(line.to_owned()),
                None => rejected_lines.push(format!(
                    "{}: not an obfs4, webtunnel or snowflake bridge line",
                    redact_line(line)
                )),
            }
        }
        let order: Vec<Rung> = match mode {
            BridgeMode::Off => vec![Rung::Direct],
            BridgeMode::Obfs4 => vec![Rung::Obfs4],
            BridgeMode::Snowflake => vec![Rung::Snowflake],
            BridgeMode::Auto => {
                let mut order = Rung::ALL.to_vec();
                if let Some(last) = last_good(paths) {
                    order.retain(|r| *r != last);
                    order.insert(0, last);
                }
                order
            }
        };
        let mut rungs = Vec::new();
        let mut skipped = Vec::new();
        for rung in order {
            if rung.needs_pt() && lyrebird.is_none() {
                skipped.push((
                    rung,
                    format!(
                        "`{LYREBIRD}` not found (set tor.pt_path or {PT_DIR_ENV}, or put it \
                         next to the tornect executable)"
                    ),
                ));
                continue;
            }
            let bridges = match rung {
                Rung::Direct => Vec::new(),
                Rung::Obfs4 => user_obfs4
                    .iter()
                    .cloned()
                    .chain(BUILTIN_OBFS4.iter().map(|l| (*l).to_owned()))
                    .collect(),
                Rung::Snowflake => user_snowflake
                    .iter()
                    .cloned()
                    .chain(BUILTIN_SNOWFLAKE.iter().map(|l| (*l).to_owned()))
                    .collect(),
            };
            rungs.push(Transport {
                rung,
                bridges,
                lyrebird: if rung.needs_pt() {
                    lyrebird.clone()
                } else {
                    None
                },
            });
        }
        Self {
            rungs,
            skipped,
            rejected_lines,
            single_rung_timeout: Duration::from_secs(u64::from(tor.bootstrap_timeout_secs)),
        }
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

/// Keep a user's private bridge address out of logs and error strings: a
/// private bridge is only useful while the censor does not know it.
fn redact_line(line: &str) -> String {
    let first = line.split_whitespace().next().unwrap_or("");
    let first: String = first.chars().take(16).collect();
    format!("{first:?} line")
}

/// Find the `lyrebird` binary: `explicit` if given (and nothing else), else
/// `$TORNECT_PT_DIR`, then next to the executable or in its `pt/` directory,
/// then `PATH`.
#[must_use]
pub fn find_lyrebird(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return path.is_file().then(|| path.to_path_buf());
    }
    let mut candidates = Vec::new();
    if let Some(dir) = std::env::var_os(PT_DIR_ENV).filter(|d| !d.is_empty()) {
        candidates.push(PathBuf::from(dir).join(LYREBIRD));
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    {
        candidates.push(dir.join(LYREBIRD));
        candidates.push(dir.join("pt").join(LYREBIRD));
    }
    if let Some(found) = candidates.into_iter().find(|p| p.is_file()) {
        return Some(found);
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(LYREBIRD))
            .find(|p| p.is_file())
    })
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

    fn fake_lyrebird(dir: &Path) -> PathBuf {
        let path = dir.join(LYREBIRD);
        std::fs::write(&path, b"").unwrap();
        path
    }

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
        let ladder = Ladder::build(&paths, &Tor::default(), BridgeMode::Auto, Some(lyrebird));
        let order: Vec<Rung> = ladder.rungs.iter().map(|t| t.rung).collect();
        assert_eq!(order, vec![Rung::Direct, Rung::Obfs4, Rung::Snowflake]);
        assert!(ladder.skipped.is_empty());
        assert_eq!(ladder.rungs[1].bridges.len(), BUILTIN_OBFS4.len());
        assert_eq!(ladder.rungs[2].bridges.len(), BUILTIN_SNOWFLAKE.len());
        // A multi-rung ladder uses the per-rung policy, stall timer included.
        assert_eq!(ladder.policy(Rung::Direct), Rung::Direct.policy());
    }

    #[test]
    fn the_last_rung_that_worked_goes_first() {
        let (tmp, paths) = paths();
        let lyrebird = fake_lyrebird(tmp.path());
        remember(&paths, Rung::Snowflake);
        assert_eq!(last_good(&paths), Some(Rung::Snowflake));
        let ladder = Ladder::build(&paths, &Tor::default(), BridgeMode::Auto, Some(lyrebird));
        let order: Vec<Rung> = ladder.rungs.iter().map(|t| t.rung).collect();
        assert_eq!(order, vec![Rung::Snowflake, Rung::Direct, Rung::Obfs4]);
    }

    #[test]
    fn without_lyrebird_only_direct_remains_and_the_gap_is_reported() {
        let (_tmp, paths) = paths();
        let ladder = Ladder::build(&paths, &Tor::default(), BridgeMode::Auto, None);
        assert_eq!(ladder.rungs.len(), 1);
        assert_eq!(ladder.rungs[0].rung, Rung::Direct);
        let skipped: Vec<Rung> = ladder.skipped.iter().map(|(r, _)| *r).collect();
        assert_eq!(skipped, vec![Rung::Obfs4, Rung::Snowflake]);
        // One rung left: nowhere to fall back to, so no stall cut-off.
        assert_eq!(ladder.policy(Rung::Direct).stall, None);
    }

    #[test]
    fn forced_modes_have_one_rung() {
        let (tmp, paths) = paths();
        let lyrebird = fake_lyrebird(tmp.path());
        for (mode, rung) in [
            (BridgeMode::Off, Rung::Direct),
            (BridgeMode::Obfs4, Rung::Obfs4),
            (BridgeMode::Snowflake, Rung::Snowflake),
        ] {
            let ladder = Ladder::build(&paths, &Tor::default(), mode, Some(lyrebird.clone()));
            assert_eq!(ladder.rungs.len(), 1, "{mode:?}");
            assert_eq!(ladder.rungs[0].rung, rung);
            let policy = ladder.policy(rung);
            assert_eq!(policy.stall, None);
            assert_eq!(policy.cap, Duration::from_secs(180));
        }
    }

    #[test]
    fn user_lines_go_first_on_their_rung_and_junk_is_rejected_without_leaking_it() {
        let (tmp, paths) = paths();
        let lyrebird = fake_lyrebird(tmp.path());
        let private =
            "obfs4 198.51.100.7:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0";
        let tor = Tor {
            bridge_lines: vec![
                private.to_owned(),
                "Bridge snowflake 192.0.2.9:80 0123456789ABCDEF0123456789ABCDEF01234567".to_owned(),
                "meek_lite 192.0.2.20:80 url=https://example.invalid".to_owned(),
                "   ".to_owned(),
            ],
            ..Tor::default()
        };
        let ladder = Ladder::build(&paths, &tor, BridgeMode::Auto, Some(lyrebird));
        assert_eq!(ladder.rungs[1].bridges[0], private);
        assert_eq!(ladder.rungs[1].bridges.len(), BUILTIN_OBFS4.len() + 1);
        assert!(ladder.rungs[2].bridges[0].starts_with("Bridge snowflake"));
        assert_eq!(ladder.rejected_lines.len(), 1);
        assert!(!ladder.rejected_lines[0].contains("192.0.2.20"));
    }

    #[test]
    fn explicit_pt_path_is_used_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let present = fake_lyrebird(tmp.path());
        assert_eq!(find_lyrebird(Some(&present)), Some(present.clone()));
        let missing = tmp.path().join("nope").join(LYREBIRD);
        assert_eq!(find_lyrebird(Some(&missing)), None);
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
}
