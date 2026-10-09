//! The window's diagnostics report (Settings, About): what `tornect doctor`
//! says of this computer's setup, without anything that identifies it, its
//! user or its peers. [`gather`] keeps only facts that name nobody (no ID, no
//! device name, no path, no onion address, no label, no host or account
//! name: it is given neither of the last two, and it keeps no path of the
//! home it reads); [`report`] writes them as lines. `tornect doctor` stays as
//! it is.

use tornect_core::keystore::{FileSecretStore, KeystoreKind, SecretStore};
use tornect_core::session_log::SessionLog;
use tornect_core::{Config, Paths, keystore};

/// What the report says: words from fixed lists, yes or no, and numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// This build's version.
    pub version: &'static str,
    /// The signalling protocol it speaks.
    pub protocol: u8,
    /// The operating system and the processor architecture.
    pub system: (&'static str, &'static str),
    /// On Linux, the desktop session's type and the desktops it names, each
    /// from a fixed list ("other" for anything else).
    pub session: Option<(&'static str, Vec<&'static str>)>,
    /// How a shared session would capture this screen.
    pub capture: &'static str,
    /// How the Tor client reaches the network.
    pub bridges: &'static str,
    /// The way into the Tor network that worked last ("none" before one did).
    pub worked_last: &'static str,
    /// The pluggable-transport program for obfs4 and Snowflake was found.
    pub lyrebird: bool,
    /// The host identity (this computer's ID) exists.
    pub host_identity: bool,
    /// The device identity exists.
    pub device_identity: bool,
    /// What holds the identities' secrets.
    pub keystore: &'static str,
    /// How many lines the session log holds; `None`: it could not be read.
    pub log_lines: Option<usize>,
}

/// The session types the report names.
const SESSION_TYPES: [&str; 4] = ["wayland", "x11", "tty", "mir"];

/// The desktops the report names.
const DESKTOPS: [&str; 16] = [
    "GNOME", "KDE", "XFCE", "LXQt", "LXDE", "MATE", "Cinnamon", "Budgie", "Pantheon", "Unity",
    "Deepin", "COSMIC", "sway", "Hyprland", "i3", "ubuntu",
];

/// `value` as `list` spells it, if it is one of them; else "other".
fn known(value: &str, list: &[&'static str]) -> &'static str {
    list.iter()
        .find(|k| k.eq_ignore_ascii_case(value))
        .copied()
        .unwrap_or("other")
}

/// Read the facts of the Tornect home `paths` under configuration `cfg`.
#[must_use]
pub fn gather(paths: &Paths, cfg: &Config) -> Facts {
    let session = cfg!(target_os = "linux").then(|| {
        let kind = std::env::var("XDG_SESSION_TYPE").unwrap_or_default();
        let desktops = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        (
            known(&kind, &SESSION_TYPES),
            desktops
                .split(':')
                .filter(|d| !d.is_empty())
                .map(|d| known(d, &DESKTOPS))
                .collect(),
        )
    });
    let capture = match tornect_session::DesktopBackend::detect() {
        tornect_session::DesktopBackend::Wayland => "the desktop portal and PipeWire",
        tornect_session::DesktopBackend::X11 => "X11",
        tornect_session::DesktopBackend::Gdi => "GDI",
        tornect_session::DesktopBackend::Unavailable(_) => "unavailable",
    };
    let bridges = match cfg.tor.bridges {
        tornect_core::config::BridgeMode::Auto => "automatic",
        tornect_core::config::BridgeMode::Off => "direct only",
        tornect_core::config::BridgeMode::Obfs4 => "obfs4",
        tornect_core::config::BridgeMode::Snowflake => "Snowflake",
    };
    // Opened only where it is: reading the facts creates nothing.
    let store = paths
        .keys_dir()
        .is_dir()
        .then(|| FileSecretStore::open(paths.keys_dir()).ok())
        .flatten();
    let has = |name: &str| {
        store
            .as_ref()
            .is_some_and(|s| s.contains(name).unwrap_or(false))
    };
    Facts {
        version: tornect_core::VERSION,
        protocol: tornect_core::PROTOCOL_VERSION,
        system: (std::env::consts::OS, std::env::consts::ARCH),
        session,
        capture,
        bridges,
        worked_last: tornect_signal::tor::last_good(paths).map_or("none", |r| r.as_str()),
        lyrebird: tornect_signal::tor::find_lyrebird(cfg.tor.pt_path.as_deref()).is_ok(),
        host_identity: has(keystore::HOST_IDENTITY_SEED),
        device_identity: has(keystore::DEVICE_IDENTITY_SEED),
        keystore: match store.as_ref().map(SecretStore::kind) {
            Some(KeystoreKind::File) => "a file store",
            Some(KeystoreKind::OsKeychain) => "the system keychain",
            None => "none",
        },
        log_lines: SessionLog::new(paths.sessions_log())
            .read_all()
            .ok()
            .map(|lines| lines.len()),
    }
}

/// The report: one line a fact.
#[must_use]
pub fn report(facts: &Facts) -> String {
    let yes = |present: bool| if present { "present" } else { "absent" };
    let mut lines = vec![
        format!("Tornect {}, protocol {}", facts.version, facts.protocol),
        format!("System: {} {}", facts.system.0, facts.system.1),
    ];
    if let Some((kind, desktops)) = &facts.session {
        let desktops = if desktops.is_empty() {
            "none named".to_owned()
        } else {
            desktops.join(", ")
        };
        lines.push(format!("Desktop session: {kind}; desktop: {desktops}"));
    }
    lines.extend([
        format!("Screen capture: {}", facts.capture),
        format!("Tor bridges: {}", facts.bridges),
        format!("Worked last: {}", facts.worked_last),
        format!(
            "lyrebird: {}",
            if facts.lyrebird { "found" } else { "not found" }
        ),
        format!("Host identity: {}", yes(facts.host_identity)),
        format!("Device identity: {}", yes(facts.device_identity)),
        format!("Keys kept in: {}", facts.keystore),
        match facts.log_lines {
            Some(n) => format!("Session log: {n} lines"),
            None => "Session log: unreadable".to_owned(),
        },
    ]);
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use tornect_core::DeviceId;
    use tornect_core::keystore::{load_or_create_device_identity, load_or_create_host_identity};
    use tornect_core::session_log::{SessionEvent, SessionRecord};
    use tornect_signal::HostSigner;

    use super::*;

    /// The window's diagnostics report names nobody (§B.6.1's privacy rule,
    /// the redesign's decision 4): from a home whose path holds an account
    /// name, with identities, a chosen device name, a lyrebird path and a
    /// session log line naming a peer, the report holds none of them: no ID
    /// or onion address, no device key, no name, no label, no path. It is
    /// given no host name and no account name ([`gather`] takes the home and
    /// the configuration only), and it asks the system for neither.
    #[test]
    fn the_diagnostics_hold_no_id_name_path_onion_or_label() {
        let _: fn(&Paths, &Config) -> Facts = gather;
        let tmp = tempfile::tempdir().unwrap();
        let account = "quillmere-account-5521";
        let home = tmp.path().join(account).join("tornect-home");
        let paths = Paths::from_home(&home);
        paths.ensure().unwrap();
        let store = FileSecretStore::open(paths.keys_dir()).unwrap();
        let (host, _) = load_or_create_host_identity(&store).unwrap();
        let (device, _) = load_or_create_device_identity(&store).unwrap();
        let onion = host.id().to_string();
        let device_key = DeviceId::from_bytes(HostSigner::public_key(&device)).to_string();
        let mut cfg = Config::default();
        cfg.general.device_name = "Brightwater studio 7731".to_owned();
        cfg.tor.pt_path = Some(home.join("pt").join("lyrebird-quillmere"));
        cfg.save(&paths.config_file()).unwrap();
        let peer = DeviceId::from_bytes([0x5a; 32]);
        SessionLog::new(paths.sessions_log())
            .append(&SessionRecord::now(SessionEvent::PairAccepted).peer(peer, "Laptop of Wren"))
            .unwrap();

        let facts = gather(&paths, &cfg);
        assert!(facts.host_identity && facts.device_identity);
        assert_eq!(facts.log_lines, Some(1));
        assert_eq!(facts.keystore, "a file store");
        let text = report(&facts);
        let home_text = home.display().to_string();
        let peer_text = peer.to_string();
        for named in [
            account,
            home_text.as_str(),
            onion.as_str(),
            &onion[..16],
            device_key.as_str(),
            &device_key[..16],
            peer_text.as_str(),
            "Brightwater",
            "Laptop of Wren",
            "quillmere",
            ".onion",
        ] {
            assert!(!text.contains(named), "{named} in {text}");
        }
        for path in ['/', '\\', '~'] {
            assert!(!text.contains(path), "{path} in {text}");
        }
        let source = include_str!("diagnostics.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        for asked in [
            "hostname",
            "host_name",
            "\"USER",
            "USERNAME",
            "COMPUTERNAME",
            "HOME",
        ] {
            assert!(!code.contains(asked), "the report's code reads {asked}");
        }
    }
}
