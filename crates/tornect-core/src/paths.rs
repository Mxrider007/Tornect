//! Where Tornect keeps its files (`docs/PLAN.md` §A.3 D13).
//!
//! | OS | config | state (keys, Arti state, pairings, unattended store) | cache | logs |
//! |---|---|---|---|---|
//! | Linux/BSD | `~/.config/tornect` | `~/.local/share/tornect` | `~/.cache/tornect` | `~/.local/share/tornect/logs` |
//! | macOS | `~/Library/Application Support/Tornect` | same | `~/Library/Caches/Tornect` | `~/Library/Logs/Tornect` |
//! | Windows | `%APPDATA%\Tornect` | `%LOCALAPPDATA%\Tornect` | `%LOCALAPPDATA%\Tornect\cache` | `%LOCALAPPDATA%\Tornect\logs` |
//!
//! Setting `TORNECT_HOME=<dir>` puts everything under one directory, which is how
//! tests and side-by-side host/client instances on one machine stay isolated.

use std::path::{Path, PathBuf};

use directories::{BaseDirs, UserDirs};

use crate::error::{CoreError, Result};
use crate::files;
use crate::keystore::create_private_dir;

/// Environment variable that overrides every directory with one root.
pub const HOME_ENV: &str = "TORNECT_HOME";

/// Where the stream window saves its screenshots: `Tornect` in the
/// platform's Pictures folder (Linux `XDG_PICTURES_DIR`, macOS
/// `~/Pictures`, Windows `FOLDERID_Pictures`); `None` when the platform names
/// none. `TORNECT_HOME` does not move it: a screenshot is the user's file,
/// not Tornect's state.
#[must_use]
pub fn pictures_dir() -> Option<PathBuf> {
    let user = UserDirs::new()?;
    Some(user.picture_dir()?.join("Tornect"))
}

/// Resolved directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// Configuration (`config.toml`).
    pub config_dir: PathBuf,
    /// Persistent state: keystore, Arti state, trusted devices, the unattended store.
    pub state_dir: PathBuf,
    /// Disposable cache (Tor directory cache).
    pub cache_dir: PathBuf,
    /// Log files, including `sessions.log`.
    pub log_dir: PathBuf,
}

impl Paths {
    /// Resolve directories from `TORNECT_HOME` or the platform conventions.
    pub fn discover() -> Result<Self> {
        match std::env::var_os(HOME_ENV) {
            Some(root) if !root.is_empty() => Ok(Self::from_home(PathBuf::from(root))),
            _ => Self::platform(),
        }
    }

    /// Put everything under `root`.
    #[must_use]
    pub fn from_home(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            config_dir: root.clone(),
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            log_dir: root.join("logs"),
        }
    }

    /// Platform-conventional directories for the current user.
    pub fn platform() -> Result<Self> {
        let base = BaseDirs::new().ok_or(CoreError::NoHomeDir)?;
        Ok(Self::from_base_dirs(&base))
    }

    #[cfg(target_os = "macos")]
    fn from_base_dirs(base: &BaseDirs) -> Self {
        let support = base.config_dir().join("Tornect");
        Self {
            config_dir: support.clone(),
            state_dir: support,
            cache_dir: base.cache_dir().join("Tornect"),
            log_dir: base.home_dir().join("Library").join("Logs").join("Tornect"),
        }
    }

    #[cfg(windows)]
    fn from_base_dirs(base: &BaseDirs) -> Self {
        let local = base.data_local_dir().join("Tornect");
        Self {
            config_dir: base.config_dir().join("Tornect"),
            state_dir: local.clone(),
            cache_dir: local.join("cache"),
            log_dir: local.join("logs"),
        }
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    fn from_base_dirs(base: &BaseDirs) -> Self {
        let state = base.data_local_dir().join("tornect");
        Self {
            config_dir: base.config_dir().join("tornect"),
            state_dir: state.clone(),
            cache_dir: base.cache_dir().join("tornect"),
            log_dir: state.join("logs"),
        }
    }

    /// `config.toml`.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// Directory of the file keystore.
    #[must_use]
    pub fn keys_dir(&self) -> PathBuf {
        self.state_dir.join("keys")
    }

    /// Arti persistent state (onion service keys, guard state).
    #[must_use]
    pub fn arti_state_dir(&self) -> PathBuf {
        self.state_dir.join("arti")
    }

    /// Arti directory cache.
    #[must_use]
    pub fn arti_cache_dir(&self) -> PathBuf {
        self.cache_dir.join("arti")
    }

    /// The Tor transport that last bootstrapped (`direct`, `obfs4` or
    /// `snowflake`), tried first on the next start (decision M1-38).
    #[must_use]
    pub fn tor_transport_file(&self) -> PathBuf {
        self.state_dir.join("tor-transport")
    }

    /// SAS-paired devices — pairings only (`docs/PLAN.md` §B.6, §B.8.9). Unattended
    /// grants live in the encrypted store ([`Paths::unattended_store`]), never here.
    #[must_use]
    pub fn trusted_devices_file(&self) -> PathBuf {
        self.state_dir.join("trusted-devices.toml")
    }

    /// The encrypted unattended store `unattended.bin` (`docs/PLAN.md` §B.8.9).
    #[must_use]
    pub fn unattended_store(&self) -> PathBuf {
        self.state_dir.join("unattended.bin")
    }

    /// Advisory lock taken by whoever writes the unattended store — the running host
    /// or the offline CLI, never both (`docs/PLAN.md` §B.8.6.2, §B.8.7.4).
    #[must_use]
    pub fn unattended_lock(&self) -> PathBuf {
        self.state_dir.join("unattended.lock")
    }

    /// Held by a running `tornect host` for its whole life, so every other
    /// command can tell that a host is alive here, including one with no control
    /// channel to answer it (Windows until M6, or a failed bind).
    #[must_use]
    pub fn host_lock(&self) -> PathBuf {
        self.state_dir.join("host.lock")
    }

    /// Client-side per-host records `hosts.toml` (`docs/PLAN.md` §B.8.9: `remember`,
    /// `server_s_pk_pin`, `suite`, `ua_worked_before`).
    #[must_use]
    pub fn hosts_file(&self) -> PathBuf {
        self.state_dir.join("hosts.toml")
    }

    /// The restore token of the Wayland screen-sharing portal (RemoteDesktop,
    /// persisted "until revoked"). With it, a later session shares the screen
    /// and takes input without the desktop asking again, so it is a 0600 file
    /// here and never logged; deleting it makes the desktop ask again.
    ///
    /// This is the token of the request without the portal clipboard, the
    /// request every host makes while `[services] wayland_clipboard` is off
    /// (the default); [`Paths::portal_restore_token_for`] picks the file for
    /// either request.
    #[must_use]
    pub fn portal_restore_token(&self) -> PathBuf {
        self.state_dir.join("portal-restore-token")
    }

    /// The restore token of the portal request this host makes: with the
    /// clipboard (`[services] wayland_clipboard` on; design `services` §4.2)
    /// a token of its own, `portal-restore-token-2`, because a token made
    /// without `RequestClipboard` does not cover a request with it; without
    /// it, [`Paths::portal_restore_token`] unchanged. One file per request,
    /// so a token is only ever restored for the request that made it.
    #[must_use]
    pub fn portal_restore_token_for(&self, clipboard: bool) -> PathBuf {
        if clipboard {
            self.state_dir.join("portal-restore-token-2")
        } else {
            self.portal_restore_token()
        }
    }

    /// The restore token files of both portal requests, the one without the
    /// clipboard first: what revoking the desktop's grant deletes, whichever
    /// request runs now, so that turning `[services] wayland_clipboard` on
    /// (or off) again later never restores a grant the user revoked.
    #[must_use]
    pub fn portal_restore_tokens(&self) -> [PathBuf; 2] {
        [
            self.portal_restore_token_for(false),
            self.portal_restore_token_for(true),
        ]
    }

    /// Restore tokens the request this host makes never restores, deleted at
    /// host start so no unused grant stays on disk: with the clipboard, the
    /// token of the request without it; without the clipboard, none, so a
    /// host with the switch off keeps and uses its token as before.
    #[must_use]
    pub fn retired_portal_tokens(&self, clipboard: bool) -> Vec<PathBuf> {
        if clipboard {
            vec![self.portal_restore_token()]
        } else {
            Vec::new()
        }
    }

    /// Append-only local audit log of session events.
    #[must_use]
    pub fn sessions_log(&self) -> PathBuf {
        self.log_dir.join("sessions.log")
    }

    /// Create every directory with private permissions, and mark each of
    /// the four as Tornect's own with [`files::PRIVATE_MARKER`] (an empty
    /// `0600` file, written once and then left as it is), so a host never
    /// lists or serves any Tornect home, another `TORNECT_HOME` included
    /// (design `services` §5.2).
    pub fn ensure(&self) -> Result<()> {
        for dir in [
            &self.config_dir,
            &self.state_dir,
            &self.cache_dir,
            &self.log_dir,
        ] {
            create_private_dir(dir)?;
            files::mark_private(dir)?;
        }
        create_private_dir(&self.keys_dir())?;
        Ok(())
    }

    /// All four directories, for reporting.
    #[must_use]
    pub fn all(&self) -> [(&'static str, &Path); 4] {
        [
            ("config", &self.config_dir),
            ("state", &self.state_dir),
            ("cache", &self.cache_dir),
            ("logs", &self.log_dir),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_override_nests_everything() {
        let p = Paths::from_home("/tmp/tornect-test");
        assert_eq!(
            p.config_file(),
            PathBuf::from("/tmp/tornect-test/config.toml")
        );
        assert_eq!(p.keys_dir(), PathBuf::from("/tmp/tornect-test/state/keys"));
        assert_eq!(
            p.unattended_store(),
            PathBuf::from("/tmp/tornect-test/state/unattended.bin")
        );
        assert_eq!(
            p.unattended_lock(),
            PathBuf::from("/tmp/tornect-test/state/unattended.lock")
        );
        assert_eq!(
            p.host_lock(),
            PathBuf::from("/tmp/tornect-test/state/host.lock")
        );
        assert_eq!(
            p.hosts_file(),
            PathBuf::from("/tmp/tornect-test/state/hosts.toml")
        );
        assert_eq!(
            p.sessions_log(),
            PathBuf::from("/tmp/tornect-test/logs/sessions.log")
        );
        assert_eq!(
            p.portal_restore_token(),
            PathBuf::from("/tmp/tornect-test/state/portal-restore-token")
        );
        assert_eq!(
            p.portal_restore_token_for(true),
            PathBuf::from("/tmp/tornect-test/state/portal-restore-token-2")
        );
        assert_eq!(
            p.arti_cache_dir(),
            PathBuf::from("/tmp/tornect-test/cache/arti")
        );
    }

    /// With `[services] wayland_clipboard` off (the default) the restore
    /// token is the file and path it always was, and nothing is retired;
    /// with it on, the request with the clipboard has its own file and
    /// retires the old one, never its own.
    #[test]
    fn the_restore_token_is_unchanged_while_the_clipboard_switch_is_off() {
        let p = Paths::from_home("/tmp/tornect-test");
        let today = PathBuf::from("/tmp/tornect-test/state/portal-restore-token");
        assert_eq!(p.portal_restore_token(), today);
        assert_eq!(p.portal_restore_token_for(false), today);
        assert!(p.retired_portal_tokens(false).is_empty());
        let with_clipboard = p.portal_restore_token_for(true);
        assert_ne!(with_clipboard, today);
        assert_eq!(with_clipboard.parent(), today.parent());
        assert_eq!(
            p.portal_restore_tokens(),
            [today.clone(), with_clipboard.clone()]
        );
        assert_eq!(p.retired_portal_tokens(true), [today]);
        assert!(!p.retired_portal_tokens(true).contains(&with_clipboard));
    }

    #[test]
    fn platform_paths_end_with_app_name() {
        if let Ok(p) = Paths::platform() {
            for (_, dir) in p.all() {
                let s = dir.to_string_lossy().to_ascii_lowercase();
                assert!(s.contains("tornect"), "{s}");
            }
        }
    }

    #[test]
    fn ensure_creates_private_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let p = Paths::from_home(tmp.path().join("home"));
        p.ensure().unwrap();
        assert!(p.keys_dir().is_dir());
        assert!(p.log_dir.is_dir());
        for (_, dir) in p.all() {
            let marker = dir.join(files::PRIVATE_MARKER);
            assert_eq!(std::fs::read(&marker).unwrap(), b"", "{}", marker.display());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(&marker).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600);
            }
        }
        assert!(!p.keys_dir().join(files::PRIVATE_MARKER).exists());
        // Every start: a marker already there is left as it is.
        let marker = p.state_dir.join(files::PRIVATE_MARKER);
        let at = std::fs::metadata(&marker).unwrap().modified().unwrap();
        p.ensure().unwrap();
        assert_eq!(std::fs::metadata(&marker).unwrap().modified().unwrap(), at);
        std::fs::remove_file(&marker).unwrap();
        p.ensure().unwrap();
        assert!(marker.is_file(), "written again at the next start");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&p.state_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
    }
}
