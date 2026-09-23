//! Error type shared by the core crate.

use std::path::PathBuf;

/// Errors produced by `tornect-core`.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// A Tornect ID or device ID failed to parse or validate.
    #[error("invalid identifier: {0}")]
    Id(#[from] crate::id::IdError),

    /// Filesystem failure; `fs_err` already embeds the path in the message.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The configuration file exists but is not valid TOML for [`crate::Config`].
    #[error("cannot parse configuration {path}: {source}")]
    ConfigParse {
        /// The file that failed to parse.
        path: PathBuf,
        /// Underlying TOML error. Boxed: it is 88 bytes, and inline it made every
        /// `Result<_, CoreError>` (and the unattended errors that wrap one) reach
        /// `clippy::result_large_err`'s 128 bytes on Windows, whose `PathBuf` is
        /// 8 bytes larger. A `Box` prints exactly what it holds.
        #[source]
        source: Box<toml::de::Error>,
    },

    /// Serializing the configuration failed (should not happen for valid configs).
    #[error("cannot serialize configuration: {0}")]
    ConfigSerialize(#[from] toml::ser::Error),

    /// A configuration value is out of range or malformed.
    #[error("invalid configuration: {0}")]
    ConfigInvalid(String),

    /// No home / profile directory could be determined for this user.
    #[error("cannot determine the user's home directory (HOME / USERPROFILE unset?)")]
    NoHomeDir,

    /// A keystore entry exists but its contents are not what was expected.
    #[error("keystore entry {name:?} is corrupt: {reason}")]
    CorruptKey {
        /// Entry name.
        name: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A keystore entry name contains characters we refuse to put in a filename.
    #[error("invalid keystore entry name {0:?}")]
    InvalidKeyName(String),

    /// The operating system RNG failed.
    #[error("random number generator failure: {0}")]
    Rng(String),

    /// The session log could not be written or read.
    #[error("session log error: {0}")]
    SessionLog(String),

    /// The unattended store could not be encoded or sealed (§B.8.9).
    #[error("unattended store error: {0}")]
    Store(String),

    /// The OS keychain backend refused or failed (`keyring` feature).
    #[error("keychain error: {0}")]
    Keychain(String),

    /// The keychain entry exists but cannot be read right now (locked collection,
    /// expired kernel keyring); readiness reports `keystore_locked` (§B.8.9).
    #[error("keychain locked: {0}")]
    KeychainLocked(String),

    /// A `hosts.toml` file is not valid for [`crate::unattended::hosts::HostsFile`].
    #[error("cannot parse {path}: {source}")]
    HostsParse {
        /// The file that failed to parse.
        path: PathBuf,
        /// Underlying TOML error, boxed as in [`CoreError::ConfigParse`].
        #[source]
        source: Box<toml::de::Error>,
    },
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::CoreError;
    use crate::unattended::{GuardError, LimiterError, StoreError};
    use std::path::Path;

    /// `clippy::result_large_err` fires when an error's largest variant reaches 128
    /// bytes. The gate lints the host target only, and a Windows `PathBuf` is 8 bytes
    /// larger than a Linux one, so the host keeps a quarter of the budget spare.
    const ERROR_SIZE_BUDGET: usize = 96;

    #[test]
    fn error_types_stay_well_below_the_large_err_threshold() {
        for (name, size) in [
            ("CoreError", size_of::<CoreError>()),
            ("StoreError", size_of::<StoreError>()),
            ("GuardError", size_of::<GuardError>()),
            ("LimiterError", size_of::<LimiterError>()),
        ] {
            assert!(
                size <= ERROR_SIZE_BUDGET,
                "{name} is {size} bytes, over the {ERROR_SIZE_BUDGET}-byte budget"
            );
        }
    }

    /// Asserts the Display, Debug and `source()` chain of `e`, with `path` written as
    /// `<path>` (the temporary directory differs per run and per OS).
    #[track_caller]
    fn assert_texts(
        e: &(dyn std::error::Error + 'static),
        path: &Path,
        display: &str,
        debug: &str,
        source: &str,
    ) {
        let mut chain = Vec::new();
        let mut next = e.source();
        while let Some(s) = next {
            chain.push(s.to_string());
            next = s.source();
        }
        let shown = e.to_string().replace(&path.display().to_string(), "<path>");
        assert_eq!(shown, display);
        assert_eq!(
            format!("{e:?}").replace(&format!("{path:?}"), "<path>"),
            debug
        );
        assert_eq!(chain.join(" | "), source);
    }

    /// The parse errors carry the file's text (`toml::de::Error` keeps its input for
    /// the snippet), and keeping them small must not change a byte of what they print.
    #[test]
    fn parse_errors_keep_their_display_debug_and_source_text() {
        const CFG: &str = "TOML parse error at line 2, column 11\n  |\n2 | max_fps = \"sixty\"\n  |           ^^^^^^^\ninvalid type: string \"sixty\", expected u32\n";
        const CFG_DEBUG: &str = r#"ConfigParse { path: <path>, source: Error { message: "invalid type: string \"sixty\", expected u32", input: Some("[media]\nmax_fps = \"sixty\"\n"), keys: ["media", "max_fps"], span: Some(18..25) } }"#;
        const TRUSTED: &str = "TOML parse error at line 1, column 11\n  |\n1 | devices = 3\n  |           ^\ninvalid type: integer `3`, expected a sequence\n";
        const TRUSTED_DEBUG: &str = r#"ConfigParse { path: <path>, source: Error { message: "invalid type: integer `3`, expected a sequence", input: Some("devices = 3\n"), keys: ["devices"], span: Some(10..11) } }"#;
        const HOSTS: &str = "TOML parse error at line 1, column 9\n  |\n1 | hosts = 5\n  |         ^\ninvalid type: integer `5`, expected a map\n";
        const HOSTS_DEBUG: &str = r#"HostsParse { path: <path>, source: Error { message: "invalid type: integer `5`, expected a map", input: Some("hosts = 5\n"), keys: ["hosts"], span: Some(8..9) } }"#;

        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "[media]\nmax_fps = \"sixty\"\n").unwrap();
        let trusted = dir.path().join("trusted.toml");
        std::fs::write(&trusted, "devices = 3\n").unwrap();
        let hosts = dir.path().join("hosts.toml");
        std::fs::write(&hosts, "hosts = 5\n").unwrap();
        let cfg_err = || crate::Config::load(&cfg).unwrap_err();
        let cfg_display = format!("cannot parse configuration <path>: {CFG}");

        assert_texts(&cfg_err(), &cfg, &cfg_display, CFG_DEBUG, CFG);
        assert_texts(
            &crate::trusted::TrustedDevices::load(&trusted).unwrap_err(),
            &trusted,
            &format!("cannot parse configuration <path>: {TRUSTED}"),
            TRUSTED_DEBUG,
            TRUSTED,
        );
        assert_texts(
            &crate::unattended::hosts::HostsFile::load(&hosts).unwrap_err(),
            &hosts,
            &format!("cannot parse <path>: {HOSTS}"),
            HOSTS_DEBUG,
            HOSTS,
        );
        assert_texts(
            &StoreError::Core(cfg_err()),
            &cfg,
            &cfg_display,
            &format!("Core({CFG_DEBUG})"),
            CFG,
        );
        let wrapped = format!("Store(Core({CFG_DEBUG}))");
        let guard = GuardError::Store(StoreError::Core(cfg_err()));
        assert_texts(&guard, &cfg, &cfg_display, &wrapped, CFG);
        let limiter = LimiterError::Store(StoreError::Core(cfg_err()));
        assert_texts(&limiter, &cfg, &cfg_display, &wrapped, CFG);
    }
}
