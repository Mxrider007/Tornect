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
        /// Where and why, without the file's text. Boxed: inline it would make
        /// every `Result<_, CoreError>` (and the unattended errors that wrap
        /// one) reach `clippy::result_large_err`'s 128 bytes on Windows, whose
        /// `PathBuf` is 8 bytes larger.
        #[source]
        source: Box<TomlError>,
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
        /// Where and why, boxed as in [`CoreError::ConfigParse`].
        #[source]
        source: Box<TomlError>,
    },
}

/// Where and why a TOML file did not parse, without the file's text.
///
/// `toml::de::Error` keeps the whole input (its `Debug` prints it) and its
/// `Display` quotes the offending line, and serde's message quotes the
/// offending value: in `config.toml` that can be a private bridge line, which
/// `tornect doctor` and a failing command's exit would then print (SLICE-E
/// E2-3). This keeps the line, the column, the key where the file names it
/// plainly, and the message with the value elided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TomlError {
    /// 1-based line.
    line: Option<usize>,
    /// 1-based column, in characters.
    column: Option<usize>,
    /// The dotted key of the error's line (`tor.bridge_lines`), or its table.
    key: Option<String>,
    /// What went wrong, with the offending value elided.
    message: String,
}

impl TomlError {
    /// What of `error`, raised while parsing `text`, may be shown.
    #[must_use]
    pub fn new(text: &str, error: &toml::de::Error) -> Self {
        let at = error.span().map(|span| span.start.min(text.len()));
        let line_index = at.map(|at| text[..at].matches('\n').count());
        let column = at.map(|at| {
            let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
            text[start..at].chars().count() + 1
        });
        Self {
            line: line_index.map(|l| l + 1),
            column,
            key: line_index.and_then(|l| key_at(text, l)),
            message: elide_values(error.message()),
        }
    }
}

impl std::fmt::Display for TomlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.line, self.column) {
            (Some(line), Some(column)) => write!(f, "line {line}, column {column}")?,
            _ => f.write_str("somewhere")?,
        }
        if let Some(key) = &self.key {
            write!(f, " ({key})")?;
        }
        write!(f, ": {}", self.message)
    }
}

impl std::error::Error for TomlError {}

/// Whether `s` is a TOML bare key, or bare keys joined by dots: a name the
/// file gives plainly, never a quoted value.
fn is_plain_key(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|part| {
            let part = part.trim();
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
}

/// The dotted key of line `index` of `text` (0-based), from the table header
/// above it and the `key =` it starts with; only names the file gives plainly.
fn key_at(text: &str, index: usize) -> Option<String> {
    let lines: Vec<&str> = text.split('\n').collect();
    let table = lines[..index.min(lines.len())]
        .iter()
        .rev()
        .map(|l| l.trim())
        .find(|l| l.starts_with('['))
        .map(|l| l.trim_start_matches('[').trim_end_matches(']').trim())
        .filter(|t| is_plain_key(t));
    let key = lines
        .get(index)
        .and_then(|l| l.split_once('='))
        .map(|(k, _)| k.trim())
        .filter(|k| is_plain_key(k));
    match (table, key) {
        (Some(t), Some(k)) => Some(format!("{t}.{k}")),
        (None, Some(k)) => Some(k.to_owned()),
        (Some(t), None) => Some(format!("in [{t}]")),
        (None, None) => None,
    }
}

/// `message` with every quoted (`"…"`) or backticked span before its
/// ", expected" elided: those hold the value the file had. What follows
/// (what the schema expects) is kept.
fn elide_values(message: &str) -> String {
    let (head, tail) = message
        .find(", expected")
        .map_or((message, ""), |i| message.split_at(i));
    let mut out = String::with_capacity(message.len());
    let mut chars = head.chars();
    while let Some(c) = chars.next() {
        out.push(c);
        if c != '"' && c != '`' {
            continue;
        }
        out.push('…');
        // Skip to the closing mark (a `\"` inside a quoted string does not
        // close it); with none, the rest goes.
        let mut escaped = false;
        for d in chars.by_ref() {
            if escaped {
                escaped = false;
            } else if c == '"' && d == '\\' {
                escaped = true;
            } else if d == c {
                out.push(c);
                break;
            }
        }
    }
    out.push_str(tail);
    out
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

    /// SLICE-E E2-3: a parse error never carries the file's text. A private
    /// bridge line written as a string instead of a list, or with a stray
    /// quote, shows up in no Display, no Debug and no source in the chain
    /// (what `tornect doctor` prints, and what a failing command prints on
    /// exit), while the error still says where it is.
    #[test]
    fn a_parse_error_never_shows_the_files_text() {
        const LINE: &str = "obfs4 203.0.113.7:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=c2VjcmV0c2VjcmV0 iat-mode=0";
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        for text in [
            format!("[tor]\nbridge_lines = \"{LINE}\"\n"),
            format!("[tor]\nbridge_lines = [\"{LINE}\" x]\n"),
        ] {
            std::fs::write(&cfg, &text).unwrap();
            let e = crate::Config::load(&cfg).unwrap_err();
            let mut shown = vec![e.to_string(), format!("{e:?}")];
            let mut next = std::error::Error::source(&e);
            while let Some(s) = next {
                shown.push(s.to_string());
                shown.push(format!("{s:?}"));
                next = s.source();
            }
            for s in &shown {
                assert!(
                    !s.contains("203.0.113.7") && !s.contains("cert=") && !s.contains("iat-mode"),
                    "the file's text in {s:?}"
                );
            }
            assert!(e.to_string().contains("line 2"), "{e}");
        }
    }

    /// What the parse errors print: the place and the key, the value elided,
    /// never the file's text (SLICE-E E2-3); the same through every error
    /// that wraps one.
    #[test]
    fn parse_errors_keep_their_display_debug_and_source_text() {
        const CFG: &str =
            "line 2, column 11 (media.max_fps): invalid type: string \"…\", expected u32";
        const CFG_DEBUG: &str = r#"ConfigParse { path: <path>, source: TomlError { line: Some(2), column: Some(11), key: Some("media.max_fps"), message: "invalid type: string \"…\", expected u32" } }"#;
        const TRUSTED: &str =
            "line 1, column 11 (devices): invalid type: integer `…`, expected a sequence";
        const TRUSTED_DEBUG: &str = r#"ConfigParse { path: <path>, source: TomlError { line: Some(1), column: Some(11), key: Some("devices"), message: "invalid type: integer `…`, expected a sequence" } }"#;
        const HOSTS: &str = "line 1, column 9 (hosts): invalid type: integer `…`, expected a map";
        const HOSTS_DEBUG: &str = r#"HostsParse { path: <path>, source: TomlError { line: Some(1), column: Some(9), key: Some("hosts"), message: "invalid type: integer `…`, expected a map" } }"#;

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
