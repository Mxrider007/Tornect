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
        /// Underlying TOML error.
        #[source]
        source: toml::de::Error,
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
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, CoreError>;
