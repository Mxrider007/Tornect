//! Tornect core: identities, keys, configuration, keystore and telemetry.
//!
//! This crate performs no networking and no `unsafe`; its only I/O is the local
//! state directory. Every other Tornect crate depends on it and it depends on
//! none of them (see `docs/PLAN.md` §B.1).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod address_book;
pub mod config;
pub mod error;
pub mod id;
pub mod keys;
pub mod keystore;
pub mod levels;
pub mod paths;
pub mod session_log;
pub mod telemetry;
pub mod trusted;
pub mod unattended;
pub mod words;

pub use config::Config;
pub use error::{CoreError, Result};
pub use id::{DeviceId, TornectId};
pub use keys::{DeviceIdentity, HostIdentity};
pub use keystore::{FileSecretStore, SecretStore};
pub use paths::Paths;

/// Version of this build, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Signaling protocol version this build speaks (`docs/PLAN.md` §B.3).
pub const PROTOCOL_VERSION: u8 = 1;
