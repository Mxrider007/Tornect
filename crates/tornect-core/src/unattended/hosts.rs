//! Client-side per-host records `hosts.toml` (`docs/PLAN.md` §B.8.9): `remember`, the
//! `server_s_pk` TOFU pin set at the first `SESSION_ACCEPT` and checked in
//! `ClientLogin::finish` on every later login (A16), the suite recorded at the first
//! success and `ua_worked_before`. Keyed by onion address. Pairing-side known-host
//! data lives elsewhere (`trusted.rs`, the envelope track); nothing here is secret.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::id::TornectId;

mod hex32 {
    use serde::{Deserialize, Deserializer, Serialize as _, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        v.map(hex::encode).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let s: Option<String> = Option::deserialize(d)?;
        match s {
            None => Ok(None),
            Some(h) => {
                let mut out = [0u8; 32];
                hex::decode_to_slice(h.as_bytes(), &mut out)
                    .map_err(|e| serde::de::Error::custom(format!("server_s_pk_pin: {e}")))?;
                Ok(Some(out))
            }
        }
    }
}

/// One host as seen by this client.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostRecord {
    /// The user chose "Remember on this device" (the password itself lives in the OS
    /// keychain entry `tornect/unattended/<onion>`, M8).
    pub remember: bool,
    /// `server_s_pk` of the host's OPAQUE setup, pinned at the first `SESSION_ACCEPT`.
    #[serde(with = "hex32")]
    pub server_s_pk_pin: Option<[u8; 32]>,
    /// PAKE suite of the first successful `SESSION_ACCEPT` (never negotiated later).
    pub suite: Option<u8>,
    /// Whether an unattended session ever succeeded (≡ `suite.is_some()`).
    pub ua_worked_before: bool,
}

/// Outcome of a pin check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCheck {
    /// No pin yet (first login): pin after `SESSION_ACCEPT`.
    NoPin,
    /// Matches.
    Match,
    /// Differs: abort before KE3 ("host's unattended setup changed", A16).
    Mismatch,
}

/// The whole `hosts.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostsFile {
    /// Records keyed by onion address.
    pub hosts: BTreeMap<String, HostRecord>,
}

impl HostsFile {
    /// Load from `path`; a missing file is empty.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match fs_err::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        toml::from_str(&text).map_err(|source| CoreError::HostsParse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }

    /// Write atomically with private permissions.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            crate::keystore::create_private_dir(parent)?;
        }
        let body = toml::to_string_pretty(self)?;
        let tmp = path.with_extension("toml.tmp");
        crate::keystore::write_private_file(&tmp, body.as_bytes())?;
        fs_err::rename(&tmp, path)?;
        Ok(())
    }

    /// The record for a host.
    #[must_use]
    pub fn get(&self, host: &TornectId) -> Option<&HostRecord> {
        self.hosts.get(&host.onion_address())
    }

    /// The record for a host, created empty if missing.
    pub fn entry(&mut self, host: &TornectId) -> &mut HostRecord {
        self.hosts.entry(host.onion_address()).or_default()
    }

    /// Compare a login's `server_s_pk` with the pin (constant time).
    #[must_use]
    pub fn check_pin(&self, host: &TornectId, server_s_pk: &[u8; 32]) -> PinCheck {
        match self.get(host).and_then(|r| r.server_s_pk_pin) {
            None => PinCheck::NoPin,
            Some(pin) => {
                if bool::from(subtle::ConstantTimeEq::ct_eq(&pin[..], &server_s_pk[..])) {
                    PinCheck::Match
                } else {
                    PinCheck::Mismatch
                }
            }
        }
    }

    /// Record the first (or a repeated) unattended success: pins `server_s_pk` when no
    /// pin exists, records the suite once, sets `ua_worked_before`. A differing pin is
    /// refused ([`PinCheck::Mismatch`]) — clearing it needs [`Self::clear_pin`]
    /// (re-pair / re-register).
    pub fn record_success(
        &mut self,
        host: &TornectId,
        server_s_pk: [u8; 32],
        suite: u8,
    ) -> std::result::Result<(), PinCheck> {
        if self.check_pin(host, &server_s_pk) == PinCheck::Mismatch {
            return Err(PinCheck::Mismatch);
        }
        let r = self.entry(host);
        r.server_s_pk_pin.get_or_insert(server_s_pk);
        r.suite.get_or_insert(suite);
        r.ua_worked_before = true;
        Ok(())
    }

    /// Forget the pin and the suite (re-pair / re-register clears the pin, A16).
    pub fn clear_pin(&mut self, host: &TornectId) {
        if let Some(r) = self.hosts.get_mut(&host.onion_address()) {
            r.server_s_pk_pin = None;
            r.suite = None;
            r.ua_worked_before = false;
        }
    }

    /// Remove a host entirely.
    pub fn remove(&mut self, host: &TornectId) -> bool {
        self.hosts.remove(&host.onion_address()).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_pin_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("hosts.toml");
        let host = TornectId::from_bytes([4u8; 32]);
        let mut f = HostsFile::load(&path).unwrap();
        assert!(f.hosts.is_empty());
        assert_eq!(f.check_pin(&host, &[1; 32]), PinCheck::NoPin);
        f.record_success(&host, [1; 32], 1).unwrap();
        f.entry(&host).remember = true;
        assert_eq!(f.check_pin(&host, &[1; 32]), PinCheck::Match);
        assert_eq!(f.check_pin(&host, &[2; 32]), PinCheck::Mismatch);
        assert_eq!(f.record_success(&host, [2; 32], 1), Err(PinCheck::Mismatch));
        f.save(&path).unwrap();
        let back = HostsFile::load(&path).unwrap();
        assert_eq!(back, f);
        let r = back.get(&host).unwrap();
        assert!(r.remember && r.ua_worked_before);
        assert_eq!(r.suite, Some(1));
        assert_eq!(r.ua_worked_before, r.suite.is_some());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&host.onion_address()));
        assert!(text.contains(&hex::encode([1u8; 32])));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let mut f = back;
        f.clear_pin(&host);
        assert_eq!(f.check_pin(&host, &[1; 32]), PinCheck::NoPin);
        assert!(!f.get(&host).unwrap().ua_worked_before);
        assert!(f.remove(&host));
        assert!(!f.remove(&host));
        std::fs::write(&path, "hosts = 5").unwrap();
        assert!(matches!(
            HostsFile::load(&path),
            Err(CoreError::HostsParse { .. })
        ));
    }
}
