//! `K_master` in an OS keychain through `keyring-core` (`docs/PLAN.md` §B.8.9, `ui.md`
//! §5.9 — never `keyring::Entry`), behind the `keyring` cargo feature.
//!
//! **Test / CI only at M1.** The only backend compiled here is the Linux kernel
//! keyutils store, whose credentials live in kernel memory
//! (`CredentialPersistence::UntilReboot`): it never prompts, which exercises the
//! "never block on a keyring prompt" path, but `K_master` would vanish at every reboot
//! and the unattended store would fail closed (`MissingKey`) after each restart — the
//! opposite of the autostart requirement. [`KeyringSecretStore::new`], the production
//! constructor, therefore refuses every store that does not persist until deleted, and
//! the M6 readiness canary of §B.8.9 (persistent *and* unlockable at autostart) is a
//! hard precondition before any keyring becomes the host's `SecretStore`; until then
//! `FileSecretStore` is the fallback. Windows / macOS stores land with
//! `tornect-platform` at M6.

use std::sync::Arc;

use keyring_core::{CredentialPersistence, CredentialStore, Entry, Error as KcError};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::keystore::{KeystoreKind, SecretStore};

/// `service` of every Tornect keychain entry.
pub const SERVICE: &str = "tornect";

/// A [`SecretStore`] over a `keyring-core` credential store.
pub struct KeyringSecretStore {
    store: Arc<CredentialStore>,
    service: String,
}

/// Human-readable name of a persistence class (the enum is non-exhaustive and has no
/// `Debug`).
fn persistence_name(p: &CredentialPersistence) -> &'static str {
    match p {
        CredentialPersistence::EntryOnly => "entry-only",
        CredentialPersistence::ProcessOnly => "process-only",
        CredentialPersistence::UntilLogout => "until-logout",
        CredentialPersistence::UntilReboot => "until-reboot",
        CredentialPersistence::UntilDelete => "until-delete",
        _ => "unspecified",
    }
}

impl std::fmt::Debug for KeyringSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyringSecretStore")
            .field("service", &self.service)
            .field("store", &self.store)
            .finish()
    }
}

impl KeyringSecretStore {
    /// Wrap a credential store for production use; entries are `<SERVICE, name>`.
    /// Refused unless the store keeps credentials until they are deleted
    /// (`CredentialPersistence::UntilDelete`): `K_master` must survive a reboot for
    /// autostart (§B.8.9), so a volatile backend can never hold it.
    pub fn new(store: Arc<CredentialStore>) -> Result<Self> {
        match store.persistence() {
            CredentialPersistence::UntilDelete => Ok(Self::new_volatile(store)),
            other => Err(CoreError::Keychain(format!(
                "credential store persistence is {}; K_master needs a store that survives a reboot",
                persistence_name(&other)
            ))),
        }
    }

    /// Wrap any credential store regardless of its persistence — **test / CI only**
    /// (the kernel keyutils and mock stores); a host never holds `K_master` here.
    #[must_use]
    pub fn new_volatile(store: Arc<CredentialStore>) -> Self {
        Self {
            store,
            service: SERVICE.to_owned(),
        }
    }

    /// Wrap with a custom service name (side-by-side test instances; volatile allowed).
    #[must_use]
    pub fn with_service(store: Arc<CredentialStore>, service: impl Into<String>) -> Self {
        Self {
            store,
            service: service.into(),
        }
    }

    /// The Linux kernel keyutils store — **test / CI only** (`UntilReboot`: refused by
    /// [`Self::new`], see the module docs).
    #[cfg(target_os = "linux")]
    pub fn linux_keyutils() -> Result<Self> {
        let store = linux_keyutils_keyring_store::Store::new()
            .map_err(|e| CoreError::Keychain(e.to_string()))?;
        Ok(Self::new_volatile(store))
    }

    /// `keyring-core`'s in-memory mock store (tests only; not a secure store).
    pub fn mock() -> Result<Self> {
        let store =
            keyring_core::mock::Store::new().map_err(|e| CoreError::Keychain(e.to_string()))?;
        Ok(Self::new_volatile(store))
    }

    /// The persistence class of the wrapped store.
    #[must_use]
    pub fn persistence(&self) -> CredentialPersistence {
        self.store.persistence()
    }

    /// Whether the wrapped store keeps credentials across reboots (the first half of
    /// the §B.8.9 canary; the second — unlockable at autostart — is the M6 probe).
    #[must_use]
    pub fn persists_across_reboots(&self) -> bool {
        matches!(self.persistence(), CredentialPersistence::UntilDelete)
    }

    fn entry(&self, name: &str) -> Result<Entry> {
        self.store.build(&self.service, name, None).map_err(map_err)
    }
}

fn map_err(e: KcError) -> CoreError {
    match e {
        KcError::NoStorageAccess(inner) => CoreError::KeychainLocked(inner.to_string()),
        other => CoreError::Keychain(other.to_string()),
    }
}

impl SecretStore for KeyringSecretStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match self.entry(name)?.get_secret() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(KcError::NoEntry) => Ok(None),
            Err(e) => Err(map_err(e)),
        }
    }

    fn put(&self, name: &str, secret: &[u8]) -> Result<()> {
        self.entry(name)?.set_secret(secret).map_err(map_err)
    }

    fn delete(&self, name: &str) -> Result<bool> {
        match self.entry(name)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(KcError::NoEntry) => Ok(false),
            Err(e) => Err(map_err(e)),
        }
    }

    fn kind(&self) -> KeystoreKind {
        KeystoreKind::OsKeychain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volatile_stores_are_refused_by_the_production_constructor() {
        let mock = keyring_core::mock::Store::new().unwrap();
        let err = KeyringSecretStore::new(mock.clone()).unwrap_err();
        assert!(err.to_string().contains("process-only"), "{err}");
        let s = KeyringSecretStore::new_volatile(mock);
        assert!(!s.persists_across_reboots());
        assert_eq!(
            persistence_name(&CredentialPersistence::UntilDelete),
            "until-delete"
        );
        assert_eq!(
            persistence_name(&CredentialPersistence::UntilReboot),
            "until-reboot"
        );
    }

    #[test]
    fn mock_store_roundtrip() {
        let s = KeyringSecretStore::mock().unwrap();
        assert_eq!(s.kind(), KeystoreKind::OsKeychain);
        assert!(s.get("unattended-master.key").unwrap().is_none());
        s.put("unattended-master.key", &[7u8; 40]).unwrap();
        assert_eq!(
            s.get("unattended-master.key").unwrap().unwrap().as_slice(),
            &[7u8; 40]
        );
        s.put("unattended-master.key", &[8u8; 40]).unwrap();
        assert_eq!(s.get("unattended-master.key").unwrap().unwrap()[0], 8);
        assert!(s.delete("unattended-master.key").unwrap());
        assert!(!s.delete("unattended-master.key").unwrap());
        assert!(s.get("unattended-master.key").unwrap().is_none());
        assert!(!format!("{s:?}").contains("secret"));
    }

    /// Needs a kernel keyring (fails in some sandboxes): run with `--ignored`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a Linux kernel keyring available to the test user"]
    fn linux_keyutils_roundtrip() {
        let store = linux_keyutils_keyring_store::Store::new().unwrap();
        assert!(
            KeyringSecretStore::new(store.clone()).is_err(),
            "kernel keyrings vanish at reboot: never a production K_master store"
        );
        let s =
            KeyringSecretStore::with_service(store, format!("tornect-test-{}", std::process::id()));
        assert!(!s.persists_across_reboots());
        s.put("k", b"v").unwrap();
        assert_eq!(s.get("k").unwrap().unwrap().as_slice(), b"v");
        assert!(s.delete("k").unwrap());
    }
}
