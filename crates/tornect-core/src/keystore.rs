//! Secret storage.
//!
//! [`SecretStore`] is the abstraction; [`FileSecretStore`] keeps each secret in
//! its own `0600` file inside a `0700` directory (`docs/PLAN.md` §A.3 D13). An OS
//! keychain backend (via the `keyring` crate) is planned behind a feature flag and
//! will implement the same trait.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::keys::{DeviceIdentity, HostIdentity};

/// Keystore entry holding the host identity seed.
pub const HOST_IDENTITY_SEED: &str = "host-identity.ed25519-seed";
/// Keystore entry holding this machine's client-device identity seed.
pub const DEVICE_IDENTITY_SEED: &str = "device-identity.ed25519-seed";

/// A place to keep small secrets by name.
pub trait SecretStore: Send + Sync {
    /// Fetch a secret, or `None` if absent.
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    /// Store (or overwrite) a secret.
    fn put(&self, name: &str, secret: &[u8]) -> Result<()>;
    /// Delete a secret; returns whether it existed.
    fn delete(&self, name: &str) -> Result<bool>;
    /// Whether a secret exists.
    fn contains(&self, name: &str) -> Result<bool> {
        Ok(self.get(name)?.is_some())
    }
}

/// File-based secret store: one private file per entry.
#[derive(Debug, Clone)]
pub struct FileSecretStore {
    dir: PathBuf,
}

impl FileSecretStore {
    /// Open (creating if needed, with private permissions) the store directory.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        create_private_dir(&dir)?;
        Ok(Self { dir })
    }

    /// The directory backing this store.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, name: &str) -> Result<PathBuf> {
        let ok = !name.is_empty()
            && name.len() <= 128
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            && !name.starts_with('.');
        if !ok {
            return Err(CoreError::InvalidKeyName(name.to_owned()));
        }
        Ok(self.dir.join(format!("{name}.secret")))
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let path = self.path_for(name)?;
        match fs_err::read(&path) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn put(&self, name: &str, secret: &[u8]) -> Result<()> {
        let path = self.path_for(name)?;
        create_private_dir(&self.dir)?;
        let tmp = path.with_extension("secret.tmp");
        write_private_file(&tmp, secret)?;
        fs_err::rename(&tmp, &path)?;
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<bool> {
        let path = self.path_for(name)?;
        match fs_err::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

/// Create `dir` (and parents) if missing and make it private (`0700` on Unix).
pub fn create_private_dir(dir: &Path) -> Result<()> {
    fs_err::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs_err::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `bytes` to `path`, creating it with `0600` on Unix (the mode is enforced
/// even if the file already existed) and syncing to disk.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut opts = fs_err::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn seed_from(store: &dyn SecretStore, name: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let Some(bytes) = store.get(name)? else {
        return Ok(None);
    };
    if bytes.len() != 32 {
        return Err(CoreError::CorruptKey {
            name: name.to_owned(),
            reason: format!("expected 32 bytes, found {}", bytes.len()),
        });
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes);
    Ok(Some(seed))
}

/// Load the host identity, generating and persisting one on first run.
///
/// Returns the identity and whether it was freshly created.
pub fn load_or_create_host_identity(store: &dyn SecretStore) -> Result<(HostIdentity, bool)> {
    if let Some(seed) = seed_from(store, HOST_IDENTITY_SEED)? {
        return Ok((HostIdentity::from_seed(&seed), false));
    }
    let host = HostIdentity::generate()?;
    store.put(HOST_IDENTITY_SEED, host.seed().as_slice())?;
    Ok((host, true))
}

/// Load this machine's device identity, generating and persisting one on first run.
pub fn load_or_create_device_identity(store: &dyn SecretStore) -> Result<(DeviceIdentity, bool)> {
    if let Some(seed) = seed_from(store, DEVICE_IDENTITY_SEED)? {
        return Ok((DeviceIdentity::from_seed(&seed), false));
    }
    let dev = DeviceIdentity::generate()?;
    store.put(DEVICE_IDENTITY_SEED, dev.seed().as_slice())?;
    Ok((dev, true))
}

/// Replace the host identity with a fresh one ("Rotate ID", `docs/PLAN.md` §B.6).
///
/// Callers must also drop all pairings and unattended grants — they are bound to
/// the old ID by design.
pub fn rotate_host_identity(store: &dyn SecretStore) -> Result<HostIdentity> {
    let host = HostIdentity::generate()?;
    store.put(HOST_IDENTITY_SEED, host.seed().as_slice())?;
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::open(dir.path().join("keys")).unwrap();
        assert!(!store.contains("a").unwrap());
        store.put("a", b"secret").unwrap();
        assert_eq!(store.get("a").unwrap().unwrap().as_slice(), b"secret");
        store.put("a", b"changed").unwrap();
        assert_eq!(store.get("a").unwrap().unwrap().as_slice(), b"changed");
        assert!(store.delete("a").unwrap());
        assert!(!store.delete("a").unwrap());
        assert!(store.get("a").unwrap().is_none());
    }

    #[test]
    fn rejects_unsafe_names() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        for bad in ["", "../x", "a/b", ".hidden", "a b", "x\0"] {
            assert!(
                matches!(store.put(bad, b"x"), Err(CoreError::InvalidKeyName(_))),
                "{bad:?} should be rejected"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn files_and_dirs_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let store = FileSecretStore::open(&keys).unwrap();
        store.put("k", b"v").unwrap();
        let dmode = std::fs::metadata(&keys).unwrap().permissions().mode() & 0o777;
        let fmode = std::fs::metadata(keys.join("k.secret"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dmode, 0o700);
        assert_eq!(fmode, 0o600);
    }

    #[test]
    fn identities_persist_across_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        let (h1, created) = load_or_create_host_identity(&store).unwrap();
        assert!(created);
        let (h2, created) = load_or_create_host_identity(&store).unwrap();
        assert!(!created);
        assert_eq!(h1.id(), h2.id());

        let (d1, _) = load_or_create_device_identity(&store).unwrap();
        let (d2, _) = load_or_create_device_identity(&store).unwrap();
        assert_eq!(d1.id(), d2.id());

        let h3 = rotate_host_identity(&store).unwrap();
        assert_ne!(h3.id(), h1.id());
        let (h4, _) = load_or_create_host_identity(&store).unwrap();
        assert_eq!(h4.id(), h3.id());
    }

    #[test]
    fn corrupt_seed_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        store.put(HOST_IDENTITY_SEED, b"short").unwrap();
        assert!(matches!(
            load_or_create_host_identity(&store),
            Err(CoreError::CorruptKey { .. })
        ));
    }
}
