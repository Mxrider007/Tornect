//! Handing the Tornect host identity to Arti (decisions M0-9, M1-1).
//!
//! `tornect-core` owns the 32-byte ed25519 seed ([`HostIdentity`]) and already
//! prints the Tornect ID at M0. Arti stores onion identities as *expanded* keys —
//! the clamped scalar and nonce prefix that RFC 8032 §5.1.5 derives from
//! `SHA-512(seed)` — so we expand the seed the same way, wrap it in Arti's
//! `HsIdKeypair` and install it into the Arti native keystore under the service
//! nickname *before* launch. Arti then finds the key and derives the very same
//! `.onion` address, which [`super::TorNode::publish`] re-checks.
//!
//! **Arti's keystore therefore holds a second copy of the host secret**:
//! `<state>/arti/keystore/hss/<nickname>/ks_hs_id.ed25519_expanded_private`, next
//! to the blinded and descriptor-signing keys derived from it, with the service's
//! intro-point state under `<state>/arti/hss/<nickname>/`. "Rotate ID"
//! (`docs/PLAN.md` §B.6) is the compromise-recovery action, so the old identity
//! must not stay recoverable there: [`forget_identity`] removes that copy, and
//! `tornect rotate-id` calls it before the new seed is written.
//!
//! Only public `tor-keymgr` / `tor-hscrypto` / `tor-llcrypto` / `tor-persist`
//! APIs are used; no `experimental-api` feature is needed
//! (docs/research/arti.md §11 option 2).

use std::path::{Path, PathBuf};

use arti_client::TorClientConfig;
use safelog::DisplayRedacted as _;
use sha2::{Digest as _, Sha512};
use tor_hscrypto::pk::{HsId, HsIdKey, HsIdKeypair};
use tor_hsservice::{HsIdKeypairSpecifier, HsNickname};
use tor_keymgr::{ArtiNativeKeystore, KeyMgr, KeyMgrBuilder, KeyPathPattern, KeystoreSelector};
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_persist::ErrorSource;
use tor_persist::state_dir::{InstanceIdentity as _, InstanceStateHandle, StateDirectory};
use tornect_core::{HostIdentity, Paths, TornectId};
use zeroize::Zeroizing;

use super::config::tor_client_config;
use crate::error::{Result, SignalError};

/// Sub-directory of Arti's state directory that holds the native keystore; the
/// location is hard-coded inside `arti-client` (docs/research/arti.md §6).
const KEYSTORE_SUBDIR: &str = "keystore";

/// Keystore directory (`ArtiPath` prefix) of onion-service keys
/// (`tor-hsservice-0.45.0/src/keys.rs`: every specifier has `prefix = "hss"`).
const HSS_KEY_PREFIX: &str = "hss";

/// Expand a seed into `scalar ‖ prefix` exactly as RFC 8032 §5.1.5 does:
/// `h = SHA-512(seed)`, clear the low 3 bits and the top bit of `h[0..32]`, set
/// bit 254; `h[32..64]` is the nonce prefix used for deterministic signing.
pub(crate) fn expand_seed(seed: &[u8; 32]) -> Zeroizing<[u8; 64]> {
    let mut expanded = Zeroizing::new([0u8; 64]);
    // Hash straight into the zeroizing buffer: `Sha512::digest` would leave an
    // unzeroized copy of the expanded key on the stack.
    Sha512::new()
        .chain_update(seed)
        .finalize_into((&mut *expanded).into());
    expanded[0] &= 248;
    expanded[31] &= 127;
    expanded[31] |= 64;
    expanded
}

/// Arti's keypair type for the host identity.
pub(crate) fn hs_id_keypair(identity: &HostIdentity) -> Result<HsIdKeypair> {
    let seed = identity.seed();
    let expanded = expand_seed(&seed);
    // Arti takes the 64 bytes by value: that argument copy lives on the stack
    // until the call returns and is not zeroized (API limitation). The
    // `ExpandedKeypair` it builds zeroizes on drop (dalek `zeroize` feature).
    let keypair = ExpandedKeypair::from_secret_key_bytes(*expanded).ok_or_else(|| {
        SignalError::Keystore("seed does not expand to a usable ed25519 key".to_owned())
    })?;
    Ok(HsIdKeypair::from(keypair))
}

/// Nickname under which Arti keeps this identity's keys and state.
///
/// Derived from the ID (`tornect-<first 8 address chars>`) so that a rotated ID
/// starts from a clean slate: Arti caches blinded and descriptor-signing keys per
/// nickname and would otherwise reuse ones derived from the old identity.
pub(crate) fn service_nickname(id: &TornectId) -> Result<HsNickname> {
    HsNickname::new(format!("tornect-{}", id.short()))
        .map_err(|e| SignalError::Config(e.to_string()))
}

/// Convert Arti's `HsId` into a [`TornectId`] via the `.onion` string, which
/// also re-validates the checksum on the way in.
pub(crate) fn hsid_to_tornect_id(hsid: &HsId) -> Result<TornectId> {
    hsid.display_unredacted()
        .to_string()
        .parse::<TornectId>()
        .map_err(|e| SignalError::InvalidAddress(e.to_string()))
}

/// The onion address Arti derives for `identity`, computed through Arti's own
/// key types. Must equal [`HostIdentity::id`]; tested, and re-checked at launch.
pub fn onion_address_for(identity: &HostIdentity) -> Result<TornectId> {
    let keypair = hs_id_keypair(identity)?;
    hsid_to_tornect_id(&HsIdKey::from(&keypair).id())
}

/// Open Arti's native keystore under `state_dir` with the same `fs-mistrust`
/// rules Arti applies to it.
pub(crate) fn open_keymgr(tor_config: &TorClientConfig, state_dir: &Path) -> Result<KeyMgr> {
    let store = ArtiNativeKeystore::from_path_and_mistrust(
        state_dir.join(KEYSTORE_SUBDIR),
        tor_config.fs_mistrust(),
    )
    .map_err(|e| SignalError::Keystore(e.to_string()))?;
    KeyMgrBuilder::default()
        .primary_store(Box::new(store))
        .build()
        .map_err(|e| SignalError::Keystore(e.to_string()))
}

/// Where the keystore keeps `nickname`'s keys (`hss/<nickname>/…`).
fn keystore_dir_for(state_dir: &Path, nickname: &HsNickname) -> PathBuf {
    state_dir
        .join(KEYSTORE_SUBDIR)
        .join(HSS_KEY_PREFIX)
        .join(nickname.to_string())
}

/// Where Arti keeps `nickname`'s service state (`hss/<nickname>/`, lock file
/// `hss/<nickname>.lock` beside it; `tor-persist` `state_dir.md`).
fn state_dir_for(state_dir: &Path, nickname: &HsNickname) -> PathBuf {
    state_dir
        .join(HsNickname::kind())
        .join(nickname.to_string())
}

/// Make sure Arti's keystore holds `identity` under its nickname; returns the nickname.
///
/// Idempotent: an identical key already present is left alone. A different key
/// under the same nickname cannot happen through Tornect (the nickname embeds
/// the ID) and is refused rather than overwritten: Arti reads blinded and
/// descriptor-signing keys back from the keystore instead of re-deriving them
/// (`tor-hsservice-0.45.0/src/publish/reactor.rs` `read_blind_id_keypair`), so
/// keys derived from the old identity would publish a wrong descriptor.
pub(crate) fn install_identity_key(
    tor_config: &TorClientConfig,
    state_dir: &Path,
    identity: &HostIdentity,
) -> Result<HsNickname> {
    let nickname = service_nickname(&identity.id())?;
    let keymgr = open_keymgr(tor_config, state_dir)?;
    let spec = HsIdKeypairSpecifier::new(nickname.clone());
    let wanted = hs_id_keypair(identity)?;
    let wanted_id = HsIdKey::from(&wanted).id();
    let keystore_err = |e: tor_keymgr::Error| SignalError::Keystore(e.to_string());

    match keymgr.get::<HsIdKeypair>(&spec).map_err(keystore_err)? {
        Some(existing) if HsIdKey::from(&existing).id() == wanted_id => {
            tracing::debug!(%nickname, "host identity already present in Arti keystore");
        }
        Some(_) => {
            return Err(SignalError::Keystore(format!(
                "Arti's keystore holds a different identity key under nickname {nickname} \
                 (corrupt or tampered state); refusing to overwrite it. Remove {} and {} \
                 and retry",
                keystore_dir_for(state_dir, &nickname).display(),
                state_dir_for(state_dir, &nickname).display(),
            )));
        }
        None => {
            tracing::info!(%nickname, "installing host identity into Arti keystore");
            keymgr
                .insert(wanted, &spec, KeystoreSelector::Primary, false)
                .map_err(keystore_err)?;
        }
    }
    Ok(nickname)
}

/// What [`forget_identity`] removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForgottenIdentity {
    /// Keys the key manager recognized and removed: the identity key, the
    /// blinded and descriptor-signing keys, and intro-point keys.
    pub keys_removed: usize,
    /// Files under the identity's keystore directory that the key manager did
    /// not recognize; removed together with the directory.
    pub unrecognized_files_removed: usize,
    /// Whether the service state (intro-point records, replay logs, PoW nonces)
    /// existed and was removed.
    pub state_removed: bool,
}

/// Remove every trace of `id` from Arti's state under `paths`: its keys
/// (`keystore/hss/<nickname>/`) and its service state (`hss/<nickname>/` plus
/// the lock file beside it).
///
/// The compromise-recovery half of "Rotate ID" (`docs/PLAN.md` §B.6): afterwards
/// the old identity is no longer recoverable from this machine's Arti state.
/// Fails with [`SignalError::Keystore`] — before removing anything — if the
/// service is still running (its state directory is locked); stop hosting
/// first. Finding nothing is not an error, so the call is idempotent.
pub fn forget_identity(paths: &Paths, id: &TornectId) -> Result<ForgottenIdentity> {
    let tor_config = tor_client_config(paths)?;
    forget_identity_in(&tor_config, &paths.arti_state_dir(), id)
}

pub(crate) fn forget_identity_in(
    tor_config: &TorClientConfig,
    state_dir: &Path,
    id: &TornectId,
) -> Result<ForgottenIdentity> {
    let nickname = service_nickname(id)?;
    let keystore_err = |e: tor_keymgr::Error| SignalError::Keystore(e.to_string());

    // Lock first. A running host holds `hss/<nickname>.lock` for its lifetime
    // (`tor-hsservice-0.45.0/src/lib.rs` 312, `acquire_instance`); the native
    // keystore has no lock of its own (docs/research/arti.md §11), so this is
    // the only way to know the keys are not in use. The lock is held across
    // the whole removal: a host launched meanwhile fails to start ("already
    // locked") instead of adopting keys that are about to disappear.
    let service = lock_service_state(tor_config, state_dir, &nickname)?;
    let keymgr = open_keymgr(tor_config, state_dir)?;

    // `**` spans path separators, so this covers `ks_hs_id`, the time-period
    // keys (`ks_hs_blind_id+<tp>`, `ks_hs_desc_sign+<tp>`) and `ipts/*`.
    let pattern = KeyPathPattern::Arti(format!("{HSS_KEY_PREFIX}/{nickname}/**"));
    let mut keys_removed = 0;
    for entry in keymgr.list_matching(&pattern).map_err(keystore_err)? {
        match keymgr.remove_entry(&entry) {
            Ok(Some(())) => keys_removed += 1,
            Ok(None) => {}
            Err(e) => tracing::warn!(
                path = ?entry.key_path(),
                error = %e,
                "could not remove keystore entry; removing its directory instead"
            ),
        }
    }
    // `list_matching` skips entries the key manager does not recognize (no
    // extension, malformed path); they must not survive either, so take the
    // directory itself.
    let unrecognized_files_removed =
        remove_dir_checked(tor_config, &keystore_dir_for(state_dir, &nickname))?;
    let state_removed = service.purge()?;

    tracing::info!(
        %nickname,
        keys_removed,
        unrecognized_files_removed,
        state_removed,
        "removed identity from Arti's keystore and state"
    );
    Ok(ForgottenIdentity {
        keys_removed,
        unrecognized_files_removed,
        state_removed,
    })
}

/// Remove `dir` and everything below it after checking it with the `fs-mistrust`
/// rules Arti applies to its state; returns how many files were removed.
fn remove_dir_checked(tor_config: &TorClientConfig, dir: &Path) -> Result<usize> {
    if !dir.is_dir() {
        return Ok(0);
    }
    tor_config
        .fs_mistrust()
        .verifier()
        .require_directory()
        .check(dir)
        .map_err(|e| SignalError::Keystore(format!("refusing to remove {}: {e}", dir.display())))?;
    let files = count_files(dir)?;
    std::fs::remove_dir_all(dir)?;
    Ok(files)
}

fn count_files(dir: &Path) -> Result<usize> {
    let mut files = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            files += count_files(&entry.path())?;
        } else {
            tracing::debug!(path = %entry.path().display(), "removing unrecognized keystore file");
            files += 1;
        }
    }
    Ok(files)
}

/// `nickname`'s service state (`hss/<nickname>/`), held under its instance lock
/// exactly as a running service holds it; [`LockedServiceState::purge`] deletes it.
struct LockedServiceState {
    handle: InstanceStateHandle,
    /// Whether the directory or its lock file existed before the lock was taken
    /// (`acquire_instance` creates both).
    existed: bool,
}

/// Take `nickname`'s instance lock through `tor-persist`. Fails with the
/// "in use" [`SignalError::Keystore`] when a running service holds it.
fn lock_service_state(
    tor_config: &TorClientConfig,
    state_dir: &Path,
    nickname: &HsNickname,
) -> Result<LockedServiceState> {
    let instance_dir = state_dir_for(state_dir, nickname);
    let existed = instance_dir.exists() || instance_dir.with_extension("lock").exists();
    let persist_err = |e: tor_persist::Error| SignalError::Keystore(e.to_string());
    let directory =
        StateDirectory::new(state_dir, tor_config.fs_mistrust()).map_err(persist_err)?;
    let handle = directory.acquire_instance(nickname).map_err(|e| {
        if matches!(e.source(), ErrorSource::AlreadyLocked) {
            SignalError::Keystore(format!(
                "{} is in use (is `tornect host` still running for that ID?); stop it and retry",
                instance_dir.display()
            ))
        } else {
            persist_err(e)
        }
    })?;
    Ok(LockedServiceState { handle, existed })
}

impl LockedServiceState {
    /// Delete the directory and then its lock file (`InstanceStateHandle::purge`).
    /// Returns whether any state existed before the lock was taken.
    fn purge(self) -> Result<bool> {
        self.handle
            .purge()
            .map_err(|e| SignalError::Keystore(e.to_string()))?;
        Ok(self.existed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arti_client::config::TorClientConfigBuilder;
    use tor_hsservice::HsIdPublicKeySpecifier;
    use tor_persist::state_dir::LockFileGuard;

    fn trusting_config(root: &Path) -> TorClientConfig {
        let mut b =
            TorClientConfigBuilder::from_directories(root.join("state"), root.join("cache"));
        // Test tempdirs live wherever the harness puts them; skip the ownership checks.
        b.storage().permissions().dangerously_trust_everyone();
        b.build().unwrap()
    }

    fn key_file(state_dir: &Path, nick: &HsNickname) -> PathBuf {
        keystore_dir_for(state_dir, nick).join("ks_hs_id.ed25519_expanded_private")
    }

    /// Fake what a launched service leaves behind: `hss/<nick>/ipts.json` and its lock file.
    fn fake_service_state(state_dir: &Path, nick: &HsNickname) -> (PathBuf, PathBuf) {
        let dir = state_dir_for(state_dir, nick);
        std::fs::create_dir_all(dir.join("iptreplay")).unwrap();
        std::fs::write(dir.join("ipts.json"), b"{}").unwrap();
        let lock = dir.with_extension("lock");
        std::fs::write(&lock, b"").unwrap();
        (dir, lock)
    }

    #[test]
    fn expand_seed_matches_rfc8032_clamping() {
        let seed = [7u8; 32];
        let raw = Sha512::digest(seed);
        let expanded = expand_seed(&seed);
        assert_eq!(expanded[0] & 0b0000_0111, 0);
        assert_eq!(expanded[31] & 0b1000_0000, 0);
        assert_eq!(expanded[31] & 0b0100_0000, 0b0100_0000);
        assert_eq!(&expanded[1..31], &raw[1..31]);
        assert_eq!(&expanded[32..], &raw[32..], "nonce prefix is untouched");
    }

    #[test]
    fn arti_derives_the_same_onion_address_as_tornect_core() {
        for _ in 0..32 {
            let identity = HostIdentity::generate().unwrap();
            let via_arti = onion_address_for(&identity).unwrap();
            assert_eq!(via_arti, identity.id());
            assert_eq!(via_arti.onion_address(), identity.id().onion_address());
        }
        // and a fixed vector, so a regression cannot hide behind randomness
        let identity = HostIdentity::from_seed(&[0x42; 32]);
        assert_eq!(
            onion_address_for(&identity).unwrap().onion_address(),
            identity.id().onion_address()
        );
    }

    #[test]
    fn nickname_is_a_valid_slug_bound_to_the_id() {
        let identity = HostIdentity::generate().unwrap();
        let nick = service_nickname(&identity.id()).unwrap();
        assert_eq!(
            nick.to_string(),
            format!("tornect-{}", identity.id().short())
        );
        let other = HostIdentity::generate().unwrap();
        assert_ne!(nick, service_nickname(&other.id()).unwrap());
    }

    #[test]
    fn install_is_idempotent_and_arti_reads_back_the_same_address() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let cfg = trusting_config(tmp.path());
        let identity = HostIdentity::generate().unwrap();

        let nick = install_identity_key(&cfg, &state_dir, &identity).unwrap();
        let again = install_identity_key(&cfg, &state_dir, &identity).unwrap();
        assert_eq!(nick, again);

        // Exactly what Arti does at launch: look up the public key by nickname.
        let keymgr = open_keymgr(&cfg, &state_dir).unwrap();
        let public = keymgr
            .get::<HsIdKey>(&HsIdPublicKeySpecifier::new(nick.clone()))
            .unwrap()
            .expect("key present");
        assert_eq!(hsid_to_tornect_id(&public.id()).unwrap(), identity.id());

        // Persisted where Arti's layout says it is (docs/research/arti.md §17).
        let key_file = key_file(&state_dir, &nick);
        assert!(key_file.is_file(), "{}", key_file.display());
    }

    #[test]
    fn a_rotated_identity_gets_its_own_keystore_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let cfg = trusting_config(tmp.path());
        let first = HostIdentity::generate().unwrap();
        let second = HostIdentity::generate().unwrap();
        let n1 = install_identity_key(&cfg, &state_dir, &first).unwrap();
        let n2 = install_identity_key(&cfg, &state_dir, &second).unwrap();
        assert_ne!(n1, n2);
        let keymgr = open_keymgr(&cfg, &state_dir).unwrap();
        for (nick, identity) in [(n1, &first), (n2, &second)] {
            let kp = keymgr
                .get::<HsIdKeypair>(&HsIdKeypairSpecifier::new(nick))
                .unwrap()
                .unwrap();
            assert_eq!(
                hsid_to_tornect_id(&HsIdKey::from(&kp).id()).unwrap(),
                identity.id()
            );
        }
    }

    #[test]
    fn a_foreign_key_under_the_nickname_is_refused_not_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let cfg = trusting_config(tmp.path());
        let identity = HostIdentity::generate().unwrap();
        let intruder = HostIdentity::generate().unwrap();
        let nick = service_nickname(&identity.id()).unwrap();

        // Tampering: someone else's key under our nickname.
        let keymgr = open_keymgr(&cfg, &state_dir).unwrap();
        keymgr
            .insert(
                hs_id_keypair(&intruder).unwrap(),
                &HsIdKeypairSpecifier::new(nick.clone()),
                KeystoreSelector::Primary,
                true,
            )
            .unwrap();

        let err = install_identity_key(&cfg, &state_dir, &identity).unwrap_err();
        assert!(
            matches!(&err, SignalError::Keystore(m) if m.contains(&nick.to_string())),
            "{err}"
        );
        // Nothing was replaced.
        let kp = keymgr
            .get::<HsIdKeypair>(&HsIdKeypairSpecifier::new(nick))
            .unwrap()
            .unwrap();
        assert_eq!(
            hsid_to_tornect_id(&HsIdKey::from(&kp).id()).unwrap(),
            intruder.id()
        );
    }

    #[test]
    fn forget_identity_removes_its_keys_and_service_state_only() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let cfg = trusting_config(tmp.path());
        let old = HostIdentity::generate().unwrap();
        let other = HostIdentity::generate().unwrap();
        let old_nick = install_identity_key(&cfg, &state_dir, &old).unwrap();
        let other_nick = install_identity_key(&cfg, &state_dir, &other).unwrap();
        // A file the key manager does not recognize (no extension ⇒ not listed),
        // and the service's state.
        std::fs::write(keystore_dir_for(&state_dir, &old_nick).join("stray"), b"x").unwrap();
        let (old_state, old_lock) = fake_service_state(&state_dir, &old_nick);
        let (other_state, _) = fake_service_state(&state_dir, &other_nick);
        assert!(key_file(&state_dir, &old_nick).is_file());

        let forgotten = forget_identity_in(&cfg, &state_dir, &old.id()).unwrap();
        assert_eq!(
            forgotten,
            ForgottenIdentity {
                keys_removed: 1,
                unrecognized_files_removed: 1,
                state_removed: true,
            }
        );
        assert!(!key_file(&state_dir, &old_nick).exists());
        assert!(!keystore_dir_for(&state_dir, &old_nick).exists());
        assert!(!old_state.exists());
        assert!(!old_lock.exists());
        let keymgr = open_keymgr(&cfg, &state_dir).unwrap();
        assert!(
            keymgr
                .get::<HsIdKeypair>(&HsIdKeypairSpecifier::new(old_nick))
                .unwrap()
                .is_none()
        );

        // The other identity is untouched.
        assert!(key_file(&state_dir, &other_nick).is_file());
        assert!(other_state.join("ipts.json").is_file());
        assert!(
            keymgr
                .get::<HsIdKeypair>(&HsIdKeypairSpecifier::new(other_nick))
                .unwrap()
                .is_some()
        );

        // Forgetting again finds nothing and is not an error.
        assert_eq!(
            forget_identity_in(&cfg, &state_dir, &old.id()).unwrap(),
            ForgottenIdentity::default()
        );
    }

    #[test]
    fn forget_identity_refuses_while_the_service_is_running() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let cfg = trusting_config(tmp.path());
        let identity = HostIdentity::generate().unwrap();
        let nick = install_identity_key(&cfg, &state_dir, &identity).unwrap();
        let (state, lock) = fake_service_state(&state_dir, &nick);

        // What a running `tornect host` holds (tor-persist locks per instance).
        let held = LockFileGuard::try_lock(&lock).unwrap().expect("lock free");
        let err = forget_identity_in(&cfg, &state_dir, &identity.id()).unwrap_err();
        assert!(
            matches!(&err, SignalError::Keystore(m) if m.contains("in use")),
            "{err}"
        );
        // Refused means nothing was touched: the running service keeps reading
        // its identity key back from the keystore (blinded-key derivation at
        // every time period), so the keys must survive, not only the state.
        assert!(state.join("ipts.json").is_file(), "state must survive");
        assert!(lock.is_file(), "lock file must survive");
        assert!(key_file(&state_dir, &nick).is_file(), "key must survive");
        let keymgr = open_keymgr(&cfg, &state_dir).unwrap();
        assert!(
            keymgr
                .get::<HsIdKeypair>(&HsIdKeypairSpecifier::new(nick.clone()))
                .unwrap()
                .is_some()
        );
        drop(held);

        let forgotten = forget_identity_in(&cfg, &state_dir, &identity.id()).unwrap();
        assert_eq!(
            forgotten,
            ForgottenIdentity {
                keys_removed: 1,
                unrecognized_files_removed: 0,
                state_removed: true,
            }
        );
        assert!(!state.exists());
        assert!(!lock.exists());
        assert!(!key_file(&state_dir, &nick).exists());
    }
}
