//! Rotate ID (`docs/PLAN.md` §B.8.9, §B.8.12): a new Tornect ID. Everything
//! unattended is wiped first, by the guard's rotate operation
//! (deny-direction, no re-authentication), which logs `HostIdRotated`; then
//! the old ID's Tor keys and service state go, a new identity seed is
//! written, and the unattended passwords this device remembers for other
//! computers go with the old ID. The command line and the window run this
//! one function; neither logs `HostIdRotated` of its own.

use anyhow::Context as _;
use tornect_core::keystore::{self, load_or_create_host_identity};
use tornect_core::session_log::Actor;
use tornect_core::unattended::credentials::SavedPasswords;
use tornect_core::unattended::guard::MutationGuard;
use tornect_core::{Paths, SecretStore, TornectId};

use crate::ua_client;

/// What a rotation did.
#[derive(Debug)]
pub(crate) struct Rotated {
    /// How many grants the guard wiped.
    pub grants: usize,
    /// The new Tornect ID.
    pub id: TornectId,
    /// The old ID's Tor keys and service state that were removed.
    pub forgotten: tornect_signal::ForgottenIdentity,
    /// How many remembered passwords were deleted, or why not all were.
    pub passwords: anyhow::Result<usize>,
}

/// Rotate the ID of the home `paths` as `by`: `guard`'s rotate operation
/// first, then the identity in `store`; `saved` are this device's remembered
/// passwords (the keychain's, a test's own vault), when it has a device key.
/// The Tor keys are removed before the new seed is written, so a failure
/// there leaves the old identity whole rather than half rotated.
pub(crate) fn rotate_id(
    paths: &Paths,
    guard: &MutationGuard,
    by: Actor,
    store: &dyn SecretStore,
    saved: Option<&SavedPasswords>,
) -> anyhow::Result<Rotated> {
    let grants = guard.rotate_id(by)?;
    let mut forgotten = tornect_signal::ForgottenIdentity::default();
    if store.contains(keystore::HOST_IDENTITY_SEED)? {
        let (old, _) = load_or_create_host_identity(store)?;
        forgotten = tornect_signal::forget_identity(paths, &old.id())
            .context("removing the old Tornect ID from the Tor keystore and state")?;
    }
    let host = keystore::rotate_host_identity(store)?;
    let passwords = saved.map_or(Ok(0), |saved| ua_client::forget_all(paths, saved));
    Ok(Rotated {
        grants,
        id: host.id(),
        forgotten,
        passwords,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tornect_core::keystore::FileSecretStore;
    use tornect_core::session_log::{SessionEvent, SessionLog};
    use tornect_core::unattended::clock::SystemClock;
    use tornect_core::unattended::grant::Preset;
    use tornect_core::unattended::guard::{
        AllowAllPaired, AllowAllReAuth, NoSessionActivity, RandomServerSetupSource,
    };
    use tornect_core::unattended::ipc::GrantOptions;
    use tornect_core::unattended::store::GrantStore;

    use super::*;

    /// §B.8.9, §B.8.12: Rotate ID wipes every grant through the guard, which
    /// logs the one `HostIdRotated` line (by the actor), then gives this home
    /// a new ID and deletes the passwords this device remembers for others,
    /// in a vault of the test's own.
    #[test]
    fn rotate_id_wipes_the_grants_through_the_guard() {
        use tornect_core::unattended::credentials::PasswordVault as _;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        let (old, _) = load_or_create_host_identity(&*secrets).unwrap();
        let log = SessionLog::new(paths.sessions_log());
        let store = GrantStore::open(
            &paths,
            Arc::clone(&secrets) as Arc<dyn SecretStore>,
            Arc::new(SystemClock::default()),
            log.clone(),
        )
        .unwrap();
        let guard = MutationGuard::new(
            store,
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::new(tornect_core::levels::FixedFacts::linux()),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(RandomServerSetupSource));
        guard.master_on(Actor::Cli, &[0x42; 32]).unwrap();
        for i in [1u8, 2] {
            guard
                .create_grant(
                    Actor::Cli,
                    &tornect_core::DeviceId::from_bytes([i; 32]),
                    Preset::HeadlessBox,
                    &GrantOptions::default(),
                    &[0u8; 192],
                    false,
                )
                .unwrap();
        }
        let vault = Arc::new(tornect_core::unattended::credentials::MemoryVault::new());
        let saved = SavedPasswords::new(Some(vault.clone()), [1; 32]);
        let elsewhere = TornectId::from_bytes([5; 32]);
        vault.put(&saved.entry(&elsewhere), "remembered").unwrap();
        let mut known = tornect_core::trusted::KnownHosts::default();
        known.pin(elsewhere, "Desk", [9; 32], 1);
        known
            .save(&tornect_core::trusted::known_hosts_file(&paths))
            .unwrap();

        let rotated = rotate_id(&paths, &guard, Actor::Ui, &*secrets, Some(&saved)).unwrap();
        assert_eq!(rotated.grants, 2);
        assert!(guard.store().grants().is_empty(), "every grant wiped");
        assert_ne!(rotated.id, old.id(), "a new ID");
        let (now, created) = load_or_create_host_identity(&*secrets).unwrap();
        assert!(!created);
        assert_eq!(now.id(), rotated.id, "the new seed is what starts next");
        assert_eq!(rotated.passwords.unwrap(), 1);
        assert!(vault.names().is_empty());
        let rotations: Vec<_> = log
            .read_all()
            .unwrap()
            .into_iter()
            .filter(|r| r.event == SessionEvent::HostIdRotated)
            .collect();
        assert_eq!(rotations.len(), 1, "one line, the guard's");
        assert_eq!(rotations[0].by, Some(Actor::Ui));
    }

    /// Q-3 as the operator ruled: `tornect rotate-id` refuses while a host
    /// holds the unattended store (it opens the store as the command line's
    /// offline route does), and changes nothing.
    #[test]
    fn the_command_line_rotate_id_refuses_while_a_host_holds_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        let (before, _) = load_or_create_host_identity(&*secrets).unwrap();
        let held = GrantStore::open(
            &paths,
            Arc::clone(&secrets) as Arc<dyn SecretStore>,
            Arc::new(SystemClock::default()),
            SessionLog::new(paths.sessions_log()),
        )
        .unwrap();
        let refused = crate::cmd_rotate_id(&paths, true).unwrap_err();
        assert!(
            format!("{refused:#}").contains(crate::ROTATE_NEEDS_TORNECT_CLOSED),
            "{refused:#}"
        );
        let (after, _) = load_or_create_host_identity(&*secrets).unwrap();
        assert_eq!(after.id(), before.id(), "the ID is unchanged");
        drop(held);
    }
}
