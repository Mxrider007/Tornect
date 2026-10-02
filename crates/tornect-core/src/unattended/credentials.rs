//! Remembered unattended passwords (`docs/PLAN.md` §B.8.9.1, B.8.10): the client's
//! "Remember on this device" lives only in an OS keychain, under an entry whose name is
//! computed from the pinned identities at use — never read from a file, since a name read
//! from a file that any program of the user can edit could point one host's entry at
//! another host's password.
//!
//! The name is opaque: `tornect/u/<hex SHA-256("tornect/v1/cred" ‖ own device public key
//! ‖ host onion key)[..16 bytes]>`. No address, name or label reaches the keychain: not in
//! the entry's target, user, comment, label or attributes.
//!
//! What may be remembered (decision M1-67, §B.8.9.1): nothing without a usable keychain; a
//! typed password only after this stream's verified unattended `SESSION_ACCEPT` that signed
//! no administrator level and says `grant_reach = 0`, and never after an `ADMIN_RESULT` (the
//! host marks a password only before it signs an accept). An answer that says 1 or 2, leaves
//! the key out, or that this side refused deletes the remembered password first, before
//! `hosts.toml` is read, and keeps none (C1-C4); a keychain that asks the person before a
//! read changes nothing without a plan change (C12). The `reach` and `administrator` flags of
//! `hosts.toml` only draw the prompt and never decide what is kept. A remembered password
//! goes stale only when it was refused (`AUTH_FAILED`, or this side's own check of the host's
//! PAKE reply, KE2), never on a transport error, a `PREEMPTED` or a refused answer (B.8.4.6,
//! C4).

use std::sync::Arc;

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::Result;
use crate::id::TornectId;
use crate::levels::Elevation;
use crate::unattended::hosts::{HostRecord, HostsFile};

/// The hash domain of an entry name.
const DOMAIN: &[u8] = b"tornect/v1/cred";

/// How many digest bytes an entry name keeps (32 hex characters).
const NAME_BYTES: usize = 16;

/// The prompt's sentence when no keychain can hold a password (§B.8.9.1).
pub const NO_KEYCHAIN: &str =
    "This computer has no system keychain Tornect can use, so the password cannot be remembered.";

/// What the risk copy adds for the Linux kernel keyrings (F4-2): the key is linked into the
/// account's persistent keyring, which outlives a sign-out until it expires a few days after
/// its last use, or the computer restarts, and any process of the account can reach it.
pub const KEYUTILS_KEPT: &str =
    "It stays on this account until a restart, or for a few days after you sign out.";

/// The prompt's sentence where no password is kept: `hosts.toml` says the host's last signed
/// answer reached administrator access, left `grant_reach` out or was refused, or the level
/// is asked for this time (M1-67, C5).
pub const ADMIN_NOT_REMEMBERED: &str = "A password that can give administrator access is never \
    remembered on this computer: its keychain does not ask you before Tornect reads it.";

/// The keychain entry of one host's remembered password. Only [`EntryName::derive`] makes
/// one: there is no parser, so a name can never come from a file.
#[derive(Clone, PartialEq, Eq)]
pub struct EntryName(String);

impl EntryName {
    /// The entry this device (its device public key) keeps for the host whose onion key is
    /// `host_onion_pk`.
    #[must_use]
    pub fn derive(own_device_pk: &[u8; 32], host_onion_pk: &[u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(own_device_pk);
        h.update(host_onion_pk);
        let digest = h.finalize();
        Self(format!("tornect/u/{}", hex::encode(&digest[..NAME_BYTES])))
    }

    /// The name, as the keychain stores it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EntryName {
    /// No digest: two debug lines never link a device and a host.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EntryName(tornect/u/…)")
    }
}

/// Where remembered passwords live: an OS keychain, or [`MemoryVault`] in tests.
pub trait PasswordVault: Send + Sync {
    /// The keychain, as the prompt names it ("Windows Credential Manager").
    fn describe(&self) -> &'static str;
    /// How long the keychain keeps a password, as a sentence the risk copy adds, when that
    /// is not until it is deleted (`None`).
    fn kept(&self) -> Option<&'static str> {
        None
    }
    /// Whether every read asks the person first (Windows Hello, Touch ID). It decides
    /// nothing: a password whose host says it can reach administrator access is not kept in
    /// such a keychain either, until a plan change says otherwise (M1-67, C12).
    fn presence_gated(&self) -> bool;
    /// The password kept under `entry`, if any.
    fn get(&self, entry: &EntryName) -> Result<Option<Zeroizing<String>>>;
    /// Keep `password` under `entry`, replacing what was there.
    fn put(&self, entry: &EntryName, password: &str) -> Result<()>;
    /// Delete `entry`; whether there was one.
    fn delete(&self, entry: &EntryName) -> Result<bool>;
}

/// An in-memory [`PasswordVault`] — **tests only**: not a keychain, forgets at exit.
#[derive(Default)]
pub struct MemoryVault {
    entries: parking_lot::Mutex<std::collections::HashMap<String, Zeroizing<String>>>,
    presence_gated: bool,
    refuse_deletes: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for MemoryVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryVault")
            .field("entries", &self.entries.lock().len())
            .finish_non_exhaustive()
    }
}

impl MemoryVault {
    /// An empty vault that asks nobody before a read.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty vault that stands for a presence-gated keychain.
    #[must_use]
    pub fn presence_gated() -> Self {
        Self {
            presence_gated: true,
            ..Self::default()
        }
    }

    /// The entry names held (for tests that look at what reached the keychain).
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entries.lock().keys().cloned().collect();
        names.sort();
        names
    }

    /// From now on every delete fails, as a keychain that refuses one does (`refuse`), or
    /// works again.
    pub fn refuse_deletes(&self, refuse: bool) {
        self.refuse_deletes
            .store(refuse, std::sync::atomic::Ordering::SeqCst);
    }
}

impl PasswordVault for MemoryVault {
    fn describe(&self) -> &'static str {
        "a test keychain"
    }

    fn presence_gated(&self) -> bool {
        self.presence_gated
    }

    fn get(&self, entry: &EntryName) -> Result<Option<Zeroizing<String>>> {
        Ok(self.entries.lock().get(entry.as_str()).cloned())
    }

    fn put(&self, entry: &EntryName, password: &str) -> Result<()> {
        self.entries.lock().insert(
            entry.as_str().to_owned(),
            Zeroizing::new(password.to_owned()),
        );
        Ok(())
    }

    fn delete(&self, entry: &EntryName) -> Result<bool> {
        if self
            .refuse_deletes
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(std::io::Error::other("the test keychain refused the delete").into());
        }
        Ok(self.entries.lock().remove(entry.as_str()).is_some())
    }
}

/// Whether the prompt offers "Remember on this device", and if not, the sentence it shows
/// instead (none when nothing needs saying).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RememberOffer {
    /// The box is shown, off by default.
    Offered,
    /// No usable keychain: [`NO_KEYCHAIN`].
    NoKeychain,
    /// The host's last signed answer reached administrator access, left `grant_reach` out
    /// or was refused (`hosts.toml`'s `reach`), or the level is asked for: no password is
    /// kept there, whatever the keychain (C5, C12): [`ADMIN_NOT_REMEMBERED`].
    NotForAdministrator,
}

impl RememberOffer {
    /// The sentence shown in place of the box, if any.
    #[must_use]
    pub fn sentence(self) -> Option<&'static str> {
        match self {
            Self::Offered => None,
            Self::NoKeychain => Some(NO_KEYCHAIN),
            Self::NotForAdministrator => Some(ADMIN_NOT_REMEMBERED),
        }
    }
}

/// How one unattended session attempt ended, as far as the remembered password is
/// concerned (M1-67). A verified `ADMIN_RESULT` is settled by
/// [`SavedPasswords::settle_admin`], which takes no password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// The host's unattended `SESSION_ACCEPT` verified (C1): the level it signed and its
    /// `grant_reach` (key 12; `None` when the host left it out, so the reach is unknown).
    Accepted {
        /// The administrator level the accept signed.
        elevation: Elevation,
        /// What the password just proven can reach through Tornect on the host: 0 none,
        /// 1 through the host, 2 this grant holds the level.
        grant_reach: Option<u8>,
    },
    /// This side refused the host's `SESSION_ACCEPT` or `ADMIN_RESULT` (its decoding, its
    /// signature, `token_confirm`, `quic_spki`, `session_type` or F-8): the remembered
    /// password is deleted, and not marked stale (C4).
    AnswerRefused,
    /// The password was not proven: the host's `AUTH_FAILED`, or this side's own check of
    /// the host's PAKE reply, KE2 (a wrong password or a re-registered grant).
    PasswordRefused,
    /// Nothing was learned about the password: the host was not reached, the stream broke,
    /// a newer request pre-empted this one, or a reject before or after the password
    /// counted (other than `AUTH_FAILED`).
    Inconclusive,
}

impl Attempt {
    /// C1: a verified answer reaches when it signed the administrator level or its
    /// `grant_reach` is anything but `Some(0)` (1, 2, or left out). Taken from that answer
    /// alone, never from `hosts.toml`.
    #[must_use]
    pub fn reaches(elevation: Elevation, grant_reach: Option<u8>) -> bool {
        elevation == Elevation::Admin || grant_reach != Some(0)
    }

    /// Whether this attempt deletes the remembered password before anything else,
    /// `hosts.toml` included (C2 step 1, C4): an accept that reaches, or a refused answer.
    #[must_use]
    pub fn deletes_first(self) -> bool {
        match self {
            Self::Accepted {
                elevation,
                grant_reach,
            } => Self::reaches(elevation, grant_reach),
            Self::AnswerRefused => true,
            Self::PasswordRefused | Self::Inconclusive => false,
        }
    }
}

/// What a delete by the derived name did ([`SavedPasswords::delete_first`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deleted {
    /// There was no entry, or no usable keychain.
    Nothing,
    /// The entry was deleted.
    Entry,
    /// The keychain refused the delete: the entry may still be there (C7).
    Refused,
}

/// What [`SavedPasswords::settle`] or [`SavedPasswords::settle_admin`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Settled {
    /// A password is kept in the keychain for the host now.
    pub remembered: bool,
    /// A remembered password was deleted: it was refused, or the host's answer reached
    /// administrator access, left `grant_reach` out or was refused.
    pub forgot: bool,
    /// The keychain refused to delete it: `remember` stays set, so that the check when the
    /// prompt opens deletes it (C6, C7).
    pub delete_failed: bool,
    /// `hosts.toml` changed and needs saving.
    pub changed: bool,
}

/// Set `flag` to `to`, noting a change.
fn set(flag: &mut bool, to: bool, changed: &mut bool) {
    if *flag != to {
        *flag = to;
        *changed = true;
    }
}

/// This device's remembered passwords: a keychain (if one is usable) and the device key the
/// entry names derive from.
#[derive(Clone)]
pub struct SavedPasswords {
    vault: Option<Arc<dyn PasswordVault>>,
    device_pk: [u8; 32],
}

impl std::fmt::Debug for SavedPasswords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SavedPasswords")
            .field("keychain", &self.vault.as_ref().map(|v| v.describe()))
            .finish_non_exhaustive()
    }
}

impl SavedPasswords {
    /// `vault` (`None`: no usable keychain) for the device whose public key is `device_pk`.
    #[must_use]
    pub fn new(vault: Option<Arc<dyn PasswordVault>>, device_pk: [u8; 32]) -> Self {
        Self { vault, device_pk }
    }

    /// No keychain: nothing is ever remembered.
    #[must_use]
    pub fn none(device_pk: [u8; 32]) -> Self {
        Self::new(None, device_pk)
    }

    /// The keychain's name, if one is usable.
    #[must_use]
    pub fn keychain(&self) -> Option<&'static str> {
        self.vault.as_ref().map(|v| v.describe())
    }

    /// How long the keychain keeps a password, when that is not until it is deleted: the
    /// sentence the risk copy adds ([`PasswordVault::kept`]).
    #[must_use]
    pub fn kept(&self) -> Option<&'static str> {
        self.vault.as_ref().and_then(|v| v.kept())
    }

    /// The entry of `host`, computed now from the identities (never read from a file).
    #[must_use]
    pub fn entry(&self, host: &TornectId) -> EntryName {
        EntryName::derive(&self.device_pk, host.public_key_bytes())
    }

    /// Whether "Remember on this device" is offered for a host: `reach` when its saved
    /// record says its last signed answer reached administrator access, left `grant_reach`
    /// out or was refused, or the person asks for the level this time (C5). A presence gate
    /// changes nothing (C12). The answer still decides what is kept (C1).
    #[must_use]
    pub fn offer(&self, reach: bool) -> RememberOffer {
        match &self.vault {
            None => RememberOffer::NoKeychain,
            Some(_) if reach => RememberOffer::NotForAdministrator,
            Some(_) => RememberOffer::Offered,
        }
    }

    /// The password remembered for `host`, if the record says one was and the keychain
    /// still holds it.
    pub fn recall(&self, hosts: &HostsFile, host: &TornectId) -> Result<Option<Zeroizing<String>>> {
        let Some(vault) = &self.vault else {
            return Ok(None);
        };
        if !hosts.get(host).is_some_and(|r| r.remember) {
            return Ok(None);
        }
        vault.get(&self.entry(host))
    }

    /// Delete the keychain entry of `host` by its derived name, whatever a file says of it
    /// (Forget before its file is read, Rotate ID, a save that failed after the entry was
    /// written: F4-5); whether there was one. Deleting a missing entry is harmless.
    pub fn erase(&self, host: &TornectId) -> Result<bool> {
        match &self.vault {
            Some(vault) => vault.delete(&self.entry(host)),
            None => Ok(false),
        }
    }

    /// Delete the entry of `host` from the keychain and the record's `remember` flag (Forget,
    /// Rotate ID, a refused password); whether `hosts` changed.
    pub fn forget(&self, hosts: &mut HostsFile, host: &TornectId) -> Result<bool> {
        self.erase(host)?;
        Ok(match hosts.hosts.get_mut(&host.onion_address()) {
            Some(r) if r.remember => {
                r.remember = false;
                true
            }
            _ => false,
        })
    }

    /// C2 step 1, C4: delete `host`'s entry by its derived name. A caller deletes with this
    /// before it reads `hosts.toml`, so that a file that cannot be read or saved does not
    /// stop the delete (ST-4).
    #[must_use]
    pub fn delete_first(&self, host: &TornectId) -> Deleted {
        match self.erase(host) {
            Ok(true) => Deleted::Entry,
            Ok(false) => Deleted::Nothing,
            Err(_) => Deleted::Refused,
        }
    }

    /// C6: when the prompt opens and before a command-line dial, a record that says both
    /// that the host's last answer reached and that a password is remembered (a delete the
    /// keychain refused, C7, or an edited file) has its entry deleted first; `remember` is
    /// cleared once the delete worked. `None` when the record asks for nothing.
    pub fn belt(&self, hosts: &mut HostsFile, host: &TornectId) -> Option<Deleted> {
        if !hosts.get(host).is_some_and(|r| r.reach && r.remember) {
            return None;
        }
        let gone = self.delete_first(host);
        if gone != Deleted::Refused {
            hosts.entry(host).remember = false;
        }
        Some(gone)
    }

    /// Settle one session attempt at `host` (M1-67, C1-C5). `first`: what
    /// [`Self::delete_first`] did when the caller deleted before it read `hosts.toml`;
    /// `None` deletes here, before `hosts` is touched, when the attempt asks for it.
    /// `remember`: the password typed, when the person ticked "Remember on this device".
    ///
    /// The answer alone decides (C1), never the flags of `hosts`. An accept that reaches,
    /// or a refused answer, keeps nothing typed and deletes the remembered password (C2,
    /// C4); an accept of `grant_reach = 0` without the level keeps a typed password only
    /// when Remember was ticked, deleting any entry under the name before it writes, and
    /// leaves a remembered one in place (C3). A refused password is deleted and the record
    /// marked stale; a transport error, a `PREEMPTED` or a reject changes nothing.
    pub fn settle(
        &self,
        hosts: &mut HostsFile,
        host: &TornectId,
        attempt: Attempt,
        first: Option<Deleted>,
        remember: Option<&str>,
    ) -> Result<Settled> {
        let mut out = Settled::default();
        match attempt {
            Attempt::Inconclusive => {
                out.remembered = hosts.get(host).is_some_and(|r| r.remember);
            }
            Attempt::PasswordRefused => {
                let had = hosts.get(host).is_some_and(|r| r.remember);
                out.changed |= self.forget(hosts, host)?;
                if had {
                    hosts.entry(host).stale = true;
                    out.forgot = true;
                    out.changed = true;
                }
            }
            Attempt::AnswerRefused => {
                let gone = first.unwrap_or_else(|| self.delete_first(host));
                reached(hosts.entry(host), gone, false, &mut out);
            }
            Attempt::Accepted {
                elevation,
                grant_reach,
            } => {
                if Attempt::reaches(elevation, grant_reach) {
                    let gone = first.unwrap_or_else(|| self.delete_first(host));
                    let record = hosts.entry(host);
                    set(&mut record.stale, false, &mut out.changed);
                    reached(record, gone, grant_reach == Some(2), &mut out);
                } else {
                    let record = hosts.entry(host);
                    set(&mut record.stale, false, &mut out.changed);
                    not_reached(record, &mut out);
                    if let (Some(password), Some(vault)) = (remember, &self.vault) {
                        // ST-8: a delete reaches every link of the key, a write may not.
                        let entry = self.entry(host);
                        vault.delete(&entry)?;
                        vault.put(&entry, password)?;
                        set(&mut hosts.entry(host).remember, true, &mut out.changed);
                    }
                    out.remembered = hosts.get(host).is_some_and(|r| r.remember);
                }
            }
        }
        Ok(out)
    }

    /// Settle a verified `ADMIN_RESULT` at `host`. It never keeps a password, so it takes
    /// none: the host marks a password only before it signs an accept (DA-15). An answer
    /// that reaches (`grant_reach` other than `Some(0)`) deletes the remembered password as
    /// an accept does (C2); at 0 a remembered one stays (C3). `first` as for
    /// [`Self::settle`].
    pub fn settle_admin(
        &self,
        hosts: &mut HostsFile,
        host: &TornectId,
        grant_reach: Option<u8>,
        first: Option<Deleted>,
    ) -> Settled {
        let mut out = Settled::default();
        if Attempt::reaches(Elevation::None, grant_reach) {
            let gone = first.unwrap_or_else(|| self.delete_first(host));
            let record = hosts.entry(host);
            set(&mut record.stale, false, &mut out.changed);
            reached(record, gone, grant_reach == Some(2), &mut out);
        } else {
            let record = hosts.entry(host);
            set(&mut record.stale, false, &mut out.changed);
            not_reached(record, &mut out);
            out.remembered = record.remember;
        }
        out
    }
}

/// C2 steps 2 and 3 (C4 likewise), after the delete: `reach` set, `administrator` to whether
/// the answer said 2, `remember` cleared unless the keychain refused the delete (C7: it
/// stays set, so that the prompt's check deletes it), nothing kept.
fn reached(record: &mut HostRecord, gone: Deleted, administrator: bool, out: &mut Settled) {
    set(&mut record.reach, true, &mut out.changed);
    set(&mut record.administrator, administrator, &mut out.changed);
    if gone == Deleted::Refused {
        out.delete_failed = true;
    } else {
        out.forgot = gone == Deleted::Entry || record.remember;
        set(&mut record.remember, false, &mut out.changed);
    }
    out.remembered = false;
}

/// C3: an answer of 0 clears both flags.
fn not_reached(record: &mut HostRecord, out: &mut Settled) {
    set(&mut record.reach, false, &mut out.changed);
    set(&mut record.administrator, false, &mut out.changed);
}

#[cfg(feature = "keyring")]
pub use self::keychain::{KeychainVault, system_vault};

/// The OS keychains, through `keyring-core` (the `keyring` feature).
#[cfg(feature = "keyring")]
mod keychain {
    use std::collections::HashMap;
    use std::sync::Arc;

    use keyring_core::{CredentialStore, Error as KcError};
    use zeroize::Zeroizing;

    use super::{EntryName, PasswordVault};
    use crate::error::{CoreError, Result};

    /// Which keychain a [`KeychainVault`] wraps: it decides the modifiers that put the
    /// opaque name, and nothing else, into the entry.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Kind {
        /// Windows Credential Manager: the name is the target, the user and the comment
        /// stay empty, `CRED_PERSIST_LOCAL_MACHINE` (never enterprise: no roaming).
        #[cfg_attr(not(windows), allow(dead_code))]
        Windows,
        /// The Linux kernel keyrings (keyutils): the name is the key's description; the key
        /// is gone at reboot, and a few days after sign-out (the persistent keyring's
        /// expiry).
        #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
        Keyutils,
    }

    impl Kind {
        /// The keychain as the prompt names it: on Linux the key is the account's, not one
        /// sign-in's (F4-2).
        fn describe(self) -> &'static str {
            match self {
                Self::Windows => "Windows Credential Manager",
                Self::Keyutils => "the kernel keyring of your user account",
            }
        }

        /// How long it keeps a password, when that is not until it is deleted.
        fn kept(self) -> Option<&'static str> {
            match self {
                Self::Windows => None,
                Self::Keyutils => Some(super::KEYUTILS_KEPT),
            }
        }
    }

    /// A [`PasswordVault`] over a `keyring-core` store.
    pub struct KeychainVault {
        store: Arc<CredentialStore>,
        kind: Kind,
    }

    impl std::fmt::Debug for KeychainVault {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("KeychainVault")
                .field("kind", &self.kind)
                .finish_non_exhaustive()
        }
    }

    fn map_err(e: KcError) -> CoreError {
        match e {
            KcError::NoStorageAccess(inner) => CoreError::KeychainLocked(inner.to_string()),
            other => CoreError::Keychain(other.to_string()),
        }
    }

    impl KeychainVault {
        fn entry(&self, name: &EntryName) -> Result<keyring_core::Entry> {
            let modifiers: HashMap<&str, &str> = match self.kind {
                Kind::Windows => {
                    HashMap::from([("target", name.as_str()), ("persistence", "Local")])
                }
                Kind::Keyutils => HashMap::from([("description", name.as_str())]),
            };
            // The user is irrelevant with an explicit target or description: the name above
            // is all the keychain records about the entry.
            self.store
                .build(crate::unattended::keyring::SERVICE, "", Some(&modifiers))
                .map_err(map_err)
        }

        /// Whether the keychain answers: a read of an entry that does not exist says
        /// "no entry" when it does, and "no storage access" when it is locked or absent.
        fn usable(&self) -> bool {
            let probe = EntryName::derive(&[0u8; 32], &[0u8; 32]);
            self.entry(&probe)
                .is_ok_and(|e| matches!(e.get_password(), Ok(_) | Err(KcError::NoEntry)))
        }

        /// Windows Credential Manager, if it answers.
        #[cfg(windows)]
        pub fn windows() -> Option<Self> {
            let store = windows_native_keyring_store::Store::new().ok()?;
            let vault = Self {
                store,
                kind: Kind::Windows,
            };
            vault.usable().then_some(vault)
        }

        /// The Linux kernel keyrings, if this session has one.
        #[cfg(target_os = "linux")]
        pub fn keyutils() -> Option<Self> {
            let store = linux_keyutils_keyring_store::Store::new().ok()?;
            let vault = Self {
                store,
                kind: Kind::Keyutils,
            };
            vault.usable().then_some(vault)
        }
    }

    impl PasswordVault for KeychainVault {
        fn describe(&self) -> &'static str {
            self.kind.describe()
        }

        fn kept(&self) -> Option<&'static str> {
            self.kind.kept()
        }

        fn presence_gated(&self) -> bool {
            // Neither asks the person before a read; Windows Hello gating is not built.
            false
        }

        fn get(&self, name: &EntryName) -> Result<Option<Zeroizing<String>>> {
            match self.entry(name)?.get_password() {
                Ok(p) => Ok(Some(Zeroizing::new(p))),
                Err(KcError::NoEntry) => Ok(None),
                Err(e) => Err(map_err(e)),
            }
        }

        fn put(&self, name: &EntryName, password: &str) -> Result<()> {
            self.entry(name)?.set_password(password).map_err(map_err)
        }

        fn delete(&self, name: &EntryName) -> Result<bool> {
            match self.entry(name)?.delete_credential() {
                Ok(()) => Ok(true),
                Err(KcError::NoEntry) => Ok(false),
                Err(e) => Err(map_err(e)),
            }
        }
    }

    /// This computer's keychain for remembered passwords, if one is usable: Windows
    /// Credential Manager on Windows, the kernel keyrings on Linux (the Secret Service is
    /// not built: its store crate needs dependencies outside this tree), none elsewhere.
    #[must_use]
    pub fn system_vault() -> Option<Arc<dyn PasswordVault>> {
        #[cfg(windows)]
        {
            KeychainVault::windows().map(|v| Arc::new(v) as Arc<dyn PasswordVault>)
        }
        #[cfg(target_os = "linux")]
        {
            KeychainVault::keyutils().map(|v| Arc::new(v) as Arc<dyn PasswordVault>)
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            None
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    mod tests {
        use super::*;

        /// F4-2: the Linux keychain is named for the account, never for one sign-in, and
        /// the risk copy says how long it keeps a password; Windows keeps it until it is
        /// deleted, so nothing is added there.
        #[test]
        fn the_kernel_keyring_is_named_for_the_account_and_its_lifetime() {
            assert_eq!(
                Kind::Keyutils.describe(),
                "the kernel keyring of your user account"
            );
            assert_eq!(
                Kind::Keyutils.kept(),
                Some(
                    "It stays on this account until a restart, or for a few days after you \
                     sign out."
                )
            );
            assert_eq!(Kind::Windows.describe(), "Windows Credential Manager");
            assert_eq!(Kind::Windows.kept(), None);
        }

        /// The entry a keyutils vault builds carries the opaque name as its whole
        /// description; nothing else of the host reaches the keychain. Needs a kernel
        /// keyring: run with `--ignored`.
        #[test]
        #[ignore = "needs a Linux kernel keyring available to the test user"]
        fn a_keyutils_vault_keeps_a_password_under_the_opaque_name_only() {
            let vault = KeychainVault::keyutils().expect("a kernel keyring");
            let name = EntryName::derive(&[0x42; 32], &[std::process::id() as u8; 32]);
            assert_eq!(vault.get(&name).unwrap(), None);
            vault
                .put(&name, "quiet verdant otter lantern zephyr")
                .unwrap();
            assert_eq!(
                vault.get(&name).unwrap().as_deref().map(String::as_str),
                Some("quiet verdant otter lantern zephyr")
            );
            let attributes = vault.entry(&name).unwrap().get_attributes().unwrap();
            assert!(
                attributes.values().all(|v| !v.contains("onion")),
                "{attributes:?}"
            );
            assert!(vault.delete(&name).unwrap());
            assert!(!vault.delete(&name).unwrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unattended::hosts::HostsFile;

    /// The golden vector of the entry name: the domain string, the device key, then the
    /// onion key, SHA-256, the first 16 bytes in lower-case hex.
    #[test]
    fn the_entry_name_is_the_documented_digest() {
        let name = EntryName::derive(&[0x11; 32], &[0x22; 32]);
        let mut h = Sha256::new();
        h.update(b"tornect/v1/cred");
        h.update([0x11; 32]);
        h.update([0x22; 32]);
        let expected = format!("tornect/u/{}", hex::encode(&h.finalize()[..16]));
        assert_eq!(name.as_str(), expected);
        assert_eq!(
            name.as_str(),
            "tornect/u/97a23fa3178ccf999aed571416258ed2",
            "golden vector"
        );
        assert_eq!(name.as_str().len(), "tornect/u/".len() + 32);
        // Both keys count, in order.
        assert_ne!(name, EntryName::derive(&[0x22; 32], &[0x11; 32]));
        assert_ne!(name, EntryName::derive(&[0x11; 32], &[0x23; 32]));
        assert_eq!(format!("{name:?}"), "EntryName(tornect/u/…)");
    }

    fn host(n: u8) -> TornectId {
        TornectId::from_bytes([n; 32])
    }

    /// An accept of `grant_reach = 0` without the level: what may be kept (C3).
    const ZERO: Attempt = Attempt::Accepted {
        elevation: Elevation::None,
        grant_reach: Some(0),
    };

    /// M1-67 (C5, C12): Remember is offered only with a usable keychain, and never where
    /// the host's last answer reached administrator access, left the key out or was
    /// refused, or the level is asked for; a keychain that asks the person first changes
    /// nothing.
    #[test]
    fn remember_is_offered_only_with_a_keychain_and_never_for_administrator_without_a_gate() {
        let none = SavedPasswords::none([1; 32]);
        assert_eq!(none.offer(false), RememberOffer::NoKeychain);
        assert_eq!(none.offer(true), RememberOffer::NoKeychain);
        assert_eq!(RememberOffer::NoKeychain.sentence(), Some(NO_KEYCHAIN));
        let plain = SavedPasswords::new(Some(Arc::new(MemoryVault::new())), [1; 32]);
        assert_eq!(plain.offer(false), RememberOffer::Offered);
        assert_eq!(plain.offer(true), RememberOffer::NotForAdministrator);
        assert_eq!(RememberOffer::Offered.sentence(), None);
        let gated = SavedPasswords::new(Some(Arc::new(MemoryVault::presence_gated())), [1; 32]);
        assert_eq!(gated.offer(false), RememberOffer::Offered);
        assert_eq!(gated.offer(true), RememberOffer::NotForAdministrator);
    }

    #[test]
    fn a_password_is_kept_after_an_accept_and_stale_only_when_refused() {
        let vault = Arc::new(MemoryVault::new());
        let saved = SavedPasswords::new(Some(vault.clone()), [1; 32]);
        let mut hosts = HostsFile::default();
        let h = host(7);
        // A refusal before anything is kept remembers nothing.
        let s = saved
            .settle(&mut hosts, &h, Attempt::PasswordRefused, None, Some("pw"))
            .unwrap();
        assert!(!s.remembered && !s.forgot);
        assert!(vault.names().is_empty());
        // An accept keeps it, under the derived name only.
        let s = saved
            .settle(&mut hosts, &h, ZERO, None, Some("pw"))
            .unwrap();
        assert!(s.remembered && s.changed);
        assert_eq!(vault.names(), vec![saved.entry(&h).as_str().to_owned()]);
        assert_eq!(
            saved
                .recall(&hosts, &h)
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("pw")
        );
        // Neither a transport error nor a pre-emption makes it stale.
        for _ in 0..3 {
            let s = saved
                .settle(&mut hosts, &h, Attempt::Inconclusive, None, None)
                .unwrap();
            assert!(s.remembered && !s.forgot && !s.changed);
        }
        assert!(!hosts.get(&h).unwrap().stale);
        // A refusal does: the entry goes, the record says why.
        let s = saved
            .settle(&mut hosts, &h, Attempt::PasswordRefused, None, None)
            .unwrap();
        assert!(s.forgot && !s.remembered && s.changed);
        assert!(vault.names().is_empty());
        assert!(hosts.get(&h).unwrap().stale);
        assert_eq!(saved.recall(&hosts, &h).unwrap(), None);
        // The next accept clears the mark; without Remember nothing is kept.
        saved.settle(&mut hosts, &h, ZERO, None, None).unwrap();
        let r = hosts.get(&h).unwrap();
        assert!(!r.stale && !r.remember);
        assert!(vault.names().is_empty());
    }

    /// M1-67 (C1, C2, C12): an accept that says 2 deletes the remembered password even when
    /// the level was not asked for, and keeps nothing typed; so do an accept that says 1,
    /// one that leaves the key out and one that signs the level. A keychain that asks the
    /// person first keeps nothing either. The record says so, for the prompt only.
    #[test]
    fn an_administrator_grant_keeps_no_password_without_a_presence_gate() {
        for gated in [false, true] {
            let vault = Arc::new(if gated {
                MemoryVault::presence_gated()
            } else {
                MemoryVault::new()
            });
            let saved = SavedPasswords::new(Some(vault.clone()), [1; 32]);
            for (elevation, grant_reach) in [
                (Elevation::None, Some(2)),
                (Elevation::None, Some(1)),
                (Elevation::None, None),
                (Elevation::Admin, Some(2)),
            ] {
                let mut hosts = HostsFile::default();
                let h = host(9);
                saved
                    .settle(&mut hosts, &h, ZERO, None, Some("pw"))
                    .unwrap();
                assert_eq!(vault.names().len(), 1);
                let reaching = Attempt::Accepted {
                    elevation,
                    grant_reach,
                };
                let s = saved
                    .settle(&mut hosts, &h, reaching, None, Some("pw"))
                    .unwrap();
                let case = format!("{gated} {elevation:?} {grant_reach:?}");
                assert!(s.forgot && !s.remembered && !s.delete_failed, "{case}");
                assert!(vault.names().is_empty(), "{case}");
                let r = hosts.get(&h).unwrap();
                assert!(r.reach && !r.remember && !r.stale, "{case}");
                assert_eq!(r.administrator, grant_reach == Some(2), "{case}");
                assert_eq!(
                    saved.offer(r.reach),
                    RememberOffer::NotForAdministrator,
                    "{case}"
                );
            }
        }
    }

    /// C1 (`settle` never reads the cache flags): over every start of the record's four
    /// flags, with and without an entry already kept, every answer and the tick, the
    /// keychain ends as the answer alone says, and so do the flags.
    #[test]
    fn settle_decides_from_the_body_never_from_the_flags() {
        let answers = [
            (Elevation::None, None),
            (Elevation::None, Some(0)),
            (Elevation::None, Some(1)),
            (Elevation::None, Some(2)),
            (Elevation::Admin, None),
            (Elevation::Admin, Some(0)),
            (Elevation::Admin, Some(2)),
        ];
        for bits in 0u8..16 {
            for kept_before in [false, true] {
                for (elevation, grant_reach) in answers {
                    for tick in [false, true] {
                        let vault = Arc::new(MemoryVault::new());
                        let saved = SavedPasswords::new(Some(vault.clone()), [1; 32]);
                        let h = host(4);
                        let mut hosts = HostsFile::default();
                        let r = hosts.entry(&h);
                        r.reach = bits & 1 != 0;
                        r.administrator = bits & 2 != 0;
                        r.remember = bits & 4 != 0;
                        r.stale = bits & 8 != 0;
                        if kept_before {
                            vault.put(&saved.entry(&h), "old").unwrap();
                        }
                        let answer = Attempt::Accepted {
                            elevation,
                            grant_reach,
                        };
                        let s = saved
                            .settle(&mut hosts, &h, answer, None, tick.then_some("typed"))
                            .unwrap();
                        let now = vault.get(&saved.entry(&h)).unwrap();
                        let now = now.as_deref().map(String::as_str);
                        let r = hosts.get(&h).unwrap();
                        let case = format!(
                            "{bits:04b} {kept_before} {elevation:?} {grant_reach:?} {tick}"
                        );
                        if elevation == Elevation::Admin || grant_reach != Some(0) {
                            assert_eq!(now, None, "{case}");
                            assert!(!s.remembered && !r.remember && r.reach, "{case}");
                            assert_eq!(r.administrator, grant_reach == Some(2), "{case}");
                        } else {
                            let expected = match (tick, kept_before) {
                                (true, _) => Some("typed"),
                                (false, true) => Some("old"),
                                (false, false) => None,
                            };
                            assert_eq!(now, expected, "{case}");
                            assert!(!r.reach && !r.administrator, "{case}");
                            assert_eq!(r.remember, tick || bits & 4 != 0, "{case}");
                        }
                        assert!(!r.stale, "{case}");
                    }
                }
            }
        }
    }

    /// C4: a refused answer deletes the remembered password and does not mark it stale:
    /// the record says only that the reach is unknown, and the next accept of 0 may keep a
    /// ticked password again (C10).
    #[test]
    fn a_refused_accept_deletes_and_is_not_stale() {
        let vault = Arc::new(MemoryVault::new());
        let saved = SavedPasswords::new(Some(vault.clone()), [1; 32]);
        let mut hosts = HostsFile::default();
        let h = host(6);
        saved
            .settle(&mut hosts, &h, ZERO, None, Some("pw"))
            .unwrap();
        let s = saved
            .settle(&mut hosts, &h, Attempt::AnswerRefused, None, Some("pw"))
            .unwrap();
        assert!(s.forgot && !s.remembered && s.changed);
        assert!(vault.names().is_empty());
        let r = hosts.get(&h).unwrap();
        assert!(!r.stale && !r.remember && r.reach && !r.administrator);
        saved
            .settle(&mut hosts, &h, ZERO, None, Some("pw"))
            .unwrap();
        assert!(!hosts.get(&h).unwrap().reach);
        assert_eq!(vault.names().len(), 1);
    }

    #[test]
    fn forget_deletes_the_entry_and_the_flag() {
        let vault = Arc::new(MemoryVault::new());
        let saved = SavedPasswords::new(Some(vault.clone()), [1; 32]);
        let mut hosts = HostsFile::default();
        let h = host(3);
        saved
            .settle(&mut hosts, &h, ZERO, None, Some("pw"))
            .unwrap();
        assert!(saved.forget(&mut hosts, &h).unwrap());
        assert!(vault.names().is_empty());
        assert!(!hosts.get(&h).unwrap().remember);
        assert!(!saved.forget(&mut hosts, &h).unwrap());
    }

    /// F4-5: an entry goes by its derived name alone, with no file that flags it; a
    /// second delete, or one without a keychain, is harmless.
    #[test]
    fn erase_deletes_the_entry_whatever_a_file_says() {
        let vault = Arc::new(MemoryVault::new());
        let saved = SavedPasswords::new(Some(vault.clone()), [1; 32]);
        let h = host(5);
        vault.put(&saved.entry(&h), "pw").unwrap();
        assert!(saved.erase(&h).unwrap());
        assert!(vault.names().is_empty());
        assert!(!saved.erase(&h).unwrap());
        assert!(!SavedPasswords::none([1; 32]).erase(&h).unwrap());
    }
}
