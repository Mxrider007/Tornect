//! [`MutationGuard`] — the single enforcement point of `docs/PLAN.md` §B.8.6.2 for
//! UI, IPC and CLI, and the traits it consumes, **defined here** (§B.8.14 *Ownership*):
//! [`ReAuth`] (OS implementations in `tornect-platform::reauth`),
//! [`RemoteSessionActivity`] (`tornect-session`; the offline CLI passes
//! [`NoSessionActivity`]), [`Presence`] (M1 stub [`UnknownPresence`]: `Unknown` ⇒
//! present), [`AttendedHistory`] (M1 stub [`SessionLogHistory`]) and [`PairedDevices`]
//! (default [`FilePairedDevices`] over `trusted-devices.toml`: grants exist only for
//! SAS-paired devices, §B.8 hard rule 2 / §B.8.6.1).
//!
//! Classes: **deny-direction** operations need nothing; **access-increasing** ones need
//! no remote session live and none ended < 60 s ago *and* a fresh [`ReAuth`] call per
//! operation — the session check is repeated after the dialog returns, because an
//! unattended session needs no local click and can start while the dialog is up;
//! **remote admin** requests are scoped by the requester's grant (§B.8.4.1). Every
//! mutation writes its `sessions.log` event, every refusal a
//! `GrantMutationRefused{code}` line.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::id::DeviceId;
use crate::session_log::{Actor, SessionEvent, SessionLog, SessionRecord};
use crate::trusted::TrustedDevices;

use super::codec::StoreLoadError;
use super::grant::{
    AuthRecord, GrantId, GrantState, Preset, SuspendReason, UnattendedGrant, sanitize_label,
};
use super::ipc::{GrantOptions, codes};
use super::store::{GrantStore, StoreError, StoreStatus, WriteClass, push_tombstone};

/// A remote session must have ended at least this long ago (§B.8.6.2).
pub const REMOTE_SESSION_COOLDOWN: Duration = Duration::from_secs(60);
/// A `reg_txn` lives this long (§B.8.7.4).
pub const REG_TXN_TTL: Duration = Duration::from_secs(120);
/// Length of the emergency stop code (§B.8.7.4).
pub const STOP_CODE_LEN: usize = 16;

/// Why OS re-authentication did not succeed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReAuthError {
    /// The user cancelled or failed the dialog.
    #[error("re-authentication denied")]
    Denied,
    /// No backend on this host (headless without polkit/PAM, release build without one).
    #[error("re-authentication unavailable: {0}")]
    Unavailable(String),
    /// The backend failed.
    #[error("re-authentication failed: {0}")]
    Failed(String),
}

/// OS re-authentication — a blocking dialog, run on `spawn_blocking`; a fresh dialog per
/// operation (`op` names it).
pub trait ReAuth: Send + Sync {
    /// Prove the OS user is present and knows the OS credential.
    fn reauthenticate(&self, op: &str) -> Result<(), ReAuthError>;
}

/// Whether a remote session is live or recently ended.
pub trait RemoteSessionActivity: Send + Sync {
    /// When the last remote session ended (`None` = never).
    fn last_session_ended_at(&self) -> Option<Instant>;
    /// Whether a remote session is live now.
    fn session_live(&self) -> bool;
}

/// Physical-input presence (§B.8.6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceState {
    /// Someone touched the host recently.
    Present,
    /// No physical input since `since`.
    Absent {
        /// Start of the idle period.
        since: Instant,
    },
    /// Not probed (M1): treated as present.
    Unknown,
}

impl PresenceState {
    /// The rule of §B.8.6.3: unknown ⇒ present.
    #[must_use]
    pub fn treated_as_present(self) -> bool {
        !matches!(self, Self::Absent { .. })
    }
}

/// Presence source; OS implementations in `tornect-platform` (M6).
pub trait Presence: Send + Sync {
    /// Current state.
    fn state(&self) -> PresenceState;
}

/// The M1 presence stub: always [`PresenceState::Unknown`].
#[derive(Debug, Default, Clone, Copy)]
pub struct UnknownPresence;

impl Presence for UnknownPresence {
    fn state(&self) -> PresenceState {
        PresenceState::Unknown
    }
}

/// Completed attended sessions per device (the grant precondition of §B.8.6.1).
pub trait AttendedHistory: Send + Sync {
    /// How many attended sessions from `device` completed.
    fn completed_attended_sessions(&self, device: &DeviceId) -> u32;
}

/// M1 [`AttendedHistory`]: counts `session_ended` lines with `unattended = false` in
/// `sessions.log` and its retained rotated files (a device's attended sessions may
/// predate a 10 MiB rotation).
///
/// Trust limit: the lines are read as data, not checked against the chain — any
/// same-uid writer can append one. The precondition it feeds sits behind OS
/// re-authentication and is waivable, so the two factors of §B.8 are unaffected; once
/// the app owns the log (M4) the count is restricted to lines at or below the head the
/// verifier accepted (`docs/VERIFICATION.md`, OPEN row).
#[derive(Debug, Clone)]
pub struct SessionLogHistory {
    log: SessionLog,
}

impl SessionLogHistory {
    /// Read from the given log.
    #[must_use]
    pub fn new(log: SessionLog) -> Self {
        Self { log }
    }
}

impl AttendedHistory for SessionLogHistory {
    fn completed_attended_sessions(&self, device: &DeviceId) -> u32 {
        self.log
            .read_all_including_rotated()
            .map(|records| {
                records
                    .iter()
                    .filter(|r| {
                        r.event == SessionEvent::SessionEnded
                            && !r.unattended
                            && r.peer_device.as_ref() == Some(device)
                    })
                    .count()
            })
            .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX))
    }
}

/// The SAS-pairing precondition of every grant (§B.8 hard rule 2, §B.8.6.1, §B.8.9
/// "must exist in `trusted-devices.toml`"): who is paired, and under which pinned label
/// (§B.8.7.3: the grant label is the pinned pairing label, never the `HELLO` name).
/// The default source is the plaintext TOML the pairing code writes — the same trust
/// limit as [`SessionLogHistory`]: a state-dir writer can pair a device on paper, but
/// the grant still needs the OS credential.
pub trait PairedDevices: Send + Sync {
    /// The pinned pairing label of `device`, `None` when it is not paired.
    fn pinned_label(&self, device: &DeviceId) -> Option<String>;
}

/// The default [`PairedDevices`]: reads `trusted-devices.toml` afresh at every check
/// (the pairing store writes the file atomically on every pin / unpair, so the file is
/// the source of truth for a check that runs once per grant mutation).
#[derive(Debug, Clone)]
pub struct FilePairedDevices {
    path: PathBuf,
}

impl FilePairedDevices {
    /// Over the given `trusted-devices.toml`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl PairedDevices for FilePairedDevices {
    fn pinned_label(&self, device: &DeviceId) -> Option<String> {
        match TrustedDevices::load(&self.path) {
            Ok(t) => t.get(device).map(|d| d.label.clone()),
            Err(e) => {
                tracing::warn!(error = %e, "cannot read trusted-devices.toml: treating every device as unpaired");
                None
            }
        }
    }
}

/// Test double: every device counts as paired under its fingerprint.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllPaired;

impl PairedDevices for AllowAllPaired {
    fn pinned_label(&self, device: &DeviceId) -> Option<String> {
        Some(device.fingerprint())
    }
}

/// Produces a fresh `opaque-ke` `ServerSetup` for the store bootstrap (the OPAQUE code
/// lives in `tornect-signal`; core only stores the bytes).
pub trait ServerSetupSource: Send + Sync {
    /// `ServerSetup::new(rng).serialize()` (128 bytes for suite 1).
    fn generate(&self) -> Result<Zeroizing<Vec<u8>>, String>;
}

/// Refuses every bootstrap (the default until the host wires the OPAQUE source).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoServerSetupSource;

impl ServerSetupSource for NoServerSetupSource {
    fn generate(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("no OPAQUE ServerSetup source configured".into())
    }
}

/// Test double: 128 random bytes (not a real `ServerSetup`).
#[derive(Debug, Default, Clone, Copy)]
pub struct RandomServerSetupSource;

impl ServerSetupSource for RandomServerSetupSource {
    fn generate(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut v = Zeroizing::new(vec![0u8; 128]);
        getrandom::fill(&mut v).map_err(|e| e.to_string())?;
        Ok(v)
    }
}

/// Refuses every re-authentication (release builds without a backend).
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllReAuth;

impl ReAuth for DenyAllReAuth {
    fn reauthenticate(&self, _op: &str) -> Result<(), ReAuthError> {
        Err(ReAuthError::Unavailable(
            "no re-authentication backend on this host".into(),
        ))
    }
}

/// Test double: accepts every re-authentication and counts the calls.
#[derive(Debug, Default)]
pub struct AllowAllReAuth {
    calls: Mutex<Vec<String>>,
}

impl AllowAllReAuth {
    /// The operations that asked for re-auth, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().clone()
    }
}

impl ReAuth for AllowAllReAuth {
    fn reauthenticate(&self, op: &str) -> Result<(), ReAuthError> {
        self.calls.lock().push(op.to_owned());
        Ok(())
    }
}

/// "No session" stub for the offline CLI.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSessionActivity;

impl RemoteSessionActivity for NoSessionActivity {
    fn last_session_ended_at(&self) -> Option<Instant> {
        None
    }

    fn session_live(&self) -> bool {
        false
    }
}

/// Scripted activity for tests.
#[derive(Debug, Default)]
pub struct ScriptedActivity {
    inner: Mutex<(bool, Option<Instant>)>,
}

impl ScriptedActivity {
    /// Mark a session live / not live.
    pub fn set_live(&self, live: bool) {
        self.inner.lock().0 = live;
    }

    /// Record when the last session ended.
    pub fn set_ended_at(&self, at: Option<Instant>) {
        self.inner.lock().1 = at;
    }
}

impl RemoteSessionActivity for ScriptedActivity {
    fn last_session_ended_at(&self) -> Option<Instant> {
        self.inner.lock().1
    }

    fn session_live(&self) -> bool {
        self.inner.lock().0
    }
}

/// Guard refusal, carrying its `G_*` code.
#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    /// `G_REAUTH_FAILED`.
    #[error("re-authentication: {0}")]
    ReauthFailed(ReAuthError),
    /// `G_REMOTE_SESSION_ACTIVE`.
    #[error("a remote session is live or ended less than 60 s ago")]
    RemoteSessionActive,
    /// `G_PRECONDITION`.
    #[error("precondition failed: {0}")]
    Precondition(String),
    /// `G_KEYSTORE_LOCKED`.
    #[error("keystore locked: {0}")]
    KeystoreLocked(String),
    /// `G_STORE_LOCKED`.
    #[error("store locked: {0}")]
    StoreLocked(String),
    /// `G_NO_TXN`.
    #[error("no live registration transaction")]
    NoTxn,
    /// Any other store failure (`G_PRECONDITION`).
    #[error(transparent)]
    Store(StoreError),
}

impl GuardError {
    /// The `G_*` code (§B.8.7.4).
    #[must_use]
    pub fn code(&self) -> u16 {
        match self {
            Self::ReauthFailed(_) => codes::G_REAUTH_FAILED,
            Self::RemoteSessionActive => codes::G_REMOTE_SESSION_ACTIVE,
            Self::Precondition(_) | Self::Store(_) => codes::G_PRECONDITION,
            Self::KeystoreLocked(_) => codes::G_KEYSTORE_LOCKED,
            Self::StoreLocked(_) => codes::G_STORE_LOCKED,
            Self::NoTxn => codes::G_NO_TXN,
        }
    }
}

impl From<StoreError> for GuardError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Locked(who) => Self::StoreLocked(who),
            StoreError::KeystoreLocked(m) => Self::KeystoreLocked(m),
            StoreError::NotLoaded(StoreStatus::FailedClosed(StoreLoadError::KeystoreLocked(m))) => {
                Self::KeystoreLocked(m)
            }
            StoreError::NotLoaded(StoreStatus::AttendedOnly) => {
                Self::Precondition("unattended access was never enabled on this host".into())
            }
            StoreError::NotLoaded(StoreStatus::FailedClosed(e)) => {
                Self::Precondition(format!("unattended store failed closed: {e}"))
            }
            StoreError::NoGrant => Self::Precondition("no unattended grant for this device".into()),
            StoreError::GrantExists => Self::Precondition("this device already has a grant".into()),
            StoreError::Options(e) => Self::Precondition(e.to_string()),
            StoreError::Invalid(m) => Self::Precondition(m),
            other => Self::Store(other),
        }
    }
}

/// Remote admin operations (§B.8.4.1 `AdminCmd`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminOp {
    /// `1 revoke(pk)`.
    Revoke(DeviceId),
    /// `2 revoke_all`.
    RevokeAll,
    /// `3 master_off`.
    MasterOff,
    /// `4 unlock(pk)`.
    Unlock(DeviceId),
    /// `5 suspend(pk)`.
    Suspend(DeviceId),
    /// `6 end_session` (the requester's own session).
    EndSession,
}

impl AdminOp {
    /// From the wire `AdminCmd { op, device_pk }`; `None` for an unknown op or a
    /// missing / superfluous `device_pk`.
    #[must_use]
    pub fn from_wire(op: u8, device_pk: Option<[u8; 32]>) -> Option<Self> {
        Some(match (op, device_pk) {
            (1, Some(pk)) => Self::Revoke(DeviceId::from_bytes(pk)),
            (2, None) => Self::RevokeAll,
            (3, None) => Self::MasterOff,
            (4, Some(pk)) => Self::Unlock(DeviceId::from_bytes(pk)),
            (5, Some(pk)) => Self::Suspend(DeviceId::from_bytes(pk)),
            (6, None) => Self::EndSession,
            _ => return None,
        })
    }

    /// The wire op byte.
    #[must_use]
    pub fn wire(&self) -> u8 {
        match self {
            Self::Revoke(_) => 1,
            Self::RevokeAll => 2,
            Self::MasterOff => 3,
            Self::Unlock(_) => 4,
            Self::Suspend(_) => 5,
            Self::EndSession => 6,
        }
    }

    /// Log name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Revoke(_) => "revoke",
            Self::RevokeAll => "revoke_all",
            Self::MasterOff => "master_off",
            Self::Unlock(_) => "unlock",
            Self::Suspend(_) => "suspend",
            Self::EndSession => "end_session",
        }
    }
}

/// What an admin request did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminEffect {
    /// Nothing (refused, or a no-op such as suspending an already suspended grant).
    None,
    /// The grant of this device was revoked (its live session gets `BYE{REVOKED}`).
    Revoked(DeviceId),
    /// Every grant was revoked.
    RevokedAll(usize),
    /// Master off (every live unattended session gets `BYE{MASTER_OFF}`).
    MasterOff,
    /// `FailState` reset (and `Suspended{Admin}` cleared).
    Unlocked(DeviceId),
    /// The grant moved to `Suspended{Admin}` (its live session gets `BYE{SUSPENDED}`).
    Suspended(DeviceId),
    /// The requester's own session must be ended (`BYE{ADMIN_END}`).
    EndSession,
}

/// `ADMIN_RESULT` plus the effect the caller must apply to live sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOutcome {
    /// `ADMIN_RESULT.ok`.
    pub ok: bool,
    /// `ADMIN_RESULT.detail`.
    pub detail: Option<String>,
    /// Side effect on live sessions.
    pub effect: AdminEffect,
}

/// Outcome of a local *Suspend*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendOutcome {
    /// Moved to `Suspended{Local{by}}` (a live session gets `BYE{SUSPENDED}`).
    Suspended,
    /// Already `Suspended{LocalBlock | Panic | Local}`: unchanged.
    NoOp,
}

/// Access-increasing operations whose effect lives outside the store (§B.8.6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalOp {
    /// `tornect service install` (`elevated`: the Windows opt-in task).
    ServiceInstall {
        /// Elevated task.
        elevated: bool,
    },
    /// `tornect service uninstall`.
    ServiceUninstall,
    /// `tornect backup export <path>`.
    BackupExport {
        /// Destination.
        path: String,
    },
    /// `tornect backup import <path>`.
    BackupImport {
        /// Source.
        path: String,
    },
    /// Identity-key view / backup (S8 *Identity*).
    IdentityView,
    /// Rebinding the panic key or changing notification settings in `config.toml`.
    SettingsChange {
        /// Which setting.
        what: String,
    },
}

impl ExternalOp {
    fn name(&self) -> &'static str {
        match self {
            // Its own name, so the dialog can say what it means (slice-F F1-3).
            Self::ServiceInstall { elevated: true } => "service_install_elevated",
            Self::ServiceInstall { elevated: false } => "service_install",
            Self::ServiceUninstall => "service_uninstall",
            Self::BackupExport { .. } => "backup_export",
            Self::BackupImport { .. } => "backup_import",
            Self::IdentityView => "identity_view",
            Self::SettingsChange { .. } => "settings_change",
        }
    }
}

/// Host-wide settings kept in the store (§B.8.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostSettings {
    /// Keep-awake while any grant is active (presets may only turn it on).
    pub keep_awake: Option<bool>,
    /// Prevent idle lock while unattended access is on.
    pub prevent_idle_lock: Option<bool>,
    /// Per-start notifications.
    pub notify: Option<bool>,
    /// Wizard default for `hard_lock_after`.
    pub default_hard_lock_after: Option<u32>,
}

/// What `reg_start` hands back.
pub struct RegStartOk {
    /// Single-use transaction, ≤ 120 s, bound to the device (zeroized on drop).
    pub reg_txn: Zeroizing<[u8; 16]>,
    /// The `ServerSetup` bytes the caller needs for `ServerRegistration::start`.
    pub server_setup: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for RegStartOk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegStartOk")
            .field("reg_txn", &"<redacted>")
            .field(
                "server_setup",
                &format_args!("<{} bytes>", self.server_setup.len()),
            )
            .finish()
    }
}

/// What `reg_finish` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegFinishOutcome {
    /// A grant was created.
    Created(GrantId),
    /// The auth record of an existing grant was replaced.
    PasswordSet(GrantId),
}

/// Result of `master_on`.
pub struct MasterOnOk {
    /// The emergency stop code, shown once on the printable card (§B.8.7.4). A fresh
    /// code is issued at every call — the token is rotated on every re-enable, so an
    /// old card stops working the moment the switch is turned on again.
    pub stop_code: Zeroizing<[u8; STOP_CODE_LEN]>,
}

impl std::fmt::Debug for MasterOnOk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterOnOk")
            .field("stop_code", &"<redacted>")
            .finish()
    }
}

/// The pause still running at `now`, if any (a `paused_until` in the past is no pause).
fn running_pause(s: &super::grant::UnattendedStore, now: u64) -> Option<u64> {
    s.paused_until.filter(|end| *end > now)
}

/// Whether `until` ends a running pause earlier than it would end by itself — the
/// access-increasing half of *pause* (§B.8.6.2: un-pausing is *master on*).
fn pause_shortens(running: Option<u64>, until: u64) -> bool {
    running.is_some_and(|end| until < end)
}

/// `SHA-256("tornect/v1/stop\0" || host_onion_pk || stop_code)` (§B.8.7.4).
#[must_use]
pub fn stop_token(host_onion_pk: &[u8; 32], stop_code: &[u8; STOP_CODE_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tornect/v1/stop\0");
    h.update(host_onion_pk);
    h.update(stop_code);
    h.finalize().into()
}

struct TxnEntry {
    txn: Zeroizing<[u8; 16]>,
    device: DeviceId,
    created: Instant,
}

/// The mutation guard (§B.8.6.2).
pub struct MutationGuard {
    store: GrantStore,
    reauth: Arc<dyn ReAuth>,
    activity: Arc<dyn RemoteSessionActivity>,
    history: Arc<dyn AttendedHistory>,
    paired: Arc<dyn PairedDevices>,
    setup: Arc<dyn ServerSetupSource>,
    txns: Mutex<Vec<TxnEntry>>,
}

impl std::fmt::Debug for MutationGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutationGuard")
            .field("store", &self.store)
            .field("live_txns", &self.txns.lock().len())
            .finish()
    }
}

impl MutationGuard {
    /// The normative constructor (§B.8.14). The attended history defaults to the
    /// store's `sessions.log`, the pairing source to the `trusted-devices.toml` of the
    /// same state directory ([`FilePairedDevices`]), the `ServerSetup` source to
    /// [`NoServerSetupSource`].
    #[must_use]
    pub fn new(
        store: GrantStore,
        reauth: Arc<dyn ReAuth>,
        activity: Arc<dyn RemoteSessionActivity>,
    ) -> Self {
        let history = Arc::new(SessionLogHistory::new(store.log().clone()));
        let paired = Arc::new(FilePairedDevices::new(store.trusted_devices_path()));
        Self {
            store,
            reauth,
            activity,
            history,
            paired,
            setup: Arc::new(NoServerSetupSource),
            txns: Mutex::new(Vec::new()),
        }
    }

    /// Replace the attended-history source.
    #[must_use]
    pub fn with_attended_history(mut self, history: Arc<dyn AttendedHistory>) -> Self {
        self.history = history;
        self
    }

    /// Replace the pairing source (the app's in-memory pairing store, or
    /// [`AllowAllPaired`] in tests).
    #[must_use]
    pub fn with_paired_devices(mut self, paired: Arc<dyn PairedDevices>) -> Self {
        self.paired = paired;
        self
    }

    /// Install the `ServerSetup` source used by the first enable.
    #[must_use]
    pub fn with_server_setup_source(mut self, setup: Arc<dyn ServerSetupSource>) -> Self {
        self.setup = setup;
        self
    }

    /// The store behind the guard.
    #[must_use]
    pub fn store(&self) -> &GrantStore {
        &self.store
    }

    fn now(&self) -> u64 {
        self.store.clock().wall()
    }

    fn remote_session_blocks(&self) -> bool {
        self.activity.session_live()
            || self
                .activity
                .last_session_ended_at()
                .is_some_and(|t| t.elapsed() < REMOTE_SESSION_COOLDOWN)
    }

    fn refuse(
        &self,
        op: &str,
        by: Option<Actor>,
        device: Option<&DeviceId>,
        err: GuardError,
    ) -> GuardError {
        let mut rec = SessionRecord::at(self.now(), SessionEvent::GrantMutationRefused)
            .op(op)
            .code(err.code())
            .detail(err.to_string())
            .during_remote_session(self.remote_session_blocks());
        if let Some(by) = by {
            rec = rec.by(by);
        }
        if let Some(d) = device {
            rec = rec.device(*d);
        }
        if let Err(e) = self.store.log_event(&rec) {
            tracing::warn!(error = %e, "could not log GrantMutationRefused");
        }
        err
    }

    /// The access-increasing gate: no remote session (+60 s) **and** a fresh re-auth,
    /// then the session check again — the dialog may have stayed open for minutes and
    /// an unattended session can start meanwhile (§B.8.7.4 spells this out for
    /// `RegFinish`; it holds for every access-increasing operation).
    fn access_increasing(
        &self,
        op: &str,
        by: Actor,
        device: Option<&DeviceId>,
    ) -> Result<(), GuardError> {
        self.no_remote_session(op, by, device)?;
        if let Err(e) = self.reauth.reauthenticate(op) {
            return Err(self.refuse(op, Some(by), device, GuardError::ReauthFailed(e)));
        }
        self.no_remote_session(op, by, device)
    }

    /// `G_REMOTE_SESSION_ACTIVE` (logged) while a remote session is live or ended < 60 s
    /// ago. Called before and after every blocking step of an access-increasing
    /// operation (the re-auth dialog, the keychain bootstrap) and last thing before the
    /// store write.
    fn no_remote_session(
        &self,
        op: &str,
        by: Actor,
        device: Option<&DeviceId>,
    ) -> Result<(), GuardError> {
        if self.remote_session_blocks() {
            return Err(self.refuse(op, Some(by), device, GuardError::RemoteSessionActive));
        }
        Ok(())
    }

    /// `G_PRECONDITION` (logged) unless `device` is SAS-paired; returns its pinned label.
    fn require_paired(&self, op: &str, by: Actor, device: &DeviceId) -> Result<String, GuardError> {
        self.paired.pinned_label(device).ok_or_else(|| {
            self.refuse(
                op,
                Some(by),
                Some(device),
                GuardError::Precondition("device is not paired".into()),
            )
        })
    }

    /// `G_KEYSTORE_LOCKED` (logged, buffered) while the store failed closed on an
    /// unreadable keystore: every line would then be buffered, not written (F2-4).
    fn log_key_readable(&self, op: &str, by: Actor) -> Result<(), GuardError> {
        match self.store.status() {
            StoreStatus::FailedClosed(StoreLoadError::KeystoreLocked(m)) => Err(self.refuse(
                op,
                Some(by),
                None,
                GuardError::KeystoreLocked(format!(
                    "{m}; this change could not be written to sessions.log now, so it waits \
                     until the keystore can be read"
                )),
            )),
            _ => Ok(()),
        }
    }

    fn require_loaded(
        &self,
        op: &str,
        by: Option<Actor>,
        device: Option<&DeviceId>,
    ) -> Result<(), GuardError> {
        match self.store.status() {
            StoreStatus::Loaded => Ok(()),
            other => Err(self.refuse(
                op,
                by,
                device,
                GuardError::from(StoreError::NotLoaded(other)),
            )),
        }
    }

    fn bootstrap_if_needed(&self, op: &str, by: Actor) -> Result<(), GuardError> {
        if self.store.status() == StoreStatus::AttendedOnly {
            let setup = self
                .setup
                .generate()
                .map_err(|m| self.refuse(op, Some(by), None, GuardError::Precondition(m)))?;
            self.store
                .bootstrap(setup)
                .map_err(|e| self.refuse(op, Some(by), None, GuardError::from(e)))?;
        }
        self.require_loaded(op, Some(by), None)
    }

    // ------------------------------------------------------------ deny-direction

    /// Master off (deny-direction). Live unattended sessions get `BYE{MASTER_OFF}`.
    pub fn master_off(&self, by: Actor) -> Result<(), GuardError> {
        self.require_loaded("master_off", Some(by), None)?;
        let rec = SessionRecord::at(self.now(), SessionEvent::UnattendedDisabled).by(by);
        self.store.mutate(WriteClass::Policy, Some(&rec), |s, _| {
            s.enabled = false;
            Ok(())
        })?;
        Ok(())
    }

    /// The answer to a `master_on` never reached the CLI — it was killed, or hung up,
    /// while the re-authentication dialog was open — so the one-time stop code exists
    /// nowhere (§B.8.7.4). Unattended access must not stay on under a stop card nobody
    /// holds: turn it back off and clear the token. Deny-direction, so no dialog;
    /// logged as `UnattendedDisabled` with the reason (track D S1).
    pub fn master_off_undelivered_stop_code(&self, by: Actor) -> Result<(), GuardError> {
        self.require_loaded("master_off", Some(by), None)?;
        let rec = SessionRecord::at(self.now(), SessionEvent::UnattendedDisabled)
            .by(by)
            .reason("stop code not delivered");
        self.store.mutate(WriteClass::Policy, Some(&rec), |s, _| {
            s.enabled = false;
            s.stop_token = None;
            Ok(())
        })?;
        Ok(())
    }

    /// Pause until `until` (unix seconds; 12 h / until 08:00 / until re-enabled). Live
    /// sessions get `BYE{PAUSED}`. Starting or extending a pause is deny-direction;
    /// ending a running pause early — an `until` before its end, or not in the future —
    /// has the effect of *master on* and is therefore access-increasing (re-auth, no
    /// remote session), classified again under the store lock after the dialog. An
    /// `until` in the past while no pause is running is refused (`G_PRECONDITION`).
    pub fn pause(&self, by: Actor, until: u64) -> Result<(), GuardError> {
        let op = "pause";
        self.require_loaded(op, Some(by), None)?;
        let now = self.now();
        let running = self.store.read(|s| running_pause(s, now)).flatten();
        if until <= now && running.is_none() {
            return Err(self.refuse(
                op,
                Some(by),
                None,
                GuardError::Precondition("pause end lies in the past".into()),
            ));
        }
        let shortens = pause_shortens(running, until);
        if shortens {
            self.access_increasing(op, by, None)?;
        }
        let rec = SessionRecord::at(now, SessionEvent::UnattendedPaused)
            .by(by)
            .detail(if shortens {
                format!("until {until} (pause shortened)")
            } else {
                format!("until {until}")
            });
        self.store
            .mutate(WriteClass::Policy, Some(&rec), |s, now| {
                // a pause extended while the dialog was up must not be cut short by a
                // caller who was classified deny-direction on the earlier picture
                if !shortens && pause_shortens(running_pause(s, now), until) {
                    return Err(StoreError::Invalid(
                        "pause changed during the operation; retry".into(),
                    ));
                }
                s.paused_until = Some(until);
                Ok(())
            })
            .map_err(|e| self.refuse(op, Some(by), None, GuardError::from(e)))?;
        Ok(())
    }

    /// Revoke one grant (deny-direction). A live session gets `BYE{REVOKED}`.
    pub fn revoke(&self, by: Actor, device: &DeviceId) -> Result<(), GuardError> {
        self.require_loaded("revoke", Some(by), Some(device))?;
        let id = self.store.grant(device).map(|g| g.id);
        let mut rec = SessionRecord::at(self.now(), SessionEvent::GrantRevoked)
            .by(by)
            .device(*device);
        if let Some(id) = id {
            rec = rec.grant(&id);
        }
        self.store
            .remove_grant(device, &rec)
            .map_err(|e| self.refuse("revoke", Some(by), Some(device), GuardError::from(e)))?;
        Ok(())
    }

    /// Revoke every grant (deny-direction).
    pub fn revoke_all(&self, by: Actor) -> Result<usize, GuardError> {
        self.require_loaded("revoke_all", Some(by), None)?;
        let rec = SessionRecord::at(self.now(), SessionEvent::GrantRevoked)
            .by(by)
            .detail("revoke all");
        Ok(self.store.remove_all_grants(&rec)?)
    }

    /// `Active` → `Disabled{by}` (deny-direction; allowed from any `Suspended` state too).
    /// A no-op — nothing logged or written — on an already disabled grant.
    pub fn disable(&self, by: Actor, device: &DeviceId) -> Result<(), GuardError> {
        self.require_loaded("disable", Some(by), Some(device))?;
        let existing = self.store.grant(device).ok_or_else(|| {
            self.refuse(
                "disable",
                Some(by),
                Some(device),
                GuardError::from(StoreError::NoGrant),
            )
        })?;
        if matches!(existing.state, GrantState::Disabled { .. }) {
            return Ok(());
        }
        let rec = SessionRecord::at(self.now(), SessionEvent::GrantDisabled)
            .by(by)
            .device(*device)
            .grant(&existing.id);
        self.store
            .update_grant(device, &rec, |g, now| {
                if !matches!(g.state, GrantState::Disabled { .. }) {
                    g.state = GrantState::Disabled { since: now, by };
                }
                Ok(())
            })
            .map_err(|e| self.refuse("disable", Some(by), Some(device), GuardError::from(e)))?;
        Ok(())
    }

    /// The unpair cascade of §B.8.6.1 / §B.8.9 ("unpair cascades"; *Remove device* =
    /// unpair + revoke): deny-direction, revokes the device's grant with a tombstone
    /// when one exists. The app calls this **before** removing the pairing from
    /// `trusted-devices.toml`, so a crash between the two leaves at worst a paired
    /// device without a grant — never a grant for an unpaired device. Returns whether
    /// a grant was revoked; a store that is not loaded (attended-only, failed closed)
    /// has no grant to cascade to.
    pub fn unpair(&self, by: Actor, device: &DeviceId) -> Result<bool, GuardError> {
        if self.store.status() != StoreStatus::Loaded {
            return Ok(false);
        }
        let Some(existing) = self.store.grant(device) else {
            return Ok(false);
        };
        let rec = SessionRecord::at(self.now(), SessionEvent::GrantRevoked)
            .by(by)
            .device(*device)
            .grant(&existing.id)
            .detail("unpair");
        match self.store.remove_grant(device, &rec) {
            Ok(_) => Ok(true),
            Err(StoreError::NoGrant) => Ok(false),
            Err(e) => Err(self.refuse("unpair", Some(by), Some(device), GuardError::from(e))),
        }
    }

    /// A local *Suspend* (deny-direction): `Active | Suspended{Admin}` →
    /// `Suspended{Local{by}}`; no-op on `LocalBlock` / `Panic` / `Local`.
    pub fn suspend(&self, by: Actor, device: &DeviceId) -> Result<SuspendOutcome, GuardError> {
        self.suspend_with(device, SuspendReason::Local { by }, Some(by))
    }

    /// The block-window *Block* (§B.8.6.3): grant → `Suspended{LocalBlock}`; a local
    /// reason already in place stays.
    pub fn block(&self, device: &DeviceId) -> Result<SuspendOutcome, GuardError> {
        let id = self.store.grant(device).map(|g| g.id);
        let mut rec = SessionRecord::at(self.now(), SessionEvent::UnattendedBlockedByLocalUser)
            .device(*device)
            .unattended(true);
        if let Some(id) = id {
            rec = rec.grant(&id);
        }
        self.store.log_event(&rec)?;
        self.suspend_with(device, SuspendReason::LocalBlock, None)
    }

    /// The panic key ended an unattended session (§B.8.7.4): grant → `Suspended{Panic}`.
    pub fn panic(&self, device: &DeviceId) -> Result<SuspendOutcome, GuardError> {
        let rec = SessionRecord::at(self.now(), SessionEvent::PanicDisconnect)
            .device(*device)
            .unattended(true);
        self.store.log_event(&rec)?;
        self.suspend_with(device, SuspendReason::Panic, None)
    }

    fn suspend_with(
        &self,
        device: &DeviceId,
        reason: SuspendReason,
        by: Option<Actor>,
    ) -> Result<SuspendOutcome, GuardError> {
        self.require_loaded("suspend", by, Some(device))?;
        let id = self.store.grant(device).map(|g| g.id);
        let mut rec = SessionRecord::at(self.now(), SessionEvent::UnattendedSuspended)
            .device(*device)
            .reason(reason.log_name());
        if let Some(b) = by {
            rec = rec.by(b);
        }
        if let Some(id) = id {
            rec = rec.grant(&id);
        }
        let outcome = self
            .store
            .update_grant(device, &rec, |g, now| {
                Ok(match g.state {
                    GrantState::Suspended { reason: r, .. } if r.is_local() => SuspendOutcome::NoOp,
                    GrantState::Disabled { .. } => {
                        return Err(StoreError::Invalid("grant is disabled".into()));
                    }
                    _ => {
                        g.state = GrantState::Suspended { reason, since: now };
                        SuspendOutcome::Suspended
                    }
                })
            })
            .map_err(|e| self.refuse("suspend", by, Some(device), GuardError::from(e)))?;
        Ok(outcome)
    }

    /// *Rotate ID* (§B.8.9, §B.8.12): wipe everything unattended — grants, `ServerSetup`,
    /// tombstones, the stop token, `K_master` with its anchor — and return to
    /// attended-only. Deny-direction (nothing widens; the identity rotation itself and
    /// the dialog naming the N grants are the app's), works from every store status (a
    /// failed-closed store is wiped too). Logs `HostIdRotated{by}` after the wipe,
    /// untagged — the line the next `master_on` records as its key epoch (§B.8.13) — so
    /// the app must not append its own `HostIdRotated` line. Returns the number of
    /// grants wiped.
    pub fn rotate_id(&self, by: Actor) -> Result<usize, GuardError> {
        let n = self.store.grants().len();
        self.store
            .wipe_all()
            .map_err(|e| self.refuse("rotate_id", Some(by), None, GuardError::from(e)))?;
        let rec = SessionRecord::at(self.now(), SessionEvent::HostIdRotated)
            .by(by)
            .detail(format!("unattended store wiped ({n} grant(s))"));
        if let Err(e) = self.store.log_event(&rec) {
            tracing::warn!(error = %e, "could not log HostIdRotated");
        }
        Ok(n)
    }

    /// The emergency stop code was presented (§B.8.7.4): master off + revoke all; the
    /// token is single-use (cleared; a new card is issued at the next `master_on`).
    pub fn emergency_stop(&self) -> Result<usize, GuardError> {
        self.require_loaded("emergency_stop", None, None)?;
        let rec = SessionRecord::at(self.now(), SessionEvent::EmergencyStop);
        let n = self
            .store
            .mutate(WriteClass::Policy, Some(&rec), |s, now| {
                s.enabled = false;
                s.stop_token = None;
                let n = s.grants.len();
                let devices: Vec<DeviceId> = s.grants.iter().map(|g| g.device).collect();
                for d in devices {
                    push_tombstone(s, d, now);
                }
                s.grants.clear();
                Ok(n)
            })?;
        Ok(n)
    }

    // ------------------------------------------------------------ access-increasing

    /// Master on (access-increasing). Bootstraps `K_master`, the store and the
    /// `ServerSetup` at the first call; issues a fresh emergency stop code at every call
    /// (the token, bound to `host_onion_pk`, is rotated on every re-enable, §B.8.7.4).
    pub fn master_on(&self, by: Actor, host_onion_pk: &[u8; 32]) -> Result<MasterOnOk, GuardError> {
        self.access_increasing("master_on", by, None)?;
        self.bootstrap_if_needed("master_on", by)?;
        self.no_remote_session("master_on", by, None)?;
        let mut code = Zeroizing::new([0u8; STOP_CODE_LEN]);
        getrandom::fill(code.as_mut_slice())
            .map_err(|e| GuardError::Precondition(format!("rng: {e}")))?;
        let token = stop_token(host_onion_pk, &code);
        let rec = SessionRecord::at(self.now(), SessionEvent::UnattendedEnabled).by(by);
        self.store.mutate(WriteClass::Policy, Some(&rec), |s, _| {
            s.enabled = true;
            s.paused_until = None;
            s.stop_token = Some(token);
            Ok(())
        })?;
        Ok(MasterOnOk { stop_code: code })
    }

    /// `Disabled` → `Active` (access-increasing, §B.8.6.1). A no-op on an `Active`
    /// grant; refused on a `Suspended` one — clearing a suspension is [`Self::resume`]'s
    /// job (its own log line and clearing rules, §B.8.6.3).
    pub fn enable(&self, by: Actor, device: &DeviceId) -> Result<(), GuardError> {
        self.access_increasing("enable", by, Some(device))?;
        self.require_loaded("enable", Some(by), Some(device))?;
        let existing = self.store.grant(device).ok_or_else(|| {
            self.refuse(
                "enable",
                Some(by),
                Some(device),
                GuardError::from(StoreError::NoGrant),
            )
        })?;
        match existing.state {
            GrantState::Active => return Ok(()),
            GrantState::Suspended { .. } => {
                return Err(self.refuse(
                    "enable",
                    Some(by),
                    Some(device),
                    GuardError::Precondition("grant is suspended; use resume".into()),
                ));
            }
            GrantState::Disabled { .. } => {}
        }
        let rec = SessionRecord::at(self.now(), SessionEvent::GrantEnabled)
            .by(by)
            .device(*device)
            .grant(&existing.id);
        self.store
            .update_grant(device, &rec, |g, _| {
                match g.state {
                    GrantState::Disabled { .. } => g.state = GrantState::Active,
                    GrantState::Active => {}
                    GrantState::Suspended { .. } => {
                        return Err(StoreError::Invalid("grant is suspended; use resume".into()));
                    }
                }
                Ok(())
            })
            .map_err(|e| self.refuse("enable", Some(by), Some(device), GuardError::from(e)))?;
        Ok(())
    }

    /// Local *Unlock* (access-increasing): `FailState` reset.
    pub fn unlock(&self, by: Actor, device: &DeviceId) -> Result<(), GuardError> {
        self.access_increasing("unlock", by, Some(device))?;
        self.require_loaded("unlock", Some(by), Some(device))?;
        let id = self.store.grant(device).map(|g| g.id);
        let mut rec = SessionRecord::at(self.now(), SessionEvent::UnattendedUnlock)
            .by(by)
            .device(*device);
        if let Some(id) = id {
            rec = rec.grant(&id);
        }
        let mut st = self.store.state();
        let before = st.store.clone();
        let before_rt = st.runtime.get(device).copied();
        if let Err(e) = self.store.reset_fail_locked(&mut st, device) {
            drop(st);
            return Err(self.refuse("unlock", Some(by), Some(device), GuardError::from(e)));
        }
        let persisted = self
            .store
            .log_locked(&mut st, &rec)
            .and_then(|()| self.store.write_locked(&mut st, WriteClass::Policy));
        if let Err(e) = persisted {
            st.store = before;
            match before_rt {
                Some(rt) => {
                    st.runtime.insert(*device, rt);
                }
                None => {
                    st.runtime.remove(device);
                }
            }
            return Err(e.into());
        }
        Ok(())
    }

    /// The §B.8.12 recovery from a failed-closed store ("unattended store was replaced —
    /// re-enable to continue"): access-increasing (re-auth, no remote session); wipes the
    /// stale file and `K_master` with its anchor and returns to attended-only, so the next
    /// [`Self::master_on`] bootstraps a fresh store and grants are recreated locally.
    /// Refused (`G_PRECONDITION`) unless the store is [`StoreStatus::FailedClosed`].
    pub fn reset_store(&self, by: Actor) -> Result<(), GuardError> {
        let op = "reset_store";
        let StoreStatus::FailedClosed(_) = self.store.status() else {
            return Err(self.refuse(
                op,
                Some(by),
                None,
                GuardError::Precondition("store is not failed closed; nothing to reset".into()),
            ));
        };
        self.access_increasing(op, by, None)?;
        let err = self
            .store
            .reset_failed_closed()
            .map_err(|e| self.refuse(op, Some(by), None, GuardError::from(e)))?;
        let rec = SessionRecord::at(self.now(), SessionEvent::UnattendedDisabled)
            .by(by)
            .detail(format!("store reset after a failed-closed load: {err}"));
        if let Err(e) = self.store.log_event(&rec) {
            tracing::warn!(error = %e, "could not log the store reset");
        }
        Ok(())
    }

    /// Local *Resume* (access-increasing): clears any `Suspended{..}` (§B.8.6.3).
    pub fn resume(&self, by: Actor, device: &DeviceId) -> Result<(), GuardError> {
        self.access_increasing("resume", by, Some(device))?;
        self.require_loaded("resume", Some(by), Some(device))?;
        let id = self.store.grant(device).map(|g| g.id);
        let mut rec = SessionRecord::at(self.now(), SessionEvent::UnattendedResumed)
            .by(by)
            .device(*device);
        if let Some(id) = id {
            rec = rec.grant(&id);
        }
        self.store
            .update_grant(device, &rec, |g, _| {
                match g.state {
                    GrantState::Suspended { .. } => g.state = GrantState::Active,
                    GrantState::Disabled { .. } => {
                        return Err(StoreError::Invalid("grant is disabled; use enable".into()));
                    }
                    GrantState::Active => {}
                }
                Ok(())
            })
            .map_err(|e| self.refuse("resume", Some(by), Some(device), GuardError::from(e)))?;
        Ok(())
    }

    /// Change a grant's options. Widening (§B.8.6.2: mode → Control, later expiry, wider
    /// schedule, lower block window, "Ask before starting" off, …) is access-increasing;
    /// a purely narrowing or neutral change needs nothing.
    ///
    /// Classification and write happen under one store lock: a narrowing change is
    /// applied in the same critical section that classified it (no window for a
    /// concurrent mutation to turn it into a widening one), a widening change is
    /// rolled back, re-authenticated outside the lock and then applied — and
    /// classified once more — under the lock again.
    pub fn set_options(
        &self,
        by: Actor,
        device: &DeviceId,
        options: &GrantOptions,
    ) -> Result<(), GuardError> {
        let op = "set_options";
        self.require_loaded(op, Some(by), Some(device))?;
        let file_keystore = self.store.keystore_kind().is_file();
        match self.apply_options_locked(by, device, options, file_keystore, false) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => return Err(self.refuse(op, Some(by), Some(device), e)),
        }
        self.access_increasing(op, by, Some(device))?;
        match self.apply_options_locked(by, device, options, file_keystore, true) {
            Ok(_) => Ok(()),
            Err(e) => Err(self.refuse(op, Some(by), Some(device), e)),
        }
    }

    /// Apply `options` to the locked grant, log `GrantChanged` and persist (policy
    /// write) in one critical section. A widening change without `reauthed` leaves
    /// everything untouched and returns `Ok(false)`. Errors are returned unlogged (the
    /// caller writes the refusal line — never under this lock).
    fn apply_options_locked(
        &self,
        by: Actor,
        device: &DeviceId,
        options: &GrantOptions,
        file_keystore: bool,
        reauthed: bool,
    ) -> Result<bool, GuardError> {
        let mut st = self.store.state();
        if st.status != StoreStatus::Loaded {
            return Err(StoreError::NotLoaded(st.status.clone()).into());
        }
        let (now, _) = self.store.wall_locked(&mut st);
        let Some(before) = st.store.clone() else {
            return Err(StoreError::NotLoaded(st.status.clone()).into());
        };
        let outcome = match st.store.as_mut().and_then(|s| s.grant_mut(device)) {
            Some(g) => g
                .apply_options(options, now, file_keystore)
                .map(|widened| (g.id, widened))
                .map_err(StoreError::Options),
            None => Err(StoreError::NoGrant),
        };
        let (id, widened) = match outcome {
            Ok(v) => v,
            Err(e) => {
                st.store = Some(before);
                return Err(e.into());
            }
        };
        if !widened.is_empty() && !reauthed {
            st.store = Some(before);
            return Ok(false);
        }
        let rec = SessionRecord::at(now, SessionEvent::GrantChanged)
            .by(by)
            .device(*device)
            .grant(&id)
            .detail(if widened.is_empty() {
                "narrowed".to_owned()
            } else {
                format!("widened: {}", widened.join(","))
            });
        let persisted = self
            .store
            .log_locked(&mut st, &rec)
            .and_then(|()| self.store.write_locked(&mut st, WriteClass::Policy));
        if let Err(e) = persisted {
            st.store = Some(before);
            return Err(e.into());
        }
        Ok(true)
    }

    /// Host-wide settings (access-increasing).
    pub fn set_settings(&self, by: Actor, settings: HostSettings) -> Result<(), GuardError> {
        self.access_increasing("set_settings", by, None)?;
        self.require_loaded("set_settings", Some(by), None)?;
        let rec = SessionRecord::at(self.now(), SessionEvent::GrantChanged)
            .by(by)
            .detail("host settings");
        self.store.mutate(WriteClass::Policy, Some(&rec), |s, _| {
            if let Some(v) = settings.keep_awake {
                s.keep_awake = v;
            }
            if let Some(v) = settings.prevent_idle_lock {
                s.prevent_idle_lock = v;
            }
            if let Some(v) = settings.notify {
                s.notify = v;
            }
            if let Some(v) = settings.default_hard_lock_after {
                s.default_hard_lock_after = v;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Authorize an access-increasing operation whose effect lives outside the store
    /// (autostart, backup, identity view, settings). Logs `AutostartChanged` /
    /// `BackupExported`; the caller performs the effect after `Ok`.
    ///
    /// Slice-F F2-4: while `K_master` exists but cannot be read, a line cannot be
    /// tagged and the store only buffers it (§B.8.13), so a change authorised then
    /// could leave no trace in `sessions.log`. An operation that must be logged is
    /// refused with `G_KEYSTORE_LOCKED`, before the dialog and again before its line.
    pub fn authorize(&self, by: Actor, op: &ExternalOp) -> Result<(), GuardError> {
        let logged = matches!(
            op,
            ExternalOp::ServiceInstall { .. }
                | ExternalOp::ServiceUninstall
                | ExternalOp::BackupExport { .. }
        );
        if logged {
            self.log_key_readable(op.name(), by)?;
        }
        self.access_increasing(op.name(), by, None)?;
        if logged {
            self.log_key_readable(op.name(), by)?;
        }
        let now = self.now();
        let rec = match op {
            ExternalOp::ServiceInstall { elevated } => Some(
                SessionRecord::at(now, SessionEvent::AutostartChanged)
                    .by(by)
                    .detail(if *elevated {
                        "install (elevated)"
                    } else {
                        "install"
                    }),
            ),
            ExternalOp::ServiceUninstall => Some(
                SessionRecord::at(now, SessionEvent::AutostartChanged)
                    .by(by)
                    .detail("uninstall"),
            ),
            ExternalOp::BackupExport { path } => Some(
                SessionRecord::at(now, SessionEvent::BackupExported)
                    .by(by)
                    .path(path.clone()),
            ),
            ExternalOp::BackupImport { .. }
            | ExternalOp::IdentityView
            | ExternalOp::SettingsChange { .. } => None,
        };
        if let Some(rec) = rec {
            self.store.log_event(&rec)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------ registration

    /// `RegStart` (§B.8.7.4): re-auth here; returns a single-use `reg_txn` (≤ 120 s,
    /// bound to `device`) and the `ServerSetup` bytes (bootstrapping the store first if
    /// unattended access was never enabled).
    pub fn reg_start(&self, by: Actor, device: &DeviceId) -> Result<RegStartOk, GuardError> {
        // Cheap preconditions first: no dialog for a device that can never get a grant.
        self.require_paired("reg_start", by, device)?;
        self.access_increasing("reg_start", by, Some(device))?;
        self.bootstrap_if_needed("reg_start", by)?;
        let server_setup = self
            .store
            .server_setup()
            .ok_or_else(|| GuardError::Precondition("store has no ServerSetup".into()))?;
        let mut txn = Zeroizing::new([0u8; 16]);
        getrandom::fill(txn.as_mut_slice())
            .map_err(|e| GuardError::Precondition(format!("rng: {e}")))?;
        let now = Instant::now();
        let mut txns = self.txns.lock();
        txns.retain(|t| now.duration_since(t.created) < REG_TXN_TTL && t.device != *device);
        txns.push(TxnEntry {
            txn: txn.clone(),
            device: *device,
            created: now,
        });
        Ok(RegStartOk {
            reg_txn: txn,
            server_setup,
        })
    }

    fn take_txn(&self, device: &DeviceId, txn: &[u8; 16]) -> bool {
        let now = Instant::now();
        let mut txns = self.txns.lock();
        txns.retain(|t| now.duration_since(t.created) < REG_TXN_TTL);
        let pos = txns.iter().position(|t| {
            bool::from(subtle::ConstantTimeEq::ct_eq(&t.txn[..], &txn[..])) && t.device == *device
        });
        match pos {
            Some(i) => {
                txns.remove(i);
                true
            }
            None => false,
        }
    }

    /// `RegFinish` (§B.8.7.4): needs the live `reg_txn` (consumed), re-checks
    /// [`RemoteSessionActivity`], then creates the grant (no grant yet) or replaces its
    /// auth record (set-password; `options` may not widen — use [`Self::set_options`]).
    pub fn reg_finish(
        &self,
        by: Actor,
        device: &DeviceId,
        reg_txn: &[u8; 16],
        upload: &[u8],
        preset: Preset,
        options: &GrantOptions,
    ) -> Result<RegFinishOutcome, GuardError> {
        if !self.take_txn(device, reg_txn) {
            return Err(self.refuse("reg_finish", Some(by), Some(device), GuardError::NoTxn));
        }
        if self.remote_session_blocks() {
            return Err(self.refuse(
                "reg_finish",
                Some(by),
                Some(device),
                GuardError::RemoteSessionActive,
            ));
        }
        self.apply_registration(by, device, upload, preset, options)
    }

    /// One-operation grant creation (UI path): re-auth inline, then the registration.
    pub fn create_grant(
        &self,
        by: Actor,
        device: &DeviceId,
        preset: Preset,
        options: &GrantOptions,
        upload: &[u8],
    ) -> Result<GrantId, GuardError> {
        self.require_paired("create_grant", by, device)?;
        self.access_increasing("create_grant", by, Some(device))?;
        self.bootstrap_if_needed("create_grant", by)?;
        self.no_remote_session("create_grant", by, Some(device))?;
        if self.store.grant(device).is_some() {
            return Err(self.refuse(
                "create_grant",
                Some(by),
                Some(device),
                GuardError::from(StoreError::GrantExists),
            ));
        }
        match self.apply_registration(by, device, upload, preset, options)? {
            RegFinishOutcome::Created(id) | RegFinishOutcome::PasswordSet(id) => Ok(id),
        }
    }

    /// One-operation password change (UI path): re-auth inline, then the registration.
    pub fn set_password(
        &self,
        by: Actor,
        device: &DeviceId,
        upload: &[u8],
    ) -> Result<GrantId, GuardError> {
        self.access_increasing("set_password", by, Some(device))?;
        self.require_loaded("set_password", Some(by), Some(device))?;
        let preset = self.store.grant(device).map(|g| g.preset).ok_or_else(|| {
            self.refuse(
                "set_password",
                Some(by),
                Some(device),
                GuardError::from(StoreError::NoGrant),
            )
        })?;
        match self.apply_registration(by, device, upload, preset, &GrantOptions::default())? {
            RegFinishOutcome::Created(id) | RegFinishOutcome::PasswordSet(id) => Ok(id),
        }
    }

    fn apply_registration(
        &self,
        by: Actor,
        device: &DeviceId,
        upload: &[u8],
        preset: Preset,
        options: &GrantOptions,
    ) -> Result<RegFinishOutcome, GuardError> {
        let op = "reg_finish";
        self.require_loaded(op, Some(by), Some(device))?;
        // §B.8 hard rule 2: grants exist only for SAS-paired devices — checked at the
        // single enforcement point, whatever path led here.
        let pinned_label = self.require_paired(op, by, device)?;
        if upload.len() != super::ipc::UPLOAD_LEN {
            return Err(self.refuse(
                op,
                Some(by),
                Some(device),
                GuardError::Precondition(format!(
                    "upload must be {} bytes",
                    super::ipc::UPLOAD_LEN
                )),
            ));
        }
        let auth = AuthRecord::Opaque {
            record: Zeroizing::new(upload.to_vec()),
        };
        let now = self.now();
        let file_keystore = self.store.keystore_kind().is_file();
        if let Some(existing) = self.store.grant(device) {
            // set-password: replace the record; options may not widen
            let mut probe = existing.clone();
            let widened = probe
                .apply_options(options, now, file_keystore)
                .map_err(|e| {
                    self.refuse(
                        op,
                        Some(by),
                        Some(device),
                        GuardError::Precondition(e.to_string()),
                    )
                })?;
            if !widened.is_empty() {
                return Err(self.refuse(
                    op,
                    Some(by),
                    Some(device),
                    GuardError::Precondition(format!(
                        "options widen the grant ({}); use set_options",
                        widened.join(",")
                    )),
                ));
            }
            let rec = SessionRecord::at(now, SessionEvent::PasswordSet)
                .by(by)
                .device(*device)
                .grant(&existing.id);
            self.store
                .update_grant(device, &rec, |g, now| {
                    // classified again on the locked grant: a concurrent narrowing must
                    // not turn these options into a widening that lands here
                    let widened = g.apply_options(options, now, file_keystore)?;
                    if !widened.is_empty() {
                        return Err(StoreError::Invalid(format!(
                            "options widen the grant ({}); use set_options",
                            widened.join(",")
                        )));
                    }
                    g.auth = auth;
                    g.suite = 1;
                    Ok(())
                })
                .map_err(|e| self.refuse(op, Some(by), Some(device), GuardError::from(e)))?;
            return Ok(RegFinishOutcome::PasswordSet(existing.id));
        }
        let waived =
            options.waive_attended_precondition || preset.defaults().waives_attended_precondition;
        if !waived && self.history.completed_attended_sessions(device) == 0 {
            return Err(self.refuse(
                op,
                Some(by),
                Some(device),
                GuardError::Precondition(
                    "no completed attended session from this device (waivable)".into(),
                ),
            ));
        }
        let mut id = [0u8; 8];
        getrandom::fill(&mut id).map_err(|e| GuardError::Precondition(format!("rng: {e}")))?;
        // §B.8.7.3: the pinned pairing label is the grant's label; an explicit option
        // overrides it (sanitized either way, the fingerprint as the last resort).
        let label = match &options.label {
            Some(l) => sanitize_label(l).map_err(|e| {
                self.refuse(
                    op,
                    Some(by),
                    Some(device),
                    GuardError::Precondition(e.to_string()),
                )
            })?,
            None => sanitize_label(&pinned_label).unwrap_or_else(|_| device.fingerprint()),
        };
        let mut grant = UnattendedGrant::from_preset(id, *device, &label, by, preset, 1, auth, now)
            .map_err(|e| {
                self.refuse(
                    op,
                    Some(by),
                    Some(device),
                    GuardError::Precondition(e.to_string()),
                )
            })?;
        grant
            .apply_options(options, now, file_keystore)
            .map_err(|e| {
                self.refuse(
                    op,
                    Some(by),
                    Some(device),
                    GuardError::Precondition(e.to_string()),
                )
            })?;
        let mut rec = SessionRecord::at(now, SessionEvent::GrantCreated)
            .by(by)
            .device(*device)
            .grant(&id)
            .detail(format!("preset {}", preset.wire()));
        if options.waive_attended_precondition {
            rec = rec.reason("attended precondition waived");
        }
        let keep_awake = preset.defaults().keep_awake;
        self.store.insert_grant(grant, &rec, |s| {
            if keep_awake {
                s.keep_awake = true;
            }
        })?;
        if let Err(e) = self.store.log_event(
            &SessionRecord::at(now, SessionEvent::PasswordSet)
                .by(by)
                .device(*device)
                .grant(&id),
        ) {
            tracing::warn!(error = %e, "could not log PasswordSet");
        }
        Ok(RegFinishOutcome::Created(id))
    }

    // ------------------------------------------------------------ remote admin

    /// A post-PAKE admin request from `requester` (§B.8.4.1 scope): every grant may
    /// `end_session` (own) and `revoke` (own pk); `unlock(pk)`, `suspend(pk ≠ self)`,
    /// `revoke(pk ≠ self)`, `revoke_all` and `master_off` need a *My machines* Control
    /// grant in `Active` state. Out of scope ⇒ `ok: false`, no state change, logged.
    ///
    /// `Err` always means the command took no effect: every write that follows a
    /// committed mutation is best-effort, so a committed deny-direction command is
    /// never reported as failed, and never loses the effect that ends live sessions.
    /// A failure is logged as an `AdminRequest{ok: false}` line (best-effort too: the
    /// store that just failed may refuse that write as well).
    pub fn admin(&self, requester: &DeviceId, op: AdminOp) -> Result<AdminOutcome, GuardError> {
        self.admin_inner(requester, op).inspect_err(|e| {
            let rec = SessionRecord::at(self.now(), SessionEvent::AdminRequest)
                .device(*requester)
                .op(op.name())
                .ok(false)
                .unattended(true)
                .code(e.code())
                .detail("host could not apply the command");
            if let Err(le) = self.store.log_event(&rec) {
                tracing::warn!(error = %le, "could not log the failed AdminRequest");
            }
        })
    }

    fn admin_inner(&self, requester: &DeviceId, op: AdminOp) -> Result<AdminOutcome, GuardError> {
        self.require_loaded("admin", None, Some(requester))?;
        let now = self.now();
        // the rollback rule of every wall-clock evaluation (§B.8.5.3): the requester's
        // `active_from` / expiry below cannot be judged on a clock behind `last_seen`
        if now < self.store.last_seen_mark() {
            let mut st = self.store.state();
            self.store
                .note_anomaly_locked(&mut st, now, self.store.clock().mono());
            drop(st);
            return Ok(self.admin_refused(requester, op, "clock rollback"));
        }
        if !self.store.enabled_at(now) {
            return Ok(self.admin_refused(requester, op, "unattended access is off or paused"));
        }
        let Some(req) = self.store.grant(requester) else {
            return Ok(self.admin_refused(requester, op, "requester has no grant"));
        };
        // the same eligibility the pre-PAKE gate applies to the requester (its own ladder
        // lock excepted: this very stream's charge armed it)
        if req.state != GrantState::Active
            || req.expired_at(now)
            || req.auth == AuthRecord::Pruned
            || now < req.active_from
            || req.fail.hard_locked
        {
            return Ok(self.admin_refused(requester, op, "requester grant not active"));
        }
        let own = |d: &DeviceId| d == requester;
        let in_scope = match op {
            AdminOp::EndSession => true,
            AdminOp::Revoke(d) => own(&d) || req.has_admin_scope(),
            AdminOp::RevokeAll | AdminOp::MasterOff | AdminOp::Unlock(_) => req.has_admin_scope(),
            AdminOp::Suspend(d) => !own(&d) && req.has_admin_scope(),
        };
        if !in_scope {
            return Ok(self.admin_refused(requester, op, "out of scope for this grant"));
        }
        let base = |ok: bool| {
            SessionRecord::at(now, SessionEvent::AdminRequest)
                .device(*requester)
                .grant(&req.id)
                .op(op.name())
                .ok(ok)
                .unattended(true)
        };
        // The per-event lines of §B.8.13 (`GrantRevoked`, `UnattendedDisabled`) are
        // written next to the `AdminRequest` line, so a viewer filtering on them sees
        // remote revocations and a remote master off too. They are best-effort: each
        // follows a mutation that has already committed together with its own
        // `AdminRequest` line, and failing the command over a missing second line
        // would report a committed deny-direction change as not done *and* drop the
        // effect that ends live sessions.
        let by_admin = |ev: SessionEvent| {
            SessionRecord::at(now, ev)
                .unattended(true)
                .reason("admin")
                .detail(format!("by admin {requester}"))
        };
        let after_commit = |rec: &SessionRecord| {
            if let Err(e) = self.store.log_event(rec) {
                tracing::warn!(error = %e, op = op.name(), "could not log after a committed admin command");
            }
        };
        let effect = match op {
            // Ending one's own session changes no state; the log line is the record,
            // and ending a session must not hang on it either.
            AdminOp::EndSession => {
                after_commit(&base(true));
                AdminEffect::EndSession
            }
            AdminOp::Revoke(d) => match self
                .store
                .remove_grant(&d, &base(true).detail(format!("target {d}")))
            {
                Ok(removed) => {
                    after_commit(
                        &by_admin(SessionEvent::GrantRevoked)
                            .device(d)
                            .grant(&removed.id),
                    );
                    AdminEffect::Revoked(d)
                }
                Err(StoreError::NoGrant) => {
                    return Ok(self.admin_refused(requester, op, "target has no grant"));
                }
                Err(e) => return Err(e.into()),
            },
            AdminOp::RevokeAll => {
                let n = self.store.remove_all_grants(&base(true))?;
                after_commit(
                    &by_admin(SessionEvent::GrantRevoked)
                        .detail(format!("revoke all ({n}) by admin {requester}")),
                );
                AdminEffect::RevokedAll(n)
            }
            AdminOp::MasterOff => {
                self.store
                    .mutate(WriteClass::Policy, Some(&base(true)), |s, _| {
                        s.enabled = false;
                        Ok(())
                    })?;
                after_commit(&by_admin(SessionEvent::UnattendedDisabled));
                AdminEffect::MasterOff
            }
            AdminOp::Unlock(d) => {
                let mut st = self.store.state();
                let before = st.store.clone();
                let before_rt = st.runtime.get(&d).copied();
                match self.store.reset_fail_locked(&mut st, &d) {
                    Ok(()) => {}
                    Err(StoreError::NoGrant) => {
                        drop(st);
                        return Ok(self.admin_refused(requester, op, "target has no grant"));
                    }
                    Err(e) => return Err(e.into()),
                }
                if let Some(store) = st.store.as_mut()
                    && let Some(g) = store.grant_mut(&d)
                    && matches!(
                        g.state,
                        GrantState::Suspended {
                            reason: SuspendReason::Admin,
                            ..
                        }
                    )
                {
                    g.state = GrantState::Active;
                }
                let persisted = self
                    .store
                    .log_locked(&mut st, &base(true).detail(format!("target {d}")))
                    .and_then(|()| {
                        self.store.log_locked(
                            &mut st,
                            &SessionRecord::at(now, SessionEvent::UnattendedUnlock)
                                .device(d)
                                .reason("admin")
                                .detail(format!("by {requester}")),
                        )
                    })
                    .and_then(|()| self.store.write_locked(&mut st, WriteClass::Policy));
                if let Err(e) = persisted {
                    st.store = before;
                    match before_rt {
                        Some(rt) => {
                            st.runtime.insert(d, rt);
                        }
                        None => {
                            st.runtime.remove(&d);
                        }
                    }
                    return Err(e.into());
                }
                AdminEffect::Unlocked(d)
            }
            AdminOp::Suspend(d) => {
                let rec = base(true).detail(format!("target {d}"));
                let changed = self.store.update_grant(&d, &rec, |g, now| {
                    Ok(match g.state {
                        GrantState::Active => {
                            g.state = GrantState::Suspended {
                                reason: SuspendReason::Admin,
                                since: now,
                            };
                            true
                        }
                        // the local reasons outrank Admin; an already suspended grant is untouched
                        _ => false,
                    })
                });
                match changed {
                    Ok(true) => {
                        if let Err(e) = self.store.log_event(
                            &SessionRecord::at(now, SessionEvent::UnattendedSuspended)
                                .device(d)
                                .reason(SuspendReason::Admin.log_name())
                                .detail(format!("by {requester}")),
                        ) {
                            tracing::warn!(error = %e, "could not log UnattendedSuspended");
                        }
                        AdminEffect::Suspended(d)
                    }
                    Ok(false) => AdminEffect::None,
                    Err(StoreError::NoGrant) => {
                        return Ok(self.admin_refused(requester, op, "target has no grant"));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        };
        Ok(AdminOutcome {
            ok: true,
            detail: None,
            effect,
        })
    }

    fn admin_refused(&self, requester: &DeviceId, op: AdminOp, why: &str) -> AdminOutcome {
        let rec = SessionRecord::at(self.now(), SessionEvent::AdminRequest)
            .device(*requester)
            .op(op.name())
            .ok(false)
            .unattended(true)
            .detail(why);
        if let Err(e) = self.store.log_event(&rec) {
            tracing::warn!(error = %e, "could not log the refused AdminRequest");
        }
        AdminOutcome {
            ok: false,
            detail: Some(why.to_owned()),
            effect: AdminEffect::None,
        }
    }
}
