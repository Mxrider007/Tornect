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
//! unattended session needs no local click and can start while the dialog is up, and
//! made a last time under the store lock, inside the store operation that commits the
//! change (decision M1-67), where a session reserved meanwhile counts as live;
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
use crate::levels::{AccountFacts, FactsSource, HelperPresence};
use crate::session_log::{Actor, SessionEvent, SessionLog, SessionRecord};
use crate::trusted::TrustedDevices;

use super::codec::StoreLoadError;
use super::grant::{
    AuthRecord, GrantId, GrantState, Preset, SuspendReason, UnattendedGrant, sanitize_label,
};
use super::ipc::{GrantOptions, codes};
use super::reach::{self, ReachRefusal};
use super::store::{GrantStore, State, StoreError, StoreStatus, WriteClass, push_tombstone};

/// Why *enable* refuses a grant at the administrator level whose password is marked
/// (`G_NEEDS_PASSWORD`; decision M1-67).
const MARKED_ADMIN_ENABLE: &str = "this grant holds administrator access and its password may be \
    kept elsewhere: give it a new generated password (Change password) before enabling it";

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

    /// The same for a registration that gives the device labelled `device` administrator
    /// access, or reach to it (decision M1-67, D3): the dialog says "give `<device>`
    /// ADMINISTRATOR access to this computer, with a new password" where it can show a
    /// sentence (Windows). The default asks as the operation `raise`.
    fn reauthenticate_raise(&self, device: &str) -> Result<(), ReAuthError> {
        let _ = device;
        self.reauthenticate("raise")
    }
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

/// Which of a device's sessions an end reaches (decision M1-67, D6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndScope {
    /// Every session of the device, live or reserved: its grant revoked, disabled or
    /// suspended.
    Every,
    /// Only its sessions at the administrator level: its grant lowered (D6). A session
    /// below the level goes on; an accept still being prepared is lowered by the read
    /// after the reservation.
    AtTheLevel,
}

/// Why a device's sessions end: what their `BYE` says (§B.8.6.1's mapping; decision
/// M1-67, D6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// `REVOKED`: the grant revoked, disabled, unpaired or lowered.
    Revoked,
    /// `SUSPENDED`: the grant suspended locally, by the block window or by an admin command.
    Suspended,
    /// `PANIC`: the grant suspended by the panic key.
    Panic,
}

/// Ends the sessions of one device within a second (decision M1-67, D6; §B.8.4.1's host
/// table): the host's kill switch addressed to one device (`tornect-signal`). The
/// offline CLI has none: no session runs there.
pub trait DeviceSessionEnd: Send + Sync {
    /// End the sessions of `device` that `scope` reaches, with `BYE{REVOKED}`.
    fn end_device(&self, device: &DeviceId, scope: EndScope);

    /// End them with the `BYE` that `reason` maps to. An end that does not tell the
    /// reasons apart ends them as [`Self::end_device`] does.
    fn end_device_because(&self, device: &DeviceId, scope: EndScope, reason: EndReason) {
        let _ = reason;
        self.end_device(device, scope);
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
    /// `G_UNSUPPORTED`: the administrator level where this host cannot give it; the
    /// detail says why (§B.8.7.4).
    #[error("{0}")]
    Unsupported(String),
    /// `G_NEEDS_PASSWORD`: a change that needs a new generated password, or a
    /// `RegFinish` that does not match its `RegStart` (decision M1-67).
    #[error("{0}")]
    NeedsPassword(String),
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
            Self::Unsupported(_) => codes::G_UNSUPPORTED,
            Self::NeedsPassword(_) => codes::G_NEEDS_PASSWORD,
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
            StoreError::RemoteSessionActive => Self::RemoteSessionActive,
            StoreError::NeedsPassword(m) => Self::NeedsPassword(m),
            StoreError::Unsupported(m) => Self::Unsupported(m),
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

/// What an admin request answers (decision M1-67, D1): its outcome and the requester's
/// `grant_reach`, as its grant was loaded under the lock of the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAnswer {
    /// The outcome (`ADMIN_RESULT.ok`, `detail`, the effect on live sessions).
    pub outcome: AdminOutcome,
    /// `ADMIN_RESULT.grant_reach`.
    pub grant_reach: u8,
}

/// An admin request that [`MutationGuard::admin`] does not answer as asked.
#[derive(Debug)]
pub enum AdminError {
    /// The requester's grant, re-loaded under the lock of the command, is gone, no longer
    /// eligible, or holds another `auth` record than the stream proved: the command does
    /// not run and no `ADMIN_RESULT` is signed (decision M1-67).
    Refused(ReachRefusal),
    /// The store could not apply the command: it took no effect, and an
    /// `AdminRequest{ok: false}` line says so. The answer still carries the requester's
    /// `grant_reach`.
    Failed {
        /// What failed.
        error: GuardError,
        /// The requester's `grant_reach`, read before the command.
        grant_reach: u8,
    },
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
    /// `tornect install` (§B.1.1, r7): Tornect copied into Program Files on
    /// Windows (then UAC), or into `~/.local/bin` with a menu entry on Linux.
    Install,
    /// `tornect uninstall` (§B.1.1, r7): what `tornect install` wrote, removed.
    Uninstall,
    /// The window's acknowledgement of the banner of devices that can connect
    /// without asking (§B.8.6.2): re-authentication with its own purpose.
    AcknowledgeBanner,
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
            Self::Install => "install",
            Self::Uninstall => "uninstall",
            Self::AcknowledgeBanner => "acknowledge_banner",
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
    /// The `RegStart` declared a raise (decision M1-67).
    raise: bool,
    /// The `RegStart` declared a generated password.
    generated: bool,
}

/// The mutation guard (§B.8.6.2).
pub struct MutationGuard {
    store: GrantStore,
    reauth: Arc<dyn ReAuth>,
    activity: Arc<dyn RemoteSessionActivity>,
    history: Arc<dyn AttendedHistory>,
    paired: Arc<dyn PairedDevices>,
    setup: Arc<dyn ServerSetupSource>,
    facts: Arc<dyn FactsSource>,
    device_end: Option<Arc<dyn DeviceSessionEnd>>,
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
    /// The normative constructor (§B.8.14). `facts` gives the account facts and the
    /// administrator helper task's presence, read at each admin answer (decision M1-67;
    /// `tornect-platform`'s `LiveFacts` on a host). The attended history defaults to the
    /// store's `sessions.log`, the pairing source to the `trusted-devices.toml` of the
    /// same state directory ([`FilePairedDevices`]), the `ServerSetup` source to
    /// [`NoServerSetupSource`].
    #[must_use]
    pub fn new(
        store: GrantStore,
        reauth: Arc<dyn ReAuth>,
        activity: Arc<dyn RemoteSessionActivity>,
        facts: Arc<dyn FactsSource>,
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
            facts,
            device_end: None,
            txns: Mutex::new(Vec::new()),
        }
    }

    /// End a device's sessions, live or reserved, when this guard revokes, disables,
    /// suspends or lowers its grant (decision M1-67, D6): the host's kill switch. Without
    /// it (the offline CLI) nothing is ended, as no session runs.
    #[must_use]
    pub fn with_device_end(mut self, end: Arc<dyn DeviceSessionEnd>) -> Self {
        self.device_end = Some(end);
        self
    }

    /// After a committed deny-direction change of `device`'s grant: the sessions `scope`
    /// reaches end, saying `reason`.
    fn end_sessions_of(&self, device: &DeviceId, scope: EndScope, reason: EndReason) {
        if let Some(end) = &self.device_end {
            end.end_device_because(device, scope, reason);
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

    /// What the grant precondition of §B.8.6.1 finds for `device` in this guard's own
    /// sources, read only: its pinned pairing label (`None`: not paired, so it gets no
    /// grant) and whether an attended session from it has completed (without one a grant
    /// needs the waiver, which *Headless box* gives itself).
    #[must_use]
    pub fn precondition(&self, device: &DeviceId) -> (Option<String>, bool) {
        (
            self.paired.pinned_label(device),
            self.history.completed_attended_sessions(device) > 0,
        )
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
        self.access_increasing_raising(op, by, device, None)
    }

    /// [`Self::access_increasing`], whose dialog, for a registration that gives the device
    /// labelled `raise` administrator access or reach to it, says so (decision M1-67).
    fn access_increasing_raising(
        &self,
        op: &str,
        by: Actor,
        device: Option<&DeviceId>,
        raise: Option<&str>,
    ) -> Result<(), GuardError> {
        self.no_remote_session(op, by, device)?;
        let dialog = match raise {
            Some(label) => self.reauth.reauthenticate_raise(label),
            None => self.reauth.reauthenticate(op),
        };
        if let Err(e) = dialog {
            return Err(self.refuse(op, Some(by), device, GuardError::ReauthFailed(e)));
        }
        self.no_remote_session(op, by, device)
    }

    /// `G_REMOTE_SESSION_ACTIVE` (logged) while a remote session is live or ended < 60 s
    /// ago. Called before and after every blocking step of an access-increasing
    /// operation (the re-auth dialog, the keychain bootstrap) and last thing before the
    /// store write, except where [`Self::no_session_at_commit`] makes the last check
    /// under the store lock.
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

    /// The last no-session check of an access-increasing operation (`create_grant`,
    /// `set_password`, `RegFinish`, `set_options`, *enable*, *resume*, local *unlock*,
    /// `set_settings`), made under the store lock inside the store operation that
    /// commits it (decision M1-67, D8.4; DA-17): a session reserved after the unlocked
    /// checks counts as live and is seen here, so the change either commits before the
    /// session's reservation or is refused. The refusal is returned unlogged, and the
    /// caller logs it once the lock is dropped ([`Self::refuse`] goes through
    /// `log_event`, which takes the same mutex). It takes the live-session lock inside
    /// the store lock: the order is store, then live-session, never the reverse.
    fn no_session_at_commit(&self) -> Result<(), StoreError> {
        if self.remote_session_blocks() {
            return Err(StoreError::RemoteSessionActive);
        }
        Ok(())
    }

    /// Log a refusal [`Self::no_session_at_commit`] decided, now that the store lock is
    /// dropped; any other store error passes through unlogged, as before.
    fn refused_at_commit(
        &self,
        op: &str,
        by: Actor,
        device: Option<&DeviceId>,
        e: StoreError,
    ) -> GuardError {
        match e {
            StoreError::RemoteSessionActive => {
                self.refuse(op, Some(by), device, GuardError::RemoteSessionActive)
            }
            other => other.into(),
        }
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
                // A shortened pause is access-increasing: its last no-session check is
                // made under the lock that commits it (decision M1-67).
                if shortens {
                    self.no_session_at_commit()?;
                }
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
        self.end_sessions_of(device, EndScope::Every, EndReason::Revoked);
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
        self.end_sessions_of(device, EndScope::Every, EndReason::Revoked);
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
            Ok(_) => {
                self.end_sessions_of(device, EndScope::Every, EndReason::Revoked);
                Ok(true)
            }
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

    /// A block window that could not be shown (§B.8.6.3): one `HostNotReady`
    /// line for `device`; the grant is left as it was (the request is refused,
    /// nothing is suspended).
    pub fn block_window_not_shown(&self, device: &DeviceId) -> Result<(), GuardError> {
        let id = self.store.grant(device).map(|g| g.id);
        let mut rec = SessionRecord::at(self.now(), SessionEvent::HostNotReady)
            .device(*device)
            .unattended(true);
        if let Some(id) = id {
            rec = rec.grant(&id);
        }
        self.store.log_event(&rec)?;
        Ok(())
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
        if outcome == SuspendOutcome::Suspended {
            // §B.8.6.1: a suspend says SUSPENDED; the panic key's says PANIC.
            let why = if reason == SuspendReason::Panic {
                EndReason::Panic
            } else {
                EndReason::Suspended
            };
            self.end_sessions_of(device, EndScope::Every, why);
        }
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
        self.store
            .mutate(WriteClass::Policy, Some(&rec), |s, _| {
                // Access-increasing (§B.8.6.2): the last no-session check is made under
                // the lock that commits it (decision M1-67).
                self.no_session_at_commit()?;
                s.enabled = true;
                s.paused_until = None;
                s.stop_token = Some(token);
                Ok(())
            })
            .map_err(|e| self.refused_at_commit("master_on", by, None, e))?;
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
        if existing.holds_level() && existing.marked() {
            return Err(self.refuse(
                "enable",
                Some(by),
                Some(device),
                GuardError::NeedsPassword(MARKED_ADMIN_ENABLE.into()),
            ));
        }
        let rec = SessionRecord::at(self.now(), SessionEvent::GrantEnabled)
            .by(by)
            .device(*device)
            .grant(&existing.id);
        self.store
            .update_grant(device, &rec, |g, _| {
                self.no_session_at_commit()?;
                // A grant at the level whose password is marked is enabled only once a new
                // generated password cleared the mark, whatever disabled it (decision
                // M1-67, D3, D9; checked again on the locked grant).
                if g.holds_level() && g.marked() {
                    return Err(StoreError::NeedsPassword(MARKED_ADMIN_ENABLE.into()));
                }
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
        if let Err(e) = self.no_session_at_commit() {
            drop(st);
            return Err(self.refuse("unlock", Some(by), Some(device), GuardError::from(e)));
        }
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
                self.no_session_at_commit()?;
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
        let lowered = match self.apply_options_locked(by, device, options, file_keystore, false) {
            Ok(Some(lowered)) => lowered,
            Ok(None) => {
                self.access_increasing(op, by, Some(device))?;
                self.apply_options_locked(by, device, options, file_keystore, true)
                    .map_err(|e| self.refuse(op, Some(by), Some(device), e))?
                    .unwrap_or(false)
            }
            Err(e) => return Err(self.refuse(op, Some(by), Some(device), e)),
        };
        // A lowering, decided under the lock that committed it, ends the device's sessions
        // at the level (D6).
        if lowered {
            self.end_sessions_of(device, EndScope::AtTheLevel, EndReason::Revoked);
        }
        Ok(())
    }

    /// Apply `options` to the locked grant, log `GrantChanged` and persist (policy
    /// write) in one critical section. A widening change without `reauthed` leaves
    /// everything untouched and returns `Ok(None)`; a committed change returns whether it
    /// took the grant off the administrator level (D6). Errors are returned unlogged (the
    /// caller writes the refusal line — never under this lock).
    fn apply_options_locked(
        &self,
        by: Actor,
        device: &DeviceId,
        options: &GrantOptions,
        file_keystore: bool,
        reauthed: bool,
    ) -> Result<Option<bool>, GuardError> {
        // The facts a raise is judged on, read before the lock (decision M1-67).
        let facts = (self.facts.account(), self.facts.helper_task());
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
        // A change that changes nothing (a level `none` asked of a grant without the
        // level): no `GrantChanged` line and no write. Judged here, under the lock, on the
        // loaded store's own grant, so it never answers for a grant another operation is
        // changing, a missing grant or a store that is not loaded.
        if before.grant(device) == st.store.as_ref().and_then(|s| s.grant(device)) {
            st.store = Some(before);
            return Ok(Some(false));
        }
        // A raise of the grant's own reach (the level, or control where it reaches the
        // level) comes only with a new generated password, never through `set_options`
        // (decision M1-67, D3): refused before any dialog, nothing changed. The level where
        // this host cannot give it at all is `G_UNSUPPORTED`.
        let (account, helper_task) = facts;
        let refusal = match (
            before.grant(device),
            st.store
                .as_ref()
                .and_then(|s| s.grant(device).map(|g| (s, g))),
        ) {
            (Some(old), Some((store, new))) => {
                if new.holds_level()
                    && !old.holds_level()
                    && let Some(why) = Self::level_unsupported(account, new.preset)
                {
                    Some(GuardError::Unsupported(why.to_owned()))
                } else if reach::own_reach(store, new, account, helper_task)
                    > reach::own_reach(&before, old, account, helper_task)
                {
                    Some(GuardError::NeedsPassword(
                        "this change gives the grant administrator reach: it needs a new \
                         generated password (Change password)"
                            .into(),
                    ))
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(e) = refusal {
            st.store = Some(before);
            return Err(e);
        }
        if !widened.is_empty() {
            if !reauthed {
                st.store = Some(before);
                return Ok(None);
            }
            // A widening change makes its last no-session check here, under the lock
            // that commits it (decision M1-67); a narrowing one is deny-direction.
            if let Err(e) = self.no_session_at_commit() {
                st.store = Some(before);
                return Err(e.into());
            }
        }
        // A lowering (D6), judged on the locked grant: the caller ends the device's sessions
        // at the level once this is committed.
        let lowered = matches!(
            (before.grant(device), st.store.as_ref().and_then(|s| s.grant(device))),
            (Some(old), Some(new)) if old.holds_level() && !new.holds_level()
        );
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
        Ok(Some(lowered))
    }

    /// Host-wide settings (access-increasing).
    pub fn set_settings(&self, by: Actor, settings: HostSettings) -> Result<(), GuardError> {
        self.access_increasing("set_settings", by, None)?;
        self.require_loaded("set_settings", Some(by), None)?;
        let rec = SessionRecord::at(self.now(), SessionEvent::GrantChanged)
            .by(by)
            .detail("host settings");
        self.store
            .mutate(WriteClass::Policy, Some(&rec), |s, _| {
                self.no_session_at_commit()?;
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
            })
            .map_err(|e| self.refused_at_commit("set_settings", by, None, e))?;
        Ok(())
    }

    /// Authorize an access-increasing operation whose effect lives outside the store
    /// (autostart, backup, identity view, settings, installing Tornect). Logs
    /// `AutostartChanged` / `BackupExported` / `Installed` / `Uninstalled`; the caller
    /// performs the effect after `Ok`, so no file is written before the line.
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
                | ExternalOp::Install
                | ExternalOp::Uninstall
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
            ExternalOp::Install => Some(SessionRecord::at(now, SessionEvent::Installed).by(by)),
            ExternalOp::Uninstall => Some(SessionRecord::at(now, SessionEvent::Uninstalled).by(by)),
            ExternalOp::BackupImport { .. }
            | ExternalOp::IdentityView
            | ExternalOp::SettingsChange { .. }
            | ExternalOp::AcknowledgeBanner => None,
        };
        if let Some(rec) = rec {
            self.store.log_event(&rec)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------ registration

    /// Why this host cannot give `preset`'s grant the administrator level, if it cannot
    /// (`G_UNSUPPORTED`, §B.8.7.4; the detail says why): Linux, a *Helping someone*
    /// grant, account facts that could not be read, a copy outside Program Files, a
    /// standard account.
    fn level_unsupported(account: AccountFacts, preset: Preset) -> Option<&'static str> {
        use crate::levels::{
            REFUSAL_ADMIN_HELPING_SOMEONE, REFUSAL_ADMIN_LINUX, REFUSAL_ADMIN_STANDALONE,
            REFUSAL_ADMIN_STANDARD_ACCOUNT, REFUSAL_ADMIN_UNREADABLE,
        };
        match account {
            AccountFacts::Linux => Some(REFUSAL_ADMIN_LINUX),
            _ if preset == Preset::HelpingSomeone => Some(REFUSAL_ADMIN_HELPING_SOMEONE),
            AccountFacts::Unreadable => Some(REFUSAL_ADMIN_UNREADABLE),
            AccountFacts::Windows(f) if !f.installed => Some(REFUSAL_ADMIN_STANDALONE),
            AccountFacts::Windows(f) if !f.administrator => Some(REFUSAL_ADMIN_STANDARD_ACCOUNT),
            AccountFacts::Windows(_) => None,
        }
    }

    /// How a registration (creation or set-password) of `device` with `preset` and
    /// `options` changes the grant's own reach, judged on the store as it is now and on
    /// `account` / `helper_task` (decision M1-67, D3): `G_UNSUPPORTED` when it would give
    /// the level where this host cannot; otherwise whether it creates a grant with reach
    /// or raises one (the dialog then names administrator access). Decided again under
    /// the lock of the commit.
    fn registration_raises(
        &self,
        device: &DeviceId,
        preset: Preset,
        options: &GrantOptions,
        account: AccountFacts,
        helper_task: HelperPresence,
    ) -> Result<bool, GuardError> {
        let (now, file_keystore) = (self.now(), self.store.keystore_kind().is_file());
        let judged = self.store.read(|s| {
            Self::judge_reach(
                s,
                device,
                preset,
                options,
                (account, helper_task),
                (now, file_keystore),
                false,
            )
        });
        judged.map_or(Ok(false), |r| r.map(|p| p.raises))
    }

    /// [`Self::registration_raises`]'s judgement on the store `s`, on `facts` (the account,
    /// the helper task) and at `at` (the wall clock, a file keystore), with the other
    /// grants the change makes reach the level when `list` is set.
    fn judge_reach(
        s: &super::grant::UnattendedStore,
        device: &DeviceId,
        preset: Preset,
        options: &GrantOptions,
        facts: (AccountFacts, HelperPresence),
        at: (u64, bool),
        list: bool,
    ) -> Result<ReachPreview, GuardError> {
        let ((account, helper_task), (now, file_keystore)) = (facts, at);
        let before = s.grant(device).cloned();
        let mut after = match &before {
            Some(g) => g.clone(),
            None => {
                let auth = AuthRecord::Opaque {
                    record: Zeroizing::new(Vec::new()),
                };
                UnattendedGrant::from_preset(
                    [0; 8],
                    *device,
                    "probe",
                    Actor::Ui,
                    preset,
                    1,
                    auth,
                    now,
                )
                .map_err(|e| GuardError::Precondition(e.to_string()))?
            }
        };
        after
            .apply_options(options, now, file_keystore)
            .map_err(|e| GuardError::Precondition(e.to_string()))?;
        let gains_level = after.holds_level() && before.as_ref().is_none_or(|g| !g.holds_level());
        if gains_level && let Some(why) = Self::level_unsupported(account, after.preset) {
            return Err(GuardError::Unsupported(why.to_owned()));
        }
        let reach_before = before
            .as_ref()
            .map_or(0, |g| reach::own_reach(s, g, account, helper_task));
        let reach_after = reach::own_reach(s, &after, account, helper_task);
        let newly_reaching = if list {
            // The store as the change leaves it: each other grant's own reach judged
            // there and here.
            let mut changed = s.clone();
            match changed.grants.iter_mut().find(|g| g.device == *device) {
                Some(g) => *g = after,
                None => changed.grants.push(after),
            }
            s.grants
                .iter()
                .filter(|g| {
                    g.device != *device
                        && reach::own_reach(&changed, g, account, helper_task)
                            > reach::own_reach(s, g, account, helper_task)
                })
                .map(|g| NewlyReaching {
                    device: g.device,
                    label: g.label.clone(),
                    marked: g.marked(),
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(ReachPreview {
            raises: reach_after > reach_before,
            reach_before,
            reach_after,
            newly_reaching,
        })
    }

    /// The preview of a registration (a creation, or a new password) or an options change
    /// of `device`'s grant with `preset` and `options` (§B.8.7.1 ④, decision M1-67):
    /// whether it raises the grant's own reach, its reach before and after, and the other
    /// grants whose control it makes reach the administrator level, each with its pinned
    /// label and its mark. Judged by the functions the commit judges with, on the account
    /// facts and the helper task read now and the store as it is now (a store not created
    /// yet as the first enable creates it: empty); the commit judges again under its lock.
    /// Read only: no dialog, no log line, no write. The level where this host cannot give
    /// it is `G_UNSUPPORTED`, and options the grant cannot take `G_PRECONDITION`, both
    /// returned unlogged.
    pub fn preview(
        &self,
        device: &DeviceId,
        preset: Preset,
        options: &GrantOptions,
    ) -> Result<ReachPreview, GuardError> {
        let facts = (self.facts.account(), self.facts.helper_task());
        let now = self.now();
        let at = (now, self.store.keystore_kind().is_file());
        let judge = |s: &super::grant::UnattendedStore| {
            Self::judge_reach(s, device, preset, options, facts, at, true)
        };
        self.store.read(judge).unwrap_or_else(|| {
            judge(&super::grant::UnattendedStore::bootstrap(
                Zeroizing::new(Vec::new()),
                None,
                now,
            ))
        })
    }

    /// `RegStart` (§B.8.7.4): re-auth here; returns a single-use `reg_txn` (≤ 120 s,
    /// bound to `device`) and the `ServerSetup` bytes (bootstrapping the store first if
    /// unattended access was never enabled). `raise` (the registration creates a grant
    /// whose `grant_reach` is not 0, or raises one) and `generated` are kept with the
    /// transaction; a raising `RegStart` asks with its own wording, naming administrator
    /// access and the device (decision M1-67, D3). No registration raises on Linux.
    pub fn reg_start(
        &self,
        by: Actor,
        device: &DeviceId,
        raise: bool,
        generated: bool,
    ) -> Result<RegStartOk, GuardError> {
        let op = "reg_start";
        // Cheap preconditions first: no dialog for a device that can never get a grant.
        let label = self.require_paired(op, by, device)?;
        if raise && self.facts.account() == AccountFacts::Linux {
            return Err(self.refuse(
                op,
                Some(by),
                Some(device),
                GuardError::Unsupported(crate::levels::REFUSAL_ADMIN_LINUX.to_owned()),
            ));
        }
        self.access_increasing_raising(op, by, Some(device), raise.then_some(label.as_str()))?;
        self.bootstrap_if_needed(op, by)?;
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
            raise,
            generated,
        });
        Ok(RegStartOk {
            reg_txn: txn,
            server_setup,
        })
    }

    /// The live transaction `txn` of `device`, consumed: its `raise` and `generated`.
    fn take_txn(&self, device: &DeviceId, txn: &[u8; 16]) -> Option<(bool, bool)> {
        let now = Instant::now();
        let mut txns = self.txns.lock();
        txns.retain(|t| now.duration_since(t.created) < REG_TXN_TTL);
        let pos = txns.iter().position(|t| {
            bool::from(subtle::ConstantTimeEq::ct_eq(&t.txn[..], &txn[..])) && t.device == *device
        })?;
        let entry = txns.remove(pos);
        Some((entry.raise, entry.generated))
    }

    /// `RegFinish` (§B.8.7.4): needs the live `reg_txn` (consumed), re-checks
    /// [`RemoteSessionActivity`], then creates the grant (no grant yet) or replaces its
    /// auth record (set-password). `generated` must be what its `RegStart` declared, and a
    /// finish that creates a grant with reach or raises one needs a raising `RegStart`
    /// (`G_NEEDS_PASSWORD` otherwise; decision M1-67). The options of a set-password may
    /// carry exactly a raise, and only with `generated`; any other widening goes through
    /// [`Self::set_options`].
    #[allow(clippy::too_many_arguments)]
    pub fn reg_finish(
        &self,
        by: Actor,
        device: &DeviceId,
        reg_txn: &[u8; 16],
        upload: &[u8],
        preset: Preset,
        options: &GrantOptions,
        generated: bool,
    ) -> Result<RegFinishOutcome, GuardError> {
        let op = "reg_finish";
        let Some((raise, declared_generated)) = self.take_txn(device, reg_txn) else {
            return Err(self.refuse(op, Some(by), Some(device), GuardError::NoTxn));
        };
        if self.remote_session_blocks() {
            return Err(self.refuse(op, Some(by), Some(device), GuardError::RemoteSessionActive));
        }
        if generated != declared_generated {
            return Err(self.refuse(
                op,
                Some(by),
                Some(device),
                GuardError::NeedsPassword(
                    "this registration's password is not what its RegStart declared".into(),
                ),
            ));
        }
        self.apply_registration(
            by,
            device,
            upload,
            preset,
            options,
            generated,
            Asked::RegStart(raise),
        )
    }

    /// One-operation grant creation (UI path): re-auth inline, then the registration.
    /// `generated`: the password came from the passphrase generator. A creation with
    /// reach asks with the raising wording, and needs `generated` (decision M1-67).
    pub fn create_grant(
        &self,
        by: Actor,
        device: &DeviceId,
        preset: Preset,
        options: &GrantOptions,
        upload: &[u8],
        generated: bool,
    ) -> Result<GrantId, GuardError> {
        let op = "create_grant";
        let label = self.require_paired(op, by, device)?;
        let raising = self
            .registration_raises(
                device,
                preset,
                options,
                self.facts.account(),
                self.facts.helper_task(),
            )
            .map_err(|e| self.refuse(op, Some(by), Some(device), e))?;
        self.access_increasing_raising(op, by, Some(device), raising.then_some(label.as_str()))?;
        self.bootstrap_if_needed(op, by)?;
        self.no_remote_session(op, by, Some(device))?;
        if self.store.grant(device).is_some() {
            return Err(self.refuse(
                op,
                Some(by),
                Some(device),
                GuardError::from(StoreError::GrantExists),
            ));
        }
        let asked = Asked::Dialog(raising);
        match self.apply_registration(by, device, upload, preset, options, generated, asked)? {
            RegFinishOutcome::Created(id) | RegFinishOutcome::PasswordSet(id) => Ok(id),
        }
    }

    /// One-operation password change (UI path): re-auth inline, then the registration.
    /// `options` may carry exactly a raise (the level, or control where it reaches the
    /// level), applied in the write that replaces `auth`, and only with `generated`; such
    /// a change asks with the raising wording (decision M1-67, D3).
    pub fn set_password(
        &self,
        by: Actor,
        device: &DeviceId,
        upload: &[u8],
        options: &GrantOptions,
        generated: bool,
    ) -> Result<GrantId, GuardError> {
        let op = "set_password";
        self.require_loaded(op, Some(by), Some(device))?;
        let (preset, label) = self
            .store
            .grant(device)
            .map(|g| (g.preset, g.label))
            .ok_or_else(|| {
                self.refuse(
                    op,
                    Some(by),
                    Some(device),
                    GuardError::from(StoreError::NoGrant),
                )
            })?;
        let raising = self
            .registration_raises(
                device,
                preset,
                options,
                self.facts.account(),
                self.facts.helper_task(),
            )
            .map_err(|e| self.refuse(op, Some(by), Some(device), e))?;
        self.access_increasing_raising(op, by, Some(device), raising.then_some(label.as_str()))?;
        self.require_loaded(op, Some(by), Some(device))?;
        let asked = Asked::Dialog(raising);
        match self.apply_registration(by, device, upload, preset, options, generated, asked)? {
            RegFinishOutcome::Created(id) | RegFinishOutcome::PasswordSet(id) => Ok(id),
        }
    }

    /// The registration both paths share. `asked`: whether what the owner confirmed named
    /// a raise, a `RegStart`'s declaration or the window's own dialog, worded on facts and a
    /// store read taken before it. Decided under the lock of the commit (decision M1-67, D3,
    /// D4, D9): the level where this host cannot give it ⇒ `G_UNSUPPORTED`; a creation with
    /// reach or a raise without `generated`, or one that what was confirmed did not name
    /// (it appeared meanwhile: S5B-2) ⇒ `G_NEEDS_PASSWORD`, nothing written; the new
    /// password is unmarked exactly when it is `generated`.
    #[allow(clippy::too_many_arguments)]
    fn apply_registration(
        &self,
        by: Actor,
        device: &DeviceId,
        upload: &[u8],
        preset: Preset,
        options: &GrantOptions,
        generated: bool,
        asked: Asked,
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
        let account = self.facts.account();
        let helper_task = self.facts.helper_task();
        // What a raise or a creation with reach needs, judged on the locked store.
        let raise_rule = |raises: bool| -> Result<(), StoreError> {
            if raises && !generated {
                return Err(StoreError::NeedsPassword(
                    "a grant whose password can reach administrator access needs a new generated \
                     password"
                        .into(),
                ));
            }
            match asked {
                Asked::RegStart(false) if raises => Err(StoreError::NeedsPassword(
                    "this registration gives the grant administrator reach, but its RegStart did \
                     not say so"
                        .into(),
                )),
                Asked::Dialog(false) if raises => Err(StoreError::NeedsPassword(
                    "this registration gives the grant administrator reach, but the confirmation \
                     did not say so"
                        .into(),
                )),
                Asked::RegStart(_) | Asked::Dialog(_) => Ok(()),
            }
        };
        let auth = AuthRecord::Opaque {
            record: Zeroizing::new(upload.to_vec()),
        };
        let now = self.now();
        let file_keystore = self.store.keystore_kind().is_file();
        if let Some(existing) = self.store.grant(device) {
            // set-password: replace the record; options may carry exactly a raise
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
            let raises = self
                .registration_raises(device, preset, options, account, helper_task)
                .map_err(|e| self.refuse(op, Some(by), Some(device), e))?;
            let other: Vec<&str> = widened
                .iter()
                .copied()
                .filter(|w| !(raises && matches!(*w, "elevation" | "mode")))
                .collect();
            if !other.is_empty() {
                return Err(self.refuse(
                    op,
                    Some(by),
                    Some(device),
                    GuardError::Precondition(format!(
                        "options widen the grant ({}); use set_options",
                        other.join(",")
                    )),
                ));
            }
            let rec = SessionRecord::at(now, SessionEvent::PasswordSet)
                .by(by)
                .device(*device)
                .grant(&existing.id);
            let lowered = self
                .store
                .mutate(WriteClass::Policy, Some(&rec), |s, now| {
                    self.no_session_at_commit()?;
                    let Some(before) = s.grant(device).cloned() else {
                        return Err(StoreError::NoGrant);
                    };
                    let mut after = before.clone();
                    // classified again on the locked grant: a concurrent change must not
                    // turn these options into a widening, or a raise, that lands here
                    let widened = after.apply_options(options, now, file_keystore)?;
                    let raises = reach::own_reach(s, &after, account, helper_task)
                        > reach::own_reach(s, &before, account, helper_task);
                    if after.holds_level()
                        && !before.holds_level()
                        && let Some(why) = Self::level_unsupported(account, after.preset)
                    {
                        return Err(StoreError::Unsupported(why.to_owned()));
                    }
                    let other: Vec<&str> = widened
                        .iter()
                        .copied()
                        .filter(|w| !(raises && matches!(*w, "elevation" | "mode")))
                        .collect();
                    if !other.is_empty() {
                        return Err(StoreError::Invalid(format!(
                            "options widen the grant ({}); use set_options",
                            other.join(",")
                        )));
                    }
                    raise_rule(raises)?;
                    // A lowering that comes with the new password (D6).
                    let lowered = before.holds_level() && !after.holds_level();
                    after.auth = auth;
                    after.suite = 1;
                    // Only a password sent as generated clears the mark (D9, D11).
                    after.unmarked = generated;
                    let g = s.grant_mut(device).ok_or(StoreError::NoGrant)?;
                    *g = after;
                    Ok(lowered)
                })
                .map_err(|e| self.refuse(op, Some(by), Some(device), GuardError::from(e)))?;
            if lowered {
                self.end_sessions_of(device, EndScope::AtTheLevel, EndReason::Revoked);
            }
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
        if grant.holds_level()
            && let Some(why) = Self::level_unsupported(account, preset)
        {
            return Err(self.refuse(
                op,
                Some(by),
                Some(device),
                GuardError::Unsupported(why.to_owned()),
            ));
        }
        // Only a password sent as generated is unmarked (D9, D11).
        grant.unmarked = generated;
        let mut rec = SessionRecord::at(now, SessionEvent::GrantCreated)
            .by(by)
            .device(*device)
            .grant(&id)
            .detail(format!("preset {}", preset.wire()));
        if options.waive_attended_precondition {
            rec = rec.reason("attended precondition waived");
        }
        let keep_awake = preset.defaults().keep_awake;
        let candidate = grant.clone();
        self.store
            .insert_grant(grant, &rec, |s| {
                self.no_session_at_commit()?;
                // A creation with reach (the level, or control where clause (ii) holds)
                // needs a generated password, decided on the locked store (DA-18, ND-3).
                raise_rule(reach::own_reach(s, &candidate, account, helper_task) > 0)?;
                if keep_awake {
                    s.keep_awake = true;
                }
                Ok(())
            })
            .map_err(|e| match e {
                StoreError::RemoteSessionActive => self.refused_at_commit(op, by, Some(device), e),
                StoreError::NeedsPassword(_) | StoreError::Unsupported(_) => {
                    self.refuse(op, Some(by), Some(device), GuardError::from(e))
                }
                other => other.into(),
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

    /// A post-PAKE admin request from `requester`, whose PAKE ran against the stored `auth`
    /// record with SHA-256 `auth_digest` (§B.8.4.1 scope; decision M1-67, B, D1).
    ///
    /// The account facts and the helper task's presence are read first, outside the store
    /// lock; then one store operation, under the lock that applies the command, re-loads
    /// the requester's grant. Gone or no longer eligible (unattended access off or paused,
    /// not `Active`, expired, not yet active, `Pruned`, hard-locked), or holding an `auth`
    /// record other than the one this stream proved, it is [`AdminError::Refused`]: the
    /// command does not run and no `ADMIN_RESULT` is signed. Otherwise every answer
    /// carries the requester's `grant_reach` as its grant was loaded before the command.
    ///
    /// Scope: every grant may `end_session` (own) and `revoke` (own pk); `unlock(pk)`,
    /// `suspend(pk ≠ self)`, `revoke(pk ≠ self)`, `revoke_all` and `master_off` need a
    /// *My machines* Control grant in `Active` state. Out of scope ⇒ `ok: false`, no state
    /// change.
    ///
    /// [`AdminError::Failed`] means the command took no effect: every write that follows
    /// a committed mutation is best-effort, so a committed deny-direction command is never
    /// reported as failed, and never loses the effect that ends live sessions.
    ///
    /// Every answer writes an `AdminRequest` line, with the command's own write (the
    /// locked logger) or once the lock is dropped; a line that cannot be written is warned
    /// and does not hold the answer back.
    pub fn admin(
        &self,
        requester: &DeviceId,
        auth_digest: &[u8; 32],
        op: AdminOp,
    ) -> Result<AdminAnswer, AdminError> {
        self.answer_admin(requester, auth_digest, Ok(op))
    }

    /// An admin command refused before it reaches [`Self::admin`]: missing, or one this
    /// build does not run (`why`; decision M1-67, D1). The requester's grant is checked as
    /// for any command, the answer carries its `grant_reach`, and its line names op
    /// `unknown`.
    pub fn admin_refused_early(
        &self,
        requester: &DeviceId,
        auth_digest: &[u8; 32],
        why: &str,
    ) -> Result<AdminAnswer, AdminError> {
        self.answer_admin(requester, auth_digest, Err(why))
    }

    fn answer_admin(
        &self,
        requester: &DeviceId,
        auth_digest: &[u8; 32],
        op: Result<AdminOp, &str>,
    ) -> Result<AdminAnswer, AdminError> {
        let account = self.facts.account();
        let helper_task = self.facts.helper_task();
        let op_name = op.map_or("unknown", |o| o.name());
        // Lines written once the lock is dropped (`log_event` takes the same mutex).
        let mut after: Vec<SessionRecord> = Vec::new();
        let refused = |why: &str| AdminOutcome {
            ok: false,
            detail: Some(why.to_owned()),
            effect: AdminEffect::None,
        };
        let (result, grant_reach) = {
            let mut st = self.store.state();
            if st.status != StoreStatus::Loaded {
                return Err(AdminError::Refused(ReachRefusal::NotEligible));
            }
            let (now, seen) = self.store.wall_locked(&mut st);
            let Some(store) = st.store.as_ref() else {
                return Err(AdminError::Refused(ReachRefusal::NotEligible));
            };
            let Some(req) = store.grant(requester).cloned() else {
                return Err(AdminError::Refused(ReachRefusal::NotEligible));
            };
            let grant_reach = reach::grant_reach_of(store, &req, account, helper_task);
            // The rollback rule of every wall-clock evaluation (§B.8.5.3): the requester's
            // `active_from` and a pause cannot be judged on a clock behind `last_seen`.
            let rollback = now < store.last_seen_unix.max(seen);
            // The eligibility the gate applies (its own ladder lock excepted: this very
            // stream's charge armed it), then the record this stream proved. Every term a
            // clock behind `last_seen` can still decide is checked before a rollback is
            // answered, so that a gone, ineligible or replaced grant is refused as at the
            // read after the reservation, with no answer signed (B; S5B-1). An expiry
            // already reached on that clock is reached now as well.
            let standing = store.enabled
                && req.state == GrantState::Active
                && !req.expired_at(now)
                && req.auth != AuthRecord::Pruned
                && !req.fail.hard_locked;
            let timely = store.active_at(now) && now >= req.active_from;
            if rollback {
                self.store
                    .note_anomaly_locked(&mut st, now, self.store.clock().mono());
            }
            if !standing || (!rollback && !timely) {
                return Err(AdminError::Refused(ReachRefusal::NotEligible));
            }
            let proven = reach::auth_digest(&req.auth);
            if !bool::from(subtle::ConstantTimeEq::ct_eq(&proven[..], &auth_digest[..])) {
                return Err(AdminError::Refused(ReachRefusal::AuthReplaced));
            }
            let base = |ok: bool| {
                SessionRecord::at(now, SessionEvent::AdminRequest)
                    .device(*requester)
                    .grant(&req.id)
                    .op(op_name)
                    .ok(ok)
                    .unattended(true)
            };
            let result = if rollback {
                after.push(base(false).detail("clock rollback"));
                Ok(refused("clock rollback"))
            } else {
                match op {
                    Err(why) => {
                        after.push(base(false).detail(why));
                        Ok(refused(why))
                    }
                    Ok(op) => {
                        let own = |d: &DeviceId| d == requester;
                        let in_scope = match op {
                            AdminOp::EndSession => true,
                            AdminOp::Revoke(d) => own(&d) || req.has_admin_scope(),
                            AdminOp::RevokeAll | AdminOp::MasterOff | AdminOp::Unlock(_) => {
                                req.has_admin_scope()
                            }
                            AdminOp::Suspend(d) => !own(&d) && req.has_admin_scope(),
                        };
                        if in_scope {
                            self.admin_locked(&mut st, requester, now, op, &base, &mut after)
                        } else {
                            after.push(base(false).detail("out of scope for this grant"));
                            Ok(refused("out of scope for this grant"))
                        }
                    }
                }
            };
            (result, grant_reach)
        };
        if let Err(e) = &result {
            after.push(
                SessionRecord::at(self.now(), SessionEvent::AdminRequest)
                    .device(*requester)
                    .op(op_name)
                    .ok(false)
                    .unattended(true)
                    .code(e.code())
                    .detail("host could not apply the command"),
            );
        }
        for rec in &after {
            if let Err(e) = self.store.log_event(rec) {
                tracing::warn!(error = %e, op = op_name, "could not log an AdminRequest line");
            }
        }
        // A remote revoke or suspend ends that device's sessions here, once its write has
        // committed and its lines are written, whatever becomes of the requester's stream
        // (D6; S5B-3). The host-wide effects stay with the state machine, after the
        // answer: they end the requester's own stream too.
        if let Ok(outcome) = &result {
            match &outcome.effect {
                AdminEffect::Revoked(target) => {
                    self.end_sessions_of(target, EndScope::Every, EndReason::Revoked);
                }
                AdminEffect::Suspended(target) => {
                    self.end_sessions_of(target, EndScope::Every, EndReason::Suspended);
                }
                AdminEffect::None
                | AdminEffect::RevokedAll(_)
                | AdminEffect::MasterOff
                | AdminEffect::Unlocked(_)
                | AdminEffect::EndSession => {}
            }
        }
        match result {
            Ok(outcome) => Ok(AdminAnswer {
                outcome,
                grant_reach,
            }),
            Err(error) => Err(AdminError::Failed { error, grant_reach }),
        }
    }

    /// Run the in-scope `op` for `requester` under the held store lock: the locked
    /// revoke, revoke-all and master-off of decision M1-67. The `AdminRequest` line goes
    /// with the command's own write; the per-event lines of §B.8.13 (`GrantRevoked`,
    /// `UnattendedDisabled`, `UnattendedSuspended`), which follow a committed command and
    /// are best-effort, are queued in `after`. An error means nothing was kept.
    fn admin_locked(
        &self,
        st: &mut State,
        requester: &DeviceId,
        now: u64,
        op: AdminOp,
        base: &dyn Fn(bool) -> SessionRecord,
        after: &mut Vec<SessionRecord>,
    ) -> Result<AdminOutcome, GuardError> {
        let refused = |why: &str| AdminOutcome {
            ok: false,
            detail: Some(why.to_owned()),
            effect: AdminEffect::None,
        };
        // The per-event lines are written next to the `AdminRequest` line, so a viewer
        // filtering on them sees remote revocations and a remote master off too; failing
        // the command over a missing second line would report a committed
        // deny-direction change as not done *and* drop the effect that ends live sessions.
        let by_admin = |ev: SessionEvent| {
            SessionRecord::at(now, ev)
                .unattended(true)
                .reason("admin")
                .detail(format!("by admin {requester}"))
        };
        let effect = match op {
            // Ending one's own session changes no state; the line is the record.
            AdminOp::EndSession => {
                after.push(base(true));
                AdminEffect::EndSession
            }
            AdminOp::Revoke(d) => {
                let rec = base(true).detail(format!("target {d}"));
                let removed =
                    self.store
                        .mutate_locked(st, WriteClass::Policy, Some(&rec), |s, now| {
                            let idx = s
                                .grants
                                .iter()
                                .position(|g| g.device == d)
                                .ok_or(StoreError::NoGrant)?;
                            let g = s.grants.remove(idx);
                            push_tombstone(s, d, now);
                            Ok(g.id)
                        });
                match removed {
                    Ok(id) => {
                        st.runtime.remove(&d);
                        after.push(by_admin(SessionEvent::GrantRevoked).device(d).grant(&id));
                        AdminEffect::Revoked(d)
                    }
                    Err(StoreError::NoGrant) => {
                        after.push(base(false).detail("target has no grant"));
                        return Ok(refused("target has no grant"));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            AdminOp::RevokeAll => {
                let n = self.store.mutate_locked(
                    st,
                    WriteClass::Policy,
                    Some(&base(true)),
                    |s, now| {
                        let devices: Vec<DeviceId> = s.grants.iter().map(|g| g.device).collect();
                        for d in &devices {
                            push_tombstone(s, *d, now);
                        }
                        s.grants.clear();
                        Ok(devices.len())
                    },
                )?;
                st.runtime.clear();
                after.push(
                    by_admin(SessionEvent::GrantRevoked)
                        .detail(format!("revoke all ({n}) by admin {requester}")),
                );
                AdminEffect::RevokedAll(n)
            }
            AdminOp::MasterOff => {
                self.store
                    .mutate_locked(st, WriteClass::Policy, Some(&base(true)), |s, _| {
                        s.enabled = false;
                        Ok(())
                    })?;
                after.push(by_admin(SessionEvent::UnattendedDisabled));
                AdminEffect::MasterOff
            }
            AdminOp::Unlock(d) => {
                let before = st.store.clone();
                let before_rt = st.runtime.get(&d).copied();
                match self.store.reset_fail_locked(st, &d) {
                    Ok(()) => {}
                    Err(StoreError::NoGrant) => {
                        after.push(base(false).detail("target has no grant"));
                        return Ok(refused("target has no grant"));
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
                    .log_locked(st, &base(true).detail(format!("target {d}")))
                    .and_then(|()| {
                        self.store.log_locked(
                            st,
                            &SessionRecord::at(now, SessionEvent::UnattendedUnlock)
                                .device(d)
                                .reason("admin")
                                .detail(format!("by {requester}")),
                        )
                    })
                    .and_then(|()| self.store.write_locked(st, WriteClass::Policy));
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
                let changed =
                    self.store
                        .mutate_locked(st, WriteClass::Policy, Some(&rec), |s, now| {
                            let g = s.grant_mut(&d).ok_or(StoreError::NoGrant)?;
                            Ok(match g.state {
                                GrantState::Active => {
                                    g.state = GrantState::Suspended {
                                        reason: SuspendReason::Admin,
                                        since: now,
                                    };
                                    true
                                }
                                // the local reasons outrank Admin; an already suspended
                                // grant is untouched
                                _ => false,
                            })
                        });
                match changed {
                    Ok(true) => {
                        after.push(
                            SessionRecord::at(now, SessionEvent::UnattendedSuspended)
                                .device(d)
                                .reason(SuspendReason::Admin.log_name())
                                .detail(format!("by {requester}")),
                        );
                        AdminEffect::Suspended(d)
                    }
                    Ok(false) => AdminEffect::None,
                    Err(StoreError::NoGrant) => {
                        after.push(base(false).detail("target has no grant"));
                        return Ok(refused("target has no grant"));
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
}

/// One other grant whose control a change would newly make reach the administrator
/// level (decision M1-67; the list of §B.8.7.1 ⑤a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewlyReaching {
    /// Its device.
    pub device: DeviceId,
    /// Its pinned label.
    pub label: String,
    /// Its password is marked "answered 0" (§B.8.6.1): it is served view only there
    /// until it gets a new generated password.
    pub marked: bool,
}

/// What a registration (a creation or a new password) or an options change of one
/// device's grant would do to its reach, judged as the commit judges it (decision M1-67;
/// §B.8.7.1 ④'s "is or becomes"): [`MutationGuard::preview`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachPreview {
    /// The change raises the grant's own reach, a creation with reach included: its
    /// registration needs a raising `RegStart` and a generated password, and
    /// `set_options` refuses it (`G_NEEDS_PASSWORD`).
    pub raises: bool,
    /// The grant's own reach before the change (2: it holds the level; 1: its control
    /// reaches the level; 0: neither), the mark aside; 0 for a grant not stored yet and
    /// always 0 on Linux.
    pub reach_before: u8,
    /// The grant's own reach after the change, in the same terms.
    pub reach_after: u8,
    /// The other grants whose control the change makes reach the level, in the store's
    /// order.
    pub newly_reaching: Vec<NewlyReaching>,
}

impl ReachPreview {
    /// The grant's reach is or becomes non-zero: its new password can only be
    /// generated (§B.8.7.1 ④, §B.8.7.2).
    #[must_use]
    pub fn generated_only(&self) -> bool {
        self.reach_before > 0 || self.reach_after > 0
    }
}

/// What the owner confirmed before a registration, and whether it named a raise
/// (decision M1-67, D3): a `RegStart`'s declaration, or the window's own dialog.
#[derive(Debug, Clone, Copy)]
enum Asked {
    /// The `RegStart` of this registration declared `raise`.
    RegStart(bool),
    /// The window's create or Change password dialog, worded for a raise or not.
    Dialog(bool),
}
