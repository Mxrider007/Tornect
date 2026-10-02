//! [`GrantStore`]: the single writer of the encrypted unattended store
//! (`docs/PLAN.md` §B.8.9) — load rules, the two write classes, the generation
//! anchor, the store lock, the machine-id check, grant CRUD, tombstones, pruning and
//! the `sessions.log` head (§B.8.13).
//!
//! The API is synchronous (async callers use `spawn_blocking`); every operation runs
//! under one mutex so a charge, a policy write and a log append never interleave.
//!
//! Two load modes (§B.8.5.1): the **host** load ([`GrantStore::open`]) settles a
//! `pending` charge, applies the wall-clock decay, re-arms locks and runs the machine-id
//! check; the **offline** load ([`GrantStore::open_offline`], the CLI with no host
//! running) only decodes and verifies — it never applies or persists decay, and the only
//! `FailState` it ever writes is the reset of a local *Unlock*.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, MutexGuard};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::id::DeviceId;
use crate::keystore::{KeystoreKind, SecretStore, create_private_dir, write_private_file};
use crate::paths::Paths;
use crate::session_log::{ChainReport, ChainStatus, SessionEvent, SessionLog, SessionRecord};

use super::clock::Clock;
use super::codec::{self, MASTER_KEY_ENTRY, MasterKey, StoreLoadError};
use super::grant::{
    AuthRecord, FailState, GrantId, GrantOptionsError, GrantState, PRUNE_AFTER_EXPIRY_S,
    UnattendedGrant, UnattendedStore,
};

/// Period of the consecutive-failure decay (§B.8.5.1).
pub const DECAY_PERIOD_S: u64 = 24 * 3600;
/// Period of the lifetime-budget decay (§B.8.5.1).
pub const LIFETIME_DECAY_PERIOD_S: u64 = 7 * 24 * 3600;
/// Tombstones kept (oldest dropped beyond this).
pub const MAX_TOMBSTONES: usize = 1024;
/// `ClockAnomaly` lines are rate-aggregated to one per this interval.
pub const ANOMALY_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// The two write classes of §B.8.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteClass {
    /// `FailState`, `last_used`, auto-renewed expiry, `log_chain_head`, `last_seen`:
    /// bumps only the in-file generation.
    Runtime,
    /// Every access-increasing and deny-direction mutation: bumps the in-file
    /// generation *and* the keychain anchor (owed while the keychain is unwritable).
    Policy,
}

/// Who loaded the store (§B.8.5.1: a *load* that settles and decays is the host's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadMode {
    /// The host process: `pending` settled as fail, decay applied and persisted, locks
    /// re-armed, machine-id check, the limiter authoritative until the next load.
    Host,
    /// The offline CLI (no host running): decode and verify only — `FailState` bytes stay
    /// untouched except for a local *Unlock*; no limiter, no housekeeping.
    Offline,
}

/// Where the store stands after [`GrantStore::open`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreStatus {
    /// No anchor and no file: unattended access was never enabled (tags are `null`).
    AttendedOnly,
    /// Decrypted and accepted; the in-memory limiter is authoritative until the next load.
    Loaded,
    /// Refused (§B.8.9): unattended off + notification, never a silent reset.
    FailedClosed(StoreLoadError),
}

/// Errors of the store API.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The store is not usable (attended-only or failed closed).
    #[error("unattended store not loaded: {0:?}")]
    NotLoaded(StoreStatus),
    /// No grant exists for the device.
    #[error("no unattended grant for this device")]
    NoGrant,
    /// A grant already exists for the device.
    #[error("an unattended grant already exists for this device")]
    GrantExists,
    /// Another process holds the store lock.
    #[error("unattended store locked by another process ({0})")]
    Locked(String),
    /// The keystore cannot be read or written right now.
    #[error("keystore locked: {0}")]
    KeystoreLocked(String),
    /// A precondition failed.
    #[error("{0}")]
    Invalid(String),
    /// A remote session is live or reserved at the commit of an access-increasing
    /// change (§B.8.6.2; decision M1-67): the guard's last no-session check, made under
    /// the store lock.
    #[error("a remote session is live or ended less than 60 s ago")]
    RemoteSessionActive,
    /// Core I/O or keystore failure.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// Load failure.
    #[error(transparent)]
    Load(StoreLoadError),
    /// Grant options refused.
    #[error(transparent)]
    Options(#[from] GrantOptionsError),
}

/// Per-grant runtime limiter state (§B.8.5.1 twins and `credit`; never persisted).
/// Public only for the F3 fuzz target.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeFail {
    /// Monotonic twin of `decay_anchor`.
    pub decay_twin: Duration,
    /// Residual seconds carried toward the first runtime consecutive-decay step.
    pub decay_credit: u64,
    /// Monotonic twin of `lifetime_decay_anchor`.
    pub lifetime_twin: Duration,
    /// Residual seconds carried toward the first runtime lifetime-decay step.
    pub lifetime_credit: u64,
    /// Running lock deadline on the monotonic clock.
    pub locked_until: Option<Duration>,
    /// The pending charge is the one that armed `hard_locked`.
    pub armed_hard_lock: bool,
}

pub(crate) struct State {
    pub status: StoreStatus,
    pub store: Option<UnattendedStore>,
    pub generation: u64,
    pub master: Option<MasterKey>,
    pub k_unatt: Option<Zeroizing<[u8; 32]>>,
    pub anchor_owed: bool,
    pub runtime: HashMap<DeviceId, RuntimeFail>,
    pub mode: LoadMode,
    /// Highest wall reading taken under the lock so far: the in-memory half of the
    /// monotone `last_seen` of §B.8.5.3 (persisted into `last_seen_unix` at every write).
    pub wall_hwm: u64,
    /// `GrantExpired` has been logged for every expiry at or before this instant.
    expired_seen: u64,
    last_anomaly_log: Option<Duration>,
    anomaly_pending: u32,
    /// Records produced while the status is `FailedClosed(KeystoreLocked)`, i.e. while
    /// `K_master` provably exists but is unreadable. Appending them untagged would put
    /// untagged lines after the key epoch and past `log_chain_head`, which
    /// `verify_chain` reports as `Broken` forever (§B.8.13). They are held here and
    /// appended *tagged* by the `keystore_locked -> readable` recovery load (§B.8.9).
    pending_log: Vec<SessionRecord>,
    /// Records dropped after `pending_log` hit `MAX_PENDING_LOG`; reported on flush so
    /// the gap is visible in the log rather than silent.
    pending_log_dropped: u32,
}

/// Cap on `State::pending_log`: a locked keychain must not grow memory without bound.
const MAX_PENDING_LOG: usize = 256;

struct Inner {
    store_path: PathBuf,
    trusted_devices_path: PathBuf,
    secrets: Arc<dyn SecretStore>,
    clock: Arc<dyn Clock>,
    log: SessionLog,
    machine_id: Option<Vec<u8>>,
    _lock: std::fs::File,
    state: Mutex<State>,
    /// Test-only fault injection: fail the next write of this class. `Runtime` fails
    /// exactly the log line a `log_event` writes *after* a committed mutation;
    /// `Policy` fails the commit itself (track D S3/S10).
    #[cfg(test)]
    fail_next_write: Mutex<Option<WriteClass>>,
}

/// Single-writer handle to the unattended store; clones share one state.
///
/// Policy writes — grant CRUD, the master switch, pauses, the bootstrap and the wipe —
/// are `pub(crate)` and reachable only through
/// [`MutationGuard`](super::guard::MutationGuard), the single enforcement point of
/// §B.8.6.2 (re-auth, remote-session rule, refusal lines); the public surface is the
/// read API plus the runtime-state writes the host performs on its own
/// ([`Self::record_session_end`], [`Self::housekeeping`], [`Self::verify_log`],
/// [`Self::log_event`], [`Self::retry_load`]) and the limiter's charge / settle.
#[derive(Clone)]
pub struct GrantStore {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for GrantStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.inner.state.lock();
        f.debug_struct("GrantStore")
            .field("path", &self.inner.store_path)
            .field("status", &st.status)
            .field("generation", &st.generation)
            .field("anchor_owed", &st.anchor_owed)
            .finish()
    }
}

fn take_lock(path: &Path) -> Result<std::fs::File, StoreError> {
    let mut opts = fs_err::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let file = opts.open(path).map_err(CoreError::from)?;
    let mut file = file.into_parts().0;
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            let mut holder = String::new();
            let _ = std::io::Read::read_to_string(&mut file, &mut holder);
            let holder = holder.trim().to_owned();
            return Err(StoreError::Locked(if holder.is_empty() {
                "unknown holder".to_owned()
            } else {
                format!("pid {holder}")
            }));
        }
        Err(std::fs::TryLockError::Error(e)) => return Err(CoreError::from(e).into()),
    }
    let _ = file.set_len(0);
    let _ = file.write_all(std::process::id().to_string().as_bytes());
    let _ = file.sync_all();
    Ok(file)
}

impl GrantStore {
    /// Take the store lock and load as the host (`docs/PLAN.md` §B.8.9 load rules,
    /// [`LoadMode::Host`]). Never creates `K_master` or a file: a fresh install stays
    /// [`StoreStatus::AttendedOnly`].
    pub fn open(
        paths: &Paths,
        secrets: Arc<dyn SecretStore>,
        clock: Arc<dyn Clock>,
        log: SessionLog,
    ) -> Result<Self, StoreError> {
        Self::open_with_machine_id(paths, secrets, clock, log, codec::local_machine_id())
    }

    /// The offline CLI's load ([`LoadMode::Offline`], §B.8.6.2 / §B.8.5.1): takes the
    /// store lock, decodes and verifies (anchor, tag, schema, rollback detection) but
    /// settles nothing, decays nothing, re-arms no lock, skips the machine-id check and
    /// writes nothing at load — so a `tornect unattended status` with no host running is
    /// not a *load* in the limiter's accounting. Every mutation the guard performs
    /// offline still follows the identical rules.
    pub fn open_offline(
        paths: &Paths,
        secrets: Arc<dyn SecretStore>,
        clock: Arc<dyn Clock>,
        log: SessionLog,
    ) -> Result<Self, StoreError> {
        Self::open_with_mode(paths, secrets, clock, log, None, LoadMode::Offline)
    }

    /// [`Self::open`] with an explicit machine id (`None` skips the check).
    pub fn open_with_machine_id(
        paths: &Paths,
        secrets: Arc<dyn SecretStore>,
        clock: Arc<dyn Clock>,
        log: SessionLog,
        machine_id: Option<Vec<u8>>,
    ) -> Result<Self, StoreError> {
        Self::open_with_mode(paths, secrets, clock, log, machine_id, LoadMode::Host)
    }

    /// The general constructor: `mode` selects the host or the offline load rules.
    pub fn open_with_mode(
        paths: &Paths,
        secrets: Arc<dyn SecretStore>,
        clock: Arc<dyn Clock>,
        log: SessionLog,
        machine_id: Option<Vec<u8>>,
        mode: LoadMode,
    ) -> Result<Self, StoreError> {
        create_private_dir(&paths.state_dir)?;
        let lock = take_lock(&paths.unattended_lock())?;
        let inner = Inner {
            store_path: paths.unattended_store(),
            trusted_devices_path: paths.trusted_devices_file(),
            secrets,
            clock,
            log,
            machine_id,
            _lock: lock,
            state: Mutex::new(State {
                status: StoreStatus::AttendedOnly,
                store: None,
                generation: 0,
                master: None,
                k_unatt: None,
                anchor_owed: false,
                runtime: HashMap::new(),
                mode,
                wall_hwm: 0,
                expired_seen: 0,
                last_anomaly_log: None,
                anomaly_pending: 0,
                pending_log: Vec::new(),
                pending_log_dropped: 0,
            }),
            #[cfg(test)]
            fail_next_write: Mutex::new(None),
        };
        let this = Self {
            inner: Arc::new(inner),
        };
        {
            let mut st = this.inner.state.lock();
            this.load_locked(&mut st);
        }
        Ok(this)
    }

    /// Current status.
    #[must_use]
    pub fn status(&self) -> StoreStatus {
        self.inner.state.lock().status.clone()
    }

    /// Test-only: make the next write of `class` fail (see `Inner::fail_next_write`).
    #[cfg(test)]
    pub(crate) fn fail_next_write(&self, class: WriteClass) {
        *self.inner.fail_next_write.lock() = Some(class);
    }

    /// Test-only: whether the store lock is held right now, by any thread (never waits).
    #[cfg(test)]
    pub(crate) fn lock_is_held(&self) -> bool {
        self.inner.state.try_lock().is_none()
    }

    /// How this handle loaded the store.
    #[must_use]
    pub fn mode(&self) -> LoadMode {
        self.inner.state.lock().mode
    }

    /// `trusted-devices.toml` of the same state directory (the pairing precondition of
    /// §B.8.6.1 is checked against it by the guard's default `PairedDevices`).
    #[must_use]
    pub fn trusted_devices_path(&self) -> &Path {
        &self.inner.trusted_devices_path
    }

    /// Read the wall clock under the lock and raise the in-memory high-water mark;
    /// returns `(now, high_water_before_this_reading)` — the caller's rollback reference
    /// is `max(last_seen_unix, high_water_before)`.
    pub(crate) fn wall_locked(&self, st: &mut State) -> (u64, u64) {
        let now = self.inner.clock.wall();
        let before = st.wall_hwm;
        st.wall_hwm = before.max(now);
        (now, before)
    }

    /// Whether a store is loaded.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.inner.state.lock().status == StoreStatus::Loaded
    }

    /// The keystore backend holding `K_master`.
    #[must_use]
    pub fn keystore_kind(&self) -> KeystoreKind {
        self.inner.secrets.kind()
    }

    /// The clock every check uses.
    #[must_use]
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.inner.clock
    }

    /// The session log (tagged once a store is loaded).
    #[must_use]
    pub fn log(&self) -> &SessionLog {
        &self.inner.log
    }

    /// The store file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.store_path
    }

    /// Whether an anchor bump is still owed to the keystore (§B.8.9 honest limit).
    #[must_use]
    pub fn anchor_owed(&self) -> bool {
        self.inner.state.lock().anchor_owed
    }

    /// In-file generation of the loaded store.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.inner.state.lock().generation
    }

    /// The `keystore_locked → readable` recovery load (§B.8.5.1, §B.8.9): re-decodes
    /// only when the last load failed on the keystore, never a loaded store.
    pub fn retry_load(&self) -> StoreStatus {
        let mut st = self.inner.state.lock();
        if matches!(
            st.status,
            StoreStatus::FailedClosed(StoreLoadError::KeystoreLocked(_))
        ) {
            self.load_locked(&mut st);
        }
        st.status.clone()
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock()
    }

    // ----------------------------------------------------------------- reading

    /// Run `f` on the loaded store.
    pub fn read<R>(&self, f: impl FnOnce(&UnattendedStore) -> R) -> Option<R> {
        self.inner.state.lock().store.as_ref().map(f)
    }

    /// The grant for `device` (a clone; carries the auth record for the PAKE).
    #[must_use]
    pub fn grant(&self, device: &DeviceId) -> Option<UnattendedGrant> {
        self.read(|s| s.grant(device).cloned()).flatten()
    }

    /// Every grant.
    #[must_use]
    pub fn grants(&self) -> Vec<UnattendedGrant> {
        self.read(|s| s.grants.clone()).unwrap_or_default()
    }

    /// The `opaque-ke` `ServerSetup` bytes.
    #[must_use]
    pub fn server_setup(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.read(|s| s.server_setup.clone())
    }

    /// Constant-time stop-token check (§B.8.7.4); `false` without a store.
    #[must_use]
    pub fn stop_token_matches(&self, presented: &[u8; 32]) -> bool {
        self.read(|s| s.stop_token_matches(presented))
            .unwrap_or(false)
    }

    /// Whether the master switch is on and no pause is active at `now`.
    #[must_use]
    pub fn enabled_at(&self, now: u64) -> bool {
        self.read(|s| s.active_at(now)).unwrap_or(false)
    }

    /// `last_seen_unix` of the loaded store.
    #[must_use]
    pub fn last_seen(&self) -> Option<u64> {
        self.read(|s| s.last_seen_unix)
    }

    /// The rollback reference of §B.8.5.3 for wall-clock checks outside the limiter:
    /// the persisted `last_seen_unix` raised to every reading taken under the lock so
    /// far (`0` without a store). A reading below it is a rollback.
    pub(crate) fn last_seen_mark(&self) -> u64 {
        let st = self.inner.state.lock();
        st.store
            .as_ref()
            .map_or(0, |s| s.last_seen_unix)
            .max(st.wall_hwm)
    }

    /// Remaining running lock of a grant, in whole seconds (0 = none). Without a runtime
    /// entry (an offline load) the persisted picture is read back without being changed.
    #[must_use]
    pub fn lock_remaining_s(&self, device: &DeviceId) -> u32 {
        let mut st = self.inner.state.lock();
        let (now, _) = self.wall_locked(&mut st);
        let mono = self.inner.clock.mono();
        Self::lock_remaining_locked(&st, device, now, mono)
    }

    /// The lock picture both load modes share: the running deadline of a grant the
    /// limiter tracks, else the persisted picture read back unchanged (an offline load
    /// keeps no runtime entries, §B.8.5.1).
    pub(crate) fn lock_remaining_locked(
        st: &State,
        device: &DeviceId,
        now: u64,
        mono: Duration,
    ) -> u32 {
        match st.runtime.get(device) {
            Some(rt) => rt.locked_until.map_or(0, |u| remaining_secs(u, mono)),
            None => st
                .store
                .as_ref()
                .and_then(|s| s.grant(device))
                .map_or(0, |g| persisted_lock_remaining(&g.fail, now)),
        }
    }

    // ----------------------------------------------------------------- loading

    fn read_master(&self) -> Result<Option<MasterKey>, StoreLoadError> {
        match self.inner.secrets.get(MASTER_KEY_ENTRY) {
            Ok(Some(bytes)) => MasterKey::parse(&bytes).map(Some),
            Ok(None) => Ok(None),
            Err(CoreError::KeychainLocked(m)) => Err(StoreLoadError::KeystoreLocked(m)),
            Err(e) => Err(StoreLoadError::KeystoreLocked(e.to_string())),
        }
    }

    fn read_file(&self) -> Result<Option<Vec<u8>>, StoreLoadError> {
        match fs_err::read(&self.inner.store_path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreLoadError::Io(e.to_string())),
        }
    }

    fn try_load(
        &self,
        st: &mut State,
    ) -> Result<Option<(MasterKey, u64, UnattendedStore)>, StoreLoadError> {
        let master = self.read_master()?;
        let file = self.read_file()?;
        let (mut master, bytes) = match (master, file) {
            (None, None) => return Ok(None),
            (None, Some(_)) => return Err(StoreLoadError::MissingKey),
            // An interrupted bootstrap (key written, file never) is still attended-only.
            (Some(m), None) if m.anchor() == 0 => {
                st.master = Some(m);
                return Ok(None);
            }
            (Some(m), None) => return Err(StoreLoadError::AnchorWithoutFile(m.anchor())),
            (Some(m), Some(b)) => (m, b),
        };
        let k_unatt = master.k_unatt();
        let (generation, store) = codec::open(&k_unatt, &bytes)?;
        // An owed bump found in the file is applied first (when writable).
        if store.pending_anchor > master.anchor() {
            master.raise_anchor(store.pending_anchor);
            match self.inner.secrets.put(MASTER_KEY_ENTRY, &master.to_entry()) {
                Ok(()) => st.anchor_owed = false,
                Err(e) => {
                    tracing::warn!(error = %e, "keystore unwritable: anchor bump stays owed");
                    st.anchor_owed = true;
                }
            }
        }
        if generation < master.anchor() {
            return Err(StoreLoadError::OlderThanAnchor {
                generation,
                anchor: master.anchor(),
            });
        }
        Ok(Some((master, generation, store)))
    }

    /// True while `K_master` exists but cannot be read, so no tag can be computed.
    fn log_key_unavailable(st: &State) -> bool {
        matches!(
            st.status,
            StoreStatus::FailedClosed(StoreLoadError::KeystoreLocked(_))
        )
    }

    /// Append `rec`, or buffer it when the keystore is locked (§B.8.13: an untagged
    /// line after the key epoch breaks the chain permanently). `AttendedOnly` still
    /// appends untagged — that is the case the epoch legitimately covers.
    fn append_or_buffer(&self, st: &mut State, rec: &SessionRecord) -> Result<(), StoreError> {
        if Self::log_key_unavailable(st) {
            if st.pending_log.len() < MAX_PENDING_LOG {
                st.pending_log.push(rec.clone());
            } else {
                st.pending_log_dropped = st.pending_log_dropped.saturating_add(1);
            }
            return Ok(());
        }
        self.inner.log.append(rec)?;
        Ok(())
    }

    /// Append everything buffered during the locked window, now that `K_log` is
    /// installed and every line can carry a tag.
    fn flush_pending_log_locked(&self, st: &mut State) {
        if st.pending_log.is_empty() && st.pending_log_dropped == 0 {
            return;
        }
        let dropped = std::mem::take(&mut st.pending_log_dropped);
        for rec in std::mem::take(&mut st.pending_log) {
            if let Err(e) = self.inner.log.append(&rec) {
                tracing::error!(error = %e, "could not flush a buffered log record");
            }
        }
        if dropped > 0 {
            let rec = SessionRecord::at(st.wall_hwm, SessionEvent::StoreLoadFailed).detail(
                format!("{dropped} log records dropped while the keystore was locked"),
            );
            if let Err(e) = self.inner.log.append(&rec) {
                tracing::error!(error = %e, "could not log the buffered-record overflow");
            }
        }
    }

    fn load_locked(&self, st: &mut State) {
        let (now, _) = self.wall_locked(st);
        let mono = self.inner.clock.mono();
        match self.try_load(st) {
            Ok(None) => {
                st.status = StoreStatus::AttendedOnly;
                st.store = None;
                st.generation = 0;
                st.k_unatt = None;
                st.runtime.clear();
            }
            Ok(Some((master, generation, mut store))) => {
                self.inner.log.set_log_key(Some(master.k_log()));
                // The keystore_locked -> readable recovery load (§B.8.9): everything
                // buffered while the key was unreadable is appended tagged, before any
                // record this load produces, preserving log order.
                self.flush_pending_log_locked(st);
                st.k_unatt = Some(master.k_unatt());
                st.master = Some(master);
                st.generation = generation;
                st.runtime.clear();
                // Expiries at or before the last write were logged by the writer that
                // saw them; everything between it and now is this load's to log.
                st.expired_seen = store.last_seen_unix;
                // Rollback: now < last_seen ⇒ locks re-armed in full, decay skipped.
                let rollback = now < store.last_seen_unix;
                if rollback {
                    st.anomaly_pending = st.anomaly_pending.saturating_add(1);
                    tracing::warn!(
                        now,
                        last_seen = store.last_seen_unix,
                        "clock rollback detected at load; schedule/expiry fail closed"
                    );
                }
                if st.mode == LoadMode::Offline {
                    // Decode and verify only: no settlement, no decay, no re-armed lock
                    // (no runtime entries), no machine-id check, nothing written to the
                    // store — the rollback still gets its `ClockAnomaly` line (a tagged
                    // line beyond the head; the next host verifier run advances it).
                    st.store = Some(store);
                    st.status = StoreStatus::Loaded;
                    if rollback {
                        let _ = self.flush_anomalies_locked(st, now, mono);
                    }
                    return;
                }
                // (device, grant, consecutive, re-armed lock) of every charge settled here
                let mut settled: Vec<(DeviceId, GrantId, u32, u32)> = Vec::new();
                for g in &mut store.grants {
                    let (rt, was_pending) =
                        settle_and_decay_at_load(&mut g.fail, now, mono, rollback);
                    if was_pending {
                        settled.push((g.device, g.id, g.fail.consecutive, g.fail.lock_remaining_s));
                    }
                    st.runtime.insert(g.device, rt);
                }
                let settled_pending = !settled.is_empty();
                st.store = Some(store);
                st.status = StoreStatus::Loaded;
                // §B.8.5.1: a `pending` charge found at load is settled as fail, and
                // §B.8.13 keeps `UnattendedAuthFailed` as the per-attempt line — so the
                // abandoned attempt gets its outcome line (before the store write, the
                // same order as a live `settle`) instead of a challenge without one.
                for (device, id, failures, lock) in &settled {
                    let rec = SessionRecord::at(now, SessionEvent::UnattendedAuthFailed)
                        .device(*device)
                        .grant(id)
                        .unattended(true)
                        .failures(*failures)
                        .lock_secs(*lock)
                        .reason("abandoned");
                    if let Err(e) = self.log_locked(st, &rec) {
                        tracing::warn!(error = %e, "could not log the abandoned attempt");
                    }
                }
                // Persist the settlement / decay (runtime write) and the machine-id check
                // (policy write) — best effort at load; a failure keeps the in-memory state.
                let mismatch = self.machine_id_mismatch(st);
                let adopted = !mismatch && self.adopt_machine_id(st);
                if mismatch {
                    if let Some(store) = st.store.as_mut() {
                        let hash = self.inner.machine_id.as_deref().map(codec::machine_id_hash);
                        let mut disabled = 0usize;
                        for g in &mut store.grants {
                            if !matches!(g.state, GrantState::Disabled { .. }) {
                                g.state = GrantState::Disabled {
                                    since: now,
                                    by: crate::session_log::Actor::Restore,
                                };
                                disabled += 1;
                            }
                        }
                        store.machine_id_hash = hash;
                        tracing::warn!(
                            disabled,
                            "machine id changed: every grant disabled (by: restore)"
                        );
                    }
                    let grants: Vec<[u8; 8]> = st
                        .store
                        .as_ref()
                        .map(|s| s.grants.iter().map(|g| g.id).collect())
                        .unwrap_or_default();
                    for id in grants {
                        let rec = SessionRecord::at(now, SessionEvent::GrantDisabled)
                            .grant(&id)
                            .by(crate::session_log::Actor::Restore)
                            .detail("machine id changed (moved state dir or reinstall)");
                        let _ = self.log_locked(st, &rec);
                    }
                    if let Err(e) = self.write_locked(st, WriteClass::Policy) {
                        tracing::error!(error = %e, "could not persist the machine-id policy write");
                    }
                } else if (settled_pending || rollback || adopted)
                    && let Err(e) = self.write_locked(st, WriteClass::Runtime)
                {
                    tracing::error!(error = %e, "could not persist the load-time settlement");
                }
                if rollback {
                    let _ = self.flush_anomalies_locked(st, now, mono);
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "unattended store failed to load: unattended access is off");
                if let Ok(Some(m)) = self.read_master() {
                    self.inner.log.set_log_key(Some(m.k_log()));
                }
                let rec =
                    SessionRecord::at(now, SessionEvent::StoreLoadFailed).detail(e.to_string());
                // Set the status first: `append_or_buffer` keys off it, and this record
                // is itself part of the locked window when `e` is `KeystoreLocked`.
                st.status = StoreStatus::FailedClosed(e);
                if let Err(le) = self.append_or_buffer(st, &rec) {
                    tracing::error!(error = %le, "could not log StoreLoadFailed");
                }
                st.store = None;
                st.k_unatt = None;
                st.runtime.clear();
            }
        }
    }

    fn machine_id_mismatch(&self, st: &State) -> bool {
        let Some(id) = self.inner.machine_id.as_deref() else {
            return false;
        };
        let ours = codec::machine_id_hash(id);
        match st.store.as_ref().and_then(|s| s.machine_id_hash) {
            Some(stored) => stored != ours,
            // No recorded id (unavailable when the store was written): nothing to compare.
            None => false,
        }
    }

    /// A store without a recorded machine id adopts this machine's (§B.8.12: the check
    /// is armed from the next load on); returns whether the field changed. Persisted by
    /// the load-time write, or by the next write of either class.
    fn adopt_machine_id(&self, st: &mut State) -> bool {
        let Some(id) = self.inner.machine_id.as_deref() else {
            return false;
        };
        let Some(store) = st.store.as_mut() else {
            return false;
        };
        if store.machine_id_hash.is_some() {
            return false;
        }
        store.machine_id_hash = Some(codec::machine_id_hash(id));
        tracing::info!("unattended store had no machine id recorded: adopted this machine's");
        true
    }

    // ----------------------------------------------------------------- writing

    /// Append `record` (tagged) and move the in-memory chain head to it; the head reaches
    /// disk with the next store write (§B.8.13 ordering: line first, head second).
    pub(crate) fn log_locked(
        &self,
        st: &mut State,
        record: &SessionRecord,
    ) -> Result<(), StoreError> {
        let hash = self.inner.log.append_chained(record)?;
        if let Some(store) = st.store.as_mut() {
            store.log_chain_head = hash;
        }
        Ok(())
    }

    /// Encrypt and atomically replace the store file; raise the anchor for policy writes
    /// (or when a bump is owed). On failure the in-memory generation is unchanged.
    pub(crate) fn write_locked(&self, st: &mut State, class: WriteClass) -> Result<(), StoreError> {
        #[cfg(test)]
        {
            let mut fail = self.inner.fail_next_write.lock();
            if *fail == Some(class) {
                *fail = None;
                return Err(StoreError::Invalid("injected write failure".into()));
            }
        }
        let (now, hwm) = self.wall_locked(st);
        let mono = self.inner.clock.mono();
        let new_generation = st.generation.saturating_add(1);
        let owed = st.anchor_owed;
        let State {
            store,
            runtime,
            k_unatt,
            ..
        } = &mut *st;
        let (Some(store), Some(k_unatt)) = (store.as_mut(), k_unatt.as_ref()) else {
            return Err(StoreError::NotLoaded(StoreStatus::AttendedOnly));
        };
        // Monotone stamps (§B.8.5.3) and the persisted lock picture. Only grants the
        // limiter tracks (a runtime entry) get their lock picture re-stamped: an offline
        // load has no entries, so its writes leave every other grant's `FailState` bytes
        // exactly as the host left them (§B.8.5.1).
        let mut last_seen = store.last_seen_unix.max(now).max(hwm);
        for g in &mut store.grants {
            if let Some(rt) = runtime.get(&g.device) {
                g.fail.lock_remaining_s = rt.locked_until.map_or(0, |u| remaining_secs(u, mono));
                g.fail.flushed_at = g.fail.flushed_at.max(now);
            }
            last_seen = last_seen
                .max(g.fail.decay_anchor)
                .max(g.fail.lifetime_decay_anchor);
        }
        store.last_seen_unix = last_seen;
        if class == WriteClass::Policy {
            store.pending_anchor = new_generation;
        }
        let bytes = codec::seal(k_unatt, new_generation, store)?;
        atomic_replace(&self.inner.store_path, &bytes)?;
        st.generation = new_generation;
        if class == WriteClass::Policy || owed {
            let target = st.store.as_ref().map_or(0, |s| s.pending_anchor);
            let Some(master) = st.master.as_mut() else {
                return Ok(());
            };
            master.raise_anchor(target);
            match self.inner.secrets.put(MASTER_KEY_ENTRY, &master.to_entry()) {
                Ok(()) => st.anchor_owed = false,
                Err(e) => {
                    tracing::warn!(error = %e, "keystore unwritable: anchor bump stays owed");
                    st.anchor_owed = true;
                }
            }
        }
        Ok(())
    }

    /// Apply `f` to the loaded store, log `event` (chain head advanced) and persist with
    /// `class`. Nothing is kept in memory if `f` or the write fails.
    pub(crate) fn mutate<R>(
        &self,
        class: WriteClass,
        event: Option<&SessionRecord>,
        f: impl FnOnce(&mut UnattendedStore, u64) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let mut st = self.inner.state.lock();
        self.mutate_locked(&mut st, class, event, f)
    }

    pub(crate) fn mutate_locked<R>(
        &self,
        st: &mut State,
        class: WriteClass,
        event: Option<&SessionRecord>,
        f: impl FnOnce(&mut UnattendedStore, u64) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        if st.status != StoreStatus::Loaded {
            return Err(StoreError::NotLoaded(st.status.clone()));
        }
        let (now, _) = self.wall_locked(st);
        let Some(before) = st.store.clone() else {
            return Err(StoreError::NotLoaded(st.status.clone()));
        };
        let result = {
            let Some(store) = st.store.as_mut() else {
                return Err(StoreError::NotLoaded(st.status.clone()));
            };
            match f(store, now) {
                Ok(r) => r,
                Err(e) => {
                    st.store = Some(before);
                    return Err(e);
                }
            }
        };
        if let Some(rec) = event
            && let Err(e) = self.log_locked(st, rec)
        {
            st.store = Some(before);
            return Err(e);
        }
        if let Err(e) = self.write_locked(st, class) {
            st.store = Some(before);
            return Err(e);
        }
        Ok(result)
    }

    /// Log an event; with a loaded store the line is tagged and the head persisted
    /// (runtime write), otherwise the line is written untagged. A failed head write
    /// leaves the in-memory head where it was (the tagged line beyond it is accepted by
    /// the verifier, §B.8.13).
    pub fn log_event(&self, record: &SessionRecord) -> Result<(), StoreError> {
        let mut st = self.inner.state.lock();
        if st.status == StoreStatus::Loaded {
            let before = st.store.clone();
            let written = self
                .log_locked(&mut st, record)
                .and_then(|()| self.write_locked(&mut st, WriteClass::Runtime));
            if let Err(e) = written {
                st.store = before;
                return Err(e);
            }
            Ok(())
        } else {
            self.append_or_buffer(&mut st, record)?;
            Ok(())
        }
    }

    /// Create `K_master`, the store (generation 1, `pending_anchor = 1`, machine id
    /// recorded, the log's current tail as the key epoch of §B.8.13) and store the
    /// caller's fresh `ServerSetup` — the first unattended enable (§B.8.9 bootstrap).
    /// A no-op error when a store already exists.
    pub(crate) fn bootstrap(&self, server_setup: Zeroizing<Vec<u8>>) -> Result<(), StoreError> {
        let mut st = self.inner.state.lock();
        match &st.status {
            StoreStatus::AttendedOnly => {}
            other => return Err(StoreError::NotLoaded(other.clone())),
        }
        let (now, _) = self.wall_locked(&mut st);
        // Every line up to here was tagged under an earlier key (or not at all); the
        // verifier checks tags from the next line on.
        let epoch = self.inner.log.tail_hash()?;
        let master = MasterKey::generate()?;
        self.inner
            .secrets
            .put(MASTER_KEY_ENTRY, &master.to_entry())
            .map_err(|e| match e {
                CoreError::KeychainLocked(m) => StoreError::KeystoreLocked(m),
                other => StoreError::Core(other),
            })?;
        self.inner.log.set_log_key(Some(master.k_log()));
        let hash = self.inner.machine_id.as_deref().map(codec::machine_id_hash);
        let mut store = UnattendedStore::bootstrap(server_setup, hash, now);
        store.log_chain_epoch = epoch;
        st.k_unatt = Some(master.k_unatt());
        st.master = Some(master);
        st.generation = 0;
        st.store = Some(store);
        st.runtime.clear();
        st.expired_seen = now;
        st.status = StoreStatus::Loaded;
        if let Err(e) = self.write_locked(&mut st, WriteClass::Policy) {
            st.status = StoreStatus::AttendedOnly;
            st.store = None;
            st.k_unatt = None;
            self.inner.log.set_log_key(None);
            return Err(e);
        }
        Ok(())
    }

    // ----------------------------------------------------------------- grants

    /// Insert a new grant (policy write, `GrantCreated` logged), applying `also` to the
    /// store in the same write (an error from it refuses the insert, nothing kept); the
    /// grant's decay twins start now, so its runtime bookkeeping is exact from the first
    /// charge (§B.8.5.1).
    pub(crate) fn insert_grant(
        &self,
        grant: UnattendedGrant,
        record: &SessionRecord,
        also: impl FnOnce(&mut UnattendedStore) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let device = grant.device;
        let mut st = self.inner.state.lock();
        let now_mono = self.inner.clock.mono();
        self.mutate_locked(&mut st, WriteClass::Policy, Some(record), |s, _| {
            if s.grant(&device).is_some() {
                return Err(StoreError::GrantExists);
            }
            also(s)?;
            s.grants.push(grant);
            Ok(())
        })?;
        st.runtime.insert(
            device,
            RuntimeFail {
                decay_twin: now_mono,
                lifetime_twin: now_mono,
                ..RuntimeFail::default()
            },
        );
        Ok(())
    }

    /// Modify one grant (policy write).
    pub(crate) fn update_grant<R>(
        &self,
        device: &DeviceId,
        record: &SessionRecord,
        f: impl FnOnce(&mut UnattendedGrant, u64) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        self.mutate(WriteClass::Policy, Some(record), |s, now| {
            let g = s.grant_mut(device).ok_or(StoreError::NoGrant)?;
            f(g, now)
        })
    }

    /// Remove a grant and add its tombstone (policy write).
    pub(crate) fn remove_grant(
        &self,
        device: &DeviceId,
        record: &SessionRecord,
    ) -> Result<UnattendedGrant, StoreError> {
        let mut st = self.inner.state.lock();
        let removed = self.mutate_locked(&mut st, WriteClass::Policy, Some(record), |s, now| {
            let idx = s
                .grants
                .iter()
                .position(|g| &g.device == device)
                .ok_or(StoreError::NoGrant)?;
            let g = s.grants.remove(idx);
            push_tombstone(s, *device, now);
            Ok(g)
        })?;
        st.runtime.remove(device);
        Ok(removed)
    }

    /// Remove every grant with tombstones (policy write).
    pub(crate) fn remove_all_grants(&self, record: &SessionRecord) -> Result<usize, StoreError> {
        let mut st = self.inner.state.lock();
        let n = self.mutate_locked(&mut st, WriteClass::Policy, Some(record), |s, now| {
            let devices: Vec<DeviceId> = s.grants.iter().map(|g| g.device).collect();
            for d in &devices {
                push_tombstone(s, *d, now);
            }
            s.grants.clear();
            Ok(devices.len())
        })?;
        st.runtime.clear();
        Ok(n)
    }

    /// Reset a grant's `FailState` (a local *Unlock* or a remote admin `unlock(pk)`):
    /// counters 0, locks cleared, `hard_locked` cleared, anchors `:= max(stored, now)`.
    pub(crate) fn reset_fail_locked(
        &self,
        st: &mut State,
        device: &DeviceId,
    ) -> Result<(), StoreError> {
        let (now, _) = self.wall_locked(st);
        let mono = self.inner.clock.mono();
        let store = st
            .store
            .as_mut()
            .ok_or(StoreError::NotLoaded(StoreStatus::AttendedOnly))?;
        let g = store.grant_mut(device).ok_or(StoreError::NoGrant)?;
        g.fail = FailState {
            consecutive: 0,
            since_unlock: 0,
            pending: false,
            last_fail_at: g.fail.last_fail_at,
            lock_remaining_s: 0,
            flushed_at: g.fail.flushed_at.max(now),
            hard_locked: false,
            decay_anchor: g.fail.decay_anchor.max(now),
            lifetime_decay_anchor: g.fail.lifetime_decay_anchor.max(now),
        };
        st.runtime.insert(
            *device,
            RuntimeFail {
                decay_twin: mono,
                lifetime_twin: mono,
                ..RuntimeFail::default()
            },
        );
        Ok(())
    }

    /// Record how a session ended on the grant's `last_used` (runtime write).
    pub fn record_session_end(
        &self,
        device: &DeviceId,
        transport: crate::session_log::TransportKind,
        duration_secs: u32,
    ) -> Result<(), StoreError> {
        self.mutate(WriteClass::Runtime, None, |s, now| {
            let g = s.grant_mut(device).ok_or(StoreError::NoGrant)?;
            let at = g.last_used.map_or(now, |l| l.at);
            g.last_used = Some(super::grant::LastUsed {
                at,
                transport,
                duration_secs,
            });
            Ok(())
        })
    }

    /// Housekeeping (host only; a no-op offline): log `GrantExpired` once for every grant
    /// whose expiry passed since the last housekeeping or, after a restart, since the
    /// last write before it (an expiry during downtime is logged by the next run); prune
    /// auth records 30 d after expiry (`GrantPruned`, policy write).
    pub fn housekeeping(&self) -> Result<(), StoreError> {
        let mut st = self.inner.state.lock();
        if st.status != StoreStatus::Loaded || st.mode == LoadMode::Offline {
            return Ok(());
        }
        let (now, _) = self.wall_locked(&mut st);
        let seen = st.expired_seen;
        let (expired, to_prune): (Vec<[u8; 8]>, Vec<[u8; 8]>) = {
            let Some(store) = st.store.as_ref() else {
                return Ok(());
            };
            let expired = store
                .grants
                .iter()
                .filter(|g| g.expires_at.is_some_and(|e| e > seen && e <= now))
                .map(|g| g.id)
                .collect();
            let prune = store
                .grants
                .iter()
                .filter(|g| {
                    g.auth != AuthRecord::Pruned
                        && g.expires_at
                            .is_some_and(|e| now >= e.saturating_add(PRUNE_AFTER_EXPIRY_S))
                })
                .map(|g| g.id)
                .collect();
            (expired, prune)
        };
        for id in &expired {
            let rec = SessionRecord::at(now, SessionEvent::GrantExpired).grant(id);
            self.log_locked(&mut st, &rec)?;
        }
        st.expired_seen = st.expired_seen.max(now);
        if !to_prune.is_empty() {
            for id in &to_prune {
                let rec = SessionRecord::at(now, SessionEvent::GrantPruned).grant(id);
                self.log_locked(&mut st, &rec)?;
            }
            if let Some(store) = st.store.as_mut() {
                for g in &mut store.grants {
                    if to_prune.contains(&g.id) {
                        g.auth = AuthRecord::Pruned;
                    }
                }
            }
            self.write_locked(&mut st, WriteClass::Policy)
        } else if !expired.is_empty() {
            self.write_locked(&mut st, WriteClass::Runtime)
        } else {
            Ok(())
        }
    }

    /// The `Status` payload (§B.8.7.4) at the current clock.
    #[must_use]
    pub fn status_report(
        &self,
        readiness: super::readiness::ReadinessSnapshot,
    ) -> super::ipc::StatusReport {
        let mut st = self.inner.state.lock();
        let (now, _) = self.wall_locked(&mut st);
        let mono = self.inner.clock.mono();
        let (enabled, paused_until, grants) = match st.store.as_ref() {
            Some(s) => (
                s.enabled,
                s.paused_until,
                s.grants
                    .iter()
                    .map(|g| {
                        let lock = Self::lock_remaining_locked(&st, &g.device, now, mono);
                        super::ipc::GrantSummary::from_grant(g, now, lock)
                    })
                    .collect(),
            ),
            None => (false, None, Vec::new()),
        };
        super::ipc::StatusReport {
            enabled,
            paused_until,
            grants,
            readiness,
            keystore_kind: self.inner.secrets.kind().wire(),
        }
    }

    /// *Rotate ID* (§B.8.9): wipe everything unattended — the store file, `K_master`
    /// (with its anchor) and the in-memory state — and return to attended-only. The
    /// caller (`MutationGuard::rotate_id`) logs `HostIdRotated`; grants, `ServerSetup`,
    /// tombstones and the stop token are gone with the file. Tagged log lines written
    /// before the wipe can no longer be verified (their key is gone): the chain restarts
    /// untagged and the next bootstrap records the tail as its key epoch, so the
    /// verifier keeps checking their `prev` links only (§B.8.13). A crash between the
    /// two deletions leaves a failed-closed store (`AnchorWithoutFile`) that
    /// [`Self::reset_failed_closed`] — behind the guard's re-auth — clears.
    pub(crate) fn wipe_all(&self) -> Result<(), StoreError> {
        let mut st = self.inner.state.lock();
        self.wipe_locked(&mut st)
    }

    /// The §B.8.12 "unattended store was replaced — re-enable to continue" recovery:
    /// only from [`StoreStatus::FailedClosed`], delete the stale file and the keystore
    /// entry (anchor included) and return to attended-only, so that the next `master_on`
    /// bootstraps a fresh store and grants are recreated locally. Access-increasing —
    /// callers go through `MutationGuard::reset_store` (re-auth, no remote session).
    pub(crate) fn reset_failed_closed(&self) -> Result<StoreLoadError, StoreError> {
        let mut st = self.inner.state.lock();
        let StoreStatus::FailedClosed(err) = st.status.clone() else {
            return Err(StoreError::Invalid(format!(
                "store is not failed closed ({:?}); nothing to reset",
                st.status
            )));
        };
        self.wipe_locked(&mut st)?;
        Ok(err)
    }

    fn wipe_locked(&self, st: &mut State) -> Result<(), StoreError> {
        match fs_err::remove_file(&self.inner.store_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(CoreError::from(e).into()),
        }
        self.inner.secrets.delete(MASTER_KEY_ENTRY)?;
        self.inner.log.set_log_key(None);
        st.status = StoreStatus::AttendedOnly;
        st.store = None;
        st.generation = 0;
        st.master = None;
        st.k_unatt = None;
        st.anchor_owed = false;
        st.runtime.clear();
        Ok(())
    }

    // ----------------------------------------------------------------- log chain

    /// The §B.8.13 startup verifier: walks the chain against the stored head and the
    /// store's key epoch (lines tagged under a wiped key are prev-linked only); validly
    /// tagged lines beyond the head are accepted and the head advanced (runtime write).
    pub fn verify_log(&self) -> Result<ChainReport, StoreError> {
        let mut st = self.inner.state.lock();
        let (head, epoch) = st
            .store
            .as_ref()
            .map_or((None, None), |s| (s.chain_head(), s.log_chain_epoch));
        let report = self.inner.log.verify_chain(head.as_ref(), epoch.as_ref())?;
        if st.status == StoreStatus::Loaded
            && let Some(last) = report.last_hash
            && matches!(report.status, ChainStatus::Valid | ChainStatus::MissingHead)
            && head != Some(last)
        {
            let before = st.store.clone();
            if let Some(store) = st.store.as_mut() {
                store.log_chain_head = last;
            }
            if let Err(e) = self.write_locked(&mut st, WriteClass::Runtime) {
                st.store = before;
                return Err(e);
            }
        }
        Ok(report)
    }

    // ----------------------------------------------------------------- clock anomalies

    /// Note a runtime rollback (`now < last_seen`) for rate-aggregated logging.
    pub(crate) fn note_anomaly_locked(&self, st: &mut State, now: u64, mono: Duration) {
        st.anomaly_pending = st.anomaly_pending.saturating_add(1);
        let _ = self.flush_anomalies_locked(st, now, mono);
    }

    fn flush_anomalies_locked(
        &self,
        st: &mut State,
        now: u64,
        mono: Duration,
    ) -> Result<(), StoreError> {
        if st.anomaly_pending == 0 {
            return Ok(());
        }
        if st
            .last_anomaly_log
            .is_some_and(|t| mono.saturating_sub(t) < ANOMALY_LOG_INTERVAL)
        {
            return Ok(());
        }
        let count = st.anomaly_pending;
        st.anomaly_pending = 0;
        st.last_anomaly_log = Some(mono);
        let last_seen = st
            .store
            .as_ref()
            .map_or(0, |s| s.last_seen_unix)
            .max(st.wall_hwm);
        let rec = SessionRecord::at(now, SessionEvent::ClockAnomaly)
            .count(count)
            .detail(format!("wall clock {now} is before last_seen {last_seen}"));
        if st.status == StoreStatus::Loaded && st.mode == LoadMode::Host {
            let before = st.store.clone();
            let written = self
                .log_locked(st, &rec)
                .and_then(|()| self.write_locked(st, WriteClass::Runtime));
            if let Err(e) = written {
                st.store = before;
                return Err(e);
            }
            Ok(())
        } else {
            self.append_or_buffer(st, &rec)?;
            Ok(())
        }
    }
}

/// Append a tombstone, keeping the list bounded (§B.8.9).
pub(crate) fn push_tombstone(s: &mut UnattendedStore, device: DeviceId, now: u64) {
    s.tombstones.push((device, now));
    if s.tombstones.len() > MAX_TOMBSTONES {
        let excess = s.tombstones.len() - MAX_TOMBSTONES;
        s.tombstones.drain(..excess);
    }
}

pub(crate) fn remaining_secs(until: Duration, now: Duration) -> u32 {
    let rem = until.saturating_sub(now);
    let secs = rem.as_secs() + u64::from(rem.subsec_nanos() > 0);
    u32::try_from(secs).unwrap_or(u32::MAX)
}

/// The lock a persisted `FailState` still holds at wall time `now`, read without
/// changing anything (`lock_remaining_s − max(0, now − flushed_at)`; in full when the
/// clock is behind `flushed_at`).
pub(crate) fn persisted_lock_remaining(f: &FailState, now: u64) -> u32 {
    if f.lock_remaining_s == 0 {
        return 0;
    }
    let elapsed = now.saturating_sub(f.flushed_at);
    u32::try_from(u64::from(f.lock_remaining_s).saturating_sub(elapsed)).unwrap_or(u32::MAX)
}

/// Load-time bookkeeping of one `FailState` (§B.8.5.1): the `pending` charge is
/// settled as fail first (anchors `:= max(stored, now)`), then decay is applied on
/// the wall clock (`consecutive` by full steps, `since_unlock` by `min(steps, 1)` while
/// its anchor advances by the full steps) — skipped entirely on a rollback — and the
/// persisted lock is re-armed as `max(0, lock_remaining_s − max(0, now − flushed_at))`
/// (in full on a rollback). Returns the runtime twins and whether a charge was settled.
/// Public only for the F3 fuzz target.
#[doc(hidden)]
pub fn settle_and_decay_at_load(
    f: &mut FailState,
    now: u64,
    mono: Duration,
    rollback: bool,
) -> (RuntimeFail, bool) {
    let settled = f.pending;
    if f.pending {
        f.pending = false;
        // clamped like every other `:= now` write (§B.8.5.3): a rollback load must not
        // move the "last failure" shown to the owner backwards
        f.last_fail_at = Some(f.last_fail_at.unwrap_or(0).max(now));
        f.decay_anchor = f.decay_anchor.max(now);
        f.lifetime_decay_anchor = f.lifetime_decay_anchor.max(now);
    }
    let mut rt = RuntimeFail {
        decay_twin: mono,
        lifetime_twin: mono,
        ..RuntimeFail::default()
    };
    if !rollback {
        if now >= f.decay_anchor {
            let steps = (now - f.decay_anchor) / DECAY_PERIOD_S;
            f.consecutive = f
                .consecutive
                .saturating_sub(u32::try_from(steps).unwrap_or(u32::MAX));
            f.decay_anchor = f
                .decay_anchor
                .saturating_add(steps.saturating_mul(DECAY_PERIOD_S));
            rt.decay_credit = now.saturating_sub(f.decay_anchor);
        }
        if now >= f.lifetime_decay_anchor {
            let steps = (now - f.lifetime_decay_anchor) / LIFETIME_DECAY_PERIOD_S;
            f.since_unlock = f.since_unlock.saturating_sub(u32::from(steps.min(1) == 1));
            f.lifetime_decay_anchor = f
                .lifetime_decay_anchor
                .saturating_add(steps.saturating_mul(LIFETIME_DECAY_PERIOD_S));
            rt.lifetime_credit = now.saturating_sub(f.lifetime_decay_anchor);
        }
    }
    if f.lock_remaining_s > 0 {
        let elapsed = if rollback {
            0
        } else {
            now.saturating_sub(f.flushed_at)
        };
        let remaining = u64::from(f.lock_remaining_s).saturating_sub(elapsed);
        rt.locked_until = (remaining > 0).then(|| super::limiter::lock_deadline(mono, remaining));
        f.lock_remaining_s = u32::try_from(remaining).unwrap_or(u32::MAX);
    }
    (rt, settled)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    let tmp = path.with_extension("bin.tmp");
    write_private_file(&tmp, bytes)?;
    fs_err::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent()
        && let Ok(d) = std::fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// F3 companion: the load-time settlement / decay is total over the whole input
        /// space (any persisted `FailState`, any wall / monotonic reading, rollback or
        /// not) and keeps every persisted clock field monotone.
        #[test]
        fn settle_and_decay_at_load_is_total_and_monotone(
            consecutive in any::<u32>(), since_unlock in any::<u32>(), pending in any::<bool>(),
            lock_remaining_s in any::<u32>(), flushed_at in any::<u64>(), hard_locked in any::<bool>(),
            decay_anchor in any::<u64>(), lifetime_decay_anchor in any::<u64>(),
            last_fail_at in proptest::option::of(any::<u64>()),
            now in any::<u64>(), mono_secs in any::<u64>(), rollback in any::<bool>(),
        ) {
            let mut f = FailState {
                consecutive, since_unlock, pending, last_fail_at, lock_remaining_s,
                flushed_at, hard_locked, decay_anchor, lifetime_decay_anchor,
            };
            let before = f;
            let (rt, settled) = settle_and_decay_at_load(&mut f, now, Duration::from_secs(mono_secs), rollback);
            prop_assert_eq!(settled, before.pending);
            prop_assert!(!f.pending);
            prop_assert!(f.decay_anchor >= before.decay_anchor);
            prop_assert!(f.lifetime_decay_anchor >= before.lifetime_decay_anchor);
            prop_assert!(f.last_fail_at >= before.last_fail_at, "last_fail_at is monotone");
            if before.pending {
                prop_assert_eq!(f.last_fail_at, Some(before.last_fail_at.unwrap_or(0).max(now)));
            }
            prop_assert!(f.consecutive <= before.consecutive);
            prop_assert!(f.since_unlock >= before.since_unlock.saturating_sub(1), "at most one lifetime step per load");
            prop_assert!(f.lock_remaining_s <= before.lock_remaining_s);
            prop_assert_eq!(f.hard_locked, before.hard_locked, "decay never clears a hard lock");
            if rollback {
                prop_assert_eq!(f.lock_remaining_s, before.lock_remaining_s, "re-armed in full");
                prop_assert_eq!(f.consecutive, before.consecutive);
            }
            prop_assert_eq!(rt.locked_until.is_some(), f.lock_remaining_s > 0);
            if !rollback {
                prop_assert_eq!(f.lock_remaining_s, persisted_lock_remaining(&before, now),
                    "the read-only picture equals the re-armed lock");
            }
        }
    }
}
