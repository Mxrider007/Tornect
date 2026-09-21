//! Cross-module tests of the unattended store, limiter and guard, named by their
//! `docs/PLAN.md` §B.8.15 matrix ids (U1, U4, U5, U7, A6, A8, A14, A15).

use std::sync::Arc;
use std::time::{Duration, Instant};

use proptest::prelude::*;
use zeroize::Zeroizing;

use crate::id::DeviceId;
use crate::keystore::{FileSecretStore, KeystoreKind, SecretStore};
use crate::paths::Paths;
use crate::session_log::{
    Actor, ChainStatus, SessionEvent, SessionLog, SessionMode, SessionRecord, TransportKind,
};

use super::codec::{self, MASTER_KEY_ENTRY, MasterKey, StoreLoadError};
use super::grant::{
    AuthRecord, FailState, GrantState, LastUsed, Preset, SuspendReason, TransportPolicy,
    UnattendedGrant, UnattendedStore, Window,
};
use super::grant::{LIFETIME_BUDGET, TransportConflict};
use super::guard::{
    AdminEffect, AdminOp, AllowAllPaired, AllowAllReAuth, DenyAllReAuth, GuardError, MutationGuard,
    NoSessionActivity, RandomServerSetupSource, ReAuth, ReAuthError, ScriptedActivity,
    SuspendOutcome, stop_token,
};
use super::ipc::{GrantOptions, codes};
use super::limiter::{
    AttemptLimiter, FailKind, HostTransport, LimiterError, PostF2Reject, Reject, Settle,
    ladder_lock_secs, post_f2,
};
use super::readiness::ReadinessSnapshot;
use super::schedule::FixedOffset;
use super::store::{GrantStore, LoadMode, StoreError, StoreStatus, WriteClass};
use super::{Clock, FakeClock};
use crate::trusted::TrustedDevices;

/// 2026-08-29T00:00:00Z (a Saturday).
const T0: u64 = 1_787_961_600;
const H: u64 = 3600;
const D: u64 = 86_400;
const HOST_PK: [u8; 32] = [0x77; 32];

/// A `SecretStore` whose `put` can be switched off (an unwritable keychain).
struct FlakySecrets {
    inner: FileSecretStore,
    put_fails: parking_lot::Mutex<bool>,
    get_fails: parking_lot::Mutex<bool>,
}

impl SecretStore for FlakySecrets {
    fn get(&self, name: &str) -> crate::error::Result<Option<Zeroizing<Vec<u8>>>> {
        if *self.get_fails.lock() {
            return Err(crate::error::CoreError::KeychainLocked(
                "collection locked".into(),
            ));
        }
        self.inner.get(name)
    }

    fn put(&self, name: &str, secret: &[u8]) -> crate::error::Result<()> {
        if *self.put_fails.lock() {
            return Err(crate::error::CoreError::KeychainLocked(
                "collection locked".into(),
            ));
        }
        self.inner.put(name, secret)
    }

    fn delete(&self, name: &str) -> crate::error::Result<bool> {
        self.inner.delete(name)
    }

    fn kind(&self) -> KeystoreKind {
        KeystoreKind::OsKeychain
    }
}

struct Env {
    _dir: tempfile::TempDir,
    paths: Paths,
    secrets: Arc<FlakySecrets>,
    clock: Arc<FakeClock>,
    machine_id: Option<Vec<u8>>,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(dir.path().join("home"));
        paths.ensure().unwrap();
        let secrets = Arc::new(FlakySecrets {
            inner: FileSecretStore::open(paths.keys_dir()).unwrap(),
            put_fails: parking_lot::Mutex::new(false),
            get_fails: parking_lot::Mutex::new(false),
        });
        Self {
            _dir: dir,
            paths,
            secrets,
            clock: Arc::new(FakeClock::at(T0)),
            machine_id: Some(b"machine-A".to_vec()),
        }
    }

    fn open(&self) -> GrantStore {
        self.try_open().unwrap()
    }

    fn try_open(&self) -> Result<GrantStore, StoreError> {
        GrantStore::open_with_machine_id(
            &self.paths,
            self.secrets.clone(),
            self.clock.clone(),
            SessionLog::new(self.paths.sessions_log()),
            self.machine_id.clone(),
        )
    }

    fn guard(&self, store: &GrantStore) -> MutationGuard {
        MutationGuard::new(
            store.clone(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
        )
        .with_server_setup_source(Arc::new(RandomServerSetupSource))
        .with_paired_devices(Arc::new(AllowAllPaired))
    }

    fn open_offline(&self) -> GrantStore {
        GrantStore::open_offline(
            &self.paths,
            self.secrets.clone(),
            self.clock.clone(),
            SessionLog::new(self.paths.sessions_log()),
        )
        .unwrap()
    }

    fn advance(&self, secs: u64) {
        self.clock.advance(Duration::from_secs(secs));
    }

    fn log_events(&self) -> Vec<SessionRecord> {
        SessionLog::new(self.paths.sessions_log())
            .read_all()
            .unwrap()
    }

    fn has_event(&self, ev: SessionEvent) -> bool {
        self.log_events().iter().any(|r| r.event == ev)
    }

    fn file_bytes(&self) -> Vec<u8> {
        std::fs::read(self.paths.unattended_store()).unwrap()
    }

    fn anchor(&self) -> u64 {
        let entry = self.secrets.inner.get(MASTER_KEY_ENTRY).unwrap().unwrap();
        MasterKey::parse(&entry).unwrap().anchor()
    }
}

fn dev(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 32])
}

fn upload() -> [u8; 192] {
    [0xAB; 192]
}

fn waived() -> GrantOptions {
    GrantOptions {
        waive_attended_precondition: true,
        ..GrantOptions::default()
    }
}

/// Master on + one grant; returns the guard.
fn enable(env: &Env, store: &GrantStore, device: DeviceId, preset: Preset) -> MutationGuard {
    let guard = env.guard(store);
    guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    guard
        .create_grant(Actor::Ui, &device, preset, &waived(), &upload())
        .unwrap();
    guard
}

fn fail_once(env: &Env, lim: &AttemptLimiter, device: &DeviceId) {
    let c = lim.charge(device).unwrap();
    lim.settle(device, Settle::Fail(FailKind::BadKe3)).unwrap();
    env.advance(u64::from(c.lock_secs) + 1);
}

fn fail_n(env: &Env, lim: &AttemptLimiter, device: &DeviceId, n: usize) {
    for _ in 0..n {
        fail_once(env, lim, device);
    }
}

fn fail_of(store: &GrantStore, device: &DeviceId) -> FailState {
    store.grant(device).unwrap().fail
}

fn gate(lim: &AttemptLimiter, device: &DeviceId) -> Result<(), Reject> {
    lim.gate(device, 1, &[1]).map(|_| ())
}

// ------------------------------------------------------------------ U7 / U1

#[test]
fn u7_charge_settle_semantics() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    assert_eq!(gate(&lim, &d), Ok(()));

    let c = lim.charge(&d).unwrap();
    assert_eq!((c.consecutive, c.since_unlock, c.lock_secs), (1, 1, 0));
    let f = fail_of(&store, &d);
    assert!(f.pending);
    assert!(env.has_event(SessionEvent::UnattendedChallengeIssued));
    // success: own charge reverted, zero prior failures ⇒ None
    assert_eq!(lim.settle(&d, Settle::Ok).unwrap(), None);
    let f = fail_of(&store, &d);
    assert_eq!((f.consecutive, f.since_unlock, f.pending), (0, 0, false));
    assert!(store.grant(&d).unwrap().last_used.is_some());
    assert!(env.has_event(SessionEvent::UnattendedAuthSucceeded));

    // two failures keep both counters
    fail_n(&env, &lim, &d, 2);
    let f = fail_of(&store, &d);
    assert_eq!((f.consecutive, f.since_unlock), (2, 2));
    assert!(f.last_fail_at.is_some());
    // the third charge arms the 10 s lock; settle(fail) keeps it
    let c = lim.charge(&d).unwrap();
    assert_eq!((c.consecutive, c.lock_secs), (3, 10));
    lim.settle(&d, Settle::Fail(FailKind::Timeout)).unwrap();
    assert_eq!(gate(&lim, &d), Err(Reject::LockedOut { retry_after_s: 10 }));
    assert!(matches!(lim.charge(&d), Err(LimiterError::Locked(_))));
    env.clock.advance_mono(Duration::from_secs(4));
    assert_eq!(
        gate(&lim, &d),
        Err(Reject::LockedOut { retry_after_s: 10 }),
        "rounded up"
    );
    env.clock.advance_mono(Duration::from_secs(6));
    assert_eq!(gate(&lim, &d), Ok(()));
    // a success after three failures reports them
    lim.charge(&d).unwrap();
    let s = lim.settle(&d, Settle::Ok).unwrap().unwrap();
    assert_eq!(s.since_success, 3);
    assert!(s.last_fail_at.is_some());
    assert_eq!(fail_of(&store, &d).consecutive, 0);
    assert_eq!(
        fail_of(&store, &d).since_unlock,
        3,
        "lifetime counter is never reset by success"
    );
    assert!(env.has_event(SessionEvent::UnattendedAuthFailed));
}

#[test]
fn u7_at_most_one_charge_per_stream() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    assert!(matches!(
        lim.settle(&d, Settle::Ok),
        Err(LimiterError::NotPending)
    ));
    lim.charge(&d).unwrap();
    assert!(matches!(lim.charge(&d), Err(LimiterError::AlreadyPending)));
    lim.settle(&d, Settle::Fail(FailKind::Preempted)).unwrap();
    assert!(matches!(
        lim.settle(&d, Settle::Fail(FailKind::Timeout)),
        Err(LimiterError::NotPending)
    ));
    assert_eq!(fail_of(&store, &d).consecutive, 1);
    assert!(matches!(lim.charge(&dev(9)), Err(LimiterError::NoGrant)));
}

#[test]
fn u1_ladder_timings_per_n() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    for n in 1..=12u32 {
        let c = lim.charge(&d).unwrap();
        assert_eq!(c.consecutive, n);
        assert_eq!(c.lock_secs, ladder_lock_secs(n), "n = {n}");
        lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
        if c.lock_secs > 0 {
            let expected = c.lock_secs.div_ceil(10) * 10;
            assert_eq!(
                gate(&lim, &d),
                Err(Reject::LockedOut {
                    retry_after_s: expected
                })
            );
            env.clock
                .advance_mono(Duration::from_secs(u64::from(c.lock_secs) - 1));
            assert!(matches!(gate(&lim, &d), Err(Reject::LockedOut { .. })));
            env.clock.advance_mono(Duration::from_secs(1));
        }
        assert_eq!(gate(&lim, &d), Ok(()), "n = {n}");
    }
    let f = fail_of(&store, &d);
    assert_eq!(
        (f.consecutive, f.since_unlock, f.hard_locked),
        (12, 12, false)
    );
}

#[test]
fn u1_lifetime_budget_60_successes_no_lock() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    for _ in 0..60 {
        let c = lim.charge(&d).unwrap();
        assert_eq!(c.lock_secs, 0);
        assert_eq!(lim.settle(&d, Settle::Ok).unwrap(), None);
    }
    let f = fail_of(&store, &d);
    assert_eq!(
        (f.consecutive, f.since_unlock, f.hard_locked),
        (0, 0, false)
    );
    assert_eq!(gate(&lim, &d), Ok(()));
}

#[test]
fn u1_abandon_after_charge_and_kill_settles_fail_on_load() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    lim.charge(&d).unwrap();
    assert!(fail_of(&store, &d).pending);
    drop((lim, g, store)); // simulated kill -9: no settle
    env.advance(5);
    let store = env.open();
    let f = fail_of(&store, &d);
    assert!(!f.pending);
    assert_eq!((f.consecutive, f.since_unlock), (1, 1));
    assert_eq!(f.last_fail_at, Some(T0 + 5));
    assert_eq!(f.decay_anchor, T0 + 5);
    assert_eq!(f.lifetime_decay_anchor, T0 + 5);
    // the abandoned attempt gets its per-attempt outcome line (§B.8.13), tagged and
    // accepted by the verifier with the head advanced by the load-time write
    let abandoned: Vec<_> = env
        .log_events()
        .into_iter()
        .filter(|r| r.event == SessionEvent::UnattendedAuthFailed)
        .collect();
    assert_eq!(abandoned.len(), 1, "{abandoned:?}");
    let line = &abandoned[0];
    assert_eq!(line.reason.as_deref(), Some("abandoned"));
    assert_eq!(line.failures, Some(1));
    assert_eq!(line.peer_device, Some(d));
    assert!(line.unattended);
    assert_eq!(line.grant, Some(hex::encode(store.grant(&d).unwrap().id)));
    let report = store.verify_log().unwrap();
    assert_eq!(report.status, ChainStatus::Valid, "{report:?}");
    assert_eq!(
        report.tagged_beyond_head, 0,
        "the load-time write carried the head"
    );
}

#[test]
fn u1_success_on_60th_since_unlock_charge_clears_hard_lock_and_reports_59() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines); // hard_lock_after = 20
    let lim = AttemptLimiter::new(store.clone());
    // 59 settled failures with successes in between (as A4), never 20 consecutive
    while fail_of(&store, &d).since_unlock < LIFETIME_BUDGET - 2 {
        for _ in 0..18 {
            if fail_of(&store, &d).since_unlock >= LIFETIME_BUDGET - 2 {
                break;
            }
            fail_once(&env, &lim, &d);
        }
        lim.charge(&d).unwrap();
        lim.settle(&d, Settle::Ok).unwrap();
    }
    fail_once(&env, &lim, &d);
    let before = fail_of(&store, &d);
    assert_eq!(before.since_unlock, LIFETIME_BUDGET - 1);
    assert!(!before.hard_locked);
    // the 60th charge arms the lifetime hard lock …
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.since_unlock, LIFETIME_BUDGET);
    assert!(c.hard_lock_armed);
    assert!(c.consecutive < 20);
    assert!(fail_of(&store, &d).hard_locked);
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::UnattendedHardLock && r.reason.as_deref() == Some("lifetime")
    }));
    // … and its own success reverts the charge: hard lock cleared, since_unlock back at 59
    let summary = lim.settle(&d, Settle::Ok).unwrap();
    assert_eq!(
        summary.map_or(0, |s| s.since_success),
        before.consecutive,
        "the own charge is excluded from the summary"
    );
    if before.consecutive > 0 {
        assert!(summary.unwrap().last_fail_at.is_some());
    }
    let f = fail_of(&store, &d);
    assert_eq!(
        (f.hard_locked, f.since_unlock, f.consecutive, f.pending),
        (false, LIFETIME_BUDGET - 1, 0, false)
    );
    assert_eq!(gate(&lim, &d), Ok(()));
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::UnattendedAuthSucceeded
            && r.detail
                .as_deref()
                .is_some_and(|s| s.contains("hard lock cleared"))
    }));
    // the next settled failure is the 60th again and re-arms it for good
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.since_unlock, LIFETIME_BUDGET);
    assert!(c.hard_lock_armed);
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
    assert!(fail_of(&store, &d).hard_locked);
    assert_eq!(gate(&lim, &d), Err(Reject::HardLocked));
    assert!(matches!(
        lim.charge(&d),
        Err(LimiterError::Locked(Reject::HardLocked))
    ));
}

#[test]
fn u1_success_on_20th_charge_clears_hard_lock_and_reports_19() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 19);
    assert!(!fail_of(&store, &d).hard_locked);
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.consecutive, 20);
    assert!(c.hard_lock_armed);
    assert!(fail_of(&store, &d).hard_locked);
    assert!(env.has_event(SessionEvent::UnattendedHardLock));
    let s = lim.settle(&d, Settle::Ok).unwrap().unwrap();
    assert_eq!(s.since_success, 19);
    assert!(s.last_fail_at.is_some());
    let f = fail_of(&store, &d);
    assert_eq!(
        (f.consecutive, f.since_unlock, f.hard_locked, f.pending),
        (0, 19, false, false)
    );
    assert_eq!(gate(&lim, &d), Ok(()));
}

#[test]
fn u1_hard_lock_on_20th_failure_stays_until_unlock() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 19);
    let c = lim.charge(&d).unwrap();
    assert!(c.hard_lock_armed);
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
    assert_eq!(gate(&lim, &d), Err(Reject::HardLocked));
    assert!(matches!(
        lim.charge(&d),
        Err(LimiterError::Locked(Reject::HardLocked))
    ));
    // decay never clears it (30 days across a restart)
    drop(lim);
    drop(g);
    drop(store);
    env.advance(30 * D);
    let store = env.open();
    let lim = AttemptLimiter::new(store.clone());
    let f = fail_of(&store, &d);
    assert!(f.hard_locked);
    assert_eq!(f.consecutive, 0, "counters decayed");
    assert_eq!(gate(&lim, &d), Err(Reject::HardLocked));
    // a local unlock clears it
    let g = env.guard(&store);
    g.unlock(Actor::Ui, &d).unwrap();
    let f = fail_of(&store, &d);
    assert_eq!(
        (f.consecutive, f.since_unlock, f.hard_locked),
        (0, 0, false)
    );
    assert_eq!(gate(&lim, &d), Ok(()));
    assert!(env.has_event(SessionEvent::UnattendedUnlock));
}

#[test]
fn u1_hard_lock_after_zero_disables_consecutive_only_and_lifetime_60_hard_locks() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    g.set_options(
        Actor::Ui,
        &d,
        &GrantOptions {
            hard_lock_after: Some(0),
            ..GrantOptions::default()
        },
    )
    .unwrap();
    let lim = AttemptLimiter::new(store.clone());
    // 25 consecutive failures: locks of 60 min each from n ≥ 10, no hard lock
    fail_n(&env, &lim, &d, 25);
    let f = fail_of(&store, &d);
    assert!(!f.hard_locked);
    assert!(
        f.consecutive >= 24,
        "at most one 24 h decay step across 25 hour-long locks"
    );
    // reach the lifetime budget: 60 settled failures since the unlock
    while fail_of(&store, &d).since_unlock < 59 {
        fail_once(&env, &lim, &d);
    }
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.since_unlock, 60);
    assert!(c.hard_lock_armed);
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
    assert!(fail_of(&store, &d).hard_locked);
    assert_eq!(gate(&lim, &d), Err(Reject::HardLocked));
}

#[test]
fn u1_pending_settled_before_decay_two_day_gap() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 2);
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.consecutive, 3);
    drop((lim, g, store));
    env.advance(2 * D);
    let store = env.open();
    let f = fail_of(&store, &d);
    // settlement moved both anchors to now first, so no step applied
    assert_eq!((f.consecutive, f.since_unlock, f.pending), (3, 3, false));
    assert_eq!(f.decay_anchor, T0 + 2 * D + 2);
    assert_eq!(f.lifetime_decay_anchor, T0 + 2 * D + 2);
}

#[test]
fn u1_21d_uptime_decays_since_unlock_by_3_at_runtime_but_a_restart_by_1() {
    // (a) runtime: full steps on both counters
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 3);
    let before = fail_of(&store, &d);
    env.advance(21 * D);
    let c = lim.charge(&d).unwrap();
    assert_eq!(
        c.since_unlock, 1,
        "3 failures − 3 lifetime steps + this charge"
    );
    assert_eq!(c.consecutive, 1);
    let f = fail_of(&store, &d);
    assert_eq!(
        f.lifetime_decay_anchor,
        before.lifetime_decay_anchor + 21 * D
    );
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();

    // (b) across a restart: the lifetime counter takes at most one step per load
    let env = Env::new();
    let store = env.open();
    let g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 3);
    let before = fail_of(&store, &d);
    drop((lim, g, store));
    env.advance(21 * D);
    let store = env.open();
    let f = fail_of(&store, &d);
    assert_eq!(f.since_unlock, 2, "min(steps, 1)");
    assert_eq!(f.consecutive, 0, "full steps");
    assert_eq!(
        f.lifetime_decay_anchor,
        before.lifetime_decay_anchor + 21 * D,
        "anchor advanced by the full steps"
    );
    assert_eq!(f.decay_anchor, before.decay_anchor + 21 * D);
}

#[test]
fn u1_anchors_advance_by_whole_periods_and_credit_carries_the_residual() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 2);
    let before = fail_of(&store, &d);
    // 36 h at runtime: one step, 12 h residual
    env.advance(36 * H);
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.consecutive, 2 - 1 + 1);
    let f = fail_of(&store, &d);
    // the charge then sets decay_anchor := now (clamped monotone); fail_once advanced 1 s
    assert_eq!(f.decay_anchor, before.decay_anchor + 36 * H + 1);
    lim.settle(&d, Settle::Ok).unwrap();
    // across a restart: 36 h ⇒ anchor + 24 h, residual 12 h kept for the next runtime step
    fail_n(&env, &lim, &d, 2);
    let before = fail_of(&store, &d);
    drop((lim, g, store));
    env.advance(36 * H);
    let store = env.open();
    let f = fail_of(&store, &d);
    assert_eq!(f.consecutive, 1);
    assert_eq!(
        f.decay_anchor,
        before.decay_anchor + D,
        "whole periods only"
    );
    // 12 h more at runtime completes the second step
    let lim = AttemptLimiter::new(store.clone());
    env.advance(12 * H);
    let c = lim.charge(&d).unwrap();
    assert_eq!(
        c.consecutive, 1,
        "credit (12 h) + 12 h = one more step before the charge"
    );
    // the step advanced the anchor to before + 48 h, then the charge stamped it := now
    assert_eq!(
        fail_of(&store, &d).decay_anchor,
        before.decay_anchor + 2 * D + 1
    );
}

// ------------------------------------------------------------------ U4

#[test]
fn u4_generation_and_anchor_follow_the_write_classes() {
    let env = Env::new();
    let store = env.open();
    assert_eq!(store.status(), StoreStatus::AttendedOnly);
    assert!(!env.paths.unattended_store().exists());
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    assert_eq!(store.status(), StoreStatus::Loaded);
    // bootstrap (1) → master_on (2) → create_grant (3, the anchor) → PasswordSet log line (4, runtime)
    let anchor_after_create = env.anchor();
    assert_eq!(anchor_after_create, 3, "policy writes raise the anchor");
    assert_eq!(store.generation(), 4);
    let lim = AttemptLimiter::new(store.clone());
    lim.charge(&d).unwrap();
    lim.settle(&d, Settle::Ok).unwrap();
    assert_eq!(store.generation(), 6);
    assert_eq!(
        env.anchor(),
        anchor_after_create,
        "runtime writes never touch the anchor"
    );
    g.revoke(Actor::Ui, &d).unwrap();
    assert_eq!(env.anchor(), store.generation());
    assert!(store.grant(&d).is_none());
    assert!(store.read(|s| s.tombstones.len()).unwrap() == 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(env.paths.unattended_store())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let lmode = std::fs::metadata(env.paths.unattended_lock())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(lmode, 0o600);
    }
}

#[test]
fn u4_store_lock_refuses_a_second_writer() {
    let env = Env::new();
    let store = env.open();
    let err = env.try_open().unwrap_err();
    assert!(
        matches!(err, StoreError::Locked(ref who) if who.contains("pid")),
        "{err}"
    );
    assert_eq!(GuardError::from(err).code(), codes::G_STORE_LOCKED);
    drop(store);
    let _again = env.open();
}

#[test]
fn u4_older_generation_than_anchor_fails_closed() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let snapshot = env.file_bytes();
    g.disable(Actor::Ui, &d).unwrap(); // a policy write
    drop((g, store));
    std::fs::write(env.paths.unattended_store(), &snapshot).unwrap();
    let store = env.open();
    assert!(
        matches!(
            store.status(),
            StoreStatus::FailedClosed(StoreLoadError::OlderThanAnchor { .. })
        ),
        "{:?}",
        store.status()
    );
    assert!(env.has_event(SessionEvent::StoreLoadFailed));
    let lim = AttemptLimiter::new(store.clone());
    assert_eq!(gate(&lim, &d), Err(Reject::NotGranted));
    assert!(matches!(
        env.guard(&store).master_on(Actor::Ui, &HOST_PK),
        Err(GuardError::Precondition(_))
    ));
}

#[test]
fn u4_revoke_then_restore_pre_revoke_file_fails_closed_but_failstate_only_rollback_loads() {
    // revoke → restore the pre-revoke file ⇒ fail closed
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let pre_revoke = env.file_bytes();
    g.revoke(Actor::Ui, &d).unwrap();
    drop((g, store));
    std::fs::write(env.paths.unattended_store(), &pre_revoke).unwrap();
    let store = env.open();
    assert!(matches!(
        store.status(),
        StoreStatus::FailedClosed(StoreLoadError::OlderThanAnchor { .. })
    ));
    assert!(env.has_event(SessionEvent::StoreLoadFailed));
    drop(store);

    // a restored file that differs only in FailState (runtime writes) loads
    let env = Env::new();
    let store = env.open();
    let g = enable(&env, &store, d, Preset::MyMachines);
    let pre_failures = env.file_bytes();
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 3);
    assert_eq!(fail_of(&store, &d).consecutive, 3);
    drop((lim, g, store));
    std::fs::write(env.paths.unattended_store(), &pre_failures).unwrap();
    let store = env.open();
    assert_eq!(store.status(), StoreStatus::Loaded);
    assert_eq!(
        fail_of(&store, &d).consecutive,
        0,
        "runtime-state rollback accepted (bounded by the ladder)"
    );
}

#[test]
fn u4_tampered_file_newer_schema_missing_key_and_anchor_without_file_fail_closed() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines);
    drop(_g);
    drop(store);
    let good = env.file_bytes();

    // tamper one ciphertext byte
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    std::fs::write(env.paths.unattended_store(), &bad).unwrap();
    let store = env.open();
    assert_eq!(
        store.status(),
        StoreStatus::FailedClosed(StoreLoadError::BadTag)
    );
    drop(store);

    // a newer schema sealed under the real key
    let entry = env.secrets.inner.get(MASTER_KEY_ENTRY).unwrap().unwrap();
    let master = MasterKey::parse(&entry).unwrap();
    let (generation, mut plain) = codec::open(&master.k_unatt(), &good).unwrap();
    plain.schema_version += 1;
    let newer = codec::seal(&master.k_unatt(), generation + 1, &plain).unwrap();
    std::fs::write(env.paths.unattended_store(), &newer).unwrap();
    let store = env.open();
    assert!(matches!(
        store.status(),
        StoreStatus::FailedClosed(StoreLoadError::NewerSchema(2))
    ));
    drop(store);

    // missing key
    std::fs::write(env.paths.unattended_store(), &good).unwrap();
    assert!(env.secrets.inner.delete(MASTER_KEY_ENTRY).unwrap());
    let store = env.open();
    assert_eq!(
        store.status(),
        StoreStatus::FailedClosed(StoreLoadError::MissingKey)
    );
    drop(store);

    // anchor without a file
    env.secrets.inner.put(MASTER_KEY_ENTRY, &entry).unwrap();
    std::fs::remove_file(env.paths.unattended_store()).unwrap();
    let store = env.open();
    assert!(matches!(
        store.status(),
        StoreStatus::FailedClosed(StoreLoadError::AnchorWithoutFile(_))
    ));
    drop(store);

    // keystore locked at start ⇒ fail closed; recovery load when it becomes readable
    std::fs::write(env.paths.unattended_store(), &good).unwrap();
    *env.secrets.get_fails.lock() = true;
    let store = env.open();
    assert!(matches!(
        store.status(),
        StoreStatus::FailedClosed(StoreLoadError::KeystoreLocked(_))
    ));
    assert_eq!(
        GuardError::from(StoreError::NotLoaded(store.status())).code(),
        codes::G_KEYSTORE_LOCKED
    );
    *env.secrets.get_fails.lock() = false;
    assert_eq!(store.retry_load(), StoreStatus::Loaded);
    assert!(store.grant(&d).is_some());
}

/// §B.8.13 + §B.8.9: `K_master` provably exists while the keychain is locked, so no line
/// written in that window may be untagged — an untagged line after the key epoch and past
/// `log_chain_head` makes `verify_chain` report `Broken` forever, a standing tamper badge
/// on a host where nothing was tampered with. The lines are buffered and flushed tagged by
/// the `keystore_locked -> readable` recovery load.
#[test]
fn a6_log_chain_stays_valid_across_a_keystore_locked_window_and_its_recovery_load() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    drop((g, store));

    // Autostart with the collection still locked: fail closed, unattended off.
    *env.secrets.get_fails.lock() = true;
    let store = env.open();
    assert!(matches!(
        store.status(),
        StoreStatus::FailedClosed(StoreLoadError::KeystoreLocked(_))
    ));

    // The host keeps running attended-only and keeps logging.
    for i in 0..3u64 {
        let rec = SessionRecord::at(1_800_000_000 + i, SessionEvent::SessionStarted);
        store.log_event(&rec).unwrap();
    }

    // The user unlocks; the 10-min readiness re-run performs the recovery load.
    *env.secrets.get_fails.lock() = false;
    assert_eq!(store.retry_load(), StoreStatus::Loaded);

    // The §B.8.13 startup verifier must still accept the chain.
    let report = store.verify_log().unwrap();
    assert_eq!(
        report.status,
        ChainStatus::Valid,
        "log chain broken by the locked window: {:?}",
        report.status
    );
}

#[test]
fn u4_machine_id_mismatch_disables_every_grant_by_restore() {
    let mut env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    drop((g, store));
    env.machine_id = Some(b"machine-B".to_vec());
    let store = env.open();
    assert_eq!(store.status(), StoreStatus::Loaded);
    let grant = store.grant(&d).unwrap();
    assert!(matches!(
        grant.state,
        GrantState::Disabled {
            by: Actor::Restore,
            ..
        }
    ));
    assert_eq!(
        store.read(|s| s.machine_id_hash).unwrap(),
        Some(codec::machine_id_hash(b"machine-B"))
    );
    let lim = AttemptLimiter::new(store.clone());
    assert_eq!(gate(&lim, &d), Err(Reject::NotGranted));
    assert!(
        env.log_events()
            .iter()
            .any(|r| r.event == SessionEvent::GrantDisabled && r.by == Some(Actor::Restore))
    );
    // enable needs re-auth and returns the grant to Active
    env.guard(&store).enable(Actor::Ui, &d).unwrap();
    assert_eq!(gate(&lim, &d), Ok(()));
    drop(lim);
    drop(store);
    // an unavailable id skips the check
    env.machine_id = None;
    let store = env.open();
    assert_eq!(store.grant(&d).unwrap().state, GrantState::Active);
}

#[test]
fn u4_owed_anchor_bump_is_applied_at_the_next_load() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let anchor_before = env.anchor();
    *env.secrets.put_fails.lock() = true;
    g.disable(Actor::Ui, &d).unwrap();
    assert!(store.anchor_owed());
    assert_eq!(
        env.anchor(),
        anchor_before,
        "keychain unwritable: bump owed"
    );
    let pending = store.read(|s| s.pending_anchor).unwrap();
    assert!(pending > anchor_before);
    drop((g, store));
    *env.secrets.put_fails.lock() = false;
    let store = env.open();
    assert_eq!(store.status(), StoreStatus::Loaded);
    assert!(!store.anchor_owed());
    assert_eq!(env.anchor(), pending, "owed bump applied first at load");
}

#[test]
fn u4_housekeeping_logs_expiry_and_prunes_auth_records() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::HelpingSomeone);
    let lim = AttemptLimiter::new(store.clone());
    env.advance(13 * H);
    assert_eq!(gate(&lim, &d), Ok(()));
    env.advance(7 * D);
    assert_eq!(gate(&lim, &d), Err(Reject::NotGranted), "expired");
    store.housekeeping().unwrap();
    assert!(env.has_event(SessionEvent::GrantExpired));
    assert_ne!(store.grant(&d).unwrap().auth, AuthRecord::Pruned);
    env.advance(30 * D);
    store.housekeeping().unwrap();
    assert_eq!(store.grant(&d).unwrap().auth, AuthRecord::Pruned);
    assert!(env.has_event(SessionEvent::GrantPruned));
    assert!(
        matches!(g.admin(&d, AdminOp::EndSession), Ok(o) if !o.ok),
        "an expired grant cannot act"
    );
}

// ------------------------------------------------------------------ U5

#[test]
fn u5_runtime_wall_jump_forward_decays_nothing_and_shortens_no_lock() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 2);
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.lock_secs, 10);
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
    // a suspend / NTP step: wall +2 days, monotonic untouched
    env.clock.advance_wall(2 * D);
    assert_eq!(
        gate(&lim, &d),
        Err(Reject::LockedOut { retry_after_s: 10 }),
        "lock not shortened"
    );
    env.clock.advance_mono(Duration::from_secs(10));
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.consecutive, 4, "nothing decayed");
    assert_eq!(c.since_unlock, 4);
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
    let f = fail_of(&store, &d);
    assert!(
        f.decay_anchor >= T0 + 2 * D,
        ":= now writes are clamped to max(stored, now)"
    );
    assert!(store.last_seen().unwrap() >= T0 + 2 * D);
}

#[test]
fn u5_runtime_rollback_fails_closed_with_not_yet_active_and_clock_anomaly() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    env.advance(H);
    lim.charge(&d).unwrap();
    lim.settle(&d, Settle::Ok).unwrap();
    let last_seen = store.last_seen().unwrap();
    assert_eq!(last_seen, T0 + H);
    env.clock.set_wall(T0 + H - 600);
    assert_eq!(
        gate(&lim, &d),
        Err(Reject::NotYetActive {
            next_open_in_s: 600
        })
    );
    assert!(env.has_event(SessionEvent::ClockAnomaly));
    assert_eq!(
        lim.post_f2(&d, &FixedOffset::utc(), HostTransport::default()),
        Err(PostF2Reject::NotYetActive {
            next_open_in_s: 600
        })
    );
    // the clock passes last_seen again ⇒ open
    env.clock.set_wall(T0 + H);
    assert_eq!(gate(&lim, &d), Ok(()));
    assert!(
        lim.post_f2(&d, &FixedOffset::utc(), HostTransport::default())
            .is_ok()
    );
    // nothing written during the rollback lowered a persisted field
    assert_eq!(store.last_seen().unwrap(), last_seen);
}

#[test]
fn u5_restart_forward_jump_shortens_only_the_persisted_lock_and_decays_lifetime_at_most_one() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 9);
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.lock_secs, 3600);
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
    assert_eq!(
        gate(&lim, &d),
        Err(Reject::LockedOut {
            retry_after_s: 3600
        })
    );
    drop((lim, g, store));
    env.clock.advance_wall(30 * D);
    let store = env.open();
    let lim = AttemptLimiter::new(store.clone());
    let f = fail_of(&store, &d);
    assert_eq!(f.consecutive, 0, "one step per 24 h of jump, uncapped");
    assert_eq!(f.since_unlock, 9, "≤ 1 lifetime step per load");
    assert_eq!(f.lock_remaining_s, 0);
    assert_eq!(
        gate(&lim, &d),
        Ok(()),
        "persisted lock shortened across the load"
    );
}

#[test]
fn u5_rollback_at_load_rearms_locks_in_full_and_skips_decay() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 4);
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.lock_secs, 60);
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
    let before = fail_of(&store, &d);
    let file_before = env.file_bytes();
    env.advance(40);
    drop((lim, g, store));
    // normal restart: 20 s remain
    let store = env.open();
    let lim = AttemptLimiter::new(store.clone());
    assert_eq!(gate(&lim, &d), Err(Reject::LockedOut { retry_after_s: 20 }));
    drop((lim, store));
    // rollback restart on the same file: the lock is re-armed in full, no decay
    std::fs::write(env.paths.unattended_store(), &file_before).unwrap();
    env.clock.set_wall(T0 - 3 * D);
    let store = env.open();
    let lim = AttemptLimiter::new(store.clone());
    // before active_from the cooling-off answer comes first (table order) …
    assert_eq!(
        gate(&lim, &d),
        Err(Reject::NotYetActive {
            next_open_in_s: u32::try_from(3 * D).unwrap()
        })
    );
    // … after it, the rollback answer: last_seen − now
    env.clock.set_wall(T0 + 10);
    assert_eq!(store.last_seen().unwrap(), T0 + 44);
    assert_eq!(
        gate(&lim, &d),
        Err(Reject::NotYetActive { next_open_in_s: 34 })
    );
    env.clock.set_wall(store.last_seen().unwrap());
    assert_eq!(gate(&lim, &d), Err(Reject::LockedOut { retry_after_s: 60 }));
    let f = fail_of(&store, &d);
    assert_eq!(f.consecutive, before.consecutive);
    assert_eq!(
        f.decay_anchor, before.decay_anchor,
        "anchors never decrease"
    );
    assert!(env.has_event(SessionEvent::ClockAnomaly));
}

// ------------------------------------------------------------------ A6

#[test]
fn a6_kill_between_charge_and_reject_persists_the_counter() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    let before = env.file_bytes();
    let gen_before = store.generation();
    lim.charge(&d).unwrap();
    assert_ne!(
        env.file_bytes(),
        before,
        "the charge is on disk before charge() returns"
    );
    assert_eq!(store.generation(), gen_before + 1);
    drop((lim, g, store)); // kill -9 before the reject / settle
    let store = env.open();
    let f = fail_of(&store, &d);
    assert_eq!((f.consecutive, f.since_unlock, f.pending), (1, 1, false));
}

#[test]
fn a6_tagged_line_beyond_the_head_is_accepted_and_the_head_advanced() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let report = store.verify_log().unwrap();
    assert_eq!(report.status, ChainStatus::Valid, "{report:?}");
    assert_eq!(report.tagged_beyond_head, 0);
    let head_before = store.read(UnattendedStore::chain_head).unwrap().unwrap();
    // a line appended and fsynced, then a kill -9 before the head write
    let hash = store
        .log()
        .append_chained(&SessionRecord::now(SessionEvent::UnattendedChallengeIssued).device(d))
        .unwrap();
    drop((g, store));
    let store = env.open();
    assert_eq!(
        store.read(UnattendedStore::chain_head).unwrap(),
        Some(head_before)
    );
    let report = store.verify_log().unwrap();
    assert_eq!(report.status, ChainStatus::Valid);
    assert_eq!(report.tagged_beyond_head, 1);
    assert_eq!(
        store.read(UnattendedStore::chain_head).unwrap(),
        Some(hash),
        "head advanced"
    );
    // an untagged line appended without K_master is refused
    std::fs::OpenOptions::new()
        .append(true)
        .open(env.paths.sessions_log())
        .unwrap()
        .write_all(
            format!(
                "{{\"ts\":\"x\",\"event\":\"grant_revoked\",\"prev\":\"{}\",\"tag\":null}}\n",
                hex::encode(hash)
            )
            .as_bytes(),
        )
        .unwrap();
    let report = store.verify_log().unwrap();
    assert!(matches!(report.status, ChainStatus::Broken { .. }));
}

#[test]
fn a6_log_verifier_survives_rotate_id_and_a_store_reset_and_still_detects_tampering() {
    // Rotate ID: the old K_log is gone with K_master; the lines it tagged stay
    // prev-linked, the new store records the boundary as its key epoch.
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let guard = enable(&env, &store, d, Preset::MyMachines);
    assert_eq!(store.verify_log().unwrap().status, ChainStatus::Valid);
    let old_lines = env.log_events().len();
    assert_eq!(guard.rotate_id(Actor::Ui).unwrap(), 1);
    assert_eq!(store.status(), StoreStatus::AttendedOnly);
    assert!(!store.log().has_log_key());
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::HostIdRotated
            && r.by == Some(Actor::Ui)
            && r.detail.as_deref().is_some_and(|s| s.contains("1 grant"))
    }));
    let on = guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    assert_eq!(on.stop_code.len(), 16);
    assert!(store.grant(&d).is_none());
    let epoch = store.read(|s| s.log_chain_epoch).unwrap();
    assert!(
        epoch.is_some(),
        "the tail at bootstrap is the epoch boundary"
    );
    let report = store.verify_log().unwrap();
    assert_eq!(report.status, ChainStatus::Valid, "{report:?}");
    assert_eq!(report.previous_epoch_lines, old_lines);
    // still valid after a restart, and after more lines under the new key
    drop((guard, store));
    let store = env.open();
    assert_eq!(store.status(), StoreStatus::Loaded);
    let report = store.verify_log().unwrap();
    assert_eq!(report.status, ChainStatus::Valid, "{report:?}");
    let guard = env.guard(&store);
    guard
        .create_grant(Actor::Ui, &d, Preset::MyMachines, &waived(), &upload())
        .unwrap();
    assert_eq!(store.verify_log().unwrap().status, ChainStatus::Valid);
    // tampering before the boundary breaks a prev link (the boundary line's hash sits
    // inside the first current-epoch line, whose tag covers it)
    let text = std::fs::read_to_string(env.paths.sessions_log()).unwrap();
    let tampered = text.replacen("unattended_enabled", "unattended_paused", 1);
    assert_ne!(text, tampered);
    std::fs::write(env.paths.sessions_log(), tampered).unwrap();
    let report = store.verify_log().unwrap();
    assert!(
        matches!(&report.status, ChainStatus::Broken { line: 2, reason, .. } if reason.contains("prev")),
        "{report:?}"
    );
    std::fs::write(env.paths.sessions_log(), &text).unwrap();
    assert_eq!(store.verify_log().unwrap().status, ChainStatus::Valid);
    drop((guard, store));

    // The store reset of §B.8.12 wipes the key the same way.
    let env = Env::new();
    let store = env.open();
    let g = enable(&env, &store, d, Preset::MyMachines);
    let snapshot = env.file_bytes();
    g.disable(Actor::Ui, &d).unwrap();
    drop((g, store));
    std::fs::write(env.paths.unattended_store(), &snapshot).unwrap();
    let store = env.open();
    assert!(matches!(store.status(), StoreStatus::FailedClosed(_)));
    let guard = env.guard(&store);
    guard.reset_store(Actor::Ui).unwrap();
    guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    let report = store.verify_log().unwrap();
    assert_eq!(report.status, ChainStatus::Valid, "{report:?}");
    assert!(report.previous_epoch_lines > 0);
    drop((guard, store));
    let store = env.open();
    assert_eq!(store.status(), StoreStatus::Loaded);
    let report = store.verify_log().unwrap();
    assert_eq!(report.status, ChainStatus::Valid, "{report:?}");
}

use std::io::Write as _;

// ------------------------------------------------------------------ A8

#[test]
fn a8_guard_refuses_access_increasing_ops_without_reauth() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let allow = enable(&env, &store, d, Preset::MyMachines);
    drop(allow);
    let deny = MutationGuard::new(
        store.clone(),
        Arc::new(DenyAllReAuth),
        Arc::new(NoSessionActivity),
    )
    .with_server_setup_source(Arc::new(RandomServerSetupSource))
    .with_paired_devices(Arc::new(AllowAllPaired));
    let err = deny.master_on(Actor::Cli, &HOST_PK).unwrap_err();
    assert_eq!(err.code(), codes::G_REAUTH_FAILED);
    assert_eq!(
        deny.enable(Actor::Cli, &d).unwrap_err().code(),
        codes::G_REAUTH_FAILED
    );
    assert_eq!(
        deny.unlock(Actor::Cli, &d).unwrap_err().code(),
        codes::G_REAUTH_FAILED
    );
    assert_eq!(
        deny.resume(Actor::Cli, &d).unwrap_err().code(),
        codes::G_REAUTH_FAILED
    );
    assert_eq!(
        deny.reg_start(Actor::Cli, &d).unwrap_err().code(),
        codes::G_REAUTH_FAILED
    );
    assert_eq!(
        deny.set_password(Actor::Cli, &d, &upload())
            .unwrap_err()
            .code(),
        codes::G_REAUTH_FAILED
    );
    assert_eq!(
        deny.authorize(
            Actor::Cli,
            &super::guard::ExternalOp::ServiceInstall { elevated: false }
        )
        .unwrap_err()
        .code(),
        codes::G_REAUTH_FAILED
    );
    assert_eq!(
        deny.authorize(
            Actor::Cli,
            &super::guard::ExternalOp::BackupExport { path: "/x".into() }
        )
        .unwrap_err()
        .code(),
        codes::G_REAUTH_FAILED
    );
    // widening needs re-auth, narrowing does not
    let widen = GrantOptions {
        block_window_s: Some(1),
        ..GrantOptions::default()
    };
    assert_eq!(
        deny.set_options(Actor::Cli, &d, &widen).unwrap_err().code(),
        codes::G_REAUTH_FAILED
    );
    assert_eq!(store.grant(&d).unwrap().block_window_s, 3);
    let narrow = GrantOptions {
        block_window_s: Some(10),
        ..GrantOptions::default()
    };
    deny.set_options(Actor::Cli, &d, &narrow).unwrap();
    assert_eq!(store.grant(&d).unwrap().block_window_s, 10);
    // deny-direction never needs re-auth
    assert_eq!(
        deny.suspend(Actor::Cli, &d).unwrap(),
        SuspendOutcome::Suspended
    );
    deny.disable(Actor::Cli, &d).unwrap();
    deny.pause(Actor::Cli, T0 + 12 * H).unwrap();
    deny.master_off(Actor::Cli).unwrap();
    deny.revoke(Actor::Cli, &d).unwrap();
    let refused: Vec<_> = env
        .log_events()
        .into_iter()
        .filter(|r| r.event == SessionEvent::GrantMutationRefused)
        .collect();
    assert!(refused.len() >= 8, "{}", refused.len());
    assert!(
        refused
            .iter()
            .all(|r| r.code == Some(codes::G_REAUTH_FAILED) && r.by == Some(Actor::Cli))
    );
    assert!(env.has_event(SessionEvent::UnattendedPaused));
    assert!(env.has_event(SessionEvent::UnattendedDisabled));
    assert!(env.has_event(SessionEvent::GrantRevoked));
}

#[test]
fn a8_pause_cannot_be_shortened_or_cleared_without_reauth() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    drop(enable(&env, &store, d, Preset::MyMachines));
    let deny = MutationGuard::new(
        store.clone(),
        Arc::new(DenyAllReAuth),
        Arc::new(NoSessionActivity),
    )
    .with_paired_devices(Arc::new(AllowAllPaired));
    // starting and extending a pause are deny-direction
    deny.pause(Actor::Cli, T0 + 12 * H).unwrap();
    deny.pause(Actor::Cli, T0 + 24 * H).unwrap();
    let paused_until = || store.read(|s| s.paused_until).unwrap();
    assert_eq!(paused_until(), Some(T0 + 24 * H));
    assert!(!store.enabled_at(T0 + 23 * H));
    // shortening or clearing it is access-increasing: refused without re-auth
    for until in [T0 + H, T0, 0] {
        let err = deny.pause(Actor::Cli, until).unwrap_err();
        assert_eq!(err.code(), codes::G_REAUTH_FAILED, "until {until}: {err}");
        assert_eq!(paused_until(), Some(T0 + 24 * H), "unchanged");
    }
    assert!(!store.enabled_at(T0 + 23 * H));
    let refused: Vec<_> = env
        .log_events()
        .into_iter()
        .filter(|r| {
            r.event == SessionEvent::GrantMutationRefused && r.op.as_deref() == Some("pause")
        })
        .collect();
    assert_eq!(refused.len(), 3, "{refused:?}");
    assert!(
        refused
            .iter()
            .all(|r| r.code == Some(codes::G_REAUTH_FAILED) && r.by == Some(Actor::Cli))
    );
    // with re-auth the pause ends early
    let reauth = Arc::new(AllowAllReAuth::default());
    let allow = MutationGuard::new(store.clone(), reauth.clone(), Arc::new(NoSessionActivity))
        .with_paired_devices(Arc::new(AllowAllPaired));
    allow.pause(Actor::Ui, T0 + H).unwrap();
    assert_eq!(paused_until(), Some(T0 + H));
    assert_eq!(reauth.calls(), vec!["pause".to_owned()]);
    assert!(store.enabled_at(T0 + H));
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::UnattendedPaused
            && r.detail.as_deref().is_some_and(|s| s.contains("shortened"))
    }));
    // a pause that would end in the past while none is running is refused
    env.advance(2 * H);
    let err = allow.pause(Actor::Ui, T0 + H).unwrap_err();
    assert_eq!(err.code(), codes::G_PRECONDITION);
    assert_eq!(reauth.calls().len(), 1, "no dialog for a refused request");
    // during a remote session even a re-authenticated caller cannot un-pause
    allow.pause(Actor::Ui, env.clock.wall() + 12 * H).unwrap();
    let activity = Arc::new(ScriptedActivity::default());
    activity.set_live(true);
    let busy = MutationGuard::new(store.clone(), reauth.clone(), activity)
        .with_paired_devices(Arc::new(AllowAllPaired));
    assert_eq!(
        busy.pause(Actor::Ui, 0).unwrap_err().code(),
        codes::G_REMOTE_SESSION_ACTIVE
    );
    assert_eq!(paused_until(), Some(env.clock.wall() + 12 * H));
}

/// A guard without a re-auth backend, as a second local caller (CLI) would hold.
fn deny_guard(store: &GrantStore) -> MutationGuard {
    MutationGuard::new(
        store.clone(),
        Arc::new(DenyAllReAuth),
        Arc::new(NoSessionActivity),
    )
    .with_paired_devices(Arc::new(AllowAllPaired))
}

/// A dialog during which another local caller extends the running pause.
struct ExtendPauseReAuth {
    store: GrantStore,
    until: u64,
}

impl ReAuth for ExtendPauseReAuth {
    fn reauthenticate(&self, _op: &str) -> Result<(), ReAuthError> {
        deny_guard(&self.store)
            .pause(Actor::Cli, self.until)
            .unwrap();
        Ok(())
    }
}

/// A dialog during which another local caller narrows the grant.
struct NarrowDuringDialog {
    store: GrantStore,
    device: DeviceId,
}

impl ReAuth for NarrowDuringDialog {
    fn reauthenticate(&self, _op: &str) -> Result<(), ReAuthError> {
        deny_guard(&self.store)
            .set_options(
                Actor::Cli,
                &self.device,
                &GrantOptions {
                    block_window_s: Some(10),
                    hard_lock_after: Some(10),
                    ..GrantOptions::default()
                },
            )
            .unwrap();
        Ok(())
    }
}

#[test]
fn a8_set_options_and_pause_are_classified_again_under_the_lock_after_the_dialog() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    drop(enable(&env, &store, d, Preset::MyMachines)); // block 3 s, hard_lock_after 20
    let other = deny_guard(&store);
    // a narrowing request never opens a dialog and lands in one critical section
    other
        .set_options(
            Actor::Cli,
            &d,
            &GrantOptions {
                hard_lock_after: Some(15),
                ..GrantOptions::default()
            },
        )
        .unwrap();
    assert_eq!(store.grant(&d).unwrap().hard_lock_after, 15);
    // a widening request: the concurrent narrowing during the dialog is seen by the
    // second classification — the log line names what really widened
    let guard = MutationGuard::new(
        store.clone(),
        Arc::new(NarrowDuringDialog {
            store: store.clone(),
            device: d,
        }),
        Arc::new(NoSessionActivity),
    )
    .with_paired_devices(Arc::new(AllowAllPaired));
    guard
        .set_options(
            Actor::Ui,
            &d,
            &GrantOptions {
                block_window_s: Some(1),
                hard_lock_after: Some(15),
                ..GrantOptions::default()
            },
        )
        .unwrap();
    let g = store.grant(&d).unwrap();
    assert_eq!((g.block_window_s, g.hard_lock_after), (1, 15));
    let changes: Vec<_> = env
        .log_events()
        .into_iter()
        .filter(|r| r.event == SessionEvent::GrantChanged && r.by == Some(Actor::Ui))
        .collect();
    assert_eq!(
        changes.last().and_then(|r| r.detail.clone()).as_deref(),
        Some("widened: block_window_s,hard_lock_after"),
        "classified against the grant as it was at the write, not the pre-dialog probe: {changes:?}"
    );
    // a pause extended while the shortening dialog was up: the re-authenticated
    // shortening still lands (the caller re-authenticated for exactly this)
    other.pause(Actor::Cli, T0 + 12 * H).unwrap();
    let guard = MutationGuard::new(
        store.clone(),
        Arc::new(ExtendPauseReAuth {
            store: store.clone(),
            until: T0 + 48 * H,
        }),
        Arc::new(NoSessionActivity),
    )
    .with_paired_devices(Arc::new(AllowAllPaired));
    guard.pause(Actor::Ui, T0 + H).unwrap();
    assert_eq!(store.read(|s| s.paused_until).unwrap(), Some(T0 + H));
}

#[test]
fn a15_admin_requests_fail_closed_on_a_clock_rollback() {
    let (env, store, guard, admin, target, _) = admin_env();
    let lim = AttemptLimiter::new(store.clone());
    assert_eq!(gate(&lim, &admin), Ok(()), "raises the in-memory mark");
    let mark = env.clock.wall();
    env.clock.set_wall(mark - 60);
    let out = guard.admin(&admin, AdminOp::Unlock(target)).unwrap();
    assert!(!out.ok);
    assert_eq!(out.detail.as_deref(), Some("clock rollback"));
    assert_eq!(out.effect, AdminEffect::None);
    assert!(env.has_event(SessionEvent::ClockAnomaly));
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::AdminRequest
            && r.ok == Some(false)
            && r.detail.as_deref() == Some("clock rollback")
    }));
    // once the clock passes the mark the same request is in scope again
    env.clock.set_wall(mark);
    assert!(guard.admin(&admin, AdminOp::Unlock(target)).unwrap().ok);
}

#[test]
fn u4_interrupted_bootstrap_key_with_anchor_zero_and_no_file_is_attended_only() {
    // decision M1-26 addendum: `K_master` written, the store file never (a crash inside
    // the first enable) — no policy write can have completed at anchor 0, so there was
    // never a grant to protect and the host starts attended-only instead of failed closed
    let env = Env::new();
    let entry = MasterKey::from_parts([7u8; 32], 0).to_entry();
    env.secrets.inner.put(MASTER_KEY_ENTRY, &entry).unwrap();
    let store = env.open();
    assert_eq!(store.status(), StoreStatus::AttendedOnly);
    assert!(!env.has_event(SessionEvent::StoreLoadFailed));
    let guard = env.guard(&store);
    guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    assert_eq!(store.status(), StoreStatus::Loaded);
    assert!(
        env.anchor() >= 1,
        "the bootstrap issued a fresh key and anchor"
    );
    assert!(store.grants().is_empty());
    // the same entry with any higher anchor is the §B.8.9 "anchor without a file"
    drop((guard, store));
    std::fs::remove_file(env.paths.unattended_store()).unwrap();
    let store = env.open();
    assert!(matches!(
        store.status(),
        StoreStatus::FailedClosed(StoreLoadError::AnchorWithoutFile(_))
    ));
}

#[test]
fn u4_offline_handle_sees_the_persisted_lock_and_logs_a_rollback_anomaly() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 3);
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.lock_secs, 30);
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
    let last_write = env.clock.wall();
    drop((lim, g, store));
    env.advance(5);
    // the offline CLI reports the same lock picture as `status_report`
    let offline = env.open_offline();
    let lim = AttemptLimiter::new(offline.clone());
    assert_eq!(offline.lock_remaining_s(&d), 25);
    assert_eq!(gate(&lim, &d), Err(Reject::LockedOut { retry_after_s: 30 }));
    assert!(matches!(lim.charge(&d), Err(LimiterError::Offline)));
    assert!(!env.has_event(SessionEvent::ClockAnomaly));
    drop((lim, offline));
    // a rollback at an offline load is logged like at a host load (nothing written)
    let file_before = env.file_bytes();
    env.clock.set_wall(last_write - 1);
    let offline = env.open_offline();
    assert_eq!(offline.status(), StoreStatus::Loaded);
    assert!(env.has_event(SessionEvent::ClockAnomaly));
    assert_eq!(env.file_bytes(), file_before, "no load-time write offline");
    assert_eq!(
        offline.lock_remaining_s(&d),
        30,
        "the persisted lock is read in full behind a rollback"
    );
}

#[test]
fn a8_attended_precondition_counts_sessions_in_rotated_files() {
    let env = Env::new();
    let store = env.open();
    let guard = env.guard(&store);
    guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    let h = dev(4);
    store
        .log_event(
            &SessionRecord::now(SessionEvent::SessionEnded)
                .peer(h, "Relative")
                .unattended(false),
        )
        .unwrap();
    // grow the live file past the rotation threshold: the next append rotates it
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(env.paths.sessions_log())
            .unwrap();
        f.write_all(&vec![
            b'x';
            usize::try_from(crate::session_log::ROTATE_AT_BYTES)
                .unwrap()
        ])
        .unwrap();
        f.write_all(b"\n").unwrap();
    }
    store
        .log_event(&SessionRecord::now(SessionEvent::PairAccepted).peer(h, "Relative"))
        .unwrap();
    assert!(store.log().rotated_path(1).exists());
    assert!(
        env.log_events()
            .iter()
            .all(|r| r.event != SessionEvent::SessionEnded),
        "the live file no longer holds the attended session"
    );
    guard
        .create_grant(
            Actor::Ui,
            &h,
            Preset::HelpingSomeone,
            &GrantOptions::default(),
            &upload(),
        )
        .unwrap();
    assert!(store.grant(&h).is_some());
}

#[test]
fn a8_guard_refuses_during_and_within_60s_after_a_remote_session() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    drop(enable(&env, &store, d, Preset::MyMachines));
    let reauth = Arc::new(AllowAllReAuth::default());
    let activity = Arc::new(ScriptedActivity::default());
    let guard = MutationGuard::new(store.clone(), reauth.clone(), activity.clone())
        .with_server_setup_source(Arc::new(RandomServerSetupSource))
        .with_paired_devices(Arc::new(AllowAllPaired));
    activity.set_live(true);
    let err = guard.unlock(Actor::Ui, &d).unwrap_err();
    assert_eq!(err.code(), codes::G_REMOTE_SESSION_ACTIVE);
    assert!(
        reauth.calls().is_empty(),
        "no dialog while a session is live"
    );
    activity.set_live(false);
    activity.set_ended_at(Some(Instant::now()));
    assert_eq!(
        guard.unlock(Actor::Ui, &d).unwrap_err().code(),
        codes::G_REMOTE_SESSION_ACTIVE
    );
    assert_eq!(
        guard
            .authorize(
                Actor::Ui,
                &super::guard::ExternalOp::BackupExport { path: "/b".into() }
            )
            .unwrap_err()
            .code(),
        codes::G_REMOTE_SESSION_ACTIVE
    );
    activity.set_ended_at(Some(Instant::now() - Duration::from_secs(61)));
    guard.unlock(Actor::Ui, &d).unwrap();
    assert_eq!(reauth.calls(), vec!["unlock".to_owned()]);
    let refused: Vec<_> = env
        .log_events()
        .into_iter()
        .filter(|r| r.event == SessionEvent::GrantMutationRefused)
        .collect();
    assert!(
        refused
            .iter()
            .all(|r| r.during_remote_session == Some(true))
    );
}

#[test]
fn a8_reg_finish_without_a_live_txn_is_g_no_txn() {
    let env = Env::new();
    let store = env.open();
    let (a, b) = (dev(1), dev(2));
    let reauth = Arc::new(AllowAllReAuth::default());
    let activity = Arc::new(ScriptedActivity::default());
    let guard = MutationGuard::new(store.clone(), reauth.clone(), activity.clone())
        .with_server_setup_source(Arc::new(RandomServerSetupSource))
        .with_paired_devices(Arc::new(AllowAllPaired));
    // no txn at all
    let err = guard
        .reg_finish(
            Actor::Cli,
            &a,
            &[9; 16],
            &upload(),
            Preset::MyMachines,
            &waived(),
        )
        .unwrap_err();
    assert_eq!(err.code(), codes::G_NO_TXN);
    assert!(
        env.log_events()
            .iter()
            .any(|r| r.event == SessionEvent::GrantMutationRefused
                && r.code == Some(codes::G_NO_TXN))
    );
    // RegStart re-auths and bootstraps the store lazily
    assert_eq!(store.status(), StoreStatus::AttendedOnly);
    let start = guard.reg_start(Actor::Cli, &a).unwrap();
    assert_eq!(store.status(), StoreStatus::Loaded);
    assert_eq!(start.server_setup.len(), 128);
    assert_eq!(reauth.calls(), vec!["reg_start".to_owned()]);
    // bound to the device
    assert_eq!(
        guard
            .reg_finish(
                Actor::Cli,
                &b,
                &start.reg_txn,
                &upload(),
                Preset::MyMachines,
                &waived()
            )
            .unwrap_err()
            .code(),
        codes::G_NO_TXN
    );
    // RegFinish re-checks activity: refused, txn consumed
    activity.set_live(true);
    assert_eq!(
        guard
            .reg_finish(
                Actor::Cli,
                &a,
                &start.reg_txn,
                &upload(),
                Preset::MyMachines,
                &waived()
            )
            .unwrap_err()
            .code(),
        codes::G_REMOTE_SESSION_ACTIVE
    );
    activity.set_live(false);
    assert_eq!(
        guard
            .reg_finish(
                Actor::Cli,
                &a,
                &start.reg_txn,
                &upload(),
                Preset::MyMachines,
                &waived()
            )
            .unwrap_err()
            .code(),
        codes::G_NO_TXN
    );
    // a fresh txn works once; the attended precondition is enforced unless waived
    let start = guard.reg_start(Actor::Cli, &a).unwrap();
    let err = guard
        .reg_finish(
            Actor::Cli,
            &a,
            &start.reg_txn,
            &upload(),
            Preset::MyMachines,
            &GrantOptions::default(),
        )
        .unwrap_err();
    assert_eq!(err.code(), codes::G_PRECONDITION);
    let start = guard.reg_start(Actor::Cli, &a).unwrap();
    let outcome = guard
        .reg_finish(
            Actor::Cli,
            &a,
            &start.reg_txn,
            &upload(),
            Preset::MyMachines,
            &waived(),
        )
        .unwrap();
    assert!(matches!(
        outcome,
        super::guard::RegFinishOutcome::Created(_)
    ));
    assert!(env.has_event(SessionEvent::GrantCreated));
    assert!(env.has_event(SessionEvent::PasswordSet));
    // set-password for the existing grant: replaces the record, refuses widening
    let start = guard.reg_start(Actor::Cli, &a).unwrap();
    let err = guard
        .reg_finish(
            Actor::Cli,
            &a,
            &start.reg_txn,
            &[0xCD; 192],
            Preset::MyMachines,
            &GrantOptions {
                block_window_s: Some(0),
                ..GrantOptions::default()
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), codes::G_PRECONDITION);
    let start = guard.reg_start(Actor::Cli, &a).unwrap();
    let outcome = guard
        .reg_finish(
            Actor::Cli,
            &a,
            &start.reg_txn,
            &[0xCD; 192],
            Preset::MyMachines,
            &GrantOptions::default(),
        )
        .unwrap();
    assert!(matches!(
        outcome,
        super::guard::RegFinishOutcome::PasswordSet(_)
    ));
    match store.grant(&a).unwrap().auth {
        AuthRecord::Opaque { record } => assert_eq!(record.as_slice(), &[0xCD; 192]),
        other => panic!("{other:?}"),
    }
    // a headless box waives the precondition by itself; a helper needs it
    let c = dev(3);
    guard
        .create_grant(
            Actor::Ui,
            &c,
            Preset::HeadlessBox,
            &GrantOptions::default(),
            &upload(),
        )
        .unwrap();
    assert!(store.read(|s| s.keep_awake).unwrap());
    let h = dev(4);
    assert_eq!(
        guard
            .create_grant(
                Actor::Ui,
                &h,
                Preset::HelpingSomeone,
                &GrantOptions::default(),
                &upload()
            )
            .unwrap_err()
            .code(),
        codes::G_PRECONDITION
    );
    // a completed attended session satisfies it
    store
        .log_event(
            &SessionRecord::now(SessionEvent::SessionEnded)
                .peer(h, "Relative")
                .unattended(false),
        )
        .unwrap();
    guard
        .create_grant(
            Actor::Ui,
            &h,
            Preset::HelpingSomeone,
            &GrantOptions::default(),
            &upload(),
        )
        .unwrap();
    assert_eq!(store.grant(&h).unwrap().mode, SessionMode::ViewOnly);
}

#[test]
fn a8_master_on_issues_a_stop_code_and_emergency_stop_is_single_use() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let guard = env.guard(&store);
    let on = guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    let dbg = format!("{on:?}");
    let code = on.stop_code;
    let token = stop_token(&HOST_PK, &code);
    assert!(store.stop_token_matches(&token));
    assert!(
        !store.stop_token_matches(&stop_token(&[1; 32], &code)),
        "pk-bound"
    );
    assert!(!dbg.contains(&hex::encode(*code)));
    assert!(dbg.contains("<redacted>"));
    guard
        .create_grant(Actor::Ui, &d, Preset::MyMachines, &waived(), &upload())
        .unwrap();
    assert!(store.enabled_at(T0));
    assert_eq!(guard.emergency_stop().unwrap(), 1);
    assert!(!store.enabled_at(T0));
    assert!(store.grant(&d).is_none());
    assert!(!store.stop_token_matches(&token), "single use");
    assert!(env.has_event(SessionEvent::EmergencyStop));
    let on = guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    assert_ne!(*on.stop_code, *code, "a new card at re-enable");
    assert!(store.stop_token_matches(&stop_token(&HOST_PK, &on.stop_code)));
}

// ------------------------------------------------------------------ A14

#[test]
fn a14_debug_output_redacts_secrets_and_the_disk_never_holds_plaintext() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let guard = env.guard(&store);
    guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    let start = guard.reg_start(Actor::Ui, &d).unwrap();
    let setup_hex = hex::encode(start.server_setup.as_slice());
    assert!(!format!("{start:?}").contains(&setup_hex));
    guard
        .reg_finish(
            Actor::Ui,
            &d,
            &start.reg_txn,
            &upload(),
            Preset::MyMachines,
            &waived(),
        )
        .unwrap();
    let upload_hex = hex::encode(upload());
    let dbg_store = store.read(|s| format!("{s:?}")).unwrap();
    assert!(!dbg_store.contains(&setup_hex));
    assert!(!dbg_store.contains(&upload_hex));
    assert!(!dbg_store.contains("171, 171"));
    let dbg_grant = format!("{:?}", store.grant(&d).unwrap());
    assert!(!dbg_grant.contains("171"));
    assert!(dbg_grant.contains("<192 bytes>"));
    assert!(!format!("{store:?}").contains(&setup_hex));
    assert!(!format!("{guard:?}").contains(&setup_hex));
    // the store file is ciphertext: neither the setup nor the record appears in clear
    let file = env.file_bytes();
    let setup = start.server_setup.as_slice();
    assert!(!file.windows(setup.len()).any(|w| w == setup));
    assert!(!file.windows(192).any(|w| w == upload()));
    let log = std::fs::read_to_string(env.paths.sessions_log()).unwrap();
    assert!(!log.contains(&setup_hex));
    assert!(!log.contains(&upload_hex));
    // the master key entry never appears in the log or the store file
    let entry = env.secrets.inner.get(MASTER_KEY_ENTRY).unwrap().unwrap();
    assert!(!file.windows(32).any(|w| w == &entry[..32]));
    assert!(!log.contains(&hex::encode(&entry[..32])));
    let mk = MasterKey::parse(&entry).unwrap();
    assert!(!format!("{mk:?}").contains(&hex::encode(&entry[..32])));
    // IPC traces: the registration messages never print the txn or the OPAQUE bytes
    let txn_hex = hex::encode(*start.reg_txn);
    let req = super::ipc::IpcRequest {
        id: 1,
        op: super::ipc::IpcOp::RegFinish {
            device: d,
            reg_txn: *start.reg_txn,
            upload: upload(),
            preset: 0,
            options: waived(),
        },
    };
    let dbg_req = format!("{req:?}");
    assert!(!dbg_req.contains(&txn_hex) && !dbg_req.contains(&upload_hex));
    assert!(!dbg_req.contains("171"), "{dbg_req}");
    assert!(dbg_req.contains("reg_txn: <redacted>") && dbg_req.contains("<192 bytes>"));
    let payload = super::ipc::RegStartPayload {
        reg_response: [0x44; 64],
        reg_txn: *start.reg_txn,
    };
    let dbg_payload = format!("{payload:?}");
    assert!(!dbg_payload.contains(&txn_hex) && !dbg_payload.contains("68"));
    assert!(dbg_payload.contains("<redacted>"));
}

// ------------------------------------------------------------------ A15

fn admin_env() -> (Env, GrantStore, MutationGuard, DeviceId, DeviceId, DeviceId) {
    let env = Env::new();
    let store = env.open();
    let (admin, target, helper) = (dev(1), dev(2), dev(3));
    let guard = enable(&env, &store, admin, Preset::MyMachines);
    guard
        .create_grant(Actor::Ui, &target, Preset::MyMachines, &waived(), &upload())
        .unwrap();
    guard
        .create_grant(
            Actor::Ui,
            &helper,
            Preset::HelpingSomeone,
            &waived(),
            &upload(),
        )
        .unwrap();
    // helpers are active 12 h after creation
    env.advance(13 * H);
    (env, store, guard, admin, target, helper)
}

/// Run one in-scope admin command whose only failing write is the per-event log
/// line that follows its committed mutation (ENOSPC right after the store write, a
/// log that just became unwritable).
fn admin_with_a_failing_log_line(
    op_for: impl Fn(DeviceId) -> AdminOp,
) -> (super::guard::AdminOutcome, Env, GrantStore, DeviceId) {
    let (env, store, guard, admin, target, _) = admin_env();
    store.fail_next_write(WriteClass::Runtime);
    let out = guard
        .admin(&admin, op_for(target))
        .expect("a committed admin command must not be reported as failed");
    (out, env, store, target)
}

/// Track D S3/S10: `master_off`, `revoke_all` and `revoke` stay successes — with the
/// effect that ends live sessions — when only the log line written after the commit
/// fails. Before the fix each returned `Err`, which the host answered as
/// `ADMIN_RESULT{ok: false}` with `AdminEffect::None`, leaving live sessions running
/// against a store that had already turned access off.
#[test]
fn a15_a_failed_log_line_after_the_commit_keeps_the_command_and_its_effect() {
    let (out, env, store, _) = admin_with_a_failing_log_line(|_| AdminOp::MasterOff);
    assert!(out.ok);
    assert_eq!(out.effect, AdminEffect::MasterOff);
    assert!(
        !store.enabled_at(env.clock.wall()),
        "the store change stands"
    );

    let (out, _env, store, _) = admin_with_a_failing_log_line(|_| AdminOp::RevokeAll);
    assert!(out.ok);
    assert_eq!(out.effect, AdminEffect::RevokedAll(3));
    assert!(store.grants().is_empty());

    let (out, _env, store, target) = admin_with_a_failing_log_line(AdminOp::Revoke);
    assert!(out.ok);
    assert_eq!(out.effect, AdminEffect::Revoked(target));
    assert!(store.grant(&target).is_none());
}

/// A command that did *not* commit is still an `Err` — nothing changed, so there is
/// no effect to lose — and it leaves an `AdminRequest{ok: false}` line. (The comment
/// in `GuardAdmin` used to say the guard had logged these; it had not.)
#[test]
fn a15_an_admin_command_that_fails_to_commit_is_an_error_and_is_logged() {
    let (env, store, guard, admin, _, _) = admin_env();
    let failed_lines = |env: &Env| {
        env.log_events()
            .into_iter()
            .filter(|r| r.event == SessionEvent::AdminRequest && r.ok == Some(false))
            .count()
    };
    let before = failed_lines(&env);
    store.fail_next_write(WriteClass::Policy);
    assert!(guard.admin(&admin, AdminOp::MasterOff).is_err());
    assert!(store.enabled_at(env.clock.wall()), "nothing committed");
    assert_eq!(failed_lines(&env), before + 1);
}

#[test]
fn a15_out_of_scope_admin_requests_are_refused_without_state_change() {
    let (env, store, guard, admin, target, helper) = admin_env();
    for op in [
        AdminOp::Unlock(target),
        AdminOp::RevokeAll,
        AdminOp::MasterOff,
        AdminOp::Suspend(target),
        AdminOp::Revoke(target),
    ] {
        let out = guard.admin(&helper, op).unwrap();
        assert!(!out.ok, "{op:?}");
        assert_eq!(out.effect, AdminEffect::None);
    }
    assert!(store.grant(&target).is_some());
    assert!(store.enabled_at(env.clock.wall()));
    // a helper may end its own session and revoke itself
    assert!(guard.admin(&helper, AdminOp::EndSession).unwrap().ok);
    let out = guard.admin(&helper, AdminOp::Revoke(helper)).unwrap();
    assert_eq!(out.effect, AdminEffect::Revoked(helper));
    assert!(store.grant(&helper).is_none());
    // a suspended admin cannot act
    assert_eq!(
        guard.suspend(Actor::Ui, &admin).unwrap(),
        SuspendOutcome::Suspended
    );
    assert!(!guard.admin(&admin, AdminOp::Unlock(target)).unwrap().ok);
    let refused = env
        .log_events()
        .into_iter()
        .filter(|r| r.event == SessionEvent::AdminRequest && r.ok == Some(false))
        .count();
    assert_eq!(refused, 6);
}

#[test]
fn a15_remote_unlock_resets_failstate_but_never_clears_a_local_block() {
    let (env, store, guard, admin, target, _) = admin_env();
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &target, 3);
    assert_eq!(guard.block(&target).unwrap(), SuspendOutcome::Suspended);
    assert!(matches!(
        store.grant(&target).unwrap().state,
        GrantState::Suspended {
            reason: SuspendReason::LocalBlock,
            ..
        }
    ));
    assert_eq!(gate(&lim, &target), Err(Reject::Suspended { cause: 1 }));
    let out = guard.admin(&admin, AdminOp::Unlock(target)).unwrap();
    assert!(out.ok);
    assert_eq!(out.effect, AdminEffect::Unlocked(target));
    let g = store.grant(&target).unwrap();
    assert_eq!((g.fail.consecutive, g.fail.since_unlock), (0, 0));
    assert!(
        matches!(
            g.state,
            GrantState::Suspended {
                reason: SuspendReason::LocalBlock,
                ..
            }
        ),
        "still blocked"
    );
    assert_eq!(gate(&lim, &target), Err(Reject::Suspended { cause: 1 }));
    assert!(env.has_event(SessionEvent::UnattendedBlockedByLocalUser));
    // only a local Resume clears it
    guard.resume(Actor::Ui, &target).unwrap();
    assert_eq!(gate(&lim, &target), Ok(()));
    assert!(env.has_event(SessionEvent::UnattendedResumed));
}

#[test]
fn a15_remote_unlock_clears_an_admin_suspension() {
    let (env, store, guard, admin, target, _) = admin_env();
    let lim = AttemptLimiter::new(store.clone());
    let out = guard.admin(&admin, AdminOp::Suspend(target)).unwrap();
    assert_eq!(out.effect, AdminEffect::Suspended(target));
    assert_eq!(gate(&lim, &target), Err(Reject::Suspended { cause: 2 }));
    fail_n(&env, &lim, &admin, 2);
    let out = guard.admin(&admin, AdminOp::Unlock(target)).unwrap();
    assert!(out.ok);
    assert_eq!(store.grant(&target).unwrap().state, GrantState::Active);
    assert_eq!(gate(&lim, &target), Ok(()));
    assert!(
        env.log_events()
            .iter()
            .any(|r| r.event == SessionEvent::UnattendedSuspended
                && r.reason.as_deref() == Some("admin"))
    );
}

#[test]
fn a15_remote_unlock_keeps_a_local_cli_suspension() {
    let (_env, store, guard, admin, target, _) = admin_env();
    let lim = AttemptLimiter::new(store.clone());
    assert_eq!(
        guard.suspend(Actor::Cli, &target).unwrap(),
        SuspendOutcome::Suspended
    );
    assert!(matches!(
        store.grant(&target).unwrap().state,
        GrantState::Suspended {
            reason: SuspendReason::Local { by: Actor::Cli },
            ..
        }
    ));
    let out = guard.admin(&admin, AdminOp::Unlock(target)).unwrap();
    assert!(out.ok);
    assert!(matches!(
        store.grant(&target).unwrap().state,
        GrantState::Suspended {
            reason: SuspendReason::Local { by: Actor::Cli },
            ..
        }
    ));
    assert_eq!(gate(&lim, &target), Err(Reject::Suspended { cause: 1 }));
}

#[test]
fn a15_suspend_then_unlock_against_a_local_block_changes_nothing_but_failstate() {
    let (env, store, guard, admin, target, _) = admin_env();
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &target, 2);
    guard.block(&target).unwrap();
    let out = guard.admin(&admin, AdminOp::Suspend(target)).unwrap();
    assert!(out.ok, "reported ok");
    assert_eq!(out.effect, AdminEffect::None, "state untouched");
    assert!(matches!(
        store.grant(&target).unwrap().state,
        GrantState::Suspended {
            reason: SuspendReason::LocalBlock,
            ..
        }
    ));
    let out = guard.admin(&admin, AdminOp::Unlock(target)).unwrap();
    assert!(out.ok);
    let g = store.grant(&target).unwrap();
    assert_eq!(g.fail.consecutive, 0);
    assert!(matches!(
        g.state,
        GrantState::Suspended {
            reason: SuspendReason::LocalBlock,
            ..
        }
    ));
    // precedence of local reasons: a local Suspend replaces Admin, is a no-op on LocalBlock / Panic
    assert_eq!(
        guard.suspend(Actor::Ui, &target).unwrap(),
        SuspendOutcome::NoOp
    );
    guard.resume(Actor::Ui, &target).unwrap();
    guard.admin(&admin, AdminOp::Suspend(target)).unwrap();
    assert_eq!(
        guard.suspend(Actor::Ui, &target).unwrap(),
        SuspendOutcome::Suspended
    );
    assert!(matches!(
        store.grant(&target).unwrap().state,
        GrantState::Suspended {
            reason: SuspendReason::Local { by: Actor::Ui },
            ..
        }
    ));
    assert_eq!(guard.panic(&target).unwrap(), SuspendOutcome::NoOp);
    guard.resume(Actor::Ui, &target).unwrap();
    assert_eq!(guard.panic(&target).unwrap(), SuspendOutcome::Suspended);
    assert!(matches!(
        store.grant(&target).unwrap().state,
        GrantState::Suspended {
            reason: SuspendReason::Panic,
            ..
        }
    ));
    // disable is allowed from any suspended state, enable returns to Active
    guard.disable(Actor::Ui, &target).unwrap();
    assert_eq!(gate(&lim, &target), Err(Reject::NotGranted));
    guard.enable(Actor::Ui, &target).unwrap();
    assert_eq!(gate(&lim, &target), Ok(()));
    // revoke_all / master_off from the admin grant
    let out = guard.admin(&admin, AdminOp::MasterOff).unwrap();
    assert_eq!(out.effect, AdminEffect::MasterOff);
    assert_eq!(gate(&lim, &target), Err(Reject::NotGranted));
    assert!(
        !guard.admin(&admin, AdminOp::RevokeAll).unwrap().ok,
        "master off: the requester is refused pre-PAKE, and the guard requires an active grant"
    );
}

// ------------------------------------------------------------------ gate order and post-F2

#[test]
fn gate_order_matches_the_table() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let guard = enable(&env, &store, d, Preset::HelpingSomeone);
    let lim = AttemptLimiter::new(store.clone());
    // cooling-off first
    assert_eq!(
        gate(&lim, &d),
        Err(Reject::NotYetActive {
            next_open_in_s: 12 * 3600
        })
    );
    // suite before active_from
    assert_eq!(lim.gate(&d, 2, &[1]), Err(Reject::UnsupportedSuite));
    assert_eq!(lim.gate(&d, 1, &[2]), Err(Reject::UnsupportedSuite));
    env.advance(12 * H);
    assert_eq!(gate(&lim, &d), Ok(()));
    // paused / master off / unknown device ⇒ NOT_GRANTED before anything else
    guard.pause(Actor::Ui, env.clock.wall() + 100).unwrap();
    assert_eq!(gate(&lim, &d), Err(Reject::NotGranted));
    env.advance(100);
    assert_eq!(gate(&lim, &d), Ok(()));
    assert_eq!(gate(&lim, &dev(9)), Err(Reject::NotGranted));
    guard.master_off(Actor::Ui).unwrap();
    assert_eq!(gate(&lim, &d), Err(Reject::NotGranted));
    guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    // suspended before locks
    fail_n(&env, &lim, &d, 2);
    lim.charge(&d).unwrap();
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
    guard.suspend(Actor::Ui, &d).unwrap();
    assert_eq!(gate(&lim, &d), Err(Reject::Suspended { cause: 1 }));
    guard.resume(Actor::Ui, &d).unwrap();
    assert_eq!(gate(&lim, &d), Err(Reject::LockedOut { retry_after_s: 10 }));
}

#[test]
fn post_f2_helpers_compute_schedule_cooldown_and_ends_at() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let guard = enable(&env, &store, d, Preset::HelpingSomeone);
    let utc = FixedOffset::utc();
    let lim = AttemptLimiter::new(store.clone());
    // the master switch and a pause are re-read post-F2 (a deny-direction change that
    // landed during the PAKE window is answered NOT_GRANTED, not only by the session kill)
    guard.pause(Actor::Ui, env.clock.wall() + 100).unwrap();
    assert_eq!(
        lim.post_f2(&d, &utc, HostTransport::default()),
        Err(PostF2Reject::NotGranted)
    );
    env.advance(100);
    assert!(lim.post_f2(&d, &utc, HostTransport::default()).is_ok());
    guard.master_off(Actor::Ui).unwrap();
    assert_eq!(
        lim.post_f2(&d, &utc, HostTransport::default()),
        Err(PostF2Reject::NotGranted)
    );
    guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    env.advance(13 * H - 100); // Saturday 2026-08-29 13:00Z
    let ok = lim.post_f2(&d, &utc, HostTransport::default()).unwrap();
    assert_eq!(
        ok.ends_at,
        Some(env.clock.wall() + 4 * 3600),
        "max_session bounds ends_at"
    );
    // a Sunday-only schedule (bit 6) closes Saturday
    guard
        .set_options(
            Actor::Ui,
            &d,
            &GrantOptions {
                schedule: Some(vec![Window {
                    days: 1 << 6,
                    start_min: 9 * 60,
                    end_min: 17 * 60,
                    tz: "UTC".into(),
                }]),
                ..GrantOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        lim.post_f2(&d, &utc, HostTransport::default()),
        Err(PostF2Reject::OutsideSchedule {
            next_open_in_s: Some(20 * 3600)
        })
    );
    env.advance(20 * H + 60);
    let ok = lim.post_f2(&d, &utc, HostTransport::default()).unwrap();
    // max_session (4 h) ends before the window (17:00)
    assert_eq!(ok.ends_at, Some(env.clock.wall() + 4 * 3600));
    // without a session cap the window end bounds it
    guard
        .set_options(
            Actor::Ui,
            &d,
            &GrantOptions {
                max_session_secs: Some(0),
                ..GrantOptions::default()
            },
        )
        .unwrap();
    let ok = lim.post_f2(&d, &utc, HostTransport::default()).unwrap();
    assert_eq!(ok.ends_at, Some(env.clock.wall() - 60 + 8 * 3600));
    // reconnect cooldown after a full-length session (pure helper on a grant snapshot)
    lim.charge(&d).unwrap();
    lim.settle(&d, Settle::Ok).unwrap();
    store
        .record_session_end(&d, TransportKind::Direct, 4 * 3600)
        .unwrap();
    let now = env.clock.wall();
    let mut g = store.grant(&d).unwrap();
    assert_eq!(
        g.last_used.map(|l| (l.at, l.duration_secs, l.transport)),
        Some((now, 4 * 3600, TransportKind::Direct))
    );
    g.max_session_secs = Some(4 * 3600);
    let cooldown = super::limiter::reconnect_cooldown(&g, now + 4 * 3600 + 100);
    assert_eq!(cooldown, Some(500));
    assert_eq!(
        super::limiter::reconnect_cooldown(&g, now + 4 * 3600 + 600),
        None
    );
    let mut short = g.clone();
    short.last_used = Some(LastUsed {
        at: now,
        transport: TransportKind::Lan,
        duration_secs: 100,
    });
    assert_eq!(
        super::limiter::reconnect_cooldown(&short, now + 200),
        None,
        "only after a full-length session"
    );
    assert_eq!(g.transport_policy(false, false), Ok(TransportPolicy::Any));
    assert_eq!(
        g.transport_policy(true, false),
        Ok(TransportPolicy::TorOnly)
    );
    assert_eq!(
        g.transport_policy(false, true),
        Ok(TransportPolicy::LanOnly)
    );
    assert_eq!(g.transport_policy(true, true), Err(TransportConflict));
}

#[test]
fn status_report_and_wipe_all() {
    let env = Env::new();
    let store = env.open();
    let empty = store.status_report(ReadinessSnapshot::unknown());
    assert!(!empty.enabled && empty.grants.is_empty());
    assert_eq!(
        empty.keystore_kind, 0,
        "FlakySecrets reports an OS keychain"
    );
    let d = dev(1);
    let guard = enable(&env, &store, d, Preset::HelpingSomeone);
    let rep = store.status_report(ReadinessSnapshot::unknown());
    assert!(rep.enabled);
    assert_eq!(rep.grants.len(), 1);
    assert_eq!(rep.grants[0].state, "not_yet_active");
    assert_eq!(rep.grants[0].preset, 2);
    assert_eq!(rep.grants[0].mode, 1);
    env.advance(13 * H);
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 2);
    lim.charge(&d).unwrap();
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
    let rep = store.status_report(ReadinessSnapshot::unknown());
    assert_eq!(rep.grants[0].state, "locked:10");
    assert_eq!(rep.grants[0].failures_since_unlock, 3);
    guard.suspend(Actor::Cli, &d).unwrap();
    let rep = store.status_report(ReadinessSnapshot::unknown());
    assert_eq!(rep.grants[0].state, "suspended:local");
    guard.disable(Actor::Ui, &d).unwrap();
    assert_eq!(
        store.status_report(ReadinessSnapshot::unknown()).grants[0].state,
        "disabled:ui"
    );
    let bytes = super::ipc::encode_payload(&rep).unwrap();
    assert_eq!(
        super::ipc::decode_payload::<super::ipc::StatusReport>(&bytes).unwrap(),
        rep
    );
    // Rotate ID (through the guard, deny-direction) wipes everything and returns to
    // attended-only; the untagged HostIdRotated line closes the key epoch
    let deny = deny_guard(&store);
    assert_eq!(deny.rotate_id(Actor::Cli).unwrap(), 1);
    assert_eq!(store.status(), StoreStatus::AttendedOnly);
    assert!(!env.paths.unattended_store().exists());
    assert!(env.secrets.inner.get(MASTER_KEY_ENTRY).unwrap().is_none());
    assert!(!store.log().has_log_key());
    let lines = store.log().read_lines().unwrap();
    let last = crate::session_log::parse_line_chain(lines.last().unwrap()).unwrap();
    assert!(last.tag.is_none(), "written after the wipe: untagged");
    assert!(lines.last().unwrap().contains("host_id_rotated"));
    assert_eq!(
        store
            .status_report(ReadinessSnapshot::unknown())
            .grants
            .len(),
        0
    );
    assert_eq!(deny.rotate_id(Actor::Cli).unwrap(), 0, "idempotent");
    drop((lim, guard, deny, store));
    let store = env.open();
    assert_eq!(store.status(), StoreStatus::AttendedOnly);
    assert!(store.grant(&d).is_none());
}

// ------------------------------------------------------------------ CBOR round-trips

fn arb_actor() -> impl Strategy<Value = Actor> {
    prop_oneof![
        Just(Actor::Ui),
        Just(Actor::Cli),
        Just(Actor::Import),
        Just(Actor::Restore)
    ]
}

fn arb_state() -> impl Strategy<Value = GrantState> {
    prop_oneof![
        Just(GrantState::Active),
        (
            prop_oneof![
                Just(SuspendReason::LocalBlock),
                Just(SuspendReason::Panic),
                Just(SuspendReason::Admin),
                arb_actor().prop_map(|by| SuspendReason::Local { by })
            ],
            any::<u64>()
        )
            .prop_map(|(reason, since)| GrantState::Suspended { reason, since }),
        (any::<u64>(), arb_actor()).prop_map(|(since, by)| GrantState::Disabled { since, by }),
    ]
}

fn arb_auth() -> impl Strategy<Value = AuthRecord> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..200).prop_map(|v| AuthRecord::Opaque {
            record: Zeroizing::new(v)
        }),
        (
            any::<[u8; 16]>(),
            proptest::collection::vec(any::<u8>(), 0..40)
        )
            .prop_map(|(salt, w)| AuthRecord::Spake2 {
                salt,
                wrapped_w: Zeroizing::new(w)
            }),
        Just(AuthRecord::Pruned),
    ]
}

fn arb_fail() -> impl Strategy<Value = FailState> {
    (
        any::<u32>(),
        any::<u32>(),
        any::<bool>(),
        proptest::option::of(any::<u64>()),
        any::<u32>(),
        any::<u64>(),
        any::<bool>(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(
            |(
                consecutive,
                since_unlock,
                pending,
                last_fail_at,
                lock_remaining_s,
                flushed_at,
                hard_locked,
                decay_anchor,
                lifetime_decay_anchor,
            )| FailState {
                consecutive,
                since_unlock,
                pending,
                last_fail_at,
                lock_remaining_s,
                flushed_at,
                hard_locked,
                decay_anchor,
                lifetime_decay_anchor,
            },
        )
}

fn arb_grant() -> impl Strategy<Value = UnattendedGrant> {
    (
        any::<[u8; 8]>(),
        any::<[u8; 32]>(),
        "[a-zA-Z0-9 ]{1,32}",
        arb_actor(),
        any::<u64>(),
        prop_oneof![
            Just(Preset::MyMachines),
            Just(Preset::HeadlessBox),
            Just(Preset::HelpingSomeone)
        ],
        arb_auth(),
        prop_oneof![Just(SessionMode::Control), Just(SessionMode::ViewOnly)],
        proptest::option::of(proptest::collection::vec(
            (0u8..=0x7f, 0u16..1440, 0u16..=1440, "[A-Za-z/+:0-9]{1,16}").prop_map(
                |(days, s, e, tz)| Window {
                    days,
                    start_min: s,
                    end_min: e,
                    tz,
                },
            ),
            0..4,
        )),
        arb_state(),
        arb_fail(),
        proptest::option::of(
            (any::<u64>(), any::<u32>()).prop_map(|(at, duration_secs)| LastUsed {
                at,
                transport: TransportKind::TorRelay,
                duration_secs,
            }),
        ),
    )
        .prop_map(
            |(
                id,
                device,
                label,
                created_by,
                created_at,
                preset,
                auth,
                mode,
                schedule,
                state,
                fail,
                last_used,
            )| UnattendedGrant {
                id,
                device: DeviceId::from_bytes(device),
                label,
                created_by,
                created_at,
                active_from: created_at.saturating_add(7),
                preset,
                suite: auth.suite(),
                auth,
                mode,
                schedule,
                expires_at: Some(created_at.saturating_add(90)),
                auto_renew: created_at % 2 == 0,
                max_session_secs: Some(u32::try_from(created_at % 4000).unwrap_or(0)),
                reconnect_cooldown_s: 600,
                block_window_s: u8::try_from(created_at % 31).unwrap_or(0),
                ask_before_start: created_at % 3 == 0,
                require_absent: created_at % 5 == 0,
                require_tor_only: created_at % 7 == 0,
                lock_on_disconnect: created_at % 11 == 0,
                hard_lock_after: u32::try_from(created_at % 21).unwrap_or(20),
                state,
                last_used,
                fail,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn grant_cbor_roundtrip(g in arb_grant()) {
        let bytes = minicbor::to_vec(&g).unwrap();
        let back: UnattendedGrant = minicbor::decode(&bytes).unwrap();
        prop_assert_eq!(back, g);
    }

    #[test]
    fn store_cbor_and_aead_roundtrip(grants in proptest::collection::vec(arb_grant(), 0..3),
                                     setup in proptest::collection::vec(any::<u8>(), 0..130),
                                     enabled in any::<bool>(), generation in any::<u64>(),
                                     head in any::<[u8; 32]>(), key in any::<[u8; 32]>()) {
        let mut store = UnattendedStore::bootstrap(Zeroizing::new(setup), Some([1; 32]), 5);
        store.grants = grants;
        store.enabled = enabled;
        store.log_chain_head = head;
        store.stop_token = Some([9; 32]);
        store.tombstones = vec![(DeviceId::from_bytes([2; 32]), 7)];
        let bytes = minicbor::to_vec(&store).unwrap();
        let back: UnattendedStore = minicbor::decode(&bytes).unwrap();
        prop_assert_eq!(&back, &store);
        let sealed = codec::seal(&key, generation, &store).unwrap();
        let (g, opened) = codec::open(&key, &sealed).unwrap();
        prop_assert_eq!(g, generation);
        prop_assert_eq!(opened, store);
    }

    #[test]
    fn store_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = minicbor::decode::<UnattendedStore>(&bytes);
        let _ = minicbor::decode::<UnattendedGrant>(&bytes);
        let _ = codec::open(&[0; 32], &bytes);
    }
}

#[test]
fn unknown_cbor_keys_in_the_store_are_skipped() {
    // a future field under key 99 inside a FailState map and a Window map
    let mut e = minicbor::Encoder::new(Vec::new());
    e.map(10).unwrap();
    e.u32(99).unwrap().str("future").unwrap();
    for (k, v) in [(0u32, 3u64), (1, 4), (4, 10), (5, 77), (7, 88), (8, 99)] {
        e.u32(k).unwrap().u64(v).unwrap();
    }
    e.u32(2).unwrap().bool(true).unwrap();
    e.u32(3).unwrap().u64(5).unwrap();
    e.u32(6).unwrap().bool(false).unwrap();
    let back: FailState = minicbor::decode(&e.into_writer()).unwrap();
    assert_eq!(
        back,
        FailState {
            consecutive: 3,
            since_unlock: 4,
            pending: true,
            last_fail_at: Some(5),
            lock_remaining_s: 10,
            flushed_at: 77,
            hard_locked: false,
            decay_anchor: 88,
            lifetime_decay_anchor: 99,
        }
    );
    let mut e = minicbor::Encoder::new(Vec::new());
    e.map(5).unwrap();
    e.u32(0).unwrap().u8(1).unwrap();
    e.u32(1).unwrap().u16(60).unwrap();
    e.u32(42)
        .unwrap()
        .array(2)
        .unwrap()
        .u8(1)
        .unwrap()
        .u8(2)
        .unwrap();
    e.u32(2).unwrap().u16(120).unwrap();
    e.u32(3).unwrap().str("UTC").unwrap();
    let back: Window = minicbor::decode(&e.into_writer()).unwrap();
    assert_eq!(
        back,
        Window {
            days: 1,
            start_min: 60,
            end_min: 120,
            tz: "UTC".into()
        }
    );
    // a missing mandatory field is an error, not a silent default
    let mut e = minicbor::Encoder::new(Vec::new());
    e.map(1).unwrap().u32(0).unwrap().u16(1).unwrap();
    assert!(minicbor::decode::<UnattendedStore>(&e.into_writer()).is_err());
}

#[test]
fn write_class_runtime_never_raises_the_anchor_even_when_owed_is_false() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines);
    let anchor = env.anchor();
    for _ in 0..5 {
        store
            .mutate(WriteClass::Runtime, None, |s, now| {
                s.last_seen_unix = s.last_seen_unix.max(now);
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(env.anchor(), anchor);
    assert!(store.generation() > anchor);
    let _ = env.clock.mono();
}

// ------------------------------------------------------------------ offline load (§B.8.5.1 / §B.8.6.2)

#[test]
fn u4_offline_open_decodes_but_never_settles_decays_or_rearms() {
    let env = Env::new();
    let store = env.open();
    let (a, b) = (dev(1), dev(2));
    let g = enable(&env, &store, a, Preset::MyMachines);
    g.create_grant(Actor::Ui, &b, Preset::MyMachines, &waived(), &upload())
        .unwrap();
    let lim = AttemptLimiter::new(store.clone());
    // b: a running 10 s lock persisted; a: a pending (abandoned) charge
    fail_n(&env, &lim, &a, 2);
    fail_n(&env, &lim, &b, 2);
    let c = lim.charge(&b).unwrap();
    assert_eq!(c.lock_secs, 10);
    lim.settle(&b, Settle::Fail(FailKind::BadKe3)).unwrap();
    let c = lim.charge(&a).unwrap();
    assert_eq!((c.consecutive, c.lock_secs), (3, 10));
    let (before_a, before_b) = (fail_of(&store, &a), fail_of(&store, &b));
    assert!(before_a.pending);
    assert_eq!(before_b.lock_remaining_s, 10);
    let file_before = env.file_bytes();
    let gen_before = store.generation();
    drop((lim, g, store));
    env.advance(30 * D);

    // the offline CLI: everything byte-identical, nothing written, no limiter
    let offline = env.open_offline();
    assert_eq!(offline.mode(), LoadMode::Offline);
    assert_eq!(offline.status(), StoreStatus::Loaded);
    assert_eq!(
        fail_of(&offline, &a),
        before_a,
        "pending, counters, anchors untouched"
    );
    assert_eq!(fail_of(&offline, &b), before_b, "lock picture untouched");
    assert_eq!(env.file_bytes(), file_before, "no load-time write");
    assert_eq!(offline.generation(), gen_before);
    assert_eq!(
        offline.lock_remaining_s(&b),
        0,
        "the persisted lock is reported read-only: 10 s armed 30 d ago has run out"
    );
    let rep = offline.status_report(ReadinessSnapshot::unknown());
    assert_eq!(rep.grants.len(), 2);
    let lim = AttemptLimiter::new(offline.clone());
    assert!(matches!(lim.charge(&a), Err(LimiterError::Offline)));
    assert!(matches!(lim.charge(&b), Err(LimiterError::Offline)));
    assert!(matches!(
        lim.settle(&a, Settle::Ok),
        Err(LimiterError::Offline)
    ));
    assert_eq!(LimiterError::Offline.reject(), Some(Reject::NotGranted));
    offline.housekeeping().unwrap();
    assert_eq!(
        env.file_bytes(),
        file_before,
        "housekeeping is the host's job"
    );
    // a deny-direction mutation offline rewrites nothing of the other grant's FailState
    let guard = env.guard(&offline);
    guard.disable(Actor::Cli, &a).unwrap();
    assert_eq!(
        fail_of(&offline, &b),
        before_b,
        "b's bytes as the host left them"
    );
    assert_eq!(
        fail_of(&offline, &a),
        before_a,
        "a policy write does not settle the pending charge"
    );
    // the only FailState write the CLI performs: a local Unlock
    guard.unlock(Actor::Cli, &b).unwrap();
    let f = fail_of(&offline, &b);
    assert_eq!(
        (
            f.consecutive,
            f.since_unlock,
            f.pending,
            f.hard_locked,
            f.lock_remaining_s
        ),
        (0, 0, false, false, 0)
    );
    assert_eq!(f.decay_anchor, env.clock.wall());
    assert_eq!(f.lifetime_decay_anchor, env.clock.wall());
    assert_eq!(fail_of(&offline, &a), before_a, "still untouched");
    drop((guard, lim, offline));

    // the host load, by contrast, settles a's pending charge as fail (anchors to now
    // first, so no decay step) — the plan's load accounting applies to the host only
    let store = env.open();
    assert_eq!(store.mode(), LoadMode::Host);
    let f = fail_of(&store, &a);
    assert_eq!((f.consecutive, f.since_unlock, f.pending), (3, 3, false));
    assert_eq!(f.last_fail_at, Some(env.clock.wall()));
    assert!(matches!(
        store.grant(&a).unwrap().state,
        GrantState::Disabled { by: Actor::Cli, .. }
    ));
}

// ------------------------------------------------------------------ charge re-check (§B.8.16)

#[test]
fn u7_charge_rechecks_the_gate_under_the_store_lock() {
    for mutation in 0..6u8 {
        let env = Env::new();
        let store = env.open();
        let d = dev(1);
        let guard = enable(&env, &store, d, Preset::MyMachines);
        let lim = AttemptLimiter::new(store.clone());
        assert_eq!(gate(&lim, &d), Ok(()), "the FSM's gate passed");
        let before = fail_of(&store, &d);
        // … then a deny-direction change lands before the charge
        let expected = match mutation {
            0 => {
                guard.suspend(Actor::Ui, &d).unwrap();
                Reject::Suspended { cause: 1 }
            }
            1 => {
                guard.disable(Actor::Ui, &d).unwrap();
                Reject::NotGranted
            }
            2 => {
                guard.pause(Actor::Ui, env.clock.wall() + 600).unwrap();
                Reject::NotGranted
            }
            3 => {
                guard.master_off(Actor::Ui).unwrap();
                Reject::NotGranted
            }
            4 => {
                env.clock.set_wall(T0 - 100);
                Reject::NotYetActive {
                    next_open_in_s: 100,
                }
            }
            _ => {
                guard.revoke(Actor::Ui, &d).unwrap();
                Reject::NotGranted
            }
        };
        let err = lim.charge(&d).unwrap_err();
        assert_eq!(err.reject(), Some(expected), "mutation {mutation}: {err}");
        if mutation < 5 {
            assert!(matches!(err, LimiterError::Refused(_)), "{err:?}");
            assert_eq!(fail_of(&store, &d), before, "nothing charged");
        } else {
            assert!(matches!(err, LimiterError::NoGrant));
        }
        assert!(
            !env.has_event(SessionEvent::UnattendedChallengeIssued),
            "no KE2 line for mutation {mutation}"
        );
    }
}

// ------------------------------------------------------------------ TOCTOU (§B.8.6.2 / §B.8.7.4)

/// A dialog during which an unattended session starts.
struct FlipLiveReAuth {
    activity: Arc<ScriptedActivity>,
    calls: parking_lot::Mutex<u32>,
}

impl ReAuth for FlipLiveReAuth {
    fn reauthenticate(&self, _op: &str) -> Result<(), ReAuthError> {
        self.activity.set_live(true);
        *self.calls.lock() += 1;
        Ok(())
    }
}

#[test]
fn a8_access_increasing_rechecks_the_remote_session_after_the_dialog() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    drop(enable(&env, &store, d, Preset::MyMachines));
    let lim = AttemptLimiter::new(store.clone());
    fail_n(&env, &lim, &d, 3);
    let activity = Arc::new(ScriptedActivity::default());
    let reauth = Arc::new(FlipLiveReAuth {
        activity: activity.clone(),
        calls: parking_lot::Mutex::new(0),
    });
    let guard = MutationGuard::new(store.clone(), reauth.clone(), activity.clone())
        .with_server_setup_source(Arc::new(RandomServerSetupSource))
        .with_paired_devices(Arc::new(AllowAllPaired));
    let token_before = store.read(|s| s.stop_token).unwrap();
    let mut refused = 0;
    let mut check = |r: Result<(), GuardError>| {
        let err = r.unwrap_err();
        assert_eq!(err.code(), codes::G_REMOTE_SESSION_ACTIVE, "{err}");
        refused += 1;
        activity.set_live(false);
    };
    check(guard.unlock(Actor::Ui, &d));
    assert_eq!(fail_of(&store, &d).consecutive, 3, "not unlocked");
    check(guard.master_on(Actor::Ui, &HOST_PK).map(|_| ()));
    assert_eq!(store.read(|s| s.stop_token).unwrap(), token_before);
    check(
        guard
            .create_grant(
                Actor::Ui,
                &dev(2),
                Preset::HeadlessBox,
                &GrantOptions::default(),
                &upload(),
            )
            .map(|_| ()),
    );
    assert!(store.grant(&dev(2)).is_none());
    check(guard.reg_start(Actor::Ui, &dev(2)).map(|_| ()));
    assert_eq!(
        guard
            .reg_finish(
                Actor::Ui,
                &dev(2),
                &[0; 16],
                &upload(),
                Preset::HeadlessBox,
                &GrantOptions::default()
            )
            .unwrap_err()
            .code(),
        codes::G_NO_TXN,
        "no txn was issued"
    );
    guard.disable(Actor::Ui, &d).unwrap();
    check(guard.enable(Actor::Ui, &d));
    assert!(matches!(
        store.grant(&d).unwrap().state,
        GrantState::Disabled { .. }
    ));
    check(guard.set_options(
        Actor::Ui,
        &d,
        &GrantOptions {
            block_window_s: Some(0),
            ..GrantOptions::default()
        },
    ));
    assert_eq!(store.grant(&d).unwrap().block_window_s, 3);
    check(guard.set_settings(
        Actor::Ui,
        super::guard::HostSettings {
            notify: Some(false),
            ..Default::default()
        },
    ));
    assert!(store.read(|s| s.notify).unwrap());
    check(guard.authorize(
        Actor::Ui,
        &super::guard::ExternalOp::BackupExport { path: "/b".into() },
    ));
    assert!(!env.has_event(SessionEvent::BackupExported));
    assert_eq!(
        *reauth.calls.lock(),
        refused,
        "every op ran its dialog first"
    );
    let lines: Vec<_> = env
        .log_events()
        .into_iter()
        .filter(|r| r.event == SessionEvent::GrantMutationRefused)
        .collect();
    assert_eq!(
        lines.len(),
        usize::try_from(refused).unwrap() + 1,
        "{lines:#?}"
    ); // + the G_NO_TXN line
    assert!(
        lines
            .iter()
            .filter(|r| r.code == Some(codes::G_REMOTE_SESSION_ACTIVE))
            .all(|r| r.during_remote_session == Some(true))
    );
}

// ------------------------------------------------------------------ pairing precondition (§B.8 rule 2, §B.8.6.1, §B.8.9)

#[test]
fn a8_grant_requires_a_sas_paired_device_and_unpair_cascades() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let reauth = Arc::new(AllowAllReAuth::default());
    // the normative constructor: pairing is read from trusted-devices.toml
    let guard = MutationGuard::new(store.clone(), reauth.clone(), Arc::new(NoSessionActivity))
        .with_server_setup_source(Arc::new(RandomServerSetupSource));
    guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    assert_eq!(reauth.calls().len(), 1);
    // unpaired ⇒ refused before any dialog, whatever the preset / waiver says
    let err = guard
        .create_grant(Actor::Ui, &d, Preset::HeadlessBox, &waived(), &upload())
        .unwrap_err();
    assert_eq!(err.code(), codes::G_PRECONDITION);
    assert!(err.to_string().contains("not paired"), "{err}");
    assert_eq!(
        guard.reg_start(Actor::Ui, &d).unwrap_err().code(),
        codes::G_PRECONDITION
    );
    assert_eq!(reauth.calls().len(), 1, "no dialog for an unpaired device");
    assert!(store.grant(&d).is_none());
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::GrantMutationRefused
            && r.code == Some(codes::G_PRECONDITION)
            && r.detail
                .as_deref()
                .is_some_and(|s| s.contains("not paired"))
    }));
    // pair it (as the pairing track does) ⇒ the grant carries the pinned label
    let trusted_path = env.paths.trusted_devices_file();
    let mut trusted = TrustedDevices::load(&trusted_path).unwrap();
    trusted.pin(d, "Ana's Laptop", T0);
    trusted.save(&trusted_path).unwrap();
    let pinned = trusted.get(&d).unwrap().label.clone();
    let id = guard
        .create_grant(
            Actor::Ui,
            &d,
            Preset::HeadlessBox,
            &GrantOptions::default(),
            &upload(),
        )
        .unwrap();
    let g = store.grant(&d).unwrap();
    assert_eq!(g.id, id);
    assert_eq!(
        g.label, pinned,
        "the pinned pairing label, never the HELLO name"
    );
    // an explicit label option overrides it (sanitized)
    guard
        .set_options(
            Actor::Ui,
            &d,
            &GrantOptions {
                label: Some(" Media\u{202e} box ".into()),
                ..GrantOptions::default()
            },
        )
        .unwrap();
    assert_eq!(store.grant(&d).unwrap().label, "Media box");
    // a device unpaired without the cascade: set-password is refused, the gate stays as is
    trusted.remove(&d);
    trusted.save(&trusted_path).unwrap();
    assert_eq!(
        guard
            .set_password(Actor::Ui, &d, &[0xCD; 192])
            .unwrap_err()
            .code(),
        codes::G_PRECONDITION
    );
    // Remove device = unpair + revoke: the cascade revokes with a tombstone
    assert!(guard.unpair(Actor::Ui, &d).unwrap());
    assert!(store.grant(&d).is_none());
    assert_eq!(
        store
            .read(|s| s.tombstones.iter().filter(|t| t.0 == d).count())
            .unwrap(),
        1
    );
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::GrantRevoked && r.detail.as_deref() == Some("unpair")
    }));
    assert!(!guard.unpair(Actor::Ui, &d).unwrap(), "idempotent");
    // re-pairing the same key later has no grant
    trusted.pin(d, "Ana's Laptop", T0 + 10);
    trusted.save(&trusted_path).unwrap();
    assert!(store.grant(&d).is_none());
    let lim = AttemptLimiter::new(store.clone());
    assert_eq!(gate(&lim, &d), Err(Reject::NotGranted));
    // unpair on an attended-only host is a harmless no-op
    let env2 = Env::new();
    let store2 = env2.open();
    assert!(!env2.guard(&store2).unpair(Actor::Ui, &d).unwrap());
}

// ------------------------------------------------------------------ recovery (§B.8.12)

#[test]
fn u4_failed_closed_store_is_recovered_by_reset_store_behind_reauth() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    let snapshot = env.file_bytes();
    g.disable(Actor::Ui, &d).unwrap();
    drop((g, store));
    std::fs::write(env.paths.unattended_store(), &snapshot).unwrap();
    let store = env.open();
    assert!(matches!(
        store.status(),
        StoreStatus::FailedClosed(StoreLoadError::OlderThanAnchor { .. })
    ));
    // the reset needs re-auth …
    let deny = MutationGuard::new(
        store.clone(),
        Arc::new(DenyAllReAuth),
        Arc::new(NoSessionActivity),
    );
    assert_eq!(
        deny.reset_store(Actor::Ui).unwrap_err().code(),
        codes::G_REAUTH_FAILED
    );
    assert!(matches!(store.status(), StoreStatus::FailedClosed(_)));
    // … and no remote session
    let activity = Arc::new(ScriptedActivity::default());
    activity.set_live(true);
    let guard = MutationGuard::new(
        store.clone(),
        Arc::new(AllowAllReAuth::default()),
        activity.clone(),
    )
    .with_server_setup_source(Arc::new(RandomServerSetupSource))
    .with_paired_devices(Arc::new(AllowAllPaired));
    assert_eq!(
        guard.reset_store(Actor::Ui).unwrap_err().code(),
        codes::G_REMOTE_SESSION_ACTIVE
    );
    activity.set_live(false);
    guard.reset_store(Actor::Ui).unwrap();
    assert_eq!(store.status(), StoreStatus::AttendedOnly);
    assert!(!env.paths.unattended_store().exists());
    assert!(env.secrets.inner.get(MASTER_KEY_ENTRY).unwrap().is_none());
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::UnattendedDisabled
            && r.detail
                .as_deref()
                .is_some_and(|s| s.contains("store reset"))
    }));
    // re-enable bootstraps a fresh store; grants are recreated locally
    let on = guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    assert_eq!(on.stop_code.len(), 16);
    assert_eq!(store.status(), StoreStatus::Loaded);
    assert!(store.grant(&d).is_none());
    // a loaded store cannot be reset
    assert_eq!(
        guard.reset_store(Actor::Ui).unwrap_err().code(),
        codes::G_PRECONDITION
    );
    assert_eq!(store.status(), StoreStatus::Loaded);
}

// ------------------------------------------------------------------ U5: runtime rollback above the last write

#[test]
fn u5_runtime_step_back_above_the_last_write_fails_closed() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    let last_seen = store.last_seen().unwrap();
    assert_eq!(last_seen, T0);
    // hours of idle without a write: the readings raise the in-memory mark only
    env.advance(6 * H);
    assert_eq!(gate(&lim, &d), Ok(()));
    assert_eq!(store.last_seen().unwrap(), last_seen, "no write happened");
    // an NTP step back by 30 min: above last_seen on disk, below the last reading
    env.clock.set_wall(T0 + 6 * H - 1800);
    assert_eq!(
        gate(&lim, &d),
        Err(Reject::NotYetActive {
            next_open_in_s: 1800
        })
    );
    assert_eq!(
        lim.post_f2(&d, &FixedOffset::utc(), HostTransport::default()),
        Err(PostF2Reject::NotYetActive {
            next_open_in_s: 1800
        })
    );
    assert!(matches!(
        lim.charge(&d),
        Err(LimiterError::Refused(Reject::NotYetActive {
            next_open_in_s: 1800
        }))
    ));
    assert!(env.has_event(SessionEvent::ClockAnomaly));
    assert!(
        store.last_seen().unwrap() >= T0 + 6 * H,
        "the anomaly line's write persisted the high-water mark"
    );
    // once the clock passes the mark the grant opens again
    env.clock.set_wall(T0 + 6 * H);
    assert_eq!(gate(&lim, &d), Ok(()));
    assert!(
        lim.post_f2(&d, &FixedOffset::utc(), HostTransport::default())
            .is_ok()
    );
}

// ------------------------------------------------------------------ machine-id adoption (§B.8.12)

#[test]
fn u4_missing_machine_id_is_adopted_and_a_later_mismatch_disables() {
    let mut env = Env::new();
    env.machine_id = None;
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::MyMachines);
    assert_eq!(store.read(|s| s.machine_id_hash).unwrap(), None);
    drop((g, store));
    env.machine_id = Some(b"machine-A".to_vec());
    let store = env.open();
    assert_eq!(
        store.grant(&d).unwrap().state,
        GrantState::Active,
        "nothing to compare against: no disable"
    );
    assert_eq!(
        store.read(|s| s.machine_id_hash).unwrap(),
        Some(codec::machine_id_hash(b"machine-A")),
        "adopted"
    );
    drop(store);
    // persisted by the load-time write: a fresh load on the same machine still passes …
    let store = env.open();
    assert_eq!(store.grant(&d).unwrap().state, GrantState::Active);
    drop(store);
    // … and a move to another machine is now detected
    env.machine_id = Some(b"machine-B".to_vec());
    let store = env.open();
    assert!(matches!(
        store.grant(&d).unwrap().state,
        GrantState::Disabled {
            by: Actor::Restore,
            ..
        }
    ));
}

// ------------------------------------------------------------------ expiry during downtime (§B.8.13)

#[test]
fn u4_expiry_during_downtime_is_logged_once_by_the_next_housekeeping() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let g = enable(&env, &store, d, Preset::HelpingSomeone); // 7 d expiry
    store.housekeeping().unwrap();
    assert!(!env.has_event(SessionEvent::GrantExpired));
    drop((g, store));
    env.advance(8 * D); // the host is off while the grant expires
    let expired = |env: &Env| {
        env.log_events()
            .iter()
            .filter(|r| r.event == SessionEvent::GrantExpired)
            .count()
    };
    let store = env.open();
    assert_eq!(expired(&env), 0);
    store.housekeeping().unwrap();
    assert_eq!(expired(&env), 1);
    store.housekeeping().unwrap();
    assert_eq!(expired(&env), 1, "logged once");
    drop(store);
    let store = env.open();
    store.housekeeping().unwrap();
    assert_eq!(expired(&env), 1, "not again after a restart");
}

// ------------------------------------------------------------------ A4: lifetime budget with successes in between

#[test]
fn a4_lifetime_budget_hard_locks_despite_successes_in_between() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let _g = enable(&env, &store, d, Preset::MyMachines); // hard_lock_after = 20
    let lim = AttemptLimiter::new(store.clone());
    let mut max_consecutive = 0;
    while fail_of(&store, &d).since_unlock < LIFETIME_BUDGET - 2 {
        // ≤ 18 failures plus the success's own charge never reach the consecutive
        // threshold of 20 …
        for _ in 0..18 {
            if fail_of(&store, &d).since_unlock >= LIFETIME_BUDGET - 2 {
                break;
            }
            fail_once(&env, &lim, &d);
            max_consecutive = max_consecutive.max(fail_of(&store, &d).consecutive);
        }
        // … and a success resets the consecutive counter (reset-on-success farming)
        lim.charge(&d).unwrap();
        lim.settle(&d, Settle::Ok).unwrap();
        let f = fail_of(&store, &d);
        assert_eq!(f.consecutive, 0);
        assert!(!f.hard_locked);
    }
    assert!(max_consecutive < 20);
    assert!(!env.has_event(SessionEvent::UnattendedHardLock));
    fail_once(&env, &lim, &d);
    assert_eq!(fail_of(&store, &d).since_unlock, LIFETIME_BUDGET - 1);
    // the 60th settled failure since the unlock hard-locks whatever the consecutive count
    let c = lim.charge(&d).unwrap();
    assert_eq!(c.since_unlock, LIFETIME_BUDGET);
    assert!(c.hard_lock_armed);
    assert!(c.consecutive < 20);
    lim.settle(&d, Settle::Fail(FailKind::BadKe3)).unwrap();
    assert!(fail_of(&store, &d).hard_locked);
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::UnattendedHardLock && r.reason.as_deref() == Some("lifetime")
    }));
    assert_eq!(gate(&lim, &d), Err(Reject::HardLocked));
    assert!(
        matches!(
            lim.charge(&d),
            Err(LimiterError::Locked(Reject::HardLocked))
        ),
        "no KE2 afterwards"
    );
    // only a local unlock (or admin unlock) clears it
    env.guard(&store).unlock(Actor::Ui, &d).unwrap();
    assert_eq!(gate(&lim, &d), Ok(()));
}

// ------------------------------------------------------------------ U1: credit / twin invariant (§B.8.5.1)

#[derive(Debug, Clone, Copy)]
enum ClockStep {
    Both(u64),
    WallOnly(u64),
    Back(u64),
    Attempt(bool),
}

fn arb_step() -> impl Strategy<Value = ClockStep> {
    prop_oneof![
        (1u64..3 * D).prop_map(ClockStep::Both),
        (1u64..3 * D).prop_map(ClockStep::WallOnly),
        (1u64..2 * H).prop_map(ClockStep::Back),
        any::<bool>().prop_map(ClockStep::Attempt),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// `credit + twin.elapsed() ≤ wall time since the persisted anchor`, with equality
    /// whenever the wall and the monotonic clock advanced together since that anchor
    /// was written (§B.8.5.1); a rollback or a clamped `:= now` write only defers decay.
    #[test]
    fn u1_credit_plus_twin_elapsed_never_exceeds_wall_since_the_anchor(
        steps in proptest::collection::vec(arb_step(), 1..24),
    ) {
        let env = Env::new();
        let store = env.open();
        let d = dev(1);
        let _g = enable(&env, &store, d, Preset::MyMachines);
        let lim = AttemptLimiter::new(store.clone());
        // per anchor: (a backward step happened, a wall-only step happened) since written
        let (mut decay_flags, mut lifetime_flags) = ((false, false), (false, false));
        for step in steps {
            match step {
                ClockStep::Both(s) => env.advance(s),
                ClockStep::WallOnly(s) => {
                    env.clock.advance_wall(s);
                    decay_flags.1 = true;
                    lifetime_flags.1 = true;
                }
                ClockStep::Back(s) => {
                    env.clock.set_wall(env.clock.wall().saturating_sub(s));
                    decay_flags.0 = true;
                    lifetime_flags.0 = true;
                }
                ClockStep::Attempt(ok) => {
                    if lim.charge(&d).is_ok() {
                        let now = env.clock.wall();
                        let f = fail_of(&store, &d);
                        // charge: decay_anchor := max(stored, now); a clamped write keeps the deficit
                        if f.decay_anchor <= now {
                            decay_flags = (false, false);
                        }
                        lim.settle(&d, if ok { Settle::Ok } else { Settle::Fail(FailKind::BadKe3) }).unwrap();
                        if !ok {
                            let f = fail_of(&store, &d);
                            if f.decay_anchor <= now {
                                decay_flags = (false, false);
                            }
                            if f.lifetime_decay_anchor <= now {
                                lifetime_flags = (false, false);
                            }
                        }
                    }
                }
            }
            let f = fail_of(&store, &d);
            prop_assert!(!f.hard_locked || f.since_unlock > 0 || f.consecutive > 0);
            let st = store.state();
            let Some(rt) = st.runtime.get(&d).copied() else { continue };
            drop(st);
            let (wall, mono) = (env.clock.wall(), env.clock.mono());
            for (anchor, credit, twin, flags) in [
                (f.decay_anchor, rt.decay_credit, rt.decay_twin, decay_flags),
                (f.lifetime_decay_anchor, rt.lifetime_credit, rt.lifetime_twin, lifetime_flags),
            ] {
                let elapsed = credit + mono.saturating_sub(twin).as_secs();
                let since_anchor = wall.saturating_sub(anchor);
                if !flags.0 {
                    prop_assert!(
                        elapsed <= since_anchor,
                        "elapsed {} > since anchor {} after {:?}",
                        elapsed,
                        since_anchor,
                        step
                    );
                    if !flags.1 {
                        prop_assert_eq!(
                            elapsed,
                            since_anchor,
                            "equality without wall-only steps after {:?}",
                            step
                        );
                    }
                }
            }
        }
        // decay never clears a hard lock and counters never go negative: trivially by type;
        // the persisted anchors never decreased across the run
        let f = fail_of(&store, &d);
        prop_assert!(f.decay_anchor >= T0 && f.lifetime_decay_anchor >= T0);
    }
}

// ------------------------------------------------------------------ enable / disable semantics, admin lines

#[test]
fn enable_only_leaves_disabled_and_disable_is_idempotent() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let guard = enable(&env, &store, d, Preset::MyMachines);
    let g0 = store.generation();
    guard.enable(Actor::Ui, &d).unwrap();
    assert_eq!(store.generation(), g0, "enable on Active: no write");
    guard.suspend(Actor::Ui, &d).unwrap();
    let err = guard.enable(Actor::Ui, &d).unwrap_err();
    assert_eq!(err.code(), codes::G_PRECONDITION);
    assert!(err.to_string().contains("resume"), "{err}");
    assert!(matches!(
        store.grant(&d).unwrap().state,
        GrantState::Suspended { .. }
    ));
    guard.resume(Actor::Ui, &d).unwrap();
    guard.disable(Actor::Ui, &d).unwrap();
    let g1 = store.generation();
    let disabled = |env: &Env| {
        env.log_events()
            .iter()
            .filter(|r| r.event == SessionEvent::GrantDisabled)
            .count()
    };
    let n = disabled(&env);
    guard.disable(Actor::Ui, &d).unwrap();
    assert_eq!(store.generation(), g1, "disable on Disabled: no write");
    assert_eq!(disabled(&env), n, "and no line");
    guard.enable(Actor::Ui, &d).unwrap();
    assert_eq!(store.grant(&d).unwrap().state, GrantState::Active);
    assert!(env.has_event(SessionEvent::GrantEnabled));
    assert_eq!(
        guard.enable(Actor::Ui, &dev(9)).unwrap_err().code(),
        codes::G_PRECONDITION
    );
}

#[test]
fn a15_remote_master_off_and_revoke_write_the_per_event_lines() {
    let (env, store, guard, admin, target, _) = admin_env();
    guard.admin(&admin, AdminOp::Revoke(target)).unwrap();
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::GrantRevoked
            && r.peer_device == Some(target)
            && r.reason.as_deref() == Some("admin")
    }));
    let out = guard.admin(&admin, AdminOp::MasterOff).unwrap();
    assert_eq!(out.effect, AdminEffect::MasterOff);
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::UnattendedDisabled && r.reason.as_deref() == Some("admin")
    }));
    guard.master_on(Actor::Ui, &HOST_PK).unwrap();
    let out = guard.admin(&admin, AdminOp::RevokeAll).unwrap();
    assert_eq!(out.effect, AdminEffect::RevokedAll(2));
    assert!(env.log_events().iter().any(|r| {
        r.event == SessionEvent::GrantRevoked
            && r.reason.as_deref() == Some("admin")
            && r.detail
                .as_deref()
                .is_some_and(|s| s.contains("revoke all (2)"))
    }));
    assert!(store.grants().is_empty());
}

// ------------------------------------------------------------------ TRANSPORT_UNAVAILABLE (§B.8.4.6, §B.8.11)

#[test]
fn post_f2_tor_only_grant_on_a_lan_only_host_is_transport_unavailable() {
    let env = Env::new();
    let store = env.open();
    let d = dev(1);
    let guard = enable(&env, &store, d, Preset::MyMachines);
    let lim = AttemptLimiter::new(store.clone());
    let utc = FixedOffset::utc();
    let ok = lim.post_f2(&d, &utc, HostTransport::default()).unwrap();
    assert_eq!(ok.transport, TransportPolicy::Any);
    let lan = HostTransport {
        paranoid: false,
        lan_only: true,
    };
    assert_eq!(
        lim.post_f2(&d, &utc, lan).unwrap().transport,
        TransportPolicy::LanOnly
    );
    let paranoid = HostTransport {
        paranoid: true,
        lan_only: false,
    };
    assert_eq!(
        lim.post_f2(&d, &utc, paranoid).unwrap().transport,
        TransportPolicy::TorOnly
    );
    // turning require_tor_only on narrows (no re-auth) …
    guard
        .set_options(
            Actor::Ui,
            &d,
            &GrantOptions {
                require_tor_only: Some(true),
                ..GrantOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        lim.post_f2(&d, &utc, HostTransport::default())
            .unwrap()
            .transport,
        TransportPolicy::TorOnly
    );
    // … and on a LAN-only host the conflict is the 0x0027 reject, never a downgrade
    assert_eq!(
        lim.post_f2(&d, &utc, lan),
        Err(PostF2Reject::TransportUnavailable)
    );
    assert_eq!(PostF2Reject::TransportUnavailable.code(), 0x0027);
    let g = store.grant(&d).unwrap();
    assert_eq!(g.transport_policy(false, true), Err(TransportConflict));
    assert_eq!(
        g.transport_policy(true, true),
        Err(TransportConflict),
        "paranoid + LAN-only is the same contradiction"
    );
    // the conflict is answered before the reconnect cooldown (code order)
    let mut cooled = g.clone();
    cooled.max_session_secs = Some(100);
    cooled.reconnect_cooldown_s = 600;
    cooled.last_used = Some(LastUsed {
        at: env.clock.wall(),
        transport: TransportKind::Lan,
        duration_secs: 100,
    });
    assert_eq!(
        post_f2(&cooled, env.clock.wall() + 150, 0, &utc, lan),
        Err(PostF2Reject::TransportUnavailable)
    );
    assert!(matches!(
        post_f2(
            &cooled,
            env.clock.wall() + 150,
            0,
            &utc,
            HostTransport::default()
        ),
        Err(PostF2Reject::Cooldown { .. })
    ));
}
