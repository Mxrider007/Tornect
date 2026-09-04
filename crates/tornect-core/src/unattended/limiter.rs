//! The attempt limiter of `docs/PLAN.md` §B.8.5 — the single writer of `FailState`
//! (decision M1-14: it lives here, next to the store; `tornect-signal` only calls it).
//!
//! * [`gate`] / [`AttemptLimiter::gate`]: the pure pre-PAKE decision in the exact order
//!   of the §B.8.4.5 table (uncharged).
//! * [`AttemptLimiter::charge`]: re-runs the gate under the store lock (§B.8.16: no KE2
//!   while locked / suspended / expired / disabled — a deny-direction mutation may have
//!   landed since the caller's `gate`), then decay-before-charge on the monotonic twins,
//!   counters up, `pending = true`, lock armed for the new `n`, **persisted and fsynced
//!   before it returns** — the caller only then writes KE2.
//! * [`AttemptLimiter::settle`]: the success/failure bookkeeping of §B.8.5.1.
//! * The post-F2 helpers ([`post_f2`], [`ends_at`], [`reconnect_cooldown`]).
//!
//! Every wall-clock evaluation compares `now` with the in-memory high-water mark of the
//! readings taken so far as well as with the persisted `last_seen_unix` (§B.8.5.3:
//! "monotone in memory and on disk"), so a runtime step back to any earlier reading —
//! not only below the last write — fails schedule / `active_from` / expiry closed.

use std::time::Duration;

use crate::id::DeviceId;
use crate::session_log::{SessionEvent, SessionRecord, TransportKind};

use super::grant::{
    AuthRecord, FailState, FailSummary, GrantId, GrantState, LIFETIME_BUDGET, LastUsed,
    TransportPolicy, UnattendedGrant,
};
use super::schedule::{self, LocalTz};
use super::store::{
    DECAY_PERIOD_S, GrantStore, LIFETIME_DECAY_PERIOD_S, LoadMode, RuntimeFail, StoreError,
    StoreStatus, WriteClass, remaining_secs,
};

/// `SESSION_REJECT.reason` codes (§B.8.4.6).
pub mod reject_codes {
    /// Attended: the user clicked Deny (or `ask_before_start` timed out).
    pub const DENIED: u16 = 0x0001;
    /// Attended: the consent popup timed out.
    pub const POPUP_TIMEOUT: u16 = 0x0002;
    /// Attended: a remote session is live (popups are not presented).
    pub const BUSY: u16 = 0x0003;
    /// No grant · disabled · expired · master off · paused · keystore locked.
    pub const NOT_GRANTED: u16 = 0x0010;
    /// Ladder lock (`retry_after_s`, rounded up to 10 s).
    pub const LOCKED_OUT: u16 = 0x0011;
    /// Hard lock.
    pub const HARD_LOCKED: u16 = 0x0012;
    /// In-flight / global budget (§B.8.5.2).
    pub const UA_BUSY: u16 = 0x0013;
    /// Suite unsupported by this build or ≠ `grant.suite`.
    pub const UNSUPPORTED_SUITE: u16 = 0x0014;
    /// Cooling-off or clock rollback (`next_open_in_s`).
    pub const NOT_YET_ACTIVE: u16 = 0x0015;
    /// `Suspended{..}` (`cause` 1 local · 2 admin).
    pub const SUSPENDED: u16 = 0x0016;
    /// Bad KE3.
    pub const AUTH_FAILED: u16 = 0x0020;
    /// Post-F2: schedule closed (`next_open_in_s`).
    pub const OUTSIDE_SCHEDULE: u16 = 0x0021;
    /// Post-F2: the local user pressed Block.
    pub const BLOCKED_BY_LOCAL_USER: u16 = 0x0022;
    /// Post-F2: readiness gate (`cause`).
    pub const HOST_NOT_READY: u16 = 0x0023;
    /// Reserved (v1 replaces the older session instead).
    pub const ALREADY_CONNECTED: u16 = 0x0024;
    /// Post-F2: another remote session is live.
    pub const SESSION_ACTIVE: u16 = 0x0026;
    /// Post-F2: grant requires Tor-only media but the host forbids it.
    pub const TRANSPORT_UNAVAILABLE: u16 = 0x0027;
    /// Post-F2: `require_absent` and a local user is present.
    pub const LOCAL_USER_PRESENT: u16 = 0x0028;
    /// Post-F2: reconnect cooldown after `max_session_secs` (`retry_after_s`).
    pub const COOLDOWN: u16 = 0x0029;
    /// A charged stream cancelled by a newer verified `SESSION_REQUEST`.
    pub const PREEMPTED: u16 = 0x002A;
}

/// Lock armed after the `n`-th consecutive challenge (§B.8.5.1 ladder), in seconds.
#[must_use]
pub fn ladder_lock_secs(n: u32) -> u32 {
    match n {
        0..=2 => 0,
        3 => 10,
        4 => 30,
        5 => 60,
        6 => 120,
        7 => 300,
        8 => 900,
        9 => 1800,
        _ => 3600,
    }
}

/// `retry_after_s` rounded **up** to the next 10 s (§B.8.4.6).
#[must_use]
pub fn round_up_10(secs: u32) -> u32 {
    secs.div_ceil(10).saturating_mul(10)
}

/// Pre-PAKE reject (§B.8.4.6), in table order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// No grant · disabled · expired · master off · paused · store not loaded.
    NotGranted,
    /// Suite unsupported by this build or ≠ `grant.suite`.
    UnsupportedSuite,
    /// `now < active_from`, or a clock rollback (`next_open_in_s = last_seen − now`).
    NotYetActive {
        /// Seconds until the grant may be used.
        next_open_in_s: u32,
    },
    /// `Suspended{..}`; `cause` 1 local · 2 admin.
    Suspended {
        /// `SESSION_REJECT.cause`.
        cause: u8,
    },
    /// Ladder lock; `retry_after_s` rounded up to 10 s.
    LockedOut {
        /// Seconds to wait.
        retry_after_s: u32,
    },
    /// Hard lock (unlock locally or by admin request).
    HardLocked,
}

impl Reject {
    /// The `SESSION_REJECT.reason` code.
    #[must_use]
    pub fn code(&self) -> u16 {
        match self {
            Self::NotGranted => reject_codes::NOT_GRANTED,
            Self::UnsupportedSuite => reject_codes::UNSUPPORTED_SUITE,
            Self::NotYetActive { .. } => reject_codes::NOT_YET_ACTIVE,
            Self::Suspended { .. } => reject_codes::SUSPENDED,
            Self::LockedOut { .. } => reject_codes::LOCKED_OUT,
            Self::HardLocked => reject_codes::HARD_LOCKED,
        }
    }

    /// `SESSION_REJECT.cause`.
    #[must_use]
    pub fn cause(&self) -> Option<u8> {
        match self {
            Self::Suspended { cause } => Some(*cause),
            _ => None,
        }
    }

    /// `SESSION_REJECT.retry_after_s`.
    #[must_use]
    pub fn retry_after_s(&self) -> Option<u32> {
        match self {
            Self::LockedOut { retry_after_s } => Some(*retry_after_s),
            _ => None,
        }
    }

    /// `SESSION_REJECT.next_open_in_s`.
    #[must_use]
    pub fn next_open_in_s(&self) -> Option<u32> {
        match self {
            Self::NotYetActive { next_open_in_s } => Some(*next_open_in_s),
            _ => None,
        }
    }
}

/// What the gate hands back when the handshake may proceed to the charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateOk {
    /// The grant that will be charged.
    pub grant_id: GrantId,
}

/// The inputs of the pure gate.
#[derive(Debug, Clone, Copy)]
pub struct GateView<'a> {
    /// A store is loaded (else everything is `NOT_GRANTED`).
    pub loaded: bool,
    /// Master switch on and not paused at `now`.
    pub enabled: bool,
    /// The device's grant, if any.
    pub grant: Option<&'a UnattendedGrant>,
    /// `UnattendedStore.last_seen_unix` (rollback test).
    pub last_seen: u64,
    /// Suite requested in `SESSION_REQUEST.unattended.suite`.
    pub requested_suite: u8,
    /// Suites compiled into this build.
    pub supported_suites: &'a [u8],
    /// Remaining running lock in seconds (0 = none).
    pub lock_remaining_s: u32,
}

/// The pure pre-PAKE decision, in the exact order of the §B.8.4.5 table: grant lookup
/// · suite · `active_from` / rollback · suspension · hard lock · ladder lock. Global
/// budgets (`UA_BUSY`) are the caller's. `view.last_seen` is the rollback reference:
/// the persisted `last_seen_unix` raised to every wall reading taken since (§B.8.5.3).
pub fn gate(view: &GateView<'_>, now: u64) -> Result<GateOk, Reject> {
    if !view.loaded || !view.enabled {
        return Err(Reject::NotGranted);
    }
    let Some(g) = view.grant else {
        return Err(Reject::NotGranted);
    };
    if matches!(g.state, GrantState::Disabled { .. })
        || g.expired_at(now)
        || g.auth == AuthRecord::Pruned
    {
        return Err(Reject::NotGranted);
    }
    if !view.supported_suites.contains(&view.requested_suite) || g.suite != view.requested_suite {
        return Err(Reject::UnsupportedSuite);
    }
    if now < g.active_from {
        return Err(Reject::NotYetActive {
            next_open_in_s: u32::try_from(g.active_from - now).unwrap_or(u32::MAX),
        });
    }
    if now < view.last_seen {
        return Err(Reject::NotYetActive {
            next_open_in_s: u32::try_from(view.last_seen - now).unwrap_or(u32::MAX),
        });
    }
    if let GrantState::Suspended { reason, .. } = g.state {
        return Err(Reject::Suspended {
            cause: reason.reject_cause(),
        });
    }
    if g.fail.hard_locked {
        return Err(Reject::HardLocked);
    }
    if view.lock_remaining_s > 0 {
        return Err(Reject::LockedOut {
            retry_after_s: round_up_10(view.lock_remaining_s),
        });
    }
    Ok(GateOk { grant_id: g.id })
}

/// Why a charge or settlement was refused.
#[derive(Debug, thiserror::Error)]
pub enum LimiterError {
    /// No store loaded.
    #[error("unattended store not loaded")]
    NotLoaded,
    /// No grant for the device.
    #[error("no unattended grant for this device")]
    NoGrant,
    /// The device already has a charged, unsettled handshake (≤ 1 charge per stream/pk).
    #[error("a charge is already pending for this device")]
    AlreadyPending,
    /// `settle` without a pending charge.
    #[error("no charge is pending for this device")]
    NotPending,
    /// The gate would have refused (hard lock or running lock): nothing charged.
    #[error("grant is locked: {0:?}")]
    Locked(Reject),
    /// The gate re-run inside `charge` refused for a state reason — the grant was
    /// disabled, suspended, expired, pruned, the master switch turned off or paused, or
    /// the clock rolled back since the caller's `gate` (§B.8.16): nothing charged, the
    /// caller answers with the reject instead of KE2.
    #[error("grant refused pre-PAKE: {0:?}")]
    Refused(Reject),
    /// The store was opened by the offline CLI (`LoadMode::Offline`): no handshake runs
    /// there, so nothing may be charged or settled.
    #[error("unattended store opened offline: no charges")]
    Offline,
    /// Persisting the charge failed: the caller must not write KE2.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl LimiterError {
    /// The pre-PAKE reject to answer with, when the refusal maps to one.
    #[must_use]
    pub fn reject(&self) -> Option<Reject> {
        match self {
            Self::Locked(r) | Self::Refused(r) => Some(*r),
            Self::NotLoaded | Self::NoGrant | Self::Offline => Some(Reject::NotGranted),
            Self::AlreadyPending | Self::NotPending | Self::Store(_) => None,
        }
    }
}

/// What a charge armed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Charged {
    /// The grant.
    pub grant_id: GrantId,
    /// Consecutive counter after the charge (the `n` of the ladder).
    pub consecutive: u32,
    /// Lifetime counter after the charge.
    pub since_unlock: u32,
    /// Lock armed for this `n`, in seconds.
    pub lock_secs: u32,
    /// Whether this charge armed the hard lock.
    pub hard_lock_armed: bool,
}

/// How a charged handshake ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settle {
    /// KE3 verified (F2).
    Ok,
    /// Bad KE3, timeout, circuit loss, `BYE`, `ERROR`-class violation or cancellation.
    Fail(FailKind),
}

/// The failure kinds of §B.8.4.5 (logged as `reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailKind {
    /// `ServerLogin::finish` failed (wrong password).
    BadKe3,
    /// No `AUTH_RESPONSE` within 30 s.
    Timeout,
    /// Circuit loss or `BYE`.
    Disconnected,
    /// `E_BAD_STATE` / `E_BAD_MSG_ID` / `E_BAD_LEN` on the stream.
    Protocol,
    /// Cancelled by a newer verified `SESSION_REQUEST` from the same pk.
    Preempted,
}

impl FailKind {
    /// Log name.
    #[must_use]
    pub fn log_name(self) -> &'static str {
        match self {
            Self::BadKe3 => "bad_ke3",
            Self::Timeout => "timeout",
            Self::Disconnected => "disconnected",
            Self::Protocol => "protocol",
            Self::Preempted => "preempted",
        }
    }
}

/// Runtime decay on the monotonic twins (§B.8.5.1): before each charge, full steps on
/// both counters; an applied step advances the persisted anchor by whole periods and
/// keeps the residual as `credit`. Public only for the F3 fuzz target.
#[doc(hidden)]
pub fn decay_runtime(f: &mut FailState, rt: &mut RuntimeFail, mono: Duration) {
    let elapsed = rt
        .decay_credit
        .saturating_add(mono.saturating_sub(rt.decay_twin).as_secs());
    let steps = elapsed / DECAY_PERIOD_S;
    if steps > 0 {
        f.consecutive = f
            .consecutive
            .saturating_sub(u32::try_from(steps).unwrap_or(u32::MAX));
        f.decay_anchor = f
            .decay_anchor
            .saturating_add(steps.saturating_mul(DECAY_PERIOD_S));
        rt.decay_credit = elapsed - steps * DECAY_PERIOD_S;
        rt.decay_twin = mono;
    }
    let elapsed = rt
        .lifetime_credit
        .saturating_add(mono.saturating_sub(rt.lifetime_twin).as_secs());
    let steps = elapsed / LIFETIME_DECAY_PERIOD_S;
    if steps > 0 {
        f.since_unlock = f
            .since_unlock
            .saturating_sub(u32::try_from(steps).unwrap_or(u32::MAX));
        f.lifetime_decay_anchor = f
            .lifetime_decay_anchor
            .saturating_add(steps.saturating_mul(LIFETIME_DECAY_PERIOD_S));
        rt.lifetime_credit = elapsed - steps * LIFETIME_DECAY_PERIOD_S;
        rt.lifetime_twin = mono;
    }
}

/// The limiter handle: a clone of the store handle plus its clock.
#[derive(Debug, Clone)]
pub struct AttemptLimiter {
    store: GrantStore,
}

impl AttemptLimiter {
    /// Wrap a store.
    #[must_use]
    pub fn new(store: GrantStore) -> Self {
        Self { store }
    }

    /// The underlying store.
    #[must_use]
    pub fn store(&self) -> &GrantStore {
        &self.store
    }

    /// The pre-PAKE gate for `device` (uncharged). A runtime rollback (`now <
    /// last_seen`) is answered `NOT_YET_ACTIVE` and logged as `ClockAnomaly`
    /// (rate-aggregated).
    pub fn gate(
        &self,
        device: &DeviceId,
        requested_suite: u8,
        supported_suites: &[u8],
    ) -> Result<GateOk, Reject> {
        let mut st = self.store.state();
        let (now, hwm) = self.store.wall_locked(&mut st);
        let mono = self.store.clock().mono();
        let loaded = st.status == StoreStatus::Loaded;
        // the running deadline, or the persisted picture on an offline handle
        let lock_remaining_s = GrantStore::lock_remaining_locked(&st, device, now, mono);
        let (enabled, last_seen) = st.store.as_ref().map_or((false, 0), |s| {
            (s.active_at(now), s.last_seen_unix.max(hwm))
        });
        let result = {
            let grant = st.store.as_ref().and_then(|s| s.grant(device));
            gate(
                &GateView {
                    loaded,
                    enabled,
                    grant,
                    last_seen,
                    requested_suite,
                    supported_suites,
                    lock_remaining_s,
                },
                now,
            )
        };
        if loaded && now < last_seen {
            self.store.note_anomaly_locked(&mut st, now, mono);
        }
        result
    }

    /// Charge the grant (write-ahead, fsynced): `consecutive += 1`, `since_unlock += 1`,
    /// `pending = true`, lock armed for the new `n`, hard lock when `n ==
    /// hard_lock_after` (`0` disables only the consecutive hard lock) or `since_unlock ≥
    /// 60`. `Ok` means the record is on disk — only then may KE2 be written.
    ///
    /// The pre-PAKE gate is re-evaluated here under the store lock with the grant's own
    /// suite (the requested suite is fixed per stream and was checked by [`Self::gate`]):
    /// a suspend, disable, revoke, pause, master off, expiry or clock rollback that
    /// landed after the caller's `gate` is answered with [`LimiterError::Refused`] /
    /// [`LimiterError::Locked`] and nothing is charged or logged (§B.8.16).
    pub fn charge(&self, device: &DeviceId) -> Result<Charged, LimiterError> {
        let mut st = self.store.state();
        let (now, hwm) = self.store.wall_locked(&mut st);
        let mono = self.store.clock().mono();
        if st.status != StoreStatus::Loaded {
            return Err(LimiterError::NotLoaded);
        }
        if st.mode == LoadMode::Offline {
            return Err(LimiterError::Offline);
        }
        // The gate, re-run under this very lock.
        let recheck = {
            let store = st.store.as_ref().ok_or(LimiterError::NotLoaded)?;
            let g = store.grant(device).ok_or(LimiterError::NoGrant)?;
            let lock_remaining_s = GrantStore::lock_remaining_locked(&st, device, now, mono);
            let last_seen = store.last_seen_unix.max(hwm);
            let view = GateView {
                loaded: true,
                enabled: store.active_at(now),
                grant: Some(g),
                last_seen,
                requested_suite: g.suite,
                supported_suites: &[g.suite],
                lock_remaining_s,
            };
            (gate(&view, now), now < last_seen)
        };
        match recheck {
            (Ok(_), _) => {}
            (Err(reject), rollback) => {
                if rollback {
                    self.store.note_anomaly_locked(&mut st, now, mono);
                }
                return Err(match reject {
                    Reject::LockedOut { .. } | Reject::HardLocked => LimiterError::Locked(reject),
                    other => LimiterError::Refused(other),
                });
            }
        }
        let before = st.store.clone();
        let before_rt = st.runtime.get(device).copied();
        let (charged, events) = {
            let super::store::State { store, runtime, .. } = &mut *st;
            let store = store.as_mut().ok_or(LimiterError::NotLoaded)?;
            let g = store.grant_mut(device).ok_or(LimiterError::NoGrant)?;
            let rt = runtime.entry(*device).or_insert(RuntimeFail {
                decay_twin: mono,
                lifetime_twin: mono,
                ..RuntimeFail::default()
            });
            if g.fail.pending {
                return Err(LimiterError::AlreadyPending);
            }
            decay_runtime(&mut g.fail, rt, mono);
            g.fail.consecutive = g.fail.consecutive.saturating_add(1);
            g.fail.since_unlock = g.fail.since_unlock.saturating_add(1);
            g.fail.pending = true;
            g.fail.decay_anchor = g.fail.decay_anchor.max(now);
            rt.decay_credit = 0;
            rt.decay_twin = mono;
            let n = g.fail.consecutive;
            let lock = ladder_lock_secs(n);
            rt.locked_until = (lock > 0).then(|| lock_deadline(mono, u64::from(lock)));
            g.fail.lock_remaining_s = lock;
            let arm = !g.fail.hard_locked
                && ((g.hard_lock_after > 0 && n >= g.hard_lock_after)
                    || g.fail.since_unlock >= LIFETIME_BUDGET);
            if arm {
                g.fail.hard_locked = true;
            }
            rt.armed_hard_lock = arm;
            let charged = Charged {
                grant_id: g.id,
                consecutive: n,
                since_unlock: g.fail.since_unlock,
                lock_secs: lock,
                hard_lock_armed: arm,
            };
            let mut events = vec![
                SessionRecord::at(now, SessionEvent::UnattendedChallengeIssued)
                    .device(*device)
                    .grant(&g.id)
                    .failures(n)
                    .lock_secs(lock)
                    .unattended(true),
            ];
            if arm {
                events.push(
                    SessionRecord::at(now, SessionEvent::UnattendedHardLock)
                        .device(*device)
                        .grant(&g.id)
                        .failures(n)
                        .unattended(true)
                        .reason(if n >= g.hard_lock_after && g.hard_lock_after > 0 {
                            "consecutive"
                        } else {
                            "lifetime"
                        }),
                );
            }
            (charged, events)
        };
        let persisted = events
            .iter()
            .try_for_each(|e| self.store.log_locked(&mut st, e))
            .and_then(|()| self.store.write_locked(&mut st, WriteClass::Runtime));
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
            return Err(LimiterError::Store(e));
        }
        Ok(charged)
    }

    /// Settle the pending charge. `Ok`: revert the own charge, snapshot the
    /// [`FailSummary`] (`None` when zero prior failures), reset `consecutive`, clear the
    /// lock (and the hard lock this very charge armed while `since_unlock < 60`), set
    /// `last_used`, auto-renew the expiry. `Fail`: `pending = false`, counters kept,
    /// both anchors `:= max(stored, now)`.
    pub fn settle(
        &self,
        device: &DeviceId,
        outcome: Settle,
    ) -> Result<Option<FailSummary>, LimiterError> {
        let mut st = self.store.state();
        let (now, _) = self.store.wall_locked(&mut st);
        let mono = self.store.clock().mono();
        if st.status != StoreStatus::Loaded {
            return Err(LimiterError::NotLoaded);
        }
        if st.mode == LoadMode::Offline {
            return Err(LimiterError::Offline);
        }
        let before = st.store.clone();
        let before_rt = st.runtime.get(device).copied();
        let (summary, event) = {
            let super::store::State { store, runtime, .. } = &mut *st;
            let store = store.as_mut().ok_or(LimiterError::NotLoaded)?;
            let g = store.grant_mut(device).ok_or(LimiterError::NoGrant)?;
            let rt = runtime.entry(*device).or_insert(RuntimeFail {
                decay_twin: mono,
                lifetime_twin: mono,
                ..RuntimeFail::default()
            });
            if !g.fail.pending {
                return Err(LimiterError::NotPending);
            }
            match outcome {
                Settle::Ok => {
                    g.fail.consecutive = g.fail.consecutive.saturating_sub(1);
                    g.fail.since_unlock = g.fail.since_unlock.saturating_sub(1);
                    let summary = (g.fail.consecutive > 0).then_some(FailSummary {
                        since_success: g.fail.consecutive,
                        last_fail_at: g.fail.last_fail_at,
                    });
                    g.fail.consecutive = 0;
                    g.fail.pending = false;
                    g.fail.lock_remaining_s = 0;
                    rt.locked_until = None;
                    let cleared_hard = rt.armed_hard_lock && g.fail.since_unlock < LIFETIME_BUDGET;
                    if cleared_hard {
                        g.fail.hard_locked = false;
                    }
                    rt.armed_hard_lock = false;
                    let transport = g.last_used.map_or(TransportKind::TorRelay, |l| l.transport);
                    g.last_used = Some(LastUsed {
                        at: now,
                        transport,
                        duration_secs: 0,
                    });
                    if g.auto_renew
                        && let (Some(exp), Some(span)) = (g.expires_at, g.renew_span_s())
                    {
                        g.expires_at = Some(exp.max(now.saturating_add(span)));
                    }
                    let mut ev = SessionRecord::at(now, SessionEvent::UnattendedAuthSucceeded)
                        .device(*device)
                        .grant(&g.id)
                        .unattended(true)
                        .failures(summary.map_or(0, |s| s.since_success));
                    if cleared_hard {
                        ev = ev
                            .detail("hard lock cleared by the success of the charge that armed it");
                    }
                    (summary, ev)
                }
                Settle::Fail(kind) => {
                    g.fail.pending = false;
                    g.fail.last_fail_at = Some(g.fail.last_fail_at.unwrap_or(0).max(now));
                    g.fail.decay_anchor = g.fail.decay_anchor.max(now);
                    g.fail.lifetime_decay_anchor = g.fail.lifetime_decay_anchor.max(now);
                    rt.decay_credit = 0;
                    rt.lifetime_credit = 0;
                    rt.decay_twin = mono;
                    rt.lifetime_twin = mono;
                    rt.armed_hard_lock = false;
                    let lock = rt.locked_until.map_or(0, |u| remaining_secs(u, mono));
                    let ev = SessionRecord::at(now, SessionEvent::UnattendedAuthFailed)
                        .device(*device)
                        .grant(&g.id)
                        .unattended(true)
                        .failures(g.fail.consecutive)
                        .lock_secs(lock)
                        .reason(kind.log_name());
                    (None, ev)
                }
            }
        };
        let persisted = self
            .store
            .log_locked(&mut st, &event)
            .and_then(|()| self.store.write_locked(&mut st, WriteClass::Runtime));
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
            return Err(LimiterError::Store(e));
        }
        Ok(summary)
    }

    /// Post-F2 policy for `device` at the current clock; a runtime rollback below the
    /// persisted `last_seen` *or* below any earlier reading is `NOT_YET_ACTIVE` and
    /// logged. The master switch and a pause are re-read under the lock too: a
    /// `master_off` / `pause` / emergency stop that landed during the 1–3 s PAKE window
    /// is answered `NOT_GRANTED` here, not only by the ≤ 1 s session kill.
    pub fn post_f2(
        &self,
        device: &DeviceId,
        tz: &dyn LocalTz,
        host: HostTransport,
    ) -> Result<PostF2Ok, PostF2Reject> {
        let mut st = self.store.state();
        let (now, hwm) = self.store.wall_locked(&mut st);
        let mono = self.store.clock().mono();
        let (grant, last_seen, enabled) = {
            let store = st.store.as_ref().ok_or(PostF2Reject::NotGranted)?;
            let grant = store.grant(device).ok_or(PostF2Reject::NotGranted)?.clone();
            (grant, store.last_seen_unix.max(hwm), store.active_at(now))
        };
        if now < last_seen {
            self.store.note_anomaly_locked(&mut st, now, mono);
        }
        drop(st);
        if !enabled {
            return Err(PostF2Reject::NotGranted);
        }
        post_f2(&grant, now, last_seen, tz, host)
    }
}

/// The host's privacy configuration that shapes the signed transport policy (§B.8.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostTransport {
    /// *Paranoid* privacy mode: media over Tor only, host-wide.
    pub paranoid: bool,
    /// LAN-only mode: link-local candidates only, no Tor media fallback.
    pub lan_only: bool,
}

/// Post-F2 refusal (§B.8.4.6, password already proven).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostF2Reject {
    /// The grant vanished, expired or was disabled between the gate and F2.
    NotGranted,
    /// A clock rollback (`now < last_seen`): fail closed (`NOT_YET_ACTIVE`).
    NotYetActive {
        /// `last_seen − now`.
        next_open_in_s: u32,
    },
    /// Schedule closed.
    OutsideSchedule {
        /// Seconds until the next window, if one opens within 8 days.
        next_open_in_s: Option<u32>,
    },
    /// The grant requires Tor-only media but the host is LAN-only (§B.8.11): neither
    /// policy can be signed without breaking the other's promise.
    TransportUnavailable,
    /// Reconnect cooldown after `max_session_secs`.
    Cooldown {
        /// Seconds to wait.
        retry_after_s: u32,
    },
}

impl PostF2Reject {
    /// The `SESSION_REJECT.reason` code.
    #[must_use]
    pub fn code(&self) -> u16 {
        match self {
            Self::NotGranted => reject_codes::NOT_GRANTED,
            Self::NotYetActive { .. } => reject_codes::NOT_YET_ACTIVE,
            Self::OutsideSchedule { .. } => reject_codes::OUTSIDE_SCHEDULE,
            Self::TransportUnavailable => reject_codes::TRANSPORT_UNAVAILABLE,
            Self::Cooldown { .. } => reject_codes::COOLDOWN,
        }
    }
}

/// What the post-F2 checks computed for the `PolicyReceipt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostF2Ok {
    /// `SESSION_ACCEPT.ends_at`: the earliest of schedule end, expiry and `now + max_session_secs`.
    pub ends_at: Option<u64>,
    /// The transport policy to sign into `SESSION_ACCEPT` (§B.8.6.4, §B.8.11).
    pub transport: TransportPolicy,
}

/// The post-F2 policy checks in order: expiry / state (`NOT_GRANTED`), rollback
/// (`NOT_YET_ACTIVE`), schedule (`OUTSIDE_SCHEDULE`), transport conflict
/// (`TRANSPORT_UNAVAILABLE`), reconnect cooldown (`COOLDOWN`). The host-wide master
/// switch / pause is the caller's ([`AttemptLimiter::post_f2`] reads it under the lock).
pub fn post_f2(
    grant: &UnattendedGrant,
    now: u64,
    last_seen: u64,
    tz: &dyn LocalTz,
    host: HostTransport,
) -> Result<PostF2Ok, PostF2Reject> {
    if grant.expired_at(now) || grant.state != GrantState::Active {
        return Err(PostF2Reject::NotGranted);
    }
    if now < last_seen {
        return Err(PostF2Reject::NotYetActive {
            next_open_in_s: u32::try_from(last_seen - now).unwrap_or(u32::MAX),
        });
    }
    if schedule::outside_schedule(grant, now, tz) {
        return Err(PostF2Reject::OutsideSchedule {
            next_open_in_s: schedule::next_open_in_s(grant, now, tz),
        });
    }
    let transport = grant
        .transport_policy(host.paranoid, host.lan_only)
        .map_err(|_| PostF2Reject::TransportUnavailable)?;
    if let Some(retry_after_s) = reconnect_cooldown(grant, now) {
        return Err(PostF2Reject::Cooldown { retry_after_s });
    }
    Ok(PostF2Ok {
        ends_at: ends_at(grant, now, tz),
        transport,
    })
}

/// `mono + secs` as a lock deadline; an overflowing sum (fuzzed clocks, F3) is a lock
/// that never expires rather than a panic.
pub(crate) fn lock_deadline(mono: Duration, secs: u64) -> Duration {
    mono.checked_add(Duration::from_secs(secs))
        .unwrap_or(Duration::MAX)
}

/// `SESSION_ACCEPT.ends_at`: the earliest of the current schedule window's end, the
/// expiry and `now + max_session_secs` (`None` when none applies).
#[must_use]
pub fn ends_at(grant: &UnattendedGrant, now: u64, tz: &dyn LocalTz) -> Option<u64> {
    let mut end: Option<u64> = None;
    let mut consider = |t: Option<u64>| {
        if let Some(t) = t {
            end = Some(end.map_or(t, |e| e.min(t)));
        }
    };
    if let Some(ws) = &grant.schedule {
        consider(schedule::current_end(ws, now, tz));
    }
    consider(grant.expires_at);
    consider(
        grant
            .max_session_secs
            .map(|m| now.saturating_add(u64::from(m))),
    );
    end
}

/// The reconnect cooldown (§B.8.6.4): after a session that ran the full
/// `max_session_secs`, a new session is refused for `reconnect_cooldown_s`.
#[must_use]
pub fn reconnect_cooldown(grant: &UnattendedGrant, now: u64) -> Option<u32> {
    let max = grant.max_session_secs?;
    let last = grant.last_used?;
    if grant.reconnect_cooldown_s == 0 || last.duration_secs < max {
        return None;
    }
    let ended = last.at.saturating_add(u64::from(last.duration_secs));
    let until = ended.saturating_add(u64::from(grant.reconnect_cooldown_s));
    (now < until).then(|| u32::try_from(until - now).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_matches_the_table() {
        assert_eq!(ladder_lock_secs(1), 0);
        assert_eq!(ladder_lock_secs(2), 0);
        assert_eq!(ladder_lock_secs(3), 10);
        assert_eq!(ladder_lock_secs(4), 30);
        assert_eq!(ladder_lock_secs(5), 60);
        assert_eq!(ladder_lock_secs(6), 120);
        assert_eq!(ladder_lock_secs(7), 300);
        assert_eq!(ladder_lock_secs(8), 900);
        assert_eq!(ladder_lock_secs(9), 1800);
        assert_eq!(ladder_lock_secs(10), 3600);
        assert_eq!(ladder_lock_secs(19), 3600);
        assert_eq!(round_up_10(1), 10);
        assert_eq!(round_up_10(10), 10);
        assert_eq!(round_up_10(11), 20);
        assert_eq!(round_up_10(0), 0);
    }

    #[test]
    fn lock_deadline_saturates_instead_of_overflowing() {
        assert_eq!(
            lock_deadline(Duration::from_secs(5), 10),
            Duration::from_secs(15)
        );
        assert_eq!(lock_deadline(Duration::MAX, 1), Duration::MAX);
        assert_eq!(
            lock_deadline(Duration::from_secs(1), u64::MAX),
            Duration::MAX
        );
        assert_eq!(
            remaining_secs(Duration::MAX, Duration::from_secs(7)),
            u32::MAX
        );
    }

    proptest::proptest! {
        /// F3 companion: the runtime decay is total over the whole input space and never
        /// lowers an anchor or raises a counter.
        #[test]
        fn decay_runtime_is_total_and_monotone(
            consecutive in proptest::prelude::any::<u32>(),
            since_unlock in proptest::prelude::any::<u32>(),
            decay_anchor in proptest::prelude::any::<u64>(),
            lifetime_decay_anchor in proptest::prelude::any::<u64>(),
            twin_secs in proptest::prelude::any::<u64>(),
            credit in proptest::prelude::any::<u64>(),
            lifetime_credit in proptest::prelude::any::<u64>(),
            mono_secs in proptest::prelude::any::<u64>(),
            mono_nanos in 0u32..1_000_000_000,
        ) {
            let mut f = FailState {
                consecutive,
                since_unlock,
                decay_anchor,
                lifetime_decay_anchor,
                ..FailState::default()
            };
            let mut rt = RuntimeFail {
                decay_twin: Duration::from_secs(twin_secs),
                lifetime_twin: Duration::from_secs(twin_secs),
                decay_credit: credit,
                lifetime_credit,
                ..RuntimeFail::default()
            };
            let before = f;
            decay_runtime(&mut f, &mut rt, Duration::new(mono_secs, mono_nanos));
            proptest::prop_assert!(f.consecutive <= before.consecutive);
            proptest::prop_assert!(f.since_unlock <= before.since_unlock);
            proptest::prop_assert!(f.decay_anchor >= before.decay_anchor);
            proptest::prop_assert!(f.lifetime_decay_anchor >= before.lifetime_decay_anchor);
            proptest::prop_assert!(rt.decay_credit < DECAY_PERIOD_S || rt.decay_credit == credit);
            proptest::prop_assert!(
                rt.lifetime_credit < LIFETIME_DECAY_PERIOD_S || rt.lifetime_credit == lifetime_credit
            );
        }
    }
}
