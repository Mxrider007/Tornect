//! The store read after a session's reservation (decision M1-67, `docs/PLAN.md`
//! §B.8.4.1 and §B.8.6.1): one store operation, under the store lock, that checks the
//! `auth` record the stream's PAKE ran against, refuses a grant no longer eligible, reads
//! the "answered 0" mark and whether some grant holds the administrator level, computes
//! `grant_reach` and the grant mode and level the clamp uses, and marks the password
//! before an answer of 0. It only ever lowers the session the gate minted; the account
//! facts and the helper task's presence are read by the caller just before, outside the
//! store lock.
//!
//! Its refusals are returned unlogged, for the caller to log once the lock is dropped, and
//! it writes no `sessions.log` line under the lock: the mark is a policy write without
//! one (`log_event` takes the same mutex).

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::id::DeviceId;
use crate::levels::{AccountFacts, Elevation, HelperPresence, clause_ii};
use crate::session_log::SessionMode;

use super::grant::{AuthRecord, GrantState, UnattendedGrant, UnattendedStore};
use super::store::{GrantStore, StoreError, StoreStatus, WriteClass};

/// SHA-256 of a grant's stored `auth` record as the store encodes it: what a session's
/// receipt keeps of the record its PAKE ran against (B step 1). Never logged, sent or
/// printed.
#[must_use]
pub fn auth_digest(auth: &AuthRecord) -> [u8; 32] {
    // The encoding holds the PAKE record: sized before it is filled and wiped after.
    let mut bytes = Zeroizing::new(Vec::with_capacity(512));
    if minicbor::encode(auth, &mut *bytes).is_err() {
        // Never: a `Vec` takes every byte. An empty encoding matches no stored record.
        bytes.clear();
    }
    Sha256::digest(bytes.as_slice()).into()
}

/// The three clauses of `grant_reach` for one grant (§B.8.4.1), read from the store.
struct Clauses {
    /// (i) the grant holds the level (never on Linux, where the level does not exist).
    holds: bool,
    /// (ii) control reaches the level through the host.
    reach_through_host: bool,
    /// (iii) the grant's password is marked "answered 0".
    marked: bool,
}

impl Clauses {
    fn of(
        store: &UnattendedStore,
        grant: &UnattendedGrant,
        account: AccountFacts,
        helper_task: HelperPresence,
    ) -> Self {
        let some_grant_holds_level = store.grants.iter().any(UnattendedGrant::holds_level);
        Self {
            holds: account != AccountFacts::Linux && grant.holds_level(),
            reach_through_host: clause_ii(grant.mode, some_grant_holds_level, account, helper_task),
            marked: grant.marked(),
        }
    }

    /// 2 for (i) without (iii); else 1 for (ii), or (i) with (iii); else 0.
    fn grant_reach(&self) -> u8 {
        if self.holds && !self.marked {
            2
        } else if self.reach_through_host || self.holds {
            1
        } else {
            0
        }
    }
}

/// `grant_reach` of `grant` as `store` holds it, on `account` and `helper_task` (§B.8.4.1;
/// decision M1-67): what every `ADMIN_RESULT` carries, from the requester's grant as
/// loaded under the lock of the command. Always 0 on Linux.
pub(crate) fn grant_reach_of(
    store: &UnattendedStore,
    grant: &UnattendedGrant,
    account: AccountFacts,
    helper_task: HelperPresence,
) -> u8 {
    Clauses::of(store, grant, account, helper_task).grant_reach()
}

/// A grant's own reach as the guard judges a change to it (decision M1-67, D3): 2 when
/// it holds the level, 1 when it is control and clause (ii) holds, else 0, the mark
/// aside; 0 on Linux. `grant` counts among the grants that hold the level in place of
/// the store's copy of it (a grant not stored yet included).
pub(crate) fn own_reach(
    store: &UnattendedStore,
    grant: &UnattendedGrant,
    account: AccountFacts,
    helper_task: HelperPresence,
) -> u8 {
    if account == AccountFacts::Linux {
        return 0;
    }
    if grant.holds_level() {
        return 2;
    }
    let others = store
        .grants
        .iter()
        .any(|g| g.device != grant.device && g.holds_level());
    u8::from(clause_ii(grant.mode, others, account, helper_task))
}

/// Why the read refuses the request (B step 1, D11). Nothing is marked on any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachRefusal {
    /// The grant's `auth` record is not the one this stream's PAKE ran against: its
    /// password was replaced since (`AUTH_FAILED`, so the client deletes it as stale).
    AuthReplaced,
    /// The grant is gone, or no longer eligible since the gate: unattended access off or
    /// paused, not `Active`, expired, not yet active, `Pruned` or hard-locked
    /// (`NOT_GRANTED`).
    NotEligible,
    /// The mark could not be written before an answer of 0 (`NOT_GRANTED`, as a post-F2
    /// store failure is): nothing is signed at 0.
    MarkNotWritten,
}

/// What the read gives the accept (B steps 2 and 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReachRead {
    /// The `grant_reach` to sign: 0, 1 or 2 (§B.8.4.1). Always 0 on Linux.
    pub grant_reach: u8,
    /// The grant level the clamp uses (D2): the grant's own level (store key 24), none
    /// while its password is marked and where the level does not exist (Linux).
    pub grant_level: Elevation,
    /// The grant's password is marked "answered 0", as stored after this read.
    pub marked: bool,
    /// Clause (ii) holds for the grant: with the mark, the session is View only (D11).
    pub clause_ii: bool,
    /// The grant's mode as stored now, which clause (ii) is judged on: the session is
    /// never served above it (B: a grant lowered since the gate is clamped there).
    pub grant_mode: SessionMode,
}

/// B steps 1 to 4 for the session `device` asked for, whose PAKE ran against the record
/// with SHA-256 `auth_digest` ([`auth_digest`] of the gate's clone), on `account` and
/// `helper_task` read just before, outside the store lock. Under the store lock: the grant
/// re-loaded and refused when gone or no longer eligible ([`ReachRefusal::NotEligible`])
/// or when its `auth` record is another ([`ReachRefusal::AuthReplaced`]); the mark and
/// whether some grant holds the level read; `grant_reach` computed from clause (i) (the
/// grant holds the level), clause (ii) and the mark; and, before an answer of 0, the
/// grant marked in a policy write, refused when that write fails
/// ([`ReachRefusal::MarkNotWritten`]). The caller lowers the session to what this returns,
/// never raises it.
pub fn read_after_reservation(
    store: &GrantStore,
    device: &DeviceId,
    auth_digest: &[u8; 32],
    account: AccountFacts,
    helper_task: HelperPresence,
) -> Result<ReachRead, ReachRefusal> {
    let mut st = store.state();
    if st.status != StoreStatus::Loaded {
        return Err(ReachRefusal::NotEligible);
    }
    let (now, _) = store.wall_locked(&mut st);
    let Some(s) = st.store.as_ref() else {
        return Err(ReachRefusal::NotEligible);
    };
    // Step 1: the grant as stored now, eligible as the gate found it (the admin path's
    // own set), then the `auth` record the PAKE proved.
    let Some(grant) = s.grant(device) else {
        return Err(ReachRefusal::NotEligible);
    };
    let eligible = s.active_at(now)
        && grant.state == GrantState::Active
        && !grant.expired_at(now)
        && grant.auth != AuthRecord::Pruned
        && now >= grant.active_from
        && !grant.fail.hard_locked;
    if !eligible {
        return Err(ReachRefusal::NotEligible);
    }
    let proven = self::auth_digest(&grant.auth);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&proven[..], &auth_digest[..])) {
        return Err(ReachRefusal::AuthReplaced);
    }
    // Steps 2 and 3: the mark, whether some grant holds the level, the three clauses.
    let clauses = Clauses::of(s, grant, account, helper_task);
    let grant_mode = grant.mode;
    let (marked, reach_through_host) = (clauses.marked, clauses.reach_through_host);
    let grant_reach = clauses.grant_reach();
    let grant_level = if clauses.holds && !marked {
        Elevation::Admin
    } else {
        Elevation::None
    };
    // Step 4: an answer of 0 is signed only once its password is marked, durably.
    if grant_reach == 0 && !marked {
        store
            .mutate_locked(&mut st, WriteClass::Policy, None, |s, _| {
                let g = s.grant_mut(device).ok_or(StoreError::NoGrant)?;
                g.unmarked = false;
                Ok(())
            })
            .map_err(|_| ReachRefusal::MarkNotWritten)?;
    }
    Ok(ReachRead {
        grant_reach,
        grant_level,
        marked: marked || grant_reach == 0,
        clause_ii: reach_through_host,
        grant_mode,
    })
}
