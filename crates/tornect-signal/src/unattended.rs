//! The unattended branch of the host FSM (`docs/PLAN.md` §B.8.4.5).
//!
//! [`UnattendedAuth`] is the real [`UnattendedHook`]: it replaces the M1
//! `NOT_GRANTED` stub with the full `HelloVerified → SESSION_REQUEST{unattended}`
//! path — the pre-PAKE gate, the write-ahead charge, the OPAQUE exchange, the
//! settlement, the post-F2 policy checks, the readiness gate, the
//! `ask_before_start` popup and the block window — and mints the
//! [`ConsentProof::Unattended`] that is the only way to reach `SESSION_ACCEPT`.
//!
//! Ordering is not a stylistic choice here. The §B.8.4.5 table fixes it:
//! everything that may be disclosed to a mere key holder happens *before* the
//! PAKE and is uncharged; everything that depends on the password being proven
//! happens *after* F2. Reordering the two leaks grant policy to anyone who can
//! reach the onion service.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use tokio::sync::Notify;
use tornect_core::id::DeviceId;
use tornect_core::levels::{AccountFacts, Elevation, FactsSource, Level, clause_ii, served_mode};
use tornect_core::session_log::SessionMode;
use tornect_core::unattended::grant::{AuthRecord, GrantId, UnattendedGrant};
use tornect_core::unattended::guard::{
    AdminAnswer, AdminEffect, AdminError, AdminOp, AdminOutcome, MutationGuard,
};
use tornect_core::unattended::limiter::{
    AttemptLimiter, FailKind, HostTransport, LimiterError, PostF2Reject, Reject, Settle,
};
use tornect_core::unattended::reach::{self, ReachRefusal};
use tornect_core::unattended::readiness::{Probe, ReadinessSnapshot, SharedReadiness};
use tornect_core::unattended::schedule::LocalTz;
use tornect_core::unattended::store::GrantStore;

use crate::auth;
use crate::consent::{
    BlockOutcome, ChosenCaps, ConsentProof, DerivedToken, PolicyReceipt, TransportPolicy,
};
use crate::fsm::host::{
    KillSwitch, StopTokenCheck, UnattendedContext, UnattendedHook, UnattendedVerdict,
};
use crate::fsm::{AuditEvent, HandshakeError, SuppressedPopup};
use crate::messages::{self, AuthChallenge, SessionReject, bye, intent, mode, reject};

/// Suites this build speaks (§B.8.4.2). Suite 2 (SPAKE2) is specified but not
/// compiled in at M1, so a request for it is `UNSUPPORTED_SUITE`.
pub const SUPPORTED_SUITES: &[u8] = &[auth::SUITE_OPAQUE];

/// §B.8.5.2 host-wide budgets. These are **never** a lock and never touch
/// attended sessions: two burned devices must not block a third device's login,
/// so there is no global breaker here, only concurrency and rate caps.
mod budget {
    /// Charged `AwaitKe3` handshakes in flight, host-wide.
    pub const MAX_IN_FLIGHT: usize = 4;
    /// `AUTH_CHALLENGE` frames per minute, host-wide.
    pub const MAX_PER_MINUTE: usize = 10;
    /// A hard-locked grant's pk is answered at most once per minute.
    pub const HARD_LOCK_QUIET_S: u64 = 60;
}

/// A one-way flag a task can wait on. Level-triggered: once set it stays set, so
/// a waiter that starts after [`Latch::set`] returns at once. A bare
/// `Notify::notify_waiters` wakes only the waiters already registered, and a
/// pre-emption that landed between the charge and the first poll of the
/// `AwaitKe3` race was lost (the stale handshake then ran its full 30 s).
#[derive(Debug, Default)]
struct Latch {
    set: AtomicBool,
    notify: Notify,
}

impl Latch {
    fn set(&self) {
        self.set.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn is_set(&self) -> bool {
        self.set.load(Ordering::SeqCst)
    }

    /// Resolves once [`Self::set`] was called, before or after this call.
    async fn wait(&self) {
        loop {
            let mut notified = std::pin::pin!(self.notify.notified());
            // Registered before the flag is read: a `set` between the read and
            // the await still wakes this waiter.
            notified.as_mut().enable();
            if self.is_set() {
                return;
            }
            notified.await;
        }
    }
}

/// How long a pre-empting stream waits for the stale handshake's charge to be
/// settled before it charges its own (§B.8.4.5). The stale one settles as soon
/// as it runs again; past this bound the newer one is answered `UA_BUSY`.
const PREEMPT_SETTLE: Duration = Duration::from_secs(5);

/// One device's in-flight `AwaitKe3` handshake, as the budget table sees it.
#[derive(Debug)]
struct Slot {
    /// Set when a newer, freshly signed `SESSION_REQUEST` pre-empts this
    /// handshake (§B.8.4.5).
    cancel: Arc<Latch>,
    /// Set once the charge is on disk and KE2 is about to go out. Until then the
    /// stream is "between F1 and KE2 written" and a newer one is answered
    /// `UA_BUSY` instead of pre-empting it (§B.8.4.5).
    charged: Arc<AtomicBool>,
    /// Set once this handshake's charge is settled, or once its handler is gone:
    /// what a pre-empting stream waits for before it charges. The limiter takes
    /// one charge per device at a time, so a charge on top of this one's would
    /// be refused.
    settled: Arc<Latch>,
    /// When the slot was taken.
    since: Instant,
}

/// The host-wide budget counters of §B.8.5.2.
#[derive(Debug, Default)]
struct Budgets {
    /// Devices with a charged `AwaitKe3` handshake in flight (≤ 1 per pk).
    in_flight: HashMap<DeviceId, Slot>,
    /// `AUTH_CHALLENGE` timestamps inside the trailing minute.
    challenges: Vec<Instant>,
    /// Last time a hard-locked pk was answered at all.
    hard_locked_answered: HashMap<DeviceId, Instant>,
}

impl Budgets {
    /// Drop entries that have aged out of the trailing minute.
    fn expire(&mut self, now: Instant) {
        self.challenges
            .retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        // Safety net, not the primary release path: `InFlight::drop` clears a slot
        // as soon as its handler leaves `AwaitKe3`. If a handler is ever lost
        // (a detached task that panics), a stale entry would otherwise pin that
        // device out for good. `AwaitKe3` is 30 s, so anything twice that old is
        // certainly dead.
        self.in_flight
            .retain(|_, slot| now.duration_since(slot.since) < STALE_SLOT);
        self.hard_locked_answered
            .retain(|_, t| now.duration_since(*t) < Duration::from_secs(budget::HARD_LOCK_QUIET_S));
    }
}

/// An in-flight entry older than this is treated as leaked (`AwaitKe3` is 30 s).
const STALE_SLOT: Duration = Duration::from_secs(60);

/// A charged in-flight slot; releases itself on drop so every early return,
/// `?` and panic unwinds the host-wide counter (§B.8.5.2).
///
/// Held only for the `AwaitKe3` phase: §B.8.5.2 counts "charged `AwaitKe3`
/// streams only", so the caller drops it right after `settle`. A session sitting
/// in its `ask_before_start` popup or block window must not occupy one of the
/// four host-wide slots.
struct InFlight {
    device: DeviceId,
    budgets: Arc<Mutex<Budgets>>,
    limiter: AttemptLimiter,
    cancel: Arc<Latch>,
    charged: Arc<AtomicBool>,
    settled: Arc<Latch>,
}

impl InFlight {
    /// The charge is on disk; from here a newer request may pre-empt this stream.
    fn mark_charged(&self) {
        self.charged.store(true, Ordering::SeqCst);
    }

    /// Settle this handshake's charge, then let a pre-empting stream charge.
    fn settle(
        &self,
        outcome: Settle,
    ) -> Result<Option<tornect_core::unattended::grant::FailSummary>, LimiterError> {
        let settled = self.limiter.settle(&self.device, outcome);
        self.settled.set();
        settled
    }

    /// Resolves when a newer, freshly signed `SESSION_REQUEST` pre-empts us,
    /// also when that happened before this call.
    async fn cancelled(&self) {
        self.cancel.wait().await;
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        // A handler that goes away charged and unsettled (its task cancelled or
        // unwinding in `AwaitKe3`) settles here as a lost stream; left pending,
        // the charge would refuse every request of this device until the next
        // load settles it (§B.8.5.1).
        if self.charged.load(Ordering::SeqCst)
            && !self.settled.is_set()
            && let Err(e) = self
                .limiter
                .settle(&self.device, Settle::Fail(FailKind::Disconnected))
        {
            tracing::warn!(peer = ?self.device, error = %e, "an abandoned handshake's charge could not be settled");
        }
        self.settled.set();
        if let Ok(mut b) = self.budgets.lock() {
            // Only clear the entry if it is still ours: a pre-empting stream has
            // already installed its own.
            if b.in_flight
                .get(&self.device)
                .is_some_and(|s| Arc::ptr_eq(&s.cancel, &self.cancel))
            {
                b.in_flight.remove(&self.device);
            }
        }
    }
}

/// What the budget check decided.
enum Admit {
    /// Proceed; hold `slot` until the handshake ends. `preempted` is the stale
    /// handshake this request cancelled: its charge must be settled before
    /// this one charges.
    Ok {
        slot: InFlight,
        preempted: Option<Arc<Latch>>,
    },
    /// Answer `UA_BUSY`.
    Busy,
    /// Answer nothing at all and close: a hard-locked pk already answered
    /// inside this minute (§B.8.5.2 — no frame, nothing charged).
    Silent,
}

/// Executes a remote `AdminCmd` (§B.8.4.1) on behalf of an authenticated
/// requester.
///
/// The scope matrix itself lives in [`MutationGuard::admin`] — it is a store
/// mutation and belongs with the other ones, next to the log lines it writes.
/// This trait exists so the signalling layer can be exercised without a real
/// store, and so that a host wired without an authority **refuses** admin
/// commands rather than silently pretending to have run them.
pub trait AdminAuthority: Send + Sync {
    /// Run `op` for `requester`, whose PAKE ran against the stored `auth` record with
    /// SHA-256 `auth_digest`, or refuse it (decision M1-67): the outcome with the
    /// requester's `grant_reach` (`None` only from an authority without a store), or a
    /// refusal that answers no `ADMIN_RESULT`.
    fn execute(
        &self,
        requester: &DeviceId,
        auth_digest: &[u8; 32],
        op: AdminOp,
    ) -> Result<(AdminOutcome, Option<u8>), ReachRefusal>;

    /// An admin command refused before it runs (missing, or one this build does not run:
    /// `why`), answered as [`Self::execute`] answers and logged with op `unknown`.
    fn refuse_early(
        &self,
        requester: &DeviceId,
        auth_digest: &[u8; 32],
        why: &str,
    ) -> Result<(AdminOutcome, Option<u8>), ReachRefusal>;
}

/// The default: this host executes no remote admin commands.
///
/// Answering `ok: false` is the honest response — the requester proved its
/// password and is entitled to know its command did not run.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseAdmin;

impl AdminAuthority for RefuseAdmin {
    fn execute(
        &self,
        _: &DeviceId,
        _: &[u8; 32],
        _: AdminOp,
    ) -> Result<(AdminOutcome, Option<u8>), ReachRefusal> {
        Ok((
            AdminOutcome {
                ok: false,
                detail: Some("remote administration is not enabled on this host".to_owned()),
                effect: AdminEffect::None,
            },
            None,
        ))
    }

    fn refuse_early(
        &self,
        _: &DeviceId,
        _: &[u8; 32],
        why: &str,
    ) -> Result<(AdminOutcome, Option<u8>), ReachRefusal> {
        Ok((
            AdminOutcome {
                ok: false,
                detail: Some(why.to_owned()),
                effect: AdminEffect::None,
            },
            None,
        ))
    }
}

/// The real authority: the host's [`MutationGuard`].
///
/// Note what is deliberately *not* here: no re-auth. §B.8.6.2's re-auth rule
/// gates operations performed **at the host**, where a human is present to
/// answer the dialog. A remote admin command has already proven the second
/// factor by completing the PAKE, and there is by definition nobody at the
/// host to type a password — requiring one would make `revoke_all` and
/// `master_off` unusable in exactly the emergency they exist for. The guard's
/// `admin()` path encodes that distinction; it is not an omission.
#[derive(Clone)]
pub struct GuardAdmin {
    guard: Arc<MutationGuard>,
}

impl GuardAdmin {
    /// Wrap the host's guard.
    #[must_use]
    pub fn new(guard: Arc<MutationGuard>) -> Self {
        Self { guard }
    }
}

impl std::fmt::Debug for GuardAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardAdmin").finish_non_exhaustive()
    }
}

impl AdminAuthority for GuardAdmin {
    fn execute(
        &self,
        requester: &DeviceId,
        auth_digest: &[u8; 32],
        op: AdminOp,
    ) -> Result<(AdminOutcome, Option<u8>), ReachRefusal> {
        answered(
            requester,
            op.name(),
            self.guard.admin(requester, auth_digest, op),
        )
    }

    fn refuse_early(
        &self,
        requester: &DeviceId,
        auth_digest: &[u8; 32],
        why: &str,
    ) -> Result<(AdminOutcome, Option<u8>), ReachRefusal> {
        answered(
            requester,
            "unknown",
            self.guard.admin_refused_early(requester, auth_digest, why),
        )
    }
}

/// The guard's admin answer as the gate answers it. A store-level failure (locked
/// keystore, store lock held, I/O) is not a scope refusal: it is reported as a plain
/// failure with the guard's own code, so the client can tell "you may not" from "the
/// host could not". The command took no effect (the guard treats every write after a
/// commit as best-effort), so `AdminEffect::None` is the truth, and the guard logged the
/// attempt as a failed `AdminRequest`.
fn answered(
    requester: &DeviceId,
    op: &str,
    answer: Result<AdminAnswer, AdminError>,
) -> Result<(AdminOutcome, Option<u8>), ReachRefusal> {
    match answer {
        Ok(answer) => Ok((answer.outcome, Some(answer.grant_reach))),
        Err(AdminError::Refused(refusal)) => Err(refusal),
        Err(AdminError::Failed { error, grant_reach }) => {
            tracing::warn!(peer = ?requester, op, error = %error, "admin command failed");
            Ok((
                AdminOutcome {
                    ok: false,
                    detail: Some(format!(
                        "host could not apply the command (0x{:04x})",
                        error.code()
                    )),
                    effect: AdminEffect::None,
                },
                Some(grant_reach),
            ))
        }
    }
}

/// The §B.8.7.4 emergency stop: the [`StopTokenCheck`] that acts.
///
/// A peer presenting the stop token in `HELLO` — paired or not, and **before**
/// any pairing decision — turns unattended access off host-wide, revokes every
/// grant, kills live sessions and clears the token so the code is single-use.
/// The comparison is constant time and the FSM never branches on the result, so
/// the unpaired path stays byte-identical whether a code is enabled or not
/// (A13).
///
/// Phishing is covered by the pk binding, not by this code path: the token a
/// client computes is `SHA-256(.. || dialed_host_onion_pk || stop_code)`, so a
/// code presented to a scam host yields a value useless at the real one
/// (§B.8.7.4).
#[derive(Clone)]
pub struct EmergencyStop {
    guard: Arc<MutationGuard>,
    kill: KillSwitch,
}

impl EmergencyStop {
    /// Wire the stop code to the host's guard and kill switch.
    #[must_use]
    pub fn new(guard: Arc<MutationGuard>, kill: KillSwitch) -> Self {
        Self { guard, kill }
    }
}

impl std::fmt::Debug for EmergencyStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmergencyStop").finish_non_exhaustive()
    }
}

impl StopTokenCheck for EmergencyStop {
    fn observe<'a>(&'a self, token: &'a [u8; 32]) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            // Constant-time inside the store, and `false` for a host with no
            // code enabled without a separate branch.
            if !self.guard.store().stop_token_matches(token) {
                return;
            }
            match self.guard.emergency_stop() {
                Ok(revoked) => {
                    // The one place in the codebase where a `warn!` is the
                    // correct level for a *successful* operation: this is the
                    // user's panic handle and it destroys every grant.
                    tracing::warn!(
                        revoked,
                        "emergency stop code accepted: unattended access off, all grants revoked"
                    );
                    self.kill.kill(bye::EMERGENCY_STOP);
                }
                Err(e) => {
                    // Fail loudly and leave the token in place: a stop that did
                    // not happen must not look like one that did, and the code
                    // must stay usable for the retry.
                    tracing::error!(error = %e, "emergency stop code accepted but NOT applied");
                }
            }
        })
    }
}

/// A condition of the host's readiness beyond the rows of §B.8.14, read at
/// each request (§B.1.1: a window host started in background mode serves no
/// unattended session before its sharing indicator was shown). While it
/// answers `false`, every unattended session is refused `HOST_NOT_READY` with
/// no `cause`.
pub type ReadyGate = Arc<dyn Fn() -> bool + Send + Sync>;

/// The real §B.8 hook.
pub struct UnattendedAuth {
    limiter: AttemptLimiter,
    budgets: Arc<Mutex<Budgets>>,
    tz: Arc<dyn LocalTz>,
    host_transport: HostTransport,
    /// M1: the all-unknown stub (§B.8.14), unless [`Self::readiness_feed`] is set.
    readiness: ReadinessSnapshot,
    /// The host's readiness as last probed (at its start and every 10 min),
    /// read at each request.
    readiness_feed: Option<SharedReadiness>,
    /// The condition of [`Self::with_ready_gate`]; none by default.
    ready_gate: Option<ReadyGate>,
    /// Executes `intent = admin` requests (§B.8.4.1). Refuses by default.
    admin: Arc<dyn AdminAuthority>,
    /// The account facts and the helper task's presence, read at each answer
    /// (decision M1-67).
    facts: Arc<dyn FactsSource>,
    /// What a Block in the block window suspends the grant through (§B.8.6.3:
    /// `Suspended{LocalBlock}`); without it a Block only refuses the request.
    block_guard: Option<Arc<MutationGuard>>,
}

impl UnattendedAuth {
    /// Build the hook over a loaded grant store; `facts` is read at each answer
    /// (decision M1-67): `tornect-platform`'s `LiveFacts` on a host.
    #[must_use]
    pub fn new(
        limiter: AttemptLimiter,
        tz: Arc<dyn LocalTz>,
        host_transport: HostTransport,
        facts: Arc<dyn FactsSource>,
    ) -> Self {
        Self {
            limiter,
            budgets: Arc::new(Mutex::new(Budgets::default())),
            tz,
            host_transport,
            readiness: ReadinessSnapshot::unknown(),
            readiness_feed: None,
            ready_gate: None,
            admin: Arc::new(RefuseAdmin),
            facts,
            block_guard: None,
        }
    }

    /// Override the readiness snapshot (M6 / tests).
    #[must_use]
    pub fn with_readiness(mut self, readiness: ReadinessSnapshot) -> Self {
        self.readiness = readiness;
        self
    }

    /// Read the readiness rows from `feed` at each request: the host probes them
    /// at its start and every 10 min (§B.8.7.1 ⑥).
    #[must_use]
    pub fn with_readiness_feed(mut self, feed: SharedReadiness) -> Self {
        self.readiness_feed = Some(feed);
        self
    }

    /// The readiness rows as of this request.
    fn readiness_now(&self) -> ReadinessSnapshot {
        self.readiness_feed
            .as_ref()
            .map_or_else(|| self.readiness.clone(), SharedReadiness::get)
    }

    /// Refuse every unattended session while `gate` answers `false`, checked
    /// beside the readiness rows, after their causes (§B.1.1): the refusal is
    /// `HOST_NOT_READY` with no `cause`, a form the wire already has.
    #[must_use]
    pub fn with_ready_gate(mut self, gate: ReadyGate) -> Self {
        self.ready_gate = Some(gate);
        self
    }

    /// Wire remote administration (§B.8.4.1) to an authority — normally
    /// [`GuardAdmin`] over the host's `MutationGuard`. Without this call the
    /// host refuses every admin command.
    #[must_use]
    pub fn with_admin_authority(mut self, admin: Arc<dyn AdminAuthority>) -> Self {
        self.admin = admin;
        self
    }

    /// A Block in the block window suspends the grant through `guard`
    /// (§B.8.6.3: `Suspended{LocalBlock}`, until a local *Resume*; a remote
    /// unlock never clears it) as well as refusing the request, and so does the
    /// panic key's kill of a session past its PAKE (§B.8.7.4:
    /// `Suspended{Panic}`). Without this call a Block only refuses, and a panic
    /// only ends.
    #[must_use]
    pub fn with_block_guard(mut self, guard: Arc<MutationGuard>) -> Self {
        self.block_guard = Some(guard);
        self
    }

    /// The block window's Block (§B.8.6.3): the grant of `device` goes to
    /// `Suspended{LocalBlock}` (logged by the guard). The request is refused
    /// whatever this does; a store that cannot take the change is warned about.
    fn blocked(&self, device: &DeviceId) {
        let Some(guard) = &self.block_guard else {
            return;
        };
        if let Err(e) = guard.block(device) {
            tracing::warn!(peer = ?device, error = %e, "a Block could not suspend the grant");
        }
    }

    /// A block window that could not be shown (§B.8.6.3): one `HostNotReady`
    /// line for `device`, through the guard of [`Self::with_block_guard`]; the
    /// grant is left as it was. The request is refused whatever this does.
    fn not_shown(&self, device: &DeviceId) {
        tracing::warn!("the block window could not be shown; the request was refused");
        let Some(guard) = &self.block_guard else {
            return;
        };
        if let Err(e) = guard.block_window_not_shown(device) {
            tracing::warn!(peer = ?device, error = %e, "a block window not shown could not be logged");
        }
    }

    /// §B.8.5.2, evaluated **before** the charge so a busy host never writes a
    /// counter it will not use.
    fn admit(&self, device: &DeviceId, hard_locked: bool) -> Admit {
        let now = Instant::now();
        let Ok(mut b) = self.budgets.lock() else {
            return Admit::Busy;
        };
        b.expire(now);
        if hard_locked {
            // Rate-aggregated: at most one answer per minute, then silence.
            if b.hard_locked_answered.contains_key(device) {
                return Admit::Silent;
            }
            b.hard_locked_answered.insert(*device, now);
            return Admit::Busy; // caller replaces this with HARD_LOCKED
        }
        // §B.8.4.5: a newer stream carrying its own signature-verified
        // `SESSION_REQUEST` (F1 under the new `host_nonce`) cancels a stale
        // charged handshake from the same pk rather than being turned away —
        // otherwise a client whose circuit died is locked out for the full 30 s
        // `AwaitKe3` timeout. Only while the older charge is still being
        // persisted is the newer one answered `UA_BUSY`.
        let mut preempted = None;
        if let Some(existing) = b.in_flight.get(device) {
            if !existing.charged.load(Ordering::SeqCst) {
                return Admit::Busy;
            }
            existing.cancel.set();
            preempted = Some(Arc::clone(&existing.settled));
        } else if b.in_flight.len() >= budget::MAX_IN_FLIGHT
            || b.challenges.len() >= budget::MAX_PER_MINUTE
        {
            return Admit::Busy;
        }
        let cancel = Arc::new(Latch::default());
        let charged = Arc::new(AtomicBool::new(false));
        let settled = Arc::new(Latch::default());
        b.in_flight.insert(
            *device,
            Slot {
                cancel: Arc::clone(&cancel),
                charged: Arc::clone(&charged),
                settled: Arc::clone(&settled),
                since: now,
            },
        );
        b.challenges.push(now);
        Admit::Ok {
            slot: InFlight {
                device: *device,
                budgets: Arc::clone(&self.budgets),
                limiter: self.limiter.clone(),
                cancel,
                charged,
                settled,
            },
            preempted,
        }
    }

    /// The readiness gate of §B.8.14: `Unknown` never blocks in M1 (fail-open
    /// with a badge); a `Fail` on one of the four load-bearing probes blocks
    /// with `HOST_NOT_READY` and the documented `cause`.
    fn readiness_reject(&self) -> Option<SessionReject> {
        let r = &self.readiness_now();
        let cause = if matches!(r.capture, Probe::Fail { .. }) {
            1
        } else if matches!(r.input, Probe::Fail { .. }) {
            2
        } else if matches!(r.lock_state, Probe::Fail { .. }) {
            3
        } else if matches!(r.console_owner, Probe::Fail { .. }) {
            4
        } else {
            return None;
        };
        let mut rej = SessionReject::new(reject::HOST_NOT_READY);
        rej.cause = Some(cause);
        Some(rej)
    }

    /// The condition of [`Self::with_ready_gate`]: `HOST_NOT_READY` without a
    /// `cause` while it does not hold.
    fn ready_gate_reject(&self) -> Option<SessionReject> {
        match &self.ready_gate {
            Some(ready) if !ready() => Some(SessionReject::new(reject::HOST_NOT_READY)),
            _ => None,
        }
    }
}

/// `tornect-core` keeps the stored policy types; `tornect-signal` keeps the wire
/// types. They are structurally identical but deliberately distinct — this module
/// is the boundary, so the mapping lives here rather than as a `From` in either
/// crate, and a new variant on one side becomes a compile error here.
fn wire_transport(t: tornect_core::unattended::grant::TransportPolicy) -> TransportPolicy {
    use tornect_core::unattended::grant::TransportPolicy as Core;
    match t {
        Core::Any => TransportPolicy::Any,
        Core::TorOnly => TransportPolicy::TorOnly,
        Core::LanOnly => TransportPolicy::LanOnly,
    }
}

/// The wire form of the §B.8.5 failure summary.
fn wire_fail_summary(f: tornect_core::unattended::grant::FailSummary) -> messages::FailSummary {
    messages::FailSummary {
        since_success: f.since_success,
        last_fail_at: f.last_fail_at,
    }
}

/// Map a pre-PAKE gate refusal onto its §B.8.4.6 wire body.
fn gate_reject(r: Reject) -> SessionReject {
    let mut out = SessionReject::new(r.code());
    out.cause = r.cause();
    out.retry_after_s = r.retry_after_s();
    out.next_open_in_s = r.next_open_in_s();
    out
}

/// Map a post-F2 policy refusal onto its wire body: `COOLDOWN` carries the time
/// left in `retry_after_s` (§B.8.4.6), which the client says.
fn post_f2_reject(r: PostF2Reject) -> SessionReject {
    let mut out = SessionReject::new(r.code());
    out.next_open_in_s = match r {
        PostF2Reject::NotYetActive { next_open_in_s } => Some(next_open_in_s),
        PostF2Reject::OutsideSchedule { next_open_in_s } => next_open_in_s,
        _ => None,
    };
    out.retry_after_s = match r {
        PostF2Reject::Cooldown { retry_after_s } => Some(retry_after_s),
        _ => None,
    };
    out
}

/// The requester left while its request waited on the `ask_before_start` popup
/// or the block window (B04): logged, and `gone` is what ends the stream.
fn requester_left(ctx: &UnattendedContext<'_>, gone: HandshakeError) -> HandshakeError {
    tracing::info!(peer = ?ctx.device, error = %gone, "the requester left before the answer");
    ctx.audit.record(AuditEvent::RequesterLeft {
        device: ctx.device,
        label: Some(ctx.label.to_owned()),
        popup: SuppressedPopup::Session,
    });
    gone
}

/// Classify a transport failure during `AwaitKe3` for the settlement log.
fn fail_kind(e: &HandshakeError) -> FailKind {
    match e {
        HandshakeError::Timeout(_) => FailKind::Timeout,
        HandshakeError::Violation { .. } => FailKind::Protocol,
        _ => FailKind::Disconnected,
    }
}

impl UnattendedHook for UnattendedAuth {
    fn handle<'a>(
        &'a self,
        ctx: UnattendedContext<'a>,
    ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
        Box::pin(async move { self.run(ctx).await })
    }

    /// §B.8.7.4: the panic key ended an unattended session of `device` past its
    /// PAKE, so its grant goes to `Suspended{Panic}` (logged by the guard), cleared
    /// only by a local Resume; a grant already suspended for a local reason stays
    /// as it is. A store that cannot take the change is warned about.
    fn panicked(&self, device: &DeviceId) {
        let Some(guard) = &self.block_guard else {
            return;
        };
        if let Err(e) = guard.panic(device) {
            tracing::warn!(peer = ?device, error = %e, "the panic key could not suspend the grant");
        }
    }

    /// Decision M1-67 (B steps 1 to 4, D2, D10, D11): after the reservation, the account
    /// facts and the helper task are read afresh, outside the store lock; then one store
    /// operation under the store lock checks the `auth` record this stream proved,
    /// refuses a grant no longer eligible, reads the mark and whether some grant holds
    /// the level, computes `grant_reach` and marks the password before an answer of 0.
    /// The session is lowered to what that read allows (the grant's mode as stored, the
    /// clamp's grant level, F-12, the marked rule), never raised, and carries the
    /// `grant_reach` it computed.
    fn reserved<'a>(
        &'a self,
        device: &'a DeviceId,
        proof: ConsentProof,
    ) -> BoxFuture<'a, Result<ConsentProof, SessionReject>> {
        Box::pin(async move {
            let ConsentProof::Unattended {
                grant,
                proof_fp,
                policy,
                block,
                token,
            } = proof
            else {
                return Ok(proof);
            };
            let account = self.facts.account();
            let helper_task = self.facts.helper_task();
            let Some(digest) = policy.auth_digest().copied() else {
                return Err(SessionReject::new(reject::NOT_GRANTED));
            };
            let read = match reach::read_after_reservation(
                self.limiter.store(),
                device,
                &digest,
                account,
                helper_task,
            ) {
                Ok(read) => read,
                // The password was replaced since the PAKE: the client deletes it as
                // stale, and nothing was marked.
                Err(ReachRefusal::AuthReplaced) => {
                    return Err(SessionReject::new(reject::AUTH_FAILED));
                }
                Err(ReachRefusal::NotEligible | ReachRefusal::MarkNotWritten) => {
                    return Err(SessionReject::new(reject::NOT_GRANTED));
                }
            };
            // Never above the grant as stored under the lock: a mode narrowed since the
            // gate is clamped first, so the level and the marked rule are judged on the
            // mode served.
            let policy = policy.lowered_to(read.grant_mode);
            let elevation = Elevation::most_restrictive(policy.elevation(), read.grant_level);
            let policy = policy.with_elevation(elevation);
            let level = Level::new(policy.mode(), policy.elevation());
            let served = served_mode(level, read.marked, read.clause_ii, account);
            Ok(ConsentProof::Unattended {
                grant,
                proof_fp,
                policy: policy.lowered_to(served).with_grant_reach(read.grant_reach),
                block,
                token,
            })
        })
    }
}

impl UnattendedAuth {
    async fn run(&self, ctx: UnattendedContext<'_>) -> Result<UnattendedVerdict, HandshakeError> {
        let device = ctx.device;
        let Some(req) = ctx.request.unattended.as_ref() else {
            // `serve_host` only routes here with `unattended = Some`.
            return Ok(UnattendedVerdict::Reject(SessionReject::new(
                reject::NOT_GRANTED,
            )));
        };

        // ---- pre-PAKE gate (uncharged, safe to disclose to a key holder) ----
        // Its grant is not the one charged below: a pre-emption may wait
        // between the two, and the charge re-runs the gate on the grant as
        // it is then.
        match self.limiter.gate(&device, req.suite, SUPPORTED_SUITES) {
            Ok(_) => {}
            Err(r) => {
                let hard = r.code() == reject::HARD_LOCKED;
                if hard && matches!(self.admit(&device, true), Admit::Silent) {
                    // §B.8.5.2: closed without any frame, nothing charged.
                    return Err(HandshakeError::Closed);
                }
                return Ok(UnattendedVerdict::Reject(gate_reject(r)));
            }
        }

        // ---- host-wide budgets (§B.8.5.2) ----
        let (slot, preempted) = match self.admit(&device, false) {
            Admit::Ok { slot, preempted } => (slot, preempted),
            Admit::Busy | Admit::Silent => {
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::UA_BUSY,
                )));
            }
        };
        // §B.8.4.5: the cancelled handshake is settled as a failure and this
        // stream continues. Until it is settled its charge is pending, and the
        // limiter refuses a second one; so wait for it, bounded, and answer the
        // retryable `UA_BUSY` should it not settle in time.
        if let Some(settled) = preempted
            && tokio::time::timeout(PREEMPT_SETTLE, settled.wait())
                .await
                .is_err()
        {
            return Ok(UnattendedVerdict::Reject(SessionReject::new(
                reject::UA_BUSY,
            )));
        }

        // ---- material for the PAKE, read before anything is charged ----
        let Some(setup_bytes) = self.limiter.store().server_setup() else {
            return Ok(UnattendedVerdict::Reject(SessionReject::new(
                reject::NOT_GRANTED,
            )));
        };
        let Some(grant) = self.limiter.store().grant(&device) else {
            return Ok(UnattendedVerdict::Reject(SessionReject::new(
                reject::NOT_GRANTED,
            )));
        };
        let AuthRecord::Opaque { record } = &grant.auth else {
            // Pruned, or a suite this build does not speak.
            return Ok(UnattendedVerdict::Reject(SessionReject::new(
                reject::UNSUPPORTED_SUITE,
            )));
        };
        let Some(ke1) = req.ke1.as_ref() else {
            return Ok(UnattendedVerdict::Reject(SessionReject::new(
                reject::UNSUPPORTED_SUITE,
            )));
        };

        let ctx_bytes = auth::context(&ctx.th_after_request, req.suite, req.intent);
        let device_pk = *device.public_key_bytes();
        let ids = auth::identifiers(&device_pk, &ctx.host_pk);

        let (setup, stored) = match (
            auth::parse_server_setup(&setup_bytes),
            auth::parse_record(record),
        ) {
            (Ok(s), Ok(r)) => (s, r),
            _ => {
                // The store decrypted but its PAKE material is unusable: fail
                // closed rather than run a PAKE that cannot succeed.
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::NOT_GRANTED,
                )));
            }
        };

        // ---- charge (write-ahead, fsynced) — only then may KE2 be written ----
        let charged = match self.limiter.charge(&device) {
            Ok(c) => c,
            Err(e) => {
                // A gate refusal is answered as the gate answers it. A charge
                // still pending (another handshake of this device not settled)
                // or one that could not be written is the host's state, not
                // the grant's: the retryable `UA_BUSY`, never `NOT_GRANTED`,
                // which tells the client that access was never given.
                let rej = match e.reject() {
                    Some(r) => gate_reject(r),
                    None => {
                        tracing::warn!(peer = ?device, error = %e, "the charge was not taken; answered busy");
                        SessionReject::new(reject::UA_BUSY)
                    }
                };
                return Ok(UnattendedVerdict::Reject(rej));
            }
        };
        // The charge is on disk: from here a newer verified `SESSION_REQUEST`
        // from this pk pre-empts us rather than being answered `UA_BUSY`, and a
        // handler dropped before its settlement settles it on the way out.
        slot.mark_charged();
        // The record was read outside the limiter's lock: an owner who
        // revoked and granted this device again in between would have the new
        // grant charged and the old record answer the PAKE. Never run it on a
        // record that is not the charged grant's; the retryable `UA_BUSY`
        // lets the device ask again at once, against the new grant.
        if charged.grant_id != grant.id {
            let _ = slot.settle(Settle::Fail(FailKind::Preempted));
            tracing::warn!(peer = ?device, "the grant changed while the request was charged; answered busy");
            return Ok(UnattendedVerdict::Reject(SessionReject::new(
                reject::UA_BUSY,
            )));
        }

        let (host_login, ke2) =
            match auth::HostLogin::start(&setup, &stored, ke1, &device_pk, &ctx_bytes, ids) {
                Ok(v) => v,
                Err(e) => {
                    let _ = slot.settle(Settle::Fail(FailKind::BadKe3));
                    tracing::warn!(peer = ?device, error = %e, "ServerLogin::start failed");
                    return Ok(UnattendedVerdict::Reject(SessionReject::new(
                        reject::AUTH_FAILED,
                    )));
                }
            };

        // ---- AwaitKe3 (30 s, charged) ----
        // Raced against pre-emption: a newer verified `SESSION_REQUEST` from this
        // pk cancels this handshake, which is settled as a failure and closed with
        // `PREEMPTED` — transport-class for the client, never a password failure,
        // so the remembered password is not marked stale (§B.8.4.6).
        let exchange = ctx.exchange.challenge(AuthChallenge {
            suite: req.suite,
            ke2: Some(ke2),
            salt: None,
            pb: None,
        });
        let (response, th_after_response) = tokio::select! {
            biased;
            () = slot.cancelled() => {
                let _ = slot.settle(Settle::Fail(FailKind::Preempted));
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::PREEMPTED,
                )));
            }
            r = exchange => match r {
                Ok(v) => v,
                Err(e) => {
                    // Settle first, then hand the transport error back unchanged so
                    // `serve_host` reports the code §B.8.4.5 documents.
                    let _ = slot.settle(Settle::Fail(fail_kind(&e)));
                    return Err(e);
                }
            },
        };

        let Some(ke3) = response.ke3.as_ref() else {
            let _ = slot.settle(Settle::Fail(FailKind::BadKe3));
            return Ok(UnattendedVerdict::Reject(SessionReject::new(
                reject::AUTH_FAILED,
            )));
        };

        let session_key = match host_login.finish(ke3, &ctx_bytes, ids) {
            Ok(k) => k,
            Err(_) => {
                let _ = slot.settle(Settle::Fail(FailKind::BadKe3));
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::AUTH_FAILED,
                )));
            }
        };

        // ---- F2 reached: settle, then the post-PAKE policy checks ----
        let fail_summary = slot.settle(Settle::Ok).unwrap_or(None);
        // §B.8.5.2 counts charged `AwaitKe3` streams only: release the host-wide
        // slot now, so the popup and block window below do not occupy one of the
        // four for up to another 90 s.
        drop(slot);

        // ---- admin intent terminates here, in place of SESSION_ACCEPT ----
        // This branch sits *before* `post_f2`, not after. §B.8.4.2 is explicit
        // that for an admin request the schedule, readiness, transport, busy and
        // concurrency gates are skipped — and those are exactly what `post_f2`
        // applies. Running them first would refuse `revoke`, `revoke_all`,
        // `master_off` and `end_session` whenever the grant's schedule window
        // happened to be shut or its reconnect cooldown was running, which is
        // the precise opposite of what those commands are for. Requester
        // eligibility is not skipped: `MutationGuard::admin` re-checks the
        // grant's state, expiry, `active_from`, hard lock and the clock
        // rollback rule before it touches anything.
        if req.intent == intent::ADMIN {
            return Ok(self.run_admin(
                &device,
                &reach::auth_digest(&grant.auth),
                req.admin.as_ref(),
            ));
        }

        let post = match self
            .limiter
            .post_f2(&device, &*self.tz, self.host_transport)
        {
            Ok(ok) => ok,
            Err(r) => return Ok(UnattendedVerdict::Reject(post_f2_reject(r))),
        };

        if let Some(rej) = self.readiness_reject() {
            return Ok(UnattendedVerdict::Reject(rej));
        }
        if let Some(rej) = self.ready_gate_reject() {
            return Ok(UnattendedVerdict::Reject(rej));
        }

        // ---- another session live: neither the popup nor the block window opens ----
        // Either would show this device's label on a screen another device may be
        // watching, and no session can start while that one is live (§B.8.6.2, §B.8.6.4):
        // the post-F2 refusal `SESSION_ACTIVE`, before the popup (§B.8.4.5), whether or
        // not the grant asks before starting; logged as suppressed, as the attended popup is.
        if ctx.activity.session_live() {
            ctx.audit.record(AuditEvent::PopupSuppressed {
                device,
                label: Some(ctx.label.to_owned()),
                popup: SuppressedPopup::Session,
            });
            return Ok(UnattendedVerdict::Reject(SessionReject::new(
                reject::SESSION_ACTIVE,
            )));
        }

        // ---- ask_before_start, then the block window ----
        let label = ctx.label;
        // The popup names the grant's level (§B.8.6.3, r7): an admin grant's
        // says that it wants to connect as administrator.
        let asked_level = if grant.holds_level() {
            Elevation::Admin
        } else {
            Elevation::None
        };
        // Both raced against the requester leaving (B04): the card or the block
        // window goes at once, and nothing is accepted into a dead stream.
        if grant.ask_before_start {
            let allowed = tokio::select! {
                biased;
                gone = ctx.exchange.departed() => return Err(requester_left(&ctx, gone)),
                allowed = ctx.local_allow.ask_at(&grant.id, label, asked_level, Duration::from_secs(60)) => allowed,
            };
            if !allowed {
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::DENIED,
                )));
            }
        }

        let outcome = tokio::select! {
            biased;
            gone = ctx.exchange.departed() => return Err(requester_left(&ctx, gone)),
            outcome = ctx.block_window.run(grant.block_window_s, &grant.id, label) => outcome,
        };
        let block = match outcome {
            BlockOutcome::Passed(w) => w,
            BlockOutcome::Blocked => {
                // §B.8.6.3: Block ⇒ `BLOCKED_BY_LOCAL_USER` and the grant
                // `Suspended{LocalBlock}` until a local Resume; nothing is
                // captured (no accept is ever built).
                self.blocked(&device);
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::BLOCKED_BY_LOCAL_USER,
                )));
            }
            BlockOutcome::NotShown => {
                // §B.8.6.3: a block window shown nowhere is no veto that
                // passed: `HOST_NOT_READY` without a cause, logged, and the
                // grant is left as it was (no suspend); nothing is captured.
                self.not_shown(&device);
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::HOST_NOT_READY,
                )));
            }
        };

        // ---- mint the proof ----
        let token = auth::session_token(&session_key, &th_after_response);
        let ck = auth::confirm_key(&session_key, &th_after_response);
        let confirm = auth::token_confirm(&ck, &th_after_response);
        let proof_fp = auth::proof_fp(&session_key);

        // `want_mode` is clamped host-side toward view-only, never a reject.
        let wanted = if req.want_mode == mode::VIEW_ONLY {
            SessionMode::ViewOnly
        } else {
            SessionMode::Control
        };
        // `want_elevation` the same way (r7, §B.8.4.1, D2): the most restrictive
        // of the grant's level, the request and what this host delivers. The
        // grant's level is the clone's (store key 24), none while its password is
        // marked (D11) and where the level does not exist (Linux); what the host
        // delivers is the state machine's to lower (the helper task, §B.8.7.5).
        // Decision M1-67 (D10, D11): the account facts and the helper task are read
        // now, never cached from start.
        let account = self.facts.account();
        let grant_level =
            if grant.holds_level() && !marked(&grant) && account != AccountFacts::Linux {
                Elevation::Admin
            } else {
                Elevation::None
            };
        let want_elevation = req
            .want_elevation
            .and_then(Elevation::from_code)
            .unwrap_or(Elevation::None);
        let level =
            Level::new(grant.mode, grant_level).clamp(wanted, want_elevation, Elevation::Admin);
        debug_assert_eq!(
            level.mode(),
            SessionMode::most_restrictive(grant.mode, wanted)
        );
        // Control is lowered to view only where it is administrator access here
        // (F-12) or where the password is marked and clause (ii) holds, before any
        // helper starts. Lowering only.
        let reach_through_host = clause_ii(
            grant.mode,
            some_grant_holds_level(self.limiter.store()),
            account,
            self.facts.helper_task(),
        );
        let served = served_mode(level, marked(&grant), reach_through_host, account);
        let level = if served == level.mode() {
            level
        } else {
            // View only never carries the level (§B.8.4.1).
            Level::new(served, Elevation::None)
        };

        let policy = PolicyReceipt::mint(
            grant.id,
            level.mode(),
            wire_transport(post.transport),
            post.ends_at,
            grant.block_window_s,
            grant.ask_before_start,
            self.readiness_now(),
            fail_summary.map(wire_fail_summary),
        )
        .with_elevation(level.elevation())
        // The record this stream's PAKE ran against, for the read after the reservation.
        .with_auth_digest(reach::auth_digest(&grant.auth));

        Ok(UnattendedVerdict::Accept {
            proof: ConsentProof::Unattended {
                grant: grant.id,
                proof_fp,
                policy,
                block,
                token: DerivedToken::new(*token, confirm),
            },
            caps: ChosenCaps::negotiate(ctx.host_caps, &ctx.request.caps),
        })
    }
}

/// Whether `grant`'s password is marked "answered 0" (decision M1-67, D9, D11): store
/// key 25 absent or false. Only a registration sent as generated clears the mark.
fn marked(grant: &UnattendedGrant) -> bool {
    grant.marked()
}

/// Whether some grant in the store holds the administrator level, whatever its state
/// (clause (ii), store key 24). The read after the reservation decides it again under the
/// store lock.
fn some_grant_holds_level(store: &GrantStore) -> bool {
    store
        .read(|s| s.grants.iter().any(UnattendedGrant::holds_level))
        .unwrap_or(false)
}

impl UnattendedAuth {
    /// The `intent = admin` branch (§B.8.4.1), reached only after F2. `auth_digest` is the
    /// SHA-256 of the stored record this stream's PAKE ran against (decision M1-67).
    fn run_admin(
        &self,
        device: &DeviceId,
        auth_digest: &[u8; 32],
        cmd: Option<&messages::AdminCmd>,
    ) -> UnattendedVerdict {
        // `admin` is required iff `intent = 1`, and `SessionRequest`'s decoder already
        // answers `E_BAD_LEN` for the three other combinations — so `None` is unreachable
        // from the wire. Refused rather than unwrapped: a caller building the type
        // directly must not get a panic. An unknown op, or a `device_pk` present for an
        // op that takes none (or absent for one that needs it), is not an `ERROR`: the
        // frame decoded cleanly, so this is a command the host will not run, reported
        // the way every other such command is, with the requester's `grant_reach` and a
        // line of its own.
        let answer = match cmd {
            None => self
                .admin
                .refuse_early(device, auth_digest, "admin command missing"),
            Some(cmd) => match AdminOp::from_wire(cmd.op, cmd.device_pk) {
                None => self
                    .admin
                    .refuse_early(device, auth_digest, "unknown admin command"),
                Some(op) => {
                    let answer = self.admin.execute(device, auth_digest, op);
                    tracing::info!(
                        peer = ?device,
                        op = op.name(),
                        ok = answer.as_ref().is_ok_and(|(outcome, _)| outcome.ok),
                        "admin command"
                    );
                    answer
                }
            },
        };
        match answer {
            // Every `ADMIN_RESULT` carries the requester's `grant_reach`, read under the
            // lock of the command (decision M1-67, D1).
            Ok((outcome, grant_reach)) => UnattendedVerdict::Admin {
                result: messages::AdminResult {
                    ok: outcome.ok,
                    detail: outcome.detail,
                    grant_reach,
                },
                effect: outcome.effect,
            },
            // The requester's password was replaced since the PAKE: the client deletes it
            // as stale. Nothing ran.
            Err(ReachRefusal::AuthReplaced) => {
                UnattendedVerdict::Reject(SessionReject::new(reject::AUTH_FAILED))
            }
            Err(ReachRefusal::NotEligible | ReachRefusal::MarkNotWritten) => {
                UnattendedVerdict::Reject(SessionReject::new(reject::NOT_GRANTED))
            }
        }
    }
}

/// The OPAQUE `ServerSetup` source the store bootstrap needs (§B.8.9).
///
/// `tornect-core` stores the bytes but must not depend on `opaque-ke`, so it
/// declares the trait and this crate supplies it — the same direction as
/// `ReAuth` / `Presence`. Without it the guard refuses every bootstrap
/// (`NoServerSetupSource`), which is the correct default: a store whose setup
/// is not a real `ServerSetup` could never complete a login.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpaqueServerSetupSource;

impl tornect_core::unattended::guard::ServerSetupSource for OpaqueServerSetupSource {
    fn generate(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        Ok(new_server_setup())
    }
}

/// Re-exported so the CLI track can build one without reaching into `auth`.
pub use crate::auth::{new_server_setup, register_locally};

/// The grant id type, re-exported for callers assembling a hook.
pub type Grant = GrantId;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tornect_core::keystore::FileSecretStore;
    use tornect_core::paths::Paths;
    use tornect_core::session_log::{Actor, SessionLog};
    use tornect_core::unattended::clock::SystemClock;
    use tornect_core::unattended::grant::Preset;
    use tornect_core::unattended::guard::{
        AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
    };
    use tornect_core::unattended::ipc::GrantOptions;
    use tornect_core::unattended::store::GrantStore;

    use super::*;
    use crate::consent::TimerOnlyWindow;
    use crate::messages::{AuthResponse, Caps, SessionRequest, UnattendedRequest};

    const PW: &str = "quiet verdant otter lantern zephyr";
    const HOST_PK: [u8; 32] = [0x22; 32];
    const TH_REQ: [u8; 32] = [0x33; 32];

    /// §B.8.4.6: `COOLDOWN` tells the client how long to wait, as the
    /// pre-PAKE `LOCKED_OUT` does; the other post-F2 refusals carry their own
    /// field or none.
    #[test]
    fn the_cooldown_reject_carries_the_time_left() {
        let r = post_f2_reject(PostF2Reject::Cooldown { retry_after_s: 42 });
        assert_eq!(
            (r.reason, r.retry_after_s, r.next_open_in_s),
            (reject::COOLDOWN, Some(42), None)
        );
        let r = post_f2_reject(PostF2Reject::OutsideSchedule {
            next_open_in_s: Some(7),
        });
        assert_eq!((r.retry_after_s, r.next_open_in_s), (None, Some(7)));
        let r = post_f2_reject(PostF2Reject::NotGranted);
        assert_eq!((r.retry_after_s, r.next_open_in_s), (None, None));
    }

    /// Denies every `ask_before_start` popup.
    struct DenyAll;
    impl crate::consent::LocalAllow for DenyAll {
        fn ask_at<'a>(
            &'a self,
            _: &'a GrantId,
            _: &'a str,
            _: Elevation,
            _: Duration,
        ) -> BoxFuture<'a, bool> {
            Box::pin(async { false })
        }
    }

    /// A block window that always reports Block.
    struct AlwaysBlock;
    impl crate::consent::BlockWindow for AlwaysBlock {
        fn run<'a>(&'a self, _: u8, _: &'a GrantId, _: &'a str) -> BoxFuture<'a, BlockOutcome> {
            Box::pin(async { BlockOutcome::Blocked })
        }
    }

    /// Drives a **real** `ClientLogin` against the host's `AUTH_CHALLENGE`, so
    /// the exchange under test is the genuine OPAQUE one, not a stub.
    struct RealClient {
        password: String,
        th_after_response: [u8; 32],
        /// Set once the client finished: its own view of the session key.
        client_key: Arc<Mutex<Option<Vec<u8>>>>,
        state: Option<auth::ClientLogin>,
        ctx: Vec<u8>,
        device_pk: [u8; 32],
    }

    impl crate::fsm::AuthExchange for RealClient {
        fn challenge<'a>(
            &'a mut self,
            challenge: AuthChallenge,
        ) -> BoxFuture<'a, Result<(AuthResponse, [u8; 32]), HandshakeError>> {
            Box::pin(async move {
                let ke2 = challenge.ke2.expect("suite 1 carries KE2");
                let ids = auth::identifiers(&self.device_pk, &HOST_PK);
                let state = self.state.take().expect("one challenge per stream");
                match state.finish(&self.password, &ke2, &self.ctx, ids) {
                    Ok(out) => {
                        *self.client_key.lock().unwrap() = Some(out.session_key.to_vec());
                        Ok((
                            AuthResponse {
                                ke3: Some(out.ke3),
                                pa: None,
                                ca: None,
                            },
                            self.th_after_response,
                        ))
                    }
                    // A wrong password still produces a KE3; the host is the one
                    // that must reject it. Send whatever the client produced.
                    Err(_) => Ok((
                        AuthResponse {
                            ke3: Some([0u8; 64]),
                            pa: None,
                            ca: None,
                        },
                        self.th_after_response,
                    )),
                }
            })
        }
    }

    struct Env {
        _tmp: tempfile::TempDir,
        guard: Arc<MutationGuard>,
        device: DeviceId,
        auth: UnattendedAuth,
        /// The §B.8.7.4 emergency stop code, shown once at enable time.
        stop_code: [u8; tornect_core::unattended::guard::STOP_CODE_LEN],
    }

    fn env(password: &str) -> Env {
        env_with(password, Preset::HeadlessBox, &GrantOptions::default())
    }

    /// An env whose grant carries admin scope (§B.8.4.1: `MyMachines` +
    /// `Control` + `Active`). `MyMachines` does not waive the "prior attended
    /// session" precondition, which no in-process test can satisfy, so the
    /// `--waive-attended-check` option does it explicitly.
    fn env_admin(password: &str) -> Env {
        env_with(
            password,
            Preset::MyMachines,
            &GrantOptions {
                waive_attended_precondition: true,
                ..GrantOptions::default()
            },
        )
    }

    fn env_with(password: &str, preset: Preset, options: &GrantOptions) -> Env {
        env_with_facts(
            password,
            preset,
            options,
            Arc::new(tornect_core::levels::FixedFacts::linux()),
        )
    }

    /// [`env_with`] on a host whose account facts and helper task `facts` gives.
    fn env_with_facts(
        password: &str,
        preset: Preset,
        options: &GrantOptions,
        facts: Arc<dyn FactsSource>,
    ) -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        std::fs::create_dir_all(paths.keys_dir()).unwrap();
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        let clock = Arc::new(SystemClock::default());
        let log = SessionLog::new(paths.sessions_log());
        let store = GrantStore::open(&paths, secrets, clock, log).unwrap();

        // Set up as the command line would on a host where nothing reaches the level; the
        // host, and the guard its admin path uses, then run on `facts`.
        let guard = MutationGuard::new(
            store.clone(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::new(tornect_core::levels::FixedFacts::linux()),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(OpaqueServerSetupSource));

        let device = DeviceId::from_bytes([0x11; 32]);
        // §B.8: the master switch is opt-in and off until the owner enables it.
        let stop_code = *guard
            .master_on(Actor::Cli, &HOST_PK)
            .expect("master_on")
            .stop_code;
        // Bootstrap happens inside create_grant; the setup must exist first, so
        // register against the setup the store ends up holding.
        // `HeadlessBox` waives the §B.8.6 "prior attended session" precondition,
        // which no in-process test can satisfy. The record is replaced by the real
        // one below; this first call exists to bootstrap the store (and with it the
        // `ServerSetup` the registration must run against).
        guard
            .create_grant(Actor::Cli, &device, preset, options, &[0u8; 192], false)
            .expect("create_grant");
        let setup_bytes = guard.store().server_setup().expect("bootstrapped");
        let setup = auth::parse_server_setup(&setup_bytes).unwrap();
        let record = register_locally(
            &setup,
            password,
            device.public_key_bytes(),
            auth::identifiers(device.public_key_bytes(), &HOST_PK),
        )
        .unwrap();
        guard
            .set_password(
                Actor::Cli,
                &device,
                &record,
                &GrantOptions::default(),
                false,
            )
            .expect("set_password");

        let guard = Arc::new(
            MutationGuard::new(
                store,
                Arc::new(AllowAllReAuth::default()),
                Arc::new(NoSessionActivity),
                Arc::clone(&facts),
            )
            .with_paired_devices(Arc::new(AllowAllPaired))
            .with_server_setup_source(Arc::new(OpaqueServerSetupSource)),
        );
        let limiter = AttemptLimiter::new(guard.store().clone());
        let auth = UnattendedAuth::new(
            limiter,
            Arc::new(tornect_core::unattended::schedule::FixedOffset::utc()),
            HostTransport::default(),
            facts,
        )
        .with_block_guard(Arc::clone(&guard));
        Env {
            _tmp: tmp,
            guard,
            device,
            auth,
            stop_code,
        }
    }

    fn request(suite: u8, ke1: Option<[u8; 96]>) -> SessionRequest {
        SessionRequest {
            caps: Caps::default(),
            unattended: Some(UnattendedRequest {
                suite,
                ke1,
                want_mode: mode::CONTROL,
                intent: intent::SESSION,
                admin: None,
                want_elevation: None,
            }),
        }
    }

    async fn run(
        env: &Env,
        password: &str,
        block: &dyn crate::consent::BlockWindow,
        allow: &dyn crate::consent::LocalAllow,
    ) -> (Result<UnattendedVerdict, HandshakeError>, Option<Vec<u8>>) {
        let device_pk = *env.device.public_key_bytes();
        let ctx_bytes = auth::context(&TH_REQ, auth::SUITE_OPAQUE, intent::SESSION);
        let (state, ke1) = auth::ClientLogin::start(password).unwrap();
        let client_key = Arc::new(Mutex::new(None));
        let mut exchange = RealClient {
            password: password.to_owned(),
            th_after_response: [0x44; 32],
            client_key: Arc::clone(&client_key),
            state: Some(state),
            ctx: ctx_bytes,
            device_pk,
        };
        let req = request(auth::SUITE_OPAQUE, Some(ke1));
        let caps = Caps::default();
        let verdict = env
            .auth
            .handle(UnattendedContext {
                device: env.device,
                label: "Laptop",
                request: &req,
                th_after_request: TH_REQ,
                host_pk: HOST_PK,
                host_caps: &caps,
                exchange: &mut exchange,
                block_window: block,
                local_allow: allow,
                activity: &crate::fsm::host::NoSession,
                audit: &crate::fsm::NoAudit,
            })
            .await;
        let k = client_key.lock().unwrap().clone();
        (verdict, k)
    }

    // ---------------------------------------------------------------------
    // Remote administration (§B.8.4.1)
    // ---------------------------------------------------------------------

    /// Drive a real OPAQUE login carrying `intent = admin`.
    ///
    /// The intent is part of the PAKE `context` (§B.8.4.3), so both sides must
    /// agree on it before a single byte is exchanged — an admin result cannot
    /// be obtained by flipping the intent byte after the fact.
    async fn run_admin_req(
        env: &Env,
        password: &str,
        op: u8,
        device_pk: Option<[u8; 32]>,
    ) -> UnattendedVerdict {
        let dev_pk = *env.device.public_key_bytes();
        let ctx_bytes = auth::context(&TH_REQ, auth::SUITE_OPAQUE, intent::ADMIN);
        let (state, ke1) = auth::ClientLogin::start(password).unwrap();
        let mut exchange = RealClient {
            password: password.to_owned(),
            th_after_response: [0x44; 32],
            client_key: Arc::new(Mutex::new(None)),
            state: Some(state),
            ctx: ctx_bytes,
            device_pk: dev_pk,
        };
        let req = SessionRequest {
            caps: Caps::default(),
            unattended: Some(UnattendedRequest {
                suite: auth::SUITE_OPAQUE,
                ke1: Some(ke1),
                want_mode: mode::CONTROL,
                intent: intent::ADMIN,
                admin: Some(messages::AdminCmd { op, device_pk }),
                want_elevation: None,
            }),
        };
        let caps = Caps::default();
        let block = TimerOnlyWindow;
        let allow = DenyAll;
        env.auth
            .handle(UnattendedContext {
                device: env.device,
                label: "Laptop",
                request: &req,
                th_after_request: TH_REQ,
                host_pk: HOST_PK,
                host_caps: &caps,
                exchange: &mut exchange,
                block_window: &block,
                local_allow: &allow,
                activity: &crate::fsm::host::NoSession,
                audit: &crate::fsm::NoAudit,
            })
            .await
            .expect("admin exchange completes")
    }

    /// The master switch as the store sees it now.
    fn store_enabled(env: &Env) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        env.guard.store().enabled_at(now)
    }

    /// A weekly window that is **closed right now**, whenever "now" is.
    ///
    /// The guard rejects an empty day mask, so the window runs on all seven days
    /// and is placed in whichever half of the day the current minute is not in.
    /// Openness then depends only on the minute of day, which makes the test
    /// deterministic instead of passing or failing by the hour it runs at.
    fn closed_window() -> tornect_core::unattended::grant::Window {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let minute_of_day = (now % 86_400) / 60;
        let (start_min, end_min) = if minute_of_day < 720 {
            (800, 900)
        } else {
            (100, 200)
        };
        tornect_core::unattended::grant::Window {
            days: 0x7F,
            start_min,
            end_min,
            tz: "UTC".to_owned(),
        }
    }

    fn admin_parts(v: UnattendedVerdict) -> (bool, AdminEffect) {
        match v {
            UnattendedVerdict::Admin { result, effect } => (result.ok, effect),
            UnattendedVerdict::Reject(r) => {
                panic!("expected ADMIN_RESULT, got reject {}", r.reason)
            }
            UnattendedVerdict::Accept { .. } => panic!("expected ADMIN_RESULT, got SESSION_ACCEPT"),
        }
    }

    /// M1-67 (D1): the two early refusals (a missing command, unreachable from the wire,
    /// and an unknown one) go through the guard: the requester's grant is checked, the
    /// answer carries its `grant_reach`, and each writes an `AdminRequest` line with op
    /// `unknown`; a password replaced since the PAKE gets no answer (`AUTH_FAILED`). An
    /// authority without a store has no value to give. (Rewritten from
    /// `the_early_admin_refusals_carry_no_grant_reach_yet`.)
    #[test]
    fn the_early_admin_refusals_carry_grant_reach_and_are_logged() {
        use tornect_core::session_log::SessionEvent;
        let mut env = env(PW);
        let without = env.auth.run_admin(&env.device, &[0; 32], None);
        let UnattendedVerdict::Admin { result, .. } = without else {
            panic!("expected ADMIN_RESULT");
        };
        assert_eq!((result.ok, result.grant_reach), (false, None));
        env.auth = env
            .auth
            .with_admin_authority(Arc::new(GuardAdmin::new(Arc::clone(&env.guard))));
        let digest = reach::auth_digest(&env.guard.store().grant(&env.device).unwrap().auth);
        let unknown = messages::AdminCmd {
            op: 0xEE,
            device_pk: None,
        };
        let lines = |env: &Env| {
            env.guard
                .store()
                .log()
                .read_all()
                .unwrap()
                .into_iter()
                .filter(|r| {
                    r.event == SessionEvent::AdminRequest && r.op.as_deref() == Some("unknown")
                })
                .count()
        };
        for (n, cmd) in [None, Some(&unknown)].into_iter().enumerate() {
            let UnattendedVerdict::Admin { result, .. } =
                env.auth.run_admin(&env.device, &digest, cmd)
            else {
                panic!("expected ADMIN_RESULT");
            };
            assert!(!result.ok);
            assert_eq!(result.grant_reach, Some(0), "Linux: 0");
            assert_eq!(lines(&env), n + 1);
        }
        let UnattendedVerdict::Reject(reject) = env.auth.run_admin(&env.device, &[0; 32], None)
        else {
            panic!("expected a refusal");
        };
        assert_eq!(reject.reason, reject::AUTH_FAILED);
        assert_eq!(lines(&env), 2, "no answer, no line");
    }

    /// The default hook has no authority wired: it refuses rather than
    /// pretending to have run the command.
    #[tokio::test]
    async fn admin_is_refused_when_no_authority_is_wired() {
        let env = env_admin(PW);
        let (ok, effect) = admin_parts(run_admin_req(&env, PW, 2 /* revoke_all */, None).await);
        assert!(!ok);
        assert_eq!(effect, AdminEffect::None);
        assert!(
            env.guard.store().grant(&env.device).is_some(),
            "nothing revoked"
        );
    }

    /// An in-scope command runs and the store really changed.
    #[tokio::test]
    async fn an_in_scope_admin_command_executes() {
        let mut env = env_admin(PW);
        env.auth = env
            .auth
            .with_admin_authority(Arc::new(GuardAdmin::new(Arc::clone(&env.guard))));

        assert!(store_enabled(&env));
        let (ok, effect) = admin_parts(run_admin_req(&env, PW, 3 /* master_off */, None).await);
        assert!(ok, "master_off is in scope for a MyMachines/Control grant");
        assert_eq!(effect, AdminEffect::MasterOff);
        assert!(!store_enabled(&env), "master switch really went off");
    }

    /// A grant without admin scope may only end its own session and revoke its
    /// own key. `HeadlessBox` is not `MyMachines`, so `revoke_all` is refused —
    /// and nothing changes.
    #[tokio::test]
    async fn an_out_of_scope_admin_command_is_refused_and_changes_nothing() {
        let mut env = env(PW);
        env.auth = env
            .auth
            .with_admin_authority(Arc::new(GuardAdmin::new(Arc::clone(&env.guard))));

        let (ok, effect) = admin_parts(run_admin_req(&env, PW, 2 /* revoke_all */, None).await);
        assert!(!ok, "revoke_all needs the MyMachines preset");
        assert_eq!(effect, AdminEffect::None);
        assert!(store_enabled(&env));
        assert!(env.guard.store().grant(&env.device).is_some());
    }

    /// An op byte this build does not know, and a `device_pk` supplied for an op
    /// that takes none, are both refused in an `ADMIN_RESULT` — the frame
    /// decoded, so this is a command the host will not run, not a protocol
    /// violation.
    #[tokio::test]
    async fn a_malformed_admin_command_is_refused() {
        let mut env = env_admin(PW);
        env.auth = env
            .auth
            .with_admin_authority(Arc::new(GuardAdmin::new(Arc::clone(&env.guard))));

        let (ok, _) = admin_parts(run_admin_req(&env, PW, 99, None).await);
        assert!(!ok, "unknown op");
        // `master_off` (3) takes no device_pk.
        let (ok, _) = admin_parts(run_admin_req(&env, PW, 3, Some([0x77; 32])).await);
        assert!(!ok, "superfluous device_pk");
        assert!(store_enabled(&env), "neither one ran");
    }

    /// **Regression (§B.8.4.2).** The schedule, readiness, transport, busy and
    /// concurrency gates are *skipped* for an admin request. Before the fix the
    /// admin branch sat after `post_f2`, so a grant whose schedule window was
    /// shut answered `SESSION_REJECT{OUTSIDE_SCHEDULE}` instead of running the
    /// command — refusing `revoke_all` and `master_off` in exactly the
    /// emergency they exist for.
    ///
    /// Fails against the pre-fix ordering: `admin_parts` panics on the reject.
    #[tokio::test]
    async fn admin_runs_even_when_the_schedule_window_is_shut() {
        let mut env = env_admin(PW);
        // Closed now, deterministically (see `closed_window`).
        env.guard
            .set_options(
                Actor::Cli,
                &env.device,
                &GrantOptions {
                    schedule: Some(vec![closed_window()]),
                    ..GrantOptions::default()
                },
            )
            .expect("set_options");

        env.auth = env
            .auth
            .with_admin_authority(Arc::new(GuardAdmin::new(Arc::clone(&env.guard))));

        let (ok, effect) = admin_parts(run_admin_req(&env, PW, 3 /* master_off */, None).await);
        assert!(ok, "an admin command is not gated by the schedule window");
        assert_eq!(effect, AdminEffect::MasterOff);
        assert!(!store_enabled(&env));
    }

    /// The same grant, same closed window, ordinary session intent: still
    /// refused. The fix above must not have opened the session path.
    #[tokio::test]
    async fn a_session_is_still_refused_outside_the_schedule_window() {
        let env = env_admin(PW);
        env.guard
            .set_options(
                Actor::Cli,
                &env.device,
                &GrantOptions {
                    schedule: Some(vec![closed_window()]),
                    ..GrantOptions::default()
                },
            )
            .expect("set_options");

        let (verdict, _) = run(&env, PW, &TimerOnlyWindow, &DenyAll).await;
        match verdict.expect("exchange completes") {
            UnattendedVerdict::Reject(r) => {
                assert_eq!(r.reason, reject::OUTSIDE_SCHEDULE);
            }
            _ => panic!("a session outside the schedule window must be refused"),
        }
    }

    // ---------------------------------------------------------------------
    // Emergency stop (§B.8.7.4)
    // ---------------------------------------------------------------------

    /// The stop code presented in `HELLO` turns unattended access off, revokes
    /// every grant, fires the kill switch and — because the code is single-use —
    /// clears the stored token so the same card cannot be replayed.
    #[tokio::test]
    async fn the_stop_code_disables_everything_and_is_single_use() {
        let env = env(PW);
        let kill = KillSwitch::new();
        let stop = EmergencyStop::new(Arc::clone(&env.guard), kill.clone());
        let token = tornect_core::unattended::guard::stop_token(&HOST_PK, &env.stop_code);

        assert!(store_enabled(&env));
        assert!(env.guard.store().grant(&env.device).is_some());

        stop.observe(&token).await;

        assert!(!store_enabled(&env), "master switch off");
        assert!(
            env.guard.store().grant(&env.device).is_none(),
            "grants revoked"
        );
        assert_eq!(kill.fired(), Some(bye::EMERGENCY_STOP));

        // Single use: the token was cleared, so a replay of the same card is
        // now indistinguishable from any other unknown value.
        let kill2 = KillSwitch::new();
        let stop2 = EmergencyStop::new(Arc::clone(&env.guard), kill2.clone());
        stop2.observe(&token).await;
        assert_eq!(kill2.fired(), None, "the code is single-use");
    }

    /// A token that is not this host's does nothing at all — including the
    /// token a *different* host's pk would produce from the same code, which is
    /// the phishing case §B.8.7.4 relies on the pk binding for.
    #[tokio::test]
    async fn a_foreign_stop_token_does_nothing() {
        let env = env(PW);
        let kill = KillSwitch::new();
        let stop = EmergencyStop::new(Arc::clone(&env.guard), kill.clone());

        // Right code, wrong host: what a client would compute after dialling a
        // scam onion address.
        let other_host = [0x99; 32];
        let foreign = tornect_core::unattended::guard::stop_token(&other_host, &env.stop_code);
        stop.observe(&foreign).await;
        // And an unrelated value.
        stop.observe(&[0x00; 32]).await;

        assert!(store_enabled(&env), "still on");
        assert!(
            env.guard.store().grant(&env.device).is_some(),
            "grant intact"
        );
        assert_eq!(kill.fired(), None);
    }

    /// A host with no stop code enabled ignores every token, including the
    /// all-zero one that a naive constant-time compare against an absent value
    /// would accept.
    #[tokio::test]
    async fn a_host_without_a_stop_code_ignores_every_token() {
        let env = env(PW);
        // `emergency_stop` is the one path that clears the token; use it to
        // reach the "no code enabled" state, then re-enable the grant store's
        // master switch would re-issue one — so assert on the cleared state.
        let kill = KillSwitch::new();
        let stop = EmergencyStop::new(Arc::clone(&env.guard), kill.clone());
        env.guard.emergency_stop().expect("clear the token");

        let kill2 = KillSwitch::new();
        let stop2 = EmergencyStop::new(Arc::clone(&env.guard), kill2.clone());
        stop2.observe(&[0x00; 32]).await;
        stop2
            .observe(&tornect_core::unattended::guard::stop_token(
                &HOST_PK,
                &env.stop_code,
            ))
            .await;
        assert_eq!(kill2.fired(), None);
        let _ = stop;
        let _ = kill;
    }

    /// The happy path: a granted, paired device with the right password reaches
    /// `SESSION_ACCEPT`, and both sides derived the *same* session token.
    #[tokio::test]
    async fn a_correct_password_accepts_and_both_sides_derive_the_same_token() {
        let env = env(PW);
        let (verdict, client_key) = run(&env, PW, &TimerOnlyWindow, &DenyAll).await;
        let UnattendedVerdict::Accept { proof, .. } = verdict.unwrap() else {
            panic!("expected Accept");
        };
        let ConsentProof::Unattended { token, .. } = &proof else {
            panic!("expected an unattended proof");
        };
        // The client's independent derivation must match the host's.
        let ck = client_key.expect("client finished");
        let expect = auth::session_token(&ck, &[0x44; 32]);
        assert_eq!(token.session_token(), expect.as_ref());
    }

    /// S5A-1 (decision M1-67, D10, D11): the receipt the gate mints, read before any read
    /// after the reservation can lower it. A control grant asking for control is minted
    /// view only where control is administrator access on this account (F-12:
    /// `ConsentPromptBehaviorAdmin` 0, facts that could not be read) and where the marked
    /// password meets clause (ii) (the helper task registered, or its query failing);
    /// control on an administrator account with UAC on and no task.
    #[tokio::test]
    async fn the_gate_mints_view_only_where_f12_or_the_marked_rule_says_so() {
        use tornect_core::levels::{AccountFacts, FixedFacts, HelperPresence, WindowsFacts};
        let admin = |cpba: Option<u32>| {
            AccountFacts::Windows(WindowsFacts {
                installed: true,
                administrator: true,
                consent_prompt_behavior_admin: cpba,
                ..WindowsFacts::default()
            })
        };
        let absent = HelperPresence::Absent;
        for (case, account, helper, expected) in [
            ("CPBA 0", admin(Some(0)), absent, SessionMode::ViewOnly),
            (
                "unreadable",
                AccountFacts::Unreadable,
                absent,
                SessionMode::ViewOnly,
            ),
            (
                "helper task registered",
                admin(None),
                HelperPresence::Registered,
                SessionMode::ViewOnly,
            ),
            (
                "helper task unreadable",
                admin(None),
                HelperPresence::Unreadable,
                SessionMode::ViewOnly,
            ),
            ("UAC on, no task", admin(None), absent, SessionMode::Control),
        ] {
            let env = env_with_facts(
                PW,
                Preset::HeadlessBox,
                &GrantOptions::default(),
                Arc::new(FixedFacts::new(account, helper)),
            );
            let (verdict, _) = run(&env, PW, &TimerOnlyWindow, &DenyAll).await;
            let Ok(UnattendedVerdict::Accept {
                proof: ConsentProof::Unattended { policy, .. },
                ..
            }) = verdict
            else {
                panic!("{case}: no accept");
            };
            assert_eq!(policy.mode(), expected, "{case}");
            assert_eq!(policy.elevation(), Elevation::None, "{case}");
        }
    }

    /// A wrong password is `AUTH_FAILED` and the charge is settled as a failure,
    /// so the ladder actually advances (§B.8.5.1).
    #[tokio::test]
    async fn a_wrong_password_is_auth_failed_and_advances_the_ladder() {
        let env = env(PW);
        let before = env
            .guard
            .store()
            .grant(&env.device)
            .unwrap()
            .fail
            .consecutive;
        let (verdict, _) = run(
            &env,
            "not the right passphrase at all",
            &TimerOnlyWindow,
            &DenyAll,
        )
        .await;
        let UnattendedVerdict::Reject(r) = verdict.unwrap() else {
            panic!("expected Reject");
        };
        assert_eq!(r.reason, reject::AUTH_FAILED);
        let after = env
            .guard
            .store()
            .grant(&env.device)
            .unwrap()
            .fail
            .consecutive;
        assert_eq!(after, before + 1, "the failed attempt was not charged");
    }

    /// Block ends the session before any accept (§B.8.4.5 `Accepting`).
    #[tokio::test]
    async fn block_during_the_window_refuses_after_a_successful_pake() {
        let env = env(PW);
        let (verdict, _) = run(&env, PW, &AlwaysBlock, &DenyAll).await;
        let UnattendedVerdict::Reject(r) = verdict.unwrap() else {
            panic!("expected Reject");
        };
        assert_eq!(r.reason, reject::BLOCKED_BY_LOCAL_USER);
    }

    /// §B.8.6.3: a Block also suspends the grant, `Suspended{LocalBlock}`, through the
    /// guard (logged as the Block and the suspension), until a local Resume; a hook
    /// built without the guard only refuses.
    #[tokio::test]
    async fn a_block_suspends_the_grant_through_the_guard() {
        use tornect_core::session_log::SessionEvent;
        use tornect_core::unattended::grant::{GrantState, SuspendReason};
        let env = env(PW);
        let (verdict, _) = run(&env, PW, &AlwaysBlock, &DenyAll).await;
        let UnattendedVerdict::Reject(r) = verdict.unwrap() else {
            panic!("expected Reject");
        };
        assert_eq!(r.reason, reject::BLOCKED_BY_LOCAL_USER);
        let state = env.guard.store().grant(&env.device).unwrap().state;
        assert!(
            matches!(
                state,
                GrantState::Suspended {
                    reason: SuspendReason::LocalBlock,
                    ..
                }
            ),
            "{state:?}"
        );
        let events: Vec<SessionEvent> = env
            .guard
            .store()
            .log()
            .read_all()
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert!(events.contains(&SessionEvent::UnattendedBlockedByLocalUser));
        assert!(events.contains(&SessionEvent::UnattendedSuspended));
        // The next request is refused before any password exchange.
        let (verdict, _) = run(&env, PW, &TimerOnlyWindow, &DenyAll).await;
        let UnattendedVerdict::Reject(r) = verdict.unwrap() else {
            panic!("expected Reject");
        };
        assert_eq!(r.reason, reject::SUSPENDED);

        // Without the guard: refused, the grant left as it was.
        let mut bare = env_with(PW, Preset::HeadlessBox, &GrantOptions::default());
        bare.auth.block_guard = None;
        let (verdict, _) = run(&bare, PW, &AlwaysBlock, &DenyAll).await;
        let UnattendedVerdict::Reject(r) = verdict.unwrap() else {
            panic!("expected Reject");
        };
        assert_eq!(r.reason, reject::BLOCKED_BY_LOCAL_USER);
        let state = bare.guard.store().grant(&bare.device).unwrap().state;
        assert!(matches!(state, GrantState::Active), "{state:?}");
    }

    /// §B.8.4.5: a newer, freshly signed `SESSION_REQUEST` from the same pk
    /// **cancels** a stale charged handshake instead of being turned away. Without
    /// this a client whose circuit died is locked out for the full 30 s AwaitKe3
    /// timeout, and `PREEMPTED` (0x002A) would never be emitted at all.
    #[tokio::test]
    async fn a_newer_request_preempts_a_stale_charged_handshake() {
        let env = env(PW);
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());

        /// Signals when it reaches AwaitKe3, then blocks until released.
        struct Stalled {
            entered: Arc<Notify>,
            release: Arc<Notify>,
        }
        impl crate::fsm::AuthExchange for Stalled {
            fn challenge<'a>(
                &'a mut self,
                _: AuthChallenge,
            ) -> BoxFuture<'a, Result<(AuthResponse, [u8; 32]), HandshakeError>> {
                Box::pin(async move {
                    self.entered.notify_waiters();
                    // Bounded, so that a build without pre-emption fails this test
                    // cleanly (Timeout != PREEMPTED) instead of hanging forever.
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), self.release.notified()).await;
                    Err(HandshakeError::Timeout("AUTH_RESPONSE"))
                })
            }
        }

        let caps = Caps::default();
        let (state, ke1) = auth::ClientLogin::start(PW).unwrap();
        drop(state);
        let req = request(auth::SUITE_OPAQUE, Some(ke1));

        // Stream 1 reaches AwaitKe3 and stalls there, holding a charged slot.
        let wait_entered = entered.notified();
        let first = async {
            let mut ex = Stalled {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            };
            env.auth
                .handle(UnattendedContext {
                    device: env.device,
                    label: "Laptop",
                    request: &req,
                    th_after_request: TH_REQ,
                    host_pk: HOST_PK,
                    host_caps: &caps,
                    exchange: &mut ex,
                    block_window: &TimerOnlyWindow,
                    local_allow: &DenyAll,
                    activity: &crate::fsm::host::NoSession,
                    audit: &crate::fsm::NoAudit,
                })
                .await
        };

        let (verdict, second) = tokio::join!(first, async {
            // Once stream 1 is charged and waiting, stream 2 arrives.
            wait_entered.await;
            run(&env, PW, &TimerOnlyWindow, &DenyAll).await.0
        });

        let UnattendedVerdict::Reject(r) = verdict.unwrap() else {
            panic!("the stale handshake should have been pre-empted, not accepted");
        };
        assert_eq!(
            r.reason,
            reject::PREEMPTED,
            "a newer verified SESSION_REQUEST must cancel the stale one"
        );
        // §B.8.4.5: "this stream continues through the gate above". The newer
        // stream used to be refused `NOT_GRANTED`, its charge landing on the
        // stale one's while that one had not yet been settled.
        assert_accepted(second, "the pre-empting request");
        release.notify_waiters();
    }

    /// Panics unless `verdict` is an accept, naming the refusal otherwise.
    fn assert_accepted(verdict: Result<UnattendedVerdict, HandshakeError>, what: &str) {
        match verdict {
            Ok(UnattendedVerdict::Accept { .. }) => {}
            Ok(UnattendedVerdict::Reject(r)) => {
                panic!("{what} was refused with 0x{:04x}", r.reason)
            }
            Ok(UnattendedVerdict::Admin { .. }) => panic!("{what} got an admin result"),
            Err(e) => panic!("{what} failed: {e}"),
        }
    }

    /// The same pre-emption with each stream on its own worker thread, as the
    /// host runs them (a task per onion stream on a multi-thread runtime):
    /// the newer stream must not charge on top of the stale one's pending
    /// charge, whichever thread gets there first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_preemption_across_worker_threads_lets_the_newer_request_in() {
        let env = Arc::new(env(PW));
        let entered = Arc::new(Notify::new());

        /// Signals once it reaches AwaitKe3, then waits (bounded) for nothing.
        struct Stalled(Arc<Notify>);
        impl crate::fsm::AuthExchange for Stalled {
            fn challenge<'a>(
                &'a mut self,
                _: AuthChallenge,
            ) -> BoxFuture<'a, Result<(AuthResponse, [u8; 32]), HandshakeError>> {
                Box::pin(async move {
                    self.0.notify_one();
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    Err(HandshakeError::Timeout("AUTH_RESPONSE"))
                })
            }
        }

        let first = tokio::spawn({
            let env = Arc::clone(&env);
            let entered = Arc::clone(&entered);
            async move {
                let caps = Caps::default();
                let (_, ke1) = auth::ClientLogin::start(PW).unwrap();
                let req = request(auth::SUITE_OPAQUE, Some(ke1));
                let mut ex = Stalled(entered);
                let verdict = env
                    .auth
                    .handle(UnattendedContext {
                        device: env.device,
                        label: "Laptop",
                        request: &req,
                        th_after_request: TH_REQ,
                        host_pk: HOST_PK,
                        host_caps: &caps,
                        exchange: &mut ex,
                        block_window: &TimerOnlyWindow,
                        local_allow: &DenyAll,
                        activity: &crate::fsm::host::NoSession,
                        audit: &crate::fsm::NoAudit,
                    })
                    .await;
                match verdict {
                    Ok(UnattendedVerdict::Reject(r)) => Some(r.reason),
                    _ => None,
                }
            }
        });
        entered.notified().await;
        let second = tokio::spawn({
            let env = Arc::clone(&env);
            async move { run(&env, PW, &TimerOnlyWindow, &DenyAll).await.0 }
        })
        .await
        .unwrap();
        assert_accepted(second, "the pre-empting request");
        assert_eq!(first.await.unwrap(), Some(reject::PREEMPTED));
    }

    /// The owner revokes this device's access and grants it again (the same
    /// password) while a pre-empting request waits for the stale handshake
    /// to settle: the newer request is charged on, and runs the PAKE against,
    /// the new grant. Its gate had seen the old grant, and an assertion that
    /// the gate's grant is the charged one panicked the handler in debug
    /// builds (B03 review).
    #[tokio::test]
    async fn a_grant_renewed_while_a_preemption_settles_is_the_one_used() {
        let env = env(PW);
        let old = env.guard.store().grant(&env.device).unwrap().id;
        let entered = Arc::new(Notify::new());

        /// Revokes and grants the device again when dropped: when the stale
        /// handshake, pre-empted, drops its exchange.
        struct Renew {
            guard: Arc<MutationGuard>,
            device: DeviceId,
        }
        impl Drop for Renew {
            fn drop(&mut self) {
                self.guard.revoke(Actor::Cli, &self.device).unwrap();
                let setup =
                    auth::parse_server_setup(&self.guard.store().server_setup().unwrap()).unwrap();
                let record = register_locally(
                    &setup,
                    PW,
                    self.device.public_key_bytes(),
                    auth::identifiers(self.device.public_key_bytes(), &HOST_PK),
                )
                .unwrap();
                self.guard
                    .create_grant(
                        Actor::Cli,
                        &self.device,
                        Preset::HeadlessBox,
                        &GrantOptions::default(),
                        &record,
                        false,
                    )
                    .unwrap();
            }
        }

        /// Signals once it reaches AwaitKe3, then stalls (bounded), holding
        /// the renewal.
        struct Stalled {
            entered: Arc<Notify>,
            renew: Option<Renew>,
        }
        impl crate::fsm::AuthExchange for Stalled {
            fn challenge<'a>(
                &'a mut self,
                _: AuthChallenge,
            ) -> BoxFuture<'a, Result<(AuthResponse, [u8; 32]), HandshakeError>> {
                let renew = self.renew.take();
                Box::pin(async move {
                    let _renew = renew;
                    self.entered.notify_waiters();
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Err(HandshakeError::Timeout("AUTH_RESPONSE"))
                })
            }
        }

        let caps = Caps::default();
        let (state, ke1) = auth::ClientLogin::start(PW).unwrap();
        drop(state);
        let req = request(auth::SUITE_OPAQUE, Some(ke1));
        let wait_entered = entered.notified();
        let first = async {
            let mut ex = Stalled {
                entered: Arc::clone(&entered),
                renew: Some(Renew {
                    guard: Arc::clone(&env.guard),
                    device: env.device,
                }),
            };
            env.auth
                .handle(UnattendedContext {
                    device: env.device,
                    label: "Laptop",
                    request: &req,
                    th_after_request: TH_REQ,
                    host_pk: HOST_PK,
                    host_caps: &caps,
                    exchange: &mut ex,
                    block_window: &TimerOnlyWindow,
                    local_allow: &DenyAll,
                    activity: &crate::fsm::host::NoSession,
                    audit: &crate::fsm::NoAudit,
                })
                .await
        };
        let (verdict, second) = tokio::join!(first, async {
            wait_entered.await;
            run(&env, PW, &TimerOnlyWindow, &DenyAll).await.0
        });

        let UnattendedVerdict::Reject(r) = verdict.unwrap() else {
            panic!("the stale handshake should have been pre-empted");
        };
        assert_eq!(r.reason, reject::PREEMPTED);
        let renewed = env.guard.store().grant(&env.device).unwrap();
        assert_ne!(renewed.id, old, "the grant was renewed");
        assert_accepted(second, "the request after the renewal");
        assert!(!renewed.fail.pending, "its charge is settled");
    }

    /// Records every audit event, for assertions.
    #[derive(Default)]
    struct Recorded(Mutex<Vec<AuditEvent>>);
    impl crate::fsm::HandshakeAudit for Recorded {
        fn record(&self, event: AuditEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    /// Sets its flag when dropped: a card or block window taken down.
    struct Gone(Arc<AtomicBool>);
    impl Drop for Gone {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A block window and an `ask_before_start` popup held open until they are
    /// taken down, saying when one opened.
    #[derive(Default)]
    struct HeldOpen {
        opened: Arc<Notify>,
        gone: Arc<AtomicBool>,
    }
    impl crate::consent::BlockWindow for HeldOpen {
        fn run<'a>(&'a self, _: u8, _: &'a GrantId, _: &'a str) -> BoxFuture<'a, BlockOutcome> {
            Box::pin(async move {
                let _shown = Gone(Arc::clone(&self.gone));
                self.opened.notify_one();
                std::future::pending().await
            })
        }
    }
    impl crate::consent::LocalAllow for HeldOpen {
        fn ask_at<'a>(
            &'a self,
            _: &'a GrantId,
            _: &'a str,
            _: Elevation,
            _: Duration,
        ) -> BoxFuture<'a, bool> {
            Box::pin(async move {
                let _shown = Gone(Arc::clone(&self.gone));
                self.opened.notify_one();
                std::future::pending().await
            })
        }
    }

    /// A real client whose requester leaves once `leave` fires.
    struct Leaving {
        client: RealClient,
        leave: Arc<Notify>,
    }
    impl crate::fsm::AuthExchange for Leaving {
        fn challenge<'a>(
            &'a mut self,
            challenge: AuthChallenge,
        ) -> BoxFuture<'a, Result<(AuthResponse, [u8; 32]), HandshakeError>> {
            self.client.challenge(challenge)
        }

        fn departed<'a>(&'a mut self) -> BoxFuture<'a, HandshakeError> {
            Box::pin(async move {
                self.leave.notified().await;
                HandshakeError::Closed
            })
        }
    }

    /// B04: a requester that leaves after its PAKE while the block window or
    /// the `ask_before_start` popup is up takes it down at once. The window
    /// used to run out and the session be accepted into the dead stream; the
    /// popup stayed until answered. The leave is logged, nothing is
    /// suspended, and the grant is left as it was.
    #[tokio::test]
    async fn a_requester_that_leaves_takes_the_block_window_and_the_popup_down() {
        use tornect_core::unattended::grant::GrantState;
        for ask_before_start in [false, true] {
            let env = env_with(
                PW,
                Preset::HeadlessBox,
                &GrantOptions {
                    ask_before_start: Some(ask_before_start),
                    ..GrantOptions::default()
                },
            );
            assert_eq!(
                env.guard
                    .store()
                    .grant(&env.device)
                    .unwrap()
                    .ask_before_start,
                ask_before_start
            );
            let held = HeldOpen::default();
            let leave = Arc::new(Notify::new());
            let audit = Recorded::default();
            let (state, ke1) = auth::ClientLogin::start(PW).unwrap();
            let mut exchange = Leaving {
                client: RealClient {
                    password: PW.to_owned(),
                    th_after_response: [0x44; 32],
                    client_key: Arc::new(Mutex::new(None)),
                    state: Some(state),
                    ctx: auth::context(&TH_REQ, auth::SUITE_OPAQUE, intent::SESSION),
                    device_pk: *env.device.public_key_bytes(),
                },
                leave: Arc::clone(&leave),
            };
            let req = request(auth::SUITE_OPAQUE, Some(ke1));
            let caps = Caps::default();
            let handshake = env.auth.handle(UnattendedContext {
                device: env.device,
                label: "Laptop",
                request: &req,
                th_after_request: TH_REQ,
                host_pk: HOST_PK,
                host_caps: &caps,
                exchange: &mut exchange,
                block_window: &held,
                local_allow: &held,
                activity: &crate::fsm::host::NoSession,
                audit: &audit,
            });
            // Bounded: without the watch the held window never ends.
            let (verdict, ()) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(handshake, async {
                    held.opened.notified().await;
                    leave.notify_one();
                })
            })
            .await
            .expect("the requester's leaving ended the handshake");
            assert!(
                matches!(verdict, Err(HandshakeError::Closed)),
                "ask_before_start = {ask_before_start}: {:?}",
                verdict.err()
            );
            assert!(held.gone.load(Ordering::SeqCst), "taken down");
            let events = audit.0.lock().unwrap();
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    AuditEvent::RequesterLeft {
                        label: Some(label),
                        popup: SuppressedPopup::Session,
                        ..
                    } if label == "Laptop"
                )),
                "{events:?}"
            );
            let state = env.guard.store().grant(&env.device).unwrap().state;
            assert!(matches!(state, GrantState::Active), "{state:?}");
        }
    }

    /// The cancel is level-triggered: a newer request that pre-empts the stale
    /// handshake after its charge but before it starts waiting in `AwaitKe3`
    /// (on another worker thread, between `mark_charged` and the first poll of
    /// the race) still cancels it. A bare `Notify::notify_waiters` was lost
    /// there, and the stale handshake held the device for its full 30 s.
    #[tokio::test]
    async fn a_preemption_before_the_stale_handshake_waits_still_cancels_it() {
        let env = env(PW);
        let Admit::Ok { slot: stale, .. } = env.auth.admit(&env.device, false) else {
            panic!("the first request is admitted");
        };
        stale.mark_charged();
        let Admit::Ok {
            slot: _newer,
            preempted,
        } = env.auth.admit(&env.device, false)
        else {
            panic!("a newer request pre-empts a charged handshake");
        };
        assert!(preempted.is_some());
        tokio::time::timeout(Duration::from_secs(1), stale.cancelled())
            .await
            .expect("a cancel set before the wait is not lost");
    }

    /// A charge still pending for the device (another handshake of it not
    /// yet settled) is the retryable `UA_BUSY`, never `NOT_GRANTED`: that
    /// answer tells the client that unattended access was never given.
    #[tokio::test]
    async fn a_charge_still_pending_is_answered_busy_never_not_granted() {
        let env = env(PW);
        env.auth.limiter.charge(&env.device).expect("charge");
        let (verdict, _) = run(&env, PW, &TimerOnlyWindow, &DenyAll).await;
        let UnattendedVerdict::Reject(r) = verdict.unwrap() else {
            panic!("a second charge on top of a pending one must not run the PAKE");
        };
        assert_eq!(r.reason, reject::UA_BUSY);
    }

    /// A handshake whose task goes away while it is charged (the stream's
    /// task cancelled, hosting stopped) settles its charge as a failure when
    /// it is dropped. Its charge used to stay pending until the host
    /// restarted, and every later request of the device was refused.
    #[tokio::test]
    async fn a_handshake_dropped_while_charged_settles_its_charge() {
        use tornect_core::session_log::SessionEvent;
        let env = env(PW);

        /// Signals once it reaches AwaitKe3, then never answers.
        struct Hangs(Arc<Notify>);
        impl crate::fsm::AuthExchange for Hangs {
            fn challenge<'a>(
                &'a mut self,
                _: AuthChallenge,
            ) -> BoxFuture<'a, Result<(AuthResponse, [u8; 32]), HandshakeError>> {
                Box::pin(async move {
                    self.0.notify_one();
                    std::future::pending().await
                })
            }
        }

        let entered = Arc::new(Notify::new());
        let caps = Caps::default();
        let (_, ke1) = auth::ClientLogin::start(PW).unwrap();
        let req = request(auth::SUITE_OPAQUE, Some(ke1));
        let mut ex = Hangs(Arc::clone(&entered));
        let handshake = env.auth.handle(UnattendedContext {
            device: env.device,
            label: "Laptop",
            request: &req,
            th_after_request: TH_REQ,
            host_pk: HOST_PK,
            host_caps: &caps,
            exchange: &mut ex,
            block_window: &TimerOnlyWindow,
            local_allow: &DenyAll,
            activity: &crate::fsm::host::NoSession,
            audit: &crate::fsm::NoAudit,
        });
        tokio::select! {
            _ = handshake => panic!("the hanging exchange cannot end the handshake"),
            () = entered.notified() => {}
        }
        // `handshake` is dropped here, charged and in AwaitKe3.
        let grant = env.guard.store().grant(&env.device).unwrap();
        assert!(
            !grant.fail.pending,
            "the dropped handshake's charge is settled"
        );
        let failed: Vec<_> = env
            .guard
            .store()
            .log()
            .read_all()
            .unwrap()
            .into_iter()
            .filter(|r| r.event == SessionEvent::UnattendedAuthFailed)
            .map(|r| r.reason)
            .collect();
        assert_eq!(failed, vec![Some("disconnected".to_owned())]);
        let (verdict, _) = run(&env, PW, &TimerOnlyWindow, &DenyAll).await;
        assert_accepted(verdict, "the next request");
    }

    /// §B.8.5.2 counts "charged `AwaitKe3` streams only". If the slot were held
    /// for the whole handler — through the popup and block window — four accepted
    /// sessions would exhaust the host-wide budget and a fifth login would be
    /// `UA_BUSY` although nothing is in `AwaitKe3`.
    #[tokio::test]
    async fn the_in_flight_slot_is_released_once_the_pake_is_settled() {
        let env = env(PW);
        for i in 0..(budget::MAX_IN_FLIGHT + 2) {
            let (verdict, _) = run(&env, PW, &TimerOnlyWindow, &DenyAll).await;
            assert!(
                matches!(verdict.unwrap(), UnattendedVerdict::Accept { .. }),
                "session {i} was refused: the host-wide slot leaked"
            );
        }
    }

    /// An unknown device never reaches the PAKE: `NOT_GRANTED`, uncharged.
    #[tokio::test]
    async fn an_ungranted_device_is_refused_pre_pake() {
        let env = env(PW);
        let other = DeviceId::from_bytes([0x77; 32]);
        let caps = Caps::default();
        let req = request(auth::SUITE_OPAQUE, Some([0u8; 96]));
        struct NeverCalled;
        impl crate::fsm::AuthExchange for NeverCalled {
            fn challenge<'a>(
                &'a mut self,
                _: AuthChallenge,
            ) -> BoxFuture<'a, Result<(AuthResponse, [u8; 32]), HandshakeError>> {
                panic!("the PAKE ran for an ungranted device");
            }
        }
        let mut exchange = NeverCalled;
        let verdict = env
            .auth
            .handle(UnattendedContext {
                device: other,
                label: "Nope",
                request: &req,
                th_after_request: TH_REQ,
                host_pk: HOST_PK,
                host_caps: &caps,
                exchange: &mut exchange,
                block_window: &TimerOnlyWindow,
                local_allow: &DenyAll,
                activity: &crate::fsm::host::NoSession,
                audit: &crate::fsm::NoAudit,
            })
            .await
            .unwrap();
        let UnattendedVerdict::Reject(r) = verdict else {
            panic!("expected Reject");
        };
        assert_eq!(r.reason, reject::NOT_GRANTED);
    }

    /// A suite this build does not speak is refused pre-PAKE too.
    #[tokio::test]
    async fn an_unsupported_suite_is_refused_pre_pake() {
        let env = env(PW);
        let (verdict, _) = {
            let caps = Caps::default();
            let req = request(2, None);
            struct NeverCalled;
            impl crate::fsm::AuthExchange for NeverCalled {
                fn challenge<'a>(
                    &'a mut self,
                    _: AuthChallenge,
                ) -> BoxFuture<'a, Result<(AuthResponse, [u8; 32]), HandshakeError>>
                {
                    panic!("the PAKE ran for an unsupported suite");
                }
            }
            let mut exchange = NeverCalled;
            (
                env.auth
                    .handle(UnattendedContext {
                        device: env.device,
                        label: "Laptop",
                        request: &req,
                        th_after_request: TH_REQ,
                        host_pk: HOST_PK,
                        host_caps: &caps,
                        exchange: &mut exchange,
                        block_window: &TimerOnlyWindow,
                        local_allow: &DenyAll,
                        activity: &crate::fsm::host::NoSession,
                        audit: &crate::fsm::NoAudit,
                    })
                    .await,
                None::<Vec<u8>>,
            )
        };
        let UnattendedVerdict::Reject(r) = verdict.unwrap() else {
            panic!("expected Reject");
        };
        assert_eq!(r.reason, reject::UNSUPPORTED_SUITE);
    }
}
