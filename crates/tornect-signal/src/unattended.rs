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
use tornect_core::levels::{Elevation, FactsSource, Level, clause_ii, served_mode};
use tornect_core::session_log::SessionMode;
use tornect_core::unattended::grant::{AuthRecord, GrantId, UnattendedGrant};
use tornect_core::unattended::guard::{AdminEffect, AdminOp, AdminOutcome, MutationGuard};
use tornect_core::unattended::limiter::{
    AttemptLimiter, FailKind, HostTransport, LimiterError, PostF2Reject, Reject, Settle,
};
use tornect_core::unattended::readiness::{Probe, ReadinessSnapshot};
use tornect_core::unattended::schedule::LocalTz;

use crate::auth;
use crate::consent::{
    BlockOutcome, ChosenCaps, ConsentProof, DerivedToken, PolicyReceipt, TransportPolicy,
};
use crate::fsm::HandshakeError;
use crate::fsm::host::{
    KillSwitch, StopTokenCheck, UnattendedContext, UnattendedHook, UnattendedVerdict,
};
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

/// One device's in-flight `AwaitKe3` handshake, as the budget table sees it.
#[derive(Debug)]
struct Slot {
    /// Fired when a newer, freshly signed `SESSION_REQUEST` pre-empts this
    /// handshake (§B.8.4.5).
    cancel: Arc<Notify>,
    /// Set once the charge is on disk and KE2 is about to go out. Until then the
    /// stream is "between F1 and KE2 written" and a newer one is answered
    /// `UA_BUSY` instead of pre-empting it (§B.8.4.5).
    charged: Arc<AtomicBool>,
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
    cancel: Arc<Notify>,
    charged: Arc<AtomicBool>,
}

impl InFlight {
    /// The charge is on disk; from here a newer request may pre-empt this stream.
    fn mark_charged(&self) {
        self.charged.store(true, Ordering::SeqCst);
    }

    /// Resolves when a newer, freshly signed `SESSION_REQUEST` pre-empts us.
    async fn cancelled(&self) {
        self.cancel.notified().await;
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
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
    /// Proceed; hold this slot until the handshake ends.
    Ok(InFlight),
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
    /// Run `op` for `requester`, or refuse it.
    fn execute(&self, requester: &DeviceId, op: AdminOp) -> AdminOutcome;
}

/// The default: this host executes no remote admin commands.
///
/// Answering `ok: false` is the honest response — the requester proved its
/// password and is entitled to know its command did not run.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseAdmin;

impl AdminAuthority for RefuseAdmin {
    fn execute(&self, _requester: &DeviceId, _op: AdminOp) -> AdminOutcome {
        AdminOutcome {
            ok: false,
            detail: Some("remote administration is not enabled on this host".to_owned()),
            effect: AdminEffect::None,
        }
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
    fn execute(&self, requester: &DeviceId, op: AdminOp) -> AdminOutcome {
        match self.guard.admin(requester, op) {
            Ok(outcome) => outcome,
            Err(e) => {
                // A store-level failure (locked keystore, store lock held, I/O)
                // is not a scope refusal. It is reported as a plain failure with
                // the guard's own code so the client can tell "you may not" from
                // "the host could not". `Err` means the command took no effect —
                // `MutationGuard::admin` treats every write after a commit as
                // best-effort — so `AdminEffect::None` is the truth, not a loss;
                // the guard logs the attempt as a failed `AdminRequest`.
                tracing::warn!(peer = ?requester, op = op.name(), error = %e, "admin command failed");
                AdminOutcome {
                    ok: false,
                    detail: Some(format!(
                        "host could not apply the command (0x{:04x})",
                        e.code()
                    )),
                    effect: AdminEffect::None,
                }
            }
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

/// The real §B.8 hook.
pub struct UnattendedAuth {
    limiter: AttemptLimiter,
    budgets: Arc<Mutex<Budgets>>,
    tz: Arc<dyn LocalTz>,
    host_transport: HostTransport,
    /// M1: the all-unknown stub (§B.8.14). M6 fills this from `tornect-platform`.
    readiness: ReadinessSnapshot,
    /// Executes `intent = admin` requests (§B.8.4.1). Refuses by default.
    admin: Arc<dyn AdminAuthority>,
    /// The account facts and the helper task's presence, read at each answer
    /// (decision M1-67).
    facts: Arc<dyn FactsSource>,
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
            admin: Arc::new(RefuseAdmin),
            facts,
        }
    }

    /// Override the readiness snapshot (M6 / tests).
    #[must_use]
    pub fn with_readiness(mut self, readiness: ReadinessSnapshot) -> Self {
        self.readiness = readiness;
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
        if let Some(existing) = b.in_flight.get(device) {
            if !existing.charged.load(Ordering::SeqCst) {
                return Admit::Busy;
            }
            existing.cancel.notify_waiters();
        } else if b.in_flight.len() >= budget::MAX_IN_FLIGHT
            || b.challenges.len() >= budget::MAX_PER_MINUTE
        {
            return Admit::Busy;
        }
        let cancel = Arc::new(Notify::new());
        let charged = Arc::new(AtomicBool::new(false));
        b.in_flight.insert(
            *device,
            Slot {
                cancel: Arc::clone(&cancel),
                charged: Arc::clone(&charged),
                since: now,
            },
        );
        b.challenges.push(now);
        Admit::Ok(InFlight {
            device: *device,
            budgets: Arc::clone(&self.budgets),
            cancel,
            charged,
        })
    }

    /// The readiness gate of §B.8.14: `Unknown` never blocks in M1 (fail-open
    /// with a badge); a `Fail` on one of the four load-bearing probes blocks
    /// with `HOST_NOT_READY` and the documented `cause`.
    fn readiness_reject(&self) -> Option<SessionReject> {
        let r = &self.readiness;
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

/// Map a post-F2 policy refusal onto its wire body.
fn post_f2_reject(r: PostF2Reject) -> SessionReject {
    let mut out = SessionReject::new(r.code());
    out.next_open_in_s = match r {
        PostF2Reject::NotYetActive { next_open_in_s } => Some(next_open_in_s),
        PostF2Reject::OutsideSchedule { next_open_in_s } => next_open_in_s,
        _ => None,
    };
    out
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

    /// Decision M1-67 (B, D10, D11): after the reservation, the account facts and the
    /// helper task are read again and the session lowered where F-12 or the marked rule
    /// says so, as at the gate: a setting changed since the gate counts. Lowering only.
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
            let reach_through_host = clause_ii(
                policy.mode(),
                some_grant_holds_level(),
                account,
                self.facts.helper_task(),
            );
            // A grant gone since the gate reads as marked: the safe direction.
            let marked = self
                .limiter
                .store()
                .grant(device)
                .is_none_or(|grant| marked(&grant));
            let level = Level::new(policy.mode(), policy.elevation());
            let served = served_mode(level, marked, reach_through_host, account);
            Ok(ConsentProof::Unattended {
                grant,
                proof_fp,
                policy: policy.lowered_to(served),
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
        let gate = match self.limiter.gate(&device, req.suite, SUPPORTED_SUITES) {
            Ok(ok) => ok,
            Err(r) => {
                let hard = r.code() == reject::HARD_LOCKED;
                if hard && matches!(self.admit(&device, true), Admit::Silent) {
                    // §B.8.5.2: closed without any frame, nothing charged.
                    return Err(HandshakeError::Closed);
                }
                return Ok(UnattendedVerdict::Reject(gate_reject(r)));
            }
        };

        // ---- host-wide budgets (§B.8.5.2) ----
        let slot = match self.admit(&device, false) {
            Admit::Ok(slot) => slot,
            Admit::Busy | Admit::Silent => {
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::UA_BUSY,
                )));
            }
        };

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
            Err(LimiterError::Refused(r) | LimiterError::Locked(r)) => {
                return Ok(UnattendedVerdict::Reject(gate_reject(r)));
            }
            Err(_) => {
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::NOT_GRANTED,
                )));
            }
        };
        debug_assert_eq!(charged.grant_id, gate.grant_id);
        // The charge is on disk: from here a newer verified `SESSION_REQUEST`
        // from this pk pre-empts us rather than being answered `UA_BUSY`.
        slot.mark_charged();

        let (host_login, ke2) =
            match auth::HostLogin::start(&setup, &stored, ke1, &device_pk, &ctx_bytes, ids) {
                Ok(v) => v,
                Err(e) => {
                    let _ = self.limiter.settle(&device, Settle::Fail(FailKind::BadKe3));
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
                let _ = self
                    .limiter
                    .settle(&device, Settle::Fail(FailKind::Preempted));
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::PREEMPTED,
                )));
            }
            r = exchange => match r {
                Ok(v) => v,
                Err(e) => {
                    // Settle first, then hand the transport error back unchanged so
                    // `serve_host` reports the code §B.8.4.5 documents.
                    let _ = self.limiter.settle(&device, Settle::Fail(fail_kind(&e)));
                    return Err(e);
                }
            },
        };

        let Some(ke3) = response.ke3.as_ref() else {
            let _ = self.limiter.settle(&device, Settle::Fail(FailKind::BadKe3));
            return Ok(UnattendedVerdict::Reject(SessionReject::new(
                reject::AUTH_FAILED,
            )));
        };

        let session_key = match host_login.finish(ke3, &ctx_bytes, ids) {
            Ok(k) => k,
            Err(_) => {
                let _ = self.limiter.settle(&device, Settle::Fail(FailKind::BadKe3));
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::AUTH_FAILED,
                )));
            }
        };

        // ---- F2 reached: settle, then the post-PAKE policy checks ----
        let fail_summary = self.limiter.settle(&device, Settle::Ok).unwrap_or(None);
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
            return Ok(self.run_admin(&device, req.admin.as_ref()));
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

        // ---- ask_before_start, then the block window ----
        let label = ctx.label;
        if grant.ask_before_start
            && !ctx
                .local_allow
                .ask(&grant.id, label, Duration::from_secs(60))
                .await
        {
            return Ok(UnattendedVerdict::Reject(SessionReject::new(
                reject::DENIED,
            )));
        }

        let block = match ctx
            .block_window
            .run(grant.block_window_s, &grant.id, label)
            .await
        {
            BlockOutcome::Passed(w) => w,
            BlockOutcome::Blocked => {
                return Ok(UnattendedVerdict::Reject(SessionReject::new(
                    reject::BLOCKED_BY_LOCAL_USER,
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
        // `want_elevation` the same way (r7, §B.8.4.1): the most restrictive
        // of the grant's level, the request and what this host delivers. A
        // grant carries no elevation before §B.8.7.1's setup exists
        // (M-FEAT-5), so an unattended session is at none for now.
        let want_elevation = req
            .want_elevation
            .and_then(Elevation::from_code)
            .unwrap_or(Elevation::None);
        let level =
            Level::new(grant.mode, Elevation::None).clamp(wanted, want_elevation, Elevation::None);
        debug_assert_eq!(
            level.mode(),
            SessionMode::most_restrictive(grant.mode, wanted)
        );
        // Decision M1-67 (D10, D11): the account facts and the helper task are read
        // now, never cached from start, and control is lowered to view only where it
        // is administrator access here (F-12) or where the password is marked and
        // clause (ii) holds, before any helper starts. Lowering only.
        let account = self.facts.account();
        let reach_through_host = clause_ii(
            grant.mode,
            some_grant_holds_level(),
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
            self.readiness.clone(),
            fail_summary.map(wire_fail_summary),
        )
        .with_elevation(level.elevation());

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

/// Whether some grant in the store holds the administrator level (clause (ii)). No grant
/// can until the store keeps a grant's level (key 24).
fn some_grant_holds_level() -> bool {
    false
}

impl UnattendedAuth {
    /// The `intent = admin` branch (§B.8.4.1), reached only after F2.
    fn run_admin(&self, device: &DeviceId, cmd: Option<&messages::AdminCmd>) -> UnattendedVerdict {
        /// One shape for every refusal so a client cannot tell "unknown op" from
        /// "out of scope" by the message shape alone; the guard logs the real
        /// reason host-side.
        fn refused(detail: &str) -> UnattendedVerdict {
            UnattendedVerdict::Admin {
                result: messages::AdminResult {
                    ok: false,
                    detail: Some(detail.to_owned()),
                    grant_reach: None,
                },
                effect: AdminEffect::None,
            }
        }

        // `admin` is required iff `intent = 1`, and `SessionRequest`'s decoder
        // already answers `E_BAD_LEN` for the three other combinations — so
        // `None` is unreachable from the wire. Refused rather than unwrapped:
        // a caller building the type directly must not get a panic.
        let Some(cmd) = cmd else {
            return refused("admin command missing");
        };
        // An unknown op, or a `device_pk` present for an op that takes none (or
        // absent for one that needs it). Not an `ERROR`: the frame decoded
        // cleanly, so this is a command the host will not run, reported the way
        // every other such command is.
        let Some(op) = AdminOp::from_wire(cmd.op, cmd.device_pk) else {
            return refused("unknown admin command");
        };
        let outcome = self.admin.execute(device, op);
        tracing::info!(
            peer = ?device,
            op = op.name(),
            ok = outcome.ok,
            "admin command"
        );
        // No `ADMIN_RESULT` carries `grant_reach` yet: it is signed only from the
        // requester's grant read under the lock of the command (decision M1-67).
        UnattendedVerdict::Admin {
            result: messages::AdminResult {
                ok: outcome.ok,
                detail: outcome.detail,
                grant_reach: None,
            },
            effect: outcome.effect,
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

    /// Denies every `ask_before_start` popup.
    struct DenyAll;
    impl crate::consent::LocalAllow for DenyAll {
        fn ask<'a>(&'a self, _: &'a GrantId, _: &'a str, _: Duration) -> BoxFuture<'a, bool> {
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
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        std::fs::create_dir_all(paths.keys_dir()).unwrap();
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        let clock = Arc::new(SystemClock::default());
        let log = SessionLog::new(paths.sessions_log());
        let store = GrantStore::open(&paths, secrets, clock, log).unwrap();

        let guard = MutationGuard::new(
            store,
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
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
            .create_grant(Actor::Cli, &device, preset, options, &[0u8; 192])
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
            .set_password(Actor::Cli, &device, &record)
            .expect("set_password");

        let guard = Arc::new(guard);
        let limiter = AttemptLimiter::new(guard.store().clone());
        let auth = UnattendedAuth::new(
            limiter,
            Arc::new(tornect_core::unattended::schedule::FixedOffset::utc()),
            HostTransport::default(),
            Arc::new(tornect_core::levels::FixedFacts::linux()),
        );
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

    /// M1-67: no `ADMIN_RESULT` carries `grant_reach` yet, the two early refusals
    /// included (a missing command, unreachable from the wire, and an unknown one).
    #[test]
    fn the_early_admin_refusals_carry_no_grant_reach_yet() {
        let env = env(PW);
        let unknown = messages::AdminCmd {
            op: 0xEE,
            device_pk: None,
        };
        for cmd in [None, Some(&unknown)] {
            let UnattendedVerdict::Admin { result, .. } = env.auth.run_admin(&env.device, cmd)
            else {
                panic!("expected ADMIN_RESULT");
            };
            assert!(!result.ok);
            assert_eq!(result.grant_reach, None);
        }
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
                })
                .await
        };

        let (verdict, ()) = tokio::join!(first, async {
            // Once stream 1 is charged and waiting, stream 2 arrives.
            wait_entered.await;
            let (_, second) = run(&env, PW, &TimerOnlyWindow, &DenyAll).await;
            let _ = second;
        });

        let UnattendedVerdict::Reject(r) = verdict.unwrap() else {
            panic!("the stale handshake should have been pre-empted, not accepted");
        };
        assert_eq!(
            r.reason,
            reject::PREEMPTED,
            "a newer verified SESSION_REQUEST must cancel the stale one"
        );
        release.notify_waiters();
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
