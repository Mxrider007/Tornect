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
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use std::sync::Mutex;
use tornect_core::id::DeviceId;
use tornect_core::session_log::SessionMode;
use tornect_core::unattended::grant::{AuthRecord, GrantId};
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
use crate::fsm::host::{UnattendedContext, UnattendedHook, UnattendedVerdict};
use crate::messages::{self, AuthChallenge, SessionReject, intent, mode, reject};

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

/// The host-wide budget counters of §B.8.5.2.
#[derive(Debug, Default)]
struct Budgets {
    /// Devices with a charged `AwaitKe3` handshake in flight (≤ 1 per pk).
    in_flight: HashMap<DeviceId, Instant>,
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
        self.hard_locked_answered
            .retain(|_, t| now.duration_since(*t) < Duration::from_secs(budget::HARD_LOCK_QUIET_S));
    }
}

/// A charged in-flight slot; releases itself on drop so every early return,
/// `?` and panic unwinds the host-wide counter (§B.8.5.2).
struct InFlight {
    device: DeviceId,
    budgets: Arc<Mutex<Budgets>>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Ok(mut b) = self.budgets.lock() {
            b.in_flight.remove(&self.device);
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

/// The real §B.8 hook.
pub struct UnattendedAuth {
    limiter: AttemptLimiter,
    budgets: Arc<Mutex<Budgets>>,
    tz: Arc<dyn LocalTz>,
    host_transport: HostTransport,
    /// M1: the all-unknown stub (§B.8.14). M6 fills this from `tornect-platform`.
    readiness: ReadinessSnapshot,
}

impl UnattendedAuth {
    /// Build the hook over a loaded grant store.
    #[must_use]
    pub fn new(
        limiter: AttemptLimiter,
        tz: Arc<dyn LocalTz>,
        host_transport: HostTransport,
    ) -> Self {
        Self {
            limiter,
            budgets: Arc::new(Mutex::new(Budgets::default())),
            tz,
            host_transport,
            readiness: ReadinessSnapshot::unknown(),
        }
    }

    /// Override the readiness snapshot (M6 / tests).
    #[must_use]
    pub fn with_readiness(mut self, readiness: ReadinessSnapshot) -> Self {
        self.readiness = readiness;
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
        if b.in_flight.contains_key(device)
            || b.in_flight.len() >= budget::MAX_IN_FLIGHT
            || b.challenges.len() >= budget::MAX_PER_MINUTE
        {
            return Admit::Busy;
        }
        b.in_flight.insert(*device, now);
        b.challenges.push(now);
        Admit::Ok(InFlight {
            device: *device,
            budgets: Arc::clone(&self.budgets),
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
        let _slot = match self.admit(&device, false) {
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

        let (host_login, ke2) =
            match auth::HostLogin::start(&setup, &stored, ke1, &device_pk, &ctx_bytes, ids) {
                Ok(v) => v,
                Err(e) => {
                    let _ = self.limiter.settle(&device, Settle::Fail(FailKind::BadKe3));
                    tracing::warn!(peer = %device, error = %e, "ServerLogin::start failed");
                    return Ok(UnattendedVerdict::Reject(SessionReject::new(
                        reject::AUTH_FAILED,
                    )));
                }
            };

        // ---- AwaitKe3 (30 s, charged) ----
        let (response, th_after_response) = match ctx
            .exchange
            .challenge(AuthChallenge {
                suite: req.suite,
                ke2: Some(ke2),
                salt: None,
                pb: None,
            })
            .await
        {
            Ok(v) => v,
            Err(e) => {
                // Settle first, then hand the transport error back unchanged so
                // `serve_host` reports the code §B.8.4.5 documents.
                let _ = self.limiter.settle(&device, Settle::Fail(fail_kind(&e)));
                return Err(e);
            }
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

        let post = match self
            .limiter
            .post_f2(&device, &*self.tz, self.host_transport)
        {
            Ok(ok) => ok,
            Err(r) => return Ok(UnattendedVerdict::Reject(post_f2_reject(r))),
        };

        // ---- admin intent terminates here, in place of SESSION_ACCEPT ----
        if req.intent == intent::ADMIN {
            let detail = req
                .admin
                .as_ref()
                .map(|_| "not implemented at M1".to_owned());
            return Ok(UnattendedVerdict::Admin(messages::AdminResult {
                ok: false,
                detail,
            }));
        }

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
        let session_mode = SessionMode::most_restrictive(grant.mode, wanted);

        let policy = PolicyReceipt::mint(
            grant.id,
            session_mode,
            wire_transport(post.transport),
            post.ends_at,
            grant.block_window_s,
            grant.ask_before_start,
            self.readiness.clone(),
            fail_summary.map(wire_fail_summary),
        );

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
        guard: MutationGuard,
        device: DeviceId,
        auth: UnattendedAuth,
    }

    fn env(password: &str) -> Env {
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
        guard.master_on(Actor::Cli, &HOST_PK).expect("master_on");
        // Bootstrap happens inside create_grant; the setup must exist first, so
        // register against the setup the store ends up holding.
        // `HeadlessBox` waives the §B.8.6 "prior attended session" precondition,
        // which no in-process test can satisfy. The record is replaced by the real
        // one below; this first call exists to bootstrap the store (and with it the
        // `ServerSetup` the registration must run against).
        guard
            .create_grant(
                Actor::Cli,
                &device,
                Preset::HeadlessBox,
                &GrantOptions::default(),
                &[0u8; 192],
            )
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

        let limiter = AttemptLimiter::new(guard.store().clone());
        let auth = UnattendedAuth::new(
            limiter,
            Arc::new(tornect_core::unattended::schedule::FixedOffset::utc()),
            HostTransport::default(),
        );
        Env {
            _tmp: tmp,
            guard,
            device,
            auth,
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
