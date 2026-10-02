//! The host-side handshake FSM (`docs/PLAN.md` §B.2, §B.8.4.2, §B.8.4.5).
//!
//! ```text
//! Start ──HELLO (sig vs its own pk; pinned?)──► HelloVerified ──HELLO_ACK──►
//!   unpaired: PairRequested ──Consent::pairing (60 s)──► PairAccepted | PairRejected
//!   pinned: AwaitSessionRequest (60 s), or a re-pair through the same popup (label kept)
//!   paired / just paired: AwaitSessionRequest (60 s) ──SESSION_REQUEST (sig over th)──►
//!     unattended: UnattendedHook (M1: NOT_GRANTED)      attended: AwaitConsent (60 s)
//!   ──SESSION_ACCEPT (built only through SessionAccept::build)──► Established ──BYE──► Closing
//! ```
//!
//! Everything that needs a human, a store or a policy is an injected seam
//! ([`HostDeps`]); the FSM itself is pure protocol. Every wait is bounded by
//! [`super::timeouts`]; every violation answers `ERROR` once and closes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::time::Instant;
use tornect_core::DeviceId;
use tornect_core::levels::{AdminPath, Answers, Availability, Elevation, Level};
use tornect_core::session_log::SessionMode;
use tornect_core::unattended::guard::{AdminEffect, EndScope, RemoteSessionActivity};
use zeroize::Zeroizing;

use super::{
    AuditEvent, AuthExchange, CandidateSink, Channel, HandshakeAudit, HandshakeError, HelperEvent,
    IgnoreCandidates, NoAudit, OsRandom, Randomness, Received, SessionToken, SuppressedPopup,
    checked_body, timeouts,
};
use crate::consent::{
    AcceptHostInfo, AlwaysDeny, BlockWindow, ChosenCaps, ConsentProof, FreshToken, LocalAllow,
    PopupChoice, TimerOnlyWindow, TransportPolicy, mode_from_code,
};
use crate::envelope::{Kind, codes};
use crate::framing::FrameError;
use crate::messages::{
    self, AdminResult, Bye, Caps, Hello, HelloAck, PairAccept, PairReject, PairRequest, Ping, Pong,
    SessionAccept, SessionReject, SessionRequest, clamp_feats, ed25519_spki,
};
use crate::pairing::{
    AutoDeny, BoxFuture, Consent, PairDecision, PairRefusal, PairingLimits, PairingPeer,
    PairingPolicy, SessionDecision, SessionRequestSummary, TrustedDeviceStore, TrustedPeer,
    normalize_label,
};
use crate::transcript::{HostSigner, verify_envelope};

/// Static facts about this host.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// The name sent in `PAIR_ACCEPT` (after consent, never before).
    pub host_name: String,
    /// The host's *device* key: its identity as a client, pinned by the peer
    /// at pairing (`PAIR_ACCEPT.host_device_pk`) and the SPKI it presents as
    /// its QUIC identity (`SESSION_ACCEPT.quic_spki`, §B.6, decision M1-31).
    pub host_device_pk: [u8; 32],
    /// Host-wide feature tokens for `HELLO_ACK.feats` (independent of the
    /// peer; brought within the wire bounds by [`clamp_feats`] when sent).
    pub feats: Vec<String>,
    /// What this host can stream.
    pub caps: Caps,
    /// The privacy mode as a transport policy (attended sessions).
    pub transport_policy: TransportPolicy,
    /// `BYE{ORPHANED}` when no `CANDIDATES` / `CANDIDATES_DONE` /
    /// `TOR_FALLBACK` arrives within this after the accept (§B.8.4.5, 15 s).
    /// `PING`s do not count: a Tor-only exchange such as the M1 `tornect ping`
    /// flow must send `TOR_FALLBACK{}` right after the accept
    /// (`ClientSession::send_tor_fallback`) or the host sets this to `None`.
    /// A value near `Duration::MAX` means "never" (no overflow).
    pub orphan_timeout: Option<Duration>,
    /// `BYE{ORPHANED}` when an established stream stays silent this long
    /// (a value near `Duration::MAX` means "never").
    pub idle_timeout: Duration,
    /// This host's row of the §B.2.1 availability table (r7): the answers
    /// the session sheet offers ([`Availability::offered`]). An answer
    /// outside them is refused (`DENIED`), never lowered or raised.
    pub levels: Availability,
}

impl HostConfig {
    /// Defaults: no feats, empty caps, `Any` transport, the §B.8.4.5 orphan
    /// timer, 90 s idle, the Linux row of the availability table (no
    /// administrator level).
    #[must_use]
    pub fn new(host_name: impl Into<String>, host_device_pk: [u8; 32]) -> Self {
        Self {
            host_name: host_name.into(),
            host_device_pk,
            feats: Vec::new(),
            caps: Caps::default(),
            transport_policy: TransportPolicy::Any,
            orphan_timeout: Some(timeouts::ORPHAN),
            idle_timeout: timeouts::ESTABLISHED_IDLE,
            levels: Availability::default(),
        }
    }
}

/// Sees every `HELLO.stop_token` (§B.8.7.4). The M1 default never matches;
/// the unattended track compares in constant time against the stored token
/// and, on a match, turns unattended access off, revokes every grant and
/// kills live sessions. The FSM's own path never depends on the outcome, so
/// the unpaired path stays byte-identical (A13).
pub trait StopTokenCheck: Send + Sync {
    /// Observe a presented token.
    fn observe<'a>(&'a self, token: &'a [u8; 32]) -> BoxFuture<'a, ()>;
}

/// Ignores every token (no stop code enabled).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoStopToken;

impl StopTokenCheck for NoStopToken {
    fn observe<'a>(&'a self, _: &'a [u8; 32]) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

/// Whether a remote session is live right now (popups are suppressed while
/// one is, §B.8.16 ⇒ `PAIR_REJECT{BUSY}` / `SESSION_REJECT{BUSY}`).
pub trait SessionActivity: Send + Sync {
    /// `true` while a remote session is live on this host, or reserved by
    /// [`try_reserve`](Self::try_reserve).
    fn session_live(&self) -> bool;

    /// The one-session gate (§B.8.6.4): `false` while a session is live or
    /// reserved; otherwise reserve one and `true`. The reservation counts as
    /// live until [`release`](Self::release), and the host releases it only
    /// once the session is registered through [`SessionSink::on_start`], or
    /// never started.
    ///
    /// A source that can see sessions start concurrently must check and
    /// reserve in one step (SLICE-C3 C3-1): the accept write between the check
    /// and `on_start` can take up to 30 s. The default, which cannot, is for
    /// sources that are constant.
    fn try_reserve(&self) -> bool {
        !self.session_live()
    }

    /// Let go of a reservation [`try_reserve`](Self::try_reserve) took.
    fn release(&self) {}
}

/// A session slot reserved by [`SessionActivity::try_reserve`]; dropping it
/// releases the slot, however the accept ends (a failed write, a cancelled task).
struct Reserved<'a>(&'a dyn SessionActivity);

impl<'a> Reserved<'a> {
    fn take(activity: &'a dyn SessionActivity) -> Option<Self> {
        activity.try_reserve().then_some(Self(activity))
    }
}

impl Drop for Reserved<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// No session is ever live (offline CLI, tests).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSession;

impl SessionActivity for NoSession {
    fn session_live(&self) -> bool {
        false
    }
}

/// What the unattended handler gets to decide on (§B.8.4.2 gate).
pub struct UnattendedContext<'a> {
    /// The signature-verified device key.
    pub device: DeviceId,
    /// The pinned label.
    pub label: &'a str,
    /// The verified request (`unattended` is `Some`).
    pub request: &'a SessionRequest,
    /// `th_after(SESSION_REQUEST)`, the `context` input of §B.8.4.3.
    pub th_after_request: [u8; 32],
    /// The host onion public key.
    pub host_pk: [u8; 32],
    /// The host's advertised caps, to intersect with the client's (§B.2).
    pub host_caps: &'a Caps,
    /// The channel for `AUTH_CHALLENGE` / `AUTH_RESPONSE`.
    pub exchange: &'a mut dyn AuthExchange,
    /// The block window of §B.8.4.5 `Accepting` (`HostDeps::block_window`).
    pub block_window: &'a dyn BlockWindow,
    /// The `ask_before_start` popup of §B.8.4.5 `AwaitLocalAllow` (`HostDeps::local_allow`).
    pub local_allow: &'a dyn LocalAllow,
}

/// What the unattended handler decided.
pub enum UnattendedVerdict {
    /// Send `SESSION_REJECT` and close (skipped, but still logged, when the
    /// stream already died in an `ERROR`-class violation — the `AwaitKe3`
    /// row of §B.8.4.5).
    Reject(SessionReject),
    /// Send a signed `SESSION_ACCEPT` built from `proof` and go on to `Established`.
    Accept {
        /// The consent proof (`ConsentProof::Unattended`).
        proof: ConsentProof,
        /// The negotiated caps.
        caps: ChosenCaps,
    },
    /// Send a signed `ADMIN_RESULT` and close, then apply `effect` to live
    /// sessions.
    Admin {
        /// The result to sign and send.
        result: AdminResult,
        /// What the command did, for the caller to apply to live sessions
        /// (§B.8.4.1). Separated from `result` because the wire answer and the
        /// local side effect have different audiences: the client is told
        /// whether its command ran, the host is told what to tear down.
        effect: AdminEffect,
    },
}

/// The §B.8 seam: fills the `HelloVerified → SESSION_REQUEST{unattended}`
/// branch. The M1 default answers `NOT_GRANTED`; the unattended track
/// replaces it with the grant lookup, limiter and OPAQUE exchange.
///
/// A [`HandshakeError`] from the `AUTH_CHALLENGE` / `AUTH_RESPONSE` exchange
/// (timeout, `E_BAD_STATE` for a `PING` in `AwaitKe3`, peer `BYE` / `ERROR`,
/// EOF) is returned as is — after the handler settled its charge as a
/// failure — so [`serve_host`] reports the code that P1 and the §B.8.4.5
/// table describe instead of a synthetic reject on a dead stream.
pub trait UnattendedHook: Send + Sync {
    /// Decide on an unattended request.
    fn handle<'a>(
        &'a self,
        ctx: UnattendedContext<'a>,
    ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>>;

    /// After the session's reservation and before its `SESSION_ACCEPT` is built
    /// (decision M1-67): read afresh what can lower the session `device` asked
    /// for, and give back `proof` lowered where that says so, never above it, or
    /// refuse the request. Never called while the live-session lock is held.
    fn reserved<'a>(
        &'a self,
        device: &'a DeviceId,
        proof: ConsentProof,
    ) -> BoxFuture<'a, Result<ConsentProof, SessionReject>>;
}

/// `SESSION_REJECT{NOT_GRANTED}` for every unattended request (no grants exist).
#[derive(Debug, Clone, Copy, Default)]
pub struct NotGranted;

impl UnattendedHook for NotGranted {
    fn reserved<'a>(
        &'a self,
        _: &'a DeviceId,
        _: ConsentProof,
    ) -> BoxFuture<'a, Result<ConsentProof, SessionReject>> {
        // Never reached: no request of this hook is accepted.
        Box::pin(async { Err(SessionReject::new(messages::reject::NOT_GRANTED)) })
    }

    fn handle<'a>(
        &'a self,
        _: UnattendedContext<'a>,
    ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
        Box::pin(async {
            Ok(UnattendedVerdict::Reject(SessionReject::new(
                messages::reject::NOT_GRANTED,
            )))
        })
    }
}

/// One-click kill for established sessions: [`kill`](Self::kill) makes every
/// session that was live when it fired send `BYE{reason}` and close.
///
/// **Host-wide (M1 scope, §B.8.4.1).** It carries one reason to every stream
/// sharing these deps and cannot address a single device.
///
/// **It does not latch.** A session snapshots the kill generation when it
/// [`arm`](Self::arm)s (at accept time); its [`KillGuard`] fires only for a
/// `kill` with a newer generation — one that happened after it armed. A reason
/// left behind by an earlier session therefore never ends a session accepted
/// later, so a host that was master-off or paused and is turned back on serves
/// new sessions without the switch having to be reset. [`fired`](Self::fired)
/// still reports the most recent reason, for status and tests.
#[derive(Debug, Clone)]
pub struct KillSwitch {
    tx: Arc<watch::Sender<KillState>>,
}

/// The watched state behind a [`KillSwitch`].
#[derive(Debug, Clone, Default)]
struct KillState {
    /// Bumped by every [`KillSwitch::kill`]. A [`KillGuard`] compares this to
    /// the value it captured at arm time, so it reacts only to a kill fired
    /// after the session began — never to a stale latched reason.
    generation: u64,
    /// The reason the most recent kill fired with (for [`KillSwitch::fired`]).
    reason: Option<u16>,
    /// Per device, how many times [`KillSwitch::end_device`] ended its sessions
    /// (decision M1-67, D6).
    devices: std::collections::HashMap<DeviceId, DeviceEnds>,
}

/// One device's count of ends, per [`EndScope`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DeviceEnds {
    every: u64,
    at_the_level: u64,
}

impl KillState {
    fn ends_of(&self, device: &DeviceId) -> DeviceEnds {
        self.devices.get(device).copied().unwrap_or_default()
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

impl KillSwitch {
    /// A switch that has not fired.
    #[must_use]
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(KillState::default());
        Self { tx: Arc::new(tx) }
    }

    /// Fire with a [`messages::bye`] reason. Ends every currently-armed
    /// session; a session armed after this call is unaffected.
    pub fn kill(&self, reason: u16) {
        self.tx.send_modify(|state| {
            // Wrapping is unreachable in practice (2^64 kills); it only keeps
            // the "changed since I armed" comparison (`generation != base`)
            // exact rather than risking a debug overflow panic.
            state.generation = state.generation.wrapping_add(1);
            state.reason = Some(reason);
        });
    }

    /// End the sessions of `device` that watch for it ([`KillGuard::watch_device`], armed at
    /// their reservation) with `BYE{REVOKED}`, live or still being accepted: all of them
    /// for [`EndScope::Every`] (revoke, disable, suspend; local or remote), only those the
    /// accept put at the administrator level for [`EndScope::AtTheLevel`] (a lowering).
    /// Every other session goes on (decision M1-67, D6). A session that starts watching
    /// after this call is unaffected.
    pub fn end_device(&self, device: &DeviceId, scope: EndScope) {
        self.tx.send_modify(|state| {
            let ends = state.devices.entry(*device).or_default();
            match scope {
                EndScope::Every => ends.every = ends.every.wrapping_add(1),
                EndScope::AtTheLevel => ends.at_the_level = ends.at_the_level.wrapping_add(1),
            }
        });
    }

    /// The reason the switch most recently fired with, if it ever has.
    #[must_use]
    pub fn fired(&self) -> Option<u16> {
        self.tx.borrow().reason
    }

    /// Snapshot the switch for one session. The returned [`KillGuard`] fires
    /// only for a [`kill`](Self::kill) after this call, so a reason latched by
    /// an earlier session never ends this one.
    #[must_use]
    pub fn arm(&self) -> KillGuard {
        let rx = self.tx.subscribe();
        let base = rx.borrow().generation;
        KillGuard {
            rx,
            base,
            device: None,
        }
    }
}

impl tornect_core::unattended::guard::DeviceSessionEnd for KillSwitch {
    fn end_device(&self, device: &DeviceId, scope: EndScope) {
        KillSwitch::end_device(self, device, scope);
    }
}

/// One session's view of a [`KillSwitch`], from [`KillSwitch::arm`].
#[derive(Debug)]
pub struct KillGuard {
    rx: watch::Receiver<KillState>,
    base: u64,
    /// The device this session watches for [`KillSwitch::end_device`].
    device: Option<Watched>,
}

/// What a [`KillGuard`] watches for its device (decision M1-67, D6).
#[derive(Debug)]
struct Watched {
    device: DeviceId,
    /// The device's count of ends when the session started watching.
    base: DeviceEnds,
    /// Whether the accept put the session at the administrator level.
    at_the_level: bool,
}

impl KillGuard {
    /// Resolve with the `BYE` reason once the switch fires after this guard was
    /// armed. Otherwise never resolves — including for a kill that predates the
    /// guard — so it composes in the session `select!` beside the peer's frames.
    pub async fn killed(&mut self) -> u16 {
        loop {
            {
                let state = self.rx.borrow_and_update();
                if state.generation != self.base
                    && let Some(reason) = state.reason
                {
                    return reason;
                }
                if let Some(watched) = &self.device {
                    let ends = state.ends_of(&watched.device);
                    if ends.every != watched.base.every
                        || (watched.at_the_level && ends.at_the_level != watched.base.at_the_level)
                    {
                        return messages::bye::REVOKED;
                    }
                }
            }
            if self.rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// Whether the switch has fired since this guard was armed, without waiting. Host-wide
    /// only: an end of this session's device ends it once it runs ([`Self::killed`]).
    #[must_use]
    pub fn fired(&self) -> bool {
        self.rx.borrow().generation != self.base
    }

    /// From now on, [`KillSwitch::end_device`] for `device` also ends this session
    /// (`BYE{REVOKED}`), also when it fires before the session starts (decision M1-67,
    /// D6): armed at the session's reservation. An end for the level reaches it only once
    /// [`Self::at_the_level`] says its accept put it there.
    pub fn watch_device(&mut self, device: DeviceId) {
        let base = self.rx.borrow().ends_of(&device);
        self.device = Some(Watched {
            device,
            base,
            at_the_level: false,
        });
    }

    /// The watched session's level as its accept signs it: at the administrator level, a
    /// lowering of its grant committed since the reservation ends it too (D6).
    pub fn at_the_level(&mut self, at_the_level: bool) {
        if let Some(watched) = &mut self.device {
            watched.at_the_level = at_the_level;
        }
    }
}

/// How long the host tries to say goodbye (`BYE`, or the close after the
/// peer's own) once a session is over. The session ends before this is
/// attempted, so a peer that stopped reading delays nothing but its own
/// goodbye (§B.8.6.1 "BYE ≤ 1 s").
const GOODBYE: Duration = Duration::from_secs(1);

/// What is left to write when [`established`] returns: the session is already
/// over, and this goes out only after the sink and the log have been told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Goodbye {
    /// Send `BYE{reason}` and close.
    Bye(u16),
    /// Send `ERROR{code}` and close, unless the channel already did: the
    /// session ended in a protocol violation (SLICE-C3 C3-2).
    Error {
        /// The `ERROR` code.
        code: u16,
        /// Which check failed.
        what: &'static str,
    },
    /// Close the stream (the peer said goodbye first).
    Close,
    /// Nothing: the stream may hold a cut-short frame.
    Nothing,
}

/// Calls `on_end` and logs the end if the session task unwinds or is dropped
/// between `on_start` and the ordinary `on_end`: a sink that panicked, or a
/// cancelled task, must not leave the session marked live, holding `BUSY`
/// answers and the guard's refusals for good (SLICE-B1 B1-4).
struct EndGuard<'a> {
    deps: &'a HostDeps,
    device: DeviceId,
    label: &'a str,
    session_id: &'a str,
    armed: bool,
}

impl Drop for EndGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.deps.sessions.on_end(self.session_id, None);
            self.deps.audit.record(AuditEvent::SessionEnded {
                device: self.device,
                label: self.label.to_owned(),
                session_id: self.session_id.to_owned(),
                detail: "aborted".to_owned(),
            });
        }
    }
}

/// Apply the side effect of a remote admin command to live sessions (§B.8.4.1): the two
/// host-wide effects through the kill switch, the two per-device ones through its
/// per-device end (decision M1-67, D6), which reaches only that device's sessions, live or
/// reserved.
fn apply_admin_effect(deps: &HostDeps, effect: &AdminEffect) {
    match effect {
        AdminEffect::MasterOff => deps.kill.kill(messages::bye::MASTER_OFF),
        AdminEffect::RevokedAll(_) => deps.kill.kill(messages::bye::REVOKED),
        AdminEffect::Revoked(device) | AdminEffect::Suspended(device) => {
            deps.kill.end_device(device, EndScope::Every);
        }
        // The requester's own stream is already closed above.
        AdminEffect::EndSession => {}
        // Access-restoring: nothing to tear down.
        AdminEffect::Unlocked(_) => {}
        AdminEffect::None => {}
    }
}

/// Live counters over every stream served with the same deps (A17 asserts
/// them; the CLI reports them).
#[derive(Debug, Default)]
pub struct HandshakeStats {
    /// Streams inside [`serve_host`].
    pub streams: AtomicUsize,
    /// Streams past a verified `HELLO` that have not sent `SESSION_REQUEST` yet.
    pub hello_verified: AtomicUsize,
    /// Pairing popups open.
    pub pair_pending: AtomicUsize,
    /// Session popups open.
    pub consent_pending: AtomicUsize,
    /// Established sessions.
    pub established: AtomicUsize,
    /// `SESSION_ACCEPT`s ever sent.
    pub accepted_total: AtomicU64,
}

struct Counted<'a>(&'a AtomicUsize);

impl<'a> Counted<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for Counted<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Where [`serve_host`] hands an established session to the layer that runs it
/// (`tornect-session` from M4; until then the CLI's own sink).
///
/// [`on_start`](SessionSink::on_start) is called once `SESSION_ACCEPT` is sent
/// and `th_final` is fixed — the first point §B.6 allows capture to begin — and
/// [`on_end`](SessionSink::on_end) once the session is over, however it ended,
/// including a protocol error and the kill switch. Every `on_start` is followed
/// by exactly one `on_end`, so a sink may treat the pair as acquire/release.
///
/// Both run on the stream's own task, between the accept and the first frame,
/// so neither may block.
pub trait SessionSink: Send + Sync {
    /// The session is live.
    fn on_start(&self, session: &LiveSession<'_>);
    /// The session is over. `end` is `None` when it ended in a protocol error.
    fn on_end(&self, session_id: &str, end: Option<&SessionEnd>);
}

/// What [`SessionSink::on_start`] is told about a live session.
pub struct LiveSession<'a> {
    /// The peer.
    pub device: DeviceId,
    /// The pinned label.
    pub label: &'a str,
    /// [`SessionToken::session_id`]: the one-way id `sessions.log` uses.
    pub session_id: &'a str,
    /// The session token. The media layer derives the `Bind` key from it
    /// (`HKDF-SHA256(session_token, "tornect/v1/tor-media-bind-key")`, decision
    /// M1-41); the token itself never goes on the wire.
    pub token: &'a SessionToken,
    /// `th` at the end of the handshake, equal on both sides.
    pub th_final: [u8; 32],
    /// Control or view-only; input is dropped host-side in
    /// [`SessionMode::ViewOnly`].
    pub mode: SessionMode,
    /// The administrator level signed in `SESSION_ACCEPT` (r7, §B.2.1): what
    /// the host's banner and indicator say, and whether the session's input
    /// goes through the administrator helper. View-only is always none.
    pub elevation: Elevation,
    /// Whether this was an unattended session (§B.8).
    pub unattended: bool,
}

/// The administrator helper of §B.8.7.5 (r7, M-FEAT-3): started for an
/// administrator answer that needs it, between the answer and the accept.
/// The accept carries the administrator level only for a helper connected
/// and checked in time; a helper never attached ends (H3).
pub trait AdminHelper: Send + Sync {
    /// Start the helper for `peer`'s session: resolves once it is connected,
    /// checked and ready, or with why administrator access was not given (in
    /// fixed words). A future dropped before it resolves ends what it started.
    fn start<'a>(
        self: Arc<Self>,
        peer: &'a TrustedPeer,
    ) -> BoxFuture<'a, Result<Box<dyn AttachedHelper>, &'static str>>;

    /// Start the helper through the on-demand task for an unattended
    /// administrator session that passed its checks and its block window
    /// (§B.8.7.5): resolves as [`Self::start`] does. The host waits for it at
    /// most [`HELPER_TASK_BUDGET`]. The default: no task.
    fn start_task<'a>(
        self: Arc<Self>,
        peer: &'a TrustedPeer,
    ) -> BoxFuture<'a, Result<Box<dyn AttachedHelper>, &'static str>> {
        let _ = peer;
        Box::pin(async { Err("this host has no administrator helper task") })
    }
}

/// How long an unattended administrator session waits for its helper
/// (§B.8.7.5: not connected within 5 s ⇒ the session starts at none and
/// stays there).
pub const HELPER_TASK_BUDGET: Duration = Duration::from_secs(5);

/// A helper connected and checked for a session not accepted yet. Dropped
/// without [`AttachedHelper::attach`], it ends: it never attaches to a
/// session midway (H3).
pub trait AttachedHelper: Send {
    /// The accept of `session_id` went out at the administrator level: from
    /// now on the session's input goes through this helper, until it ends.
    fn attach(self: Box<Self>, session_id: &str);
}

/// No administrator helper: every start fails (the headless default, and
/// every system but Windows).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAdminHelper;

impl AdminHelper for NoAdminHelper {
    fn start<'a>(
        self: Arc<Self>,
        _: &'a TrustedPeer,
    ) -> BoxFuture<'a, Result<Box<dyn AttachedHelper>, &'static str>> {
        Box::pin(async { Err("this host cannot start the administrator helper") })
    }
}

/// Runs no session: the accept is the end of the story (M1 default, tests).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSessionSink;

impl SessionSink for NoSessionSink {
    fn on_start(&self, _: &LiveSession<'_>) {}
    fn on_end(&self, _: &str, _: Option<&SessionEnd>) {}
}

/// The sessions live on this host. The [`SessionSink`] calls feed it, and it
/// answers two questions: [`SessionActivity`] for the FSM, which rejects popups
/// `BUSY` while a session is live (§B.8.16), and
/// [`RemoteSessionActivity`] for the `MutationGuard`, which refuses
/// access-increasing changes during a remote session and for a minute after
/// (§B.8.6.2).
///
/// Serving all three roles from one instance means the popups the FSM
/// suppresses, the changes the guard refuses and the sessions the sink was told
/// about can never disagree. The layer that runs sessions (the CLI now,
/// `tornect-session` from M4) forwards its own `on_start` / `on_end` here.
#[derive(Debug, Default)]
pub struct LiveSessions {
    state: std::sync::Mutex<LiveState>,
}

#[derive(Debug, Default)]
struct LiveState {
    live: Vec<LiveEntry>,
    /// Accepts between the one-session gate and `on_start` (SLICE-C3 C3-1).
    reserved: usize,
    last_ended: Option<std::time::Instant>,
}

impl LiveState {
    fn busy(&self) -> bool {
        !self.live.is_empty() || self.reserved > 0
    }
}

/// One live session, as [`LiveSessions::snapshot`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveEntry {
    /// [`SessionToken::session_id`].
    pub session_id: String,
    /// The peer.
    pub device: DeviceId,
    /// Its pinned label.
    pub label: String,
    /// Control or view-only.
    pub mode: SessionMode,
    /// Whether it is an unattended session.
    pub unattended: bool,
}

impl LiveSessions {
    /// No session live, none ever ended.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the live-session lock is free right now: a hook run under it would
    /// see it taken (decision M1-67).
    #[cfg(test)]
    pub(crate) fn lock_is_free(&self) -> bool {
        self.state.try_lock().is_ok()
    }

    /// The sessions live right now, oldest first.
    #[must_use]
    pub fn snapshot(&self) -> Vec<LiveEntry> {
        crate::pairing::lock(&self.state).live.clone()
    }

    /// How many sessions are live.
    #[must_use]
    pub fn count(&self) -> usize {
        crate::pairing::lock(&self.state).live.len()
    }
}

impl SessionSink for LiveSessions {
    fn on_start(&self, session: &LiveSession<'_>) {
        crate::pairing::lock(&self.state).live.push(LiveEntry {
            session_id: session.session_id.to_owned(),
            device: session.device,
            label: session.label.to_owned(),
            mode: session.mode,
            unattended: session.unattended,
        });
    }

    fn on_end(&self, session_id: &str, _: Option<&SessionEnd>) {
        let mut state = crate::pairing::lock(&self.state);
        state.live.retain(|s| s.session_id != session_id);
        // Set even for an id this tracker never saw: a later end only lengthens
        // the guard's cool-down, which errs on the refusing side.
        state.last_ended = Some(std::time::Instant::now());
    }
}

impl SessionActivity for LiveSessions {
    fn session_live(&self) -> bool {
        crate::pairing::lock(&self.state).busy()
    }

    fn try_reserve(&self) -> bool {
        let mut state = crate::pairing::lock(&self.state);
        if state.busy() {
            return false;
        }
        state.reserved += 1;
        true
    }

    fn release(&self) {
        let mut state = crate::pairing::lock(&self.state);
        state.reserved = state.reserved.saturating_sub(1);
    }
}

impl RemoteSessionActivity for LiveSessions {
    fn last_session_ended_at(&self) -> Option<std::time::Instant> {
        crate::pairing::lock(&self.state).last_ended
    }

    /// A session being accepted counts: the guard errs on the refusing side.
    fn session_live(&self) -> bool {
        crate::pairing::lock(&self.state).busy()
    }
}

/// Everything the host FSM is injected with.
#[derive(Clone)]
pub struct HostDeps {
    /// Signs `HELLO_ACK`, `SESSION_ACCEPT`, `ADMIN_RESULT` with the onion identity key.
    pub signer: Arc<dyn HostSigner>,
    /// Pinned devices and temp-bans.
    pub trusted: Arc<TrustedDeviceStore>,
    /// In-flight / rate-limit policy for `PAIR_REQUEST`.
    pub policy: Arc<PairingPolicy>,
    /// The same shape of policy for the attended session popup
    /// ([`PairingLimits::sessions`]): one popup in flight per paired device
    /// and a host-wide budget, `SESSION_REJECT{BUSY}` beyond them.
    pub session_policy: Arc<PairingPolicy>,
    /// The popups.
    pub consent: Arc<dyn Consent>,
    /// The block window before an unattended session (§B.8.4.5 `Accepting`);
    /// `tornect-session` (M4) supplies the UI-backed one.
    pub block_window: Arc<dyn BlockWindow>,
    /// The `ask_before_start` popup (§B.8.4.5 `AwaitLocalAllow`).
    pub local_allow: Arc<dyn LocalAllow>,
    /// `HELLO.stop_token` observer.
    pub stop_token: Arc<dyn StopTokenCheck>,
    /// The unattended branch.
    pub unattended: Arc<dyn UnattendedHook>,
    /// Whether a remote session is live.
    pub activity: Arc<dyn SessionActivity>,
    /// `sessions.log`.
    pub audit: Arc<dyn HandshakeAudit>,
    /// Post-accept frames for M2.
    pub candidates: Arc<dyn CandidateSink>,
    /// The layer that runs an established session (M4 `tornect-session`).
    pub sessions: Arc<dyn SessionSink>,
    /// The administrator helper (§B.8.7.5): started between an administrator
    /// answer and its accept.
    pub admin_helper: Arc<dyn AdminHelper>,
    /// Nonces and tokens.
    pub random: Arc<dyn Randomness>,
    /// Counters.
    pub stats: Arc<HandshakeStats>,
    /// One-click kill.
    pub kill: KillSwitch,
}

impl HostDeps {
    /// Headless defaults: `AutoDeny`, no stop token, `NotGranted`, no live
    /// session, no audit, candidates ignored, no session sink, OS randomness,
    /// default limits, a timer-only block window and `AlwaysDeny` for
    /// `ask_before_start`.
    #[must_use]
    pub fn headless(signer: Arc<dyn HostSigner>, trusted: Arc<TrustedDeviceStore>) -> Self {
        Self {
            signer,
            trusted,
            policy: Arc::new(PairingPolicy::new(PairingLimits::default())),
            session_policy: Arc::new(PairingPolicy::new(PairingLimits::sessions())),
            consent: Arc::new(AutoDeny),
            block_window: Arc::new(TimerOnlyWindow),
            local_allow: Arc::new(AlwaysDeny),
            stop_token: Arc::new(NoStopToken),
            unattended: Arc::new(NotGranted),
            activity: Arc::new(NoSession),
            audit: Arc::new(NoAudit),
            candidates: Arc::new(IgnoreCandidates),
            sessions: Arc::new(NoSessionSink),
            admin_helper: Arc::new(NoAdminHelper),
            random: Arc::new(OsRandom),
            stats: Arc::new(HandshakeStats::default()),
            kill: KillSwitch::new(),
        }
    }
}

/// How an established session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEnd {
    /// The peer sent `BYE{reason}`.
    PeerBye(u16),
    /// The peer sent `ERROR{code}`.
    PeerError(u16),
    /// The peer closed the stream.
    PeerClosed,
    /// The kill switch fired; `BYE{reason}` was sent.
    Killed(u16),
    /// No `CANDIDATES` / `TOR_FALLBACK` in time; `BYE{ORPHANED}` was sent.
    Orphaned,
    /// No frame for the idle timeout; `BYE{ORPHANED}` was sent.
    Idle,
}

/// How [`serve_host`] ended without a protocol error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostOutcome {
    /// The pairing was refused (`PAIR_REJECT{reason}` sent).
    PairRejected {
        /// The peer.
        device: DeviceId,
        /// A [`messages::pair_reject`] code.
        reason: u16,
    },
    /// Paired, and the peer left, or said nothing more within
    /// [`timeouts::SESSION_REQUEST`], without a `SESSION_REQUEST`.
    PairedOnly {
        /// The peer.
        device: DeviceId,
        /// The pinned label.
        label: String,
    },
    /// `SESSION_REJECT{reason}` sent (or, for an unattended stream that died
    /// in a violation, only logged).
    SessionRejected {
        /// The peer.
        device: DeviceId,
        /// The pinned label.
        label: String,
        /// A [`messages::reject`] code.
        reason: u16,
    },
    /// `ADMIN_RESULT` sent.
    Admin {
        /// The peer.
        device: DeviceId,
        /// Whether the command was executed.
        ok: bool,
    },
    /// A session was established and then ended.
    Session {
        /// The peer.
        device: DeviceId,
        /// The pinned label.
        label: String,
        /// Whether the peer was paired (or re-paired) in this exchange.
        paired_now: bool,
        /// The session token (attended: the fresh token; unattended: the derived one).
        token: SessionToken,
        /// The mode.
        mode: SessionMode,
        /// Whether it was unattended.
        unattended: bool,
        /// `th` at the end of the handshake (after `SESSION_ACCEPT`), equal on both sides.
        th_final: [u8; 32],
        /// How it ended.
        end: SessionEnd,
    },
}

/// Serve one accepted stream from `HELLO` to the end of the session.
///
/// Returns `Ok` for every outcome the protocol foresees and `Err` for a
/// violation, a timeout, or the peer leaving before anything was decided.
pub async fn serve_host<S>(
    stream: S,
    cfg: &HostConfig,
    deps: &HostDeps,
) -> Result<HostOutcome, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let _streams = Counted::new(&deps.stats.streams);
    // Armed at accept, before the handshake: a kill fired at any point from here
    // to session end ends this stream, while one fired earlier (a master-off or
    // panic left over from a previous session) does not — the switch no longer
    // latches onto sessions accepted after it fired.
    let mut kill = deps.kill.arm();
    let host_pk = deps.signer.public_key();
    let mut chan = Channel::new(stream, &host_pk);

    // Start → HelloVerified.
    let rx = chan
        .recv_expect(timeouts::HELLO, "HELLO", &[Kind::Hello])
        .await?;
    let hello: Hello = chan.body(&rx).await?;
    let pk = match VerifyingKey::from_bytes(&hello.device_pk) {
        Ok(pk) => pk,
        Err(_) => return Err(chan.fail(codes::E_BAD_SIG, "signature").await),
    };
    if verify_envelope(&pk, &chan.th(), &rx.env).is_err() {
        return Err(chan.fail(codes::E_BAD_SIG, "signature").await);
    }
    chan.absorb(&rx);
    if hello.v_max < tornect_core::PROTOCOL_VERSION {
        return Err(chan.fail(codes::E_VERSION, "v_max").await);
    }
    // The common version (§B.8.4.5: `v ≤ v_max`); fixed on the channel before
    // `HELLO_ACK` so that frame already carries it. A v2 host picks here.
    let version = tornect_core::PROTOCOL_VERSION.min(hello.v_max);
    if let Some(token) = &hello.stop_token {
        deps.stop_token.observe(token).await;
    }
    let device = DeviceId::from_bytes(hello.device_pk);
    let declared_name = normalize_label(&hello.name);
    let pinned = deps.trusted.get(&device).map(|rec| rec.label);
    let hello_verified = Counted::new(&deps.stats.hello_verified);
    tracing::debug!(peer = ?device, paired = pinned.is_some(), "HELLO verified");

    // HelloVerified → HELLO_ACK.
    let mut host_nonce = [0u8; 32];
    deps.random.fill(&mut host_nonce)?;
    let ack = HelloAck {
        v: version,
        host_nonce,
        feats: clamp_feats(&cfg.feats),
    };
    chan.set_version(version);
    chan.send(&ack, Some(&*deps.signer)).await?;
    // th_after(HELLO_ACK): the SAS input (§B.3), taken before PAIR_REQUEST is absorbed.
    let th_hello_ack = chan.th();

    // AwaitSessionRequest (60 s from HELLO_ACK). An unpaired peer must pair
    // first; a pinned device may also re-pair through the same popup, keeping
    // its label (decision M1-32: a client that lost `known-hosts.toml`).
    let mut paired_now = false;
    let (what, allowed): (&'static str, &[Kind]) = match pinned {
        Some(_) => (
            "SESSION_REQUEST",
            &[Kind::SessionRequest, Kind::PairRequest],
        ),
        None => ("PAIR_REQUEST", &[Kind::PairRequest]),
    };
    let mut rx = chan
        .recv_expect(timeouts::SESSION_REQUEST, what, allowed)
        .await?;
    let label = match pinned {
        Some(label) if rx.env.kind == Kind::SessionRequest => label,
        _ => {
            // PairRequested → PairAccepted | PairRejected.
            let label = match pair(
                &mut chan,
                cfg,
                deps,
                &device,
                &declared_name,
                pinned.as_deref(),
                &rx,
                SasBinding {
                    th_hello_ack: &th_hello_ack,
                    commit: &hello.sas_commit,
                },
            )
            .await?
            {
                Ok(label) => label,
                Err(reason) => return Ok(HostOutcome::PairRejected { device, reason }),
            };
            paired_now = true;
            // The timer restarts at PAIR_ACCEPT (§B.8.4.5).
            rx = match chan
                .recv_expect(
                    timeouts::SESSION_REQUEST,
                    "SESSION_REQUEST",
                    &[Kind::SessionRequest],
                )
                .await
            {
                Ok(rx) => rx,
                // Paired either way: this host's accept pinned the device
                // (above). A peer that says nothing more by the timer may
                // still be at its code check; only the reported outcome
                // differs from a peer that left.
                Err(
                    HandshakeError::Closed
                    | HandshakeError::PeerBye { .. }
                    | HandshakeError::Timeout(_),
                ) => {
                    return Ok(HostOutcome::PairedOnly { device, label });
                }
                Err(e) => return Err(e),
            };
            label
        }
    };
    let peer = TrustedPeer {
        device,
        label: label.clone(),
    };

    // SESSION_REQUEST: the signature first (it covers `host_nonce`, F1), then
    // the body; only then does the device count as seen (`HELLO` is replayable).
    if verify_envelope(&pk, &chan.th(), &rx.env).is_err() {
        return Err(chan.fail(codes::E_BAD_SIG, "signature").await);
    }
    let request: SessionRequest = chan.body(&rx).await?;
    chan.absorb(&rx);
    drop(hello_verified);
    deps.trusted.touch(&device);
    let unattended = request.unattended.is_some();
    deps.audit.record(AuditEvent::SessionRequested {
        device,
        label: label.clone(),
        unattended,
    });

    let host_info = AcceptHostInfo {
        quic_spki: ed25519_spki(&cfg.host_device_pk),
        transport_policy: cfg.transport_policy,
    };
    let (proof, caps, helper) = if unattended {
        let th_after_request = chan.th();
        let verdict = deps
            .unattended
            .handle(UnattendedContext {
                device,
                label: &label,
                request: &request,
                th_after_request,
                host_pk,
                host_caps: &cfg.caps,
                exchange: &mut chan,
                block_window: &*deps.block_window,
                local_allow: &*deps.local_allow,
            })
            .await?;
        match verdict {
            UnattendedVerdict::Reject(reject) => {
                let reason = reject.reason;
                // §B.8.4.5 `AwaitKe3`: the reject goes out only if the stream
                // is still alive (a violation already answered `ERROR` and
                // closed); it is logged either way.
                if !chan.is_closing() {
                    chan.send(&reject, None).await?;
                    chan.close().await;
                }
                deps.audit.record(AuditEvent::SessionDenied {
                    device,
                    label: label.clone(),
                    reason,
                });
                return Ok(HostOutcome::SessionRejected {
                    device,
                    label,
                    reason,
                });
            }
            UnattendedVerdict::Admin { result, effect } => {
                let ok = result.ok;
                // The answer goes out before the effect is applied. A
                // `master_off` or `revoke_all` fires the kill switch, and the
                // requester's own stream is one of the streams it would tear
                // down — sending first is what lets the device that asked for
                // the emergency stop actually see it succeed.
                //
                // The effect never *depends* on the send, though: the store
                // change has already committed, so a requester whose circuit
                // dropped while it waited (common over Tor, likelier still in
                // an emergency) must not leave the other live sessions running
                // against a store that says access is off. The send error is
                // reported only after the effect has fired.
                let sent = chan.send(&result, Some(&*deps.signer)).await;
                chan.close().await;
                apply_admin_effect(deps, &effect);
                sent?;
                return Ok(HostOutcome::Admin { device, ok });
            }
            // An unattended administrator level on a row whose host holds a
            // filtered token needs the helper task (§B.8.7.5), started now,
            // after the checks and the block window; not ready within
            // `HELPER_TASK_BUDGET`, the session starts at none and stays
            // there, never signed at a level it does not have.
            UnattendedVerdict::Accept { proof, caps } => {
                if unattended_needs_helper(&proof, &cfg.levels.offered()) {
                    let started = tokio::time::timeout(
                        HELPER_TASK_BUDGET,
                        Arc::clone(&deps.admin_helper).start_task(&peer),
                    )
                    .await;
                    match started {
                        Ok(Ok(helper)) => (proof, caps, Some(helper)),
                        failed => {
                            let reason = match failed {
                                Ok(Err(reason)) => reason,
                                _ => "the administrator helper did not start in time",
                            };
                            deps.audit.record(AuditEvent::AdminHelper {
                                device,
                                label: label.clone(),
                                session_id: None,
                                what: HelperEvent::Failed,
                                reason,
                            });
                            (without_elevation(proof), caps, None)
                        }
                    }
                } else {
                    (proof, caps, None)
                }
            }
        }
    } else {
        // AwaitConsent. The session popup has the pairing popup's budget —
        // one in flight per device, per-device and host-wide buckets — so a
        // paired key can neither stack popups nor open one per rendezvous;
        // then the live-session suppression of §B.8.6.2 (logged as such).
        let _slot = match deps.session_policy.admit(*device.public_key_bytes()) {
            Ok(guard) => guard,
            Err(refusal) => {
                tracing::debug!(peer = ?device, ?refusal, "session popup refused by the limiter");
                return reject_session(&mut chan, deps, &peer, messages::reject::BUSY).await;
            }
        };
        if deps.activity.session_live() {
            deps.audit.record(AuditEvent::PopupSuppressed {
                device,
                label: Some(label.clone()),
                popup: SuppressedPopup::Session,
            });
            return reject_session(&mut chan, deps, &peer, messages::reject::BUSY).await;
        }
        let summary = SessionRequestSummary {
            caps: request.caps.clone(),
        };
        // The level is the person's answer (§B.8.4.1), and only an answer the
        // sheet could offer: anything else is refused as a Deny, never
        // started at another level (§B.2.1: an administrator answer never
        // starts a session at a lower one).
        let offered = cfg.levels.offered();
        let deadline = Instant::now() + timeouts::POPUP;
        let mut not_given = false;
        let (choice, helper) = loop {
            let asking = if not_given {
                let left = deadline.saturating_duration_since(Instant::now());
                deps.consent
                    .session_again(&peer, &summary, &cfg.levels, left)
            } else {
                deps.consent.session_at(&peer, &summary, &cfg.levels)
            };
            let decision = {
                let _pending = Counted::new(&deps.stats.consent_pending);
                tokio::time::timeout_at(deadline, asking).await
            };
            let choice = match decision {
                Err(_) => {
                    return reject_session(&mut chan, deps, &peer, messages::reject::POPUP_TIMEOUT)
                        .await;
                }
                Ok(decision) => match accepted(decision, &offered) {
                    Some(choice) => choice,
                    None => {
                        if decision != SessionDecision::Deny {
                            tracing::warn!(peer = ?device, ?decision, "an answer the sheet does not offer; refused");
                        }
                        return reject_session(&mut chan, deps, &peer, messages::reject::DENIED)
                            .await;
                    }
                },
            };
            if !needs_helper(choice, &offered) {
                break (choice, None);
            }
            // Between the answer and the accept (§B.8.7.5): Windows' prompt
            // and the helper's start run here while the popup's time keeps
            // running; a helper not ready in time is never attached.
            let started =
                tokio::time::timeout_at(deadline, Arc::clone(&deps.admin_helper).start(&peer))
                    .await;
            match started {
                Err(_) => {
                    return reject_session(&mut chan, deps, &peer, messages::reject::POPUP_TIMEOUT)
                        .await;
                }
                Ok(Ok(helper)) => break (choice, Some(helper)),
                Ok(Err(reason)) => {
                    deps.audit.record(AuditEvent::AdminHelper {
                        device,
                        label: label.clone(),
                        session_id: None,
                        what: HelperEvent::Failed,
                        reason,
                    });
                    // The sheet again, with the other answers.
                    not_given = true;
                }
            }
        };
        let mut token = Zeroizing::new([0u8; 32]);
        deps.random.fill(&mut token[..])?;
        let proof = ConsentProof::HumanClick {
            choice,
            at: Instant::now(),
            token: FreshToken::mint(*token),
        };
        (
            proof,
            ChosenCaps::negotiate(&cfg.caps, &request.caps),
            helper,
        )
    };

    // The owner may have pressed the panic key, or another session may have
    // gone live, while the popup, the PAKE or the block window was open. Either
    // way this is no longer a session to accept: a kill is refused as the Deny
    // or the Block it stands for, and a live session as the busy answer of the
    // path (SLICE-B1 B1-1/B1-3, SLICE-B2 B2-5). Checked last, right here, so
    // nothing that waited can slip past it.
    if kill.fired() {
        let reason = if unattended {
            messages::reject::BLOCKED_BY_LOCAL_USER
        } else {
            messages::reject::DENIED
        };
        return reject_session(&mut chan, deps, &peer, reason).await;
    }
    // Checked and reserved in one step: a second session that gets here while
    // this accept is still being written sees the reservation, not an empty
    // host (SLICE-C3 C3-1). It gives way to the live entry after `on_start`.
    let Some(reserved) = Reserved::take(&*deps.activity) else {
        let reason = if unattended {
            messages::reject::SESSION_ACTIVE
        } else {
            messages::reject::BUSY
        };
        return reject_session(&mut chan, deps, &peer, reason).await;
    };
    // Decision M1-67 (D6): from the reservation on, an end of this device's sessions (its
    // grant revoked, disabled, suspended or lowered) ends this one too, also when it comes
    // before the session starts: then at once.
    if unattended {
        kill.watch_device(device);
    }

    // Decision M1-67: once the session is reserved, the unattended hook reads
    // afresh what can lower it (the account facts, the helper task) and gives
    // the proof back lowered, never above, or refuses. The live-session lock is
    // not held here: `try_reserve` let it go. A helper started for a level the
    // read took away ends here, never attached.
    let (proof, helper) = if unattended {
        // What the hook may give back at most: the proof as the gate minted it.
        let minted = unattended_level(&proof);
        match deps.unattended.reserved(&device, proof).await {
            // The read only lowers: a proof above the one passed in, in mode or in
            // level, or no unattended proof at all, is never signed.
            Ok(lowered) if raised(minted, unattended_level(&lowered)) => {
                tracing::warn!(peer = ?device, "the read after the reservation raised the session; refused");
                drop(helper);
                drop(reserved);
                return reject_session(&mut chan, deps, &peer, messages::reject::NOT_GRANTED).await;
            }
            Ok(lowered) => {
                let still_admin = matches!(
                    &lowered,
                    ConsentProof::Unattended { policy, .. } if policy.elevation() == Elevation::Admin
                );
                (lowered, helper.filter(|_| still_admin))
            }
            Err(reject) => {
                drop(helper);
                drop(reserved);
                return reject_session(&mut chan, deps, &peer, reject.reason).await;
            }
        }
    } else {
        (proof, helper)
    };
    // The panic check again, after the hook: a kill fired while it read is
    // refused as the Block it stands for, the reservation and any helper let go.
    if kill.fired() {
        let reason = if unattended {
            messages::reject::BLOCKED_BY_LOCAL_USER
        } else {
            messages::reject::DENIED
        };
        drop(helper);
        drop(reserved);
        return reject_session(&mut chan, deps, &peer, reason).await;
    }

    // Accept → Established. `build` is the only source of the session token:
    // the accept body carries `session_token` for attended sessions and only
    // `token_confirm` for unattended ones (§B.8.4.3), never the BIND key.
    // `grant_reach` (decision M1-67): an unattended accept carries the value the
    // read after the reservation computed under the store lock, together with
    // the mark it implies; an attended accept never carries the key.
    let grant_reach = match &proof {
        ConsentProof::Unattended { policy, .. } => policy.grant_reach(),
        _ => None,
    };
    let (accept, token) = SessionAccept::build(proof, caps, &host_info, grant_reach);
    let session_id = token.session_id();
    let mode = mode_from_code(accept.mode()).unwrap_or(SessionMode::ViewOnly);
    // The level the accept signs, and nothing else, is the session's level.
    let elevation = Level::new(mode, accept.elevation()).elevation();
    // At the level, a lowering of the grant since the reservation ends it too (D6).
    kill.at_the_level(elevation == Elevation::Admin);
    chan.send(&accept, Some(&*deps.signer)).await?;
    deps.stats.accepted_total.fetch_add(1, Ordering::SeqCst);
    deps.audit.record(AuditEvent::SessionStarted {
        device,
        label: label.clone(),
        session_id: session_id.clone(),
        mode,
        elevation,
        unattended,
    });
    // The helper attaches only to the session whose accept went out at the
    // administrator level; any other ends here, never attached (H3).
    if let Some(helper) = helper
        && elevation == Elevation::Admin
    {
        helper.attach(&session_id);
        deps.audit.record(AuditEvent::AdminHelper {
            device,
            label: label.clone(),
            session_id: Some(session_id.clone()),
            what: HelperEvent::Started,
            reason: "connected and checked before the accept",
        });
    }
    tracing::info!(peer = ?device, %label, session = %session_id, "session accepted");

    let th_final = chan.th();
    // Armed before `on_start`, so even a sink that panics inside it is released.
    let mut end_guard = EndGuard {
        deps,
        device,
        label: &label,
        session_id: &session_id,
        armed: true,
    };
    deps.sessions.on_start(&LiveSession {
        device,
        label: &label,
        session_id: &session_id,
        token: &token,
        th_final,
        mode,
        elevation,
        unattended,
    });
    drop(reserved);
    let ended = {
        let _established = Counted::new(&deps.stats.established);
        established(&mut chan, cfg, deps, &mut kill).await
    };
    let (end, goodbye) = match ended {
        Ok((end, goodbye)) => (Ok(end), goodbye),
        // Its `ERROR` goes out as the goodbye, after the end is recorded: a
        // peer that stops reading must not hold the end back (SLICE-C3 C3-2).
        Err(HandshakeError::Violation { code, what }) => (
            Err(HandshakeError::Violation { code, what }),
            Goodbye::Error { code, what },
        ),
        Err(e) => (Err(e), Goodbye::Nothing),
    };
    end_guard.armed = false;
    drop(end_guard);
    // The session is over the moment it is decided. The sink hears first, since
    // it is what stops capture, then the log, and only then is anything written
    // to the peer: a peer that stopped reading must not hold the end back
    // (SLICE-B1 B1-2, SLICE-B2 B2-1). Taken before the `?` below, so a session
    // that ended in a protocol error still releases what the sink acquired.
    deps.sessions.on_end(&session_id, end.as_ref().ok());
    // Logged before any error propagates: a peer that hangs up mid-frame or
    // sends an illegal kind must not erase its own session-end line (§B.6,
    // §B.8.16 "every session start/end reaches sessions.log").
    deps.audit.record(AuditEvent::SessionEnded {
        device,
        label: label.clone(),
        session_id: session_id.clone(),
        detail: match &end {
            Ok(end) => format!("{end:?}"),
            Err(err) => end_detail(err),
        },
    });
    // Best effort, bounded: the peer may never take it.
    match goodbye {
        Goodbye::Bye(reason) => {
            let _ = tokio::time::timeout(GOODBYE, chan.bye(reason)).await;
        }
        Goodbye::Error { code, what } => {
            let _ = tokio::time::timeout(GOODBYE, chan.fail(code, what)).await;
        }
        Goodbye::Close => {
            let _ = tokio::time::timeout(GOODBYE, chan.close()).await;
        }
        Goodbye::Nothing => {}
    }
    let end = end?;
    Ok(HostOutcome::Session {
        device,
        label,
        paired_now,
        token,
        mode,
        unattended,
        th_final,
        end,
    })
}

/// The popup choice of an answer the sheet offered: `None` for Deny and for
/// an answer outside `offered`, which is refused, never lowered or raised.
fn accepted(decision: SessionDecision, offered: &Answers) -> Option<PopupChoice> {
    let choice = match decision {
        SessionDecision::AllowOnce => PopupChoice::AllowOnce,
        SessionDecision::AllowOnceViewOnly => PopupChoice::AllowOnceViewOnly,
        SessionDecision::AllowOnceAdmin => PopupChoice::AllowOnceAdmin,
        SessionDecision::Deny => return None,
    };
    offered.offers(choice.level()).then_some(choice)
}

/// Whether the answer `choice` takes the administrator helper on a host
/// offering `offered`: the administrator answer on a row whose host runs
/// with a filtered token (the Windows prompt, or no prompt with the helper).
fn needs_helper(choice: PopupChoice, offered: &Answers) -> bool {
    matches!(choice, PopupChoice::AllowOnceAdmin)
        && matches!(
            offered.admin,
            Some(AdminPath::WindowsPrompt | AdminPath::TornectConfirmation { needs_helper: true })
        )
}

/// Whether an unattended session's proof is at the administrator level on a
/// row whose host holds a filtered token (every row but the ones where every
/// program runs as administrator): its level takes the helper task.
fn unattended_needs_helper(proof: &ConsentProof, offered: &Answers) -> bool {
    matches!(proof, ConsentProof::Unattended { policy, .. } if policy.elevation() == Elevation::Admin)
        && !matches!(
            offered.admin,
            Some(AdminPath::TornectConfirmation {
                needs_helper: false
            })
        )
}

/// The mode and level of an unattended proof; `None` for any other proof.
fn unattended_level(proof: &ConsentProof) -> Option<(SessionMode, Elevation)> {
    match proof {
        ConsentProof::Unattended { policy, .. } => Some((policy.mode(), policy.elevation())),
        _ => None,
    }
}

/// Whether the proof given back after the reservation (`back`) is above the one the
/// gate minted (`minted`) in mode or in level, or is no unattended proof at all
/// (decision M1-67: that read only lowers).
fn raised(
    minted: Option<(SessionMode, Elevation)>,
    back: Option<(SessionMode, Elevation)>,
) -> bool {
    match (minted, back) {
        (Some((mode, level)), Some((back_mode, back_level))) => {
            SessionMode::most_restrictive(mode, back_mode) != back_mode
                || Elevation::most_restrictive(level, back_level) != back_level
        }
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// An unattended session's proof lowered to none (§B.8.7.5: the helper not
/// connected ⇒ elevation 0, and it stays 0).
fn without_elevation(proof: ConsentProof) -> ConsentProof {
    match proof {
        ConsentProof::Unattended {
            grant,
            proof_fp,
            policy,
            block,
            token,
        } => ConsentProof::Unattended {
            grant,
            proof_fp,
            policy: policy.with_elevation(Elevation::None),
            block,
            token,
        },
        other => other,
    }
}

/// Fixed text for a session that ended in an error (never peer-controlled).
fn end_detail(err: &HandshakeError) -> String {
    match err {
        HandshakeError::Violation { code, .. } => codes::name(*code).to_owned(),
        HandshakeError::Timeout(what) => format!("timeout({what})"),
        HandshakeError::Frame(FrameError::Truncated) => "truncated".to_owned(),
        HandshakeError::Frame(_) | HandshakeError::Io(_) => "io".to_owned(),
        HandshakeError::Aborted(what) => format!("aborted({what})"),
        _ => "error".to_owned(),
    }
}

async fn reject_session<S>(
    chan: &mut Channel<S>,
    deps: &HostDeps,
    peer: &TrustedPeer,
    reason: u16,
) -> Result<HostOutcome, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    chan.send(&SessionReject::new(reason), None).await?;
    chan.close().await;
    deps.audit.record(AuditEvent::SessionDenied {
        device: peer.device,
        label: peer.label.clone(),
        reason,
    });
    Ok(HostOutcome::SessionRejected {
        device: peer.device,
        label: peer.label.clone(),
        reason,
    })
}

/// `PairRequested → PairAccepted | PairRejected` for the received
/// `PAIR_REQUEST` `rx`: the pinned label, or the `PAIR_REJECT` reason that
/// was sent (the stream is closed then). `pinned` is the label of an already
/// trusted key asking to pair again (decision M1-32): the popup is told, and
/// a Deny does not count toward the temp-ban — `HELLO` is replayable, so the
/// request is no evidence that the trusted device itself sent it.
/// The two SAS inputs of §B.3: the transcript hash after `HELLO_ACK` and the
/// commitment the signed `HELLO` published for the nonce `PAIR_REQUEST` reveals.
#[derive(Clone, Copy)]
struct SasBinding<'a> {
    th_hello_ack: &'a [u8; 32],
    commit: &'a [u8; 32],
}

async fn pair<S>(
    chan: &mut Channel<S>,
    cfg: &HostConfig,
    deps: &HostDeps,
    device: &DeviceId,
    declared_name: &str,
    pinned: Option<&str>,
    rx: &Received,
    sas: SasBinding<'_>,
) -> Result<Result<String, u16>, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let request: PairRequest = chan.body(rx).await?;
    // The revealed nonce must open the commitment carried by the signed HELLO
    // (§B.3). Without this check the peer could choose its SAS contribution after
    // seeing ours, which makes a 20-bit code grindable to a collision.
    if crate::pairing::sas_commit(&request.sas_nonce) != *sas.commit {
        return Err(chan.fail(codes::E_BAD_LEN, "sas_commit").await);
    }
    chan.absorb(rx);
    let sas = crate::pairing::Sas::derive(sas.th_hello_ack, &request.sas_nonce);

    let refuse = |reason: u16| -> Result<Result<String, u16>, HandshakeError> {
        deps.audit.record(AuditEvent::PairRejected {
            device: *device,
            declared_name: declared_name.to_owned(),
            reason,
        });
        Ok(Err(reason))
    };
    if let Some(until) = deps.trusted.banned_until(device) {
        tracing::info!(peer = ?device, until, "pairing refused: temp-banned");
        send_pair_reject(chan, messages::pair_reject::BANNED).await?;
        return refuse(messages::pair_reject::BANNED);
    }
    // The limiter comes before anything the answer could disclose (decision
    // M1-9, amended): a BUSY answer costs a per-peer and a host-wide token
    // and takes the in-flight slot, so an unpaired key cannot poll whether a
    // remote session is live faster than it could open pairing popups.
    let _in_flight = match deps.policy.admit(*device.public_key_bytes()) {
        Ok(guard) => guard,
        Err(PairRefusal::InFlight) => {
            send_pair_reject(chan, messages::pair_reject::IN_FLIGHT).await?;
            return refuse(messages::pair_reject::IN_FLIGHT);
        }
        Err(PairRefusal::RateLimited) => {
            send_pair_reject(chan, messages::pair_reject::RATE_LIMITED).await?;
            return refuse(messages::pair_reject::RATE_LIMITED);
        }
    };
    if deps.activity.session_live() {
        deps.audit.record(AuditEvent::PopupSuppressed {
            device: *device,
            label: pinned.map(str::to_owned),
            popup: SuppressedPopup::Pairing,
        });
        send_pair_reject(chan, messages::pair_reject::BUSY).await?;
        return refuse(messages::pair_reject::BUSY);
    }

    deps.audit.record(AuditEvent::PairRequested {
        device: *device,
        declared_name: declared_name.to_owned(),
    });
    let peer = PairingPeer {
        device: *device,
        name: declared_name.to_owned(),
        fingerprint: device.fingerprint(),
        pinned_label: pinned.map(str::to_owned),
    };
    let decision = {
        let _pending = Counted::new(&deps.stats.pair_pending);
        tokio::time::timeout(timeouts::POPUP, deps.consent.pairing(&peer, &sas.render())).await
    };
    match decision {
        Err(_) => {
            send_pair_reject(chan, messages::pair_reject::TIMEOUT).await?;
            refuse(messages::pair_reject::TIMEOUT)
        }
        Ok(PairDecision::Reject) => {
            if pinned.is_none() {
                let until = deps
                    .trusted
                    .record_reject(*device, &deps.policy.limits().ban)?;
                if let Some(until) = until {
                    tracing::info!(peer = ?device, until, "peer temp-banned after repeated rejects");
                }
            }
            send_pair_reject(chan, messages::pair_reject::DENIED).await?;
            refuse(messages::pair_reject::DENIED)
        }
        Ok(PairDecision::Accept { label }) => {
            let wanted = match label {
                Some(l) => normalize_label(&l),
                None => declared_name.to_owned(),
            };
            // An already pinned device keeps its label (re-pair).
            let pinned = deps.trusted.pin(*device, &wanted)?;
            let accept = PairAccept {
                host_device_pk: cfg.host_device_pk,
                host_name: normalize_label(&cfg.host_name),
            };
            chan.send(&accept, None).await?;
            deps.audit.record(AuditEvent::PairAccepted {
                device: *device,
                label: pinned.clone(),
            });
            tracing::info!(peer = ?device, label = %pinned, "device paired");
            Ok(Ok(pinned))
        }
    }
}

async fn send_pair_reject<S>(chan: &mut Channel<S>, reason: u16) -> Result<(), HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    chan.send(
        &PairReject {
            reason,
            detail: None,
        },
        None,
    )
    .await?;
    chan.close().await;
    Ok(())
}

/// `Established`: answer `PING`, hand M2 frames to the sink, end on `BYE`,
/// the kill switch, the orphan timer or the idle timer. It returns as soon as
/// the session is over, with what is still to be written: the caller releases
/// the session first and says goodbye after. A violation found here (a body
/// that does not decode, a kind out of place) is returned unanswered, and its
/// `ERROR` is that goodbye (SLICE-C3 C3-2); only `recv`'s own checks answer in
/// place, inside the `select!` that the kill can win.
async fn established<S>(
    chan: &mut Channel<S>,
    cfg: &HostConfig,
    deps: &HostDeps,
    kill: &mut KillGuard,
) -> Result<(SessionEnd, Goodbye), HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // `checked_add`: a configured timeout near `Duration::MAX` means "never",
    // never a panic.
    let orphan_at = cfg
        .orphan_timeout
        .and_then(|d| Instant::now().checked_add(d));
    let mut have_path = false;
    loop {
        let now = Instant::now();
        let idle_at = now.checked_add(cfg.idle_timeout);
        let (deadline, orphan_first) = match (orphan_at, idle_at) {
            (Some(o), idle) if !have_path && idle.is_none_or(|i| o < i) => (Some(o), true),
            (_, idle) => (idle, false),
        };
        let wait = deadline.map_or(Duration::MAX, |d| d.saturating_duration_since(now));
        let received = tokio::select! {
            biased;
            reason = kill.killed() => {
                return Ok((SessionEnd::Killed(reason), Goodbye::Bye(reason)));
            }
            rx = chan.recv(wait, "frame") => rx,
        };
        let rx: Received = match received {
            Ok(Some(rx)) => rx,
            Ok(None) => return Ok((SessionEnd::PeerClosed, Goodbye::Nothing)),
            Err(HandshakeError::Timeout(_)) => {
                let end = if orphan_first {
                    SessionEnd::Orphaned
                } else {
                    SessionEnd::Idle
                };
                return Ok((end, Goodbye::Bye(messages::bye::ORPHANED)));
            }
            Err(e) => return Err(e),
        };
        match rx.env.kind {
            Kind::Ping => {
                let ping: Ping = checked_body(&rx)?;
                // A peer that stops reading stalls this write for as long as
                // it withholds credit; the kill must not wait behind it
                // (SLICE-B2 B2-1). The write goes first, so one that can
                // finish does; a kill that cuts one short leaves a torn frame,
                // after which nothing more is written.
                let pong = Pong { nonce: ping.nonce };
                tokio::select! {
                    biased;
                    sent = chan.send(&pong, None) => {
                        sent?;
                    }
                    reason = kill.killed() => {
                        return Ok((SessionEnd::Killed(reason), Goodbye::Nothing));
                    }
                }
            }
            Kind::Candidates => {
                let c: messages::Candidates = checked_body(&rx)?;
                have_path = true;
                deps.candidates.on_candidates(c);
            }
            Kind::CandidatesDone => {
                let _: messages::CandidatesDone = checked_body(&rx)?;
                have_path = true;
                deps.candidates.on_candidates_done();
            }
            Kind::TorFallback => {
                let _: messages::TorFallback = checked_body(&rx)?;
                have_path = true;
                deps.candidates.on_tor_fallback();
            }
            Kind::Bye => {
                let reason = decode_reason::<Bye>(&rx, |b| b.reason);
                return Ok((SessionEnd::PeerBye(reason), Goodbye::Close));
            }
            Kind::Error => {
                let code = decode_reason::<messages::Error>(&rx, |e| e.code);
                return Ok((SessionEnd::PeerError(code), Goodbye::Close));
            }
            _ => {
                return Err(HandshakeError::Violation {
                    code: codes::E_BAD_STATE,
                    what: "kind",
                });
            }
        }
    }
}

fn decode_reason<B: messages::Body>(rx: &Received, get: impl Fn(&B) -> u16) -> u16 {
    messages::decode_body::<B>(&rx.env.body)
        .map(|b| get(&b))
        .unwrap_or(0)
}
