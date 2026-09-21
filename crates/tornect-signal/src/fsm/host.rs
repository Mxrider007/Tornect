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
use tornect_core::session_log::SessionMode;
use tornect_core::unattended::guard::AdminEffect;
use zeroize::Zeroizing;

use super::{
    AuditEvent, AuthExchange, CandidateSink, Channel, HandshakeAudit, HandshakeError,
    IgnoreCandidates, NoAudit, OsRandom, Randomness, Received, SessionToken, SuppressedPopup,
    timeouts,
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
}

impl HostConfig {
    /// Defaults: no feats, empty caps, `Any` transport, the §B.8.4.5 orphan timer, 90 s idle.
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
    /// `true` while a remote session is live on this host.
    fn session_live(&self) -> bool;
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
}

/// `SESSION_REJECT{NOT_GRANTED}` for every unattended request (no grants exist).
#[derive(Debug, Clone, Copy, Default)]
pub struct NotGranted;

impl UnattendedHook for NotGranted {
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
#[derive(Debug, Clone, Copy, Default)]
struct KillState {
    /// Bumped by every [`KillSwitch::kill`]. A [`KillGuard`] compares this to
    /// the value it captured at arm time, so it reacts only to a kill fired
    /// after the session began — never to a stale latched reason.
    generation: u64,
    /// The reason the most recent kill fired with (for [`KillSwitch::fired`]).
    reason: Option<u16>,
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
        KillGuard { rx, base }
    }
}

/// One session's view of a [`KillSwitch`], from [`KillSwitch::arm`].
#[derive(Debug)]
pub struct KillGuard {
    rx: watch::Receiver<KillState>,
    base: u64,
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
            }
            if self.rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Apply the side effect of a remote admin command to live sessions (§B.8.4.1).
///
/// **M1 scope, stated plainly.** [`KillSwitch`] is host-wide: it carries one
/// `BYE` reason to every stream sharing these deps and cannot address a single
/// device. The two host-wide effects are therefore applied exactly; the two
/// per-device ones are not, and are not pretended to be. That gap is real but
/// bounded — the store mutation has already happened, so the revoked or
/// suspended device's *next* handshake fails its grant lookup, and at M1 no
/// media session exists to tear down (`tornect-session` owns live sessions from
/// M4, §B.8.14). The M4 row is where a per-device kill belongs; wiring a
/// host-wide kill to a per-device effect here would end innocent sessions to
/// look complete.
fn apply_admin_effect(deps: &HostDeps, effect: &AdminEffect) {
    match effect {
        AdminEffect::MasterOff => deps.kill.kill(messages::bye::MASTER_OFF),
        AdminEffect::RevokedAll(_) => deps.kill.kill(messages::bye::REVOKED),
        // Per-device, and the requester's own stream is already closed above.
        AdminEffect::Revoked(_) | AdminEffect::Suspended(_) | AdminEffect::EndSession => {}
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
    /// Nonces and tokens.
    pub random: Arc<dyn Randomness>,
    /// Counters.
    pub stats: Arc<HandshakeStats>,
    /// One-click kill.
    pub kill: KillSwitch,
}

impl HostDeps {
    /// Headless defaults: `AutoDeny`, no stop token, `NotGranted`, no live
    /// session, no audit, candidates ignored, OS randomness, default limits,
    /// a timer-only block window and `AlwaysDeny` for `ask_before_start`.
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
    /// Paired, and the peer left without a `SESSION_REQUEST`.
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
    tracing::debug!(peer = %device, paired = pinned.is_some(), "HELLO verified");

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
                Err(HandshakeError::Closed | HandshakeError::PeerBye { .. }) => {
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
    let (proof, caps) = if unattended {
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
            UnattendedVerdict::Accept { proof, caps } => (proof, caps),
        }
    } else {
        // AwaitConsent. The session popup has the pairing popup's budget —
        // one in flight per device, per-device and host-wide buckets — so a
        // paired key can neither stack popups nor open one per rendezvous;
        // then the live-session suppression of §B.8.6.2 (logged as such).
        let _slot = match deps.session_policy.admit(*device.public_key_bytes()) {
            Ok(guard) => guard,
            Err(refusal) => {
                tracing::debug!(peer = %device, ?refusal, "session popup refused by the limiter");
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
        let decision = {
            let _pending = Counted::new(&deps.stats.consent_pending);
            tokio::time::timeout(timeouts::POPUP, deps.consent.session(&peer, &summary)).await
        };
        let choice = match decision {
            Err(_) => {
                return reject_session(&mut chan, deps, &peer, messages::reject::POPUP_TIMEOUT)
                    .await;
            }
            Ok(SessionDecision::Deny) => {
                return reject_session(&mut chan, deps, &peer, messages::reject::DENIED).await;
            }
            Ok(SessionDecision::AllowOnce) => PopupChoice::AllowOnce,
            Ok(SessionDecision::AllowOnceViewOnly) => PopupChoice::AllowOnceViewOnly,
        };
        let mut token = Zeroizing::new([0u8; 32]);
        deps.random.fill(&mut token[..])?;
        let proof = ConsentProof::HumanClick {
            choice,
            at: Instant::now(),
            token: FreshToken::mint(*token),
        };
        (proof, ChosenCaps::negotiate(&cfg.caps, &request.caps))
    };

    // Accept → Established. `build` is the only source of the session token:
    // the accept body carries `session_token` for attended sessions and only
    // `token_confirm` for unattended ones (§B.8.4.3), never the BIND key.
    let (accept, token) = SessionAccept::build(proof, caps, &host_info);
    let session_id = token.session_id();
    let mode = mode_from_code(accept.mode()).unwrap_or(SessionMode::ViewOnly);
    chan.send(&accept, Some(&*deps.signer)).await?;
    deps.stats.accepted_total.fetch_add(1, Ordering::SeqCst);
    deps.audit.record(AuditEvent::SessionStarted {
        device,
        label: label.clone(),
        session_id: session_id.clone(),
        mode,
        unattended,
    });
    tracing::info!(peer = %device, %label, session = %session_id, "session accepted");

    let th_final = chan.th();
    let end = {
        let _established = Counted::new(&deps.stats.established);
        established(&mut chan, cfg, deps, &mut kill).await
    };
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
        tracing::info!(peer = %device, until, "pairing refused: temp-banned");
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
                    tracing::info!(peer = %device, until, "peer temp-banned after repeated rejects");
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
            tracing::info!(peer = %device, label = %pinned, "device paired");
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
/// the kill switch, the orphan timer or the idle timer.
async fn established<S>(
    chan: &mut Channel<S>,
    cfg: &HostConfig,
    deps: &HostDeps,
    kill: &mut KillGuard,
) -> Result<SessionEnd, HandshakeError>
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
                chan.bye(reason).await?;
                return Ok(SessionEnd::Killed(reason));
            }
            rx = chan.recv(wait, "frame") => rx,
        };
        let rx: Received = match received {
            Ok(Some(rx)) => rx,
            Ok(None) => return Ok(SessionEnd::PeerClosed),
            Err(HandshakeError::Timeout(_)) => {
                chan.bye(messages::bye::ORPHANED).await?;
                return Ok(if orphan_first {
                    SessionEnd::Orphaned
                } else {
                    SessionEnd::Idle
                });
            }
            Err(e) => return Err(e),
        };
        match rx.env.kind {
            Kind::Ping => {
                let ping: Ping = chan.body(&rx).await?;
                chan.send(&Pong { nonce: ping.nonce }, None).await?;
            }
            Kind::Candidates => {
                let c: messages::Candidates = chan.body(&rx).await?;
                have_path = true;
                deps.candidates.on_candidates(c);
            }
            Kind::CandidatesDone => {
                let _: messages::CandidatesDone = chan.body(&rx).await?;
                have_path = true;
                deps.candidates.on_candidates_done();
            }
            Kind::TorFallback => {
                let _: messages::TorFallback = chan.body(&rx).await?;
                have_path = true;
                deps.candidates.on_tor_fallback();
            }
            Kind::Bye => {
                let reason = decode_reason::<Bye>(&rx, |b| b.reason);
                chan.close().await;
                return Ok(SessionEnd::PeerBye(reason));
            }
            Kind::Error => {
                let code = decode_reason::<messages::Error>(&rx, |e| e.code);
                chan.close().await;
                return Ok(SessionEnd::PeerError(code));
            }
            _ => return Err(chan.fail(codes::E_BAD_STATE, "kind").await),
        }
    }
}

fn decode_reason<B: messages::Body>(rx: &Received, get: impl Fn(&B) -> u16) -> u16 {
    messages::decode_body::<B>(&rx.env.body)
        .map(|b| get(&b))
        .unwrap_or(0)
}
