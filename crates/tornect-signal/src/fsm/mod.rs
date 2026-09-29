//! The `HELLO` … `SESSION_ACCEPT` state machines (`docs/PLAN.md` §B.2,
//! §B.8.4.2, §B.8.4.5) and the channel they share.
//!
//! * [`host`] — the host side: `Start → HelloVerified → (PairRequested →
//!   PairAccepted | PairRejected) → AwaitSessionRequest → AwaitConsent →
//!   Established → Closing`, behind the injected seams of [`host::HostDeps`].
//! * [`client`] — the client side: dial, `HELLO`, verify `HELLO_ACK` against
//!   the dialed address, pair with the SAS shown through
//!   [`client::ClientPairingUi`], `SESSION_REQUEST`, verify `SESSION_ACCEPT`.
//! * [`Channel`] — one framed stream with per-direction `msg_id`s, the
//!   negotiated version, the transcript, the strict-alternation window and
//!   the `ERROR` / close discipline. Every network wait is bounded by a
//!   [`timeouts`] constant.
//! * [`vectors`] and [`harness`] — the fixed inputs of the golden vectors and
//!   the F1 harness that feeds either FSM arbitrary frames (the fuzz target
//!   and its committed seeds are built on them).
//!
//! Both FSMs are generic over any `AsyncRead + AsyncWrite + Unpin + Send`
//! stream: [`crate::OnionStream`] in production, `tokio::io::duplex` in tests.

pub mod client;
pub mod harness;
pub mod host;
pub mod vectors;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tornect_core::DeviceId;
use tornect_core::session_log::{
    AggregatedReject, RejectAggregator, SessionEvent, SessionLog, SessionMode, SessionRecord,
};
use tornect_core::trusted;
use zeroize::{Zeroize as _, Zeroizing};

pub use crate::consent::SessionToken;
use crate::envelope::{Envelope, EnvelopeError, Kind, codes};
use crate::framing::{FrameError, MAX_FRAME_LEN, read_frame_max, write_frame};
use crate::messages::{self, Body, BodyError, decode_body, encode_body};
use crate::pairing::{BoxFuture, lock};
use crate::transcript::{HostSigner, Transcript, sign_envelope, wire_bytes};

/// Every timer of §B.8.4.5, plus the ones the plan leaves to M1 (decision M1-13).
pub mod timeouts {
    use std::time::Duration;

    /// Host: a stream that sends no `HELLO` (plan: unauthenticated peers never hold a slot for free).
    pub const HELLO: Duration = Duration::from_secs(30);
    /// Client: `HELLO_ACK` after `HELLO`.
    pub const HELLO_ACK: Duration = Duration::from_secs(20);
    /// Host: `SESSION_REQUEST` after `HELLO_ACK`, restarted at `PAIR_ACCEPT` / `PAIR_REJECT`.
    pub const SESSION_REQUEST: Duration = Duration::from_secs(60);
    /// Host: the pairing and session popups.
    pub const POPUP: Duration = Duration::from_secs(60);
    /// Client: `PAIR_ACCEPT` / `PAIR_REJECT` after `PAIR_REQUEST` (the host popup's 60 s + Tor).
    pub const PAIR_ACCEPT: Duration = Duration::from_secs(90);
    /// Client: the fixed `30 + 60 + 20 s` for `SESSION_ACCEPT` (never shortened by grant policy).
    pub const SESSION_ACCEPT: Duration = Duration::from_secs(110);
    /// Client: `AUTH_CHALLENGE` after an unattended `SESSION_REQUEST`.
    pub const AUTH_CHALLENGE: Duration = Duration::from_secs(30);
    /// Host: `AUTH_RESPONSE` after `AUTH_CHALLENGE` (charged).
    pub const AUTH_RESPONSE: Duration = Duration::from_secs(30);
    /// Host: `CANDIDATES` / `TOR_FALLBACK` after `SESSION_ACCEPT`, else `BYE{ORPHANED}`.
    pub const ORPHAN: Duration = Duration::from_secs(15);
    /// Either side: a `PONG` after a `PING`.
    pub const PONG: Duration = Duration::from_secs(30);
    /// Host: an established stream with no frame at all (the client keeps the
    /// circuit alive with `PING`s, §B.2 "low-rate heartbeat").
    pub const ESTABLISHED_IDLE: Duration = Duration::from_secs(90);
    /// Client: sending `BYE`, waiting for the host to close, and closing. A
    /// Tor round trip must fit, and a host that stops reading must not keep
    /// the client from leaving (SLICE-B2 B2-8).
    pub const BYE: Duration = Duration::from_secs(3);
}

/// Largest frame accepted before the handshake window closes: a `HELLO`
/// is ≈ 200 bytes and a `SESSION_REQUEST{unattended}` ≈ 300, so an
/// unauthenticated peer can reserve at most this much per stream (A17;
/// decision M1-13). After `SESSION_ACCEPT` the §B.3 64 KiB limit applies.
pub const HANDSHAKE_FRAME_CAP: usize = 8 * 1024;

/// How a handshake or session ended without an accept.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HandshakeError {
    /// We detected a protocol violation, sent `ERROR{code}` and closed.
    #[error("protocol violation {}: {what}", codes::name(*code))]
    Violation {
        /// The `ERROR` code sent.
        code: u16,
        /// Which check failed (fixed text, never peer-controlled).
        what: &'static str,
    },
    /// The peer sent `ERROR{code}`.
    #[error("peer reported {}", codes::name(*code))]
    PeerError {
        /// The code.
        code: u16,
        /// The peer's free text (untrusted; render as plain text).
        detail: Option<String>,
    },
    /// The peer sent `BYE{reason}` before the session was established.
    #[error("peer said goodbye ({})", messages::bye::name(*reason))]
    PeerBye {
        /// The reason.
        reason: u16,
        /// Untrusted free text.
        detail: Option<String>,
    },
    /// Client side: the host answered `PAIR_REJECT`.
    #[error("pairing rejected ({})", messages::pair_reject::name(*reason))]
    PairRejected {
        /// A [`messages::pair_reject`] code.
        reason: u16,
        /// Untrusted free text.
        detail: Option<String>,
    },
    /// Client side: the host answered `SESSION_REJECT`.
    #[error("session rejected ({})", messages::reject::name(reject.reason))]
    SessionRejected {
        /// The full reject body.
        reject: Box<messages::SessionReject>,
    },
    /// Client side: the host answered `E_BAD_STATE` to the `SESSION_REQUEST`
    /// of a host this device believes it is paired with — the host no longer
    /// trusts this device (unpaired there, or its state was lost). Forget the
    /// host and pair again.
    #[error("the host no longer trusts this device: forget it and pair again")]
    PairingLost,
    /// A §B.8.4.5 timer elapsed; the payload says which wait.
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    /// The peer closed the stream.
    #[error("peer closed the stream")]
    Closed,
    /// A local decision ended the exchange (SAS not confirmed, kill switch, …).
    #[error("aborted: {0}")]
    Aborted(&'static str),
    /// Client side, unattended: the host's `AUTH_CHALLENGE` did not verify under this
    /// password — a wrong password, or a grant registered again since — so no proof was
    /// sent and the host was told `BYE{CLIENT_AUTH_ABORT}` (§B.8.4.2). The password was not
    /// proven: what the host logs as a failed attempt.
    #[error("the unattended password was not accepted")]
    PasswordRefused,
    /// Client side, unattended: the host's OPAQUE key differs from the one pinned at the
    /// first accept (A16): its unattended setup was created again since, or this is not
    /// that host. Checked before the proof, so none was sent.
    #[error("the host's unattended setup changed since the last connection")]
    ServerKeyChanged,
    /// Framing failure (truncated frame, oversize frame we announced, I/O).
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Transport I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A store (trusted devices, known hosts) could not be read or written.
    #[error(transparent)]
    Store(#[from] tornect_core::CoreError),
    /// The OS random number generator failed.
    #[error("random number generator failure: {0}")]
    Rng(String),
}

impl HandshakeError {
    /// The `ERROR` code this side sent, if the error is a violation.
    #[must_use]
    pub fn violation_code(&self) -> Option<u16> {
        match self {
            HandshakeError::Violation { code, .. } => Some(*code),
            _ => None,
        }
    }
}

/// Source of nonces and tokens: the OS RNG in production, a scripted one in
/// tests and golden vectors.
pub trait Randomness: Send + Sync {
    /// Fill `buf` with random bytes.
    fn fill(&self, buf: &mut [u8]) -> Result<(), HandshakeError>;
}

/// The OS RNG (`getrandom`).
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl Randomness for OsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), HandshakeError> {
        getrandom::fill(buf).map_err(|e| HandshakeError::Rng(e.to_string()))
    }
}

/// A [`Randomness`] that hands out scripted values in order (tests and the
/// golden vector); once the script is exhausted it repeats the last value.
#[derive(Debug, Default)]
pub struct ScriptedRandom {
    values: Mutex<Vec<Vec<u8>>>,
}

impl ScriptedRandom {
    /// A script of fills, used in order.
    #[must_use]
    pub fn new(values: Vec<Vec<u8>>) -> Self {
        Self {
            values: Mutex::new(values),
        }
    }
}

impl Randomness for ScriptedRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), HandshakeError> {
        let mut values = lock(&self.values);
        let next = if values.len() > 1 {
            values.remove(0)
        } else {
            values.first().cloned().unwrap_or_default()
        };
        for (dst, src) in buf.iter_mut().zip(next.iter().cycle()) {
            *dst = *src;
        }
        Ok(())
    }
}

/// What happened to a session's administrator helper ([`AuditEvent::AdminHelper`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperEvent {
    /// Connected and checked in time: the accept carries the administrator level.
    Started,
    /// Stopped (the session ended, the helper's panic chord, a lost pipe).
    Stopped,
    /// Not started or not attached: the session got no administrator access.
    Failed,
}

/// Events the host FSM records in `sessions.log` (`docs/PLAN.md` §B.6:
/// every pairing / session event is appended locally). `peer_name` in the
/// log is the *pinned* label only (§B.8.13, §B.8.16): the name a not yet
/// paired peer declares is carried here for the popup and the CLI but never
/// written to the log, where any key could otherwise plant chosen text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditEvent {
    /// An unpaired peer asked to pair.
    PairRequested {
        /// The peer.
        device: DeviceId,
        /// Its declared name (normalized) — shown, never logged.
        declared_name: String,
    },
    /// The host user accepted the pairing.
    PairAccepted {
        /// The peer.
        device: DeviceId,
        /// The pinned label.
        label: String,
    },
    /// The pairing was rejected (by the user, a timeout, a ban or a limit).
    PairRejected {
        /// The peer.
        device: DeviceId,
        /// Its declared name (normalized) — shown, never logged.
        declared_name: String,
        /// A [`messages::pair_reject`] code.
        reason: u16,
    },
    /// A paired device asked for a session.
    SessionRequested {
        /// The peer.
        device: DeviceId,
        /// The pinned label.
        label: String,
        /// Whether the request carried `unattended`.
        unattended: bool,
    },
    /// A session was accepted (`SESSION_ACCEPT` sent).
    SessionStarted {
        /// The peer.
        device: DeviceId,
        /// The pinned label.
        label: String,
        /// Session id ([`SessionToken::session_id`], a one-way derivation).
        session_id: String,
        /// The mode.
        mode: SessionMode,
        /// The administrator level signed in the accept (r7, §B.8.13).
        elevation: tornect_core::levels::Elevation,
        /// Whether it is an unattended session.
        unattended: bool,
    },
    /// The administrator helper of a session (§B.8.7.5): started (connected
    /// and checked, before the accept), stopped, or failed (the session got
    /// no administrator access).
    AdminHelper {
        /// The peer.
        device: DeviceId,
        /// The pinned label.
        label: String,
        /// The session, once there is one (a helper that failed before the
        /// accept has none).
        session_id: Option<String>,
        /// What happened.
        what: HelperEvent,
        /// Why, in fixed words (never peer-controlled).
        reason: &'static str,
    },
    /// A session request was rejected.
    SessionDenied {
        /// The peer.
        device: DeviceId,
        /// The pinned label.
        label: String,
        /// A [`messages::reject`] code.
        reason: u16,
    },
    /// An established session ended — however it ended: a peer `BYE`, a
    /// protocol violation, a truncated frame, an I/O error, the kill switch or
    /// a timer (§B.6: every session end is logged).
    SessionEnded {
        /// The peer.
        device: DeviceId,
        /// The pinned label.
        label: String,
        /// Session id.
        session_id: String,
        /// How (fixed text, never peer-controlled).
        detail: String,
    },
    /// A consent popup was not shown because a remote session is live
    /// (§B.8.6.2: answered `BUSY`, `popup_suppressed_remote_session` logged,
    /// the owner notified afterwards).
    PopupSuppressed {
        /// The peer.
        device: DeviceId,
        /// The pinned label, when the peer is paired.
        label: Option<String>,
        /// Which popup.
        popup: SuppressedPopup,
    },
}

/// Which consent popup [`AuditEvent::PopupSuppressed`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressedPopup {
    /// The pairing popup (`PAIR_REJECT{BUSY}`).
    Pairing,
    /// The session popup (`SESSION_REJECT{BUSY}`).
    Session,
}

impl SuppressedPopup {
    /// The `detail` word in the log line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pairing => "pairing",
            Self::Session => "session",
        }
    }
}

/// Where the host FSM records [`AuditEvent`]s.
pub trait HandshakeAudit: Send + Sync {
    /// Record `event`; failures are the implementation's to log, never fatal.
    fn record(&self, event: AuditEvent);
}

/// Records nothing (tests, the client role).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAudit;

impl HandshakeAudit for NoAudit {
    fn record(&self, _: AuditEvent) {}
}

/// `sessions.log` as the host FSM's audit sink (§B.6 "all session starts/ends
/// logged locally", §B.8.13 field rules).
///
/// Every event is one line, except the rejects a peer can provoke without a
/// human in the loop — `PAIR_REJECT{BANNED | IN_FLIGHT | RATE_LIMITED}` and
/// `SESSION_REJECT{BUSY}` — which are rate-aggregated the way the plan
/// aggregates pre-PAKE rejects: one line per (device, reason) per
/// [`RejectAggregator::WINDOW`], stamped with the first occurrence and
/// carrying `count`, so one key cannot fill the log at the circuit rate. A
/// bucket is written once its window closed, at the next recorded event, at
/// [`HostAudit::flush`], or when the last handle is dropped — the CLI keeps
/// one `Arc<HostAudit>` for the host's lifetime.
pub struct HostAudit {
    log: Arc<SessionLog>,
    epoch: std::time::Instant,
    pair_rejects: Mutex<RejectAggregator>,
    session_denials: Mutex<RejectAggregator>,
}

impl HostAudit {
    /// Write to `log`.
    #[must_use]
    pub fn new(log: Arc<SessionLog>) -> Self {
        Self {
            log,
            epoch: std::time::Instant::now(),
            pair_rejects: Mutex::new(RejectAggregator::default()),
            session_denials: Mutex::new(RejectAggregator::default()),
        }
    }

    /// The log this sink writes to.
    #[must_use]
    pub fn log(&self) -> &Arc<SessionLog> {
        &self.log
    }

    /// Write every open aggregation bucket now (shutdown).
    pub fn flush(&self) {
        let pairs = lock(&self.pair_rejects).flush_all();
        let sessions = lock(&self.session_denials).flush_all();
        self.emit(
            SessionEvent::PairRejected,
            pairs,
            messages::pair_reject::name,
        );
        self.emit(
            SessionEvent::SessionDenied,
            sessions,
            messages::reject::name,
        );
    }

    /// Whether a pairing reject with `reason` is aggregated rather than
    /// written per stream.
    #[must_use]
    pub const fn aggregates_pair_reject(reason: u16) -> bool {
        matches!(
            reason,
            messages::pair_reject::BANNED
                | messages::pair_reject::IN_FLIGHT
                | messages::pair_reject::RATE_LIMITED
        )
    }

    fn mono(&self) -> Duration {
        self.epoch.elapsed()
    }

    fn write(&self, record: SessionRecord) {
        if let Err(e) = self.log.append(&record) {
            tracing::warn!(error = %e, "could not append to sessions.log");
        }
    }

    fn emit(
        &self,
        event: SessionEvent,
        closed: Vec<AggregatedReject>,
        name: fn(u16) -> &'static str,
    ) {
        for a in closed {
            self.write(
                SessionRecord::at(a.first_at, event)
                    .device(a.device)
                    .detail(name(a.reason))
                    .count(a.count),
            );
        }
    }

    /// Write the buckets whose windows closed, so lines stay in time order.
    fn drain(&self) {
        let mono = self.mono();
        let pairs = lock(&self.pair_rejects).drain(mono);
        let sessions = lock(&self.session_denials).drain(mono);
        self.emit(
            SessionEvent::PairRejected,
            pairs,
            messages::pair_reject::name,
        );
        self.emit(
            SessionEvent::SessionDenied,
            sessions,
            messages::reject::name,
        );
    }
}

impl Drop for HostAudit {
    fn drop(&mut self) {
        self.flush();
    }
}

impl HandshakeAudit for HostAudit {
    fn record(&self, event: AuditEvent) {
        self.drain();
        let record = match event {
            // No pinned label exists before pairing: device only (§B.8.13).
            AuditEvent::PairRequested { device, .. } => {
                SessionRecord::now(SessionEvent::PairRequested).device(device)
            }
            AuditEvent::PairAccepted { device, label } => {
                SessionRecord::now(SessionEvent::PairAccepted).peer(device, label)
            }
            AuditEvent::PairRejected { device, reason, .. }
                if Self::aggregates_pair_reject(reason) =>
            {
                let closed =
                    lock(&self.pair_rejects).note(device, reason, self.mono(), trusted::unix_now());
                self.emit(
                    SessionEvent::PairRejected,
                    closed,
                    messages::pair_reject::name,
                );
                return;
            }
            AuditEvent::PairRejected { device, reason, .. } => {
                SessionRecord::now(SessionEvent::PairRejected)
                    .device(device)
                    .detail(messages::pair_reject::name(reason))
            }
            AuditEvent::SessionRequested {
                device,
                label,
                unattended,
            } => SessionRecord::now(SessionEvent::SessionRequested)
                .peer(device, label)
                .unattended(unattended),
            AuditEvent::SessionStarted {
                device,
                label,
                session_id,
                mode,
                elevation,
                unattended,
            } => SessionRecord::now(SessionEvent::SessionStarted)
                .peer(device, label)
                .session(session_id)
                .mode(mode)
                .elevation(elevation)
                .unattended(unattended),
            AuditEvent::AdminHelper {
                device,
                label,
                session_id,
                what,
                reason,
            } => {
                let record = SessionRecord::now(match what {
                    HelperEvent::Started => SessionEvent::AdminHelperStarted,
                    HelperEvent::Stopped => SessionEvent::AdminHelperStopped,
                    HelperEvent::Failed => SessionEvent::AdminHelperFailed,
                })
                .peer(device, label)
                .elevation(tornect_core::levels::Elevation::Admin)
                .reason(reason);
                match session_id {
                    Some(id) => record.session(id),
                    None => record,
                }
            }
            AuditEvent::SessionDenied {
                device,
                reason: messages::reject::BUSY,
                ..
            } => {
                let closed = lock(&self.session_denials).note(
                    device,
                    messages::reject::BUSY,
                    self.mono(),
                    trusted::unix_now(),
                );
                self.emit(SessionEvent::SessionDenied, closed, messages::reject::name);
                return;
            }
            AuditEvent::SessionDenied {
                device,
                label,
                reason,
            } => SessionRecord::now(SessionEvent::SessionDenied)
                .peer(device, label)
                .detail(messages::reject::name(reason)),
            AuditEvent::SessionEnded {
                device,
                label,
                session_id,
                detail,
            } => SessionRecord::now(SessionEvent::SessionEnded)
                .peer(device, label)
                .session(session_id)
                .detail(detail),
            AuditEvent::PopupSuppressed {
                device,
                label,
                popup,
            } => {
                let record = SessionRecord::now(SessionEvent::PopupSuppressedRemoteSession)
                    .detail(popup.name())
                    .during_remote_session(true);
                match label {
                    Some(label) => record.peer(device, label),
                    None => record.device(device),
                }
            }
        };
        self.write(record);
    }
}

/// Sink for the post-accept frames M2 consumes (`CANDIDATES`,
/// `CANDIDATES_DONE`, `TOR_FALLBACK`); M1 only proves they arrive.
pub trait CandidateSink: Send + Sync {
    /// A `CANDIDATES` frame.
    fn on_candidates(&self, candidates: messages::Candidates);
    /// A `CANDIDATES_DONE` frame.
    fn on_candidates_done(&self);
    /// A `TOR_FALLBACK` frame.
    fn on_tor_fallback(&self);
}

/// Drops everything (M1 default).
#[derive(Debug, Clone, Copy, Default)]
pub struct IgnoreCandidates;

impl CandidateSink for IgnoreCandidates {
    fn on_candidates(&self, _: messages::Candidates) {}
    fn on_candidates_done(&self) {}
    fn on_tor_fallback(&self) {}
}

/// A frame received and checked at the envelope level (not yet at the
/// state or signature level). Both copies of the body are zeroized on drop
/// and hidden from `Debug` (a `SESSION_ACCEPT` carries the attended token).
#[derive(Clone, PartialEq, Eq)]
pub struct Received {
    /// The decoded envelope.
    pub env: Envelope,
    /// The exact bytes that were on the wire, length prefix included.
    pub wire: Vec<u8>,
}

impl core::fmt::Debug for Received {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Received")
            .field("env", &self.env)
            .field("wire", &format_args!("<{} bytes>", self.wire.len()))
            .finish()
    }
}

impl Drop for Received {
    fn drop(&mut self) {
        self.wire.zeroize();
    }
}

/// One direction-aware framed stream: `msg_id`s, version, transcript,
/// strict-alternation phase and the close discipline.
#[derive(Debug)]
pub struct Channel<S> {
    stream: S,
    tx_next: u64,
    rx_next: u64,
    version: u8,
    negotiated: bool,
    th: Transcript,
    in_window: bool,
    closing: bool,
    frame_cap: usize,
}

impl<S> Channel<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// A channel seeded with `th_0` for `host_onion_pk`, before `HELLO`.
    pub fn new(stream: S, host_onion_pk: &[u8; 32]) -> Self {
        Self {
            stream,
            tx_next: 1,
            rx_next: 1,
            version: tornect_core::PROTOCOL_VERSION,
            negotiated: false,
            th: Transcript::new(host_onion_pk),
            in_window: true,
            closing: false,
            frame_cap: HANDSHAKE_FRAME_CAP,
        }
    }

    /// The current transcript hash.
    #[must_use]
    pub fn th(&self) -> [u8; 32] {
        self.th.current()
    }

    /// The protocol version frames carry (`1` until `HELLO_ACK` fixes it).
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Fix the negotiated version (after `HELLO_ACK`); later frames must carry it.
    pub fn set_version(&mut self, v: u8) {
        self.version = v;
        self.negotiated = true;
    }

    /// Whether the strict-alternation window is still open.
    #[must_use]
    pub fn in_window(&self) -> bool {
        self.in_window
    }

    /// Whether this side has closed (frames are dropped from then on).
    #[must_use]
    pub fn is_closing(&self) -> bool {
        self.closing
    }

    /// Take the stream back (after the handshake, for the session layer).
    pub fn into_stream(self) -> S {
        self.stream
    }

    /// Next `msg_id` this side will send.
    #[must_use]
    pub fn next_tx_id(&self) -> u64 {
        self.tx_next
    }

    /// Next `msg_id` expected from the peer.
    #[must_use]
    pub fn next_rx_id(&self) -> u64 {
        self.rx_next
    }

    /// Build the envelope for `body` with the next `msg_id`, sign it if a
    /// signer is given, send it, and absorb it into the transcript when it
    /// belongs to the open window. Returns the frame payload (zeroized on
    /// drop: a `SESSION_ACCEPT` carries the attended token).
    pub async fn send<B: Body>(
        &mut self,
        body: &B,
        signer: Option<&dyn HostSigner>,
    ) -> Result<Zeroizing<Vec<u8>>, HandshakeError> {
        self.send_kind(B::KIND, encode_body(body), signer).await
    }

    /// [`Channel::send`] with an already encoded body of `kind`.
    pub async fn send_kind(
        &mut self,
        kind: Kind,
        body: Vec<u8>,
        signer: Option<&dyn HostSigner>,
    ) -> Result<Zeroizing<Vec<u8>>, HandshakeError> {
        if self.closing {
            return Err(HandshakeError::Aborted("channel is closing"));
        }
        let mut env = Envelope::new(self.version, self.tx_next, kind, body);
        if let Some(signer) = signer {
            sign_envelope(signer, &self.th.current(), &mut env);
        }
        let payload = Zeroizing::new(env.encode());
        write_frame(&mut self.stream, &payload).await?;
        self.tx_next = self.tx_next.saturating_add(1);
        self.note_handshake_frame(kind, &payload);
        Ok(payload)
    }

    /// Absorb a frame into the transcript if it belongs to the open window,
    /// and close the window on the kinds that end it.
    fn note_handshake_frame(&mut self, kind: Kind, payload: &[u8]) {
        if self.in_window && kind.in_handshake() {
            self.th.absorb_payload(payload);
            if kind.ends_handshake() {
                self.in_window = false;
                self.frame_cap = MAX_FRAME_LEN;
            }
        }
    }

    /// Absorb a verified received frame (call after its signature checked out).
    pub fn absorb(&mut self, rx: &Received) {
        if self.in_window && rx.env.kind.in_handshake() {
            self.th.absorb_wire(&rx.wire);
            if rx.env.kind.ends_handshake() {
                self.in_window = false;
                self.frame_cap = MAX_FRAME_LEN;
            }
        }
    }

    /// Read one frame within `timeout` and check it at the envelope level:
    /// size (`E_TOO_LARGE`), shape (`E_BAD_LEN` / `E_UNKNOWN_KIND`), `msg_id`
    /// (`E_BAD_MSG_ID`) and version (`E_VERSION`). A violation is answered
    /// with `ERROR` and the stream closed; `Ok(None)` is a clean EOF.
    pub async fn recv(
        &mut self,
        timeout: Duration,
        what: &'static str,
    ) -> Result<Option<Received>, HandshakeError> {
        if self.closing {
            return Err(HandshakeError::Aborted("channel is closing"));
        }
        let read =
            tokio::time::timeout(timeout, read_frame_max(&mut self.stream, self.frame_cap)).await;
        let payload = match read {
            Err(_) => return Err(HandshakeError::Timeout(what)),
            Ok(Ok(Some(p))) => Zeroizing::new(p),
            Ok(Ok(None)) => return Ok(None),
            Ok(Err(FrameError::TooLarge { .. })) => {
                return Err(self.fail(codes::E_TOO_LARGE, "frame").await);
            }
            Ok(Err(e)) => return Err(e.into()),
        };
        let env = match Envelope::decode(&payload) {
            Ok(env) => env,
            Err(e) => {
                let what = match e {
                    EnvelopeError::UnknownKind(_) => "kind",
                    _ => "envelope",
                };
                return Err(self.fail(e.code(), what).await);
            }
        };
        if env.msg_id != self.rx_next {
            return Err(self.fail(codes::E_BAD_MSG_ID, "msg_id").await);
        }
        self.rx_next = self.rx_next.saturating_add(1);
        // Before negotiation a `HELLO` must carry v = 1 and a `HELLO_ACK` may
        // carry any version (the client checks it against `v_max`); from the
        // negotiated version on, every frame must carry it.
        let expected_v = match (self.negotiated, env.kind) {
            (false, Kind::Hello) => Some(tornect_core::PROTOCOL_VERSION),
            (false, Kind::HelloAck) => None,
            _ => Some(self.version),
        };
        if expected_v.is_some_and(|v| env.v != v) {
            return Err(self.fail(codes::E_VERSION, "version").await);
        }
        Ok(Some(Received {
            wire: wire_bytes(&payload),
            env,
        }))
    }

    /// [`Channel::recv`] restricted to `allowed` kinds: `ERROR` / `BYE`
    /// become [`HandshakeError::PeerError`] / [`HandshakeError::PeerBye`],
    /// EOF becomes [`HandshakeError::Closed`], any other kind is answered
    /// with `E_BAD_STATE`.
    pub async fn recv_expect(
        &mut self,
        timeout: Duration,
        what: &'static str,
        allowed: &[Kind],
    ) -> Result<Received, HandshakeError> {
        let rx = self
            .recv(timeout, what)
            .await?
            .ok_or(HandshakeError::Closed)?;
        if allowed.contains(&rx.env.kind) {
            return Ok(rx);
        }
        match rx.env.kind {
            Kind::Error => {
                self.closing = true;
                let (code, detail) = match decode_body::<messages::Error>(&rx.env.body) {
                    Ok(e) => (e.code, e.detail),
                    Err(_) => (0, None),
                };
                Err(HandshakeError::PeerError { code, detail })
            }
            Kind::Bye => {
                self.closing = true;
                let (reason, detail) = match decode_body::<messages::Bye>(&rx.env.body) {
                    Ok(b) => (b.reason, b.detail),
                    Err(_) => (0, None),
                };
                Err(HandshakeError::PeerBye { reason, detail })
            }
            _ => Err(self.fail(codes::E_BAD_STATE, "kind").await),
        }
    }

    /// Decode and validate a received body, answering `E_BAD_LEN` on failure.
    pub async fn body<B: Body>(&mut self, rx: &Received) -> Result<B, HandshakeError> {
        match decode_body::<B>(&rx.env.body) {
            Ok(b) => Ok(b),
            Err(e) => Err(self.fail(codes::E_BAD_LEN, body_fault(&e)).await),
        }
    }

    /// Send `ERROR{code}` (fixed detail per code, so a pinned and an unpinned
    /// peer see byte-identical answers), close, and return the matching error.
    pub async fn fail(&mut self, code: u16, what: &'static str) -> HandshakeError {
        if !self.closing {
            let body = messages::Error {
                code,
                detail: Some(codes::name(code).to_owned()),
            };
            let env = Envelope::new(self.version, self.tx_next, Kind::Error, encode_body(&body));
            self.tx_next = self.tx_next.saturating_add(1);
            // Best effort: the peer may already be gone.
            let _ = write_frame(&mut self.stream, &env.encode()).await;
            self.closing = true;
            let _ = self.stream.shutdown().await;
        }
        HandshakeError::Violation { code, what }
    }

    /// Send `BYE{reason}` and close.
    pub async fn bye(&mut self, reason: u16) -> Result<(), HandshakeError> {
        if self.closing {
            return Ok(());
        }
        let body = messages::Bye {
            reason,
            detail: None,
        };
        let result = self.send(&body, None).await.map(|_| ());
        self.closing = true;
        let _ = self.stream.shutdown().await;
        result
    }

    /// Close without a frame.
    pub async fn close(&mut self) {
        self.closing = true;
        let _ = self.stream.shutdown().await;
    }
}

/// Decode and validate a received body without answering: the error is the
/// `E_BAD_LEN` violation [`Channel::body`] would send. For a caller that must
/// record the end before it writes to the peer (SLICE-C3 C3-2), and then sends
/// the `ERROR` with [`Channel::fail`].
pub(crate) fn checked_body<B: Body>(rx: &Received) -> Result<B, HandshakeError> {
    decode_body::<B>(&rx.env.body).map_err(|e| HandshakeError::Violation {
        code: codes::E_BAD_LEN,
        what: body_fault(&e),
    })
}

/// Which body check failed, as `Violation::what`.
fn body_fault(e: &BodyError) -> &'static str {
    match e {
        BodyError::Malformed { .. } => "body",
        BodyError::TooLong { .. } => "bound",
        BodyError::Inconsistent { .. } => "field",
        BodyError::ForbiddenChar { .. } => "text",
    }
}

/// The seam through which the unattended handler drives `AUTH_CHALLENGE` /
/// `AUTH_RESPONSE` inside the strictly alternating window (§B.8.4.5).
pub trait AuthExchange: Send {
    /// Send `AUTH_CHALLENGE`, wait [`timeouts::AUTH_RESPONSE`] for
    /// `AUTH_RESPONSE`, and return it with `th_after(AUTH_RESPONSE)`.
    fn challenge<'a>(
        &'a mut self,
        challenge: messages::AuthChallenge,
    ) -> BoxFuture<'a, Result<(messages::AuthResponse, [u8; 32]), HandshakeError>>;
}

impl<S> AuthExchange for Channel<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn challenge<'a>(
        &'a mut self,
        challenge: messages::AuthChallenge,
    ) -> BoxFuture<'a, Result<(messages::AuthResponse, [u8; 32]), HandshakeError>> {
        Box::pin(async move {
            self.send(&challenge, None).await?;
            let rx = self
                .recv_expect(
                    timeouts::AUTH_RESPONSE,
                    "AUTH_RESPONSE",
                    &[Kind::AuthResponse],
                )
                .await?;
            let response: messages::AuthResponse = self.body(&rx).await?;
            self.absorb(&rx);
            Ok((response, self.th()))
        })
    }
}

#[cfg(test)]
mod golden;
#[cfg(test)]
mod props;
#[cfg(test)]
mod tests;
