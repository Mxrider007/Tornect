//! The client-side handshake FSM (`docs/PLAN.md` §B.2, §B.8.4.2 client checks).
//!
//! ```text
//! dial (th_0 from the dialed address) ── HELLO (v = 1, signed) ──►
//! ◄── HELLO_ACK (sig vs the dialed onion pk; v ≤ v_max) ── 20 s
//! unknown host: PAIR_REQUEST ──► SAS shown ── ◄── PAIR_ACCEPT | PAIR_REJECT ── 90 s ── user confirms ⇒ pin
//! SESSION_REQUEST (signed) ──► ◄── SESSION_ACCEPT | SESSION_REJECT ── 110 s
//! accept: sig; session_type = 0; session_token present, token_confirm absent;
//!         quic_spki == SPKI(pinned host_device_pk) (ct, §B.6)
//! Established: PING / PONG (either direction), BYE, the M2 frames
//! ```

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;
use tornect_core::unattended::hosts::PinCheck;
use tornect_core::{DeviceIdentity, TornectId};
use zeroize::Zeroizing;

use super::{Channel, HandshakeError, OsRandom, Randomness, Received, SessionToken, timeouts};
use crate::auth;
use crate::consent::{TransportPolicy, mode_from_code};
use crate::envelope::{Kind, codes};
use crate::messages::{
    self, Candidates, Caps, Hello, HelloAck, PairAccept, PairReject, PairRequest, Ping, Pong,
    SessionAccept, SessionReject, SessionRequest, clamp_feats, ed25519_spki,
};
use crate::pairing::{BoxFuture, KnownHostStore, Sas, lock, normalize_label};
use crate::transcript::{HostSigner, verify_envelope};

/// What the client sends in `HELLO` and `SESSION_REQUEST`.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// The Tornect ID the user dialed; `th_0` and every host signature check derive from it.
    pub host: TornectId,
    /// This device's self-declared name (sent normalized and sanitized, ≤ 64
    /// characters; the host pins its own sanitized copy).
    pub name: String,
    /// The PAKE suites this build supports (`"ua1"` / `"ua2"`).
    pub feats: Vec<String>,
    /// Caps to request.
    pub caps: Caps,
    /// The emergency stop token for this host, if the user entered a stop code (§B.8.7.4).
    pub stop_token: Option<[u8; 32]>,
    /// Highest protocol version this build speaks.
    pub v_max: u8,
}

impl ClientConfig {
    /// Defaults: no feats, empty caps, no stop token, `v_max = 1`.
    #[must_use]
    pub fn new(host: TornectId, name: impl Into<String>) -> Self {
        Self {
            host,
            name: name.into(),
            feats: Vec::new(),
            caps: Caps::default(),
            stop_token: None,
            v_max: tornect_core::PROTOCOL_VERSION,
        }
    }
}

/// What to do once `HELLO_ACK` verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    /// Pair if the host is unknown (an already known host is reported as
    /// paired without a new exchange), then `BYE{USER}`.
    PairOnly,
    /// Pair if the host is unknown, then request an attended session.
    Session,
    /// Request an **unattended** session (§B.8): no popup on the host, the grant
    /// password proven with the PAKE instead. Pairing must already have happened
    /// (a grant exists only for a SAS-paired device, §B.8 hard rule 2).
    Unattended(UnattendedIntent),
}

/// What an unattended client needs beyond the attended path.
#[derive(Clone, PartialEq, Eq)]
pub struct UnattendedIntent {
    /// The grant password. Never logged, never persisted by this crate.
    pub password: Zeroizing<String>,
    /// A [`messages::mode`] value; the host clamps it toward view-only.
    pub want_mode: u8,
}

impl fmt::Debug for UnattendedIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnattendedIntent")
            .field("password", &"<redacted>")
            .field("want_mode", &self.want_mode)
            .finish()
    }
}

/// The client's TOFU pin for the host's OPAQUE static key (`hosts.toml`, §B.8.9).
///
/// A pin change means the host's unattended setup was replaced — or someone is
/// impersonating it — and MUST abort before KE3 is sent (A16).
pub trait ServerKeyPin: Send + Sync {
    /// Check `server_s_pk` against the stored pin.
    fn check(&self, host: &TornectId, server_s_pk: &[u8; 32]) -> PinCheck;
    /// Record the key after a successful `SESSION_ACCEPT` (first use).
    fn record(&self, host: &TornectId, server_s_pk: &[u8; 32]);
}

/// Headless default: trust on first use, remember nothing. Test-and-CLI-shim
/// only — a real client passes a `hosts.toml`-backed implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoServerKeyPin;

impl ServerKeyPin for NoServerKeyPin {
    fn check(&self, _: &TornectId, _: &[u8; 32]) -> PinCheck {
        PinCheck::NoPin
    }
    fn record(&self, _: &TornectId, _: &[u8; 32]) {}
}

/// The client's pairing UI: shows the SAS while the host user compares, then
/// asks this user to confirm it once the host accepted.
pub trait ClientPairingUi: Send + Sync {
    /// Display `sas` for `host` (returns as soon as it is on screen).
    fn show_sas<'a>(&'a self, host: &'a TornectId, sas: &'a str) -> BoxFuture<'a, ()>;
    /// The host accepted as `host_name`: does this user confirm the codes matched?
    fn confirm<'a>(
        &'a self,
        host: &'a TornectId,
        host_name: &'a str,
        sas: &'a str,
    ) -> BoxFuture<'a, bool>;
}

/// Never confirms: the headless default (a session with an unknown host fails
/// instead of pinning anything unseen).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPairingUi;

impl ClientPairingUi for NoPairingUi {
    fn show_sas<'a>(&'a self, _: &'a TornectId, _: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    fn confirm<'a>(&'a self, _: &'a TornectId, _: &'a str, _: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async { false })
    }
}

/// A scripted [`ClientPairingUi`] for tests: records what it showed and
/// answers `confirm` with a fixed value.
#[derive(Debug)]
pub struct ScriptedClientUi {
    answer: bool,
    /// SAS strings shown, in order.
    pub shown: Mutex<Vec<String>>,
    /// `(host_name, sas)` pairs confirmed or refused, in order.
    pub asked: Mutex<Vec<(String, String)>>,
}

impl ScriptedClientUi {
    /// Confirm (or refuse) every pairing.
    #[must_use]
    pub fn new(answer: bool) -> Self {
        Self {
            answer,
            shown: Mutex::new(Vec::new()),
            asked: Mutex::new(Vec::new()),
        }
    }

    /// The SAS strings shown so far.
    #[must_use]
    pub fn sas_shown(&self) -> Vec<String> {
        lock(&self.shown).clone()
    }
}

impl ClientPairingUi for ScriptedClientUi {
    fn show_sas<'a>(&'a self, _: &'a TornectId, sas: &'a str) -> BoxFuture<'a, ()> {
        lock(&self.shown).push(sas.to_owned());
        Box::pin(async {})
    }

    fn confirm<'a>(
        &'a self,
        _: &'a TornectId,
        host_name: &'a str,
        sas: &'a str,
    ) -> BoxFuture<'a, bool> {
        lock(&self.asked).push((host_name.to_owned(), sas.to_owned()));
        let answer = self.answer;
        Box::pin(async move { answer })
    }
}

/// Everything the client FSM is injected with.
#[derive(Clone)]
pub struct ClientDeps {
    /// Pinned hosts.
    pub known_hosts: Arc<KnownHostStore>,
    /// The pairing UI.
    pub ui: Arc<dyn ClientPairingUi>,
    /// Nonces.
    pub random: Arc<dyn Randomness>,
    /// The `hosts.toml` TOFU pin for the host's OPAQUE static key (§B.8.9).
    pub server_key_pin: Arc<dyn ServerKeyPin>,
}

impl ClientDeps {
    /// Headless defaults: [`NoPairingUi`], OS randomness.
    #[must_use]
    pub fn headless(known_hosts: Arc<KnownHostStore>) -> Self {
        Self {
            known_hosts,
            ui: Arc::new(NoPairingUi),
            random: Arc::new(OsRandom),
            server_key_pin: Arc::new(NoServerKeyPin),
        }
    }
}

/// An established attended session, ready for `PING` / `PONG` and the M2 exchange.
pub struct ClientSession<S> {
    chan: Channel<S>,
    accept: SessionAccept,
    token: SessionToken,
    host_label: String,
    random: Arc<dyn Randomness>,
    /// M2 frames that arrived while [`ClientSession::ping`] waited for its
    /// `PONG`; [`ClientSession::next_event`] hands them out first.
    pending: VecDeque<SessionEvent>,
}

impl<S> ClientSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// The verified `SESSION_ACCEPT`.
    #[must_use]
    pub fn accept(&self) -> &SessionAccept {
        &self.accept
    }

    /// The session token.
    #[must_use]
    pub fn session_token(&self) -> &SessionToken {
        &self.token
    }

    /// The host's pinned label.
    #[must_use]
    pub fn host_label(&self) -> &str {
        &self.host_label
    }

    /// The transcript hash at the end of the handshake.
    #[must_use]
    pub fn th(&self) -> [u8; 32] {
        self.chan.th()
    }

    /// The transport policy the host imposed.
    #[must_use]
    pub fn transport_policy(&self) -> TransportPolicy {
        TransportPolicy::from_code(self.accept.transport_policy()).unwrap_or_default()
    }

    /// Send `PING` and wait [`timeouts::PONG`] for the matching `PONG`;
    /// returns the round trip. The Tor circuit is a heartbeat channel in both
    /// directions (§B.2), so a `PING` from the host that arrives meanwhile is
    /// answered in place, M2 frames are queued for [`ClientSession::next_event`],
    /// and only a `PONG` with the wrong nonce or an out-of-place kind is
    /// `E_BAD_STATE`.
    pub async fn ping(&mut self) -> Result<Duration, HandshakeError> {
        let mut nonce = [0u8; 8];
        self.random.fill(&mut nonce)?;
        let nonce = u64::from_be_bytes(nonce);
        let start = Instant::now();
        self.chan.send(&Ping { nonce }, None).await?;
        let deadline = start.checked_add(timeouts::PONG);
        loop {
            let wait = deadline.map_or(Duration::MAX, |d| {
                d.saturating_duration_since(Instant::now())
            });
            let Some(rx) = self.chan.recv(wait, "PONG").await? else {
                return Err(HandshakeError::Closed);
            };
            if rx.env.kind == Kind::Pong {
                let pong: Pong = self.chan.body(&rx).await?;
                if pong.nonce != nonce {
                    return Err(self.chan.fail(codes::E_BAD_STATE, "pong nonce").await);
                }
                return Ok(start.elapsed());
            }
            match self.classify(&rx).await? {
                None => {}
                Some(SessionEvent::Bye { reason, detail }) => {
                    return Err(HandshakeError::PeerBye { reason, detail });
                }
                Some(SessionEvent::Error { code, detail }) => {
                    return Err(HandshakeError::PeerError { code, detail });
                }
                Some(event) => self.pending.push_back(event),
            }
        }
    }

    /// Send a `CANDIDATES` frame (M2 placeholder).
    pub async fn send_candidates(&mut self, candidates: &Candidates) -> Result<(), HandshakeError> {
        self.chan.send(candidates, None).await.map(|_| ())
    }

    /// Send `TOR_FALLBACK{}`: what stops the host's 15 s orphan timer
    /// (§B.8.4.5, `HostConfig::orphan_timeout`) when the Tor circuit is the
    /// only transport — the M1 `tornect ping` flow sends it right after the
    /// accept; M2 replaces it with `CANDIDATES` and the real fallback decision.
    pub async fn send_tor_fallback(&mut self) -> Result<(), HandshakeError> {
        self.chan
            .send(&messages::TorFallback {}, None)
            .await
            .map(|_| ())
    }

    /// Wait up to `timeout` for the next frame from the host (a `BYE`, an
    /// `ERROR`, or one of the M2 frames), after anything queued by
    /// [`ClientSession::ping`]; a `PING` from the host is answered in place
    /// and not reported. `Ok(None)` when the host closed the stream.
    pub async fn next_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<SessionEvent>, HandshakeError> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(Some(event));
            }
            let Some(rx) = self.chan.recv(timeout, "session frame").await? else {
                return Ok(None);
            };
            if let Some(event) = self.classify(&rx).await? {
                return Ok(Some(event));
            }
        }
    }

    /// One post-accept frame: a `PING` is answered in place (`Ok(None)`),
    /// `BYE` / `ERROR` close the channel, the M2 frames become events, and
    /// anything else — an unsolicited `PONG` included — is `E_BAD_STATE`.
    async fn classify(&mut self, rx: &Received) -> Result<Option<SessionEvent>, HandshakeError> {
        let event = match rx.env.kind {
            Kind::Bye => {
                let b: messages::Bye = self.chan.body(rx).await?;
                self.chan.close().await;
                SessionEvent::Bye {
                    reason: b.reason,
                    detail: b.detail,
                }
            }
            Kind::Error => {
                let e: messages::Error = self.chan.body(rx).await?;
                self.chan.close().await;
                SessionEvent::Error {
                    code: e.code,
                    detail: e.detail,
                }
            }
            Kind::Ping => {
                let p: Ping = self.chan.body(rx).await?;
                self.chan.send(&Pong { nonce: p.nonce }, None).await?;
                return Ok(None);
            }
            Kind::Candidates => SessionEvent::Candidates(self.chan.body(rx).await?),
            Kind::CandidatesDone => {
                let _: messages::CandidatesDone = self.chan.body(rx).await?;
                SessionEvent::CandidatesDone
            }
            Kind::TorFallback => {
                let _: messages::TorFallback = self.chan.body(rx).await?;
                SessionEvent::TorFallback
            }
            _ => return Err(self.chan.fail(codes::E_BAD_STATE, "kind").await),
        };
        Ok(Some(event))
    }

    /// Send `BYE{reason}`, wait for the host to close, and close, all within
    /// [`timeouts::BYE`]: a host that stops reading must not keep the client
    /// from leaving (SLICE-B2 B2-8).
    ///
    /// The host closes only once it has read the `BYE`, and that close is the
    /// only sign the `BYE` arrived. Over Tor a flushed `BYE` was lost when the
    /// client shut its node down straight after, and the host logged the
    /// session's end as an I/O error (live run, 2026-09-22).
    pub async fn bye(mut self, reason: u16) -> Result<(), HandshakeError> {
        let deadline = Instant::now() + timeouts::BYE;
        let left = move || deadline.saturating_duration_since(Instant::now());
        tokio::time::timeout(timeouts::BYE, async {
            let bye = messages::Bye {
                reason,
                detail: None,
            };
            self.chan.send(&bye, None).await?;
            // Anything the host still sends is moot; its close, an error or
            // the deadline ends the wait.
            while let Ok(Some(_)) = self.chan.recv(left(), "the host's close").await {}
            self.chan.close().await;
            Ok(())
        })
        .await
        .unwrap_or(Err(HandshakeError::Timeout("BYE")))
    }

    /// Take the stream back for the session layer.
    pub fn into_stream(self) -> S {
        self.chan.into_stream()
    }
}

/// A frame from the host after the accept ([`ClientSession::next_event`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEvent {
    /// The host ended the session.
    Bye {
        /// A [`messages::bye`] code.
        reason: u16,
        /// Untrusted free text (no control characters, bounded — but still
        /// the peer's words).
        detail: Option<String>,
    },
    /// The host reported a protocol error and closed.
    Error {
        /// An [`codes`] value.
        code: u16,
        /// Untrusted free text.
        detail: Option<String>,
    },
    /// M2: the host's candidates.
    Candidates(Candidates),
    /// M2: the host finished gathering.
    CandidatesDone,
    /// M2: the host asks for the Tor fallback.
    TorFallback,
}

/// How [`connect`] ended.
pub enum ClientOutcome<S> {
    /// [`Intent::PairOnly`]: paired and said goodbye.
    Paired {
        /// The host's name (normalized), now pinned.
        host_name: String,
    },
    /// An attended session was accepted (boxed: the session carries the channel and the accept).
    Session(Box<ClientSession<S>>),
}

impl<S> core::fmt::Debug for ClientOutcome<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Paired { host_name } => f
                .debug_struct("Paired")
                .field("host_name", host_name)
                .finish(),
            Self::Session(s) => f
                .debug_struct("Session")
                .field("host_label", &s.host_label)
                .field("session", &s.token.session_id())
                .finish_non_exhaustive(),
        }
    }
}

/// Run the client side over `stream` (already connected to `cfg.host`).
pub async fn connect<S>(
    stream: S,
    cfg: &ClientConfig,
    identity: &DeviceIdentity,
    deps: &ClientDeps,
    intent: Intent,
) -> Result<ClientOutcome<S>, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let host_pk_bytes = *cfg.host.public_key_bytes();
    let host_pk = VerifyingKey::from_bytes(&host_pk_bytes)
        .map_err(|_| HandshakeError::Aborted("the dialed Tornect ID is not a valid key"))?;
    let known = deps.known_hosts.get(&cfg.host);
    let mut chan = Channel::new(stream, &host_pk_bytes);

    // HELLO.
    let mut client_nonce = [0u8; 32];
    deps.random.fill(&mut client_nonce)?;
    // The SAS nonce is committed to in HELLO and revealed in PAIR_REQUEST (§B.3),
    // so a proxying MITM must fix its own host_nonce before it can learn the value
    // the code depends on.
    let mut sas_nonce = [0u8; 32];
    deps.random.fill(&mut sas_nonce)?;
    let hello = Hello {
        v_max: cfg.v_max.max(tornect_core::PROTOCOL_VERSION),
        client_nonce,
        sas_commit: crate::pairing::sas_commit(&sas_nonce),
        device_pk: HostSigner::public_key(identity),
        name: normalize_label(&cfg.name),
        feats: clamp_feats(&cfg.feats),
        stop_token: cfg.stop_token,
        pairing_state: u8::from(known.is_some()),
    };
    chan.send(&hello, Some(identity)).await?;

    // HELLO_ACK: signed with the onion identity key of the *dialed* address.
    let rx = chan
        .recv_expect(timeouts::HELLO_ACK, "HELLO_ACK", &[Kind::HelloAck])
        .await?;
    let ack: HelloAck = chan.body(&rx).await?;
    if verify_envelope(&host_pk, &chan.th(), &rx.env).is_err() {
        return Err(chan.fail(codes::E_BAD_SIG, "signature").await);
    }
    if ack.v != rx.env.v
        || ack.v < 1
        || ack.v > cfg.v_max
        || ack.v != tornect_core::PROTOCOL_VERSION
    {
        return Err(chan.fail(codes::E_VERSION, "version").await);
    }
    chan.absorb(&rx);
    chan.set_version(ack.v);
    // th_after(HELLO_ACK): the SAS input, taken before PAIR_REQUEST is absorbed.
    let th_hello_ack = chan.th();

    // PAIR path. A host that already trusts this device expects
    // `SESSION_REQUEST` next (§B.2, §B.8.4.5), so pairing is attempted only
    // for a host this side does not know; forget the host first to re-pair
    // (the host accepts that, decision M1-32).
    let mut paired_now = false;
    let (host_label, host_device_pk) = match known {
        None => {
            let (name, host_device_pk) =
                pair(&mut chan, cfg, deps, &th_hello_ack, &sas_nonce).await?;
            paired_now = true;
            if intent == Intent::PairOnly {
                chan.bye(messages::bye::USER).await?;
                return Ok(ClientOutcome::Paired { host_name: name });
            }
            (name, host_device_pk)
        }
        Some(k) if intent == Intent::PairOnly => {
            chan.bye(messages::bye::USER).await?;
            return Ok(ClientOutcome::Paired { host_name: k.label });
        }
        Some(k) => (k.label, k.host_device_pk),
    };

    // §B.8: the unattended branch has its own request, its own AUTH exchange and
    // its own accept checks; everything before this point (HELLO, HELLO_ACK,
    // pairing) is shared.
    if let Intent::Unattended(ua) = &intent {
        return unattended_session(
            chan,
            cfg,
            identity,
            deps,
            ua,
            host_pk,
            host_label,
            host_device_pk,
        )
        .await;
    }

    // SESSION_REQUEST (attended).
    let request = SessionRequest {
        caps: cfg.caps.clone(),
        unattended: None,
    };
    chan.send(&request, Some(identity)).await?;
    let rx = match chan
        .recv_expect(
            timeouts::SESSION_ACCEPT,
            "SESSION_ACCEPT",
            &[Kind::SessionAccept, Kind::SessionReject],
        )
        .await
    {
        // A host that expected PAIR_REQUEST here no longer pins this device.
        Err(HandshakeError::PeerError {
            code: codes::E_BAD_STATE,
            ..
        }) if !paired_now => return Err(HandshakeError::PairingLost),
        other => other?,
    };
    if rx.env.kind == Kind::SessionReject {
        let reject: SessionReject = chan.body(&rx).await?;
        chan.absorb(&rx);
        chan.close().await;
        return Err(HandshakeError::SessionRejected {
            reject: Box::new(reject),
        });
    }
    let accept: SessionAccept = chan.body(&rx).await?;
    if verify_envelope(&host_pk, &chan.th(), &rx.env).is_err() {
        return Err(chan.fail(codes::E_BAD_SIG, "signature").await);
    }
    chan.absorb(&rx);
    // §B.8.4.6: a client that did not send `unattended` MUST abort on session_type = 1.
    if accept.session_type() != messages::session_type::ATTENDED {
        return Err(chan.fail(codes::E_BAD_STATE, "session_type").await);
    }
    let token = match (accept.session_token(), accept.token_confirm()) {
        (Some(t), None) => SessionToken::new(*t),
        _ => return Err(chan.fail(codes::E_BAD_LEN, "session_token").await),
    };
    // §B.6, §B.8.4.1: the SPKI must be that of the host device key pinned at
    // pairing, compared in constant time (decision M1-31).
    let expected_spki = ed25519_spki(&host_device_pk);
    if !bool::from(accept.quic_spki()[..].ct_eq(&expected_spki[..])) {
        return Err(chan.fail(codes::E_BAD_SIG, "quic_spki").await);
    }
    if mode_from_code(accept.mode()).is_none()
        || TransportPolicy::from_code(accept.transport_policy()).is_none()
    {
        return Err(chan.fail(codes::E_BAD_LEN, "mode").await);
    }
    deps.known_hosts.touch(&cfg.host);
    tracing::info!(host = %cfg.host, session = %token.session_id(), "session accepted");
    Ok(ClientOutcome::Session(Box::new(ClientSession {
        chan,
        accept,
        token,
        host_label,
        random: Arc::clone(&deps.random),
        pending: VecDeque::new(),
    })))
}

/// `PAIR_REQUEST` → SAS shown → `PAIR_ACCEPT` → user confirms ⇒ pin; returns
/// the host's name and the pinned `host_device_pk`.
async fn pair<S>(
    chan: &mut Channel<S>,
    cfg: &ClientConfig,
    deps: &ClientDeps,
    th_hello_ack: &[u8; 32],
    sas_nonce: &[u8; 32],
) -> Result<(String, [u8; 32]), HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    chan.send(
        &PairRequest {
            sas_nonce: *sas_nonce,
            ..PairRequest::default()
        },
        None,
    )
    .await?;
    let sas = Sas::derive(th_hello_ack, sas_nonce).render();
    deps.ui.show_sas(&cfg.host, &sas).await;
    let rx = chan
        .recv_expect(
            timeouts::PAIR_ACCEPT,
            "PAIR_ACCEPT",
            &[Kind::PairAccept, Kind::PairReject],
        )
        .await?;
    if rx.env.kind == Kind::PairReject {
        let reject: PairReject = chan.body(&rx).await?;
        chan.absorb(&rx);
        chan.close().await;
        return Err(HandshakeError::PairRejected {
            reason: reject.reason,
            detail: reject.detail,
        });
    }
    let accept: PairAccept = chan.body(&rx).await?;
    chan.absorb(&rx);
    // The pinned key must be an Ed25519 point: it is the host's QUIC identity
    // (§B.6) and its identity when it acts as a client.
    if VerifyingKey::from_bytes(&accept.host_device_pk).is_err() {
        return Err(chan.fail(codes::E_BAD_LEN, "host_device_pk").await);
    }
    let host_name = normalize_label(&accept.host_name);
    if !deps.ui.confirm(&cfg.host, &host_name, &sas).await {
        chan.bye(messages::bye::USER).await?;
        return Err(HandshakeError::Aborted("pairing not confirmed"));
    }
    deps.known_hosts
        .pin(cfg.host, &host_name, accept.host_device_pk)?;
    tracing::info!(host = %cfg.host, %host_name, "host paired");
    Ok((host_name, accept.host_device_pk))
}

/// The `SESSION_REQUEST{unattended}` … `SESSION_ACCEPT` exchange of §B.8.4.2.
///
/// Runs after `HELLO` / `HELLO_ACK` (and pairing, if the host was unknown), so
/// `chan` is already at `th_after(HELLO_ACK)` or later and the host key is
/// verified. Strict alternation applies throughout (§B.8.4.5): the only frames
/// this side may see are `AUTH_CHALLENGE`, then `SESSION_ACCEPT` / `SESSION_REJECT`.
#[allow(clippy::too_many_arguments)]
async fn unattended_session<S>(
    mut chan: Channel<S>,
    cfg: &ClientConfig,
    identity: &DeviceIdentity,
    deps: &ClientDeps,
    ua: &UnattendedIntent,
    host_pk: VerifyingKey,
    host_label: String,
    host_device_pk: [u8; 32],
) -> Result<ClientOutcome<S>, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let host_onion_pk = cfg.host.public_key_bytes();
    let device_pk = HostSigner::public_key(identity);

    // A fresh ClientLogin per stream: the OPRF blind must never be reused.
    let (login, ke1) = auth::ClientLogin::start(&ua.password)
        .map_err(|_| HandshakeError::Aborted("PAKE start failed"))?;

    let request = SessionRequest {
        caps: cfg.caps.clone(),
        unattended: Some(messages::UnattendedRequest {
            suite: auth::SUITE_OPAQUE,
            ke1: Some(ke1),
            want_mode: ua.want_mode,
            intent: messages::intent::SESSION,
            admin: None,
        }),
    };
    chan.send(&request, Some(identity)).await?;
    // `context` is bound to the *signed* SESSION_REQUEST (§B.8.4.3).
    let th_after_request = chan.th();

    // AUTH_CHALLENGE (30 s). A pre-PAKE refusal arrives as SESSION_REJECT here.
    let rx = chan
        .recv_expect(
            timeouts::AUTH_CHALLENGE,
            "AUTH_CHALLENGE",
            &[Kind::AuthChallenge, Kind::SessionReject],
        )
        .await?;
    if rx.env.kind == Kind::SessionReject {
        let reject: SessionReject = chan.body(&rx).await?;
        chan.absorb(&rx);
        chan.close().await;
        return Err(HandshakeError::SessionRejected {
            reject: Box::new(reject),
        });
    }
    let challenge: messages::AuthChallenge = chan.body(&rx).await?;
    chan.absorb(&rx);
    if challenge.suite != auth::SUITE_OPAQUE {
        return Err(chan.fail(codes::E_BAD_LEN, "suite").await);
    }
    let Some(ke2) = challenge.ke2 else {
        return Err(chan.fail(codes::E_BAD_LEN, "ke2").await);
    };

    let ctx = auth::context(
        &th_after_request,
        auth::SUITE_OPAQUE,
        messages::intent::SESSION,
    );
    let ids = auth::identifiers(&device_pk, host_onion_pk);
    let out = match login.finish(&ua.password, &ke2, &ctx, ids) {
        Ok(out) => out,
        Err(_) => {
            // §B.8.4.2: the server MAC failed — either the password is wrong or
            // this is not the host we think it is. Say so and hang up rather
            // than dropping the stream: the host is waiting out its 30 s
            // `AwaitKe3` timer otherwise, holding a charged in-flight slot.
            chan.bye(messages::bye::CLIENT_AUTH_ABORT).await?;
            return Err(HandshakeError::Aborted("unattended authentication failed"));
        }
    };

    // §B.8.9 / A16: a changed `server_s_pk` means the host's unattended setup was
    // replaced — abort *before* KE3, so a wrong host never sees the proof.
    match deps.server_key_pin.check(&cfg.host, &out.server_s_pk) {
        PinCheck::Mismatch => {
            chan.close().await;
            return Err(HandshakeError::Aborted(
                "the host's unattended setup changed: pin mismatch",
            ));
        }
        PinCheck::Match | PinCheck::NoPin => {}
    }

    chan.send(
        &messages::AuthResponse {
            ke3: Some(out.ke3),
            pa: None,
            ca: None,
        },
        None,
    )
    .await?;
    let th_after_response = chan.th();

    // SESSION_ACCEPT within the fixed 110 s budget (§B.8.4.5): grant policy is
    // not disclosed before it, so the wait is deliberately uninformative.
    let rx = chan
        .recv_expect(
            timeouts::SESSION_ACCEPT,
            "SESSION_ACCEPT",
            &[Kind::SessionAccept, Kind::SessionReject],
        )
        .await?;
    if rx.env.kind == Kind::SessionReject {
        let reject: SessionReject = chan.body(&rx).await?;
        chan.absorb(&rx);
        chan.close().await;
        return Err(HandshakeError::SessionRejected {
            reject: Box::new(reject),
        });
    }
    let accept: SessionAccept = chan.body(&rx).await?;
    if verify_envelope(&host_pk, &chan.th(), &rx.env).is_err() {
        return Err(chan.fail(codes::E_BAD_SIG, "signature").await);
    }
    chan.absorb(&rx);

    if accept.session_type() != messages::session_type::UNATTENDED {
        return Err(chan.fail(codes::E_BAD_STATE, "session_type").await);
    }
    // The mirror of the attended rule: the token is *derived*, never sent, and
    // the host proves it holds the same one with `token_confirm` (§B.8.4.3).
    let (None, Some(confirm)) = (accept.session_token(), accept.token_confirm()) else {
        return Err(chan.fail(codes::E_BAD_LEN, "token_confirm").await);
    };
    let ck = auth::confirm_key(&out.session_key, &th_after_response);
    let expected = auth::token_confirm(&ck, &th_after_response);
    if !bool::from(expected.ct_eq(confirm)) {
        return Err(chan.fail(codes::E_BAD_SIG, "token_confirm").await);
    }
    let token = SessionToken::new(*auth::session_token(&out.session_key, &th_after_response));

    let expected_spki = ed25519_spki(&host_device_pk);
    if !bool::from(accept.quic_spki()[..].ct_eq(&expected_spki[..])) {
        return Err(chan.fail(codes::E_BAD_SIG, "quic_spki").await);
    }
    if mode_from_code(accept.mode()).is_none()
        || TransportPolicy::from_code(accept.transport_policy()).is_none()
    {
        return Err(chan.fail(codes::E_BAD_LEN, "mode").await);
    }

    // Only now, with the host's proof verified, is the key worth remembering.
    deps.server_key_pin.record(&cfg.host, &out.server_s_pk);
    deps.known_hosts.touch(&cfg.host);
    tracing::info!(host = %cfg.host, session = %token.session_id(), "unattended session accepted");
    Ok(ClientOutcome::Session(Box::new(ClientSession {
        chan,
        accept,
        token,
        host_label,
        random: Arc::clone(&deps.random),
        pending: VecDeque::new(),
    })))
}
