//! Consent evidence and the only constructor of `SESSION_ACCEPT`
//! (`docs/PLAN.md` §B.8.14 Rust block, §B.8.16).
//!
//! A [`SessionAccept`] can only be built from a [`ConsentProof`]:
//!
//! * [`ConsentProof::HumanClick`] — the attended path: a popup choice and a
//!   [`FreshToken`] that only this crate can mint (the FSM mints it right
//!   after `Consent::session` returns Allow).
//! * [`ConsentProof::Unattended`] — the §B.8 path: a [`PolicyReceipt`] minted
//!   only by the `AwaitKe3` handler after `ServerLogin::finish`, the block
//!   window's [`WindowPassed`] evidence and the PAKE-derived [`DerivedToken`].
//!   Their constructors are `pub(crate)`; the unattended track fills the one
//!   call site each.
//!
//! [`SessionAccept::build`] returns the accept *and* the [`SessionToken`] the
//! session layer keys the M2 `BIND` exchange by — the only way to obtain it,
//! so the unattended `session_token` (never sent, §B.8.4.3) can neither be
//! confused with the public `token_confirm` nor be forgotten.
//!
//! The seams `tornect-session` implements at M4 — [`BlockWindow`] and
//! [`LocalAllow`] — live here with their headless M1 defaults
//! ([`TimerOnlyWindow`], [`AlwaysDeny`]).

use std::time::Duration;

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::time::Instant;
use tornect_core::session_log::SessionMode;
use tornect_core::unattended::ReadinessSnapshot;
use zeroize::Zeroizing;

use crate::messages::{self, Caps, FailSummary, Resolution, SPKI_LEN, SessionAccept};
use crate::pairing::BoxFuture;

/// `UnattendedGrant.id`: random at creation, hex in logs.
pub type GrantId = [u8; 8];

/// Domain separator of the session id derived from a [`SessionToken`].
pub const SESSION_ID_LABEL: &[u8] = b"tornect/v1/session-id\0";

/// The block window shown before an unattended session starts (§B.8.4.5
/// `Accepting`). M4 supplies the UI-backed implementation.
pub trait BlockWindow: Send + Sync {
    /// Run the window for `secs` seconds on behalf of grant `who` / `label`.
    fn run<'a>(&'a self, secs: u8, who: &'a GrantId, label: &'a str)
    -> BoxFuture<'a, BlockOutcome>;
}

/// The `ask_before_start` popup (§B.8.4.5 `AwaitLocalAllow`). M4 supplies
/// the UI-backed implementation.
pub trait LocalAllow: Send + Sync {
    /// Ask the local user; `false` on Deny or when `timeout` elapses.
    fn ask<'a>(
        &'a self,
        who: &'a GrantId,
        label: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, bool>;
}

/// Headless M1 default: a timer, nobody can click Block.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerOnlyWindow;

impl BlockWindow for TimerOnlyWindow {
    fn run<'a>(&'a self, secs: u8, _: &'a GrantId, _: &'a str) -> BoxFuture<'a, BlockOutcome> {
        Box::pin(async move {
            if secs == 0 {
                BlockOutcome::Passed(WindowPassed::Skipped)
            } else {
                tokio::time::sleep(Duration::from_secs(u64::from(secs))).await;
                BlockOutcome::Passed(WindowPassed::Elapsed)
            }
        })
    }
}

/// Headless M1 default: `ask_before_start` ⇒ Deny.
#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysDeny;

impl LocalAllow for AlwaysDeny {
    fn ask<'a>(&'a self, _: &'a GrantId, _: &'a str, _: Duration) -> BoxFuture<'a, bool> {
        Box::pin(async { false })
    }
}

/// What a [`BlockWindow`] returns; `Blocked` never reaches
/// [`SessionAccept::build`] (it ends in `SESSION_REJECT{BLOCKED_BY_LOCAL_USER}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockOutcome {
    /// Nobody clicked Block.
    Passed(WindowPassed),
    /// Block was clicked.
    Blocked,
}

/// The only block evidence a [`ConsentProof`] can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowPassed {
    /// The window ran to its end.
    Elapsed,
    /// `block_window_s = 0`: no window.
    Skipped,
}

/// Transport policy of a session (`SESSION_ACCEPT.transport_policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportPolicy {
    /// Any path (direct, LAN, Tor fallback).
    #[default]
    Any,
    /// Tor only — the host's Paranoid mode.
    TorOnly,
    /// LAN only — the host's LAN-only toggle.
    LanOnly,
}

impl TransportPolicy {
    /// From the host privacy settings (§B.8.4.1: Paranoid ⇒ `tor_only`,
    /// LAN-only ⇒ `lan_only`, else `any`; the two are mutually exclusive in
    /// `Config::validate`, Paranoid wins if both are set).
    #[must_use]
    pub fn from_privacy(paranoid: bool, lan_only: bool) -> Self {
        if paranoid {
            Self::TorOnly
        } else if lan_only {
            Self::LanOnly
        } else {
            Self::Any
        }
    }

    /// The wire value.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Any => messages::transport::ANY,
            Self::TorOnly => messages::transport::TOR_ONLY,
            Self::LanOnly => messages::transport::LAN_ONLY,
        }
    }

    /// From the wire value.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            messages::transport::ANY => Some(Self::Any),
            messages::transport::TOR_ONLY => Some(Self::TorOnly),
            messages::transport::LAN_ONLY => Some(Self::LanOnly),
            _ => None,
        }
    }
}

/// The policy an unattended grant imposes on one session, minted only by
/// the `AwaitKe3` handler after `ServerLogin::finish` (§B.8.14), carrying
/// the readiness snapshot the `HOST_NOT_READY` gate was evaluated on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReceipt {
    grant: GrantId,
    mode: SessionMode,
    transport: TransportPolicy,
    ends_at: Option<u64>,
    block_window_s: u8,
    ask_before_start: bool,
    // Boxed: twelve probes with messages would otherwise dwarf every other
    // `ConsentProof` / `UnattendedVerdict` variant.
    readiness: Box<ReadinessSnapshot>,
    minted_at: Instant,
    fail_summary: Option<FailSummary>,
}

impl PolicyReceipt {
    /// The single call site is the `AwaitKe3` handler (unattended track).
    #[allow(dead_code)] // consumed by the unattended track
    #[allow(clippy::too_many_arguments)] // one argument per §B.8.14 receipt field
    pub(crate) fn mint(
        grant: GrantId,
        mode: SessionMode,
        transport: TransportPolicy,
        ends_at: Option<u64>,
        block_window_s: u8,
        ask_before_start: bool,
        readiness: ReadinessSnapshot,
        fail_summary: Option<FailSummary>,
    ) -> Self {
        Self {
            grant,
            mode,
            transport,
            ends_at,
            block_window_s,
            ask_before_start,
            readiness: Box::new(readiness),
            minted_at: Instant::now(),
            fail_summary,
        }
    }

    /// The grant.
    #[must_use]
    pub fn grant(&self) -> &GrantId {
        &self.grant
    }

    /// `most_restrictive(grant.mode, want_mode)`.
    #[must_use]
    pub fn mode(&self) -> SessionMode {
        self.mode
    }

    /// The grant's transport policy.
    #[must_use]
    pub fn transport(&self) -> TransportPolicy {
        self.transport
    }

    /// When the session must end.
    #[must_use]
    pub fn ends_at(&self) -> Option<u64> {
        self.ends_at
    }

    /// The block window length.
    #[must_use]
    pub fn block_window_s(&self) -> u8 {
        self.block_window_s
    }

    /// Whether a local Allow is asked first.
    #[must_use]
    pub fn ask_before_start(&self) -> bool {
        self.ask_before_start
    }

    /// The readiness snapshot the post-F2 gate evaluated (§B.8.14).
    #[must_use]
    pub fn readiness(&self) -> &ReadinessSnapshot {
        &self.readiness
    }

    /// When the receipt was minted.
    #[must_use]
    pub fn minted_at(&self) -> Instant {
        self.minted_at
    }

    /// The limiter snapshot.
    #[must_use]
    pub fn fail_summary(&self) -> Option<FailSummary> {
        self.fail_summary
    }
}

/// The unattended tokens: HKDF of the PAKE `session_key` (§B.8.4.3).
/// Compared in constant time, zeroized on drop, redacted in `Debug`.
#[derive(Clone)]
pub struct DerivedToken {
    session_token: [u8; 32],
    token_confirm: [u8; 32],
}

impl PartialEq for DerivedToken {
    fn eq(&self, other: &Self) -> bool {
        bool::from(
            self.session_token[..].ct_eq(&other.session_token[..])
                & self.token_confirm[..].ct_eq(&other.token_confirm[..]),
        )
    }
}

impl Eq for DerivedToken {}

impl DerivedToken {
    /// The single call site is the `AwaitKe3` handler (unattended track).
    #[allow(dead_code)] // consumed by the unattended track
    pub(crate) fn new(session_token: [u8; 32], token_confirm: [u8; 32]) -> Self {
        Self {
            session_token,
            token_confirm,
        }
    }

    /// The token the QUIC `BIND` exchange is keyed by (never sent).
    #[must_use]
    pub fn session_token(&self) -> &[u8; 32] {
        &self.session_token
    }

    /// The confirmation sent in `SESSION_ACCEPT.token_confirm`.
    #[must_use]
    pub fn token_confirm(&self) -> &[u8; 32] {
        &self.token_confirm
    }
}

impl core::fmt::Debug for DerivedToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DerivedToken(..)")
    }
}

impl Drop for DerivedToken {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.session_token.zeroize();
        self.token_confirm.zeroize();
    }
}

/// The attended `session_token`: fresh from the OS RNG, minted only by the
/// host FSM once the popup answered Allow. Compared in constant time.
#[derive(Clone)]
pub struct FreshToken([u8; 32]);

impl PartialEq for FreshToken {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0[..].ct_eq(&other.0[..]))
    }
}

impl Eq for FreshToken {}

impl FreshToken {
    pub(crate) fn mint(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The token bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for FreshToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FreshToken(..)")
    }
}

impl Drop for FreshToken {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.0.zeroize();
    }
}

/// The `session_token` of an established session (attended: the fresh random
/// token; unattended: the PAKE-derived one, §B.8.4.3): the key of the M2
/// `BIND` exchange. Zeroized on drop, redacted in `Debug`, compared in
/// constant time. Only [`SessionAccept::build`] and the client's verified
/// `SESSION_ACCEPT` produce one.
#[derive(Clone)]
pub struct SessionToken(Zeroizing<[u8; 32]>);

impl PartialEq for SessionToken {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0[..].ct_eq(&other.0[..]))
    }
}

impl Eq for SessionToken {}

impl SessionToken {
    /// Wrap a token.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The bytes (they key the M2 `BIND` exchange; never log them).
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The session id for logs and the UI, identical on both sides:
    /// `hex(SHA-256("tornect/v1/session-id\0" || token)[..8])`. A one-way
    /// derivation, so no token bits ever reach `sessions.log` (§B.8.13
    /// "never logged: … tokens").
    #[must_use]
    pub fn session_id(&self) -> String {
        let digest = Sha256::new()
            .chain_update(SESSION_ID_LABEL)
            .chain_update(*self.0)
            .finalize();
        hex::encode(&digest[..8])
    }
}

impl core::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SessionToken({})", self.session_id())
    }
}

/// What the host user clicked on the session popup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopupChoice {
    /// Allow once, full control.
    AllowOnce,
    /// Allow once, view-only.
    AllowOnceViewOnly,
}

impl PopupChoice {
    /// The session mode the choice grants.
    #[must_use]
    pub fn mode(self) -> SessionMode {
        match self {
            Self::AllowOnce => SessionMode::Control,
            Self::AllowOnceViewOnly => SessionMode::ViewOnly,
        }
    }
}

/// Evidence that a session may start (§B.8.14).
#[derive(Debug)]
pub enum ConsentProof {
    /// An attended session: a human clicked Allow.
    HumanClick {
        /// The choice.
        choice: PopupChoice,
        /// When it was clicked.
        at: Instant,
        /// The fresh random `session_token`.
        token: FreshToken,
    },
    /// An unattended session (§B.8).
    Unattended {
        /// The grant.
        grant: GrantId,
        /// `proof_fp` (§B.8.4.3), for the log.
        proof_fp: [u8; 8],
        /// The policy minted after `ServerLogin::finish`.
        policy: PolicyReceipt,
        /// The block window evidence.
        block: WindowPassed,
        /// The PAKE-derived tokens.
        token: DerivedToken,
    },
}

/// The caps negotiated for a session (§B.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChosenCaps(Caps);

impl ChosenCaps {
    /// Intersect what the host offers with what the client asked for:
    /// codecs in the client's preference order that the host also lists,
    /// the smaller resolution, HDR only if both, the fewer monitors.
    #[must_use]
    pub fn negotiate(host: &Caps, client: &Caps) -> Self {
        let codecs = client
            .codecs
            .iter()
            .filter(|c| host.codecs.iter().any(|h| h == *c))
            .take(messages::MAX_CODECS)
            .cloned()
            .collect();
        Self(Caps {
            codecs,
            max_res: Resolution {
                width: host.max_res.width.min(client.max_res.width),
                height: host.max_res.height.min(client.max_res.height),
            },
            hdr: host.hdr && client.hdr,
            monitors: host.monitors.min(client.monitors),
        })
    }

    /// The negotiated caps.
    #[must_use]
    pub fn caps(&self) -> &Caps {
        &self.0
    }
}

/// Host facts every accept carries: the SPKI of the host *device* key — the
/// key the client pinned at pairing (`PAIR_ACCEPT.host_device_pk`) and the
/// host's QUIC identity (§B.6, decision M1-31) — and, for attended sessions,
/// the privacy-mode transport policy (unattended sessions take the policy
/// from their [`PolicyReceipt`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptHostInfo {
    /// `ed25519_spki(host_device_pk)`.
    pub quic_spki: [u8; SPKI_LEN],
    /// The host privacy mode as a transport policy.
    pub transport_policy: TransportPolicy,
}

impl SessionAccept {
    /// The only constructor (§B.8.14, §B.8.16). Infallible: a Blocked window
    /// or a token of the wrong kind is unrepresentable in [`ConsentProof`].
    /// Returns the accept together with the [`SessionToken`] of the session
    /// (attended: the fresh token that also travels in the accept;
    /// unattended: the derived token that never travels — the accept carries
    /// only its `token_confirm`).
    ///
    /// Attended (§B.8.4.1): `session_type = 0`, `block_window_s = 0`,
    /// `ask_before_start = false`, `transport_policy` = the host privacy
    /// mode, `ends_at = None`, `fail_summary = None`, `session_token` set,
    /// `token_confirm` absent. Unattended: the receipt's policy,
    /// `token_confirm` set, `session_token` absent.
    #[must_use]
    pub fn build(
        proof: ConsentProof,
        caps: ChosenCaps,
        host: &AcceptHostInfo,
    ) -> (Self, SessionToken) {
        match proof {
            ConsentProof::HumanClick { choice, token, .. } => (
                SessionAccept {
                    caps: caps.0.clone(),
                    quic_spki: host.quic_spki,
                    session_type: messages::session_type::ATTENDED,
                    mode: mode_code(choice.mode()),
                    transport_policy: host.transport_policy.code(),
                    session_token: Some(*token.bytes()),
                    token_confirm: None,
                    block_window_s: 0,
                    ask_before_start: false,
                    ends_at: None,
                    fail_summary: None,
                },
                SessionToken::new(*token.bytes()),
            ),
            ConsentProof::Unattended { policy, token, .. } => (
                SessionAccept {
                    caps: caps.0.clone(),
                    quic_spki: host.quic_spki,
                    session_type: messages::session_type::UNATTENDED,
                    mode: mode_code(policy.mode()),
                    transport_policy: policy.transport().code(),
                    session_token: None,
                    token_confirm: Some(*token.token_confirm()),
                    block_window_s: policy.block_window_s(),
                    ask_before_start: policy.ask_before_start(),
                    ends_at: policy.ends_at(),
                    fail_summary: policy.fail_summary(),
                },
                SessionToken::new(*token.session_token()),
            ),
        }
    }
}

/// Wire value of a session mode.
#[must_use]
pub fn mode_code(mode: SessionMode) -> u8 {
    match mode {
        SessionMode::Control => messages::mode::CONTROL,
        SessionMode::ViewOnly => messages::mode::VIEW_ONLY,
    }
}

/// Session mode from a wire value.
#[must_use]
pub fn mode_from_code(code: u8) -> Option<SessionMode> {
    match code {
        messages::mode::CONTROL => Some(SessionMode::Control),
        messages::mode::VIEW_ONLY => Some(SessionMode::ViewOnly),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::ed25519_spki;

    fn host_caps() -> Caps {
        Caps {
            codecs: vec!["h264".into(), "av1".into(), "hevc".into()],
            max_res: Resolution {
                width: 2560,
                height: 1440,
            },
            hdr: true,
            monitors: 2,
        }
    }

    #[test]
    fn negotiation_is_an_intersection_in_client_order() {
        let client = Caps {
            codecs: vec!["hevc".into(), "vp9".into(), "h264".into()],
            max_res: Resolution {
                width: 1920,
                height: 2160,
            },
            hdr: false,
            monitors: 3,
        };
        let chosen = ChosenCaps::negotiate(&host_caps(), &client);
        assert_eq!(chosen.caps().codecs, vec!["hevc", "h264"]);
        assert_eq!(
            chosen.caps().max_res,
            Resolution {
                width: 1920,
                height: 1440
            }
        );
        assert!(!chosen.caps().hdr);
        assert_eq!(chosen.caps().monitors, 2);
    }

    #[test]
    fn attended_accept_has_the_fixed_policy_fields() {
        let info = AcceptHostInfo {
            quic_spki: ed25519_spki(&[1u8; 32]),
            transport_policy: TransportPolicy::TorOnly,
        };
        let proof = ConsentProof::HumanClick {
            choice: PopupChoice::AllowOnceViewOnly,
            at: Instant::now(),
            token: FreshToken::mint([7u8; 32]),
        };
        let (accept, token) = SessionAccept::build(
            proof,
            ChosenCaps::negotiate(&host_caps(), &Caps::default()),
            &info,
        );
        assert_eq!(accept.session_type(), 0);
        assert_eq!(accept.mode(), 1);
        assert_eq!(accept.transport_policy(), 1);
        assert_eq!(accept.session_token(), Some(&[7u8; 32]));
        assert_eq!(token, SessionToken::new([7u8; 32]));
        assert_eq!(accept.token_confirm(), None);
        assert_eq!(accept.block_window_s(), 0);
        assert!(!accept.ask_before_start());
        assert_eq!(accept.ends_at(), None);
        assert_eq!(accept.fail_summary(), None);
        assert_eq!(accept.quic_spki(), &ed25519_spki(&[1u8; 32]));
        assert!(accept.caps().codecs.is_empty());
    }

    #[test]
    fn unattended_accept_takes_its_policy_from_the_receipt_and_keeps_the_token() {
        let info = AcceptHostInfo {
            quic_spki: ed25519_spki(&[1u8; 32]),
            transport_policy: TransportPolicy::Any,
        };
        let receipt = PolicyReceipt::mint(
            [1u8; 8],
            SessionMode::ViewOnly,
            TransportPolicy::LanOnly,
            Some(99),
            3,
            true,
            ReadinessSnapshot::default(),
            Some(FailSummary {
                since_success: 1,
                last_fail_at: Some(5),
            }),
        );
        assert_eq!(receipt.grant(), &[1u8; 8]);
        assert_eq!(receipt.readiness(), &ReadinessSnapshot::default());
        assert!(receipt.minted_at() <= Instant::now());
        let proof = ConsentProof::Unattended {
            grant: [1u8; 8],
            proof_fp: [0u8; 8],
            policy: receipt,
            block: WindowPassed::Elapsed,
            token: DerivedToken::new([2u8; 32], [3u8; 32]),
        };
        let (accept, token) = SessionAccept::build(
            proof,
            ChosenCaps::negotiate(&host_caps(), &host_caps()),
            &info,
        );
        assert_eq!(accept.session_type(), 1);
        assert_eq!(accept.mode(), 1);
        assert_eq!(
            accept.transport_policy(),
            2,
            "the receipt wins over the host default"
        );
        assert_eq!(accept.session_token(), None, "never sent (§B.8.4.3)");
        assert_eq!(accept.token_confirm(), Some(&[3u8; 32]));
        assert_eq!(
            token,
            SessionToken::new([2u8; 32]),
            "the BIND key is the derived session_token, not token_confirm"
        );
        assert_ne!(token, SessionToken::new([3u8; 32]));
        assert_eq!(accept.block_window_s(), 3);
        assert!(accept.ask_before_start());
        assert_eq!(accept.ends_at(), Some(99));
        assert_eq!(accept.fail_summary().unwrap().since_success, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn headless_defaults() {
        let w = TimerOnlyWindow;
        assert_eq!(
            w.run(0, &[0u8; 8], "x").await,
            BlockOutcome::Passed(WindowPassed::Skipped)
        );
        let started = Instant::now();
        assert_eq!(
            w.run(3, &[0u8; 8], "x").await,
            BlockOutcome::Passed(WindowPassed::Elapsed)
        );
        assert!(started.elapsed() >= Duration::from_secs(3));
        assert!(
            !AlwaysDeny
                .ask(&[0u8; 8], "x", Duration::from_secs(60))
                .await
        );
    }

    #[test]
    fn codes_roundtrip_and_secrets_are_redacted() {
        for p in [
            TransportPolicy::Any,
            TransportPolicy::TorOnly,
            TransportPolicy::LanOnly,
        ] {
            assert_eq!(TransportPolicy::from_code(p.code()), Some(p));
        }
        assert_eq!(TransportPolicy::from_code(9), None);
        assert_eq!(
            TransportPolicy::from_privacy(true, true),
            TransportPolicy::TorOnly
        );
        assert_eq!(
            TransportPolicy::from_privacy(false, true),
            TransportPolicy::LanOnly
        );
        assert_eq!(
            TransportPolicy::from_privacy(false, false),
            TransportPolicy::Any
        );
        for m in [SessionMode::Control, SessionMode::ViewOnly] {
            assert_eq!(mode_from_code(mode_code(m)), Some(m));
        }
        assert_eq!(mode_from_code(7), None);
        let t = FreshToken::mint([0xAB; 32]);
        assert!(!format!("{t:?}").contains("ab"));
        let d = DerivedToken::new([0xAB; 32], [0xCD; 32]);
        assert!(!format!("{d:?}").contains("ab"));
        assert_eq!(PopupChoice::AllowOnce.mode(), SessionMode::Control);

        // The accept and the session token never print token bytes; the
        // session id is a one-way derivation, not a prefix.
        let info = AcceptHostInfo {
            quic_spki: ed25519_spki(&[1u8; 32]),
            transport_policy: TransportPolicy::Any,
        };
        let proof = ConsentProof::HumanClick {
            choice: PopupChoice::AllowOnce,
            at: Instant::now(),
            token: FreshToken::mint([0xAB; 32]),
        };
        let (accept, token) = SessionAccept::build(
            proof,
            ChosenCaps::negotiate(&Caps::default(), &Caps::default()),
            &info,
        );
        let printed = format!("{accept:?}");
        assert!(!printed.contains("171"), "{printed}"); // 0xAB as a decimal byte
        assert!(!printed.contains("abab"), "{printed}");
        assert!(printed.contains("session_token: Some(\"..\")"), "{printed}");
        let id = token.session_id();
        assert_eq!(id.len(), 16);
        assert!(!id.contains("abab"), "{id}");
        assert_eq!(id, SessionToken::new([0xAB; 32]).session_id());
        assert_ne!(id, SessionToken::new([0xAC; 32]).session_id());
        let expected: [u8; 32] = Sha256::new()
            .chain_update(b"tornect/v1/session-id\0")
            .chain_update([0xAB; 32])
            .finalize()
            .into();
        assert_eq!(id, hex::encode(&expected[..8]));
        let printed = format!("{token:?}");
        assert!(!printed.contains("abab"), "{printed}");
        assert!(printed.contains(&id), "{printed}");
    }
}
