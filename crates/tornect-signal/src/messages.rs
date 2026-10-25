//! Message bodies (`docs/PLAN.md` §B.2, §B.8.4.1) and their code tables
//! (§B.8.4.1 `BYE` reasons and `ERROR` codes, §B.8.4.6 reject reasons).
//!
//! Every body is a CBOR map with small unsigned-integer keys (documented on
//! each field as `key n`). Receivers ignore unknown keys and default missing
//! optional keys, so later versions may add fields without a version bump;
//! non-optional fields are forever. Size-fixed fields (`bytes[32]`, `bytes[44]`,
//! `bytes[96]`, `bytes[320]`, `bytes[64]`, `bytes[16]`) are checked to the byte
//! at decode time, every string or list from the wire is bounded, and no wire
//! string may carry a control or invisible format character
//! (`tornect_core::trusted::is_invisible_or_control`: the crate is the
//! boundary, so a hostile `detail` can never reach a terminal or a UI label
//! with an escape sequence or a bidi override in it), so a successfully decoded
//! value is a valid one: [`decode_body`] is the only way to obtain one from the
//! network and it returns [`BodyError`] (⇒ `E_BAD_LEN`) otherwise.
//!
//! [`SessionAccept`] has private fields: `SessionAccept::build` in
//! [`crate::consent`] is its only constructor, so an accept exists only with
//! consent evidence behind it (§B.8.14, §B.8.16).

use minicbor::{Decode, Encode};
use subtle::{Choice, ConstantTimeEq as _};
use tornect_core::levels::Elevation;
use tornect_core::trusted::is_invisible_or_control;
use zeroize::Zeroize as _;

use crate::envelope::Kind;

/// Longest self-declared peer name (`HELLO.name`, `PAIR_ACCEPT.host_name`), in characters.
pub const MAX_NAME_CHARS: usize = 64;
/// Most feature tokens in `HELLO.feats` / `HELLO_ACK.feats`.
pub const MAX_FEATS: usize = 8;
/// Longest feature token, in characters.
pub const MAX_FEAT_CHARS: usize = 8;
/// Longest free-text `detail`, in characters (§B.8.4.1 `tstr ≤ 120`).
pub const MAX_DETAIL_CHARS: usize = 120;
/// Most codec names in [`Caps::codecs`].
pub const MAX_CODECS: usize = 8;
/// Longest codec name, in characters.
pub const MAX_CODEC_CHARS: usize = 16;
/// Most entries in the M2 placeholder [`Candidates::candidates`].
pub const MAX_CANDIDATES: usize = 32;
/// Longest placeholder candidate string, in characters.
pub const MAX_CANDIDATE_CHARS: usize = 64;
/// Length of an Ed25519 `SubjectPublicKeyInfo` DER (RFC 8410).
pub const SPKI_LEN: usize = 44;

/// PAKE suite ids (`SESSION_REQUEST.unattended.suite`, `AUTH_CHALLENGE.suite`).
pub mod suite {
    /// OPAQUE-3DH over ristretto255 / SHA-512 / Argon2id (§B.8.4.4).
    pub const OPAQUE: u8 = 1;
    /// SPAKE2 fallback (§B.8.4.7), `pake-fallback` builds only.
    pub const SPAKE2: u8 = 2;
}

/// `HELLO.feats` / `HELLO_ACK.feats` tokens (§B.8.4.2).
pub mod feats {
    /// Suite 1 supported.
    pub const UA1: &str = "ua1";
    /// Suite 2 supported.
    pub const UA2: &str = "ua2";
    /// Host only (`HELLO_ACK.feats`): this host answers a session's services
    /// stream on [`crate::SERVICES_PORT`] (decision M1-76). A viewer opens that
    /// port only when the host's signed `HELLO_ACK` carries this token
    /// ([`crate::fsm::client::ClientSession::host_has`]), since a host built
    /// before it destroys the whole circuit on the port. A host that serves no services still
    /// advertises it and refuses the stream, so the token does not tell one
    /// kind of host from another before pairing.
    pub const SVC1: &str = "svc1";
}

/// Session modes on the wire (`SESSION_ACCEPT.mode`, `want_mode`).
pub mod mode {
    /// Full control.
    pub const CONTROL: u8 = 0;
    /// View-only.
    pub const VIEW_ONLY: u8 = 1;
}

/// The administrator level (r7, §B.2.1): `SESSION_ACCEPT.elevation`,
/// `SESSION_REQUEST.unattended.want_elevation`. Absent on the wire = none.
pub mod elevation {
    /// The session acts as the signed-in user.
    pub const NONE: u8 = 0;
    /// Windows: input also reaches programs running as administrator.
    pub const ADMIN: u8 = 1;
}

/// The bits of the host's notice code, key 1 of its `PONG` ([`HostPong`],
/// decision M1-70, §B.8.4.1). The other bits are reserved: kept as received
/// and ignored.
pub mod notice {
    /// The host runs Windows.
    pub const WINDOWS: u8 = 0x01;
    /// The session is not at the administrator level on a Windows host, so
    /// its input cannot reach windows that run as administrator (UIPI,
    /// §B.2.1).
    pub const NO_ADMIN_WINDOWS: u8 = 0x02;
    /// A secure Windows screen is showing: a UAC prompt, the lock or the
    /// sign-in screen (§B.8.8).
    pub const SECURE_SCREEN: u8 = 0x04;
    /// The Control session's input reaches nothing on the host: its media
    /// stream is served with no injector (the desktop's dialog left remote
    /// interaction off, XTEST is missing, …). The viewer still decides from
    /// the signed accept whether it sends input (SLICE-C2 C2-6); this only
    /// lets it say why nothing happens.
    pub const NO_INPUT: u8 = 0x08;
    /// The Control session's input ended during the session, because the
    /// injector could not follow a change of the shown screen (decision
    /// M1-75): the host let go of everything held and dropped the injector
    /// rather than mis-map a click. The viewer can still watch. An older
    /// viewer ignores the bit, as every reserved one.
    pub const INPUT_LOST: u8 = 0x10;
}

/// `SESSION_ACCEPT.session_type`.
pub mod session_type {
    /// Attended: a human clicked Allow.
    pub const ATTENDED: u8 = 0;
    /// Unattended: pinned key + PAKE + block window (§B.8).
    pub const UNATTENDED: u8 = 1;
}

/// `SESSION_ACCEPT.transport_policy`.
pub mod transport {
    /// Any path.
    pub const ANY: u8 = 0;
    /// Tor only (Paranoid).
    pub const TOR_ONLY: u8 = 1;
    /// LAN only.
    pub const LAN_ONLY: u8 = 2;
}

/// `SESSION_REQUEST.unattended.intent`.
pub mod intent {
    /// Start a session.
    pub const SESSION: u8 = 0;
    /// Run an admin command instead (§B.8.4.1 admin scope).
    pub const ADMIN: u8 = 1;
}

/// `AdminCmd.op` (§B.8.4.1).
pub mod admin_op {
    /// Revoke the grant of `device_pk`.
    pub const REVOKE: u8 = 1;
    /// Revoke every grant.
    pub const REVOKE_ALL: u8 = 2;
    /// Turn unattended access off host-wide.
    pub const MASTER_OFF: u8 = 3;
    /// Reset the lockout of `device_pk`.
    pub const UNLOCK: u8 = 4;
    /// Suspend the grant of `device_pk`.
    pub const SUSPEND: u8 = 5;
    /// End the requester's own live session.
    pub const END_SESSION: u8 = 6;
}

/// `PAIR_REJECT.reason` codes (defined at M1; the plan leaves the body to
/// the implementation, decision M1-9).
pub mod pair_reject {
    /// The host user clicked Deny.
    pub const DENIED: u16 = 0x0001;
    /// The pairing popup timed out.
    pub const TIMEOUT: u16 = 0x0002;
    /// Popups are suppressed while a remote session is live (§B.8.16).
    pub const BUSY: u16 = 0x0003;
    /// This peer key is temp-banned after repeated rejects (§B.3).
    pub const BANNED: u16 = 0x0004;
    /// Another pairing request from this peer key is already in flight (§B.3).
    pub const IN_FLIGHT: u16 = 0x0005;
    /// Per-peer or host-wide pairing rate limit (§B.3).
    pub const RATE_LIMITED: u16 = 0x0006;

    /// Human-readable name.
    #[must_use]
    pub const fn name(reason: u16) -> &'static str {
        match reason {
            DENIED => "DENIED",
            TIMEOUT => "TIMEOUT",
            BUSY => "BUSY",
            BANNED => "BANNED",
            IN_FLIGHT => "IN_FLIGHT",
            RATE_LIMITED => "RATE_LIMITED",
            _ => "UNKNOWN",
        }
    }
}

/// `SESSION_REJECT.reason` codes (`docs/PLAN.md` §B.8.4.6).
pub mod reject {
    /// Attended: the host user clicked Deny.
    pub const DENIED: u16 = 0x0001;
    /// Attended: no click within the popup timeout.
    pub const POPUP_TIMEOUT: u16 = 0x0002;
    /// Attended: popups are suppressed while a remote session is live.
    pub const BUSY: u16 = 0x0003;
    /// Pre-PAKE: no grant, disabled, expired, master off, paused, keystore locked.
    pub const NOT_GRANTED: u16 = 0x0010;
    /// Pre-PAKE: ladder lockout (`retry_after_s`).
    pub const LOCKED_OUT: u16 = 0x0011;
    /// Pre-PAKE: hard lock.
    pub const HARD_LOCKED: u16 = 0x0012;
    /// Pre-PAKE: in-flight or global budget (§B.8.5.2).
    pub const UA_BUSY: u16 = 0x0013;
    /// Pre-PAKE: suite not compiled in or not the grant's suite.
    pub const UNSUPPORTED_SUITE: u16 = 0x0014;
    /// Pre-PAKE: cooling-off or clock rollback (`next_open_in_s`).
    pub const NOT_YET_ACTIVE: u16 = 0x0015;
    /// Pre-PAKE: grant suspended (`cause` 1 local · 2 admin).
    pub const SUSPENDED: u16 = 0x0016;
    /// PAKE failure: bad KE3.
    pub const AUTH_FAILED: u16 = 0x0020;
    /// Post-PAKE: outside the schedule (`next_open_in_s`).
    pub const OUTSIDE_SCHEDULE: u16 = 0x0021;
    /// Post-PAKE: Block clicked during the window.
    pub const BLOCKED_BY_LOCAL_USER: u16 = 0x0022;
    /// Post-PAKE: readiness probe failed (`cause`).
    pub const HOST_NOT_READY: u16 = 0x0023;
    /// Reserved (v1 replaces the older session instead).
    pub const ALREADY_CONNECTED: u16 = 0x0024;
    /// Reserved (was SUSPENDED, now pre-PAKE `0x0016`).
    pub const RESERVED_0025: u16 = 0x0025;
    /// Post-PAKE: another remote session is live.
    pub const SESSION_ACTIVE: u16 = 0x0026;
    /// Post-PAKE: the grant requires a transport the host forbids.
    pub const TRANSPORT_UNAVAILABLE: u16 = 0x0027;
    /// Post-PAKE: `require_absent` and a local user is present.
    pub const LOCAL_USER_PRESENT: u16 = 0x0028;
    /// Post-PAKE: reconnect cooldown (`retry_after_s`).
    pub const COOLDOWN: u16 = 0x0029;
    /// Cancellation: a newer verified `SESSION_REQUEST` from the same key.
    pub const PREEMPTED: u16 = 0x002A;

    /// Human-readable name.
    #[must_use]
    pub const fn name(reason: u16) -> &'static str {
        match reason {
            DENIED => "DENIED",
            POPUP_TIMEOUT => "POPUP_TIMEOUT",
            BUSY => "BUSY",
            NOT_GRANTED => "NOT_GRANTED",
            LOCKED_OUT => "LOCKED_OUT",
            HARD_LOCKED => "HARD_LOCKED",
            UA_BUSY => "UA_BUSY",
            UNSUPPORTED_SUITE => "UNSUPPORTED_SUITE",
            NOT_YET_ACTIVE => "NOT_YET_ACTIVE",
            SUSPENDED => "SUSPENDED",
            AUTH_FAILED => "AUTH_FAILED",
            OUTSIDE_SCHEDULE => "OUTSIDE_SCHEDULE",
            BLOCKED_BY_LOCAL_USER => "BLOCKED_BY_LOCAL_USER",
            HOST_NOT_READY => "HOST_NOT_READY",
            ALREADY_CONNECTED => "ALREADY_CONNECTED",
            RESERVED_0025 => "RESERVED_0025",
            SESSION_ACTIVE => "SESSION_ACTIVE",
            TRANSPORT_UNAVAILABLE => "TRANSPORT_UNAVAILABLE",
            LOCAL_USER_PRESENT => "LOCAL_USER_PRESENT",
            COOLDOWN => "COOLDOWN",
            PREEMPTED => "PREEMPTED",
            _ => "UNKNOWN",
        }
    }
}

/// `SESSION_REJECT.cause` values (§B.8.4.1).
pub mod cause {
    /// `HOST_NOT_READY`: capture permission missing.
    pub const CAPTURE_PERMISSION: u8 = 1;
    /// `HOST_NOT_READY`: input permission missing.
    pub const INPUT_PERMISSION: u8 = 2;
    /// `HOST_NOT_READY`: host locked.
    pub const LOCKED: u8 = 3;
    /// `HOST_NOT_READY`: another user owns the console.
    pub const OTHER_USER_ACTIVE: u8 = 4;
    /// `SUSPENDED`: a local suspension (Block, panic, local).
    pub const SUSPENDED_LOCAL: u8 = 1;
    /// `SUSPENDED`: an admin suspension.
    pub const SUSPENDED_ADMIN: u8 = 2;
}

/// `BYE.reason` codes (§B.8.4.1).
pub mod bye {
    /// The user ended the session.
    pub const USER: u16 = 0x01;
    /// The grant was revoked.
    pub const REVOKED: u16 = 0x02;
    /// Unattended access turned off host-wide.
    pub const MASTER_OFF: u16 = 0x03;
    /// The grant expired.
    pub const EXPIRED: u16 = 0x04;
    /// The schedule window ended.
    pub const SCHEDULE_END: u16 = 0x05;
    /// `max_session_secs` reached.
    pub const MAX_SESSION: u16 = 0x06;
    /// The host locked.
    pub const HOST_LOCKED: u16 = 0x07;
    /// The panic key.
    pub const PANIC: u16 = 0x08;
    /// No LAN path under `lan_only`.
    pub const NO_LAN_PATH: u16 = 0x09;
    /// Ended by an admin request.
    pub const ADMIN_END: u16 = 0x0A;
    /// The emergency stop code.
    pub const EMERGENCY_STOP: u16 = 0x0B;
    /// Client aborted the PAKE (KE2 MAC failed).
    pub const CLIENT_AUTH_ABORT: u16 = 0x0C;
    /// No `CANDIDATES` / `TOR_FALLBACK` after the accept, or no activity.
    pub const ORPHANED: u16 = 0x0D;
    /// Replaced by a newer session from the same key.
    pub const REPLACED: u16 = 0x0E;
    /// Unattended access paused.
    pub const PAUSED: u16 = 0x0F;
    /// The grant was suspended.
    pub const SUSPENDED: u16 = 0x10;

    /// Human-readable name.
    #[must_use]
    pub const fn name(reason: u16) -> &'static str {
        match reason {
            USER => "USER",
            REVOKED => "REVOKED",
            MASTER_OFF => "MASTER_OFF",
            EXPIRED => "EXPIRED",
            SCHEDULE_END => "SCHEDULE_END",
            MAX_SESSION => "MAX_SESSION",
            HOST_LOCKED => "HOST_LOCKED",
            PANIC => "PANIC",
            NO_LAN_PATH => "NO_LAN_PATH",
            ADMIN_END => "ADMIN_END",
            EMERGENCY_STOP => "EMERGENCY_STOP",
            CLIENT_AUTH_ABORT => "CLIENT_AUTH_ABORT",
            ORPHANED => "ORPHANED",
            REPLACED => "REPLACED",
            PAUSED => "PAUSED",
            SUSPENDED => "SUSPENDED",
            _ => "UNKNOWN",
        }
    }
}

/// A body that decoded but violates a documented bound or requirement
/// (⇒ `E_BAD_LEN`, §B.8.4.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BodyError {
    /// The CBOR is not a map of the expected shape, a required key is
    /// missing, or a size-fixed field has the wrong length.
    #[error("malformed {kind} body: {detail}")]
    Malformed {
        /// The message kind.
        kind: Kind,
        /// What the decoder objected to (no peer-controlled text).
        detail: String,
    },
    /// A list or string exceeds its bound.
    #[error("{kind}.{field} exceeds its bound")]
    TooLong {
        /// The message kind.
        kind: Kind,
        /// The offending field.
        field: &'static str,
    },
    /// A field is required by another field's value but absent, or present
    /// when it must not be (e.g. `admin` iff `intent = 1`).
    #[error("{kind}.{field}: {detail}")]
    Inconsistent {
        /// The message kind.
        kind: Kind,
        /// The offending field.
        field: &'static str,
        /// Which requirement failed.
        detail: &'static str,
    },
    /// A string carries a control or invisible format character.
    #[error("{kind}.{field} contains a control or invisible character")]
    ForbiddenChar {
        /// The message kind.
        kind: Kind,
        /// The offending field.
        field: &'static str,
    },
}

/// A message body with a fixed [`Kind`] and documented bounds.
pub trait Body: Encode<()> + for<'b> Decode<'b, ()> + Sized {
    /// The kind whose envelopes carry this body.
    const KIND: Kind;

    /// Check the bounds a plain decode cannot express (string and list
    /// lengths, conditional fields). Called by [`decode_body`].
    fn validate(&self) -> Result<(), BodyError> {
        Ok(())
    }
}

/// Encode a body to CBOR.
#[must_use]
pub fn encode_body<T: Body>(body: &T) -> Vec<u8> {
    // Encoding into a Vec is infallible (`encode::Error<Infallible>`).
    minicbor::to_vec(body).unwrap_or_default()
}

/// Decode and validate a body from the wire.
pub fn decode_body<T: Body>(bytes: &[u8]) -> Result<T, BodyError> {
    let value: T = minicbor::decode(bytes).map_err(|e| BodyError::Malformed {
        kind: T::KIND,
        detail: e.to_string(),
    })?;
    value.validate()?;
    Ok(value)
}

fn check_str(kind: Kind, field: &'static str, s: &str, max_chars: usize) -> Result<(), BodyError> {
    if s.chars().count() > max_chars {
        return Err(BodyError::TooLong { kind, field });
    }
    if s.chars().any(is_invisible_or_control) {
        return Err(BodyError::ForbiddenChar { kind, field });
    }
    Ok(())
}

/// Bring a locally configured feature list within the wire bounds
/// (≤ [`MAX_FEATS`] tokens of ≤ [`MAX_FEAT_CHARS`] visible characters), so a
/// misconfigured `config.toml` can never make every peer answer `E_BAD_LEN`.
#[must_use]
pub fn clamp_feats(feats: &[String]) -> Vec<String> {
    feats
        .iter()
        .take(MAX_FEATS)
        .map(|f| {
            f.chars()
                .filter(|c| !is_invisible_or_control(*c))
                .take(MAX_FEAT_CHARS)
                .collect()
        })
        .collect()
}

fn check_list(
    kind: Kind,
    field: &'static str,
    items: &[String],
    max_items: usize,
    max_chars: usize,
) -> Result<(), BodyError> {
    if items.len() > max_items {
        return Err(BodyError::TooLong { kind, field });
    }
    for s in items {
        check_str(kind, field, s, max_chars)?;
    }
    Ok(())
}

fn check_detail(kind: Kind, detail: Option<&String>) -> Result<(), BodyError> {
    match detail {
        Some(s) => check_str(kind, "detail", s, MAX_DETAIL_CHARS),
        None => Ok(()),
    }
}

/// `HELLO` (client → host, signed by the device key).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Hello {
    /// key 0 — highest protocol version the client speaks (the envelope itself carries `v = 1`).
    #[n(0)]
    pub v_max: u8,
    /// key 1 — fresh random nonce.
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub client_nonce: [u8; 32],
    /// key 2 — the client's ed25519 device public key (`client_device_pk` in
    /// §B.2 / §B.8.4.2); the signature is verified against it.
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub device_pk: [u8; 32],
    /// key 3 — self-declared name (≤ [`MAX_NAME_CHARS`]); shown only at pairing, never pinned as-is.
    #[n(3)]
    pub name: String,
    /// key 4 — PAKE suites this build supports (`"ua1"` / `"ua2"`, ≤ [`MAX_FEATS`] × [`MAX_FEAT_CHARS`]).
    #[n(4)]
    pub feats: Vec<String>,
    /// key 5 — `SHA-256("tornect/v1/stop\0" || dialed_host_onion_pk || stop_code)` (§B.8.7.4), never the code.
    #[n(5)]
    #[cbor(with = "minicbor::bytes")]
    pub stop_token: Option<[u8; 32]>,
    /// key 6 — advisory: `1` if the client believes it is already paired with this host, else `0`
    /// (default). The host never trusts it; it only helps explain a surprising PAIR path in logs.
    #[n(6)]
    #[cbor(default)]
    pub pairing_state: u8,
    /// key 7 — `SHA-256("tornect/v1/sas-commit\0" || sas_nonce)`, the SAS commitment
    /// of §B.3. The nonce itself is withheld until `PAIR_REQUEST`, so a proxying MITM
    /// must fix its `host_nonce` before it can learn the value the SAS depends on.
    /// Covered by the `HELLO` signature.
    #[n(7)]
    #[cbor(with = "minicbor::bytes")]
    #[cbor(default)]
    pub sas_commit: [u8; 32],
}

impl Body for Hello {
    const KIND: Kind = Kind::Hello;

    fn validate(&self) -> Result<(), BodyError> {
        check_str(Self::KIND, "name", &self.name, MAX_NAME_CHARS)?;
        check_list(Self::KIND, "feats", &self.feats, MAX_FEATS, MAX_FEAT_CHARS)
    }
}

/// `HELLO_ACK` (host → client, signed by the onion identity key).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct HelloAck {
    /// key 0 — the chosen protocol version (`≤ HELLO.v_max`); both sides use it from here on.
    #[n(0)]
    pub v: u8,
    /// key 1 — fresh random nonce; the client's `SESSION_REQUEST` signature covers it (F1).
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub host_nonce: [u8; 32],
    /// key 2 — host-wide feature tokens (independent of the peer): the PAKE
    /// suites, and [`feats::SVC1`] when the host answers the services stream.
    /// Covered by the signature, so the client trusts only what it verified.
    #[n(2)]
    pub feats: Vec<String>,
}

impl Body for HelloAck {
    const KIND: Kind = Kind::HelloAck;

    fn validate(&self) -> Result<(), BodyError> {
        check_list(Self::KIND, "feats", &self.feats, MAX_FEATS, MAX_FEAT_CHARS)
    }
}

/// `PAIR_REQUEST` (client → host, unpaired peers only).
#[derive(Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct PairRequest {
    /// key 0 — the client's x25519 key for restricted discovery (§B.8.11), if it wants one installed.
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub client_auth_pk: Option<[u8; 32]>,
    /// key 1 — the SAS nonce committed to in `HELLO.sas_commit` (§B.3). The host
    /// recomputes the commitment and closes on a mismatch, so this value is fixed
    /// before either side has seen the peer's contribution.
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    #[cbor(default)]
    pub sas_nonce: [u8; 32],
}

impl Body for PairRequest {
    const KIND: Kind = Kind::PairRequest;
}

/// `PAIR_ACCEPT` (host → client, after the pairing popup).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct PairAccept {
    /// key 0 — the host's *device* key (the machine's client identity), pinned by the client.
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub host_device_pk: [u8; 32],
    /// key 1 — the host's name (≤ [`MAX_NAME_CHARS`]); unpaired peers learn it here, after consent.
    #[n(1)]
    pub host_name: String,
}

impl Body for PairAccept {
    const KIND: Kind = Kind::PairAccept;

    fn validate(&self) -> Result<(), BodyError> {
        check_str(Self::KIND, "host_name", &self.host_name, MAX_NAME_CHARS)
    }
}

/// `PAIR_REJECT` (host → client).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct PairReject {
    /// key 0 — a [`pair_reject`] code.
    #[n(0)]
    pub reason: u16,
    /// key 1 — untrusted free text (≤ [`MAX_DETAIL_CHARS`]).
    #[n(1)]
    pub detail: Option<String>,
}

impl Body for PairReject {
    const KIND: Kind = Kind::PairReject;

    fn validate(&self) -> Result<(), BodyError> {
        check_detail(Self::KIND, self.detail.as_ref())
    }
}

/// A resolution, encoded as the two-item array `[width, height]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(array)]
pub struct Resolution {
    /// Width in pixels.
    #[n(0)]
    pub width: u16,
    /// Height in pixels.
    #[n(1)]
    pub height: u16,
}

/// Media capabilities offered (`SESSION_REQUEST`) or chosen (`SESSION_ACCEPT`), §B.2.
#[derive(Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct Caps {
    /// key 0 — codec names in preference order (≤ [`MAX_CODECS`] × [`MAX_CODEC_CHARS`]).
    #[n(0)]
    pub codecs: Vec<String>,
    /// key 1 — largest resolution.
    #[n(1)]
    pub max_res: Resolution,
    /// key 2 — HDR wanted / offered.
    #[n(2)]
    pub hdr: bool,
    /// key 3 — monitors wanted / offered.
    #[n(3)]
    pub monitors: u8,
}

impl Caps {
    fn validate(&self, kind: Kind) -> Result<(), BodyError> {
        check_list(
            kind,
            "caps.codecs",
            &self.codecs,
            MAX_CODECS,
            MAX_CODEC_CHARS,
        )
    }
}

/// An admin command (`SESSION_REQUEST.unattended.admin`, §B.8.4.1).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AdminCmd {
    /// key 0 — an [`admin_op`] code.
    #[n(0)]
    pub op: u8,
    /// key 1 — the target device key, present iff `op` is `revoke` /
    /// `unlock` / `suspend`.
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub device_pk: Option<[u8; 32]>,
}

impl AdminCmd {
    /// Whether `op` takes a `device_pk` (§B.8.4.1: `revoke(pk)`, `unlock(pk)`, `suspend(pk)`).
    #[must_use]
    pub const fn op_takes_device(op: u8) -> bool {
        matches!(op, admin_op::REVOKE | admin_op::UNLOCK | admin_op::SUSPEND)
    }

    fn validate(&self, kind: Kind) -> Result<(), BodyError> {
        if !(admin_op::REVOKE..=admin_op::END_SESSION).contains(&self.op) {
            return Err(BodyError::Inconsistent {
                kind,
                field: "unattended.admin.op",
                detail: "1..=6",
            });
        }
        if Self::op_takes_device(self.op) != self.device_pk.is_some() {
            return Err(BodyError::Inconsistent {
                kind,
                field: "unattended.admin.device_pk",
                detail: "present iff op is revoke, unlock or suspend",
            });
        }
        Ok(())
    }
}

/// The unattended half of a `SESSION_REQUEST` (§B.8.4.1).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct UnattendedRequest {
    /// key 0 — a [`suite`] id.
    #[n(0)]
    pub suite: u8,
    /// key 1 — OPAQUE KE1 (raw `serialize()` bytes), required iff `suite = 1`.
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub ke1: Option<[u8; 96]>,
    /// key 2 — a [`mode`] value; clamped host-side toward view-only, never a reject.
    #[n(2)]
    pub want_mode: u8,
    /// key 3 — an [`intent`] value.
    #[n(3)]
    pub intent: u8,
    /// key 4 — required iff `intent = 1`.
    #[n(4)]
    pub admin: Option<AdminCmd>,
    /// key 5 — an [`elevation`] value (r7, §B.8.4.1): absent = none; clamped
    /// host-side to the grant's level and to what the host can deliver,
    /// never a reject. A peer that predates it ignores it (unknown key).
    #[n(5)]
    pub want_elevation: Option<u8>,
}

/// `SESSION_REQUEST` (client → host, signed).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct SessionRequest {
    /// key 0 — what the client wants.
    #[n(0)]
    pub caps: Caps,
    /// key 1 — present for an unattended session (§B.8), absent for an attended one.
    #[n(1)]
    pub unattended: Option<UnattendedRequest>,
}

impl Body for SessionRequest {
    const KIND: Kind = Kind::SessionRequest;

    fn validate(&self) -> Result<(), BodyError> {
        self.caps.validate(Self::KIND)?;
        if let Some(u) = &self.unattended {
            // Enum-valued fields stay inside their §B.8.4.1 domain, so a
            // handler can branch on `intent == ADMIN` / `want_mode` without
            // an unknown value silently taking the other arm.
            if u.intent != intent::SESSION && u.intent != intent::ADMIN {
                return Err(BodyError::Inconsistent {
                    kind: Self::KIND,
                    field: "unattended.intent",
                    detail: "0 session or 1 admin",
                });
            }
            if u.want_mode != mode::CONTROL && u.want_mode != mode::VIEW_ONLY {
                return Err(BodyError::Inconsistent {
                    kind: Self::KIND,
                    field: "unattended.want_mode",
                    detail: "0 control or 1 view-only",
                });
            }
            if u.want_elevation
                .is_some_and(|e| e != elevation::NONE && e != elevation::ADMIN)
            {
                return Err(BodyError::Inconsistent {
                    kind: Self::KIND,
                    field: "unattended.want_elevation",
                    detail: "0 none or 1 admin",
                });
            }
            let admin_required = u.intent == intent::ADMIN;
            if admin_required != u.admin.is_some() {
                return Err(BodyError::Inconsistent {
                    kind: Self::KIND,
                    field: "unattended.admin",
                    detail: "present iff intent = 1",
                });
            }
            if let Some(admin) = &u.admin {
                admin.validate(Self::KIND)?;
            }
            // §B.8.4.1: `ke1` is required iff `suite = 1` and must be absent
            // for suite 2. An unknown suite is left to the handler's
            // `UNSUPPORTED_SUITE` gate but carries no key material either.
            let ke1_wrong = match u.suite {
                suite::OPAQUE => u.ke1.is_none(),
                _ => u.ke1.is_some(),
            };
            if ke1_wrong {
                return Err(BodyError::Inconsistent {
                    kind: Self::KIND,
                    field: "unattended.ke1",
                    detail: "present iff suite = 1",
                });
            }
        }
        Ok(())
    }
}

/// The limiter snapshot disclosed in a `SESSION_ACCEPT` (§B.8.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct FailSummary {
    /// key 0 — failed attempts since the last success (own charge excluded).
    #[n(0)]
    pub since_success: u32,
    /// key 1 — Unix seconds of the last failure; `Some` whenever `since_success > 0`.
    #[n(1)]
    pub last_fail_at: Option<u64>,
}

/// `SESSION_ACCEPT` (host → client, signed).
///
/// Constructed only by `SessionAccept::build` ([`crate::consent`]); decoded
/// from the wire by [`decode_body`] and read through the accessors. The two
/// token fields are secrets: redacted in `Debug`, zeroized on drop, compared
/// in constant time.
#[derive(Clone, Encode, Decode)]
#[cbor(map)]
pub struct SessionAccept {
    /// key 0 — the negotiated caps.
    #[n(0)]
    pub(crate) caps: Caps,
    /// key 1 — the host's Ed25519 `SubjectPublicKeyInfo` DER (§B.6): the SPKI
    /// of the host *device* key pinned at pairing (`PAIR_ACCEPT.host_device_pk`).
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub(crate) quic_spki: [u8; SPKI_LEN],
    /// key 2 — a [`session_type`] value.
    #[n(2)]
    pub(crate) session_type: u8,
    /// key 3 — a [`mode`] value.
    #[n(3)]
    pub(crate) mode: u8,
    /// key 4 — a [`transport`] value.
    #[n(4)]
    pub(crate) transport_policy: u8,
    /// key 5 — attended only; absent when `session_type = 1`.
    #[n(5)]
    #[cbor(with = "minicbor::bytes")]
    pub(crate) session_token: Option<[u8; 32]>,
    /// key 6 — unattended only.
    #[n(6)]
    #[cbor(with = "minicbor::bytes")]
    pub(crate) token_confirm: Option<[u8; 32]>,
    /// key 7 — grant policy (0 for attended).
    #[n(7)]
    pub(crate) block_window_s: u8,
    /// key 8 — grant policy (`false` for attended).
    #[n(8)]
    pub(crate) ask_before_start: bool,
    /// key 9 — Unix seconds when the session must end (unattended).
    #[n(9)]
    pub(crate) ends_at: Option<u64>,
    /// key 10 — the limiter snapshot (unattended, `None` when nothing failed).
    #[n(10)]
    pub(crate) fail_summary: Option<FailSummary>,
    /// key 11 — an [`elevation`] value (r7, §B.2.1): absent = none, and a
    /// session at none never carries the key, so its bytes are the ones a
    /// peer that predates it sends and reads. Inside the signed body like
    /// every key; never admin unless `mode = 0` (control).
    #[n(11)]
    pub(crate) elevation: Option<u8>,
    /// key 12 — `grant_reach` (decision M1-67): what the password just proven can reach
    /// through Tornect on this host, whatever was asked: 0 none, 1 through the host, 2 this
    /// grant holds the administrator level. Unattended accepts only, inside the signed body;
    /// absent from a host that does not send it (the reach is then unknown). Left out of
    /// `Debug` and never logged (C13).
    #[n(12)]
    pub(crate) grant_reach: Option<u8>,
}

impl SessionAccept {
    /// The negotiated caps.
    #[must_use]
    pub fn caps(&self) -> &Caps {
        &self.caps
    }

    /// The host's SPKI DER.
    #[must_use]
    pub fn quic_spki(&self) -> &[u8; SPKI_LEN] {
        &self.quic_spki
    }

    /// A [`session_type`] value.
    #[must_use]
    pub fn session_type(&self) -> u8 {
        self.session_type
    }

    /// A [`mode`] value.
    #[must_use]
    pub fn mode(&self) -> u8 {
        self.mode
    }

    /// A [`transport`] value.
    #[must_use]
    pub fn transport_policy(&self) -> u8 {
        self.transport_policy
    }

    /// The attended session token.
    #[must_use]
    pub fn session_token(&self) -> Option<&[u8; 32]> {
        self.session_token.as_ref()
    }

    /// The unattended token confirmation.
    #[must_use]
    pub fn token_confirm(&self) -> Option<&[u8; 32]> {
        self.token_confirm.as_ref()
    }

    /// Block window length in seconds.
    #[must_use]
    pub fn block_window_s(&self) -> u8 {
        self.block_window_s
    }

    /// Whether the grant asks a local user before starting.
    #[must_use]
    pub fn ask_before_start(&self) -> bool {
        self.ask_before_start
    }

    /// When the session must end.
    #[must_use]
    pub fn ends_at(&self) -> Option<u64> {
        self.ends_at
    }

    /// The limiter snapshot.
    #[must_use]
    pub fn fail_summary(&self) -> Option<FailSummary> {
        self.fail_summary
    }

    /// The session's administrator level (absent = none). A decoded accept
    /// holds only `0` or `1`, and `1` only with control ([`decode_body`]).
    #[must_use]
    pub fn elevation(&self) -> Elevation {
        self.elevation
            .and_then(Elevation::from_code)
            .unwrap_or(Elevation::None)
    }

    /// `grant_reach` (key 12, decision M1-67): `None` on an attended accept and from a host
    /// that does not send it. A decoded accept holds only 0, 1 or 2, and 2 whenever an
    /// unattended accept signs the administrator level ([`decode_body`]).
    #[must_use]
    pub fn grant_reach(&self) -> Option<u8> {
        self.grant_reach
    }
}

impl Body for SessionAccept {
    const KIND: Kind = Kind::SessionAccept;

    fn validate(&self) -> Result<(), BodyError> {
        self.caps.validate(Self::KIND)?;
        match self.elevation {
            None | Some(elevation::NONE) => {}
            // View-only never carries an elevation (§B.8.4.1), and neither
            // does a mode this build does not know.
            Some(elevation::ADMIN) if self.mode == mode::CONTROL => {}
            Some(elevation::ADMIN) => {
                return Err(BodyError::Inconsistent {
                    kind: Self::KIND,
                    field: "elevation",
                    detail: "admin only with mode = 0",
                });
            }
            Some(_) => {
                return Err(BodyError::Inconsistent {
                    kind: Self::KIND,
                    field: "elevation",
                    detail: "0 none or 1 admin",
                });
            }
        }
        check_grant_reach(Self::KIND, self.grant_reach)?;
        // M1-67 (B, the receive rules): the key only on an unattended accept, and an
        // unattended accept that signs the level says 2. An attended accept keeps its
        // rules, so the attended vector 3 still decodes.
        let unattended = self.session_type == session_type::UNATTENDED;
        if self.grant_reach.is_some() && !unattended {
            return Err(BodyError::Inconsistent {
                kind: Self::KIND,
                field: "grant_reach",
                detail: "unattended accepts only",
            });
        }
        if unattended && self.elevation == Some(elevation::ADMIN) && self.grant_reach != Some(2) {
            return Err(BodyError::Inconsistent {
                kind: Self::KIND,
                field: "grant_reach",
                detail: "2 when the administrator level is signed",
            });
        }
        Ok(())
    }
}

/// `grant_reach` (decision M1-67) is 0, 1 or 2 in either body that carries it.
fn check_grant_reach(kind: Kind, grant_reach: Option<u8>) -> Result<(), BodyError> {
    match grant_reach {
        None | Some(0..=2) => Ok(()),
        Some(_) => Err(BodyError::Inconsistent {
            kind,
            field: "grant_reach",
            detail: "0, 1 or 2",
        }),
    }
}

/// Constant-time equality of two optional 32-byte secrets (`None == None`).
fn ct_option_eq(a: Option<&[u8; 32]>, b: Option<&[u8; 32]>) -> Choice {
    match (a, b) {
        (Some(a), Some(b)) => a[..].ct_eq(&b[..]),
        (None, None) => Choice::from(1),
        _ => Choice::from(0),
    }
}

impl PartialEq for SessionAccept {
    fn eq(&self, other: &Self) -> bool {
        let tokens = ct_option_eq(self.session_token.as_ref(), other.session_token.as_ref())
            & ct_option_eq(self.token_confirm.as_ref(), other.token_confirm.as_ref());
        self.caps == other.caps
            && self.quic_spki == other.quic_spki
            && self.session_type == other.session_type
            && self.mode == other.mode
            && self.transport_policy == other.transport_policy
            && self.block_window_s == other.block_window_s
            && self.ask_before_start == other.ask_before_start
            && self.ends_at == other.ends_at
            && self.fail_summary == other.fail_summary
            && self.elevation == other.elevation
            && self.grant_reach == other.grant_reach
            && bool::from(tokens)
    }
}

impl Eq for SessionAccept {}

impl core::fmt::Debug for SessionAccept {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionAccept")
            .field("caps", &self.caps)
            .field("quic_spki", &hex::encode(self.quic_spki))
            .field("session_type", &self.session_type)
            .field("mode", &self.mode)
            .field("transport_policy", &self.transport_policy)
            .field("session_token", &self.session_token.as_ref().map(|_| ".."))
            .field("token_confirm", &self.token_confirm.as_ref().map(|_| ".."))
            .field("block_window_s", &self.block_window_s)
            .field("ask_before_start", &self.ask_before_start)
            .field("ends_at", &self.ends_at)
            .field("fail_summary", &self.fail_summary)
            .field("elevation", &self.elevation)
            .finish()
    }
}

impl Drop for SessionAccept {
    fn drop(&mut self) {
        if let Some(t) = self.session_token.as_mut() {
            t.zeroize();
        }
        if let Some(t) = self.token_confirm.as_mut() {
            t.zeroize();
        }
    }
}

/// `SESSION_REJECT` (host → client).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct SessionReject {
    /// key 0 — a [`reject`] code.
    #[n(0)]
    pub reason: u16,
    /// key 1 — a [`cause`] value for `HOST_NOT_READY` / `SUSPENDED`.
    #[n(1)]
    pub cause: Option<u8>,
    /// key 2 — seconds until a retry may succeed (`LOCKED_OUT`, `COOLDOWN`).
    #[n(2)]
    pub retry_after_s: Option<u32>,
    /// key 3 — seconds until the next open window (`NOT_YET_ACTIVE`, `OUTSIDE_SCHEDULE`).
    #[n(3)]
    pub next_open_in_s: Option<u32>,
    /// key 4 — untrusted free text (≤ [`MAX_DETAIL_CHARS`]).
    #[n(4)]
    pub detail: Option<String>,
}

impl SessionReject {
    /// A reject with only a reason.
    #[must_use]
    pub fn new(reason: u16) -> Self {
        Self {
            reason,
            cause: None,
            retry_after_s: None,
            next_open_in_s: None,
            detail: None,
        }
    }
}

impl Body for SessionReject {
    const KIND: Kind = Kind::SessionReject;

    fn validate(&self) -> Result<(), BodyError> {
        check_detail(Self::KIND, self.detail.as_ref())
    }
}

/// `AUTH_CHALLENGE` (host → client, unattended only).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AuthChallenge {
    /// key 0 — a [`suite`] id (must equal the requested one).
    #[n(0)]
    pub suite: u8,
    /// key 1 — OPAQUE KE2, iff `suite = 1`.
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub ke2: Option<[u8; 320]>,
    /// key 2 — SPAKE2 salt, iff `suite = 2`.
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub salt: Option<[u8; 16]>,
    /// key 3 — SPAKE2 `pB`, iff `suite = 2`.
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub pb: Option<[u8; 32]>,
}

impl Body for AuthChallenge {
    const KIND: Kind = Kind::AuthChallenge;

    fn validate(&self) -> Result<(), BodyError> {
        match self.suite {
            suite::OPAQUE if self.ke2.is_none() || self.salt.is_some() || self.pb.is_some() => {
                Err(BodyError::Inconsistent {
                    kind: Self::KIND,
                    field: "ke2",
                    detail: "suite 1 carries ke2 only",
                })
            }
            suite::SPAKE2 if self.ke2.is_some() || self.salt.is_none() || self.pb.is_none() => {
                Err(BodyError::Inconsistent {
                    kind: Self::KIND,
                    field: "salt/pb",
                    detail: "suite 2 carries salt and pb only",
                })
            }
            suite::OPAQUE | suite::SPAKE2 => Ok(()),
            // A challenge names the suite the host runs; an unknown one must
            // not carry either suite's fields.
            _ => Err(BodyError::Inconsistent {
                kind: Self::KIND,
                field: "suite",
                detail: "1 or 2",
            }),
        }
    }
}

/// `AUTH_RESPONSE` (client → host, unattended only).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AuthResponse {
    /// key 0 — OPAQUE KE3, iff suite 1.
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub ke3: Option<[u8; 64]>,
    /// key 1 — SPAKE2 `pA`, iff suite 2.
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub pa: Option<[u8; 32]>,
    /// key 2 — SPAKE2 `cA`, iff suite 2.
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub ca: Option<[u8; 32]>,
}

impl Body for AuthResponse {
    const KIND: Kind = Kind::AuthResponse;

    fn validate(&self) -> Result<(), BodyError> {
        // Exactly one suite's fields; which suite is right is the handler's check.
        let opaque = self.ke3.is_some() && self.pa.is_none() && self.ca.is_none();
        let spake = self.ke3.is_none() && self.pa.is_some() && self.ca.is_some();
        if opaque || spake {
            Ok(())
        } else {
            Err(BodyError::Inconsistent {
                kind: Self::KIND,
                field: "ke3/pa/ca",
                detail: "exactly one suite's fields",
            })
        }
    }
}

/// `ADMIN_RESULT` (host → client, signed).
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AdminResult {
    /// key 0 — whether the command was executed.
    #[n(0)]
    pub ok: bool,
    /// key 1 — untrusted free text (≤ [`MAX_DETAIL_CHARS`]).
    #[n(1)]
    pub detail: Option<String>,
    /// key 2 — `grant_reach` (decision M1-67), as in `SESSION_ACCEPT`: what the requester's
    /// password can reach through Tornect on this host. Absent from a host that does not send
    /// it. Left out of `Debug` and never logged (C13).
    #[n(2)]
    pub grant_reach: Option<u8>,
}

impl core::fmt::Debug for AdminResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdminResult")
            .field("ok", &self.ok)
            .field("detail", &self.detail)
            .finish_non_exhaustive()
    }
}

impl Body for AdminResult {
    const KIND: Kind = Kind::AdminResult;

    fn validate(&self) -> Result<(), BodyError> {
        check_detail(Self::KIND, self.detail.as_ref())?;
        check_grant_reach(Self::KIND, self.grant_reach)
    }
}

/// `CANDIDATES` — M2 placeholder: opaque candidate strings (`docs/PLAN.md` §B.2).
///
/// M2 defines the real candidate encoding (`tornect-net`); until then this
/// body only proves the post-accept path and is handed to a callback unparsed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct Candidates {
    /// key 0 — candidates (≤ [`MAX_CANDIDATES`] × [`MAX_CANDIDATE_CHARS`]).
    #[n(0)]
    pub candidates: Vec<String>,
}

impl Body for Candidates {
    const KIND: Kind = Kind::Candidates;

    fn validate(&self) -> Result<(), BodyError> {
        check_list(
            Self::KIND,
            "candidates",
            &self.candidates,
            MAX_CANDIDATES,
            MAX_CANDIDATE_CHARS,
        )
    }
}

/// `CANDIDATES_DONE` — M2 placeholder, empty map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct CandidatesDone {}

impl Body for CandidatesDone {
    const KIND: Kind = Kind::CandidatesDone;
}

/// `TOR_FALLBACK` — M2 placeholder, empty map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct TorFallback {}

impl Body for TorFallback {
    const KIND: Kind = Kind::TorFallback;
}

/// `PING` (either direction after `SESSION_ACCEPT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct Ping {
    /// key 0 — echoed by the `PONG`.
    #[n(0)]
    pub nonce: u64,
}

impl Body for Ping {
    const KIND: Kind = Kind::Ping;
}

/// `PONG`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct Pong {
    /// key 0 — the `PING.nonce`.
    #[n(0)]
    pub nonce: u64,
}

impl Body for Pong {
    const KIND: Kind = Kind::Pong;
}

/// `PONG` as the host of a session sends it, and as the client reads it
/// (decision M1-70): [`Pong`]'s nonce and key 1, the host's notice code (the
/// bits of [`notice`]). Absent, it says nothing new and the bytes are
/// [`Pong`]'s: a peer built before the key reads a `HostPong` as a plain
/// `PONG`, and a plain `PONG` reads as a `HostPong` with no notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct HostPong {
    /// key 0 — the `PING.nonce`.
    #[n(0)]
    pub nonce: u64,
    /// key 1 — the host's notice code: a number, never text, so the viewer
    /// says its own fixed sentences. Bits it does not know are kept as
    /// received and ignored.
    #[n(1)]
    pub notice: Option<u8>,
}

impl Body for HostPong {
    const KIND: Kind = Kind::Pong;
}

/// `BYE` (either direction).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Bye {
    /// key 0 — a [`bye`] code.
    #[n(0)]
    pub reason: u16,
    /// key 1 — untrusted free text (≤ [`MAX_DETAIL_CHARS`]).
    #[n(1)]
    pub detail: Option<String>,
}

impl Body for Bye {
    const KIND: Kind = Kind::Bye;

    fn validate(&self) -> Result<(), BodyError> {
        check_detail(Self::KIND, self.detail.as_ref())
    }
}

/// `ERROR` (either direction; the sender closes afterwards).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Error {
    /// key 0 — an [`crate::envelope::codes`] value.
    #[n(0)]
    pub code: u16,
    /// key 1 — untrusted free text (≤ [`MAX_DETAIL_CHARS`]).
    #[n(1)]
    pub detail: Option<String>,
}

impl Body for Error {
    const KIND: Kind = Kind::Error;

    fn validate(&self) -> Result<(), BodyError> {
        check_detail(Self::KIND, self.detail.as_ref())
    }
}

/// Any body, decoded by kind ([`decode_any`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// `HELLO`.
    Hello(Hello),
    /// `HELLO_ACK`.
    HelloAck(HelloAck),
    /// `PAIR_REQUEST`.
    PairRequest(PairRequest),
    /// `PAIR_ACCEPT`.
    PairAccept(PairAccept),
    /// `PAIR_REJECT`.
    PairReject(PairReject),
    /// `SESSION_REQUEST`.
    SessionRequest(SessionRequest),
    /// `SESSION_ACCEPT`.
    SessionAccept(SessionAccept),
    /// `SESSION_REJECT`.
    SessionReject(SessionReject),
    /// `AUTH_CHALLENGE` (boxed: 320-byte KE2).
    AuthChallenge(Box<AuthChallenge>),
    /// `AUTH_RESPONSE`.
    AuthResponse(AuthResponse),
    /// `ADMIN_RESULT`.
    AdminResult(AdminResult),
    /// `CANDIDATES`.
    Candidates(Candidates),
    /// `CANDIDATES_DONE`.
    CandidatesDone(CandidatesDone),
    /// `TOR_FALLBACK`.
    TorFallback(TorFallback),
    /// `PING`.
    Ping(Ping),
    /// `PONG`.
    Pong(Pong),
    /// `BYE`.
    Bye(Bye),
    /// `ERROR`.
    Error(Error),
}

/// Decode the body of an envelope of `kind`.
pub fn decode_any(kind: Kind, body: &[u8]) -> Result<Message, BodyError> {
    Ok(match kind {
        Kind::Hello => Message::Hello(decode_body(body)?),
        Kind::HelloAck => Message::HelloAck(decode_body(body)?),
        Kind::PairRequest => Message::PairRequest(decode_body(body)?),
        Kind::PairAccept => Message::PairAccept(decode_body(body)?),
        Kind::PairReject => Message::PairReject(decode_body(body)?),
        Kind::SessionRequest => Message::SessionRequest(decode_body(body)?),
        Kind::SessionAccept => Message::SessionAccept(decode_body(body)?),
        Kind::SessionReject => Message::SessionReject(decode_body(body)?),
        Kind::AuthChallenge => Message::AuthChallenge(Box::new(decode_body(body)?)),
        Kind::AuthResponse => Message::AuthResponse(decode_body(body)?),
        Kind::AdminResult => Message::AdminResult(decode_body(body)?),
        Kind::Candidates => Message::Candidates(decode_body(body)?),
        Kind::CandidatesDone => Message::CandidatesDone(decode_body(body)?),
        Kind::TorFallback => Message::TorFallback(decode_body(body)?),
        Kind::Ping => Message::Ping(decode_body(body)?),
        Kind::Pong => Message::Pong(decode_body(body)?),
        Kind::Bye => Message::Bye(decode_body(body)?),
        Kind::Error => Message::Error(decode_body(body)?),
    })
}

/// The DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410 §4):
/// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused bits) }`.
pub const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The 44-byte SPKI DER of an Ed25519 public key (`SESSION_ACCEPT.quic_spki`, §B.6).
#[must_use]
pub fn ed25519_spki(pk: &[u8; 32]) -> [u8; SPKI_LEN] {
    let mut out = [0u8; SPKI_LEN];
    out[..SPKI_PREFIX.len()].copy_from_slice(&SPKI_PREFIX);
    out[SPKI_PREFIX.len()..].copy_from_slice(pk);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn roundtrip<T: Body + PartialEq + core::fmt::Debug>(v: &T) -> T {
        let bytes = encode_body(v);
        let back: T = decode_body(&bytes).unwrap();
        assert_eq!(&back, v);
        back
    }

    fn hello() -> Hello {
        Hello {
            v_max: 1,
            client_nonce: [1u8; 32],
            device_pk: [2u8; 32],
            name: "Laptop of Ana".to_owned(),
            feats: vec!["ua1".to_owned()],
            stop_token: None,
            pairing_state: 0,
            sas_commit: [3u8; 32],
        }
    }

    fn accept() -> SessionAccept {
        SessionAccept {
            caps: Caps {
                codecs: vec!["h264".to_owned()],
                max_res: Resolution {
                    width: 1920,
                    height: 1080,
                },
                hdr: false,
                monitors: 1,
            },
            quic_spki: ed25519_spki(&[5u8; 32]),
            session_type: 0,
            mode: 0,
            transport_policy: 0,
            session_token: Some([6u8; 32]),
            token_confirm: None,
            block_window_s: 0,
            ask_before_start: false,
            ends_at: None,
            fail_summary: None,
            elevation: None,
            grant_reach: None,
        }
    }

    #[test]
    fn every_body_roundtrips() {
        roundtrip(&hello());
        roundtrip(&Hello {
            stop_token: Some([9u8; 32]),
            pairing_state: 1,
            ..hello()
        });
        roundtrip(&HelloAck {
            v: 1,
            host_nonce: [3u8; 32],
            feats: vec![],
        });
        roundtrip(&PairRequest::default());
        roundtrip(&PairRequest {
            client_auth_pk: Some([4u8; 32]),
            sas_nonce: [5u8; 32],
        });
        roundtrip(&PairAccept {
            host_device_pk: [7u8; 32],
            host_name: "Desk".to_owned(),
        });
        roundtrip(&PairReject {
            reason: pair_reject::DENIED,
            detail: Some("no".to_owned()),
        });
        roundtrip(&SessionRequest {
            caps: Caps::default(),
            unattended: None,
        });
        roundtrip(&SessionRequest {
            caps: Caps::default(),
            unattended: Some(UnattendedRequest {
                suite: 1,
                ke1: Some([1u8; 96]),
                want_mode: 0,
                intent: intent::ADMIN,
                admin: Some(AdminCmd {
                    op: admin_op::UNLOCK,
                    device_pk: Some([8u8; 32]),
                }),
                want_elevation: None,
            }),
        });
        roundtrip(&accept());
        let mut unattended = accept();
        unattended.session_type = 1;
        unattended.session_token = None;
        unattended.token_confirm = Some([1u8; 32]);
        unattended.block_window_s = 3;
        unattended.ask_before_start = true;
        unattended.ends_at = Some(1_700_000_000);
        unattended.fail_summary = Some(FailSummary {
            since_success: 2,
            last_fail_at: Some(5),
        });
        roundtrip(&unattended);
        roundtrip(&SessionReject {
            reason: reject::LOCKED_OUT,
            cause: None,
            retry_after_s: Some(30),
            next_open_in_s: None,
            detail: None,
        });
        roundtrip(&AuthChallenge {
            suite: 1,
            ke2: Some([2u8; 320]),
            salt: None,
            pb: None,
        });
        roundtrip(&AuthChallenge {
            suite: 2,
            ke2: None,
            salt: Some([1u8; 16]),
            pb: Some([2u8; 32]),
        });
        roundtrip(&AuthResponse {
            ke3: Some([3u8; 64]),
            pa: None,
            ca: None,
        });
        roundtrip(&AuthResponse {
            ke3: None,
            pa: Some([3u8; 32]),
            ca: Some([4u8; 32]),
        });
        roundtrip(&AdminResult {
            ok: true,
            detail: None,
            grant_reach: None,
        });
        roundtrip(&Candidates {
            candidates: vec!["192.0.2.1:4000".to_owned()],
        });
        roundtrip(&CandidatesDone {});
        roundtrip(&TorFallback {});
        roundtrip(&Ping { nonce: u64::MAX });
        roundtrip(&Pong { nonce: 0 });
        roundtrip(&Bye {
            reason: bye::USER,
            detail: None,
        });
        roundtrip(&Error {
            code: 7,
            detail: Some("x".to_owned()),
        });
    }

    #[test]
    fn decode_any_covers_every_kind() {
        let bodies: Vec<(Kind, Vec<u8>)> = vec![
            (Kind::Hello, encode_body(&hello())),
            (
                Kind::HelloAck,
                encode_body(&HelloAck {
                    v: 1,
                    host_nonce: [0; 32],
                    feats: vec![],
                }),
            ),
            (Kind::PairRequest, encode_body(&PairRequest::default())),
            (
                Kind::PairAccept,
                encode_body(&PairAccept {
                    host_device_pk: [0; 32],
                    host_name: String::new(),
                }),
            ),
            (
                Kind::PairReject,
                encode_body(&PairReject {
                    reason: 1,
                    detail: None,
                }),
            ),
            (
                Kind::SessionRequest,
                encode_body(&SessionRequest {
                    caps: Caps::default(),
                    unattended: None,
                }),
            ),
            (Kind::SessionAccept, encode_body(&accept())),
            (Kind::SessionReject, encode_body(&SessionReject::new(1))),
            (
                Kind::AuthChallenge,
                encode_body(&AuthChallenge {
                    suite: 1,
                    ke2: Some([0; 320]),
                    salt: None,
                    pb: None,
                }),
            ),
            (
                Kind::AuthResponse,
                encode_body(&AuthResponse {
                    ke3: Some([0; 64]),
                    pa: None,
                    ca: None,
                }),
            ),
            (
                Kind::AdminResult,
                encode_body(&AdminResult {
                    ok: false,
                    detail: None,
                    grant_reach: None,
                }),
            ),
            (Kind::Candidates, encode_body(&Candidates::default())),
            (Kind::CandidatesDone, encode_body(&CandidatesDone {})),
            (Kind::TorFallback, encode_body(&TorFallback {})),
            (Kind::Ping, encode_body(&Ping { nonce: 1 })),
            (Kind::Pong, encode_body(&Pong { nonce: 1 })),
            (
                Kind::Bye,
                encode_body(&Bye {
                    reason: 1,
                    detail: None,
                }),
            ),
            (
                Kind::Error,
                encode_body(&Error {
                    code: 1,
                    detail: None,
                }),
            ),
        ];
        assert_eq!(bodies.len(), Kind::ALL.len());
        for (kind, body) in bodies {
            let msg = decode_any(kind, &body).unwrap();
            let same_kind = matches!(
                (&msg, kind),
                (Message::Hello(_), Kind::Hello)
                    | (Message::HelloAck(_), Kind::HelloAck)
                    | (Message::PairRequest(_), Kind::PairRequest)
                    | (Message::PairAccept(_), Kind::PairAccept)
                    | (Message::PairReject(_), Kind::PairReject)
                    | (Message::SessionRequest(_), Kind::SessionRequest)
                    | (Message::SessionAccept(_), Kind::SessionAccept)
                    | (Message::SessionReject(_), Kind::SessionReject)
                    | (Message::AuthChallenge(_), Kind::AuthChallenge)
                    | (Message::AuthResponse(_), Kind::AuthResponse)
                    | (Message::AdminResult(_), Kind::AdminResult)
                    | (Message::Candidates(_), Kind::Candidates)
                    | (Message::CandidatesDone(_), Kind::CandidatesDone)
                    | (Message::TorFallback(_), Kind::TorFallback)
                    | (Message::Ping(_), Kind::Ping)
                    | (Message::Pong(_), Kind::Pong)
                    | (Message::Bye(_), Kind::Bye)
                    | (Message::Error(_), Kind::Error)
            );
            assert!(same_kind, "{kind}: {msg:?}");
            // Every kind rejects an empty map missing its required keys or a non-map.
            assert!(decode_any(kind, &[0x05]).is_err(), "{kind} accepted an int");
        }
    }

    #[test]
    fn unknown_keys_are_ignored_and_missing_optionals_default() {
        // {0: 1, 1: nonce, 2: pk, 3: "n", 4: [], 99: "future", 6 absent}
        let mut e = minicbor::Encoder::new(Vec::new());
        e.map(6)
            .unwrap()
            .u8(0)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&[1u8; 32])
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&[2u8; 32])
            .unwrap()
            .u8(3)
            .unwrap()
            .str("n")
            .unwrap()
            .u8(4)
            .unwrap()
            .array(0)
            .unwrap()
            .u8(99)
            .unwrap()
            .str("future")
            .unwrap();
        let bytes = e.into_writer();
        let h: Hello = decode_body(&bytes).unwrap();
        assert_eq!(h.name, "n");
        assert_eq!(h.stop_token, None);
        assert_eq!(h.pairing_state, 0);
        // A missing required key fails.
        let mut e = minicbor::Encoder::new(Vec::new());
        e.map(1).unwrap().u8(0).unwrap().u8(1).unwrap();
        assert!(matches!(
            decode_body::<Hello>(&e.into_writer()).unwrap_err(),
            BodyError::Malformed {
                kind: Kind::Hello,
                ..
            }
        ));
    }

    #[test]
    fn fixed_length_fields_are_exact() {
        for len in [0usize, 31, 33, 64] {
            let mut e = minicbor::Encoder::new(Vec::new());
            e.map(5)
                .unwrap()
                .u8(0)
                .unwrap()
                .u8(1)
                .unwrap()
                .u8(1)
                .unwrap()
                .bytes(&vec![0u8; len])
                .unwrap()
                .u8(2)
                .unwrap()
                .bytes(&[2u8; 32])
                .unwrap()
                .u8(3)
                .unwrap()
                .str("n")
                .unwrap()
                .u8(4)
                .unwrap()
                .array(0)
                .unwrap();
            let err = decode_body::<Hello>(&e.into_writer()).unwrap_err();
            assert!(matches!(err, BodyError::Malformed { .. }), "{len}: {err}");
        }
        // quic_spki must be 44 bytes, ke2 320.
        let mut a = accept();
        let mut bytes = encode_body(&a);
        // Corrupt the SPKI length byte (0x58 0x2c ⇒ 0x58 0x2b would desync; instead re-encode with 43 bytes).
        a.quic_spki = [0u8; 44];
        bytes.clear();
        let mut e = minicbor::Encoder::new(Vec::new());
        e.map(3)
            .unwrap()
            .u8(0)
            .unwrap()
            .encode(Caps::default())
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&[0u8; 43])
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(0)
            .unwrap();
        bytes.extend(e.into_writer());
        assert!(decode_body::<SessionAccept>(&bytes).is_err());
        let mut e = minicbor::Encoder::new(Vec::new());
        e.map(2)
            .unwrap()
            .u8(0)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&[0u8; 319])
            .unwrap();
        assert!(decode_body::<AuthChallenge>(&e.into_writer()).is_err());
    }

    #[test]
    fn bounds_and_conditional_fields() {
        let long_name = Hello {
            name: "x".repeat(MAX_NAME_CHARS + 1),
            ..hello()
        };
        assert_eq!(
            decode_body::<Hello>(&encode_body(&long_name)).unwrap_err(),
            BodyError::TooLong {
                kind: Kind::Hello,
                field: "name"
            }
        );
        let many_feats = Hello {
            feats: (0..MAX_FEATS + 1).map(|i| i.to_string()).collect(),
            ..hello()
        };
        assert!(decode_body::<Hello>(&encode_body(&many_feats)).is_err());
        let long_feat = Hello {
            feats: vec!["x".repeat(MAX_FEAT_CHARS + 1)],
            ..hello()
        };
        assert!(decode_body::<Hello>(&encode_body(&long_feat)).is_err());
        let exact = Hello {
            name: "é".repeat(MAX_NAME_CHARS),
            feats: vec!["12345678".to_owned(); MAX_FEATS],
            ..hello()
        };
        roundtrip(&exact);

        let long_detail = Bye {
            reason: 1,
            detail: Some("d".repeat(MAX_DETAIL_CHARS + 1)),
        };
        assert!(decode_body::<Bye>(&encode_body(&long_detail)).is_err());

        let admin_missing = SessionRequest {
            caps: Caps::default(),
            unattended: Some(UnattendedRequest {
                suite: 1,
                ke1: Some([0; 96]),
                want_mode: 0,
                intent: intent::ADMIN,
                admin: None,
                want_elevation: None,
            }),
        };
        assert!(matches!(
            decode_body::<SessionRequest>(&encode_body(&admin_missing)).unwrap_err(),
            BodyError::Inconsistent {
                field: "unattended.admin",
                ..
            }
        ));
        let admin_unexpected = SessionRequest {
            caps: Caps::default(),
            unattended: Some(UnattendedRequest {
                suite: 1,
                ke1: Some([0; 96]),
                want_mode: 0,
                intent: intent::SESSION,
                admin: Some(AdminCmd {
                    op: 1,
                    device_pk: None,
                }),
                want_elevation: None,
            }),
        };
        assert!(decode_body::<SessionRequest>(&encode_body(&admin_unexpected)).is_err());

        let mixed = AuthChallenge {
            suite: 1,
            ke2: Some([0; 320]),
            salt: Some([0; 16]),
            pb: None,
        };
        assert!(decode_body::<AuthChallenge>(&encode_body(&mixed)).is_err());
        let none = AuthResponse {
            ke3: None,
            pa: None,
            ca: None,
        };
        assert!(decode_body::<AuthResponse>(&encode_body(&none)).is_err());
        let too_many_codecs = SessionRequest {
            caps: Caps {
                codecs: vec!["c".to_owned(); MAX_CODECS + 1],
                ..Caps::default()
            },
            unattended: None,
        };
        assert!(decode_body::<SessionRequest>(&encode_body(&too_many_codecs)).is_err());

        // `ke1` iff suite 1 (§B.8.4.1); an unknown suite is the handler's
        // (`UNSUPPORTED_SUITE`) but carries no `ke1`.
        let unattended = |suite: u8, ke1: Option<[u8; 96]>| SessionRequest {
            caps: Caps::default(),
            unattended: Some(UnattendedRequest {
                suite,
                ke1,
                want_mode: 0,
                intent: intent::SESSION,
                admin: None,
                want_elevation: None,
            }),
        };
        for (suite, ke1) in [
            (suite::OPAQUE, None),
            (suite::SPAKE2, Some([0u8; 96])),
            (9, Some([0u8; 96])),
        ] {
            assert!(matches!(
                decode_body::<SessionRequest>(&encode_body(&unattended(suite, ke1))).unwrap_err(),
                BodyError::Inconsistent {
                    field: "unattended.ke1",
                    ..
                }
            ));
        }
        roundtrip(&unattended(suite::OPAQUE, Some([0u8; 96])));
        roundtrip(&unattended(suite::SPAKE2, None));
        roundtrip(&unattended(9, None));

        // Enum-valued fields outside their domain never decode as valid.
        let with = |f: fn(&mut UnattendedRequest)| {
            let mut u = UnattendedRequest {
                suite: suite::OPAQUE,
                ke1: Some([0u8; 96]),
                want_mode: mode::CONTROL,
                intent: intent::SESSION,
                admin: None,
                want_elevation: None,
            };
            f(&mut u);
            SessionRequest {
                caps: Caps::default(),
                unattended: Some(u),
            }
        };
        let field_of = |r: &SessionRequest| match decode_body::<SessionRequest>(&encode_body(r)) {
            Err(BodyError::Inconsistent { field, .. }) => field,
            other => panic!("expected Inconsistent, got {other:?}"),
        };
        assert_eq!(field_of(&with(|u| u.intent = 2)), "unattended.intent");
        assert_eq!(field_of(&with(|u| u.intent = 255)), "unattended.intent");
        assert_eq!(field_of(&with(|u| u.want_mode = 2)), "unattended.want_mode");
        assert_eq!(field_of(&with(|u| u.want_mode = 5)), "unattended.want_mode");
        roundtrip(&with(|u| u.want_mode = mode::VIEW_ONLY));
        let admin = |op: u8, device_pk: Option<[u8; 32]>| with_admin(AdminCmd { op, device_pk });
        fn with_admin(cmd: AdminCmd) -> SessionRequest {
            SessionRequest {
                caps: Caps::default(),
                unattended: Some(UnattendedRequest {
                    suite: suite::OPAQUE,
                    ke1: Some([0u8; 96]),
                    want_mode: mode::CONTROL,
                    intent: intent::ADMIN,
                    admin: Some(cmd),
                    want_elevation: None,
                }),
            }
        }
        assert_eq!(field_of(&admin(0, None)), "unattended.admin.op");
        assert_eq!(field_of(&admin(7, None)), "unattended.admin.op");
        assert_eq!(field_of(&admin(200, None)), "unattended.admin.op");
        assert_eq!(
            field_of(&admin(admin_op::REVOKE, None)),
            "unattended.admin.device_pk"
        );
        assert_eq!(
            field_of(&admin(admin_op::UNLOCK, None)),
            "unattended.admin.device_pk"
        );
        assert_eq!(
            field_of(&admin(admin_op::SUSPEND, None)),
            "unattended.admin.device_pk"
        );
        assert_eq!(
            field_of(&admin(admin_op::REVOKE_ALL, Some([1u8; 32]))),
            "unattended.admin.device_pk"
        );
        assert_eq!(
            field_of(&admin(admin_op::MASTER_OFF, Some([1u8; 32]))),
            "unattended.admin.device_pk"
        );
        assert_eq!(
            field_of(&admin(admin_op::END_SESSION, Some([1u8; 32]))),
            "unattended.admin.device_pk"
        );
        for op in [admin_op::REVOKE, admin_op::UNLOCK, admin_op::SUSPEND] {
            roundtrip(&admin(op, Some([1u8; 32])));
        }
        for op in [
            admin_op::REVOKE_ALL,
            admin_op::MASTER_OFF,
            admin_op::END_SESSION,
        ] {
            roundtrip(&admin(op, None));
        }
        assert!(AdminCmd::op_takes_device(admin_op::SUSPEND));
        assert!(!AdminCmd::op_takes_device(admin_op::END_SESSION));

        // An unknown challenge suite is refused whether or not it carries fields.
        for (ke2, salt, pb) in [
            (Some([0u8; 320]), Some([0u8; 16]), Some([0u8; 32])),
            (None, None, None),
            (Some([0u8; 320]), None, None),
        ] {
            let c = AuthChallenge {
                suite: 3,
                ke2,
                salt,
                pb,
            };
            assert!(matches!(
                decode_body::<AuthChallenge>(&encode_body(&c)).unwrap_err(),
                BodyError::Inconsistent { field: "suite", .. }
            ));
        }
    }

    #[test]
    fn wire_strings_refuse_control_and_invisible_characters() {
        let escape = Bye {
            reason: 1,
            detail: Some("\x1b[2Jcleared".to_owned()),
        };
        assert_eq!(
            decode_body::<Bye>(&encode_body(&escape)).unwrap_err(),
            BodyError::ForbiddenChar {
                kind: Kind::Bye,
                field: "detail"
            }
        );
        for bad in [
            "\x07bell",
            "a\u{202E}b",
            "tag\u{E0041}",
            "nul\0",
            "\u{9B}csi",
        ] {
            let named = Hello {
                name: bad.to_owned(),
                ..hello()
            };
            assert!(
                matches!(
                    decode_body::<Hello>(&encode_body(&named)).unwrap_err(),
                    BodyError::ForbiddenChar {
                        kind: Kind::Hello,
                        field: "name"
                    }
                ),
                "{bad:?}"
            );
            let feat = Hello {
                feats: vec![bad.chars().take(MAX_FEAT_CHARS).collect()],
                ..hello()
            };
            assert!(
                decode_body::<Hello>(&encode_body(&feat)).is_err(),
                "{bad:?}"
            );
            let c = Candidates {
                candidates: vec![bad.to_owned()],
            };
            assert!(
                decode_body::<Candidates>(&encode_body(&c)).is_err(),
                "{bad:?}"
            );
            let e = Error {
                code: 1,
                detail: Some(bad.to_owned()),
            };
            assert!(decode_body::<Error>(&encode_body(&e)).is_err(), "{bad:?}");
        }
        // Ordinary text, emoji and combining marks pass.
        roundtrip(&Bye {
            reason: 1,
            detail: Some("Ana's 🦀 café".to_owned()),
        });
        assert_eq!(
            clamp_feats(&[
                "ua1".to_owned(),
                "x\x1by".to_owned(),
                "123456789".to_owned()
            ]),
            ["ua1", "xy", "12345678"]
        );
        assert_eq!(
            clamp_feats(&vec!["f".to_owned(); MAX_FEATS + 3]).len(),
            MAX_FEATS
        );
    }

    #[test]
    fn every_feature_token_fits_the_wire_and_survives_the_clamp() {
        let all = [feats::UA1, feats::UA2, feats::SVC1];
        for (i, token) in all.iter().enumerate() {
            assert!(!token.is_empty() && token.chars().count() <= MAX_FEAT_CHARS);
            assert!(!all[..i].contains(token), "{token} is listed twice");
        }
        let owned: Vec<String> = all.iter().map(|t| (*t).to_owned()).collect();
        assert_eq!(clamp_feats(&owned), owned);
        assert!(owned.len() <= MAX_FEATS);
        // A host's HELLO_ACK with the suite and the services token round-trips.
        let ack = HelloAck {
            v: 1,
            host_nonce: [4u8; 32],
            feats: vec![feats::UA1.to_owned(), feats::SVC1.to_owned()],
        };
        assert_eq!(roundtrip(&ack).feats, ["ua1", "svc1"]);
    }

    #[test]
    fn session_accept_redacts_its_tokens() {
        let a = accept();
        let text = format!("{a:?}");
        assert!(text.contains("session_token: Some(\"..\")"), "{text}");
        assert!(text.contains("token_confirm: None"), "{text}");
        assert!(!text.contains("060606"), "{text}");
        assert!(!text.contains("[6, 6"), "{text}");
        let msg = Message::SessionAccept(a.clone());
        assert!(!format!("{msg:?}").contains("[6, 6"));
    }

    #[test]
    fn session_accept_equality_covers_every_field_including_the_tokens() {
        let a = accept();
        assert_eq!(a, a.clone());
        let mut b = accept();
        b.session_token = Some([7u8; 32]);
        assert_ne!(a, b);
        let mut b = accept();
        b.session_token = None;
        assert_ne!(a, b);
        let mut b = accept();
        b.token_confirm = Some([6u8; 32]);
        assert_ne!(a, b);
        let mut b = accept();
        b.mode = 1;
        assert_ne!(a, b);
        let mut b = accept();
        b.quic_spki = ed25519_spki(&[9u8; 32]);
        assert_ne!(a, b);
        let mut b = accept();
        b.caps.hdr = true;
        assert_ne!(a, b);
    }

    #[test]
    fn spki_matches_rfc8410_example() {
        // RFC 8410 §10.1 example public key.
        let expected = hex::decode(
            "302a300506032b6570032100\
             19bf44096b04cdfe8541bac167dc3b96c85085aa30b6b6cb0c5c38ad702166e1",
        )
        .unwrap();
        let pk: [u8; 32] = expected[12..].try_into().unwrap();
        assert_eq!(ed25519_spki(&pk).to_vec(), expected);
        assert_eq!(SPKI_LEN, 44);
    }

    #[test]
    fn code_tables_match_the_plan() {
        assert_eq!(reject::DENIED, 0x0001);
        assert_eq!(reject::POPUP_TIMEOUT, 0x0002);
        assert_eq!(reject::BUSY, 0x0003);
        assert_eq!(reject::NOT_GRANTED, 0x0010);
        assert_eq!(reject::SUSPENDED, 0x0016);
        assert_eq!(reject::AUTH_FAILED, 0x0020);
        assert_eq!(reject::COOLDOWN, 0x0029);
        assert_eq!(reject::PREEMPTED, 0x002A);
        assert_eq!(reject::name(reject::PREEMPTED), "PREEMPTED");
        assert_eq!(bye::USER, 0x01);
        assert_eq!(bye::SUSPENDED, 0x10);
        assert_eq!(bye::name(bye::ORPHANED), "ORPHANED");
        assert_eq!(pair_reject::name(pair_reject::BANNED), "BANNED");
        assert_eq!(pair_reject::name(0xffff), "UNKNOWN");
    }

    proptest! {
        #[test]
        fn decoding_random_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            for kind in Kind::ALL {
                let _ = decode_any(kind, &bytes);
            }
        }

        #[test]
        fn hello_with_random_fields_roundtrips(
            name in "[a-zA-Z0-9 ]{0,64}",
            feats in proptest::collection::vec("[a-z0-9]{1,8}", 0..=8),
            nonce in any::<[u8; 32]>(),
            stop in proptest::option::of(any::<[u8; 32]>()),
            state in any::<u8>(),
        ) {
            let h = Hello { v_max: 1, client_nonce: nonce, device_pk: [0; 32], name, feats, stop_token: stop, pairing_state: state, sas_commit: [7u8; 32] };
            let back: Hello = decode_body(&encode_body(&h)).unwrap();
            prop_assert_eq!(back, h);
        }
    }
    /// r7, §B.8.4.1: `SESSION_ACCEPT.elevation` (key 11) is 0 or 1, and 1
    /// only with control; absent reads as none. `want_elevation` (key 5 of
    /// the unattended map) is 0 or 1.
    #[test]
    fn the_elevation_keys_decode_only_in_their_domain() {
        let with = |mode: u8, elevation: Option<u8>| {
            let mut a = accept();
            a.mode = mode;
            a.elevation = elevation;
            encode_body(&a)
        };
        let field_of = |bytes: &[u8]| match decode_body::<SessionAccept>(bytes) {
            Err(BodyError::Inconsistent { field, .. }) => field,
            other => panic!("{other:?}"),
        };
        for elevation in [None, Some(elevation::NONE)] {
            for m in [mode::CONTROL, mode::VIEW_ONLY] {
                let a: SessionAccept = decode_body(&with(m, elevation)).unwrap();
                assert_eq!(a.elevation(), Elevation::None);
            }
        }
        let admin: SessionAccept = decode_body(&with(mode::CONTROL, Some(1))).unwrap();
        assert_eq!(admin.elevation(), Elevation::Admin);
        // View-only never elevated, nor a mode this build does not know.
        assert_eq!(field_of(&with(mode::VIEW_ONLY, Some(1))), "elevation");
        assert_eq!(field_of(&with(7, Some(1))), "elevation");
        for bad in [2u8, 3, 0x80, u8::MAX] {
            assert_eq!(
                field_of(&with(mode::CONTROL, Some(bad))),
                "elevation",
                "{bad}"
            );
        }
        // A value that does not fit a u8 is not an elevation either.
        let mut big = with(mode::CONTROL, None);
        big[0] += 1; // one more map entry
        big.extend_from_slice(&[0x0b, 0x19, 0x01, 0x00]); // 11: 256
        assert!(decode_body::<SessionAccept>(&big).is_err());

        let request = |want_elevation| SessionRequest {
            caps: Caps::default(),
            unattended: Some(UnattendedRequest {
                suite: suite::OPAQUE,
                ke1: Some([0u8; 96]),
                want_mode: mode::VIEW_ONLY,
                intent: intent::SESSION,
                admin: None,
                want_elevation,
            }),
        };
        // Asking for admin with view-only is lowered by the host, never a reject.
        for want in [None, Some(0), Some(1)] {
            roundtrip(&request(want));
        }
        for bad in [2u8, 9, u8::MAX] {
            assert!(
                matches!(
                    decode_body::<SessionRequest>(&encode_body(&request(Some(bad)))),
                    Err(BodyError::Inconsistent {
                        field: "unattended.want_elevation",
                        ..
                    })
                ),
                "{bad}"
            );
        }
    }

    /// An unattended accept as the client receives it: `token_confirm`, no `session_token`.
    fn unattended_accept(
        mode: u8,
        elevation: Option<u8>,
        grant_reach: Option<u8>,
    ) -> SessionAccept {
        let mut a = accept();
        a.session_type = session_type::UNATTENDED;
        a.session_token = None;
        a.token_confirm = Some([7u8; 32]);
        a.mode = mode;
        a.elevation = elevation;
        a.grant_reach = grant_reach;
        a
    }

    /// M1-67 (B), A23: `grant_reach` (key 12) decodes only in its domain. An unattended
    /// accept with `elevation = 1` and the key absent, 0 or 1; a value of 3; the key on an
    /// attended accept: each `E_BAD_LEN` (an `Inconsistent` body). The key at 1 or 2 with
    /// view only, or without `elevation`, is valid: it describes the password, not the
    /// session.
    #[test]
    fn a23_grant_reach_decodes_only_in_its_domain() {
        let field_of = |a: &SessionAccept| match decode_body::<SessionAccept>(&encode_body(a)) {
            Err(BodyError::Inconsistent { field, .. }) => field,
            other => panic!("{other:?}"),
        };
        for reach in [None, Some(0), Some(1)] {
            assert_eq!(
                field_of(&unattended_accept(mode::CONTROL, Some(1), reach)),
                "grant_reach",
                "{reach:?}"
            );
        }
        for bad in [3u8, 9, u8::MAX] {
            assert_eq!(
                field_of(&unattended_accept(mode::CONTROL, None, Some(bad))),
                "grant_reach"
            );
            let result = AdminResult {
                ok: true,
                detail: None,
                grant_reach: Some(bad),
            };
            assert!(matches!(
                decode_body::<AdminResult>(&encode_body(&result)),
                Err(BodyError::Inconsistent {
                    field: "grant_reach",
                    ..
                })
            ));
        }
        let mut attended = accept();
        attended.grant_reach = Some(0);
        assert_eq!(field_of(&attended), "grant_reach");
        for (m, elevation, reach) in [
            (mode::CONTROL, None, Some(0)),
            (mode::CONTROL, None, Some(1)),
            (mode::CONTROL, None, Some(2)),
            (mode::CONTROL, Some(1), Some(2)),
            (mode::VIEW_ONLY, None, Some(2)),
            (mode::VIEW_ONLY, None, Some(1)),
            (mode::CONTROL, None, None),
        ] {
            let a: SessionAccept =
                decode_body(&encode_body(&unattended_accept(m, elevation, reach))).unwrap();
            assert_eq!(a.grant_reach(), reach);
        }
        for reach in [None, Some(0), Some(1), Some(2)] {
            let result = AdminResult {
                ok: false,
                detail: Some("x".to_owned()),
                grant_reach: reach,
            };
            let back: AdminResult = decode_body(&encode_body(&result)).unwrap();
            assert_eq!(back.grant_reach, reach);
        }
    }

    /// A23: key 12 duplicated reads the last value; CBOR null reads as absent. Only the
    /// host signs, so neither is a check of its own (B).
    #[test]
    fn a23_a_duplicated_grant_reach_reads_the_last_and_null_reads_absent() {
        let base = encode_body(&unattended_accept(mode::CONTROL, None, None));
        let with = |entries: &[&[u8]]| {
            let mut body = base.clone();
            body[0] += u8::try_from(entries.len()).unwrap();
            for e in entries {
                body.extend_from_slice(e);
            }
            body
        };
        let twice: SessionAccept = decode_body(&with(&[&[0x0c, 0x00], &[0x0c, 0x01]])).unwrap();
        assert_eq!(twice.grant_reach(), Some(1));
        let null: SessionAccept = decode_body(&with(&[&[0x0c, 0xf6]])).unwrap();
        assert_eq!(null.grant_reach(), None);
    }

    /// M1-67 (C13), TM-9: two accepts that differ only in `grant_reach` are unequal, and
    /// neither `Debug` shows the key.
    #[test]
    fn two_accepts_differing_only_in_grant_reach_are_unequal() {
        let zero = unattended_accept(mode::CONTROL, None, Some(0));
        for other in [None, Some(1), Some(2)] {
            assert_ne!(zero, unattended_accept(mode::CONTROL, None, other));
        }
        assert_eq!(zero, unattended_accept(mode::CONTROL, None, Some(0)));
        let two = unattended_accept(mode::CONTROL, Some(1), Some(2));
        let text = format!("{two:?}");
        assert!(!text.contains("grant_reach"), "{text}");
        let result = AdminResult {
            ok: true,
            detail: None,
            grant_reach: Some(2),
        };
        let text = format!("{result:?}");
        assert!(
            !text.contains("grant_reach") && !text.contains('2'),
            "{text}"
        );
        assert_ne!(
            result,
            AdminResult {
                ok: true,
                detail: None,
                grant_reach: Some(0),
            }
        );
    }

    /// Backward compatibility (r7): a peer built before the keys decodes a
    /// body that carries them — receivers ignore unknown keys — and sees
    /// the level it always saw; a body without them reads as none here.
    /// The "old" types are the pre-r7 maps, keys 0–10 and 0–4.
    #[test]
    fn a_peer_before_the_keys_ignores_them() {
        #[derive(Debug, Decode)]
        #[cbor(map)]
        struct OldAccept {
            #[n(0)]
            caps: Caps,
            #[n(2)]
            session_type: u8,
            #[n(3)]
            mode: u8,
            #[n(5)]
            #[cbor(with = "minicbor::bytes")]
            session_token: Option<[u8; 32]>,
        }
        #[derive(Debug, Decode)]
        #[cbor(map)]
        struct OldUnattended {
            #[n(0)]
            suite: u8,
            #[n(2)]
            want_mode: u8,
            #[n(3)]
            intent: u8,
        }
        let mut admin = accept();
        admin.elevation = Some(elevation::ADMIN);
        let old: OldAccept = minicbor::decode(&encode_body(&admin)).unwrap();
        assert_eq!((old.session_type, old.mode), (0, mode::CONTROL));
        assert!(old.session_token.is_some() && old.caps == admin.caps);
        let request = UnattendedRequest {
            suite: suite::OPAQUE,
            ke1: Some([0u8; 96]),
            want_mode: mode::CONTROL,
            intent: intent::SESSION,
            admin: None,
            want_elevation: Some(elevation::ADMIN),
        };
        let old: OldUnattended = minicbor::decode(&minicbor::to_vec(&request).unwrap()).unwrap();
        assert_eq!((old.suite, old.want_mode, old.intent), (1, 0, 0));
        // Built at none, the accept is the pre-r7 map, key 11 absent.
        let none = accept();
        assert_eq!(none.elevation, None);
        assert_eq!(
            encode_body(&admin)[0],
            encode_body(&none)[0] + 1,
            "one map entry more, key 11"
        );
        let decoded: SessionAccept = decode_body(&encode_body(&none)).unwrap();
        assert_eq!(decoded.elevation(), Elevation::None);
    }
}
