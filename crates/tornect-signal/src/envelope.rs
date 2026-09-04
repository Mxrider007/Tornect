//! The signaling envelope (`docs/PLAN.md` §B.3, §B.8.4.1).
//!
//! Wire form, inside one [`crate::framing`] frame:
//!
//! ```text
//! CBOR array [v: uint, msg_id: uint, kind: uint, body: bytes, sig: bytes(64) | null]
//! ```
//!
//! The array is positional, so a verifier never re-serializes CBOR: a
//! signature (§B.8.4.3) covers the *decoded* header fields (`v`, `msg_id`,
//! `kind`) and the raw `body` bytes through [`crate::transcript::digest`],
//! while the transcript hash absorbs the exact frame bytes. Bodies are the
//! CBOR maps of [`crate::messages`].
//!
//! Decoding is strict about *shape* (definite-length array of exactly five
//! items, `sig` either absent as `null` or exactly 64 bytes) and lenient about
//! *integer encoding* (a `v` of `0x18 0x01` is still 1). A re-encoded header
//! therefore still verifies, but it changes the frame bytes and so the two
//! sides' `th`: the next signed frame fails, which is only a self-inflicted
//! abort — nothing is gained by refusing non-canonical integers. Every failure
//! maps to one of the `ERROR` codes of [`codes`].

use minicbor::data::Type;
use minicbor::decode::Decoder;
use minicbor::encode::Encoder;
use zeroize::Zeroize as _;

/// `ERROR` codes (`docs/PLAN.md` §B.8.4.1).
pub mod codes {
    /// A kind that is not allowed in the current state (strict alternation, §B.8.4.5).
    pub const E_BAD_STATE: u16 = 0x0001;
    /// A signature is missing or does not verify (§B.8.4.3). A `sig` of the
    /// wrong length is a size-fixed field of the wrong length: `E_BAD_LEN`.
    pub const E_BAD_SIG: u16 = 0x0002;
    /// `msg_id ≠ prev + 1` in this direction (§B.8.4.5).
    pub const E_BAD_MSG_ID: u16 = 0x0003;
    /// A frame longer than the limit in force.
    pub const E_TOO_LARGE: u16 = 0x0004;
    /// A `Kind` outside the §B.3 list.
    pub const E_UNKNOWN_KIND: u16 = 0x0005;
    /// Protocol version not acceptable (`HELLO` not `v = 1`, `v_max < 1`,
    /// or a later frame not carrying the negotiated version).
    pub const E_VERSION: u16 = 0x0006;
    /// A size-fixed field has the wrong length (`sig` included), a bound is
    /// exceeded, a required field is missing, an enum-valued field is outside
    /// its documented domain, or the envelope / body CBOR is malformed.
    pub const E_BAD_LEN: u16 = 0x0007;

    /// Human-readable name of an `ERROR` code, for logs and the CLI.
    #[must_use]
    pub const fn name(code: u16) -> &'static str {
        match code {
            E_BAD_STATE => "E_BAD_STATE",
            E_BAD_SIG => "E_BAD_SIG",
            E_BAD_MSG_ID => "E_BAD_MSG_ID",
            E_TOO_LARGE => "E_TOO_LARGE",
            E_UNKNOWN_KIND => "E_UNKNOWN_KIND",
            E_VERSION => "E_VERSION",
            E_BAD_LEN => "E_BAD_LEN",
            _ => "E_UNKNOWN",
        }
    }
}

/// Number of items in the envelope array.
pub const ENVELOPE_ITEMS: u64 = 5;

/// Length of an envelope signature.
pub const SIG_LEN: usize = 64;

/// Message kinds, numbered exactly as `docs/PLAN.md` §B.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Kind {
    /// Client → host, signed by the device key.
    Hello = 1,
    /// Host → client, signed by the onion identity key.
    HelloAck = 2,
    /// Client → host (unpaired peers only).
    PairRequest = 3,
    /// Host → client after the pairing consent popup.
    PairAccept = 4,
    /// Host → client.
    PairReject = 5,
    /// Client → host, signed.
    SessionRequest = 6,
    /// Host → client, signed.
    SessionAccept = 7,
    /// Host → client.
    SessionReject = 8,
    /// Host → client (unattended sessions only, §B.8.4).
    AuthChallenge = 9,
    /// Client → host (unattended sessions only).
    AuthResponse = 10,
    /// Host → client, signed; ends an admin-intent exchange.
    AdminResult = 11,
    /// Either direction after `SESSION_ACCEPT` (M2).
    Candidates = 12,
    /// Either direction after `SESSION_ACCEPT` (M2).
    CandidatesDone = 13,
    /// Either direction after `SESSION_ACCEPT` (M2).
    TorFallback = 14,
    /// Either direction after `SESSION_ACCEPT`.
    Ping = 15,
    /// Answer to `PING`.
    Pong = 16,
    /// Either direction, any time; never absorbed into the transcript.
    Bye = 17,
    /// Either direction, any time; never absorbed into the transcript.
    Error = 18,
}

impl Kind {
    /// Every kind, in wire order.
    pub const ALL: [Kind; 18] = [
        Kind::Hello,
        Kind::HelloAck,
        Kind::PairRequest,
        Kind::PairAccept,
        Kind::PairReject,
        Kind::SessionRequest,
        Kind::SessionAccept,
        Kind::SessionReject,
        Kind::AuthChallenge,
        Kind::AuthResponse,
        Kind::AdminResult,
        Kind::Candidates,
        Kind::CandidatesDone,
        Kind::TorFallback,
        Kind::Ping,
        Kind::Pong,
        Kind::Bye,
        Kind::Error,
    ];

    /// The §B.3 number.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The kind for a §B.3 number, if it is one.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Kind> {
        Some(match code {
            1 => Kind::Hello,
            2 => Kind::HelloAck,
            3 => Kind::PairRequest,
            4 => Kind::PairAccept,
            5 => Kind::PairReject,
            6 => Kind::SessionRequest,
            7 => Kind::SessionAccept,
            8 => Kind::SessionReject,
            9 => Kind::AuthChallenge,
            10 => Kind::AuthResponse,
            11 => Kind::AdminResult,
            12 => Kind::Candidates,
            13 => Kind::CandidatesDone,
            14 => Kind::TorFallback,
            15 => Kind::Ping,
            16 => Kind::Pong,
            17 => Kind::Bye,
            18 => Kind::Error,
            _ => return None,
        })
    }

    /// Upper-case ASCII name, exactly as it enters the signature input
    /// (`"tornect/v1/sig/" || name || "\0"`, §B.8.4.3).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Hello => "HELLO",
            Kind::HelloAck => "HELLO_ACK",
            Kind::PairRequest => "PAIR_REQUEST",
            Kind::PairAccept => "PAIR_ACCEPT",
            Kind::PairReject => "PAIR_REJECT",
            Kind::SessionRequest => "SESSION_REQUEST",
            Kind::SessionAccept => "SESSION_ACCEPT",
            Kind::SessionReject => "SESSION_REJECT",
            Kind::AuthChallenge => "AUTH_CHALLENGE",
            Kind::AuthResponse => "AUTH_RESPONSE",
            Kind::AdminResult => "ADMIN_RESULT",
            Kind::Candidates => "CANDIDATES",
            Kind::CandidatesDone => "CANDIDATES_DONE",
            Kind::TorFallback => "TOR_FALLBACK",
            Kind::Ping => "PING",
            Kind::Pong => "PONG",
            Kind::Bye => "BYE",
            Kind::Error => "ERROR",
        }
    }

    /// Whether the envelope of this kind carries a signature (§B.3 "Signing").
    #[must_use]
    pub const fn is_signed(self) -> bool {
        matches!(
            self,
            Kind::Hello
                | Kind::HelloAck
                | Kind::SessionRequest
                | Kind::SessionAccept
                | Kind::AdminResult
        )
    }

    /// Whether the frame belongs to the strictly alternating `HELLO` …
    /// `SESSION_ACCEPT` / `SESSION_REJECT` / `ADMIN_RESULT` window and is
    /// therefore absorbed into the transcript hash (§B.8.4.5).
    #[must_use]
    pub const fn in_handshake(self) -> bool {
        (self as u8) <= (Kind::AdminResult as u8)
    }

    /// Whether this kind closes the handshake window.
    #[must_use]
    pub const fn ends_handshake(self) -> bool {
        matches!(
            self,
            Kind::SessionAccept | Kind::SessionReject | Kind::AdminResult
        )
    }
}

impl core::fmt::Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// One signaling message as it travels inside a frame.
///
/// The body may carry a secret (the attended `session_token` of a
/// `SESSION_ACCEPT`), so `Debug` prints only its length and the signature's
/// presence, and the body is zeroized when the envelope is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Protocol version: `1` on `HELLO`, the negotiated version afterwards.
    pub v: u8,
    /// Per-direction counter starting at 1; every frame consumes one.
    pub msg_id: u64,
    /// Message kind.
    pub kind: Kind,
    /// The CBOR body (a map, see [`crate::messages`]); signed and hashed as-is.
    pub body: Vec<u8>,
    /// Ed25519 signature over the transcript (§B.8.4.3), on signed kinds.
    pub sig: Option<[u8; SIG_LEN]>,
}

impl core::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Envelope")
            .field("v", &self.v)
            .field("msg_id", &self.msg_id)
            .field("kind", &self.kind)
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .field("sig", &self.sig.as_ref().map(|_| ".."))
            .finish()
    }
}

impl Drop for Envelope {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// Why a frame is not an envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// Not a definite five-item array of the expected item types.
    #[error("malformed envelope: {0}")]
    Malformed(&'static str),
    /// `kind` is an unsigned integer outside the §B.3 list.
    #[error("unknown message kind {0}")]
    UnknownKind(u64),
    /// `sig` is a byte string of the wrong length.
    #[error("signature of {0} bytes (expected 64)")]
    BadSigLen(usize),
    /// Bytes follow the array.
    #[error("trailing bytes after the envelope")]
    Trailing,
}

impl EnvelopeError {
    /// The `ERROR` code a receiver answers with.
    #[must_use]
    pub const fn code(&self) -> u16 {
        match self {
            EnvelopeError::UnknownKind(_) => codes::E_UNKNOWN_KIND,
            EnvelopeError::Malformed(_) | EnvelopeError::BadSigLen(_) | EnvelopeError::Trailing => {
                codes::E_BAD_LEN
            }
        }
    }
}

impl Envelope {
    /// A new unsigned envelope.
    #[must_use]
    pub fn new(v: u8, msg_id: u64, kind: Kind, body: Vec<u8>) -> Self {
        Self {
            v,
            msg_id,
            kind,
            body,
            sig: None,
        }
    }

    /// Encode to the CBOR array (without the frame length prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::with_capacity(16 + self.body.len() + SIG_LEN));
        // Encoding into a `Vec` cannot fail (`encode::Error<Infallible>`);
        // the `Result`s are consumed without a branch below.
        let r = e
            .array(ENVELOPE_ITEMS)
            .and_then(|e| e.u8(self.v))
            .and_then(|e| e.u64(self.msg_id))
            .and_then(|e| e.u8(self.kind.code()))
            .and_then(|e| e.bytes(&self.body))
            .and_then(|e| match &self.sig {
                Some(sig) => e.bytes(sig),
                None => e.null(),
            });
        debug_assert!(r.is_ok(), "encoding into a Vec is infallible");
        e.into_writer()
    }

    /// Decode one frame payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let mut d = Decoder::new(bytes);
        let malformed =
            |what: &'static str| move |_: minicbor::decode::Error| EnvelopeError::Malformed(what);
        match d.array().map_err(malformed("not an array"))? {
            Some(ENVELOPE_ITEMS) => {}
            Some(_) => return Err(EnvelopeError::Malformed("array is not five items")),
            None => return Err(EnvelopeError::Malformed("indefinite-length array")),
        }
        let v = d.u8().map_err(malformed("v is not a u8"))?;
        let msg_id = d.u64().map_err(malformed("msg_id is not a u64"))?;
        let kind_code = d
            .u64()
            .map_err(malformed("kind is not an unsigned integer"))?;
        let kind = Kind::from_code(kind_code).ok_or(EnvelopeError::UnknownKind(kind_code))?;
        let body = d
            .bytes()
            .map_err(malformed("body is not a definite byte string"))?
            .to_vec();
        let sig = match d.datatype().map_err(malformed("sig is missing"))? {
            Type::Null => {
                d.null().map_err(malformed("sig"))?;
                None
            }
            Type::Bytes => {
                let raw = d
                    .bytes()
                    .map_err(malformed("sig is not a definite byte string"))?;
                let sig: [u8; SIG_LEN] = raw
                    .try_into()
                    .map_err(|_| EnvelopeError::BadSigLen(raw.len()))?;
                Some(sig)
            }
            _ => return Err(EnvelopeError::Malformed("sig is neither bytes nor null")),
        };
        if d.position() != bytes.len() {
            return Err(EnvelopeError::Trailing);
        }
        Ok(Self {
            v,
            msg_id,
            kind,
            body,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn kinds_carry_the_plan_numbers_and_names() {
        assert_eq!(Kind::Hello.code(), 1);
        assert_eq!(Kind::Error.code(), 18);
        for (i, k) in Kind::ALL.iter().enumerate() {
            assert_eq!(k.code() as usize, i + 1);
            assert_eq!(Kind::from_code(k.code().into()), Some(*k));
            assert_eq!(k.name(), k.name().to_ascii_uppercase());
            assert_eq!(k.to_string(), k.name());
        }
        assert_eq!(Kind::from_code(0), None);
        assert_eq!(Kind::from_code(19), None);
        assert_eq!(Kind::from_code(u64::MAX), None);
        assert_eq!(Kind::SessionAccept.name(), "SESSION_ACCEPT");
        let signed: Vec<Kind> = Kind::ALL
            .iter()
            .copied()
            .filter(|k| k.is_signed())
            .collect();
        assert_eq!(
            signed,
            [
                Kind::Hello,
                Kind::HelloAck,
                Kind::SessionRequest,
                Kind::SessionAccept,
                Kind::AdminResult
            ]
        );
        assert!(Kind::AdminResult.in_handshake());
        assert!(!Kind::Candidates.in_handshake());
        assert!(!Kind::Bye.in_handshake());
        assert!(Kind::SessionReject.ends_handshake());
        assert!(!Kind::PairAccept.ends_handshake());
    }

    #[test]
    fn roundtrip_with_and_without_signature() {
        let env = Envelope {
            v: 1,
            msg_id: 7,
            kind: Kind::SessionAccept,
            body: vec![0xa0],
            sig: Some([9u8; 64]),
        };
        let bytes = env.encode();
        assert_eq!(bytes[0], 0x85, "definite array of five");
        assert_eq!(Envelope::decode(&bytes).unwrap(), env);
        let unsigned = Envelope::new(1, 1, Kind::Ping, vec![0xa1, 0x00, 0x05]);
        let bytes = unsigned.encode();
        assert_eq!(*bytes.last().unwrap(), 0xf6, "null sig");
        assert_eq!(Envelope::decode(&bytes).unwrap(), unsigned);
    }

    #[test]
    fn rejects_bad_shapes() {
        // Not an array.
        assert_eq!(
            Envelope::decode(&[0xa0]).unwrap_err(),
            EnvelopeError::Malformed("not an array")
        );
        // Four items.
        assert!(matches!(
            Envelope::decode(&[0x84, 1, 1, 1, 0x40]).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));
        // Indefinite array.
        assert!(matches!(
            Envelope::decode(&[0x9f, 1, 1, 1, 0x40, 0xf6, 0xff]).unwrap_err(),
            EnvelopeError::Malformed("indefinite-length array")
        ));
        // Unknown kind.
        assert_eq!(
            Envelope::decode(&[0x85, 1, 1, 0x18, 0x63, 0x40, 0xf6]).unwrap_err(),
            EnvelopeError::UnknownKind(99)
        );
        assert_eq!(EnvelopeError::UnknownKind(99).code(), codes::E_UNKNOWN_KIND);
        // Kind zero and a negative kind.
        assert_eq!(
            Envelope::decode(&[0x85, 1, 1, 0, 0x40, 0xf6]).unwrap_err(),
            EnvelopeError::UnknownKind(0)
        );
        assert!(matches!(
            Envelope::decode(&[0x85, 1, 1, 0x20, 0x40, 0xf6]).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));
        // Body as text instead of bytes.
        assert!(matches!(
            Envelope::decode(&[0x85, 1, 1, 15, 0x60, 0xf6]).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));
        // Signature of the wrong length.
        let mut short = vec![0x85, 1, 1, 1, 0x40, 0x43];
        short.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            Envelope::decode(&short).unwrap_err(),
            EnvelopeError::BadSigLen(3)
        );
        assert_eq!(EnvelopeError::BadSigLen(3).code(), codes::E_BAD_LEN);
        // Signature as an integer.
        assert!(matches!(
            Envelope::decode(&[0x85, 1, 1, 1, 0x40, 0x05]).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));
        // Trailing bytes.
        assert_eq!(
            Envelope::decode(&[0x85, 1, 1, 15, 0x40, 0xf6, 0x00]).unwrap_err(),
            EnvelopeError::Trailing
        );
        // Truncated.
        assert!(matches!(
            Envelope::decode(&[0x85, 1, 1]).unwrap_err(),
            EnvelopeError::Malformed(_)
        ));
        // Oversized integers.
        assert!(matches!(
            Envelope::decode(&[0x85, 0x19, 0x01, 0x00, 1, 15, 0x40, 0xf6]).unwrap_err(),
            EnvelopeError::Malformed("v is not a u8")
        ));
    }

    #[test]
    fn non_canonical_integers_are_accepted() {
        // v = 1 encoded as `0x18 0x01`, msg_id as a u32: the signature covers
        // the decoded values and `th` the exact bytes, so a re-encoding only
        // desynchronizes the sender's own transcript — nothing is gained by
        // refusing it.
        let bytes = [0x85, 0x18, 0x01, 0x1a, 0, 0, 0, 2, 15, 0x40, 0xf6];
        let env = Envelope::decode(&bytes).unwrap();
        assert_eq!((env.v, env.msg_id, env.kind), (1, 2, Kind::Ping));
    }

    #[test]
    fn debug_prints_neither_body_nor_signature_bytes() {
        let env = Envelope {
            v: 1,
            msg_id: 7,
            kind: Kind::SessionAccept,
            body: vec![0xAB; 32],
            sig: Some([0xCD; 64]),
        };
        let printed = format!("{env:?}");
        assert!(printed.contains("<32 bytes>"), "{printed}");
        assert!(printed.contains("sig: Some(\"..\")"), "{printed}");
        assert!(!printed.contains("171"), "{printed}"); // 0xAB as a decimal byte
        assert!(!printed.contains("205"), "{printed}"); // 0xCD
        let unsigned = Envelope::new(1, 1, Kind::Ping, vec![]);
        assert!(format!("{unsigned:?}").contains("sig: None"));
    }

    #[test]
    fn error_code_names() {
        assert_eq!(codes::name(codes::E_BAD_SIG), "E_BAD_SIG");
        assert_eq!(codes::name(0x7777), "E_UNKNOWN");
    }

    proptest! {
        #[test]
        fn any_envelope_roundtrips(
            v in any::<u8>(),
            msg_id in any::<u64>(),
            kind_idx in 0usize..18,
            body in proptest::collection::vec(any::<u8>(), 0..300),
            sig in proptest::option::of(proptest::collection::vec(any::<u8>(), 64..=64)),
        ) {
            let env = Envelope {
                v,
                msg_id,
                kind: Kind::ALL[kind_idx],
                body,
                sig: sig.map(|s| <[u8; 64]>::try_from(s).unwrap()),
            };
            let bytes = env.encode();
            prop_assert_eq!(Envelope::decode(&bytes).unwrap(), env);
        }

        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = Envelope::decode(&bytes);
        }
    }
}
