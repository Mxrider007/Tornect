//! The Tor media stream wire format (decision M1-39): what flows on a session's
//! second onion stream (`tornect_signal::MEDIA_PORT`) once the handshake on the
//! signaling stream reached `SESSION_ACCEPT`.
//!
//! This is the vertical-slice transport. The plan's QUIC datagram format
//! (`docs/PLAN.md` §B.4: packetizer, FEC, jitter buffer) replaces the video part
//! when M2's QUIC path lands; the 16-byte input event and the bind stay.
//!
//! Every message is one frame: `u32` big-endian length of what follows, a `u8`
//! type, then the body. Bodies are hand-packed big-endian fields (§B.4 "hand-packed
//! fixed headers"), bounded by [`MAX_FRAME`]. The crate opens no sockets: the
//! helpers run over any tokio `AsyncRead`/`AsyncWrite` (an `OnionStream` in
//! production, a `duplex` pipe in tests).
//!
//! ```text
//! client → host   Bind            session_id (16 ASCII hex) · mac[32]
//! host → client   BindOk          width u32 · height u32 · codec u8 · mode u8
//! host → client   BindRefused     reason u16
//! host → client   Video           seq u32 · flags u8 · ts_ms u32 · Annex-B access unit
//! client → host   VideoAck        seq u32
//! client → host   Input           16-byte event (tornect-input)
//! client → host   KeyframeRequest —
//! either          Ping / Pong     nonce u64
//! either          Close           reason u16
//! ```
//!
//! **Binding.** The first frame on a media stream must be `Bind`, carrying
//! `HMAC-SHA256(k_bind, "tornect/v1/tor-media-bind\0" ‖ th_final)` with
//! `k_bind = HKDF-SHA256(session_token, "tornect/v1/tor-media-bind-key")`
//! ([`bind_mac`], decision M1-41); the host answers only after checking it in
//! constant time against a session it accepted on the signaling stream.
//! Nothing is captured before that (§B.6).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use zeroize::Zeroizing;

/// Largest frame accepted (type byte + body): 8 MiB fits a 4K keyframe at a
/// generous bitrate; anything larger is a protocol error, not a bigger buffer.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Largest frame a client sends (`Bind`, 49 bytes, is its biggest message).
/// The host reads the client's direction with this cap ([`read_msg_max`]), so
/// a client can make it allocate a few bytes per frame, never [`MAX_FRAME`]
/// (SLICE-A2 A2-6).
pub const MAX_CLIENT_FRAME: usize = 64;

/// Domain separator of the media-stream bind MAC.
pub const BIND_LABEL: &[u8] = b"tornect/v1/tor-media-bind\0";

/// Length of `SessionToken::session_id` (hex of 8 bytes).
pub const SESSION_ID_LEN: usize = 16;

/// Codec identifiers carried in [`Msg::BindOk`].
pub mod codec {
    /// H.264 Annex-B access units (OpenH264, constrained baseline).
    pub const H264: u8 = 1;
}

/// `Video.flags` bits.
pub mod video_flags {
    /// The access unit starts with an IDR picture.
    pub const KEYFRAME: u8 = 1;
}

/// Reasons in [`Msg::BindRefused`] and [`Msg::Close`].
pub mod reason {
    /// The session id is unknown, already bound, or the MAC does not verify.
    pub const BAD_BIND: u16 = 1;
    /// The host could not start screen capture.
    pub const CAPTURE_FAILED: u16 = 2;
    /// The host user ended the session (Stop sharing, panic key).
    pub const ENDED_BY_HOST: u16 = 3;
    /// The viewer disconnected.
    pub const ENDED_BY_VIEWER: u16 = 4;
    /// The signaling stream ended (BYE, kill switch, idle).
    pub const SESSION_OVER: u16 = 5;
    /// A malformed or unexpected frame.
    pub const PROTOCOL: u16 = 6;
    /// The video pipeline failed on the host (encoder error).
    pub const ENCODER_FAILED: u16 = 7;
}

/// Frame types.
mod ty {
    pub const BIND: u8 = 0x01;
    pub const BIND_OK: u8 = 0x02;
    pub const BIND_REFUSED: u8 = 0x03;
    pub const VIDEO: u8 = 0x10;
    pub const VIDEO_ACK: u8 = 0x11;
    pub const INPUT: u8 = 0x20;
    pub const KEYFRAME_REQUEST: u8 = 0x30;
    pub const PING: u8 = 0x40;
    pub const PONG: u8 = 0x41;
    // 0x50 `SetQuality`, 0x51 `Quality` and 0x52 `Stats` are reserved for the
    // quality presets (decision M1-74); another new message takes the next
    // free code.
    pub const CLOSE: u8 = 0x7f;
}

/// One media-stream message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// First client frame: bind this stream to an accepted session.
    Bind {
        /// `SessionToken::session_id()` (16 lowercase hex characters).
        session_id: String,
        /// [`bind_mac`] over the handshake's final transcript hash.
        mac: [u8; 32],
    },
    /// The host accepted the bind; video follows.
    ///
    /// `width` × `height` describe the first picture only. The resolution may
    /// change at any access unit, so a viewer sizes each picture from what it
    /// decodes, never from these fields (SLICE-A2 A2-4).
    BindOk {
        /// Width of the first encoded picture (a hint).
        width: u32,
        /// Height of the first encoded picture (a hint).
        height: u32,
        /// A [`codec`] value.
        codec: u8,
        /// `tornect_signal::messages::mode` (0 = control, 1 = view-only).
        mode: u8,
    },
    /// The host refused the bind; the stream closes.
    BindRefused {
        /// A [`reason`] code.
        reason: u16,
    },
    /// One encoded access unit.
    Video {
        /// Increments by one per access unit, wrapping.
        seq: u32,
        /// [`video_flags`].
        flags: u8,
        /// Host capture time, milliseconds on a wrapping host clock.
        ts_ms: u32,
        /// Annex-B H.264 access unit.
        data: Vec<u8>,
    },
    /// The client decoded (or dropped) access unit `seq`; the host's flow control.
    VideoAck {
        /// The access unit.
        seq: u32,
    },
    /// One input event (`tornect-input`, 16 bytes).
    Input([u8; 16]),
    /// The decoder lost sync; send an IDR.
    KeyframeRequest,
    /// Liveness / RTT probe.
    Ping {
        /// Echoed in the `Pong`.
        nonce: u64,
    },
    /// Answer to `Ping`.
    Pong {
        /// The ping's nonce.
        nonce: u64,
    },
    /// Orderly end.
    Close {
        /// A [`reason`] code.
        reason: u16,
    },
}

/// Wire errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// Socket failure.
    #[error("media stream I/O: {0}")]
    Io(#[from] std::io::Error),
    /// A frame larger than [`MAX_FRAME`] or shorter than its fixed fields.
    #[error("media frame of {0} bytes is out of bounds")]
    Size(usize),
    /// An unknown frame type.
    #[error("unknown media frame type 0x{0:02x}")]
    UnknownType(u8),
    /// A body that does not match its type.
    #[error("malformed {0} frame")]
    Malformed(&'static str),
}

impl Msg {
    /// Encode to one frame (length prefix included).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(16);
        let t = match self {
            Self::Bind { session_id, mac } => {
                body.extend_from_slice(session_id.as_bytes());
                body.extend_from_slice(mac);
                ty::BIND
            }
            Self::BindOk {
                width,
                height,
                codec,
                mode,
            } => {
                body.extend_from_slice(&width.to_be_bytes());
                body.extend_from_slice(&height.to_be_bytes());
                body.push(*codec);
                body.push(*mode);
                ty::BIND_OK
            }
            Self::BindRefused { reason } => {
                body.extend_from_slice(&reason.to_be_bytes());
                ty::BIND_REFUSED
            }
            Self::Video {
                seq,
                flags,
                ts_ms,
                data,
            } => {
                body.reserve(9 + data.len());
                body.extend_from_slice(&seq.to_be_bytes());
                body.push(*flags);
                body.extend_from_slice(&ts_ms.to_be_bytes());
                body.extend_from_slice(data);
                ty::VIDEO
            }
            Self::VideoAck { seq } => {
                body.extend_from_slice(&seq.to_be_bytes());
                ty::VIDEO_ACK
            }
            Self::Input(event) => {
                body.extend_from_slice(event);
                ty::INPUT
            }
            Self::KeyframeRequest => ty::KEYFRAME_REQUEST,
            Self::Ping { nonce } => {
                body.extend_from_slice(&nonce.to_be_bytes());
                ty::PING
            }
            Self::Pong { nonce } => {
                body.extend_from_slice(&nonce.to_be_bytes());
                ty::PONG
            }
            Self::Close { reason } => {
                body.extend_from_slice(&reason.to_be_bytes());
                ty::CLOSE
            }
        };
        // Every body this crate builds is far below `MAX_FRAME`; a larger one is
        // a caller bug, caught here rather than written with a wrong prefix.
        debug_assert!(body.len() < MAX_FRAME, "media frame body over MAX_FRAME");
        let len = u32::try_from(body.len() + 1).unwrap_or(u32::MAX);
        let mut out = Vec::with_capacity(5 + body.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.push(t);
        out.extend_from_slice(&body);
        out
    }

    /// Decode one frame's type byte + body (the length prefix already removed).
    pub fn decode(frame: &[u8]) -> Result<Self, ProtoError> {
        let (&t, body) = frame.split_first().ok_or(ProtoError::Size(0))?;
        let fixed = |name: &'static str, n: usize| {
            if body.len() == n {
                Ok(())
            } else {
                Err(ProtoError::Malformed(name))
            }
        };
        Ok(match t {
            ty::BIND => {
                fixed("Bind", SESSION_ID_LEN + 32)?;
                let (id, mac) = body.split_at(SESSION_ID_LEN);
                if !id.iter().all(|b| b.is_ascii_hexdigit()) {
                    return Err(ProtoError::Malformed("Bind"));
                }
                let session_id =
                    String::from_utf8(id.to_vec()).map_err(|_| ProtoError::Malformed("Bind"))?;
                let mac: [u8; 32] = mac.try_into().map_err(|_| ProtoError::Malformed("Bind"))?;
                Self::Bind { session_id, mac }
            }
            ty::BIND_OK => {
                fixed("BindOk", 10)?;
                Self::BindOk {
                    width: be_u32(&body[0..4]),
                    height: be_u32(&body[4..8]),
                    codec: body[8],
                    mode: body[9],
                }
            }
            ty::BIND_REFUSED => {
                fixed("BindRefused", 2)?;
                Self::BindRefused {
                    reason: be_u16(body),
                }
            }
            ty::VIDEO => {
                if body.len() < 9 {
                    return Err(ProtoError::Malformed("Video"));
                }
                Self::Video {
                    seq: be_u32(&body[0..4]),
                    flags: body[4],
                    ts_ms: be_u32(&body[5..9]),
                    data: body[9..].to_vec(),
                }
            }
            ty::VIDEO_ACK => {
                fixed("VideoAck", 4)?;
                Self::VideoAck { seq: be_u32(body) }
            }
            ty::INPUT => {
                let event: [u8; 16] = body
                    .try_into()
                    .map_err(|_| ProtoError::Malformed("Input"))?;
                Self::Input(event)
            }
            ty::KEYFRAME_REQUEST => {
                fixed("KeyframeRequest", 0)?;
                Self::KeyframeRequest
            }
            ty::PING => {
                fixed("Ping", 8)?;
                Self::Ping {
                    nonce: be_u64(body),
                }
            }
            ty::PONG => {
                fixed("Pong", 8)?;
                Self::Pong {
                    nonce: be_u64(body),
                }
            }
            ty::CLOSE => {
                fixed("Close", 2)?;
                Self::Close {
                    reason: be_u16(body),
                }
            }
            other => return Err(ProtoError::UnknownType(other)),
        })
    }
}

fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_be_bytes(a)
}

/// Read one message; `Ok(None)` on a clean end of stream between frames.
pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Msg>, ProtoError> {
    read_msg_max(r, MAX_FRAME).await
}

/// [`read_msg`], refusing any frame longer than `max` (clamped to
/// [`MAX_FRAME`]) before allocating for it.
pub async fn read_msg_max<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Option<Msg>, ProtoError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > max.min(MAX_FRAME) {
        return Err(ProtoError::Size(len));
    }
    let mut frame = vec![0u8; len];
    r.read_exact(&mut frame).await?;
    Msg::decode(&frame).map(Some)
}

/// Write one message and flush it (Arti buffers writes until a flush).
pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &Msg) -> Result<(), ProtoError> {
    w.write_all(&msg.encode()).await?;
    w.flush().await?;
    Ok(())
}

/// HKDF-SHA256 `info` that derives the bind key from the session token.
pub const BIND_KEY_INFO: &[u8] = b"tornect/v1/tor-media-bind-key";

/// The key the bind MAC is computed under: `HKDF-SHA256(ikm = session_token,
/// info = BIND_KEY_INFO)`, never the token itself. The token is also the QUIC
/// `BIND` exporter context (§B.6) and the seed of the session id, and
/// `tornect-signal`'s key schedule keeps it out of every HMAC key for exactly
/// that reason (decision M1-39, amended after SLICE-A2 A2-2).
fn bind_key(session_token: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(None, session_token)
        .expand(BIND_KEY_INFO, key.as_mut_slice())
        .unwrap_or_else(|_| unreachable!("32 bytes is a valid HKDF-SHA256 output length"));
    key
}

/// `HMAC-SHA256(bind_key(session_token), BIND_LABEL ‖ th_final)` — proves the
/// media stream belongs to the handshake that produced `th_final`.
#[must_use]
pub fn bind_mac(session_token: &[u8; 32], th_final: &[u8; 32]) -> [u8; 32] {
    let key = bind_key(session_token);
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_slice())
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 takes a key of any length"));
    mac.update(BIND_LABEL);
    mac.update(th_final);
    mac.finalize().into_bytes().into()
}

/// Constant-time check of a received bind MAC.
#[must_use]
pub fn bind_mac_ok(session_token: &[u8; 32], th_final: &[u8; 32], received: &[u8; 32]) -> bool {
    bool::from(bind_mac(session_token, th_final).ct_eq(received))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SLICE-A2 A2-2: the bind MAC is keyed by an HKDF subkey of the token, not
    /// the token. The expected value was computed independently (Python
    /// `hmac`/`hashlib`: RFC 5869 HKDF with an empty salt, then HMAC-SHA256).
    #[test]
    fn the_bind_mac_is_keyed_by_a_derived_subkey() {
        let (token, th) = ([0x11; 32], [0x22; 32]);
        let mac = bind_mac(&token, &th);
        let expected: [u8; 32] = [
            0x09, 0x3a, 0x5e, 0x67, 0xc5, 0x93, 0xe4, 0x62, 0x27, 0xdf, 0x8c, 0x0a, 0xbc, 0xa4,
            0x1a, 0x3c, 0x23, 0xe2, 0x73, 0x2a, 0x6e, 0x6b, 0xf4, 0xed, 0xf5, 0xe4, 0xa7, 0xb7,
            0xc4, 0x63, 0x5f, 0x57,
        ];
        assert_eq!(mac, expected);
        // Not the old construction, `HMAC(token, BIND_LABEL ‖ th_final)`.
        let mut old = Hmac::<Sha256>::new_from_slice(&token).unwrap();
        old.update(BIND_LABEL);
        old.update(&th);
        assert_ne!(mac, <[u8; 32]>::from(old.finalize().into_bytes()));
        assert!(bind_mac_ok(&token, &th, &mac));
    }

    fn samples() -> Vec<Msg> {
        vec![
            Msg::Bind {
                session_id: "0123456789abcdef".into(),
                mac: [7; 32],
            },
            Msg::BindOk {
                width: 1920,
                height: 1080,
                codec: codec::H264,
                mode: 1,
            },
            Msg::BindRefused {
                reason: reason::BAD_BIND,
            },
            Msg::Video {
                seq: u32::MAX,
                flags: video_flags::KEYFRAME,
                ts_ms: 12345,
                data: vec![0, 0, 0, 1, 0x67, 1, 2, 3],
            },
            Msg::Video {
                seq: 1,
                flags: 0,
                ts_ms: 0,
                data: Vec::new(),
            },
            Msg::VideoAck { seq: 99 },
            Msg::Input([3; 16]),
            Msg::KeyframeRequest,
            Msg::Ping { nonce: 42 },
            Msg::Pong { nonce: 42 },
            Msg::Close {
                reason: reason::ENDED_BY_VIEWER,
            },
        ]
    }

    #[test]
    fn every_message_round_trips() {
        for msg in samples() {
            let bytes = msg.encode();
            let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            assert_eq!(len, bytes.len() - 4);
            assert_eq!(Msg::decode(&bytes[4..]).unwrap(), msg);
        }
    }

    #[tokio::test]
    async fn stream_helpers_round_trip_and_report_clean_eof() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        for msg in samples() {
            write_msg(&mut a, &msg).await.unwrap();
        }
        drop(a);
        for msg in samples() {
            assert_eq!(read_msg(&mut b).await.unwrap(), Some(msg));
        }
        assert_eq!(read_msg(&mut b).await.unwrap(), None);
    }

    #[tokio::test]
    async fn oversized_and_empty_frames_are_refused_before_allocation() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(MAX_FRAME as u32 + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(read_msg(&mut b).await, Err(ProtoError::Size(_))));
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&0u32.to_be_bytes()).await.unwrap();
        assert!(matches!(read_msg(&mut b).await, Err(ProtoError::Size(0))));
    }

    /// Every message a client sends fits [`MAX_CLIENT_FRAME`], and a longer
    /// frame is refused at its length prefix.
    #[tokio::test]
    async fn the_client_cap_fits_every_client_message_and_refuses_more() {
        let client_msgs = [
            Msg::Bind {
                session_id: "0123456789abcdef".into(),
                mac: [7; 32],
            },
            Msg::VideoAck { seq: u32::MAX },
            Msg::Input([0xff; 16]),
            Msg::KeyframeRequest,
            Msg::Ping { nonce: u64::MAX },
            Msg::Pong { nonce: 1 },
            Msg::Close {
                reason: reason::ENDED_BY_VIEWER,
            },
        ];
        let (mut a, mut b) = tokio::io::duplex(4096);
        for msg in &client_msgs {
            assert!(msg.encode().len() - 4 <= MAX_CLIENT_FRAME, "{msg:?}");
            write_msg(&mut a, msg).await.unwrap();
        }
        for msg in client_msgs {
            assert_eq!(
                read_msg_max(&mut b, MAX_CLIENT_FRAME).await.unwrap(),
                Some(msg)
            );
        }
        a.write_all(&(MAX_CLIENT_FRAME as u32 + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(
            read_msg_max(&mut b, MAX_CLIENT_FRAME).await,
            Err(ProtoError::Size(n)) if n == MAX_CLIENT_FRAME + 1
        ));
    }

    #[test]
    fn malformed_bodies_are_errors_not_panics() {
        for frame in [
            vec![ty::BIND, b'x'],
            vec![ty::BIND_OK, 0, 1],
            vec![ty::VIDEO, 1, 2],
            vec![ty::INPUT, 1, 2, 3],
            vec![ty::PING],
            vec![0x99],
            Vec::new(),
        ] {
            assert!(Msg::decode(&frame).is_err(), "{frame:?}");
        }
        // Non-hex session ids are refused.
        let mut bind = vec![ty::BIND];
        bind.extend_from_slice(b"zzzzzzzzzzzzzzzz");
        bind.extend_from_slice(&[0; 32]);
        assert!(Msg::decode(&bind).is_err());
    }

    #[test]
    fn bind_mac_binds_token_and_transcript() {
        let token = [1u8; 32];
        let th = [2u8; 32];
        let mac = bind_mac(&token, &th);
        assert!(bind_mac_ok(&token, &th, &mac));
        assert!(!bind_mac_ok(&[9; 32], &th, &mac));
        assert!(!bind_mac_ok(&token, &[9; 32], &mac));
        let mut flipped = mac;
        flipped[0] ^= 1;
        assert!(!bind_mac_ok(&token, &th, &flipped));
    }
}
