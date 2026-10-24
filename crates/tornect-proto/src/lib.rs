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
//! client → host   Bind            session_id (16 ASCII hex) · mac[32] · quality u8
//! host → client   BindOk          width u32 · height u32 · codec u8 · mode u8 · QualityInfo
//! host → client   BindRefused     reason u16
//! host → client   Video           seq u32 · flags u8 · ts_ms u32 · Annex-B access unit
//! client → host   VideoAck        seq u32
//! client → host   Input           16-byte event (tornect-input)
//! client → host   KeyframeRequest —
//! either          Ping / Pong     nonce u64
//! client → host   SetQuality      quality u8
//! host → client   Quality         width u32 · height u32 · QualityInfo
//! host → client   Stats           HostStats
//! either          Close           reason u16
//!
//! QualityInfo (10 bytes)  preset u8 · max_fps u8 · kbps u32 · max_long u16 · max_short u16
//! HostStats (36 bytes)    source_width u16 · source_height u16 · frames u16 · window_ms u16 ·
//!                         grab_us · age_us · scale_us · convert_us · encode_us · send_us ·
//!                         ack_us (each u32)
//! ```
//!
//! **Quality.** The viewer names one of three [`quality`] presets in its
//! `Bind` and later in `SetQuality`; the host answers with what it applied
//! ([`QualityInfo`]) and the exact size of every picture from then on, in
//! `BindOk` and in a `Quality` sent before each size change, and reports its
//! per-stage timings in `Stats` (the quality design, §4). A preset code this
//! version does not know, and a `QualityInfo` or `HostStats` outside its
//! ranges, is a malformed frame.
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

/// Largest frame a client sends (`Bind`, 50 bytes, is its biggest message).
/// The host reads the client's direction with this cap ([`read_msg_max`]), so
/// a client can make it allocate a few bytes per frame, never [`MAX_FRAME`]
/// (SLICE-A2 A2-6).
pub const MAX_CLIENT_FRAME: usize = 64;

/// Domain separator of the media-stream bind MAC.
pub const BIND_LABEL: &[u8] = b"tornect/v1/tor-media-bind\0";

/// Length of `SessionToken::session_id` (hex of 8 bytes).
pub const SESSION_ID_LEN: usize = 16;

/// The type byte of [`Msg::Bind`], the first frame of every media stream. A
/// host that reads a frame of this type at another length than this
/// version's `Bind` can tell that the viewer runs another Tornect version
/// (the quality design, §4.7).
pub const BIND_TYPE: u8 = ty::BIND;

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

/// The quality presets a viewer names in [`Msg::Bind`] and
/// [`Msg::SetQuality`], and a host reports in [`QualityInfo::preset`]. The
/// numbers behind each preset are the host's (`tornect-session`'s `quality`
/// table, bounded by its `[media]` configuration), never the viewer's.
pub mod quality {
    /// Best quality: the sharpest picture, for the fastest link.
    pub const BEST_QUALITY: u8 = 1;
    /// Balanced, the default.
    pub const BALANCED: u8 = 2;
    /// Best performance: the quickest response, a smaller picture.
    pub const BEST_PERFORMANCE: u8 = 3;

    /// Whether `code` names a preset; any other code is a malformed frame.
    #[must_use]
    pub const fn known(code: u8) -> bool {
        matches!(code, BEST_QUALITY | BALANCED | BEST_PERFORMANCE)
    }
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
    // The quality presets (decision M1-74); another new message takes the
    // next free code.
    pub const SET_QUALITY: u8 = 0x50;
    pub const QUALITY: u8 = 0x51;
    pub const STATS: u8 = 0x52;
    pub const CLOSE: u8 = 0x7f;
}

/// What a host applies to a stream (the quality design, §4.2): the preset
/// and the numbers it stands for there. Display-only on the viewer: it never
/// sizes a buffer.
///
/// Decoding refuses a field outside its range (a malformed frame); encoding
/// writes the fields as they are, so a sender builds them from its own table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualityInfo {
    /// A [`quality`] code.
    pub preset: u8,
    /// The frame-rate cap, at least 1.
    pub max_fps: u8,
    /// The bitrate in kbit/s, at least 1.
    pub kbps: u32,
    /// The picture cap's long edge, at least 2.
    pub max_long: u16,
    /// The picture cap's short edge, from 2 to `max_long`.
    pub max_short: u16,
}

impl QualityInfo {
    /// Its size on the wire.
    pub const LEN: usize = 10;

    /// Whether every field is in its range.
    const fn valid(&self) -> bool {
        quality::known(self.preset)
            && self.max_fps >= 1
            && self.kbps >= 1
            && self.max_long >= 2
            && self.max_short >= 2
            && self.max_short <= self.max_long
    }

    fn put(&self, out: &mut Vec<u8>) {
        out.push(self.preset);
        out.push(self.max_fps);
        out.extend_from_slice(&self.kbps.to_be_bytes());
        out.extend_from_slice(&self.max_long.to_be_bytes());
        out.extend_from_slice(&self.max_short.to_be_bytes());
    }

    /// Exactly [`Self::LEN`] bytes, in range; `None` otherwise.
    fn get(b: &[u8]) -> Option<Self> {
        if b.len() != Self::LEN {
            return None;
        }
        let info = Self {
            preset: b[0],
            max_fps: b[1],
            kbps: be_u32(&b[2..6]),
            max_long: be_u16(&b[6..8]),
            max_short: be_u16(&b[8..10]),
        };
        info.valid().then_some(info)
    }
}

/// A host's per-stage timings over a window of about a second (the quality
/// design, §4.3), written just before a `Video`. Display-only on the viewer.
/// Every mean is in microseconds and saturates at `u32::MAX`; the sizes and
/// the count saturate at `u16::MAX`.
///
/// Decoding refuses a `window_ms` of 0 (a malformed frame).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostStats {
    /// The captured width.
    pub source_width: u16,
    /// The captured height.
    pub source_height: u16,
    /// Pictures sent in the window.
    pub frames: u16,
    /// The window's length in milliseconds, at least 1.
    pub window_ms: u16,
    /// Mean cost of the source producing a fresh picture (copy, pack, grab,
    /// render), without waiting for one.
    pub grab_us: u32,
    /// Mean time from a fresh picture's capture to its encode starting.
    pub age_us: u32,
    /// Mean time of fitting a picture under its cap.
    pub scale_us: u32,
    /// Mean BGRx → I420 conversion.
    pub convert_us: u32,
    /// Mean OpenH264 encode.
    pub encode_us: u32,
    /// Mean time from encoded to fully written (queue and flow control).
    pub send_us: u32,
    /// Mean time from written to its `VideoAck` (0 with none in the window).
    pub ack_us: u32,
}

impl HostStats {
    /// Its size on the wire.
    pub const LEN: usize = 36;

    fn put(&self, out: &mut Vec<u8>) {
        for v in [
            self.source_width,
            self.source_height,
            self.frames,
            self.window_ms,
        ] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        for v in [
            self.grab_us,
            self.age_us,
            self.scale_us,
            self.convert_us,
            self.encode_us,
            self.send_us,
            self.ack_us,
        ] {
            out.extend_from_slice(&v.to_be_bytes());
        }
    }

    /// Exactly [`Self::LEN`] bytes with a window of at least 1 ms; `None`
    /// otherwise.
    fn get(b: &[u8]) -> Option<Self> {
        if b.len() != Self::LEN {
            return None;
        }
        let u32_at = |i: usize| be_u32(&b[i..i + 4]);
        let stats = Self {
            source_width: be_u16(&b[0..2]),
            source_height: be_u16(&b[2..4]),
            frames: be_u16(&b[4..6]),
            window_ms: be_u16(&b[6..8]),
            grab_us: u32_at(8),
            age_us: u32_at(12),
            scale_us: u32_at(16),
            convert_us: u32_at(20),
            encode_us: u32_at(24),
            send_us: u32_at(28),
            ack_us: u32_at(32),
        };
        (stats.window_ms >= 1).then_some(stats)
    }
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
        /// The [`quality`] preset the viewer starts with. Outside the MAC: it
        /// can ask for nothing beyond the host's own caps.
        quality: u8,
    },
    /// The host accepted the bind; video follows.
    ///
    /// `width` × `height` are the exact size of the first picture; a later
    /// size is announced by [`Msg::Quality`]. The viewer still sizes each
    /// picture from what it decodes, never from these fields (SLICE-A2 A2-4).
    BindOk {
        /// Width of the first encoded picture.
        width: u32,
        /// Height of the first encoded picture.
        height: u32,
        /// A [`codec`] value.
        codec: u8,
        /// `tornect_signal::messages::mode` (0 = control, 1 = view-only).
        mode: u8,
        /// What the host applies to the stream.
        quality: QualityInfo,
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
    /// The viewer picks another preset; legal in control and view-only
    /// sessions alike.
    SetQuality {
        /// A [`quality`] code.
        quality: u8,
    },
    /// What the host applies from the next access unit on, sent when a preset
    /// is applied, before every change of the picture's size, and in answer
    /// to a pick of the preset already applied. The next access unit after a
    /// size change is an IDR at `width` × `height`.
    Quality {
        /// The exact width of every picture from the next one.
        width: u32,
        /// The exact height of every picture from the next one.
        height: u32,
        /// What the host applies.
        quality: QualityInfo,
    },
    /// The host's per-stage timings, at most about once a second.
    Stats(HostStats),
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
            Self::Bind {
                session_id,
                mac,
                quality,
            } => {
                body.extend_from_slice(session_id.as_bytes());
                body.extend_from_slice(mac);
                body.push(*quality);
                ty::BIND
            }
            Self::BindOk {
                width,
                height,
                codec,
                mode,
                quality,
            } => {
                body.extend_from_slice(&width.to_be_bytes());
                body.extend_from_slice(&height.to_be_bytes());
                body.push(*codec);
                body.push(*mode);
                quality.put(&mut body);
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
            Self::SetQuality { quality } => {
                body.push(*quality);
                ty::SET_QUALITY
            }
            Self::Quality {
                width,
                height,
                quality,
            } => {
                body.extend_from_slice(&width.to_be_bytes());
                body.extend_from_slice(&height.to_be_bytes());
                quality.put(&mut body);
                ty::QUALITY
            }
            Self::Stats(stats) => {
                stats.put(&mut body);
                ty::STATS
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
                fixed("Bind", SESSION_ID_LEN + 32 + 1)?;
                let (id, rest) = body.split_at(SESSION_ID_LEN);
                let (mac, preset) = rest.split_at(32);
                if !id.iter().all(|b| b.is_ascii_hexdigit()) || !quality::known(preset[0]) {
                    return Err(ProtoError::Malformed("Bind"));
                }
                let session_id =
                    String::from_utf8(id.to_vec()).map_err(|_| ProtoError::Malformed("Bind"))?;
                let mac: [u8; 32] = mac.try_into().map_err(|_| ProtoError::Malformed("Bind"))?;
                Self::Bind {
                    session_id,
                    mac,
                    quality: preset[0],
                }
            }
            ty::BIND_OK => {
                fixed("BindOk", 10 + QualityInfo::LEN)?;
                Self::BindOk {
                    width: be_u32(&body[0..4]),
                    height: be_u32(&body[4..8]),
                    codec: body[8],
                    mode: body[9],
                    quality: QualityInfo::get(&body[10..])
                        .ok_or(ProtoError::Malformed("BindOk"))?,
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
            ty::SET_QUALITY => {
                fixed("SetQuality", 1)?;
                if !quality::known(body[0]) {
                    return Err(ProtoError::Malformed("SetQuality"));
                }
                Self::SetQuality { quality: body[0] }
            }
            ty::QUALITY => {
                fixed("Quality", 8 + QualityInfo::LEN)?;
                Self::Quality {
                    width: be_u32(&body[0..4]),
                    height: be_u32(&body[4..8]),
                    quality: QualityInfo::get(&body[8..])
                        .ok_or(ProtoError::Malformed("Quality"))?,
                }
            }
            ty::STATS => Self::Stats(HostStats::get(body).ok_or(ProtoError::Malformed("Stats"))?),
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
    use proptest::prelude::*;

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

    /// The design's Balanced example (§4.4).
    const BALANCED_1080P: QualityInfo = QualityInfo {
        preset: quality::BALANCED,
        max_fps: 15,
        kbps: 1500,
        max_long: 1920,
        max_short: 1080,
    };

    /// The design's Best performance example (§4.4).
    const PERFORMANCE_720P: QualityInfo = QualityInfo {
        preset: quality::BEST_PERFORMANCE,
        max_fps: 20,
        kbps: 1000,
        max_long: 1280,
        max_short: 720,
    };

    /// The design's `Stats` example (§4.4).
    const STATS: HostStats = HostStats {
        source_width: 2560,
        source_height: 1440,
        frames: 15,
        window_ms: 1000,
        grab_us: 4000,
        age_us: 6200,
        scale_us: 2100,
        convert_us: 1500,
        encode_us: 9800,
        send_us: 120_000,
        ack_us: 1_100_000,
    };

    fn samples() -> Vec<Msg> {
        vec![
            Msg::Bind {
                session_id: "0123456789abcdef".into(),
                mac: [7; 32],
                quality: quality::BALANCED,
            },
            Msg::BindOk {
                width: 1920,
                height: 1080,
                codec: codec::H264,
                mode: 1,
                quality: BALANCED_1080P,
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
            Msg::SetQuality {
                quality: quality::BEST_PERFORMANCE,
            },
            Msg::Quality {
                width: 1280,
                height: 694,
                quality: PERFORMANCE_720P,
            },
            Msg::Stats(STATS),
            Msg::Stats(HostStats {
                window_ms: 1,
                ..HostStats::default()
            }),
            Msg::Stats(HostStats {
                source_width: u16::MAX,
                source_height: u16::MAX,
                frames: u16::MAX,
                window_ms: u16::MAX,
                grab_us: u32::MAX,
                age_us: u32::MAX,
                scale_us: u32::MAX,
                convert_us: u32::MAX,
                encode_us: u32::MAX,
                send_us: u32::MAX,
                ack_us: u32::MAX,
            }),
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
        let bind = Msg::Bind {
            session_id: "0123456789abcdef".into(),
            mac: [7; 32],
            quality: quality::BEST_QUALITY,
        };
        assert_eq!(bind.encode().len() - 4, 50, "the biggest client frame");
        let client_msgs = [
            bind,
            Msg::VideoAck { seq: u32::MAX },
            Msg::Input([0xff; 16]),
            Msg::KeyframeRequest,
            Msg::Ping { nonce: u64::MAX },
            Msg::Pong { nonce: 1 },
            Msg::SetQuality {
                quality: quality::BEST_QUALITY,
            },
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
            vec![ty::SET_QUALITY],
            vec![ty::QUALITY, 0, 0, 5, 0],
            vec![ty::STATS, 0],
            vec![0x99],
            vec![0x53],
            Vec::new(),
        ] {
            assert!(Msg::decode(&frame).is_err(), "{frame:?}");
        }
        // Non-hex session ids are refused.
        let mut bind = vec![ty::BIND];
        bind.extend_from_slice(b"zzzzzzzzzzzzzzzz");
        bind.extend_from_slice(&[0; 32]);
        bind.push(quality::BALANCED);
        assert!(matches!(
            Msg::decode(&bind),
            Err(ProtoError::Malformed("Bind"))
        ));
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The quality design's §4.4 vectors, written out by hand there (and
    /// checked apart from this code with Python's `struct.pack`).
    #[test]
    fn the_quality_messages_match_the_golden_vectors() {
        let bind = Msg::Bind {
            session_id: "0123456789abcdef".into(),
            mac: [7; 32],
            quality: quality::BALANCED,
        };
        let mut want = hex("00000032 01 30313233343536373839616263646566");
        want.extend_from_slice(&[7; 32]);
        want.push(0x02);
        assert_eq!(bind.encode(), want);
        let vectors = [
            (
                Msg::BindOk {
                    width: 1920,
                    height: 1080,
                    codec: codec::H264,
                    mode: 1,
                    quality: BALANCED_1080P,
                },
                "00000015 02 00000780 00000438 01 01 02 0f 000005dc 0780 0438",
            ),
            (
                Msg::SetQuality {
                    quality: quality::BEST_PERFORMANCE,
                },
                "00000002 50 03",
            ),
            (
                Msg::Quality {
                    width: 1280,
                    height: 694,
                    quality: PERFORMANCE_720P,
                },
                "00000013 51 00000500 000002b6 03 14 000003e8 0500 02d0",
            ),
            (
                Msg::Stats(STATS),
                "00000025 52 0a00 05a0 000f 03e8 00000fa0 00001838 00000834 000005dc \
                 00002648 0001d4c0 0010c8e0",
            ),
        ];
        for (msg, bytes) in vectors {
            let bytes = hex(bytes);
            assert_eq!(msg.encode(), bytes, "{msg:?}");
            assert_eq!(Msg::decode(&bytes[4..]).unwrap(), msg);
        }
        assert_eq!(Msg::decode(&want[4..]).unwrap(), bind);
        assert_eq!(BIND_TYPE, want[4], "the type byte of a Bind");
        assert_eq!((QualityInfo::LEN, HostStats::LEN), (10, 36));
    }

    #[test]
    fn only_the_three_presets_are_known() {
        let known: Vec<u8> = (0..=u8::MAX).filter(|&c| quality::known(c)).collect();
        assert_eq!(
            known,
            [
                quality::BEST_QUALITY,
                quality::BALANCED,
                quality::BEST_PERFORMANCE
            ]
        );
        assert_eq!(known, [1, 2, 3]);
    }

    /// The decoded frame of `msg`, with `edit` applied to its body bytes.
    fn edited(msg: &Msg, edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut frame = msg.encode().split_off(4);
        edit(&mut frame);
        frame
    }

    /// Preset codes 0, 4 and 255 in `Bind`, `SetQuality` and a `QualityInfo`
    /// (in `BindOk` and `Quality`) are malformed frames; 1 to 3 are not.
    #[test]
    fn an_unknown_preset_is_a_malformed_frame() {
        let samples = samples();
        let (bind, bind_ok) = (&samples[0], &samples[1]);
        let set = Msg::SetQuality {
            quality: quality::BALANCED,
        };
        let changed = Msg::Quality {
            width: 1280,
            height: 694,
            quality: PERFORMANCE_720P,
        };
        // The preset's offset in each body (the frame's type byte first).
        let cases: [(&Msg, usize, &str); 4] = [
            (bind, 1 + SESSION_ID_LEN + 32, "Bind"),
            (bind_ok, 1 + 10, "BindOk"),
            (&set, 1, "SetQuality"),
            (&changed, 1 + 8, "Quality"),
        ];
        for (msg, at, name) in cases {
            for code in [0, 4, 255] {
                let frame = edited(msg, |f| f[at] = code);
                assert!(
                    matches!(Msg::decode(&frame), Err(ProtoError::Malformed(n)) if n == name),
                    "{name} with preset {code}: {:?}",
                    Msg::decode(&frame)
                );
            }
            for code in 1..=3 {
                assert!(Msg::decode(&edited(msg, |f| f[at] = code)).is_ok());
            }
        }
    }

    /// A `QualityInfo` field outside its range makes the frame that carries
    /// it malformed; its boundaries are accepted.
    #[test]
    fn a_quality_info_out_of_range_is_malformed() {
        let refused = [
            QualityInfo {
                max_fps: 0,
                ..BALANCED_1080P
            },
            QualityInfo {
                kbps: 0,
                ..BALANCED_1080P
            },
            QualityInfo {
                max_long: 1,
                max_short: 1,
                ..BALANCED_1080P
            },
            QualityInfo {
                max_long: 1,
                ..BALANCED_1080P
            },
            QualityInfo {
                max_short: 1,
                ..BALANCED_1080P
            },
            QualityInfo {
                max_long: 1080,
                max_short: 1920,
                ..BALANCED_1080P
            },
            QualityInfo {
                max_short: 0,
                ..BALANCED_1080P
            },
        ];
        let accepted = [
            BALANCED_1080P,
            QualityInfo {
                max_fps: 1,
                kbps: 1,
                max_long: 2,
                max_short: 2,
                ..BALANCED_1080P
            },
            QualityInfo {
                preset: quality::BEST_QUALITY,
                max_fps: u8::MAX,
                kbps: u32::MAX,
                max_long: u16::MAX,
                max_short: u16::MAX,
            },
        ];
        let carriers = |info: QualityInfo| {
            [
                (
                    Msg::BindOk {
                        width: 1,
                        height: 1,
                        codec: codec::H264,
                        mode: 0,
                        quality: info,
                    },
                    "BindOk",
                ),
                (
                    Msg::Quality {
                        width: 0,
                        height: 0,
                        quality: info,
                    },
                    "Quality",
                ),
            ]
        };
        for info in refused {
            for (msg, name) in carriers(info) {
                let frame = msg.encode();
                assert!(
                    matches!(Msg::decode(&frame[4..]), Err(ProtoError::Malformed(n)) if n == name),
                    "{info:?} in {name}"
                );
            }
        }
        for info in accepted {
            for (msg, _) in carriers(info) {
                assert_eq!(Msg::decode(&msg.encode()[4..]).unwrap(), msg);
            }
        }
    }

    #[test]
    fn a_stats_window_of_zero_is_malformed() {
        let zero = Msg::Stats(HostStats {
            window_ms: 0,
            ..STATS
        });
        assert!(matches!(
            Msg::decode(&zero.encode()[4..]),
            Err(ProtoError::Malformed("Stats"))
        ));
        let zero = Msg::Stats(HostStats::default());
        assert!(matches!(
            Msg::decode(&zero.encode()[4..]),
            Err(ProtoError::Malformed("Stats"))
        ));
    }

    /// Every new or changed body one byte short or one byte long is a
    /// malformed frame of its own type.
    #[test]
    fn every_quality_body_one_byte_off_is_malformed() {
        let set = Msg::SetQuality {
            quality: quality::BALANCED,
        };
        let changed = Msg::Quality {
            width: 1280,
            height: 694,
            quality: PERFORMANCE_720P,
        };
        let stats = Msg::Stats(STATS);
        let samples = samples();
        let cases: [(&Msg, &str, usize); 5] = [
            (&samples[0], "Bind", 49),
            (&samples[1], "BindOk", 20),
            (&set, "SetQuality", 1),
            (&changed, "Quality", 18),
            (&stats, "Stats", 36),
        ];
        for (msg, name, len) in cases {
            assert_eq!(msg.encode().len(), 4 + 1 + len, "{name}'s body");
            for frame in [
                edited(msg, |f| {
                    f.pop();
                }),
                edited(msg, |f| f.push(0)),
                edited(msg, |f| f.truncate(1)),
            ] {
                assert!(
                    matches!(Msg::decode(&frame), Err(ProtoError::Malformed(n)) if n == name),
                    "{name} of {} bytes: {:?}",
                    frame.len() - 1,
                    Msg::decode(&frame)
                );
            }
        }
    }

    /// The quality design §4.7: the frames of the version before it, a
    /// 48-byte `Bind` body (no preset) and a 10-byte `BindOk` body (no
    /// `QualityInfo`), are malformed here, so mixed builds fail at the bind.
    #[test]
    fn the_previous_versions_bind_and_bind_ok_are_malformed() {
        let mut old_bind = vec![BIND_TYPE];
        old_bind.extend_from_slice(b"0123456789abcdef");
        old_bind.extend_from_slice(&[7; 32]);
        assert_eq!(old_bind.len(), 49, "the old Bind frame");
        assert!(matches!(
            Msg::decode(&old_bind),
            Err(ProtoError::Malformed("Bind"))
        ));
        let old_bind_ok = hex("02 00000780 00000438 01 01");
        assert!(matches!(
            Msg::decode(&old_bind_ok),
            Err(ProtoError::Malformed("BindOk"))
        ));
    }

    /// The committed seeds of the `media` fuzz target (`fuzz/seeds/media/`):
    /// one whole frame of each message, length prefix included, each the
    /// encoding of the message its name says.
    #[test]
    fn the_fuzz_seeds_are_one_frame_of_each_message() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/seeds/media");
        let samples = samples();
        let expected: [(&str, &Msg); 13] = [
            ("bind.bin", &samples[0]),
            ("bind-ok.bin", &samples[1]),
            ("bind-refused.bin", &samples[2]),
            ("video.bin", &samples[3]),
            ("video-ack.bin", &samples[5]),
            ("input.bin", &samples[6]),
            ("keyframe-request.bin", &samples[7]),
            ("ping.bin", &samples[8]),
            ("pong.bin", &samples[9]),
            ("set-quality.bin", &samples[10]),
            ("quality.bin", &samples[11]),
            ("stats.bin", &samples[12]),
            ("close.bin", &samples[15]),
        ];
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort_unstable();
        let mut want: Vec<&str> = expected.iter().map(|(n, _)| *n).collect();
        want.sort_unstable();
        assert_eq!(names, want);
        for (name, msg) in expected {
            let seed = std::fs::read(format!("{dir}/{name}")).unwrap();
            assert_eq!(seed, msg.encode(), "{name}");
        }
    }

    /// Any `QualityInfo` decoding accepts.
    fn valid_info() -> impl Strategy<Value = QualityInfo> {
        (1u8..=3, 1u8.., 1u32.., 2u16.., 2u16..).prop_map(|(preset, fps, kbps, a, b)| QualityInfo {
            preset,
            max_fps: fps,
            kbps,
            max_long: a.max(b),
            max_short: a.min(b),
        })
    }

    /// Any message decoding accepts.
    fn valid_msg() -> impl Strategy<Value = Msg> {
        prop_oneof![
            ("[0-9a-fA-F]{16}", any::<[u8; 32]>(), 1u8..=3).prop_map(|(session_id, mac, q)| {
                Msg::Bind {
                    session_id,
                    mac,
                    quality: q,
                }
            }),
            (
                any::<u32>(),
                any::<u32>(),
                any::<u8>(),
                any::<u8>(),
                valid_info()
            )
                .prop_map(|(width, height, codec, mode, quality)| Msg::BindOk {
                    width,
                    height,
                    codec,
                    mode,
                    quality,
                }),
            any::<u16>().prop_map(|reason| Msg::BindRefused { reason }),
            (
                any::<u32>(),
                any::<u8>(),
                any::<u32>(),
                proptest::collection::vec(any::<u8>(), 0..64)
            )
                .prop_map(|(seq, flags, ts_ms, data)| Msg::Video {
                    seq,
                    flags,
                    ts_ms,
                    data,
                }),
            any::<u32>().prop_map(|seq| Msg::VideoAck { seq }),
            any::<[u8; 16]>().prop_map(Msg::Input),
            Just(Msg::KeyframeRequest),
            any::<u64>().prop_map(|nonce| Msg::Ping { nonce }),
            any::<u64>().prop_map(|nonce| Msg::Pong { nonce }),
            (1u8..=3).prop_map(|quality| Msg::SetQuality { quality }),
            (any::<u32>(), any::<u32>(), valid_info()).prop_map(|(width, height, quality)| {
                Msg::Quality {
                    width,
                    height,
                    quality,
                }
            }),
            (any::<[u16; 4]>(), any::<[u32; 7]>(), 1u16..).prop_map(|(a, b, window_ms)| {
                Msg::Stats(HostStats {
                    source_width: a[0],
                    source_height: a[1],
                    frames: a[2],
                    window_ms,
                    grab_us: b[0],
                    age_us: b[1],
                    scale_us: b[2],
                    convert_us: b[3],
                    encode_us: b[4],
                    send_us: b[5],
                    ack_us: b[6],
                })
            }),
            any::<u16>().prop_map(|reason| Msg::Close { reason }),
        ]
    }

    proptest! {
        /// `decode` of any frame up to 128 bytes returns, never panics, and
        /// what it accepts encodes back to the same bytes.
        #[test]
        fn decoding_any_short_frame_never_panics(
            frame in proptest::collection::vec(any::<u8>(), 0..=128),
        ) {
            if let Ok(msg) = Msg::decode(&frame) {
                prop_assert_eq!(&msg.encode()[4..], &frame[..]);
            }
        }

        /// A valid message decodes back to itself, behind a length prefix
        /// that counts its type byte and body.
        #[test]
        fn valid_messages_round_trip(msg in valid_msg()) {
            let bytes = msg.encode();
            let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            prop_assert_eq!(len, bytes.len() - 4);
            prop_assert_eq!(Msg::decode(&bytes[4..]).unwrap(), msg);
        }

        /// A frame whose type is a quality message decodes only at its exact
        /// length, whatever its bytes.
        #[test]
        fn quality_frames_decode_only_at_their_length(
            t in prop_oneof![
                Just(ty::BIND),
                Just(ty::BIND_OK),
                Just(ty::SET_QUALITY),
                Just(ty::QUALITY),
                Just(ty::STATS)
            ],
            body in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let len = match t {
                ty::BIND => 49,
                ty::BIND_OK => 20,
                ty::SET_QUALITY => 1,
                ty::QUALITY => 18,
                _ => 36,
            };
            let mut frame = vec![t];
            frame.extend_from_slice(&body);
            if body.len() != len {
                prop_assert!(matches!(Msg::decode(&frame), Err(ProtoError::Malformed(_))));
            }
        }
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
