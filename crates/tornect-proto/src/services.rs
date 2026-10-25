//! The session services stream (decision M1-76, the services design §0 and
//! §3): chat, clipboard text and files on a session's third onion stream
//! (`tornect_signal::SERVICES_PORT`), beside the media stream and bound to the
//! same session by its own `Bind` MAC.
//!
//! The envelope is the media one: a `u32` big-endian length of what follows
//! (`1 ..= MAX_SERVICES_FRAME`), a `u8` type, then the body. A reader refuses a
//! larger prefix before allocating ([`read_header`]) and decides from the type
//! alone, before any body byte is read, whether the frame is decoded, skipped
//! or ends the stream ([`ty::gate`]): a frame for a service the session was
//! never granted is never decoded (the view-only guarantee, design §3.2).
//!
//! ```text
//! ty    name        dir   body
//! 0x01  Bind        C→H   session_id[16 ASCII hex] · mac[32]   (exactly 48 bytes; read at fixed size)
//! 0x02  Welcome     H→C   CBOR {0: caps u16, 1: clip_max u32, 2: file_max u64, 3: session_quota u64,
//!                               4: session_files u16, 5: chat_max u16, 6: bulk_window u32, 7: inbox tstr}
//! 0x03  Refused     H→C   reason u16
//! 0x04  Caps        H→C   CBOR {0: caps u16, 1: paused u16}
//! 0x05  ClipSwitch  C→H   CBOR {0: on bool}
//! 0x10  Chat        both  CBOR {0: text tstr}
//! 0x20  ClipStart   both  CBOR {0: seq u32, 1: len u32}
//! 0x21  ClipChunk   both  seq u32 · offset u32 · bytes[1..=16384]
//! 0x30  Offer       C→H   CBOR {0: xfer u32, 1: name tstr, 2: size u64}
//! 0x31  Accepted    H→C   CBOR {0: xfer u32, 1: name tstr}
//! 0x32  Get         C→H   CBOR {0: xfer u32, 1: handle u32}
//! 0x33  Sending     H→C   CBOR {0: xfer u32, 1: name tstr, 2: size u64}
//! 0x34  Data        both  xfer u32 · offset u64 · bytes[1..=16384]
//! 0x35  Credit      both  xfer u32 · upto u64
//! 0x36  Done        both  CBOR {0: xfer u32, 1: sha256 bstr[32]}
//! 0x37  Complete    both  CBOR {0: xfer u32}
//! 0x38  Cancel      both  CBOR {0: xfer u32, 1: reason u16}
//! 0x40  List        C→H   CBOR {0: req u32, 1: folder u32, 2: from u32}
//! 0x41  Listing     H→C   CBOR {0: req u32, 1: folder u32, 2: title tstr, 3: parent u32?,
//!                               4: [Entry], 5: next u32?, 6: truncated bool}
//! 0x42  ListFailed  H→C   CBOR {0: req u32, 1: reason u16}
//! 0x7f  Close       both  reason u16
//! ```
//!
//! Any other type is a protocol error; a new type comes only together with a
//! new [`caps`] bit. Hand-packed bodies are big-endian and exact; CBOR bodies
//! are maps with integer keys whose unknown keys are skipped. A decoded message
//! is a valid one: every bound of the design's §3.1 is checked when decoding.
//!
//! No `Debug` here prints peer-supplied text, clipboard or file bytes, or a
//! file's digest: only kinds, numbers and lengths (design §2.5).

use std::fmt;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use zeroize::{Zeroize as _, Zeroizing};

use crate::SESSION_ID_LEN;

/// Largest frame (type byte and body) in either direction. A reader refuses a
/// larger length prefix before it allocates anything for the frame.
pub const MAX_SERVICES_FRAME: usize = 65_536;

/// Most content bytes in one `ClipChunk` or `Data`.
pub const CHUNK: usize = 16_384;

/// Largest clipboard text, in UTF-8 bytes (256 KiB): `ClipStart.len` and the
/// end of every `ClipChunk` stay within it.
pub const MAX_CLIP: u32 = 262_144;

/// The `Bind` frame's length prefix: the type byte, the session id and the
/// MAC. The host reads exactly this much from an unbound stream.
pub const BIND_LEN: usize = 1 + SESSION_ID_LEN + 32;

/// Which end of the stream sent a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The viewer, which opened the stream.
    Viewer,
    /// The host, which serves it.
    Host,
}

/// Who may send a frame type ([`ty::direction`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Only the viewer (C→H).
    ToHost,
    /// Only the host (H→C).
    ToViewer,
    /// Either end.
    Both,
}

impl Dir {
    /// Whether `side` may send a frame of this direction.
    #[must_use]
    pub const fn sent_by(self, side: Side) -> bool {
        matches!(
            (self, side),
            (Self::Both, _) | (Self::ToHost, Side::Viewer) | (Self::ToViewer, Side::Host)
        )
    }
}

/// The services a session is granted, as `u16` bits (`Welcome.caps`,
/// `Caps.caps`, `Caps.paused`).
pub mod caps {
    /// Chat, in every session.
    pub const CHAT: u16 = 0x01;
    /// Clipboard text, both directions.
    pub const CLIP: u16 = 0x02;
    /// The viewer sends files into the host's inbox.
    pub const UPLOAD: u16 = 0x04;
    /// The viewer lists the host's folders and downloads files.
    pub const BROWSE: u16 = 0x08;
    /// Every bit this version knows; any other bit is a malformed frame.
    pub const ALL: u16 = CHAT | CLIP | UPLOAD | BROWSE;
    /// What a locked host pauses and what its user can turn off: everything
    /// but chat (design §2.3, §2.5).
    pub const PAUSABLE: u16 = CLIP | UPLOAD | BROWSE;
}

/// The codes of `Refused`, `Cancel`, `ListFailed` and `Close` (design §3.1).
pub mod reason {
    /// The `Bind` names no session waiting for services, or its MAC is wrong.
    pub const BAD_BIND: u16 = 1;
    /// The service was never granted in this session.
    pub const NOT_OFFERED: u16 = 2;
    /// The file is larger than the receiver takes.
    pub const TOO_LARGE: u16 = 3;
    /// The session's byte or file quota is used up.
    pub const QUOTA: u16 = 4;
    /// The receiver's disk would fall below what it keeps free.
    pub const NO_SPACE: u16 = 5;
    /// Too many transfers or listings at once.
    pub const BUSY: u16 = 6;
    /// The file name is empty once sanitised.
    pub const BAD_NAME: u16 = 7;
    /// An unknown or evicted handle, or a path that is gone.
    pub const NOT_FOUND: u16 = 8;
    /// The path is outside every place or inside a denied folder.
    pub const DENIED: u16 = 9;
    /// The handle names something that is not a regular file.
    pub const NOT_A_FILE: u16 = 10;
    /// A read or write failed.
    pub const IO: u16 = 11;
    /// The bytes received do not match the sender's length or digest.
    pub const CORRUPT: u16 = 12;
    /// The file changed length while it was read.
    pub const CHANGED: u16 = 13;
    /// The host user cancelled.
    pub const BY_HOST: u16 = 14;
    /// The viewer cancelled.
    pub const BY_VIEWER: u16 = 15;
    /// The session ended.
    pub const SESSION_OVER: u16 = 16;
    /// A malformed or unexpected frame.
    pub const PROTOCOL: u16 = 17;
    /// The host user turned the service off for this session.
    pub const TURNED_OFF: u16 = 18;
    /// The host user ended the session (kill switch, Stop sharing, panic key).
    pub const ENDED_BY_HOST: u16 = 19;
    /// The host is locked or shows a secure screen.
    pub const LOCKED: u16 = 20;
    /// Screen capture stopped, and services with it.
    pub const CAPTURE_STOPPED: u16 = 21;
    /// Capture did not go live in time.
    pub const NOT_LIVE: u16 = 22;

    /// Whether this version knows `code`. A code it does not know is still a
    /// valid frame: the peer may be newer, and the code is only shown.
    #[must_use]
    pub const fn known(code: u16) -> bool {
        matches!(code, BAD_BIND..=NOT_LIVE)
    }
}

/// Frame types, who sends each one, what each one needs, and the reader's
/// decision before a body is read (design §3.1, §3.2).
pub mod ty {
    use super::{CHUNK, Dir, MAX_SERVICES_FRAME, SESSION_ID_LEN, Side, caps, reason};

    /// The first viewer frame: bind the stream to a session.
    pub const BIND: u8 = 0x01;
    /// The host's answer to a good `Bind` once capture is live.
    pub const WELCOME: u8 = 0x02;
    /// The host's answer instead of `Welcome`; the host then closes.
    pub const REFUSED: u8 = 0x03;
    /// The caps left and the caps paused.
    pub const CAPS: u8 = 0x04;
    /// The viewer turns the clipboard on or off.
    pub const CLIP_SWITCH: u8 = 0x05;
    /// A chat message.
    pub const CHAT: u8 = 0x10;
    /// A clipboard text starts.
    pub const CLIP_START: u8 = 0x20;
    /// Bytes of a clipboard text.
    pub const CLIP_CHUNK: u8 = 0x21;
    /// The viewer offers a file.
    pub const OFFER: u8 = 0x30;
    /// The host takes an offered file.
    pub const ACCEPTED: u8 = 0x31;
    /// The viewer asks for a file.
    pub const GET: u8 = 0x32;
    /// The host sends an asked-for file.
    pub const SENDING: u8 = 0x33;
    /// Bytes of a file.
    pub const DATA: u8 = 0x34;
    /// Bytes written so far.
    pub const CREDIT: u8 = 0x35;
    /// The sender sent every byte.
    pub const DONE: u8 = 0x36;
    /// The receiver verified the file and put it in place.
    pub const COMPLETE: u8 = 0x37;
    /// Either end stops a transfer.
    pub const CANCEL: u8 = 0x38;
    /// The viewer asks for one page of a folder.
    pub const LIST: u8 = 0x40;
    /// One page of a folder.
    pub const LISTING: u8 = 0x41;
    /// A folder could not be listed.
    pub const LIST_FAILED: u8 = 0x42;
    /// Orderly end of the stream.
    pub const CLOSE: u8 = 0x7f;

    /// Every frame type, in code order.
    pub const ALL: [u8; 21] = [
        BIND,
        WELCOME,
        REFUSED,
        CAPS,
        CLIP_SWITCH,
        CHAT,
        CLIP_START,
        CLIP_CHUNK,
        OFFER,
        ACCEPTED,
        GET,
        SENDING,
        DATA,
        CREDIT,
        DONE,
        COMPLETE,
        CANCEL,
        LIST,
        LISTING,
        LIST_FAILED,
        CLOSE,
    ];

    /// Who may send a frame of type `t`; `None` for a type this version does
    /// not know.
    #[must_use]
    pub const fn direction(t: u8) -> Option<Dir> {
        Some(match t {
            BIND | CLIP_SWITCH | OFFER | GET | LIST => Dir::ToHost,
            WELCOME | REFUSED | CAPS | ACCEPTED | SENDING | LISTING | LIST_FAILED => Dir::ToViewer,
            CHAT | CLIP_START | CLIP_CHUNK | DATA | CREDIT | DONE | COMPLETE | CANCEL | CLOSE => {
                Dir::Both
            }
            _ => return None,
        })
    }

    /// The caps a frame of type `t` from `from` needs once the stream is
    /// bound; any one of them suffices, and `Some(0)` means none (`Caps`,
    /// `Close`). `None` means the frame never comes from `from` past the bind:
    /// an unknown type, the wrong direction, or a frame of the bind itself
    /// (`Bind`, `Welcome`, `Refused`), which only opens a stream.
    ///
    /// For the frames of a transfer, the cap is that of the transfer the frame
    /// moves: the viewer's `Data` is an upload, the host's a download; a
    /// `Credit` answers what the other end sends (its clipboard and its
    /// files).
    #[must_use]
    pub const fn needs(t: u8, from: Side) -> Option<u16> {
        Some(match (from, t) {
            (_, CLOSE) | (Side::Host, CAPS) => 0,
            (_, CHAT) => caps::CHAT,
            (_, CLIP_START | CLIP_CHUNK) | (Side::Viewer, CLIP_SWITCH) => caps::CLIP,
            (_, CANCEL) => caps::UPLOAD | caps::BROWSE,
            (Side::Viewer, OFFER | DATA | DONE) | (Side::Host, ACCEPTED | COMPLETE) => caps::UPLOAD,
            (Side::Viewer, GET | LIST | COMPLETE)
            | (Side::Host, SENDING | DATA | DONE | LISTING | LIST_FAILED) => caps::BROWSE,
            (Side::Viewer, CREDIT) => caps::CLIP | caps::BROWSE,
            (Side::Host, CREDIT) => caps::CLIP | caps::UPLOAD,
            _ => return None,
        })
    }

    /// The frames a locked host skips while their cap is paused: the ones that
    /// start something new (design §2.3).
    #[must_use]
    pub const fn pausable(t: u8) -> bool {
        matches!(
            t,
            OFFER | GET | LIST | CLIP_SWITCH | CLIP_START | CLIP_CHUNK
        )
    }

    /// The largest body a valid frame of type `t` has; `None` for a type this
    /// version does not know. CBOR bodies may carry keys a newer peer adds,
    /// so theirs is the frame's.
    #[must_use]
    pub const fn max_body(t: u8) -> Option<usize> {
        Some(match t {
            BIND => SESSION_ID_LEN + 32,
            REFUSED | CLOSE => 2,
            CREDIT => 12,
            CLIP_CHUNK => 8 + CHUNK,
            DATA => 12 + CHUNK,
            _ if direction(t).is_some() => MAX_SERVICES_FRAME - 1,
            _ => return None,
        })
    }

    /// What a reader does with a frame of type `t` from `from`, decided before
    /// any body byte is read (design §3.2): `granted` is the caps the stream
    /// was opened with, `off` the ones turned off since, `paused` the ones a
    /// lock pauses (the host passes its own; the viewer 0, as the host stops
    /// its own sends while paused).
    #[must_use]
    pub const fn gate(t: u8, from: Side, granted: u16, off: u16, paused: u16) -> Gate {
        let Some(needs) = needs(t, from) else {
            return Gate::Close(reason::PROTOCOL);
        };
        if needs == 0 {
            return Gate::Decode;
        }
        if needs & granted == 0 {
            return Gate::Close(reason::NOT_OFFERED);
        }
        let live = needs & granted & !off;
        if live == 0 || (matches!(from, Side::Viewer) && pausable(t) && live & !paused == 0) {
            return Gate::Skip;
        }
        Gate::Decode
    }

    /// A reader's decision for one frame ([`gate`]).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Gate {
        /// Read the body and decode it.
        Decode,
        /// Read the body into a scratch buffer and drop it, undecoded and
        /// without error: a frame in flight when its cap was turned off or
        /// paused.
        Skip,
        /// End the stream with `Close` and this reason, leaving the body
        /// unread.
        Close(u16),
    }
}

/// Services wire errors. No message carries a frame's content.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SvcError {
    /// Socket failure, or the stream ended inside a frame.
    #[error("services stream I/O: {0}")]
    Io(#[from] std::io::Error),
    /// A frame (type byte and body) of 0 bytes, or over its bound.
    #[error("services frame of {0} bytes is out of bounds")]
    Size(usize),
    /// A frame type this version does not know.
    #[error("unknown services frame type 0x{0:02x}")]
    UnknownType(u8),
    /// A body that does not match its type, or breaks one of its bounds.
    #[error("malformed {0} frame")]
    Malformed(&'static str),
}

/// The first frame of a services stream: the session it binds to and the
/// proof that the viewer holds that session's token and transcript.
#[derive(Clone, PartialEq, Eq)]
pub struct Bind {
    /// `SessionToken::session_id()`: 16 ASCII hex characters.
    pub session_id: String,
    /// The services bind MAC over the handshake's final transcript hash.
    pub mac: [u8; 32],
}

impl fmt::Debug for Bind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bind")
            .field("session_id", &self.session_id)
            .field("mac", &"<redacted>")
            .finish()
    }
}

impl Bind {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.session_id.as_bytes());
        out.extend_from_slice(&self.mac);
    }

    /// Exactly 48 bytes, the id ASCII hex; `None` otherwise.
    fn get(body: &[u8]) -> Option<Self> {
        if body.len() != SESSION_ID_LEN + 32 {
            return None;
        }
        let (id, mac) = body.split_at(SESSION_ID_LEN);
        if !id.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        Some(Self {
            session_id: String::from_utf8(id.to_vec()).ok()?,
            mac: mac.try_into().ok()?,
        })
    }
}

/// One services message.
#[derive(Clone, PartialEq, Eq)]
pub enum SvcMsg {
    /// The viewer binds the stream to a session.
    Bind(Bind),
    /// The host refuses the bind or the services; it closes after this.
    Refused {
        /// A [`reason`] code.
        reason: u16,
    },
    /// Bytes of clipboard text `seq`, contiguous from 0; the text is complete
    /// when `offset` plus the bytes reach its `ClipStart.len`.
    ClipChunk {
        /// The text's `ClipStart.seq`.
        seq: u32,
        /// Where these bytes start in the text.
        offset: u32,
        /// `1..=CHUNK` bytes, ending at most at [`MAX_CLIP`]; wiped on drop.
        bytes: Zeroizing<Vec<u8>>,
    },
    /// Bytes of a file, contiguous from 0.
    Data {
        /// The transfer, never 0.
        xfer: u32,
        /// The bytes of this transfer sent before these.
        offset: u64,
        /// `1..=CHUNK` bytes.
        bytes: Vec<u8>,
    },
    /// The bytes of a transfer the receiver has written so far, which open
    /// the sender's window again.
    Credit {
        /// The transfer; 0 counts the sender's clipboard bytes.
        xfer: u32,
        /// Bytes written so far.
        upto: u64,
    },
    /// Orderly end of the stream.
    Close {
        /// A [`reason`] code.
        reason: u16,
    },
}

/// Prints the kind and the numbers of a message, never its text, bytes or
/// digest.
impl fmt::Debug for SvcMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(bind) => fmt::Debug::fmt(bind, f),
            Self::Refused { reason } => f.debug_struct("Refused").field("reason", reason).finish(),
            Self::ClipChunk { seq, offset, bytes } => f
                .debug_struct("ClipChunk")
                .field("seq", seq)
                .field("offset", offset)
                .field("bytes", &bytes.len())
                .finish(),
            Self::Data {
                xfer,
                offset,
                bytes,
            } => f
                .debug_struct("Data")
                .field("xfer", xfer)
                .field("offset", offset)
                .field("bytes", &bytes.len())
                .finish(),
            Self::Credit { xfer, upto } => f
                .debug_struct("Credit")
                .field("xfer", xfer)
                .field("upto", upto)
                .finish(),
            Self::Close { reason } => f.debug_struct("Close").field("reason", reason).finish(),
        }
    }
}

impl SvcMsg {
    /// The frame type of this message.
    #[must_use]
    pub const fn ty(&self) -> u8 {
        match self {
            Self::Bind(_) => ty::BIND,
            Self::Refused { .. } => ty::REFUSED,
            Self::ClipChunk { .. } => ty::CLIP_CHUNK,
            Self::Data { .. } => ty::DATA,
            Self::Credit { .. } => ty::CREDIT,
            Self::Close { .. } => ty::CLOSE,
        }
    }

    /// Check every bound of the message's frame (design §3.1); [`Self::decode`]
    /// returns only messages that pass.
    pub fn validate(&self) -> Result<(), SvcError> {
        let ok = match self {
            Self::Bind(bind) => {
                bind.session_id.len() == SESSION_ID_LEN
                    && bind.session_id.bytes().all(|b| b.is_ascii_hexdigit())
            }
            Self::ClipChunk { offset, bytes, .. } => {
                (1..=CHUNK).contains(&bytes.len())
                    && u64::from(*offset) + bytes.len() as u64 <= u64::from(MAX_CLIP)
            }
            Self::Data {
                xfer,
                offset,
                bytes,
            } => {
                *xfer != 0
                    && (1..=CHUNK).contains(&bytes.len())
                    && offset.checked_add(bytes.len() as u64).is_some()
            }
            Self::Refused { .. } | Self::Credit { .. } | Self::Close { .. } => true,
        };
        if ok {
            Ok(())
        } else {
            Err(SvcError::Malformed(self.name()))
        }
    }

    /// The message's name in errors.
    const fn name(&self) -> &'static str {
        name(self.ty())
    }

    /// Encode to one frame, length prefix included.
    ///
    /// A clipboard frame holds clipboard text: [`write_msg`] wipes it after
    /// writing, and a caller that keeps the bytes should too.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.validate().is_ok(),
            "{self:?} breaks a bound of its frame"
        );
        let mut out = Vec::with_capacity(5 + 16);
        out.extend_from_slice(&[0; 4]);
        out.push(self.ty());
        match self {
            Self::Bind(bind) => bind.put(&mut out),
            Self::Refused { reason } | Self::Close { reason } => {
                out.extend_from_slice(&reason.to_be_bytes());
            }
            Self::ClipChunk { seq, offset, bytes } => {
                out.reserve(8 + bytes.len());
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Self::Data {
                xfer,
                offset,
                bytes,
            } => {
                out.reserve(12 + bytes.len());
                out.extend_from_slice(&xfer.to_be_bytes());
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Self::Credit { xfer, upto } => {
                out.extend_from_slice(&xfer.to_be_bytes());
                out.extend_from_slice(&upto.to_be_bytes());
            }
        }
        debug_assert!(
            out.len() - 4 <= MAX_SERVICES_FRAME,
            "services frame over MAX_SERVICES_FRAME"
        );
        let len = u32::try_from(out.len() - 4).unwrap_or(u32::MAX);
        out[..4].copy_from_slice(&len.to_be_bytes());
        out
    }

    /// Decode the body of a frame of type `t` (the prefix and the type byte
    /// already read), checking every bound of the frame.
    pub fn decode(t: u8, body: &[u8]) -> Result<Self, SvcError> {
        let malformed = || SvcError::Malformed(name(t));
        let exact = |n: usize| {
            if body.len() == n {
                Ok(())
            } else {
                Err(malformed())
            }
        };
        let msg = match t {
            ty::BIND => Self::Bind(Bind::get(body).ok_or_else(malformed)?),
            ty::REFUSED => {
                exact(2)?;
                Self::Refused {
                    reason: be_u16(body),
                }
            }
            ty::CLIP_CHUNK => {
                let (head, bytes) = body.split_at_checked(8).ok_or_else(malformed)?;
                Self::ClipChunk {
                    seq: be_u32(&head[..4]),
                    offset: be_u32(&head[4..]),
                    bytes: Zeroizing::new(bytes.to_vec()),
                }
            }
            ty::DATA => {
                let (head, bytes) = body.split_at_checked(12).ok_or_else(malformed)?;
                Self::Data {
                    xfer: be_u32(&head[..4]),
                    offset: be_u64(&head[4..]),
                    bytes: bytes.to_vec(),
                }
            }
            ty::CREDIT => {
                exact(12)?;
                Self::Credit {
                    xfer: be_u32(&body[..4]),
                    upto: be_u64(&body[4..]),
                }
            }
            ty::CLOSE => {
                exact(2)?;
                Self::Close {
                    reason: be_u16(body),
                }
            }
            other if ty::direction(other).is_some() => return Err(malformed()),
            other => return Err(SvcError::UnknownType(other)),
        };
        msg.validate()?;
        Ok(msg)
    }
}

/// The name of frame type `t` in errors.
const fn name(t: u8) -> &'static str {
    match t {
        ty::BIND => "Bind",
        ty::WELCOME => "Welcome",
        ty::REFUSED => "Refused",
        ty::CAPS => "Caps",
        ty::CLIP_SWITCH => "ClipSwitch",
        ty::CHAT => "Chat",
        ty::CLIP_START => "ClipStart",
        ty::CLIP_CHUNK => "ClipChunk",
        ty::OFFER => "Offer",
        ty::ACCEPTED => "Accepted",
        ty::GET => "Get",
        ty::SENDING => "Sending",
        ty::DATA => "Data",
        ty::CREDIT => "Credit",
        ty::DONE => "Done",
        ty::COMPLETE => "Complete",
        ty::CANCEL => "Cancel",
        ty::LIST => "List",
        ty::LISTING => "Listing",
        ty::LIST_FAILED => "ListFailed",
        ty::CLOSE => "Close",
        _ => "unknown",
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

/// A frame's type and the length of its body, read before the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The frame type (any byte: the reader gates it with [`ty::gate`]).
    pub ty: u8,
    /// The body's length, `0..MAX_SERVICES_FRAME`.
    pub len: usize,
}

/// Read the next frame's length prefix and type byte. `Ok(None)` when the
/// stream ends cleanly between frames; a stream that ends inside the 5 bytes
/// is an I/O error. A prefix of 0 or over [`MAX_SERVICES_FRAME`] is refused
/// before the type byte is read.
pub async fn read_header<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Header>, SvcError> {
    let mut prefix = [0u8; 4];
    let first = r.read(&mut prefix).await?;
    if first == 0 {
        return Ok(None);
    }
    r.read_exact(&mut prefix[first..]).await?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > MAX_SERVICES_FRAME {
        return Err(SvcError::Size(len));
    }
    let mut t = [0u8; 1];
    r.read_exact(&mut t).await?;
    Ok(Some(Header {
        ty: t[0],
        len: len - 1,
    }))
}

/// Read the body `header` announces, refusing one longer than `max` (for
/// example [`ty::max_body`] of its type) before allocating. The buffer is
/// wiped when dropped: a body may hold clipboard text.
pub async fn read_body_max<R: AsyncRead + Unpin>(
    r: &mut R,
    header: Header,
    max: usize,
) -> Result<Zeroizing<Vec<u8>>, SvcError> {
    if header.len > max.min(MAX_SERVICES_FRAME - 1) {
        return Err(SvcError::Size(header.len + 1));
    }
    let mut body = Zeroizing::new(vec![0u8; header.len]);
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Read the body `header` announces through `scratch` and drop it, undecoded
/// ([`ty::Gate::Skip`]). Allocates nothing; `scratch` is wiped afterwards.
pub async fn skip_body<R: AsyncRead + Unpin>(
    r: &mut R,
    header: Header,
    scratch: &mut [u8],
) -> Result<(), SvcError> {
    let mut spare = [0u8; 64];
    let buf = if scratch.is_empty() {
        &mut spare[..]
    } else {
        scratch
    };
    let mut left = header.len;
    while left > 0 {
        let n = left.min(buf.len());
        r.read_exact(&mut buf[..n]).await?;
        left -= n;
    }
    buf.zeroize();
    Ok(())
}

/// Read a services stream's first frame, which must be a `Bind`, at its
/// fixed size: a prefix other than [`BIND_LEN`] is refused unread, so an
/// unbound stream makes the host read 53 bytes at most.
pub async fn read_bind<R: AsyncRead + Unpin>(r: &mut R) -> Result<Bind, SvcError> {
    let mut prefix = [0u8; 4];
    r.read_exact(&mut prefix).await?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len != BIND_LEN {
        return Err(SvcError::Size(len));
    }
    let mut frame = [0u8; BIND_LEN];
    r.read_exact(&mut frame).await?;
    if frame[0] != ty::BIND {
        return Err(SvcError::Malformed("Bind"));
    }
    Bind::get(&frame[1..]).ok_or(SvcError::Malformed("Bind"))
}

/// Write one message and flush it (Arti buffers writes until a flush). The
/// encoded frame is wiped once written.
pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &SvcMsg) -> Result<(), SvcError> {
    let frame = Zeroizing::new(msg.encode());
    w.write_all(&frame).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ty::Gate;
    use super::*;
    use proptest::prelude::*;

    pub(super) fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn bind() -> SvcMsg {
        SvcMsg::Bind(Bind {
            session_id: "0123456789abcdef".into(),
            mac: [7; 32],
        })
    }

    /// One message of each kind, with the bounds at their limits.
    pub(super) fn samples() -> Vec<SvcMsg> {
        vec![
            bind(),
            SvcMsg::Refused {
                reason: reason::NOT_LIVE,
            },
            SvcMsg::ClipChunk {
                seq: 3,
                offset: 0,
                bytes: Zeroizing::new(b"hello".to_vec()),
            },
            SvcMsg::ClipChunk {
                seq: u32::MAX,
                offset: MAX_CLIP - CHUNK as u32,
                bytes: Zeroizing::new(vec![0xa5; CHUNK]),
            },
            SvcMsg::Data {
                xfer: 1,
                offset: 0,
                bytes: vec![1, 2, 3],
            },
            SvcMsg::Data {
                xfer: u32::MAX,
                offset: u64::MAX - CHUNK as u64,
                bytes: vec![0x5a; CHUNK],
            },
            SvcMsg::Credit { xfer: 0, upto: 0 },
            SvcMsg::Credit {
                xfer: 9,
                upto: u64::MAX,
            },
            SvcMsg::Close {
                reason: reason::CAPTURE_STOPPED,
            },
        ]
    }

    /// Read one frame back the way a reader does, ungated.
    pub(super) async fn read_one<R: AsyncRead + Unpin>(
        r: &mut R,
    ) -> Result<Option<SvcMsg>, SvcError> {
        let Some(header) = read_header(r).await? else {
            return Ok(None);
        };
        let max = ty::max_body(header.ty).ok_or(SvcError::UnknownType(header.ty))?;
        let body = read_body_max(r, header, max).await?;
        SvcMsg::decode(header.ty, &body).map(Some)
    }

    #[test]
    fn every_message_round_trips() {
        for msg in samples() {
            let bytes = msg.encode();
            let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            assert_eq!(len, bytes.len() - 4, "{msg:?}");
            assert!(len <= MAX_SERVICES_FRAME);
            assert_eq!(bytes[4], msg.ty());
            assert!(
                bytes.len() - 5 <= ty::max_body(msg.ty()).unwrap(),
                "{msg:?}"
            );
            assert_eq!(SvcMsg::decode(bytes[4], &bytes[5..]).unwrap(), msg);
        }
    }

    /// The hand-packed frames byte for byte, written out by hand from the
    /// design's §3.1 table (and checked apart from this code with Python's
    /// `struct.pack('>IB16s32s', 49, 1, ...)`, `'>IBH'`, `'>IBII'`, `'>IBIQ'`).
    #[test]
    fn the_hand_packed_frames_match_the_golden_vectors() {
        let mut want = hex("00000031 01 30313233343536373839616263646566");
        want.extend_from_slice(&[7; 32]);
        assert_eq!(bind().encode(), want);
        assert_eq!(want.len(), 4 + BIND_LEN);
        let vectors = [
            (
                SvcMsg::Refused {
                    reason: reason::BAD_BIND,
                },
                "00000003 03 0001",
            ),
            (
                SvcMsg::ClipChunk {
                    seq: 0x0102_0304,
                    offset: 0x10,
                    bytes: Zeroizing::new(b"ab".to_vec()),
                },
                "0000000b 21 01020304 00000010 6162",
            ),
            (
                SvcMsg::Data {
                    xfer: 2,
                    offset: 0x0000_0001_0000_0000,
                    bytes: vec![0xff],
                },
                "0000000e 34 00000002 0000000100000000 ff",
            ),
            (
                SvcMsg::Credit {
                    xfer: 0,
                    upto: 262_144,
                },
                "0000000d 35 00000000 0000000000040000",
            ),
            (
                SvcMsg::Close {
                    reason: reason::PROTOCOL,
                },
                "00000003 7f 0011",
            ),
        ];
        for (msg, bytes) in vectors {
            let bytes = hex(bytes);
            assert_eq!(msg.encode(), bytes, "{msg:?}");
            assert_eq!(SvcMsg::decode(bytes[4], &bytes[5..]).unwrap(), msg);
        }
    }

    #[test]
    fn the_codes_are_the_designs() {
        assert_eq!(
            ty::ALL,
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x20, 0x21, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                0x36, 0x37, 0x38, 0x40, 0x41, 0x42, 0x7f
            ]
        );
        assert_eq!(
            [caps::CHAT, caps::CLIP, caps::UPLOAD, caps::BROWSE],
            [1, 2, 4, 8]
        );
        assert_eq!((caps::ALL, caps::PAUSABLE), (0x0f, 0x0e));
        let reasons = [
            reason::BAD_BIND,
            reason::NOT_OFFERED,
            reason::TOO_LARGE,
            reason::QUOTA,
            reason::NO_SPACE,
            reason::BUSY,
            reason::BAD_NAME,
            reason::NOT_FOUND,
            reason::DENIED,
            reason::NOT_A_FILE,
            reason::IO,
            reason::CORRUPT,
            reason::CHANGED,
            reason::BY_HOST,
            reason::BY_VIEWER,
            reason::SESSION_OVER,
            reason::PROTOCOL,
            reason::TURNED_OFF,
            reason::ENDED_BY_HOST,
            reason::LOCKED,
            reason::CAPTURE_STOPPED,
            reason::NOT_LIVE,
        ];
        assert_eq!(reasons.to_vec(), (1..=22).collect::<Vec<u16>>());
        assert!(reasons.iter().all(|&r| reason::known(r)));
        assert!(!reason::known(0) && !reason::known(23) && !reason::known(u16::MAX));
        assert_eq!(
            (MAX_SERVICES_FRAME, CHUNK, MAX_CLIP, BIND_LEN),
            (65_536, 16_384, 262_144, 49)
        );
    }

    /// The direction table: exactly the 21 types of the design, each with the
    /// sender the design names, and nothing else.
    #[test]
    fn the_direction_table_is_complete() {
        use Dir::{Both, ToHost, ToViewer};
        let want = [
            (ty::BIND, ToHost),
            (ty::WELCOME, ToViewer),
            (ty::REFUSED, ToViewer),
            (ty::CAPS, ToViewer),
            (ty::CLIP_SWITCH, ToHost),
            (ty::CHAT, Both),
            (ty::CLIP_START, Both),
            (ty::CLIP_CHUNK, Both),
            (ty::OFFER, ToHost),
            (ty::ACCEPTED, ToViewer),
            (ty::GET, ToHost),
            (ty::SENDING, ToViewer),
            (ty::DATA, Both),
            (ty::CREDIT, Both),
            (ty::DONE, Both),
            (ty::COMPLETE, Both),
            (ty::CANCEL, Both),
            (ty::LIST, ToHost),
            (ty::LISTING, ToViewer),
            (ty::LIST_FAILED, ToViewer),
            (ty::CLOSE, Both),
        ];
        for t in 0..=u8::MAX {
            let expected = want.iter().find(|(w, _)| *w == t).map(|(_, d)| *d);
            assert_eq!(ty::direction(t), expected, "type 0x{t:02x}");
            assert_eq!(ty::max_body(t).is_some(), expected.is_some(), "0x{t:02x}");
        }
        assert!(ToHost.sent_by(Side::Viewer) && !ToHost.sent_by(Side::Host));
        assert!(ToViewer.sent_by(Side::Host) && !ToViewer.sent_by(Side::Viewer));
        assert!(Both.sent_by(Side::Host) && Both.sent_by(Side::Viewer));
    }

    /// The needs table: the host's column is the design's §3.2 table, the
    /// viewer's its mirror; a frame from the wrong side, a bind frame past
    /// the bind and an unknown type need "never".
    #[test]
    fn the_needs_table_is_complete() {
        use caps::{BROWSE, CHAT, CLIP, UPLOAD};
        // (type, from the viewer, from the host)
        let want: [(u8, Option<u16>, Option<u16>); 21] = [
            (ty::BIND, None, None),
            (ty::WELCOME, None, None),
            (ty::REFUSED, None, None),
            (ty::CAPS, None, Some(0)),
            (ty::CLIP_SWITCH, Some(CLIP), None),
            (ty::CHAT, Some(CHAT), Some(CHAT)),
            (ty::CLIP_START, Some(CLIP), Some(CLIP)),
            (ty::CLIP_CHUNK, Some(CLIP), Some(CLIP)),
            (ty::OFFER, Some(UPLOAD), None),
            (ty::ACCEPTED, None, Some(UPLOAD)),
            (ty::GET, Some(BROWSE), None),
            (ty::SENDING, None, Some(BROWSE)),
            (ty::DATA, Some(UPLOAD), Some(BROWSE)),
            (ty::CREDIT, Some(CLIP | BROWSE), Some(CLIP | UPLOAD)),
            (ty::DONE, Some(UPLOAD), Some(BROWSE)),
            (ty::COMPLETE, Some(BROWSE), Some(UPLOAD)),
            (ty::CANCEL, Some(UPLOAD | BROWSE), Some(UPLOAD | BROWSE)),
            (ty::LIST, Some(BROWSE), None),
            (ty::LISTING, None, Some(BROWSE)),
            (ty::LIST_FAILED, None, Some(BROWSE)),
            (ty::CLOSE, Some(0), Some(0)),
        ];
        for t in 0..=u8::MAX {
            let (viewer, host) = want
                .iter()
                .find(|(w, ..)| *w == t)
                .map_or((None, None), |&(_, v, h)| (v, h));
            assert_eq!(
                ty::needs(t, Side::Viewer),
                viewer,
                "0x{t:02x} from the viewer"
            );
            assert_eq!(ty::needs(t, Side::Host), host, "0x{t:02x} from the host");
            // A side sends past the bind only what its direction allows.
            for (side, needs) in [(Side::Viewer, viewer), (Side::Host, host)] {
                if needs.is_some() {
                    assert!(ty::direction(t).unwrap().sent_by(side), "0x{t:02x}");
                }
                assert_eq!(needs.unwrap_or(0) & !caps::ALL, 0);
            }
        }
    }

    /// The gate's rules in the design's §3.2 order, for every type, side and
    /// cap set.
    #[test]
    fn the_gate_follows_the_rules_in_order() {
        for t in 0..=u8::MAX {
            for from in [Side::Viewer, Side::Host] {
                for granted in 0..=caps::ALL {
                    for off in 0..=caps::ALL {
                        for paused in [0, caps::PAUSABLE, caps::CLIP, caps::UPLOAD] {
                            let gate = ty::gate(t, from, granted, off, paused);
                            let expected = match ty::needs(t, from) {
                                None => Gate::Close(reason::PROTOCOL),
                                Some(0) => Gate::Decode,
                                Some(n) if n & granted == 0 => Gate::Close(reason::NOT_OFFERED),
                                Some(n) if n & granted & !off == 0 => Gate::Skip,
                                Some(n)
                                    if from == Side::Viewer
                                        && ty::pausable(t)
                                        && n & granted & !off & !paused == 0 =>
                                {
                                    Gate::Skip
                                }
                                Some(_) => Gate::Decode,
                            };
                            assert_eq!(
                                gate, expected,
                                "0x{t:02x} {from:?} {granted} {off} {paused}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// The design's view-only guarantee: with only `CHAT` granted, every
    /// clipboard and file frame from the viewer ends the stream with
    /// `NOT_OFFERED`, chat and the stream's own frames are decoded.
    #[test]
    fn a_view_only_stream_decodes_only_chat() {
        let gate = |t| ty::gate(t, Side::Viewer, caps::CHAT, 0, 0);
        for t in [
            ty::CLIP_SWITCH,
            ty::CLIP_START,
            ty::CLIP_CHUNK,
            ty::OFFER,
            ty::GET,
            ty::LIST,
            ty::DATA,
            ty::CREDIT,
            ty::CANCEL,
            ty::DONE,
            ty::COMPLETE,
        ] {
            assert_eq!(gate(t), Gate::Close(reason::NOT_OFFERED), "0x{t:02x}");
        }
        assert_eq!(gate(ty::CHAT), Gate::Decode);
        assert_eq!(gate(ty::CLOSE), Gate::Decode);
        for t in [
            ty::BIND,
            ty::WELCOME,
            ty::CAPS,
            ty::LISTING,
            0x06,
            0x7e,
            0xff,
        ] {
            assert_eq!(gate(t), Gate::Close(reason::PROTOCOL), "0x{t:02x}");
        }
    }

    /// Turned off: a frame whose granted caps are all off is skipped, not an
    /// error; `Credit` still counts while one of its caps is on.
    #[test]
    fn turned_off_frames_are_skipped_and_paused_requests_too() {
        let all = caps::ALL;
        let off = caps::PAUSABLE;
        for t in [ty::OFFER, ty::DATA, ty::GET, ty::LIST, ty::CLIP_START] {
            assert_eq!(
                ty::gate(t, Side::Viewer, all, off, 0),
                Gate::Skip,
                "0x{t:02x}"
            );
        }
        assert_eq!(
            ty::gate(ty::CREDIT, Side::Viewer, all, caps::CLIP, 0),
            Gate::Decode
        );
        assert_eq!(
            ty::gate(ty::CREDIT, Side::Viewer, all, caps::CLIP | caps::BROWSE, 0),
            Gate::Skip
        );
        // A cap that was never granted is not "off": BROWSE alone answers.
        assert_eq!(
            ty::gate(ty::CREDIT, Side::Viewer, caps::BROWSE, caps::BROWSE, 0),
            Gate::Skip
        );
        // Paused: new requests are skipped, a running transfer's frames are
        // decoded (it stalls on the host's side instead).
        let paused = caps::PAUSABLE;
        for t in [
            ty::OFFER,
            ty::GET,
            ty::LIST,
            ty::CLIP_SWITCH,
            ty::CLIP_START,
            ty::CLIP_CHUNK,
        ] {
            assert_eq!(ty::gate(t, Side::Viewer, all, 0, paused), Gate::Skip);
            assert!(ty::pausable(t));
        }
        for t in [
            ty::DATA,
            ty::DONE,
            ty::CREDIT,
            ty::CANCEL,
            ty::COMPLETE,
            ty::CHAT,
        ] {
            assert_eq!(ty::gate(t, Side::Viewer, all, 0, paused), Gate::Decode);
            assert!(!ty::pausable(t));
        }
        // The host's own frames are never paused by the gate.
        assert_eq!(
            ty::gate(ty::CLIP_START, Side::Host, all, 0, paused),
            Gate::Decode
        );
    }

    #[tokio::test]
    async fn stream_helpers_round_trip_and_report_clean_eof() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        for msg in samples() {
            write_msg(&mut a, &msg).await.unwrap();
        }
        drop(a);
        for msg in samples() {
            assert_eq!(read_one(&mut b).await.unwrap(), Some(msg));
        }
        assert_eq!(read_one(&mut b).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_stream_cut_inside_a_header_is_an_error_not_an_end() {
        for cut in 1..5 {
            let bytes = samples()[1].encode();
            let mut r = &bytes[..cut];
            assert!(
                matches!(read_header(&mut r).await, Err(SvcError::Io(_))),
                "cut at {cut}"
            );
        }
        let bytes = samples()[1].encode();
        let mut r = &bytes[..bytes.len() - 1];
        let header = read_header(&mut r).await.unwrap().unwrap();
        assert_eq!(
            header,
            Header {
                ty: ty::REFUSED,
                len: 2
            }
        );
        assert!(matches!(
            read_body_max(&mut r, header, 2).await,
            Err(SvcError::Io(_))
        ));
    }

    #[tokio::test]
    async fn oversized_and_empty_frames_are_refused_before_allocation() {
        for len in [0, MAX_SERVICES_FRAME as u32 + 1, u32::MAX] {
            let mut bytes = len.to_be_bytes().to_vec();
            bytes.push(ty::CHAT);
            let mut r = &bytes[..];
            assert!(
                matches!(read_header(&mut r).await, Err(SvcError::Size(n)) if n == len as usize),
                "{len}"
            );
            assert_eq!(r, [ty::CHAT], "the type byte stays unread");
        }
        // The largest frame passes the header; a body over the caller's cap is
        // refused before it is read.
        let mut bytes = (MAX_SERVICES_FRAME as u32).to_be_bytes().to_vec();
        bytes.push(ty::CREDIT);
        let mut r = &bytes[..];
        let header = read_header(&mut r).await.unwrap().unwrap();
        assert_eq!(header.len, MAX_SERVICES_FRAME - 1);
        assert!(matches!(
            read_body_max(&mut r, header, ty::max_body(ty::CREDIT).unwrap()).await,
            Err(SvcError::Size(n)) if n == MAX_SERVICES_FRAME
        ));
    }

    #[tokio::test]
    async fn a_skipped_body_is_read_through_the_scratch_and_the_next_frame_follows() {
        let mut bytes = SvcMsg::Data {
            xfer: 4,
            offset: 0,
            bytes: vec![9; CHUNK],
        }
        .encode();
        bytes.extend_from_slice(&samples()[8].encode());
        let mut r = &bytes[..];
        let header = read_header(&mut r).await.unwrap().unwrap();
        let mut scratch = [0u8; 1000];
        skip_body(&mut r, header, &mut scratch).await.unwrap();
        assert_eq!(scratch, [0; 1000], "wiped");
        assert_eq!(read_one(&mut r).await.unwrap(), Some(samples()[8].clone()));
        // An empty scratch still works.
        let bytes = samples()[4].encode();
        let mut r = &bytes[..];
        let header = read_header(&mut r).await.unwrap().unwrap();
        skip_body(&mut r, header, &mut []).await.unwrap();
        assert!(r.is_empty());
    }

    #[tokio::test]
    async fn the_bind_is_read_at_its_fixed_size() {
        let bytes = bind().encode();
        let mut r = &bytes[..];
        assert_eq!(SvcMsg::Bind(read_bind(&mut r).await.unwrap()), bind());
        // Another length is refused after the prefix: nothing more is read.
        for len in [0u32, 48, 50, MAX_SERVICES_FRAME as u32, u32::MAX] {
            let mut frame = bytes.clone();
            frame[..4].copy_from_slice(&len.to_be_bytes());
            let mut r = &frame[..];
            assert!(matches!(read_bind(&mut r).await, Err(SvcError::Size(n)) if n == len as usize));
            assert_eq!(r.len(), frame.len() - 4);
        }
        // Another type at the bind's length, or a non-hex id, is malformed.
        let mut other = bytes.clone();
        other[4] = ty::CHAT;
        assert!(matches!(
            read_bind(&mut &other[..]).await,
            Err(SvcError::Malformed("Bind"))
        ));
        let mut id = bytes.clone();
        id[5] = b'z';
        assert!(matches!(
            read_bind(&mut &id[..]).await,
            Err(SvcError::Malformed("Bind"))
        ));
        // A short stream is an I/O error.
        assert!(matches!(
            read_bind(&mut &bytes[..20]).await,
            Err(SvcError::Io(_))
        ));
    }

    /// Every hand-packed body one byte off, out of its bounds, or of an
    /// unknown type is an error, never a panic.
    #[test]
    fn malformed_hand_packed_bodies_are_errors() {
        let cases: [(u8, &[u8], &str); 12] = [
            (ty::BIND, b"0123456789abcdef", "Bind"),
            (ty::REFUSED, &[0], "Refused"),
            (ty::REFUSED, &[0, 1, 2], "Refused"),
            (ty::CLOSE, &[], "Close"),
            (ty::CREDIT, &[0; 11], "Credit"),
            (ty::CREDIT, &[0; 13], "Credit"),
            // A chunk with no bytes, a short head.
            (ty::CLIP_CHUNK, &[0; 8], "ClipChunk"),
            (ty::CLIP_CHUNK, &[0; 7], "ClipChunk"),
            (ty::DATA, &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], "Data"),
            (ty::DATA, &[0; 11], "Data"),
            // Data of transfer 0 (reserved for the clipboard's credit).
            (ty::DATA, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], "Data"),
            // Data past u64::MAX.
            (
                ty::DATA,
                &[
                    0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1,
                ],
                "Data",
            ),
        ];
        for (t, body, name) in cases {
            assert!(
                matches!(SvcMsg::decode(t, body), Err(SvcError::Malformed(n)) if n == name),
                "{name} of {} bytes: {:?}",
                body.len(),
                SvcMsg::decode(t, body)
            );
        }
        // A chunk of CHUNK + 1 bytes, and one that ends past MAX_CLIP.
        let mut long = vec![0u8; 8];
        long.extend_from_slice(&[1; CHUNK + 1]);
        assert!(SvcMsg::decode(ty::CLIP_CHUNK, &long).is_err());
        let mut long = vec![0, 0, 0, 1];
        long.extend_from_slice(&[1; CHUNK + 1]);
        long.splice(4..4, [0; 8]);
        assert!(SvcMsg::decode(ty::DATA, &long).is_err());
        let mut past = vec![0, 0, 0, 0];
        past.extend_from_slice(&(MAX_CLIP - 1).to_be_bytes());
        past.extend_from_slice(&[1, 2]);
        assert!(SvcMsg::decode(ty::CLIP_CHUNK, &past).is_err());
        past.pop();
        assert!(SvcMsg::decode(ty::CLIP_CHUNK, &past).is_ok());
        for t in [0x00, 0x06, 0x11, 0x43, 0x7e, 0x80, 0xff] {
            assert!(matches!(
                SvcMsg::decode(t, &[]),
                Err(SvcError::UnknownType(u)) if u == t
            ));
        }
    }

    /// `Debug` shows numbers and lengths, never clipboard or file bytes or the
    /// bind MAC.
    #[test]
    fn debug_shows_no_content() {
        let chunk = SvcMsg::ClipChunk {
            seq: 1,
            offset: 0,
            bytes: Zeroizing::new(b"hunter2-secret".to_vec()),
        };
        let printed = format!("{chunk:?}");
        assert_eq!(printed, "ClipChunk { seq: 1, offset: 0, bytes: 14 }");
        let data = SvcMsg::Data {
            xfer: 2,
            offset: 5,
            bytes: b"PRIVATE".to_vec(),
        };
        assert_eq!(format!("{data:?}"), "Data { xfer: 2, offset: 5, bytes: 7 }");
        let printed = format!("{:?}", bind());
        assert!(!printed.contains("[7, 7"), "{printed}");
        assert!(!printed.contains("07070707"), "{printed}");
        assert!(printed.contains("<redacted>"));
    }

    /// Any valid hand-packed message.
    fn valid_packed() -> impl Strategy<Value = SvcMsg> {
        prop_oneof![
            ("[0-9a-fA-F]{16}", any::<[u8; 32]>())
                .prop_map(|(session_id, mac)| SvcMsg::Bind(Bind { session_id, mac })),
            any::<u16>().prop_map(|reason| SvcMsg::Refused { reason }),
            (
                any::<u32>(),
                proptest::collection::vec(any::<u8>(), 1..=64),
                0..=MAX_CLIP
            )
                .prop_map(|(seq, bytes, at)| SvcMsg::ClipChunk {
                    seq,
                    offset: at.min(MAX_CLIP - bytes.len() as u32),
                    bytes: Zeroizing::new(bytes),
                }),
            (
                1u32..,
                any::<u64>(),
                proptest::collection::vec(any::<u8>(), 1..=64)
            )
                .prop_map(|(xfer, at, bytes)| SvcMsg::Data {
                    xfer,
                    offset: at.min(u64::MAX - bytes.len() as u64),
                    bytes,
                }),
            (any::<u32>(), any::<u64>()).prop_map(|(xfer, upto)| SvcMsg::Credit { xfer, upto }),
            any::<u16>().prop_map(|reason| SvcMsg::Close { reason }),
        ]
    }

    proptest! {
        /// A valid message decodes back to itself behind a prefix that counts
        /// its type byte and body.
        #[test]
        fn valid_packed_messages_round_trip(msg in valid_packed()) {
            let bytes = msg.encode();
            let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            prop_assert_eq!(len, bytes.len() - 4);
            prop_assert_eq!(SvcMsg::decode(bytes[4], &bytes[5..]).unwrap(), msg);
        }

        /// `decode` of any type and body returns, never panics; a hand-packed
        /// frame it accepts encodes back to exactly its bytes.
        #[test]
        fn decoding_any_body_never_panics(
            t in any::<u8>(),
            body in proptest::collection::vec(any::<u8>(), 0..=96),
        ) {
            if let Ok(msg) = SvcMsg::decode(t, &body) {
                prop_assert_eq!(&msg.encode()[5..], &body[..]);
                prop_assert!(msg.validate().is_ok());
            }
        }
    }
}
