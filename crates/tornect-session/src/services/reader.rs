//! The services reader (the services design §3.2, §3.4): one task per
//! stream reads the peer's frames and decides, from the type alone and before
//! any body byte is read, whether a frame is decoded, skipped or ends the
//! stream ([`ty::gate`]). A frame for a service the session was never
//! granted is never decoded: the view-only guarantee lives here, not in the
//! loop that handles what was decoded.
//!
//! The reader never waits on the writer. It hands what it decoded to the
//! stream's loop through a channel of [`ServicesLimits::inbound_depth`]
//! frames (8 by default, so at most 8 × 64 KiB is held per stream) and stops
//! reading while that is full, which Tor's flow control turns into the
//! peer's wait.
//!
//! [`ServicesLimits::inbound_depth`]: super::ServicesLimits::inbound_depth

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use tokio::io::AsyncRead;
use tokio::sync::mpsc;
use tornect_proto::services::{
    Side, SvcError, SvcMsg, read_body_max, read_header, reason, skip_body, ty,
};

/// What the bodies of skipped frames are read through, and wiped after.
const SCRATCH: usize = 4096;

/// The caps a stream was opened with and what became of them, shared by the
/// stream's reader and its loop. `granted` is fixed at the bind; `off` only
/// grows (a cap the host user turned off, or one whose viewer input was
/// lost, never returns in that session); `paused` follows the host's lock.
#[derive(Debug)]
pub(crate) struct CapState {
    granted: u16,
    off: AtomicU16,
    paused: AtomicU16,
    /// Frames whose body the reader decoded (the design's counting hook: a
    /// frame for a cap never granted is never one of them).
    decoded: AtomicU64,
    /// Frames read past undecoded: turned off, or paused.
    skipped: AtomicU64,
}

/// How many frames a reader decoded and skipped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReaderCounts {
    /// Frames whose body was decoded.
    pub decoded: u64,
    /// Frames read past without decoding them (a cap turned off or paused).
    pub skipped: u64,
}

impl CapState {
    /// A stream granted `granted`, nothing turned off or paused.
    pub(crate) fn new(granted: u16) -> Self {
        Self {
            granted,
            off: AtomicU16::new(0),
            paused: AtomicU16::new(0),
            decoded: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
        }
    }

    /// The caps still on: granted and not turned off.
    pub(crate) fn left(&self) -> u16 {
        self.granted & !self.off.load(Ordering::SeqCst)
    }

    /// The caps paused now.
    pub(crate) fn paused(&self) -> u16 {
        self.paused.load(Ordering::SeqCst)
    }

    /// Turn `caps` off for the rest of the stream: frames that need only
    /// caps turned off are skipped from now on. Returns the caps left.
    pub(crate) fn turn_off(&self, caps: u16) -> u16 {
        self.off.fetch_or(caps & self.granted, Ordering::SeqCst);
        self.left()
    }

    /// Whether a frame of type `t` from `from` is still served: the
    /// reader's rule for caps turned off (§3.2) applied again, to a frame it
    /// decoded before they were and queued. Pauses are not: a new request
    /// decoded before a pause is answered (`LOCKED`).
    pub(crate) fn serves(&self, t: u8, from: Side) -> bool {
        let off = self.granted & !self.left();
        matches!(ty::gate(t, from, self.granted, off, 0), ty::Gate::Decode)
    }

    /// What the reader did so far.
    pub(crate) fn counts(&self) -> ReaderCounts {
        ReaderCounts {
            decoded: self.decoded.load(Ordering::SeqCst),
            skipped: self.skipped.load(Ordering::SeqCst),
        }
    }
}

/// What the reader hands the stream's loop.
#[derive(Debug)]
pub(crate) enum Inbound {
    /// A decoded frame the stream's caps let through.
    Frame(SvcMsg),
    /// The last thing the reader says: it stopped reading.
    End(ReadEnd),
}

/// Why a reader stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadEnd {
    /// The peer closed the stream between frames.
    Eof,
    /// The stream failed, or ended inside a frame.
    Io,
    /// The peer broke the protocol, or sent a frame for a cap never
    /// granted: the stream ends with `Close` and this reason.
    Refuse(u16),
}

/// Read `from`'s frames into `tx` until the stream ends or a frame ends it,
/// gating each one with `caps` before its body is read (the design §3.2):
///
/// 1. an unknown type, a type `from` never sends, or a body longer than its
///    type's bound: `Close{PROTOCOL}`, the body unread;
/// 2. a frame for a cap never granted: `Close{NOT_OFFERED}`, the body unread;
/// 3. a frame whose caps were all turned off, or (from the viewer) a new
///    request whose cap is paused: read through a fixed scratch buffer and
///    dropped, undecoded and without error;
/// 4. anything else is decoded, and a body that does not decode is
///    `Close{PROTOCOL}`.
///
/// The host's own pauses are passed for `paused`; a viewer's reader sees none
/// (the host stops sending while it is paused).
pub(crate) async fn read_frames<R: AsyncRead + Unpin>(
    mut rd: R,
    from: Side,
    caps: Arc<CapState>,
    tx: mpsc::Sender<Inbound>,
) {
    let mut scratch = vec![0u8; SCRATCH];
    let end = loop {
        let header = match read_header(&mut rd).await {
            Ok(Some(header)) => header,
            Ok(None) => break ReadEnd::Eof,
            Err(SvcError::Io(_)) => break ReadEnd::Io,
            Err(_) => break ReadEnd::Refuse(reason::PROTOCOL),
        };
        let paused = match from {
            Side::Viewer => caps.paused(),
            Side::Host => 0,
        };
        let off = caps.granted & !caps.left();
        let max = ty::max_body(header.ty).unwrap_or(0);
        match ty::gate(header.ty, from, caps.granted, off, paused) {
            ty::Gate::Close(code) => break ReadEnd::Refuse(code),
            _ if header.len > max => break ReadEnd::Refuse(reason::PROTOCOL),
            ty::Gate::Skip => {
                if skip_body(&mut rd, header, &mut scratch).await.is_err() {
                    break ReadEnd::Io;
                }
                caps.skipped.fetch_add(1, Ordering::SeqCst);
            }
            ty::Gate::Decode => {
                let body = match read_body_max(&mut rd, header, max).await {
                    Ok(body) => body,
                    Err(SvcError::Io(_)) => break ReadEnd::Io,
                    Err(_) => break ReadEnd::Refuse(reason::PROTOCOL),
                };
                caps.decoded.fetch_add(1, Ordering::SeqCst);
                let Ok(msg) = SvcMsg::decode(header.ty, &body) else {
                    break ReadEnd::Refuse(reason::PROTOCOL);
                };
                if tx.send(Inbound::Frame(msg)).await.is_err() {
                    return;
                }
            }
        }
    };
    let _ = tx.send(Inbound::End(end)).await;
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt as _, duplex};
    use tornect_proto::services::{Cancel, Chat, Get, caps, write_msg};

    use super::*;

    async fn feed(from: Side, granted: u16, frames: &[SvcMsg]) -> (Vec<Inbound>, ReaderCounts) {
        let (mut peer, ours) = duplex(1 << 20);
        for frame in frames {
            write_msg(&mut peer, frame).await.unwrap();
        }
        peer.shutdown().await.unwrap();
        let state = Arc::new(CapState::new(granted));
        let (tx, mut rx) = mpsc::channel(64);
        read_frames(ours, from, Arc::clone(&state), tx).await;
        let mut got = Vec::new();
        while let Ok(inbound) = rx.try_recv() {
            got.push(inbound);
        }
        (got, state.counts())
    }

    fn chat() -> SvcMsg {
        SvcMsg::Chat(Chat { text: "hi".into() })
    }

    /// A frame for a cap never granted ends the stream with `NOT_OFFERED`
    /// before its body is decoded; one the peer never sends, with
    /// `PROTOCOL`.
    #[tokio::test]
    async fn frames_are_gated_before_they_are_decoded() {
        let (got, counts) = feed(
            Side::Viewer,
            caps::CHAT,
            &[chat(), SvcMsg::Get(Get { xfer: 1, handle: 2 }), chat()],
        )
        .await;
        assert!(matches!(got[0], Inbound::Frame(SvcMsg::Chat(_))));
        assert!(matches!(
            got[1],
            Inbound::End(ReadEnd::Refuse(reason::NOT_OFFERED))
        ));
        assert_eq!(got.len(), 2);
        assert_eq!(
            counts,
            ReaderCounts {
                decoded: 1,
                skipped: 0
            }
        );

        // The host's frame from the viewer, the viewer's from the host.
        let (got, counts) = feed(Side::Viewer, caps::ALL, &[SvcMsg::Refused { reason: 1 }]).await;
        assert!(matches!(
            got[0],
            Inbound::End(ReadEnd::Refuse(reason::PROTOCOL))
        ));
        assert_eq!(counts.decoded, 0);
        let (got, _) = feed(
            Side::Host,
            caps::ALL,
            &[SvcMsg::Get(Get { xfer: 1, handle: 2 })],
        )
        .await;
        assert!(matches!(
            got[0],
            Inbound::End(ReadEnd::Refuse(reason::PROTOCOL))
        ));
    }

    /// Caps turned off are skipped without error, through the scratch
    /// buffer; paused requests from the viewer too.
    #[tokio::test]
    async fn turned_off_and_paused_frames_are_skipped() {
        let (mut peer, ours) = duplex(1 << 20);
        let state = Arc::new(CapState::new(caps::CHAT | caps::BROWSE));
        assert_eq!(state.turn_off(caps::BROWSE | caps::CLIP), caps::CHAT);
        write_msg(&mut peer, &SvcMsg::Get(Get { xfer: 1, handle: 2 }))
            .await
            .unwrap();
        write_msg(
            &mut peer,
            &SvcMsg::Cancel(Cancel {
                xfer: 1,
                reason: 15,
            }),
        )
        .await
        .unwrap();
        write_msg(&mut peer, &chat()).await.unwrap();
        peer.shutdown().await.unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        read_frames(ours, Side::Viewer, Arc::clone(&state), tx).await;
        assert!(matches!(
            rx.recv().await,
            Some(Inbound::Frame(SvcMsg::Chat(_)))
        ));
        assert!(matches!(rx.recv().await, Some(Inbound::End(ReadEnd::Eof))));
        assert_eq!(
            state.counts(),
            ReaderCounts {
                decoded: 1,
                skipped: 2
            }
        );
    }

    /// A body longer than its type allows is refused unread, also for a
    /// frame that would be skipped; a stream that ends inside a frame is an
    /// I/O end; a body that does not decode is a protocol error.
    #[tokio::test]
    async fn bounds_and_broken_frames_end_the_stream() {
        // A `Credit` announced at 13 bytes.
        let (mut peer, ours) = duplex(1024);
        peer.write_all(&[0, 0, 0, 14, ty::CREDIT]).await.unwrap();
        peer.write_all(&[0; 13]).await.unwrap();
        peer.shutdown().await.unwrap();
        let state = Arc::new(CapState::new(caps::ALL));
        let (tx, mut rx) = mpsc::channel(8);
        read_frames(ours, Side::Viewer, Arc::clone(&state), tx).await;
        assert!(matches!(
            rx.recv().await,
            Some(Inbound::End(ReadEnd::Refuse(reason::PROTOCOL)))
        ));
        assert_eq!(state.counts().decoded, 0);

        // Cut inside a frame.
        let (mut peer, ours) = duplex(1024);
        peer.write_all(&[0, 0, 0, 9, ty::CHAT, 1, 2]).await.unwrap();
        peer.shutdown().await.unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        read_frames(ours, Side::Viewer, Arc::new(CapState::new(caps::ALL)), tx).await;
        assert!(matches!(rx.recv().await, Some(Inbound::End(ReadEnd::Io))));

        // Not CBOR.
        let (mut peer, ours) = duplex(1024);
        peer.write_all(&[0, 0, 0, 3, ty::CHAT, 0xff, 0xff])
            .await
            .unwrap();
        peer.shutdown().await.unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        read_frames(ours, Side::Viewer, Arc::new(CapState::new(caps::ALL)), tx).await;
        assert!(matches!(
            rx.recv().await,
            Some(Inbound::End(ReadEnd::Refuse(reason::PROTOCOL)))
        ));
    }
}
