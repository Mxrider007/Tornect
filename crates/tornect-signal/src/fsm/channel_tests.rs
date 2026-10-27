//! The channel's cancel-safe reads and value faults (design `direct` §8.2,
//! §12.1 "Channel"): partial frames survive timeouts and dropped futures,
//! `take_frame` never writes, every envelope fault comes back as a value,
//! and a write cut short is the last write.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use proptest::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf, duplex};

use super::harness::{Took, channel_takes};
use super::*;
use crate::envelope::{Envelope, Kind, codes};
use crate::framing::{HEADER_LEN, MAX_FRAME_LEN, read_frame};
use crate::messages::{Ping, encode_body};

const TH_PK: [u8; 32] = [0x11; 32];

/// The wire bytes (length prefix included) of an envelope.
fn wire(env: &Envelope) -> Vec<u8> {
    let payload = env.encode();
    let mut out = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(&payload);
    out
}

fn ping(msg_id: u64, nonce: u64) -> Envelope {
    Envelope::new(1, msg_id, Kind::Ping, encode_body(&Ping { nonce }))
}

/// A stream whose writes are counted and can be frozen (a peer that grants
/// no credit); reads go to a duplex.
struct Counted {
    inner: DuplexStream,
    writes: Arc<AtomicUsize>,
    frozen: Arc<AtomicBool>,
}

impl Counted {
    fn new(inner: DuplexStream) -> Self {
        Self {
            inner,
            writes: Arc::new(AtomicUsize::new(0)),
            frozen: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.frozen.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.frozen.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.frozen.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A channel past the handshake window (the 64 KiB cap, v1 fixed) over a
/// counted stream, and the peer's end.
fn established() -> (Channel<Counted>, DuplexStream) {
    let (a, b) = duplex(MAX_FRAME_LEN + 64);
    let mut chan = Channel::new(Counted::new(a), &TH_PK);
    chan.set_version(1);
    chan.frame_cap = MAX_FRAME_LEN;
    (chan, b)
}

/// A header alone, then `recv` times out; the frame is not lost to the
/// timeout (it used to be: the dropped read took the header with it, and the
/// next read misparsed the body as a header).
#[tokio::test(start_paused = true)]
async fn a_timeout_keeps_the_partial_frame() {
    let (mut chan, mut peer) = established();
    let frame = wire(&ping(1, 7));
    peer.write_all(&frame[..HEADER_LEN]).await.unwrap();
    let waited = chan.recv(Duration::from_millis(10), "frame").await;
    assert!(
        matches!(waited, Err(HandshakeError::Timeout("frame"))),
        "{waited:?}"
    );
    assert_eq!(chan.rx.buffered(), HEADER_LEN);
    peer.write_all(&frame[HEADER_LEN..HEADER_LEN + 3])
        .await
        .unwrap();
    assert!(chan.recv(Duration::from_millis(10), "frame").await.is_err());
    peer.write_all(&frame[HEADER_LEN + 3..]).await.unwrap();
    let rx = chan
        .recv(Duration::from_millis(10), "frame")
        .await
        .unwrap()
        .expect("the whole frame");
    assert_eq!(rx.env.kind, Kind::Ping);
    assert_eq!(rx.wire, frame);
    assert_eq!(chan.next_rx_id(), 2);
    assert_eq!(chan.stream.writes.load(Ordering::SeqCst), 0);
}

/// `frame_ready` dropped by a `select!` that another branch won, at every
/// point of a frame, loses nothing; `take_frame` before it resolves is
/// `Pending`.
#[tokio::test(start_paused = true)]
async fn frame_ready_dropped_in_a_select_loses_nothing() {
    let (mut chan, mut peer) = established();
    let frames: Vec<Vec<u8>> = (1..=3).map(|id| wire(&ping(id, id * 10))).collect();
    let all: Vec<u8> = frames.concat();
    let mut got = Vec::new();
    for byte in all {
        assert!(matches!(chan.take_frame(), Taken::Pending));
        peer.write_all(&[byte]).await.unwrap();
        // The timer wins unless the byte completed a frame.
        let woke = tokio::select! {
            biased;
            ready = chan.frame_ready() => Some(ready),
            () = tokio::time::sleep(Duration::from_millis(1)) => None,
        };
        if let Some(ready) = woke {
            ready.unwrap();
            match chan.take_frame() {
                Taken::Frame(rx) => got.push(rx),
                other => panic!("{other:?}"),
            }
        }
    }
    let ids: Vec<u64> = got.iter().map(|rx| rx.env.msg_id).collect();
    assert_eq!(ids, [1, 2, 3], "msg_id order kept");
    let wires: Vec<Vec<u8>> = got.iter().map(|rx| rx.wire.clone()).collect();
    assert_eq!(wires, frames);
    drop(peer);
    chan.frame_ready().await.unwrap();
    assert!(matches!(chan.take_frame(), Taken::Eof));
    // The end is sticky: no read past it.
    chan.frame_ready().await.unwrap();
    assert!(matches!(chan.take_frame(), Taken::Eof));
    assert_eq!(chan.stream.writes.load(Ordering::SeqCst), 0);
}

/// Every envelope-level fault is a value, written nowhere, and sticky: the
/// channel reads no further and reports it again.
#[tokio::test]
async fn take_frame_returns_each_envelope_fault_and_never_writes() {
    let cases: Vec<(Vec<u8>, u16, &str)> = vec![
        // A length over the 64 KiB cap: the body is never read.
        (
            u32::try_from(MAX_FRAME_LEN + 1)
                .unwrap()
                .to_be_bytes()
                .to_vec(),
            codes::E_TOO_LARGE,
            "frame",
        ),
        // Not an envelope.
        (vec![0, 0, 0, 2, 0xff, 0xff], codes::E_BAD_LEN, "envelope"),
        // An envelope of a kind outside §B.3.
        (
            {
                let mut env = ping(1, 1).encode();
                // [v, msg_id, kind, body, sig]: kind is the third item.
                let pos = env.iter().position(|&b| b == Kind::Ping as u8).unwrap();
                env[pos] = 0x17;
                let mut out = u32::try_from(env.len()).unwrap().to_be_bytes().to_vec();
                out.extend_from_slice(&env);
                out
            },
            codes::E_UNKNOWN_KIND,
            "kind",
        ),
        (wire(&ping(2, 1)), codes::E_BAD_MSG_ID, "msg_id"),
        (
            wire(&Envelope::new(
                2,
                1,
                Kind::Ping,
                encode_body(&Ping { nonce: 1 }),
            )),
            codes::E_VERSION,
            "version",
        ),
    ];
    for (bytes, code, what) in cases {
        let (mut chan, mut peer) = established();
        peer.write_all(&bytes).await.unwrap();
        // A frame that would be fine follows; it is never read.
        peer.write_all(&wire(&ping(1, 9))).await.unwrap();
        chan.frame_ready().await.unwrap();
        match chan.take_frame() {
            Taken::Fault { code: c, what: w } => {
                assert_eq!((c, w), (code, what), "{}", codes::name(code));
            }
            other => panic!("{}: {other:?}", codes::name(code)),
        }
        chan.frame_ready().await.unwrap();
        assert!(
            matches!(chan.take_frame(), Taken::Fault { code: c, .. } if c == code),
            "sticky"
        );
        assert_eq!(
            chan.stream.writes.load(Ordering::SeqCst),
            0,
            "{} written in place",
            codes::name(code)
        );
        assert!(!chan.is_closing());
    }
}

/// `recv` answers a fault in place, as before: `ERROR{code}`, then the close.
/// Here a length over the handshake cap.
#[tokio::test]
async fn recv_answers_a_too_large_header_with_e_too_large() {
    let (a, mut peer) = duplex(64 * 1024);
    let mut chan = Channel::new(a, &TH_PK);
    let len = u32::try_from(HANDSHAKE_FRAME_CAP + 1).unwrap();
    peer.write_all(&len.to_be_bytes()).await.unwrap();
    let err = chan
        .recv(Duration::from_secs(5), "HELLO")
        .await
        .unwrap_err();
    assert_eq!(err.violation_code(), Some(codes::E_TOO_LARGE));
    assert!(chan.is_closing());
    let answer = read_frame(&mut peer).await.unwrap().unwrap();
    let env = Envelope::decode(&answer).unwrap();
    assert_eq!(env.kind, Kind::Error);
    let e: messages::Error = decode_body(&env.body).unwrap();
    assert_eq!(e.code, codes::E_TOO_LARGE);
    assert!(
        read_frame(&mut peer).await.unwrap().is_none(),
        "then closed"
    );
}

/// An end inside a frame is a framing error, from `frame_ready` and `recv`.
#[tokio::test]
async fn an_end_inside_a_frame_is_truncated() {
    let (mut chan, mut peer) = established();
    let frame = wire(&ping(1, 1));
    peer.write_all(&frame[..frame.len() - 1]).await.unwrap();
    drop(peer);
    assert!(matches!(
        chan.frame_ready().await,
        Err(HandshakeError::Frame(FrameError::Truncated))
    ));
    assert!(matches!(
        chan.recv(Duration::from_secs(1), "frame").await,
        Err(HandshakeError::Frame(FrameError::Truncated))
    ));
}

/// A write cut short leaves a partial frame in the stream, so it is the last
/// write: a later frame is refused, and `fail` and `bye` only close.
#[tokio::test(start_paused = true)]
async fn a_write_cut_short_is_the_last_write() {
    let (mut chan, mut peer) = established();
    chan.stream.frozen.store(true, Ordering::SeqCst);
    let cut = tokio::time::timeout(
        Duration::from_millis(10),
        chan.send(&Ping { nonce: 1 }, None),
    )
    .await;
    assert!(cut.is_err(), "the write stalls");
    chan.stream.frozen.store(false, Ordering::SeqCst);
    let refused = chan.send(&Ping { nonce: 2 }, None).await;
    assert!(
        matches!(refused, Err(HandshakeError::Aborted(_))),
        "{refused:?}"
    );
    let writes = chan.stream.writes.load(Ordering::SeqCst);
    let err = chan.fail(codes::E_BAD_STATE, "kind").await;
    assert_eq!(err.violation_code(), Some(codes::E_BAD_STATE));
    assert!(chan.is_closing());
    assert_eq!(
        chan.stream.writes.load(Ordering::SeqCst),
        writes + 1,
        "only the shutdown, no ERROR"
    );
    let mut seen = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut peer, &mut seen)
        .await
        .unwrap();
    assert!(seen.is_empty(), "nothing reached the peer: {seen:?}");
}

/// A whole frame that comes while `departure` watches stops the watch from
/// reading, once it read the first byte past it (to see the stream end
/// there): the rest of the next frame stays in the stream, and `recv` takes
/// the first, then the second whole.
#[tokio::test(start_paused = true)]
async fn departure_reads_at_most_one_frame() {
    let (mut chan, mut peer) = established();
    let first = wire(&ping(1, 1));
    let second = wire(&ping(2, 2));
    peer.write_all(&first).await.unwrap();
    peer.write_all(&second).await.unwrap();
    let watched = tokio::time::timeout(Duration::from_millis(10), chan.departure()).await;
    assert!(watched.is_err(), "the peer is still there");
    assert_eq!(chan.rx.buffered(), first.len(), "one frame, no more");
    assert_eq!(chan.rx.past_len(), 1, "and one byte of the next");
    let again = tokio::time::timeout(Duration::from_millis(10), chan.departure()).await;
    assert!(again.is_err(), "a second watch reads nothing more");
    assert_eq!((chan.rx.buffered(), chan.rx.past_len()), (first.len(), 1));
    let rx = chan
        .recv(Duration::from_secs(1), "frame")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rx.wire, first);
    let rx = chan
        .recv(Duration::from_secs(1), "frame")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rx.wire, second);
    drop(peer);
    assert!(matches!(chan.departure().await, HandshakeError::Closed));
}

/// A peer that sends one whole frame while it owes silence and then leaves
/// is still seen leaving (B04): the watch reads one byte past the frame,
/// which is the stream's end. The frame is not lost: the next `recv` takes
/// it, and the one after reads the end. Also when the frame and the end
/// came before the watch began, and when the watch was dropped in between.
#[tokio::test(start_paused = true)]
async fn departure_sees_a_peer_leave_after_one_early_frame() {
    for watched_first in [false, true] {
        let (mut chan, mut peer) = established();
        let first = wire(&ping(1, 1));
        peer.write_all(&first).await.unwrap();
        if watched_first {
            let watched = tokio::time::timeout(Duration::from_millis(10), chan.departure()).await;
            assert!(watched.is_err(), "the peer is still there");
            assert_eq!(chan.rx.past_len(), 0, "nothing past the frame yet");
        }
        drop(peer);
        let gone = tokio::time::timeout(Duration::from_millis(10), chan.departure())
            .await
            .expect("the leave is seen at once");
        assert!(matches!(gone, HandshakeError::Closed), "{gone:?}");
        assert!(
            matches!(chan.departure().await, HandshakeError::Closed),
            "kept"
        );
        let rx = chan
            .recv(Duration::from_secs(1), "frame")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rx.wire, first, "the early frame is still handed on");
        assert!(
            chan.recv(Duration::from_secs(1), "frame")
                .await
                .unwrap()
                .is_none()
        );
    }
}

fn frames_strategy() -> impl Strategy<Value = Vec<(u64, u16)>> {
    proptest::collection::vec((any::<u64>(), 0u16..2048), 0..12)
}

proptest! {
    /// Random split and cancel points (design `direct` §12.1): the frames
    /// come out identical, in `msg_id` order, and the same as with no cut at
    /// all, inside the handshake window and after it.
    #[test]
    fn cancelled_reads_at_random_points_give_identical_frames(
        frames in frames_strategy(),
        cuts in proptest::collection::vec(any::<u8>(), 1..16),
        tail in proptest::collection::vec(any::<u8>(), 0..8),
        after_accept in any::<bool>(),
    ) {
        let mut stream = Vec::new();
        let mut expected = Vec::new();
        for (i, (nonce, pad)) in frames.iter().enumerate() {
            let msg_id = u64::try_from(i).unwrap() + 1;
            // Pad the body with unknown keys' worth of bytes: `Envelope`
            // carries the body opaquely, so any length is a valid frame.
            let mut body = encode_body(&Ping { nonce: *nonce });
            body.extend(std::iter::repeat_n(0u8, usize::from(*pad)));
            let env = Envelope::new(1, msg_id, Kind::Ping, body);
            let bytes = wire(&env);
            expected.push(Took::Frame { msg_id, wire: bytes.clone() });
            stream.extend_from_slice(&bytes);
        }
        // Then garbage or nothing: whatever the end is, cuts never change it.
        stream.extend_from_slice(&tail);
        let uncut = channel_takes(&stream, &[], after_accept);
        let cut = channel_takes(&stream, &cuts, after_accept);
        prop_assert_eq!(&uncut, &cut);
        prop_assert!(uncut.len() > expected.len() || tail.is_empty());
        prop_assert_eq!(&uncut[..expected.len()], &expected[..]);
        if tail.is_empty() {
            prop_assert_eq!(uncut.last(), Some(&Took::Eof));
        }
    }

    /// Arbitrary bytes: cut or not, the same takes (the `framing` fuzz
    /// target's property, here with proptest's inputs).
    #[test]
    fn arbitrary_bytes_take_the_same_with_and_without_cuts(
        stream in proptest::collection::vec(any::<u8>(), 0..512),
        cuts in proptest::collection::vec(any::<u8>(), 1..8),
        after_accept in any::<bool>(),
    ) {
        prop_assert_eq!(
            channel_takes(&stream, &[], after_accept),
            channel_takes(&stream, &cuts, after_accept)
        );
    }
}
