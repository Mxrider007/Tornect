//! The channel's receive buffer (design `direct` §8.2): at most one frame,
//! filled by reads that a dropped future cannot cut short.
//!
//! [`RxBuf::fill`] reads only what the current frame still needs, the rest of
//! the `u32`-BE length prefix and then the body (`docs/PLAN.md` §B.3), and
//! appends every byte it read before its next await. A caller may therefore
//! race it in a `select!` and drop it at any point: the next call carries on
//! where the last one stopped, and no byte is lost or read twice. It never
//! reads past the frame it holds, so whatever the peer sends next stays in
//! the stream until that frame is taken.

use tokio::io::{AsyncRead, AsyncReadExt as _};
use zeroize::{Zeroize as _, Zeroizing};

use crate::framing::{FrameError, HEADER_LEN};

/// One body read goes through a zeroized chunk of this size.
const CHUNK: usize = 1024;

/// What [`RxBuf::fill`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Filled {
    /// A whole frame is buffered.
    Frame,
    /// The peer closed the stream at a frame boundary.
    Eof,
}

/// What the buffer reports from now on, whatever the stream does: the end of
/// the stream, or an envelope fault the channel already reported. Sticky, so
/// a channel never reads past either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RxFault {
    /// The stream ended at a frame boundary.
    Eof,
    /// The frame failed an envelope-level check (fixed `what`).
    Envelope {
        /// The `ERROR` code it is answered with.
        code: u16,
        /// Which check failed.
        what: &'static str,
    },
}

/// At most one frame, as it was on the wire. The bytes are wiped when the
/// frame is taken and on drop, and `Debug` prints only sizes: a client frame
/// of the handshake may carry KE3 and an accept carries the attended token.
#[derive(Default)]
pub(super) struct RxBuf {
    /// The length prefix while it is incomplete.
    hdr: [u8; HEADER_LEN],
    /// How much of `hdr` has arrived.
    hdr_len: usize,
    /// The frame, prefix included (the transcript absorbs exactly these
    /// bytes), once the prefix is complete and within the cap. Reserved once
    /// at its full size, so it never moves and leaves no copy behind.
    wire: Zeroizing<Vec<u8>>,
    /// The announced payload length, once the prefix is complete.
    want: Option<usize>,
    fault: Option<RxFault>,
}

impl core::fmt::Debug for RxBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RxBuf")
            .field("buffered", &self.buffered())
            .field("want", &self.want)
            .field("fault", &self.fault)
            .finish()
    }
}

impl Drop for RxBuf {
    fn drop(&mut self) {
        self.hdr.zeroize();
    }
}

impl RxBuf {
    /// Bytes held for the current frame, prefix included.
    pub(super) fn buffered(&self) -> usize {
        if self.wire.is_empty() {
            self.hdr_len
        } else {
            self.wire.len()
        }
    }

    /// The payload length the current frame announced, once its prefix is in.
    pub(super) fn announced(&self) -> Option<usize> {
        self.want
    }

    /// Whether the announced frame is buffered whole (an announced length
    /// over the cap never is).
    pub(super) fn complete(&self) -> bool {
        self.want
            .is_some_and(|len| !self.wire.is_empty() && self.wire.len() == HEADER_LEN + len)
    }

    /// The sticky end or fault, if any.
    pub(super) fn fault(&self) -> Option<RxFault> {
        self.fault
    }

    /// Make `fault` what the buffer reports from now on.
    pub(super) fn set_fault(&mut self, fault: RxFault) {
        self.fault = Some(fault);
    }

    /// Take the whole frame (prefix included) and start the next one.
    pub(super) fn take_wire(&mut self) -> Zeroizing<Vec<u8>> {
        let wire = std::mem::take(&mut self.wire);
        self.hdr.zeroize();
        self.hdr_len = 0;
        self.want = None;
        wire
    }

    /// Read until a whole frame of at most `cap` payload bytes is buffered,
    /// or the stream ends at a frame boundary. Returns at once if either is
    /// already so.
    ///
    /// Cancel safe: each read is a single `read` call, cancel safe itself,
    /// whose bytes are appended before the next await. An announced length
    /// over `cap` is [`FrameError::TooLarge`] with the prefix kept, before any
    /// of the body is read or reserved, and judged again against the cap of
    /// the next call; an end inside a frame is [`FrameError::Truncated`].
    pub(super) async fn fill<R>(&mut self, stream: &mut R, cap: usize) -> Result<Filled, FrameError>
    where
        R: AsyncRead + Unpin,
    {
        let mut chunk = Zeroizing::new([0u8; CHUNK]);
        loop {
            if self.fault == Some(RxFault::Eof) {
                return Ok(Filled::Eof);
            }
            let Some(len) = self.want else {
                let n = stream.read(&mut self.hdr[self.hdr_len..]).await?;
                if n == 0 {
                    if self.hdr_len == 0 {
                        self.fault = Some(RxFault::Eof);
                        continue;
                    }
                    return Err(FrameError::Truncated);
                }
                self.hdr_len += n;
                if self.hdr_len == HEADER_LEN {
                    self.want = Some(u32::from_be_bytes(self.hdr) as usize);
                }
                continue;
            };
            if len > cap {
                return Err(FrameError::TooLarge { len, max: cap });
            }
            if self.wire.is_empty() {
                self.wire.reserve_exact(HEADER_LEN + len);
                self.wire.extend_from_slice(&self.hdr);
            }
            let missing = HEADER_LEN + len - self.wire.len();
            if missing == 0 {
                return Ok(Filled::Frame);
            }
            let n = stream.read(&mut chunk[..missing.min(CHUNK)]).await?;
            if n == 0 {
                return Err(FrameError::Truncated);
            }
            self.wire.extend_from_slice(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::MAX_FRAME_LEN;
    use tokio::io::{AsyncWriteExt as _, duplex};

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[tokio::test]
    async fn fill_holds_one_frame_and_leaves_the_next_in_the_stream() {
        let (mut a, mut b) = duplex(4096);
        let mut both = frame(b"first");
        both.extend_from_slice(&frame(b"second"));
        a.write_all(&both).await.unwrap();
        let mut rx = RxBuf::default();
        assert_eq!(rx.fill(&mut b, 64).await.unwrap(), Filled::Frame);
        assert!(rx.complete());
        assert_eq!(rx.buffered(), HEADER_LEN + 5);
        // Already whole: a second fill reads nothing more.
        assert_eq!(rx.fill(&mut b, 64).await.unwrap(), Filled::Frame);
        assert_eq!(&rx.take_wire()[..], &frame(b"first")[..]);
        assert_eq!(rx.buffered(), 0);
        assert_eq!(rx.fill(&mut b, 64).await.unwrap(), Filled::Frame);
        assert_eq!(&rx.take_wire()[..], &frame(b"second")[..]);
        drop(a);
        assert_eq!(rx.fill(&mut b, 64).await.unwrap(), Filled::Eof);
        assert_eq!(
            rx.fill(&mut b, 64).await.unwrap(),
            Filled::Eof,
            "the end is sticky"
        );
        assert_eq!(rx.fault(), Some(RxFault::Eof));
    }

    #[tokio::test]
    async fn a_dropped_fill_keeps_what_it_read() {
        let (mut a, mut b) = duplex(4096);
        let whole = frame(&[7u8; 3000]);
        let mut rx = RxBuf::default();
        // Cut at every byte boundary of the prefix and at chunk boundaries of
        // the body: each fill is dropped once the stream runs dry.
        for piece in [
            &whole[..1],
            &whole[1..3],
            &whole[3..1500],
            &whole[1500..2999],
        ] {
            a.write_all(piece).await.unwrap();
            let pending =
                tokio::time::timeout(std::time::Duration::from_millis(5), rx.fill(&mut b, 4096))
                    .await;
            assert!(pending.is_err(), "not whole yet");
        }
        assert_eq!(rx.buffered(), 2999);
        a.write_all(&whole[2999..]).await.unwrap();
        assert_eq!(rx.fill(&mut b, 4096).await.unwrap(), Filled::Frame);
        assert_eq!(&rx.take_wire()[..], &whole[..]);
    }

    #[tokio::test]
    async fn an_announcement_over_the_cap_reads_no_body_and_is_judged_again() {
        let (mut a, mut b) = duplex(4096);
        a.write_all(&frame(&[1u8; 100])).await.unwrap();
        let mut rx = RxBuf::default();
        let err = rx.fill(&mut b, 50).await.unwrap_err();
        assert!(
            matches!(err, FrameError::TooLarge { len: 100, max: 50 }),
            "{err}"
        );
        assert_eq!(
            rx.buffered(),
            HEADER_LEN,
            "the prefix is kept, no body read"
        );
        assert_eq!(rx.announced(), Some(100));
        assert!(!rx.complete());
        // A larger cap (the handshake window closed meanwhile) reads it.
        assert_eq!(rx.fill(&mut b, MAX_FRAME_LEN).await.unwrap(), Filled::Frame);
        assert_eq!(rx.take_wire().len(), HEADER_LEN + 100);
    }

    #[tokio::test]
    async fn an_end_inside_a_frame_is_truncated() {
        for cut in [1, 3, HEADER_LEN, HEADER_LEN + 2] {
            let (mut a, mut b) = duplex(64);
            a.write_all(&frame(b"abcd")[..cut]).await.unwrap();
            drop(a);
            let mut rx = RxBuf::default();
            assert!(
                matches!(rx.fill(&mut b, 64).await, Err(FrameError::Truncated)),
                "cut at {cut}"
            );
        }
        // An empty frame is whole once its prefix is in.
        let (mut a, mut b) = duplex(64);
        a.write_all(&frame(b"")).await.unwrap();
        let mut rx = RxBuf::default();
        assert_eq!(rx.fill(&mut b, 64).await.unwrap(), Filled::Frame);
        assert_eq!(&rx.take_wire()[..], &[0, 0, 0, 0]);
    }

    #[test]
    fn debug_prints_sizes_only() {
        let mut rx = RxBuf::default();
        rx.hdr = [0, 0, 0, 3];
        rx.hdr_len = HEADER_LEN;
        rx.want = Some(3);
        rx.wire.extend_from_slice(&[0, 0, 0, 3, 0xAB, 0xCD, 0xEF]);
        let shown = format!("{rx:?}");
        assert!(shown.contains("buffered: 7"), "{shown}");
        for secret in ["171", "205", "239", "AB", "ab"] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }
}
