//! First-frame dispatch on the signaling port (decision M1-42).
//!
//! `tornect host` answers two protocols on [`crate::SIGNALING_PORT`]: the
//! pairing-free [`crate::ping`] liveness check and the handshake FSM
//! ([`crate::fsm::host::serve_host`]). They cannot be confused. A ping is one
//! 22-byte frame that starts with `TORNECT-PING/1`. An envelope is a CBOR array
//! of five items, so its first byte is `0x85`, never `T`, and no `HELLO` is
//! anywhere near 22 bytes.
//!
//! [`first_frame`] reads the stream's first frame whole, under one deadline and
//! the FSM's handshake frame cap, then hands the stream back with those bytes
//! put in front of it ([`Replay`]). Whichever protocol takes the stream sees
//! exactly what the peer sent, so the FSM answers every first frame — a `HELLO`,
//! garbage, or a header announcing more than the cap — byte for byte as it
//! would without the dispatch. And an unauthenticated peer holds the stream no
//! longer than before: the deadline covers the whole first frame, and the FSM
//! reads the replayed frame without waiting.

use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::framing::HEADER_LEN;
use crate::fsm::{HANDSHAKE_FRAME_CAP, timeouts};

/// How long [`first_frame`] waits for the whole first frame: the FSM's `HELLO`
/// deadline, which is also the ping protocol's per-frame deadline.
pub const FIRST_FRAME_DEADLINE: Duration = timeouts::HELLO;

// The two protocols share one first-frame deadline; neither may quietly get a
// longer one than the other allows.
const _: () = assert!(timeouts::HELLO.as_secs() == crate::ping::PEER_IDLE_TIMEOUT.as_secs());

/// What the first frame on a signaling stream turned out to be.
#[derive(Debug)]
pub enum FirstFrame<S> {
    /// A `TORNECT-PING/1` frame: serve the stream with [`crate::ping::serve`].
    Ping(Replay<S>),
    /// Anything else: serve the stream with [`crate::fsm::host::serve_host`].
    Handshake(Replay<S>),
    /// No complete first frame arrived. Nothing was sent to the peer, which is
    /// what the FSM does on these paths too.
    Gone(Gone),
}

/// Why [`first_frame`] gave up on a stream.
#[derive(Debug)]
#[non_exhaustive]
pub enum Gone {
    /// The peer closed the stream before sending a byte.
    Closed,
    /// The peer closed the stream in the middle of the first frame.
    Truncated,
    /// The first frame did not arrive within the deadline.
    Timeout,
    /// Transport error.
    Io(io::Error),
}

enum Read {
    Closed,
    Truncated,
    /// The header announced more than the handshake cap; only the header was read.
    HeaderOnly,
    Whole,
}

/// Read the first frame of `stream` within `deadline` ([`FIRST_FRAME_DEADLINE`]
/// in production) and say which protocol it belongs to.
pub async fn first_frame<S>(mut stream: S, deadline: Duration) -> FirstFrame<S>
where
    S: AsyncRead + Unpin,
{
    let mut head = Zeroizing::new(Vec::new());
    match tokio::time::timeout(deadline, read_first(&mut stream, &mut head)).await {
        Err(_) => FirstFrame::Gone(Gone::Timeout),
        Ok(Err(e)) => FirstFrame::Gone(Gone::Io(e)),
        Ok(Ok(Read::Closed)) => FirstFrame::Gone(Gone::Closed),
        Ok(Ok(Read::Truncated)) => FirstFrame::Gone(Gone::Truncated),
        Ok(Ok(Read::HeaderOnly)) => FirstFrame::Handshake(Replay::new(head, stream)),
        Ok(Ok(Read::Whole)) => {
            if crate::ping::is_ping(&head[HEADER_LEN..]) {
                FirstFrame::Ping(Replay::new(head, stream))
            } else {
                FirstFrame::Handshake(Replay::new(head, stream))
            }
        }
    }
}

async fn read_first<S>(stream: &mut S, head: &mut Vec<u8>) -> io::Result<Read>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_LEN];
    let mut filled = 0;
    while filled < HEADER_LEN {
        let n = stream.read(&mut header[filled..]).await?;
        if n == 0 {
            return Ok(if filled == 0 {
                Read::Closed
            } else {
                Read::Truncated
            });
        }
        filled += n;
    }
    head.extend_from_slice(&header);
    let len = u32::from_be_bytes(header) as usize;
    // Never buffer more than the FSM itself would accept before the handshake.
    // The FSM reads this header from the replay and refuses it with
    // `E_TOO_LARGE`, as it always has.
    if len > HANDSHAKE_FRAME_CAP {
        return Ok(Read::HeaderOnly);
    }
    head.resize(HEADER_LEN + len, 0);
    match stream.read_exact(&mut head[HEADER_LEN..]).await {
        Ok(_) => Ok(Read::Whole),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Ok(Read::Truncated),
        Err(e) => Err(e),
    }
}

/// A stream with the bytes already read from it put back in front: reads
/// drain `head` first, then continue on the stream; writes go straight
/// through. The replayed bytes are zeroized once consumed (a `HELLO` can
/// carry the emergency stop token).
pub struct Replay<S> {
    head: Zeroizing<Vec<u8>>,
    pos: usize,
    inner: S,
}

impl<S> Replay<S> {
    /// Replay `head`, then read on from `inner`.
    #[must_use]
    pub fn new(head: Zeroizing<Vec<u8>>, inner: S) -> Self {
        Self {
            head,
            pos: 0,
            inner,
        }
    }

    /// The bytes still waiting to be replayed.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.head.len() - self.pos
    }

    /// The underlying stream.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S> std::fmt::Debug for Replay<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replay")
            .field("pending", &self.pending())
            .finish_non_exhaustive()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.head.len() {
            let n = (this.head.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.head[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.head.len() {
                // Zeroized on drop, and the stream reads straight through from now on.
                this.head = Zeroizing::new(Vec::new());
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};
    use tornect_core::HostIdentity;
    use tornect_core::trusted::TrustedDevices;

    use super::*;
    use crate::envelope::{Envelope, Kind, codes};
    use crate::framing::{MAX_FRAME_LEN, read_frame, write_frame};
    use crate::fsm::host::{HostConfig, HostDeps, serve_host};
    use crate::fsm::{HandshakeError, vectors};
    use crate::messages;
    use crate::pairing::TrustedDeviceStore;
    use crate::ping::{NONCE_LEN, PING_MAGIC};

    const DEADLINE: Duration = Duration::from_secs(5);

    fn ping_frame(nonce: u8) -> Vec<u8> {
        let mut payload = PING_MAGIC.to_vec();
        payload.extend_from_slice(&[nonce; NONCE_LEN]);
        payload
    }

    fn headless_host(tmp: &std::path::Path) -> (HostConfig, HostDeps) {
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let trusted = Arc::new(TrustedDeviceStore::with(
            tmp.join("trusted-devices.toml"),
            TrustedDevices::default(),
        ));
        let deps = HostDeps::headless(identity, trusted);
        (HostConfig::new("Desk", vectors::host_device_pk()), deps)
    }

    /// Reads from the replay return the frame that was consumed, then the rest
    /// of the stream, however small the reader's buffer.
    #[tokio::test]
    async fn replay_returns_the_first_frame_then_the_stream() {
        let (mut peer, host) = duplex(1024);
        write_frame(&mut peer, &ping_frame(7)).await.unwrap();
        write_frame(&mut peer, b"second").await.unwrap();
        let FirstFrame::Ping(mut replay) = first_frame(host, DEADLINE).await else {
            panic!("a ping frame is a ping");
        };
        assert_eq!(replay.pending(), HEADER_LEN + ping_frame(7).len());
        let mut got = Vec::new();
        let mut small = [0u8; 3];
        while got.len() < 2 * HEADER_LEN + ping_frame(7).len() + 6 {
            let n = replay.read(&mut small).await.unwrap();
            assert!(n > 0, "no premature EOF at the replay boundary");
            got.extend_from_slice(&small[..n]);
        }
        let mut want = (22u32).to_be_bytes().to_vec();
        want.extend_from_slice(&ping_frame(7));
        want.extend_from_slice(&6u32.to_be_bytes());
        want.extend_from_slice(b"second");
        assert_eq!(got, want);
        assert_eq!(replay.pending(), 0);
        // Writes go straight through.
        replay.write_all(b"back").await.unwrap();
        let mut back = [0u8; 4];
        peer.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"back");
    }

    /// The ping protocol, served on the replay, answers the ping the dispatch
    /// consumed and every later one.
    #[tokio::test]
    async fn a_ping_stream_is_answered_by_the_ping_protocol() {
        let (mut client, host) = duplex(1024);
        let host_task = tokio::spawn(async move {
            match first_frame(host, DEADLINE).await {
                FirstFrame::Ping(mut s) => crate::ping::serve(&mut s, |_| {}).await,
                other => panic!("expected a ping, got {other:?}"),
            }
        });
        for i in 0..3u8 {
            crate::ping::ping(&mut client, [i; NONCE_LEN])
                .await
                .unwrap();
        }
        drop(client);
        assert_eq!(host_task.await.unwrap().unwrap(), 3);
    }

    /// A 22-byte frame is only a ping if it carries the magic, and a ping-shaped
    /// payload of the wrong length is not a ping either.
    #[tokio::test]
    async fn only_the_exact_ping_frame_goes_to_the_ping_protocol() {
        let mut not_magic = ping_frame(1);
        not_magic[0] = b'X';
        let mut long = ping_frame(1);
        long.push(0);
        for payload in [not_magic, long, ping_frame(1)[..21].to_vec(), Vec::new()] {
            let (mut peer, host) = duplex(1024);
            write_frame(&mut peer, &payload).await.unwrap();
            assert!(
                matches!(first_frame(host, DEADLINE).await, FirstFrame::Handshake(_)),
                "{payload:?}"
            );
        }
    }

    /// A frame the dispatch refuses to buffer still reaches the FSM, which
    /// answers `ERROR{E_TOO_LARGE}` exactly as it does without the dispatch.
    #[tokio::test]
    async fn an_oversize_first_frame_gets_the_fsms_own_answer() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, deps) = headless_host(tmp.path());
        let (mut peer, host) = duplex(1024);
        peer.write_all(&(MAX_FRAME_LEN as u32).to_be_bytes())
            .await
            .unwrap();
        let FirstFrame::Handshake(replay) = first_frame(host, DEADLINE).await else {
            panic!("an oversize frame belongs to the FSM");
        };
        assert_eq!(replay.pending(), HEADER_LEN, "only the header was read");
        let err = serve_host(replay, &cfg, &deps).await.unwrap_err();
        assert_eq!(err.violation_code(), Some(codes::E_TOO_LARGE), "{err}");
        let answer = read_frame(&mut peer).await.unwrap().unwrap();
        let env = Envelope::decode(&answer).unwrap();
        assert_eq!(env.kind, Kind::Error);
        let body: messages::Error = messages::decode_body(&env.body).unwrap();
        assert_eq!(body.code, codes::E_TOO_LARGE);
    }

    /// Garbage that is not a ping is the FSM's to answer, and it does.
    #[tokio::test]
    async fn garbage_gets_the_fsms_error_answer() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, deps) = headless_host(tmp.path());
        let (mut peer, host) = duplex(1024);
        write_frame(&mut peer, b"not a ping, not cbor")
            .await
            .unwrap();
        let FirstFrame::Handshake(replay) = first_frame(host, DEADLINE).await else {
            panic!("garbage belongs to the FSM");
        };
        let err = serve_host(replay, &cfg, &deps).await.unwrap_err();
        assert!(err.violation_code().is_some(), "{err}");
        let env = Envelope::decode(&read_frame(&mut peer).await.unwrap().unwrap()).unwrap();
        assert_eq!(env.kind, Kind::Error);
    }

    #[tokio::test]
    async fn a_peer_that_leaves_early_is_gone_without_an_answer() {
        let (peer, host) = duplex(64);
        drop(peer);
        assert!(matches!(
            first_frame(host, DEADLINE).await,
            FirstFrame::Gone(Gone::Closed)
        ));

        let (mut peer, host) = duplex(64);
        peer.write_all(&[0, 0]).await.unwrap();
        drop(peer);
        assert!(matches!(
            first_frame(host, DEADLINE).await,
            FirstFrame::Gone(Gone::Truncated)
        ));

        let (mut peer, host) = duplex(64);
        peer.write_all(&10u32.to_be_bytes()).await.unwrap();
        peer.write_all(b"four").await.unwrap();
        drop(peer);
        assert!(matches!(
            first_frame(host, DEADLINE).await,
            FirstFrame::Gone(Gone::Truncated)
        ));
    }

    /// One deadline covers the whole first frame: a peer that sends a header
    /// and then goes quiet is dropped at the deadline, not handed to the FSM
    /// with a fresh one (which would double how long it can hold the stream).
    #[tokio::test(start_paused = true)]
    async fn one_deadline_covers_the_whole_first_frame() {
        let (mut peer, host) = duplex(64);
        peer.write_all(&100u32.to_be_bytes()).await.unwrap();
        peer.write_all(&[0u8; 50]).await.unwrap();
        let started = tokio::time::Instant::now();
        assert!(matches!(
            first_frame(host, FIRST_FRAME_DEADLINE).await,
            FirstFrame::Gone(Gone::Timeout)
        ));
        let waited = started.elapsed();
        assert!(
            waited >= FIRST_FRAME_DEADLINE
                && waited < FIRST_FRAME_DEADLINE + Duration::from_secs(1),
            "{waited:?}"
        );
        drop(peer);
    }

    /// The whole FSM runs over the replay: the first-frame dispatch changes
    /// nothing a client can see.
    #[tokio::test]
    async fn a_hello_stream_runs_the_handshake_over_the_replay() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, deps) = headless_host(tmp.path());
        let host_id = HostIdentity::from_seed(&[0x11; 32]).id();
        let (client_end, host_end) = duplex(64 * 1024);
        let host_task = tokio::spawn(async move {
            match first_frame(host_end, DEADLINE).await {
                FirstFrame::Handshake(s) => serve_host(s, &cfg, &deps).await,
                other => panic!("expected a handshake, got {other:?}"),
            }
        });
        let known = Arc::new(crate::pairing::KnownHostStore::with(
            tmp.path().join("known-hosts.toml"),
            tornect_core::trusted::KnownHosts::default(),
        ));
        let client_deps = crate::fsm::client::ClientDeps::headless(known);
        let identity = tornect_core::DeviceIdentity::from_seed(&[0x22; 32]);
        let ccfg = crate::fsm::client::ClientConfig::new(host_id, "Laptop");
        // The headless host denies every pairing: the client gets the FSM's
        // PAIR_REJECT{DENIED}, proving HELLO, HELLO_ACK and PAIR_REQUEST all
        // crossed the replay intact.
        let err = crate::fsm::client::connect(
            client_end,
            &ccfg,
            &identity,
            &client_deps,
            crate::fsm::client::Intent::Session,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                HandshakeError::PairRejected {
                    reason: messages::pair_reject::DENIED,
                    ..
                }
            ),
            "{err}"
        );
        assert!(host_task.await.unwrap().is_ok());
    }
}
