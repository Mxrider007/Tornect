//! Interim liveness protocol behind `tornect ping` (Milestone 1, track 1).
//!
//! Client → host: one frame `"TORNECT-PING/1" ‖ nonce[8]`.
//! Host → client: one frame `"TORNECT-PONG/1" ‖ nonce[8]` echoing the nonce.
//!
//! This exists only to prove the Tor path end to end; the CBOR envelope
//! `PING`/`PONG` kinds (`docs/PLAN.md` §B.3) replace it once the envelope track
//! lands. Frames come from [`crate::framing`].

use std::io::ErrorKind;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::error::{Result, SignalError};
use crate::framing::{FrameError, read_frame, read_frame_max, write_frame};

/// Request marker.
pub const PING_MAGIC: &[u8; 14] = b"TORNECT-PING/1";
/// Reply marker.
pub const PONG_MAGIC: &[u8; 14] = b"TORNECT-PONG/1";
/// Nonce length; the reply must echo it byte for byte.
pub const NONCE_LEN: usize = 8;

/// How long [`serve`] waits for the next ping, and for a pong to go out,
/// before disconnecting the peer.
///
/// An unauthenticated peer must never hold a host-side slot indefinitely (see
/// `tor::listener`); a live Tor round trip is ~1 s, so 30 s is generous. The
/// same bound covers sending: Arti parks a write once the peer stops granting
/// flow-control credit (stream/circuit `SENDME`s), which is otherwise free for
/// a peer to withhold forever.
pub const PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest one ping session may last, however busy the peer keeps it.
///
/// The idle deadline alone lets a peer that sends a ping every few seconds
/// keep a stream — and its rendezvous circuit's slot — for as long as it likes.
/// Real pings are a handful of round trips; the budget ends the session with
/// [`SignalError::Timeout`] afterwards, whatever the peer is doing.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

/// Most pings one session answers; the session then ends with
/// [`SignalError::BudgetExhausted`]. Bounds the work a peer can extract per
/// rendezvous independently of how fast it pipelines requests.
pub const MAX_PINGS_PER_SESSION: u32 = 100;

const MAGIC_LEN: usize = PING_MAGIC.len();
const MSG_LEN: usize = MAGIC_LEN + NONCE_LEN;

/// Bounds on one [`serve`] session; see [`ServeLimits::default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeLimits {
    /// Longest wait for the next ping, and for a pong to be sent.
    pub frame_deadline: Duration,
    /// Longest a session may last in total.
    pub session_deadline: Duration,
    /// Most pings answered in one session.
    pub max_pings: u32,
}

impl Default for ServeLimits {
    /// [`PEER_IDLE_TIMEOUT`], [`SESSION_TIMEOUT`], [`MAX_PINGS_PER_SESSION`].
    fn default() -> Self {
        Self {
            frame_deadline: PEER_IDLE_TIMEOUT,
            session_deadline: SESSION_TIMEOUT,
            max_pings: MAX_PINGS_PER_SESSION,
        }
    }
}

fn message(magic: &[u8; 14], nonce: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(MSG_LEN);
    msg.extend_from_slice(magic);
    msg.extend_from_slice(nonce);
    msg
}

/// Send one ping and wait for its pong; returns the round-trip time.
///
/// The caller applies its own overall timeout (`tokio::time::timeout`).
pub async fn ping<S>(stream: &mut S, nonce: [u8; NONCE_LEN]) -> Result<Duration>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    write_frame(stream, &message(PING_MAGIC, &nonce)).await?;
    let reply = read_frame(stream).await?.ok_or_else(|| {
        SignalError::Protocol("host closed the stream before answering the ping".to_owned())
    })?;
    let rtt = start.elapsed();
    if reply.len() != MSG_LEN || reply[..MAGIC_LEN] != PONG_MAGIC[..] {
        return Err(SignalError::Protocol(
            "unexpected reply to ping (not a TORNECT-PONG/1 frame)".to_owned(),
        ));
    }
    if reply[MAGIC_LEN..] != nonce {
        return Err(SignalError::Protocol(
            "pong nonce does not match".to_owned(),
        ));
    }
    Ok(rtt)
}

/// Answer pings until the client closes the stream; returns how many were answered.
///
/// `on_answered` is invoked with the running count after each pong is flushed
/// (used by `tornect host --once`). A frame that is not a ping ends the session
/// with [`SignalError::Protocol`]; a peer that sends nothing, or accepts
/// nothing, for [`PEER_IDLE_TIMEOUT`] is disconnected with
/// [`SignalError::Timeout`], as is one still going after [`SESSION_TIMEOUT`];
/// the [`MAX_PINGS_PER_SESSION`]th pong ends the session with
/// [`SignalError::BudgetExhausted`]. The client going away — cleanly (EOF) or
/// not (Arti reports an abrupt `END` as "not connected") — ends it normally.
/// Every await in here is bounded: the caller may hold host-side resources
/// (a rendezvous circuit slot) for exactly as long as this runs.
pub async fn serve<S, F>(stream: &mut S, on_answered: F) -> Result<u32>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(u32),
{
    serve_with_limits(stream, ServeLimits::default(), on_answered).await
}

/// [`serve`] with explicit bounds. The frame deadline restarts after every
/// ping (it bounds silence and stalled sends); the session deadline and ping
/// budget bound the session as a whole.
pub async fn serve_with_limits<S, F>(
    stream: &mut S,
    limits: ServeLimits,
    mut on_answered: F,
) -> Result<u32>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(u32),
{
    let session_end = Instant::now() + limits.session_deadline;
    // Whichever of the two deadlines comes first.
    let next_deadline =
        |frame_deadline: Duration| (Instant::now() + frame_deadline).min(session_end);
    let expired = |while_: &'static str| {
        if Instant::now() >= session_end {
            SignalError::Timeout("serving pings (session time budget spent)")
        } else {
            SignalError::Timeout(while_)
        }
    };

    let mut answered = 0u32;
    loop {
        // A ping is exactly MSG_LEN bytes: refuse a larger header before
        // allocating for it.
        let read = read_frame_max(stream, MSG_LEN);
        let frame = match tokio::time::timeout_at(next_deadline(limits.frame_deadline), read).await
        {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => break,
            Ok(Err(FrameError::Io(e))) if peer_gone(&e) => {
                tracing::debug!(error = %e, "client went away without a clean close");
                break;
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(expired("waiting for the next ping")),
        };
        if frame.len() != MSG_LEN || frame[..MAGIC_LEN] != PING_MAGIC[..] {
            return Err(SignalError::Protocol(
                "unexpected frame from client (not a TORNECT-PING/1 frame)".to_owned(),
            ));
        }
        // The write is bounded too: Arti pends it for as long as the peer
        // withholds flow-control credit.
        let pong = message(PONG_MAGIC, &frame[MAGIC_LEN..]);
        let write = write_frame(stream, &pong);
        tokio::time::timeout_at(next_deadline(limits.frame_deadline), write)
            .await
            .map_err(|_| expired("sending the pong"))??;
        answered = answered.saturating_add(1);
        on_answered(answered);
        if answered >= limits.max_pings {
            return Err(SignalError::BudgetExhausted(
                "the pings one session may ask for have been answered",
            ));
        }
    }
    Ok(answered)
}

/// I/O errors that mean "the peer is gone", as opposed to a local fault.
fn peer_gone(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::NotConnected
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::MAX_FRAME_LEN;
    use tokio::io::{AsyncWriteExt as _, duplex};

    #[tokio::test]
    async fn three_pings_then_close() {
        let (mut client, mut host) = duplex(256);
        let host_task = tokio::spawn(async move {
            let mut seen = Vec::new();
            let n = serve(&mut host, |c| seen.push(c)).await.unwrap();
            (n, seen)
        });
        for i in 0..3u8 {
            let rtt = ping(&mut client, [i; NONCE_LEN]).await.unwrap();
            assert!(rtt < Duration::from_secs(5));
        }
        drop(client);
        let (n, seen) = host_task.await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(seen, vec![1, 2, 3]);
    }

    /// A stream whose reads are scripted: chunks, then one I/O error kind.
    /// With `stall_writes`, every write and flush stays pending forever — what
    /// Arti's `DataStream` does once the peer withholds flow-control credit.
    struct Scripted {
        reads: std::collections::VecDeque<std::io::Result<Vec<u8>>>,
        written: Vec<u8>,
        stall_writes: bool,
    }

    impl Scripted {
        fn new(reads: impl IntoIterator<Item = std::io::Result<Vec<u8>>>) -> Self {
            Self {
                reads: reads.into_iter().collect(),
                written: Vec::new(),
                stall_writes: false,
            }
        }
    }

    impl AsyncRead for Scripted {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.reads.pop_front() {
                Some(Ok(mut bytes)) => {
                    // Honour the caller's buffer size like a real socket would.
                    let n = buf.remaining().min(bytes.len());
                    buf.put_slice(&bytes[..n]);
                    if n < bytes.len() {
                        let rest = bytes.split_off(n);
                        self.reads.push_front(Ok(rest));
                    }
                    std::task::Poll::Ready(Ok(()))
                }
                Some(Err(e)) => std::task::Poll::Ready(Err(e)),
                None => std::task::Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for Scripted {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.stall_writes {
                return std::task::Poll::Pending;
            }
            self.written.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.stall_writes {
                return std::task::Poll::Pending;
            }
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    /// Bounds with a short per-frame deadline and everything else at its default.
    fn frame_limit(frame_deadline: Duration) -> ServeLimits {
        ServeLimits {
            frame_deadline,
            ..ServeLimits::default()
        }
    }

    #[tokio::test]
    async fn host_treats_abrupt_disconnect_as_end_of_session() {
        for kind in [
            ErrorKind::NotConnected,
            ErrorKind::ConnectionReset,
            ErrorKind::BrokenPipe,
        ] {
            let mut stream = Scripted::new([
                Ok(framed(&message(PING_MAGIC, &[3u8; NONCE_LEN]))),
                Err(std::io::Error::new(kind, "peer gone")),
            ]);
            let n = serve(&mut stream, |_| {}).await.unwrap();
            assert_eq!(n, 1, "{kind:?}");
            assert_eq!(
                stream.written,
                framed(&message(PONG_MAGIC, &[3u8; NONCE_LEN]))
            );
        }
        // but a local fault is still an error
        let mut stream = Scripted::new([Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "local",
        ))]);
        assert!(matches!(
            serve(&mut stream, |_| {}).await,
            Err(SignalError::Frame(FrameError::Io(_)))
        ));
    }

    #[tokio::test]
    async fn silent_client_is_disconnected_after_the_deadline() {
        let (client, mut host) = duplex(256);
        let started = Instant::now();
        let deadline = Duration::from_millis(50);
        let err = serve_with_limits(&mut host, frame_limit(deadline), |_| {})
            .await
            .unwrap_err();
        assert!(
            matches!(err, SignalError::Timeout(m) if m.contains("next ping")),
            "{err}"
        );
        assert!(started.elapsed() >= deadline);
        // The host dropped nothing on the wire: the client is simply cut off.
        drop(client);
    }

    #[tokio::test]
    async fn stalled_pong_write_is_cut_after_the_deadline() {
        // The peer sends a ping and then stops granting flow-control credit:
        // the pong's write never completes. Without a deadline this task —
        // and the circuit slot it holds — would live until the host restarts.
        let mut stream = Scripted::new([Ok(framed(&message(PING_MAGIC, &[5u8; NONCE_LEN])))]);
        stream.stall_writes = true;
        let deadline = Duration::from_millis(50);
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            serve_with_limits(&mut stream, frame_limit(deadline), |_| {
                panic!("a pong that never left must not count")
            }),
        )
        .await
        .expect("the stalled write must be cut, not awaited forever");
        let err = result.unwrap_err();
        assert!(
            matches!(err, SignalError::Timeout(m) if m.contains("pong")),
            "{err}"
        );
        assert!(started.elapsed() >= deadline);
        assert!(stream.written.is_empty());
    }

    #[tokio::test]
    async fn deadline_is_per_frame_not_per_session() {
        let (mut client, mut host) = duplex(256);
        let deadline = Duration::from_secs(1);
        let host_task = tokio::spawn(async move {
            serve_with_limits(&mut host, frame_limit(deadline), |_| {}).await
        });
        // Three pings spread over more than one deadline, each well inside it
        // (4× margin, so a slow CI runner cannot turn this into a flake).
        for i in 0..3u8 {
            tokio::time::sleep(deadline / 4).await;
            ping(&mut client, [i; NONCE_LEN]).await.unwrap();
        }
        drop(client);
        assert_eq!(host_task.await.unwrap().unwrap(), 3);
    }

    #[tokio::test]
    async fn chatty_client_is_cut_when_the_session_budget_is_spent() {
        // A peer that pings continuously never trips the idle deadline; the
        // session deadline ends it anyway.
        let (mut client, mut host) = duplex(256);
        let limits = ServeLimits {
            frame_deadline: Duration::from_secs(10),
            session_deadline: Duration::from_millis(100),
            max_pings: u32::MAX,
        };
        let started = Instant::now();
        let host_task =
            tokio::spawn(async move { serve_with_limits(&mut host, limits, |_| {}).await });
        let mut sent = 0u32;
        while ping(&mut client, u64::from(sent).to_be_bytes())
            .await
            .is_ok()
        {
            sent += 1;
        }
        let err = host_task.await.unwrap().unwrap_err();
        assert!(
            matches!(err, SignalError::Timeout(m) if m.contains("session")),
            "{err}"
        );
        assert!(started.elapsed() >= limits.session_deadline);
        assert!(sent > 0, "the peer was being answered until the cut");
    }

    #[tokio::test]
    async fn ping_budget_ends_the_session() {
        let (mut client, mut host) = duplex(256);
        let limits = ServeLimits {
            max_pings: 3,
            ..ServeLimits::default()
        };
        let host_task = tokio::spawn(async move {
            let mut seen = Vec::new();
            let result = serve_with_limits(&mut host, limits, |c| seen.push(c)).await;
            (result, seen)
        });
        for i in 0..3u8 {
            ping(&mut client, [i; NONCE_LEN]).await.unwrap();
        }
        let (result, seen) = host_task.await.unwrap();
        assert!(
            matches!(result, Err(SignalError::BudgetExhausted(_))),
            "{result:?}"
        );
        assert_eq!(seen, vec![1, 2, 3]);
        // The host hung up: the fourth ping cannot be answered.
        assert!(ping(&mut client, [9u8; NONCE_LEN]).await.is_err());
    }

    #[tokio::test]
    async fn host_rejects_garbage() {
        let (mut client, mut host) = duplex(256);
        let host_task = tokio::spawn(async move { serve(&mut host, |_| {}).await });
        write_frame(&mut client, b"not a ping").await.unwrap();
        let err = host_task.await.unwrap().unwrap_err();
        assert!(matches!(err, SignalError::Protocol(_)), "{err}");

        // A frame larger than a ping is refused at the header, before any
        // payload buffer exists.
        let (mut client, mut host) = duplex(256);
        let host_task = tokio::spawn(async move { serve(&mut host, |_| {}).await });
        client
            .write_all(&(MAX_FRAME_LEN as u32).to_be_bytes())
            .await
            .unwrap();
        let err = host_task.await.unwrap().unwrap_err();
        assert!(
            matches!(
                err,
                SignalError::Frame(FrameError::TooLarge { len, max })
                    if len == MAX_FRAME_LEN && max == MSG_LEN
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn client_rejects_wrong_nonce_and_wrong_magic() {
        let (mut client, mut host) = duplex(256);
        let host_task = tokio::spawn(async move {
            let req = read_frame(&mut host).await.unwrap().unwrap();
            assert_eq!(&req[..MAGIC_LEN], PING_MAGIC);
            write_frame(&mut host, &message(PONG_MAGIC, &[9u8; NONCE_LEN]))
                .await
                .unwrap();
            let _ = read_frame(&mut host).await.unwrap();
            write_frame(&mut host, &message(PING_MAGIC, &[1u8; NONCE_LEN]))
                .await
                .unwrap();
        });
        let err = ping(&mut client, [1u8; NONCE_LEN]).await.unwrap_err();
        assert!(matches!(err, SignalError::Protocol(m) if m.contains("nonce")));
        let err = ping(&mut client, [1u8; NONCE_LEN]).await.unwrap_err();
        assert!(matches!(err, SignalError::Protocol(m) if m.contains("unexpected reply")));
        host_task.await.unwrap();
    }

    #[tokio::test]
    async fn client_reports_closed_stream() {
        let (mut client, host) = duplex(256);
        drop(host);
        let err = ping(&mut client, [0u8; NONCE_LEN]).await.unwrap_err();
        // Either the write fails (broken pipe) or the read sees a clean EOF.
        assert!(
            matches!(err, SignalError::Protocol(_) | SignalError::Frame(_)),
            "{err}"
        );
    }
}
