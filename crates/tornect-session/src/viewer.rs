//! The client half of the media layer: bind a media stream to its session,
//! then decode and acknowledge what arrives.

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tornect_codec::{DecodedFrame, H264Decoder};
use tornect_core::session_log::SessionMode;
use tornect_input::InputEvent;
use tornect_proto::{
    Msg, ProtoError, bind_mac, codec, quality, read_msg, reason, video_flags, write_msg,
};
use tornect_signal::consent::{SessionToken, mode_from_code};

use crate::flow::KeyframeLimiter;

/// Least time between two keyframe requests from a viewer (the host keeps its
/// own, longer limit).
const KEYFRAME_REQUEST_EVERY: Duration = Duration::from_millis(500);
/// Bound on the `Close` written to a host that may not be reading.
const LAST_WRITE: Duration = Duration::from_secs(5);
/// A viewer that has written nothing for this long pings the host, so that its
/// silence means it is gone: the host lets go of held keys after a few seconds
/// of it (`MediaLimits::viewer_quiet`, SLICE-C1 C1-3).
const PING_EVERY: Duration = Duration::from_secs(1);

/// What proves a media stream belongs to a session: the session id and the
/// bind MAC (decisions M1-39, M1-41). Both come from the handshake; the token
/// itself never leaves this process.
#[derive(Clone)]
pub struct Binding {
    session_id: String,
    mac: [u8; 32],
}

impl Binding {
    /// The binding of the session whose token is `token` and whose handshake
    /// ended at `th_final` (`ClientSession::session_token` and `th`).
    #[must_use]
    pub fn new(token: &SessionToken, th_final: &[u8; 32]) -> Self {
        Self {
            session_id: token.session_id(),
            mac: bind_mac(token.bytes(), th_final),
        }
    }

    /// The session id.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The `Bind` frame, which asks for the Balanced preset.
    pub(crate) fn msg(&self) -> Msg {
        Msg::Bind {
            session_id: self.session_id.clone(),
            mac: self.mac,
            quality: quality::BALANCED,
        }
    }
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binding")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

/// What the host's `BindOk` announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundStream {
    /// Width of the first picture, as the host announced it. Display-only:
    /// each picture is sized from what it decodes (SLICE-A2 A2-4).
    pub width: u32,
    /// Height of the first picture, as the host announced it. Display-only.
    pub height: u32,
    /// Control or view-only.
    pub mode: SessionMode,
}

/// Where decoded pictures go.
pub trait FrameSink: Send {
    /// Picture `seq`, decoded. Size the display from `frame`, every time: the
    /// host may change resolution at any access unit, and the sizes it
    /// announces are display-only (SLICE-A2 A2-4).
    fn picture(&mut self, seq: u32, frame: &DecodedFrame);
}

/// What a viewer received.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViewerStats {
    /// Access units received.
    pub access_units: u64,
    /// Their bytes.
    pub bytes: u64,
    /// Keyframes among them.
    pub keyframes: u64,
    /// Pictures decoded.
    pub decoded: u64,
    /// Access units that did not decode.
    pub decode_errors: u64,
    /// `KeyframeRequest`s sent.
    pub keyframe_requests: u64,
    /// `Input` frames sent.
    pub input_sent: u64,
}

/// How a bound media stream ended, seen from the viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerEnd {
    /// The host sent `Close{reason}`.
    Host(u16),
    /// The host closed the stream without a `Close`.
    Closed,
    /// This side stopped (`Close{ENDED_BY_VIEWER}` was sent).
    Stopped,
}

/// Viewer failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ViewerError {
    /// The host refused the bind (`BindRefused{reason}`), or closed at once.
    #[error("the host refused the media stream (reason {0})")]
    Refused(u16),
    /// The host closed the stream without answering the bind.
    #[error("the host closed the media stream without answering")]
    Closed,
    /// No answer to the bind in time.
    #[error("the host did not answer the media bind within {} s", .0.as_secs())]
    Timeout(Duration),
    /// A frame that does not parse, or the stream failed.
    #[error(transparent)]
    Proto(#[from] ProtoError),
    /// A frame the host must not send.
    #[error("the host sent an out-of-place {0} frame")]
    Unexpected(&'static str),
    /// A `BindOk` for something this viewer cannot play.
    #[error("the host offered codec {codec} in mode {mode}, which this viewer cannot play")]
    Unsupported {
        /// The codec byte.
        codec: u8,
        /// The mode byte.
        mode: u8,
    },
    /// The decoder could not start.
    #[error("H.264 decoder: {0}")]
    Decoder(String),
}

/// A bound media stream.
pub struct MediaViewer<S> {
    rd: ReadHalf<S>,
    wr: WriteHalf<S>,
    decoder: H264Decoder,
    bound: BoundStream,
    keyframes: KeyframeLimiter,
}

impl<S> std::fmt::Debug for MediaViewer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaViewer")
            .field("bound", &self.bound)
            .finish_non_exhaustive()
    }
}

impl<S> MediaViewer<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Send the `Bind` on `stream` and wait up to `wait` for the answer.
    pub async fn bind(stream: S, binding: &Binding, wait: Duration) -> Result<Self, ViewerError> {
        let (mut rd, mut wr) = tokio::io::split(stream);
        write_msg(&mut wr, &binding.msg()).await?;
        let answer = tokio::time::timeout(wait, read_msg(&mut rd))
            .await
            .map_err(|_| ViewerError::Timeout(wait))??;
        let bound = match answer {
            Some(Msg::BindOk {
                width,
                height,
                codec,
                mode,
                ..
            }) => match (codec, mode_from_code(mode)) {
                (codec::H264, Some(mode)) => BoundStream {
                    width,
                    height,
                    mode,
                },
                _ => return Err(ViewerError::Unsupported { codec, mode }),
            },
            Some(Msg::BindRefused { reason } | Msg::Close { reason }) => {
                return Err(ViewerError::Refused(reason));
            }
            Some(other) => return Err(ViewerError::Unexpected(kind(&other))),
            None => return Err(ViewerError::Closed),
        };
        let decoder = H264Decoder::new().map_err(|e| ViewerError::Decoder(e.to_string()))?;
        Ok(Self {
            rd,
            wr,
            decoder,
            bound,
            keyframes: KeyframeLimiter::new(KEYFRAME_REQUEST_EVERY),
        })
    }

    /// What `BindOk` announced.
    #[must_use]
    pub fn bound(&self) -> &BoundStream {
        &self.bound
    }

    /// Decode and acknowledge until the host closes the stream, or until `stop`
    /// resolves (then `Close{ENDED_BY_VIEWER}` is sent). Every access unit is
    /// acknowledged once handled, decoded or not; that is the host's flow
    /// control. A decode error asks for a keyframe. Decoding runs on this task,
    /// which yields after every message: a host that sends as fast as the
    /// stream allows must not starve what the caller joins this with, such as
    /// its signaling keep-alive (SLICE-C2 C2-1). Every write races `stop`, so a
    /// host that stalls one cannot hold a stop back (SLICE-C2 C2-2 (b)). With
    /// nothing written for a second it pings, so that its silence tells the
    /// host it is gone (SLICE-C1 C1-3).
    pub async fn run<F>(
        self,
        sink: &mut dyn FrameSink,
        stats: &mut ViewerStats,
        stop: F,
    ) -> Result<ViewerEnd, ViewerError>
    where
        F: Future<Output = ()>,
    {
        self.run_with_input(sink, stats, None, stop).await
    }

    /// [`run`](Self::run), also sending each event `input` yields to the host
    /// as an `Input` frame (its 16-byte form), ahead of reading the next
    /// picture, until the channel closes.
    ///
    /// Whether a session has an input channel at all is the caller's decision,
    /// and it must be taken from the mode of the signed `SESSION_ACCEPT`
    /// (`ClientSession::accept().mode()`), never from the `BindOk` of this
    /// stream (SLICE-C2 C2-6): a view-only session passes `None` and sends no
    /// input. The host drops a view-only session's input undecoded anyway.
    pub async fn run_with_input<F>(
        self,
        sink: &mut dyn FrameSink,
        stats: &mut ViewerStats,
        mut input: Option<mpsc::Receiver<InputEvent>>,
        stop: F,
    ) -> Result<ViewerEnd, ViewerError>
    where
        F: Future<Output = ()>,
    {
        tokio::pin!(stop);
        let Self {
            rd,
            mut wr,
            mut decoder,
            mut keyframes,
            ..
        } = self;
        // The read owns the reader, so it stays pending across rounds that the
        // ping timer wins, and a frame is never cut short.
        let mut read = Box::pin(read_owned(rd));
        let mut next_ping = tokio::time::Instant::now() + PING_EVERY;
        let mut nonce = 0u64;
        loop {
            let msg = tokio::select! {
                biased;
                () = &mut stop => None,
                // Before the read: a host that keeps pictures coming must not
                // hold the viewer's input back.
                event = next_input(&mut input) => {
                    let Some(event) = event else {
                        // The caller dropped its sender: no more input.
                        input = None;
                        continue;
                    };
                    let frame = Msg::Input(event.encode());
                    if !write_unless_stopped(&mut wr, &frame, stop.as_mut()).await? {
                        return Ok(ViewerEnd::Stopped);
                    }
                    stats.input_sent += 1;
                    next_ping = tokio::time::Instant::now() + PING_EVERY;
                    continue;
                }
                (rd, msg) = &mut read => {
                    read.set(read_owned(rd));
                    Some(msg?)
                }
                () = tokio::time::sleep_until(next_ping) => {
                    nonce = nonce.wrapping_add(1);
                    let ping = Msg::Ping { nonce };
                    if !write_unless_stopped(&mut wr, &ping, stop.as_mut()).await? {
                        return Ok(ViewerEnd::Stopped);
                    }
                    next_ping = tokio::time::Instant::now() + PING_EVERY;
                    continue;
                }
            };
            let Some(msg) = msg else {
                let close = Msg::Close {
                    reason: reason::ENDED_BY_VIEWER,
                };
                let _ = tokio::time::timeout(LAST_WRITE, write_msg(&mut wr, &close)).await;
                let _ = tokio::time::timeout(LAST_WRITE, wr.shutdown()).await;
                return Ok(ViewerEnd::Stopped);
            };
            match msg {
                Some(Msg::Video {
                    seq, flags, data, ..
                }) => {
                    stats.access_units += 1;
                    stats.bytes += data.len() as u64;
                    stats.keyframes += u64::from(flags & video_flags::KEYFRAME != 0);
                    match decoder.decode(&data) {
                        Ok(Some(frame)) => {
                            stats.decoded += 1;
                            sink.picture(seq, frame);
                        }
                        // The decoder is buffering.
                        Ok(None) => {}
                        Err(e) => {
                            stats.decode_errors += 1;
                            tracing::debug!(error = %e, seq, "access unit did not decode");
                            if keyframes.allow(Instant::now()) {
                                stats.keyframe_requests += 1;
                                let ask = Msg::KeyframeRequest;
                                if !write_unless_stopped(&mut wr, &ask, stop.as_mut()).await? {
                                    return Ok(ViewerEnd::Stopped);
                                }
                            }
                        }
                    }
                    let ack = Msg::VideoAck { seq };
                    if !write_unless_stopped(&mut wr, &ack, stop.as_mut()).await? {
                        return Ok(ViewerEnd::Stopped);
                    }
                    next_ping = tokio::time::Instant::now() + PING_EVERY;
                }
                Some(Msg::Ping { nonce }) => {
                    let pong = Msg::Pong { nonce };
                    if !write_unless_stopped(&mut wr, &pong, stop.as_mut()).await? {
                        return Ok(ViewerEnd::Stopped);
                    }
                    next_ping = tokio::time::Instant::now() + PING_EVERY;
                }
                Some(Msg::Pong { .. }) => {}
                // Display-only (the quality design, §4.6): neither sizes a
                // buffer nor ends the stream.
                Some(Msg::Quality { .. } | Msg::Stats(_)) => {}
                Some(Msg::Close { reason }) => return Ok(ViewerEnd::Host(reason)),
                Some(other) => return Err(ViewerError::Unexpected(kind(&other))),
                None => return Ok(ViewerEnd::Closed),
            }
            tokio::task::yield_now().await;
        }
    }
}

/// The next event from `input`; `None` once it is closed; never without one.
async fn next_input(input: &mut Option<mpsc::Receiver<InputEvent>>) -> Option<InputEvent> {
    match input {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Read one message and hand the reader back.
async fn read_owned<R>(mut rd: R) -> (R, Result<Option<Msg>, ProtoError>)
where
    R: AsyncRead + Unpin,
{
    let msg = read_msg(&mut rd).await;
    (rd, msg)
}

/// Write `msg`, unless `stop` resolves first: `Ok(false)` when it did. A write
/// that can finish goes first. One that `stop` cuts short may leave part of a
/// frame on the stream, so the caller writes nothing more, not even its
/// `Close`: a host that stalled the write would stall that too.
async fn write_unless_stopped<W, F>(
    wr: &mut W,
    msg: &Msg,
    stop: std::pin::Pin<&mut F>,
) -> Result<bool, ViewerError>
where
    W: AsyncWrite + Unpin,
    F: Future<Output = ()>,
{
    tokio::select! {
        biased;
        written = write_msg(wr, msg) => {
            written?;
            Ok(true)
        }
        () = stop => Ok(false),
    }
}

/// A frame's name, for errors.
fn kind(msg: &Msg) -> &'static str {
    match msg {
        Msg::Bind { .. } => "Bind",
        Msg::BindOk { .. } => "BindOk",
        Msg::BindRefused { .. } => "BindRefused",
        Msg::Video { .. } => "Video",
        Msg::VideoAck { .. } => "VideoAck",
        Msg::Input(_) => "Input",
        Msg::KeyframeRequest => "KeyframeRequest",
        Msg::Ping { .. } => "Ping",
        Msg::Pong { .. } => "Pong",
        Msg::SetQuality { .. } => "SetQuality",
        Msg::Quality { .. } => "Quality",
        Msg::Stats(_) => "Stats",
        Msg::Close { .. } => "Close",
    }
}
