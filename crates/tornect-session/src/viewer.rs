//! The client half of the media layer: bind a media stream to its session,
//! then decode and acknowledge what arrives.

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, watch};
use tornect_codec::{DecodedFrame, H264Decoder};
use tornect_core::config::QualityPreset;
use tornect_core::session_log::SessionMode;
use tornect_input::InputEvent;
use tornect_proto::{
    HostStats, Msg, ProtoError, QualityInfo, bind_mac, codec, read_msg, reason, video_flags,
    write_msg,
};
use tornect_signal::consent::{SessionToken, mode_from_code};

use crate::flow::KeyframeLimiter;
use crate::quality;

/// Least time between two keyframe requests from a viewer (the host keeps its
/// own, longer limit).
const KEYFRAME_REQUEST_EVERY: Duration = Duration::from_millis(500);
/// Bound on the `Close` written to a host that may not be reading.
const LAST_WRITE: Duration = Duration::from_secs(5);
/// A viewer that has written nothing for this long pings the host, so that its
/// silence means it is gone: the host lets go of held keys after a few seconds
/// of it (`MediaLimits::viewer_quiet`, SLICE-C1 C1-3).
const PING_EVERY: Duration = Duration::from_secs(1);
/// Least time, on this viewer's clock, between two of the host's `Stats`
/// handed to the [`FrameSink`] (the quality design §5.12): the host sends
/// them about once a second, and one that sends more cannot make the
/// display redraw or the terminal print faster than this.
const HOST_STATS_EVERY: Duration = Duration::from_millis(900);

/// What proves a media stream belongs to a session: the session id and the
/// bind MAC (decisions M1-39, M1-41). Both come from the handshake; the token
/// itself never leaves this process.
#[derive(Clone)]
pub struct Binding {
    session_id: String,
    mac: [u8; 32],
    quality: QualityPreset,
}

impl Binding {
    /// The binding of the session whose token is `token` and whose handshake
    /// ended at `th_final` (`ClientSession::session_token` and `th`).
    #[must_use]
    pub fn new(token: &SessionToken, th_final: &[u8; 32]) -> Self {
        Self {
            session_id: token.session_id(),
            mac: bind_mac(token.bytes(), th_final),
            quality: QualityPreset::default(),
        }
    }

    /// Ask for `preset` in the `Bind` (Balanced by default). The host maps it
    /// to its own table, bounded by its `[media]`; the byte is outside the
    /// bind MAC and can raise nothing beyond the host's caps (the quality
    /// design §4.1).
    #[must_use]
    pub fn with_quality(mut self, preset: QualityPreset) -> Self {
        self.quality = preset;
        self
    }

    /// The preset the `Bind` asks for.
    #[must_use]
    pub fn quality(&self) -> QualityPreset {
        self.quality
    }

    /// The session id.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The `Bind` frame, which asks for [`Binding::quality`].
    pub(crate) fn msg(&self) -> Msg {
        Msg::Bind {
            session_id: self.session_id.clone(),
            mac: self.mac,
            quality: quality::code(self.quality),
        }
    }
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binding")
            .field("session_id", &self.session_id)
            .field("quality", &self.quality)
            .finish_non_exhaustive()
    }
}

/// What the host's `BindOk` announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundStream {
    /// Width of the first picture, exactly as the host encodes it. Still
    /// display-only: each picture is sized from what it decodes (SLICE-A2
    /// A2-4); a picture of another size is counted
    /// ([`ViewerStats::unannounced`]).
    pub width: u32,
    /// Height of the first picture, exactly. Display-only.
    pub height: u32,
    /// Control or view-only.
    pub mode: SessionMode,
    /// The preset the host applies, with its frame-rate cap, bitrate and
    /// picture cap. Display-only.
    pub quality: QualityInfo,
}

/// Where decoded pictures go.
pub trait FrameSink: Send {
    /// Picture `seq`, decoded. Size the display from `frame`, every time: the
    /// host may change resolution at any access unit, and the sizes it
    /// announces are display-only (SLICE-A2 A2-4).
    fn picture(&mut self, seq: u32, frame: &DecodedFrame);

    /// What the host applies: the exact `width`×`height` of the pictures
    /// from here on and the preset `quality`. Called once with `BindOk`'s
    /// before the first picture, then whenever a host `Quality` changes any
    /// of them. Display-only: never size a buffer from it.
    fn quality(&mut self, _width: u32, _height: u32, _quality: &QualityInfo) {}

    /// The host's per-stage means, at most once per 900 ms of this viewer's
    /// clock (more frequent ones are counted in
    /// [`ViewerStats::stats_coalesced`]). Display-only; every value saturates.
    fn host_stats(&mut self, _stats: &HostStats) {}
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
    /// What the host last said it applies (`BindOk`, then each `Quality`).
    pub quality: Option<QualityInfo>,
    /// The host's last per-stage means (`Stats`).
    pub host: Option<HostStats>,
    /// Sum of the decodes of the pictures decoded, µs.
    pub decode_us: u64,
    /// Sum of their I420 → RGBA conversions, µs.
    pub convert_us: u64,
    /// Pictures decoded at a size other than the one last announced
    /// (`BindOk`, then each `Quality`). The host announces every size
    /// before its first picture, so this stays 0 with an honest host.
    pub unannounced: u64,
    /// Host `Stats` that came within 900 ms of the last one handed to the
    /// sink, and were kept in [`ViewerStats::host`] only.
    pub stats_coalesced: u64,
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
    /// The host speaks another version of the media stream: it refused this
    /// viewer's `Bind` as malformed (`BindRefused{PROTOCOL}`), or its
    /// `BindOk` is not this version's (the quality design §4.7).
    #[error("the other computer runs a different version of Tornect; use the same version on both")]
    Version,
}

/// A bound media stream.
pub struct MediaViewer<S> {
    rd: ReadHalf<S>,
    wr: WriteHalf<S>,
    decoder: H264Decoder,
    bound: BoundStream,
    keyframes: KeyframeLimiter,
    /// The viewer's picks, sent as `SetQuality` as they change.
    picks: Option<watch::Receiver<QualityPreset>>,
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
    ///
    /// A host of another version refuses this version's `Bind` as malformed,
    /// or answers with a `BindOk` this version cannot read: both are
    /// [`ViewerError::Version`], which says what to do about it.
    pub async fn bind(stream: S, binding: &Binding, wait: Duration) -> Result<Self, ViewerError> {
        let (mut rd, mut wr) = tokio::io::split(stream);
        write_msg(&mut wr, &binding.msg()).await?;
        let answer = match tokio::time::timeout(wait, read_msg(&mut rd)).await {
            Err(_) => return Err(ViewerError::Timeout(wait)),
            Ok(Err(ProtoError::Malformed("BindOk"))) => return Err(ViewerError::Version),
            Ok(answer) => answer?,
        };
        let bound = match answer {
            Some(Msg::BindOk {
                width,
                height,
                codec,
                mode,
                quality,
            }) => match (codec, mode_from_code(mode)) {
                (codec::H264, Some(mode)) => BoundStream {
                    width,
                    height,
                    mode,
                    quality,
                },
                _ => return Err(ViewerError::Unsupported { codec, mode }),
            },
            // A well-formed `Bind` is refused as malformed only by a host
            // that reads another length or layout.
            Some(Msg::BindRefused {
                reason: reason::PROTOCOL,
            }) => return Err(ViewerError::Version),
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
            picks: None,
        })
    }

    /// Send the host a `SetQuality` each time `picks` changes, with the value
    /// it holds then (the latest pick wins; the one it holds now counts as
    /// seen). Choosing quality never touches input: a view-only session may
    /// pick too. Once every sender is gone, nothing more is sent.
    #[must_use]
    pub fn with_quality(mut self, picks: watch::Receiver<QualityPreset>) -> Self {
        self.picks = Some(picks);
        self
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
    ///
    /// What the host says it applies (`BindOk`, then each `Quality` that
    /// changes it) and its per-stage means (`Stats`, at most one per 900 ms)
    /// go to the sink's display-only hooks; neither sizes a buffer.
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
    /// picture, until the channel closes. A change of the viewer's pick
    /// ([`with_quality`](Self::with_quality)) goes out as a `SetQuality` after
    /// the input waiting and before the next read.
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
            bound,
            mut picks,
        } = self;
        // What the host last said, and the size every picture should have.
        let mut said = (bound.width, bound.height, bound.quality);
        let mut announced = (bound.width, bound.height);
        stats.quality = Some(bound.quality);
        sink.quality(bound.width, bound.height, &bound.quality);
        let mut stats_handed: Option<tokio::time::Instant> = None;
        // One debug line per stream for pictures of a size not announced.
        let mut unannounced_said = false;
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
                pick = next_pick(&mut picks) => {
                    let Some(preset) = pick else {
                        // Every sender is gone: no more picks.
                        picks = None;
                        continue;
                    };
                    let set = Msg::SetQuality {
                        quality: quality::code(preset),
                    };
                    if !write_unless_stopped(&mut wr, &set, stop.as_mut()).await? {
                        return Ok(ViewerEnd::Stopped);
                    }
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
                            stats.decode_us =
                                stats.decode_us.saturating_add(micros(frame.timing.decode));
                            stats.convert_us = stats
                                .convert_us
                                .saturating_add(micros(frame.timing.convert));
                            if (frame.width, frame.height) != announced {
                                if !unannounced_said {
                                    unannounced_said = true;
                                    tracing::debug!(
                                        width = frame.width,
                                        height = frame.height,
                                        announced_width = announced.0,
                                        announced_height = announced.1,
                                        "a picture of a size the host did not announce"
                                    );
                                }
                                stats.unannounced += 1;
                            }
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
                // Display-only (the quality design §4.6, §5.12): neither sizes
                // a buffer nor ends the stream, and a host that repeats them
                // cannot make the sink do more than say what changed, or more
                // than one `Stats` per `HOST_STATS_EVERY`.
                Some(Msg::Quality {
                    width,
                    height,
                    quality,
                }) => {
                    stats.quality = Some(quality);
                    announced = (width, height);
                    if said != (width, height, quality) {
                        said = (width, height, quality);
                        sink.quality(width, height, &quality);
                    }
                }
                Some(Msg::Stats(host)) => {
                    stats.host = Some(host);
                    let now = tokio::time::Instant::now();
                    if stats_handed.is_some_and(|at| now.duration_since(at) < HOST_STATS_EVERY) {
                        stats.stats_coalesced += 1;
                    } else {
                        stats_handed = Some(now);
                        sink.host_stats(&host);
                    }
                }
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

/// The viewer's next pick from `picks`; `None` once every sender is gone;
/// never without `picks`.
async fn next_pick(picks: &mut Option<watch::Receiver<QualityPreset>>) -> Option<QualityPreset> {
    match picks {
        Some(rx) => match rx.changed().await {
            Ok(()) => Some(*rx.borrow_and_update()),
            Err(_) => None,
        },
        None => std::future::pending().await,
    }
}

/// `d` in whole microseconds, saturating.
fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
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
