//! The client half of the media layer: bind a media stream to its session,
//! then decode and acknowledge what arrives.

use std::time::{Duration, Instant};

use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, watch};
use tornect_codec::{DecodedFrame, H264Decoder};
use tornect_core::config::QualityPreset;
use tornect_core::session_log::SessionMode;
use tornect_input::InputEvent;
use tornect_proto::{
    BindSide, HostStats, MAX_MONITORS, MonitorEntry, Msg, ProtoError, QualityInfo, bind_mac,
    bind_mac_direct, codec, monitor_status, read_msg, reason, video_flags, write_msg,
};
use tornect_signal::consent::{SessionToken, mode_from_code};
use zeroize::Zeroizing;

use crate::flow::KeyframeLimiter;
use crate::quality;

/// Least time between two keyframe requests from a viewer (the host keeps its
/// own, longer limit).
const KEYFRAME_REQUEST_EVERY: Duration = Duration::from_millis(500);
/// Bound on the `Close` written to a host that may not be reading.
const LAST_WRITE: Duration = Duration::from_secs(5);
/// Bound on the read for the host's `Close` after a write to it failed
/// ([`host_said`]).
const LAST_READ: Duration = Duration::from_secs(2);
/// A viewer that has written nothing for this long pings the host, so that its
/// silence means it is gone: the host lets go of held keys after a few seconds
/// of it (`MediaLimits::viewer_quiet`, SLICE-C1 C1-3).
const PING_EVERY: Duration = Duration::from_secs(1);
/// Least time, on this viewer's clock, between two of the host's `Stats`
/// handed to the [`FrameSink`] (the quality design §5.12): the host sends
/// them about once a second, and one that sends more cannot make the
/// display redraw or the terminal print faster than this.
const HOST_STATS_EVERY: Duration = Duration::from_millis(900);
/// How long a viewer waits for the answer to its `SelectMonitor` before it
/// gives the request up (the monitors design's V3). The host answers within
/// its own `MediaLimits::switch_answer` (15 s), so only a stalled stream
/// runs this out; an answer that comes later is the host's news.
pub const SWITCH_WAIT: Duration = Duration::from_secs(25);

/// What proves a media stream belongs to a session: the session id and the
/// bind MAC (decisions M1-39, M1-41). Both come from the handshake; the token
/// itself never leaves this process. On the direct path it also holds the
/// proof the host must answer with (the direct design §6.6).
#[derive(Clone)]
pub struct Binding {
    session_id: String,
    mac: Zeroizing<[u8; 32]>,
    /// The `BindProof` MAC a direct host must send before anything else;
    /// `None` on the onion path, which has no proof.
    expect_proof: Option<Zeroizing<[u8; 32]>>,
    quality: QualityPreset,
}

impl Binding {
    /// The binding of the session whose token is `token` and whose handshake
    /// ended at `th_final` (`ClientSession::session_token` and `th`).
    #[must_use]
    pub fn new(token: &SessionToken, th_final: &[u8; 32]) -> Self {
        Self {
            session_id: token.session_id(),
            mac: Zeroizing::new(bind_mac(token.bytes(), th_final)),
            expect_proof: None,
            quality: QualityPreset::default(),
        }
    }

    /// The binding of the same session's media stream on its direct
    /// connection, whose exporter output is `ekm`
    /// (`tornect_net::Established::binding_secret`; the direct design
    /// §6.6): the client MAC over `th_final ‖ ekm`, and the server MAC the
    /// host must prove itself with in its `BindProof`, before
    /// [`MediaViewer::bind`] reads `BindOk`, decodes a picture or sends
    /// input.
    #[must_use]
    pub fn direct(token: &SessionToken, th_final: &[u8; 32], ekm: &[u8; 32]) -> Self {
        let mac = bind_mac_direct(token.bytes(), th_final, ekm, BindSide::Client);
        let proof = bind_mac_direct(token.bytes(), th_final, ekm, BindSide::Server);
        Self {
            session_id: token.session_id(),
            mac: Zeroizing::new(mac),
            expect_proof: Some(Zeroizing::new(proof)),
            quality: QualityPreset::default(),
        }
    }

    /// Whether this binds a direct connection's stream, which the host
    /// answers with a proof first.
    #[must_use]
    pub fn is_direct(&self) -> bool {
        self.expect_proof.is_some()
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
            mac: *self.mac,
            quality: quality::code(self.quality),
        }
    }
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binding")
            .field("session_id", &self.session_id)
            .field("direct", &self.is_direct())
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

    /// The host's monitors as its last `Monitors` lists them, and why the
    /// sink hears them now ([`ScreensNews`]). A `Monitors` is the host's
    /// news or the answer to this viewer's request, and is said once each;
    /// a request given up or not sent is said with the monitors last listed.
    /// Display-only: the pictures from [`Screens::seq`] on show
    /// [`Screens::shown`], and each is still sized from what it decodes.
    fn screens(&mut self, _screens: &Screens, _news: ScreensNews) {}
}

/// What the viewer's side hands a media stream besides its pictures' sink
/// ([`MediaViewer::run_with`]). A channel left `None` carries nothing.
#[derive(Debug, Default)]
pub struct ViewerChannels {
    /// Input events, each sent as an `Input` frame. Only a Control session
    /// has one: the caller takes that from the signed `SESSION_ACCEPT`,
    /// never from `BindOk` (SLICE-C2 C2-6).
    pub input: Option<mpsc::Receiver<InputEvent>>,
    /// What the viewer asks of the host's capture. Legal in control and
    /// view-only sessions alike: choosing a screen is a viewing choice.
    pub requests: Option<mpsc::Receiver<ViewerRequest>>,
}

/// A viewer's request about what the host shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerRequest {
    /// Show monitor `id` of the host's last list, or all of them at once
    /// with [`tornect_proto::ALL_MONITORS`] (0). Sent as a `SelectMonitor`
    /// once the host has listed its monitors, one at a time (the monitors
    /// design's V1).
    ShowScreen(u8),
}

/// The host's monitors, as its last `Monitors` said them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screens {
    /// The monitors; monitor `id` is `monitors[id - 1]`. Geometry in the
    /// host desktop's units, display-only; a 0×0 size is not known.
    pub monitors: Vec<MonitorEntry>,
    /// The host can show all of them at once.
    pub all: bool,
    /// What the pictures from [`seq`](Self::seq) on show: a monitor's id, or
    /// [`tornect_proto::ALL_MONITORS`].
    pub shown: u8,
    /// The list's generation, which a request names.
    pub list: u16,
    /// The `Video` seq from which this applies.
    pub seq: u32,
    /// The pictures from `seq` on show another part of the host's desktop:
    /// input made against an earlier picture must not be sent (the monitors
    /// design's V5; the host holds such input back anyway, H5).
    pub remapped: bool,
}

/// Why a [`FrameSink`] hears [`Screens`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreensNews {
    /// The host's own news: its first list, a change of its monitors or of
    /// what it shows, or the late answer to a request this viewer gave up.
    Layout,
    /// The answer to this viewer's request for `asked`: a
    /// [`tornect_proto::monitor_status`] code. An id no list can hold
    /// (above [`tornect_proto::MAX_MONITORS`]) is answered `UNKNOWN` here,
    /// unsent.
    Answer {
        /// What was asked for.
        asked: u8,
        /// The host's status.
        status: u8,
    },
    /// No answer to the request for `asked` within [`SWITCH_WAIT`]; it is
    /// given up, and a later answer is [`ScreensNews::Layout`].
    NoAnswer {
        /// What was asked for.
        asked: u8,
    },
    /// The request for `asked` was not sent: another one is still waiting
    /// for its answer.
    NotSent {
        /// What was asked for.
        asked: u8,
    },
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
    /// `SelectMonitor`s sent.
    pub monitor_requests: u64,
    /// `Monitors` received.
    pub screens_received: u64,
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
    #[error("the host refused the media stream: {words} (reason {0})", words = media_reason(*.0))]
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
    /// On the direct path, the host's first frame was not the `BindProof`
    /// its session's token makes for this connection (the direct design
    /// §6.6): it did not prove itself, so nothing it sends is decoded and
    /// no input goes to it.
    #[error("the host did not prove it holds this session on the direct connection")]
    HostProof,
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
    ///
    /// On the direct path ([`Binding::direct`]) the host's first frame must
    /// be the `BindProof` the binding expects; a wrong or missing proof is
    /// [`ViewerError::HostProof`], before `BindOk` is read. When the bind
    /// fails there, [`after_bind_close`](crate::direct::after_bind_close)
    /// says whether the session may still fall back to the onion path.
    pub async fn bind(stream: S, binding: &Binding, wait: Duration) -> Result<Self, ViewerError> {
        let (mut rd, mut wr) = tokio::io::split(stream);
        write_msg(&mut wr, &binding.msg()).await?;
        // One deadline for the whole answer: the proof and `BindOk` on the
        // direct path (the direct design §4: the caller's bind wait covers
        // both, never the punch window).
        let deadline = tokio::time::Instant::now() + wait;
        if let Some(expected) = &binding.expect_proof {
            let first = match tokio::time::timeout_at(deadline, read_msg(&mut rd)).await {
                Err(_) => return Err(ViewerError::Timeout(wait)),
                Ok(Err(ProtoError::Malformed(_))) => return Err(ViewerError::HostProof),
                Ok(first) => first?,
            };
            match first {
                // Compared in constant time, before anything else is read.
                Some(Msg::BindProof { mac }) if bool::from(mac.ct_eq(&**expected)) => {}
                // A refusal comes instead of the proof (§6.5): its reason
                // ends the session, as on the onion path.
                Some(Msg::BindRefused {
                    reason: reason::PROTOCOL,
                }) => return Err(ViewerError::Version),
                Some(Msg::BindRefused { reason } | Msg::Close { reason }) => {
                    return Err(ViewerError::Refused(reason));
                }
                None => return Err(ViewerError::Closed),
                // A wrong proof, `BindOk` first, or anything else: the host
                // did not prove itself.
                Some(_) => return Err(ViewerError::HostProof),
            }
        }
        let answer = match tokio::time::timeout_at(deadline, read_msg(&mut rd)).await {
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
    /// resolves (then `Close{ENDED_BY_VIEWER}` is sent): [`run_with`](Self::run_with)
    /// with no input and no requests.
    pub async fn run<F>(
        self,
        sink: &mut dyn FrameSink,
        stats: &mut ViewerStats,
        stop: F,
    ) -> Result<ViewerEnd, ViewerError>
    where
        F: Future<Output = ()>,
    {
        self.run_with(sink, stats, ViewerChannels::default(), stop)
            .await
    }

    /// [`run_with`](Self::run_with) with `input` and no requests.
    pub async fn run_with_input<F>(
        self,
        sink: &mut dyn FrameSink,
        stats: &mut ViewerStats,
        input: Option<mpsc::Receiver<InputEvent>>,
        stop: F,
    ) -> Result<ViewerEnd, ViewerError>
    where
        F: Future<Output = ()>,
    {
        let channels = ViewerChannels {
            input,
            requests: None,
        };
        self.run_with(sink, stats, channels, stop).await
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
    ///
    /// Each event `channels.input` yields goes to the host as an `Input` frame
    /// (its 16-byte form), ahead of reading the next picture, until the
    /// channel closes. Whether a session has an input channel at all is the
    /// caller's decision, and it must be taken from the mode of the signed
    /// `SESSION_ACCEPT` (`ClientSession::accept().mode()`), never from the
    /// `BindOk` of this stream (SLICE-C2 C2-6): a view-only session passes
    /// `None` and sends no input. The host drops a view-only session's input
    /// undecoded anyway. A change of the viewer's pick
    /// ([`with_quality`](Self::with_quality)) goes out as a `SetQuality`
    /// after the input waiting and before the next read.
    ///
    /// Each [`ViewerRequest`] `channels.requests` yields is sent once the
    /// host has listed its monitors, so a request made before waits for the
    /// first `Monitors` (and is never sent to a host that lists none), as a
    /// `SelectMonitor` naming the last list (the monitors design's V1). One
    /// waits for its answer at a time: a request made meanwhile is not sent
    /// ([`ScreensNews::NotSent`]). An answer is the `Monitors` that carries
    /// the request's id; every other `Monitors` is the host's news (V2). With
    /// no answer in [`SWITCH_WAIT`] the request is given up
    /// ([`ScreensNews::NoAnswer`]), and its late answer is news (V3). A host's
    /// `SelectMonitor` is [`ViewerError::Unexpected`] (V4). The viewer holds
    /// no input back across a change of screen: the host's `VideoAck` barrier
    /// does that (H5), and the window adds its own hold (V5).
    pub async fn run_with<F>(
        self,
        sink: &mut dyn FrameSink,
        stats: &mut ViewerStats,
        channels: ViewerChannels,
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
        let ViewerChannels {
            mut input,
            mut requests,
        } = channels;
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
        // What the host last listed; requests wait for its first list.
        let mut screens: Option<Screens> = None;
        // The request waiting for its answer, and the last id used.
        let mut pending: Option<Pending> = None;
        let mut last_request = 0u16;
        // Every write: `stop` cutting it short ends the stream; a failed one
        // ends it as the host's frames already here say ([`host_said`]).
        macro_rules! write_or_end {
            ($frame:expr) => {
                match write_unless_stopped(&mut wr, $frame, stop.as_mut()).await {
                    Ok(true) => {}
                    Ok(false) => return Ok(ViewerEnd::Stopped),
                    Err(error) => return host_said(read, stop.as_mut(), error).await,
                }
            };
        }
        loop {
            let give_up = pending.as_ref().map(|p| p.deadline);
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
                    write_or_end!(&frame);
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
                    write_or_end!(&set);
                    next_ping = tokio::time::Instant::now() + PING_EVERY;
                    continue;
                }
                request = next_request(&mut requests), if screens.is_some() => {
                    let Some(ViewerRequest::ShowScreen(asked)) = request else {
                        // Every sender is gone: no more requests.
                        requests = None;
                        continue;
                    };
                    let Some(listed) = screens.as_ref() else {
                        continue;
                    };
                    if pending.is_some() {
                        sink.screens(listed, ScreensNews::NotSent { asked });
                        continue;
                    }
                    if usize::from(asked) > MAX_MONITORS {
                        // No list holds that id; the frame could not carry
                        // it, and the host would answer UNKNOWN.
                        let status = monitor_status::UNKNOWN;
                        sink.screens(listed, ScreensNews::Answer { asked, status });
                        continue;
                    }
                    last_request = following(last_request);
                    let select = Msg::SelectMonitor {
                        request: last_request,
                        list: listed.list,
                        monitor: asked,
                    };
                    write_or_end!(&select);
                    stats.monitor_requests += 1;
                    let now = tokio::time::Instant::now();
                    pending = Some(Pending {
                        request: last_request,
                        asked,
                        deadline: now + SWITCH_WAIT,
                    });
                    next_ping = now + PING_EVERY;
                    continue;
                }
                // Before the read: a host that keeps pictures coming must not
                // keep a request waiting past its deadline.
                () = until(give_up) => {
                    if let Some(given_up) = pending.take() {
                        tracing::debug!(
                            request = given_up.request,
                            "no answer to the screen request in time"
                        );
                        if let Some(listed) = screens.as_ref() {
                            let asked = given_up.asked;
                            sink.screens(listed, ScreensNews::NoAnswer { asked });
                        }
                    }
                    continue;
                }
                (rd, msg) = &mut read => {
                    read.set(read_owned(rd));
                    Some(msg?)
                }
                () = tokio::time::sleep_until(next_ping) => {
                    nonce = nonce.wrapping_add(1);
                    let ping = Msg::Ping { nonce };
                    write_or_end!(&ping);
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
                                write_or_end!(&ask);
                            }
                        }
                    }
                    let ack = Msg::VideoAck { seq };
                    write_or_end!(&ack);
                    next_ping = tokio::time::Instant::now() + PING_EVERY;
                }
                Some(Msg::Ping { nonce }) => {
                    let pong = Msg::Pong { nonce };
                    write_or_end!(&pong);
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
                // The host's monitors: the answer to the request waiting for
                // one (V1), or its news (V2). They size nothing; a
                // `SelectMonitor` is the viewer's own frame and ends the
                // stream below (V4).
                Some(Msg::Monitors {
                    request,
                    status,
                    shown,
                    all,
                    remapped,
                    list,
                    seq,
                    monitors,
                }) => {
                    stats.screens_received += 1;
                    let news = match pending {
                        Some(waiting) if request != 0 && request == waiting.request => {
                            pending = None;
                            ScreensNews::Answer {
                                asked: waiting.asked,
                                status,
                            }
                        }
                        _ => ScreensNews::Layout,
                    };
                    tracing::debug!(
                        request,
                        status,
                        shown,
                        of = monitors.len(),
                        remapped,
                        seq,
                        "the host's screens"
                    );
                    let listed = Screens {
                        monitors,
                        all,
                        shown,
                        list,
                        seq,
                        remapped,
                    };
                    sink.screens(&listed, news);
                    screens = Some(listed);
                }
                Some(Msg::Close { reason }) => return Ok(ViewerEnd::Host(reason)),
                Some(other) => return Err(ViewerError::Unexpected(kind(&other))),
                None => return Ok(ViewerEnd::Closed),
            }
            tokio::task::yield_now().await;
        }
    }
}

/// A `SelectMonitor` waiting for its answer.
#[derive(Debug, Clone, Copy)]
struct Pending {
    /// Its id, which the answer carries.
    request: u16,
    /// What it asked for.
    asked: u8,
    /// When it is given up ([`SWITCH_WAIT`]).
    deadline: tokio::time::Instant,
}

/// A [`tornect_proto::reason`] code in words, the one table both ends use:
/// the host's lines about a media stream that ended, and the viewer's about
/// a stream the host refused or closed. Fixed words; a code this build does
/// not know reads "unknown reason".
#[must_use]
pub fn media_reason(reason: u16) -> &'static str {
    use tornect_proto::reason as r;
    match reason {
        r::BAD_BIND => "the session did not match",
        r::CAPTURE_FAILED => "screen capture failed",
        r::ENDED_BY_HOST => "ended by the host",
        r::ENDED_BY_VIEWER => "ended by the viewer",
        r::SESSION_OVER => "the session ended",
        r::PROTOCOL => "protocol error",
        r::ENCODER_FAILED => "the video encoder failed",
        r::TRANSPORT => "the session's transport policy forbids this path",
        _ => "unknown reason",
    }
}

/// The request id after `last`: they count up from 1, wrapping, and skip 0,
/// which is the host's news.
fn following(last: u16) -> u16 {
    match last.wrapping_add(1) {
        0 => 1,
        next => next,
    }
}

/// Resolves at `deadline`; never without one.
async fn until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// The next request from `requests`; `None` once it is closed; never
/// without one.
async fn next_request(
    requests: &mut Option<mpsc::Receiver<ViewerRequest>>,
) -> Option<ViewerRequest> {
    match requests {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
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

/// How the stream ends after a write to the host failed with `error`: as
/// the host's `Close` says, when one is among the frames already on their
/// way, read through `read` (the read in progress, never cut short) for at
/// most [`LAST_READ`]; with none, or once `stop` resolves, the write's
/// error stands. A host's end can come before a frame this side writes
/// after it: on a direct QUIC stream the host's end stops this side's
/// sending half, so the `VideoAck` of a picture still unread at the end
/// fails while that `Close` is still unread.
async fn host_said<R, F, S>(
    read: F,
    stop: std::pin::Pin<&mut S>,
    error: ViewerError,
) -> Result<ViewerEnd, ViewerError>
where
    R: AsyncRead + Unpin,
    F: Future<Output = (R, Result<Option<Msg>, ProtoError>)>,
    S: Future<Output = ()>,
{
    let close = async {
        let (mut rd, mut msg) = read.await;
        loop {
            match msg {
                Ok(Some(Msg::Close { reason })) => return Some(reason),
                Ok(Some(_)) => msg = read_msg(&mut rd).await,
                Ok(None) | Err(_) => return None,
            }
        }
    };
    tokio::select! {
        biased;
        () = stop => Err(error),
        close = tokio::time::timeout(LAST_READ, close) => match close {
            Ok(Some(reason)) => Ok(ViewerEnd::Host(reason)),
            Ok(None) | Err(_) => Err(error),
        },
    }
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
        Msg::BindProof { .. } => "BindProof",
        Msg::Video { .. } => "Video",
        Msg::VideoAck { .. } => "VideoAck",
        Msg::Input(_) => "Input",
        Msg::KeyframeRequest => "KeyframeRequest",
        Msg::Ping { .. } => "Ping",
        Msg::Pong { .. } => "Pong",
        Msg::SetQuality { .. } => "SetQuality",
        Msg::Quality { .. } => "Quality",
        Msg::Stats(_) => "Stats",
        Msg::SelectMonitor { .. } => "SelectMonitor",
        Msg::Monitors { .. } => "Monitors",
        Msg::Close { .. } => "Close",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `tornect_proto::reason` code has words of its own, and the
    /// codes around them read "unknown reason"; a refusal says the words
    /// and the code (the direct design §6.6's `TRANSPORT` included).
    #[test]
    fn every_media_reason_has_its_own_words() {
        use tornect_proto::reason as r;

        let codes = [
            r::BAD_BIND,
            r::CAPTURE_FAILED,
            r::ENDED_BY_HOST,
            r::ENDED_BY_VIEWER,
            r::SESSION_OVER,
            r::PROTOCOL,
            r::ENCODER_FAILED,
            r::TRANSPORT,
        ];
        let words: Vec<&str> = codes.iter().map(|&code| media_reason(code)).collect();
        for (code, said) in codes.iter().zip(&words) {
            assert_ne!(*said, "unknown reason", "reason {code}");
        }
        let mut distinct = words.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), codes.len(), "{words:?}");
        // The codes are 1 to 8, with no gap: anything beside them is unknown.
        assert_eq!(codes.to_vec(), (1..=8).collect::<Vec<u16>>());
        for code in [0, 9, u16::MAX] {
            assert_eq!(media_reason(code), "unknown reason");
        }
        assert_eq!(
            ViewerError::Refused(r::TRANSPORT).to_string(),
            "the host refused the media stream: the session's transport policy forbids this \
             path (reason 8)"
        );
    }

    /// The monitors design's V1: request ids count up from 1, wrap, and
    /// never take 0, the host's news.
    #[test]
    fn request_ids_count_from_1_and_skip_0_when_they_wrap() {
        assert_eq!(following(0), 1);
        assert_eq!(following(1), 2);
        assert_eq!(following(u16::MAX - 1), u16::MAX);
        assert_eq!(following(u16::MAX), 1);
        let mut id = 0;
        for _ in 0..=u32::from(u16::MAX) * 2 {
            id = following(id);
            assert_ne!(id, 0);
        }
    }

    /// The viewer gives a request up only after the host has given it up:
    /// a host answers within its `switch_answer`.
    #[test]
    fn a_viewer_waits_longer_than_the_host_answers() {
        assert!(crate::MediaLimits::default().switch_answer < SWITCH_WAIT);
    }
}
