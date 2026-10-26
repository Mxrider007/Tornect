//! `tornect demo --loopback --headless-stats` (the quality design §3.6, G6):
//! the media pipeline measured on this computer.
//!
//! A real [`MediaHost`] and [`MediaViewer`] run in one process over an
//! in-memory pipe (`tokio::io::duplex`, 4 MiB each way), with no Tor, no
//! network and no window. The source is a synthetic card of the given size and
//! rate that notes when it took each picture, so the viewer times each picture
//! from capture to decoded and converted on the one clock both halves share.
//! Once a second a `STATS` line gives the host's stage means (from its `Stats`
//! frames, as a remote viewer sees them) and this viewer's; at the end a
//! `SUMMARY` line and a `B7` line read the run's means against `docs/PLAN.md`
//! §B.7, saying `FAIL` wherever they miss it (ground rule 3).
//!
//! This is not M3's loopback demo: it has no packetizer, FEC, jitter buffer
//! or render, and does not meet M3's acceptance. It measures the CPU stages;
//! the limits of a link come from the live run over Tor.
//!
//! The session is registered as the handshake registers an accepted one,
//! view-only, with a fresh random token: nothing here opens a desktop, an
//! injector, a listener or Tor, and nothing is read from or written to the
//! config, the keys or `sessions.log`.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;
use tornect_capture::{CaptureError, Frame, TestCard, VideoSource};
use tornect_codec::DecodedFrame;
use tornect_core::DeviceId;
use tornect_core::config::QualityPreset;
use tornect_core::levels::Elevation;
use tornect_core::session_log::SessionMode;
use tornect_input::InputSink;
use tornect_proto::HostStats;
use tornect_session::quality::QualityCaps;
use tornect_session::{
    Binding, BoundStream, FrameSink, MediaBackend, MediaEnd, MediaHost, MediaLimits, MediaOutcome,
    MediaReport, MediaViewer, NoObserver, SourceRequest, ViewerEnd, ViewerStats,
};
use tornect_signal::consent::SessionToken;
use tornect_signal::fsm::host::{LiveSession, SessionSink as _};
use tornect_signal::fsm::{OsRandom, Randomness as _};
use zeroize::Zeroize as _;

/// What any other form of `tornect demo` says (with exit code 2).
pub(crate) const ONLY_LOOPBACK: &str = "demo: only --loopback --headless-stats is available";

/// The longest side of the synthetic desktop: what the PipeWire pod lets a
/// real one be.
pub(crate) const MAX_SIDE: u32 = 8192;

/// The in-memory pipe's buffer, each way.
const PIPE: usize = 4 * 1024 * 1024;
/// Capture times kept for the viewer to look a picture's index up in.
const STAMPS: usize = 4096;
/// How often a `STATS` line is printed.
const EVERY: Duration = Duration::from_secs(1);
/// How long the viewer waits for `BindOk`.
const BIND_WAIT: Duration = Duration::from_secs(10);
/// How long past the run the viewer waits for the host to end the stream
/// before it leaves by itself (and the demo fails).
const GRACE: Duration = Duration::from_secs(10);
/// §B.7's targets, ms: capture, convert/map + encode, decode.
const B7_CAPTURE_MS: u64 = 4;
const B7_ENCODE_MS: u64 = 5;
const B7_DECODE_MS: u64 = 4;

/// `tornect demo`'s options, checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DemoOpts {
    /// The synthetic desktop's size.
    pub size: (u32, u32),
    /// Its frame rate: it delivers at that rate whatever the preset, as a
    /// desktop does at its compositor's; the encoder paces the preset's.
    pub fps: u32,
    /// The preset the viewer binds with.
    pub quality: QualityPreset,
    /// How long the stream runs after the bind.
    pub run_for: Duration,
    /// The encoder's threads (`[media] encoder_threads`: 1, 0 for
    /// automatic, 2 to 4).
    pub threads: u8,
}

/// `--size WIDTHxHEIGHT`: from the card's least size to [`MAX_SIDE`] each
/// way.
pub(crate) fn parse_size(text: &str) -> Result<(u32, u32), String> {
    let side = |s: &str| {
        s.parse::<u32>()
            .ok()
            .filter(|_| s.bytes().all(|b| b.is_ascii_digit()))
    };
    let size = text
        .split_once(['x', 'X'])
        .and_then(|(w, h)| Some((side(w)?, side(h)?)));
    match size {
        Some((w, h))
            if (tornect_capture::synthetic::MIN_WIDTH..=MAX_SIDE).contains(&w)
                && (tornect_capture::synthetic::MIN_HEIGHT..=MAX_SIDE).contains(&h) =>
        {
            Ok((w, h))
        }
        _ => Err(format!(
            "{text:?}: expected WIDTHxHEIGHT, from {}x{} to {MAX_SIDE}x{MAX_SIDE} (e.g. 1920x1080)",
            tornect_capture::synthetic::MIN_WIDTH,
            tornect_capture::synthetic::MIN_HEIGHT,
        )),
    }
}

/// Run the demo and print its lines on stdout. An error when the stream did
/// not run to its end (the numbers printed up to then stay).
pub(crate) fn run(opts: DemoOpts) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the demo's runtime")?;
    let mut print = |line: String| println!("{line}");
    runtime.block_on(demo(opts, &mut print)).map(drop)
}

/// The demo: each line goes to `out` as it is made. The [`Summary`] once
/// the host ended the stream after `opts.run_for`; an error, after the
/// summary's lines, when the stream ended any other way.
pub(crate) async fn demo(
    opts: DemoOpts,
    out: &mut (dyn FnMut(String) + Send),
) -> anyhow::Result<Summary> {
    let stamps = Arc::new(Stamps::default());
    let backend = Arc::new(DemoBackend {
        size: opts.size,
        fps: opts.fps,
        stamps: Arc::clone(&stamps),
    });
    let defaults = MediaLimits::default();
    let limits = MediaLimits {
        caps: QualityCaps {
            encoder_threads: u16::from(opts.threads),
            ..defaults.caps
        },
        ..defaults
    };
    let host = Arc::new(MediaHost::new(backend, Arc::new(NoObserver), limits));

    // A session as the handshake registers an accepted one, with a token
    // and a transcript hash of its own.
    let mut secret = [0u8; 32];
    let mut th_final = [0u8; 32];
    OsRandom
        .fill(&mut secret)
        .and_then(|()| OsRandom.fill(&mut th_final))
        .map_err(|e| anyhow::anyhow!("no random session token for the demo: {e}"))?;
    let token = SessionToken::new(secret);
    secret.zeroize();
    let session_id = token.session_id();
    host.on_start(&LiveSession {
        device: DeviceId::from_bytes([0; 32]),
        label: "demo",
        session_id: &session_id,
        token: &token,
        th_final,
        mode: SessionMode::ViewOnly,
        elevation: Elevation::None,
        unattended: false,
        transport: tornect_signal::consent::TransportPolicy::Any,
        viewer_dir1: false,
    });
    let binding = Binding::new(&token, &th_final).with_quality(opts.quality);
    drop(token);

    let (client, server) = tokio::io::duplex(PIPE);
    let served = tokio::spawn({
        let host = Arc::clone(&host);
        async move { host.serve(server).await }
    });
    let received = Arc::new(AtomicU64::new(0));
    let client = Counted {
        inner: client,
        read: Arc::clone(&received),
    };
    let viewer = MediaViewer::bind(client, &binding, BIND_WAIT)
        .await
        .context("binding the demo's media stream")?;
    let bound = *viewer.bound();
    out(start_line(&opts, &bound));

    let started = Instant::now();
    let ender = tokio::spawn({
        let host = Arc::clone(&host);
        let session_id = session_id.clone();
        async move {
            tokio::time::sleep(opts.run_for).await;
            host.on_end(&session_id, None);
        }
    });
    let mut stats = ViewerStats::default();
    let mut sink = DemoSink::new(opts.size, stamps, received, started, out);
    let viewed = viewer
        .run(
            &mut sink,
            &mut stats,
            tokio::time::sleep(opts.run_for + GRACE),
        )
        .await;
    let elapsed = started.elapsed();
    let host_ended = ender.is_finished();
    ender.abort();
    let run = sink.finish();
    let outcome = served.await.context("the demo's host task")?;
    let report = match &outcome {
        MediaOutcome::Served { report, .. } => report.clone(),
        _ => MediaReport::default(),
    };
    let summary = Summary::of(&run, &report, &stats, elapsed);
    out(summary.line());
    out(summary.b7_line());

    match viewed {
        Ok(ViewerEnd::Host(_)) => {}
        Ok(end) => anyhow::bail!("the demo's viewer ended with {end:?}, not at the host's end"),
        // The host closes its end once the session is over; a viewer still
        // behind then fails its next write to the closed pipe.
        Err(e) if host_ended && summary.lost > 0 => {
            return Err(e).context(format!(
                "the demo's viewer was {} pictures behind when the host ended the session: \
                 it takes them slower than the host sends them",
                summary.lost
            ));
        }
        Err(e) => return Err(e).context("the demo's viewer"),
    }
    match outcome {
        MediaOutcome::Served {
            end: MediaEnd::SessionOver(_),
            ..
        } => Ok(summary),
        other => anyhow::bail!("the demo's host ended with {other:?}"),
    }
}

/// `DEMO START size=1920x1080 fps=30 quality=balanced picture=1920x1080
/// threads=1`: the picture is the first one's exact size, from `BindOk`.
fn start_line(opts: &DemoOpts, bound: &BoundStream) -> String {
    format!(
        "DEMO START size={}x{} fps={} quality={} picture={}x{} threads={}",
        opts.size.0, opts.size.1, opts.fps, opts.quality, bound.width, bound.height, opts.threads
    )
}

/// The card's capture times by picture index, the latest [`STAMPS`] of them.
#[derive(Debug, Default)]
struct Stamps(Mutex<VecDeque<(u32, Instant)>>);

impl Stamps {
    fn lock(&self) -> MutexGuard<'_, VecDeque<(u32, Instant)>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, index: u32, at: Instant) {
        let mut stamps = self.lock();
        if stamps.len() == STAMPS {
            stamps.pop_front();
        }
        stamps.push_back((index, at));
    }

    /// When picture `index` was taken, if it is among the latest.
    fn captured(&self, index: u32) -> Option<Instant> {
        self.lock()
            .iter()
            .rev()
            .find(|(i, _)| *i == index)
            .map(|(_, at)| *at)
    }
}

/// The test card, noting when it took each picture. Its pictures carry their
/// index from 0, one up per picture.
struct Stamped {
    card: TestCard,
    next: u32,
    stamps: Arc<Stamps>,
}

impl VideoSource for Stamped {
    fn name(&self) -> &'static str {
        "demo card"
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let frame = self.card.next_frame(timeout)?;
        if let Some(frame) = &frame {
            self.stamps.record(self.next, frame.captured_at);
            self.next = self.next.wrapping_add(1);
        }
        Ok(frame)
    }

    fn recycle(&mut self, bgrx: Vec<u8>) {
        self.card.recycle(bgrx);
    }
}

/// The demo's host side: the stamped card, and no input anywhere.
struct DemoBackend {
    size: (u32, u32),
    fps: u32,
    stamps: Arc<Stamps>,
}

impl MediaBackend for DemoBackend {
    fn open_source(
        &self,
        _request: SourceRequest,
        _cancel: watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError> {
        Ok(Box::new(Stamped {
            card: TestCard::new(self.size.0, self.size.1, self.fps),
            next: 0,
            stamps: Arc::clone(&self.stamps),
        }))
    }

    fn open_injector(&self) -> Option<Box<dyn InputSink>> {
        None
    }
}

/// A stream that counts the bytes read from it.
struct Counted<S> {
    inner: S,
    read: Arc<AtomicU64>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        let n = buf.filled().len().saturating_sub(before);
        this.read.fetch_add(n as u64, Ordering::Relaxed);
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// What the viewer saw in one `STATS` interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Window {
    /// How long it lasted, µs.
    span_us: u64,
    /// Pictures decoded.
    pictures: u64,
    /// The last one's size.
    size: (u32, u32),
    /// Bytes read from the host.
    bytes: u64,
    /// Sums over the pictures, µs.
    decode_us: u64,
    convert_us: u64,
    /// Sum of the end-to-end times of the pictures whose index was read,
    /// and how many those were.
    e2e_us: u64,
    e2e_n: u64,
}

impl Window {
    /// `STATS t=1 fps=15.0 picture=1920x1080 kbps=1488 grab_ms=0.4 age_ms=1.1
    /// scale_ms=0.0 convert_ms=1.6 encode_ms=8.9 send_ms=0.2 ack_ms=14.0
    /// decode_ms=3.0 yuv2rgb_ms=1.1 e2e_ms=17.2`, the host's stages from its
    /// last `Stats` (`-` before the first), the rest over this window.
    fn line(&self, t: u64, host: Option<&HostStats>) -> String {
        let per_second = |n: u64| n.saturating_mul(1_000_000) / self.span_us.max(1);
        let fps_tenths = per_second(self.pictures.saturating_mul(10));
        let kbps = per_second(self.bytes.saturating_mul(8)) / 1000;
        let host_ms = |field: fn(&HostStats) -> u32| {
            host.map_or_else(|| "-".to_owned(), |h| ms(u64::from(field(h))))
        };
        format!(
            "STATS t={t} fps={}.{} picture={}x{} kbps={kbps} grab_ms={} age_ms={} scale_ms={} \
             convert_ms={} encode_ms={} send_ms={} ack_ms={} decode_ms={} yuv2rgb_ms={} e2e_ms={}",
            fps_tenths / 10,
            fps_tenths % 10,
            self.size.0,
            self.size.1,
            host_ms(|h| h.grab_us),
            host_ms(|h| h.age_us),
            host_ms(|h| h.scale_us),
            host_ms(|h| h.convert_us),
            host_ms(|h| h.encode_us),
            host_ms(|h| h.send_us),
            host_ms(|h| h.ack_us),
            ms_or_dash(self.decode_us.checked_div(self.pictures)),
            ms_or_dash(self.convert_us.checked_div(self.pictures)),
            ms_or_dash(self.e2e_us.checked_div(self.e2e_n)),
        )
    }
}

/// What the viewer saw over the whole run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Run {
    /// End-to-end times of the pictures whose index was read, µs.
    e2e_us: Vec<u64>,
    /// Decode times of every picture, µs.
    decode_us: Vec<u64>,
    /// The host's mean encode of each `Stats` handed over, µs.
    host_encode_us: Vec<u64>,
    /// Pictures whose index could not be read, or was not one the card took.
    unreadable: u64,
}

/// The viewer's side: reads each picture's index, times it end to end and
/// prints a `STATS` line about once a second.
struct DemoSink<'a> {
    source: (u32, u32),
    stamps: Arc<Stamps>,
    received: Arc<AtomicU64>,
    started: Instant,
    out: &'a mut (dyn FnMut(String) + Send),
    window: Window,
    window_since: Instant,
    window_bytes_at: u64,
    host: Option<HostStats>,
    run: Run,
}

impl<'a> DemoSink<'a> {
    fn new(
        source: (u32, u32),
        stamps: Arc<Stamps>,
        received: Arc<AtomicU64>,
        started: Instant,
        out: &'a mut (dyn FnMut(String) + Send),
    ) -> Self {
        let window_bytes_at = received.load(Ordering::Relaxed);
        Self {
            source,
            stamps,
            received,
            started,
            out,
            window: Window::default(),
            window_since: started,
            window_bytes_at,
            host: None,
            run: Run::default(),
        }
    }

    /// What the run saw.
    fn finish(self) -> Run {
        self.run
    }

    /// Picture `frame` was decoded and converted at `now`.
    fn seen(&mut self, frame: &DecodedFrame, now: Instant) {
        let decode = micros(frame.timing.decode);
        let convert = micros(frame.timing.convert);
        self.window.pictures += 1;
        self.window.size = (frame.width, frame.height);
        self.window.decode_us = self.window.decode_us.saturating_add(decode);
        self.window.convert_us = self.window.convert_us.saturating_add(convert);
        self.run.decode_us.push(decode);
        let captured = TestCard::read_index_scaled(
            &frame.rgba,
            frame.width,
            frame.height,
            self.source.0,
            self.source.1,
        )
        .and_then(|index| self.stamps.captured(index));
        match captured {
            Some(at) => {
                let e2e = micros(now.saturating_duration_since(at));
                self.window.e2e_us = self.window.e2e_us.saturating_add(e2e);
                self.window.e2e_n += 1;
                self.run.e2e_us.push(e2e);
            }
            None => self.run.unreadable += 1,
        }
        let span = now.saturating_duration_since(self.window_since);
        if span >= EVERY {
            let bytes = self.received.load(Ordering::Relaxed);
            self.window.span_us = micros(span);
            self.window.bytes = bytes.saturating_sub(self.window_bytes_at);
            let t = now.saturating_duration_since(self.started).as_secs();
            (self.out)(self.window.line(t, self.host.as_ref()));
            self.window = Window::default();
            self.window_since = now;
            self.window_bytes_at = bytes;
        }
    }
}

impl FrameSink for DemoSink<'_> {
    fn picture(&mut self, _seq: u32, frame: &DecodedFrame) {
        self.seen(frame, Instant::now());
    }

    fn host_stats(&mut self, stats: &HostStats) {
        self.host = Some(*stats);
        if stats.frames > 0 {
            self.run.host_encode_us.push(u64::from(stats.encode_us));
        }
    }
}

/// The run's numbers, as the last two lines say them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Summary {
    /// Pictures decoded.
    pub frames: u64,
    /// How long the stream ran, µs.
    pub span_us: u64,
    /// End to end, µs: the median and the 95th percentile.
    pub e2e_p50_us: Option<u64>,
    pub e2e_p95_us: Option<u64>,
    /// The median of the host's per-second mean encode times, µs: the host
    /// reports means only, never one picture's time.
    pub encode_p50_us: Option<u64>,
    /// The median decode, µs.
    pub decode_p50_us: Option<u64>,
    /// Pictures the host sent that the viewer did not decode.
    pub lost: u64,
    /// Pictures decoded whose index could not be read or matched.
    pub unreadable: u64,
    /// The host's mean capture (the card's own cost per fresh picture), µs.
    pub capture_us: Option<u64>,
    /// The host's mean scale, conversion and encode per picture, µs: the
    /// stage §B.7 calls "convert/map + encode".
    pub encode_us: Option<u64>,
    /// The viewer's mean decode, µs.
    pub decode_us: Option<u64>,
}

impl Summary {
    fn of(run: &Run, report: &MediaReport, stats: &ViewerStats, span: Duration) -> Self {
        let sorted = |v: &[u64]| {
            let mut v = v.to_vec();
            v.sort_unstable();
            v
        };
        let e2e = sorted(&run.e2e_us);
        let fresh = report.frames_sent.saturating_sub(report.repeats);
        let encode_sum = report
            .scale_us
            .saturating_add(report.convert_us)
            .saturating_add(report.encode_us);
        Self {
            frames: stats.decoded,
            span_us: micros(span),
            e2e_p50_us: percentile(&e2e, 50),
            e2e_p95_us: percentile(&e2e, 95),
            encode_p50_us: percentile(&sorted(&run.host_encode_us), 50),
            decode_p50_us: percentile(&sorted(&run.decode_us), 50),
            lost: report.frames_sent.saturating_sub(stats.decoded),
            unreadable: run.unreadable,
            capture_us: report.grab_us.checked_div(fresh),
            encode_us: encode_sum.checked_div(report.frames_sent),
            decode_us: stats.decode_us.checked_div(stats.decoded),
        }
    }

    /// `SUMMARY frames=150 fps=15.0 e2e_p50_ms=16.8 e2e_p95_ms=22.4
    /// encode_p50_ms=8.7 decode_p50_ms=2.9 lost=0 unreadable=0`.
    fn line(&self) -> String {
        let fps_tenths = self.frames.saturating_mul(10_000_000) / self.span_us.max(1);
        format!(
            "SUMMARY frames={} fps={}.{} e2e_p50_ms={} e2e_p95_ms={} encode_p50_ms={} \
             decode_p50_ms={} lost={} unreadable={}",
            self.frames,
            fps_tenths / 10,
            fps_tenths % 10,
            ms_or_dash(self.e2e_p50_us),
            ms_or_dash(self.e2e_p95_us),
            ms_or_dash(self.encode_p50_us),
            ms_or_dash(self.decode_p50_us),
            self.lost,
            self.unreadable,
        )
    }

    /// `B7 capture=0.4/4 PASS convert+encode=10.5/5 FAIL decode=3.0/4 PASS
    /// (B.7 targets are hardware, 1080p60, direct path)`: each mean against
    /// its §B.7 target; a stage with no measurement fails.
    fn b7_line(&self) -> String {
        let judge = |us: Option<u64>, target_ms: u64| {
            let verdict = match us {
                Some(us) if us <= target_ms * 1000 => "PASS",
                _ => "FAIL",
            };
            format!("{}/{target_ms} {verdict}", ms_or_dash(us))
        };
        format!(
            "B7 capture={} convert+encode={} decode={} (B.7 targets are hardware, 1080p60, \
             direct path)",
            judge(self.capture_us, B7_CAPTURE_MS),
            judge(self.encode_us, B7_ENCODE_MS),
            judge(self.decode_us, B7_DECODE_MS),
        )
    }
}

/// The `pct`th percentile of `sorted` (nearest rank); `None` when empty.
fn percentile(sorted: &[u64], pct: u64) -> Option<u64> {
    let n = sorted.len() as u64;
    let rank = (n.checked_mul(pct)?).div_ceil(100).max(1);
    sorted.get(usize::try_from(rank - 1).ok()?).copied()
}

/// µs as milliseconds with one decimal.
fn ms(us: u64) -> String {
    let tenths = us.saturating_add(50) / 100;
    format!("{}.{}", tenths / 10, tenths % 10)
}

/// [`ms`], or `-` for nothing measured.
fn ms_or_dash(us: Option<u64>) -> String {
    us.map_or_else(|| "-".to_owned(), ms)
}

/// `d` in whole microseconds, saturating.
fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_size_is_width_x_height_within_the_cards_bounds() {
        assert_eq!(parse_size("1920x1080"), Ok((1920, 1080)));
        assert_eq!(parse_size("3538X1918"), Ok((3538, 1918)));
        assert_eq!(parse_size("256x96"), Ok((256, 96)));
        assert_eq!(parse_size("8192x8192"), Ok((8192, 8192)));
        for wrong in [
            "",
            "1920",
            "1920x",
            "x1080",
            "1920*1080",
            "255x96",
            "256x95",
            "8193x100",
            "100x8193",
            "+1920x1080",
            "1920x-1080",
            "1920 x 1080",
            "0x0",
            "1920x1080x1",
        ] {
            let err = parse_size(wrong).unwrap_err();
            assert!(
                err.contains("WIDTHxHEIGHT") && err.contains("256x96"),
                "{wrong:?}: {err}"
            );
        }
    }

    #[test]
    fn percentiles_take_the_nearest_rank() {
        assert_eq!(percentile(&[], 50), None);
        assert_eq!(percentile(&[7], 50), Some(7));
        assert_eq!(percentile(&[7], 95), Some(7));
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&v, 50), Some(50));
        assert_eq!(percentile(&v, 95), Some(95));
        assert_eq!(percentile(&[1, 2, 3, 4], 50), Some(2));
        assert_eq!(percentile(&[1, 2, 3, 4], 95), Some(4));
    }

    #[test]
    fn milliseconds_carry_one_decimal() {
        assert_eq!(ms(0), "0.0");
        assert_eq!(ms(49), "0.0");
        assert_eq!(ms(50), "0.1");
        assert_eq!(ms(8_949), "8.9");
        assert_eq!(ms(14_000), "14.0");
        assert_eq!(ms(1_100_000), "1100.0");
        assert_eq!(
            ms(u64::MAX),
            "18446744073709551.6",
            "saturates, never wraps"
        );
        assert_eq!(ms_or_dash(None), "-");
    }

    /// The design's lines (§3.6), word for word for its example numbers.
    #[test]
    fn the_lines_read_as_the_design_writes_them() {
        let opts = DemoOpts {
            size: (1920, 1080),
            fps: 30,
            quality: QualityPreset::Balanced,
            run_for: Duration::from_secs(10),
            threads: 1,
        };
        let bound = BoundStream {
            width: 1920,
            height: 1080,
            mode: SessionMode::ViewOnly,
            quality: tornect_proto::QualityInfo {
                preset: tornect_proto::quality::BALANCED,
                max_fps: 15,
                kbps: 1500,
                max_long: 1920,
                max_short: 1080,
            },
        };
        assert_eq!(
            start_line(&opts, &bound),
            "DEMO START size=1920x1080 fps=30 quality=balanced picture=1920x1080 threads=1"
        );

        let window = Window {
            span_us: 1_000_000,
            pictures: 15,
            size: (1920, 1080),
            bytes: 186_000,
            decode_us: 15 * 3_000,
            convert_us: 15 * 1_100,
            e2e_us: 15 * 17_200,
            e2e_n: 15,
        };
        let host = HostStats {
            source_width: 1920,
            source_height: 1080,
            frames: 15,
            window_ms: 1000,
            grab_us: 400,
            age_us: 1_100,
            scale_us: 0,
            convert_us: 1_600,
            encode_us: 8_900,
            send_us: 200,
            ack_us: 14_000,
        };
        assert_eq!(
            window.line(1, Some(&host)),
            "STATS t=1 fps=15.0 picture=1920x1080 kbps=1488 grab_ms=0.4 age_ms=1.1 scale_ms=0.0 \
             convert_ms=1.6 encode_ms=8.9 send_ms=0.2 ack_ms=14.0 decode_ms=3.0 yuv2rgb_ms=1.1 \
             e2e_ms=17.2"
        );
        assert_eq!(
            Window::default().line(0, None),
            "STATS t=0 fps=0.0 picture=0x0 kbps=0 grab_ms=- age_ms=- scale_ms=- convert_ms=- \
             encode_ms=- send_ms=- ack_ms=- decode_ms=- yuv2rgb_ms=- e2e_ms=-"
        );

        let summary = Summary {
            frames: 150,
            span_us: 10_000_000,
            e2e_p50_us: Some(16_800),
            e2e_p95_us: Some(22_400),
            encode_p50_us: Some(8_700),
            decode_p50_us: Some(2_900),
            lost: 0,
            unreadable: 0,
            capture_us: Some(400),
            encode_us: Some(10_500),
            decode_us: Some(3_000),
        };
        assert_eq!(
            summary.line(),
            "SUMMARY frames=150 fps=15.0 e2e_p50_ms=16.8 e2e_p95_ms=22.4 encode_p50_ms=8.7 \
             decode_p50_ms=2.9 lost=0 unreadable=0"
        );
        assert_eq!(
            summary.b7_line(),
            "B7 capture=0.4/4 PASS convert+encode=10.5/5 FAIL decode=3.0/4 PASS (B.7 targets are \
             hardware, 1080p60, direct path)"
        );
        let nothing = Summary {
            capture_us: None,
            encode_us: Some(5_000),
            decode_us: Some(4_001),
            ..summary
        };
        assert_eq!(
            nothing.b7_line(),
            "B7 capture=-/4 FAIL convert+encode=5.0/5 PASS decode=4.0/4 FAIL (B.7 targets are \
             hardware, 1080p60, direct path)",
            "the target itself passes; a microsecond over it, or nothing measured, fails"
        );
    }

    /// The run's numbers: the host's means per fresh picture and per picture
    /// sent (scale, convert and encode together, the stage §B.7 names), the
    /// viewer's per picture decoded, `lost` what was sent and not decoded.
    #[test]
    fn the_summary_takes_the_means_of_the_report_and_the_viewer() {
        let run = Run {
            e2e_us: vec![30, 10, 20],
            decode_us: vec![5, 1, 3],
            host_encode_us: vec![9, 7],
            unreadable: 2,
        };
        let report = MediaReport {
            frames_sent: 12,
            repeats: 2,
            grab_us: 1_000,
            scale_us: 120,
            convert_us: 240,
            encode_us: 1_200,
            ..MediaReport::default()
        };
        let stats = ViewerStats {
            decoded: 10,
            decode_us: 50,
            ..ViewerStats::default()
        };
        let summary = Summary::of(&run, &report, &stats, Duration::from_secs(2));
        assert_eq!(
            summary,
            Summary {
                frames: 10,
                span_us: 2_000_000,
                e2e_p50_us: Some(20),
                e2e_p95_us: Some(30),
                encode_p50_us: Some(7),
                decode_p50_us: Some(3),
                lost: 2,
                unreadable: 2,
                capture_us: Some(100),
                encode_us: Some(130),
                decode_us: Some(5),
            }
        );
        let empty = Summary::of(
            &Run::default(),
            &MediaReport::default(),
            &ViewerStats::default(),
            Duration::ZERO,
        );
        assert_eq!(
            (
                empty.capture_us,
                empty.encode_us,
                empty.decode_us,
                empty.e2e_p50_us
            ),
            (None, None, None, None)
        );
        assert!(
            empty.line().starts_with("SUMMARY frames=0 fps=0.0 "),
            "{}",
            empty.line()
        );
    }

    /// The stamps keep the latest pictures only, and find each by index.
    #[test]
    fn the_stamps_keep_the_latest_pictures() {
        let stamps = Stamps::default();
        let t0 = Instant::now();
        for i in 0..(STAMPS as u32 + 10) {
            stamps.record(i, t0 + Duration::from_millis(u64::from(i)));
        }
        assert_eq!(stamps.captured(0), None, "the oldest are let go");
        assert_eq!(stamps.captured(9), None);
        assert_eq!(stamps.captured(10), Some(t0 + Duration::from_millis(10)));
        let last = STAMPS as u32 + 9;
        assert_eq!(
            stamps.captured(last),
            Some(t0 + Duration::from_millis(u64::from(last)))
        );
        assert_eq!(stamps.captured(last + 1), None);
    }

    /// The demo end to end, for a short run: a card scaled down by Best
    /// performance (1920×1080 → 1280×720) and one sent as it is; every
    /// picture sent is decoded, its index read and timed, and the lines
    /// come in their order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_short_run_prints_its_lines_and_loses_nothing() {
        for (size, quality, picture) in [
            ((1920, 1080), QualityPreset::BestPerformance, (1280, 720)),
            ((640, 360), QualityPreset::Balanced, (640, 360)),
        ] {
            let opts = DemoOpts {
                size,
                fps: 30,
                quality,
                run_for: Duration::from_millis(2500),
                threads: 1,
            };
            let mut lines = Vec::new();
            let mut out = |line: String| lines.push(line);
            let summary = demo(opts, &mut out)
                .await
                .expect("the demo runs to its end");
            let start = format!(
                "DEMO START size={}x{} fps=30 quality={quality} picture={}x{} threads=1",
                size.0, size.1, picture.0, picture.1
            );
            assert_eq!(lines.first(), Some(&start), "{lines:#?}");
            let stats: Vec<_> = lines.iter().filter(|l| l.starts_with("STATS ")).collect();
            assert!(!stats.is_empty(), "{lines:#?}");
            assert!(
                stats
                    .iter()
                    .all(|l| l.contains(&format!("picture={}x{} ", picture.0, picture.1))),
                "{stats:#?}"
            );
            let n = lines.len();
            assert!(lines[n - 2].starts_with("SUMMARY "), "{lines:#?}");
            assert!(lines[n - 1].starts_with("B7 capture="), "{lines:#?}");
            assert!(summary.frames >= 10, "{summary:?}");
            assert_eq!((summary.lost, summary.unreadable), (0, 0), "{summary:?}");
            assert!(
                summary.e2e_p50_us.is_some() && summary.capture_us.is_some(),
                "{summary:?}"
            );
        }
    }
}
