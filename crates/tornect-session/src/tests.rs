//! The media layer end to end over in-process pipes: the requirements of
//! SLICE-A2 A2-3/A2-4/A2-6 and SLICE-A1 G3, each pinned by a test, and one
//! run through the real handshake FSM.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{
    AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, ReadHalf, SimplexStream, WriteHalf,
    duplex, simplex,
};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tornect_capture::{CaptureError, Frame, TestCard, VideoSource};
use tornect_codec::scale::{ResolutionCap, picture_size, shown_region};
use tornect_codec::{DecodedFrame, EncoderSettings, H264Decoder, H264Encoder};
use tornect_core::config::QualityPreset;
use tornect_core::session_log::SessionMode;
use tornect_core::{DeviceId, DeviceIdentity, HostIdentity};
use tornect_input::{Button, InputError, InputEvent, InputSink};
use tornect_proto::{
    HostStats, Msg, QualityInfo, codec, quality, read_msg, reason, video_flags, write_msg,
};
use tornect_signal::consent::SessionToken;
use tornect_signal::fsm::client::{
    self, ClientConfig, ClientDeps, ClientOutcome, Intent, ScriptedClientUi, SessionEvent,
};
use tornect_signal::fsm::host::{
    HostConfig, HostDeps, LiveSession, SessionEnd, SessionSink, serve_host,
};
use tornect_signal::messages::bye;
use tornect_signal::pairing::{
    KnownHostStore, PairDecision, PairScript, ScriptedConsent, SessionDecision, SessionScript,
    TrustedDeviceStore,
};

use crate::viewer::BoundStream;
use crate::*;

const WAIT: Duration = Duration::from_secs(10);
const KEY_A: u32 = 0x07_0004;
/// What a host applies to a stream bound with Balanced, the preset a
/// `Binding` asks for (the table under the default caps: the 1080p cap,
/// 15 fps, 1500 kbit/s), and what the scripted hosts here say in their
/// `BindOk`.
const APPLIED: QualityInfo = QualityInfo {
    preset: quality::BALANCED,
    max_fps: 15,
    kbps: 1500,
    max_long: 1920,
    max_short: 1080,
};
/// Best quality under the default caps: the codec's cap, 12 fps, the Tor
/// bitrate (4000 kbit/s).
const BEST_QUALITY: QualityInfo = QualityInfo {
    preset: quality::BEST_QUALITY,
    max_fps: 12,
    kbps: 4000,
    max_long: 3840,
    max_short: 2160,
};
/// Best performance under the default caps: the 720p cap, 20 fps,
/// 1000 kbit/s.
const BEST_PERFORMANCE: QualityInfo = QualityInfo {
    preset: quality::BEST_PERFORMANCE,
    max_fps: 20,
    kbps: 1000,
    max_long: 1280,
    max_short: 720,
};

/// A test card that says when it was closed.
struct Card {
    inner: TestCard,
    closed: Arc<AtomicBool>,
    /// While set, the card has no new picture, as GDI has none while a
    /// secure Windows screen shows: it waits the timeout and says so.
    stalled: Arc<AtomicBool>,
    /// Buffers handed back by the pipeline.
    recycled: Arc<AtomicUsize>,
}

impl VideoSource for Card {
    fn name(&self) -> &'static str {
        "card"
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        if self.stalled.load(Ordering::SeqCst) {
            std::thread::sleep(timeout);
            return Ok(None);
        }
        self.inner.next_frame(timeout)
    }

    fn recycle(&mut self, bgrx: Vec<u8>) {
        self.recycled.fetch_add(1, Ordering::SeqCst);
        self.inner.recycle(bgrx);
    }
}

impl Drop for Card {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

/// Records what is injected.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<InputEvent>>>);

impl Recorder {
    fn events(&self) -> Vec<InputEvent> {
        self.0.lock().unwrap().clone()
    }
}

impl InputSink for Recorder {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        self.0.lock().unwrap().push(*event);
        Ok(())
    }
}

#[derive(Default)]
struct TestBackend {
    fail: bool,
    closed: Arc<AtomicBool>,
    sources: AtomicUsize,
    injectors: AtomicUsize,
    recorder: Recorder,
    /// What an injector is built from, kept when a source opens, as the
    /// Wayland backend keeps its portal session's input handle.
    input: Mutex<Option<Recorder>>,
    /// Opening waits, as the desktop's dialog does, until its cancel turns
    /// `true` or 10 s.
    open_waits: bool,
    /// An open ended because its cancel turned `true`.
    cancelled: AtomicBool,
    /// Holds the source's pictures back while set ([`Card::stalled`]).
    stalled: Arc<AtomicBool>,
    /// Buffers the pipeline handed back to the card ([`Card::recycled`]).
    recycled: Arc<AtomicUsize>,
    /// The open keeps nothing to build an injector from, as on a Wayland
    /// host whose dialog left remote interaction off.
    no_injector: bool,
    /// The source the open returns instead of the card, taken by the first
    /// open.
    desktop: Mutex<Option<Box<dyn VideoSource>>>,
    /// What each open was asked for, in order.
    requests: Mutex<Vec<SourceRequest>>,
    /// The card's size; `None` for 256×96.
    card: Option<(u32, u32)>,
}

/// The desktop's dialog: up until `cancel` turns `true` (then `true`), or for
/// [`WAIT`].
fn dialog(cancel: &tokio::sync::watch::Receiver<bool>) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < WAIT {
        if *cancel.borrow() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

impl MediaBackend for TestBackend {
    fn open_source(
        &self,
        request: SourceRequest,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError> {
        self.sources.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().unwrap().push(request);
        if self.fail {
            return Err(CaptureError::Unavailable("no screen here".into()));
        }
        if self.open_waits && dialog(&cancel) {
            self.cancelled.store(true, Ordering::SeqCst);
            return Err(CaptureError::Unavailable("the session ended".into()));
        }
        if !self.no_injector {
            *self.input.lock().unwrap() = Some(self.recorder.clone());
        }
        if let Some(desktop) = self.desktop.lock().unwrap().take() {
            return Ok(desktop);
        }
        let (width, height) = self.card.unwrap_or((256, 96));
        Ok(Box::new(Card {
            // Faster than any preset's rate, so the encoder sets the pace.
            inner: TestCard::new(width, height, 60),
            closed: Arc::clone(&self.closed),
            stalled: Arc::clone(&self.stalled),
            recycled: Arc::clone(&self.recycled),
        }))
    }

    fn open_injector(&self) -> Option<Box<dyn InputSink>> {
        let input = self.input.lock().unwrap().take()?;
        self.injectors.fetch_add(1, Ordering::SeqCst);
        Some(Box::new(input))
    }

    fn view_only(&self) {
        self.input.lock().unwrap().take();
    }
}

#[derive(Default)]
struct Seen(Mutex<Vec<String>>);

impl Seen {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

impl MediaObserver for Seen {
    fn capture_started(&self, s: &CaptureStarted<'_>) {
        self.0.lock().unwrap().push(format!(
            "started {} {}x{} {:?} input={}",
            s.source, s.width, s.height, s.mode, s.input
        ));
    }

    fn capture_stopped(&self, _: &str, _: &MediaReport, end: &MediaEnd) {
        self.0.lock().unwrap().push(format!("stopped {end:?}"));
    }
}

struct Rig {
    host: Arc<MediaHost>,
    backend: Arc<TestBackend>,
    seen: Arc<Seen>,
}

fn rig(limits: MediaLimits) -> Rig {
    rig_with(TestBackend::default(), limits)
}

fn rig_with(backend: TestBackend, limits: MediaLimits) -> Rig {
    let backend = Arc::new(backend);
    let seen = Arc::new(Seen::default());
    Rig {
        host: Arc::new(MediaHost::new(backend.clone(), seen.clone(), limits)),
        backend,
        seen,
    }
}

/// Register a session as the FSM does, and return what its viewer binds with.
fn start(host: &MediaHost, seed: u8, mode: SessionMode) -> (String, Binding) {
    let token = SessionToken::new([seed; 32]);
    let th_final = [!seed; 32];
    let session_id = token.session_id();
    host.on_start(&LiveSession {
        device: DeviceId::from_bytes([seed; 32]),
        label: "Laptop",
        session_id: &session_id,
        token: &token,
        th_final,
        mode,
        elevation: tornect_core::levels::Elevation::None,
        unattended: false,
    });
    (session_id, Binding::new(&token, &th_final))
}

/// A media stream to `host`, served on its own task.
fn connect(host: &Arc<MediaHost>) -> (DuplexStream, JoinHandle<MediaOutcome>) {
    let (client, server) = duplex(1 << 20);
    let host = Arc::clone(host);
    (
        client,
        tokio::spawn(async move { host.serve(server).await }),
    )
}

/// The viewer's end of [`connect_narrow`].
type NarrowPipe = tokio::io::Join<ReadHalf<SimplexStream>, WriteHalf<SimplexStream>>;

/// [`connect`] over a pipe that holds only 16 bytes toward the viewer and
/// 64 KiB toward the host: once the viewer stops reading, the host's next
/// `Video` write waits for good (a pipe has no stall timer), while what the
/// viewer writes never waits.
fn connect_narrow(host: &Arc<MediaHost>) -> (NarrowPipe, JoinHandle<MediaOutcome>) {
    let (viewer_rd, host_wr) = simplex(16);
    let (host_rd, viewer_wr) = simplex(64 * 1024);
    let host = Arc::clone(host);
    (
        tokio::io::join(viewer_rd, viewer_wr),
        tokio::spawn(async move { host.serve(tokio::io::join(host_rd, host_wr)).await }),
    )
}

/// Bind by hand and return `BindOk`'s mode byte.
async fn bind_raw<S>(client: &mut S, binding: &Binding) -> u8
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    write_msg(client, &binding.msg()).await.unwrap();
    match read_msg(client).await.unwrap() {
        Some(Msg::BindOk { mode, .. }) => mode,
        other => panic!("expected BindOk, got {other:?}"),
    }
}

/// The next `Video` frame's `(seq, flags)`, skipping anything else.
async fn next_video(client: &mut DuplexStream) -> (u32, u8) {
    loop {
        match tokio::time::timeout(WAIT, read_msg(client))
            .await
            .unwrap()
            .unwrap()
        {
            Some(Msg::Video { seq, flags, .. }) => return (seq, flags),
            Some(_) => {}
            None => panic!("stream closed"),
        }
    }
}

/// Read until `Close` (its reason) or the end of the stream (`None`).
async fn until_close(client: &mut DuplexStream) -> Option<u16> {
    loop {
        match tokio::time::timeout(WAIT, read_msg(client))
            .await
            .unwrap()
            .unwrap()
        {
            Some(Msg::Close { reason }) => return Some(reason),
            Some(_) => {}
            None => return None,
        }
    }
}

/// A round trip: once the `Pong` is back, the host has handled everything
/// sent before the `Ping`.
async fn sync(client: &mut DuplexStream, nonce: u64) {
    write_msg(client, &Msg::Ping { nonce }).await.unwrap();
    loop {
        match tokio::time::timeout(WAIT, read_msg(client))
            .await
            .unwrap()
            .unwrap()
        {
            Some(Msg::Pong { nonce: n }) if n == nonce => return,
            Some(_) => {}
            None => panic!("stream closed"),
        }
    }
}

/// Collects the card indices of what it decodes; says when it has `want`.
#[derive(Default)]
struct Pictures {
    indices: Vec<u32>,
    sizes: Vec<(u32, u32)>,
    want: usize,
    done: Option<oneshot::Sender<()>>,
}

impl Pictures {
    fn wanting(want: usize) -> (Self, oneshot::Receiver<()>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                want,
                done: Some(tx),
                ..Self::default()
            },
            rx,
        )
    }
}

impl FrameSink for Pictures {
    fn picture(&mut self, _seq: u32, frame: &DecodedFrame) {
        self.sizes.push((frame.width, frame.height));
        // RGBA keeps green at offset 1, as BGRx does.
        if let Some(index) = TestCard::read_index(&frame.rgba, frame.width, frame.height) {
            self.indices.push(index);
        }
        if self.indices.len() >= self.want
            && let Some(done) = self.done.take()
        {
            let _ = done.send(());
        }
    }
}

/// The card goes out in order and comes back decoded, every picture, sized
/// from the pictures themselves; capture stops when the viewer leaves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_test_card_reaches_the_viewer_in_order() {
    let rig = rig(MediaLimits::default());
    let (_, binding) = start(&rig.host, 1, SessionMode::Control);
    let (client, served) = connect(&rig.host);
    let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
    assert_eq!(
        *viewer.bound(),
        BoundStream {
            width: 256,
            height: 96,
            mode: SessionMode::Control
        }
    );
    let (mut pictures, done) = Pictures::wanting(10);
    let mut stats = ViewerStats::default();
    let end = viewer
        .run(&mut pictures, &mut stats, async {
            let _ = done.await;
        })
        .await
        .unwrap();
    assert_eq!(end, ViewerEnd::Stopped);

    assert!(pictures.indices.len() >= 10, "{:?}", pictures.indices);
    assert_eq!(
        pictures.indices[0], 0,
        "the first picture is the first captured"
    );
    for pair in pictures.indices.windows(2) {
        assert_eq!(
            pair[1],
            pair[0] + 1,
            "in order, none lost: {:?}",
            pictures.indices
        );
    }
    assert!(pictures.sizes.iter().all(|&size| size == (256, 96)));
    assert_eq!(stats.decode_errors, 0);
    assert!(stats.keyframes >= 1, "the stream starts with an IDR");

    let MediaOutcome::Served { report, end, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!(end, MediaEnd::ViewerLeft);
    assert!(report.frames_sent >= 10);
    assert!(rig.backend.closed.load(Ordering::SeqCst), "capture stopped");
    assert_eq!(
        rig.seen.lines(),
        [
            "started card 256x96 Control input=true",
            "stopped ViewerLeft"
        ]
    );
}

/// Every picture's buffer goes back to its source once a newer picture
/// replaces it, so a source that paints or packs into a buffer given back
/// allocates no memory per picture. The last one is kept, for a quality
/// change to encode again on a still screen (the design §6.6), and goes with
/// the source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_picture_buffer_goes_back_to_the_source() {
    let rig = rig(MediaLimits::default());
    let (_, binding) = start(&rig.host, 1, SessionMode::Control);
    let (client, served) = connect(&rig.host);
    let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
    let (mut pictures, done) = Pictures::wanting(5);
    let mut stats = ViewerStats::default();
    viewer
        .run(&mut pictures, &mut stats, async {
            let _ = done.await;
        })
        .await
        .unwrap();
    let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert!(report.frames_sent >= 5);
    let recycled = rig.backend.recycled.load(Ordering::SeqCst) as u64;
    assert!(
        recycled + 1 >= report.frames_sent,
        "{recycled} buffers back for {} pictures sent",
        report.frames_sent
    );
}

/// Two side-by-side 4K screens, 7681×2161 with an odd last column and row:
/// the left screen blue, the right one red, the odd column and row white.
/// One picture, then a still screen.
struct TwoScreens(bool);

impl TwoScreens {
    const SIZE: (u32, u32) = (7681, 2161);
}

impl VideoSource for TwoScreens {
    fn name(&self) -> &'static str {
        "two screens"
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        if std::mem::replace(&mut self.0, true) {
            std::thread::sleep(timeout);
            return Ok(None);
        }
        let (w, h) = Self::SIZE;
        let mut bgrx = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                let px: [u8; 4] = if x == w - 1 || y == h - 1 {
                    [255, 255, 255, 255]
                } else if x < w / 2 {
                    [200, 40, 40, 255]
                } else {
                    [40, 40, 200, 255]
                };
                bgrx.extend_from_slice(&px);
            }
        }
        Ok(Some(Frame {
            width: w,
            height: h,
            bgrx,
            captured_at: std::time::Instant::now(),
            grab: Duration::ZERO,
        }))
    }
}

/// Keeps the first decoded picture.
struct FirstPicture(Option<DecodedFrame>, Option<oneshot::Sender<()>>);

impl FrameSink for FirstPicture {
    fn picture(&mut self, _seq: u32, frame: &DecodedFrame) {
        if self.0.is_none() {
            self.0 = Some(frame.clone());
            if let Some(done) = self.1.take() {
                let _ = done.send(());
            }
        }
    }
}

/// Asserts that `frame` shows [`TwoScreens`] whole, at `picture`: the left
/// screen from the left edge, the right one up to the right edge, and none of
/// the odd last column and row (white), which the shown region leaves out.
fn assert_two_screens_whole(frame: &DecodedFrame, picture: (u32, u32)) {
    assert_eq!((frame.width, frame.height), picture);
    let rgba = |x: u32, y: u32| {
        let at = ((y * frame.width + x) * 4) as usize;
        [frame.rgba[at], frame.rgba[at + 1], frame.rgba[at + 2]]
    };
    let blue = |[r, g, b]: [u8; 3]| b > 150 && r < 90 && g < 90;
    let red = |[r, g, b]: [u8; 3]| r > 150 && g < 90 && b < 90;
    let (w, h) = picture;
    for y in [0, h / 2, h - 1] {
        assert!(blue(rgba(0, y)), "left edge, row {y}: {:?}", rgba(0, y));
        assert!(blue(rgba(w / 2 - 8, y)), "left screen, row {y}");
        assert!(red(rgba(w / 2 + 8, y)), "right screen, row {y}");
        assert!(
            red(rgba(w - 1, y)),
            "the right screen reaches the right edge, with no white: {:?}",
            rgba(w - 1, y)
        );
    }
    for x in [0, w / 4, w - 1] {
        let px = rgba(x, h - 1);
        assert!(blue(px) || red(px), "no white in the last row: {px:?}");
    }
}

/// Decision M1-74 (3): a desktop above the codec's maximum is scaled whole
/// into the picture instead of cropped to its top-left 3840×2160, so the
/// picture shows exactly the `shown_region` the injectors map the pointer
/// over: the right screen reaches the picture's right edge, and the odd last
/// column and row never reach it. `BindOk` and the sharing indicator give
/// the scaled size. Under Best quality the cap is the codec's own (3840×1080
/// here, as before the presets); under Balanced, which a `Binding` asks for,
/// it is 1920×1080 (1920×540 here).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_desktop_above_the_codec_maximum_is_scaled_whole() {
    let two_screens = || TestBackend {
        desktop: Mutex::new(Some(Box::new(TwoScreens(false)))),
        ..TestBackend::default()
    };
    let (rw, rh) = shown_region(TwoScreens::SIZE.0, TwoScreens::SIZE.1);
    assert_eq!((rw, rh), (7680, 2160));

    // Balanced, through the viewer.
    let rig = rig_with(two_screens(), MediaLimits::default());
    let (_, binding) = start(&rig.host, 51, SessionMode::ViewOnly);
    let (client, served) = connect(&rig.host);
    let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
    let cap = ResolutionCap::new(u32::from(APPLIED.max_long), u32::from(APPLIED.max_short));
    let picture = picture_size((rw, rh), cap);
    assert_eq!(picture, (1920, 540), "a quarter of the region either way");
    assert_eq!(
        (viewer.bound().width, viewer.bound().height),
        picture,
        "BindOk gives the scaled size"
    );

    let (tx, rx) = oneshot::channel();
    let mut first = FirstPicture(None, Some(tx));
    let mut stats = ViewerStats::default();
    let end = viewer
        .run(&mut first, &mut stats, async {
            let _ = rx.await;
        })
        .await
        .unwrap();
    assert_eq!(end, ViewerEnd::Stopped);
    assert_two_screens_whole(&first.0.expect("a picture"), picture);

    let MediaOutcome::Served { end, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!(end, MediaEnd::ViewerLeft);
    assert_eq!(
        rig.seen.lines(),
        [
            "started two screens 1920x540 ViewOnly input=false",
            "stopped ViewerLeft"
        ]
    );

    // Best quality, bound by hand: the codec's own cap.
    let rig = rig_with(two_screens(), MediaLimits::default());
    let (_, binding) = start(&rig.host, 52, SessionMode::ViewOnly);
    let (mut client, served) = connect(&rig.host);
    let picture = picture_size((rw, rh), ResolutionCap::CODEC);
    assert_eq!(picture, (3840, 1080), "half the region either way");
    let (width, height, info) = bind_preset(&mut client, &binding, quality::BEST_QUALITY).await;
    assert_eq!((width, height, info), (3840, 1080, BEST_QUALITY));
    let mut decoder = H264Decoder::new().unwrap();
    let since = tokio::time::Instant::now();
    let frame = loop {
        in_time(since, "a picture");
        if let Msg::Video { data, .. } = next_acking(&mut client).await {
            break decoder.decode(&data).unwrap().expect("a picture").clone();
        }
    };
    assert_two_screens_whole(&frame, picture);
    drop(client);
    assert!(matches!(served.await.unwrap(), MediaOutcome::Served { .. }));
    assert_eq!(
        rig.seen.lines()[0],
        "started two screens 3840x1080 ViewOnly input=false"
    );
}

/// SLICE-A2 A2-3: a view-only session has no injector, so its input is dropped
/// before anything decodes it. Bytes no decoder would accept break nothing,
/// which is the proof that none was decoded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn view_only_input_is_never_decoded_or_injected() {
    let rig = rig(MediaLimits::default());
    let (_, binding) = start(&rig.host, 2, SessionMode::ViewOnly);
    let (mut client, served) = connect(&rig.host);
    assert_eq!(
        bind_raw(&mut client, &binding).await,
        1,
        "BindOk says view-only"
    );
    let key = InputEvent::Key {
        usb: KEY_A,
        pressed: true,
    };
    for i in 0..40 {
        let bytes = if i % 2 == 0 { key.encode() } else { [0xff; 16] };
        write_msg(&mut client, &Msg::Input(bytes)).await.unwrap();
    }
    write_msg(
        &mut client,
        &Msg::Close {
            reason: reason::ENDED_BY_VIEWER,
        },
    )
    .await
    .unwrap();

    let MediaOutcome::Served { report, end, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!(
        end,
        MediaEnd::ViewerLeft,
        "no protocol error: nothing was decoded"
    );
    assert_eq!((report.input_injected, report.input_dropped), (0, 40));
    assert_eq!(
        rig.backend.injectors.load(Ordering::SeqCst),
        0,
        "no injector was opened"
    );
    assert!(rig.backend.recorder.events().is_empty());
    assert_eq!(
        rig.seen.lines()[0],
        "started card 256x96 ViewOnly input=false"
    );
    // Nothing kept from the view-only session's source can build an injector
    // (the Wayland portal session carries the input grant): defence in depth
    // behind "a view-only session never asks for one".
    assert!(
        rig.backend.open_injector().is_none(),
        "the view-only session's input handle was kept"
    );
}

/// A control session served with no injector says so to its viewer: the
/// notice code its host tells gains `NO_INPUT`, and only for that session.
/// Its input is still read and dropped, as the signed accept leaves the
/// viewer sending it. A view-only session stays told nothing, and a control
/// session with an injector is told only what its host says.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_session_with_no_injector_tells_its_viewer() {
    use tornect_signal::messages::notice;
    let rig = rig_with(
        TestBackend {
            no_injector: true,
            ..TestBackend::default()
        },
        MediaLimits::default(),
    );
    let (id, binding) = start(&rig.host, 13, SessionMode::Control);
    let (view_id, _) = start(&rig.host, 14, SessionMode::ViewOnly);
    // Nothing is said before the stream is served.
    assert_eq!(rig.host.viewer_notice(&id, Some(0)), Some(0));
    let (mut client, served) = connect(&rig.host);
    assert_eq!(
        bind_raw(&mut client, &binding).await,
        0,
        "BindOk says control"
    );
    let key = InputEvent::Key {
        usb: KEY_A,
        pressed: true,
    };
    write_msg(&mut client, &Msg::Input(key.encode()))
        .await
        .unwrap();
    sync(&mut client, 1).await;
    assert_eq!(rig.host.viewer_notice(&id, Some(0)), Some(notice::NO_INPUT));
    assert_eq!(
        rig.host.viewer_notice(&id, Some(notice::WINDOWS)),
        Some(notice::WINDOWS | notice::NO_INPUT)
    );
    assert_eq!(rig.host.viewer_notice(&id, None), None);
    assert_eq!(rig.host.viewer_notice(&view_id, None), None);
    assert_eq!(rig.host.viewer_notice(&view_id, Some(0)), Some(0));
    assert_eq!(
        rig.seen.lines()[0],
        "started card 256x96 Control input=false"
    );
    drop(client);
    let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!((report.input_injected, report.input_dropped), (0, 1));

    // The same host with an injector says nothing of the kind.
    let rig = rig_with(TestBackend::default(), MediaLimits::default());
    let (id, binding) = start(&rig.host, 15, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    sync(&mut client, 2).await;
    assert_eq!(
        rig.seen.lines()[0],
        "started card 256x96 Control input=true"
    );
    assert_eq!(rig.host.viewer_notice(&id, Some(0)), Some(0));
    drop(client);
    served.await.unwrap();
}

/// SLICE-A2 A2-3 and the hand-off's release rule: control input is rate
/// capped, and a key still held when the panic key ends the session is
/// released on the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_input_is_capped_and_released_when_the_session_is_killed() {
    // A bucket of five that never refills: exactly five events get through.
    let rig = rig(MediaLimits {
        input_rate: 0,
        input_burst: 5,
        ..MediaLimits::default()
    });
    let (session_id, binding) = start(&rig.host, 3, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    assert_eq!(
        bind_raw(&mut client, &binding).await,
        0,
        "BindOk says control"
    );
    let press = InputEvent::Key {
        usb: KEY_A,
        pressed: true,
    };
    write_msg(&mut client, &Msg::Input(press.encode()))
        .await
        .unwrap();
    for i in 0..20u16 {
        let moved = InputEvent::PointerMove { x: i, y: i };
        write_msg(&mut client, &Msg::Input(moved.encode()))
            .await
            .unwrap();
    }
    sync(&mut client, 7).await;

    // The FSM's end of a killed session.
    rig.host
        .on_end(&session_id, Some(&SessionEnd::Killed(bye::PANIC)));
    assert_eq!(until_close(&mut client).await, Some(reason::ENDED_BY_HOST));

    let MediaOutcome::Served { report, end, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!(end, MediaEnd::SessionOver(reason::ENDED_BY_HOST));
    assert_eq!((report.input_injected, report.input_dropped), (5, 16));
    let events = rig.backend.recorder.events();
    assert_eq!(events.len(), 6, "{events:?}");
    assert_eq!(events[0], press);
    assert_eq!(
        events[5],
        InputEvent::Key {
            usb: KEY_A,
            pressed: false
        },
        "the held key is released when the session ends"
    );
    assert!(rig.backend.closed.load(Ordering::SeqCst), "capture stopped");
    assert_eq!(rig.host.live(), 0);
}

/// SLICE-E E1-6: a release is never lost to the input budget. A burst of 600
/// inputs, more than the bucket holds, ends in a button-up and a key-up: the
/// moves past the budget are dropped, and both releases reach the injector
/// while the session goes on. Before, they were dropped too, and the key and
/// the button stayed down until the session ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn releases_are_never_dropped_by_the_input_budget() {
    // A bucket of 500 that never refills.
    let rig = rig(MediaLimits {
        input_rate: 0,
        input_burst: 500,
        ..MediaLimits::default()
    });
    let (session_id, binding) = start(&rig.host, 5, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    let key = |pressed| InputEvent::Key {
        usb: KEY_A,
        pressed,
    };
    let button = |pressed| InputEvent::PointerButton {
        button: Button::Left,
        pressed,
    };
    let mut burst = vec![key(true), button(true)];
    burst.extend((0..596u16).map(|i| InputEvent::PointerMove { x: i, y: i }));
    burst.extend([button(false), key(false)]);
    assert_eq!(burst.len(), 600);
    for event in &burst {
        write_msg(&mut client, &Msg::Input(event.encode()))
            .await
            .unwrap();
    }
    sync(&mut client, 9).await;

    let events = rig.backend.recorder.events();
    assert_eq!(
        events.len(),
        502,
        "500 within the budget, then the releases"
    );
    assert_eq!(&events[..2], &[key(true), button(true)]);
    assert_eq!(
        &events[500..],
        &[button(false), key(false)],
        "the releases got through while the session goes on"
    );
    assert!(!served.is_finished());

    rig.host
        .on_end(&session_id, Some(&SessionEnd::Killed(bye::PANIC)));
    assert_eq!(until_close(&mut client).await, Some(reason::ENDED_BY_HOST));
    let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!((report.input_injected, report.input_dropped), (502, 98));
    assert_eq!(
        rig.backend.recorder.events().len(),
        502,
        "nothing was left held for the end to release"
    );
}

/// SLICE-C1 C1-3: a key held by a control viewer that goes quiet is released
/// while the session goes on. Its network may be gone without a word, and X11
/// repeats a held key until the session ends at the 90 s idle timeout; before,
/// only the end of the session released it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_held_by_a_viewer_that_goes_quiet_is_released() {
    let rig = rig(MediaLimits {
        viewer_quiet: Duration::from_millis(300),
        ..MediaLimits::default()
    });
    let (session_id, binding) = start(&rig.host, 4, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    let press = InputEvent::Key {
        usb: KEY_A,
        pressed: true,
    };
    let release = InputEvent::Key {
        usb: KEY_A,
        pressed: false,
    };
    write_msg(&mut client, &Msg::Input(press.encode()))
        .await
        .unwrap();
    // Nothing more from the viewer: no ack, no input, no ping.
    let deadline = tokio::time::Instant::now() + WAIT;
    while !rig.backend.recorder.events().contains(&release) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the held key was never released: {:?}",
            rig.backend.recorder.events()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!served.is_finished(), "released, and the session goes on");
    assert_eq!(rig.backend.recorder.events(), [press, release]);

    // A viewer that speaks again is injected again.
    write_msg(&mut client, &Msg::Input(press.encode()))
        .await
        .unwrap();
    sync(&mut client, 1).await;
    assert_eq!(rig.backend.recorder.events(), [press, release, press]);
    rig.host
        .on_end(&session_id, Some(&SessionEnd::Killed(bye::PANIC)));
    assert_eq!(until_close(&mut client).await, Some(reason::ENDED_BY_HOST));
    assert!(matches!(served.await.unwrap(), MediaOutcome::Served { .. }));
}

/// A control session over a [`connect_narrow`] pipe, with an ack window that
/// never fills, whose viewer pressed `KEY_A` and then stopped reading: from
/// then on the host's picture write waits for good. (The caps are far above
/// the window the stream derives, 23 units for Balanced, and the viewer reads
/// at most 3 pictures before it stops: the write stalls on the pipe, never
/// on the window.)
async fn press_then_stop_reading(
    seed: u8,
    viewer_quiet: Duration,
) -> (Rig, String, NarrowPipe, JoinHandle<MediaOutcome>) {
    let rig = rig(MediaLimits {
        viewer_quiet,
        window_frames: 10_000,
        window_bytes: 1 << 30,
        ..MediaLimits::default()
    });
    let (session_id, binding) = start(&rig.host, seed, SessionMode::Control);
    let (mut client, served) = connect_narrow(&rig.host);
    bind_raw(&mut client, &binding).await;
    let press = InputEvent::Key {
        usb: KEY_A,
        pressed: true,
    };
    write_msg(&mut client, &Msg::Input(press.encode()))
        .await
        .unwrap();
    while !rig.backend.recorder.events().contains(&press) {
        tokio::time::timeout(WAIT, read_msg(&mut client))
            .await
            .unwrap()
            .unwrap();
    }
    (rig, session_id, client, served)
}

/// Slice-G G2-1: the quiet release also comes while the host is stuck writing
/// a picture. A viewer that vanishes without a word stops taking pictures, and
/// the host's write then waits on Tor's flow control until the 30 s stall; the
/// quiet release waited behind it, so a key the viewer held repeated for up to
/// 30 s instead of 3 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_held_by_a_viewer_that_vanishes_mid_picture_is_released() {
    let (rig, session_id, _client, served) =
        press_then_stop_reading(16, Duration::from_millis(500)).await;
    let release = InputEvent::Key {
        usb: KEY_A,
        pressed: false,
    };
    let deadline = tokio::time::Instant::now() + WAIT;
    while !rig.backend.recorder.events().contains(&release) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the held key was never released: {:?}",
            rig.backend.recorder.events()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!served.is_finished(), "released, and the session goes on");
    assert_eq!(rig.backend.recorder.events().len(), 2);
    // The end is still heard while the write waits.
    rig.host
        .on_end(&session_id, Some(&SessionEnd::Killed(bye::PANIC)));
    let outcome = tokio::time::timeout(WAIT, served).await.unwrap().unwrap();
    assert!(
        matches!(
            outcome,
            MediaOutcome::Served {
                end: MediaEnd::SessionOver(_),
                ..
            }
        ),
        "{outcome:?}"
    );
}

/// The other side of G2-1: a viewer that is still heard while the host's
/// write waits keeps what it holds. Its frames wait in the queue behind the
/// write, and count as heard when the reader reads them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_heard_while_a_picture_write_waits_keeps_its_key() {
    let (rig, session_id, mut client, served) =
        press_then_stop_reading(17, Duration::from_millis(300)).await;
    // 1.5 s of a ping every 100 ms, five times the quiet time.
    for nonce in 0..15 {
        write_msg(&mut client, &Msg::Ping { nonce }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        rig.backend.recorder.events().len(),
        1,
        "released a viewer that was heard"
    );
    assert!(!served.is_finished());
    rig.host
        .on_end(&session_id, Some(&SessionEnd::Killed(bye::PANIC)));
    tokio::time::timeout(WAIT, served).await.unwrap().unwrap();
}

/// G2-1, a burst, now that the host reads the viewer's frames while its write
/// waits (PR-A of the quality design): a viewer that sends more than the queue
/// holds and then goes quiet counts as heard up to its last frame, so it is
/// not let go of before one quiet period after the burst, and it is let go of
/// then, well before the write ends. Before, its frames filled the queue
/// behind the write and the release fell back on the queue-full rule, one more
/// quiet period later (about two after the burst, which the bound below
/// refuses); that rule is kept for a loop that falls behind its reader, and
/// `host::tests::a_full_queue_holds_the_quiet_release_for_one_more_quiet_period`
/// pins it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_that_bursts_then_goes_quiet_while_a_write_waits_is_let_go_after_one_quiet_period()
{
    let quiet = Duration::from_secs(2);
    let (rig, session_id, mut client, served) = press_then_stop_reading(18, quiet).await;
    // More than the queue's 64.
    for nonce in 0..80 {
        write_msg(&mut client, &Msg::Ping { nonce }).await.unwrap();
    }
    let burst = tokio::time::Instant::now();
    tokio::time::sleep(quiet - Duration::from_millis(100)).await;
    assert_eq!(
        rig.backend.recorder.events().len(),
        1,
        "let go of before one quiet period after its burst"
    );
    let release = InputEvent::Key {
        usb: KEY_A,
        pressed: false,
    };
    while !rig.backend.recorder.events().contains(&release) {
        assert!(
            burst.elapsed() < quiet + quiet / 2,
            "not let go of one quiet period after its burst: {:?}",
            rig.backend.recorder.events()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!served.is_finished(), "released, and the session goes on");
    rig.host
        .on_end(&session_id, Some(&SessionEnd::Killed(bye::PANIC)));
    tokio::time::timeout(WAIT, served).await.unwrap().unwrap();
}

/// A session of `mode` over a [`connect_narrow`] pipe whose viewer binds and
/// then reads nothing more: the host's first picture write waits for good, so
/// everything the viewer sends from then on reaches the host while a write
/// waits (and `report.frames_sent` stays 0 to prove it).
async fn bind_then_stop_reading(
    rig: &Rig,
    seed: u8,
    mode: SessionMode,
) -> (String, NarrowPipe, JoinHandle<MediaOutcome>) {
    let (session_id, binding) = start(&rig.host, seed, mode);
    let (mut client, served) = connect_narrow(&rig.host);
    bind_raw(&mut client, &binding).await;
    (session_id, client, served)
}

/// Wait until the injector has received `n` events; return them.
async fn injected(rig: &Rig, n: usize) -> Vec<InputEvent> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let events = rig.backend.recorder.events();
        if events.len() >= n {
            return events;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "only {events:?} injected"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// What a viewer that stopped reading finds in the pipe once the host is done:
/// asserts that it is a single picture cut short, so that nothing, not even a
/// `Close`, was written after the write that waited.
async fn only_a_cut_short_picture(client: &mut NarrowPipe) {
    let mut rest = Vec::new();
    tokio::time::timeout(WAIT, client.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert!(rest.len() > 5, "{rest:?}");
    let video = Msg::Video {
        seq: 0,
        flags: 0,
        ts_ms: 0,
        data: Vec::new(),
    }
    .encode()[4];
    assert_eq!(rest[4], video, "not a picture: {rest:?}");
    let announced = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
    assert!(
        4 + announced > rest.len(),
        "a whole picture, then more: {rest:?}"
    );
}

/// The next frame from the host.
async fn next_msg(client: &mut NarrowPipe) -> Option<Msg> {
    tokio::time::timeout(WAIT, read_msg(client))
        .await
        .unwrap()
        .unwrap()
}

/// PR-A test 1 (quality design §8): input sent while the host's picture write
/// waits on flow control is injected then, under the token bucket, and the
/// releases at the end of it are never budgeted. Before, the input waited
/// behind the write, which over Tor lasts until the viewer reads or the 30 s
/// stall timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn input_sent_while_a_picture_write_waits_is_injected_within_its_budget() {
    // A bucket of four that never refills.
    let rig = rig(MediaLimits {
        input_rate: 0,
        input_burst: 4,
        ..MediaLimits::default()
    });
    let (session_id, mut client, served) =
        bind_then_stop_reading(&rig, 40, SessionMode::Control).await;
    let key = |pressed| InputEvent::Key {
        usb: KEY_A,
        pressed,
    };
    let button = |pressed| InputEvent::PointerButton {
        button: Button::Left,
        pressed,
    };
    let mut burst = vec![key(true), button(true)];
    burst.extend((0..20u16).map(|i| InputEvent::PointerMove { x: i, y: i }));
    burst.extend([button(false), key(false)]);
    for event in &burst {
        write_msg(&mut client, &Msg::Input(event.encode()))
            .await
            .unwrap();
    }
    let want = [
        key(true),
        button(true),
        InputEvent::PointerMove { x: 0, y: 0 },
        InputEvent::PointerMove { x: 1, y: 1 },
        button(false),
        key(false),
    ];
    assert_eq!(injected(&rig, want.len()).await, want);
    assert!(!served.is_finished(), "the session goes on");
    rig.host
        .on_end(&session_id, Some(&SessionEnd::Killed(bye::PANIC)));
    let MediaOutcome::Served { report, end, .. } =
        tokio::time::timeout(WAIT, served).await.unwrap().unwrap()
    else {
        panic!("not served");
    };
    assert_eq!(end, MediaEnd::SessionOver(reason::ENDED_BY_HOST));
    assert_eq!(
        report.frames_sent, 0,
        "all of it while the first picture's write waited"
    );
    assert_eq!((report.input_injected, report.input_dropped), (6, 18));
    assert_eq!(
        rig.backend.recorder.events().len(),
        6,
        "nothing was left held for the end to release"
    );
}

/// PR-A test 2: in a view-only session, input sent while the host's write
/// waits is still dropped undecoded: bytes no decoder accepts end nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn view_only_input_sent_while_a_picture_write_waits_is_dropped_undecoded() {
    let rig = rig(MediaLimits::default());
    let (_, mut client, served) = bind_then_stop_reading(&rig, 41, SessionMode::ViewOnly).await;
    let key = InputEvent::Key {
        usb: KEY_A,
        pressed: true,
    };
    for i in 0..10 {
        let bytes = if i % 2 == 0 { key.encode() } else { [0xff; 16] };
        write_msg(&mut client, &Msg::Input(bytes)).await.unwrap();
    }
    write_msg(
        &mut client,
        &Msg::Close {
            reason: reason::ENDED_BY_VIEWER,
        },
    )
    .await
    .unwrap();
    let MediaOutcome::Served { report, end, .. } =
        tokio::time::timeout(WAIT, served).await.unwrap().unwrap()
    else {
        panic!("not served");
    };
    assert_eq!(
        end,
        MediaEnd::ViewerLeft,
        "no protocol error: nothing was decoded"
    );
    assert_eq!(report.frames_sent, 0, "all of it while the write waited");
    assert_eq!((report.input_injected, report.input_dropped), (0, 10));
    assert_eq!(rig.backend.injectors.load(Ordering::SeqCst), 0);
    assert!(rig.backend.recorder.events().is_empty());
}

/// What the injector had received, and whether the source was closed, when
/// the host reported capture stopped.
struct AtStop {
    recorder: Recorder,
    closed: Arc<AtomicBool>,
    seen: Mutex<Option<(Vec<InputEvent>, bool)>>,
}

impl MediaObserver for AtStop {
    fn capture_started(&self, _: &CaptureStarted<'_>) {}

    fn capture_stopped(&self, _: &str, _: &MediaReport, _: &MediaEnd) {
        *self.seen.lock().unwrap() =
            Some((self.recorder.events(), self.closed.load(Ordering::SeqCst)));
    }
}

/// PR-A test 3: a `Close` sent while the host's write waits ends the stream
/// then (`ViewerLeft`), with the teardown order kept: what the viewer held is
/// released and capture is closed before `capture_stopped`, and nothing is
/// written after the picture cut short.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_while_a_picture_write_waits_releases_before_capture_stops() {
    let backend = Arc::new(TestBackend::default());
    let observer = Arc::new(AtStop {
        recorder: backend.recorder.clone(),
        closed: Arc::clone(&backend.closed),
        seen: Mutex::new(None),
    });
    let rig = Rig {
        host: Arc::new(MediaHost::new(
            backend.clone(),
            observer.clone(),
            MediaLimits::default(),
        )),
        backend,
        seen: Arc::new(Seen::default()),
    };
    let (_, mut client, served) = bind_then_stop_reading(&rig, 42, SessionMode::Control).await;
    let press = InputEvent::Key {
        usb: KEY_A,
        pressed: true,
    };
    write_msg(&mut client, &Msg::Input(press.encode()))
        .await
        .unwrap();
    assert_eq!(injected(&rig, 1).await, [press]);
    write_msg(
        &mut client,
        &Msg::Close {
            reason: reason::ENDED_BY_VIEWER,
        },
    )
    .await
    .unwrap();
    let MediaOutcome::Served { report, end, .. } =
        tokio::time::timeout(WAIT, served).await.unwrap().unwrap()
    else {
        panic!("not served");
    };
    assert_eq!(end, MediaEnd::ViewerLeft);
    assert_eq!(report.frames_sent, 0);
    let release = InputEvent::Key {
        usb: KEY_A,
        pressed: false,
    };
    assert_eq!(
        *observer.seen.lock().unwrap(),
        Some((vec![press, release], true)),
        "released, and capture closed, before capture_stopped"
    );
    only_a_cut_short_picture(&mut client).await;
}

/// PR-A test 4: the panic key ends a session at once while the host's write
/// waits and the viewer keeps sending: capture stops, what the viewer held is
/// released, and no `Close` follows the picture cut short.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kill_while_a_picture_write_waits_ends_the_session_at_once() {
    let rig = rig(MediaLimits::default());
    let kill = tornect_signal::fsm::host::KillSwitch::new();
    let watcher = rig.host.watch_kill(kill.clone());
    let (_, mut client, served) = bind_then_stop_reading(&rig, 43, SessionMode::Control).await;
    let press = InputEvent::Key {
        usb: KEY_A,
        pressed: true,
    };
    write_msg(&mut client, &Msg::Input(press.encode()))
        .await
        .unwrap();
    assert_eq!(injected(&rig, 1).await, [press]);
    // More input on its way while the kill lands.
    for i in 0..200u16 {
        let moved = InputEvent::PointerMove { x: i, y: i };
        write_msg(&mut client, &Msg::Input(moved.encode()))
            .await
            .unwrap();
    }
    let killed = std::time::Instant::now();
    kill.kill(bye::PANIC);
    let MediaOutcome::Served { report, end, .. } =
        tokio::time::timeout(Duration::from_secs(2), served)
            .await
            .expect("the kill waited behind the write")
            .unwrap()
    else {
        panic!("not served");
    };
    assert!(
        killed.elapsed() < Duration::from_secs(1),
        "{:?}",
        killed.elapsed()
    );
    assert_eq!(end, MediaEnd::SessionOver(reason::ENDED_BY_HOST));
    assert_eq!(report.frames_sent, 0);
    assert!(rig.backend.closed.load(Ordering::SeqCst), "capture stopped");
    let events = rig.backend.recorder.events();
    assert_eq!(
        events.last(),
        Some(&InputEvent::Key {
            usb: KEY_A,
            pressed: false
        }),
        "the held key is released: {events:?}"
    );
    only_a_cut_short_picture(&mut client).await;
    watcher.abort();
}

/// PR-A test 5: a `Ping` read while the host's write waits is answered right
/// after that write, and two in one wait get one `Pong`, for the latest nonce
/// (the viewer's pings are liveness probes; it ignores `Pong`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pings_while_a_picture_write_waits_get_one_pong_after_it() {
    let rig = rig(MediaLimits::default());
    let (session_id, mut client, served) =
        bind_then_stop_reading(&rig, 44, SessionMode::Control).await;
    let press = InputEvent::Key {
        usb: KEY_A,
        pressed: true,
    };
    write_msg(&mut client, &Msg::Ping { nonce: 1 })
        .await
        .unwrap();
    write_msg(&mut client, &Msg::Ping { nonce: 2 })
        .await
        .unwrap();
    write_msg(&mut client, &Msg::Input(press.encode()))
        .await
        .unwrap();
    // Frames are handled in order: with the press injected, both pings were
    // taken, while the write still waits.
    assert_eq!(injected(&rig, 1).await, [press]);

    assert!(
        matches!(next_msg(&mut client).await, Some(Msg::Video { seq: 0, .. })),
        "the picture whose write waited comes first"
    );
    assert_eq!(
        next_msg(&mut client).await,
        Some(Msg::Pong { nonce: 2 }),
        "then one Pong, for the latest nonce"
    );
    // And no other: the next frames are pictures (the window holds 23), or
    // the means that may go out before one.
    let mut pictures = 0;
    while pictures < 3 {
        match next_msg(&mut client).await {
            Some(Msg::Video { .. }) => pictures += 1,
            Some(Msg::Stats(_)) => {}
            msg => panic!("{msg:?}"),
        }
    }
    rig.host
        .on_end(&session_id, Some(&SessionEnd::Killed(bye::PANIC)));
    tokio::time::timeout(WAIT, served).await.unwrap().unwrap();
}

/// SLICE-C1 C1-3: a viewer with nothing else to say pings, so that the host can
/// tell a quiet viewer from a gone one, also when the host's screen is still
/// and no picture needs acknowledging.
#[tokio::test(start_paused = true)]
async fn a_viewer_with_nothing_to_say_pings_the_host() {
    let binding = Binding::new(&SessionToken::new([6; 32]), &[6; 32]);
    let (client, mut host) = duplex(1 << 16);
    let bound = tokio::spawn(async move {
        let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
        let (mut sink, mut stats) = (NoPictures, ViewerStats::default());
        viewer
            .run(&mut sink, &mut stats, std::future::pending())
            .await
    });
    assert!(matches!(
        read_msg(&mut host).await.unwrap(),
        Some(Msg::Bind { .. })
    ));
    let bind_ok = Msg::BindOk {
        width: 1280,
        height: 720,
        codec: codec::H264,
        mode: 0,
        quality: APPLIED,
    };
    write_msg(&mut host, &bind_ok).await.unwrap();
    let start = tokio::time::Instant::now();
    let first = tokio::time::timeout(Duration::from_secs(5), read_msg(&mut host))
        .await
        .expect("the viewer said nothing for 5 s");
    assert!(matches!(first, Ok(Some(Msg::Ping { .. }))), "{first:?}");
    assert!(start.elapsed() <= Duration::from_secs(1));
    drop(host);
    let _ = bound.await;
}

/// Bind a viewer over a pipe to a scripted host and run it with `input`;
/// returns the host's end, past `BindOk`.
async fn run_viewer_with(
    input: Option<tokio::sync::mpsc::Receiver<InputEvent>>,
) -> (
    DuplexStream,
    JoinHandle<(Result<ViewerEnd, ViewerError>, ViewerStats)>,
) {
    let binding = Binding::new(&SessionToken::new([8; 32]), &[8; 32]);
    let (client, mut host) = duplex(1 << 16);
    let viewer = tokio::spawn(async move {
        let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
        let (mut sink, mut stats) = (NoPictures, ViewerStats::default());
        let end = viewer
            .run_with_input(&mut sink, &mut stats, input, std::future::pending())
            .await;
        (end, stats)
    });
    assert!(matches!(
        read_msg(&mut host).await.unwrap(),
        Some(Msg::Bind { .. })
    ));
    let bind_ok = Msg::BindOk {
        width: 1280,
        height: 720,
        codec: codec::H264,
        mode: 0,
        quality: APPLIED,
    };
    write_msg(&mut host, &bind_ok).await.unwrap();
    (host, viewer)
}

/// The viewer's half of input over the media stream: each event handed to a
/// control session's viewer goes to the host as one `Input` frame carrying the
/// 16-byte event, in order, and nothing else is sent in its place.
#[tokio::test(start_paused = true)]
async fn a_viewer_sends_each_input_event_as_one_16_byte_frame() {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let (mut host, viewer) = run_viewer_with(Some(rx)).await;
    let events = [
        InputEvent::PointerMove { x: 100, y: 65_000 },
        InputEvent::PointerButton {
            button: Button::Left,
            pressed: true,
        },
        InputEvent::Key {
            usb: KEY_A,
            pressed: true,
        },
        InputEvent::Key {
            usb: KEY_A,
            pressed: false,
        },
        InputEvent::Wheel { dx: 0, dy: -120 },
        InputEvent::ReleaseAll,
    ];
    for event in events {
        tx.send(event).await.unwrap();
    }
    for event in events {
        // The raw frame: a length of 17 (the type byte and 16 bytes of event).
        let mut len = [0u8; 4];
        host.read_exact(&mut len).await.unwrap();
        assert_eq!(u32::from_be_bytes(len), 17);
        let mut frame = [0u8; 17];
        host.read_exact(&mut frame).await.unwrap();
        let Msg::Input(bytes) = Msg::decode(&frame).unwrap() else {
            panic!("not an Input frame: {frame:?}");
        };
        assert_eq!(InputEvent::decode(&bytes).unwrap(), event);
    }
    drop(tx);
    drop(host);
    let (_, stats) = viewer.await.unwrap();
    assert_eq!(stats.input_sent, events.len() as u64);
}

/// A viewer run without an input channel (a view-only session, gated on the
/// signed `SESSION_ACCEPT` by the caller) sends no `Input` frame at all: only
/// its keep-alive pings.
#[tokio::test(start_paused = true)]
async fn a_viewer_without_an_input_channel_sends_no_input() {
    let (mut host, viewer) = run_viewer_with(None).await;
    for _ in 0..3 {
        let msg = tokio::time::timeout(Duration::from_secs(5), read_msg(&mut host))
            .await
            .expect("the viewer said nothing for 5 s");
        assert!(matches!(msg, Ok(Some(Msg::Ping { .. }))), "{msg:?}");
    }
    drop(host);
    let (_, stats) = viewer.await.unwrap();
    assert_eq!(stats.input_sent, 0);
}

/// The quality design §4.6: a host's `Quality` and `Stats` are display-only
/// to the viewer, which reads on past them; a host's `SetQuality` is a frame
/// it must not send, as `Input` is.
#[tokio::test(start_paused = true)]
async fn a_viewer_reads_on_past_quality_and_stats_and_refuses_a_host_set_quality() {
    let (mut host, viewer) = run_viewer_with(None).await;
    for msg in [
        Msg::Quality {
            width: 1280,
            height: 694,
            quality: APPLIED,
        },
        Msg::Stats(HostStats {
            window_ms: 1000,
            ..HostStats::default()
        }),
        Msg::Close {
            reason: reason::ENDED_BY_HOST,
        },
    ] {
        write_msg(&mut host, &msg).await.unwrap();
    }
    let (end, _) = viewer.await.unwrap();
    assert!(
        matches!(end, Ok(ViewerEnd::Host(r)) if r == reason::ENDED_BY_HOST),
        "{end:?}"
    );

    let (mut host, viewer) = run_viewer_with(None).await;
    let set = Msg::SetQuality {
        quality: quality::BEST_QUALITY,
    };
    write_msg(&mut host, &set).await.unwrap();
    let (end, _) = viewer.await.unwrap();
    assert!(
        matches!(end, Err(ViewerError::Unexpected("SetQuality"))),
        "{end:?}"
    );
}

/// Addendum Q3: a session that ends while its source is still opening (on
/// Wayland, while the desktop's dialog is up) ends the open too. Before, the
/// open ran on, detached, for the rest of its 30 s, and a dialog answered then
/// left a remembered grant that no session had asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_that_ends_while_its_source_opens_ends_the_open() {
    let backend = TestBackend {
        open_waits: true,
        ..TestBackend::default()
    };
    let rig = rig_with(backend, MediaLimits::default());
    let (session_id, binding) = start(&rig.host, 5, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    write_msg(&mut client, &binding.msg()).await.unwrap();
    let deadline = tokio::time::Instant::now() + WAIT;
    while rig.backend.sources.load(Ordering::SeqCst) == 0 {
        assert!(tokio::time::Instant::now() < deadline, "no open started");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    rig.host
        .on_end(&session_id, Some(&SessionEnd::Killed(bye::PANIC)));
    let outcome = tokio::time::timeout(WAIT, served).await.unwrap().unwrap();
    assert!(
        matches!(outcome, MediaOutcome::NotStarted(_)),
        "{outcome:?}"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while !rig.backend.cancelled.load(Ordering::SeqCst) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the open was left to run out its time"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Opens as `SystemBackend` does on Wayland, behind a gate that stands for the
/// blocking pool's delay before the open's first line. (At `37a70e1` it made
/// its cancel only past the gate, in an `opening` slot that `cancel_open`
/// took, as `SystemBackend` did; that shape failed both tests below.)
#[derive(Default)]
struct GatedOpen {
    entered: AtomicBool,
    gate: (Mutex<bool>, std::sync::Condvar),
    /// Whether the open's wait ended cancelled, and how long it took.
    ended: Mutex<Option<(bool, Duration)>>,
}

impl GatedOpen {
    fn open_gate(&self) {
        let (open, opened) = &self.gate;
        *open.lock().unwrap() = true;
        opened.notify_all();
    }
}

impl MediaBackend for GatedOpen {
    fn open_source(
        &self,
        _: SourceRequest,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError> {
        self.entered.store(true, Ordering::SeqCst);
        let (open, opened) = &self.gate;
        drop(
            opened
                .wait_while(open.lock().unwrap(), |open| !*open)
                .unwrap(),
        );
        let started = std::time::Instant::now();
        let cancelled = dialog(&cancel);
        *self.ended.lock().unwrap() = Some((cancelled, started.elapsed()));
        Err(CaptureError::Unavailable("the session ended".into()))
    }

    fn open_injector(&self) -> Option<Box<dyn InputSink>> {
        None
    }
}

/// A media host over a [`GatedOpen`], with a control session bound and its
/// open entered (and held at the gate).
async fn open_held_at_the_gate(
    seed: u8,
) -> (
    Arc<GatedOpen>,
    Arc<MediaHost>,
    String,
    DuplexStream,
    JoinHandle<MediaOutcome>,
) {
    let backend = Arc::new(GatedOpen::default());
    let host = Arc::new(MediaHost::new(
        backend.clone(),
        Arc::new(Seen::default()),
        MediaLimits::default(),
    ));
    let (session_id, binding) = start(&host, seed, SessionMode::Control);
    let (mut client, served) = connect(&host);
    write_msg(&mut client, &binding.msg()).await.unwrap();
    let deadline = tokio::time::Instant::now() + WAIT;
    while !backend.entered.load(Ordering::SeqCst) {
        assert!(tokio::time::Instant::now() < deadline, "no open started");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (backend, host, session_id, client, served)
}

/// Open the gate, and say whether the open's dialog ended cancelled within 1 s.
async fn let_the_open_on(backend: &GatedOpen) {
    backend.open_gate();
    let deadline = tokio::time::Instant::now() + WAIT + Duration::from_secs(2);
    let (cancelled, took) = loop {
        if let Some(ended) = *backend.ended.lock().unwrap() {
            break ended;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the open never ended"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert!(
        cancelled && took < Duration::from_secs(1),
        "the open ran on for {took:?} (cancelled: {cancelled})"
    );
}

/// Slice-G G1-1: a session that ends before its blocking open is under way
/// still ends that open. The end used to reach only a cancel the open had
/// already stored, so an end in between was lost: the desktop's dialog stayed
/// up for its 30 s, and an Allow kept a grant that no session had asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_that_ends_before_its_open_starts_still_ends_it() {
    let (backend, host, session_id, _client, served) = open_held_at_the_gate(14).await;
    host.on_end(&session_id, Some(&SessionEnd::Killed(bye::PANIC)));
    let outcome = tokio::time::timeout(WAIT, served).await.unwrap().unwrap();
    assert!(
        matches!(outcome, MediaOutcome::NotStarted(_)),
        "{outcome:?}"
    );
    // Only now does the open reach the point where it can be cancelled.
    let_the_open_on(&backend).await;
}

/// A stream whose task is dropped while its source opens (a host that stops
/// drops its media streams' tasks) ends the open too: the desktop's dialog
/// does not stay up, and no grant is kept, for a host that stopped sharing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_dropped_while_its_source_opens_ends_the_open() {
    let (backend, _host, _, _client, served) = open_held_at_the_gate(15).await;
    served.abort();
    assert!(served.await.unwrap_err().is_cancelled());
    let_the_open_on(&backend).await;
}

/// SLICE-B1 B1-2: a kill stops capture at once, before the FSM has finished its
/// `BYE` (here, before `on_end` is called at all), and a killed session that
/// has not bound its media yet cannot bind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kill_stops_capture_without_waiting_for_the_fsm() {
    let rig = rig(MediaLimits::default());
    let kill = tornect_signal::fsm::host::KillSwitch::new();
    let watcher = rig.host.watch_kill(kill.clone());
    let (_, streaming) = start(&rig.host, 12, SessionMode::Control);
    let (_, unbound) = start(&rig.host, 13, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &streaming).await;
    next_video(&mut client).await;

    kill.kill(bye::PANIC);
    assert_eq!(until_close(&mut client).await, Some(reason::ENDED_BY_HOST));
    assert!(matches!(
        served.await.unwrap(),
        MediaOutcome::Served {
            end: MediaEnd::SessionOver(r),
            ..
        } if r == reason::ENDED_BY_HOST
    ));
    assert!(rig.backend.closed.load(Ordering::SeqCst), "capture stopped");
    assert_eq!(
        rig.host.live(),
        2,
        "the FSM has not ended either session yet"
    );

    let (late, served) = connect(&rig.host);
    let refused = MediaViewer::bind(late, &unbound, WAIT).await.unwrap_err();
    assert!(matches!(refused, ViewerError::Refused(r) if r == reason::BAD_BIND));
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
    watcher.abort();
}

/// SLICE-A1 G3 / A2-3: one media stream per session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_is_single_use() {
    let rig = rig(MediaLimits::default());
    let (_, binding) = start(&rig.host, 4, SessionMode::Control);
    let (first, first_served) = connect(&rig.host);
    let viewer = MediaViewer::bind(first, &binding, WAIT).await.unwrap();

    let (second, second_served) = connect(&rig.host);
    let refused = MediaViewer::bind(second, &binding, WAIT).await.unwrap_err();
    assert!(
        matches!(refused, ViewerError::Refused(r) if r == reason::BAD_BIND),
        "{refused:?}"
    );
    assert_eq!(second_served.await.unwrap(), MediaOutcome::NotBound);
    assert_eq!(rig.backend.sources.load(Ordering::SeqCst), 1, "one capture");

    drop(viewer);
    // The host sees the viewer go either at its read (EOF) or at a frame write
    // already in flight (a broken pipe), depending on timing under load.
    assert!(matches!(
        first_served.await.unwrap(),
        MediaOutcome::Served {
            end: MediaEnd::ViewerLeft | MediaEnd::Io,
            ..
        }
    ));
}

/// A wrong MAC binds nothing, and it does not burn the session for the real
/// viewer either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_mac_neither_binds_nor_locks_the_viewer_out() {
    let rig = rig(MediaLimits::default());
    let (_, binding) = start(&rig.host, 5, SessionMode::Control);
    // Same token (so the same session id), another transcript: another MAC.
    let forged = Binding::new(&SessionToken::new([5; 32]), &[0; 32]);
    assert_eq!(forged.session_id(), binding.session_id());

    let (client, served) = connect(&rig.host);
    let refused = MediaViewer::bind(client, &forged, WAIT).await.unwrap_err();
    assert!(matches!(refused, ViewerError::Refused(r) if r == reason::BAD_BIND));
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
    assert_eq!(
        rig.backend.sources.load(Ordering::SeqCst),
        0,
        "nothing captured"
    );

    let (client, served) = connect(&rig.host);
    let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
    drop(viewer);
    assert!(matches!(served.await.unwrap(), MediaOutcome::Served { .. }));
}

/// SLICE-A1 G3: a stream that never binds is dropped at the deadline, and a
/// `Bind` for a session that never starts is refused then; nothing is captured.
#[tokio::test(start_paused = true)]
async fn unbound_streams_end_at_the_bind_deadline() {
    let rig = rig(MediaLimits::default());
    let deadline = MediaLimits::default().bind_deadline;

    let (mut silent, served) = connect(&rig.host);
    let t0 = tokio::time::Instant::now();
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
    assert!(t0.elapsed() >= deadline);
    let mut byte = [0u8; 1];
    assert_eq!(
        silent.read(&mut byte).await.unwrap(),
        0,
        "closed, unanswered"
    );

    let ghost = Binding::new(&SessionToken::new([6; 32]), &[6; 32]);
    let (mut client, served) = connect(&rig.host);
    write_msg(&mut client, &ghost.msg()).await.unwrap();
    let t0 = tokio::time::Instant::now();
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
    assert!(t0.elapsed() >= deadline - Duration::from_millis(1));
    assert_eq!(
        read_msg(&mut client).await.unwrap(),
        Some(Msg::BindRefused {
            reason: reason::BAD_BIND
        })
    );
    assert_eq!(rig.backend.sources.load(Ordering::SeqCst), 0);
}

/// Binds waiting for a session nobody has registered are capped: one beyond
/// the cap is refused at once, without waiting out the deadline.
#[tokio::test(start_paused = true)]
async fn waiting_binds_beyond_the_cap_are_refused_at_once() {
    let rig = rig(MediaLimits {
        max_waiting: 2,
        ..MediaLimits::default()
    });
    let ghost = |seed| Binding::new(&SessionToken::new([seed; 32]), &[seed; 32]);
    let (mut a, a_served) = connect(&rig.host);
    write_msg(&mut a, &ghost(1).msg()).await.unwrap();
    let (mut b, b_served) = connect(&rig.host);
    write_msg(&mut b, &ghost(2).msg()).await.unwrap();
    tokio::task::yield_now().await;
    let (mut c, c_served) = connect(&rig.host);
    write_msg(&mut c, &ghost(3).msg()).await.unwrap();
    let t0 = tokio::time::Instant::now();
    assert_eq!(c_served.await.unwrap(), MediaOutcome::Busy);
    assert_eq!(t0.elapsed(), Duration::ZERO);
    assert_eq!(
        read_msg(&mut c).await.unwrap(),
        Some(Msg::BindRefused {
            reason: reason::BAD_BIND
        })
    );
    assert_eq!(a_served.await.unwrap(), MediaOutcome::NotBound);
    assert_eq!(b_served.await.unwrap(), MediaOutcome::NotBound);
}

/// SLICE-C1 C1-1: streams that squat the waiting slots, idle or bound to a
/// session nobody registered, do not keep a live session's viewer from
/// binding. Before, every stream took a slot before a byte was read, so eight
/// idle streams from anyone with the Tornect ID denied every session its
/// picture.
///
/// Every slot is held by a ghost bind, and the set is shown to be full, so a
/// live session's bind that took a slot would be refused (SLICE-D D3: with
/// half the slots held, that regression passed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn squatting_streams_do_not_starve_a_live_sessions_bind() {
    let rig = rig(MediaLimits::default());
    let mut squatters = Vec::new();
    // Every waiting slot: a bind for a session that never registers.
    for i in 0..MediaLimits::default().max_waiting as u8 {
        let (mut stream, served) = connect(&rig.host);
        let ghost = Binding::new(&SessionToken::new([0x60 + i; 32]), &[0x61; 32]);
        write_msg(&mut stream, &ghost.msg()).await.unwrap();
        squatters.push((stream, served));
    }
    // And idle streams on top, which say nothing.
    for _ in 0..4 {
        squatters.push(connect(&rig.host));
    }
    // The waiting set is full once one more ghost is refused at once. The
    // squatters' binds are read on other tasks, so ask until it is; an extra
    // ghost that got a slot meanwhile is one more squatter.
    let mut full = false;
    for seed in 0x20..0x40u8 {
        let (mut extra, mut extra_served) = connect(&rig.host);
        let ghost = Binding::new(&SessionToken::new([seed; 32]), &[0x61; 32]);
        write_msg(&mut extra, &ghost.msg()).await.unwrap();
        match tokio::time::timeout(Duration::from_millis(200), &mut extra_served).await {
            Ok(outcome) => {
                assert_eq!(outcome.unwrap(), MediaOutcome::Busy);
                full = true;
                break;
            }
            Err(_) => squatters.push((extra, extra_served)),
        }
    }
    assert!(full, "the waiting set never filled");
    let (_, binding) = start(&rig.host, 9, SessionMode::ViewOnly);
    let (stream, served) = connect(&rig.host);
    let viewer = MediaViewer::bind(stream, &binding, WAIT)
        .await
        .expect("the live session's viewer binds");
    drop(viewer);
    assert!(matches!(served.await.unwrap(), MediaOutcome::Served { .. }));
    for (_, served) in squatters {
        served.abort();
    }
}

/// The FSM registers a session just after sending `SESSION_ACCEPT`; a viewer
/// that binds in between waits instead of being refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_that_beats_the_registration_waits_for_it() {
    let rig = rig(MediaLimits::default());
    let token = SessionToken::new([7; 32]);
    let th_final = [8; 32];
    let binding = Binding::new(&token, &th_final);
    let (client, served) = connect(&rig.host);
    let bind = tokio::spawn(async move { MediaViewer::bind(client, &binding, WAIT).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!bind.is_finished(), "no answer before the session exists");

    let session_id = token.session_id();
    rig.host.on_start(&LiveSession {
        device: DeviceId::from_bytes([7; 32]),
        label: "Laptop",
        session_id: &session_id,
        token: &token,
        th_final,
        mode: SessionMode::Control,
        elevation: tornect_core::levels::Elevation::None,
        unattended: false,
    });
    let viewer = bind.await.unwrap().unwrap();
    drop(viewer);
    assert!(matches!(served.await.unwrap(), MediaOutcome::Served { .. }));
}

/// SLICE-A2 A2-6: the host sends at most the window's worth of video before
/// the viewer acknowledges, and one more per acknowledged unit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unacknowledged_video_stops_at_the_window() {
    let rig = rig(MediaLimits {
        window_frames: 3,
        ..MediaLimits::default()
    });
    let (_, binding) = start(&rig.host, 9, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    for want in 0..3 {
        assert_eq!(next_video(&mut client).await.0, want);
    }
    // At 15 fps, an unbounded host would send ~7 more in half a second.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), read_msg(&mut client))
            .await
            .is_err(),
        "nothing beyond the window"
    );
    write_msg(&mut client, &Msg::VideoAck { seq: 0 })
        .await
        .unwrap();
    assert_eq!(next_video(&mut client).await.0, 3, "one ack, one more");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), read_msg(&mut client))
            .await
            .is_err()
    );
    drop(client);
    assert!(matches!(served.await.unwrap(), MediaOutcome::Served { .. }));
}

/// A `KeyframeRequest` forces an IDR soon after, and a second one within the
/// interval is counted but forces nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_keyframe_request_forces_an_idr_at_a_bounded_rate() {
    let rig = rig(MediaLimits::default());
    let (_, binding) = start(&rig.host, 10, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    for _ in 0..3 {
        let (seq, _) = next_video(&mut client).await;
        write_msg(&mut client, &Msg::VideoAck { seq })
            .await
            .unwrap();
    }
    write_msg(&mut client, &Msg::KeyframeRequest).await.unwrap();
    write_msg(&mut client, &Msg::KeyframeRequest).await.unwrap();
    let mut idr = false;
    // One picture may already be in the encoder when the request lands.
    for _ in 0..3 {
        let (seq, flags) = next_video(&mut client).await;
        write_msg(&mut client, &Msg::VideoAck { seq })
            .await
            .unwrap();
        if flags & video_flags::KEYFRAME != 0 {
            idr = true;
            break;
        }
    }
    assert!(idr, "no IDR after a KeyframeRequest");
    drop(client);
    let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!((report.keyframe_requests, report.keyframes_forced), (2, 1));
}

/// A source with no new picture for a while (GDI while a secure Windows
/// screen shows) leaves the session up: the host still answers, a
/// `KeyframeRequest` made meanwhile is kept, and the first picture after the
/// pause is that keyframe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_with_no_picture_for_a_while_keeps_the_session() {
    let rig = rig(MediaLimits::default());
    let (_, binding) = start(&rig.host, 12, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    let (seq, _) = next_video(&mut client).await;
    write_msg(&mut client, &Msg::VideoAck { seq })
        .await
        .unwrap();
    rig.backend.stalled.store(true, Ordering::SeqCst);
    // A picture already on its way may still come, after the means that may
    // go out before it (`Stats`); then nothing does.
    loop {
        match tokio::time::timeout(Duration::from_millis(500), read_msg(&mut client)).await {
            Err(_) => break,
            Ok(Ok(Some(Msg::Video { seq, .. }))) => write_msg(&mut client, &Msg::VideoAck { seq })
                .await
                .unwrap(),
            Ok(Ok(Some(Msg::Stats(_) | Msg::Quality { .. }))) => {}
            Ok(other) => panic!("during the pause: {other:?}"),
        }
    }
    write_msg(&mut client, &Msg::KeyframeRequest).await.unwrap();
    for nonce in 1..=3 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        sync(&mut client, nonce).await;
    }
    rig.backend.stalled.store(false, Ordering::SeqCst);
    let (_, flags) = next_video(&mut client).await;
    assert_ne!(
        flags & video_flags::KEYFRAME,
        0,
        "the picture after the pause"
    );
    drop(client);
    let MediaOutcome::Served { report, end, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!(end, MediaEnd::ViewerLeft);
    assert_eq!((report.keyframe_requests, report.keyframes_forced), (1, 1));
}

/// The first frame is read at a `Bind`'s size: a peer announcing 8 MiB gets a
/// refusal, not an allocation.
#[tokio::test]
async fn a_first_frame_that_is_not_a_bind_is_refused_unread() {
    let rig = rig(MediaLimits::default());
    let (mut client, served) = connect(&rig.host);
    client.write_all(&(8u32 << 20).to_be_bytes()).await.unwrap();
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
    assert_eq!(
        read_msg(&mut client).await.unwrap(),
        Some(Msg::BindRefused {
            reason: reason::PROTOCOL
        })
    );
}

/// The viewer's `Bind` with `preset` instead of the one it sends.
fn bind_with(binding: &Binding, preset: u8) -> Msg {
    let Msg::Bind {
        session_id, mac, ..
    } = binding.msg()
    else {
        unreachable!("a binding's message is a Bind");
    };
    Msg::Bind {
        session_id,
        mac,
        quality: preset,
    }
}

/// Bind with `preset` by hand: `BindOk`'s picture size and quality.
async fn bind_preset(
    client: &mut DuplexStream,
    binding: &Binding,
    preset: u8,
) -> (u32, u32, QualityInfo) {
    write_msg(client, &bind_with(binding, preset))
        .await
        .unwrap();
    match tokio::time::timeout(WAIT, read_msg(client))
        .await
        .unwrap()
        .unwrap()
    {
        Some(Msg::BindOk {
            width,
            height,
            quality,
            ..
        }) => (width, height, quality),
        other => panic!("expected BindOk, got {other:?}"),
    }
}

/// Panics once [`WAIT`] has passed since `since`, naming what was awaited: a
/// loop that reads past the frames it does not want must still end when what
/// it wants never comes.
fn in_time(since: tokio::time::Instant, what: &str) {
    assert!(since.elapsed() < WAIT, "{what} never came");
}

/// The host's next frame, within [`WAIT`]; a `Video` is acknowledged as it
/// is read, as a viewer does.
async fn next_acking(client: &mut DuplexStream) -> Msg {
    let msg = tokio::time::timeout(WAIT, read_msg(client))
        .await
        .expect("a frame in time")
        .unwrap()
        .expect("the stream is open");
    if let Msg::Video { seq, .. } = msg {
        write_msg(client, &Msg::VideoAck { seq }).await.unwrap();
    }
    msg
}

/// The size `preset` fits a `width`×`height` desktop to under the default
/// caps.
fn fitted(preset: QualityPreset, width: u32, height: u32) -> (u32, u32) {
    let settings = crate::quality::settings(
        preset,
        crate::quality::Route::Tor,
        &MediaLimits::default().caps,
    );
    picture_size(shown_region(width, height), settings.cap)
}

/// The quality design §8 host test 1: a `Bind` naming each preset gets a
/// `BindOk` carrying that preset's `QualityInfo` from the host's table, and
/// the exact size of the first picture: the card fitted under that preset's
/// cap, which the first `Video`, an IDR, decodes at.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_of_each_preset_gets_what_the_stream_applies() {
    // Wider than Balanced's and Best performance's caps, under Best quality's.
    const CARD: (u32, u32) = (2000, 240);
    let rig = rig_with(
        TestBackend {
            card: Some(CARD),
            ..TestBackend::default()
        },
        MediaLimits::default(),
    );
    for (seed, preset, info, size) in [
        (40, QualityPreset::BestQuality, BEST_QUALITY, (2000, 240)),
        (41, QualityPreset::Balanced, APPLIED, (1920, 230)),
        (
            42,
            QualityPreset::BestPerformance,
            BEST_PERFORMANCE,
            (1280, 152),
        ),
    ] {
        assert_eq!(fitted(preset, CARD.0, CARD.1), size);
        let (_, binding) = start(&rig.host, seed, SessionMode::ViewOnly);
        let (mut client, served) = connect(&rig.host);
        write_msg(
            &mut client,
            &bind_with(&binding, crate::quality::code(preset)),
        )
        .await
        .unwrap();
        assert_eq!(
            read_msg(&mut client).await.unwrap(),
            Some(Msg::BindOk {
                width: size.0,
                height: size.1,
                codec: codec::H264,
                mode: 1,
                quality: info,
            }),
            "{preset}"
        );
        let Msg::Video { flags, data, .. } = next_acking(&mut client).await else {
            panic!("{preset}: the first picture comes first");
        };
        assert_ne!(flags & video_flags::KEYFRAME, 0, "{preset}");
        let mut decoder = H264Decoder::new().unwrap();
        let frame = decoder.decode(&data).unwrap().expect("a picture");
        assert_eq!((frame.width, frame.height), size, "{preset}");
        drop(client);
        assert!(matches!(served.await.unwrap(), MediaOutcome::Served { .. }));
    }
    assert_eq!(rig.backend.sources.load(Ordering::SeqCst), 3);
}

/// Host test 4: a `SetQuality` mid-stream is said in a `Quality` before the
/// first `Video` encoded with it. The `Quality` carries the card fitted under
/// the new preset's cap and the preset's `QualityInfo`; the `Video` after it
/// is an IDR, and decodes at that size; every picture before it, already on
/// its way, decodes at the size before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_quality_change_mid_stream_is_said_before_its_first_picture() {
    const CARD: (u32, u32) = (2000, 240);
    let rig = rig_with(
        TestBackend {
            card: Some(CARD),
            ..TestBackend::default()
        },
        MediaLimits::default(),
    );
    let (_, binding) = start(&rig.host, 60, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    let before = fitted(QualityPreset::Balanced, CARD.0, CARD.1);
    let after = fitted(QualityPreset::BestPerformance, CARD.0, CARD.1);
    assert_eq!((before, after), ((1920, 230), (1280, 152)));
    let (width, height, info) = bind_preset(&mut client, &binding, quality::BALANCED).await;
    assert_eq!((width, height, info), (before.0, before.1, APPLIED));

    let mut decoder = H264Decoder::new().unwrap();
    let mut decoded = |data: &[u8]| {
        let frame = decoder.decode(data).unwrap().expect("a picture");
        (frame.width, frame.height)
    };
    let mut pictures = 0;
    let since = tokio::time::Instant::now();
    while pictures < 3 {
        in_time(since, "three pictures");
        match next_acking(&mut client).await {
            Msg::Video { data, .. } => {
                assert_eq!(decoded(&data), before);
                pictures += 1;
            }
            Msg::Stats(_) => {}
            other => panic!("before the change: {other:?}"),
        }
    }
    write_msg(
        &mut client,
        &Msg::SetQuality {
            quality: quality::BEST_PERFORMANCE,
        },
    )
    .await
    .unwrap();
    let since = tokio::time::Instant::now();
    let said = loop {
        in_time(since, "the Quality");
        match next_acking(&mut client).await {
            Msg::Video { data, .. } => assert_eq!(decoded(&data), before, "already on its way"),
            Msg::Stats(_) => {}
            Msg::Quality {
                width,
                height,
                quality,
            } => break (width, height, quality),
            other => panic!("before the Quality: {other:?}"),
        }
    };
    assert_eq!(said, (after.0, after.1, BEST_PERFORMANCE));
    let (flags, data) = loop {
        in_time(since, "the picture after the Quality");
        match next_acking(&mut client).await {
            Msg::Video { flags, data, .. } => break (flags, data),
            Msg::Stats(_) => {}
            other => panic!("after the Quality: {other:?}"),
        }
    };
    assert_ne!(flags & video_flags::KEYFRAME, 0, "an IDR at the new size");
    assert_eq!(decoded(&data), after);
    write_msg(
        &mut client,
        &Msg::Close {
            reason: reason::ENDED_BY_VIEWER,
        },
    )
    .await
    .unwrap();
    let MediaOutcome::Served { report, end, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!(end, MediaEnd::ViewerLeft);
    assert_eq!(
        (
            report.quality_requests,
            report.quality_changes,
            report.repeats
        ),
        (1, 1, 1),
        "the change encodes the last picture again"
    );
    assert_eq!(rig.backend.sources.load(Ordering::SeqCst), 1);
}

/// The window follows the preset (the quality design §3.1): a stream bound
/// with Balanced has 23 pictures in flight at most before an ack, and once
/// Best performance applies, 30 (the caps here are far above both).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_preset_change_resizes_the_ack_window() {
    let rig = rig(MediaLimits {
        window_frames: 10_000,
        window_bytes: 1 << 30,
        ..MediaLimits::default()
    });
    let (_, binding) = start(&rig.host, 61, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    // Read without acknowledging until nothing more comes.
    let unacked = |said: Vec<Msg>| {
        said.into_iter()
            .filter_map(|msg| match msg {
                Msg::Video { seq, .. } => Some(seq),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let mut said = Vec::new();
    while let Ok(msg) =
        tokio::time::timeout(Duration::from_millis(500), read_msg(&mut client)).await
    {
        said.push(msg.unwrap().unwrap());
    }
    let videos = unacked(said);
    assert_eq!(videos.len(), 23, "Balanced's window: {videos:?}");

    write_msg(
        &mut client,
        &Msg::SetQuality {
            quality: quality::BEST_PERFORMANCE,
        },
    )
    .await
    .unwrap();
    write_msg(&mut client, &Msg::VideoAck { seq: videos[22] })
        .await
        .unwrap();
    let mut said = Vec::new();
    while let Ok(msg) =
        tokio::time::timeout(Duration::from_millis(500), read_msg(&mut client)).await
    {
        said.push(msg.unwrap().unwrap());
    }
    assert!(
        said.iter().any(|msg| matches!(
            msg,
            Msg::Quality {
                quality: BEST_PERFORMANCE,
                ..
            }
        )),
        "{said:?}"
    );
    assert_eq!(unacked(said).len(), 30, "Best performance's window");
    drop(client);
    let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!((report.frames_sent, report.quality_changes), (53, 1));
}

/// The quality design §5 rule 1 and §8 host test 3: a source is opened for
/// the fastest preset's rate on the route, held to the host's `max_fps`: from
/// the host's config and the route alone, so binds naming different presets
/// make identical requests. Five `SetQuality`s change the preset twice and
/// never open capture again. `serve_on` with the Tor route serves as `serve`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_source_is_opened_at_the_hosts_capture_rate_whatever_the_preset() {
    for (max_fps, want) in [(60, 20), (10, 10)] {
        let rig = rig(MediaLimits {
            caps: crate::quality::QualityCaps {
                max_fps,
                ..crate::quality::QualityCaps::default()
            },
            quality_interval: Duration::from_millis(300),
            keyframe_interval: Duration::from_millis(300),
            ..MediaLimits::default()
        });
        for (seed, bound, other) in [
            (45, quality::BEST_QUALITY, quality::BEST_PERFORMANCE),
            (46, quality::BEST_PERFORMANCE, quality::BEST_QUALITY),
        ] {
            let (_, binding) = start(&rig.host, seed, SessionMode::Control);
            let (mut client, server) = duplex(1 << 20);
            let host = Arc::clone(&rig.host);
            let served =
                tokio::spawn(
                    async move { host.serve_on(server, crate::quality::Route::Tor).await },
                );
            let (.., info) = bind_preset(&mut client, &binding, bound).await;
            assert_eq!(info.preset, bound);
            // Only the last of them names `other`.
            let picks = [quality::BALANCED, bound, quality::BALANCED, bound, other];
            for quality in picks {
                write_msg(&mut client, &Msg::SetQuality { quality })
                    .await
                    .unwrap();
            }
            let since = tokio::time::Instant::now();
            loop {
                in_time(since, "a Quality naming the last pick");
                if let Msg::Quality { quality, .. } = next_acking(&mut client).await
                    && quality.preset == other
                {
                    break;
                }
            }
            drop(client);
            let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
                panic!("not served");
            };
            assert_eq!(report.quality_requests, 5);
            assert!(report.quality_changes >= 1, "{report:?}");
        }
        assert_eq!(
            *rig.backend.requests.lock().unwrap(),
            [SourceRequest::new(want); 2],
            "max_fps {max_fps}: one open per stream, whatever was picked"
        );
        assert_eq!(rig.backend.sources.load(Ordering::SeqCst), 2);
    }
}

/// The quality design §8 host test 2: a `Bind` naming a preset this version
/// does not know is refused like any malformed bind, before its session is
/// looked up or claimed: nothing is captured, and the real bind still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_with_an_unknown_preset_is_refused_before_anything_opens() {
    let rig = rig(MediaLimits::default());
    let (_, binding) = start(&rig.host, 43, SessionMode::Control);
    for preset in [0, 4, 9, 255] {
        let (mut client, served) = connect(&rig.host);
        write_msg(&mut client, &bind_with(&binding, preset))
            .await
            .unwrap();
        assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
        assert_eq!(
            read_msg(&mut client).await.unwrap(),
            Some(Msg::BindRefused {
                reason: reason::PROTOCOL
            }),
            "preset {preset}"
        );
    }
    assert_eq!(rig.backend.sources.load(Ordering::SeqCst), 0);
    let (client, served) = connect(&rig.host);
    let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
    drop(viewer);
    assert!(matches!(served.await.unwrap(), MediaOutcome::Served { .. }));
}

/// The quality design §4.7: a viewer of the version before it sends a
/// 49-byte `Bind`, which is refused as a protocol error with nothing opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_of_the_previous_version_is_refused() {
    let rig = rig(MediaLimits::default());
    let (_, binding) = start(&rig.host, 44, SessionMode::Control);
    let mut old = bind_with(&binding, quality::BALANCED).encode();
    old.pop();
    old[..4].copy_from_slice(&49u32.to_be_bytes());
    let (mut client, served) = connect(&rig.host);
    client.write_all(&old).await.unwrap();
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
    assert_eq!(
        read_msg(&mut client).await.unwrap(),
        Some(Msg::BindRefused {
            reason: reason::PROTOCOL
        })
    );
    assert_eq!(rig.backend.sources.load(Ordering::SeqCst), 0);
}

/// The quality design §4.6 and §8 host test 12: `SetQuality` is legal in
/// control and view-only sessions alike, and honoured in both: the host says
/// the new preset in a `Quality` (the card is under every cap, so the size
/// stays), and the picture after it is an IDR. Input is still injected in
/// control, and still dropped undecoded in view-only: bytes no decoder
/// accepts end nothing there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_quality_is_honoured_in_either_mode() {
    for (seed, mode) in [(45, SessionMode::Control), (46, SessionMode::ViewOnly)] {
        let rig = rig(MediaLimits::default());
        let (_, binding) = start(&rig.host, seed, mode);
        let (mut client, served) = connect(&rig.host);
        bind_raw(&mut client, &binding).await;
        write_msg(
            &mut client,
            &Msg::SetQuality {
                quality: quality::BEST_PERFORMANCE,
            },
        )
        .await
        .unwrap();
        let key = InputEvent::Key {
            usb: KEY_A,
            pressed: true,
        };
        write_msg(&mut client, &Msg::Input(key.encode()))
            .await
            .unwrap();
        if matches!(mode, SessionMode::ViewOnly) {
            write_msg(&mut client, &Msg::Input([0xff; 16]))
                .await
                .unwrap();
        }
        let since = tokio::time::Instant::now();
        let said = loop {
            in_time(since, "the Quality");
            if let msg @ Msg::Quality { .. } = next_acking(&mut client).await {
                break msg;
            }
        };
        assert_eq!(
            said,
            Msg::Quality {
                width: 256,
                height: 96,
                quality: BEST_PERFORMANCE,
            },
            "{mode:?}"
        );
        let flags = loop {
            in_time(since, "the picture after the Quality");
            match next_acking(&mut client).await {
                Msg::Video { flags, .. } => break flags,
                Msg::Stats(_) | Msg::Pong { .. } => {}
                other => panic!("{mode:?}: after the Quality: {other:?}"),
            }
        };
        assert_ne!(flags & video_flags::KEYFRAME, 0, "{mode:?}");
        sync(&mut client, 7).await;
        write_msg(
            &mut client,
            &Msg::Close {
                reason: reason::ENDED_BY_VIEWER,
            },
        )
        .await
        .unwrap();
        let MediaOutcome::Served { report, end, .. } = served.await.unwrap() else {
            panic!("not served");
        };
        assert_eq!(end, MediaEnd::ViewerLeft, "{mode:?}");
        assert_eq!(
            (report.quality_requests, report.quality_changes),
            (1, 1),
            "{mode:?}"
        );
        if matches!(mode, SessionMode::Control) {
            assert_eq!(report.input_injected, 1);
            assert_eq!(rig.backend.recorder.events()[0], key);
        } else {
            assert_eq!((report.input_injected, report.input_dropped), (0, 2));
            assert!(rig.backend.recorder.events().is_empty());
        }
        assert_eq!(rig.backend.sources.load(Ordering::SeqCst), 1, "{mode:?}");
    }
}

/// The quality design §8 host test 13: `Stats` come about once per
/// `stats_every`, each just before a picture, each with pictures in its
/// window and the card's size as the source, and with the stages' means;
/// the report sums the same stages over the whole stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stats_come_about_once_per_period_with_the_stages_means() {
    let every = Duration::from_millis(200);
    let rig = rig(MediaLimits {
        stats_every: every,
        ..MediaLimits::default()
    });
    let (_, binding) = start(&rig.host, 62, SessionMode::ViewOnly);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    let run = Duration::from_millis(1500);
    let started = std::time::Instant::now();
    let mut stats = Vec::new();
    let mut after_stats = false;
    while started.elapsed() < run {
        match next_acking(&mut client).await {
            Msg::Stats(s) => {
                assert!(!after_stats, "two Stats with no picture between");
                stats.push(s);
                after_stats = true;
            }
            Msg::Video { .. } => after_stats = false,
            other => panic!("{other:?}"),
        }
    }
    // A window opens when the last closes, and closes at the first picture
    // after `every`: at most one per period, and at 15 fps not much later.
    let most = run.as_millis().div_ceil(every.as_millis()) as usize;
    assert!(
        (3..=most).contains(&stats.len()),
        "{} Stats in {run:?}",
        stats.len()
    );
    for s in &stats {
        assert_eq!((s.source_width, s.source_height), (256, 96), "{s:?}");
        assert!(s.frames > 0, "{s:?}");
        assert!(u128::from(s.window_ms) >= every.as_millis(), "{s:?}");
        assert!(
            s.grab_us > 0 && s.encode_us > 0 && s.convert_us > 0,
            "{s:?}"
        );
    }
    assert!(
        stats.iter().any(|s| s.ack_us > 0),
        "acknowledged pictures have a round trip: {stats:?}"
    );
    drop(client);
    let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    let in_windows: u64 = stats.iter().map(|s| u64::from(s.frames)).sum();
    assert!(in_windows <= report.frames_sent, "{report:?}");
    assert!(
        report.acks > 0 && report.acks <= report.frames_sent,
        "{report:?}"
    );
    assert!(report.grab_us > 0 && report.encode_us > 0 && report.convert_us > 0);
    assert!(report.ack_us > 0, "{report:?}");
    assert_eq!(
        (
            report.repeats,
            report.quality_requests,
            report.quality_changes
        ),
        (0, 0, 0)
    );
}

/// Read, acknowledging every `Video`, until the host has said nothing for
/// `quiet`: what it said meanwhile.
async fn drain(client: &mut DuplexStream, quiet: Duration) -> Vec<Msg> {
    let mut said = Vec::new();
    while let Ok(msg) = tokio::time::timeout(quiet, read_msg(client)).await {
        let msg = msg.unwrap().expect("the stream is open");
        if let Msg::Video { seq, .. } = msg {
            write_msg(client, &Msg::VideoAck { seq }).await.unwrap();
        }
        said.push(msg);
    }
    said
}

/// A raw viewer's decoder, fed every picture in order.
struct Decoded(H264Decoder);

impl Decoded {
    fn new() -> Self {
        Self(H264Decoder::new().unwrap())
    }

    /// Decode `data`: the picture's card index and size.
    fn picture(&mut self, data: &[u8]) -> (Option<u32>, (u32, u32)) {
        let frame = self.0.decode(data).unwrap().expect("a picture");
        (
            TestCard::read_index(&frame.rgba, frame.width, frame.height),
            (frame.width, frame.height),
        )
    }
}

/// Three pictures, then the card held still (as GDI is while a secure screen
/// shows) and what was on its way read, acknowledged and decoded: the card
/// index of the last picture, the one a quality change encodes again.
async fn go_still(rig: &Rig, client: &mut DuplexStream, decoded: &mut Decoded) -> u32 {
    let mut last = None;
    let mut pictures = 0;
    let since = tokio::time::Instant::now();
    while pictures < 3 {
        in_time(since, "three pictures");
        if let Msg::Video { data, .. } = next_acking(client).await {
            last = decoded.picture(&data).0;
            pictures += 1;
        }
    }
    rig.backend.stalled.store(true, Ordering::SeqCst);
    for msg in drain(client, Duration::from_millis(500)).await {
        if let Msg::Video { data, .. } = msg {
            last = decoded.picture(&data).0;
        }
    }
    last.expect("the card's index")
}

/// The host's answer to a pick: its `Quality`, then the picture after it
/// (`Stats` may go out between), acknowledged: the `Quality`, the picture's
/// flags and its access unit.
async fn answer(client: &mut DuplexStream) -> (Msg, u8, Vec<u8>) {
    let since = tokio::time::Instant::now();
    let said = loop {
        in_time(since, "the Quality");
        match next_acking(client).await {
            msg @ Msg::Quality { .. } => break msg,
            Msg::Stats(_) => {}
            other => panic!("before the Quality: {other:?}"),
        }
    };
    loop {
        in_time(since, "the picture after the Quality");
        match next_acking(client).await {
            Msg::Video { flags, data, .. } => return (said, flags, data),
            Msg::Stats(_) => {}
            other => panic!("after the Quality: {other:?}"),
        }
    }
}

/// Close the stream as a viewer does and return the host's report.
async fn close_and_report(
    client: &mut DuplexStream,
    served: JoinHandle<MediaOutcome>,
) -> MediaReport {
    write_msg(
        client,
        &Msg::Close {
            reason: reason::ENDED_BY_VIEWER,
        },
    )
    .await
    .unwrap();
    let MediaOutcome::Served { report, end, .. } =
        tokio::time::timeout(WAIT, served).await.unwrap().unwrap()
    else {
        panic!("not served");
    };
    assert_eq!(end, MediaEnd::ViewerLeft);
    report
}

/// The quality design §8 host test 5: on a still screen a `SetQuality` is
/// answered at once, without anything moving on the desktop: a `Quality`
/// naming the new preset and an IDR of the last picture again (the same card
/// index), within a poll of the capture thread and 200 ms. Nothing more
/// comes while the screen stays still.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_quality_change_on_a_still_screen_is_answered_within_a_poll() {
    let rig = rig(MediaLimits::default());
    let (_, binding) = start(&rig.host, 70, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    let mut decoded = Decoded::new();
    let last = go_still(&rig, &mut client, &mut decoded).await;

    let asked = std::time::Instant::now();
    write_msg(
        &mut client,
        &Msg::SetQuality {
            quality: quality::BEST_PERFORMANCE,
        },
    )
    .await
    .unwrap();
    let (said, flags, data) = answer(&mut client).await;
    let took = asked.elapsed();
    assert_eq!(
        said,
        Msg::Quality {
            width: 256,
            height: 96,
            quality: BEST_PERFORMANCE,
        }
    );
    assert!(
        took <= host::POLL + Duration::from_millis(200),
        "answered after {took:?}"
    );
    assert_ne!(flags & video_flags::KEYFRAME, 0, "an IDR");
    assert_eq!(
        decoded.picture(&data),
        (Some(last), (256, 96)),
        "the last picture again"
    );
    let after = drain(&mut client, Duration::from_millis(400)).await;
    assert!(
        !after.iter().any(|msg| matches!(msg, Msg::Video { .. })),
        "the screen is still: {after:?}"
    );
    let report = close_and_report(&mut client, served).await;
    assert_eq!(
        (
            report.repeats,
            report.quality_changes,
            report.keyframes_forced
        ),
        (1, 1, 0)
    );
}

/// Host test 6: on a still screen, a second pick 100 ms after the first is
/// answered once the gate's interval since the first is over, not sooner,
/// and again with the last picture (no new capture).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_pick_within_the_interval_is_answered_when_it_is_over() {
    let interval = Duration::from_millis(300);
    let rig = rig(MediaLimits {
        quality_interval: interval,
        keyframe_interval: interval,
        ..MediaLimits::default()
    });
    let (_, binding) = start(&rig.host, 71, SessionMode::ViewOnly);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    let mut decoded = Decoded::new();
    let last = go_still(&rig, &mut client, &mut decoded).await;

    let asked = std::time::Instant::now();
    for (quality, wait) in [
        (quality::BEST_PERFORMANCE, Duration::from_millis(100)),
        (quality::BEST_QUALITY, Duration::ZERO),
    ] {
        write_msg(&mut client, &Msg::SetQuality { quality })
            .await
            .unwrap();
        tokio::time::sleep(wait).await;
    }
    let (said, flags, data) = answer(&mut client).await;
    assert!(
        matches!(
            said,
            Msg::Quality {
                quality: BEST_PERFORMANCE,
                ..
            }
        ),
        "{said:?}"
    );
    assert_ne!(flags & video_flags::KEYFRAME, 0);
    assert_eq!(decoded.picture(&data).0, Some(last));

    let (said, flags, data) = answer(&mut client).await;
    let took = asked.elapsed();
    assert_eq!(
        said,
        Msg::Quality {
            width: 256,
            height: 96,
            quality: BEST_QUALITY,
        }
    );
    // The first action came after `asked`, and the next one an interval
    // after it at the soonest.
    assert!(took >= interval, "answered after {took:?}");
    assert!(
        took <= interval + host::POLL + Duration::from_millis(400),
        "answered after {took:?}"
    );
    assert_ne!(flags & video_flags::KEYFRAME, 0);
    assert_eq!(
        decoded.picture(&data).0,
        Some(last),
        "no new picture was captured"
    );
    let report = close_and_report(&mut client, served).await;
    assert_eq!(
        (
            report.quality_requests,
            report.quality_changes,
            report.repeats
        ),
        (2, 2, 2)
    );
}

/// `picks` (cycled) sent every 5 ms for `flood` to a host serving a still
/// screen, with what the host wrote meanwhile read on another task, stamped
/// from just before the first pick; then a `Close` after one more `wait`.
/// Returns the stamped frames, the picks sent and the host's report.
async fn flood_of_picks(
    rig: &Rig,
    seed: u8,
    picks: &[u8],
    flood: Duration,
    wait: Duration,
) -> (Vec<(Duration, Msg)>, u64, MediaReport) {
    let (_, binding) = start(&rig.host, seed, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    go_still(rig, &mut client, &mut Decoded::new()).await;
    let (mut rd, mut wr) = tokio::io::split(client);
    let started = std::time::Instant::now();
    let reader = tokio::spawn(async move {
        let mut said = Vec::new();
        while let Some(msg) = read_msg(&mut rd).await.unwrap() {
            said.push((started.elapsed(), msg));
        }
        said
    });
    let mut sent = 0u64;
    for &quality in picks.iter().cycle() {
        if started.elapsed() >= flood {
            break;
        }
        write_msg(&mut wr, &Msg::SetQuality { quality })
            .await
            .unwrap();
        sent += 1;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The last pick may wait one more turn of the gate.
    tokio::time::sleep(wait).await;
    write_msg(
        &mut wr,
        &Msg::Close {
            reason: reason::ENDED_BY_VIEWER,
        },
    )
    .await
    .unwrap();
    let said = tokio::time::timeout(WAIT, reader).await.unwrap().unwrap();
    let MediaOutcome::Served { report, end, .. } =
        tokio::time::timeout(WAIT, served).await.unwrap().unwrap()
    else {
        panic!("not served");
    };
    assert_eq!(end, MediaEnd::ViewerLeft);
    (said, sent, report)
}

/// The quality design §5.3 and §8 host test 7: a flood of picks of the
/// preset in force on a still screen costs a count each and is answered at
/// most once per interval, with a `Quality` and no encoder work: no
/// `Video` at all, no change. Within the flood's 3 s, at most
/// ceil(3 s / 300 ms) + 1 answers; one more may come for the last pick.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_of_picks_of_the_preset_in_force_is_answered_once_per_interval() {
    let interval = Duration::from_millis(300);
    let flood = Duration::from_secs(3);
    let rig = rig(MediaLimits {
        quality_interval: interval,
        ..MediaLimits::default()
    });
    let (said, sent, report) = flood_of_picks(
        &rig,
        72,
        &[quality::BALANCED],
        flood,
        interval + Duration::from_millis(200),
    )
    .await;
    let mut answers = Vec::new();
    for (at, msg) in said {
        match msg {
            Msg::Quality { .. } => {
                assert_eq!(
                    msg,
                    Msg::Quality {
                        width: 256,
                        height: 96,
                        quality: APPLIED,
                    }
                );
                answers.push(at);
            }
            Msg::Close { .. } => {}
            other => panic!("only answers, never a picture: {other:?}"),
        }
    }
    let most = flood.as_millis().div_ceil(interval.as_millis()) as usize + 1;
    let within = answers.iter().filter(|&&at| at <= flood).count();
    assert!(
        within <= most,
        "{within} answers within the flood: {answers:?}"
    );
    assert!(answers.len() <= most + 1, "{answers:?}");
    assert!(answers.len() >= 5, "answered at every turn: {answers:?}");
    assert_eq!(report.quality_requests, sent);
    assert!(sent > 100, "a flood: {sent}");
    assert_eq!(
        (
            report.quality_changes,
            report.repeats,
            report.keyframes_forced
        ),
        (0, 0, 0)
    );
}

/// Host test 8: a flood alternating between two presets on a still screen
/// rebuilds the encoder (an IDR of the last picture each time) at most once
/// per keyframe interval, the longer of the two bounds here: within the
/// flood's 3 s, at most ceil(3 s / 1 s) + 1; one more may come for the last
/// pick. Each rebuild is said in a `Quality` before its picture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_alternating_flood_rebuilds_at_most_once_per_keyframe_interval() {
    let interval = Duration::from_millis(300);
    let flood = Duration::from_secs(3);
    let limits = MediaLimits {
        quality_interval: interval,
        ..MediaLimits::default()
    };
    let turn = limits.keyframe_interval.max(interval);
    let rig = rig(limits);
    let (said, sent, report) = flood_of_picks(
        &rig,
        73,
        &[quality::BEST_PERFORMANCE, quality::BEST_QUALITY],
        flood,
        turn + Duration::from_millis(300),
    )
    .await;
    let mut rebuilds = Vec::new();
    let mut said_before = false;
    for (at, msg) in said {
        match msg {
            Msg::Quality { .. } => said_before = true,
            Msg::Video { flags, .. } => {
                assert!(said_before, "a rebuild's picture after its Quality");
                assert_ne!(flags & video_flags::KEYFRAME, 0, "an IDR");
                said_before = false;
                rebuilds.push(at);
            }
            Msg::Stats(_) | Msg::Close { .. } => {}
            other => panic!("{other:?}"),
        }
    }
    let most = flood.as_millis().div_ceil(turn.as_millis()) as usize + 1;
    let within = rebuilds.iter().filter(|&&at| at <= flood).count();
    assert!(
        within <= most,
        "{within} rebuilds within the flood: {rebuilds:?}"
    );
    assert!(rebuilds.len() <= most + 1, "{rebuilds:?}");
    assert!(rebuilds.len() >= 2, "rebuilt at every turn: {rebuilds:?}");
    assert_eq!(report.quality_requests, sent);
    assert_eq!(report.repeats, rebuilds.len() as u64);
    assert!(
        (1..=report.repeats).contains(&report.quality_changes),
        "{report:?}"
    );
    assert_eq!(report.keyframes_forced, 0);
}

/// Host test 9: a rebuild for a quality change and a `KeyframeRequest`
/// share one keyframe limiter. A request right after a rebuild forces
/// nothing; a request a turn later forces an IDR, and a pick of another
/// preset right after it waits for the limiter's next turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebuilds_and_keyframe_requests_share_the_keyframe_limiter() {
    let turn = Duration::from_millis(600);
    let rig = rig(MediaLimits {
        keyframe_interval: turn,
        quality_interval: Duration::from_millis(300),
        ..MediaLimits::default()
    });
    let (_, binding) = start(&rig.host, 74, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    write_msg(
        &mut client,
        &Msg::SetQuality {
            quality: quality::BEST_PERFORMANCE,
        },
    )
    .await
    .unwrap();
    // The card moves: pictures on their way come before the answer.
    let since = tokio::time::Instant::now();
    loop {
        in_time(since, "the Quality for Best performance");
        if let Msg::Quality {
            quality: BEST_PERFORMANCE,
            ..
        } = next_acking(&mut client).await
        {
            break;
        }
    }
    let flags = loop {
        in_time(since, "the rebuild's picture");
        match next_acking(&mut client).await {
            Msg::Video { flags, .. } => break flags,
            Msg::Stats(_) => {}
            other => panic!("{other:?}"),
        }
    };
    assert_ne!(flags & video_flags::KEYFRAME, 0);
    // Right after the rebuild: counted, not forced.
    write_msg(&mut client, &Msg::KeyframeRequest).await.unwrap();
    tokio::time::sleep(turn + Duration::from_millis(100)).await;

    // A turn later: forced; and the pick after it waits a turn.
    let asked = std::time::Instant::now();
    write_msg(&mut client, &Msg::KeyframeRequest).await.unwrap();
    write_msg(
        &mut client,
        &Msg::SetQuality {
            quality: quality::BEST_QUALITY,
        },
    )
    .await
    .unwrap();
    let mut forced = false;
    let since = tokio::time::Instant::now();
    loop {
        in_time(since, "the Quality for Best quality");
        match next_acking(&mut client).await {
            Msg::Quality {
                quality: BEST_QUALITY,
                ..
            } => break,
            // Pictures the window let out meanwhile, then the forced IDR.
            Msg::Video { flags, .. } => {
                forced |= asked.elapsed() < turn && flags & video_flags::KEYFRAME != 0;
            }
            Msg::Stats(_) => {}
            other => panic!("{other:?}"),
        }
    }
    let took = asked.elapsed();
    assert!(took >= turn, "the rebuild came after {took:?}");
    assert!(forced, "the request a turn later forced an IDR");
    let report = close_and_report(&mut client, served).await;
    assert_eq!(
        (report.keyframe_requests, report.keyframes_forced),
        (2, 1),
        "the request right after the rebuild forced nothing"
    );
    assert_eq!((report.quality_changes, report.repeats), (2, 2));
}

/// A desktop whose size changes: a card of one size for its first `after`
/// pictures, then a card of another.
struct Resizing {
    small: TestCard,
    large: TestCard,
    after: u32,
}

impl VideoSource for Resizing {
    fn name(&self) -> &'static str {
        "resizing"
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        if self.after == 0 {
            return self.large.next_frame(timeout);
        }
        let frame = self.small.next_frame(timeout)?;
        self.after -= u32::from(frame.is_some());
        Ok(frame)
    }
}

/// The quality design §4.1 and §8 host test 15: a source that changes size
/// (640×360, then 800×600) is said in a `Quality` with the new size before
/// the first picture at that size, an IDR; every picture decodes at the size
/// last announced (`BindOk`, then the `Quality`), so a viewer counting
/// mismatches counts none; the preset stays, so no change is counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_resize_is_said_before_its_first_picture() {
    let backend = TestBackend {
        desktop: Mutex::new(Some(Box::new(Resizing {
            small: TestCard::new(640, 360, 60),
            large: TestCard::new(800, 600, 60),
            after: 5,
        }))),
        ..TestBackend::default()
    };
    let rig = rig_with(backend, MediaLimits::default());
    let (_, binding) = start(&rig.host, 75, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    let (width, height, info) = bind_preset(&mut client, &binding, quality::BALANCED).await;
    assert_eq!((width, height, info), (640, 360, APPLIED));
    let mut announced = (width, height);
    let mut unannounced = 0;
    let mut said = Vec::new();
    let mut sizes = Vec::new();
    let mut decoded = Decoded::new();
    let since = tokio::time::Instant::now();
    while sizes.iter().filter(|(size, _)| *size == (800, 600)).count() < 5 {
        in_time(since, "five pictures at the new size");
        match next_acking(&mut client).await {
            Msg::Quality {
                width,
                height,
                quality,
            } => {
                announced = (width, height);
                said.push((width, height, quality));
            }
            Msg::Video { flags, data, .. } => {
                let (_, size) = decoded.picture(&data);
                unannounced += usize::from(size != announced);
                sizes.push((size, flags & video_flags::KEYFRAME != 0));
            }
            Msg::Stats(_) => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(unannounced, 0, "{sizes:?}");
    assert_eq!(said, [(800, 600, APPLIED)]);
    let first_large = sizes.iter().position(|(size, _)| *size == (800, 600));
    assert_eq!(first_large, Some(5), "{sizes:?}");
    assert!(sizes[5].1, "the first picture at the new size is an IDR");
    let report = close_and_report(&mut client, served).await;
    assert_eq!((report.quality_changes, report.repeats), (0, 0));
}

/// The quality design §8 host test 14: a viewer's `Quality` or `Stats`, the
/// host's own messages, ends the stream as a protocol error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewers_quality_or_stats_is_a_protocol_error() {
    let rig = rig(MediaLimits::default());
    for (seed, msg) in [
        (
            47,
            Msg::Quality {
                width: 256,
                height: 96,
                quality: APPLIED,
            },
        ),
        (
            48,
            Msg::Stats(HostStats {
                window_ms: 1,
                ..HostStats::default()
            }),
        ),
    ] {
        let (_, binding) = start(&rig.host, seed, SessionMode::Control);
        let (mut client, served) = connect(&rig.host);
        bind_raw(&mut client, &binding).await;
        write_msg(&mut client, &msg).await.unwrap();
        let MediaOutcome::Served { end, .. } = served.await.unwrap() else {
            panic!("not served");
        };
        assert_eq!(end, MediaEnd::Protocol, "{msg:?}");
        assert_eq!(until_close(&mut client).await, Some(reason::PROTOCOL));
    }
}

/// Capture that cannot start refuses the bind, says why, and starts nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_capture_that_cannot_start_refuses_the_bind() {
    let rig = rig_with(
        TestBackend {
            fail: true,
            ..TestBackend::default()
        },
        MediaLimits::default(),
    );
    let (_, binding) = start(&rig.host, 11, SessionMode::Control);
    let (client, served) = connect(&rig.host);
    let refused = MediaViewer::bind(client, &binding, WAIT).await.unwrap_err();
    assert!(
        matches!(refused, ViewerError::Refused(r) if r == reason::CAPTURE_FAILED),
        "{refused:?}"
    );
    assert_eq!(
        served.await.unwrap(),
        MediaOutcome::NotStarted(MediaEnd::Pipeline(reason::CAPTURE_FAILED))
    );
    assert!(
        rig.seen.lines().is_empty(),
        "no sharing indicator for nothing shared"
    );
}

/// SLICE-A2 A2-4 and the decode-error rule, from the viewer's side: an access
/// unit that does not decode asks for a keyframe and is still acknowledged.
#[tokio::test]
async fn an_undecodable_unit_asks_for_a_keyframe_and_is_still_acknowledged() {
    let mut encoder = H264Encoder::new(EncoderSettings::default()).unwrap();
    let _idr = encoder
        .encode(&TestCard::render(256, 96, 0), 256, 96)
        .unwrap();
    let p_frame = encoder
        .encode(&TestCard::render(256, 96, 1), 256, 96)
        .unwrap();
    assert!(!p_frame.keyframe);

    let (client, mut host) = duplex(1 << 20);
    let fake_host = tokio::spawn(async move {
        assert!(matches!(
            read_msg(&mut host).await.unwrap(),
            Some(Msg::Bind { .. })
        ));
        let bind_ok = Msg::BindOk {
            width: 256,
            height: 96,
            codec: codec::H264,
            mode: 0,
            quality: APPLIED,
        };
        write_msg(&mut host, &bind_ok).await.unwrap();
        // The P-frame alone: the viewer has no parameter sets to decode it with.
        let video = Msg::Video {
            seq: 0,
            flags: 0,
            ts_ms: 0,
            data: p_frame.data,
        };
        write_msg(&mut host, &video).await.unwrap();
        let answers = [
            read_msg(&mut host).await.unwrap(),
            read_msg(&mut host).await.unwrap(),
        ];
        let close = Msg::Close {
            reason: reason::ENDED_BY_HOST,
        };
        write_msg(&mut host, &close).await.unwrap();
        answers
    });

    let binding = Binding::new(&SessionToken::new([1; 32]), &[2; 32]);
    let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
    let (mut pictures, _) = Pictures::wanting(usize::MAX);
    let mut stats = ViewerStats::default();
    let end = viewer
        .run(&mut pictures, &mut stats, std::future::pending())
        .await
        .unwrap();
    assert_eq!(end, ViewerEnd::Host(reason::ENDED_BY_HOST));
    assert_eq!(
        fake_host.await.unwrap(),
        [Some(Msg::KeyframeRequest), Some(Msg::VideoAck { seq: 0 })]
    );
    assert_eq!(
        (stats.decoded, stats.decode_errors, stats.keyframe_requests),
        (0, 1, 1)
    );
}

/// Through the real handshake: the FSM's `on_start` registers the session, the
/// client binds with the handshake's own token and transcript, the card
/// streams, and the panic key stops capture and ends both streams.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accepted_session_streams_until_the_panic_key() {
    let tmp = tempfile::tempdir().unwrap();
    let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
    let trusted = Arc::new(TrustedDeviceStore::with(
        tmp.path().join("trusted-devices.toml"),
        tornect_core::trusted::TrustedDevices::default(),
    ));
    let consent = Arc::new(ScriptedConsent::new());
    consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let rig = rig(MediaLimits::default());
    let mut deps = HostDeps::headless(identity.clone(), trusted);
    deps.consent = consent;
    deps.sessions = rig.host.clone();
    let kill = deps.kill.clone();
    let cfg = HostConfig::new("Desk", [9; 32]);
    let (client_end, host_end) = duplex(64 * 1024);
    let fsm = tokio::spawn(async move { serve_host(host_end, &cfg, &deps).await });

    let known = Arc::new(KnownHostStore::with(
        tmp.path().join("known-hosts.toml"),
        tornect_core::trusted::KnownHosts::default(),
    ));
    let mut client_deps = ClientDeps::headless(known);
    client_deps.ui = Arc::new(ScriptedClientUi::new(true));
    let device = DeviceIdentity::from_seed(&[0x22; 32]);
    let ccfg = ClientConfig::new(identity.id(), "Laptop");
    let ClientOutcome::Session(mut session) =
        client::connect(client_end, &ccfg, &device, &client_deps, Intent::Session)
            .await
            .unwrap()
    else {
        panic!("no session");
    };
    session.send_tor_fallback().await.unwrap();

    let binding = Binding::new(session.session_token(), &session.th());
    let (media, served) = connect(&rig.host);
    let viewer = MediaViewer::bind(media, &binding, WAIT).await.unwrap();
    let (mut pictures, enough) = Pictures::wanting(3);
    let panic_key = tokio::spawn(async move {
        let _ = enough.await;
        kill.kill(bye::PANIC);
    });
    let mut stats = ViewerStats::default();
    let end = viewer
        .run(&mut pictures, &mut stats, std::future::pending())
        .await
        .unwrap();
    panic_key.await.unwrap();
    assert_eq!(end, ViewerEnd::Host(reason::ENDED_BY_HOST));
    assert!(pictures.indices.len() >= 3);

    let MediaOutcome::Served { end, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!(end, MediaEnd::SessionOver(reason::ENDED_BY_HOST));
    assert!(
        rig.backend.closed.load(Ordering::SeqCst),
        "the panic key stopped capture"
    );
    assert_eq!(
        session.next_event(WAIT).await.unwrap(),
        Some(SessionEvent::Bye {
            reason: bye::PANIC,
            detail: None
        })
    );
    fsm.await.unwrap().unwrap();
    assert_eq!(rig.host.live(), 0);
}

/// The hosts' session sinks in small: the media layer's sessions, and a
/// notice code of 0 for every session (a control session's start code on a
/// host that does not run Windows), with what the media layer knows added.
struct NoticeSink(Arc<MediaHost>);

impl SessionSink for NoticeSink {
    fn on_start(&self, session: &LiveSession<'_>) {
        self.0.on_start(session);
    }

    fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
        self.0.on_end(session_id, end);
    }

    fn notice(&self, session_id: &str) -> Option<u8> {
        self.0.viewer_notice(session_id, Some(0))
    }
}

/// Through the real handshake: a control session whose host has nothing to
/// inject into tells its viewer so in the `PONG` that answers its next
/// `PING`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_viewer_of_a_control_session_with_no_injector_hears_it_at_its_next_ping() {
    let tmp = tempfile::tempdir().unwrap();
    let identity = Arc::new(HostIdentity::from_seed(&[0x13; 32]));
    let trusted = Arc::new(TrustedDeviceStore::with(
        tmp.path().join("trusted-devices.toml"),
        tornect_core::trusted::TrustedDevices::default(),
    ));
    let consent = Arc::new(ScriptedConsent::new());
    consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let rig = rig_with(
        TestBackend {
            no_injector: true,
            ..TestBackend::default()
        },
        MediaLimits::default(),
    );
    let mut deps = HostDeps::headless(identity.clone(), trusted);
    deps.consent = consent;
    deps.sessions = Arc::new(NoticeSink(rig.host.clone()));
    let kill = deps.kill.clone();
    let cfg = HostConfig::new("Desk", [9; 32]);
    let (client_end, host_end) = duplex(64 * 1024);
    let fsm = tokio::spawn(async move { serve_host(host_end, &cfg, &deps).await });

    let known = Arc::new(KnownHostStore::with(
        tmp.path().join("known-hosts.toml"),
        tornect_core::trusted::KnownHosts::default(),
    ));
    let mut client_deps = ClientDeps::headless(known);
    client_deps.ui = Arc::new(ScriptedClientUi::new(true));
    let device = DeviceIdentity::from_seed(&[0x24; 32]);
    let ccfg = ClientConfig::new(identity.id(), "Laptop");
    let ClientOutcome::Session(mut session) =
        client::connect(client_end, &ccfg, &device, &client_deps, Intent::Session)
            .await
            .unwrap()
    else {
        panic!("no session");
    };
    session.send_tor_fallback().await.unwrap();
    let notices = session.notices();
    session.ping().await.unwrap();
    assert_eq!(*notices.borrow(), Some(0), "before the media stream");

    let binding = Binding::new(session.session_token(), &session.th());
    let (media, served) = connect(&rig.host);
    let viewer = MediaViewer::bind(media, &binding, WAIT).await.unwrap();
    assert_eq!(viewer.bound().mode, SessionMode::Control);
    let started = std::time::Instant::now();
    while rig.seen.lines().is_empty() {
        assert!(started.elapsed() < WAIT, "capture never started");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    session.ping().await.unwrap();
    assert_eq!(
        *notices.borrow(),
        Some(tornect_signal::messages::notice::NO_INPUT)
    );

    kill.kill(bye::PANIC);
    drop(viewer);
    assert!(matches!(served.await.unwrap(), MediaOutcome::Served { .. }));
    fsm.await.unwrap().unwrap();
}

/// A host that never stops sending: `BindOk`, then the same `Video` unit for
/// ever, always ready, as bytes already buffered in Arti would be. Writes
/// always succeed at once.
struct Flood {
    head: Vec<u8>,
    unit: Vec<u8>,
    pos: usize,
}

impl Flood {
    async fn new() -> Self {
        let mut head = Vec::new();
        write_msg(
            &mut head,
            &Msg::BindOk {
                width: 1280,
                height: 720,
                codec: codec::H264,
                mode: 1,
                quality: APPLIED,
            },
        )
        .await
        .unwrap();
        let mut unit = Vec::new();
        let video = Msg::Video {
            seq: 0,
            flags: 0,
            ts_ms: 0,
            data: vec![0, 0, 0, 1, 0x41, 0x9a],
        };
        write_msg(&mut unit, &video).await.unwrap();
        Self { head, unit, pos: 0 }
    }
}

impl tokio::io::AsyncRead for Flood {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        while buf.remaining() > 0 {
            let (src, pos) = if self.pos < self.head.len() {
                (&self.head, self.pos)
            } else {
                let at = (self.pos - self.head.len()) % self.unit.len();
                (&self.unit, at)
            };
            let n = (src.len() - pos).min(buf.remaining());
            buf.put_slice(&src[pos..pos + n]);
            self.pos += n;
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for Flood {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

struct NoPictures;

impl FrameSink for NoPictures {
    fn picture(&mut self, _: u32, _: &DecodedFrame) {}
}

/// A [`Flood`] that takes the first `writes` writes (the `Bind`), and then no
/// more, as a host that stops granting Tor credit.
struct StallsWrites {
    flood: Flood,
    writes: usize,
    stalled: bool,
}

impl tokio::io::AsyncRead for StallsWrites {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.flood).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for StallsWrites {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.writes == 0 {
            self.stalled = true;
            return std::task::Poll::Pending;
        }
        self.writes -= 1;
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.stalled {
            return std::task::Poll::Pending;
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.stalled {
            return std::task::Poll::Pending;
        }
        std::task::Poll::Ready(Ok(()))
    }
}

/// SLICE-C2 C2-2 (b): a stop is heard while a write to the host is stalled.
/// The acks, keyframe requests and pongs were written outside the race with
/// `stop`, so a host that stopped granting credit held a Ctrl-C back for as
/// long as the stall timer allows, 30 s, per write.
#[tokio::test(start_paused = true)]
async fn a_stop_is_heard_while_a_write_to_the_host_is_stalled() {
    let binding = Binding::new(&SessionToken::new([5; 32]), &[5; 32]);
    let stream = StallsWrites {
        flood: Flood::new().await,
        writes: 1,
        stalled: false,
    };
    let viewer = MediaViewer::bind(stream, &binding, WAIT).await.unwrap();
    let (mut sink, mut stats) = (NoPictures, ViewerStats::default());
    let stop = tokio::time::sleep(Duration::from_secs(1));
    let ended = tokio::time::timeout(
        Duration::from_secs(60),
        viewer.run(&mut sink, &mut stats, stop),
    )
    .await
    .expect("the stop waited behind a stalled write");
    assert!(matches!(ended, Ok(ViewerEnd::Stopped)), "{ended:?}");
    assert!(
        stats.access_units >= 1,
        "it read a unit and stalled on its ack"
    );
}

/// SLICE-C2 C2-1: a host that sends as fast as the stream allows must not
/// starve what the viewer is joined with — in `tornect connect`, the
/// signaling keep-alive and its Ctrl-C. Before, `run` never returned `Pending`
/// while units kept coming, so the other branch of a `join!` never ran again.
#[test]
fn a_flooding_host_does_not_starve_what_the_viewer_is_joined_with() {
    let (done, finished) = std::sync::mpsc::channel();
    // On its own thread: on the old code this spins for good.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let ended = rt.block_on(async {
            let binding = Binding::new(&SessionToken::new([5; 32]), &[5; 32]);
            let viewer = MediaViewer::bind(Flood::new().await, &binding, WAIT)
                .await
                .unwrap();
            let (stop_tx, stop_rx) = oneshot::channel::<()>();
            let (mut sink, mut stats) = (NoPictures, ViewerStats::default());
            let stop = async {
                let _ = stop_rx.await;
            };
            let (ended, ()) = tokio::join!(viewer.run(&mut sink, &mut stats, stop), async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = stop_tx.send(());
            });
            ended
        });
        let _ = done.send(format!("{ended:?}"));
    });
    let ended = finished
        .recv_timeout(Duration::from_secs(20))
        .expect("the viewer never let the other branch run");
    assert_eq!(ended, "Ok(Stopped)");
}
