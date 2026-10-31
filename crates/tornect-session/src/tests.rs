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
use tornect_capture::{
    CaptureError, Frame, Layout, Monitor, Rect, Selection, TestCard, TestScreens, VideoSource, View,
};
use tornect_codec::scale::{ResolutionCap, picture_size, shown_region};
use tornect_codec::{DecodedFrame, EncoderSettings, H264Decoder, H264Encoder};
use tornect_core::config::QualityPreset;
use tornect_core::session_log::SessionMode;
use tornect_core::{DeviceId, DeviceIdentity, HostIdentity};
use tornect_input::{Button, InputError, InputEvent, InputSink, denormalize, remap};
use tornect_proto::{
    HostStats, Msg, QualityInfo, codec, quality, read_msg, reason, seq_reached, video_flags,
    write_msg,
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

mod direct_bind;
mod direct_host;
mod direct_loopback;
mod direct_nat;
mod direct_path;

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

/// Records what is injected, and each view the injector is told to follow.
#[derive(Clone, Default)]
struct Recorder {
    events: Arc<Mutex<Vec<InputEvent>>>,
    /// Each view received, with how many events had been injected before it.
    views: Arc<Mutex<Vec<(usize, View)>>>,
    /// Refuse every view, as an injector that cannot follow the picture to
    /// another screen.
    refuses: Arc<AtomicBool>,
}

impl Recorder {
    fn events(&self) -> Vec<InputEvent> {
        self.events.lock().unwrap().clone()
    }

    fn views(&self) -> Vec<(usize, View)> {
        self.views.lock().unwrap().clone()
    }
}

impl InputSink for Recorder {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        self.events.lock().unwrap().push(*event);
        Ok(())
    }

    fn retarget(&mut self, view: &View) -> Result<(), InputError> {
        let injected = self.events.lock().unwrap().len();
        self.views.lock().unwrap().push((injected, *view));
        if self.refuses.load(Ordering::SeqCst) {
            return Err(InputError::Inject(
                "this injector cannot follow the picture".into(),
            ));
        }
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
    /// Opening takes this long, as a slow dialog the user answers does.
    open_for: Option<Duration>,
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
        if let Some(answered) = self.open_for {
            std::thread::sleep(answered);
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

    fn capture_changed(&self, c: &CaptureChanged<'_>) {
        let shown = c.shown.map_or_else(
            || "none".to_owned(),
            |r| format!("{}x{}+{}+{}", r.width, r.height, r.x, r.y),
        );
        self.0.lock().unwrap().push(format!(
            "changed screen={} of={} all={} shown={shown} input={}",
            c.screen, c.of, c.all, c.input
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
        transport: tornect_signal::consent::TransportPolicy::Any,
        viewer_dir1: false,
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
            mode: SessionMode::Control,
            quality: APPLIED,
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

/// A host that ended its stream before the viewer's answer to its last
/// frame: the answer's write fails, while the host's `Close` is still
/// unread behind that frame (on a direct QUIC stream the host's end stops
/// the viewer's sending half; on this pipe the host's half is gone). The
/// stream ends as the `Close` says, not with the write's error; with no
/// `Close` among the frames left, the write's error stands.
#[tokio::test(start_paused = true)]
async fn a_failed_write_after_the_hosts_close_ends_as_the_close_says() {
    for close in [true, false] {
        let (mut host, viewer) = run_viewer_with(None).await;
        // Neither task yields until the host's half is gone: the viewer
        // reads the `Ping` only then, and its `Pong` fails.
        write_msg(&mut host, &Msg::Ping { nonce: 7 }).await.unwrap();
        if close {
            let close = Msg::Close {
                reason: reason::ENDED_BY_HOST,
            };
            write_msg(&mut host, &close).await.unwrap();
        }
        drop(host);
        let (end, _) = tokio::time::timeout(WAIT, viewer).await.unwrap().unwrap();
        if close {
            assert!(
                matches!(end, Ok(ViewerEnd::Host(reason::ENDED_BY_HOST))),
                "{end:?}"
            );
        } else {
            assert!(
                matches!(&end, Err(ViewerError::Proto(tornect_proto::ProtoError::Io(e)))
                    if e.kind() == std::io::ErrorKind::BrokenPipe),
                "{end:?}"
            );
        }
    }
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

/// What a viewer's sink was told, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hook {
    Quality(u32, u32, QualityInfo),
    Stats(HostStats),
    Picture(u32, u32),
}

/// A sink that says each call as a [`Hook`].
struct Hooks(tokio::sync::mpsc::UnboundedSender<Hook>);

impl FrameSink for Hooks {
    fn picture(&mut self, _: u32, frame: &DecodedFrame) {
        let _ = self.0.send(Hook::Picture(frame.width, frame.height));
    }

    fn quality(&mut self, width: u32, height: u32, quality: &QualityInfo) {
        let _ = self.0.send(Hook::Quality(width, height, *quality));
    }

    fn host_stats(&mut self, stats: &HostStats) {
        let _ = self.0.send(Hook::Stats(*stats));
    }
}

/// The next hook, within [`WAIT`] of `since`.
async fn next_hook(
    hooks: &mut tokio::sync::mpsc::UnboundedReceiver<Hook>,
    since: tokio::time::Instant,
) -> Hook {
    in_time(since, "the hook");
    tokio::time::timeout(WAIT, hooks.recv())
        .await
        .expect("a hook in time")
        .expect("the viewer runs")
}

/// Every hook said so far.
fn hooks_so_far(hooks: &mut tokio::sync::mpsc::UnboundedReceiver<Hook>) -> Vec<Hook> {
    std::iter::from_fn(|| hooks.try_recv().ok()).collect()
}

/// A viewer's run, with what it received.
type ViewerRun = JoinHandle<(Result<ViewerEnd, ViewerError>, ViewerStats)>;

/// Bind a viewer over a pipe to a scripted host that answers `BindOk`
/// 1280×720 with [`APPLIED`], and run it into [`Hooks`] with `picks` and no
/// input (as a view-only session): the host's end past `BindOk`, the hooks
/// and the run.
async fn run_viewer_hooked(
    picks: Option<tokio::sync::watch::Receiver<QualityPreset>>,
) -> (
    DuplexStream,
    tokio::sync::mpsc::UnboundedReceiver<Hook>,
    ViewerRun,
) {
    let binding = Binding::new(&SessionToken::new([8; 32]), &[8; 32]);
    let (client, mut host) = duplex(1 << 16);
    let (tx, hooks) = tokio::sync::mpsc::unbounded_channel();
    let viewer = tokio::spawn(async move {
        let mut viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
        if let Some(picks) = picks {
            viewer = viewer.with_quality(picks);
        }
        let (mut sink, mut stats) = (Hooks(tx), ViewerStats::default());
        let end = viewer
            .run(&mut sink, &mut stats, std::future::pending())
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
        mode: 1,
        quality: APPLIED,
    };
    write_msg(&mut host, &bind_ok).await.unwrap();
    (host, hooks, viewer)
}

/// The next `SetQuality` the viewer wrote to the scripted host `host`, past
/// its pings, within [`WAIT`]: the preset's code. Anything else is a failure.
async fn next_set_quality(host: &mut DuplexStream) -> u8 {
    let since = tokio::time::Instant::now();
    loop {
        in_time(since, "a SetQuality");
        match tokio::time::timeout(WAIT, read_msg(host))
            .await
            .expect("a frame in time")
            .unwrap()
        {
            Some(Msg::Ping { .. }) => {}
            Some(Msg::SetQuality { quality: code }) => return code,
            other => panic!("expected SetQuality, got {other:?}"),
        }
    }
}

/// The monitors design §5.4.2: a source lists as many monitors as the
/// media stream's `Monitors` can carry.
#[test]
fn a_layout_lists_as_many_monitors_as_the_stream_carries() {
    assert_eq!(tornect_capture::MAX_MONITORS, tornect_proto::MAX_MONITORS);
}

/// The quality design §4.1 and §6.6: a `Binding` asks for Balanced unless
/// told otherwise, and `with_quality` names the preset in the `Bind`'s last
/// byte, outside the MAC (the bind MAC is the same for every preset), in a
/// 50-byte frame.
#[test]
fn a_binding_names_its_preset_outside_the_mac() {
    let plain = Binding::new(&SessionToken::new([9; 32]), &[3; 32]);
    assert_eq!(plain.quality(), QualityPreset::Balanced);
    let Msg::Bind {
        session_id,
        mac,
        quality: code,
    } = plain.msg()
    else {
        unreachable!("a binding's message is a Bind");
    };
    assert_eq!(code, quality::BALANCED);
    for preset in QualityPreset::ALL {
        let binding = plain.clone().with_quality(preset);
        assert_eq!(binding.quality(), preset);
        assert_eq!(
            binding.msg(),
            Msg::Bind {
                session_id: session_id.clone(),
                mac,
                quality: crate::quality::code(preset),
            }
        );
        let frame = binding.msg().encode();
        assert_eq!(frame.len(), 4 + 50);
        assert_eq!(frame[53], crate::quality::code(preset));
    }
}

/// The quality design §6.6 and §8 (viewer): each change of the viewer's
/// pick goes to the host as one `SetQuality` with the value held then (two
/// picks before the run give one frame, the latest), a value set again
/// without a change (`send_if_modified`, as the window sends) sends
/// nothing, picks need no input channel (view-only), and once the sender is
/// gone the viewer goes on without them.
#[tokio::test(start_paused = true)]
async fn a_viewers_picks_reach_the_host_as_set_quality() {
    let (picker, picks) = tokio::sync::watch::channel(QualityPreset::Balanced);
    picker.send(QualityPreset::BestQuality).unwrap();
    picker.send(QualityPreset::BestPerformance).unwrap();
    let (mut host, _hooks, viewer) = run_viewer_hooked(Some(picks)).await;
    assert_eq!(
        next_set_quality(&mut host).await,
        quality::BEST_PERFORMANCE,
        "the latest of two picks made before the run, once"
    );
    let changed = picker.send_if_modified(|held| {
        let changed = *held != QualityPreset::BestPerformance;
        *held = QualityPreset::BestPerformance;
        changed
    });
    assert!(!changed);
    picker.send(QualityPreset::BestQuality).unwrap();
    assert_eq!(
        next_set_quality(&mut host).await,
        quality::BEST_QUALITY,
        "the next frame after the first pick is the next pick"
    );
    drop(picker);
    // No sender: the viewer keeps going, with its pings and nothing else.
    for _ in 0..3 {
        let msg = tokio::time::timeout(Duration::from_secs(5), read_msg(&mut host))
            .await
            .expect("the viewer said nothing for 5 s");
        assert!(matches!(msg, Ok(Some(Msg::Ping { .. }))), "{msg:?}");
    }
    let close = Msg::Close {
        reason: reason::ENDED_BY_HOST,
    };
    write_msg(&mut host, &close).await.unwrap();
    let (end, stats) = viewer.await.unwrap();
    assert!(
        matches!(end, Ok(ViewerEnd::Host(r)) if r == reason::ENDED_BY_HOST),
        "{end:?}"
    );
    assert_eq!(stats.input_sent, 0);
}

/// The quality design §5.12 and §8 (viewer): what the host says it applies
/// reaches the sink first from `BindOk`, then only when a `Quality` changes
/// something (the same again is not said twice); the host's `Stats` reach it
/// at most once per 900 ms of the viewer's clock (ten within 100 ms give one
/// call, and the rest are counted), the last one always kept in the stats.
#[tokio::test(start_paused = true)]
async fn the_hosts_quality_and_stats_reach_the_sink_without_a_flood() {
    let (mut host, mut hooks, viewer) = run_viewer_hooked(None).await;
    let smaller = Msg::Quality {
        width: 1280,
        height: 694,
        quality: BEST_PERFORMANCE,
    };
    let same = Msg::Quality {
        width: 1280,
        height: 720,
        quality: APPLIED,
    };
    for msg in [&same, &smaller, &smaller] {
        write_msg(&mut host, msg).await.unwrap();
    }
    let means = |frames: u16| HostStats {
        source_width: 2560,
        source_height: 1440,
        frames,
        window_ms: 1000,
        encode_us: 9800,
        ..HostStats::default()
    };
    let first = tokio::time::Instant::now();
    for frames in 1..=10 {
        if frames > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        write_msg(&mut host, &Msg::Stats(means(frames)))
            .await
            .unwrap();
    }
    assert!(first.elapsed() < Duration::from_millis(100));
    tokio::time::sleep_until(first + Duration::from_millis(900)).await;
    write_msg(&mut host, &Msg::Stats(means(11))).await.unwrap();
    let close = Msg::Close {
        reason: reason::ENDED_BY_HOST,
    };
    write_msg(&mut host, &close).await.unwrap();
    let (end, stats) = viewer.await.unwrap();
    assert!(matches!(end, Ok(ViewerEnd::Host(_))), "{end:?}");
    assert_eq!(
        hooks_so_far(&mut hooks),
        [
            Hook::Quality(1280, 720, APPLIED),
            Hook::Quality(1280, 694, BEST_PERFORMANCE),
            Hook::Stats(means(1)),
            Hook::Stats(means(11)),
        ]
    );
    assert_eq!(stats.stats_coalesced, 9);
    assert_eq!(stats.host, Some(means(11)));
    assert_eq!(stats.quality, Some(BEST_PERFORMANCE));
}

/// The quality design §4.1: the viewer still sizes every picture from what
/// it decodes, and counts one decoded at a size the host did not announce
/// (`BindOk`, then each `Quality`); one announced first is not counted.
#[tokio::test(start_paused = true)]
async fn a_picture_of_a_size_not_announced_is_counted() {
    let mut encoder = H264Encoder::new(EncoderSettings::default()).unwrap();
    let idr = encoder
        .encode(&TestCard::render(64, 48, 0), 64, 48)
        .unwrap();
    let next = encoder
        .encode(&TestCard::render(64, 48, 1), 64, 48)
        .unwrap();
    let (mut host, mut hooks, viewer) = run_viewer_hooked(None).await;
    let video = |seq, data| Msg::Video {
        seq,
        flags: 0,
        ts_ms: 0,
        data,
    };
    // Announced 1280×720 in `BindOk`: this 64×48 picture was not.
    write_msg(&mut host, &video(0, idr.data)).await.unwrap();
    let announced = Msg::Quality {
        width: 64,
        height: 48,
        quality: APPLIED,
    };
    write_msg(&mut host, &announced).await.unwrap();
    write_msg(&mut host, &video(1, next.data)).await.unwrap();
    let close = Msg::Close {
        reason: reason::ENDED_BY_HOST,
    };
    write_msg(&mut host, &close).await.unwrap();
    let (end, stats) = viewer.await.unwrap();
    assert!(matches!(end, Ok(ViewerEnd::Host(_))), "{end:?}");
    assert_eq!((stats.decoded, stats.unannounced), (2, 1));
    assert_eq!(
        hooks_so_far(&mut hooks),
        [
            Hook::Quality(1280, 720, APPLIED),
            Hook::Picture(64, 48),
            Hook::Quality(64, 48, APPLIED),
            Hook::Picture(64, 48),
        ]
    );
}

/// The quality design §4.7 and §8 (viewer): a host of another version is
/// told apart from a refusal. It refuses this version's 50-byte `Bind` as
/// malformed (`BindRefused{PROTOCOL}`), or answers with the 10-byte `BindOk`
/// of the version before: both are `ViewerError::Version`, which says what
/// to do. Any other refusal stays a refusal.
#[tokio::test(start_paused = true)]
async fn a_host_of_another_version_is_said_to_be_one() {
    let mut old_bind_ok = vec![0, 0, 0, 11, 0x02];
    old_bind_ok.extend_from_slice(&[0, 0, 5, 0, 0, 0, 2, 0xd0, codec::H264, 0]);
    let answers: [(Vec<u8>, &str); 3] = [
        (
            Msg::BindRefused {
                reason: reason::PROTOCOL,
            }
            .encode(),
            "Version",
        ),
        (old_bind_ok, "Version"),
        (
            Msg::BindRefused {
                reason: reason::BAD_BIND,
            }
            .encode(),
            "Refused",
        ),
    ];
    for (answer, want) in answers {
        let binding = Binding::new(&SessionToken::new([8; 32]), &[8; 32]);
        let (client, mut host) = duplex(1 << 16);
        let bound = tokio::spawn(async move { MediaViewer::bind(client, &binding, WAIT).await });
        assert!(matches!(
            read_msg(&mut host).await.unwrap(),
            Some(Msg::Bind { .. })
        ));
        host.write_all(&answer).await.unwrap();
        let err = bound.await.unwrap().unwrap_err();
        match want {
            "Version" => {
                assert!(matches!(err, ViewerError::Version), "{err:?}");
                assert_eq!(
                    err.to_string(),
                    "the other computer runs a different version of Tornect; use the same \
                     version on both"
                );
            }
            _ => assert!(
                matches!(err, ViewerError::Refused(r) if r == reason::BAD_BIND),
                "{err:?}"
            ),
        }
    }
}

/// The quality design §6.6 and §8 (viewer), end to end with the real host:
/// a viewer bound with Best performance is told so in `BindOk` (a 1600×900
/// desktop fitted to 1280×720); a pick of Balanced from its watch channel,
/// in a view-only session, gets a `Quality` with the new exact size before
/// the first picture at that size, so no picture is unannounced; the host's
/// means reach the sink; decoding is timed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewers_pick_changes_what_the_real_host_sends() {
    let backend = TestBackend {
        card: Some((1600, 900)),
        ..TestBackend::default()
    };
    let rig = rig_with(
        backend,
        MediaLimits {
            quality_interval: Duration::from_millis(300),
            stats_every: Duration::from_millis(200),
            ..MediaLimits::default()
        },
    );
    let (_, binding) = start(&rig.host, 80, SessionMode::ViewOnly);
    let binding = binding.with_quality(QualityPreset::BestPerformance);
    let (client, served) = connect(&rig.host);
    let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
    assert_eq!(
        *viewer.bound(),
        BoundStream {
            width: 1280,
            height: 720,
            mode: SessionMode::ViewOnly,
            quality: BEST_PERFORMANCE,
        }
    );
    let (picker, picks) = tokio::sync::watch::channel(QualityPreset::BestPerformance);
    let (tx, mut hooks) = tokio::sync::mpsc::unbounded_channel();
    let (stop, stopped) = oneshot::channel::<()>();
    let run = tokio::spawn(async move {
        let (mut sink, mut stats) = (Hooks(tx), ViewerStats::default());
        let end = viewer
            .with_quality(picks)
            .run(&mut sink, &mut stats, async {
                let _ = stopped.await;
            })
            .await;
        (end, stats)
    });
    let mut seen = Vec::new();
    let since = tokio::time::Instant::now();
    while seen
        .iter()
        .filter(|h| **h == Hook::Picture(1280, 720))
        .count()
        < 3
    {
        seen.push(next_hook(&mut hooks, since).await);
    }
    picker.send(QualityPreset::Balanced).unwrap();
    while seen
        .iter()
        .filter(|h| **h == Hook::Picture(1600, 900))
        .count()
        < 3
    {
        seen.push(next_hook(&mut hooks, since).await);
    }
    stop.send(()).unwrap();
    let (end, stats) = run.await.unwrap();
    assert_eq!(end.unwrap(), ViewerEnd::Stopped);

    assert_eq!(seen[0], Hook::Quality(1280, 720, BEST_PERFORMANCE));
    let said: Vec<usize> = (0..seen.len())
        .filter(|&i| matches!(seen[i], Hook::Quality(..)))
        .collect();
    assert_eq!(said.len(), 2, "{seen:?}");
    assert_eq!(seen[said[1]], Hook::Quality(1600, 900, APPLIED));
    let first_large = seen.iter().position(|h| *h == Hook::Picture(1600, 900));
    assert!(first_large > Some(said[1]), "{seen:?}");
    assert!(
        seen.iter()
            .any(|h| matches!(h, Hook::Stats(s) if s.frames > 0))
    );
    assert_eq!(stats.unannounced, 0, "{seen:?}");
    assert_eq!(stats.quality, Some(APPLIED));
    assert!(stats.host.is_some());
    assert!(stats.decode_us > 0 && stats.convert_us > 0, "{stats:?}");

    let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!((report.quality_requests, report.quality_changes), (1, 1));
}

/// The quality design §8 host test 15, from the real viewer: across a source
/// resize (640×360, then 800×600) every picture decodes at the size last
/// announced, so the viewer counts no unannounced picture, and its sink is
/// told the new size before the first picture at it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_counts_no_unannounced_picture_across_a_source_resize() {
    let backend = TestBackend {
        desktop: Mutex::new(Some(Box::new(Resizing {
            small: TestCard::new(640, 360, 60),
            large: TestCard::new(800, 600, 60),
            after: 5,
        }))),
        ..TestBackend::default()
    };
    let rig = rig_with(backend, MediaLimits::default());
    let (_, binding) = start(&rig.host, 81, SessionMode::Control);
    let (client, served) = connect(&rig.host);
    let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
    let (tx, mut hooks) = tokio::sync::mpsc::unbounded_channel();
    let (stop, stopped) = oneshot::channel::<()>();
    let run = tokio::spawn(async move {
        let (mut sink, mut stats) = (Hooks(tx), ViewerStats::default());
        let end = viewer
            .run(&mut sink, &mut stats, async {
                let _ = stopped.await;
            })
            .await;
        (end, stats)
    });
    let mut seen = Vec::new();
    let since = tokio::time::Instant::now();
    while seen
        .iter()
        .filter(|h| **h == Hook::Picture(800, 600))
        .count()
        < 3
    {
        seen.push(next_hook(&mut hooks, since).await);
    }
    stop.send(()).unwrap();
    let (end, stats) = run.await.unwrap();
    assert_eq!(end.unwrap(), ViewerEnd::Stopped);
    let said: Vec<Hook> = seen
        .iter()
        .copied()
        .filter(|h| matches!(h, Hook::Quality(..)))
        .collect();
    assert_eq!(
        said,
        [
            Hook::Quality(640, 360, APPLIED),
            Hook::Quality(800, 600, APPLIED)
        ]
    );
    let told = seen
        .iter()
        .position(|h| *h == Hook::Quality(800, 600, APPLIED));
    let first_large = seen.iter().position(|h| *h == Hook::Picture(800, 600));
    assert!(told < first_large, "{seen:?}");
    assert_eq!(stats.unannounced, 0, "{seen:?}");
    drop(served);
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
/// blocking pool's delay before the open's first line. (At `877ac00` it made
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
        transport: tornect_signal::consent::TransportPolicy::Any,
        viewer_dir1: false,
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

/// A pick sent every 5 ms for `flood` to a host serving a still screen, each
/// `pick(applied)`, where `applied` is the preset the viewer last heard is in
/// force (Balanced from `BindOk`, then each `Quality`), with what the host
/// wrote meanwhile read on another task, stamped from just before the first
/// pick; then a `Close` after one more `wait`. Returns the stamped frames,
/// the picks sent and the host's report.
async fn flood_of_picks(
    rig: &Rig,
    seed: u8,
    pick: fn(u8) -> u8,
    flood: Duration,
    wait: Duration,
) -> (Vec<(Duration, Msg)>, u64, MediaReport) {
    let (_, binding) = start(&rig.host, seed, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    go_still(rig, &mut client, &mut Decoded::new()).await;
    let (mut rd, mut wr) = tokio::io::split(client);
    let applied = Arc::new(std::sync::atomic::AtomicU8::new(quality::BALANCED));
    let heard = Arc::clone(&applied);
    let started = std::time::Instant::now();
    let reader = tokio::spawn(async move {
        let mut said = Vec::new();
        while let Some(msg) = read_msg(&mut rd).await.unwrap() {
            if let Msg::Quality { quality, .. } = msg {
                heard.store(quality.preset, Ordering::SeqCst);
            }
            said.push((started.elapsed(), msg));
        }
        said
    });
    let mut sent = 0u64;
    while started.elapsed() < flood {
        let quality = pick(applied.load(Ordering::SeqCst));
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
        |_| quality::BALANCED,
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
/// pick. Each rebuild is said in a `Quality` before its picture. The flood
/// always picks the preset not in force, as the viewer last heard: at every
/// turn of the gate it asks for a rebuild, the most a viewer can, so the
/// keyframe limiter alone bounds them (picks that alternate one by one meet
/// the gate's turns, taken as a frame is read, in step with the 5 ms beat,
/// and then mostly with the preset in force).
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
        |applied| {
            if applied == quality::BEST_PERFORMANCE {
                quality::BEST_QUALITY
            } else {
                quality::BEST_PERFORMANCE
            }
        },
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

/// A link of `chunk` bytes per `tick` from the host to a viewer on
/// [`connect_narrow`]: what the host writes reaches the returned pipe at that
/// rate, as it reaches a viewer over a link slower than the stream.
fn slow_link(
    from_host: ReadHalf<NarrowPipe>,
    chunk: usize,
    tick: Duration,
) -> ReadHalf<SimplexStream> {
    let (viewer, mut link) = simplex(1 << 20);
    let mut from_host = from_host;
    tokio::spawn(async move {
        let mut buf = vec![0u8; chunk];
        loop {
            let mut got = 0;
            while got < chunk {
                let n = match from_host.read(&mut buf[..chunk - got]).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                if link.write_all(&buf[..n]).await.is_err() {
                    return;
                }
                got += n;
            }
            tokio::time::sleep(tick).await;
        }
    });
    viewer
}

/// The host's next frame over a [`slow_link`], within `wait`; a `Video` is
/// acknowledged as soon as it has been read, as a viewer does.
async fn next_over_link(
    link: &mut ReadHalf<SimplexStream>,
    to_host: &mut WriteHalf<NarrowPipe>,
    wait: Duration,
) -> Option<Msg> {
    let msg = tokio::time::timeout(wait, read_msg(link))
        .await
        .ok()?
        .unwrap()
        .expect("the stream is open");
    if let Msg::Video { seq, .. } = msg {
        write_msg(to_host, &Msg::VideoAck { seq }).await.unwrap();
    }
    Some(msg)
}

/// The quality design §3.2 on a stream the link limits: every picture's write
/// outlasts Balanced's frame interval, so the viewer's acks, taken while a
/// write waits, have the next picture encoded before the write ends, and a
/// picture is ready whenever the host could act on a pick. The pick is acted
/// on all the same: its `Quality` comes within a few picture writes (the
/// gate's first turn is at once), not never.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pick_is_acted_on_while_the_link_limits_the_stream() {
    let rig = rig(MediaLimits::default());
    let (_, binding) = start(&rig.host, 76, SessionMode::Control);
    let (mut client, served) = connect_narrow(&rig.host);
    bind_raw(&mut client, &binding).await;
    let (from_host, mut to_host) = tokio::io::split(client);
    let mut link = slow_link(from_host, 4, Duration::from_millis(20));

    // Past the first IDR, pictures arrive at the link's pace (a P-frame of
    // the card is about 30 bytes framed: 8 ticks), further apart than
    // Balanced's 66 ms frame interval plus a tick: each write outlasts both.
    let mut arrived = Vec::new();
    let since = tokio::time::Instant::now();
    while arrived.len() < 6 {
        in_time(since, "six pictures");
        if let Some(Msg::Video { .. }) = next_over_link(&mut link, &mut to_host, WAIT).await {
            arrived.push(std::time::Instant::now());
        }
    }
    let spacing = (arrived[5] - arrived[1]) / 4;
    assert!(
        spacing > Duration::from_millis(100),
        "the link limits the stream: pictures {spacing:?} apart"
    );

    let asked = std::time::Instant::now();
    write_msg(
        &mut to_host,
        &Msg::SetQuality {
            quality: quality::BEST_PERFORMANCE,
        },
    )
    .await
    .unwrap();
    // The gate's first turn is at once: then the write under way, the
    // picture encoded meanwhile, perhaps a `Stats`, and the `Quality`
    // itself, each about a picture's spacing at most.
    let bound = (spacing * 6).max(MediaLimits::default().quality_interval);
    loop {
        let left = bound.saturating_sub(asked.elapsed());
        match next_over_link(&mut link, &mut to_host, left).await {
            None => panic!("the pick was not acted on within {bound:?}"),
            Some(Msg::Quality {
                quality: BEST_PERFORMANCE,
                ..
            }) => break,
            // Pictures already on their way, at Balanced.
            Some(Msg::Video { .. } | Msg::Stats(_)) => {}
            Some(other) => panic!("{other:?}"),
        }
    }

    write_msg(
        &mut to_host,
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
    assert_eq!((report.quality_requests, report.quality_changes), (1, 1));
}

/// The quality design §6.6, a pick of the preset on its way to the pipeline:
/// with the ack window full the capture thread has no credit and cannot take
/// a change, so a pick of Best performance is handed over and waits there. A
/// second pick of it a gate's interval later takes the gate's turn and is
/// answered by nothing: no `Quality` naming Balanced, which still applies,
/// nor Best performance, which does not yet. Once the viewer acknowledges
/// again, the change applies: one `Quality` naming it, before one repeat of
/// the last picture, an IDR.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pick_of_the_preset_on_its_way_is_answered_by_its_change() {
    let interval = Duration::from_millis(300);
    let rig = rig(MediaLimits {
        quality_interval: interval,
        keyframe_interval: interval,
        ..MediaLimits::default()
    });
    let (_, binding) = start(&rig.host, 77, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    // Read, acknowledging nothing, until the window is full.
    let mut unacked = Vec::new();
    while let Ok(msg) =
        tokio::time::timeout(Duration::from_millis(500), read_msg(&mut client)).await
    {
        match msg.unwrap().expect("the stream is open") {
            Msg::Video { seq, .. } => unacked.push(seq),
            Msg::Stats(_) => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(unacked.len(), 23, "Balanced's window");

    for nonce in [1, 2] {
        write_msg(
            &mut client,
            &Msg::SetQuality {
                quality: quality::BEST_PERFORMANCE,
            },
        )
        .await
        .unwrap();
        // The host handles the pick, and its turn when it has come, before
        // the ping: nothing is said before the `Pong`.
        write_msg(&mut client, &Msg::Ping { nonce }).await.unwrap();
        match tokio::time::timeout(WAIT, read_msg(&mut client))
            .await
            .unwrap()
            .unwrap()
        {
            Some(Msg::Pong { nonce: n }) if n == nonce => {}
            other => panic!("while the window is full, pick {nonce}: {other:?}"),
        }
        if nonce == 1 {
            // The second pick comes after the gate's next turn.
            tokio::time::sleep(interval + Duration::from_millis(50)).await;
        }
    }
    assert!(
        tokio::time::timeout(interval, read_msg(&mut client))
            .await
            .is_err(),
        "nothing while the window stays full"
    );

    for seq in unacked {
        write_msg(&mut client, &Msg::VideoAck { seq })
            .await
            .unwrap();
    }
    let resumed = tokio::time::Instant::now();
    let mut said = Vec::new();
    let mut pictures = Vec::new();
    while resumed.elapsed() < Duration::from_secs(1) {
        match next_acking(&mut client).await {
            msg @ Msg::Quality { .. } => said.push((pictures.len(), msg)),
            Msg::Video { flags, .. } => pictures.push(flags & video_flags::KEYFRAME != 0),
            Msg::Stats(_) => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(
        said,
        [(
            0,
            Msg::Quality {
                width: 256,
                height: 96,
                quality: BEST_PERFORMANCE,
            }
        )],
        "one Quality, before the first picture after the window drained"
    );
    assert!(pictures.len() > 5, "{pictures:?}");
    assert!(pictures[0], "the repeat is an IDR");
    let report = close_and_report(&mut client, served).await;
    assert_eq!(
        (
            report.quality_requests,
            report.quality_changes,
            report.repeats,
            report.keyframes_forced
        ),
        (2, 1, 1, 0)
    );
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

/// The monitors design's H6: a `Monitors` from the viewer, the host's own
/// message, and a malformed `SelectMonitor` (request 0, a monitor past 16, a
/// body a byte short) end the stream as a protocol error, in control and
/// view-only sessions alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewers_monitors_or_a_malformed_select_monitor_is_a_protocol_error() {
    let rig = rig(MediaLimits::default());
    let monitors = Msg::Monitors {
        request: 0,
        status: tornect_proto::monitor_status::OK,
        shown: 1,
        all: false,
        remapped: false,
        list: 0,
        seq: 0,
        monitors: vec![tornect_proto::MonitorEntry::saturating(
            true, 0, 0, 1280, 720,
        )],
    }
    .encode();
    // Type 0x53, then request, list and monitor.
    let frames: [&[u8]; 4] = [
        &monitors,
        &[0, 0, 0, 6, 0x53, 0, 0, 0, 0, 1],
        &[0, 0, 0, 6, 0x53, 0, 7, 0, 0, 17],
        &[0, 0, 0, 5, 0x53, 0, 7, 0, 0],
    ];
    for (seed, (frame, mode)) in (49..).zip(frames.into_iter().zip([
        SessionMode::Control,
        SessionMode::ViewOnly,
        SessionMode::Control,
        SessionMode::ViewOnly,
    ])) {
        let (_, binding) = start(&rig.host, seed, mode);
        let (mut client, served) = connect(&rig.host);
        bind_raw(&mut client, &binding).await;
        client.write_all(frame).await.unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(10), served)
            .await
            .unwrap_or_else(|_| panic!("{frame:02x?} did not end the stream"));
        let MediaOutcome::Served { end, .. } = outcome.unwrap() else {
            panic!("not served");
        };
        assert_eq!(end, MediaEnd::Protocol, "{frame:02x?}");
        assert_eq!(until_close(&mut client).await, Some(reason::PROTOCOL));
    }
}

/// A desktop whose monitors the test changes under the session, as a
/// hotplug or a change of the primary does: about every 20 ms a test card
/// of what `layout` shows at that moment, described by it.
struct Shifting {
    layout: Arc<Mutex<Layout>>,
    last: Option<Layout>,
    index: u32,
}

impl VideoSource for Shifting {
    fn name(&self) -> &'static str {
        "desk"
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        std::thread::sleep(timeout.min(Duration::from_millis(20)));
        let layout = self.layout.lock().unwrap().clone();
        let View::Rect { shown, .. } = layout.view else {
            unreachable!("the test desktop shows rectangles")
        };
        self.last = Some(layout);
        self.index += 1;
        Ok(Some(Frame {
            width: shown.width,
            height: shown.height,
            bgrx: TestCard::render(shown.width, shown.height, self.index),
            captured_at: std::time::Instant::now(),
            grab: Duration::ZERO,
        }))
    }

    fn layout(&self) -> Option<Layout> {
        self.last.clone()
    }
}

/// The test screens' desktop: 1280×720 (primary) and 1024×768 side by side
/// on a 2304×768 desktop, showing `shown`.
fn two_screens(shown: Selection) -> Layout {
    let space = Rect::new(0, 0, 2304, 768);
    let monitors = vec![
        Monitor {
            id: 1,
            primary: true,
            rect: Rect::new(0, 0, 1280, 720),
        },
        Monitor {
            id: 2,
            primary: false,
            rect: Rect::new(1280, 0, 1024, 768),
        },
    ];
    let rect = match shown {
        Selection::All => space,
        Selection::Monitor(id) => monitors[usize::from(id) - 1].rect,
    };
    Layout {
        monitors,
        all: true,
        shown,
        view: View::Rect { shown: rect, space },
    }
}

/// [`two_screens`] once its first monitor is unplugged: the 1024×768 one
/// alone, made primary, at the corner of a desktop of its size.
fn one_screen() -> Layout {
    let rect = Rect::new(0, 0, 1024, 768);
    Layout {
        monitors: vec![Monitor {
            id: 1,
            primary: true,
            rect,
        }],
        all: false,
        shown: Selection::Monitor(1),
        view: View::Rect {
            shown: rect,
            space: rect,
        },
    }
}

/// A rig whose source is a [`Shifting`] desktop that starts at `layout`,
/// and the handle that changes it.
fn shifting_rig(layout: Layout) -> (Rig, Arc<Mutex<Layout>>) {
    let shared = Arc::new(Mutex::new(layout));
    let source = Shifting {
        layout: Arc::clone(&shared),
        last: None,
        index: 0,
    };
    let rig = rig_with(
        TestBackend {
            desktop: Mutex::new(Some(Box::new(source))),
            ..TestBackend::default()
        },
        MediaLimits::default(),
    );
    (rig, shared)
}

/// A `PointerMove` to `(x, y)` over the picture, as the injector behind the
/// host's viewport receives it under `view`.
fn moved_over(x: u16, y: u16, view: View) -> InputEvent {
    let View::Rect { shown, space } = view else {
        unreachable!("a rectangle")
    };
    let (x, y) = remap(x, y, shown, space);
    InputEvent::PointerMove { x, y }
}

/// Send each of `events` as an `Input` frame.
async fn send_input(client: &mut DuplexStream, events: &[InputEvent]) {
    for event in events {
        write_msg(client, &Msg::Input(event.encode()))
            .await
            .unwrap();
    }
}

/// Read, acknowledging every `Video`, up to the next `Monitors`.
async fn next_monitors(client: &mut DuplexStream) -> Msg {
    let since = tokio::time::Instant::now();
    loop {
        in_time(since, "a Monitors");
        let msg = next_acking(client).await;
        if matches!(msg, Msg::Monitors { .. }) {
            return msg;
        }
    }
}

const LEFT_DOWN: InputEvent = InputEvent::PointerButton {
    button: Button::Left,
    pressed: true,
};
const LEFT_UP: InputEvent = InputEvent::PointerButton {
    button: Button::Left,
    pressed: false,
};
const A_DOWN: InputEvent = InputEvent::Key {
    usb: KEY_A,
    pressed: true,
};
const A_UP: InputEvent = InputEvent::Key {
    usb: KEY_A,
    pressed: false,
};

/// The monitors design's H1 (and the injector test step 10 owed): a source
/// with monitors to choose from has them said in one `Monitors` (request 0,
/// REMAPPED clear, list 0, seq 0) after `BindOk` and right before `Video` 0,
/// and the injector took that picture's view before any input was handled,
/// so the viewer's pointer lands on the screen shown: its bottom-right
/// corner on monitor 1's last pixel, not on the desktop's. The indicator
/// hears where the picture lies. A source with nothing to choose says
/// nothing, and its injector is never retargeted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_layout_is_said_before_the_first_picture_and_the_injector_follows_it() {
    let (rig, _) = shifting_rig(two_screens(Selection::Monitor(1)));
    let (_, binding) = start(&rig.host, 61, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    assert_eq!(
        next_acking(&mut client).await,
        Msg::Monitors {
            request: 0,
            status: tornect_proto::monitor_status::OK,
            shown: 1,
            all: true,
            remapped: false,
            list: 0,
            seq: 0,
            monitors: vec![
                tornect_proto::MonitorEntry::saturating(true, 0, 0, 1280, 720),
                tornect_proto::MonitorEntry::saturating(false, 1280, 0, 1024, 768),
            ],
        }
    );
    let Msg::Video { seq, flags, .. } = next_acking(&mut client).await else {
        panic!("the Monitors is right before the first picture");
    };
    assert_eq!(
        (seq, flags & video_flags::KEYFRAME),
        (0, video_flags::KEYFRAME)
    );
    let view = two_screens(Selection::Monitor(1)).view;
    assert_eq!(
        rig.backend.recorder.views(),
        [(0, view)],
        "the first view, before any input"
    );

    send_input(
        &mut client,
        &[InputEvent::PointerMove { x: 65535, y: 65535 }],
    )
    .await;
    sync(&mut client, 1).await;
    let corner = moved_over(65535, 65535, view);
    assert_eq!(rig.backend.recorder.events(), [corner]);
    let InputEvent::PointerMove { x, y } = corner else {
        unreachable!()
    };
    assert_eq!(
        (denormalize(x, 2304), denormalize(y, 768)),
        (1279, 719),
        "monitor 1's last pixel"
    );
    drop(client);
    let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!(report.input_held_back, 0);
    assert_eq!(
        rig.seen.lines(),
        [
            "started desk 1280x720 Control input=true",
            "changed screen=1 of=2 all=false shown=1280x720+0+0 input=true",
            "stopped ViewerLeft",
        ]
    );

    // The card has nothing to choose: its first picture comes right after
    // `BindOk`, and the injector keeps passing positions through.
    let rig = rig_with(TestBackend::default(), MediaLimits::default());
    let (_, binding) = start(&rig.host, 62, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    assert!(
        matches!(next_acking(&mut client).await, Msg::Video { seq: 0, .. }),
        "no Monitors"
    );
    let middle = InputEvent::PointerMove { x: 30000, y: 20000 };
    send_input(&mut client, &[middle]).await;
    sync(&mut client, 2).await;
    assert_eq!(rig.backend.recorder.events(), [middle]);
    assert!(rig.backend.recorder.views().is_empty());
    drop(client);
    served.await.unwrap();
}

/// The monitors design's H3, H4 and H5: when the desktop changes under the
/// session (monitor 1 unplugged, monitor 2 shown alone), the change is said
/// as news (request 0, REMAPPED, a new list) right before the first picture
/// that shows it, a keyframe; the injector follows it first, letting go of
/// the button held (no drag across screens) and keeping the key. Moves,
/// wheel turns and presses made before the viewer acknowledged that picture
/// are held back, and after it wheel turns and presses until a move placed
/// the pointer; keys and releases always go. The indicator hears the new
/// screen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_of_screen_is_said_before_its_picture_and_earlier_input_waits_for_its_ack() {
    let (rig, layout) = shifting_rig(two_screens(Selection::Monitor(1)));
    let (_, binding) = start(&rig.host, 63, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    assert!(matches!(
        next_acking(&mut client).await,
        Msg::Monitors { list: 0, .. }
    ));
    let first = two_screens(Selection::Monitor(1)).view;
    let start_drag = moved_over(1000, 1000, first);
    send_input(
        &mut client,
        &[
            InputEvent::PointerMove { x: 1000, y: 1000 },
            LEFT_DOWN,
            A_DOWN,
        ],
    )
    .await;
    sync(&mut client, 1).await;
    assert_eq!(
        rig.backend.recorder.events(),
        [start_drag, LEFT_DOWN, A_DOWN]
    );

    *layout.lock().unwrap() = one_screen();
    let news = next_monitors(&mut client).await;
    let Msg::Monitors { seq: at, .. } = news else {
        unreachable!()
    };
    assert_eq!(
        news,
        Msg::Monitors {
            request: 0,
            status: tornect_proto::monitor_status::OK,
            shown: 1,
            all: false,
            remapped: true,
            list: 1,
            seq: at,
            monitors: vec![tornect_proto::MonitorEntry::saturating(
                true, 0, 0, 1024, 768
            )],
        }
    );
    // The picture it describes comes next, unacknowledged for now.
    match tokio::time::timeout(WAIT, read_msg(&mut client))
        .await
        .unwrap()
        .unwrap()
    {
        Some(Msg::Video { seq, flags, .. }) => {
            assert_eq!(seq, at);
            assert_ne!(flags & video_flags::KEYFRAME, 0, "a keyframe");
        }
        other => panic!("expected the Video the Monitors describes, got {other:?}"),
    }
    let second = one_screen().view;
    assert_eq!(
        rig.backend.recorder.views(),
        [(0, first), (4, second)],
        "followed once, before the picture, after letting go of the button"
    );
    assert_eq!(
        rig.backend.recorder.events(),
        [start_drag, LEFT_DOWN, A_DOWN, LEFT_UP],
        "the drag ends at the switch; the key stays down"
    );

    // Made against the pictures before `at`: only the key goes. An ack of
    // an earlier picture leaves the barrier up.
    let corner = InputEvent::PointerMove { x: 65535, y: 65535 };
    let wheel = InputEvent::Wheel { dx: 0, dy: 120 };
    write_msg(
        &mut client,
        &Msg::VideoAck {
            seq: at.wrapping_sub(1),
        },
    )
    .await
    .unwrap();
    send_input(&mut client, &[corner, wheel, LEFT_DOWN, LEFT_UP, A_UP]).await;
    sync(&mut client, 2).await;
    assert_eq!(
        rig.backend.recorder.events(),
        [start_drag, LEFT_DOWN, A_DOWN, LEFT_UP, A_UP]
    );

    // The viewer has the picture: a press or a wheel turn still waits for a
    // move to place the pointer on the new screen.
    write_msg(&mut client, &Msg::VideoAck { seq: at })
        .await
        .unwrap();
    send_input(
        &mut client,
        &[LEFT_DOWN, wheel, corner, LEFT_DOWN, wheel, LEFT_UP],
    )
    .await;
    sync(&mut client, 3).await;
    let placed = moved_over(65535, 65535, second);
    assert_eq!(
        placed,
        InputEvent::PointerMove { x: 65535, y: 65535 },
        "the whole of the new desktop is shown"
    );
    assert_eq!(
        rig.backend.recorder.events(),
        [
            start_drag, LEFT_DOWN, A_DOWN, LEFT_UP, A_UP, placed, LEFT_DOWN, wheel, LEFT_UP
        ]
    );
    write_msg(
        &mut client,
        &Msg::Close {
            reason: reason::ENDED_BY_VIEWER,
        },
    )
    .await
    .unwrap();
    let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!(report.input_held_back, 5, "three before the ack, two after");
    assert!(report.input_dropped >= 5);
    assert_eq!(
        rig.seen.lines(),
        [
            "started desk 1280x720 Control input=true",
            "changed screen=1 of=2 all=false shown=1280x720+0+0 input=true",
            "changed screen=1 of=1 all=false shown=1024x768+0+0 input=true",
            "stopped ViewerLeft",
        ]
    );
}

/// A change of the monitor list that moves nothing (the primary is now
/// monitor 2, and monitor 1 is still shown) is said with a new list and
/// REMAPPED clear: the injector keeps its view, a drag goes on, nothing is
/// held back, and the indicator stays where it is. (The drag starts with a
/// move: the session opens on one of two screens, so a press waits for the
/// pointer to be placed.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_list_that_moves_nothing_holds_nothing_back() {
    let (rig, layout) = shifting_rig(two_screens(Selection::Monitor(1)));
    let (_, binding) = start(&rig.host, 64, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    assert!(matches!(
        next_monitors(&mut client).await,
        Msg::Monitors { list: 0, .. }
    ));
    let start_at = InputEvent::PointerMove { x: 100, y: 100 };
    send_input(&mut client, &[start_at, LEFT_DOWN]).await;
    sync(&mut client, 1).await;

    let mut new_primary = two_screens(Selection::Monitor(1));
    new_primary.monitors[0].primary = false;
    new_primary.monitors[1].primary = true;
    *layout.lock().unwrap() = new_primary;
    let news = next_monitors(&mut client).await;
    assert!(
        matches!(
            &news,
            Msg::Monitors { list: 1, remapped: false, shown: 1, monitors, .. }
                if !monitors[0].primary && monitors[1].primary
        ),
        "{news:?}"
    );
    let corner = InputEvent::PointerMove { x: 65535, y: 65535 };
    send_input(&mut client, &[corner, LEFT_UP]).await;
    sync(&mut client, 2).await;
    let view = two_screens(Selection::Monitor(1)).view;
    assert_eq!(rig.backend.recorder.views(), [(0, view)]);
    assert_eq!(
        rig.backend.recorder.events(),
        [
            moved_over(100, 100, view),
            LEFT_DOWN,
            moved_over(65535, 65535, view),
            LEFT_UP
        ]
    );
    drop(client);
    let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!(report.input_held_back, 0);
    assert_eq!(
        rig.seen.lines(),
        [
            "started desk 1280x720 Control input=true",
            "changed screen=1 of=2 all=false shown=1280x720+0+0 input=true",
            "stopped ViewerLeft",
        ]
    );
}

/// The safety net of the monitors design §4 (and the second host test step
/// 10 owed): an injector that refuses the view ends the session's input
/// rather than mis-map a click. Mid-session: everything held is let go of
/// (the button by the retarget, the key when the injector is dropped), the
/// notice gains `INPUT_LOST` (not `NO_INPUT`), the indicator hears
/// `input: false`, and later input reaches nothing. At the first picture:
/// the same, before any input. (The press follows a move: the session opens
/// on one of two screens, so a press waits for the pointer to be placed.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_injector_that_cannot_follow_the_picture_ends_the_sessions_input() {
    use tornect_signal::messages::notice;
    let (rig, layout) = shifting_rig(two_screens(Selection::Monitor(1)));
    let (id, binding) = start(&rig.host, 65, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    let placed = InputEvent::PointerMove { x: 100, y: 100 };
    send_input(&mut client, &[A_DOWN, placed, LEFT_DOWN]).await;
    sync(&mut client, 1).await;
    assert_eq!(rig.host.viewer_notice(&id, Some(0)), Some(0));

    rig.backend.recorder.refuses.store(true, Ordering::SeqCst);
    *layout.lock().unwrap() = two_screens(Selection::Monitor(2));
    assert!(matches!(
        next_monitors(&mut client).await,
        Msg::Monitors {
            shown: 2,
            remapped: true,
            list: 0,
            ..
        }
    ));
    let placed = moved_over(100, 100, two_screens(Selection::Monitor(1)).view);
    assert_eq!(
        rig.backend.recorder.events(),
        [A_DOWN, placed, LEFT_DOWN, LEFT_UP, A_UP],
        "everything held let go of"
    );
    assert_eq!(
        rig.host.viewer_notice(&id, Some(0)),
        Some(notice::INPUT_LOST)
    );
    assert_eq!(
        rig.host.viewer_notice(&id, Some(notice::WINDOWS)),
        Some(notice::WINDOWS | notice::INPUT_LOST)
    );
    assert_eq!(rig.host.viewer_notice(&id, None), None);
    send_input(
        &mut client,
        &[A_DOWN, InputEvent::PointerMove { x: 9, y: 9 }],
    )
    .await;
    sync(&mut client, 2).await;
    assert_eq!(rig.backend.recorder.events().len(), 5, "nothing more");
    drop(client);
    let MediaOutcome::Served { report, .. } = served.await.unwrap() else {
        panic!("not served");
    };
    assert_eq!(report.input_dropped, 2);
    assert_eq!(
        rig.seen.lines(),
        [
            "started desk 1280x720 Control input=true",
            "changed screen=1 of=2 all=false shown=1280x720+0+0 input=true",
            "changed screen=2 of=2 all=false shown=1024x768+1280+0 input=false",
            "stopped ViewerLeft",
        ]
    );

    // Refused at the first view.
    let (rig, _) = shifting_rig(two_screens(Selection::Monitor(1)));
    rig.backend.recorder.refuses.store(true, Ordering::SeqCst);
    let (id, binding) = start(&rig.host, 66, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    assert!(matches!(
        next_acking(&mut client).await,
        Msg::Monitors { seq: 0, .. }
    ));
    send_input(&mut client, &[A_DOWN]).await;
    sync(&mut client, 3).await;
    assert!(rig.backend.recorder.events().is_empty());
    assert_eq!(
        rig.host.viewer_notice(&id, Some(0)),
        Some(notice::INPUT_LOST)
    );
    drop(client);
    served.await.unwrap();
    assert_eq!(
        rig.seen.lines()[..2],
        [
            "started desk 1280x720 Control input=true",
            "changed screen=1 of=2 all=false shown=1280x720+0+0 input=false",
        ]
    );
}

/// A viewer reads past the `Monitors` of a host whose source has monitors
/// to choose from (the test screens, view-only: a view-only session hears
/// its monitors too), and decodes every picture in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_reads_past_the_monitors_of_a_host_with_screens() {
    let rig = rig_with(
        TestBackend {
            desktop: Mutex::new(Some(Box::new(TestScreens::new(&TEST_SCREENS, 30)))),
            ..TestBackend::default()
        },
        MediaLimits::default(),
    );
    let (_, binding) = start(&rig.host, 67, SessionMode::ViewOnly);
    let (client, served) = connect(&rig.host);
    let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
    let (mut pictures, done) = Pictures::wanting(5);
    let mut stats = ViewerStats::default();
    let end = viewer
        .run(&mut pictures, &mut stats, async {
            let _ = done.await;
        })
        .await
        .unwrap();
    assert_eq!(end, ViewerEnd::Stopped);
    assert!(pictures.indices.len() >= 5, "{:?}", pictures.indices);
    for pair in pictures.indices.windows(2) {
        assert_eq!(pair[1], pair[0] + 1, "{:?}", pictures.indices);
    }
    assert!(pictures.sizes.iter().all(|&size| size == (1280, 720)));
    served.await.unwrap();
    assert_eq!(
        rig.seen.lines(),
        [
            "started synthetic screens 1280x720 ViewOnly input=false",
            "changed screen=1 of=2 all=false shown=1280x720+0+0 input=false",
            "stopped ViewerLeft",
        ]
    );
}

/// From the viewer's side (the monitors design's V2 and V4): a host's
/// `Monitors` is news the stream reads on past, also for a viewer with no
/// request to make, and a `SelectMonitor`, the viewer's own frame, ends the
/// stream.
#[tokio::test(start_paused = true)]
async fn a_viewer_reads_past_monitors_and_refuses_a_hosts_select_monitor() {
    let (mut host, viewer) = run_viewer_with(None).await;
    for msg in [
        Msg::Monitors {
            request: 0,
            status: tornect_proto::monitor_status::OK,
            shown: 2,
            all: true,
            remapped: true,
            list: 3,
            seq: 0,
            monitors: vec![
                tornect_proto::MonitorEntry::saturating(true, 0, 0, 1280, 720),
                tornect_proto::MonitorEntry::saturating(false, 1280, 0, 0, 0),
            ],
        },
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
    let select = Msg::SelectMonitor {
        request: 1,
        list: 0,
        monitor: 2,
    };
    write_msg(&mut host, &select).await.unwrap();
    let (end, _) = viewer.await.unwrap();
    assert!(
        matches!(end, Err(ViewerError::Unexpected("SelectMonitor"))),
        "{end:?}"
    );
}

/// What a [`Desk`] does when the host hands it a selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnSelect {
    /// Show it from the next picture on (a monitor it does not have is
    /// [`CaptureError::NoMonitor`]).
    Switch,
    /// Fail, as a source that could not switch.
    Fail,
    /// Wait until [`DeskControl::release`] is set, then switch; a stop ends
    /// the wait with a failure within 5 ms, and 10 s at most.
    Hold,
}

/// The test's handle on a [`Desk`] the host owns.
#[derive(Clone)]
struct DeskControl {
    /// The monitors, side by side from (0, 0), the first primary.
    sizes: Arc<Mutex<Vec<(u32, u32)>>>,
    /// All monitors at once is offered (with two or more).
    all: Arc<AtomicBool>,
    on_select: Arc<Mutex<OnSelect>>,
    release: Arc<AtomicBool>,
    /// Every selection the host handed over, in order.
    asked: Arc<Mutex<Vec<Selection>>>,
    /// `None`: a picture about every 20 ms, as a polled desktop (X11, GDI).
    /// `Some(n)`: damage-driven, as a PipeWire stream: `n` more pictures,
    /// then nothing until the test adds some.
    pictures: Arc<Mutex<Option<usize>>>,
    /// A switch while damage-driven brings one picture of the new screen, as
    /// the Wayland switch waits for the new stream's first one.
    first_after_switch: Arc<AtomicBool>,
    /// Inside a held `select`.
    selecting: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
}

impl DeskControl {
    fn new(sizes: &[(u32, u32)]) -> Self {
        Self {
            sizes: Arc::new(Mutex::new(sizes.to_vec())),
            all: Arc::new(AtomicBool::new(true)),
            on_select: Arc::new(Mutex::new(OnSelect::Switch)),
            release: Arc::default(),
            asked: Arc::default(),
            pictures: Arc::default(),
            first_after_switch: Arc::default(),
            selecting: Arc::default(),
            closed: Arc::default(),
        }
    }

    fn on_select(&self, on: OnSelect) {
        *self.on_select.lock().unwrap() = on;
    }

    fn asked(&self) -> Vec<Selection> {
        self.asked.lock().unwrap().clone()
    }

    /// Damage-driven from now on, with no picture to give.
    fn still(&self) {
        *self.pictures.lock().unwrap() = Some(0);
    }

    /// `n` more pictures of a damage-driven desk.
    fn damage(&self, n: usize) {
        let mut pictures = self.pictures.lock().unwrap();
        *pictures = Some(pictures.unwrap_or(0) + n);
    }

    /// Waits until the desk is inside a held `select`.
    async fn until_selecting(&self) {
        let since = tokio::time::Instant::now();
        while !self.selecting.load(Ordering::SeqCst) {
            in_time(since, "the selection");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// A scripted desktop of monitors the test controls ([`DeskControl`]):
/// pictures are test cards of what is shown, one monitor or all of them as
/// one card of their union. A monitor that goes, or "all" with one left,
/// falls back to monitor 1, as the capture's chooser does.
struct Desk {
    ctl: DeskControl,
    shown: Selection,
    last: Option<Layout>,
    index: u32,
}

impl Desk {
    fn now(&mut self) -> Layout {
        let sizes = self.ctl.sizes.lock().unwrap().clone();
        let n = sizes.len();
        let all = self.ctl.all.load(Ordering::SeqCst) && n >= 2;
        match self.shown {
            Selection::Monitor(id) if (1..=n).contains(&usize::from(id)) => {}
            Selection::All if all => {}
            _ => self.shown = Selection::Monitor(1),
        }
        let mut x = 0;
        let monitors: Vec<Monitor> = sizes
            .iter()
            .enumerate()
            .map(|(i, &(width, height))| {
                let rect = Rect::new(x, 0, width, height);
                x += i32::try_from(width).unwrap();
                Monitor {
                    id: u8::try_from(i + 1).unwrap(),
                    primary: i == 0,
                    rect,
                }
            })
            .collect();
        let space = Rect::new(
            0,
            0,
            sizes.iter().map(|s| s.0).sum(),
            sizes.iter().map(|s| s.1).max().unwrap(),
        );
        let shown = match self.shown {
            Selection::All => space,
            Selection::Monitor(id) => monitors[usize::from(id) - 1].rect,
        };
        Layout {
            monitors,
            all,
            shown: self.shown,
            view: View::Rect { shown, space },
        }
    }

    fn take(&mut self, selection: Selection) -> Result<(), CaptureError> {
        let n = self.ctl.sizes.lock().unwrap().len();
        match selection {
            Selection::Monitor(id) if (1..=n).contains(&usize::from(id)) => {}
            Selection::All if n >= 2 && self.ctl.all.load(Ordering::SeqCst) => {}
            Selection::Monitor(id) => return Err(CaptureError::NoMonitor(id)),
            Selection::All => return Err(CaptureError::NoMonitor(0)),
        }
        self.shown = selection;
        if self.ctl.first_after_switch.load(Ordering::SeqCst)
            && let Some(n) = self.ctl.pictures.lock().unwrap().as_mut()
        {
            *n += 1;
        }
        Ok(())
    }
}

impl VideoSource for Desk {
    fn name(&self) -> &'static str {
        "desk"
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let wait = match self.ctl.pictures.lock().unwrap().as_mut() {
            None => Some(Duration::from_millis(20)),
            Some(0) => None,
            Some(n) => {
                *n -= 1;
                Some(Duration::ZERO)
            }
        };
        let Some(wait) = wait else {
            std::thread::sleep(timeout);
            return Ok(None);
        };
        std::thread::sleep(timeout.min(wait));
        let layout = self.now();
        let View::Rect { shown, .. } = layout.view else {
            unreachable!("a desk shows rectangles")
        };
        self.last = Some(layout);
        self.index += 1;
        Ok(Some(Frame {
            width: shown.width,
            height: shown.height,
            bgrx: TestCard::render(shown.width, shown.height, self.index),
            captured_at: std::time::Instant::now(),
            grab: Duration::ZERO,
        }))
    }

    fn layout(&self) -> Option<Layout> {
        self.last.clone()
    }

    fn select(&mut self, selection: Selection, stop: &AtomicBool) -> Result<(), CaptureError> {
        self.ctl.asked.lock().unwrap().push(selection);
        let on_select = *self.ctl.on_select.lock().unwrap();
        match on_select {
            OnSelect::Switch => self.take(selection),
            OnSelect::Fail => Err(CaptureError::Failed("the desk could not switch".into())),
            OnSelect::Hold => {
                self.ctl.selecting.store(true, Ordering::SeqCst);
                let asked = std::time::Instant::now();
                let held = loop {
                    if stop.load(Ordering::SeqCst) {
                        break Err(CaptureError::Failed("stopped".into()));
                    }
                    if self.ctl.release.load(Ordering::SeqCst) {
                        break self.take(selection);
                    }
                    if asked.elapsed() > WAIT {
                        break Err(CaptureError::Failed("held too long".into()));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                };
                self.ctl.selecting.store(false, Ordering::SeqCst);
                held
            }
        }
    }
}

impl Drop for Desk {
    fn drop(&mut self) {
        self.ctl.closed.store(true, Ordering::SeqCst);
    }
}

/// A rig whose source is a [`Desk`] of monitors of `sizes` showing monitor
/// 1, with its handle.
fn desk_rig(sizes: &[(u32, u32)], limits: MediaLimits) -> (Rig, DeskControl) {
    let ctl = DeskControl::new(sizes);
    let source = Desk {
        ctl: ctl.clone(),
        shown: Selection::Monitor(1),
        last: None,
        index: 0,
    };
    let rig = rig_with(
        TestBackend {
            desktop: Mutex::new(Some(Box::new(source))),
            ..TestBackend::default()
        },
        limits,
    );
    (rig, ctl)
}

/// A rig whose source is [`TestScreens`] of `sizes` at `fps`.
fn screens_rig(sizes: &[(u32, u32)], fps: u32, limits: MediaLimits) -> Rig {
    rig_with(
        TestBackend {
            desktop: Mutex::new(Some(Box::new(TestScreens::new(sizes, fps)))),
            ..TestBackend::default()
        },
        limits,
    )
}

/// Ask for `monitor` of the list `list` with `request`.
async fn ask(client: &mut DuplexStream, request: u16, list: u16, monitor: u8) {
    write_msg(
        client,
        &Msg::SelectMonitor {
            request,
            list,
            monitor,
        },
    )
    .await
    .unwrap();
}

/// What a `Monitors` says, but its seq and its monitors' geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Said {
    request: u16,
    status: u8,
    shown: u8,
    all: bool,
    remapped: bool,
    list: u16,
    /// How many monitors it lists.
    n: usize,
}

/// What `msg`, a `Monitors`, says, and its seq.
fn said(msg: &Msg) -> (Said, u32) {
    let Msg::Monitors {
        request,
        status,
        shown,
        all,
        remapped,
        list,
        seq,
        monitors,
    } = msg
    else {
        panic!("not a Monitors: {msg:?}");
    };
    (
        Said {
            request: *request,
            status: *status,
            shown: *shown,
            all: *all,
            remapped: *remapped,
            list: *list,
            n: monitors.len(),
        },
        *seq,
    )
}

/// Read, acknowledging every `Video`, up to the `Monitors` that answers
/// `request` (the host's news and other answers are passed over).
async fn answer_to(client: &mut DuplexStream, request: u16) -> Msg {
    let since = tokio::time::Instant::now();
    loop {
        in_time(since, "the answer");
        let msg = next_acking(client).await;
        if matches!(msg, Msg::Monitors { request: r, .. } if r == request) {
            return msg;
        }
    }
}

/// The next frame, unacknowledged, which must be the `Video` a `Monitors` at
/// `seq` describes, a keyframe: its access unit.
async fn the_picture_at(client: &mut DuplexStream, seq: u32) -> Vec<u8> {
    match tokio::time::timeout(WAIT, read_msg(client))
        .await
        .expect("a frame in time")
        .unwrap()
    {
        Some(Msg::Video {
            seq: s,
            flags,
            data,
            ..
        }) => {
            assert_eq!(s, seq, "the picture the Monitors describes");
            assert_ne!(flags & video_flags::KEYFRAME, 0, "a keyframe");
            data
        }
        other => panic!("expected the Video right after the Monitors, got {other:?}"),
    }
}

/// Short switch limits for the tests: an interval of 300 ms between
/// accepted switches, and an answer due within 800 ms.
fn quick_switches() -> MediaLimits {
    MediaLimits {
        switch_interval: Duration::from_millis(300),
        switch_answer: Duration::from_millis(800),
        ..MediaLimits::default()
    }
}

const OK: u8 = tornect_proto::monitor_status::OK;
const UNKNOWN: u8 = tornect_proto::monitor_status::UNKNOWN;
const FAILED: u8 = tornect_proto::monitor_status::FAILED;
const BUSY: u8 = tornect_proto::monitor_status::BUSY;

/// The monitors design's H2, session test 2: a viewer's `SelectMonitor` for
/// another screen is answered `OK` right before the first picture of that
/// screen, which is a keyframe of the new size at the answer's `seq`, with
/// `REMAPPED`; the injector took the new view before that picture; the card
/// counts on across the switch, so no picture was lost or repeated. The
/// report counts the request and the switch, and the indicator hears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_switch_is_answered_right_before_the_first_picture_of_the_new_screen() {
    let rig = screens_rig(&TEST_SCREENS, 30, MediaLimits::default());
    let (_, binding) = start(&rig.host, 70, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    let (first, _) = said(&next_acking(&mut client).await);
    assert_eq!(
        first,
        Said {
            request: 0,
            status: OK,
            shown: 1,
            all: true,
            remapped: false,
            list: 0,
            n: 2
        }
    );
    let mut decoded = Decoded::new();
    let Msg::Video { data, .. } = next_acking(&mut client).await else {
        panic!("the first picture right after its Monitors");
    };
    let (mut last, size) = decoded.picture(&data);
    assert_eq!(size, (1280, 720));

    ask(&mut client, 1, 0, 2).await;
    let since = tokio::time::Instant::now();
    let answer = loop {
        in_time(since, "the answer");
        match next_acking(&mut client).await {
            Msg::Video { data, .. } => {
                let (index, size) = decoded.picture(&data);
                assert_eq!(size, (1280, 720), "screen 1 until the answer");
                last = index;
            }
            msg @ Msg::Monitors { .. } => break msg,
            Msg::Stats(_) | Msg::Quality { .. } => {}
            other => panic!("before the answer: {other:?}"),
        }
    };
    let (answer, at) = said(&answer);
    assert_eq!(
        answer,
        Said {
            request: 1,
            status: OK,
            shown: 2,
            all: true,
            remapped: true,
            list: 0,
            n: 2
        }
    );
    let data = the_picture_at(&mut client, at).await;
    let (index, size) = decoded.picture(&data);
    assert_eq!(size, (1024, 768), "screen 2's size");
    assert!(last.is_some(), "the card's index is read");
    assert_eq!(index, last.map(|i| i + 1), "the card counts on");
    let views: Vec<View> = rig.backend.recorder.views().iter().map(|v| v.1).collect();
    assert_eq!(
        views,
        [
            two_screens(Selection::Monitor(1)).view,
            two_screens(Selection::Monitor(2)).view
        ]
    );

    let report = close_and_report(&mut client, served).await;
    assert_eq!((report.monitor_requests, report.monitor_switches), (1, 1));
    assert_eq!(
        rig.seen.lines(),
        [
            "started synthetic screens 1280x720 Control input=true",
            "changed screen=1 of=2 all=false shown=1280x720+0+0 input=true",
            "changed screen=2 of=2 all=false shown=1024x768+1280+0 input=true",
            "stopped ViewerLeft",
        ]
    );
}

/// Session test 3: all screens of two 2560×1440 monitors, side by side
/// (5120×1440), under Best quality decode at 3840×1080: scaled whole, so the
/// pixel at 0.8 of the width is the card's seventh bar (BARS[6], blue) of
/// the whole desktop. A crop to the first 3840 columns would put the fifth
/// bar (magenta) there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_screens_wider_than_the_codec_are_scaled_whole() {
    let rig = screens_rig(&[(2560, 1440), (2560, 1440)], 10, MediaLimits::default());
    let (_, binding) = start(&rig.host, 71, SessionMode::ViewOnly);
    let (mut client, served) = connect(&rig.host);
    let (width, height, _) = bind_preset(&mut client, &binding, quality::BEST_QUALITY).await;
    assert_eq!((width, height), (2560, 1440), "the primary first");
    next_monitors(&mut client).await;
    ask(&mut client, 1, 0, tornect_proto::ALL_MONITORS).await;
    let (answer, at) = said(&answer_to(&mut client, 1).await);
    assert_eq!(
        answer,
        Said {
            request: 1,
            status: OK,
            shown: 0,
            all: true,
            remapped: true,
            list: 0,
            n: 2
        }
    );
    let data = the_picture_at(&mut client, at).await;
    let mut decoder = H264Decoder::new().unwrap();
    let frame = decoder.decode(&data).unwrap().expect("a picture").clone();
    assert_eq!((frame.width, frame.height), (3840, 1080));
    let x = 3840 * 8 / 10;
    let at = ((100 * frame.width + x) * 4) as usize;
    let [r, g, b] = [frame.rgba[at], frame.rgba[at + 1], frame.rgba[at + 2]];
    assert!(
        b > 150 && r < 60 && g < 60,
        "the seventh bar (blue) of the whole desktop at x {x}, not the fifth \
         (magenta) a crop would show: {:?}",
        (r, g, b)
    );
    drop(client);
    assert!(matches!(served.await.unwrap(), MediaOutcome::Served { .. }));
}

/// Read, acknowledging every `Video`, until `count` answers (`Monitors` with
/// a request) have come: each answer, with the seq of the `Video` that came
/// right after it, or `None` when another answer came first.
async fn answers_and_next_seq(client: &mut DuplexStream, count: usize) -> Vec<(Msg, Option<u32>)> {
    let since = tokio::time::Instant::now();
    let mut answers: Vec<(Msg, Option<u32>)> = Vec::new();
    let mut open = false;
    loop {
        in_time(since, "the answers");
        match next_acking(client).await {
            Msg::Video { seq, .. } => {
                if open {
                    if let Some(last) = answers.last_mut() {
                        last.1 = Some(seq);
                    }
                    open = false;
                    if answers.len() == count {
                        return answers;
                    }
                }
            }
            msg @ Msg::Monitors { request, .. } if request != 0 => {
                answers.push((msg, None));
                open = true;
            }
            _ => {}
        }
    }
}

/// Session test 4, the refusals at once: `UNKNOWN` for a monitor the list
/// does not have, for a stale list, and for all monitors where the host
/// offers no "all"; a request for the screen already shown is a no-op
/// answered `OK` at once with `REMAPPED` clear. Each answer says the current
/// list from the next picture on (its `seq` is that picture's), and none
/// moves the injector. A source with nothing to choose answers `UNKNOWN`
/// with an empty list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_select_monitor_that_changes_nothing_is_answered_at_once() {
    let mut no_all = two_screens(Selection::Monitor(1));
    no_all.all = false;
    let (rig, _) = shifting_rig(no_all);
    let (_, binding) = start(&rig.host, 72, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    let (first, _) = said(&next_monitors(&mut client).await);
    assert!(!first.all && first.n == 2, "{first:?}");
    for (request, list, monitor) in [(1, 0, 3), (2, 9, 2), (3, 0, 0), (4, 0, 1)] {
        ask(&mut client, request, list, monitor).await;
    }
    let answers = answers_and_next_seq(&mut client, 4).await;
    for ((msg, next), (request, status)) in
        answers
            .iter()
            .zip([(1, UNKNOWN), (2, UNKNOWN), (3, UNKNOWN), (4, OK)])
    {
        let (answer, seq) = said(msg);
        assert_eq!(
            answer,
            Said {
                request,
                status,
                shown: 1,
                all: false,
                remapped: false,
                list: 0,
                n: 2
            }
        );
        if let Some(next) = next {
            assert_eq!(seq, *next, "from the next picture on");
        }
    }
    assert!(answers.last().unwrap().1.is_some());
    assert_eq!(
        rig.backend.recorder.views().len(),
        1,
        "only the first view: nothing moved"
    );
    let report = close_and_report(&mut client, served).await;
    assert_eq!((report.monitor_requests, report.monitor_switches), (4, 0));

    // Nothing to choose: the card.
    let rig = rig_with(TestBackend::default(), MediaLimits::default());
    let (_, binding) = start(&rig.host, 73, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    ask(&mut client, 1, 0, 1).await;
    let answers = answers_and_next_seq(&mut client, 1).await;
    let (answer, seq) = said(&answers[0].0);
    assert_eq!(
        answer,
        Said {
            request: 1,
            status: UNKNOWN,
            shown: 0,
            all: false,
            remapped: false,
            list: 0,
            n: 0
        }
    );
    assert_eq!(Some(seq), answers[0].1);
    let report = close_and_report(&mut client, served).await;
    assert_eq!((report.monitor_requests, report.monitor_switches), (1, 0));
}

/// Session test 4, one switch at a time: a request while a switch is under
/// way is answered `BUSY` at once, also once the switch interval is over;
/// a request within the interval of the last accepted switch is `BUSY` too,
/// also once that switch is answered; after the interval a switch is
/// accepted again; a request for the screen shown is a no-op `OK` whatever
/// the interval. Only accepted switches reach the source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_switch_under_way_or_too_soon_is_answered_busy() {
    let interval = Duration::from_millis(600);
    let limits = MediaLimits {
        switch_interval: interval,
        ..MediaLimits::default()
    };
    let (rig, desk) = desk_rig(&[(320, 192), (256, 128)], limits);
    let (_, binding) = start(&rig.host, 74, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;

    // Under way, past the interval.
    desk.on_select(OnSelect::Hold);
    let first = tokio::time::Instant::now();
    ask(&mut client, 1, 0, 2).await;
    desk.until_selecting().await;
    tokio::time::sleep_until(first + interval + Duration::from_millis(100)).await;
    ask(&mut client, 2, 0, 0).await;
    let (busy, _) = said(&answer_to(&mut client, 2).await);
    assert_eq!(
        busy,
        Said {
            request: 2,
            status: BUSY,
            shown: 1,
            all: true,
            remapped: false,
            list: 0,
            n: 2
        },
        "a switch is under way"
    );
    desk.release.store(true, Ordering::SeqCst);
    let (switched, _) = said(&answer_to(&mut client, 1).await);
    assert_eq!(
        (switched.status, switched.shown, switched.remapped),
        (OK, 2, true)
    );

    // Accepted (past the interval, none under way) and answered at once,
    // then another right after it: too soon.
    let second = tokio::time::Instant::now();
    ask(&mut client, 3, 0, 1).await;
    let (back, _) = said(&answer_to(&mut client, 3).await);
    assert_eq!((back.status, back.shown, back.remapped), (OK, 1, true));
    ask(&mut client, 4, 0, 2).await;
    let (soon, _) = said(&answer_to(&mut client, 4).await);
    assert!(
        second.elapsed() < interval,
        "the test was too slow to ask within the interval"
    );
    assert_eq!(
        (soon.status, soon.shown, soon.remapped),
        (BUSY, 1, false),
        "within the interval"
    );

    tokio::time::sleep_until(second + interval + Duration::from_millis(200)).await;
    ask(&mut client, 5, 0, 2).await;
    let (again, _) = said(&answer_to(&mut client, 5).await);
    assert_eq!((again.status, again.shown, again.remapped), (OK, 2, true));
    ask(&mut client, 6, 0, 2).await;
    let (noop, _) = said(&answer_to(&mut client, 6).await);
    assert_eq!(
        (noop.status, noop.shown, noop.remapped),
        (OK, 2, false),
        "a no-op, at once, within the interval"
    );
    assert_eq!(
        desk.asked(),
        [
            Selection::Monitor(2),
            Selection::Monitor(1),
            Selection::Monitor(2)
        ],
        "only the accepted reach the source"
    );
    let report = close_and_report(&mut client, served).await;
    assert_eq!((report.monitor_requests, report.monitor_switches), (6, 3));
}

/// Session test 5: input follows the screen asked for. Moves made before
/// the switch land on screen 1; at the switch the held button is let go of
/// and the key stays down; moves, wheel turns and presses read after the
/// `REMAPPED` answer at S and before `VideoAck(S)` are held back, and after
/// it a press waits for a move; the viewer's bottom-right corner then lands
/// on screen 2's bottom-right pixel. Keys and releases always go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn input_follows_the_screen_asked_for_once_its_picture_is_acknowledged() {
    let rig = screens_rig(&TEST_SCREENS, 30, MediaLimits::default());
    let (_, binding) = start(&rig.host, 75, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    let one = two_screens(Selection::Monitor(1)).view;
    let two = two_screens(Selection::Monitor(2)).view;
    send_input(
        &mut client,
        &[
            InputEvent::PointerMove { x: 1000, y: 1000 },
            LEFT_DOWN,
            A_DOWN,
        ],
    )
    .await;
    sync(&mut client, 1).await;
    let dragged = moved_over(1000, 1000, one);
    assert_eq!(rig.backend.recorder.events(), [dragged, LEFT_DOWN, A_DOWN]);

    ask(&mut client, 1, 0, 2).await;
    let (answer, at) = said(&answer_to(&mut client, 1).await);
    assert!(answer.remapped && answer.shown == 2, "{answer:?}");
    the_picture_at(&mut client, at).await;
    assert_eq!(rig.backend.recorder.views(), [(0, one), (4, two)]);
    assert_eq!(
        rig.backend.recorder.events(),
        [dragged, LEFT_DOWN, A_DOWN, LEFT_UP],
        "no drag across screens; the key stays down"
    );

    let corner = InputEvent::PointerMove { x: 65535, y: 65535 };
    let wheel = InputEvent::Wheel { dx: 0, dy: -120 };
    write_msg(
        &mut client,
        &Msg::VideoAck {
            seq: at.wrapping_sub(1),
        },
    )
    .await
    .unwrap();
    send_input(&mut client, &[corner, wheel, LEFT_DOWN, LEFT_UP, A_UP]).await;
    sync(&mut client, 2).await;
    assert_eq!(
        rig.backend.recorder.events(),
        [dragged, LEFT_DOWN, A_DOWN, LEFT_UP, A_UP],
        "made against screen 1's pictures: only the key goes"
    );

    write_msg(&mut client, &Msg::VideoAck { seq: at })
        .await
        .unwrap();
    send_input(&mut client, &[LEFT_DOWN, corner, LEFT_DOWN, LEFT_UP]).await;
    sync(&mut client, 3).await;
    let placed = moved_over(65535, 65535, two);
    let InputEvent::PointerMove { x, y } = placed else {
        unreachable!()
    };
    assert_eq!(
        (denormalize(x, 2304), denormalize(y, 768)),
        (2303, 767),
        "screen 2's bottom-right pixel"
    );
    assert_eq!(
        rig.backend.recorder.events(),
        [
            dragged, LEFT_DOWN, A_DOWN, LEFT_UP, A_UP, placed, LEFT_DOWN, LEFT_UP
        ]
    );
    let report = close_and_report(&mut client, served).await;
    assert_eq!(
        report.input_held_back, 4,
        "three before the ack, a press after"
    );
    assert_eq!(report.monitor_switches, 1);
}

/// The final review of the monitors feature: a session that opens on one
/// monitor of several (the primary) holds back wheel turns and presses until
/// the viewer's first move has placed the host's pointer on it, as after a
/// remap (H5): the pointer may sit on a monitor the viewer is not shown.
/// Keys go. A session whose first picture shows the whole desktop holds
/// nothing back, as before monitors could be chosen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_opening_on_one_of_several_screens_waits_for_a_move_before_a_click() {
    let wheel = InputEvent::Wheel { dx: 0, dy: -120 };
    let rig = screens_rig(&TEST_SCREENS, 30, MediaLimits::default());
    let (_, binding) = start(&rig.host, 86, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    send_input(&mut client, &[wheel, LEFT_DOWN, A_DOWN, A_UP]).await;
    sync(&mut client, 1).await;
    assert_eq!(
        rig.backend.recorder.events(),
        [A_DOWN, A_UP],
        "before a move only the key goes"
    );
    let middle = InputEvent::PointerMove { x: 32768, y: 32768 };
    send_input(&mut client, &[middle, wheel, LEFT_DOWN, LEFT_UP]).await;
    sync(&mut client, 2).await;
    let placed = moved_over(32768, 32768, two_screens(Selection::Monitor(1)).view);
    assert_eq!(
        rig.backend.recorder.events(),
        [A_DOWN, A_UP, placed, wheel, LEFT_DOWN, LEFT_UP]
    );
    let report = close_and_report(&mut client, served).await;
    assert_eq!(report.input_held_back, 2, "the wheel turn and the press");

    let rig = screens_rig(&[(640, 360)], 30, MediaLimits::default());
    let (_, binding) = start(&rig.host, 87, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    let (first, _) = said(&next_monitors(&mut client).await);
    assert_eq!((first.shown, first.n), (1, 1));
    send_input(&mut client, &[wheel, LEFT_DOWN, LEFT_UP]).await;
    sync(&mut client, 3).await;
    assert_eq!(
        rig.backend.recorder.events(),
        [wheel, LEFT_DOWN, LEFT_UP],
        "the whole desktop is shown, the pointer on it"
    );
    let report = close_and_report(&mut client, served).await;
    assert_eq!(report.input_held_back, 0);
}

/// Session test 6: a view-only viewer may switch (a viewing choice): its
/// request is answered and it sees the new screen, while its input stays
/// undecoded and no injector is opened or retargeted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_view_only_viewer_switches_and_its_input_stays_undecoded() {
    let rig = screens_rig(&TEST_SCREENS, 30, MediaLimits::default());
    let (_, binding) = start(&rig.host, 76, SessionMode::ViewOnly);
    let (mut client, served) = connect(&rig.host);
    assert_eq!(bind_raw(&mut client, &binding).await, 1, "view-only");
    next_monitors(&mut client).await;
    write_msg(&mut client, &Msg::Input([0xff; 16]))
        .await
        .unwrap();
    ask(&mut client, 1, 0, 2).await;
    let (answer, at) = said(&answer_to(&mut client, 1).await);
    assert_eq!(
        (answer.status, answer.shown, answer.remapped),
        (OK, 2, true)
    );
    let data = the_picture_at(&mut client, at).await;
    assert_eq!(Decoded::new().picture(&data).1, (1024, 768));
    write_msg(&mut client, &Msg::Input([0xff; 16]))
        .await
        .unwrap();
    let report = close_and_report(&mut client, served).await;
    assert_eq!((report.input_injected, report.input_dropped), (0, 2));
    assert_eq!(report.monitor_switches, 1);
    assert_eq!(rig.backend.injectors.load(Ordering::SeqCst), 0);
    assert!(rig.backend.recorder.views().is_empty());
    assert_eq!(
        rig.seen.lines(),
        [
            "started synthetic screens 1280x720 ViewOnly input=false",
            "changed screen=1 of=2 all=false shown=1280x720+0+0 input=false",
            "changed screen=2 of=2 all=false shown=1024x768+1280+0 input=false",
            "stopped ViewerLeft",
        ]
    );
}

/// Session test 7: a switch the source cannot make is answered `FAILED`,
/// and the screen shown stays, at its size, with no news and no new view;
/// the next switch, after the interval, succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_switch_keeps_the_screen_and_the_next_one_succeeds() {
    let (rig, desk) = desk_rig(&[(320, 192), (256, 128)], quick_switches());
    let (_, binding) = start(&rig.host, 77, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    desk.on_select(OnSelect::Fail);
    let asked = tokio::time::Instant::now();
    ask(&mut client, 1, 0, 2).await;
    let (failed, _) = said(&answer_to(&mut client, 1).await);
    assert_eq!(
        failed,
        Said {
            request: 1,
            status: FAILED,
            shown: 1,
            all: true,
            remapped: false,
            list: 0,
            n: 2
        }
    );
    // The screen shown stays: the next keyframe, asked for, is screen 1's,
    // and no news comes before it.
    write_msg(&mut client, &Msg::KeyframeRequest).await.unwrap();
    let since = tokio::time::Instant::now();
    let data = loop {
        in_time(since, "a keyframe");
        match next_acking(&mut client).await {
            Msg::Video { flags, data, .. } if flags & video_flags::KEYFRAME != 0 => break data,
            msg @ Msg::Monitors { .. } => panic!("no news after a failed switch: {msg:?}"),
            _ => {}
        }
    };
    assert_eq!(
        Decoded::new().picture(&data).1,
        (320, 192),
        "still screen 1"
    );
    assert_eq!(rig.backend.recorder.views().len(), 1, "no new view");

    desk.on_select(OnSelect::Switch);
    tokio::time::sleep_until(asked + Duration::from_millis(500)).await;
    ask(&mut client, 2, 0, 2).await;
    let (switched, at) = said(&answer_to(&mut client, 2).await);
    assert_eq!(
        (switched.status, switched.shown, switched.remapped),
        (OK, 2, true)
    );
    let data = the_picture_at(&mut client, at).await;
    assert_eq!(Decoded::new().picture(&data).1, (256, 128));
    assert_eq!(desk.asked(), [Selection::Monitor(2), Selection::Monitor(2)]);
    let report = close_and_report(&mut client, served).await;
    assert_eq!((report.monitor_requests, report.monitor_switches), (2, 1));
}

/// Session test 8: the screen shown is unplugged. The desk falls back to
/// monitor 1, and the host says so as news (request 0, `REMAPPED`, a new
/// list of one) right before the first picture of it; the injector follows
/// that view before the picture, and the move made against the screen
/// that went is held back until the viewer acknowledges it. A request from
/// the old list is `UNKNOWN`, with the new list in the answer (the design's
/// §9 risk 8). A monitor that went while the host still lists it (no picture
/// since, on a damage-driven desk) is the source's `UNKNOWN`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_monitor_unplugged_falls_back_and_holds_back_input_in_flight() {
    let (rig, desk) = desk_rig(&[(320, 192), (256, 128)], MediaLimits::default());
    let (_, binding) = start(&rig.host, 78, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    ask(&mut client, 1, 0, 2).await;
    let (answer, at) = said(&answer_to(&mut client, 1).await);
    assert_eq!((answer.status, answer.shown), (OK, 2));
    the_picture_at(&mut client, at).await;
    // Acknowledged, so the barrier of the switch comes down.
    write_msg(&mut client, &Msg::VideoAck { seq: at })
        .await
        .unwrap();
    let corner = InputEvent::PointerMove { x: 65535, y: 65535 };
    send_input(&mut client, &[corner]).await;
    sync(&mut client, 1).await;
    assert_eq!(rig.backend.recorder.events().len(), 1, "placed on screen 2");

    desk.sizes.lock().unwrap().truncate(1);
    let (news, at) = said(&next_monitors(&mut client).await);
    assert_eq!(
        news,
        Said {
            request: 0,
            status: OK,
            shown: 1,
            all: false,
            remapped: true,
            list: 1,
            n: 1
        }
    );
    the_picture_at(&mut client, at).await;
    let alone = View::Rect {
        shown: Rect::new(0, 0, 320, 192),
        space: Rect::new(0, 0, 320, 192),
    };
    assert_eq!(
        rig.backend.recorder.views().last().map(|v| v.1),
        Some(alone),
        "followed before the picture"
    );
    send_input(&mut client, &[corner]).await;
    ask(&mut client, 2, 0, 2).await;
    let (stale, _) = said(&answer_to(&mut client, 2).await);
    assert_eq!(
        stale,
        Said {
            request: 2,
            status: UNKNOWN,
            shown: 1,
            all: false,
            remapped: false,
            list: 1,
            n: 1
        },
        "a stale list"
    );
    assert_eq!(rig.backend.recorder.events().len(), 1, "held back");
    write_msg(&mut client, &Msg::VideoAck { seq: at })
        .await
        .unwrap();
    send_input(&mut client, &[corner]).await;
    sync(&mut client, 2).await;
    assert_eq!(
        rig.backend.recorder.events().last(),
        Some(&moved_over(65535, 65535, alone))
    );
    let report = close_and_report(&mut client, served).await;
    assert_eq!(report.input_held_back, 1);

    // Gone while the host still lists it: no picture since, so the host
    // accepts, and the source refuses.
    let (rig, desk) = desk_rig(&[(320, 192), (256, 128)], MediaLimits::default());
    let (_, binding) = start(&rig.host, 79, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    desk.still();
    drain(&mut client, Duration::from_millis(300)).await;
    desk.sizes.lock().unwrap().truncate(1);
    ask(&mut client, 1, 0, 2).await;
    let (refused, _) = said(&answer_to(&mut client, 1).await);
    assert_eq!(
        refused,
        Said {
            request: 1,
            status: UNKNOWN,
            shown: 1,
            all: true,
            remapped: false,
            list: 0,
            n: 2
        },
        "the host's list until a picture says otherwise"
    );
    assert_eq!(desk.asked(), [Selection::Monitor(2)]);
    let report = close_and_report(&mut client, served).await;
    assert_eq!((report.monitor_requests, report.monitor_switches), (1, 0));
}

/// The final review of the monitors feature: the source resolves an id
/// against its latest grab, which can be a picture ahead of the list the host
/// said, the grab's picture still on its way while the host's write waits.
/// Here a monitor is plugged in between the two the viewer was told of, so
/// in the source's newer list "Screen 2" is the new monitor. A request for
/// Screen 2 of the list the viewer has passes the host's check (the host has
/// said no other list yet), and the capture thread refuses it `UNKNOWN`
/// without asking the source: the viewer hears the new list with its
/// picture, then the refusal, and a request from the new list goes through.
/// Without the check the source would show the new monitor as the answer to
/// a request for the one that moved to Screen 3 (the design's §9, item 8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_from_a_list_the_source_has_moved_past_is_unknown() {
    let interval = Duration::from_secs(2);
    let (rig, desk) = desk_rig(
        &[(320, 192), (256, 128)],
        MediaLimits {
            switch_interval: interval,
            ..MediaLimits::default()
        },
    );
    // One picture to open with, then a still screen; a switch brings one
    // picture of the new screen, as a damage-driven source's does.
    desk.damage(1);
    desk.first_after_switch.store(true, Ordering::SeqCst);
    let (_, binding) = start(&rig.host, 85, SessionMode::Control);
    let (mut client, served) = connect_narrow(&rig.host);
    bind_raw(&mut client, &binding).await;
    let first = next_msg(&mut client).await.expect("the first Monitors");
    let (said_first, _) = said(&first);
    assert_eq!((said_first.list, said_first.shown, said_first.n), (0, 1, 2));
    // The viewer reads nothing more for now: the host's write of picture 0
    // waits, and what the viewer sends is handled meanwhile.

    // A monitor plugged in at x 320: the 256×128 one moves to Screen 3.
    *desk.sizes.lock().unwrap() = vec![(320, 192), (128, 128), (256, 128)];
    desk.damage(1);
    // The ack credits the next picture, which the source grabs with the new
    // list; that picture waits behind the write.
    write_msg(&mut client, &Msg::VideoAck { seq: 0 })
        .await
        .unwrap();
    let since = tokio::time::Instant::now();
    while *desk.pictures.lock().unwrap() != Some(0) {
        in_time(since, "the grab of the new list");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    write_msg(
        &mut client,
        &Msg::SelectMonitor {
            request: 1,
            list: 0,
            monitor: 2,
        },
    )
    .await
    .unwrap();
    // The host handles it while its write still waits.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut order = Vec::new();
    let since = tokio::time::Instant::now();
    let refused = loop {
        in_time(since, "the answer");
        match next_msg(&mut client).await.expect("the stream is open") {
            Msg::Video { seq, .. } => order.push(format!("video {seq}")),
            msg @ Msg::Monitors { .. } => {
                let (s, _) = said(&msg);
                if s.request == 1 {
                    break s;
                }
                order.push(format!("news list={} n={}", s.list, s.n));
            }
            _ => {}
        }
    };
    assert_eq!(order, ["video 0", "news list=1 n=3", "video 1"]);
    assert_eq!(
        refused,
        Said {
            request: 1,
            status: UNKNOWN,
            shown: 1,
            all: true,
            remapped: false,
            list: 1,
            n: 3
        },
        "refused against the list the source has, said with it"
    );
    assert!(desk.asked().is_empty(), "the source was never asked");
    // The host accepted the request, so its switch interval runs: proof that
    // the capture thread, not the host's own list check, refused it.
    write_msg(
        &mut client,
        &Msg::SelectMonitor {
            request: 2,
            list: 1,
            monitor: 3,
        },
    )
    .await
    .unwrap();
    let busy = loop {
        in_time(since, "the second answer");
        if let Some(msg @ Msg::Monitors { .. }) = next_msg(&mut client).await {
            break said(&msg).0;
        }
    };
    assert_eq!((busy.request, busy.status), (2, BUSY));

    // From the new list, after the interval: the monitor asked for.
    tokio::time::sleep(interval).await;
    write_msg(
        &mut client,
        &Msg::SelectMonitor {
            request: 3,
            list: 1,
            monitor: 3,
        },
    )
    .await
    .unwrap();
    let since = tokio::time::Instant::now();
    let (switched, at) = loop {
        in_time(since, "the third answer");
        if let Some(msg @ Msg::Monitors { .. }) = next_msg(&mut client).await {
            let (s, at) = said(&msg);
            if s.request == 3 {
                break (s, at);
            }
        }
    };
    assert_eq!(
        (switched.status, switched.shown, switched.remapped),
        (OK, 3, true)
    );
    match next_msg(&mut client).await {
        Some(Msg::Video { seq, .. }) => assert_eq!(seq, at),
        other => panic!("expected the answer's picture, got {other:?}"),
    }
    assert_eq!(desk.asked(), [Selection::Monitor(3)]);
    assert_eq!(
        rig.backend.recorder.views().last().map(|v| v.1),
        Some(View::Rect {
            shown: Rect::new(448, 0, 256, 128),
            space: Rect::new(0, 0, 704, 192),
        }),
        "the monitor that moved to Screen 3"
    );

    write_msg(
        &mut client,
        &Msg::Close {
            reason: reason::ENDED_BY_VIEWER,
        },
    )
    .await
    .unwrap();
    let MediaOutcome::Served { report, .. } =
        tokio::time::timeout(WAIT, served).await.unwrap().unwrap()
    else {
        panic!("not served");
    };
    assert_eq!((report.monitor_requests, report.monitor_switches), (3, 1));
}

/// Session test 9: a kill while the source is inside a blocking switch (a
/// Wayland switch may block for up to 10 s) stops capture well within the
/// host's stop wait (`STOP_WAIT`, 5 s): the source checks the stop flag, the
/// stream ends with `Close{ENDED_BY_HOST}`, and the source is closed by the
/// time the stream is over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kill_while_the_source_switches_stops_capture_in_time() {
    let (rig, desk) = desk_rig(&[(320, 192), (256, 128)], MediaLimits::default());
    let kill = tornect_signal::fsm::host::KillSwitch::new();
    let watcher = rig.host.watch_kill(kill.clone());
    let (_, binding) = start(&rig.host, 80, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    desk.on_select(OnSelect::Hold);
    ask(&mut client, 1, 0, 2).await;
    desk.until_selecting().await;

    let killed = tokio::time::Instant::now();
    kill.kill(bye::PANIC);
    assert_eq!(until_close(&mut client).await, Some(reason::ENDED_BY_HOST));
    let outcome = tokio::time::timeout(WAIT, served).await.unwrap().unwrap();
    assert!(
        killed.elapsed() < Duration::from_secs(2),
        "capture stopped {:?} after the kill",
        killed.elapsed()
    );
    assert!(
        matches!(
            outcome,
            MediaOutcome::Served {
                end: MediaEnd::SessionOver(r),
                ..
            } if r == reason::ENDED_BY_HOST
        ),
        "{outcome:?}"
    );
    assert!(desk.closed.load(Ordering::SeqCst), "the source is closed");
    assert!(!desk.selecting.load(Ordering::SeqCst), "the switch gave up");
    assert_eq!(desk.asked(), [Selection::Monitor(2)]);
    watcher.abort();
}

/// Session test 10, through a switch the viewer asked for: an injector that
/// refuses the new screen's view ends the session's input rather than map a
/// click elsewhere (the design's §4). The switch is still answered `OK` (the
/// picture shows that screen); the key held is let go of, the notice gains
/// `INPUT_LOST`, the indicator hears `input: false`, and nothing is
/// injected after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_switch_the_injector_cannot_follow_ends_the_sessions_input() {
    use tornect_signal::messages::notice;
    let rig = screens_rig(&TEST_SCREENS, 30, MediaLimits::default());
    let (id, binding) = start(&rig.host, 81, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    send_input(&mut client, &[A_DOWN]).await;
    sync(&mut client, 1).await;
    rig.backend.recorder.refuses.store(true, Ordering::SeqCst);

    ask(&mut client, 1, 0, 2).await;
    let (answer, _) = said(&answer_to(&mut client, 1).await);
    assert_eq!(
        (answer.status, answer.shown, answer.remapped),
        (OK, 2, true)
    );
    assert_eq!(rig.backend.recorder.events(), [A_DOWN, A_UP]);
    assert_eq!(
        rig.host.viewer_notice(&id, Some(0)),
        Some(notice::INPUT_LOST)
    );
    send_input(
        &mut client,
        &[A_DOWN, InputEvent::PointerMove { x: 9, y: 9 }],
    )
    .await;
    sync(&mut client, 2).await;
    assert_eq!(rig.backend.recorder.events().len(), 2, "nothing more");
    let report = close_and_report(&mut client, served).await;
    assert_eq!(report.monitor_switches, 1);
    assert_eq!(
        rig.seen.lines(),
        [
            "started synthetic screens 1280x720 Control input=true",
            "changed screen=1 of=2 all=false shown=1280x720+0+0 input=true",
            "changed screen=2 of=2 all=false shown=1024x768+1280+0 input=false",
            "stopped ViewerLeft",
        ]
    );
}

/// The views of a [`Desk`] of 320×192 and 256×128 side by side.
fn desk_view(monitor: u8) -> View {
    let space = Rect::new(0, 0, 576, 192);
    let shown = match monitor {
        1 => Rect::new(0, 0, 320, 192),
        2 => Rect::new(320, 0, 256, 128),
        _ => space,
    };
    View::Rect { shown, space }
}

/// Session test 11, a damage-driven desk (pictures only on change, as a
/// PipeWire stream): a switch completes on a still screen, its answer riding
/// the new screen's first picture, and nothing more comes; a no-op is
/// answered at once with no picture, from the next seq on; pointer input made
/// while a switch is under way keeps landing with the view of the picture the
/// viewer sees, until the new screen's picture says otherwise. The design
/// runs it on paused time; here it runs on the real clock with short limits,
/// as the capture thread is a blocking thread tokio's paused clock does not
/// see.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_damage_driven_desk_switches_on_a_still_screen() {
    let limits = MediaLimits {
        switch_interval: Duration::from_millis(300),
        switch_answer: WAIT,
        ..MediaLimits::default()
    };
    let (rig, desk) = desk_rig(&[(320, 192), (256, 128)], limits);
    desk.first_after_switch.store(true, Ordering::SeqCst);
    desk.still();
    desk.damage(1);
    let (_, binding) = start(&rig.host, 82, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    assert!(matches!(
        next_acking(&mut client).await,
        Msg::Video { seq: 0, .. }
    ));

    let asked = tokio::time::Instant::now();
    ask(&mut client, 1, 0, 2).await;
    let (switched, at) = said(&answer_to(&mut client, 1).await);
    assert_eq!(
        (switched.status, switched.shown, switched.remapped),
        (OK, 2, true)
    );
    let data = the_picture_at(&mut client, at).await;
    assert_eq!(Decoded::new().picture(&data).1, (256, 128));
    write_msg(&mut client, &Msg::VideoAck { seq: at })
        .await
        .unwrap();
    assert!(
        !drain(&mut client, Duration::from_millis(300))
            .await
            .iter()
            .any(|m| matches!(m, Msg::Video { .. })),
        "nothing more on a still screen"
    );

    ask(&mut client, 2, 0, 2).await;
    let msg = tokio::time::timeout(Duration::from_secs(2), read_msg(&mut client))
        .await
        .expect("answered at once, with no picture")
        .unwrap()
        .unwrap();
    assert_eq!(
        said(&msg),
        (
            Said {
                request: 2,
                status: OK,
                shown: 2,
                all: true,
                remapped: false,
                list: 0,
                n: 2
            },
            at.wrapping_add(1)
        ),
        "a no-op, from the next picture on"
    );

    desk.on_select(OnSelect::Hold);
    tokio::time::sleep_until(asked + Duration::from_millis(400)).await;
    ask(&mut client, 3, 0, 1).await;
    desk.until_selecting().await;
    let corner = InputEvent::PointerMove { x: 65535, y: 65535 };
    send_input(&mut client, &[corner]).await;
    sync(&mut client, 1).await;
    assert_eq!(
        rig.backend.recorder.events(),
        [moved_over(65535, 65535, desk_view(2))],
        "with the view of the picture the viewer sees: screen 2's corner"
    );
    desk.release.store(true, Ordering::SeqCst);
    let (back, at) = said(&answer_to(&mut client, 3).await);
    assert_eq!((back.status, back.shown, back.remapped), (OK, 1, true));
    let data = the_picture_at(&mut client, at).await;
    assert_eq!(Decoded::new().picture(&data).1, (320, 192));
    let report = close_and_report(&mut client, served).await;
    assert_eq!((report.monitor_requests, report.monitor_switches), (3, 2));
}

/// Session test 11, a source that switches and then gives no picture (a
/// still Wayland screen whose first picture never comes, GDI while a secure
/// screen shows): the host answers `FAILED` at `switch_answer`, saying the
/// screen it still shows, and input keeps that screen's view. When the
/// picture comes late it is the host's news (request 0, `REMAPPED`) right
/// before it, and the barrier holds back what was made against the screen
/// before until the viewer acknowledges it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_switch_with_no_picture_in_time_is_failed_and_its_late_picture_is_news() {
    let within = Duration::from_millis(500);
    let limits = MediaLimits {
        switch_answer: within,
        ..MediaLimits::default()
    };
    let (rig, desk) = desk_rig(&[(320, 192), (256, 128)], limits);
    desk.still();
    desk.damage(1);
    let (_, binding) = start(&rig.host, 83, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    assert!(matches!(
        next_acking(&mut client).await,
        Msg::Video { seq: 0, .. }
    ));

    let asked = tokio::time::Instant::now();
    ask(&mut client, 1, 0, 2).await;
    let (failed, _) = said(&answer_to(&mut client, 1).await);
    let took = asked.elapsed();
    assert_eq!(
        failed,
        Said {
            request: 1,
            status: FAILED,
            shown: 1,
            all: true,
            remapped: false,
            list: 0,
            n: 2
        }
    );
    assert!(
        took >= within && took < within + Duration::from_secs(2),
        "answered after {took:?}"
    );
    assert_eq!(desk.asked(), [Selection::Monitor(2)], "the source took it");
    let corner = InputEvent::PointerMove { x: 65535, y: 65535 };
    send_input(&mut client, &[corner]).await;
    sync(&mut client, 1).await;
    let before = moved_over(65535, 65535, desk_view(1));
    assert_eq!(rig.backend.recorder.events(), [before], "screen 1's view");

    desk.damage(1);
    let (news, at) = said(&next_monitors(&mut client).await);
    assert_eq!(
        news,
        Said {
            request: 0,
            status: OK,
            shown: 2,
            all: true,
            remapped: true,
            list: 0,
            n: 2
        },
        "the late picture is news"
    );
    let data = the_picture_at(&mut client, at).await;
    assert_eq!(Decoded::new().picture(&data).1, (256, 128));
    send_input(&mut client, &[corner, LEFT_DOWN]).await;
    sync(&mut client, 2).await;
    assert_eq!(rig.backend.recorder.events(), [before], "held back");
    write_msg(&mut client, &Msg::VideoAck { seq: at })
        .await
        .unwrap();
    send_input(&mut client, &[corner]).await;
    sync(&mut client, 3).await;
    assert_eq!(
        rig.backend.recorder.events(),
        [before, moved_over(65535, 65535, desk_view(2))]
    );
    let report = close_and_report(&mut client, served).await;
    assert_eq!(
        (
            report.monitor_requests,
            report.monitor_switches,
            report.input_held_back
        ),
        (1, 0, 2)
    );
}

/// Session test 12: a flood of 100 `SelectMonitor`s gets at most the
/// budget's answers (burst 4, then 2 a second over the time the host took to
/// read them): the first is accepted and answered with its picture, the
/// next few `BUSY`, the rest ignored; pictures keep flowing all the while.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_of_select_monitor_gets_at_most_the_budgets_answers() {
    let rig = screens_rig(&TEST_SCREENS, 30, MediaLimits::default());
    let (_, binding) = start(&rig.host, 84, SessionMode::ViewOnly);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;

    let flooded = tokio::time::Instant::now();
    for request in 1..=100 {
        ask(&mut client, request, 0, 2).await;
    }
    // Its `Pong` comes once the host has handled all 100.
    write_msg(&mut client, &Msg::Ping { nonce: 7 })
        .await
        .unwrap();
    let until = flooded + Duration::from_millis(1500);
    let mut answers = Vec::new();
    let mut handled = None;
    let mut pictures = 0;
    loop {
        let read = tokio::time::timeout_at(until, next_acking(&mut client)).await;
        match read {
            Ok(msg @ Msg::Monitors { .. }) if said(&msg).0.request != 0 => {
                answers.push(said(&msg).0);
            }
            Ok(Msg::Video { .. }) => pictures += 1,
            Ok(Msg::Pong { nonce: 7 }) => handled = Some(flooded.elapsed()),
            Ok(_) => {}
            Err(_) if handled.is_some() => break,
            Err(_) => panic!("the host did not handle the flood in time"),
        }
    }
    let handled = handled.unwrap();
    let budget = 4 + (2.0 * handled.as_secs_f64()).ceil() as usize;
    assert!(
        !answers.is_empty() && answers.len() <= budget,
        "{} answers for a budget of {budget} (read in {handled:?}): {answers:?}",
        answers.len()
    );
    let mut requests: Vec<u16> = answers.iter().map(|a| a.request).collect();
    requests.sort_unstable();
    requests.dedup();
    assert_eq!(requests.len(), answers.len(), "one answer per request");
    for answer in &answers {
        if answer.request == 1 {
            assert_eq!(
                (answer.status, answer.shown, answer.remapped),
                (OK, 2, true)
            );
        } else {
            // BUSY while the first is under way or within the interval; a
            // request the budget let through after the first was answered
            // asks for the screen shown, a no-op.
            assert!(
                !answer.remapped
                    && (answer.status == BUSY || (answer.status == OK && answer.shown == 2)),
                "{answer:?}"
            );
        }
    }
    assert!(answers.iter().any(|a| a.request == 1), "the first accepted");
    assert!(pictures >= 8, "pictures kept flowing: {pictures}");
    let report = close_and_report(&mut client, served).await;
    assert_eq!((report.monitor_requests, report.monitor_switches), (100, 1));
}

/// Session test 13: the observer (the sharing indicator) hears where the
/// pictures lie at the first picture (H1) and at each change of screen the
/// viewer asks for, with the rectangle shown: screen 2, all screens (the
/// whole desktop, screen 0), screen 1 again; a no-op says nothing. The
/// injector follows each view in turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_indicator_hears_each_screen_shown() {
    let limits = MediaLimits {
        switch_interval: Duration::from_millis(200),
        ..MediaLimits::default()
    };
    let rig = screens_rig(&TEST_SCREENS, 30, limits);
    let (_, binding) = start(&rig.host, 85, SessionMode::Control);
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    for (request, monitor, remapped) in [
        (1, 2, true),
        (2, tornect_proto::ALL_MONITORS, true),
        (3, 1, true),
        (4, 1, false),
    ] {
        ask(&mut client, request, 0, monitor).await;
        let (answer, _) = said(&answer_to(&mut client, request).await);
        assert_eq!(
            (answer.status, answer.shown, answer.remapped),
            (OK, monitor, remapped)
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let report = close_and_report(&mut client, served).await;
    assert_eq!((report.monitor_requests, report.monitor_switches), (4, 3));
    let views: Vec<View> = rig.backend.recorder.views().iter().map(|v| v.1).collect();
    assert_eq!(
        views,
        [
            two_screens(Selection::Monitor(1)).view,
            two_screens(Selection::Monitor(2)).view,
            two_screens(Selection::All).view,
            two_screens(Selection::Monitor(1)).view,
        ]
    );
    assert_eq!(
        rig.seen.lines(),
        [
            "started synthetic screens 1280x720 Control input=true",
            "changed screen=1 of=2 all=false shown=1280x720+0+0 input=true",
            "changed screen=2 of=2 all=false shown=1024x768+1280+0 input=true",
            "changed screen=0 of=2 all=true shown=2304x768+0+0 input=true",
            "changed screen=1 of=2 all=false shown=1280x720+0+0 input=true",
            "stopped ViewerLeft",
        ]
    );
}

/// What a viewer's sink heard, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Heard {
    /// A picture: its seq, size and test card index.
    Picture {
        seq: u32,
        size: (u32, u32),
        index: Option<u32>,
    },
    /// The host's screens, and why the sink heard them.
    Screens(Screens, ScreensNews),
}

/// A sink that says each picture and each screens hook as a [`Heard`].
struct Hears(tokio::sync::mpsc::UnboundedSender<Heard>);

impl FrameSink for Hears {
    fn picture(&mut self, seq: u32, frame: &DecodedFrame) {
        let _ = self.0.send(Heard::Picture {
            seq,
            size: (frame.width, frame.height),
            index: TestCard::read_index(&frame.rgba, frame.width, frame.height),
        });
    }

    fn screens(&mut self, screens: &Screens, news: ScreensNews) {
        let _ = self.0.send(Heard::Screens(screens.clone(), news));
    }
}

/// The next screens hook, past any picture, within [`WAIT`].
async fn next_screens(
    heard: &mut tokio::sync::mpsc::UnboundedReceiver<Heard>,
) -> (Screens, ScreensNews) {
    let since = tokio::time::Instant::now();
    loop {
        in_time(since, "a screens hook");
        match tokio::time::timeout(WAIT, heard.recv())
            .await
            .expect("a hook in time")
            .expect("the viewer runs")
        {
            Heard::Screens(screens, news) => return (screens, news),
            Heard::Picture { .. } => {}
        }
    }
}

/// The test screens as a host lists them: 1280×720 (main) and 1024×768 to
/// its right.
fn listed() -> Vec<tornect_proto::MonitorEntry> {
    vec![
        tornect_proto::MonitorEntry::saturating(true, 0, 0, 1280, 720),
        tornect_proto::MonitorEntry::saturating(false, 1280, 0, 1024, 768),
    ]
}

/// A scripted host's `Monitors` over [`listed`], with "all" offered.
fn monitors_msg(request: u16, status: u8, shown: u8, list: u16, seq: u32, remapped: bool) -> Msg {
    Msg::Monitors {
        request,
        status,
        shown,
        all: true,
        remapped,
        list,
        seq,
        monitors: listed(),
    }
}

/// What a viewer that heard `msg`, a `Monitors`, knows of the screens.
fn screens_of(msg: &Msg) -> Screens {
    let Msg::Monitors {
        shown,
        all,
        remapped,
        list,
        seq,
        monitors,
        ..
    } = msg
    else {
        panic!("not a Monitors: {msg:?}");
    };
    Screens {
        monitors: monitors.clone(),
        all: *all,
        shown: *shown,
        list: *list,
        seq: *seq,
        remapped: *remapped,
    }
}

/// Bind a viewer over a pipe to a scripted host and run it with `requests`
/// and no input, into [`Hears`]: the host's end past `BindOk`, what the sink
/// hears, and the run.
async fn run_viewer_asking(
    requests: tokio::sync::mpsc::Receiver<ViewerRequest>,
) -> (
    DuplexStream,
    tokio::sync::mpsc::UnboundedReceiver<Heard>,
    ViewerRun,
) {
    let binding = Binding::new(&SessionToken::new([9; 32]), &[9; 32]);
    let (client, mut host) = duplex(1 << 16);
    let (tx, heard) = tokio::sync::mpsc::unbounded_channel();
    let viewer = tokio::spawn(async move {
        let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
        let (mut sink, mut stats) = (Hears(tx), ViewerStats::default());
        let channels = ViewerChannels {
            input: None,
            requests: Some(requests),
        };
        let end = viewer
            .run_with(&mut sink, &mut stats, channels, std::future::pending())
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
        mode: 1,
        quality: APPLIED,
    };
    write_msg(&mut host, &bind_ok).await.unwrap();
    (host, heard, viewer)
}

/// The viewer's next frame to the scripted host `host` past its pings,
/// within [`WAIT`].
async fn next_from_viewer(host: &mut DuplexStream) -> Msg {
    let since = tokio::time::Instant::now();
    loop {
        in_time(since, "a frame from the viewer");
        match tokio::time::timeout(WAIT, read_msg(host))
            .await
            .expect("a frame in time")
            .unwrap()
            .expect("the viewer's stream is open")
        {
            Msg::Ping { .. } => {}
            other => return other,
        }
    }
}

/// For `quiet`, the viewer writes nothing to the scripted host `host` but
/// its pings.
async fn only_pings_for(host: &mut DuplexStream, quiet: Duration) {
    let until = tokio::time::Instant::now() + quiet;
    while let Ok(msg) = tokio::time::timeout_at(until, read_msg(host)).await {
        let msg = msg.unwrap();
        assert!(matches!(msg, Some(Msg::Ping { .. })), "{msg:?}");
    }
}

/// End a scripted host's stream with `Close{ENDED_BY_HOST}`: what the
/// viewer received.
async fn close_viewer(mut host: DuplexStream, viewer: ViewerRun) -> ViewerStats {
    let close = Msg::Close {
        reason: reason::ENDED_BY_HOST,
    };
    write_msg(&mut host, &close).await.unwrap();
    let (end, stats) = viewer.await.unwrap();
    assert!(
        matches!(end, Ok(ViewerEnd::Host(r)) if r == reason::ENDED_BY_HOST),
        "{end:?}"
    );
    stats
}

/// The monitors design's V1 and test 14: a request made before the host
/// listed its monitors waits for the first `Monitors` (a host that lists
/// none is never asked), then goes as a `SelectMonitor` naming that list,
/// with request id 1. The sink hears the list as the host's news, with its
/// seq.
#[tokio::test(start_paused = true)]
async fn a_viewers_request_waits_for_the_first_monitors_and_names_its_list() {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(ViewerRequest::ShowScreen(2)).await.unwrap();
    let (mut host, mut heard, viewer) = run_viewer_asking(rx).await;
    only_pings_for(&mut host, Duration::from_secs(3)).await;
    let first = monitors_msg(0, OK, 1, 7, 0, false);
    write_msg(&mut host, &first).await.unwrap();
    assert_eq!(
        next_screens(&mut heard).await,
        (screens_of(&first), ScreensNews::Layout)
    );
    assert_eq!(
        next_from_viewer(&mut host).await,
        Msg::SelectMonitor {
            request: 1,
            list: 7,
            monitor: 2,
        }
    );
    let stats = close_viewer(host, viewer).await;
    assert_eq!((stats.monitor_requests, stats.screens_received), (1, 1));
}

/// The monitors design's V1, V2 and test 14: one request waits for its
/// answer at a time, and one made meanwhile is not sent (`NotSent`); the
/// answer, the `Monitors` that carries the request's id, clears it and
/// reaches the sink with its status, its seq and REMAPPED; the next request
/// takes the next id and names the newest list; a refusal is an answer too;
/// an id no list can hold is answered UNKNOWN unsent.
#[tokio::test(start_paused = true)]
async fn one_request_waits_for_its_answer_at_a_time() {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let (mut host, mut heard, viewer) = run_viewer_asking(rx).await;
    let first = monitors_msg(0, OK, 1, 7, 0, false);
    write_msg(&mut host, &first).await.unwrap();
    assert_eq!(next_screens(&mut heard).await.1, ScreensNews::Layout);

    tx.send(ViewerRequest::ShowScreen(2)).await.unwrap();
    assert_eq!(
        next_from_viewer(&mut host).await,
        Msg::SelectMonitor {
            request: 1,
            list: 7,
            monitor: 2,
        }
    );
    tx.send(ViewerRequest::ShowScreen(tornect_proto::ALL_MONITORS))
        .await
        .unwrap();
    assert_eq!(
        next_screens(&mut heard).await,
        (
            screens_of(&first),
            ScreensNews::NotSent {
                asked: tornect_proto::ALL_MONITORS
            }
        )
    );
    only_pings_for(&mut host, Duration::from_secs(2)).await;

    let answer = monitors_msg(1, OK, 2, 7, 41, true);
    write_msg(&mut host, &answer).await.unwrap();
    let (screens, news) = next_screens(&mut heard).await;
    assert_eq!(
        news,
        ScreensNews::Answer {
            asked: 2,
            status: OK
        }
    );
    assert_eq!(
        (screens.shown, screens.seq, screens.remapped),
        (2, 41, true)
    );
    assert_eq!(screens, screens_of(&answer));

    tx.send(ViewerRequest::ShowScreen(tornect_proto::ALL_MONITORS))
        .await
        .unwrap();
    assert_eq!(
        next_from_viewer(&mut host).await,
        Msg::SelectMonitor {
            request: 2,
            list: 7,
            monitor: tornect_proto::ALL_MONITORS,
        }
    );
    let busy = monitors_msg(2, tornect_proto::monitor_status::BUSY, 2, 7, 42, false);
    write_msg(&mut host, &busy).await.unwrap();
    assert_eq!(
        next_screens(&mut heard).await,
        (
            screens_of(&busy),
            ScreensNews::Answer {
                asked: tornect_proto::ALL_MONITORS,
                status: tornect_proto::monitor_status::BUSY,
            }
        )
    );

    tx.send(ViewerRequest::ShowScreen(17)).await.unwrap();
    assert_eq!(
        next_screens(&mut heard).await,
        (
            screens_of(&busy),
            ScreensNews::Answer {
                asked: 17,
                status: tornect_proto::monitor_status::UNKNOWN,
            }
        )
    );
    only_pings_for(&mut host, Duration::from_secs(2)).await;

    let news = monitors_msg(0, OK, 2, 8, 60, false);
    write_msg(&mut host, &news).await.unwrap();
    assert_eq!(
        next_screens(&mut heard).await,
        (screens_of(&news), ScreensNews::Layout)
    );
    tx.send(ViewerRequest::ShowScreen(1)).await.unwrap();
    assert_eq!(
        next_from_viewer(&mut host).await,
        Msg::SelectMonitor {
            request: 3,
            list: 8,
            monitor: 1,
        }
    );
    let stats = close_viewer(host, viewer).await;
    assert_eq!((stats.monitor_requests, stats.screens_received), (3, 4));
}

/// The monitors design's V3 and test 14: a request with no answer in
/// `SWITCH_WAIT` is given up (`NoAnswer`, not a moment before), its late
/// answer is the host's news, and the next request may go.
#[tokio::test(start_paused = true)]
async fn a_request_unanswered_in_switch_wait_is_given_up_and_its_late_answer_is_news() {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let (mut host, mut heard, viewer) = run_viewer_asking(rx).await;
    let first = monitors_msg(0, OK, 1, 0, 0, false);
    write_msg(&mut host, &first).await.unwrap();
    assert_eq!(next_screens(&mut heard).await.1, ScreensNews::Layout);
    tx.send(ViewerRequest::ShowScreen(2)).await.unwrap();
    assert!(matches!(
        next_from_viewer(&mut host).await,
        Msg::SelectMonitor { request: 1, .. }
    ));
    let asked_at = tokio::time::Instant::now();
    // The viewer pings meanwhile; the pipe holds them all.
    assert!(
        tokio::time::timeout(SWITCH_WAIT - Duration::from_millis(100), heard.recv())
            .await
            .is_err(),
        "a hook before SWITCH_WAIT"
    );
    assert_eq!(
        next_screens(&mut heard).await,
        (screens_of(&first), ScreensNews::NoAnswer { asked: 2 })
    );
    assert!(asked_at.elapsed() >= SWITCH_WAIT);

    let late = monitors_msg(1, OK, 2, 0, 400, true);
    write_msg(&mut host, &late).await.unwrap();
    assert_eq!(
        next_screens(&mut heard).await,
        (screens_of(&late), ScreensNews::Layout)
    );
    tx.send(ViewerRequest::ShowScreen(1)).await.unwrap();
    assert_eq!(
        next_from_viewer(&mut host).await,
        Msg::SelectMonitor {
            request: 2,
            list: 0,
            monitor: 1,
        }
    );
    let stats = close_viewer(host, viewer).await;
    assert_eq!((stats.monitor_requests, stats.screens_received), (2, 2));
}

/// Test 14 against the real host: a view-only viewer asks for screen 2,
/// then for all screens, of a host sharing the test screens. Each answer
/// reaches its sink right before the first picture of the new screen,
/// REMAPPED, with that picture's seq: every picture before it has the
/// earlier screen's size, every one from it the new size (all screens
/// fitted to Balanced), and the card's index counts on across both
/// switches.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_switches_the_hosts_screens_and_its_pictures_follow() {
    let limits = MediaLimits {
        switch_interval: Duration::from_millis(200),
        ..MediaLimits::default()
    };
    let rig = screens_rig(&TEST_SCREENS, 30, limits);
    let (_, binding) = start(&rig.host, 86, SessionMode::ViewOnly);
    let (client, served) = connect(&rig.host);
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(ViewerRequest::ShowScreen(2)).await.unwrap();
    let (heard_tx, mut heard) = tokio::sync::mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let viewer = tokio::spawn(async move {
        let viewer = MediaViewer::bind(client, &binding, WAIT).await.unwrap();
        let (mut sink, mut stats) = (Hears(heard_tx), ViewerStats::default());
        let channels = ViewerChannels {
            input: None,
            requests: Some(rx),
        };
        let end = viewer
            .run_with(&mut sink, &mut stats, channels, async {
                let _ = stop_rx.await;
            })
            .await;
        (end, stats)
    });

    let mut seen: Vec<(u32, (u32, u32), Option<u32>)> = Vec::new();
    let mut answers: Vec<Screens> = Vec::new();
    let since = tokio::time::Instant::now();
    while answers.len() < 2
        || !seen
            .iter()
            .any(|&(seq, _, _)| seq_after(seq, answers[1].seq, 3))
    {
        in_time(since, "both switches");
        match tokio::time::timeout(WAIT, heard.recv())
            .await
            .expect("a hook in time")
            .expect("the viewer runs")
        {
            Heard::Picture { seq, size, index } => seen.push((seq, size, index)),
            Heard::Screens(screens, ScreensNews::Layout) => {
                assert!(answers.is_empty(), "news after a switch: {screens:?}");
                assert_eq!(
                    (screens.shown, screens.seq, screens.remapped),
                    (1, 0, false)
                );
                assert_eq!(screens.monitors, listed());
            }
            Heard::Screens(screens, ScreensNews::Answer { asked, status }) => {
                assert_eq!((status, screens.shown, screens.remapped), (OK, asked, true));
                answers.push(screens);
                if answers.len() == 1 {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    tx.send(ViewerRequest::ShowScreen(tornect_proto::ALL_MONITORS))
                        .await
                        .unwrap();
                }
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    let _ = stop_tx.send(());
    let (end, stats) = viewer.await.unwrap();
    assert_eq!(end.unwrap(), ViewerEnd::Stopped);
    served.await.unwrap();
    assert_eq!(stats.monitor_requests, 2);

    let all = fitted(QualityPreset::Balanced, 2304, 768);
    for &(seq, size, _) in &seen {
        let want = if seq_reached(seq, answers[1].seq) {
            all
        } else if seq_reached(seq, answers[0].seq) {
            (1024, 768)
        } else {
            (1280, 720)
        };
        assert_eq!(size, want, "picture {seq} of {seen:?}");
    }
    for (screens, size) in answers.iter().zip([(1024, 768), all]) {
        assert!(
            seen.iter()
                .any(|&(seq, s, _)| seq == screens.seq && s == size),
            "no picture {} of {size:?}: {seen:?}",
            screens.seq
        );
    }
    let indices: Vec<u32> = seen.iter().filter_map(|&(_, _, index)| index).collect();
    for pair in indices.windows(2) {
        assert!(pair[1] > pair[0], "{indices:?}");
    }
}

/// Whether `seq` is at least `n` past `target`.
fn seq_after(seq: u32, target: u32, n: u32) -> bool {
    seq_reached(seq, target.wrapping_add(n))
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
    session.send_tor_fallback(None).await.unwrap();

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
    session.send_tor_fallback(None).await.unwrap();
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

/// What the services stream of the session [`start`] registers with `seed`
/// binds with (the services design §3.3).
fn services_mac(seed: u8) -> [u8; 32] {
    tornect_proto::services::services_bind_mac(&[seed; 32], &[!seed; 32])
}

/// A `Bind` on the media port for the session [`start`] registers with
/// `seed`, carrying `mac`.
fn media_bind_with(seed: u8, mac: [u8; 32]) -> Msg {
    Msg::Bind {
        session_id: SessionToken::new([seed; 32]).session_id(),
        mac,
        quality: quality::BALANCED,
    }
}

/// The services design §3.3 and §6.2: a services stream binds once per
/// session, under the services MAC alone, with nothing waited for. An
/// unknown session, the media MAC, a MAC over another transcript and a
/// second bind are refused, and none of them burns the session's services
/// or its media stream; the services MAC on the media port is refused too,
/// and burns neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_services_stream_binds_once_under_its_own_mac() {
    let rig = rig(MediaLimits::default());
    let (id, binding) = start(&rig.host, 81, SessionMode::Control);
    let (token, th_final) = ([81; 32], [!81; 32]);

    // Never registered: refused at once, nothing waits for it.
    let unknown = SessionToken::new([82; 32]).session_id();
    assert!(
        rig.host
            .claim_services(&unknown, &services_mac(82))
            .is_none()
    );
    // The media MAC, and the services MAC over another transcript.
    let media = tornect_proto::bind_mac(&token, &th_final);
    assert!(rig.host.claim_services(&id, &media).is_none());
    let forged = tornect_proto::services::services_bind_mac(&token, &[0; 32]);
    assert!(rig.host.claim_services(&id, &forged).is_none());

    // The services MAC on the media port: refused, nothing captured.
    let (mut client, served) = connect(&rig.host);
    write_msg(&mut client, &media_bind_with(81, services_mac(81)))
        .await
        .unwrap();
    assert!(matches!(
        read_msg(&mut client).await.unwrap(),
        Some(Msg::BindRefused { reason: r }) if r == reason::BAD_BIND
    ));
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
    assert_eq!(rig.backend.sources.load(Ordering::SeqCst), 0);

    // None of that burned the services: the right MAC binds, with the
    // session's signed mode and label, before capture is live.
    let claim = rig
        .host
        .claim_services(&id, &services_mac(81))
        .expect("the services stream binds");
    assert_eq!(claim.mode, SessionMode::Control);
    assert_eq!(claim.label, "Laptop");
    assert_eq!(*claim.end.borrow(), None);
    assert_eq!(*claim.capture.borrow(), CaptureState::Pending);
    // Once only.
    assert!(rig.host.claim_services(&id, &services_mac(81)).is_none());

    // Nor did the services bind take the media stream's.
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_video(&mut client).await;
    assert!(rig.host.claim_services(&id, &services_mac(81)).is_none());
    drop(client);
    assert!(matches!(served.await.unwrap(), MediaOutcome::Served { .. }));
    assert_eq!(*claim.capture.borrow(), CaptureState::Stopped);
}

/// A killed session binds no services stream before the FSM ends it, and
/// an ended one none at all; a services stream bound before hears the end
/// (`end` set), and with no media stream bound its capture channel closes,
/// which the services host reads as `Stopped` (the services design §6.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_killed_or_ended_session_binds_no_services_stream() {
    let rig = rig(MediaLimits::default());
    let kill = tornect_signal::fsm::host::KillSwitch::new();
    let watcher = rig.host.watch_kill(kill.clone());
    let (killed, _) = start(&rig.host, 83, SessionMode::Control);
    let (ended, _) = start(&rig.host, 84, SessionMode::ViewOnly);
    let mut before = rig.host.claim_services(&ended, &services_mac(84)).unwrap();
    assert_eq!(before.mode, SessionMode::ViewOnly);

    kill.kill(bye::PANIC);
    let deadline = tokio::time::Instant::now() + WAIT;
    while before.end.borrow().is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the kill was not heard"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(*before.end.borrow_and_update(), Some(reason::ENDED_BY_HOST));
    assert_eq!(rig.host.live(), 2, "the FSM has not ended either yet");
    assert!(
        rig.host
            .claim_services(&killed, &services_mac(83))
            .is_none()
    );

    rig.host
        .on_end(&ended, Some(&SessionEnd::Killed(bye::PANIC)));
    rig.host.on_end(&killed, None);
    assert!(
        rig.host
            .claim_services(&killed, &services_mac(83))
            .is_none()
    );
    assert!(
        before.capture.has_changed().is_err(),
        "the capture channel of an ended session closes"
    );
    assert_eq!(
        *before.capture.borrow(),
        CaptureState::Pending,
        "never live"
    );
    watcher.abort();
}

/// Records the capture state its session's services stream would read as
/// the indicator hears capture start and stop.
#[derive(Default)]
struct CaptureAt {
    capture: Mutex<Option<tokio::sync::watch::Receiver<CaptureState>>>,
    saw: Mutex<Vec<String>>,
}

impl CaptureAt {
    fn note(&self, what: &str) {
        let state = self.capture.lock().unwrap().as_ref().map(|c| *c.borrow());
        self.saw.lock().unwrap().push(format!("{what} {state:?}"));
    }
}

impl MediaObserver for CaptureAt {
    fn capture_started(&self, _: &CaptureStarted<'_>) {
        self.note("started");
    }

    fn capture_stopped(&self, _: &str, _: &MediaReport, _: &MediaEnd) {
        self.note("stopped");
    }
}

/// The media half of the services design's test 3 (§2.2, §6.2): a session
/// is `Pending` until its first picture, `Live` before the indicator hears
/// capture start, and `Stopped` before it hears capture stop, which the
/// services host turns into `Close{CAPTURE_STOPPED}`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_is_live_from_the_first_picture_and_stopped_before_the_indicator_hears() {
    let backend = Arc::new(TestBackend::default());
    let observer = Arc::new(CaptureAt::default());
    let host = Arc::new(MediaHost::new(
        backend,
        observer.clone(),
        MediaLimits::default(),
    ));
    let (id, binding) = start(&host, 85, SessionMode::Control);
    let claim = host.claim_services(&id, &services_mac(85)).unwrap();
    *observer.capture.lock().unwrap() = Some(claim.capture.clone());
    assert_eq!(*claim.capture.borrow(), CaptureState::Pending);

    let (mut client, served) = connect(&host);
    bind_raw(&mut client, &binding).await;
    next_video(&mut client).await;
    assert_eq!(*claim.capture.borrow(), CaptureState::Live { input: true });
    drop(client);
    served.await.unwrap();
    assert_eq!(*claim.capture.borrow(), CaptureState::Stopped);
    assert_eq!(
        *observer.saw.lock().unwrap(),
        [
            "started Some(Live { input: true })",
            "stopped Some(Stopped)"
        ]
    );
    // Final: the session is still registered, and nothing makes it live
    // again (its media stream is single-use).
    assert_eq!(host.live(), 1);
    let (late, served) = connect(&host);
    assert!(MediaViewer::bind(late, &binding, WAIT).await.is_err());
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
    assert_eq!(*claim.capture.borrow(), CaptureState::Stopped);
}

/// `Live { input }` is the media layer's own fact (the services design
/// §2.1): an injector was built for the session. A view-only session and a
/// control session with nothing to inject into are live without input; a
/// control session whose injector cannot follow the picture loses it
/// (`INPUT_LOST`) and never gets it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_says_whether_the_viewers_input_reaches_the_desktop() {
    async fn live_of(rig: &Rig, seed: u8, mode: SessionMode) -> CaptureState {
        let (id, binding) = start(&rig.host, seed, mode);
        let claim = rig.host.claim_services(&id, &services_mac(seed)).unwrap();
        let (mut client, served) = connect(&rig.host);
        bind_raw(&mut client, &binding).await;
        next_video(&mut client).await;
        let live = *claim.capture.borrow();
        drop(client);
        served.await.unwrap();
        assert_eq!(*claim.capture.borrow(), CaptureState::Stopped);
        live
    }
    let rig = rig(MediaLimits::default());
    assert_eq!(
        live_of(&rig, 86, SessionMode::ViewOnly).await,
        CaptureState::Live { input: false }
    );
    assert_eq!(
        live_of(&rig, 87, SessionMode::Control).await,
        CaptureState::Live { input: true }
    );
    let rig = rig_with(
        TestBackend {
            no_injector: true,
            ..TestBackend::default()
        },
        MediaLimits::default(),
    );
    assert_eq!(
        live_of(&rig, 88, SessionMode::Control).await,
        CaptureState::Live { input: false }
    );

    // INPUT_LOST mid-session.
    let (rig, layout) = shifting_rig(two_screens(Selection::Monitor(1)));
    let (id, binding) = start(&rig.host, 89, SessionMode::Control);
    let claim = rig.host.claim_services(&id, &services_mac(89)).unwrap();
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_monitors(&mut client).await;
    assert_eq!(*claim.capture.borrow(), CaptureState::Live { input: true });
    rig.backend.recorder.refuses.store(true, Ordering::SeqCst);
    *layout.lock().unwrap() = two_screens(Selection::Monitor(2));
    next_monitors(&mut client).await;
    assert_eq!(*claim.capture.borrow(), CaptureState::Live { input: false });
    // Back on the first screen, with an injector that would follow again:
    // the input stays lost.
    rig.backend.recorder.refuses.store(false, Ordering::SeqCst);
    *layout.lock().unwrap() = two_screens(Selection::Monitor(1));
    next_monitors(&mut client).await;
    sync(&mut client, 1).await;
    assert_eq!(*claim.capture.borrow(), CaptureState::Live { input: false });
    drop(client);
    served.await.unwrap();
    assert_eq!(*claim.capture.borrow(), CaptureState::Stopped);
}

/// Capture that never starts ends `Pending` as `Stopped`, never `Live`:
/// a source that fails to open, and a session that ends while its source
/// opens (the media stream returns before its first picture).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_that_never_starts_is_stopped_without_being_live() {
    let rig = rig_with(
        TestBackend {
            fail: true,
            ..TestBackend::default()
        },
        MediaLimits::default(),
    );
    let (id, binding) = start(&rig.host, 90, SessionMode::Control);
    let claim = rig.host.claim_services(&id, &services_mac(90)).unwrap();
    let (mut client, served) = connect(&rig.host);
    write_msg(&mut client, &binding.msg()).await.unwrap();
    assert!(matches!(served.await.unwrap(), MediaOutcome::NotStarted(_)));
    assert_eq!(*claim.capture.borrow(), CaptureState::Stopped);
    assert!(
        rig.seen.lines().is_empty(),
        "no capture started or stopped: {:?}",
        rig.seen.lines()
    );

    let rig = rig_with(
        TestBackend {
            open_waits: true,
            ..TestBackend::default()
        },
        MediaLimits::default(),
    );
    let (id, binding) = start(&rig.host, 91, SessionMode::Control);
    let claim = rig.host.claim_services(&id, &services_mac(91)).unwrap();
    let (mut client, served) = connect(&rig.host);
    write_msg(&mut client, &binding.msg()).await.unwrap();
    let deadline = tokio::time::Instant::now() + WAIT;
    while rig.backend.sources.load(Ordering::SeqCst) == 0 {
        assert!(tokio::time::Instant::now() < deadline, "no open started");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(*claim.capture.borrow(), CaptureState::Pending);
    rig.host.on_end(&id, None);
    assert!(matches!(
        tokio::time::timeout(WAIT, served).await.unwrap().unwrap(),
        MediaOutcome::NotStarted(_)
    ));
    assert_eq!(*claim.capture.borrow(), CaptureState::Stopped);
    assert_eq!(*claim.end.borrow(), Some(reason::SESSION_OVER));
}

/// The drop guard (the services design §6.2): a media stream that panics,
/// or whose task is dropped, still says `Stopped`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_media_stream_that_panics_or_is_dropped_says_stopped() {
    /// An indicator that fails at capture start.
    struct Panics;
    impl MediaObserver for Panics {
        fn capture_started(&self, _: &CaptureStarted<'_>) {
            panic!("the indicator failed");
        }
        fn capture_stopped(&self, _: &str, _: &MediaReport, _: &MediaEnd) {}
    }
    let host = Arc::new(MediaHost::new(
        Arc::new(TestBackend::default()),
        Arc::new(Panics),
        MediaLimits::default(),
    ));
    let (id, binding) = start(&host, 92, SessionMode::Control);
    let claim = host.claim_services(&id, &services_mac(92)).unwrap();
    let (mut client, served) = connect(&host);
    write_msg(&mut client, &binding.msg()).await.unwrap();
    let panicked = tokio::time::timeout(WAIT, served).await.unwrap();
    assert!(panicked.unwrap_err().is_panic());
    assert_eq!(*claim.capture.borrow(), CaptureState::Stopped);

    let rig = rig(MediaLimits::default());
    let (id, binding) = start(&rig.host, 93, SessionMode::Control);
    let claim = rig.host.claim_services(&id, &services_mac(93)).unwrap();
    let (mut client, served) = connect(&rig.host);
    bind_raw(&mut client, &binding).await;
    next_video(&mut client).await;
    assert_eq!(*claim.capture.borrow(), CaptureState::Live { input: true });
    served.abort();
    assert!(served.await.unwrap_err().is_cancelled());
    assert_eq!(*claim.capture.borrow(), CaptureState::Stopped);
}
