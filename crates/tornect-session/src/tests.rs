//! The media layer end to end over in-process pipes: the requirements of
//! SLICE-A2 A2-3/A2-4/A2-6 and SLICE-A1 G3, each pinned by a test, and one
//! run through the real handshake FSM.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tornect_capture::{CaptureError, Frame, TestCard, VideoSource};
use tornect_codec::{DecodedFrame, EncoderSettings, H264Encoder};
use tornect_core::session_log::SessionMode;
use tornect_core::{DeviceId, DeviceIdentity, HostIdentity};
use tornect_input::{Button, InputError, InputEvent, InputSink};
use tornect_proto::{Msg, codec, read_msg, reason, video_flags, write_msg};
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

/// A test card that says when it was closed.
struct Card {
    inner: TestCard,
    closed: Arc<AtomicBool>,
}

impl VideoSource for Card {
    fn name(&self) -> &'static str {
        "card"
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        self.inner.next_frame(timeout)
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
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError> {
        self.sources.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(CaptureError::Unavailable("no screen here".into()));
        }
        if self.open_waits && dialog(&cancel) {
            self.cancelled.store(true, Ordering::SeqCst);
            return Err(CaptureError::Unavailable("the session ended".into()));
        }
        *self.input.lock().unwrap() = Some(self.recorder.clone());
        Ok(Box::new(Card {
            // Faster than the encoder's 15 fps, so the encoder sets the pace.
            inner: TestCard::new(256, 96, 60),
            closed: Arc::clone(&self.closed),
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

/// Bind by hand and return `BindOk`'s mode byte.
async fn bind_raw(client: &mut DuplexStream, binding: &Binding) -> u8 {
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
/// blocking pool's delay before the open's first line. (At `312748e` it made
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
