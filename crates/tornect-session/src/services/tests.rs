//! The services streams end to end over in-process pipes (the services
//! design §10, tests 1, 2, 10 and 15 and the close paths of step 12): a real
//! [`MediaHost`] registry, its capture state driven by hand or by a real
//! media stream, a fake desktop clipboard, and a temporary inbox.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf, duplex};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tornect_capture::{CaptureError, TestCard, VideoSource};
use tornect_core::DeviceId;
use tornect_core::levels::Elevation;
use tornect_core::session_log::SessionMode;
use tornect_input::clipboard::{ClipboardLink, DesktopEnds};
use tornect_input::{InputError, InputEvent, InputSink};
use tornect_proto::services::{
    Bind, CHUNK, Cancel, Caps, Chat, ClipStart, ClipSwitch, Complete, Done, Get, List,
    MAX_CHAT_BYTES, MAX_CLIP, MAX_SERVICES_FRAME, Offer, SvcMsg, Welcome, caps, read_body_max,
    read_header, reason, services_bind_mac, ty, write_msg,
};
use tornect_signal::consent::SessionToken;
use tornect_signal::fsm::host::{KillSwitch, LiveSession, SessionSink as _};
use tornect_signal::messages::bye;

use super::*;
use crate::{
    Binding, CaptureState, MediaBackend, MediaHost, MediaLimits, NoObserver, Source, SourceRequest,
    SystemBackend,
};

const WAIT: Duration = Duration::from_secs(10);
const INBOX_WORDS: &str = "Downloads › Tornect";

/// An injector that goes nowhere.
struct Nowhere;

impl InputSink for Nowhere {
    fn inject(&mut self, _: &InputEvent) -> Result<(), InputError> {
        Ok(())
    }
}

/// The desktop: a test card, an injector when `injector`, and clipboard
/// links whose far ends it keeps.
struct Desk {
    injector: bool,
    /// An administrator session's helper does not start: its injector is
    /// `None` (`AdminBackend::open_session_injector`).
    refuse_admin: bool,
    no_clipboard: bool,
    /// `open_clipboard` calls.
    opens: AtomicUsize,
    /// The far ends of the links given out.
    ends: Mutex<Vec<DesktopEnds>>,
    /// The next `open_clipboard` waits for this before it answers.
    hold: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl Default for Desk {
    fn default() -> Self {
        Self {
            injector: true,
            refuse_admin: false,
            no_clipboard: false,
            opens: AtomicUsize::new(0),
            ends: Mutex::new(Vec::new()),
            hold: Mutex::new(None),
        }
    }
}

impl Desk {
    fn opens(&self) -> usize {
        self.opens.load(Ordering::SeqCst)
    }

    /// Whether every link given out was dropped (its backend would stop).
    fn links_dropped(&self) -> bool {
        self.ends
            .lock()
            .unwrap()
            .iter()
            .all(|ends| ends.to_desktop.has_changed().is_err())
    }
}

impl MediaBackend for Desk {
    fn open_source(
        &self,
        _: SourceRequest,
        _: watch::Receiver<bool>,
    ) -> Result<Box<dyn VideoSource>, CaptureError> {
        Ok(Box::new(TestCard::new(256, 96, 30)))
    }

    fn open_injector(&self) -> Option<Box<dyn InputSink>> {
        self.injector
            .then(|| Box::new(Nowhere) as Box<dyn InputSink>)
    }

    fn open_session_injector(&self, _: &str, elevation: Elevation) -> Option<Box<dyn InputSink>> {
        if self.refuse_admin && elevation == Elevation::Admin {
            return None;
        }
        self.open_injector()
    }

    fn open_clipboard(&self, _: &str) -> Option<ClipboardLink> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        let hold = self.hold.lock().unwrap().take();
        if let Some(hold) = hold {
            let _ = hold.recv_timeout(WAIT);
        }
        if self.no_clipboard {
            return None;
        }
        let (link, ends) = ClipboardLink::pair();
        self.ends.lock().unwrap().push(ends);
        Some(link)
    }
}

/// Passes the host's events on, with their session.
struct Heard(mpsc::UnboundedSender<(String, HostEvent)>);

impl ServicesObserver for Heard {
    fn event(&self, session_id: &str, event: HostEvent) {
        let _ = self.0.send((session_id.to_owned(), event));
    }
}

struct Rig {
    media: Arc<MediaHost>,
    services: Arc<ServicesHost>,
    desk: Arc<Desk>,
    heard: mpsc::UnboundedReceiver<(String, HostEvent)>,
    policy: watch::Sender<ServicesPolicy>,
    /// Holds the inbox, `Tornect` in it.
    home: tempfile::TempDir,
}

impl Rig {
    fn inbox(&self) -> PathBuf {
        self.home.path().join("Tornect")
    }

    /// The next event of session `id`, skipping other sessions'.
    async fn event(&mut self, id: &str) -> HostEvent {
        loop {
            let (sid, event) = tokio::time::timeout(WAIT, self.heard.recv())
                .await
                .expect("an event in time")
                .expect("the host is there");
            if sid == id {
                return event;
            }
        }
    }
}

struct Build {
    desk: Desk,
    policy: ServicesPolicy,
    limits: ServicesLimits,
    media: MediaLimits,
    inbox: bool,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            desk: Desk::default(),
            policy: ServicesPolicy::default(),
            limits: ServicesLimits::default(),
            media: MediaLimits::default(),
            inbox: true,
        }
    }
}

fn rig() -> Rig {
    rig_with(Build::default())
}

fn rig_with(build: Build) -> Rig {
    let Build {
        desk,
        policy,
        limits,
        media,
        inbox,
    } = build;
    let desk = Arc::new(desk);
    let media = Arc::new(MediaHost::new(
        Arc::clone(&desk) as Arc<dyn MediaBackend>,
        Arc::new(NoObserver),
        media,
    ));
    rig_on(media, desk, policy, limits, inbox)
}

/// The services of `media`, whose desktop is `desk`.
fn rig_on(
    media: Arc<MediaHost>,
    desk: Arc<Desk>,
    policy: ServicesPolicy,
    limits: ServicesLimits,
    inbox: bool,
) -> Rig {
    let home = tempfile::tempdir().unwrap();
    let (tx, heard) = mpsc::unbounded_channel();
    let (policy, policy_rx) = watch::channel(policy);
    let env = ServicesEnv {
        inbox: inbox.then(|| home.path().join("Tornect")),
        inbox_words: INBOX_WORDS.to_owned(),
    };
    let services = Arc::new(ServicesHost::new(
        Arc::clone(&media),
        Arc::new(Heard(tx)),
        policy_rx,
        env,
        limits,
    ));
    Rig {
        media,
        services,
        desk,
        heard,
        policy,
        home,
    }
}

/// A session as the FSM starts it (services first, as the app's session sink
/// calls them), and what its viewer binds with.
struct Session {
    id: String,
    binding: ServicesBinding,
    media: Binding,
    capture: Arc<watch::Sender<CaptureState>>,
}

impl Session {
    fn live(&self, input: bool) {
        self.capture.send_replace(CaptureState::Live { input });
    }
}

fn start(rig: &Rig, seed: u8, mode: SessionMode) -> Session {
    start_as(rig, seed, mode, Elevation::None)
}

fn start_as(rig: &Rig, seed: u8, mode: SessionMode, elevation: Elevation) -> Session {
    let token = SessionToken::new([seed; 32]);
    let th_final = [!seed; 32];
    let id = token.session_id();
    let live = LiveSession {
        device: DeviceId::from_bytes([seed; 32]),
        label: "Laptop",
        session_id: &id,
        token: &token,
        th_final,
        mode,
        elevation,
        unattended: false,
    };
    rig.services.on_start(&live);
    rig.media.on_start(&live);
    Session {
        capture: rig.media.capture_of(&id).expect("registered"),
        binding: ServicesBinding::new(&token, &th_final),
        media: Binding::new(&token, &th_final),
        id,
    }
}

/// A services stream to `services`, served on its own task.
fn open(services: &Arc<ServicesHost>) -> (DuplexStream, JoinHandle<ServicesOutcome>) {
    let (client, server) = duplex(1 << 20);
    let services = Arc::clone(services);
    (
        client,
        tokio::spawn(async move { services.serve(server).await }),
    )
}

/// The host's next frame within [`WAIT`]; `None` at the end of the stream.
async fn next(client: &mut DuplexStream) -> Option<SvcMsg> {
    let header = tokio::time::timeout(WAIT, read_header(client))
        .await
        .expect("a frame in time")
        .expect("a frame")?;
    let body = read_body_max(client, header, MAX_SERVICES_FRAME)
        .await
        .unwrap();
    Some(SvcMsg::decode(header.ty, &body).expect("a valid frame"))
}

/// Bind `session`'s services and return the host's answer.
async fn bind(client: &mut DuplexStream, session: &Session) -> SvcMsg {
    write_msg(client, &session.binding.msg()).await.unwrap();
    next(client).await.expect("an answer")
}

/// Bind and expect `Welcome`.
async fn welcome(client: &mut DuplexStream, session: &Session) -> Welcome {
    match bind(client, session).await {
        SvcMsg::Welcome(welcome) => welcome,
        other => panic!("expected Welcome, got {other:?}"),
    }
}

fn raw_bind(session_id: &str, mac: [u8; 32]) -> SvcMsg {
    SvcMsg::Bind(Bind {
        session_id: session_id.to_owned(),
        mac,
    })
}

fn chat(text: &str) -> SvcMsg {
    SvcMsg::Chat(Chat { text: text.into() })
}

/// What a served stream's outcome says: its reason and reader counts.
async fn served(task: JoinHandle<ServicesOutcome>) -> (u16, ServicesSummary, ReaderCounts) {
    match tokio::time::timeout(WAIT, task).await.unwrap().unwrap() {
        ServicesOutcome::Served {
            reason,
            summary,
            frames,
            ..
        } => (reason, summary, frames),
        other => panic!("not served: {other:?}"),
    }
}

/// A stream end that counts what its reader took.
struct Counted {
    inner: DuplexStream,
    read: Arc<AtomicUsize>,
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        self.read.fetch_add(n, Ordering::SeqCst);
        polled
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// --- Test 1: binding ------------------------------------------------------

/// The services design's test 1: a services stream binds only a registered
/// session, under the services MAC, once. An unknown session, the media
/// stream's MAC and a second bind get `Refused{BAD_BIND}`, and none of them
/// burns the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_services_stream_binds_its_session_once_under_its_own_mac() {
    let rig = rig();
    let session = start(&rig, 1, SessionMode::Control);
    session.live(true);

    let refused = async |frame: SvcMsg| {
        let (mut client, task) = open(&rig.services);
        write_msg(&mut client, &frame).await.unwrap();
        let answer = next(&mut client).await;
        assert_eq!(task.await.unwrap(), ServicesOutcome::NotBound);
        assert_eq!(next(&mut client).await, None, "closed after the refusal");
        answer
    };
    let bad = Some(SvcMsg::Refused {
        reason: reason::BAD_BIND,
    });
    let unknown = SessionToken::new([2; 32]).session_id();
    assert_eq!(
        refused(raw_bind(&unknown, services_bind_mac(&[2; 32], &[!2; 32]))).await,
        bad
    );
    let media_mac = tornect_proto::bind_mac(&[1; 32], &[!1; 32]);
    assert_eq!(refused(raw_bind(&session.id, media_mac)).await, bad);
    let other_transcript = services_bind_mac(&[1; 32], &[0; 32]);
    assert_eq!(refused(raw_bind(&session.id, other_transcript)).await, bad);

    let (mut client, task) = open(&rig.services);
    let welcome = welcome(&mut client, &session).await;
    assert_eq!(welcome.caps, caps::ALL);
    assert_eq!(rig.services.open_streams(), 1);
    // Once only.
    assert_eq!(refused(session.binding.msg()).await, bad);

    drop(client);
    let (code, _, _) = served(task).await;
    assert_eq!(code, reason::BY_VIEWER);
    assert_eq!(rig.services.open_streams(), 0);
}

/// Test 1: an unbound stream costs the host one `Bind` frame at most (53
/// bytes with its prefix): another prefix is refused after 4 bytes, a frame
/// of the bind's size that is no `Bind` after 53, a bind of no session after
/// 53 whatever follows it; a silent stream is dropped at the bind deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbound_stream_costs_one_bind_frame_at_most() {
    let rig = rig_with(Build {
        media: MediaLimits {
            bind_deadline: Duration::from_millis(300),
            ..MediaLimits::default()
        },
        ..Build::default()
    });
    let costs = async |bytes: &[u8]| {
        let (mut client, server) = duplex(1 << 20);
        let read = Arc::new(AtomicUsize::new(0));
        let counted = Counted {
            inner: server,
            read: Arc::clone(&read),
        };
        let services = Arc::clone(&rig.services);
        let task = tokio::spawn(async move { services.serve(counted).await });
        client.write_all(bytes).await.unwrap();
        assert_eq!(task.await.unwrap(), ServicesOutcome::NotBound);
        (next(&mut client).await, read.load(Ordering::SeqCst))
    };

    let huge = (8u32 << 20).to_be_bytes();
    assert_eq!(
        costs(&huge).await,
        (
            Some(SvcMsg::Refused {
                reason: reason::PROTOCOL
            }),
            4
        )
    );
    let mut not_a_bind = vec![0, 0, 0, 49, ty::CHAT];
    not_a_bind.extend_from_slice(&[b'a'; 48]);
    not_a_bind.extend_from_slice(&[0; 1000]);
    assert_eq!(
        costs(&not_a_bind).await,
        (
            Some(SvcMsg::Refused {
                reason: reason::PROTOCOL
            }),
            53
        )
    );
    let unknown = SessionToken::new([3; 32]).session_id();
    let mut bind = raw_bind(&unknown, [7; 32]).encode();
    assert_eq!(bind.len(), 53);
    bind.extend_from_slice(&[0xff; 4096]);
    assert_eq!(
        costs(&bind).await,
        (
            Some(SvcMsg::Refused {
                reason: reason::BAD_BIND
            }),
            53
        )
    );
    let started = tokio::time::Instant::now();
    assert_eq!(costs(&[]).await, (None, 0));
    assert!(started.elapsed() < WAIT);
}

/// Test 1: nothing is answered before the session's capture is live.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_is_answered_before_capture_is_live() {
    let mut rig = rig();
    let session = start(&rig, 4, SessionMode::Control);
    let (mut client, task) = open(&rig.services);
    write_msg(&mut client, &session.binding.msg())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(400), read_header(&mut client))
            .await
            .is_err(),
        "an answer before capture went live"
    );
    assert_eq!(rig.desk.opens(), 0, "nothing opened before capture is live");
    assert!(!rig.inbox().exists());
    session.live(true);
    let SvcMsg::Welcome(welcome) = next(&mut client).await.unwrap() else {
        panic!("expected Welcome");
    };
    assert_eq!(welcome.caps, caps::ALL);
    assert_eq!(
        rig.event(&session.id).await,
        HostEvent::Opened {
            caps: caps::ALL,
            input: true,
            clipboard_refused: false
        }
    );
    drop(client);
    served(task).await;
}

/// Test 1: capture that stops before it is live, or is not live in time, is
/// `Refused{NOT_LIVE}`; a session that ends first is refused with its end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn services_wait_for_capture_and_no_longer() {
    let rig = rig_with(Build {
        limits: ServicesLimits {
            live_wait: Duration::from_millis(300),
            ..ServicesLimits::default()
        },
        ..Build::default()
    });
    let refused = async |session: &Session, act: &dyn Fn()| {
        let (mut client, task) = open(&rig.services);
        write_msg(&mut client, &session.binding.msg())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        act();
        let answer = next(&mut client).await;
        let outcome = task.await.unwrap();
        assert_eq!(next(&mut client).await, None);
        (answer, outcome)
    };

    let stops = start(&rig, 5, SessionMode::Control);
    let (answer, outcome) = refused(&stops, &|| {
        stops.capture.send_replace(CaptureState::Stopped);
    })
    .await;
    assert_eq!(
        answer,
        Some(SvcMsg::Refused {
            reason: reason::NOT_LIVE
        })
    );
    assert_eq!(
        outcome,
        ServicesOutcome::Refused {
            session_id: stops.id.clone(),
            reason: reason::NOT_LIVE
        }
    );

    let late = start(&rig, 6, SessionMode::Control);
    let (answer, _) = refused(&late, &|| {}).await;
    assert_eq!(
        answer,
        Some(SvcMsg::Refused {
            reason: reason::NOT_LIVE
        })
    );

    let ends = start(&rig, 7, SessionMode::Control);
    let (answer, _) = refused(&ends, &|| rig.media.on_end(&ends.id, None)).await;
    assert_eq!(
        answer,
        Some(SvcMsg::Refused {
            reason: reason::SESSION_OVER
        })
    );

    let kill = KillSwitch::new();
    let watcher = rig.media.watch_kill(kill.clone());
    let killed = start(&rig, 8, SessionMode::Control);
    let (answer, _) = refused(&killed, &|| kill.kill(bye::PANIC)).await;
    assert_eq!(
        answer,
        Some(SvcMsg::Refused {
            reason: reason::ENDED_BY_HOST
        })
    );
    watcher.abort();
    assert_eq!(rig.desk.opens(), 0);
    assert_eq!(rig.services.open_streams(), 0);
}

// --- Test 2: view-only and the input gate ---------------------------------

/// Every frame a viewer sends for a service other than chat.
fn beyond_chat() -> Vec<SvcMsg> {
    vec![
        SvcMsg::ClipSwitch(ClipSwitch { on: true }),
        SvcMsg::ClipStart(ClipStart { seq: 1, len: 5 }),
        SvcMsg::ClipChunk {
            seq: 1,
            offset: 0,
            bytes: b"hello".to_vec().into(),
        },
        SvcMsg::Offer(Offer {
            xfer: 1,
            name: "notes.txt".into(),
            size: 10,
        }),
        SvcMsg::Data {
            xfer: 1,
            offset: 0,
            bytes: vec![1; 10],
        },
        SvcMsg::Done(Done {
            xfer: 1,
            sha256: [0; 32],
        }),
        SvcMsg::List(List {
            req: 1,
            folder: 0,
            from: 0,
        }),
        SvcMsg::Get(Get { xfer: 1, handle: 3 }),
        SvcMsg::Complete(Complete { xfer: 1 }),
        SvcMsg::Credit { xfer: 0, upto: 5 },
        SvcMsg::Cancel(Cancel {
            xfer: 1,
            reason: 15,
        }),
    ]
}

/// Bind sessions of `mode` whose capture is live with `input`, one per frame
/// of [`beyond_chat`]: each gets chat only, and each of those frames ends its
/// stream with `Close{NOT_OFFERED}` before its body is decoded; nothing
/// opens the clipboard and nothing is written to the inbox.
async fn chat_only(rig: &Rig, first_seed: u8, mode: SessionMode, input: bool) {
    for (n, frame) in beyond_chat().into_iter().enumerate() {
        let session = start(rig, first_seed + u8::try_from(n).unwrap(), mode);
        session.live(input);
        let (mut client, task) = open(&rig.services);
        let welcome = welcome(&mut client, &session).await;
        assert_eq!(welcome.caps, caps::CHAT, "{mode:?} input={input}");
        assert_eq!(welcome.inbox, "", "no inbox words without uploads");
        // Chat works.
        write_msg(&mut client, &chat("hello")).await.unwrap();
        let kind = frame.ty();
        write_msg(&mut client, &frame).await.unwrap();
        assert_eq!(
            next(&mut client).await,
            Some(SvcMsg::Close {
                reason: reason::NOT_OFFERED
            }),
            "frame type 0x{kind:02x}"
        );
        assert_eq!(next(&mut client).await, None);
        let (code, summary, frames) = served(task).await;
        assert_eq!(code, reason::NOT_OFFERED);
        assert_eq!(summary.chat_in, 1);
        assert_eq!(
            frames.decoded, 1,
            "only the chat line was decoded, never frame type 0x{kind:02x}"
        );
    }
    assert_eq!(rig.desk.opens(), 0, "the clipboard was never opened");
    assert!(!rig.inbox().exists(), "nothing was written");
}

/// Test 2: a view-only session gets chat and nothing else, and every frame
/// of another service ends its stream undecoded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_view_only_session_gets_chat_only_and_nothing_else_is_decoded() {
    let rig = rig();
    chat_only(&rig, 10, SessionMode::ViewOnly, false).await;
    // A view-only session is never live with input; were it, still chat only.
    chat_only(&rig, 30, SessionMode::ViewOnly, true).await;
}

/// Test 2: so does a Control session whose viewer's input reaches nothing
/// (`Live { input: false }`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_session_whose_input_reaches_nothing_gets_chat_only() {
    let rig = rig();
    chat_only(&rig, 50, SessionMode::Control, false).await;
}

/// Bind a media stream for `session` and read up to its first picture, so
/// that its capture is live as the media layer sets it.
async fn media_live(media: &Arc<MediaHost>, session: &Session) -> DuplexStream {
    let (mut client, server) = duplex(1 << 20);
    let host = Arc::clone(media);
    tokio::spawn(async move { host.serve(server).await });
    tornect_proto::write_msg(&mut client, &session.media.msg())
        .await
        .unwrap();
    loop {
        match tokio::time::timeout(WAIT, tornect_proto::read_msg(&mut client))
            .await
            .expect("a picture in time")
            .unwrap()
        {
            Some(tornect_proto::Msg::Video { .. }) => return client,
            Some(_) => {}
            None => panic!("the media stream closed"),
        }
    }
}

/// Test 2 through real media streams: the test card (`SystemBackend` gives
/// it no injector), a desktop with no injector and an administrator session
/// whose helper did not start are live without input, so their Control
/// sessions get chat only; a desktop with an injector gets everything the
/// host allows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_input_gate_follows_the_media_streams_injector() {
    // The test card.
    let card = Arc::new(MediaHost::new(
        Arc::new(SystemBackend::new(Source::TestCard)),
        Arc::new(NoObserver),
        MediaLimits::default(),
    ));
    let rig = rig_on(
        card,
        Arc::new(Desk::default()),
        ServicesPolicy::default(),
        ServicesLimits::default(),
        true,
    );
    let session = start(&rig, 70, SessionMode::Control);
    let _media = media_live(&rig.media, &session).await;
    assert_eq!(
        *session.capture.borrow(),
        CaptureState::Live { input: false }
    );
    let (mut client, task) = open(&rig.services);
    assert_eq!(welcome(&mut client, &session).await.caps, caps::CHAT);
    drop(client);
    served(task).await;
    assert!(!rig.inbox().exists());

    // A desktop that gives no injector, then one that does, then an
    // administrator session whose helper did not start on it.
    for (injector, elevation, input) in [
        (false, Elevation::None, false),
        (true, Elevation::None, true),
        (true, Elevation::Admin, false),
    ] {
        let rig = rig_with(Build {
            desk: Desk {
                injector,
                refuse_admin: true,
                ..Desk::default()
            },
            ..Build::default()
        });
        let session = start_as(&rig, 71, SessionMode::Control, elevation);
        let _media = media_live(&rig.media, &session).await;
        assert_eq!(*session.capture.borrow(), CaptureState::Live { input });
        let want = if input { caps::ALL } else { caps::CHAT };
        let (mut client, task) = open(&rig.services);
        assert_eq!(
            welcome(&mut client, &session).await.caps,
            want,
            "injector={injector} {elevation:?}"
        );
        assert_eq!(rig.desk.opens(), usize::from(input));
        assert_eq!(rig.inbox().exists(), input);
        drop(client);
        served(task).await;
    }
}

/// Test 2: with chat off, a session without input is offered nothing:
/// `Refused{NOT_OFFERED}`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_chat_off_a_session_without_input_is_offered_nothing() {
    let rig = rig_with(Build {
        policy: ServicesPolicy {
            chat: false,
            ..ServicesPolicy::default()
        },
        ..Build::default()
    });
    for (seed, mode, input) in [
        (80, SessionMode::ViewOnly, false),
        (81, SessionMode::Control, false),
    ] {
        let session = start(&rig, seed, mode);
        session.live(input);
        let (mut client, task) = open(&rig.services);
        assert_eq!(
            bind(&mut client, &session).await,
            SvcMsg::Refused {
                reason: reason::NOT_OFFERED
            }
        );
        assert_eq!(
            task.await.unwrap(),
            ServicesOutcome::Refused {
                session_id: session.id.clone(),
                reason: reason::NOT_OFFERED
            }
        );
    }
    assert_eq!(rig.desk.opens(), 0);
}

/// A Control session whose input reaches the desktop gets what the host
/// allows, within the wire's bounds: the clipboard only when the desktop
/// gives a link, uploads only with an inbox (made `0700`), the inbox's
/// display words only with uploads; the policy is the one the session
/// started with.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_session_with_input_gets_what_the_host_allows() {
    let mut rig = rig();
    let session = start(&rig, 90, SessionMode::Control);
    // Changed after the session started: applies to later sessions only.
    rig.policy.send_replace(ServicesPolicy {
        browse_files: false,
        ..ServicesPolicy::default()
    });
    session.live(true);
    let (mut client, task) = open(&rig.services);
    let got = welcome(&mut client, &session).await;
    assert_eq!(
        got,
        Welcome {
            caps: caps::ALL,
            clip_max: MAX_CLIP,
            file_max: 2048 << 20,
            session_quota: 8192 << 20,
            session_files: 1000,
            chat_max: u16::try_from(MAX_CHAT_BYTES).unwrap(),
            bulk_window: 256 * 1024,
            inbox: INBOX_WORDS.to_owned(),
        }
    );
    assert_eq!(rig.desk.opens(), 1);
    assert!(
        !rig.desk.links_dropped(),
        "the link is held while services run"
    );
    assert!(rig.inbox().is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(rig.inbox()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
    assert_eq!(
        rig.event(&session.id).await,
        HostEvent::Opened {
            caps: caps::ALL,
            input: true,
            clipboard_refused: false
        }
    );
    drop(client);
    served(task).await;
    assert!(rig.desk.links_dropped(), "the link goes with the stream");
    assert!(matches!(
        rig.event(&session.id).await,
        HostEvent::Closed {
            reason: reason::BY_VIEWER,
            ..
        }
    ));

    // A later session takes the changed policy.
    let later = start(&rig, 91, SessionMode::Control);
    later.live(true);
    let (mut client, task) = open(&rig.services);
    assert_eq!(
        welcome(&mut client, &later).await.caps,
        caps::CHAT | caps::CLIP | caps::UPLOAD
    );
    drop(client);
    served(task).await;

    // No clipboard from the desktop, no inbox.
    let mut rig = rig_with(Build {
        desk: Desk {
            no_clipboard: true,
            ..Desk::default()
        },
        inbox: false,
        ..Build::default()
    });
    let session = start(&rig, 92, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    let got = welcome(&mut client, &session).await;
    assert_eq!(got.caps, caps::CHAT | caps::BROWSE);
    assert_eq!(got.inbox, "");
    assert_eq!(
        rig.event(&session.id).await,
        HostEvent::Opened {
            caps: caps::CHAT | caps::BROWSE,
            input: true,
            clipboard_refused: true
        }
    );
    drop(client);
    served(task).await;
}

/// The step 8–9 obligation: once the viewer's input is lost mid-session
/// (`INPUT_LOST`), the clipboard and files are turned off for good: the
/// viewer hears `Caps`, the clipboard link is dropped, and their frames are
/// skipped from then on (in flight, so not an error) while chat goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn input_lost_mid_session_takes_the_clipboard_and_files_back() {
    let mut rig = rig();
    let session = start(&rig, 100, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    assert_eq!(welcome(&mut client, &session).await.caps, caps::ALL);
    rig.event(&session.id).await;

    session.live(false);
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Caps(Caps {
            caps: caps::CHAT,
            paused: 0
        }))
    );
    assert_eq!(
        rig.event(&session.id).await,
        HostEvent::Caps {
            caps: caps::CHAT,
            paused: 0
        }
    );
    assert!(
        rig.desk.links_dropped(),
        "the clipboard went with the input"
    );
    for frame in beyond_chat() {
        write_msg(&mut client, &frame).await.unwrap();
    }
    write_msg(&mut client, &chat("still here")).await.unwrap();
    assert_eq!(
        rig.event(&session.id).await,
        HostEvent::Chat(sanitize_peer_text("still here").unwrap())
    );
    // Input never comes back, nor do the caps.
    session.live(true);
    write_msg(&mut client, &SvcMsg::Get(Get { xfer: 2, handle: 1 }))
        .await
        .unwrap();
    write_msg(&mut client, &chat("and here")).await.unwrap();
    assert_eq!(
        rig.event(&session.id).await,
        HostEvent::Chat(sanitize_peer_text("and here").unwrap())
    );
    rig.media.on_end(&session.id, None);
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::SESSION_OVER
        })
    );
    let (code, _, frames) = served(task).await;
    assert_eq!(code, reason::SESSION_OVER);
    assert_eq!(frames.skipped, 12, "every frame beyond chat was skipped");
    assert_eq!(frames.decoded, 2, "the two chat lines");
}

/// The step 8–9 obligation: input lost while the clipboard opens. The link
/// that opened then is dropped, and the session gets chat only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn input_lost_while_the_clipboard_opens_drops_the_link() {
    let (release, hold) = std::sync::mpsc::channel();
    let desk = Desk::default();
    *desk.hold.lock().unwrap() = Some(hold);
    let mut rig = rig_with(Build {
        desk,
        ..Build::default()
    });
    let session = start(&rig, 110, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    write_msg(&mut client, &session.binding.msg())
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + WAIT;
    while rig.desk.opens() == 0 {
        assert!(tokio::time::Instant::now() < deadline, "no open started");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    session.live(false);
    release.send(()).unwrap();
    let SvcMsg::Welcome(welcome) = next(&mut client).await.unwrap() else {
        panic!("expected Welcome");
    };
    assert_eq!(welcome.caps, caps::CHAT);
    assert_eq!(welcome.inbox, "");
    assert_eq!(
        rig.event(&session.id).await,
        HostEvent::Opened {
            caps: caps::CHAT,
            input: false,
            clipboard_refused: false
        }
    );
    // The link was given out, and dropped before `Welcome`.
    assert_eq!(rig.desk.ends.lock().unwrap().len(), 1);
    assert!(rig.desk.links_dropped());
    write_msg(
        &mut client,
        &SvcMsg::ClipStart(ClipStart { seq: 1, len: 3 }),
    )
    .await
    .unwrap();
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::NOT_OFFERED
        })
    );
    served(task).await;
}

/// Input lost in a session with chat off leaves it nothing: the stream ends
/// with `Close{NOT_OFFERED}`; capture that stops before `Welcome` refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_left_with_nothing_ends() {
    let rig = rig_with(Build {
        policy: ServicesPolicy {
            chat: false,
            ..ServicesPolicy::default()
        },
        ..Build::default()
    });
    let session = start(&rig, 120, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    assert_eq!(
        welcome(&mut client, &session).await.caps,
        caps::CLIP | caps::UPLOAD | caps::BROWSE
    );
    session.live(false);
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::NOT_OFFERED
        })
    );
    assert_eq!(served(task).await.0, reason::NOT_OFFERED);
    assert!(rig.desk.links_dropped());
    assert_eq!(rig.media.live(), 1, "the session goes on");
}

// --- Close paths ------------------------------------------------------------

/// Services end when capture stops (`Close{CAPTURE_STOPPED}`), when the
/// session ends (`SESSION_OVER`) or is killed (`ENDED_BY_HOST`), on a frame
/// this version does not know (`PROTOCOL`), and when the viewer leaves
/// (nothing written back); the session goes on in each case it can.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn services_end_with_capture_the_session_a_bad_frame_or_the_viewer() {
    let mut rig = rig();
    let kill = KillSwitch::new();
    let watcher = rig.media.watch_kill(kill.clone());
    let opened = async |rig: &Rig, seed: u8| {
        let session = start(rig, seed, SessionMode::Control);
        session.live(true);
        let (mut client, task) = open(&rig.services);
        welcome(&mut client, &session).await;
        (session, client, task)
    };

    let (session, mut client, task) = opened(&rig, 130).await;
    session.capture.send_replace(CaptureState::Stopped);
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::CAPTURE_STOPPED
        })
    );
    assert_eq!(next(&mut client).await, None);
    assert_eq!(served(task).await.0, reason::CAPTURE_STOPPED);
    assert_eq!(rig.media.live(), 1, "the session goes on");
    rig.event(&session.id).await;
    assert_eq!(
        rig.event(&session.id).await,
        HostEvent::Closed {
            reason: reason::CAPTURE_STOPPED,
            summary: ServicesSummary::default()
        }
    );

    let (session, mut client, task) = opened(&rig, 131).await;
    rig.media.on_end(&session.id, None);
    rig.services.on_end(&session.id);
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::SESSION_OVER
        })
    );
    assert_eq!(served(task).await.0, reason::SESSION_OVER);

    let (_, mut client, task) = opened(&rig, 132).await;
    kill.kill(bye::PANIC);
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::ENDED_BY_HOST
        })
    );
    assert_eq!(served(task).await.0, reason::ENDED_BY_HOST);
    watcher.abort();

    let rig = self::rig();
    let (_, mut client, task) = opened(&rig, 133).await;
    client.write_all(&[0, 0, 0, 1, 0x66]).await.unwrap();
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::PROTOCOL
        })
    );
    let (code, _, frames) = served(task).await;
    assert_eq!(code, reason::PROTOCOL);
    assert_eq!(frames.decoded, 0);

    let (_, mut client, task) = opened(&rig, 134).await;
    write_msg(
        &mut client,
        &SvcMsg::Close {
            reason: reason::BY_VIEWER,
        },
    )
    .await
    .unwrap();
    assert_eq!(next(&mut client).await, None, "nothing written back");
    assert_eq!(served(task).await.0, reason::BY_VIEWER);
    assert_eq!(rig.media.live(), 2);
}

/// The terminal host answers every services stream `Refused{NOT_OFFERED}`.
#[tokio::test]
async fn the_terminal_hosts_refusal() {
    let (mut client, server) = duplex(1024);
    refuse(server).await;
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Refused {
            reason: reason::NOT_OFFERED
        })
    );
    assert_eq!(next(&mut client).await, None);
}

// --- Test 10: chat ----------------------------------------------------------

/// Test 10: chat goes both ways through [`ServicesViewer`], sanitised on
/// receipt, and is counted; neither side's `Debug` shows it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chat_goes_both_ways_sanitised() {
    let mut rig = rig();
    let session = start(&rig, 140, SessionMode::ViewOnly);
    session.live(false);
    let (client, task) = open(&rig.services);
    let (viewer, welcome) = ServicesViewer::bind(client, &session.binding, WAIT)
        .await
        .unwrap();
    assert_eq!(welcome.caps, caps::CHAT);
    assert_eq!(viewer.welcome(), &welcome);
    rig.event(&session.id).await;
    let (ops, ops_rx) = mpsc::channel(8);
    let (events_tx, mut events) = mpsc::channel(8);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let viewer = tokio::spawn(viewer.run(ops_rx, events_tx, async {
        let _ = stopped.await;
    }));

    ops.send(ViewerOp::Chat(
        sanitize_peer_text("hello \u{202e}there").unwrap(),
    ))
    .await
    .unwrap();
    let HostEvent::Chat(heard) = rig.event(&session.id).await else {
        panic!("expected the viewer's chat");
    };
    assert_eq!(heard.as_str(), "hello there");
    assert!(!format!("{heard:?}").contains("hello"));

    // The host's user; a peer's raw text is sanitised on the viewer too.
    assert!(
        rig.services
            .send_chat(&session.id, sanitize_peer_text("hi back").unwrap())
    );
    assert_eq!(
        events.recv().await,
        Some(ViewerEvent::Chat(sanitize_peer_text("hi back").unwrap()))
    );
    assert!(
        !rig.services
            .send_chat("0123456789abcdef", sanitize_peer_text("x").unwrap())
    );

    stop.send(()).unwrap();
    assert_eq!(viewer.await.unwrap(), ViewerServicesEnd::Stopped);
    let (code, summary, _) = served(task).await;
    assert_eq!(code, reason::SESSION_OVER, "the viewer's Close");
    assert_eq!((summary.chat_in, summary.chat_out), (1, 1));
    assert!(
        !rig.services
            .send_chat(&session.id, sanitize_peer_text("late").unwrap())
    );
}

/// Test 10: each receiver takes 8 chat lines at once and 4 a second: the
/// ninth of a burst is dropped, on the host and on the viewer alike. Lines
/// with nothing visible are dropped too.
#[tokio::test(start_paused = true)]
async fn the_ninth_chat_line_of_a_burst_is_dropped_on_both_sides() {
    let mut rig = rig();
    let session = start(&rig, 150, SessionMode::ViewOnly);
    session.live(false);

    // The host's side, from a raw viewer.
    let (mut client, task) = open(&rig.services);
    welcome(&mut client, &session).await;
    rig.event(&session.id).await;
    for n in 0..9 {
        write_msg(&mut client, &chat(&format!("line {n}")))
            .await
            .unwrap();
    }
    write_msg(&mut client, &chat("\u{200b}\u{202e}"))
        .await
        .unwrap();
    // Everything above is read at once: the clock moves only once the host
    // has nothing left to do.
    tokio::time::sleep(Duration::from_millis(300)).await;
    write_msg(&mut client, &chat("line 9")).await.unwrap();
    let mut heard = Vec::new();
    for _ in 0..9 {
        let HostEvent::Chat(text) = rig.event(&session.id).await else {
            panic!("expected chat");
        };
        heard.push(text.as_str().to_owned());
    }
    let want: Vec<String> = [0, 1, 2, 3, 4, 5, 6, 7, 9]
        .iter()
        .map(|n| format!("line {n}"))
        .collect();
    assert_eq!(heard, want);
    drop(client);
    let (_, summary, _) = served(task).await;
    assert_eq!((summary.chat_in, summary.dropped), (9, 2));

    // The viewer's side, from the host's user.
    let session = start(&rig, 151, SessionMode::ViewOnly);
    session.live(false);
    let (client, task) = open(&rig.services);
    let (viewer, _) = ServicesViewer::bind(client, &session.binding, WAIT)
        .await
        .unwrap();
    rig.event(&session.id).await;
    let (_ops, ops_rx) = mpsc::channel(1);
    let (events_tx, mut events) = mpsc::channel(32);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let viewer = tokio::spawn(viewer.run(ops_rx, events_tx, async {
        let _ = stopped.await;
    }));
    for n in 0..9 {
        let text = sanitize_peer_text(&format!("host {n}")).unwrap();
        assert!(rig.services.send_chat(&session.id, text));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        rig.services
            .send_chat(&session.id, sanitize_peer_text("host 9").unwrap())
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
    stop.send(()).unwrap();
    assert_eq!(viewer.await.unwrap(), ViewerServicesEnd::Stopped);
    let mut got = Vec::new();
    while let Ok(ViewerEvent::Chat(text)) = events.try_recv() {
        got.push(text.as_str().to_owned());
    }
    let want: Vec<String> = [0, 1, 2, 3, 4, 5, 6, 7, 9]
        .iter()
        .map(|n| format!("host {n}"))
        .collect();
    assert_eq!(got, want);
    let (_, summary, _) = served(task).await;
    assert_eq!(summary.chat_out, 10);
}

/// Chat is a cap like the others: with chat off a viewer's line ends the
/// stream undecoded, and a viewer never sends one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_chat_a_chat_line_is_never_decoded() {
    let mut rig = rig_with(Build {
        policy: ServicesPolicy {
            chat: false,
            ..ServicesPolicy::default()
        },
        ..Build::default()
    });
    let session = start(&rig, 160, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    assert_eq!(welcome(&mut client, &session).await.caps & caps::CHAT, 0);
    assert!(matches!(
        rig.event(&session.id).await,
        HostEvent::Opened { .. }
    ));
    // Queued, and dropped by the stream's loop: chat is not granted.
    assert!(
        rig.services
            .send_chat(&session.id, sanitize_peer_text("x").unwrap())
    );
    write_msg(&mut client, &chat("hi")).await.unwrap();
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::NOT_OFFERED
        })
    );
    let (_, summary, frames) = served(task).await;
    assert_eq!(frames.decoded, 0);
    assert_eq!(summary.chat_out, 0);
    assert!(matches!(
        rig.event(&session.id).await,
        HostEvent::Closed {
            reason: reason::NOT_OFFERED,
            ..
        }
    ));

    // The viewer's side: a chat op without the cap sends nothing.
    let (mut host, client) = duplex(1 << 16);
    let binding = ServicesBinding::new(&SessionToken::new([161; 32]), &[0; 32]);
    let bound = tokio::spawn(async move { ServicesViewer::bind(client, &binding, WAIT).await });
    assert!(matches!(next(&mut host).await, Some(SvcMsg::Bind(_))));
    write_msg(&mut host, &SvcMsg::Welcome(test_welcome(caps::BROWSE)))
        .await
        .unwrap();
    let (viewer, _) = bound.await.unwrap().unwrap();
    let (ops, ops_rx) = mpsc::channel(1);
    let (events_tx, _events) = mpsc::channel(8);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let viewer = tokio::spawn(viewer.run(ops_rx, events_tx, async {
        let _ = stopped.await;
    }));
    ops.send(ViewerOp::Chat(sanitize_peer_text("x").unwrap()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop.send(()).unwrap();
    assert_eq!(viewer.await.unwrap(), ViewerServicesEnd::Stopped);
    assert_eq!(
        next(&mut host).await,
        Some(SvcMsg::Close {
            reason: reason::SESSION_OVER
        }),
        "no chat line before the Close"
    );
}

// --- The viewer's end ------------------------------------------------------

fn test_welcome(caps: u16) -> Welcome {
    Welcome {
        caps,
        clip_max: MAX_CLIP,
        file_max: 1 << 20,
        session_quota: 1 << 30,
        session_files: 1000,
        chat_max: 16,
        bulk_window: u32::try_from(CHUNK).unwrap(),
        inbox: String::new(),
    }
}

/// A raw host for `ServicesViewer`: it reads the `Bind` and answers with
/// `answer`.
async fn raw_host(
    answer: Option<SvcMsg>,
    wait: Duration,
) -> (
    DuplexStream,
    Result<(ServicesViewer<DuplexStream>, Welcome), ServicesBindError>,
) {
    let (mut host, client) = duplex(1 << 16);
    let binding = ServicesBinding::new(&SessionToken::new([170; 32]), &[1; 32]);
    let bound = tokio::spawn(async move { ServicesViewer::bind(client, &binding, wait).await });
    let Some(SvcMsg::Bind(bind)) = next(&mut host).await else {
        panic!("expected the Bind");
    };
    assert_eq!(bind.session_id, SessionToken::new([170; 32]).session_id());
    assert_eq!(bind.mac, services_bind_mac(&[170; 32], &[1; 32]));
    if let Some(answer) = answer {
        write_msg(&mut host, &answer).await.unwrap();
    }
    (host, bound.await.unwrap())
}

/// The viewer's bind: `Welcome`, or why there are no services: the host's
/// refusal (the terminal host's included), no answer in time, or an answer
/// that is neither. The binding's `Debug` hides its MAC.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_viewer_binds_or_hears_why_not() {
    let (_host, bound) = raw_host(Some(SvcMsg::Welcome(test_welcome(caps::CHAT))), WAIT).await;
    assert_eq!(bound.unwrap().1, test_welcome(caps::CHAT));
    let (_host, bound) = raw_host(
        Some(SvcMsg::Refused {
            reason: reason::NOT_LIVE,
        }),
        WAIT,
    )
    .await;
    assert!(matches!(
        bound,
        Err(ServicesBindError::Refused(reason::NOT_LIVE))
    ));
    let (_host, bound) = raw_host(None, Duration::from_millis(200)).await;
    assert!(matches!(bound, Err(ServicesBindError::Timeout)));
    let (_host, bound) = raw_host(
        Some(SvcMsg::Caps(Caps {
            caps: caps::CHAT,
            paused: 0,
        })),
        WAIT,
    )
    .await;
    assert!(matches!(bound, Err(ServicesBindError::Protocol)));

    // The terminal host.
    let (client, server) = duplex(1024);
    tokio::spawn(refuse(server));
    let binding = ServicesBinding::new(&SessionToken::new([171; 32]), &[2; 32]);
    assert!(matches!(
        ServicesViewer::bind(client, &binding, WAIT).await,
        Err(ServicesBindError::Refused(reason::NOT_OFFERED))
    ));
    let shown = format!("{binding:?}");
    assert!(shown.contains("<redacted>"));
    assert!(!shown.contains(&format!("{:?}", services_bind_mac(&[171; 32], &[2; 32]))));
}

/// What the viewer does with the host's frames: `Caps` that take caps away
/// are said and their frames skipped after; `Caps` that add one, a frame
/// only a viewer sends, and one for a cap never granted end the stream with
/// `Close`; the host's `Close` is said; a chat line is cut to what the host
/// takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_viewer_follows_and_polices_the_host() {
    struct Run {
        host: DuplexStream,
        ops: mpsc::Sender<ViewerOp>,
        events: mpsc::Receiver<ViewerEvent>,
        task: JoinHandle<ViewerServicesEnd>,
        _stop: tokio::sync::oneshot::Sender<()>,
    }
    async fn run(caps: u16) -> Run {
        let (host, bound) = raw_host(Some(SvcMsg::Welcome(test_welcome(caps))), WAIT).await;
        let (viewer, _) = bound.unwrap();
        let (ops, ops_rx) = mpsc::channel(8);
        let (events_tx, events) = mpsc::channel(8);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(viewer.run(ops_rx, events_tx, async {
            let _ = stopped.await;
        }));
        Run {
            host,
            ops,
            events,
            task,
            _stop: stop,
        }
    }

    // Caps shrink; chat goes, and a line is cut to the host's 16 bytes.
    let mut r = run(caps::CHAT | caps::BROWSE).await;
    write_msg(
        &mut r.host,
        &SvcMsg::Caps(Caps {
            caps: caps::CHAT,
            paused: 0,
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        r.events.recv().await,
        Some(ViewerEvent::Caps {
            caps: caps::CHAT,
            paused: 0
        })
    );
    // A listing in flight when browsing went: skipped, no error.
    write_msg(
        &mut r.host,
        &SvcMsg::ListFailed(tornect_proto::services::ListFailed { req: 1, reason: 9 }),
    )
    .await
    .unwrap();
    r.ops
        .send(ViewerOp::Chat(
            sanitize_peer_text("0123456789abcdefghij").unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(next(&mut r.host).await, Some(chat("0123456789abcdef")));
    write_msg(
        &mut r.host,
        &SvcMsg::Close {
            reason: reason::CAPTURE_STOPPED,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        r.events.recv().await,
        Some(ViewerEvent::Closed(reason::CAPTURE_STOPPED))
    );
    assert_eq!(
        r.task.await.unwrap(),
        ViewerServicesEnd::Closed(reason::CAPTURE_STOPPED)
    );
    assert_eq!(next(&mut r.host).await, None, "nothing written back");

    // Each of these ends the stream with the viewer's `Close`.
    for (granted, frame, code) in [
        (
            caps::CHAT,
            SvcMsg::Caps(Caps {
                caps: caps::CHAT | caps::CLIP,
                paused: 0,
            }),
            reason::PROTOCOL,
        ),
        (
            caps::ALL,
            SvcMsg::Offer(Offer {
                xfer: 1,
                name: "x".into(),
                size: 1,
            }),
            reason::PROTOCOL,
        ),
        (
            caps::CHAT,
            SvcMsg::Data {
                xfer: 1,
                offset: 0,
                bytes: vec![0; 4],
            },
            reason::NOT_OFFERED,
        ),
        (
            caps::CHAT,
            SvcMsg::ClipStart(ClipStart { seq: 1, len: 4 }),
            reason::NOT_OFFERED,
        ),
    ] {
        let mut r = run(granted).await;
        let kind = frame.ty();
        write_msg(&mut r.host, &frame).await.unwrap();
        assert_eq!(
            next(&mut r.host).await,
            Some(SvcMsg::Close { reason: code }),
            "frame type 0x{kind:02x}"
        );
        assert_eq!(r.events.recv().await, Some(ViewerEvent::Closed(code)));
        assert_eq!(r.task.await.unwrap(), ViewerServicesEnd::Refused(code));
    }
}

// --- Test 15: eligible and granted ------------------------------------------

/// The services design's test 15: [`eligible`] and [`granted`] over every
/// mode × input × switch × clipboard × inbox combination, each cap checked
/// against its own rule (§2.1): chat behind its switch in any session; the
/// clipboard, uploads and browsing each behind its switch and only in a
/// Control session whose input reaches the desktop; the clipboard only with
/// a link, uploads only with a usable inbox.
#[test]
fn eligible_and_granted_follow_the_table() {
    let mut rows = 0;
    for switches in 0u8..16 {
        let policy = ServicesPolicy {
            chat: switches & 1 != 0,
            clipboard: switches & 2 != 0,
            receive_files: switches & 4 != 0,
            browse_files: switches & 8 != 0,
            ..ServicesPolicy::default()
        };
        for mode in [SessionMode::Control, SessionMode::ViewOnly] {
            for input in [false, true] {
                let may = eligible(&policy, mode, input);
                let reaches = mode == SessionMode::Control && input;
                for clipboard_opened in [false, true] {
                    for inbox_usable in [false, true] {
                        let gets = granted(may, clipboard_opened, inbox_usable);
                        let row = format!(
                            "{policy:?} {mode:?} input={input} \
                             clipboard={clipboard_opened} inbox={inbox_usable}"
                        );
                        let has = |cap: u16| gets & cap != 0;
                        assert_eq!(has(caps::CHAT), policy.chat, "{row}");
                        assert_eq!(
                            has(caps::CLIP),
                            policy.clipboard && reaches && clipboard_opened,
                            "{row}"
                        );
                        assert_eq!(
                            has(caps::UPLOAD),
                            policy.receive_files && reaches && inbox_usable,
                            "{row}"
                        );
                        assert_eq!(has(caps::BROWSE), policy.browse_files && reaches, "{row}");
                        assert_eq!(gets & !caps::ALL, 0, "{row}");
                        assert_eq!(gets & !may, 0, "granted within eligible: {row}");
                        if !reaches {
                            assert_eq!(gets & !caps::CHAT, 0, "chat only: {row}");
                        }
                        rows += 1;
                    }
                }
            }
        }
    }
    assert_eq!(rows, 16 * 2 * 2 * 2 * 2);

    // Each way a Control session's input reaches nothing is
    // `Live { input: false }` (§2.1): chat only, whatever the switches, the
    // clipboard and the inbox say, and nothing with chat off. The test
    // card's and a remote `DISPLAY`'s facts are checked here; the others are
    // pinned where they are made: remote interaction off and the Wayland
    // input handle in `backend.rs`
    // (`the_portal_clipboard_goes_with_the_viewers_input_only`), a refused
    // administrator helper in
    // `the_input_gate_follows_the_media_streams_injector` and the app's
    // `admin_helper` tests.
    let test_card = SystemBackend::new(Source::TestCard)
        .open_injector()
        .is_some();
    #[cfg(target_os = "linux")]
    let remote_display = tornect_capture::x11::display_is_local(Some("otherhost:0"))
        || tornect_capture::x11::display_is_local(Some("localhost:10.0"));
    #[cfg(not(target_os = "linux"))]
    let remote_display = false;
    let all_on = ServicesPolicy::default();
    let chat_off = ServicesPolicy {
        chat: false,
        ..ServicesPolicy::default()
    };
    for (path, input) in [
        ("the test card", test_card),
        ("remote interaction off", false),
        (
            "a DISPLAY that is not this machine's, or no XTEST",
            remote_display,
        ),
        ("a Wayland session without a logical size", false),
        ("an administrator helper that did not start", false),
    ] {
        assert!(!input, "{path} has no injector");
        let may = eligible(&all_on, SessionMode::Control, input);
        assert_eq!(may, caps::CHAT, "{path}");
        assert_eq!(granted(may, true, true), caps::CHAT, "{path}");
        let may = eligible(&chat_off, SessionMode::Control, input);
        assert_eq!(granted(may, true, true), 0, "{path} with chat off");
    }
    let may = eligible(&all_on, SessionMode::Control, true);
    assert_eq!(granted(may, true, true), caps::ALL);
}
