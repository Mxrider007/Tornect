//! The services streams end to end over in-process pipes (the services
//! design §10, tests 1, 2, 4, 5, 6, 10, 12 and 15 and the close paths of
//! step 12, and the review of steps 14 and 15): a real [`MediaHost`]
//! registry, its capture state driven by hand or by a real media stream, a
//! fake desktop clipboard, a temporary inbox, a fake reading of its disk's
//! free space, and a hook that holds an upload worker as it finishes a file.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
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
    Accepted, Bind, CHUNK, Cancel, Caps, Chat, ClipStart, ClipSwitch, Complete, Done, Get, List,
    MAX_CHAT_BYTES, MAX_CLIP, MAX_SERVICES_FRAME, Offer, SvcMsg, Welcome, caps, read_body_max,
    read_header, reason, services_bind_mac, ty, write_msg,
};
use tornect_signal::consent::SessionToken;
use tornect_signal::fsm::host::{KillSwitch, LiveSession, SessionSink as _};
use tornect_signal::messages::bye;

use super::store::{FinishHook, Finishing};
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
    /// What the inbox's disk has free.
    free: Arc<AtomicU64>,
    /// While set, a reading of the free space waits: the upload worker
    /// reading it stalls.
    stall: Arc<AtomicBool>,
    /// Readings that waited on [`Rig::stall`].
    stalled: Arc<AtomicUsize>,
    /// While set, an upload worker finishing a file waits at this stage.
    hold_at: Arc<Mutex<Option<Finishing>>>,
    /// Workers that waited at [`Rig::hold_at`] and were not yet counted by
    /// [`Rig::held`].
    held: Arc<AtomicUsize>,
}

/// A test that fails while a worker waits on [`Rig::stall`] or
/// [`Rig::hold_at`] would otherwise hang: the runtime's end waits for its
/// blocking tasks.
impl Drop for Rig {
    fn drop(&mut self) {
        self.stall.store(false, Ordering::SeqCst);
        *self
            .hold_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
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
    let free = Arc::new(AtomicU64::new(u64::MAX / 2));
    let stall = Arc::new(AtomicBool::new(false));
    let stalled = Arc::new(AtomicUsize::new(0));
    let hold_at = Arc::new(Mutex::new(None));
    let held = Arc::new(AtomicUsize::new(0));
    let finishing: FinishHook = {
        let (hold_at, held) = (Arc::clone(&hold_at), Arc::clone(&held));
        Arc::new(move |stage: Finishing| {
            let holds = || *hold_at.lock().unwrap() == Some(stage);
            if holds() {
                held.fetch_add(1, Ordering::SeqCst);
                while holds() {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        })
    };
    let free_space: FreeSpaceFn = {
        let (free, stall, stalled) = (Arc::clone(&free), Arc::clone(&stall), Arc::clone(&stalled));
        Arc::new(move |_: &std::path::Path| {
            if stall.load(Ordering::SeqCst) {
                stalled.fetch_add(1, Ordering::SeqCst);
                while stall.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            Ok(free.load(Ordering::SeqCst))
        })
    };
    let env = ServicesEnv {
        inbox: inbox.then(|| home.path().join("Tornect")),
        inbox_words: INBOX_WORDS.to_owned(),
        free_space,
        finishing: Some(finishing),
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
        free,
        stall,
        stalled,
        hold_at,
        held,
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

// --- Tests 4, 5, 6 and 12: uploads ------------------------------------------

/// How long a sender that waits on its window is watched to send nothing.
const QUIET: Duration = Duration::from_millis(300);

impl Rig {
    /// The next transfer row of session `id`.
    async fn row(&mut self, id: &str) -> TransferRow {
        match self.event(id).await {
            HostEvent::Transfer(row) => row,
            other => panic!("expected a transfer row, got {other:?}"),
        }
    }

    /// Wait until some reading of the free space waits on [`Rig::stall`].
    async fn stalled(&self) {
        let deadline = tokio::time::Instant::now() + WAIT;
        while self.stalled.load(Ordering::SeqCst) == 0 {
            assert!(tokio::time::Instant::now() < deadline, "no worker stalled");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

/// The names in the inbox, sorted; none when it does not exist.
fn inbox_names(rig: &Rig) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(rig.inbox())
        .map(|dir| {
            dir.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Wait until the inbox holds exactly `names`: an upload's worker deletes
/// its files once the stream's loop let it go.
async fn inbox_settles(rig: &Rig, names: &[&str]) {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let got = inbox_names(rig);
        if got == names {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the inbox holds {got:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn offer(xfer: u32, name: &str, size: u64) -> SvcMsg {
    SvcMsg::Offer(Offer {
        xfer,
        name: name.into(),
        size,
    })
}

fn accepted(xfer: u32, name: &str) -> SvcMsg {
    SvcMsg::Accepted(Accepted {
        xfer,
        name: name.into(),
    })
}

fn cancel(xfer: u32, reason: u16) -> SvcMsg {
    SvcMsg::Cancel(Cancel { xfer, reason })
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Send `bytes` of transfer `xfer` from `offset`, a chunk a frame.
async fn send_data(client: &mut DuplexStream, xfer: u32, offset: u64, bytes: &[u8]) {
    let mut at = offset;
    for piece in bytes.chunks(CHUNK) {
        write_msg(
            client,
            &SvcMsg::Data {
                xfer,
                offset: at,
                bytes: piece.to_vec(),
            },
        )
        .await
        .unwrap();
        at += piece.len() as u64;
    }
}

/// Upload `content` (within the window) as transfer `xfer` named `name`
/// from a raw viewer, through to `Complete`: the name the host stored it
/// under.
async fn upload(client: &mut DuplexStream, xfer: u32, name: &str, content: &[u8]) -> String {
    assert!(content.len() <= 256 * 1024);
    write_msg(client, &offer(xfer, name, content.len() as u64))
        .await
        .unwrap();
    let Some(SvcMsg::Accepted(took)) = next(client).await else {
        panic!("expected Accepted");
    };
    assert_eq!(took.xfer, xfer);
    send_data(client, xfer, 0, content).await;
    write_msg(
        client,
        &SvcMsg::Done(Done {
            xfer,
            sha256: sha256(content),
        }),
    )
    .await
    .unwrap();
    loop {
        match next(client).await {
            Some(SvcMsg::Credit { xfer: x, .. }) if x == xfer => {}
            Some(SvcMsg::Complete(Complete { xfer: x })) if x == xfer => return took.name,
            other => panic!("expected Complete, got {other:?}"),
        }
    }
}

/// A [`ServicesViewer`]'s loop, running.
struct Running {
    ops: mpsc::Sender<ViewerOp>,
    events: mpsc::Receiver<ViewerEvent>,
    task: JoinHandle<ViewerServicesEnd>,
    stop: tokio::sync::oneshot::Sender<()>,
}

fn run_viewer(viewer: ServicesViewer<DuplexStream>) -> Running {
    let (ops, ops_rx) = mpsc::channel(8);
    let (events_tx, events) = mpsc::channel(1024);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(viewer.run(ops_rx, events_tx, async {
        let _ = stopped.await;
    }));
    Running {
        ops,
        events,
        task,
        stop,
    }
}

/// A [`ServicesViewer`] bound to `rig`'s host for `session` and running,
/// its `Welcome`, and the host's end.
async fn viewing(rig: &Rig, session: &Session) -> (Running, Welcome, JoinHandle<ServicesOutcome>) {
    let (client, host) = open(&rig.services);
    let (viewer, welcome) = ServicesViewer::bind(client, &session.binding, WAIT)
        .await
        .unwrap();
    (run_viewer(viewer), welcome, host)
}

/// The viewer's next event, which must be a transfer row.
async fn transfer(events: &mut mpsc::Receiver<ViewerEvent>) -> TransferRow {
    match tokio::time::timeout(WAIT, events.recv()).await {
        Ok(Some(ViewerEvent::Transfer(row))) => row,
        other => panic!("expected a transfer row, got {other:?}"),
    }
}

/// The services design's test 4: files sent through [`ServicesViewer`] land
/// in the inbox under their sanitised names, a taken name gets ` (2)`, each
/// is its owner's only, its hash is checked, and both ends see it `Done`
/// under the stored name (the row the app's `file_received` record takes).
/// A file beyond the window moves as the host credits it; a third file
/// waits for one of the two places.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uploads_land_in_the_inbox_under_sanitised_names() {
    let mut rig = rig();
    let session = start(&rig, 200, SessionMode::Control);
    session.live(true);
    let (mut v, got, host) = viewing(&rig, &session).await;
    assert_eq!(got.caps, caps::ALL);
    assert_eq!(got.bulk_window, 256 * 1024);
    rig.event(&session.id).await;

    let local = tempfile::tempdir().unwrap();
    let big: Vec<u8> = (0..300 * 1024 + 123).map(|n| (n % 251) as u8).collect();
    let tricky = local.path().join("my\u{202e}report.txt");
    std::fs::write(&tricky, &big).unwrap();
    let small = local.path().join("notes.txt");
    std::fs::write(&small, b"hello").unwrap();
    for path in [&tricky, &tricky, &small] {
        v.ops
            .send(ViewerOp::UploadPath(path.clone()))
            .await
            .unwrap();
    }

    // The viewer's rows, in order, until all three ended.
    let mut rows = Vec::new();
    let mut ended = HashMap::new();
    while ended.len() < 3 {
        let row = transfer(&mut v.events).await;
        assert_eq!(row.dir, Direction::ToHost);
        if !matches!(row.state, TransferState::Queued | TransferState::Running) {
            ended.insert(row.xfer, row.clone());
        }
        rows.push(row);
    }
    let stored = |row: &TransferRow| match &row.state {
        TransferState::Done { stored } => stored.as_str().to_owned(),
        other => panic!("not done: {other:?}"),
    };
    let mut twins = vec![stored(&ended[&1]), stored(&ended[&2])];
    twins.sort();
    assert_eq!(twins, ["myreport (2).txt", "myreport.txt"]);
    assert_eq!(stored(&ended[&3]), "notes.txt");
    for id in [1, 2] {
        assert_eq!(ended[&id].name.as_str(), "myreport.txt");
        assert_eq!(
            (ended[&id].size, ended[&id].done),
            (big.len() as u64, big.len() as u64)
        );
    }
    assert!(
        rows.iter().any(|row| row.state == TransferState::Running
            && row.done > 0
            && row.done < big.len() as u64),
        "credits came while the file moved"
    );
    let first_end = rows
        .iter()
        .position(|row| row.xfer != 3 && matches!(row.state, TransferState::Done { .. }))
        .unwrap();
    let third_runs = rows
        .iter()
        .position(|row| row.xfer == 3 && row.state == TransferState::Running)
        .unwrap();
    assert!(first_end < third_runs, "the third file waited for a place");

    // The host's rows say the same, under the stored names.
    let mut host_done = Vec::new();
    while host_done.len() < 3 {
        let row = rig.row(&session.id).await;
        assert_eq!(row.dir, Direction::ToHost);
        match row.state {
            TransferState::Running => {}
            TransferState::Done { ref stored } => {
                assert_eq!(row.name, *stored);
                assert_eq!(row.done, row.size);
                host_done.push(stored.as_str().to_owned());
            }
            other => panic!("{other:?}"),
        }
    }
    host_done.sort();
    assert_eq!(host_done, ["myreport (2).txt", "myreport.txt", "notes.txt"]);

    assert_eq!(
        inbox_names(&rig),
        ["myreport (2).txt", "myreport.txt", "notes.txt"],
        "no part file is left"
    );
    for name in ["myreport (2).txt", "myreport.txt"] {
        assert_eq!(std::fs::read(rig.inbox().join(name)).unwrap(), big);
    }
    assert_eq!(
        std::fs::read(rig.inbox().join("notes.txt")).unwrap(),
        b"hello"
    );
    #[cfg(unix)]
    for name in inbox_names(&rig) {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(rig.inbox().join(&name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }

    v.stop.send(()).unwrap();
    assert_eq!(v.task.await.unwrap(), ViewerServicesEnd::Stopped);
    let (code, summary, _) = served(host).await;
    assert_eq!(code, reason::SESSION_OVER);
    assert_eq!(summary.files_in, 3);
    assert_eq!(summary.bytes_in, 2 * big.len() as u64 + 5);
    let HostEvent::Closed { summary, .. } = rig.event(&session.id).await else {
        panic!("expected Closed");
    };
    assert_eq!(summary.files_in, 3);

    // A file whose hash does not match, or that is cut short, is refused
    // `CORRUPT` and deleted.
    let session = start(&rig, 201, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    welcome(&mut client, &session).await;
    rig.event(&session.id).await;
    write_msg(&mut client, &offer(1, "bad.bin", 10))
        .await
        .unwrap();
    assert_eq!(next(&mut client).await, Some(accepted(1, "bad.bin")));
    send_data(&mut client, 1, 0, &[1; 10]).await;
    write_msg(
        &mut client,
        &SvcMsg::Done(Done {
            xfer: 1,
            sha256: sha256(&[2; 10]),
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Credit { xfer: 1, upto: 10 })
    );
    assert_eq!(next(&mut client).await, Some(cancel(1, reason::CORRUPT)));
    write_msg(&mut client, &offer(2, "short.bin", 10))
        .await
        .unwrap();
    assert_eq!(next(&mut client).await, Some(accepted(2, "short.bin")));
    send_data(&mut client, 2, 0, &[1; 5]).await;
    write_msg(
        &mut client,
        &SvcMsg::Done(Done {
            xfer: 2,
            sha256: sha256(&[1; 5]),
        }),
    )
    .await
    .unwrap();
    assert_eq!(next(&mut client).await, Some(cancel(2, reason::CORRUPT)));
    assert_eq!(
        inbox_names(&rig),
        ["myreport (2).txt", "myreport.txt", "notes.txt"]
    );
    let mut ends = Vec::new();
    while ends.len() < 2 {
        let row = rig.row(&session.id).await;
        if row.state != TransferState::Running {
            ends.push((row.name.as_str().to_owned(), row.state));
        }
    }
    assert_eq!(
        ends,
        [
            ("bad.bin".to_owned(), TransferState::Failed(reason::CORRUPT)),
            (
                "short.bin".to_owned(),
                TransferState::Failed(reason::CORRUPT)
            ),
        ]
    );
    drop(client);
    let (_, summary, _) = served(task).await;
    assert_eq!(summary.files_in, 0);
}

/// A raw viewer that has sent the first 64 KiB of a 1 MiB file as transfer
/// 1 to a new session of `rig`, which the host wrote and credited: its part
/// file and its reservation are in the inbox.
async fn midway(rig: &mut Rig, seed: u8) -> (Session, DuplexStream, JoinHandle<ServicesOutcome>) {
    let session = start(rig, seed, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    welcome(&mut client, &session).await;
    rig.event(&session.id).await;
    write_msg(&mut client, &offer(1, "big.bin", 1 << 20))
        .await
        .unwrap();
    assert_eq!(next(&mut client).await, Some(accepted(1, "big.bin")));
    send_data(&mut client, 1, 0, &vec![7; 64 * 1024]).await;
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Credit {
            xfer: 1,
            upto: 64 * 1024
        })
    );
    assert_eq!(rig.row(&session.id).await.done, 0);
    assert_eq!(rig.row(&session.id).await.done, 64 * 1024);
    assert_eq!(inbox_names(rig), ["big.bin", "big.bin.tornect-part"]);
    (session, client, task)
}

/// The services design's test 5: whatever ends an upload midway (a cancel
/// by either side, a protocol error, the session's end, capture stopping,
/// lost input, the viewer leaving, the kill switch) leaves neither its part
/// file nor its reservation; on the stream's end, none is left once
/// `serve` returned. The kill switch's `Close` goes out within 100 ms even
/// while a worker is stuck in a write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_end_of_an_upload_leaves_nothing_in_the_inbox() {
    let mut rig = rig_with(Build {
        limits: ServicesLimits {
            recheck_free_every: CHUNK as u64,
            ..ServicesLimits::default()
        },
        ..Build::default()
    });
    let kill = KillSwitch::new();
    let watcher = rig.media.watch_kill(kill.clone());

    // The viewer stops it; its data still in flight is dropped, and the
    // stream goes on.
    let (session, mut client, task) = midway(&mut rig, 210).await;
    write_msg(&mut client, &cancel(1, reason::BY_VIEWER))
        .await
        .unwrap();
    send_data(&mut client, 1, 64 * 1024, &[7; 100]).await;
    assert_eq!(
        rig.row(&session.id).await.state,
        TransferState::Cancelled(reason::BY_VIEWER)
    );
    inbox_settles(&rig, &[]).await;
    write_msg(&mut client, &chat("still here")).await.unwrap();
    assert!(matches!(rig.event(&session.id).await, HostEvent::Chat(_)));
    drop(client);
    assert_eq!(served(task).await.0, reason::BY_VIEWER);

    // The host's user stops it.
    let (session, mut client, task) = midway(&mut rig, 211).await;
    assert!(rig.services.cancel(&session.id, 1));
    assert_eq!(next(&mut client).await, Some(cancel(1, reason::BY_HOST)));
    assert_eq!(
        rig.row(&session.id).await.state,
        TransferState::Cancelled(reason::BY_HOST)
    );
    inbox_settles(&rig, &[]).await;
    assert!(rig.services.cancel(&session.id, 1), "ended: left as it is");
    write_msg(&mut client, &chat("still here")).await.unwrap();
    assert!(matches!(rig.event(&session.id).await, HostEvent::Chat(_)));
    drop(client);
    served(task).await;

    // A protocol error: bytes out of order.
    let (_, mut client, task) = midway(&mut rig, 212).await;
    send_data(&mut client, 1, 0, &[7; 10]).await;
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::PROTOCOL
        })
    );
    assert_eq!(served(task).await.0, reason::PROTOCOL);
    assert_eq!(inbox_names(&rig), Vec::<String>::new());

    // The session ends.
    let (session, mut client, task) = midway(&mut rig, 213).await;
    rig.media.on_end(&session.id, None);
    rig.services.on_end(&session.id);
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::SESSION_OVER
        })
    );
    assert_eq!(served(task).await.0, reason::SESSION_OVER);
    assert_eq!(inbox_names(&rig), Vec::<String>::new());

    // Capture stops.
    let (session, mut client, task) = midway(&mut rig, 214).await;
    session.capture.send_replace(CaptureState::Stopped);
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::CAPTURE_STOPPED
        })
    );
    assert_eq!(served(task).await.0, reason::CAPTURE_STOPPED);
    assert_eq!(inbox_names(&rig), Vec::<String>::new());

    // The viewer's input is lost: uploads are turned off, each running one
    // cancelled before the viewer hears the caps.
    let (session, mut client, task) = midway(&mut rig, 215).await;
    session.live(false);
    assert_eq!(next(&mut client).await, Some(cancel(1, reason::TURNED_OFF)));
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Caps(Caps {
            caps: caps::CHAT,
            paused: 0
        }))
    );
    assert_eq!(
        rig.row(&session.id).await.state,
        TransferState::Cancelled(reason::TURNED_OFF)
    );
    inbox_settles(&rig, &[]).await;
    drop(client);
    served(task).await;

    // The viewer leaves.
    let (_, client, task) = midway(&mut rig, 216).await;
    drop(client);
    assert_eq!(served(task).await.0, reason::BY_VIEWER);
    assert_eq!(inbox_names(&rig), Vec::<String>::new());

    // The kill switch, while the worker is stuck in a write.
    let (_, mut client, task) = midway(&mut rig, 217).await;
    rig.stall.store(true, Ordering::SeqCst);
    send_data(&mut client, 1, 64 * 1024, &vec![7; CHUNK]).await;
    rig.stalled().await;
    let killed = tokio::time::Instant::now();
    kill.kill(bye::PANIC);
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::ENDED_BY_HOST
        })
    );
    let took = killed.elapsed();
    assert!(took < Duration::from_millis(100), "Close took {took:?}");
    assert_eq!(
        inbox_names(&rig),
        ["big.bin", "big.bin.tornect-part"],
        "the stuck worker still holds its files"
    );
    rig.stall.store(false, Ordering::SeqCst);
    assert_eq!(served(task).await.0, reason::ENDED_BY_HOST);
    assert_eq!(inbox_names(&rig), Vec::<String>::new());
    watcher.abort();
}

/// The services design's test 6: an offer the host cannot take is refused
/// before a byte of it is written, with no row: over the largest file
/// (`TOO_LARGE`), a name with nothing left (`BAD_NAME`), beyond the
/// session's quota with tiny files counted at 4 KiB each (`QUOTA`), a disk
/// that would keep less than its reserve free (`NO_SPACE`), and a third
/// upload while two run (`BUSY`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uploads_are_refused_before_any_byte_is_written() {
    const KEEP_FREE: u64 = 1 << 20;
    let mut rig = rig_with(Build {
        policy: ServicesPolicy {
            max_file: 1 << 20,
            session_quota: 2 * 4096,
            keep_free: KEEP_FREE,
            ..ServicesPolicy::default()
        },
        ..Build::default()
    });
    let session = start(&rig, 220, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    let got = welcome(&mut client, &session).await;
    assert_eq!((got.file_max, got.session_quota), (1 << 20, 2 * 4096));
    rig.event(&session.id).await;

    write_msg(&mut client, &offer(1, "huge.bin", (1 << 20) + 1))
        .await
        .unwrap();
    assert_eq!(next(&mut client).await, Some(cancel(1, reason::TOO_LARGE)));
    write_msg(&mut client, &offer(2, "..", 10)).await.unwrap();
    assert_eq!(next(&mut client).await, Some(cancel(2, reason::BAD_NAME)));
    // Two files of 10 bytes spend the quota of 8 KiB.
    assert_eq!(
        upload(&mut client, 3, "a.txt", b"0123456789").await,
        "a.txt"
    );
    assert_eq!(
        upload(&mut client, 4, "b.txt", b"0123456789").await,
        "b.txt"
    );
    write_msg(&mut client, &offer(5, "c.txt", 1)).await.unwrap();
    assert_eq!(next(&mut client).await, Some(cancel(5, reason::QUOTA)));
    // Data of a refused offer, in flight, is dropped.
    send_data(&mut client, 5, 0, &[1]).await;
    assert_eq!(inbox_names(&rig), ["a.txt", "b.txt"]);
    drop(client);
    let (_, summary, _) = served(task).await;
    assert_eq!((summary.files_in, summary.bytes_in), (2, 20));

    // A later session, with a quota to spare, on a disk nearly full.
    rig.policy
        .send_modify(|policy| policy.session_quota = 1 << 30);
    let session = start(&rig, 221, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    welcome(&mut client, &session).await;
    rig.free.store(KEEP_FREE + 99, Ordering::SeqCst);
    write_msg(&mut client, &offer(1, "d.bin", 100))
        .await
        .unwrap();
    assert_eq!(next(&mut client).await, Some(cancel(1, reason::NO_SPACE)));
    rig.free.store(KEEP_FREE + 100, Ordering::SeqCst);
    assert_eq!(upload(&mut client, 2, "d.bin", &[1; 100]).await, "d.bin");
    rig.free.store(u64::MAX / 2, Ordering::SeqCst);
    // Two run; a third is busy.
    write_msg(&mut client, &offer(3, "e1.bin", 10))
        .await
        .unwrap();
    assert_eq!(next(&mut client).await, Some(accepted(3, "e1.bin")));
    write_msg(&mut client, &offer(4, "e2.bin", 10))
        .await
        .unwrap();
    assert_eq!(next(&mut client).await, Some(accepted(4, "e2.bin")));
    write_msg(&mut client, &offer(5, "e3.bin", 10))
        .await
        .unwrap();
    assert_eq!(next(&mut client).await, Some(cancel(5, reason::BUSY)));
    for xfer in [3, 4] {
        write_msg(&mut client, &cancel(xfer, reason::BY_VIEWER))
            .await
            .unwrap();
    }
    inbox_settles(&rig, &["a.txt", "b.txt", "d.bin"]).await;
    // An id used once is never used again, refused or not.
    write_msg(&mut client, &offer(5, "again.bin", 10))
        .await
        .unwrap();
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::PROTOCOL
        })
    );
    served(task).await;

    // Only files the inbox took have rows.
    let mut named = Vec::new();
    while let Ok((_, event)) = rig.heard.try_recv() {
        if let HostEvent::Transfer(row) = event {
            named.push(row.name.as_str().to_owned());
        }
    }
    named.sort();
    named.dedup();
    assert_eq!(named, ["a.txt", "b.txt", "d.bin", "e1.bin", "e2.bin"]);
}

/// Test 6: a session takes 1000 files, however small, each counted 4 KiB
/// toward its quota: the 1001st is refused `QUOTA`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_takes_a_thousand_files_at_most() {
    let rig = rig();
    let session = start(&rig, 230, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    assert_eq!(welcome(&mut client, &session).await.session_files, 1000);
    for n in 1..=1000u32 {
        upload(&mut client, n, &format!("t{n}"), &[1]).await;
    }
    write_msg(&mut client, &offer(1001, "t1001", 1))
        .await
        .unwrap();
    assert_eq!(next(&mut client).await, Some(cancel(1001, reason::QUOTA)));
    assert_eq!(inbox_names(&rig).len(), 1000);
    drop(client);
    let (_, summary, _) = served(task).await;
    assert_eq!((summary.files_in, summary.bytes_in), (1000, 1000));
}

/// Read the `Data` of `xfer` from `offset` until nothing comes for
/// [`QUIET`]: the bytes read.
async fn data_until_quiet(host: &mut DuplexStream, xfer: u32, offset: u64) -> u64 {
    let mut got = 0;
    loop {
        let Ok(header) = tokio::time::timeout(QUIET, read_header(host)).await else {
            return got;
        };
        let header = header.unwrap().expect("a frame");
        let body = read_body_max(host, header, MAX_SERVICES_FRAME)
            .await
            .unwrap();
        match SvcMsg::decode(header.ty, &body).unwrap() {
            SvcMsg::Data {
                xfer: x,
                offset: at,
                bytes,
            } if x == xfer && at == offset + got => got += bytes.len() as u64,
            other => panic!("expected Data, got {other:?}"),
        }
    }
}

/// The services design's test 12: a sender keeps at most the bulk window
/// beyond what its receiver credited. The viewer, sending to a host that
/// withholds `Credit`, stops at 256 KiB, and sends exactly what a credit
/// frees; a credit beyond what it sent ends the stream, and the upload
/// with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sender_keeps_to_the_bulk_window() {
    let mut granted = test_welcome(caps::CHAT | caps::UPLOAD);
    granted.bulk_window = 256 * 1024;
    let (mut host, bound) = raw_host(Some(SvcMsg::Welcome(granted)), WAIT).await;
    let mut v = run_viewer(bound.unwrap().0);
    let local = tempfile::tempdir().unwrap();
    let path = local.path().join("f.bin");
    std::fs::write(&path, vec![5u8; 1 << 20]).unwrap();
    v.ops.send(ViewerOp::UploadPath(path)).await.unwrap();
    assert_eq!(next(&mut host).await, Some(offer(1, "f.bin", 1 << 20)));
    write_msg(&mut host, &accepted(1, "f.bin")).await.unwrap();

    let mut sent = data_until_quiet(&mut host, 1, 0).await;
    assert_eq!(sent, 256 * 1024, "one window, then nothing");
    write_msg(
        &mut host,
        &SvcMsg::Credit {
            xfer: 1,
            upto: 64 * 1024,
        },
    )
    .await
    .unwrap();
    sent += data_until_quiet(&mut host, 1, sent).await;
    assert_eq!(sent, 320 * 1024, "exactly what the credit freed");

    // A credit of clipboard bytes, none of which were sent.
    write_msg(&mut host, &SvcMsg::Credit { xfer: 0, upto: 1 })
        .await
        .unwrap();
    assert_eq!(
        next(&mut host).await,
        Some(SvcMsg::Close {
            reason: reason::PROTOCOL
        })
    );
    assert_eq!(
        v.task.await.unwrap(),
        ViewerServicesEnd::Refused(reason::PROTOCOL)
    );
    let mut last = None;
    while let Some(event) = v.events.recv().await {
        match event {
            ViewerEvent::Transfer(row) => last = Some(row),
            ViewerEvent::Closed(code) => {
                assert_eq!(code, reason::PROTOCOL);
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    let last = last.unwrap();
    assert_eq!(last.state, TransferState::Failed(reason::PROTOCOL));
    assert_eq!(last.done, 64 * 1024, "what the host credited");
}

/// Test 12, the host's side: a viewer that keeps to the window is never
/// refused, even while the host's disk is slow and it credits nothing; one
/// byte beyond the window ends the stream with `Close{PROTOCOL}`, and
/// nothing of the file is left.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_holds_the_viewer_to_the_bulk_window() {
    let mut rig = rig_with(Build {
        limits: ServicesLimits {
            recheck_free_every: CHUNK as u64,
            ..ServicesLimits::default()
        },
        ..Build::default()
    });
    let session = start(&rig, 240, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    assert_eq!(welcome(&mut client, &session).await.bulk_window, 256 * 1024);
    rig.event(&session.id).await;
    write_msg(&mut client, &offer(1, "w.bin", 1 << 20))
        .await
        .unwrap();
    assert_eq!(next(&mut client).await, Some(accepted(1, "w.bin")));
    assert_eq!(rig.row(&session.id).await.state, TransferState::Running);
    rig.stall.store(true, Ordering::SeqCst);
    send_data(&mut client, 1, 0, &vec![3; CHUNK]).await;
    rig.stalled().await;
    send_data(&mut client, 1, CHUNK as u64, &vec![3; 256 * 1024 - CHUNK]).await;
    write_msg(&mut client, &chat("still here")).await.unwrap();
    assert!(
        matches!(rig.event(&session.id).await, HostEvent::Chat(_)),
        "a full window, no credit, no refusal"
    );
    send_data(&mut client, 1, 256 * 1024, &[3]).await;
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::PROTOCOL
        })
    );
    rig.stall.store(false, Ordering::SeqCst);
    assert_eq!(served(task).await.0, reason::PROTOCOL);
    assert_eq!(inbox_names(&rig), Vec::<String>::new());
}

/// The viewer refuses, with nothing sent, what it cannot send: a folder
/// (`NOT_A_FILE`), a missing file (`NOT_FOUND`), a file over the host's
/// largest (`TOO_LARGE`), and anything once the host turned uploads off
/// (`NOT_OFFERED`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_viewer_refuses_what_it_cannot_send() {
    let (mut host, bound) = raw_host(
        Some(SvcMsg::Welcome(test_welcome(caps::CHAT | caps::UPLOAD))),
        WAIT,
    )
    .await;
    let mut v = run_viewer(bound.unwrap().0);
    let local = tempfile::tempdir().unwrap();
    let big = local.path().join("big.bin");
    std::fs::write(&big, vec![0u8; (1 << 20) + 1]).unwrap();
    for (path, code) in [
        (local.path().to_path_buf(), reason::NOT_A_FILE),
        (local.path().join("missing"), reason::NOT_FOUND),
        (big, reason::TOO_LARGE),
    ] {
        v.ops.send(ViewerOp::UploadPath(path)).await.unwrap();
        assert_eq!(transfer(&mut v.events).await.state, TransferState::Queued);
        assert_eq!(
            transfer(&mut v.events).await.state,
            TransferState::Failed(code)
        );
    }
    v.ops
        .send(ViewerOp::Chat(sanitize_peer_text("x").unwrap()))
        .await
        .unwrap();
    assert_eq!(next(&mut host).await, Some(chat("x")), "no offer went out");

    write_msg(
        &mut host,
        &SvcMsg::Caps(Caps {
            caps: caps::CHAT,
            paused: 0,
        }),
    )
    .await
    .unwrap();
    assert!(matches!(
        v.events.recv().await,
        Some(ViewerEvent::Caps { .. })
    ));
    let small = local.path().join("small.txt");
    std::fs::write(&small, b"hi").unwrap();
    v.ops.send(ViewerOp::UploadPath(small)).await.unwrap();
    assert_eq!(
        transfer(&mut v.events).await.state,
        TransferState::Failed(reason::NOT_OFFERED)
    );
    v.ops
        .send(ViewerOp::Chat(sanitize_peer_text("y").unwrap()))
        .await
        .unwrap();
    assert_eq!(next(&mut host).await, Some(chat("y")), "no offer went out");
    v.stop.send(()).unwrap();
    assert_eq!(v.task.await.unwrap(), ViewerServicesEnd::Stopped);
}

// --- The review of steps 14 and 15: an upload's end races its worker ------

impl Rig {
    /// Hold every upload worker finishing a file at `at`; `None` lets them
    /// go on.
    fn hold(&self, at: Option<Finishing>) {
        *self.hold_at.lock().unwrap() = at;
    }

    /// Wait until a worker waits at the stage [`Rig::hold`] set.
    async fn held(&self) {
        let deadline = tokio::time::Instant::now() + WAIT;
        while self.held.swap(0, Ordering::SeqCst) == 0 {
            assert!(tokio::time::Instant::now() < deadline, "no worker held");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

/// `Done` of transfer `xfer` with the hash of `content`.
fn done(xfer: u32, content: &[u8]) -> SvcMsg {
    SvcMsg::Done(Done {
        xfer,
        sha256: sha256(content),
    })
}

/// A raw viewer that has sent a whole 10-byte file `name` as transfer 1 to a
/// new session of `rig`, and its `Done`; the worker finishing it waits at
/// `at`. The host credited the bytes, and told two `Running` rows.
async fn finishing(
    rig: &mut Rig,
    seed: u8,
    name: &str,
    at: Finishing,
) -> (Session, DuplexStream, JoinHandle<ServicesOutcome>) {
    let session = start(rig, seed, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    welcome(&mut client, &session).await;
    rig.event(&session.id).await;
    rig.hold(Some(at));
    write_msg(&mut client, &offer(1, name, 10)).await.unwrap();
    assert_eq!(next(&mut client).await, Some(accepted(1, name)));
    send_data(&mut client, 1, 0, &[9; 10]).await;
    write_msg(&mut client, &done(1, &[9; 10])).await.unwrap();
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Credit { xfer: 1, upto: 10 })
    );
    rig.held().await;
    assert_eq!(rig.row(&session.id).await.done, 0);
    assert_eq!(rig.row(&session.id).await.done, 10);
    (session, client, task)
}

/// The rows the host tells for session `id` until its stream's `Closed`,
/// and the summary that carries.
async fn rows_until_closed(rig: &mut Rig, id: &str) -> (Vec<TransferRow>, ServicesSummary) {
    let mut rows = Vec::new();
    loop {
        match rig.event(id).await {
            HostEvent::Transfer(row) => rows.push(row),
            HostEvent::Closed { summary, .. } => return (rows, summary),
            other => panic!("{other:?}"),
        }
    }
}

/// How an upload whose last bytes and `Done` arrived ends, in
/// [`a_file_lands_with_its_row_or_not_at_all`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The viewer closes the stream (`Close`, or it goes, or its media
    /// stream ends and capture with it: the same stop of every worker).
    Close,
    /// The kill switch.
    Kill,
    /// The host's user stops the upload.
    HostCancel,
    /// The viewer's input is lost.
    InputLost,
}

/// The review's race of steps 14 and 15, made deterministic by holding the
/// worker: an upload whose `Done` arrived ends while its worker finishes the
/// file. Stopped before the worker committed to putting it in place
/// (`Verified`: the sync, the hash), nothing of it lands, it has no `Done`
/// row and the summary does not count it. Stopped after (`Landing`: the
/// rename), the stop no longer takes it: it lands, its `Done` row (what the
/// app's `file_received` record takes) is told and the summary counts it,
/// the host claims no cancel for it, and on a stream still open the viewer
/// hears `Complete`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_lands_with_its_row_or_not_at_all() {
    let mut rig = rig();
    let kill = KillSwitch::new();
    let watcher = rig.media.watch_kill(kill.clone());
    let mut seed = 30u8;
    let mut landed: Vec<String> = Vec::new();
    for at in [Finishing::Verified, Finishing::Landing] {
        for end in [End::Close, End::Kill, End::HostCancel, End::InputLost] {
            seed += 1;
            let name = format!("f{seed}.bin");
            let lands = at == Finishing::Landing;
            let case = format!("{end:?} at {at:?}");
            let (session, mut client, task) = finishing(&mut rig, seed, &name, at).await;
            // The end, seen to be handled before the worker goes on.
            match end {
                End::Close => {
                    write_msg(
                        &mut client,
                        &SvcMsg::Close {
                            reason: reason::BY_VIEWER,
                        },
                    )
                    .await
                    .unwrap();
                    // Nothing is written back to a viewer that closed: the
                    // stream's end says the loop stopped its workers.
                    assert_eq!(next(&mut client).await, None, "{case}");
                }
                End::Kill => {
                    kill.kill(bye::PANIC);
                    assert_eq!(
                        next(&mut client).await,
                        Some(SvcMsg::Close {
                            reason: reason::ENDED_BY_HOST
                        }),
                        "{case}"
                    );
                }
                End::HostCancel => {
                    assert!(rig.services.cancel(&session.id, 1));
                    if !lands {
                        assert_eq!(
                            next(&mut client).await,
                            Some(cancel(1, reason::BY_HOST)),
                            "{case}"
                        );
                        assert_eq!(
                            rig.row(&session.id).await.state,
                            TransferState::Cancelled(reason::BY_HOST),
                            "{case}"
                        );
                    }
                    // The host's requests are served before the viewer's
                    // frames: once this line is heard, the stop was handled.
                    write_msg(&mut client, &chat("after")).await.unwrap();
                    assert!(
                        matches!(rig.event(&session.id).await, HostEvent::Chat(_)),
                        "{case}: no row"
                    );
                }
                End::InputLost => {
                    session.live(false);
                    if !lands {
                        assert_eq!(
                            next(&mut client).await,
                            Some(cancel(1, reason::TURNED_OFF)),
                            "{case}"
                        );
                        assert_eq!(
                            rig.row(&session.id).await.state,
                            TransferState::Cancelled(reason::TURNED_OFF),
                            "{case}"
                        );
                    }
                    assert_eq!(
                        next(&mut client).await,
                        Some(SvcMsg::Caps(Caps {
                            caps: caps::CHAT,
                            paused: 0
                        })),
                        "{case}"
                    );
                    assert!(
                        matches!(rig.event(&session.id).await, HostEvent::Caps { .. }),
                        "{case}: no row"
                    );
                }
            }
            rig.hold(None);
            if matches!(end, End::HostCancel | End::InputLost) {
                if lands {
                    assert_eq!(
                        next(&mut client).await,
                        Some(SvcMsg::Complete(Complete { xfer: 1 })),
                        "{case}"
                    );
                }
                drop(client);
            }
            let (_, summary, _) = served(task).await;
            let (rows, closed) = rows_until_closed(&mut rig, &session.id).await;
            assert_eq!(closed, summary, "{case}");
            assert_eq!(rows.len(), usize::from(lands), "{case}: the Done row");
            for row in &rows {
                assert_eq!(
                    row.state,
                    TransferState::Done {
                        stored: Untrusted::file_name(&name)
                    },
                    "{case}"
                );
                assert_eq!((row.size, row.done), (10, 10), "{case}");
            }
            let counted = if lands { (1, 10) } else { (0, 0) };
            assert_eq!((summary.files_in, summary.bytes_in), counted, "{case}");
            if lands {
                landed.push(name.clone());
                landed.sort();
            }
            let expected: Vec<&str> = landed.iter().map(String::as_str).collect();
            inbox_settles(&rig, &expected).await;
            if lands {
                assert_eq!(std::fs::read(rig.inbox().join(&name)).unwrap(), [9; 10]);
            }
        }
    }
    watcher.abort();
}

/// The same race left to run, as the review's attack sends it: `Done` and
/// `Close` back to back, twenty times. Whichever way each goes, the file is
/// in the inbox exactly when its `Done` row was told and the summary counts
/// it, and no part file is left.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn done_then_close_lands_with_its_row_or_not_at_all() {
    let mut rig = rig();
    let mut landed: Vec<String> = Vec::new();
    for seed in 60..80u8 {
        let session = start(&rig, seed, SessionMode::Control);
        session.live(true);
        let (mut client, task) = open(&rig.services);
        welcome(&mut client, &session).await;
        rig.event(&session.id).await;
        let name = format!("r{seed}.bin");
        write_msg(&mut client, &offer(1, &name, 10)).await.unwrap();
        assert_eq!(next(&mut client).await, Some(accepted(1, &name)));
        send_data(&mut client, 1, 0, &[seed; 10]).await;
        write_msg(&mut client, &done(1, &[seed; 10])).await.unwrap();
        write_msg(
            &mut client,
            &SvcMsg::Close {
                reason: reason::BY_VIEWER,
            },
        )
        .await
        .unwrap();
        let (_, summary, _) = served(task).await;
        let (rows, _) = rows_until_closed(&mut rig, &session.id).await;
        let lands = summary.files_in == 1;
        // A stream's end tells no row of an upload it stopped; one already
        // putting its file in place may still tell its progress first.
        let mut done = 0;
        for row in &rows {
            match &row.state {
                TransferState::Done { stored } => {
                    assert_eq!(*stored, Untrusted::file_name(&name), "seed {seed}");
                    assert_eq!((row.size, row.done), (10, 10), "seed {seed}");
                    done += 1;
                }
                TransferState::Running => {}
                other => panic!("seed {seed}: {other:?}"),
            }
        }
        assert_eq!(done, usize::from(lands), "seed {seed}");
        assert_eq!(summary.bytes_in, if lands { 10 } else { 0 }, "seed {seed}");
        if lands {
            landed.push(name);
            landed.sort();
        }
        let expected: Vec<&str> = landed.iter().map(String::as_str).collect();
        assert_eq!(inbox_names(&rig), expected, "seed {seed}");
    }
}

/// A rename that outlasts the stream end's wait for its workers: `serve`
/// returns, its summary without the file, and once the file lands its
/// `Done` row is still told, after `Closed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_landing_after_the_end_is_still_told() {
    let mut rig = rig_with(Build {
        limits: ServicesLimits {
            workers_wait: Duration::from_millis(100),
            ..ServicesLimits::default()
        },
        ..Build::default()
    });
    let kill = KillSwitch::new();
    let watcher = rig.media.watch_kill(kill.clone());
    let (session, mut client, task) = finishing(&mut rig, 90, "slow.bin", Finishing::Landing).await;
    kill.kill(bye::PANIC);
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Close {
            reason: reason::ENDED_BY_HOST
        })
    );
    let (code, summary, _) = served(task).await;
    assert_eq!(code, reason::ENDED_BY_HOST);
    assert_eq!(summary.files_in, 0, "not in place yet");
    let (rows, _) = rows_until_closed(&mut rig, &session.id).await;
    assert!(rows.is_empty());
    assert_eq!(inbox_names(&rig), ["slow.bin", "slow.bin.tornect-part"]);
    rig.hold(None);
    let row = rig.row(&session.id).await;
    assert_eq!(
        row.state,
        TransferState::Done {
            stored: Untrusted::file_name("slow.bin")
        }
    );
    inbox_settles(&rig, &["slow.bin"]).await;
    watcher.abort();
}

/// An `Offer` the reader decoded and queued just before the viewer's input
/// was lost is dropped, as the reader skips such a frame from then on: no
/// worker starts, nothing is reserved in the inbox, the viewer hears no
/// `Accepted` and the host's user sees no row. On one thread the reader
/// queues the `Offer` before the loop runs, and the loop takes the
/// capture's news first.
#[tokio::test(flavor = "current_thread")]
async fn an_offer_queued_before_the_input_was_lost_starts_nothing() {
    let mut rig = rig();
    let session = start(&rig, 95, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    welcome(&mut client, &session).await;
    rig.event(&session.id).await;
    write_msg(&mut client, &offer(1, "late.bin", 10))
        .await
        .unwrap();
    session.live(false);
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Caps(Caps {
            caps: caps::CHAT,
            paused: 0
        }))
    );
    assert!(matches!(
        rig.event(&session.id).await,
        HostEvent::Caps { .. }
    ));
    write_msg(&mut client, &chat("still here")).await.unwrap();
    assert!(
        matches!(rig.event(&session.id).await, HostEvent::Chat(_)),
        "no row"
    );
    // Time for a worker, had one started, to reserve the name.
    tokio::time::sleep(QUIET).await;
    assert_eq!(inbox_names(&rig), Vec::<String>::new());
    write_msg(
        &mut client,
        &SvcMsg::Close {
            reason: reason::BY_VIEWER,
        },
    )
    .await
    .unwrap();
    assert_eq!(next(&mut client).await, None, "no Accepted");
    let (_, summary, frames) = served(task).await;
    assert_eq!(summary.files_in, 0);
    assert_eq!(frames.decoded, 3, "the Offer, the chat line and the Close");
    let (rows, _) = rows_until_closed(&mut rig, &session.id).await;
    assert!(rows.is_empty());
}

/// Offers and cancels sent at stream speed against workers stuck on a slow
/// disk: the worker of an upload stopped before it ended counts toward the
/// two places until it ended, so a third offer is `BUSY` and no third worker
/// starts; once the stuck ones ended, an offer is taken again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_upload_holds_its_place_until_its_worker_ended() {
    let mut rig = rig();
    let session = start(&rig, 100, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    welcome(&mut client, &session).await;
    rig.event(&session.id).await;
    rig.stall.store(true, Ordering::SeqCst);
    for xfer in [1, 2] {
        write_msg(&mut client, &offer(xfer, "s.bin", 10))
            .await
            .unwrap();
        write_msg(&mut client, &cancel(xfer, reason::BY_VIEWER))
            .await
            .unwrap();
    }
    for xfer in 3..=6 {
        write_msg(&mut client, &offer(xfer, "s.bin", 10))
            .await
            .unwrap();
        assert_eq!(next(&mut client).await, Some(cancel(xfer, reason::BUSY)));
    }
    let deadline = tokio::time::Instant::now() + WAIT;
    while rig.stalled.load(Ordering::SeqCst) < 2 {
        assert!(tokio::time::Instant::now() < deadline, "two workers wait");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    tokio::time::sleep(QUIET).await;
    assert_eq!(rig.stalled.load(Ordering::SeqCst), 2, "no third worker");
    rig.stall.store(false, Ordering::SeqCst);
    // Once the stuck workers ended, an offer is taken again.
    let mut xfer = 7;
    loop {
        write_msg(&mut client, &offer(xfer, "t.bin", 1))
            .await
            .unwrap();
        match next(&mut client).await {
            Some(SvcMsg::Accepted(took)) => {
                assert_eq!(took.xfer, xfer);
                break;
            }
            other => {
                assert_eq!(other, Some(cancel(xfer, reason::BUSY)));
                assert!(tokio::time::Instant::now() < deadline, "still busy");
                tokio::time::sleep(Duration::from_millis(5)).await;
                xfer += 1;
            }
        }
    }
    drop(client);
    served(task).await;
    inbox_settles(&rig, &[]).await;
}

/// The host's order checks, each ending the stream with `Close{PROTOCOL}`
/// and leaving nothing in the inbox: `Data` or `Done` before `Accepted` (the
/// worker held on a slow disk before it took the file), a second `Done` or
/// `Data` after `Done` (the worker held as it finishes the file), and `Data`
/// past the announced size.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_frames_out_of_order_end_the_stream() {
    let mut rig = rig();
    let protocol = Some(SvcMsg::Close {
        reason: reason::PROTOCOL,
    });
    let data = |offset: u64, bytes: &[u8]| SvcMsg::Data {
        xfer: 1,
        offset,
        bytes: bytes.to_vec(),
    };

    // Before `Accepted`.
    for (seed, early) in [(110, data(0, &[1; 10])), (111, done(1, &[1; 10]))] {
        let kind = early.ty();
        let session = start(&rig, seed, SessionMode::Control);
        session.live(true);
        let (mut client, task) = open(&rig.services);
        welcome(&mut client, &session).await;
        rig.event(&session.id).await;
        rig.stalled.store(0, Ordering::SeqCst);
        rig.stall.store(true, Ordering::SeqCst);
        write_msg(&mut client, &offer(1, "early.bin", 10))
            .await
            .unwrap();
        rig.stalled().await;
        write_msg(&mut client, &early).await.unwrap();
        assert_eq!(next(&mut client).await, protocol, "0x{kind:02x}");
        rig.stall.store(false, Ordering::SeqCst);
        assert_eq!(served(task).await.0, reason::PROTOCOL);
        inbox_settles(&rig, &[]).await;
    }

    // After `Done`: a second `Done`, and `Data` (one byte past the end,
    // which no `Data` after a whole file's `Done` can avoid).
    for (seed, late) in [(112, done(1, &[9; 10])), (113, data(10, &[1]))] {
        let kind = late.ty();
        let (_, mut client, task) =
            finishing(&mut rig, seed, "late.bin", Finishing::Verified).await;
        write_msg(&mut client, &late).await.unwrap();
        assert_eq!(next(&mut client).await, protocol, "0x{kind:02x}");
        rig.hold(None);
        assert_eq!(served(task).await.0, reason::PROTOCOL);
        inbox_settles(&rig, &[]).await;
    }

    // Past the size.
    let session = start(&rig, 114, SessionMode::Control);
    session.live(true);
    let (mut client, task) = open(&rig.services);
    welcome(&mut client, &session).await;
    write_msg(&mut client, &offer(1, "past.bin", 10))
        .await
        .unwrap();
    assert_eq!(next(&mut client).await, Some(accepted(1, "past.bin")));
    send_data(&mut client, 1, 0, &[1; 11]).await;
    assert_eq!(next(&mut client).await, protocol);
    assert_eq!(served(task).await.0, reason::PROTOCOL);
    inbox_settles(&rig, &[]).await;
}

/// The viewer's checks of the host's upload frames, each ending the stream
/// with `Close{PROTOCOL}`: `Credit` or `Complete` before `Accepted`,
/// `Accepted` twice, and `Complete` or `Credit` for an id never offered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_viewer_refuses_upload_frames_out_of_order() {
    let local = tempfile::tempdir().unwrap();
    let path = local.path().join("v.bin");
    std::fs::write(&path, [4u8; 10]).unwrap();
    let cases = [
        (
            "Credit before Accepted",
            true,
            vec![SvcMsg::Credit { xfer: 1, upto: 0 }],
        ),
        (
            "Complete before Accepted",
            true,
            vec![SvcMsg::Complete(Complete { xfer: 1 })],
        ),
        (
            "Accepted twice",
            true,
            vec![accepted(1, "v.bin"), accepted(1, "v.bin")],
        ),
        (
            "Complete of an id never offered",
            false,
            vec![SvcMsg::Complete(Complete { xfer: 9 })],
        ),
        (
            "Credit of an id never offered",
            false,
            vec![SvcMsg::Credit { xfer: 9, upto: 0 }],
        ),
    ];
    for (case, upload, frames) in cases {
        let (mut host, bound) = raw_host(
            Some(SvcMsg::Welcome(test_welcome(caps::CHAT | caps::UPLOAD))),
            WAIT,
        )
        .await;
        let v = run_viewer(bound.unwrap().0);
        if upload {
            v.ops
                .send(ViewerOp::UploadPath(path.clone()))
                .await
                .unwrap();
            assert_eq!(next(&mut host).await, Some(offer(1, "v.bin", 10)), "{case}");
        }
        for frame in &frames {
            write_msg(&mut host, frame).await.unwrap();
        }
        // What the viewer sent meanwhile (the file, after a first
        // `Accepted`), then its `Close`.
        loop {
            match next(&mut host).await {
                Some(SvcMsg::Data { .. } | SvcMsg::Done(_)) => {}
                Some(SvcMsg::Close {
                    reason: reason::PROTOCOL,
                }) => break,
                other => panic!("{case}: {other:?}"),
            }
        }
        assert_eq!(
            v.task.await.unwrap(),
            ViewerServicesEnd::Refused(reason::PROTOCOL),
            "{case}"
        );
    }
}

/// The viewer's `Cancel` of an upload goes out before any byte the window
/// it frees lets another upload send: the host counts the cancelled
/// upload's bytes in flight until it hears the `Cancel`, and would take such
/// a byte for one beyond the window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_goes_out_before_what_its_window_frees() {
    let mut granted = test_welcome(caps::CHAT | caps::UPLOAD);
    granted.bulk_window = 256 * 1024;
    let (mut host, bound) = raw_host(Some(SvcMsg::Welcome(granted)), WAIT).await;
    let v = run_viewer(bound.unwrap().0);
    let local = tempfile::tempdir().unwrap();
    for name in ["a.bin", "b.bin"] {
        let path = local.path().join(name);
        std::fs::write(&path, vec![6u8; 1 << 20]).unwrap();
        v.ops.send(ViewerOp::UploadPath(path)).await.unwrap();
    }
    assert_eq!(next(&mut host).await, Some(offer(1, "a.bin", 1 << 20)));
    assert_eq!(next(&mut host).await, Some(offer(2, "b.bin", 1 << 20)));
    write_msg(&mut host, &accepted(1, "a.bin")).await.unwrap();
    assert_eq!(data_until_quiet(&mut host, 1, 0).await, 256 * 1024);
    write_msg(&mut host, &accepted(2, "b.bin")).await.unwrap();
    assert_eq!(data_until_quiet(&mut host, 2, 0).await, 0, "no room");
    // Row 1 is the first file's.
    v.ops.send(ViewerOp::Cancel(1)).await.unwrap();
    assert_eq!(next(&mut host).await, Some(cancel(1, reason::BY_VIEWER)));
    assert!(matches!(
        next(&mut host).await,
        Some(SvcMsg::Data {
            xfer: 2,
            offset: 0,
            ..
        })
    ));
    v.stop.send(()).unwrap();
    assert_eq!(v.task.await.unwrap(), ViewerServicesEnd::Stopped);
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
