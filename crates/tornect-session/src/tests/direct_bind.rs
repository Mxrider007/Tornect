//! The direct path's media bind (the direct design §6.6, §8.5, §12.1 "proto
//! and session bind"), host side: `MediaHost::serve_direct` over a pipe that
//! stands for a direct connection's stream, beside the onion `serve`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tornect_core::levels::Elevation;
use tornect_core::session_log::TransportKind;
use tornect_proto::{BindSide, bind_mac, bind_mac_direct};
use tornect_signal::consent::TransportPolicy;
use zeroize::Zeroizing;

use super::*;

/// The exporter output both ends of a test connection share.
const EKM: [u8; 32] = [0x33; 32];

/// One end of a pipe standing for a direct connection's stream; it
/// remembers the code its connection was closed with by a refusal.
struct TestLink {
    pipe: DuplexStream,
    closed_with: Arc<Mutex<Option<u16>>>,
}

impl AsyncRead for TestLink {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_read(cx, buf)
    }
}

impl AsyncWrite for TestLink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.pipe).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_shutdown(cx)
    }
}

impl DirectStream for TestLink {
    async fn refuse(mut self, frame: Vec<u8>, code: u16) {
        let _ = self.pipe.write_all(&frame).await;
        let _ = self.pipe.shutdown().await;
        *self.closed_with.lock().unwrap() = Some(code);
    }
}

/// Records the route of every `capture_started`.
#[derive(Default)]
struct Routes(Mutex<Vec<TransportKind>>);

impl Routes {
    fn started(&self) -> Vec<TransportKind> {
        self.0.lock().unwrap().clone()
    }
}

impl MediaObserver for Routes {
    fn capture_started(&self, started: &CaptureStarted<'_>) {
        self.0.lock().unwrap().push(started.route);
    }

    fn capture_stopped(&self, _: &str, _: &MediaReport, _: &MediaEnd) {}
}

struct DirectRig {
    host: Arc<MediaHost>,
    backend: Arc<TestBackend>,
    routes: Arc<Routes>,
}

fn direct_rig(backend: TestBackend) -> DirectRig {
    let backend = Arc::new(backend);
    let routes = Arc::new(Routes::default());
    DirectRig {
        host: Arc::new(MediaHost::new(
            backend.clone(),
            routes.clone(),
            MediaLimits::default(),
        )),
        backend,
        routes,
    }
}

impl DirectRig {
    fn sources(&self) -> usize {
        self.backend.sources.load(Ordering::SeqCst)
    }
}

/// A session as the FSM registers it, with what its viewer knows.
struct Viewer {
    id: String,
    token: SessionToken,
    th_final: [u8; 32],
    device: DeviceId,
}

impl Viewer {
    /// The direct `Bind` over `ekm`.
    fn bind(&self, ekm: &[u8; 32]) -> Msg {
        self.bind_with(bind_mac_direct(
            self.token.bytes(),
            &self.th_final,
            ekm,
            BindSide::Client,
        ))
    }

    /// A `Bind` of this session carrying `mac`.
    fn bind_with(&self, mac: [u8; 32]) -> Msg {
        Msg::Bind {
            session_id: self.id.clone(),
            mac,
            quality: quality::BALANCED,
        }
    }

    /// The host's `BindProof` over `ekm`.
    fn proof(&self, ekm: &[u8; 32]) -> Msg {
        Msg::BindProof {
            mac: bind_mac_direct(self.token.bytes(), &self.th_final, ekm, BindSide::Server),
        }
    }

    /// The onion stream's binding.
    fn onion(&self) -> Binding {
        Binding::new(&self.token, &self.th_final)
    }
}

/// Register session `seed` (device, token and transcript from it) under the
/// signed `transport` policy.
fn start_direct(host: &MediaHost, seed: u8, transport: TransportPolicy) -> Viewer {
    let token = SessionToken::new([seed; 32]);
    let th_final = [!seed; 32];
    let id = token.session_id();
    let device = DeviceId::from_bytes([seed; 32]);
    host.on_start(&LiveSession {
        device,
        label: "Laptop",
        session_id: &id,
        token: &token,
        th_final,
        mode: SessionMode::Control,
        elevation: Elevation::None,
        unattended: false,
        transport,
        viewer_dir1: true,
    });
    Viewer {
        id,
        token,
        th_final,
        device,
    }
}

/// The viewer's end of a direct stream served on its own task.
struct DirectConn {
    client: DuplexStream,
    served: JoinHandle<MediaOutcome>,
    closed_with: Arc<Mutex<Option<u16>>>,
}

/// A direct stream of the link made for `link_session` with the device
/// `peer`, whose exporter output is `ekm`, on `route`; `room` bytes of pipe
/// each way.
fn connect_direct_with(
    host: &Arc<MediaHost>,
    link_session: &str,
    peer: DeviceId,
    ekm: [u8; 32],
    route: TransportKind,
    room: usize,
) -> DirectConn {
    let (client, pipe) = duplex(room);
    let closed_with = Arc::new(Mutex::new(None));
    let link = TestLink {
        pipe,
        closed_with: Arc::clone(&closed_with),
    };
    let host = Arc::clone(host);
    let session = link_session.to_owned();
    let served = tokio::spawn(async move {
        host.serve_direct(link, &session, peer, Zeroizing::new(ekm), route)
            .await
    });
    DirectConn {
        client,
        served,
        closed_with,
    }
}

fn connect_direct(
    host: &Arc<MediaHost>,
    viewer: &Viewer,
    ekm: [u8; 32],
    route: TransportKind,
) -> DirectConn {
    connect_direct_with(host, &viewer.id, viewer.device, ekm, route, 1 << 20)
}

/// Send `bind` on a direct stream and expect `BindRefused{code}`, the
/// connection closed with `code`, and nothing bound.
async fn refused_direct(mut conn: DirectConn, bind: &Msg, code: u16) {
    write_msg(&mut conn.client, bind).await.unwrap();
    assert_eq!(
        read_msg(&mut conn.client).await.unwrap(),
        Some(Msg::BindRefused { reason: code })
    );
    assert_eq!(read_msg(&mut conn.client).await.unwrap(), None);
    assert_eq!(conn.served.await.unwrap(), MediaOutcome::NotBound);
    assert_eq!(
        *conn.closed_with.lock().unwrap(),
        Some(code),
        "the connection's close code"
    );
}

/// The direct design §6.6: a valid direct `Bind` is answered with
/// `BindProof` (the server MAC over the same `ekm`) before `BindOk`; the
/// claim is published as `Direct`, and the observer hears the route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_bind_is_answered_with_its_proof_first() {
    let rig = direct_rig(TestBackend::default());
    let viewer = start_direct(&rig.host, 60, TransportPolicy::Any);
    let mut claimed = rig.host.claimed(&viewer.id).expect("registered");
    assert_eq!(*claimed.borrow_and_update(), None);
    assert_eq!(rig.host.route(&viewer.id), None);

    let mut conn = connect_direct(&rig.host, &viewer, EKM, TransportKind::Direct);
    write_msg(&mut conn.client, &viewer.bind(&EKM))
        .await
        .unwrap();
    assert_eq!(
        read_msg(&mut conn.client).await.unwrap(),
        Some(viewer.proof(&EKM)),
        "the proof is the first host frame"
    );
    assert!(matches!(
        read_msg(&mut conn.client).await.unwrap(),
        Some(Msg::BindOk { .. })
    ));
    next_video(&mut conn.client).await;
    claimed.changed().await.unwrap();
    assert_eq!(*claimed.borrow_and_update(), Some(TransportKind::Direct));
    assert_eq!(rig.host.route(&viewer.id), Some(TransportKind::Direct));
    assert_eq!(rig.routes.started(), [TransportKind::Direct]);
    assert_eq!(rig.sources(), 1);

    drop(conn.client);
    assert!(matches!(
        conn.served.await.unwrap(),
        MediaOutcome::Served {
            end: MediaEnd::ViewerLeft | MediaEnd::Io,
            ..
        }
    ));
    assert_eq!(*conn.closed_with.lock().unwrap(), None, "no refusal");
}

/// The proof never waits on the desktop: it is written while the source's
/// open (the portal's dialog here) is still up, and an end that comes then
/// still cancels the open (revision 1 blocker 1; slice-G G1-1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_proof_is_written_before_the_source_opens() {
    let rig = direct_rig(TestBackend {
        open_waits: true,
        ..TestBackend::default()
    });
    let viewer = start_direct(&rig.host, 61, TransportPolicy::Any);
    let mut conn = connect_direct(&rig.host, &viewer, EKM, TransportKind::Direct);
    write_msg(&mut conn.client, &viewer.bind(&EKM))
        .await
        .unwrap();
    let proof = tokio::time::timeout(Duration::from_secs(2), read_msg(&mut conn.client))
        .await
        .expect("the proof does not wait for the dialog")
        .unwrap();
    assert_eq!(proof, Some(viewer.proof(&EKM)));
    // The dialog is up: the open has started and has not ended.
    let started = tokio::time::Instant::now();
    while rig.sources() == 0 {
        assert!(started.elapsed() < WAIT, "the open never started");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!rig.backend.cancelled.load(Ordering::SeqCst));

    rig.host.on_end(&viewer.id, None);
    assert_eq!(
        read_msg(&mut conn.client).await.unwrap(),
        Some(Msg::BindRefused {
            reason: reason::SESSION_OVER
        })
    );
    assert_eq!(
        conn.served.await.unwrap(),
        MediaOutcome::NotStarted(MediaEnd::SessionOver(reason::SESSION_OVER))
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while !rig.backend.cancelled.load(Ordering::SeqCst) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the open was not cancelled"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(rig.routes.started().is_empty());
}

/// A session that ends while the proof waits on a viewer that does not
/// read ends the stream at once, with nothing opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_end_while_the_proof_waits_opens_nothing() {
    let rig = direct_rig(TestBackend::default());
    let viewer = start_direct(&rig.host, 62, TransportPolicy::Any);
    let conn = connect_direct_with(
        &rig.host,
        &viewer.id,
        viewer.device,
        EKM,
        TransportKind::Direct,
        8,
    );
    let DirectConn { client, served, .. } = conn;
    let (mut rd, mut wr) = tokio::io::split(client);
    let bind = viewer.bind(&EKM);
    let writer = tokio::spawn(async move {
        write_msg(&mut wr, &bind).await.unwrap();
        wr
    });
    let _wr = writer.await.unwrap();
    // The 37-byte proof fills the 8-byte pipe and waits; the session ends.
    let claimed = tokio::time::Instant::now();
    while rig.host.route(&viewer.id).is_none() {
        assert!(claimed.elapsed() < WAIT, "never claimed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    rig.host.on_end(&viewer.id, None);
    let outcome = tokio::time::timeout(WAIT, served).await.unwrap().unwrap();
    assert_eq!(
        outcome,
        MediaOutcome::NotStarted(MediaEnd::SessionOver(reason::SESSION_OVER))
    );
    assert_eq!(rig.sources(), 0, "nothing opened");
    let mut head = [0u8; 8];
    rd.read_exact(&mut head).await.unwrap();
    assert_eq!(&head[..5], &[0, 0, 0, 33, 0x04], "the proof's first bytes");
}

/// The direct design §12.1: a wrong `ekm`, device, token, transcript or
/// session id, and every MAC made for something else, is refused with
/// `BindRefused{BAD_BIND}` before anything opens, and the connection is
/// closed with that code; the real viewer can still bind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_direct_bind_is_refused_before_capture() {
    let rig = direct_rig(TestBackend::default());
    let viewer = start_direct(&rig.host, 63, TransportPolicy::Any);
    let other = start_direct(&rig.host, 64, TransportPolicy::Any);
    let token = viewer.token.bytes();
    let th = &viewer.th_final;
    let cases: Vec<(&str, DeviceId, &str, Msg)> = vec![
        (
            "another connection's ekm",
            viewer.device,
            &viewer.id,
            viewer.bind(&[0x34; 32]),
        ),
        (
            "another device's connection",
            DeviceId::from_bytes([99; 32]),
            &viewer.id,
            viewer.bind(&EKM),
        ),
        (
            "another token",
            viewer.device,
            &viewer.id,
            viewer.bind_with(bind_mac_direct(&[64; 32], th, &EKM, BindSide::Client)),
        ),
        (
            "another transcript",
            viewer.device,
            &viewer.id,
            viewer.bind_with(bind_mac_direct(token, &[0; 32], &EKM, BindSide::Client)),
        ),
        (
            "another session's valid bind on this session's link",
            other.device,
            &viewer.id,
            other.bind(&EKM),
        ),
        (
            "the onion MAC",
            viewer.device,
            &viewer.id,
            viewer.bind_with(bind_mac(token, th)),
        ),
        (
            "the host's own proof reflected",
            viewer.device,
            &viewer.id,
            viewer.bind_with(bind_mac_direct(token, th, &EKM, BindSide::Server)),
        ),
        (
            "the direct services MAC",
            viewer.device,
            &viewer.id,
            viewer.bind_with(tornect_proto::services::services_bind_mac_direct(
                token, th, &EKM,
            )),
        ),
    ];
    for (what, peer, link_session, bind) in cases {
        let conn = connect_direct_with(
            &rig.host,
            link_session,
            peer,
            EKM,
            TransportKind::Direct,
            1 << 20,
        );
        refused_direct(conn, &bind, reason::BAD_BIND).await;
        assert_eq!(rig.sources(), 0, "{what}: nothing opened");
        assert_eq!(rig.host.route(&viewer.id), None, "{what}");
        assert_eq!(rig.host.route(&other.id), None, "{what}");
    }

    let mut conn = connect_direct(&rig.host, &viewer, EKM, TransportKind::Direct);
    write_msg(&mut conn.client, &viewer.bind(&EKM))
        .await
        .unwrap();
    assert_eq!(
        read_msg(&mut conn.client).await.unwrap(),
        Some(viewer.proof(&EKM))
    );
    assert!(matches!(
        read_msg(&mut conn.client).await.unwrap(),
        Some(Msg::BindOk { .. })
    ));
    assert_eq!(rig.sources(), 1);
    drop(conn.client);
    conn.served.await.unwrap();
}

/// The signed policy decides the paths (the direct design §6.6 check 4,
/// §9.2): a `tor_only` session refuses every direct `Bind` with
/// `TRANSPORT`, a forged one too, and still binds on the onion path; a
/// `lan_only` session refuses a direct-internet `Bind` and an onion one with
/// `TRANSPORT`, and binds a same-site one; a direct proof on no direct path
/// is refused. Nothing opens for a refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_signed_policy_refuses_the_paths_it_forbids() {
    let rig = direct_rig(TestBackend::default());

    let tor_only = start_direct(&rig.host, 65, TransportPolicy::TorOnly);
    for route in [TransportKind::Direct, TransportKind::Lan] {
        let conn = connect_direct(&rig.host, &tor_only, EKM, route);
        refused_direct(conn, &tor_only.bind(&EKM), reason::TRANSPORT).await;
    }
    let forged = tor_only.bind_with([0; 32]);
    let conn = connect_direct(&rig.host, &tor_only, EKM, TransportKind::Direct);
    refused_direct(conn, &forged, reason::TRANSPORT).await;
    assert_eq!(rig.sources(), 0);

    let lan_only = start_direct(&rig.host, 66, TransportPolicy::LanOnly);
    let conn = connect_direct(&rig.host, &lan_only, EKM, TransportKind::Direct);
    refused_direct(conn, &lan_only.bind(&EKM), reason::TRANSPORT).await;
    let (client, served) = connect(&rig.host);
    let refused = MediaViewer::bind(client, &lan_only.onion(), WAIT)
        .await
        .unwrap_err();
    assert!(
        matches!(refused, ViewerError::Refused(r) if r == reason::TRANSPORT),
        "{refused:?}"
    );
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);

    let any = start_direct(&rig.host, 67, TransportPolicy::Any);
    let conn = connect_direct(&rig.host, &any, EKM, TransportKind::TorRelay);
    refused_direct(conn, &any.bind(&EKM), reason::TRANSPORT).await;
    assert_eq!(rig.sources(), 0, "nothing opened for a refusal");
    assert_eq!(rig.host.route(&any.id), None);

    // Each refusal left its session unbound: the allowed path still binds.
    let (client, served) = connect(&rig.host);
    let onion = MediaViewer::bind(client, &tor_only.onion(), WAIT)
        .await
        .unwrap();
    drop(onion);
    served.await.unwrap();
    let mut conn = connect_direct(&rig.host, &lan_only, EKM, TransportKind::Lan);
    write_msg(&mut conn.client, &lan_only.bind(&EKM))
        .await
        .unwrap();
    assert_eq!(
        read_msg(&mut conn.client).await.unwrap(),
        Some(lan_only.proof(&EKM))
    );
    assert!(matches!(
        read_msg(&mut conn.client).await.unwrap(),
        Some(Msg::BindOk { .. })
    ));
    // The observer hears of capture before the first picture goes out.
    next_video(&mut conn.client).await;
    assert_eq!(rig.host.route(&tor_only.id), Some(TransportKind::TorRelay));
    assert_eq!(rig.host.route(&lan_only.id), Some(TransportKind::Lan));
    assert_eq!(
        rig.routes.started(),
        [TransportKind::TorRelay, TransportKind::Lan]
    );
    drop(conn.client);
    conn.served.await.unwrap();
}

/// The `Bind` is single-use across both paths: once the direct path claimed
/// a session, an onion `Bind` (the viewer's fallback arriving late) and a
/// second direct one are refused, the claim is not published again, and the
/// direct stream goes on (revision 1 blocker 1: a late fallback changes
/// nothing). Once the onion path claimed a session, its claim reads
/// `TorRelay` and a direct `Bind` is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_is_single_use_across_both_paths() {
    let rig = direct_rig(TestBackend::default());
    let viewer = start_direct(&rig.host, 68, TransportPolicy::Any);
    let mut claimed = rig.host.claimed(&viewer.id).unwrap();
    claimed.borrow_and_update();
    let mut conn = connect_direct(&rig.host, &viewer, EKM, TransportKind::Direct);
    write_msg(&mut conn.client, &viewer.bind(&EKM))
        .await
        .unwrap();
    assert_eq!(
        read_msg(&mut conn.client).await.unwrap(),
        Some(viewer.proof(&EKM))
    );
    next_video(&mut conn.client).await;
    claimed.changed().await.unwrap();
    assert_eq!(*claimed.borrow_and_update(), Some(TransportKind::Direct));

    let (client, served) = connect(&rig.host);
    let refused = MediaViewer::bind(client, &viewer.onion(), WAIT)
        .await
        .unwrap_err();
    assert!(matches!(refused, ViewerError::Refused(r) if r == reason::BAD_BIND));
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
    let again = connect_direct(&rig.host, &viewer, EKM, TransportKind::Direct);
    refused_direct(again, &viewer.bind(&EKM), reason::BAD_BIND).await;

    assert!(!claimed.has_changed().unwrap(), "claimed once");
    assert_eq!(rig.host.route(&viewer.id), Some(TransportKind::Direct));
    next_video(&mut conn.client).await;
    assert_eq!(rig.sources(), 1, "one capture");
    drop(conn.client);
    assert!(matches!(
        conn.served.await.unwrap(),
        MediaOutcome::Served { .. }
    ));

    // The onion path first.
    let onion_first = start_direct(&rig.host, 69, TransportPolicy::Any);
    let mut claimed = rig.host.claimed(&onion_first.id).unwrap();
    claimed.borrow_and_update();
    let (client, served) = connect(&rig.host);
    let onion = MediaViewer::bind(client, &onion_first.onion(), WAIT)
        .await
        .unwrap();
    claimed.changed().await.unwrap();
    assert_eq!(*claimed.borrow_and_update(), Some(TransportKind::TorRelay));
    let late = connect_direct(&rig.host, &onion_first, EKM, TransportKind::Direct);
    refused_direct(late, &onion_first.bind(&EKM), reason::BAD_BIND).await;
    assert_eq!(rig.sources(), 2);
    drop(onion);
    served.await.unwrap();
}

/// The direct design §8.5: a stream that closes before its first byte (the
/// viewer's unused onion pre-open) is `Abandoned`, on either path, and
/// leaves its session unbound; one that closes after part of a frame is
/// `NotBound` as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_closed_before_any_byte_is_abandoned() {
    let rig = direct_rig(TestBackend::default());
    let viewer = start_direct(&rig.host, 70, TransportPolicy::Any);

    let (client, served) = connect(&rig.host);
    drop(client);
    assert_eq!(served.await.unwrap(), MediaOutcome::Abandoned);
    let conn = connect_direct(&rig.host, &viewer, EKM, TransportKind::Direct);
    drop(conn.client);
    assert_eq!(conn.served.await.unwrap(), MediaOutcome::Abandoned);
    assert_eq!(*conn.closed_with.lock().unwrap(), None);

    let (mut client, served) = connect(&rig.host);
    client.write_all(&[0, 0]).await.unwrap();
    drop(client);
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
    assert_eq!(rig.sources(), 0);
    assert_eq!(rig.host.route(&viewer.id), None);

    let (client, served) = connect(&rig.host);
    let onion = MediaViewer::bind(client, &viewer.onion(), WAIT)
        .await
        .unwrap();
    drop(onion);
    served.await.unwrap();
}

/// The claim channel follows the session: `None` for a session not
/// registered, and closed once it ends.
#[tokio::test]
async fn the_claim_channel_closes_when_the_session_ends() {
    let rig = direct_rig(TestBackend::default());
    assert!(rig.host.claimed("0000000000000000").is_none());
    let viewer = start_direct(&rig.host, 71, TransportPolicy::Any);
    let mut claimed = rig.host.claimed(&viewer.id).unwrap();
    rig.host.on_end(&viewer.id, None);
    assert!(claimed.changed().await.is_err(), "closed, never claimed");
    assert_eq!(*claimed.borrow(), None);
    assert!(rig.host.claimed(&viewer.id).is_none());
    assert_eq!(rig.host.route(&viewer.id), None);
}
