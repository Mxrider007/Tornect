//! The direct path's media bind (the direct design §6.6, §8.5, §12.1 "proto
//! and session bind"). Host side (step A14): `MediaHost::serve_direct` over
//! a pipe that stands for a direct connection's stream, beside the onion
//! `serve`. Viewer side (step A15): `Binding::direct` and the `BindProof`
//! check in `MediaViewer::bind`, against the host and against scripted
//! hosts, and `after_bind_close` on in-memory QUIC links (`MemNet`).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tornect_core::levels::Elevation;
use tornect_core::session_log::TransportKind;
use tornect_net::mem::{LinkSpec, MachineSpec, MemNet};
use tornect_net::{DirectLink, DirectParams, LocalBatch, NetEnv, Scope, TornectRole};
use tornect_proto::{BindSide, ProtoError, bind_mac, bind_mac_direct};
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
    start_direct_for(host, seed, transport, DeviceId::from_bytes([seed; 32]))
}

/// [`start_direct`] for the paired `device`.
fn start_direct_for(
    host: &MediaHost,
    seed: u8,
    transport: TransportPolicy,
    device: DeviceId,
) -> Viewer {
    let token = SessionToken::new([seed; 32]);
    let th_final = [!seed; 32];
    let id = token.session_id();
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
///
/// The end comes only once the viewer has read the proof's first bytes:
/// the write has started and is stalled on the rest, past `send`'s first
/// look at the session's end. An end that came between the claim and that
/// look would end the stream before the proof (also with nothing opened),
/// which is not the case this test is about.
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
    // The 37-byte proof fills the 8-byte pipe and waits: its first 8 bytes
    // are read, the next 8 fill the pipe again and 21 are left.
    let mut head = [0u8; 8];
    tokio::time::timeout(WAIT, rd.read_exact(&mut head))
        .await
        .expect("the proof's write started")
        .unwrap();
    assert_eq!(&head[..5], &[0, 0, 0, 33, 0x04], "the proof's first bytes");
    assert_eq!(rig.host.route(&viewer.id), Some(TransportKind::Direct));
    rig.host.on_end(&viewer.id, None);
    let outcome = tokio::time::timeout(WAIT, served).await.unwrap().unwrap();
    assert_eq!(
        outcome,
        MediaOutcome::NotStarted(MediaEnd::SessionOver(reason::SESSION_OVER))
    );
    assert_eq!(rig.sources(), 0, "nothing opened");
    assert!(rig.routes.started().is_empty());
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

/// The onion media port, which anyone with the Tornect ID can dial, tells a
/// `Bind` whose MAC does not verify nothing of its session's policy: a wrong
/// MAC, and the direct MAC of the same session, read `BAD_BIND` on a
/// `lan_only` session as on an `any` and a `tor_only` one, and leave the
/// session unbound. Only the right onion MAC reads `TRANSPORT` on the
/// `lan_only` session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_onion_bind_learns_the_policy_only_with_the_right_mac() {
    let rig = direct_rig(TestBackend::default());
    let sessions = [
        start_direct(&rig.host, 90, TransportPolicy::LanOnly),
        start_direct(&rig.host, 91, TransportPolicy::Any),
        start_direct(&rig.host, 92, TransportPolicy::TorOnly),
    ];
    for session in &sessions {
        for bind in [session.bind_with([0; 32]), session.bind(&EKM)] {
            let (mut client, served) = connect(&rig.host);
            write_msg(&mut client, &bind).await.unwrap();
            assert_eq!(
                read_msg(&mut client).await.unwrap(),
                Some(Msg::BindRefused {
                    reason: reason::BAD_BIND
                }),
                "session {}",
                session.id
            );
            assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
            assert_eq!(rig.host.route(&session.id), None);
        }
    }
    assert_eq!(rig.sources(), 0, "nothing opened for a refusal");

    let (client, served) = connect(&rig.host);
    let refused = MediaViewer::bind(client, &sessions[0].onion(), WAIT)
        .await
        .unwrap_err();
    assert!(
        matches!(refused, ViewerError::Refused(r) if r == reason::TRANSPORT),
        "{refused:?}"
    );
    assert_eq!(served.await.unwrap(), MediaOutcome::NotBound);
    assert_eq!(rig.sources(), 0);
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

/// The direct design §9.1 invariant 3, §8.5: the owner of a direct link
/// that subscribes after the onion path claimed the session still hears of
/// it from `changed()` alone, once; one that subscribed before hears of it
/// as it happens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_claim_before_the_subscription_still_changes_once() {
    let rig = direct_rig(TestBackend::default());
    let viewer = start_direct(&rig.host, 74, TransportPolicy::Any);
    let mut early = rig.host.claimed(&viewer.id).unwrap();
    assert!(!early.has_changed().unwrap(), "nothing claimed yet");
    let (client, served) = connect(&rig.host);
    let onion = MediaViewer::bind(client, &viewer.onion(), WAIT)
        .await
        .unwrap();

    let mut late = rig.host.claimed(&viewer.id).unwrap();
    tokio::time::timeout(WAIT, late.changed())
        .await
        .expect("a claim made before the subscription is news")
        .unwrap();
    assert_eq!(*late.borrow_and_update(), Some(TransportKind::TorRelay));
    assert!(!late.has_changed().unwrap(), "once");
    tokio::time::timeout(WAIT, early.changed())
        .await
        .expect("the claim as it happened")
        .unwrap();
    assert_eq!(*early.borrow_and_update(), Some(TransportKind::TorRelay));
    assert!(!early.has_changed().unwrap(), "once");

    drop(onion);
    served.await.unwrap();
}

/// A `lan_only` session refuses its onion services stream as it refuses
/// its onion media (`Proof::allowed_by` applies to both kinds): until step
/// B10 adds the direct services stream, a `lan_only` session has no chat,
/// files or clipboard (decision M1-85). An `any` or `tor_only` session's
/// onion services stream binds under the same MAC.
#[tokio::test]
async fn a_lan_only_session_binds_no_onion_services_stream() {
    let rig = direct_rig(TestBackend::default());
    let services_mac =
        |v: &Viewer| tornect_proto::services::services_bind_mac(v.token.bytes(), &v.th_final);
    let lan_only = start_direct(&rig.host, 75, TransportPolicy::LanOnly);
    assert!(
        rig.host
            .claim_services(&lan_only.id, &services_mac(&lan_only))
            .is_none()
    );
    for (seed, policy) in [(76, TransportPolicy::Any), (77, TransportPolicy::TorOnly)] {
        let viewer = start_direct(&rig.host, seed, policy);
        assert!(
            rig.host
                .claim_services(&viewer.id, &services_mac(&viewer))
                .is_some(),
            "{policy:?}"
        );
    }
    assert_eq!(rig.sources(), 0);
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

// The viewer's side (step A15).

/// The viewer's direct binding of `viewer`'s session on a connection whose
/// exporter output is `ekm`.
fn direct_binding(viewer: &Viewer, ekm: &[u8; 32]) -> Binding {
    Binding::direct(&viewer.token, &viewer.th_final, ekm)
}

/// `msg` as it travels.
async fn frame(msg: &Msg) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_msg(&mut bytes, msg).await.unwrap();
    bytes
}

/// A valid `BindOk`.
fn bind_ok() -> Msg {
    Msg::BindOk {
        width: 1280,
        height: 720,
        codec: codec::H264,
        mode: 0,
        quality: APPLIED,
    }
}

/// `MediaViewer::bind` with `binding` against a scripted host that reads
/// the `Bind` (it must be `binding`'s), then writes `first` followed by a
/// valid `BindOk` and holds the stream open; `None` closes the stream
/// instead.
async fn bind_scripted(
    binding: &Binding,
    first: Option<Vec<u8>>,
) -> Result<MediaViewer<DuplexStream>, ViewerError> {
    let (client, mut host) = duplex(1 << 16);
    let expected = binding.msg();
    tokio::spawn(async move {
        assert_eq!(read_msg(&mut host).await.unwrap(), Some(expected));
        let Some(first) = first else { return };
        host.write_all(&first).await.unwrap();
        // A viewer that refused the proof never reads this.
        let _ = write_msg(&mut host, &bind_ok()).await;
        while let Ok(Some(_)) = read_msg(&mut host).await {}
    });
    MediaViewer::bind(client, binding, WAIT).await
}

/// The direct design §6.6: the direct binding sends the client MAC over
/// the connection's `ekm`, reads the host's `BindProof`, then `BindOk`; the
/// host claims the session as `Direct`. Its `Debug` names the path and no
/// MAC.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_viewer_binds_once_the_host_proves_itself() {
    let rig = direct_rig(TestBackend::default());
    let viewer = start_direct(&rig.host, 80, TransportPolicy::Any);
    let binding = direct_binding(&viewer, &EKM);
    assert!(binding.is_direct());
    assert!(!viewer.onion().is_direct());
    assert_eq!(binding.msg(), viewer.bind(&EKM), "the client MAC over ekm");
    let shown = format!("{binding:?}");
    assert!(shown.contains("direct: true"), "{shown}");
    assert!(!shown.contains("mac"), "{shown}");

    let conn = connect_direct(&rig.host, &viewer, EKM, TransportKind::Direct);
    let bound = MediaViewer::bind(conn.client, &binding, WAIT)
        .await
        .unwrap();
    assert_eq!(bound.bound().mode, SessionMode::Control);
    assert_eq!(rig.host.route(&viewer.id), Some(TransportKind::Direct));
    assert_eq!(rig.sources(), 1);
    drop(bound);
    assert!(matches!(
        conn.served.await.unwrap(),
        MediaOutcome::Served { .. }
    ));
}

/// The direct design §6.6 (`HostProof` before `BindOk`): a host whose
/// first frame is not the expected `BindProof` (one over another
/// connection's `ekm` or another transcript, the viewer's own MAC
/// reflected, `BindOk` with no proof, anything else, or a proof that does
/// not parse) has not proved itself; the `BindOk` that follows is never
/// read. A refusal in the proof's place is the host's reason, and a host
/// that closes is `Closed`. The expected proof binds.
#[tokio::test]
async fn a_host_that_does_not_prove_itself_is_refused_before_bind_ok() {
    let viewer = Viewer {
        id: SessionToken::new([81; 32]).session_id(),
        token: SessionToken::new([81; 32]),
        th_final: [!81; 32],
        device: DeviceId::from_bytes([81; 32]),
    };
    let binding = direct_binding(&viewer, &EKM);
    let token = viewer.token.bytes();
    let th = &viewer.th_final;
    let mut malformed = vec![0, 0, 0, 32, 0x04];
    malformed.extend_from_slice(&[0x5a; 31]);
    let not_proven: Vec<(&str, Vec<u8>)> = vec![
        (
            "a proof over another ekm",
            frame(&viewer.proof(&[0x34; 32])).await,
        ),
        (
            "a proof over another transcript",
            frame(&Msg::BindProof {
                mac: bind_mac_direct(token, &[0; 32], &EKM, BindSide::Server),
            })
            .await,
        ),
        (
            "the viewer's own MAC reflected",
            frame(&Msg::BindProof {
                mac: bind_mac_direct(token, th, &EKM, BindSide::Client),
            })
            .await,
        ),
        (
            "the onion MAC",
            frame(&Msg::BindProof {
                mac: bind_mac(token, th),
            })
            .await,
        ),
        ("BindOk with no proof", frame(&bind_ok()).await),
        ("a ping", frame(&Msg::Ping { nonce: 7 }).await),
        ("a proof that does not parse", malformed),
    ];
    for (what, first) in not_proven {
        let failed = bind_scripted(&binding, Some(first)).await.unwrap_err();
        assert!(
            matches!(failed, ViewerError::HostProof),
            "{what}: {failed:?}"
        );
    }

    let refused = frame(&Msg::BindRefused {
        reason: reason::TRANSPORT,
    })
    .await;
    let failed = bind_scripted(&binding, Some(refused)).await.unwrap_err();
    assert!(
        matches!(failed, ViewerError::Refused(r) if r == reason::TRANSPORT),
        "{failed:?}"
    );
    let protocol = frame(&Msg::BindRefused {
        reason: reason::PROTOCOL,
    })
    .await;
    let failed = bind_scripted(&binding, Some(protocol)).await.unwrap_err();
    assert!(matches!(failed, ViewerError::Version), "{failed:?}");
    let failed = bind_scripted(&binding, None).await.unwrap_err();
    assert!(matches!(failed, ViewerError::Closed), "{failed:?}");

    let proven = bind_scripted(&binding, Some(frame(&viewer.proof(&EKM)).await))
        .await
        .unwrap();
    assert_eq!(proven.bound().quality, APPLIED);

    // The onion binding expects no proof: one is an unexpected frame there.
    let failed = bind_scripted(&viewer.onion(), Some(frame(&viewer.proof(&EKM)).await))
        .await
        .unwrap_err();
    assert!(
        matches!(failed, ViewerError::Unexpected("BindProof")),
        "{failed:?}"
    );
}

/// The direct design §4: one bind wait covers the proof and `BindOk`; a
/// proof that comes late leaves only what is left of it for `BindOk`.
#[tokio::test(start_paused = true)]
async fn one_bind_wait_covers_the_proof_and_bind_ok() {
    let token = SessionToken::new([82; 32]);
    let th_final = [!82; 32];
    let binding = Binding::direct(&token, &th_final, &EKM);
    let proof = Msg::BindProof {
        mac: bind_mac_direct(token.bytes(), &th_final, &EKM, BindSide::Server),
    };
    let (client, mut host) = duplex(1 << 16);
    tokio::spawn(async move {
        read_msg(&mut host).await.unwrap();
        tokio::time::sleep(WAIT * 6 / 10).await;
        write_msg(&mut host, &proof).await.unwrap();
        tokio::time::sleep(WAIT).await;
        drop(host);
    });
    let started = tokio::time::Instant::now();
    let failed = MediaViewer::bind(client, &binding, WAIT).await.unwrap_err();
    assert!(
        matches!(failed, ViewerError::Timeout(w) if w == WAIT),
        "{failed:?}"
    );
    assert_eq!(started.elapsed(), WAIT);
}

/// The direct design §12.1 "refused before capture", through the viewer: a
/// direct binding over another connection's `ekm`, the onion binding on a
/// direct stream, and a `tor_only` session's direct binding are refused in
/// the proof's place (`BAD_BIND`, `BAD_BIND`, `TRANSPORT`); the viewer
/// reports the reason, the connection is closed with it, nothing opens and
/// nothing is claimed. The right binding then binds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_direct_viewer_opens_nothing_on_the_host() {
    let rig = direct_rig(TestBackend::default());
    let viewer = start_direct(&rig.host, 83, TransportPolicy::Any);
    let tor_only = start_direct(&rig.host, 84, TransportPolicy::TorOnly);
    let cases = [
        (
            &viewer,
            direct_binding(&viewer, &[0x34; 32]),
            reason::BAD_BIND,
        ),
        (&viewer, viewer.onion(), reason::BAD_BIND),
        (
            &tor_only,
            direct_binding(&tor_only, &EKM),
            reason::TRANSPORT,
        ),
    ];
    for (session, binding, code) in cases {
        let conn = connect_direct(&rig.host, session, EKM, TransportKind::Direct);
        let failed = MediaViewer::bind(conn.client, &binding, WAIT)
            .await
            .unwrap_err();
        assert!(
            matches!(failed, ViewerError::Refused(r) if r == code),
            "{binding:?}: {failed:?}"
        );
        assert_eq!(conn.served.await.unwrap(), MediaOutcome::NotBound);
        assert_eq!(*conn.closed_with.lock().unwrap(), Some(code));
        assert_eq!(rig.sources(), 0, "{binding:?}: nothing opened");
        assert_eq!(rig.host.route(&session.id), None);
    }

    let conn = connect_direct(&rig.host, &viewer, EKM, TransportKind::Direct);
    let bound = MediaViewer::bind(conn.client, &direct_binding(&viewer, &EKM), WAIT)
        .await
        .unwrap();
    assert_eq!(rig.sources(), 1);
    drop(bound);
    conn.served.await.unwrap();
}

/// Revision 1 blocker 1 (the direct design §4, §12.1), at the viewer's API
/// only: a direct `MediaViewer::bind` given a wait longer than the host's
/// source open (a 5 s dialog the user takes time to answer) binds. That the
/// caller passes its bind wait here, never the 4 s punch window, is
/// `choose_path`'s to show (step A17).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_five_second_open_on_the_direct_path_still_binds() {
    let rig = direct_rig(TestBackend {
        open_for: Some(Duration::from_secs(5)),
        ..TestBackend::default()
    });
    let viewer = start_direct(&rig.host, 85, TransportPolicy::Any);
    let conn = connect_direct(&rig.host, &viewer, EKM, TransportKind::Direct);
    let started = tokio::time::Instant::now();
    let bound = MediaViewer::bind(conn.client, &direct_binding(&viewer, &EKM), WAIT)
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert_eq!(rig.host.route(&viewer.id), Some(TransportKind::Direct));
    assert_eq!(rig.sources(), 1);
    drop(bound);
    conn.served.await.unwrap();
}

/// Three device-key seeds, lowest public key first: the lower key of a
/// pair dials the direct connection, the higher accepts
/// (`tornect_net::PunchRole::of`).
fn seeds_by_key() -> [u8; 3] {
    let mut seeds = [91, 92, 93];
    seeds.sort_by_key(|seed| device_key(*seed).verifying_key().to_bytes());
    seeds
}

fn device_key(seed: u8) -> Arc<DeviceIdentity> {
    Arc::new(DeviceIdentity::from_seed(&[seed; 32]))
}

/// Both ends of a session's direct link on one in-memory LAN.
struct Links {
    viewer: DirectLink,
    host: DirectLink,
    _net: MemNet,
}

impl Links {
    async fn close(self) {
        self.viewer.close().await;
        self.host.close().await;
    }
}

/// The viewer's link with device key `viewer`, pinned to `host`, and the
/// host's with key `host`, pinned to `pinned` (the viewer's, or another
/// device's for a pin the host's TLS refuses), for the session `token`,
/// on a LAN with 50 ms each way. Each side has the other's candidates.
async fn links_on_a_lan(token: &[u8; 32], viewer: u8, host: u8, pinned: u8) -> Links {
    let net = MemNet::new(1);
    let lan = net.segment(LinkSpec {
        latency: Duration::from_millis(50),
        loss: 0.0,
    });
    let viewer_env: Arc<dyn NetEnv> =
        Arc::new(net.machine(MachineSpec::on(lan, "192.168.1.10/24")));
    let host_env: Arc<dyn NetEnv> = Arc::new(net.machine(MachineSpec::on(lan, "192.168.1.20/24")));
    let params = |me, mine: u8, peer: u8| DirectParams {
        me,
        identity: device_key(mine),
        peer_pk: device_key(peer).verifying_key().to_bytes(),
        session_token: Zeroizing::new(*token),
        direct_port: None,
        scope: Scope::SameSite,
    };
    let (mut viewer_link, viewer_offered) =
        DirectLink::start(params(TornectRole::Viewer, viewer, host), viewer_env)
            .await
            .expect("the viewer's link");
    let (mut host_link, host_offered) =
        DirectLink::start(params(TornectRole::Host, host, pinned), host_env)
            .await
            .expect("the host's link");
    host_link.add_remote(viewer_offered, Scope::SameSite);
    assert_eq!(viewer_link.next_local().await, LocalBatch::Done);
    host_link.remote_done();
    viewer_link.add_remote(host_offered, Scope::SameSite);
    assert_eq!(host_link.next_local().await, LocalBatch::Done);
    viewer_link.remote_done();
    Links {
        viewer: viewer_link,
        host: host_link,
        _net: net,
    }
}

/// The host's side of a direct connection, as step A16 wires it: the
/// viewer's stream, served with the pinned peer's device and the
/// connection's own exporter output.
fn serve_link(
    host: &Arc<MediaHost>,
    link: &tornect_net::Established,
    viewer: &Viewer,
    route: TransportKind,
) -> JoinHandle<MediaOutcome> {
    let (host, link) = (Arc::clone(host), link.clone());
    let (session, token) = (viewer.id.clone(), *viewer.token.bytes());
    tokio::spawn(async move {
        let stream = link.accept_stream().await.expect("the media stream");
        let peer = DeviceId::from_bytes(link.peer_key());
        let ekm = link.binding_secret(&token).expect("the exporter");
        host.serve_direct(stream, &session, peer, ekm, route).await
    })
}

/// The bind over in-memory QUIC: both ends export the same secret, the
/// host serves the link's `QuicStream` with the pinned peer's device, and
/// the viewer binds after the proof. A bind that failed after a host byte
/// would never fall back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_bind_over_a_quic_link_binds() {
    let [viewer_key, _, host_key] = seeds_by_key();
    let rig = direct_rig(TestBackend::default());
    let device = device_key(viewer_key).id();
    let viewer = start_direct_for(&rig.host, 86, TransportPolicy::Any, device);
    let mut links = links_on_a_lan(viewer.token.bytes(), viewer_key, host_key, viewer_key).await;
    let (v, h) = tokio::time::timeout(WAIT, async {
        tokio::join!(links.viewer.established(), links.host.established())
    })
    .await
    .expect("in time");
    let (v, h) = (v.expect("the viewer's connection"), h.expect("the host's"));
    assert_eq!(DeviceId::from_bytes(h.peer_key()), device);
    let served = serve_link(&rig.host, &h, &viewer, TransportKind::Lan);

    let ekm = v.binding_secret(viewer.token.bytes()).unwrap();
    let stream = v.open_stream(1).await.unwrap();
    let bound = MediaViewer::bind(stream, &direct_binding(&viewer, &ekm), WAIT)
        .await
        .unwrap();
    assert_eq!(rig.host.route(&viewer.id), Some(TransportKind::Lan));
    assert!(v.stream_bytes_received() > 0);
    assert_eq!(after_bind_close(&v), AfterBind::End);
    drop(bound);
    assert!(matches!(
        tokio::time::timeout(WAIT, served).await.unwrap().unwrap(),
        MediaOutcome::Served { .. }
    ));
    links.close().await;
}

/// A refusal over a QUIC link (the direct design §6.5) ends the media
/// without a fallback: the viewer read `BindRefused{TRANSPORT}` (a host
/// byte), and the host's close carries the reason, not a TLS alert.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_over_a_quic_link_ends_without_fallback() {
    let [viewer_key, _, host_key] = seeds_by_key();
    let rig = direct_rig(TestBackend::default());
    let device = device_key(viewer_key).id();
    let viewer = start_direct_for(&rig.host, 87, TransportPolicy::TorOnly, device);
    let mut links = links_on_a_lan(viewer.token.bytes(), viewer_key, host_key, viewer_key).await;
    let (v, h) = tokio::time::timeout(WAIT, async {
        tokio::join!(links.viewer.established(), links.host.established())
    })
    .await
    .expect("in time");
    let (v, h) = (v.expect("the viewer's connection"), h.expect("the host's"));
    let served = serve_link(&rig.host, &h, &viewer, TransportKind::Lan);

    let ekm = v.binding_secret(viewer.token.bytes()).unwrap();
    let stream = v.open_stream(1).await.unwrap();
    let failed = MediaViewer::bind(stream, &direct_binding(&viewer, &ekm), WAIT)
        .await
        .unwrap_err();
    assert!(
        matches!(failed, ViewerError::Refused(r) if r == reason::TRANSPORT),
        "{failed:?}"
    );
    assert_eq!(
        tokio::time::timeout(WAIT, served).await.unwrap().unwrap(),
        MediaOutcome::NotBound
    );
    tokio::time::timeout(WAIT, v.closed())
        .await
        .expect("closed");
    assert!(!v.closed_by_crypto());
    assert!(v.stream_bytes_received() > 0);
    assert_eq!(after_bind_close(&v), AfterBind::End);
    assert_eq!(rig.sources(), 0);
    links.close().await;
}

/// DIRECT-2's one exception (the direct design §6.5 "Pin refused by the
/// host's TLS", §12.1): the host's link is pinned to another device, so its
/// TLS refuses the viewer's key after the viewer's own handshake completed.
/// The viewer's `Bind` never reaches the host: the bind fails with no host
/// byte, `after_bind_close` says `Fallback`, nothing was claimed or opened,
/// and the onion `Bind` is then accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crypto_close_before_any_host_byte_falls_back_to_the_onion_path() {
    let [viewer_key, other_key, host_key] = seeds_by_key();
    let rig = direct_rig(TestBackend::default());
    let viewer = start_direct_for(
        &rig.host,
        88,
        TransportPolicy::Any,
        device_key(viewer_key).id(),
    );
    let mut links = links_on_a_lan(viewer.token.bytes(), viewer_key, host_key, other_key).await;
    let v = tokio::time::timeout(WAIT, links.viewer.established())
        .await
        .expect("in time")
        .expect("the viewer's handshake completes before the host checks its key");
    let ekm = v.binding_secret(viewer.token.bytes()).unwrap();
    let stream = v.open_stream(1).await.unwrap();
    let failed = MediaViewer::bind(stream, &direct_binding(&viewer, &ekm), WAIT)
        .await
        .unwrap_err();
    assert!(
        matches!(
            failed,
            ViewerError::Closed | ViewerError::Proto(ProtoError::Io(_))
        ),
        "{failed:?}"
    );
    assert!(v.closed_by_crypto());
    assert_eq!(v.stream_bytes_received(), 0);
    assert_eq!(after_bind_close(&v), AfterBind::Fallback);
    assert!(!links.host.stats().established);
    assert_eq!(rig.host.route(&viewer.id), None, "nothing claimed");
    assert_eq!(rig.sources(), 0, "nothing opened");

    let (client, served) = connect(&rig.host);
    let onion = MediaViewer::bind(client, &viewer.onion(), WAIT)
        .await
        .unwrap();
    assert_eq!(rig.host.route(&viewer.id), Some(TransportKind::TorRelay));
    assert_eq!(rig.sources(), 1);
    drop(onion);
    served.await.unwrap();
    links.close().await;
}
