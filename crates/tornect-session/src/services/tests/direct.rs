//! The services stream on a session's direct connection (the direct design
//! §6.7, §12.1 "services direct", step B10), over in-process pipes:
//! [`ServicesHost::serve_direct`] binds it only once the session's media was
//! claimed on the same path, from the same pinned device, under its own MAC
//! over the connection's exporter output; it is served with the direct bulk
//! window beside the media stream, and the onion services port binds
//! nothing for a session whose media is direct.

use tokio::io::AsyncWriteExt as _;
use tornect_core::session_log::TransportKind;
use tornect_proto::services::services_bind_mac_direct;
use tornect_proto::{BindSide, Msg, bind_mac_direct};
use zeroize::Zeroizing;

use super::*;
use crate::{DirectStream, MediaOutcome};

/// The exporter output of the test connection.
const EKM: [u8; 32] = [0x5a; 32];

/// One end of a pipe standing for a direct connection's stream.
struct Pipe(DuplexStream);

impl AsyncRead for Pipe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Pipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl DirectStream for Pipe {
    async fn refuse(mut self, frame: Vec<u8>, _code: u16) {
        let _ = self.0.write_all(&frame).await;
        let _ = self.0.shutdown().await;
    }
}

/// Session `seed`'s token and transcript, as [`start`] registers them.
fn token_of(seed: u8) -> (SessionToken, [u8; 32]) {
    (SessionToken::new([seed; 32]), [!seed; 32])
}

/// Session `seed`'s viewer device, as [`start`] registers it.
fn device(seed: u8) -> DeviceId {
    DeviceId::from_bytes([seed; 32])
}

/// Session `seed`'s direct services binding over `ekm`.
fn direct_binding(seed: u8, ekm: &[u8; 32]) -> ServicesBinding {
    let (token, th_final) = token_of(seed);
    ServicesBinding::direct(&token, &th_final, ekm)
}

/// Bind session `seed`'s media on its direct connection (exporter output
/// [`EKM`]) on `route`, and read its `BindProof` and up to its first
/// picture: the claim is published as `route`, and capture is live.
async fn media_direct(
    rig: &Rig,
    seed: u8,
    route: TransportKind,
) -> (DuplexStream, JoinHandle<MediaOutcome>) {
    let (token, th_final) = token_of(seed);
    let (mut client, server) = duplex(1 << 20);
    let media = Arc::clone(&rig.media);
    let id = token.session_id();
    let served = tokio::spawn(async move {
        media
            .serve_direct(Pipe(server), &id, device(seed), Zeroizing::new(EKM), route)
            .await
    });
    let bind = Msg::Bind {
        session_id: token.session_id(),
        mac: bind_mac_direct(token.bytes(), &th_final, &EKM, BindSide::Client),
        quality: tornect_proto::quality::BALANCED,
    };
    tornect_proto::write_msg(&mut client, &bind).await.unwrap();
    let mut first = true;
    loop {
        let msg = tokio::time::timeout(WAIT, tornect_proto::read_msg(&mut client))
            .await
            .expect("a frame in time")
            .unwrap();
        match msg {
            Some(Msg::BindProof { .. }) if first => {}
            Some(other) if first => panic!("expected BindProof first, got {other:?}"),
            Some(Msg::Video { .. }) => return (client, served),
            Some(_) => {}
            None => panic!("the media stream closed"),
        }
        first = false;
    }
}

/// A services stream of the direct connection made for `link_session` with
/// the device `peer`, whose exporter output is `ekm`, on `route`, served on
/// its own task.
fn open_direct(
    rig: &Rig,
    link_session: &str,
    peer: DeviceId,
    ekm: [u8; 32],
    route: TransportKind,
) -> (DuplexStream, JoinHandle<ServicesOutcome>) {
    let (client, server) = duplex(1 << 20);
    let services = Arc::clone(&rig.services);
    let session = link_session.to_owned();
    (
        client,
        tokio::spawn(async move {
            services
                .serve_direct(server, &session, peer, Zeroizing::new(ekm), route)
                .await
        }),
    )
}

/// Write `bind` and expect `Refused{BAD_BIND}`, the stream closed, and
/// nothing bound.
async fn refused(
    (mut client, task): (DuplexStream, JoinHandle<ServicesOutcome>),
    bind: &SvcMsg,
    case: &str,
) {
    write_msg(&mut client, bind).await.unwrap();
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Refused {
            reason: reason::BAD_BIND
        }),
        "{case}"
    );
    assert_eq!(next(&mut client).await, None, "{case}: closed");
    assert_eq!(task.await.unwrap(), ServicesOutcome::NotBound, "{case}");
}

/// Write `bind` and expect `Welcome`.
async fn welcomed(client: &mut DuplexStream, bind: &SvcMsg) -> Welcome {
    write_msg(client, bind).await.unwrap();
    match next(client).await {
        Some(SvcMsg::Welcome(welcome)) => welcome,
        other => panic!("expected Welcome, got {other:?}"),
    }
}

/// The viewer's next chat line the host heard for `id`, skipping its other
/// events.
async fn chat_heard(rig: &mut Rig, id: &str) -> String {
    loop {
        if let HostEvent::Chat(text) = rig.event(id).await {
            return text.as_str().to_owned();
        }
    }
}

/// The next picture on a media stream.
async fn picture(media: &mut DuplexStream) {
    loop {
        match tokio::time::timeout(WAIT, tornect_proto::read_msg(media))
            .await
            .expect("a picture in time")
            .unwrap()
        {
            Some(Msg::Video { .. }) => return,
            Some(_) => {}
            None => panic!("the media stream closed"),
        }
    }
}

/// §12.1 "services direct": refused before the media's claim; once the
/// media is claimed on the link, refused under the onion services MAC, the
/// direct media MAC, another exporter output, another device, another path
/// and another session's link (each leaving the services unbound), then
/// bound under its own MAC with the direct bulk window, once only; chat
/// then goes over it while the media stream keeps sending pictures.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_services_stream_binds_only_after_its_media_on_the_same_link() {
    let mut rig = rig();
    let seed = 200;
    let session = start(&rig, seed, SessionMode::Control);
    let right = direct_binding(seed, &EKM).msg();
    let link = |peer, ekm, route| open_direct(&rig, &session.id, peer, ekm, route);

    refused(
        link(device(seed), EKM, TransportKind::Lan),
        &right,
        "before the media's claim",
    )
    .await;

    let (mut media, _served) = media_direct(&rig, seed, TransportKind::Lan).await;
    assert_eq!(rig.media.route(&session.id), Some(TransportKind::Lan));

    let (token, th_final) = token_of(seed);
    let onion_mac = raw_bind(&session.id, services_bind_mac(token.bytes(), &th_final));
    refused(
        link(device(seed), EKM, TransportKind::Lan),
        &onion_mac,
        "the onion services MAC",
    )
    .await;
    let media_mac = raw_bind(
        &session.id,
        bind_mac_direct(token.bytes(), &th_final, &EKM, BindSide::Client),
    );
    refused(
        link(device(seed), EKM, TransportKind::Lan),
        &media_mac,
        "the direct media MAC",
    )
    .await;
    refused(
        link(device(seed), [0x11; 32], TransportKind::Lan),
        &right,
        "another connection's exporter output",
    )
    .await;
    refused(
        link(device(seed + 1), EKM, TransportKind::Lan),
        &right,
        "another device",
    )
    .await;
    refused(
        link(device(seed), EKM, TransportKind::Direct),
        &right,
        "a path the media was not claimed on",
    )
    .await;
    refused(
        link(device(seed), EKM, TransportKind::TorRelay),
        &right,
        "the onion path",
    )
    .await;
    let other = token_of(seed + 1).0.session_id();
    refused(
        open_direct(&rig, &other, device(seed), EKM, TransportKind::Lan),
        &right,
        "another session's link",
    )
    .await;
    assert_eq!(
        right,
        raw_bind(
            &session.id,
            services_bind_mac_direct(token.bytes(), &th_final, &EKM)
        ),
        "the binding carries the direct services MAC"
    );

    let (mut client, task) = link(device(seed), EKM, TransportKind::Lan);
    let welcome = welcomed(&mut client, &right).await;
    assert_eq!(welcome.caps, caps::ALL);
    assert_eq!(welcome.bulk_window, DIRECT_BULK_WINDOW);
    assert_eq!(DIRECT_BULK_WINDOW, 4 << 20);
    assert_eq!(rig.services.open_streams(), 1);
    // Once only, on either port.
    refused(
        link(device(seed), EKM, TransportKind::Lan),
        &right,
        "a second direct stream",
    )
    .await;
    let (mut onion, onion_task) = open(&rig.services);
    assert_eq!(
        bind(&mut onion, &session).await,
        SvcMsg::Refused {
            reason: reason::BAD_BIND
        }
    );
    assert_eq!(onion_task.await.unwrap(), ServicesOutcome::NotBound);

    // Beside the media, neither waiting on the other.
    write_msg(&mut client, &chat("over the direct link"))
        .await
        .unwrap();
    assert_eq!(
        chat_heard(&mut rig, &session.id).await,
        "over the direct link"
    );
    picture(&mut media).await;
    assert!(
        rig.services
            .send_chat(&session.id, sanitize_peer_text("and back").unwrap())
    );
    assert_eq!(
        next(&mut client).await,
        Some(SvcMsg::Chat(Chat {
            text: "and back".into()
        }))
    );
    picture(&mut media).await;

    drop(client);
    let (code, summary, _) = served(task).await;
    assert_eq!(code, reason::BY_VIEWER);
    assert_eq!((summary.chat_in, summary.chat_out), (1, 1));
    assert_eq!(rig.services.open_streams(), 0);
}

/// The direct design §6.7: while a session's media is direct, its onion
/// services stream is refused even under the right MAC (its viewer never
/// opens one then), and the refusal burns nothing: the direct stream still
/// binds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_onion_services_port_binds_nothing_while_the_media_is_direct() {
    let rig = rig();
    let seed = 203;
    let session = start(&rig, seed, SessionMode::Control);
    let (_media, _served) = media_direct(&rig, seed, TransportKind::Direct).await;

    let (mut onion, task) = open(&rig.services);
    assert_eq!(
        bind(&mut onion, &session).await,
        SvcMsg::Refused {
            reason: reason::BAD_BIND
        }
    );
    assert_eq!(task.await.unwrap(), ServicesOutcome::NotBound);

    let (mut client, task) =
        open_direct(&rig, &session.id, device(seed), EKM, TransportKind::Direct);
    let welcome = welcomed(&mut client, &direct_binding(seed, &EKM).msg()).await;
    assert_eq!(welcome.bulk_window, DIRECT_BULK_WINDOW);
    drop(client);
    assert_eq!(served(task).await.0, reason::BY_VIEWER);
}

/// A session whose media was claimed on the onion path binds no direct
/// services stream, on any path; its onion stream binds with the onion
/// bulk window. [`ServicesLimits::direct`] changes the bulk window only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn media_on_the_onion_path_binds_no_direct_services_stream() {
    let rig = rig();
    let seed = 205;
    let session = start(&rig, seed, SessionMode::Control);
    let _media = media_live(&rig.media, &session).await;
    assert_eq!(rig.media.route(&session.id), Some(TransportKind::TorRelay));

    let right = direct_binding(seed, &EKM).msg();
    for route in [
        TransportKind::Lan,
        TransportKind::Direct,
        TransportKind::TorRelay,
    ] {
        refused(
            open_direct(&rig, &session.id, device(seed), EKM, route),
            &right,
            &format!("{route:?}"),
        )
        .await;
    }

    let (mut onion, task) = open(&rig.services);
    let welcome = welcome(&mut onion, &session).await;
    assert_eq!(welcome.bulk_window, ServicesLimits::default().bulk_window);
    assert_eq!(welcome.bulk_window, 256 << 10);
    drop(onion);
    assert_eq!(served(task).await.0, reason::BY_VIEWER);

    let onion_limits = ServicesLimits::default();
    let direct = onion_limits.direct();
    assert_eq!(direct.bulk_window, DIRECT_BULK_WINDOW);
    assert_eq!(
        (
            direct.chunk,
            direct.session_files,
            direct.live_wait,
            direct.lock_wait,
            direct.workers_wait
        ),
        (
            onion_limits.chunk,
            onion_limits.session_files,
            onion_limits.live_wait,
            onion_limits.lock_wait,
            onion_limits.workers_wait
        )
    );
}
