//! Property tests P1–P4 (`docs/PLAN.md` §B.8.15) over the host FSM:
//!
//! * P1 — random interleavings, `PING` at every position ⇒ identical `th` on
//!   both sides or a clean `E_BAD_STATE`, never an accept after a violation.
//! * P2 — per-direction `msg_id`: any perturbation ⇒ `E_BAD_MSG_ID`.
//! * P3 — any single-byte mutation of a frame before `SESSION_ACCEPT` ⇒
//!   abort with a protocol error, never an accept, never a popup — proven
//!   against a control replay of the *same* recording that the peer accepts
//!   (scripted nonces), for both scripts (paired / unpaired) and both sides:
//!   the client's frames replayed at the host, the host's frames replayed at
//!   the client.
//! * P4 — unknown CBOR keys in signed bodies round-trip through the FSM
//!   (ignored on decode, covered by the signature as raw bytes).

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use proptest::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex};
use tokio::runtime::Runtime;
use tornect_core::trusted::{KnownHosts, TrustedDevices};
use tornect_core::{DeviceIdentity, HostIdentity};

use super::client::{ClientConfig, ClientDeps, ClientOutcome, Intent, ScriptedClientUi, connect};
use super::host::{HostConfig, HostDeps, HostOutcome, serve_host};
use super::vectors::host_device_pk;
use super::*;
use crate::envelope::{Envelope, Kind, codes};
use crate::framing::{HEADER_LEN, write_frame};
use crate::messages::{self, Caps, Hello, PairRequest, Ping, SessionRequest};
use crate::pairing::{
    KnownHostStore, PairDecision, PairScript, ScriptedConsent, SessionDecision, SessionScript,
    TrustedDeviceStore, lock,
};
use crate::transcript::{HostSigner, sign_envelope};

const HOST_SEED: [u8; 32] = [0x11; 32];
const CLIENT_SEED: [u8; 32] = [0x22; 32];

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

struct Fixture {
    identity: Arc<HostIdentity>,
    cfg: HostConfig,
    deps: HostDeps,
    consent: Arc<ScriptedConsent>,
}

/// A host with an ephemeral trust store; `scripted` fixes every nonce and
/// token to `0x44…` so a recorded exchange replays byte-identically.
fn fixture(paired: Option<&DeviceIdentity>, scripted: bool) -> Fixture {
    let identity = Arc::new(HostIdentity::from_seed(&HOST_SEED));
    let mut devices = TrustedDevices::default();
    if let Some(d) = paired {
        devices.pin(d.id(), "paired", 1);
    }
    let trusted = Arc::new(TrustedDeviceStore::ephemeral(devices));
    let consent = Arc::new(ScriptedConsent::new());
    consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let mut deps = HostDeps::headless(identity.clone(), trusted);
    deps.consent = consent.clone();
    if scripted {
        deps.random = Arc::new(ScriptedRandom::new(vec![vec![0x44]]));
    }
    let cfg = HostConfig::new("host", host_device_pk());
    Fixture {
        identity,
        cfg,
        deps,
        consent,
    }
}

fn spawn(
    f: &Fixture,
    stream: DuplexStream,
) -> tokio::task::JoinHandle<Result<HostOutcome, HandshakeError>> {
    let cfg = f.cfg.clone();
    let deps = f.deps.clone();
    tokio::spawn(async move { serve_host(stream, &cfg, &deps).await })
}

fn hello_body(identity: &DeviceIdentity, nonce: [u8; 32], name: &str) -> Vec<u8> {
    encode_body(&Hello {
        v_max: 1,
        client_nonce: nonce,
        device_pk: HostSigner::public_key(identity),
        name: name.to_owned(),
        feats: vec!["ua1".into()],
        stop_token: None,
        pairing_state: 0,
    })
}

fn request_body() -> Vec<u8> {
    encode_body(&SessionRequest {
        caps: Caps::default(),
        unattended: None,
    })
}

/// The frames a well-behaved client sends, in order, for a paired or
/// unpaired device.
fn script(paired: bool) -> Vec<Kind> {
    if paired {
        vec![Kind::Hello, Kind::SessionRequest]
    } else {
        vec![Kind::Hello, Kind::PairRequest, Kind::SessionRequest]
    }
}

/// Drive the host with `script`, inserting a `PING` before step `ping_at`
/// (`== script.len()` ⇒ after the accept, where it is legal). Returns the
/// host outcome and the client's `th` after the last absorbed frame.
async fn drive(
    f: &Fixture,
    identity: &DeviceIdentity,
    nonce: [u8; 32],
    name: &str,
    paired: bool,
    ping_at: usize,
) -> (Result<HostOutcome, HandshakeError>, Option<[u8; 32]>) {
    let (a, b) = duplex(64 * 1024);
    let task = spawn(f, a);
    let mut chan = Channel::new(b, &HostSigner::public_key(&*f.identity));
    let steps = script(paired);
    let mut client_th = None;
    for (i, kind) in steps.iter().enumerate() {
        if ping_at == i {
            chan.send(&Ping { nonce: 1 }, None).await.unwrap();
            // The host answers E_BAD_STATE and closes.
            let rx = chan.recv(Duration::from_secs(5), "err").await;
            if let Ok(Some(rx)) = rx {
                assert_eq!(rx.env.kind, Kind::Error);
            }
            return (task.await.unwrap(), None);
        }
        let body = match kind {
            Kind::Hello => hello_body(identity, nonce, name),
            Kind::PairRequest => encode_body(&PairRequest::default()),
            _ => request_body(),
        };
        let signer: Option<&dyn HostSigner> = if kind.is_signed() {
            Some(identity)
        } else {
            None
        };
        let sent = chan.send_kind(*kind, body, signer).await;
        if sent.is_err() {
            return (task.await.unwrap(), None);
        }
        let reply = chan.recv(Duration::from_secs(5), "reply").await;
        let Ok(Some(rx)) = reply else {
            return (task.await.unwrap(), None);
        };
        match rx.env.kind {
            Kind::HelloAck => {
                chan.absorb(&rx);
                chan.set_version(1);
            }
            Kind::PairAccept | Kind::SessionAccept => {
                chan.absorb(&rx);
                if rx.env.kind == Kind::SessionAccept {
                    client_th = Some(chan.th());
                }
            }
            _ => return (task.await.unwrap(), None),
        }
    }
    if ping_at >= steps.len() {
        chan.send(&Ping { nonce: 2 }, None).await.unwrap();
        let rx = chan
            .recv(Duration::from_secs(5), "pong")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rx.env.kind, Kind::Pong);
    }
    chan.bye(messages::bye::USER).await.unwrap();
    (task.await.unwrap(), client_th)
}

/// The frames a genuine client sends to `f` (`HELLO`, `PAIR_REQUEST` when
/// unpaired, `SESSION_REQUEST`), recorded while driving the exchange to an
/// accept. With a scripted host nonce the recording replays byte-identically
/// on a fresh fixture.
async fn record_client_frames(
    f: &Fixture,
    identity: &DeviceIdentity,
    paired: bool,
) -> Vec<Vec<u8>> {
    let (a, b) = duplex(64 * 1024);
    let task = spawn(f, a);
    let mut chan = Channel::new(b, &HostSigner::public_key(&*f.identity));
    let mut frames = Vec::new();
    let hello = chan
        .send_kind(
            Kind::Hello,
            hello_body(identity, [3u8; 32], "rec"),
            Some(identity),
        )
        .await
        .unwrap();
    frames.push(hello.to_vec());
    let ack = chan
        .recv(Duration::from_secs(5), "ack")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ack.env.kind, Kind::HelloAck);
    chan.absorb(&ack);
    chan.set_version(1);
    if !paired {
        let request = chan.send(&PairRequest::default(), None).await.unwrap();
        frames.push(request.to_vec());
        let accept = chan
            .recv(Duration::from_secs(5), "pair accept")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accept.env.kind, Kind::PairAccept);
        chan.absorb(&accept);
    }
    let request = chan
        .send_kind(Kind::SessionRequest, request_body(), Some(identity))
        .await
        .unwrap();
    frames.push(request.to_vec());
    let accept = chan
        .recv(Duration::from_secs(5), "accept")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accept.env.kind, Kind::SessionAccept);
    chan.bye(messages::bye::USER).await.unwrap();
    task.await.unwrap().unwrap();
    frames
}

/// Write `frames` verbatim on a fresh stream and return the host's outcome.
async fn replay(f: &Fixture, frames: &[Vec<u8>]) -> Result<HostOutcome, HandshakeError> {
    let (a, mut b) = duplex(64 * 1024);
    let task = spawn(f, a);
    for frame in frames {
        if write_frame(&mut b, frame).await.is_err() {
            break;
        }
    }
    // Keep the stream open until the host is done (a replayed accept ends in
    // `PeerClosed` when `b` drops).
    let outcome = tokio::time::timeout(Duration::from_secs(5), task);
    tokio::select! {
        biased;
        out = outcome => out.expect("host finished").unwrap(),
        () = async {
            // Give the host time to accept, then hang up.
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(b);
            std::future::pending::<()>().await;
        } => unreachable!(),
    }
}

/// A stream wrapper that records every byte read from it (the host's frames,
/// as the real client sees them).
struct Tee<S> {
    inner: S,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tee<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            lock(&this.seen).extend_from_slice(&buf.filled()[before..]);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tee<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Split a captured byte stream into frame payloads (the `u32`-BE prefixes
/// `write_frame` put on the wire).
fn split_wire(mut bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while bytes.len() >= HEADER_LEN {
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let end = HEADER_LEN + len;
        assert!(bytes.len() >= end, "truncated capture");
        out.push(bytes[HEADER_LEN..end].to_vec());
        bytes = &bytes[end..];
    }
    assert!(bytes.is_empty(), "trailing bytes in the capture");
    out
}

struct ClientFixture {
    cfg: ClientConfig,
    identity: DeviceIdentity,
    deps: ClientDeps,
    known: Arc<KnownHostStore>,
}

/// A client with an ephemeral known-hosts store and every nonce scripted to
/// `0x33…`, so its frames are byte-identical from one run to the next.
fn client_fixture(host: &HostIdentity, paired: bool) -> ClientFixture {
    let identity = DeviceIdentity::from_seed(&CLIENT_SEED);
    let mut hosts = KnownHosts::default();
    if paired {
        hosts.pin(host.id(), "host", host_device_pk(), 1);
    }
    let known = Arc::new(KnownHostStore::ephemeral(hosts));
    let mut deps = ClientDeps::headless(known.clone());
    deps.ui = Arc::new(ScriptedClientUi::new(true));
    deps.random = Arc::new(ScriptedRandom::new(vec![vec![0x33]]));
    ClientFixture {
        cfg: ClientConfig::new(host.id(), "rec"),
        identity,
        deps,
        known,
    }
}

/// The frames a genuine host sends to the real client (`HELLO_ACK`,
/// `PAIR_ACCEPT` when unpaired, `SESSION_ACCEPT`), recorded through a [`Tee`].
async fn record_host_frames(f: &Fixture, paired: bool) -> Vec<Vec<u8>> {
    let c = client_fixture(&f.identity, paired);
    let (a, b) = duplex(64 * 1024);
    let task = spawn(f, a);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let tee = Tee {
        inner: b,
        seen: seen.clone(),
    };
    match connect(tee, &c.cfg, &c.identity, &c.deps, Intent::Session)
        .await
        .unwrap()
    {
        ClientOutcome::Session(s) => s.bye(messages::bye::USER).await.unwrap(),
        ClientOutcome::Paired { .. } => panic!("expected a session"),
    }
    task.await.unwrap().unwrap();
    let captured = lock(&seen).clone();
    split_wire(&captured)
}

/// Write `frames` up front on the host end and run `connect()` against them.
async fn replay_into_client(
    c: &ClientFixture,
    frames: &[Vec<u8>],
) -> Result<ClientOutcome<DuplexStream>, HandshakeError> {
    let (mut a, b) = duplex(64 * 1024);
    for frame in frames {
        write_frame(&mut a, frame).await.unwrap();
    }
    // `a` stays open until the client is done: a dropped host end would turn
    // every outcome into an I/O error.
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        connect(b, &c.cfg, &c.identity, &c.deps, Intent::Session),
    )
    .await
    .expect("the client never waits on a mutated recording");
    drop(a);
    outcome
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// P1.
    #[test]
    fn p1_ping_anywhere_gives_equal_th_or_bad_state(
        paired in any::<bool>(),
        ping_at in 0usize..=3,
        nonce in any::<[u8; 32]>(),
        name in "[a-z ]{0,20}",
    ) {
        let rt = runtime();
        rt.block_on(async {
            let identity = DeviceIdentity::from_seed(&CLIENT_SEED);
            let f = fixture(paired.then_some(&identity), false);
            let steps = script(paired).len();
            let ping_at = ping_at.min(steps);
            let (outcome, client_th) = drive(&f, &identity, nonce, &name, paired, ping_at).await;
            if ping_at < steps {
                let err = outcome.unwrap_err();
                prop_assert_eq!(err.violation_code(), Some(codes::E_BAD_STATE));
                prop_assert_eq!(f.consent.session_popups(), 0);
                prop_assert_eq!(f.deps.stats.accepted_total.load(Ordering::SeqCst), 0);
            } else {
                match outcome.unwrap() {
                    HostOutcome::Session { th_final, .. } => prop_assert_eq!(Some(th_final), client_th),
                    other => prop_assert!(false, "{other:?}"),
                }
            }
            Ok(())
        })?;
    }

    /// P2: the host enforces `prev + 1` on every received frame.
    #[test]
    fn p2_any_msg_id_perturbation_is_bad_msg_id(
        paired in any::<bool>(),
        at in 0usize..3,
        delta in prop_oneof![Just(-1i64), Just(1), Just(2), Just(100), Just(-1000)],
    ) {
        let rt = runtime();
        rt.block_on(async {
            let identity = DeviceIdentity::from_seed(&CLIENT_SEED);
            let f = fixture(paired.then_some(&identity), false);
            let steps = script(paired);
            let at = at.min(steps.len() - 1);
            let (a, b) = duplex(64 * 1024);
            let task = spawn(&f, a);
            let mut chan = Channel::new(b, &HostSigner::public_key(&*f.identity));
            let mut result = None;
            for (i, kind) in steps.iter().enumerate() {
                let body = match kind {
                    Kind::Hello => hello_body(&identity, [7u8; 32], "x"),
                    Kind::PairRequest => encode_body(&PairRequest::default()),
                    _ => request_body(),
                };
                if i == at {
                    let expected = chan.next_tx_id();
                    let wrong = (expected as i64 + delta).max(0) as u64;
                    let mut env = Envelope::new(chan.version(), wrong, *kind, body);
                    if kind.is_signed() {
                        sign_envelope(&identity, &chan.th(), &mut env);
                    }
                    let mut stream = chan.into_stream();
                    write_frame(&mut stream, &env.encode()).await.unwrap();
                    result = Some(task.await.unwrap());
                    break;
                }
                let signer: Option<&dyn HostSigner> = if kind.is_signed() { Some(&identity) } else { None };
                chan.send_kind(*kind, body, signer).await.unwrap();
                let rx = chan.recv(Duration::from_secs(5), "reply").await.unwrap().unwrap();
                chan.absorb(&rx);
                if rx.env.kind == Kind::HelloAck {
                    chan.set_version(1);
                }
            }
            let err = result.unwrap().unwrap_err();
            prop_assert_eq!(err.violation_code(), Some(codes::E_BAD_MSG_ID), "{}", err);
            prop_assert_eq!(f.deps.stats.accepted_total.load(Ordering::SeqCst), 0);
            Ok(())
        })?;
    }

    /// P3 (host side): record an exchange, prove the un-mutated recording is
    /// accepted again by a fresh host (scripted host nonce), then flip one
    /// byte of one client frame — `HELLO`, `PAIR_REQUEST` (unpaired) or
    /// `SESSION_REQUEST` — and replay: never an accept, never a session
    /// popup, and a pairing popup only for a genuine `PAIR_REQUEST`.
    #[test]
    fn p3_single_byte_mutation_never_accepts(
        paired in any::<bool>(),
        which in any::<prop::sample::Index>(),
        index in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let rt = runtime();
        rt.block_on(async {
            let identity = DeviceIdentity::from_seed(&CLIENT_SEED);
            let frames = record_client_frames(
                &fixture(paired.then_some(&identity), true),
                &identity,
                paired,
            )
            .await;
            prop_assert_eq!(frames.len(), if paired { 2 } else { 3 });

            // Control: the verbatim recording is accepted by a fresh host
            // (same nonce ⇒ same transcript), so a rejection below is caused
            // by the mutation and nothing else.
            let control = fixture(paired.then_some(&identity), true);
            match replay(&control, &frames).await {
                Ok(HostOutcome::Session { .. }) => {}
                other => prop_assert!(false, "control replay not accepted: {other:?}"),
            }
            prop_assert_eq!(control.consent.session_popups(), 1);
            prop_assert_eq!(control.consent.sas_shown().len(), usize::from(!paired));
            prop_assert_eq!(control.deps.stats.accepted_total.load(Ordering::SeqCst), 1);

            // Mutate one byte of one frame, replay on another fresh host.
            let which = which.index(frames.len());
            let mut frames = frames;
            let i = index.index(frames[which].len());
            frames[which][i] ^= flip;
            let f = fixture(paired.then_some(&identity), true);
            let outcome = replay(&f, &frames).await;
            // A flipped `kind` byte can turn the frame into an ERROR or BYE
            // envelope (6 ^ 20 = 18, 6 ^ 19 = 17): the host then reports the
            // peer's own close — after a genuine pairing, a BYE in place of
            // `SESSION_REQUEST` is the legal `PairedOnly` ending. Still no
            // accept and no session popup.
            let ok = match &outcome {
                Ok(HostOutcome::PairedOnly { .. }) => !paired && which == 2,
                Ok(_) => false,
                Err(HandshakeError::Violation { code, .. }) => matches!(
                    *code,
                    codes::E_BAD_SIG | codes::E_BAD_LEN | codes::E_BAD_MSG_ID | codes::E_VERSION
                        | codes::E_UNKNOWN_KIND | codes::E_BAD_STATE | codes::E_TOO_LARGE
                ),
                Err(
                    HandshakeError::PeerError { .. }
                    | HandshakeError::PeerBye { .. }
                    | HandshakeError::Closed
                    | HandshakeError::Frame(_),
                ) => true,
                Err(_) => false,
            };
            prop_assert!(ok, "frame {which} byte {i} ^ {flip:#04x}: {outcome:?}");
            prop_assert_eq!(f.consent.session_popups(), 0, "no session popup for the mutated replay");
            // Only a genuine PAIR_REQUEST (both frames before it intact) reaches the pairing popup.
            prop_assert_eq!(
                f.consent.sas_shown().len(),
                usize::from(!paired && which == 2),
                "pairing popup for the mutated replay"
            );
            prop_assert_eq!(f.deps.stats.accepted_total.load(Ordering::SeqCst), 0);
            Ok(())
        })?;
    }

    /// P3 (client side): the host's frames — `HELLO_ACK`, `PAIR_ACCEPT`
    /// (unpaired), `SESSION_ACCEPT` — recorded from a genuine host with
    /// scripted randomness replay byte-identically into `connect()` (control:
    /// a session); with one byte flipped the client never establishes a
    /// session. What it pins: nothing after a tampered `HELLO_ACK`; after a
    /// tampered `PAIR_ACCEPT` it may pin (the frame is unsigned and outside
    /// the SAS, decision M1-31 / the r7 item) but the signed `SESSION_ACCEPT`
    /// then fails over the diverged transcript, so the pin never carries a
    /// session; after a tampered `SESSION_ACCEPT` the genuine pairing stands.
    #[test]
    fn p3_client_single_byte_mutation_never_establishes(
        paired in any::<bool>(),
        which in any::<prop::sample::Index>(),
        index in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let rt = runtime();
        rt.block_on(async {
            let identity = DeviceIdentity::from_seed(&CLIENT_SEED);
            let host = fixture(paired.then_some(&identity), true);
            let frames = record_host_frames(&host, paired).await;
            prop_assert_eq!(frames.len(), if paired { 2 } else { 3 });

            // Control: the verbatim recording establishes a session.
            let control = client_fixture(&host.identity, paired);
            match replay_into_client(&control, &frames).await {
                Ok(ClientOutcome::Session(_)) => {}
                other => prop_assert!(false, "control replay not established: {other:?}"),
            }
            prop_assert!(control.known.is_known(&host.identity.id()));

            // Mutate one byte of one host frame.
            let which = which.index(frames.len());
            let mut frames = frames;
            let i = index.index(frames[which].len());
            frames[which][i] ^= flip;
            let c = client_fixture(&host.identity, paired);
            let outcome = replay_into_client(&c, &frames).await;
            let err = match outcome {
                Ok(ClientOutcome::Session(_)) => panic!("established on a mutated frame"),
                Ok(ClientOutcome::Paired { .. }) => panic!("pair-only outcome with Intent::Session"),
                Err(e) => e,
            };
            let ok = match &err {
                HandshakeError::Violation { code, .. } => matches!(
                    *code,
                    codes::E_BAD_SIG | codes::E_BAD_LEN | codes::E_BAD_MSG_ID | codes::E_VERSION
                        | codes::E_UNKNOWN_KIND | codes::E_BAD_STATE | codes::E_TOO_LARGE
                ),
                HandshakeError::PeerError { .. }
                | HandshakeError::PeerBye { .. }
                | HandshakeError::PairRejected { .. }
                | HandshakeError::SessionRejected { .. }
                | HandshakeError::Closed
                | HandshakeError::Frame(_) => true,
                _ => false,
            };
            prop_assert!(ok, "frame {which} byte {i} ^ {flip:#04x}: {err}");
            let pinned = c.known.is_known(&host.identity.id());
            let last = frames.len() - 1;
            if paired {
                prop_assert!(pinned, "the pre-existing pin is never removed");
            } else if which == 0 {
                prop_assert!(!pinned, "a tampered HELLO_ACK pins nothing");
            } else if which == last {
                prop_assert!(pinned, "the pairing before a tampered SESSION_ACCEPT was genuine");
            } else if pinned {
                // A tampered PAIR_ACCEPT that still decodes is pinned (M1-31),
                // and the signed accept over the diverged transcript is what
                // catches it.
                prop_assert_eq!(err.violation_code(), Some(codes::E_BAD_SIG), "{}", err);
            }
            Ok(())
        })?;
    }

    /// P4: unknown keys in a signed body are ignored and still verify.
    #[test]
    fn p4_unknown_cbor_keys_roundtrip_through_the_fsm(
        extra in proptest::collection::vec((100u32..1000, any::<u8>()), 0..6),
    ) {
        let rt = runtime();
        rt.block_on(async {
            let identity = DeviceIdentity::from_seed(&CLIENT_SEED);
            let f = fixture(Some(&identity), false);
            let with_extra = |base: Vec<u8>| -> Vec<u8> {
                // Re-open the map with a larger count and append unknown keys
                // of assorted types.
                let mut d = minicbor::Decoder::new(&base);
                let n = d.map().unwrap().unwrap();
                let mut e = minicbor::Encoder::new(Vec::new());
                e.map(n + extra.len() as u64).unwrap();
                let mut out = e.into_writer();
                out.extend_from_slice(&base[d.position()..]);
                let mut e = minicbor::Encoder::new(Vec::new());
                for (k, v) in &extra {
                    e.u32(*k).unwrap();
                    match v % 4 {
                        0 => { e.u8(*v).unwrap(); }
                        1 => { e.str("future").unwrap(); }
                        2 => { e.bytes(&[*v; 3]).unwrap(); }
                        _ => { e.array(2).unwrap().u8(1).unwrap().null().unwrap(); }
                    }
                }
                out.extend(e.into_writer());
                out
            };
            let (a, b) = duplex(64 * 1024);
            let task = spawn(&f, a);
            let mut chan = Channel::new(b, &HostSigner::public_key(&*f.identity));
            let hello = with_extra(hello_body(&identity, [5u8; 32], "p4"));
            let decoded: Hello = decode_body(&hello).unwrap();
            prop_assert_eq!(decoded.name, "p4");
            chan.send_kind(Kind::Hello, hello, Some(&identity)).await.unwrap();
            let ack = chan.recv(Duration::from_secs(5), "ack").await.unwrap().unwrap();
            prop_assert_eq!(ack.env.kind, Kind::HelloAck);
            chan.absorb(&ack);
            chan.set_version(1);
            chan.send_kind(Kind::SessionRequest, with_extra(request_body()), Some(&identity)).await.unwrap();
            let accept = chan.recv(Duration::from_secs(5), "accept").await.unwrap().unwrap();
            prop_assert_eq!(accept.env.kind, Kind::SessionAccept);
            chan.absorb(&accept);
            chan.bye(messages::bye::USER).await.unwrap();
            match task.await.unwrap().unwrap() {
                HostOutcome::Session { th_final, .. } => prop_assert_eq!(th_final, chan.th()),
                other => prop_assert!(false, "{other:?}"),
            }
            Ok(())
        })?;
    }
}
