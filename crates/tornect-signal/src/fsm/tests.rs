//! Host + client FSMs over `tokio::io::duplex` (`docs/PLAN.md` §B.8.15:
//! P1–P4, A1, A3 signaling half, A13 signaling half, A17; timeouts under
//! `tokio::time::pause`; the B.8.4.3 golden vector).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncWriteExt as _, DuplexStream, duplex};
use tornect_core::trusted::{KnownHosts, TrustedDevices};
use tornect_core::{DeviceId, DeviceIdentity, HostIdentity, TornectId};
use zeroize::Zeroizing;

use tornect_core::session_log::{SessionEvent as LogEvent, SessionLog};
use tornect_core::unattended::ReadinessSnapshot;

use super::client::{
    ClientConfig, ClientDeps, ClientOutcome, Intent, ScriptedClientUi, SessionEvent, connect,
};
use super::host::{
    HostConfig, HostDeps, HostOutcome, KillSwitch, SessionActivity, SessionEnd, StopTokenCheck,
    UnattendedContext, UnattendedHook, UnattendedVerdict, serve_host,
};
use super::vectors::host_device_pk;
use super::*;
use crate::consent::{
    BlockOutcome, ChosenCaps, ConsentProof, DerivedToken, PolicyReceipt, TransportPolicy,
    WindowPassed,
};
use crate::envelope::{Envelope, Kind, codes};
use crate::framing::{FrameError, write_frame};
use crate::messages::{
    self, Caps, Hello, PairRequest, Ping, Pong, Resolution, SessionRequest, bye, ed25519_spki,
    pair_reject, reject,
};
use crate::pairing::{
    KnownHostStore, PairDecision, PairScript, PairingLimits, PairingPolicy, ScriptedConsent,
    SessionDecision, SessionScript, TrustedDeviceStore,
};
use crate::transcript::{HostSigner, sign_envelope};

const HOST_SEED: [u8; 32] = [0x11; 32];
const CLIENT_SEED: [u8; 32] = [0x22; 32];

struct HostSide {
    identity: Arc<HostIdentity>,
    cfg: HostConfig,
    deps: HostDeps,
    consent: Arc<ScriptedConsent>,
    trusted: Arc<TrustedDeviceStore>,
}

fn host_side(tmp: &std::path::Path, seed: [u8; 32]) -> HostSide {
    let identity = Arc::new(HostIdentity::from_seed(&seed));
    let trusted = Arc::new(TrustedDeviceStore::with(
        tmp.join("trusted-devices.toml"),
        TrustedDevices::default(),
    ));
    let consent = Arc::new(ScriptedConsent::new());
    let mut deps = HostDeps::headless(identity.clone(), trusted.clone());
    deps.consent = consent.clone();
    let mut cfg = HostConfig::new("Desk of Bob", host_device_pk());
    cfg.caps = Caps {
        codecs: vec!["h264".into(), "av1".into()],
        max_res: Resolution {
            width: 2560,
            height: 1440,
        },
        hdr: true,
        monitors: 2,
    };
    cfg.feats = vec!["ua1".into()];
    HostSide {
        identity,
        cfg,
        deps,
        consent,
        trusted,
    }
}

struct ClientSide {
    identity: DeviceIdentity,
    cfg: ClientConfig,
    deps: ClientDeps,
    ui: Arc<ScriptedClientUi>,
    known: Arc<KnownHostStore>,
}

fn client_side(tmp: &std::path::Path, host: TornectId, seed: [u8; 32]) -> ClientSide {
    let identity = DeviceIdentity::from_seed(&seed);
    let known = Arc::new(KnownHostStore::with(
        tmp.join("known-hosts.toml"),
        KnownHosts::default(),
    ));
    let ui = Arc::new(ScriptedClientUi::new(true));
    let mut deps = ClientDeps::headless(known.clone());
    deps.ui = ui.clone();
    let mut cfg = ClientConfig::new(host, "Laptop of Ana");
    cfg.caps = Caps {
        codecs: vec!["av1".into(), "h264".into()],
        max_res: Resolution {
            width: 1920,
            height: 1080,
        },
        hdr: false,
        monitors: 1,
    };
    cfg.feats = vec!["ua1".into()];
    ClientSide {
        identity,
        cfg,
        deps,
        ui,
        known,
    }
}

fn pipe() -> (DuplexStream, DuplexStream) {
    duplex(64 * 1024)
}

/// A hand-driven client built on the raw channel, for adversarial tests.
struct RawClient {
    chan: Channel<DuplexStream>,
    identity: DeviceIdentity,
}

/// SAS nonce the raw test client commits to in `HELLO` and reveals in `PAIR_REQUEST`.
const RAW_SAS_NONCE: [u8; 32] = [0x44; 32];

/// A `PAIR_REQUEST` opening the commitment the raw client published.
fn raw_pair_request() -> PairRequest {
    PairRequest {
        sas_nonce: RAW_SAS_NONCE,
        ..PairRequest::default()
    }
}

impl RawClient {
    fn new(stream: DuplexStream, host: &HostIdentity, seed: [u8; 32]) -> Self {
        Self {
            chan: Channel::new(stream, &HostSigner::public_key(host)),
            identity: DeviceIdentity::from_seed(&seed),
        }
    }

    fn hello(&self, stop_token: Option<[u8; 32]>) -> Hello {
        Hello {
            v_max: 1,
            client_nonce: [0x33; 32],
            sas_commit: crate::pairing::sas_commit(&RAW_SAS_NONCE),
            device_pk: HostSigner::public_key(&self.identity),
            name: "raw".into(),
            feats: vec![],
            stop_token,
            pairing_state: 0,
        }
    }

    async fn send_hello(&mut self, stop_token: Option<[u8; 32]>) -> Zeroizing<Vec<u8>> {
        let hello = self.hello(stop_token);
        self.chan.send(&hello, Some(&self.identity)).await.unwrap()
    }

    /// `HELLO` → `HELLO_ACK` absorbed, version fixed: ready for the next frame.
    async fn hello_ack(&mut self) {
        self.send_hello(None).await;
        let ack = self.recv().await.unwrap();
        assert_eq!(ack.env.kind, Kind::HelloAck);
        self.chan.absorb(&ack);
        self.chan.set_version(1);
    }

    /// A signed attended `SESSION_REQUEST`, then the host's answer.
    async fn request_session(&mut self) -> Received {
        let request = SessionRequest {
            caps: Caps::default(),
            unattended: None,
        };
        self.chan
            .send(&request, Some(&self.identity))
            .await
            .unwrap();
        self.recv().await.unwrap()
    }

    async fn recv(&mut self) -> Option<Received> {
        self.chan
            .recv(Duration::from_secs(5), "frame")
            .await
            .unwrap()
    }
}

/// §B.3: the SAS is derived from `th_after(HELLO_ACK)` and the committed nonce, never
/// from `th_after(PAIR_REQUEST)`. `PAIR_REQUEST` is unsigned, its `client_auth_pk` is
/// discarded by the host and `decode_body` ignores unknown keys, so anything derived
/// from its bytes is grindable: a proxying MITM meets a 20-bit code in ~2^10 tries per
/// side and shows both users the same digits. Filler must not move the code.
#[tokio::test]
async fn pair_request_filler_cannot_move_the_sas() {
    async fn sas_with(filler: Option<[u8; 32]>) -> String {
        let tmp = tempfile::tempdir().unwrap();
        let mut host = host_side(tmp.path(), HOST_SEED);
        // Script host_nonce so th_after(HELLO_ACK) — the other SAS input — is identical
        // across runs and `client_auth_pk` is the only thing that varies.
        host.deps.random = Arc::new(ScriptedRandom::new(vec![vec![0x44]]));
        host.consent
            .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
        let (a, b) = pipe();
        let host_task = spawn_host(a, &host);
        let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
        raw.hello_ack().await;
        raw.chan
            .send(
                &PairRequest {
                    client_auth_pk: filler,
                    sas_nonce: RAW_SAS_NONCE,
                },
                None,
            )
            .await
            .unwrap();
        let accept = raw.recv().await.unwrap();
        assert_eq!(accept.env.kind, Kind::PairAccept);
        drop(raw);
        let _ = host_task.await;
        let shown = host.consent.sas_shown();
        assert_eq!(shown.len(), 1);
        shown[0].clone()
    }

    let plain = sas_with(None).await;
    // 32 bytes of attacker-chosen material the host parses and throws away.
    let filled = sas_with(Some([0xAB; 32])).await;
    let other = sas_with(Some([0xCD; 32])).await;
    assert_eq!(plain, filled, "client_auth_pk moved the SAS");
    assert_eq!(plain, other, "client_auth_pk moved the SAS");
}

/// §B.3: the revealed `sas_nonce` must open `HELLO.sas_commit`. Without this the peer
/// could pick its SAS contribution after seeing ours, which is what makes the code
/// grindable; the host must close instead of showing a popup.
#[tokio::test]
async fn pair_request_with_an_unopened_sas_commitment_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
    raw.hello_ack().await;
    raw.chan
        .send(
            &PairRequest {
                client_auth_pk: None,
                // Not the nonce committed to in HELLO.
                sas_nonce: [0x01; 32],
            },
            None,
        )
        .await
        .unwrap();
    let rx = raw.recv().await.unwrap();
    assert_eq!(
        rx.env.kind,
        Kind::Error,
        "expected ERROR, got {:?}",
        rx.env.kind
    );
    drop(raw);
    let _ = host_task.await;
    assert_eq!(
        host.consent.sas_shown().len(),
        0,
        "no pairing popup may run on an unopened commitment"
    );
}

/// §B.8 end-to-end: a real `connect(Intent::Unattended)` against a real host
/// running the real `UnattendedAuth` hook — no stubbed exchange anywhere. This
/// is the M1 acceptance shape of B.8.14 ("headless unattended handshake ending
/// in SESSION_ACCEPT"), minus the Tor transport.
#[tokio::test]
async fn unattended_session_end_to_end_over_a_duplex_pipe() {
    use std::sync::Arc as StdArc;

    use tornect_core::keystore::FileSecretStore;
    use tornect_core::paths::Paths;
    use tornect_core::session_log::{Actor, SessionLog};
    use tornect_core::unattended::clock::SystemClock;
    use tornect_core::unattended::grant::Preset;
    use tornect_core::unattended::guard::{
        AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
    };
    use tornect_core::unattended::ipc::GrantOptions;
    use tornect_core::unattended::limiter::{AttemptLimiter, HostTransport};
    use tornect_core::unattended::schedule::FixedOffset;
    use tornect_core::unattended::store::GrantStore;

    use crate::auth;
    use crate::fsm::client::UnattendedIntent;
    use crate::unattended::{OpaqueServerSetupSource, UnattendedAuth};

    const PW: &str = "quiet verdant otter lantern zephyr";

    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    let device = client.identity.id();
    let host_onion_pk = *host.identity.id().public_key_bytes();

    // Already paired both ways (a grant exists only for a SAS-paired device,
    // §B.8 hard rule 2); the pairing exchange itself is covered elsewhere.
    host.trusted.pin(device, "Laptop of Ana").unwrap();
    client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();

    // A host-side store with one grant for this device.
    let paths = Paths::from_home(tmp.path().join("host-home"));
    std::fs::create_dir_all(paths.keys_dir()).unwrap();
    let secrets = StdArc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
    let store = GrantStore::open(
        &paths,
        secrets,
        StdArc::new(SystemClock::default()),
        SessionLog::new(paths.sessions_log()),
    )
    .unwrap();
    let guard = MutationGuard::new(
        store,
        StdArc::new(AllowAllReAuth::default()),
        StdArc::new(NoSessionActivity),
    )
    .with_paired_devices(StdArc::new(AllowAllPaired))
    .with_server_setup_source(StdArc::new(OpaqueServerSetupSource));
    guard.master_on(Actor::Cli, &host_onion_pk).unwrap();
    guard
        .create_grant(
            Actor::Cli,
            &device,
            Preset::HeadlessBox,
            &GrantOptions::default(),
            &[0u8; 192],
        )
        .unwrap();
    let setup_bytes = guard.store().server_setup().unwrap();
    let setup = auth::parse_server_setup(&setup_bytes).unwrap();
    let record = auth::register_locally(
        &setup,
        PW,
        device.public_key_bytes(),
        auth::identifiers(device.public_key_bytes(), &host_onion_pk),
    )
    .unwrap();
    guard.set_password(Actor::Cli, &device, &record).unwrap();

    let mut host = host;
    host.deps.unattended = Arc::new(UnattendedAuth::new(
        AttemptLimiter::new(guard.store().clone()),
        Arc::new(FixedOffset::utc()),
        HostTransport::default(),
    ));

    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    let outcome = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Unattended(UnattendedIntent {
            password: zeroize::Zeroizing::new(PW.to_owned()),
            want_mode: messages::mode::CONTROL,
        }),
    )
    .await
    .expect("unattended connect");

    let session = match outcome {
        ClientOutcome::Session(s) => s,
        other => panic!("expected a session, got {other:?}"),
    };

    // The host reached Established with the *same* derived token, and no popup
    // ran on either side (that is the whole point of an unattended session).
    drop(session);
    match host_task.await.unwrap() {
        Ok(HostOutcome::Session { token, .. }) => {
            assert_eq!(token.session_id().len(), 16, "a derived token was minted");
        }
        other => panic!("host outcome: {other:?}"),
    }
    assert_eq!(host.consent.sas_shown().len(), 0, "no pairing popup ran");
}

/// Run the host in a task; returns its outcome once the stream ends.
fn spawn_host(
    stream: DuplexStream,
    side: &HostSide,
) -> tokio::task::JoinHandle<Result<HostOutcome, HandshakeError>> {
    let cfg = side.cfg.clone();
    let deps = side.deps.clone();
    tokio::spawn(async move { serve_host(stream, &cfg, &deps).await })
}

#[tokio::test]
async fn pairing_then_attended_session_ping_bye() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);

    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    let outcome = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap();
    let mut session = match outcome {
        ClientOutcome::Session(s) => s,
        ClientOutcome::Paired { .. } => panic!("expected a session"),
    };

    // Both sides showed the same SAS and pinned each other.
    let host_sas = host.consent.sas_shown();
    assert_eq!(host_sas.len(), 1);
    assert_eq!(client.ui.sas_shown(), host_sas);
    assert_eq!(host_sas[0].len(), 7);
    let device = client.identity.id();
    assert_eq!(host.trusted.get(&device).unwrap().label, "Laptop of Ana");
    let known = client.known.get(&host.identity.id()).unwrap();
    assert_eq!(known.label, "Desk of Bob");
    assert_eq!(known.host_device_pk, host_device_pk());
    assert_eq!(session.host_label(), "Desk of Bob");
    // The accept is attended, control, with the negotiated caps and the SPKI
    // of the host *device* key the client just pinned (§B.6, M1-31).
    let accept = session.accept();
    assert_eq!(accept.session_type(), 0);
    assert_eq!(accept.mode(), 0);
    assert_eq!(accept.caps().codecs, vec!["av1", "h264"]);
    assert_eq!(accept.caps().max_res.width, 1920);
    assert!(!accept.caps().hdr);
    assert_eq!(accept.quic_spki(), &ed25519_spki(&host_device_pk()));
    assert_ne!(
        accept.quic_spki(),
        &ed25519_spki(&HostSigner::public_key(&*host.identity)),
        "the onion key is Tor's identity, not the QUIC pin"
    );
    let token = session.session_token().clone();

    for _ in 0..3 {
        let rtt = session.ping().await.unwrap();
        assert!(rtt < Duration::from_secs(1));
    }
    session.bye(bye::USER).await.unwrap();

    match host_task.await.unwrap().unwrap() {
        HostOutcome::Session {
            device: d,
            label,
            paired_now,
            token: host_token,
            mode,
            unattended,
            end,
            ..
        } => {
            assert_eq!(d, device);
            assert_eq!(label, "Laptop of Ana");
            assert!(paired_now);
            assert_eq!(host_token, token, "session_token matches on both sides");
            assert_eq!(mode, SessionMode::Control);
            assert!(!unattended);
            assert_eq!(end, SessionEnd::PeerBye(bye::USER));
        }
        other => panic!("unexpected outcome {other:?}"),
    }
    assert_eq!(host.deps.stats.accepted_total.load(Ordering::SeqCst), 1);
    assert_eq!(host.deps.stats.streams.load(Ordering::SeqCst), 0);
    assert_eq!(host.deps.stats.established.load(Ordering::SeqCst), 0);

    // A second connection from the paired device skips the PAIR path.
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnceViewOnly));
    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    let outcome = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap();
    let session = match outcome {
        ClientOutcome::Session(s) => s,
        ClientOutcome::Paired { .. } => panic!("expected a session"),
    };
    assert_eq!(session.accept().mode(), 1);
    assert_eq!(host.consent.sas_shown().len(), 1, "no second pairing popup");
    session.bye(bye::USER).await.unwrap();
    match host_task.await.unwrap().unwrap() {
        HostOutcome::Session { paired_now, .. } => assert!(!paired_now),
        other => panic!("unexpected outcome {other:?}"),
    }
}

#[tokio::test]
async fn pair_only_then_known_host_session_and_denials() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept {
            label: Some("  Ana's\u{202E} laptop ".into()),
        }));
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);

    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    match connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::PairOnly,
    )
    .await
    .unwrap()
    {
        ClientOutcome::Paired { host_name } => assert_eq!(host_name, "Desk of Bob"),
        ClientOutcome::Session(_) => panic!("expected pair only"),
    }
    match host_task.await.unwrap().unwrap() {
        HostOutcome::PairedOnly { label, .. } => assert_eq!(label, "Ana's laptop"),
        other => panic!("unexpected outcome {other:?}"),
    }

    // PairOnly against a host this side already knows: no new exchange (the
    // host expects SESSION_REQUEST from a trusted device), just BYE.
    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    match connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::PairOnly,
    )
    .await
    .unwrap()
    {
        ClientOutcome::Paired { host_name } => assert_eq!(host_name, "Desk of Bob"),
        ClientOutcome::Session(_) => panic!("expected pair only"),
    }
    let err = host_task.await.unwrap().unwrap_err();
    assert!(
        matches!(
            err,
            HandshakeError::PeerBye {
                reason: bye::USER,
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(host.consent.sas_shown().len(), 1);

    // Denied session.
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::Deny));
    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::DENIED),
        "{err}"
    );
    assert!(matches!(
        host_task.await.unwrap().unwrap(),
        HostOutcome::SessionRejected {
            reason: reject::DENIED,
            ..
        }
    ));

    // Unattended requests hit the M1 seam: NOT_GRANTED.
    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
    raw.send_hello(None).await;
    let ack = raw.recv().await.unwrap();
    assert_eq!(ack.env.kind, Kind::HelloAck);
    raw.chan.absorb(&ack);
    raw.chan.set_version(1);
    let request = SessionRequest {
        caps: Caps::default(),
        unattended: Some(messages::UnattendedRequest {
            suite: 1,
            ke1: Some([0u8; 96]),
            want_mode: 0,
            intent: 0,
            admin: None,
        }),
    };
    raw.chan.send(&request, Some(&raw.identity)).await.unwrap();
    let rx = raw.recv().await.unwrap();
    assert_eq!(rx.env.kind, Kind::SessionReject);
    let rej: messages::SessionReject = decode_body(&rx.env.body).unwrap();
    assert_eq!(rej.reason, reject::NOT_GRANTED);
    assert!(matches!(
        host_task.await.unwrap().unwrap(),
        HostOutcome::SessionRejected {
            reason: reject::NOT_GRANTED,
            ..
        }
    ));
    assert_eq!(host.consent.session_popups(), 1, "no popup for unattended");
}

#[tokio::test]
async fn pairing_rejects_escalate_to_a_ban_and_the_client_can_refuse() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    for _ in 0..3 {
        host.consent
            .push_pairing(PairScript::Decide(PairDecision::Reject));
        let (a, b) = pipe();
        let host_task = spawn_host(a, &host);
        let err = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::PairRejected {
                reason: pair_reject::DENIED,
                ..
            }
        ));
        assert!(matches!(
            host_task.await.unwrap().unwrap(),
            HostOutcome::PairRejected {
                reason: pair_reject::DENIED,
                ..
            }
        ));
    }
    // Banned now: HELLO_ACK then PAIR_REJECT{BANNED}, no popup.
    let shown = host.consent.sas_shown().len();
    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            HandshakeError::PairRejected {
                reason: pair_reject::BANNED,
                ..
            }
        ),
        "{err}"
    );
    assert!(matches!(
        host_task.await.unwrap().unwrap(),
        HostOutcome::PairRejected {
            reason: pair_reject::BANNED,
            ..
        }
    ));
    assert_eq!(host.consent.sas_shown().len(), shown);
    assert!(host.trusted.banned_until(&client.identity.id()).is_some());
    assert!(!client.known.is_known(&host.identity.id()));

    // Another device: the client user refuses the SAS ⇒ BYE, nothing pinned on the client.
    let other = client_side(
        tmp.path().join("c2").as_path(),
        host.identity.id(),
        [0x23; 32],
    );
    let refusing = Arc::new(ScriptedClientUi::new(false));
    let mut deps = other.deps.clone();
    deps.ui = refusing.clone();
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    let err = connect(b, &other.cfg, &other.identity, &deps, Intent::Session)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        HandshakeError::Aborted("pairing not confirmed")
    ));
    assert!(!other.known.is_known(&host.identity.id()));
    // The host pinned it (documented: the host user already confirmed).
    assert!(host.trusted.get(&other.identity.id()).is_some());
    assert!(matches!(
        host_task.await.unwrap().unwrap(),
        HostOutcome::PairedOnly { .. }
    ));
}

/// A1 / A13 (signaling half): an unpaired peer takes the PAIR path, and the
/// host's answers are the same with a random `stop_token`, without one, and
/// with the "correct" one — signatures aside, which necessarily differ with
/// the transcript. The stop-token seam sees the token and nothing else changes.
#[tokio::test]
async fn unpaired_peer_takes_the_pair_path_regardless_of_stop_token() {
    #[derive(Default)]
    struct Recorder(Mutex<Vec<[u8; 32]>>);
    impl StopTokenCheck for Recorder {
        fn observe<'a>(&'a self, token: &'a [u8; 32]) -> BoxFuture<'a, ()> {
            self.0.lock().unwrap().push(*token);
            Box::pin(async {})
        }
    }

    async fn run(
        tmp: &std::path::Path,
        stop_token: Option<[u8; 32]>,
    ) -> (Vec<(u8, u64, Kind, Vec<u8>)>, usize) {
        let mut host = host_side(tmp, HOST_SEED);
        host.deps.random = Arc::new(ScriptedRandom::new(vec![vec![0x44]]));
        let recorder = Arc::new(Recorder::default());
        host.deps.stop_token = recorder.clone();
        let (a, b) = pipe();
        let host_task = spawn_host(a, &host);
        let mut raw = RawClient::new(b, &host.identity, [0x77; 32]);
        raw.send_hello(stop_token).await;
        let mut frames = Vec::new();
        let ack = raw.recv().await.unwrap();
        raw.chan.absorb(&ack);
        raw.chan.set_version(1);
        frames.push((
            ack.env.v,
            ack.env.msg_id,
            ack.env.kind,
            ack.env.body.clone(),
        ));
        raw.chan.send(&raw_pair_request(), None).await.unwrap();
        let rej = raw.recv().await.unwrap();
        frames.push((
            rej.env.v,
            rej.env.msg_id,
            rej.env.kind,
            rej.env.body.clone(),
        ));
        assert!(raw.recv().await.is_none(), "host closed after the reject");
        let _ = host_task.await.unwrap();
        (frames, recorder.0.lock().unwrap().len())
    }

    let tmp = tempfile::tempdir().unwrap();
    let (none, seen_none) = run(&tmp.path().join("a"), None).await;
    let (random, seen_random) = run(&tmp.path().join("b"), Some([0x5A; 32])).await;
    let (correct, seen_correct) = run(&tmp.path().join("c"), Some([0xC0; 32])).await;
    assert_eq!(none, random);
    assert_eq!(none, correct);
    assert_eq!(none[0].2, Kind::HelloAck);
    assert_eq!(none[1].2, Kind::PairReject);
    let rej: messages::PairReject = decode_body(&none[1].3).unwrap();
    assert_eq!(rej.reason, pair_reject::DENIED);
    assert_eq!((seen_none, seen_random, seen_correct), (0, 1, 1));
}

/// A3 (signaling half): a recorded `HELLO` + `SESSION_REQUEST` replayed on a
/// fresh stream ⇒ `E_BAD_SIG` (the fresh `host_nonce` is under the signature),
/// nothing accepted, no popup.
#[tokio::test]
async fn replayed_hello_and_session_request_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Recorded")
        .unwrap();
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));

    // Record a genuine exchange.
    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
    let hello_wire = raw.send_hello(None).await;
    let ack = raw.recv().await.unwrap();
    raw.chan.absorb(&ack);
    raw.chan.set_version(1);
    let request = SessionRequest {
        caps: Caps::default(),
        unattended: None,
    };
    let request_wire = raw.chan.send(&request, Some(&raw.identity)).await.unwrap();
    let accept = raw.recv().await.unwrap();
    assert_eq!(accept.env.kind, Kind::SessionAccept);
    raw.chan.bye(bye::USER).await.unwrap();
    host_task.await.unwrap().unwrap();
    assert_eq!(host.consent.session_popups(), 1);

    // Replay both frames verbatim.
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let (a, mut b) = pipe();
    let host_task = spawn_host(a, &host);
    write_frame(&mut b, &hello_wire).await.unwrap();
    let mut peek = Channel::new(b, &HostSigner::public_key(&*host.identity));
    let ack = peek
        .recv(Duration::from_secs(5), "ack")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ack.env.kind,
        Kind::HelloAck,
        "HELLO is replayable by design"
    );
    let mut stream = peek.into_stream();
    write_frame(&mut stream, &request_wire).await.unwrap();
    let mut peek = Channel::new(stream, &[0u8; 32]);
    // The first frame we read here is the host's msg_id 2; skip the id check by
    // reading raw.
    let err = host_task.await.unwrap().unwrap_err();
    assert_eq!(err.violation_code(), Some(codes::E_BAD_SIG), "{err}");
    let _ = peek.close().await;
    assert_eq!(host.consent.session_popups(), 1, "no popup for the replay");
    assert_eq!(host.deps.stats.accepted_total.load(Ordering::SeqCst), 1);
}

/// A17: 50 bare `HELLO`s held open do not keep a paired device from reaching
/// the consent popup; the per-stream state is one small frame cap and a few
/// hashes, and the counters say exactly how many streams sit in `HelloVerified`.
#[tokio::test]
async fn fifty_bare_hellos_do_not_block_a_paired_device() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    let paired = DeviceIdentity::from_seed(&CLIENT_SEED);
    host.trusted.pin(paired.id(), "Paired").unwrap();
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));

    let mut holders = Vec::new();
    let mut tasks = Vec::new();
    for i in 0..50u8 {
        let (a, b) = pipe();
        tasks.push(spawn_host(a, &host));
        let mut seed = [0x80u8; 32];
        seed[0] = i;
        let mut raw = RawClient::new(b, &host.identity, seed);
        raw.send_hello(None).await;
        let ack = raw.recv().await.unwrap();
        assert_eq!(ack.env.kind, Kind::HelloAck);
        holders.push(raw);
    }
    assert_eq!(host.deps.stats.hello_verified.load(Ordering::SeqCst), 50);
    assert_eq!(host.deps.stats.streams.load(Ordering::SeqCst), 50);
    assert_eq!(HANDSHAKE_FRAME_CAP, 8 * 1024);

    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    let (a, b) = pipe();
    let paired_task = spawn_host(a, &host);
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        ),
    )
    .await
    .expect("not blocked by the bare HELLOs")
    .unwrap();
    assert_eq!(host.consent.session_popups(), 1);
    match outcome {
        ClientOutcome::Session(s) => s.bye(bye::USER).await.unwrap(),
        ClientOutcome::Paired { .. } => panic!("expected a session"),
    }
    paired_task.await.unwrap().unwrap();
    assert_eq!(host.deps.stats.hello_verified.load(Ordering::SeqCst), 50);
    drop(holders);
    for t in tasks {
        let err = t.await.unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::Closed), "{err}");
    }
    assert_eq!(host.deps.stats.streams.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn protocol_violations_get_the_documented_codes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    let host_pk = HostSigner::public_key(&*host.identity);

    // Helper: send raw bytes, expect ERROR{code} from the host and the given host error.
    async fn expect_error(host: &HostSide, frames: Vec<Vec<u8>>, code: u16) {
        let (a, mut b) = pipe();
        let task = spawn_host(a, host);
        for f in &frames {
            write_frame(&mut b, f).await.unwrap();
        }
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err.violation_code(), Some(code), "{err}");
        // The host's answer is exactly one ERROR frame, then EOF.
        let mut chan = Channel::new(b, &[0u8; 32]);
        let rx = chan
            .recv(Duration::from_secs(5), "err")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rx.env.kind, Kind::Error);
        let e: messages::Error = decode_body(&rx.env.body).unwrap();
        assert_eq!(e.code, code);
        assert_eq!(e.detail.as_deref(), Some(codes::name(code)));
        assert!(
            chan.recv(Duration::from_secs(5), "eof")
                .await
                .unwrap()
                .is_none()
        );
    }

    let identity = DeviceIdentity::from_seed(&CLIENT_SEED);
    let th0 = Transcript::new(&host_pk).current();
    let hello = Hello {
        v_max: 1,
        client_nonce: [1; 32],
        device_pk: HostSigner::public_key(&identity),
        name: "x".into(),
        feats: vec![],
        stop_token: None,
        pairing_state: 0,
        sas_commit: crate::pairing::sas_commit(&RAW_SAS_NONCE),
    };
    let signed = |v: u8, msg_id: u64, kind: Kind, body: Vec<u8>| {
        let mut env = Envelope::new(v, msg_id, kind, body);
        sign_envelope(&identity, &th0, &mut env);
        env.encode()
    };
    let hello_body = encode_body(&hello);

    // Not an envelope.
    expect_error(&host, vec![vec![0x01, 0x02]], codes::E_BAD_LEN).await;
    // A signature of the wrong length is a size-fixed field of the wrong
    // length (§B.8.4.1) ⇒ E_BAD_LEN, not E_BAD_SIG.
    expect_error(
        &host,
        vec![vec![0x85, 1, 1, 1, 0x40, 0x43, 0, 0, 0]],
        codes::E_BAD_LEN,
    )
    .await;
    // Unknown kind.
    expect_error(
        &host,
        vec![vec![0x85, 1, 1, 0x18, 0x63, 0x40, 0xf6]],
        codes::E_UNKNOWN_KIND,
    )
    .await;
    // msg_id must start at 1.
    expect_error(
        &host,
        vec![signed(1, 2, Kind::Hello, hello_body.clone())],
        codes::E_BAD_MSG_ID,
    )
    .await;
    // HELLO must carry v = 1.
    expect_error(
        &host,
        vec![signed(2, 1, Kind::Hello, hello_body.clone())],
        codes::E_VERSION,
    )
    .await;
    // PING before HELLO.
    expect_error(
        &host,
        vec![Envelope::new(1, 1, Kind::Ping, encode_body(&Ping { nonce: 1 })).encode()],
        codes::E_BAD_STATE,
    )
    .await;
    // Unsigned HELLO ⇒ E_BAD_SIG; forged pk ⇒ E_BAD_SIG (byte-identical answer).
    expect_error(
        &host,
        vec![Envelope::new(1, 1, Kind::Hello, hello_body.clone()).encode()],
        codes::E_BAD_SIG,
    )
    .await;
    let forged = Hello {
        device_pk: [9u8; 32],
        ..hello.clone()
    };
    expect_error(
        &host,
        vec![signed(1, 1, Kind::Hello, encode_body(&forged))],
        codes::E_BAD_SIG,
    )
    .await;
    // Malformed HELLO body ⇒ E_BAD_LEN.
    expect_error(
        &host,
        vec![signed(1, 1, Kind::Hello, vec![0xa0])],
        codes::E_BAD_LEN,
    )
    .await;
    // A name over the bound ⇒ E_BAD_LEN.
    let long = Hello {
        name: "n".repeat(65),
        ..hello.clone()
    };
    expect_error(
        &host,
        vec![signed(1, 1, Kind::Hello, encode_body(&long))],
        codes::E_BAD_LEN,
    )
    .await;
    // v_max = 0 ⇒ E_VERSION.
    let v0 = Hello {
        v_max: 0,
        ..hello.clone()
    };
    expect_error(
        &host,
        vec![signed(1, 1, Kind::Hello, encode_body(&v0))],
        codes::E_VERSION,
    )
    .await;
    // Oversize frame during the handshake ⇒ E_TOO_LARGE (announced only; the
    // host refuses at the header).
    {
        let (a, mut b) = pipe();
        let task = spawn_host(a, &host);
        b.write_all(&(HANDSHAKE_FRAME_CAP as u32 + 1).to_be_bytes())
            .await
            .unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err.violation_code(), Some(codes::E_TOO_LARGE), "{err}");
    }
    // A valid HELLO followed by a PING (strict alternation) ⇒ E_BAD_STATE, and
    // a second HELLO likewise.
    for second in [Kind::Ping, Kind::Hello, Kind::SessionRequest] {
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
        raw.send_hello(None).await;
        let ack = raw.recv().await.unwrap();
        raw.chan.absorb(&ack);
        raw.chan.set_version(1);
        let body = match second {
            Kind::Ping => encode_body(&Ping { nonce: 1 }),
            Kind::Hello => hello_body.clone(),
            _ => encode_body(&SessionRequest {
                caps: Caps::default(),
                unattended: None,
            }),
        };
        raw.chan
            .send_kind(second, body, Some(&raw.identity))
            .await
            .unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(
            err.violation_code(),
            Some(codes::E_BAD_STATE),
            "{second}: {err}"
        );
    }
    // Wrong msg_id after HELLO ⇒ E_BAD_MSG_ID.
    {
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
        raw.send_hello(None).await;
        let _ack = raw.recv().await.unwrap();
        let mut stream = raw.chan.into_stream();
        let env = Envelope::new(1, 5, Kind::PairRequest, encode_body(&raw_pair_request()));
        write_frame(&mut stream, &env.encode()).await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err.violation_code(), Some(codes::E_BAD_MSG_ID), "{err}");
    }
    // Wrong version after negotiation ⇒ E_VERSION.
    {
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
        raw.send_hello(None).await;
        let _ack = raw.recv().await.unwrap();
        let mut stream = raw.chan.into_stream();
        let env = Envelope::new(2, 2, Kind::PairRequest, encode_body(&raw_pair_request()));
        write_frame(&mut stream, &env.encode()).await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err.violation_code(), Some(codes::E_VERSION), "{err}");
    }
    // Peer BYE before HELLO ends the stream quietly.
    {
        let (a, mut b) = pipe();
        let task = spawn_host(a, &host);
        let env = Envelope::new(
            1,
            1,
            Kind::Bye,
            encode_body(&messages::Bye {
                reason: bye::USER,
                detail: None,
            }),
        );
        write_frame(&mut b, &env.encode()).await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert!(
            matches!(
                err,
                HandshakeError::PeerBye {
                    reason: bye::USER,
                    ..
                }
            ),
            "{err}"
        );
    }
    assert_eq!(host.consent.session_popups(), 0);
    assert_eq!(host.consent.sas_shown().len(), 0);
}

/// A raw host for client-side checks: answers with frames the test crafts,
/// signing with `signer` over a transcript seeded with `th_pk`.
struct RawHost {
    chan: Channel<DuplexStream>,
}

impl RawHost {
    fn new(stream: DuplexStream, th_pk: &[u8; 32]) -> Self {
        Self {
            chan: Channel::new(stream, th_pk),
        }
    }

    async fn take_hello(&mut self) -> Received {
        let rx = self
            .chan
            .recv(Duration::from_secs(5), "hello")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rx.env.kind, Kind::Hello);
        self.chan.absorb(&rx);
        rx
    }

    async fn ack(&mut self, signer: &dyn HostSigner) {
        let ack = messages::HelloAck {
            v: 1,
            host_nonce: [0x44; 32],
            feats: vec![],
        };
        self.chan.send(&ack, Some(signer)).await.unwrap();
        self.chan.set_version(1);
    }

    async fn take(&mut self, kind: Kind) -> Received {
        let rx = self
            .chan
            .recv(Duration::from_secs(5), "frame")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rx.env.kind, kind);
        self.chan.absorb(&rx);
        rx
    }
}

/// A genuine attended accept: the SPKI of the pinned host device key.
fn genuine_accept() -> messages::SessionAccept {
    messages::SessionAccept {
        caps: Caps::default(),
        quic_spki: ed25519_spki(&host_device_pk()),
        session_type: 0,
        mode: 0,
        transport_policy: 0,
        session_token: Some([0x55; 32]),
        token_confirm: None,
        block_window_s: 0,
        ask_before_start: false,
        ends_at: None,
        fail_summary: None,
    }
}

/// [`genuine_accept`] with one field changed (`SessionAccept` zeroizes on
/// drop, so struct update syntax cannot move out of it).
fn accept_with(change: impl FnOnce(&mut messages::SessionAccept)) -> messages::SessionAccept {
    let mut accept = genuine_accept();
    change(&mut accept);
    accept
}

#[tokio::test]
async fn client_side_checks_reject_a_forged_host() {
    let tmp = tempfile::tempdir().unwrap();
    let real = HostIdentity::from_seed(&HOST_SEED);
    let real_pk = HostSigner::public_key(&real);
    let phisher = HostIdentity::from_seed(&[0x99; 32]);
    let phisher_pk = HostSigner::public_key(&phisher);
    let client = client_side(tmp.path(), real.id(), CLIENT_SEED);
    client
        .known
        .pin(real.id(), "Desk of Bob", host_device_pk())
        .unwrap();

    // A relay that forwards the transcript faithfully but signs HELLO_ACK
    // with its own key: the client verifies against the dialed address.
    {
        let (a, b) = pipe();
        let relay = tokio::spawn(async move {
            let mut h = RawHost::new(a, &real_pk);
            h.take_hello().await;
            h.ack(&phisher).await;
            h.chan.recv(Duration::from_secs(5), "err").await
        });
        let err = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        )
        .await
        .unwrap_err();
        assert_eq!(err.violation_code(), Some(codes::E_BAD_SIG), "{err}");
        let seen = relay.await.unwrap().unwrap().unwrap();
        assert_eq!(seen.env.kind, Kind::Error);
    }

    // Genuinely signed accepts with a wrong field each: aborted before any session.
    let cases: Vec<(messages::SessionAccept, u16, &str)> = vec![
        (
            accept_with(|a| {
                a.session_type = 1;
                a.session_token = None;
                a.token_confirm = Some([1u8; 32]);
            }),
            codes::E_BAD_STATE,
            "session_type = 1 on an attended request",
        ),
        (
            accept_with(|a| a.session_token = None),
            codes::E_BAD_LEN,
            "no session_token",
        ),
        (
            accept_with(|a| a.token_confirm = Some([1u8; 32])),
            codes::E_BAD_LEN,
            "token_confirm on an attended accept",
        ),
        (
            accept_with(|a| a.quic_spki = ed25519_spki(&phisher_pk)),
            codes::E_BAD_SIG,
            "quic_spki of another key",
        ),
        (
            accept_with(|a| a.quic_spki = ed25519_spki(&real_pk)),
            codes::E_BAD_SIG,
            "quic_spki of the onion key instead of the pinned host_device_pk",
        ),
        (
            accept_with(|a| a.mode = 7),
            codes::E_BAD_LEN,
            "unknown mode",
        ),
    ];
    for (accept, code, what) in cases {
        let (a, b) = pipe();
        let signer = HostIdentity::from_seed(&HOST_SEED);
        let relay = tokio::spawn(async move {
            let mut h = RawHost::new(a, &real_pk);
            h.take_hello().await;
            h.ack(&signer).await;
            h.take(Kind::SessionRequest).await;
            h.chan.send(&accept, Some(&signer)).await.unwrap();
            h.chan.recv(Duration::from_secs(5), "err").await
        });
        let err = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        )
        .await
        .unwrap_err();
        assert_eq!(err.violation_code(), Some(code), "{what}: {err}");
        let seen = relay.await.unwrap().unwrap().unwrap();
        assert_eq!(seen.env.kind, Kind::Error, "{what}");
    }

    // A genuine accept with a bad signature (signed by the phisher over the
    // right transcript) ⇒ E_BAD_SIG; an unsigned one too.
    for signer_is_real in [false, true] {
        let (a, b) = pipe();
        let real_signer = HostIdentity::from_seed(&HOST_SEED);
        let phish_signer = HostIdentity::from_seed(&[0x99; 32]);
        let relay = tokio::spawn(async move {
            let mut h = RawHost::new(a, &real_pk);
            h.take_hello().await;
            h.ack(&real_signer).await;
            h.take(Kind::SessionRequest).await;
            let accept = genuine_accept();
            let signer: Option<&dyn HostSigner> = if signer_is_real {
                None
            } else {
                Some(&phish_signer)
            };
            h.chan.send(&accept, signer).await.unwrap();
            h.chan.recv(Duration::from_secs(5), "err").await
        });
        let err = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        )
        .await
        .unwrap_err();
        assert_eq!(err.violation_code(), Some(codes::E_BAD_SIG), "{err}");
        relay.await.unwrap().unwrap();
    }

    // Wrong msg_id / version from the host ⇒ the client enforces too.
    for (v, msg_id, code) in [(1u8, 7u64, codes::E_BAD_MSG_ID), (3, 1, codes::E_VERSION)] {
        let (a, mut b) = pipe();
        let mut chan = Channel::new(a, &real_pk);
        let relay = tokio::spawn(async move {
            let rx = chan
                .recv(Duration::from_secs(5), "hello")
                .await
                .unwrap()
                .unwrap();
            chan.absorb(&rx);
            let ack = messages::HelloAck {
                v,
                host_nonce: [0x44; 32],
                feats: vec![],
            };
            let mut env = Envelope::new(v, msg_id, Kind::HelloAck, encode_body(&ack));
            sign_envelope(&HostIdentity::from_seed(&HOST_SEED), &chan.th(), &mut env);
            let mut stream = chan.into_stream();
            write_frame(&mut stream, &env.encode()).await.unwrap();
            stream
        });
        let err = connect(
            &mut b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        )
        .await
        .unwrap_err();
        assert_eq!(err.violation_code(), Some(code), "{err}");
        drop(relay.await.unwrap());
    }

    // A PAIR_ACCEPT whose host_device_pk is not an Ed25519 point is refused
    // before the user is asked to confirm anything (E_BAD_LEN).
    {
        let fresh = client_side(tmp.path().join("fresh").as_path(), real.id(), CLIENT_SEED);
        let (a, b) = pipe();
        let signer = HostIdentity::from_seed(&HOST_SEED);
        let relay = tokio::spawn(async move {
            let mut h = RawHost::new(a, &real_pk);
            h.take_hello().await;
            h.ack(&signer).await;
            h.take(Kind::PairRequest).await;
            let accept = messages::PairAccept {
                host_device_pk: [0xB0; 32],
                host_name: "Desk".into(),
            };
            h.chan.send(&accept, None).await.unwrap();
            h.chan.recv(Duration::from_secs(5), "err").await
        });
        let err = connect(b, &fresh.cfg, &fresh.identity, &fresh.deps, Intent::Session)
            .await
            .unwrap_err();
        assert_eq!(err.violation_code(), Some(codes::E_BAD_LEN), "{err}");
        let seen = relay.await.unwrap().unwrap().unwrap();
        assert_eq!(seen.env.kind, Kind::Error);
        assert!(
            fresh.ui.asked.lock().unwrap().is_empty(),
            "no confirm popup"
        );
        assert!(!fresh.known.is_known(&real.id()));
    }

    // A silent host: HELLO_ACK timeout (20 s) under paused time.
    tokio::time::pause();
    let (_a, b) = pipe();
    let started = tokio::time::Instant::now();
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, HandshakeError::Timeout("HELLO_ACK")), "{err}");
    assert!(started.elapsed() >= timeouts::HELLO_ACK);
    assert!(started.elapsed() < timeouts::HELLO_ACK + Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn host_timeouts_are_the_plan_values() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);

    // No HELLO at all.
    let (_a, b) = pipe();
    let started = tokio::time::Instant::now();
    let err = serve_host(b, &host.cfg, &host.deps).await.unwrap_err();
    assert!(matches!(err, HandshakeError::Timeout("HELLO")), "{err}");
    assert_eq!(started.elapsed(), timeouts::HELLO);

    // HELLO then silence: 60 s to SESSION_REQUEST / PAIR_REQUEST.
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
    raw.send_hello(None).await;
    let _ack = raw.recv().await.unwrap();
    let started = tokio::time::Instant::now();
    let err = task.await.unwrap().unwrap_err();
    assert!(
        matches!(err, HandshakeError::Timeout("PAIR_REQUEST")),
        "{err}"
    );
    assert!(started.elapsed() >= timeouts::SESSION_REQUEST - Duration::from_millis(50));
    assert!(started.elapsed() <= timeouts::SESSION_REQUEST + Duration::from_millis(50));

    // Pairing popup hangs ⇒ PAIR_REJECT{TIMEOUT} after 60 s.
    host.consent.push_pairing(PairScript::Hang);
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let started = tokio::time::Instant::now();
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            HandshakeError::PairRejected {
                reason: pair_reject::TIMEOUT,
                ..
            }
        ),
        "{err}"
    );
    assert!(started.elapsed() >= timeouts::POPUP);
    assert!(started.elapsed() < timeouts::PAIR_ACCEPT);
    assert!(matches!(
        task.await.unwrap().unwrap(),
        HostOutcome::PairRejected {
            reason: pair_reject::TIMEOUT,
            ..
        }
    ));

    // Session popup hangs ⇒ SESSION_REJECT{POPUP_TIMEOUT} after 60 s; the
    // timer restarted at PAIR_ACCEPT so the pairing wait never cut it short.
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    host.consent.push_session(SessionScript::Hang);
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let started = tokio::time::Instant::now();
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::POPUP_TIMEOUT),
        "{err}"
    );
    assert!(started.elapsed() >= timeouts::POPUP);
    assert!(started.elapsed() < timeouts::SESSION_ACCEPT);
    assert!(matches!(
        task.await.unwrap().unwrap(),
        HostOutcome::SessionRejected {
            reason: reject::POPUP_TIMEOUT,
            ..
        }
    ));

    // Established: no CANDIDATES within 15 s ⇒ BYE{ORPHANED}.
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let session = match connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap()
    {
        ClientOutcome::Session(s) => s,
        ClientOutcome::Paired { .. } => panic!(),
    };
    let started = tokio::time::Instant::now();
    match task.await.unwrap().unwrap() {
        HostOutcome::Session { end, .. } => assert_eq!(end, SessionEnd::Orphaned),
        other => panic!("{other:?}"),
    }
    assert!(started.elapsed() >= timeouts::ORPHAN);
    assert!(started.elapsed() < timeouts::ESTABLISHED_IDLE);
    drop(session);

    // `TOR_FALLBACK{}` right after the accept (the M1 Tor-only flow) stops
    // the orphan timer: the stream then lives until the 90 s idle bound.
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut session = match connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap()
    {
        ClientOutcome::Session(s) => s,
        ClientOutcome::Paired { .. } => panic!(),
    };
    session.send_tor_fallback().await.unwrap();
    let started = tokio::time::Instant::now();
    match task.await.unwrap().unwrap() {
        HostOutcome::Session { end, .. } => assert_eq!(end, SessionEnd::Idle),
        other => panic!("{other:?}"),
    }
    assert!(started.elapsed() >= timeouts::ESTABLISHED_IDLE);
    drop(session);
}

/// A host-configured timeout near `Duration::MAX` means "never", not a panic
/// in the `Established` loop.
#[tokio::test(start_paused = true)]
async fn extreme_established_timeouts_never_panic() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.cfg.orphan_timeout = Some(Duration::MAX);
    host.cfg.idle_timeout = Duration::MAX;
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut session = match connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap()
    {
        ClientOutcome::Session(s) => s,
        ClientOutcome::Paired { .. } => panic!(),
    };
    session.ping().await.unwrap();
    session.bye(bye::USER).await.unwrap();
    match task.await.unwrap().unwrap() {
        HostOutcome::Session { end, .. } => assert_eq!(end, SessionEnd::PeerBye(bye::USER)),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn established_session_ends_on_kill_switch_and_idle() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.cfg.orphan_timeout = None;
    host.cfg.idle_timeout = Duration::from_secs(30);
    let kill = KillSwitch::new();
    host.deps.kill = kill.clone();
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();

    // Kill switch.
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut session = match connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap()
    {
        ClientOutcome::Session(s) => s,
        ClientOutcome::Paired { .. } => panic!(),
    };
    session.ping().await.unwrap();
    kill.kill(bye::PANIC);
    match task.await.unwrap().unwrap() {
        HostOutcome::Session { end, .. } => assert_eq!(end, SessionEnd::Killed(bye::PANIC)),
        other => panic!("{other:?}"),
    }
    let event = session.next_event(Duration::from_secs(5)).await.unwrap();
    assert_eq!(
        event,
        Some(SessionEvent::Bye {
            reason: bye::PANIC,
            detail: None
        })
    );

    // Idle.
    let host2 = {
        let mut h = host_side(tmp.path().join("h2").as_path(), HOST_SEED);
        h.cfg.orphan_timeout = None;
        h.cfg.idle_timeout = Duration::from_secs(30);
        h.trusted
            .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
            .unwrap();
        h.consent
            .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
        h
    };
    let (a, b) = pipe();
    let task = spawn_host(a, &host2);
    let session = match connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap()
    {
        ClientOutcome::Session(s) => s,
        ClientOutcome::Paired { .. } => panic!(),
    };
    let started = tokio::time::Instant::now();
    match task.await.unwrap().unwrap() {
        HostOutcome::Session { end, .. } => assert_eq!(end, SessionEnd::Idle),
        other => panic!("{other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_secs(30));
    drop(session);
}

/// A kill fired for an earlier session must not latch onto the next one. The
/// switch still reports `fired()`, but a session accepted afterwards is armed
/// against the newer generation and stays live — the host answers its `PING`
/// instead of sending `BYE` on entry — while a kill fired *during* the live
/// session still tears it down. Regression: the old `watch<Option<u16>>`
/// returned the latched reason to every later session, ending it immediately.
#[tokio::test(start_paused = true)]
async fn a_prior_kill_does_not_latch_onto_a_later_session() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.cfg.orphan_timeout = None;
    host.cfg.idle_timeout = Duration::from_secs(30);
    let kill = KillSwitch::new();
    host.deps.kill = kill.clone();
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();

    // A kill fired before this stream is even accepted (a master-off left over
    // from an earlier session). It stays observable through `fired()`…
    kill.kill(bye::MASTER_OFF);
    assert_eq!(kill.fired(), Some(bye::MASTER_OFF));

    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut session = match connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap()
    {
        ClientOutcome::Session(s) => s,
        ClientOutcome::Paired { .. } => panic!(),
    };

    // …but the later session is not killed on entry: the host answers the ping.
    // On the latched code this returned `Err(PeerBye { MASTER_OFF })`.
    session
        .ping()
        .await
        .expect("host answers ping, not BYE on entry");

    // A kill fired now, during the live session, still ends it: host-wide
    // teardown of live sessions is intact.
    kill.kill(bye::PANIC);
    match task.await.unwrap().unwrap() {
        HostOutcome::Session { end, .. } => assert_eq!(end, SessionEnd::Killed(bye::PANIC)),
        other => panic!("{other:?}"),
    }
    let event = session.next_event(Duration::from_secs(5)).await.unwrap();
    assert_eq!(
        event,
        Some(SessionEvent::Bye {
            reason: bye::PANIC,
            detail: None
        })
    );
}

#[tokio::test]
async fn candidates_reach_the_sink_and_busy_hosts_reject() {
    #[derive(Default)]
    struct Sink(Mutex<Vec<String>>);
    impl CandidateSink for Sink {
        fn on_candidates(&self, c: messages::Candidates) {
            self.0.lock().unwrap().extend(c.candidates);
        }
        fn on_candidates_done(&self) {
            self.0.lock().unwrap().push("done".into());
        }
        fn on_tor_fallback(&self) {
            self.0.lock().unwrap().push("tor".into());
        }
    }
    struct Live;
    impl SessionActivity for Live {
        fn session_live(&self) -> bool {
            true
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let sink = Arc::new(Sink::default());
    host.deps.candidates = sink.clone();
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut session = match connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap()
    {
        ClientOutcome::Session(s) => s,
        ClientOutcome::Paired { .. } => panic!(),
    };
    session
        .send_candidates(&messages::Candidates {
            candidates: vec!["192.0.2.1:4000".into()],
        })
        .await
        .unwrap();
    session.ping().await.unwrap();
    session.send_tor_fallback().await.unwrap();
    session.bye(bye::USER).await.unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(sink.0.lock().unwrap().as_slice(), ["192.0.2.1:4000", "tor"]);

    // A live remote session suppresses popups: BUSY for sessions and pairing.
    host.deps.activity = Arc::new(Live);
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::BUSY),
        "{err}"
    );
    task.await.unwrap().unwrap();
    let other = client_side(
        tmp.path().join("o").as_path(),
        host.identity.id(),
        [0x24; 32],
    );
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let err = connect(b, &other.cfg, &other.identity, &other.deps, Intent::Session)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            HandshakeError::PairRejected {
                reason: pair_reject::BUSY,
                ..
            }
        ),
        "{err}"
    );
    assert!(matches!(
        task.await.unwrap().unwrap(),
        HostOutcome::PairRejected {
            reason: pair_reject::BUSY,
            ..
        }
    ));
    assert_eq!(host.consent.session_popups(), 1);
    assert_eq!(host.consent.sas_shown().len(), 0);
}

#[tokio::test]
async fn one_pair_request_in_flight_per_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    host.consent.push_pairing(PairScript::Hang);
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    let (a, b) = pipe();
    let first = spawn_host(a, &host);
    let cfg = client.cfg.clone();
    let deps = client.deps.clone();
    let identity = DeviceIdentity::from_seed(&CLIENT_SEED);
    let first_client =
        tokio::spawn(async move { connect(b, &cfg, &identity, &deps, Intent::Session).await });
    // Wait until the first popup is open.
    tokio::time::timeout(Duration::from_secs(5), async {
        while host.deps.stats.pair_pending.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (a, b) = pipe();
    let second = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            HandshakeError::PairRejected {
                reason: pair_reject::IN_FLIGHT,
                ..
            }
        ),
        "{err}"
    );
    assert!(matches!(
        second.await.unwrap().unwrap(),
        HostOutcome::PairRejected {
            reason: pair_reject::IN_FLIGHT,
            ..
        }
    ));
    first.abort();
    first_client.abort();
}

#[test]
fn scripted_random_repeats_its_last_value() {
    let r = ScriptedRandom::new(vec![vec![1, 2], vec![9]]);
    let mut a = [0u8; 4];
    r.fill(&mut a).unwrap();
    assert_eq!(a, [1, 2, 1, 2]);
    r.fill(&mut a).unwrap();
    assert_eq!(a, [9; 4]);
    r.fill(&mut a).unwrap();
    assert_eq!(a, [9; 4]);
    let empty = ScriptedRandom::default();
    let mut b = [7u8; 2];
    empty.fill(&mut b).unwrap();
    assert_eq!(b, [7, 7], "nothing scripted ⇒ untouched");
    let mut c = [0u8; 8];
    OsRandom.fill(&mut c).unwrap();
}

#[test]
fn audit_events_land_in_the_session_log_without_secrets_or_declared_names() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("sessions.log");
    let log = Arc::new(SessionLog::new(path.clone()));
    let audit = HostAudit::new(log.clone());
    let device = DeviceId::from_bytes([3u8; 32]);
    let token = SessionToken::new([0xAB; 32]);
    let session_id = token.session_id();
    audit.record(AuditEvent::PairRequested {
        device,
        declared_name: "Chosen by the peer".into(),
    });
    audit.record(AuditEvent::PairRejected {
        device,
        declared_name: "Chosen by the peer".into(),
        reason: pair_reject::DENIED,
    });
    audit.record(AuditEvent::SessionStarted {
        device,
        label: "n".into(),
        session_id: session_id.clone(),
        mode: SessionMode::ViewOnly,
        unattended: false,
    });
    audit.record(AuditEvent::SessionEnded {
        device,
        label: "n".into(),
        session_id: session_id.clone(),
        detail: "PeerBye".into(),
    });
    audit.record(AuditEvent::PopupSuppressed {
        device,
        label: None,
        popup: SuppressedPopup::Pairing,
    });
    let records = audit.log().read_all().unwrap();
    assert_eq!(records.len(), 5);
    // Pre-pairing lines carry the device but no `peer_name` (§B.8.13: the
    // pinned label only).
    assert_eq!(records[0].peer_device, Some(device));
    assert_eq!(records[0].peer_name, None);
    assert_eq!(records[1].peer_name, None);
    assert_eq!(records[1].detail.as_deref(), Some("DENIED"));
    assert_eq!(records[2].session_id.as_deref(), Some(session_id.as_str()));
    assert_eq!(records[2].peer_name.as_deref(), Some("n"));
    assert_eq!(records[4].event, LogEvent::PopupSuppressedRemoteSession);
    assert_eq!(records[4].detail.as_deref(), Some("pairing"));
    assert_eq!(records[4].during_remote_session, Some(true));
    assert_eq!(records[4].peer_name, None);
    // No token bytes — not even a prefix — reach the file. Four token bytes
    // (`abababab`), not two: the `prev` chain hashes are random hex, and one of
    // four hashes held "abab" by chance about once in 270 runs.
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("Chosen by the peer"), "{text}");
    assert!(!text.contains("abababab"), "{text}");
    assert!(text.contains(&session_id), "{text}");
    assert_eq!(session_id.len(), 16);
    NoAudit.record(AuditEvent::PairAccepted {
        device,
        label: "x".into(),
    });

    // The limiter-driven rejects are aggregated per (device, reason): nothing
    // is written while the 60 s window is open, one line with `count` at
    // flush (or when the window closes at the next event, or on drop).
    let other = DeviceId::from_bytes([4u8; 32]);
    for _ in 0..3 {
        audit.record(AuditEvent::PairRejected {
            device: other,
            declared_name: "x".into(),
            reason: pair_reject::BANNED,
        });
    }
    audit.record(AuditEvent::PairRejected {
        device: other,
        declared_name: "x".into(),
        reason: pair_reject::IN_FLIGHT,
    });
    for _ in 0..2 {
        audit.record(AuditEvent::SessionDenied {
            device,
            label: "n".into(),
            reason: reject::BUSY,
        });
    }
    assert_eq!(
        audit.log().read_all().unwrap().len(),
        5,
        "buckets still open"
    );
    assert!(HostAudit::aggregates_pair_reject(pair_reject::RATE_LIMITED));
    assert!(!HostAudit::aggregates_pair_reject(pair_reject::TIMEOUT));
    audit.flush();
    let records = audit.log().read_all().unwrap();
    assert_eq!(records.len(), 8);
    let banned = records
        .iter()
        .find(|r| r.event == LogEvent::PairRejected && r.detail.as_deref() == Some("BANNED"))
        .unwrap();
    assert_eq!(banned.count, Some(3));
    assert_eq!(banned.peer_device, Some(other));
    let in_flight = records
        .iter()
        .find(|r| r.event == LogEvent::PairRejected && r.detail.as_deref() == Some("IN_FLIGHT"))
        .unwrap();
    assert_eq!(in_flight.count, Some(1));
    let busy = records
        .iter()
        .find(|r| r.event == LogEvent::SessionDenied && r.detail.as_deref() == Some("BUSY"))
        .unwrap();
    assert_eq!(busy.count, Some(2));
    assert_eq!(busy.peer_device, Some(device));
    // Dropping the last handle flushes what is left.
    audit.record(AuditEvent::SessionDenied {
        device,
        label: "n".into(),
        reason: reject::BUSY,
    });
    drop(audit);
    assert_eq!(log.read_all().unwrap().len(), 9);
}

/// Records every audit event for assertions.
#[derive(Default)]
struct RecordingAudit(Mutex<Vec<AuditEvent>>);

impl HandshakeAudit for RecordingAudit {
    fn record(&self, event: AuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}

/// An unattended request from a paired raw client: `HELLO`, `HELLO_ACK`,
/// then a signed `SESSION_REQUEST{unattended}`; returns the raw client.
async fn raw_unattended_request(
    host: &HostSide,
    seed: [u8; 32],
    stream: DuplexStream,
) -> RawClient {
    let mut raw = RawClient::new(stream, &host.identity, seed);
    raw.send_hello(None).await;
    let ack = raw.recv().await.unwrap();
    assert_eq!(ack.env.kind, Kind::HelloAck);
    raw.chan.absorb(&ack);
    raw.chan.set_version(1);
    let request = SessionRequest {
        caps: Caps {
            codecs: vec!["h264".into()],
            ..Caps::default()
        },
        unattended: Some(messages::UnattendedRequest {
            suite: 1,
            ke1: Some([0u8; 96]),
            want_mode: 0,
            intent: 0,
            admin: None,
        }),
    };
    raw.chan.send(&request, Some(&raw.identity)).await.unwrap();
    raw
}

/// The `HostOutcome::Session.token` of an unattended accept is the derived
/// `session_token`, never the public `token_confirm` that travels in the
/// accept (§B.8.4.3), and the log's session id derives from it.
#[tokio::test]
async fn unattended_accept_reports_the_derived_session_token() {
    const SESSION_TOKEN: [u8; 32] = [0xA5; 32];
    const TOKEN_CONFIRM: [u8; 32] = [0x5A; 32];

    struct Grant;
    impl UnattendedHook for Grant {
        fn handle<'a>(
            &'a self,
            ctx: UnattendedContext<'a>,
        ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
            Box::pin(async move {
                assert!(ctx.request.unattended.is_some());
                let policy = PolicyReceipt::mint(
                    [9u8; 8],
                    SessionMode::Control,
                    TransportPolicy::Any,
                    None,
                    0,
                    false,
                    ReadinessSnapshot::default(),
                    None,
                );
                Ok(UnattendedVerdict::Accept {
                    proof: ConsentProof::Unattended {
                        grant: [9u8; 8],
                        proof_fp: [0u8; 8],
                        policy,
                        block: WindowPassed::Skipped,
                        token: DerivedToken::new(SESSION_TOKEN, TOKEN_CONFIRM),
                    },
                    caps: ChosenCaps::negotiate(&Caps::default(), &ctx.request.caps),
                })
            })
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.deps.unattended = Arc::new(Grant);
    let audit = Arc::new(RecordingAudit::default());
    host.deps.audit = audit.clone();
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut raw = raw_unattended_request(&host, CLIENT_SEED, b).await;
    let rx = raw.recv().await.unwrap();
    assert_eq!(rx.env.kind, Kind::SessionAccept);
    let accept: messages::SessionAccept = decode_body(&rx.env.body).unwrap();
    assert_eq!(accept.session_type(), 1);
    assert_eq!(accept.session_token(), None, "never sent");
    assert_eq!(accept.token_confirm(), Some(&TOKEN_CONFIRM));
    raw.chan.absorb(&rx);
    raw.chan.bye(bye::USER).await.unwrap();
    match task.await.unwrap().unwrap() {
        HostOutcome::Session {
            token, unattended, ..
        } => {
            assert!(unattended);
            assert_eq!(token, SessionToken::new(SESSION_TOKEN));
            assert_ne!(token, SessionToken::new(TOKEN_CONFIRM));
            let started = audit.0.lock().unwrap().iter().find_map(|e| match e {
                AuditEvent::SessionStarted { session_id, .. } => Some(session_id.clone()),
                _ => None,
            });
            assert_eq!(started.as_deref(), Some(token.session_id().as_str()));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(host.consent.session_popups(), 0, "no popup for unattended");
}

/// §B.8.4.1 / §B.8.6.1: a remote `master_off` whose requester vanished before
/// `ADMIN_RESULT` could be written still fires the kill switch. The store change
/// commits before the verdict exists, so the effect on the *other* live sessions
/// must not hang on whether the requester's circuit survived (track D S2).
#[tokio::test]
async fn an_admin_effect_fires_even_when_its_answer_cannot_be_sent() {
    struct AdminAfterHangup {
        hung_up: Arc<tokio::sync::Notify>,
    }
    impl UnattendedHook for AdminAfterHangup {
        fn handle<'a>(
            &'a self,
            _: UnattendedContext<'a>,
        ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
            Box::pin(async move {
                self.hung_up.notified().await;
                Ok(UnattendedVerdict::Admin {
                    result: messages::AdminResult {
                        ok: true,
                        detail: None,
                    },
                    effect: tornect_core::unattended::guard::AdminEffect::MasterOff,
                })
            })
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let hung_up = Arc::new(tokio::sync::Notify::new());
    host.deps.unattended = Arc::new(AdminAfterHangup {
        hung_up: Arc::clone(&hung_up),
    });
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let raw = raw_unattended_request(&host, CLIENT_SEED, b).await;
    // The requester's stream is gone before the verdict is answered.
    drop(raw);
    hung_up.notify_one();

    let outcome = task.await.unwrap();
    assert!(
        outcome.is_err(),
        "the failed send is still reported: {outcome:?}"
    );
    assert_eq!(
        host.deps.kill.fired(),
        Some(bye::MASTER_OFF),
        "a committed master_off must end live sessions whether or not its answer arrived"
    );
}

/// The unattended seam hands `HandshakeError`s from the AUTH exchange back
/// unchanged; a reject decided after the stream died in a violation is
/// logged but not sent (§B.8.4.5 `AwaitKe3` row).
#[tokio::test]
async fn unattended_hook_errors_propagate_and_dead_streams_are_only_logged() {
    struct Fails;
    impl UnattendedHook for Fails {
        fn handle<'a>(
            &'a self,
            _: UnattendedContext<'a>,
        ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
            Box::pin(async { Err(HandshakeError::Timeout("AUTH_RESPONSE")) })
        }
    }
    /// Runs the AUTH exchange; on a violation settles as `AUTH_FAILED` like
    /// the unattended handler does after `settle(fail)`.
    struct Exchanges {
        propagate: bool,
    }
    impl UnattendedHook for Exchanges {
        fn handle<'a>(
            &'a self,
            ctx: UnattendedContext<'a>,
        ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
            Box::pin(async move {
                let challenge = messages::AuthChallenge {
                    suite: 1,
                    ke2: Some([0u8; 320]),
                    salt: None,
                    pb: None,
                };
                match ctx.exchange.challenge(challenge).await {
                    Ok(_) => panic!("the test client never answers with KE3"),
                    Err(e) if self.propagate => Err(e),
                    Err(e) => {
                        assert_eq!(e.violation_code(), Some(codes::E_BAD_STATE), "{e}");
                        Ok(UnattendedVerdict::Reject(messages::SessionReject::new(
                            reject::AUTH_FAILED,
                        )))
                    }
                }
            })
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let device = DeviceIdentity::from_seed(&CLIENT_SEED).id();

    // An error from the hook is the host's error.
    let mut host = host_side(tmp.path().join("a").as_path(), HOST_SEED);
    host.deps.unattended = Arc::new(Fails);
    host.trusted.pin(device, "Paired").unwrap();
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let _raw = raw_unattended_request(&host, CLIENT_SEED, b).await;
    let err = task.await.unwrap().unwrap_err();
    assert!(
        matches!(err, HandshakeError::Timeout("AUTH_RESPONSE")),
        "{err}"
    );

    // A PING in AwaitKe3 ⇒ E_BAD_STATE on the wire; the hook's AUTH_FAILED is
    // recorded, not sent, and the outcome carries it.
    for propagate in [false, true] {
        let mut host = host_side(tmp.path().join("b").as_path(), HOST_SEED);
        host.deps.unattended = Arc::new(Exchanges { propagate });
        let audit = Arc::new(RecordingAudit::default());
        host.deps.audit = audit.clone();
        host.trusted.pin(device, "Paired").unwrap();
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let mut raw = raw_unattended_request(&host, CLIENT_SEED, b).await;
        let challenge = raw.recv().await.unwrap();
        assert_eq!(challenge.env.kind, Kind::AuthChallenge);
        raw.chan.absorb(&challenge);
        raw.chan.send(&Ping { nonce: 1 }, None).await.unwrap();
        let err = raw.recv().await.unwrap();
        assert_eq!(err.env.kind, Kind::Error);
        let e: messages::Error = decode_body(&err.env.body).unwrap();
        assert_eq!(e.code, codes::E_BAD_STATE);
        assert!(
            raw.recv().await.is_none(),
            "exactly one ERROR frame, then EOF"
        );
        let outcome = task.await.unwrap();
        if propagate {
            let err = outcome.unwrap_err();
            assert_eq!(err.violation_code(), Some(codes::E_BAD_STATE), "{err}");
            assert!(
                !audit
                    .0
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|e| matches!(e, AuditEvent::SessionDenied { .. }))
            );
        } else {
            assert!(matches!(
                outcome.unwrap(),
                HostOutcome::SessionRejected {
                    reason: reject::AUTH_FAILED,
                    ..
                }
            ));
            assert!(audit.0.lock().unwrap().iter().any(|e| matches!(
                e,
                AuditEvent::SessionDenied {
                    reason: reject::AUTH_FAILED,
                    ..
                }
            )));
        }
    }
}

/// `PAIR_REJECT{BUSY}` is answered after the pairing limiter admitted the
/// request, so probing "is a session live?" costs a per-peer and a
/// host-wide token like any other pairing request.
#[tokio::test]
async fn busy_rejects_are_charged_by_the_pairing_limiter() {
    struct Live;
    impl SessionActivity for Live {
        fn session_live(&self) -> bool {
            true
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.deps.activity = Arc::new(Live);
    let limits = PairingLimits {
        per_peer_burst: 2,
        per_peer_refill: Duration::from_secs(600),
        host_burst: 3,
        host_refill: Duration::from_secs(600),
        max_tracked_peers: 16,
        ..PairingLimits::default()
    };
    let policy = Arc::new(PairingPolicy::new(limits));
    host.deps.policy = policy.clone();

    async fn probe(host: &HostSide, seed: [u8; 32]) -> u16 {
        let (a, b) = pipe();
        let task = spawn_host(a, host);
        let mut raw = RawClient::new(b, &host.identity, seed);
        raw.send_hello(None).await;
        let ack = raw.recv().await.unwrap();
        raw.chan.absorb(&ack);
        raw.chan.set_version(1);
        raw.chan.send(&raw_pair_request(), None).await.unwrap();
        let rej = raw.recv().await.unwrap();
        assert_eq!(rej.env.kind, Kind::PairReject);
        let body: messages::PairReject = decode_body(&rej.env.body).unwrap();
        match task.await.unwrap().unwrap() {
            HostOutcome::PairRejected { reason, .. } => {
                assert_eq!(reason, body.reason);
                reason
            }
            other => panic!("{other:?}"),
        }
    }

    // Key A: two BUSY answers, then its own bucket is empty.
    assert_eq!(probe(&host, [0xA1; 32]).await, pair_reject::BUSY);
    assert_eq!(probe(&host, [0xA1; 32]).await, pair_reject::BUSY);
    assert_eq!(probe(&host, [0xA1; 32]).await, pair_reject::RATE_LIMITED);
    // Key B takes the last host-wide token; key C gets nothing.
    assert_eq!(probe(&host, [0xB1; 32]).await, pair_reject::BUSY);
    assert_eq!(probe(&host, [0xC1; 32]).await, pair_reject::RATE_LIMITED);
    assert_eq!(policy.in_flight(), 0, "slots are released with the answer");
    assert_eq!(host.consent.sas_shown().len(), 0);
}

/// Decision M1-32: a client that lost `known-hosts.toml` may pair again with
/// a host that still pins it (label kept); a host that unpaired the device
/// makes the client report `PairingLost` instead of a bare `E_BAD_STATE`.
#[tokio::test]
async fn pairing_lost_is_reported_and_a_pinned_device_can_re_pair() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    let device = DeviceIdentity::from_seed(&CLIENT_SEED).id();

    // The client believes it is paired; the host does not know it.
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, HandshakeError::PairingLost), "{err}");
    let err = task.await.unwrap().unwrap_err();
    assert_eq!(err.violation_code(), Some(codes::E_BAD_STATE), "{err}");

    // The host pins the device under "Paired"; the client forgot the host and
    // pairs again: the popup runs, the label stays, the session proceeds.
    host.trusted.pin(device, "Paired").unwrap();
    client.known.remove(&host.identity.id()).unwrap();
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept {
            label: Some("renamed by the host user".into()),
        }));
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let session = match connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap()
    {
        ClientOutcome::Session(s) => s,
        ClientOutcome::Paired { .. } => panic!("expected a session"),
    };
    assert_eq!(host.consent.sas_shown().len(), 1, "the pairing popup ran");
    assert_eq!(client.ui.sas_shown(), host.consent.sas_shown());
    assert!(client.known.is_known(&host.identity.id()));
    session.bye(bye::USER).await.unwrap();
    match task.await.unwrap().unwrap() {
        HostOutcome::Session {
            label, paired_now, ..
        } => {
            assert_eq!(label, "Paired", "a re-pair never changes the pinned label");
            assert!(paired_now);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(host.trusted.get(&device).unwrap().label, "Paired");
}

/// §B.6 / §B.8.16: `session_ended` follows `session_started` whichever way
/// the `Established` phase ends — a peer that sends an illegal kind, a wrong
/// `msg_id` or half a frame cannot erase its own session-end line.
#[tokio::test]
async fn session_end_is_logged_whichever_way_the_established_phase_ends() {
    #[derive(Clone, Copy)]
    enum Way {
        IllegalKind,
        BadMsgId,
        Truncated,
        Bye,
    }
    let tmp = tempfile::tempdir().unwrap();
    let device = DeviceIdentity::from_seed(&CLIENT_SEED).id();
    for (way, expected) in [
        (Way::IllegalKind, "E_BAD_STATE"),
        (Way::BadMsgId, "E_BAD_MSG_ID"),
        (Way::Truncated, "truncated"),
        (Way::Bye, "PeerBye(1)"),
    ] {
        let mut host = host_side(tmp.path(), HOST_SEED);
        let audit = Arc::new(RecordingAudit::default());
        host.deps.audit = audit.clone();
        host.trusted.pin(device, "Paired").unwrap();
        host.consent
            .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
        raw.hello_ack().await;
        let accept = raw.request_session().await;
        assert_eq!(accept.env.kind, Kind::SessionAccept);
        raw.chan.absorb(&accept);
        let outcome = match way {
            Way::IllegalKind => {
                raw.chan.send(&raw_pair_request(), None).await.unwrap();
                task.await.unwrap()
            }
            Way::BadMsgId => {
                let mut stream = raw.chan.into_stream();
                let env = Envelope::new(1, 99, Kind::Ping, encode_body(&Ping { nonce: 1 }));
                write_frame(&mut stream, &env.encode()).await.unwrap();
                task.await.unwrap()
            }
            Way::Truncated => {
                let mut stream = raw.chan.into_stream();
                stream.write_all(&[0, 0, 0, 10, 1, 2, 3]).await.unwrap();
                drop(stream);
                task.await.unwrap()
            }
            Way::Bye => {
                raw.chan.bye(bye::USER).await.unwrap();
                task.await.unwrap()
            }
        };
        match way {
            Way::IllegalKind => assert_eq!(
                outcome.unwrap_err().violation_code(),
                Some(codes::E_BAD_STATE)
            ),
            Way::BadMsgId => assert_eq!(
                outcome.unwrap_err().violation_code(),
                Some(codes::E_BAD_MSG_ID)
            ),
            Way::Truncated => assert!(matches!(
                outcome.unwrap_err(),
                HandshakeError::Frame(FrameError::Truncated)
            )),
            Way::Bye => assert!(matches!(
                outcome.unwrap(),
                HostOutcome::Session {
                    end: SessionEnd::PeerBye(bye::USER),
                    ..
                }
            )),
        }
        let events = audit.0.lock().unwrap().clone();
        let started = events
            .iter()
            .position(|e| matches!(e, AuditEvent::SessionStarted { .. }))
            .expect("session_started");
        let ended = events
            .iter()
            .position(|e| matches!(e, AuditEvent::SessionEnded { .. }))
            .expect("session_ended");
        assert!(ended > started, "{expected}: {events:?}");
        let (
            AuditEvent::SessionStarted { session_id: s, .. },
            AuditEvent::SessionEnded {
                session_id: e,
                detail,
                ..
            },
        ) = (&events[started], &events[ended])
        else {
            unreachable!()
        };
        assert_eq!(s, e);
        assert_eq!(detail, expected);
        assert_eq!(host.deps.stats.established.load(Ordering::SeqCst), 0);
    }
}

/// The two client-side waits the plan fixes (§B.8.4.5: `SESSION_ACCEPT` is
/// the fixed `30 + 60 + 20 s = 110 s`, never shortened by grant policy;
/// decision M1-13: `PAIR_ACCEPT` 90 s) actually elapse against a host that
/// answers `HELLO_ACK` and then goes silent.
#[tokio::test(start_paused = true)]
async fn client_timeouts_are_the_plan_values() {
    let tmp = tempfile::tempdir().unwrap();
    let real = HostIdentity::from_seed(&HOST_SEED);
    let real_pk = HostSigner::public_key(&real);

    // A known host: HELLO_ACK, the SESSION_REQUEST taken, then nothing.
    let client = client_side(tmp.path(), real.id(), CLIENT_SEED);
    client
        .known
        .pin(real.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    let (a, b) = pipe();
    let signer = HostIdentity::from_seed(&HOST_SEED);
    let silent = tokio::spawn(async move {
        let mut h = RawHost::new(a, &real_pk);
        h.take_hello().await;
        h.ack(&signer).await;
        h.take(Kind::SessionRequest).await;
        // Holds the stream open until the client gives up.
        h.chan.recv(Duration::from_secs(3600), "nothing").await
    });
    let started = tokio::time::Instant::now();
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, HandshakeError::Timeout("SESSION_ACCEPT")),
        "{err}"
    );
    assert_eq!(started.elapsed(), timeouts::SESSION_ACCEPT);
    assert!(
        matches!(silent.await.unwrap(), Ok(None)),
        "the client hung up without a frame"
    );

    // An unknown host: HELLO_ACK, the PAIR_REQUEST taken, then nothing ⇒
    // 90 s, nothing pinned, no confirm popup.
    let fresh = client_side(tmp.path().join("fresh").as_path(), real.id(), CLIENT_SEED);
    let (a, b) = pipe();
    let signer = HostIdentity::from_seed(&HOST_SEED);
    let silent = tokio::spawn(async move {
        let mut h = RawHost::new(a, &real_pk);
        h.take_hello().await;
        h.ack(&signer).await;
        h.take(Kind::PairRequest).await;
        h.chan.recv(Duration::from_secs(3600), "nothing").await
    });
    let started = tokio::time::Instant::now();
    let err = connect(b, &fresh.cfg, &fresh.identity, &fresh.deps, Intent::Session)
        .await
        .unwrap_err();
    assert!(
        matches!(err, HandshakeError::Timeout("PAIR_ACCEPT")),
        "{err}"
    );
    assert_eq!(started.elapsed(), timeouts::PAIR_ACCEPT);
    assert!(matches!(silent.await.unwrap(), Ok(None)));
    assert!(!fresh.known.is_known(&real.id()));
    assert_eq!(fresh.ui.sas_shown().len(), 1, "the SAS was on screen");
    assert!(
        fresh.ui.asked.lock().unwrap().is_empty(),
        "no confirm popup"
    );
}

/// P1, client half (§B.8.4.5 strict alternation): a `PING` from the host
/// before `HELLO_ACK`, before `PAIR_ACCEPT` or before `SESSION_ACCEPT` is
/// answered with exactly one `ERROR{E_BAD_STATE}` and a close; after the
/// accept it is answered with `PONG` and both sides hold the same `th`.
#[tokio::test]
async fn client_strict_alternation_answers_ping_only_after_the_accept() {
    let tmp = tempfile::tempdir().unwrap();
    let real = HostIdentity::from_seed(&HOST_SEED);
    let real_pk = HostSigner::public_key(&real);
    for paired in [false, true] {
        let windows = if paired { 2 } else { 3 };
        for ping_at in 0..=windows {
            let client = client_side(
                tmp.path().join(format!("{paired}-{ping_at}")).as_path(),
                real.id(),
                CLIENT_SEED,
            );
            if paired {
                client
                    .known
                    .pin(real.id(), "Desk of Bob", host_device_pk())
                    .unwrap();
            }
            let (a, b) = pipe();
            let signer = HostIdentity::from_seed(&HOST_SEED);
            let host = tokio::spawn(async move {
                let mut h = RawHost::new(a, &real_pk);
                // Inject the PING and collect everything the client sends until EOF.
                async fn inject(h: &mut RawHost) -> (Vec<Kind>, Option<[u8; 32]>) {
                    h.chan.send(&Ping { nonce: 9 }, None).await.unwrap();
                    let mut kinds = Vec::new();
                    while let Ok(Some(rx)) = h.chan.recv(Duration::from_secs(5), "after").await {
                        if rx.env.kind == Kind::Error {
                            let e: messages::Error = decode_body(&rx.env.body).unwrap();
                            assert_eq!(e.code, codes::E_BAD_STATE);
                        }
                        kinds.push(rx.env.kind);
                    }
                    (kinds, None)
                }
                let mut pos = 0;
                h.take_hello().await;
                if ping_at == pos {
                    return inject(&mut h).await;
                }
                pos += 1;
                h.ack(&signer).await;
                if !paired {
                    h.take(Kind::PairRequest).await;
                    if ping_at == pos {
                        return inject(&mut h).await;
                    }
                    pos += 1;
                    let accept = messages::PairAccept {
                        host_device_pk: host_device_pk(),
                        host_name: "Desk of Bob".into(),
                    };
                    h.chan.send(&accept, None).await.unwrap();
                }
                h.take(Kind::SessionRequest).await;
                if ping_at == pos {
                    return inject(&mut h).await;
                }
                h.chan.send(&genuine_accept(), Some(&signer)).await.unwrap();
                // After the accept: PING then BYE; the PONG comes back first.
                h.chan.send(&Ping { nonce: 9 }, None).await.unwrap();
                let pong = h
                    .chan
                    .recv(Duration::from_secs(5), "pong")
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(pong.env.kind, Kind::Pong);
                let p: Pong = decode_body(&pong.env.body).unwrap();
                assert_eq!(p.nonce, 9);
                h.chan.bye(bye::USER).await.unwrap();
                (vec![Kind::Pong], Some(h.chan.th()))
            });
            let result = connect(
                b,
                &client.cfg,
                &client.identity,
                &client.deps,
                Intent::Session,
            )
            .await;
            if ping_at < windows {
                let err = result.unwrap_err();
                assert_eq!(
                    err.violation_code(),
                    Some(codes::E_BAD_STATE),
                    "paired {paired}, ping at {ping_at}: {err}"
                );
                let (kinds, _) = host.await.unwrap();
                assert_eq!(
                    kinds,
                    [Kind::Error],
                    "exactly one ERROR then EOF (paired {paired}, ping at {ping_at})"
                );
                if !paired && ping_at < 2 {
                    assert!(!client.known.is_known(&real.id()));
                }
            } else {
                let mut session = match result.unwrap() {
                    ClientOutcome::Session(s) => s,
                    ClientOutcome::Paired { .. } => panic!("expected a session"),
                };
                // The PING is answered inside `next_event`; the BYE the host
                // sends once it has the PONG is what it reports.
                let event = session.next_event(Duration::from_secs(5)).await.unwrap();
                assert_eq!(
                    event,
                    Some(SessionEvent::Bye {
                        reason: bye::USER,
                        detail: None
                    })
                );
                let (kinds, th) = host.await.unwrap();
                assert_eq!(kinds, [Kind::Pong]);
                assert_eq!(Some(session.th()), th, "th identical on both sides");
            }
        }
    }
}

/// The Tor circuit is a heartbeat channel in both directions (§B.2): a host
/// `PING` that arrives while the client waits for its own `PONG` is answered
/// in place, an M2 frame that arrives meanwhile is queued for `next_event`,
/// and a `PONG` with the wrong nonce is still `E_BAD_STATE`.
#[tokio::test]
async fn client_ping_answers_a_host_ping_and_queues_m2_frames() {
    let tmp = tempfile::tempdir().unwrap();
    let real = HostIdentity::from_seed(&HOST_SEED);
    let real_pk = HostSigner::public_key(&real);
    for wrong_nonce in [false, true] {
        let client = client_side(
            tmp.path().join(format!("{wrong_nonce}")).as_path(),
            real.id(),
            CLIENT_SEED,
        );
        client
            .known
            .pin(real.id(), "Desk of Bob", host_device_pk())
            .unwrap();
        let (a, b) = pipe();
        let signer = HostIdentity::from_seed(&HOST_SEED);
        let host = tokio::spawn(async move {
            let mut h = RawHost::new(a, &real_pk);
            h.take_hello().await;
            h.ack(&signer).await;
            h.take(Kind::SessionRequest).await;
            h.chan.send(&genuine_accept(), Some(&signer)).await.unwrap();
            let ping = h
                .chan
                .recv(Duration::from_secs(5), "ping")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(ping.env.kind, Kind::Ping);
            let nonce = decode_body::<Ping>(&ping.env.body).unwrap().nonce;
            // The host's own heartbeat and an M2 frame, then the answer.
            h.chan.send(&Ping { nonce: 42 }, None).await.unwrap();
            h.chan
                .send(
                    &messages::Candidates {
                        candidates: vec!["c".into()],
                    },
                    None,
                )
                .await
                .unwrap();
            let answer = Pong {
                nonce: if wrong_nonce { nonce ^ 1 } else { nonce },
            };
            h.chan.send(&answer, None).await.unwrap();
            // The client answers the host's PING before it sees the PONG.
            let reply = h
                .chan
                .recv(Duration::from_secs(5), "reply")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.env.kind, Kind::Pong);
            assert_eq!(decode_body::<Pong>(&reply.env.body).unwrap().nonce, 42);
            if wrong_nonce {
                let reply = h
                    .chan
                    .recv(Duration::from_secs(5), "error")
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(reply.env.kind, Kind::Error);
                let e: messages::Error = decode_body(&reply.env.body).unwrap();
                assert_eq!(e.code, codes::E_BAD_STATE);
                assert!(
                    h.chan
                        .recv(Duration::from_secs(5), "eof")
                        .await
                        .unwrap()
                        .is_none()
                );
                return;
            }
            h.chan.bye(bye::USER).await.unwrap();
        });
        let mut session = match connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        )
        .await
        .unwrap()
        {
            ClientOutcome::Session(s) => s,
            ClientOutcome::Paired { .. } => panic!("expected a session"),
        };
        let result = session.ping().await;
        if wrong_nonce {
            let err = result.unwrap_err();
            assert_eq!(err.violation_code(), Some(codes::E_BAD_STATE), "{err}");
            host.await.unwrap();
            continue;
        }
        result.unwrap();
        assert_eq!(
            session.next_event(Duration::from_secs(5)).await.unwrap(),
            Some(SessionEvent::Candidates(messages::Candidates {
                candidates: vec!["c".into()]
            })),
            "the M2 frame that arrived during ping is delivered first"
        );
        assert_eq!(
            session.next_event(Duration::from_secs(5)).await.unwrap(),
            Some(SessionEvent::Bye {
                reason: bye::USER,
                detail: None
            })
        );
        host.await.unwrap();
    }
}

/// The attended session popup has the pairing popup's budget: one popup in
/// flight per paired device (`SESSION_REJECT{BUSY}` for a second stream while
/// it is open, no second popup), another device still gets its own popup,
/// and the per-device / host-wide buckets refuse with `BUSY` too.
#[tokio::test]
async fn session_popups_have_one_in_flight_per_device_and_a_budget() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    let device = DeviceIdentity::from_seed(&CLIENT_SEED);
    host.trusted.pin(device.id(), "Paired").unwrap();
    host.consent.push_session(SessionScript::Hang);
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    let (a, b) = pipe();
    let first = spawn_host(a, &host);
    let cfg = client.cfg.clone();
    let deps = client.deps.clone();
    let first_client =
        tokio::spawn(async move { connect(b, &cfg, &device, &deps, Intent::Session).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while host.deps.stats.consent_pending.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    // The same device again while its popup is open ⇒ BUSY, no second popup.
    let (a, b) = pipe();
    let second = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::BUSY),
        "{err}"
    );
    assert!(matches!(
        second.await.unwrap().unwrap(),
        HostOutcome::SessionRejected {
            reason: reject::BUSY,
            ..
        }
    ));
    assert_eq!(host.consent.session_popups(), 1);

    // Another paired device reaches its own popup.
    let other = DeviceIdentity::from_seed(&[0x24; 32]);
    host.trusted.pin(other.id(), "Other").unwrap();
    host.consent.push_session(SessionScript::Hang);
    let other_client = client_side(
        tmp.path().join("o").as_path(),
        host.identity.id(),
        [0x24; 32],
    );
    other_client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    let (a, b) = pipe();
    let third = spawn_host(a, &host);
    let cfg = other_client.cfg.clone();
    let deps = other_client.deps.clone();
    let third_client =
        tokio::spawn(async move { connect(b, &cfg, &other, &deps, Intent::Session).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while host.deps.stats.consent_pending.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(host.consent.session_popups(), 2);
    assert_eq!(host.deps.session_policy.in_flight(), 2);
    for t in [first, third] {
        t.abort();
    }
    for t in [first_client, third_client] {
        t.abort();
    }

    // Buckets: a per-device budget of one popup per 10 min ⇒ the second
    // request after a Deny is BUSY without a popup; a host-wide budget of
    // two ⇒ a third device is BUSY as well.
    let mut host = host_side(tmp.path().join("b").as_path(), HOST_SEED);
    host.deps.session_policy = Arc::new(PairingPolicy::new(PairingLimits {
        per_peer_burst: 1,
        per_peer_refill: Duration::from_secs(600),
        host_burst: 2,
        host_refill: Duration::from_secs(600),
        ..PairingLimits::sessions()
    }));
    let audit = Arc::new(RecordingAudit::default());
    host.deps.audit = audit.clone();
    let device = DeviceIdentity::from_seed(&CLIENT_SEED).id();
    host.trusted.pin(device, "Paired").unwrap();
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::Deny));
    async fn attempt(host: &HostSide, client: &ClientSide) -> u16 {
        let (a, b) = pipe();
        let task = spawn_host(a, host);
        let err = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        )
        .await
        .unwrap_err();
        let HandshakeError::SessionRejected { reject } = err else {
            panic!("{err}");
        };
        match task.await.unwrap().unwrap() {
            HostOutcome::SessionRejected { reason, .. } => {
                assert_eq!(reason, reject.reason);
                reason
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(attempt(&host, &client).await, reject::DENIED);
    assert_eq!(attempt(&host, &client).await, reject::BUSY);
    assert_eq!(
        host.consent.session_popups(),
        1,
        "no popup for the throttled request"
    );
    let third = client_side(
        tmp.path().join("t").as_path(),
        host.identity.id(),
        [0x26; 32],
    );
    third
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    host.trusted.pin(third.identity.id(), "Third").unwrap();
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::Deny));
    assert_eq!(attempt(&host, &third).await, reject::DENIED);
    let fourth = client_side(
        tmp.path().join("f").as_path(),
        host.identity.id(),
        [0x27; 32],
    );
    fourth
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    host.trusted.pin(fourth.identity.id(), "Fourth").unwrap();
    assert_eq!(
        attempt(&host, &fourth).await,
        reject::BUSY,
        "host-wide budget"
    );
    assert_eq!(host.consent.session_popups(), 2);
    // Throttling is a plain `session_denied{BUSY}`; only a live session
    // writes `popup_suppressed_remote_session`.
    let events = audit.0.lock().unwrap().clone();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(
                e,
                AuditEvent::SessionDenied {
                    reason: reject::BUSY,
                    ..
                }
            ))
            .count(),
        2
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, AuditEvent::PopupSuppressed { .. }))
    );
}

/// Decision M1-32 hardened: a pinned key asking to pair again is shown as
/// such ("already paired as <label>"), a Deny on that popup never feeds the
/// temp-ban (`HELLO` is replayable, so the request is no evidence the trusted
/// device sent it), and the pin survives. An unpaired key's popup carries no
/// pinned label.
#[tokio::test]
async fn re_pairing_popup_names_the_pinned_label_and_a_deny_never_bans_it() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    // Four attempts from one key exceed the default 3-per-key burst.
    host.deps.policy = Arc::new(PairingPolicy::new(PairingLimits {
        per_peer_burst: 10,
        ..PairingLimits::default()
    }));
    let device = DeviceIdentity::from_seed(&CLIENT_SEED).id();
    host.trusted.pin(device, "Paired").unwrap();
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    // Four Denies: one more than the default ban threshold.
    for _ in 0..4 {
        host.consent
            .push_pairing(PairScript::Decide(PairDecision::Reject));
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let err = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                HandshakeError::PairRejected {
                    reason: pair_reject::DENIED,
                    ..
                }
            ),
            "{err}"
        );
        assert!(matches!(
            task.await.unwrap().unwrap(),
            HostOutcome::PairRejected {
                reason: pair_reject::DENIED,
                ..
            }
        ));
    }
    let peers = host.consent.pairing_peers.lock().unwrap().clone();
    assert_eq!(peers.len(), 4);
    assert!(
        peers
            .iter()
            .all(|p| p.pinned_label.as_deref() == Some("Paired")),
        "{peers:?}"
    );
    assert!(host.trusted.banned_until(&device).is_none());
    assert_eq!(host.trusted.get(&device).unwrap().label, "Paired");
    assert!(host.trusted.snapshot().bans.is_empty());

    // An unpaired key: no pinned label on the popup, and its Denies do count.
    let other = client_side(
        tmp.path().join("o").as_path(),
        host.identity.id(),
        [0x25; 32],
    );
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Reject));
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let _ = connect(b, &other.cfg, &other.identity, &other.deps, Intent::Session).await;
    task.await.unwrap().unwrap();
    let peers = host.consent.pairing_peers.lock().unwrap().clone();
    assert_eq!(peers.last().unwrap().pinned_label, None);
    assert_eq!(host.trusted.snapshot().bans.len(), 1);
}

/// §B.8.6.2: a popup suppressed by a live remote session is logged as
/// `popup_suppressed_remote_session` (pairing and session alike), next to the
/// `BUSY` answer.
#[tokio::test]
async fn popup_suppression_during_a_live_session_is_logged() {
    struct Live;
    impl SessionActivity for Live {
        fn session_live(&self) -> bool {
            true
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.deps.activity = Arc::new(Live);
    let audit = Arc::new(RecordingAudit::default());
    host.deps.audit = audit.clone();
    let device = DeviceIdentity::from_seed(&CLIENT_SEED).id();
    host.trusted.pin(device, "Paired").unwrap();
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::BUSY),
        "{err}"
    );
    task.await.unwrap().unwrap();
    let other = client_side(
        tmp.path().join("o").as_path(),
        host.identity.id(),
        [0x24; 32],
    );
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let err = connect(b, &other.cfg, &other.identity, &other.deps, Intent::Session)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            HandshakeError::PairRejected {
                reason: pair_reject::BUSY,
                ..
            }
        ),
        "{err}"
    );
    task.await.unwrap().unwrap();
    let events = audit.0.lock().unwrap().clone();
    assert!(events.contains(&AuditEvent::PopupSuppressed {
        device,
        label: Some("Paired".into()),
        popup: SuppressedPopup::Session,
    }));
    assert!(events.contains(&AuditEvent::PopupSuppressed {
        device: other.identity.id(),
        label: None,
        popup: SuppressedPopup::Pairing,
    }));
    assert!(events.iter().any(|e| matches!(
        e,
        AuditEvent::SessionDenied {
            reason: reject::BUSY,
            ..
        }
    )));
    assert!(events.iter().any(|e| matches!(
        e,
        AuditEvent::PairRejected {
            reason: pair_reject::BUSY,
            ..
        }
    )));
    assert_eq!(host.consent.session_popups(), 0);
    assert_eq!(host.consent.sas_shown().len(), 0);
}

/// The unattended seam receives the `BlockWindow` / `LocalAllow` seams of
/// §B.8.14 through `UnattendedContext`, with the headless defaults
/// (`TimerOnlyWindow`, `AlwaysDeny`) unless `HostDeps` says otherwise.
#[tokio::test]
async fn unattended_context_carries_the_block_window_and_local_allow_seams() {
    struct Probe;
    impl UnattendedHook for Probe {
        fn handle<'a>(
            &'a self,
            ctx: UnattendedContext<'a>,
        ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
            Box::pin(async move {
                assert_eq!(
                    ctx.block_window.run(0, &[1u8; 8], ctx.label).await,
                    BlockOutcome::Passed(WindowPassed::Skipped)
                );
                assert!(
                    !ctx.local_allow
                        .ask(&[1u8; 8], ctx.label, Duration::from_secs(1))
                        .await
                );
                Ok(UnattendedVerdict::Reject(messages::SessionReject::new(
                    reject::BLOCKED_BY_LOCAL_USER,
                )))
            })
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.deps.unattended = Arc::new(Probe);
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut raw = raw_unattended_request(&host, CLIENT_SEED, b).await;
    let rx = raw.recv().await.unwrap();
    assert_eq!(rx.env.kind, Kind::SessionReject);
    assert!(matches!(
        task.await.unwrap().unwrap(),
        HostOutcome::SessionRejected {
            reason: reject::BLOCKED_BY_LOCAL_USER,
            ..
        }
    ));
}
