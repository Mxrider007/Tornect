//! Host + client FSMs over `tokio::io::duplex` (`docs/PLAN.md` §B.8.15:
//! P1–P4, A1, A3 signaling half, A13 signaling half, A17; timeouts under
//! `tokio::time::pause`; the B.8.4.3 golden vector).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncWriteExt as _, DuplexStream, duplex};
use tornect_core::levels::{Availability, Level, WindowsFacts};
use tornect_core::trusted::{KnownHosts, TrustedDevices};
use tornect_core::{DeviceId, DeviceIdentity, HostIdentity, TornectId};
use zeroize::Zeroizing;

use tornect_core::session_log::{SessionEvent as LogEvent, SessionLog, SessionMode};
use tornect_core::unattended::ReadinessSnapshot;

use super::client::{
    ClientConfig, ClientDeps, ClientOutcome, Intent, ScriptedClientUi, SessionEvent, connect,
};
use super::host::{
    AdminHelper, AttachedHelper, HostConfig, HostDeps, HostOutcome, KillGuard, KillSwitch,
    LiveSession, LiveSessions, SessionActivity, SessionEnd, SessionSink, StopTokenCheck,
    UnattendedContext, UnattendedHook, UnattendedVerdict, serve_host,
};
use super::vectors::host_device_pk;
use super::*;
use crate::consent::{
    BlockOutcome, ChosenCaps, ConsentProof, DerivedToken, PolicyReceipt, TransportPolicy,
    WindowPassed, mode_code,
};
use crate::envelope::{Envelope, Kind, codes};
use crate::framing::{FrameError, write_frame};
use crate::messages::{
    self, Caps, Hello, PairRequest, Ping, Pong, Resolution, SessionRequest, bye, ed25519_spki,
    pair_reject, reject,
};
use crate::pairing::{
    BoxFuture, KnownHostStore, PairDecision, PairScript, PairingLimits, PairingPolicy,
    ScriptedConsent, SessionDecision, SessionScript, TrustedDeviceStore,
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
        StdArc::new(tornect_core::levels::FixedFacts::linux()),
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
            false,
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
    guard
        .set_password(
            Actor::Cli,
            &device,
            &record,
            &GrantOptions::default(),
            false,
        )
        .unwrap();

    let mut host = host;
    host.deps.unattended = Arc::new(UnattendedAuth::new(
        AttemptLimiter::new(guard.store().clone()),
        Arc::new(FixedOffset::utc()),
        HostTransport::default(),
        Arc::new(tornect_core::levels::FixedFacts::linux()),
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
            want_elevation: tornect_core::levels::Elevation::None,
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

/// Every log line written while the test runs, as text.
#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

thread_local! {
    /// Where this thread's log lines go while it captures them.
    static CAPTURING: std::cell::RefCell<Option<LogCapture>> =
        const { std::cell::RefCell::new(None) };
}

/// The capturing subscriber's writer: this thread's capture.
struct ThreadCapture;

impl tracing_subscriber::fmt::MakeWriter<'_> for ThreadCapture {
    type Writer = LogCapture;

    fn make_writer(&self) -> LogCapture {
        // The filter lets events through only on a capturing thread. `try_with`:
        // an event from a thread-local destructor, after `CAPTURING` is gone,
        // must not panic (and abort the test binary).
        CAPTURING
            .try_with(|c| c.borrow().clone())
            .ok()
            .flatten()
            .unwrap_or_default()
    }
}

/// This thread's log lines, at every level, until dropped.
struct Capturing {
    lines: LogCapture,
}

impl Drop for Capturing {
    fn drop(&mut self) {
        let _ = CAPTURING.try_with(|c| c.borrow_mut().take());
    }
}

/// Capture this thread's log lines at every level.
///
/// Not with a thread-local subscriber (`set_default`), which made
/// `the_logs_name_peers_by_short_forms_only` fail about one full run in five:
/// tracing caches each call site's interest for the whole process when the
/// site is first reached, and while only one dispatcher is registered it asks
/// the *reaching thread's* default (tracing-core 0.1.36, `callsite.rs`,
/// `Rebuilder::JustOne`). When another test's thread, which has no subscriber,
/// reached `session accepted` first, the site was cached as "never" and this
/// thread's line was never written. One process-wide subscriber instead,
/// installed once for this test binary, answers "sometimes" for every call
/// site (`DynFilterFn`, whose answer is never cached) and writes an event only
/// on a thread that is capturing.
fn capture_logs() -> Capturing {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(ThreadCapture)
            .with_filter(tracing_subscriber::filter::DynFilterFn::new(|_, _| {
                CAPTURING
                    .try_with(|c| c.borrow().is_some())
                    .unwrap_or(false)
            }));
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
            .expect("this test binary sets no other global subscriber");
        // `set_global_default` recomputes the call sites before it stores the
        // global (tracing-core `dispatcher.rs`, `set_global_default`): a call
        // site another thread first reached in between was cached "never".
        // Now that the global is stored, recompute them again (review P2-I1).
        tracing::callsite::rebuild_interest_cache();
    });
    let lines = LogCapture::default();
    CAPTURING.with(|c| *c.borrow_mut() = Some(lines.clone()));
    Capturing { lines }
}

/// Why the capture above used to miss lines: a call site that another
/// thread reaches first must still be captured on this one.
#[test]
fn a_call_site_first_reached_on_another_thread_is_still_captured() {
    fn probe() {
        tracing::info!("the probe's line");
    }
    let capture = capture_logs();
    std::thread::spawn(probe).join().unwrap();
    probe();
    let logs = capture.lines.text();
    assert!(logs.contains("the probe's line"), "not captured: {logs:?}");
}

/// SLICE-E E2-7: the lines a pairing and a session write, at every level,
/// name the peer by a short form (the host by the first eight characters of
/// its address, a device by its fingerprint), never by the full ID: the
/// console of `tornect.exe` shows them, and people share screenshots of it.
#[tokio::test]
async fn the_logs_name_peers_by_short_forms_only() {
    let capture = capture_logs();
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
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
    session.bye(bye::USER).await.unwrap();
    let _ = host_task.await.unwrap().unwrap();

    let logs = capture.lines.text();
    for needle in ["device paired", "host paired", "session accepted"] {
        assert!(logs.contains(needle), "no `{needle}` line:\n{logs}");
    }
    let host_id = host.identity.id();
    let device = client.identity.id();
    for (what, full) in [
        ("the host's address", host_id.onion_address()),
        (
            "the host's address",
            host_id.onion_address().replace(".onion", ""),
        ),
        ("the device ID", device.to_string()),
    ] {
        assert!(
            !logs.contains(&full),
            "{what} appears in full in the logs:\n{logs}"
        );
    }
    assert!(logs.contains(&host_id.short()), "{logs}");
    assert!(logs.contains(&device.fingerprint()), "{logs}");
}

/// One [`LiveSessions`] drives the FSM's `BUSY` answers and the guard's view
/// of a remote session. While a session runs, a second device's pairing popup
/// is suppressed and both views say "live"; once it ends, the guard's view
/// knows when, and the next device gets its popup.
#[tokio::test]
async fn the_live_session_tracker_drives_busy_and_the_guard_view() {
    use tornect_core::unattended::guard::RemoteSessionActivity;

    let tmp = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let live = Arc::new(LiveSessions::new());
    host.deps.sessions = live.clone();
    host.deps.activity = live.clone();
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnceViewOnly));
    let a = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    let b = client_side(tmp_b.path(), host.identity.id(), [0x33; 32]);

    let (x, y) = pipe();
    let host_task = spawn_host(x, &host);
    let mut session = match connect(y, &a.cfg, &a.identity, &a.deps, Intent::Session)
        .await
        .unwrap()
    {
        ClientOutcome::Session(s) => s,
        other => panic!("expected a session, got {other:?}"),
    };
    // The host answers PINGs only once `on_start` has run.
    session.ping().await.unwrap();
    let snapshot = live.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].session_id, session.session_token().session_id());
    assert_eq!(snapshot[0].device, a.identity.id());
    assert_eq!(snapshot[0].label, "Laptop of Ana");
    assert_eq!(snapshot[0].mode, SessionMode::ViewOnly);
    assert!(!snapshot[0].unattended);
    assert!(SessionActivity::session_live(&*live));
    assert!(RemoteSessionActivity::session_live(&*live));
    assert!(live.last_session_ended_at().is_none());

    // A second device asks to pair while the session is live: BUSY, no popup.
    let (x, y) = pipe();
    let busy_task = spawn_host(x, &host);
    let err = connect(y, &b.cfg, &b.identity, &b.deps, Intent::Session)
        .await
        .unwrap_err();
    assert!(
        matches!(err, HandshakeError::PairRejected { reason, .. } if reason == pair_reject::BUSY),
        "{err}"
    );
    assert!(matches!(
        busy_task.await.unwrap().unwrap(),
        HostOutcome::PairRejected { reason, .. } if reason == pair_reject::BUSY
    ));
    assert_eq!(
        host.consent.sas_shown().len(),
        1,
        "no popup during a session"
    );

    // The session ends: nothing is live, and the guard's cool-down has a start.
    session.bye(bye::USER).await.unwrap();
    host_task.await.unwrap().unwrap();
    assert_eq!(live.count(), 0);
    assert!(!SessionActivity::session_live(&*live));
    assert!(!RemoteSessionActivity::session_live(&*live));
    assert!(live.last_session_ended_at().is_some());

    // The second device now gets its popup (and a Deny).
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Reject));
    let (x, y) = pipe();
    let denied_task = spawn_host(x, &host);
    let err = connect(y, &b.cfg, &b.identity, &b.deps, Intent::Session)
        .await
        .unwrap_err();
    assert!(
        matches!(err, HandshakeError::PairRejected { reason, .. } if reason == pair_reject::DENIED),
        "{err}"
    );
    denied_task.await.unwrap().unwrap();
    assert_eq!(host.consent.sas_shown().len(), 2, "the popup is back");
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
            want_elevation: None,
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

/// r7, §B.2.1 / §B.8.4.1: an attended session's level is the person's
/// answer, and only an answer the host's availability row offers. An answer
/// off the offer is refused as a Deny — never started lower, never higher —
/// and the level reaches the client only through the signed accept.
#[tokio::test]
async fn the_level_is_the_answer_and_only_an_offered_one() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    let always_admin = Availability::of(Some(&WindowsFacts {
        installed: true,
        administrator: true,
        enable_lua: Some(0),
        ..WindowsFacts::default()
    }));
    let admin_prompt = Availability::of(Some(&WindowsFacts {
        installed: true,
        administrator: true,
        ..WindowsFacts::default()
    }));
    // (row, answer) ⇒ the accepted level, or `None`: refused `DENIED`.
    let cases = [
        (Availability::LINUX, SessionDecision::AllowOnceAdmin, None),
        (
            Availability::LINUX,
            SessionDecision::AllowOnce,
            Some(Level::CONTROL),
        ),
        (
            Availability::LINUX,
            SessionDecision::AllowOnceViewOnly,
            Some(Level::VIEW_ONLY),
        ),
        // The prompt path waits for the administrator helper: not offered.
        (admin_prompt, SessionDecision::AllowOnceAdmin, None),
        (
            admin_prompt,
            SessionDecision::AllowOnce,
            Some(Level::CONTROL),
        ),
        // Control there is administrator access: plain Allow is not offered.
        (always_admin, SessionDecision::AllowOnce, None),
        (
            always_admin,
            SessionDecision::AllowOnceAdmin,
            Some(Level::ADMIN),
        ),
        (
            always_admin,
            SessionDecision::AllowOnceViewOnly,
            Some(Level::VIEW_ONLY),
        ),
    ];
    for (levels, answer, expected) in cases {
        host.cfg.levels = levels;
        // A fresh popup budget per case: this is not the limiter's test.
        host.deps.session_policy = Arc::new(PairingPolicy::new(PairingLimits::sessions()));
        host.consent.push_session(SessionScript::Decide(answer));
        let (a, b) = pipe();
        let host_task = spawn_host(a, &host);
        let outcome = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        )
        .await;
        let case = format!("{:?} {answer:?}", levels.row);
        match expected {
            None => {
                let err = outcome.map(|_| ()).unwrap_err();
                assert!(
                    matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::DENIED),
                    "{case}: {err}"
                );
                assert!(
                    matches!(
                        host_task.await.unwrap().unwrap(),
                        HostOutcome::SessionRejected {
                            reason: reject::DENIED,
                            ..
                        }
                    ),
                    "{case}"
                );
            }
            Some(level) => {
                let ClientOutcome::Session(session) = outcome.unwrap() else {
                    panic!("{case}: no session");
                };
                let accept = session.accept();
                assert_eq!(accept.mode(), mode_code(level.mode()), "{case}");
                assert_eq!(accept.elevation(), level.elevation(), "{case}");
                session.bye(bye::USER).await.unwrap();
                match host_task.await.unwrap().unwrap() {
                    HostOutcome::Session { mode, .. } => assert_eq!(mode, level.mode(), "{case}"),
                    other => panic!("{case}: {other:?}"),
                }
            }
        }
    }
}

/// The session's level on the host is the level the accept signed (H5; M-UI-3
/// Security F-1, F-16): the session sink's `LiveSession` and the
/// `session_started` audit line carry the accept's elevation, and nothing
/// else; view-only never carries one (H8).
#[tokio::test]
async fn the_host_side_level_is_the_signed_one() {
    #[derive(Default)]
    struct Levels(Mutex<Vec<(SessionMode, tornect_core::levels::Elevation)>>);
    impl SessionSink for Levels {
        fn on_start(&self, s: &LiveSession<'_>) {
            self.0.lock().unwrap().push((s.mode, s.elevation));
        }
        fn on_end(&self, _: &str, _: Option<&SessionEnd>) {}
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    let sink = Arc::new(Levels::default());
    host.deps.sessions = sink.clone();
    let audit = Arc::new(RecordingAudit::default());
    host.deps.audit = audit.clone();
    host.cfg.levels = Availability::of(Some(&WindowsFacts {
        installed: true,
        administrator: true,
        enable_lua: Some(0),
        ..WindowsFacts::default()
    }));
    for answer in [
        SessionDecision::AllowOnceAdmin,
        SessionDecision::AllowOnceViewOnly,
    ] {
        host.deps.session_policy = Arc::new(PairingPolicy::new(PairingLimits::sessions()));
        host.consent.push_session(SessionScript::Decide(answer));
        let (a, b) = pipe();
        let host_task = spawn_host(a, &host);
        let ClientOutcome::Session(session) = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        )
        .await
        .unwrap() else {
            panic!("{answer:?}: no session");
        };
        let signed = session.accept().elevation();
        session.bye(bye::USER).await.unwrap();
        host_task.await.unwrap().unwrap();
        let (mode, elevation) = *sink.0.lock().unwrap().last().unwrap();
        assert_eq!(elevation, signed, "{answer:?}");
        let logged = audit
            .0
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find_map(|e| match e {
                AuditEvent::SessionStarted { elevation, .. } => Some(*elevation),
                _ => None,
            })
            .unwrap();
        assert_eq!(logged, signed, "{answer:?}");
        match answer {
            SessionDecision::AllowOnceAdmin => {
                assert_eq!(signed, tornect_core::levels::Elevation::Admin);
            }
            _ => {
                assert_eq!(mode, SessionMode::ViewOnly);
                assert_eq!(signed, tornect_core::levels::Elevation::None, "H8");
            }
        }
    }
}

/// A scripted administrator helper: what its start answers, what became of
/// the helper it handed out.
#[derive(Default)]
struct FakeHelper {
    /// How each start answers, in order (the last repeats).
    script: Mutex<Vec<HelperScript>>,
    started: std::sync::atomic::AtomicUsize,
    attached: Mutex<Vec<String>>,
    /// Helpers ended without being attached (dropped).
    ended: std::sync::atomic::AtomicUsize,
}

#[derive(Clone, Copy)]
enum HelperScript {
    Ready,
    Fail(&'static str),
    /// Ready only after this long (a helper later than the popup's time).
    ReadyAfter(Duration),
}

struct FakeAttached(Arc<FakeHelper>, bool);

impl AttachedHelper for FakeAttached {
    fn attach(mut self: Box<Self>, session_id: &str) {
        self.1 = true;
        self.0.attached.lock().unwrap().push(session_id.to_owned());
    }
}

impl Drop for FakeAttached {
    fn drop(&mut self) {
        if !self.1 {
            self.0.ended.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl AdminHelper for FakeHelper {
    fn start<'a>(
        self: Arc<Self>,
        _: &'a crate::pairing::TrustedPeer,
    ) -> BoxFuture<'a, Result<Box<dyn AttachedHelper>, &'static str>> {
        Box::pin(async move {
            self.started.fetch_add(1, Ordering::SeqCst);
            let step = {
                let mut script = self.script.lock().unwrap();
                if script.len() > 1 {
                    script.remove(0)
                } else {
                    script
                        .first()
                        .copied()
                        .unwrap_or(HelperScript::Fail("none"))
                }
            };
            // Made first, so a start dropped while it waits still ends it.
            let helper = FakeAttached(Arc::clone(&self), false);
            match step {
                HelperScript::Ready => Ok(Box::new(helper) as Box<dyn AttachedHelper>),
                HelperScript::Fail(why) => {
                    drop(helper);
                    Err(why)
                }
                HelperScript::ReadyAfter(wait) => {
                    tokio::time::sleep(wait).await;
                    Ok(Box::new(helper) as Box<dyn AttachedHelper>)
                }
            }
        })
    }

    fn start_task<'a>(
        self: Arc<Self>,
        peer: &'a crate::pairing::TrustedPeer,
    ) -> BoxFuture<'a, Result<Box<dyn AttachedHelper>, &'static str>> {
        self.start(peer)
    }
}

/// An unattended grant whose receipt is at the administrator level (what
/// an admin grant of M-FEAT-5 will give).
struct AdminGrant;

impl UnattendedHook for AdminGrant {
    fn reserved<'a>(
        &'a self,
        _: &'a DeviceId,
        proof: ConsentProof,
    ) -> BoxFuture<'a, Result<ConsentProof, messages::SessionReject>> {
        Box::pin(async move { Ok(proof) })
    }

    fn handle<'a>(
        &'a self,
        ctx: UnattendedContext<'a>,
    ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
        Box::pin(async move {
            let policy = PolicyReceipt::mint(
                [9u8; 8],
                SessionMode::Control,
                TransportPolicy::Any,
                None,
                0,
                false,
                ReadinessSnapshot::default(),
                None,
            )
            .with_elevation(tornect_core::levels::Elevation::Admin)
            // An unattended accept at the level carries 2 (decision M1-67).
            .with_grant_reach(2);
            Ok(UnattendedVerdict::Accept {
                proof: ConsentProof::Unattended {
                    grant: [9u8; 8],
                    proof_fp: [0u8; 8],
                    policy,
                    block: WindowPassed::Skipped,
                    token: DerivedToken::new([0xA5; 32], [0x5A; 32]),
                },
                caps: ChosenCaps::negotiate(&Caps::default(), &ctx.request.caps),
            })
        })
    }
}

/// One unattended session of [`AdminGrant`] against `host`: the elevation its
/// accept signed.
async fn unattended_admin_session(host: &HostSide) -> tornect_core::levels::Elevation {
    let (a, b) = pipe();
    let task = spawn_host(a, host);
    let mut raw = raw_unattended_request(host, CLIENT_SEED, b).await;
    // Longer than the host's own wait for the helper task.
    let rx = raw
        .chan
        .recv(Duration::from_secs(30), "accept")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rx.env.kind, Kind::SessionAccept);
    let accept: messages::SessionAccept = decode_body(&rx.env.body).unwrap();
    raw.chan.absorb(&rx);
    raw.chan.bye(bye::USER).await.unwrap();
    assert!(matches!(
        task.await.unwrap().unwrap(),
        HostOutcome::Session {
            unattended: true,
            ..
        }
    ));
    accept.elevation()
}

/// §B.8.7.5: an unattended administrator session on a row whose host holds a
/// filtered token starts the helper task after its checks and block window;
/// ready ⇒ the accept carries the administrator level and the helper
/// attaches to that session; not ready ⇒ the session starts at none and
/// stays there, `admin_helper_failed` logged. No popup either way.
#[tokio::test]
async fn an_unattended_administrator_session_takes_the_helper_task_or_starts_at_none() {
    use tornect_core::levels::Elevation;
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.deps.unattended = Arc::new(AdminGrant);
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    host.cfg.levels = installed_row();
    let audit = Arc::new(RecordingAudit::default());
    host.deps.audit = audit.clone();
    for (script, expected) in [
        (HelperScript::Ready, Elevation::Admin),
        (
            HelperScript::Fail("the helper task did not start"),
            Elevation::None,
        ),
    ] {
        let helper = Arc::new(FakeHelper::default());
        *helper.script.lock().unwrap() = vec![script];
        host.deps.admin_helper = helper.clone();
        assert_eq!(unattended_admin_session(&host).await, expected);
        assert_eq!(helper.started.load(Ordering::SeqCst), 1);
        assert_eq!(
            helper.attached.lock().unwrap().len(),
            usize::from(expected == Elevation::Admin)
        );
    }
    let failed = audit.0.lock().unwrap().iter().any(|e| {
        matches!(
            e,
            AuditEvent::AdminHelper {
                what: HelperEvent::Failed,
                ..
            }
        )
    });
    assert!(failed);
    assert_eq!(host.consent.session_popups(), 0, "no popup for unattended");
    // Where every program runs as administrator (UAC off), the level needs
    // no helper: none is started.
    host.cfg.levels = Availability::of(Some(&WindowsFacts {
        installed: true,
        administrator: true,
        enable_lua: Some(0),
        ..WindowsFacts::default()
    }));
    let helper = Arc::new(FakeHelper::default());
    host.deps.admin_helper = helper.clone();
    assert_eq!(unattended_admin_session(&host).await, Elevation::Admin);
    assert_eq!(helper.started.load(Ordering::SeqCst), 0);
}

/// §B.8.7.5: a helper task not connected within 5 s is ended, never attached,
/// and the unattended session starts at none.
#[tokio::test(start_paused = true)]
async fn a_late_helper_task_leaves_the_session_at_none() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.deps.unattended = Arc::new(AdminGrant);
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    host.cfg.levels = installed_row();
    let helper = Arc::new(FakeHelper::default());
    *helper.script.lock().unwrap() = vec![HelperScript::ReadyAfter(
        host::HELPER_TASK_BUDGET + Duration::from_secs(1),
    )];
    host.deps.admin_helper = helper.clone();
    assert_eq!(
        unattended_admin_session(&host).await,
        tornect_core::levels::Elevation::None
    );
    assert!(helper.attached.lock().unwrap().is_empty(), "never attached");
    assert_eq!(helper.ended.load(Ordering::SeqCst), 1, "ended");
}

fn installed_row() -> Availability {
    Availability::of(Some(&WindowsFacts {
        installed: true,
        administrator: true,
        ..WindowsFacts::default()
    }))
}

/// §B.2.1, §B.8.7.5 (H3, H5, H8; amendment §1.3 (i)): the helper starts
/// between the administrator answer and the accept; the accept carries the
/// administrator level only when it is attached, and it attaches to that
/// session; a helper that fails leaves the sheet to be answered again (never
/// a silent lower level); a view-only answer never starts one.
#[tokio::test]
async fn the_accept_carries_the_administrator_level_only_with_the_helper_attached() {
    if !tornect_core::levels::ADMIN_HELPER {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    host.cfg.levels = installed_row();
    let audit = Arc::new(RecordingAudit::default());
    host.deps.audit = audit.clone();
    // (script, answers in order, the accepted level, attached?)
    let cases = [
        (
            vec![HelperScript::Ready],
            vec![SessionDecision::AllowOnceAdmin],
            Level::ADMIN,
            true,
        ),
        (
            vec![HelperScript::Fail("Windows' prompt was cancelled")],
            vec![SessionDecision::AllowOnceAdmin, SessionDecision::AllowOnce],
            Level::CONTROL,
            false,
        ),
        (
            vec![HelperScript::Ready],
            vec![SessionDecision::AllowOnceViewOnly],
            Level::VIEW_ONLY,
            false,
        ),
    ];
    for (script, answers, level, attached) in cases {
        let helper = Arc::new(FakeHelper::default());
        *helper.script.lock().unwrap() = script;
        host.deps.admin_helper = helper.clone();
        host.deps.session_policy = Arc::new(PairingPolicy::new(PairingLimits::sessions()));
        for answer in &answers {
            host.consent.push_session(SessionScript::Decide(*answer));
        }
        let asked_before = host.consent.session_popups();
        let (a, b) = pipe();
        let host_task = spawn_host(a, &host);
        let ClientOutcome::Session(session) = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            Intent::Session,
        )
        .await
        .unwrap() else {
            panic!("{level:?}: no session");
        };
        let accept = session.accept();
        assert_eq!(accept.elevation(), level.elevation(), "{level:?}");
        assert_eq!(accept.mode(), mode_code(level.mode()), "{level:?}");
        session.bye(bye::USER).await.unwrap();
        host_task.await.unwrap().unwrap();
        let started = helper.started.load(Ordering::SeqCst);
        let attached_to = helper.attached.lock().unwrap().clone();
        assert_eq!(attached_to.len(), usize::from(attached), "{level:?}");
        assert_eq!(
            host.consent.session_popups() - asked_before,
            answers.len(),
            "{level:?}: asked once per answer"
        );
        match level.mode() {
            SessionMode::ViewOnly => assert_eq!(started, 0, "view-only starts no helper"),
            SessionMode::Control => assert_eq!(started, 1),
        }
        if attached {
            let logged = audit.0.lock().unwrap().iter().any(|e| {
                matches!(e, AuditEvent::AdminHelper { what: HelperEvent::Started, session_id: Some(id), .. } if *id == attached_to[0])
            });
            assert!(logged, "admin_helper_started for the session");
        }
    }
    let failed = audit.0.lock().unwrap().iter().any(|e| {
        matches!(
            e,
            AuditEvent::AdminHelper {
                what: HelperEvent::Failed,
                session_id: None,
                ..
            }
        )
    });
    assert!(failed, "admin_helper_failed recorded");
}

/// §B.2.1 (the 5 s budget ends inside the popup's time): a helper not ready
/// before the popup's time runs out is ended, never attached, and the
/// session is refused `POPUP_TIMEOUT`, never started at a level.
#[tokio::test(start_paused = true)]
async fn a_late_helper_is_ended_and_never_attached() {
    if !tornect_core::levels::ADMIN_HELPER {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    host.cfg.levels = installed_row();
    let helper = Arc::new(FakeHelper::default());
    *helper.script.lock().unwrap() = vec![HelperScript::ReadyAfter(
        timeouts::POPUP + Duration::from_secs(5),
    )];
    host.deps.admin_helper = helper.clone();
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnceAdmin));
    let (a, b) = pipe();
    let host_task = spawn_host(a, &host);
    let outcome = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await;
    let err = outcome.map(|_| ()).unwrap_err();
    assert!(
        matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::POPUP_TIMEOUT),
        "{err}"
    );
    assert!(matches!(
        host_task.await.unwrap().unwrap(),
        HostOutcome::SessionRejected {
            reason: reject::POPUP_TIMEOUT,
            ..
        }
    ));
    assert_eq!(helper.started.load(Ordering::SeqCst), 1);
    assert!(helper.attached.lock().unwrap().is_empty(), "never attached");
    assert_eq!(helper.ended.load(Ordering::SeqCst), 1, "ended");
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
        elevation: None,
        grant_reach: None,
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

/// The session sink is handed the live session exactly once — with the
/// transcript hash and the token both sides agree on — and released exactly
/// once when it ends, including when the kill switch ends it. `on_end` is what
/// stops capture, so it has to run on every way out of `Established`.
#[tokio::test(start_paused = true)]
async fn the_session_sink_sees_one_start_and_one_end() {
    struct Started {
        session_id: String,
        th_final: [u8; 32],
        mode: SessionMode,
        unattended: bool,
        token: SessionToken,
    }
    #[derive(Default)]
    struct Recorder {
        started: Mutex<Vec<Started>>,
        ended: Mutex<Vec<(String, Option<SessionEnd>)>>,
    }
    impl SessionSink for Recorder {
        fn on_start(&self, s: &LiveSession<'_>) {
            self.started.lock().unwrap().push(Started {
                session_id: s.session_id.to_owned(),
                th_final: s.th_final,
                mode: s.mode,
                unattended: s.unattended,
                token: s.token.clone(),
            });
        }
        fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
            self.ended
                .lock()
                .unwrap()
                .push((session_id.to_owned(), end.cloned()));
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.cfg.orphan_timeout = None;
    host.cfg.idle_timeout = Duration::from_secs(30);
    let sink = Arc::new(Recorder::default());
    host.deps.sessions = sink.clone();
    let kill = KillSwitch::new();
    host.deps.kill = kill.clone();
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

    // Started before the first frame of the session is served.
    session.ping().await.unwrap();
    let session_id = {
        let started = sink.started.lock().unwrap();
        assert_eq!(started.len(), 1, "exactly one start");
        let s = &started[0];
        assert_eq!(s.th_final, session.th(), "both sides agree on th_final");
        assert_eq!(&s.token, session.session_token(), "the media key matches");
        assert_eq!(s.mode, SessionMode::Control);
        assert!(!s.unattended, "this one was attended");
        assert!(!s.session_id.is_empty());
        s.session_id.clone()
    };
    assert!(sink.ended.lock().unwrap().is_empty(), "not ended yet");

    kill.kill(bye::PANIC);
    match task.await.unwrap().unwrap() {
        HostOutcome::Session { end, .. } => assert_eq!(end, SessionEnd::Killed(bye::PANIC)),
        other => panic!("{other:?}"),
    }
    let ended = sink.ended.lock().unwrap();
    assert_eq!(ended.len(), 1, "exactly one end");
    assert_eq!(ended[0].0, session_id, "same session");
    assert_eq!(ended[0].1, Some(SessionEnd::Killed(bye::PANIC)));
    assert_eq!(sink.started.lock().unwrap().len(), 1, "started only once");
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
        elevation: tornect_core::levels::Elevation::None,
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
            want_elevation: None,
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
        fn reserved<'a>(
            &'a self,
            _: &'a DeviceId,
            proof: ConsentProof,
        ) -> BoxFuture<'a, Result<ConsentProof, messages::SessionReject>> {
            Box::pin(async move { Ok(proof) })
        }

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
        fn reserved<'a>(
            &'a self,
            _: &'a DeviceId,
            proof: ConsentProof,
        ) -> BoxFuture<'a, Result<ConsentProof, messages::SessionReject>> {
            Box::pin(async move { Ok(proof) })
        }

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
                        grant_reach: None,
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
        fn reserved<'a>(
            &'a self,
            _: &'a DeviceId,
            proof: ConsentProof,
        ) -> BoxFuture<'a, Result<ConsentProof, messages::SessionReject>> {
            Box::pin(async move { Ok(proof) })
        }

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
        fn reserved<'a>(
            &'a self,
            _: &'a DeviceId,
            proof: ConsentProof,
        ) -> BoxFuture<'a, Result<ConsentProof, messages::SessionReject>> {
            Box::pin(async move { Ok(proof) })
        }

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

/// SLICE-D D2 (the `PING` half of SLICE-B2 B2-8): a host `PING` is answered
/// inside `next_event` without moving its deadline. A host that pings every
/// 5 s must not keep a 10 s wait, and with it `tornect connect --pings N`,
/// from ever ending.
#[tokio::test(start_paused = true)]
async fn host_pings_do_not_move_the_next_event_deadline() {
    let tmp = tempfile::tempdir().unwrap();
    let real = HostIdentity::from_seed(&HOST_SEED);
    let real_pk = HostSigner::public_key(&real);
    let client = client_side(tmp.path(), real.id(), CLIENT_SEED);
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
        // A PING every 5 s, until the client goes; count the answers.
        let mut answered = 0u32;
        for nonce in 0u64.. {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if h.chan.send(&Ping { nonce }, None).await.is_err() {
                break;
            }
            match h.chan.recv(Duration::from_secs(5), "pong").await {
                Ok(Some(rx)) if rx.env.kind == Kind::Pong => answered += 1,
                _ => break,
            }
        }
        answered
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
    let start = tokio::time::Instant::now();
    let waited = tokio::time::timeout(
        Duration::from_secs(60),
        session.next_event(Duration::from_secs(10)),
    )
    .await;
    let result =
        waited.expect("next_event(10 s) was still waiting at 60 s: every host PING restarted it");
    assert!(
        matches!(result, Err(HandshakeError::Timeout(_))),
        "{result:?}"
    );
    assert_eq!(start.elapsed(), Duration::from_secs(10));
    drop(session);
    assert!(
        host.await.unwrap() >= 1,
        "the host's PINGs were answered in place"
    );
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
        fn reserved<'a>(
            &'a self,
            _: &'a DeviceId,
            proof: ConsentProof,
        ) -> BoxFuture<'a, Result<ConsentProof, messages::SessionReject>> {
            Box::pin(async move { Ok(proof) })
        }

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

/// A session popup held open until the test answers it (Allow once), saying
/// when it opened.
struct HeldPopup {
    opened: Arc<tokio::sync::Notify>,
    answer: Arc<tokio::sync::Notify>,
}

impl crate::pairing::Consent for HeldPopup {
    fn pairing<'a>(
        &'a self,
        _: &'a crate::pairing::PairingPeer,
        _: &'a str,
    ) -> BoxFuture<'a, PairDecision> {
        Box::pin(async { PairDecision::Reject })
    }

    fn session<'a>(
        &'a self,
        _: &'a crate::pairing::TrustedPeer,
        _: &'a crate::pairing::SessionRequestSummary,
    ) -> BoxFuture<'a, SessionDecision> {
        Box::pin(async move {
            self.opened.notify_one();
            self.answer.notified().await;
            SessionDecision::AllowOnce
        })
    }
}

/// Counts `on_start` calls in front of a tracker.
#[derive(Default)]
struct CountingSink {
    starts: std::sync::atomic::AtomicUsize,
    live: Arc<LiveSessions>,
}

impl SessionSink for CountingSink {
    fn on_start(&self, session: &LiveSession<'_>) {
        self.starts.fetch_add(1, Ordering::SeqCst);
        self.live.on_start(session);
    }

    fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
        self.live.on_end(session_id, end);
    }
}

/// A host whose paired client is `CLIENT_SEED`, with the popup held open by a
/// [`HeldPopup`] and a counting sink that is also its activity source.
fn held_popup_host(
    tmp: &std::path::Path,
) -> (
    HostSide,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
    Arc<CountingSink>,
) {
    let mut host = host_side(tmp, HOST_SEED);
    let (opened, answer) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    host.deps.consent = Arc::new(HeldPopup {
        opened: opened.clone(),
        answer: answer.clone(),
    });
    let sink = Arc::new(CountingSink::default());
    host.deps.sessions = sink.clone();
    host.deps.activity = sink.live.clone();
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    (host, opened, answer, sink)
}

/// SLICE-B1 B1-3 / SLICE-B2 B2-5 (a): a panic pressed while the session popup
/// is open refuses the session, even when the owner then clicks Allow. The host
/// used to send `SESSION_ACCEPT`, log the start and call `on_start` (where
/// capture begins) before it noticed the kill.
#[tokio::test]
async fn a_kill_while_the_popup_is_open_refuses_the_session() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut host, opened, answer, sink) = held_popup_host(tmp.path());
    let kill = KillSwitch::new();
    host.deps.kill = kill.clone();
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
    raw.hello_ack().await;
    let asked = tokio::spawn(async move { raw.request_session().await });

    opened.notified().await;
    kill.kill(bye::PANIC);
    answer.notify_one();
    assert_eq!(asked.await.unwrap().env.kind, Kind::SessionReject);
    match task.await.unwrap().unwrap() {
        HostOutcome::SessionRejected { reason, .. } => assert_eq!(reason, reject::DENIED),
        other => panic!("{other:?}"),
    }
    assert_eq!(sink.starts.load(Ordering::SeqCst), 0, "no on_start");
}

/// SLICE-B2 B2-5 (b): a session that went live while this popup was open blocks
/// the accept: one remote session at a time (§B.8.6.4).
#[tokio::test]
async fn a_session_that_went_live_during_the_popup_blocks_the_accept() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, opened, answer, sink) = held_popup_host(tmp.path());
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
    raw.hello_ack().await;
    let asked = tokio::spawn(async move { raw.request_session().await });

    opened.notified().await;
    let other = SessionToken::new([7; 32]);
    let other_id = other.session_id();
    sink.live.on_start(&LiveSession {
        device: DeviceId::from_bytes([7; 32]),
        label: "Other",
        session_id: &other_id,
        token: &other,
        th_final: [0; 32],
        mode: SessionMode::Control,
        elevation: tornect_core::levels::Elevation::None,
        unattended: false,
    });
    answer.notify_one();
    assert_eq!(asked.await.unwrap().env.kind, Kind::SessionReject);
    match task.await.unwrap().unwrap() {
        HostOutcome::SessionRejected { reason, .. } => assert_eq!(reason, reject::BUSY),
        other => panic!("{other:?}"),
    }
    assert_eq!(sink.starts.load(Ordering::SeqCst), 0, "no second on_start");
    assert_eq!(sink.live.count(), 1);
}

/// SLICE-C3 C3-1: two accepts racing let one session go live (§B.8.6.4). The
/// first accept's write is stuck, as when its peer withholds Tor credit; a
/// second paired device that asks meanwhile found nothing live, since the
/// first registers only after its write, and both went live. The gate now
/// reserves the slot in the same step as its check.
#[tokio::test(start_paused = true)]
async fn two_accepts_racing_let_only_one_session_go_live() {
    const OTHER_SEED: [u8; 32] = [0x23; 32];
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let sink = Arc::new(CountingSink::default());
    host.deps.sessions = sink.clone();
    host.deps.activity = sink.live.clone();
    for (seed, label) in [(CLIENT_SEED, "First"), (OTHER_SEED, "Second")] {
        host.trusted
            .pin(DeviceIdentity::from_seed(&seed).id(), label)
            .unwrap();
        host.consent
            .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    }

    // The first: its SESSION_ACCEPT goes into a 64-byte pipe nobody reads.
    let (a, b) = duplex(64);
    let first = spawn_host(a, &host);
    let mut stuck = RawClient::new(b, &host.identity, CLIENT_SEED);
    stuck.hello_ack().await;
    let request = SessionRequest {
        caps: Caps::default(),
        unattended: None,
    };
    stuck
        .chan
        .send(&request, Some(&stuck.identity))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(host.consent.session_popups(), 1);
    assert_eq!(sink.starts.load(Ordering::SeqCst), 0, "stuck in its accept");

    // The second asks while the first accept is still being written.
    let (a, b) = pipe();
    let second = spawn_host(a, &host);
    let mut raw = RawClient::new(b, &host.identity, OTHER_SEED);
    raw.hello_ack().await;
    let answer = raw.request_session().await;
    assert_eq!(
        answer.env.kind,
        Kind::SessionReject,
        "a second session went live beside the first"
    );
    match second.await.unwrap().unwrap() {
        HostOutcome::SessionRejected { reason, .. } => assert_eq!(reason, reject::BUSY),
        other => panic!("{other:?}"),
    }

    // The first goes live once its accept is read.
    assert_eq!(stuck.recv().await.unwrap().env.kind, Kind::SessionAccept);
    stuck.chan.send(&Ping { nonce: 1 }, None).await.unwrap();
    assert_eq!(stuck.recv().await.unwrap().env.kind, Kind::Pong);
    assert_eq!(sink.starts.load(Ordering::SeqCst), 1);
    assert_eq!(sink.live.count(), 1);
    drop(stuck);
    first.await.unwrap().unwrap();
    assert_eq!(sink.live.count(), 0);
    assert!(!SessionActivity::session_live(&*sink.live));
}

/// SLICE-C3 C3-1: the reservation is let go however the accept ends. A host
/// task dropped in the middle of its accept write leaves no session behind
/// that would answer every later request `BUSY`.
#[tokio::test(start_paused = true)]
async fn an_accept_that_never_completes_lets_go_of_its_reservation() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let sink = Arc::new(CountingSink::default());
    host.deps.sessions = sink.clone();
    host.deps.activity = sink.live.clone();
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "First")
        .unwrap();
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let (a, b) = duplex(64);
    let task = spawn_host(a, &host);
    let mut stuck = RawClient::new(b, &host.identity, CLIENT_SEED);
    stuck.hello_ack().await;
    let request = SessionRequest {
        caps: Caps::default(),
        unattended: None,
    };
    stuck
        .chan
        .send(&request, Some(&stuck.identity))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        SessionActivity::session_live(&*sink.live),
        "reserved while its accept is written"
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!SessionActivity::session_live(&*sink.live));
    assert_eq!(sink.starts.load(Ordering::SeqCst), 0);
}

/// An unattended hook that accepts every request, as a correct password would.
struct AcceptAll;

impl UnattendedHook for AcceptAll {
    fn reserved<'a>(
        &'a self,
        _: &'a DeviceId,
        proof: ConsentProof,
    ) -> BoxFuture<'a, Result<ConsentProof, messages::SessionReject>> {
        Box::pin(async move { Ok(proof) })
    }

    fn handle<'a>(
        &'a self,
        ctx: UnattendedContext<'a>,
    ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
        Box::pin(async move {
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
                    token: DerivedToken::new([0xA5; 32], [0x5A; 32]),
                },
                caps: ChosenCaps::negotiate(&Caps::default(), &ctx.request.caps),
            })
        })
    }
}

/// SLICE-B1 B1-1: an unattended request that got through its PAKE while another
/// session is live is refused `SESSION_ACTIVE` (§B.8.4.6 `0x0026`), with no
/// second session and no `on_start`. Only attended and pairing requests were
/// answered `BUSY` before.
#[tokio::test]
async fn an_unattended_request_while_a_session_is_live_is_session_active() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.deps.unattended = Arc::new(AcceptAll);
    let sink = Arc::new(CountingSink::default());
    host.deps.sessions = sink.clone();
    host.deps.activity = sink.live.clone();
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    let other = SessionToken::new([7; 32]);
    let other_id = other.session_id();
    sink.live.on_start(&LiveSession {
        device: DeviceId::from_bytes([7; 32]),
        label: "Helper",
        session_id: &other_id,
        token: &other,
        th_final: [0; 32],
        mode: SessionMode::ViewOnly,
        elevation: tornect_core::levels::Elevation::None,
        unattended: false,
    });

    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut raw = raw_unattended_request(&host, CLIENT_SEED, b).await;
    let rx = raw.recv().await.unwrap();
    assert_eq!(rx.env.kind, Kind::SessionReject);
    let refused: messages::SessionReject = decode_body(&rx.env.body).unwrap();
    assert_eq!(refused.reason, reject::SESSION_ACTIVE);
    match task.await.unwrap().unwrap() {
        HostOutcome::SessionRejected { reason, .. } => {
            assert_eq!(reason, reject::SESSION_ACTIVE);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(sink.starts.load(Ordering::SeqCst), 0);
    assert_eq!(sink.live.count(), 1);
}

/// SLICE-B1 B1-2 / SLICE-B2 B2-1: a kill ends the session at once even while
/// the host is stuck writing to a peer that stopped reading. The sink and the
/// log hear of it first, as `Killed` rather than `io`, and the goodbye is tried
/// after, bounded. Over a 256-byte pipe the unread `PONG`s back up the way
/// withheld Tor credit does; the host used to wait in that write for good.
#[tokio::test(start_paused = true)]
async fn a_kill_ends_the_session_while_a_write_to_the_peer_is_stuck() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.cfg.orphan_timeout = None;
    let kill = KillSwitch::new();
    host.deps.kill = kill.clone();
    let live = Arc::new(LiveSessions::new());
    host.deps.sessions = live.clone();
    host.deps.activity = live.clone();
    let audit = Arc::new(RecordingAudit::default());
    host.deps.audit = audit.clone();
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));

    let (a, b) = duplex(256);
    let task = spawn_host(a, &host);
    let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
    raw.hello_ack().await;
    assert_eq!(raw.request_session().await.env.kind, Kind::SessionAccept);
    // `PING`s whose `PONG`s are never read: about a dozen fill the host's side.
    for nonce in 0..20u64 {
        raw.chan.send(&Ping { nonce }, None).await.unwrap();
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(live.count(), 1, "live, with its host stuck in a write");

    kill.kill(bye::PANIC);
    let outcome = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the kill must not wait for the peer")
        .unwrap()
        .unwrap();
    assert!(
        matches!(
            outcome,
            HostOutcome::Session {
                end: SessionEnd::Killed(bye::PANIC),
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(live.count(), 0);
    let ended = audit.0.lock().unwrap().iter().find_map(|e| match e {
        AuditEvent::SessionEnded { detail, .. } => Some(detail.clone()),
        _ => None,
    });
    assert_eq!(ended.as_deref(), Some("Killed(8)"));
    drop(raw);
}

/// The host's end of a pipe whose writes can be frozen, as a peer that
/// withholds Tor credit freezes them; reads go on.
struct FrozenWrites {
    inner: DuplexStream,
    frozen: Arc<std::sync::atomic::AtomicBool>,
}

impl AsyncRead for FrozenWrites {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FrozenWrites {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.frozen.load(Ordering::SeqCst) {
            return std::task::Poll::Pending;
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.frozen.load(Ordering::SeqCst) {
            return std::task::Poll::Pending;
        }
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.frozen.load(Ordering::SeqCst) {
            return std::task::Poll::Pending;
        }
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// SLICE-C3 C3-2: a violation inside a live session (an out-of-place kind, a
/// malformed body) ends the session at once, even when its `ERROR` cannot be
/// written; the `ERROR` is only the goodbye, bounded like a `BYE`. The host
/// used to write it and close first, unraced, so a peer that withheld credit
/// kept the session live, capture running and a kill unheard for up to a
/// minute, and a kill was then logged as the violation.
#[tokio::test(start_paused = true)]
async fn a_violation_ends_the_session_before_its_error_is_written() {
    for malformed_body in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let mut host = host_side(tmp.path(), HOST_SEED);
        host.cfg.orphan_timeout = None;
        let kill = KillSwitch::new();
        host.deps.kill = kill.clone();
        let live = Arc::new(LiveSessions::new());
        host.deps.sessions = live.clone();
        host.deps.activity = live.clone();
        let audit = Arc::new(RecordingAudit::default());
        host.deps.audit = audit.clone();
        host.trusted
            .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
            .unwrap();
        host.consent
            .push_session(SessionScript::Decide(SessionDecision::AllowOnce));

        let (a, b) = pipe();
        let frozen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stream = FrozenWrites {
            inner: a,
            frozen: frozen.clone(),
        };
        let (cfg, deps) = (host.cfg.clone(), host.deps.clone());
        let task = tokio::spawn(async move { serve_host(stream, &cfg, &deps).await });
        let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
        raw.hello_ack().await;
        assert_eq!(raw.request_session().await.env.kind, Kind::SessionAccept);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(live.count(), 1);

        frozen.store(true, Ordering::SeqCst);
        let msg_id = raw.chan.next_tx_id();
        let mut client = raw.chan.into_stream();
        let (kind, body, code) = if malformed_body {
            (Kind::Ping, vec![0xff], codes::E_BAD_LEN)
        } else {
            (
                Kind::PairRequest,
                encode_body(&raw_pair_request()),
                codes::E_BAD_STATE,
            )
        };
        let env = Envelope::new(1, msg_id, kind, body);
        write_frame(&mut client, &env.encode()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            live.count(),
            0,
            "the session ends at the violation, not once its ERROR is written \
             (malformed body: {malformed_body})"
        );

        kill.kill(bye::PANIC);
        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the host must not wait for the peer")
            .unwrap();
        assert_eq!(outcome.unwrap_err().violation_code(), Some(code));
        let ended = audit.0.lock().unwrap().iter().find_map(|e| match e {
            AuditEvent::SessionEnded { detail, .. } => Some(detail.clone()),
            _ => None,
        });
        assert_eq!(ended.as_deref(), Some(codes::name(code)));
        drop(client);
    }
}

/// SLICE-B1 B1-4: a sink that panics inside `on_start` still gets its `on_end`,
/// and the end is logged: no tracker entry outlives the task that served it.
#[tokio::test]
async fn a_sink_that_panics_still_releases_the_session() {
    struct Panicking(Arc<LiveSessions>);
    impl SessionSink for Panicking {
        fn on_start(&self, session: &LiveSession<'_>) {
            self.0.on_start(session);
            panic!("the sink failed");
        }

        fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
            self.0.on_end(session_id, end);
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let live = Arc::new(LiveSessions::new());
    host.deps.sessions = Arc::new(Panicking(live.clone()));
    host.deps.activity = live.clone();
    let audit = Arc::new(RecordingAudit::default());
    host.deps.audit = audit.clone();
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));

    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
    raw.hello_ack().await;
    assert_eq!(raw.request_session().await.env.kind, Kind::SessionAccept);
    assert!(task.await.unwrap_err().is_panic());
    assert_eq!(live.count(), 0, "released despite the panic");
    let ended = audit.0.lock().unwrap().iter().find_map(|e| match e {
        AuditEvent::SessionEnded { detail, .. } => Some(detail.clone()),
        _ => None,
    });
    assert_eq!(ended.as_deref(), Some("aborted"));
}

/// Pairs up to its code check and then says nothing more, as the window's
/// code card does while nobody looks at it: `confirm` never answers.
struct SilentAtTheCode;

impl client::ClientPairingUi for SilentAtTheCode {
    fn show_sas<'a>(&'a self, _: &'a TornectId, _: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    fn confirm<'a>(&'a self, _: &'a TornectId, _: &'a str, _: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(std::future::pending())
    }
}

/// A device the host's user paired, which then says nothing (its user has not
/// confirmed the code yet), is reported as paired when the host stops waiting
/// for its session request, as one that leaves is, not as a failed handshake:
/// the host's accept pinned it. Only the reported outcome changes. A timeout
/// before the host's accept still pins nothing and grants nothing: silence
/// after `HELLO_ACK`, or a pairing popup nobody answers.
#[tokio::test(start_paused = true)]
async fn a_device_the_host_paired_that_then_says_nothing_is_reported_paired() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    let device = DeviceIdentity::from_seed(&CLIENT_SEED).id();
    let nothing_granted = |host: &HostSide| {
        assert_eq!(host.consent.session_popups(), 0, "a session popup");
        assert_eq!(
            host.deps.stats.accepted_total.load(Ordering::SeqCst),
            0,
            "a session accepted"
        );
    };

    // Before the host's accept: HELLO, then silence.
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut raw = RawClient::new(b, &host.identity, CLIENT_SEED);
    raw.send_hello(None).await;
    let _ack = raw.recv().await.unwrap();
    let err = task.await.unwrap().unwrap_err();
    assert!(
        matches!(err, HandshakeError::Timeout("PAIR_REQUEST")),
        "{err}"
    );
    assert!(
        host.trusted.get(&device).is_none(),
        "pinned without a pairing"
    );
    nothing_granted(&host);

    // Before the host's accept: the pairing popup is never answered.
    host.consent.push_pairing(PairScript::Hang);
    let mut client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    client.deps.ui = Arc::new(SilentAtTheCode);
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
                reason: pair_reject::TIMEOUT,
                ..
            }
        ),
        "{err}"
    );
    assert!(matches!(
        task.await.unwrap().unwrap(),
        HostOutcome::PairRejected {
            reason: pair_reject::TIMEOUT,
            ..
        }
    ));
    assert!(
        host.trusted.get(&device).is_none(),
        "pinned without an accept"
    );
    nothing_granted(&host);

    // After the host's accept: the client never answers its code check.
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let asking = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    );
    tokio::pin!(asking);
    let started = tokio::time::Instant::now();
    let outcome = tokio::select! {
        biased;
        outcome = task => outcome.unwrap(),
        ended = &mut asking => panic!("the client ended first: {ended:?}"),
    };
    match outcome {
        Ok(HostOutcome::PairedOnly {
            device: paired,
            label,
        }) => {
            assert_eq!(paired, device);
            assert_eq!(label, "Laptop of Ana");
        }
        other => panic!("expected PairedOnly, got {other:?}"),
    }
    assert!(started.elapsed() >= timeouts::SESSION_REQUEST);
    assert!(
        host.trusted.get(&device).is_some(),
        "the host's accept pinned it"
    );
    assert!(
        !client.known.is_known(&host.identity.id()),
        "the client pinned nothing"
    );
    nothing_granted(&host);
}

/// A host whose unattended grant for [`CLIENT_SEED`] has the password `pw`, served by
/// the real `UnattendedAuth` hook, and a client paired with it both ways.
fn unattended_pair(tmp: &std::path::Path, pw: &str) -> (HostSide, ClientSide) {
    unattended_pair_with(tmp, pw, Arc::new(tornect_core::levels::FixedFacts::linux()))
}

/// [`unattended_pair`] on a host whose account facts and helper task are `facts`.
fn unattended_pair_with(
    tmp: &std::path::Path,
    pw: &str,
    facts: Arc<dyn tornect_core::levels::FactsSource>,
) -> (HostSide, ClientSide) {
    use tornect_core::keystore::FileSecretStore;
    use tornect_core::paths::Paths;
    use tornect_core::session_log::Actor;
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
    use crate::unattended::{GuardAdmin, OpaqueServerSetupSource, UnattendedAuth};

    let mut host = host_side(tmp, HOST_SEED);
    let client = client_side(tmp, host.identity.id(), CLIENT_SEED);
    let device = client.identity.id();
    let host_onion_pk = *host.identity.id().public_key_bytes();
    host.trusted.pin(device, "Laptop of Ana").unwrap();
    client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    let paths = Paths::from_home(tmp.join("host-home"));
    std::fs::create_dir_all(paths.keys_dir()).unwrap();
    let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
    let store = GrantStore::open(
        &paths,
        secrets,
        Arc::new(SystemClock::default()),
        SessionLog::new(paths.sessions_log()),
    )
    .unwrap();
    // The grant is set up as the command line would on a host where nothing reaches the
    // level; the host itself, and its admin path, run on `facts`.
    let guard = MutationGuard::new(
        store.clone(),
        Arc::new(AllowAllReAuth::default()),
        Arc::new(NoSessionActivity),
        Arc::new(tornect_core::levels::FixedFacts::linux()),
    )
    .with_paired_devices(Arc::new(AllowAllPaired))
    .with_server_setup_source(Arc::new(OpaqueServerSetupSource));
    let admin_guard = MutationGuard::new(
        store,
        Arc::new(AllowAllReAuth::default()),
        Arc::new(NoSessionActivity),
        Arc::clone(&facts),
    )
    .with_paired_devices(Arc::new(AllowAllPaired));
    guard.master_on(Actor::Cli, &host_onion_pk).unwrap();
    guard
        .create_grant(
            Actor::Cli,
            &device,
            Preset::HeadlessBox,
            &GrantOptions::default(),
            &[0u8; 192],
            false,
        )
        .unwrap();
    let setup = auth::parse_server_setup(&guard.store().server_setup().unwrap()).unwrap();
    let record = auth::register_locally(
        &setup,
        pw,
        device.public_key_bytes(),
        auth::identifiers(device.public_key_bytes(), &host_onion_pk),
    )
    .unwrap();
    guard
        .set_password(
            Actor::Cli,
            &device,
            &record,
            &GrantOptions::default(),
            false,
        )
        .unwrap();
    let limiter = AttemptLimiter::new(guard.store().clone());
    host.deps.unattended = Arc::new(
        UnattendedAuth::new(
            limiter,
            Arc::new(FixedOffset::utc()),
            HostTransport::default(),
            facts,
        )
        .with_admin_authority(Arc::new(GuardAdmin::new(Arc::new(admin_guard)))),
    );
    (host, client)
}

/// The real hook, then an accept signed above what the grant and the request allow: what
/// a host-side clamp bug would send (M-FEAT-2 F-8).
struct Inflated {
    inner: Arc<dyn UnattendedHook>,
    mode: SessionMode,
    administrator: bool,
}

impl UnattendedHook for Inflated {
    fn reserved<'a>(
        &'a self,
        _: &'a DeviceId,
        proof: ConsentProof,
    ) -> BoxFuture<'a, Result<ConsentProof, messages::SessionReject>> {
        Box::pin(async move { Ok(proof) })
    }

    fn handle<'a>(
        &'a self,
        ctx: UnattendedContext<'a>,
    ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
        Box::pin(async move {
            Ok(match self.inner.handle(ctx).await? {
                UnattendedVerdict::Accept {
                    proof:
                        ConsentProof::Unattended {
                            grant,
                            proof_fp,
                            policy,
                            block,
                            token,
                        },
                    caps,
                } => {
                    let mut policy2 = PolicyReceipt::mint(
                        *policy.grant(),
                        self.mode,
                        policy.transport(),
                        policy.ends_at(),
                        policy.block_window_s(),
                        policy.ask_before_start(),
                        policy.readiness().clone(),
                        policy.fail_summary(),
                    );
                    if self.administrator {
                        policy2 = policy2
                            .with_elevation(tornect_core::levels::Elevation::Admin)
                            .with_grant_reach(2);
                    }
                    UnattendedVerdict::Accept {
                        proof: ConsentProof::Unattended {
                            grant,
                            proof_fp,
                            policy: policy2,
                            block,
                            token,
                        },
                        caps,
                    }
                }
                other => other,
            })
        })
    }
}

fn unattended_intent(pw: &str, want_mode: u8, admin: bool) -> Intent {
    Intent::Unattended(client::UnattendedIntent {
        password: Zeroizing::new(pw.to_owned()),
        want_mode,
        want_elevation: if admin {
            tornect_core::levels::Elevation::Admin
        } else {
            tornect_core::levels::Elevation::None
        },
    })
}

/// A host where every program runs as administrator: the level needs no helper, so an
/// administrator accept is what the policy says.
fn always_administrator() -> Availability {
    Availability::of(Some(&WindowsFacts {
        installed: true,
        administrator: true,
        enable_lua: Some(0),
        ..WindowsFacts::default()
    }))
}

/// M-FEAT-2 F-8: an unattended accept above the client's own request — control for a
/// view-only request, the administrator level unasked — is a protocol violation: the
/// client closes with `E_BAD_STATE` and records nothing (no `server_s_pk` pin).
#[tokio::test]
async fn an_unattended_accept_above_the_request_is_a_violation() {
    const PW: &str = "quiet verdant otter lantern zephyr";
    for (want_mode, admin_asked, given, admin_given) in [
        (
            messages::mode::VIEW_ONLY,
            false,
            SessionMode::Control,
            false,
        ),
        (messages::mode::CONTROL, false, SessionMode::Control, true),
        (messages::mode::VIEW_ONLY, true, SessionMode::Control, false),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (mut host, client) = unattended_pair(tmp.path(), PW);
        host.cfg.levels = always_administrator();
        host.deps.unattended = Arc::new(Inflated {
            inner: host.deps.unattended.clone(),
            mode: given,
            administrator: admin_given,
        });
        let pins = Arc::new(RecordingPin::default());
        let mut deps = client.deps.clone();
        deps.server_key_pin = pins.clone();
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let err = connect(
            b,
            &client.cfg,
            &client.identity,
            &deps,
            unattended_intent(PW, want_mode, admin_asked),
        )
        .await
        .expect_err("an accept above the request");
        assert_eq!(
            err.violation_code(),
            Some(codes::E_BAD_STATE),
            "{want_mode} {admin_asked}: {err}"
        );
        assert!(
            matches!(err, HandshakeError::AnswerRefused { .. }),
            "{want_mode} {admin_asked}: {err}"
        );
        assert_eq!(pins.recorded.load(Ordering::SeqCst), 0, "nothing pinned");
        let _ = task.await;
    }
}

/// A relay between a client and a host that hands every frame of `kind` the host sends to
/// `tamper` on its way to the client: a frame changed after it was signed.
fn tamper_relay(
    client: DuplexStream,
    host: DuplexStream,
    kind: Kind,
    tamper: impl Fn(&mut Envelope) + Send + Sync + 'static,
) -> tokio::task::JoinHandle<()> {
    use crate::framing::{MAX_FRAME_LEN, read_frame_max};
    tokio::spawn(async move {
        let (mut client_rx, mut client_tx) = tokio::io::split(client);
        let (mut host_rx, mut host_tx) = tokio::io::split(host);
        let up = async {
            while let Ok(Some(frame)) = read_frame_max(&mut client_rx, MAX_FRAME_LEN).await {
                if write_frame(&mut host_tx, &frame).await.is_err() {
                    break;
                }
            }
            let _ = host_tx.shutdown().await;
        };
        let down = async {
            while let Ok(Some(frame)) = read_frame_max(&mut host_rx, MAX_FRAME_LEN).await {
                let frame = match Envelope::decode(&frame) {
                    Ok(mut env) if env.kind == kind => {
                        tamper(&mut env);
                        env.encode()
                    }
                    _ => frame,
                };
                if write_frame(&mut client_tx, &frame).await.is_err() {
                    break;
                }
            }
            let _ = client_tx.shutdown().await;
        };
        tokio::join!(up, down);
    })
}

/// One bit of the signature flipped.
fn flip_sig(env: &mut Envelope) {
    if let Some(sig) = env.sig.as_mut() {
        sig[0] ^= 1;
    }
}

/// A body that does not decode.
fn garbage_body(env: &mut Envelope) {
    env.body = vec![0xff];
}

/// M1-67 C4: only the checks of the host's `SESSION_ACCEPT` and `ADMIN_RESULT` raise
/// `AnswerRefused`, after the same `ERROR{code}` a violation sends; a refused `HELLO_ACK`
/// or `AUTH_CHALLENGE` stays a `Violation`. Each frame is changed on its way, after the
/// real host signed it.
#[tokio::test]
async fn only_the_answers_checks_raise_answer_refused() {
    /// The frame's kind, the change, an admin command, whether the answer is refused,
    /// the `ERROR` code.
    type Case = (Kind, fn(&mut Envelope), bool, bool, u16);
    const PW: &str = "quiet verdant otter lantern zephyr";
    let cases: [Case; 6] = [
        (Kind::HelloAck, flip_sig, false, false, codes::E_BAD_SIG),
        (
            Kind::AuthChallenge,
            garbage_body,
            false,
            false,
            codes::E_BAD_LEN,
        ),
        (Kind::SessionAccept, flip_sig, false, true, codes::E_BAD_SIG),
        (
            Kind::SessionAccept,
            garbage_body,
            false,
            true,
            codes::E_BAD_LEN,
        ),
        (Kind::AdminResult, flip_sig, true, true, codes::E_BAD_SIG),
        (
            Kind::AdminResult,
            garbage_body,
            true,
            true,
            codes::E_BAD_LEN,
        ),
    ];
    for (kind, tamper, admin, answer, code) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let (host, client) = unattended_pair(tmp.path(), PW);
        let (client_end, relay_client) = pipe();
        let (relay_host, host_end) = pipe();
        let task = spawn_host(host_end, &host);
        let relay = tamper_relay(relay_client, relay_host, kind, tamper);
        let err = if admin {
            client::admin(
                client_end,
                &client.cfg,
                &client.identity,
                &client.deps,
                &client::AdminIntent {
                    password: Zeroizing::new(PW.to_owned()),
                    op: messages::admin_op::END_SESSION,
                    device_pk: None,
                },
            )
            .await
            .expect_err("a changed answer")
        } else {
            connect(
                client_end,
                &client.cfg,
                &client.identity,
                &client.deps,
                unattended_intent(PW, messages::mode::CONTROL, false),
            )
            .await
            .expect_err("a changed frame")
        };
        assert_eq!(err.violation_code(), Some(code), "{kind:?}: {err}");
        assert_eq!(
            matches!(err, HandshakeError::AnswerRefused { .. }),
            answer,
            "{kind:?}: {err}"
        );
        let _ = task.await;
        let _ = relay.await;
    }
}

/// M-FEAT-2 F-8, the other direction: asked for the administrator level, signed none (the
/// host clamps to what the grant gives): the session goes on at the signed level and says
/// that the level was withheld; asked for none, nothing is withheld.
#[tokio::test]
async fn an_unattended_accept_below_the_requested_level_goes_on_at_the_signed_level() {
    const PW: &str = "quiet verdant otter lantern zephyr";
    for admin_asked in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let (host, client) = unattended_pair(tmp.path(), PW);
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let outcome = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            unattended_intent(PW, messages::mode::CONTROL, admin_asked),
        )
        .await
        .expect("an accept at or below the request");
        let ClientOutcome::Session(session) = outcome else {
            panic!("no session");
        };
        assert!(session.unattended());
        assert_eq!(
            session.accept().elevation(),
            tornect_core::levels::Elevation::None
        );
        assert_eq!(session.elevation_withheld(), admin_asked);
        drop(session);
        let _ = task.await;
    }
}

/// A wrong password ends before any proof leaves this side (`PasswordRefused`, the
/// host told `CLIENT_AUTH_ABORT`), and the FSM tries it once: one charge at the host.
#[tokio::test]
async fn a_wrong_password_is_refused_once_before_any_proof() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, client) = unattended_pair(tmp.path(), "quiet verdant otter lantern zephyr");
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        unattended_intent("not the password at all", messages::mode::CONTROL, false),
    )
    .await
    .expect_err("a wrong password");
    assert!(matches!(err, HandshakeError::PasswordRefused), "{err}");
    let host_end = task.await.unwrap();
    assert!(host_end.is_err(), "the host saw the abort: {host_end:?}");
}

/// A changed `server_s_pk` (the host's unattended setup created again) ends before the
/// proof, as its own error: the window blocks until the person confirms.
#[tokio::test]
async fn a_changed_opaque_key_is_its_own_error() {
    const PW: &str = "quiet verdant otter lantern zephyr";
    let tmp = tempfile::tempdir().unwrap();
    let (host, client) = unattended_pair(tmp.path(), PW);
    let mut deps = client.deps.clone();
    deps.server_key_pin = Arc::new(MismatchPin);
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &deps,
        unattended_intent(PW, messages::mode::CONTROL, false),
    )
    .await
    .expect_err("a pin mismatch");
    assert!(matches!(err, HandshakeError::ServerKeyChanged), "{err}");
    let _ = task.await;
}

/// `client::admin`: one command on the grant's two factors, answered by a signed
/// `ADMIN_RESULT`; revoking itself is in every grant's scope, and afterwards the
/// device is refused before any password exchange. An unknown host gets nothing.
#[tokio::test]
async fn an_admin_command_gets_the_hosts_signed_answer() {
    const PW: &str = "quiet verdant otter lantern zephyr";
    let tmp = tempfile::tempdir().unwrap();
    let (host, client) = unattended_pair(tmp.path(), PW);
    let command = |op, device_pk| client::AdminIntent {
        password: Zeroizing::new(PW.to_owned()),
        op,
        device_pk,
    };
    // Nothing live to end, and no grant of that device to unlock: answered.
    for (op, device_pk) in [
        (messages::admin_op::END_SESSION, None),
        (messages::admin_op::UNLOCK, Some([0x5A; 32])),
    ] {
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        client::admin(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            &command(op, device_pk),
        )
        .await
        .expect("an admin answer");
        let _ = task.await;
    }
    // Revoking itself is in every grant's scope.
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let own = *client.identity.id().public_key_bytes();
    let answer = client::admin(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        &command(messages::admin_op::REVOKE, Some(own)),
    )
    .await
    .expect("an admin answer");
    assert!(answer.ok, "{answer:?}");
    let _ = task.await;
    // Revoked: the next request is refused before any password exchange.
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        unattended_intent(PW, messages::mode::CONTROL, false),
    )
    .await
    .expect_err("revoked");
    assert!(
        matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::NOT_GRANTED),
        "{err}"
    );
    let _ = task.await;
    // A host this device never paired with is sent nothing.
    let stranger = client_side(&tmp.path().join("other"), host.identity.id(), [0x33; 32]);
    let (_a, b) = pipe();
    let err = client::admin(
        b,
        &stranger.cfg,
        &stranger.identity,
        &stranger.deps,
        &command(messages::admin_op::END_SESSION, None),
    )
    .await
    .expect_err("not paired");
    assert!(matches!(err, HandshakeError::Aborted(_)), "{err}");
}

/// The accept's body as the relay changes it: decoded, `change`d, encoded again; the
/// signature stays the host's, over the body it signed.
fn rewrite_accept(env: &mut Envelope, change: impl FnOnce(&mut messages::SessionAccept)) {
    let mut accept: messages::SessionAccept =
        decode_body(&env.body).expect("the host's accept decodes");
    change(&mut accept);
    env.body = encode_body(&accept);
}

/// M1-67 A23 on the real FSMs: an unattended accept changed after the host signed it.
/// With `elevation = 1`, `grant_reach` absent (the key stripped), 0 or 1 is `E_BAD_LEN`,
/// and so is a value of 3: the client decodes and validates before it verifies. On an
/// accept without `elevation`, which this host signs at 0, the key stripped or flipped to
/// 1 is `E_BAD_SIG`. Each is a refused answer (the remembered password goes, not stale),
/// and nothing is pinned.
#[tokio::test]
async fn a23_an_accept_changed_after_signing_is_refused() {
    const PW: &str = "quiet verdant otter lantern zephyr";
    let cases: [(Option<u8>, Option<u8>, u16); 6] = [
        (Some(1), None, codes::E_BAD_LEN),
        (Some(1), Some(0), codes::E_BAD_LEN),
        (Some(1), Some(1), codes::E_BAD_LEN),
        (None, Some(3), codes::E_BAD_LEN),
        (None, None, codes::E_BAD_SIG),
        (None, Some(1), codes::E_BAD_SIG),
    ];
    for (elevation, grant_reach, code) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let (host, client) = unattended_pair(tmp.path(), PW);
        let pins = Arc::new(RecordingPin::default());
        let mut deps = client.deps.clone();
        deps.server_key_pin = pins.clone();
        let (client_end, relay_client) = pipe();
        let (relay_host, host_end) = pipe();
        let task = spawn_host(host_end, &host);
        let relay = tamper_relay(relay_client, relay_host, Kind::SessionAccept, move |env| {
            rewrite_accept(env, |a| {
                a.elevation = elevation;
                a.grant_reach = grant_reach;
            });
        });
        let admin_asked = elevation.is_some();
        let err = connect(
            client_end,
            &client.cfg,
            &client.identity,
            &deps,
            unattended_intent(PW, messages::mode::CONTROL, admin_asked),
        )
        .await
        .expect_err("a changed accept");
        let case = format!("{elevation:?} {grant_reach:?}");
        assert_eq!(err.violation_code(), Some(code), "{case}: {err}");
        assert!(
            matches!(err, HandshakeError::AnswerRefused { .. }),
            "{case}: {err}"
        );
        assert_eq!(pins.recorded.load(Ordering::SeqCst), 0, "{case}");
        let _ = task.await;
        let _ = relay.await;
    }
}

/// M1-67 A23: `grant_reach` on an attended accept is `E_BAD_LEN`, before the signature.
#[tokio::test]
async fn a23_grant_reach_on_an_attended_accept_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let real = HostIdentity::from_seed(&HOST_SEED);
    let real_pk = HostSigner::public_key(&real);
    let client = client_side(tmp.path(), real.id(), CLIENT_SEED);
    client
        .known
        .pin(real.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    let (a, b) = pipe();
    let signer = HostIdentity::from_seed(&HOST_SEED);
    let relay = tokio::spawn(async move {
        let mut h = RawHost::new(a, &real_pk);
        h.take_hello().await;
        h.ack(&signer).await;
        h.take(Kind::SessionRequest).await;
        let accept = accept_with(|a| a.grant_reach = Some(0));
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
    assert_eq!(err.violation_code(), Some(codes::E_BAD_LEN), "{err}");
    let seen = relay.await.unwrap().unwrap().unwrap();
    assert_eq!(seen.env.kind, Kind::Error);
}

/// One admin command of [`ClientSide`] against `host`, answered.
async fn admin_answer(
    host: &HostSide,
    client: &ClientSide,
    pw: &str,
    op: u8,
) -> client::AdminAnswer {
    let (a, b) = pipe();
    let task = spawn_host(a, host);
    let answer = client::admin(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        &client::AdminIntent {
            password: Zeroizing::new(pw.to_owned()),
            op,
            device_pk: None,
        },
    )
    .await
    .expect("an admin answer");
    let _ = task.await;
    answer
}

/// M1-67, the release coupling (B, D1, D8.3), the `ADMIN_RESULT` half: every
/// `ADMIN_RESULT` the real gate and guard sign carries the requester's `grant_reach`,
/// read under the lock of the command: a command run and one the guard refuses out of
/// the grant's scope, at 0 on Linux, 1 where clause (ii) holds, 2 for an unmarked grant
/// at the level. The two early refusals cannot be reached from the wire (the decoder
/// refuses such a command first): the gate's own test covers them.
/// (`no_unattended_answer_carries_grant_reach_yet`'s `ADMIN_RESULT` half, rewritten here.)
#[tokio::test]
async fn release_coupling_every_admin_result_carries_grant_reach() {
    use tornect_core::levels::{FixedFacts, HelperPresence};
    const PW: &str = "quiet verdant otter lantern zephyr";
    for (case, facts, at_the_level, reach) in [
        ("Linux", FixedFacts::linux(), false, 0),
        (
            "the helper task registered",
            FixedFacts::new(windows_facts(|_| {}), HelperPresence::Registered),
            false,
            1,
        ),
        (
            "an unmarked grant at the level",
            FixedFacts::new(windows_facts(|_| {}), HelperPresence::Absent),
            true,
            2,
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (host, client, _guard) = unattended_pair_edited(tmp.path(), PW, Arc::new(facts), |g| {
            if at_the_level {
                g.elevation = tornect_core::levels::Elevation::Admin;
                g.unmarked = true;
            }
        });
        // a command run, then one out of a Headless box grant's scope
        let ran = admin_answer(&host, &client, PW, messages::admin_op::END_SESSION).await;
        assert!(ran.ok, "{case}");
        assert_eq!(ran.grant_reach, Some(reach), "{case}: run");
        let refused = admin_answer(&host, &client, PW, messages::admin_op::MASTER_OFF).await;
        assert!(!refused.ok, "{case}");
        assert_eq!(refused.grant_reach, Some(reach), "{case}: refused");
    }
}

/// Windows facts of an administrator account, with `change` applied.
fn windows_facts(change: impl FnOnce(&mut WindowsFacts)) -> tornect_core::levels::AccountFacts {
    let mut facts = WindowsFacts {
        installed: true,
        administrator: true,
        ..WindowsFacts::default()
    };
    change(&mut facts);
    tornect_core::levels::AccountFacts::Windows(facts)
}

/// The mode the real gate signs for a control request (and the level, when asked) on a
/// host whose facts and helper task `facts` gives.
async fn served(
    facts: Arc<dyn tornect_core::levels::FactsSource>,
    admin_asked: bool,
) -> (u8, tornect_core::levels::Elevation) {
    const PW: &str = "quiet verdant otter lantern zephyr";
    let tmp = tempfile::tempdir().unwrap();
    let (host, client) = unattended_pair_with(tmp.path(), PW, facts);
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let outcome = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        unattended_intent(PW, messages::mode::CONTROL, admin_asked),
    )
    .await
    .expect("an accept");
    let ClientOutcome::Session(session) = outcome else {
        panic!("no session");
    };
    let signed = (session.accept().mode(), session.accept().elevation());
    drop(session);
    let _ = task.await;
    signed
}

/// M1-67 A21 (c)-(h), the served mode: a control grant asking for control is served view
/// only (F-12, and the marked rule where clause (ii) holds, every password marked so far)
/// where UAC is off (installed or standalone), `ConsentPromptBehaviorAdmin` is 0 (installed
/// or standalone, also set after the host started, before the answer), the facts could not
/// be read, or the helper task is registered or cannot be queried; control otherwise, and
/// always on Linux.
#[tokio::test]
async fn a21_view_only_cases_are_served_view_only() {
    use tornect_core::levels::{AccountFacts, FixedFacts, HelperPresence};
    let absent = HelperPresence::Absent;
    let view = [
        (
            "(c) UAC off, installed",
            windows_facts(|f| f.enable_lua = Some(0)),
            absent,
        ),
        (
            "(d) UAC off, standalone",
            windows_facts(|f| {
                f.enable_lua = Some(0);
                f.installed = false;
            }),
            absent,
        ),
        (
            "(e) CPBA 0, installed",
            windows_facts(|f| f.consent_prompt_behavior_admin = Some(0)),
            absent,
        ),
        (
            "(f) CPBA 0, standalone",
            windows_facts(|f| {
                f.consent_prompt_behavior_admin = Some(0);
                f.installed = false;
            }),
            absent,
        ),
        ("(h) unreadable", AccountFacts::Unreadable, absent),
        (
            "(b) helper task registered",
            windows_facts(|_| {}),
            HelperPresence::Registered,
        ),
        (
            "(b) helper task unreadable",
            windows_facts(|_| {}),
            HelperPresence::Unreadable,
        ),
    ];
    for (case, account, helper) in view {
        let (mode, _) = served(Arc::new(FixedFacts::new(account, helper)), false).await;
        assert_eq!(mode, messages::mode::VIEW_ONLY, "{case}");
    }
    for (case, account) in [
        ("an administrator account, UAC on", windows_facts(|_| {})),
        (
            "a standard account, CPBA 0",
            windows_facts(|f| {
                f.administrator = false;
                f.consent_prompt_behavior_admin = Some(0);
            }),
        ),
        ("Linux", AccountFacts::Linux),
    ] {
        let (mode, _) = served(Arc::new(FixedFacts::new(account, absent)), false).await;
        assert_eq!(mode, messages::mode::CONTROL, "{case}");
    }
    // (g) set after the host started, before an answer: the next answer reads it.
    let facts = Arc::new(FixedFacts::new(windows_facts(|_| {}), absent));
    const PW: &str = "quiet verdant otter lantern zephyr";
    let tmp = tempfile::tempdir().unwrap();
    let (host, client) = unattended_pair_with(tmp.path(), PW, facts.clone());
    for (cpba, expected) in [
        (None, messages::mode::CONTROL),
        (Some(0), messages::mode::VIEW_ONLY),
    ] {
        facts.set_account(windows_facts(|f| f.consent_prompt_behavior_admin = cpba));
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let outcome = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            unattended_intent(PW, messages::mode::CONTROL, false),
        )
        .await
        .expect("an accept");
        let ClientOutcome::Session(session) = outcome else {
            panic!("no session");
        };
        assert_eq!(session.accept().mode(), expected, "(g) {cpba:?}");
        drop(session);
        let _ = task.await;
    }
}

/// M1-67 A25 (n), the served mode: a request served view only by F-12 is answered view
/// only and at no level, also when it asks for the level.
#[tokio::test]
async fn a25_n_view_only_by_f12_is_served_view_only() {
    use tornect_core::levels::{FixedFacts, HelperPresence};
    let cpba_0 = windows_facts(|f| f.consent_prompt_behavior_admin = Some(0));
    let (mode, elevation) = served(
        Arc::new(FixedFacts::new(cpba_0, HelperPresence::Absent)),
        true,
    )
    .await;
    assert_eq!(mode, messages::mode::VIEW_ONLY);
    assert_eq!(elevation, tornect_core::levels::Elevation::None);
}

/// A facts source whose account turns to `later` after its first read: a setting
/// changed between the gate and the session's reservation.
struct ChangesAfterFirstRead {
    reads: std::sync::atomic::AtomicUsize,
    first: tornect_core::levels::AccountFacts,
    later: tornect_core::levels::AccountFacts,
}

impl tornect_core::levels::FactsSource for ChangesAfterFirstRead {
    fn account(&self) -> tornect_core::levels::AccountFacts {
        if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first
        } else {
            self.later
        }
    }

    fn helper_task(&self) -> tornect_core::levels::HelperPresence {
        tornect_core::levels::HelperPresence::Absent
    }
}

/// M1-67 A21 (g), its first half: `ConsentPromptBehaviorAdmin` set to 0 after the
/// gate read the facts and before the answer: the read after the reservation lowers
/// the session to view only.
#[tokio::test]
async fn a21_g_cpba_set_after_start_lowers_the_next_answer() {
    const PW: &str = "quiet verdant otter lantern zephyr";
    let facts = Arc::new(ChangesAfterFirstRead {
        reads: std::sync::atomic::AtomicUsize::new(0),
        first: windows_facts(|_| {}),
        later: windows_facts(|f| f.consent_prompt_behavior_admin = Some(0)),
    });
    let tmp = tempfile::tempdir().unwrap();
    let (host, client) = unattended_pair_with(tmp.path(), PW, facts.clone());
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let outcome = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        unattended_intent(PW, messages::mode::CONTROL, false),
    )
    .await
    .expect("an accept");
    let ClientOutcome::Session(session) = outcome else {
        panic!("no session");
    };
    assert_eq!(session.accept().mode(), messages::mode::VIEW_ONLY);
    assert_eq!(
        facts.reads.load(Ordering::SeqCst),
        2,
        "the gate's read, then this one"
    );
    drop(session);
    let _ = task.await;
}

/// The hook of an [`AdminGrant`] request, with the read after the reservation
/// played by `then`.
struct AfterReservation<F> {
    then: F,
}

impl<F> UnattendedHook for AfterReservation<F>
where
    F: Fn(ConsentProof) -> ConsentProof + Send + Sync,
{
    fn handle<'a>(
        &'a self,
        ctx: UnattendedContext<'a>,
    ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
        Box::pin(async move { AdminGrant.handle(ctx).await })
    }

    fn reserved<'a>(
        &'a self,
        _: &'a DeviceId,
        proof: ConsentProof,
    ) -> BoxFuture<'a, Result<ConsentProof, messages::SessionReject>> {
        let proof = (self.then)(proof);
        Box::pin(async move { Ok(proof) })
    }
}

/// M1-67 (K18): a session lowered by the read after the reservation goes on at the
/// lowered level, and the helper started for the level it lost ends, never attached.
#[tokio::test]
async fn a_lowered_answer_drops_the_started_helper() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    host.deps.unattended = Arc::new(AfterReservation {
        then: |proof| match proof {
            ConsentProof::Unattended {
                grant,
                proof_fp,
                policy,
                block,
                token,
            } => ConsentProof::Unattended {
                grant,
                proof_fp,
                policy: policy.lowered_to(SessionMode::ViewOnly),
                block,
                token,
            },
            other => other,
        },
    });
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    host.cfg.levels = installed_row();
    let helper = Arc::new(FakeHelper::default());
    *helper.script.lock().unwrap() = vec![HelperScript::Ready];
    host.deps.admin_helper = helper.clone();
    assert_eq!(
        unattended_admin_session(&host).await,
        tornect_core::levels::Elevation::None
    );
    assert_eq!(helper.started.load(Ordering::SeqCst), 1);
    assert!(helper.attached.lock().unwrap().is_empty(), "never attached");
    assert_eq!(helper.ended.load(Ordering::SeqCst), 1, "ended");
}

/// M1-67 (DA-17): the hook after the reservation runs with the live-session lock
/// free: it could take it.
#[tokio::test]
async fn the_reservation_hook_runs_outside_the_session_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let live = Arc::new(LiveSessions::new());
    let free = Arc::new(Mutex::new(None));
    host.deps.activity = live.clone();
    let (seen_live, seen_free) = (live.clone(), free.clone());
    host.deps.unattended = Arc::new(AfterReservation {
        then: move |proof| {
            *seen_free.lock().unwrap() = Some(seen_live.lock_is_free());
            proof
        },
    });
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    host.cfg.levels = installed_row();
    let helper = Arc::new(FakeHelper::default());
    *helper.script.lock().unwrap() = vec![HelperScript::Ready];
    host.deps.admin_helper = helper;
    let _ = unattended_admin_session(&host).await;
    assert_eq!(
        *free.lock().unwrap(),
        Some(true),
        "the hook ran, the lock free"
    );
}

/// M1-67 (FC-1): a panic pressed while the hook after the reservation reads is
/// refused as the Block it stands for, before any accept: the panic check runs again
/// after the hook, "checked last"; the reservation is let go and the helper ends.
#[tokio::test]
async fn a_panic_during_the_reservation_hook_rejects_the_request() {
    let tmp = tempfile::tempdir().unwrap();
    let mut host = host_side(tmp.path(), HOST_SEED);
    let kill = KillSwitch::new();
    host.deps.kill = kill.clone();
    let live = Arc::new(LiveSessions::new());
    host.deps.activity = live.clone();
    host.deps.unattended = Arc::new(AfterReservation {
        then: move |proof| {
            kill.kill(bye::PANIC);
            proof
        },
    });
    host.trusted
        .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
        .unwrap();
    host.cfg.levels = installed_row();
    let helper = Arc::new(FakeHelper::default());
    *helper.script.lock().unwrap() = vec![HelperScript::Ready];
    host.deps.admin_helper = helper.clone();
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let mut raw = raw_unattended_request(&host, CLIENT_SEED, b).await;
    let rx = raw
        .chan
        .recv(Duration::from_secs(30), "answer")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rx.env.kind, Kind::SessionReject);
    match task.await.unwrap().unwrap() {
        HostOutcome::SessionRejected { reason, .. } => {
            assert_eq!(reason, reject::BLOCKED_BY_LOCAL_USER);
        }
        other => panic!("{other:?}"),
    }
    assert!(
        !SessionActivity::session_live(&*live),
        "the reservation went"
    );
    assert!(helper.attached.lock().unwrap().is_empty());
    assert_eq!(helper.ended.load(Ordering::SeqCst), 1);
}

/// A facts source whose helper task turns registered after its first read: the task
/// registered between the gate and the session's reservation.
struct HelperRegisteredAfterFirstRead {
    reads: std::sync::atomic::AtomicUsize,
}

impl tornect_core::levels::FactsSource for HelperRegisteredAfterFirstRead {
    fn account(&self) -> tornect_core::levels::AccountFacts {
        windows_facts(|_| {})
    }

    fn helper_task(&self) -> tornect_core::levels::HelperPresence {
        if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
            tornect_core::levels::HelperPresence::Absent
        } else {
            tornect_core::levels::HelperPresence::Registered
        }
    }
}

/// M1-67 A21 (g)'s twin for the helper task (S5A-1): the task registered after the gate
/// read its presence and before the answer. The gate mints control (an administrator
/// account with UAC on, no task); the read after the reservation finds the task, so
/// clause (ii) holds for the marked password and the session is view only: the hook's
/// marked rule alone lowers it.
#[tokio::test]
async fn a21_g_the_helper_task_registered_after_start_lowers_the_next_answer() {
    const PW: &str = "quiet verdant otter lantern zephyr";
    let facts = Arc::new(HelperRegisteredAfterFirstRead {
        reads: std::sync::atomic::AtomicUsize::new(0),
    });
    let tmp = tempfile::tempdir().unwrap();
    let (host, client) = unattended_pair_with(tmp.path(), PW, facts.clone());
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let outcome = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        unattended_intent(PW, messages::mode::CONTROL, false),
    )
    .await
    .expect("an accept");
    let ClientOutcome::Session(session) = outcome else {
        panic!("no session");
    };
    assert_eq!(session.accept().mode(), messages::mode::VIEW_ONLY);
    assert_eq!(
        facts.reads.load(Ordering::SeqCst),
        2,
        "the gate's read, then this one"
    );
    drop(session);
    let _ = task.await;
}

/// The receipt of a hook's proof at `level`.
fn receipt_at(level: (SessionMode, tornect_core::levels::Elevation)) -> PolicyReceipt {
    PolicyReceipt::mint(
        [9u8; 8],
        level.0,
        TransportPolicy::Any,
        None,
        0,
        false,
        ReadinessSnapshot::default(),
        None,
    )
    .with_elevation(level.1)
}

/// A hook that mints `minted` at the gate and gives back a proof at `back` after the
/// reservation.
struct ReservedGivesBack {
    minted: (SessionMode, tornect_core::levels::Elevation),
    back: (SessionMode, tornect_core::levels::Elevation),
}

impl UnattendedHook for ReservedGivesBack {
    fn handle<'a>(
        &'a self,
        ctx: UnattendedContext<'a>,
    ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
        Box::pin(async move {
            Ok(UnattendedVerdict::Accept {
                proof: ConsentProof::Unattended {
                    grant: [9u8; 8],
                    proof_fp: [0u8; 8],
                    policy: receipt_at(self.minted),
                    block: WindowPassed::Skipped,
                    token: DerivedToken::new([0xA5; 32], [0x5A; 32]),
                },
                caps: ChosenCaps::negotiate(&Caps::default(), &ctx.request.caps),
            })
        })
    }

    fn reserved<'a>(
        &'a self,
        _: &'a DeviceId,
        proof: ConsentProof,
    ) -> BoxFuture<'a, Result<ConsentProof, messages::SessionReject>> {
        Box::pin(async move {
            Ok(match proof {
                ConsentProof::Unattended {
                    grant,
                    proof_fp,
                    block,
                    token,
                    ..
                } => ConsentProof::Unattended {
                    grant,
                    proof_fp,
                    policy: receipt_at(self.back),
                    block,
                    token,
                },
                other => other,
            })
        })
    }
}

/// M1-67 (S5A-2): the read after the reservation only lowers, and the state machine
/// holds it to that: a proof given back above the one the gate minted, in mode or in
/// level, is refused `NOT_GRANTED` and never signed; the reservation goes and no helper
/// attaches.
#[tokio::test]
async fn a_proof_raised_after_the_reservation_is_refused() {
    use tornect_core::levels::Elevation;
    for (minted, back) in [
        (
            (SessionMode::ViewOnly, Elevation::None),
            (SessionMode::Control, Elevation::None),
        ),
        (
            (SessionMode::Control, Elevation::None),
            (SessionMode::Control, Elevation::Admin),
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let mut host = host_side(tmp.path(), HOST_SEED);
        let live = Arc::new(LiveSessions::new());
        host.deps.activity = live.clone();
        host.deps.unattended = Arc::new(ReservedGivesBack { minted, back });
        host.trusted
            .pin(DeviceIdentity::from_seed(&CLIENT_SEED).id(), "Paired")
            .unwrap();
        host.cfg.levels = installed_row();
        let helper = Arc::new(FakeHelper::default());
        *helper.script.lock().unwrap() = vec![HelperScript::Ready];
        host.deps.admin_helper = helper.clone();
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let mut raw = raw_unattended_request(&host, CLIENT_SEED, b).await;
        let rx = raw
            .chan
            .recv(Duration::from_secs(30), "answer")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rx.env.kind, Kind::SessionReject, "{minted:?} -> {back:?}");
        match task.await.unwrap().unwrap() {
            HostOutcome::SessionRejected { reason, .. } => {
                assert_eq!(reason, reject::NOT_GRANTED, "{minted:?} -> {back:?}");
            }
            other => panic!("{minted:?} -> {back:?}: {other:?}"),
        }
        assert!(
            !SessionActivity::session_live(&*live),
            "the reservation went"
        );
        assert!(helper.attached.lock().unwrap().is_empty());
    }
}

/// Change `device`'s grant as stored in `paths`' store, keeping its generation (so the
/// anchor still matches): the level or the mark, which no guard path of this build sets
/// yet. Only while no `GrantStore` holds the store.
fn edit_grant_on_disk(
    paths: &tornect_core::paths::Paths,
    device: &DeviceId,
    edit: impl FnOnce(&mut tornect_core::unattended::grant::UnattendedGrant),
) {
    use tornect_core::keystore::{FileSecretStore, SecretStore as _};
    use tornect_core::unattended::codec::{self, MASTER_KEY_ENTRY, MasterKey};
    let secrets = FileSecretStore::open(paths.keys_dir()).unwrap();
    let master = MasterKey::parse(&secrets.get(MASTER_KEY_ENTRY).unwrap().unwrap()).unwrap();
    let bytes = std::fs::read(paths.unattended_store()).unwrap();
    let (generation, mut store) = codec::open(&master.k_unatt(), &bytes).unwrap();
    edit(store.grant_mut(device).unwrap());
    let sealed = codec::seal(&master.k_unatt(), generation, &store).unwrap();
    std::fs::write(paths.unattended_store(), sealed).unwrap();
}

/// [`unattended_pair_with`] whose grant `edit` changes as stored first, and the host's
/// guard (the window's and the command line's single enforcement point).
fn unattended_pair_edited(
    tmp: &std::path::Path,
    pw: &str,
    facts: Arc<dyn tornect_core::levels::FactsSource>,
    edit: impl FnOnce(&mut tornect_core::unattended::grant::UnattendedGrant),
) -> (
    HostSide,
    ClientSide,
    Arc<tornect_core::unattended::guard::MutationGuard>,
) {
    use tornect_core::keystore::FileSecretStore;
    use tornect_core::paths::Paths;
    use tornect_core::session_log::Actor;
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
    use crate::unattended::{GuardAdmin, OpaqueServerSetupSource, UnattendedAuth};

    let mut host = host_side(tmp, HOST_SEED);
    let client = client_side(tmp, host.identity.id(), CLIENT_SEED);
    let device = client.identity.id();
    let host_onion_pk = *host.identity.id().public_key_bytes();
    host.trusted.pin(device, "Laptop of Ana").unwrap();
    client
        .known
        .pin(host.identity.id(), "Desk of Bob", host_device_pk())
        .unwrap();
    let paths = Paths::from_home(tmp.join("host-home"));
    std::fs::create_dir_all(paths.keys_dir()).unwrap();
    let open = |facts: Arc<dyn tornect_core::levels::FactsSource>| {
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        let store = GrantStore::open(
            &paths,
            secrets,
            Arc::new(SystemClock::default()),
            SessionLog::new(paths.sessions_log()),
        )
        .unwrap();
        MutationGuard::new(
            store,
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            facts,
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(OpaqueServerSetupSource))
    };
    // Set up as the command line would on a host where nothing reaches the level; the
    // host itself, and its guard, then run on `facts`.
    let guard = open(Arc::new(tornect_core::levels::FixedFacts::linux()));
    guard.master_on(Actor::Cli, &host_onion_pk).unwrap();
    guard
        .create_grant(
            Actor::Cli,
            &device,
            Preset::HeadlessBox,
            &GrantOptions::default(),
            &[0u8; 192],
            false,
        )
        .unwrap();
    let setup = auth::parse_server_setup(&guard.store().server_setup().unwrap()).unwrap();
    let record = auth::register_locally(
        &setup,
        pw,
        device.public_key_bytes(),
        auth::identifiers(device.public_key_bytes(), &host_onion_pk),
    )
    .unwrap();
    guard
        .set_password(
            Actor::Cli,
            &device,
            &record,
            &GrantOptions::default(),
            false,
        )
        .unwrap();
    drop(guard);
    edit_grant_on_disk(&paths, &device, edit);
    let guard = Arc::new(open(Arc::clone(&facts)));
    let limiter = AttemptLimiter::new(guard.store().clone());
    host.deps.unattended = Arc::new(
        UnattendedAuth::new(
            limiter,
            Arc::new(FixedOffset::utc()),
            HostTransport::default(),
            facts,
        )
        .with_admin_authority(Arc::new(GuardAdmin::new(Arc::clone(&guard))))
        .with_block_guard(Arc::clone(&guard)),
    );
    (host, client, guard)
}

/// What the accept of one unattended session signed: its mode, its level and its
/// `grant_reach`.
async fn signed(
    host: &HostSide,
    client: &ClientSide,
    intent: Intent,
) -> (u8, tornect_core::levels::Elevation, Option<u8>) {
    let (a, b) = pipe();
    let task = spawn_host(a, host);
    let outcome = connect(b, &client.cfg, &client.identity, &client.deps, intent)
        .await
        .expect("an accept");
    let ClientOutcome::Session(session) = outcome else {
        panic!("no session");
    };
    let accept = session.accept();
    let answer = (accept.mode(), accept.elevation(), accept.grant_reach());
    drop(session);
    let _ = task.await;
    answer
}

/// M1-67, the release coupling (B, D1, D8.3), the accept half: every unattended accept
/// the real gate signs carries `grant_reach` as the read after the reservation computed
/// it, with the mark it implies: 0 on Linux, 1 where clause (ii) holds (the password
/// marked, so view only), 2 for an unmarked grant at the level, which alone is signed the
/// level. The value is never lowered by `want_mode` or `want_elevation`. An attended accept
/// never carries the key. (`no_unattended_answer_carries_grant_reach_yet`'s accept half,
/// rewritten here.)
#[tokio::test]
async fn release_coupling_every_unattended_accept_carries_grant_reach() {
    use tornect_core::levels::{FixedFacts, HelperPresence};
    const PW: &str = "quiet verdant otter lantern zephyr";
    let control = |admin| unattended_intent(PW, messages::mode::CONTROL, admin);
    // Linux: 0, and the grant marked by the answer
    let tmp = tempfile::tempdir().unwrap();
    let (host, client, guard) =
        unattended_pair_edited(tmp.path(), PW, Arc::new(FixedFacts::linux()), |g| {
            g.unmarked = true
        });
    assert_eq!(
        signed(&host, &client, control(false)).await,
        (
            messages::mode::CONTROL,
            tornect_core::levels::Elevation::None,
            Some(0)
        )
    );
    let device = client.identity.id();
    assert!(
        guard.store().grant(&device).unwrap().marked(),
        "answered 0: marked"
    );
    drop((host, client, guard));
    // Windows, the helper task registered: 1, and view only for the marked password
    let tmp = tempfile::tempdir().unwrap();
    let (host, client, _guard) = unattended_pair_edited(
        tmp.path(),
        PW,
        Arc::new(FixedFacts::new(
            windows_facts(|_| {}),
            HelperPresence::Registered,
        )),
        |_| {},
    );
    assert_eq!(
        signed(&host, &client, control(false)).await,
        (
            messages::mode::VIEW_ONLY,
            tornect_core::levels::Elevation::None,
            Some(1)
        )
    );
    // Windows, every program administrator (no helper needed), an unmarked grant at the
    // level: 2, the level signed only when asked, and 2 whatever was asked
    let tmp = tempfile::tempdir().unwrap();
    let (mut host, client, _guard) = unattended_pair_edited(
        tmp.path(),
        PW,
        Arc::new(FixedFacts::new(
            windows_facts(|f| f.enable_lua = Some(0)),
            HelperPresence::Absent,
        )),
        |g| {
            g.elevation = tornect_core::levels::Elevation::Admin;
            g.unmarked = true;
        },
    );
    host.cfg.levels = always_administrator();
    assert_eq!(
        signed(&host, &client, control(true)).await,
        (
            messages::mode::CONTROL,
            tornect_core::levels::Elevation::Admin,
            Some(2)
        )
    );
    // the level not asked: control without the level, view only on these facts (F-12)
    assert_eq!(
        signed(&host, &client, control(false)).await,
        (
            messages::mode::VIEW_ONLY,
            tornect_core::levels::Elevation::None,
            Some(2)
        )
    );
    assert_eq!(
        signed(
            &host,
            &client,
            unattended_intent(PW, messages::mode::VIEW_ONLY, false)
        )
        .await,
        (
            messages::mode::VIEW_ONLY,
            tornect_core::levels::Elevation::None,
            Some(2)
        )
    );
    // an attended accept: no key
    let tmp = tempfile::tempdir().unwrap();
    let host = host_side(tmp.path(), HOST_SEED);
    host.consent
        .push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    host.consent
        .push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let client = client_side(tmp.path(), host.identity.id(), CLIENT_SEED);
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let outcome = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        Intent::Session,
    )
    .await
    .unwrap();
    let ClientOutcome::Session(session) = outcome else {
        panic!("no session");
    };
    assert!(!session.unattended());
    assert_eq!(session.accept().grant_reach(), None);
    drop(session);
    let _ = task.await;
}

/// M1-67 A25 (n), the helper half: no administrator helper starts for a session the
/// gate's receipt already lowers, the level asked: P marked at the level (the clamp's
/// grant level is none) and a request served View only by F-12; the same grant unmarked
/// does start it, attaches it, and is answered 2 at the level.
#[tokio::test]
async fn a25_n_no_helper_starts_for_a_session_the_receipt_lowers() {
    use tornect_core::levels::{FixedFacts, HelperPresence};
    const PW: &str = "quiet verdant otter lantern zephyr";
    for (case, account, holds, unmarked, started) in [
        ("marked at the level", windows_facts(|_| {}), true, false, 0),
        (
            "F-12: CPBA 0, at none",
            windows_facts(|f| f.consent_prompt_behavior_admin = Some(0)),
            false,
            true,
            0,
        ),
        (
            "unmarked at the level",
            windows_facts(|_| {}),
            true,
            true,
            1,
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (mut host, client, _guard) = unattended_pair_edited(
            tmp.path(),
            PW,
            Arc::new(FixedFacts::new(account, HelperPresence::Absent)),
            |g| {
                if holds {
                    g.elevation = tornect_core::levels::Elevation::Admin;
                }
                g.unmarked = unmarked;
            },
        );
        host.cfg.levels = installed_row();
        let helper = Arc::new(FakeHelper::default());
        *helper.script.lock().unwrap() = vec![HelperScript::Ready];
        host.deps.admin_helper = helper.clone();
        let (mode, elevation, reach) = signed(
            &host,
            &client,
            unattended_intent(PW, messages::mode::CONTROL, true),
        )
        .await;
        assert_eq!(helper.started.load(Ordering::SeqCst), started, "{case}");
        if started == 1 {
            assert_eq!(
                (mode, elevation, reach),
                (
                    messages::mode::CONTROL,
                    tornect_core::levels::Elevation::Admin,
                    Some(2)
                ),
                "{case}"
            );
            assert_eq!(helper.attached.lock().unwrap().len(), 1, "{case}");
        } else {
            assert_eq!(elevation, tornect_core::levels::Elevation::None, "{case}");
        }
    }
}

/// The block window, during which the owner gives the grant a new password.
struct NewPasswordDuringTheWindow {
    guard: Arc<tornect_core::unattended::guard::MutationGuard>,
    device: DeviceId,
    record: Vec<u8>,
}

impl crate::consent::BlockWindow for NewPasswordDuringTheWindow {
    fn run<'a>(
        &'a self,
        _: u8,
        _: &'a tornect_core::unattended::grant::GrantId,
        _: &'a str,
    ) -> BoxFuture<'a, BlockOutcome> {
        use tornect_core::unattended::ipc::GrantOptions;
        Box::pin(async move {
            self.guard
                .set_password(
                    tornect_core::session_log::Actor::Ui,
                    &self.device,
                    &self.record,
                    &GrantOptions::default(),
                    // a generated Change password (A25 (h): the new password unmarked)
                    true,
                )
                .unwrap();
            BlockOutcome::Passed(WindowPassed::Elapsed)
        })
    }
}

/// M1-67 A25 (h), and D8.4's second half for a change that does not raise: *Change
/// password* during P's block window, between the PAKE and the reservation. The read after
/// the reservation finds another `auth` record than the one this stream proved:
/// `AUTH_FAILED`, no session, and nothing marked.
#[tokio::test]
async fn a25_h_change_password_in_the_block_window_fails_auth() {
    const PW: &str = "quiet verdant otter lantern zephyr";
    let tmp = tempfile::tempdir().unwrap();
    let (mut host, client, guard) = unattended_pair_edited(
        tmp.path(),
        PW,
        Arc::new(tornect_core::levels::FixedFacts::linux()),
        |g| g.unmarked = true,
    );
    let device = client.identity.id();
    let host_onion_pk = *host.identity.id().public_key_bytes();
    let setup = crate::auth::parse_server_setup(&guard.store().server_setup().unwrap()).unwrap();
    let record = crate::auth::register_locally(
        &setup,
        "another long passphrase entirely",
        device.public_key_bytes(),
        crate::auth::identifiers(device.public_key_bytes(), &host_onion_pk),
    )
    .unwrap();
    host.deps.block_window = Arc::new(NewPasswordDuringTheWindow {
        guard: Arc::clone(&guard),
        device,
        record: record.to_vec(),
    });
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        unattended_intent(PW, messages::mode::CONTROL, false),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::AUTH_FAILED),
        "{err:?}"
    );
    assert!(matches!(
        task.await.unwrap().unwrap(),
        HostOutcome::SessionRejected { .. }
    ));
    assert!(
        !guard.store().grant(&device).unwrap().marked(),
        "nothing marked"
    );
}

/// A block window that counts how often it opened, and lets the session through.
#[derive(Default)]
struct CountingWindow(std::sync::atomic::AtomicUsize);

impl crate::consent::BlockWindow for CountingWindow {
    fn run<'a>(
        &'a self,
        _: u8,
        _: &'a tornect_core::unattended::grant::GrantId,
        _: &'a str,
    ) -> BoxFuture<'a, BlockOutcome> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { BlockOutcome::Passed(WindowPassed::Elapsed) })
    }
}

/// An "Ask before starting" popup that counts how often it was asked, and allows.
#[derive(Default)]
struct CountingAllow(std::sync::atomic::AtomicUsize);

impl crate::consent::LocalAllow for CountingAllow {
    fn ask_at<'a>(
        &'a self,
        _: &'a crate::consent::GrantId,
        _: &'a str,
        _: tornect_core::levels::Elevation,
        _: Duration,
    ) -> BoxFuture<'a, bool> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { true })
    }
}

/// Another session, live while the flag is set.
struct LiveWhile(std::sync::atomic::AtomicBool);

impl SessionActivity for LiveWhile {
    fn session_live(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// §B.8.6.2, §B.8.6.4: while another device's session is live, an unattended request
/// that got through its PAKE opens neither the block window (nor so its notification) nor
/// the "Ask before starting" popup, so the live viewer never sees the requester's label:
/// it is answered `SESSION_ACTIVE`, or `DENIED` with the popup on, and logged as
/// suppressed, as the attended popup is. Once that session is over, the same request
/// opens them as before.
#[tokio::test]
async fn a_live_session_suppresses_the_block_window_and_the_ask() {
    const PW: &str = "quiet verdant otter lantern zephyr";
    for (case, ask, refused) in [
        ("block window", false, reject::SESSION_ACTIVE),
        ("ask before starting", true, reject::DENIED),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (mut host, client, _guard) = unattended_pair_edited(
            tmp.path(),
            PW,
            Arc::new(tornect_core::levels::FixedFacts::linux()),
            |g| g.ask_before_start = ask,
        );
        let window = Arc::new(CountingWindow::default());
        let allow = Arc::new(CountingAllow::default());
        let live = Arc::new(LiveWhile(std::sync::atomic::AtomicBool::new(true)));
        let audit = Arc::new(RecordingAudit::default());
        host.deps.block_window = window.clone();
        host.deps.local_allow = allow.clone();
        host.deps.activity = live.clone();
        host.deps.audit = audit.clone();
        let device = client.identity.id();
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let err = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            unattended_intent(PW, messages::mode::CONTROL, false),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == refused),
            "{case}: {err}"
        );
        assert!(
            matches!(
                task.await.unwrap().unwrap(),
                HostOutcome::SessionRejected { reason, .. } if reason == refused
            ),
            "{case}"
        );
        assert_eq!(
            window.0.load(Ordering::SeqCst),
            0,
            "{case}: no block window"
        );
        assert_eq!(allow.0.load(Ordering::SeqCst), 0, "{case}: no popup");
        let events = audit.0.lock().unwrap().clone();
        assert!(
            events.contains(&AuditEvent::PopupSuppressed {
                device,
                label: Some("Laptop of Ana".into()),
                popup: SuppressedPopup::Session,
            }),
            "{case}"
        );
        assert!(
            events.contains(&AuditEvent::SessionDenied {
                device,
                label: "Laptop of Ana".into(),
                reason: refused,
            }),
            "{case}"
        );
        // that session over, the same request opens them as before
        live.0.store(false, Ordering::SeqCst);
        let (mode, _, _) = signed(
            &host,
            &client,
            unattended_intent(PW, messages::mode::CONTROL, false),
        )
        .await;
        assert_eq!(mode, messages::mode::CONTROL, "{case}");
        assert_eq!(window.0.load(Ordering::SeqCst), 1, "{case}");
        assert_eq!(allow.0.load(Ordering::SeqCst), usize::from(ask), "{case}");
    }
}

/// §B.8.7.2: a password is registered normalized (one space between words, a list word's
/// hyphen read as a space), and the client normalizes the typed one the same way before
/// the PAKE: a generated phrase typed with its list word's hyphen, or with a run of
/// spaces and a tab, logs in.
#[tokio::test]
async fn a_typed_password_is_normalized_before_the_pake() {
    const REGISTERED: &str = "quiet t shirt otter lantern zephyr";
    let tmp = tempfile::tempdir().unwrap();
    let (host, client) = unattended_pair(tmp.path(), REGISTERED);
    for typed in [
        "quiet t-shirt otter lantern zephyr",
        "quiet  t-shirt otter\tlantern zephyr",
    ] {
        let (mode, _, _) = signed(
            &host,
            &client,
            unattended_intent(typed, messages::mode::CONTROL, false),
        )
        .await;
        assert_eq!(mode, messages::mode::CONTROL, "{typed}");
    }
}

/// M1-67 C4: each check of a signed unattended `SESSION_ACCEPT` past its signature raises
/// `AnswerRefused` (the client deletes a remembered password), never `Violation` (which
/// keeps it): the session type, a missing `token_confirm` or one beside a `session_token`,
/// a wrong `token_confirm`, the QUIC key, and a mode or transport policy this build cannot
/// read. The host's test-only edit makes each fault before the accept is signed, the
/// faults its builder never makes among them.
#[tokio::test]
async fn each_check_of_a_signed_accept_raises_answer_refused() {
    const PW: &str = "quiet verdant otter lantern zephyr";
    type Edit = fn(&mut messages::SessionAccept);
    let cases: [(&str, Edit, u16, &str); 7] = [
        (
            "attended session type",
            |a| {
                a.session_type = messages::session_type::ATTENDED;
                a.grant_reach = None;
            },
            codes::E_BAD_STATE,
            "session_type",
        ),
        (
            "no token_confirm",
            |a| a.token_confirm = None,
            codes::E_BAD_LEN,
            "token_confirm",
        ),
        (
            "a session_token beside it",
            |a| a.session_token = Some([7; 32]),
            codes::E_BAD_LEN,
            "token_confirm",
        ),
        (
            "a wrong token_confirm",
            |a| {
                if let Some(confirm) = a.token_confirm.as_mut() {
                    confirm[0] ^= 1;
                }
            },
            codes::E_BAD_SIG,
            "token_confirm",
        ),
        (
            "another QUIC key",
            |a| a.quic_spki[40] ^= 1,
            codes::E_BAD_SIG,
            "quic_spki",
        ),
        ("an unknown mode", |a| a.mode = 7, codes::E_BAD_LEN, "mode"),
        (
            "an unknown transport policy",
            |a| a.transport_policy = 0xEE,
            codes::E_BAD_LEN,
            "mode",
        ),
    ];
    for (case, edit, code, what) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let (mut host, client) = unattended_pair(tmp.path(), PW);
        host.deps.edit_accept = Some(edit);
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let err = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            unattended_intent(PW, messages::mode::CONTROL, false),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                &err,
                HandshakeError::AnswerRefused { code: c, what: w } if *c == code && *w == what
            ),
            "{case}: {err:?}"
        );
        let _ = task.await;
    }
}

/// A pin that records how often it was asked to record.
#[derive(Default)]
struct RecordingPin {
    recorded: std::sync::atomic::AtomicUsize,
}

impl client::ServerKeyPin for RecordingPin {
    fn check(&self, _: &TornectId, _: &[u8; 32]) -> tornect_core::unattended::hosts::PinCheck {
        tornect_core::unattended::hosts::PinCheck::NoPin
    }
    fn record(&self, _: &TornectId, _: &[u8; 32]) {
        self.recorded.fetch_add(1, Ordering::SeqCst);
    }
}

/// A pin that never matches.
struct MismatchPin;

impl client::ServerKeyPin for MismatchPin {
    fn check(&self, _: &TornectId, _: &[u8; 32]) -> tornect_core::unattended::hosts::PinCheck {
        tornect_core::unattended::hosts::PinCheck::Mismatch
    }
    fn record(&self, _: &TornectId, _: &[u8; 32]) {}
}

/// M1-67 D6: [`KillSwitch::end_device`] ends only the sessions that watch for that
/// device, and only those that started watching before it; an end for the level only those
/// whose accept put them at the level, also when it came between the reservation and the
/// accept; the host-wide kill still reaches every session.
#[tokio::test(start_paused = true)]
async fn a_device_end_reaches_only_that_devices_sessions() {
    use tornect_core::unattended::guard::EndScope;
    async fn soon(guard: &mut KillGuard) -> Option<u16> {
        tokio::time::timeout(Duration::from_millis(100), guard.killed())
            .await
            .ok()
    }
    let kill = KillSwitch::new();
    let (p, q) = (DeviceId::from_bytes([1; 32]), DeviceId::from_bytes([2; 32]));
    let watching = |device: DeviceId, at_the_level: bool| {
        let mut guard = kill.arm();
        guard.watch_device(device);
        guard.at_the_level(at_the_level);
        guard
    };
    let mut p_at_the_level = watching(p, true);
    let mut p_below = watching(p, false);
    let mut q_at_the_level = watching(q, true);
    let mut attended = kill.arm();
    kill.end_device(&p, EndScope::AtTheLevel);
    assert_eq!(
        soon(&mut p_at_the_level).await,
        Some(bye::REVOKED),
        "a lowering, at the level"
    );
    assert_eq!(
        soon(&mut p_below).await,
        None,
        "a lowering, below the level"
    );
    assert_eq!(soon(&mut q_at_the_level).await, None);
    assert_eq!(soon(&mut attended).await, None);
    kill.end_device(&p, EndScope::Every);
    assert_eq!(
        soon(&mut p_below).await,
        Some(bye::REVOKED),
        "a revoke, any level"
    );
    assert_eq!(soon(&mut q_at_the_level).await, None);
    assert_eq!(soon(&mut attended).await, None);
    assert!(
        !q_at_the_level.fired(),
        "the host-wide check is not the device's"
    );
    let mut later = watching(p, true);
    assert_eq!(soon(&mut later).await, None, "ends before it watched");
    // a lowering between the reservation and the accept, the accept at the level
    let mut reserved = kill.arm();
    reserved.watch_device(q);
    kill.end_device(&q, EndScope::AtTheLevel);
    reserved.at_the_level(true);
    assert_eq!(
        soon(&mut reserved).await,
        Some(bye::REVOKED),
        "lowered while reserved"
    );
    kill.kill(bye::PANIC);
    assert_eq!(soon(&mut later).await, Some(bye::PANIC));
    assert_eq!(soon(&mut attended).await, Some(bye::PANIC));
}

/// The owner's guard over `guard`'s store, on the always-administrator facts of these
/// tests, wired to `host`'s kill switch as the host wires its own (decision M1-67, D6).
fn owner_guard(
    guard: &tornect_core::unattended::guard::MutationGuard,
    host: &HostSide,
) -> Arc<tornect_core::unattended::guard::MutationGuard> {
    use tornect_core::levels::{FixedFacts, HelperPresence};
    use tornect_core::unattended::guard::{
        AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
    };
    Arc::new(
        MutationGuard::new(
            guard.store().clone(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::new(FixedFacts::new(
                windows_facts(|f| f.enable_lua = Some(0)),
                HelperPresence::Absent,
            )),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_device_end(Arc::new(host.deps.kill.clone())),
    )
}

/// The real hook, then `then` once its read after the reservation has returned: an owner's
/// change committed after that read, before the accept goes out.
struct AfterTheRead<F> {
    inner: Arc<dyn UnattendedHook>,
    then: F,
}

impl<F> UnattendedHook for AfterTheRead<F>
where
    F: Fn() + Send + Sync,
{
    fn handle<'a>(
        &'a self,
        ctx: UnattendedContext<'a>,
    ) -> BoxFuture<'a, Result<UnattendedVerdict, HandshakeError>> {
        self.inner.handle(ctx)
    }

    fn reserved<'a>(
        &'a self,
        device: &'a DeviceId,
        proof: ConsentProof,
    ) -> BoxFuture<'a, Result<ConsentProof, messages::SessionReject>> {
        Box::pin(async move {
            let read = self.inner.reserved(device, proof).await;
            (self.then)();
            read
        })
    }
}

/// M1-67 A25 (p): a revoke, a disable, a suspend and a lowering of P's grant, each with
/// P's session reserved (the change committed after the read, before the accept) and with
/// it live, end P's session within 1 s, with `BYE{SUSPENDED}` for the suspend and
/// `BYE{REVOKED}` for the others (§B.8.6.1; P5B-1); another device's session goes on. On a
/// paused clock: 1 s of the host's time, however slow the machine.
#[tokio::test(start_paused = true)]
async fn a25_p_a_deny_direction_change_ends_that_devices_session_within_a_second() {
    use tornect_core::levels::{Elevation, FixedFacts, HelperPresence};
    use tornect_core::session_log::Actor;
    use tornect_core::unattended::guard::MutationGuard;
    use tornect_core::unattended::ipc::GrantOptions;
    const PW: &str = "quiet verdant otter lantern zephyr";
    type Change = fn(&MutationGuard, &DeviceId);
    let changes: [(&str, Change); 4] = [
        ("revoke", |g, d| g.revoke(Actor::Ui, d).unwrap()),
        ("disable", |g, d| g.disable(Actor::Ui, d).unwrap()),
        ("suspend", |g, d| {
            g.suspend(Actor::Ui, d).unwrap();
        }),
        ("lowering", |g, d| {
            g.set_options(
                Actor::Ui,
                d,
                &GrantOptions {
                    elevation: Some(Elevation::None),
                    ..GrantOptions::default()
                },
            )
            .unwrap();
        }),
    ];
    for (case, change) in changes {
        let expected = if case == "suspend" {
            bye::SUSPENDED
        } else {
            bye::REVOKED
        };
        for reserved in [false, true] {
            let case = format!("{case}, reserved: {reserved}");
            let tmp = tempfile::tempdir().unwrap();
            let facts = FixedFacts::new(
                windows_facts(|f| f.enable_lua = Some(0)),
                HelperPresence::Absent,
            );
            let (mut host, client, guard) =
                unattended_pair_edited(tmp.path(), PW, Arc::new(facts), |g| {
                    g.elevation = Elevation::Admin;
                    g.unmarked = true;
                });
            host.cfg.levels = always_administrator();
            host.cfg.orphan_timeout = None;
            host.cfg.idle_timeout = Duration::from_secs(30);
            let device = client.identity.id();
            // the owner's guard, wired to the host's kill switch as the host wires it
            let owner = owner_guard(&guard, &host);
            if reserved {
                let (owner, inner) = (Arc::clone(&owner), Arc::clone(&host.deps.unattended));
                host.deps.unattended = Arc::new(AfterTheRead {
                    inner,
                    then: move || change(&owner, &device),
                });
            }
            // another device, in an attended session (View only: on these facts the sheet
            // offers no plain Allow)
            let other = client_side(&tmp.path().join("other"), host.identity.id(), [0x33; 32]);
            host.trusted.pin(other.identity.id(), "Other").unwrap();
            other
                .known
                .pin(host.identity.id(), "Desk of Bob", host_device_pk())
                .unwrap();
            host.consent
                .push_session(SessionScript::Decide(SessionDecision::AllowOnceViewOnly));
            let (a, b) = pipe();
            let other_task = spawn_host(a, &host);
            let ClientOutcome::Session(mut other_session) =
                connect(b, &other.cfg, &other.identity, &other.deps, Intent::Session)
                    .await
                    .unwrap()
            else {
                panic!("{case}: no attended session");
            };
            // P's session
            let (a, b) = pipe();
            let task = spawn_host(a, &host);
            let ClientOutcome::Session(mut session) = connect(
                b,
                &client.cfg,
                &client.identity,
                &client.deps,
                unattended_intent(PW, messages::mode::CONTROL, true),
            )
            .await
            .unwrap_or_else(|e| panic!("{case}: {e}")) else {
                panic!("{case}: no session");
            };
            assert_eq!(session.accept().elevation(), Elevation::Admin, "{case}");
            if !reserved {
                session.ping().await.unwrap();
                change(&owner, &device);
            }
            assert_eq!(
                session.next_event(Duration::from_secs(1)).await.unwrap(),
                Some(SessionEvent::Bye {
                    reason: expected,
                    detail: None
                }),
                "{case}"
            );
            match task.await.unwrap().unwrap() {
                HostOutcome::Session { end, .. } => {
                    assert_eq!(end, SessionEnd::Killed(expected), "{case}");
                }
                other => panic!("{case}: {other:?}"),
            }
            // the other device's session goes on
            other_session.ping().await.unwrap();
            assert!(!other_task.is_finished(), "{case}");
            drop(other_session);
            let _ = other_task.await;
        }
    }
}

/// The block window during which the owner lowers the grant's level.
struct LowerDuringTheWindow {
    owner: Arc<tornect_core::unattended::guard::MutationGuard>,
    device: DeviceId,
}

impl crate::consent::BlockWindow for LowerDuringTheWindow {
    fn run<'a>(
        &'a self,
        _: u8,
        _: &'a tornect_core::unattended::grant::GrantId,
        _: &'a str,
    ) -> BoxFuture<'a, BlockOutcome> {
        use tornect_core::unattended::ipc::GrantOptions;
        Box::pin(async move {
            self.owner
                .set_options(
                    tornect_core::session_log::Actor::Ui,
                    &self.device,
                    &GrantOptions {
                        elevation: Some(tornect_core::levels::Elevation::None),
                        ..GrantOptions::default()
                    },
                )
                .unwrap();
            BlockOutcome::Passed(WindowPassed::Elapsed)
        })
    }
}

/// M1-67 A25 (d): a lowering during an administrator request's block window: the read after
/// the reservation finds the grant at none, and the accept carries no `elevation = 1`.
#[tokio::test]
async fn a25_d_a_lowering_in_the_block_window_signs_no_level() {
    use tornect_core::levels::{Elevation, FixedFacts, HelperPresence};
    const PW: &str = "quiet verdant otter lantern zephyr";
    let tmp = tempfile::tempdir().unwrap();
    let facts = || {
        Arc::new(FixedFacts::new(
            windows_facts(|f| f.enable_lua = Some(0)),
            HelperPresence::Absent,
        ))
    };
    let (mut host, client, guard) = unattended_pair_edited(tmp.path(), PW, facts(), |g| {
        g.elevation = Elevation::Admin;
        g.unmarked = true;
    });
    host.cfg.levels = always_administrator();
    host.deps.block_window = Arc::new(LowerDuringTheWindow {
        owner: guard,
        device: client.identity.id(),
    });
    let (mode, elevation, reach) = signed(
        &host,
        &client,
        unattended_intent(PW, messages::mode::CONTROL, true),
    )
    .await;
    assert_eq!(elevation, Elevation::None, "no elevation = 1");
    assert_eq!(
        reach,
        Some(1),
        "control is administrator access on these facts"
    );
    assert_eq!(mode, messages::mode::VIEW_ONLY, "F-12, without the level");
}

/// The block window during which the owner narrows the grant to View only, after giving
/// another device a grant at the administrator level when `admin_grant_for` names one.
struct NarrowDuringTheWindow {
    owner: Arc<tornect_core::unattended::guard::MutationGuard>,
    device: DeviceId,
    admin_grant_for: Option<DeviceId>,
}

impl crate::consent::BlockWindow for NarrowDuringTheWindow {
    fn run<'a>(
        &'a self,
        _: u8,
        _: &'a tornect_core::unattended::grant::GrantId,
        _: &'a str,
    ) -> BoxFuture<'a, BlockOutcome> {
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::ipc::GrantOptions;
        Box::pin(async move {
            if let Some(other) = &self.admin_grant_for {
                self.owner
                    .create_grant(
                        Actor::Ui,
                        other,
                        Preset::HeadlessBox,
                        &GrantOptions {
                            elevation: Some(tornect_core::levels::Elevation::Admin),
                            ..GrantOptions::default()
                        },
                        &[0u8; 192],
                        true,
                    )
                    .unwrap();
            }
            self.owner
                .set_options(
                    Actor::Ui,
                    &self.device,
                    &GrantOptions {
                        mode: Some(SessionMode::ViewOnly),
                        ..GrantOptions::default()
                    },
                )
                .unwrap();
            BlockOutcome::Passed(WindowPassed::Elapsed)
        })
    }
}

/// M1-67 B ("a grant lowered since the gate is clamped there") and D11: P's control grant
/// set to View only during its block window, after the gate read it as control. The read
/// after the reservation finds P at View only and answers 0, and the session is served
/// View only, never control at 0: for a password marked before, where nothing reaches the
/// level, and for one this answer marks while another grant was just given the level,
/// where control would reach it.
#[tokio::test]
async fn a_grant_narrowed_in_the_block_window_is_served_view_only() {
    use tornect_core::levels::{Elevation, FixedFacts, HelperPresence};
    const PW: &str = "quiet verdant otter lantern zephyr";
    for (case, unmarked, admin_grant_for) in [
        ("marked before, nothing at the level", false, None),
        (
            "marked by this answer, another grant at the level",
            true,
            Some(DeviceId::from_bytes([0x66; 32])),
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        // UAC on and no helper task: control is not administrator access, and no grant
        // holds the level when the gate reads it, so the gate mints control.
        let facts = Arc::new(FixedFacts::new(
            windows_facts(|_| {}),
            HelperPresence::Absent,
        ));
        let (mut host, client, guard) =
            unattended_pair_edited(tmp.path(), PW, facts, |g| g.unmarked = unmarked);
        let device = client.identity.id();
        host.deps.block_window = Arc::new(NarrowDuringTheWindow {
            owner: Arc::clone(&guard),
            device,
            admin_grant_for,
        });
        let (mode, elevation, reach) = signed(
            &host,
            &client,
            unattended_intent(PW, messages::mode::CONTROL, false),
        )
        .await;
        assert_eq!(
            mode,
            messages::mode::VIEW_ONLY,
            "{case}: never control at 0"
        );
        assert_eq!(elevation, Elevation::None, "{case}");
        assert_eq!(reach, Some(0), "{case}");
        let stored = guard.store().grant(&device).unwrap();
        assert_eq!(stored.mode, SessionMode::ViewOnly, "{case}");
        assert!(stored.marked(), "{case}: answered 0, marked");
        assert_eq!(
            guard
                .store()
                .read(|s| s.grants.iter().any(|g| g.holds_level()))
                .unwrap(),
            admin_grant_for.is_some(),
            "{case}"
        );
    }
}

/// M1-67 D6: a lowering ends P's sessions at the level only: P's View only session at none
/// goes on through it, and a revoke then still ends it.
#[tokio::test(start_paused = true)]
async fn a_lowering_leaves_a_session_below_the_level_running() {
    use tornect_core::levels::{Elevation, FixedFacts, HelperPresence};
    use tornect_core::session_log::Actor;
    use tornect_core::unattended::ipc::GrantOptions;
    const PW: &str = "quiet verdant otter lantern zephyr";
    let tmp = tempfile::tempdir().unwrap();
    let facts = FixedFacts::new(
        windows_facts(|f| f.enable_lua = Some(0)),
        HelperPresence::Absent,
    );
    let (mut host, client, guard) = unattended_pair_edited(tmp.path(), PW, Arc::new(facts), |g| {
        g.elevation = Elevation::Admin;
        g.unmarked = true;
    });
    host.cfg.levels = always_administrator();
    host.cfg.orphan_timeout = None;
    host.cfg.idle_timeout = Duration::from_secs(30);
    let device = client.identity.id();
    let owner = owner_guard(&guard, &host);
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let ClientOutcome::Session(mut session) = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        unattended_intent(PW, messages::mode::VIEW_ONLY, false),
    )
    .await
    .unwrap() else {
        panic!("no session");
    };
    assert_eq!(session.accept().elevation(), Elevation::None);
    session.ping().await.unwrap();
    owner
        .set_options(
            Actor::Ui,
            &device,
            &GrantOptions {
                elevation: Some(Elevation::None),
                ..GrantOptions::default()
            },
        )
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    session.ping().await.unwrap();
    assert!(!task.is_finished(), "below the level, the session goes on");
    owner.revoke(Actor::Ui, &device).unwrap();
    assert_eq!(
        session.next_event(Duration::from_secs(1)).await.unwrap(),
        Some(SessionEvent::Bye {
            reason: bye::REVOKED,
            detail: None
        })
    );
    match task.await.unwrap().unwrap() {
        HostOutcome::Session { end, .. } => assert_eq!(end, SessionEnd::Killed(bye::REVOKED)),
        other => panic!("{other:?}"),
    }
}

/// §B.8.6.3, TM-20: Block ⇒ `SESSION_REJECT{BLOCKED_BY_LOCAL_USER}` before any accept, so
/// no session starts and nothing is captured (capture begins at the sink's start), and
/// the grant is `Suspended{LocalBlock}` until a local Resume: the next request is refused
/// before any password exchange.
#[tokio::test]
async fn block_means_no_capture() {
    use tornect_core::unattended::grant::{GrantState, SuspendReason};
    const PW: &str = "quiet verdant otter lantern zephyr";
    /// The person at the host presses Block.
    struct Blocks;
    impl crate::consent::BlockWindow for Blocks {
        fn run<'a>(
            &'a self,
            _: u8,
            _: &'a crate::consent::GrantId,
            _: &'a str,
        ) -> BoxFuture<'a, BlockOutcome> {
            Box::pin(async { BlockOutcome::Blocked })
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let (mut host, client, guard) = unattended_pair_edited(
        tmp.path(),
        PW,
        Arc::new(tornect_core::levels::FixedFacts::linux()),
        |_| {},
    );
    host.deps.block_window = Arc::new(Blocks);
    let sink = Arc::new(CountingSink::default());
    host.deps.activity = sink.live.clone();
    host.deps.sessions = sink.clone();
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        unattended_intent(PW, messages::mode::CONTROL, false),
    )
    .await
    .expect_err("blocked");
    assert!(
        matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::BLOCKED_BY_LOCAL_USER),
        "{err}"
    );
    match task.await.unwrap().unwrap() {
        HostOutcome::SessionRejected { reason, .. } => {
            assert_eq!(reason, reject::BLOCKED_BY_LOCAL_USER);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(sink.starts.load(Ordering::SeqCst), 0, "nothing started");
    assert!(!SessionActivity::session_live(&*sink.live));
    let device = client.identity.id();
    let state = guard.store().grant(&device).unwrap().state;
    assert!(
        matches!(
            state,
            GrantState::Suspended {
                reason: SuspendReason::LocalBlock,
                ..
            }
        ),
        "{state:?}"
    );
    // Until a local Resume: refused before any password exchange.
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let err = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        unattended_intent(PW, messages::mode::CONTROL, false),
    )
    .await
    .expect_err("suspended");
    assert!(
        matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::SUSPENDED),
        "{err}"
    );
    let _ = task.await;
    assert_eq!(sink.starts.load(Ordering::SeqCst), 0);
}

/// §B.8.6.3, r7 (TM-29): "Ask before starting" is given the grant's level, so an admin
/// grant's popup names administrator access and a grant at none's does not; denied, the
/// request is refused `DENIED` and nothing starts.
#[tokio::test]
async fn ask_before_starting_names_the_administrator_level() {
    use tornect_core::levels::Elevation;
    const PW: &str = "quiet verdant otter lantern zephyr";
    /// Records what each popup was asked with, and denies.
    #[derive(Default)]
    struct Asked(Mutex<Vec<(String, Elevation, Duration)>>);
    impl crate::consent::LocalAllow for Asked {
        fn ask_at<'a>(
            &'a self,
            _: &'a crate::consent::GrantId,
            label: &'a str,
            level: Elevation,
            timeout: Duration,
        ) -> BoxFuture<'a, bool> {
            self.0
                .lock()
                .unwrap()
                .push((label.to_owned(), level, timeout));
            Box::pin(async { false })
        }
    }
    for (at_the_level, level) in [(true, Elevation::Admin), (false, Elevation::None)] {
        let tmp = tempfile::tempdir().unwrap();
        let (mut host, client, _guard) = unattended_pair_edited(
            tmp.path(),
            PW,
            Arc::new(tornect_core::levels::FixedFacts::linux()),
            |g| {
                g.ask_before_start = true;
                if at_the_level {
                    g.elevation = Elevation::Admin;
                }
            },
        );
        let asked = Arc::new(Asked::default());
        host.deps.local_allow = asked.clone();
        let sink = Arc::new(CountingSink::default());
        host.deps.activity = sink.live.clone();
        host.deps.sessions = sink.clone();
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let err = connect(
            b,
            &client.cfg,
            &client.identity,
            &client.deps,
            unattended_intent(PW, messages::mode::CONTROL, at_the_level),
        )
        .await
        .expect_err("denied");
        assert!(
            matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::DENIED),
            "{err}"
        );
        let _ = task.await;
        assert_eq!(
            *asked.0.lock().unwrap(),
            vec![("Laptop of Ana".to_owned(), level, Duration::from_secs(60))],
            "at the level: {at_the_level}"
        );
        assert_eq!(sink.starts.load(Ordering::SeqCst), 0);
    }
}

/// P5B-1 (§B.8.6.1): a device end carries its change's `BYE` reason, for every session and
/// for the level alike: `REVOKED` for a revoke, a disable or a lowering, `SUSPENDED` for a
/// suspend, `PANIC` for the panic key's; the plain end says `REVOKED`.
#[tokio::test(start_paused = true)]
async fn a_device_end_says_why() {
    use tornect_core::unattended::guard::{DeviceSessionEnd, EndReason, EndScope};
    let kill = KillSwitch::new();
    let p = DeviceId::from_bytes([1; 32]);
    for (reason, scope, said) in [
        (EndReason::Revoked, EndScope::Every, bye::REVOKED),
        (EndReason::Suspended, EndScope::Every, bye::SUSPENDED),
        (EndReason::Panic, EndScope::Every, bye::PANIC),
        (EndReason::Revoked, EndScope::AtTheLevel, bye::REVOKED),
        (EndReason::Suspended, EndScope::AtTheLevel, bye::SUSPENDED),
    ] {
        let mut guard = kill.arm();
        guard.watch_device(p);
        guard.at_the_level(true);
        kill.end_device_because(&p, scope, reason);
        let ended = tokio::time::timeout(Duration::from_millis(100), guard.killed()).await;
        assert_eq!(ended.ok(), Some(said), "{reason:?} {scope:?}");
    }
    let mut guard = kill.arm();
    guard.watch_device(p);
    DeviceSessionEnd::end_device(&kill, &p, EndScope::Every);
    let ended = tokio::time::timeout(Duration::from_millis(100), guard.killed()).await;
    assert_eq!(ended.ok(), Some(bye::REVOKED), "the plain end");
}

/// A relay that hands the client the host's frames up to and including the first of
/// `kind`, then reads nothing more from the host: from there on the client's stream takes
/// nothing, and a host frame larger than the host's pipe stays unwritten.
fn stalling_relay(
    client: DuplexStream,
    host: DuplexStream,
    kind: Kind,
) -> tokio::task::JoinHandle<()> {
    use crate::framing::{MAX_FRAME_LEN, read_frame_max};
    tokio::spawn(async move {
        let (mut client_rx, mut client_tx) = tokio::io::split(client);
        let (mut host_rx, mut host_tx) = tokio::io::split(host);
        let up = async {
            while let Ok(Some(frame)) = read_frame_max(&mut client_rx, MAX_FRAME_LEN).await {
                if write_frame(&mut host_tx, &frame).await.is_err() {
                    break;
                }
            }
        };
        let down = async {
            while let Ok(Some(frame)) = read_frame_max(&mut host_rx, MAX_FRAME_LEN).await {
                let last = Envelope::decode(&frame).is_ok_and(|env| env.kind == kind);
                if write_frame(&mut client_tx, &frame).await.is_err() || last {
                    break;
                }
            }
            std::future::pending::<()>().await;
        };
        tokio::join!(up, down);
    })
}

/// S5B-3, P5B-1 (D6; §B.8.6.1): R, a *My machines* control grant, revokes or suspends P
/// while P's session is live and R's stream takes nothing after the host's PAKE reply, so
/// the host's `ADMIN_RESULT` to R cannot be written. P's session still ends within 1 s,
/// with `BYE{REVOKED}` or `BYE{SUSPENDED}`: the end comes from the guard's committed
/// write, not after the answer. On a paused clock.
#[tokio::test(start_paused = true)]
async fn a_remote_revoke_or_suspend_ends_the_target_with_the_requester_stalled() {
    use tornect_core::levels::FixedFacts;
    use tornect_core::session_log::Actor;
    use tornect_core::unattended::grant::Preset;
    use tornect_core::unattended::ipc::GrantOptions;
    use tornect_core::unattended::limiter::{AttemptLimiter, HostTransport};
    use tornect_core::unattended::schedule::FixedOffset;

    use crate::unattended::{GuardAdmin, UnattendedAuth};
    const PW: &str = "quiet verdant otter lantern zephyr";
    for (case, op, said) in [
        ("revoke", messages::admin_op::REVOKE, bye::REVOKED),
        ("suspend", messages::admin_op::SUSPEND, bye::SUSPENDED),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (mut host, target, guard) =
            unattended_pair_edited(tmp.path(), PW, Arc::new(FixedFacts::linux()), |_| {});
        host.cfg.orphan_timeout = None;
        host.cfg.idle_timeout = Duration::from_secs(30);
        // R: a My machines control grant on the same host, in scope to revoke or suspend P
        let requester = client_side(
            &tmp.path().join("requester"),
            host.identity.id(),
            [0x55; 32],
        );
        let r = requester.identity.id();
        let host_onion_pk = *host.identity.id().public_key_bytes();
        host.trusted.pin(r, "Requester").unwrap();
        requester
            .known
            .pin(host.identity.id(), "Desk of Bob", host_device_pk())
            .unwrap();
        guard
            .create_grant(
                Actor::Cli,
                &r,
                Preset::MyMachines,
                &GrantOptions {
                    waive_attended_precondition: true,
                    ..GrantOptions::default()
                },
                &[0u8; 192],
                false,
            )
            .unwrap();
        let setup =
            crate::auth::parse_server_setup(&guard.store().server_setup().unwrap()).unwrap();
        let record = crate::auth::register_locally(
            &setup,
            PW,
            r.public_key_bytes(),
            crate::auth::identifiers(r.public_key_bytes(), &host_onion_pk),
        )
        .unwrap();
        guard
            .set_password(Actor::Cli, &r, &record, &GrantOptions::default(), false)
            .unwrap();
        // the host's admin authority: its guard, wired to its kill switch as the host
        // wires it
        let owner = owner_guard(&guard, &host);
        host.deps.unattended = Arc::new(
            UnattendedAuth::new(
                AttemptLimiter::new(guard.store().clone()),
                Arc::new(FixedOffset::utc()),
                HostTransport::default(),
                Arc::new(FixedFacts::linux()),
            )
            .with_admin_authority(Arc::new(GuardAdmin::new(owner))),
        );
        // P's session, live
        let (a, b) = pipe();
        let task = spawn_host(a, &host);
        let ClientOutcome::Session(mut session) = connect(
            b,
            &target.cfg,
            &target.identity,
            &target.deps,
            unattended_intent(PW, messages::mode::CONTROL, false),
        )
        .await
        .unwrap_or_else(|e| panic!("{case}: {e}")) else {
            panic!("{case}: no session");
        };
        session.ping().await.unwrap();
        // R's command, its stream stalled after the host's PAKE reply
        let (r_end, relay_client) = pipe();
        let (relay_host, host_end) = duplex(32);
        let answering = spawn_host(host_end, &host);
        let _relay = stalling_relay(relay_client, relay_host, Kind::AuthChallenge);
        let intent = client::AdminIntent {
            password: Zeroizing::new(PW.to_owned()),
            op,
            device_pk: Some(*target.identity.id().public_key_bytes()),
        };
        let asking = tokio::spawn(async move {
            client::admin(
                r_end,
                &requester.cfg,
                &requester.identity,
                &requester.deps,
                &intent,
            )
            .await
        });
        assert_eq!(
            session.next_event(Duration::from_secs(1)).await.unwrap(),
            Some(SessionEvent::Bye {
                reason: said,
                detail: None
            }),
            "{case}"
        );
        assert!(
            !answering.is_finished(),
            "{case}: the answer to R is not written"
        );
        match task.await.unwrap().unwrap() {
            HostOutcome::Session { end, .. } => {
                assert_eq!(end, SessionEnd::Killed(said), "{case}");
            }
            other => panic!("{case}: {other:?}"),
        }
        asking.abort();
        answering.abort();
    }
}

/// P5B-1 (§B.8.6.1): the panic key's suspend of P's grant ends P's live session with
/// `BYE{PANIC}`, also without the host-wide kill that comes first on the key's path.
#[tokio::test(start_paused = true)]
async fn the_panic_keys_suspend_ends_the_device_with_panic() {
    use tornect_core::levels::FixedFacts;
    const PW: &str = "quiet verdant otter lantern zephyr";
    let tmp = tempfile::tempdir().unwrap();
    let (mut host, client, guard) =
        unattended_pair_edited(tmp.path(), PW, Arc::new(FixedFacts::linux()), |_| {});
    host.cfg.orphan_timeout = None;
    host.cfg.idle_timeout = Duration::from_secs(30);
    let device = client.identity.id();
    let owner = owner_guard(&guard, &host);
    let (a, b) = pipe();
    let task = spawn_host(a, &host);
    let ClientOutcome::Session(mut session) = connect(
        b,
        &client.cfg,
        &client.identity,
        &client.deps,
        unattended_intent(PW, messages::mode::CONTROL, false),
    )
    .await
    .unwrap() else {
        panic!("no session");
    };
    session.ping().await.unwrap();
    owner.panic(&device).unwrap();
    assert_eq!(
        session.next_event(Duration::from_secs(1)).await.unwrap(),
        Some(SessionEvent::Bye {
            reason: bye::PANIC,
            detail: None
        })
    );
    match task.await.unwrap().unwrap() {
        HostOutcome::Session { end, .. } => assert_eq!(end, SessionEnd::Killed(bye::PANIC)),
        other => panic!("{other:?}"),
    }
    assert_eq!(host.deps.kill.fired(), None, "no host-wide kill");
}
