//! `tornect host`, `tornect ping` and `tornect connect` over the live Tor
//! network. The host answers the pairing-free ping protocol and the handshake
//! FSM on one port, routed by the first frame (decision M1-42), and shares the
//! screen of each accepted session on the media port (decision M1-39).

use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Semaphore, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tornect_capture::TestCard;
use tornect_codec::DecodedFrame;
use tornect_core::config::BridgeMode;
use tornect_core::keystore::{
    FileSecretStore, load_or_create_device_identity, load_or_create_host_identity,
};
use tornect_core::session_log::SessionMode;
use tornect_core::{Config, DeviceIdentity, HostIdentity, Paths, TornectId};
use tornect_session::{
    Binding, FrameSink, MediaHost, MediaLimits, MediaViewer, Source, SystemBackend, ViewerEnd,
    ViewerStats,
};
use tornect_signal::framing::FrameError;
use tornect_signal::fsm::client::{
    self, ClientConfig, ClientDeps, ClientOutcome, ClientSession, Intent, NoServerKeyPin,
    SessionEvent,
};
use tornect_signal::fsm::{HandshakeError, OsRandom};
use tornect_signal::messages::{bye, pair_reject, reject};
use tornect_signal::pairing::{AutoDeny, Consent, KnownHostStore};
use tornect_signal::ping::NONCE_LEN;
use tornect_signal::tor::Admission;
use tornect_signal::{
    HostSigner, Isolation, Ladder, LadderEvent, MEDIA_PORT, OnionStatus, SIGNALING_PORT,
    SignalError, TorNode, install_crypto_provider, ping, shutdown_runtime,
};

use crate::host::{CliMedia, ControlChannel, HostLock, HostWiring, Served};
use crate::prompt::{CliConsent, CliPairingUi, Prompter};

/// Per-ping reply deadline once the stream is open.
const PING_TIMEOUT: Duration = Duration::from_secs(30);

/// Signaling streams served at once. Every stream the listener hands out comes
/// from an unauthenticated peer and costs a task until its protocol lets go of
/// it (bounded: `ping::SESSION_TIMEOUT`, the FSM's timers); one per live
/// rendezvous circuit (`tornect_signal::tor::MAX_LIVE_CIRCUITS`) is what honest
/// use needs, so streams beyond that are closed immediately.
const MAX_SIGNALING_STREAMS: usize = tornect_signal::tor::MAX_LIVE_CIRCUITS;

/// How long `tornect host` waits, after Ctrl-C, for its streams to send `BYE`.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

/// How often `tornect connect` pings a live session: well inside the host's
/// 90 s idle timeout, and often enough to notice a host `BYE` within seconds.
const SESSION_PING_EVERY: Duration = Duration::from_secs(10);

/// How long `tornect connect` waits for the host to answer its media bind: the
/// host's own first-picture deadline (10 s) plus a Tor round trip or two.
const MEDIA_BIND_WAIT: Duration = Duration::from_secs(30);

/// When the host closes the media stream, how long `tornect connect` waits for
/// the host's `BYE` on the signaling stream, so the end is reported as the
/// host's rather than as the client's own.
const BYE_GRACE: Duration = Duration::from_secs(5);

/// How often `tornect connect` reports the pictures it receives.
const VIDEO_NOTE_EVERY: Duration = Duration::from_secs(5);

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating the tokio runtime")
}

/// `tornect host [--once] [--pow|--no-pow] [--capture …]`
pub fn host(
    paths: &Paths,
    once: bool,
    pow: Option<bool>,
    bridges: Option<BridgeMode>,
    source: Source,
) -> anyhow::Result<()> {
    install_crypto_provider();
    paths.ensure().context("creating Tornect directories")?;
    // Held until this host exits: it tells every other command that a host is
    // alive here, even one with no control channel (SLICE-B2 B2-2).
    let _host_lock = HostLock::acquire(paths)?;
    let store = FileSecretStore::open(paths.keys_dir()).context("opening keystore")?;
    let (identity, created) = load_or_create_host_identity(&store)?;
    if created {
        eprintln!(
            "generated a new Tornect ID (stored in {})",
            paths.keys_dir().display()
        );
    }
    // The host's device key: what a client pins at pairing and the QUIC
    // identity it presents (§B.6, decision M1-31).
    let (device, _) = load_or_create_device_identity(&store)?;
    let mut cfg = Config::load(&paths.config_file())?;
    if let Some(pow) = pow {
        cfg.tor.pow_defense = pow;
    }
    if let Some(mode) = bridges {
        cfg.tor.bridges = mode;
    }
    block_on(run_host(
        paths,
        &cfg,
        Arc::new(identity),
        HostSigner::public_key(&device),
        once,
        source,
    ))
}

/// What `tornect host` says it will share, before any session asks.
fn describe_source(source: Source) -> String {
    match source {
        Source::TestCard => {
            "sharing: a synthetic test card (no desktop; viewers' input goes nowhere)".to_owned()
        }
        Source::Desktop if wayland_without_capture() => {
            "sharing: nothing yet. This is a Wayland session and Wayland capture is not built \
             yet, so sessions connect but no picture can be shared; `--capture test-card` \
             shares a test card instead"
                .to_owned()
        }
        Source::Desktop => "sharing: this desktop".to_owned(),
    }
}

fn wayland_without_capture() -> bool {
    cfg!(target_os = "linux")
        && std::env::var("XDG_SESSION_TYPE").is_ok_and(|session| session == "wayland")
}

/// `tornect tor-check [--bridges …]`: reach the Tor network the way `host` and
/// `ping` would, report which transport worked, and exit.
pub fn tor_check(paths: &Paths, bridges: Option<BridgeMode>) -> anyhow::Result<()> {
    install_crypto_provider();
    paths.ensure().context("creating Tornect directories")?;
    let mut cfg = Config::load(&paths.config_file())?;
    if let Some(mode) = bridges {
        cfg.tor.bridges = mode;
    }
    block_on(async {
        let started = Instant::now();
        let node = start_tor(paths, &cfg).await?;
        println!(
            "TOR OK via {} in {:.1} s",
            node.rung(),
            started.elapsed().as_secs_f64()
        );
        node.shutdown().await;
        Ok(())
    })
}

/// Reach the Tor network through the bridge ladder (decision M1-38), printing
/// each step: direct Tor, then obfs4 bridges, then Snowflake, starting from the
/// transport that worked last time (`tor.bridges` in config.toml).
pub(crate) async fn start_tor(paths: &Paths, cfg: &Config) -> anyhow::Result<TorNode> {
    let ladder = Ladder::from_config(paths, &cfg.tor);
    for line in &ladder.rejected_lines {
        eprintln!("tor: ignoring {line}");
    }
    let mut last_pct = u32::MAX;
    let node = TorNode::start_auto(paths, cfg, &ladder, |event| match event {
        LadderEvent::Skipped { rung, reason } => {
            eprintln!("tor: {} unavailable: {reason}", rung.describe());
        }
        LadderEvent::Trying { rung, attempt, of } => {
            last_pct = u32::MAX;
            eprintln!(
                "tor: connecting via {} ({attempt}/{of})...",
                rung.describe()
            );
        }
        LadderEvent::Progress {
            fraction, blocked, ..
        } => {
            let pct = (fraction * 100.0).round() as u32;
            if pct != last_pct || blocked.is_some() {
                match blocked {
                    Some(why) => eprintln!("tor: bootstrap {pct:3}% - stuck: {why}"),
                    None => eprintln!("tor: bootstrap {pct:3}%"),
                }
                last_pct = pct;
            }
        }
        LadderEvent::Failed { rung, reason } => {
            eprintln!("tor: {} did not work: {reason}", rung.describe());
        }
        LadderEvent::Ready { rung } => eprintln!("tor: ready (via {})", rung.describe()),
        _ => {}
    })
    .await
    .map_err(explain)
    .context("reaching the Tor network")?;
    Ok(node)
}

/// Run `fut` on a fresh multi-thread runtime, then tear the runtime down the way
/// Arti needs (`tornect_signal::shutdown_runtime`: final state flush, PoW-thread
/// teardown noise muted).
fn block_on<F: Future<Output = anyhow::Result<()>>>(fut: F) -> anyhow::Result<()> {
    let rt = runtime()?;
    let result = rt.block_on(fut);
    shutdown_runtime(rt);
    result
}

async fn run_host(
    paths: &Paths,
    cfg: &Config,
    identity: Arc<HostIdentity>,
    device_pk: [u8; 32],
    once: bool,
    source: Source,
) -> anyhow::Result<()> {
    let consent: Arc<dyn Consent> = match Prompter::stdin() {
        Some(prompter) => Arc::new(CliConsent::new(prompter)),
        None => {
            eprintln!(
                "warning: stdin is not a terminal, so every pairing and session request is \
                 refused (run `tornect host` in a terminal to answer them); pings are answered"
            );
            Arc::new(AutoDeny)
        }
    };
    let control = ControlChannel::default();
    let media = Arc::new(MediaHost::new(
        Arc::new(SystemBackend::new(source)),
        Arc::new(CliMedia::new(control.clone())),
        MediaLimits::default(),
    ));
    let HostWiring {
        cfg: host_cfg,
        deps,
        ctx,
        live,
        audit,
    } = crate::host::wire(
        paths,
        cfg,
        Arc::clone(&identity),
        device_pk,
        consent,
        Arc::clone(&media),
        control.clone(),
    )?;
    // A kill ends every session's media at once, without waiting for the FSM's
    // `BYE` to a peer that may not be reading (SLICE-B1 B1-2).
    let kill_watch = media.watch_kill(deps.kill.clone());
    eprintln!("{}", describe_source(source));

    // The §B.8.7.4 control channel, bound **before** Tor. A running host owns the
    // endpoint and the store's advisory lock, so `tornect unattended …` in
    // another terminal routes here instead of opening the store itself — and
    // bringing it up first means that works during the slow part, which is
    // exactly when someone wants to ask what the host is doing. It shares the
    // FSM's kill switch, so `tornect panic` ends this host's sessions, with or
    // without a store (SLICE-B2 B2-2).
    let ipc = crate::host::start_control_channel(paths, ctx, deps.kill.clone(), control).await?;

    eprintln!("bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...");
    let node = start_tor(paths, cfg).await?;
    if node.rung() == tornect_signal::tor::Rung::Snowflake {
        // SLICE-A1 A1-7, kept as a warning rather than a refusal: in a censored
        // network where obfs4 is blocked too, Snowflake is the only way to host.
        eprintln!(
            "warning: hosting over Snowflake. The volunteer proxies that relay this machine's \
             Tor traffic can see its IP address, and anyone who knows this Tornect ID can send \
             it traffic. Private obfs4 bridges (tor.bridge_lines) avoid that."
        );
    }

    let pow = match (cfg.tor.pow_defense, tornect_signal::tor::pow_supported()) {
        (true, true) => "on",
        (true, false) => {
            "requested but not compiled in (feature `tor-pow`): publishing will be \
             refused; pass --no-pow to host without it"
        }
        (false, _) => "off",
    };
    eprintln!(
        "publishing onion service (PoW defense {pow}; reachable after descriptor upload, \
         typically ~10 s past bootstrap, up to 2 min on a cold start)..."
    );
    let mut listener = node
        .publish(&identity)
        .await
        .map_err(explain)
        .context("publishing the onion service")?;
    println!("Tornect ID: {}", listener.onion_address());
    let limits = listener.limits();
    eprintln!(
        "rendezvous budget: {} handshakes, {} live circuits; beyond that {}",
        limits.max_handshakes,
        limits.max_live_circuits,
        match listener.admission() {
            Admission::Backpressure => "requests wait in Tor's proof-of-work queue",
            Admission::Drop => "requests are dropped (no proof-of-work queue)",
        }
    );
    let status = spawn_status_reporter(listener.status());

    // Answered pings and finished sessions, for `--once`.
    let (served_tx, mut served_rx) = watch::channel(0u64);
    let slots = Arc::new(Semaphore::new(MAX_SIGNALING_STREAMS));
    let serving = Arc::new((host_cfg, deps.clone()));
    // Media streams: each bounds itself (bind deadline, unbound cap, session end).
    let mut media_streams = JoinSet::new();
    let mut ctrl_c = pin!(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            result = &mut ctrl_c => {
                result.context("waiting for Ctrl-C")?;
                eprintln!("Ctrl-C: shutting down");
                break;
            }
            stream = listener.accept() => {
                let Some(stream) = stream else {
                    eprintln!("listener closed");
                    break;
                };
                while media_streams.try_join_next().is_some() {}
                if stream.port() == MEDIA_PORT {
                    let media = Arc::clone(&media);
                    media_streams.spawn(async move {
                        let outcome = media.serve(stream).await;
                        if let Some(line) = crate::host::describe_media(&outcome) {
                            eprintln!("{line}");
                        }
                    });
                    continue;
                }
                // The listener admits no other port; this only keeps that true here.
                if stream.port() != SIGNALING_PORT {
                    continue;
                }
                // Dropping the stream closes it; the peer sees EOF.
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                    eprintln!(
                        "client connected over Tor but {MAX_SIGNALING_STREAMS} streams are \
                         already being served; closing it"
                    );
                    continue;
                };
                let serving = Arc::clone(&serving);
                let served = served_tx.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    let (cfg, deps) = &*serving;
                    let outcome = crate::host::serve_signaling(stream, cfg, deps, |n| {
                        println!("answered ping #{n}");
                        served.send_modify(|total| *total += 1);
                    })
                    .await;
                    if outcome == Served::Session {
                        served.send_modify(|total| *total += 1);
                    }
                });
            }
            changed = served_rx.changed(), if once => {
                if changed.is_err() || *served_rx.borrow() >= 1 {
                    eprintln!("first ping answered or session finished; exiting (--once)");
                    break;
                }
            }
        }
    }

    // End every handshake and session with a `BYE` (and every media stream with
    // a `Close`), and give the streams a moment to send it before Tor goes away
    // under them.
    deps.kill.kill(bye::USER);
    let grace = tokio::time::Instant::now() + SHUTDOWN_GRACE;
    loop {
        while media_streams.try_join_next().is_some() {}
        let busy = deps.stats.streams.load(Ordering::SeqCst) > 0 || !media_streams.is_empty();
        if !busy || tokio::time::Instant::now() >= grace {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if live.count() > 0 {
        eprintln!("{} session(s) did not close in time", live.count());
    }
    media_streams.abort_all();
    kill_watch.abort();
    if let Some(ipc) = &ipc {
        ipc.abort();
    }
    audit.flush();
    status.abort();
    drop(listener);
    node.shutdown().await;
    Ok(())
}

/// `tornect ping <onion> [--count N]`
pub fn ping(
    paths: &Paths,
    onion: &str,
    count: u32,
    bridges: Option<BridgeMode>,
) -> anyhow::Result<()> {
    install_crypto_provider();
    let id: TornectId = onion
        .parse()
        .map_err(|e| anyhow::anyhow!("{onion:?} is not a Tornect ID: {e}"))?;
    let mut cfg = Config::load(&paths.config_file())?;
    if let Some(mode) = bridges {
        cfg.tor.bridges = mode;
    }
    block_on(run_ping(paths, &cfg, id, count))
}

async fn run_ping(paths: &Paths, cfg: &Config, id: TornectId, count: u32) -> anyhow::Result<()> {
    eprintln!("bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...");
    let node = start_tor(paths, cfg).await?;

    eprintln!("connecting to {id} (rendezvous usually takes 5-30 s, up to 60 s)...");
    let started = Instant::now();
    let mut stream = node.connect(&id).await.map_err(explain)?;
    eprintln!("connected in {:.1} s", started.elapsed().as_secs_f64());

    let mut rtts_ms = Vec::with_capacity(count as usize);
    for i in 1..=count {
        let rtt = tokio::time::timeout(PING_TIMEOUT, ping::ping(&mut stream, nonce(i)))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "ping {i}/{count}: no reply within {} s",
                    PING_TIMEOUT.as_secs()
                )
            })?
            .map_err(explain)?;
        let ms = rtt.as_secs_f64() * 1000.0;
        println!("ping {i}/{count}: rtt {ms:.1} ms");
        rtts_ms.push(ms);
    }
    let min = rtts_ms.iter().copied().fold(f64::INFINITY, f64::min);
    let max = rtts_ms.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let avg = rtts_ms.iter().sum::<f64>() / rtts_ms.len() as f64;
    println!("PING OK n={count} min/avg/max={min:.1}/{avg:.1}/{max:.1} ms");

    // shutdown() closes our send side; Arti emits END(MISC), which the host's
    // OnionStream maps to a clean EOF.
    if let Err(e) = stream.shutdown().await {
        tracing::debug!(error = %e, "stream shutdown");
    }
    drop(stream);
    node.shutdown().await;
    Ok(())
}

/// What `tornect connect` should do beyond the handshake.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectOpts {
    /// Pair (if the host is new) and stop there.
    pub pair_only: bool,
    /// Forget the host first, so this connection pairs again (a host that
    /// lost its trusted-devices file answers the old pairing `E_BAD_STATE`).
    pub forget: bool,
    /// End the session after this many pings (scripted checks); `None` keeps
    /// it alive until Ctrl-C.
    pub pings: Option<u32>,
    /// Open the session's media stream and receive the shared screen.
    pub video: bool,
}

/// `tornect connect <onion> [--pair-only] [--forget] [--pings N]`
pub fn connect(
    paths: &Paths,
    onion: &str,
    opts: ConnectOpts,
    bridges: Option<BridgeMode>,
) -> anyhow::Result<()> {
    install_crypto_provider();
    let id: TornectId = onion
        .parse()
        .map_err(|e| anyhow::anyhow!("{onion:?} is not a Tornect ID: {e}"))?;
    let mut cfg = Config::load(&paths.config_file())?;
    if let Some(mode) = bridges {
        cfg.tor.bridges = mode;
    }
    paths.ensure().context("creating Tornect directories")?;
    let store = FileSecretStore::open(paths.keys_dir()).context("opening keystore")?;
    let (device, _) = load_or_create_device_identity(&store)?;
    let known = Arc::new(
        KnownHostStore::open(tornect_core::trusted::known_hosts_file(paths))
            .context("opening known-hosts.toml")?,
    );
    if opts.forget && known.remove(&id)? {
        eprintln!("forgot {id}; this connection pairs again");
    }
    block_on(run_connect(paths, &cfg, id, &device, known, opts))
}

async fn run_connect(
    paths: &Paths,
    cfg: &Config,
    id: TornectId,
    device: &DeviceIdentity,
    known: Arc<KnownHostStore>,
    opts: ConnectOpts,
) -> anyhow::Result<()> {
    eprintln!("bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...");
    let node = start_tor(paths, cfg).await?;
    let result = connect_session(&node, cfg, id, device, known, opts).await;
    node.shutdown().await;
    result
}

async fn connect_session(
    node: &TorNode,
    cfg: &Config,
    id: TornectId,
    device: &DeviceIdentity,
    known: Arc<KnownHostStore>,
    opts: ConnectOpts,
) -> anyhow::Result<()> {
    eprintln!("connecting to {id} (rendezvous usually takes 5-30 s, up to 60 s)...");
    let started = Instant::now();
    // One isolation group for the session: the media stream opened later rides
    // the signaling stream's rendezvous circuit (decision M1-39).
    let isolation = Isolation::new();
    let stream = node
        .connect_on(&id, SIGNALING_PORT, &isolation)
        .await
        .map_err(explain)?;
    eprintln!("connected in {:.1} s", started.elapsed().as_secs_f64());

    let pairing = known.get(&id).is_none();
    let ccfg = ClientConfig::new(id, cfg.general.device_name.clone());
    let deps = ClientDeps {
        known_hosts: known,
        ui: Arc::new(CliPairingUi::new(Prompter::stdin())),
        random: Arc::new(OsRandom),
        // Consulted only by unattended sessions, which this command does not request.
        server_key_pin: Arc::new(NoServerKeyPin),
    };
    let intent = if opts.pair_only {
        Intent::PairOnly
    } else {
        Intent::Session
    };
    match (pairing, opts.pair_only) {
        (true, _) => eprintln!("new host: pairing first (the host's user compares a code)..."),
        (false, true) => {}
        (false, false) => {
            eprintln!("asking for a session; the host's user has to accept it (up to 110 s)...");
        }
    }
    let outcome = client::connect(stream, &ccfg, device, &deps, intent)
        .await
        .map_err(explain_handshake)?;
    let mut session = match outcome {
        ClientOutcome::Paired { host_name } => {
            println!("PAIRED with \"{host_name}\"");
            return Ok(());
        }
        ClientOutcome::Session(session) => session,
    };
    let mode = match tornect_signal::consent::mode_from_code(session.accept().mode()) {
        Some(SessionMode::ViewOnly) => "view-only",
        _ => "control",
    };
    println!(
        "SESSION LIVE {} with \"{}\" ({mode})",
        session.session_token().session_id(),
        session.host_label()
    );
    // M1 has no direct path: the Tor circuit is the transport, and saying so
    // stops the host's 15 s orphan timer (§B.8.4.5).
    session
        .send_tor_fallback()
        .await
        .map_err(explain_handshake)?;
    eprintln!(
        "the session stays alive with a ping every {} s; Ctrl-C ends it",
        SESSION_PING_EVERY.as_secs()
    );

    let interrupts = Interrupts::listen();
    let end = if opts.video {
        watch(
            node,
            &id,
            &isolation,
            &mut session,
            opts.pings,
            &interrupts.pressed,
        )
        .await?
    } else {
        let stop = pressed(interrupts.pressed.clone());
        keep_alive(&mut session, opts.pings, SESSION_PING_EVERY, async {
            stop.await;
            Ok(())
        })
        .await?
    };
    match end {
        End::You => {
            if let Err(e) = session.bye(bye::USER).await {
                tracing::debug!(error = %e, "sending BYE");
            }
            println!("SESSION ENDED (by you)");
        }
        End::Host(reason) => println!("SESSION ENDED by the host ({})", bye::name(reason)),
        End::Lost(e) => {
            println!("SESSION ENDED (connection lost)");
            return Err(explain_handshake(e));
        }
        End::NoPicture(e) => {
            if let Err(e) = session.bye(bye::USER).await {
                tracing::debug!(error = %e, "sending BYE");
            }
            println!("SESSION ENDED (no picture)");
            return Err(e);
        }
    }
    Ok(())
}

/// Ctrl-C for a live session, heard on a task of its own so that nothing the
/// session does can starve it (SLICE-C2 C2-1). The first press asks the
/// session to end; a second quits at once, without waiting for the host.
struct Interrupts {
    /// Becomes `true` at the first Ctrl-C.
    pressed: watch::Receiver<bool>,
    task: JoinHandle<()>,
}

impl Interrupts {
    fn listen() -> Self {
        let (tx, pressed) = watch::channel(false);
        let task = tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_err() {
                return;
            }
            eprintln!("Ctrl-C: ending the session (press it again to quit at once)");
            let _ = tx.send(true);
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("second Ctrl-C: quitting without waiting for the host");
                std::process::exit(130);
            }
        });
        Self { pressed, task }
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Resolves at the first Ctrl-C, and never if the listener is gone.
async fn pressed(mut rx: watch::Receiver<bool>) {
    if rx.wait_for(|pressed| *pressed).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// How a live session ended, seen from the client.
#[derive(Debug)]
enum End {
    /// This side ended it (Ctrl-C, or `--pings` reached).
    You,
    /// The host sent `BYE{reason}`.
    Host(u16),
    /// The session broke.
    Lost(HandshakeError),
    /// The media stream could not be opened or bound, or it broke.
    NoPicture(anyhow::Error),
}

/// Open the session's media stream beside the signaling stream and receive
/// the screen, while the signaling stream keeps the session alive. Whichever
/// side ends first ends the other.
async fn watch<S>(
    node: &TorNode,
    id: &TornectId,
    isolation: &Isolation,
    session: &mut ClientSession<S>,
    pings: Option<u32>,
    interrupted: &watch::Receiver<bool>,
) -> anyhow::Result<End>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let binding = Binding::new(session.session_token(), &session.th());
    let opened = async {
        let stream = node
            .connect_on(id, MEDIA_PORT, isolation)
            .await
            .map_err(explain)?;
        MediaViewer::bind(stream, &binding, MEDIA_BIND_WAIT)
            .await
            .map_err(|e| anyhow::Error::new(e).context("binding the media stream"))
    };
    let viewer = match opened.await {
        Ok(viewer) => viewer,
        Err(e) => {
            println!("MEDIA FAILED: {e:#}");
            return Ok(End::NoPicture(e));
        }
    };
    let bound = *viewer.bound();
    println!(
        "MEDIA BOUND {}x{} ({})",
        bound.width,
        bound.height,
        match bound.mode {
            SessionMode::ViewOnly => "view-only",
            _ => "control",
        }
    );

    let mut pictures = CliPictures::new();
    let mut stats = ViewerStats::default();
    let (media_done, media_ended) = oneshot::channel::<bool>();
    let (stop_media, media_stop) = oneshot::channel::<()>();
    let viewing = async {
        // Ctrl-C reaches the viewer directly, not through the signaling
        // branch, which a flooding host could starve (SLICE-C2 C2-1).
        let stop = async {
            tokio::select! {
                _ = media_stop => {}
                () = pressed(interrupted.clone()) => {}
            }
        };
        let viewed = viewer.run(&mut pictures, &mut stats, stop).await;
        let by_host = matches!(viewed, Ok(ViewerEnd::Host(_) | ViewerEnd::Closed));
        let _ = media_done.send(by_host);
        viewed
    };
    let signaling = async {
        let stop = async {
            tokio::select! {
                () = pressed(interrupted.clone()) => Ok(()),
                by_host = media_ended => {
                    // The host closed the media stream: its `BYE` is usually on
                    // the way, and the end should be reported as the host's.
                    // Ctrl-C still cuts the wait short (SLICE-C2 C2-2).
                    if by_host.unwrap_or(false) {
                        tokio::select! {
                            () = tokio::time::sleep(BYE_GRACE) => {}
                            () = pressed(interrupted.clone()) => {}
                        }
                    }
                    Ok(())
                }
            }
        };
        let end = keep_alive(session, pings, SESSION_PING_EVERY, stop).await;
        let _ = stop_media.send(());
        end
    };
    let (viewed, end) = tokio::join!(viewing, signaling);

    pictures.report(&stats);
    let end = end?;
    // The viewer stops when the session ends, whoever ended it: the host's
    // `BYE` often arrives before its media `Close` (live run, 2026-09-21).
    match (&viewed, &end) {
        (Ok(ViewerEnd::Host(reason)), _) => println!(
            "MEDIA ENDED by the host ({})",
            crate::host::media_reason(*reason)
        ),
        (Ok(ViewerEnd::Closed), _) => println!("MEDIA ENDED (the host closed the stream)"),
        (Ok(ViewerEnd::Stopped), End::Host(_)) => {
            println!("MEDIA ENDED by the host (the session ended)");
        }
        (Ok(ViewerEnd::Stopped), End::Lost(_)) => println!("MEDIA ENDED (the session was lost)"),
        (Ok(ViewerEnd::Stopped), _) => println!("MEDIA ENDED (by you)"),
        (Err(e), _) => println!("MEDIA FAILED: {e}"),
    }
    Ok(match (viewed, end) {
        // The picture failed first; the session ended because of it.
        (Err(e), End::You) => End::NoPicture(anyhow::Error::new(e)),
        (_, end) => end,
    })
}

/// The CLI's stand-in for a viewer window: counts what it decodes, says so every
/// few seconds, and checks the test card's frame index when there is one.
struct CliPictures {
    started: Instant,
    last_note: Instant,
    decoded: u64,
    size: Option<(u32, u32)>,
    /// The first and last test-card index, while every picture has carried the
    /// next one.
    card: Option<(u32, u32)>,
    card_in_order: bool,
}

impl CliPictures {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            last_note: now,
            decoded: 0,
            size: None,
            card: None,
            card_in_order: true,
        }
    }

    fn fps(&self) -> f64 {
        self.decoded as f64 / self.started.elapsed().as_secs_f64().max(0.001)
    }

    fn report(&self, stats: &ViewerStats) {
        let secs = self.started.elapsed().as_secs_f64().max(0.001);
        let (w, h) = self.size.unwrap_or_default();
        println!(
            "MEDIA {} pictures={} units={} keyframes={} errors={} size={w}x{h} fps={:.1} kbps={:.0}",
            if self.decoded > 0 { "OK" } else { "EMPTY" },
            self.decoded,
            stats.access_units,
            stats.keyframes,
            stats.decode_errors,
            self.fps(),
            stats.bytes as f64 * 8.0 / 1000.0 / secs,
        );
        // Only a test card carries an index in every picture, in order.
        if let Some((first, last)) = self.card.filter(|_| self.card_in_order && self.decoded > 1) {
            println!("MEDIA CARD first={first} last={last} in-order");
        }
    }
}

impl FrameSink for CliPictures {
    fn picture(&mut self, _seq: u32, frame: &DecodedFrame) {
        self.decoded += 1;
        // Sized from the picture itself, never from `BindOk` (SLICE-A2 A2-4).
        self.size = Some((frame.width, frame.height));
        // RGBA keeps green at offset 1, as the BGRx the card is drawn in does.
        let index = TestCard::read_index(&frame.rgba, frame.width, frame.height);
        self.card = match (self.card, index) {
            (None, Some(index)) if self.decoded == 1 => Some((index, index)),
            (Some((first, last)), Some(index)) if index == last.wrapping_add(1) => {
                Some((first, index))
            }
            (card, _) => {
                self.card_in_order = false;
                card
            }
        };
        if self.last_note.elapsed() >= VIDEO_NOTE_EVERY {
            eprintln!(
                "video: {} pictures, {:.1} fps, {}x{}",
                self.decoded,
                self.fps(),
                frame.width,
                frame.height
            );
            self.last_note = Instant::now();
        }
    }
}

/// Keep `session` alive with a `PING` every `every` (the first at once) until
/// `stop` resolves, `pings` pings have been answered, or the host ends it.
/// Pings run to a deadline that frames from the host do not move, so a host
/// that keeps sending cannot keep `--pings N` from ending (SLICE-B2 B2-8).
///
/// Between pings it waits on the stream, not on a timer, so a host `BYE` is
/// reported the moment it arrives. Over Tor the host's circuit is often gone
/// by the next ping, whose write would then fail first and turn a deliberate
/// end (`tornect panic`) into "connection lost". Cutting that wait short
/// cannot drop part of a frame: after the accept the host sends nothing
/// unprompted except `BYE`, which ends the session anyway.
async fn keep_alive<S, F>(
    session: &mut ClientSession<S>,
    pings: Option<u32>,
    every: Duration,
    stop: F,
) -> anyhow::Result<End>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    F: Future<Output = std::io::Result<()>>,
{
    let mut stop = pin!(stop);
    let mut sent = 0u32;
    let mut next_ping = tokio::time::Instant::now();
    Ok(loop {
        if pings.is_some_and(|max| sent >= max) {
            break End::You;
        }
        let wait = next_ping.saturating_duration_since(tokio::time::Instant::now());
        if !wait.is_zero() {
            let event = tokio::select! {
                result = &mut stop => {
                    result.context("waiting for Ctrl-C")?;
                    break End::You;
                }
                event = session.next_event(wait) => event,
            };
            match event {
                // Nothing from the host in `wait`: time for the next ping.
                Err(HandshakeError::Timeout(_)) => {}
                Ok(Some(SessionEvent::Bye { reason, .. })) => break End::Host(reason),
                Ok(Some(SessionEvent::Error { code, detail })) => {
                    break End::Lost(HandshakeError::PeerError { code, detail });
                }
                // The M2 frames: nothing uses them before M2, and they do not
                // move the next ping.
                Ok(Some(_)) => continue,
                Ok(None) => break End::Lost(HandshakeError::Closed),
                Err(e) => break End::Lost(e),
            }
        }
        let pinged = tokio::select! {
            result = &mut stop => {
                result.context("waiting for Ctrl-C")?;
                break End::You;
            }
            rtt = session.ping() => rtt,
        };
        next_ping = tokio::time::Instant::now() + every;
        match pinged {
            Ok(rtt) => {
                sent += 1;
                println!(
                    "session ping {sent}: rtt {:.1} ms",
                    rtt.as_secs_f64() * 1000.0
                );
            }
            Err(HandshakeError::PeerBye { reason, .. }) => break End::Host(reason),
            Err(e) => break End::Lost(e),
        }
    })
}

/// Nonces only need to be unique per stream; wall-clock nanoseconds mixed with
/// the sequence number are plenty.
fn nonce(seq: u32) -> [u8; NONCE_LEN] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    ((nanos as u64) ^ (u64::from(seq) << 48)).to_be_bytes()
}

fn spawn_status_reporter(mut rx: watch::Receiver<OnionStatus>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut announced = false;
        let mut last: Option<OnionStatus> = None;
        loop {
            let s = rx.borrow_and_update().clone();
            if last.as_ref() != Some(&s) {
                if s.reachable {
                    if !announced {
                        println!("REACHABLE");
                        eprintln!("onion service reachable ({}); waiting for pings", s.state);
                        announced = true;
                    }
                } else {
                    match &s.problem {
                        Some(problem) => eprintln!("onion service: {} ({problem})", s.state),
                        None => eprintln!("onion service: {}", s.state),
                    }
                }
                last = Some(s);
            }
            if rx.changed().await.is_err() {
                break;
            }
        }
    })
}

/// Turn a [`SignalError`] into a user-facing message with a next step.
fn explain(err: SignalError) -> anyhow::Error {
    let hint = match &err {
        SignalError::HostOffline => {
            "The host is offline or has not finished publishing its Tornect ID. \
             On the host, run `tornect host` and wait for REACHABLE, then retry."
        }
        SignalError::HostNotRunning => {
            "The host's Tornect ID is published but the host is not reachable right now \
             (it just stopped, or its introduction points expired). Retry in a minute."
        }
        SignalError::Timeout(_) => {
            "Tor did not answer in time. Check the network on both ends and retry."
        }
        SignalError::Bootstrap(_) => {
            "Tor could not be reached directly, through obfs4 bridges or through Snowflake. \
             Check the network connection (a full disk also shows up this way: the Tor \
             cache lives under `tornect paths`). Where Tor is censored, get private bridges \
             from https://bridges.torproject.org and add them to `tor.bridge_lines` in \
             config.toml; `tornect doctor` shows whether the `lyrebird` bridge helper was found."
        }
        SignalError::Config(_) => {
            "Check `tornect config show`: a security setting this build cannot honour \
             is refused rather than silently ignored."
        }
        SignalError::Frame(FrameError::Io(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            "The host closed the connection mid-session (it exited, restarted, or \
             was started with --once)."
        }
        _ => "",
    };
    if hint.is_empty() {
        anyhow::Error::new(err)
    } else {
        anyhow::Error::new(err).context(hint)
    }
}

/// Turn a [`HandshakeError`] into a user-facing message with a next step.
fn explain_handshake(err: HandshakeError) -> anyhow::Error {
    let hint: std::borrow::Cow<'static, str> = match &err {
        HandshakeError::PairRejected { reason, .. } => match *reason {
            pair_reject::DENIED => "The host's user refused the pairing.".into(),
            pair_reject::TIMEOUT => {
                "Nobody answered the pairing request on the host in time.".into()
            }
            pair_reject::BUSY => "The host is in a session; try again when it has ended.".into(),
            pair_reject::BANNED | pair_reject::RATE_LIMITED | pair_reject::IN_FLIGHT => {
                "Too many pairing attempts; wait a few minutes and try again.".into()
            }
            _ => "".into(),
        },
        HandshakeError::SessionRejected { reject } => match reject.reason {
            reject::DENIED => "The host's user refused the session.".into(),
            reject::POPUP_TIMEOUT => "Nobody answered on the host in time.".into(),
            reject::BUSY => {
                "The host is busy (in a session, or asked too often); try again later.".into()
            }
            _ => "".into(),
        },
        HandshakeError::PairingLost => {
            "Pair again with `tornect connect <id> --forget` (the host's user compares a code)."
                .into()
        }
        HandshakeError::Aborted(_) => "Nothing was pinned; run the command again to retry.".into(),
        HandshakeError::Timeout(_) => {
            "The host did not answer in time (its user may not have responded).".into()
        }
        _ => "".into(),
    };
    if hint.is_empty() {
        anyhow::Error::new(err)
    } else {
        anyhow::Error::new(err).context(hint)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::task::{Context, Poll};

    use tokio::io::{DuplexStream, ReadBuf, duplex};
    use tornect_core::trusted::{KnownHosts, TrustedDevices};
    use tornect_signal::fsm::client::ScriptedClientUi;
    use tornect_signal::fsm::host::{HostConfig, HostDeps, KillSwitch, serve_host};
    use tornect_signal::pairing::{
        PairDecision, PairScript, ScriptedConsent, SessionDecision, SessionScript,
        TrustedDeviceStore,
    };

    use super::*;

    /// The client's end of the signaling stream, whose writes can be frozen,
    /// as a host that grants no Tor flow-control credit freezes them.
    struct Freezable {
        inner: DuplexStream,
        frozen: Arc<AtomicBool>,
    }

    impl AsyncRead for Freezable {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Freezable {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.frozen.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.frozen.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.frozen.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// A live session with a real host FSM behind a duplex.
    struct Live {
        _tmp: tempfile::TempDir,
        session: ClientSession<Freezable>,
        frozen: Arc<AtomicBool>,
        kill: KillSwitch,
        host: JoinHandle<Result<tornect_signal::fsm::host::HostOutcome, HandshakeError>>,
    }

    async fn live() -> Live {
        let tmp = tempfile::tempdir().unwrap();
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let trusted = Arc::new(TrustedDeviceStore::with(
            tmp.path().join("trusted-devices.toml"),
            TrustedDevices::default(),
        ));
        let consent = Arc::new(ScriptedConsent::new());
        consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
        consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
        let mut deps = HostDeps::headless(identity.clone(), trusted);
        deps.consent = consent;
        let kill = deps.kill.clone();
        let cfg = HostConfig::new("Desk", [9; 32]);
        let (client_end, host_end) = duplex(64 * 1024);
        let host = tokio::spawn(async move { serve_host(host_end, &cfg, &deps).await });

        let known = Arc::new(KnownHostStore::with(
            tmp.path().join("known-hosts.toml"),
            KnownHosts::default(),
        ));
        let mut client_deps = ClientDeps::headless(known);
        client_deps.ui = Arc::new(ScriptedClientUi::new(true));
        let device = DeviceIdentity::from_seed(&[0x22; 32]);
        let ccfg = ClientConfig::new(identity.id(), "Laptop");
        let frozen = Arc::new(AtomicBool::new(false));
        let stream = Freezable {
            inner: client_end,
            frozen: Arc::clone(&frozen),
        };
        let mut session =
            match client::connect(stream, &ccfg, &device, &client_deps, Intent::Session)
                .await
                .unwrap()
            {
                ClientOutcome::Session(s) => *s,
                other => panic!("expected a session, got {other:?}"),
            };
        session.send_tor_fallback().await.unwrap();
        Live {
            _tmp: tmp,
            session,
            frozen,
            kill,
            host,
        }
    }

    /// A host that ends the session between two pings (`tornect panic`) must be
    /// reported as the host's `BYE`, not as a lost connection. Live over Tor the
    /// host's circuit was already gone by the next ping, and the client printed
    /// "connection lost" for a session the host had deliberately ended.
    #[tokio::test(start_paused = true)]
    async fn a_host_bye_between_pings_is_reported_as_the_hosts() {
        let Live {
            mut session,
            kill,
            host,
            ..
        } = live().await;

        // The host's user presses the panic key 5 s into the 10 s gap between pings.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            kill.kill(bye::PANIC);
        });
        let end = keep_alive(
            &mut session,
            None,
            Duration::from_secs(10),
            std::future::pending(),
        )
        .await
        .unwrap();
        assert!(
            matches!(end, End::Host(reason) if reason == bye::PANIC),
            "{end:?}"
        );
        host.await.unwrap().unwrap();
    }

    /// SLICE-B2 B2-8 and C2-2: leaving never waits on a host that stops
    /// reading. Before, `bye` had no deadline, so a Ctrl-C (or a failed
    /// picture) ended in a hang that no further Ctrl-C could break.
    #[tokio::test(start_paused = true)]
    async fn leaving_does_not_wait_on_a_host_that_stops_reading() {
        let Live {
            session, frozen, ..
        } = live().await;
        frozen.store(true, Ordering::SeqCst);
        let left = tokio::time::timeout(Duration::from_secs(60), session.bye(bye::USER)).await;
        assert!(
            matches!(left, Ok(Err(HandshakeError::Timeout(_)))),
            "{left:?}"
        );
    }
}
