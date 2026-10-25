//! `tornect host`, `tornect ping` and `tornect connect` over the live Tor
//! network. The host answers the pairing-free ping protocol and the handshake
//! FSM on one port, routed by the first frame (decision M1-42), and shares the
//! screen of each accepted session on the media port (decision M1-39).

use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tornect_capture::TestCard;
use tornect_codec::DecodedFrame;
use tornect_core::config::{BridgeMode, QualityPreset};
use tornect_core::keystore::{
    FileSecretStore, load_or_create_device_identity, load_or_create_host_identity,
};
use tornect_core::session_log::SessionMode;
use tornect_core::{Config, DeviceIdentity, HostIdentity, Paths, TornectId};
use tornect_input::InputEvent;
use tornect_proto::{HostStats, ProtoError, QualityInfo};
use tornect_session::{
    Binding, DesktopBackend, FrameSink, MediaHost, MediaLimits, MediaViewer, Source, SystemBackend,
    ViewerEnd, ViewerError, ViewerStats,
};
use tornect_signal::framing::FrameError;
use tornect_signal::fsm::client::{
    self, ClientConfig, ClientDeps, ClientOutcome, ClientSession, Intent, NoServerKeyPin,
    SessionEvent,
};
use tornect_signal::fsm::{HandshakeError, OsRandom, Randomness as _};
use tornect_signal::messages::{bye, pair_reject, reject};
use tornect_signal::pairing::KnownHostStore;
use tornect_signal::ping::NONCE_LEN;
use tornect_signal::tor::Admission;
use tornect_signal::{
    HostSigner, Isolation, Ladder, LadderEvent, MEDIA_PORT, OnionStatus, SIGNALING_PORT,
    SignalError, TorNode, install_crypto_provider, ping, shutdown_runtime,
};

use crate::host::{CliMedia, ControlChannel, HostLock, HostWiring, Served};
use crate::prompt::{CliPairingUi, Prompter};

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
/// Least time between two `MEDIA QUALITY` lines, and between two `MEDIA
/// TIMING` lines (the quality design §3.5): a host that keeps saying things
/// cannot flood the terminal.
const MEDIA_LINE_EVERY: Duration = Duration::from_secs(1);

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

/// What `tornect host` says it will share, before any session asks: only a
/// desktop that `desktop` can capture is "this desktop" (SLICE-C3 C3-5).
fn describe_source(source: Source, desktop: &DesktopBackend) -> String {
    match (source, desktop) {
        (Source::TestCard, _) => {
            "sharing: a synthetic test card (no desktop; viewers' input goes nowhere)".to_owned()
        }
        (Source::TestScreens, _) => {
            let [(w1, h1), (w2, h2)] = tornect_session::TEST_SCREENS;
            format!(
                "sharing: two synthetic test screens side by side, {w1}x{h1} (main) and \
                 {w2}x{h2} (no desktop; viewers' input goes nowhere)"
            )
        }
        (Source::Desktop, DesktopBackend::Wayland) => {
            "sharing: this desktop, through the desktop's screen-sharing portal. When a viewer's \
             picture starts, the desktop asks whether to share the screen and allow remote \
             control, unless it was allowed before and remembered"
                .to_owned()
        }
        (Source::Desktop, DesktopBackend::X11) => "sharing: this desktop (X11)".to_owned(),
        (Source::Desktop, DesktopBackend::Gdi) => "sharing: this desktop".to_owned(),
        (Source::Desktop, DesktopBackend::Unavailable(why)) => format!(
            "sharing: nothing: this desktop cannot be captured here ({why}), so a viewer gets \
             no picture; `--capture test-card` shares a synthetic card instead"
        ),
    }
}

/// `tornect doctor`'s lines about capture: the backend a host would share its
/// desktop with here (SLICE-C3 C3-5), and on Wayland the file that holds the
/// desktop's remembered grant, whose deletion revokes it. The path is printed
/// for the owner and never logged.
pub(crate) fn capture_lines(paths: &Paths, desktop: &DesktopBackend) -> Vec<String> {
    let mut lines = vec![match desktop {
        DesktopBackend::Wayland => {
            "capture: wayland (the RemoteDesktop portal and PipeWire)".to_owned()
        }
        DesktopBackend::X11 => "capture: x11 (the X11 grab and XTEST)".to_owned(),
        DesktopBackend::Gdi => "capture: gdi (GDI and SendInput)".to_owned(),
        DesktopBackend::Unavailable(why) => format!("capture: none ({why})"),
    }];
    if *desktop == DesktopBackend::Wayland {
        let token = paths.portal_restore_token();
        lines.push(format!(
            "  desktop grant: {} [{}]; delete it to revoke the remembered grant, and the \
             desktop asks again at the next session",
            token.display(),
            if token.exists() { "present" } else { "absent" }
        ));
    }
    lines
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
    let prompter = Prompter::stdin();
    if prompter.is_none() {
        eprintln!("{}", crate::host::NO_TERMINAL_LINE);
    }
    let control = ControlChannel::default();
    // An administrator session's input goes through its administrator
    // helper (§B.8.7.5), started between the answer and the accept.
    let helpers = crate::admin_helper::AdminHelpers::new();
    let media = Arc::new(MediaHost::new(
        Arc::new(crate::admin_helper::AdminBackend::new(
            Arc::new(SystemBackend::new(source).with_restore_token(paths.portal_restore_token())),
            Arc::clone(&helpers),
        )),
        Arc::new(CliMedia::new(control.clone())),
        // The presets' bounds come from this host's `[media]`.
        MediaLimits::with_media(&cfg.media),
    ));
    let HostWiring {
        cfg: host_cfg,
        mut deps,
        ctx,
        live,
        audit,
        pins: _,
        polkit: _,
    } = crate::host::wire_cli(
        paths,
        cfg,
        Arc::clone(&identity),
        device_pk,
        prompter,
        Arc::clone(&media),
        control.clone(),
    )?;
    helpers.wire(deps.kill.clone(), audit.clone(), host_cfg.levels);
    deps.admin_helper = helpers;
    // A kill ends every session's media at once, without waiting for the FSM's
    // `BYE` to a peer that may not be reading (SLICE-B1 B1-2).
    let kill_watch = media.watch_kill(deps.kill.clone());
    eprintln!("{}", describe_source(source, &DesktopBackend::detect()));

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
    crate::host::own_id(format_args!("Tornect ID: {}", listener.onion_address()));
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
    // Media streams: each bounds itself (the bind deadline, the cap on binds
    // waiting for an unregistered session, the session's end). Streams still
    // reading their `Bind` hold no slot (SLICE-C1 C1-1); the listener's cap of 4
    // streams per circuit and 64 circuits is what bounds them.
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
        // A kill ends only the sessions armed before it: one that goes live
        // during the grace (a consent answered just now) ends too (P2-I4).
        deps.kill.kill(bye::USER);
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

/// The host a command names (design `invite` §2.5): a bare Tornect ID, its
/// `tornect:` link, or a whole pasted invitation. A refusal names the problem
/// only: the input is never echoed, and never logged (L-7).
fn named_host(text: &str) -> anyhow::Result<TornectId> {
    tornect_core::invite::find_id(text)
        .map(|found| found.id)
        .map_err(|problem| anyhow::anyhow!("that is not a Tornect ID: {problem}"))
}

/// `tornect ping <onion> [--count N]`
pub fn ping(
    paths: &Paths,
    onion: &str,
    count: u32,
    bridges: Option<BridgeMode>,
) -> anyhow::Result<()> {
    install_crypto_provider();
    let id = named_host(onion)?;
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
        let rtt = tokio::time::timeout(PING_TIMEOUT, ping::ping(&mut stream, nonce()?))
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

/// `tornect connect --unattended`: what the person chose on the command line.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnattendedOpts {
    /// View only this time.
    pub view_only: bool,
    /// Keep the password in the keychain once it worked.
    pub remember: bool,
    /// Ask for the administrator level.
    pub administrator: bool,
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
    /// The picture quality to ask for; `None` asks for `[viewer] quality`.
    pub quality: Option<QualityPreset>,
    /// Connect without asking, on this device's unattended grant.
    pub unattended: Option<UnattendedOpts>,
}

/// `tornect admin <id> <action>`: one admin command on this device's grant at
/// a paired host (§B.8.4.1, B.8.10): a confirmation naming the host, the
/// password (remembered, or asked masked on this terminal), one attempt, and
/// the host's signed answer.
pub fn admin(
    paths: &Paths,
    onion: &str,
    action: crate::ua_client::AdminAction,
    device_arg: Option<&str>,
    bridges: Option<BridgeMode>,
) -> anyhow::Result<()> {
    use std::io::IsTerminal as _;

    use crate::ua_client::{self, AdminAction, Logged};
    install_crypto_provider();
    let id = named_host(onion)?;
    let mut cfg = Config::load(&paths.config_file())?;
    if let Some(mode) = bridges {
        cfg.tor.bridges = mode;
    }
    paths.ensure().context("creating Tornect directories")?;
    let store = FileSecretStore::open(paths.keys_dir()).context("opening keystore")?;
    let (device, _) = load_or_create_device_identity(&store)?;
    let target = match action {
        AdminAction::Unlock => {
            let other: tornect_core::DeviceId = device_arg
                .ok_or_else(|| anyhow::anyhow!("unlock needs --device <DEVICE_ID>"))?
                .parse()
                .map_err(|e| anyhow::anyhow!("that is not a device ID: {e}"))?;
            Some(*other.public_key_bytes())
        }
        AdminAction::RevokeThisDevice => Some(*device.id().public_key_bytes()),
        AdminAction::EndSession | AdminAction::TurnOff => None,
    };
    crate::history::coarsen_pins(paths);
    let pins = crate::history::Pins::open(paths, id).context("opening known-hosts.toml")?;
    let Some(known) = pins.store().get(&id) else {
        anyhow::bail!("this computer is not paired with that host; admin commands go only to one");
    };
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        anyhow::bail!(
            "an admin command asks for a confirmation and its password on a terminal, and this \
             is not one"
        );
    }
    crate::host::peer_note(format_args!("{}", action.confirmation(&known.label)));
    if !crate::unattended::confirm("Send it?")? {
        anyhow::bail!("not sent");
    }
    let saved = ua_client::system_passwords(&device);
    // C6: a password the host's last answer did not let this device keep goes first.
    if let Err(e) = ua_client::belt(paths, &saved, &id) {
        tracing::warn!(error = %format!("{e:#}"), "hosts.toml could not be read");
    }
    let password = match ua_client::recall_for_use(paths, &saved, &id)? {
        ua_client::Recalled::Password(password) => password,
        other => {
            if matches!(other, ua_client::Recalled::Vanished) {
                eprintln!(
                    "the password remembered for this host is no longer in {}; type it",
                    saved.keychain().unwrap_or("the keychain")
                );
            }
            crate::unattended::read_password("Unattended password (not shown): ")?
        }
    };
    if password.is_empty() {
        anyhow::bail!("no password typed; nothing was sent");
    }
    let request = ua_client::Request {
        password,
        view_only: true,
        administrator: false,
        remember: false,
    };
    block_on(async {
        eprintln!("bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...");
        let node = start_tor(paths, &cfg).await?;
        let result = async {
            let stream = match node
                .connect_on(&id, SIGNALING_PORT, &Isolation::new())
                .await
            {
                Ok(stream) => stream,
                Err(e) => {
                    let ended = ua_client::unreachable(&known.label);
                    ua_client::log_attempt(paths, &known, &Logged::Ended(&ended.reason));
                    crate::host::peer_note(format_args!("{}", ended.text));
                    return Err(explain(e));
                }
            };
            let ccfg = ClientConfig::new(id, cfg.general.device_name.clone());
            let deps = ClientDeps {
                known_hosts: pins.store(),
                ui: Arc::new(CliPairingUi::new(None)),
                random: Arc::new(OsRandom),
                server_key_pin: Arc::new(ua_client::HostsPin::new(paths)),
            };
            let command = client::AdminIntent {
                password: request.password.clone(),
                op: action.op(),
                device_pk: target,
            };
            match client::admin(stream, &ccfg, &device, &deps, &command).await {
                Ok(answer) => {
                    // An admin answer keeps no password (DA-15); its decoded `grant_reach`
                    // decides about a remembered one (C1, C11).
                    match ua_client::after_admin(
                        paths,
                        &saved,
                        &id,
                        &answer,
                        &format!("\"{}\"", known.label),
                    ) {
                        Ok(notes) => say_notes(&notes),
                        Err(e) => eprintln!("hosts.toml could not be updated: {e:#}"),
                    }
                    ua_client::log_attempt(
                        paths,
                        &known,
                        &Logged::Admin {
                            op: action.name(),
                            ok: answer.ok,
                        },
                    );
                    // The host's own words: untrusted text, shown quoted and
                    // escaped, on a terminal only.
                    if let Some(detail) = &answer.detail {
                        crate::host::peer_note(format_args!(
                            "the host says: \"{}\"",
                            detail.escape_debug()
                        ));
                    }
                    if answer.ok {
                        if action == AdminAction::RevokeThisDevice
                            && let Err(e) = ua_client::forget(paths, &saved, &id)
                        {
                            eprintln!("{e}");
                        }
                        println!("ADMIN OK {}", action.name());
                        Ok(())
                    } else {
                        anyhow::bail!(
                            "the host did not do it ({}): this device's access there does not \
                             allow it, or the host could not",
                            action.name()
                        )
                    }
                }
                Err(e) => {
                    let ended = ua_client::ended(&e, &known.label);
                    match ua_client::settle(paths, &saved, &id, ended.attempt, &request) {
                        Ok(settled) => say_notes(&ua_client::refused_notes(
                            &format!("\"{}\"", known.label),
                            saved.keychain().unwrap_or("the keychain"),
                            ended.attempt,
                            &settled,
                        )),
                        Err(err) => eprintln!("hosts.toml could not be updated: {err:#}"),
                    }
                    ua_client::log_attempt(paths, &known, &Logged::Ended(&ended.reason));
                    crate::host::peer_note(format_args!("{}", ended.text));
                    anyhow::bail!("the admin command was not answered ({})", ended.reason)
                }
            }
        }
        .await;
        node.shutdown().await;
        result
    })
}

/// The notes after an unattended answer (decision M1-67) on stderr: they name
/// the host, so only a terminal sees them (`host::peer_note`, U3-M1); the exit
/// status is the attempt's.
fn say_notes(notes: &[String]) {
    for note in notes {
        crate::host::peer_note(format_args!("{note}"));
    }
}

/// `--remember` is refused before dialing where no password can be kept: no
/// usable keychain, the level asked for, or `hosts.toml` saying that the
/// host's last answer reached administrator access, left the key out or was
/// refused (C11). The words name no host: they are an error for the shell.
fn remember_refused(
    saved: &tornect_core::unattended::credentials::SavedPasswords,
    record: &tornect_core::unattended::hosts::HostRecord,
    administrator: bool,
) -> Option<String> {
    saved
        .offer(record.reach || record.administrator || administrator)
        .sentence("this host")
        .map(|why| format!("--remember: {why}"))
}

/// An unattended attempt, ready before anything is dialed: the prompt ran
/// (§B.8.10: the password comes before the connection).
struct Prepared {
    request: crate::ua_client::Request,
    saved: tornect_core::unattended::credentials::SavedPasswords,
    known: tornect_core::trusted::KnownHost,
}

/// The password prompt of `tornect connect --unattended`, before dialing: a
/// remembered password is used as it is; otherwise one is asked, masked, and
/// only when stdin and stderr are a terminal. `--remember` is refused where the
/// keychain may not keep it (none usable; administrator access, DA-14).
fn prepare_unattended(
    paths: &Paths,
    id: TornectId,
    device: &DeviceIdentity,
    pins: &crate::history::Pins,
    ua: UnattendedOpts,
) -> anyhow::Result<Prepared> {
    use std::io::IsTerminal as _;
    let Some(known) = pins.store().get(&id) else {
        anyhow::bail!(
            "this computer is not paired with that host: connect once without --unattended \
             (its user compares a code), then ask its owner for unattended access"
        );
    };
    let saved = crate::ua_client::system_passwords(device);
    // C6: a password the host's last answer did not let this device keep goes first.
    if let Err(e) = crate::ua_client::belt(paths, &saved, &id) {
        tracing::warn!(error = %format!("{e:#}"), "hosts.toml could not be read");
    }
    let record = crate::ua_client::record(paths, &id);
    if ua.remember
        && let Some(why) = remember_refused(&saved, &record, ua.administrator)
    {
        anyhow::bail!("{why}");
    }
    let password = match crate::ua_client::recall_for_use(paths, &saved, &id)? {
        crate::ua_client::Recalled::Password(password) => {
            eprintln!(
                "using the password remembered in {}",
                saved.keychain().unwrap_or("the keychain")
            );
            password
        }
        other => {
            if matches!(other, crate::ua_client::Recalled::Vanished) {
                eprintln!(
                    "the password remembered for this host is no longer in {}; type it",
                    saved.keychain().unwrap_or("the keychain")
                );
            }
            if record.stale {
                eprintln!(
                    "the password remembered for this host was refused last time and deleted; \
                     type it again"
                );
            }
            if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
                anyhow::bail!(
                    "the unattended password is asked on a terminal, and this is not one: run the \
                     command interactively (Tornect never takes a password from the command line \
                     or the environment)"
                );
            }
            crate::unattended::read_password("Unattended password (not shown): ")?
        }
    };
    if password.is_empty() {
        anyhow::bail!("no password typed; nothing was sent");
    }
    Ok(Prepared {
        request: crate::ua_client::Request {
            password,
            view_only: ua.view_only,
            administrator: ua.administrator,
            remember: ua.remember,
        },
        saved,
        known,
    })
}

/// `tornect connect <onion> [--pair-only] [--forget] [--pings N]`
pub fn connect(
    paths: &Paths,
    onion: &str,
    opts: ConnectOpts,
    bridges: Option<BridgeMode>,
) -> anyhow::Result<()> {
    install_crypto_provider();
    let id = named_host(onion)?;
    let mut cfg = Config::load(&paths.config_file())?;
    if let Some(mode) = bridges {
        cfg.tor.bridges = mode;
    }
    paths.ensure().context("creating Tornect directories")?;
    let store = FileSecretStore::open(paths.keys_dir()).context("opening keystore")?;
    let (device, _) = load_or_create_device_identity(&store)?;
    if opts.forget {
        let known = KnownHostStore::open(tornect_core::trusted::known_hosts_file(paths))
            .context("opening known-hosts.toml")?;
        if known.remove(&id)? {
            crate::host::peer_note(format_args!("forgot {id}; this connection pairs again"));
        }
        // Its remembered unattended password goes too (§B.8.9.1).
        let saved = crate::ua_client::system_passwords(&device);
        if let Err(e) = crate::ua_client::forget(paths, &saved, &id) {
            eprintln!("{e}");
        }
    }
    // With history off the handshake works on a copy of the known hosts, so
    // that its last-seen touch writes nothing (`crate::history`); its
    // pairing times past their first day are kept to the day first (P-L4).
    crate::history::coarsen_pins(paths);
    let pins = crate::history::Pins::open(paths, id).context("opening known-hosts.toml")?;
    let prepared = match opts.unattended {
        Some(ua) => Some(prepare_unattended(paths, id, &device, &pins, ua)?),
        None => None,
    };
    block_on(run_connect(paths, &cfg, id, &device, &pins, opts, prepared))
}

async fn run_connect(
    paths: &Paths,
    cfg: &Config,
    id: TornectId,
    device: &DeviceIdentity,
    pins: &crate::history::Pins,
    opts: ConnectOpts,
    prepared: Option<Prepared>,
) -> anyhow::Result<()> {
    eprintln!("bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...");
    let node = start_tor(paths, cfg).await?;
    let result = connect_session(&node, cfg, paths, id, device, pins, opts, prepared).await;
    node.shutdown().await;
    result
}

#[allow(clippy::too_many_arguments)] // the command's context, one argument each
async fn connect_session(
    node: &TorNode,
    cfg: &Config,
    paths: &Paths,
    id: TornectId,
    device: &DeviceIdentity,
    pins: &crate::history::Pins,
    opts: ConnectOpts,
    prepared: Option<Prepared>,
) -> anyhow::Result<()> {
    use crate::ua_client::{self, Logged};
    // The ID names the host: only a terminal sees it (U3-M1).
    crate::host::peer_note(format_args!(
        "connecting to {id} (rendezvous usually takes 5-30 s, up to 60 s)..."
    ));
    let started = Instant::now();
    // One isolation group for the session: the media stream opened later rides
    // the signaling stream's rendezvous circuit (decision M1-39).
    let isolation = Isolation::new();
    let stream = match node.connect_on(&id, SIGNALING_PORT, &isolation).await {
        Ok(stream) => stream,
        Err(e) => {
            if let Some(p) = &prepared {
                let ended = ua_client::unreachable(&p.known.label);
                ua_client::log_attempt(paths, &p.known, &Logged::Ended(&ended.reason));
                crate::host::peer_note(format_args!("{}", ended.text));
            }
            return Err(explain(e));
        }
    };
    eprintln!("connected in {:.1} s", started.elapsed().as_secs_f64());

    let pairing = !pins.known();
    let ccfg = ClientConfig::new(id, cfg.general.device_name.clone());
    let deps = ClientDeps {
        known_hosts: pins.store(),
        ui: Arc::new(CliPairingUi::new(Prompter::stdin())),
        random: Arc::new(OsRandom),
        // The host's OPAQUE key, pinned in hosts.toml: only unattended
        // sessions consult it.
        server_key_pin: match &prepared {
            Some(_) => Arc::new(ua_client::HostsPin::new(paths)),
            None => Arc::new(NoServerKeyPin),
        },
    };
    let intent = match (&prepared, opts.pair_only) {
        (Some(p), _) => p.request.intent(),
        (None, true) => Intent::PairOnly,
        (None, false) => Intent::Session,
    };
    match (pairing, opts.pair_only, &prepared) {
        (_, _, Some(_)) => eprintln!(
            "checking the password; someone at the host can still block this, or must allow it..."
        ),
        (true, _, None) => {
            eprintln!("new host: pairing first (the host's user compares a code)...");
        }
        (false, true, None) => {}
        (false, false, None) => {
            eprintln!("asking for a session; the host's user has to accept it (up to 110 s)...");
        }
    }
    let outcome = client::connect(stream, &ccfg, device, &deps, intent).await;
    // A pin the handshake made is kept however it ended.
    if let Err(e) = pins.settle() {
        eprintln!("the pairing could not be saved: {e:#}");
    }
    // One attempt, settled once: a refused password is stale, an accepted one
    // kept if asked; nothing is tried again.
    if let (Some(p), Err(e)) = (&prepared, &outcome) {
        let ended = ua_client::ended(e, &p.known.label);
        match ua_client::settle(paths, &p.saved, &id, ended.attempt, &p.request) {
            Ok(settled) => say_notes(&ua_client::refused_notes(
                &format!("\"{}\"", p.known.label),
                p.saved.keychain().unwrap_or("the keychain"),
                ended.attempt,
                &settled,
            )),
            Err(err) => eprintln!("hosts.toml could not be updated: {err:#}"),
        }
        ua_client::log_attempt(paths, &p.known, &Logged::Ended(&ended.reason));
        crate::host::peer_note(format_args!("{}", ended.text));
        anyhow::bail!("the unattended connection did not start ({})", ended.reason);
    }
    let outcome = outcome.map_err(explain_handshake)?;
    let mut session = match outcome {
        ClientOutcome::Paired { host_name } => {
            crate::host::say_evidence(
                format_args!("PAIRED with \"{host_name}\""),
                Some(format_args!("PAIRED")),
            );
            return Ok(());
        }
        ClientOutcome::Session(session) => session,
    };
    let control = matches!(
        tornect_signal::consent::mode_from_code(session.accept().mode()),
        Some(SessionMode::Control)
    );
    let administrator =
        control && session.accept().elevation() == tornect_core::levels::Elevation::Admin;
    let mode = match (control, administrator) {
        (true, true) => "control · administrator",
        (true, false) => "control",
        (false, _) => "view-only",
    };
    let sid = session.session_token().session_id();
    crate::host::say_evidence(
        format_args!(
            "SESSION LIVE {sid} with \"{}\" ({mode})",
            session.host_label()
        ),
        Some(format_args!("SESSION LIVE {sid}")),
    );
    if let Some(p) = &prepared {
        // C1: the verified accept alone decides, before QUIC, by the key decoded from it.
        let after = ua_client::after_accept(
            paths,
            &p.saved,
            &id,
            session.accept(),
            &p.request,
            &format!("\"{}\"", p.known.label),
            session.elevation_withheld(),
        );
        match &after.settled {
            Ok(s) if s.remembered && p.request.remember => eprintln!(
                "the password is remembered in {}{}",
                p.saved.keychain().unwrap_or("the keychain"),
                p.saved
                    .kept()
                    .map(|kept| format!(". {kept}"))
                    .unwrap_or_default()
            ),
            Ok(_) => {}
            Err(e) if after.deleted_first => {
                eprintln!("hosts.toml could not be updated: {e:#}");
            }
            Err(e) => eprintln!("the password could not be remembered: {e:#}"),
        }
        say_notes(&after.notes);
        ua_client::log_attempt(
            paths,
            &p.known,
            &Logged::Session {
                id: &sid,
                control,
                administrator,
            },
        );
        eprintln!("{}", ua_client::badge(control, administrator));
        if let Some(line) = ua_client::fail_summary_text(session.accept().fail_summary()) {
            eprintln!("{line}");
        }
    }
    // The day of the visit, if history is kept; nothing otherwise.
    if let Err(e) = pins.visited() {
        tracing::warn!(error = %format!("{e:#}"), "the visit was not recorded");
    }
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
        let watching = WatchOptions {
            pings: opts.pings,
            quality: opts.quality.unwrap_or(cfg.viewer.quality),
            ..WatchOptions::default()
        };
        watch(
            node,
            &id,
            &isolation,
            &mut session,
            &interrupts.pressed,
            watching,
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
pub(crate) enum End {
    /// This side ended it (Ctrl-C, or `--pings` reached).
    You,
    /// The host sent `BYE{reason}`.
    Host(u16),
    /// The session broke.
    Lost(HandshakeError),
    /// The media stream could not be opened or bound, or it broke.
    NoPicture(anyhow::Error),
}

/// How [`watch()`] receives the screen.
#[derive(Default)]
pub(crate) struct WatchOptions<'a> {
    /// End the session after this many pings; `None` keeps it until the user
    /// ends it.
    pub pings: Option<u32>,
    /// Each event goes to the host: the caller passes one only for a control
    /// session, by the signed `SESSION_ACCEPT`'s mode (SLICE-C2 C2-6).
    pub input: Option<mpsc::Receiver<InputEvent>>,
    /// Every picture, and what the host says about them, also go here (the
    /// window's).
    pub forward: Option<&'a mut dyn FrameSink>,
    /// The preset the `Bind` asks for.
    pub quality: QualityPreset,
    /// The viewer's picks during the session, each sent as a `SetQuality`.
    pub quality_rx: Option<watch::Receiver<QualityPreset>>,
}

/// Open the session's media stream beside the signaling stream and receive
/// the screen, while the signaling stream keeps the session alive. Whichever
/// side ends first ends the other. `interrupted` turning `true` is the user's
/// own end (Ctrl-C, or the window's Stop). `options` say what else goes
/// where.
pub(crate) async fn watch<S>(
    node: &TorNode,
    id: &TornectId,
    isolation: &Isolation,
    session: &mut ClientSession<S>,
    interrupted: &watch::Receiver<bool>,
    options: WatchOptions<'_>,
) -> anyhow::Result<End>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let WatchOptions {
        pings,
        input,
        forward,
        quality,
        quality_rx,
    } = options;
    let binding = Binding::new(session.session_token(), &session.th()).with_quality(quality);
    let opened = async {
        let stream = node
            .connect_on(id, MEDIA_PORT, isolation)
            .await
            .map_err(explain)?;
        MediaViewer::bind(stream, &binding, MEDIA_BIND_WAIT)
            .await
            .map_err(bind_failed)
    };
    let viewer = match unless_interrupted(opened, interrupted).await {
        None => {
            println!("MEDIA ENDED (by you, before the first picture)");
            return Ok(End::You);
        }
        Some(Ok(viewer)) => viewer,
        Some(Err(e)) => {
            println!("MEDIA FAILED: {e:#}");
            return Ok(End::NoPicture(e));
        }
    };
    let bound = *viewer.bound();
    println!("{}", bound_line(&bound));
    let viewer = match quality_rx {
        Some(picks) => viewer.with_quality(picks),
        None => viewer,
    };

    let mut pictures = CliPictures::new(forward);
    let mut stats = ViewerStats::default();
    let (viewed, end) = view(
        viewer,
        session,
        pings,
        interrupted,
        &mut pictures,
        &mut stats,
        input,
    )
    .await;
    pictures.report(&stats);
    let end = end?;
    println!("{}", media_end(&viewed, &end));
    Ok(match (viewed, end) {
        // The picture failed first; the session ended because of it.
        (Err(e), End::You) => End::NoPicture(anyhow::Error::new(e)),
        (_, end) => end,
    })
}

/// A bind that failed, as `MEDIA FAILED` and the window's "No picture" say
/// it: a host of another version reads "binding the media stream: the other
/// computer runs a different version of Tornect; use the same version on
/// both" (the quality design §3.5).
fn bind_failed(e: ViewerError) -> anyhow::Error {
    anyhow::Error::new(e).context("binding the media stream")
}

/// `work`, unless the first Ctrl-C comes first (`None`): opening and binding
/// the media stream can take a minute and a half over Tor, and a Ctrl-C then
/// ends the session at once, not after the open (SLICE-D R2).
async fn unless_interrupted<F: Future>(
    work: F,
    interrupted: &watch::Receiver<bool>,
) -> Option<F::Output> {
    tokio::select! {
        biased;
        () = pressed(interrupted.clone()) => None,
        done = work => Some(done),
    }
}

/// Receive the screen on a bound `viewer` while `session` keeps the session
/// alive; whichever side ends first ends the other. Returns how each ended.
async fn view<M, S>(
    viewer: MediaViewer<M>,
    session: &mut ClientSession<S>,
    pings: Option<u32>,
    interrupted: &watch::Receiver<bool>,
    pictures: &mut dyn FrameSink,
    stats: &mut ViewerStats,
    input: Option<mpsc::Receiver<InputEvent>>,
) -> (Result<ViewerEnd, ViewerError>, anyhow::Result<End>)
where
    M: AsyncRead + AsyncWrite + Unpin + Send,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
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
        let viewed = viewer.run_with_input(pictures, stats, input, stop).await;
        let _ = media_done.send(host_may_have_ended(&viewed));
        viewed
    };
    let signaling = async {
        let stop = async {
            tokio::select! {
                () = pressed(interrupted.clone()) => Ok(()),
                by_host = media_ended => {
                    // The host closed the media stream, or its circuit went:
                    // its `BYE` is usually on the way, and the end should be
                    // reported as the host's. Ctrl-C still cuts the wait short
                    // (SLICE-C2 C2-2).
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
    tokio::join!(viewing, signaling)
}

/// Whether the media stream ended in a way the host's own end of the session
/// explains: its `Close`, its end of stream, or its circuit closing under the
/// stream. Then the host's `BYE` is worth waiting a moment for.
fn host_may_have_ended(viewed: &Result<ViewerEnd, ViewerError>) -> bool {
    matches!(
        viewed,
        Ok(ViewerEnd::Host(_) | ViewerEnd::Closed) | Err(ViewerError::Proto(ProtoError::Io(_)))
    )
}

/// The line that says how the media stream ended.
fn media_end(viewed: &Result<ViewerEnd, ViewerError>, end: &End) -> String {
    // The viewer stops when the session ends, whoever ended it: the host's
    // `BYE` often arrives before its media `Close` (live run, 2026-09-21).
    // And a host that ends the session can lose its media circuit before its
    // `Close` goes out, when tearing capture down takes a moment (the Wayland
    // portal, live run, 2026-09-22): a stream that broke under a session the
    // host ended ended with it.
    match (viewed, end) {
        (Ok(ViewerEnd::Host(reason)), _) => format!(
            "MEDIA ENDED by the host ({})",
            crate::host::media_reason(*reason)
        ),
        (Ok(ViewerEnd::Closed), _) => "MEDIA ENDED (the host closed the stream)".to_owned(),
        (Ok(ViewerEnd::Stopped) | Err(ViewerError::Proto(ProtoError::Io(_))), End::Host(_)) => {
            "MEDIA ENDED by the host (the session ended)".to_owned()
        }
        (Ok(ViewerEnd::Stopped), End::Lost(_)) => "MEDIA ENDED (the session was lost)".to_owned(),
        (Ok(ViewerEnd::Stopped), _) => "MEDIA ENDED (by you)".to_owned(),
        (Err(e), _) => format!("MEDIA FAILED: {e}"),
    }
}

/// The CLI's stand-in for a viewer window: counts what it decodes, says so every
/// few seconds, and checks the test card's frame index when there is one. It
/// says what the host applies when that changes, and the host's means with
/// its own, each at most once a second. The window, when there is one, gets
/// every picture and every word from the host too (`forward`).
struct CliPictures<'a> {
    forward: Option<&'a mut dyn FrameSink>,
    started: Instant,
    last_note: Instant,
    decoded: u64,
    size: Option<(u32, u32)>,
    /// The first and last test-card index, while every picture has carried the
    /// next one, or the last again just after a change of what the host
    /// applies (a quality change encodes the last picture again).
    card: Option<(u32, u32)>,
    card_in_order: bool,
    /// The host said it applies something new since the last picture.
    changed_since_picture: bool,
    /// What the host last said it applies, at which exact size.
    said: Option<(u32, u32, QualityInfo)>,
    /// When the last `MEDIA QUALITY` and `MEDIA TIMING` lines went out.
    quality_line: Option<Instant>,
    timing_line: Option<Instant>,
    /// This viewer's decode and conversion since the last `MEDIA TIMING`
    /// line: sums in µs, and the pictures.
    decode_us: u64,
    convert_us: u64,
    timed: u64,
}

impl<'a> CliPictures<'a> {
    fn new(forward: Option<&'a mut dyn FrameSink>) -> Self {
        let now = Instant::now();
        Self {
            forward,
            started: now,
            last_note: now,
            decoded: 0,
            size: None,
            card: None,
            card_in_order: true,
            changed_since_picture: false,
            said: None,
            quality_line: None,
            timing_line: None,
            decode_us: 0,
            convert_us: 0,
            timed: 0,
        }
    }

    fn fps(&self) -> f64 {
        self.decoded as f64 / self.started.elapsed().as_secs_f64().max(0.001)
    }

    fn report(&self, stats: &ViewerStats) {
        for line in self.report_lines(stats) {
            println!("{line}");
        }
    }

    /// The lines that end a stream: `MEDIA OK` (its wording is what the
    /// evidence drivers match), the card's order, the input sent, and what
    /// the host last said it applies.
    fn report_lines(&self, stats: &ViewerStats) -> Vec<String> {
        let secs = self.started.elapsed().as_secs_f64().max(0.001);
        let (w, h) = self.size.unwrap_or_default();
        let mut lines = vec![format!(
            "MEDIA {} pictures={} units={} keyframes={} errors={} size={w}x{h} fps={:.1} kbps={:.0}",
            if self.decoded > 0 { "OK" } else { "EMPTY" },
            self.decoded,
            stats.access_units,
            stats.keyframes,
            stats.decode_errors,
            self.fps(),
            stats.bytes as f64 * 8.0 / 1000.0 / secs,
        )];
        // Only a test card carries an index in every picture, in order.
        if let Some((first, last)) = self.card.filter(|_| self.card_in_order && self.decoded > 1) {
            lines.push(format!("MEDIA CARD first={first} last={last} in-order"));
        }
        if stats.input_sent > 0 {
            lines.push(format!("MEDIA INPUT sent={}", stats.input_sent));
        }
        // The last value is always in the report, also when the one-second
        // limit held its line back.
        if let Some((width, height, quality)) = self.said {
            lines.push(quality_line(width, height, &quality));
        }
        lines
    }

    /// What the host applies changed (`FrameSink::quality`): the line to
    /// print now, if any. The first is `BindOk`'s, which the `MEDIA BOUND`
    /// line already said; later ones go out at most once a second.
    fn quality_at(
        &mut self,
        width: u32,
        height: u32,
        quality: &QualityInfo,
        now: Instant,
    ) -> Option<String> {
        let first = self.said.is_none();
        self.said = Some((width, height, *quality));
        self.changed_since_picture = !first;
        if first {
            return None;
        }
        if self
            .quality_line
            .is_some_and(|at| now.duration_since(at) < MEDIA_LINE_EVERY)
        {
            // The report says the last value.
            return None;
        }
        self.quality_line = Some(now);
        Some(quality_line(width, height, quality))
    }

    /// The host's means arrived (`FrameSink::host_stats`): the `MEDIA
    /// TIMING` line to print now, with this viewer's own means since the
    /// last one, at most once a second.
    fn host_stats_at(&mut self, host: &HostStats, now: Instant) -> Option<String> {
        if self
            .timing_line
            .is_some_and(|at| now.duration_since(at) < MEDIA_LINE_EVERY)
        {
            return None;
        }
        self.timing_line = Some(now);
        let line = timing_line(
            mean_us(self.decode_us, self.timed),
            mean_us(self.convert_us, self.timed),
            host,
        );
        (self.decode_us, self.convert_us, self.timed) = (0, 0, 0);
        Some(line)
    }
}

/// `sum` over `n`, 0 for none.
fn mean_us(sum: u64, n: u64) -> u64 {
    sum.checked_div(n).unwrap_or(0)
}

/// `d` in whole microseconds, saturating.
fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

/// A preset's config name from its wire code.
fn preset_name(code: u8) -> String {
    tornect_session::quality::preset(code)
        .map_or_else(|| format!("preset-{code}"), |p| p.as_str().to_owned())
}

/// What a `QualityInfo` says, as the `MEDIA` lines put it:
/// `quality=balanced fps<=15 kbps=1500 cap=1920x1080`.
fn quality_fields(quality: &QualityInfo) -> String {
    format!(
        "quality={} fps<={} kbps={} cap={}x{}",
        preset_name(quality.preset),
        quality.max_fps,
        quality.kbps,
        quality.max_long,
        quality.max_short
    )
}

/// The line that says the stream is bound (the quality design §3.5):
/// `MEDIA BOUND 1280x720 (control) quality=balanced fps<=15 kbps=1500
/// cap=1920x1080`.
fn bound_line(bound: &tornect_session::BoundStream) -> String {
    format!(
        "MEDIA BOUND {}x{} ({}) {}",
        bound.width,
        bound.height,
        match bound.mode {
            SessionMode::ViewOnly => "view-only",
            _ => "control",
        },
        quality_fields(&bound.quality)
    )
}

/// The line that says what the host applies now: `MEDIA QUALITY
/// quality=best-performance fps<=20 kbps=1000 cap=1280x720 size=1280x694`.
fn quality_line(width: u32, height: u32, quality: &QualityInfo) -> String {
    format!(
        "MEDIA QUALITY {} size={width}x{height}",
        quality_fields(quality)
    )
}

/// The line of per-stage means (the quality design §3.5): this viewer's
/// decode and conversion, the host's stages, the ack round trip and the
/// source size. Every number from the host is display-only.
fn timing_line(decode_us: u64, convert_us: u64, host: &HostStats) -> String {
    format!(
        "MEDIA TIMING decode_ms={} yuv2rgb_ms={} host_grab_ms={} host_age_ms={} \
         host_scale_ms={} host_convert_ms={} host_encode_ms={} host_send_ms={} ack_ms={} \
         source={}x{}",
        ms_field(decode_us),
        ms_field(convert_us),
        ms_field(u64::from(host.grab_us)),
        ms_field(u64::from(host.age_us)),
        ms_field(u64::from(host.scale_us)),
        ms_field(u64::from(host.convert_us)),
        ms_field(u64::from(host.encode_us)),
        ms_field(u64::from(host.send_us)),
        ms_field(u64::from(host.ack_us)),
        host.source_width,
        host.source_height,
    )
}

/// µs as a `_ms=` value: one decimal under 10 ms (`3.1`), whole
/// milliseconds from there (`120`, `1100`).
fn ms_field(us: u64) -> String {
    let tenths = us.saturating_add(50) / 100;
    if tenths < 100 {
        format!("{}.{}", tenths / 10, tenths % 10)
    } else {
        (us.saturating_add(500) / 1000).to_string()
    }
}

impl FrameSink for CliPictures<'_> {
    fn quality(&mut self, width: u32, height: u32, quality: &QualityInfo) {
        if let Some(forward) = self.forward.as_deref_mut() {
            forward.quality(width, height, quality);
        }
        if let Some(line) = self.quality_at(width, height, quality, Instant::now()) {
            println!("{line}");
        }
    }

    fn host_stats(&mut self, stats: &HostStats) {
        if let Some(forward) = self.forward.as_deref_mut() {
            forward.host_stats(stats);
        }
        if let Some(line) = self.host_stats_at(stats, Instant::now()) {
            println!("{line}");
        }
    }

    fn picture(&mut self, seq: u32, frame: &DecodedFrame) {
        if let Some(forward) = self.forward.as_deref_mut() {
            forward.picture(seq, frame);
        }
        self.decoded += 1;
        self.decode_us = self.decode_us.saturating_add(micros(frame.timing.decode));
        self.convert_us = self.convert_us.saturating_add(micros(frame.timing.convert));
        self.timed += 1;
        // Sized from the picture itself, never from `BindOk` (SLICE-A2 A2-4).
        self.size = Some((frame.width, frame.height));
        // RGBA keeps green at offset 1, as the BGRx the card is drawn in does.
        let index = TestCard::read_index(&frame.rgba, frame.width, frame.height);
        let repeat_allowed = std::mem::take(&mut self.changed_since_picture);
        self.card = match (self.card, index) {
            (None, Some(index)) if self.decoded == 1 => Some((index, index)),
            (Some((first, last)), Some(index))
                if index == last.wrapping_add(1) || (repeat_allowed && index == last) =>
            {
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
/// that keeps sending cannot keep `--pings N` from ending (SLICE-B2 B2-8):
/// M2 frames come back here and wait for the same `next_ping`, and a host
/// `PING` is answered inside `next_event`, whose one deadline it does not move
/// either (SLICE-D D2).
///
/// Between pings it waits on the stream, not on a timer, so a host `BYE` is
/// reported the moment it arrives. Over Tor the host's circuit is often gone
/// by the next ping, whose write would then fail first and turn a deliberate
/// end (`tornect panic`) into "connection lost". Cutting that wait short
/// cannot drop part of a frame: after the accept an honest host sends nothing
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

/// A ping's nonce: random bytes from the OS. It only needs to be unique per
/// stream, and it must say nothing about this computer: the wall clock it
/// was made from before told the pinged host this computer's time (the
/// privacy finding P-L1).
pub(crate) fn nonce() -> anyhow::Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRandom
        .fill(&mut nonce)
        .map_err(|e| anyhow::anyhow!("no random nonce for the ping: {e}"))?;
    Ok(nonce)
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
pub(crate) fn explain(err: SignalError) -> anyhow::Error {
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
pub(crate) fn explain_handshake(err: HandshakeError) -> anyhow::Error {
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

    /// Design `invite` §2.5: `connect`, `ping` and `admin` take the host's ID
    /// bare, grouped, with `.onion`, as a `tornect:` link or inside a whole
    /// pasted invitation. A refusal reads "that is not a Tornect ID: <the
    /// problem>" and never echoes what was given (L-7): not a typo'd ID, not a
    /// link's parameters, not the text around it.
    #[test]
    fn a_command_takes_an_id_a_link_or_an_invitation_and_never_echoes_it() {
        use tornect_core::invite::{self, IdProblem};
        let id = TornectId::from_public_key(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
        );
        for given in [
            id.base32(),
            id.onion_address(),
            id.display_groups(),
            invite::link(&id),
            format!("tornect:{}", id.base32().to_uppercase()),
            invite::invitation(&id),
            format!("my id is {}, thanks", id.display_groups()),
        ] {
            assert_eq!(named_host(&given).unwrap(), id, "{given}");
        }
        let mut typo = id.base32();
        typo.replace_range(10..11, if &typo[10..11] == "a" { "b" } else { "a" });
        let other = TornectId::from_public_key(
            &ed25519_dalek::SigningKey::from_bytes(&[8; 32]).verifying_key(),
        );
        for (given, problem) in [
            (String::new(), IdProblem::Empty),
            (typo.clone(), IdProblem::Checksum),
            (
                format!("{}?secret=hunter2", invite::link(&id)),
                IdProblem::LinkExtras,
            ),
            (
                format!("{} {}", invite::link(&id), invite::link(&other)),
                IdProblem::Several,
            ),
            (
                "see you at the cafe on main street at noon".to_owned(),
                IdProblem::NoId,
            ),
            ("call me at noon".to_owned(), IdProblem::Short { found: 12 }),
        ] {
            let err = named_host(&given).unwrap_err().to_string();
            assert_eq!(
                err,
                format!("that is not a Tornect ID: {problem}"),
                "{given}"
            );
            for part in given.split_whitespace() {
                assert!(
                    part.len() < 4 || !err.contains(part),
                    "{part:?} echoed: {err}"
                );
            }
            assert!(
                !err.contains(&id.base32()) && !err.contains("hunter2"),
                "{err}"
            );
        }
    }

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

    /// The quality design §3.5: the `MEDIA` lines of the presets, as the
    /// design words them, and the numbers' format (one decimal under 10 ms,
    /// whole milliseconds from there; every host value saturates).
    #[test]
    fn the_media_lines_say_the_preset_and_the_stage_means() {
        use tornect_session::BoundStream;
        let balanced = QualityInfo {
            preset: tornect_proto::quality::BALANCED,
            max_fps: 15,
            kbps: 1500,
            max_long: 1920,
            max_short: 1080,
        };
        let mut bound = BoundStream {
            width: 1280,
            height: 720,
            mode: SessionMode::Control,
            quality: balanced,
        };
        assert_eq!(
            bound_line(&bound),
            "MEDIA BOUND 1280x720 (control) quality=balanced fps<=15 kbps=1500 cap=1920x1080"
        );
        bound.mode = SessionMode::ViewOnly;
        assert!(bound_line(&bound).starts_with("MEDIA BOUND 1280x720 (view-only) quality="));
        let performance = QualityInfo {
            preset: tornect_proto::quality::BEST_PERFORMANCE,
            max_fps: 20,
            kbps: 1000,
            max_long: 1280,
            max_short: 720,
        };
        assert_eq!(
            quality_line(1280, 694, &performance),
            "MEDIA QUALITY quality=best-performance fps<=20 kbps=1000 cap=1280x720 size=1280x694"
        );
        let host = HostStats {
            source_width: 2560,
            source_height: 1440,
            frames: 15,
            window_ms: 1000,
            grab_us: 4000,
            age_us: 6200,
            scale_us: 2100,
            convert_us: 1500,
            encode_us: 9800,
            send_us: 120_000,
            ack_us: 1_100_000,
        };
        assert_eq!(
            timing_line(3100, 1200, &host),
            "MEDIA TIMING decode_ms=3.1 yuv2rgb_ms=1.2 host_grab_ms=4.0 host_age_ms=6.2 \
             host_scale_ms=2.1 host_convert_ms=1.5 host_encode_ms=9.8 host_send_ms=120 \
             ack_ms=1100 source=2560x1440"
        );
        for (us, text) in [
            (0, "0.0"),
            (49, "0.0"),
            (50, "0.1"),
            (9_949, "9.9"),
            (9_950, "10"),
            (999_499, "999"),
            (1_100_000, "1100"),
            (u64::from(u32::MAX), "4294967"),
            (u64::MAX, "18446744073709551"),
        ] {
            assert_eq!(ms_field(us), text, "{us} µs");
        }
        let unknown = QualityInfo {
            preset: 9,
            ..balanced
        };
        assert!(quality_line(8, 2, &unknown).contains("quality=preset-9 "));
    }

    /// The quality design §3.5: a host of another version is said as such,
    /// on the `MEDIA FAILED` line and in the window's "No picture" note.
    #[test]
    fn a_host_of_another_version_is_said_on_the_failed_line() {
        assert_eq!(
            format!("MEDIA FAILED: {:#}", bind_failed(ViewerError::Version)),
            "MEDIA FAILED: binding the media stream: the other computer runs a different \
             version of Tornect; use the same version on both"
        );
    }

    /// A picture of the test card at `index`, as the decoder lends it (the
    /// card's BGRx keeps green where RGBA does, which is what the index is
    /// read from).
    fn card_picture(width: u32, height: u32, index: u32) -> DecodedFrame {
        DecodedFrame {
            width,
            height,
            rgba: TestCard::render(width, height, index),
            timing: tornect_codec::DecodeTiming {
                decode: Duration::from_micros(3000),
                convert: Duration::from_micros(1000),
            },
        }
    }

    /// The quality design §3.5: `MEDIA CARD … in-order` accepts the last
    /// index again right after the host said it applies something new (a
    /// quality change encodes the last picture again), and nowhere else.
    #[test]
    fn the_card_check_takes_a_repeat_only_after_a_quality_change() {
        let balanced = QualityInfo {
            preset: tornect_proto::quality::BALANCED,
            max_fps: 15,
            kbps: 1500,
            max_long: 1920,
            max_short: 1080,
        };
        let performance = QualityInfo {
            preset: tornect_proto::quality::BEST_PERFORMANCE,
            ..balanced
        };
        let stats = ViewerStats::default();
        let card_line = |pictures: &CliPictures<'_>| {
            pictures
                .report_lines(&stats)
                .into_iter()
                .find(|line| line.starts_with("MEDIA CARD"))
        };

        let mut pictures = CliPictures::new(None);
        pictures.quality(256, 96, &balanced);
        for index in [5, 6] {
            pictures.picture(index, &card_picture(256, 96, index));
        }
        pictures.quality(256, 96, &performance);
        for index in [6, 7, 8] {
            pictures.picture(index, &card_picture(256, 96, index));
        }
        assert_eq!(
            card_line(&pictures).as_deref(),
            Some("MEDIA CARD first=5 last=8 in-order")
        );

        // The same index again with no change before it is out of order.
        let mut pictures = CliPictures::new(None);
        pictures.quality(256, 96, &balanced);
        for index in [5, 6, 6, 7] {
            pictures.picture(index, &card_picture(256, 96, index));
        }
        assert_eq!(card_line(&pictures), None);

        // A change lets one repeat through, not two.
        let mut pictures = CliPictures::new(None);
        pictures.quality(256, 96, &balanced);
        pictures.picture(0, &card_picture(256, 96, 5));
        pictures.quality(256, 96, &performance);
        for index in [5, 5] {
            pictures.picture(index, &card_picture(256, 96, index));
        }
        assert_eq!(card_line(&pictures), None);
    }

    /// Records what a `CliPictures` forwards.
    #[derive(Default)]
    struct Forwarded {
        pictures: Vec<u32>,
        said: Vec<(u32, u32, QualityInfo)>,
        host: Vec<HostStats>,
    }

    impl FrameSink for Forwarded {
        fn picture(&mut self, seq: u32, _: &DecodedFrame) {
            self.pictures.push(seq);
        }

        fn quality(&mut self, width: u32, height: u32, quality: &QualityInfo) {
            self.said.push((width, height, *quality));
        }

        fn host_stats(&mut self, stats: &HostStats) {
            self.host.push(*stats);
        }
    }

    /// The quality design §3.5: the `MEDIA QUALITY` line goes out when what
    /// the host applies changes (not for `BindOk`'s, which `MEDIA BOUND`
    /// says), at most once a second, and the last value is always in the
    /// final report; `MEDIA TIMING` goes out with a host's means at most
    /// once a second, with this viewer's means since the line before. The
    /// window gets every picture and every word from the host whatever the
    /// terminal prints.
    #[test]
    fn the_quality_and_timing_lines_are_rate_limited_and_the_window_gets_all() {
        let balanced = QualityInfo {
            preset: tornect_proto::quality::BALANCED,
            max_fps: 15,
            kbps: 1500,
            max_long: 1920,
            max_short: 1080,
        };
        let quick = QualityInfo {
            preset: tornect_proto::quality::BEST_PERFORMANCE,
            max_fps: 20,
            kbps: 1000,
            max_long: 1280,
            max_short: 720,
        };
        let sharp = QualityInfo {
            preset: tornect_proto::quality::BEST_QUALITY,
            max_fps: 12,
            kbps: 4000,
            max_long: 3840,
            max_short: 2160,
        };
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut window = Forwarded::default();
        let mut pictures = CliPictures::new(Some(&mut window));
        assert_eq!(pictures.quality_at(1600, 900, &balanced, at(0)), None);
        assert_eq!(
            pictures.quality_at(1280, 720, &quick, at(10)).as_deref(),
            Some(
                "MEDIA QUALITY quality=best-performance fps<=20 kbps=1000 cap=1280x720 \
                 size=1280x720"
            )
        );
        assert_eq!(pictures.quality_at(1600, 900, &sharp, at(500)), None);
        let host = |frames| HostStats {
            source_width: 1600,
            source_height: 900,
            frames,
            window_ms: 1000,
            encode_us: 9800,
            ..HostStats::default()
        };
        pictures.picture(1, &card_picture(64, 48, 1));
        pictures.picture(2, &card_picture(64, 48, 2));
        let first = pictures.host_stats_at(&host(1), at(600)).unwrap();
        assert!(
            first.starts_with("MEDIA TIMING decode_ms=3.0 yuv2rgb_ms=1.0 host_grab_ms=0.0 "),
            "{first}"
        );
        assert!(first.contains(" host_encode_ms=9.8 "), "{first}");
        assert!(first.ends_with(" source=1600x900"), "{first}");
        assert_eq!(pictures.host_stats_at(&host(2), at(1500)), None);
        let next = pictures.host_stats_at(&host(3), at(1600)).unwrap();
        assert!(
            next.starts_with("MEDIA TIMING decode_ms=0.0 yuv2rgb_ms=0.0 "),
            "no picture since the line before: {next}"
        );
        let report = pictures.report_lines(&ViewerStats::default());
        assert_eq!(
            report.last().map(String::as_str),
            Some(
                "MEDIA QUALITY quality=best-quality fps<=12 kbps=4000 cap=3840x2160 \
                 size=1600x900"
            ),
            "{report:?}"
        );
        assert!(report[0].starts_with("MEDIA OK pictures=2 "), "{report:?}");

        // Through the hooks, everything reaches the window.
        pictures.quality(1600, 900, &balanced);
        pictures.host_stats(&host(4));
        pictures.picture(3, &card_picture(64, 48, 3));
        assert_eq!(window.said, [(1600, 900, balanced)]);
        assert_eq!(window.host, [host(4)]);
        assert_eq!(window.pictures, [1, 2, 3]);
    }

    /// A live session's media stream, whose host end took the `Bind` and
    /// answered `BindOk`; when the host drops its end, reads fail the way a
    /// Tor circuit that closes fails them, not as a clean end of stream.
    struct Collapsing(DuplexStream);

    impl AsyncRead for Collapsing {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            match std::pin::Pin::new(&mut self.0).poll_read(cx, buf) {
                Poll::Ready(Ok(())) if buf.filled().len() == before => Poll::Ready(Err(
                    std::io::Error::new(std::io::ErrorKind::ConnectionReset, "Circuit closed"),
                )),
                other => other,
            }
        }
    }

    impl AsyncWrite for Collapsing {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    /// Phase B wording race (live run, 2026-09-22): the host ends the session,
    /// and its media circuit closes before its closing message arrives. The
    /// client said "MEDIA FAILED: media stream I/O: Circuit closed" for a
    /// session the host had ended on purpose (`tornect panic`).
    #[tokio::test(start_paused = true)]
    async fn a_host_end_whose_media_circuit_closes_first_is_the_hosts() {
        use tornect_proto::{Msg, QualityInfo, codec, quality, read_msg, write_msg};
        let Live {
            mut session,
            kill,
            host,
            ..
        } = live().await;
        let binding = Binding::new(session.session_token(), &session.th());
        let (client_media, mut host_media) = duplex(1 << 16);
        let media_host = tokio::spawn(async move {
            let bind = read_msg(&mut host_media).await.unwrap();
            assert!(matches!(bind, Some(Msg::Bind { .. })), "{bind:?}");
            let ok = Msg::BindOk {
                width: 640,
                height: 360,
                codec: codec::H264,
                mode: 1,
                quality: QualityInfo {
                    preset: quality::BALANCED,
                    max_fps: 15,
                    kbps: 1500,
                    max_long: 3840,
                    max_short: 2160,
                },
            };
            write_msg(&mut host_media, &ok).await.unwrap();
            host_media
        });
        let viewer = MediaViewer::bind(Collapsing(client_media), &binding, MEDIA_BIND_WAIT)
            .await
            .unwrap();
        let host_media = media_host.await.unwrap();
        // The host ends the session: its media circuit goes first, its BYE
        // comes a moment later.
        tokio::spawn(async move {
            drop(host_media);
            tokio::time::sleep(Duration::from_millis(100)).await;
            kill.kill(bye::PANIC);
        });
        let (_ctrl_c, interrupted) = watch::channel(false);
        let (mut pictures, mut stats) = (CliPictures::new(None), ViewerStats::default());
        let (viewed, end) = view(
            viewer,
            &mut session,
            None,
            &interrupted,
            &mut pictures,
            &mut stats,
            None,
        )
        .await;
        let end = end.unwrap();
        assert_eq!(
            media_end(&viewed, &end),
            "MEDIA ENDED by the host (the session ended)"
        );
        assert!(
            matches!(end, End::Host(reason) if reason == bye::PANIC),
            "{end:?}"
        );
        host.await.unwrap().unwrap();
    }

    /// C11 (decision M1-67): `--remember` is refused before dialing where
    /// `hosts.toml` says that the host's last answer reached administrator
    /// access, left the key out or was refused, as without a keychain and with
    /// the level asked for; the refusal names no host. Otherwise it is not.
    #[test]
    fn remember_is_refused_before_dialing_where_reach_is_set() {
        use tornect_core::unattended::credentials::{MemoryVault, NO_KEYCHAIN, SavedPasswords};
        use tornect_core::unattended::hosts::HostRecord;
        let saved = SavedPasswords::new(Some(Arc::new(MemoryVault::new())), [1; 32]);
        let plain = HostRecord::default();
        assert_eq!(remember_refused(&saved, &plain, false), None);
        let reach = HostRecord {
            reach: true,
            ..HostRecord::default()
        };
        let why = remember_refused(&saved, &reach, false).expect("refused");
        assert_eq!(
            why,
            "--remember: A password that can reach administrator access on this host, or that \
             this host did not rule out, is never remembered."
        );
        assert_eq!(remember_refused(&saved, &plain, true), Some(why.clone()));
        let administrator = HostRecord {
            administrator: true,
            ..HostRecord::default()
        };
        assert_eq!(remember_refused(&saved, &administrator, false), Some(why));
        assert_eq!(
            remember_refused(&SavedPasswords::none([1; 32]), &plain, false),
            Some(format!("--remember: {NO_KEYCHAIN}"))
        );
    }

    /// SLICE-C3 C3-5: the banner says "this desktop" only where a desktop can
    /// be captured, and otherwise says that nothing will be, and why.
    #[test]
    fn the_banner_names_only_a_desktop_that_can_be_shared() {
        let why = "not a Wayland or X11 session (XDG_SESSION_TYPE=tty)";
        let refused = describe_source(
            Source::Desktop,
            &DesktopBackend::Unavailable(why.to_owned()),
        );
        assert!(refused.starts_with("sharing: nothing"), "{refused}");
        assert!(refused.contains(why), "{refused}");
        assert!(describe_source(Source::Desktop, &DesktopBackend::X11).contains("X11"));
        assert!(describe_source(Source::Desktop, &DesktopBackend::Wayland).contains("portal"));
        let card = describe_source(Source::TestCard, &DesktopBackend::Unavailable(why.into()));
        assert!(card.contains("test card"), "{card}");
        let screens = describe_source(Source::TestScreens, &DesktopBackend::X11);
        assert_eq!(
            screens,
            "sharing: two synthetic test screens side by side, 1280x720 (main) and 1024x768 \
             (no desktop; viewers' input goes nowhere)"
        );
    }

    /// SLICE-C3 C3-5 and the Wayland grant's revocation: `doctor` names the
    /// backend truthfully, and on Wayland the file whose deletion revokes the
    /// desktop's remembered grant.
    #[test]
    fn doctor_names_the_capture_backend_and_how_to_revoke_the_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let token = paths.portal_restore_token().display().to_string();
        let wayland = capture_lines(&paths, &DesktopBackend::Wayland).join("\n");
        assert!(wayland.contains("capture: wayland"), "{wayland}");
        assert!(wayland.contains(&token), "{wayland}");
        assert!(wayland.contains("absent"), "{wayland}");
        assert!(wayland.contains("delete"), "{wayland}");
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        std::fs::write(paths.portal_restore_token(), "t").unwrap();
        let kept = capture_lines(&paths, &DesktopBackend::Wayland).join("\n");
        assert!(kept.contains("present"), "{kept}");
        let x11 = capture_lines(&paths, &DesktopBackend::X11).join("\n");
        assert!(x11.contains("capture: x11"), "{x11}");
        assert!(!x11.contains("out of scope"), "{x11}");
        let none = capture_lines(&paths, &DesktopBackend::Unavailable("no seat".into())).join("\n");
        assert!(none.contains("capture: none (no seat)"), "{none}");
    }

    /// SLICE-D R2: the first Ctrl-C while the media stream opens and binds
    /// (up to a minute and a half over Tor) ends the wait at once. Before, it
    /// was heard and printed, but acted on only once the open had finished.
    #[tokio::test(start_paused = true)]
    async fn a_ctrl_c_while_the_media_stream_opens_ends_the_wait() {
        let (ctrl_c, interrupted) = watch::channel(false);
        let started = tokio::time::Instant::now();
        let press = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            ctrl_c.send_replace(true);
        };
        let (opened, ()) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(60),
                unless_interrupted(std::future::pending::<()>(), &interrupted),
            ),
            press
        );
        assert_eq!(opened, Ok(None), "the open outlived the Ctrl-C");
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        let (_quiet, untouched) = watch::channel(false);
        assert_eq!(unless_interrupted(async { 5 }, &untouched).await, Some(5));
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
        let started = tokio::time::Instant::now();
        let left = tokio::time::timeout(Duration::from_secs(60), session.bye(bye::USER)).await;
        assert!(
            matches!(left, Ok(Err(HandshakeError::Timeout(_)))),
            "{left:?}"
        );
        // Exactly the bound, not merely under the envelope (SLICE-D R9).
        assert_eq!(
            started.elapsed(),
            tornect_signal::fsm::timeouts::BYE,
            "bye gave up after something other than timeouts::BYE"
        );
    }

    /// Leaving waits until the host has read the `BYE` and closed. Over Tor a
    /// flushed `BYE` was lost when the client shut its node down straight
    /// after, and the host logged the session's end as an I/O error (live run,
    /// 2026-09-22).
    #[tokio::test(start_paused = true)]
    async fn leaving_waits_until_the_host_has_read_the_bye() {
        use tornect_signal::fsm::host::{HostOutcome, SessionEnd};
        let Live { session, host, .. } = live().await;
        session.bye(bye::USER).await.unwrap();
        assert!(host.is_finished(), "the host had not read the BYE yet");
        let outcome = host.await.unwrap().unwrap();
        assert!(
            matches!(
                outcome,
                HostOutcome::Session {
                    end: SessionEnd::PeerBye(reason),
                    ..
                } if reason == bye::USER
            ),
            "{outcome:?}"
        );
    }
}
