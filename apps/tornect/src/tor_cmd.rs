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
use tornect_net::CandidateKind;
use tornect_proto::services::Welcome;
use tornect_proto::{ALL_MONITORS, HostStats, ProtoError, QualityInfo, monitor_status};
use tornect_session::services::{
    ServicesBindError, ServicesBinding, ServicesHost, ServicesViewer, ViewerEvent, ViewerLocal,
    ViewerOp, ViewerServicesEnd,
};
use tornect_session::{
    AfterBind, Binding, Decision, DesktopBackend, DirectBindFailed, FallbackWhy, FrameSink,
    MediaHost, MediaLimits, MediaViewer, PathChoice, PathEnd, QuicStream, Screens, ScreensNews,
    Source, SystemBackend, TorWhy, ViewerChannels, ViewerEnd, ViewerError, ViewerRequest,
    ViewerStats, decide,
};
use tornect_signal::framing::FrameError;
use tornect_signal::fsm::client::{
    self, ClientConfig, ClientDeps, ClientOutcome, ClientSession, Intent, NoServerKeyPin,
    SessionEvent,
};
use tornect_signal::fsm::{HandshakeError, OsRandom, Randomness as _};
use tornect_signal::messages::{bye, fallback, feats, pair_reject, reject};
use tornect_signal::pairing::KnownHostStore;
use tornect_signal::ping::NONCE_LEN;
use tornect_signal::tor::Admission;
use tornect_signal::{
    Isolation, Ladder, LadderEvent, MEDIA_PORT, OnionStatus, SERVICES_PORT, SIGNALING_PORT,
    SignalError, TorNode, install_crypto_provider, ping, shutdown_runtime,
};

use crate::direct::{DirectCtx, DirectKnobs, DirectWiring};
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
/// host's own first-picture deadline (10 s) plus a Tor round trip or two. A
/// direct bind waits as long, never only the punch window: the host's source
/// can take a desktop dialog's time to open (design `direct` §4, revision 1
/// blocker 1).
const MEDIA_BIND_WAIT: Duration = Duration::from_secs(30);

/// How long an onion media stream opened beside the path phase stays
/// usable (design `direct` §4 `ONION_PREOPEN_MAX`), counted from the start
/// of its open: an older one is dropped and a fresh one opened. The host's
/// bind deadline (`MediaLimits::bind_deadline`, 10 s) runs from its accept
/// of the stream, which comes after the open started by at least the open's
/// trip to the host; the `Bind` takes the same trip on the same circuit. So
/// a `Bind` written before this age reaches the host within this age of its
/// accept, whatever the circuit's delay, and this must stay below the
/// host's deadline (a test holds the margin).
const ONION_PREOPEN_MAX: Duration = Duration::from_secs(8);

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
    let direct = DirectWiring::real(Arc::new(device), DirectKnobs::new(&cfg));
    block_on(run_host(
        paths,
        &cfg,
        Arc::new(identity),
        direct,
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
/// desktop's remembered grant, whose deletion revokes it: the file of the
/// portal request a host with `cfg` makes (`[services] wayland_clipboard`),
/// with a line saying the clipboard is asked for when it is. The path is
/// printed for the owner and never logged.
pub(crate) fn capture_lines(paths: &Paths, cfg: &Config, desktop: &DesktopBackend) -> Vec<String> {
    let mut lines = vec![match desktop {
        DesktopBackend::Wayland => {
            "capture: wayland (the RemoteDesktop portal and PipeWire)".to_owned()
        }
        DesktopBackend::X11 => "capture: x11 (the X11 grab and XTEST)".to_owned(),
        DesktopBackend::Gdi => "capture: gdi (GDI and SendInput)".to_owned(),
        DesktopBackend::Unavailable(why) => format!("capture: none ({why})"),
    }];
    if *desktop == DesktopBackend::Wayland {
        let token = crate::host::portal_token(paths, cfg);
        lines.push(format!(
            "  desktop grant: {} [{}]; delete it to revoke the remembered grant, and the \
             desktop asks again at the next session",
            token.display(),
            if token.exists() { "present" } else { "absent" }
        ));
        if cfg.services.wayland_clipboard {
            lines.push(
                "  desktop clipboard: asked for with the screen ([services] wayland_clipboard)"
                    .to_owned(),
            );
        }
        // A grant the other request made (the switch stood the other way)
        // is restored again once the switch is turned back.
        let other = paths.portal_restore_token_for(!cfg.services.wayland_clipboard);
        if other.exists() {
            lines.push(format!(
                "  other desktop grant: {} [present], made {} the clipboard; delete it too to \
                 revoke every remembered grant",
                other.display(),
                if cfg.services.wayland_clipboard {
                    "without"
                } else {
                    "with"
                }
            ));
        }
    }
    lines
}

/// `tornect doctor`'s `screens:` line: the monitors a session on this
/// desktop could switch between, numbered as a session lists them, in the
/// desktop's units (physical pixels on Windows and X11). `None` where
/// capture lists none: on Wayland the desktop's dialog chooses the screen.
pub(crate) fn screens_line(desktop: &DesktopBackend) -> Option<String> {
    desktop_monitors(desktop).map(|listed| screens_text(&listed))
}

/// The monitors of this desktop as a session would number them, on X11 and
/// Windows; `None` where capture lists none (Wayland: the desktop's dialog
/// chooses the screen).
pub(crate) fn desktop_monitors(
    desktop: &DesktopBackend,
) -> Option<Result<Vec<tornect_capture::Monitor>, tornect_capture::CaptureError>> {
    match desktop {
        #[cfg(target_os = "linux")]
        DesktopBackend::X11 => Some(tornect_capture::x11::desktop_monitors()),
        #[cfg(windows)]
        DesktopBackend::Gdi => Some(tornect_capture::gdi::desktop_monitors()),
        _ => None,
    }
}

/// `listed` as the `screens:` line says it: `screens: 2 (1 2560x1440+0+0
/// main, 2 1920x1080+2560+0)`, a monitor left of or above the primary at a
/// negative offset (`1920x1080-1920+0`).
fn screens_text(
    listed: &Result<Vec<tornect_capture::Monitor>, tornect_capture::CaptureError>,
) -> String {
    match listed {
        Ok(monitors) => format!("screens: {}", monitors_text(monitors)),
        Err(e) => format!("screens: unknown ({e})"),
    }
}

/// `monitors` by number, size and place: `2 (1 2560x1440+0+0 main, 2
/// 1920x1080+2560+0)`. Never a monitor's name.
pub(crate) fn monitors_text(monitors: &[tornect_capture::Monitor]) -> String {
    let each: Vec<String> = monitors
        .iter()
        .map(|m| {
            format!(
                "{} {}x{}{:+}{:+}{}",
                m.id,
                m.rect.width,
                m.rect.height,
                m.rect.x,
                m.rect.y,
                if m.primary { " main" } else { "" }
            )
        })
        .collect();
    format!("{} ({})", monitors.len(), each.join(", "))
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
    direct: DirectWiring,
    once: bool,
    source: Source,
) -> anyhow::Result<()> {
    let knobs = direct.knobs.clone();
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
            Arc::new(SystemBackend::new(source).with_portal(paths, cfg.services.wayland_clipboard)),
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
        direct,
        prompter,
        Arc::clone(&media),
        control.clone(),
    )?;
    helpers.wire(deps.kill.clone(), audit.clone(), host_cfg.levels);
    deps.admin_helper = helpers;
    let services = terminal_services(&media);
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
    // Through a bridge, sessions are signed `tor_only` unless
    // `network.direct_with_bridges` (decision M1-86): set before the onion
    // service is published, so no accept is signed without it.
    knobs.bootstrapped(node.rung(), &cfg.tor);
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
    // Media and services streams: each bounds itself (the bind deadline, the
    // cap on binds waiting for an unregistered session, the session's end).
    // Streams still reading their `Bind` hold no slot (SLICE-C1 C1-1); the
    // listener's cap of 4 streams per circuit and 64 circuits is what bounds
    // them.
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
                let port = stream.port();
                let Some(stream) = dispatch(stream, port, &media, &services, &mut media_streams)
                else {
                    continue;
                };
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

/// The terminal host's services over its `media` (design `services` §0,
/// decision M1-76 (bk)): it advertises `svc1` like the window host and
/// serves the stream the way a window host whose `[services]` switches are
/// all off does ([`ServicesHost::offering_nothing`]), so that its services
/// port does not tell the two hosts apart before pairing. A session here is
/// never offered a service.
pub(crate) fn terminal_services(media: &Arc<MediaHost>) -> Arc<ServicesHost> {
    Arc::new(ServicesHost::offering_nothing(Arc::clone(media)))
}

/// Put `stream`, accepted on `port`, where the terminal host serves it: a
/// media stream to `media` and a services stream to `services`, each on a
/// task of `streams` (each bounds itself: its bind deadline, its session's
/// end); a signaling stream is given back, to be served in a slot of its
/// own; a stream on any other port is closed (dropped: the peer sees EOF).
/// A services stream's outcome is not told: a session here is never offered
/// a service, and a stream that binds nothing can come from any peer.
pub(crate) fn dispatch<S>(
    stream: S,
    port: u16,
    media: &Arc<MediaHost>,
    services: &Arc<ServicesHost>,
    streams: &mut JoinSet<()>,
) -> Option<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match port {
        MEDIA_PORT => {
            let media = Arc::clone(media);
            streams.spawn(async move {
                let outcome = media.serve(stream).await;
                if let Some(line) = crate::host::describe_media(&outcome) {
                    eprintln!("{line}");
                }
            });
            None
        }
        SERVICES_PORT => {
            let services = Arc::clone(services);
            streams.spawn(async move {
                services.serve(stream).await;
            });
            None
        }
        SIGNALING_PORT => Some(stream),
        _ => None,
    }
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
    /// The host's screen to show, asked for once the host lists its
    /// screens: a monitor's id, or [`ALL_MONITORS`]; `None` asks nothing.
    pub screen: Option<u8>,
    /// Connect without asking, on this device's unattended grant.
    pub unattended: Option<UnattendedOpts>,
    /// This session's policy is `tor_only` (design `direct` §3.5): its media
    /// is relayed through Tor whatever the settings say.
    pub tor_only: bool,
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
    let device = Arc::new(device);
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
    let direct = DirectWiring::real(device, DirectKnobs::new(&cfg));
    block_on(run_connect(paths, &cfg, id, &direct, &pins, opts, prepared))
}

async fn run_connect(
    paths: &Paths,
    cfg: &Config,
    id: TornectId,
    direct: &DirectWiring,
    pins: &crate::history::Pins,
    opts: ConnectOpts,
    prepared: Option<Prepared>,
) -> anyhow::Result<()> {
    eprintln!("bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...");
    let node = start_tor(paths, cfg).await?;
    // The bridge rule from the way Tor went in (decision M1-86), before the
    // session decides its path.
    direct.knobs.bootstrapped(node.rung(), &cfg.tor);
    let result = connect_session(&node, cfg, paths, id, direct, pins, opts, prepared).await;
    node.shutdown().await;
    result
}

#[allow(clippy::too_many_arguments)] // the command's context, one argument each
async fn connect_session(
    node: &TorNode,
    cfg: &Config,
    paths: &Paths,
    id: TornectId,
    direct: &DirectWiring,
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
    let ccfg = viewer_config(id, cfg.general.device_name.clone());
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
    let outcome = client::connect(stream, &ccfg, &direct.device, &deps, intent).await;
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
    // The path phase starts at once after the accept (design `direct` §4):
    // `watch` runs it for the picture, `no_media` without one. Either answer
    // stops the host's 15 s orphan timer (§B.8.4.5).
    let direct = direct.ctx(opts.tor_only);
    eprintln!(
        "the session stays alive with a ping every {} s; Ctrl-C ends it",
        SESSION_PING_EVERY.as_secs()
    );

    let interrupts = Interrupts::listen();
    let end = if opts.video {
        let watching = WatchOptions {
            pings: opts.pings,
            quality: opts.quality.unwrap_or(cfg.viewer.quality),
            channels: ViewerChannels {
                input: None,
                requests: screen_requests(opts.screen),
            },
            ..WatchOptions::default()
        };
        watch(
            node,
            &id,
            &isolation,
            &mut session,
            &interrupts.pressed,
            &direct,
            watching,
        )
        .await?
    } else {
        match no_media(&mut session, &direct, &interrupts.pressed).await {
            Ok(()) => {
                println!("{}", crate::direct::route_line(&PathEnd::NoMedia));
                let stop = pressed(interrupts.pressed.clone());
                keep_alive(&mut session, opts.pings, SESSION_PING_EVERY, async {
                    stop.await;
                    Ok(())
                })
                .await?
            }
            Err(end) => end,
        }
    };
    if let Some(code) = end.bye()
        && let Err(e) = session.bye(code).await
    {
        tracing::debug!(error = %e, "sending BYE");
    }
    match end {
        End::You => println!("SESSION ENDED (by you)"),
        End::Host(reason) => println!("SESSION ENDED by the host ({})", bye::name(reason)),
        End::Lost(e) => {
            println!("SESSION ENDED (connection lost)");
            return Err(explain_handshake(e));
        }
        End::NoPicture(e) => {
            println!("SESSION ENDED (no picture)");
            return Err(e);
        }
        End::Refused(code) => {
            println!("SESSION ENDED ({})", bye::name(code));
            anyhow::bail!("{}", refused_why(code));
        }
    }
    Ok(())
}

/// What this side says when it ended the session with `BYE{code}` before
/// any media: only `NO_LAN_PATH` for now (decision M1-85).
pub(crate) fn refused_why(code: u16) -> String {
    match code {
        bye::NO_LAN_PATH => "no direct connection on this local network, and network.lan_only \
                             relays nothing through Tor"
            .to_owned(),
        other => format!("the session was ended ({})", bye::name(other)),
    }
}

/// What a viewer announces in `HELLO` for a session: `dir1`, the direct
/// path's exchange (design `direct` §8.2), so that the host takes part in
/// it. A viewer that left it out would still try the path against a host
/// that ignores its candidates, and fall back after the whole punch window
/// in every session.
pub(crate) fn viewer_config(host: TornectId, name: String) -> ClientConfig {
    let mut cfg = ClientConfig::new(host, name);
    cfg.feats.push(feats::DIR1.to_owned());
    cfg
}

/// `connect --screen`'s request, already waiting in a channel of its own:
/// the viewer sends it once the host has listed its screens, and never if
/// the host lists none. The sender is gone, so nothing follows it.
fn screen_requests(screen: Option<u8>) -> Option<mpsc::Receiver<ViewerRequest>> {
    let screen = screen?;
    let (requests, rx) = mpsc::channel(1);
    // A new channel of one has room for it.
    let _ = requests.try_send(ViewerRequest::ShowScreen(screen));
    Some(rx)
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
    /// The path phase ended the session: this side owes the host
    /// `BYE{code}` (`NO_LAN_PATH`: a `lan_only` session with no same-site
    /// path, decision M1-85).
    Refused(u16),
}

impl End {
    /// The `BYE` this side owes the host for this end: `USER` when this
    /// side ended it or its picture failed, the path phase's own code when
    /// that ended it, none when the host ended it or it broke.
    pub(crate) fn bye(&self) -> Option<u16> {
        match self {
            Self::You | Self::NoPicture(_) => Some(bye::USER),
            Self::Refused(code) => Some(*code),
            Self::Host(_) | Self::Lost(_) => None,
        }
    }
}

/// How [`watch()`] receives the screen.
#[derive(Default)]
pub(crate) struct WatchOptions<'a> {
    /// End the session after this many pings; `None` keeps it until the user
    /// ends it.
    pub pings: Option<u32>,
    /// What the viewer sends besides its acks: input events, which the
    /// caller passes only for a control session, by the signed
    /// `SESSION_ACCEPT`'s mode (SLICE-C2 C2-6), and screen requests, legal
    /// in either mode.
    pub channels: ViewerChannels,
    /// Every picture, and what the host says about them, also go here (the
    /// window's).
    pub forward: Option<&'a mut dyn FrameSink>,
    /// The preset the `Bind` asks for.
    pub quality: QualityPreset,
    /// The viewer's picks during the session, each sent as a `SetQuality`.
    pub quality_rx: Option<watch::Receiver<QualityPreset>>,
    /// The session's services stream, opened once the media stream is
    /// bound (the window's viewer, when the host's signed `HELLO_ACK` offers
    /// it; the terminal viewer opens none).
    pub services: Option<ServicesStart>,
}

/// How long the viewer waits for the host's answer on its services stream:
/// the host answers once the session's capture is live (it waits up to
/// 10 s) and the desktop's clipboard opened (up to 5 s), over Tor.
const SERVICES_BIND_WAIT: Duration = Duration::from_secs(45);

/// Events of the services stream queued between its run and the window.
const SERVICES_EVENTS: usize = 64;

/// What the viewer's services stream says (design `services` §6.1).
#[derive(Debug)]
pub(crate) enum ServicesNews {
    /// The host granted these services.
    Opened(Welcome),
    /// The stream did not open: the host refused it (with this reason) or
    /// it failed. The session goes on without services.
    NotOpened(Option<u16>),
    /// Something happened on it.
    Event(ViewerEvent),
    /// Its run returned.
    Ended(ViewerServicesEnd),
}

/// Where the services stream's news go (the window's model).
pub(crate) type ServicesReport = Arc<dyn Fn(ServicesNews) + Send + Sync>;

/// What the viewer opens its services stream with (design `services` §6.1).
pub(crate) struct ServicesStart {
    /// The session's services binding.
    pub binding: ServicesBinding,
    /// What the stream works with on this computer.
    pub local: ViewerLocal,
    /// The person's requests.
    pub ops: mpsc::Receiver<ViewerOp>,
    /// Where its news go.
    pub report: ServicesReport,
}

/// Open the session's services stream beside its bound media stream, on the
/// same circuit (`isolation`), and serve it until `stop` resolves (the
/// session is over: `Close{SESSION_OVER}` goes out), the host closes it, or
/// it fails. Its end never ends the session.
async fn run_services<F>(
    node: &TorNode,
    id: &TornectId,
    isolation: &Isolation,
    start: ServicesStart,
    stop: F,
) where
    F: Future<Output = ()>,
{
    let opened = async {
        node.connect_on(id, SERVICES_PORT, isolation)
            .await
            .map_err(|e| ServicesBindError::Io(std::io::Error::other(e.to_string())))
    };
    services_over(opened, start, stop).await;
}

/// The services stream `opened` gives, bound with `start`'s binding and
/// served until `stop` resolves, the host closes it, or it fails; each step
/// reported. Nothing is reported when `stop` comes before the stream is
/// bound (the session is over and nothing shows it).
pub(crate) async fn services_over<S, O, F>(opened: O, start: ServicesStart, stop: F)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Future<Output = Result<S, ServicesBindError>>,
    F: Future<Output = ()>,
{
    let ServicesStart {
        binding,
        local,
        ops,
        report,
    } = start;
    let mut stop = pin!(stop);
    let opened = async {
        let stream = opened.await?;
        ServicesViewer::bind(stream, &binding, SERVICES_BIND_WAIT).await
    };
    let bound = tokio::select! {
        biased;
        () = &mut stop => return,
        bound = opened => bound,
    };
    let viewer = match bound {
        Ok((viewer, welcome)) => {
            report(ServicesNews::Opened(welcome));
            viewer
        }
        Err(e) => {
            // The error's words only: no address, no path.
            tracing::info!(error = %e, "the services stream did not open");
            let refused = match e {
                ServicesBindError::Refused(code) => Some(code),
                _ => None,
            };
            report(ServicesNews::NotOpened(refused));
            return;
        }
    };
    let (events, mut heard) = mpsc::channel(SERVICES_EVENTS);
    let forward = async {
        while let Some(event) = heard.recv().await {
            report(ServicesNews::Event(event));
        }
    };
    let (end, ()) = tokio::join!(viewer.run(ops, events, local, &mut stop), forward);
    report(ServicesNews::Ended(end));
}

/// The session's bound media stream, on the path the path phase chose.
pub(crate) enum MediaPath<O> {
    /// The direct connection's stream.
    Direct(MediaViewer<QuicStream>),
    /// The onion media stream (`MEDIA_PORT`).
    Onion(MediaViewer<O>),
}

impl<O> MediaPath<O>
where
    O: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// What the host answered the bind with.
    fn bound(&self) -> tornect_session::BoundStream {
        match self {
            Self::Direct(viewer) => *viewer.bound(),
            Self::Onion(viewer) => *viewer.bound(),
        }
    }
}

/// A session's media, bound ([`bind_media`]).
pub(crate) struct BoundMedia<O> {
    /// The bound stream.
    pub media: MediaPath<O>,
    /// How the path phase ended (the `ROUTE` line, the window's route).
    pub end: PathEnd,
    /// The kind of the host candidate the direct connection runs to; `None`
    /// on Tor (the `PATH` line).
    pub winner: Option<CandidateKind>,
    /// From the accept to the open direct stream or to `TOR_FALLBACK` (the
    /// `PATH` line).
    pub elapsed: Duration,
    /// Whether the services stream may go over the onion service: not for a
    /// `lan_only` session, which the host refuses it (decision M1-85). The
    /// direct services stream is step B10's.
    pub onion_services: bool,
}

impl<O> std::fmt::Debug for BoundMedia<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundMedia")
            .field(
                "media",
                &match self.media {
                    MediaPath::Direct(_) => "direct",
                    MediaPath::Onion(_) => "onion",
                },
            )
            .field("end", &self.end)
            .field("winner", &self.winner)
            .field("elapsed", &self.elapsed)
            .field("onion_services", &self.onion_services)
            .finish()
    }
}

/// The onion media stream opened beside the path phase (design `direct`
/// §4, DIRECT-2), only when the path is tried with a Tor fallback: the
/// fallback then finds its stream open, one round trip on the session's
/// circuit sooner.
enum Preopen<F: Future> {
    /// Nothing opened beside the path phase.
    None,
    /// Opening since that instant.
    Opening(std::pin::Pin<Box<F>>, tokio::time::Instant),
    /// Opened (or failed); the open started at that instant.
    Opened(F::Output, tokio::time::Instant),
}

impl<O, F> Preopen<F>
where
    F: Future<Output = anyhow::Result<O>>,
{
    /// The open `opening`, starting now.
    fn start(opening: F) -> Self {
        Self::Opening(Box::pin(opening), tokio::time::Instant::now())
    }

    /// `work`, while the open goes on beside it; the open's result is kept.
    async fn beside<W: Future>(&mut self, work: W) -> W::Output {
        let mut work = pin!(work);
        loop {
            let Self::Opening(opening, started) = self else {
                return work.await;
            };
            let started = *started;
            let opened = tokio::select! {
                biased;
                out = &mut work => return out,
                opened = opening.as_mut() => opened,
            };
            *self = Self::Opened(opened, started);
        }
    }

    /// The onion stream for the Tor path: the one opened beside the path
    /// phase while its open started less than [`ONION_PREOPEN_MAX`] ago
    /// (still opening counts: its `Bind` follows the host's accept by a
    /// round trip), else a fresh one from `fresh`, which is also tried once
    /// when the early open failed.
    async fn take(self, fresh: impl FnOnce() -> F) -> anyhow::Result<O> {
        let early = match self {
            Self::Opening(opening, _) => opening.await,
            Self::Opened(opened, started) if started.elapsed() < ONION_PREOPEN_MAX => opened,
            Self::Opened(..) | Self::None => return fresh().await,
        };
        match early {
            Ok(stream) => Ok(stream),
            Err(e) => {
                tracing::debug!(error = %format!("{e:#}"), "the early onion media stream failed");
                fresh().await
            }
        }
    }
}

/// The session's end when its path phase ended it; the path otherwise.
fn into_path(choice: PathChoice) -> Result<PathChoice, End> {
    match choice {
        PathChoice::End(code) => Err(End::Refused(code)),
        PathChoice::HostEnded(SessionEvent::Bye { reason, .. }) => Err(End::Host(reason)),
        PathChoice::HostEnded(SessionEvent::Error { code, detail }) => {
            Err(End::Lost(HandshakeError::PeerError { code, detail }))
        }
        PathChoice::HostEnded(_) => Err(End::Lost(HandshakeError::Closed)),
        PathChoice::Broken(e) => Err(End::Lost(e)),
        PathChoice::Interrupted => Err(End::You),
        path @ (PathChoice::Direct(_) | PathChoice::Tor { .. } | PathChoice::NoMedia) => Ok(path),
    }
}

/// The session's path phase and its media bind (design `direct` §4, §8.6),
/// called at once after the accept: [`ViewerDirect::choose_path`] with
/// `direct`'s policy, the onion media stream opened beside it
/// (`open_onion`, only for a try that may fall back), then the bind on the
/// path chosen, each wait raced against `interrupted`:
///
/// - direct: the onion stream is dropped and the `Bind` written on the
///   direct stream, waiting up to [`MEDIA_BIND_WAIT`] (never the punch
///   window); a connection closed by a TLS alert before any host byte
///   ([`AfterBind::Fallback`]) sends `TOR_FALLBACK{QUIC}` and binds a
///   fresh onion stream, unless the session is `lan_only`, which ends it
///   (`BYE{NO_LAN_PATH}`); any other failure is the session's;
/// - Tor: the onion stream opened beside the path phase (or a fresh one)
///   is bound with `onion`, the session's onion binding;
/// - the path phase ended the session ([`End::Refused`] when this side
///   owes the host `BYE{NO_LAN_PATH}`), or the host ended it, or it broke.
///
/// [`ViewerDirect::choose_path`]: tornect_session::ViewerDirect::choose_path
pub(crate) async fn bind_media<S, O, F, Fut>(
    session: &mut ClientSession<S>,
    direct: &DirectCtx,
    onion: &Binding,
    open_onion: F,
    interrupted: &watch::Receiver<bool>,
) -> Result<BoundMedia<O>, End>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    O: AsyncRead + AsyncWrite + Unpin + Send,
    F: Fn() -> Fut,
    Fut: Future<Output = anyhow::Result<O>>,
{
    let accepted = tokio::time::Instant::now();
    // `choose_path` decides the same way from the same facts; the decision
    // is read here only for the onion stream opened beside it.
    let decision = decide(
        session.transport_policy(),
        direct.mine,
        true,
        session.host_has(feats::DIR1),
        session.host_device_pk() == direct.device_pk,
    );
    let lan_only = matches!(decision, Decision::Try { lan_only: true, .. });
    let mut preopen = match decision {
        Decision::Try {
            lan_only: false, ..
        } => Preopen::start(open_onion()),
        _ => Preopen::None,
    };
    let stop = pressed(interrupted.clone());
    let choice = preopen
        .beside(direct.viewer.choose_path(session, direct.mine, true, stop))
        .await;
    let (why, elapsed) = match into_path(choice)? {
        PathChoice::Direct(media) => {
            preopen = Preopen::None;
            let (route, winner, elapsed) = (media.route, media.winner, media.elapsed);
            match unless_interrupted(media.bind(MEDIA_BIND_WAIT), interrupted).await {
                None => return Err(End::You),
                Some(Ok(viewer)) => {
                    return Ok(BoundMedia {
                        media: MediaPath::Direct(viewer),
                        end: PathEnd::Direct(route),
                        winner: Some(winner),
                        elapsed,
                        onion_services: !lan_only,
                    });
                }
                // A `lan_only` session never falls back: it ends as one
                // with no same-site path does (decision M1-85).
                Some(Err(DirectBindFailed {
                    error,
                    after: AfterBind::Fallback,
                })) if lan_only => {
                    tracing::info!(
                        error = %error,
                        "the direct connection failed before its bind; lan_only ends the session"
                    );
                    return Err(End::Refused(bye::NO_LAN_PATH));
                }
                Some(Err(DirectBindFailed {
                    error,
                    after: AfterBind::Fallback,
                })) => {
                    // The words only: no address, no port.
                    tracing::info!(
                        error = %error,
                        "the direct connection failed before its bind; media goes through Tor"
                    );
                    let fell_back = session.send_tor_fallback(Some(fallback::QUIC));
                    match unless_interrupted(fell_back, interrupted).await {
                        None => return Err(End::You),
                        Some(Err(e)) => return Err(End::Lost(e)),
                        Some(Ok(())) => {}
                    }
                    (TorWhy::Fallback(FallbackWhy::Quic), accepted.elapsed())
                }
                Some(Err(DirectBindFailed {
                    error,
                    after: AfterBind::End,
                })) => return Err(End::NoPicture(bind_failed(error))),
            }
        }
        PathChoice::Tor { why, elapsed } => (why, elapsed),
        // `decide`'s first rule: a session with media is never `NoMedia`.
        _ => {
            return Err(End::NoPicture(anyhow::anyhow!(
                "the path phase chose no media for a session with media"
            )));
        }
    };
    let opened = async {
        let stream = preopen.take(&open_onion).await?;
        MediaViewer::bind(stream, onion, MEDIA_BIND_WAIT)
            .await
            .map_err(bind_failed)
    };
    match unless_interrupted(opened, interrupted).await {
        None => Err(End::You),
        Some(Ok(viewer)) => Ok(BoundMedia {
            media: MediaPath::Onion(viewer),
            end: PathEnd::Tor(why),
            winner: None,
            elapsed,
            onion_services: true,
        }),
        Some(Err(e)) => Err(End::NoPicture(e)),
    }
}

/// The path phase of a session without media (`connect --no-video`, design
/// `direct` §3.5): `TOR_FALLBACK{NO_MEDIA}`, with no network interface
/// read; the session's end when the host ended it, it broke, or
/// `interrupted` came first.
pub(crate) async fn no_media<S>(
    session: &mut ClientSession<S>,
    direct: &DirectCtx,
    interrupted: &watch::Receiver<bool>,
) -> Result<(), End>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let stop = pressed(interrupted.clone());
    // `decide`'s first rule: a session without media is never tried, so
    // no other path comes back (one would be dropped, its link shut).
    into_path(
        direct
            .viewer
            .choose_path(session, direct.mine, false, stop)
            .await,
    )
    .map(drop)
}

/// The line `watch` prints when the session ended before its media was
/// bound.
fn unbound_line(end: &End) -> String {
    match end {
        End::You => "MEDIA ENDED (by you, before the first picture)".to_owned(),
        End::NoPicture(e) => format!("MEDIA FAILED: {e:#}"),
        End::Refused(bye::NO_LAN_PATH) => crate::direct::route_line(&PathEnd::LanRefused),
        End::Refused(_) => crate::direct::route_line(&PathEnd::NoMedia),
        End::Host(_) | End::Lost(_) => {
            "MEDIA ENDED (the session ended before the first picture)".to_owned()
        }
    }
}

/// Choose the session's media path and bind it ([`bind_media`]: the direct
/// path, else the onion media stream beside the signaling stream), then
/// receive the screen while the signaling stream keeps the session alive.
/// Whichever side ends first ends the other. `interrupted` turning `true` is
/// the user's own end (Ctrl-C, or the window's Stop). `options` say what
/// else goes where.
#[allow(clippy::too_many_arguments)] // the session's context, one argument each
pub(crate) async fn watch<S>(
    node: &TorNode,
    id: &TornectId,
    isolation: &Isolation,
    session: &mut ClientSession<S>,
    interrupted: &watch::Receiver<bool>,
    direct: &DirectCtx,
    options: WatchOptions<'_>,
) -> anyhow::Result<End>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let binding =
        Binding::new(session.session_token(), &session.th()).with_quality(options.quality);
    let open_onion = || async {
        node.connect_on(id, MEDIA_PORT, isolation)
            .await
            .map_err(explain)
    };
    let bound = match bind_media(session, direct, &binding, open_onion, interrupted).await {
        Ok(bound) => bound,
        Err(end) => {
            println!("{}", unbound_line(&end));
            return Ok(end);
        }
    };
    println!("{}", bound_line(&bound.media.bound()));
    println!("{}", crate::direct::route_line(&bound.end));
    println!("{}", crate::direct::path_line(bound.winner, bound.elapsed));
    let services = Services {
        node,
        id,
        isolation,
        onion: bound.onion_services,
    };
    match bound.media {
        MediaPath::Direct(viewer) => {
            watch_bound(viewer, session, interrupted, services, options).await
        }
        MediaPath::Onion(viewer) => {
            watch_bound(viewer, session, interrupted, services, options).await
        }
    }
}

/// Where a session's services stream opens.
struct Services<'a> {
    node: &'a TorNode,
    id: &'a TornectId,
    isolation: &'a Isolation,
    /// Over the onion service (on the session's circuit); `false`: not at
    /// all (a `lan_only` session's, until the direct services stream).
    onion: bool,
}

/// Receive the screen on the bound `viewer` while `session` keeps the
/// session alive, the services stream beside it.
async fn watch_bound<M, S>(
    viewer: MediaViewer<M>,
    session: &mut ClientSession<S>,
    interrupted: &watch::Receiver<bool>,
    at: Services<'_>,
    options: WatchOptions<'_>,
) -> anyhow::Result<End>
where
    M: AsyncRead + AsyncWrite + Unpin + Send,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let WatchOptions {
        pings,
        channels,
        forward,
        quality: _,
        quality_rx,
        services,
    } = options;
    let viewer = match quality_rx {
        Some(picks) => viewer.with_quality(picks),
        None => viewer,
    };

    let mut pictures = CliPictures::new(forward);
    let mut stats = ViewerStats::default();
    // The services stream opens only now, after the media stream's `BindOk`
    // (the host refuses a services bind for a session media has not bound),
    // and stops when the session does.
    let (services_stop, stopped) = oneshot::channel::<()>();
    let viewing = async {
        let viewed = view(
            viewer,
            session,
            pings,
            interrupted,
            &mut pictures,
            &mut stats,
            channels,
        )
        .await;
        let _ = services_stop.send(());
        viewed
    };
    let services = async {
        match services {
            Some(start) if at.onion => {
                let stop = async {
                    let _ = stopped.await;
                };
                run_services(at.node, at.id, at.isolation, start, stop).await;
            }
            Some(start) => (start.report)(ServicesNews::NotOpened(None)),
            None => {}
        }
    };
    let ((viewed, end), ()) = tokio::join!(viewing, services);
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
pub(crate) fn bind_failed(e: ViewerError) -> anyhow::Error {
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
    channels: ViewerChannels,
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
        let viewed = viewer.run_with(pictures, stats, channels, stop).await;
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
    /// This viewer's screen requests the stream has said something about:
    /// the number of the last one (the viewer numbers them on the wire alike,
    /// from 1, and `connect` makes at most one).
    screen_requests: u16,
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
            screen_requests: 0,
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

    /// The host's screens arrived, or this viewer's request for one ended
    /// (`FrameSink::screens`): the `MEDIA SCREENS` line, one for each. The
    /// host's own news is request 0; a request that got no answer, or was
    /// not sent, says so and nothing else.
    fn screens_at(&mut self, screens: &Screens, news: ScreensNews) -> String {
        let status = match news {
            ScreensNews::Layout => return media_screens_line(0, monitor_status::OK, screens),
            ScreensNews::Answer { status, .. } => status,
            ScreensNews::NoAnswer { .. } | ScreensNews::NotSent { .. } => {
                self.screen_requests = self.screen_requests.wrapping_add(1);
                return format!(
                    "MEDIA SCREENS request={} status=no-answer",
                    self.screen_requests
                );
            }
        };
        self.screen_requests = self.screen_requests.wrapping_add(1);
        media_screens_line(self.screen_requests, status, screens)
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

/// The `MEDIA SCREENS` line of `screens`, said for `request` with
/// `status`: `MEDIA SCREENS request=1 status=ok shown=2 all=yes list=0
/// seq=41 remapped=yes 1:1280x720+0+0:main 2:1024x768+1280+0`. Each monitor
/// is `id:WxH±X±Y`, `:main` on the primary; `shown=all` when the pictures
/// show every monitor at once. Geometry only: a host's monitors carry no
/// names.
fn media_screens_line(request: u16, status: u8, screens: &Screens) -> String {
    use std::fmt::Write as _;
    let yes = |b: bool| if b { "yes" } else { "no" };
    let status = match status {
        monitor_status::OK => "ok".to_owned(),
        monitor_status::UNKNOWN => "unknown".to_owned(),
        monitor_status::FAILED => "failed".to_owned(),
        monitor_status::BUSY => "busy".to_owned(),
        other => format!("code-{other}"),
    };
    let shown = match screens.shown {
        ALL_MONITORS if screens.all => "all".to_owned(),
        id => id.to_string(),
    };
    let mut line = format!(
        "MEDIA SCREENS request={request} status={status} shown={shown} all={} list={} seq={} \
         remapped={}",
        yes(screens.all),
        screens.list,
        screens.seq,
        yes(screens.remapped)
    );
    for (index, m) in screens.monitors.iter().enumerate() {
        let _ = write!(
            line,
            " {}:{}x{}{:+}{:+}{}",
            index + 1,
            m.width,
            m.height,
            m.x,
            m.y,
            if m.primary { ":main" } else { "" }
        );
    }
    line
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

    fn screens(&mut self, screens: &Screens, news: ScreensNews) {
        if let Some(forward) = self.forward.as_deref_mut() {
            forward.screens(screens, news);
        }
        println!("{}", self.screens_at(screens, news));
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
///
/// `stop` is heard at once, whatever the host does (design `direct` §4).
/// Every wait races it, and only cancel-safe futures: between pings the loop
/// waits on [`ClientSession::event_ready`] and the ping timer, then
/// [`ClientSession::take_event`] handles one frame without writing. A host
/// `PING` leaves its `PONG` owed, and [`ClientSession::flush_owed`] writes it
/// next, raced against `stop` alone; so are the ping itself and the `ERROR`
/// that answers a fault ([`ClientSession::fail_bounded`], bounded too). A
/// host that stops reading can stall those writes, never the stop.
///
/// Pings run to a deadline that frames from the host do not move, so a host
/// that keeps sending cannot keep `--pings N` from ending (SLICE-B2 B2-8):
/// its path frames, late once the path phase has chosen, are taken as they
/// come and ignored, the timer staying where it was, and a host `PING` is
/// answered without moving it either (SLICE-D D2).
///
/// Between pings it waits on the stream, not on the timer alone, so a host
/// `BYE` is reported the moment it arrives. Over Tor the host's circuit is
/// often gone by the next ping, whose write would then fail first and turn a
/// deliberate end (`tornect panic`) into "connection lost". Cutting that wait
/// short for the ping loses nothing: the channel keeps a partial frame for
/// the next read.
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
        if session.owes() {
            let flushed = tokio::select! {
                biased;
                result = &mut stop => {
                    result.context("waiting for Ctrl-C")?;
                    break End::You;
                }
                flushed = session.flush_owed() => flushed,
            };
            if let Err(e) = flushed {
                break End::Lost(e);
            }
            continue;
        }
        if tokio::time::Instant::now() < next_ping {
            let ready = tokio::select! {
                biased;
                result = &mut stop => {
                    result.context("waiting for Ctrl-C")?;
                    break End::You;
                }
                ready = session.event_ready() => ready,
                // Nothing whole from the host by then: time for the next ping.
                () = tokio::time::sleep_until(next_ping) => continue,
            };
            if let Err(e) = ready {
                break End::Lost(e);
            }
            match session.take_event() {
                // A host `PING` (its `PONG` is now owed), or nothing yet.
                Ok(None) => {}
                Ok(Some(SessionEvent::Bye { reason, .. })) => break End::Host(reason),
                Ok(Some(SessionEvent::Error { code, detail })) => {
                    break End::Lost(HandshakeError::PeerError { code, detail });
                }
                // The path frames (`CANDIDATES`, `CANDIDATES_DONE`,
                // `TOR_FALLBACK`), late once the path phase has chosen
                // (design `direct` §4): the path is fixed for the session,
                // so they are neither a fault nor acted on, and they do not
                // move the next ping.
                Ok(Some(_)) => {}
                Err(e @ HandshakeError::Violation { .. }) => {
                    let e = tokio::select! {
                        biased;
                        result = &mut stop => {
                            result.context("waiting for Ctrl-C")?;
                            break End::You;
                        }
                        e = session.fail_bounded(e) => e,
                    };
                    break End::Lost(e);
                }
                Err(e) => break End::Lost(e),
            }
            continue;
        }
        let pinged = tokio::select! {
            biased;
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
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::task::{Context, Poll};

    use tokio::io::{DuplexStream, ReadBuf, duplex};
    use tornect_core::session_log::TransportKind;
    use tornect_core::trusted::{KnownHosts, TrustedDevices};
    use tornect_net::mem::{CountingEnv, LinkSpec, MachineSpec, MemHost, MemNet};
    use tornect_session::MediaOutcome;
    use tornect_signal::envelope::{Envelope, Kind, codes};
    use tornect_signal::framing::{HEADER_LEN, read_frame};
    use tornect_signal::fsm::client::ScriptedClientUi;
    use tornect_signal::fsm::host::{HostConfig, HostDeps, KillSwitch, serve_host};
    use tornect_signal::messages::{self, decode_body, encode_body};
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
        session.send_tor_fallback(None).await.unwrap();
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

    /// A live session whose host is played by hand
    /// ([`tornect_signal::fsm::harness::raw_session`]), so it can send what
    /// the host FSM never sends unprompted: the session, its write switch, the
    /// host's end of the stream and the next `msg_id` the host sends.
    async fn raw_live() -> (ClientSession<Freezable>, Arc<AtomicBool>, DuplexStream, u64) {
        let (client_end, host_end) = duplex(64 * 1024);
        let frozen = Arc::new(AtomicBool::new(false));
        let stream = Freezable {
            inner: client_end,
            frozen: Arc::clone(&frozen),
        };
        let (session, host) = tornect_signal::fsm::harness::raw_session(stream, host_end).await;
        let msg_id = host.next_tx_id();
        (session, frozen, host.into_stream(), msg_id)
    }

    /// A host frame of `kind`, length prefix included.
    fn host_frame(msg_id: u64, kind: Kind, body: Vec<u8>) -> Vec<u8> {
        let payload = Envelope::new(1, msg_id, kind, body).encode();
        let mut out = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(&payload);
        out
    }

    /// The client's next frame, as the host reads it.
    async fn client_frame(stream: &mut DuplexStream) -> Envelope {
        let payload = read_frame(stream).await.unwrap().expect("a frame");
        Envelope::decode(&payload).unwrap()
    }

    /// Answer the client's `PING` that `ping` is.
    fn pong_for(msg_id: u64, ping: &Envelope) -> Vec<u8> {
        assert_eq!(ping.kind, Kind::Ping);
        let nonce = decode_body::<messages::Ping>(&ping.body).unwrap().nonce;
        host_frame(msg_id, Kind::Pong, encode_body(&messages::Pong { nonce }))
    }

    /// Design `direct` §4 (step A3): frames from the host between two pings
    /// do not move the next one, and a frame the ping time cuts in two is not
    /// lost. A host that sends `CANDIDATES_DONE` every second still gets the
    /// second ping 10 s after the first, and the frame whose second half
    /// comes after the ping time is read whole when it arrives, inside the
    /// ping. The wait used to be a timed read: cut there, it lost the half it
    /// had read, and the ping misread the rest as a frame of its own.
    #[tokio::test(start_paused = true)]
    async fn host_frames_between_pings_keep_the_deadline_and_a_cut_frame_is_kept() {
        use tokio::io::AsyncWriteExt as _;
        let (mut session, _frozen, mut host, mut msg_id) = raw_live().await;
        let t0 = tokio::time::Instant::now();
        let done = || encode_body(&messages::CandidatesDone {});
        let play = async move {
            let ping = client_frame(&mut host).await;
            host.write_all(&pong_for(msg_id, &ping)).await.unwrap();
            msg_id += 1;
            for second in 1..=9 {
                tokio::time::sleep_until(t0 + Duration::from_secs(second)).await;
                let frame = host_frame(msg_id, Kind::CandidatesDone, done());
                host.write_all(&frame).await.unwrap();
                msg_id += 1;
            }
            let cut = host_frame(msg_id, Kind::CandidatesDone, done());
            msg_id += 1;
            tokio::time::sleep_until(t0 + Duration::from_millis(9_500)).await;
            host.write_all(&cut[..HEADER_LEN + 2]).await.unwrap();
            tokio::time::sleep_until(t0 + Duration::from_millis(10_500)).await;
            host.write_all(&cut[HEADER_LEN + 2..]).await.unwrap();
            let ping = client_frame(&mut host).await;
            host.write_all(&pong_for(msg_id, &ping)).await.unwrap();
            host
        };
        let (end, host) = tokio::join!(
            keep_alive(
                &mut session,
                Some(2),
                Duration::from_secs(10),
                std::future::pending(),
            ),
            play
        );
        let end = end.unwrap();
        assert!(matches!(end, End::You), "{end:?}");
        assert_eq!(
            t0.elapsed(),
            Duration::from_millis(10_500),
            "the second ping went out at 10 s and its PONG came after the cut frame"
        );
        assert_eq!(
            session.take_event().unwrap(),
            Some(SessionEvent::CandidatesDone),
            "the cut frame, whole, queued by the ping"
        );
        drop(host);
    }

    /// Design `direct` §12.1 kill liveness, the viewer's keep-alive (step
    /// A3): a host `PING` that comes while this side's writes are stuck
    /// leaves its `PONG` owed, and a Ctrl-C ends the session the moment it
    /// comes, with the `PONG` still unwritten. Leaving returns at once too:
    /// the write cut short is the channel's last, so no `BYE` is tried on the
    /// stuck stream.
    #[tokio::test(start_paused = true)]
    async fn a_stop_while_a_pong_is_owed_to_a_host_that_stops_reading_ends_at_once() {
        use tokio::io::AsyncWriteExt as _;
        let (mut session, frozen, mut host, msg_id) = raw_live().await;
        let t0 = tokio::time::Instant::now();
        let play = async {
            let ping = client_frame(&mut host).await;
            host.write_all(&pong_for(msg_id, &ping)).await.unwrap();
            frozen.store(true, Ordering::SeqCst);
            tokio::time::sleep_until(t0 + Duration::from_secs(2)).await;
            let ping = host_frame(
                msg_id + 1,
                Kind::Ping,
                encode_body(&messages::Ping { nonce: 5 }),
            );
            host.write_all(&ping).await.unwrap();
        };
        let stop = async {
            tokio::time::sleep_until(t0 + Duration::from_secs(3)).await;
            Ok(())
        };
        let (end, ()) = tokio::join!(
            keep_alive(&mut session, None, Duration::from_secs(10), stop),
            play
        );
        let end = end.unwrap();
        assert!(matches!(end, End::You), "{end:?}");
        assert_eq!(t0.elapsed(), Duration::from_secs(3), "the stop waited");
        assert!(session.owes(), "the PONG was written to a stuck stream");
        let left = session.bye(bye::USER).await;
        assert!(matches!(left, Err(HandshakeError::Aborted(_))), "{left:?}");
        assert_eq!(
            t0.elapsed(),
            Duration::from_secs(3),
            "leaving waited on the stuck stream"
        );
        drop(host);
    }

    /// Design `direct` §4 (step A3): a fault from the host ends the session
    /// with the violation, its `ERROR` written raced against the stop and
    /// bounded by `timeouts::BYE`: at once to a host that reads, after
    /// exactly that bound to one that stops reading. Here a frame whose
    /// `msg_id` skips one.
    #[tokio::test(start_paused = true)]
    async fn a_fault_from_the_host_ends_the_keep_alive_in_bounded_time() {
        use tokio::io::AsyncWriteExt as _;
        for host_reads in [true, false] {
            let (mut session, frozen, mut host, msg_id) = raw_live().await;
            let t0 = tokio::time::Instant::now();
            let play = async {
                let ping = client_frame(&mut host).await;
                host.write_all(&pong_for(msg_id, &ping)).await.unwrap();
                frozen.store(!host_reads, Ordering::SeqCst);
                tokio::time::sleep_until(t0 + Duration::from_secs(2)).await;
                let skipped = host_frame(
                    msg_id + 2,
                    Kind::CandidatesDone,
                    encode_body(&messages::CandidatesDone {}),
                );
                host.write_all(&skipped).await.unwrap();
                if host_reads {
                    let answer = client_frame(&mut host).await;
                    assert_eq!(answer.kind, Kind::Error);
                    let e: messages::Error = decode_body(&answer.body).unwrap();
                    assert_eq!(e.code, codes::E_BAD_MSG_ID);
                    assert!(
                        read_frame(&mut host).await.unwrap().is_none(),
                        "then closed"
                    );
                }
            };
            let (end, ()) = tokio::join!(
                keep_alive(
                    &mut session,
                    None,
                    Duration::from_secs(10),
                    std::future::pending(),
                ),
                play
            );
            match end.unwrap() {
                End::Lost(e) => assert_eq!(e.violation_code(), Some(codes::E_BAD_MSG_ID), "{e}"),
                other => panic!("host reads {host_reads}: {other:?}"),
            }
            let bound = if host_reads {
                Duration::ZERO
            } else {
                tornect_signal::fsm::timeouts::BYE
            };
            assert_eq!(
                t0.elapsed(),
                Duration::from_secs(2) + bound,
                "host reads {host_reads}"
            );
        }
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
            ViewerChannels::default(),
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

    /// What a viewer's sink heard of the host's screens, and why.
    #[derive(Default)]
    struct HeardScreens(Vec<(Screens, ScreensNews)>);

    impl FrameSink for HeardScreens {
        fn picture(&mut self, _seq: u32, _frame: &DecodedFrame) {}

        fn screens(&mut self, screens: &Screens, news: ScreensNews) {
            self.0.push((screens.clone(), news));
        }
    }

    /// The host's `SHARING VIEW` lines, as `tornect host` prints them.
    #[derive(Default)]
    struct Views(std::sync::Mutex<Vec<String>>);

    impl tornect_session::MediaObserver for Views {
        fn capture_started(&self, _: &tornect_session::CaptureStarted<'_>) {}

        fn capture_changed(&self, changed: &tornect_session::CaptureChanged<'_>) {
            let line = crate::host::view_line(changed);
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line);
        }

        fn capture_stopped(
            &self,
            _: &str,
            _: &tornect_session::MediaReport,
            _: &tornect_session::MediaEnd,
        ) {
        }
    }

    /// The design's runtime demo (§7) in one process, without Tor: a real
    /// host sharing `--capture test-screens` with a view-only session, and
    /// `connect --screen N`'s viewer and lines. The first `MEDIA SCREENS`
    /// line lists both screens with screen 1 (main) shown; the answer is
    /// request 1, `status=ok`, the screen asked for, `remapped=yes`; the
    /// pictures end at its size with the card's index in order across the
    /// switch; the host says `SHARING VIEW` for the first screen and the
    /// one asked for. "All screens" (2304×768) is asked under Best quality,
    /// whose cap takes it whole; Balanced's (1920×1080) fits it to 1920×640.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::print_stderr)] // reports the lines a live run prints
    async fn the_test_screens_switch_as_connect_asks() {
        use tornect_core::DeviceId;
        use tornect_core::levels::Elevation;
        use tornect_signal::consent::SessionToken;
        use tornect_signal::fsm::host::{LiveSession, SessionSink as _};

        let [(w1, h1), (w2, h2)] = tornect_session::TEST_SCREENS;
        for (asked, preset, size) in [
            (2, QualityPreset::Balanced, (w2, h2)),
            (
                ALL_MONITORS,
                QualityPreset::BestQuality,
                (w1 + w2, h1.max(h2)),
            ),
        ] {
            let views = Arc::new(Views::default());
            let host = Arc::new(MediaHost::new(
                Arc::new(SystemBackend::new(Source::TestScreens)),
                Arc::clone(&views) as Arc<dyn tornect_session::MediaObserver>,
                MediaLimits::default(),
            ));
            let token = SessionToken::new([0x42; 32]);
            let session_id = token.session_id();
            let th_final = [7; 32];
            host.on_start(&LiveSession {
                device: DeviceId::from_bytes([0; 32]),
                label: "screens",
                session_id: &session_id,
                token: &token,
                th_final,
                mode: SessionMode::ViewOnly,
                elevation: Elevation::None,
                unattended: false,
                transport: tornect_signal::consent::TransportPolicy::Any,
                viewer_dir1: false,
            });
            let binding = Binding::new(&token, &th_final).with_quality(preset);
            let (client, server) = duplex(1 << 22);
            let served = tokio::spawn({
                let host = Arc::clone(&host);
                async move { host.serve(server).await }
            });
            let viewer = MediaViewer::bind(client, &binding, MEDIA_BIND_WAIT)
                .await
                .unwrap();
            let ender = tokio::spawn({
                let host = Arc::clone(&host);
                let session_id = session_id.clone();
                async move {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    host.on_end(&session_id, None);
                }
            });
            let mut heard = HeardScreens::default();
            let mut stats = ViewerStats::default();
            let mut pictures = CliPictures::new(Some(&mut heard));
            let channels = ViewerChannels {
                input: None,
                requests: screen_requests(Some(asked)),
            };
            let viewed =
                pictures_until_host_ends(viewer, &mut pictures, &mut stats, channels).await;
            let report = pictures.report_lines(&stats);
            ender.await.unwrap();
            served.await.unwrap();
            assert!(matches!(viewed, Ok(ViewerEnd::Host(_))), "{viewed:?}");
            let mut replay = CliPictures::new(None);
            let lines: Vec<String> = heard
                .0
                .iter()
                .map(|(screens, news)| replay.screens_at(screens, *news))
                .collect();
            let views = views
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            for line in lines.iter().chain(&report).chain(&views) {
                eprintln!("{line}");
            }
            assert_eq!(
                lines[0],
                format!(
                    "MEDIA SCREENS request=0 status=ok shown=1 all=yes list=0 seq=0 \
                     remapped=no 1:{w1}x{h1}+0+0:main 2:{w2}x{h2}+{w1}+0"
                )
            );
            let shown = if asked == ALL_MONITORS {
                "all".to_owned()
            } else {
                asked.to_string()
            };
            assert!(
                lines[1].starts_with(&format!(
                    "MEDIA SCREENS request=1 status=ok shown={shown} all=yes list=0 seq="
                )) && lines[1].contains(" remapped=yes "),
                "{lines:?}"
            );
            assert_eq!(lines.len(), 2, "{lines:?}");
            assert!(
                report[0].starts_with("MEDIA OK ")
                    && report[0].contains(&format!(" size={}x{} ", size.0, size.1)),
                "{report:?}"
            );
            assert!(
                report
                    .iter()
                    .any(|l| l.starts_with("MEDIA CARD ") && l.ends_with(" in-order")),
                "{report:?}"
            );
            assert_eq!(
                views,
                [
                    format!("SHARING VIEW {session_id} screen=1 of=2"),
                    format!("SHARING VIEW {session_id} screen={shown} of=2"),
                ]
            );
            assert_eq!((stats.monitor_requests, stats.screens_received), (1, 2));
        }
    }

    /// Run `viewer` into `pictures` until the host ends the stream, or 20 s.
    async fn pictures_until_host_ends(
        viewer: MediaViewer<DuplexStream>,
        pictures: &mut dyn FrameSink,
        stats: &mut ViewerStats,
        channels: ViewerChannels,
    ) -> Result<ViewerEnd, ViewerError> {
        viewer
            .run_with(
                pictures,
                stats,
                channels,
                tokio::time::sleep(Duration::from_secs(20)),
            )
            .await
    }

    /// The monitors design §2, `connect --screen 2`: the request waits in
    /// its channel while the host has listed nothing (only pings reach it,
    /// for five seconds), goes as one `SelectMonitor` for screen 2 naming
    /// the list the host's first `Monitors` gave, and the host's answer
    /// reaches the sink (the window's, when there is one) as the answer;
    /// nothing else is asked.
    #[tokio::test(start_paused = true)]
    async fn connect_asks_for_its_screen_once_the_host_lists_them() {
        use tornect_proto::{
            MonitorEntry, Msg, QualityInfo, codec, quality, read_msg, reason, write_msg,
        };
        let Live {
            mut session,
            kill,
            host,
            ..
        } = live().await;
        let binding = Binding::new(session.session_token(), &session.th());
        let (client_media, mut host_media) = duplex(1 << 16);
        let entry = |primary, x, width, height| MonitorEntry {
            primary,
            x,
            y: 0,
            width,
            height,
        };
        let listed = vec![entry(true, 0, 1280, 720), entry(false, 1280, 1024, 768)];
        let media_host = tokio::spawn(async move {
            let bind = read_msg(&mut host_media).await.unwrap();
            assert!(matches!(bind, Some(Msg::Bind { .. })), "{bind:?}");
            let ok = Msg::BindOk {
                width: 1280,
                height: 720,
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
            let unlisted = tokio::time::Instant::now() + Duration::from_secs(5);
            while let Ok(msg) = tokio::time::timeout_at(unlisted, read_msg(&mut host_media)).await {
                let msg = msg.unwrap().expect("the stream is open");
                assert!(matches!(msg, Msg::Ping { .. }), "before a list: {msg:?}");
            }
            let monitors = |request, shown, remapped, seq| Msg::Monitors {
                request,
                status: monitor_status::OK,
                shown,
                all: true,
                remapped,
                list: 7,
                seq,
                monitors: listed.clone(),
            };
            write_msg(&mut host_media, &monitors(0, 1, false, 0))
                .await
                .unwrap();
            let asked = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    match read_msg(&mut host_media).await.unwrap().unwrap() {
                        Msg::Ping { .. } => {}
                        other => break other,
                    }
                }
            })
            .await
            .expect("the viewer asks once the host lists its screens");
            assert_eq!(
                asked,
                Msg::SelectMonitor {
                    request: 1,
                    list: 7,
                    monitor: 2
                }
            );
            write_msg(&mut host_media, &monitors(1, 2, true, 41))
                .await
                .unwrap();
            let after = tokio::time::Instant::now() + Duration::from_secs(5);
            while let Ok(msg) = tokio::time::timeout_at(after, read_msg(&mut host_media)).await {
                let msg = msg.unwrap().expect("the stream is open");
                assert!(matches!(msg, Msg::Ping { .. }), "after the answer: {msg:?}");
            }
            let close = Msg::Close {
                reason: reason::ENDED_BY_HOST,
            };
            write_msg(&mut host_media, &close).await.unwrap();
            host_media
        });
        let viewer = MediaViewer::bind(client_media, &binding, MEDIA_BIND_WAIT)
            .await
            .unwrap();
        let (_ctrl_c, interrupted) = watch::channel(false);
        let mut heard = HeardScreens::default();
        let mut stats = ViewerStats::default();
        let mut pictures = CliPictures::new(Some(&mut heard));
        let channels = ViewerChannels {
            input: None,
            requests: screen_requests(Some(2)),
        };
        let (viewed, end) = view(
            viewer,
            &mut session,
            None,
            &interrupted,
            &mut pictures,
            &mut stats,
            channels,
        )
        .await;
        assert_eq!(pictures.screen_requests, 1);
        let _host_media = media_host.await.unwrap();
        assert!(
            matches!(viewed, Ok(ViewerEnd::Host(r)) if r == reason::ENDED_BY_HOST),
            "{viewed:?}"
        );
        assert!(matches!(end, Ok(End::You)), "{end:?}");
        let said: Vec<(u8, ScreensNews)> = heard
            .0
            .iter()
            .map(|(screens, news)| (screens.shown, *news))
            .collect();
        assert_eq!(
            said,
            [
                (1, ScreensNews::Layout),
                (
                    2,
                    ScreensNews::Answer {
                        asked: 2,
                        status: monitor_status::OK
                    }
                ),
            ]
        );
        assert_eq!((stats.monitor_requests, stats.screens_received), (1, 2));
        kill.kill(bye::USER);
        host.await.unwrap().unwrap();
    }

    /// `connect --screen N`'s request waits alone in a channel whose sender
    /// is gone, so the viewer sends it once and then hears that no more
    /// follow; without `--screen` there is no channel.
    #[tokio::test]
    async fn a_screen_request_waits_alone_in_its_channel() {
        assert!(screen_requests(None).is_none());
        let mut rx = screen_requests(Some(ALL_MONITORS)).unwrap();
        assert_eq!(
            rx.recv().await,
            Some(ViewerRequest::ShowScreen(ALL_MONITORS))
        );
        assert_eq!(rx.recv().await, None);
    }

    /// The monitors design §2: one `MEDIA SCREENS` line per `Monitors`, the
    /// host's news as request 0, an answer under the request's number with
    /// its status, a request given up or not sent as `status=no-answer`;
    /// each monitor `id:WxH±X±Y`, `:main` on the primary, `shown=all` for
    /// all of them at once.
    #[test]
    fn the_screens_lines_say_each_list_and_answer() {
        use tornect_proto::MonitorEntry;
        let entry = |primary, x, width, height| MonitorEntry {
            primary,
            x,
            y: 0,
            width,
            height,
        };
        let mut screens = Screens {
            monitors: vec![entry(true, 0, 1280, 720), entry(false, 1280, 1024, 768)],
            all: true,
            shown: 1,
            list: 0,
            seq: 0,
            remapped: false,
        };
        let mut pictures = CliPictures::new(None);
        assert_eq!(
            pictures.screens_at(&screens, ScreensNews::Layout),
            "MEDIA SCREENS request=0 status=ok shown=1 all=yes list=0 seq=0 remapped=no \
             1:1280x720+0+0:main 2:1024x768+1280+0"
        );
        (screens.shown, screens.seq, screens.remapped) = (2, 41, true);
        let answer = ScreensNews::Answer {
            asked: 2,
            status: monitor_status::OK,
        };
        assert_eq!(
            pictures.screens_at(&screens, answer),
            "MEDIA SCREENS request=1 status=ok shown=2 all=yes list=0 seq=41 remapped=yes \
             1:1280x720+0+0:main 2:1024x768+1280+0"
        );
        for news in [
            ScreensNews::NoAnswer { asked: 1 },
            ScreensNews::NotSent { asked: 1 },
        ] {
            let line = pictures.screens_at(&screens, news);
            assert_eq!(
                line,
                format!(
                    "MEDIA SCREENS request={} status=no-answer",
                    pictures.screen_requests
                )
            );
        }
        assert_eq!(pictures.screen_requests, 3);
        let busy = ScreensNews::Answer {
            asked: 0,
            status: monitor_status::BUSY,
        };
        assert!(
            pictures
                .screens_at(&screens, busy)
                .starts_with("MEDIA SCREENS request=4 status=busy shown=2 ")
        );
        // All screens at once; a monitor left of the primary; a size the
        // host does not know; a host with nothing to choose.
        screens = Screens {
            monitors: vec![entry(false, -1920, 1920, 1080), entry(true, 0, 0, 0)],
            all: true,
            shown: ALL_MONITORS,
            list: 3,
            seq: 9,
            remapped: true,
        };
        assert_eq!(
            pictures.screens_at(&screens, ScreensNews::Layout),
            "MEDIA SCREENS request=0 status=ok shown=all all=yes list=3 seq=9 remapped=yes \
             1:1920x1080-1920+0 2:0x0+0+0:main"
        );
        let none = Screens {
            monitors: Vec::new(),
            all: false,
            shown: 0,
            list: 0,
            seq: 0,
            remapped: false,
        };
        assert_eq!(
            pictures.screens_at(&none, ScreensNews::Layout),
            "MEDIA SCREENS request=0 status=ok shown=0 all=no list=0 seq=0 remapped=no"
        );
        for (code, name) in [
            (monitor_status::UNKNOWN, "unknown"),
            (monitor_status::FAILED, "failed"),
            (9, "code-9"),
        ] {
            assert!(
                media_screens_line(5, code, &none).contains(&format!(" status={name} ")),
                "{code}"
            );
        }
    }

    /// The monitors design §2: `doctor`'s `screens:` line lists a desktop's
    /// monitors by number, size and place (a negative offset left of the
    /// primary), `main` on the primary, and says why when they cannot be
    /// listed; a desktop whose capture lists none (Wayland, none at all)
    /// has no such line.
    #[test]
    #[allow(clippy::print_stderr)] // reports this machine's line
    fn doctor_lists_the_screens_a_session_can_switch_between() {
        use tornect_capture::{CaptureError, Monitor, Rect};
        let listed = Ok(vec![
            Monitor {
                id: 1,
                primary: true,
                rect: Rect::new(0, 0, 2560, 1440),
            },
            Monitor {
                id: 2,
                primary: false,
                rect: Rect::new(2560, 0, 1920, 1080),
            },
        ]);
        assert_eq!(
            screens_text(&listed),
            "screens: 2 (1 2560x1440+0+0 main, 2 1920x1080+2560+0)"
        );
        let left = Ok(vec![Monitor {
            id: 1,
            primary: false,
            rect: Rect::new(-1920, -120, 1920, 1080),
        }]);
        assert_eq!(screens_text(&left), "screens: 1 (1 1920x1080-1920-120)");
        let refused = Err(CaptureError::Unavailable("not an X11 session".to_owned()));
        assert_eq!(
            screens_text(&refused),
            "screens: unknown (capture unavailable: not an X11 session)"
        );
        assert_eq!(screens_line(&DesktopBackend::Wayland), None);
        assert_eq!(
            screens_line(&DesktopBackend::Unavailable("no seat".into())),
            None
        );
        // This machine's own X11 desktop, if any, or why not: under
        // `xvfb-run` with `XDG_SESSION_TYPE=x11`, the line of a real listing.
        #[cfg(target_os = "linux")]
        {
            let line = screens_line(&DesktopBackend::X11).expect("a line on X11");
            eprintln!("{line}");
            assert!(line.starts_with("screens: "), "{line}");
        }
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
        let cfg = Config::default();
        let token = paths.portal_restore_token().display().to_string();
        let wayland = capture_lines(&paths, &cfg, &DesktopBackend::Wayland).join("\n");
        assert!(wayland.contains("capture: wayland"), "{wayland}");
        assert!(wayland.contains(&token), "{wayland}");
        assert!(wayland.contains("absent"), "{wayland}");
        assert!(wayland.contains("delete"), "{wayland}");
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        std::fs::write(paths.portal_restore_token(), "t").unwrap();
        let kept = capture_lines(&paths, &cfg, &DesktopBackend::Wayland).join("\n");
        assert!(kept.contains("present"), "{kept}");
        let x11 = capture_lines(&paths, &cfg, &DesktopBackend::X11).join("\n");
        assert!(x11.contains("capture: x11"), "{x11}");
        assert!(!x11.contains("out of scope"), "{x11}");
        let none =
            capture_lines(&paths, &cfg, &DesktopBackend::Unavailable("no seat".into())).join("\n");
        assert!(none.contains("capture: none (no seat)"), "{none}");
    }

    /// `[services] wayland_clipboard`: off (the default) `doctor`'s capture
    /// lines are the two from before the switch, naming the grant file from
    /// before it; on, they name the clipboard request's own file, which the
    /// other request's grant never satisfies, and say the clipboard is asked
    /// for.
    #[test]
    fn doctor_names_the_grant_file_of_the_request_the_host_makes() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let mut cfg = Config::default();
        assert!(!cfg.services.wayland_clipboard, "off by default");
        let off = capture_lines(&paths, &cfg, &DesktopBackend::Wayland);
        assert_eq!(off.len(), 2, "{off:?}");
        assert!(
            off[1].starts_with(&format!(
                "  desktop grant: {} [absent]",
                paths.portal_restore_token().display()
            )),
            "{off:?}"
        );
        cfg.services.wayland_clipboard = true;
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        std::fs::write(paths.portal_restore_token(), "made without the clipboard").unwrap();
        let on = capture_lines(&paths, &cfg, &DesktopBackend::Wayland).join("\n");
        let with = paths.portal_restore_token_for(true).display().to_string();
        assert!(on.contains(&format!("{with} [absent]")), "{on}");
        assert!(on.contains("desktop clipboard: asked for"), "{on}");
        assert_eq!(
            crate::host::portal_token(&paths, &cfg),
            paths.portal_restore_token_for(true)
        );
    }

    /// The final review's revoke finding: a grant the other request made is
    /// named too, so that it is not left on disk unseen; with none, the
    /// lines are what they were.
    #[test]
    fn doctor_names_a_grant_the_other_request_left() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let mut cfg = Config::default();
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let with = paths.portal_restore_token_for(true);
        std::fs::write(&with, "made with the clipboard").unwrap();
        let off = capture_lines(&paths, &cfg, &DesktopBackend::Wayland);
        assert_eq!(off.len(), 3, "{off:?}");
        assert_eq!(
            off[2],
            format!(
                "  other desktop grant: {} [present], made with the clipboard; delete it too to \
                 revoke every remembered grant",
                with.display()
            )
        );
        std::fs::remove_file(&with).unwrap();
        assert_eq!(
            capture_lines(&paths, &cfg, &DesktopBackend::Wayland).len(),
            2
        );
        cfg.services.wayland_clipboard = true;
        std::fs::write(paths.portal_restore_token(), "made without").unwrap();
        let on = capture_lines(&paths, &cfg, &DesktopBackend::Wayland);
        assert!(
            on.last().unwrap().contains("made without the clipboard"),
            "{on:?}"
        );
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

    /// A viewer's services start whose news are kept, for [`services_over`].
    #[allow(clippy::type_complexity)] // a test's kept news
    fn kept_services(
        token: &tornect_signal::consent::SessionToken,
    ) -> (
        ServicesStart,
        Arc<std::sync::Mutex<Vec<ServicesNews>>>,
        mpsc::Sender<ViewerOp>,
    ) {
        let news = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (ops_tx, ops) = mpsc::channel(4);
        let report: ServicesReport = {
            let news = Arc::clone(&news);
            Arc::new(move |n| news.lock().unwrap().push(n))
        };
        let start = ServicesStart {
            binding: ServicesBinding::new(token, &[7; 32]),
            local: ViewerLocal::default(),
            ops,
            report,
        };
        (start, news, ops_tx)
    }

    /// Everything a stream shows of the host behind it: the bytes written
    /// back until it closed (or 30 s passed), and how long that took.
    async fn answer_of(mut client: DuplexStream, bytes: &[u8]) -> (Vec<u8>, Duration) {
        use tokio::io::AsyncReadExt as _;
        let started = tokio::time::Instant::now();
        client.write_all(bytes).await.unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), client.read_to_end(&mut answer))
            .await
            .expect("the host closes the stream")
            .unwrap();
        (answer, started.elapsed())
    }

    /// A media host on the test card, as the terminal host's.
    fn test_card_host() -> Arc<MediaHost> {
        Arc::new(MediaHost::new(
            Arc::new(SystemBackend::new(Source::TestCard)),
            Arc::new(tornect_session::NoObserver),
            MediaLimits::default(),
        ))
    }

    /// The review of steps 20–21: the terminal host's accept loop puts each
    /// stream where `dispatch` says: a media stream to its media host
    /// (junk: the media `BindRefused{PROTOCOL}`), a services stream to its
    /// services (junk: `Refused{PROTOCOL}`; a silent one is dropped
    /// unanswered at the bind deadline); a signaling stream comes back to the
    /// loop, and a stream on any other port is closed at once.
    #[tokio::test(start_paused = true)]
    async fn the_terminal_host_serves_each_port_with_its_host() {
        use tornect_proto::services::{SvcMsg, reason};
        let media = test_card_host();
        let services = terminal_services(&media);
        let mut streams = JoinSet::new();
        let mut open = |port: u16| {
            let (client, server) = duplex(1 << 16);
            let back = dispatch(server, port, &media, &services, &mut streams);
            (client, back)
        };

        let (_client, back) = open(SIGNALING_PORT);
        assert!(back.is_some(), "a signaling stream goes back to the loop");
        let (client, back) = open(4242);
        assert!(back.is_none());
        let (answer, took) = answer_of(client, &[]).await;
        assert!(
            answer.is_empty() && took.is_zero(),
            "{answer:?} after {took:?}"
        );

        let junk = [0x5a; 53];
        let (client, back) = open(MEDIA_PORT);
        assert!(back.is_none());
        let (answer, _) = answer_of(client, &junk).await;
        let refused = tornect_proto::Msg::BindRefused {
            reason: tornect_proto::reason::PROTOCOL,
        };
        let mut media_refusal = Vec::new();
        tornect_proto::write_msg(&mut media_refusal, &refused)
            .await
            .unwrap();
        assert_eq!(answer, media_refusal, "the media host answered");

        let (client, back) = open(SERVICES_PORT);
        assert!(back.is_none());
        let (answer, _) = answer_of(client, &junk).await;
        let services_refusal = SvcMsg::Refused {
            reason: reason::PROTOCOL,
        }
        .encode();
        assert_eq!(answer, services_refusal, "the services host answered");
        let (client, _) = open(SERVICES_PORT);
        let (answer, took) = answer_of(client, &[]).await;
        assert!(answer.is_empty(), "{answer:?}");
        assert!(
            took >= MediaLimits::default().bind_deadline,
            "dropped after {took:?}"
        );
        while streams.join_next().await.is_some() {}
    }

    /// Design `services` §0, §6.1, and the review of steps 20–21: the
    /// terminal host serves a bound session's services stream as a window
    /// host whose `[services]` switches are all off would: once the session's
    /// capture is live, `Refused{NOT_OFFERED}`. The viewer reports that once,
    /// as a stream that did not open with that code, and nothing else, and
    /// the session goes on. A stream that could not be reached is
    /// reported the same way with no code; a session that ends before its
    /// stream is bound reports nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_terminal_hosts_services_leave_the_session_without_them() {
        use tornect_core::DeviceId;
        use tornect_core::levels::Elevation;
        use tornect_proto::services::reason;
        use tornect_signal::fsm::host::{LiveSession, SessionSink as _};
        let token = tornect_signal::consent::SessionToken::new([0x51; 32]);
        let session_id = token.session_id();

        let media = test_card_host();
        let services = terminal_services(&media);
        media.on_start(&LiveSession {
            device: DeviceId::from_bytes([5; 32]),
            label: "Laptop",
            session_id: &session_id,
            token: &token,
            th_final: [7; 32],
            mode: SessionMode::Control,
            elevation: Elevation::None,
            unattended: false,
            transport: tornect_signal::consent::TransportPolicy::Any,
            viewer_dir1: false,
        });
        let mut streams = JoinSet::new();
        let (media_client, media_server) = duplex(1 << 22);
        assert!(dispatch(media_server, MEDIA_PORT, &media, &services, &mut streams).is_none());
        let viewer = MediaViewer::bind(
            media_client,
            &Binding::new(&token, &[7; 32]),
            MEDIA_BIND_WAIT,
        )
        .await
        .expect("the media stream binds");

        let (start, news, _ops) = kept_services(&token);
        let (client, server) = duplex(64 * 1024);
        assert!(dispatch(server, SERVICES_PORT, &media, &services, &mut streams).is_none());
        tokio::time::timeout(
            Duration::from_secs(20),
            services_over(async { Ok(client) }, start, std::future::pending()),
        )
        .await
        .expect("the refusal comes once capture is live");
        let heard = std::mem::take(&mut *news.lock().unwrap());
        assert!(
            matches!(
                heard.as_slice(),
                [ServicesNews::NotOpened(Some(reason::NOT_OFFERED))]
            ),
            "{heard:?}"
        );
        assert_eq!(media.live(), 1, "the session goes on");
        assert_eq!(services.open_streams(), 0);
        drop(viewer);
        media.on_end(&session_id, None);
        while streams.join_next().await.is_some() {}

        let (start, news, _ops) = kept_services(&token);
        let unreachable = async {
            Err::<DuplexStream, _>(ServicesBindError::Io(std::io::Error::other("no circuit")))
        };
        services_over(unreachable, start, std::future::pending()).await;
        let heard = std::mem::take(&mut *news.lock().unwrap());
        assert!(
            matches!(heard.as_slice(), [ServicesNews::NotOpened(None)]),
            "{heard:?}"
        );

        let (start, news, _ops) = kept_services(&token);
        let never = std::future::pending::<Result<DuplexStream, ServicesBindError>>();
        services_over(never, start, async {}).await;
        assert!(news.lock().unwrap().is_empty());
    }

    // Step A19 of design `direct`: the viewer's path phase in the app.

    /// The viewer's device in the sessions below.
    fn viewer_device() -> DeviceIdentity {
        DeviceIdentity::from_seed(&[0x22; 32])
    }

    /// A viewer's path context: the device of `seed`, `cfg`'s knobs, the
    /// machine `net`, and `--tor-only` or not.
    fn viewer_ctx(
        cfg: &Config,
        net: Arc<dyn tornect_net::NetEnv>,
        seed: u8,
        tor_only: bool,
    ) -> DirectCtx {
        DirectWiring {
            device: Arc::new(DeviceIdentity::from_seed(&[seed; 32])),
            knobs: DirectKnobs::new(cfg),
            net,
        }
        .ctx(tor_only)
    }

    /// One LAN segment: the viewer's machine at `.10` and the host's at
    /// `.20`.
    fn lan_pair(seed: u64) -> (MemHost, Arc<dyn tornect_net::NetEnv>) {
        let net = MemNet::new(seed);
        let lan = net.segment(LinkSpec::LAN);
        let viewer = net.machine(MachineSpec::on(lan, "192.168.1.10/24"));
        let host = net.machine(MachineSpec::on(lan, "192.168.1.20/24"));
        (viewer, Arc::new(host))
    }

    /// A session whose host is played by hand and signed `host_feats` and
    /// the transport policy `policy` ([`harness::raw_session_with`]): the
    /// session, its write switch and the host's end of the stream.
    ///
    /// [`harness::raw_session_with`]: tornect_signal::fsm::harness::raw_session_with
    async fn raw_direct(
        host_feats: &[&str],
        policy: u8,
    ) -> (ClientSession<Freezable>, Arc<AtomicBool>, DuplexStream) {
        let (client_end, host_end) = duplex(64 * 1024);
        let frozen = Arc::new(AtomicBool::new(false));
        let stream = Freezable {
            inner: client_end,
            frozen: Arc::clone(&frozen),
        };
        let (session, host) =
            tornect_signal::fsm::harness::raw_session_with(stream, host_end, host_feats, policy)
                .await;
        (session, frozen, host.into_stream())
    }

    /// An onion opener that counts its calls and never opens.
    fn never_opens(
        opens: &Arc<AtomicUsize>,
    ) -> impl Fn() -> std::future::Pending<anyhow::Result<DuplexStream>> {
        let opens = Arc::clone(opens);
        move || {
            opens.fetch_add(1, Ordering::SeqCst);
            std::future::pending()
        }
    }

    type Opening = std::pin::Pin<Box<dyn Future<Output = anyhow::Result<DuplexStream>> + Send>>;

    /// The onion media streams a test opened, and how the host's media
    /// port served each.
    #[derive(Clone, Default)]
    struct OnionLog {
        opens: Arc<AtomicUsize>,
        outcomes: Arc<std::sync::Mutex<Vec<MediaOutcome>>>,
    }

    impl OnionLog {
        /// The outcomes, once there are `n` of them (5 s at most).
        async fn outcomes(&self, n: usize) -> Vec<MediaOutcome> {
            for _ in 0..500 {
                if self.outcomes.lock().unwrap().len() >= n {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            self.outcomes.lock().unwrap().clone()
        }
    }

    /// An onion opener whose streams `media` serves as `tornect host`'s
    /// `MEDIA_PORT` listener does ([`MediaHost::serve`]), logged in `log`.
    fn onion_to(media: &Arc<MediaHost>, log: &OnionLog) -> impl Fn() -> Opening + use<> {
        let (media, log) = (Arc::clone(media), log.clone());
        move || {
            log.opens.fetch_add(1, Ordering::SeqCst);
            let (media, outcomes) = (Arc::clone(&media), Arc::clone(&log.outcomes));
            Box::pin(async move {
                let (viewer_end, host_end) = duplex(1 << 20);
                tokio::spawn(async move {
                    let outcome = media.serve(host_end).await;
                    outcomes.lock().unwrap().push(outcome);
                });
                Ok(viewer_end)
            })
        }
    }

    /// The test card, served as `tornect host --capture test-card` serves it.
    fn test_card() -> Arc<MediaHost> {
        Arc::new(MediaHost::new(
            Arc::new(SystemBackend::new(Source::TestCard)),
            Arc::new(tornect_session::NoObserver),
            MediaLimits::default(),
        ))
    }

    /// A host wired as `tornect host` wires it ([`crate::host::wire`]: the
    /// real FSM, its `DirectHost` with the knobs of `cfg`, the media host
    /// `media`) on the machine `net`, and the session the viewer
    /// ([`viewer_device`]) opened with it over a pipe, announcing what
    /// [`viewer_config`] announces.
    struct Rig {
        _tmp: tempfile::TempDir,
        _wiring: HostWiring,
        session: ClientSession<DuplexStream>,
    }

    async fn rig(cfg: &Config, net: Arc<dyn tornect_net::NetEnv>, media: Arc<MediaHost>) -> Rig {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let consent = Arc::new(ScriptedConsent::new());
        consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
        consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
        let direct = DirectWiring {
            device: Arc::new(DeviceIdentity::from_seed(&[0x44; 32])),
            knobs: DirectKnobs::new(cfg),
            net,
        };
        let wiring = crate::host::wire(
            &paths,
            cfg,
            Arc::clone(&identity),
            direct,
            consent,
            media,
            ControlChannel::default(),
        )
        .unwrap();
        let (client_end, host_end) = duplex(64 * 1024);
        let (host_cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        tokio::spawn(async move {
            crate::host::serve_signaling(host_end, &host_cfg, &deps, |_| {}).await
        });
        let known = Arc::new(KnownHostStore::with(
            tmp.path().join("viewer-known-hosts.toml"),
            KnownHosts::default(),
        ));
        let mut client_deps = ClientDeps::headless(known);
        client_deps.ui = Arc::new(ScriptedClientUi::new(true));
        let ccfg = viewer_config(identity.id(), "Laptop".to_owned());
        let session = match client::connect(
            client_end,
            &ccfg,
            &viewer_device(),
            &client_deps,
            Intent::Session,
        )
        .await
        .unwrap()
        {
            ClientOutcome::Session(session) => *session,
            ClientOutcome::Paired { .. } => panic!("expected a session"),
        };
        Rig {
            _tmp: tmp,
            _wiring: wiring,
            session,
        }
    }

    /// Design `direct` §8.2 and the step A19 caller obligation (c): a
    /// viewer announces `dir1` in its `HELLO`, the one token the host's
    /// direct half waits for (the sessions below show the host taking part
    /// because of it).
    #[test]
    fn a_viewer_announces_the_direct_exchange() {
        let id = HostIdentity::from_seed(&[0x11; 32]).id();
        let cfg = viewer_config(id, "Laptop".to_owned());
        assert_eq!(cfg.feats, vec![feats::DIR1.to_owned()]);
        assert_eq!(cfg.name, "Laptop");
    }

    /// Design `direct` §4 and §3.5 through the caller, with the host wired
    /// as `tornect host` wires it, both on one LAN: the host takes part (the
    /// viewer's `dir1`), the media goes direct within the punch window, and
    /// the lines read `ROUTE direct lan` and `PATH host <ms> ms`; the onion
    /// stream opened beside the path phase is dropped unused (the host's
    /// `Abandoned`), and the host's route is `lan`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_viewer_on_the_hosts_lan_goes_direct_and_says_so() {
        let (viewer_net, host_net) = lan_pair(5);
        let media = test_card();
        let mut rig = rig(&Config::default(), host_net, Arc::clone(&media)).await;
        let session = &mut rig.session;
        assert!(session.host_has(feats::DIR1));
        let sid = session.session_token().session_id();
        let ctx = viewer_ctx(&Config::default(), Arc::new(viewer_net), 0x22, false);
        let log = OnionLog::default();
        let binding = Binding::new(session.session_token(), &session.th());
        let (_stop, stopped) = watch::channel(false);
        let bound = bind_media(session, &ctx, &binding, onion_to(&media, &log), &stopped)
            .await
            .unwrap_or_else(|end| panic!("not bound: {end:?}"));
        assert!(matches!(bound.media, MediaPath::Direct(_)));
        assert_eq!(crate::direct::route_line(&bound.end), "ROUTE direct lan");
        assert_eq!(bound.winner, Some(CandidateKind::Host));
        assert!(
            bound.elapsed < Duration::from_secs(4),
            "{:?}",
            bound.elapsed
        );
        let path = crate::direct::path_line(bound.winner, bound.elapsed);
        assert!(
            path.starts_with("PATH host ") && path.ends_with(" ms"),
            "{path}"
        );
        assert!(
            bound.onion_services,
            "an `any` session's services stay on Tor until B10"
        );
        assert_eq!(media.route(&sid), Some(TransportKind::Lan));
        assert_eq!(log.opens.load(Ordering::SeqCst), 1, "opened beside the try");
        assert_eq!(log.outcomes(1).await, vec![MediaOutcome::Abandoned]);
    }

    /// DIRECT-2's one exception through the caller: a link whose key is
    /// not the session's device key is refused by the host's TLS before any
    /// stream byte, so the bind fails with [`AfterBind::Fallback`]; the
    /// viewer sends `TOR_FALLBACK{QUIC}` and binds a fresh onion stream:
    /// `ROUTE tor quic`, `PATH - <ms> ms`, the host's route `tor`. The
    /// stream opened beside the path phase was dropped at the direct choice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_direct_connection_the_host_refuses_falls_back_to_a_fresh_onion_stream() {
        let (viewer_net, host_net) = lan_pair(6);
        let media = test_card();
        let mut rig = rig(&Config::default(), host_net, Arc::clone(&media)).await;
        let session = &mut rig.session;
        let sid = session.session_token().session_id();
        // The link presents device 0x23's key; the session is 0x22's.
        let ctx = viewer_ctx(&Config::default(), Arc::new(viewer_net), 0x23, false);
        let log = OnionLog::default();
        let binding = Binding::new(session.session_token(), &session.th());
        let (_stop, stopped) = watch::channel(false);
        let bound = bind_media(session, &ctx, &binding, onion_to(&media, &log), &stopped)
            .await
            .unwrap_or_else(|end| panic!("not bound: {end:?}"));
        assert!(matches!(bound.media, MediaPath::Onion(_)));
        assert_eq!(crate::direct::route_line(&bound.end), "ROUTE tor quic");
        assert_eq!(bound.winner, None);
        assert!(crate::direct::path_line(bound.winner, bound.elapsed).starts_with("PATH - "));
        assert_eq!(media.route(&sid), Some(TransportKind::TorRelay));
        assert_eq!(
            log.opens.load(Ordering::SeqCst),
            2,
            "the early one and a fresh one"
        );
        assert_eq!(log.outcomes(1).await[0], MediaOutcome::Abandoned);
    }

    /// DIRECT-2's pre-open through the caller: a host with no address
    /// answers the viewer's candidates with `TOR_FALLBACK{NO_ADDRESSES}`,
    /// and the onion stream opened beside the path phase is the one bound:
    /// one open in all, `ROUTE tor host-no-addresses`, the host's route
    /// `tor`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_try_that_ends_on_tor_binds_the_stream_opened_beside_it() {
        let (viewer_net, _) = lan_pair(13);
        let media = test_card();
        let host_net = crate::direct::no_network();
        let mut rig = rig(&Config::default(), host_net, Arc::clone(&media)).await;
        let session = &mut rig.session;
        let sid = session.session_token().session_id();
        let ctx = viewer_ctx(&Config::default(), Arc::new(viewer_net), 0x22, false);
        let log = OnionLog::default();
        let binding = Binding::new(session.session_token(), &session.th());
        let (_stop, stopped) = watch::channel(false);
        let bound = bind_media(session, &ctx, &binding, onion_to(&media, &log), &stopped)
            .await
            .unwrap_or_else(|end| panic!("not bound: {end:?}"));
        assert!(matches!(bound.media, MediaPath::Onion(_)));
        assert_eq!(
            crate::direct::route_line(&bound.end),
            "ROUTE tor host-no-addresses"
        );
        assert_eq!(bound.winner, None);
        assert_eq!(media.route(&sid), Some(TransportKind::TorRelay));
        assert_eq!(
            log.opens.load(Ordering::SeqCst),
            1,
            "the one opened beside the try"
        );
    }

    /// Design `direct` §5.5 (DIRECT-6) at the viewer's sinks: a host whose
    /// key is pinned reads the `Bind`, then closes the direct connection
    /// with a reason of its own (control sequences included). The `MEDIA
    /// FAILED` line, the error `connect` returns (its chain, and its
    /// `Debug` as the terminal prints it), and the line of a bound stream
    /// that broke the same way say fixed words only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hosts_close_reason_is_never_printed() {
        use crate::test_support::{HOSTILE_REASON, bind_closed_with_reason, none_holds_the_reason};

        let failed = bind_closed_with_reason(HOSTILE_REASON).await;
        assert!(
            matches!(failed, ViewerError::Proto(ProtoError::Io(_))),
            "{failed:?}"
        );
        let viewed = Err(failed);
        let broke = media_end(&viewed, &End::You);
        let Err(failed) = viewed else { unreachable!() };
        assert_eq!(
            broke,
            "MEDIA FAILED: media stream I/O: the direct connection closed"
        );
        let end = End::NoPicture(bind_failed(failed));
        let line = unbound_line(&end);
        // `ProtoError::Io` says its I/O error and hands it on as its source
        // too, so the chain says the fixed words twice.
        assert_eq!(
            line,
            "MEDIA FAILED: binding the media stream: media stream I/O: the direct connection \
             closed: the direct connection closed"
        );
        let End::NoPicture(e) = end else {
            unreachable!()
        };
        none_holds_the_reason(&[broke, line, format!("{e:#}"), format!("{e:?}")]);
    }

    /// The early onion stream (DIRECT-2's pre-open): used while it is
    /// younger than [`ONION_PREOPEN_MAX`] (still opening counts), replaced
    /// by one fresh open when it is older or its open failed; with nothing
    /// opened beside the path phase the fresh open is the only one.
    #[tokio::test(start_paused = true)]
    async fn the_early_onion_stream_is_used_young_and_replaced_stale_or_failed() {
        type Open = std::future::Ready<anyhow::Result<u8>>;
        let early = |ok: bool| -> Preopen<Open> {
            let opened = if ok {
                Ok(1)
            } else {
                Err(anyhow::anyhow!("refused"))
            };
            Preopen::start(std::future::ready(opened))
        };
        let fresh = || -> Open { std::future::ready(Ok(2)) };
        for (mut preopen, took, bound) in [
            (early(true), Duration::from_secs(3), 1),
            (early(true), ONION_PREOPEN_MAX + Duration::from_secs(1), 2),
            (early(false), Duration::from_secs(1), 2),
            (Preopen::None, Duration::from_secs(1), 2),
        ] {
            preopen.beside(tokio::time::sleep(took)).await;
            assert!(!matches!(preopen, Preopen::Opening(..)), "{took:?}");
            assert_eq!(preopen.take(fresh).await.unwrap(), bound, "{took:?}");
        }
        // A path phase that ended before the open is still waited for.
        let mut opening = early(true);
        opening.beside(std::future::ready(())).await;
        assert!(matches!(opening, Preopen::Opening(..)));
        let unused = || -> Open { unreachable!("the early stream is used") };
        assert_eq!(opening.take(unused).await.unwrap(), 1);
    }

    /// The pre-open's age counts from the start of its open, not its end:
    /// the host's bind deadline runs from its accept, which comes before the
    /// open ends here. An open that took 3 s is replaced when the path
    /// phase fails 10 s after it started (it would be 7 s old counted from
    /// its end), and used when the phase fails at 7.5 s.
    #[tokio::test(start_paused = true)]
    async fn the_early_onion_streams_age_counts_from_its_open() {
        type Open = std::pin::Pin<Box<dyn Future<Output = anyhow::Result<u8>> + Send>>;
        let slow_open = || -> Open {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(3)).await;
                Ok(1)
            })
        };
        let fresh = || -> Open { Box::pin(std::future::ready(Ok(2))) };
        for (failed_at, bound) in [
            (Duration::from_secs(10), 2),
            (Duration::from_millis(7_500), 1),
        ] {
            let mut preopen = Preopen::start(slow_open());
            preopen.beside(tokio::time::sleep(failed_at)).await;
            assert!(matches!(preopen, Preopen::Opened(..)), "{failed_at:?}");
            assert_eq!(preopen.take(fresh).await.unwrap(), bound, "{failed_at:?}");
        }
    }

    /// The margin [`ONION_PREOPEN_MAX`] keeps below the host's bind
    /// deadline: a `Bind` written on a pre-open just under the maximum age
    /// still has 2 s at the host for the write and the host's read.
    #[test]
    fn the_preopen_age_stays_below_the_hosts_bind_deadline() {
        let deadline = MediaLimits::default().bind_deadline;
        assert!(
            ONION_PREOPEN_MAX + Duration::from_secs(2) <= deadline,
            "{ONION_PREOPEN_MAX:?} against {deadline:?}"
        );
    }

    /// Decision M1-85 at DIRECT-2's exception: a `lan_only` viewer whose
    /// direct connection the host's TLS refused does not fall back; the
    /// session ends `BYE{NO_LAN_PATH}` and no onion stream is ever opened.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_lan_only_viewer_whose_connection_is_refused_does_not_fall_back() {
        let (viewer_net, host_net) = lan_pair(12);
        let media = test_card();
        let mut rig = rig(&Config::default(), host_net, Arc::clone(&media)).await;
        let session = &mut rig.session;
        let mut lan_only = Config::default();
        lan_only.network.lan_only = true;
        let ctx = viewer_ctx(&lan_only, Arc::new(viewer_net), 0x23, false);
        let log = OnionLog::default();
        let binding = Binding::new(session.session_token(), &session.th());
        let (_stop, stopped) = watch::channel(false);
        let end = bind_media(session, &ctx, &binding, onion_to(&media, &log), &stopped)
            .await
            .expect_err("the session ends");
        assert!(matches!(end, End::Refused(bye::NO_LAN_PATH)), "{end:?}");
        assert_eq!(unbound_line(&end), "ROUTE none no-lan-path");
        assert_eq!(log.opens.load(Ordering::SeqCst), 0);
    }

    /// Design `direct` §3.5 and §4, the policy rows of the live recipe:
    /// `--tor-only` reads `ROUTE tor here-off`, a paranoid host
    /// `ROUTE tor policy`; neither reads an interface nor opens an onion
    /// stream beside the path phase, one is opened after it, and the host's
    /// route is `tor`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_tor_decision_reads_no_interface_and_binds_the_onion_stream() {
        for (seed, paranoid_host, tor_only, route) in [
            (7, false, true, "ROUTE tor here-off"),
            (8, true, false, "ROUTE tor policy"),
        ] {
            let (viewer_net, host_net) = lan_pair(seed);
            let mut host_cfg = Config::default();
            host_cfg.network.paranoid = paranoid_host;
            let media = test_card();
            let mut rig = rig(&host_cfg, host_net, Arc::clone(&media)).await;
            let session = &mut rig.session;
            let sid = session.session_token().session_id();
            let counting = CountingEnv::new(viewer_net);
            let ctx = viewer_ctx(&Config::default(), counting.clone(), 0x22, tor_only);
            let log = OnionLog::default();
            let binding = Binding::new(session.session_token(), &session.th());
            let (_stop, stopped) = watch::channel(false);
            let bound = bind_media(session, &ctx, &binding, onion_to(&media, &log), &stopped)
                .await
                .unwrap_or_else(|end| panic!("{route}: not bound: {end:?}"));
            assert_eq!(crate::direct::route_line(&bound.end), route);
            assert!(
                crate::direct::path_line(bound.winner, bound.elapsed).starts_with("PATH - "),
                "{route}"
            );
            assert!(matches!(bound.media, MediaPath::Onion(_)), "{route}");
            assert_eq!(counting.calls().total(), 0, "{route}");
            assert_eq!(log.opens.load(Ordering::SeqCst), 1, "{route}");
            assert_eq!(media.route(&sid), Some(TransportKind::TorRelay), "{route}");
        }
    }

    /// The step A19 caller obligation (a): the stop is wired for the whole
    /// path phase. A host that announced `dir1` and never answers is cut
    /// short by the stop at 1 s, well inside the 4 s punch window; a host
    /// that stops reading stalls the viewer's `CANDIDATES` write past the
    /// window, and the stop still ends it when it comes (6 s). Each time
    /// the onion stream was being opened beside the try.
    #[tokio::test(start_paused = true)]
    async fn a_stop_ends_the_path_phase_whatever_the_host_does() {
        for (stalled, at) in [(false, 1), (true, 6)] {
            let (mut session, frozen, _host) =
                raw_direct(&[feats::DIR1], messages::transport::ANY).await;
            frozen.store(stalled, Ordering::SeqCst);
            let (viewer_net, _) = lan_pair(9);
            let ctx = viewer_ctx(&Config::default(), Arc::new(viewer_net), 0x22, false);
            let (stop, stopped) = watch::channel(false);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(at)).await;
                let _ = stop.send(true);
            });
            let opens = Arc::new(AtomicUsize::new(0));
            let binding = Binding::new(session.session_token(), &session.th());
            let t0 = tokio::time::Instant::now();
            let end = bind_media(&mut session, &ctx, &binding, never_opens(&opens), &stopped).await;
            assert!(matches!(end, Err(End::You)), "stalled {stalled}: {end:?}");
            let took = t0.elapsed();
            assert!(
                took >= Duration::from_secs(at)
                    && took < Duration::from_secs(at) + Duration::from_millis(100),
                "stalled {stalled}: {took:?}"
            );
            assert_eq!(opens.load(Ordering::SeqCst), 1, "stalled {stalled}");
        }
    }

    /// A desktop whose dialog nobody answers: `open_source` waits until its
    /// session is cancelled (20 s at most), saying when it was asked and
    /// whether the cancel came.
    struct Unanswered {
        asked: watch::Sender<bool>,
        cancelled: Arc<AtomicBool>,
    }

    impl tornect_session::MediaBackend for Unanswered {
        fn open_source(
            &self,
            _: tornect_session::SourceRequest,
            cancel: watch::Receiver<bool>,
        ) -> Result<Box<dyn tornect_capture::VideoSource>, tornect_capture::CaptureError> {
            self.asked.send_replace(true);
            let since = Instant::now();
            while !*cancel.borrow() && since.elapsed() < Duration::from_secs(20) {
                std::thread::sleep(Duration::from_millis(10));
            }
            self.cancelled.store(*cancel.borrow(), Ordering::SeqCst);
            Err(tornect_capture::CaptureError::Unavailable(
                "nobody answered".to_owned(),
            ))
        }

        fn open_injector(&self) -> Option<Box<dyn tornect_input::InputSink>> {
            None
        }
    }

    /// The step A19 caller obligations (b) and the bind wait: the direct
    /// bind is raced against the stop, and it waits the media bind wait,
    /// never the punch window. The host's source waits on a dialog nobody
    /// answers; 5 s after the host was asked (past the 4 s punch window,
    /// where a bind given the punch window would have timed out) the stop
    /// comes and the bind ends at once as the user's. The caller's `BYE`
    /// then ends the session and the host's open is cancelled: nothing was
    /// captured.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stop_ends_a_direct_bind_the_host_has_not_answered() {
        let (viewer_net, host_net) = lan_pair(10);
        let (asked_tx, mut asked) = watch::channel(false);
        let cancelled = Arc::new(AtomicBool::new(false));
        let media = Arc::new(MediaHost::new(
            Arc::new(Unanswered {
                asked: asked_tx,
                cancelled: Arc::clone(&cancelled),
            }),
            Arc::new(tornect_session::NoObserver),
            MediaLimits::default(),
        ));
        let Rig {
            _tmp,
            _wiring,
            mut session,
        } = rig(&Config::default(), host_net, Arc::clone(&media)).await;
        let ctx = viewer_ctx(&Config::default(), Arc::new(viewer_net), 0x22, false);
        let (stop, stopped) = watch::channel(false);
        let stopper = tokio::spawn(async move {
            let _ = asked.wait_for(|asked| *asked).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
            let _ = stop.send(true);
            Instant::now()
        });
        let log = OnionLog::default();
        let binding = Binding::new(session.session_token(), &session.th());
        let end = tokio::time::timeout(
            Duration::from_secs(25),
            bind_media(
                &mut session,
                &ctx,
                &binding,
                onion_to(&media, &log),
                &stopped,
            ),
        )
        .await
        .expect("the stop ends the bind before its own 30 s wait");
        let stopped_at = stopper.await.unwrap();
        assert!(matches!(end, Err(End::You)), "{end:?}");
        assert!(
            stopped_at.elapsed() < Duration::from_secs(1),
            "ended at the stop"
        );
        session.bye(bye::USER).await.unwrap();
        for _ in 0..1000 {
            if cancelled.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            cancelled.load(Ordering::SeqCst),
            "the host's open was cancelled"
        );
    }

    /// Decision M1-85 (DIRECT-8) through the caller: a `lan_only` viewer
    /// with no same-site path (here, no address at all) ends the session:
    /// `ROUTE none no-lan-path`, no `TOR_FALLBACK`, no onion stream, and the
    /// caller's `BYE{NO_LAN_PATH}` is the host's next frame; `connect` then
    /// fails, which is exit status 1.
    #[tokio::test(start_paused = true)]
    async fn a_lan_only_viewer_with_no_path_ends_the_session() {
        let (mut session, _frozen, mut host) =
            raw_direct(&[feats::DIR1], messages::transport::ANY).await;
        let mut cfg = Config::default();
        cfg.network.lan_only = true;
        let ctx = viewer_ctx(&cfg, crate::direct::no_network(), 0x22, false);
        let opens = Arc::new(AtomicUsize::new(0));
        let binding = Binding::new(session.session_token(), &session.th());
        let (_stop, stopped) = watch::channel(false);
        let end = bind_media(&mut session, &ctx, &binding, never_opens(&opens), &stopped)
            .await
            .expect_err("the session ends");
        assert!(matches!(end, End::Refused(bye::NO_LAN_PATH)), "{end:?}");
        assert_eq!(unbound_line(&end), "ROUTE none no-lan-path");
        assert_eq!(end.bye(), Some(bye::NO_LAN_PATH));
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        assert!(refused_why(bye::NO_LAN_PATH).contains("network.lan_only"));
        let code = end.bye().unwrap();
        let (byed, frame) = tokio::join!(session.bye(code), client_frame(&mut host));
        drop(byed);
        assert_eq!(frame.kind, Kind::Bye, "the first frame after the accept");
        let said: messages::Bye = decode_body(&frame.body).unwrap();
        assert_eq!(said.reason, bye::NO_LAN_PATH);
    }

    /// Design `direct` §3.5: `connect --no-video` answers
    /// `TOR_FALLBACK{NO_MEDIA}` at once, reads no interface and binds
    /// nothing; its route line is `ROUTE none`.
    #[tokio::test(start_paused = true)]
    async fn a_session_without_media_answers_no_media_and_reads_no_interface() {
        let (mut session, _frozen, mut host) =
            raw_direct(&[feats::DIR1], messages::transport::ANY).await;
        let (viewer_net, _) = lan_pair(11);
        let counting = CountingEnv::new(viewer_net);
        let ctx = viewer_ctx(&Config::default(), counting.clone(), 0x22, false);
        let (_stop, stopped) = watch::channel(false);
        no_media(&mut session, &ctx, &stopped).await.unwrap();
        let frame = client_frame(&mut host).await;
        assert_eq!(frame.kind, Kind::TorFallback);
        let said: messages::TorFallback = decode_body(&frame.body).unwrap();
        assert_eq!(said.reason, Some(fallback::NO_MEDIA));
        assert_eq!(counting.calls().total(), 0);
        assert_eq!(crate::direct::route_line(&PathEnd::NoMedia), "ROUTE none");
    }

    /// The step A19 caller obligation (d): path frames that come after the
    /// path phase chose (a host's `CANDIDATES`, `CANDIDATES_DONE` and
    /// `TOR_FALLBACK` between two pings) are neither a fault nor acted on:
    /// the keep-alive pings on and ends as asked, and writes nothing but its
    /// pings.
    #[tokio::test(start_paused = true)]
    async fn late_path_frames_are_neither_a_fault_nor_acted_on() {
        use tokio::io::AsyncWriteExt as _;
        let (mut session, _frozen, mut host, mut msg_id) = raw_live().await;
        let candidates = messages::Candidates {
            candidates: vec![messages::Candidate {
                kind: messages::candidate_kind::HOST,
                ip: vec![192, 168, 1, 20],
                port: 40_000,
            }],
            scope: Some(messages::scope::SAME_SITE),
        };
        let play = async move {
            let ping = client_frame(&mut host).await;
            host.write_all(&pong_for(msg_id, &ping)).await.unwrap();
            msg_id += 1;
            for (kind, body) in [
                (Kind::Candidates, encode_body(&candidates)),
                (
                    Kind::CandidatesDone,
                    encode_body(&messages::CandidatesDone {}),
                ),
                (
                    Kind::TorFallback,
                    encode_body(&messages::TorFallback {
                        reason: Some(fallback::NO_PATH),
                    }),
                ),
            ] {
                host.write_all(&host_frame(msg_id, kind, body))
                    .await
                    .unwrap();
                msg_id += 1;
            }
            let ping = client_frame(&mut host).await;
            host.write_all(&pong_for(msg_id, &ping)).await.unwrap();
            host
        };
        let (end, mut host) = tokio::join!(
            keep_alive(
                &mut session,
                Some(2),
                Duration::from_secs(10),
                std::future::pending()
            ),
            play
        );
        assert!(matches!(end.unwrap(), End::You));
        let more = tokio::time::timeout(Duration::from_secs(30), client_frame(&mut host)).await;
        assert!(more.is_err(), "nothing more was written: {more:?}");
    }

    /// How each end of the path phase reaches the session's end, and the
    /// `BYE` each end owes the host.
    #[test]
    fn the_path_phase_ends_are_the_sessions() {
        let bye_end = into_path(PathChoice::HostEnded(SessionEvent::Bye {
            reason: bye::PANIC,
            detail: None,
        }));
        assert!(matches!(bye_end, Err(End::Host(bye::PANIC))));
        let error_end = into_path(PathChoice::HostEnded(SessionEvent::Error {
            code: codes::E_BAD_STATE,
            detail: None,
        }));
        assert!(matches!(
            error_end,
            Err(End::Lost(HandshakeError::PeerError {
                code: codes::E_BAD_STATE,
                ..
            }))
        ));
        assert!(matches!(
            into_path(PathChoice::Broken(HandshakeError::Closed)),
            Err(End::Lost(HandshakeError::Closed))
        ));
        assert!(matches!(into_path(PathChoice::Interrupted), Err(End::You)));
        assert!(matches!(
            into_path(PathChoice::End(bye::NO_LAN_PATH)),
            Err(End::Refused(bye::NO_LAN_PATH))
        ));
        assert!(matches!(
            into_path(PathChoice::NoMedia),
            Ok(PathChoice::NoMedia)
        ));
        assert_eq!(End::You.bye(), Some(bye::USER));
        assert_eq!(End::NoPicture(anyhow::anyhow!("x")).bye(), Some(bye::USER));
        assert_eq!(End::Refused(bye::NO_LAN_PATH).bye(), Some(bye::NO_LAN_PATH));
        assert_eq!(End::Host(bye::PANIC).bye(), None);
        assert_eq!(End::Lost(HandshakeError::Closed).bye(), None);
        assert_eq!(
            unbound_line(&End::Host(bye::PANIC)),
            "MEDIA ENDED (the session ended before the first picture)"
        );
        assert_eq!(
            unbound_line(&End::You),
            "MEDIA ENDED (by you, before the first picture)"
        );
    }
}
