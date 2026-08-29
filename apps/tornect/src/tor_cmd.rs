//! `tornect host` and `tornect ping`: Milestone 1 track 1 — signaling over the
//! live Tor network with the interim ping protocol.

use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tornect_core::keystore::{FileSecretStore, load_or_create_host_identity};
use tornect_core::{Config, HostIdentity, Paths, TornectId};
use tornect_signal::framing::FrameError;
use tornect_signal::ping::NONCE_LEN;
use tornect_signal::tor::Admission;
use tornect_signal::{
    OnionStatus, SignalError, TorNode, install_crypto_provider, ping, shutdown_runtime,
};

/// Per-ping reply deadline once the stream is open.
const PING_TIMEOUT: Duration = Duration::from_secs(30);

/// Ping sessions served at once. Every stream the listener hands out comes
/// from an unauthenticated peer, and each session costs a task for up to
/// `ping::SESSION_TIMEOUT`; one per live rendezvous circuit
/// (`tornect_signal::tor::MAX_LIVE_CIRCUITS`) is what honest use needs, so
/// streams beyond that are closed immediately.
const MAX_PING_SESSIONS: usize = tornect_signal::tor::MAX_LIVE_CIRCUITS;

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating the tokio runtime")
}

/// `tornect host [--once] [--pow|--no-pow]`
pub fn host(paths: &Paths, once: bool, pow: Option<bool>) -> anyhow::Result<()> {
    install_crypto_provider();
    paths.ensure().context("creating Tornect directories")?;
    let store = FileSecretStore::open(paths.keys_dir()).context("opening keystore")?;
    let (identity, created) = load_or_create_host_identity(&store)?;
    if created {
        eprintln!(
            "generated a new Tornect ID (stored in {})",
            paths.keys_dir().display()
        );
    }
    let mut cfg = Config::load(&paths.config_file())?;
    if let Some(pow) = pow {
        cfg.tor.pow_defense = pow;
    }
    block_on(run_host(paths, &cfg, &identity, once))
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
    identity: &HostIdentity,
    once: bool,
) -> anyhow::Result<()> {
    eprintln!("bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...");
    let node = TorNode::start(paths, cfg)
        .await
        .context("starting the embedded Tor client")?;
    let progress = spawn_progress_reporter(&node);

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
        .publish(identity)
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

    let (answered_tx, mut answered_rx) = watch::channel(0u64);
    let sessions = Arc::new(Semaphore::new(MAX_PING_SESSIONS));
    let mut ctrl_c = pin!(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            result = &mut ctrl_c => {
                result.context("waiting for Ctrl-C")?;
                eprintln!("Ctrl-C: shutting down");
                break;
            }
            stream = listener.accept() => {
                let Some(mut stream) = stream else {
                    eprintln!("listener closed");
                    break;
                };
                // Dropping the stream closes it; the peer sees EOF.
                let Ok(session) = Arc::clone(&sessions).try_acquire_owned() else {
                    eprintln!(
                        "client connected over Tor but {MAX_PING_SESSIONS} sessions are \
                         already being served; closing it"
                    );
                    continue;
                };
                eprintln!("client connected over Tor");
                let answered = answered_tx.clone();
                tokio::spawn(async move {
                    let _session = session;
                    let outcome = ping::serve(&mut stream, |n| {
                        println!("answered ping #{n}");
                        answered.send_modify(|total| *total += 1);
                    })
                    .await;
                    match outcome {
                        Ok(n) => eprintln!("client disconnected after {n} ping(s)"),
                        Err(e) => eprintln!("ping session ended: {e}"),
                    }
                });
            }
            changed = answered_rx.changed(), if once => {
                if changed.is_err() || *answered_rx.borrow() >= 1 {
                    eprintln!("first ping answered; exiting (--once)");
                    break;
                }
            }
        }
    }

    status.abort();
    progress.abort();
    drop(listener);
    node.shutdown().await;
    Ok(())
}

/// `tornect ping <onion> [--count N]`
pub fn ping(paths: &Paths, onion: &str, count: u32) -> anyhow::Result<()> {
    install_crypto_provider();
    let id: TornectId = onion
        .parse()
        .map_err(|e| anyhow::anyhow!("{onion:?} is not a Tornect ID: {e}"))?;
    let cfg = Config::load(&paths.config_file())?;
    block_on(run_ping(paths, &cfg, id, count))
}

async fn run_ping(paths: &Paths, cfg: &Config, id: TornectId, count: u32) -> anyhow::Result<()> {
    eprintln!("bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...");
    let node = TorNode::start(paths, cfg)
        .await
        .context("starting the embedded Tor client")?;
    let progress = spawn_progress_reporter(&node);
    node.wait_ready(Duration::from_secs(u64::from(
        cfg.tor.bootstrap_timeout_secs,
    )))
    .await
    .map_err(explain)?;
    progress.abort();

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

/// Nonces only need to be unique per stream; wall-clock nanoseconds mixed with
/// the sequence number are plenty.
fn nonce(seq: u32) -> [u8; NONCE_LEN] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    ((nanos as u64) ^ (u64::from(seq) << 48)).to_be_bytes()
}

fn spawn_progress_reporter(node: &TorNode) -> JoinHandle<()> {
    let mut rx = node.bootstrap_progress();
    tokio::spawn(async move {
        let mut last_pct = u32::MAX;
        let mut last_blocked: Option<String> = None;
        loop {
            let p = rx.borrow_and_update().clone();
            let pct = (p.fraction * 100.0).round() as u32;
            if pct != last_pct || p.blocked != last_blocked {
                match &p.blocked {
                    Some(why) => eprintln!("tor: bootstrap {pct:3}% - stuck: {why}"),
                    None => eprintln!("tor: bootstrap {pct:3}%"),
                }
                last_pct = pct;
                last_blocked.clone_from(&p.blocked);
            }
            if p.ready {
                eprintln!("tor: ready");
                break;
            }
            if rx.changed().await.is_err() {
                break;
            }
        }
    })
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
            "Tor could not bootstrap. Check the network connection; a full disk also \
             shows up this way (the Tor cache lives under `tornect paths`)."
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
