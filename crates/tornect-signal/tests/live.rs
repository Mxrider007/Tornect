//! Live-network integration tests: a host and a client, each with its own Tor
//! client and state directory, in one process over the real Tor network.
//!
//! Ignored by default (each needs the network and 1–3 minutes). Run with:
//!
//! ```text
//! CARGO_BUILD_JOBS=3 cargo test -p tornect-signal --test live -- --ignored --nocapture
//! ```
//!
//! State lives under `target/tornect-test/live/{host,client}` (never `/tmp`,
//! which is a small tmpfs on the dev VM); a second run reuses the caches and
//! must print the same Tornect ID. Set `TORNECT_LOG` (e.g.
//! `tornect_signal=debug,tor_hsservice::pow=debug,tor_hsclient::pow=debug`) to
//! see Arti's and the listener's own logs alongside the timeline.

// Progress lines are the point of an interactive live test.
#![allow(clippy::print_stderr)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tornect_core::keystore::{FileSecretStore, load_or_create_host_identity};
use tornect_core::telemetry::{self, LogOptions};
use tornect_core::{Config, HostIdentity, Paths, TornectId};
use tornect_signal::ping::{NONCE_LEN, ping, serve};
use tornect_signal::tor::{Admission, RendezvousLimits};
use tornect_signal::{
    Isolation, MEDIA_PORT, OnionStream, SERVICES_PORT, SIGNALING_PORT, SignalError, TorNode,
    install_crypto_provider, shutdown_runtime,
};

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);
const PUBLISH_DEADLINE: Duration = Duration::from_secs(240);
const PINGS: u32 = 3;

/// One host and one client node under `target/tornect-test/live/`.
struct Nodes {
    identity: HostIdentity,
    host: TorNode,
    client: TorNode,
    t0: Instant,
}

impl Nodes {
    async fn start() -> anyhow::Result<Self> {
        install_crypto_provider();
        // Logs only on request, so the timeline stays readable by default.
        if std::env::var_os("TORNECT_LOG").is_some() {
            let _ = telemetry::init(LogOptions::default())?;
        }
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("tornect-test")
            .join("live");
        let host_paths = Paths::from_home(root.join("host"));
        let client_paths = Paths::from_home(root.join("client"));
        host_paths.ensure()?;
        client_paths.ensure()?;
        let store = FileSecretStore::open(host_paths.keys_dir())?;
        let (identity, _) = load_or_create_host_identity(&store)?;
        let cfg = Config::default();
        let t0 = Instant::now();
        // Host first: it publishes while its bootstrap is still running.
        let host = TorNode::start(&host_paths, &cfg).await?;
        let client = TorNode::start(&client_paths, &cfg).await?;
        Ok(Self {
            identity,
            host,
            client,
            t0,
        })
    }

    fn elapsed(&self) -> f64 {
        self.t0.elapsed().as_secs_f64()
    }
}

/// Connect to `id`, retrying while the descriptor is not on the HsDirs yet (or
/// the client's own vanguard layer is still settling after bootstrap).
async fn connect_when_published(
    client: &TorNode,
    id: &TornectId,
    deadline: Instant,
    t0: Instant,
) -> anyhow::Result<OnionStream> {
    loop {
        match client.connect(id).await {
            Ok(stream) => return Ok(stream),
            Err(
                e @ (SignalError::HostOffline
                | SignalError::HostNotRunning
                | SignalError::NotBootstrapped),
            ) if Instant::now() < deadline => {
                eprintln!(
                    "[{:5.1}s] not connectable yet ({e}); retrying",
                    t0.elapsed().as_secs_f64()
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// [`connect_when_published`] plus what a user does when Tor drops one
/// rendezvous on the floor (about one connect in ten on the dev VM, per the
/// evidence note): try again, up to `attempts` times.
async fn connect_with_retries(
    client: &TorNode,
    id: &TornectId,
    deadline: Instant,
    t0: Instant,
    attempts: u32,
    label: &str,
) -> anyhow::Result<(OnionStream, u32)> {
    for attempt in 1..=attempts {
        match connect_when_published(client, id, deadline, t0).await {
            Ok(stream) => return Ok((stream, attempt)),
            Err(e) if attempt < attempts => eprintln!(
                "[{:5.1}s] {label}: attempt {attempt} failed ({e}); retrying",
                t0.elapsed().as_secs_f64()
            ),
            Err(e) => return Err(e),
        }
    }
    unreachable!("attempts >= 1")
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?)
}

#[test]
#[ignore = "needs the live Tor network; run with --ignored"]
fn live_tor_roundtrip() -> anyhow::Result<()> {
    let rt = runtime()?;
    let result = rt.block_on(roundtrip());
    // Tear the runtime down the way the CLI does: Arti's final state flush and
    // its PoW-thread teardown noise are handled there.
    shutdown_runtime(rt);
    result
}

async fn roundtrip() -> anyhow::Result<()> {
    let nodes = Nodes::start().await?;
    let mut listener = nodes.host.publish(&nodes.identity).await?;
    assert_eq!(
        listener.onion_address(),
        nodes.identity.id(),
        "Arti must publish exactly the Tornect ID"
    );
    eprintln!(
        "[{:5.1}s] host launched {} ({:?}, {} handshakes / {} circuits)",
        nodes.elapsed(),
        listener.onion_address(),
        listener.admission(),
        listener.limits().max_handshakes,
        listener.limits().max_live_circuits,
    );
    let served = tokio::spawn(async move {
        let mut stream = listener.accept().await.expect("listener alive");
        serve(&mut stream, |_| {}).await
    });

    nodes.client.wait_ready(BOOTSTRAP_TIMEOUT).await?;
    eprintln!("[{:5.1}s] client bootstrapped", nodes.elapsed());

    let deadline = Instant::now() + PUBLISH_DEADLINE;
    let mut stream =
        connect_when_published(&nodes.client, &nodes.identity.id(), deadline, nodes.t0).await?;
    eprintln!("[{:5.1}s] client connected", nodes.elapsed());

    for i in 0..PINGS {
        let rtt = tokio::time::timeout(
            Duration::from_secs(30),
            ping(&mut stream, [i as u8; NONCE_LEN]),
        )
        .await??;
        eprintln!(
            "[{:5.1}s] ping {} rtt {:.0} ms",
            nodes.elapsed(),
            i + 1,
            rtt.as_secs_f64() * 1000.0
        );
    }
    // shutdown() closes our send side; Arti emits END(MISC), which the host's
    // OnionStream maps to a clean EOF. The host drops its side as soon as it
    // sees that EOF, which Arti can report to a close still in flight as
    // "Received an END cell with reason MISC"; that race is benign.
    if let Err(e) = stream.shutdown().await {
        eprintln!(
            "[{:5.1}s] close raced with the host dropping its side: {e}",
            nodes.elapsed()
        );
    }
    drop(stream);
    let answered = served.await??;
    assert_eq!(answered, PINGS);
    eprintln!(
        "[{:5.1}s] host answered {answered} ping(s)",
        nodes.elapsed()
    );

    let Nodes { host, client, .. } = nodes;
    client.shutdown().await;
    host.shutdown().await;
    Ok(())
}

/// The listener's port rule over the live network (design `services` step 6):
/// a session's three streams — signaling, media, services — open on one
/// rendezvous circuit (one isolation group) and are each accepted with their
/// port; a `BEGIN` on any other port then destroys that circuit, which ends
/// the streams already open on it.
#[test]
#[ignore = "needs the live Tor network; run with --ignored"]
fn live_session_ports() -> anyhow::Result<()> {
    let rt = runtime()?;
    let result = rt.block_on(session_ports());
    shutdown_runtime(rt);
    result
}

async fn session_ports() -> anyhow::Result<()> {
    let nodes = Nodes::start().await?;
    let mut listener = nodes.host.publish(&nodes.identity).await?;
    eprintln!(
        "[{:5.1}s] host launched {}",
        nodes.elapsed(),
        listener.onion_address()
    );
    // Host: take the three streams and keep them (and the listener) open.
    let accepted = tokio::spawn(async move {
        let mut streams = Vec::new();
        while streams.len() < 3 {
            streams.push(listener.accept().await.expect("listener alive"));
        }
        (listener, streams)
    });

    nodes.client.wait_ready(BOOTSTRAP_TIMEOUT).await?;
    eprintln!("[{:5.1}s] client bootstrapped", nodes.elapsed());
    let id = nodes.identity.id();
    let isolation = Isolation::new();
    let deadline = Instant::now() + PUBLISH_DEADLINE;
    // The signaling stream builds the circuit, once the descriptor is up.
    let mut signaling = loop {
        match nodes
            .client
            .connect_on(&id, SIGNALING_PORT, &isolation)
            .await
        {
            Ok(stream) => break stream,
            Err(
                e @ (SignalError::HostOffline
                | SignalError::HostNotRunning
                | SignalError::NotBootstrapped),
            ) if Instant::now() < deadline => {
                eprintln!(
                    "[{:5.1}s] not connectable yet ({e}); retrying",
                    nodes.elapsed()
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => return Err(e.into()),
        }
    };
    let media = nodes.client.connect_on(&id, MEDIA_PORT, &isolation).await?;
    let mut services = nodes
        .client
        .connect_on(&id, SERVICES_PORT, &isolation)
        .await?;
    eprintln!(
        "[{:5.1}s] signaling, media and services open on one circuit",
        nodes.elapsed()
    );
    let (listener, mut streams) = tokio::time::timeout(Duration::from_secs(60), accepted).await??;
    let ports: Vec<u16> = streams.iter().map(OnionStream::port).collect();
    assert_eq!(ports, [SIGNALING_PORT, MEDIA_PORT, SERVICES_PORT]);
    // The services stream carries bytes both ways.
    services.write_all(b"svc1").await?;
    services.flush().await?;
    let mut got = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(30), streams[2].read_exact(&mut got)).await??;
    assert_eq!(&got, b"svc1");
    streams[2].write_all(b"ack1").await?;
    streams[2].flush().await?;
    tokio::time::timeout(Duration::from_secs(30), services.read_exact(&mut got)).await??;
    assert_eq!(&got, b"ack1");
    eprintln!("[{:5.1}s] services stream carries data", nodes.elapsed());

    // A fourth stream on a port the host does not serve destroys the circuit.
    let refused = nodes
        .client
        .connect_on(&id, SERVICES_PORT + 1, &isolation)
        .await;
    assert!(refused.is_err(), "a BEGIN on an unserved port must fail");
    let mut buf = [0u8; 16];
    let ended = tokio::time::timeout(Duration::from_secs(60), signaling.read(&mut buf)).await?;
    assert!(
        matches!(ended, Ok(0) | Err(_)),
        "the signaling stream must end with its circuit: {ended:?}"
    );
    eprintln!(
        "[{:5.1}s] port {} destroyed the circuit and its streams",
        nodes.elapsed(),
        SERVICES_PORT + 1
    );

    drop((signaling, media, services, streams, listener));
    let Nodes { host, client, .. } = nodes;
    client.shutdown().await;
    host.shutdown().await;
    Ok(())
}

/// How long the host holds each accepted stream before closing it.
const HOLD: Duration = Duration::from_secs(5);
/// Parallel client connects against a one-slot host.
const PARALLEL: usize = 3;
/// Connect attempts per client (Tor transients, not the host, fail some).
const CONNECT_ATTEMPTS: u32 = 3;
/// Upper bound on the whole exchange.
const BACKPRESSURE_DEADLINE: Duration = Duration::from_secs(300);

/// Backpressure over the live network (decision M1-4, third review): a host
/// with a budget of one handshake and one live circuit, and three clients
/// connecting at once. The requests that find the slot taken must wait in
/// Arti's queue — not be dropped — and be served one after the other as the
/// slot frees up: consecutive accepts are at least a hold plus an idle
/// timeout apart, and every client gets through.
#[test]
#[ignore = "needs the live Tor network; run with --ignored"]
fn live_rendezvous_backpressure() -> anyhow::Result<()> {
    let rt = runtime()?;
    let result = rt.block_on(backpressure());
    shutdown_runtime(rt);
    result
}

async fn backpressure() -> anyhow::Result<()> {
    let nodes = Nodes::start().await?;
    let limits = RendezvousLimits {
        max_handshakes: 1,
        max_live_circuits: 1,
        circuit_idle_timeout: Duration::from_secs(2),
    };
    let mut listener = nodes
        .host
        .publish_with_limits(&nodes.identity, limits)
        .await?;
    anyhow::ensure!(
        listener.admission() == Admission::Backpressure,
        "this demonstration needs proof-of-work (the `tor-pow` feature and tor.pow_defense)"
    );
    eprintln!(
        "[{:5.1}s] host launched {} with a one-slot budget ({:?})",
        nodes.elapsed(),
        listener.onion_address(),
        listener.admission()
    );
    let t0 = nodes.t0;
    // Host: take one stream at a time, hold it, close it. Closing lets the
    // circuit idle out, which frees the slot for the next queued request.
    let served = tokio::spawn(async move {
        let mut accepted_at = Vec::new();
        let give_up = tokio::time::sleep(BACKPRESSURE_DEADLINE);
        tokio::pin!(give_up);
        while accepted_at.len() < PARALLEL {
            let stream = tokio::select! {
                stream = listener.accept() => stream.expect("listener alive"),
                () = &mut give_up => break,
            };
            accepted_at.push(Instant::now());
            eprintln!(
                "[{:5.1}s] host accepted stream {}/{PARALLEL}; holding it for {} s",
                t0.elapsed().as_secs_f64(),
                accepted_at.len(),
                HOLD.as_secs()
            );
            tokio::time::sleep(HOLD).await;
            drop(stream);
        }
        accepted_at
    });

    nodes.client.wait_ready(BOOTSTRAP_TIMEOUT).await?;
    eprintln!("[{:5.1}s] client bootstrapped", nodes.elapsed());

    let Nodes {
        identity,
        host,
        client,
        ..
    } = nodes;
    let client = Arc::new(client);
    let id = identity.id();
    let deadline = Instant::now() + PUBLISH_DEADLINE;
    let mut connects = Vec::new();
    for n in 1..=PARALLEL {
        let client = Arc::clone(&client);
        connects.push(tokio::spawn(async move {
            let label = format!("client {n}");
            let (mut stream, attempt) =
                connect_with_retries(&client, &id, deadline, t0, CONNECT_ATTEMPTS, &label).await?;
            let connected_at = Instant::now();
            eprintln!(
                "[{:5.1}s] {label} connected (attempt {attempt})",
                t0.elapsed().as_secs_f64()
            );
            // Hold the stream until the host closes it (EOF), then let go.
            let mut buf = [0u8; 16];
            while stream.read(&mut buf).await? != 0 {}
            eprintln!(
                "[{:5.1}s] {label} closed by the host",
                t0.elapsed().as_secs_f64()
            );
            Ok::<_, anyhow::Error>((connected_at, attempt))
        }));
    }
    let mut connected = Vec::new();
    for connect in connects {
        connected.push(connect.await??);
    }
    let accepted_at = served.await?;
    let retries: u32 = connected.iter().map(|(_, attempt)| attempt - 1).sum();
    eprintln!(
        "[{:5.1}s] every client was served ({retries} Tor-side connect failure(s) retried)",
        t0.elapsed().as_secs_f64(),
    );

    assert_eq!(accepted_at.len(), PARALLEL);
    assert_eq!(connected.len(), PARALLEL);
    // One at a time: each later stream could only be accepted after the previous
    // one had been held and its circuit had idled out.
    for (n, pair) in accepted_at.windows(2).enumerate() {
        let gap = pair[1].duration_since(pair[0]);
        eprintln!(
            "[{:5.1}s] gap between accepts {} and {}: {:.1} s",
            t0.elapsed().as_secs_f64(),
            n + 1,
            n + 2,
            gap.as_secs_f64()
        );
        assert!(
            gap >= HOLD + limits.circuit_idle_timeout,
            "streams {} and {} were served {:.1} s apart with a one-slot budget",
            n + 1,
            n + 2,
            gap.as_secs_f64()
        );
    }

    if let Ok(client) = Arc::try_unwrap(client) {
        client.shutdown().await;
    }
    host.shutdown().await;
    Ok(())
}
