//! The embedded Tor client, [`TorNode`]: one per role, wrapping
//! `Arc<TorClient<TokioRustlsRuntime>>` (docs/research/arti.md §5, §7, §9).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arti_client::config::BoolOrAuto;
use arti_client::status::{BlockageKind, BootstrapStatus};
use arti_client::{
    BootstrapBehavior, ErrorKind, HasKind as _, StreamPrefs, TorClient, TorClientConfig,
};
use futures::StreamExt as _;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tor_rtcompat::tokio::TokioRustlsRuntime;
use tornect_core::config::Tor;
use tornect_core::{Config, HostIdentity, Paths, TornectId};

use super::bridges::{self, Ladder, Rung, RungPolicy, Transport};
use super::config::{CONNECT_TIMEOUT, onion_service_config, tor_client_config};
use super::listener::{Admission, OnionListener, OnionStream, RendezvousLimits};
use super::{SIGNALING_PORT, identity, map_arti_error};
use crate::error::{Result, SignalError, error_chain};

/// How long [`TorNode::publish`] waits for the background bootstrap to *start*
/// (Arti needs its internals constructed before a service can be launched; the
/// directory itself need not be complete).
const LAUNCH_RETRY: Duration = Duration::from_millis(100);
const LAUNCH_RETRIES: u32 = 100;

/// Arti reports `ready_for_traffic` a moment before its vanguard manager —
/// which every onion-service circuit goes through — has consumed the
/// directory; a `connect` in that window fails with `BootstrapRequired`
/// ("Cannot select vanguard with unbootstrapped vanguard manager", seen ~50 ms
/// after a warm bootstrap in `tests/live.rs`). Such failures are retried every
/// [`VANGUARD_RETRY`] for this long after the first one.
const VANGUARD_GRACE: Duration = Duration::from_secs(10);
const VANGUARD_RETRY: Duration = Duration::from_millis(500);

/// Upper bound on waiting for the last `TorClient` handle to be released.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
/// Time given to Arti's onion-service reactors to observe the drop and exit.
const SHUTDOWN_SETTLE: Duration = Duration::from_millis(250);

/// Bootstrap progress snapshot, for progress bars and "why is it stuck" copy.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BootstrapProgress {
    /// Rough completion from 0.0 (just started) to 1.0 (ready for traffic).
    pub fraction: f32,
    /// Whether the client can carry traffic right now.
    pub ready: bool,
    /// Arti's best-effort diagnosis when no progress is being made, e.g.
    /// "We seem to be offline (...)". Present it modestly (arti.md §7).
    pub blocked: Option<String>,
}

impl BootstrapProgress {
    fn from_status(status: &BootstrapStatus) -> Self {
        let blocked = status
            .blocked()
            // "Disabled" only means bootstrap has not been requested yet.
            .filter(|b| !matches!(b.kind(), BlockageKind::Disabled))
            .map(|b| b.to_string());
        Self {
            fraction: status.as_frac().clamp(0.0, 1.0),
            ready: status.ready_for_traffic(),
            blocked,
        }
    }
}

/// Terminal result of the background `bootstrap()` call.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BootstrapOutcome {
    Pending,
    Ready,
    Failed(String),
}

/// An embedded Tor client.
///
/// Created unbootstrapped with `BootstrapBehavior::Manual`; bootstrap runs in a
/// background task from the moment [`TorNode::start`] returns. Hosts call
/// [`TorNode::publish`] (which works while bootstrap is still in progress),
/// clients [`TorNode::wait_ready`] then [`TorNode::connect`].
///
/// Dropping the node (or calling [`TorNode::shutdown`]) stops its background
/// tasks; Arti flushes its persistent state when the last reference goes away.
pub struct TorNode {
    client: Arc<TorClient<TokioRustlsRuntime>>,
    tor_config: TorClientConfig,
    state_dir: PathBuf,
    tor: Tor,
    rung: Rung,
    progress: watch::Receiver<BootstrapProgress>,
    outcome: watch::Receiver<BootstrapOutcome>,
    tasks: Vec<JoinHandle<()>>,
    /// The runtime Arti runs on when the node owns one ([`TorNode::start_auto`]);
    /// shutting it down is what releases Arti's state lock (bridges.md §1.11).
    runtime: Option<tokio::runtime::Runtime>,
}

impl std::fmt::Debug for TorNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorNode")
            .field("state_dir", &self.state_dir)
            .field("rung", &self.rung)
            .field("progress", &*self.progress.borrow())
            .finish_non_exhaustive()
    }
}

/// A circuit-isolation group for [`TorNode::connect_on`]: every stream opened
/// with the same value may share circuits; a fresh value gets its own.
#[derive(Debug, Clone, Copy)]
pub struct Isolation(arti_client::IsolationToken);

impl Isolation {
    /// A new, unshared group.
    #[must_use]
    pub fn new() -> Self {
        Self(arti_client::IsolationToken::new())
    }
}

impl Default for Isolation {
    fn default() -> Self {
        Self::new()
    }
}

/// Progress of [`TorNode::start_auto`], for status lines and the UI.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum LadderEvent {
    /// A rung was left out before starting (no `lyrebird`, …).
    Skipped {
        /// The rung.
        rung: Rung,
        /// Why.
        reason: String,
    },
    /// Trying `rung`, attempt `attempt` of `of`.
    Trying {
        /// The rung.
        rung: Rung,
        /// 1-based.
        attempt: usize,
        /// Rungs in the ladder.
        of: usize,
    },
    /// `rung` did not reach the network; the next one is tried.
    Failed {
        /// The rung.
        rung: Rung,
        /// Why, e.g. "no bootstrap progress for 40 s (We seem to be offline)".
        reason: String,
    },
    /// Bootstrap progress on the current rung (sent when it moves by ≥ 5 %
    /// or the blockage diagnosis changes).
    Progress {
        /// The rung.
        rung: Rung,
        /// 0.0 ..= 1.0.
        fraction: f32,
        /// Arti's diagnosis when stuck, e.g. "We seem to be offline".
        blocked: Option<String>,
    },
    /// Connected to the Tor network through `rung`.
    Ready {
        /// The rung.
        rung: Rung,
    },
}

impl TorNode {
    /// Create a direct (no bridges) client under `paths` and start
    /// bootstrapping in the background.
    ///
    /// Must be called from inside a tokio runtime (Arti wraps the current one).
    /// Bootstrap takes ~30 s cold and a few seconds with a warm cache
    /// (docs/research/arti.md §17); watch [`TorNode::bootstrap_progress`].
    /// [`TorNode::start_auto`] is the censorship-resistant entry point.
    pub async fn start(paths: &Paths, config: &Config) -> Result<Self> {
        Self::start_with_transport(paths, config, &Transport::direct()).await
    }

    /// Reach the Tor network through the first rung of `ladder` that works
    /// (decision M1-38): each rung is a fresh client on its own runtime, given
    /// [`Ladder::policy`] to reach `ready_for_traffic`, and torn down
    /// completely before the next is tried. The rung that works is remembered
    /// and goes first next time ([`bridges::last_good`]).
    ///
    /// `bootstrap()` returning `Ok` is not success: from a warm cache it does so
    /// while the network is blocked (bridges.md §3.2), so only
    /// `ready_for_traffic` counts. Fails with [`SignalError::Bootstrap`] naming
    /// every rung's reason when none works.
    pub async fn start_auto(
        paths: &Paths,
        config: &Config,
        ladder: &Ladder,
        mut on_event: impl FnMut(&LadderEvent) + Send,
    ) -> Result<Self> {
        for (rung, reason) in &ladder.skipped {
            on_event(&LadderEvent::Skipped {
                rung: *rung,
                reason: reason.clone(),
            });
        }
        if ladder.rungs.is_empty() {
            return Err(SignalError::Bootstrap(
                "no way to reach the Tor network is available (see the skipped transports)"
                    .to_owned(),
            ));
        }
        let mut failures = Vec::new();
        for (i, transport) in ladder.rungs.iter().enumerate() {
            let rung = transport.rung;
            on_event(&LadderEvent::Trying {
                rung,
                attempt: i + 1,
                of: ladder.rungs.len(),
            });
            match Self::try_rung(paths, config, transport, ladder.policy(rung), &mut on_event).await
            {
                Ok(node) => {
                    bridges::remember(paths, rung);
                    on_event(&LadderEvent::Ready { rung });
                    tracing::info!(%rung, "connected to the Tor network");
                    return Ok(node);
                }
                Err(reason) => {
                    tracing::warn!(%rung, %reason, "Tor transport failed");
                    on_event(&LadderEvent::Failed {
                        rung,
                        reason: reason.clone(),
                    });
                    failures.push(format!("{}: {reason}", rung.describe()));
                }
            }
        }
        Err(SignalError::Bootstrap(format!(
            "could not reach the Tor network ({})",
            failures.join("; ")
        )))
    }

    /// One rung: a dedicated runtime, a client on it, and a bounded wait for
    /// `ready_for_traffic`. Everything is torn down before an error returns.
    async fn try_rung(
        paths: &Paths,
        config: &Config,
        transport: &Transport,
        policy: RungPolicy,
        on_event: &mut (impl FnMut(&LadderEvent) + Send),
    ) -> std::result::Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("tornect-tor")
            .enable_all()
            .build()
            .map_err(|e| format!("creating the Tor runtime: {e}"))?;
        let (p, c, t) = (paths.clone(), config.clone(), transport.clone());
        let started = runtime
            .spawn(async move { Self::start_with_transport(&p, &c, &t).await })
            .await;
        let mut node = match started {
            Ok(Ok(node)) => node,
            Ok(Err(e)) => {
                teardown(runtime).await;
                return Err(e.to_string());
            }
            Err(e) => {
                teardown(runtime).await;
                return Err(format!("the Tor client task failed: {e}"));
            }
        };
        node.runtime = Some(runtime);
        match node.wait_for_traffic(policy, on_event).await {
            Ok(()) => Ok(node),
            Err(reason) => {
                node.shutdown().await;
                Err(reason)
            }
        }
    }

    /// Wait for `ready_for_traffic` under `policy`: the cap, and — when set —
    /// the stall timer, which fires when the bootstrap fraction has not grown
    /// for that long.
    async fn wait_for_traffic(
        &self,
        policy: RungPolicy,
        on_event: &mut (impl FnMut(&LadderEvent) + Send),
    ) -> std::result::Result<(), String> {
        let mut progress = self.progress.clone();
        let started = tokio::time::Instant::now();
        let mut best = progress.borrow().fraction;
        let mut last_gain = started;
        let mut reported: Option<(f32, Option<String>)> = None;
        loop {
            let snapshot = progress.borrow_and_update().clone();
            if snapshot.ready {
                return Ok(());
            }
            let moved = reported
                .as_ref()
                .is_none_or(|(f, b)| snapshot.fraction >= f + 0.05 || *b != snapshot.blocked);
            if moved {
                on_event(&LadderEvent::Progress {
                    rung: self.rung,
                    fraction: snapshot.fraction,
                    blocked: snapshot.blocked.clone(),
                });
                reported = Some((snapshot.fraction, snapshot.blocked.clone()));
            }
            if let BootstrapOutcome::Failed(message) = &*self.outcome.borrow() {
                return Err(message.clone());
            }
            let now = tokio::time::Instant::now();
            if snapshot.fraction > best + 0.005 {
                best = snapshot.fraction;
                last_gain = now;
            }
            let why = snapshot
                .blocked
                .as_deref()
                .map(|b| format!(" ({b})"))
                .unwrap_or_default();
            if now.duration_since(started) >= policy.cap {
                return Err(format!(
                    "not connected after {} s{why}",
                    policy.cap.as_secs()
                ));
            }
            if let Some(stall) = policy.stall
                && now.duration_since(last_gain) >= stall
            {
                return Err(format!(
                    "no bootstrap progress for {} s{why}",
                    stall.as_secs()
                ));
            }
            // Wake on progress, and at least once a second for the timers.
            let _ = tokio::time::timeout(Duration::from_secs(1), progress.changed()).await;
        }
    }

    /// Create a client for `transport` and start bootstrapping in the background.
    ///
    /// Must be called from inside a tokio runtime (Arti wraps the current one).
    pub async fn start_with_transport(
        paths: &Paths,
        config: &Config,
        transport: &Transport,
    ) -> Result<Self> {
        super::install_crypto_provider();
        let tor_config = tor_client_config(paths, transport)?;
        let runtime = TokioRustlsRuntime::current()?;
        let client = TorClient::with_runtime(runtime)
            .config(tor_config.clone())
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped_async()
            .await
            .map_err(|e| map_arti_error(&e))?;
        tracing::info!(state_dir = %paths.arti_state_dir().display(), "Tor client created");

        let (progress_tx, progress) =
            watch::channel(BootstrapProgress::from_status(&client.bootstrap_status()));
        let mut events = Box::pin(client.bootstrap_events());
        let progress_task = tokio::spawn(async move {
            while let Some(status) = events.next().await {
                let progress = BootstrapProgress::from_status(&status);
                tracing::debug!(
                    fraction = progress.fraction,
                    ready = progress.ready,
                    blocked = progress.blocked.as_deref().unwrap_or("-"),
                    "Tor bootstrap progress"
                );
                progress_tx.send_replace(progress);
            }
        });

        let (outcome_tx, outcome) = watch::channel(BootstrapOutcome::Pending);
        let bootstrap_client = Arc::clone(&client);
        let bootstrap_task = tokio::spawn(async move {
            let outcome = match bootstrap_client.bootstrap().await {
                Ok(()) => {
                    tracing::info!("Tor bootstrap complete");
                    BootstrapOutcome::Ready
                }
                Err(e) => {
                    let message = error_chain(&e);
                    tracing::warn!(error = %message, "Tor bootstrap failed");
                    BootstrapOutcome::Failed(message)
                }
            };
            outcome_tx.send_replace(outcome);
        });

        Ok(Self {
            client,
            tor_config,
            state_dir: paths.arti_state_dir(),
            tor: config.tor.clone(),
            rung: transport.rung,
            progress,
            outcome,
            tasks: vec![progress_task, bootstrap_task],
            runtime: None,
        })
    }

    /// Live view of the bootstrap progress (a `watch` receiver: always holds the
    /// latest snapshot; `changed().await` wakes on updates).
    #[must_use]
    pub fn bootstrap_progress(&self) -> watch::Receiver<BootstrapProgress> {
        self.progress.clone()
    }

    /// How this node reaches the Tor network.
    #[must_use]
    pub fn rung(&self) -> Rung {
        self.rung
    }

    /// Whether the client can carry traffic right now.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.progress.borrow().ready || *self.outcome.borrow() == BootstrapOutcome::Ready
    }

    /// Wait until the client is ready for traffic.
    ///
    /// Fails with [`SignalError::Bootstrap`] if bootstrapping failed and with
    /// [`SignalError::Timeout`] after `timeout`.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let mut progress = self.progress.clone();
        let mut outcome = self.outcome.clone();
        let mut progress_alive = true;
        let mut outcome_alive = true;
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            if progress.borrow().ready {
                return Ok(());
            }
            match outcome.borrow().clone() {
                BootstrapOutcome::Ready => return Ok(()),
                BootstrapOutcome::Failed(message) => return Err(SignalError::Bootstrap(message)),
                BootstrapOutcome::Pending => {}
            }
            if !progress_alive && !outcome_alive {
                return Err(SignalError::Bootstrap(
                    "bootstrap task ended without a result".to_owned(),
                ));
            }
            tokio::select! {
                () = &mut deadline => return Err(SignalError::Timeout("bootstrapping Tor")),
                changed = progress.changed(), if progress_alive => {
                    progress_alive = changed.is_ok();
                }
                changed = outcome.changed(), if outcome_alive => {
                    outcome_alive = changed.is_ok();
                }
            }
        }
    }

    /// Publish this machine's onion service for `identity` and start accepting
    /// signaling streams, with the default [`RendezvousLimits`].
    ///
    /// The identity key is installed into Arti's keystore first, so the address
    /// Arti publishes is exactly `identity.id()` — verified before returning.
    /// Returns as soon as the service is launched; reachability (descriptor
    /// uploaded, intro points up) follows via [`OnionListener::status`], typically
    /// within ~10 s of bootstrap completing and up to ~2 min on a cold start.
    pub async fn publish(&self, identity: &HostIdentity) -> Result<OnionListener> {
        self.publish_with_limits(identity, RendezvousLimits::default())
            .await
    }

    /// [`TorNode::publish`] with explicit host-side rendezvous bounds (tests use
    /// small ones). The [`Admission`] policy is derived from the service's
    /// proof-of-work setting, not chosen here. A zero budget would admit nothing
    /// and is refused with [`SignalError::Config`].
    pub async fn publish_with_limits(
        &self,
        identity: &HostIdentity,
        limits: RendezvousLimits,
    ) -> Result<OnionListener> {
        if limits.max_handshakes == 0 || limits.max_live_circuits == 0 {
            return Err(SignalError::Config(
                "rendezvous limits must allow at least one handshake and one live circuit"
                    .to_owned(),
            ));
        }
        let expected = identity.id();
        let nickname = identity::install_identity_key(&self.tor_config, &self.state_dir, identity)?;
        let svc_config = onion_service_config(nickname.clone(), &self.tor)?;
        // The built config, not `self.tor.pow_defense`: it is what Arti enforces.
        let admission = Admission::for_pow(*svc_config.enable_pow());

        let mut attempts = 0;
        let (service, rend_requests) = loop {
            match self.client.launch_onion_service(svc_config.clone()) {
                Ok(Some(launched)) => break launched,
                Ok(None) => {
                    return Err(SignalError::Launch(
                        "onion service is disabled in its configuration".to_owned(),
                    ));
                }
                Err(e) if e.kind() == ErrorKind::BootstrapRequired && attempts < LAUNCH_RETRIES => {
                    // The background bootstrap has not constructed the client yet.
                    attempts += 1;
                    tokio::time::sleep(LAUNCH_RETRY).await;
                }
                Err(e) => return Err(map_arti_error(&e)),
            }
        };

        let hsid = service.onion_address().ok_or_else(|| {
            SignalError::Launch("identity key missing from Arti's keystore after launch".to_owned())
        })?;
        let published = identity::hsid_to_tornect_id(&hsid)?;
        if published != expected {
            return Err(SignalError::IdentityMismatch {
                tor: published.onion_address(),
                expected: expected.onion_address(),
            });
        }
        tracing::info!(
            address = %published,
            %nickname,
            ?admission,
            max_handshakes = limits.max_handshakes,
            max_live_circuits = limits.max_live_circuits,
            "onion service launched"
        );
        Ok(OnionListener::new(
            service,
            rend_requests,
            published,
            admission,
            limits,
        ))
    }

    /// Open a signaling stream to the host with Tornect ID `id`.
    ///
    /// Each call uses a fresh isolation group (its own circuits) and is bounded by
    /// [`CONNECT_TIMEOUT`]. Errors distinguish [`SignalError::HostOffline`] (no
    /// descriptor), [`SignalError::HostNotRunning`] (descriptor but no intro
    /// points) and [`SignalError::Timeout`].
    pub async fn connect(&self, id: &TornectId) -> Result<OnionStream> {
        self.connect_on(id, SIGNALING_PORT, &Isolation::new()).await
    }

    /// Open a stream to `port` on the host `id`, in the isolation group
    /// `isolation`: streams that share one reuse the same rendezvous circuit,
    /// which is how a session's media stream ([`super::MEDIA_PORT`]) follows its
    /// signaling stream in one round trip instead of a second rendezvous.
    pub async fn connect_on(
        &self,
        id: &TornectId,
        port: u16,
        isolation: &Isolation,
    ) -> Result<OnionStream> {
        if !self.is_ready() {
            return Err(SignalError::NotBootstrapped);
        }
        let mut prefs = StreamPrefs::new();
        prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
        prefs.set_isolation(isolation.0);
        let address = id.onion_address();
        tracing::info!(host = %id, port, "connecting to host over Tor");
        let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
        let mut vanguard_grace: Option<tokio::time::Instant> = None;
        let stream = loop {
            let attempt = self
                .client
                .connect_with_prefs((address.as_str(), port), &prefs);
            match tokio::time::timeout_at(deadline, attempt).await {
                Ok(Ok(stream)) => break stream,
                Ok(Err(e)) if e.kind() == ErrorKind::BootstrapRequired => {
                    let now = tokio::time::Instant::now();
                    let until = *vanguard_grace.get_or_insert(now + VANGUARD_GRACE);
                    if now >= until {
                        return Err(map_arti_error(&e));
                    }
                    tracing::debug!(
                        error = %error_chain(&e),
                        "Tor client not ready for onion circuits yet; retrying"
                    );
                    tokio::time::sleep(VANGUARD_RETRY).await;
                }
                Ok(Err(e)) => return Err(map_arti_error(&e)),
                Err(_) => return Err(SignalError::Timeout("connecting to the host over Tor")),
            }
        };
        tracing::info!(host = %id, port, "onion stream open");
        Ok(OnionStream::new(stream, port))
    }

    /// Stop the background tasks, release the client and give Arti's
    /// onion-service reactors a moment to exit.
    ///
    /// Any [`OnionListener`] must be dropped first (it owns the running service).
    /// Arti's directory manager keeps its circuit manager alive from a background
    /// task, so the final guard/circuit-state flush ("Flushed persistent state at
    /// exit") happens only when the caller shuts the tokio runtime down after
    /// this returns; state is also flushed every 60 s while running. A node
    /// from [`TorNode::start_auto`] owns its runtime and shuts it down here.
    pub async fn shutdown(mut self) {
        tracing::info!("Tor node shutting down");
        let runtime = self.runtime.take();
        let client = Arc::downgrade(&self.client);
        let started = Instant::now();
        drop(self);
        // First wait for our own handles to let go of the client (task aborts are
        // processed asynchronously), then give Arti's reactors — IPT manager,
        // publisher, circuit/guard managers with their persistent-state flush —
        // time to observe the drop and exit.
        while client.upgrade().is_some() && started.elapsed() < SHUTDOWN_GRACE {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let released_after = started.elapsed();
        tokio::time::sleep(SHUTDOWN_SETTLE).await;
        tracing::debug!(
            released = client.upgrade().is_none(),
            released_after_ms = released_after.as_millis(),
            "Tor client released"
        );
        if let Some(runtime) = runtime {
            teardown(runtime).await;
        }
    }
}

impl Drop for TorNode {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        // Dropped without `shutdown`: a blocking teardown is not allowed here
        // (this may run on an async thread), so let the runtime go in the background.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Shut a node-owned runtime down completely, off the async thread: this is
/// what makes Arti drop its managers and release the state lock, so the next
/// rung can take it (bridges.md §1.11).
async fn teardown(runtime: tokio::runtime::Runtime) {
    if tokio::task::spawn_blocking(move || shutdown_runtime(runtime))
        .await
        .is_err()
    {
        tracing::warn!("the Tor runtime teardown task panicked");
    }
}

/// Upper bound on waiting for Arti's remaining tasks when the runtime is torn down.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// tokio's message when a timer is polled after the runtime's time driver shut
/// down (`tokio/src/util/error.rs`, `RUNTIME_SHUTTING_DOWN_ERROR`).
const TOKIO_SHUTDOWN_PANIC: &str = "A Tokio 1.x context was found, but it is being shutdown";

/// Serializes [`shutdown_runtime`] calls: the panic-hook swap is process-global,
/// so two runtimes shutting down at once (host and client nodes in the app)
/// would otherwise cross-restore each other's hooks.
static SHUTDOWN_HOOK_LOCK: Mutex<()> = Mutex::new(());

/// Tear down a tokio runtime that hosted a [`TorNode`].
///
/// Shutting the runtime down is what makes Arti drop its directory and circuit
/// managers and write guard state one last time ("Flushed persistent state at
/// exit"); [`TorNode::shutdown`] alone cannot, because Arti's directory task
/// holds them. Call this after every node has been shut down.
///
/// With the `tor-pow` feature, Arti's proof-of-work manager
/// (`tor-hsservice/src/pow/v1.rs`, started for every onion service whether or
/// not `enable_pow` is set) keeps `spawn_blocking` threads that re-enter
/// `block_on(sleep(..))` and cannot observe the shutdown, so tokio makes each of
/// them panic once its time driver is gone. Those panics are harmless (the
/// threads are being discarded and tokio catches the unwind) but noisy, so
/// exactly that message is muted while the runtime shuts down — logged at
/// `warn` so it stays visible in bug reports, since a genuine bug tripping the
/// same tokio assertion during teardown would be muted too. Every other panic
/// still reaches the previously installed hook, which is restored afterwards.
/// Calls are serialized process-wide. Worth reporting upstream to Arti.
pub fn shutdown_runtime(runtime: tokio::runtime::Runtime) {
    let _serialized = SHUTDOWN_HOOK_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let previous: Arc<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync> =
        Arc::from(std::panic::take_hook());
    let forward = Arc::clone(&previous);
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let text = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        if text.contains(TOKIO_SHUTDOWN_PANIC) {
            tracing::warn!(
                "muted a tokio teardown panic (Arti PoW-manager blocking thread; \
                 tor-hsservice pow/v1.rs) during runtime shutdown"
            );
        } else {
            forward(info);
        }
    }));
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    std::panic::set_hook(Box::new(move |info| previous(info)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_default_is_not_ready() {
        let p = BootstrapProgress::default();
        assert!(!p.ready);
        assert_eq!(p.fraction, 0.0);
        assert!(p.blocked.is_none());
    }

    #[test]
    fn progress_from_a_fresh_status_hides_the_disabled_blockage() {
        // A default BootstrapStatus is what an unbootstrapped Manual client reports.
        let p = BootstrapProgress::from_status(&BootstrapStatus::default());
        assert!(!p.ready);
        assert!(p.fraction >= 0.0 && p.fraction <= 1.0);
        assert!(p.blocked.is_none(), "{:?}", p.blocked);
    }
}
