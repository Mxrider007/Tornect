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
    progress: watch::Receiver<BootstrapProgress>,
    outcome: watch::Receiver<BootstrapOutcome>,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for TorNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorNode")
            .field("state_dir", &self.state_dir)
            .field("progress", &*self.progress.borrow())
            .finish_non_exhaustive()
    }
}

impl TorNode {
    /// Create the client under `paths` and start bootstrapping in the background.
    ///
    /// Must be called from inside a tokio runtime (Arti wraps the current one).
    /// Bootstrap takes ~30 s cold and a few seconds with a warm cache
    /// (docs/research/arti.md §17); watch [`TorNode::bootstrap_progress`].
    pub async fn start(paths: &Paths, config: &Config) -> Result<Self> {
        super::install_crypto_provider();
        let tor_config = tor_client_config(paths)?;
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
            progress,
            outcome,
            tasks: vec![progress_task, bootstrap_task],
        })
    }

    /// Live view of the bootstrap progress (a `watch` receiver: always holds the
    /// latest snapshot; `changed().await` wakes on updates).
    #[must_use]
    pub fn bootstrap_progress(&self) -> watch::Receiver<BootstrapProgress> {
        self.progress.clone()
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
        if !self.is_ready() {
            return Err(SignalError::NotBootstrapped);
        }
        let mut prefs = StreamPrefs::new();
        prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
        prefs.new_isolation_group();
        let address = id.onion_address();
        tracing::info!(host = %id, "connecting to host over Tor");
        let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
        let mut vanguard_grace: Option<tokio::time::Instant> = None;
        let stream = loop {
            let attempt = self
                .client
                .connect_with_prefs((address.as_str(), SIGNALING_PORT), &prefs);
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
        tracing::info!(host = %id, "onion stream open");
        Ok(OnionStream::new(stream))
    }

    /// Stop the background tasks, release the client and give Arti's
    /// onion-service reactors a moment to exit.
    ///
    /// Any [`OnionListener`] must be dropped first (it owns the running service).
    /// Arti's directory manager keeps its circuit manager alive from a background
    /// task, so the final guard/circuit-state flush ("Flushed persistent state at
    /// exit") happens only when the caller shuts the tokio runtime down after
    /// this returns; state is also flushed every 60 s while running.
    pub async fn shutdown(self) {
        tracing::info!("Tor node shutting down");
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
    }
}

impl Drop for TorNode {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
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
