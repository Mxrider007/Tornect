//! The host role of `tornect host`: the handshake FSM wired to its real seams
//! (`docs/PLAN.md` §B.2, §B.8.14 M1), and the first-frame dispatch that keeps
//! the pairing-free `tornect ping` answering on the same port (decision M1-42).
//!
//! [`wire`] builds everything a stream is served with. The kill switch and the
//! live-session tracker are shared with the IPC context, so a `tornect panic`
//! (or `unattended off`) reaches every handshake and session this host serves,
//! and the guard refuses access-increasing changes while one is live. Each
//! session's screen goes out on the media port through `tornect-session`'s
//! [`MediaHost`], which the same sink feeds.
//!
//! A running host holds [`HostLock`] and, wherever the platform has one, serves
//! a control channel ([`start_control_channel`]) even when its unattended store
//! did not open. The terminal names `tornect panic` as the way to end a session
//! only while that channel is up ([`ControlChannel`]; SLICE-B2 B2-2).

use std::fmt;
use std::io::{IsTerminal as _, Write as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tornect_core::session_log::{SessionLog, SessionMode, TransportKind};
use tornect_core::unattended::limiter::{AttemptLimiter, HostTransport};
use tornect_core::unattended::schedule::FixedOffset;
use tornect_core::{Config, HostIdentity, Paths};
use tornect_platform::ipc::{Endpoint, IpcError};
use tornect_session::{
    CaptureChanged, CaptureStarted, DirectHost, MediaEnd, MediaHost, MediaObserver, MediaOutcome,
    MediaReport,
};
use tornect_signal::dispatch::{FIRST_FRAME_DEADLINE, FirstFrame, first_frame};
use tornect_signal::envelope::codes;
use tornect_signal::fsm::HostAudit;
use tornect_signal::fsm::host::{
    HostConfig, HostDeps, HostOutcome, KillSwitch, LiveSession, LiveSessions, NotGranted,
    SessionEnd, SessionSink, serve_host,
};
use tornect_signal::messages::{self, bye, pair_reject, reject};
#[cfg(test)]
use tornect_signal::pairing::TrustedDeviceStore;
use tornect_signal::pairing::{AutoDeny, Consent};
use tornect_signal::ping::{self, ServeLimits};
use tornect_signal::unattended::{EmergencyStop, GuardAdmin, UnattendedAuth};

use crate::direct::DirectWiring;
use crate::prompt::{CliConsent, Prompter};
use crate::unattended::HostContext;

/// How long `tornect host` waits for [`HostLock`] before deciding that another
/// host holds it. A command probing [`HostLock::holder`] holds the lock for an
/// instant when no host runs, and that must not stop a host from starting.
const HOST_LOCK_WAIT: Duration = Duration::from_secs(1);

/// The lock a running `tornect host` holds on [`Paths::host_lock`] for its whole
/// life, so every other command can tell that a host is alive here — including
/// one with no control channel to answer it (SLICE-B2 B2-2). The operating
/// system drops the lock when the process ends, however it ends, so it cannot
/// go stale. It also keeps a second host off the same state directory.
#[derive(Debug)]
pub struct HostLock {
    _file: std::fs::File,
}

impl HostLock {
    /// Take the lock for this process, or fail if another host holds it.
    pub fn acquire(paths: &Paths) -> anyhow::Result<Self> {
        let path = paths.host_lock();
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let deadline = std::time::Instant::now() + HOST_LOCK_WAIT;
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
                    "another `tornect host` is already running for {} ({})",
                    paths.state_dir.display(),
                    read_holder(&mut file)
                ),
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(e).with_context(|| format!("locking {}", path.display()));
                }
            }
        }
        // Best effort: the pid is only ever shown to people.
        let _ = file.set_len(0);
        let _ = file.write_all(std::process::id().to_string().as_bytes());
        let _ = file.sync_all();
        Ok(Self { _file: file })
    }

    /// Who holds the lock: `Some` while a host runs for `paths` (naming its pid
    /// where the platform lets another process read it), `None` otherwise.
    #[must_use]
    pub fn holder(paths: &Paths) -> Option<String> {
        let mut file = std::fs::File::open(paths.host_lock()).ok()?;
        match file.try_lock() {
            // Nobody holds it, and dropping the file lets go again.
            Ok(()) => None,
            Err(std::fs::TryLockError::WouldBlock) => Some(read_holder(&mut file)),
            Err(std::fs::TryLockError::Error(e)) => {
                tracing::debug!(error = %e, "could not probe the host lock");
                None
            }
        }
    }
}

/// The pid a lock holder wrote, for messages. Windows' locks keep other
/// processes from reading a locked file, hence the fallback.
fn read_holder(file: &mut std::fs::File) -> String {
    let mut pid = String::new();
    let _ = std::io::Read::read_to_string(file, &mut pid);
    match pid.trim() {
        "" => "pid unknown".to_owned(),
        pid => format!("pid {pid}"),
    }
}

/// Whether this host's control channel is serving right now. The terminal
/// names `tornect panic` as the way to end a session only while it is
/// (SLICE-B2 B2-2), and Ctrl-C otherwise.
#[derive(Debug, Clone, Default)]
pub struct ControlChannel(Arc<AtomicBool>);

impl ControlChannel {
    /// `true` while `tornect panic` can reach this host.
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    fn set(&self, up: bool) {
        self.0.store(up, Ordering::SeqCst);
    }

    /// How someone at this machine ends a session right now.
    #[must_use]
    pub fn kill_path(&self) -> &'static str {
        if self.is_up() {
            "`tornect panic`"
        } else {
            "Ctrl-C in this terminal"
        }
    }
}

/// Bring up the host's control channel (§B.8.7.4) and serve it until the
/// returned task is aborted.
///
/// With a store it serves the whole unattended CLI. Without one (`wire` could
/// not open it) it still ends every session on `tornect panic`, from `kill`,
/// and refuses the rest with the reason: before, such a host had no control
/// channel at all, and `tornect panic` said no host was running while a session
/// went on (SLICE-B2 B2-2). It binds before returning, so `control` is up
/// before anything names `tornect panic`, and goes down if serving stops.
///
/// A failed bind is not fatal, nor on Windows a pipe another process made
/// first, which is never used (§B.8.7.4): the host says that Ctrl-C ends its
/// sessions. Another host serving this state directory is.
pub async fn start_control_channel(
    paths: &Paths,
    ctx: Result<HostContext, String>,
    kill: KillSwitch,
    control: ControlChannel,
) -> anyhow::Result<Option<JoinHandle<()>>> {
    // The panic key, the other kill path that never runs on the UI thread
    // (D10), and the readiness probes every 10 min; never in this crate's
    // tests, which must not reach the desktop.
    if !cfg!(test) {
        start_panic_key(
            paths,
            kill.clone(),
            ctx.as_ref().ok().map(|c| Arc::clone(&c.guard)),
        );
        if let Ok(c) = &ctx {
            reprobe_readiness(
                paths,
                Arc::clone(&c.guard),
                c.readiness.clone(),
                c.indicator.clone(),
            );
        }
    }
    let endpoint = match Endpoint::bind(&paths.state_dir).await {
        Ok(endpoint) => endpoint,
        Err(e @ IpcError::AlreadyRunning(_)) => {
            return Err(e).context("binding the control channel");
        }
        Err(e) => {
            eprintln!(
                "warning: no control channel ({e}), so `tornect panic` cannot reach this host; \
                 Ctrl-C in this terminal ends its sessions"
            );
            return Ok(None);
        }
    };
    if let Err(why) = &ctx {
        eprintln!(
            "the control channel answers `tornect panic` only: the unattended store did not \
             open ({why})"
        );
    }
    control.set(true);
    Ok(Some(tokio::spawn(async move {
        let served = match ctx {
            Ok(ctx) => crate::unattended::serve(Arc::new(ctx), &endpoint).await,
            Err(why) => crate::unattended::serve_without_store(kill, why, &endpoint).await,
        };
        control.set(false);
        if let Err(e) = served {
            eprintln!(
                "warning: the control channel stopped ({e:#}); from now on Ctrl-C in this \
                 terminal is what ends sessions"
            );
        }
    })))
}

/// Within how long a second press of the panic key also turns unattended
/// access off (§B.8.7.4).
pub const PANIC_TWICE_WITHIN: Duration = Duration::from_secs(2);

/// What a second press within [`PANIC_TWICE_WITHIN`] says (the toast).
pub const PANIC_TWICE_NOTE: &str = "Unattended access is off: the panic key was pressed twice. \
     Turn it on again with `tornect unattended on`.";

/// The panic key's presses (§B.8.7.4), told off the UI thread by
/// `tornect_platform::hotkey`: each ends every handshake and session this host
/// serves, the host-wide kill with the PANIC reason, as `tornect panic` does,
/// and always first; a second press within [`PANIC_TWICE_WITHIN`] then also
/// turns unattended access off, persisted (the guard's `master_off`), and says
/// so. Each unattended session the kill ended past its PAKE then suspends its
/// own grant (`Suspended{Panic}`, until a local Resume), as it does for
/// `tornect panic`; nothing here suspends a grant.
pub struct PanicPresses {
    kill: KillSwitch,
    guard: Option<Arc<tornect_core::unattended::guard::MutationGuard>>,
    last: std::sync::Mutex<Option<std::time::Instant>>,
    notes: tokio::sync::broadcast::Sender<String>,
}

impl fmt::Debug for PanicPresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PanicPresses").finish_non_exhaustive()
    }
}

impl PanicPresses {
    /// Presses that end what `kill` reaches and, twice, turn `guard`'s
    /// unattended access off (`None`: a host without its store, where there is
    /// nothing to turn off).
    #[must_use]
    pub fn new(
        kill: KillSwitch,
        guard: Option<Arc<tornect_core::unattended::guard::MutationGuard>>,
    ) -> Self {
        Self {
            kill,
            guard,
            last: std::sync::Mutex::new(None),
            notes: tokio::sync::broadcast::channel(4).0,
        }
    }

    /// What a press says to the window (the terminal gets it on stderr).
    #[must_use]
    pub fn notes(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.notes.subscribe()
    }

    /// One press at `now`; whether it was the second within
    /// [`PANIC_TWICE_WITHIN`].
    pub fn press(&self, now: std::time::Instant) -> bool {
        // The host-wide kill first, before anything that writes the store.
        self.kill.kill(bye::PANIC);
        let twice = {
            let mut last = self
                .last
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let twice =
                last.is_some_and(|at| now.saturating_duration_since(at) <= PANIC_TWICE_WITHIN);
            *last = if twice { None } else { Some(now) };
            twice
        };
        if twice {
            let line = match &self.guard {
                Some(guard) => match guard.master_off(tornect_core::session_log::Actor::Ui) {
                    Ok(()) => PANIC_TWICE_NOTE.to_owned(),
                    Err(e) => format!(
                        "The panic key was pressed twice, but unattended access could not be \
                         turned off: {e}"
                    ),
                },
                None => "The panic key was pressed twice; this host has no unattended store, so \
                         there is no unattended access to turn off."
                    .to_owned(),
            };
            note(format_args!("{line}"));
            let _ = self.notes.send(line);
        }
        twice
    }

    /// The callback the platform's watcher calls, on its own thread.
    #[must_use]
    pub fn pressed(self: &Arc<Self>) -> tornect_platform::hotkey::Pressed {
        let presses = Arc::clone(self);
        Arc::new(move || {
            presses.press(std::time::Instant::now());
        })
    }
}

/// This process's panic key, once a host has started it.
static PANIC_KEY: std::sync::OnceLock<Arc<PanicPresses>> = std::sync::OnceLock::new();

/// What the panic key says, for the window: `None` until a host started it.
#[must_use]
pub fn panic_key_notes() -> Option<tokio::sync::broadcast::Receiver<String>> {
    PANIC_KEY.get().map(|presses| presses.notes())
}

/// Start the panic key of `cfg` (`security.panic_key`) for the host whose kill
/// switch is `kill` and whose guard (if its store opened) is `guard`: bound
/// off the UI thread by `tornect_platform::hotkey`, once per process. A chord
/// that cannot be read leaves the key unbound (its readiness row says so).
fn start_panic_key(
    paths: &Paths,
    kill: KillSwitch,
    guard: Option<Arc<tornect_core::unattended::guard::MutationGuard>>,
) {
    let presses = Arc::new(PanicPresses::new(kill, guard));
    if PANIC_KEY.set(Arc::clone(&presses)).is_err() {
        return;
    }
    let text = Config::load(&paths.config_file())
        .map(|cfg| cfg.security.panic_key)
        .unwrap_or_else(|_| tornect_core::config::Security::default().panic_key);
    let chord = match tornect_platform::hotkey::Chord::parse(&text) {
        Ok(chord) => chord,
        Err(why) => {
            eprintln!("warning: the panic key is not bound: {why}");
            return;
        }
    };
    let pressed = presses.pressed();
    tokio::spawn(async move {
        let state = tornect_platform::hotkey::bind(chord, pressed).await;
        tracing::info!(row = state.row(), "panic key");
    });
}

/// Whether this process is the window host, whose indicator is a window on
/// top (the readiness row "indicator shown"); the terminal host's is its
/// terminal's lines.
static WINDOW_HOST: AtomicBool = AtomicBool::new(false);

/// This process is the window host (set before its host is wired).
pub fn this_is_the_window_host() {
    WINDOW_HOST.store(true, Ordering::SeqCst);
}

/// Whether this process's host asks the Wayland portal for the desktop's
/// clipboard (`[services] wayland_clipboard`), set by [`wire_window`] from its
/// config: which restore token the readiness row "capture/input" looks for.
/// One host per process (the host lock), as with the window host's fact.
static PORTAL_CLIPBOARD: AtomicBool = AtomicBool::new(false);

/// The restore token of the portal request a host with `cfg` makes: with
/// `[services] wayland_clipboard` the clipboard request's own file, else the
/// file from before the switch (`Paths::portal_restore_token_for`). Every
/// place that opens, grants, revokes or reports the desktop's grant names it
/// through here, so they all agree with the request.
pub fn portal_token(paths: &Paths, cfg: &Config) -> std::path::PathBuf {
    paths.portal_restore_token_for(cfg.services.wayland_clipboard)
}

/// Revoke the desktop's remembered screen-sharing grants: delete the restore
/// token of both portal requests (`Paths::portal_restore_tokens`), not only
/// the one the request with `[services] wayland_clipboard` as it is now
/// would restore, so that a grant made while the switch stood the other way
/// is never restored after the user revoked. A file already gone is no
/// error; every file is tried, and the first other error is returned.
pub fn revoke_portal_grants(paths: &Paths) -> std::io::Result<()> {
    let mut first = Ok(());
    for token in paths.portal_restore_tokens() {
        match std::fs::remove_file(&token) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                if first.is_ok() {
                    first = Err(e);
                }
            }
        }
    }
    first
}

/// Delete the screen-sharing grants the portal request of a host with `cfg`
/// never restores (with `[services] wayland_clipboard` on, the one made
/// without the clipboard), so no unused bearer grant stays on disk; the
/// desktop then asks once more. With the switch off there are none, and the
/// grant on disk is used as before.
fn forget_retired_grants(paths: &Paths, cfg: &Config) {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    {
        let retired =
            tornect_capture::wayland::forget_retired_tokens(paths, cfg.services.wayland_clipboard);
        if retired > 0 {
            tracing::info!(
                retired,
                "a screen-sharing grant made without the clipboard was deleted; the desktop asks \
                 once more"
            );
        }
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    let _ = (paths, cfg);
}

/// The "indicator shown" fact of a window host started in background mode
/// (§B.1.1, decision M1-58): set once this process drew its sharing
/// indicator's window (the probe right after the main window opens), never
/// unset. One process is one start, so one sign-in. Until it is set, the
/// readiness row "indicator shown" warns and no unattended session is served.
#[derive(Debug, Clone, Default)]
pub struct IndicatorShown(Arc<AtomicBool>);

impl IndicatorShown {
    /// Whether the indicator's window was drawn.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// The indicator's window drew its first frame.
    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// The readiness row "indicator shown" of the host this fact belongs to
    /// (§B.8.7.1 ⑥).
    #[must_use]
    pub fn row(&self) -> tornect_core::unattended::readiness::Probe {
        tornect_platform::readiness::indicator_row(true, Some(self.is_set()))
    }
}

/// The readiness rows this computer can read now, for the host whose guard is
/// `guard` and, in background mode, whose indicator fact is `indicator`
/// (§B.8.7.1 ⑥; the others stay `Unknown`).
fn probe_readiness(
    paths: &Paths,
    guard: &tornect_core::unattended::guard::MutationGuard,
    indicator: Option<&IndicatorShown>,
) -> tornect_core::unattended::readiness::ReadinessSnapshot {
    use tornect_core::keystore::KeystoreKind;
    use tornect_core::unattended::grant::UnattendedGrant;
    let store = guard.store();
    let admin_grant = store
        .read(|s| s.grants.iter().any(UnattendedGrant::holds_level))
        .unwrap_or(false);
    let facts = tornect_platform::readiness::facts_now(
        &paths.state_dir,
        &paths.portal_restore_token_for(PORTAL_CLIPBOARD.load(Ordering::SeqCst)),
        store.keystore_kind() == KeystoreKind::File,
        WINDOW_HOST.load(Ordering::SeqCst),
        indicator.map(IndicatorShown::is_set),
        admin_grant,
    );
    tornect_platform::readiness::rows(&facts)
}

/// Probe the readiness rows again every 10 min into `feed` (§B.8.7.1 ⑥: a
/// screen-sharing grant lost, the panic key's portal gone), with the store's
/// upkeep of [`periodic_upkeep`]; the row "Session log intact" keeps the
/// verifier's verdict.
fn reprobe_readiness(
    paths: &Paths,
    guard: Arc<tornect_core::unattended::guard::MutationGuard>,
    feed: tornect_core::unattended::readiness::SharedReadiness,
    indicator: Option<IndicatorShown>,
) {
    let paths = paths.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tornect_core::unattended::readiness::REPROBE_EVERY).await;
            let (paths, guard, indicator) = (paths.clone(), Arc::clone(&guard), indicator.clone());
            let log_row = feed.get().session_log;
            match tokio::task::spawn_blocking(move || {
                let log_row = periodic_upkeep(guard.store(), log_row);
                let mut snapshot = probe_readiness(&paths, &guard, indicator.as_ref());
                snapshot.session_log = log_row;
                snapshot
            })
            .await
            {
                Ok(snapshot) => feed.set(snapshot),
                Err(e) => tracing::warn!(error = %e, "the readiness probe failed"),
            }
        }
    });
}

/// What a host does with its unattended store at its start: the
/// `sessions.log` verifier (§B.8.13), whose verdict is the readiness row
/// "Session log intact", then the housekeeping (a `GrantExpired` line for each
/// grant that expired since, auth records pruned 30 days after expiry,
/// §B.8.6.1). The verdict is on the log as the host found it: a break the
/// store's load found before the lines it appended itself ([`check_log`]),
/// else the verifier's walk, which runs before the housekeeping's lines.
fn start_upkeep(
    store: &tornect_core::unattended::store::GrantStore,
) -> tornect_core::unattended::readiness::Probe {
    let row = check_log(store);
    housekeep(store);
    row
}

/// What a host does with its store every 10 min, with its readiness probe:
/// while the keystore could not be read, the one recovery load (§B.8.9: the
/// `keystore_locked → readable` transition; a loaded store is never re-read),
/// after which the log is verified as at a start; then the housekeeping.
/// `row` is the row "Session log intact" as it stands, kept otherwise.
fn periodic_upkeep(
    store: &tornect_core::unattended::store::GrantStore,
    row: tornect_core::unattended::readiness::Probe,
) -> tornect_core::unattended::readiness::Probe {
    use tornect_core::unattended::codec::StoreLoadError;
    use tornect_core::unattended::store::StoreStatus;
    let locked = matches!(
        store.status(),
        StoreStatus::FailedClosed(StoreLoadError::KeystoreLocked(_))
    );
    let row = if locked && store.retry_load() == StoreStatus::Loaded {
        tracing::info!("the keystore can be read again: unattended access's store is loaded");
        check_log(store)
    } else {
        row
    };
    housekeep(store);
    row
}

/// The verifier's verdict on `sessions.log`, as its readiness row; anything
/// but a valid chain is also said on stderr. A break that the store's last
/// load found, before the first line it appended (an abandoned charge
/// settled, a machine-id change, a clock anomaly, the lines held while the
/// keystore was locked), is the verdict: each such line links to the file's
/// tail as the load found it, so a tail cut while no host ran would read as
/// a whole chain afterwards. Otherwise the verifier walks the log now, which
/// also accepts the validly tagged lines beyond the stored head.
fn check_log(
    store: &tornect_core::unattended::store::GrantStore,
) -> tornect_core::unattended::readiness::Probe {
    use tornect_core::session_log::ChainStatus;
    use tornect_core::unattended::readiness::{Probe, session_log_row};
    let verdict = match store.take_found_log() {
        Some(Ok(found)) if matches!(found.status, ChainStatus::Broken { .. }) => Ok(found),
        _ => store.verify_log(),
    };
    let row = session_log_row(&verdict, &store.status());
    if let Probe::Fail(why) | Probe::Warn(why) = &row {
        tracing::warn!(%why, "sessions.log");
        eprintln!("warning: sessions.log: {why}");
    }
    row
}

fn housekeep(store: &tornect_core::unattended::store::GrantStore) {
    if let Err(e) = store.housekeeping() {
        tracing::warn!(error = %e, "the unattended store's housekeeping failed");
    }
}

/// Everything `tornect host` serves its signaling streams with.
pub struct HostWiring {
    /// Static facts sent in the handshake.
    pub cfg: HostConfig,
    /// The FSM's seams.
    pub deps: HostDeps,
    /// The IPC context, sharing `deps.kill` and [`Self::live`], or why the
    /// unattended store could not be opened. Without it, unattended requests
    /// are refused `NOT_GRANTED`, no stop code is honoured, and the control
    /// channel answers `tornect panic` only — attended pairing and sessions
    /// still work.
    pub ctx: Result<HostContext, String>,
    /// The sessions live right now.
    pub live: Arc<LiveSessions>,
    /// `sessions.log` as the FSM writes it (flushed at shutdown).
    pub audit: Arc<HostAudit>,
    /// The paired devices the FSM works on: each pairing, unpairing and
    /// reject count is written as it happens, last-seen times only while
    /// history is kept.
    pub pins: Arc<crate::history::DevicePins>,
    /// polkit's remembered approvals, revoked while a Control session is
    /// live (§B.2.1; Linux). The window's own session sink uses it too.
    pub polkit: Arc<PolkitRevocation>,
}

/// Wire the host FSM for `paths`: `consent` answers the popups, `identity`
/// signs, `direct` holds the host's device key (its QUIC identity, §B.6),
/// the knobs and the machine its sessions' direct paths run with (design
/// `direct` §8.6), `media` serves the sessions' screens, and `control` says
/// whether `tornect panic` can reach this host when a session starts.
pub fn wire(
    paths: &Paths,
    cfg: &Config,
    identity: Arc<HostIdentity>,
    direct: DirectWiring,
    consent: Arc<dyn Consent>,
    media: Arc<MediaHost>,
    control: ControlChannel,
) -> anyhow::Result<HostWiring> {
    wire_window(paths, cfg, identity, direct, consent, media, control, None)
}

/// [`wire`], for the window host: `background` is the "indicator shown" fact
/// of a start in background mode (`tornect --background`, §B.1.1). There the
/// readiness row "indicator shown" reads it, and every unattended session is
/// refused `HOST_NOT_READY` until it is set (MUST). A window started by hand
/// (`None`) is shown with its banner and is wired as [`wire`] wires it.
pub fn wire_window(
    paths: &Paths,
    cfg: &Config,
    identity: Arc<HostIdentity>,
    direct: DirectWiring,
    consent: Arc<dyn Consent>,
    media: Arc<MediaHost>,
    control: ControlChannel,
    background: Option<IndicatorShown>,
) -> anyhow::Result<HostWiring> {
    // The session levels this computer can give (§B.2.1). A host started
    // elevated while UAC is on, or running as root on Linux (where Tornect
    // never runs as administrator), or that cannot rule root out (decision
    // M1-67), opens no onion service at all.
    let levels = levels_for(root_check(), tornect_platform::levels::probe)?;
    if !levels.serves() {
        anyhow::bail!(
            "{}",
            levels
                .sentence
                .unwrap_or(tornect_core::levels::SENTENCE_STARTED_ELEVATED)
        );
    }
    PORTAL_CLIPBOARD.store(cfg.services.wayland_clipboard, Ordering::SeqCst);
    forget_retired_grants(paths, cfg);
    let kill = KillSwitch::new();
    let live = Arc::new(LiveSessions::new());
    let polkit = Arc::new(PolkitRevocation::for_this_host());
    let ctx = match crate::unattended::host_context(paths, live.clone(), kill.clone()) {
        Ok(mut ctx) => {
            ctx.indicator = background.clone();
            Ok(ctx)
        }
        Err(e) => {
            eprintln!(
                "warning: unattended access is unavailable ({e:#}); attended pairing and \
                 sessions still work"
            );
            Err(format!("{e:#}"))
        }
    };
    let pins = Arc::new(
        crate::history::DevicePins::open(paths).context("opening the trusted-devices store")?,
    );
    // The load keeps pairing times past their first day to the day in
    // memory only; the start writes them to the file once (P-L4).
    pins.write_back_to_the_day();
    let trusted = pins.store();
    // One handle on `sessions.log` for the whole host: the log is a hash chain
    // whose lock lives in the handle, and the grant store keys it. A second
    // handle writing concurrently could fork the chain.
    let log = ctx.as_ref().map_or_else(
        |_| SessionLog::new(paths.sessions_log()),
        |ctx| ctx.log.clone(),
    );
    let audit = Arc::new(HostAudit::new(Arc::new(log)));

    let mut deps = HostDeps::headless(identity, trusted);
    deps.consent = consent;
    deps.audit = audit.clone();
    deps.sessions = UnattendedUse::wrap(
        &ctx,
        Arc::new(CliSessions {
            live: Arc::clone(&live),
            polkit: Arc::clone(&polkit),
            media: Arc::clone(&media),
            control,
        }),
        media_routes(&media),
    );
    deps.activity = live.clone();
    deps.kill = kill.clone();
    // The sessions' direct paths (design `direct` §8.6): one link at most
    // per session, opened only once the viewer's candidates come, and
    // closed by the host-wide kill like everything else. A direct media
    // stream that never got as far as sharing says so as an onion one does.
    deps.paths = Arc::new(DirectHost::new(
        media,
        // The services stream stays on the onion circuit until it serves a
        // direct connection's second stream (design `direct` step B10).
        None,
        Arc::clone(&direct.device),
        direct.knobs.direct.clone(),
        Arc::clone(&direct.net),
        kill.clone(),
        Arc::new(|outcome: &MediaOutcome| {
            if let Some(line) = describe_media(outcome) {
                note(format_args!("{line}"));
            }
        }),
    ));

    let mut host_cfg = HostConfig::new(cfg.general.device_name.clone(), direct.device_pk());
    // One knob for both kinds of accept (design `direct` §8.2): attended
    // accepts read it at the accept, unattended receipts at the request. The
    // caller holds it too, sets the bridge state after each Tor bootstrap
    // (`DirectKnobs::bootstrapped`, decision M1-86) and asks its own
    // sessions' paths with it.
    host_cfg.transport = direct.knobs.transport.clone();
    host_cfg.levels = levels;

    if let Ok(ctx) = &ctx {
        let log_row = start_upkeep(ctx.guard.store());
        let mut snapshot = probe_readiness(paths, &ctx.guard, ctx.indicator.as_ref());
        snapshot.session_log = log_row;
        ctx.readiness.set(snapshot);
        deps.stop_token = Arc::new(EmergencyStop::new(Arc::clone(&ctx.guard), kill));
        // M1 has no local-zone source (decision M1-15; a tzdb-backed zone is
        // M6). The zone only matters for grant schedules, and no path in this
        // build creates one: the presets have none and `tornect unattended
        // grant` sends none.
        let auth = UnattendedAuth::new(
                AttemptLimiter::new(ctx.guard.store().clone()),
                Arc::new(FixedOffset::utc()),
                HostTransport {
                    paranoid: cfg.network.paranoid,
                    lan_only: cfg.network.lan_only,
                },
                // Read at each answer (decision M1-67).
                Arc::new(tornect_platform::levels::LiveFacts),
            )
            // Readiness as probed at the start and every 10 min (§B.8.7.1 ⑥).
            .with_readiness_feed(ctx.readiness.clone())
            .with_admin_authority(Arc::new(GuardAdmin::new(Arc::clone(&ctx.guard))))
            // Block suspends the grant (§B.8.6.3). The window host and the
            // terminal host each have a block window with Block (`wire_cli`
            // gives the terminal's); "Ask before starting" is the window's
            // sheet, and denied on the terminal.
            .with_block_guard(Arc::clone(&ctx.guard))
            // The same knob the attended accepts read, at each request.
            .with_transport_knob(host_cfg.transport.clone());
        // §B.1.1 (MUST): in background mode, no unattended session before
        // the indicator was shown; the rows' causes still go first.
        let auth = match background {
            Some(shown) => auth.with_ready_gate(Arc::new(move || shown.is_set())),
            None => auth,
        };
        deps.unattended = Arc::new(auth);
        host_cfg.feats = vec![messages::feats::UA1.to_owned()];
    }
    // The services stream (design `services` §0): pushed after the
    // unattended suite so that nothing overwrites it, and offered with or
    // without a store. The window host serves it; the terminal host
    // advertises it too and refuses every services stream, so the token does
    // not tell one kind of host from the other before pairing (decision
    // M1-76). A host with nothing to show a session on clears it with the
    // rest ([`HostWiring::without_unattended`]).
    host_cfg.feats.push(messages::feats::SVC1.to_owned());
    // The direct path (design `direct` §4): with it a viewer of this build
    // tries a direct connection after the accept; without it, one sends
    // `TOR_FALLBACK{}` at once, as to an older host. Offered whatever the
    // policy: the accept signs the policy, and the viewer reads it there.
    host_cfg.feats.push(messages::feats::DIR1.to_owned());

    Ok(HostWiring {
        cfg: host_cfg,
        deps,
        ctx,
        live,
        audit,
        pins,
        polkit,
    })
}

impl HostWiring {
    /// This wiring for a host that has nothing to show a session on: no
    /// terminal and no window. It offers no unattended suite and answers every
    /// unattended request `NOT_GRANTED` before any password exchange, remote
    /// admin requests included, because §B.6's indicator must be visible for
    /// every session and nobody could see one here (slice-F F2-1; decision
    /// M1-48 (8)). What only takes access away stays: the control channel
    /// (`tornect panic`, `unattended off`, `service uninstall`), the kill switch
    /// and the emergency stop code.
    #[must_use]
    pub fn without_unattended(mut self) -> Self {
        self.cfg.feats.clear();
        self.deps.unattended = Arc::new(NotGranted);
        self
    }
}

/// What `tornect host` says at start when stdin is not a terminal (a pipe, a
/// script, or the systemd user unit that `tornect service install` of earlier
/// versions registered; today's start at login is the window, §B.1.1).
pub(crate) const NO_TERMINAL_LINE: &str = "warning: stdin is not a terminal, so this host answers \
     pings only: every pairing, session and unattended request is refused, because nothing here \
     can ask you or show you a session (run `tornect host` in a terminal to answer them)";

/// Wire `tornect host`, the command-line host, whose terminal (`prompter`)
/// answers the popups, shows every session and runs the block window with
/// Block ([`crate::term_block::TerminalBlockWindow`]; decision M1-68). With no
/// terminal (`None`) nothing can ask or show, so the host answers pings only
/// ([`HostWiring::without_unattended`]).
pub fn wire_cli(
    paths: &Paths,
    cfg: &Config,
    identity: Arc<HostIdentity>,
    direct: DirectWiring,
    prompter: Option<Arc<Prompter>>,
    media: Arc<MediaHost>,
    control: ControlChannel,
) -> anyhow::Result<HostWiring> {
    match prompter {
        Some(prompter) => {
            // The terminal's pairing question shows device words and runs the
            // look-alike alarm (§B.6.1).
            let words = crate::ui::recognize::Recognizer::new(
                paths.clone(),
                crate::ui::recognize::Me {
                    name: cfg.general.device_name.clone(),
                    onion: identity.id(),
                    device: tornect_core::DeviceId::from_bytes(direct.device_pk()),
                },
            );
            let mut wiring = wire(
                paths,
                cfg,
                identity,
                direct,
                Arc::new(CliConsent::new(Arc::clone(&prompter)).with_words(Arc::new(words))),
                media,
                control,
            )?;
            // The block window with Block, on this terminal (§B.8.6.3): it
            // goes before every question there. "Ask before starting" stays
            // denied (`AlwaysDeny`). Its line after a Block names the device
            // by the fingerprint its grant gives (B23).
            let window = crate::term_block::TerminalBlockWindow::new(prompter);
            let window = match &wiring.ctx {
                Ok(ctx) => window.with_grants(ctx.guard.store().clone()),
                Err(_) => window,
            };
            wiring.deps.block_window = Arc::new(window);
            Ok(wiring)
        }
        None => Ok(wire(
            paths,
            cfg,
            identity,
            direct,
            Arc::new(AutoDeny),
            media,
            control,
        )?
        .without_unattended()),
    }
}

/// The CLI's [`SessionSink`]: records each session in the tracker, hands it to
/// the media layer, and says on the terminal when one starts and ends.
struct CliSessions {
    live: Arc<LiveSessions>,
    polkit: Arc<PolkitRevocation>,
    media: Arc<MediaHost>,
    control: ControlChannel,
}

/// Where a [`PolkitRevocation`] finds polkit's authority.
type AuthorityFactory = Arc<
    dyn Fn() -> tornect_platform::polkit::BoxFuture<
            'static,
            Result<
                Arc<dyn tornect_platform::polkit::TemporaryAuthority>,
                tornect_platform::polkit::PolkitError,
            >,
        > + Send
        + Sync,
>;

/// What the Linux root check found: the owner of `/proc/self` is this
/// process's effective user (proc(5)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum Root {
    /// Not root (and every system but Linux).
    No,
    /// Root.
    Yes,
    /// `/proc/self` could not be read: root is not ruled out.
    Unreadable,
}

/// The refusal of a host that cannot rule out running as root (decision M1-67).
const SENTENCE_ROOT_UNREADABLE: &str = "Tornect could not read which user it runs as \
    (/proc/self), so it does not share this computer: on Linux it never runs as \
    administrator, and it cannot rule that out.";

/// The Linux root check of this process.
fn root_check() -> Root {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt as _;
        root_from(std::fs::metadata("/proc/self").map(|m| m.uid()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Root::No
    }
}

/// The root check from what reading `/proc/self` gave: its owner, or why it
/// could not be read (A21: a host that cannot rule out root does not serve).
#[cfg(any(test, target_os = "linux"))]
fn root_from(read: std::io::Result<u32>) -> Root {
    match read {
        Ok(uid) if is_root(uid) => Root::Yes,
        Ok(_) => Root::No,
        Err(_) => Root::Unreadable,
    }
}

/// Whether this process may run as root on Linux: root, or its user could not
/// be read.
#[cfg(all(test, target_os = "linux"))]
fn running_as_root() -> bool {
    root_check() != Root::No
}

/// The session levels a host whose root check found `root` can give: the probe's
/// row, the root row, or a refusal when root cannot be ruled out.
fn levels_for(
    root: Root,
    probe: impl FnOnce() -> tornect_core::levels::Availability,
) -> anyhow::Result<tornect_core::levels::Availability> {
    match root {
        Root::No => Ok(probe()),
        Root::Yes => Ok(tornect_core::levels::Availability::LINUX_ROOT),
        Root::Unreadable => anyhow::bail!("{SENTENCE_ROOT_UNREADABLE}"),
    }
}

/// Whether `uid` is root's.
#[cfg(any(test, target_os = "linux"))]
fn is_root(uid: u32) -> bool {
    uid == 0
}

/// `connect`, run once for the host's life: every Control session shares the
/// first authority it connected (one system-bus connection per host, not one
/// per session); a failed attempt is tried again by the next session.
#[cfg(any(test, target_os = "linux"))]
fn once_per_host(connect: AuthorityFactory) -> AuthorityFactory {
    let cell: Arc<tokio::sync::OnceCell<Arc<dyn tornect_platform::polkit::TemporaryAuthority>>> =
        Arc::default();
    Arc::new(move || {
        let (cell, connect) = (Arc::clone(&cell), Arc::clone(&connect));
        Box::pin(async move { cell.get_or_try_init(|| connect()).await.cloned() })
    })
}

/// Keeps polkit's remembered approvals revoked while a Control session is
/// live (§B.2.1, M-FEAT-2): at its start and after every change the
/// authority reports, until it ends. It only makes the person at the
/// computer type a password again; it is never described as enforcement.
/// View-only sessions and systems without polkit are left alone.
pub struct PolkitRevocation {
    authority: Option<AuthorityFactory>,
    live: std::sync::Mutex<std::collections::HashMap<String, JoinHandle<()>>>,
    /// How a revocation that failed, or a watch that stopped, is told to
    /// the person at this computer (default: the terminal).
    tell: std::sync::Mutex<Tell>,
}

/// How [`PolkitRevocation`] tells the person at this computer.
type Tell = Arc<dyn Fn(&str) + Send + Sync>;

/// What the person at this computer is told when polkit's remembered
/// approvals could not be cleared for a Control session, or stopped being
/// cleared during it (§B.2.1: best effort, disclosed, never enforcement).
pub const POLKIT_NOT_CLEARED: &str = "Tornect could not clear this computer's remembered \
    password approvals for this session: an approval given shortly before may still work for \
    the person connected.";
/// ... when the approvals were cleared at the start but changes during the
/// session are not watched.
pub const POLKIT_NOT_WATCHED: &str = "Tornect cleared this computer's remembered password \
    approvals when this session started, but cannot clear the ones given during it.";

impl PolkitRevocation {
    /// The system's authority on Linux; nothing elsewhere, and nothing in
    /// this crate's tests (they must not touch the machine's polkit).
    #[must_use]
    pub fn for_this_host() -> Self {
        #[cfg(all(target_os = "linux", not(test)))]
        let authority: Option<AuthorityFactory> = Some(once_per_host(Arc::new(|| {
            Box::pin(async {
                let authority = tornect_platform::polkit::SystemAuthority::connect().await?;
                Ok(Arc::new(authority) as Arc<dyn tornect_platform::polkit::TemporaryAuthority>)
            })
        })));
        #[cfg(not(all(target_os = "linux", not(test))))]
        let authority: Option<AuthorityFactory> = None;
        Self::with(authority)
    }

    /// Revocation through `authority` (`None`: never).
    #[must_use]
    fn with(authority: Option<AuthorityFactory>) -> Self {
        Self {
            authority,
            live: std::sync::Mutex::new(std::collections::HashMap::new()),
            tell: std::sync::Mutex::new(Arc::new(|line: &str| note(format_args!("{line}")))),
        }
    }

    /// Tell the person at this computer through `tell` (the window's line)
    /// instead of the terminal.
    pub fn tell_through(&self, tell: Tell) {
        *self
            .tell
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = tell;
    }

    /// A session went live: a Control one starts the revocation.
    pub fn on_start(&self, session: &LiveSession<'_>) {
        let Some(authority) = self.authority.clone() else {
            return;
        };
        if session.mode != SessionMode::Control {
            return;
        }
        let tell = Arc::clone(
            &self
                .tell
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let task = tokio::spawn(async move {
            let authority = match authority().await {
                Ok(authority) => authority,
                Err(e) => {
                    tracing::warn!(error = %e, "polkit's remembered approvals could not be revoked");
                    tell(POLKIT_NOT_CLEARED);
                    return;
                }
            };
            let (guard, started) = tornect_platform::polkit::guard_control_session(authority).await;
            match started {
                tornect_platform::polkit::Started::Revoked => {
                    tracing::info!("polkit's remembered approvals revoked for a Control session");
                }
                tornect_platform::polkit::Started::Unwatched(e) => {
                    tracing::warn!(error = %e, "polkit's changes are not watched this session");
                    tell(POLKIT_NOT_WATCHED);
                }
                tornect_platform::polkit::Started::Failed(e) => {
                    tracing::warn!(error = %e, "polkit's remembered approvals could not be revoked");
                    tell(POLKIT_NOT_CLEARED);
                }
            }
            // Held until the session ends and aborts this task; a watch that
            // stops before that is said.
            if let Some(mut guard) = guard {
                guard.stopped().await;
                tracing::warn!("polkit's changes stopped being watched during a Control session");
                tell(POLKIT_NOT_WATCHED);
            }
            std::future::pending::<()>().await;
        });
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(session.session_id.to_owned(), task);
    }

    /// A session ended: its revocation stops.
    pub fn on_end(&self, session_id: &str) {
        let task = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(session_id);
        if let Some(task) = task {
            task.abort();
        }
    }
}

impl SessionSink for CliSessions {
    fn on_start(&self, session: &LiveSession<'_>) {
        self.live.on_start(session);
        crate::secure_screen::on_start(&self.live, session, cfg!(windows));
        self.polkit.on_start(session);
        self.media.on_start(session);
        say(format_args!("SESSION LIVE {}", session.session_id));
        peer_note(format_args!(
            "session with \"{}\" is live ({}{}{}); {} ends it",
            session.label,
            mode_name(session.mode),
            if session.elevation == tornect_core::levels::Elevation::Admin {
                " as administrator"
            } else {
                ""
            },
            if session.unattended {
                ", unattended"
            } else {
                ""
            },
            self.control.kill_path(),
        ));
        // §B.8.8: a secure Windows screen (a UAC prompt, Ctrl+Alt+Del, the
        // lock screen) is out of the session's reach; said while it shows.
        #[cfg(windows)]
        if session.mode == SessionMode::Control {
            let (live, id) = (Arc::clone(&self.live), session.session_id.to_owned());
            let (sessions, told_id) = (Arc::clone(&self.live), id.clone());
            tokio::spawn(async move {
                crate::secure_screen::run(
                    Arc::new(crate::secure_screen::WindowsDesktop),
                    crate::secure_screen::EVERY,
                    move || live.snapshot().iter().any(|s| s.session_id == id),
                    move |shown| {
                        // The viewer is told too, by the bit its PONGs carry.
                        let line = crate::secure_screen::on_change(&sessions, &told_id, shown);
                        note(format_args!("{line}"));
                    },
                )
                .await;
            });
        }
    }

    /// The start code and the secure-screen bit, with the media layer's
    /// no-input bit added (a control session with nothing to inject into).
    fn notice(&self, session_id: &str) -> Option<u8> {
        self.media
            .viewer_notice(session_id, self.live.notice(session_id))
    }

    fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
        // Media first: that is what stops capture.
        self.media.on_end(session_id, end);
        self.live.on_end(session_id, end);
        self.polkit.on_end(session_id);
        say(format_args!("SESSION ENDED {session_id}"));
        note(format_args!(
            "session ended: {}",
            end.map_or_else(|| "protocol error".to_owned(), describe_end)
        ));
    }
}

/// The path a session's media stream was claimed on, by session id
/// ([`MediaHost::route`]): `None` before the claim and once the media layer
/// ended the session.
pub type RouteOf = Arc<dyn Fn(&str) -> Option<TransportKind> + Send + Sync>;

/// [`RouteOf`] for the sessions `media` serves.
#[must_use]
pub fn media_routes(media: &Arc<MediaHost>) -> RouteOf {
    let media = Arc::clone(media);
    Arc::new(move |session_id: &str| media.route(session_id))
}

/// The longest gap between a PAKE success and its session's start that counts
/// towards the session's length: the block window and an "Ask before
/// starting" card are bounded far below it.
const MAX_LEAD: u64 = 15 * 60;

/// Each unattended session's length, on its grant's `last_used` (§B.8.6.4):
/// the reconnect cooldown after a session that ran the full
/// `max_session_secs` is judged post-F2 from it, so every host serves its
/// sessions through this sink, around its own ([`CliSessions`], the
/// window's). Attended sessions pass through untouched.
///
/// `last_used.at` is the PAKE success that let the session in (`settle(Ok)`,
/// §B.8.5.1), and the length written at the end counts from it: `at +
/// duration_secs` is then the session's end, and a session cut at its signed
/// `ends_at` (reckoned post-F2, before the block window) counts as full
/// length: the length is counted in the wall clock's whole seconds, as `at`
/// and `ends_at` are, so such a session ends exactly at `at + max_session_secs`
/// or later (the monotonic time alone, rounded down twice, read it a second
/// short of the maximum, which leaves no cooldown). The monotonic time counts
/// where it is the longer, when the wall went back during the session; a wall
/// that jumped forward makes a session longer, never shorter, so no session
/// that ran its maximum escapes the cooldown. Should `last_used` hold an earlier
/// session's end at the start (that session's cooldown ran out between the
/// PAKE and the post-F2 check), the start is recorded first. Only a device's
/// latest session writes its end, so an older one ending after a newer one of
/// the same device started (`BYE{REPLACED}`) leaves the newer one's record
/// alone. A session whose host process ends without the session's end (killed,
/// crashed) records no length, and so no cooldown follows it.
///
/// `last_used.transport` is the path the session's media took (design
/// `direct`: a direct LAN path, or the Tor stream), read at the session's end
/// from `routes` before the media layer forgets it; a session whose media
/// never bound went over Tor alone. The path is chosen after the accept, so
/// the start (and the PAKE success before it) leaves the transport on record
/// as it was until the end writes the session's own.
pub struct UnattendedUse {
    inner: Arc<dyn SessionSink>,
    store: tornect_core::unattended::store::GrantStore,
    routes: RouteOf,
    state: std::sync::Mutex<UseState>,
}

#[derive(Default)]
struct UseState {
    next: u64,
    /// The live unattended sessions, by session id.
    live: std::collections::HashMap<String, UseStart>,
    /// Each device's latest start.
    latest: std::collections::HashMap<tornect_core::DeviceId, u64>,
}

struct UseStart {
    device: tornect_core::DeviceId,
    /// The store clock's wall reading at the start (unix seconds).
    wall: u64,
    /// Its monotonic reading, just after.
    mono: Duration,
    /// Seconds from the PAKE success to the start.
    lead: u64,
    /// Which start of this host it was.
    seq: u64,
}

impl UnattendedUse {
    /// `inner`, recording unattended sessions on the grants of `ctx`'s store,
    /// each with the path `routes` says its media took; `inner` itself when
    /// the store did not open (no unattended session can start then).
    #[must_use]
    pub fn wrap(
        ctx: &Result<HostContext, String>,
        inner: Arc<dyn SessionSink>,
        routes: RouteOf,
    ) -> Arc<dyn SessionSink> {
        match ctx {
            Ok(ctx) => Arc::new(Self::new(inner, ctx.guard.store().clone(), routes)),
            Err(_) => inner,
        }
    }

    fn new(
        inner: Arc<dyn SessionSink>,
        store: tornect_core::unattended::store::GrantStore,
        routes: RouteOf,
    ) -> Self {
        Self {
            inner,
            store,
            routes,
            state: std::sync::Mutex::new(UseState::default()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, UseState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn started(&self, session: &LiveSession<'_>) {
        if !session.unattended {
            return;
        }
        let device = session.device;
        let clock = Arc::clone(self.store.clock());
        // The wall first, the monotonic reading after it, and the other way round
        // at the end: the monotonic span then never exceeds the wall's where the
        // two clocks agree ([`session_secs`]).
        let wall = clock.wall();
        let mono = clock.mono();
        let last = self.store.grant(&device).and_then(|g| g.last_used);
        let lead = match last {
            // This session's own PAKE success: `settle(Ok)` writes no length.
            Some(last) if last.duration_secs == 0 && last.at <= wall => {
                (wall - last.at).min(MAX_LEAD)
            }
            _ => {
                // The media's path is not chosen yet: the transport on record
                // stays, as `settle(Ok)` keeps it, until the end writes it.
                let transport = last.map_or(TransportKind::TorRelay, |l| l.transport);
                if let Err(e) = self.store.record_session_start(&device, transport) {
                    not_recorded(&device, &e, "start");
                }
                0
            }
        };
        let mut st = self.state();
        st.next += 1;
        let seq = st.next;
        st.latest.insert(device, seq);
        st.live.insert(
            session.session_id.to_owned(),
            UseStart {
                device,
                wall,
                mono,
                lead,
                seq,
            },
        );
    }

    /// Session `session_id` ended; its media went over `route` (`None`:
    /// its media never bound, so it went over Tor alone).
    fn ended(&self, session_id: &str, route: Option<TransportKind>) {
        let start = {
            let mut st = self.state();
            let Some(start) = st.live.remove(session_id) else {
                return;
            };
            if st.latest.get(&start.device) != Some(&start.seq) {
                return;
            }
            st.latest.remove(&start.device);
            start
        };
        let clock = self.store.clock();
        let mono = clock.mono();
        let wall = clock.wall();
        let ran = session_secs((start.wall, start.mono), (wall, mono)).saturating_add(start.lead);
        let secs = u32::try_from(ran).unwrap_or(u32::MAX);
        let transport = route.unwrap_or(TransportKind::TorRelay);
        if let Err(e) = self
            .store
            .record_session_end(&start.device, transport, secs)
        {
            not_recorded(&start.device, &e, "length");
        }
    }
}

/// How long a session ran from `start` to `end` (each a wall reading in unix
/// seconds and a monotonic reading), in whole seconds: the wall's span, which
/// `last_used.at` and the signed `ends_at` count in, or the monotonic span
/// rounded down where that is longer (the wall went back meanwhile). Where the
/// clocks agree the monotonic span, rounded down, is never the longer, so the
/// wall's counts exactly.
fn session_secs(start: (u64, Duration), end: (u64, Duration)) -> u64 {
    let wall = end.0.saturating_sub(start.0);
    wall.max(end.1.saturating_sub(start.1).as_secs())
}

/// A session's `what` that did not reach its grant: expected when the grant
/// went during the session (a revoke ends it), a fault otherwise.
fn not_recorded(
    device: &tornect_core::DeviceId,
    e: &tornect_core::unattended::store::StoreError,
    what: &str,
) {
    use tornect_core::unattended::store::StoreError;
    match e {
        StoreError::NoGrant | StoreError::NotLoaded(_) => {
            tracing::debug!(peer = ?device, error = %e, what, "no grant to record the session on");
        }
        _ => {
            tracing::warn!(peer = ?device, error = %e, what, "the session could not be recorded on its grant")
        }
    }
}

impl SessionSink for UnattendedUse {
    fn on_start(&self, session: &LiveSession<'_>) {
        // The sink's own start first: the tracker and the indicator.
        self.inner.on_start(session);
        self.started(session);
    }

    fn notice(&self, session_id: &str) -> Option<u8> {
        self.inner.notice(session_id)
    }

    fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
        // The media's path is read first, for a session this sink tracks:
        // the sink's own end, which then comes first because it is what stops
        // capture, ends the media the path belongs to.
        let tracked = self.state().live.contains_key(session_id);
        let route = if tracked {
            (self.routes)(session_id)
        } else {
            None
        };
        self.inner.on_end(session_id, end);
        self.ended(session_id, route);
    }
}

/// The §B.6 sharing indicator, as a terminal can show it: a line when a
/// session's screen starts going out, and one when capture has stopped.
pub struct CliMedia {
    control: ControlChannel,
}

impl CliMedia {
    /// An indicator that names the kill path `control` says works.
    #[must_use]
    pub fn new(control: ControlChannel) -> Self {
        Self { control }
    }
}

impl MediaObserver for CliMedia {
    fn capture_started(&self, s: &CaptureStarted<'_>) {
        say(format_args!("SHARING {}", s.session_id));
        // The route its media was claimed on (design `direct` §3.5).
        say(format_args!(
            "{}",
            crate::direct::session_route_line(s.session_id, s.route)
        ));
        let input = match (s.mode, s.input) {
            (SessionMode::ViewOnly, _) => "view-only",
            (_, true) => "their input is injected",
            (_, false) => "their input goes nowhere here",
        };
        peer_note(format_args!(
            "sharing this screen with \"{}\" ({} {}x{}; {input}); {} stops it",
            s.label,
            s.source,
            s.width,
            s.height,
            self.control.kill_path()
        ));
    }

    fn capture_changed(&self, changed: &CaptureChanged<'_>) {
        say(format_args!("{}", view_line(changed)));
    }

    fn capture_stopped(&self, session_id: &str, report: &MediaReport, end: &MediaEnd) {
        say(format_args!("SHARING STOPPED {session_id}"));
        note(format_args!(
            "screen sharing stopped ({}): {} pictures, {} KiB sent; {}",
            describe_media_end(*end),
            report.frames_sent,
            report.bytes_sent / 1024,
            stage_means(report)
        ));
    }
}

/// The host's line for what a session's pictures show (the monitors design
/// §2), at its first picture of a desktop with monitors to choose from and
/// whenever they show another part of it: `SHARING VIEW <session> screen=2
/// of=3`, or `screen=all of=3`. Numbers only: a monitor's name never goes
/// out.
pub(crate) fn view_line(changed: &CaptureChanged<'_>) -> String {
    let screen = if changed.all {
        "all".to_owned()
    } else {
        changed.screen.to_string()
    };
    format!(
        "SHARING VIEW {} screen={screen} of={}",
        changed.session_id, changed.of
    )
}

/// The means of a served stream's stages, for the host's stop line (the
/// quality design §3.5): `encode 9.8 ms, scale 2.1 ms, convert 1.5 ms, send
/// 120 ms, round trip 1.1 s, quality changes 2`. The stage means are over the
/// pictures sent and the round trip over the acks; each is left out when
/// there were none.
pub(crate) fn stage_means(report: &MediaReport) -> String {
    let mut parts = Vec::new();
    if report.frames_sent > 0 {
        let mean = |sum: u64| duration_text(sum / report.frames_sent);
        parts.push(format!("encode {}", mean(report.encode_us)));
        parts.push(format!("scale {}", mean(report.scale_us)));
        parts.push(format!("convert {}", mean(report.convert_us)));
        parts.push(format!("send {}", mean(report.send_us)));
    }
    if let Some(rtt) = report.ack_us.checked_div(report.acks) {
        parts.push(format!("round trip {}", duration_text(rtt)));
    }
    parts.push(format!("quality changes {}", report.quality_changes));
    parts.join(", ")
}

/// A duration in µs as people read it (the quality design §3.3): one decimal
/// under 10 ms (`9.8 ms`), whole milliseconds under a second (`120 ms`), then
/// seconds with one decimal (`1.1 s`).
pub(crate) fn duration_text(us: u64) -> String {
    let tenths_ms = us.saturating_add(50) / 100;
    if tenths_ms < 100 {
        return format!("{}.{} ms", tenths_ms / 10, tenths_ms % 10);
    }
    let ms = us.saturating_add(500) / 1000;
    if ms < 1000 {
        return format!("{ms} ms");
    }
    let tenths_s = us.saturating_add(50_000) / 100_000;
    format!("{}.{} s", tenths_s / 10, tenths_s % 10)
}

pub(crate) fn describe_media_end(end: MediaEnd) -> String {
    match end {
        MediaEnd::SessionOver(reason) => format!("session over, {}", media_reason(reason)),
        MediaEnd::ViewerLeft => "the viewer left".to_owned(),
        MediaEnd::Protocol => "the viewer broke the media protocol".to_owned(),
        MediaEnd::Pipeline(reason) => media_reason(reason).to_owned(),
        MediaEnd::Io => "the connection to the viewer failed".to_owned(),
    }
}

/// A `tornect_proto::reason` for people: the table the viewer's refusal
/// text uses too.
pub use tornect_session::media_reason;

/// One line for a media stream that never got as far as sharing (the observer
/// reports the ones that did).
pub fn describe_media(outcome: &MediaOutcome) -> Option<String> {
    Some(match outcome {
        MediaOutcome::Busy => {
            "media bind refused: too many are waiting for their session".to_owned()
        }
        MediaOutcome::NotBound => "media stream closed: it did not prove a live session".to_owned(),
        MediaOutcome::NotStarted(end) => {
            format!("screen sharing did not start: {}", describe_media_end(*end))
        }
        // Served: the observer reported it. Abandoned: a viewer's unused
        // onion pre-open, closed once its direct path won (the direct design
        // §8.5), which is nothing to report.
        MediaOutcome::Served { .. } | MediaOutcome::Abandoned => return None,
    })
}

/// A line on stdout that cannot panic. `println!` panics when stdout is a
/// closed pipe, and a panic inside a [`SessionSink`] call would skip the
/// `on_end` that releases the session and stops capture (SLICE-B1 B1-4).
pub(crate) fn say(line: fmt::Arguments<'_>) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}").and_then(|()| out.flush());
}

/// [`say`] for stderr.
pub(crate) fn note(line: fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// Whether the live-check scripts asked for the evidence lines that name a
/// peer or this computer (U3-M1): set once at start, from this process's own
/// command line (`--evidence`) or environment ([`EVIDENCE_ENV`] = `1`) only.
static EVIDENCE: AtomicBool = AtomicBool::new(false);

/// The environment variable of the evidence opt-in.
pub(crate) const EVIDENCE_ENV: &str = "TORNECT_EVIDENCE";

/// Whether the evidence lines are wanted: the flag, or `1` in [`EVIDENCE_ENV`].
fn evidence_wanted(flag: bool, env: Option<&str>) -> bool {
    flag || env == Some("1")
}

/// Take the evidence opt-in from `--evidence` and the environment.
pub(crate) fn opt_in_evidence(flag: bool) {
    let env = std::env::var(EVIDENCE_ENV).ok();
    EVIDENCE.store(evidence_wanted(flag, env.as_deref()), Ordering::Relaxed);
}

/// An evidence line on stdout (U3-M1): `full`, which names the host viewed
/// or this computer's address, only when the live-check scripts opted in;
/// otherwise `bare` (the session id only), or nothing without one.
pub(crate) fn say_evidence(full: fmt::Arguments<'_>, bare: Option<fmt::Arguments<'_>>) {
    evidence_to(
        &mut std::io::stdout().lock(),
        EVIDENCE.load(Ordering::Relaxed),
        full,
        bare,
    );
}

fn evidence_to(
    out: &mut dyn std::io::Write,
    opted_in: bool,
    full: fmt::Arguments<'_>,
    bare: Option<fmt::Arguments<'_>>,
) {
    if let Some(line) = if opted_in { Some(full) } else { bare } {
        let _ = writeln!(out, "{line}").and_then(|()| out.flush());
    }
}

/// A note on stderr that names a peer (its label or its device's
/// fingerprint): written only when stderr is a terminal (the rule of the
/// terminal's questions, R-3g), else nothing, so that a journal or a log
/// file never collects who connected (U3-M1).
pub(crate) fn peer_note(line: fmt::Arguments<'_>) {
    let stderr = std::io::stderr();
    let terminal = stderr.is_terminal();
    peer_note_to(&mut stderr.lock(), terminal, line);
}

fn peer_note_to(out: &mut dyn std::io::Write, terminal: bool, line: fmt::Arguments<'_>) {
    if terminal {
        let _ = writeln!(out, "{line}");
    }
}

/// `tornect host`'s own `Tornect ID: …` line (FX1-L2): on stdout only when
/// stdout is a terminal or the evidence opt-in is set, so that a journal or
/// a file never collects this computer's address (`tornect id` and the
/// window show it).
pub(crate) fn own_id(line: fmt::Arguments<'_>) {
    let stdout = std::io::stdout();
    let terminal = stdout.is_terminal();
    own_id_to(
        &mut stdout.lock(),
        terminal,
        EVIDENCE.load(Ordering::Relaxed),
        line,
    );
}

fn own_id_to(
    out: &mut dyn std::io::Write,
    terminal: bool,
    opted_in: bool,
    line: fmt::Arguments<'_>,
) {
    if terminal || opted_in {
        let _ = writeln!(out, "{line}").and_then(|()| out.flush());
    }
}

fn mode_name(mode: SessionMode) -> &'static str {
    match mode {
        SessionMode::ViewOnly => "view-only",
        _ => "control",
    }
}

pub(crate) fn describe_end(end: &SessionEnd) -> String {
    match end {
        SessionEnd::PeerBye(reason) => format!("the client left ({})", bye::name(*reason)),
        SessionEnd::PeerError(code) => {
            format!("the client reported an error ({})", codes::name(*code))
        }
        SessionEnd::PeerClosed => "the client closed the connection".to_owned(),
        SessionEnd::Killed(reason) => format!("ended here ({})", bye::name(*reason)),
        SessionEnd::Orphaned => "the client chose no transport in time".to_owned(),
        SessionEnd::Idle => "no traffic for the idle timeout".to_owned(),
        SessionEnd::Transport(reason) => {
            format!("no media route the session allows ({})", bye::name(*reason))
        }
        other => format!("{other:?}"),
    }
}

/// What one signaling stream amounted to (`tornect host --once` stops after
/// the first answered ping or finished session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// The ping protocol answered this many pings.
    Pings(u32),
    /// A session was established and has ended.
    Session,
    /// A handshake that established no session.
    Handshake,
    /// No complete first frame.
    Nothing,
}

/// Serve one stream from the signaling port: route it by its first frame to the
/// ping protocol or to the FSM, and report the result on the terminal.
/// `answered` sees the running count after each pong.
pub async fn serve_signaling<S, F>(
    stream: S,
    cfg: &HostConfig,
    deps: &HostDeps,
    answered: F,
) -> Served
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    F: FnMut(u32),
{
    let started = Instant::now();
    match first_frame(stream, FIRST_FRAME_DEADLINE).await {
        FirstFrame::Ping(mut stream) => {
            eprintln!("ping client connected over Tor");
            // The session budget counts from the first byte, as it did when the
            // ping protocol read that frame itself.
            let limits = ServeLimits {
                session_deadline: ping::SESSION_TIMEOUT.saturating_sub(started.elapsed()),
                ..ServeLimits::default()
            };
            let mut count = 0;
            let mut answered = answered;
            let outcome = ping::serve_with_limits(&mut stream, limits, |n| {
                count = n;
                answered(n);
            })
            .await;
            match outcome {
                Ok(n) => eprintln!("ping client disconnected after {n} ping(s)"),
                Err(e) => eprintln!("ping session ended: {e}"),
            }
            Served::Pings(count)
        }
        FirstFrame::Handshake(stream) => match serve_host(stream, cfg, deps).await {
            Ok(outcome) => {
                note_outcome(&outcome, deps.activity.session_live());
                if matches!(outcome, HostOutcome::Session { .. }) {
                    Served::Session
                } else {
                    Served::Handshake
                }
            }
            Err(e) => {
                eprintln!("handshake ended: {e}");
                Served::Handshake
            }
        },
        FirstFrame::Gone(why) => {
            tracing::debug!(?why, "signaling stream closed before its first frame");
            Served::Nothing
        }
    }
}

/// The terminal's note for a handshake that ended without a live session
/// ([`describe_outcome`]), on stderr when it is a terminal ([`peer_note`]).
fn note_outcome(outcome: &HostOutcome, live: bool) {
    let stderr = std::io::stderr();
    let terminal = stderr.is_terminal();
    note_outcome_to(&mut stderr.lock(), terminal, outcome, live);
}

fn note_outcome_to(
    out: &mut dyn std::io::Write,
    terminal: bool,
    outcome: &HostOutcome,
    live: bool,
) {
    if let Some(line) = describe_outcome(outcome, live) {
        peer_note_to(out, terminal, format_args!("{line}"));
    }
}

/// One line for a handshake that ended without a live session (the sink
/// already reported the ones that had one). While a session is live
/// (`live`) this screen may be in its picture: the line names no other
/// device, neither its label nor its fingerprint (FX1-L1).
fn describe_outcome(outcome: &HostOutcome, live: bool) -> Option<String> {
    Some(match outcome {
        HostOutcome::PairRejected { reason, .. } if live => format!(
            "a pairing request was refused: {}",
            pair_reject::name(*reason).to_ascii_lowercase()
        ),
        HostOutcome::PairedOnly { .. } if live => {
            "a device paired; it asked for no session".to_owned()
        }
        HostOutcome::SessionRejected { reason, .. } if live => format!(
            "a session request was refused: {}",
            reject::name(*reason).to_ascii_lowercase()
        ),
        HostOutcome::Admin { ok, .. } if live => format!(
            "a remote admin command was {}",
            if *ok { "executed" } else { "refused" }
        ),
        HostOutcome::PairRejected { device, reason } => format!(
            "pairing refused for device {} ({})",
            device.fingerprint(),
            pair_reject::name(*reason)
        ),
        HostOutcome::PairedOnly { label, .. } => {
            format!("paired with \"{label}\"; it asked for no session")
        }
        HostOutcome::SessionRejected { label, reason, .. } => {
            format!(
                "session refused for \"{label}\" ({})",
                reject::name(*reason)
            )
        }
        HostOutcome::Admin { device, ok } => format!(
            "remote admin command from device {} {}",
            device.fingerprint(),
            if *ok { "executed" } else { "refused" }
        ),
        HostOutcome::Session { .. } => return None,
        _ => "handshake finished".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::duplex;
    use tornect_core::DeviceIdentity;
    use tornect_core::id::DeviceId;
    use tornect_core::unattended::guard::RemoteSessionActivity;
    use tornect_core::unattended::ipc::{IpcOp, IpcRequest, codes as codes_ipc};
    use tornect_signal::HostSigner;
    use tornect_signal::consent::TransportPolicy;
    use tornect_signal::fsm::client::{
        ClientConfig, ClientDeps, ClientOutcome, Intent, ScriptedClientUi, connect,
    };
    use tornect_signal::pairing::{
        KnownHostStore, PairDecision, PairScript, ScriptedConsent, SessionDecision, SessionScript,
    };

    use super::*;

    /// The monitors design §2: the host's `SHARING VIEW` line names the
    /// session and the screen its pictures show by number, `all` for every
    /// screen at once, out of how many; nothing else about the monitors.
    #[test]
    fn the_view_line_says_the_screen_shown_by_number() {
        let mut changed = CaptureChanged {
            session_id: "4f1c9a",
            shown: Some(tornect_input::Rect::new(1280, 0, 1024, 768)),
            all: false,
            screen: 2,
            of: 3,
            input: true,
        };
        assert_eq!(view_line(&changed), "SHARING VIEW 4f1c9a screen=2 of=3");
        changed.all = true;
        changed.screen = tornect_proto::ALL_MONITORS;
        changed.shown = Some(tornect_input::Rect::new(0, 0, 3328, 768));
        assert_eq!(view_line(&changed), "SHARING VIEW 4f1c9a screen=all of=3");
        changed.input = false;
        assert_eq!(view_line(&changed), "SHARING VIEW 4f1c9a screen=all of=3");
    }

    /// The quality design §3.5: the host's stop line (the terminal's and the
    /// window's) ends with the stream's stage means, in §3.3's format: one
    /// decimal under 10 ms, whole milliseconds under a second, then seconds;
    /// a mean with nothing to average is left out.
    #[test]
    fn the_stop_line_says_the_stage_means() {
        let report = MediaReport {
            frames_sent: 10,
            acks: 4,
            encode_us: 98_000,
            scale_us: 21_000,
            convert_us: 15_000,
            send_us: 1_200_000,
            ack_us: 4_400_000,
            quality_changes: 2,
            ..MediaReport::default()
        };
        assert_eq!(
            stage_means(&report),
            "encode 9.8 ms, scale 2.1 ms, convert 1.5 ms, send 120 ms, round trip 1.1 s, \
             quality changes 2"
        );
        assert_eq!(
            stage_means(&MediaReport::default()),
            "quality changes 0",
            "no picture, no ack"
        );
        let unacked = MediaReport {
            frames_sent: 1,
            encode_us: 12_345,
            ..MediaReport::default()
        };
        assert_eq!(
            stage_means(&unacked),
            "encode 12 ms, scale 0.0 ms, convert 0.0 ms, send 0.0 ms, quality changes 0"
        );
        for (us, text) in [
            (0, "0.0 ms"),
            (9_949, "9.9 ms"),
            (9_950, "10 ms"),
            (120_000, "120 ms"),
            (999_499, "999 ms"),
            (999_500, "1.0 s"),
            (1_100_000, "1.1 s"),
            (u64::MAX, "18446744073709.5 s"),
        ] {
            assert_eq!(duration_text(us), text, "{us} µs");
        }
    }

    struct Env {
        _tmp: tempfile::TempDir,
        paths: Paths,
        identity: Arc<HostIdentity>,
    }

    fn env() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        Env {
            _tmp: tmp,
            paths,
            identity: Arc::new(HostIdentity::from_seed(&[0x11; 32])),
        }
    }

    fn media() -> Arc<MediaHost> {
        Arc::new(MediaHost::new(
            Arc::new(tornect_session::SystemBackend::new(
                tornect_session::Source::TestCard,
            )),
            Arc::new(tornect_session::NoObserver),
            tornect_session::MediaLimits::default(),
        ))
    }

    fn client(env: &Env) -> (DeviceIdentity, ClientConfig, ClientDeps) {
        let known = Arc::new(
            KnownHostStore::open(env.paths.state_dir.join("client-known-hosts.toml")).unwrap(),
        );
        let mut deps = ClientDeps::headless(known);
        deps.ui = Arc::new(ScriptedClientUi::new(true));
        (
            DeviceIdentity::from_seed(&[0x22; 32]),
            ClientConfig::new(env.identity.id(), "Laptop"),
            deps,
        )
    }

    /// `[services] wayland_clipboard` off (the default): a host keeps and
    /// uses the desktop's grant file from before the switch, deletes nothing
    /// at its start, and its readiness row reads that file, so the portal
    /// request, the grant and the desktop's dialog are what they were.
    #[test]
    fn a_host_with_the_clipboard_switch_off_keeps_the_grant_it_had() {
        let env = env();
        let cfg = Config::default();
        assert!(!cfg.services.wayland_clipboard, "off by default");
        let today = env.paths.portal_restore_token();
        assert_eq!(portal_token(&env.paths, &cfg), today);
        std::fs::write(&today, "a grant from before the switch").unwrap();
        // A clipboard grant made while the switch was on is not this
        // request's either, and is left to the switch's next turn.
        let with = env.paths.portal_restore_token_for(true);
        std::fs::write(&with, "a grant with the clipboard").unwrap();
        let wiring = wire(
            &env.paths,
            &cfg,
            Arc::clone(&env.identity),
            DirectWiring::for_test(9),
            Arc::new(ScriptedConsent::new()),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        assert!(
            today.exists(),
            "the grant from before the switch was deleted"
        );
        assert!(with.exists());
        assert!(!PORTAL_CLIPBOARD.load(Ordering::SeqCst));
        drop(wiring);
    }

    /// The final review's revoke finding: revoking deletes the grant of both
    /// portal requests, with the clipboard switch off or on, so that a grant
    /// made while the switch was on is not restored when it is turned on
    /// again; a file already gone is no error.
    #[test]
    fn revoking_deletes_the_grant_of_either_request() {
        for switch in [false, true] {
            let env = env();
            let mut cfg = Config::default();
            cfg.services.wayland_clipboard = switch;
            std::fs::create_dir_all(&env.paths.state_dir).unwrap();
            let [without, with] = env.paths.portal_restore_tokens();
            std::fs::write(&without, "a grant without the clipboard").unwrap();
            std::fs::write(&with, "a grant with the clipboard").unwrap();
            assert!(portal_token(&env.paths, &cfg).exists());
            revoke_portal_grants(&env.paths).unwrap();
            assert!(!without.exists(), "switch {switch}");
            assert!(!with.exists(), "switch {switch}");
            revoke_portal_grants(&env.paths).unwrap();
        }
    }

    /// The FSM audits into the host's `sessions.log`, and a host whose store
    /// opened offers the unattended suite.
    #[test]
    fn the_fsm_audits_into_the_hosts_log() {
        let env = env();
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(9),
            Arc::new(ScriptedConsent::new()),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        let ctx = wiring
            .ctx
            .as_ref()
            .expect("the store opens in a fresh home");
        assert_eq!(wiring.audit.log().path(), ctx.log.path());
        assert!(wiring.deps.kill.fired().is_none());
        assert_eq!(
            wiring.cfg.feats,
            vec![
                messages::feats::UA1.to_owned(),
                messages::feats::SVC1.to_owned(),
                messages::feats::DIR1.to_owned()
            ],
            "a host with a store offers the unattended suite, the services stream and the \
             direct path"
        );
    }

    /// Slice-F F2-1 (§B.6): a host with no terminal (the systemd user unit of
    /// `tornect service install`) has nothing to show a session on, so it does
    /// not offer the unattended suite. Its control channel keeps the store, so
    /// `tornect panic`, `unattended off` and `service uninstall` still reach it.
    /// A host with a terminal still offers the suite.
    #[test]
    fn a_host_with_no_terminal_offers_no_unattended_suite() {
        let env = env();
        let headless = wire_cli(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(9),
            None,
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        assert!(
            headless.cfg.feats.is_empty(),
            "a host with no terminal offers {:?}",
            headless.cfg.feats
        );
        let ctx = headless
            .ctx
            .as_ref()
            .expect("the control channel keeps its store");
        assert!(ctx.kill.is_some(), "`tornect panic` still ends sessions");
        drop(headless);

        let (prompter, _typed) = Prompter::scripted();
        let terminal = wire_cli(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(9),
            Some(prompter),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        assert_eq!(
            terminal.cfg.feats,
            vec![
                messages::feats::UA1.to_owned(),
                messages::feats::SVC1.to_owned(),
                messages::feats::DIR1.to_owned()
            ]
        );
    }

    /// Design `direct` §8.6 (step A18): the host signs its accepts with the
    /// caller's own knob, so the bridge state each Tor bootstrap sets
    /// (decision M1-86) reaches the next accept, attended or unattended,
    /// and the device key it offers is the wiring's.
    #[test]
    fn the_host_signs_with_the_knob_its_caller_bootstraps() {
        use tornect_signal::consent::TransportPolicy;
        use tornect_signal::tor::Rung;

        let env = env();
        let direct = DirectWiring::for_test(0x33);
        let cfg = Config::default();
        let wiring = wire(
            &env.paths,
            &cfg,
            Arc::clone(&env.identity),
            direct.clone(),
            Arc::new(ScriptedConsent::new()),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        assert_eq!(wiring.cfg.host_device_pk, direct.device_pk());
        assert_eq!(wiring.cfg.transport.get(), TransportPolicy::Any);
        direct.knobs.bootstrapped(Rung::Obfs4, &cfg.tor);
        assert_eq!(wiring.cfg.transport.get(), TransportPolicy::TorOnly);
        assert!(wiring.cfg.transport.off_by_bridge());
        assert!(
            wiring.cfg.transport.host_transport().paranoid,
            "the unattended path reads the same knob"
        );
        direct.knobs.bootstrapped(Rung::Direct, &cfg.tor);
        assert_eq!(wiring.cfg.transport.get(), TransportPolicy::Any);
    }

    /// FR2R-L1 (P-L4, the host's file): the host's start writes
    /// `trusted-devices.toml` back with a pairing time past its first day
    /// kept to the day (and a last-seen time that still was that second),
    /// with no pairing and history off; a pairing within its first day keeps
    /// its second. A file with nothing to keep to the day is not rewritten,
    /// and a home with no file gets none.
    #[test]
    fn the_hosts_start_keeps_the_pairing_time_to_the_day_on_disk() {
        use tornect_core::trusted::{TrustedDevices, unix_now};

        let start = |env: &Env| {
            drop(
                wire(
                    &env.paths,
                    &Config::default(),
                    Arc::clone(&env.identity),
                    DirectWiring::for_test(9),
                    Arc::new(ScriptedConsent::new()),
                    media(),
                    ControlChannel::default(),
                )
                .unwrap(),
            );
        };
        let fresh = env();
        start(&fresh);
        assert!(
            !fresh.paths.trusted_devices_file().exists(),
            "no file: none written"
        );

        let env = env();
        tornect_core::address_book::Store::new(&env.paths)
            .set_history(false)
            .unwrap();
        let file = env.paths.trusted_devices_file();
        let dev = |b: u8| DeviceId::from_bytes([b; 32]);
        let now = unix_now();
        let day = now - now % 86_400 - 2 * 86_400;
        let (old, recent) = (day + 41_234, now - 60);
        let mut devices = TrustedDevices::default();
        devices.pin(dev(1), "Laptop", old);
        devices.pin(dev(2), "Tablet", recent);
        devices.save(&file).unwrap();

        start(&env);
        let kept = TrustedDevices::load(&file).unwrap();
        let laptop = kept.get(&dev(1)).unwrap();
        assert_eq!((laptop.paired_at, laptop.last_seen), (day, day));
        let tablet = kept.get(&dev(2)).unwrap();
        assert_eq!(
            (tablet.paired_at, tablet.last_seen),
            (recent, recent),
            "its first day: the second"
        );
        assert!(
            !std::fs::read_to_string(&file)
                .unwrap()
                .contains(&old.to_string())
        );

        let long_ago = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        let bytes = std::fs::read(&file).unwrap();
        start(&env);
        assert_eq!(std::fs::read(&file).unwrap(), bytes, "nothing to keep");
        assert_eq!(
            std::fs::metadata(&file).unwrap().modified().unwrap(),
            long_ago,
            "not rewritten"
        );
    }

    /// Give `device` an unattended grant with `password` in `env`'s store, the
    /// way the CLI does after re-authentication, and turn unattended access on.
    /// Returns the emergency stop code.
    fn grant_unattended(env: &Env, device: &DeviceId, password: &str) -> [u8; 16] {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::clock::SystemClock;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{
            AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
        };
        use tornect_core::unattended::ipc::GrantOptions;
        use tornect_core::unattended::store::GrantStore;

        let host_onion_pk = *env.identity.id().public_key_bytes();
        let secrets = Arc::new(FileSecretStore::open(env.paths.keys_dir()).unwrap());
        let store = GrantStore::open(
            &env.paths,
            secrets,
            Arc::new(SystemClock::default()),
            SessionLog::new(env.paths.sessions_log()),
        )
        .unwrap();
        let guard = MutationGuard::new(
            store,
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::new(tornect_core::levels::FixedFacts::linux()),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(
            tornect_signal::unattended::OpaqueServerSetupSource,
        ));
        let on = guard.master_on(Actor::Cli, &host_onion_pk).unwrap();
        guard
            .create_grant(
                Actor::Cli,
                device,
                Preset::HeadlessBox,
                &GrantOptions::default(),
                &[0u8; 192],
                false,
            )
            .unwrap();
        let setup =
            tornect_signal::auth::parse_server_setup(&guard.store().server_setup().unwrap())
                .unwrap();
        let record = tornect_signal::auth::register_locally(
            &setup,
            password,
            device.public_key_bytes(),
            tornect_signal::auth::identifiers(device.public_key_bytes(), &host_onion_pk),
        )
        .unwrap();
        guard
            .set_password(Actor::Cli, device, &record, &GrantOptions::default(), false)
            .unwrap();
        *on.stop_code
    }

    /// §B.8.9.1: an unattended connect with "Remember on this device" keeps the
    /// password in the keychain only (here a test keychain, under the derived
    /// name): no file under the home holds it, nor the entry's name; hosts.toml
    /// has the pin and the flag, and the client's log line names the pinned host.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_password_remembered_after_an_unattended_connect_is_in_no_file() {
        use tornect_core::unattended::credentials::{MemoryVault, SavedPasswords};
        use tornect_signal::fsm::client::ServerKeyPin as _;

        const PASSWORD: &str = "quiet verdant otter lantern zephyr";
        let env = env();
        let host_device_pk = HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32]));
        let (identity, ccfg, mut cdeps) = client(&env);
        let device = identity.id();
        TrustedDeviceStore::open(env.paths.trusted_devices_file())
            .unwrap()
            .pin(device, "Laptop")
            .unwrap();
        cdeps
            .known_hosts
            .pin(env.identity.id(), "Desk", host_device_pk)
            .unwrap();
        grant_unattended(&env, &device, PASSWORD);
        let pin = Arc::new(crate::ua_client::HostsPin::new(&env.paths));
        cdeps.server_key_pin = pin.clone();
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(0x33),
            Arc::new(ScriptedConsent::new()),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        let vault = Arc::new(MemoryVault::new());
        let saved = SavedPasswords::new(Some(vault.clone()), *device.public_key_bytes());
        let request = crate::ua_client::Request {
            password: zeroize::Zeroizing::new(PASSWORD.to_owned()),
            view_only: false,
            administrator: false,
            remember: true,
        };
        let (client_end, host_end) = duplex(64 * 1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        let session = match connect(client_end, &ccfg, &identity, &cdeps, request.intent()).await {
            Ok(ClientOutcome::Session(session)) => session,
            other => panic!("the window host refused its grant: {other:?}"),
        };
        let host = env.identity.id();
        let remembered = crate::ua_client::settle(
            &env.paths,
            &saved,
            &host,
            crate::ua_client::accepted(session.accept()),
            &request,
        )
        .unwrap()
        .remembered;
        assert!(remembered);
        let known = cdeps.known_hosts.get(&host).unwrap();
        crate::ua_client::log_attempt(
            &env.paths,
            &known,
            &crate::ua_client::Logged::Session {
                id: &session.session_token().session_id(),
                control: true,
                administrator: false,
            },
        );
        drop(session);
        assert_eq!(host_task.await.unwrap(), Served::Session);

        let record = crate::ua_client::record(&env.paths, &host);
        assert!(record.remember && record.ua_worked_before && !record.stale);
        let pinned = record.server_s_pk_pin.expect("pinned at the accept");
        assert_eq!(
            pin.check(&host, &pinned),
            tornect_core::unattended::hosts::PinCheck::Match
        );
        let entry = saved.entry(&host);
        assert_eq!(vault.names(), vec![entry.as_str().to_owned()]);
        assert_eq!(
            crate::ua_client::recall(&env.paths, &saved, &host)
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some(PASSWORD)
        );
        // Nothing under the home holds the password (UTF-8 or UTF-16) or the
        // entry's name.
        let utf16: Vec<u8> = PASSWORD.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let needles = [
            PASSWORD.as_bytes().to_vec(),
            utf16,
            entry.as_str().as_bytes().to_vec(),
        ];
        let mut files = 0;
        let mut dirs = vec![env._tmp.path().to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for item in std::fs::read_dir(&dir).unwrap() {
                let path = item.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                let bytes = std::fs::read(&path).unwrap();
                files += 1;
                for needle in &needles {
                    assert!(
                        !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                        "{} holds a secret",
                        path.display()
                    );
                }
            }
        }
        assert!(
            files >= 4,
            "hosts.toml, the pins, the log and the store were read"
        );
        let log = std::fs::read_to_string(env.paths.sessions_log()).unwrap();
        let line = log
            .lines()
            .find(|l| l.contains(r#""event":"unattended_connect""#))
            .expect("the client's line");
        assert!(line.contains(r#""peer_name":"Desk""#), "{line}");
        assert!(line.contains(r#""reason":"accepted""#), "{line}");
        assert!(!line.contains(&host.onion_address()), "{line}");
    }

    /// [`grant_unattended`] with `options` (a block window, say).
    fn grant_unattended_with(
        env: &Env,
        device: &DeviceId,
        password: &str,
        options: tornect_core::unattended::ipc::GrantOptions,
    ) {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::clock::SystemClock;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{
            AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
        };
        use tornect_core::unattended::ipc::GrantOptions;
        use tornect_core::unattended::store::GrantStore;

        let host_onion_pk = *env.identity.id().public_key_bytes();
        let secrets = Arc::new(FileSecretStore::open(env.paths.keys_dir()).unwrap());
        let store = GrantStore::open(
            &env.paths,
            secrets,
            Arc::new(SystemClock::default()),
            SessionLog::new(env.paths.sessions_log()),
        )
        .unwrap();
        let guard = MutationGuard::new(
            store,
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::new(tornect_core::levels::FixedFacts::linux()),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(
            tornect_signal::unattended::OpaqueServerSetupSource,
        ));
        guard.master_on(Actor::Cli, &host_onion_pk).unwrap();
        guard
            .create_grant(
                Actor::Cli,
                device,
                Preset::HeadlessBox,
                &options,
                &[0u8; 192],
                false,
            )
            .unwrap();
        let setup =
            tornect_signal::auth::parse_server_setup(&guard.store().server_setup().unwrap())
                .unwrap();
        let record = tornect_signal::auth::register_locally(
            &setup,
            password,
            device.public_key_bytes(),
            tornect_signal::auth::identifiers(device.public_key_bytes(), &host_onion_pk),
        )
        .unwrap();
        guard
            .set_password(Actor::Cli, device, &record, &GrantOptions::default(), false)
            .unwrap();
    }

    /// Decision M1-68 (§B.8.6.3): the terminal host's block window is the
    /// terminal's, with Block: `block` typed there blocks. The host with no
    /// terminal keeps the headless seams (a timer nobody can block) and
    /// answers pings only.
    #[tokio::test(start_paused = true)]
    async fn the_terminal_host_uses_the_terminal_block_window() {
        use tornect_signal::consent::{BlockOutcome, WindowPassed};

        let env = env();
        let (prompter, typed) = Prompter::scripted();
        let terminal = wire_cli(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(9),
            Some(Arc::clone(&prompter)),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        let window = Arc::clone(&terminal.deps.block_window);
        let running = tokio::spawn(async move { window.run(10, &[1; 8], "Laptop").await });
        while !prompter.block_window_open() {
            tokio::task::yield_now().await;
        }
        typed.send("block".to_owned()).await.unwrap();
        assert_eq!(running.await.unwrap(), BlockOutcome::Blocked);
        drop(terminal);

        let headless = wire_cli(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(9),
            None,
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        assert!(headless.cfg.feats.is_empty(), "pings only");
        assert_eq!(
            headless.deps.block_window.run(1, &[1; 8], "Laptop").await,
            BlockOutcome::Passed(WindowPassed::Elapsed),
            "a timer nobody can block"
        );
    }

    /// R-A (§B.8.6.3, PLAN:1977 and 2207): `block` typed on the terminal host's
    /// terminal during the block window refuses the request
    /// `BLOCKED_BY_LOCAL_USER` and suspends the grant (`LocalBlock`) before
    /// `SESSION_ACCEPT`: no session starts, so nothing reaches the media layer
    /// (the FSM's `block_means_no_capture`, through the real terminal host).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn terminal_block_means_no_capture() {
        use std::sync::atomic::AtomicUsize;
        use tornect_core::unattended::grant::{GrantState, SuspendReason};
        use tornect_signal::fsm::HandshakeError;

        /// Counts the sessions that start: a capture starts only there.
        struct Starts {
            inner: Arc<dyn SessionSink>,
            started: AtomicUsize,
        }

        impl SessionSink for Starts {
            fn on_start(&self, session: &LiveSession<'_>) {
                self.started.fetch_add(1, Ordering::SeqCst);
                self.inner.on_start(session);
            }

            fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
                self.inner.on_end(session_id, end);
            }
        }

        const PASSWORD: &str = "quiet verdant otter lantern zephyr";
        let env = env();
        let host_device_pk = HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32]));
        let (identity, ccfg, cdeps) = client(&env);
        let device = identity.id();
        TrustedDeviceStore::open(env.paths.trusted_devices_file())
            .unwrap()
            .pin(device, "Laptop")
            .unwrap();
        cdeps
            .known_hosts
            .pin(env.identity.id(), "Desk", host_device_pk)
            .unwrap();
        grant_unattended_with(
            &env,
            &device,
            PASSWORD,
            tornect_core::unattended::ipc::GrantOptions {
                block_window_s: Some(10),
                ..tornect_core::unattended::ipc::GrantOptions::default()
            },
        );
        let (prompter, typed) = Prompter::scripted();
        let mut wiring = wire_cli(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(0x33),
            Some(Arc::clone(&prompter)),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        let starts = Arc::new(Starts {
            inner: Arc::clone(&wiring.deps.sessions),
            started: AtomicUsize::new(0),
        });
        wiring.deps.sessions = starts.clone();
        let request = crate::ua_client::Request {
            password: zeroize::Zeroizing::new(PASSWORD.to_owned()),
            view_only: false,
            administrator: false,
            remember: false,
        };
        let (client_end, host_end) = duplex(64 * 1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        let client_task = tokio::spawn(async move {
            connect(client_end, &ccfg, &identity, &cdeps, request.intent()).await
        });
        // The block line is up once the window holds the terminal.
        let up = tokio::time::timeout(Duration::from_secs(60), async {
            while !prompter.block_window_open() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(up.is_ok(), "the block window never opened");
        assert_eq!(starts.started.load(Ordering::SeqCst), 0);
        typed.send("block".to_owned()).await.unwrap();
        let err = client_task.await.unwrap().expect_err("blocked");
        assert!(
            matches!(&err, HandshakeError::SessionRejected { reject } if reject.reason == reject::BLOCKED_BY_LOCAL_USER),
            "{err}"
        );
        assert_eq!(host_task.await.unwrap(), Served::Handshake);
        assert_eq!(
            starts.started.load(Ordering::SeqCst),
            0,
            "no session started, so nothing was captured"
        );
        assert_eq!(wiring.live.count(), 0);
        let state = wiring
            .ctx
            .as_ref()
            .unwrap()
            .guard
            .store()
            .grant(&device)
            .unwrap()
            .state;
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
    }

    /// Change `device`'s grant as stored in `paths`' store, keeping its generation (so the
    /// anchor still matches): the level or the mark, which no guard path of this build
    /// sets yet. Only while no `GrantStore` holds the store.
    fn edit_grant_on_disk(
        paths: &Paths,
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

    /// M1-67 A20 through a real host: the window host on a Windows administrator
    /// account's facts (UAC on, no helper task), a client with Remember ticked and an
    /// entry planted for the host. The grant at the administrator level and not marked:
    /// every answer the host signs says 2 (the level not asked, view only, the level asked
    /// with no helper to give it), and the window's and the command line's own path after
    /// a session started (`ua_client::after_accept`), fed that verified frame, keeps
    /// nothing and has deleted the planted entry. A grant at none on a host without admin
    /// grants: every answer says 0, and the typed password is kept in place of the planted
    /// one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a20_real_host_frame_decides_the_keep() {
        use tornect_core::levels::{AccountFacts, Elevation, FixedFacts, HelperPresence};
        use tornect_core::unattended::credentials::{
            MemoryVault, PasswordVault as _, SavedPasswords,
        };

        const PASSWORD: &str = "quiet verdant otter lantern zephyr";
        let windows = AccountFacts::Windows(tornect_core::levels::WindowsFacts {
            installed: true,
            administrator: true,
            ..tornect_core::levels::WindowsFacts::default()
        });
        for at_the_level in [true, false] {
            let env = env();
            let host_device_pk = HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32]));
            let (identity, ccfg, mut cdeps) = client(&env);
            let device = identity.id();
            TrustedDeviceStore::open(env.paths.trusted_devices_file())
                .unwrap()
                .pin(device, "Laptop")
                .unwrap();
            cdeps
                .known_hosts
                .pin(env.identity.id(), "Desk", host_device_pk)
                .unwrap();
            grant_unattended(&env, &device, PASSWORD);
            if at_the_level {
                edit_grant_on_disk(&env.paths, &device, |g| {
                    g.elevation = Elevation::Admin;
                    g.unmarked = true;
                });
            }
            cdeps.server_key_pin = Arc::new(crate::ua_client::HostsPin::new(&env.paths));
            let mut wiring = wire(
                &env.paths,
                &Config::default(),
                Arc::clone(&env.identity),
                DirectWiring::for_test(0x33),
                Arc::new(ScriptedConsent::new()),
                media(),
                ControlChannel::default(),
            )
            .unwrap();
            let store = wiring.ctx.as_ref().unwrap().guard.store().clone();
            wiring.deps.unattended = Arc::new(UnattendedAuth::new(
                AttemptLimiter::new(store),
                Arc::new(FixedOffset::utc()),
                HostTransport::default(),
                Arc::new(FixedFacts::new(windows, HelperPresence::Absent)),
            ));
            let vault = Arc::new(MemoryVault::new());
            let saved = SavedPasswords::new(Some(vault.clone()), *device.public_key_bytes());
            let host = env.identity.id();
            vault.put(&saved.entry(&host), "planted").unwrap();
            for (case, view_only, administrator) in [
                ("the level not asked", false, false),
                ("view only", true, false),
                ("the level asked", false, true),
            ] {
                let case = format!("{case}, at the level: {at_the_level}");
                let request = crate::ua_client::Request {
                    password: zeroize::Zeroizing::new(PASSWORD.to_owned()),
                    view_only,
                    administrator,
                    remember: true,
                };
                let (client_end, host_end) = duplex(64 * 1024);
                let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
                let host_task =
                    tokio::spawn(
                        async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await },
                    );
                let session =
                    match connect(client_end, &ccfg, &identity, &cdeps, request.intent()).await {
                        Ok(ClientOutcome::Session(session)) => session,
                        other => panic!("{case}: {other:?}"),
                    };
                let signed = session.accept().grant_reach();
                let settled = crate::ua_client::after_accept(
                    &env.paths,
                    &saved,
                    &host,
                    session.accept(),
                    &request,
                    "\"Desk\"",
                    session.elevation_withheld(),
                )
                .settled
                .unwrap();
                drop(session);
                let _ = host_task.await;
                if at_the_level {
                    assert_eq!(signed, Some(2), "{case}");
                    assert!(!settled.remembered, "{case}");
                    assert!(vault.names().is_empty(), "{case}: {:?}", vault.names());
                } else {
                    assert_eq!(signed, Some(0), "{case}");
                    assert!(settled.remembered, "{case}");
                    assert_eq!(vault.names(), vec![saved.entry(&host).as_str().to_owned()]);
                    assert_eq!(
                        crate::ua_client::recall(&env.paths, &saved, &host)
                            .unwrap()
                            .as_deref()
                            .map(String::as_str),
                        Some(PASSWORD),
                        "{case}"
                    );
                }
            }
        }
    }

    /// M1-67 (the approved test list: "the no password in any file test, re-run with an
    /// admin-capable grant"): the window host on a Windows administrator account's facts,
    /// the grant at the administrator level and not marked, a client with Remember ticked.
    /// The answer says 2, the settle fed from it keeps nothing, and no file under the home
    /// holds the password (UTF-8 or UTF-16) or the entry's name.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_password_typed_for_an_admin_capable_grant_is_in_no_file() {
        use tornect_core::levels::{AccountFacts, Elevation, FixedFacts, HelperPresence};
        use tornect_core::unattended::credentials::{MemoryVault, SavedPasswords};

        const PASSWORD: &str = "quiet verdant otter lantern zephyr";
        let env = env();
        let host_device_pk = HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32]));
        let (identity, ccfg, mut cdeps) = client(&env);
        let device = identity.id();
        TrustedDeviceStore::open(env.paths.trusted_devices_file())
            .unwrap()
            .pin(device, "Laptop")
            .unwrap();
        cdeps
            .known_hosts
            .pin(env.identity.id(), "Desk", host_device_pk)
            .unwrap();
        grant_unattended(&env, &device, PASSWORD);
        edit_grant_on_disk(&env.paths, &device, |g| {
            g.elevation = Elevation::Admin;
            g.unmarked = true;
        });
        cdeps.server_key_pin = Arc::new(crate::ua_client::HostsPin::new(&env.paths));
        let mut wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(0x33),
            Arc::new(ScriptedConsent::new()),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        let store = wiring.ctx.as_ref().unwrap().guard.store().clone();
        let windows = AccountFacts::Windows(tornect_core::levels::WindowsFacts {
            installed: true,
            administrator: true,
            ..tornect_core::levels::WindowsFacts::default()
        });
        wiring.deps.unattended = Arc::new(UnattendedAuth::new(
            AttemptLimiter::new(store),
            Arc::new(FixedOffset::utc()),
            HostTransport::default(),
            Arc::new(FixedFacts::new(windows, HelperPresence::Absent)),
        ));
        let vault = Arc::new(MemoryVault::new());
        let saved = SavedPasswords::new(Some(vault.clone()), *device.public_key_bytes());
        let request = crate::ua_client::Request {
            password: zeroize::Zeroizing::new(PASSWORD.to_owned()),
            view_only: false,
            administrator: false,
            remember: true,
        };
        let (client_end, host_end) = duplex(64 * 1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        let session = match connect(client_end, &ccfg, &identity, &cdeps, request.intent()).await {
            Ok(ClientOutcome::Session(session)) => session,
            other => panic!("the window host refused its grant: {other:?}"),
        };
        assert_eq!(session.accept().grant_reach(), Some(2));
        let host = env.identity.id();
        let settled = crate::ua_client::settle(
            &env.paths,
            &saved,
            &host,
            crate::ua_client::accepted(session.accept()),
            &request,
        )
        .unwrap();
        assert!(!settled.remembered);
        drop(session);
        let _ = host_task.await;
        assert!(vault.names().is_empty());
        let entry = saved.entry(&host);
        let utf16: Vec<u8> = PASSWORD.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let needles = [
            PASSWORD.as_bytes().to_vec(),
            utf16,
            entry.as_str().as_bytes().to_vec(),
        ];
        let mut files = 0;
        let mut dirs = vec![env._tmp.path().to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for item in std::fs::read_dir(&dir).unwrap() {
                let path = item.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                let bytes = std::fs::read(&path).unwrap();
                files += 1;
                for needle in &needles {
                    assert!(
                        !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                        "{} holds a secret",
                        path.display()
                    );
                }
            }
        }
        assert!(
            files >= 4,
            "hosts.toml, the pins, the log and the store were read"
        );
    }

    /// M1-67 A20 (d)(e) through a real host: the window host on a Windows administrator
    /// account's facts, wired with its guard, and a client that remembered the password.
    /// The grant at the level and not marked: a command run (`end_session`) and one the
    /// guard refuses (`master_off`, out of a Headless box grant's scope) are both answered
    /// 2, and the window's and the command line's own path after an admin answer
    /// (`ua_client::after_admin`), fed the verified answer, deletes the remembered password
    /// at the first answer and writes none. A grant at none on a host without admin
    /// grants: both answered 0, and the remembered password stays in place.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a20_d_e_real_admin_answers_decide_the_keep() {
        use tornect_core::levels::{AccountFacts, Elevation, FixedFacts, HelperPresence};
        use tornect_core::unattended::credentials::{
            MemoryVault, PasswordVault as _, SavedPasswords,
        };
        use tornect_signal::fsm::client::{AdminIntent, admin};

        const PASSWORD: &str = "quiet verdant otter lantern zephyr";
        let windows = AccountFacts::Windows(tornect_core::levels::WindowsFacts {
            installed: true,
            administrator: true,
            ..tornect_core::levels::WindowsFacts::default()
        });
        for at_the_level in [true, false] {
            let env = env();
            let host_device_pk = HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32]));
            let (identity, ccfg, mut cdeps) = client(&env);
            let device = identity.id();
            TrustedDeviceStore::open(env.paths.trusted_devices_file())
                .unwrap()
                .pin(device, "Laptop")
                .unwrap();
            cdeps
                .known_hosts
                .pin(env.identity.id(), "Desk", host_device_pk)
                .unwrap();
            grant_unattended(&env, &device, PASSWORD);
            if at_the_level {
                edit_grant_on_disk(&env.paths, &device, |g| {
                    g.elevation = Elevation::Admin;
                    g.unmarked = true;
                });
            }
            cdeps.server_key_pin = Arc::new(crate::ua_client::HostsPin::new(&env.paths));
            let mut wiring = wire(
                &env.paths,
                &Config::default(),
                Arc::clone(&env.identity),
                DirectWiring::for_test(0x33),
                Arc::new(ScriptedConsent::new()),
                media(),
                ControlChannel::default(),
            )
            .unwrap();
            let guard = Arc::clone(&wiring.ctx.as_ref().unwrap().guard);
            let windows_guard = Arc::new(
                tornect_core::unattended::guard::MutationGuard::new(
                    guard.store().clone(),
                    Arc::new(tornect_core::unattended::guard::AllowAllReAuth::default()),
                    Arc::new(tornect_core::unattended::guard::NoSessionActivity),
                    Arc::new(FixedFacts::new(windows, HelperPresence::Absent)),
                )
                .with_paired_devices(Arc::new(tornect_core::unattended::guard::AllowAllPaired)),
            );
            wiring.deps.unattended = Arc::new(
                UnattendedAuth::new(
                    AttemptLimiter::new(guard.store().clone()),
                    Arc::new(FixedOffset::utc()),
                    HostTransport::default(),
                    Arc::new(FixedFacts::new(windows, HelperPresence::Absent)),
                )
                .with_admin_authority(Arc::new(GuardAdmin::new(windows_guard))),
            );
            let vault = Arc::new(MemoryVault::new());
            let saved = SavedPasswords::new(Some(vault.clone()), *device.public_key_bytes());
            let host = env.identity.id();
            vault.put(&saved.entry(&host), PASSWORD).unwrap();
            for (op, ok) in [
                (messages::admin_op::END_SESSION, true),
                (messages::admin_op::MASTER_OFF, false),
            ] {
                let case = format!("op {op}, at the level: {at_the_level}");
                let (client_end, host_end) = duplex(64 * 1024);
                let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
                let host_task =
                    tokio::spawn(
                        async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await },
                    );
                let answer = admin(
                    client_end,
                    &ccfg,
                    &identity,
                    &cdeps,
                    &AdminIntent {
                        password: zeroize::Zeroizing::new(PASSWORD.to_owned()),
                        op,
                        device_pk: None,
                    },
                )
                .await
                .unwrap_or_else(|e| panic!("{case}: {e}"));
                let _ = host_task.await;
                assert_eq!(answer.ok, ok, "{case}");
                crate::ua_client::after_admin(&env.paths, &saved, &host, &answer, "\"Desk\"")
                    .unwrap();
                if at_the_level {
                    assert_eq!(answer.grant_reach, Some(2), "{case}");
                    assert!(vault.names().is_empty(), "{case}: deleted");
                } else {
                    assert_eq!(answer.grant_reach, Some(0), "{case}");
                    assert_eq!(
                        vault.names(),
                        vec![saved.entry(&host).as_str().to_owned()],
                        "{case}: left in place"
                    );
                }
            }
        }
    }

    /// Slice-F F2-1 (§B.6, decision M1-48 (8)): an unattended request to a host
    /// with no terminal is refused `NOT_GRANTED`, while the window host's
    /// wiring serves the same grant. The stop code, deny-direction, still
    /// works on the host with no terminal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_a_host_that_can_show_a_session_serves_an_unattended_one() {
        use tornect_core::unattended::guard::stop_token;
        use tornect_signal::fsm::HandshakeError;
        use tornect_signal::fsm::client::UnattendedIntent;

        const PASSWORD: &str = "quiet verdant otter lantern zephyr";
        let env = env();
        let host_device_pk = HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32]));
        let (identity, mut ccfg, cdeps) = client(&env);
        let device = identity.id();
        TrustedDeviceStore::open(env.paths.trusted_devices_file())
            .unwrap()
            .pin(device, "Laptop")
            .unwrap();
        cdeps
            .known_hosts
            .pin(env.identity.id(), "Desk", host_device_pk)
            .unwrap();
        let stop_code = grant_unattended(&env, &device, PASSWORD);
        let unattended = || {
            Intent::Unattended(UnattendedIntent {
                password: zeroize::Zeroizing::new(PASSWORD.to_owned()),
                want_mode: messages::mode::CONTROL,
                want_elevation: tornect_core::levels::Elevation::None,
            })
        };

        // The window host (the GUI's wiring) serves the grant.
        {
            let wiring = wire(
                &env.paths,
                &Config::default(),
                Arc::clone(&env.identity),
                DirectWiring::for_test(0x33),
                Arc::new(ScriptedConsent::new()),
                media(),
                ControlChannel::default(),
            )
            .unwrap();
            assert_eq!(
                wiring.cfg.feats,
                [
                    messages::feats::UA1,
                    messages::feats::SVC1,
                    messages::feats::DIR1
                ]
            );
            let (client_end, host_end) = duplex(64 * 1024);
            let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
            let host_task =
                tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
            match connect(client_end, &ccfg, &identity, &cdeps, unattended()).await {
                Ok(ClientOutcome::Session(session)) => drop(session),
                other => panic!("the window host refused its grant: {other:?}"),
            }
            assert_eq!(host_task.await.unwrap(), Served::Session);
        }

        // The host with no terminal refuses it, before any password exchange.
        let headless = wire_cli(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(0x33),
            None,
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        let serve = |host_end| {
            let (cfg, deps) = (headless.cfg.clone(), headless.deps.clone());
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await })
        };
        let (client_end, host_end) = duplex(64 * 1024);
        let host_task = serve(host_end);
        match connect(client_end, &ccfg, &identity, &cdeps, unattended()).await {
            Err(HandshakeError::SessionRejected { reject: why }) => {
                assert_eq!(why.reason, reject::NOT_GRANTED);
            }
            other => panic!("a host with no terminal answered {other:?}"),
        }
        assert_eq!(host_task.await.unwrap(), Served::Handshake);
        assert_eq!(headless.live.count(), 0);

        // The stop code still ends unattended access there.
        ccfg.stop_token = Some(stop_token(env.identity.id().public_key_bytes(), &stop_code));
        let (client_end, host_end) = duplex(64 * 1024);
        let host_task = serve(host_end);
        let _ = connect(client_end, &ccfg, &identity, &cdeps, Intent::PairOnly).await;
        let _ = host_task.await.unwrap();
        let store = headless.ctx.as_ref().unwrap().guard.store();
        assert!(store.grants().is_empty(), "the stop code revoked nothing");
    }

    /// A paired client with an unattended grant at a host in a fresh home,
    /// and the request it sends.
    struct UnattendedSetup {
        env: Env,
        identity: DeviceIdentity,
        ccfg: ClientConfig,
        cdeps: ClientDeps,
    }

    const SETUP_PASSWORD: &str = "quiet verdant otter lantern zephyr";

    fn unattended_setup() -> UnattendedSetup {
        let env = env();
        let host_device_pk = HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32]));
        let (identity, ccfg, cdeps) = client(&env);
        let device = identity.id();
        TrustedDeviceStore::open(env.paths.trusted_devices_file())
            .unwrap()
            .pin(device, "Laptop")
            .unwrap();
        cdeps
            .known_hosts
            .pin(env.identity.id(), "Desk", host_device_pk)
            .unwrap();
        grant_unattended(&env, &device, SETUP_PASSWORD);
        UnattendedSetup {
            env,
            identity,
            ccfg,
            cdeps,
        }
    }

    impl UnattendedSetup {
        /// The window host's wiring, in background mode when `background`.
        fn window(&self, background: Option<IndicatorShown>) -> HostWiring {
            wire_window(
                &self.env.paths,
                &Config::default(),
                Arc::clone(&self.env.identity),
                DirectWiring::for_test(0x33),
                Arc::new(ScriptedConsent::new()),
                media(),
                ControlChannel::default(),
                background,
            )
            .unwrap()
        }

        /// One unattended request to `wiring`: what the client got, and what
        /// the host served.
        async fn request(
            &self,
            wiring: &HostWiring,
        ) -> (
            Result<ClientOutcome<tokio::io::DuplexStream>, tornect_signal::fsm::HandshakeError>,
            Served,
        ) {
            use tornect_signal::fsm::client::UnattendedIntent;
            let (client_end, host_end) = duplex(64 * 1024);
            let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
            let host_task =
                tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
            let intent = Intent::Unattended(UnattendedIntent {
                password: zeroize::Zeroizing::new(SETUP_PASSWORD.to_owned()),
                want_mode: messages::mode::CONTROL,
                want_elevation: tornect_core::levels::Elevation::None,
            });
            let got = connect(client_end, &self.ccfg, &self.identity, &self.cdeps, intent).await;
            (got, host_task.await.unwrap())
        }
    }

    /// §B.1.1 (MUST, decision M1-58): a window host started in background
    /// mode serves no unattended session until its readiness row "indicator
    /// shown" passes. The request is refused `HOST_NOT_READY` with no `cause`
    /// (a form the wire has), after the password, and no session starts.
    /// Shown failing first (the fact not yet a gate: the session was served).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_refuses_unattended_until_the_indicator_row_passes() {
        use tornect_core::unattended::readiness::Probe;
        use tornect_signal::fsm::HandshakeError;

        let setup = unattended_setup();
        let shown = IndicatorShown::default();
        let wiring = setup.window(Some(shown.clone()));
        assert_eq!(
            wiring.cfg.feats,
            [
                messages::feats::UA1,
                messages::feats::SVC1,
                messages::feats::DIR1
            ]
        );
        let ctx = wiring.ctx.as_ref().unwrap();
        let pending = Probe::Warn(tornect_platform::readiness::INDICATOR_NOT_SHOWN.to_owned());
        assert_eq!(ctx.readiness.get().consent_indicator, pending, "as probed");
        assert_eq!(shown.row(), pending);
        match setup.request(&wiring).await {
            (Err(HandshakeError::SessionRejected { reject: why }), served) => {
                assert_eq!(why.reason, reject::HOST_NOT_READY);
                assert_eq!(why.cause, None, "no cause: no new wire value");
                assert_eq!(served, Served::Handshake);
            }
            (other, _) => panic!("a background host before its indicator answered {other:?}"),
        }
        assert_eq!(wiring.live.count(), 0, "no session started");
        assert!(!shown.is_set());
    }

    /// §B.1.1: once the indicator's window was drawn, the same host serves
    /// the same grant, and its row passes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_serves_after_it_passes() {
        use tornect_core::unattended::readiness::Probe;
        use tornect_signal::fsm::HandshakeError;

        let setup = unattended_setup();
        let shown = IndicatorShown::default();
        let wiring = setup.window(Some(shown.clone()));
        match setup.request(&wiring).await {
            (Err(HandshakeError::SessionRejected { reject: why }), _) => {
                assert_eq!(why.reason, reject::HOST_NOT_READY);
            }
            (other, _) => panic!("served before the indicator was shown: {other:?}"),
        }
        shown.set();
        assert_eq!(shown.row(), Probe::Ok);
        match setup.request(&wiring).await {
            (Ok(ClientOutcome::Session(session)), served) => {
                drop(session);
                assert_eq!(served, Served::Session);
            }
            (other, _) => panic!("the background host refused after its indicator: {other:?}"),
        }
    }

    /// §B.1.1: the gates are those of the start at sign-in. A window started
    /// by hand runs no probe and is not gated: it serves the grant as before,
    /// and its context carries no indicator fact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_window_started_by_hand_is_not_gated() {
        let setup = unattended_setup();
        let wiring = setup.window(None);
        assert!(wiring.ctx.as_ref().unwrap().indicator.is_none());
        match setup.request(&wiring).await {
            (Ok(ClientOutcome::Session(session)), served) => {
                drop(session);
                assert_eq!(served, Served::Session);
            }
            (other, _) => panic!("a window started by hand refused its grant: {other:?}"),
        }
    }

    /// The whole reason for the wiring. `tornect panic` (IPC `Panic`) ends a
    /// live session: before, the IPC context had no kill switch, so `Panic`
    /// answered `G_PRECONDITION` and the session ran on. And the guard sees the
    /// session: `unattended on` is refused while it runs and for the cool-down
    /// after (§B.8.6.2), where before the guard was told no session ever runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ipc_panic_ends_a_live_session() {
        let env = env();
        let consent = Arc::new(ScriptedConsent::new());
        consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
        consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(0x33),
            consent,
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        let ctx = wiring.ctx.as_ref().unwrap();

        let (client_end, host_end) = duplex(64 * 1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        let (identity, ccfg, cdeps) = client(&env);
        let mut session = match connect(client_end, &ccfg, &identity, &cdeps, Intent::Session)
            .await
            .unwrap()
        {
            ClientOutcome::Session(s) => s,
            other => panic!("expected a session, got {other:?}"),
        };
        session.send_tor_fallback(None).await.unwrap();
        session.ping().await.unwrap();
        assert_eq!(wiring.live.count(), 1);
        assert!(
            RemoteSessionActivity::session_live(&*wiring.live),
            "the guard's activity source sees the session"
        );
        // Refused before any re-auth dialog could open.
        let on = |id| crate::unattended::dispatch(ctx, IpcRequest { id, op: IpcOp::On });
        let refused = on(2);
        assert!(!refused.ok);
        assert_eq!(
            refused.code,
            codes_ipc::G_REMOTE_SESSION_ACTIVE,
            "{refused:?}"
        );

        let resp = crate::unattended::dispatch(
            ctx,
            IpcRequest {
                id: 1,
                op: IpcOp::Panic,
            },
        );
        assert!(resp.ok, "{resp:?}");

        let event = session.next_event(Duration::from_secs(10)).await.unwrap();
        assert_eq!(
            event,
            Some(tornect_signal::fsm::client::SessionEvent::Bye {
                reason: bye::PANIC,
                detail: None
            })
        );
        assert_eq!(host_task.await.unwrap(), Served::Session);
        assert_eq!(wiring.live.count(), 0);
        assert!(wiring.live.last_session_ended_at().is_some());
        // Still refused: the cool-down runs from the session's end.
        assert_eq!(on(3).code, codes_ipc::G_REMOTE_SESSION_ACTIVE);
    }

    /// §B.8.7.4, Part C row 9a: `tornect panic` ends a live unattended session first
    /// (`BYE{PANIC}`), and then that session's grant is suspended (`Suspended{Panic}`):
    /// the device is refused `SUSPENDED` until a local Resume.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tornect_panic_suspends_the_grant_behind_an_unattended_session() {
        use tornect_core::unattended::grant::{GrantState, SuspendReason};
        use tornect_signal::fsm::HandshakeError;
        use tornect_signal::fsm::client::UnattendedIntent;

        const PASSWORD: &str = "quiet verdant otter lantern zephyr";
        let env = env();
        let host_device_pk = HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32]));
        let (identity, ccfg, cdeps) = client(&env);
        let device = identity.id();
        TrustedDeviceStore::open(env.paths.trusted_devices_file())
            .unwrap()
            .pin(device, "Laptop")
            .unwrap();
        cdeps
            .known_hosts
            .pin(env.identity.id(), "Desk", host_device_pk)
            .unwrap();
        grant_unattended(&env, &device, PASSWORD);
        let unattended = || {
            Intent::Unattended(UnattendedIntent {
                password: zeroize::Zeroizing::new(PASSWORD.to_owned()),
                want_mode: messages::mode::CONTROL,
                want_elevation: tornect_core::levels::Elevation::None,
            })
        };
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(0x33),
            Arc::new(ScriptedConsent::new()),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        let ctx = wiring.ctx.as_ref().unwrap();
        let (client_end, host_end) = duplex(64 * 1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        let mut session = match connect(client_end, &ccfg, &identity, &cdeps, unattended()).await {
            Ok(ClientOutcome::Session(s)) => s,
            other => panic!("no unattended session: {other:?}"),
        };
        session.send_tor_fallback(None).await.unwrap();
        session.ping().await.unwrap();
        let state = ctx.guard.store().grant(&device).unwrap().state;
        assert_eq!(state, GrantState::Active);

        let resp = crate::unattended::dispatch(
            ctx,
            IpcRequest {
                id: 1,
                op: IpcOp::Panic,
            },
        );
        assert!(resp.ok, "{resp:?}");
        assert_eq!(
            session.next_event(Duration::from_secs(10)).await.unwrap(),
            Some(tornect_signal::fsm::client::SessionEvent::Bye {
                reason: bye::PANIC,
                detail: None
            })
        );
        assert_eq!(host_task.await.unwrap(), Served::Session);
        let state = ctx.guard.store().grant(&device).unwrap().state;
        assert!(
            matches!(
                state,
                GrantState::Suspended {
                    reason: SuspendReason::Panic,
                    ..
                }
            ),
            "{state:?}"
        );

        // Until a local Resume: refused before any password exchange.
        let (client_end, host_end) = duplex(64 * 1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        match connect(client_end, &ccfg, &identity, &cdeps, unattended()).await {
            Err(HandshakeError::SessionRejected { reject: why }) => {
                assert_eq!(why.reason, reject::SUSPENDED);
            }
            other => panic!("a suspended grant answered {other:?}"),
        }
        let _ = host_task.await;
    }

    /// B12 (§B.8.6.4) through a real host: an unattended session that ran its
    /// grant's `max_session_secs` is followed by the reconnect cooldown, so the
    /// device's next request, with the right password, is refused `COOLDOWN`
    /// with the time left. Before, `settle(Ok)` zeroed `last_used`'s length and
    /// nothing wrote a session's end, so the second request was served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_that_ran_its_maximum_is_followed_by_the_cooldown() {
        use tornect_signal::fsm::HandshakeError;
        use tornect_signal::fsm::client::UnattendedIntent;

        const PASSWORD: &str = "quiet verdant otter lantern zephyr";
        let env = env();
        let host_device_pk = HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32]));
        let (identity, ccfg, cdeps) = client(&env);
        let device = identity.id();
        TrustedDeviceStore::open(env.paths.trusted_devices_file())
            .unwrap()
            .pin(device, "Laptop")
            .unwrap();
        cdeps
            .known_hosts
            .pin(env.identity.id(), "Desk", host_device_pk)
            .unwrap();
        grant_unattended(&env, &device, PASSWORD);
        // A one-second maximum with the ten-minute cooldown of *Helping
        // someone*, whose twelve-hour cooling-off a test cannot wait out.
        edit_grant_on_disk(&env.paths, &device, |g| {
            g.max_session_secs = Some(1);
            g.reconnect_cooldown_s = 600;
        });
        let unattended = || {
            Intent::Unattended(UnattendedIntent {
                password: zeroize::Zeroizing::new(PASSWORD.to_owned()),
                want_mode: messages::mode::CONTROL,
                want_elevation: tornect_core::levels::Elevation::None,
            })
        };
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(0x33),
            Arc::new(ScriptedConsent::new()),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        let store = wiring.ctx.as_ref().unwrap().guard.store().clone();
        let (client_end, host_end) = duplex(64 * 1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        let mut session = match connect(client_end, &ccfg, &identity, &cdeps, unattended()).await {
            Ok(ClientOutcome::Session(s)) => s,
            other => panic!("no unattended session: {other:?}"),
        };
        session.send_tor_fallback(None).await.unwrap();
        session.ping().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        session.bye(bye::USER).await.unwrap();
        assert_eq!(host_task.await.unwrap(), Served::Session);
        let last = store.grant(&device).unwrap().last_used.unwrap();
        assert!(last.duration_secs >= 1, "{last:?}");
        assert_eq!(last.transport, TransportKind::TorRelay);

        let (client_end, host_end) = duplex(64 * 1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        match connect(client_end, &ccfg, &identity, &cdeps, unattended()).await {
            Err(HandshakeError::SessionRejected { reject: why }) => {
                assert_eq!(why.reason, reject::COOLDOWN, "{why:?}");
                let left = why.retry_after_s.expect("the time left");
                assert!((590..=600).contains(&left), "{left}");
            }
            other => panic!("the request right after a full-length session got {other:?}"),
        }
        let _ = host_task.await;
        assert_eq!(
            store.grant(&device).unwrap().last_used,
            Some(last),
            "the refused request leaves the session it was refused for"
        );
        assert_eq!(wiring.live.count(), 0);
    }

    /// Routes for a sink whose sessions never bind media.
    fn no_routes() -> RouteOf {
        Arc::new(|_: &str| None)
    }

    /// An inner sink whose end makes the media layer forget the session, as
    /// the real one's does ([`MediaHost`]'s `on_end`).
    struct Forgets(Arc<AtomicBool>);

    impl SessionSink for Forgets {
        fn on_start(&self, _: &LiveSession<'_>) {
            self.0.store(false, Ordering::SeqCst);
        }

        fn on_end(&self, _: &str, _: Option<&SessionEnd>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// The grant's `last_used.transport` is the path the session's media
    /// took, read before the sink's own end forgets it: a direct LAN session
    /// records `lan`. A start that writes (no PAKE success of its own on
    /// record) keeps the transport on record, the path being unknown yet;
    /// a session whose media never bound records Tor.
    #[test]
    fn the_use_sink_records_the_path_its_media_took() {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::clock::FakeClock;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{
            AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
            RandomServerSetupSource,
        };
        use tornect_core::unattended::ipc::GrantOptions;
        use tornect_core::unattended::limiter::Settle;
        use tornect_core::unattended::store::GrantStore;
        use tornect_signal::consent::SessionToken;

        let env = env();
        let clock = Arc::new(FakeClock::at(1_787_961_600));
        let store = GrantStore::open(
            &env.paths,
            Arc::new(FileSecretStore::open(env.paths.keys_dir()).unwrap()),
            clock.clone(),
            SessionLog::new(env.paths.sessions_log()),
        )
        .unwrap();
        let guard = MutationGuard::new(
            store.clone(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::new(tornect_core::levels::FixedFacts::linux()),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(RandomServerSetupSource));
        guard.master_on(Actor::Cli, &[9; 32]).unwrap();
        let device = DeviceId::from_bytes([3; 32]);
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
        let limiter = AttemptLimiter::new(store.clone());
        let forgotten = Arc::new(AtomicBool::new(false));
        let routes: RouteOf = {
            let forgotten = Arc::clone(&forgotten);
            Arc::new(move |id: &str| {
                (id == "lan" && !forgotten.load(Ordering::SeqCst)).then_some(TransportKind::Lan)
            })
        };
        let sink = UnattendedUse::new(Arc::new(Forgets(forgotten)), store.clone(), routes);
        let token = SessionToken::new([1; 32]);
        let live = |id: &'static str| LiveSession {
            device,
            label: "Laptop",
            session_id: id,
            token: &token,
            th_final: [0; 32],
            mode: SessionMode::Control,
            elevation: tornect_core::levels::Elevation::None,
            unattended: true,
            transport: TransportPolicy::Any,
            viewer_dir1: true,
        };
        let last = || store.grant(&device).unwrap().last_used.unwrap();

        limiter.charge(&device).unwrap();
        limiter.settle(&device, Settle::Ok).unwrap();
        assert_eq!(
            last().transport,
            TransportKind::TorRelay,
            "none on record yet"
        );
        sink.on_start(&live("lan"));
        clock.advance(Duration::from_secs(30));
        sink.on_end("lan", None);
        assert_eq!(
            (last().transport, last().duration_secs),
            (TransportKind::Lan, 30)
        );

        // No PAKE success of its own on record: the start writes, keeping
        // the transport the last session took.
        sink.on_start(&live("never-bound"));
        assert_eq!(
            (last().transport, last().duration_secs),
            (TransportKind::Lan, 0)
        );
        clock.advance(Duration::from_secs(5));
        sink.on_end("never-bound", None);
        assert_eq!(
            (last().transport, last().duration_secs),
            (TransportKind::TorRelay, 5)
        );
    }

    /// The same through a host wired as `tornect host` wires it: an
    /// unattended session whose viewer is on the host's LAN goes direct, and
    /// its grant's `last_used` says `lan` once it ended.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_direct_unattended_session_records_the_lan() {
        use tornect_net::mem::{LinkSpec, MachineSpec, MemNet};
        use tornect_signal::fsm::client::UnattendedIntent;

        const PASSWORD: &str = "quiet verdant otter lantern zephyr";
        let env = env();
        let host_device = Arc::new(DeviceIdentity::from_seed(&[0x33; 32]));
        let (identity, ccfg, cdeps) = client(&env);
        let device = identity.id();
        TrustedDeviceStore::open(env.paths.trusted_devices_file())
            .unwrap()
            .pin(device, "Laptop")
            .unwrap();
        cdeps
            .known_hosts
            .pin(
                env.identity.id(),
                "Desk",
                HostSigner::public_key(host_device.as_ref()),
            )
            .unwrap();
        grant_unattended(&env, &device, PASSWORD);
        let net = MemNet::new(17);
        let lan = net.segment(LinkSpec::LAN);
        let viewer_net: Arc<dyn tornect_net::NetEnv> =
            Arc::new(net.machine(MachineSpec::on(lan, "192.168.1.10/24")));
        let host_net: Arc<dyn tornect_net::NetEnv> =
            Arc::new(net.machine(MachineSpec::on(lan, "192.168.1.20/24")));
        let knobs = crate::direct::DirectKnobs::new(&Config::default());
        let media = media();
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring {
                device: host_device,
                knobs: knobs.clone(),
                net: host_net,
            },
            Arc::new(ScriptedConsent::new()),
            Arc::clone(&media),
            ControlChannel::default(),
        )
        .unwrap();
        let store = wiring.ctx.as_ref().unwrap().guard.store().clone();
        let (client_end, host_end) = duplex(64 * 1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        let unattended = Intent::Unattended(UnattendedIntent {
            password: zeroize::Zeroizing::new(PASSWORD.to_owned()),
            want_mode: messages::mode::CONTROL,
            want_elevation: tornect_core::levels::Elevation::None,
        });
        let ccfg = crate::tor_cmd::viewer_config(ccfg.host, ccfg.name);
        let mut session = match connect(client_end, &ccfg, &identity, &cdeps, unattended).await {
            Ok(ClientOutcome::Session(s)) => s,
            other => panic!("no unattended session: {other:?}"),
        };
        let sid = session.session_token().session_id();
        let ctx = DirectWiring {
            device: Arc::new(identity),
            knobs,
            net: viewer_net,
        }
        .ctx(false);
        let binding = tornect_session::Binding::new(session.session_token(), &session.th());
        let never = || std::future::pending::<anyhow::Result<tokio::io::DuplexStream>>();
        let (_stop, stopped) = tokio::sync::watch::channel(false);
        let bound = crate::tor_cmd::bind_media(&mut session, &ctx, &binding, never, &stopped)
            .await
            .unwrap_or_else(|end| panic!("not bound: {end:?}"));
        assert!(matches!(bound.media, crate::tor_cmd::MediaPath::Direct(_)));
        assert_eq!(media.route(&sid), Some(TransportKind::Lan));
        session.ping().await.unwrap();
        session.bye(bye::USER).await.unwrap();
        assert_eq!(host_task.await.unwrap(), Served::Session);
        drop(bound);
        let last = store.grant(&device).unwrap().last_used.unwrap();
        assert_eq!(last.transport, TransportKind::Lan, "{last:?}");
    }

    /// The sink records only unattended sessions, and an older session of a
    /// device that ends after a newer one of the same device started leaves
    /// the newer one's record alone; the length counts from the PAKE success.
    #[test]
    fn the_use_sink_records_the_latest_unattended_session_only() {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::clock::FakeClock;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{
            AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
            RandomServerSetupSource,
        };
        use tornect_core::unattended::ipc::GrantOptions;
        use tornect_core::unattended::limiter::Settle;
        use tornect_core::unattended::store::GrantStore;
        use tornect_signal::consent::SessionToken;

        let env = env();
        let clock = Arc::new(FakeClock::at(1_787_961_600));
        let store = GrantStore::open(
            &env.paths,
            Arc::new(FileSecretStore::open(env.paths.keys_dir()).unwrap()),
            clock.clone(),
            SessionLog::new(env.paths.sessions_log()),
        )
        .unwrap();
        let guard = MutationGuard::new(
            store.clone(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::new(tornect_core::levels::FixedFacts::linux()),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(RandomServerSetupSource));
        guard.master_on(Actor::Cli, &[9; 32]).unwrap();
        let device = DeviceId::from_bytes([3; 32]);
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
        let limiter = AttemptLimiter::new(store.clone());
        let auth = || {
            limiter.charge(&device).unwrap();
            limiter.settle(&device, Settle::Ok).unwrap();
        };
        let sink = UnattendedUse::new(Arc::new(LiveSessions::new()), store.clone(), no_routes());
        let token = SessionToken::new([1; 32]);
        let live = |id: &'static str, unattended: bool| LiveSession {
            device,
            label: "Laptop",
            session_id: id,
            token: &token,
            th_final: [0; 32],
            mode: SessionMode::Control,
            elevation: tornect_core::levels::Elevation::None,
            unattended,
            transport: TransportPolicy::Any,
            viewer_dir1: false,
        };
        let advance = |secs: u64| clock.advance(Duration::from_secs(secs));
        let last = || store.grant(&device).unwrap().last_used.unwrap();

        // An attended session is not a use of the grant.
        auth();
        let authed = last();
        sink.on_start(&live("attended", false));
        advance(500);
        sink.on_end("attended", None);
        assert_eq!(last(), authed);

        // Ten seconds of block window, then 100 s of session: 110 s from the PAKE.
        auth();
        let first = last().at;
        advance(10);
        sink.on_start(&live("a", true));
        advance(100);
        // The same device again (BYE{REPLACED} ends the older one later).
        auth();
        let second = last().at;
        advance(5);
        sink.on_start(&live("b", true));
        sink.on_end("a", None);
        assert_eq!(
            (last().at, last().duration_secs),
            (second, 0),
            "the older session's end leaves the newer one's start"
        );
        advance(60);
        sink.on_end("b", None);
        assert_eq!((last().at, last().duration_secs), (second, 65));
        assert_ne!(first, second);
    }

    /// B13 (§B.8.13): a host's start runs the `sessions.log` verifier, and its
    /// verdict is the readiness row "Session log intact" that the gate, the
    /// control channel and the window read. A log edited between two starts
    /// fails the row with the line, which nothing checked before.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tampered_session_log_is_reported_at_the_start() {
        use tornect_core::unattended::readiness::Probe;

        let env = env();
        grant_unattended(&env, &DeviceId::from_bytes([3; 32]), "quiet verdant otter");
        let start = || {
            wire(
                &env.paths,
                &Config::default(),
                Arc::clone(&env.identity),
                DirectWiring::for_test(0x33),
                Arc::new(ScriptedConsent::new()),
                media(),
                ControlChannel::default(),
            )
            .unwrap()
        };
        let wiring = start();
        let row = wiring.ctx.as_ref().unwrap().readiness.get().session_log;
        assert_eq!(row, Probe::Ok);
        drop(wiring);

        // Someone without the log key edits the second line.
        let text = std::fs::read_to_string(env.paths.sessions_log()).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        assert!(lines.len() >= 3, "{lines:?}");
        lines[1] = lines[1].replacen("\"ts\":\"20", "\"ts\":\"19", 1);
        std::fs::write(env.paths.sessions_log(), lines.join("\n") + "\n").unwrap();

        let wiring = start();
        let ctx = wiring.ctx.as_ref().unwrap();
        match ctx.readiness.get().session_log {
            Probe::Fail(why) => assert!(
                why.starts_with("log modified or truncated at line 2 of sessions.log"),
                "{why}"
            ),
            other => panic!("a tampered log read {other:?}"),
        }
        assert_eq!(
            ctx.readiness_now().session_log,
            ctx.readiness.get().session_log,
            "the control channel's report carries it"
        );
    }

    /// B13 (§B.8.6.1): a host's start runs the housekeeping, which before
    /// ran nowhere: a grant that expired while no host ran gets its
    /// `GrantExpired` line, and one expired more than 30 days ago has its
    /// auth record pruned (`GrantPruned`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_start_logs_expired_grants_and_prunes_them() {
        use tornect_core::session_log::SessionEvent;
        use tornect_core::unattended::grant::AuthRecord;

        let env = env();
        let device = DeviceId::from_bytes([3; 32]);
        grant_unattended(&env, &device, "quiet verdant otter");
        let events = || -> Vec<SessionEvent> {
            SessionLog::new(env.paths.sessions_log())
                .read_all()
                .unwrap()
                .into_iter()
                .map(|r| r.event)
                .collect()
        };
        let start = || {
            wire(
                &env.paths,
                &Config::default(),
                Arc::clone(&env.identity),
                DirectWiring::for_test(0x33),
                Arc::new(ScriptedConsent::new()),
                media(),
                ControlChannel::default(),
            )
            .unwrap()
        };
        let now = tornect_core::trusted::unix_now();
        edit_grant_on_disk(&env.paths, &device, |g| g.expires_at = Some(now + 2));
        tokio::time::sleep(Duration::from_secs(3)).await;
        let wiring = start();
        let seen = events();
        assert_eq!(
            seen.iter()
                .filter(|e| **e == SessionEvent::GrantExpired)
                .count(),
            1,
            "{seen:?}"
        );
        assert!(!seen.contains(&SessionEvent::GrantPruned), "{seen:?}");
        assert_eq!(
            wiring.ctx.as_ref().unwrap().readiness.get().session_log,
            tornect_core::unattended::readiness::Probe::Ok,
            "the verifier ran before the housekeeping's line"
        );
        drop(wiring);

        edit_grant_on_disk(&env.paths, &device, |g| {
            g.expires_at = Some(now - 31 * 86_400);
        });
        let wiring = start();
        let seen = events();
        assert!(seen.contains(&SessionEvent::GrantPruned), "{seen:?}");
        let store = wiring.ctx.as_ref().unwrap().guard.store();
        assert_eq!(store.grant(&device).unwrap().auth, AuthRecord::Pruned);
    }

    /// B13 (§B.8.9): a store that opened failed closed because its key could
    /// not be read is loaded again by the 10-minute upkeep once the key can be
    /// read (the one recovery load), and its log is then verified; until then
    /// the upkeep changes nothing and the row keeps its verdict.
    #[test]
    fn the_upkeep_loads_a_store_whose_keystore_was_locked() {
        use std::sync::atomic::AtomicBool;
        use tornect_core::keystore::{FileSecretStore, SecretStore};
        use tornect_core::unattended::clock::SystemClock;
        use tornect_core::unattended::codec::StoreLoadError;
        use tornect_core::unattended::readiness::Probe;
        use tornect_core::unattended::store::{GrantStore, StoreStatus};

        /// A keystore whose reads fail while `locked`.
        struct Locked {
            inner: FileSecretStore,
            locked: AtomicBool,
        }
        impl SecretStore for Locked {
            fn get(&self, name: &str) -> tornect_core::Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
                if self.locked.load(Ordering::SeqCst) {
                    return Err(tornect_core::CoreError::KeychainLocked(
                        "collection locked".into(),
                    ));
                }
                self.inner.get(name)
            }
            fn put(&self, name: &str, secret: &[u8]) -> tornect_core::Result<()> {
                self.inner.put(name, secret)
            }
            fn delete(&self, name: &str) -> tornect_core::Result<bool> {
                self.inner.delete(name)
            }
        }

        let env = env();
        let device = DeviceId::from_bytes([3; 32]);
        grant_unattended(&env, &device, "quiet verdant otter");
        let secrets = Arc::new(Locked {
            inner: FileSecretStore::open(env.paths.keys_dir()).unwrap(),
            locked: AtomicBool::new(true),
        });
        let store = GrantStore::open(
            &env.paths,
            secrets.clone(),
            Arc::new(SystemClock::default()),
            SessionLog::new(env.paths.sessions_log()),
        )
        .unwrap();
        assert!(matches!(
            store.status(),
            StoreStatus::FailedClosed(StoreLoadError::KeystoreLocked(_))
        ));
        let row = start_upkeep(&store);
        assert!(
            matches!(row, Probe::Warn(_)),
            "unread, so unchecked: {row:?}"
        );
        let row = periodic_upkeep(&store, row);
        assert!(matches!(row, Probe::Warn(_)), "{row:?}");
        assert!(!store.is_loaded());

        secrets.locked.store(false, Ordering::SeqCst);
        let row = periodic_upkeep(&store, row);
        assert_eq!(store.status(), StoreStatus::Loaded);
        assert_eq!(row, Probe::Ok, "verified once loaded");
        assert!(store.grant(&device).is_some());
        // A loaded store is never loaded again; the row stays.
        let generation = store.generation();
        assert_eq!(periodic_upkeep(&store, Probe::Ok), Probe::Ok);
        assert_eq!(store.generation(), generation);
    }

    /// A host start over `env`'s home, as `wire()` makes it for the terminal.
    fn start_host(env: &Env) -> HostWiring {
        wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(0x33),
            Arc::new(ScriptedConsent::new()),
            media(),
            ControlChannel::default(),
        )
        .unwrap()
    }

    /// B13 review: this device's own lines for its unattended connects (the
    /// client's `UnattendedConnect`) keep `sessions.log` intact in a home whose
    /// host has unattended access on: the window's go through its host role's
    /// store, a terminal's `tornect connect` keys its own handle with the
    /// home's `K_log`, so every one carries the tag the verifier checks. They
    /// were written untagged, and every later start read "log modified or
    /// truncated" at the first of them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn this_devices_connect_lines_keep_the_log_intact() {
        use crate::ua_client::{Logged, log_attempt, log_attempt_via};
        use tornect_core::trusted::KnownHost;
        use tornect_core::unattended::readiness::Probe;

        let env = env();
        grant_unattended(&env, &DeviceId::from_bytes([3; 32]), "quiet verdant otter");
        let known = KnownHost {
            label: "Desk".to_owned(),
            host_device_pk: [7; 32],
            paired_at: 1,
            last_seen: 1,
        };
        let row = |wiring: &HostWiring| wiring.ctx.as_ref().unwrap().readiness.get().session_log;
        // No host runs: `tornect connect --unattended` from a terminal.
        log_attempt(&env.paths, &known, &Logged::Ended("unreachable"));
        let wiring = start_host(&env);
        assert_eq!(row(&wiring), Probe::Ok);

        // The window: its host role's store writes the line and moves the head.
        let store = wiring.ctx.as_ref().unwrap().guard.store().clone();
        log_attempt_via(
            Some(&store),
            &env.paths,
            &known,
            &Logged::Admin {
                op: "unlock",
                ok: true,
            },
        );
        let report = store.verify_log().unwrap();
        assert_eq!(
            (report.tagged_beyond_head, report.status),
            (0, tornect_core::session_log::ChainStatus::Valid)
        );
        // A terminal's while that host runs.
        log_attempt(&env.paths, &known, &Logged::Ended("cancelled"));
        drop((store, wiring));

        let wiring = start_host(&env);
        assert_eq!(row(&wiring), Probe::Ok);
        let text = std::fs::read_to_string(env.paths.sessions_log()).unwrap();
        let mine: Vec<&str> = text
            .lines()
            .filter(|l| l.contains(r#""event":"unattended_connect""#))
            .collect();
        assert_eq!(mine.len(), 3, "{text}");
        for line in mine {
            let chain = tornect_core::session_log::parse_line_chain(line).unwrap();
            assert!(chain.tag.is_some(), "{line}");
        }
    }

    /// B13 review: a start reports a tail cut while no host ran, the stored head
    /// with it, although the store's load appends a line first (the outcome of a
    /// charge that a killed host left pending): that line links to the cut tail
    /// and becomes the head, after which a walk of the log finds it whole. The
    /// verdict is the load's own, taken before its first line.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cut_tail_is_reported_although_the_load_appends_first() {
        use tornect_core::session_log::SessionEvent;
        use tornect_core::unattended::readiness::Probe;

        let env = env();
        let device = DeviceId::from_bytes([3; 32]);
        grant_unattended(&env, &device, "quiet verdant otter");
        let wiring = start_host(&env);
        assert_eq!(
            wiring.ctx.as_ref().unwrap().readiness.get().session_log,
            Probe::Ok
        );
        drop(wiring);
        // A host killed between a charge and its settlement.
        edit_grant_on_disk(&env.paths, &device, |g| g.fail.pending = true);
        let text = std::fs::read_to_string(env.paths.sessions_log()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(
            env.paths.sessions_log(),
            lines[..lines.len() - 1].join("\n") + "\n",
        )
        .unwrap();

        let wiring = start_host(&env);
        let settled = SessionLog::new(env.paths.sessions_log())
            .read_all()
            .unwrap()
            .into_iter()
            .any(|r| {
                r.event == SessionEvent::UnattendedAuthFailed
                    && r.reason.as_deref() == Some("abandoned")
            });
        assert!(settled, "the load appended its line");
        match wiring.ctx.as_ref().unwrap().readiness.get().session_log {
            Probe::Fail(why) => assert!(why.contains("stored head matches no line"), "{why}"),
            other => panic!("the cut tail read {other:?}"),
        }
    }

    /// B12 review: a session cut at its signed `ends_at` counts as full length
    /// whatever the sub-second phases of the PAKE, the start and the cut, so the
    /// device's next request is refused `COOLDOWN`. Both parts of the length
    /// were rounded down: such a session read `max_session_secs - 1`, and no
    /// cooldown followed it.
    #[test]
    fn a_session_cut_at_its_signed_end_is_followed_by_the_cooldown() {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::clock::{Clock as _, FakeClock};
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{
            AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
            RandomServerSetupSource,
        };
        use tornect_core::unattended::ipc::GrantOptions;
        use tornect_core::unattended::limiter::{PostF2Reject, Settle};
        use tornect_core::unattended::store::GrantStore;
        use tornect_signal::consent::SessionToken;

        const BASE: u64 = 1_787_961_600;
        let env = env();
        let clock = Arc::new(FakeClock::at(BASE));
        let store = GrantStore::open(
            &env.paths,
            Arc::new(FileSecretStore::open(env.paths.keys_dir()).unwrap()),
            clock.clone(),
            SessionLog::new(env.paths.sessions_log()),
        )
        .unwrap();
        let guard = MutationGuard::new(
            store.clone(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::new(tornect_core::levels::FixedFacts::linux()),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(RandomServerSetupSource));
        guard.master_on(Actor::Cli, &[9; 32]).unwrap();
        let device = DeviceId::from_bytes([3; 32]);
        guard
            .create_grant(
                Actor::Cli,
                &device,
                Preset::HelpingSomeone,
                &GrantOptions {
                    waive_attended_precondition: true,
                    ..GrantOptions::default()
                },
                &[0u8; 192],
                false,
            )
            .unwrap();
        let grant = store.grant(&device).unwrap();
        let max = grant.max_session_secs.unwrap();
        assert_eq!(grant.reconnect_cooldown_s, 600);
        let limiter = AttemptLimiter::new(store.clone());
        let utc = FixedOffset::utc();
        let request = || {
            limiter.charge(&device).unwrap();
            limiter.settle(&device, Settle::Ok).unwrap();
            limiter.post_f2(&device, &utc, HostTransport::default())
        };
        // Time since BASE in milliseconds: the wall reads its whole seconds,
        // the monotonic clock all of it.
        let to = |ms: u64| {
            let real = Duration::from_millis(ms);
            clock.set_wall(BASE + real.as_secs());
            clock.advance_mono(real.saturating_sub(clock.mono()));
        };
        let sink = UnattendedUse::new(Arc::new(LiveSessions::new()), store.clone(), no_routes());
        let token = SessionToken::new([1; 32]);

        // (the PAKE's, the start's, the cut's milliseconds into their seconds)
        let phases = [
            (100, 600, 5),
            (900, 100, 1),
            (0, 0, 0),
            (999, 999, 0),
            (500, 0, 999),
        ];
        // Past the 12-hour cooling-off of *Helping someone*.
        let mut second = 13 * 3600;
        for (n, (pake, start, cut)) in phases.into_iter().enumerate() {
            to(second * 1000 + pake);
            let ends_at = request().expect("a session").ends_at.expect("its maximum");
            // A ten-second block window, then the session.
            to((second + 10) * 1000 + start);
            let id = format!("s{n}");
            sink.on_start(&LiveSession {
                device,
                label: "Laptop",
                session_id: &id,
                token: &token,
                th_final: [0; 32],
                mode: SessionMode::ViewOnly,
                elevation: tornect_core::levels::Elevation::None,
                unattended: true,
                transport: TransportPolicy::Any,
                viewer_dir1: false,
            });
            // Cut at the first wall reading of its end.
            to((ends_at - BASE) * 1000 + cut);
            sink.on_end(&id, None);
            let last = store.grant(&device).unwrap().last_used.unwrap();
            assert_eq!(
                last.at + u64::from(last.duration_secs),
                ends_at,
                "{:?}: {} s of {max}",
                (pake, start, cut),
                last.duration_secs
            );
            assert_eq!(
                request(),
                Err(PostF2Reject::Cooldown { retry_after_s: 600 }),
                "{:?}: the request at once",
                (pake, start, cut)
            );
            second = ends_at - BASE + 601;
        }

        // The wall set back an hour during a session that then runs its maximum
        // by the monotonic clock: that counts it full.
        to(second * 1000 + 300);
        request().expect("a session");
        let pake = store.grant(&device).unwrap().last_used.unwrap().at;
        to((second + 10) * 1000 + 700);
        sink.on_start(&LiveSession {
            device,
            label: "Laptop",
            session_id: "back",
            token: &token,
            th_final: [0; 32],
            mode: SessionMode::ViewOnly,
            elevation: tornect_core::levels::Elevation::None,
            unattended: true,
            transport: TransportPolicy::Any,
            viewer_dir1: false,
        });
        clock.set_wall(clock.wall() - 3600);
        clock.advance_mono(Duration::from_secs(u64::from(max) - 10));
        sink.on_end("back", None);
        let last = store.grant(&device).unwrap().last_used.unwrap();
        assert_eq!(last.at, pake);
        assert!(
            last.duration_secs >= max,
            "{} s of {max}",
            last.duration_secs
        );
    }

    /// Both protocols answer on the one port: a ping stream is served by the
    /// ping protocol, with no pairing and no popup.
    #[tokio::test]
    async fn a_ping_needs_no_pairing() {
        let env = env();
        let consent = Arc::new(ScriptedConsent::new());
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(9),
            consent.clone(),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        let (mut client_end, host_end) = duplex(1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        for i in 0..2u8 {
            ping::ping(&mut client_end, [i; ping::NONCE_LEN])
                .await
                .unwrap();
        }
        drop(client_end);
        assert_eq!(host_task.await.unwrap(), Served::Pings(2));
        assert!(consent.sas_shown().is_empty(), "no popup for a ping");
        assert_eq!(wiring.live.count(), 0);
    }

    /// SLICE-B2 B2-2. A host whose store was locked at start (another Tornect
    /// command held it, e.g. `unattended grant` waiting at a prompt) still has
    /// a control channel, and `tornect panic` ends its sessions. Before, it had
    /// none: `tornect panic` answered "no host is running here" while the
    /// session went on. Everything but `Panic` is refused with the reason,
    /// rather than run without the guard.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_whose_store_was_locked_still_answers_panic() {
        let env = env();
        // What another command holds while it runs (the grant store's lock).
        let held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(env.paths.unattended_lock())
            .unwrap();
        held.try_lock().unwrap();
        let consent = Arc::new(ScriptedConsent::new());
        consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
        consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
        let control = ControlChannel::default();
        let HostWiring {
            cfg,
            deps,
            ctx,
            live,
            ..
        } = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(0x33),
            consent,
            media(),
            control.clone(),
        )
        .unwrap();
        assert!(ctx.is_err(), "the store is held elsewhere");
        assert_eq!(
            cfg.feats,
            [messages::feats::SVC1, messages::feats::DIR1],
            "without a store the host offers no unattended suite, and still the services stream \
             and the direct path"
        );
        let ipc = start_control_channel(&env.paths, ctx, deps.kill.clone(), control.clone())
            .await
            .unwrap()
            .expect("a control channel without a store");
        assert_eq!(control.kill_path(), "`tornect panic`");

        let (client_end, host_end) = duplex(64 * 1024);
        let host_task = {
            let (cfg, deps) = (cfg.clone(), deps.clone());
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await })
        };
        let (identity, ccfg, cdeps) = client(&env);
        let mut session = match connect(client_end, &ccfg, &identity, &cdeps, Intent::Session)
            .await
            .unwrap()
        {
            ClientOutcome::Session(s) => s,
            other => panic!("expected a session, got {other:?}"),
        };
        assert!(
            session.host_has(messages::feats::SVC1),
            "the client reads the services stream's token from the signed HELLO_ACK"
        );
        assert!(
            session.host_has(messages::feats::DIR1),
            "and the direct path's (design `direct` §4)"
        );
        session.send_tor_fallback(None).await.unwrap();
        session.ping().await.unwrap();
        assert_eq!(live.count(), 1);

        // `tornect panic`, as the CLI sends it.
        let state = &env.paths.state_dir;
        let panic = IpcRequest {
            id: 1,
            op: IpcOp::Panic,
        };
        let resp = tornect_platform::ipc::request(state, &panic).await.unwrap();
        assert!(resp.ok, "{resp:?}");
        let event = session.next_event(Duration::from_secs(10)).await.unwrap();
        assert_eq!(
            event,
            Some(tornect_signal::fsm::client::SessionEvent::Bye {
                reason: bye::PANIC,
                detail: None
            })
        );
        assert_eq!(host_task.await.unwrap(), Served::Session);
        assert_eq!(live.count(), 0);

        let on = IpcRequest {
            id: 2,
            op: IpcOp::On,
        };
        let refused = tornect_platform::ipc::request(state, &on).await.unwrap();
        assert!(!refused.ok);
        assert_eq!(refused.code, codes_ipc::G_PRECONDITION);
        assert!(
            refused
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("without its unattended store")),
            "{refused:?}"
        );
        ipc.abort();
    }

    /// The terminal names `tornect panic` only while it can reach this host
    /// (SLICE-B2 B2-2). A Windows host (no endpoint until M6), or one whose
    /// channel failed or stopped, names Ctrl-C.
    #[test]
    fn the_kill_path_named_is_one_that_works() {
        let control = ControlChannel::default();
        assert_eq!(control.kill_path(), "Ctrl-C in this terminal");
        control.set(true);
        assert_eq!(control.kill_path(), "`tornect panic`");
        control.set(false);
        assert_eq!(control.kill_path(), "Ctrl-C in this terminal");
    }

    /// SLICE-D R7: a host whose control channel cannot bind names Ctrl-C, never
    /// `tornect panic`, as the way to end its sessions.
    #[tokio::test]
    async fn a_host_whose_control_channel_cannot_bind_names_ctrl_c() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("a-file");
        std::fs::write(&file, "x").unwrap();
        let mut paths = Paths::from_home(tmp.path());
        // Nothing can be created under a regular file, so the bind fails.
        paths.state_dir = file.join("state");
        let control = ControlChannel::default();
        let served = start_control_channel(
            &paths,
            Err("no store".to_owned()),
            KillSwitch::new(),
            control.clone(),
        )
        .await
        .unwrap();
        assert!(served.is_none(), "a channel was bound under a file");
        assert!(!control.is_up());
        assert_eq!(control.kill_path(), "Ctrl-C in this terminal");
    }

    /// What a host killed mid-run leaves behind (a crash, SIGKILL, or the
    /// window before it handled SIGTERM): `state/host.lock` with a dead pid
    /// and `state/ipc.sock` with nobody listening. Neither blocks the next
    /// host: the lock is the OS's and died with its process, and a socket that
    /// refuses connections is replaced.
    #[cfg(unix)]
    #[tokio::test]
    async fn what_a_killed_host_leaves_behind_never_blocks_the_next() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        std::fs::write(paths.host_lock(), b"4242").unwrap();
        let socket = paths.state_dir.join("ipc.sock");
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        assert!(socket.exists(), "the dead host's socket stays on disk");
        assert_eq!(HostLock::holder(&paths), None, "no live holder");
        let _lock = HostLock::acquire(&paths).expect("the lock is free");
        let control = ControlChannel::default();
        let served = start_control_channel(
            &paths,
            Err("no store in this test".to_owned()),
            KillSwitch::new(),
            control.clone(),
        )
        .await
        .expect("a stale socket is replaced");
        assert!(served.is_some() && control.is_up());
        assert!(tornect_platform::ipc::is_running(&paths.state_dir).await);
        if let Some(task) = served {
            task.abort();
        }
    }

    /// One host per state directory, and every other command can see it: the
    /// lock names its holder while the host runs and is gone when it ends.
    #[test]
    fn a_second_host_on_the_same_home_is_refused() {
        let env = env();
        assert_eq!(HostLock::holder(&env.paths), None);
        let first = HostLock::acquire(&env.paths).unwrap();
        assert_eq!(
            HostLock::holder(&env.paths),
            Some(format!("pid {}", std::process::id()))
        );
        let second = HostLock::acquire(&env.paths).unwrap_err().to_string();
        assert!(second.contains("already running"), "{second}");
        drop(first);
        assert_eq!(HostLock::holder(&env.paths), None);
        let _again = HostLock::acquire(&env.paths).unwrap();
    }
    /// §B.2.1 (Linux): a Control session revokes polkit's remembered
    /// approvals at its start and after a change the authority reports, a
    /// view-only one touches nothing, and the session's end stops the watch.
    #[tokio::test]
    async fn control_sessions_revoke_polkits_remembered_approvals() {
        use std::sync::atomic::AtomicUsize;

        use tornect_platform::polkit::{BoxFuture, PolkitError, TemporaryAuthority};
        use tornect_signal::consent::SessionToken;

        #[derive(Default)]
        struct Fake {
            remembered: AtomicUsize,
            revokes: AtomicUsize,
            tx: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
        }
        impl TemporaryAuthority for Fake {
            fn revoke(&self) -> BoxFuture<'_, Result<(), PolkitError>> {
                Box::pin(async move {
                    self.revokes.fetch_add(1, Ordering::SeqCst);
                    self.remembered.store(0, Ordering::SeqCst);
                    Ok(())
                })
            }
            fn remembered(&self) -> BoxFuture<'_, Result<usize, PolkitError>> {
                Box::pin(async move { Ok(self.remembered.load(Ordering::SeqCst)) })
            }
            fn changes(
                &self,
            ) -> BoxFuture<'_, Result<tokio::sync::mpsc::Receiver<()>, PolkitError>> {
                Box::pin(async move {
                    let (tx, rx) = tokio::sync::mpsc::channel(4);
                    *self.tx.lock().unwrap() = Some(tx);
                    Ok(rx)
                })
            }
        }
        async fn settle() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let fake = Arc::new(Fake::default());
        let factory: AuthorityFactory = {
            let fake = Arc::clone(&fake);
            Arc::new(move || {
                let fake = Arc::clone(&fake);
                Box::pin(async move { Ok(fake as Arc<dyn TemporaryAuthority>) })
            })
        };
        let revocation = PolkitRevocation::with(Some(factory));
        let token = SessionToken::new([5; 32]);
        let session = |id: &'static str, mode| LiveSession {
            device: DeviceIdentity::from_seed(&[9; 32]).id(),
            label: "Laptop",
            session_id: id,
            token: &token,
            th_final: [0; 32],
            mode,
            elevation: tornect_core::levels::Elevation::None,
            unattended: false,
            transport: TransportPolicy::Any,
            viewer_dir1: false,
        };
        revocation.on_start(&session("v1", SessionMode::ViewOnly));
        settle().await;
        assert_eq!(
            fake.revokes.load(Ordering::SeqCst),
            0,
            "view-only touches nothing"
        );
        fake.remembered.store(1, Ordering::SeqCst);
        revocation.on_start(&session("c1", SessionMode::Control));
        settle().await;
        assert_eq!(
            fake.revokes.load(Ordering::SeqCst),
            1,
            "revoked at the start"
        );
        fake.remembered.store(2, Ordering::SeqCst);
        let changed = fake.tx.lock().unwrap().clone().unwrap();
        changed.send(()).await.unwrap();
        settle().await;
        assert_eq!(
            fake.revokes.load(Ordering::SeqCst),
            2,
            "revoked after a change"
        );
        assert_eq!(fake.remembered.load(Ordering::SeqCst), 0);
        revocation.on_end("c1");
        settle().await;
        fake.remembered.store(3, Ordering::SeqCst);
        let _ = changed.send(()).await;
        settle().await;
        assert_eq!(
            fake.revokes.load(Ordering::SeqCst),
            2,
            "watched after the end"
        );
        // This crate's own wiring never reaches the machine's polkit.
        assert!(PolkitRevocation::for_this_host().authority.is_none());
    }

    /// Every Control session of a host shares one authority (one bus
    /// connection): the first that connected. A failed connection is tried
    /// again by the next session.
    #[tokio::test]
    async fn the_host_connects_to_polkit_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tornect_platform::polkit::{BoxFuture, PolkitError, TemporaryAuthority};

        struct Idle;
        impl TemporaryAuthority for Idle {
            fn revoke(&self) -> BoxFuture<'_, Result<(), PolkitError>> {
                Box::pin(async { Ok(()) })
            }
            fn remembered(&self) -> BoxFuture<'_, Result<usize, PolkitError>> {
                Box::pin(async { Ok(0) })
            }
            fn changes(
                &self,
            ) -> BoxFuture<'_, Result<tokio::sync::mpsc::Receiver<()>, PolkitError>> {
                Box::pin(async { Ok(tokio::sync::mpsc::channel(1).1) })
            }
        }
        let attempts = Arc::new(AtomicUsize::new(0));
        let connect: AuthorityFactory = {
            let attempts = Arc::clone(&attempts);
            Arc::new(move || {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    if n == 0 {
                        Err(PolkitError("no bus yet".to_owned()))
                    } else {
                        Ok(Arc::new(Idle) as Arc<dyn TemporaryAuthority>)
                    }
                })
            })
        };
        let shared = once_per_host(connect);
        assert!(shared().await.is_err(), "the first attempt failed");
        let a = shared().await.expect("the second connected");
        let b = shared().await.expect("then shared");
        assert!(Arc::ptr_eq(&a, &b), "one authority for every session");
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "connected once");
    }

    /// A Linux host running as root refuses to serve before anything is
    /// published, and says why; any other user serves.
    #[test]
    fn a_root_host_serves_nothing() {
        use tornect_core::levels::{Availability, SENTENCE_LINUX_ROOT};
        assert!(is_root(0));
        assert!(!is_root(1000));
        let root = Availability::LINUX_ROOT;
        assert!(!root.serves());
        assert_eq!(root.sentence, Some(SENTENCE_LINUX_ROOT));
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt as _;
            let me = std::fs::metadata("/proc/self").unwrap().uid();
            assert_eq!(running_as_root(), me == 0);
        }
    }

    /// Decision M1-67 (A21): a Linux host whose root check cannot read
    /// `/proc/self` does not serve, and says why; one that read its user
    /// serves as before.
    #[test]
    fn the_root_check_refuses_when_it_cannot_read() {
        let unreadable = root_from(Err(std::io::Error::other("no /proc")));
        assert_eq!(unreadable, Root::Unreadable);
        let refused = levels_for(unreadable, || panic!("no probe")).unwrap_err();
        assert_eq!(refused.to_string(), SENTENCE_ROOT_UNREADABLE);
        assert_eq!(root_from(Ok(0)), Root::Yes);
        assert!(
            !levels_for(Root::Yes, || panic!("no probe"))
                .unwrap()
                .serves()
        );
        assert_eq!(root_from(Ok(1000)), Root::No);
        let linux = tornect_core::levels::Availability::of(None);
        assert_eq!(levels_for(Root::No, || linux).unwrap(), linux);
    }

    /// A Control session whose revocation fails, or whose watch stops, is
    /// told to the person at this computer, not only logged.
    #[tokio::test]
    async fn a_failed_revocation_is_told_to_the_person_here() {
        use tornect_platform::polkit::{PolkitError, TemporaryAuthority};

        let told = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let factory: AuthorityFactory = Arc::new(|| {
            Box::pin(async {
                Err::<Arc<dyn TemporaryAuthority>, _>(PolkitError("no bus".to_owned()))
            })
        });
        let revocation = PolkitRevocation::with(Some(factory));
        let sink = Arc::clone(&told);
        revocation.tell_through(Arc::new(move |line: &str| {
            sink.lock().unwrap().push(line.to_owned());
        }));
        let token = tornect_signal::consent::SessionToken::new([5; 32]);
        revocation.on_start(&LiveSession {
            device: DeviceIdentity::from_seed(&[9; 32]).id(),
            label: "Laptop",
            session_id: "c1",
            token: &token,
            th_final: [0; 32],
            mode: SessionMode::Control,
            elevation: tornect_core::levels::Elevation::None,
            unattended: false,
            transport: TransportPolicy::Any,
            viewer_dir1: false,
        });
        for _ in 0..100 {
            if !told.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(*told.lock().unwrap(), vec![POLKIT_NOT_CLEARED.to_owned()]);
        revocation.on_end("c1");
    }

    /// U3-M1: the evidence lines name the host viewed or this computer's
    /// address only on the live-check scripts' opt-in (`--evidence`, or
    /// `TORNECT_EVIDENCE=1`); without it a line carries its session id, or
    /// is not written. Both paths, captured.
    #[test]
    fn the_evidence_lines_name_nobody_without_the_opt_in() {
        let written = |opted_in: bool| {
            let mut out = Vec::new();
            let sid = "5e55";
            evidence_to(
                &mut out,
                opted_in,
                format_args!("SESSION LIVE {sid} with \"Desk\" (control)"),
                Some(format_args!("SESSION LIVE {sid}")),
            );
            evidence_to(
                &mut out,
                opted_in,
                format_args!("VIEWER: Session with \"Desk\" ended (by you)."),
                Some(format_args!("VIEWER ENDED {sid}")),
            );
            evidence_to(
                &mut out,
                opted_in,
                format_args!("Tornect ID: abcdefgh.onion"),
                None,
            );
            String::from_utf8(out).unwrap()
        };
        assert_eq!(
            written(true),
            "SESSION LIVE 5e55 with \"Desk\" (control)\n\
             VIEWER: Session with \"Desk\" ended (by you).\n\
             Tornect ID: abcdefgh.onion\n"
        );
        assert_eq!(written(false), "SESSION LIVE 5e55\nVIEWER ENDED 5e55\n");
        for (flag, env, wanted) in [
            (false, None, false),
            (false, Some("0"), false),
            (false, Some("yes"), false),
            (false, Some("1"), true),
            (true, None, true),
        ] {
            assert_eq!(evidence_wanted(flag, env), wanted, "{flag} {env:?}");
        }
    }

    /// U3-M1 (the R-3g rule): a note that names a peer reaches stderr only
    /// when stderr is a terminal; a redirected stderr (the user journal, a
    /// file) gets nothing. Both paths, captured.
    #[test]
    fn a_peer_note_reaches_a_terminal_only() {
        for terminal in [true, false] {
            let mut out = Vec::new();
            peer_note_to(
                &mut out,
                terminal,
                format_args!("paired with \"Laptop\"; it asked for no session"),
            );
            let expected = if terminal {
                "paired with \"Laptop\"; it asked for no session\n"
            } else {
                ""
            };
            assert_eq!(String::from_utf8(out).unwrap(), expected, "{terminal}");
        }
    }

    /// Decision M1-67 (C11): the notes after an unattended answer name the
    /// host, so the command line writes them only to a terminal, through the
    /// gate of its other host-naming lines.
    #[test]
    fn the_cli_notes_name_no_host_off_a_terminal() {
        use tornect_core::unattended::credentials::Settled;
        let notes = crate::ua_client::notes(
            "\"Desk\"",
            "a test keychain",
            crate::ua_client::Answered::Session {
                elevation: tornect_core::levels::Elevation::None,
                grant_reach: Some(1),
                asked_control: true,
                given_control: false,
                withheld: true,
            },
            true,
            Some(&Settled {
                forgot: true,
                ..Settled::default()
            }),
        );
        assert_eq!(notes.len(), 3, "{notes:?}");
        for note in &notes {
            assert!(note.contains("\"Desk\""), "{note}");
            let mut off = Vec::new();
            peer_note_to(&mut off, false, format_args!("{note}"));
            assert!(off.is_empty(), "off a terminal: {note}");
            let mut on = Vec::new();
            peer_note_to(&mut on, true, format_args!("{note}"));
            assert_eq!(String::from_utf8(on).unwrap(), format!("{note}\n"));
        }
    }

    /// FX1-L1: while a session is live the terminal's note for a refused
    /// request (or any other handshake) names no other device, neither its
    /// pinned label nor its fingerprint; outside a live session it is as it
    /// was. Both states, captured through the writer `serve_signaling` uses.
    #[test]
    fn a_refusal_during_a_live_session_names_nobody() {
        let device = DeviceIdentity::from_seed(&[0x33; 32]).id();
        let fingerprint = device.fingerprint();
        let outcomes = [
            HostOutcome::SessionRejected {
                device,
                label: "Desk of Bob".to_owned(),
                reason: reject::BUSY,
            },
            HostOutcome::PairRejected {
                device,
                reason: pair_reject::BUSY,
            },
        ];
        let written = |live: bool| {
            let mut out = Vec::new();
            for outcome in &outcomes {
                note_outcome_to(&mut out, true, outcome, live);
            }
            String::from_utf8(out).unwrap()
        };
        let live = written(true);
        assert_eq!(
            live,
            "a session request was refused: busy\na pairing request was refused: busy\n"
        );
        assert!(!live.contains("Desk of Bob") && !live.contains(&fingerprint));
        let idle = written(false);
        assert_eq!(
            idle,
            format!(
                "session refused for \"Desk of Bob\" (BUSY)\npairing refused for device \
                 {fingerprint} (BUSY)\n"
            )
        );
        let mut out = Vec::new();
        note_outcome_to(&mut out, false, &outcomes[0], false);
        assert!(out.is_empty(), "not a terminal: nothing");
    }

    /// FX1-L2: `tornect host`'s own `Tornect ID:` line reaches stdout only on
    /// a terminal or with the evidence opt-in; a journal gets nothing.
    #[test]
    fn the_hosts_own_id_line_reaches_a_terminal_or_the_opt_in_only() {
        for (terminal, opted_in) in [(true, false), (false, true), (true, true), (false, false)] {
            let mut out = Vec::new();
            own_id_to(
                &mut out,
                terminal,
                opted_in,
                format_args!("Tornect ID: abcdefgh.onion"),
            );
            let expected = if terminal || opted_in {
                "Tornect ID: abcdefgh.onion\n"
            } else {
                ""
            };
            assert_eq!(
                String::from_utf8(out).unwrap(),
                expected,
                "{terminal} {opted_in}"
            );
        }
    }

    /// §B.8.7.4, A9 (the in-process half; the hook and the portal are
    /// NEEDS-DEVICE): a press of the panic key, told on a thread of the key's
    /// own as the platform's watcher tells it, ends a live session within
    /// 100 ms with `BYE{PANIC}`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panic_from_the_key_path_ends_sessions_within_100_ms() {
        let env = env();
        let consent = Arc::new(ScriptedConsent::new());
        consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
        consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            DirectWiring::for_test(0x33),
            consent,
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        let (client_end, host_end) = duplex(64 * 1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        let (identity, ccfg, cdeps) = client(&env);
        let mut session = match connect(client_end, &ccfg, &identity, &cdeps, Intent::Session)
            .await
            .unwrap()
        {
            ClientOutcome::Session(s) => s,
            other => panic!("expected a session, got {other:?}"),
        };
        session.send_tor_fallback(None).await.unwrap();
        session.ping().await.unwrap();
        assert_eq!(wiring.live.count(), 1);

        let presses = Arc::new(PanicPresses::new(wiring.deps.kill.clone(), None));
        let pressed = presses.pressed();
        let at = std::time::Instant::now();
        std::thread::spawn(move || pressed());
        let event = session
            .next_event(Duration::from_millis(100))
            .await
            .expect("the session ended within 100 ms");
        assert_eq!(
            event,
            Some(tornect_signal::fsm::client::SessionEvent::Bye {
                reason: bye::PANIC,
                detail: None
            })
        );
        assert!(
            at.elapsed() < Duration::from_millis(100),
            "{:?}",
            at.elapsed()
        );
        assert_eq!(host_task.await.unwrap(), Served::Session);
        assert_eq!(wiring.live.count(), 0);
    }

    /// §B.8.7.4: each press ends what the host serves, the kill first; a second
    /// press within 2 s also turns unattended access off, persisted, and says
    /// so; two presses further apart do not, and neither does a third press
    /// right after the pair (it starts a new pair).
    #[test]
    fn the_panic_key_pressed_twice_within_2_s_turns_unattended_access_off() {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::{Actor, SessionLog};
        use tornect_core::unattended::clock::SystemClock;
        use tornect_core::unattended::guard::{AllowAllReAuth, MutationGuard, NoSessionActivity};
        use tornect_core::unattended::store::GrantStore;

        let env = env();
        let secrets = Arc::new(FileSecretStore::open(env.paths.keys_dir()).unwrap());
        let store = GrantStore::open(
            &env.paths,
            secrets,
            Arc::new(SystemClock::default()),
            SessionLog::new(env.paths.sessions_log()),
        )
        .unwrap();
        let guard = Arc::new(
            MutationGuard::new(
                store,
                Arc::new(AllowAllReAuth::default()),
                Arc::new(NoSessionActivity),
                Arc::new(tornect_core::levels::FixedFacts::linux()),
            )
            .with_server_setup_source(Arc::new(
                tornect_signal::unattended::OpaqueServerSetupSource,
            )),
        );
        let on = |guard: &MutationGuard| {
            guard
                .master_on(Actor::Cli, env.identity.id().public_key_bytes())
                .unwrap();
        };
        let enabled = |guard: &MutationGuard| guard.store().read(|s| s.enabled).unwrap();
        on(&guard);
        let kill = KillSwitch::new();
        let presses = PanicPresses::new(kill.clone(), Some(Arc::clone(&guard)));
        let mut notes = presses.notes();
        let t0 = std::time::Instant::now();

        // Apart by more than 2 s: two single presses.
        let session = kill.arm();
        assert!(!presses.press(t0));
        assert_eq!(kill.fired(), Some(bye::PANIC), "the kill comes first");
        assert!(session.fired());
        assert!(!presses.press(t0 + Duration::from_millis(2_001)));
        assert!(enabled(&guard), "presses 2.001 s apart leave it on");
        assert!(notes.try_recv().is_err());

        // Within 2 s: off, persisted, and said.
        assert!(presses.press(t0 + Duration::from_millis(3_000)));
        assert!(!enabled(&guard));
        assert_eq!(notes.try_recv().unwrap(), PANIC_TWICE_NOTE);

        // A third press right after the pair starts a new pair.
        on(&guard);
        assert!(!presses.press(t0 + Duration::from_millis(3_500)));
        assert!(enabled(&guard));
    }

    /// The terminal's sessions sink tells a Control session's viewer the
    /// host's start code from the session's start on, through `notice`: 0 on
    /// a host that does not run Windows; on Windows, at the level none, the
    /// Windows bit and the administrator-windows bit. A view-only session's
    /// viewer is told nothing.
    #[tokio::test]
    async fn the_terminal_sink_tells_the_viewer_the_start_code() {
        let sessions = CliSessions {
            live: Arc::new(LiveSessions::new()),
            polkit: Arc::new(PolkitRevocation::for_this_host()),
            media: media(),
            control: ControlChannel::default(),
        };
        let token = tornect_signal::consent::SessionToken::new([5; 32]);
        let control = if cfg!(windows) { 0x03 } else { 0x00 };
        for (id, mode, want) in [
            ("c1", SessionMode::Control, Some(control)),
            ("v1", SessionMode::ViewOnly, None),
        ] {
            sessions.on_start(&LiveSession {
                device: DeviceIdentity::from_seed(&[9; 32]).id(),
                label: "Laptop",
                session_id: id,
                token: &token,
                th_final: [0; 32],
                mode,
                elevation: tornect_core::levels::Elevation::None,
                unattended: false,
                transport: TransportPolicy::Any,
                viewer_dir1: false,
            });
            assert_eq!(sessions.notice(id), want, "{id}");
            sessions.on_end(id, None);
        }
    }
}
