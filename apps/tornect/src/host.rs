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
use tornect_core::session_log::{SessionLog, SessionMode};
use tornect_core::unattended::limiter::{AttemptLimiter, HostTransport};
use tornect_core::unattended::schedule::FixedOffset;
use tornect_core::{Config, HostIdentity, Paths};
use tornect_platform::ipc::{Endpoint, IpcError};
use tornect_session::{
    CaptureStarted, MediaEnd, MediaHost, MediaObserver, MediaOutcome, MediaReport,
};
use tornect_signal::consent::TransportPolicy;
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
            reprobe_readiness(paths, Arc::clone(&c.guard), c.readiness.clone());
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
/// so. Suspending the grant behind an unattended session is not done here, as
/// `tornect panic` does not.
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

/// The readiness rows this computer can read now, for the host whose guard is
/// `guard` (§B.8.7.1 ⑥; the others stay `Unknown`).
fn probe_readiness(
    paths: &Paths,
    guard: &tornect_core::unattended::guard::MutationGuard,
) -> tornect_core::unattended::readiness::ReadinessSnapshot {
    use tornect_core::keystore::KeystoreKind;
    use tornect_core::unattended::grant::UnattendedGrant;
    let store = guard.store();
    let admin_grant = store
        .read(|s| s.grants.iter().any(UnattendedGrant::holds_level))
        .unwrap_or(false);
    let facts = tornect_platform::readiness::facts_now(
        &paths.state_dir,
        &paths.portal_restore_token(),
        store.keystore_kind() == KeystoreKind::File,
        WINDOW_HOST.load(Ordering::SeqCst),
        admin_grant,
    );
    tornect_platform::readiness::rows(&facts)
}

/// Probe the readiness rows again every 10 min into `feed` (§B.8.7.1 ⑥: a
/// screen-sharing grant lost, the panic key's portal gone).
fn reprobe_readiness(
    paths: &Paths,
    guard: Arc<tornect_core::unattended::guard::MutationGuard>,
    feed: tornect_core::unattended::readiness::SharedReadiness,
) {
    let paths = paths.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tornect_core::unattended::readiness::REPROBE_EVERY).await;
            let (paths, guard) = (paths.clone(), Arc::clone(&guard));
            match tokio::task::spawn_blocking(move || probe_readiness(&paths, &guard)).await {
                Ok(snapshot) => feed.set(snapshot),
                Err(e) => tracing::warn!(error = %e, "the readiness probe failed"),
            }
        }
    });
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
/// signs, `device_pk` is the host's device key (its QUIC identity, §B.6),
/// `media` serves the sessions' screens, and `control` says whether
/// `tornect panic` can reach this host when a session starts.
pub fn wire(
    paths: &Paths,
    cfg: &Config,
    identity: Arc<HostIdentity>,
    device_pk: [u8; 32],
    consent: Arc<dyn Consent>,
    media: Arc<MediaHost>,
    control: ControlChannel,
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
    let kill = KillSwitch::new();
    let live = Arc::new(LiveSessions::new());
    let polkit = Arc::new(PolkitRevocation::for_this_host());
    let ctx = match crate::unattended::host_context(paths, live.clone(), kill.clone()) {
        Ok(ctx) => Ok(ctx),
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
    deps.sessions = Arc::new(CliSessions {
        live: Arc::clone(&live),
        polkit: Arc::clone(&polkit),
        media,
        control,
    });
    deps.activity = live.clone();
    deps.kill = kill.clone();

    let mut host_cfg = HostConfig::new(cfg.general.device_name.clone(), device_pk);
    host_cfg.transport_policy =
        TransportPolicy::from_privacy(cfg.network.paranoid, cfg.network.lan_only);
    host_cfg.levels = levels;

    if let Ok(ctx) = &ctx {
        ctx.readiness.set(probe_readiness(paths, &ctx.guard));
        deps.stop_token = Arc::new(EmergencyStop::new(Arc::clone(&ctx.guard), kill));
        // M1 has no local-zone source (decision M1-15; a tzdb-backed zone is
        // M6). The zone only matters for grant schedules, and no path in this
        // build creates one: the presets have none and `tornect unattended
        // grant` sends none.
        deps.unattended = Arc::new(
            UnattendedAuth::new(
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
            .with_block_guard(Arc::clone(&ctx.guard)),
        );
        host_cfg.feats = vec![messages::feats::UA1.to_owned()];
    }

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

/// What `tornect host` says at start when stdin is not a terminal (the systemd
/// user unit of `tornect service install`, a pipe, a script).
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
    device_pk: [u8; 32],
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
                    device: tornect_core::DeviceId::from_bytes(device_pk),
                },
            );
            let mut wiring = wire(
                paths,
                cfg,
                identity,
                device_pk,
                Arc::new(CliConsent::new(Arc::clone(&prompter)).with_words(Arc::new(words))),
                media,
                control,
            )?;
            // The block window with Block, on this terminal (§B.8.6.3): it
            // goes before every question there. "Ask before starting" stays
            // denied (`AlwaysDeny`).
            wiring.deps.block_window =
                Arc::new(crate::term_block::TerminalBlockWindow::new(prompter));
            Ok(wiring)
        }
        None => Ok(wire(
            paths,
            cfg,
            identity,
            device_pk,
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
            tokio::spawn(async move {
                crate::secure_screen::run(
                    Arc::new(crate::secure_screen::WindowsDesktop),
                    crate::secure_screen::EVERY,
                    move || live.snapshot().iter().any(|s| s.session_id == id),
                    |shown| {
                        note(format_args!(
                            "{}",
                            if shown {
                                crate::secure_screen::NOTICE
                            } else {
                                crate::secure_screen::NOTICE_GONE
                            }
                        ));
                    },
                )
                .await;
            });
        }
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

    fn capture_stopped(&self, session_id: &str, report: &MediaReport, end: &MediaEnd) {
        say(format_args!("SHARING STOPPED {session_id}"));
        note(format_args!(
            "screen sharing stopped ({}): {} pictures, {} KiB sent",
            describe_media_end(*end),
            report.frames_sent,
            report.bytes_sent / 1024
        ));
    }
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

/// A `tornect_proto::reason` for people.
pub fn media_reason(reason: u16) -> &'static str {
    use tornect_proto::reason as r;
    match reason {
        r::BAD_BIND => "the session did not match",
        r::CAPTURE_FAILED => "screen capture failed",
        r::ENDED_BY_HOST => "ended by the host",
        r::ENDED_BY_VIEWER => "ended by the viewer",
        r::SESSION_OVER => "the session ended",
        r::PROTOCOL => "protocol error",
        r::ENCODER_FAILED => "the video encoder failed",
        _ => "unknown reason",
    }
}

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
        MediaOutcome::Served { .. } => return None,
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
    use tornect_signal::fsm::client::{
        ClientConfig, ClientDeps, ClientOutcome, Intent, ScriptedClientUi, connect,
    };
    use tornect_signal::pairing::{
        KnownHostStore, PairDecision, PairScript, ScriptedConsent, SessionDecision, SessionScript,
    };

    use super::*;

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

    /// The FSM audits into the host's `sessions.log`, and a host whose store
    /// opened offers the unattended suite.
    #[test]
    fn the_fsm_audits_into_the_hosts_log() {
        let env = env();
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            [9; 32],
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
            vec![messages::feats::UA1.to_owned()],
            "a host with a store offers the unattended suite"
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
            [9; 32],
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
            [9; 32],
            Some(prompter),
            media(),
            ControlChannel::default(),
        )
        .unwrap();
        assert_eq!(terminal.cfg.feats, vec![messages::feats::UA1.to_owned()]);
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
                    [9; 32],
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
            host_device_pk,
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
            [9; 32],
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
            [9; 32],
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
            host_device_pk,
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
                host_device_pk,
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
            host_device_pk,
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
                host_device_pk,
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
                host_device_pk,
                Arc::new(ScriptedConsent::new()),
                media(),
                ControlChannel::default(),
            )
            .unwrap();
            assert_eq!(wiring.cfg.feats, vec![messages::feats::UA1.to_owned()]);
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
            host_device_pk,
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
            HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32])),
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
        session.send_tor_fallback().await.unwrap();
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
            [9; 32],
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
            HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32])),
            consent,
            media(),
            control.clone(),
        )
        .unwrap();
        assert!(ctx.is_err(), "the store is held elsewhere");
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
        session.send_tor_fallback().await.unwrap();
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
            HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32])),
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
        session.send_tor_fallback().await.unwrap();
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
}
