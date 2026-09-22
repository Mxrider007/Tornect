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
use std::io::Write as _;
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
    HostConfig, HostDeps, HostOutcome, KillSwitch, LiveSession, LiveSessions, SessionEnd,
    SessionSink, serve_host,
};
use tornect_signal::messages::{self, bye, pair_reject, reject};
use tornect_signal::pairing::{Consent, TrustedDeviceStore};
use tornect_signal::ping::{self, ServeLimits};
use tornect_signal::unattended::{EmergencyStop, GuardAdmin, UnattendedAuth};

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
/// A platform without an endpoint (Windows until M6) or a failed bind is not
/// fatal: the host says that Ctrl-C ends its sessions. Another host serving
/// this state directory is.
pub async fn start_control_channel(
    paths: &Paths,
    ctx: Result<HostContext, String>,
    kill: KillSwitch,
    control: ControlChannel,
) -> anyhow::Result<Option<JoinHandle<()>>> {
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
    let kill = KillSwitch::new();
    let live = Arc::new(LiveSessions::new());
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
    let trusted = Arc::new(
        TrustedDeviceStore::open(paths.trusted_devices_file())
            .context("opening the trusted-devices store")?,
    );
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
        media,
        control,
    });
    deps.activity = live.clone();
    deps.kill = kill.clone();

    let mut host_cfg = HostConfig::new(cfg.general.device_name.clone(), device_pk);
    host_cfg.transport_policy =
        TransportPolicy::from_privacy(cfg.network.paranoid, cfg.network.lan_only);

    if let Ok(ctx) = &ctx {
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
            )
            .with_admin_authority(Arc::new(GuardAdmin::new(Arc::clone(&ctx.guard)))),
        );
        host_cfg.feats = vec![messages::feats::UA1.to_owned()];
    }

    Ok(HostWiring {
        cfg: host_cfg,
        deps,
        ctx,
        live,
        audit,
    })
}

/// The CLI's [`SessionSink`]: records each session in the tracker, hands it to
/// the media layer, and says on the terminal when one starts and ends.
struct CliSessions {
    live: Arc<LiveSessions>,
    media: Arc<MediaHost>,
    control: ControlChannel,
}

impl SessionSink for CliSessions {
    fn on_start(&self, session: &LiveSession<'_>) {
        self.live.on_start(session);
        self.media.on_start(session);
        say(format_args!("SESSION LIVE {}", session.session_id));
        note(format_args!(
            "session with \"{}\" is live ({}{}); {} ends it",
            session.label,
            mode_name(session.mode),
            if session.unattended {
                ", unattended"
            } else {
                ""
            },
            self.control.kill_path(),
        ));
    }

    fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
        // Media first: that is what stops capture.
        self.media.on_end(session_id, end);
        self.live.on_end(session_id, end);
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
        note(format_args!(
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

fn describe_media_end(end: MediaEnd) -> String {
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
        MediaOutcome::Busy => "media stream closed: too many are waiting to bind".to_owned(),
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
fn say(line: fmt::Arguments<'_>) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}").and_then(|()| out.flush());
}

/// [`say`] for stderr.
fn note(line: fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

fn mode_name(mode: SessionMode) -> &'static str {
    match mode {
        SessionMode::ViewOnly => "view-only",
        _ => "control",
    }
}

fn describe_end(end: &SessionEnd) -> String {
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
                if let Some(line) = describe_outcome(&outcome) {
                    eprintln!("{line}");
                }
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

/// One line for a handshake that ended without a live session (the sink
/// already reported the ones that had one).
fn describe_outcome(outcome: &HostOutcome) -> Option<String> {
    Some(match outcome {
        HostOutcome::PairRejected { device, reason } => format!(
            "pairing refused for device {} ({})",
            device.fingerprint(),
            pair_reject::name(*reason)
        ),
        HostOutcome::PairedOnly { label, .. } => {
            format!("paired with \"{label}\"; it left without asking for a session")
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
}
