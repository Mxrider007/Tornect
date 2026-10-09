//! The tokio side of the window: Tor, hosting (the handshake FSM with the
//! window's consent seams, the media host, the control channel) and viewing
//! (the client handshake and the media viewer), reporting into the model and
//! taking the window's [`Command`]s. It reuses what `tornect host` and
//! `tornect connect` run, so both paths share their fixes.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tornect_core::levels::Elevation;
use tornect_core::session_log::SessionMode;
use tornect_core::{Config, DeviceIdentity, HostIdentity, Paths, TornectId};
use tornect_input::InputEvent;
use tornect_session::{
    CaptureStarted, MediaEnd, MediaHost, MediaLimits, MediaObserver, MediaReport, Source,
    SystemBackend,
};
use tornect_signal::fsm::client::{
    self, ClientConfig, ClientDeps, ClientOutcome, Intent, NoServerKeyPin,
};
use tornect_signal::fsm::host::{
    HostConfig, HostDeps, KillSwitch, LiveSession, LiveSessions, SessionActivity as _, SessionEnd,
    SessionSink,
};
use tornect_signal::fsm::{HandshakeError, HostAudit, OsRandom};
use tornect_signal::messages::{bye, pair_reject, reject};
use tornect_signal::pairing::AutoDeny;
#[cfg(test)]
use tornect_signal::pairing::KnownHostStore;
use tornect_signal::tor::{Ladder, LadderEvent, OnionListener};
use tornect_signal::{Isolation, MEDIA_PORT, SIGNALING_PORT, TorNode};

use super::block::GuiBlockWindow;
use super::book::{self, Change};
use super::consent::{CodeCheck, GuiConsent, GuiPairingUi, Popups, Withdraw};
use super::model::{
    CaptureNote, Check, ClientStage, Dial, Failure, Hosting, Settings, SettingsChange, Shared,
    Sharing, TorState, UnattendedBanner, Viewing, Wake,
};
use super::recognize::Lookalike;
use super::stream::{FrameSlot, SlotSink};
use crate::host::{
    ControlChannel, HostLock, HostWiring, PolkitRevocation, describe_end, describe_media, note,
    say, say_evidence,
};
use crate::tor_cmd::{End, explain, explain_handshake};
use crate::ua_client::{self, AdminAction, Logged};

/// Input events queued for the media stream; one beyond that is dropped (the
/// host's own budget is 250/s with a burst of 500).
const INPUT_QUEUE: usize = 256;
/// How long the owner has to answer the desktop's dialog at the setup step:
/// they are at the desk, having just clicked.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const GRANT_WAIT: Duration = Duration::from_secs(120);
/// How long shutting down waits for the streams' goodbyes.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

/// What the window asks the tokio side to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// View the host with this ID (an ID not in the address book is checked
    /// against the saved ones first, §B.6.1 item 4).
    Connect(TornectId),
    /// View it although it looks like a saved one: only after the warning
    /// for this very ID.
    ConnectAnyway(TornectId),
    /// End the session being viewed.
    EndViewing,
    /// End the session this screen is shared with (a host-wide kill).
    StopSharing,
    /// The first-run desktop grant.
    Grant,
    /// Forget the desktop's remembered grant.
    Revoke,
    /// Check once whether this computer answers: one pairing-free ping over
    /// Tor (never repeated, never in the background).
    Ping(TornectId),
    /// Forget this computer: its pin, its saved name, its history.
    ForgetHost(TornectId),
    /// Name this computer (empty: remove the saved name).
    RenameHost(TornectId, String),
    /// Save a computer by its ID, with a name.
    SaveEntry(TornectId, String),
    /// Clear the history of connections.
    ClearHistory,
    /// Keep a history of connections, or stop keeping one.
    SetHistory(bool),
    /// Save one change of the settings pages in `config.toml`. Never an
    /// operation of §B.8.6.2: those run through the unattended guard.
    SaveSettings(SettingsChange),
    /// Open the password prompt for `id`, for a session or an admin command
    /// (with the other device an Unlock names) (§B.8.10).
    AskPassword(TornectId, Option<AdminAction>, Option<[u8; 32]>),
    /// Connect to `id` without asking, as chosen in the prompt: one attempt.
    ConnectUnattended(TornectId, UaChoice),
    /// Send one admin command to `id` (with the other device an Unlock
    /// names), as chosen in the prompt.
    Admin(TornectId, AdminAction, Option<[u8; 32]>, UaChoice),
    /// The person read that `id`'s unattended setup was re-created (A16).
    ConfirmSetupChanged(TornectId),
    /// Work out the device words of a device key typed into the Unlock
    /// confirmation (F4-4).
    DeviceWords([u8; 32]),
    /// Acknowledge the banner of devices that can connect without asking,
    /// with re-authentication (§B.8.6.2).
    AcknowledgeBanner,
    /// Background mode: show or take down the desktop notification that
    /// mirrors a host sheet (§B.1.1).
    Notice(super::notice::NoticeChange),
    /// Shut down.
    Quit,
}

/// A password on its way from the prompt to the attempt: wiped on drop,
/// never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(pub zeroize::Zeroizing<String>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// What the person chose in the prompt (§B.8.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UaChoice {
    /// The password typed; `None`: the remembered one.
    pub password: Option<Secret>,
    /// "View only this time".
    pub view_only: bool,
    /// "Remember on this device" (only where offered).
    pub remember: bool,
    /// "Ask for administrator access" (only where offered).
    pub administrator: bool,
}

/// What the viewer and the stream window share: the newest picture, and while
/// a control session runs, the way to the host for input.
#[derive(Debug, Default)]
pub struct StreamLink {
    /// The newest picture.
    pub slot: Arc<FrameSlot>,
    input: Mutex<Input>,
}

/// The way to the host for input, while a control session runs.
#[derive(Debug, Default)]
struct Input {
    tx: Option<mpsc::Sender<InputEvent>>,
    /// A release (a key-up, a button-up or `ReleaseAll`) found the queue full:
    /// a `ReleaseAll` goes out before anything else once there is room, so no
    /// key or button stays down on the host (SLICE-E E1-6).
    owed: bool,
}

impl StreamLink {
    fn set_input(&self, tx: Option<mpsc::Sender<InputEvent>>) {
        *self.input.lock().unwrap_or_else(PoisonError::into_inner) = Input { tx, owed: false };
    }

    /// Queue `event` for the host; `false` when there is no control session
    /// or the queue is full (never blocks the UI thread). A release that finds
    /// the queue full is not lost: a `ReleaseAll` is owed, and goes out first
    /// here or at [`StreamLink::settle`] once there is room.
    pub fn send(&self, event: InputEvent) -> bool {
        let mut guard = self.input.lock().unwrap_or_else(PoisonError::into_inner);
        let input = &mut *guard;
        let Some(tx) = &input.tx else {
            return false;
        };
        if input.owed {
            if tx.try_send(InputEvent::ReleaseAll).is_err() {
                return false;
            }
            input.owed = false;
        }
        match tx.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                input.owed |= event.is_release();
                false
            }
            // The session is over; its end releases everything on the host.
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Send an owed `ReleaseAll` if the queue has room now; whether one is
    /// still owed (the window then tries again soon).
    pub fn settle(&self) -> bool {
        let mut guard = self.input.lock().unwrap_or_else(PoisonError::into_inner);
        let input = &mut *guard;
        if input.owed
            && let Some(tx) = &input.tx
            && tx.try_send(InputEvent::ReleaseAll).is_ok()
        {
            input.owed = false;
        }
        input.owed
    }
}

/// Everything the tokio side starts from.
pub struct Backend {
    /// This instance's directories.
    pub paths: Paths,
    /// Its configuration (with the command line's overrides).
    pub cfg: Config,
    /// The model.
    pub shared: Arc<Shared>,
    /// The popups.
    pub popups: Arc<Popups>,
    /// The stream window's link.
    pub link: Arc<StreamLink>,
    /// What a shared session shows.
    pub source: Source,
    /// Whether to publish this ID and answer requests.
    pub host: bool,
    /// The host identity (the onion service key).
    pub identity: Arc<HostIdentity>,
    /// The device identity (what hosts pin when this machine connects).
    pub device: Arc<DeviceIdentity>,
    /// The device key's public half.
    pub device_pk: [u8; 32],
    /// The device words and the look-alike alarm of this home (§B.6.1).
    pub words: Arc<super::recognize::Recognizer>,
    /// Started in background mode (`tornect --background`, §B.1.1): the
    /// "indicator shown" fact the window's probe sets, which the host's
    /// readiness row and its gate on unattended sessions read. `None` for a
    /// window started by hand.
    pub background: Option<crate::host::IndicatorShown>,
}

/// Whether this is the window's first run in the home `paths`: the first
/// time, a marker is left in the state directory so that the history notice
/// shows once. The marker says nothing about any connection. When it cannot
/// be written the notice shows again next time.
fn first_run(paths: &Paths) -> bool {
    let marker = paths.state_dir.join("history-notice-shown");
    if marker.exists() {
        return false;
    }
    if let Err(e) =
        std::fs::create_dir_all(&paths.state_dir).and_then(|()| std::fs::write(&marker, b""))
    {
        tracing::debug!(error = %e, "the history notice will show again");
    }
    true
}

/// The settings page's line when a change was not saved because this screen
/// may be in a picture that leaves it (the change may not be this
/// computer's user's own).
const NOT_SAVED_SHARED: &str = "Not saved: this screen is shared.";

/// The settings page's line when `config.toml` could not be read or
/// written (the reason goes to the log, which may name the path).
const NOT_SAVED_FILE: &str = "Not saved: the settings file could not be read or written.";

/// Save one settings change: `config.toml` as it is now, with the change,
/// checked and written back; the model then holds what was saved. Nothing is
/// saved while this screen may be in a picture that leaves it.
fn save_settings(paths: &Paths, shared: &Shared, change: &SettingsChange) {
    if shared.read(|m| m.screen_shared(Instant::now())) {
        shared.update(|m| m.settings.problem = Some(NOT_SAVED_SHARED));
        return;
    }
    let path = paths.config_file();
    let saved = Config::load(&path).and_then(|mut cfg| {
        change.apply(&mut cfg);
        cfg.save(&path).map(|()| cfg)
    });
    match saved {
        Ok(cfg) => shared.update(|m| m.settings = Settings::of(&cfg)),
        Err(e) => {
            tracing::warn!(error = %e, "the settings were not saved");
            shared.update(|m| m.settings.problem = Some(NOT_SAVED_FILE));
        }
    }
}

/// How often a window that is not the host looks whether another Tornect
/// process holds this home's host lock.
const HOST_LOCK_EVERY: Duration = Duration::from_secs(2);

/// How often the banner of devices that can connect without asking is read
/// again from the host's store and log.
const BANNER_EVERY: Duration = Duration::from_secs(30);

/// The banner of §B.8.6.2 for the window host: read from its guard's store
/// (how many devices can connect without asking) and log (the last grant
/// created, changed, enabled or given a new password, which is how a raise to
/// the administrator level is logged, unattended access turned on or resumed,
/// or backup exported, and who did it), until that change is acknowledged with
/// re-authentication, which is kept in memory only.
struct BannerWatch {
    guard: Arc<tornect_core::unattended::guard::MutationGuard>,
    acknowledged: Mutex<Option<String>>,
}

impl BannerWatch {
    /// The devices that can connect without asking now, and the last change.
    fn read(&self) -> (usize, Option<(String, &'static str)>) {
        use tornect_core::session_log::{Actor, SessionEvent};
        use tornect_core::unattended::grant::GrantState;
        let now = tornect_core::trusted::unix_now();
        let store = self.guard.store();
        let devices = store
            .read(|s| {
                if !s.enabled || s.paused_until.is_some_and(|until| until > now) {
                    0
                } else {
                    s.grants
                        .iter()
                        .filter(|g| matches!(g.state, GrantState::Active))
                        .count()
                }
            })
            .unwrap_or(0);
        let last = store.log().read_all().ok().and_then(|records| {
            records
                .iter()
                .rev()
                .find(|r| {
                    matches!(
                        r.event,
                        SessionEvent::GrantCreated
                            | SessionEvent::GrantChanged
                            | SessionEvent::GrantEnabled
                            | SessionEvent::PasswordSet
                            | SessionEvent::UnattendedEnabled
                            | SessionEvent::UnattendedResumed
                            | SessionEvent::BackupExported
                    )
                })
                .map(|r| {
                    let by = match r.by {
                        Some(Actor::Ui) => "ui",
                        Some(Actor::Cli) => "cli",
                        Some(Actor::Import) => "import",
                        Some(Actor::Restore) => "restore",
                        None => "unknown",
                    };
                    (r.ts.clone(), by)
                })
        });
        (devices, last)
    }

    /// Put the banner as it is now into the model.
    fn refresh(&self, shared: &Shared) {
        let (devices, last) = self.read();
        let acknowledged = self
            .acknowledged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let banner = UnattendedBanner::of(devices, last, acknowledged.as_deref());
        if shared.read(|m| m.unattended_banner != banner) {
            shared.update(|m| m.unattended_banner = banner);
        }
    }

    /// Acknowledge the banner as it is now: the host's re-authentication (an
    /// access-increasing kind of operation, so never during a remote session,
    /// §B.8.6.2), then the banner goes until a newer change.
    fn acknowledge(&self, shared: &Shared) {
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::guard::ExternalOp;
        let (_, last) = self.read();
        let asked = self.guard.authorize(
            Actor::Ui,
            &ExternalOp::SettingsChange {
                what: "acknowledge the banner of devices that can connect without asking".into(),
            },
        );
        match asked {
            Ok(()) => {
                *self
                    .acknowledged
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) =
                    Some(last.map(|(at, _)| at).unwrap_or_default());
                self.refresh(shared);
            }
            Err(e) => shared.update(|m| m.note(format!("The banner stays: {e}"))),
        }
    }
}

/// The host role, once wired.
struct Hosted {
    serving: Arc<(HostConfig, HostDeps)>,
    /// The banner of devices that can connect without asking (a host with its
    /// unattended store).
    banner: Option<Arc<BannerWatch>>,
    media: Arc<MediaHost>,
    live: Arc<LiveSessions>,
    audit: Arc<HostAudit>,
    ipc: Option<JoinHandle<()>>,
    kill_watch: JoinHandle<()>,
    pins: Arc<crate::history::DevicePins>,
    _lock: HostLock,
}

/// The window's [`SessionSink`]: the tracker, the media layer, then the
/// sharing indicator, and a bump of the counter that withdraws open popups.
struct GuiSessions {
    live: Arc<LiveSessions>,
    /// polkit's remembered approvals, revoked during Control sessions.
    polkit: Arc<PolkitRevocation>,
    media: Arc<MediaHost>,
    shared: Arc<Shared>,
    started: watch::Sender<u64>,
}

impl SessionSink for GuiSessions {
    fn on_start(&self, session: &LiveSession<'_>) {
        self.live.on_start(session);
        crate::secure_screen::on_start(&self.live, session, cfg!(windows));
        self.polkit.on_start(session);
        self.media.on_start(session);
        self.started.send_modify(|n| *n = n.wrapping_add(1));
        let control = session.mode == SessionMode::Control;
        // The level the host signed in the accept (H5): never inferred from
        // the answer given on the sheet.
        let admin = control && session.elevation == Elevation::Admin;
        let sharing = Sharing {
            session_id: session.session_id.to_owned(),
            label: session.label.to_owned(),
            control,
            unattended: session.unattended,
            since: Instant::now(),
            capture: None,
        };
        self.shared.update(|m| {
            m.note(format!(
                "session with \"{}\" started ({})",
                session.label,
                if control { "control" } else { "view only" }
            ));
            if admin {
                m.admin_sessions.insert(session.session_id.to_owned());
            }
            m.sharing.push(sharing);
        });
        self.shared.wake(Wake::Attention);
        say(format_args!("SESSION LIVE {}", session.session_id));
        // §B.8.8: a secure Windows screen (a UAC prompt, Ctrl+Alt+Del, the
        // lock screen) is out of the session's reach; said while it shows.
        #[cfg(windows)]
        if control {
            let (shared, id) = (Arc::clone(&self.shared), session.session_id.to_owned());
            let (sessions, told_id) = (Arc::clone(&self.live), id.clone());
            tokio::spawn(async move {
                let live = {
                    let shared = Arc::clone(&shared);
                    move || shared.read(|m| m.sharing.iter().any(|s| s.session_id == id))
                };
                crate::secure_screen::run(
                    Arc::new(crate::secure_screen::WindowsDesktop),
                    crate::secure_screen::EVERY,
                    live,
                    move |shown| {
                        // The viewer is told too, by the bit its PONGs carry.
                        let line = crate::secure_screen::on_change(&sessions, &told_id, shown);
                        tracing::info!("{line}");
                        shared.update(|m| m.note(line.to_owned()));
                    },
                )
                .await;
            });
        }
    }

    fn notice(&self, session_id: &str) -> Option<u8> {
        self.live.notice(session_id)
    }

    fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
        // Media first: that is what stops capture.
        self.media.on_end(session_id, end);
        self.live.on_end(session_id, end);
        self.polkit.on_end(session_id);
        let why = end.map_or_else(|| "protocol error".to_owned(), describe_end);
        self.shared.update(|m| {
            m.sharing.retain(|s| s.session_id != session_id);
            m.admin_sessions.remove(session_id);
            if m.sharing.is_empty() {
                m.polkit_warning = None;
            }
            m.note(format!("session ended: {why}"));
        });
        say(format_args!("SESSION ENDED {session_id}"));
        note(format_args!("session ended: {why}"));
    }
}

/// The window's [`MediaObserver`]: what capture does, on the banner and on
/// stdout (the evidence lines `tornect host` prints too).
struct GuiMedia {
    shared: Arc<Shared>,
}

impl MediaObserver for GuiMedia {
    fn capture_started(&self, s: &CaptureStarted<'_>) {
        let capture = CaptureNote {
            source: s.source,
            width: s.width,
            height: s.height,
            input: s.input,
        };
        self.shared.update(|m| {
            if let Some(sharing) = m.sharing.iter_mut().find(|x| x.session_id == s.session_id) {
                sharing.capture = Some(capture);
            }
        });
        say(format_args!("SHARING {}", s.session_id));
        // The window's stderr names nobody (the banner does, on screen).
        note(format_args!(
            "sharing this screen ({} {}x{}; input {})",
            s.source,
            s.width,
            s.height,
            if s.input { "injected" } else { "not injected" }
        ));
    }

    fn capture_stopped(&self, session_id: &str, report: &MediaReport, end: &MediaEnd) {
        say(format_args!("SHARING STOPPED {session_id}"));
        let line = format!(
            "screen sharing stopped ({}): {} pictures, {} KiB sent; input {} injected, {} dropped",
            crate::host::describe_media_end(*end),
            report.frames_sent,
            report.bytes_sent / 1024,
            report.input_injected,
            report.input_dropped
        );
        note(format_args!("{line}"));
        self.shared.update(|m| m.note(line));
    }
}

/// The window host's raise for `IpcOp::Show` (§B.1.1): a wake of the window's
/// event loop (`Wake::Show`). It holds the model's waker only, so it cannot
/// answer, dismiss or re-order a sheet.
fn show_hook(shared: Arc<Shared>) -> crate::unattended::ShowHook {
    Arc::new(move || shared.wake(Wake::Show))
}

/// Wire the host role: the FSM with the window's consent, the media host, and
/// the control channel (bound before Tor, as `tornect host` does).
async fn host_role(b: &Backend) -> Result<Hosted, String> {
    let lock = HostLock::acquire(&b.paths).map_err(|e| format!("{e:#}"))?;
    // Its indicator is a window on top (the readiness row "indicator shown").
    crate::host::this_is_the_window_host();
    let control = ControlChannel::default();
    // An administrator session's input goes through its administrator
    // helper (§B.8.7.5), started between the answer and the accept.
    let helpers = crate::admin_helper::AdminHelpers::new();
    let media = Arc::new(MediaHost::new(
        Arc::new(crate::admin_helper::AdminBackend::new(
            Arc::new(
                SystemBackend::new(b.source).with_restore_token(b.paths.portal_restore_token()),
            ),
            Arc::clone(&helpers),
        )),
        Arc::new(GuiMedia {
            shared: Arc::clone(&b.shared),
        }),
        MediaLimits::default(),
    ));
    let HostWiring {
        cfg,
        mut deps,
        ctx,
        live,
        audit,
        pins,
        polkit,
    } = crate::host::wire_window(
        &b.paths,
        &b.cfg,
        Arc::clone(&b.identity),
        b.device_pk,
        Arc::new(AutoDeny),
        Arc::clone(&media),
        control.clone(),
        b.background.clone(),
    )
    .map_err(|e| format!("{e:#}"))?;
    helpers.wire(deps.kill.clone(), audit.clone(), cfg.levels);
    deps.admin_helper = helpers;
    // The window says it, on Home and under the banner.
    let shared = Arc::clone(&b.shared);
    polkit.tell_through(Arc::new(move |line: &str| {
        let line = line.to_owned();
        shared.update(|m| {
            m.polkit_warning = Some(line.clone());
            m.note(line);
        });
    }));
    let (started_tx, started) = watch::channel(0u64);
    let activity = Arc::clone(&live);
    let consent = Arc::new(
        GuiConsent::new(
            Arc::clone(&b.popups),
            Withdraw {
                kill: deps.kill.clone(),
                started,
                live: Arc::new(move || activity.session_live()),
            },
        )
        .with_words(Arc::clone(&b.words)),
    );
    deps.consent = consent.clone();
    // Before an unattended session (§B.8.6.3): "Ask before starting" on the
    // same sheets, withdrawn alike, and the block window on every monitor.
    deps.local_allow = consent;
    deps.block_window = Arc::new(GuiBlockWindow::new(Arc::clone(&b.popups)));
    deps.sessions = Arc::new(GuiSessions {
        live: Arc::clone(&live),
        polkit: Arc::clone(&polkit),
        media: Arc::clone(&media),
        shared: Arc::clone(&b.shared),
        started: started_tx,
    });
    let kill_watch = media.watch_kill(deps.kill.clone());
    let banner = ctx.as_ref().ok().map(|c| {
        Arc::new(BannerWatch {
            guard: Arc::clone(&c.guard),
            acknowledged: Mutex::new(None),
        })
    });
    if let Some(watch) = &banner {
        let (watch, shared) = (Arc::clone(watch), Arc::clone(&b.shared));
        tokio::spawn(async move {
            let mut every = tokio::time::interval(BANNER_EVERY);
            loop {
                every.tick().await;
                let (watch, shared) = (Arc::clone(&watch), Arc::clone(&shared));
                let _ = tokio::task::spawn_blocking(move || watch.refresh(&shared)).await;
            }
        });
    }
    // A second launch raises this window through the control channel
    // (`IpcOp::Show`, §B.1.1).
    let ctx = ctx.map(|mut c| {
        c.show = Some(show_hook(Arc::clone(&b.shared)));
        c
    });
    let ipc = crate::host::start_control_channel(&b.paths, ctx, deps.kill.clone(), control)
        .await
        .map_err(|e| format!("{e:#}"))?;
    // What the panic key says (pressed twice: unattended access off), in the
    // window's recent activity.
    if let Some(mut notes) = crate::host::panic_key_notes() {
        let shared = Arc::clone(&b.shared);
        tokio::spawn(async move {
            while let Ok(line) = notes.recv().await {
                shared.update(|m| m.note(line));
            }
        });
    }
    Ok(Hosted {
        serving: Arc::new((cfg, deps)),
        banner,
        media,
        live,
        audit,
        ipc,
        kill_watch,
        pins,
        _lock: lock,
    })
}

/// Reach the Tor network through the bridge ladder (decision M1-38),
/// showing each step in the window.
async fn start_tor(paths: Paths, cfg: Config, shared: Arc<Shared>) -> anyhow::Result<TorNode> {
    let ladder = Ladder::from_config(&paths, &cfg.tor);
    for line in &ladder.rejected_lines {
        shared.update(|m| m.note(format!("tor: ignoring {line}")));
    }
    let events = Arc::clone(&shared);
    TorNode::start_auto(&paths, &cfg, &ladder, move |event| {
        let state = match event {
            LadderEvent::Trying { rung, attempt, of } => TorState::Trying {
                via: rung.describe(),
                attempt: *attempt,
                of: *of,
            },
            LadderEvent::Progress {
                rung,
                fraction,
                blocked,
            } => TorState::Progress {
                via: rung.describe(),
                pct: (fraction * 100.0).round() as u32,
                blocked: blocked.clone(),
            },
            LadderEvent::Ready { rung } => TorState::Ready {
                via: rung.describe(),
            },
            LadderEvent::Skipped { rung, reason } => {
                let line = format!("tor: {} unavailable: {reason}", rung.describe());
                events.update(|m| m.note(line));
                return;
            }
            LadderEvent::Failed { rung, reason } => {
                let line = format!("tor: {} did not work: {reason}", rung.describe());
                events.update(|m| m.note(line));
                return;
            }
            _ => return,
        };
        events.update(|m| m.tor = state);
    })
    .await
    .map_err(explain)
}

/// Keep the hosting line current with the onion service's reachability.
fn watch_reachability(listener: &OnionListener, shared: Arc<Shared>) -> JoinHandle<()> {
    let mut rx = listener.status();
    tokio::spawn(async move {
        let mut announced = false;
        loop {
            let s = rx.borrow_and_update().clone();
            if s.reachable && !announced {
                say(format_args!("REACHABLE"));
                announced = true;
            }
            shared.update(|m| {
                m.hosting = Hosting::Published {
                    reachable: s.reachable,
                    state: s.state,
                    problem: s.problem,
                };
            });
            if rx.changed().await.is_err() {
                break;
            }
        }
    })
}

/// The first-run grant's desktop check: only a Wayland desktop this machine
/// shares has one.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn grant(token: std::path::PathBuf) -> Result<(bool, bool), String> {
    let options = tornect_capture::wayland::WaylandOptions {
        dialog_wait: GRANT_WAIT,
        ..tornect_capture::wayland::WaylandOptions::new(Some(token))
    };
    tornect_capture::wayland::grant(&options)
        .map(|g| (g.input, g.remembered))
        .map_err(|e| e.to_string())
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn grant(_: std::path::PathBuf) -> Result<(bool, bool), String> {
    Err("this desktop needs no grant".to_owned())
}

/// Put the diagnostics report of Settings, About into the model, gathered
/// off the command loop (it reads the keystore, the log and lyrebird).
fn refresh_diagnostics(b: &Backend) {
    let (paths, cfg, shared) = (b.paths.clone(), b.cfg.clone(), Arc::clone(&b.shared));
    tokio::task::spawn_blocking(move || {
        let report = crate::diagnostics::report(&crate::diagnostics::gather(&paths, &cfg));
        shared.update(|m| m.diagnostics = report);
    });
}

/// Run until [`Command::Quit`], then shut down and mark the model closed.
pub async fn run(b: Backend, mut commands: mpsc::UnboundedReceiver<Command>) {
    let b = Arc::new(b);
    let first = first_run(&b.paths);
    b.shared.update(|m| m.history_notice = first);
    refresh_diagnostics(&b);
    // Background mode: the desktop notifications that mirror the host's
    // sheets (§B.1.1).
    let notices = b
        .background
        .is_some()
        .then(|| super::notice::start(Arc::clone(&b.shared)));
    // The pairing times of known-hosts.toml past their first day (P-L4).
    crate::history::coarsen_pins(&b.paths);
    // This computer's words and the saved keys' (derived once, off this
    // task), then the address book again with its words.
    {
        let b = Arc::clone(&b);
        tokio::spawn(async move {
            let words = Arc::clone(&b.words);
            if let Ok(mine) = tokio::task::spawn_blocking(move || {
                let mine = words.mine();
                words.warm();
                mine
            })
            .await
            {
                b.shared.update(|m| m.mine = mine);
                refresh_book(&b, None);
            }
        });
    }
    let hosted = if b.host {
        match host_role(&b).await {
            Ok(hosted) => Some(hosted),
            Err(why) => {
                b.shared.update(|m| m.hosting = Hosting::Off(why));
                None
            }
        }
    } else {
        None
    };
    // Not the host here: another Tornect process may be, and may share this
    // screen, which this window cannot see. While one holds the host lock,
    // the window hides what it hides while sharing.
    if hosted.is_none() {
        let b = Arc::clone(&b);
        tokio::spawn(async move {
            let mut every = tokio::time::interval(HOST_LOCK_EVERY);
            loop {
                every.tick().await;
                let paths = b.paths.clone();
                let held = tokio::task::spawn_blocking(move || HostLock::holder(&paths).is_some())
                    .await
                    .unwrap_or(true);
                if b.shared.read(|m| m.hosted_elsewhere) != held {
                    b.shared.update(|m| m.hosted_elsewhere = held);
                }
            }
        });
    }

    // Tor starts on a task of its own and is never cancelled: the ladder owns
    // runtimes that must not be dropped inside this one.
    let mut tor_start = Some(tokio::spawn(start_tor(
        b.paths.clone(),
        b.cfg.clone(),
        Arc::clone(&b.shared),
    )));
    let mut node: Option<Arc<TorNode>> = None;
    let mut listener: Option<OnionListener> = None;
    let mut status: Option<JoinHandle<()>> = None;
    let mut publish: Option<JoinHandle<anyhow::Result<OnionListener>>> = None;
    let mut viewing: Option<(watch::Sender<bool>, JoinHandle<()>)> = None;
    let mut granting: Option<JoinHandle<Result<(bool, bool), String>>> = None;
    let slots = Arc::new(Semaphore::new(tornect_signal::tor::MAX_LIVE_CIRCUITS));
    let mut media_streams = JoinSet::new();

    loop {
        tokio::select! {
            started = async { tor_start.as_mut().expect("guarded").await }, if tor_start.is_some() => {
                tor_start = None;
                // The way into Tor that worked is known now.
                refresh_diagnostics(&b);
                match started {
                    Ok(Ok(started)) => {
                        let started = Arc::new(started);
                        if hosted.is_some() {
                            b.shared.update(|m| m.hosting = Hosting::Publishing);
                            let (n, identity) = (Arc::clone(&started), Arc::clone(&b.identity));
                            publish = Some(tokio::spawn(async move {
                                n.publish(&identity).await.map_err(explain)
                            }));
                        }
                        node = Some(started);
                    }
                    Ok(Err(e)) => {
                        let why = format!("{e:#}");
                        b.shared.update(|m| {
                            m.tor = TorState::Failed(why.clone());
                            if hosted.is_some() {
                                m.hosting = Hosting::Off("Tor is not reachable".to_owned());
                            }
                        });
                    }
                    Err(e) => b.shared.update(|m| m.tor = TorState::Failed(e.to_string())),
                }
            }
            published = async { publish.as_mut().expect("guarded").await }, if publish.is_some() => {
                publish = None;
                match published {
                    Ok(Ok(l)) => {
                        say_evidence(format_args!("Tornect ID: {}", l.onion_address()), None);
                        status = Some(watch_reachability(&l, Arc::clone(&b.shared)));
                        listener = Some(l);
                    }
                    Ok(Err(e)) => {
                        let why = format!("publishing failed: {e:#}");
                        b.shared.update(|m| m.hosting = Hosting::Off(why));
                    }
                    Err(e) => b.shared.update(|m| m.hosting = Hosting::Off(e.to_string())),
                }
            }
            stream = async { listener.as_mut().expect("guarded").accept().await }, if listener.is_some() => {
                let (Some(stream), Some(hosted)) = (stream, &hosted) else {
                    listener = None;
                    b.shared.update(|m| m.hosting = Hosting::Off("the listener closed".to_owned()));
                    continue;
                };
                while media_streams.try_join_next().is_some() {}
                if stream.port() == MEDIA_PORT {
                    let media = Arc::clone(&hosted.media);
                    media_streams.spawn(async move {
                        let outcome = media.serve(stream).await;
                        if let Some(line) = describe_media(&outcome) {
                            note(format_args!("{line}"));
                        }
                    });
                    continue;
                }
                if stream.port() != SIGNALING_PORT {
                    continue;
                }
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                    continue;
                };
                let serving = Arc::clone(&hosted.serving);
                let (pins, b) = (Arc::clone(&hosted.pins), Arc::clone(&b));
                tokio::spawn(async move {
                    let _slot = slot;
                    let (cfg, deps) = &*serving;
                    crate::host::serve_signaling(stream, cfg, deps, |_| {}).await;
                    if pins.changed() {
                        refresh_book(&b, None);
                    }
                });
            }
            granted = async { granting.as_mut().expect("guarded").await }, if granting.is_some() => {
                granting = None;
                let outcome = granted.unwrap_or_else(|e| Err(e.to_string()));
                let token = b.paths.portal_restore_token();
                b.shared.update(|m| {
                    let Some(setup) = &mut m.setup else { return };
                    setup.busy = false;
                    setup.granted = token.exists();
                    setup.note = Some(match outcome {
                        Ok((true, true)) => "Granted: the screen, the keyboard and the mouse, remembered until revoked.".to_owned(),
                        Ok((false, true)) => "Granted for the screen only: \"Allow Remote Interaction\" was off, so viewers cannot control this desktop. Grant again to change it.".to_owned(),
                        Ok((_, false)) => "The desktop shared the screen but kept no grant, so it will ask again at each session.".to_owned(),
                        Err(why) => format!("Not granted: {why}"),
                    });
                });
            }
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    Command::Quit => break,
                    Command::Notice(change) => {
                        if let Some(notices) = &notices {
                            let _ = notices.send(change);
                        }
                    }
                    Command::Connect(id) | Command::ConnectAnyway(id) => {
                        let Some(node) = node.clone() else {
                            b.shared.update(|m| m.client = ClientStage::Ended("Tor is not connected yet.".to_owned()));
                            continue;
                        };
                        if viewing.as_ref().is_some_and(|(_, task)| !task.is_finished()) {
                            continue;
                        }
                        // The second click counts only for the ID warned about.
                        let anyway = matches!(command, Command::ConnectAnyway(_))
                            && b.shared.read(|m| {
                                m.connect_warning.as_ref().is_some_and(|w| w.id == id)
                                    || m.connect_unchecked == Some(id)
                            });
                        b.shared.update(|m| {
                            m.connect_warning = None;
                            m.connect_unchecked = None;
                        });
                        let (stop_tx, stop) = watch::channel(false);
                        let task =
                            tokio::spawn(view_session(Arc::clone(&b), node, id, stop, anyway, None));
                        viewing = Some((stop_tx, task));
                    }
                    Command::EndViewing => {
                        if let Some((stop, _)) = &viewing {
                            let _ = stop.send(true);
                        }
                    }
                    Command::StopSharing => {
                        if let Some(hosted) = &hosted {
                            stop_sharing(&hosted.serving.1.kill, &b.shared);
                        }
                    }
                    Command::AcknowledgeBanner => {
                        if let Some(watch) = hosted.as_ref().and_then(|h| h.banner.clone()) {
                            let shared = Arc::clone(&b.shared);
                            // The re-authentication dialog blocks.
                            tokio::task::spawn_blocking(move || watch.acknowledge(&shared));
                        }
                    }
                    Command::Grant => {
                        let sharing = b.shared.read(|m| !m.sharing.is_empty());
                        if granting.is_none() && !sharing && b.shared.read(|m| m.setup.is_some()) {
                            b.shared.update(|m| {
                                if let Some(setup) = &mut m.setup {
                                    setup.busy = true;
                                    setup.note = None;
                                }
                            });
                            let token = b.paths.portal_restore_token();
                            granting = Some(tokio::task::spawn_blocking(move || grant(token)));
                        }
                    }
                    Command::Ping(id) => {
                        let asking = b.shared.read(|m| m.book.check(&id) == Some(&Check::Asking));
                        if asking {
                            continue;
                        }
                        let Some(node) = node.clone() else {
                            let why = Check::Unreachable("Tor is not connected yet.".to_owned());
                            b.shared.update(|m| m.book.set_check(id, why));
                            continue;
                        };
                        b.shared.update(|m| m.book.set_check(id, Check::Asking));
                        let shared = Arc::clone(&b.shared);
                        tokio::spawn(async move {
                            let check = book::check(&node, id).await;
                            shared.update(|m| m.book.set_check(id, check));
                        });
                    }
                    Command::ForgetHost(id) => change_book(&b, &Change::Forget(id)),
                    Command::RenameHost(id, name) | Command::SaveEntry(id, name) => {
                        change_book(&b, &Change::Name(id, name));
                    }
                    Command::ClearHistory => change_book(&b, &Change::Clear),
                    Command::SetHistory(on) => change_book(&b, &Change::History(on)),
                    Command::SaveSettings(change) => save_settings(&b.paths, &b.shared, &change),
                    Command::AskPassword(id, admin, target) => open_prompt(&b, id, admin, target),
                    Command::DeviceWords(key) => {
                        // Argon2id over 64 MiB: off the command loop, paced
                        // like every key nobody saved.
                        let (words, shared) = (Arc::clone(&b.words), Arc::clone(&b.shared));
                        tokio::spawn(async move {
                            let derived =
                                tokio::task::spawn_blocking(move || words.device_words(&key)).await;
                            if let Ok(derived) = derived {
                                shared.update(|m| m.unlock_words = Some((key, derived)));
                            }
                        });
                    }
                    Command::ConfirmSetupChanged(id) => {
                        if let Err(e) = ua_client::renew_pin(&b.paths, &id) {
                            tracing::warn!(error = %format!("{e:#}"), "hosts.toml could not be updated");
                        }
                        b.shared.update(|m| {
                            m.setup_changed.remove(&id);
                            if m.dial.id == Some(id) && matches!(m.client, ClientStage::Ended(_)) {
                                m.client = ClientStage::Idle;
                                m.dial = Dial::default();
                            }
                        });
                    }
                    Command::ConnectUnattended(id, choice) => {
                        let Some(node) = node.clone() else {
                            b.shared.update(|m| m.client = ClientStage::Ended("Tor is not connected yet.".to_owned()));
                            continue;
                        };
                        if viewing.as_ref().is_some_and(|(_, task)| !task.is_finished())
                            || b.shared.read(|m| m.setup_changed.contains(&id))
                        {
                            continue;
                        }
                        let request = match unattended_request(&b, &id, choice) {
                            Ok(request) => request,
                            Err(NoPassword::Vanished) => {
                                ask_again(&b, id, None, None);
                                continue;
                            }
                            Err(NoPassword::None) => {
                                b.shared.update(|m| {
                                    m.client = ClientStage::Ended(
                                        "No password: none was typed and none is remembered."
                                            .to_owned(),
                                    );
                                });
                                continue;
                            }
                        };
                        let (stop_tx, stop) = watch::channel(false);
                        let task = tokio::spawn(view_session(
                            Arc::clone(&b),
                            node,
                            id,
                            stop,
                            true,
                            Some(request),
                        ));
                        viewing = Some((stop_tx, task));
                    }
                    Command::Admin(id, action, target, choice) => {
                        let Some(node) = node.clone() else {
                            b.shared.update(|m| m.note("Tor is not connected yet."));
                            continue;
                        };
                        match unattended_request(&b, &id, choice) {
                            Ok(request) => {
                                tokio::spawn(admin_command(
                                    Arc::clone(&b),
                                    node,
                                    id,
                                    (action, target),
                                    request,
                                ));
                            }
                            Err(NoPassword::Vanished) => ask_again(&b, id, Some(action), target),
                            Err(NoPassword::None) => {}
                        }
                    }
                    Command::Revoke => {
                        let token = b.paths.portal_restore_token();
                        let removed = match std::fs::remove_file(&token) {
                            Ok(()) => Ok(()),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                            Err(e) => Err(e),
                        };
                        b.shared.update(|m| {
                            if let Some(setup) = &mut m.setup {
                                setup.granted = token.exists();
                                setup.note = Some(match &removed {
                                    Ok(()) => "Revoked: the desktop asks again at the next session.".to_owned(),
                                    Err(e) => format!("Could not delete the grant file: {e}"),
                                });
                            }
                        });
                    }
                }
            }
        }
    }

    // Shutting down: the notifications go with the window, the sessions end
    // (`end_sessions`), every media stream gets its `Close`, then Tor goes.
    drop(notices);
    end_sessions(viewing.take(), hosted.as_ref().map(|h| &h.serving.1.kill)).await;
    if let Some(hosted) = &hosted {
        let grace = tokio::time::Instant::now() + SHUTDOWN_GRACE;
        loop {
            // A session that goes live during the grace ends too (P2-I4).
            hosted.serving.1.kill.kill(bye::USER);
            while media_streams.try_join_next().is_some() {}
            let busy = hosted.serving.1.stats.streams.load(Ordering::SeqCst) > 0
                || !media_streams.is_empty();
            if !busy || tokio::time::Instant::now() >= grace {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if hosted.live.count() > 0 {
            note(format_args!(
                "{} session(s) did not close in time",
                hosted.live.count()
            ));
        }
        media_streams.abort_all();
        hosted.kill_watch.abort();
        if let Some(ipc) = &hosted.ipc {
            ipc.abort();
        }
        hosted.audit.flush();
    }
    if let Some(status) = status {
        status.abort();
    }
    drop(listener);
    if let Some(node) = node
        && let Ok(node) = Arc::try_unwrap(node)
    {
        node.shutdown().await;
    }
    b.shared.update(|m| m.closed = true);
}

/// The window's notes after the verified accept of an unattended connect to the
/// host named `named` (quoted): what the settle said, then the attempt's notes,
/// but for the one that the administrator level was not given, which the Home
/// status line says for as long as the session lasts (said there once).
fn connect_notes(named: &str, after: ua_client::AfterAccept) -> Vec<String> {
    let mut notes = Vec::new();
    match &after.settled {
        Ok(_) => {}
        Err(e) if after.deleted_first => {
            notes.push(format!("hosts.toml could not be updated: {e:#}"));
        }
        Err(e) => notes.push(format!("The password could not be remembered: {e:#}")),
    }
    let not_given = tornect_core::unattended::credentials::note::level_not_given(named);
    notes.extend(after.notes.into_iter().filter(|note| *note != not_given));
    notes
}

/// Make an address-book change the window asked for (on this side, never on
/// the UI thread) and show the files as they are now.
fn change_book(b: &Backend, change: &Change) {
    let note = match change {
        Change::Forget(id) => forget(&b.paths, &ua_client::system_passwords(&b.device), id),
        _ => book::apply(&b.paths, change),
    };
    refresh_book(b, Some(note));
}

/// Forget `id`: its remembered unattended password and record (§B.8.9.1),
/// then its pin, its saved entry and its recent lines; the note to show.
/// When the keychain or `hosts.toml` refused, the note says what stayed, so
/// that Forget never reports a deletion that did not happen (FR2-L1).
fn forget(
    paths: &Paths,
    saved: &tornect_core::unattended::credentials::SavedPasswords,
    id: &TornectId,
) -> String {
    let kept = ua_client::forget(paths, saved, id).err();
    if let Some(e) = &kept {
        tracing::warn!(error = %e, "Forget did not finish");
    }
    // Named as the connect's notes name a host: its pinned label, quoted; read
    // before the change below takes the pin away.
    let named =
        tornect_core::trusted::KnownHosts::load(&tornect_core::trusted::known_hosts_file(paths))
            .ok()
            .and_then(|known| known.get(id).map(|pin| format!("\"{}\"", pin.label)))
            .unwrap_or_else(|| format!("{}…", id.short()));
    let note = book::apply(paths, &Change::Forget(*id));
    match kept {
        None => note,
        // The window lists no computer once its pin and entry went, so it
        // offers no second Forget: Rotate ID is what deletes the password then.
        Some(ua_client::Kept::Password(_)) => format!(
            "{note} The password remembered for {named} could not be deleted from {}; Rotate ID \
             deletes it later.",
            saved.keychain().unwrap_or("the keychain")
        ),
        Some(ua_client::Kept::Record(_)) => format!(
            "{note} Its remembered password was deleted, but its unattended record could not \
             be removed from hosts.toml."
        ),
    }
}

/// Read the address book's files into the model again, keeping the checks.
fn refresh_book(b: &Backend, note: Option<String>) {
    let mut fresh = book::read(
        &b.paths,
        tornect_core::address_book::Day::today(),
        Some(b.words.known()),
    );
    b.shared.update(|m| {
        fresh.checks = std::mem::take(&mut m.book.checks);
        fresh
            .checks
            .retain(|(id, _)| fresh.computers.iter().any(|c| c.id == *id));
        fresh.note = note;
        m.book = fresh;
    });
}

/// How long the viewed session's goodbye may take when the window closes.
const VIEWER_GOODBYE: Duration = Duration::from_secs(6);

/// How often the shutdown fires the host-wide kill again while it waits.
const REKILL_EVERY: Duration = Duration::from_millis(100);

/// The sessions' end when the window closes (its close button, Ctrl-C or
/// SIGTERM): first every hosted session gets its `BYE` through the host-wide
/// kill, so this screen stops being shared at once; then the viewed session
/// says goodbye, which Tor may stall for up to [`VIEWER_GOODBYE`]. In the
/// other order a remote controller kept this desktop for those seconds
/// (review N-4).
///
/// A kill ends only the sessions armed before it, and a session can still go
/// live after the first one: a stream accepted just before the close whose
/// peer has unattended rights, or whose consent is clicked while the window
/// closes. So the kill fires again every [`REKILL_EVERY`] while the goodbye
/// waits, and once more at the end (review P2-I4); the caller does the same
/// through its grace period.
async fn end_sessions(
    viewing: Option<(watch::Sender<bool>, JoinHandle<()>)>,
    hosted_kill: Option<&KillSwitch>,
) {
    let kill = || {
        if let Some(kill) = hosted_kill {
            kill.kill(bye::USER);
        }
    };
    kill();
    if let Some((stop, task)) = viewing {
        let _ = stop.send(true);
        let goodbye = tokio::time::timeout(VIEWER_GOODBYE, task);
        tokio::pin!(goodbye);
        loop {
            tokio::select! {
                _ = &mut goodbye => break,
                () = tokio::time::sleep(REKILL_EVERY) => kill(),
            }
        }
    }
    kill();
}

/// The Stop of the banner and of the indicator window: the host-wide kill with
/// `BYE{USER}`, which ends every session this screen is shared with (the host
/// serves one at a time) and refuses any popup still open, and never the
/// session this machine views.
fn stop_sharing(kill: &KillSwitch, shared: &Shared) {
    kill.kill(bye::USER);
    shared.update(|m| m.note("you stopped sharing"));
}

/// Resolves when the user ends the session (`stop` turns `true`).
async fn stopped(stop: &watch::Receiver<bool>) {
    let mut stop = stop.clone();
    if stop.wait_for(|stopped| *stopped).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// `work`, unless the user ends the session first (`None`). Only for the
/// steps before a session exists: once one does, `tor_cmd::watch` ends it with
/// its goodbye.
async fn unless_stopped<F: Future>(work: F, stop: &watch::Receiver<bool>) -> Option<F::Output> {
    tokio::select! {
        biased;
        () = stopped(stop) => None,
        done = work => Some(done),
    }
}

/// Open the password prompt for `id` (§B.8.10): what its saved record says
/// (a remembered password, a stale one, whether the grant may carry the
/// administrator level) and whether "Remember" can be offered here.
fn open_prompt(b: &Backend, id: TornectId, admin: Option<AdminAction>, target: Option<[u8; 32]>) {
    let saved = ua_client::system_passwords(&b.device);
    // C6: a password the host's last answer did not let this device keep goes first.
    if let Err(e) = ua_client::belt(&b.paths, &saved, &id) {
        tracing::warn!(error = %format!("{e:#}"), "hosts.toml could not be read");
    }
    let record = ua_client::record(&b.paths, &id);
    b.shared.update(|m| {
        let host = m.book.title_of(&id);
        m.prompt = Some(super::model::Prompt {
            id,
            host,
            keychain: saved.keychain(),
            kept: saved.kept(),
            remember: (saved.offer(record.reach), saved.offer(true)),
            remembered: record.remember && saved.keychain().is_some(),
            vanished: false,
            stale: record.stale,
            may_admin: record.administrator,
            retry_at: m.retry_at.get(&id).copied(),
            admin,
            target,
        });
    });
}

/// Why the prompt's choice gave no password to send.
enum NoPassword {
    /// None was typed, none could be read.
    None,
    /// The one remembered is gone from the keychain: its flag went, and the
    /// prompt asks for it again (I-9).
    Vanished,
}

/// The attempt the prompt asked for: the password typed, else the one
/// remembered for `id` (read from the keychain now, under its derived name).
fn unattended_request(
    b: &Backend,
    id: &TornectId,
    choice: UaChoice,
) -> Result<ua_client::Request, NoPassword> {
    let password = match choice.password {
        Some(Secret(typed)) => typed,
        None => {
            let saved = ua_client::system_passwords(&b.device);
            match ua_client::recall_for_use(&b.paths, &saved, id) {
                Ok(ua_client::Recalled::Password(remembered)) => remembered,
                Ok(ua_client::Recalled::Vanished) => return Err(NoPassword::Vanished),
                Ok(ua_client::Recalled::Nothing) => return Err(NoPassword::None),
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), "the keychain could not be read");
                    return Err(NoPassword::None);
                }
            }
        }
    };
    Ok(ua_client::Request {
        password,
        view_only: choice.view_only,
        administrator: choice.administrator,
        remember: choice.remember,
    })
}

/// Open the prompt for `id` again, asking for the password that vanished
/// from the keychain (I-9).
fn ask_again(b: &Backend, id: TornectId, admin: Option<AdminAction>, target: Option<[u8; 32]>) {
    open_prompt(b, id, admin, target);
    b.shared.update(|m| {
        if let Some(prompt) = m.prompt.as_mut().filter(|p| p.id == id) {
            prompt.vanished = true;
        }
    });
}

/// One admin command at `id` (§B.8.10): dial, one attempt, the host's signed
/// answer; the result goes to the activity lines (they name the computer, so
/// they are hidden while this screen is shared).
async fn admin_command(
    b: Arc<Backend>,
    node: Arc<TorNode>,
    id: TornectId,
    (action, target): (AdminAction, Option<[u8; 32]>),
    request: ua_client::Request,
) {
    crate::history::coarsen_pins(&b.paths);
    let pins = match crate::history::Pins::open(&b.paths, id) {
        Ok(pins) => pins,
        Err(e) => {
            b.shared
                .update(|m| m.note(format!("That did not work: {e:#}")));
            return;
        }
    };
    let Some(known) = pins.store().get(&id) else {
        b.shared
            .update(|m| m.note("Admin commands go only to a paired computer."));
        return;
    };
    let host = known.label.clone();
    let saved = ua_client::system_passwords(&b.device);
    let (named, keychain) = (
        format!("\"{host}\""),
        saved.keychain().unwrap_or("the keychain"),
    );
    let mut notes = Vec::new();
    let said = match node
        .connect_on(&id, SIGNALING_PORT, &Isolation::new())
        .await
    {
        Err(_) => {
            let ended = ua_client::unreachable(&host);
            ua_client::log_attempt(&b.paths, &known, &Logged::Ended(&ended.reason));
            ended.text
        }
        Ok(stream) => {
            let ccfg = ClientConfig::new(id, b.cfg.general.device_name.clone());
            let deps = ClientDeps {
                known_hosts: pins.store(),
                ui: Arc::new(client::NoPairingUi),
                random: Arc::new(OsRandom),
                server_key_pin: Arc::new(ua_client::HostsPin::new(&b.paths)),
            };
            let command = client::AdminIntent {
                password: request.password.clone(),
                op: action.op(),
                device_pk: match action {
                    AdminAction::RevokeThisDevice => Some(*b.device.id().public_key_bytes()),
                    AdminAction::Unlock => target,
                    AdminAction::EndSession | AdminAction::TurnOff => None,
                },
            };
            match client::admin(stream, &ccfg, &b.device, &deps, &command).await {
                Ok(answer) => {
                    // An admin answer keeps no password (DA-15); its decoded `grant_reach`
                    // decides about a remembered one (C1, C11).
                    match ua_client::after_admin(&b.paths, &saved, &id, &answer, &named) {
                        Ok(after) => notes = after,
                        Err(e) => notes.push(format!("hosts.toml could not be updated: {e:#}")),
                    }
                    ua_client::log_attempt(
                        &b.paths,
                        &known,
                        &Logged::Admin {
                            op: action.name(),
                            ok: answer.ok,
                        },
                    );
                    if answer.ok && action == AdminAction::RevokeThisDevice {
                        let _ = ua_client::forget(&b.paths, &saved, &id);
                    }
                    if answer.ok {
                        format!("\"{host}\" did it: {}.", action.title().to_lowercase())
                    } else {
                        format!(
                            "\"{host}\" did not do it ({}): this device's access there does not \
                             allow it, or it could not.",
                            action.title().to_lowercase()
                        )
                    }
                }
                Err(e) => {
                    let ended = ua_client::ended(&e, &host);
                    match ua_client::settle(&b.paths, &saved, &id, ended.attempt, &request) {
                        Ok(settled) => {
                            notes =
                                ua_client::refused_notes(&named, keychain, ended.attempt, &settled);
                        }
                        Err(err) if ended.attempt.deletes_first() => {
                            notes.push(format!("hosts.toml could not be updated: {err:#}"));
                        }
                        Err(err) => {
                            tracing::warn!(error = %format!("{err:#}"), "hosts.toml could not be updated");
                        }
                    }
                    ua_client::log_attempt(&b.paths, &known, &Logged::Ended(&ended.reason));
                    if ended.blocks {
                        b.shared.update(|m| {
                            m.setup_changed.insert(id);
                        });
                    }
                    ended.text
                }
            }
        }
    };
    b.shared.update(|m| {
        m.note(said);
        for note in notes {
            m.note(note);
        }
    });
    refresh_book(&b, None);
}

/// View `id`: pair if it is new, ask for a session, then show its screen and
/// send input if the host allowed control. Ends when the user stops or either
/// side goes away; the window learns how it ended.
async fn view_session(
    b: Arc<Backend>,
    node: Arc<TorNode>,
    id: TornectId,
    stop: watch::Receiver<bool>,
    anyway: bool,
    ua: Option<ua_client::Request>,
) {
    // The connect field's look-alike check (§B.6.1 item 4): an ID that is not
    // in the address book is compared with the saved ones before anything is
    // dialled; one that looks like one waits for a second click.
    if !anyway && !b.shared.read(|m| m.book.computer(&id).is_some()) {
        let words = Arc::clone(&b.words);
        let looks = tokio::task::spawn_blocking(move || words.connect_check(&id)).await;
        match looks {
            Ok(Some(Lookalike::Named(name))) => {
                b.shared.update(|m| {
                    m.connect_warning = Some(super::model::ConnectWarning { id, name });
                    m.client = ClientStage::Idle;
                });
                return;
            }
            // A file of saved entries could not be read: say so and wait for
            // the same second click (F-4).
            Ok(Some(Lookalike::Unchecked)) => {
                b.shared.update(|m| {
                    m.connect_unchecked = Some(id);
                    m.client = ClientStage::Idle;
                });
                return;
            }
            Ok(None) | Err(_) => {}
        }
    }
    let mut live = None;
    let ended = viewed(&b, &node, id, &stop, &mut live, ua).await;
    b.link.set_input(None);
    let message = match ended {
        Ok(message) => message,
        Err(e) => format!("{e:#}"),
    };
    // The message names the host: the id of the session it ended, if one
    // was live, without the scripts' opt-in (U3-M1).
    match &live {
        Some(sid) => say_evidence(
            format_args!("VIEWER: {message}"),
            Some(format_args!("VIEWER ENDED {sid}")),
        ),
        None => say_evidence(format_args!("VIEWER: {message}"), None),
    }
    b.shared.update(|m| {
        m.client = ClientStage::Ended(message.clone());
        m.ua_live = None;
        m.note(message);
    });
}

/// View `id` until the session ends; `live` gets the session's id once it
/// is live.
async fn viewed(
    b: &Backend,
    node: &TorNode,
    id: TornectId,
    stop: &watch::Receiver<bool>,
    live: &mut Option<String>,
    ua: Option<ua_client::Request>,
) -> anyhow::Result<String> {
    b.shared.update(|m| {
        m.client = ClientStage::Reaching {
            id: id.display_groups(),
        };
        m.dial = Dial {
            id: Some(id),
            since: Some(Instant::now()),
            paired_now: false,
            failed: None,
            unattended: ua.is_some(),
        };
        m.ua_live = None;
    });
    // With history off the handshake works on a copy of the known hosts, so
    // that its last-seen touch writes nothing (`crate::history`).
    crate::history::coarsen_pins(&b.paths);
    let pins = crate::history::Pins::open(&b.paths, id)?;
    // Unattended access is a paired computer's (§B.8 hard rule 2).
    let known = match (&ua, pins.store().get(&id)) {
        (Some(_), None) => {
            failed(b, Failure::Other);
            anyhow::bail!("This computer is not paired with it: Knock first.");
        }
        (_, known) => known,
    };
    // One isolation group: the media stream rides the signaling circuit.
    let isolation = Isolation::new();
    let Some(stream) = unless_stopped(node.connect_on(&id, SIGNALING_PORT, &isolation), stop).await
    else {
        return Ok("Cancelled.".to_owned());
    };
    if stream.is_err() {
        failed(b, Failure::Unreachable);
        if let (Some(_), Some(known)) = (&ua, &known) {
            let ended = ua_client::unreachable(&known.label);
            ua_client::log_attempt(&b.paths, known, &Logged::Ended(&ended.reason));
            return Err(anyhow::Error::msg(ended.text));
        }
    }
    let stream = stream.map_err(explain)?;
    if ua.is_some() {
        b.shared.update(|m| m.client = ClientStage::Checking);
    } else if pins.known() {
        b.shared.update(|m| m.client = ClientStage::Asking);
    }
    let ccfg = ClientConfig::new(id, b.cfg.general.device_name.clone());
    let pairing = Arc::new(GuiPairingUi::new(Arc::clone(&b.popups)));
    let deps = ClientDeps {
        known_hosts: pins.store(),
        ui: pairing.clone(),
        random: Arc::new(OsRandom),
        // The host's OPAQUE key, pinned in hosts.toml: only unattended
        // sessions consult it.
        server_key_pin: match &ua {
            Some(_) => Arc::new(ua_client::HostsPin::new(&b.paths)),
            None => Arc::new(NoServerKeyPin),
        },
    };
    let intent = ua
        .as_ref()
        .map_or(Intent::Session, ua_client::Request::intent);
    let outcome = unless_stopped(
        client::connect(stream, &ccfg, &b.device, &deps, intent),
        stop,
    )
    .await;
    // A pin the handshake made is kept however it ended, a cancel included.
    if let Err(e) = pins.settle() {
        let line = format!("the pairing could not be saved: {e:#}");
        tracing::warn!("{line}");
        b.shared.update(|m| m.note(line));
    }
    refresh_book(b, None);
    let Some(outcome) = outcome else {
        if let (Some(_), Some(known)) = (&ua, &known) {
            ua_client::log_attempt(&b.paths, known, &Logged::Ended("cancelled"));
        }
        return Ok("Cancelled before the session started.".to_owned());
    };
    // One attempt, settled once: nothing is tried again (§B.8.10).
    if let (Some(request), Some(known), Err(e)) = (&ua, &known, &outcome) {
        let ended = ua_client::ended(e, &known.label);
        let saved = ua_client::system_passwords(&b.device);
        let notes = match ua_client::settle(&b.paths, &saved, &id, ended.attempt, request) {
            Ok(settled) => ua_client::refused_notes(
                &format!("\"{}\"", known.label),
                saved.keychain().unwrap_or("the keychain"),
                ended.attempt,
                &settled,
            ),
            Err(err) if ended.attempt.deletes_first() => {
                vec![format!("hosts.toml could not be updated: {err:#}")]
            }
            Err(err) => {
                tracing::warn!(error = %format!("{err:#}"), "hosts.toml could not be updated");
                Vec::new()
            }
        };
        b.shared.update(|m| {
            for note in notes {
                m.note(note);
            }
        });
        ua_client::log_attempt(&b.paths, known, &Logged::Ended(&ended.reason));
        let (why, step) = ua_failure(e, &ended);
        b.shared.update(|m| {
            m.dial.failed = Some((why, step));
            if ended.blocks {
                m.setup_changed.insert(id);
            }
            if let HandshakeError::SessionRejected { reject: r } = e
                && let Some(secs) = r.retry_after_s
            {
                m.retry_at.insert(
                    id,
                    Instant::now() + Duration::from_secs(u64::from(secs.min(24 * 3600))),
                );
            }
        });
        refresh_book(b, None);
        return Err(anyhow::Error::msg(ended.text));
    }
    let outcome = outcome.map_err(|e| {
        failed(b, classify(&e, pairing.ended()));
        not_started(e, pairing.ended())
    })?;
    let ClientOutcome::Session(mut session) = outcome else {
        anyhow::bail!("paired, but no session came of it");
    };
    // The input gate: the signed SESSION_ACCEPT's mode, never the media
    // stream's BindOk (SLICE-C2 C2-6).
    let control = sends_input(session.accept().mode());
    // The level, likewise, only from the signed accept (§B.2.1).
    let administrator = control && session.accept().elevation() == Elevation::Admin;
    let host = session.host_label().to_owned();
    let sid = session.session_token().session_id();
    say_evidence(
        format_args!(
            "SESSION LIVE {sid} with \"{host}\" ({}{})",
            if session.unattended() {
                "unattended · "
            } else {
                ""
            },
            match (control, administrator) {
                (true, true) => "control · administrator",
                (true, false) => "control",
                (false, _) => "view-only",
            }
        ),
        Some(format_args!("SESSION LIVE {sid}")),
    );
    let unattended = session.unattended();
    if let (Some(request), Some(known)) = (&ua, &known) {
        let saved = ua_client::system_passwords(&b.device);
        // C1: the verified accept alone decides, before QUIC, by the key decoded from it.
        let after = ua_client::after_accept(
            &b.paths,
            &saved,
            &id,
            session.accept(),
            request,
            &format!("\"{host}\""),
            session.elevation_withheld(),
        );
        let notes = connect_notes(&format!("\"{host}\""), after);
        b.shared.update(|m| {
            for note in notes {
                m.note(note);
            }
        });
        if let Err(e) = ua_client::note_mode(&b.paths, &id, control) {
            tracing::warn!(error = %format!("{e:#}"), "hosts.toml could not be updated");
        }
        ua_client::log_attempt(
            &b.paths,
            known,
            &Logged::Session {
                id: &sid,
                control,
                administrator,
            },
        );
        let lines = super::model::UaLive {
            withheld: session.elevation_withheld(),
            fail_summary: ua_client::fail_summary_text(session.accept().fail_summary()),
        };
        b.shared.update(|m| m.ua_live = Some(lines));
        refresh_book(b, None);
    }
    *live = Some(sid);
    b.shared.update(|m| {
        m.go_live(Viewing {
            host: host.clone(),
            control,
            administrator,
            unattended,
            since: Instant::now(),
            pictures: 0,
            size: (0, 0),
        });
    });
    // The day of the visit, if history is kept; nothing otherwise.
    match pins.visited() {
        Ok(true) => refresh_book(b, None),
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %format!("{e:#}"), "the visit was not recorded"),
    }
    // Tor is the transport in the slice; saying so stops the host's orphan timer.
    session
        .send_tor_fallback()
        .await
        .map_err(explain_handshake)?;
    let input = control.then(|| {
        let (tx, rx) = mpsc::channel(INPUT_QUEUE);
        b.link.set_input(Some(tx));
        rx
    });
    let mut sink = SlotSink::new(Arc::clone(&b.link.slot), Arc::clone(&b.shared));
    // The host's notice code (decision M1-70), into the model as it changes;
    // the stream window shows it in a control session only.
    let mut notices = session.notices();
    let told = Arc::clone(&b.shared);
    let notices_task = tokio::spawn(async move {
        while notices.changed().await.is_ok() {
            let code = *notices.borrow_and_update();
            told.update(|m| m.host_notice = code);
        }
    });
    let end = crate::tor_cmd::watch(
        node,
        &id,
        &isolation,
        &mut session,
        None,
        stop,
        input,
        Some(&mut sink),
    )
    .await;
    notices_task.abort();
    // Awaited, so that no code the task held lands after the clear.
    let _ = notices_task.await;
    b.shared.update(super::model::Model::end_notices);
    b.link.set_input(None);
    Ok(match end? {
        End::You => {
            if let Err(e) = session.bye(bye::USER).await {
                tracing::debug!(error = %e, "sending BYE");
            }
            format!("Session with \"{host}\" ended (by you).")
        }
        End::Host(reason) => {
            format!("\"{host}\" ended the session ({}).", bye::name(reason))
        }
        End::Lost(e) => format!(
            "The session with \"{host}\" was lost: {:#}",
            explain_handshake(e)
        ),
        End::NoPicture(e) => {
            if let Err(e) = session.bye(bye::USER).await {
                tracing::debug!(error = %e, "sending BYE");
            }
            format!("No picture from \"{host}\": {e:#}")
        }
    })
}

/// Where an unattended attempt that got no session belongs in the stepper:
/// reaching the computer (step 1) when its host stopped answering before the
/// password was tried, the password (step 2) or the computer's own checks
/// after it (step 3).
fn ua_failure(err: &HandshakeError, ended: &ua_client::Ended) -> (Failure, u8) {
    if ended.blocks {
        return (Failure::SetupChanged, 2);
    }
    if ended.attempt == tornect_core::unattended::credentials::Attempt::PasswordRefused {
        return (Failure::WrongPassword, 2);
    }
    match err {
        HandshakeError::SessionRejected { reject: r } => {
            // Codes of 0x0021 and above come after the password was proven.
            let after = r.reason >= reject::OUTSIDE_SCHEDULE && r.reason != reject::PREEMPTED
                || r.reason == reject::DENIED
                || r.reason == reject::POPUP_TIMEOUT;
            (Failure::NotLetIn, if after { 3 } else { 2 })
        }
        // A host that stopped answering before the password was tried: not
        // a person who did not answer.
        HandshakeError::Timeout("HELLO_ACK" | "AUTH_CHALLENGE") => (Failure::Unreachable, 1),
        HandshakeError::Timeout(_) => (Failure::TimedOut, 3),
        _ => (Failure::Other, 2),
    }
}

/// Record why the connection ended without a session, at the step it had
/// reached.
fn failed(b: &Backend, why: Failure) {
    b.shared.update(|m| {
        let step = match m.client {
            ClientStage::Pairing { .. } | ClientStage::Checking => 2,
            ClientStage::Asking => 3,
            ClientStage::Live(_) => 4,
            _ if why == Failure::CodesDiffer => 2,
            _ => 1,
        };
        m.dial.failed = Some((why, step));
    });
}

/// Where a handshake that ended before its session belongs in the connect
/// stepper's error taxonomy.
fn classify(err: &HandshakeError, check: Option<CodeCheck>) -> Failure {
    use tornect_signal::envelope::codes::E_VERSION;
    match (err, check) {
        (_, Some(CodeCheck::Differ)) => Failure::CodesDiffer,
        // This computer's own question went unanswered: nobody there to blame.
        (_, Some(CodeCheck::Unanswered)) => Failure::CodeUnanswered,
        (HandshakeError::PairRejected { reason, .. }, _) if *reason == pair_reject::DENIED => {
            Failure::Denied
        }
        (HandshakeError::PairRejected { reason, .. }, _) if *reason == pair_reject::TIMEOUT => {
            Failure::TimedOut
        }
        (HandshakeError::SessionRejected { reject }, _) if reject.reason == reject::DENIED => {
            Failure::Denied
        }
        (HandshakeError::SessionRejected { reject }, _)
            if reject.reason == reject::POPUP_TIMEOUT =>
        {
            Failure::TimedOut
        }
        // A host that stopped answering before anyone was asked anything.
        // Only an unattended attempt waits for an `AUTH_CHALLENGE`, and it
        // never comes here (`ua_failure` words it, the same way); the name
        // stays so that the two read alike.
        (HandshakeError::Timeout("HELLO_ACK" | "AUTH_CHALLENGE"), _) => Failure::Unreachable,
        (HandshakeError::Timeout(_), _) => Failure::TimedOut,
        (HandshakeError::Violation { code, .. } | HandshakeError::PeerError { code, .. }, _)
            if *code == E_VERSION =>
        {
            Failure::VersionMismatch
        }
        _ => Failure::Other,
    }
}

/// The window's words for a handshake that ended before its session. The
/// command line's hints (`tor_cmd::explain_handshake`) name commands to run
/// again; how the code question ended is said here in the window's terms.
fn not_started(err: HandshakeError, check: Option<CodeCheck>) -> anyhow::Error {
    let text = match check {
        Some(CodeCheck::Differ) => {
            "Not paired: you answered that the codes differ. If they really did, something \
             between the two computers changed them, so do not pair now; if it was a slip, press \
             Connect again and compare the new code."
        }
        Some(CodeCheck::Unanswered) => {
            "Not paired: nobody answered the code question. Press Connect again to pair; the \
             host's user sees the request again, with a new code."
        }
        // Only when the host has gone: any other error (a known-hosts file
        // that could not be written, a violation or a timeout from a host
        // still there) keeps its own words.
        Some(CodeCheck::MatchedLate)
            if matches!(
                err,
                HandshakeError::Closed
                    | HandshakeError::Io(_)
                    | HandshakeError::Frame(_)
                    | HandshakeError::PeerBye { .. }
            ) =>
        {
            "Paired: this computer now knows the host, but the host had stopped waiting for the \
             session by then. Press Connect again to ask for a session."
        }
        _ => return explain_handshake(err),
    };
    tracing::debug!(error = %err, "the handshake ended before a session");
    anyhow::Error::msg(text)
}

/// Whether the viewer sends input, from the `mode` of the host's signed
/// SESSION_ACCEPT: only a control grant does. A view-only grant never does,
/// nor does a mode this build does not know.
fn sends_input(mode: u8) -> bool {
    matches!(
        tornect_signal::consent::mode_from_code(mode),
        Some(SessionMode::Control)
    )
}

#[cfg(test)]
mod tests {
    use tornect_signal::HostSigner;
    use tornect_signal::fsm::client::{ScriptedClientUi, SessionEvent, connect};
    use tornect_signal::fsm::host::serve_host;
    use tornect_signal::pairing::{
        PairDecision, PairScript, ScriptedConsent, SessionDecision, TrustedDeviceStore,
    };

    use super::super::indicator::{Change, Indicator};
    use super::super::model::{Model, PopupKind};
    use super::*;

    /// §B.1.1, §B.2.1: `IpcOp::Show` reaches the window host as one wake of
    /// its event loop (`Wake::Show`, which raises the window and re-arms the
    /// cards) and nothing else: the open sheets stay as they were, in their
    /// order, none answered or dismissed, and it is no mutation (no dialog,
    /// no log line).
    #[test]
    fn show_never_answers_dismisses_or_reorders() {
        use super::super::model::Popup;
        use tornect_core::unattended::ipc::{IpcOp, IpcRequest};

        let woken = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&woken);
        let shared = Shared::new(
            Model::default(),
            Arc::new(move |why| into.lock().unwrap().push(why)),
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        let sheets = vec![
            Popup {
                id: 3,
                kind: PopupKind::Pairing {
                    name: "Phone".to_owned(),
                    fingerprint: "a1b2c3".to_owned(),
                    sas: "123 456".to_owned(),
                    pinned: None,
                },
                deadline,
            },
            Popup {
                id: 4,
                kind: PopupKind::Session {
                    label: "Laptop".to_owned(),
                    fingerprint: "d4e5f6".to_owned(),
                },
                deadline,
            },
        ];
        shared.update(|m| m.popups = sheets.clone());
        woken.lock().unwrap().clear();
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::unattended::test_context(tmp.path(), Some(show_hook(Arc::clone(&shared))));
        let lines = ctx.log.read_all().unwrap().len();
        let resp = crate::unattended::dispatch(
            &ctx,
            IpcRequest {
                id: 7,
                op: IpcOp::Show,
            },
        );
        assert!(resp.ok, "{resp:?}");
        assert_eq!(
            *woken.lock().unwrap(),
            vec![Wake::Show],
            "one wake, nothing else"
        );
        let after = shared.read(|m| m.popups.clone());
        assert_eq!(
            after
                .iter()
                .map(|p| (p.id, p.kind.clone(), p.deadline))
                .collect::<Vec<_>>(),
            sheets
                .iter()
                .map(|p| (p.id, p.kind.clone(), p.deadline))
                .collect::<Vec<_>>(),
            "the sheets as they were"
        );
        assert_eq!(ctx.log.read_all().unwrap().len(), lines, "nothing logged");
    }

    /// §B.8.6.2 (the banner returns "after any grant creation, widening or backup
    /// export"): acknowledged, the banner goes; a raise to the administrator level
    /// through a password change, which the guard logs as `PasswordSet`, brings it
    /// back.
    #[test]
    fn the_banner_returns_after_a_raise_through_a_password_change() {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::{Actor, SessionLog};
        use tornect_core::unattended::clock::FakeClock;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{
            AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
            RandomServerSetupSource,
        };
        use tornect_core::unattended::ipc::GrantOptions;
        use tornect_core::unattended::store::GrantStore;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        // the log's times have a resolution of one second: the raise is logged later
        let clock = Arc::new(FakeClock::at(1_787_961_600));
        let store = GrantStore::open(
            &paths,
            secrets,
            clock.clone(),
            SessionLog::new(paths.sessions_log()),
        )
        .unwrap();
        // an installed copy on a Windows administrator account: the level exists there
        let facts =
            tornect_core::levels::AccountFacts::Windows(tornect_core::levels::WindowsFacts {
                installed: true,
                administrator: true,
                ..tornect_core::levels::WindowsFacts::default()
            });
        let guard = Arc::new(
            MutationGuard::new(
                store,
                Arc::new(AllowAllReAuth::default()),
                Arc::new(NoSessionActivity),
                Arc::new(tornect_core::levels::FixedFacts::new(
                    facts,
                    tornect_core::levels::HelperPresence::Absent,
                )),
            )
            .with_paired_devices(Arc::new(AllowAllPaired))
            .with_server_setup_source(Arc::new(RandomServerSetupSource)),
        );
        let device = tornect_core::DeviceId::from_bytes([3; 32]);
        guard.master_on(Actor::Cli, &[9; 32]).unwrap();
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
        let watch = BannerWatch {
            guard: Arc::clone(&guard),
            acknowledged: Mutex::new(None),
        };
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.refresh(&shared);
        assert!(
            shared.read(|m| m.unattended_banner.is_some()),
            "a grant created"
        );
        watch.acknowledge(&shared);
        assert!(
            shared.read(|m| m.unattended_banner.is_none()),
            "acknowledged"
        );
        // a raise: a new generated password with the level, in one write
        clock.advance(Duration::from_secs(5));
        guard
            .set_password(
                Actor::Cli,
                &device,
                &[1u8; 192],
                &GrantOptions {
                    elevation: Some(Elevation::Admin),
                    ..GrantOptions::default()
                },
                true,
            )
            .unwrap();
        assert!(guard.store().grant(&device).unwrap().holds_level());
        watch.refresh(&shared);
        assert!(
            shared.read(|m| m.unattended_banner.is_some()),
            "back after the raise"
        );
    }

    /// The row "indicator shown" as the host at `state_dir` answers it over
    /// its control channel.
    async fn indicator_row_of(
        state_dir: &std::path::Path,
    ) -> tornect_core::unattended::readiness::Probe {
        use tornect_core::unattended::ipc::{IpcOp, IpcRequest, decode_payload};
        use tornect_core::unattended::readiness::ReadinessSnapshot;
        let resp = tornect_platform::ipc::request(
            state_dir,
            &IpcRequest {
                id: 1,
                op: IpcOp::Readiness,
            },
        )
        .await
        .unwrap();
        assert!(resp.ok, "{resp:?}");
        let snapshot: ReadinessSnapshot =
            decode_payload(resp.payload.as_deref().expect("a readiness payload")).unwrap();
        snapshot.consent_indicator
    }

    /// §B.1.1 (MUST): background mode wires the window host as a start by
    /// hand does. Its block window is the window's: a block request comes up
    /// in the window and its Block blocks, where the headless seam is a timer
    /// nobody can block. And the indicator fact reaches the host: its
    /// readiness answer warns until the probe drew, then passes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_mode_wires_the_window_hosts_block_window() {
        use tornect_core::unattended::readiness::Probe;
        use tornect_signal::consent::BlockOutcome;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let popups = Popups::new(Arc::clone(&shared));
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let device = DeviceIdentity::from_seed(&[0x12; 32]);
        let device_pk = HostSigner::public_key(&device);
        let words = Arc::new(super::super::recognize::Recognizer::new(
            paths.clone(),
            super::super::recognize::Me {
                name: "Linux PC".to_owned(),
                onion: identity.id(),
                device: tornect_core::DeviceId::from_bytes(device_pk),
            },
        ));
        let shown = crate::host::IndicatorShown::default();
        let b = Backend {
            paths: paths.clone(),
            cfg: Config::default(),
            shared: Arc::clone(&shared),
            popups: Arc::clone(&popups),
            link: Arc::new(StreamLink::default()),
            source: Source::TestCard,
            host: true,
            identity,
            device: Arc::new(device),
            device_pk,
            words,
            background: Some(shown.clone()),
        };
        let hosted = host_role(&b).await.expect("the window host is wired");
        assert_eq!(
            indicator_row_of(&paths.state_dir).await,
            Probe::Warn(tornect_platform::readiness::INDICATOR_NOT_SHOWN.to_owned())
        );
        shown.set();
        assert_eq!(indicator_row_of(&paths.state_dir).await, Probe::Ok);

        let window = Arc::clone(&hosted.serving.1.block_window);
        let running = tokio::spawn(async move { window.run(10, &[1; 8], "Laptop").await });
        let request = loop {
            if let Some(id) = shared.read(|m| m.blocks.first().map(|b| b.id)) {
                break id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert!(popups.answer_block(request), "the window's Block");
        assert_eq!(running.await.unwrap(), BlockOutcome::Blocked);
        if let Some(ipc) = &hosted.ipc {
            ipc.abort();
        }
    }

    /// How the window's user answers a pairing sheet in
    /// [`pairing_requests`].
    #[derive(Debug, Clone, Copy)]
    enum Reply {
        /// A click on the accept button.
        Click,
        /// The code typed from the other device's screen.
        Type,
        /// Deny.
        Deny,
    }

    /// What one pairing request met: the sheet, if one came up (its device
    /// words and the saved name its alarm named), and how the request ended
    /// for the device.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Met {
        sheet: Option<(tornect_core::words::Words, Option<String>)>,
        ended: String,
    }

    /// The window host's pairing path as `host_role` wires it (the window's
    /// sheets with device words and the look-alike alarm, §B.6.1), in a home
    /// with one paired device, "Office PC", in background mode when
    /// `background` is given: a run of pairing requests (a new device; a new
    /// device declaring the paired one's name; three denials and the ban; a
    /// paired device asking again until the rate limit; a request during a
    /// session), and what each met.
    async fn pairing_requests(background: Option<crate::host::IndicatorShown>) -> Vec<Met> {
        use tornect_core::trusted::{KnownHosts, TrustedDevices};

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let mut devices = TrustedDevices::default();
        devices.pin(
            DeviceIdentity::from_seed(&[0x41; 32]).id(),
            "Office PC",
            1000,
        );
        devices.save(&paths.trusted_devices_file()).unwrap();
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let host_pk = HostSigner::public_key(&DeviceIdentity::from_seed(&[0x12; 32]));
        let media = Arc::new(MediaHost::new(
            Arc::new(SystemBackend::new(Source::TestCard)),
            Arc::new(tornect_session::NoObserver),
            MediaLimits::default(),
        ));
        let mut wiring = crate::host::wire_window(
            &paths,
            &Config::default(),
            Arc::clone(&identity),
            host_pk,
            Arc::new(AutoDeny),
            media,
            ControlChannel::default(),
            background,
        )
        .unwrap();
        let popups = Popups::new(Shared::new(Model::default(), Arc::new(|_| {})));
        let (_started_tx, started) = watch::channel(0u64);
        let live = Arc::clone(&wiring.live);
        let words = Arc::new(super::super::recognize::Recognizer::new(
            paths.clone(),
            super::super::recognize::Me {
                name: "Linux PC".to_owned(),
                onion: identity.id(),
                device: tornect_core::DeviceId::from_bytes(host_pk),
            },
        ));
        let consent = Arc::new(
            GuiConsent::new(
                Arc::clone(&popups),
                Withdraw {
                    kill: wiring.deps.kill.clone(),
                    started,
                    live: Arc::new(move || live.session_live()),
                },
            )
            .with_words(words),
        );
        wiring.deps.consent = consent.clone();
        wiring.deps.local_allow = consent;
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());

        let request = |seed: u8, name: &'static str, reply: Option<Reply>| {
            let (cfg, deps, popups) = (cfg.clone(), deps.clone(), Arc::clone(&popups));
            let known = paths.state_dir.join(format!("known-{seed}.toml"));
            let host = identity.id();
            async move {
                let (client_end, host_end) = tokio::io::duplex(64 * 1024);
                let serving = tokio::spawn(async move {
                    crate::host::serve_signaling(host_end, &cfg, &deps, |_| {}).await
                });
                let replying = tokio::spawn(async move {
                    let reply = reply?;
                    let mut sheet = None;
                    for _ in 0..4000 {
                        sheet = popups.shared().read(|m| m.popups.first().cloned());
                        if sheet.is_some() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    let sheet = sheet?;
                    let seen = popups
                        .shared()
                        .read(|m| m.recognition.get(&sheet.id).cloned())?;
                    let PopupKind::Pairing { sas, .. } = &sheet.kind else {
                        return None;
                    };
                    match reply {
                        Reply::Click => {
                            popups.answer_pairing(sheet.id, PairDecision::Accept { label: None });
                        }
                        Reply::Type => {
                            popups.answer_pairing_code(sheet.id, sas, None);
                        }
                        Reply::Deny => {
                            popups.answer_pairing(sheet.id, PairDecision::Reject);
                        }
                    }
                    Some((seen.words, seen.looks_like))
                });
                let known = Arc::new(KnownHostStore::with(known, KnownHosts::default()));
                let mut cdeps = ClientDeps::headless(known);
                cdeps.ui = Arc::new(ScriptedClientUi::new(true));
                let device = DeviceIdentity::from_seed(&[seed; 32]);
                let ccfg = ClientConfig::new(host, name);
                let ended =
                    match connect(client_end, &ccfg, &device, &cdeps, Intent::PairOnly).await {
                        Ok(ClientOutcome::Paired { .. }) => "paired".to_owned(),
                        Ok(ClientOutcome::Session(_)) => "a session".to_owned(),
                        Err(HandshakeError::PairRejected { reason, .. }) => {
                            pair_reject::name(reason).to_owned()
                        }
                        Err(e) => e.to_string(),
                    };
                let _ = serving.await;
                Met {
                    sheet: replying.await.unwrap(),
                    ended,
                }
            }
        };

        let mut met = Vec::new();
        // A new device: its words, no alarm; the click pairs.
        met.push(request(0x51, "Kitchen", Some(Reply::Click)).await);
        // A new device declaring the paired one's name: the alarm; the click
        // refuses, the code typed from its screen pairs.
        met.push(request(0x52, "Office PC", Some(Reply::Click)).await);
        met.push(request(0x52, "Office PC", Some(Reply::Type)).await);
        // Three denials of a new device, then its ban.
        for _ in 0..3 {
            met.push(request(0x53, "Garage", Some(Reply::Deny)).await);
        }
        met.push(request(0x53, "Garage", None).await);
        // The paired device asking again: its denials do not ban it, and the
        // rate limit stops its fourth request.
        for _ in 0..2 {
            met.push(request(0x51, "Kitchen", Some(Reply::Deny)).await);
        }
        met.push(request(0x51, "Kitchen", None).await);
        // During a session: BUSY, and no sheet.
        let token = tornect_signal::consent::SessionToken::new([5; 32]);
        let session = LiveSession {
            device: DeviceIdentity::from_seed(&[0x60; 32]).id(),
            label: "Laptop",
            session_id: "s1",
            token: &token,
            th_final: [0; 32],
            mode: SessionMode::ViewOnly,
            elevation: Elevation::None,
            unattended: false,
        };
        wiring.live.on_start(&session);
        met.push(request(0x54, "Hall", None).await);
        wiring.live.on_end("s1", None);
        met
    }

    /// Decision M1-68 (§B.1.1 as the operator ruled it): in background mode a
    /// new device pairs exactly as with the window open. The same pairing
    /// requests to the window host's pairing path, by hand and in background
    /// mode, meet the same: the limiter, the ban after three denials, BUSY
    /// during a session, the device words, the alarm and the pairing by the
    /// typed code. No setting and no condition is added.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_mode_changes_nothing_in_the_pairing_path() {
        let by_hand = pairing_requests(None).await;
        let background = pairing_requests(Some(crate::host::IndicatorShown::default())).await;
        assert_eq!(background, by_hand);
        let ended: Vec<&str> = by_hand.iter().map(|m| m.ended.as_str()).collect();
        assert_eq!(
            ended,
            [
                "paired",
                "DENIED",
                "paired",
                "DENIED",
                "DENIED",
                "DENIED",
                "BANNED",
                "DENIED",
                "DENIED",
                "RATE_LIMITED",
                "BUSY"
            ]
        );
        let sheets: Vec<bool> = by_hand.iter().map(|m| m.sheet.is_some()).collect();
        assert_eq!(
            sheets,
            [
                true, true, true, true, true, true, false, true, true, false, false
            ]
        );
        assert_eq!(by_hand[0].sheet.as_ref().unwrap().1, None, "no alarm");
        for alarmed in &by_hand[1..3] {
            assert_eq!(
                alarmed.sheet.as_ref().unwrap().1.as_deref(),
                Some("Office PC"),
                "the alarm"
            );
        }
    }

    /// A pairing through the window's code question, against a host whose
    /// user accepts it. `answer` is how the window's user answers the code
    /// card, and after how long (`None`: never). Returns what the window then
    /// says, and whether this computer pinned the host.
    async fn pair_in_the_window(answer: Option<(bool, Duration)>) -> (String, bool) {
        let tmp = tempfile::tempdir().unwrap();
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let trusted = Arc::new(TrustedDeviceStore::with(
            tmp.path().join("trusted-devices.toml"),
            tornect_core::trusted::TrustedDevices::default(),
        ));
        let consent = Arc::new(ScriptedConsent::new());
        consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
        let mut hdeps = HostDeps::headless(identity.clone(), trusted);
        hdeps.consent = consent;
        let hcfg = HostConfig::new("Desk", [9; 32]);
        let (client_end, host_end) = tokio::io::duplex(64 * 1024);
        let host = tokio::spawn(async move { serve_host(host_end, &hcfg, &hdeps).await });

        let popups = Popups::new(Shared::new(Model::default(), Arc::new(|_| {})));
        let pairing = Arc::new(GuiPairingUi::new(Arc::clone(&popups)));
        let known = Arc::new(KnownHostStore::with(
            tmp.path().join("known-hosts.toml"),
            tornect_core::trusted::KnownHosts::default(),
        ));
        let mut cdeps = ClientDeps::headless(Arc::clone(&known));
        cdeps.ui = pairing.clone();
        if let Some((matched, after)) = answer {
            let popups = Arc::clone(&popups);
            tokio::spawn(async move {
                let id = loop {
                    if let Some(c) = popups.shared().read(|m| m.confirm.clone()) {
                        break c.id;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                };
                tokio::time::sleep(after).await;
                popups.answer_confirm(id, matched);
            });
        }
        let device = DeviceIdentity::from_seed(&[0x22; 32]);
        let ccfg = ClientConfig::new(identity.id(), "Laptop");
        let err = connect(client_end, &ccfg, &device, &cdeps, Intent::Session)
            .await
            .unwrap_err();
        let _ = host.await;
        let said = format!("{:#}", not_started(err, pairing.ended()));
        (said, known.is_known(&identity.id()))
    }

    /// The live console check of 2026-09-24: the window's code question ran
    /// out unseen after 50 s (the card never comes to the front: SLICE-E
    /// E1-1), after the host had paired this device, and the window then said
    /// "run the command again", a hint for the command line. The question now
    /// stays up past the host's wait, a late "the codes match" still pairs
    /// this computer, and every end of the question is said in the window's
    /// terms.
    #[tokio::test(start_paused = true)]
    async fn an_unconfirmed_pairing_ends_in_the_windows_words() {
        for (answer, says, pinned) in [
            (
                Some((false, Duration::from_secs(5))),
                "Not paired: you answered that the codes differ",
                false,
            ),
            (None, "Not paired: nobody answered the code question", false),
            (
                Some((true, Duration::from_secs(70))),
                "Paired: this computer now knows the host",
                true,
            ),
        ] {
            let (said, is_pinned) = pair_in_the_window(answer).await;
            assert!(said.starts_with(says), "{answer:?}: {said}");
            assert!(said.contains("Connect again"), "{answer:?}: {said}");
            assert!(!said.contains("command"), "{answer:?}: {said}");
            assert_eq!(is_pinned, pinned, "{answer:?}: {said}");
        }
    }

    /// Slice-G closure R2-I1: after a late "the codes match", only an end
    /// that says the host went away (the stream closed, an I/O or framing
    /// failure, the host's goodbye) is worded "Paired". Any other error keeps
    /// its own words: a known-hosts file that could not be written pinned
    /// nothing, and a violation or a timeout came from a host still there.
    #[test]
    fn only_the_host_going_away_after_a_late_yes_reads_as_paired() {
        use tornect_signal::envelope::codes;
        use tornect_signal::framing::FrameError;

        let late = Some(CodeCheck::MatchedLate);
        for gone in [
            HandshakeError::Closed,
            HandshakeError::Io(std::io::ErrorKind::BrokenPipe.into()),
            HandshakeError::Frame(FrameError::Truncated),
            HandshakeError::PeerBye {
                reason: bye::USER,
                detail: None,
            },
        ] {
            let said = format!("{:#}", not_started(gone, late));
            assert!(said.starts_with("Paired:"), "{said}");
        }
        for other in [
            HandshakeError::Store(tornect_core::CoreError::Io(
                std::io::ErrorKind::PermissionDenied.into(),
            )),
            HandshakeError::Violation {
                code: codes::E_BAD_SIG,
                what: "signature",
            },
            HandshakeError::Timeout("SESSION_ACCEPT"),
        ] {
            let said = format!("{:#}", not_started(other, late));
            assert!(!said.contains("Paired"), "{said}");
        }
    }

    /// Review N-4: closing a window that both views another host and shares
    /// this screen (the close button, Ctrl-C or SIGTERM) ends the hosted
    /// session at once, however long Tor stalls the viewed session's goodbye;
    /// the viewed session still gets its goodbye time.
    #[tokio::test]
    async fn closing_ends_the_hosted_session_before_the_viewed_goodbye() {
        let kill = KillSwitch::new();
        let (stop, _stopped) = watch::channel(false);
        // A viewed session whose goodbye never gets through.
        let stalled = tokio::spawn(std::future::pending::<()>());
        let hosted = kill.clone();
        let ending =
            tokio::spawn(async move { end_sessions(Some((stop, stalled)), Some(&hosted)).await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let fired = kill.fired();
        let waiting = !ending.is_finished();
        ending.abort();
        assert_eq!(
            fired,
            Some(bye::USER),
            "the hosted session was still shared while the viewed goodbye waited"
        );
        assert!(waiting, "the viewed session got no time for its goodbye");
    }

    /// Review P2-I4: a session that goes live while the viewed session's
    /// goodbye stalls (it armed after the shutdown kill: a peer with
    /// unattended rights, or a consent clicked while the window closes) is
    /// ended too, while the goodbye still waits.
    #[tokio::test]
    async fn a_session_that_goes_live_during_the_goodbye_is_ended_too() {
        let kill = KillSwitch::new();
        let (stop, _stopped) = watch::channel(false);
        let stalled = tokio::spawn(std::future::pending::<()>());
        let hosted = kill.clone();
        let ending =
            tokio::spawn(async move { end_sessions(Some((stop, stalled)), Some(&hosted)).await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        // A session accepted now, after the shutdown kill.
        let mut late = kill.arm();
        let ended = tokio::time::timeout(Duration::from_secs(1), late.killed()).await;
        let waiting = !ending.is_finished();
        ending.abort();
        assert_eq!(
            ended.ok(),
            Some(bye::USER),
            "a session that went live during the goodbye stayed live"
        );
        assert!(waiting, "the viewed session got no time for its goodbye");
    }

    /// SLICE-E E1-6: a release that finds the input queue full (a Tor stall
    /// with the pointer moving) is not lost: once there is room, a
    /// `ReleaseAll` goes out before anything else, so no key or button stays
    /// down on the host.
    #[test]
    fn a_release_that_finds_the_queue_full_goes_out_as_release_all() {
        let link = StreamLink::default();
        let (tx, mut rx) = mpsc::channel(INPUT_QUEUE);
        link.set_input(Some(tx));
        for i in 0..INPUT_QUEUE {
            assert!(link.send(InputEvent::PointerMove {
                x: u16::try_from(i).unwrap(),
                y: 0
            }));
        }
        let key_up = InputEvent::Key {
            usb: 0x07_0004,
            pressed: false,
        };
        assert!(!link.send(key_up), "the queue is full");
        // The stall ends: the viewer task drains the queue.
        while rx.try_recv().is_ok() {}
        let moved = InputEvent::PointerMove { x: 7, y: 7 };
        assert!(link.send(moved));
        assert_eq!(
            rx.try_recv(),
            Ok(InputEvent::ReleaseAll),
            "the lost key-up is made good first"
        );
        assert_eq!(rx.try_recv(), Ok(moved));
        assert!(rx.try_recv().is_err());

        // With nothing more to send, the window's idle loop settles it.
        for _ in 0..INPUT_QUEUE {
            assert!(link.send(moved));
        }
        let button_up = InputEvent::PointerButton {
            button: tornect_input::Button::Left,
            pressed: false,
        };
        assert!(!link.send(button_up));
        assert!(link.settle(), "still owed while the queue is full");
        while rx.try_recv().is_ok() {}
        assert!(!link.settle(), "sent once there is room");
        assert_eq!(rx.try_recv(), Ok(InputEvent::ReleaseAll));
        assert!(rx.try_recv().is_err());

        // A move that finds the queue full owes nothing.
        for _ in 0..INPUT_QUEUE {
            assert!(link.send(moved));
        }
        assert!(!link.send(moved));
        while rx.try_recv().is_ok() {}
        assert!(!link.settle());
        assert!(rx.try_recv().is_err());
    }

    /// Release verification T-1: the window's first input gate, the mode of
    /// the host's signed SESSION_ACCEPT. Only a control grant sends input; a
    /// view-only grant never does, nor does a code this build does not know.
    #[test]
    fn only_a_control_grant_sends_input() {
        use tornect_signal::consent::mode_code;

        // Every mode a host can grant; a new one fails to compile here until
        // it is decided.
        for mode in [SessionMode::Control, SessionMode::ViewOnly] {
            let control = match mode {
                SessionMode::Control => true,
                SessionMode::ViewOnly => false,
            };
            assert_eq!(sends_input(mode_code(mode)), control, "{mode:?}");
        }
        // Every wire value: the control code is the only one that sends input.
        for code in 0..=u8::MAX {
            assert_eq!(
                sends_input(code),
                code == mode_code(SessionMode::Control),
                "mode code {code}"
            );
        }
    }

    /// Through the real handshake: an allowed session shows on the indicator,
    /// and its Stop (the host-wide kill, `Command::StopSharing`) ends that
    /// session with `BYE{USER}`, after which the indicator closes; the
    /// session this machine views is not touched.
    #[tokio::test]
    async fn the_indicators_stop_ends_the_shared_session_and_it_closes() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        // This machine also views another host; Stop must leave that alone.
        shared.update(|m| {
            m.client = ClientStage::Live(Viewing {
                host: "Office PC".to_owned(),
                control: true,
                administrator: false,
                unattended: false,
                since: Instant::now(),
                pictures: 0,
                size: (0, 0),
            });
        });
        let popups = Popups::new(Arc::clone(&shared));
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let media = Arc::new(MediaHost::new(
            Arc::new(SystemBackend::new(Source::TestCard)),
            Arc::new(GuiMedia {
                shared: Arc::clone(&shared),
            }),
            MediaLimits::default(),
        ));
        let mut wiring = crate::host::wire(
            &paths,
            &Config::default(),
            Arc::clone(&identity),
            HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32])),
            Arc::new(AutoDeny),
            Arc::clone(&media),
            ControlChannel::default(),
        )
        .unwrap();
        let (started_tx, started) = watch::channel(0u64);
        let activity = Arc::clone(&wiring.live);
        wiring.deps.consent = Arc::new(GuiConsent::new(
            Arc::clone(&popups),
            Withdraw {
                kill: wiring.deps.kill.clone(),
                started,
                live: Arc::new(move || activity.session_live()),
            },
        ));
        wiring.deps.sessions = Arc::new(GuiSessions {
            live: Arc::clone(&wiring.live),
            polkit: Arc::clone(&wiring.polkit),
            media,
            shared: Arc::clone(&shared),
            started: started_tx,
        });
        let kill = wiring.deps.kill.clone();
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let (client_end, host_end) = tokio::io::duplex(64 * 1024);
        let host = tokio::spawn(async move {
            crate::host::serve_signaling(host_end, &cfg, &deps, |_| {}).await;
        });

        // The window's user: the codes match, and the session may control.
        let answering = {
            let popups = Arc::clone(&popups);
            tokio::spawn(async move {
                for _ in 0..2000 {
                    let open = popups.shared().read(|m| m.popups.clone());
                    if let Some(p) = open.first() {
                        match p.kind {
                            PopupKind::Pairing { .. } => {
                                popups.answer_pairing(p.id, PairDecision::Accept { label: None });
                            }
                            PopupKind::Session { .. } => {
                                popups.answer_session(p.id, SessionDecision::AllowOnce);
                                return;
                            }
                            PopupKind::Ask { .. } => {}
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                panic!("no session popup");
            })
        };
        let known = Arc::new(
            KnownHostStore::open(paths.state_dir.join("client-known-hosts.toml")).unwrap(),
        );
        let mut cdeps = ClientDeps::headless(known);
        cdeps.ui = Arc::new(ScriptedClientUi::new(true));
        let device = DeviceIdentity::from_seed(&[0x22; 32]);
        let ccfg = ClientConfig::new(identity.id(), "Laptop");
        let outcome = connect(client_end, &ccfg, &device, &cdeps, Intent::Session).await;
        answering.await.unwrap();
        let Ok(ClientOutcome::Session(mut session)) = outcome else {
            panic!("no session: {outcome:?}");
        };
        session.send_tor_fallback().await.unwrap();

        // Live: the indicator opens and shows the session.
        let sharing = shared.read(|m| m.sharing.clone());
        assert_eq!(sharing.len(), 1);
        assert_eq!(sharing[0].label, "Laptop");
        assert!(sharing[0].control);
        assert!(!sharing[0].unattended, "allowed at a popup");
        let mut indicator = Indicator::default();
        assert_eq!(indicator.sync(&sharing), Change::Open);

        // Stop, as `Command::StopSharing` runs it.
        stop_sharing(&kill, &shared);
        match session.next_event(Duration::from_secs(10)).await {
            Ok(Some(SessionEvent::Bye { reason, .. })) => assert_eq!(reason, bye::USER),
            other => panic!("expected BYE{{USER}}, got {other:?}"),
        }
        let mut closed = false;
        for _ in 0..2000 {
            let sharing = shared.read(|m| m.sharing.clone());
            if indicator.sync(&sharing) == Change::Close {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(closed, "the indicator closed at the session's end");
        assert!(
            shared.read(|m| matches!(m.client, ClientStage::Live(_))),
            "the viewed session is not the one Stop ends"
        );
        tokio::time::timeout(Duration::from_secs(10), host)
            .await
            .expect("the host's stream task ended")
            .unwrap();
    }

    /// The banner and the indicator say "as administrator" from the level
    /// the host signed in the session's accept, as its start reports it, and
    /// never from an answer given on a sheet (H5; M-UI-3 Security F-1).
    #[tokio::test]
    async fn the_banner_and_indicator_read_the_signed_level() {
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let media = Arc::new(MediaHost::new(
            Arc::new(SystemBackend::new(Source::TestCard)),
            Arc::new(GuiMedia {
                shared: Arc::clone(&shared),
            }),
            MediaLimits::default(),
        ));
        let (started, _seen) = watch::channel(0u64);
        let sessions = GuiSessions {
            live: Arc::new(LiveSessions::new()),
            polkit: Arc::new(PolkitRevocation::for_this_host()),
            media,
            shared: Arc::clone(&shared),
            started,
        };
        let token = tornect_signal::consent::SessionToken::new([5; 32]);
        for (id, elevation) in [("a1", Elevation::Admin), ("c1", Elevation::None)] {
            sessions.on_start(&LiveSession {
                device: DeviceIdentity::from_seed(&[9; 32]).id(),
                label: "Laptop",
                session_id: id,
                token: &token,
                th_final: [0; 32],
                mode: SessionMode::Control,
                elevation,
                unattended: false,
            });
            assert_eq!(
                shared.read(|m| m.admin_sessions.contains(id)),
                elevation == Elevation::Admin,
                "{id}"
            );
            sessions.on_end(id, None);
            assert!(
                !shared.read(|m| m.admin_sessions.contains(id)),
                "{id} ended"
            );
        }
    }

    /// The window's sessions sink tells a Control session's viewer the
    /// host's start code from the session's start on, through `notice`: 0 on
    /// a host that does not run Windows; on Windows, at the level none, the
    /// Windows bit and the administrator-windows bit. A view-only session's
    /// viewer is told nothing.
    #[tokio::test]
    async fn the_window_sink_tells_the_viewer_the_start_code() {
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let media = Arc::new(MediaHost::new(
            Arc::new(SystemBackend::new(Source::TestCard)),
            Arc::new(GuiMedia {
                shared: Arc::clone(&shared),
            }),
            MediaLimits::default(),
        ));
        let (started, _seen) = watch::channel(0u64);
        let sessions = GuiSessions {
            live: Arc::new(LiveSessions::new()),
            polkit: Arc::new(PolkitRevocation::for_this_host()),
            media,
            shared: Arc::clone(&shared),
            started,
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
                elevation: Elevation::None,
                unattended: false,
            });
            assert_eq!(sessions.notice(id), want, "{id}");
            sessions.on_end(id, None);
        }
    }

    /// Settings, General: a saved name and theme reach `config.toml`, the
    /// file's other keys stay as they were, and the model then holds what
    /// was saved while the name in use stays until the next start. While
    /// this screen is shared nothing is saved, and a file that cannot be
    /// read keeps what it holds; each says so.
    #[test]
    fn a_saved_name_and_theme_reach_the_config() {
        use tornect_core::config::Theme;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let path = paths.config_file();
        let mut before = Config::default();
        before.media.max_fps = 30;
        before.save(&path).unwrap();
        let shared = Shared::new(
            Model {
                device_name: "Linux PC".to_owned(),
                ..Model::default()
            },
            Arc::new(|_| {}),
        );
        save_settings(
            &paths,
            &shared,
            &SettingsChange::DeviceName("Desk by the window".to_owned()),
        );
        save_settings(&paths, &shared, &SettingsChange::Theme(Theme::Light));
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.general.device_name, "Desk by the window");
        assert_eq!(cfg.general.theme, Theme::Light);
        assert_eq!(cfg.media.max_fps, 30, "the other keys stay");
        shared.read(|m| {
            assert_eq!(m.settings, Settings::of(&cfg));
            assert_eq!(m.settings.problem, None);
            assert_eq!(
                m.device_name, "Linux PC",
                "the name in use until the next start"
            );
        });

        shared.update(|m| m.hosted_elsewhere = true);
        save_settings(&paths, &shared, &SettingsChange::Theme(Theme::Dark));
        assert_eq!(
            Config::load(&path).unwrap(),
            cfg,
            "nothing saved while shared"
        );
        shared.read(|m| {
            assert_eq!(m.settings.theme, Theme::Light);
            assert_eq!(m.settings.problem, Some(NOT_SAVED_SHARED));
        });

        shared.update(|m| m.hosted_elsewhere = false);
        std::fs::write(&path, "this is = not [valid").unwrap();
        save_settings(&paths, &shared, &SettingsChange::Theme(Theme::Dark));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "this is = not [valid"
        );
        shared.read(|m| {
            assert_eq!(m.settings.theme, Theme::Light);
            assert_eq!(m.settings.problem, Some(NOT_SAVED_FILE));
        });
    }

    /// Settings, Connection: the way to Tor, the private bridge lines and the
    /// proof-of-work defence reach `config.toml`, and the model then holds
    /// them; the lines are never printed.
    #[test]
    fn the_bridge_choice_and_lines_reach_the_config() {
        use super::super::model::{BridgeLines, TorChoice};
        use tornect_core::config::BridgeMode;
        const LINE: &str =
            "obfs4 198.51.100.7:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0";
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let choice = TorChoice {
            bridges: BridgeMode::Snowflake,
            bridge_lines: BridgeLines(vec![LINE.to_owned()]),
            pow_defense: false,
        };
        save_settings(&paths, &shared, &SettingsChange::Tor(choice.clone()));
        let cfg = Config::load(&paths.config_file()).unwrap();
        assert_eq!(cfg.tor.bridges, BridgeMode::Snowflake);
        assert_eq!(cfg.tor.bridge_lines, [LINE]);
        assert!(!cfg.tor.pow_defense);
        shared.read(|m| assert_eq!(m.settings.tor, choice));
        let printed = format!("{:?}", SettingsChange::Tor(choice));
        assert!(
            !printed.contains("198.51") && printed.contains("1 lines"),
            "{printed}"
        );
    }

    /// The history notice shows on the first run of a home only.
    #[test]
    fn the_history_notice_shows_once() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        assert!(first_run(&paths), "the first run");
        assert!(!first_run(&paths), "then never again");
        assert!(!first_run(&paths));
    }

    /// FR2-L1: when the keychain refuses to delete the remembered password,
    /// Forget's note says so plainly (the pairing goes all the same); with a
    /// keychain that deletes, the note says what went and nothing more.
    #[test]
    fn forget_says_when_the_password_could_not_be_deleted() {
        use tornect_core::trusted::{KnownHosts, known_hosts_file};
        use tornect_core::unattended::credentials::{
            EntryName, MemoryVault, PasswordVault, SavedPasswords,
        };
        use zeroize::Zeroizing;

        /// A keychain whose delete fails.
        struct Refusing(MemoryVault);
        impl PasswordVault for Refusing {
            fn describe(&self) -> &'static str {
                self.0.describe()
            }
            fn presence_gated(&self) -> bool {
                false
            }
            fn get(&self, entry: &EntryName) -> tornect_core::Result<Option<Zeroizing<String>>> {
                self.0.get(entry)
            }
            fn put(&self, entry: &EntryName, password: &str) -> tornect_core::Result<()> {
                self.0.put(entry, password)
            }
            fn delete(&self, _: &EntryName) -> tornect_core::Result<bool> {
                Err(std::io::Error::other("the keychain refused").into())
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        paths.ensure().unwrap();
        let host = HostIdentity::from_seed(&[0x77; 32]).id();
        let paired = || {
            let mut known = KnownHosts::default();
            known.pin(host, "Desk", [9; 32], 1);
            known.save(&known_hosts_file(&paths)).unwrap();
        };
        let forgot = format!(
            "Forgot {}…: the next connection to it compares a code again.",
            host.short()
        );

        let refusing = Arc::new(Refusing(MemoryVault::new()));
        let saved = SavedPasswords::new(Some(refusing.clone()), [1; 32]);
        paired();
        refusing.0.put(&saved.entry(&host), "pw").unwrap();
        assert_eq!(
            forget(&paths, &saved, &host),
            format!(
                "{forgot} The password remembered for \"Desk\" could not be deleted from a test \
                 keychain; Rotate ID deletes it later."
            )
        );
        assert_eq!(refusing.0.names().len(), 1, "the password is still there");
        let known = KnownHosts::load(&known_hosts_file(&paths)).unwrap();
        assert!(known.get(&host).is_none(), "the pairing went all the same");

        let vault = Arc::new(MemoryVault::new());
        let saved = SavedPasswords::new(Some(vault.clone()), [1; 32]);
        paired();
        vault.put(&saved.entry(&host), "pw").unwrap();
        assert_eq!(forget(&paths, &saved, &host), forgot);
        assert!(vault.names().is_empty());
    }

    /// After a refused delete the window cannot offer Forget for that host again:
    /// Forget took its pin and its address-book entry, so the address book lists
    /// no computer to forget, while `hosts.toml` keeps the record with `remember`
    /// set, for the check when the prompt opens or Rotate ID to delete it.
    #[test]
    fn forget_is_not_offered_again_after_a_refused_delete() {
        use tornect_core::trusted::{KnownHosts, known_hosts_file};
        use tornect_core::unattended::credentials::{
            EntryName, MemoryVault, PasswordVault, SavedPasswords,
        };
        use tornect_core::unattended::hosts::HostsFile;
        use zeroize::Zeroizing;

        /// A keychain whose delete fails.
        struct Refusing(MemoryVault);
        impl PasswordVault for Refusing {
            fn describe(&self) -> &'static str {
                self.0.describe()
            }
            fn presence_gated(&self) -> bool {
                false
            }
            fn get(&self, entry: &EntryName) -> tornect_core::Result<Option<Zeroizing<String>>> {
                self.0.get(entry)
            }
            fn put(&self, entry: &EntryName, password: &str) -> tornect_core::Result<()> {
                self.0.put(entry, password)
            }
            fn delete(&self, _: &EntryName) -> tornect_core::Result<bool> {
                Err(std::io::Error::other("the keychain refused").into())
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        paths.ensure().unwrap();
        let host = HostIdentity::from_seed(&[0x78; 32]).id();
        let mut known = KnownHosts::default();
        known.pin(host, "Desk", [9; 32], 1);
        known.save(&known_hosts_file(&paths)).unwrap();
        let mut file = HostsFile::default();
        file.entry(&host).remember = true;
        file.save(&paths.hosts_file()).unwrap();
        let refusing = Arc::new(Refusing(MemoryVault::new()));
        let saved = SavedPasswords::new(Some(refusing.clone()), [1; 32]);
        refusing.0.put(&saved.entry(&host), "pw").unwrap();
        let today = tornect_core::address_book::Day::today();
        assert!(
            book::read(&paths, today, None)
                .computers
                .iter()
                .any(|c| c.id == host),
            "listed, with its Forget, before"
        );

        let note = forget(&paths, &saved, &host);
        assert_eq!(refusing.0.names().len(), 1, "the password is still there");
        assert!(
            !book::read(&paths, today, None)
                .computers
                .iter()
                .any(|c| c.id == host),
            "no computer left to forget"
        );
        let record = HostsFile::load(&paths.hosts_file()).unwrap();
        assert!(record.get(&host).is_some_and(|r| r.remember));
        // So the note names what does delete it.
        assert!(note.ends_with("; Rotate ID deletes it later."), "{note}");
    }

    /// The window says once that the administrator level was not given: on the
    /// Home status line, not again in the recent activity; its other notes stay,
    /// in order, after what the settle said.
    #[test]
    fn the_window_does_not_repeat_the_level_not_given_note() {
        use tornect_core::unattended::credentials::note;
        let named = "\"Desk\"";
        let after = ua_client::AfterAccept {
            settled: Err(anyhow::anyhow!("the disk is full")),
            deleted_first: false,
            notes: vec![
                note::view_only(named),
                note::level_not_given(named),
                note::failed_delete(named, "a test keychain"),
            ],
        };
        assert_eq!(
            connect_notes(named, after),
            vec![
                "The password could not be remembered: the disk is full".to_owned(),
                note::view_only(named),
                note::failed_delete(named, "a test keychain"),
            ]
        );
    }

    /// An attended or a pairing connect (`classify`) whose host stops
    /// answering before anything is asked of anyone (its `HELLO_ACK`; an
    /// `AUTH_CHALLENGE`, which only an unattended attempt waits for, would
    /// read the same) reads as unreachable, never as a person who did not
    /// answer. An unattended attempt is worded by `ua_failure`:
    /// `an_unattended_stall_reads_as_unreachable`.
    #[test]
    fn a_stalled_host_reads_as_unreachable() {
        for what in ["HELLO_ACK", "AUTH_CHALLENGE"] {
            assert_eq!(
                classify(&HandshakeError::Timeout(what), None),
                Failure::Unreachable,
                "{what}"
            );
        }
        // A popup or a pairing question that ran out of time is still the
        // person's.
        let popup = HandshakeError::SessionRejected {
            reject: Box::new(tornect_signal::messages::SessionReject::new(
                reject::POPUP_TIMEOUT,
            )),
        };
        let pairing = HandshakeError::PairRejected {
            reason: pair_reject::TIMEOUT,
            detail: None,
        };
        for err in [popup, pairing, HandshakeError::Timeout("SESSION_ACCEPT")] {
            assert_eq!(classify(&err, None), Failure::TimedOut, "{err}");
        }
    }

    /// This computer's own code question, left unanswered, has its own
    /// words: nobody at the other computer is blamed.
    #[test]
    fn an_unanswered_code_question_here_has_its_own_words() {
        for err in [
            HandshakeError::Timeout("PAIR_ACCEPT"),
            HandshakeError::Closed,
            HandshakeError::PairRejected {
                reason: pair_reject::TIMEOUT,
                detail: None,
            },
        ] {
            assert_eq!(
                classify(&err, Some(CodeCheck::Unanswered)),
                Failure::CodeUnanswered,
                "{err}"
            );
        }
        assert_eq!(
            Failure::CodeUnanswered.title(),
            "Nobody answered the code question here"
        );
        assert_eq!(
            Failure::CodeUnanswered.advice(),
            "Nothing was saved. Press Connect again and answer the code question on this computer."
        );
    }

    /// An unattended attempt (`ua_failure`) whose host stops answering
    /// before the password was tried (its `HELLO_ACK` or `AUTH_CHALLENGE`)
    /// reads as unreachable at the step of reaching the computer, never as a
    /// person who did not answer; one whose accept never came after the
    /// password still reads as timed out at the computer's checks.
    #[test]
    fn an_unattended_stall_reads_as_unreachable() {
        for what in ["HELLO_ACK", "AUTH_CHALLENGE"] {
            let err = HandshakeError::Timeout(what);
            let ended = ua_client::ended(&err, "Office PC");
            assert_eq!(
                ua_failure(&err, &ended),
                (Failure::Unreachable, 1),
                "{what}"
            );
        }
        let err = HandshakeError::Timeout("SESSION_ACCEPT");
        let ended = ua_client::ended(&err, "Office PC");
        assert_eq!(ua_failure(&err, &ended), (Failure::TimedOut, 3));
    }
}
