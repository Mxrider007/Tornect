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

use super::book::{self, Change};
use super::consent::{CodeCheck, GuiConsent, GuiPairingUi, Popups, Withdraw};
use super::model::{
    CaptureNote, Check, ClientStage, Dial, Failure, Hosting, Shared, Sharing, TorState, Viewing,
    Wake,
};
use super::recognize::Lookalike;
use super::stream::{FrameSlot, SlotSink};
use crate::host::{
    ControlChannel, HostLock, HostWiring, PolkitRevocation, describe_end, describe_media, note, say,
};
use crate::tor_cmd::{End, explain, explain_handshake};

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
    /// Shut down.
    Quit,
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

/// How often a window that is not the host looks whether another Tornect
/// process holds this home's host lock.
const HOST_LOCK_EVERY: Duration = Duration::from_secs(2);

/// The host role, once wired.
struct Hosted {
    serving: Arc<(HostConfig, HostDeps)>,
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

/// Wire the host role: the FSM with the window's consent, the media host, and
/// the control channel (bound before Tor, as `tornect host` does).
async fn host_role(b: &Backend) -> Result<Hosted, String> {
    let lock = HostLock::acquire(&b.paths).map_err(|e| format!("{e:#}"))?;
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
    } = crate::host::wire(
        &b.paths,
        &b.cfg,
        Arc::clone(&b.identity),
        b.device_pk,
        Arc::new(AutoDeny),
        Arc::clone(&media),
        control.clone(),
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
    deps.consent = Arc::new(
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
    deps.sessions = Arc::new(GuiSessions {
        live: Arc::clone(&live),
        polkit: Arc::clone(&polkit),
        media: Arc::clone(&media),
        shared: Arc::clone(&b.shared),
        started: started_tx,
    });
    let kill_watch = media.watch_kill(deps.kill.clone());
    let ipc = crate::host::start_control_channel(&b.paths, ctx, deps.kill.clone(), control)
        .await
        .map_err(|e| format!("{e:#}"))?;
    Ok(Hosted {
        serving: Arc::new((cfg, deps)),
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

/// Run until [`Command::Quit`], then shut down and mark the model closed.
pub async fn run(b: Backend, mut commands: mpsc::UnboundedReceiver<Command>) {
    let b = Arc::new(b);
    let first = first_run(&b.paths);
    b.shared.update(|m| m.history_notice = first);
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
                        say(format_args!("Tornect ID: {}", l.onion_address()));
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
                        let task = tokio::spawn(view_session(Arc::clone(&b), node, id, stop, anyway));
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

    // Shutting down: the sessions end (`end_sessions`), every media stream
    // gets its `Close`, then Tor goes.
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

/// Make an address-book change the window asked for (on this side, never on
/// the UI thread) and show the files as they are now.
fn change_book(b: &Backend, change: &Change) {
    let note = book::apply(&b.paths, change);
    refresh_book(b, Some(note));
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

/// View `id`: pair if it is new, ask for a session, then show its screen and
/// send input if the host allowed control. Ends when the user stops or either
/// side goes away; the window learns how it ended.
async fn view_session(
    b: Arc<Backend>,
    node: Arc<TorNode>,
    id: TornectId,
    stop: watch::Receiver<bool>,
    anyway: bool,
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
    let ended = viewed(&b, &node, id, &stop).await;
    b.link.set_input(None);
    let message = match ended {
        Ok(message) => message,
        Err(e) => format!("{e:#}"),
    };
    say(format_args!("VIEWER: {message}"));
    b.shared.update(|m| {
        m.client = ClientStage::Ended(message.clone());
        m.note(message);
    });
}

async fn viewed(
    b: &Backend,
    node: &TorNode,
    id: TornectId,
    stop: &watch::Receiver<bool>,
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
        };
    });
    // One isolation group: the media stream rides the signaling circuit.
    let isolation = Isolation::new();
    let Some(stream) = unless_stopped(node.connect_on(&id, SIGNALING_PORT, &isolation), stop).await
    else {
        return Ok("Cancelled.".to_owned());
    };
    if stream.is_err() {
        failed(b, Failure::Unreachable);
    }
    let stream = stream.map_err(explain)?;
    // With history off the handshake works on a copy of the known hosts, so
    // that its last-seen touch writes nothing (`crate::history`).
    let pins = crate::history::Pins::open(&b.paths, id)?;
    if pins.known() {
        b.shared.update(|m| m.client = ClientStage::Asking);
    }
    let ccfg = ClientConfig::new(id, b.cfg.general.device_name.clone());
    let pairing = Arc::new(GuiPairingUi::new(Arc::clone(&b.popups)));
    let deps = ClientDeps {
        known_hosts: pins.store(),
        ui: pairing.clone(),
        random: Arc::new(OsRandom),
        // Consulted only by unattended sessions, which the window does not ask for.
        server_key_pin: Arc::new(NoServerKeyPin),
    };
    let outcome = unless_stopped(
        client::connect(stream, &ccfg, &b.device, &deps, Intent::Session),
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
        return Ok("Cancelled before the session started.".to_owned());
    };
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
    say(format_args!(
        "SESSION LIVE {} with \"{host}\" ({})",
        session.session_token().session_id(),
        match (control, administrator) {
            (true, true) => "control · administrator",
            (true, false) => "control",
            (false, _) => "view-only",
        }
    ));
    b.shared.update(|m| {
        m.client = ClientStage::Live(Viewing {
            host: host.clone(),
            control,
            administrator,
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

/// Record why the connection ended without a session, at the step it had
/// reached.
fn failed(b: &Backend, why: Failure) {
    b.shared.update(|m| {
        let step = match m.client {
            ClientStage::Pairing { .. } => 2,
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
        (_, Some(CodeCheck::Unanswered)) => Failure::TimedOut,
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

    /// The history notice shows on the first run of a home only.
    #[test]
    fn the_history_notice_shows_once() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        assert!(first_run(&paths), "the first run");
        assert!(!first_run(&paths), "then never again");
        assert!(!first_run(&paths));
    }
}
