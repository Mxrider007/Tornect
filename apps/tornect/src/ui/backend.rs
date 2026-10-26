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
use tornect_core::config::QualityPreset;
use tornect_core::levels::Elevation;
use tornect_core::session_log::SessionMode;
use tornect_core::{Config, DeviceIdentity, HostIdentity, Paths, TornectId};
use tornect_input::InputEvent;
use tornect_input::clipboard::ClipText;
use tornect_session::services::{
    ChatText, ServicesBinding, ServicesHost, ServicesLimits, ServicesPolicy, ViewerClip, ViewerOp,
};
use tornect_session::{
    CaptureChanged, CaptureStarted, MediaEnd, MediaHost, MediaLimits, MediaObserver, MediaReport,
    Source, SystemBackend, ViewerRequest,
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
use tornect_signal::{Isolation, MEDIA_PORT, SERVICES_PORT, SIGNALING_PORT, TorNode};

use super::block::GuiBlockWindow;
use super::book::{self, Change};
use super::consent::{CodeCheck, GuiConsent, GuiPairingUi, Popups, Withdraw};
use super::model::{
    Candidate, CaptureNote, Check, ClientStage, DeviceCard, Dial, Failure, GrantLevel,
    GrantRequest, GrantRow, HostSetting, Hosting, Manager, ManagerOp, NewPassword, PauseEnd,
    PolicyInputs, RotateFailed, Settings, SettingsChange, Shared, Sharing, StreamInfo, TorState,
    UnattendedBanner, ViewOnly, ViewerServices, Viewing, Wake, WizardAnswer, WizardChoice,
    WizardView,
};
use super::recognize::Lookalike;
use super::services::GuiServices;
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
/// Screen requests queued for the media stream: the window sends one at a
/// time (its button waits for the answer), and one more finds it full.
const SCREEN_REQUESTS: usize = 1;
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
    /// Run one operation of Settings, Security through the window host's
    /// guard, as the window (§B.8.6.2).
    Manager(ManagerOp),
    /// The first run's question answered: the name typed, or `None` (Skip).
    FirstRunName(Option<String>),
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
    /// Try Tor, or the publishing of this computer's ID, again now, rather
    /// than when the automatic try after its failure is due (B02).
    RetryTor,
    /// The viewer picked this preset in the stream window's Quality menu:
    /// sent to the host of the session being viewed, if it changes anything
    /// (the quality design §3.2).
    Quality(QualityPreset),
    /// The viewer chose this screen in the stream window's Screens menu (0:
    /// all of them): sent to the host of the session being viewed, in
    /// control and view-only sessions alike, unless a request waits for its
    /// answer (the monitors design §2, V1).
    ShowScreen(u8),
    /// The host's person acts on a shared session's services (design
    /// `services` §7.2): writes in its chat, stops one of its transfers, or
    /// turns its clipboard and files off for the rest of the session.
    HostServices {
        /// The shared session (`sessions.log`'s id).
        session_id: String,
        /// What to do.
        op: HostServicesOp,
    },
    /// The viewer's person acts on the viewed session's services (design
    /// §7.1): chat, the Clipboard switch, the files panel, a file dropped on
    /// the stream window.
    Services(ViewerOp),
    /// Shut down.
    Quit,
}

/// What the host's person does with a shared session's services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostServicesOp {
    /// Write to the viewer.
    Chat(ChatText),
    /// Stop the transfer whose row has this id (`Cancel{BY_HOST}`).
    Cancel(u32),
    /// Turn these caps (`tornect_proto::services::caps`) off for the rest
    /// of the session: one way, never back (`ServicesHost::turn_off`).
    TurnOff(u16),
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

/// What the viewer and the stream window share: the newest picture, while
/// a control session runs the way to the host for input, and while any
/// session runs the way to it for the viewer's quality picks and screen
/// requests.
#[derive(Debug, Default)]
pub struct StreamLink {
    /// The newest picture.
    pub slot: Arc<FrameSlot>,
    input: Mutex<Input>,
    /// The picks of the session being viewed (`MediaViewer::with_quality`
    /// sends each change as one `SetQuality`): a new channel for every
    /// session, so no pick of an earlier one reaches a later one.
    quality: Mutex<Option<watch::Sender<QualityPreset>>>,
    /// The screen requests of the session being viewed
    /// (`MediaViewer::run_with` sends each as one `SelectMonitor`), in
    /// control and view-only sessions alike: a new channel for every
    /// session, as for the picks.
    requests: Mutex<Option<mpsc::Sender<ViewerRequest>>>,
    /// The services requests of the session being viewed
    /// (`ServicesViewer::run` reads them; design `services` §6.1): a new
    /// channel for every session, as for the picks.
    services: Mutex<Option<mpsc::Sender<ViewerOp>>>,
    /// The window's clipboard for the session's services (design §4.3).
    clip: ClipSlot,
}

/// Services requests queued for the stream: the window sends one per click
/// or key, and one beyond that is dropped.
const SERVICES_REQUESTS: usize = 32;

/// The stream window's clipboard as the viewed session's services stream
/// sees it (design `services` §4.3, §7.1): what the window read of its
/// clipboard goes out through `outbound`, what the host sent waits in
/// `inbound` for the window to put it on this computer's clipboard.
#[derive(Debug, Default)]
struct ClipSlot {
    /// The window reads and sets its clipboard for a session's services
    /// (from the design's step 24, which says so): until it does, no
    /// session shares a clipboard and the host is never asked to, so no
    /// text of the host's leaves it for a window that would not use it.
    window: std::sync::atomic::AtomicBool,
    /// The session's ends, while its services run.
    ends: Mutex<Option<WindowClip>>,
}

/// The window's ends of a session's clipboard channels.
#[derive(Debug)]
struct WindowClip {
    /// Text the window read (newest wins).
    outbound: watch::Sender<Option<ClipText>>,
    /// Text the host sent (newest wins).
    inbound: watch::Receiver<Option<ClipText>>,
}

/// The window's ends of the session's clipboard (design `services` §4.3).
impl super::pages::viewer::Ends for StreamLink {
    fn offer(&self, text: ClipText) -> bool {
        self.offer_clip(text)
    }

    fn take(&self) -> Option<ClipText> {
        self.take_clip()
    }
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

    /// A session starts with `initial` (the settings' preset): a fresh
    /// channel for its picks, whose receiver goes to its viewer.
    fn start_quality(&self, initial: QualityPreset) -> watch::Receiver<QualityPreset> {
        let (tx, rx) = watch::channel(initial);
        self.set_quality(Some(tx));
        rx
    }

    /// The channel of the session's picks; `None` at its end.
    fn set_quality(&self, tx: Option<watch::Sender<QualityPreset>>) {
        *self.quality.lock().unwrap_or_else(PoisonError::into_inner) = tx;
    }

    /// A session starts: a fresh channel for its screen requests, whose
    /// receiver goes to its viewer.
    fn start_requests(&self) -> mpsc::Receiver<ViewerRequest> {
        let (tx, rx) = mpsc::channel(SCREEN_REQUESTS);
        self.set_requests(Some(tx));
        rx
    }

    /// The channel of the session's screen requests; `None` at its end.
    fn set_requests(&self, tx: Option<mpsc::Sender<ViewerRequest>>) {
        *self.requests.lock().unwrap_or_else(PoisonError::into_inner) = tx;
    }

    /// A session's services start: a fresh channel for their requests, whose
    /// receiver goes to its stream.
    fn start_services(&self) -> mpsc::Receiver<ViewerOp> {
        let (tx, rx) = mpsc::channel(SERVICES_REQUESTS);
        self.set_services(Some(tx));
        rx
    }

    /// The channel of the session's services requests; `None` at its end.
    fn set_services(&self, tx: Option<mpsc::Sender<ViewerOp>>) {
        *self.services.lock().unwrap_or_else(PoisonError::into_inner) = tx;
    }

    /// Queue `op` for the viewed session's services stream; whether it was
    /// queued (never blocks the UI thread). `false` with no services stream,
    /// or with the queue full.
    pub fn services(&self, op: ViewerOp) -> bool {
        self.services
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|tx| tx.try_send(op).is_ok())
    }

    /// The window says whether it reads and sets its clipboard for the
    /// sessions' services (design `services` §4.3): sessions whose services
    /// start afterwards follow it. Turned off, the clipboard ends of the
    /// session whose services run go at once; whether a session's ends are
    /// held after the change (`true` only when turned on, for a session
    /// whose services started with the window's clipboard).
    pub fn set_window_clipboard(&self, on: bool) -> bool {
        let mut ends = self
            .clip
            .ends
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.clip.window.store(on, Ordering::SeqCst);
        if !on {
            *ends = None;
        }
        ends.is_some()
    }

    /// Whether the window said it reads and sets its clipboard.
    #[cfg(test)]
    pub(crate) fn window_clipboard(&self) -> bool {
        self.clip.window.load(Ordering::SeqCst)
    }

    /// A session's services start with the window's switch at `on`: a fresh
    /// pair of clipboard channels, whose far ends go to its stream; `None`
    /// when the window shares no clipboard (the host is then never asked
    /// to share one).
    pub(super) fn start_clip(&self, on: bool) -> Option<ViewerClip> {
        let mut ends = self
            .clip
            .ends
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *ends = None;
        if !self.clip.window.load(Ordering::SeqCst) {
            return None;
        }
        let (outbound, outbound_rx) = watch::channel(None);
        let (inbound_tx, inbound) = watch::channel(None);
        *ends = Some(WindowClip { outbound, inbound });
        Some(ViewerClip {
            outbound: outbound_rx,
            inbound: inbound_tx,
            on,
        })
    }

    /// The session's clipboard channels go with its services.
    fn end_clip(&self) {
        *self
            .clip
            .ends
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// The window read `text` from this computer's clipboard (after it got
    /// the keyboard focus, never while this computer shares its screen, and
    /// never the text that was there when the session went live): it goes
    /// to the host if the session's services share the clipboard, newest
    /// wins. Whether a session's services took it.
    pub fn offer_clip(&self, text: ClipText) -> bool {
        self.clip
            .ends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|ends| {
                ends.outbound.send_replace(Some(text));
                true
            })
    }

    /// The text the host sent that the window has not put on this
    /// computer's clipboard yet (the newest), taken: each text is handed out
    /// once.
    pub fn take_clip(&self) -> Option<ClipText> {
        let mut ends = self
            .clip
            .ends
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let inbound = &mut ends.as_mut()?.inbound;
        if !inbound.has_changed().unwrap_or(false) {
            return None;
        }
        inbound.borrow_and_update().clone()
    }

    /// The session's clipboard text from the host, for the window's own
    /// clipboard: each change wakes the stream window, so that text sent
    /// while no picture comes is put on the clipboard without waiting for
    /// one. `None` without the session's clipboard ends.
    fn clip_arrivals(&self) -> Option<watch::Receiver<Option<ClipText>>> {
        self.clip
            .ends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|ends| ends.inbound.clone())
    }

    /// Ask the host of the session being viewed to show screen `id` (0: all
    /// of them); whether the request was queued (never blocks the UI
    /// thread). `false` with no session, or with the queue full.
    pub fn show_screen(&self, id: u8) -> bool {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|tx| tx.try_send(ViewerRequest::ShowScreen(id)).is_ok())
    }

    /// The viewer picked `preset` in the toolbar: it goes to the host only
    /// if it differs from the last pick (or the session's first preset),
    /// and only while a session runs. Whether it goes.
    pub fn request_quality(&self, preset: QualityPreset) -> bool {
        self.quality
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|tx| {
                tx.send_if_modified(|held| {
                    let changed = *held != preset;
                    *held = preset;
                    changed
                })
            })
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
    /// The unattended store of this window's host role, once wired with one:
    /// this device's own lines for its unattended connects go through it
    /// ([`Self::log_attempt`]), so that `sessions.log` has one writer in this
    /// process and the lines carry the tag the host's verifier checks.
    pub hosted_store: std::sync::OnceLock<tornect_core::unattended::store::GrantStore>,
}

impl Backend {
    /// This device's `sessions.log` line for one unattended attempt at `known`
    /// (§B.8.13): through the store of this window's host role, else keyed as
    /// that store would key it ([`ua_client::log_attempt_via`]).
    fn log_attempt(&self, known: &tornect_core::trusted::KnownHost, logged: &Logged<'_>) {
        ua_client::log_attempt_via(self.hosted_store.get(), &self.paths, known, logged);
    }
}

/// The marker the window's first run leaves in the state directory of the
/// home `paths`. It says nothing about any connection.
fn first_run_marker(paths: &Paths) -> std::path::PathBuf {
    paths.state_dir.join("history-notice-shown")
}

/// Whether this is the window's first run in the home `paths`: its marker is
/// not there yet. The check writes nothing.
fn first_run_due(paths: &Paths) -> bool {
    !first_run_marker(paths).exists()
}

/// Leave the first run's marker, so that the history notice and the name
/// question show once. When it cannot be written they show again next time.
fn mark_first_run(paths: &Paths) {
    let marker = first_run_marker(paths);
    if let Err(e) =
        std::fs::create_dir_all(&paths.state_dir).and_then(|()| std::fs::write(&marker, b""))
    {
        tracing::debug!(error = %e, "the history notice will show again");
    }
}

/// Whether this is the window's first run in the home `paths`, checked and
/// marked at once, for a start that asks nothing (background mode): the
/// first time, the marker is left so that the history notice shows once.
fn first_run(paths: &Paths) -> bool {
    let first = first_run_due(paths);
    if first {
        mark_first_run(paths);
    }
    first
}

/// The settings page's line when a change was not saved because this screen
/// may be in a picture that leaves it (the change may not be this
/// computer's user's own).
const NOT_SAVED_SHARED: &str = "Not saved: this screen is shared.";

/// The settings page's line when `config.toml` could not be read or
/// written (the log gets a fixed line: the reason may name the path, and so
/// the account).
const NOT_SAVED_FILE: &str = "Not saved: the settings file could not be read or written.";

/// Save one settings change: `config.toml` as it is now, with the change,
/// checked and written back; the model then holds what was saved, which is
/// returned. Nothing is saved while this screen may be in a picture that
/// leaves it.
fn save_settings(paths: &Paths, shared: &Shared, change: &SettingsChange) -> Option<Config> {
    if shared.read(|m| m.screen_shared(Instant::now())) {
        shared.update(|m| m.settings.problem = Some(NOT_SAVED_SHARED));
        return None;
    }
    let path = paths.config_file();
    let saved = Config::load(&path).and_then(|mut cfg| {
        change.apply(&mut cfg);
        cfg.save(&path).map(|()| cfg)
    });
    match saved {
        Ok(cfg) => {
            shared.update(|m| m.settings = Settings::of(&cfg));
            Some(cfg)
        }
        // No error text: it may name the path, which names the account.
        Err(_) => {
            tracing::warn!("the settings were not saved");
            shared.update(|m| m.settings.problem = Some(NOT_SAVED_FILE));
            None
        }
    }
}

/// The services' policy the window host publishes for `services`: as they
/// say, but without the clipboard where the running portal request does not
/// ask the desktop for it (`portal_lacks_clipboard`,
/// `Model::portal_lacks_clipboard`: a Wayland desktop with `[services]
/// wayland_clipboard` off at this start). No session is then eligible for
/// it, so the desktop is never asked and no session is told the desktop
/// refused it: the strip never says "This desktop did not allow clipboard
/// sharing" of a clipboard Tornect never asked for, and what the host serves
/// is what the sheet, the wizard and the block window say
/// (`Model::services_offered`).
fn host_policy(
    services: &tornect_core::config::Services,
    portal_lacks_clipboard: bool,
) -> ServicesPolicy {
    let mut policy = ServicesPolicy::from_config(services);
    if portal_lacks_clipboard {
        policy.clipboard = false;
    }
    policy
}

/// The services' policy as `saved` holds it ([`host_policy`]), for the
/// sessions that start from now on (design `services` §2.5: settings apply
/// to later sessions; each live one keeps the snapshot it took at its
/// start). Whether it changed.
fn republish(
    policy: &watch::Sender<ServicesPolicy>,
    saved: &Config,
    portal_lacks_clipboard: bool,
) -> bool {
    let now = host_policy(&saved.services, portal_lacks_clipboard);
    policy.send_if_modified(|held| {
        let changed = *held != now;
        *held = now;
        changed
    })
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
        let asked = self
            .guard
            .authorize(Actor::Ui, &ExternalOp::AcknowledgeBanner);
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

/// How often the Sessions page's rows are read again from the session log.
const SESSIONS_EVERY: Duration = Duration::from_secs(30);

/// The Sessions page's rows and the log's folder (§B.8.13), from the session
/// log and its rotated files, into the model when they changed: read on a
/// blocking thread at the start and every [`SESSIONS_EVERY`], so that opening
/// the page asks for nothing. Reads only.
fn refresh_sessions(paths: &Paths, shared: &Shared) {
    let log = tornect_core::session_log::SessionLog::new(paths.sessions_log());
    // The rows that could be read, and whether a part could not be (the
    // reader logs it without the file's path).
    let (records, whole) = log.read_all_readable();
    let rows = Some(super::pages::session_rows(&records));
    let partial = !whole;
    let folder = paths
        .sessions_log()
        .parent()
        .map(|p| p.display().to_string());
    if shared
        .read(|m| m.sessions != rows || m.log_folder != folder || m.sessions_partial != partial)
    {
        shared.update(|m| {
            m.sessions = rows;
            m.log_folder = folder;
            m.sessions_partial = partial;
        });
    }
}

/// How often Settings, Security's view of unattended access is read again
/// from the window host's guard.
const MANAGER_EVERY: Duration = Duration::from_secs(30);

/// Settings, Security's view of unattended access for the window host
/// (§B.8.7.3): a copy of the host's context, read on a blocking thread at the
/// host role's start, every [`MANAGER_EVERY`] and after each answer of the
/// guard, so that opening a page asks for nothing. It writes nothing.
struct ManagerWatch {
    ctx: crate::unattended::HostContext,
    words: Arc<super::recognize::Recognizer>,
    /// The host's own paired devices, from which *Remove device* removes one.
    trusted: Arc<tornect_signal::pairing::TrustedDeviceStore>,
    /// The host's live sessions: *Remove device* ends one of the removed
    /// device, attended ones included (the guard ends its unattended ones).
    live: Arc<LiveSessions>,
    /// The window is closing: a stop code that arrives now is not shown,
    /// and access is turned off again. Held while a code is put into the
    /// model and while the closing window takes it back, so that one of the
    /// two always sees the other.
    closing: Mutex<bool>,
    /// The start-at-sign-in registration for the executable at a path, built
    /// at each change for the program running then (as the command line's
    /// offline route builds it); a fake in the tests.
    autostart_for: AutostartFor,
    /// Whether Tornect is installed on this computer (the install's probe).
    installed: Arc<dyn Fn() -> Option<bool> + Send + Sync>,
}

/// How [`ManagerWatch`] builds a start-at-sign-in registration for an
/// executable.
type AutostartFor =
    Arc<dyn Fn(&std::path::Path) -> Arc<dyn tornect_platform::autostart::Autostart> + Send + Sync>;

/// The registration `tornect service install` would make for the executable
/// at `exe` and the home `paths`; refused (nothing can be registered) when
/// that executable is gone.
fn autostart_for(paths: Paths) -> AutostartFor {
    use tornect_platform::autostart;
    Arc::new(
        move |exe| match crate::unattended::launch_spec_for(&paths, exe.to_path_buf()) {
            Ok(spec) => autostart::for_this_os(spec),
            Err(e) => Arc::new(autostart::NoAutostart(format!("{e:#}"))),
        },
    )
}

/// Whether Tornect is installed on this computer, by the install's own
/// probe (§B.1.1): on Linux the per-user files, on Windows the copy in
/// Program Files; `None` where it cannot be read.
fn installed_now() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        tornect_platform::install::LinuxInstall::for_this_user()
            .ok()
            .map(|files| files.installed())
    }
    #[cfg(windows)]
    {
        let sys = tornect_platform::install::windows_system().ok()?;
        let target = tornect_platform::install::WindowsTarget::entry_of(&*sys).ok()?;
        Some(std::path::Path::new(&target.exe).is_file())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

/// Why a start-at-sign-in change was not made, in plain words, by its code.
fn sign_in_refusal(code: u16) -> &'static str {
    use tornect_core::unattended::ipc::codes;
    match code {
        codes::G_REMOTE_SESSION_ACTIVE => {
            "Not done: a remote session is running, or ended less than a minute ago."
        }
        codes::G_REAUTH_FAILED => "Not done: this computer's password was not confirmed.",
        codes::G_KEYSTORE_LOCKED => "Not done: Tornect cannot read its keystore right now.",
        _ => "Not done: what starts at sign-in could not be changed from here.",
    }
}

/// How long the shorter pause of Settings, Security lasts.
const PAUSE_SHORT: Duration = Duration::from_secs(12 * 3600);

/// Why an operation of Settings, Security was not done, in plain words: the
/// guard's reason, never its detail (which may name a path).
fn refusal(e: &tornect_core::unattended::guard::GuardError) -> &'static str {
    use tornect_core::unattended::guard::GuardError;
    match e {
        GuardError::RemoteSessionActive => {
            "Not done: a remote session is running, or ended less than a minute ago."
        }
        GuardError::ReauthFailed(_) => "Not done: this computer's password was not confirmed.",
        GuardError::KeystoreLocked(_) => "Not done: Tornect cannot read its keystore right now.",
        GuardError::StoreLocked(_) => {
            "Not done: another Tornect command is changing unattended access right now."
        }
        GuardError::NeedsPassword(_) => {
            "Not done: this device needs a new password before its access can be enabled."
        }
        GuardError::Unsupported(why) => level_refusal(why).unwrap_or(NOT_CHANGED),
        _ => NOT_CHANGED,
    }
}

/// Why an operation of Settings, Security was not done, when no plainer
/// reason applies.
const NOT_CHANGED: &str = "Not done: unattended access could not be changed.";

/// Why the guard refuses the administrator level here (`G_UNSUPPORTED`,
/// §B.8.7.4), as the plan words it: the guard's reason when it is one of
/// those sentences, never any other text.
fn level_refusal(why: &str) -> Option<&'static str> {
    use tornect_core::levels::{
        REFUSAL_ADMIN_HELPING_SOMEONE, REFUSAL_ADMIN_LINUX, REFUSAL_ADMIN_STANDALONE,
        REFUSAL_ADMIN_STANDARD_ACCOUNT, REFUSAL_ADMIN_UNREADABLE,
    };
    [
        REFUSAL_ADMIN_LINUX,
        REFUSAL_ADMIN_STANDALONE,
        REFUSAL_ADMIN_STANDARD_ACCOUNT,
        REFUSAL_ADMIN_HELPING_SOMEONE,
        REFUSAL_ADMIN_UNREADABLE,
    ]
    .into_iter()
    .find(|text| *text == why)
}

/// Why the wizard's *Turn on* did not register a password of the person's
/// own: it does not meet the policy of §B.8.7.2.
const NOT_THE_POLICY: &str = "Not done: this password is too short, too long or too easy to guess.";

/// Why *Change mode* to control was not done: control here now reaches the
/// administrator level, so it comes only with a new generated password.
const MODE_NEEDS: &str =
    "Not done: control here now needs a new password for this device. Nothing was changed.";

/// Why the wizard's *Turn on* waits for nothing: another operation asks for
/// this computer's password right now (one dialog at a time).
const ANOTHER_ASKS: &str =
    "Not done: another Tornect command is changing unattended access right now.";

/// Why a pause was not started from Settings, Security: one runs already,
/// and a pause is never ended sooner from there.
const PAUSE_RUNS: &str = "Not done: a pause is running already.";

/// Why *Remove device* left the pairing: its unattended access, if it had
/// any, is gone, but the paired devices could not be written.
const PAIRING_KEPT: &str = "The pairing could not be removed: the list of paired devices could \
    not be written. Unattended access, if the device had it, was removed.";

/// Why *Remove device* changed nothing: unattended access's store did not
/// load, so a grant the device may have cannot be removed before its pairing
/// (decision M1-25: never a grant for an unpaired device, which would come
/// back with a later pairing).
const STORE_CLOSED: &str = "Not done: unattended access's store could not be read, so this \
    device's unattended access cannot be removed first. Nothing was changed.";

/// Whether the section's operation `op` asks for this computer's password:
/// one dialog at a time, so such an operation waits for none other and
/// holds the section's busy flag until it is done. The others are
/// deny-direction and ask nothing.
fn asks_password(op: &ManagerOp) -> bool {
    matches!(
        op,
        ManagerOp::On
            | ManagerOp::Enable(_)
            | ManagerOp::Unlock(_)
            | ManagerOp::Resume(_)
            | ManagerOp::Setting(_)
            | ManagerOp::SignIn(_)
            | ManagerOp::SetMode(_, SessionMode::Control)
    )
}

/// One press of the wizard's *Turn on*, *Change password* or restore at a
/// time (one password dialog at a time, kept in the wizard's own state):
/// while another operation asks for this computer's password, the press
/// `attempt` is answered, not queued, and the running press stays;
/// otherwise it becomes the running press. Whether it was taken.
fn take_press(m: &mut super::model::Model, attempt: u64) -> bool {
    if m.manager_busy || m.wizard.running.is_some() {
        m.wizard.answer = Some((attempt, WizardAnswer::Refused(ANOTHER_ASKS)));
        return false;
    }
    m.wizard.running = Some(attempt);
    true
}

impl ManagerWatch {
    /// The readiness rows as the host last probed them, with the rows read
    /// now: the start at sign-in from `autostart` (the system's answer), the
    /// panic key, and in background mode whether the indicator was shown.
    fn readiness(
        &self,
        autostart: &Result<
            tornect_platform::autostart::AutostartState,
            tornect_platform::autostart::AutostartError,
        >,
    ) -> tornect_core::unattended::readiness::ReadinessSnapshot {
        use tornect_core::unattended::readiness::Probe;
        use tornect_platform::hotkey::{self, KeyState};
        let mut snap = self.ctx.readiness.get();
        snap.autostart = tornect_platform::autostart::readiness_probe(autostart);
        snap.panic_key = match hotkey::state() {
            KeyState::Bound => Probe::Ok,
            state => Probe::Fail(state.row().to_owned()),
        };
        if let Some(shown) = &self.ctx.indicator {
            snap.consent_indicator = shown.row();
        }
        snap
    }

    /// Unattended access as the store and the readiness rows say it now.
    fn read(&self) -> Manager {
        use tornect_core::unattended::readiness::Probe;
        use tornect_core::words::Role;
        use tornect_platform::autostart::AutostartState;
        let now = tornect_core::trusted::unix_now();
        let autostart = self.ctx.autostart.status();
        let sign_in = match &autostart {
            Ok(AutostartState::Registered(_)) => Some(true),
            Ok(AutostartState::Absent) => Some(false),
            Ok(AutostartState::Unavailable(_)) | Err(_) => None,
        };
        let readiness = self.readiness(&autostart);
        let not_ready = readiness.badge();
        let rows: Vec<(&'static str, Probe)> = readiness
            .fields()
            .iter()
            .map(|(name, probe)| (*name, (*probe).clone()))
            .collect();
        let store = self.ctx.guard.store();
        let report = store.status_report(readiness);
        let given_by = store
            .read(|s| {
                s.grants
                    .iter()
                    .map(|g| (g.id, g.created_by))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let (keep_awake, prevent_idle_lock, notify) = store
            .read(|s| (s.keep_awake, s.prevent_idle_lock, s.notify))
            .unwrap_or_default();
        let paused_until = report.paused_until.filter(|until| *until > now);
        let grants: Vec<GrantRow> = report
            .grants
            .iter()
            .map(|g| GrantRow {
                device: g.device,
                label: g.label.clone(),
                words: self
                    .words
                    .known()
                    .cached(g.device.public_key_bytes(), Role::Device)
                    .map(|h| h.words()),
                created_by: given_by
                    .iter()
                    .find(|(id, _)| *id == g.id)
                    .map(|(_, by)| *by),
                last_used: g.last_used,
                state: g.state.clone(),
                failures: g.failures_since_unlock,
            })
            .collect();
        let without_asking = if report.enabled && paused_until.is_none() {
            grants.iter().filter(|g| g.state == "active").count()
        } else {
            0
        };
        Manager {
            on: report.enabled,
            paused_until,
            without_asking,
            grants,
            readiness: rows,
            not_ready,
            keep_awake,
            prevent_idle_lock,
            notify,
            sign_in,
            installed: (self.installed)(),
        }
    }

    /// Put unattended access as it is now into the model, and whether the
    /// grant wizard has a device to offer.
    fn refresh(&self, shared: &Shared) {
        let view = Some(self.read());
        let (offer, all_granted) = self.offer();
        let offer = Some(offer);
        let modes: Vec<(tornect_core::DeviceId, SessionMode)> = self
            .ctx
            .guard
            .store()
            .read(|s| s.grants.iter().map(|g| (g.device, g.mode)).collect())
            .unwrap_or_default();
        let levels: Vec<(tornect_core::DeviceId, GrantLevel)> = self
            .ctx
            .guard
            .store()
            .read(|s| {
                s.grants
                    .iter()
                    .map(|g| {
                        let level = GrantLevel {
                            holds: g.holds_level(),
                            marked: g.marked(),
                            preset: g.preset,
                        };
                        (g.device, level)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let account = Some(self.ctx.facts.account());
        let cards = self.cards();
        if shared.read(|m| {
            m.manager != view
                || m.wizard.offer != offer
                || m.wizard.all_granted != all_granted
                || m.wizard.modes != modes
                || m.wizard.levels != levels
                || m.wizard.account != account
                || m.wizard.cards != cards
        }) {
            shared.update(|m| {
                m.manager = view;
                m.wizard.offer = offer;
                m.wizard.all_granted = all_granted;
                m.wizard.modes = modes;
                m.wizard.levels = levels;
                m.wizard.account = account;
                m.wizard.cards = cards;
            });
        }
        // The last turn-off's lines (§B.8.7.1 ⑤a) are true only while that
        // grant is there, active and without the level: read again with the
        // view, they go once it holds the level, is gone or is not active.
        let off = shared.read(|m| m.wizard.level_off);
        if let Some((device, _)) = off {
            let still = self
                .ctx
                .guard
                .store()
                .read(|s| {
                    s.grants.iter().any(|g| {
                        g.device == device
                            && !g.holds_level()
                            && matches!(
                                g.state,
                                tornect_core::unattended::grant::GrantState::Active
                            )
                    })
                })
                .unwrap_or(false);
            if !still {
                shared.update(|m| {
                    if m.wizard.level_off == off {
                        m.wizard.level_off = None;
                    }
                });
            }
        }
    }

    /// Each granted device's card lines in the address book (§B.8.6.1,
    /// decision M1-67): whether its sessions are served view only and why,
    /// decided by the levels' own rules on the account's facts now, and how
    /// many of its admin commands ran nothing, counted over the session log
    /// and its rotated files (read only).
    fn cards(&self) -> Vec<(tornect_core::DeviceId, DeviceCard)> {
        use tornect_core::levels::{self, AccountFacts, HelperPresence, Level};
        let grants: Vec<(tornect_core::DeviceId, SessionMode, Elevation, bool)> = self
            .ctx
            .guard
            .store()
            .read(|s| {
                s.grants
                    .iter()
                    .map(|g| (g.device, g.mode, g.elevation, g.marked()))
                    .collect()
            })
            .unwrap_or_default();
        if grants.is_empty() {
            return Vec::new();
        }
        let account = self.ctx.facts.account();
        let some_holds = grants.iter().any(|(_, _, e, _)| *e == Elevation::Admin);
        // Clause (ii) needs the helper task's presence only where nothing else
        // decides it, and only a marked control grant's line depends on it; its
        // query starts a program on Windows, so it is read only then.
        let needs_helper = account != AccountFacts::Linux
            && !some_holds
            && !account.control_is_administrator()
            && grants
                .iter()
                .any(|(_, mode, _, marked)| *mode == SessionMode::Control && *marked);
        let helper = if needs_helper {
            self.ctx.facts.helper_task()
        } else {
            HelperPresence::Absent
        };
        // What could be read of the log: a part that cannot be leaves the
        // counts of the rest.
        let records = Some(self.ctx.log.read_all_readable().0);
        grants
            .into_iter()
            .map(|(device, mode, elevation, marked)| {
                let level = Level::new(mode, elevation);
                let clause = levels::clause_ii(mode, some_holds, account, helper);
                let served = levels::served_mode(level, marked, clause, account);
                let renewed = levels::served_mode(level, false, clause, account);
                let view_only = (mode == SessionMode::Control && served == SessionMode::ViewOnly)
                    .then_some(if renewed == SessionMode::Control {
                        ViewOnly::UntilNewPassword
                    } else {
                        ViewOnly::AccountSettings
                    });
                let nothing_ran = records.as_ref().map(|r| {
                    tornect_core::session_log::admin_commands_that_ran_nothing(r, &device)
                });
                (
                    device,
                    DeviceCard {
                        view_only,
                        nothing_ran,
                    },
                )
            })
            .collect()
    }

    /// Whether a paired device of this host has no grant yet: what the grant
    /// wizard can offer (§B.8.7.1 ②); and, when none has, whether that is
    /// because every paired device already has one (false: none is paired).
    /// Reads no log.
    fn offer(&self) -> (bool, bool) {
        let granted: Vec<tornect_core::DeviceId> = self
            .ctx
            .guard
            .store()
            .read(|s| s.grants.iter().map(|g| g.device).collect())
            .unwrap_or_default();
        let paired = self.trusted.snapshot();
        let offer = paired.devices.iter().any(|d| !granted.contains(&d.device));
        (offer, !offer && !paired.devices.is_empty())
    }

    /// Run `op` through the guard as the window (`Actor::Ui`), then read the
    /// view again; whether the paired devices changed. Each is
    /// deny-direction and asks no dialog; after master off, a pause and
    /// revoke-all the live sessions end as the control channel ends them,
    /// and the guard ends a device's own sessions itself. A pause is never
    /// started while one runs: ending one sooner would turn access back on.
    /// The busy flag is cleared only by an operation that set it
    /// ([`asks_password`]): one that asks nothing leaves another's dialog
    /// counted.
    fn run(&self, op: ManagerOp, shared: &Shared) -> bool {
        use tornect_core::session_log::Actor;
        use tornect_signal::messages::bye;
        let guard = &self.ctx.guard;
        let end_sessions = |reason| {
            if let Some(kill) = &self.ctx.kill {
                kill.kill(reason);
            }
        };
        // The last turn-off's lines speak of the state before this operation:
        // they go with it (a turn-off sets its own again).
        if shared.read(|m| m.wizard.level_off.is_some()) {
            shared.update(|m| m.wizard.level_off = None);
        }
        // The wizard's operations keep their own state: none of them touches
        // the section's note or its busy flag.
        let op = match op {
            ManagerOp::WizardDevices => {
                self.wizard_devices(shared);
                return false;
            }
            ManagerOp::Preview(choice) => {
                self.wizard_preview(*choice, shared);
                return false;
            }
            ManagerOp::Grant(request) => {
                self.wizard_grant(*request, shared);
                return false;
            }
            ManagerOp::ChangePassword(request) => {
                self.change_password(*request, shared);
                return false;
            }
            ManagerOp::Restore(request) => {
                self.restore(*request, shared);
                return false;
            }
            other => other,
        };
        let asks = asks_password(&op);
        // Remove device is also on the address book's Devices tab: why it
        // was not done is said there too.
        let removing = matches!(op, ManagerOp::Remove(_));
        let mut paired_changed = false;
        let done: Result<(), &'static str> = match op {
            ManagerOp::On => match guard.master_on(Actor::Ui, &self.ctx.host_onion_pk) {
                Ok(ok) => {
                    self.show_stop_code(&ok.stop_code, shared);
                    Ok(())
                }
                Err(e) => Err(refusal(&e)),
            },
            ManagerOp::StopCodeWrittenDown(id) => {
                // Delivered: the only copy goes, wiped on drop; a click on an
                // earlier card leaves a newer one up.
                shared.update(|m| {
                    if m.stop_card_id == id {
                        m.stop_card = None;
                    }
                });
                Ok(())
            }
            ManagerOp::Enable(device) => guard.enable(Actor::Ui, &device).map_err(|e| refusal(&e)),
            ManagerOp::Unlock(device) => guard.unlock(Actor::Ui, &device).map_err(|e| refusal(&e)),
            ManagerOp::Resume(device) => guard.resume(Actor::Ui, &device).map_err(|e| refusal(&e)),
            // Rotate ID runs at the window's close (`ManagerWatch::rotate`),
            // never here; the wizard's operations returned above.
            ManagerOp::RotateId
            | ManagerOp::WizardDevices
            | ManagerOp::Preview(_)
            | ManagerOp::Grant(_)
            | ManagerOp::ChangePassword(_)
            | ManagerOp::Restore(_) => Ok(()),
            ManagerOp::SetMode(device, mode) => guard
                .set_options(
                    Actor::Ui,
                    &device,
                    &tornect_core::unattended::ipc::GrantOptions {
                        mode: Some(mode),
                        ..Default::default()
                    },
                )
                .map_err(|e| match e {
                    tornect_core::unattended::guard::GuardError::NeedsPassword(_) => MODE_NEEDS,
                    e => refusal(&e),
                }),
            ManagerOp::SignIn(on) => {
                let backend = match std::env::current_exe() {
                    Ok(exe) => (self.autostart_for)(&exe),
                    Err(_) => Arc::new(tornect_platform::autostart::NoAutostart(
                        "this program's file cannot be found".to_owned(),
                    )),
                };
                crate::unattended::autostart_change(
                    guard,
                    &*backend,
                    Actor::Ui,
                    on.then_some(false),
                )
                .map(|_| ())
                .map_err(|refused| sign_in_refusal(refused.code))
            }
            ManagerOp::Setting(setting) => {
                let mut settings = tornect_core::unattended::guard::HostSettings::default();
                match setting {
                    HostSetting::KeepAwake(on) => settings.keep_awake = Some(on),
                    HostSetting::PreventIdleLock(on) => settings.prevent_idle_lock = Some(on),
                    HostSetting::Notify(on) => settings.notify = Some(on),
                }
                guard
                    .set_settings(Actor::Ui, settings)
                    .map_err(|e| refusal(&e))
            }
            ManagerOp::Off => guard
                .master_off(Actor::Ui)
                .map(|()| end_sessions(bye::MASTER_OFF))
                .map_err(|e| refusal(&e)),
            ManagerOp::Pause(end) => {
                let now = tornect_core::trusted::unix_now();
                let running = guard
                    .store()
                    .read(|s| s.paused_until.is_some_and(|until| until > now))
                    .unwrap_or(false);
                let until = match end {
                    PauseEnd::TwelveHours => now.saturating_add(PAUSE_SHORT.as_secs()),
                    PauseEnd::UntilOn => u64::MAX,
                };
                if running {
                    Err(PAUSE_RUNS)
                } else {
                    guard
                        .pause(Actor::Ui, until)
                        .map(|()| end_sessions(bye::PAUSED))
                        .map_err(|e| refusal(&e))
                }
            }
            ManagerOp::RevokeAll => guard
                .revoke_all(Actor::Ui)
                .map(|_| end_sessions(bye::REVOKED))
                .map_err(|e| refusal(&e)),
            ManagerOp::Suspend(device) => guard
                .suspend(Actor::Ui, &device)
                .map(|_| ())
                .map_err(|e| refusal(&e)),
            ManagerOp::Disable(device) => {
                guard.disable(Actor::Ui, &device).map_err(|e| refusal(&e))
            }
            ManagerOp::Revoke(device) => guard.revoke(Actor::Ui, &device).map_err(|e| refusal(&e)),
            // The command line's `set-level <device> none` as the window: the
            // guard ends a session at the level itself; no dialog.
            ManagerOp::LevelOff(device) => guard
                .set_options(Actor::Ui, &device, &crate::unattended::level_none_options())
                .map(|()| {
                    let keeps = crate::unattended::keeps_at_the_level(&self.ctx, &device);
                    shared.update(|m| m.wizard.level_off = Some((device, keeps)));
                })
                .map_err(|e| refusal(&e)),
            ManagerOp::Remove(_)
                if matches!(
                    guard.store().status(),
                    tornect_core::unattended::store::StoreStatus::FailedClosed(_)
                ) =>
            {
                Err(STORE_CLOSED)
            }
            ManagerOp::Remove(device) => match guard.unpair(Actor::Ui, &device) {
                Ok(_) => {
                    let removed = self.unpin(&device);
                    // Deny-direction, whether or not the file could be
                    // written (the running host forgot the pin either way):
                    // a session of the device ends, attended or not.
                    if self.live.snapshot().iter().any(|s| s.device == device) {
                        end_sessions(bye::REVOKED);
                    }
                    removed.map(|removed| paired_changed = removed)
                }
                Err(e) => Err(refusal(&e)),
            },
        };
        shared.update(|m| {
            m.manager_note = done.err();
            if removing && let Err(why) = done {
                m.book.note = Some(why.to_owned());
            }
            if asks {
                m.manager_busy = false;
            }
        });
        self.refresh(shared);
        paired_changed
    }

    /// *Remove device*'s second step, after the guard's unpair (decision
    /// M1-25: the grant goes first, so a crash between the two leaves a
    /// paired device without a grant, never the reverse): the pairing goes
    /// from the host's paired devices, and a pairing that went is logged
    /// (`DeviceUnpaired`, with the pinned label), whether or not the device
    /// had unattended access. A pin whose removal could not be written
    /// before is still in the file: it is written again, and fails the same
    /// way while the file stays unwritable. Whether a pairing went; the
    /// refusal's words when the file could not be written.
    fn unpin(&self, device: &tornect_core::DeviceId) -> Result<bool, &'static str> {
        use tornect_core::session_log::{Actor, SessionEvent, SessionRecord};
        match self.trusted.remove(device) {
            Ok(Some(label)) => {
                let line = SessionRecord::now(SessionEvent::DeviceUnpaired)
                    .by(Actor::Ui)
                    .peer(*device, label);
                if self.ctx.log.append(&line).is_err() {
                    tracing::warn!("the removal of a paired device was not logged");
                }
                Ok(true)
            }
            Ok(None) => Ok(false),
            // No error text: it may name a path, which names the account.
            Err(_) => {
                tracing::warn!("a paired device was not removed");
                Err(PAIRING_KEPT)
            }
        }
    }

    /// Put the stop code `code` of a *Turn on* into the model as the one card
    /// (§B.8.7.4), grouped as the command line prints it; a window already
    /// closing never shows it and turns access off again instead.
    fn show_stop_code(&self, code: &[u8; 16], shared: &Shared) {
        let closing = self.closing.lock().unwrap_or_else(PoisonError::into_inner);
        if *closing {
            self.undelivered();
            return;
        }
        let card = Secret(crate::unattended::format_stop_code(code));
        shared.update(|m| {
            m.stop_card_id = m.stop_card_id.wrapping_add(1);
            m.stop_card = Some(card);
        });
    }

    /// The window is closing: a stop code still on its card was never
    /// confirmed as written down, so unattended access must not stay on
    /// under it (§B.8.7.4): the code is dropped and access turned off again.
    fn close_undelivered(&self, shared: &Shared) {
        let mut closing = self.closing.lock().unwrap_or_else(PoisonError::into_inner);
        *closing = true;
        let mut card = None;
        shared.update_quiet(|m| card = m.stop_card.take());
        if card.is_some() {
            drop(card);
            self.undelivered();
        }
    }

    /// Rotate the ID of the home `paths` (§B.8.12), the host role and Tor
    /// stopped: the guard's rotate operation as the window, then the new
    /// identity, and the passwords `device` remembers go with the old ID.
    fn rotate(
        &self,
        paths: &Paths,
        device: &DeviceIdentity,
    ) -> anyhow::Result<crate::rotate::Rotated> {
        use tornect_core::session_log::Actor;
        let store = tornect_core::keystore::FileSecretStore::open(paths.keys_dir())?;
        let saved = ua_client::system_passwords(device);
        crate::rotate::rotate_id(paths, &self.ctx.guard, Actor::Ui, &store, Some(&saved))
    }

    /// The paired devices the grant wizard may give unattended access
    /// (§B.8.7.1 ②), into the model: this host's paired devices without a
    /// grant, each with what the guard's own precondition finds (§B.8.6.1:
    /// its pinned label, an attended session completed), and the password
    /// policy's inputs for the meter (§B.8.7.2). Writes nothing.
    fn wizard_devices(&self, shared: &Shared) {
        use tornect_core::words::Role;
        let guard = &self.ctx.guard;
        let devices: Vec<Candidate> = self
            .trusted
            .snapshot()
            .devices
            .iter()
            .filter(|d| guard.store().grant(&d.device).is_none())
            .filter_map(|d| {
                let (label, attended) = guard.precondition(&d.device);
                label.map(|label| Candidate {
                    device: d.device,
                    label,
                    words: self
                        .words
                        .known()
                        .cached(d.device.public_key_bytes(), Role::Device)
                        .map(|h| h.words()),
                    attended,
                })
            })
            .collect();
        let policy = PolicyInputs {
            inputs: self.ctx.user_inputs.clone(),
            min_score: self.ctx.min_score(),
        };
        let account = self.ctx.facts.account();
        shared.update(|m| {
            m.wizard.devices = Some(devices);
            m.wizard.policy = Some(policy);
            m.wizard.account = Some(account);
        });
    }

    /// Judge the wizard's `choice` (decision M1-67): whether its password can
    /// only be generated, into the model. The guard's preview: no dialog, no
    /// line, no write.
    fn wizard_preview(&self, choice: WizardChoice, shared: &Shared) {
        use tornect_core::unattended::guard::GuardError;
        let judged = self
            .ctx
            .guard
            .preview(&choice.device, choice.preset, &choice.options);
        let refused = match &judged {
            Err(GuardError::Unsupported(why)) => level_refusal(why),
            _ => None,
        };
        let judged = judged.ok();
        let generated_only = judged.as_ref().map(|p| p.generated_only());
        let raises = judged.as_ref().map(|p| p.raises);
        shared.update(|m| {
            m.wizard.level_refused = refused.map(|why| (choice.clone(), why));
            m.wizard.raises = Some((choice.clone(), raises));
            m.wizard.preview = Some((choice, generated_only));
        });
    }

    /// The manager's *Change password* (§B.8.7.3): the guard's preview again
    /// and the policy for a chosen password, then the client's half of a
    /// registration over the store's `ServerSetup` and the window's own
    /// password change (`set_password`: its one dialog, worded for a raise
    /// where the options raise; refused, never a new grant, when the grant is
    /// gone). The password is dropped (wiped) whatever happened; the answer
    /// goes into the model; the view is read again.
    fn change_password(&self, request: GrantRequest, shared: &Shared) {
        let GrantRequest {
            attempt,
            choice,
            password,
        } = request;
        let changed = self.set_password(&choice, &password);
        drop(password);
        let (answer, reaching) = match changed {
            Ok(reaching) => (WizardAnswer::Done, reaching),
            Err(answer) => (answer, Vec::new()),
        };
        shared.update(|m| {
            m.wizard.running = None;
            m.wizard.answer = Some((attempt, answer));
            m.wizard.reaching = reaching;
        });
        self.refresh(shared);
    }

    /// The restore of a marked grant at the administrator level (§B.8.6.1,
    /// decision M1-67): its new generated password first (the window's
    /// password change, its one dialog), then *Enable* (its own); a refused
    /// enable leaves the new password and the grant disabled. The password is
    /// dropped (wiped) whatever happened; the answer goes into the model; the
    /// view is read again.
    fn restore(&self, request: GrantRequest, shared: &Shared) {
        use tornect_core::session_log::Actor;
        let GrantRequest {
            attempt,
            choice,
            password,
        } = request;
        let changed = if matches!(password, NewPassword::Generated(_)) {
            self.set_password(&choice, &password)
        } else {
            Err(WizardAnswer::NeedsGenerated)
        };
        drop(password);
        let (answer, reaching) = match changed {
            Ok(reaching) => match self.ctx.guard.enable(Actor::Ui, &choice.device) {
                Ok(()) => (WizardAnswer::Done, reaching),
                // The new password stays: the step says so and asks for no
                // other.
                Err(_) => (WizardAnswer::SetNotEnabled, Vec::new()),
            },
            Err(answer) => (answer, Vec::new()),
        };
        shared.update(|m| {
            m.wizard.running = None;
            m.wizard.answer = Some((attempt, answer));
            m.wizard.reaching = reaching;
        });
        self.refresh(shared);
    }

    /// [`Self::change_password`]'s registration: how it failed, if it did;
    /// else the other control grants it made reach the administrator level,
    /// as its preview listed them.
    fn set_password(
        &self,
        choice: &WizardChoice,
        password: &NewPassword,
    ) -> Result<Vec<tornect_core::unattended::guard::NewlyReaching>, WizardAnswer> {
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::guard::GuardError;
        use tornect_signal::auth;
        let guard = &self.ctx.guard;
        let device = &choice.device;
        let generated = matches!(password, NewPassword::Generated(_));
        let refused = |e: &GuardError| match e {
            GuardError::NeedsPassword(_) => WizardAnswer::NeedsGenerated,
            e => WizardAnswer::Refused(refusal(e)),
        };
        let preview = guard
            .preview(device, choice.preset, &choice.options)
            .map_err(|e| refused(&e))?;
        if preview.generated_only() && !generated {
            return Err(WizardAnswer::NeedsGenerated);
        }
        self.meets_the_policy(password)?;
        let not_done = |_| WizardAnswer::Refused(NOT_CHANGED);
        let setup = guard
            .store()
            .server_setup()
            .ok_or(WizardAnswer::Refused(NOT_CHANGED))?;
        let setup = auth::parse_server_setup(&setup).map_err(not_done)?;
        let secret = password.secret().0.as_str();
        let (client, reg_request) = auth::PasswordRegistration::start(secret).map_err(not_done)?;
        let reg_response =
            auth::registration_response(&setup, &reg_request, device.public_key_bytes())
                .map_err(not_done)?;
        let ids = auth::identifiers(device.public_key_bytes(), &self.ctx.host_onion_pk);
        let upload = client
            .finish(secret, &reg_response, ids)
            .map_err(not_done)?;
        guard
            .set_password(Actor::Ui, device, &upload, &choice.options, generated)
            .map(|_| preview.newly_reaching)
            .map_err(|e| refused(&e))
    }

    /// §B.8.7.2 once more on this side, as the command line's client checks
    /// it: a chosen password that does not meet it goes no further (no
    /// dialog).
    fn meets_the_policy(&self, password: &NewPassword) -> Result<(), WizardAnswer> {
        use tornect_core::unattended::password as policy;
        if let NewPassword::Chosen(chosen) = password {
            let inputs: Vec<&str> = self.ctx.user_inputs.iter().map(String::as_str).collect();
            let file_keystore = self.ctx.min_score() >= policy::MIN_SCORE_FILE_KEYSTORE;
            if policy::check(chosen.0.as_str(), &inputs, file_keystore).is_err() {
                return Err(WizardAnswer::Refused(NOT_THE_POLICY));
            }
        }
        Ok(())
    }

    /// The wizard's *Turn on* (§B.8.7.1 ⑦): one registration as the window,
    /// then, while unattended access is off, *Turn on* with its own dialog and
    /// the new stop code on its one card (§B.8.7.4: delivered only by the
    /// click). The password is dropped (wiped) whatever happened, then the
    /// answer goes into the model, then the view is read again.
    fn wizard_grant(&self, request: GrantRequest, shared: &Shared) {
        use tornect_core::session_log::Actor;
        let GrantRequest {
            attempt,
            choice,
            password,
        } = request;
        let registered = self.register(&choice, &password);
        drop(password);
        let mut reaching = Vec::new();
        let answer = match registered {
            Ok(listed) => {
                reaching = listed;
                let on = self.ctx.guard.store().read(|s| s.enabled).unwrap_or(false);
                if !on {
                    match self.ctx.guard.master_on(Actor::Ui, &self.ctx.host_onion_pk) {
                        Ok(ok) => self.show_stop_code(&ok.stop_code, shared),
                        Err(e) => shared.update(|m| m.manager_note = Some(refusal(&e))),
                    }
                }
                WizardAnswer::Done
            }
            Err(answer) => answer,
        };
        shared.update(|m| {
            m.wizard.running = None;
            m.wizard.answer = Some((attempt, answer));
            m.wizard.reaching = reaching;
        });
        self.refresh(shared);
    }

    /// One registration of the wizard's `choice` with `password`, as the
    /// window (§B.8.7.4's two messages, both halves in this process): the
    /// guard's preview again, a chosen password refused where the grant's
    /// reach is or becomes non-zero (no dialog); `RegStart` with the raise the
    /// preview found and `generated` from the password's own arm (its one
    /// dialog; it creates the store at the first enable); the client's half;
    /// `RegFinish` at once. A raise that appeared while the person was asked
    /// is refused by the guard, and nothing is written. Registered: the other
    /// control grants it made reach the administrator level, as its preview
    /// listed them.
    fn register(
        &self,
        choice: &WizardChoice,
        password: &NewPassword,
    ) -> Result<Vec<tornect_core::unattended::guard::NewlyReaching>, WizardAnswer> {
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::guard::GuardError;
        use tornect_signal::auth;
        let guard = &self.ctx.guard;
        let WizardChoice {
            device,
            preset,
            options,
        } = choice;
        let generated = matches!(password, NewPassword::Generated(_));
        let refused = |e: &GuardError| match e {
            GuardError::NeedsPassword(_) => WizardAnswer::NeedsGenerated,
            e => WizardAnswer::Refused(refusal(e)),
        };
        let preview = guard
            .preview(device, *preset, options)
            .map_err(|e| refused(&e))?;
        if preview.generated_only() && !generated {
            return Err(WizardAnswer::NeedsGenerated);
        }
        self.meets_the_policy(password)?;
        let not_done = |_| WizardAnswer::Refused(NOT_CHANGED);
        let secret = password.secret().0.as_str();
        let (client, reg_request) = auth::PasswordRegistration::start(secret).map_err(not_done)?;
        let started = guard
            .reg_start(Actor::Ui, device, preview.raises, generated)
            .map_err(|e| refused(&e))?;
        let setup = auth::parse_server_setup(&started.server_setup).map_err(not_done)?;
        // `credential_identifier` is the device's key, as at every login (§B.8.4.3).
        let reg_response =
            auth::registration_response(&setup, &reg_request, device.public_key_bytes())
                .map_err(not_done)?;
        let ids = auth::identifiers(device.public_key_bytes(), &self.ctx.host_onion_pk);
        let upload = client
            .finish(secret, &reg_response, ids)
            .map_err(not_done)?;
        guard
            .reg_finish(
                Actor::Ui,
                device,
                &started.reg_txn,
                &upload,
                *preset,
                options,
                generated,
            )
            .map(|_| preview.newly_reaching)
            .map_err(|e| refused(&e))
    }

    /// Turn unattended access off because its stop code was not delivered.
    fn undelivered(&self) {
        use tornect_core::session_log::Actor;
        if let Err(e) = self.ctx.guard.master_off_undelivered_stop_code(Actor::Ui) {
            tracing::warn!(
                code = e.code(),
                "a stop code nobody holds: access not turned off"
            );
        }
    }
}

/// The host role, once wired.
struct Hosted {
    serving: Arc<(HostConfig, HostDeps)>,
    /// The banner of devices that can connect without asking (a host with its
    /// unattended store).
    banner: Option<Arc<BannerWatch>>,
    /// Settings, Security's view of unattended access (a host with its
    /// unattended store).
    manager: Option<Arc<ManagerWatch>>,
    media: Arc<MediaHost>,
    /// The services streams' host (design `services` §6).
    services: Arc<ServicesHost>,
    /// What the services report into: the model and `sessions.log`.
    observer: Arc<GuiServices>,
    /// The policy each session takes at its start (`[services]`),
    /// republished whenever the settings are saved.
    policy: watch::Sender<ServicesPolicy>,
    /// Reads the lock while a services stream is open (design §2.3).
    lock_watch: JoinHandle<()>,
    live: Arc<LiveSessions>,
    audit: Arc<HostAudit>,
    ipc: Option<JoinHandle<()>>,
    kill_watch: JoinHandle<()>,
    pins: Arc<crate::history::DevicePins>,
    _lock: HostLock,
}

/// The window's [`SessionSink`]: the tracker, the sharing indicator, then the
/// media layer, and a bump of the counter that withdraws open popups.
struct GuiSessions {
    live: Arc<LiveSessions>,
    /// polkit's remembered approvals, revoked during Control sessions.
    polkit: Arc<PolkitRevocation>,
    media: Arc<MediaHost>,
    /// The sessions' services (design `services` §6): each session takes
    /// its policy at its start, before its media starts.
    services: Arc<ServicesHost>,
    /// Where the services report: it keeps each session's peer for the
    /// `sessions.log` lines of its files.
    observer: Arc<GuiServices>,
    shared: Arc<Shared>,
    started: watch::Sender<u64>,
}

impl SessionSink for GuiSessions {
    fn on_start(&self, session: &LiveSession<'_>) {
        self.live.on_start(session);
        crate::secure_screen::on_start(&self.live, session, cfg!(windows));
        self.polkit.on_start(session);
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
            services: None,
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
        // The services' policy snapshot comes first (design `services`
        // §2.5): settings saved from now on apply to later sessions.
        self.observer.started(crate::services::Peer {
            session_id: session.session_id.to_owned(),
            device: session.device,
            label: session.label.to_owned(),
        });
        self.services.on_start(session);
        // The media starts only now: the window counts this screen as shared
        // (and hides what sharing hides) before a frame can leave it.
        self.media.on_start(session);
        self.started.send_modify(|n| *n = n.wrapping_add(1));
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

    /// The start code and the secure-screen bit, with the media layer's
    /// no-input bit added (a control session with nothing to inject into).
    fn notice(&self, session_id: &str) -> Option<u8> {
        self.media
            .viewer_notice(session_id, self.live.notice(session_id))
    }

    fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
        // Media first: that is what stops capture, and the services stream
        // with it (`Close{SESSION_OVER}`).
        self.media.on_end(session_id, end);
        self.services.on_end(session_id);
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
            shown: None,
            all: false,
            screens: 0,
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

    /// What the session's pictures show moved, or its input ended (the
    /// monitors design §4): the indicator follows the monitor shown and
    /// stops claiming control; the evidence line is `tornect host`'s.
    fn capture_changed(&self, changed: &CaptureChanged<'_>) {
        self.shared.update(|m| {
            if let Some(capture) = m
                .sharing
                .iter_mut()
                .find(|x| x.session_id == changed.session_id)
                .and_then(|x| x.capture.as_mut())
            {
                capture.shown = changed.shown;
                capture.all = changed.all;
                capture.input = changed.input;
                capture.screens = changed.of;
            }
        });
        say(format_args!("{}", crate::host::view_line(changed)));
    }

    fn capture_stopped(&self, session_id: &str, report: &MediaReport, end: &MediaEnd) {
        say(format_args!("SHARING STOPPED {session_id}"));
        let line = format!(
            "screen sharing stopped ({}): {} pictures, {} KiB sent; input {} injected, {} \
             dropped; {}",
            crate::host::describe_media_end(*end),
            report.frames_sent,
            report.bytes_sent / 1024,
            report.input_injected,
            report.input_dropped,
            crate::host::stage_means(report)
        );
        note(format_args!("{line}"));
        self.shared.update(|m| m.note(line));
    }
}

/// The window host's raise for `IpcOp::Show` (§B.1.1): a wake of the window's
/// event loop (`Wake::Show`), carrying the link a link launch sent (design
/// `invite` §2.4). It holds the model's waker only, so it cannot answer,
/// dismiss or re-order a sheet, connect, or write the model.
fn show_hook(shared: Arc<Shared>) -> crate::unattended::ShowHook {
    Arc::new(move |link| shared.wake(Wake::Show(link)))
}

/// How many screens a session of `source` could show, for the session
/// sheet's words (decision M1-75 (3)): the monitors a GDI or X11 desktop
/// lists now, the test screens' two, else one (the test card; Wayland, whose
/// dialog picks one screen; a desktop that cannot be listed).
fn screen_count(source: Source) -> super::consent::ScreenCount {
    Arc::new(move || match source {
        Source::TestCard => 1,
        Source::TestScreens => tornect_session::TEST_SCREENS.len(),
        Source::Desktop => {
            match crate::tor_cmd::desktop_monitors(&tornect_session::DesktopBackend::detect()) {
                Some(Ok(monitors)) => monitors.len().max(1),
                Some(Err(_)) | None => 1,
            }
        }
    })
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
                SystemBackend::new(b.source)
                    .with_portal(&b.paths, b.cfg.services.wayland_clipboard),
            ),
            Arc::clone(&helpers),
        )),
        Arc::new(GuiMedia {
            shared: Arc::clone(&b.shared),
        }),
        // The presets' bounds come from this host's `[media]`.
        MediaLimits::with_media(&b.cfg.media),
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
    if let Ok(c) = &ctx {
        // A window takes its host role once.
        let _ = b.hosted_store.set(c.guard.store().clone());
    }
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
        .with_words(Arc::clone(&b.words))
        .with_screens(screen_count(b.source)),
    );
    deps.consent = consent.clone();
    // Before an unattended session (§B.8.6.3): "Ask before starting" on the
    // same sheets, withdrawn alike, and the block window on every monitor.
    deps.local_allow = consent;
    deps.block_window = Arc::new(GuiBlockWindow::new(Arc::clone(&b.popups)));
    // Each unattended session's length goes on its grant (the reconnect
    // cooldown, §B.8.6.4), as on the terminal host.
    // The services: their places and inbox are read off the command loop
    // (canonicalising touches the disk), and they report into the model and
    // the host's one handle on `sessions.log`.
    let env = {
        let paths = b.paths.clone();
        tokio::task::spawn_blocking(move || crate::services::host_env(&paths))
            .await
            .map_err(|e| format!("preparing the session services: {e}"))?
    };
    // What Settings, Sharing last saved, which a save before hosting
    // started did not publish (there was no watch yet).
    let (saved, lacks_clipboard) = b
        .shared
        .read(|m| (m.settings.services, m.portal_lacks_clipboard()));
    let (policy, policy_rx) = watch::channel(host_policy(&saved, lacks_clipboard));
    let observer = Arc::new(GuiServices::new(
        Arc::clone(&b.shared),
        Arc::clone(audit.log()),
    ));
    let services = Arc::new(ServicesHost::new(
        Arc::clone(&media),
        Arc::clone(&observer) as Arc<dyn tornect_session::services::ServicesObserver>,
        policy_rx,
        env,
        ServicesLimits::default(),
    ));
    let lock_watch = {
        let (open, set) = (Arc::clone(&services), Arc::clone(&services));
        tokio::spawn(crate::services::watch_lock(
            crate::services::SystemLock::default(),
            move || open.open_streams(),
            move |locked| set.set_locked(locked),
            crate::services::LOCK_EVERY,
        ))
    };
    deps.sessions = crate::host::UnattendedUse::wrap(
        &ctx,
        Arc::new(GuiSessions {
            live: Arc::clone(&live),
            polkit: Arc::clone(&polkit),
            media: Arc::clone(&media),
            services: Arc::clone(&services),
            observer: Arc::clone(&observer),
            shared: Arc::clone(&b.shared),
            started: started_tx,
        }),
    );
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
    // Settings, Security reads its own copy of the context: the control
    // channel takes this one.
    let manager = ctx.as_ref().ok().map(|c| {
        Arc::new(ManagerWatch {
            ctx: crate::unattended::HostContext {
                guard: Arc::clone(&c.guard),
                host_onion_pk: c.host_onion_pk,
                readiness: c.readiness.clone(),
                autostart: Arc::clone(&c.autostart),
                user_inputs: c.user_inputs.clone(),
                kill: c.kill.clone(),
                log: c.log.clone(),
                facts: Arc::clone(&c.facts),
                show: None,
                indicator: c.indicator.clone(),
            },
            words: Arc::clone(&b.words),
            trusted: Arc::clone(&deps.trusted),
            live: Arc::clone(&live),
            closing: Mutex::new(false),
            autostart_for: autostart_for(b.paths.clone()),
            installed: Arc::new(installed_now),
        })
    });
    if let Some(watch) = &manager {
        let (watch, shared) = (Arc::clone(watch), Arc::clone(&b.shared));
        tokio::spawn(async move {
            let mut every = tokio::time::interval(MANAGER_EVERY);
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
        manager,
        media,
        services,
        observer,
        policy,
        lock_watch,
        live,
        audit,
        ipc,
        kill_watch,
        pins,
        _lock: lock,
    })
}

/// The host's person acts on shared session `session_id`'s services (design
/// `services` §7.2): a message that went out shows on its card at once; a
/// turn-off of the clipboard and files the session still has (chat is not
/// turned off this way) is written to `sessions.log` here, where it is
/// asked for: the stream raises no event of its own for it, and its `Caps`
/// follow.
fn host_services(
    services: &ServicesHost,
    observer: &GuiServices,
    shared: &Shared,
    session_id: &str,
    op: HostServicesOp,
) {
    use tornect_proto::services::caps;
    match op {
        HostServicesOp::Chat(text) => {
            if services.send_chat(session_id, text.clone()) {
                shared.update(|m| {
                    if let Some(card) = m
                        .sharing
                        .iter_mut()
                        .find(|s| s.session_id == session_id)
                        .and_then(|s| s.services.as_mut())
                    {
                        card.said(text);
                    }
                });
            }
        }
        HostServicesOp::Cancel(xfer) => {
            services.cancel(session_id, xfer);
        }
        HostServicesOp::TurnOff(off) => {
            // Only what the card says the session still has: the line then
            // names what was taken away, never a service it never had.
            let left = shared.read(|m| {
                m.sharing
                    .iter()
                    .find(|s| s.session_id == session_id)
                    .and_then(|s| s.services.as_ref())
                    .map_or(0, |card| card.caps)
            });
            let off = off & left & (caps::CLIP | caps::UPLOAD | caps::BROWSE);
            if off == 0 || !services.turn_off(session_id, off) {
                return;
            }
            let peer = observer.peer(session_id);
            let record = crate::services::turned_off_record(session_id, peer.as_ref(), off);
            if let Err(e) = observer.log().append(&record) {
                tracing::warn!(error = %e, "could not append to sessions.log");
            }
        }
    }
}

/// The viewer's person acts on the viewed session's services (design
/// `services` §7.1): the request goes to its stream (never blocking), and a
/// message or a switch that went shows in the window at once. Nothing
/// happens without a services stream.
fn viewer_services(shared: &Shared, link: &StreamLink, op: ViewerOp) {
    let said = match &op {
        ViewerOp::Chat(text) => Some(text.clone()),
        _ => None,
    };
    let switch = match &op {
        ViewerOp::ClipSwitch(on) => Some(*on),
        _ => None,
    };
    if !link.services(op) {
        return;
    }
    shared.update(|m| {
        if let ClientStage::Live(viewing) = &mut m.client
            && let Some(services) = &mut viewing.services
        {
            if let Some(text) = said {
                services.said(text);
            }
            if let Some(on) = switch {
                services.clipboard = on;
            }
        }
    });
}

/// The wait before the first automatic try after Tor, or the publishing of
/// this computer's ID, failed (B02).
const RETRY_FIRST: Duration = Duration::from_secs(30);
/// The longest wait between two automatic tries: each failure in a row
/// doubles the wait, up to this.
const RETRY_MOST: Duration = Duration::from_secs(5 * 60);

/// What the window says when no way into Tor worked (B02): plain words, no
/// command and no file name; why each way failed is in the recent activity
/// (the ladder's own notes).
pub(super) const TOR_DOWN: &str = "Check that this computer is online. Where Tor is blocked, \
    choose bridges in Settings, Connection, then start Tornect again.";

/// What the window says when none of the ways into Tor the settings allow
/// can run here (the ladder is empty: a bridge helper is missing).
pub(super) const TOR_NO_WAY: &str = "None of the ways to reach Tor chosen in Settings, \
    Connection can run on this computer; Settings, About shows what is missing.";

/// The hosting line's words when this computer's ID could not be published.
pub(super) const PUBLISH_FAILED: &str = "this ID could not be published";

/// The hosting line's words when the published ID stopped being served.
pub(super) const SERVICE_STOPPED: &str = "this ID stopped being served";

/// How long a start that worked must stay up before its failure counts as
/// the first in a row again: a service that stops at once after each
/// publish is a failure in a row, not one that worked, so its tries keep
/// doubling instead of coming every 30 s for good.
const STAYED_UP: Duration = RETRY_MOST;

/// The wait before the automatic try that follows `failures` failures in a
/// row: [`RETRY_FIRST`] after the first, twice as long after each next
/// one, at most [`RETRY_MOST`].
fn retry_after(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    RETRY_FIRST.saturating_mul(1 << doublings).min(RETRY_MOST)
}

/// A start that runs on a task of its own and starts again after a failure
/// (B02): Tor's, through the bridge ladder (each try builds its ladder from
/// the same configuration, as the first did: decisions M1-38 and M1-40),
/// and the publishing of this computer's ID. A running start is never
/// cancelled here: Tor's owns runtimes that must not be dropped inside this
/// one. A failure arms the next try ([`retry_after`]); [`Restarting::next`]
/// says when it is due, and the caller starts it.
struct Restarting<T> {
    /// The start running now.
    task: Option<JoinHandle<anyhow::Result<T>>>,
    /// Failures in a row since a start that worked stayed up
    /// [`STAYED_UP`].
    failures: u32,
    /// When the last start that worked returned, until a failure.
    up_since: Option<tokio::time::Instant>,
    /// The next try's time, after a failure.
    due: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

/// What [`Restarting::next`] came to.
enum Restart<T> {
    /// The start worked.
    Started(T),
    /// It failed, and the next try is due after this wait.
    Failed(anyhow::Error, Duration),
    /// The next try is due: the caller starts it.
    Due,
}

impl<T> Restarting<T> {
    /// Nothing running and nothing due.
    fn idle() -> Self {
        Self {
            task: None,
            failures: 0,
            up_since: None,
            due: None,
        }
    }

    /// Run `task` as the start (any wait for a try ends).
    fn start(&mut self, task: JoinHandle<anyhow::Result<T>>) {
        self.due = None;
        self.task = Some(task);
    }

    /// Whether a start runs, or a try waits.
    fn pending(&self) -> bool {
        self.task.is_some() || self.due.is_some()
    }

    /// A failure, the start's own or one seen elsewhere (a listener that
    /// closed): the next try is armed. Returns its wait. It is the first in
    /// a row again only after a start that stayed up [`STAYED_UP`].
    fn failed(&mut self) -> Duration {
        if self
            .up_since
            .take()
            .is_some_and(|since| since.elapsed() >= STAYED_UP)
        {
            self.failures = 0;
        }
        self.failures = self.failures.saturating_add(1);
        let wait = retry_after(self.failures);
        self.due = Some(Box::pin(tokio::time::sleep(wait)));
        wait
    }

    /// Try again now, not when the armed try is due: `true` when a try was
    /// waited for (the caller starts it); `false` while a start runs or
    /// nothing failed.
    fn now(&mut self) -> bool {
        self.task.is_none() && self.due.take().is_some()
    }

    /// The running start, taken (Rotate ID waits for it, §B.8.12).
    fn take_task(&mut self) -> Option<JoinHandle<anyhow::Result<T>>> {
        self.task.take()
    }

    /// The next thing that happens: the running start returns, or the armed
    /// try comes due. Safe to drop at any await (a `select!` arm): the task
    /// and the timer stay as they were.
    async fn next(&mut self) -> Restart<T> {
        if let Some(task) = &mut self.task {
            let out = task.await;
            self.task = None;
            match out {
                Ok(Ok(started)) => {
                    self.up_since = Some(tokio::time::Instant::now());
                    Restart::Started(started)
                }
                Ok(Err(e)) => Restart::Failed(e, self.failed()),
                Err(e) => Restart::Failed(anyhow::Error::new(e), self.failed()),
            }
        } else if let Some(due) = &mut self.due {
            due.as_mut().await;
            self.due = None;
            Restart::Due
        } else {
            std::future::pending().await
        }
    }
}

/// None of the ways into Tor the settings allow can run here: the window
/// says [`TOR_NO_WAY`] rather than [`TOR_DOWN`].
#[derive(Debug)]
struct NoWayIn;

impl std::fmt::Display for NoWayIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no way to reach the Tor network can run here")
    }
}

/// The plain words of a Tor start that failed with `e`.
fn tor_down_words(e: &anyhow::Error) -> &'static str {
    if e.downcast_ref::<NoWayIn>().is_some() {
        TOR_NO_WAY
    } else {
        TOR_DOWN
    }
}

/// Tor did not start (B02): the window says what to check, and when it
/// tries again by itself; a host answers no request meanwhile.
fn tor_failed(m: &mut super::model::Model, words: &str, wait: Duration, hosting: bool) {
    m.tor = TorState::Failed(words.to_owned());
    m.tor_retry = Some(Instant::now() + wait);
    m.note(format!(
        "tor: not reachable; trying again in {}",
        super::model::wait_in_words(wait)
    ));
    if hosting {
        m.hosting = Hosting::Off("Tor is not reachable".to_owned());
    }
}

/// Tor is tried again, from its first step as at the start; a host waits
/// for it.
fn tor_retrying(m: &mut super::model::Model, hosting: bool) {
    m.tor = TorState::Starting;
    m.tor_retry = None;
    if hosting {
        m.hosting = Hosting::Waiting;
    }
}

/// This computer's ID is not served (`why`: it could not be published, or
/// it stopped): the hosting line says so, and when it is tried again.
fn hosting_failed(m: &mut super::model::Model, why: &str, wait: Duration) {
    m.hosting = Hosting::Off(why.to_owned());
    m.tor_retry = Some(Instant::now() + wait);
}

/// This computer's ID is published again.
fn republishing(m: &mut super::model::Model) {
    m.hosting = Hosting::Publishing;
    m.tor_retry = None;
}

/// Start Tor on a task of its own (it is never cancelled).
fn spawn_tor(b: &Backend) -> JoinHandle<anyhow::Result<TorNode>> {
    tokio::spawn(start_tor(
        b.paths.clone(),
        b.cfg.clone(),
        Arc::clone(&b.shared),
    ))
}

/// Publish this computer's ID through `node`, on a task of its own.
fn spawn_publish(
    node: &Arc<TorNode>,
    identity: &Arc<HostIdentity>,
) -> JoinHandle<anyhow::Result<OnionListener>> {
    let (n, identity) = (Arc::clone(node), Arc::clone(identity));
    tokio::spawn(async move { n.publish(&identity).await.map_err(explain) })
}

/// Reach the Tor network through the bridge ladder (decision M1-38),
/// showing each step in the window. A failure is told in the window's own
/// plain words ([`tor_down_words`]), not in the command line's.
async fn start_tor(paths: Paths, cfg: Config, shared: Arc<Shared>) -> anyhow::Result<TorNode> {
    let ladder = Ladder::from_config(&paths, &cfg.tor);
    for line in &ladder.rejected_lines {
        shared.update(|m| m.note(format!("tor: ignoring {line}")));
    }
    let no_way = ladder.rungs.is_empty();
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
    .map_err(|e| {
        let e = anyhow::Error::new(e);
        if no_way { e.context(NoWayIn) } else { e }
    })
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
/// shares has one. It makes the portal request every session makes, the
/// clipboard's included with `[services] wayland_clipboard`, and keeps the
/// grant in that request's file (`token`).
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn grant(token: std::path::PathBuf, clipboard: bool) -> Result<(bool, bool), String> {
    let options = tornect_capture::wayland::WaylandOptions {
        dialog_wait: GRANT_WAIT,
        clipboard,
        ..tornect_capture::wayland::WaylandOptions::new(Some(token))
    };
    tornect_capture::wayland::grant(&options)
        .map(|g| (g.input, g.remembered))
        .map_err(|e| e.to_string())
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn grant(_: std::path::PathBuf, _: bool) -> Result<(bool, bool), String> {
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

/// The viewer chose screen `id` in the stream window (0: all of them): one
/// request to the viewed session's host, only once the host listed its
/// monitors and while no other request waits for its answer. The model is
/// held while the request is queued, so that the viewer's answer, which
/// clears "Switching…", always comes after it was set, even one said at
/// once (a request not sent, an id no list holds).
fn show_screen(shared: &Shared, link: &StreamLink, id: u8) {
    shared.update(|m| {
        if let ClientStage::Live(v) = &mut m.client
            && let Some(screens) = &mut v.screens
            && screens.switching.is_none()
            && link.show_screen(id)
        {
            screens.switching = Some(id);
        }
    });
}

/// Whether a start asks the first run's question: on the first start of a
/// home (`first_run`; an upgraded install has its marker and is not asked),
/// unless the window starts in background mode, with no window shown, where
/// the neutral default stays.
fn name_question_due(first: bool, background: bool) -> bool {
    first && !background
}

/// Ask the first run's question and wait for its answer: until it comes,
/// nothing starts that could send this computer's name (the host role, Tor,
/// a connection); only a settings change, the history switch and Clear
/// history act meanwhile, each on this computer's own files as the started
/// window does it, and nothing reaches the network. The name saved then
/// goes into every copy the start reads: the configuration the host and the
/// client are built from, the recognizer's own entry and the model.
/// `false`: the window closed first, and nothing was started (a name not
/// given stays the neutral default next time).
async fn ask_the_name(b: &mut Backend, commands: &mut mpsc::UnboundedReceiver<Command>) -> bool {
    b.shared.update(|m| m.name_question = true);
    loop {
        match commands.recv().await {
            Some(Command::FirstRunName(name)) => {
                if let Some(name) = name {
                    let _ = save_settings(&b.paths, &b.shared, &SettingsChange::DeviceName(name));
                }
                break;
            }
            Some(Command::SaveSettings(change)) => {
                let _ = save_settings(&b.paths, &b.shared, &change);
            }
            Some(Command::SetHistory(on)) => change_book(b, &Change::History(on)),
            Some(Command::ClearHistory) => change_book(b, &Change::Clear),
            Some(Command::Quit) | None => return false,
            Some(_) => {}
        }
    }
    let name = b.shared.read(|m| m.settings.device_name.clone());
    // The backend is the recognizer's only holder until it starts.
    if let Some(words) = Arc::get_mut(&mut b.words) {
        words.set_name(&name);
    }
    b.shared.update(|m| {
        m.device_name.clone_from(&name);
        m.name_question = false;
    });
    b.cfg.general.device_name = name;
    true
}

/// Look every [`HOST_LOCK_EVERY`] whether another Tornect process holds the
/// host lock of the home `paths`, into `hosted_elsewhere`, from the start on:
/// such a process may share this screen, which the window cannot see, and
/// the first run's question hides what sharing hides too. It stops before
/// this window takes the host role (`take_host_role`): it would count the
/// window's own lock as another process's.
fn watch_host_lock_early(paths: Paths, shared: Arc<Shared>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(HOST_LOCK_EVERY);
        loop {
            every.tick().await;
            let paths = paths.clone();
            let held = tokio::task::spawn_blocking(move || HostLock::holder(&paths).is_some())
                .await
                .unwrap_or(true);
            if shared.read(|m| m.hosted_elsewhere) != held {
                shared.update(|m| m.hosted_elsewhere = held);
            }
        }
    })
}

/// The start before anything can send this computer's name: whether another
/// Tornect process holds this home's host lock, read before the first frame
/// of the question and then watched (`watch_host_lock_early`); the first
/// run's check; and on the first start of a window shown on screen the
/// question, whose marker is left only once it is answered (in background
/// mode, which asks nothing, at once). `None`: the window closed during the
/// question, and the next start asks it again. Otherwise whether this was
/// the first run, and the early watch.
async fn before_the_start(
    b: &mut Backend,
    commands: &mut mpsc::UnboundedReceiver<Command>,
) -> Option<(bool, JoinHandle<()>)> {
    let paths = b.paths.clone();
    let held = tokio::task::spawn_blocking(move || HostLock::holder(&paths).is_some())
        .await
        .unwrap_or(true);
    b.shared.update(|m| m.hosted_elsewhere = held);
    let early = watch_host_lock_early(b.paths.clone(), Arc::clone(&b.shared));
    if !name_question_due(first_run_due(&b.paths), b.background.is_some()) {
        return Some((first_run(&b.paths), early));
    }
    if !ask_the_name(b, commands).await {
        early.abort();
        return None;
    }
    mark_first_run(&b.paths);
    Some((true, early))
}

/// The host role, when this window is to be the host, taken once the early
/// host-lock watch has stopped. The window that holds the lock is hosted by
/// no other process, whatever the watch read last.
async fn take_host_role(b: &Backend, early: JoinHandle<()>) -> Option<Hosted> {
    early.abort();
    let _ = early.await;
    if !b.host {
        return None;
    }
    match host_role(b).await {
        Ok(hosted) => {
            b.shared.update(|m| m.hosted_elsewhere = false);
            Some(hosted)
        }
        Err(why) => {
            b.shared.update(|m| m.hosting = Hosting::Off(why));
            None
        }
    }
}

/// Run until [`Command::Quit`], then shut down and mark the model closed.
pub async fn run(mut b: Backend, mut commands: mpsc::UnboundedReceiver<Command>) {
    let Some((first, early)) = before_the_start(&mut b, &mut commands).await else {
        b.shared.update(|m| m.closed = true);
        return;
    };
    let b = Arc::new(b);
    b.shared.update(|m| m.history_notice = first);
    refresh_diagnostics(&b);
    {
        let (paths, shared) = (b.paths.clone(), Arc::clone(&b.shared));
        tokio::spawn(async move {
            let mut every = tokio::time::interval(SESSIONS_EVERY);
            loop {
                every.tick().await;
                let (paths, shared) = (paths.clone(), Arc::clone(&shared));
                let _ =
                    tokio::task::spawn_blocking(move || refresh_sessions(&paths, &shared)).await;
            }
        });
    }
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
    let hosted = take_host_role(&b, early).await;
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
    // runtimes that must not be dropped inside this one. A start that fails
    // is tried again after a wait, as is the publishing of this ID (B02).
    let mut tor = Restarting::idle();
    tor.start(spawn_tor(&b));
    let mut node: Option<Arc<TorNode>> = None;
    let mut listener: Option<OnionListener> = None;
    let mut status: Option<JoinHandle<()>> = None;
    let mut publish: Restarting<OnionListener> = Restarting::idle();
    let mut viewing: Option<(watch::Sender<bool>, JoinHandle<()>)> = None;
    let mut granting: Option<JoinHandle<Result<(bool, bool), String>>> = None;
    let slots = Arc::new(Semaphore::new(tornect_signal::tor::MAX_LIVE_CIRCUITS));
    let mut media_streams = JoinSet::new();
    let mut services_streams = JoinSet::new();
    // Rotate ID was asked for: it runs once the sessions, the host role and
    // Tor have stopped, and the window closes after it.
    let mut rotating: Option<Arc<ManagerWatch>> = None;

    loop {
        tokio::select! {
            step = tor.next(), if tor.pending() => match step {
                Restart::Started(started) => {
                    // The way into Tor that worked is known now.
                    refresh_diagnostics(&b);
                    let started = Arc::new(started);
                    b.shared.update(|m| m.tor_retry = None);
                    if hosted.is_some() {
                        b.shared.update(republishing);
                        publish.start(spawn_publish(&started, &b.identity));
                    }
                    node = Some(started);
                }
                Restart::Failed(e, wait) => {
                    refresh_diagnostics(&b);
                    if e.downcast_ref::<tokio::task::JoinError>().is_some() {
                        tracing::warn!(error = %e, "the Tor start task failed");
                    }
                    let words = tor_down_words(&e);
                    b.shared.update(|m| tor_failed(m, words, wait, hosted.is_some()));
                }
                Restart::Due => {
                    b.shared.update(|m| tor_retrying(m, hosted.is_some()));
                    tor.start(spawn_tor(&b));
                }
            },
            step = publish.next(), if publish.pending() => match step {
                Restart::Started(l) => {
                    say_evidence(format_args!("Tornect ID: {}", l.onion_address()), None);
                    if let Some(old) = status.take() {
                        old.abort();
                    }
                    status = Some(watch_reachability(&l, Arc::clone(&b.shared)));
                    listener = Some(l);
                    b.shared.update(|m| m.tor_retry = None);
                }
                Restart::Failed(e, wait) => {
                    let line = format!("publishing this ID failed: {}", e.root_cause());
                    tracing::warn!("{line}");
                    b.shared.update(|m| {
                        m.note(line);
                        hosting_failed(m, PUBLISH_FAILED, wait);
                    });
                }
                Restart::Due => {
                    if let Some(n) = &node {
                        b.shared.update(republishing);
                        publish.start(spawn_publish(n, &b.identity));
                    }
                }
            },
            stream = async { listener.as_mut().expect("guarded").accept().await }, if listener.is_some() => {
                let (Some(stream), Some(hosted)) = (stream, &hosted) else {
                    // The onion service stopped: published again after a wait.
                    listener = None;
                    if let Some(old) = status.take() {
                        old.abort();
                    }
                    let wait = publish.failed();
                    b.shared.update(|m| {
                        m.note("this ID stopped being served; publishing it again");
                        hosting_failed(m, SERVICE_STOPPED, wait);
                    });
                    continue;
                };
                while media_streams.try_join_next().is_some() {}
                while services_streams.try_join_next().is_some() {}
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
                // The session's services (design `services` §6.3): each stream
                // bounds itself (the bind deadline, its session's end), and the
                // listener's cap of 4 streams per circuit bounds how many.
                if stream.port() == SERVICES_PORT {
                    let services = Arc::clone(&hosted.services);
                    services_streams.spawn(async move {
                        let outcome = services.serve(stream).await;
                        if let Some(line) = crate::services::describe_outcome(&outcome) {
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
                let token = crate::host::portal_token(&b.paths, &b.cfg);
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
                    // Now rather than when the automatic try is due: Tor's
                    // start, or else the publishing of this ID.
                    Command::RetryTor => {
                        if tor.now() {
                            b.shared.update(|m| tor_retrying(m, hosted.is_some()));
                            tor.start(spawn_tor(&b));
                        } else if let Some(n) = &node
                            && publish.now()
                        {
                            b.shared.update(republishing);
                            publish.start(spawn_publish(n, &b.identity));
                        }
                    }
                    Command::Notice(change) => {
                        if let Some(notices) = &notices {
                            let _ = notices.send(change);
                        }
                    }
                    Command::Connect(id) | Command::ConnectAnyway(id) => {
                        let Some(node) = node.clone() else {
                            b.shared.update(|m| not_dialled(m, id, false, TOR_NOT_YET));
                            continue;
                        };
                        if viewing.as_ref().is_some_and(|(_, task)| !task.is_finished()) {
                            continue;
                        }
                        // The connect field refuses this computer's own ID;
                        // nothing is dialled should one come (B26).
                        if id == b.identity.id() {
                            b.shared.update(own_id_refused);
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
                    Command::Quality(preset) => {
                        b.link.request_quality(preset);
                    }
                    Command::ShowScreen(id) => show_screen(&b.shared, &b.link, id),
                    Command::HostServices { session_id, op } => {
                        if let Some(hosted) = &hosted {
                            host_services(
                                &hosted.services,
                                &hosted.observer,
                                &b.shared,
                                &session_id,
                                op,
                            );
                        }
                    }
                    Command::Services(op) => viewer_services(&b.shared, &b.link, op),
                    Command::StopSharing => {
                        if let Some(hosted) = &hosted {
                            stop_sharing(&hosted.serving.1.kill, &b.shared);
                        }
                    }
                    Command::AcknowledgeBanner => {
                        if let Some(watch) = hosted.as_ref().and_then(|h| h.banner.clone()) {
                            let shared = Arc::clone(&b.shared);
                            let manager = hosted.as_ref().and_then(|h| h.manager.clone());
                            // The re-authentication dialog blocks; the
                            // manager's view is read again after the answer.
                            tokio::task::spawn_blocking(move || {
                                watch.acknowledge(&shared);
                                if let Some(manager) = manager {
                                    manager.refresh(&shared);
                                }
                            });
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
                            let token = crate::host::portal_token(&b.paths, &b.cfg);
                            let clipboard = b.cfg.services.wayland_clipboard;
                            granting = Some(tokio::task::spawn_blocking(move || {
                                grant(token, clipboard)
                            }));
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
                    Command::SaveSettings(change) => {
                        let saved = save_settings(&b.paths, &b.shared, &change);
                        if let (Some(saved), Some(hosted)) = (saved, &hosted) {
                            let lacks = b.shared.read(|m| m.portal_lacks_clipboard());
                            republish(&hosted.policy, &saved, lacks);
                        }
                    }
                    Command::Manager(ManagerOp::RotateId) => {
                        // Not while another operation waits at its password
                        // dialog: the wipe would come between its dialog and
                        // its commit.
                        if b.shared.read(|m| m.manager_busy || m.wizard.running.is_some()) {
                            continue;
                        }
                        if let Some(manager) = hosted.as_ref().and_then(|h| h.manager.clone()) {
                            rotating = Some(manager);
                            b.shared.update(|m| m.rotating = true);
                            break;
                        }
                    }
                    Command::Manager(ManagerOp::WizardDevices) => {
                        if let Some(manager) = hosted.as_ref().and_then(|h| h.manager.clone()) {
                            // A new wizard: none of the last one's answers
                            // (a press still running stays known: one dialog at
                            // a time).
                            b.shared.update(|m| {
                                m.wizard = WizardView {
                                    offer: m.wizard.offer,
                                    running: m.wizard.running,
                                    ..WizardView::default()
                                };
                            });
                            let shared = Arc::clone(&b.shared);
                            tokio::task::spawn_blocking(move || manager.wizard_devices(&shared));
                        }
                    }
                    Command::Manager(ManagerOp::Preview(choice)) => {
                        if let Some(manager) = hosted.as_ref().and_then(|h| h.manager.clone()) {
                            // Until this preview's answer lands, the pages
                            // read none (④'s own password, *Change mode*'s
                            // raise): an earlier answer may judge an equal
                            // choice on a computer that has changed since.
                            b.shared.update(|m| m.wizard.forget_preview());
                            let shared = Arc::clone(&b.shared);
                            tokio::task::spawn_blocking(move || {
                                manager.wizard_preview(*choice, &shared);
                            });
                        }
                    }
                    Command::Manager(
                        op @ (ManagerOp::Grant(_)
                        | ManagerOp::ChangePassword(_)
                        | ManagerOp::Restore(_)),
                    ) => {
                        if let Some(manager) = hosted.as_ref().and_then(|h| h.manager.clone()) {
                            // One password dialog at a time, kept in the
                            // wizard's own state: a press while another
                            // operation asks for one is answered, not queued.
                            let attempt = match &op {
                                ManagerOp::Grant(request)
                                | ManagerOp::ChangePassword(request)
                                | ManagerOp::Restore(request) => request.attempt,
                                _ => continue,
                            };
                            let mut taken = false;
                            b.shared.update(|m| taken = take_press(m, attempt));
                            if !taken {
                                continue;
                            }
                            let shared = Arc::clone(&b.shared);
                            // `run` hands the wizard's operations to their own
                            // methods, apart from the section's note and flag.
                            tokio::task::spawn_blocking(move || manager.run(op, &shared));
                        }
                    }
                    Command::Manager(op) => {
                        if let Some(manager) = hosted.as_ref().and_then(|h| h.manager.clone()) {
                            // One password dialog at a time: an operation that
                            // asks for one waits for none other (the wizard's
                            // included).
                            if asks_password(&op) {
                                if b.shared.read(|m| m.manager_busy || m.wizard.running.is_some())
                                {
                                    continue;
                                }
                                b.shared.update(|m| m.manager_busy = true);
                            }
                            let b = Arc::clone(&b);
                            // Off the command loop: the guard writes the store
                            // and the log.
                            tokio::task::spawn_blocking(move || {
                                if manager.run(op, &b.shared) {
                                    refresh_book(&b, None);
                                }
                            });
                        }
                    }
                    // Answered before the start; a late one changes nothing.
                    Command::FirstRunName(_) => {}
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
                            b.shared.update(|m| not_dialled(m, id, true, TOR_NOT_YET));
                            continue;
                        };
                        if viewing.as_ref().is_some_and(|(_, task)| !task.is_finished())
                            || b.shared.read(|m| m.setup_changed.contains(&id))
                        {
                            continue;
                        }
                        if id == b.identity.id() {
                            b.shared.update(own_id_refused);
                            continue;
                        }
                        let request = match unattended_request(&b, &id, choice) {
                            Ok(request) => request,
                            Err(NoPassword::Vanished) => {
                                ask_again(&b, id, None, None);
                                continue;
                            }
                            Err(NoPassword::None) => {
                                b.shared.update(|m| not_dialled(m, id, true, NO_PASSWORD));
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
                        // Both requests' grants: one made while the
                        // clipboard switch stood the other way would
                        // otherwise come back when it is turned again.
                        let token = crate::host::portal_token(&b.paths, &b.cfg);
                        let removed = crate::host::revoke_portal_grants(&b.paths);
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

    // A stop code shown but never confirmed as written down: unattended
    // access does not stay on under a card nobody holds (§B.8.7.4).
    if let Some(manager) = hosted.as_ref().and_then(|h| h.manager.clone()) {
        let shared = Arc::clone(&b.shared);
        let _ = tokio::task::spawn_blocking(move || manager.close_undelivered(&shared)).await;
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
            while services_streams.try_join_next().is_some() {}
            let busy = hosted.serving.1.stats.streams.load(Ordering::SeqCst) > 0
                || !media_streams.is_empty()
                || !services_streams.is_empty();
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
        services_streams.abort_all();
        hosted.kill_watch.abort();
        hosted.lock_watch.abort();
        if let Some(ipc) = &hosted.ipc {
            ipc.abort();
        }
        hosted.audit.flush();
    }
    if let Some(status) = status {
        status.abort();
    }
    // Rotate ID, with every session ended, the onion service gone and Tor
    // stopped; the window waits for it (§B.8.12).
    if let Some(manager) = rotating {
        let stopped =
            stop_tor_for_rotation(tor.take_task(), publish.take_task(), listener, node).await;
        let (paths, device) = (b.paths.clone(), Arc::clone(&b.device));
        rotate_at_close(&b.shared, stopped, move || manager.rotate(&paths, &device)).await;
        return;
    }
    drop(listener);
    if let Some(node) = node
        && let Ok(node) = Arc::try_unwrap(node)
    {
        node.shutdown().await;
    }
    b.shared.update(|m| m.closed = true);
}

/// Tor's part of the shutdown before Rotate ID (§B.8.12): a publish still
/// running is aborted and waited for, a Tor start still running is waited
/// for (it is never cancelled), then the listener goes and the node is shut
/// down. `false`: Tor did not shut down, since another task still holds the
/// node, and the rotation must not run.
async fn stop_tor_for_rotation(
    tor_start: Option<JoinHandle<anyhow::Result<TorNode>>>,
    publish: Option<JoinHandle<anyhow::Result<OnionListener>>>,
    listener: Option<OnionListener>,
    node: Option<Arc<TorNode>>,
) -> bool {
    if let Some(publish) = publish {
        publish.abort();
        let _ = publish.await;
    }
    let mut node = node;
    if let Some(start) = tor_start
        && let Ok(Ok(started)) = start.await
    {
        node = Some(Arc::new(started));
    }
    drop(listener);
    match node.map(Arc::try_unwrap) {
        None => true,
        Some(Ok(node)) => {
            node.shutdown().await;
            true
        }
        Some(Err(_)) => false,
    }
}

/// Rotate ID at the window's close (§B.8.12), once Tor is `stopped`:
/// `rotate` runs off this task, and the window closes after it. With Tor not
/// stopped nothing is wiped. A rotation that did not finish leaves the
/// window open on one card that says what is left (`rotate_failed`), with
/// `rotating` still set, so that the window waits for its Close. Neither the
/// card nor the log says the error: it may name a path, which names the
/// account.
async fn rotate_at_close<F>(shared: &Shared, stopped: bool, rotate: F)
where
    F: FnOnce() -> anyhow::Result<crate::rotate::Rotated> + Send + 'static,
{
    let failed = if stopped {
        match tokio::task::spawn_blocking(rotate).await {
            Ok(Ok(rotated)) => {
                say(format_args!(
                    "Rotate ID: unattended access removed for {} device(s); the new ID is used \
                     from the next start",
                    rotated.grants
                ));
                None
            }
            Ok(Err(e)) => {
                tracing::warn!("Rotate ID did not finish");
                Some(
                    if e.downcast_ref::<crate::rotate::PartialRotation>().is_some() {
                        RotateFailed::AccessRemoved
                    } else {
                        RotateFailed::NothingChanged
                    },
                )
            }
            // A panic: what it wiped is not known, so the card claims no
            // removed access.
            Err(_) => {
                tracing::warn!("Rotate ID did not finish");
                Some(RotateFailed::NothingChanged)
            }
        }
    } else {
        tracing::warn!("Rotate ID did not run: Tor did not stop");
        Some(RotateFailed::NothingChanged)
    };
    shared.update(|m| match failed {
        None => m.closed = true,
        Some(failed) => m.rotate_failed = Some(failed),
    });
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
            b.log_attempt(&known, &Logged::Ended(&ended.reason));
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
                    b.log_attempt(
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
                    b.log_attempt(&known, &Logged::Ended(&ended.reason));
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
    b.link.set_quality(None);
    b.link.set_requests(None);
    b.link.set_services(None);
    b.link.end_clip();
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

/// Whether the stream window's Clipboard switch starts on: when `[viewer]
/// clipboard_sync` says so and the host was paired before this connection.
/// The plan's cross-feature rule (§B.6, decision M1-73; decision M1-76):
/// nothing of this computer's goes to a host unless the person chose it for
/// that host, and never by default in the first session with a computer
/// paired in that connection, where only the toolbar's switch turns it on.
fn clipboard_starts_on(clipboard_sync: bool, paired_before: bool) -> bool {
    clipboard_sync && paired_before
}

/// The viewed session's services stream (design `services` §6.1, §7.1): its
/// binding, what it works with on this computer (made off this task: the
/// places are canonicalised), a fresh channel for the person's requests,
/// the window's clipboard when the window shares one, its switch from
/// `[viewer] clipboard_sync` ([`clipboard_starts_on`]: off with a host
/// paired in this connection), and its news into the model. Also the switch.
async fn services_start(
    b: &Backend,
    binding: ServicesBinding,
    paired_before: bool,
) -> (crate::tor_cmd::ServicesStart, bool) {
    let on = clipboard_starts_on(
        b.shared.read(|m| m.settings.viewer.clipboard_sync),
        paired_before,
    );
    let clip = b.link.start_clip(on);
    // The host's text wakes the stream window; the task ends with the
    // session's stream, which holds the sending end.
    if let Some(mut arrivals) = b.link.clip_arrivals() {
        let shared = Arc::clone(&b.shared);
        tokio::spawn(async move {
            while arrivals.changed().await.is_ok() {
                shared.wake(Wake::Frame);
            }
        });
    }
    // The limits as last saved (Settings writes `config.toml` again, with
    // what it holds now): not the start's copy.
    let (paths, cfg) = (b.paths.clone(), b.shared.read(|m| m.settings.services));
    // A failed preparation leaves nothing to send and nowhere to download
    // to: chat still works.
    let local =
        tokio::task::spawn_blocking(move || crate::services::viewer_local(&paths, &cfg, clip))
            .await
            .unwrap_or_default();
    let shared = Arc::clone(&b.shared);
    let report: crate::tor_cmd::ServicesReport =
        Arc::new(move |news| shared.update(|m| services_news(m, news)));
    let start = crate::tor_cmd::ServicesStart {
        binding,
        local,
        ops: b.link.start_services(),
        report,
    };
    (start, on)
}

/// What the viewed session's services stream said, into the model: only
/// while that session is live and offers services.
fn services_news(m: &mut super::model::Model, news: crate::tor_cmd::ServicesNews) {
    use crate::tor_cmd::ServicesNews;
    let ClientStage::Live(viewing) = &mut m.client else {
        return;
    };
    let Some(services) = &mut viewing.services else {
        return;
    };
    match news {
        ServicesNews::Opened(welcome) => services.opened(&welcome),
        ServicesNews::NotOpened(refused) => services.not_opened(refused),
        ServicesNews::Event(event) => services.apply(event),
        ServicesNews::Ended(end) => services.finished(end),
    }
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
            went_live: false,
        };
        m.ua_live = None;
    });
    // With history off the handshake works on a copy of the known hosts, so
    // that its last-seen touch writes nothing (`crate::history`).
    crate::history::coarsen_pins(&b.paths);
    let pins =
        crate::history::Pins::open(&b.paths, id).inspect_err(|_| failed(b, Failure::Other))?;
    // Read before the handshake, which may pin the host: the clipboard's
    // switch starts off with a computer paired in this connection.
    let paired_before = pins.known();
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
        failed(b, Failure::Cancelled);
        return Ok("Cancelled.".to_owned());
    };
    if stream.is_err() {
        failed(b, Failure::Unreachable);
        if let (Some(_), Some(known)) = (&ua, &known) {
            let ended = ua_client::unreachable(&known.label);
            b.log_attempt(known, &Logged::Ended(&ended.reason));
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
        failed(b, Failure::Cancelled);
        if let (Some(_), Some(known)) = (&ua, &known) {
            b.log_attempt(known, &Logged::Ended("cancelled"));
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
        b.log_attempt(known, &Logged::Ended(&ended.reason));
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
        failed(b, Failure::Other);
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
        b.log_attempt(
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
    // The session's own channel for the picks, before its window opens: a
    // pick made in it can only go to this session.
    let quality = b.shared.read(|m| m.settings.viewer.quality);
    let picks = b.link.start_quality(quality);
    // Its own channel for screen requests too, in either mode: choosing a
    // screen is a viewing choice (the monitors design §4).
    let requests = b.link.start_requests();
    // The services stream, only when the host's signed HELLO_ACK offers it:
    // a host of an earlier version destroys the circuit on its port (design
    // `services` §0).
    let services = if session.host_has(tornect_signal::messages::feats::SVC1) {
        let binding = ServicesBinding::new(session.session_token(), &session.th());
        Some(services_start(b, binding, paired_before).await)
    } else {
        None
    };
    let card = services.as_ref().map(|(start, on)| {
        Box::new(ViewerServices {
            // The toolbar offers the Clipboard switch only for a window that
            // shares its clipboard.
            shares_clipboard: start.local.clip.is_some(),
            ..ViewerServices::opening(*on)
        })
    });
    let services = services.map(|(start, _)| start);
    b.shared.update(|m| {
        m.go_live(Viewing {
            host: host.clone(),
            control,
            administrator,
            unattended,
            since: Instant::now(),
            pictures: 0,
            size: (0, 0),
            stream: StreamInfo::default(),
            services: card,
            screens: None,
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
    let watching = crate::tor_cmd::WatchOptions {
        channels: tornect_session::ViewerChannels {
            input,
            requests: Some(requests),
        },
        forward: Some(&mut sink),
        quality,
        quality_rx: Some(picks),
        services,
        ..crate::tor_cmd::WatchOptions::default()
    };
    let end = crate::tor_cmd::watch(node, &id, &isolation, &mut session, stop, watching).await;
    notices_task.abort();
    // Awaited, so that no code the task held lands after the clear.
    let _ = notices_task.await;
    b.shared.update(super::model::Model::end_notices);
    b.link.set_input(None);
    b.link.set_quality(None);
    b.link.set_requests(None);
    b.link.set_services(None);
    b.link.end_clip();
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

/// A connect to this computer's own ID, refused before anything is dialled
/// (B26): no warning stays, and the stepper says why, with nothing done.
fn own_id_refused(m: &mut super::model::Model) {
    m.connect_warning = None;
    m.connect_unchecked = None;
    m.dial = Dial::default();
    m.client = ClientStage::Ended(OWN_ID.to_owned());
}

/// What a connect to this computer's own ID ends with.
const OWN_ID: &str = "That is this computer's own ID: there is nothing to connect to.";

/// A connect to `id` that ends before anything is dialled, for `why`: a
/// dial of its own, so the stepper shows no step done and none failed
/// rather than the previous dial's (every step ticked under "The session
/// ended", or its failure; B25), and Try again dials this ID.
fn not_dialled(m: &mut super::model::Model, id: TornectId, unattended: bool, why: &str) {
    m.dial = Dial {
        id: Some(id),
        unattended,
        ..Dial::default()
    };
    m.client = ClientStage::Ended(why.to_owned());
}

/// What a connect asked for before Tor is up ends with.
const TOR_NOT_YET: &str = "Tor is not connected yet.";

/// What an unattended connect with no password ends with.
const NO_PASSWORD: &str = "No password: none was typed and none is remembered.";

/// Record why the connection ended without a session, at the step it had
/// reached.
fn failed(b: &Backend, why: Failure) {
    b.shared.update(|m| failed_at_stage(m, why));
}

/// [`failed`] on the model: the step is the stage's (a cancel included, so
/// that the stepper ticks only the steps done, B25).
fn failed_at_stage(m: &mut super::model::Model, why: Failure) {
    let step = match m.client {
        ClientStage::Pairing { .. } | ClientStage::Checking => 2,
        ClientStage::Asking => 3,
        ClientStage::Live(_) => 4,
        _ if why == Failure::CodesDiffer => 2,
        _ => 1,
    };
    m.dial.failed = Some((why, step));
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

    /// The window host's services over `media`, as `host_role` builds them,
    /// with no places, no inbox and the default policy; their
    /// `sessions.log` lines go to `log`.
    fn test_services(
        media: &Arc<MediaHost>,
        shared: &Arc<Shared>,
        log: &std::path::Path,
    ) -> (Arc<ServicesHost>, Arc<GuiServices>) {
        let observer = Arc::new(GuiServices::new(
            Arc::clone(shared),
            Arc::new(tornect_core::session_log::SessionLog::new(log)),
        ));
        let services = Arc::new(ServicesHost::new(
            Arc::clone(media),
            Arc::clone(&observer) as Arc<dyn tornect_session::services::ServicesObserver>,
            watch::channel(ServicesPolicy::default()).1,
            tornect_session::services::ServicesEnv::default(),
            ServicesLimits::default(),
        ));
        (services, observer)
    }

    /// Decision M1-75 (3), the final review: the session sheet of a host
    /// sharing the test screens asks for both of them, the test card's for
    /// "this screen"; a desktop counts what its backend lists, at least one
    /// (this machine's Wayland session, whose dialog picks one, says one).
    #[test]
    fn the_session_sheet_counts_what_the_source_could_show() {
        assert_eq!(screen_count(Source::TestCard)(), 1);
        assert_eq!(
            screen_count(Source::TestScreens)(),
            tornect_session::TEST_SCREENS.len()
        );
        assert!(screen_count(Source::Desktop)() >= 1);
    }

    /// §B.1.1, §B.2.1: `IpcOp::Show` reaches the window host as one wake of
    /// its event loop (`Wake::Show`, which raises the window and re-arms the
    /// cards) and nothing else: the open sheets stay as they were, in their
    /// order, none answered or dismissed, and it is no mutation (no dialog,
    /// no log line). Design `invite` §2.4, §4.4: the same holds with a link,
    /// a fill or a refusal, which travels with the wake exactly as it came,
    /// and writes nothing into the model (no connect, no address-book entry).
    #[test]
    fn show_never_answers_dismisses_or_reorders() {
        use super::super::model::Popup;
        use tornect_core::unattended::ipc::{IpcOp, IpcRequest, ShownLink};

        let id = TornectId::from_public_key(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
        );
        // Not a key: what arrives is passed on as it came, for the window
        // to check again (a decoded fill holds any 32 bytes).
        let not_a_key = (0u8..=255)
            .map(|b| TornectId::from_bytes([b; 32]))
            .find(|id| id.verifying_key().is_err())
            .expect("some repeated byte is no curve point");
        for link in [
            None,
            Some(ShownLink::Fill(id)),
            Some(ShownLink::Fill(not_a_key)),
            Some(ShownLink::Refused),
        ] {
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
            let before = shared.read(|m| format!("{m:?}"));
            let tmp = tempfile::tempdir().unwrap();
            let ctx =
                crate::unattended::test_context(tmp.path(), Some(show_hook(Arc::clone(&shared))));
            let lines = ctx.log.read_all().unwrap().len();
            let resp = crate::unattended::dispatch(
                &ctx,
                IpcRequest {
                    id: 7,
                    op: IpcOp::Show { link },
                },
            );
            assert!(resp.ok, "{resp:?}");
            assert_eq!(resp.payload, None, "{link:?}");
            assert_eq!(
                *woken.lock().unwrap(),
                vec![Wake::Show(link)],
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
            assert_eq!(
                shared.read(|m| format!("{m:?}")),
                before,
                "the model as it was: {link:?}"
            );
            assert_eq!(ctx.log.read_all().unwrap().len(), lines, "nothing logged");
        }
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

    /// §B.8.6.2: the banner's acknowledgement asks as an operation of its own,
    /// so that the dialog says what the password confirms.
    #[test]
    fn the_acknowledgement_asks_as_its_own_operation() {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::levels::{AccountFacts, FixedFacts, HelperPresence};
        use tornect_core::session_log::SessionLog;
        use tornect_core::unattended::clock::FakeClock;
        use tornect_core::unattended::guard::{AllowAllReAuth, MutationGuard, NoSessionActivity};
        use tornect_core::unattended::store::GrantStore;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        let store = GrantStore::open(
            &paths,
            secrets,
            Arc::new(FakeClock::at(1_787_961_600)),
            SessionLog::new(paths.sessions_log()),
        )
        .unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let guard = Arc::new(MutationGuard::new(
            store,
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            Arc::new(FixedFacts::new(AccountFacts::Linux, HelperPresence::Absent)),
        ));
        let watch = BannerWatch {
            guard,
            acknowledged: Mutex::new(None),
        };
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.acknowledge(&shared);
        assert_eq!(reauth.calls(), ["acknowledge_banner"]);
    }

    /// A banner watch over a store in `home` with unattended access on and
    /// one grant just created (so the banner shows), whose guard asks
    /// `reauth` and sees `activity`.
    fn banner_with_a_grant(
        home: &std::path::Path,
        reauth: Arc<dyn tornect_core::unattended::guard::ReAuth>,
        activity: Arc<dyn tornect_core::unattended::guard::RemoteSessionActivity>,
    ) -> BannerWatch {
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{AllowAllReAuth, MutationGuard, NoSessionActivity};
        use tornect_core::unattended::ipc::GrantOptions;
        let setup = manager_over(
            home,
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            tornect_core::levels::AccountFacts::Linux,
            b"this machine",
        );
        let guard = &setup.ctx.guard;
        guard.master_on(Actor::Cli, &[9; 32]).unwrap();
        guard
            .create_grant(
                Actor::Cli,
                &tornect_core::DeviceId::from_bytes([3; 32]),
                Preset::HeadlessBox,
                &GrantOptions::default(),
                &[0u8; 192],
                false,
            )
            .unwrap();
        BannerWatch {
            guard: Arc::new(MutationGuard::new(
                guard.store().clone(),
                reauth,
                activity,
                Arc::clone(&setup.ctx.facts),
            )),
            acknowledged: Mutex::new(None),
        }
    }

    /// §B.8.6.2: an acknowledgement whose password is not confirmed changes
    /// nothing: the banner stays, also when the view is read again.
    #[test]
    fn a_refused_acknowledgement_keeps_the_banner() {
        use tornect_core::unattended::guard::{DenyAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let watch = banner_with_a_grant(
            tmp.path(),
            Arc::new(DenyAllReAuth),
            Arc::new(NoSessionActivity),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.refresh(&shared);
        assert!(shared.read(|m| m.unattended_banner.is_some()), "shown");
        watch.acknowledge(&shared);
        watch.refresh(&shared);
        assert!(shared.read(|m| m.unattended_banner.is_some()), "it stays");
    }

    /// §B.8.6.2: the acknowledgement is an access-increasing kind of
    /// operation: during a remote session it asks no dialog and the banner
    /// stays.
    #[test]
    fn no_acknowledgement_during_a_remote_session() {
        use tornect_core::unattended::guard::{AllowAllReAuth, ScriptedActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let activity = Arc::new(ScriptedActivity::default());
        activity.set_live(true);
        let watch = banner_with_a_grant(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::clone(&activity)
                as Arc<dyn tornect_core::unattended::guard::RemoteSessionActivity>,
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.refresh(&shared);
        assert!(shared.read(|m| m.unattended_banner.is_some()), "shown");
        watch.acknowledge(&shared);
        watch.refresh(&shared);
        assert!(reauth.calls().is_empty(), "no dialog");
        assert!(shared.read(|m| m.unattended_banner.is_some()), "it stays");
    }

    /// Settings, Security's view is read from the window host's guard
    /// (§B.8.7.3): the master switch, a running pause, each grant's pinned
    /// label, who gave it access, its state, when it last connected and its
    /// failed attempts, how many devices can connect without asking, and the
    /// readiness rows with the badge they raise. Reading writes nothing.
    #[test]
    fn the_manager_view_is_read_from_the_guard() {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::{Actor, SessionLog};
        use tornect_core::unattended::clock::FakeClock;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{
            AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
            RandomServerSetupSource,
        };
        use tornect_core::unattended::ipc::GrantOptions;
        use tornect_core::unattended::readiness::{FIELD_NAMES, SharedReadiness};
        use tornect_core::unattended::store::GrantStore;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        let log = SessionLog::new(paths.sessions_log());
        let store = GrantStore::open(
            &paths,
            secrets,
            Arc::new(FakeClock::at(1_787_961_600)),
            log.clone(),
        )
        .unwrap();
        let facts: Arc<dyn tornect_core::levels::FactsSource> =
            Arc::new(tornect_core::levels::FixedFacts::linux());
        let guard = Arc::new(
            MutationGuard::new(
                store,
                Arc::new(AllowAllReAuth::default()),
                Arc::new(NoSessionActivity),
                Arc::clone(&facts),
            )
            .with_paired_devices(Arc::new(AllowAllPaired))
            .with_server_setup_source(Arc::new(RandomServerSetupSource)),
        );
        let watch = ManagerWatch {
            ctx: crate::unattended::HostContext {
                guard: Arc::clone(&guard),
                host_onion_pk: [0x42; 32],
                readiness: SharedReadiness::default(),
                autostart: Arc::new(tornect_platform::autostart::NoAutostart("test".to_owned())),
                user_inputs: Vec::new(),
                kill: None,
                log,
                facts,
                show: None,
                indicator: None,
            },
            words: Arc::new(super::super::recognize::Recognizer::default()),
            trusted: Arc::new(TrustedDeviceStore::ephemeral(Default::default())),
            live: Arc::new(LiveSessions::new()),
            closing: Mutex::new(false),
            autostart_for: Arc::new(|_| {
                Arc::new(tornect_platform::autostart::NoAutostart("test".to_owned()))
            }),
            installed: Arc::new(|| None),
        };
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.refresh(&shared);
        let off = shared.read(|m| m.manager.clone()).expect("read");
        assert!(!off.on && off.grants.is_empty() && off.without_asking == 0);
        guard.master_on(Actor::Cli, &[9; 32]).unwrap();
        let device = tornect_core::DeviceId::from_bytes([3; 32]);
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
        let logged = std::fs::read(paths.sessions_log()).unwrap();
        watch.refresh(&shared);
        let on = shared.read(|m| m.manager.clone()).expect("read");
        assert!(on.on);
        assert_eq!(on.paused_until, None);
        assert_eq!(on.without_asking, 1);
        let [row] = on.grants.as_slice() else {
            panic!("one row: {:?}", on.grants);
        };
        assert_eq!(row.label, guard.store().grant(&device).unwrap().label);
        assert_eq!(row.created_by, Some(Actor::Cli));
        assert_eq!(row.state, "active");
        assert_eq!((row.last_used, row.failures), (None, 0));
        let names: Vec<&str> = on.readiness.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, FIELD_NAMES);
        assert_eq!(
            on.not_ready,
            watch.readiness(&watch.ctx.autostart.status()).badge()
        );
        assert_eq!(
            std::fs::read(paths.sessions_log()).unwrap(),
            logged,
            "reading logs nothing"
        );
        guard.pause(Actor::Cli, u64::MAX).unwrap();
        watch.refresh(&shared);
        let paused = shared.read(|m| m.manager.clone()).expect("read");
        assert_eq!(paused.paused_until, Some(u64::MAX));
        assert_eq!(paused.without_asking, 0, "none while paused");
    }

    /// Settings, Security's operations are deny-direction (§B.8.6.2): run
    /// as the window, none asks for the password, and each changes the store
    /// as the guard says. Suspend, Disable, Revoke unattended and Remove
    /// device (which removes the pairing too); a pause of 12 hours, and none
    /// while one runs (one ending sooner would turn access back on); until
    /// access is turned back on; Revoke all; Turn off, which ends the live
    /// sessions as the control channel does.
    #[test]
    fn deny_direction_ops_ask_no_reauth() {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::{Actor, SessionLog};
        use tornect_core::trusted::{TrustedDevice, TrustedDevices};
        use tornect_core::unattended::clock::SystemClock;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{
            AllowAllPaired, AllowAllReAuth, MutationGuard, NoSessionActivity,
            RandomServerSetupSource, ReAuth,
        };
        use tornect_core::unattended::ipc::GrantOptions;
        use tornect_core::unattended::readiness::SharedReadiness;
        use tornect_core::unattended::store::GrantStore;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        let log = SessionLog::new(paths.sessions_log());
        let store = GrantStore::open(
            &paths,
            secrets,
            Arc::new(SystemClock::default()),
            log.clone(),
        )
        .unwrap();
        let facts: Arc<dyn tornect_core::levels::FactsSource> =
            Arc::new(tornect_core::levels::FixedFacts::linux());
        let reauth = Arc::new(AllowAllReAuth::default());
        let guard = Arc::new(
            MutationGuard::new(
                store,
                Arc::clone(&reauth) as Arc<dyn ReAuth>,
                Arc::new(NoSessionActivity),
                Arc::clone(&facts),
            )
            .with_paired_devices(Arc::new(AllowAllPaired))
            .with_server_setup_source(Arc::new(RandomServerSetupSource)),
        );
        let [a, b, c, d] = [1u8, 2, 3, 4].map(|i| tornect_core::DeviceId::from_bytes([i; 32]));
        guard.master_on(Actor::Cli, &[9; 32]).unwrap();
        for device in [a, b, c, d] {
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
        }
        let trusted = Arc::new(TrustedDeviceStore::ephemeral(TrustedDevices {
            devices: vec![TrustedDevice {
                device: d,
                label: "Desk".to_owned(),
                paired_at: 1,
                last_seen: 1,
            }],
            ..TrustedDevices::default()
        }));
        let kill = KillSwitch::new();
        let watch = ManagerWatch {
            ctx: crate::unattended::HostContext {
                guard: Arc::clone(&guard),
                host_onion_pk: [0x42; 32],
                readiness: SharedReadiness::default(),
                autostart: Arc::new(tornect_platform::autostart::NoAutostart("test".to_owned())),
                user_inputs: Vec::new(),
                kill: Some(kill.clone()),
                log,
                facts,
                show: None,
                indicator: None,
            },
            words: Arc::new(super::super::recognize::Recognizer::default()),
            trusted: Arc::clone(&trusted),
            live: Arc::new(LiveSessions::new()),
            closing: Mutex::new(false),
            autostart_for: Arc::new(|_| {
                Arc::new(tornect_platform::autostart::NoAutostart("test".to_owned()))
            }),
            installed: Arc::new(|| None),
        };
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let state = |device: tornect_core::DeviceId| {
            guard
                .store()
                .status_report(Default::default())
                .grants
                .into_iter()
                .find(|g| g.device == device)
                .map(|g| g.state)
        };
        let paused = || guard.store().read(|s| s.paused_until).flatten();
        let asked = reauth.calls();

        assert!(!watch.run(ManagerOp::Suspend(a), &shared));
        assert_eq!(state(a).as_deref(), Some("suspended:local"));
        assert!(!watch.run(ManagerOp::Disable(b), &shared));
        assert_eq!(state(b).as_deref(), Some("disabled:ui"));
        assert!(!watch.run(ManagerOp::Revoke(c), &shared));
        assert_eq!(state(c), None);
        assert!(watch.run(ManagerOp::Remove(d), &shared), "the pairing goes");
        assert_eq!(state(d), None);
        assert!(trusted.get(&d).is_none());

        let now = tornect_core::trusted::unix_now();
        watch.run(ManagerOp::Pause(PauseEnd::TwelveHours), &shared);
        let until = paused().expect("paused");
        assert!(
            until >= now + 12 * 3600 && until <= now + 12 * 3600 + 60,
            "{until}"
        );
        assert_eq!(kill.fired(), Some(bye::PAUSED));
        watch.run(ManagerOp::Pause(PauseEnd::UntilOn), &shared);
        assert_eq!(paused(), Some(until), "a running pause is not changed");
        assert_eq!(shared.read(|m| m.manager_note), Some(PAUSE_RUNS));
        assert_eq!(reauth.calls(), asked, "no dialog");

        // Turned back on (a dialog of the command line, not counted), then
        // paused until it is turned on again.
        guard.master_on(Actor::Cli, &[9; 32]).unwrap();
        let asked = reauth.calls();
        watch.run(ManagerOp::Pause(PauseEnd::UntilOn), &shared);
        assert_eq!(paused(), Some(u64::MAX));
        assert_eq!(shared.read(|m| m.manager_note), None);
        watch.run(ManagerOp::RevokeAll, &shared);
        assert!(guard.store().read(|s| s.grants.is_empty()).unwrap());
        watch.run(ManagerOp::Off, &shared);
        assert!(!guard.store().read(|s| s.enabled).unwrap());
        assert_eq!(kill.fired(), Some(bye::MASTER_OFF));
        assert_eq!(reauth.calls(), asked, "no dialog");
        assert_eq!(shared.read(|m| m.manager_note), None);
        let view = shared.read(|m| m.manager.clone()).expect("read again");
        assert!(!view.on && view.grants.is_empty());
    }

    /// A window host's view of unattended access over a fresh store in
    /// `home` (the machine `machine`): its guard asks `reauth`, sees
    /// `activity` and reads `account`; every device counts as paired.
    fn manager_over(
        home: &std::path::Path,
        reauth: Arc<dyn tornect_core::unattended::guard::ReAuth>,
        activity: Arc<dyn tornect_core::unattended::guard::RemoteSessionActivity>,
        account: tornect_core::levels::AccountFacts,
        machine: &[u8],
    ) -> ManagerWatch {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::SessionLog;
        use tornect_core::unattended::clock::SystemClock;
        use tornect_core::unattended::guard::{
            AllowAllPaired, MutationGuard, RandomServerSetupSource,
        };
        use tornect_core::unattended::readiness::SharedReadiness;
        use tornect_core::unattended::store::GrantStore;
        let paths = Paths::from_home(home);
        paths.ensure().unwrap();
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        let log = SessionLog::new(paths.sessions_log());
        let store = GrantStore::open_with_machine_id(
            &paths,
            secrets,
            Arc::new(SystemClock::default()),
            log.clone(),
            Some(machine.to_vec()),
        )
        .unwrap();
        let facts: Arc<dyn tornect_core::levels::FactsSource> =
            Arc::new(tornect_core::levels::FixedFacts::new(
                account,
                tornect_core::levels::HelperPresence::Absent,
            ));
        let guard = Arc::new(
            MutationGuard::new(store, reauth, activity, Arc::clone(&facts))
                .with_paired_devices(Arc::new(AllowAllPaired))
                .with_server_setup_source(Arc::new(RandomServerSetupSource)),
        );
        ManagerWatch {
            ctx: crate::unattended::HostContext {
                guard,
                host_onion_pk: [0x42; 32],
                readiness: SharedReadiness::default(),
                autostart: Arc::new(tornect_platform::autostart::NoAutostart("test".to_owned())),
                user_inputs: Vec::new(),
                kill: Some(KillSwitch::new()),
                log,
                facts,
                show: None,
                indicator: None,
            },
            words: Arc::new(super::super::recognize::Recognizer::default()),
            trusted: Arc::new(TrustedDeviceStore::ephemeral(Default::default())),
            live: Arc::new(LiveSessions::new()),
            closing: Mutex::new(false),
            autostart_for: Arc::new(|_| {
                Arc::new(tornect_platform::autostart::NoAutostart("test".to_owned()))
            }),
            installed: Arc::new(|| None),
        }
    }

    /// B27: *Remove device* (the address book's Devices tab and Settings,
    /// Security) removes a paired device that has no unattended access too,
    /// through the guard's unpair (a no-op without a grant) and then the pin:
    /// the pin goes, one `DeviceUnpaired` line names the device by its
    /// pinned label, and a live session of it ends with `REVOKED`, attended
    /// as well (no grant ends it). A live session of another device goes on;
    /// a device no longer paired changes nothing and logs nothing.
    #[test]
    fn remove_device_unpairs_a_device_without_unattended_access() {
        use tornect_core::session_log::{Actor, SessionEvent as Logged};
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let (laptop, tablet) = (
            tornect_core::DeviceId::from_bytes([1; 32]),
            tornect_core::DeviceId::from_bytes([2; 32]),
        );
        let trusted = TrustedDeviceStore::ephemeral(Default::default());
        trusted.pin(laptop, "Office laptop").unwrap();
        trusted.pin(tablet, "Tablet").unwrap();
        let watch = ManagerWatch {
            trusted: Arc::new(trusted),
            ..manager_over(
                tmp.path(),
                Arc::new(AllowAllReAuth::default()),
                Arc::new(NoSessionActivity),
                tornect_core::levels::AccountFacts::Linux,
                b"machine",
            )
        };
        let kill = watch.ctx.kill.clone().expect("a host's kill switch");
        let token = tornect_signal::consent::SessionToken::new([5; 32]);
        watch.live.on_start(&LiveSession {
            device: tablet,
            label: "Tablet",
            session_id: "s1",
            token: &token,
            th_final: [0; 32],
            mode: SessionMode::Control,
            elevation: Elevation::None,
            unattended: false,
        });
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let unpaired = || {
            watch
                .ctx
                .log
                .read_all()
                .unwrap()
                .into_iter()
                .filter(|r| r.event == Logged::DeviceUnpaired)
                .collect::<Vec<_>>()
        };

        assert!(
            watch.run(ManagerOp::Remove(laptop), &shared),
            "the pairing goes"
        );
        assert!(watch.trusted.get(&laptop).is_none());
        assert!(watch.trusted.get(&tablet).is_some());
        assert_eq!(kill.fired(), None, "the tablet's session goes on");
        assert_eq!(shared.read(|m| m.manager_note), None);
        let lines = unpaired();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].peer_device, Some(laptop));
        assert_eq!(lines[0].peer_name.as_deref(), Some("Office laptop"));
        assert_eq!(lines[0].by, Some(Actor::Ui));

        assert!(watch.run(ManagerOp::Remove(tablet), &shared));
        assert!(watch.trusted.get(&tablet).is_none());
        assert_eq!(
            kill.fired(),
            Some(bye::REVOKED),
            "its attended session ends"
        );
        assert_eq!(unpaired().len(), 2);

        assert!(!watch.run(ManagerOp::Remove(laptop), &shared), "not paired");
        assert_eq!(unpaired().len(), 2, "nothing more is logged");
        assert_eq!(
            shared.read(|m| (m.manager_note, m.book.note.clone())),
            (None, None)
        );
    }

    /// B27: a pairing whose file cannot be written is not reported as
    /// removed: the section and the Devices tab both say why, nothing is
    /// logged as unpaired, and a live session of the device still ends (the
    /// running host forgot the pin, deny-direction either way).
    #[test]
    fn a_pairing_that_cannot_be_written_says_so_on_the_devices_tab() {
        use tornect_core::session_log::SessionEvent as Logged;
        use tornect_core::trusted::{TrustedDevice, TrustedDevices};
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let laptop = tornect_core::DeviceId::from_bytes([1; 32]);
        // A directory where the file should be: every save fails.
        let blocked = tmp.path().join("trusted-devices.toml");
        std::fs::create_dir(&blocked).unwrap();
        let trusted = TrustedDeviceStore::with(
            blocked,
            TrustedDevices {
                devices: vec![TrustedDevice {
                    device: laptop,
                    label: "Office laptop".to_owned(),
                    paired_at: 1,
                    last_seen: 1,
                }],
                ..TrustedDevices::default()
            },
        );
        let watch = ManagerWatch {
            trusted: Arc::new(trusted),
            ..manager_over(
                &tmp.path().join("home"),
                Arc::new(AllowAllReAuth::default()),
                Arc::new(NoSessionActivity),
                tornect_core::levels::AccountFacts::Linux,
                b"machine",
            )
        };
        let kill = watch.ctx.kill.clone().expect("a host's kill switch");
        let token = tornect_signal::consent::SessionToken::new([5; 32]);
        watch.live.on_start(&LiveSession {
            device: laptop,
            label: "Office laptop",
            session_id: "s1",
            token: &token,
            th_final: [0; 32],
            mode: SessionMode::ViewOnly,
            elevation: Elevation::None,
            unattended: false,
        });
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        assert!(!watch.run(ManagerOp::Remove(laptop), &shared));
        assert_eq!(shared.read(|m| m.manager_note), Some(PAIRING_KEPT));
        assert_eq!(
            shared.read(|m| m.book.note.clone()).as_deref(),
            Some(PAIRING_KEPT)
        );
        assert_eq!(kill.fired(), Some(bye::REVOKED));
        let logged = watch.ctx.log.read_all().unwrap();
        assert!(!logged.iter().any(|r| r.event == Logged::DeviceUnpaired));

        // A second Remove on the same card: the running host forgot the pin
        // at the first, but the file still has it. It says so again rather
        // than finding nothing to remove (B27 review).
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        assert!(!watch.run(ManagerOp::Remove(laptop), &shared));
        assert_eq!(shared.read(|m| m.manager_note), Some(PAIRING_KEPT));
        assert_eq!(
            shared.read(|m| m.book.note.clone()).as_deref(),
            Some(PAIRING_KEPT)
        );
        let logged = watch.ctx.log.read_all().unwrap();
        assert!(!logged.iter().any(|r| r.event == Logged::DeviceUnpaired));
    }

    /// B27: while unattended access's store failed closed, *Remove device*
    /// changes nothing: a grant the device may have could not be removed
    /// first, and a pin removed without it would leave a grant for an
    /// unpaired device, live again at a later pairing (decision M1-25). The
    /// section and the Devices tab say why.
    #[test]
    fn remove_device_changes_nothing_while_the_store_failed_closed() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        use tornect_core::unattended::store::StoreStatus;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        std::fs::write(paths.unattended_store(), b"not a store").unwrap();
        let laptop = tornect_core::DeviceId::from_bytes([1; 32]);
        let trusted = TrustedDeviceStore::ephemeral(Default::default());
        trusted.pin(laptop, "Office laptop").unwrap();
        let watch = ManagerWatch {
            trusted: Arc::new(trusted),
            ..manager_over(
                tmp.path(),
                Arc::new(AllowAllReAuth::default()),
                Arc::new(NoSessionActivity),
                tornect_core::levels::AccountFacts::Linux,
                b"machine",
            )
        };
        let status = watch.ctx.guard.store().status();
        assert!(matches!(status, StoreStatus::FailedClosed(_)), "{status:?}");
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        assert!(!watch.run(ManagerOp::Remove(laptop), &shared));
        assert!(watch.trusted.get(&laptop).is_some(), "the pairing stays");
        assert_eq!(shared.read(|m| m.manager_note), Some(STORE_CLOSED));
        assert_eq!(
            shared.read(|m| m.book.note.clone()).as_deref(),
            Some(STORE_CLOSED)
        );
    }

    /// The emergency stop code as the window's card holds it, read back
    /// into its 16 bytes.
    fn card_bytes(text: &str) -> [u8; 16] {
        let hex: String = text.chars().filter(char::is_ascii_hexdigit).collect();
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// §B.8.7.4: *Turn on* asks for the password once and shows the new stop
    /// code on one card, grouped as the command line prints it: the code the
    /// store's token was made from, and nowhere in the model's `Debug`. A
    /// second Turn on replaces the card (the old code stops working); the
    /// click on "I have written it down" drops it, and access stays on.
    #[test]
    fn master_on_shows_the_stop_code_once() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity, stop_token};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let watch = manager_over(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            tornect_core::levels::AccountFacts::Linux,
            b"this machine",
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.run(ManagerOp::On, &shared);
        assert_eq!(reauth.calls(), ["master_on"]);
        let card = shared.read(|m| m.stop_card.clone()).expect("a card");
        let groups: Vec<String> = card.0.split('-').map(str::to_owned).collect();
        assert_eq!(groups.len(), 8, "eight groups");
        assert!(
            groups
                .iter()
                .all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_hexdigit()))
        );
        let token = watch.ctx.guard.store().read(|s| s.stop_token).flatten();
        assert_eq!(token, Some(stop_token(&[0x42; 32], &card_bytes(&card.0))));
        let debug = shared.read(|m| format!("{m:?}"));
        assert!(
            debug.contains("Secret(<redacted>)"),
            "the card is in the model"
        );
        assert!(!debug.contains(card.0.as_str()));
        for pair in groups.windows(2) {
            assert!(!debug.contains(&pair.join("-")), "{pair:?}");
        }
        watch.run(ManagerOp::On, &shared);
        let second = shared.read(|m| m.stop_card.clone()).expect("one card");
        assert!(second.0 != card.0, "a new code replaces the card");
        watch.run(
            ManagerOp::StopCodeWrittenDown(shared.read(|m| m.stop_card_id)),
            &shared,
        );
        assert!(
            shared.read(|m| m.stop_card.is_none()),
            "dropped on the click"
        );
        assert!(watch.ctx.guard.store().read(|s| s.enabled).unwrap());
    }

    /// §B.8.7.4: "I have written it down" drops only the card it was
    /// clicked on: a click on an earlier card leaves a newer one up, whose
    /// code was not shown yet.
    #[test]
    fn the_click_drops_only_its_own_card() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let watch = manager_over(
            tmp.path(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            tornect_core::levels::AccountFacts::Linux,
            b"this machine",
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.run(ManagerOp::On, &shared);
        let first = shared.read(|m| m.stop_card_id);
        watch.run(ManagerOp::On, &shared);
        let second = shared.read(|m| m.stop_card_id);
        assert_ne!(first, second, "each card its number");
        let shown = shared
            .read(|m| m.stop_card.clone())
            .expect("the second card");
        watch.run(ManagerOp::StopCodeWrittenDown(first), &shared);
        assert_eq!(
            shared.read(|m| m.stop_card.clone()),
            Some(shown),
            "the newer card stays"
        );
        watch.run(ManagerOp::StopCodeWrittenDown(second), &shared);
        assert!(shared.read(|m| m.stop_card.is_none()), "its own click");
    }

    /// §B.8.7.4: a stop code whose card ends without the click (the window
    /// closed, Quit, the tokio side shutting down) leaves no access on under
    /// it: the closing window turns unattended access off again first, logged
    /// as a code not delivered, also after the card was hidden while this
    /// screen was shared; a Turn on that returns once the window is closing
    /// shows nothing and turns access off at once; a delivered code changes
    /// nothing at the close.
    #[test]
    fn a_stop_card_closed_without_the_click_turns_access_off_again() {
        use tornect_core::session_log::SessionEvent;
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let open = |home: &std::path::Path| {
            manager_over(
                home,
                Arc::new(AllowAllReAuth::default()),
                Arc::new(NoSessionActivity),
                tornect_core::levels::AccountFacts::Linux,
                b"this machine",
            )
        };
        let on = |watch: &ManagerWatch| watch.ctx.guard.store().read(|s| s.enabled).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let watch = open(tmp.path());
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.run(ManagerOp::On, &shared);
        assert!(shared.read(|m| m.stop_card.is_some()) && on(&watch));
        shared.update(|m| m.hosted_elsewhere = true);
        watch.close_undelivered(&shared);
        assert!(shared.read(|m| m.stop_card.is_none()), "the code is gone");
        assert!(!on(&watch), "access is off again");
        assert_eq!(
            watch.ctx.guard.store().read(|s| s.stop_token).flatten(),
            None
        );
        assert!(watch.ctx.log.read_all().unwrap().iter().any(|r| {
            r.event == SessionEvent::UnattendedDisabled
                && r.reason.as_deref() == Some("stop code not delivered")
        }));

        let tmp = tempfile::tempdir().unwrap();
        let watch = open(tmp.path());
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.close_undelivered(&shared);
        watch.run(ManagerOp::On, &shared);
        assert!(shared.read(|m| m.stop_card.is_none()), "never shown");
        assert!(!on(&watch), "off at once");

        let tmp = tempfile::tempdir().unwrap();
        let watch = open(tmp.path());
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.run(ManagerOp::On, &shared);
        watch.run(
            ManagerOp::StopCodeWrittenDown(shared.read(|m| m.stop_card_id)),
            &shared,
        );
        watch.close_undelivered(&shared);
        assert!(on(&watch), "a delivered code changes nothing");
    }

    /// §B.8.6.2: each access-increasing operation of Settings, Security asks
    /// for the password once, under its own name: Turn on, Enable, Resume,
    /// Unlock and a host setting; each then does what the guard says.
    #[test]
    fn access_increasing_ops_reauth_once_each() {
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        use tornect_core::unattended::ipc::GrantOptions;
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let watch = manager_over(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            tornect_core::levels::AccountFacts::Linux,
            b"this machine",
        );
        let guard = Arc::clone(&watch.ctx.guard);
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let asks = |op: ManagerOp| {
            let before = reauth.calls().len();
            watch.run(op.clone(), &shared);
            assert_eq!(shared.read(|m| m.manager_note), None, "{op:?}");
            reauth.calls()[before..].to_vec()
        };
        assert_eq!(asks(ManagerOp::On), ["master_on"]);
        watch.run(
            ManagerOp::StopCodeWrittenDown(shared.read(|m| m.stop_card_id)),
            &shared,
        );
        let [a, b, c] = [1u8, 2, 3].map(|i| tornect_core::DeviceId::from_bytes([i; 32]));
        for device in [a, b, c] {
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
        }
        let state = |device| {
            guard
                .store()
                .status_report(Default::default())
                .grants
                .into_iter()
                .find(|g| g.device == device)
                .map(|g| g.state)
        };
        assert!(asks(ManagerOp::Disable(a)).is_empty(), "deny-direction");
        assert_eq!(asks(ManagerOp::Enable(a)), ["enable"]);
        assert_eq!(state(a).as_deref(), Some("active"));
        assert!(asks(ManagerOp::Suspend(b)).is_empty(), "deny-direction");
        assert_eq!(asks(ManagerOp::Resume(b)), ["resume"]);
        assert_eq!(state(b).as_deref(), Some("active"));
        assert_eq!(asks(ManagerOp::Unlock(c)), ["unlock"]);
        assert_eq!(
            asks(ManagerOp::Setting(HostSetting::KeepAwake(true))),
            ["set_settings"]
        );
        assert!(guard.store().read(|s| s.keep_awake).unwrap());
        assert!(shared.read(|m| m.manager.as_ref().is_some_and(|v| v.keep_awake)));
        assert!(!shared.read(|m| m.manager_busy));
    }

    /// Only an operation that asks for the password clears the section's
    /// busy flag, which only such an operation sets: a Turn off or a
    /// Disable while another operation's dialog is up leaves it set, so the
    /// section offers no second dialog beside the first.
    #[test]
    fn only_an_asking_operation_clears_the_busy_flag() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let watch = manager_over(
            tmp.path(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            tornect_core::levels::AccountFacts::Linux,
            b"this machine",
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        shared.update(|m| m.manager_busy = true);
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        for op in [ManagerOp::Off, ManagerOp::Disable(device)] {
            watch.run(op.clone(), &shared);
            assert!(shared.read(|m| m.manager_busy), "{op:?}");
        }
        watch.run(ManagerOp::On, &shared);
        assert!(!shared.read(|m| m.manager_busy), "Turn on clears it");
    }

    /// §B.8.6.2: a password not confirmed changes nothing: Turn on leaves
    /// access off with no stop code, a host setting stays as it was, and the
    /// section shows what it showed, with the refusal in plain words.
    #[test]
    fn a_refused_reauth_leaves_store_and_page_unchanged() {
        use tornect_core::unattended::guard::{DenyAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let watch = manager_over(
            tmp.path(),
            Arc::new(DenyAllReAuth),
            Arc::new(NoSessionActivity),
            tornect_core::levels::AccountFacts::Linux,
            b"this machine",
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.refresh(&shared);
        let before = shared.read(|m| m.manager.clone());
        watch.run(ManagerOp::On, &shared);
        assert_eq!(
            shared.read(|m| m.manager_note),
            Some("Not done: this computer's password was not confirmed.")
        );
        assert!(shared.read(|m| m.stop_card.is_none()));
        assert!(!watch.ctx.guard.store().read(|s| s.enabled).unwrap_or(false));
        assert_eq!(
            shared.read(|m| m.manager.clone()),
            before,
            "the page as it was"
        );
        watch.run(ManagerOp::Setting(HostSetting::Notify(true)), &shared);
        assert!(shared.read(|m| m.manager_note.is_some()));
        assert_eq!(shared.read(|m| m.manager.clone()), before);
    }

    /// §B.8.6.2: no access-increasing operation runs during a remote session
    /// or in the 60 s after one: the window's refuses before any dialog, in
    /// plain words, and nothing changes.
    #[test]
    fn access_increasing_ops_wait_for_the_remote_session_rule() {
        use tornect_core::unattended::guard::{AllowAllReAuth, RemoteSessionActivity};
        struct Live;
        impl RemoteSessionActivity for Live {
            fn last_session_ended_at(&self) -> Option<Instant> {
                None
            }
            fn session_live(&self) -> bool {
                true
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let watch = manager_over(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(Live),
            tornect_core::levels::AccountFacts::Linux,
            b"this machine",
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.run(ManagerOp::On, &shared);
        assert_eq!(
            shared.read(|m| m.manager_note),
            Some("Not done: a remote session is running, or ended less than a minute ago.")
        );
        assert!(reauth.calls().is_empty(), "no dialog");
        assert!(shared.read(|m| m.stop_card.is_none()));
        assert!(!watch.ctx.guard.store().read(|s| s.enabled).unwrap_or(false));
    }

    /// Decision M1-67: a grant that holds the administrator level and was
    /// restored on another machine (disabled and marked) is not enabled from
    /// the window until a new generated password cleared its mark: Enable is
    /// refused, said in plain words, and the grant stays disabled.
    #[test]
    fn enabling_a_marked_admin_grant_is_refused_until_a_new_password() {
        use tornect_core::levels::{AccountFacts, WindowsFacts};
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        use tornect_core::unattended::ipc::GrantOptions;
        let windows = AccountFacts::Windows(WindowsFacts {
            installed: true,
            administrator: true,
            ..WindowsFacts::default()
        });
        let tmp = tempfile::tempdir().unwrap();
        let device = tornect_core::DeviceId::from_bytes([7; 32]);
        {
            let watch = manager_over(
                tmp.path(),
                Arc::new(AllowAllReAuth::default()),
                Arc::new(NoSessionActivity),
                windows,
                b"the first machine",
            );
            let guard = &watch.ctx.guard;
            guard.master_on(Actor::Cli, &[0x42; 32]).unwrap();
            guard
                .create_grant(
                    Actor::Cli,
                    &device,
                    Preset::HeadlessBox,
                    &GrantOptions {
                        elevation: Some(Elevation::Admin),
                        ..GrantOptions::default()
                    },
                    &[0u8; 192],
                    true,
                )
                .unwrap();
            let grant = guard.store().grant(&device).unwrap();
            assert!(grant.holds_level() && !grant.marked());
        }
        let watch = manager_over(
            tmp.path(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            windows,
            b"another machine",
        );
        let grant = watch.ctx.guard.store().grant(&device).unwrap();
        assert!(grant.holds_level() && grant.marked(), "restored: marked");
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.run(ManagerOp::Enable(device), &shared);
        assert_eq!(
            shared.read(|m| m.manager_note),
            Some("Not done: this device needs a new password before its access can be enabled.")
        );
        let view = shared.read(|m| m.manager.clone()).expect("read");
        assert_eq!(view.grants[0].state, "disabled:restore");
    }

    /// `watch` reading and changing what starts at sign-in through `fake`.
    fn with_autostart(
        mut watch: ManagerWatch,
        fake: &Arc<crate::test_support::FakeAutostart>,
    ) -> ManagerWatch {
        use tornect_platform::autostart::Autostart;
        watch.ctx.autostart = Arc::clone(fake) as Arc<dyn Autostart>;
        let fake = Arc::clone(fake);
        watch.autostart_for = Arc::new(move |_| Arc::clone(&fake) as Arc<dyn Autostart>);
        watch
    }

    /// §B.1.1: the window's "Start Tornect when I sign in" runs the guard's
    /// operation of `tornect service install`, as the window: one dialog
    /// under its own name, the line `AutostartChanged` by the window, then
    /// the registration, and the switch reads what the system says after.
    /// A password not confirmed registers nothing.
    #[test]
    fn the_sign_in_switch_goes_through_the_guard() {
        use tornect_core::session_log::{Actor, SessionEvent};
        use tornect_core::unattended::guard::{AllowAllReAuth, DenyAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let fake = Arc::new(crate::test_support::FakeAutostart::default());
        let watch = with_autostart(
            manager_over(
                tmp.path(),
                Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
                Arc::new(NoSessionActivity),
                tornect_core::levels::AccountFacts::Linux,
                b"this machine",
            ),
            &fake,
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.refresh(&shared);
        let sign_in = |shared: &Shared| shared.read(|m| m.manager.as_ref().and_then(|v| v.sign_in));
        assert_eq!(sign_in(&shared), Some(false));
        watch.run(ManagerOp::SignIn(true), &shared);
        assert_eq!(reauth.calls(), ["service_install"]);
        assert_eq!(fake.installs(), [false]);
        assert_eq!(sign_in(&shared), Some(true));
        assert_eq!(shared.read(|m| m.manager_note), None);
        assert!(watch.ctx.log.read_all().unwrap().iter().any(|r| {
            r.event == SessionEvent::AutostartChanged
                && r.by == Some(Actor::Ui)
                && r.detail.as_deref() == Some("install")
        }));

        let tmp = tempfile::tempdir().unwrap();
        let fake = Arc::new(crate::test_support::FakeAutostart::default());
        let watch = with_autostart(
            manager_over(
                tmp.path(),
                Arc::new(DenyAllReAuth),
                Arc::new(NoSessionActivity),
                tornect_core::levels::AccountFacts::Linux,
                b"this machine",
            ),
            &fake,
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.run(ManagerOp::SignIn(true), &shared);
        assert!(fake.installs().is_empty(), "nothing registered");
        assert_eq!(
            shared.read(|m| m.manager_note),
            Some("Not done: this computer's password was not confirmed.")
        );
        assert_eq!(sign_in(&shared), Some(false));
    }

    /// §B.8.6.2: during a remote session, and for 60 s after one, the switch
    /// registers nothing and asks no dialog; the section says why.
    #[test]
    fn the_sign_in_switch_waits_for_the_remote_session_rule() {
        use tornect_core::unattended::guard::{AllowAllReAuth, RemoteSessionActivity};
        struct Live;
        impl RemoteSessionActivity for Live {
            fn last_session_ended_at(&self) -> Option<Instant> {
                None
            }
            fn session_live(&self) -> bool {
                true
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let fake = Arc::new(crate::test_support::FakeAutostart::default());
        let watch = with_autostart(
            manager_over(
                tmp.path(),
                Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
                Arc::new(Live),
                tornect_core::levels::AccountFacts::Linux,
                b"this machine",
            ),
            &fake,
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.run(ManagerOp::SignIn(true), &shared);
        assert!(fake.installs().is_empty());
        assert!(reauth.calls().is_empty(), "no dialog");
        assert_eq!(
            shared.read(|m| m.manager_note),
            Some("Not done: a remote session is running, or ended less than a minute ago.")
        );
        assert_eq!(
            shared.read(|m| m.manager.as_ref().and_then(|v| v.sign_in)),
            Some(false)
        );
    }

    /// Turning the start at sign-in off with nothing registered changes
    /// nothing and asks nothing; with a registration it asks once and
    /// removes it.
    #[test]
    fn turning_sign_in_off_with_nothing_registered_asks_nothing() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let fake = Arc::new(crate::test_support::FakeAutostart::default());
        let watch = with_autostart(
            manager_over(
                tmp.path(),
                Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
                Arc::new(NoSessionActivity),
                tornect_core::levels::AccountFacts::Linux,
                b"this machine",
            ),
            &fake,
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.run(ManagerOp::SignIn(false), &shared);
        assert!(reauth.calls().is_empty());
        assert_eq!(fake.uninstalls(), 0);
        assert_eq!(shared.read(|m| m.manager_note), None);
        watch.run(ManagerOp::SignIn(true), &shared);
        watch.run(ManagerOp::SignIn(false), &shared);
        assert_eq!(reauth.calls(), ["service_install", "service_uninstall"]);
        assert_eq!(fake.uninstalls(), 1);
        assert_eq!(
            shared.read(|m| m.manager.as_ref().and_then(|v| v.sign_in)),
            Some(false)
        );
    }

    /// The install state Settings, General shows is the install's own probe
    /// (§B.1.1): the per-user files, here in a temporary home.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_install_state_follows_the_install_probe() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let (bin, apps) = (tmp.path().join("bin"), tmp.path().join("apps"));
        let mut watch = manager_over(
            &tmp.path().join("home"),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            tornect_core::levels::AccountFacts::Linux,
            b"this machine",
        );
        let files = tornect_platform::install::LinuxInstall::new(
            bin.clone(),
            apps,
            tmp.path().join("config"),
        );
        let probe = files.clone();
        watch.installed = Arc::new(move || Some(probe.installed()));
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.refresh(&shared);
        let installed =
            |shared: &Shared| shared.read(|m| m.manager.as_ref().and_then(|v| v.installed));
        assert_eq!(installed(&shared), Some(false));
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(files.exe(), b"").unwrap();
        watch.refresh(&shared);
        assert_eq!(installed(&shared), Some(true));
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
            hosted_store: std::sync::OnceLock::new(),
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

    /// The plan's cross-feature rule (§B.6, decision M1-73; decision M1-76):
    /// the stream window's Clipboard switch starts on only when `[viewer]
    /// clipboard_sync` is on and the host was paired before this connection;
    /// never in the first session with a computer paired in it.
    #[test]
    fn the_clipboard_starts_off_with_a_host_paired_in_this_connection() {
        for (sync, before, on) in [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            assert_eq!(clipboard_starts_on(sync, before), on, "{sync} {before}");
        }
    }

    /// Design `services` §7.5: what Settings, Sharing last saved (the model's
    /// settings), not the copy of `config.toml` read at the start, sets the
    /// policy the host starts with and this computer's own download limits
    /// at each viewed session; the saved clipboard switch counts only with a
    /// host paired before the connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_saved_services_settings_set_the_policy_and_the_download_limits() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let popups = Popups::new(Arc::clone(&shared));
        let identity = Arc::new(HostIdentity::from_seed(&[0x21; 32]));
        let device = DeviceIdentity::from_seed(&[0x22; 32]);
        let device_pk = HostSigner::public_key(&device);
        let words = Arc::new(super::super::recognize::Recognizer::new(
            paths.clone(),
            super::super::recognize::Me {
                name: "Linux PC".to_owned(),
                onion: identity.id(),
                device: tornect_core::DeviceId::from_bytes(device_pk),
            },
        ));
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
            background: None,
            hosted_store: std::sync::OnceLock::new(),
        };
        shared.update(|m| {
            let services = &mut m.settings.services;
            services.browse_files = false;
            services.max_file_mib = 16;
            services.keep_free_mib = 64;
        });
        assert!(b.cfg.services.browse_files, "the start's copy differs");
        let hosted = host_role(&b).await.expect("the window host is wired");
        {
            let policy = hosted.policy.borrow();
            assert!(!policy.browse_files);
            assert!(policy.chat && policy.clipboard && policy.receive_files);
            assert_eq!(policy.max_file, 16 << 20);
        }
        let token = tornect_signal::consent::SessionToken::new([5; 32]);
        let (start, on) = services_start(&b, ServicesBinding::new(&token, &[7; 32]), true).await;
        assert_eq!(start.local.max_file, 16 << 20);
        assert_eq!(start.local.keep_free, 64 << 20);
        assert!(!on, "the clipboard's switch is off unless turned on");
        // The cross-feature rule (decision M1-76): the saved switch counts
        // only with a host paired before this connection.
        shared.update(|m| m.settings.viewer.clipboard_sync = true);
        let (_, on) = services_start(&b, ServicesBinding::new(&token, &[7; 32]), true).await;
        assert!(on, "a host paired before");
        let (_, on) = services_start(&b, ServicesBinding::new(&token, &[7; 32]), false).await;
        assert!(!on, "a host paired in this connection");
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

    /// The quality design §6.7: each viewed session gets its own channel of
    /// picks, starting at the settings' preset; a pick goes only when it
    /// changes something and only while a session runs, and a second
    /// session's viewer starts from the settings' preset again, never from
    /// the last session's pick.
    #[test]
    fn each_session_starts_its_quality_picks_from_the_settings() {
        use tornect_core::config::QualityPreset::{Balanced, BestPerformance, BestQuality};
        let link = StreamLink::default();
        assert!(!link.request_quality(BestQuality), "no session");
        let mut first = link.start_quality(Balanced);
        assert_eq!(*first.borrow_and_update(), Balanced);
        assert!(!link.request_quality(Balanced), "the session's own preset");
        assert!(!first.has_changed().unwrap());
        assert!(link.request_quality(BestPerformance));
        assert!(first.has_changed().unwrap());
        assert_eq!(*first.borrow_and_update(), BestPerformance);
        assert!(!link.request_quality(BestPerformance), "picked already");
        // The session ends: no pick goes anywhere, and the old receiver
        // hears that its sender went.
        link.set_quality(None);
        assert!(!link.request_quality(BestQuality));
        assert!(first.has_changed().is_err());
        // The next session, with the settings at Balanced.
        let mut second = link.start_quality(Balanced);
        assert_eq!(*second.borrow_and_update(), Balanced, "not the last pick");
        assert!(link.request_quality(BestQuality));
        assert_eq!(*second.borrow_and_update(), BestQuality);
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
                stream: StreamInfo::default(),
                services: None,
                screens: None,
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
        let (services, observer) = test_services(&media, &shared, &paths.sessions_log());
        wiring.deps.sessions = Arc::new(GuiSessions {
            live: Arc::clone(&wiring.live),
            polkit: Arc::clone(&wiring.polkit),
            media,
            services,
            observer,
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
        let tmp = tempfile::tempdir().unwrap();
        let (services, observer) = test_services(&media, &shared, &tmp.path().join("sessions.log"));
        let sessions = GuiSessions {
            live: Arc::new(LiveSessions::new()),
            polkit: Arc::new(PolkitRevocation::for_this_host()),
            media,
            services,
            observer,
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
        let tmp = tempfile::tempdir().unwrap();
        let (services, observer) = test_services(&media, &shared, &tmp.path().join("sessions.log"));
        let sessions = GuiSessions {
            live: Arc::new(LiveSessions::new()),
            polkit: Arc::new(PolkitRevocation::for_this_host()),
            media,
            services,
            observer,
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

    /// Decision M1-76 (cv): a save reloads `config.toml`, but what the
    /// window says of the clipboard follows the running portal request (the
    /// switch as read at this window's start), not the file: a hand edit
    /// turning `[services] wayland_clipboard` off while the window runs
    /// leaves the session sheet naming the clipboard the sessions still get,
    /// and Settings, Sharing not saying the desktop does not share it; a
    /// hand edit turning it on promises nothing the portal does not do.
    #[test]
    fn a_save_never_changes_what_the_running_portal_asks_for() {
        use super::super::model::{ServicesSettings, Setup};

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let path = paths.config_file();
        let mut on_disk = Config::default();
        on_disk.services.wayland_clipboard = true;
        on_disk.save(&path).unwrap();
        let wayland = Setup {
            token_file: std::path::PathBuf::from("token"),
            granted: true,
            busy: false,
            note: None,
        };
        let shared = Shared::new(
            Model {
                settings: Settings::of(&on_disk),
                setup: Some(wayland.clone()),
                portal_clipboard: true,
                ..Model::default()
            },
            Arc::new(|_| {}),
        );
        // What the session sheet and the block window say control also
        // gives (`strip::sheet_services_line` of it names the clipboard
        // exactly when this is true).
        let clipboard = |m: &Model| m.services_offered().clipboard;
        assert!(shared.read(clipboard));
        // config.toml edited by hand while the window runs, then any switch.
        on_disk.services.wayland_clipboard = false;
        on_disk.save(&path).unwrap();
        let switches = ServicesSettings {
            browse_files: false,
            ..ServicesSettings::of(&on_disk.services)
        };
        save_settings(&paths, &shared, &SettingsChange::Services(switches));
        shared.read(|m| {
            assert!(!m.settings.services.wayland_clipboard, "the file reloaded");
            assert!(m.portal_clipboard);
            assert!(clipboard(m), "the sessions still get it");
            assert!(!m.clipboard_not_shared());
        });

        // The other way: started without it, turned on by hand since.
        let shared = Shared::new(
            Model {
                settings: Settings::of(&on_disk),
                setup: Some(wayland),
                ..Model::default()
            },
            Arc::new(|_| {}),
        );
        on_disk.services.wayland_clipboard = true;
        on_disk.save(&path).unwrap();
        save_settings(&paths, &shared, &SettingsChange::Services(switches));
        shared.read(|m| {
            assert!(m.settings.services.wayland_clipboard, "the file reloaded");
            assert!(!clipboard(m), "the running portal does not ask for it");
            assert!(m.clipboard_not_shared());
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

    /// A settings change that cannot be saved logs a fixed line, as the log
    /// writes it: no error text, which names the settings file's path, and
    /// so the account.
    #[test]
    fn a_failed_save_logs_no_path() {
        use std::io::Write;
        use tornect_core::config::Theme;
        use tracing_subscriber::layer::SubscriberExt as _;

        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = Capture(Arc::clone(&buffer));
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .fmt_fields(tornect_core::telemetry::redacting_fields())
                .with_ansi(false)
                .with_writer(move || writer.clone()),
        );
        let _default = tracing::subscriber::set_default(subscriber);

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        paths.ensure().unwrap();
        std::fs::write(paths.config_file(), "this is = not [valid").unwrap();
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        save_settings(&paths, &shared, &SettingsChange::Theme(Theme::Dark));
        assert_eq!(shared.read(|m| m.settings.problem), Some(NOT_SAVED_FILE));
        let logged = String::from_utf8(
            buffer
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        )
        .unwrap();
        assert!(logged.contains("the settings were not saved"), "{logged}");
        let home = tmp.path().to_string_lossy();
        assert!(
            !logged.contains(&*home) && !logged.contains("config.toml"),
            "{logged}"
        );
    }

    /// A window's backend for the first run's tests, in a fresh home under
    /// `tmp`: shown on screen (not in background mode), hosting.
    fn first_start(tmp: &tempfile::TempDir) -> (Backend, Arc<Shared>, Paths) {
        let paths = Paths::from_home(tmp.path().join("home"));
        paths.ensure().unwrap();
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let identity = Arc::new(HostIdentity::from_seed(&[0x21; 32]));
        let device = DeviceIdentity::from_seed(&[0x22; 32]);
        let device_pk = HostSigner::public_key(&device);
        let words = Arc::new(super::super::recognize::Recognizer::new(
            paths.clone(),
            super::super::recognize::Me {
                name: tornect_core::config::default_device_name(),
                onion: identity.id(),
                device: tornect_core::DeviceId::from_bytes(device_pk),
            },
        ));
        let b = Backend {
            paths: paths.clone(),
            cfg: Config::default(),
            shared: Arc::clone(&shared),
            popups: Popups::new(Arc::clone(&shared)),
            link: Arc::new(StreamLink::default()),
            source: Source::TestCard,
            host: true,
            identity,
            device: Arc::new(device),
            device_pk,
            words,
            background: None,
            hosted_store: std::sync::OnceLock::new(),
        };
        (b, shared, paths)
    }

    /// The first run's question (the operator's ruling: before the first
    /// pairing or connection sends the name): until it is answered nothing
    /// acts (a connect asked meanwhile is dropped, no host and no Tor are
    /// started), and the answer reaches every copy the held start reads:
    /// `config.toml`, the configuration the host's `HostConfig` and the
    /// client's `ClientConfig` are built from, the recognizer's own entry and
    /// the model.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_first_run_asks_the_name_before_anything_is_sent() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut b, shared, paths) = first_start(&tmp);
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(Command::Connect(TornectId::from_bytes([0x42; 32])))
            .unwrap();
        tx.send(Command::FirstRunName(Some("Desk by the window".to_owned())))
            .unwrap();
        assert!(ask_the_name(&mut b, &mut rx).await);
        shared.read(|m| {
            assert!(matches!(m.client, ClientStage::Idle), "nothing dialed");
            assert!(!m.name_question);
            assert_eq!(m.device_name, "Desk by the window");
        });
        assert_eq!(b.cfg.general.device_name, "Desk by the window");
        assert_eq!(
            Config::load(&paths.config_file())
                .unwrap()
                .general
                .device_name,
            "Desk by the window"
        );
        assert!(
            b.words
                .saved()
                .iter()
                .any(|s| s.name == "Desk by the window")
        );
        let hosted = host_role(&b).await.expect("the window host is wired");
        assert_eq!(hosted.serving.0.host_name, "Desk by the window");
        if let Some(ipc) = &hosted.ipc {
            ipc.abort();
        }
    }

    /// B13 review: the window's own lines for its unattended connects go
    /// through its host role's store (one writer on `sessions.log` in this
    /// process; the store tags them once unattended access is on), not
    /// through a handle of their own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_window_logs_its_connects_through_its_host_role() {
        let tmp = tempfile::tempdir().unwrap();
        let (b, _shared, paths) = first_start(&tmp);
        assert!(b.hosted_store.get().is_none(), "no host role yet");
        let hosted = host_role(&b).await.expect("the window host is wired");
        let store = b.hosted_store.get().expect("the host role's store");
        assert_eq!(store.path(), paths.unattended_store().as_path());
        let watch = hosted.manager.as_ref().expect("a host with its store");
        let before = watch.ctx.log.read_all().unwrap().len();
        let known = tornect_core::trusted::KnownHost {
            label: "Desk".to_owned(),
            host_device_pk: [7; 32],
            paired_at: 1,
            last_seen: 1,
        };
        b.log_attempt(&known, &Logged::Ended("cancelled"));
        let logged = watch.ctx.log.read_all().unwrap();
        assert_eq!(logged.len(), before + 1);
        assert_eq!(
            logged.last().map(|r| r.event),
            Some(tornect_core::session_log::SessionEvent::UnattendedConnect)
        );
        if let Some(ipc) = &hosted.ipc {
            ipc.abort();
        }
    }

    /// Skip keeps the neutral default, written nowhere; a window closed
    /// before the answer starts nothing, and its home keeps the neutral
    /// name.
    #[tokio::test]
    async fn skipping_keeps_the_neutral_name() {
        let neutral = tornect_core::config::default_device_name();
        let tmp = tempfile::tempdir().unwrap();
        let (mut b, shared, paths) = first_start(&tmp);
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(Command::FirstRunName(None)).unwrap();
        assert!(ask_the_name(&mut b, &mut rx).await);
        assert_eq!(b.cfg.general.device_name, neutral);
        shared.read(|m| assert_eq!(m.device_name, neutral));
        assert!(!paths.config_file().exists(), "nothing saved");

        let tmp = tempfile::tempdir().unwrap();
        let (mut b, shared, paths) = first_start(&tmp);
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(Command::Quit).unwrap();
        assert!(!ask_the_name(&mut b, &mut rx).await, "closed first");
        assert!(shared.read(|m| m.name_question), "never answered");
        assert_eq!(b.cfg.general.device_name, neutral);
        assert!(!paths.config_file().exists());
    }

    /// The history switch and Clear history work while the first run's
    /// question waits: each acts at once on this computer's own files, before
    /// the answer.
    #[tokio::test]
    async fn the_question_keeps_the_history_switch_and_clear() {
        use tornect_core::address_book::{Day, Store};
        let tmp = tempfile::tempdir().unwrap();
        let (mut b, shared, paths) = first_start(&tmp);
        let store = Store::new(&paths);
        store.set_history(true).unwrap();
        let id = TornectId::from_bytes([0x42; 32]);
        assert!(
            store
                .record_visit(id, [7; 32], "Desk", Day::today())
                .unwrap()
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(Command::ClearHistory).unwrap();
        tx.send(Command::SetHistory(false)).unwrap();
        tx.send(Command::FirstRunName(None)).unwrap();
        assert!(ask_the_name(&mut b, &mut rx).await);
        assert!(store.recent().unwrap().visits.is_empty(), "cleared");
        assert!(!store.keeps_history(), "switched off");
        shared.read(|m| {
            assert!(m.book.recent.is_empty() && !m.book.history);
            assert_eq!(
                m.book.note.as_deref(),
                Some("History is off: no list of recent connections is kept from now on.")
            );
        });
    }

    /// Only the first start of a home asks, and only in a window shown on
    /// screen: an existing home (the first run's marker is there, as after an
    /// upgrade) and a start in background mode keep the name they have.
    #[test]
    fn an_existing_home_is_not_asked() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let first = first_run(&paths);
        assert!(first && name_question_due(first, false), "a fresh home");
        assert!(!name_question_due(first, true), "background mode");
        let again = first_run(&paths);
        assert!(
            !again && !name_question_due(again, false),
            "an existing home"
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

    /// While another Tornect process holds this home's host lock, the first
    /// run's question is shared from its first frame on, as every page is:
    /// a settings change and the name sent meanwhile are not saved, and
    /// `config.toml` stays byte for byte as it was.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_first_run_question_is_shared_while_another_process_hosts() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut b, shared, paths) = first_start(&tmp);
        Config::default().save(&paths.config_file()).unwrap();
        let before = std::fs::read(paths.config_file()).unwrap();
        let held = HostLock::acquire(&paths).unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let meanwhile = async {
            while !shared.read(|m| m.name_question) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(
                shared.read(|m| m.screen_shared(Instant::now())),
                "shared while the question is open"
            );
            tx.send(Command::SaveSettings(SettingsChange::DeviceName(
                "Desk".to_owned(),
            )))
            .unwrap();
            tx.send(Command::FirstRunName(Some("Desk by the window".to_owned())))
                .unwrap();
        };
        let (started, ()) = tokio::join!(before_the_start(&mut b, &mut rx), meanwhile);
        let (first, early) = started.expect("answered");
        early.abort();
        assert!(first);
        assert_eq!(
            std::fs::read(paths.config_file()).unwrap(),
            before,
            "nothing saved"
        );
        shared.read(|m| assert_eq!(m.settings.problem, Some(NOT_SAVED_SHARED)));
        drop(held);
    }

    /// A window that becomes the host is hosted by no other process: the
    /// early watch, which read another process's lock, stops before the
    /// window takes the lock, so the window's own lock never counts as
    /// another's, and `hosted_elsewhere` is false from then on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_window_that_becomes_the_host_is_not_hosted_elsewhere() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut b, shared, paths) = first_start(&tmp);
        let held = HostLock::acquire(&paths).unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(Command::FirstRunName(None)).unwrap();
        let (first, early) = before_the_start(&mut b, &mut rx).await.expect("answered");
        assert!(first);
        assert!(
            shared.read(|m| m.hosted_elsewhere),
            "another process held the lock"
        );
        drop(held);
        let hosted = take_host_role(&b, early)
            .await
            .expect("the window host is wired");
        assert!(
            !shared.read(|m| m.hosted_elsewhere),
            "this window holds the lock"
        );
        tokio::time::sleep(HOST_LOCK_EVERY + Duration::from_millis(500)).await;
        assert!(
            !shared.read(|m| m.hosted_elsewhere),
            "its own lock is not another process's"
        );
        if let Some(ipc) = &hosted.ipc {
            ipc.abort();
        }
    }

    /// A window closed during the first run's question leaves no marker: the
    /// next start asks the question again, with the history notice.
    #[tokio::test]
    async fn closing_during_the_question_asks_it_again_next_time() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut b, _shared, paths) = first_start(&tmp);
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(Command::Quit).unwrap();
        assert!(
            before_the_start(&mut b, &mut rx).await.is_none(),
            "closed first"
        );
        assert!(first_run(&paths), "the next start is a first run");
    }

    /// A window host's view of unattended access in `home` for Rotate ID:
    /// unattended access on, one device with a grant.
    fn rotation_watch(home: &std::path::Path) -> ManagerWatch {
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        use tornect_core::unattended::ipc::GrantOptions;
        let watch = manager_over(
            home,
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            tornect_core::levels::AccountFacts::Linux,
            b"machine-R",
        );
        let guard = &watch.ctx.guard;
        guard.master_on(Actor::Cli, &[0x42; 32]).unwrap();
        guard
            .create_grant(
                Actor::Cli,
                &tornect_core::DeviceId::from_bytes([3; 32]),
                Preset::HeadlessBox,
                &GrantOptions::default(),
                &[0u8; 192],
                false,
            )
            .unwrap();
        watch
    }

    /// The home's own keys, whose writes fail: the identity step of a
    /// rotation cannot write the new seed.
    struct NoWrites(tornect_core::keystore::FileSecretStore);

    impl tornect_core::SecretStore for NoWrites {
        fn get(&self, name: &str) -> tornect_core::Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
            self.0.get(name)
        }
        fn put(&self, _: &str, _: &[u8]) -> tornect_core::Result<()> {
            Err(tornect_core::CoreError::Io(std::io::Error::other(
                "no writes in this test",
            )))
        }
        fn delete(&self, name: &str) -> tornect_core::Result<bool> {
            self.0.delete(name)
        }
    }

    /// §B.8.12: a rotation whose identity step fails after the guard's wipe
    /// leaves the window open on the card that says access was removed and
    /// the old ID kept: `closed` stays unset and `rotating` set (the window
    /// keeps waiting); every grant is gone, and the ID is the old one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rotation_whose_identity_step_fails_keeps_the_card() {
        use tornect_core::keystore::{FileSecretStore, load_or_create_host_identity};
        use tornect_core::session_log::Actor;
        let tmp = tempfile::tempdir().unwrap();
        let watch = rotation_watch(tmp.path());
        let paths = Paths::from_home(tmp.path());
        let keys = FileSecretStore::open(paths.keys_dir()).unwrap();
        let (old, _) = load_or_create_host_identity(&keys).unwrap();
        let shared = Shared::new(
            Model {
                rotating: true,
                ..Model::default()
            },
            Arc::new(|_| {}),
        );
        let guard = Arc::clone(&watch.ctx.guard);
        let failing = NoWrites(keys.clone());
        rotate_at_close(&shared, true, move || {
            crate::rotate::rotate_id(&paths, &guard, Actor::Ui, &failing, None)
        })
        .await;
        shared.read(|m| {
            assert_eq!(m.rotate_failed, Some(RotateFailed::AccessRemoved));
            assert!(!m.closed, "the window stays on its card");
            assert!(m.rotating, "and keeps waiting");
        });
        assert!(
            watch.ctx.guard.store().grants().is_empty(),
            "access removed"
        );
        let (now, created) = load_or_create_host_identity(&keys).unwrap();
        assert!(!created);
        assert_eq!(now.id(), old.id(), "the old ID kept");
    }

    /// §B.8.12: the window waits for a slow rotation past the quit's cut:
    /// while the rotation runs, `rotating` stays set and `closed` unset (the
    /// window keeps waiting); `closed` comes only once it has returned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_window_closes_only_after_a_slow_rotation_returns() {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::Actor;
        let tmp = tempfile::tempdir().unwrap();
        let watch = rotation_watch(tmp.path());
        let paths = Paths::from_home(tmp.path());
        let keys = FileSecretStore::open(paths.keys_dir()).unwrap();
        let shared = Shared::new(
            Model {
                rotating: true,
                ..Model::default()
            },
            Arc::new(|_| {}),
        );
        let (release, held) = std::sync::mpsc::channel::<()>();
        let (began, running) = tokio::sync::oneshot::channel::<()>();
        let guard = Arc::clone(&watch.ctx.guard);
        let closing = {
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                rotate_at_close(&shared, true, move || {
                    let _ = began.send(());
                    held.recv().expect("released");
                    crate::rotate::rotate_id(&paths, &guard, Actor::Ui, &keys, None)
                })
                .await;
            })
        };
        running.await.expect("the rotation runs");
        tokio::time::sleep(Duration::from_millis(300)).await;
        shared.read(|m| {
            assert!(m.rotating, "the window keeps waiting");
            assert!(!m.closed, "not before the rotation returns");
        });
        release.send(()).unwrap();
        closing.await.unwrap();
        shared.read(|m| {
            assert!(m.closed, "closed once it returned");
            assert_eq!(m.rotate_failed, None);
        });
    }

    /// §B.8.12: while another task still holds the Tor node (Tor did not
    /// stop), Rotate ID does not run: the store is unchanged, and the
    /// window's card says nothing was changed, the window still open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_still_held_refuses_the_rotation() {
        use tornect_core::keystore::FileSecretStore;
        use tornect_core::session_log::Actor;
        let tmp = tempfile::tempdir().unwrap();
        let watch = rotation_watch(tmp.path());
        let before = watch.ctx.guard.store().grants();
        let paths = Paths::from_home(tmp.path());
        let keys = FileSecretStore::open(paths.keys_dir()).unwrap();
        let shared = Shared::new(
            Model {
                rotating: true,
                ..Model::default()
            },
            Arc::new(|_| {}),
        );
        let guard = Arc::clone(&watch.ctx.guard);
        rotate_at_close(&shared, false, move || {
            crate::rotate::rotate_id(&paths, &guard, Actor::Ui, &keys, None)
        })
        .await;
        shared.read(|m| {
            assert_eq!(m.rotate_failed, Some(RotateFailed::NothingChanged));
            assert!(!m.closed && m.rotating, "the window stays on its card");
        });
        assert_eq!(watch.ctx.guard.store().grants(), before, "nothing wiped");
        assert!(watch.ctx.guard.store().read(|s| s.enabled).unwrap());
    }

    /// §B.8.12: before Rotate ID runs, Tor's shutdown aborts a publish still
    /// running and waits for its end, and waits for a Tor start still
    /// running (it is never cancelled), so that neither holds the node when
    /// the rotation runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_shutdown_before_the_rotation_stops_the_publish_and_the_tor_start() {
        use std::sync::atomic::AtomicBool;
        let (held, mut publishing) = tokio::sync::oneshot::channel::<()>();
        let publish: JoinHandle<anyhow::Result<OnionListener>> = tokio::spawn(async move {
            let _held = held;
            std::future::pending::<anyhow::Result<OnionListener>>().await
        });
        let started = Arc::new(AtomicBool::new(false));
        let tor_start: JoinHandle<anyhow::Result<TorNode>> = {
            let started = Arc::clone(&started);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                started.store(true, Ordering::SeqCst);
                Err(anyhow::anyhow!("no Tor in this test"))
            })
        };
        assert!(
            stop_tor_for_rotation(Some(tor_start), Some(publish), None, None).await,
            "no node held"
        );
        assert_eq!(
            publishing.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed),
            "the publish ended before the rotation"
        );
        assert!(
            started.load(Ordering::SeqCst),
            "the Tor start was waited for"
        );
    }

    /// B02: the wait before each automatic try doubles from 30 s and stops
    /// growing at 5 min, however many failures come in a row.
    #[test]
    fn the_retry_wait_doubles_up_to_five_minutes() {
        let secs: Vec<u64> = (1..=7).map(|n| retry_after(n).as_secs()).collect();
        assert_eq!(secs, [30, 60, 120, 240, 300, 300, 300]);
        assert_eq!(retry_after(0), RETRY_FIRST);
        assert_eq!(retry_after(u32::MAX), RETRY_MOST);
    }

    /// B02: a start that fails is not the end. Its failure arms the next
    /// try, which comes due after the wait and no sooner; a second failure in
    /// a row waits twice as long; a start that works and stays up 5 min
    /// resets the count, so the next failure waits 30 s again. Before the fix
    /// the first failure was final: nothing ever started Tor again.
    #[tokio::test(start_paused = true)]
    async fn a_failed_start_is_tried_again_after_its_wait() {
        let fails = || tokio::spawn(async { Err::<u32, _>(anyhow::anyhow!("offline")) });
        let mut tor: Restarting<u32> = Restarting::idle();
        assert!(!tor.pending(), "nothing runs, nothing waits");
        tor.start(fails());
        let Restart::Failed(e, wait) = tor.next().await else {
            panic!("the start failed");
        };
        assert_eq!(e.to_string(), "offline");
        assert_eq!(wait, Duration::from_secs(30));
        assert!(tor.pending(), "a try waits");
        let armed = tokio::time::Instant::now();
        assert!(matches!(tor.next().await, Restart::Due));
        assert_eq!(
            armed.elapsed(),
            Duration::from_secs(30),
            "due after its wait"
        );
        assert!(!tor.pending(), "the caller starts the try");

        tor.start(fails());
        let Restart::Failed(_, wait) = tor.next().await else {
            panic!("failed again");
        };
        assert_eq!(wait, Duration::from_secs(60), "twice as long");
        assert!(matches!(tor.next().await, Restart::Due));

        tor.start(tokio::spawn(async { Ok(7) }));
        assert!(matches!(tor.next().await, Restart::Started(7)));
        assert!(!tor.pending());
        tokio::time::advance(STAYED_UP).await;
        tor.start(fails());
        let Restart::Failed(_, wait) = tor.next().await else {
            panic!("failed after working");
        };
        assert_eq!(wait, Duration::from_secs(30), "the count starts again");

        // A panicked start is a failure like any other.
        fn boom() -> anyhow::Result<u32> {
            panic!("in the start")
        }
        let mut panics: Restarting<u32> = Restarting::idle();
        panics.start(tokio::spawn(async { boom() }));
        assert!(matches!(panics.next().await, Restart::Failed(..)));
        assert!(panics.pending());
    }

    /// B02 review: a service that stops right after each publish that
    /// worked is a failure in a row: the tries keep doubling up to 5 min
    /// instead of coming every 30 s for good. One that stayed up 5 min
    /// worked: its stop is the first failure again.
    #[tokio::test(start_paused = true)]
    async fn a_publish_that_stops_at_once_keeps_backing_off() {
        let mut publish: Restarting<u32> = Restarting::idle();
        let mut waits = Vec::new();
        for _ in 0..6 {
            publish.start(tokio::spawn(async { Ok(1) }));
            assert!(matches!(publish.next().await, Restart::Started(1)));
            tokio::time::advance(Duration::from_secs(1)).await;
            // The listener closed.
            waits.push(publish.failed().as_secs());
            assert!(matches!(publish.next().await, Restart::Due));
        }
        assert_eq!(waits, [30, 60, 120, 240, 300, 300]);

        publish.start(tokio::spawn(async { Ok(1) }));
        assert!(matches!(publish.next().await, Restart::Started(1)));
        tokio::time::advance(STAYED_UP - Duration::from_secs(1)).await;
        assert_eq!(publish.failed(), RETRY_MOST, "not up long enough");
        assert!(matches!(publish.next().await, Restart::Due));
        publish.start(tokio::spawn(async { Ok(1) }));
        assert!(matches!(publish.next().await, Restart::Started(1)));
        tokio::time::advance(STAYED_UP).await;
        assert_eq!(publish.failed(), RETRY_FIRST, "it stayed up: worked");
    }

    /// B02: Try again starts the waiting try at once, and only that: while a
    /// start runs, or when nothing failed, it does nothing; a listener that
    /// closed arms a try as a failed start does.
    #[tokio::test(start_paused = true)]
    async fn try_again_ends_the_wait_and_only_the_wait() {
        let mut publish: Restarting<u32> = Restarting::idle();
        assert!(!publish.now(), "nothing failed");
        publish.start(tokio::spawn(async { Err(anyhow::anyhow!("no service")) }));
        assert!(!publish.now(), "a start runs");
        assert!(matches!(publish.next().await, Restart::Failed(..)));
        assert!(publish.now(), "the wait ends");
        assert!(!publish.pending(), "and the caller starts the try");
        assert!(!publish.now(), "once");

        let mut serving: Restarting<u32> = Restarting::idle();
        assert_eq!(serving.failed(), Duration::from_secs(30));
        let armed = tokio::time::Instant::now();
        assert!(matches!(serving.next().await, Restart::Due));
        assert_eq!(armed.elapsed(), Duration::from_secs(30));
    }

    /// B02: what the window shows through a failure and its try. Tor's
    /// failure says what to check in plain words, when the next try comes,
    /// and turns a host's requests off; the try starts from Tor's first step
    /// with the host waiting for it; a publish that failed says so on the
    /// hosting line, and publishing again clears the countdown.
    #[test]
    fn the_model_through_a_failure_and_its_try() {
        let mut m = Model::default();
        tor_failed(&mut m, TOR_DOWN, Duration::from_secs(30), true);
        assert_eq!(m.tor, TorState::Failed(TOR_DOWN.to_owned()));
        let left = m.tor_retry.expect("a try waits") - Instant::now();
        assert!(left <= Duration::from_secs(30) && left > Duration::from_secs(25));
        assert_eq!(m.hosting, Hosting::Off("Tor is not reachable".to_owned()));
        assert!(
            m.events
                .last()
                .is_some_and(|e| e.contains("trying again in 30 s")),
            "{:?}",
            m.events
        );
        tor_retrying(&mut m, true);
        assert_eq!(m.tor, TorState::Starting);
        assert_eq!(m.tor_retry, None);
        assert_eq!(m.hosting, Hosting::Waiting);

        let mut viewer = Model::default();
        tor_failed(&mut viewer, TOR_DOWN, Duration::from_secs(60), false);
        tor_retrying(&mut viewer, false);
        assert_eq!(viewer.hosting, Hosting::Waiting, "not a host: untouched");

        hosting_failed(&mut m, PUBLISH_FAILED, Duration::from_secs(30));
        assert_eq!(m.hosting, Hosting::Off(PUBLISH_FAILED.to_owned()));
        assert!(m.tor_retry.is_some());
        republishing(&mut m);
        assert_eq!(m.hosting, Hosting::Publishing);
        assert_eq!(m.tor_retry, None);
    }

    /// B25: a cancel is recorded at the step the dial had reached, as a
    /// failure is: reaching the computer, pairing (or checking the
    /// password), waiting for approval. Before the fix a cancel recorded
    /// nothing, and the stepper showed every step ticked.
    #[test]
    fn a_cancel_is_recorded_at_its_step() {
        for (stage, step) in [
            (ClientStage::Reaching { id: "x".to_owned() }, 1),
            (
                ClientStage::Pairing {
                    sas: "305 116".to_owned(),
                },
                2,
            ),
            (ClientStage::Checking, 2),
            (ClientStage::Asking, 3),
        ] {
            let mut m = Model {
                client: stage.clone(),
                ..Model::default()
            };
            failed_at_stage(&mut m, Failure::Cancelled);
            assert_eq!(m.dial.failed, Some((Failure::Cancelled, step)), "{stage:?}");
        }
    }

    /// B26: a connect to this computer's own ID ends before anything is
    /// dialled, with the reason and no warning left over, and the stepper
    /// shows no step done.
    #[test]
    fn this_computers_own_id_is_refused() {
        let own = HostIdentity::from_seed(&[0x31; 32]).id();
        let mut m = Model {
            connect_warning: Some(super::super::model::ConnectWarning {
                id: own,
                name: "Linux PC".to_owned(),
            }),
            connect_unchecked: Some(own),
            ..Model::default()
        };
        m.dial.went_live = true;
        own_id_refused(&mut m);
        assert!(matches!(&m.client, ClientStage::Ended(why) if why == OWN_ID));
        assert!(m.connect_warning.is_none() && m.connect_unchecked.is_none());
        assert_eq!(m.dial.id, None);
        assert!(!m.dial.went_live && m.dial.failed.is_none());
    }

    /// B25 review: a connect that ends before anything is dialled (Tor not
    /// up yet, no password) is a dial of its own: after a session that went
    /// live, or a dial that failed, the stepper shows no step done and none
    /// failed, with this ID for Try again.
    #[test]
    fn a_connect_that_dials_nothing_forgets_the_last_dial() {
        let before = HostIdentity::from_seed(&[0x31; 32]).id();
        let now = HostIdentity::from_seed(&[0x32; 32]).id();
        for (unattended, why) in [
            (false, TOR_NOT_YET),
            (true, TOR_NOT_YET),
            (true, NO_PASSWORD),
        ] {
            for (went_live, failed) in [(true, None), (false, Some((Failure::Denied, 3)))] {
                let mut m = Model {
                    dial: Dial {
                        id: Some(before),
                        since: Some(Instant::now()),
                        paired_now: true,
                        failed,
                        unattended: !unattended,
                        went_live,
                    },
                    ..Model::default()
                };
                not_dialled(&mut m, now, unattended, why);
                assert!(matches!(&m.client, ClientStage::Ended(w) if w == why));
                assert_eq!(m.dial.id, Some(now));
                assert_eq!(m.dial.unattended, unattended);
                assert!(!m.dial.went_live && m.dial.failed.is_none() && !m.dial.paired_now);
                assert!(m.dial.since.is_none());
            }
        }
    }

    /// B02: the window's words for a Tor that did not start name no command,
    /// no file and no setting key (the terminal's hint said `tor.bridge_lines`
    /// in config.toml and `tornect doctor`); a ladder with no way in that can
    /// run here gets its own words.
    #[test]
    fn a_tor_failure_is_said_in_plain_words() {
        let offline = anyhow::Error::new(tornect_signal::SignalError::Bootstrap(
            "could not reach the Tor network".to_owned(),
        ));
        assert_eq!(tor_down_words(&offline), TOR_DOWN);
        let none = anyhow::Error::new(tornect_signal::SignalError::Bootstrap("no way".to_owned()))
            .context(NoWayIn);
        assert_eq!(tor_down_words(&none), TOR_NO_WAY);
        for words in [TOR_DOWN, TOR_NO_WAY, PUBLISH_FAILED, SERVICE_STOPPED] {
            for terminal in ["`", "tornect ", "config.toml", "bridge_lines", "https://"] {
                assert!(!words.contains(terminal), "{words:?} says {terminal:?}");
            }
        }
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

    // ------------------------------------------------------------ the grant wizard (§B.8.7.1)

    /// The wizard's *Turn on* for `device` with `password`, as press 1: a
    /// *My machines* grant, the attended precondition waived.
    fn turn_on(device: tornect_core::DeviceId, password: NewPassword) -> GrantRequest {
        GrantRequest {
            attempt: 1,
            choice: WizardChoice {
                device,
                preset: tornect_core::unattended::grant::Preset::MyMachines,
                options: tornect_core::unattended::ipc::GrantOptions {
                    waive_attended_precondition: true,
                    ..Default::default()
                },
            },
            password,
        }
    }

    /// A generated or a chosen password of the wizard (both pass the policy).
    fn generated_pw() -> NewPassword {
        NewPassword::Generated(Secret(zeroize::Zeroizing::new(
            "plaza cubicle ruse ditto unwind".to_owned(),
        )))
    }

    fn chosen_pw() -> NewPassword {
        NewPassword::Chosen(Secret(zeroize::Zeroizing::new(
            "quiet verdant otter lantern 41 cobalt fjord".to_owned(),
        )))
    }

    /// A Windows administrator account of an installed Tornect, UAC on.
    fn windows_admin() -> tornect_core::levels::AccountFacts {
        tornect_core::levels::AccountFacts::Windows(tornect_core::levels::WindowsFacts {
            installed: true,
            administrator: true,
            ..Default::default()
        })
    }

    /// The window host's view of unattended access over a fresh store in
    /// `home`, as [`manager_over`] makes it, with a guard that asks `reauth`,
    /// sees `activity`, reads `facts` and makes a real `ServerSetup` at the
    /// first enable (the wizard runs both halves of the registration).
    fn wizard_watch(
        home: &std::path::Path,
        reauth: Arc<dyn tornect_core::unattended::guard::ReAuth>,
        activity: Arc<dyn tornect_core::unattended::guard::RemoteSessionActivity>,
        facts: Arc<tornect_core::levels::FixedFacts>,
    ) -> ManagerWatch {
        use tornect_core::unattended::guard::{AllowAllPaired, MutationGuard, NoSessionActivity};
        let mut watch = manager_over(
            home,
            Arc::clone(&reauth),
            Arc::new(NoSessionActivity),
            tornect_core::levels::AccountFacts::Linux,
            b"this machine",
        );
        watch.ctx.guard = Arc::new(
            MutationGuard::new(
                watch.ctx.guard.store().clone(),
                reauth,
                activity,
                Arc::clone(&facts) as Arc<dyn tornect_core::levels::FactsSource>,
            )
            .with_paired_devices(Arc::new(AllowAllPaired))
            .with_server_setup_source(Arc::new(
                tornect_signal::unattended::OpaqueServerSetupSource,
            )),
        );
        watch.ctx.facts = facts;
        watch
    }

    /// Linux facts, as a source the tests can change.
    fn linux_facts() -> Arc<tornect_core::levels::FixedFacts> {
        Arc::new(tornect_core::levels::FixedFacts::linux())
    }

    /// §B.8.7.4: one press of the wizard at a time, decided where the
    /// command loop decides it: a second press while one runs, and a press
    /// while a section operation asks for this computer's password, are
    /// answered that another command is changing access, with the running
    /// press unchanged; once the running press is cleared, as *Turn on* and
    /// *Change password* clear it when they end, a press is taken.
    #[test]
    fn one_press_of_the_wizard_at_a_time() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let press = |attempt| {
            let mut taken = false;
            shared.update(|m| taken = take_press(m, attempt));
            taken
        };
        let state = || shared.read(|m| (m.wizard.running, m.wizard.answer));
        let refused = |attempt| Some((attempt, WizardAnswer::Refused(ANOTHER_ASKS)));
        assert!(press(1));
        assert_eq!(state(), (Some(1), None));
        assert!(!press(2), "a second press while one runs");
        assert_eq!(state(), (Some(1), refused(2)));
        shared.update(|m| m.wizard.running = None);
        shared.update(|m| m.manager_busy = true);
        assert!(!press(3), "a press while a section operation asks");
        assert_eq!(state(), (None, refused(3)));
        shared.update(|m| m.manager_busy = false);
        // The wizard's operations clear the running press when they end.
        let tmp = tempfile::tempdir().unwrap();
        let watch = wizard_watch(
            tmp.path(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            linux_facts(),
        );
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        assert!(press(1));
        watch.run(
            ManagerOp::Grant(Box::new(turn_on(device, generated_pw()))),
            &shared,
        );
        assert_eq!(shared.read(|m| m.wizard.running), None, "Turn on ended");
        assert!(press(1), "taken once Turn on ended");
        assert!(!press(2));
        assert_eq!(state(), (Some(1), refused(2)));
        shared.update(|m| m.wizard.running = None);
        assert!(press(1));
        watch.run(
            ManagerOp::ChangePassword(Box::new(turn_on(device, generated_pw()))),
            &shared,
        );
        assert_eq!(
            shared.read(|m| m.wizard.running),
            None,
            "Change password ended"
        );
        assert!(press(4), "taken once Change password ended");
        assert_eq!(state().0, Some(4));
    }

    /// Every password that crosses the window's channel is a `Secret`: a
    /// manager command carrying the wizard's new password prints none of it,
    /// whichever arm it is.
    #[test]
    fn a_manager_command_with_a_password_prints_redacted() {
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        for password in [generated_pw(), chosen_pw()] {
            let command = Command::Manager(ManagerOp::Grant(Box::new(turn_on(device, password))));
            let printed = format!("{command:?}");
            for word in ["plaza", "cubicle", "verdant", "otter"] {
                assert!(!printed.contains(word), "{printed}");
            }
            assert!(printed.contains("<redacted>"), "{printed}");
        }
        for password in [generated_pw(), chosen_pw()] {
            let command = Command::Manager(ManagerOp::ChangePassword(Box::new(turn_on(
                device, password,
            ))));
            let printed = format!("{command:?}");
            for word in ["plaza", "cubicle", "verdant", "otter"] {
                assert!(!printed.contains(word), "{printed}");
            }
            assert!(printed.contains("<redacted>"), "{printed}");
        }
    }

    /// §B.8.6.2, §B.8.7.4: the wizard's *Turn on* asks one dialog per
    /// operation: `reg_start` (its registration; `reg_finish` asks none),
    /// then `master_on` while unattended access was off, with the new stop
    /// code on its one card; with access on, `reg_start` only.
    #[test]
    fn the_wizard_asks_one_dialog_per_operation() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            linux_facts(),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let (one, two) = (
            tornect_core::DeviceId::from_bytes([1; 32]),
            tornect_core::DeviceId::from_bytes([2; 32]),
        );
        watch.wizard_grant(turn_on(one, generated_pw()), &shared);
        assert_eq!(reauth.calls(), ["reg_start", "master_on"]);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((1, WizardAnswer::Done))
        );
        assert!(
            shared.read(|m| m.stop_card.is_some()),
            "the stop code's card"
        );
        let store = watch.ctx.guard.store();
        assert!(store.read(|s| s.enabled).unwrap());
        assert!(store.grant(&one).is_some());
        // Access on: one dialog, no new stop code.
        shared.update(|m| m.stop_card = None);
        watch.wizard_grant(turn_on(two, generated_pw()), &shared);
        assert_eq!(reauth.calls(), ["reg_start", "master_on", "reg_start"]);
        assert!(shared.read(|m| m.stop_card.is_none()));
        assert!(store.grant(&two).is_some());
        let view = shared.read(|m| m.manager.clone()).expect("read again");
        assert_eq!(view.grants.len(), 2);
    }

    /// Decision M1-67: the tokio side registers the wizard's password as
    /// generated exactly when it is the generator's arm: a chosen password
    /// leaves the grant marked, a generated one does not.
    #[test]
    fn only_a_generated_password_registers_as_generated() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let watch = wizard_watch(
            tmp.path(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            linux_facts(),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let (one, two) = (
            tornect_core::DeviceId::from_bytes([1; 32]),
            tornect_core::DeviceId::from_bytes([2; 32]),
        );
        watch.wizard_grant(turn_on(one, chosen_pw()), &shared);
        watch.wizard_grant(turn_on(two, generated_pw()), &shared);
        let store = watch.ctx.guard.store();
        assert!(store.grant(&one).unwrap().marked(), "chosen: marked");
        assert!(!store.grant(&two).unwrap().marked(), "generated: unmarked");
    }

    /// The administrator helper task registers while the person answers the
    /// dialog (`RegStart`'s): control here now reaches the level.
    struct TaskDuringDialog {
        facts: Arc<tornect_core::levels::FixedFacts>,
        asked: Mutex<Vec<String>>,
    }

    impl tornect_core::unattended::guard::ReAuth for TaskDuringDialog {
        fn reauthenticate(
            &self,
            op: &str,
        ) -> Result<(), tornect_core::unattended::guard::ReAuthError> {
            self.asked.lock().unwrap().push(op.to_owned());
            self.facts
                .set_helper_task(tornect_core::levels::HelperPresence::Registered);
            Ok(())
        }
    }

    /// Decision M1-67: a raise that appears while the person is asked
    /// (the helper task registered meanwhile, so the new control grant now
    /// reaches the level) is refused at `RegFinish`, a chosen password and a
    /// generated one alike: the answer says so, no grant is written, and
    /// unattended access stays off (no second dialog).
    #[test]
    fn a_raise_that_appeared_meanwhile_is_refused_and_written_nowhere() {
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::unattended::guard::NoSessionActivity;
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        for password in [chosen_pw(), generated_pw()] {
            let tmp = tempfile::tempdir().unwrap();
            let facts = Arc::new(FixedFacts::new(windows_admin(), HelperPresence::Absent));
            let reauth = Arc::new(TaskDuringDialog {
                facts: Arc::clone(&facts),
                asked: Mutex::new(Vec::new()),
            });
            let watch = wizard_watch(
                tmp.path(),
                Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
                Arc::new(NoSessionActivity),
                Arc::clone(&facts),
            );
            let preview = watch
                .ctx
                .guard
                .preview(
                    &device,
                    tornect_core::unattended::grant::Preset::MyMachines,
                    &turn_on(device, chosen_pw()).choice.options,
                )
                .unwrap();
            assert!(!preview.generated_only(), "at the click: reach 0");
            let shared = Shared::new(Model::default(), Arc::new(|_| {}));
            watch.wizard_grant(turn_on(device, password), &shared);
            assert_eq!(
                shared.read(|m| m.wizard.answer),
                Some((1, WizardAnswer::NeedsGenerated))
            );
            let store = watch.ctx.guard.store();
            assert!(store.grant(&device).is_none(), "written nowhere");
            assert!(!store.read(|s| s.enabled).unwrap_or(false), "still off");
            assert_eq!(*reauth.asked.lock().unwrap(), ["reg_start"]);
            assert!(shared.read(|m| m.stop_card.is_none()));
        }
    }

    /// Decision M1-67: where control is administrator access (UAC off) the
    /// wizard's Turn on with a chosen password is refused before any dialog,
    /// the guard's preview judging the store the first enable creates, and no
    /// store is created; with a generated password the raising dialog and
    /// Turn on's follow, and the new grant is unmarked: the preview and the
    /// commit agree on a store that did not exist yet.
    #[test]
    fn a_chosen_password_where_the_reach_is_non_zero_asks_nothing() {
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let uac_off =
            tornect_core::levels::AccountFacts::Windows(tornect_core::levels::WindowsFacts {
                installed: true,
                administrator: true,
                enable_lua: Some(0),
                ..Default::default()
            });
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            Arc::new(FixedFacts::new(uac_off, HelperPresence::Absent)),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        watch.wizard_grant(turn_on(device, chosen_pw()), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((1, WizardAnswer::NeedsGenerated))
        );
        assert!(reauth.calls().is_empty(), "no dialog");
        let paths = Paths::from_home(tmp.path());
        assert!(!paths.unattended_store().exists(), "no store created");
        let mut generated = turn_on(device, generated_pw());
        generated.attempt = 2;
        watch.wizard_grant(generated, &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((2, WizardAnswer::Done))
        );
        assert_eq!(reauth.calls(), ["raise", "master_on"]);
        let grant = watch.ctx.guard.store().grant(&device).expect("given");
        assert!(!grant.marked(), "generated: unmarked");
    }

    /// §B.8.7.2: a chosen password that does not meet the policy (here, on a
    /// file keystore, too easy to guess) is refused by the tokio side too,
    /// before any dialog: nothing is written and no store is created.
    #[test]
    fn a_weak_chosen_password_is_refused_before_any_dialog() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            linux_facts(),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        let weak = NewPassword::Chosen(Secret(zeroize::Zeroizing::new("password1234".to_owned())));
        watch.wizard_grant(turn_on(device, weak), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((1, WizardAnswer::Refused(NOT_THE_POLICY)))
        );
        assert!(reauth.calls().is_empty(), "no dialog");
        assert!(watch.ctx.guard.store().grant(&device).is_none());
        assert!(!Paths::from_home(tmp.path()).unattended_store().exists());
    }

    /// The manager's *Change password* of `device`'s grant as press
    /// `attempt`: the options change nothing (or the mode only).
    fn change(
        device: tornect_core::DeviceId,
        mode: Option<SessionMode>,
        password: NewPassword,
        attempt: u64,
    ) -> GrantRequest {
        GrantRequest {
            attempt,
            choice: WizardChoice {
                device,
                preset: tornect_core::unattended::grant::Preset::MyMachines,
                options: tornect_core::unattended::ipc::GrantOptions {
                    mode,
                    ..Default::default()
                },
            },
            password,
        }
    }

    /// §B.8.7.3, decision M1-67: *Change password* from the manager is one
    /// registration through the window's own password change (its one
    /// dialog): a chosen password leaves the grant marked and a generated one
    /// clears the mark; the grant's mode and preset stay.
    #[test]
    fn change_password_keeps_the_mark_for_a_chosen_password() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            linux_facts(),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        watch.wizard_grant(turn_on(device, generated_pw()), &shared);
        let store = watch.ctx.guard.store();
        let before = store.grant(&device).unwrap();
        assert!(!before.marked());
        watch.change_password(change(device, None, chosen_pw(), 2), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((2, WizardAnswer::Done))
        );
        let after = store.grant(&device).unwrap();
        assert!(after.marked(), "chosen: marked");
        assert_ne!(after.auth, before.auth, "a new password");
        assert_eq!((after.mode, after.preset), (before.mode, before.preset));
        watch.change_password(change(device, None, generated_pw(), 3), &shared);
        assert!(
            !store.grant(&device).unwrap().marked(),
            "generated: unmarked"
        );
        assert_eq!(
            reauth.calls(),
            ["reg_start", "master_on", "set_password", "set_password"]
        );
    }

    /// §B.8.7.3: *Change mode* to view only is one operation that narrows,
    /// with no dialog; back to control, where control reaches nothing more,
    /// one that widens, with its one dialog.
    #[test]
    fn mode_to_view_only_runs_one_set_options() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            linux_facts(),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        watch.wizard_grant(turn_on(device, generated_pw()), &shared);
        let store = watch.ctx.guard.store();
        let asked = reauth.calls().len();
        watch.run(ManagerOp::SetMode(device, SessionMode::ViewOnly), &shared);
        assert_eq!(store.grant(&device).unwrap().mode, SessionMode::ViewOnly);
        assert_eq!(reauth.calls().len(), asked, "no dialog");
        assert_eq!(shared.read(|m| m.manager_note), None);
        assert!(
            shared
                .read(|m| m.wizard.modes.clone())
                .contains(&(device, SessionMode::ViewOnly)),
            "the view read again"
        );
        watch.run(ManagerOp::SetMode(device, SessionMode::Control), &shared);
        assert_eq!(store.grant(&device).unwrap().mode, SessionMode::Control);
        assert_eq!(
            reauth.calls().last().map(String::as_str),
            Some("set_options")
        );
    }

    /// Decision M1-67: where control reaches the administrator level (UAC
    /// off), *Change mode* of a view-only grant to control by `set_options`
    /// is refused (in plain words, nothing changed), a chosen password with
    /// the mode is refused before any dialog, and a generated one carries the
    /// mode in one registration with the raising dialog.
    #[test]
    fn mode_to_control_at_the_level_registers_with_a_new_password() {
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let uac_off =
            tornect_core::levels::AccountFacts::Windows(tornect_core::levels::WindowsFacts {
                installed: true,
                administrator: true,
                enable_lua: Some(0),
                ..Default::default()
            });
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            Arc::new(FixedFacts::new(uac_off, HelperPresence::Absent)),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        let mut helping = turn_on(device, generated_pw());
        helping.choice.preset = tornect_core::unattended::grant::Preset::HelpingSomeone;
        watch.wizard_grant(helping, &shared);
        let store = watch.ctx.guard.store();
        assert_eq!(store.grant(&device).unwrap().mode, SessionMode::ViewOnly);
        watch.run(ManagerOp::SetMode(device, SessionMode::Control), &shared);
        assert_eq!(shared.read(|m| m.manager_note), Some(MODE_NEEDS));
        assert_eq!(store.grant(&device).unwrap().mode, SessionMode::ViewOnly);
        let asked = reauth.calls().len();
        watch.change_password(
            change(device, Some(SessionMode::Control), chosen_pw(), 2),
            &shared,
        );
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((2, WizardAnswer::NeedsGenerated))
        );
        assert_eq!(reauth.calls().len(), asked, "no dialog");
        watch.change_password(
            change(device, Some(SessionMode::Control), generated_pw(), 3),
            &shared,
        );
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((3, WizardAnswer::Done))
        );
        let grant = store.grant(&device).unwrap();
        assert_eq!(grant.mode, SessionMode::Control);
        assert!(!grant.marked());
        assert_eq!(reauth.calls().last().map(String::as_str), Some("raise"));
    }

    /// §B.8.6.2: during a remote session (and 60 s after one) the wizard's
    /// *Turn on* is refused in plain words before any dialog: nothing is
    /// written, access stays off, no stop code, no success.
    #[test]
    fn the_wizard_waits_for_the_remote_session_rule() {
        use tornect_core::unattended::guard::{AllowAllReAuth, ScriptedActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let activity = Arc::new(ScriptedActivity::default());
        activity.set_live(true);
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::clone(&activity)
                as Arc<dyn tornect_core::unattended::guard::RemoteSessionActivity>,
            linux_facts(),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        watch.wizard_grant(turn_on(device, generated_pw()), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((
                1,
                WizardAnswer::Refused(
                    "Not done: a remote session is running, or ended less than a minute ago."
                )
            ))
        );
        assert!(reauth.calls().is_empty(), "no dialog");
        assert!(watch.ctx.guard.store().grant(&device).is_none());
        assert!(shared.read(|m| m.stop_card.is_none() && m.wizard.running.is_none()));
    }

    /// The wizard's devices (§B.8.7.1 ②): the host's paired devices without
    /// a grant, each saying whether an attended session from it completed,
    /// with the policy's inputs; the section's offer follows the view.
    #[test]
    fn the_wizard_lists_the_paired_devices_without_access() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let (one, two) = (
            tornect_core::DeviceId::from_bytes([1; 32]),
            tornect_core::DeviceId::from_bytes([2; 32]),
        );
        let trusted = TrustedDeviceStore::ephemeral(Default::default());
        trusted.pin(one, "Office laptop").unwrap();
        trusted.pin(two, "Tablet").unwrap();
        let watch = ManagerWatch {
            trusted: Arc::new(trusted),
            ..wizard_watch(
                tmp.path(),
                Arc::new(AllowAllReAuth::default()),
                Arc::new(NoSessionActivity),
                linux_facts(),
            )
        };
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.refresh(&shared);
        assert_eq!(shared.read(|m| m.wizard.offer), Some(true));
        watch.wizard_devices(&shared);
        let devices = shared.read(|m| m.wizard.devices.clone()).unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices.iter().all(|c| !c.attended), "no session yet");
        assert!(shared.read(|m| m.wizard.policy.is_some()));
        watch.wizard_grant(turn_on(one, generated_pw()), &shared);
        watch.wizard_devices(&shared);
        let devices = shared.read(|m| m.wizard.devices.clone()).unwrap();
        assert_eq!(devices.iter().map(|c| c.device).collect::<Vec<_>>(), [two]);
        watch.wizard_grant(turn_on(two, generated_pw()), &shared);
        assert_eq!(shared.read(|m| m.wizard.offer), Some(false), "none left");
    }

    /// With no device to offer, the view tells "no device is paired" from
    /// "every paired device already has unattended access".
    #[test]
    fn no_device_to_offer_says_which_case() {
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let one = tornect_core::DeviceId::from_bytes([1; 32]);
        let watch = ManagerWatch {
            trusted: Arc::new(TrustedDeviceStore::ephemeral(Default::default())),
            ..wizard_watch(
                tmp.path(),
                Arc::new(AllowAllReAuth::default()),
                Arc::new(NoSessionActivity),
                linux_facts(),
            )
        };
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let offer = || shared.read(|m| (m.wizard.offer, m.wizard.all_granted));
        watch.refresh(&shared);
        assert_eq!(offer(), (Some(false), false), "no device is paired");
        watch.trusted.pin(one, "Office laptop").unwrap();
        watch.refresh(&shared);
        assert_eq!(offer(), (Some(true), false));
        watch.wizard_grant(turn_on(one, generated_pw()), &shared);
        assert_eq!(
            offer(),
            (Some(false), true),
            "every paired device has access"
        );
    }

    // ------------------------------------------------------------ ⑤a (§B.8.7.1)

    /// The wizard's *Turn on* as press `attempt` for `device`, `preset`, with
    /// the administrator level, the attended precondition waived.
    fn with_level(
        attempt: u64,
        device: tornect_core::DeviceId,
        preset: tornect_core::unattended::grant::Preset,
        password: NewPassword,
    ) -> GrantRequest {
        GrantRequest {
            attempt,
            choice: WizardChoice {
                device,
                preset,
                options: tornect_core::unattended::ipc::GrantOptions {
                    waive_attended_precondition: true,
                    elevation: Some(Elevation::Admin),
                    ..Default::default()
                },
            },
            password,
        }
    }

    /// Decision M1-67, §B.8.7.1 ⑤a: on an installed Tornect of a Windows
    /// administrator account the wizard's grant with the level and a chosen
    /// password is refused before any dialog, and nothing is written; with a
    /// generated one it is one raising dialog (then Turn on's), and the grant
    /// holds the level with its password unmarked. The wizard opened reads
    /// the guard's account facts.
    #[test]
    fn an_administrator_grant_is_created_only_with_a_generated_password() {
        use tornect_core::levels::{FactsSource, FixedFacts, HelperPresence};
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let facts = Arc::new(FixedFacts::new(windows_admin(), HelperPresence::Absent));
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            Arc::clone(&facts),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.wizard_devices(&shared);
        assert_eq!(shared.read(|m| m.wizard.account), Some(windows_admin()));
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        watch.wizard_grant(
            with_level(1, device, Preset::MyMachines, chosen_pw()),
            &shared,
        );
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((1, WizardAnswer::NeedsGenerated))
        );
        assert!(reauth.calls().is_empty(), "no dialog");
        assert!(watch.ctx.guard.store().grant(&device).is_none());
        watch.wizard_grant(
            with_level(2, device, Preset::MyMachines, generated_pw()),
            &shared,
        );
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((2, WizardAnswer::Done))
        );
        assert_eq!(reauth.calls(), ["raise", "master_on"]);
        let grant = watch.ctx.guard.store().grant(&device).expect("given");
        assert!(grant.holds_level(), "the level");
        assert!(!grant.marked(), "generated: unmarked");
        assert_eq!(facts.helper_task(), HelperPresence::Absent);
    }

    /// The guard's refusal of the level as the wizard learns it: the preview
    /// of `request`'s choice puts the plan's sentence into the model, and its
    /// Turn on is refused in it before any dialog, nothing written.
    fn refused_with(
        account: tornect_core::levels::AccountFacts,
        request: GrantRequest,
        why: &'static str,
    ) {
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            Arc::new(FixedFacts::new(account, HelperPresence::Absent)),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.wizard_preview(request.choice.clone(), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.level_refused.clone()),
            Some((request.choice.clone(), why))
        );
        let device = request.choice.device;
        watch.wizard_grant(request, &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((1, WizardAnswer::Refused(why)))
        );
        assert!(reauth.calls().is_empty(), "{why}: no dialog");
        assert!(watch.ctx.guard.store().grant(&device).is_none(), "{why}");
    }

    /// §B.8.7.4: a standard account and a copy outside Program Files cannot
    /// give the level: the step learns the guard's reason, and a grant with
    /// the level is refused in it.
    #[test]
    fn a_standard_account_or_portable_copy_is_refused_with_its_reason() {
        use tornect_core::levels::{
            AccountFacts, REFUSAL_ADMIN_STANDALONE, REFUSAL_ADMIN_STANDARD_ACCOUNT, WindowsFacts,
        };
        use tornect_core::unattended::grant::Preset;
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        let standard = AccountFacts::Windows(WindowsFacts {
            installed: true,
            ..Default::default()
        });
        let portable = AccountFacts::Windows(WindowsFacts {
            administrator: true,
            ..Default::default()
        });
        for (account, why) in [
            (standard, REFUSAL_ADMIN_STANDARD_ACCOUNT),
            (portable, REFUSAL_ADMIN_STANDALONE),
        ] {
            refused_with(
                account,
                with_level(1, device, Preset::MyMachines, generated_pw()),
                why,
            );
        }
    }

    /// §B.8.7.1 ⑤a: *Helping someone* refuses the level, on an account that
    /// could give it otherwise.
    #[test]
    fn helping_someone_refuses_the_administrator_step() {
        use tornect_core::levels::REFUSAL_ADMIN_HELPING_SOMEONE;
        use tornect_core::unattended::grant::Preset;
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        refused_with(
            windows_admin(),
            with_level(1, device, Preset::HelpingSomeone, generated_pw()),
            REFUSAL_ADMIN_HELPING_SOMEONE,
        );
    }

    /// §B.8.6.2: a grant with the level is access-increasing: refused during
    /// and within a minute after a remote session, before any dialog, and
    /// nothing is written.
    #[test]
    fn the_administrator_step_waits_for_the_remote_session_rule() {
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{AllowAllReAuth, ScriptedActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let activity = Arc::new(ScriptedActivity::default());
        activity.set_live(true);
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::clone(&activity)
                as Arc<dyn tornect_core::unattended::guard::RemoteSessionActivity>,
            Arc::new(FixedFacts::new(windows_admin(), HelperPresence::Absent)),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        watch.wizard_grant(
            with_level(1, device, Preset::MyMachines, generated_pw()),
            &shared,
        );
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((
                1,
                WizardAnswer::Refused(
                    "Not done: a remote session is running, or ended less than a minute ago."
                )
            ))
        );
        assert!(reauth.calls().is_empty(), "no dialog");
        assert!(watch.ctx.guard.store().grant(&device).is_none());
    }

    // ------------------------------------------------------------ the raise and the restore (§B.8.7.1)

    /// The manager's raise of `device`'s grant to the administrator level
    /// with `password`, as press `attempt`.
    fn raise(attempt: u64, device: tornect_core::DeviceId, password: NewPassword) -> GrantRequest {
        GrantRequest {
            attempt,
            choice: WizardChoice {
                device,
                preset: tornect_core::unattended::grant::Preset::MyMachines,
                options: tornect_core::unattended::ipc::GrantOptions {
                    elevation: Some(Elevation::Admin),
                    ..Default::default()
                },
            },
            password,
        }
    }

    /// Decision M1-67: the manager's raise is one registration with a
    /// generated password: a chosen one is refused before any dialog and the
    /// grant keeps no level; the level by an options change alone is refused
    /// by the guard; a generated one asks once, with the raising wording, and
    /// the grant holds the level, its password unmarked.
    #[test]
    fn a_raise_registers_the_level_with_a_generated_password_only() {
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::guard::{AllowAllReAuth, GuardError, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            Arc::new(FixedFacts::new(windows_admin(), HelperPresence::Absent)),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        watch.wizard_grant(turn_on(device, generated_pw()), &shared);
        assert_eq!(reauth.calls(), ["reg_start", "master_on"]);
        watch.change_password(raise(2, device, chosen_pw()), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((2, WizardAnswer::NeedsGenerated))
        );
        assert_eq!(reauth.calls(), ["reg_start", "master_on"], "no dialog");
        let store = watch.ctx.guard.store();
        assert!(!store.grant(&device).unwrap().holds_level());
        let level_alone = watch.ctx.guard.set_options(
            Actor::Ui,
            &device,
            &raise(3, device, generated_pw()).choice.options,
        );
        assert!(
            matches!(level_alone, Err(GuardError::NeedsPassword(_))),
            "{level_alone:?}"
        );
        assert!(!store.grant(&device).unwrap().holds_level());
        watch.change_password(raise(4, device, generated_pw()), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((4, WizardAnswer::Done))
        );
        assert_eq!(reauth.calls().last().map(String::as_str), Some("raise"));
        let grant = store.grant(&device).unwrap();
        assert!(grant.holds_level() && !grant.marked());
        let levels = shared.read(|m| m.wizard.levels.clone());
        assert_eq!(
            levels
                .iter()
                .find(|(d, _)| *d == device)
                .map(|(_, l)| l.holds),
            Some(true),
            "the view reads the level"
        );
    }

    /// The window host's view over the store in `home` as on the machine
    /// `machine` (another machine id: a restored state), with a guard that
    /// asks `reauth`, reads `facts` and makes a real `ServerSetup`.
    fn watch_on_machine(
        home: &std::path::Path,
        reauth: Arc<dyn tornect_core::unattended::guard::ReAuth>,
        facts: Arc<tornect_core::levels::FixedFacts>,
        machine: &[u8],
    ) -> ManagerWatch {
        use tornect_core::unattended::guard::{AllowAllPaired, MutationGuard, NoSessionActivity};
        let mut watch = manager_over(
            home,
            Arc::clone(&reauth),
            Arc::new(NoSessionActivity),
            tornect_core::levels::AccountFacts::Linux,
            machine,
        );
        watch.ctx.guard = Arc::new(
            MutationGuard::new(
                watch.ctx.guard.store().clone(),
                reauth,
                Arc::new(NoSessionActivity),
                Arc::clone(&facts) as Arc<dyn tornect_core::levels::FactsSource>,
            )
            .with_paired_devices(Arc::new(AllowAllPaired))
            .with_server_setup_source(Arc::new(
                tornect_signal::unattended::OpaqueServerSetupSource,
            )),
        );
        watch.ctx.facts = facts;
        watch
    }

    /// §B.8.6.1, decision M1-67: a grant at the level restored on another
    /// machine is disabled and marked; the restore gives it a new generated
    /// password (one dialog), then enables it (its own), and it is active and
    /// unmarked; a chosen password is refused before any dialog; a refused
    /// password dialog leaves it disabled and marked, and no enable is asked.
    #[test]
    fn a_restored_grant_is_enabled_after_its_new_password() {
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::unattended::grant::{GrantState, Preset};
        use tornect_core::unattended::guard::{AllowAllReAuth, DenyAllReAuth};
        let tmp = tempfile::tempdir().unwrap();
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        let facts = || Arc::new(FixedFacts::new(windows_admin(), HelperPresence::Absent));
        {
            let watch = watch_on_machine(
                tmp.path(),
                Arc::new(AllowAllReAuth::default()),
                facts(),
                b"the first machine",
            );
            let shared = Shared::new(Model::default(), Arc::new(|_| {}));
            watch.wizard_grant(
                with_level(1, device, Preset::MyMachines, generated_pw()),
                &shared,
            );
            assert_eq!(
                shared.read(|m| m.wizard.answer),
                Some((1, WizardAnswer::Done))
            );
        }
        let restore = |attempt, password| GrantRequest {
            attempt,
            choice: WizardChoice {
                device,
                preset: Preset::MyMachines,
                options: tornect_core::unattended::ipc::GrantOptions::default(),
            },
            password,
        };
        let denied = watch_on_machine(
            tmp.path(),
            Arc::new(DenyAllReAuth),
            facts(),
            b"another machine",
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let grant = denied.ctx.guard.store().grant(&device).unwrap();
        assert!(grant.holds_level() && grant.marked(), "restored: marked");
        denied.restore(restore(2, generated_pw()), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((
                2,
                WizardAnswer::Refused("Not done: this computer's password was not confirmed.")
            ))
        );
        let grant = denied.ctx.guard.store().grant(&device).unwrap();
        assert!(grant.marked(), "unchanged");
        assert!(
            matches!(grant.state, GrantState::Disabled { .. }),
            "{:?}",
            grant.state
        );
        drop(denied);
        let reauth = Arc::new(AllowAllReAuth::default());
        let watch = watch_on_machine(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            facts(),
            b"another machine",
        );
        watch.restore(restore(3, chosen_pw()), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((3, WizardAnswer::NeedsGenerated))
        );
        assert!(reauth.calls().is_empty(), "no dialog");
        watch.restore(restore(4, generated_pw()), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((4, WizardAnswer::Done))
        );
        assert_eq!(reauth.calls(), ["set_password", "enable"]);
        let grant = watch.ctx.guard.store().grant(&device).unwrap();
        assert!(!grant.marked(), "a new generated password");
        assert!(
            matches!(grant.state, GrantState::Active),
            "{:?}",
            grant.state
        );
    }

    /// §B.8.6.1: a restore whose new password is set but whose *Enable* is
    /// refused answers so: the grant keeps the new password (unmarked) and
    /// stays disabled.
    #[test]
    fn a_restore_whose_enable_is_refused_keeps_the_new_password() {
        use crate::test_support::ReAuthSequence;
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::unattended::grant::{GrantState, Preset};
        use tornect_core::unattended::guard::AllowAllReAuth;
        let tmp = tempfile::tempdir().unwrap();
        let device = tornect_core::DeviceId::from_bytes([1; 32]);
        let facts = || Arc::new(FixedFacts::new(windows_admin(), HelperPresence::Absent));
        {
            let watch = watch_on_machine(
                tmp.path(),
                Arc::new(AllowAllReAuth::default()),
                facts(),
                b"the first machine",
            );
            let shared = Shared::new(Model::default(), Arc::new(|_| {}));
            watch.wizard_grant(
                with_level(1, device, Preset::MyMachines, generated_pw()),
                &shared,
            );
            assert_eq!(
                shared.read(|m| m.wizard.answer),
                Some((1, WizardAnswer::Done))
            );
        }
        let reauth = Arc::new(ReAuthSequence::new(&[true, false]));
        let watch = watch_on_machine(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            facts(),
            b"another machine",
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        watch.restore(
            GrantRequest {
                attempt: 2,
                choice: WizardChoice {
                    device,
                    preset: Preset::MyMachines,
                    options: tornect_core::unattended::ipc::GrantOptions::default(),
                },
                password: generated_pw(),
            },
            &shared,
        );
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((2, WizardAnswer::SetNotEnabled))
        );
        assert_eq!(reauth.calls(), ["set_password", "enable"]);
        let grant = watch.ctx.guard.store().grant(&device).unwrap();
        assert!(!grant.marked(), "the new password is set");
        assert!(
            matches!(grant.state, GrantState::Disabled { .. }),
            "{:?}",
            grant.state
        );
    }

    // ------------------------------------------------------------ ⑤a's offer (§B.8.7.1)

    /// Decision M1-67: an answer that gave access names the other control
    /// grants the change made reach the administrator level, with their
    /// pinned labels and marks, as its preview listed them; a change that
    /// made none reach it names none.
    #[test]
    fn a_new_admin_grant_names_the_control_grants_it_makes_reach() {
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{AllowAllReAuth, NewlyReaching, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let watch = wizard_watch(
            tmp.path(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::new(FixedFacts::new(windows_admin(), HelperPresence::Absent)),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let [one, two, three] = [1, 2, 3].map(|b| tornect_core::DeviceId::from_bytes([b; 32]));
        watch.wizard_grant(turn_on(one, generated_pw()), &shared);
        assert!(
            shared.read(|m| m.wizard.reaching.is_empty()),
            "reaches nothing"
        );
        let mut chosen = turn_on(two, chosen_pw());
        chosen.attempt = 2;
        watch.wizard_grant(chosen, &shared);
        watch.wizard_grant(
            with_level(3, three, Preset::MyMachines, generated_pw()),
            &shared,
        );
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((3, WizardAnswer::Done))
        );
        let store = watch.ctx.guard.store();
        let named = |device| NewlyReaching {
            device,
            label: store.grant(&device).unwrap().label.clone(),
            marked: store.grant(&device).unwrap().marked(),
        };
        assert_eq!(
            shared.read(|m| m.wizard.reaching.clone()),
            [named(one), named(two)]
        );
        assert!(named(two).marked && !named(one).marked);
    }

    /// §B.8.7.1: each of the offer's new passwords is its own registration
    /// and dialog: with the first confirmed and the second refused, the first
    /// device gets its new generated password (its mark goes), the second
    /// keeps its old one (still marked), and the answer says why.
    #[test]
    fn each_offer_prompt_is_its_own_registration_and_dialog() {
        use crate::test_support::ReAuthSequence;
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::NoSessionActivity;
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(ReAuthSequence::new(&[true, true, true, true, true, false]));
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            Arc::new(FixedFacts::new(windows_admin(), HelperPresence::Absent)),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let [one, two, three] = [1, 2, 3].map(|b| tornect_core::DeviceId::from_bytes([b; 32]));
        watch.wizard_grant(turn_on(one, chosen_pw()), &shared);
        let mut chosen = turn_on(two, chosen_pw());
        chosen.attempt = 2;
        watch.wizard_grant(chosen, &shared);
        watch.wizard_grant(
            with_level(3, three, Preset::MyMachines, generated_pw()),
            &shared,
        );
        let listed: Vec<_> = shared.read(|m| {
            m.wizard
                .reaching
                .iter()
                .map(|d| (d.device, d.marked))
                .collect()
        });
        assert_eq!(listed, [(one, true), (two, true)]);
        let renew = |attempt, device| GrantRequest {
            attempt,
            choice: WizardChoice {
                device,
                preset: Preset::MyMachines,
                options: tornect_core::unattended::ipc::GrantOptions::default(),
            },
            password: generated_pw(),
        };
        watch.change_password(renew(4, one), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((4, WizardAnswer::Done))
        );
        watch.change_password(renew(5, two), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((
                5,
                WizardAnswer::Refused("Not done: this computer's password was not confirmed.")
            ))
        );
        assert_eq!(
            reauth.calls(),
            [
                "reg_start",
                "master_on",
                "reg_start",
                "raise",
                "set_password",
                "set_password"
            ]
        );
        let store = watch.ctx.guard.store();
        assert!(!store.grant(&one).unwrap().marked(), "its new password");
        assert!(store.grant(&two).unwrap().marked(), "its old password");
    }

    // ------------------------------------------------------------ the turn-off (§B.8.7.1 ⑤a)

    /// §B.8.6.2, decision M1-68: turning the administrator level off is
    /// deny-direction: no dialog, also during a remote session; the grant
    /// keeps control without the level, and the answer says which clause of
    /// the turn-off sentence's condition holds: another grant at the level,
    /// then, once that one is off too, nothing.
    #[test]
    fn turning_the_level_off_asks_no_reauth() {
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{AllowAllReAuth, ScriptedActivity};
        use tornect_core::unattended::ipc::SetLevelNonePayload;
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let activity = Arc::new(ScriptedActivity::default());
        let watch = wizard_watch(
            tmp.path(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::clone(&activity)
                as Arc<dyn tornect_core::unattended::guard::RemoteSessionActivity>,
            Arc::new(FixedFacts::new(windows_admin(), HelperPresence::Absent)),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let [one, two] = [1, 2].map(|b| tornect_core::DeviceId::from_bytes([b; 32]));
        for (attempt, device) in [(1, one), (2, two)] {
            watch.wizard_grant(
                with_level(attempt, device, Preset::MyMachines, generated_pw()),
                &shared,
            );
            assert_eq!(
                shared.read(|m| m.wizard.answer),
                Some((attempt, WizardAnswer::Done))
            );
        }
        let asked = reauth.calls();
        activity.set_live(true);
        let store = watch.ctx.guard.store();
        watch.run(ManagerOp::LevelOff(one), &shared);
        assert_eq!(reauth.calls(), asked, "no dialog");
        let grant = store.grant(&one).unwrap();
        assert!(!grant.holds_level());
        assert_eq!(grant.mode, SessionMode::Control, "control kept");
        assert_eq!(
            shared.read(|m| m.wizard.level_off),
            Some((one, SetLevelNonePayload::ANOTHER_ADMIN_GRANT))
        );
        assert_eq!(shared.read(|m| m.manager_note), None);
        watch.run(ManagerOp::LevelOff(two), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.level_off),
            Some((two, SetLevelNonePayload::NOTHING))
        );
        assert!(!store.grant(&two).unwrap().holds_level());
        assert_eq!(reauth.calls(), asked, "no dialog");
    }

    /// The turn-off's lines go once they stop being true: a raise of the
    /// device (the view then reads its grant at the level), a change made
    /// elsewhere that the view reads next (the grant disabled), and the next
    /// operation of the section.
    #[test]
    fn the_turn_off_lines_go_when_they_stop_being_true() {
        use tornect_core::levels::{FixedFacts, HelperPresence};
        use tornect_core::session_log::Actor;
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let watch = wizard_watch(
            tmp.path(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::new(FixedFacts::new(windows_admin(), HelperPresence::Absent)),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let [one, two] = [1, 2].map(|b| tornect_core::DeviceId::from_bytes([b; 32]));
        for (attempt, device) in [(1, one), (2, two)] {
            watch.wizard_grant(
                with_level(attempt, device, Preset::MyMachines, generated_pw()),
                &shared,
            );
        }
        // Turned off, then raised again.
        watch.run(ManagerOp::LevelOff(one), &shared);
        assert!(shared.read(|m| m.wizard.level_off).is_some());
        watch.change_password(raise(3, one, generated_pw()), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.answer),
            Some((3, WizardAnswer::Done))
        );
        assert!(watch.ctx.guard.store().grant(&one).unwrap().holds_level());
        assert_eq!(shared.read(|m| m.wizard.level_off), None, "raised");
        // Turned off, then disabled from the command line.
        watch.run(ManagerOp::LevelOff(two), &shared);
        assert!(shared.read(|m| m.wizard.level_off).is_some());
        watch.ctx.guard.disable(Actor::Cli, &two).unwrap();
        watch.refresh(&shared);
        assert_eq!(shared.read(|m| m.wizard.level_off), None, "disabled");
        // Turned off, then the section's next operation.
        watch.run(ManagerOp::LevelOff(one), &shared);
        assert!(shared.read(|m| m.wizard.level_off).is_some());
        watch.run(ManagerOp::Setting(HostSetting::Notify(true)), &shared);
        assert_eq!(
            shared.read(|m| m.wizard.level_off),
            None,
            "the next operation"
        );
    }

    // ------------------------------------------------------------ the device cards (§B.8.6.1)

    /// §B.8.6.1, decision M1-67: the device cards' lines follow the levels'
    /// own rules on the account's facts now: on a Windows administrator
    /// account (UAC on) a control grant with a chosen, so marked, password
    /// beside a grant at the level is view only until it gets a new password;
    /// with UAC off it is view only for the account's settings; the grant at
    /// the level with its generated password has no line, and on Linux none
    /// has. The count is the session log's, and reading it writes nothing.
    #[test]
    fn the_device_cards_follow_the_levels_rules() {
        use tornect_core::levels::{AccountFacts, FixedFacts, HelperPresence, WindowsFacts};
        use tornect_core::session_log::{SessionEvent, SessionRecord};
        use tornect_core::unattended::grant::Preset;
        use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
        let tmp = tempfile::tempdir().unwrap();
        let facts = Arc::new(FixedFacts::new(windows_admin(), HelperPresence::Absent));
        let watch = wizard_watch(
            tmp.path(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            Arc::clone(&facts),
        );
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let [one, two] = [1, 2].map(|b| tornect_core::DeviceId::from_bytes([b; 32]));
        watch.wizard_grant(turn_on(one, chosen_pw()), &shared);
        watch.wizard_grant(
            with_level(2, two, Preset::MyMachines, generated_pw()),
            &shared,
        );
        let card = |device| {
            shared.read(|m| {
                m.wizard
                    .cards
                    .iter()
                    .find(|(d, _)| *d == device)
                    .map(|(_, c)| *c)
            })
        };
        watch.refresh(&shared);
        assert_eq!(
            card(one).and_then(|c| c.view_only),
            Some(ViewOnly::UntilNewPassword)
        );
        assert_eq!(card(two).and_then(|c| c.view_only), None);
        assert_eq!(card(one).and_then(|c| c.nothing_ran), Some(0));
        facts.set_account(AccountFacts::Windows(WindowsFacts {
            installed: true,
            administrator: true,
            enable_lua: Some(0),
            ..Default::default()
        }));
        watch.refresh(&shared);
        assert_eq!(
            card(one).and_then(|c| c.view_only),
            Some(ViewOnly::AccountSettings)
        );
        assert_eq!(card(two).and_then(|c| c.view_only), None);
        facts.set_account(AccountFacts::Linux);
        watch.refresh(&shared);
        assert_eq!(card(one).and_then(|c| c.view_only), None);
        let refused = SessionRecord::now(SessionEvent::AdminRequest)
            .device(one)
            .op("suspend")
            .ok(false);
        watch.ctx.log.append(&refused).unwrap();
        let log = Paths::from_home(tmp.path()).sessions_log();
        let before = std::fs::read(&log).unwrap();
        watch.refresh(&shared);
        assert_eq!(card(one).and_then(|c| c.nothing_ran), Some(1));
        assert_eq!(card(two).and_then(|c| c.nothing_ran), Some(0));
        assert_eq!(std::fs::read(&log).unwrap(), before, "read only");
    }

    // ------------------------------------------------------------ the Sessions page (§B.8.13)

    /// §B.8.13: the tokio side reads the Sessions page's rows from the log by
    /// itself, and reading writes nothing: the log stays byte-identical, no
    /// file is added, and the rows hold the planned fields only.
    #[test]
    fn viewing_the_sessions_page_writes_nothing() {
        use tornect_core::session_log::{SessionEvent, SessionLog, SessionMode, SessionRecord};
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let log = SessionLog::new(paths.sessions_log());
        let started = SessionRecord::now(SessionEvent::SessionStarted)
            .peer(tornect_core::DeviceId::from_bytes([1; 32]), "Office laptop")
            .session("s1")
            .mode(SessionMode::Control);
        log.append(&started).unwrap();
        let dir = paths.sessions_log().parent().unwrap().to_path_buf();
        let files = || std::fs::read_dir(&dir).unwrap().count();
        let (before, count) = (std::fs::read(paths.sessions_log()).unwrap(), files());
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        refresh_sessions(&paths, &shared);
        let rows = shared.read(|m| m.sessions.clone()).expect("read");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "Office laptop");
        assert_eq!(rows[0].mode, Some(SessionMode::Control));
        assert_eq!(
            shared.read(|m| m.log_folder.clone()),
            Some(dir.display().to_string())
        );
        assert_eq!(std::fs::read(paths.sessions_log()).unwrap(), before);
        assert_eq!(files(), count, "no file added");
    }

    /// §B.8.13: a log read in part keeps the rows that could be read: a line
    /// that is not UTF-8 among good ones leaves the good rows, and a file
    /// that cannot be read leaves none, with the page's sentence either way
    /// and never a spinner for ever.
    #[test]
    fn a_log_read_in_part_keeps_its_rows() {
        use std::io::Write as _;
        use tornect_core::session_log::{SessionEvent, SessionLog, SessionMode, SessionRecord};
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let log = SessionLog::new(paths.sessions_log());
        let started = SessionRecord::now(SessionEvent::SessionStarted)
            .peer(tornect_core::DeviceId::from_bytes([1; 32]), "Office laptop")
            .session("s1")
            .mode(SessionMode::Control);
        log.append(&started).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(paths.sessions_log())
            .unwrap()
            .write_all(b"\xff\xfe\n")
            .unwrap();
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        refresh_sessions(&paths, &shared);
        shared.read(|m| {
            let rows = m.sessions.as_ref().expect("the rows read");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].label, "Office laptop");
            assert!(m.sessions_partial, "part could not be read");
        });
        // A directory where the live file is: it cannot be read.
        std::fs::remove_file(paths.sessions_log()).unwrap();
        std::fs::create_dir(paths.sessions_log()).unwrap();
        refresh_sessions(&paths, &shared);
        shared.read(|m| {
            assert_eq!(m.sessions.as_deref().map(<[_]>::len), Some(0), "no spinner");
            assert!(m.sessions_partial);
        });
    }

    /// The monitors design §2: each viewed session gets its own channel of
    /// screen requests; a request is queued without blocking the UI thread,
    /// at most one waits, none goes without a session, and none of an
    /// earlier session reaches a later one.
    #[test]
    fn each_session_gets_its_own_screen_requests() {
        use tokio::sync::mpsc::error::TryRecvError;
        let link = StreamLink::default();
        assert!(!link.show_screen(2), "no session");
        let mut first = link.start_requests();
        assert!(link.show_screen(2));
        assert!(!link.show_screen(1), "one waits already");
        assert_eq!(first.try_recv(), Ok(ViewerRequest::ShowScreen(2)));
        assert!(link.show_screen(tornect_proto::ALL_MONITORS));
        // The session ends: nothing more goes, and its receiver hears that.
        link.set_requests(None);
        assert!(!link.show_screen(1));
        assert_eq!(first.try_recv(), Ok(ViewerRequest::ShowScreen(0)));
        assert_eq!(first.try_recv(), Err(TryRecvError::Disconnected));
        let mut second = link.start_requests();
        assert_eq!(second.try_recv(), Err(TryRecvError::Empty));
        assert!(link.show_screen(1));
        assert_eq!(second.try_recv(), Ok(ViewerRequest::ShowScreen(1)));
        assert_eq!(first.try_recv(), Err(TryRecvError::Disconnected));
    }

    /// A choice in the Screens menu marks the session as switching only once
    /// its request is queued, and does so under the model's lock, so the
    /// viewer's answer (even one it gives at once, as for a request it
    /// could not send) always comes after the mark. In control and
    /// view-only sessions alike; never before the host listed its screens,
    /// without a session, or while a request waits.
    #[test]
    fn a_screen_choice_marks_the_session_switching_once_it_is_queued() {
        use super::super::model::ScreensView;
        use tokio::sync::mpsc::error::TryRecvError;
        let listed = || ScreensView {
            monitors: vec![
                tornect_proto::MonitorEntry::saturating(true, 0, 0, 2560, 1440),
                tornect_proto::MonitorEntry::saturating(false, 2560, 0, 1920, 1080),
            ],
            all: true,
            shown: 1,
            ..ScreensView::default()
        };
        let live = |control, screens| {
            ClientStage::Live(Viewing {
                host: "Desk".to_owned(),
                control,
                administrator: false,
                unattended: false,
                since: Instant::now(),
                pictures: 0,
                size: (0, 0),
                stream: StreamInfo::default(),
                services: None,
                screens,
            })
        };
        let switching = |shared: &Shared| {
            shared.read(|m| match &m.client {
                ClientStage::Live(v) => v.screens.as_ref().and_then(|s| s.switching),
                _ => None,
            })
        };
        let link = StreamLink::default();
        let mut rx = link.start_requests();
        // No session; a session whose host listed nothing yet.
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        show_screen(&shared, &link, 2);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        shared.update(|m| m.client = live(true, None));
        show_screen(&shared, &link, 2);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        for control in [false, true] {
            shared.update(|m| m.client = live(control, Some(listed())));
            show_screen(&shared, &link, 2);
            assert_eq!(switching(&shared), Some(2), "{control}");
            // A second choice while the first waits asks for nothing.
            show_screen(&shared, &link, tornect_proto::ALL_MONITORS);
            assert_eq!(switching(&shared), Some(2), "{control}");
            assert_eq!(rx.try_recv(), Ok(ViewerRequest::ShowScreen(2)), "{control}");
            assert_eq!(rx.try_recv(), Err(TryRecvError::Empty), "{control}");
        }
        // The session's channel is gone: the request is not queued, so the
        // window does not wait for an answer.
        link.set_requests(None);
        shared.update(|m| m.client = live(true, Some(listed())));
        show_screen(&shared, &link, 2);
        assert_eq!(switching(&shared), None);
    }

    /// The monitors design §4: what capture says later of a shared session
    /// (the rectangle shown, all monitors, its input ended) reaches that
    /// session's note for the indicator, and no other session's.
    #[test]
    fn what_capture_says_later_reaches_the_sessions_note() {
        use tornect_input::Rect;
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let sharing = |id: &str| Sharing {
            session_id: id.to_owned(),
            label: "Laptop".to_owned(),
            control: true,
            unattended: false,
            since: Instant::now(),
            services: None,
            capture: None,
        };
        shared.update(|m| m.sharing = vec![sharing("s-1"), sharing("s-2")]);
        let media = GuiMedia {
            shared: Arc::clone(&shared),
        };
        let started = |id| CaptureStarted {
            session_id: id,
            label: "Laptop",
            source: "test-screens",
            width: 1920,
            height: 1080,
            mode: SessionMode::Control,
            input: true,
        };
        media.capture_started(&started("s-1"));
        media.capture_started(&started("s-2"));
        let note = |id: &str| {
            shared.read(|m| {
                m.sharing
                    .iter()
                    .find(|s| s.session_id == id)
                    .and_then(|s| s.capture.clone())
                    .unwrap()
            })
        };
        assert_eq!((note("s-1").shown, note("s-1").all), (None, false));
        let right = Rect::new(2560, 0, 1920, 1080);
        media.capture_changed(&CaptureChanged {
            session_id: "s-1",
            shown: Some(right),
            all: false,
            screen: 2,
            of: 2,
            input: false,
        });
        let first = note("s-1");
        assert_eq!(
            (first.shown, first.all, first.input),
            (Some(right), false, false)
        );
        assert_eq!(
            (first.source, first.width, first.height),
            ("test-screens", 1920, 1080)
        );
        let second = note("s-2");
        assert_eq!(
            (second.shown, second.all, second.input),
            (None, false, true)
        );
        let whole = Rect::new(0, 0, 4480, 1440);
        media.capture_changed(&CaptureChanged {
            session_id: "s-2",
            shown: Some(whole),
            all: true,
            screen: 0,
            of: 2,
            input: true,
        });
        assert_eq!(note("s-2").shown, Some(whole));
        assert!(note("s-2").all);
        // A session the model does not hold changes nothing.
        media.capture_changed(&CaptureChanged {
            session_id: "s-9",
            shown: None,
            all: false,
            screen: 1,
            of: 2,
            input: false,
        });
        assert_eq!(note("s-1"), first);
    }

    /// A session's services get the window's clipboard only once the window
    /// says it reads and sets its clipboard (design `services` §4.3; until
    /// then the host is never asked to share one). The text the window read
    /// goes out newest-wins, the host's text is taken once, and both ends go
    /// with the session's services.
    #[test]
    fn the_services_get_the_windows_clipboard_only_when_it_handles_one() {
        let text = |t: &str| ClipText::new(t.to_owned()).unwrap();
        let link = StreamLink::default();
        assert!(
            link.start_clip(true).is_none(),
            "the window shares none yet"
        );
        assert!(!link.offer_clip(text("early")));
        assert!(link.take_clip().is_none());

        link.set_window_clipboard(true);
        let mut clip = link.start_clip(false).expect("the window shares one now");
        assert!(!clip.on, "the switch as the settings hold it");
        assert!(link.offer_clip(text("first")));
        assert!(link.offer_clip(text("second")));
        assert_eq!(
            clip.outbound
                .borrow_and_update()
                .as_ref()
                .map(ClipText::as_str),
            Some("second"),
            "newest wins"
        );
        assert!(link.take_clip().is_none(), "the host sent nothing yet");
        clip.inbound.send_replace(Some(text("from the host")));
        assert_eq!(
            link.take_clip().as_ref().map(ClipText::as_str),
            Some("from the host")
        );
        assert!(link.take_clip().is_none(), "taken once");

        link.end_clip();
        assert!(!link.offer_clip(text("late")));
        clip.inbound.send_replace(Some(text("after the end")));
        assert!(link.take_clip().is_none());

        // Turned off while a session's services run: its ends go at once,
        // and later sessions share none.
        let clip = link.start_clip(true).expect("shared");
        assert!(
            link.set_window_clipboard(true),
            "the session holds its ends"
        );
        assert!(!link.set_window_clipboard(false));
        assert!(!link.offer_clip(text("after the switch")));
        clip.inbound.send_replace(Some(text("from the host")));
        assert!(link.take_clip().is_none());
        assert!(link.start_clip(true).is_none());
        assert!(!link.set_window_clipboard(true), "no session's ends");
    }

    /// The stream window's clipboard through the session's real ends (design
    /// `services` §4.3): what the window read goes to the stream, the
    /// stream's text comes to this computer's clipboard; each change of the
    /// host's text can be waited for (it wakes the window).
    #[test]
    fn the_windows_clipboard_carries_both_ways_through_the_link() {
        use super::super::pages::viewer::Board;
        use super::super::pages::viewer::clip::{Sharing, WindowClip};
        struct Fake(Option<String>, Vec<String>);
        impl Board for Fake {
            fn read(&mut self) -> Option<String> {
                self.0.clone()
            }
            fn set(&mut self, text: &ClipText) {
                self.0 = Some(text.as_str().to_owned());
                self.1.push(text.as_str().to_owned());
            }
        }
        let on = Sharing {
            on: true,
            clip_max: 262_144,
            may_read: true,
        };
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let link = StreamLink::default();
        assert!(link.clip_arrivals().is_none());
        link.set_window_clipboard(true);
        let mut stream = link.start_clip(true).unwrap();
        let arrivals = link.clip_arrivals().expect("while the session runs");
        let mut board = Fake(Some("base".into()), Vec::new());
        let mut w = WindowClip::default();
        w.focus(true, t0);
        w.sync(t0, on, &mut board, &link);
        w.sync(t0 + ms(200), on, &mut board, &link);
        assert!(!arrivals.has_changed().unwrap());
        stream
            .inbound
            .send_replace(Some(ClipText::new("from the host".into()).unwrap()));
        assert!(arrivals.has_changed().unwrap(), "the window is woken");
        w.sync(t0 + ms(300), on, &mut board, &link);
        assert_eq!(board.1, ["from the host"]);
        board.0 = Some("mine".into());
        w.focus(false, t0 + ms(400));
        w.focus(true, t0 + ms(500));
        w.sync(t0 + ms(700), on, &mut board, &link);
        assert_eq!(
            stream
                .outbound
                .borrow_and_update()
                .as_ref()
                .map(ClipText::as_str),
            Some("mine")
        );
    }

    /// The viewer's services requests go to the session's stream only while
    /// it runs; one that went shows in the window at once (its message, its
    /// switch), one that could not go changes nothing.
    #[test]
    fn the_viewers_services_requests_go_only_while_a_stream_runs() {
        use super::super::services::ServicesState;
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        shared.update(|m| {
            m.client = ClientStage::Live(Viewing {
                host: "Desk".to_owned(),
                control: false,
                administrator: false,
                unattended: false,
                since: Instant::now(),
                pictures: 0,
                size: (0, 0),
                stream: StreamInfo::default(),
                services: Some(Box::new(ViewerServices::opening(true))),
                screens: None,
            });
        });
        let card = |shared: &Shared| {
            shared.read(|m| match &m.client {
                ClientStage::Live(v) => v.services.as_deref().cloned(),
                _ => None,
            })
        };
        let hello = tornect_session::services::sanitize_peer_text("hello").unwrap();
        let link = StreamLink::default();
        viewer_services(&shared, &link, ViewerOp::Chat(hello.clone()));
        viewer_services(&shared, &link, ViewerOp::ClipSwitch(false));
        let held = card(&shared).unwrap();
        assert!(held.chat.is_empty() && held.clipboard, "nothing went");

        let mut ops = link.start_services();
        viewer_services(&shared, &link, ViewerOp::Chat(hello.clone()));
        viewer_services(&shared, &link, ViewerOp::ClipSwitch(false));
        assert_eq!(ops.try_recv().unwrap(), ViewerOp::Chat(hello.clone()));
        assert_eq!(ops.try_recv().unwrap(), ViewerOp::ClipSwitch(false));
        let held = card(&shared).unwrap();
        assert_eq!(held.state, ServicesState::Opening);
        assert!(!held.clipboard);
        assert_eq!(held.chat.len(), 1);
        assert!(!held.chat[0].theirs);
        assert_eq!(held.chat[0].text, hello);

        link.set_services(None);
        assert!(!link.services(ViewerOp::ClipSwitch(true)));
    }

    /// Design `services` §2.5: a saved change of `[services]` is published
    /// for the sessions that start afterwards, and a save that changes
    /// nothing of it publishes nothing; a session's own snapshot stays.
    #[test]
    fn a_saved_services_change_reaches_later_sessions_only() {
        let mut saved = Config::default();
        let (policy, _rx) = watch::channel(ServicesPolicy::from_config(&saved.services));
        let started = policy.borrow().clone();
        saved.general.device_name = "Desk".to_owned();
        assert!(
            !republish(&policy, &saved, false),
            "nothing of [services] changed"
        );
        saved.services.browse_files = false;
        assert!(republish(&policy, &saved, false));
        assert!(!policy.borrow().browse_files);
        assert!(started.browse_files, "a running session keeps its snapshot");
        assert!(!republish(&policy, &saved, false), "published once");
    }

    /// The final review's strip finding: on a Wayland desktop whose running
    /// portal request does not ask for the clipboard (`[services]
    /// wayland_clipboard` off, the default), the window host publishes no
    /// clipboard, at its start and at each save, so a Control session with
    /// input is not eligible for one: the desktop is never asked, and no
    /// session is told it refused (no CLIPBOARD_REFUSED line on the strip).
    /// With the switch on, or off a Wayland desktop, the clipboard follows
    /// `[services] clipboard` as before.
    #[test]
    fn a_wayland_host_without_the_portal_clipboard_offers_none() {
        use tornect_proto::services::caps;
        use tornect_session::services::eligible;

        let mut m = Model {
            setup: Some(super::super::model::Setup {
                token_file: std::path::PathBuf::from("token"),
                granted: false,
                busy: false,
                note: None,
            }),
            ..Model::default()
        };
        assert!(!m.portal_clipboard);
        assert!(m.portal_lacks_clipboard());
        let saved = Config::default();
        assert!(saved.services.clipboard, "on by default");
        let policy = host_policy(&saved.services, m.portal_lacks_clipboard());
        assert!(!policy.clipboard);
        assert_eq!(policy, m.services_offered(), "what the sheet says");
        assert_eq!(
            eligible(&policy, SessionMode::Control, true) & caps::CLIP,
            0
        );
        let (held, _rx) = watch::channel(ServicesPolicy::from_config(&saved.services));
        assert!(republish(&held, &saved, m.portal_lacks_clipboard()));
        assert!(!held.borrow().clipboard, "nor after a save");

        m.portal_clipboard = true;
        assert!(!m.portal_lacks_clipboard());
        assert!(host_policy(&saved.services, m.portal_lacks_clipboard()).clipboard);
        m.portal_clipboard = false;
        m.setup = None;
        assert!(!m.portal_lacks_clipboard(), "not a Wayland desktop shared");
        let policy = host_policy(&saved.services, m.portal_lacks_clipboard());
        assert_ne!(
            eligible(&policy, SessionMode::Control, true) & caps::CLIP,
            0
        );
    }

    /// Wait until `done` holds of the model.
    async fn until(shared: &Shared, what: &str, done: impl Fn(&Model) -> bool) {
        for _ in 0..1500 {
            if shared.read(&done) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("{what} did not happen in time");
    }

    /// The review of steps 20–21: before a session is bound, the terminal
    /// host's services port (`tor_cmd::dispatch` to `terminal_services`)
    /// answers byte for byte as the window host's (`host_role`'s services,
    /// the default switches on), so that a peer that has only the host's ID
    /// cannot tell the two apart: a silent stream is dropped unanswered at
    /// the bind deadline, 53 bytes of junk get `Refused{PROTOCOL}`, a `Bind`
    /// of no session or with a wrong MAC `Refused{BAD_BIND}`.
    #[tokio::test(start_paused = true)]
    async fn both_hosts_answer_an_unbound_services_stream_alike() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tornect_proto::services::{Bind, SvcMsg, reason};

        async fn answer_of(
            mut client: tokio::io::DuplexStream,
            bytes: &[u8],
        ) -> (Vec<u8>, Duration) {
            let started = tokio::time::Instant::now();
            client.write_all(bytes).await.unwrap();
            let mut answer = Vec::new();
            tokio::time::timeout(Duration::from_secs(30), client.read_to_end(&mut answer))
                .await
                .expect("the host closes the stream")
                .unwrap();
            (answer, started.elapsed())
        }

        let tmp = tempfile::tempdir().unwrap();
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let media = Arc::new(MediaHost::new(
            Arc::new(SystemBackend::new(Source::TestCard)),
            Arc::new(tornect_session::NoObserver),
            MediaLimits::default(),
        ));
        let (window, _observer) = test_services(&media, &shared, &tmp.path().join("sessions.log"));
        let terminal = crate::tor_cmd::terminal_services(&media);
        let token = tornect_signal::consent::SessionToken::new([0x25; 32]);
        let session_id = token.session_id();
        media.on_start(&LiveSession {
            device: DeviceIdentity::from_seed(&[9; 32]).id(),
            label: "Laptop",
            session_id: &session_id,
            token: &token,
            th_final: [3; 32],
            mode: SessionMode::Control,
            elevation: Elevation::None,
            unattended: false,
        });
        let bind = |session_id: String| {
            SvcMsg::Bind(Bind {
                session_id,
                mac: [7; 32],
            })
            .encode()
        };
        let probes = [
            ("silent", Vec::new(), Vec::new()),
            (
                "53 bytes of junk",
                vec![0x5a; 53],
                SvcMsg::Refused {
                    reason: reason::PROTOCOL,
                }
                .encode(),
            ),
            (
                "a bind of no session",
                bind(tornect_signal::consent::SessionToken::new([0x26; 32]).session_id()),
                SvcMsg::Refused {
                    reason: reason::BAD_BIND,
                }
                .encode(),
            ),
            (
                "a bind with a wrong MAC",
                bind(session_id.clone()),
                SvcMsg::Refused {
                    reason: reason::BAD_BIND,
                }
                .encode(),
            ),
        ];
        let mut streams = JoinSet::new();
        for (what, bytes, expected) in probes {
            let (client, server) = tokio::io::duplex(1 << 16);
            let served = tokio::spawn({
                let window = Arc::clone(&window);
                async move { window.serve(server).await }
            });
            let (from_window, window_took) = answer_of(client, &bytes).await;
            assert_eq!(
                served.await.unwrap(),
                tornect_session::services::ServicesOutcome::NotBound,
                "{what}"
            );
            let (client, server) = tokio::io::duplex(1 << 16);
            let back =
                crate::tor_cmd::dispatch(server, SERVICES_PORT, &media, &terminal, &mut streams);
            assert!(back.is_none(), "{what}");
            let (from_terminal, terminal_took) = answer_of(client, &bytes).await;
            assert_eq!(from_terminal, from_window, "{what}: the bytes differ");
            assert_eq!(from_window, expected, "{what}");
            assert_eq!(terminal_took, window_took, "{what}: the timing differs");
            if bytes.is_empty() {
                assert_eq!(window_took, MediaLimits::default().bind_deadline, "{what}");
            }
        }
        while streams.join_next().await.is_some() {}
    }

    /// Steps 20 and 21 of the services design over in-memory streams: the
    /// window host's sessions sink starts a session's services with its
    /// media; the viewer's services stream opens once the media stream is
    /// bound and capture is live; chat goes both ways into both cards; a
    /// turn-off of a service the session does not have writes nothing; the
    /// session's end closes the stream (`SESSION_OVER`), ends the viewer's
    /// card and writes the summary line, which holds counts and no text.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_window_hosts_services_carry_chat_both_ways() {
        use tornect_proto::services::{caps, reason};
        use tornect_session::services::{ServicesOutcome, ViewerLocal, sanitize_peer_text};

        use super::super::services::ServicesState;
        use crate::tor_cmd::{ServicesReport, ServicesStart, services_over};

        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("sessions.log");
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let media = Arc::new(MediaHost::new(
            Arc::new(SystemBackend::new(Source::TestCard)),
            Arc::new(GuiMedia {
                shared: Arc::clone(&shared),
            }),
            MediaLimits::default(),
        ));
        let (services, observer) = test_services(&media, &shared, &log_path);
        let (started, _seen) = watch::channel(0u64);
        let sessions = GuiSessions {
            live: Arc::new(LiveSessions::new()),
            polkit: Arc::new(PolkitRevocation::for_this_host()),
            media: Arc::clone(&media),
            services: Arc::clone(&services),
            observer: Arc::clone(&observer),
            shared: Arc::clone(&shared),
            started,
        };
        let token = tornect_signal::consent::SessionToken::new([0x24; 32]);
        let session_id = token.session_id();
        let th_final = [3; 32];
        sessions.on_start(&LiveSession {
            device: DeviceIdentity::from_seed(&[9; 32]).id(),
            label: "Laptop",
            session_id: &session_id,
            token: &token,
            th_final,
            mode: SessionMode::ViewOnly,
            elevation: Elevation::None,
            unattended: false,
        });

        // The media stream, bound: capture goes live with its first picture.
        let (media_client, media_server) = tokio::io::duplex(1 << 22);
        let media_served = tokio::spawn({
            let media = Arc::clone(&media);
            async move { media.serve(media_server).await }
        });
        let _viewer = tornect_session::MediaViewer::bind(
            media_client,
            &tornect_session::Binding::new(&token, &th_final),
            Duration::from_secs(30),
        )
        .await
        .expect("the media stream binds");

        // This window also views the session: the model holds both ends.
        shared.update(|m| {
            m.client = ClientStage::Live(Viewing {
                host: "Desk".to_owned(),
                control: false,
                administrator: false,
                unattended: false,
                since: Instant::now(),
                pictures: 0,
                size: (0, 0),
                stream: StreamInfo::default(),
                services: Some(Box::new(ViewerServices::opening(false))),
                screens: None,
            });
        });
        let link = StreamLink::default();
        let report: ServicesReport = {
            let shared = Arc::clone(&shared);
            Arc::new(move |news| shared.update(|m| services_news(m, news)))
        };
        let start = ServicesStart {
            binding: ServicesBinding::new(&token, &th_final),
            local: ViewerLocal::default(),
            ops: link.start_services(),
            report,
        };
        let (svc_client, svc_server) = tokio::io::duplex(1 << 20);
        let served = tokio::spawn({
            let services = Arc::clone(&services);
            async move { services.serve(svc_server).await }
        });
        let viewer = tokio::spawn(services_over(
            async { Ok(svc_client) },
            start,
            std::future::pending(),
        ));
        let viewer_card = |m: &Model| match &m.client {
            ClientStage::Live(v) => v.services.as_deref().cloned(),
            _ => None,
        };
        let host_card = |m: &Model| {
            m.sharing
                .iter()
                .find(|s| s.session_id == session_id)
                .and_then(|s| s.services.clone())
        };
        until(&shared, "both cards open", |m| {
            viewer_card(m).is_some_and(|c| c.state == ServicesState::Open) && host_card(m).is_some()
        })
        .await;
        let (viewer_now, host_now) = shared.read(|m| (viewer_card(m), host_card(m)));
        assert_eq!(viewer_now.unwrap().caps, caps::CHAT, "view only: chat only");
        assert_eq!(host_now.unwrap().caps, caps::CHAT);

        let to_host = sanitize_peer_text("hello host").unwrap();
        let to_viewer = sanitize_peer_text("hello viewer").unwrap();
        viewer_services(&shared, &link, ViewerOp::Chat(to_host.clone()));
        host_services(
            &services,
            &observer,
            &shared,
            &session_id,
            HostServicesOp::Chat(to_viewer.clone()),
        );
        until(&shared, "each card shows both lines", |m| {
            let lines = |chat: &[super::super::services::ChatLine]| {
                chat.iter()
                    .map(|l| (l.theirs, l.text.as_str().to_owned()))
                    .collect::<Vec<_>>()
            };
            let viewer = viewer_card(m).map(|c| lines(&c.chat)).unwrap_or_default();
            let host = host_card(m).map(|c| lines(&c.chat)).unwrap_or_default();
            viewer.contains(&(false, "hello host".to_owned()))
                && viewer.contains(&(true, "hello viewer".to_owned()))
                && host.contains(&(true, "hello host".to_owned()))
                && host.contains(&(false, "hello viewer".to_owned()))
        })
        .await;
        // No transfer has this id: nothing changes.
        host_services(
            &services,
            &observer,
            &shared,
            &session_id,
            HostServicesOp::Cancel(99),
        );
        // The session has no clipboard: nothing to turn off, nothing logged.
        host_services(
            &services,
            &observer,
            &shared,
            &session_id,
            HostServicesOp::TurnOff(caps::CLIP),
        );

        sessions.on_end(&session_id, None);
        let outcome = tokio::time::timeout(Duration::from_secs(20), served)
            .await
            .expect("the host's stream ends with the session")
            .unwrap();
        // How the media stream ended, said beside a wrong services outcome:
        // capture that stopped before `on_end` ends the services stream
        // `CAPTURE_STOPPED`.
        let media = tokio::time::timeout(Duration::from_secs(20), media_served).await;
        assert!(
            matches!(
                outcome,
                ServicesOutcome::Served {
                    reason: reason::SESSION_OVER,
                    ..
                }
            ),
            "{outcome:?}; the media stream: {media:?}"
        );
        tokio::time::timeout(Duration::from_secs(20), viewer)
            .await
            .expect("the viewer's stream ends with the host's")
            .unwrap();
        assert_eq!(
            shared.read(|m| viewer_card(m).map(|c| c.state)),
            Some(ServicesState::Ended(reason::SESSION_OVER))
        );

        let records = tornect_core::session_log::SessionLog::new(&log_path)
            .read_all()
            .unwrap();
        let ours: Vec<_> = records
            .iter()
            .filter(|r| r.session_id.as_deref() == Some(session_id.as_str()))
            .map(|r| r.event)
            .collect();
        assert_eq!(
            ours,
            [tornect_core::session_log::SessionEvent::ServicesSummary],
            "one summary line and no turn-off line"
        );
        let summary = records
            .iter()
            .find(|r| r.event == tornect_core::session_log::SessionEvent::ServicesSummary)
            .unwrap();
        assert_eq!(summary.peer_name.as_deref(), Some("Laptop"));
        assert_eq!(summary.reason.as_deref(), Some("session_over"));
        let written = std::fs::read_to_string(&log_path).unwrap();
        assert!(!written.contains("hello"), "no chat text in sessions.log");
    }
}
