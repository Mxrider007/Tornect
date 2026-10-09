//! What the window shows. The tokio side writes it and wakes the UI thread;
//! the UI thread reads it once per frame. Every screen is drawn from a
//! [`Model`] alone (`docs/UI_PLAN.md` §4: no screen reaches around the state to
//! the network), which is also what the view tests build.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tornect_core::address_book::{Day, mixes_scripts};
use tornect_core::config::{BridgeMode, Theme, Viewer};
use tornect_core::levels::{Answers, Availability};
use tornect_core::session_log::{Actor, SessionMode};
use tornect_core::unattended::credentials::RememberOffer;
use tornect_core::unattended::grant::Preset;
use tornect_core::unattended::ipc::GrantOptions;
use tornect_core::unattended::readiness::Probe;
use tornect_core::{DeviceId, TornectId};

use super::backend::Secret;
use crate::ua_client::AdminAction;
use tornect_core::words::{Identicon, Words};

/// Why the UI thread is woken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    /// The model changed.
    Model,
    /// A new picture is waiting for the stream window.
    Frame,
    /// A popup opened or a session started: raise the main window.
    Attention,
    /// `IpcOp::Show` (a second launch, §B.1.1): raise the main window and arm
    /// every open card again; answer, dismiss and re-order nothing.
    Show,
    /// The process was asked to end (SIGINT or SIGTERM; Ctrl-C or Ctrl-Break
    /// on Windows): close as the window's close button does, ending every
    /// session with a goodbye.
    Quit,
}

/// Wakes the UI thread (a winit event-loop proxy); a no-op in tests.
pub type Waker = Arc<dyn Fn(Wake) + Send + Sync>;

/// The model and the way to wake whoever draws it.
pub struct Shared {
    model: Mutex<Model>,
    wake: Waker,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

impl Shared {
    /// Share `model`, waking through `wake` after every change.
    #[must_use]
    pub fn new(model: Model, wake: Waker) -> Arc<Self> {
        Arc::new(Self {
            model: Mutex::new(model),
            wake,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Model> {
        // A panic while the lock was held leaves a model that is still worth
        // drawing; the window must not die with it.
        self.model.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Look at the model.
    pub fn read<R>(&self, f: impl FnOnce(&Model) -> R) -> R {
        f(&self.lock())
    }

    /// Change the model and wake the UI thread.
    pub fn update(&self, f: impl FnOnce(&mut Model)) {
        f(&mut self.lock());
        (self.wake)(Wake::Model);
    }

    /// Change the model without waking anyone (the caller wakes as it needs).
    pub fn update_quiet(&self, f: impl FnOnce(&mut Model)) {
        f(&mut self.lock());
    }

    /// Wake the UI thread without a change.
    pub fn wake(&self, why: Wake) {
        (self.wake)(why);
    }
}

/// Everything the windows show.
#[derive(Debug, Clone, Default)]
pub struct Model {
    /// This machine's Tornect ID in 4-character groups, once known.
    pub id: Option<String>,
    /// The connection to the Tor network.
    pub tor: TorState,
    /// Whether this machine answers requests.
    pub hosting: Hosting,
    /// The first-run desktop grant, on a Wayland desktop this machine shares.
    pub setup: Option<Setup>,
    /// The host's consent and pairing popups, oldest first.
    pub popups: Vec<Popup>,
    /// The banner of devices that can connect without asking (§B.8.6.2), until
    /// its last change is acknowledged with re-authentication.
    pub unattended_banner: Option<UnattendedBanner>,
    /// The unattended requests in their block window (§B.8.6.3), oldest first:
    /// each is shown in a window of its own on every monitor, with Block, until
    /// it ends.
    pub blocks: Vec<BlockRequest>,
    /// The client's "did the host show this code?" question.
    pub confirm: Option<Confirm>,
    /// The shared sessions (by `sessions.log` id) that run at the
    /// administrator level: the level the host signed in their accept
    /// (§B.2.1, H5), as the session's start reported it. The banner and the
    /// indicator say so.
    pub admin_sessions: HashSet<String>,
    /// The sessions this machine's screen is shared with, oldest first. The
    /// host serves one at a time, but a list keeps every live one on the
    /// indicator should two ever overlap (one's end reported after the next
    /// one's start).
    pub sharing: Vec<Sharing>,
    /// The session this machine is viewing.
    pub client: ClientStage,
    /// The notice code the viewed session's host last sent (decision M1-70,
    /// §B.8.4.1): a number, the bits of `tornect_signal::messages::notice`.
    /// `None` until the host says, and again once the session is over.
    pub host_notice: Option<u8>,
    /// The connection this computer last asked for: the ID dialed (for Try
    /// again), when it started, whether it went through pairing, and how it
    /// failed if it ended without a session.
    pub dial: Dial,
    /// The last few things that happened, newest last.
    pub events: Vec<String>,
    /// The name other devices see for this computer: sent to every device it
    /// pairs with and every computer it connects to.
    pub device_name: String,
    /// The address book, the recent connections and the paired devices.
    pub book: Book,
    /// polkit's remembered approvals could not be cleared for the Control
    /// session shared now, or stopped being cleared: said under the banner.
    pub polkit_warning: Option<String>,
    /// This is the window's first run in this home: Home says once that no
    /// list of past connections is kept unless history is switched on.
    pub history_notice: bool,
    /// This computer's two sets of device words, once derived (§B.6.1 item 5).
    pub mine: Option<MyWords>,
    /// The connect field's look-alike warning (§B.6.1 item 4): the ID typed
    /// is not in the address book and looks like a saved one; Connect then
    /// takes a second, deliberate click.
    pub connect_warning: Option<ConnectWarning>,
    /// The connect field could not compare this ID with every saved one: a
    /// file holding saved entries could not be read (F-4). Connect then
    /// takes a second, deliberate click, as for a look-alike.
    pub connect_unchecked: Option<TornectId>,
    /// What each open host sheet shows about the key asking, by popup id:
    /// its device words, its identicon beside a saved name, the look-alike
    /// alarm (§B.6.1). Set with the popup, in the same update.
    pub recognition: HashMap<u64, Recognition>,
    /// What each open session sheet offers, by popup id (§B.2.1, r7): set
    /// with the popup. A sheet with no entry offers the three answers it
    /// always did, with no sentence under them.
    pub levels: HashMap<u64, SheetLevels>,
    /// The session sheets whose "Allow as administrator" was clicked: each
    /// shows its Tornect confirmation instead (§B.2.1: no Windows prompt
    /// follows; Deny first, armed after 1 s).
    pub admin_confirm: HashSet<u64>,
    /// The session sheets whose "Allow as administrator…" ended without
    /// administrator access (Windows' prompt cancelled or failed, or no
    /// administrator helper in this build): each says so and keeps its other
    /// answers open (§B.2.1).
    pub admin_not_given: HashSet<u64>,
    /// The session sheets of a device paired moments before: beside the
    /// administrator answer they say the scam line (§B.2.1, T10).
    pub paired_recently: HashSet<u64>,
    /// When the person here last allowed a session: from that click on, the
    /// screen counts as shared, before the session is live and before any
    /// picture can leave, until [`Model::ACCEPTED_HIDES_FOR`] has passed
    /// without the session starting.
    pub accepted: Option<Instant>,
    /// Another Tornect process holds this home's host lock: it may be
    /// sharing this screen, which this window cannot see, so the window
    /// hides what it would hide while sharing.
    pub hosted_elsewhere: bool,
    /// The password prompt of an unattended connect or admin command, open
    /// before anything is dialed (§B.8.10).
    pub prompt: Option<Prompt>,
    /// The computers whose unattended setup was re-created (A16) and whose
    /// warning the person has not confirmed yet: Connect waits for that.
    pub setup_changed: HashSet<TornectId>,
    /// When a computer asked this device to wait before the next password
    /// (`LOCKED_OUT`, `COOLDOWN`): the prompt says so before submitting.
    pub retry_at: HashMap<TornectId, Instant>,
    /// The live unattended session's lines from its signed accept.
    pub ua_live: Option<UaLive>,
    /// The device words of the device key typed into the Unlock
    /// confirmation, once worked out (F4-4).
    pub unlock_words: Option<([u8; 32], Words)>,
    /// The tokio side has finished shutting down.
    pub closed: bool,
    /// What `config.toml` holds of what the settings pages change.
    pub settings: Settings,
    /// The diagnostics report of Settings, About (`crate::diagnostics`: it
    /// names nobody); empty until the tokio side has gathered it.
    pub diagnostics: String,
    /// The first start of this home in a window on screen: Home asks the
    /// name others see, and nothing that could send it (the host's start,
    /// Tor, a connection) runs until it is answered or skipped.
    pub name_question: bool,
    /// Unattended access as Settings, Security and Home show it (§B.8.7.3),
    /// as this window's host last read it from its guard; `None` while the
    /// window has no guard (no host role here, a store that did not open,
    /// another Tornect holding it) and until the first read.
    pub manager: Option<Manager>,
    /// Why the last operation of Settings, Security was not done, in plain
    /// words (never a path); `None` once one is done.
    pub manager_note: Option<&'static str>,
    /// An operation of Settings, Security that asks for the password is
    /// running: the section offers none other until it returns.
    pub manager_busy: bool,
    /// Rotate ID runs: the window closes once it returned (no time limit cuts
    /// it short).
    pub rotating: bool,
    /// The emergency stop code of the last *Turn on*, grouped as the command
    /// line prints it (§B.8.7.4), until the person clicks "I have written it
    /// down": then it is dropped (wiped). Never logged, never in `Debug`; a
    /// window that closes while it is here turns unattended access off again.
    pub stop_card: Option<Secret>,
    /// The grant wizard of Settings, Security (§B.8.7.1) as the tokio side
    /// last answered it.
    pub wizard: WizardView,
}

impl Model {
    /// The host's notice code as the stream window may use it: in a control
    /// session only, so a view-only window shows nothing a host sends.
    #[must_use]
    pub fn viewer_notice(&self) -> Option<u8> {
        match &self.client {
            ClientStage::Live(v) if v.control => self.host_notice,
            _ => None,
        }
    }

    /// The viewed session went live as `viewing`: no notice code of an
    /// earlier session's host is kept, so nothing is known of this one's
    /// until it says.
    pub fn go_live(&mut self, viewing: Viewing) {
        self.host_notice = None;
        self.client = ClientStage::Live(viewing);
    }

    /// The viewed session's watch returned: its host's notice code goes, so
    /// none is shown from now on, nor kept for the next session.
    pub fn end_notices(&mut self) {
        self.host_notice = None;
    }

    /// How many [`Model::events`] are kept.
    pub const EVENTS_KEPT: usize = 6;

    /// How long an accepted session counts as sharing before it goes live:
    /// the host sends its accept at once, and a session that has not started
    /// by then never will (the client has 15 s to go on, §B.8.4.5).
    pub const ACCEPTED_HIDES_FOR: Duration = Duration::from_secs(30);

    /// Whether this computer's screen may be in a picture that leaves it at
    /// `now`: a session of this window's host is live, one was just allowed,
    /// or another Tornect process hosts this home. The pages then hide the
    /// address book's names, IDs, days and devices.
    #[must_use]
    pub fn screen_shared(&self, now: Instant) -> bool {
        !self.sharing.is_empty()
            || self.hosted_elsewhere
            || self
                .accepted
                .is_some_and(|at| now.saturating_duration_since(at) < Self::ACCEPTED_HIDES_FOR)
    }

    /// Remember that `what` happened.
    pub fn note(&mut self, what: impl Into<String>) {
        self.events.push(what.into());
        let extra = self.events.len().saturating_sub(Self::EVENTS_KEPT);
        self.events.drain(..extra);
    }
}

/// The connection to the Tor network.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum TorState {
    /// Not started yet.
    #[default]
    Starting,
    /// Trying a way in: `via` is "direct Tor", "obfs4 bridges" or "Snowflake".
    Trying {
        /// The transport.
        via: &'static str,
        /// 1-based.
        attempt: usize,
        /// Transports in the ladder.
        of: usize,
    },
    /// Bootstrapping through `via`.
    Progress {
        /// The transport.
        via: &'static str,
        /// 0 ..= 100.
        pct: u32,
        /// Arti's diagnosis when stuck.
        blocked: Option<String>,
    },
    /// Connected through `via`.
    Ready {
        /// The transport.
        via: &'static str,
    },
    /// No way in worked.
    Failed(String),
}

impl TorState {
    /// Whether streams can be opened.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

/// Whether this machine answers requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Hosting {
    /// Waiting for Tor.
    #[default]
    Waiting,
    /// Publishing the onion service.
    Publishing,
    /// Published; `reachable` once the descriptor is out.
    Published {
        /// Clients can reach this ID.
        reachable: bool,
        /// Arti's state name.
        state: String,
        /// Its most severe problem.
        problem: Option<String>,
    },
    /// Not hosting, and why.
    Off(String),
}

/// The first-run desktop grant (the operator's decision of 2026-09-23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    /// The file that holds the desktop's remembered grant; deleting it revokes
    /// the grant (`tornect doctor` names it too).
    pub token_file: PathBuf,
    /// Whether a grant is remembered.
    pub granted: bool,
    /// The desktop's dialog is open.
    pub busy: bool,
    /// What the last attempt said.
    pub note: Option<String>,
}

/// One host popup.
#[derive(Debug, Clone)]
pub struct Popup {
    /// Answers name it.
    pub id: u64,
    /// What it asks.
    pub kind: PopupKind,
    /// When the handshake stops waiting for it (the FSM's popup timeout).
    pub deadline: Instant,
}

/// What a host popup asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PopupKind {
    /// `docs/UI_PLAN.md` §6.2, host side: pair with a new device?
    Pairing {
        /// The name the device declared (normalized; a suggestion only).
        name: String,
        /// Its key's fingerprint.
        fingerprint: String,
        /// The code both screens must show.
        sas: String,
        /// The label it is already paired under (a re-pair), if any.
        pinned: Option<String>,
    },
    /// `docs/UI_PLAN.md` §6.1: start a session with a paired device?
    Session {
        /// The device's pinned label.
        label: String,
        /// Its key's fingerprint.
        fingerprint: String,
    },
    /// §B.8.6.3 "Ask before starting": may this unattended request start? Deny
    /// or Allow only: the level comes from the grant (r7).
    Ask {
        /// The device's pinned label.
        label: String,
        /// The grant holds the administrator level: the sheet says that the
        /// device wants to connect as administrator.
        administrator: bool,
    },
}

/// The banner of §B.8.6.2: how many devices can connect without asking, and
/// the last change that let them (a grant created, widened or enabled,
/// unattended access turned on or resumed, a backup exported), shown until
/// that change is acknowledged with re-authentication; a newer change shows
/// it again. The acknowledgement is kept in memory only (no store field), so
/// the banner shows again after a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnattendedBanner {
    /// Devices that can connect without asking now.
    pub devices: usize,
    /// The last change: its time (RFC 3339, UTC) and who made it.
    pub last_change: Option<(String, &'static str)>,
}

impl UnattendedBanner {
    /// The banner of `devices` and `last_change`, unless no device can connect
    /// without asking or that change was the one `acknowledged`.
    #[must_use]
    pub fn of(
        devices: usize,
        last_change: Option<(String, &'static str)>,
        acknowledged: Option<&str>,
    ) -> Option<Self> {
        if devices == 0 {
            return None;
        }
        match (&last_change, acknowledged) {
            (Some((at, _)), Some(seen)) if at.as_str() <= seen => return None,
            (None, Some(_)) => return None,
            _ => {}
        }
        Some(Self {
            devices,
            last_change,
        })
    }

    /// Its line: §B.8.6.2's sentence with the count, the day of the last change
    /// and who made it filled in, `today` being today's day.
    #[must_use]
    pub fn line(&self, today: Option<Day>) -> String {
        let devices = if self.devices == 1 {
            "1 device can".to_owned()
        } else {
            format!("{} devices can", self.devices)
        };
        match &self.last_change {
            Some((at, by)) => {
                let when = day_of(at).map_or_else(
                    || "at an unknown time".to_owned(),
                    |day| super::pages::day_in_sentence(day, today),
                );
                format!("{devices} connect without asking — last change {when} by {by}")
            }
            None => format!("{devices} connect without asking"),
        }
    }
}

/// The day of an RFC 3339 time (`2026-10-02T…`).
fn day_of(at: &str) -> Option<Day> {
    let date = at.get(..10)?;
    let mut parts = date.split('-');
    let y = parts.next()?.parse().ok()?;
    let m = parts.next()?.parse().ok()?;
    let d = parts.next()?.parse().ok()?;
    Day::from_ymd(y, m, d)
}

/// One unattended request in its block window (§B.8.6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRequest {
    /// Block names it.
    pub id: u64,
    /// The device's pinned label.
    pub label: String,
    /// When the window ends and the session starts unless blocked.
    pub ends_at: Instant,
}

/// This computer's two sets of device words (§B.6.1 item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MyWords {
    /// Its device key's: what another computer's sheet shows when this one
    /// connects to it.
    pub device: Words,
    /// Its Tornect ID's ("this address").
    pub address: Words,
}

/// The connect field's look-alike warning.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectWarning {
    /// The ID typed, which is not in the address book.
    pub id: TornectId,
    /// The saved computer it looks like.
    pub name: String,
}

impl std::fmt::Debug for ConnectWarning {
    /// No ID and no saved name: a debug line never names a computer.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectWarning").finish_non_exhaustive()
    }
}

/// What a session sheet offers on this computer (§B.2.1, r7): the answers
/// this build can deliver — a level it cannot deliver is absent, never a
/// greyed button — the line under Allow, and the sentence under the
/// buttons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SheetLevels {
    /// The answers besides Deny.
    pub answers: Answers,
    /// The one sentence under the buttons, if the row has one: the row's
    /// own, or why its administrator answer is absent in this build.
    pub sentence: Option<&'static str>,
    /// `PromptOnSecureDesktop` is 0: Windows' prompts show on the shared
    /// screen, said at every level.
    pub prompts_on_shared_screen: bool,
    /// The line under "Allow" on this row.
    pub allow_line: &'static str,
}

impl SheetLevels {
    /// What a sheet offers on a host in the row `levels`.
    #[must_use]
    pub fn of(levels: &Availability) -> Self {
        Self {
            answers: levels.offered(),
            sentence: levels.offered_sentence(),
            prompts_on_shared_screen: levels.prompts_on_shared_screen,
            allow_line: levels.allow_line(),
        }
    }
}

/// What a host sheet shows about the key asking (§B.6.1).
#[derive(Clone, PartialEq, Eq)]
pub struct Recognition {
    /// Its device words: recognition only, labelled as such.
    pub words: Words,
    /// Its identicon: only for a pinned key, beside its saved name (W-B8).
    pub identicon: Option<Identicon>,
    /// The saved entry an unpinned key looks like: the alarm fired, and the
    /// pairing takes the code typed from the other device (W-B3).
    pub looks_like: Option<String>,
    /// The alarm could not compare: a file holding saved entries could not
    /// be read, and none of the entries that could be read matched. It
    /// counts as fired (F-4): the pairing takes only the typed code.
    pub unchecked: bool,
}

impl std::fmt::Debug for Recognition {
    /// Whether the alarm fired, never which saved entry it named.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recognition")
            .field("alarm", &self.looks_like.is_some())
            .field("unchecked", &self.unchecked)
            .finish_non_exhaustive()
    }
}

impl Recognition {
    /// Whether the pairing takes only the code typed from the other device:
    /// the alarm fired, or it could not compare.
    #[must_use]
    pub fn typed_only(&self) -> bool {
        self.looks_like.is_some() || self.unchecked
    }
}

/// The client's side of pairing: the host accepted; do the codes match?
#[derive(Debug, Clone)]
pub struct Confirm {
    /// Answers name it.
    pub id: u64,
    /// The name the host sent with its accept.
    pub host_name: String,
    /// The code this screen showed.
    pub sas: String,
    /// Until when the host waits for the session request that follows a
    /// "the codes match"; a later one still pairs this computer.
    pub host_waits_until: Instant,
    /// When the question gives up (and refuses).
    pub deadline: Instant,
}

/// A session this machine's screen is shared with: what the persistent
/// sharing indicator shows (`docs/UI_PLAN.md` §6.3), in the main window's
/// banner and in its own window (`indicator`).
#[derive(Debug, Clone)]
pub struct Sharing {
    /// `sessions.log`'s session id.
    pub session_id: String,
    /// The viewer's pinned label.
    pub label: String,
    /// Control, or view-only.
    pub control: bool,
    /// Started on an unattended grant, with no popup (§B.8): the indicator
    /// says so (§B.8.7.3: "Unattended · `name` · Control · End").
    pub unattended: bool,
    /// When the session started.
    pub since: Instant,
    /// What capture reported once the first picture went out.
    pub capture: Option<CaptureNote>,
}

/// What capture reported for a shared session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureNote {
    /// The capture backend.
    pub source: &'static str,
    /// Size of the first picture.
    pub width: u32,
    /// Size of the first picture.
    pub height: u32,
    /// Whether the viewer's input reaches this machine.
    pub input: bool,
}

/// The connection this computer last asked for, as the connect stepper
/// shows it.
#[derive(Debug, Clone, Default)]
pub struct Dial {
    /// The ID dialed.
    pub id: Option<TornectId>,
    /// When the connection was asked for.
    pub since: Option<Instant>,
    /// It went through pairing (the code was compared).
    pub paired_now: bool,
    /// It ended without a session: why, and at which step (1 reaching,
    /// 2 pairing, 3 waiting for approval, 4 opening the picture; unattended:
    /// 2 the password, 3 the computer's own checks).
    pub failed: Option<(Failure, u8)>,
    /// An unattended connect: the stepper names its own steps.
    pub unattended: bool,
}

/// Why a connection ended without a session: the connect stepper's error
/// taxonomy (the redesign's §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Tor could not reach the computer.
    Unreachable,
    /// The person at the computer said no.
    Denied,
    /// Nobody answered in time.
    TimedOut,
    /// The two computers speak different protocol versions.
    VersionMismatch,
    /// The codes differed (or this computer's person said so).
    CodesDiffer,
    /// Unattended: the password was not accepted.
    WrongPassword,
    /// Unattended: the computer did not let this device in (its reason is
    /// the stage's own words).
    NotLetIn,
    /// Unattended: the computer's unattended setup was re-created (A16).
    SetupChanged,
    /// Nobody answered the code question on this computer.
    CodeUnanswered,
    /// Anything else; the stage's own words say what.
    Other,
}

impl Failure {
    /// The error's headline.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Unreachable => "Could not reach the computer",
            Self::Denied => "The person at the computer said no",
            Self::TimedOut => "Nobody answered in time",
            Self::VersionMismatch => "The two computers run Tornect versions that cannot talk",
            Self::CodesDiffer => "Not paired. Nothing was saved.",
            Self::WrongPassword => "Wrong password",
            Self::NotLetIn => "The computer did not let this device in",
            Self::SetupChanged => "Its unattended setup was re-created",
            Self::CodeUnanswered => "Nobody answered the code question here",
            Self::Other => "The connection ended",
        }
    }

    /// What to do about it, in plain words.
    #[must_use]
    pub fn advice(self) -> &'static str {
        match self {
            Self::Unreachable => {
                "It may be off, not running Tornect, or still publishing its ID; Tor itself may \
                 be slow. Try again in a minute."
            }
            Self::Denied => {
                "Nothing was shared. Ask the person at that computer before trying again."
            }
            Self::TimedOut => {
                "The request waited up to its limit. Ask the person at that computer to watch \
                 for it, then try again."
            }
            Self::VersionMismatch => "Update Tornect on both computers, then try again.",
            Self::CodeUnanswered => {
                "Nothing was saved. Press Connect again and answer the code question on this \
                 computer."
            }
            Self::CodesDiffer => {
                "If the codes differed, something between you may have changed them. Try again \
                 later, ideally after checking the ID with the person at that computer."
            }
            Self::WrongPassword => {
                "Nothing else was tried. Try again when you want to: each try counts at the \
                 computer."
            }
            Self::NotLetIn => "Its reason is below. Nothing is tried again by itself.",
            Self::SetupChanged => {
                "If that wasn't you, revoke devices there. Connecting waits until you say you \
                 read this."
            }
            Self::Other => "Try again, or go back.",
        }
    }
}

/// The session this machine is viewing (`docs/UI_PLAN.md` §5, S3).
#[derive(Debug, Clone, Default)]
pub enum ClientStage {
    /// Nothing asked yet.
    #[default]
    Idle,
    /// Opening a Tor circuit to `id`.
    Reaching {
        /// The dialed ID, in groups: never a name the host sent (§B.8.4.1).
        id: String,
    },
    /// Pairing: the host's user compares this code.
    Pairing {
        /// The code.
        sas: String,
    },
    /// Waiting for the host's user to accept the session.
    Asking,
    /// Unattended: the password is being checked, and someone at the
    /// computer can still block the session (or must allow it); no countdown
    /// (§B.8.10: the grant's policy is disclosed only in the signed accept).
    Checking,
    /// The session is live; the stream window is open.
    Live(Viewing),
    /// It ended, and why.
    Ended(String),
}

/// A live session as the stream window shows it.
#[derive(Debug, Clone)]
pub struct Viewing {
    /// The host's pinned label: shown inside the stream window, never while
    /// this screen is shared; never the onion address (`docs/UI_PLAN.md` §8).
    pub host: String,
    /// Input goes to the host: the signed `SESSION_ACCEPT` said control.
    pub control: bool,
    /// The signed `SESSION_ACCEPT` said administrator (§B.2.1): the bar
    /// reads "Control · administrator". Never from anything but the accept.
    pub administrator: bool,
    /// Started on this device's unattended access (the signed accept's
    /// session type): the bar says "Unattended · …" (§B.8.10).
    pub unattended: bool,
    /// When the session started.
    pub since: Instant,
    /// Pictures decoded so far.
    pub pictures: u64,
    /// Size of the last picture.
    pub size: (u32, u32),
}

/// The address book as the pages show it: read from the files by the tokio
/// side (`book::read`), never written by the window, which asks for every
/// change with an [`super::view::Action`].
#[derive(Debug, Clone, Default)]
pub struct Book {
    /// The computers this one connects to, the most recently seen first: the
    /// paired ones (`known-hosts.toml`) and the saved ones
    /// (`address-book.toml`).
    pub computers: Vec<Computer>,
    /// Recent connections, newest first: which computer, which day.
    pub recent: Vec<(TornectId, Day)>,
    /// The devices that can ask to connect here (`trusted-devices.toml`).
    pub devices: Vec<Device>,
    /// Whether history is kept.
    pub history: bool,
    /// Today (UTC), for "Today" and "Yesterday".
    pub today: Option<Day>,
    /// Why a file could not be read, if one could not.
    pub problem: Option<String>,
    /// The last reachability check of each computer (asked on a click only).
    pub checks: Vec<(TornectId, Check)>,
    /// What the last change did, or why it failed.
    pub note: Option<String>,
}

impl Book {
    /// The computer `id`, if the book has it.
    #[must_use]
    pub fn computer(&self, id: &TornectId) -> Option<&Computer> {
        self.computers.iter().find(|c| c.id == *id)
    }

    /// The last check of `id`.
    #[must_use]
    pub fn check(&self, id: &TornectId) -> Option<&Check> {
        self.checks
            .iter()
            .find(|(c, _)| c == id)
            .map(|(_, check)| check)
    }

    /// Record a check of `id`.
    pub fn set_check(&mut self, id: TornectId, check: Check) {
        self.checks.retain(|(c, _)| *c != id);
        self.checks.push((id, check));
    }

    /// What a line of the lists calls `id`.
    #[must_use]
    pub fn title_of(&self, id: &TornectId) -> String {
        self.computer(id)
            .map_or_else(|| format!("{}…", id.short()), Computer::title)
    }
}

/// A computer this one connects to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Computer {
    /// Its Tornect ID.
    pub id: TornectId,
    /// The name saved for it, when that applies to the key pinned now.
    pub name: Option<String>,
    /// The label pinned when it was paired: the trust anchor.
    pub pinned: Option<String>,
    /// The name it declared when last seen.
    pub declared: Option<String>,
    /// The device words of its ID, once derived (the one short form; the
    /// fingerprint left every surface, §B.6.1 item 6).
    pub words: Option<Words>,
    /// Its identicon: only for a paired computer, beside its name (W-B8).
    pub identicon: Option<Identicon>,
    /// The day it was paired.
    pub paired: Option<Day>,
    /// The last day a session with it started (history).
    pub last_seen: Option<Day>,
    /// A name saved for it no longer applies: its key changed since.
    pub name_hidden: bool,
    /// What this computer knows of its unattended access there
    /// (`hosts.toml`): never a password.
    pub unattended: UaRecord,
}

/// A saved computer's unattended record, as the pages show it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UaRecord {
    /// An unattended session there worked before: Connect (without asking)
    /// is the card's first action, Knock otherwise (§B.8.10).
    pub worked_before: bool,
    /// A password is remembered for it in the keychain.
    pub remembered: bool,
    /// The last signed accept there was control: the card offers the admin
    /// actions that need a control grant (the host decides their scope).
    pub control: bool,
}

/// The password prompt of an unattended connect or admin command (§B.8.10):
/// before dialing, masked, one attempt per explicit action.
#[derive(Clone)]
pub struct Prompt {
    /// The computer.
    pub id: TornectId,
    /// What the lists call it (hidden while this screen is shared).
    pub host: String,
    /// The keychain a password can be remembered in, if one is usable.
    pub keychain: Option<&'static str>,
    /// How long that keychain keeps a password, when not until it is
    /// deleted: the risk copy says it (F4-2).
    pub kept: Option<&'static str>,
    /// Whether "Remember on this device" is offered, without and with the
    /// administrator level asked for.
    pub remember: (RememberOffer, RememberOffer),
    /// A password is remembered for it: used unless one is typed.
    pub remembered: bool,
    /// The password remembered for it was gone from the keychain when it was
    /// to be sent: the prompt asks for it again and says why (I-9).
    pub vanished: bool,
    /// The remembered password was refused last time and deleted.
    pub stale: bool,
    /// The saved record says the grant may carry the administrator level:
    /// "Ask for administrator access" is offered (else absent).
    pub may_admin: bool,
    /// The computer asked to wait until then before the next password.
    pub retry_at: Option<Instant>,
    /// An admin command instead of a session.
    pub admin: Option<AdminAction>,
    /// The other device an Unlock names (its device key).
    pub target: Option<[u8; 32]>,
}

impl std::fmt::Debug for Prompt {
    /// No computer and nothing of a password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prompt")
            .field("remembered", &self.remembered)
            .field("admin", &self.admin)
            .finish_non_exhaustive()
    }
}

/// A live unattended session's lines from its signed accept (§B.8.10).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UaLive {
    /// The administrator level was asked for and the accept gave none.
    pub withheld: bool,
    /// "3 failed attempts since your last login", if there were any.
    pub fail_summary: Option<String>,
}

impl Computer {
    /// What the lists call it: the saved name, else the pinned label, else
    /// the start of its ID.
    #[must_use]
    pub fn title(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.pinned.clone())
            .unwrap_or_else(|| format!("{}…", self.id.short()))
    }

    /// Whether the name shown mixes alphabets with look-alike letters (noted
    /// beside it, never refused).
    #[must_use]
    pub fn looks_mixed(&self) -> bool {
        mixes_scripts(&self.title())
    }
}

/// A device that can ask to connect here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The label pinned when it was paired.
    pub label: String,
    /// Its device words, once derived.
    pub words: Option<Words>,
    /// Its identicon (a pinned key), once derived.
    pub identicon: Option<Identicon>,
    /// The day it was paired.
    pub paired: Day,
    /// The day of its last session request.
    pub last_seen: Day,
}

/// Unattended access as Settings, Security and Home show it (§B.8.7.3),
/// read by the tokio side from the window host's own guard: at the host
/// role's start, every half minute and after each answer of the guard. It
/// holds no secret: no password, no stop code, no device key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manager {
    /// The master switch.
    pub on: bool,
    /// When the running pause ends (Unix seconds); `u64::MAX`: when
    /// unattended access is turned back on. `None` while no pause runs.
    pub paused_until: Option<u64>,
    /// How many devices can connect without asking now: the active grants,
    /// while unattended access is on and not paused.
    pub without_asking: usize,
    /// One row per grant, in the store's order.
    pub grants: Vec<GrantRow>,
    /// The readiness rows (§B.8.7.1 ⑥) by field name, in their order.
    pub readiness: Vec<(&'static str, Probe)>,
    /// A readiness row is not green: Home's sticky not-ready badge, while
    /// unattended access is on.
    pub not_ready: bool,
    /// The host settings kept in the store: keep this computer awake, prevent
    /// its idle lock, notify at each unattended session.
    pub keep_awake: bool,
    /// See [`Manager::keep_awake`].
    pub prevent_idle_lock: bool,
    /// See [`Manager::keep_awake`].
    pub notify: bool,
    /// What starts at sign-in, as the system says it now: `Some(true)` when
    /// Tornect is registered, `Some(false)` when nothing is, `None` when it
    /// cannot be read or is unavailable here.
    pub sign_in: Option<bool>,
    /// Whether Tornect is installed on this computer, by the install's own
    /// probe; `None` when it cannot be read.
    pub installed: Option<bool>,
}

/// A device that can connect here without asking, as the manager shows it
/// (§B.8.7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    /// The device, which the row's operations name.
    pub device: DeviceId,
    /// The label pinned at pairing (never the name the device declares).
    pub label: String,
    /// Its device words, once derived.
    pub words: Option<Words>,
    /// Who gave it access, when the store said so in the same read.
    pub created_by: Option<Actor>,
    /// When it last connected (Unix seconds).
    pub last_used: Option<u64>,
    /// Its state, as `tornect unattended status` labels it (`active`,
    /// `disabled:ui`, `locked:<seconds>`, …).
    pub state: String,
    /// Its failed attempts since the last unlock.
    pub failures: u32,
}

/// One operation of Settings, Security (§B.8.6.2, §B.8.7.3), which the tokio
/// side runs through the window host's guard as the window (`Actor::Ui`);
/// the page changes only on the guard's answer. Turn off, Pause, Revoke all,
/// Suspend, Disable, Revoke and Remove are deny-direction and ask no
/// password; Turn on, Enable, Unlock, Resume, the host settings, the start
/// at sign-in and the wizard's grant are access-increasing: one dialog each,
/// never during or 60 s after a remote session. The wizard's two reads ask
/// nothing and change nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagerOp {
    /// The grant wizard opened: read the paired devices it may give access.
    WizardDevices,
    /// Judge whether a choice of the wizard makes the grant's reach non-zero
    /// (decision M1-67): then its password can only be generated.
    Preview(Box<WizardChoice>),
    /// Give a device unattended access as the wizard chose it: one
    /// registration (its one dialog), then, while unattended access is off,
    /// Turn on (its own dialog) and a new stop code shown once.
    Grant(Box<GrantRequest>),
    /// Give a device's grant a new password from the manager (*Change
    /// password*, §B.8.7.3): one registration (its one dialog) whose options
    /// change nothing but, where control reaches the administrator level, the
    /// mode.
    ChangePassword(Box<GrantRequest>),
    /// Set a device's mode from the manager (*Change mode*): to view only,
    /// deny-direction; to control where control reaches nothing more, a
    /// widening that asks for the password.
    SetMode(DeviceId, SessionMode),
    /// Turn unattended access on: a new emergency stop code is shown once.
    On,
    /// The stop code was written down: it is dropped (no guard operation).
    StopCodeWrittenDown,
    /// Enable the device's disabled access.
    Enable(DeviceId),
    /// Unlock the device's locked access (its failed attempts are reset).
    Unlock(DeviceId),
    /// Resume the device's suspended access.
    Resume(DeviceId),
    /// Change one host setting kept in the store.
    Setting(HostSetting),
    /// Start Tornect when this user signs in, or stop doing so (§B.1.1): the
    /// same guard operation as `tornect service install|uninstall`.
    SignIn(bool),
    /// Rotate ID (§B.8.12): the window ends every session, stops its host
    /// role and Tor, then the guard wipes everything unattended and this
    /// computer gets a new ID; the window closes after.
    RotateId,
    /// Turn unattended access off.
    Off,
    /// Pause unattended access: only while no pause runs, so that no choice
    /// can end one sooner (which would turn access back on).
    Pause(PauseEnd),
    /// Remove unattended access for every device.
    RevokeAll,
    /// Suspend the device's access until a local Resume.
    Suspend(DeviceId),
    /// Disable the device's access until it is enabled again.
    Disable(DeviceId),
    /// Remove the device's unattended access; it stays paired.
    Revoke(DeviceId),
    /// Remove the device: its unattended access, then its pairing.
    Remove(DeviceId),
}

/// What the grant wizard chose for a new grant (§B.8.7.1 ②, ③, ⑤).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardChoice {
    /// The paired device.
    pub device: DeviceId,
    /// The preset.
    pub preset: Preset,
    /// The options set over the preset's defaults (the waiver among them).
    pub options: GrantOptions,
}

/// A new password for a grant on its way from the wizard to the tokio side
/// (decision M1-67): only the wizard's generator builds `Generated`, and the
/// tokio side registers the password as generated exactly when it is that
/// arm. No flag that says "generated" crosses beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewPassword {
    /// Drawn by the passphrase generator (five words of EFF's long list), as
    /// a login reads it.
    Generated(Secret),
    /// Typed by the person ("Use my own password"), as a login reads it.
    Chosen(Secret),
}

impl NewPassword {
    /// The password itself.
    #[must_use]
    pub fn secret(&self) -> &Secret {
        match self {
            Self::Generated(s) | Self::Chosen(s) => s,
        }
    }
}

/// The wizard's *Turn on*: its choice and its password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRequest {
    /// Which press of *Turn on* this is (the answer names it).
    pub attempt: u64,
    /// What it gives.
    pub choice: WizardChoice,
    /// The new password.
    pub password: NewPassword,
}

/// A paired device the grant wizard may give unattended access (§B.8.7.1
/// ②): one without it yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The device.
    pub device: DeviceId,
    /// The label pinned when it was paired.
    pub label: String,
    /// Its device words, once derived.
    pub words: Option<Words>,
    /// An attended session from it has completed here (§B.8.6.1); without
    /// one its access needs the waiver.
    pub attended: bool,
}

/// The password policy's inputs of §B.8.7.2 for the wizard's meter (this
/// computer's names, the labels, the onion address): never shown, never in
/// `Debug`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct PolicyInputs {
    /// The inputs.
    pub inputs: Vec<String>,
    /// The score a chosen password needs: 4 on a file keystore, else 3.
    pub min_score: u8,
}

impl std::fmt::Debug for PolicyInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PolicyInputs({} inputs, score {})",
            self.inputs.len(),
            self.min_score
        )
    }
}

/// How the tokio side answered a press of the wizard's *Turn on*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardAnswer {
    /// The device was given access (and unattended access turned on, if it
    /// was off and the person confirmed it).
    Done,
    /// Nothing was saved, for this reason, in plain words.
    Refused(&'static str),
    /// Nothing was saved: something changed while the person was asked, and
    /// this device now needs a new generated password (`G_NEEDS_PASSWORD`).
    NeedsGenerated,
}

/// The grant wizard as the tokio side last answered it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WizardView {
    /// Whether a paired device without unattended access exists, as the
    /// tokio side last read it with the manager's view: Settings, Security
    /// offers the wizard then. `None` until read.
    pub offer: Option<bool>,
    /// The paired devices the wizard may give access, read when it opened;
    /// `None` until read.
    pub devices: Option<Vec<Candidate>>,
    /// The password policy's inputs, read with the devices.
    pub policy: Option<PolicyInputs>,
    /// The last choice judged, and whether its password can only be
    /// generated (`None`: it could not be judged, so it can only be).
    pub preview: Option<(WizardChoice, Option<bool>)>,
    /// The last choice judged, and whether it raises the grant's own reach
    /// (`None`: it could not be judged).
    pub raises: Option<(WizardChoice, Option<bool>)>,
    /// Each grant's mode, read with the manager's view (*Change mode*).
    pub modes: Vec<(DeviceId, SessionMode)>,
    /// The press of *Turn on* that runs now.
    pub running: Option<u64>,
    /// How the last press ended.
    pub answer: Option<(u64, WizardAnswer)>,
}

/// One host setting of Settings, Security, as it is to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSetting {
    /// Keep this computer awake while unattended access is on.
    KeepAwake(bool),
    /// Prevent the idle lock while unattended access is on.
    PreventIdleLock(bool),
    /// Notify at each unattended session.
    Notify(bool),
}

/// When a pause started from Settings, Security ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseEnd {
    /// Twelve hours after the click.
    TwelveHours,
    /// When unattended access is turned back on.
    UntilOn,
}

/// A reachability check: one pairing-free ping over Tor, asked on a click.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// Waiting for the answer.
    Asking,
    /// It answered, after this many milliseconds (the circuit included).
    Reachable {
        /// Milliseconds from the click to the answer.
        millis: u64,
    },
    /// It did not, and why.
    Unreachable(String),
}

/// What `config.toml` holds of what the settings pages change, as saved:
/// read at the window's start and again after each save from the window. The
/// name others see may differ from the one in use until the next start.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    /// The name others see, as saved.
    pub device_name: String,
    /// The window's colours.
    pub theme: Theme,
    /// How the stream window opens for a new session.
    pub viewer: Viewer,
    /// How Tornect reaches the Tor network (from the next start).
    pub tor: TorChoice,
    /// Why the last save from the window was not made, in plain words;
    /// `None` once one was.
    pub problem: Option<&'static str>,
}

impl Default for Settings {
    fn default() -> Self {
        Self::of(&tornect_core::Config::default())
    }
}

impl Settings {
    /// What `cfg` holds.
    #[must_use]
    pub fn of(cfg: &tornect_core::Config) -> Self {
        Self {
            device_name: cfg.general.device_name.clone(),
            theme: cfg.general.theme,
            viewer: cfg.viewer,
            tor: TorChoice {
                bridges: cfg.tor.bridges,
                bridge_lines: BridgeLines(cfg.tor.bridge_lines.clone()),
                pow_defense: cfg.tor.pow_defense,
            },
            problem: None,
        }
    }
}

/// One change the settings pages ask for. None of them is an operation of
/// §B.8.6.2: those go through the unattended guard, never through this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsChange {
    /// The name others see (it applies at the next start).
    DeviceName(String),
    /// The window's colours (they apply at once).
    Theme(Theme),
    /// How the stream window opens (from the next session on).
    Viewer(Viewer),
    /// How Tornect reaches the Tor network (from the next start).
    Tor(TorChoice),
}

/// How Tornect reaches the Tor network, as `config.toml` holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorChoice {
    /// Direct Tor, bridges, or the automatic ladder.
    pub bridges: BridgeMode,
    /// Private bridge lines.
    pub bridge_lines: BridgeLines,
    /// The onion service's proof-of-work defence.
    pub pow_defense: bool,
}

/// Private bridge lines: useful only while a censor does not know them, so
/// never printed (`Debug` says how many there are).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct BridgeLines(pub Vec<String>);

impl std::fmt::Debug for BridgeLines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BridgeLines({} lines)", self.0.len())
    }
}

impl SettingsChange {
    /// Make the change in `cfg`.
    pub fn apply(&self, cfg: &mut tornect_core::Config) {
        match self {
            Self::DeviceName(name) => cfg.general.device_name.clone_from(name),
            Self::Theme(theme) => cfg.general.theme = *theme,
            Self::Viewer(viewer) => cfg.viewer = *viewer,
            Self::Tor(tor) => {
                cfg.tor.bridges = tor.bridges;
                cfg.tor.bridge_lines.clone_from(&tor.bridge_lines.0);
                cfg.tor.pow_defense = tor.pow_defense;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A new viewed session starts with no notice code, whatever the last
    /// host said, and the code goes once the session's watch returned.
    #[test]
    fn a_stale_notice_is_cleared_at_going_live_and_after_the_end() {
        let viewing = Viewing {
            host: "Office PC".to_owned(),
            control: true,
            administrator: false,
            unattended: false,
            since: Instant::now(),
            pictures: 0,
            size: (0, 0),
        };
        let mut model = Model {
            host_notice: Some(0x07),
            ..Model::default()
        };
        model.go_live(viewing);
        assert_eq!(model.host_notice, None);
        assert!(matches!(model.client, ClientStage::Live(_)));
        assert_eq!(model.viewer_notice(), None);
        model.host_notice = Some(0x05);
        assert_eq!(model.viewer_notice(), Some(0x05));
        model.end_notices();
        assert_eq!(model.host_notice, None);
        assert_eq!(model.viewer_notice(), None);
    }
}
