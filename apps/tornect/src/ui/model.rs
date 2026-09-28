//! What the window shows. The tokio side writes it and wakes the UI thread;
//! the UI thread reads it once per frame. Every screen is drawn from a
//! [`Model`] alone (`docs/UI_PLAN.md` §4: no screen reaches around the state to
//! the network), which is also what the view tests build.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use tornect_core::TornectId;
use tornect_core::address_book::{Day, mixes_scripts};
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
    /// The client's "did the host show this code?" question.
    pub confirm: Option<Confirm>,
    /// The sessions this machine's screen is shared with, oldest first. The
    /// host serves one at a time, but a list keeps every live one on the
    /// indicator should two ever overlap (one's end reported after the next
    /// one's start).
    pub sharing: Vec<Sharing>,
    /// The session this machine is viewing.
    pub client: ClientStage,
    /// The last few things that happened, newest last.
    pub events: Vec<String>,
    /// The name other devices see for this computer: sent to every device it
    /// pairs with and every computer it connects to.
    pub device_name: String,
    /// The address book, the recent connections and the paired devices.
    pub book: Book,
    /// What each open host sheet shows about the key asking, by popup id:
    /// its device words, its identicon beside a saved name, the look-alike
    /// alarm (§B.6.1). Set with the popup, in the same update.
    pub recognition: HashMap<u64, Recognition>,
    /// The tokio side has finished shutting down.
    pub closed: bool,
}

impl Model {
    /// How many [`Model::events`] are kept.
    pub const EVENTS_KEPT: usize = 6;

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
}

/// What a host sheet shows about the key asking (§B.6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recognition {
    /// Its device words: recognition only, labelled as such.
    pub words: Words,
    /// Its identicon: only for a pinned key, beside its saved name (W-B8).
    pub identicon: Option<Identicon>,
    /// The saved entry an unpinned key looks like: the alarm fired, and the
    /// pairing takes the code typed from the other device (W-B3).
    pub looks_like: Option<String>,
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
    /// The session is live; the stream window is open.
    Live(Viewing),
    /// It ended, and why.
    Ended(String),
}

/// A live session as the stream window shows it.
#[derive(Debug, Clone)]
pub struct Viewing {
    /// The host's pinned label (the window title; never the onion address,
    /// `docs/UI_PLAN.md` §8).
    pub host: String,
    /// Input goes to the host: the signed `SESSION_ACCEPT` said control.
    pub control: bool,
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
    /// The pinned host key's fingerprint, once paired.
    pub fingerprint: Option<String>,
    /// The day it was paired.
    pub paired: Option<Day>,
    /// The last day a session with it started (history).
    pub last_seen: Option<Day>,
    /// A name saved for it no longer applies: its key changed since.
    pub name_hidden: bool,
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
    /// Its key's fingerprint.
    pub fingerprint: String,
    /// The day it was paired.
    pub paired: Day,
    /// The day of its last session request.
    pub last_seen: Day,
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
