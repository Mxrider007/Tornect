//! What the window shows. The tokio side writes it and wakes the UI thread;
//! the UI thread reads it once per frame. Every screen is drawn from a
//! [`Model`] alone (`docs/UI_PLAN.md` §4: no screen reaches around the state to
//! the network), which is also what the view tests build.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

/// Why the UI thread is woken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    /// The model changed.
    Model,
    /// A new picture is waiting for the stream window.
    Frame,
    /// A popup opened or a session started: raise the main window.
    Attention,
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
    /// The session this machine's screen is shared with.
    pub sharing: Option<Sharing>,
    /// The session this machine is viewing.
    pub client: ClientStage,
    /// The last few things that happened, newest last.
    pub events: Vec<String>,
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

/// The client's side of pairing: the host accepted; do the codes match?
#[derive(Debug, Clone)]
pub struct Confirm {
    /// Answers name it.
    pub id: u64,
    /// The name the host sent with its accept.
    pub host_name: String,
    /// The code this screen showed.
    pub sas: String,
    /// When the question gives up (and refuses).
    pub deadline: Instant,
}

/// The session this machine's screen is shared with: the persistent sharing
/// indicator (`docs/UI_PLAN.md` §6.3).
#[derive(Debug, Clone)]
pub struct Sharing {
    /// `sessions.log`'s session id.
    pub session_id: String,
    /// The viewer's pinned label.
    pub label: String,
    /// Control, or view-only.
    pub control: bool,
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
