//! Session services (the services design, decision M1-76): chat, clipboard
//! text and files on a session's third onion stream,
//! `tornect_signal::SERVICES_PORT`, beside its media stream and bound to the
//! same session by its own MAC.
//!
//! - [`ServicesHost`] serves the host's end. A stream binds a session the
//!   media layer registered ([`MediaHost`]'s registry, once per session,
//!   under the services MAC), then waits for the session's capture to go
//!   live: nothing is answered before the first picture went out, and
//!   services end when capture stops, however it stops (§2.2). What the
//!   session gets is fixed then ([`eligible`], [`granted`]): chat in every
//!   session; the clipboard and files only in a Control session whose input
//!   reaches the desktop (§2.1), and never again once that input is lost.
//! - [`ServicesViewer`] is the viewer's end: it binds with a
//!   [`ServicesBinding`] once its media stream is bound, and runs until the
//!   host closes the stream or the viewer's session ends.
//!
//! Each end reads the other's frames on a task of its own and gates each one
//! by its type before its body is read: a frame for a service the session was
//! never granted ends the stream with `Close{NOT_OFFERED}`, undecoded (the
//! view-only guarantee, §3.2). Each end writes from a task of its own, which
//! drains its queues in priority order (§3.4). The services stream ending
//! never ends the session.
//!
//! Nothing here logs peer text, clipboard text, file names or host paths:
//! only kinds, counts, byte totals and reason codes (§2.5).
//!
//! Files the viewer sends land in the host's inbox, `<Downloads>/Tornect`
//! (the upload protocol, §3.5): each is written beside its reserved final
//! name as a private `.tornect-part` file on a blocking worker, within the
//! session's file count, byte quota and the disk's free space, checked
//! against the sender's SHA-256 and renamed into place; whatever ends a
//! transfer before that (a cancel, a protocol error, the session's end, the
//! kill switch, capture stopping, lost input) deletes what was written. A
//! sender keeps at most the bulk window of file bytes beyond what the
//! receiver credited, and the receiver holds it to that.
//!
//! What a stream may show or send of a computer's files is decided by that
//! computer's [`Access`] (§5.2): a place allowlist, a deny-list of Tornect's
//! own folders (and Linux's system ones), the private marker every Tornect
//! home holds, and part files, all judged on the canonical path, which is
//! the one opened. The viewer judges each file it sends by its own
//! [`Access`] before anything goes out.
//!
//! The viewer browses the host's files by handle (§3.5, §5.2): a `List`
//! names a folder's handle (`0`, the places) and the host answers one page,
//! within the page budget; the viewer asks for the next page only once it
//! has the one before, so a large folder never fills the stream. One listing
//! is read at a time, on a blocking worker bounded in entries and in time,
//! and at most [`LIST_RATE`] first pages a second; more get
//! `ListFailed{BUSY}`. A `Get` names a file's handle: the host checks the
//! path again, opens the canonical one read-only within the read timeout, and
//! sends `Sending`, the bytes within the bulk window as the viewer credits
//! them, and `Done` with their SHA-256. The viewer takes them into its own
//! `<Downloads>/Tornect` the way the host's inbox takes an upload and says
//! `Complete` once the file is in place; the host is told the file sent only
//! then. At most [`MAX_DOWNLOADS`] files are sent at once per stream.
//!
//! Clipboard text crosses both ways (§3.4, §4): each end sends its newest
//! text as a `ClipStart` and `ClipChunk`s within the same bulk window as
//! files (the clipboard's flight, credited with `Credit{0}`), at most one
//! start every [`CLIP_EVERY`], and takes the peer's at most [`CLIP_RATE`] a
//! second. The host's clipboard link is active only while the viewer's
//! switch is on (`ClipSwitch`) and the host is not locked; text received
//! becomes clipboard text only through `ClipText::from_peer`, and neither end
//! sends again the text it sent or applied last.
//!
//! While the host is locked or shows a secure screen
//! ([`ServicesHost::set_locked`], §2.3) the clipboard, uploads and browsing
//! are paused for every stream: new requests for them are skipped unread
//! (the viewer fails its own unanswered ones with `LOCKED`), transfers stall
//! instead of failing (no `Credit` for uploads, no `Data` for downloads),
//! and the clipboard's link is inactive; chat goes on. The host's user can
//! turn services off for the rest of a session ([`ServicesHost::turn_off`]):
//! their transfers end with `TURNED_OFF`, and they never come back.
//!
//! The stream is built in the design's steps: this build has the bind, the
//! live wait, the caps, chat both ways, the clipboard, uploads, browsing the
//! host's files and downloads, the viewer's own file browser, the lock
//! pause, the host user's turn-off and the close paths; the app wires them
//! in the design's steps 20 and 21.
//!
//! [`MediaHost`]: crate::MediaHost

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tornect_core::session_log::SessionMode;
use tornect_proto::services::caps;

pub mod browse;
pub mod chat;
mod clip;
mod download;
mod host;
mod listing;
mod reader;
mod store;
mod transfer;
mod upload;
mod viewer;
mod window;
mod writer;

#[cfg(test)]
mod tests;

pub use browse::{
    Access, EntryKind, EntryView, ListingView, system_denied, tornect_denied, windows_drive_root,
};
pub use chat::{CHAT_BURST, CHAT_RATE, ChatText, sanitize_peer_text};
pub use clip::{CLIP_BURST, CLIP_EVERY, CLIP_RATE, ViewerClip};
pub use host::{ServicesHost, ServicesOutcome};
pub use listing::LIST_RATE;
pub use reader::ReaderCounts;
pub use store::{FreeSpaceFn, RECHECK_FREE_EVERY};
pub use transfer::{
    Direction, HostPath, MAX_DOWNLOADS, MAX_UPLOADS, TransferRow, TransferState, Untrusted,
};
pub use viewer::{
    ServicesBindError, ServicesBinding, ServicesViewer, ViewerEvent, ViewerLocal, ViewerOp,
    ViewerServicesEnd,
};

/// What the host lets a session use (`config.toml [services]`), as a session
/// takes it at its start (§2.5): changes apply to later sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicesPolicy {
    /// Chat, in any session.
    pub chat: bool,
    /// Clipboard text, both directions.
    pub clipboard: bool,
    /// The viewer sends files into the inbox.
    pub receive_files: bool,
    /// The viewer lists this computer's folders and downloads files.
    pub browse_files: bool,
    /// The largest file either way, in bytes.
    pub max_file: u64,
    /// The bytes the host receives in one session.
    pub session_quota: u64,
    /// Receiving stops before the disk has less than this free, in bytes.
    pub keep_free: u64,
}

impl ServicesPolicy {
    /// The policy `config.toml`'s `[services]` sets.
    #[must_use]
    pub fn from_config(services: &tornect_core::config::Services) -> Self {
        Self {
            chat: services.chat,
            clipboard: services.clipboard,
            receive_files: services.receive_files,
            browse_files: services.browse_files,
            max_file: services.max_file_bytes(),
            session_quota: services.session_quota_bytes(),
            keep_free: services.keep_free_bytes(),
        }
    }

    /// Every service off: chat, the clipboard, receiving and browsing files
    /// (the sizes as `[services]`' defaults). A session under it is offered
    /// nothing: `Refused{NOT_OFFERED}` once its capture is live.
    #[must_use]
    pub fn none() -> Self {
        Self {
            chat: false,
            clipboard: false,
            receive_files: false,
            browse_files: false,
            ..Self::default()
        }
    }
}

impl Default for ServicesPolicy {
    fn default() -> Self {
        Self::from_config(&tornect_core::config::Services::default())
    }
}

/// The host's bounds on a services stream (§3.4, §6.1). Only
/// [`ServicesLimits::bulk_window`] differs per transport.
#[derive(Debug, Clone, Copy)]
pub struct ServicesLimits {
    /// Bytes of file data and clipboard text a sender keeps in flight beyond
    /// what the receiver credited, summed over its transfers (256 KiB on
    /// Tor; provisional until the live measurement of the design's §10).
    pub bulk_window: u32,
    /// Bytes of content in one `Data` or `ClipChunk`.
    pub chunk: usize,
    /// Decoded frames held between a stream's reader and its loop.
    pub inbound_depth: usize,
    /// How long a bound stream waits for its session's capture to go live.
    pub live_wait: Duration,
    /// How long the desktop's clipboard may take to open for a session.
    pub clipboard_wait: Duration,
    /// How long a folder's listing may take.
    pub list_timeout: Duration,
    /// How long one read of a file being sent may take.
    pub read_timeout: Duration,
    /// Entries of one folder listed at most.
    pub max_entries: usize,
    /// Bytes of entries in one `Listing` page at most.
    pub page_budget: usize,
    /// Handles a stream keeps at most (the oldest go first).
    pub max_handles: usize,
    /// Files the host receives in one session at most.
    pub session_files: u16,
    /// What each received file counts toward the session's quota at least.
    pub min_file_charge: u64,
    /// Bytes of a received file written between two readings of the disk's
    /// free space.
    pub recheck_free_every: u64,
    /// How long a stream waits, before its `Welcome`, for a lock reading
    /// taken after it opened, when a lock watcher feeds the host
    /// ([`ServicesHost::with_lock_watcher`]) and the clipboard or files
    /// would be granted (§2.3); the last reading holds past it.
    pub lock_wait: Duration,
    /// How long a stream's end waits for its upload workers (each deletes
    /// what it wrote, or puts a file it had verified in place) before
    /// `serve` returns.
    pub workers_wait: Duration,
}

impl Default for ServicesLimits {
    fn default() -> Self {
        Self {
            bulk_window: 256 * 1024,
            chunk: tornect_proto::services::CHUNK,
            inbound_depth: 8,
            live_wait: Duration::from_secs(10),
            clipboard_wait: Duration::from_secs(5),
            list_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            max_entries: 10_000,
            page_budget: 60 * 1024,
            max_handles: 65_536,
            session_files: 1000,
            min_file_charge: 4096,
            recheck_free_every: RECHECK_FREE_EVERY,
            lock_wait: Duration::from_secs(2),
            workers_wait: Duration::from_secs(5),
        }
    }
}

/// Where the host's services act (§6.1).
#[derive(Clone)]
pub struct ServicesEnv {
    /// The folder uploads land in (`<Downloads>/Tornect`,
    /// `tornect_core::files::downloads_dir`); `None` when this computer has
    /// no Downloads folder, and then no session gets uploads.
    pub inbox: Option<PathBuf>,
    /// The inbox in display words, such as "Downloads › Tornect"
    /// (`Welcome.inbox`): never a path.
    pub inbox_words: String,
    /// The free space of the inbox's disk (`tornect_platform::disk::available`
    /// on a real host). A file is taken only when the free space can be read.
    pub free_space: FreeSpaceFn,
    /// What a viewer may list and copy of this computer (§5.2): its places
    /// (the user's folders, plus `/` on Linux or each fixed drive's root on
    /// Windows) and its deny-list (Tornect's folders of `Paths::discover()`
    /// and `Paths::platform()`, plus [`system_denied`]).
    pub access: Arc<Access>,
    /// Holds the upload workers as they finish a file (tests only).
    #[cfg(test)]
    pub(crate) finishing: Option<store::FinishHook>,
    /// Called by each listing worker as it starts (tests only).
    #[cfg(test)]
    pub(crate) list_hook: Option<listing::ListHook>,
    /// Called by each open of a file to send before it opens it (tests
    /// only).
    #[cfg(test)]
    pub(crate) open_hook: Option<download::OpenHook>,
}

impl Default for ServicesEnv {
    /// No inbox, no free space known, and nothing to list.
    fn default() -> Self {
        Self {
            inbox: None,
            inbox_words: String::new(),
            free_space: store::unknown_free_space(),
            access: Arc::new(Access::none()),
            #[cfg(test)]
            finishing: None,
            #[cfg(test)]
            list_hook: None,
            #[cfg(test)]
            open_hook: None,
        }
    }
}

impl std::fmt::Debug for ServicesEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServicesEnv")
            .field("inbox", &self.inbox.is_some())
            .field("inbox_words", &self.inbox_words)
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
}

/// What a session may use before the desktop is asked (§2.1): chat when the
/// host allows it; the clipboard, uploads and browsing, each behind its
/// switch, only in a Control session whose input reaches the desktop
/// (`input`: an injector serves it, [`crate::CaptureState::Live`]).
#[must_use]
pub fn eligible(policy: &ServicesPolicy, mode: SessionMode, input: bool) -> u16 {
    let mut eligible = 0;
    if policy.chat {
        eligible |= caps::CHAT;
    }
    if matches!(mode, SessionMode::Control) && input {
        for (on, cap) in [
            (policy.clipboard, caps::CLIP),
            (policy.receive_files, caps::UPLOAD),
            (policy.browse_files, caps::BROWSE),
        ] {
            if on {
                eligible |= cap;
            }
        }
    }
    eligible
}

/// What a session gets (§2.1): `eligible` without the clipboard when no
/// clipboard link opened, and without uploads when the inbox is not usable.
#[must_use]
pub fn granted(eligible: u16, clipboard_opened: bool, inbox_usable: bool) -> u16 {
    let mut granted = eligible;
    if !clipboard_opened {
        granted &= !caps::CLIP;
    }
    if !inbox_usable {
        granted &= !caps::UPLOAD;
    }
    granted
}

/// Where the host's services report what they do: the host's window shows
/// it (the services strip and the chat card) and `sessions.log` records the
/// files (§7.2, §8).
pub trait ServicesObserver: Send + Sync {
    /// Something happened on session `session_id`'s services stream.
    fn event(&self, session_id: &str, event: HostEvent);
}

/// Observes nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoServicesObserver;

impl ServicesObserver for NoServicesObserver {
    fn event(&self, _: &str, _: HostEvent) {}
}

/// What [`ServicesObserver::event`] is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEvent {
    /// The stream opened with `caps` (`Welcome` was queued).
    Opened {
        /// The caps granted.
        caps: u16,
        /// Whether the viewer's input reaches this desktop.
        input: bool,
        /// The session was eligible for the clipboard and the desktop gave
        /// none: "This desktop did not allow clipboard sharing in this
        /// session."
        clipboard_refused: bool,
    },
    /// The caps left, or the ones paused, changed (`Caps` was queued): the
    /// viewer's input was lost, the host user turned services off, a lock
    /// paused them, or its end resumed them.
    Caps {
        /// The caps left.
        caps: u16,
        /// The caps paused.
        paused: u16,
    },
    /// The viewer wrote, sanitised ([`sanitize_peer_text`]).
    Chat(ChatText),
    /// The viewer put text on this computer's clipboard: "They put text on
    /// this computer's clipboard (`chars` characters)". Never the text.
    ClipIn {
        /// Its length in characters.
        chars: usize,
    },
    /// Text copied on this computer went to the viewer: "Copied text was
    /// sent to them (`chars` characters)". Never the text.
    ClipOut {
        /// Its length in characters.
        chars: usize,
    },
    /// A transfer started, moved on or ended. An upload is told once the
    /// inbox took it (refusals before that are not), at each credit, and at
    /// its end; its `Done` carries the stored, sanitised name, the one
    /// `sessions.log`'s `file_received` records. Every file put in place is
    /// told so. A stream's end tells no row of an upload it stopped (its
    /// files are deleted); one whose file was already being put in place is
    /// waited for up to [`ServicesLimits::workers_wait`], and when its rename
    /// outlasts that, its `Done` row comes after [`HostEvent::Closed`],
    /// whose summary does not count it.
    Transfer(TransferRow),
    /// The viewer has a whole copy of a file of this computer: it credited
    /// every byte and said `Complete` (after the file's `Done` row). For
    /// `sessions.log`'s `file_sent` record only: `path` is this computer's
    /// own (canonical) path of it, never shown to anyone else nor logged by
    /// `tracing`.
    FileSent {
        /// The transfer (its rows' id).
        xfer: u32,
        /// The file's path on this computer.
        path: HostPath,
        /// Its size in bytes.
        bytes: u64,
    },
    /// The stream ended.
    Closed {
        /// The `Close` reason written or received
        /// (`tornect_proto::services::reason`).
        reason: u16,
        /// What the stream carried.
        summary: ServicesSummary,
    },
}

/// What a services stream carried, in counts (never content): the host's
/// `sessions.log` summary line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServicesSummary {
    /// Clipboard texts the viewer put on this computer.
    pub clip_in: u32,
    /// Clipboard texts sent to the viewer.
    pub clip_out: u32,
    /// Files received.
    pub files_in: u32,
    /// Bytes of files received.
    pub bytes_in: u64,
    /// Files sent.
    pub files_out: u32,
    /// Bytes of files sent.
    pub bytes_out: u64,
    /// Chat messages received and shown.
    pub chat_in: u32,
    /// Chat messages sent.
    pub chat_out: u32,
    /// Messages and clipboard texts from the viewer dropped: over a rate,
    /// or with nothing to show or apply once checked (a clipboard text that
    /// is not UTF-8, holds a NUL, or holds only control characters).
    pub dropped: u32,
}
