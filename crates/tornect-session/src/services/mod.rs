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
//! The stream is built in the design's steps: this build has the bind, the
//! live wait, the caps, chat both ways, uploads and the close paths.
//! Browsing, downloads, the clipboard and the lock pause come with the
//! design's steps 16–19; until then their frames, when granted, are read and
//! left unanswered, and a granted clipboard link is held inactive, so the
//! backend reads and sets nothing.
//!
//! [`MediaHost`]: crate::MediaHost

use std::path::PathBuf;
use std::time::Duration;

use tornect_core::session_log::SessionMode;
use tornect_proto::services::caps;

pub mod chat;
mod host;
mod reader;
mod store;
mod transfer;
mod upload;
mod viewer;
mod window;
mod writer;

#[cfg(test)]
mod tests;

pub use chat::{CHAT_BURST, CHAT_RATE, ChatText, sanitize_peer_text};
pub use host::{ServicesHost, ServicesOutcome, refuse};
pub use reader::ReaderCounts;
pub use store::{FreeSpaceFn, RECHECK_FREE_EVERY};
pub use transfer::{Direction, MAX_UPLOADS, TransferRow, TransferState, Untrusted};
pub use viewer::{
    ServicesBindError, ServicesBinding, ServicesViewer, ViewerEvent, ViewerOp, ViewerServicesEnd,
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
}

impl Default for ServicesEnv {
    /// No inbox, and no free space known.
    fn default() -> Self {
        Self {
            inbox: None,
            inbox_words: String::new(),
            free_space: store::unknown_free_space(),
        }
    }
}

impl std::fmt::Debug for ServicesEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServicesEnv")
            .field("inbox", &self.inbox.is_some())
            .field("inbox_words", &self.inbox_words)
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
    /// viewer's input was lost, the host user turned services off, or a lock
    /// paused them.
    Caps {
        /// The caps left.
        caps: u16,
        /// The caps paused.
        paused: u16,
    },
    /// The viewer wrote, sanitised ([`sanitize_peer_text`]).
    Chat(ChatText),
    /// A transfer started, moved on or ended. An upload is told once the
    /// inbox took it (refusals before that are not), at each credit, and at
    /// its end; its `Done` carries the stored, sanitised name, the one
    /// `sessions.log`'s `file_received` records.
    Transfer(TransferRow),
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
    /// Messages from the viewer dropped: over a rate, or with nothing to
    /// show once sanitised.
    pub dropped: u32,
}
