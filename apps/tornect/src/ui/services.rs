//! The session services as the windows show them (design `services` §7):
//! the host's side of each shared session ([`HostServices`], from the
//! services host's events through [`GuiServices`]) and the viewer's side of
//! the session viewed ([`ViewerServices`], from its services stream). The
//! pages draw from these alone; what they hold of the other computer (chat,
//! names, folder titles) is sanitised text, shown as plain text, and none of
//! it is a path of this computer.

use std::sync::Arc;

use tornect_core::session_log::SessionLog;
use tornect_proto::services::{Welcome, caps, reason};
use tornect_session::services::{
    ChatText, HostEvent, ListingView, ServicesObserver, TransferRow, TransferState, Untrusted,
    ViewerEvent, ViewerServicesEnd,
};

use super::model::Shared;
use crate::host::say;
use crate::services::{Peer, Peers, log_record, reason_name};

/// Chat lines a card keeps, the oldest dropped first (design §7.2).
pub const CHAT_KEPT: usize = 200;

/// Clipboard lines the host's strip keeps: the last three (design §7.2).
pub const CLIPS_KEPT: usize = 3;

/// Ended transfer rows kept beside the running ones, the newest.
pub const ENDED_ROWS_KEPT: usize = 20;

/// The longest inbox words shown, in bytes (`Welcome.inbox` is at most 64
/// characters).
const INBOX_BYTES: usize = 256;

/// One chat line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatLine {
    /// The other computer's person wrote it (else this computer's).
    pub theirs: bool,
    /// What was written, sanitised.
    pub text: ChatText,
}

/// One clipboard event of a shared session (counts only, never the text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipNote {
    /// "Copied text was sent to them (`chars` characters)".
    Sent {
        /// The text's length in characters.
        chars: usize,
    },
    /// "They put text on this computer's clipboard (`chars` characters)".
    Received {
        /// The text's length in characters.
        chars: usize,
    },
}

/// Keep the newest `kept` of `lines`.
fn keep_last<T>(lines: &mut Vec<T>, kept: usize) {
    let extra = lines.len().saturating_sub(kept);
    lines.drain(..extra);
}

/// Put `row` in `rows` (its id names it), then keep every running row and
/// the newest [`ENDED_ROWS_KEPT`] ended ones.
fn put_row(rows: &mut Vec<TransferRow>, row: TransferRow) {
    match rows
        .iter_mut()
        .find(|r| r.xfer == row.xfer && r.dir == row.dir)
    {
        Some(held) => *held = row,
        None => rows.push(row),
    }
    let over = rows.iter().filter(|r| is_over(&r.state)).count();
    let mut extra = over.saturating_sub(ENDED_ROWS_KEPT);
    rows.retain(|r| {
        if extra > 0 && is_over(&r.state) {
            extra -= 1;
            false
        } else {
            true
        }
    });
}

/// Whether a transfer in `state` is over.
fn is_over(state: &TransferState) -> bool {
    matches!(
        state,
        TransferState::Done { .. } | TransferState::Failed(_) | TransferState::Cancelled(_)
    )
}

// --- The host's side ------------------------------------------------------

/// A shared session's services as the host's window shows them (design
/// §7.2): the strip, the chat card and the indicator read it. Set when the
/// stream opens; it goes with the session's row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostServices {
    /// The caps granted when the stream opened
    /// (`tornect_proto::services::caps`).
    pub granted: u16,
    /// The caps left: input lost or the host user's turn-off take some away
    /// for good.
    pub caps: u16,
    /// The caps paused while this computer is locked.
    pub paused: u16,
    /// The viewer's input reached this desktop when the stream opened.
    pub input: bool,
    /// The session could have had the clipboard and the desktop gave none:
    /// "This desktop did not allow clipboard sharing in this session."
    pub clipboard_refused: bool,
    /// The chat, oldest first, at most [`CHAT_KEPT`] lines.
    pub chat: Vec<ChatLine>,
    /// Lines from the other computer not yet seen (the chat card clears it).
    pub unread: usize,
    /// The transfers, in the order they started.
    pub transfers: Vec<TransferRow>,
    /// The last [`CLIPS_KEPT`] clipboard events, oldest first.
    pub clips: Vec<ClipNote>,
    /// The stream ended with this `tornect_proto::services::reason` code.
    pub ended: Option<u16>,
}

impl HostServices {
    /// A stream that opened with `caps`.
    #[must_use]
    pub fn opened(caps: u16, input: bool, clipboard_refused: bool) -> Self {
        Self {
            granted: caps,
            caps,
            input,
            clipboard_refused,
            ..Self::default()
        }
    }

    /// The caps in effect now: granted, not turned off, not paused.
    // Read by the host window's services strip (the design's step 25).
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn effective(&self) -> u16 {
        self.caps & !self.paused
    }

    /// The host user wrote `text` (it was queued for the viewer).
    pub fn said(&mut self, text: ChatText) {
        self.chat.push(ChatLine {
            theirs: false,
            text,
        });
        keep_last(&mut self.chat, CHAT_KEPT);
    }

    /// What `event` changes. `Opened` starts over; `FileSent` changes
    /// nothing here (its path is for `sessions.log` alone).
    pub fn apply(&mut self, event: &HostEvent) {
        match event {
            HostEvent::Opened {
                caps,
                input,
                clipboard_refused,
            } => *self = Self::opened(*caps, *input, *clipboard_refused),
            HostEvent::Caps { caps, paused } => {
                self.caps = *caps;
                self.paused = *paused;
            }
            HostEvent::Chat(text) => {
                self.chat.push(ChatLine {
                    theirs: true,
                    text: text.clone(),
                });
                keep_last(&mut self.chat, CHAT_KEPT);
                self.unread = self.unread.saturating_add(1);
            }
            HostEvent::ClipIn { chars } => {
                self.clips.push(ClipNote::Received { chars: *chars });
                keep_last(&mut self.clips, CLIPS_KEPT);
            }
            HostEvent::ClipOut { chars } => {
                self.clips.push(ClipNote::Sent { chars: *chars });
                keep_last(&mut self.clips, CLIPS_KEPT);
            }
            HostEvent::Transfer(row) => put_row(&mut self.transfers, row.clone()),
            HostEvent::FileSent { .. } => {}
            HostEvent::Closed { reason, .. } => self.ended = Some(*reason),
        }
    }
}

/// The window host's [`ServicesObserver`] (design §8): each event goes into
/// the shared session's row of the model, and what `sessions.log` records of
/// it (a file received or sent, the stream's summary) into the host's log.
pub(super) struct GuiServices {
    shared: Arc<Shared>,
    log: Arc<SessionLog>,
    peers: Peers,
}

impl GuiServices {
    /// Report into `shared`, log into `log` (the host's one handle on
    /// `sessions.log`).
    pub(super) fn new(shared: Arc<Shared>, log: Arc<SessionLog>) -> Self {
        Self {
            shared,
            log,
            peers: Peers::default(),
        }
    }

    /// A session started: its peer is kept for the lines its stream causes.
    pub(super) fn started(&self, peer: Peer) {
        self.peers.started(peer);
    }

    /// The peer of session `session_id`, if kept.
    pub(super) fn peer(&self, session_id: &str) -> Option<Peer> {
        self.peers.of(session_id)
    }

    /// The host's log.
    pub(super) fn log(&self) -> &Arc<SessionLog> {
        &self.log
    }
}

impl ServicesObserver for GuiServices {
    fn event(&self, session_id: &str, event: HostEvent) {
        if let Some(record) = log_record(session_id, self.peers.of(session_id).as_ref(), &event)
            && let Err(e) = self.log.append(&record)
        {
            tracing::warn!(error = %e, "could not append to sessions.log");
        }
        match &event {
            HostEvent::Opened { caps, input, .. } => say(format_args!(
                "SERVICES OPEN {session_id} caps={caps:#04x} input={input}"
            )),
            HostEvent::Closed { reason, .. } => say(format_args!(
                "SERVICES ENDED {session_id} ({})",
                reason_name(*reason)
            )),
            _ => {}
        }
        if matches!(event, HostEvent::FileSent { .. }) {
            return;
        }
        self.shared.update(|m| {
            let Some(sharing) = m.sharing.iter_mut().find(|s| s.session_id == session_id) else {
                return;
            };
            match (&mut sharing.services, &event) {
                (
                    services,
                    HostEvent::Opened {
                        caps,
                        input,
                        clipboard_refused,
                    },
                ) => {
                    *services = Some(HostServices::opened(*caps, *input, *clipboard_refused));
                }
                (Some(services), event) => services.apply(event),
                (None, _) => {}
            }
        });
    }
}

// --- The viewer's side ----------------------------------------------------

/// Where the viewed session's services stand.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ServicesState {
    /// The stream is being opened (after the picture's stream was bound).
    #[default]
    Opening,
    /// The host granted services ([`ViewerServices::granted`]).
    Open,
    /// The stream did not open: the host refused it with this
    /// `tornect_proto::services::reason` code, or it failed (`None`). "Chat
    /// and files are not available in this session."; the session goes on.
    Unavailable(Option<u16>),
    /// It ended, with this `tornect_proto::services::reason` code
    /// (`CAPTURE_STOPPED`: "Chat and files stopped because screen sharing
    /// stopped.").
    Ended(u16),
}

/// The viewed session's services as the stream window shows them (design
/// §7.1): its toolbar entries, the chat and files panels and their toasts
/// read it. Set when the host's signed `HELLO_ACK` offers the stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViewerServices {
    /// Where the stream stands.
    pub state: ServicesState,
    /// The caps the host granted (`Welcome.caps`).
    pub granted: u16,
    /// The caps left (`Caps`): they only shrink.
    pub caps: u16,
    /// The caps paused while the host is locked.
    pub paused: u16,
    /// The longest clipboard text either side sends, in bytes.
    pub clip_max: u32,
    /// The largest file either way, in bytes.
    pub file_max: u64,
    /// Where uploads land on the host, in its words ("Downloads ›
    /// Tornect"), sanitised; never a path.
    pub inbox: String,
    /// The toolbar's "Clipboard" switch (from `[viewer] clipboard_sync`).
    pub clipboard: bool,
    /// The stream window reads and sets this computer's clipboard for the
    /// session (`StreamLink::set_window_clipboard`, the design's step 24):
    /// only then does the toolbar offer the switch.
    pub shares_clipboard: bool,
    /// The chat, oldest first, at most [`CHAT_KEPT`] lines.
    pub chat: Vec<ChatLine>,
    /// Lines from the host so far: the stream window counts the ones its
    /// chat panel showed, and the toolbar's "Chat · 2" the ones after.
    pub unread: usize,
    /// The transfers, in the order they were asked for.
    pub transfers: Vec<TransferRow>,
    /// The host's folder shown in "Their files", its pages put together.
    pub remote: Option<ListingView>,
    /// Why the host's folder last asked for could not be listed.
    pub remote_failed: Option<u16>,
    /// This computer's folder shown in "Send files".
    pub local: Option<ListingView>,
    /// Why this computer's folder last asked for could not be listed.
    pub local_failed: Option<u16>,
}

impl ViewerServices {
    /// A stream being opened, the window's switch at `clipboard`.
    #[must_use]
    pub fn opening(clipboard: bool) -> Self {
        Self {
            clipboard,
            ..Self::default()
        }
    }

    /// The caps in effect now: granted, not taken away, not paused.
    #[must_use]
    pub fn effective(&self) -> u16 {
        self.left() & !self.paused
    }

    /// The caps left while the stream is open: granted and not taken away,
    /// paused or not (`tornect_proto::services::caps`); 0 before the
    /// `Welcome` and once the stream ended.
    #[must_use]
    pub fn left(&self) -> u16 {
        if self.state == ServicesState::Open {
            self.caps
        } else {
            0
        }
    }

    /// The host granted `welcome`.
    pub fn opened(&mut self, welcome: &Welcome) {
        self.state = ServicesState::Open;
        self.granted = welcome.caps;
        self.caps = welcome.caps;
        self.paused = 0;
        self.clip_max = welcome.clip_max;
        self.file_max = welcome.file_max;
        self.inbox = Untrusted::shown(&welcome.inbox, INBOX_BYTES)
            .as_str()
            .to_owned();
    }

    /// The stream did not open: the host refused it with `refused`, or it
    /// failed.
    pub fn not_opened(&mut self, refused: Option<u16>) {
        self.state = ServicesState::Unavailable(refused);
    }

    /// This computer's person wrote `text` (it was queued for the host).
    pub fn said(&mut self, text: ChatText) {
        self.chat.push(ChatLine {
            theirs: false,
            text,
        });
        keep_last(&mut self.chat, CHAT_KEPT);
    }

    /// What `event` changes.
    pub fn apply(&mut self, event: ViewerEvent) {
        match event {
            ViewerEvent::Caps { caps, paused } => {
                self.caps = caps;
                self.paused = paused;
                if caps & caps::BROWSE == 0 {
                    self.remote = None;
                }
            }
            ViewerEvent::Chat(text) => {
                self.chat.push(ChatLine { theirs: true, text });
                keep_last(&mut self.chat, CHAT_KEPT);
                self.unread = self.unread.saturating_add(1);
            }
            ViewerEvent::Transfer(row) => put_row(&mut self.transfers, row),
            ViewerEvent::Listing { remote, view } => {
                let (shown, failed) = if remote {
                    (&mut self.remote, &mut self.remote_failed)
                } else {
                    (&mut self.local, &mut self.local_failed)
                };
                *failed = None;
                add_page(shown, view);
            }
            ViewerEvent::ListFailed { remote, reason } => {
                if remote {
                    self.remote_failed = Some(reason);
                } else {
                    self.local_failed = Some(reason);
                }
            }
            ViewerEvent::Closed(code) => self.end(code),
        }
    }

    /// The stream's run returned with `end`. A close already reported
    /// stays as it was; the viewer's own stop (its session is over) changes
    /// nothing.
    pub fn finished(&mut self, end: ViewerServicesEnd) {
        if matches!(self.state, ServicesState::Ended(_)) {
            return;
        }
        match end {
            ViewerServicesEnd::Stopped => {}
            ViewerServicesEnd::Closed(code) | ViewerServicesEnd::Refused(code) => self.end(code),
            ViewerServicesEnd::Io => self.end(reason::IO),
        }
    }

    fn end(&mut self, code: u16) {
        self.state = ServicesState::Ended(code);
        self.caps = 0;
        self.paused = 0;
    }
}

/// Put `page` into `shown`: a first page (`from` 0), or a page of another
/// folder, starts the folder again; a next page of the same folder adds its
/// entries.
fn add_page(shown: &mut Option<ListingView>, page: ListingView) {
    match shown {
        Some(folder) if page.from != 0 && folder.folder == page.folder => {
            folder.entries.extend(page.entries);
            folder.more = page.more;
            folder.truncated |= page.truncated;
        }
        _ => *shown = Some(page),
    }
}

#[cfg(test)]
mod tests {
    use tornect_session::services::{Direction, EntryKind, EntryView, sanitize_peer_text};

    use super::*;

    fn text(s: &str) -> ChatText {
        sanitize_peer_text(s).unwrap()
    }

    fn row(xfer: u32, state: TransferState) -> TransferRow {
        TransferRow {
            xfer,
            dir: Direction::ToHost,
            name: Untrusted::file_name("a.txt"),
            size: 10,
            done: 0,
            state,
        }
    }

    /// The host's card: caps and pauses follow the events, the chat keeps
    /// 200 lines and counts the unread ones, the clipboard lines keep the
    /// last three, a transfer is one row however often it is reported, and
    /// a sent file's path never reaches the model.
    #[test]
    fn the_host_card_follows_the_stream() {
        let mut card = HostServices::opened(caps::CHAT | caps::CLIP | caps::UPLOAD, true, false);
        assert_eq!(card.effective(), caps::CHAT | caps::CLIP | caps::UPLOAD);
        card.apply(&HostEvent::Caps {
            caps: caps::CHAT | caps::CLIP | caps::UPLOAD,
            paused: caps::CLIP | caps::UPLOAD,
        });
        assert_eq!(card.effective(), caps::CHAT);
        card.apply(&HostEvent::Caps {
            caps: caps::CHAT,
            paused: 0,
        });
        assert_eq!((card.granted, card.caps), (0x07, caps::CHAT));
        for n in 0..250 {
            card.apply(&HostEvent::Chat(text(&format!("line {n}"))));
        }
        card.said(text("mine"));
        assert_eq!(card.chat.len(), CHAT_KEPT);
        assert_eq!(card.unread, 250);
        assert_eq!(card.chat.last().unwrap().text.as_str(), "mine");
        assert!(!card.chat.last().unwrap().theirs);
        assert_eq!(card.chat[0].text.as_str(), "line 51");
        for chars in 1..=5 {
            card.apply(&HostEvent::ClipIn { chars });
        }
        card.apply(&HostEvent::ClipOut { chars: 9 });
        assert_eq!(
            card.clips,
            [
                ClipNote::Received { chars: 4 },
                ClipNote::Received { chars: 5 },
                ClipNote::Sent { chars: 9 }
            ]
        );
        card.apply(&HostEvent::Transfer(row(1, TransferState::Running)));
        card.apply(&HostEvent::Transfer(row(1, TransferState::Stalled)));
        card.apply(&HostEvent::Transfer(row(
            1,
            TransferState::Done {
                stored: Untrusted::file_name("a.txt"),
            },
        )));
        assert_eq!(card.transfers.len(), 1);
        let before = card.clone();
        card.apply(&HostEvent::FileSent {
            xfer: 1,
            path: test_path(),
            bytes: 10,
        });
        assert_eq!(card, before, "a host path never reaches the model");
        card.apply(&HostEvent::Closed {
            reason: reason::SESSION_OVER,
            summary: tornect_session::services::ServicesSummary::default(),
        });
        assert_eq!(card.ended, Some(reason::SESSION_OVER));
    }

    /// A path of this computer, as a download's `FileSent` names it.
    fn test_path() -> tornect_session::services::HostPath {
        tornect_session::services::HostPath::new(std::path::PathBuf::from("/home/u/plan.odt"))
    }

    /// Running rows stay, and only the newest ended ones are kept.
    #[test]
    fn ended_rows_are_bounded_and_running_ones_kept() {
        let mut rows = Vec::new();
        put_row(&mut rows, row(1, TransferState::Running));
        for xfer in 2..40 {
            put_row(&mut rows, row(xfer, TransferState::Failed(reason::IO)));
        }
        assert_eq!(rows.len(), 1 + ENDED_ROWS_KEPT);
        assert_eq!(rows[0].xfer, 1);
        assert_eq!(rows.last().unwrap().xfer, 39);
    }

    fn welcome(caps: u16) -> Welcome {
        Welcome {
            caps,
            clip_max: 1000,
            file_max: 2000,
            session_quota: 4000,
            session_files: 10,
            chat_max: 8000,
            bulk_window: 1 << 18,
            inbox: "Downloads \u{202e}› Tornect".to_owned(),
        }
    }

    fn page(folder: u32, from: u32, names: &[&str], more: bool) -> ListingView {
        ListingView {
            folder,
            title: Untrusted::shown("/home/x", 64),
            parent: Some(0),
            from,
            entries: names
                .iter()
                .enumerate()
                .map(|(i, name)| EntryView {
                    name: Untrusted::shown(name, 255),
                    handle: from + u32::try_from(i).unwrap() + 1,
                    kind: EntryKind::File,
                    size: Some(1),
                    mtime: None,
                    lossy: false,
                })
                .collect(),
            more,
            truncated: false,
        }
    }

    /// The viewer's card: the welcome's words are sanitised, a folder's
    /// pages are put together and a first page starts it again, a failure
    /// is kept until the next page, `Caps` shrink and pause, and the end
    /// says why (the stream's own close first).
    #[test]
    fn the_viewer_card_follows_the_stream() {
        let mut card = ViewerServices::opening(true);
        assert_eq!(card.effective(), 0, "nothing before the welcome");
        card.opened(&welcome(caps::CHAT | caps::UPLOAD | caps::BROWSE));
        assert_eq!(card.state, ServicesState::Open);
        assert_eq!(card.inbox, "Downloads › Tornect", "no bidi control shown");
        assert_eq!(card.effective(), caps::CHAT | caps::UPLOAD | caps::BROWSE);
        card.apply(ViewerEvent::Listing {
            remote: true,
            view: page(5, 0, &["a", "b"], true),
        });
        card.apply(ViewerEvent::Listing {
            remote: true,
            view: page(5, 2, &["c"], false),
        });
        let shown = card.remote.as_ref().unwrap();
        assert_eq!(shown.entries.len(), 3);
        assert!(!shown.more);
        card.apply(ViewerEvent::ListFailed {
            remote: true,
            reason: reason::DENIED,
        });
        assert_eq!(card.remote_failed, Some(reason::DENIED));
        card.apply(ViewerEvent::Listing {
            remote: true,
            view: page(9, 0, &["z"], false),
        });
        assert_eq!(card.remote.as_ref().unwrap().entries.len(), 1);
        assert_eq!(card.remote_failed, None);
        card.apply(ViewerEvent::Listing {
            remote: false,
            view: page(0, 0, &["Home"], false),
        });
        assert_eq!(card.local.as_ref().unwrap().folder, 0);
        card.apply(ViewerEvent::Caps {
            caps: caps::CHAT | caps::UPLOAD | caps::BROWSE,
            paused: caps::UPLOAD | caps::BROWSE,
        });
        assert_eq!(card.effective(), caps::CHAT);
        card.apply(ViewerEvent::Caps {
            caps: caps::CHAT,
            paused: 0,
        });
        assert!(card.remote.is_none(), "browsing went, and its folder");
        card.apply(ViewerEvent::Chat(text("hello")));
        assert_eq!(card.unread, 1);
        card.apply(ViewerEvent::Closed(reason::CAPTURE_STOPPED));
        card.finished(ViewerServicesEnd::Closed(reason::CAPTURE_STOPPED));
        card.finished(ViewerServicesEnd::Io);
        assert_eq!(card.state, ServicesState::Ended(reason::CAPTURE_STOPPED));
        assert_eq!(card.effective(), 0);

        let mut stopped = ViewerServices::opening(false);
        stopped.opened(&welcome(caps::CHAT));
        stopped.finished(ViewerServicesEnd::Stopped);
        assert_eq!(stopped.state, ServicesState::Open, "its session is over");
        let mut failed = ViewerServices::opening(false);
        failed.not_opened(None);
        assert_eq!(failed.state, ServicesState::Unavailable(None));
        failed.finished(ViewerServicesEnd::Io);
        assert_eq!(failed.state, ServicesState::Ended(reason::IO));
    }
}
