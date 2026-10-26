//! The host's side of a shared session's services in the main window (the
//! services design §7.2), both in the sharing banner under the session's
//! line: the strip (what the viewer may do with chat, the clipboard and
//! files, the transfers, the clipboard's last events, the one-way turn-off)
//! and the chat card.
//!
//! Everything they show of the other computer (chat lines, file names) is
//! sanitised text from the services stream, shown as plain text; a file's
//! name is cut to 40 characters and sits on a line of its own, never on the
//! banner's mode and clock line (SLICE-E E1-2). No line names a path of this
//! computer: a received file is said by its stored name and the inbox's
//! words, a copied one by its name.

use std::collections::HashMap;

use egui::RichText;
use tornect_proto::services::{MAX_CHAT_CHARS, caps, reason};
use tornect_session::services::{Direction, TransferRow, TransferState, sanitize_peer_text};

use super::super::model::Sharing;
use super::super::pages::viewer::{cut_name, percent, size_text};
use super::super::services::{ChatLine, ClipNote, HostServices};
use super::super::theme::{self, Face};
use super::super::widgets;
use super::{Action, shown, stop_button};

/// The strip's one-way button: this session only, never back.
pub const TURN_OFF: &str = "Turn off clipboard and files";

/// A control session whose input reaches nothing on this desktop.
pub const NO_INPUT: &str =
    "Only chat: their input does not reach this desktop, so files and the clipboard are off.";

/// While this computer is locked.
pub const PAUSED: &str = "Files and the clipboard are paused while this computer is locked.";

/// The session could have had the clipboard and the desktop gave none.
pub const CLIPBOARD_REFUSED: &str = "This desktop did not allow clipboard sharing in this session.";

/// A running transfer's button.
pub const CANCEL: &str = "Cancel";

/// The chat field's hint.
pub const WRITE: &str = "Write a message";

/// The chat card's button.
pub const SEND: &str = "Send";

/// The chat card's footer.
pub const NOT_SAVED: &str = "Not saved. It ends with the session.";

/// Where this computer keeps what it receives, in words: never a path.
const INBOX_WORDS: &str = "Downloads › Tornect";

/// What the turn-off takes away: the clipboard and files (chat stays).
const CLIP_AND_FILES: u16 = caps::CLIP | caps::UPLOAD | caps::BROWSE;

/// Ended transfers the strip shows beside the running ones, the newest.
const ENDED_SHOWN: usize = 3;

/// The chat card's history, at most this tall, in points: the card sits in
/// the banner, above every page.
const HISTORY_HEIGHT: f32 = 120.0;

/// The chat card's widest, in points.
const CHAT_WIDTH: f32 = 520.0;

/// What the host's person does on the strip or the chat card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostServicesAction {
    /// Send what the chat card's field holds.
    Send,
    /// Stop the transfer whose row has this id.
    Cancel(u32),
    /// "Turn off clipboard and files" for the rest of the session.
    TurnOff,
    /// The chat card showed every line in a window that has the focus:
    /// none is unread any more.
    Read,
}

/// The strip's first line: what is in effect now (granted, not turned off,
/// not paused), such as `Chat on · Clipboard shared both ways · They can
/// send files and see and copy your files`; `None` when nothing is.
#[must_use]
pub fn summary(services: &HostServices) -> Option<String> {
    let on = services.effective();
    let files = match (on & caps::UPLOAD != 0, on & caps::BROWSE != 0) {
        (true, true) => Some("They can send files and see and copy your files"),
        (true, false) => Some("They can send files"),
        (false, true) => Some("They can see and copy your files"),
        (false, false) => None,
    };
    let parts: Vec<&str> = [
        (on & caps::CHAT != 0).then_some("Chat on"),
        (on & caps::CLIP != 0).then_some("Clipboard shared both ways"),
        files,
    ]
    .into_iter()
    .flatten()
    .collect();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

/// Whether the strip says [`NO_INPUT`]: a control session whose input did
/// not reach this desktop when the stream opened, or stopped reaching it.
/// A view-only session's banner says so already.
#[must_use]
pub fn no_input(sharing: &Sharing, services: &HostServices) -> bool {
    sharing.control && (!services.input || sharing.capture.as_ref().is_some_and(|c| !c.input))
}

/// Whether the strip says [`PAUSED`]: the clipboard or files the session
/// still has are held while this computer is locked.
#[must_use]
pub fn paused(services: &HostServices) -> bool {
    services.caps & services.paused & CLIP_AND_FILES != 0
}

/// A clipboard event as the strip says it (counts only, never the text).
#[must_use]
pub fn clip_line(note: ClipNote) -> String {
    match note {
        ClipNote::Sent { chars } => format!("Copied text was sent to them ({chars} characters)"),
        ClipNote::Received { chars } => {
            format!("They put text on this computer's clipboard ({chars} characters)")
        }
    }
}

/// Whether a transfer in `state` can still be stopped.
fn runs(state: &TransferState) -> bool {
    matches!(
        state,
        TransferState::Queued | TransferState::Running | TransferState::Stalled
    )
}

/// A transfer as the strip says it, without its Cancel (the services
/// design §7.2): `Receiving "a.txt" · 45%`, `They are copying "a.txt" ·
/// 45%`, `Received "a (2).txt" (12 MB) in Downloads › Tornect`, `They
/// copied "a.txt" (12 MB)`; `waiting` before it starts, `paused` while this
/// computer is locked, and why one that ended without its file did.
#[must_use]
pub fn transfer_line(row: &TransferRow) -> String {
    let name = cut_name(row.name.as_str());
    let received = row.dir == Direction::ToHost;
    let going = if received {
        format!("Receiving \"{name}\"")
    } else {
        format!("They are copying \"{name}\"")
    };
    match &row.state {
        TransferState::Queued => format!("{going} · waiting"),
        TransferState::Stalled => format!("{going} · paused"),
        TransferState::Running => format!("{going} · {}%", percent(row.done, row.size)),
        TransferState::Done { stored } if received => format!(
            "Received \"{}\" ({}) in {INBOX_WORDS}",
            cut_name(stored.as_str()),
            size_text(row.size)
        ),
        TransferState::Done { .. } => {
            format!("They copied \"{name}\" ({})", size_text(row.size))
        }
        TransferState::Failed(code) | TransferState::Cancelled(code) => {
            let not = if received {
                "was not received"
            } else {
                "was not copied"
            };
            format!("\"{name}\" {not}: {}", ending(*code, row.dir))
        }
    }
}

/// Why a transfer ended without its file, as the end of the strip's line:
/// said from this computer's side.
#[must_use]
pub fn ending(code: u16, dir: Direction) -> &'static str {
    let received = dir == Direction::ToHost;
    match code {
        reason::NO_SPACE if received => "this computer has no room for it.",
        reason::NO_SPACE => "their computer has no room for it.",
        reason::TOO_LARGE | reason::QUOTA if received => "it is larger than this computer accepts.",
        reason::TOO_LARGE | reason::QUOTA => "it is larger than their computer accepts.",
        reason::BY_HOST => "you stopped it.",
        reason::BY_VIEWER => "they stopped it.",
        reason::TURNED_OFF => "file transfer was turned off.",
        reason::CHANGED => "it changed while it was being sent.",
        reason::CORRUPT => "it arrived damaged and was deleted.",
        reason::LOCKED => "this computer is locked.",
        reason::CAPTURE_STOPPED | reason::SESSION_OVER | reason::ENDED_BY_HOST => {
            "the session ended."
        }
        _ => "it could not be copied.",
    }
}

/// The transfers the strip shows, oldest first: every running one and the
/// newest [`ENDED_SHOWN`] that ended.
fn shown_rows(transfers: &[TransferRow]) -> impl Iterator<Item = &TransferRow> {
    let ended = transfers.iter().filter(|r| !runs(&r.state)).count();
    let mut skip = ended.saturating_sub(ENDED_SHOWN);
    transfers.iter().filter(move |r| {
        if skip > 0 && !runs(&r.state) {
            skip -= 1;
            false
        } else {
            true
        }
    })
}

/// The strip under `sharing`'s banner, once its services stream opened and
/// for as long as it runs: the summary with the turn-off, the no-input,
/// refused-clipboard and paused lines, the transfers with Cancel while they
/// run, and the last clipboard events.
pub(super) fn services_strip(ui: &mut egui::Ui, sharing: &Sharing, actions: &mut Vec<Action>) {
    let Some(services) = &sharing.services else {
        return;
    };
    if services.ended.is_some() {
        return;
    }
    let t = theme::tokens(ui.ctx());
    let line = |ui: &mut egui::Ui, text: &str| {
        ui.add(egui::Label::new(RichText::new(text).small().color(t.on_sharing)).wrap());
    };
    let act = |op| Action::HostServices {
        session_id: sharing.session_id.clone(),
        op,
    };
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if services.caps & CLIP_AND_FILES != 0 && stop_button(ui, TURN_OFF).clicked() {
                actions.push(act(HostServicesAction::TurnOff));
            }
            if let Some(summary) = summary(services) {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(summary).small().color(t.on_sharing)).wrap(),
                    );
                });
            }
        });
    });
    if no_input(sharing, services) {
        line(ui, NO_INPUT);
    }
    if services.clipboard_refused {
        line(ui, CLIPBOARD_REFUSED);
    }
    if paused(services) {
        line(ui, PAUSED);
    }
    for row in shown_rows(&services.transfers) {
        ui.horizontal(|ui| {
            line(ui, &transfer_line(row));
            if runs(&row.state) && ui.small_button(CANCEL).clicked() {
                actions.push(act(HostServicesAction::Cancel(row.xfer)));
            }
        });
    }
    for note in &services.clips {
        line(ui, &clip_line(*note));
    }
}

/// A chat line as the card shows it, `"<label>": …` or `You: …`, its text
/// sanitised once more before display; `None` when nothing visible is left.
#[must_use]
pub fn chat_line(label: &str, line: &ChatLine) -> Option<String> {
    let text = sanitize_peer_text(line.text.as_str())?;
    if line.theirs {
        Some(format!("\"{}\": {}", shown(label), text.as_str()))
    } else {
        Some(format!("You: {}", text.as_str()))
    }
}

/// `sharing`'s services when their chat was granted.
fn chat_of(sharing: &Sharing) -> Option<&HostServices> {
    sharing
        .services
        .as_ref()
        .filter(|s| s.granted & caps::CHAT != 0)
}

/// The chat card of a shared session whose chat was granted, under its
/// strip: its history, and while chat is on, the field (`drafts` holds what
/// is typed, by session) and Send (Enter also sends). Shown in a window with
/// the focus, its lines count as read.
pub(super) fn chat_card(
    ui: &mut egui::Ui,
    sharing: &Sharing,
    drafts: &mut HashMap<String, String>,
    actions: &mut Vec<Action>,
) {
    let Some(services) = chat_of(sharing) else {
        return;
    };
    let t = theme::tokens(ui.ctx());
    let id = &sharing.session_id;
    let act = |op| Action::HostServices {
        session_id: id.clone(),
        op,
    };
    ui.add_space(6.0);
    ui.push_id(("host-chat", id), |ui| {
        widgets::card_frame(t, 10, egui::Margin::symmetric(14, 10)).show(ui, |ui| {
            ui.set_width(ui.available_width().min(CHAT_WIDTH));
            ui.label(
                RichText::new(format!("Chat with \"{}\"", shown(&sharing.label)))
                    .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                    .color(t.text_primary),
            );
            egui::ScrollArea::vertical()
                .id_salt("lines")
                .max_height(HISTORY_HEIGHT)
                .auto_shrink([false, true])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &services.chat {
                        if let Some(text) = chat_line(&sharing.label, line) {
                            ui.add(
                                egui::Label::new(RichText::new(text).color(t.text_primary)).wrap(),
                            );
                        }
                    }
                });
            if services.ended.is_none() && services.caps & caps::CHAT != 0 {
                ui.horizontal(|ui| {
                    let draft = drafts.entry(id.clone()).or_default();
                    let field = ui.add(
                        egui::TextEdit::singleline(draft)
                            .hint_text(WRITE)
                            .char_limit(MAX_CHAT_CHARS)
                            .desired_width((ui.available_width() - 72.0).max(80.0)),
                    );
                    let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.button(SEND).clicked() || enter {
                        actions.push(act(HostServicesAction::Send));
                        field.request_focus();
                    }
                });
            }
            ui.label(RichText::new(NOT_SAVED).small().color(t.text_muted));
        });
    });
    if services.unread > 0 && ui.ctx().input(|i| i.focused) {
        actions.push(act(HostServicesAction::Read));
    }
}

#[cfg(test)]
mod tests {
    use tornect_session::services::Untrusted;

    use super::*;

    fn row(xfer: u32, dir: Direction, state: TransferState) -> TransferRow {
        TransferRow {
            xfer,
            dir,
            name: Untrusted::file_name("report.pdf"),
            size: 12_000_000,
            done: 5_400_000,
            state,
        }
    }

    /// The summary lists only what is in effect, in the design's words.
    #[test]
    fn the_summary_lists_only_what_is_in_effect() {
        let all = HostServices::opened(caps::ALL, true, false);
        assert_eq!(
            summary(&all).as_deref(),
            Some(
                "Chat on · Clipboard shared both ways · They can send files and see and copy \
                 your files"
            )
        );
        let mut card = all.clone();
        card.paused = caps::CLIP | caps::UPLOAD | caps::BROWSE;
        assert_eq!(summary(&card).as_deref(), Some("Chat on"));
        assert!(paused(&card));
        card.caps = caps::CHAT;
        assert!(!paused(&card), "nothing left to pause");
        let upload = HostServices::opened(caps::CHAT | caps::UPLOAD, true, false);
        assert_eq!(
            summary(&upload).as_deref(),
            Some("Chat on · They can send files")
        );
        let browse = HostServices::opened(caps::BROWSE, true, false);
        assert_eq!(
            summary(&browse).as_deref(),
            Some("They can see and copy your files")
        );
        assert_eq!(summary(&HostServices::opened(0, true, false)), None);
    }

    /// Every transfer line says where its file stands from this computer's
    /// side, by its name cut to 40 characters, never by a path.
    #[test]
    fn transfer_lines_say_where_each_file_stands() {
        let stored = Untrusted::file_name("report (2).pdf");
        let cases = [
            (
                row(1, Direction::ToHost, TransferState::Running),
                "Receiving \"report.pdf\" · 45%",
            ),
            (
                row(2, Direction::FromHost, TransferState::Running),
                "They are copying \"report.pdf\" · 45%",
            ),
            (
                row(3, Direction::ToHost, TransferState::Done { stored }),
                "Received \"report (2).pdf\" (12 MB) in Downloads › Tornect",
            ),
            (
                row(
                    4,
                    Direction::FromHost,
                    TransferState::Done {
                        stored: Untrusted::file_name("report.pdf"),
                    },
                ),
                "They copied \"report.pdf\" (12 MB)",
            ),
            (
                row(5, Direction::ToHost, TransferState::Stalled),
                "Receiving \"report.pdf\" · paused",
            ),
            (
                row(6, Direction::FromHost, TransferState::Queued),
                "They are copying \"report.pdf\" · waiting",
            ),
            (
                row(
                    7,
                    Direction::ToHost,
                    TransferState::Failed(reason::NO_SPACE),
                ),
                "\"report.pdf\" was not received: this computer has no room for it.",
            ),
            (
                row(
                    8,
                    Direction::FromHost,
                    TransferState::Cancelled(reason::BY_HOST),
                ),
                "\"report.pdf\" was not copied: you stopped it.",
            ),
        ];
        for (row, expected) in cases {
            assert_eq!(transfer_line(&row), expected);
        }
        let mut long = row(9, Direction::ToHost, TransferState::Running);
        long.name = Untrusted::file_name(&format!("{}.txt", "n".repeat(60)));
        let line = transfer_line(&long);
        assert_eq!(line, format!("Receiving \"{}…\" · 45%", "n".repeat(40)));
    }

    /// The strip keeps every running transfer and the newest three that
    /// ended.
    #[test]
    fn the_strip_shows_running_transfers_and_the_last_three_ended() {
        let mut rows = vec![row(1, Direction::ToHost, TransferState::Running)];
        for xfer in 2..8 {
            rows.push(row(
                xfer,
                Direction::ToHost,
                TransferState::Failed(reason::IO),
            ));
        }
        rows.push(row(8, Direction::FromHost, TransferState::Stalled));
        let shown: Vec<u32> = shown_rows(&rows).map(|r| r.xfer).collect();
        assert_eq!(shown, [1, 5, 6, 7, 8]);
    }

    /// The clipboard lines give counts, never text.
    #[test]
    fn clipboard_lines_count_characters() {
        assert_eq!(
            clip_line(ClipNote::Sent { chars: 12 }),
            "Copied text was sent to them (12 characters)"
        );
        assert_eq!(
            clip_line(ClipNote::Received { chars: 3 }),
            "They put text on this computer's clipboard (3 characters)"
        );
    }
}
