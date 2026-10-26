//! The stream window's services panels (the services design §7.1): Chat and
//! Files, each an area at the window's right under the toolbar's lines,
//! drawn while the toolbar shows (an open panel keeps it shown). Their rects
//! go into the window's areas, so nothing pressed on them reaches the host.
//!
//! Everything they show of the other computer (chat lines, names, folder
//! titles, the inbox words) is sanitised text from the services stream,
//! shown as plain text; none of it is a path of this computer. While this
//! computer's own screen is shared, the chat's history and everything of
//! the files panel give way to the hidden card, and the chat's title names
//! nobody.

use std::time::{SystemTime, UNIX_EPOCH};

use egui::{CornerRadius, RichText, Stroke, vec2};
use tornect_core::address_book::Day;
use tornect_proto::services::{MAX_CHAT_CHARS, caps, reason};
use tornect_session::services::{
    Direction, EntryKind, EntryView, TransferRow, TransferState, sanitize_peer_text,
};

use super::super::super::model::{ViewerServices, Viewing};
use super::super::super::services::ChatLine;
use super::super::super::theme::{self, Tokens};
use super::super::super::view::Action;
use super::{ViewerAction, ViewerState};

/// The chat panel's width, in points.
const CHAT_WIDTH: f32 = 320.0;

/// The files panel's width, in points.
const FILES_WIDTH: f32 = 440.0;

/// A row of a folder's listing, in points.
const ROW_HEIGHT: f32 = 24.0;

/// The panel's height left for its lines (or rows) never goes below this.
const MIN_LINES: f32 = 80.0;

/// What a panel takes besides its lines: its title, field or tabs, footer
/// and margins, and the relay strip below the picture.
const CHROME: f32 = 170.0;

/// The longest file name a transfer line shows, in characters (longer ones
/// are cut, with "…").
const NAME_CHARS: usize = 40;

/// The chat panel's title while this screen is shared (it names nobody).
pub const CHAT_TITLE: &str = "Chat";

/// The chat field's hint.
pub const WRITE: &str = "Write a message";

/// The chat panel's button, and a file row's in "Send files".
pub const SEND: &str = "Send";

/// The chat panel's footer.
pub const NOT_SAVED: &str = "Not saved. It ends with the session.";

/// What the hidden card says in the chat panel.
pub const CHAT_HIDDEN: &str = "Messages show again once this screen is no longer shared.";

/// What the hidden card says in the files panel.
pub const FILES_HIDDEN: &str =
    "Folders, file names and transfers show again once this screen is no longer shared.";

/// The button to the folder above.
pub const UP: &str = "Up";

/// A file row's button in "Their files".
pub const DOWNLOAD: &str = "Download";

/// A running transfer's button.
pub const CANCEL: &str = "Cancel";

/// The footer of "Their files".
pub const THEIR_FOOTER: &str = "Downloads go to Downloads › Tornect on this computer.";

/// A folder that could not be listed.
pub const CANNOT_OPEN: &str = "This folder cannot be opened.";

/// A folder the other computer would not list: one of Tornect's own.
pub const OWN_FOLDERS: &str = "Tornect does not share its own folders.";

/// A folder listed only in part.
pub const TRUNCATED: &str = "Only the first 10,000 items are shown.";

/// "Send files" where files dropped on the window reach it.
pub const DROP_HINT: &str = "You can also drop files on this window.";

/// Both tabs while the host is locked.
pub const PAUSED: &str = "Paused while the other computer is locked or showing a secure screen.";

/// After a name shown approximately (it was not valid Unicode, or lost
/// characters that are not shown).
pub const LOSSY: &str = "(name shown approximately)";

/// A request of the Files panel for the session's services stream
/// (`tornect_session::services::ViewerOp`): handles only, never a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    /// List the other computer's folder with this handle (0: its places).
    OpenRemote(u32),
    /// Copy the other computer's file with this handle into Downloads ›
    /// Tornect here.
    Download(u32),
    /// List this computer's folder with this handle (0: its places).
    OpenLocal(u32),
    /// Send this computer's file with this handle.
    Send(u32),
    /// Stop the transfer whose row has this id.
    Cancel(u32),
}

impl FileOp {
    /// The cap the request needs (`tornect_proto::services::caps`); a
    /// cancel needs either of the files' caps.
    #[must_use]
    pub fn needs(self) -> u16 {
        match self {
            Self::OpenRemote(_) | Self::Download(_) => caps::BROWSE,
            Self::OpenLocal(_) | Self::Send(_) => caps::UPLOAD,
            Self::Cancel(_) => caps::UPLOAD | caps::BROWSE,
        }
    }
}

/// The Files panel's tabs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FilesTab {
    /// The other computer's folders: browse and download.
    #[default]
    Theirs,
    /// This computer's folders: send files.
    Mine,
}

impl FilesTab {
    /// The tabs, in order.
    pub const ALL: [Self; 2] = [Self::Theirs, Self::Mine];

    /// The cap the tab needs.
    #[must_use]
    pub fn cap(self) -> u16 {
        match self {
            Self::Theirs => caps::BROWSE,
            Self::Mine => caps::UPLOAD,
        }
    }

    /// Its words.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Theirs => "Their files",
            Self::Mine => "Send files",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Theirs => 0,
            Self::Mine => 1,
        }
    }

    /// The tab shown when `wanted` is asked for and `offer` is offered:
    /// `wanted` if offered, else the first one offered.
    #[must_use]
    pub fn shown(wanted: Self, offer: u16) -> Option<Self> {
        if offer & wanted.cap() != 0 {
            return Some(wanted);
        }
        Self::ALL.into_iter().find(|tab| offer & tab.cap() != 0)
    }
}

/// The frame of a panel, on the toolbar's surface.
fn panel_frame(t: &Tokens) -> egui::Frame {
    egui::Frame::new()
        .fill(t.surface_overlay)
        .stroke(Stroke::new(1.0, t.border_subtle))
        .corner_radius(CornerRadius::same(10))
        .shadow(t.popup_shadow)
        .inner_margin(egui::Margin::same(12))
}

/// The height a panel `y` points below the window's top leaves for its
/// lines.
fn lines_height(ctx: &egui::Context, y: f32) -> f32 {
    (ctx.content_rect().height() - y - CHROME).max(MIN_LINES)
}

/// The chat panel, `y` points below the window's top: its history (the
/// hidden card while this screen is shared), the field and Send. Esc closes
/// it. Returns where it was drawn.
pub(super) fn chat(
    ctx: &egui::Context,
    v: &Viewing,
    services: &ViewerServices,
    y: f32,
    actions: &mut Vec<Action>,
    viewer: &mut ViewerState,
) -> egui::Rect {
    let t = theme::tokens(ctx);
    let height = lines_height(ctx, y);
    let area = egui::Area::new(egui::Id::new("viewer-chat"))
        .anchor(egui::Align2::RIGHT_TOP, vec2(-12.0, y))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            panel_frame(t).show(ui, |ui| {
                ui.set_width(CHAT_WIDTH);
                let title = if viewer.shared {
                    CHAT_TITLE.to_owned()
                } else {
                    format!("Chat with \"{}\"", v.host)
                };
                ui.label(RichText::new(title).strong());
                if viewer.shared {
                    super::super::hidden_card(ui, CHAT_HIDDEN);
                } else {
                    viewer.chat_seen = services.unread;
                    egui::ScrollArea::vertical()
                        .id_salt("viewer-chat-lines")
                        .max_height(height)
                        .auto_shrink([false, true])
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in &services.chat {
                                if let Some(text) = chat_line(&v.host, line) {
                                    ui.add(egui::Label::new(text).wrap());
                                }
                            }
                        });
                }
                ui.horizontal(|ui| {
                    let field = ui.add(
                        egui::TextEdit::singleline(&mut viewer.chat_draft.0)
                            .hint_text(WRITE)
                            .char_limit(MAX_CHAT_CHARS)
                            .desired_width(CHAT_WIDTH - 72.0),
                    );
                    let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if std::mem::take(&mut viewer.chat_focus) {
                        field.request_focus();
                    } else if field.gained_focus() {
                        actions.push(Action::Viewer(ViewerAction::ChatField));
                    }
                    // While keys go to the host, the field holds no focus:
                    // nothing typed for the host lands in it.
                    if v.control
                        && !viewer.keyboard_local
                        && !viewer.input_paused
                        && field.has_focus()
                    {
                        field.surrender_focus();
                    }
                    if ui.button(SEND).clicked() || enter {
                        actions.push(Action::Viewer(ViewerAction::SendChat));
                    }
                });
                ui.label(RichText::new(NOT_SAVED).small().color(t.text_muted));
            });
        });
    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        actions.push(Action::Viewer(ViewerAction::Chat(false)));
    }
    area.response.rect
}

/// A chat line as the panel shows it, `<host>: …` or `You: …`, its text
/// sanitised once more before display; `None` when nothing visible is left.
#[must_use]
pub fn chat_line(host: &str, line: &ChatLine) -> Option<String> {
    let text = sanitize_peer_text(line.text.as_str())?;
    let who = if line.theirs { host } else { "You" };
    Some(format!("{who}: {}", text.as_str()))
}

/// The files panel, `y` points below the window's top: the tabs `offer`ed,
/// the tab's folder (the hidden card while this screen is shared, the
/// paused line while the host is locked), its footer and the transfers. Esc
/// closes it. Returns where it was drawn.
pub(super) fn files(
    ctx: &egui::Context,
    services: &ViewerServices,
    offer: u16,
    y: f32,
    actions: &mut Vec<Action>,
    viewer: &mut ViewerState,
) -> egui::Rect {
    let t = theme::tokens(ctx);
    let tab = FilesTab::shown(viewer.files_tab, offer).unwrap_or_default();
    viewer.files_tab = tab;
    // Offered but not in effect: paused while the host is locked.
    let paused = offer & (caps::UPLOAD | caps::BROWSE) & !services.effective() != 0;
    if paused {
        // Once the host is unlocked, a folder not listed is asked for anew.
        viewer.files_asked = [false; 2];
    }
    let height = lines_height(ctx, y) - 60.0;
    let today = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| Day::from_unix(d.as_secs()));
    let area = egui::Area::new(egui::Id::new("viewer-files"))
        .anchor(egui::Align2::RIGHT_TOP, vec2(-12.0, y))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            panel_frame(t).show(ui, |ui| {
                ui.set_width(FILES_WIDTH);
                ui.horizontal(|ui| {
                    for each in FilesTab::ALL {
                        if offer & each.cap() != 0
                            && ui.selectable_label(each == tab, each.label()).clicked()
                            && each != tab
                        {
                            actions.push(Action::Viewer(ViewerAction::FilesTab(each)));
                        }
                    }
                });
                if viewer.shared {
                    super::super::hidden_card(ui, FILES_HIDDEN);
                    return;
                }
                if paused {
                    ui.label(RichText::new(PAUSED).color(t.warn));
                } else {
                    folder(ui, services, tab, height, today, actions, viewer);
                }
                let footer = match tab {
                    FilesTab::Theirs => THEIR_FOOTER.to_owned(),
                    FilesTab::Mine => send_footer(&services.inbox, services.file_max),
                };
                ui.add(egui::Label::new(RichText::new(footer).small().color(t.text_muted)).wrap());
                if tab == FilesTab::Mine && viewer.drops {
                    ui.label(RichText::new(DROP_HINT).small().color(t.text_muted));
                }
                transfers(ui, services, actions);
            });
        });
    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        actions.push(Action::Viewer(ViewerAction::Files(false)));
    }
    area.response.rect
}

/// The folder of `tab`: its first listing asked for once, why it could not
/// be listed, the folder line with Up, and its rows (only those on screen
/// are laid out).
fn folder(
    ui: &mut egui::Ui,
    services: &ViewerServices,
    tab: FilesTab,
    height: f32,
    today: Option<Day>,
    actions: &mut Vec<Action>,
    viewer: &mut ViewerState,
) {
    let t = theme::tokens(ui.ctx());
    let (shown, failed) = match tab {
        FilesTab::Theirs => (services.remote.as_ref(), services.remote_failed),
        FilesTab::Mine => (services.local.as_ref(), services.local_failed),
    };
    let open = |handle| match tab {
        FilesTab::Theirs => FileOp::OpenRemote(handle),
        FilesTab::Mine => FileOp::OpenLocal(handle),
    };
    if shown.is_none() && !viewer.files_asked[tab.index()] {
        viewer.files_asked[tab.index()] = true;
        actions.push(Action::Viewer(ViewerAction::File(open(0))));
    }
    if let Some(code) = failed {
        ui.label(RichText::new(folder_failed(code)).color(t.warn));
    }
    let Some(listing) = shown else {
        if failed.is_none() {
            ui.spinner();
        }
        return;
    };
    ui.horizontal(|ui| {
        if let Some(parent) = listing.parent
            && ui.button(UP).clicked()
        {
            actions.push(Action::Viewer(ViewerAction::File(open(parent))));
        }
        let title = listing.title.as_str();
        if !title.is_empty() {
            ui.add(egui::Label::new(RichText::new(title).color(t.text_secondary)).truncate());
        }
    });
    let remote = tab == FilesTab::Theirs;
    egui::ScrollArea::vertical()
        .id_salt(("viewer-files-rows", remote, listing.folder))
        .max_height(height.max(MIN_LINES))
        .auto_shrink([false, true])
        .show_rows(ui, ROW_HEIGHT, listing.entries.len(), |ui, range| {
            for entry in listing.entries.get(range).unwrap_or_default() {
                row(ui, entry, tab, today, actions);
            }
        });
    if listing.more {
        ui.spinner();
    }
    if listing.truncated {
        ui.label(RichText::new(TRUNCATED).small().color(t.text_muted));
    }
}

/// One entry of a folder: its kind, name, size and day; a folder opens on a
/// double click, a file has Download ("Their files") or Send ("Send
/// files").
fn row(
    ui: &mut egui::Ui,
    entry: &EntryView,
    tab: FilesTab,
    today: Option<Day>,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    ui.horizontal(|ui| {
        ui.set_height(ROW_HEIGHT);
        kind_icon(ui, entry.kind, t);
        let width = (ui.available_width() - 200.0).max(80.0);
        let name = ui
            .scope(|ui| {
                ui.set_width(width);
                ui.add(
                    egui::Label::new(entry_name(entry))
                        .truncate()
                        .sense(egui::Sense::click()),
                )
            })
            .inner;
        if entry.kind == EntryKind::Folder && name.double_clicked() {
            let op = match tab {
                FilesTab::Theirs => FileOp::OpenRemote(entry.handle),
                FilesTab::Mine => FileOp::OpenLocal(entry.handle),
            };
            actions.push(Action::Viewer(ViewerAction::File(op)));
        }
        let small = |ui: &mut egui::Ui, text: String, width: f32| {
            ui.scope(|ui| {
                ui.set_width(width);
                ui.label(RichText::new(text).small().color(t.text_muted));
            });
        };
        small(ui, entry.size.map(size_text).unwrap_or_default(), 64.0);
        small(ui, modified_text(entry.mtime, today), 72.0);
        if entry.kind == EntryKind::File {
            let (words, op) = match tab {
                FilesTab::Theirs => (DOWNLOAD, FileOp::Download(entry.handle)),
                FilesTab::Mine => (SEND, FileOp::Send(entry.handle)),
            };
            if ui.small_button(words).clicked() {
                actions.push(Action::Viewer(ViewerAction::File(op)));
            }
        }
    });
}

/// An entry's kind, drawn: a folder, a sheet of paper, or a dot for anything
/// else. Decoration only.
fn kind_icon(ui: &mut egui::Ui, kind: EntryKind, t: &Tokens) {
    let (rect, _) = ui.allocate_exact_size(vec2(16.0, 16.0), egui::Sense::hover());
    let painter = ui.painter();
    let stroke = Stroke::new(1.4, t.text_secondary);
    let c = rect.center();
    match kind {
        EntryKind::Folder => {
            let body = egui::Rect::from_center_size(c + vec2(0.0, 1.0), vec2(14.0, 10.0));
            painter.rect_stroke(
                body,
                CornerRadius::same(2),
                stroke,
                egui::StrokeKind::Middle,
            );
            let tab = egui::Rect::from_min_size(body.min - vec2(0.0, 2.5), vec2(6.0, 2.5));
            painter.rect_filled(tab, CornerRadius::same(1), t.text_secondary);
        }
        EntryKind::File => {
            let sheet = egui::Rect::from_center_size(c, vec2(10.0, 13.0));
            painter.rect_stroke(
                sheet,
                CornerRadius::same(1),
                stroke,
                egui::StrokeKind::Middle,
            );
            painter.line_segment(
                [
                    sheet.left_top() + vec2(2.5, 4.0),
                    sheet.right_top() + vec2(-2.5, 4.0),
                ],
                stroke,
            );
        }
        EntryKind::Other => {
            painter.circle_filled(c, 2.5, t.text_muted);
        }
    }
}

/// An entry's name as a row shows it: with "(name shown approximately)"
/// after a lossy one.
#[must_use]
pub fn entry_name(entry: &EntryView) -> String {
    if entry.lossy {
        format!("{} {LOSSY}", entry.name.as_str())
    } else {
        entry.name.as_str().to_owned()
    }
}

/// Why a folder could not be listed, in the panel's words.
#[must_use]
pub fn folder_failed(code: u16) -> &'static str {
    match code {
        reason::DENIED => OWN_FOLDERS,
        reason::LOCKED => PAUSED,
        _ => CANNOT_OPEN,
    }
}

/// The footer of "Send files": `Files go to Downloads › Tornect on the other
/// computer. Each file up to 2 GiB.`, from the host's `Welcome`.
#[must_use]
pub fn send_footer(inbox: &str, file_max: u64) -> String {
    let limit = limit_text(file_max);
    if inbox.is_empty() {
        format!("Files go to the other computer. Each file up to {limit}.")
    } else {
        format!("Files go to {inbox} on the other computer. Each file up to {limit}.")
    }
}

/// The transfers, oldest first: each line with Cancel while it runs.
fn transfers(ui: &mut egui::Ui, services: &ViewerServices, actions: &mut Vec<Action>) {
    if services.transfers.is_empty() {
        return;
    }
    ui.separator();
    egui::ScrollArea::vertical()
        .id_salt("viewer-transfers")
        .max_height(140.0)
        .auto_shrink([false, true])
        .stick_to_bottom(true)
        .show(ui, |ui| {
            for row in &services.transfers {
                ui.horizontal(|ui| {
                    ui.add(egui::Label::new(transfer_line(row)).wrap());
                    if runs(&row.state) && ui.small_button(CANCEL).clicked() {
                        actions.push(Action::Viewer(ViewerAction::File(FileOp::Cancel(row.xfer))));
                    }
                });
            }
        });
}

/// Whether a transfer in `state` can still be stopped.
fn runs(state: &TransferState) -> bool {
    matches!(
        state,
        TransferState::Queued | TransferState::Running | TransferState::Stalled
    )
}

/// `name` cut to [`NAME_CHARS`] characters, with "…" when it was longer.
fn cut(name: &str) -> String {
    let mut chars = name.chars();
    let kept: String = chars.by_ref().take(NAME_CHARS).collect();
    if chars.next().is_some() {
        format!("{kept}…")
    } else {
        kept
    }
}

/// A transfer as the panel says it (the services design §7.1): `Sending
/// "a.txt" · 3.1 of 12 MB`, `Downloading "a.txt" · 45%`, `Sent "a.txt"`,
/// `Downloaded "a (2).txt" to Downloads › Tornect`, `"a.txt" was not sent:
/// the other computer has no room for it.`; `paused` while the host is
/// locked and `waiting` before it starts.
#[must_use]
pub fn transfer_line(row: &TransferRow) -> String {
    let name = cut(row.name.as_str());
    let upload = row.dir == Direction::ToHost;
    let going = if upload { "Sending" } else { "Downloading" };
    match &row.state {
        TransferState::Queued => format!("{going} \"{name}\" · waiting"),
        TransferState::Stalled => format!("{going} \"{name}\" · paused"),
        TransferState::Running if upload => {
            format!("Sending \"{name}\" · {}", progress_text(row.done, row.size))
        }
        TransferState::Running => {
            format!("Downloading \"{name}\" · {}%", percent(row.done, row.size))
        }
        TransferState::Done { .. } if upload => format!("Sent \"{name}\""),
        TransferState::Done { stored } => {
            format!(
                "Downloaded \"{}\" to Downloads › Tornect",
                cut(stored.as_str())
            )
        }
        TransferState::Failed(code) | TransferState::Cancelled(code) => {
            let not = if upload {
                "was not sent"
            } else {
                "was not downloaded"
            };
            format!("\"{name}\" {not}: {}", ending(*code, row.dir))
        }
    }
}

/// Why a transfer ended, as the end of its line.
#[must_use]
pub fn ending(code: u16, dir: Direction) -> &'static str {
    let upload = dir == Direction::ToHost;
    match code {
        reason::NO_SPACE if upload => "the other computer has no room for it.",
        reason::NO_SPACE => "this computer has no room for it.",
        reason::TOO_LARGE | reason::QUOTA if upload => {
            "it is larger than the other computer accepts."
        }
        reason::TOO_LARGE | reason::QUOTA => "it is larger than this computer accepts.",
        reason::BY_HOST => "the other computer stopped it.",
        reason::BY_VIEWER => "you stopped it.",
        reason::TURNED_OFF => "file transfer was turned off.",
        reason::CHANGED => "it changed while it was being sent.",
        reason::CORRUPT => "it arrived damaged and was deleted.",
        reason::LOCKED => "the other computer is locked.",
        reason::CAPTURE_STOPPED | reason::SESSION_OVER | reason::ENDED_BY_HOST => {
            "the session ended."
        }
        reason::DENIED => "Tornect does not share its own files.",
        reason::NOT_FOUND => "it is not there any more.",
        reason::NOT_A_FILE => "it is not a file.",
        reason::BAD_NAME => "its name cannot be used.",
        _ => "it could not be copied.",
    }
}

/// The units a size is said in: decimal, as the transfer lines say them.
const UNITS: [(u64, &str); 3] = [(1_000_000_000, "GB"), (1_000_000, "MB"), (1_000, "kB")];

/// The unit `bytes` is said in: the largest of [`UNITS`] it reaches once
/// rounded to a tenth of it; `None` below a kilobyte.
fn unit(bytes: u64) -> Option<(u64, &'static str)> {
    UNITS
        .into_iter()
        .find(|(size, _)| bytes.saturating_mul(10).saturating_add(size / 2) / size >= 10)
}

/// `bytes` in `size`ths: one decimal below 10, whole above.
fn in_unit(bytes: u64, size: u64) -> String {
    let tenths = (u128::from(bytes) * 10 + u128::from(size) / 2) / u128::from(size);
    if tenths < 100 {
        format!("{}.{}", tenths / 10, tenths % 10)
    } else {
        ((u128::from(bytes) + u128::from(size) / 2) / u128::from(size)).to_string()
    }
}

/// A size as people read it: `512 bytes`, `1.5 kB`, `3.1 MB`, `12 MB`,
/// `2.1 GB`.
#[must_use]
pub fn size_text(bytes: u64) -> String {
    match unit(bytes) {
        Some((size, name)) => format!("{} {name}", in_unit(bytes, size)),
        None if bytes == 1 => "1 byte".to_owned(),
        None => format!("{bytes} bytes"),
    }
}

/// How far a transfer of `size` bytes is, in the unit of its size: `3.1 of
/// 12 MB`.
#[must_use]
pub fn progress_text(done: u64, size: u64) -> String {
    match unit(size) {
        Some((unit, name)) => format!("{} of {} {name}", in_unit(done, unit), in_unit(size, unit)),
        None => format!("{done} of {size} bytes"),
    }
}

/// How far a transfer of `size` bytes is, in percent (0 before its size is
/// known).
#[must_use]
pub fn percent(done: u64, size: u64) -> u64 {
    if size == 0 {
        0
    } else {
        u64::try_from(u128::from(done.min(size)) * 100 / u128::from(size)).unwrap_or(100)
    }
}

/// A limit as Settings says it, in binary units: `2 GiB`, `1.5 GiB`, `512
/// MiB`.
#[must_use]
pub fn limit_text(bytes: u64) -> String {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    if bytes >= GIB {
        let tenths = (u128::from(bytes) * 10 + u128::from(GIB) / 2) / u128::from(GIB);
        if tenths % 10 == 0 {
            format!("{} GiB", tenths / 10)
        } else {
            format!("{}.{} GiB", tenths / 10, tenths % 10)
        }
    } else if bytes >= MIB {
        format!("{} MiB", (bytes + MIB / 2) / MIB)
    } else {
        size_text(bytes)
    }
}

/// When an entry was modified, as a row says it (`Today`, `3 days ago`, `12
/// Sep 2026`); empty when not known.
#[must_use]
pub fn modified_text(mtime: Option<i64>, today: Option<Day>) -> String {
    mtime
        .and_then(|secs| u64::try_from(secs).ok())
        .map(|secs| super::super::day_text(Day::from_unix(secs), today))
        .unwrap_or_default()
}

/// A page of a folder, for the tests and the preview.
#[cfg(test)]
#[must_use]
pub fn page(folder: u32, entries: Vec<EntryView>) -> tornect_session::services::ListingView {
    use tornect_session::services::{ListingView, Untrusted};
    ListingView {
        folder,
        title: Untrusted::shown(
            if folder == 0 {
                ""
            } else {
                "/home/desk/Documents"
            },
            64,
        ),
        parent: (folder != 0).then_some(0),
        from: 0,
        entries,
        more: false,
        truncated: false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use egui::accesskit::Toggled;
    use tornect_session::services::{Untrusted, ViewerEvent, ViewerServicesEnd};
    use tornect_signal::messages::notice;

    use super::super::testing::{Window, granted};
    use super::*;
    use crate::ui::pages::HIDDEN_WHILE_SHARED;

    fn ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    /// A window of a session at `control` whose host granted `caps`, its
    /// toolbar shown.
    fn window(control: bool, caps: u16) -> Window {
        let mut w = Window::new(control);
        w.viewing.services = Some(granted(caps));
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        w
    }

    fn services(w: &mut Window) -> &mut ViewerServices {
        w.viewing.services.as_deref_mut().expect("services")
    }

    /// The host wrote `text`.
    fn said(w: &mut Window, text: &str) {
        services(w).apply(ViewerEvent::Chat(sanitize_peer_text(text).unwrap()));
    }

    /// Two passes at `at`: the second lays out what the first asked for.
    fn settle(w: &mut Window, at: u64) -> Vec<Action> {
        let mut actions = w.pass(ms(at), Vec::new());
        actions.extend(w.pass(ms(at), Vec::new()));
        actions
    }

    fn file(op: FileOp) -> Action {
        Action::Viewer(ViewerAction::File(op))
    }

    fn entry(handle: u32, name: &str, kind: EntryKind, size: Option<u64>) -> EntryView {
        EntryView {
            name: Untrusted::file_name(name),
            handle,
            kind,
            size,
            mtime: None,
            lossy: false,
        }
    }

    /// The centre of the widget or text starting with `text` nearest to
    /// height `y`: a row's own button.
    fn nearest(w: &Window, text: &str, y: f32) -> egui::Pos2 {
        w.centres(text)
            .into_iter()
            .min_by(|a, b| (a.y - y).abs().total_cmp(&(b.y - y).abs()))
            .unwrap_or_else(|| panic!("no \"{text}\" on screen"))
    }

    /// Whether `at` is in one of the window's areas: a press there never
    /// reaches the host.
    fn in_areas(w: &Window, at: egui::Pos2) -> bool {
        w.viewer.areas().iter().any(|r| r.contains(at))
    }

    fn row(dir: Direction, state: TransferState, done: u64, size: u64) -> TransferRow {
        TransferRow {
            xfer: 1,
            dir,
            name: Untrusted::file_name("plan.odt"),
            size,
            done,
            state,
        }
    }

    /// Sizes read as people read them, in decimal units for transfers and
    /// in binary units for limits, as Settings says them.
    #[test]
    fn sizes_and_limits_read_as_people_read_them() {
        for (bytes, text) in [
            (0, "0 bytes"),
            (1, "1 byte"),
            (512, "512 bytes"),
            (949, "949 bytes"),
            (950, "1.0 kB"),
            (1_500, "1.5 kB"),
            (45_000, "45 kB"),
            (999_999, "1.0 MB"),
            (3_100_000, "3.1 MB"),
            (12_000_000, "12 MB"),
            (2_147_483_648, "2.1 GB"),
            (u64::MAX, "18446744074 GB"),
        ] {
            assert_eq!(size_text(bytes), text, "{bytes}");
        }
        assert_eq!(progress_text(3_100_000, 12_000_000), "3.1 of 12 MB");
        assert_eq!(progress_text(0, 12_000_000), "0.0 of 12 MB");
        assert_eq!(progress_text(300, 900), "300 of 900 bytes");
        assert_eq!(percent(45, 100), 45);
        assert_eq!(percent(0, 0), 0);
        assert_eq!(percent(200, 100), 100, "never over 100");
        assert_eq!(percent(u64::MAX, u64::MAX), 100);
        assert_eq!(limit_text(2048 << 20), "2 GiB");
        assert_eq!(limit_text(1536 << 20), "1.5 GiB");
        assert_eq!(limit_text(512 << 20), "512 MiB");
        assert_eq!(limit_text(1000), "1.0 kB");
        assert_eq!(
            send_footer("Downloads › Tornect", 2048 << 20),
            "Files go to Downloads › Tornect on the other computer. Each file up to 2 GiB."
        );
        assert_eq!(
            send_footer("", 512 << 20),
            "Files go to the other computer. Each file up to 512 MiB."
        );
    }

    /// The transfer lines in the design's words, each name cut to 40
    /// characters; a download names the file as it was stored here.
    #[test]
    fn transfer_lines_say_where_each_file_stands() {
        use Direction::{FromHost, ToHost};
        for (row, line) in [
            (
                row(ToHost, TransferState::Running, 3_100_000, 12_000_000),
                "Sending \"plan.odt\" · 3.1 of 12 MB",
            ),
            (
                row(FromHost, TransferState::Running, 45, 100),
                "Downloading \"plan.odt\" · 45%",
            ),
            (
                row(ToHost, TransferState::Queued, 0, 10),
                "Sending \"plan.odt\" · waiting",
            ),
            (
                row(FromHost, TransferState::Stalled, 1, 10),
                "Downloading \"plan.odt\" · paused",
            ),
            (
                row(ToHost, TransferState::Stalled, 1, 10),
                "Sending \"plan.odt\" · paused",
            ),
            (
                row(
                    ToHost,
                    TransferState::Done {
                        stored: Untrusted::file_name("plan (2).odt"),
                    },
                    10,
                    10,
                ),
                "Sent \"plan.odt\"",
            ),
            (
                row(
                    FromHost,
                    TransferState::Done {
                        stored: Untrusted::file_name("plan (2).odt"),
                    },
                    10,
                    10,
                ),
                "Downloaded \"plan (2).odt\" to Downloads › Tornect",
            ),
            (
                row(ToHost, TransferState::Failed(reason::NO_SPACE), 0, 10),
                "\"plan.odt\" was not sent: the other computer has no room for it.",
            ),
            (
                row(ToHost, TransferState::Failed(reason::QUOTA), 0, 10),
                "\"plan.odt\" was not sent: it is larger than the other computer accepts.",
            ),
            (
                row(ToHost, TransferState::Cancelled(reason::BY_HOST), 0, 10),
                "\"plan.odt\" was not sent: the other computer stopped it.",
            ),
            (
                row(ToHost, TransferState::Cancelled(reason::TURNED_OFF), 0, 10),
                "\"plan.odt\" was not sent: file transfer was turned off.",
            ),
            (
                row(FromHost, TransferState::Failed(reason::CHANGED), 0, 10),
                "\"plan.odt\" was not downloaded: it changed while it was being sent.",
            ),
            (
                row(FromHost, TransferState::Failed(reason::CORRUPT), 0, 10),
                "\"plan.odt\" was not downloaded: it arrived damaged and was deleted.",
            ),
            (
                row(ToHost, TransferState::Failed(reason::LOCKED), 0, 10),
                "\"plan.odt\" was not sent: the other computer is locked.",
            ),
            (
                row(
                    FromHost,
                    TransferState::Failed(reason::CAPTURE_STOPPED),
                    0,
                    10,
                ),
                "\"plan.odt\" was not downloaded: the session ended.",
            ),
            (
                row(ToHost, TransferState::Failed(reason::SESSION_OVER), 0, 10),
                "\"plan.odt\" was not sent: the session ended.",
            ),
            (
                row(FromHost, TransferState::Failed(reason::NO_SPACE), 0, 10),
                "\"plan.odt\" was not downloaded: this computer has no room for it.",
            ),
        ] {
            assert_eq!(transfer_line(&row), line);
        }
        let long = TransferRow {
            name: Untrusted::file_name(&format!("{}.txt", "a".repeat(60))),
            ..row(ToHost, TransferState::Queued, 0, 10)
        };
        assert_eq!(
            transfer_line(&long),
            format!("Sending \"{}…\" · waiting", "a".repeat(40))
        );
        // A reason the panel has no words for still says the file is not
        // there.
        assert_eq!(ending(reason::PROTOCOL, ToHost), "it could not be copied.");
    }

    /// The tab shown is the one asked for while offered, else the first
    /// offered; a cancel needs either of the files' caps.
    #[test]
    fn the_files_tabs_follow_what_is_offered() {
        use FilesTab::{Mine, Theirs};
        let both = caps::UPLOAD | caps::BROWSE;
        assert_eq!(FilesTab::shown(Mine, both), Some(Mine));
        assert_eq!(FilesTab::shown(Theirs, caps::UPLOAD), Some(Mine));
        assert_eq!(FilesTab::shown(Mine, caps::BROWSE), Some(Theirs));
        assert_eq!(FilesTab::shown(Theirs, caps::CHAT | caps::CLIP), None);
        assert_eq!(FileOp::Download(1).needs(), caps::BROWSE);
        assert_eq!(FileOp::OpenRemote(0).needs(), caps::BROWSE);
        assert_eq!(FileOp::Send(1).needs(), caps::UPLOAD);
        assert_eq!(FileOp::OpenLocal(0).needs(), caps::UPLOAD);
        assert_eq!(FileOp::Cancel(1).needs(), both);
        assert_eq!(folder_failed(reason::DENIED), OWN_FOLDERS);
        assert_eq!(folder_failed(reason::IO), CANNOT_OPEN);
        assert_eq!(folder_failed(reason::NOT_FOUND), CANNOT_OPEN);
        assert_eq!(modified_text(None, None), "");
        assert_eq!(modified_text(Some(-1), None), "");
        let today = Day::from_unix(20_000 * 86_400);
        assert_eq!(
            modified_text(Some(20_000 * 86_400 + 5), Some(today)),
            "Today"
        );
    }

    /// A chat line names its writer and keeps nothing invisible.
    #[test]
    fn chat_lines_name_the_writer() {
        let line = |theirs, raw: &str| ChatLine {
            theirs,
            text: sanitize_peer_text(raw).unwrap(),
        };
        assert_eq!(
            chat_line("Desk", &line(true, "hello")).as_deref(),
            Some("Desk: hello")
        );
        assert_eq!(
            chat_line("Desk", &line(false, "hi\u{202e}there")).as_deref(),
            Some("You: hithere")
        );
    }

    /// The services design §7.1: the toolbar has Chat, Files and the
    /// Clipboard switch for what the host granted, and only where this
    /// session can use them: chat in any session; files and the clipboard
    /// in a control session whose input reaches the host, the switch only
    /// for a window that shares its clipboard. Nothing before the host's
    /// `Welcome`, from a host without services, or once the stream ended; a
    /// pause leaves the entries (the panels say so); caps taken away go.
    #[test]
    fn the_toolbar_offers_what_the_host_granted_and_the_session_can_use() {
        const CHAT: &str = "Chat with them";
        const SWITCH: &str = "Share the clipboard";
        let entries = |w: &Window| [w.has(CHAT), w.has("Files"), w.has(SWITCH)];
        let mut w = Window::new(true);
        settle(&mut w, 0);
        assert!(w.has("End session"));
        assert_eq!(entries(&w), [false; 3], "a host without services");
        w.viewing.services = Some(Box::new(ViewerServices::opening(true)));
        settle(&mut w, 0);
        assert_eq!(entries(&w), [false; 3], "before the Welcome");
        w.viewing.services = Some(granted(caps::ALL));
        settle(&mut w, 0);
        assert_eq!(entries(&w), [true, true, false], "no window clipboard");
        services(&mut w).shares_clipboard = true;
        settle(&mut w, 0);
        assert_eq!(entries(&w), [true; 3], "all of them");
        assert_eq!(w.toggled(SWITCH), Some(Toggled::True));
        assert!(w.has("Chat"), "the button's words");
        assert_eq!(
            w.click(ms(100), CHAT),
            vec![Action::Viewer(ViewerAction::Chat(true))]
        );
        assert_eq!(
            w.click(ms(100), "Files"),
            vec![Action::Viewer(ViewerAction::Files(true))]
        );
        assert_eq!(
            w.click(ms(100), SWITCH),
            vec![Action::Viewer(ViewerAction::Clipboard(false))]
        );
        services(&mut w).clipboard = false;
        settle(&mut w, 100);
        assert_eq!(w.toggled(SWITCH), Some(Toggled::False));
        // Input that reaches nothing on the host, or no longer: chat only.
        for code in [notice::NO_INPUT, notice::INPUT_LOST] {
            w.viewer.host_notice = Some(code);
            settle(&mut w, 200);
            assert_eq!(entries(&w), [true, false, false], "{code:#x}");
        }
        w.viewer.host_notice = Some(0);
        settle(&mut w, 200);
        assert_eq!(entries(&w), [true; 3], "the notice withdrawn");
        // Locked: paused, still offered.
        services(&mut w).apply(ViewerEvent::Caps {
            caps: caps::ALL,
            paused: caps::CLIP | caps::UPLOAD | caps::BROWSE,
        });
        settle(&mut w, 300);
        assert_eq!(entries(&w), [true; 3], "paused");
        services(&mut w).apply(ViewerEvent::Caps {
            caps: caps::CHAT | caps::CLIP,
            paused: 0,
        });
        settle(&mut w, 300);
        assert_eq!(entries(&w), [true, false, true], "files turned off");
        services(&mut w).finished(ViewerServicesEnd::Closed(reason::ENDED_BY_HOST));
        settle(&mut w, 300);
        assert_eq!(entries(&w), [false; 3], "the stream ended");
        // A view-only session: chat only.
        let mut w = window(false, caps::ALL);
        services(&mut w).shares_clipboard = true;
        settle(&mut w, 0);
        assert_eq!(entries(&w), [true, false, false], "view-only");
        // Either of the files' caps alone is the Files button.
        for one in [caps::UPLOAD, caps::BROWSE] {
            let w = window(true, one);
            assert_eq!(entries(&w), [false, true, false], "{one:#x}");
        }
    }

    /// The Chat button counts the host's lines the panel has not shown:
    /// none of this computer's own; none while the panel shows them; the
    /// ones after once it closed. While this screen is shared the panel
    /// shows no history, and the lines stay counted.
    #[test]
    fn the_chat_button_counts_the_hosts_lines_the_panel_has_not_shown() {
        let mut w = window(false, caps::CHAT);
        assert!(w.has("Chat"));
        said(&mut w, "one");
        said(&mut w, "two");
        services(&mut w).said(sanitize_peer_text("mine").unwrap());
        settle(&mut w, 100);
        assert!(w.has("Chat · 2"));
        w.viewer.chat = true;
        settle(&mut w, 200);
        assert!(w.has("Chat") && !w.has("Chat · 2"), "while it shows them");
        for line in ["Desk: one", "Desk: two", "You: mine"] {
            assert!(w.has(line), "{line}");
        }
        w.viewer.chat = false;
        settle(&mut w, 300);
        assert!(w.has("Chat") && !w.has(NOT_SAVED), "seen, and closed");
        said(&mut w, "three");
        settle(&mut w, 400);
        assert!(w.has("Chat · 1"));
        w.viewer.shared = true;
        w.viewer.chat = true;
        said(&mut w, "four");
        settle(&mut w, 500);
        assert!(w.has("Chat · 2"), "not shown while shared");
        assert!(w.has(CHAT_HIDDEN));
        assert!(
            !w.texts()
                .iter()
                .any(|t| t.contains("three") || t.contains("four"))
        );
        w.viewer.shared = false;
        settle(&mut w, 600);
        assert!(w.has("Desk: four") && w.has("Chat") && !w.has("Chat · 2"));
    }

    /// The services design §7.1: the chat panel shows the lines, its field
    /// and Send, and its footer, in the window's areas; the toolbar stays
    /// while it is open. A click on the field while keys go to the host
    /// asks for the keyboard (`ChatField`), and the field takes nothing
    /// until it came; then what is typed lands there, and Enter or Send
    /// sends it. Esc closes the panel.
    #[test]
    fn the_chat_panel_takes_the_keyboard_for_its_field_and_sends_on_enter() {
        let mut w = window(true, caps::ALL);
        said(&mut w, "hello");
        assert_eq!(
            w.click(ms(100), "Chat with them"),
            vec![Action::Viewer(ViewerAction::Chat(true))]
        );
        // As the app does (`ViewerState::open_chat`): the field is to take
        // the focus, the keyboard comes here.
        w.viewer.chat = true;
        w.viewer.chat_focus = true;
        w.viewer.keyboard_local = true;
        settle(&mut w, 200);
        for text in ["Chat with \"Desk\"", "Desk: hello", NOT_SAVED, SEND] {
            assert!(w.has(text), "{text}");
        }
        let field = w.field(WRITE);
        for at in [field, w.centre(NOT_SAVED), w.centre("Desk: hello")] {
            assert!(in_areas(&w, at), "{at:?}");
        }
        assert!(
            w.pass(ms(300), vec![egui::Event::Text("see you".into())])
                .is_empty()
        );
        assert_eq!(w.viewer.chat_draft.0, "see you");
        assert_eq!(
            w.key(ms(400), egui::Key::Enter),
            vec![Action::Viewer(ViewerAction::SendChat)]
        );
        assert_eq!(w.viewer.take_chat(), "see you");
        settle(&mut w, 500);
        w.pass(ms(500), vec![egui::Event::Text("again".into())]);
        assert_eq!(w.viewer.chat_draft.0, "again", "the field kept the focus");
        let send = nearest(&w, SEND, field.y);
        assert_eq!(
            w.click_at(ms(600), send),
            vec![Action::Viewer(ViewerAction::SendChat)]
        );
        for at in [3_000, 9_000] {
            settle(&mut w, at);
            assert!(w.has("End session") && w.has(NOT_SAVED), "{at} ms");
        }
        // Keys go to the host again (a press on the picture): the field
        // lets go, and a click on it asks for the keyboard first.
        w.viewer.keyboard_local = false;
        w.viewer.write_chat("");
        settle(&mut w, 9_100);
        w.pass(ms(9_100), vec![egui::Event::Text("x".into())]);
        assert_eq!(w.viewer.chat_draft.0, "", "typed for the host");
        let asked = w.click_at(ms(9_200), w.field(WRITE));
        assert!(
            asked.contains(&Action::Viewer(ViewerAction::ChatField)),
            "{asked:?}"
        );
        w.pass(ms(9_300), vec![egui::Event::Text("y".into())]);
        assert_eq!(w.viewer.chat_draft.0, "", "not before the keyboard came");
        w.viewer.keyboard_local = true;
        w.click_at(ms(9_400), w.field(WRITE));
        w.pass(ms(9_500), vec![egui::Event::Text("z".into())]);
        assert_eq!(w.viewer.chat_draft.0, "z");
        assert!(
            w.key(ms(9_600), egui::Key::Escape)
                .contains(&Action::Viewer(ViewerAction::Chat(false)))
        );
    }

    /// While this computer's own screen is shared, the chat panel names
    /// nobody and its history gives way to the hidden card.
    #[test]
    fn while_this_screen_is_shared_the_chat_shows_no_history_and_names_nobody() {
        let mut w = window(true, caps::CHAT);
        said(&mut w, "the code is 1234");
        w.viewer.shared = true;
        w.viewer.chat = true;
        settle(&mut w, 100);
        for text in [CHAT_TITLE, HIDDEN_WHILE_SHARED, CHAT_HIDDEN, NOT_SAVED] {
            assert!(w.has(text), "{text}");
        }
        w.field(WRITE);
        assert!(
            !w.texts()
                .iter()
                .any(|t| t.contains("Desk") || t.contains("1234")),
            "{:?}",
            w.texts()
        );
    }

    /// The services design §7.1, "Their files": the host's places are asked
    /// for once; a folder shows its title, Up, and its rows (a name shown
    /// approximately says so, a file its size); a double click opens a
    /// folder, Download asks for that file by its handle, Up for the folder
    /// above; a folder not listed says why. All of it is in the window's
    /// areas.
    #[test]
    fn their_files_list_the_hosts_folder_and_download_by_handle() {
        let mut w = window(true, caps::ALL);
        w.viewer.open_files(true, caps::ALL);
        let mut asked = Vec::new();
        for at in [100, 200, 300] {
            asked.extend(w.pass(ms(at), Vec::new()));
        }
        assert_eq!(asked, vec![file(FileOp::OpenRemote(0))], "asked once");
        for text in ["Their files", "Send files", THEIR_FOOTER] {
            assert!(w.has(text), "{text}");
        }
        let mut lossy = entry(13, "resume.pdf", EntryKind::File, Some(1_500));
        lossy.lossy = true;
        services(&mut w).apply(ViewerEvent::Listing {
            remote: true,
            view: page(
                7,
                vec![
                    entry(11, "Photos", EntryKind::Folder, None),
                    entry(12, "plan.odt", EntryKind::File, Some(12_000_000)),
                    lossy,
                ],
            ),
        });
        assert!(settle(&mut w, 400).is_empty());
        for text in [
            "Photos",
            "plan.odt",
            "resume.pdf (name shown approximately)",
            "12 MB",
            "1.5 kB",
            UP,
            "/home/desk/Documents",
        ] {
            assert!(w.has(text), "{text}");
        }
        let photos = w.centre("Photos");
        assert!(in_areas(&w, photos) && in_areas(&w, w.centre(THEIR_FOOTER)));
        let plan = w.centre("plan.odt").y;
        assert_eq!(
            w.click_at(ms(500), nearest(&w, DOWNLOAD, plan)),
            vec![file(FileOp::Download(12))]
        );
        // Clicks far enough from the last one not to make a triple click.
        assert!(w.click_at(ms(2_000), photos).is_empty(), "a single click");
        assert_eq!(
            w.click_at(ms(2_050), photos),
            vec![file(FileOp::OpenRemote(11))]
        );
        assert_eq!(w.click(ms(3_000), UP), vec![file(FileOp::OpenRemote(0))]);
        services(&mut w).apply(ViewerEvent::ListFailed {
            remote: true,
            reason: reason::DENIED,
        });
        settle(&mut w, 3_100);
        assert!(w.has(OWN_FOLDERS));
        services(&mut w).apply(ViewerEvent::ListFailed {
            remote: true,
            reason: reason::NOT_FOUND,
        });
        settle(&mut w, 3_200);
        assert!(w.has(CANNOT_OPEN) && !w.has(OWN_FOLDERS));
        let mut many = page(9, vec![entry(1, "a.txt", EntryKind::File, Some(1))]);
        many.truncated = true;
        services(&mut w).apply(ViewerEvent::Listing {
            remote: true,
            view: many,
        });
        settle(&mut w, 3_300);
        assert!(w.has(TRUNCATED) && w.has("1 byte") && !w.has(CANNOT_OPEN));
        assert!(
            w.key(ms(3_400), egui::Key::Escape)
                .contains(&Action::Viewer(ViewerAction::Files(false)))
        );
    }

    /// "Send files": the tab asks for this computer's places once; its
    /// footer says where files go on the host and how large each may be,
    /// and that dropped files reach it where they do; Send asks for the
    /// file by its local handle, a double click opens a folder. With only
    /// sending granted, it is the only tab.
    #[test]
    fn send_files_lists_this_computers_folder_and_sends_by_handle() {
        let both = caps::UPLOAD | caps::BROWSE;
        let mut w = window(true, both);
        w.viewer.open_files(true, both);
        assert_eq!(settle(&mut w, 100), vec![file(FileOp::OpenRemote(0))]);
        assert_eq!(
            w.click(ms(200), "Send files"),
            vec![Action::Viewer(ViewerAction::FilesTab(FilesTab::Mine))]
        );
        w.viewer.files_tab = FilesTab::Mine;
        assert_eq!(settle(&mut w, 300), vec![file(FileOp::OpenLocal(0))]);
        assert!(
            w.has("Files go to Downloads › Tornect on the other computer. Each file up to 2 GiB.")
        );
        assert!(!w.has(DROP_HINT) && !w.has(THEIR_FOOTER), "no drops here");
        w.viewer.drops = true;
        settle(&mut w, 300);
        assert!(w.has(DROP_HINT));
        services(&mut w).apply(ViewerEvent::Listing {
            remote: false,
            view: page(
                0,
                vec![
                    entry(3, "Documents", EntryKind::Folder, None),
                    entry(5, "notes.txt", EntryKind::File, Some(512)),
                ],
            ),
        });
        settle(&mut w, 400);
        assert!(w.has("Documents") && w.has("notes.txt") && w.has("512 bytes"));
        assert!(!w.has(UP), "the places have nothing above");
        let notes = w.centre("notes.txt").y;
        assert_eq!(
            w.click_at(ms(500), nearest(&w, SEND, notes)),
            vec![file(FileOp::Send(5))]
        );
        let documents = w.centre("Documents");
        w.click_at(ms(2_000), documents);
        assert_eq!(
            w.click_at(ms(2_050), documents),
            vec![file(FileOp::OpenLocal(3))]
        );
        // Only sending granted: the tab asked for is not there.
        let mut w = window(true, caps::UPLOAD);
        w.viewer.files = true;
        assert_eq!(settle(&mut w, 100), vec![file(FileOp::OpenLocal(0))]);
        assert_eq!(w.viewer.files_tab, FilesTab::Mine);
        assert!(w.has("Send files") && !w.has("Their files"));
    }

    /// The transfers, under either tab, each in the design's words; Cancel
    /// on a running one stops it by its id, and an ended one has none.
    #[test]
    fn the_transfers_say_where_each_file_stands_and_running_ones_cancel() {
        let mut w = window(true, caps::ALL);
        w.viewer.open_files(true, caps::ALL);
        for (xfer, dir, state, done, size) in [
            (
                4,
                Direction::ToHost,
                TransferState::Running,
                3_100_000,
                12_000_000,
            ),
            (
                5,
                Direction::FromHost,
                TransferState::Done {
                    stored: Untrusted::file_name("big (2).iso"),
                },
                10,
                10,
            ),
            (
                6,
                Direction::ToHost,
                TransferState::Failed(reason::NO_SPACE),
                0,
                10,
            ),
        ] {
            services(&mut w).apply(ViewerEvent::Transfer(TransferRow {
                xfer,
                name: Untrusted::file_name("big.iso"),
                ..row(dir, state, done, size)
            }));
        }
        settle(&mut w, 100);
        for line in [
            "Sending \"big.iso\" · 3.1 of 12 MB",
            "Downloaded \"big (2).iso\" to Downloads › Tornect",
            "\"big.iso\" was not sent: the other computer has no room for it.",
        ] {
            assert!(w.has(line), "{line}");
            assert!(in_areas(&w, w.centre(line)), "{line}");
        }
        let cancels = w.centres(CANCEL);
        assert_eq!(cancels.len(), 1, "the running one only");
        assert_eq!(
            w.click_at(ms(200), cancels[0]),
            vec![file(FileOp::Cancel(4))]
        );
        w.viewer.files_tab = FilesTab::Mine;
        settle(&mut w, 300);
        assert!(
            w.has("Sending \"big.iso\" · 3.1 of 12 MB"),
            "under both tabs"
        );
    }

    /// While the host is locked both tabs say so, and nothing is asked
    /// for; once it is unlocked, the folder not listed is asked for.
    #[test]
    fn while_the_host_is_locked_both_tabs_say_they_are_paused() {
        let mut w = window(true, caps::ALL);
        services(&mut w).apply(ViewerEvent::Caps {
            caps: caps::ALL,
            paused: caps::CLIP | caps::UPLOAD | caps::BROWSE,
        });
        w.viewer.open_files(true, caps::ALL);
        assert!(settle(&mut w, 100).is_empty());
        assert!(w.has(PAUSED) && w.has(THEIR_FOOTER));
        w.viewer.files_tab = FilesTab::Mine;
        assert!(settle(&mut w, 200).is_empty());
        assert!(w.has(PAUSED));
        services(&mut w).apply(ViewerEvent::Caps {
            caps: caps::ALL,
            paused: 0,
        });
        assert_eq!(settle(&mut w, 300), vec![file(FileOp::OpenLocal(0))]);
        assert!(!w.has(PAUSED));
        // A folder refused as locked says the same.
        assert_eq!(folder_failed(reason::LOCKED), PAUSED);
    }

    /// While this computer's own screen is shared, the files panel shows
    /// its tabs and the hidden card: no folder, name or transfer, and
    /// nothing is asked for.
    #[test]
    fn while_this_screen_is_shared_the_files_panel_shows_no_name() {
        let mut w = window(true, caps::ALL);
        w.viewer.shared = true;
        w.viewer.open_files(true, caps::ALL);
        assert!(settle(&mut w, 100).is_empty());
        services(&mut w).apply(ViewerEvent::Listing {
            remote: true,
            view: page(
                7,
                vec![entry(1, "secret-plan.odt", EntryKind::File, Some(10))],
            ),
        });
        services(&mut w).apply(ViewerEvent::Transfer(TransferRow {
            name: Untrusted::file_name("salary.xlsx"),
            ..row(Direction::FromHost, TransferState::Running, 1, 10)
        }));
        settle(&mut w, 200);
        for text in [
            "Their files",
            "Send files",
            HIDDEN_WHILE_SHARED,
            FILES_HIDDEN,
        ] {
            assert!(w.has(text), "{text}");
        }
        assert!(
            !w.texts().iter().any(|t| t.contains("secret")
                || t.contains("salary")
                || t.contains("/home")
                || t.contains("Downloads")),
            "{:?}",
            w.texts()
        );
    }

    /// A panel closes once its service is no longer offered: files in a
    /// view-only session never open, they close once the host's input is
    /// lost, and the chat once the stream ended.
    #[test]
    fn a_panel_closes_once_its_service_is_not_offered() {
        let mut w = window(false, caps::ALL);
        w.viewer.files = true;
        assert!(settle(&mut w, 100).is_empty());
        assert!(!w.viewer.files && !w.has("Their files"), "view-only");
        let mut w = window(true, caps::ALL);
        w.viewer.open_files(true, caps::ALL);
        settle(&mut w, 100);
        assert!(w.has("Their files"));
        w.viewer.host_notice = Some(notice::INPUT_LOST);
        settle(&mut w, 200);
        assert!(!w.viewer.files && !w.has("Their files"), "input lost");
        w.viewer.chat = true;
        settle(&mut w, 300);
        assert!(w.has(NOT_SAVED), "chat stays");
        services(&mut w).finished(ViewerServicesEnd::Closed(reason::ENDED_BY_HOST));
        settle(&mut w, 400);
        assert!(!w.viewer.chat && !w.has(NOT_SAVED), "the stream ended");
    }
}
