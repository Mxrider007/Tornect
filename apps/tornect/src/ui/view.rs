//! The screens (`docs/UI_PLAN.md` §5–§8), drawn from a [`Model`] alone. What
//! the user asks for comes back as [`Action`]s; nothing here touches the
//! network, a store or a channel.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use egui::{Color32, RichText};
use tornect_core::TornectId;
use tornect_core::levels::{
    ADMIN_LINE, ADMIN_LINE_NO_PROMPT, AdminPath, Answers, LINE_VIEW_ONLY, SENTENCE_ADMIN_NOT_GIVEN,
    SENTENCE_SECURE_DESKTOP_OFF,
};
use tornect_core::unattended::ipc::ShownLink;
use tornect_core::words::{Identicon, label_refusal};
use tornect_signal::fsm::timeouts;
use tornect_signal::pairing::{PairDecision, SessionDecision};

use super::model::{
    BlockRequest, Confirm, ManagerOp, Model, Popup, PopupKind, Prompt, Recognition, Reveals,
    RotateFailed, SettingsChange, Sharing, SheetLevels,
};
#[cfg(test)]
use super::model::{ClientStage, Hosting, Setup, StreamInfo, TorState, Viewing};
use super::nav::{self, Page};
use super::pages;
use super::pages::viewer::ViewerAction;
#[cfg(test)]
use super::pages::viewer::ViewerState;
use super::theme::{self, Face};
use super::widgets;
use crate::ua_client::AdminAction;

mod strip;

pub use self::strip::HostServicesAction;

/// The SAS display size (§7: "SAS display 44 mono").
pub const SAS_SIZE: f32 = 44.0;

/// How long a card's accept buttons stay disabled after the card appears and
/// after it moves (a card above it came or went, the window scrolled or was
/// resized): a click aimed at the program underneath must not land on an
/// accept that just appeared under the pointer (SLICE-E E1-1). Browsers wait
/// about as long before a permission prompt's buttons work.
const ARM_AFTER: Duration = Duration::from_secs(1);

/// How far (in points) a card's answer row may shift between two passes and
/// still count as not moved: layout rounding, not a move.
const MOVE_TOLERANCE: f32 = 1.0;

/// The request sheet's widest, in points.
const SHEET_WIDTH: f32 = 600.0;

/// The countdown ring's size beside a question's headline, in points.
const RING: f32 = 30.0;

/// The line under Allow on a sheet from before the session levels.
const ALLOW_LINE_ANY: &str = "They can type and click as you.";

/// How many characters of a viewer's label the banner and the indicator
/// show: a pinned label of up to 64 characters must not push Stop, the mode
/// or the clock out of sight, nor pass for them (SLICE-E E1-2). The banner's
/// tooltip has the whole label.
const LABEL_SHOWN: usize = 24;

/// `label`, cut to [`LABEL_SHOWN`] characters with an ellipsis.
fn shown(label: &str) -> String {
    if label.chars().count() <= LABEL_SHOWN {
        return label.to_owned();
    }
    let mut out: String = label.chars().take(LABEL_SHOWN - 1).collect();
    out.push('…');
    out
}

/// What the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Connect to this Tornect ID.
    Connect(TornectId),
    /// Connect to this Tornect ID although it looks like a saved one (the
    /// second, deliberate click after the connect field's warning).
    ConnectAnyway(TornectId),
    /// "Allow as administrator" on session sheet `id`: its Tornect
    /// confirmation comes next (§B.2.1: no Windows prompt follows).
    AdminConfirm {
        /// The popup.
        id: u64,
    },
    /// "Allow as administrator…" on session sheet `id`: Windows' own prompt
    /// comes next, to start the administrator helper (§B.2.1, M-FEAT-3).
    AdminPrompt {
        /// The popup.
        id: u64,
    },
    /// End the session this screen is shared with (the kill), from the banner
    /// or the indicator window.
    StopSharing,
    /// Start moving the indicator window with the pointer (it has no title
    /// bar).
    MoveIndicator,
    /// The indicator's Chat: raise the main window as a second launch does
    /// (`Wake::Show`), its chat field of `session_id` ready to type into
    /// (the services design §7.3).
    ShowChat {
        /// The shared session whose chat card is wanted.
        session_id: String,
    },
    /// End the session this machine views, or stop asking for one.
    EndViewing,
    /// One of the stream window's own controls.
    Viewer(ViewerAction),
    /// Put the connect stepper away after a connection that ended.
    DismissConnect,
    /// Open the desktop's screen-sharing dialog now (the first-run grant).
    Grant,
    /// Forget the desktop's remembered grant.
    Revoke,
    /// The host user's answer to a pairing popup.
    Pair {
        /// The popup.
        id: u64,
        /// The answer.
        decision: PairDecision,
        /// Given by a primary click of the pointer, not by Space or Enter;
        /// always so for an accept (decision M1-50).
        pointer: bool,
    },
    /// The code the host user typed on a pairing sheet whose look-alike
    /// alarm fired (§B.6.1 W-B3): the host checks it against its own code;
    /// a match pairs, anything else refuses.
    PairCode {
        /// The popup.
        id: u64,
        /// The digits typed.
        code: String,
        /// The name typed for the device, if any.
        label: Option<String>,
    },
    /// The host user's answer to a session popup.
    Session {
        /// The popup.
        id: u64,
        /// The answer.
        decision: SessionDecision,
        /// Given by a primary click of the pointer, not by Space or Enter;
        /// always so for an accept (decision M1-50).
        pointer: bool,
    },
    /// The host user's answer to an "Ask before starting" popup (§B.8.6.3).
    Ask {
        /// The popup.
        id: u64,
        /// Allow (`false`: Deny).
        allow: bool,
        /// Given by a primary click of the pointer, not by Space or Enter;
        /// always so for Allow (decision M1-50).
        pointer: bool,
    },
    /// Block, in the block window of request `id` (§B.8.6.3).
    Block {
        /// The request.
        id: u64,
    },
    /// Acknowledge the banner of devices that can connect without asking
    /// (§B.8.6.2): the host's re-authentication comes next.
    AcknowledgeBanner,
    /// The client user's answer to the code question.
    Confirm {
        /// The question.
        id: u64,
        /// The codes matched.
        matched: bool,
        /// Given by a primary click of the pointer, not by Space or Enter;
        /// always so for an accept (decision M1-50).
        pointer: bool,
    },
    /// Copy this machine's ID.
    CopyId,
    /// Copy this text (another computer's ID).
    Copy(String),
    /// Check once whether this computer answers (asked on a click only).
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
    /// Save one change of the settings pages in `config.toml` (never an
    /// operation of §B.8.6.2).
    SaveSettings(SettingsChange),
    /// One operation of Settings, Security, which the window host's guard
    /// runs (§B.8.6.2): the page changes only on its answer.
    Manager(ManagerOp),
    /// The first run's question answered: the name typed, or `None` (Skip:
    /// the neutral default stays).
    FirstRunName(Option<String>),
    /// Open the password prompt for an unattended connect to this computer
    /// (§B.8.10): the prompt comes before anything is dialed.
    AskPassword(TornectId),
    /// Open the password prompt for an admin command at this computer, after
    /// its confirmation (§B.8.10).
    AskAdmin(TornectId, AdminAction),
    /// Open the password prompt to unlock another device (this device key) at
    /// this computer, after its confirmation.
    AskUnlock(TornectId, [u8; 32]),
    /// Work out the device words of this device key, for the Unlock
    /// confirmation to show (F4-4).
    DeviceWords([u8; 32]),
    /// The prompt's Connect (or Send), with what the form holds. Answered by
    /// a primary click of the pointer only: no key sequence submits it.
    SubmitPrompt {
        /// Given by the pointer.
        pointer: bool,
    },
    /// Close the prompt; what was typed is wiped.
    ClosePrompt,
    /// The person read that this computer's unattended setup was re-created:
    /// connecting may go on, and the next accept pins its new key (A16).
    ConfirmSetupChanged(TornectId),
    /// Close the window: the card of a Rotate ID that did not finish was
    /// read (§B.8.12).
    CloseWindow,
    /// Try Tor, or publishing this computer's ID, again now (B02).
    RetryTor,
    /// The host's person acts on a shared session's services, from its
    /// strip or its chat card (the services design §7.2).
    HostServices {
        /// The shared session (`sessions.log`'s id).
        session_id: String,
        /// What to do.
        op: HostServicesAction,
    },
}

/// The main window's one card when Rotate ID did not finish, with Close.
fn rotate_failed(ui: &mut egui::Ui, failed: RotateFailed, actions: &mut Vec<Action>) {
    let t = theme::tokens(ui.ctx());
    egui::CentralPanel::default()
        .frame(
            egui::Frame::new()
                .fill(t.bg_app)
                .inner_margin(egui::Margin::same(32)),
        )
        .show(ui, |ui| {
            widgets::card(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(
                    egui::Label::new(
                        RichText::new(pages::SettingsForm::rotate_failed(failed))
                            .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                            .color(t.text_primary),
                    )
                    .wrap(),
                );
                ui.add_space(10.0);
                if widgets::Button::new(widgets::Kind::Primary, "Close")
                    .show(ui)
                    .clicked()
                {
                    actions.push(Action::CloseWindow);
                }
            });
        });
}

/// The password prompt's fields (§B.8.10). The password is wiped when the
/// prompt closes or is submitted.
#[derive(Default)]
pub struct UaForm {
    /// The password typed.
    pub password: zeroize::Zeroizing<String>,
    /// Show it as typed (the reveal toggle).
    pub reveal: bool,
    /// Type a password although one is remembered.
    pub typing: bool,
    /// "View only this time".
    pub view_only: bool,
    /// "Remember on this device" (off by default).
    pub remember: bool,
    /// "Ask for administrator access".
    pub administrator: bool,
    /// The computer and the admin command whose confirmation is shown.
    pub confirming: Option<(TornectId, AdminAction)>,
    /// The computer where another device is to be unlocked, and that
    /// device's ID as typed so far.
    pub unlocking: Option<(TornectId, String)>,
    /// The device key whose words the Unlock confirmation asked for last.
    pub words_asked: Option<[u8; 32]>,
}

impl std::fmt::Debug for UaForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UaForm")
            .field("typed", &!self.password.is_empty())
            .finish_non_exhaustive()
    }
}

impl UaForm {
    /// Wipe what was typed and chosen.
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// What the user is typing, and what the window remembers of its cards.
#[derive(Debug, Default)]
pub struct Form {
    /// The connect field.
    pub connect_to: String,
    /// The label typed into each pairing popup.
    pub labels: HashMap<u64, String>,
    /// The code typed into each pairing popup whose alarm fired.
    pub codes: HashMap<u64, String>,
    /// Each open card's answer row, by popup or question id.
    cards: HashMap<u64, Card>,
    /// The page the window shows.
    pub page: Page,
    /// When Copy ID was last pressed (the button says "Copied" for a while).
    pub copied: Option<Instant>,
    /// When Copy invitation was last pressed (its button says "Copied" for
    /// a while).
    pub invited: Option<Instant>,
    /// The ID a link filled into the connect field, while the field still
    /// yields it, and its Connect row's arming: counted from the first pass
    /// that draws the row, again after every return of the window and every
    /// later link (L-1, L-4). Its note shows for as long as it is kept,
    /// whatever a later link said (design `invite` §2.2).
    link_fill: Option<(TornectId, Option<Card>)>,
    /// The note of the last link when it filled nothing: `Refused` or
    /// `Own`, never `Filled`. Shown under the note of a fill still in the
    /// field, until the field is edited or another link arrives.
    link_refusal: Option<LinkNote>,
    /// Since a link last brought the window to Home, and until the user
    /// picks another page: each of Home's rows that dial (the Connect row,
    /// each saved computer's actions) arms as a card's answers do, from its
    /// first sight and again after every return of the window and every
    /// later link, so that a click aimed at what was there before the link
    /// never lands on one (L-1, L-4).
    link_rows: Option<HashMap<LinkRow, Card>>,
    /// The connect field gives up the keyboard focus at its next pass: a
    /// link filled it.
    pub(super) unfocus_connect: bool,
    /// Home shows this computer's ID as a QR code.
    pub qr: bool,
    /// The address book page's own state.
    pub book: pages::BookForm,
    /// The settings page's own state.
    pub settings: pages::SettingsForm,
    /// The first run's name as typed so far.
    pub first_name: Option<String>,
    /// The password prompt's fields.
    pub ua: UaForm,
    /// The Sessions page shows the session log's folder.
    pub log_folder_shown: bool,
    /// What is typed into each shared session's chat card, by the
    /// session's id; it goes with the session.
    pub chats: HashMap<String, String>,
    /// The shared session whose chat field takes the keyboard at its card's
    /// next pass: the indicator's Chat asked for it (the services design
    /// §7.3). Dropped once taken, or with the session.
    pub chat_focus: Option<String>,
    /// What the request sheet last kept in view: its viewport's size, its
    /// newest card, how many cards it held and how tall they were. When any
    /// of them changes the newest card's answers are brought into view again.
    sheet_view: Option<(egui::Vec2, u64, usize, i32)>,
}

impl Form {
    /// Card `id` arms again, as a card that just appeared does: its answers
    /// wait another second (the return from an administrator prompt).
    pub fn rearm(&mut self, id: u64) {
        self.cards.remove(&id);
    }

    /// The window came back into view: restored from the taskbar, brought
    /// back by a newer card's attention request, or focused (review N-1).
    /// Every card's arming second starts again: a card armed before the
    /// window was minimized must not be live under a pointer aimed at the
    /// program the window now covers.
    pub fn window_came_back(&mut self) {
        self.cards.clear();
        if let Some((_, card)) = &mut self.link_fill {
            *card = None;
        }
        if let Some(rows) = &mut self.link_rows {
            rows.clear();
        }
    }

    /// A `tornect:` link reached this window (design `invite` §2.4): the
    /// one it was opened for, or one a later launch sent with `Show`. It
    /// at most fills the connect field: it sends nothing, answers and
    /// touches no card, prompt, dial or saved entry (L-1, L-4). The ID is
    /// checked again here, since what came over IPC may be any 32 bytes:
    /// one that is no key is a refused link, this computer's own (`own`) is
    /// said so; neither fills anything, nor takes away the note of a fill
    /// still in the field, which is still what Connect dials. A fill takes
    /// the keyboard focus from the field and leaves Connect disarmed until
    /// its row has been seen, still, for a second; any link restarts that
    /// second for a fill still in the field. The window shows Home, unless
    /// the grant wizard is open (leaving Settings would close it and wipe its
    /// passwords), and Home's rows that dial arm again, each from its first
    /// sight, whatever the link said ([`Form::link_row_armed`]).
    pub fn link_arrived(&mut self, link: ShownLink, own: Option<TornectId>) {
        if let Some((_, card)) = &mut self.link_fill {
            *card = None;
        }
        self.link_refusal = match link {
            ShownLink::Fill(id) if id.verifying_key().is_err() => Some(LinkNote::Refused),
            ShownLink::Fill(id) if Some(id) == own => Some(LinkNote::Own),
            ShownLink::Fill(id) => {
                self.connect_to = id.display_groups();
                self.link_fill = Some((id, None));
                self.unfocus_connect = true;
                None
            }
            ShownLink::Refused => Some(LinkNote::Refused),
        };
        if !self.settings.wizard_open() {
            self.page = Page::Home;
            self.link_rows = Some(HashMap::new());
        }
    }

    /// Whether the Connect row, whose start is the cursor of `ui`, may dial
    /// at `now`: always, unless a link filled the field or brought the
    /// window to Home, after which the row arms as a card's answers do.
    pub(super) fn link_armed(&mut self, ui: &egui::Ui, now: Instant) -> bool {
        let filled = match &mut self.link_fill {
            Some((_, card)) => arm_card(ui, card, now),
            None => true,
        };
        // Both are kept from the same pass, so that both seconds start at
        // the row's first sight.
        let shown = self.link_row_armed(ui, LinkRow::Connect, now);
        filled && shown
    }

    /// Whether Home's row `row`, whose start is the cursor of `ui`, may dial
    /// at `now`: always, unless a link brought the window to Home since the
    /// user last picked another page; then once the row has been still, in
    /// view, for a second (`link_rows`).
    pub(super) fn link_row_armed(&mut self, ui: &egui::Ui, row: LinkRow, now: Instant) -> bool {
        match &mut self.link_rows {
            Some(rows) => arm(ui, rows, row, now),
            None => true,
        }
    }

    /// The user is on another page than Home: what a link's page change
    /// armed is over (a later return to Home is the user's own).
    pub(super) fn left_home(&mut self) {
        self.link_rows = None;
    }

    /// Whether the connect field holds what a link filled in: its Connect
    /// row then answers only a primary click of the pointer.
    pub(super) fn link_filled(&self) -> bool {
        self.link_fill.is_some()
    }

    /// The connect field now yields `field_id`, and was edited this pass
    /// when `changed`: a fill and its note go once the field no longer
    /// yields the filled ID; a refused or own-ID note goes with an edit.
    pub(super) fn link_seen(&mut self, field_id: Option<TornectId>, changed: bool) {
        if self
            .link_fill
            .is_some_and(|(filled, _)| field_id != Some(filled))
        {
            self.link_fill = None;
        }
        if changed {
            self.link_refusal = None;
        }
    }

    /// The notes under the connect field, in the order they are drawn: the
    /// fill's while the field still yields its ID, then the refusal of a
    /// later link that filled nothing (design `invite` §2.2). Both show
    /// when both apply, so that a link refused after a fill never hides
    /// that the field still holds the fill.
    pub(super) fn link_notes(&self) -> impl Iterator<Item = LinkNote> + use<> {
        let filled = self.link_fill.map(|(id, _)| LinkNote::Filled(id));
        filled.into_iter().chain(self.link_refusal)
    }
}

/// One of Home's rows that dial, as [`Form::link_row_armed`] arms it after a
/// link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum LinkRow {
    /// Connect (or Connect anyway) under the connect field.
    Connect,
    /// A saved computer's card's actions (Knock, Connect, Connect without
    /// asking).
    Saved(TornectId),
}

/// What a `tornect:` link said under the connect field (design `invite`
/// §2.2). None of the notes names the ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LinkNote {
    /// It filled in this ID; shown while the field still yields it, a
    /// later link's refusal under it.
    Filled(TornectId),
    /// It held no valid Tornect ID; shown until the field is edited or
    /// another link arrives.
    Refused,
    /// It held this computer's own ID; shown as long as a refusal is.
    Own,
}

/// A card's answer row as the window remembers it from pass to pass.
#[derive(Debug, Clone, Copy)]
struct Card {
    /// Since when the row has been where it is.
    since: Instant,
    /// Where the row starts, in window points.
    at: egui::Pos2,
}

/// Remember where the answer row of card `id` starts (the cursor of `ui`),
/// and say whether its accepts may answer now: once the row has been still
/// for [`ARM_AFTER`].
fn arm<K: std::hash::Hash + Eq>(
    ui: &egui::Ui,
    cards: &mut HashMap<K, Card>,
    id: K,
    now: Instant,
) -> bool {
    let mut card = cards.get(&id).copied();
    let armed = arm_card(ui, &mut card, now);
    if let Some(card) = card {
        cards.insert(id, card);
    }
    armed
}

/// [`arm`] for one row remembered in `card` (`None`: not drawn yet, so the
/// second starts now).
fn arm_card(ui: &egui::Ui, card: &mut Option<Card>, now: Instant) -> bool {
    let at = ui.cursor().min;
    let card = card.get_or_insert(Card { since: now, at });
    if card.at.distance(at) > MOVE_TOLERANCE {
        card.since = now;
        card.at = at;
    }
    let still = now.saturating_duration_since(card.since);
    if still < ARM_AFTER {
        ui.ctx().request_repaint_after(ARM_AFTER - still);
        return false;
    }
    true
}

/// An accept button (Allow control, View only, pair, the codes match),
/// answered only by a primary click of the pointer (SLICE-E E1-1, decision
/// M1-50): disabled until the card is `armed`, and never in the Tab order
/// (`Sense::CLICK`, not focusable), so Space or Enter, typed for another
/// program, never answers it. `true` when it was clicked.
fn accept(ui: &mut egui::Ui, text: RichText, armed: bool) -> bool {
    ui.add_enabled(armed, egui::Button::new(text).sense(egui::Sense::CLICK))
        .clicked_by(egui::PointerButton::Primary)
}

/// A refusal button (Deny, Refuse, No): first in its row, reachable by Tab
/// at once, answered by the pointer or the keyboard. `Some(pointer)` when it
/// answered.
fn refuse(ui: &mut egui::Ui, text: &str) -> Option<bool> {
    let response = ui.button(text);
    response
        .clicked()
        .then(|| response.clicked_by(egui::PointerButton::Primary))
}

fn countdown(deadline: Instant, now: Instant) -> u64 {
    deadline.saturating_duration_since(now).as_secs()
}

/// `now - since` as minutes and seconds, `mm:ss`.
pub(super) fn clock(since: Instant, now: Instant) -> String {
    let secs = now.saturating_duration_since(since).as_secs();
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

/// The main window: the sharing banner (with each session's services strip
/// and chat card), the open questions, the page and the sidebar. The
/// keyboard reaches them in that order: the banner's Stop, the strip and the
/// chat, the questions (a refusal first in each), the page, and last the
/// navigation, whose room is reserved first and filled after the page.
pub fn main_window(
    ui: &mut egui::Ui,
    model: &Model,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    theme::ensure(ui.ctx());
    let t = theme::tokens(ui.ctx());
    // Rotate ID did not finish (§B.8.12): one card says what was left, and
    // its Close closes the window; nothing else is drawn.
    if let Some(failed) = model.rotate_failed {
        rotate_failed(ui, failed, actions);
        return;
    }
    let window = ui.max_rect().width();
    let mut below = ui.max_rect();
    if !model.sharing.is_empty() {
        let banner = egui::Panel::top("sharing")
            .frame(
                egui::Frame::new()
                    .fill(t.sharing_fill)
                    .inner_margin(egui::Margin::symmetric(12, 8)),
            )
            .show(ui, |ui| {
                for sharing in &model.sharing {
                    let admin = model.admin_sessions.contains(&sharing.session_id);
                    sharing_banner(ui, sharing, admin, now, actions);
                    strip::services_strip(ui, sharing, actions);
                    // In the banner, not above the page: the page's widgets
                    // keep their ids whether a chat card shows or not.
                    strip::chat_card(ui, sharing, &mut form.chats, &mut form.chat_focus, actions);
                }
                if let Some(warning) = &model.polkit_warning {
                    ui.add(
                        egui::Label::new(RichText::new(warning).small().color(t.on_sharing)).wrap(),
                    );
                }
            });
        below.min.y = banner.response.rect.max.y;
    }
    // A label typed into a question that is gone goes with it, and so does
    // what the window remembered of its card.
    form.labels
        .retain(|id, _| model.popups.iter().any(|p| p.id == *id));
    form.codes
        .retain(|id, _| model.popups.iter().any(|p| p.id == *id));
    form.chats
        .retain(|id, _| model.sharing.iter().any(|s| s.session_id == *id));
    if form
        .chat_focus
        .as_ref()
        .is_some_and(|id| !model.sharing.iter().any(|s| s.session_id == *id))
    {
        form.chat_focus = None;
    }
    form.cards.retain(|id, _| {
        model.popups.iter().any(|p| {
            p.id == *id || (model.admin_confirm.contains(&p.id) && confirmation_card(p.id) == *id)
        }) || model.confirm.as_ref().is_some_and(|c| c.id == *id)
    });
    // The grant wizard's passwords go with it when the window leaves
    // Settings (§B.8.7.2).
    if form.page != Page::Settings {
        form.settings.close_wizard(ui.ctx());
    }
    // The sidebar's room, with nothing in it yet.
    let side = egui::Panel::left("sidebar")
        .exact_size(nav::width(window))
        .resizable(false)
        .show_separator_line(false)
        .frame(egui::Frame::new().fill(t.bg_sidebar))
        .show(ui, |ui| {
            let rect = ui.max_rect();
            ui.painter().vline(
                rect.right() - 0.5,
                rect.y_range(),
                egui::Stroke::new(1.0, t.border_subtle),
            );
            rect
        })
        .inner;
    let asking = !model.popups.is_empty() || model.confirm.is_some();
    if !asking {
        form.sheet_view = None;
    }
    let mut sheet = None;
    egui::CentralPanel::default()
        .frame(
            egui::Frame::new()
                .fill(t.bg_app)
                .inner_margin(egui::Margin {
                    left: 32,
                    right: 32,
                    top: 26,
                    bottom: 0,
                }),
        )
        .show(ui, |ui| {
            // The open questions: the request sheet, laid out before the
            // page, so the keyboard and a screen reader reach it first.
            if asking {
                sheet = Some(request_sheet(ui, model, form, now, actions));
                ui.add_space(8.0);
            } else {
                // The page's widgets keep their ids whether a sheet is up or
                // not (the sheet is one child here), so a field of the page
                // keeps the focus when a question appears.
                ui.skip_ahead_auto_ids(1);
            }
            // This computer's own password prompt, under the host's
            // questions (they come first) and above the page.
            if let (Some(prompt), false) = (&model.prompt, asking) {
                password_prompt(ui, prompt, model.screen_shared(now), form, now, actions);
                ui.add_space(12.0);
            } else {
                if model.prompt.is_none() {
                    ui.ctx().data_mut(|d| {
                        d.remove::<egui::text_edit::TextEditState>(egui::Id::new(PASSWORD_FIELD));
                    });
                }
                // The one-time notice that direct connections are on (design
                // `direct` §3.6), in the prompt's place (never both), above
                // the page. It waits under a question, while the prompt is up
                // and while this screen is shared: its switch saves a
                // setting, which is refused then. Drawn or not, it takes the
                // prompt's one id (the card is one child), so the page's
                // widgets keep their ids and a field of the page keeps the
                // focus when the card waits for a question and comes back.
                if model.direct_notice && !asking && !model.screen_shared(now) {
                    direct_notice(ui, model, actions);
                    ui.add_space(12.0);
                } else {
                    ui.skip_ahead_auto_ids(1);
                }
            }
            egui::ScrollArea::vertical()
                .id_salt("page")
                .auto_shrink(false)
                .show(ui, |ui| {
                    let page = form.page;
                    pages::draw(ui, page, model, form, now, actions);
                });
        });
    let mut side_ui = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("sidebar-room")
            .max_rect(side),
    );
    nav::sidebar(
        &mut side_ui,
        model,
        &mut form.page,
        window < nav::RAIL_BELOW,
    );
    if let Some(sheet) = sheet {
        scrim(ui, below, sheet);
    }
    // Countdowns and the banner's clock move once a second.
    if !model.popups.is_empty() || model.confirm.is_some() || !model.sharing.is_empty() {
        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
}

/// The one-time notice after the upgrade to direct connections across the
/// internet (design `direct` §3.6): shown from the window's start while it
/// is due (`Settings::direct_notice_due`), since a saved `network.paranoid =
/// false` cannot be told apart from a deliberate choice.
pub(super) const DIRECT_NOTICE: &str = "Direct connections are on. After a session is accepted, \
    the two computers try to connect directly, which is faster, and each learns the other's IP \
    address. To keep your IP address hidden from the computers you connect to, turn this off.";

/// The notice's card: [`DIRECT_NOTICE`], the direct connections switch as
/// Settings, Connection has it, and OK, which records that it was seen.
fn direct_notice(ui: &mut egui::Ui, model: &Model, actions: &mut Vec<Action>) {
    let t = theme::tokens(ui.ctx());
    let width = ui.available_width().min(SHEET_WIDTH);
    ui.scope(|ui| {
        ui.set_max_width(width);
        widgets::card(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(
                egui::Label::new(RichText::new(DIRECT_NOTICE).color(t.text_primary))
                    .wrap()
                    .selectable(false),
            );
            ui.add_space(8.0);
            let label = pages::direct_switch(model.settings.internet);
            let mut on = model.settings.direct;
            ui.horizontal_top(|ui| {
                if widgets::toggle(ui, &mut on, label).clicked() {
                    actions.push(Action::SaveSettings(SettingsChange::Direct(on)));
                }
                ui.add(
                    egui::Label::new(
                        RichText::new(label)
                            .font(theme::font(ui.ctx(), Face::Medium, 14.0))
                            .color(t.text_primary),
                    )
                    .wrap()
                    .selectable(false),
                );
            });
            ui.add_space(8.0);
            if widgets::Button::new(widgets::Kind::Primary, "OK")
                .show(ui)
                .clicked()
            {
                actions.push(Action::SaveSettings(SettingsChange::DirectNoticeSeen));
            }
        });
    });
}

/// The id of the prompt's password field.
const PASSWORD_FIELD: &str = "unattended-password";

/// egui keeps undo copies of a text field's content in its memory: none are
/// kept of a password, and the field's state goes with the prompt.
fn forget_field_history(ctx: &egui::Context) {
    let id = egui::Id::new(PASSWORD_FIELD);
    if let Some(mut state) = egui::text_edit::TextEditState::load(ctx, id) {
        state.clear_undoer();
        state.store(ctx, id);
    }
}

/// The password prompt of an unattended connect or admin command (§B.8.10),
/// before dialing: masked with a reveal toggle, "View only this time",
/// "Remember on this device" off by default with its two-part risk copy (or
/// the sentence that says why it is absent), what the computer said about
/// waiting, Cancel, and a Connect (Send) that answers the pointer only. While
/// this screen is shared it shows nothing of the computer and no field.
fn password_prompt(
    ui: &mut egui::Ui,
    prompt: &Prompt,
    shared: bool,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    let width = ui.available_width().min(SHEET_WIDTH);
    ui.scope(|ui| {
        ui.set_max_width(width);
        widgets::card(ui, |ui| {
            ui.set_width(ui.available_width());
            if shared {
                ui.label(
                    RichText::new("The password prompt waits")
                        .font(theme::font(ui.ctx(), Face::Semibold, 16.0))
                        .color(t.text_primary),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "It comes back when this screen is no longer shared: a password \
                             is never typed on a shared screen.",
                        )
                        .color(t.text_secondary),
                    )
                    .wrap(),
                );
                if ui.button("Cancel").clicked() {
                    actions.push(Action::ClosePrompt);
                }
                return;
            }
            let ua = &mut form.ua;
            let heading = match prompt.admin {
                None => format!("Connect to \"{}\" without asking", prompt.host),
                Some(action) => format!("{}: \"{}\"", action.title(), prompt.host),
            };
            ui.add(
                egui::Label::new(
                    RichText::new(heading)
                        .font(theme::font(ui.ctx(), Face::Semibold, 16.0))
                        .color(t.text_primary),
                )
                .wrap(),
            );
            if prompt.stale {
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "The password remembered here was refused last time and deleted: \
                             type it again.",
                        )
                        .color(t.warn),
                    )
                    .wrap(),
                );
            }
            if prompt.vanished {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "The password remembered here is no longer in {}: type it.",
                            prompt.keychain.unwrap_or("the keychain")
                        ))
                        .color(t.warn),
                    )
                    .wrap(),
                );
            }
            if let Some(at) = prompt.retry_at.filter(|at| *at > now) {
                let secs =
                    u32::try_from(at.saturating_duration_since(now).as_secs()).unwrap_or(u32::MAX);
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "\"{}\" asked this device to wait: it takes the next password in {}.",
                            prompt.host,
                            crate::ua_client::wait_text(secs)
                        ))
                        .color(t.warn),
                    )
                    .wrap(),
                );
            }
            let saved = prompt.remembered && !ua.typing;
            if saved {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "The password remembered in {} is used.",
                            prompt.keychain.unwrap_or("the keychain")
                        ))
                        .color(t.text_secondary),
                    );
                    if ui.button("Type it instead").clicked() {
                        ua.typing = true;
                    }
                });
            } else {
                ui.horizontal(|ui| {
                    let field = ui.add(
                        egui::TextEdit::singleline(&mut *ua.password)
                            .id(PASSWORD_FIELD.into())
                            .password(!ua.reveal)
                            .hint_text("Password")
                            .desired_width(260.0),
                    );
                    field.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::WidgetType::TextEdit, true, "Password")
                    });
                    ui.checkbox(&mut ua.reveal, "Show");
                });
                forget_field_history(ui.ctx());
            }
            if prompt.admin.is_none() {
                ui.checkbox(&mut ua.view_only, "View only this time");
                // The level goes with control only (§B.8.4.1): view only asks
                // for none.
                if prompt.may_admin && !ua.view_only {
                    ui.checkbox(&mut ua.administrator, "Ask for administrator access");
                } else {
                    ua.administrator = false;
                }
                let offer = if ua.administrator || prompt.may_admin {
                    prompt.remember.1
                } else {
                    prompt.remember.0
                };
                let named = format!("\"{}\"", prompt.host);
                match offer.sentence(&named) {
                    None if !saved => {
                        ui.checkbox(&mut ua.remember, "Remember on this device");
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "Anyone who can use this computer as you could then \
                                     connect to \"{}\" without the password, and any program \
                                     running as you can read it from {}.{} {}",
                                    prompt.host,
                                    prompt.keychain.unwrap_or("the keychain"),
                                    prompt
                                        .kept
                                        .map(|kept| format!(" {kept}"))
                                        .unwrap_or_default(),
                                    tornect_core::unattended::credentials::remember_unless_reach(
                                        &named
                                    )
                                ))
                                .small()
                                .color(t.text_muted),
                            )
                            .wrap(),
                        );
                    }
                    None => ua.remember = false,
                    Some(sentence) => {
                        ua.remember = false;
                        ui.add(
                            egui::Label::new(RichText::new(sentence).small().color(t.text_muted))
                                .wrap(),
                        );
                    }
                }
            }
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "One try: if it fails, nothing is tried again by itself. The computer \
                         counts every wrong password.",
                    )
                    .small()
                    .color(t.text_muted),
                )
                .wrap(),
            );
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    actions.push(Action::ClosePrompt);
                }
                let ready = saved || !ua.password.is_empty();
                let label = if prompt.admin.is_some() {
                    "Send"
                } else {
                    "Connect"
                };
                if accept(ui, RichText::new(label).strong(), ready) {
                    actions.push(Action::SubmitPrompt { pointer: true });
                }
            });
        });
    });
}

/// The open questions (the redesign's request sheet, §4): one question at a
/// time, the oldest first, at the top of the page's room, under a line that
/// says how many more are waiting, and the rest of the window below the
/// banner dimmed and deaf to the pointer ([`scrim`]). The next question
/// appears only once the shown one is answered, withdrawn or timed out, as
/// a new card whose accepts wait their second ([`arm`]); the waiting line
/// coming or going moves the card, which waits again. Only when the card
/// does not fit does the column scroll, and then it keeps the card's answers
/// in view: when the card changes, and when its room changes (a resize, the
/// banner appearing). Returns where it was drawn.
fn request_sheet(
    ui: &mut egui::Ui,
    model: &Model,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) -> egui::Rect {
    let width = ui.available_width().min(SHEET_WIDTH);
    let room = egui::Rect::from_min_size(
        egui::pos2(ui.max_rect().center().x - width / 2.0, ui.cursor().top()),
        egui::vec2(width, ui.available_height()),
    );
    let dim = Color32::from_black_alpha(if ui.visuals().dark_mode { 150 } else { 96 });
    // The sheet's own room is dimmed as the scrim dims the rest, under its
    // cards: a place kept before them, filled once the room's size is known.
    let under = ui.painter().add(egui::Shape::Noop);
    let drawn = ui
        .scope_builder(egui::UiBuilder::new().max_rect(room), |ui| {
            egui::ScrollArea::vertical()
            .id_salt("questions")
            .max_height(ui.available_height())
            .auto_shrink([false, true])
            // A jump, not a glide: a card that moves waits its second again,
            // and a glide would keep it moving.
            .animated(false)
            .show(ui, |ui| {
                let open = model.popups.len() + usize::from(model.confirm.is_some());
                let waiting = open.saturating_sub(1);
                if waiting > 0 {
                    let t = theme::tokens(ui.ctx());
                    ui.add(
                        egui::Label::new(
                            RichText::new(if waiting == 1 {
                                "1 more waiting".to_owned()
                            } else {
                                format!("{waiting} more waiting")
                            })
                            .small()
                            .color(t.on_accent)
                            .background_color(t.accent_fill),
                        )
                        .selectable(false),
                    );
                }
                // The oldest question: the ids come from one counter, so the
                // lowest is the oldest, host questions and this computer's
                // code question alike.
                let oldest = model.popups.iter().min_by_key(|popup| popup.id);
                let confirm = model
                    .confirm
                    .as_ref()
                    .filter(|confirm| oldest.is_none_or(|popup| confirm.id < popup.id));
                let shown = if let Some(confirm) = confirm {
                    let shared = model.screen_shared(now);
                    let card =
                        question(ui, |ui| confirm_popup(ui, confirm, shared, form, now, actions));
                    Some((confirm.id, card))
                } else if let Some(popup) = oldest {
                    let services = strip::sheet_services_line(model);
                    let sheet = Sheet {
                        seen: model.recognition.get(&popup.id),
                        levels: model.levels.get(&popup.id),
                        confirming: model.admin_confirm.contains(&popup.id),
                        admin_not_given: model.admin_not_given.contains(&popup.id),
                        paired_recently: model.paired_recently.contains(&popup.id),
                        screens: model.sheet_screens.get(&popup.id).copied().unwrap_or(1),
                        services: services.as_deref(),
                        direct: model.settings.reveals(),
                    };
                    let card = question(ui, |ui| host_popup(ui, popup, sheet, form, now, actions));
                    Some((popup.id, card))
                } else {
                    None
                };
                // Only when the shown card's answers are out of view.
                if let Some((id, card)) = shown {
                    let viewport = ui.clip_rect();
                    let tall = ui.min_rect().height().round() as i32;
                    let key = (viewport.size(), id, open, tall);
                    if form.sheet_view != Some(key) {
                        form.sheet_view = Some(key);
                        if !viewport.expand(0.5).contains_rect(card) {
                            ui.scroll_to_rect(card, Some(egui::Align::Max));
                        }
                    }
                }
            });
        })
        .response
        .rect;
    ui.painter()
        .set(under, egui::Shape::rect_filled(drawn, 0, dim));
    drawn
}

/// The scrim of the request sheet: everything below the banner but the
/// sheet, dimmed, in strips that take every press there and answer nothing
/// (never focusable). The banner stays above it and live.
fn scrim(ui: &egui::Ui, below: egui::Rect, sheet: egui::Rect) {
    let dim = Color32::from_black_alpha(if ui.visuals().dark_mode { 150 } else { 96 });
    let strips = [
        egui::Rect::from_min_max(below.min, egui::pos2(below.max.x, sheet.min.y)),
        egui::Rect::from_min_max(egui::pos2(below.min.x, sheet.max.y), below.max),
        egui::Rect::from_min_max(
            egui::pos2(below.min.x, sheet.min.y),
            egui::pos2(sheet.min.x, sheet.max.y),
        ),
        egui::Rect::from_min_max(
            egui::pos2(sheet.max.x, sheet.min.y),
            egui::pos2(below.max.x, sheet.max.y),
        ),
    ];
    for (i, strip) in strips.into_iter().enumerate() {
        if strip.width() <= 0.0 || strip.height() <= 0.0 {
            continue;
        }
        egui::Area::new(egui::Id::new(("request-scrim", i)))
            .order(egui::Order::Middle)
            .fixed_pos(strip.min)
            .show(ui.ctx(), |ui| {
                let (rect, _) = ui.allocate_exact_size(strip.size(), egui::Sense::CLICK);
                ui.painter().rect_filled(rect, 0, dim);
            });
    }
}

/// A question's first row: the identicon beside a saved name (W-B8), the
/// headline, and the countdown ring at the right.
fn headline_row(
    ui: &mut egui::Ui,
    identicon: Option<&Identicon>,
    headline: RichText,
    deadline: Instant,
    now: Instant,
) {
    ui.horizontal_top(|ui| {
        if let Some(identicon) = identicon {
            widgets::identicon(ui, &identicon.seed(), 36.0);
        }
        let room = (ui.available_width() - RING - 8.0).max(80.0);
        ui.allocate_ui_with_layout(
            egui::vec2(room, 0.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                // The whole room, so that the ring sits at the right edge.
                ui.set_min_width(room);
                ui.add(egui::Label::new(headline).wrap().selectable(false));
            },
        );
        ring(ui, deadline, now);
    });
}

/// The countdown ring of a question that ends at `deadline`: the share of
/// the popup's time left, red in its last ten seconds.
fn ring(ui: &mut egui::Ui, deadline: Instant, now: Instant) {
    let t = theme::tokens(ui.ctx());
    let left = deadline.saturating_duration_since(now).as_secs_f32();
    let color = if left <= 10.0 {
        t.danger_text
    } else {
        t.accent_text
    };
    widgets::countdown_ring(ui, left / timeouts::POPUP.as_secs_f32(), RING, color);
}

/// The line under an answer (§B.2.1): its name, then what it does.
fn answer_line(ui: &mut egui::Ui, answer: &str, line: &str) {
    let t = theme::tokens(ui.ctx());
    ui.horizontal_top(|ui| {
        ui.label(RichText::new(answer).small().strong().color(t.text_primary));
        ui.vertical(|ui| {
            ui.add(
                egui::Label::new(RichText::new(line).small().color(t.text_secondary))
                    .wrap()
                    .selectable(false),
            );
        });
    });
}

/// The session sheet's line while an accept may let the session connect
/// directly (design `direct` §3.6, \[SEC\]): what `label` then learns
/// (`reveals`: the local address on the same site only, the internet
/// address where direct connections reach the internet), and where to turn
/// it off.
#[must_use]
pub fn direct_consent_line(label: &str, reveals: Reveals) -> String {
    let what = match reveals {
        Reveals::Local => "local address",
        Reveals::Internet => "internet address",
    };
    format!("Accepting also lets \"{label}\" learn this computer's {what} (Settings > Connection).")
}

fn direct_line(ui: &mut egui::Ui, label: &str, reveals: Reveals) {
    let t = theme::tokens(ui.ctx());
    ui.add(
        egui::Label::new(
            RichText::new(direct_consent_line(label, reveals))
                .small()
                .color(t.text_muted),
        )
        .wrap()
        .selectable(false),
    );
}

/// The session sheet's line of what control also gives (the services
/// design §7.4), in the style of an answer's line.
fn services_answer_line(ui: &mut egui::Ui, line: &str) {
    let t = theme::tokens(ui.ctx());
    ui.add(
        egui::Label::new(RichText::new(line).small().color(t.text_secondary))
            .wrap()
            .selectable(false),
    );
}

/// The scam line beside the administrator answer of a device paired
/// moments before (§B.2.1, the wizard's T10 step).
pub const SCAM_LINE: &str = "This device was paired less than a day ago. Did someone call and \
    ask you to allow this? Hang up, and deny.";

fn scam_line(ui: &mut egui::Ui) {
    let t = theme::tokens(ui.ctx());
    ui.add(
        egui::Label::new(RichText::new(SCAM_LINE).strong().color(t.danger_text))
            .wrap()
            .selectable(false),
    );
}

/// A name a device declared, as a sheet quotes it: without quotation marks
/// or middle dots, which could imitate the sheet's own lines: every one a
/// label may not hold (`tornect_core::words::label_refusal`).
fn quoted_free(name: &str) -> String {
    use tornect_core::words::{MIDDLE_DOTS, QUOTATION_MARKS};
    name.chars()
        .filter(|c| !QUOTATION_MARKS.contains(c) && !MIDDLE_DOTS.contains(c))
        .collect()
}

/// A question card: framed in the accent colour, above everything else.
/// Returns where it was drawn.
fn question(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) -> egui::Rect {
    let t = theme::tokens(ui.ctx());
    let card = egui::Frame::new()
        .fill(t.surface_card)
        .corner_radius(14)
        .stroke(egui::Stroke::new(2.0, t.accent_fill))
        .shadow(t.popup_shadow)
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        })
        .response
        .rect;
    ui.add_space(8.0);
    card
}

/// §6.3: "Sharing with `name` · 12:41 · End", for as long as a session runs.
/// Laid out from the right: Stop, then the clock, then the line, which says
/// what the viewer may do before it names the viewer and is cut to the room
/// left, so that no label can push Stop out of the window or pass for the
/// mode (SLICE-E E1-2).
fn sharing_banner(
    ui: &mut egui::Ui,
    sharing: &Sharing,
    admin: bool,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if stop_button(ui, "Stop sharing").clicked() {
                actions.push(Action::StopSharing);
            }
            ui.label(
                RichText::new(clock(sharing.since, now))
                    .monospace()
                    .color(t.on_sharing),
            );
            // The level the host signed: administrator only from an
            // "Allow as administrator" answer (§B.2.1).
            let what = match sharing.capture.as_ref().map(|c| c.screens) {
                Some(n) if n >= 2 => "this computer's screens",
                _ => "this screen",
            };
            let mode = match (sharing.control, admin) {
                (true, true) => format!("sees and controls {what} as administrator"),
                (true, false) => format!("sees and controls {what}"),
                (false, _) => format!("sees {what} (view only)"),
            };
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "{} · {mode} · \"{}\"",
                            headline(sharing),
                            shown(&sharing.label)
                        ))
                        .strong()
                        .color(t.on_sharing),
                    )
                    .truncate(),
                )
                .on_hover_text(format!("\"{}\"", sharing.label));
            });
        });
    });
    if sharing.capture.is_none() {
        ui.label(
            RichText::new("starting: the viewer's picture has not gone out yet")
                .small()
                .color(t.on_sharing),
        );
    }
    if let Some(capture) = &sharing.capture {
        ui.label(
            RichText::new(format!(
                "{} {}×{} · {}",
                capture.source,
                capture.width,
                capture.height,
                input_effect(sharing.control, capture.input)
            ))
            .small()
            .color(t.on_sharing),
        );
    }
}

/// Stop on the sharing red: a white button with red text, text only.
fn stop_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let t = theme::tokens(ui.ctx());
    ui.add(
        egui::Button::new(RichText::new(text).strong().color(t.sharing_fill)).fill(Color32::WHITE),
    )
}

/// The indicator's second line in an administrator session: the level the
/// host signed, before what the viewer's input does (§B.2.1).
const AS_ADMINISTRATOR: &str = "as administrator · ";

/// The indicator's first word: an unattended session says so (§B.8.7.3).
fn headline(sharing: &Sharing) -> &'static str {
    if sharing.unattended {
        "UNATTENDED"
    } else {
        "SHARING"
    }
}

/// What the viewer's input does here: the session's mode, and once capture
/// started, whether input is injected at all.
fn input_effect(control: bool, injected: bool) -> &'static str {
    match (control, injected) {
        (false, _) => "their input is ignored",
        (true, true) => "their keyboard and mouse act on this desktop",
        (true, false) => "their input reaches nothing here",
    }
}

/// The indicator window's content as a square (the tests' view of
/// `indicator_pill`).
#[cfg(test)]
pub fn indicator(ui: &mut egui::Ui, sharing: &[Sharing], now: Instant, actions: &mut Vec<Action>) {
    indicator_pill(ui, sharing, &HashSet::new(), now, actions, false);
}

/// The indicator window (§6.3, `indicator`): for every session this screen
/// is shared with, who, which mode and the clock; and Stop, which ends sharing
/// exactly as the banner's Stop does. A press anywhere else moves the window.
/// Drawn as a pill with rounded ends when `rounded` (the window is
/// see-through where the desktop composites it), with a white dot before
/// the rows. The headline, the mode and the clock come first on each row and
/// are never cut; only the label, last, is shortened. On the second line the
/// administrator level is never cut either; only what the viewer's input
/// does, after it, is. A file moving adds a third line.
pub fn indicator_pill(
    ui: &mut egui::Ui,
    sharing: &[Sharing],
    admin: &HashSet<String>,
    now: Instant,
    actions: &mut Vec<Action>,
    rounded: bool,
) {
    theme::ensure(ui.ctx());
    let t = theme::tokens(ui.ctx());
    // Text is not selectable here: a press on it moves the window instead.
    ui.style_mut().interaction.selectable_labels = false;
    egui::CentralPanel::no_frame()
        .frame(
            egui::Frame::new()
                .fill(t.sharing_fill)
                .corner_radius(if rounded { 20 } else { 0 })
                .inner_margin(egui::Margin::symmetric(10, 8)),
        )
        .show(ui, |ui| {
            // The white dot of "this screen is shared", left of the rows
            // (painted only: a press there moves the window too).
            let dot = egui::pos2(ui.max_rect().left() + 4.0, ui.max_rect().top() + 9.0);
            ui.painter().circle_filled(dot, 4.0, Color32::WHITE);
            // Click-and-drag, not drag alone: a drag-only area would start
            // moving at the press, even a press on Stop, and the desktop's
            // move would then swallow Stop's release.
            let grab = ui.interact(
                ui.max_rect(),
                egui::Id::new("indicator-move"),
                egui::Sense::click_and_drag(),
            );
            if grab.drag_started() {
                actions.push(Action::MoveIndicator);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if stop_button(ui, "Stop").clicked() {
                    actions.push(Action::StopSharing);
                }
                // Left of Stop, laid out after it: it can never cover Stop
                // (the services design §7.3). It raises the main window,
                // where the chat cards are.
                if let Some((text, session_id)) = strip::indicator_chat(sharing)
                    && ui
                        .add(
                            egui::Button::new(
                                RichText::new(text).small().strong().color(t.on_sharing),
                            )
                            .fill(Color32::TRANSPARENT)
                            .stroke(egui::Stroke::new(1.0, t.on_sharing)),
                        )
                        .clicked()
                {
                    actions.push(Action::ShowChat { session_id });
                }
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    ui.spacing_mut().indent = 12.0;
                    ui.indent("rows", |ui| {
                        for s in sharing {
                            let mode = if s.control { "control" } else { "view only" };
                            // The label last, and shortened: it can neither push
                            // the mode or the clock out nor pass for them
                            // (SLICE-E E1-2).
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!(
                                        "{} · {mode} · {} · \"{}\"",
                                        headline(s),
                                        clock(s.since, now),
                                        shown(&s.label)
                                    ))
                                    .strong()
                                    .color(t.on_sharing),
                                )
                                .truncate(),
                            );
                            let detail = s
                                .capture
                                .as_ref()
                                .map_or("starting: no picture has gone out yet", |c| {
                                    input_effect(s.control, c.input)
                                });
                            // The level the host signed, first on the second
                            // line and a label of its own, never shortened:
                            // only what the viewer's input does, after it, is.
                            // Top-aligned, not `horizontal`: the line keeps
                            // its text's height, and the rows fit the window.
                            let level = s.control && admin.contains(&s.session_id);
                            ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
                                ui.spacing_mut().item_spacing.x = 0.0;
                                if level {
                                    ui.add(egui::Label::new(
                                        RichText::new(AS_ADMINISTRATOR).small().color(t.on_sharing),
                                    ));
                                }
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(detail).small().color(t.on_sharing),
                                    )
                                    .truncate(),
                                );
                            });
                            // A file moving (the services design §7.3): fixed
                            // words on a line of their own under the two, so
                            // neither the level nor the input's effect gives
                            // way to them (the window is a line taller while
                            // it moves, `indicator::size`).
                            if let Some((dir, percent)) = s
                                .services
                                .as_ref()
                                .and_then(super::services::HostServices::moving)
                            {
                                ui.add(egui::Label::new(
                                    RichText::new(strip::indicator_transfer(dir, percent))
                                        .small()
                                        .color(t.on_sharing),
                                ));
                            }
                        }
                    });
                });
            });
        });
    // The clock moves once a second.
    ui.ctx().request_repaint_after(Duration::from_millis(500));
}

/// The block window's line where the session may be control and the saved
/// settings give the clipboard or files (the services design §7.4).
pub const BLOCK_SERVICES: &str = "With control it can also copy files and use the clipboard.";

/// Whether `code` holds a whole code: six digits (a space allowed).
/// A block window (§B.8.6.3, `block`): who is about to connect without asking,
/// the seconds left, and the window's one control, Block, which a click or the
/// keyboard answers (it only refuses).
pub fn block_window(
    ui: &mut egui::Ui,
    block: &BlockRequest,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    theme::ensure(ui.ctx());
    let t = theme::tokens(ui.ctx());
    let left = countdown(block.ends_at, now);
    let label = shown(&block.label);
    egui::CentralPanel::no_frame()
        .frame(
            egui::Frame::new()
                .fill(t.bg_app)
                .inner_margin(egui::Margin::symmetric(18, 14)),
        )
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(
                    RichText::new(format!("\"{label}\" is connecting without asking"))
                        .strong()
                        .size(17.0),
                )
                .wrap()
                .selectable(false),
            );
            ui.add_space(4.0);
            ui.add(
                egui::Label::new(format!(
                    "The session starts in {left} s. Block refuses it, and \"{label}\" cannot \
                     connect without asking until you resume its access on this computer."
                ))
                .wrap()
                .selectable(false),
            );
            if block.services {
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(RichText::new(BLOCK_SERVICES).color(t.text_secondary))
                        .wrap()
                        .selectable(false),
                );
            }
            ui.add_space(10.0);
            let block_button = egui::Button::new(
                RichText::new("Block")
                    .strong()
                    .size(16.0)
                    .color(t.on_sharing),
            )
            .fill(t.sharing_fill);
            if ui.add(block_button).clicked() {
                actions.push(Action::Block { id: block.id });
            }
        });
    // The seconds move.
    ui.ctx().request_repaint_after(Duration::from_millis(250));
}

fn whole_code(code: &str) -> bool {
    code.chars().filter(char::is_ascii_digit).count() == 6
}

/// What a session sheet asks to show: "this screen", or, where the viewer
/// could switch between two or more monitors or see them all (decision
/// M1-75 (3)), "this computer's N screens".
fn what_is_shared(screens: usize) -> String {
    if screens >= 2 {
        format!("this computer's {screens} screens")
    } else {
        "this screen".to_owned()
    }
}

/// What a host sheet shows beside its popup: the key's recognition, the
/// levels a session sheet offers, and whether its administrator
/// confirmation is up.
#[derive(Clone, Copy)]
struct Sheet<'a> {
    seen: Option<&'a Recognition>,
    levels: Option<&'a SheetLevels>,
    confirming: bool,
    /// Its "Allow as administrator…" ended without administrator access.
    admin_not_given: bool,
    /// The device was paired moments before: the scam line (T10).
    paired_recently: bool,
    /// How many screens the session could show (decision M1-75 (3)).
    screens: usize,
    /// What control also gives here, from the saved settings (the services
    /// design §7.4): said once under the answers when one gives control, and
    /// under an "Ask before starting" sheet's when the session may be
    /// control.
    services: Option<&'a str>,
    /// What an accept may let the other computer learn of this computer's
    /// addresses (design `direct` §3.6: the policy the host signs is not Tor
    /// only): the sheet says it. `None` while every session is relayed.
    direct: Option<Reveals>,
}

/// The arming card of session sheet `id`'s administrator confirmation: its
/// own second, counted from when the confirmation appears.
fn confirmation_card(id: u64) -> u64 {
    id ^ (1 << 63)
}

/// A host sheet (§B.6.1): the key asking is named by its saved name only
/// when all 32 bytes match a pinned key, with its identicon beside it;
/// otherwise by its device words, "not yet trusted · compare the code". When
/// the look-alike alarm fired, the sheet says so, hides its own code, and
/// pairs only through the code typed from the other device.
fn host_popup(
    ui: &mut egui::Ui,
    popup: &Popup,
    sheet: Sheet<'_>,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    let seen = sheet.seen;
    let left = countdown(popup.deadline, now);
    let t = theme::tokens(ui.ctx());
    let title = match popup.kind {
        PopupKind::Pairing { .. } => "Pairing request",
        PopupKind::Session { .. } => "Session request",
        PopupKind::Ask { .. } => "Unattended request",
    };
    ui.label(RichText::new(title).heading().color(t.accent_text));
    ui.push_id(("popup", popup.id), |ui| match &popup.kind {
        PopupKind::Pairing {
            name, sas, pinned, ..
        } => {
            let looks_like = seen.and_then(|s| s.looks_like.as_deref());
            // The alarm fired, or could not compare (F-4): either way only
            // the typed code pairs.
            let fired = seen.is_some_and(Recognition::typed_only);
            // A re-pair is named by its pinned label (all 32 bytes matched),
            // without the identicon: the request may be a replay, and the
            // picture would lend it an assurance it does not carry. A new
            // device by the name it declared, quoted as a suggestion.
            let headline = match pinned {
                Some(label) => format!(
                    "A device ALREADY PAIRED as \"{label}\" asks to pair again. Refusing does \
                     not unpair it."
                ),
                None => format!(
                    "A device calling itself \"{}\" asks to pair with this computer.",
                    quoted_free(name)
                ),
            };
            headline_row(ui, None, RichText::new(headline), popup.deadline, now);
            if let (None, Some(seen)) = (pinned, seen) {
                // The words in their labelled slot, never where a name goes.
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "device words: {} · not yet trusted · compare the code",
                            seen.words.shown()
                        ))
                        .small()
                        .color(t.text_secondary),
                    )
                    .wrap(),
                );
            }
            if let Some(like) = looks_like {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "Looks like your saved device \"{like}\", but it is a different \
                             device"
                        ))
                        .strong()
                        .color(t.danger_text),
                    )
                    .wrap(),
                );
            } else if fired {
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "Could not compare it with your saved devices: a file of saved \
                             entries could not be read",
                        )
                        .strong()
                        .color(t.danger_text),
                    )
                    .wrap(),
                );
            }
            ui.add_space(6.0);
            if !fired {
                ui.label("Code:");
                egui::Frame::new()
                    .fill(t.surface_raised)
                    .corner_radius(10)
                    .inner_margin(egui::Margin::symmetric(14, 4))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(sas)
                                .font(theme::font(ui.ctx(), Face::MonoSemibold, SAS_SIZE))
                                .color(t.accent_text),
                        );
                    });
                ui.label(
                    "The other device shows a code too. Pair only if the numbers match on both \
                         screens; if they differ, refuse: something between you changed them.",
                );
            } else {
                // This computer's code stays hidden: it is typed from the
                // other screen, and this computer compares (W-B3).
                ui.label(
                    "Type the 6-digit code the other device shows. This computer checks it \
                     against its own code; a wrong code refuses the device.",
                );
            }
            // It starts with the declared name (a re-pair: the pinned label,
            // which the store keeps), so the owner sees what an accept
            // without typing pins (SLICE-E E1-2).
            let label = form
                .labels
                .entry(popup.id)
                .or_insert_with(|| pinned.as_ref().unwrap_or(name).clone());
            ui.horizontal(|ui| {
                ui.label("Name it (this is what an accept saves):");
                ui.text_edit_singleline(label);
            });
            let label = label.trim().to_owned();
            let label = (!label.is_empty()).then_some(label);
            // What an accept pins never puts words in the name slot nor
            // imitates a sheet's lines (§B.6.1 item 7); a re-pair keeps the
            // label it has.
            let refusal = pinned
                .is_none()
                .then(|| label_refusal(label.as_deref().unwrap_or(name)))
                .flatten();
            if let Some(why) = refusal {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "This name cannot be saved: {why}. Type another name."
                        ))
                        .small()
                        .color(t.danger_text),
                    )
                    .wrap()
                    .selectable(false),
                );
            }
            let mut typed = None;
            if fired {
                let code = form.codes.entry(popup.id).or_default();
                ui.horizontal(|ui| {
                    ui.label("Their code:");
                    let field = ui.add(
                        egui::TextEdit::singleline(code)
                            .hint_text(RichText::new("6 digits, then Enter").monospace())
                            .char_limit(7)
                            .desired_width(150.0)
                            .font(egui::TextStyle::Monospace),
                    );
                    code.retain(|c| c.is_ascii_digit() || c == ' ');
                    if field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        typed = Some(code.clone());
                    }
                });
            }
            let armed = arm(ui, &mut form.cards, popup.id, now);
            ui.horizontal(|ui| {
                if let Some(pointer) = refuse(ui, "Refuse") {
                    actions.push(Action::Pair {
                        id: popup.id,
                        decision: PairDecision::Reject,
                        pointer,
                    });
                }
                // No accept button when the alarm fired: only the typed code
                // pairs then.
                if !fired
                    && accept(
                        ui,
                        RichText::new("The codes match: pair").strong(),
                        armed && refusal.is_none(),
                    )
                {
                    actions.push(Action::Pair {
                        id: popup.id,
                        decision: PairDecision::Accept {
                            label: label.clone(),
                        },
                        pointer: true,
                    });
                }
            });
            // Six digits read off the other screen are a deliberate answer on
            // their own: no arming second (the field's own height may change
            // with its first digit), and nothing else pairs this sheet.
            if let Some(code) = typed
                .filter(|c| whole_code(c))
                .filter(|_| refusal.is_none())
            {
                actions.push(Action::PairCode {
                    id: popup.id,
                    code,
                    label,
                });
            }
            ui.label(
                RichText::new(format!(
                    "Refused automatically in {left} s · only a mouse click or their code \
                     can pair"
                ))
                .small()
                .color(t.text_muted),
            );
        }
        PopupKind::Session { label, .. } => {
            // The administrator answer's own confirmation (§B.2.1): only for
            // a sheet that offers it.
            let confirmable = sheet.levels.is_some_and(|l| {
                matches!(l.answers.admin, Some(AdminPath::TornectConfirmation { .. }))
            });
            if sheet.confirming && confirmable {
                admin_confirmation(ui, popup.id, label, form, now, actions, left);
                if let Some(reveals) = sheet.direct {
                    direct_line(ui, label, reveals);
                }
                if let Some(line) = sheet.services {
                    services_answer_line(ui, line);
                }
                if sheet.paired_recently {
                    scam_line(ui);
                }
                return;
            }
            // A session request comes from a pinned key (all 32 bytes
            // matched): its pinned label names it, the identicon beside it
            // (W-B8).
            headline_row(
                ui,
                seen.and_then(|s| s.identicon.as_ref()),
                RichText::new(format!("\"{label}\" wants to connect to this computer"))
                    .strong()
                    .size(16.0),
                popup.deadline,
                now,
            );
            ui.add(
                egui::Label::new(format!(
                    "\"{label}\" wants to see {}. Whatever you answer lasts for this session \
                     only, and \"Stop sharing\" ends it.",
                    what_is_shared(sheet.screens)
                ))
                .wrap()
                .selectable(false),
            );
            if let Some(reveals) = sheet.direct {
                direct_line(ui, label, reveals);
            }
            // Without levels (a sheet from before them): the three answers.
            let answers = sheet.levels.map_or(
                Answers {
                    view_only: true,
                    allow: true,
                    admin: None,
                },
                |l| l.answers,
            );
            let allow_line = sheet.levels.map_or(ALLOW_LINE_ANY, |l| l.allow_line);
            if sheet.admin_not_given {
                // The administrator answer ended without administrator
                // access; the other answers stay open (§B.2.1).
                ui.add(
                    egui::Label::new(
                        RichText::new(if tornect_core::levels::ADMIN_HELPER {
                            format!(
                                "{SENTENCE_ADMIN_NOT_GIVEN}: Windows' prompt was cancelled or \
                                 failed, or the administrator helper did not start in time. The \
                                 other answers are still open."
                            )
                        } else {
                            format!(
                                "{SENTENCE_ADMIN_NOT_GIVEN}: this version of Tornect cannot \
                                 start the administrator helper, so Windows was not asked. The \
                                 other answers are still open."
                            )
                        })
                        .strong()
                        .color(t.danger_text),
                    )
                    .wrap()
                    .selectable(false),
                );
            }
            ui.add_space(4.0);
            let armed = arm(ui, &mut form.cards, popup.id, now);
            ui.horizontal(|ui| {
                if let Some(pointer) = refuse(ui, "Deny") {
                    actions.push(Action::Session {
                        id: popup.id,
                        decision: SessionDecision::Deny,
                        pointer,
                    });
                }
                if answers.view_only && accept(ui, RichText::new("View only"), armed) {
                    actions.push(Action::Session {
                        id: popup.id,
                        decision: SessionDecision::AllowOnceViewOnly,
                        pointer: true,
                    });
                }
                if answers.allow && accept(ui, RichText::new("Allow control").strong(), armed) {
                    actions.push(Action::Session {
                        id: popup.id,
                        decision: SessionDecision::AllowOnce,
                        pointer: true,
                    });
                }
            });
            // What each answer does (§B.2.1: the line under it).
            if answers.view_only {
                answer_line(ui, "View only", LINE_VIEW_ONLY);
            }
            if answers.allow {
                answer_line(ui, "Allow control", allow_line);
            }
            // Never adjacent to Allow (§B.2.1): a row of its own, under the
            // others. Where no Windows prompt follows it opens the Tornect
            // confirmation; where one does it asks Windows (the helper of
            // M-FEAT-3), and once that failed it is gone. It never answers
            // the sheet by itself.
            let admin = answers
                .admin
                .filter(|path| !(sheet.admin_not_given && *path == AdminPath::WindowsPrompt));
            if let Some(path) = admin {
                let (text, line, action) = match path {
                    AdminPath::WindowsPrompt => (
                        "Allow as administrator…",
                        ADMIN_LINE,
                        Action::AdminPrompt { id: popup.id },
                    ),
                    AdminPath::TornectConfirmation { .. } => (
                        "Allow as administrator",
                        ADMIN_LINE_NO_PROMPT,
                        Action::AdminConfirm { id: popup.id },
                    ),
                };
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if accept(ui, RichText::new(text).color(t.danger_text), armed) {
                        actions.push(action);
                    }
                });
                answer_line(ui, text, line);
                if sheet.paired_recently {
                    scam_line(ui);
                }
            }
            // Once, after every answer's line, where an answer gives control
            // (plain or as administrator): what control also gives here. No
            // button, arming or order changes; View only's line stays.
            if let (true, Some(line)) = (answers.allow || admin.is_some(), sheet.services) {
                services_answer_line(ui, line);
            }
            if let Some(levels) = sheet.levels {
                // The sentence under the buttons: why a level is absent, or
                // what the one offered means here (once: on Linux it is the
                // line under Allow; on the no-prompt row it is the line under
                // the administrator answer).
                let admin_line = admin.map(|path| match path {
                    AdminPath::WindowsPrompt => ADMIN_LINE,
                    AdminPath::TornectConfirmation { .. } => ADMIN_LINE_NO_PROMPT,
                });
                let said = |line: &&str| {
                    (answers.allow && *line == levels.allow_line) || admin_line == Some(*line)
                };
                for line in levels
                    .sentence
                    .into_iter()
                    .filter(|line| !said(line))
                    .chain(
                        levels
                            .prompts_on_shared_screen
                            .then_some(SENTENCE_SECURE_DESKTOP_OFF),
                    )
                {
                    ui.add(
                        egui::Label::new(RichText::new(line).small().color(t.text_secondary))
                            .wrap()
                            .selectable(false),
                    );
                }
            }
            ui.label(
                RichText::new(format!(
                    "Denied automatically in {left} s · only a mouse click can allow"
                ))
                .small()
                .color(t.text_muted),
            );
        }
        PopupKind::Ask {
            label,
            administrator,
            control,
        } => {
            // §B.8.6.3: the grant's level, never a choice of one (r7): Deny or
            // Allow only.
            let headline = if *administrator {
                format!("\"{label}\" wants to connect as administrator")
            } else {
                format!("\"{label}\" wants to connect to this computer")
            };
            headline_row(
                ui,
                None,
                RichText::new(headline).strong().size(16.0),
                popup.deadline,
                now,
            );
            ui.add(
                egui::Label::new(
                    "This device may connect without asking, and its access asks you before \
                     each session. Deny refuses this session only.",
                )
                .wrap()
                .selectable(false),
            );
            ui.add_space(4.0);
            let armed = arm(ui, &mut form.cards, popup.id, now);
            ui.horizontal(|ui| {
                if let Some(pointer) = refuse(ui, "Deny") {
                    actions.push(Action::Ask {
                        id: popup.id,
                        allow: false,
                        pointer,
                    });
                }
                if accept(ui, RichText::new("Allow").strong(), armed) {
                    actions.push(Action::Ask {
                        id: popup.id,
                        allow: true,
                        pointer: true,
                    });
                }
            });
            // Where the session may be control, what control also gives here,
            // as under the session sheet's answers: with no block window after
            // it, this sheet is the only one at session time.
            if let (true, Some(line)) = (*control, sheet.services) {
                services_answer_line(ui, line);
            }
            ui.label(
                RichText::new(format!(
                    "Denied automatically in {left} s · only a mouse click can allow"
                ))
                .small()
                .color(t.text_muted),
            );
        }
    });
}

/// The Tornect confirmation of "Allow as administrator" (§B.2.1), where no
/// Windows prompt follows: the administrator line, Deny first, and the
/// accept armed only after the confirmation has been still for its own
/// second. Deny refuses the session.
fn admin_confirmation(
    ui: &mut egui::Ui,
    id: u64,
    label: &str,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
    left: u64,
) {
    let t = theme::tokens(ui.ctx());
    ui.label(
        RichText::new(format!("Allow \"{label}\" as administrator?"))
            .strong()
            .size(16.0),
    );
    ui.add(
        egui::Label::new(ADMIN_LINE_NO_PROMPT)
            .wrap()
            .selectable(false),
    );
    let armed = arm(ui, &mut form.cards, confirmation_card(id), now);
    ui.horizontal(|ui| {
        if let Some(pointer) = refuse(ui, "Deny") {
            actions.push(Action::Session {
                id,
                decision: SessionDecision::Deny,
                pointer,
            });
        }
        if accept(
            ui,
            RichText::new("Allow as administrator")
                .strong()
                .color(t.danger_text),
            armed,
        ) {
            actions.push(Action::Session {
                id,
                decision: SessionDecision::AllowOnceAdmin,
                pointer: true,
            });
        }
    });
    ui.label(
        RichText::new(format!("Denied automatically in {left} s"))
            .small()
            .color(t.text_muted),
    );
}

/// The client's code question. While this screen may be `shared` it names
/// no host (U3-L2), as the stepper beside it does not.
fn confirm_popup(
    ui: &mut egui::Ui,
    confirm: &Confirm,
    shared: bool,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    ui.label(
        RichText::new("Compare the code")
            .heading()
            .color(t.accent_text),
    );
    ui.push_id(("confirm", confirm.id), |ui| {
        ui.label(if shared {
            "The host accepted. Did its screen show this code?".to_owned()
        } else {
            format!(
                "The host accepted; it calls itself \"{}\". Did its screen show this code?",
                confirm.host_name
            )
        });
        ui.label(
            RichText::new(&confirm.sas)
                .font(theme::font(ui.ctx(), Face::MonoSemibold, SAS_SIZE))
                .color(t.accent_text),
        );
        let armed = arm(ui, &mut form.cards, confirm.id, now);
        ui.horizontal(|ui| {
            if let Some(pointer) = refuse(ui, "No") {
                actions.push(Action::Confirm {
                    id: confirm.id,
                    matched: false,
                    pointer,
                });
            }
            if accept(ui, RichText::new("Yes, the codes match").strong(), armed) {
                actions.push(Action::Confirm {
                    id: confirm.id,
                    matched: true,
                    pointer: true,
                });
            }
        });
        // The host waits for the session only so long; the question itself
        // stays up much longer, so that it cannot run out unseen, and a late
        // yes still pairs this computer.
        let note = if now < confirm.host_waits_until {
            format!(
                "Answer within {} s and the session request follows.",
                countdown(confirm.host_waits_until, now)
            )
        } else {
            format!(
                "The host has stopped waiting for the session. Yes still pairs this computer; \
                 then press Connect again to ask for a session. Refused automatically in {} s.",
                countdown(confirm.deadline, now)
            )
        };
        // Not selectable: a selectable label is also one accessibility node
        // per row, and the whole note must read as one.
        ui.add(egui::Label::new(RichText::new(note).small().color(t.text_muted)).selectable(false));
    });
}

pub use super::pages::viewer::stream_window;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::super::model::CaptureNote;
    use super::*;

    fn run(model: &Model, form: &mut Form) -> Vec<Action> {
        let ctx = egui::Context::default();
        let mut actions = Vec::new();
        // Two passes: egui lays windows out on the first.
        for _ in 0..2 {
            ctx.run_ui(egui::RawInput::default(), |ui| {
                main_window(ui, model, form, Instant::now(), &mut actions);
            })
            .drop_without_applying_deltas();
        }
        actions
    }

    /// The main window at its default size (560 × 720), driven one pass at
    /// a time with the clock and the events a test gives, as the event loop
    /// drives it. Buttons are found by their labels in the accessibility
    /// tree, where egui records every widget's rectangle.
    struct Harness {
        ctx: egui::Context,
        model: Model,
        form: Form,
        start: Instant,
        nodes: Vec<egui::accesskit::Node>,
    }

    impl Harness {
        fn new(model: Model, start: Instant) -> Self {
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            let mut harness = Self {
                ctx,
                model,
                form: Form::default(),
                start,
                nodes: Vec::new(),
            };
            // Two passes: egui lays out on the first.
            for _ in 0..2 {
                harness.pass(start, Vec::new());
            }
            harness
        }

        /// One pass at `now` with `events`: what the user asked for.
        fn pass(&mut self, now: Instant, events: Vec<egui::Event>) -> Vec<Action> {
            let raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(560.0, 720.0),
                )),
                time: Some(now.duration_since(self.start).as_secs_f64()),
                events,
                ..egui::RawInput::default()
            };
            let mut actions = Vec::new();
            let (model, form) = (&self.model, &mut self.form);
            let out = self.ctx.run_ui(raw, |ui| {
                main_window(ui, model, form, now, &mut actions);
            });
            if let Some(update) = &out.platform_output.accesskit_update {
                self.nodes = update.nodes.iter().map(|(_, n)| n.clone()).collect();
            }
            out.drop_without_applying_deltas();
            actions
        }

        /// The centre of the button labelled `label` in the last pass.
        fn button(&self, label: &str) -> egui::Pos2 {
            let bounds = self
                .nodes
                .iter()
                .find(|n| n.label() == Some(label))
                .and_then(egui::accesskit::Node::bounds)
                .unwrap_or_else(|| panic!("no button \"{label}\" on screen"));
            egui::pos2(
                ((bounds.x0 + bounds.x1) / 2.0) as f32,
                ((bounds.y0 + bounds.y1) / 2.0) as f32,
            )
        }

        /// The rectangle (x0, y0, x1, y1) of the widget labelled `label` in
        /// the last pass.
        fn bounds(&self, label: &str) -> (f64, f64, f64, f64) {
            let b = self
                .nodes
                .iter()
                .find(|n| n.label() == Some(label))
                .and_then(egui::accesskit::Node::bounds)
                .unwrap_or_else(|| panic!("no \"{label}\" on screen"));
            (b.x0, b.y0, b.x1, b.y1)
        }

        /// The text of the label node whose text starts with `start`.
        fn text(&self, start: &str) -> String {
            self.nodes
                .iter()
                .filter_map(|n| n.value())
                .find(|v| v.starts_with(start))
                .unwrap_or_else(|| panic!("no text starting with \"{start}\""))
                .to_owned()
        }

        /// Whether a widget labelled `label` was on screen in the last pass.
        fn has(&self, label: &str) -> bool {
            self.nodes.iter().any(|n| n.label() == Some(label))
        }

        /// The text of every label in the last pass.
        fn texts(&self) -> Vec<String> {
            self.nodes
                .iter()
                .filter_map(|n| n.value())
                .map(str::to_owned)
                .collect()
        }

        /// Whether the button labelled `label` was disabled in the last pass.
        fn disabled(&self, label: &str) -> bool {
            self.nodes
                .iter()
                .find(|n| n.label() == Some(label))
                .unwrap_or_else(|| panic!("no button \"{label}\" on screen"))
                .is_disabled()
        }

        /// `key` pressed and released in one pass.
        fn key(&mut self, now: Instant, key: egui::Key) -> Vec<Action> {
            let event = |pressed| egui::Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            };
            self.pass(now, vec![event(true), event(false)])
        }

        /// A primary click at `at`: the pointer moves there and presses in
        /// one pass, and releases 50 ms later in the next.
        fn click(&mut self, now: Instant, at: egui::Pos2) -> Vec<Action> {
            let button = |pressed| egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let mut actions = self.pass(now, vec![egui::Event::PointerMoved(at), button(true)]);
            actions.extend(self.pass(now + Duration::from_millis(50), vec![button(false)]));
            actions
        }
    }

    fn session_popup(id: u64, now: Instant) -> Popup {
        Popup {
            id,
            kind: PopupKind::Session {
                label: "Laptop".to_owned(),
                fingerprint: "ab:cd".to_owned(),
            },
            deadline: now + Duration::from_secs(60),
        }
    }

    fn pairing_popup(id: u64, now: Instant) -> Popup {
        Popup {
            id,
            kind: PopupKind::Pairing {
                name: "Phone".to_owned(),
                fingerprint: "ef:01".to_owned(),
                sas: "123 456".to_owned(),
                pinned: None,
            },
            deadline: now + Duration::from_secs(60),
        }
    }

    fn ask_popup(id: u64, now: Instant, administrator: bool) -> Popup {
        ask_popup_for(id, now, administrator, true)
    }

    fn ask_popup_for(id: u64, now: Instant, administrator: bool, control: bool) -> Popup {
        Popup {
            id,
            kind: PopupKind::Ask {
                label: "Laptop".to_owned(),
                administrator,
                control,
            },
            deadline: now + Duration::from_secs(60),
        }
    }

    fn with_popups(popups: Vec<Popup>) -> Model {
        Model {
            id: Some("abcd efgh".to_owned()),
            popups,
            ..Model::default()
        }
    }

    fn allowed(actions: &[Action]) -> bool {
        actions.iter().any(|a| {
            matches!(
                a,
                Action::Session {
                    decision: SessionDecision::AllowOnce | SessionDecision::AllowOnceViewOnly,
                    ..
                }
            )
        })
    }

    /// SLICE-E E1-1: keys typed for another program must not answer a card
    /// that appeared under them. Before the owner has clicked in the window,
    /// no run of Tabs followed by Space or Enter allows a session, however
    /// long the card has been up.
    #[test]
    fn keys_alone_never_allow_a_session() {
        for confirm in [egui::Key::Space, egui::Key::Enter] {
            for tabs in 1..=5 {
                let t0 = Instant::now();
                let mut window = Harness::new(with_popups(vec![session_popup(7, t0)]), t0);
                let later = t0 + Duration::from_secs(5);
                let mut actions = Vec::new();
                for _ in 0..tabs {
                    actions.extend(window.key(later, egui::Key::Tab));
                }
                actions.extend(window.key(later, confirm));
                assert!(
                    !allowed(&actions),
                    "{tabs} Tab(s) then {confirm:?} allowed a session: {actions:?}"
                );
            }
        }
    }

    /// The pairing card: Tab reaches the name field, and no further Tab
    /// followed by Space or Enter pairs.
    #[test]
    fn keys_alone_never_pair() {
        for confirm in [egui::Key::Space, egui::Key::Enter] {
            for tabs in 1..=5 {
                let t0 = Instant::now();
                let mut window = Harness::new(with_popups(vec![pairing_popup(3, t0)]), t0);
                let later = t0 + Duration::from_secs(5);
                let mut actions = Vec::new();
                for _ in 0..tabs {
                    actions.extend(window.key(later, egui::Key::Tab));
                }
                actions.extend(window.key(later, confirm));
                assert!(
                    !actions.iter().any(|a| matches!(
                        a,
                        Action::Pair {
                            decision: PairDecision::Accept { .. },
                            ..
                        }
                    )),
                    "{tabs} Tab(s) then {confirm:?} paired: {actions:?}"
                );
            }
        }
    }

    /// The client's code question: keys alone never say the codes match.
    #[test]
    fn keys_alone_never_confirm_the_codes() {
        for confirm_key in [egui::Key::Space, egui::Key::Enter] {
            for tabs in 1..=5 {
                let t0 = Instant::now();
                let model = Model {
                    confirm: Some(Confirm {
                        id: 4,
                        host_name: "Desk".to_owned(),
                        sas: "654 321".to_owned(),
                        host_waits_until: t0 + Duration::from_secs(50),
                        deadline: t0 + Duration::from_secs(600),
                    }),
                    ..with_popups(Vec::new())
                };
                let mut window = Harness::new(model, t0);
                let later = t0 + Duration::from_secs(5);
                let mut actions = Vec::new();
                for _ in 0..tabs {
                    actions.extend(window.key(later, egui::Key::Tab));
                }
                actions.extend(window.key(later, confirm_key));
                assert!(
                    !actions
                        .iter()
                        .any(|a| matches!(a, Action::Confirm { matched: true, .. })),
                    "{tabs} Tab(s) then {confirm_key:?} confirmed: {actions:?}"
                );
            }
        }
    }

    /// The code card outlives the host's wait so that it cannot run out
    /// unseen: until then it says how long the session request still waits,
    /// after it that a yes still pairs this computer, and a click on the
    /// accept still answers it.
    #[test]
    fn the_code_card_says_a_late_yes_still_pairs() {
        let t0 = Instant::now();
        let model = Model {
            confirm: Some(Confirm {
                id: 5,
                host_name: "Desk".to_owned(),
                sas: "654 321".to_owned(),
                host_waits_until: t0 + Duration::from_secs(50),
                deadline: t0 + Duration::from_secs(600),
            }),
            ..with_popups(Vec::new())
        };
        let mut window = Harness::new(model, t0);
        let note = window.text("Answer within");
        assert!(note.contains("50 s"), "{note}");
        let late = t0 + Duration::from_secs(60);
        window.pass(late, Vec::new());
        let note = window.text("The host has stopped waiting for the session.");
        assert!(note.contains("Yes still pairs this computer"), "{note}");
        assert!(note.contains("in 540 s"), "{note}");
        let yes = window.button("Yes, the codes match");
        let actions = window.click(late, yes);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Confirm {
                    id: 5,
                    matched: true,
                    ..
                }
            )),
            "{actions:?}"
        );
    }

    /// Deny is the first stop of the keyboard in a session card, and it
    /// answers at once: refusing never waits.
    #[test]
    fn deny_is_the_first_key_stop_and_answers_at_once() {
        let t0 = Instant::now();
        let mut window = Harness::new(with_popups(vec![session_popup(7, t0)]), t0);
        window.key(t0, egui::Key::Tab);
        let actions = window.key(t0, egui::Key::Space);
        assert!(
            matches!(
                actions.as_slice(),
                [Action::Session {
                    id: 7,
                    decision: SessionDecision::Deny,
                    ..
                }]
            ),
            "{actions:?}"
        );
    }

    /// A click aimed at the program underneath can land on a card that just
    /// appeared: in the card's first second a click on "Allow control" does
    /// nothing; once the card has been still for a second, it allows.
    #[test]
    fn a_click_in_the_cards_first_second_does_nothing() {
        let t0 = Instant::now();
        let mut window = Harness::new(with_popups(vec![session_popup(7, t0)]), t0);
        assert!(window.disabled("Allow control") && window.disabled("View only"));
        assert!(!window.disabled("Deny"), "refusing never waits");
        let allow = window.button("Allow control");
        let early = window.click(t0 + Duration::from_millis(300), allow);
        assert!(early.is_empty(), "answered in the first second: {early:?}");

        window.pass(t0 + Duration::from_millis(1500), Vec::new());
        assert!(!window.disabled("Allow control"));
        assert_eq!(window.button("Allow control"), allow, "it did not move");
        let late = window.click(t0 + Duration::from_millis(1600), allow);
        assert_eq!(
            late,
            vec![Action::Session {
                id: 7,
                decision: SessionDecision::AllowOnce,
                pointer: true,
            }]
        );
    }

    /// Review N-1: a card armed before the window was minimized is not live
    /// the moment the window comes back (a newer card's attention request
    /// restores it under the pointer, or it gets the focus): its arming
    /// second starts again, so a click meant for another program 300 ms
    /// later answers nothing.
    #[test]
    fn a_window_that_comes_back_arms_its_cards_again() {
        let t0 = Instant::now();
        let mut window = Harness::new(with_popups(vec![session_popup(7, t0)]), t0);
        window.pass(t0 + Duration::from_millis(1500), Vec::new());
        assert!(!window.disabled("Allow control"), "armed after a second");
        let allow = window.button("Allow control");
        // Minimized unanswered; twenty seconds later the window comes back.
        let back = t0 + Duration::from_secs(20);
        window.form.window_came_back();
        window.pass(back, Vec::new());
        let early = window.click(back + Duration::from_millis(300), allow);
        assert!(
            early.is_empty(),
            "the old card answered 300 ms after the window came back: {early:?}"
        );
        window.pass(back + Duration::from_millis(1500), Vec::new());
        let late = window.click(back + Duration::from_millis(1600), allow);
        assert_eq!(
            late,
            vec![Action::Session {
                id: 7,
                decision: SessionDecision::AllowOnce,
                pointer: true,
            }]
        );
    }

    /// The main window as the event loop's helpers see it, minimised as
    /// given; what they ask of it is pinned in the app's own tests.
    struct MainWindow(Option<bool>);

    impl super::super::app::Attention for MainWindow {
        fn is_minimized(&self) -> Option<bool> {
            self.0
        }

        fn set_minimized(&self, _minimized: bool) {}

        fn request_user_attention(&self, _kind: Option<winit::window::UserAttentionType>) {}
    }

    /// A window with one card armed long ago; `event` reaches the event
    /// loop's helper 20 s later: whether the card's accept answers a click
    /// 300 ms after that.
    fn answers_right_after(event: impl FnOnce(&mut Form)) -> bool {
        let t0 = Instant::now();
        let mut window = Harness::new(with_popups(vec![session_popup(7, t0)]), t0);
        window.pass(t0 + Duration::from_millis(1500), Vec::new());
        assert!(!window.disabled("Allow control"), "armed after a second");
        let allow = window.button("Allow control");
        let back = t0 + Duration::from_secs(20);
        event(&mut window.form);
        window.pass(back, Vec::new());
        !window
            .click(back + Duration::from_millis(300), allow)
            .is_empty()
    }

    /// §B.2.1 (Arming, MUST): `Show` (a second launch) arms every open card
    /// again, whatever the window's state, through the helper the event loop
    /// calls for it: a card armed before answers nothing 300 ms after.
    #[test]
    fn show_arms_the_open_cards_again() {
        for minimized in [Some(true), Some(false), None] {
            assert!(
                !answers_right_after(|form| super::super::app::on_show(
                    &MainWindow(minimized),
                    form
                )),
                "minimized {minimized:?}: a card answered 300 ms after Show"
            );
        }
    }

    /// §B.1.1, §B.2.1: in background mode, a sharing indicator that does not
    /// open brings the minimised window back, through the helper the event
    /// loop calls, and its cards arm again; a window it did not bring back
    /// (not minimised, Wayland's unknown, or started by hand) keeps its
    /// cards as they were.
    #[test]
    fn a_failed_indicator_that_brings_the_window_back_arms_its_cards_again() {
        for (minimized, background, rearmed) in [
            (Some(true), true, true),
            (Some(false), true, false),
            (None, true, false),
            (Some(true), false, false),
        ] {
            assert_eq!(
                answers_right_after(|form| super::super::app::on_indicator_failed(
                    &MainWindow(minimized),
                    background,
                    form
                )),
                !rearmed,
                "minimized {minimized:?}, background {background}"
            );
        }
    }

    /// Decision M1-50 ("pointer-only Allow"): even after the owner has
    /// clicked in the window, Tab never reaches an accept and Space or Enter
    /// never answers one; Deny stays on the keyboard.
    #[test]
    fn even_after_a_click_in_the_window_keys_never_allow() {
        for confirm in [egui::Key::Space, egui::Key::Enter] {
            for tabs in 1..=5 {
                let t0 = Instant::now();
                let mut window = Harness::new(with_popups(vec![session_popup(7, t0)]), t0);
                let later = t0 + Duration::from_secs(2);
                // The window's lower right corner: no button there.
                assert!(window.click(later, egui::pos2(550.0, 710.0)).is_empty());
                let later = later + Duration::from_millis(100);
                let mut actions = Vec::new();
                for _ in 0..tabs {
                    actions.extend(window.key(later, egui::Key::Tab));
                }
                actions.extend(window.key(later, confirm));
                assert!(
                    !allowed(&actions),
                    "{tabs} Tab(s) then {confirm:?} allowed a session: {actions:?}"
                );
                if tabs == 1 {
                    assert_eq!(
                        actions,
                        vec![Action::Session {
                            id: 7,
                            decision: SessionDecision::Deny,
                            pointer: false,
                        }]
                    );
                }
            }
        }
    }

    /// A label of the most characters a pinned label may have, crafted to
    /// look like the indicator's own words (SLICE-E E1-2).
    fn crafted_label() -> String {
        let label: String = format!("Ana\" · view only · 00:04 {}", "x".repeat(64))
            .chars()
            .take(tornect_core::trusted::MAX_LABEL_CHARS)
            .collect();
        assert_eq!(label.chars().count(), 64);
        label
    }

    /// SLICE-E E1-2: a 64-character label never pushes the banner's Stop out
    /// of the 560-point window, and the banner says what the viewer may do
    /// before it names the viewer.
    #[test]
    fn a_long_label_keeps_the_banners_stop_in_the_window() {
        let t0 = Instant::now();
        let model = Model {
            sharing: vec![Sharing {
                session_id: "0011".to_owned(),
                label: crafted_label(),
                control: true,
                unattended: false,
                since: t0,
                services: None,
                capture: None,
            }],
            ..with_popups(Vec::new())
        };
        let window = Harness::new(model, t0);
        let (x0, _, x1, _) = window.bounds("Stop sharing");
        assert!(x0 >= 0.0 && x1 <= 560.0, "Stop at {x0}..{x1}");
        let line = window.text("SHARING");
        assert!(
            line.starts_with("SHARING · sees and controls this screen · \"Ana"),
            "{line}"
        );
        assert!(!line.contains(&crafted_label()), "shortened: {line}");
    }

    /// SLICE-E E1-2: the pairing card's name field starts with the name the
    /// device declared (a re-pair: the label it is pinned under), so the
    /// owner sees what an accept without typing pins.
    #[test]
    fn the_name_field_starts_with_the_declared_name() {
        for (pinned, expected) in [(None, "Phone"), (Some("Old laptop"), "Old laptop")] {
            let t0 = Instant::now();
            let mut popup = pairing_popup(3, t0);
            if let PopupKind::Pairing { pinned: p, .. } = &mut popup.kind {
                *p = pinned.map(str::to_owned);
            }
            let mut window = Harness::new(with_popups(vec![popup]), t0);
            window.pass(t0 + Duration::from_millis(1500), Vec::new());
            let pair = window.button("The codes match: pair");
            let actions = window.click(t0 + Duration::from_millis(1600), pair);
            assert!(
                matches!(
                    actions.as_slice(),
                    [Action::Pair {
                        id: 3,
                        decision: PairDecision::Accept { label: Some(l) },
                        ..
                    }] if l == expected
                ),
                "{actions:?}"
            );
        }
    }

    /// SLICE-E E1-5: the home screen's promise holds in every state: a paired
    /// device granted unattended access can start a session without asking
    /// (PLAN §B.8), so "you are asked before anyone sees this screen" was
    /// false while one exists.
    #[test]
    fn the_hosting_line_promises_only_what_is_true() {
        let t0 = Instant::now();
        let model = Model {
            hosting: Hosting::Published {
                reachable: true,
                state: "running".to_owned(),
                problem: None,
            },
            ..with_popups(Vec::new())
        };
        let window = Harness::new(model, t0);
        let line = window.text("Incoming requests");
        assert!(!line.contains("you are asked before anyone sees"), "{line}");
        assert!(
            line.contains("unless you granted one unattended access"),
            "{line}"
        );
    }

    /// U3-L2: while this screen may be in a picture that leaves it (a
    /// session live, one just allowed, another process hosting this home),
    /// the client's code question names no host; otherwise it quotes the
    /// name the host gave.
    #[test]
    fn the_code_question_names_no_host_while_this_screen_is_shared() {
        let t0 = Instant::now();
        let mut model = with_popups(Vec::new());
        model.confirm = Some(Confirm {
            id: 3,
            host_name: "Desk".to_owned(),
            sas: "654 321".to_owned(),
            host_waits_until: t0 + Duration::from_secs(50),
            deadline: t0 + Duration::from_secs(600),
        });
        let window = Harness::new(model.clone(), t0);
        let line = window.text("The host accepted");
        assert!(line.contains("it calls itself \"Desk\""), "{line}");
        let live = Model {
            sharing: vec![Sharing {
                session_id: "0011".to_owned(),
                label: "Laptop".to_owned(),
                control: true,
                unattended: false,
                since: t0,
                services: None,
                capture: None,
            }],
            ..model.clone()
        };
        let allowed = Model {
            accepted: Some(t0),
            ..model.clone()
        };
        let elsewhere = Model {
            hosted_elsewhere: true,
            ..model
        };
        for (case, model) in [
            ("live", live),
            ("allowed", allowed),
            ("elsewhere", elsewhere),
        ] {
            let window = Harness::new(model, t0);
            let line = window.text("The host accepted");
            assert_eq!(
                line, "The host accepted. Did its screen show this code?",
                "{case}"
            );
            assert!(
                window.nodes.iter().all(|n| {
                    n.value().is_none_or(|v| !v.contains("Desk"))
                        && n.label().is_none_or(|l| !l.contains("Desk"))
                }),
                "{case}: the host's name on screen"
            );
            assert!(window.has("Yes, the codes match"), "{case}");
        }
    }

    /// A card that moves (the waiting line above it coming as a question
    /// arrives behind it, or going as that one is answered, withdrawn or
    /// timed out) waits another second before a click on it counts.
    #[test]
    fn a_card_that_moves_waits_another_second() {
        let t0 = Instant::now();
        let mut window = Harness::new(with_popups(vec![session_popup(1, t0)]), t0);
        let arrived_at = t0 + Duration::from_secs(3);
        window.pass(arrived_at, Vec::new());
        let alone = window.button("Allow control");
        // A second question arrives: it waits, and its line above the card
        // moves the card down.
        window.model.popups.push(pairing_popup(2, t0));
        window.pass(arrived_at, Vec::new());
        let lower = window.button("Allow control");
        assert!(lower.y > alone.y, "the session card moved down");
        assert!(!window.has("Refuse"), "one question at a time");
        let early = window.click(arrived_at + Duration::from_millis(300), lower);
        assert!(early.is_empty(), "answered right after moving: {early:?}");

        // The waiting question goes: its line goes, and the card moves up.
        let moved_at = t0 + Duration::from_secs(6);
        window.pass(moved_at, Vec::new());
        window.model.popups.remove(1);
        window.pass(moved_at, Vec::new());
        let allow = window.button("Allow control");
        assert!(allow.y < lower.y, "the session card moved up");

        let early = window.click(moved_at + Duration::from_millis(300), allow);
        assert!(early.is_empty(), "answered right after moving: {early:?}");
        window.pass(moved_at + Duration::from_millis(1500), Vec::new());
        let late = window.click(moved_at + Duration::from_millis(1600), allow);
        assert!(
            matches!(
                late.as_slice(),
                [Action::Session {
                    id: 1,
                    decision: SessionDecision::AllowOnce,
                    ..
                }]
            ),
            "{late:?}"
        );
    }

    /// The redesign §4: one question at a time, the oldest first, with how
    /// many more are waiting; the next question appears only once the shown
    /// one is gone, as a new card whose accepts wait their second; a click
    /// on the shown card answers that card's question and no other.
    #[test]
    fn one_question_at_a_time_the_oldest_first() {
        let t0 = Instant::now();
        let mut model = with_popups(vec![
            session_popup(4, t0),
            pairing_popup(2, t0),
            session_popup(9, t0),
        ]);
        model.confirm = Some(Confirm {
            id: 7,
            host_name: "Desk".to_owned(),
            sas: "654 321".to_owned(),
            host_waits_until: t0 + Duration::from_secs(50),
            deadline: t0 + Duration::from_secs(600),
        });
        let mut window = Harness::new(model, t0);
        let later = t0 + Duration::from_secs(3);
        window.pass(later, Vec::new());
        // The pairing question (id 2) is the oldest: it alone is shown.
        assert!(window.text("3 more waiting").starts_with("3 more waiting"));
        assert!(window.has("Refuse") && window.has("The codes match: pair"));
        for other in ["Deny", "Allow control", "Yes, the codes match"] {
            assert!(!window.has(other), "{other} of a waiting question");
        }
        // Answered (the popup leaves the model): the session question 4
        // comes, in the pairing card's place, disarmed for its second.
        window.model.popups.retain(|p| p.id != 2);
        window.pass(later, Vec::new());
        assert!(window.text("2 more waiting").starts_with("2 more waiting"));
        assert!(!window.has("Refuse"));
        assert!(
            window.disabled("Allow control"),
            "the new card waits its second"
        );
        let allow = window.button("Allow control");
        let early = window.click(later + Duration::from_millis(300), allow);
        assert!(early.is_empty(), "{early:?}");
        window.pass(later + Duration::from_millis(1500), Vec::new());
        let late = window.click(later + Duration::from_millis(1600), allow);
        assert!(
            matches!(
                late.as_slice(),
                [Action::Session {
                    id: 4,
                    decision: SessionDecision::AllowOnce,
                    ..
                }]
            ),
            "{late:?}"
        );
        // Then this computer's code question (id 7), older than session 9.
        let at = later + Duration::from_secs(3);
        window.model.popups.retain(|p| p.id != 4);
        window.pass(at, Vec::new());
        assert!(window.text("1 more waiting").starts_with("1 more waiting"));
        assert!(window.has("Yes, the codes match") && !window.has("Deny"));
        assert!(window.disabled("Yes, the codes match"));
        // The last: no waiting line.
        window.model.confirm = None;
        window.pass(at, Vec::new());
        assert!(window.has("Deny") && window.has("Allow control"));
        assert!(
            window
                .nodes
                .iter()
                .all(|n| n.value().is_none_or(|v| !v.contains("more waiting"))),
            "nothing waits"
        );
    }

    /// Every screen state draws without a panic (no GPU needed): home in each
    /// Tor state, the popups of both roles, the banner and the setup card.
    #[test]
    fn every_screen_state_draws() {
        let now = Instant::now();
        let mut form = Form::default();
        let mut model = Model {
            id: Some("abcd efgh".to_owned()),
            ..Model::default()
        };
        for tor in [
            TorState::Starting,
            TorState::Trying {
                via: "obfs4 bridges",
                attempt: 2,
                of: 3,
            },
            TorState::Progress {
                via: "direct Tor",
                pct: 45,
                blocked: Some("We seem to be offline".to_owned()),
            },
            TorState::Ready { via: "Snowflake" },
            TorState::Failed("no network".to_owned()),
        ] {
            model.tor = tor;
            assert!(run(&model, &mut form).is_empty());
        }
        model.setup = Some(Setup {
            token_file: PathBuf::from("/tmp/x/portal-restore-token"),
            granted: false,
            busy: true,
            note: Some("declined".to_owned()),
        });
        model.popups = vec![
            Popup {
                id: 1,
                kind: PopupKind::Pairing {
                    name: "Laptop".to_owned(),
                    fingerprint: "ab:cd".to_owned(),
                    sas: "123 456".to_owned(),
                    pinned: Some("Old laptop".to_owned()),
                },
                deadline: now + Duration::from_secs(60),
            },
            Popup {
                id: 2,
                kind: PopupKind::Session {
                    label: "Laptop".to_owned(),
                    fingerprint: "ab:cd".to_owned(),
                },
                deadline: now + Duration::from_secs(60),
            },
        ];
        model.confirm = Some(Confirm {
            id: 3,
            host_name: "Desk".to_owned(),
            sas: "654 321".to_owned(),
            host_waits_until: now + Duration::from_secs(50),
            deadline: now + Duration::from_secs(600),
        });
        model.sharing = vec![Sharing {
            session_id: "0011".to_owned(),
            label: "Laptop".to_owned(),
            control: true,
            unattended: true,
            since: now,
            services: None,
            capture: Some(CaptureNote {
                source: "wayland",
                width: 1920,
                height: 1080,
                input: false,
                shown: None,
                all: false,
                screens: 0,
            }),
        }];
        for stage in [
            ClientStage::Reaching {
                id: "abcd".to_owned(),
            },
            ClientStage::Pairing {
                sas: "111 222".to_owned(),
            },
            ClientStage::Asking,
            ClientStage::Live(Viewing {
                host: "Desk".to_owned(),
                control: false,
                administrator: false,
                unattended: false,
                since: now,
                pictures: 3,
                size: (640, 480),
                stream: StreamInfo::default(),
                services: None,
                screens: None,
                route: crate::ui::model::RouteView::Tor(tornect_session::TorWhy::OldHost),
            }),
            ClientStage::Ended("SESSION ENDED by the host".to_owned()),
        ] {
            model.client = stage;
            model.note("something happened");
            assert!(run(&model, &mut form).is_empty(), "nothing clicked");
        }
        assert_eq!(
            form.labels.len(),
            1,
            "one label field, for the pairing popup"
        );
    }

    /// The stream window draws with and without a picture, and says where
    /// the picture went.
    #[test]
    fn the_stream_window_reports_where_the_picture_is() {
        let ctx = egui::Context::default();
        let viewing = Viewing {
            host: "Desk".to_owned(),
            control: true,
            administrator: false,
            unattended: false,
            since: Instant::now(),
            pictures: 1,
            size: (1600, 900),
            stream: StreamInfo::default(),
            services: None,
            screens: None,
            route: crate::ui::model::RouteView::Tor(tornect_session::TorWhy::OldHost),
        };
        let mut actions = Vec::new();
        let mut drawn = None;
        ctx.run_ui(egui::RawInput::default(), |ui| {
            drawn = stream_window(
                ui,
                Some(&viewing),
                Some((egui::TextureId::User(0), (1600, 900))),
                0,
                Instant::now(),
                &mut actions,
                &mut Default::default(),
            );
        })
        .drop_without_applying_deltas();
        let rect = drawn.expect("a picture was drawn");
        assert!((rect.width() / rect.height() - 16.0 / 9.0).abs() < 0.01);
        ctx.run_ui(egui::RawInput::default(), |ui| {
            drawn = stream_window(
                ui,
                None,
                None,
                0,
                Instant::now(),
                &mut actions,
                &mut Default::default(),
            );
        })
        .drop_without_applying_deltas();
        assert!(drawn.is_none());
        assert!(actions.is_empty());
    }
    /// The levels an invented Windows host with UAC off offers (§B.2.1):
    /// View only and "Allow as administrator", no plain Allow.
    fn always_admin() -> SheetLevels {
        SheetLevels::of(&tornect_core::levels::Availability::of(Some(
            &tornect_core::levels::WindowsFacts {
                installed: true,
                administrator: true,
                enable_lua: Some(0),
                ..tornect_core::levels::WindowsFacts::default()
            },
        )))
    }

    /// §B.2.1: a session sheet offers the answers of its row and nothing
    /// else — a level the host cannot deliver is absent, never greyed —
    /// with the row's sentence under the buttons. Deny stays first.
    #[test]
    fn the_session_sheet_offers_only_the_levels_of_its_row() {
        use tornect_core::levels::{
            Availability, SENTENCE_ALWAYS_ADMINISTRATOR, SENTENCE_LINUX, WindowsFacts,
        };

        let t0 = Instant::now();
        let sheet = |levels: SheetLevels| {
            let mut model = with_popups(vec![session_popup(7, t0)]);
            model.levels.insert(7, levels);
            Harness::new(model, t0)
        };
        // Linux: three answers and the Linux sentence.
        let linux = sheet(SheetLevels::of(&Availability::LINUX));
        for label in ["Deny", "View only", "Allow control"] {
            assert!(linux.has(label), "{label}");
        }
        assert!(!linux.has("Allow as administrator"));
        assert_eq!(linux.text("On Linux, Tornect never runs"), SENTENCE_LINUX);
        assert!(linux.bounds("Deny").0 < linux.bounds("View only").0);
        // Installed with UAC on: the administrator answer takes Windows'
        // prompt and the helper, which this build does not have: absent.
        let prompt = sheet(SheetLevels::of(&Availability::of(Some(&WindowsFacts {
            installed: true,
            administrator: true,
            ..WindowsFacts::default()
        }))));
        assert!(prompt.has("Allow control") && !prompt.has("Allow as administrator"));
        assert!(!prompt.has("Allow as administrator…"));
        // UAC off: control is administrator access, so no plain Allow; the
        // administrator answer on a row of its own, under Deny's.
        let admin = sheet(always_admin());
        assert!(admin.has("Deny") && admin.has("View only"));
        assert!(
            !admin.has("Allow control"),
            "a level it cannot give is absent"
        );
        assert!(
            admin.disabled("Allow as administrator"),
            "armed after a second"
        );
        let (deny, allow_admin) = (admin.bounds("Deny"), admin.bounds("Allow as administrator"));
        assert!(allow_admin.1 >= deny.3, "{deny:?} {allow_admin:?}");
        assert_eq!(
            admin.text("Windows runs every program"),
            SENTENCE_ALWAYS_ADMINISTRATOR
        );
        // A sheet from before the levels: the three answers, no sentence.
        let plain = Harness::new(with_popups(vec![session_popup(7, t0)]), t0);
        assert!(plain.has("Allow control") && !plain.has("Allow as administrator"));
    }

    /// §B.2.1 arming MUSTs: "Allow as administrator" where no Windows prompt
    /// follows opens a Tornect confirmation — it never answers by itself —
    /// whose Deny comes first and answers at once, and whose accept is armed
    /// only after the confirmation has been still for its own second; a
    /// raise or a restore re-arms it; the administrator answer is never
    /// beside Allow.
    #[test]
    fn the_administrator_answer_asks_a_tornect_confirmation() {
        let t0 = Instant::now();
        let mut model = with_popups(vec![session_popup(7, t0)]);
        model.levels.insert(7, always_admin());
        let mut window = Harness::new(model, t0);
        let early = window.click(
            t0 + Duration::from_millis(300),
            window.button("Allow as administrator"),
        );
        assert!(early.is_empty(), "{early:?}");
        window.pass(t0 + Duration::from_millis(1500), Vec::new());
        let at = window.button("Allow as administrator");
        let asked = window.click(t0 + Duration::from_millis(1600), at);
        assert_eq!(
            asked,
            vec![Action::AdminConfirm { id: 7 }],
            "an answer without confirmation"
        );

        // The app puts the confirmation up in its place.
        window.model.admin_confirm.insert(7);
        let t1 = t0 + Duration::from_secs(2);
        window.pass(t1, Vec::new());
        window.pass(t1, Vec::new());
        assert!(!window.has("View only") && !window.has("Allow control"));
        assert!(
            window
                .text("They can change anything on this computer")
                .contains("Tornect's settings and its log")
        );
        assert!(!window.disabled("Deny"), "Deny answers at once");
        assert!(window.disabled("Allow as administrator"), "its own second");
        let (deny, accept) = (
            window.bounds("Deny"),
            window.bounds("Allow as administrator"),
        );
        assert!(deny.2 <= accept.0, "Deny first: {deny:?} {accept:?}");
        let early = window.click(
            t1 + Duration::from_millis(300),
            window.button("Allow as administrator"),
        );
        assert!(
            early.is_empty(),
            "answered in the confirmation's first second: {early:?}"
        );
        // The window came back (a raise, a restore): the second starts again.
        window.pass(t1 + Duration::from_millis(1100), Vec::new());
        assert!(!window.disabled("Allow as administrator"));
        window.form.window_came_back();
        let t2 = t1 + Duration::from_millis(1200);
        window.pass(t2, Vec::new());
        assert!(
            window.disabled("Allow as administrator"),
            "a raise re-arms it"
        );
        window.pass(t2 + Duration::from_millis(1100), Vec::new());
        let late = window.click(
            t2 + Duration::from_millis(1200),
            window.button("Allow as administrator"),
        );
        assert_eq!(
            late,
            vec![Action::Session {
                id: 7,
                decision: SessionDecision::AllowOnceAdmin,
                pointer: true,
            }]
        );
        // Deny on the confirmation refuses the session.
        let denied = window.click(t2 + Duration::from_millis(1300), window.button("Deny"));
        assert!(
            matches!(
                denied.as_slice(),
                [Action::Session {
                    id: 7,
                    decision: SessionDecision::Deny,
                    ..
                }]
            ),
            "{denied:?}"
        );

        // A row that offers both (the helper's, M-FEAT-3): never side by side.
        let mut both = with_popups(vec![session_popup(8, t0)]);
        let mut levels = always_admin();
        levels.answers.allow = true;
        both.levels.insert(8, levels);
        let window = Harness::new(both, t0);
        let (allow, admin) = (
            window.bounds("Allow control"),
            window.bounds("Allow as administrator"),
        );
        assert!(admin.1 >= allow.3, "beside Allow: {allow:?} {admin:?}");
    }

    /// `PromptOnSecureDesktop` 0 (§B.2.1): the sheet says that Windows'
    /// prompts show on the shared screen, beside the row's own sentence, and
    /// not otherwise.
    #[test]
    fn prompts_on_the_shared_screen_are_said() {
        use tornect_core::levels::{Availability, WindowsFacts};

        let t0 = Instant::now();
        for (shared, said) in [(Some(0), true), (Some(1), false), (None, false)] {
            let mut model = with_popups(vec![session_popup(7, t0)]);
            model.levels.insert(
                7,
                SheetLevels::of(&Availability::of(Some(&WindowsFacts {
                    installed: false,
                    prompt_on_secure_desktop: shared,
                    ..WindowsFacts::default()
                }))),
            );
            let window = Harness::new(model, t0);
            let texts: Vec<&str> = window.nodes.iter().filter_map(|n| n.value()).collect();
            assert_eq!(
                texts.contains(&SENTENCE_SECURE_DESKTOP_OFF),
                said,
                "{shared:?}: {texts:?}"
            );
            assert!(
                texts.contains(&tornect_core::levels::SENTENCE_STANDALONE),
                "{texts:?}"
            );
        }
    }

    /// The stream bar says "Control · administrator" only when the signed
    /// accept said so (the backend's `Viewing::administrator`).
    #[test]
    fn the_stream_bar_names_the_signed_level() {
        for (administrator, shown, hidden) in [
            (true, "Control · administrator", "control"),
            (false, "control", "Control · administrator"),
        ] {
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            let viewing = Viewing {
                host: "Desk".to_owned(),
                control: true,
                administrator,
                unattended: false,
                since: Instant::now(),
                pictures: 1,
                size: (1600, 900),
                stream: StreamInfo::default(),
                services: None,
                screens: None,
                route: crate::ui::model::RouteView::Tor(tornect_session::TorWhy::OldHost),
            };
            let mut nodes = Vec::new();
            for _ in 0..2 {
                let out = ctx.run_ui(egui::RawInput::default(), |ui| {
                    let _ = stream_window(
                        ui,
                        Some(&viewing),
                        None,
                        0,
                        Instant::now(),
                        &mut Vec::new(),
                        &mut Default::default(),
                    );
                });
                if let Some(update) = &out.platform_output.accesskit_update {
                    nodes = update.nodes.iter().map(|(_, n)| n.clone()).collect();
                }
                out.drop_without_applying_deltas();
            }
            let texts: Vec<String> = nodes
                .iter()
                .filter_map(|n| n.value().map(str::to_owned))
                .collect();
            assert!(texts.iter().any(|t| t == shown), "{texts:?}");
            assert!(!texts.iter().any(|t| t == hidden), "{texts:?}");
        }
    }

    /// Every text of the stream window as a screen reader gets it: each
    /// accessibility node's label, value and description, after two passes
    /// (egui lays out on the first).
    fn viewer_texts(viewing: &Viewing, viewer: &mut ViewerState) -> Vec<String> {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut nodes = Vec::new();
        for _ in 0..2 {
            let out = ctx.run_ui(egui::RawInput::default(), |ui| {
                let _ = stream_window(
                    ui,
                    Some(viewing),
                    Some((egui::TextureId::User(0), (1600, 900))),
                    0,
                    Instant::now(),
                    &mut Vec::new(),
                    viewer,
                );
            });
            if let Some(update) = &out.platform_output.accesskit_update {
                nodes = update.nodes.iter().map(|(_, n)| n.clone()).collect();
            }
            out.drop_without_applying_deltas();
        }
        nodes
            .iter()
            .flat_map(|n| [n.label(), n.value(), n.description()])
            .flatten()
            .map(str::to_owned)
            .collect()
    }

    /// The host's name shows inside the viewer only while this screen is not
    /// shared: a picture of this screen that leaves it never carries the name
    /// of the computer it is connected to.
    #[test]
    fn the_viewer_names_the_host_only_while_this_screen_is_not_shared() {
        let viewing = Viewing {
            host: "Desk".to_owned(),
            control: true,
            administrator: false,
            unattended: false,
            since: Instant::now(),
            pictures: 1,
            size: (1600, 900),
            stream: StreamInfo::default(),
            services: None,
            screens: None,
            route: crate::ui::model::RouteView::Tor(tornect_session::TorWhy::OldHost),
        };
        for shared in [false, true] {
            let mut viewer = ViewerState::default();
            viewer.shared = shared;
            viewer.details = true;
            let texts = viewer_texts(&viewing, &mut viewer);
            assert_eq!(
                texts.iter().any(|t| t.contains("Desk")),
                !shared,
                "shared: {shared}: {texts:?}"
            );
            // The help line and the connection's details are on screen.
            let whom = if shared {
                "the remote computer"
            } else {
                "Desk"
            };
            let help = format!("your keyboard goes to {whom}.");
            assert!(texts.iter().any(|t| t.contains(&help)), "{texts:?}");
            assert!(texts.iter().any(|t| t == "Route"), "{texts:?}");
        }
    }

    /// The labels of the buttons, in the order of the accessibility tree (a
    /// walk from its root, children in order): what a screen reader reads.
    fn button_order(window: &mut Harness, now: Instant) -> Vec<String> {
        use egui::accesskit::{NodeId, Role};
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(560.0, 720.0),
            )),
            time: Some(now.duration_since(window.start).as_secs_f64()),
            ..egui::RawInput::default()
        };
        let mut actions = Vec::new();
        let (model, form) = (&window.model, &mut window.form);
        let out = window.ctx.run_ui(raw, |ui| {
            main_window(ui, model, form, now, &mut actions);
        });
        let update = out
            .platform_output
            .accesskit_update
            .clone()
            .expect("an accessibility update");
        out.drop_without_applying_deltas();
        let nodes: HashMap<NodeId, &egui::accesskit::Node> =
            update.nodes.iter().map(|(id, n)| (*id, n)).collect();
        let children: Vec<NodeId> = nodes
            .values()
            .flat_map(|n| n.children().iter().copied())
            .collect();
        let root = update.tree.as_ref().map_or_else(
            || {
                *nodes
                    .keys()
                    .find(|id| !children.contains(id))
                    .expect("a root")
            },
            |tree| tree.root,
        );
        let mut order = Vec::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if let Some(node) = nodes.get(&id) {
                if node.role() == Role::Button
                    && let Some(label) = node.label()
                {
                    order.push(label.to_owned());
                }
                stack.extend(node.children().iter().rev());
            }
        }
        order
    }

    /// §B.2.1 on the session sheet: "<name> wants to connect to this
    /// computer", Deny first in the accessibility tree, and the line under
    /// each answer the row offers: Linux's sentence once (it is the line
    /// under Allow), Windows' Allow line, the line of an administrator
    /// account that elevates without prompting, and why an administrator
    /// answer this build cannot give is absent.
    #[test]
    fn the_session_sheet_says_what_each_answer_does() {
        use tornect_core::levels::{
            Availability, LINE_ALLOW_WINDOWS, SENTENCE_LINUX, SENTENCE_NO_HELPER, WindowsFacts,
        };

        let t0 = Instant::now();
        let sheet = |levels: Availability| {
            let mut model = with_popups(vec![session_popup(7, t0)]);
            model.levels.insert(7, SheetLevels::of(&levels));
            Harness::new(model, t0)
        };
        let texts = |window: &Harness| -> Vec<String> {
            window
                .nodes
                .iter()
                .filter_map(|n| n.value().map(str::to_owned))
                .collect()
        };
        let mut linux = sheet(Availability::LINUX);
        let all = texts(&linux);
        assert!(
            all.iter()
                .any(|t| t == "\"Laptop\" wants to connect to this computer"),
            "{all:?}"
        );
        assert!(all.iter().any(|t| t == LINE_VIEW_ONLY), "{all:?}");
        assert_eq!(
            all.iter().filter(|t| *t == SENTENCE_LINUX).count(),
            1,
            "the Linux sentence once: {all:?}"
        );
        let order = button_order(&mut linux, t0);
        let at = |label: &str| order.iter().position(|b| b == label);
        assert!(at("Deny") < at("View only") && at("View only") < at("Allow control"));
        assert_eq!(at("Deny"), Some(0), "Deny first: {order:?}");

        let installed = sheet(Availability::of(Some(&WindowsFacts {
            installed: true,
            administrator: true,
            ..WindowsFacts::default()
        })));
        let all = texts(&installed);
        assert!(all.iter().any(|t| t == LINE_ALLOW_WINDOWS), "{all:?}");
        if !tornect_core::levels::ADMIN_HELPER {
            assert!(all.iter().any(|t| t == SENTENCE_NO_HELPER), "{all:?}");
        }
        let no_prompt = sheet(Availability::of(Some(&WindowsFacts {
            installed: true,
            administrator: true,
            consent_prompt_behavior_admin: Some(0),
            ..WindowsFacts::default()
        })));
        let all = texts(&no_prompt);
        assert!(
            !all.iter().any(|t| t == LINE_ALLOW_WINDOWS),
            "no plain Allow on the no-prompt row: {all:?}"
        );
        if tornect_core::levels::ADMIN_HELPER {
            assert_eq!(
                all.iter().filter(|t| *t == ADMIN_LINE_NO_PROMPT).count(),
                1,
                "the administrator line once: {all:?}"
            );
        } else {
            assert!(all.iter().any(|t| t == SENTENCE_NO_HELPER), "{all:?}");
        }
    }

    /// The no-prompt row (`ConsentPromptBehaviorAdmin` 0; the operator's
    /// ruling of 2026-09-29) offers what the always-administrator row does:
    /// View only and "Allow as administrator" with the Tornect confirmation,
    /// no plain Allow, the administrator line once, and for a device paired
    /// moments before, the scam line beside the administrator answer and on
    /// the confirmation.
    #[test]
    fn the_no_prompt_row_offers_the_administrator_answer_with_its_scam_line() {
        use tornect_core::levels::{Availability, LINE_ALLOW_WINDOWS, WindowsFacts};

        let row = Availability::of(Some(&WindowsFacts {
            installed: true,
            administrator: true,
            consent_prompt_behavior_admin: Some(0),
            ..WindowsFacts::default()
        }));
        // What the row offers with the administrator helper.
        let mut levels = SheetLevels::of(&row);
        levels.answers = row.answers;
        levels.sentence = row.sentence;
        for recent in [true, false] {
            let t0 = Instant::now();
            let mut model = with_popups(vec![session_popup(7, t0)]);
            model.levels.insert(7, levels);
            if recent {
                model.paired_recently.insert(7);
            }
            let mut window = Harness::new(model, t0);
            let texts: Vec<String> = window
                .nodes
                .iter()
                .filter_map(|n| n.value().map(str::to_owned))
                .collect();
            assert!(!texts.iter().any(|t| t == LINE_ALLOW_WINDOWS), "{texts:?}");
            assert_eq!(
                texts.iter().filter(|t| *t == ADMIN_LINE_NO_PROMPT).count(),
                1,
                "{texts:?}"
            );
            let said = |w: &Harness| w.nodes.iter().any(|n| n.value() == Some(SCAM_LINE));
            assert_eq!(said(&window), recent, "beside the answer, {recent}");
            let order = button_order(&mut window, t0);
            assert!(!order.iter().any(|b| b == "Allow control"), "{order:?}");
            assert!(
                order.iter().any(|b| b == "Allow as administrator"),
                "{order:?}"
            );
            assert_eq!(order.first().map(String::as_str), Some("Deny"), "{order:?}");
            window.model.admin_confirm.insert(7);
            window.pass(t0 + Duration::from_secs(2), Vec::new());
            assert_eq!(said(&window), recent, "the confirmation too, {recent}");
        }
    }

    /// §B.2.1: "Allow as administrator…" (a Windows prompt follows) sits on
    /// a row of its own, armed like every accept, and asks for the prompt; it
    /// never answers. Until the administrator helper exists the prompt ends
    /// at once: the sheet says administrator access was not given, the
    /// answer is gone, the other answers stay and wait their second again.
    #[test]
    fn the_prompt_path_ends_honestly_until_the_helper_exists() {
        let t0 = Instant::now();
        let mut model = with_popups(vec![session_popup(7, t0)]);
        let mut levels = SheetLevels::of(&tornect_core::levels::Availability::LINUX);
        levels.answers.admin = Some(AdminPath::WindowsPrompt);
        model.levels.insert(7, levels);
        let mut window = Harness::new(model, t0);
        assert!(
            window.disabled("Allow as administrator…"),
            "armed after 1 s"
        );
        let (allow, admin) = (
            window.bounds("Allow control"),
            window.bounds("Allow as administrator…"),
        );
        assert!(
            admin.1 >= allow.3,
            "never beside Allow: {allow:?} {admin:?}"
        );
        assert!(
            window
                .text("Windows asks you to confirm next")
                .starts_with(ADMIN_LINE)
        );
        window.pass(t0 + Duration::from_millis(1500), Vec::new());
        let asked = window.click(
            t0 + Duration::from_millis(1600),
            window.button("Allow as administrator…"),
        );
        assert_eq!(asked, vec![Action::AdminPrompt { id: 7 }]);

        // What the app does with it in this build.
        window.form.rearm(7);
        window.model.admin_not_given.insert(7);
        let t1 = t0 + Duration::from_secs(2);
        window.pass(t1, Vec::new());
        assert!(
            window
                .text("Administrator access was not given")
                .contains("other answers are still open")
        );
        assert!(!window.has("Allow as administrator…"));
        assert!(window.disabled("View only") && window.disabled("Allow control"));
        assert!(!window.disabled("Deny"));
        window.pass(t1 + Duration::from_millis(1100), Vec::new());
        let late = window.click(t1 + Duration::from_millis(1200), window.button("View only"));
        assert_eq!(
            late,
            vec![Action::Session {
                id: 7,
                decision: SessionDecision::AllowOnceViewOnly,
                pointer: true,
            }]
        );
    }

    /// §B.6.1 item 7 at pin time: a name that would put device words in the
    /// name slot, or quote marks and dots that imitate a sheet's lines, is
    /// not what an accept may save; the sheet says so and its accept stays
    /// off until another name is typed.
    #[test]
    fn a_name_that_reads_like_words_is_not_saved() {
        let t0 = Instant::now();
        let mut popup = pairing_popup(3, t0);
        if let PopupKind::Pairing { name, .. } = &mut popup.kind {
            *name = "arctic crisp lamp orbit".to_owned();
        }
        let mut window = Harness::new(with_popups(vec![popup]), t0);
        window.pass(t0 + Duration::from_millis(1500), Vec::new());
        assert!(
            window
                .text("This name cannot be saved")
                .contains("three of its words are device words. Type another name.")
        );
        assert!(window.disabled("The codes match: pair"));
        let pair = window.button("The codes match: pair");
        assert!(
            window
                .click(t0 + Duration::from_millis(1600), pair)
                .is_empty()
        );
        window.form.labels.insert(3, "Tablet".to_owned());
        // The red line goes, the answers move up and wait their second again.
        window.pass(t0 + Duration::from_millis(1700), Vec::new());
        window.pass(t0 + Duration::from_millis(2800), Vec::new());
        assert!(!window.disabled("The codes match: pair"));
        let pair = window.button("The codes match: pair");
        let paired = window.click(t0 + Duration::from_millis(3000), pair);
        assert!(
            matches!(
                paired.as_slice(),
                [Action::Pair {
                    id: 3,
                    decision: PairDecision::Accept { label: Some(l) },
                    ..
                }] if l == "Tablet"
            ),
            "{paired:?}"
        );
    }

    /// The banner says the level the host signed: "as administrator" only for
    /// a session that an administrator answer started.
    #[test]
    fn the_banner_says_an_administrator_session() {
        for admin in [false, true] {
            let t0 = Instant::now();
            let mut model = Model {
                sharing: vec![Sharing {
                    session_id: "0011".to_owned(),
                    label: "Laptop".to_owned(),
                    control: true,
                    unattended: false,
                    since: t0,
                    services: None,
                    capture: None,
                }],
                ..with_popups(Vec::new())
            };
            if admin {
                model.admin_sessions.insert("0011".to_owned());
            }
            let window = Harness::new(model, t0);
            let line = window.text("SHARING");
            assert!(
                line.starts_with("SHARING · sees and controls this screen"),
                "{line}"
            );
            assert_eq!(line.contains("as administrator"), admin, "{line}");
        }
    }

    /// Decision M1-75 (3), the final review: where the viewer can switch
    /// between two or more monitors or see them all, the session sheet asks
    /// for "this computer's N screens", not for "this screen"; with one
    /// screen, or no count (Wayland's dialog picks one), it asks for "this
    /// screen" as before.
    #[test]
    fn a_session_sheet_names_the_screens_a_viewer_can_switch_between() {
        let t0 = Instant::now();
        for (count, asked) in [
            (None, "this screen."),
            (Some(1), "this screen."),
            (Some(2), "this computer's 2 screens."),
            (Some(3), "this computer's 3 screens."),
        ] {
            let mut model = with_popups(vec![session_popup(7, t0)]);
            if let Some(count) = count {
                model.sheet_screens.insert(7, count);
            }
            let window = Harness::new(model, t0);
            let line = window.text("\"Laptop\" wants to see ");
            assert!(
                line.starts_with(&format!("\"Laptop\" wants to see {asked} Whatever")),
                "{count:?}: {line}"
            );
        }
    }

    /// Design `direct` §3.6 [SEC]: while an accept may let the session
    /// connect directly (this computer's policy is not Tor only: direct
    /// connections on, or `lan_only`), the session sheet says what the
    /// asking device then learns, under the request and again under the
    /// administrator confirmation: this computer's internet address where
    /// direct connections reach the internet (Phase B), its local address
    /// under `lan_only` or in a build whose direct connections stay on the
    /// local network (Phase A). With direct connections off, or a bridge in
    /// use, it says nothing of it.
    #[test]
    fn the_session_sheet_says_what_an_accept_discloses_on_a_direct_path() {
        let t0 = Instant::now();
        let local = direct_consent_line("Laptop", Reveals::Local);
        assert_eq!(
            local,
            "Accepting also lets \"Laptop\" learn this computer's local address (Settings > \
             Connection)."
        );
        let internet = direct_consent_line("Laptop", Reveals::Internet);
        assert_eq!(
            internet,
            "Accepting also lets \"Laptop\" learn this computer's internet address (Settings > \
             Connection)."
        );
        // A name, the settings, the line said in each build (local network
        // only, internet).
        type Case<'a> = (&'static str, fn(&mut Model), [Option<&'a String>; 2]);
        let cases: [Case<'_>; 4] = [
            ("direct on", |_| {}, [Some(&local), Some(&internet)]),
            (
                "lan_only",
                |m| m.settings.lan_only = true,
                [Some(&local), Some(&local)],
            ),
            ("direct off", |m| m.settings.direct = false, [None, None]),
            (
                "a bridge in use",
                |m| m.settings.bridged_off = true,
                [None, None],
            ),
        ];
        for (case, set, said) in cases {
            for (internet_build, said) in [false, true].into_iter().zip(said) {
                let case = format!("{case} {internet_build}");
                let prepare = |model: &mut Model| {
                    model.settings.internet = internet_build;
                    set(model);
                };
                let mut model = with_popups(vec![session_popup(7, t0)]);
                prepare(&mut model);
                let window = Harness::new(model, t0);
                assert!(
                    window
                        .texts()
                        .iter()
                        .any(|t| t.starts_with("\"Laptop\" wants to see ")),
                    "{case}"
                );
                for line in [&local, &internet] {
                    assert_eq!(
                        window.texts().contains(line),
                        said == Some(line),
                        "{case}: {line}"
                    );
                }
                // Under the administrator confirmation too.
                let mut model = with_popups(vec![session_popup(7, t0)]);
                prepare(&mut model);
                model.levels.insert(7, always_admin());
                model.admin_confirm.insert(7);
                let window = Harness::new(model, t0);
                assert!(window.has("Allow as administrator"), "{case}");
                for line in [&local, &internet] {
                    assert_eq!(
                        window.texts().contains(line),
                        said == Some(line),
                        "{case}: confirming: {line}"
                    );
                }
            }
        }
    }

    /// Design `direct` §3.6: the one-time notice says that direct
    /// connections are on and what each computer learns, with the direct
    /// switch (saving `Direct(..)`) and OK (saving `DirectNoticeSeen`). It
    /// shows while its latch is up only, and waits under a question and
    /// while this screen is shared, where a save would be refused.
    #[test]
    fn the_direct_notice_says_what_an_accept_reveals_until_its_ok() {
        let t0 = Instant::now();
        assert_eq!(
            DIRECT_NOTICE,
            "Direct connections are on. After a session is accepted, the two computers try to \
             connect directly, which is faster, and each learns the other's IP address. To keep \
             your IP address hidden from the computers you connect to, turn this off."
        );
        let notice = DIRECT_NOTICE.to_owned();
        let switch = pages::direct_switch(true);
        let mut model = with_popups(Vec::new());
        model.settings.internet = true;
        model.direct_notice = true;
        let mut window = Harness::new(model.clone(), t0);
        assert!(window.texts().contains(&notice), "{:?}", window.texts());
        assert!(window.has(switch));
        let at = window.button(switch);
        assert_eq!(
            window.click(t0, at),
            vec![Action::SaveSettings(SettingsChange::Direct(false))]
        );
        let at = window.button("OK");
        assert_eq!(
            window.click(t0, at),
            vec![Action::SaveSettings(SettingsChange::DirectNoticeSeen)]
        );
        // Off already (the switch was turned off from the notice): the
        // switch says so and turns it on again.
        let mut off = model.clone();
        off.settings.direct = false;
        let mut window = Harness::new(off, t0);
        assert!(window.texts().contains(&notice));
        let at = window.button(switch);
        assert_eq!(
            window.click(t0, at),
            vec![Action::SaveSettings(SettingsChange::Direct(true))]
        );
        // Without its latch, under a question, and while shared: nothing.
        let mut cases: Vec<(&str, Model)> = Vec::new();
        let mut down = model.clone();
        down.direct_notice = false;
        cases.push(("no latch", down));
        let mut asking = model.clone();
        asking.popups = vec![session_popup(7, t0)];
        cases.push(("a question", asking));
        let mut shared = model.clone();
        shared.hosted_elsewhere = true;
        cases.push(("shared", shared));
        for (case, model) in cases {
            let window = Harness::new(model, t0);
            assert!(!window.texts().contains(&notice), "{case}");
            assert!(!window.has(switch), "{case}");
        }
    }

    /// The review of step B11: with the notice latched, a field of the page
    /// being typed into keeps the focus while a question comes, which the
    /// card waits under, and goes again: the page's widgets have the same
    /// ids whether the card is drawn or not.
    #[test]
    fn a_page_field_keeps_the_focus_while_the_notice_waits_under_a_question() {
        let t0 = Instant::now();
        let notice = DIRECT_NOTICE.to_owned();
        let mut model = with_popups(Vec::new());
        model.settings.internet = true;
        model.direct_notice = true;
        let mut window = Harness::new(model, t0);
        assert!(window.texts().contains(&notice));
        let b = window
            .nodes
            .iter()
            .find(|n| n.role() == egui::accesskit::Role::TextInput)
            .and_then(egui::accesskit::Node::bounds)
            .expect("the connect field");
        let at = egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32);
        assert!(window.click(t0, at).is_empty());
        let field = window.ctx.memory(|m| m.focused());
        assert!(field.is_some(), "the field has the focus");
        // egui's clock only moves forward: each pass 100 ms after the last.
        let mut now = t0 + Duration::from_millis(50);
        let mut pass = |window: &mut Harness, events: Vec<egui::Event>| {
            now += Duration::from_millis(100);
            window.pass(now, events)
        };
        pass(&mut window, vec![egui::Event::Text("ab".to_owned())]);
        assert_eq!(window.form.connect_to, "ab");

        window.model.popups = vec![session_popup(7, t0)];
        for _ in 0..2 {
            pass(&mut window, Vec::new());
        }
        assert!(!window.texts().contains(&notice), "the card waits");
        assert_eq!(window.ctx.memory(|m| m.focused()), field, "a question");
        window.model.popups.clear();
        for _ in 0..2 {
            pass(&mut window, Vec::new());
        }
        assert!(window.texts().contains(&notice), "the card is back");
        assert_eq!(window.ctx.memory(|m| m.focused()), field, "it went");
        pass(&mut window, vec![egui::Event::Text("c".to_owned())]);
        assert_eq!(window.form.connect_to, "abc", "typed into the same field");
    }

    /// Decision M1-75 (3), the final review: once capture says it lists two
    /// or more monitors, the banner says "this computer's screens" at every
    /// level; before it said (0) and with one it says "this screen".
    #[test]
    fn the_banner_names_the_screens_of_a_host_with_several() {
        let t0 = Instant::now();
        for (screens, control, said) in [
            (0, true, "SHARING · sees and controls this screen · "),
            (1, true, "SHARING · sees and controls this screen · "),
            (
                2,
                true,
                "SHARING · sees and controls this computer's screens · ",
            ),
            (
                3,
                false,
                "SHARING · sees this computer's screens (view only) · ",
            ),
            (1, false, "SHARING · sees this screen (view only) · "),
        ] {
            let model = Model {
                sharing: vec![Sharing {
                    session_id: "0011".to_owned(),
                    label: "Laptop".to_owned(),
                    control,
                    unattended: false,
                    since: t0,
                    services: None,
                    capture: Some(CaptureNote {
                        source: "gdi",
                        width: 1920,
                        height: 1080,
                        input: control,
                        shown: None,
                        all: false,
                        screens,
                    }),
                }],
                ..with_popups(Vec::new())
            };
            let window = Harness::new(model, t0);
            let line = window.text("SHARING");
            assert!(line.starts_with(said), "{screens} {control}: {line}");
        }
    }

    /// §B.2.1 (T10): for a device paired moments before, the administrator
    /// answer and its confirmation carry the scam line; otherwise, and on a
    /// sheet without the administrator answer, it is not there.
    #[test]
    fn a_device_paired_moments_before_gets_the_scam_line() {
        for (recent, admin) in [(true, true), (false, true), (true, false)] {
            let t0 = Instant::now();
            let mut model = with_popups(vec![session_popup(7, t0)]);
            model.levels.insert(
                7,
                if admin {
                    always_admin()
                } else {
                    SheetLevels::of(&tornect_core::levels::Availability::LINUX)
                },
            );
            if recent {
                model.paired_recently.insert(7);
            }
            let mut window = Harness::new(model, t0);
            let said = |w: &Harness| w.nodes.iter().any(|n| n.value() == Some(SCAM_LINE));
            assert_eq!(said(&window), recent && admin, "{recent} {admin}");
            if admin {
                window.model.admin_confirm.insert(7);
                window.pass(t0 + Duration::from_secs(2), Vec::new());
                assert_eq!(said(&window), recent, "the confirmation too");
            }
        }
    }

    /// §B.8.6.3, r7: the "Ask before starting" sheet of an admin grant says that the
    /// device wants to connect as administrator, a grant at none's that it wants to
    /// connect; Deny and Allow only, since the level comes from the grant. Allow waits for
    /// its second and answers the pointer only; no run of keys allows.
    #[test]
    fn the_ask_sheet_names_the_administrator_level_with_deny_and_allow_only() {
        for administrator in [true, false] {
            let t0 = Instant::now();
            let model = with_popups(vec![ask_popup(5, t0, administrator)]);
            let mut window = Harness::new(model, t0);
            let later = t0 + Duration::from_secs(2);
            window.pass(later, Vec::new());
            assert_eq!(
                window.text("\"Laptop\" wants"),
                if administrator {
                    "\"Laptop\" wants to connect as administrator"
                } else {
                    "\"Laptop\" wants to connect to this computer"
                }
            );
            for absent in [
                "View only",
                "Allow control",
                "Allow as administrator",
                "Allow as administrator…",
            ] {
                assert!(!window.has(absent), "{absent} on the sheet");
            }
            let deny = window.button("Deny");
            assert_eq!(
                window.click(later, deny),
                vec![Action::Ask {
                    id: 5,
                    allow: false,
                    pointer: true
                }]
            );
            let allow = window.button("Allow");
            assert_eq!(
                window.click(later, allow),
                vec![Action::Ask {
                    id: 5,
                    allow: true,
                    pointer: true
                }]
            );
        }
        // Before its second, Allow is disabled; keys alone never allow.
        let t0 = Instant::now();
        let mut window = Harness::new(with_popups(vec![ask_popup(6, t0, true)]), t0);
        assert!(window.disabled("Allow"));
        let later = t0 + Duration::from_secs(5);
        let mut actions = Vec::new();
        for _ in 0..4 {
            actions.extend(window.key(later, egui::Key::Tab));
            actions.extend(window.key(later, egui::Key::Enter));
            actions.extend(window.key(later, egui::Key::Space));
        }
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::Ask { allow: true, .. })),
            "{actions:?}"
        );
    }

    /// The services design §7.4, decision M1-76 (cw): an "Ask before starting" sheet
    /// whose session may be control says once, under Deny and Allow, what control also
    /// gives here, from the saved settings and this desktop, as the session sheet does
    /// (with no block window after it, it is the only sheet at session time); one whose
    /// session can only be view only, or with nothing control gives, says nothing.
    #[test]
    fn the_ask_sheet_says_what_control_also_gives() {
        use tornect_core::config::Services;

        const ALL: &str = "With control they can also see and copy any file you can open on \
                           this computer, send files into Downloads › Tornect and copy text to \
                           and from this computer's clipboard.";
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(2);
        let ask = |administrator: bool, control: bool, services: Services| {
            let mut model = with_popups(vec![ask_popup_for(5, t0, administrator, control)]);
            model.settings.services = services;
            let mut window = Harness::new(model, t0);
            window.pass(later, Vec::new());
            window
        };
        let said = |window: &Harness| {
            window
                .texts()
                .into_iter()
                .filter(|t| t.starts_with("With control"))
                .collect::<Vec<_>>()
        };
        for administrator in [false, true] {
            let window = ask(administrator, true, Services::default());
            assert_eq!(said(&window), vec![ALL.to_owned()], "{administrator}");
            let line = text_bounds(&window, "With control");
            let allow = window.bounds("Allow");
            assert!(line.1 >= allow.3, "under the buttons: {line:?} {allow:?}");
            let window = ask(administrator, false, Services::default());
            assert!(said(&window).is_empty(), "view only: {:?}", said(&window));
        }
        let off = Services {
            clipboard: false,
            receive_files: false,
            browse_files: false,
            ..Services::default()
        };
        assert!(said(&ask(false, true, off)).is_empty(), "nothing given");
        // A Wayland desktop whose portal is not asked for its clipboard.
        let mut model = with_popups(vec![ask_popup_for(5, t0, false, true)]);
        model.setup = Some(Setup {
            token_file: PathBuf::from("token"),
            granted: true,
            busy: false,
            note: None,
        });
        let mut window = Harness::new(model, t0);
        window.pass(later, Vec::new());
        assert_eq!(
            said(&window),
            vec![
                "With control they can also see and copy any file you can open on this \
                 computer and send files into Downloads › Tornect."
                    .to_owned()
            ]
        );
    }

    /// §B.8.6.3: the block window names who is connecting without asking and the
    /// seconds left, and has exactly one control, Block, which answers at once.
    #[test]
    fn the_block_window_has_one_control_block() {
        let t0 = Instant::now();
        let block = BlockRequest {
            id: 9,
            label: "Laptop".to_owned(),
            ends_at: t0 + Duration::from_secs(10),
            services: false,
        };
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let pass = |now: Instant, events: Vec<egui::Event>| {
            let raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(460.0, 190.0),
                )),
                time: Some(now.duration_since(t0).as_secs_f64()),
                events,
                ..egui::RawInput::default()
            };
            let mut actions = Vec::new();
            let out = ctx.run_ui(raw, |ui| block_window(ui, &block, now, &mut actions));
            let nodes: Vec<egui::accesskit::Node> = out
                .platform_output
                .accesskit_update
                .as_ref()
                .map(|u| u.nodes.iter().map(|(_, n)| n.clone()).collect())
                .unwrap_or_default();
            out.drop_without_applying_deltas();
            (actions, nodes)
        };
        pass(t0, Vec::new());
        let (_, nodes) = pass(t0, Vec::new());
        let texts: Vec<String> = nodes
            .iter()
            .filter_map(|n| n.value().map(str::to_owned))
            .collect();
        assert!(
            texts
                .iter()
                .any(|t| t == "\"Laptop\" is connecting without asking"),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|t| t.starts_with("The session starts in 10 s. Block refuses it")),
            "{texts:?}"
        );
        let buttons: Vec<&egui::accesskit::Node> = nodes
            .iter()
            .filter(|n| n.role() == egui::accesskit::Role::Button)
            .collect();
        assert_eq!(buttons.len(), 1, "one control");
        assert_eq!(buttons[0].label(), Some("Block"));
        let b = buttons[0].bounds().unwrap();
        let at = egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32);
        let press = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        let mut actions = pass(t0, vec![egui::Event::PointerMoved(at), press(true)]).0;
        actions.extend(pass(t0 + Duration::from_millis(50), vec![press(false)]).0);
        assert_eq!(actions, vec![Action::Block { id: 9 }]);
    }

    /// The services design §7.4: where the session may be control and the
    /// settings give the clipboard or files, the block window says so in one
    /// fixed line, between the countdown and Block, and everything still
    /// fits the window (`block::size`, 460 × 232) for a label of the most
    /// characters a label may have; otherwise no such line.
    #[test]
    fn the_block_window_says_what_control_also_gives() {
        let t0 = Instant::now();
        let window = super::super::block::size();
        assert_eq!((window.width, window.height), (460.0, 232.0));
        for services in [true, false] {
            let block = BlockRequest {
                id: 9,
                label: "x".repeat(64),
                ends_at: t0 + Duration::from_secs(10),
                services,
            };
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            let mut nodes = Vec::new();
            for _ in 0..2 {
                let raw = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(window.width as f32, window.height as f32),
                    )),
                    ..egui::RawInput::default()
                };
                let out = ctx.run_ui(raw, |ui| block_window(ui, &block, t0, &mut Vec::new()));
                if let Some(update) = &out.platform_output.accesskit_update {
                    nodes = update.nodes.iter().map(|(_, n)| n.clone()).collect();
                }
                out.drop_without_applying_deltas();
            }
            let line = nodes.iter().find(|n| n.value() == Some(BLOCK_SERVICES));
            assert_eq!(line.is_some(), services, "{services}");
            let block_button = nodes
                .iter()
                .find(|n| n.role() == egui::accesskit::Role::Button)
                .and_then(egui::accesskit::Node::bounds)
                .expect("Block");
            // Block whole, and the frame's bottom margin (14) under it.
            assert!(
                block_button.y1 + 14.0 <= window.height,
                "{services}: Block at {block_button:?}"
            );
            if let Some(line) = line.and_then(egui::accesskit::Node::bounds) {
                let countdown = nodes
                    .iter()
                    .find(|n| {
                        n.value()
                            .is_some_and(|v| v.starts_with("The session starts"))
                    })
                    .and_then(egui::accesskit::Node::bounds)
                    .expect("the countdown");
                assert!(countdown.y1 <= line.y0 && line.y1 <= block_button.y0);
            }
        }
    }

    /// A sheet strips from a quoted name every quotation mark and middle
    /// dot a label may not hold, the five it always stripped among them.
    #[test]
    fn quoted_free_strips_every_quote_and_dot_the_pin_refuses() {
        use tornect_core::words::{MIDDLE_DOTS, QUOTATION_MARKS, label_refusal};
        for c in QUOTATION_MARKS.iter().chain(&MIDDLE_DOTS) {
            let name = format!("Desk{c}of{c}Bob");
            assert!(label_refusal(&name).is_some(), "{c:?}");
            assert_eq!(quoted_free(&name), "DeskofBob", "{c:?}");
        }
        for c in ['"', '\u{201c}', '\u{201d}', '·', '•'] {
            assert!(
                QUOTATION_MARKS.contains(&c) || MIDDLE_DOTS.contains(&c),
                "{c:?}"
            );
        }
        assert_eq!(QUOTATION_MARKS.len() + MIDDLE_DOTS.len(), 11);
        assert_eq!(quoted_free("Desk of Bob"), "Desk of Bob");
    }

    /// A shared session "0011" with "Laptop", in control or view only, whose
    /// services are `services`.
    fn serviced(
        control: bool,
        input: bool,
        services: super::super::services::HostServices,
        t0: Instant,
    ) -> Model {
        Model {
            sharing: vec![Sharing {
                session_id: "0011".to_owned(),
                label: "Laptop".to_owned(),
                control,
                unattended: false,
                since: t0,
                capture: Some(CaptureNote {
                    source: "test card",
                    width: 640,
                    height: 360,
                    input,
                    shown: None,
                    all: false,
                    screens: 0,
                }),
                services: Some(services),
            }],
            ..with_popups(Vec::new())
        }
    }

    fn host_action(op: HostServicesAction) -> Action {
        Action::HostServices {
            session_id: "0011".to_owned(),
            op,
        }
    }

    /// The services design §7.2: under the banner, the strip says in fixed
    /// words what the viewer may do, each transfer (Cancel while it runs)
    /// and the clipboard's last events, and its buttons ask for what they
    /// say. No line names a path of this computer, and no file's name is
    /// on the banner's mode and clock line.
    #[test]
    fn the_services_strip_says_what_the_viewer_may_do() {
        use tornect_proto::services::caps;
        use tornect_session::services::{Direction, TransferRow, TransferState, Untrusted};

        use super::super::services::{ClipNote, HostServices};

        let t0 = Instant::now();
        let row = |xfer, dir, state| TransferRow {
            xfer,
            dir,
            name: Untrusted::file_name("plan.odt"),
            size: 12_000_000,
            done: 5_400_000,
            state,
        };
        let mut services = HostServices::opened(caps::ALL, true, false);
        services.transfers = vec![
            row(7, Direction::ToHost, TransferState::Running),
            row(
                8,
                Direction::ToHost,
                TransferState::Done {
                    stored: Untrusted::file_name("plan (2).odt"),
                },
            ),
            row(
                9,
                Direction::FromHost,
                TransferState::Done {
                    stored: Untrusted::file_name("plan.odt"),
                },
            ),
        ];
        services.clips = vec![
            ClipNote::Sent { chars: 12 },
            ClipNote::Received { chars: 3 },
        ];
        let mut window = Harness::new(serviced(true, true, services, t0), t0);
        assert_eq!(
            window.text("Chat on"),
            "Chat on · Clipboard shared both ways · They can send files and see and copy your \
             files"
        );
        assert_eq!(window.text("Receiving"), "Receiving \"plan.odt\" · 45%");
        assert_eq!(
            window.text("Received"),
            "Received \"plan (2).odt\" (12 MB) in Downloads › Tornect"
        );
        assert_eq!(
            window.text("They copied"),
            "They copied \"plan.odt\" (12 MB)"
        );
        assert_eq!(
            window.text("Copied text"),
            "Copied text was sent to them (12 characters)"
        );
        assert_eq!(
            window.text("They put"),
            "They put text on this computer's clipboard (3 characters)"
        );
        let texts = window.texts();
        for line in [strip::NO_INPUT, strip::PAUSED, strip::CLIPBOARD_REFUSED] {
            assert!(!texts.iter().any(|t| t == line), "{line}");
        }
        for text in texts
            .iter()
            .filter(|t| t.contains("plan") || t.contains("characters"))
        {
            assert!(!text.contains('/') && !text.contains('\\'), "{text}");
        }
        let line = window.text("SHARING");
        assert!(!line.contains("plan"), "{line}");

        let at = window.button(strip::CANCEL);
        let actions = window.click(t0 + Duration::from_secs(2), at);
        assert_eq!(actions, vec![host_action(HostServicesAction::Cancel(7))]);
        let at = window.button(strip::TURN_OFF);
        let actions = window.click(t0 + Duration::from_secs(3), at);
        assert_eq!(actions, vec![host_action(HostServicesAction::TurnOff)]);
    }

    /// The strip's other lines: no input in a control session (at the
    /// stream's start or since), the clipboard the desktop refused, the
    /// pause while this computer is locked; a view-only session gets none
    /// of the no-input line, a session with only chat no turn-off, and a
    /// stream that ended no strip.
    #[test]
    fn the_strip_says_when_files_and_the_clipboard_are_off_or_paused() {
        use tornect_proto::services::{caps, reason};

        use super::super::services::HostServices;

        let t0 = Instant::now();
        let shows = |model: Model| {
            let window = Harness::new(model, t0);
            (window.texts(), window.has(strip::TURN_OFF))
        };

        let (texts, turn_off) = shows(serviced(
            true,
            false,
            HostServices::opened(caps::CHAT, false, true),
            t0,
        ));
        assert!(texts.iter().any(|t| t == strip::NO_INPUT));
        assert!(texts.iter().any(|t| t == strip::CLIPBOARD_REFUSED));
        assert!(texts.iter().any(|t| t == "Chat on"));
        assert!(!turn_off, "nothing to turn off");

        // Input that stopped reaching this desktop after the stream opened.
        let (texts, _) = shows(serviced(
            true,
            false,
            HostServices::opened(caps::CHAT, true, false),
            t0,
        ));
        assert!(texts.iter().any(|t| t == strip::NO_INPUT));

        let mut paused = HostServices::opened(caps::ALL, true, false);
        paused.paused = caps::CLIP | caps::UPLOAD | caps::BROWSE;
        let (texts, turn_off) = shows(serviced(true, true, paused, t0));
        assert!(texts.iter().any(|t| t == strip::PAUSED));
        assert!(texts.iter().any(|t| t == "Chat on"), "{texts:?}");
        assert!(turn_off, "what is paused can still be turned off");
        assert!(!texts.iter().any(|t| t == strip::NO_INPUT));

        let (texts, turn_off) = shows(serviced(
            false,
            false,
            HostServices::opened(caps::CHAT, false, false),
            t0,
        ));
        assert!(
            !texts.iter().any(|t| t == strip::NO_INPUT),
            "view only says so already"
        );
        assert!(texts.iter().any(|t| t == "Chat on"));
        assert!(!turn_off);

        let mut ended = HostServices::opened(caps::ALL, true, false);
        ended.ended = Some(reason::CAPTURE_STOPPED);
        let (texts, turn_off) = shows(serviced(true, true, ended, t0));
        assert!(!texts.iter().any(|t| t.starts_with("Chat on")));
        assert!(!turn_off);
    }

    /// The chat card (§7.2): `Chat with "<label>"`, the viewer's lines under
    /// their label and this computer's as `You`, the field and Send while
    /// chat is on, the footer; shown in a focused window, its lines count
    /// as read. A stream that ended keeps the history without the field,
    /// and what was typed goes with the session's row.
    #[test]
    fn the_chat_card_shows_both_sides_and_sends_what_is_typed() {
        use tornect_proto::services::{caps, reason};
        use tornect_session::services::{HostEvent, sanitize_peer_text};

        use super::super::services::HostServices;

        let t0 = Instant::now();
        let mut services = HostServices::opened(caps::CHAT, false, false);
        services.apply(&HostEvent::Chat(sanitize_peer_text("hello there").unwrap()));
        services.said(sanitize_peer_text("hi").unwrap());
        let mut window = Harness::new(serviced(false, false, services.clone(), t0), t0);
        assert_eq!(window.text("Chat with"), "Chat with \"Laptop\"");
        assert_eq!(window.text("\"Laptop\":"), "\"Laptop\": hello there");
        assert_eq!(window.text("You:"), "You: hi");
        assert_eq!(window.text("Not saved"), strip::NOT_SAVED);
        let actions = window.pass(t0 + Duration::from_secs(1), Vec::new());
        assert_eq!(actions, vec![host_action(HostServicesAction::Read)]);

        window
            .form
            .chats
            .insert("0011".to_owned(), "on my way".to_owned());
        let at = window.button(strip::SEND);
        let actions = window.click(t0 + Duration::from_secs(2), at);
        assert!(
            actions.contains(&host_action(HostServicesAction::Send)),
            "{actions:?}"
        );

        services.unread = 0;
        services.ended = Some(reason::SESSION_OVER);
        let mut window = Harness::new(serviced(false, false, services, t0), t0);
        assert!(!window.has(strip::SEND), "no field once the stream ended");
        assert_eq!(window.text("You:"), "You: hi");
        assert!(window.pass(t0, Vec::new()).is_empty(), "nothing unread");

        window
            .form
            .chats
            .insert("0011".to_owned(), "late".to_owned());
        window.model.sharing.clear();
        window.pass(t0, Vec::new());
        assert!(window.form.chats.is_empty(), "the draft goes with the row");
        assert!(!window.texts().iter().any(|t| t.starts_with("Chat with")));
    }

    /// The rectangle (x0, y0, x1, y1) of the label whose text starts with
    /// `start` in `window`'s last pass.
    fn text_bounds(window: &Harness, start: &str) -> (f64, f64, f64, f64) {
        let b = window
            .nodes
            .iter()
            .find(|n| n.value().is_some_and(|v| v.starts_with(start)))
            .and_then(egui::accesskit::Node::bounds)
            .unwrap_or_else(|| panic!("no text starting with \"{start}\""));
        (b.x0, b.y0, b.x1, b.y1)
    }

    /// The services design §7.4: once, after every answer's line, where an
    /// answer gives control (plain, or as administrator) and the saved
    /// settings give more than chat, the session sheet says what control
    /// also gives, in fixed words; not on a sheet that offers View only
    /// alone, not with every switch off, and again in the administrator
    /// answer's confirmation. No button moves before it.
    #[test]
    fn the_session_sheet_says_what_control_also_gives() {
        use tornect_core::config::Services;
        use tornect_core::levels::Availability;

        const ALL: &str = "With control they can also see and copy any file you can open on \
                           this computer, send files into Downloads › Tornect and copy text to \
                           and from this computer's clipboard.";
        let t0 = Instant::now();
        let sheet = |levels: SheetLevels, services: Services| {
            let mut model = with_popups(vec![session_popup(7, t0)]);
            model.levels.insert(7, levels);
            model.settings.services = services;
            Harness::new(model, t0)
        };
        let said = |window: &Harness| {
            window
                .texts()
                .into_iter()
                .filter(|t| t.starts_with("With control"))
                .collect::<Vec<_>>()
        };
        // Linux: under View only's and Allow control's lines, once.
        let linux_levels = SheetLevels::of(&Availability::LINUX);
        let linux = sheet(linux_levels, Services::default());
        assert_eq!(said(&linux), vec![ALL.to_owned()]);
        let line = text_bounds(&linux, "With control");
        let allow = linux.bounds("Allow control");
        assert!(line.1 >= allow.3, "under the buttons: {line:?} {allow:?}");
        for answer_line in [LINE_VIEW_ONLY, linux_levels.allow_line] {
            let above = text_bounds(&linux, answer_line);
            assert!(line.1 >= above.3, "{answer_line}: {line:?} {above:?}");
        }
        assert!(
            linux.bounds("Deny").0 < linux.bounds("View only").0,
            "Deny first"
        );
        // Administrator only (UAC off): under its row.
        let admin = sheet(always_admin(), Services::default());
        assert_eq!(said(&admin), vec![ALL.to_owned()]);
        let line = text_bounds(&admin, "With control");
        let row = admin.bounds("Allow as administrator");
        assert!(line.1 >= row.3, "{line:?} {row:?}");
        // View only alone: nothing control gives is offered.
        let view_only = SheetLevels {
            answers: Answers {
                view_only: true,
                allow: false,
                admin: None,
            },
            ..linux_levels
        };
        let window = sheet(view_only, Services::default());
        assert!(window.has("View only") && !window.has("Allow control"));
        assert!(said(&window).is_empty(), "{:?}", said(&window));
        // Every switch off (chat on): no line.
        let off = Services {
            clipboard: false,
            receive_files: false,
            browse_files: false,
            ..Services::default()
        };
        let window = sheet(linux_levels, off);
        assert!(said(&window).is_empty(), "{:?}", said(&window));
        // One switch: its part alone.
        let window = sheet(
            linux_levels,
            Services {
                receive_files: true,
                ..off
            },
        );
        assert_eq!(
            said(&window),
            vec!["With control they can also send files into Downloads › Tornect.".to_owned()]
        );
        // The administrator answer's confirmation says it too.
        let mut window = sheet(always_admin(), Services::default());
        window.model.admin_confirm.insert(7);
        let t1 = t0 + Duration::from_secs(2);
        window.pass(t1, Vec::new());
        window.pass(t1, Vec::new());
        assert!(window.has("Allow as administrator") && !window.has("View only"));
        assert_eq!(said(&window), vec![ALL.to_owned()]);
    }

    /// The services design §7.3: the indicator's Chat asks for the session's
    /// chat field, which takes the keyboard at its card's next pass, once;
    /// a request for a session gone is dropped.
    #[test]
    fn the_indicators_chat_readies_the_chat_field_once() {
        use tornect_proto::services::caps;

        use super::super::services::HostServices;

        let t0 = Instant::now();
        let typed = |text: &str| vec![egui::Event::Text(text.to_owned())];
        let services = HostServices::opened(caps::ALL, true, false);
        let mut window = Harness::new(serviced(true, true, services, t0), t0);
        // Without the request, typing reaches no field.
        window.pass(t0, typed("x"));
        assert!(
            window.form.chats.get("0011").is_none_or(String::is_empty),
            "{:?}",
            window.form.chats
        );
        window.form.chat_focus = Some("0011".to_owned());
        window.pass(t0, Vec::new());
        assert_eq!(window.form.chat_focus, None, "taken once");
        window.pass(t0, typed("on my way"));
        assert_eq!(
            window.form.chats.get("0011").map(String::as_str),
            Some("on my way")
        );
        // A request for a session that ended is dropped with it.
        window.form.chat_focus = Some("0099".to_owned());
        window.pass(t0, Vec::new());
        assert_eq!(window.form.chat_focus, None);
    }
}
