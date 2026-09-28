//! The screens (`docs/UI_PLAN.md` §5–§8), drawn from a [`Model`] alone. What
//! the user asks for comes back as [`Action`]s; nothing here touches the
//! network, a store or a channel.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use egui::{Color32, RichText};
use tornect_core::TornectId;
use tornect_core::levels::{ADMIN_LINE_NO_PROMPT, AdminPath, Answers, SENTENCE_SECURE_DESKTOP_OFF};
use tornect_signal::pairing::{PairDecision, SessionDecision};

#[cfg(test)]
use super::model::{ClientStage, Hosting, Setup, TorState};
use super::model::{Confirm, Model, Popup, PopupKind, Recognition, Sharing, SheetLevels, Viewing};
use super::nav::{self, Page};
use super::pages;
use super::theme::{self, Face};
use super::widgets;

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
    /// End the session this screen is shared with (the kill), from the banner
    /// or the indicator window.
    StopSharing,
    /// Start moving the indicator window with the pointer (it has no title
    /// bar).
    MoveIndicator,
    /// End the session this machine views.
    EndViewing,
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
    /// Home shows this computer's ID as a QR code.
    pub qr: bool,
    /// The address book page's own state.
    pub book: pages::BookForm,
}

impl Form {
    /// The window came back into view: restored from the taskbar, brought
    /// back by a newer card's attention request, or focused (review N-1).
    /// Every card's arming second starts again: a card armed before the
    /// window was minimized must not be live under a pointer aimed at the
    /// program the window now covers.
    pub fn window_came_back(&mut self) {
        self.cards.clear();
    }
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
fn arm(ui: &egui::Ui, cards: &mut HashMap<u64, Card>, id: u64, now: Instant) -> bool {
    let at = ui.cursor().min;
    let card = cards.entry(id).or_insert(Card { since: now, at });
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

fn clock(since: Instant, now: Instant) -> String {
    let secs = now.saturating_duration_since(since).as_secs();
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

/// The main window: the sharing banner, the open questions, the page and the
/// sidebar. The keyboard reaches them in that order: the banner's Stop, the
/// questions (a refusal first in each), the page, and last the navigation,
/// whose room is reserved first and filled after the page.
pub fn main_window(
    ui: &mut egui::Ui,
    model: &Model,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    theme::ensure(ui.ctx());
    let t = theme::tokens(ui.ctx());
    let window = ui.max_rect().width();
    if !model.sharing.is_empty() {
        egui::Panel::top("sharing")
            .frame(
                egui::Frame::new()
                    .fill(t.sharing_fill)
                    .inner_margin(egui::Margin::symmetric(12, 8)),
            )
            .show(ui, |ui| {
                for sharing in &model.sharing {
                    sharing_banner(ui, sharing, now, actions);
                }
            });
    }
    // A label typed into a question that is gone goes with it, and so does
    // what the window remembered of its card.
    form.labels
        .retain(|id, _| model.popups.iter().any(|p| p.id == *id));
    form.cards.retain(|id, _| {
        model.popups.iter().any(|p| {
            p.id == *id || (model.admin_confirm.contains(&p.id) && confirmation_card(p.id) == *id)
        }) || model.confirm.as_ref().is_some_and(|c| c.id == *id)
    });
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
            // Open questions come first, one card each, so none hides
            // another's buttons, in a region of their own above the page's
            // scroll area (review F-2): a request that arrives while the page
            // is scrolled down is in view at once. Only when the cards do not
            // all fit does the region scroll, and then a new card is brought
            // into view once.
            if !model.popups.is_empty() || model.confirm.is_some() {
                egui::ScrollArea::vertical()
                    .id_salt("questions")
                    .max_height(ui.available_height())
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for popup in &model.popups {
                            let new = !form.cards.contains_key(&popup.id);
                            let seen = model.recognition.get(&popup.id);
                            let sheet = Sheet {
                                seen,
                                levels: model.levels.get(&popup.id),
                                confirming: model.admin_confirm.contains(&popup.id),
                            };
                            let card =
                                question(ui, |ui| host_popup(ui, popup, sheet, form, now, actions));
                            if new {
                                ui.scroll_to_rect(card, None);
                            }
                        }
                        if let Some(confirm) = &model.confirm {
                            let new = !form.cards.contains_key(&confirm.id);
                            let card =
                                question(ui, |ui| confirm_popup(ui, confirm, form, now, actions));
                            if new {
                                ui.scroll_to_rect(card, None);
                            }
                        }
                    });
            }
            egui::ScrollArea::vertical()
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
    // Countdowns and the banner's clock move once a second.
    if !model.popups.is_empty() || model.confirm.is_some() || !model.sharing.is_empty() {
        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
}

/// A question card: framed in the accent colour, above everything else.
/// Returns where it was drawn.
fn question(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) -> egui::Rect {
    let t = theme::tokens(ui.ctx());
    let card = egui::Frame::new()
        .fill(t.surface_card)
        .corner_radius(14)
        .stroke(egui::Stroke::new(2.0, t.accent_fill))
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
fn sharing_banner(ui: &mut egui::Ui, sharing: &Sharing, now: Instant, actions: &mut Vec<Action>) {
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
            let mode = if sharing.control {
                "sees and controls this screen"
            } else {
                "sees this screen (view only)"
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

/// The indicator window (§6.3, `indicator`): for every session this screen
/// is shared with, who, which mode and the clock; and Stop, which ends sharing
/// exactly as the banner's Stop does. A press anywhere else moves the window.
pub fn indicator(ui: &mut egui::Ui, sharing: &[Sharing], now: Instant, actions: &mut Vec<Action>) {
    theme::ensure(ui.ctx());
    let t = theme::tokens(ui.ctx());
    // Text is not selectable here: a press on it moves the window instead.
    ui.style_mut().interaction.selectable_labels = false;
    egui::CentralPanel::no_frame()
        .frame(
            egui::Frame::new()
                .fill(t.sharing_fill)
                .inner_margin(egui::Margin::symmetric(10, 8)),
        )
        .show(ui, |ui| {
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
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
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
                        ui.add(
                            egui::Label::new(RichText::new(detail).small().color(t.on_sharing))
                                .truncate(),
                        );
                    }
                });
            });
        });
    // The clock moves once a second.
    ui.ctx().request_repaint_after(Duration::from_millis(500));
}

/// Whether `code` holds a whole code: six digits (a space allowed).
fn whole_code(code: &str) -> bool {
    code.chars().filter(char::is_ascii_digit).count() == 6
}

/// What a host sheet shows beside its popup: the key's recognition, the
/// levels a session sheet offers, and whether its administrator
/// confirmation is up.
#[derive(Clone, Copy)]
struct Sheet<'a> {
    seen: Option<&'a Recognition>,
    levels: Option<&'a SheetLevels>,
    confirming: bool,
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
            match (pinned, seen.and_then(|s| s.identicon)) {
                // A pinned key: its saved name, with the identicon beside it.
                (Some(label), Some(identicon)) => {
                    ui.horizontal_top(|ui| {
                        widgets::identicon(ui, &identicon.seed(), 36.0);
                        ui.add(
                            egui::Label::new(format!(
                                "A device ALREADY PAIRED as \"{label}\" asks to pair again. \
                                 Refusing does not unpair it."
                            ))
                            .wrap(),
                        );
                    });
                }
                (Some(label), None) => {
                    ui.label(format!(
                        "A device ALREADY PAIRED as \"{label}\" asks to pair again. Refusing \
                             does not unpair it."
                    ));
                }
                (None, _) => {
                    ui.label(format!(
                        "A device calling itself \"{name}\" asks to pair with this computer."
                    ));
                }
            }
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
                ui.label(
                    RichText::new(sas)
                        .font(theme::font(ui.ctx(), Face::MonoSemibold, SAS_SIZE))
                        .color(t.accent_text),
                );
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
                ui.label("Name it (optional):");
                ui.text_edit_singleline(label);
            });
            let label = label.trim().to_owned();
            let label = (!label.is_empty()).then_some(label);
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
                if !fired && accept(ui, RichText::new("The codes match: pair").strong(), armed) {
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
            if let Some(code) = typed.filter(|c| whole_code(c)) {
                actions.push(Action::PairCode {
                    id: popup.id,
                    code,
                    label,
                });
            }
            ui.label(
                RichText::new(format!("Refused automatically in {left} s"))
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
                return;
            }
            let asks = RichText::new(format!("\"{label}\" wants to see this screen."))
                .strong()
                .size(16.0);
            match seen.and_then(|s| s.identicon) {
                // A paired device: its pinned label, the identicon beside it.
                Some(identicon) => {
                    ui.horizontal_top(|ui| {
                        widgets::identicon(ui, &identicon.seed(), 36.0);
                        ui.add(egui::Label::new(asks).wrap());
                    });
                }
                None => {
                    ui.label(asks);
                }
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
            // Only "Allow as administrator" without a Windows prompt is drawn
            // in this build; the prompt path waits for the helper (M-FEAT-3).
            let admin = matches!(answers.admin, Some(AdminPath::TornectConfirmation { .. }));
            ui.add_space(4.0);
            ui.label(if answers.allow || !admin {
                "Allow control also lets it use this computer's keyboard and mouse. View \
                     only shows the screen and nothing else. Either way it lasts for this \
                     session only, and \"Stop sharing\" ends it."
            } else {
                "Allow as administrator also lets it use this computer's keyboard and mouse. \
                     View only shows the screen and nothing else. Either way it lasts for this \
                     session only, and \"Stop sharing\" ends it."
            });
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
            // Never adjacent to Allow (§B.2.1): a row of its own, under the
            // others; it opens the Tornect confirmation, it does not answer.
            if admin {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if accept(
                        ui,
                        RichText::new("Allow as administrator").color(t.danger_text),
                        armed,
                    ) {
                        actions.push(Action::AdminConfirm { id: popup.id });
                    }
                });
            }
            if let Some(levels) = sheet.levels {
                // The sentence under the buttons: why a level is absent, or
                // what the one offered means here.
                for line in levels.sentence.into_iter().chain(
                    levels
                        .prompts_on_shared_screen
                        .then_some(SENTENCE_SECURE_DESKTOP_OFF),
                ) {
                    ui.add(
                        egui::Label::new(RichText::new(line).small().color(t.text_secondary))
                            .wrap(),
                    );
                }
            }
            ui.label(
                RichText::new(format!("Denied automatically in {left} s"))
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
    ui.add(egui::Label::new(ADMIN_LINE_NO_PROMPT).wrap());
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

fn confirm_popup(
    ui: &mut egui::Ui,
    confirm: &Confirm,
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
        ui.label(format!(
            "The host accepted; it calls itself \"{}\". Did its screen show this code?",
            confirm.host_name
        ));
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

/// The stream window (§8): a slim bar with the host, the mode and Stop, and
/// the picture letterboxed below it. Returns where the picture was drawn, in
/// points, once there is one.
pub fn stream_window(
    ui: &mut egui::Ui,
    viewing: Option<&Viewing>,
    picture: Option<(egui::TextureId, (u32, u32))>,
    input_sent: u64,
    now: Instant,
    actions: &mut Vec<Action>,
) -> Option<egui::Rect> {
    theme::ensure(ui.ctx());
    let t = theme::tokens(ui.ctx());
    egui::Panel::top("stream-bar")
        .frame(
            egui::Frame::new()
                .fill(t.bg_sidebar)
                .inner_margin(egui::Margin::symmetric(12, 8)),
        )
        .show(ui, |ui| {
            ui.horizontal(|ui| match viewing {
                Some(v) => {
                    ui.label(RichText::new(&v.host).strong());
                    // The level only from the signed accept (§B.2.1).
                    let (mode, color) = if v.control && v.administrator {
                        ("Control · administrator", t.danger_text)
                    } else if v.control {
                        ("control", t.ok)
                    } else {
                        ("view only", t.text_muted)
                    };
                    ui.label(RichText::new(mode).color(color));
                    ui.label(
                        RichText::new(format!(
                            "{} · {}×{} · {} pictures · {} inputs",
                            clock(v.since, now),
                            v.size.0,
                            v.size.1,
                            v.pictures,
                            input_sent
                        ))
                        .small()
                        .monospace(),
                    );
                    ui.label(
                        RichText::new("Relayed via Tor: quality limited")
                            .small()
                            .color(t.warn),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Stop").clicked() {
                            actions.push(Action::EndViewing);
                        }
                    });
                }
                None => {
                    ui.label("The session has ended.");
                }
            });
        });
    let mut drawn = None;
    egui::CentralPanel::no_frame()
        .frame(egui::Frame::new().fill(Color32::BLACK))
        .show(ui, |ui| {
            let avail = ui.available_rect_before_wrap();
            match picture {
                Some((texture, size)) => {
                    let (x, y, w, h) = super::stream::letterbox(
                        (avail.min.x, avail.min.y, avail.width(), avail.height()),
                        size,
                    );
                    let rect = egui::Rect::from_min_size(egui::pos2(x, y), egui::vec2(w, h));
                    ui.painter().image(
                        texture,
                        rect,
                        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                        Color32::WHITE,
                    );
                    drawn = Some(rect);
                }
                None => {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new("Waiting for the first picture…").color(t.text_muted),
                        );
                    });
                }
            }
        });
    drawn
}

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

    /// A card that moves (one above it answered, withdrawn or timed out)
    /// waits another second before a click on it counts.
    #[test]
    fn a_card_that_moves_waits_another_second() {
        let t0 = Instant::now();
        let mut window = Harness::new(
            with_popups(vec![pairing_popup(1, t0), session_popup(2, t0)]),
            t0,
        );
        let moved_at = t0 + Duration::from_secs(3);
        window.pass(moved_at, Vec::new());
        let before = window.button("Allow control");
        window.model.popups.remove(0);
        window.pass(moved_at, Vec::new());
        let allow = window.button("Allow control");
        assert!(allow.y < before.y, "the session card moved up");

        let early = window.click(moved_at + Duration::from_millis(300), allow);
        assert!(early.is_empty(), "answered right after moving: {early:?}");
        window.pass(moved_at + Duration::from_millis(1500), Vec::new());
        let late = window.click(moved_at + Duration::from_millis(1600), allow);
        assert!(
            matches!(
                late.as_slice(),
                [Action::Session {
                    id: 2,
                    decision: SessionDecision::AllowOnce,
                    ..
                }]
            ),
            "{late:?}"
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
            capture: Some(CaptureNote {
                source: "wayland",
                width: 1920,
                height: 1080,
                input: false,
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
                since: now,
                pictures: 3,
                size: (640, 480),
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
            since: Instant::now(),
            pictures: 1,
            size: (1600, 900),
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
            );
        })
        .drop_without_applying_deltas();
        let rect = drawn.expect("a picture was drawn");
        assert!((rect.width() / rect.height() - 16.0 / 9.0).abs() < 0.01);
        ctx.run_ui(egui::RawInput::default(), |ui| {
            drawn = stream_window(ui, None, None, 0, Instant::now(), &mut actions);
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
                since: Instant::now(),
                pictures: 1,
                size: (1600, 900),
            };
            let mut nodes = Vec::new();
            for _ in 0..2 {
                let out = ctx.run_ui(egui::RawInput::default(), |ui| {
                    let _ =
                        stream_window(ui, Some(&viewing), None, 0, Instant::now(), &mut Vec::new());
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
}
