//! The address book (the redesign's §4): the computers this one connects
//! to, the recent connections and the devices that can connect here, stored
//! only on this computer (`tornect_core::address_book`). Every change goes
//! to the tokio side as an [`Action`], never a file edit from here. Whether a
//! computer answers is asked on a click only, once: there is no presence dot
//! and nothing is checked in the background.

use egui::{Align, Layout, Margin, RichText, Sense, Stroke, Ui, WidgetInfo, WidgetType, vec2};
use tornect_core::TornectId;

use super::super::icons::{self, Icon};
use super::super::model::{Book, Check, ClientStage, Computer, Model};
use super::super::theme::{self, Face, Tokens};
use super::super::view::{Action, Form};
use super::super::widgets::{self, Button, Kind, Tone};
use super::{day_in_sentence, day_text};
use crate::ua_client::AdminAction;

/// The page's tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    /// The computers this one connects to.
    #[default]
    Computers,
    /// The recent connections, and the history switch.
    Recent,
    /// The devices that can connect here.
    Devices,
}

/// What the page remembers from pass to pass.
#[derive(Debug, Default)]
pub struct BookForm {
    /// The tab shown.
    pub tab: Tab,
    /// The computer whose details are shown.
    pub selected: Option<TornectId>,
    /// The search field.
    pub search: String,
    /// The computer being renamed, and the name typed so far.
    pub renaming: Option<(TornectId, String)>,
    /// The Add computer form: the ID and the name typed so far.
    pub adding: Option<(String, String)>,
    /// The computer whose Forget waits for its confirmation.
    pub forgetting: Option<TornectId>,
}

/// The Recent tab's line while history is off: the switch governs the
/// recent list only; the session log records connection attempts either
/// way (F4-M1).
pub(super) const HISTORY_OFF: &str = "Off: no list of recent connections is kept. Switched on, \
    it keeps the day of each connection (never the time) and each computer's last-connected day, \
    only on this computer; anything kept before stays until you clear it. The switch does not \
    cover the session log: it always records connection attempts in both directions, with their \
    time, on this computer only.";

/// Forget's question for the computer called `title`: what goes (its
/// pairing, name, recent lines and remembered password). No longer than
/// the question it replaced, so its answers stay where they were.
pub(super) fn forget_question(title: &str) -> String {
    format!(
        "Forget \"{title}\"? Its pairing, name, recent connections and remembered password go; \
         the next connection compares a code again."
    )
}

/// Under Forget's answers: what stays (F4-M1).
pub(super) const FORGET_KEEPS: &str = "Its lines in the session log stay: the session log always \
    records connection attempts in both directions.";

/// From this content width on, the details sit beside the list.
const SIDE_BY_SIDE_FROM: f32 = 760.0;
/// The space between cards.
const GAP: f32 = 16.0;

pub(super) fn page(
    ui: &mut Ui,
    model: &Model,
    form: &mut Form,
    shared: bool,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    let book = &model.book;
    widgets::page_header(
        ui,
        "Address book",
        "Computers you connect to, and devices that can ask to see this one. Stored only on \
         this computer.",
    );
    ui.add_space(14.0);
    // While this screen may be in a picture that leaves it: no name, no ID,
    // no day, no device, not even how many there are.
    if shared {
        super::hidden_card(
            ui,
            "The saved computers, the recent connections and the devices that can connect \
             here come back when sharing ends.",
        );
        ui.add_space(8.0);
        muted(
            ui,
            t,
            "Device words are hidden while this computer is shared.",
        );
        return;
    }
    let narrow = ui.available_width() < 600.0;
    let labels = [
        format!("Computers {}", book.computers.len()),
        "Recent".to_owned(),
        format!(
            "{} {}",
            if narrow {
                "Devices here"
            } else {
                "Devices that can connect here"
            },
            book.devices.len()
        ),
    ];
    let names: Vec<&str> = labels.iter().map(String::as_str).collect();
    ui.horizontal(|ui| {
        let mut index = form.book.tab as usize;
        widgets::segmented(ui, &mut index, &names);
        form.book.tab = match index {
            1 => Tab::Recent,
            2 => Tab::Devices,
            _ => Tab::Computers,
        };
        if form.book.tab == Tab::Computers && form.book.adding.is_none() {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if Button::new(Kind::Primary, "Add computer")
                    .icon(Icon::Plus)
                    .show(ui)
                    .clicked()
                {
                    form.book.adding = Some((String::new(), String::new()));
                }
            });
        }
    });
    ui.add_space(12.0);
    if let Some(problem) = &book.problem {
        note_line(ui, Icon::CircleAlert, problem, t.warn);
    }
    if let Some(note) = &book.note {
        note_line(ui, Icon::Info, note, t.text_secondary);
    }
    match form.book.tab {
        Tab::Computers => computers(ui, t, model, form, actions),
        Tab::Recent => recent(ui, t, book, actions),
        Tab::Devices => devices(ui, t, book, !model.sharing.is_empty()),
    }
    ui.add_space(8.0);
}

/// An icon and a line of text in `color`.
fn note_line(ui: &mut Ui, icon: Icon, text: &str, color: egui::Color32) {
    ui.horizontal_top(|ui| {
        icons::show(ui, icon, 15.0, color);
        ui.add(
            egui::Label::new(
                RichText::new(text)
                    .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                    .color(color),
            )
            .wrap(),
        );
    });
    ui.add_space(6.0);
}

/// Small muted text.
fn muted(ui: &mut Ui, t: &Tokens, text: &str) {
    ui.add(
        egui::Label::new(
            RichText::new(text)
                .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                .color(t.text_muted),
        )
        .wrap(),
    );
}

/// The Computers tab: the Add form, the search field, the list and the
/// selected computer's details.
fn computers(ui: &mut Ui, t: &Tokens, model: &Model, form: &mut Form, actions: &mut Vec<Action>) {
    let book = &model.book;
    if form.book.adding.is_some() {
        add_card(ui, t, model, form, actions);
        ui.add_space(GAP);
    }
    if book.computers.is_empty() {
        widgets::card(ui, |ui| {
            ui.set_width(ui.available_width());
            widgets::section_header(ui, "No saved computers yet");
            muted(
                ui,
                t,
                "Connect to a computer by its ID on Home: the first time, both screens show a \
                 6-digit code, and once the codes match it is listed here. Or add one by its ID \
                 with Add computer.",
            );
        });
        return;
    }
    let field = widgets::text_field(
        ui,
        &mut form.book.search,
        "Search the address book",
        false,
        ui.available_width().min(420.0),
    );
    field.widget_info(|| WidgetInfo::labeled(WidgetType::TextEdit, true, "Search"));
    ui.add_space(10.0);
    let query = form.book.search.trim().to_lowercase();
    let shown: Vec<&Computer> = book
        .computers
        .iter()
        .filter(|c| {
            query.is_empty()
                || c.title().to_lowercase().contains(&query)
                || c.id.base32().starts_with(&query)
        })
        .collect();
    if shown.is_empty() {
        muted(ui, t, "Nothing in the address book matches the search.");
        return;
    }
    let selected = form
        .book
        .selected
        .filter(|id| shown.iter().any(|c| c.id == *id))
        .unwrap_or(shown[0].id);
    let width = ui.available_width();
    if width >= SIDE_BY_SIDE_FROM {
        let list_width = ((width - GAP) * 0.52).floor();
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = GAP;
            ui.allocate_ui_with_layout(vec2(list_width, 0.0), Layout::top_down(Align::Min), |ui| {
                list(
                    ui,
                    t,
                    book,
                    &shown,
                    selected,
                    form,
                    !model.sharing.is_empty(),
                );
            });
            ui.allocate_ui_with_layout(
                vec2(width - GAP - list_width, 0.0),
                Layout::top_down(Align::Min),
                |ui| {
                    if let Some(computer) = book.computer(&selected) {
                        details(ui, t, model, computer, form, actions);
                    }
                },
            );
        });
    } else {
        list(
            ui,
            t,
            book,
            &shown,
            selected,
            form,
            !model.sharing.is_empty(),
        );
        ui.add_space(GAP);
        if let Some(computer) = book.computer(&selected) {
            details(ui, t, model, computer, form, actions);
        }
    }
    ui.add_space(GAP);
    note_line(
        ui,
        Icon::Info,
        "No online dots: Tornect never checks your computers in the background. \"Check if \
         reachable\" asks once, over Tor, when you click it.",
        t.text_muted,
    );
}

/// The list of computers; a click selects one.
fn list(
    ui: &mut Ui,
    t: &Tokens,
    book: &Book,
    shown: &[&Computer],
    selected: TornectId,
    form: &mut Form,
    shared: bool,
) {
    widgets::card_frame(t, 14, Margin::same(6)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.spacing_mut().item_spacing.y = 2.0;
        for computer in shown {
            let on = computer.id == selected;
            let title = computer.title();
            let row = egui::Frame::new()
                .fill(if on {
                    t.accent_tint
                } else {
                    egui::Color32::TRANSPARENT
                })
                .corner_radius(10)
                .inner_margin(Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        identicon(ui, computer, 32.0, shared);
                        ui.vertical(|ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&title)
                                        .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                                        .color(t.text_primary),
                                )
                                .selectable(false)
                                .truncate(),
                            );
                            let second = match (computer.paired, computer.last_seen) {
                                (_, Some(day)) => format!(
                                    "{}… · last connected {}",
                                    computer.id.short(),
                                    day_in_sentence(day, book.today)
                                ),
                                (Some(_), None) => format!("{}… · paired", computer.id.short()),
                                (None, None) => {
                                    format!("{}… · saved, not paired yet", computer.id.short())
                                }
                            };
                            ui.add(
                                egui::Label::new(
                                    RichText::new(second)
                                        .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                                        .color(t.text_muted),
                                )
                                .selectable(false)
                                .truncate(),
                            );
                        });
                    });
                })
                .response
                .interact(Sense::click());
            row.widget_info(|| WidgetInfo::selected(WidgetType::SelectableLabel, true, on, &title));
            if row.clicked() {
                form.book.selected = Some(computer.id);
                form.book.renaming = None;
                form.book.forgetting = None;
            }
        }
    });
}

/// The identicon of a paired computer, drawn from its ID's device words
/// (§B.6.1): only beside its name, never beside an unpinned key (W-B8), and
/// never while this computer is shared; elsewhere a plain tile keeps the
/// place. It helps recognise one, never replaces comparing its ID.
fn identicon(ui: &mut Ui, computer: &Computer, size: f32, shared: bool) {
    match computer.identicon.filter(|_| !shared) {
        Some(identicon) => {
            widgets::identicon(ui, &identicon.seed(), size);
        }
        None => {
            widgets::identicon(ui, &[], size);
        }
    }
}

/// The selected computer: who it is, Connect, Check, Copy ID, Rename and
/// Forget (after a confirmation).
fn details(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    computer: &Computer,
    form: &mut Form,
    actions: &mut Vec<Action>,
) {
    let book = &model.book;
    let id = computer.id;
    widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            identicon(ui, computer, 44.0, !model.sharing.is_empty());
            ui.vertical(|ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(computer.title())
                            .font(theme::font(ui.ctx(), Face::Bold, 18.0))
                            .color(t.text_primary),
                    )
                    .truncate(),
                );
                let paired = match computer.paired {
                    Some(day) => format!("Paired {}", day_in_sentence(day, book.today)),
                    None => {
                        "Saved, not paired yet: the first connection compares a code".to_owned()
                    }
                };
                muted(ui, t, &paired);
            });
            ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                if computer.paired.is_some() {
                    widgets::chip(ui, Tone::Ok, false, "Paired");
                } else {
                    widgets::chip(ui, Tone::Neutral, false, "Saved");
                }
            });
        });
        if computer.looks_mixed() {
            note_line(
                ui,
                Icon::CircleAlert,
                "This name mixes letters of different alphabets, some of which look alike. \
                 Compare the ID, not the name.",
                t.warn,
            );
        }
        if computer.name_hidden {
            note_line(
                ui,
                Icon::CircleAlert,
                "The name you saved for it is not shown: its key changed since you named it \
                 (it was paired again). Name it again if you trust it.",
                t.warn,
            );
        }
        if let (Some(pinned), Some(name)) = (&computer.pinned, &computer.name)
            && pinned != name
        {
            muted(
                ui,
                t,
                &format!("Paired as \"{pinned}\"; requests from it show that name."),
            );
        }
        if let Some(declared) = computer
            .declared
            .as_ref()
            .filter(|d| Some(*d) != computer.pinned.as_ref())
        {
            muted(ui, t, &format!("Last seen calling itself \"{declared}\"."));
        }
        ui.add_space(6.0);
        widgets::caps_label(ui, "Tornect ID");
        let groups: Vec<String> = id.display_groups().split(' ').map(str::to_owned).collect();
        let (first, second) = groups.split_at(4);
        ui.label(
            RichText::new(format!("{}\n{}", first.join(" "), second.join(" ")))
                .font(theme::font(ui.ctx(), Face::Mono, 13.0))
                .color(t.text_primary),
        );
        // Its address's device words: the one short form (§B.6.1 item 6),
        // for recognition only; none while this computer is shared (R-W2).
        if model.sharing.is_empty() {
            if let Some(words) = computer.words {
                widgets::caps_label(ui, "Device words of this address");
                ui.label(
                    RichText::new(words.shown())
                        .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                        .color(t.text_secondary),
                );
                muted(
                    ui,
                    t,
                    "They help you recognise it; its own Home shows them under its ID. They do \
                     not prove who it is, and they cannot be typed to connect.",
                );
            }
        } else {
            muted(
                ui,
                t,
                "Device words are hidden while this computer is shared.",
            );
        }
        let last = computer.last_seen.map_or_else(
            || "never, or not kept".to_owned(),
            |d| day_in_sentence(d, book.today),
        );
        muted(ui, t, &format!("Last connected: {last}"));
        ui.add_space(8.0);

        let idle = matches!(model.client, ClientStage::Idle | ClientStage::Ended(_));
        let check = book.check(&id);
        if model.setup_changed.contains(&id) {
            note_line(
                ui,
                Icon::CircleAlert,
                &format!(
                    "\"{}\"'s unattended setup was re-created since you last connected — if \
                     that wasn't you, revoke devices there.",
                    computer.title()
                ),
                t.warn,
            );
            if Button::new(Kind::Secondary, "I read this")
                .small()
                .show(ui)
                .clicked()
            {
                actions.push(Action::ConfirmSetupChanged(id));
            }
        }
        ui.horizontal_wrapped(|ui| {
            super::home::host_actions_with(
                ui,
                model,
                computer,
                model.tor.is_ready() && idle,
                false,
                false,
                actions,
            );
            let asking = check == Some(&Check::Asking);
            if Button::new(
                Kind::Secondary,
                if asking {
                    "Checking…"
                } else {
                    "Check if reachable"
                },
            )
            .icon(Icon::Activity)
            .enabled(!asking && model.tor.is_ready())
            .show(ui)
            .clicked()
            {
                actions.push(Action::Ping(id));
            }
        });
        let (text, color) = match check {
            None => (
                "Asks once over Tor, only when you click. Tornect never checks in the background."
                    .to_owned(),
                t.text_muted,
            ),
            Some(Check::Asking) => (
                "Asking once over Tor (reaching a computer takes up to a minute)…".to_owned(),
                t.text_muted,
            ),
            Some(Check::Reachable { millis }) => (
                format!(
                    "It answered over Tor ({:.1} s). Nothing is checked again until you click.",
                    *millis as f64 / 1000.0
                ),
                t.ok,
            ),
            Some(Check::Unreachable(why)) => (format!("No answer: {why}"), t.warn),
        };
        ui.add(
            egui::Label::new(
                RichText::new(text)
                    .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                    .color(color),
            )
            .wrap(),
        );
        ui.add_space(8.0);
        rename_row(ui, t, computer, form, actions);
        forget_row(ui, t, computer, form, actions);
        if computer.paired.is_some() {
            ui.add_space(8.0);
            let ready = model.tor.is_ready() && idle && !model.setup_changed.contains(&id);
            admin_row(ui, t, computer, ready, form, actions);
        }
    });
}

/// The admin commands of this device's unattended access there (§B.8.10):
/// Revoke this device and End the session for every grant; Turn unattended
/// off only after a control session (the host checks the *My machines*
/// scope, B.8.4.1). Each is one action, confirmed in words that name the
/// computer, then the password prompt; nothing is sent by itself.
fn admin_row(
    ui: &mut Ui,
    t: &Tokens,
    computer: &Computer,
    ready: bool,
    form: &mut Form,
    actions: &mut Vec<Action>,
) {
    let id = computer.id;
    widgets::caps_label(ui, "Unattended access there");
    if !computer.unattended.worked_before {
        // Before a first success: the way to try it (Knock stays first).
        if Button::new(Kind::Ghost, "Connect without asking")
            .small()
            .enabled(ready)
            .show(ui)
            .clicked()
        {
            actions.push(Action::AskPassword(id));
        }
        muted(
            ui,
            t,
            "Works once its owner gave this device unattended access there; the password is \
             asked first.",
        );
        return;
    }
    if let Some((_, action)) = form.ua.confirming.filter(|(c, _)| *c == id) {
        widgets::card_frame(t, 12, Margin::same(12))
            .stroke(Stroke::new(1.0, theme::tint(t.danger_text, 0.5)))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(
                    egui::Label::new(
                        RichText::new(action.confirmation(&computer.title())).color(t.text_primary),
                    )
                    .wrap(),
                );
                ui.horizontal(|ui| {
                    if Button::new(Kind::Secondary, "Keep things as they are")
                        .small()
                        .show(ui)
                        .clicked()
                    {
                        form.ua.confirming = None;
                    }
                    if Button::new(Kind::Danger, "Continue: the password")
                        .small()
                        .enabled(ready)
                        .show(ui)
                        .clicked()
                    {
                        form.ua.confirming = None;
                        actions.push(Action::AskAdmin(id, action));
                    }
                });
            });
        return;
    }
    if let Some((_, typed)) = form.ua.unlocking.as_mut().filter(|(c, _)| *c == id) {
        // Unlock names the other device: its ID, as `tornect id` there shows
        // it (this computer cannot know another computer's grants).
        let mut done = None;
        widgets::card_frame(t, 12, Margin::same(12))
            .stroke(Stroke::new(1.0, theme::tint(t.danger_text, 0.5)))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(
                    egui::Label::new(
                        RichText::new(AdminAction::Unlock.confirmation(&computer.title()))
                            .color(t.text_primary),
                    )
                    .wrap(),
                );
                let field = widgets::text_field(ui, typed, "Its device ID", true, 320.0);
                field.widget_info(|| WidgetInfo::labeled(WidgetType::TextEdit, true, "Device ID"));
                muted(ui, t, "`tornect id` on that device shows its device ID.");
                let device = typed.trim().parse::<tornect_core::DeviceId>().ok();
                ui.horizontal(|ui| {
                    if Button::new(Kind::Secondary, "Keep things as they are")
                        .small()
                        .show(ui)
                        .clicked()
                    {
                        done = Some(None);
                    }
                    if Button::new(Kind::Danger, "Continue: the password")
                        .small()
                        .enabled(ready && device.is_some())
                        .show(ui)
                        .clicked()
                        && let Some(device) = device
                    {
                        done = Some(Some(*device.public_key_bytes()));
                    }
                });
            });
        match done {
            Some(Some(device)) => {
                form.ua.unlocking = None;
                actions.push(Action::AskUnlock(id, device));
            }
            Some(None) => form.ua.unlocking = None,
            None => {}
        }
        return;
    }
    ui.horizontal_wrapped(|ui| {
        let mut offered = vec![AdminAction::RevokeThisDevice, AdminAction::EndSession];
        if computer.unattended.control {
            offered.push(AdminAction::TurnOff);
        }
        for action in offered {
            if Button::new(Kind::Ghost, action.title())
                .small()
                .show(ui)
                .clicked()
            {
                form.ua.confirming = Some((id, action));
                form.ua.unlocking = None;
            }
        }
        if computer.unattended.control
            && Button::new(Kind::Ghost, AdminAction::Unlock.title())
                .small()
                .show(ui)
                .clicked()
        {
            form.ua.unlocking = Some((id, String::new()));
            form.ua.confirming = None;
        }
    });
    muted(
        ui,
        t,
        "Each asks you first, then for the password. Turning unattended off there works only \
         from a \"My machines\" access with control; the computer decides.",
    );
}

/// Copy ID and Rename, or the name field while renaming.
fn rename_row(
    ui: &mut Ui,
    t: &Tokens,
    computer: &Computer,
    form: &mut Form,
    actions: &mut Vec<Action>,
) {
    let id = computer.id;
    match &mut form.book.renaming {
        Some((renaming, name)) if *renaming == id => {
            let mut done = None;
            ui.horizontal_wrapped(|ui| {
                let field = widgets::text_field(ui, name, "A name for it", false, 220.0);
                field.widget_info(|| WidgetInfo::labeled(WidgetType::TextEdit, true, "Name"));
                let entered = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if Button::new(Kind::Primary, "Save")
                    .small()
                    .show(ui)
                    .clicked()
                    || entered
                {
                    done = Some(true);
                }
                if Button::new(Kind::Ghost, "Cancel")
                    .small()
                    .show(ui)
                    .clicked()
                {
                    done = Some(false);
                }
            });
            muted(ui, t, "The name stays on this computer; it is never sent.");
            match done {
                Some(true) => {
                    let name = name.trim().to_owned();
                    actions.push(Action::RenameHost(id, name));
                    form.book.renaming = None;
                }
                Some(false) => form.book.renaming = None,
                None => {}
            }
        }
        _ => {
            ui.horizontal_wrapped(|ui| {
                if Button::new(Kind::Secondary, "Copy ID")
                    .icon(Icon::Copy)
                    .small()
                    .show(ui)
                    .clicked()
                {
                    actions.push(Action::Copy(id.to_string()));
                }
                if Button::new(Kind::Secondary, "Rename")
                    .icon(Icon::Pencil)
                    .small()
                    .show(ui)
                    .clicked()
                {
                    form.book.renaming = Some((id, computer.name.clone().unwrap_or_default()));
                    form.book.forgetting = None;
                }
            });
        }
    }
}

/// Forget, then its confirmation.
fn forget_row(
    ui: &mut Ui,
    t: &Tokens,
    computer: &Computer,
    form: &mut Form,
    actions: &mut Vec<Action>,
) {
    let id = computer.id;
    ui.add_space(4.0);
    if form.book.forgetting == Some(id) {
        widgets::card_frame(t, 12, Margin::same(12))
            .stroke(Stroke::new(1.0, theme::tint(t.danger_text, 0.5)))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(
                    egui::Label::new(
                        RichText::new(forget_question(&computer.title())).color(t.text_primary),
                    )
                    .wrap(),
                );
                ui.horizontal(|ui| {
                    if Button::new(Kind::Secondary, "Keep it")
                        .small()
                        .show(ui)
                        .clicked()
                    {
                        form.book.forgetting = None;
                    }
                    if Button::new(Kind::Danger, "Forget")
                        .icon(Icon::Trash)
                        .small()
                        .show(ui)
                        .clicked()
                    {
                        actions.push(Action::ForgetHost(id));
                        form.book.forgetting = None;
                        form.book.selected = None;
                    }
                });
                muted(ui, t, FORGET_KEEPS);
            });
    } else if Button::new(Kind::Danger, "Forget this computer")
        .icon(Icon::Trash)
        .small()
        .show(ui)
        .clicked()
    {
        form.book.forgetting = Some(id);
        form.book.renaming = None;
    }
}

/// The Add computer form: an ID (checked as it is typed) and a name.
fn add_card(ui: &mut Ui, t: &Tokens, model: &Model, form: &mut Form, actions: &mut Vec<Action>) {
    let own = model
        .id
        .as_deref()
        .and_then(|groups| groups.parse::<TornectId>().ok());
    let mut done = None;
    widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        let Some((id_text, name)) = &mut form.book.adding else {
            return;
        };
        widgets::section_header(ui, "Add a computer");
        muted(
            ui,
            t,
            "Saved on this computer only. The first connection to it still compares a 6-digit \
             code on both screens.",
        );
        let field = widgets::text_field(ui, id_text, "Its Tornect ID", true, ui.available_width());
        field.widget_info(|| WidgetInfo::labeled(WidgetType::TextEdit, true, "Tornect ID"));
        let parsed = id_text.trim().parse::<TornectId>();
        let problem = match &parsed {
            _ if id_text.trim().is_empty() => None,
            Err(_) => Some("That is not a Tornect ID: 56 letters a–z and digits 2–7."),
            Ok(id) if id.verifying_key().is_err() => {
                Some("That ID has the right shape but is no computer's key: check for a typo.")
            }
            Ok(id) if Some(*id) == own => Some("That is this computer's own ID."),
            Ok(_) => None,
        };
        if let Some(problem) = problem {
            ui.label(
                RichText::new(problem)
                    .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                    .color(t.danger_text),
            );
        }
        let name_field =
            widgets::text_field(ui, name, "A name for it", false, ui.available_width());
        name_field.widget_info(|| WidgetInfo::labeled(WidgetType::TextEdit, true, "Name"));
        let valid = parsed
            .as_ref()
            .ok()
            .filter(|_| problem.is_none() && !id_text.trim().is_empty());
        ui.horizontal(|ui| {
            if Button::new(Kind::Primary, "Save")
                .enabled(valid.is_some())
                .show(ui)
                .clicked()
                && let Some(id) = valid
            {
                done = Some(Some((*id, name.trim().to_owned())));
            }
            if Button::new(Kind::Ghost, "Cancel").show(ui).clicked() {
                done = Some(None);
            }
        });
    });
    match done {
        Some(Some((id, name))) => {
            actions.push(Action::SaveEntry(id, name));
            form.book.adding = None;
            form.book.selected = Some(id);
        }
        Some(None) => form.book.adding = None,
        None => {}
    }
}

/// The Recent tab: the history switch, Clear, and the recent connections.
fn recent(ui: &mut Ui, t: &Tokens, book: &Book, actions: &mut Vec<Action>) {
    widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        widgets::section_header(ui, "History on this computer");
        ui.horizontal(|ui| {
            let mut on = book.history;
            if widgets::toggle(ui, &mut on, "Keep a list of recent connections").clicked() {
                actions.push(Action::SetHistory(on));
            }
            ui.label(
                RichText::new("Keep a list of recent connections")
                    .font(theme::font(ui.ctx(), Face::Medium, 14.0))
                    .color(t.text_primary),
            );
        });
        muted(
            ui,
            t,
            if book.history {
                "On. The list keeps the day of each connection, never the time; it stays on this \
                 computer and is never sent anywhere."
            } else {
                HISTORY_OFF
            },
        );
        ui.add_space(6.0);
        if Button::new(Kind::Danger, "Clear history")
            .icon(Icon::Trash)
            .small()
            .show(ui)
            .clicked()
        {
            actions.push(Action::ClearHistory);
        }
        muted(
            ui,
            t,
            "Clearing removes this list and the last-connected days. Saved computers stay until \
             you forget them; the session log of this computer is kept by design.",
        );
    });
    ui.add_space(GAP);
    if book.recent.is_empty() {
        muted(
            ui,
            t,
            if book.history {
                "No connections kept yet."
            } else {
                "History is off: no list of recent connections is kept."
            },
        );
        return;
    }
    widgets::card_frame(t, 14, Margin::symmetric(16, 10)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        for (id, day) in &book.recent {
            ui.horizontal(|ui| {
                icons::show(ui, Icon::Clock, 15.0, t.text_muted);
                ui.label(
                    RichText::new(day_text(*day, book.today))
                        .font(theme::font(ui.ctx(), Face::Medium, 13.0))
                        .color(t.text_secondary),
                );
                ui.label(
                    RichText::new(format!("You connected to \"{}\"", book.title_of(id)))
                        .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                        .color(t.text_primary),
                );
                ui.label(
                    RichText::new(format!("{}…", id.short()))
                        .font(theme::font(ui.ctx(), Face::Mono, 12.0))
                        .color(t.text_muted),
                );
            });
        }
    });
}

/// The Devices tab: who can ask to connect here (read-only in this version).
fn devices(ui: &mut Ui, t: &Tokens, book: &Book, shared: bool) {
    if book.devices.is_empty() {
        widgets::card(ui, |ui| {
            ui.set_width(ui.available_width());
            widgets::section_header(ui, "No device has paired with this computer yet");
            muted(
                ui,
                t,
                "A device that connects here for the first time pairs first: a 6-digit code on \
                 both screens, and your yes.",
            );
        });
        return;
    }
    widgets::card_frame(t, 14, Margin::same(6)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        for device in &book.devices {
            egui::Frame::new()
                .inner_margin(Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        // A pinned device: its identicon beside its label;
                        // its words labelled as such (§B.6.1), neither while
                        // this computer is shared.
                        let seed = device.identicon.filter(|_| !shared).map(|i| i.seed());
                        widgets::identicon(ui, seed.as_ref().map_or(&[][..], |s| &s[..]), 32.0);
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(&device.label)
                                    .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                                    .color(t.text_primary),
                            );
                            if let Some(words) = device.words.filter(|_| !shared) {
                                ui.label(
                                    RichText::new(format!("device words: {}", words.shown()))
                                        .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                                        .color(t.text_muted),
                                );
                            }
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!(
                                    "Paired {} · last request {}",
                                    day_in_sentence(device.paired, book.today),
                                    day_in_sentence(device.last_seen, book.today)
                                ))
                                .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                                .color(t.text_muted),
                            );
                        });
                    });
                });
        }
    });
    ui.add_space(GAP);
    note_line(
        ui,
        Icon::ShieldCheck,
        "A paired device still asks before every session, unless you gave it unattended access \
         (a password of its own). This list is read-only in this version.",
        t.text_muted,
    );
}
