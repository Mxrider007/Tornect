//! Home (the redesign's §4, as far as it works today): this computer's ID
//! with Copy, the connect field, the Tor and hosting lines, the desktop's
//! screen-sharing grant, the client's stage and what happened recently.

use std::time::{Duration, Instant};

use egui::{Align, Layout, Margin, RichText, Stroke, Ui, vec2};
use tornect_core::TornectId;

use super::super::icons::{self, Icon};
use super::super::model::{ClientStage, Hosting, Model, Setup, TorState};
use super::super::theme::{self, Face, Tokens};
use super::super::view::{Action, Form, SAS_SIZE};
use super::super::widgets::{self, Button, Kind, Tone};

/// How long "Copied" shows after Copy ID.
const COPIED_FOR: Duration = Duration::from_secs(2);
/// From this content width on, the ID and connect cards sit side by side.
const TWO_COLUMNS_FROM: f32 = 720.0;
/// The space between cards.
const GAP: f32 = 20.0;

pub(super) fn home(
    ui: &mut Ui,
    model: &Model,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    widgets::page_header(
        ui,
        "Home",
        "Reach your computers over Tor, and let paired devices ask to see this one.",
    );
    ui.add_space(14.0);

    let pending_grant = model.setup.as_ref().filter(|s| !s.granted);
    if let Some(setup) = pending_grant {
        setup_card(ui, t, setup, !model.sharing.is_empty(), actions);
        ui.add_space(GAP);
    }

    let width = ui.available_width();
    if width >= TWO_COLUMNS_FROM {
        let left = ((width - GAP) * 1.3 / 2.3).floor();
        let right = width - GAP - left;
        // Both cards as tall as the taller one's content in the last pass.
        let heights = egui::Id::new("home-row-height");
        let min = ui.data(|d| d.get_temp::<f32>(heights)).unwrap_or(0.0);
        let mut tallest = 0.0_f32;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = GAP;
            ui.allocate_ui_with_layout(vec2(left, 0.0), Layout::top_down(Align::Min), |ui| {
                tallest = tallest.max(id_card(ui, t, model, form, now, min, actions));
            });
            ui.allocate_ui_with_layout(vec2(right, 0.0), Layout::top_down(Align::Min), |ui| {
                tallest = tallest.max(connect_card(ui, t, model, form, min, actions));
            });
        });
        if (tallest - min).abs() > 0.5 {
            ui.data_mut(|d| d.insert_temp(heights, tallest));
            ui.ctx().request_repaint();
        }
    } else {
        id_card(ui, t, model, form, now, 0.0, actions);
        ui.add_space(GAP - 8.0);
        connect_card(ui, t, model, form, 0.0, actions);
    }

    if !matches!(model.client, ClientStage::Idle) {
        ui.add_space(GAP - 8.0);
        widgets::card(ui, |ui| {
            ui.set_width(ui.available_width());
            client_stage(ui, t, &model.client, actions);
        });
    }

    if let Some(setup) = model.setup.as_ref().filter(|s| s.granted) {
        ui.add_space(GAP - 8.0);
        setup_card(ui, t, setup, !model.sharing.is_empty(), actions);
    }

    if !model.events.is_empty() {
        ui.add_space(GAP);
        ui.horizontal(|ui| {
            widgets::section_header(ui, "Recent activity");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new("Since this window opened")
                        .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                        .color(t.text_muted),
                );
            });
        });
        widgets::card_frame(t, 14, Margin::symmetric(16, 10)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            for line in model.events.iter().rev() {
                ui.horizontal(|ui| {
                    widgets::dot(ui, Tone::Neutral);
                    ui.add(
                        egui::Label::new(
                            RichText::new(line)
                                .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                                .color(t.text_primary),
                        )
                        .wrap(),
                    );
                });
            }
        });
    }
    ui.add_space(8.0);
}

/// A hero card's frame around its content, 20 points of margin and a
/// 1-point border above and below.
const CARD_FRAME_HEIGHT: f32 = 42.0;

/// The hero card: the ID in two lines of mono groups, Copy, and the lines
/// that say whether it can be reached and what a paired device may do. At
/// least `min_height` tall; returns the height its content needs.
fn id_card(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    form: &mut Form,
    now: Instant,
    min_height: f32,
    actions: &mut Vec<Action>,
) -> f32 {
    let mut needs = 0.0;
    widgets::card_frame(t, 18, Margin::symmetric(24, 20))
        .stroke(Stroke::new(1.0, theme::tint(t.accent_text, 0.30)))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                widgets::caps_label(ui, "Your Tornect ID");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let (tone, text) = reachability(&model.hosting);
                    widgets::chip(ui, tone, true, text);
                });
            });
            match &model.id {
                Some(id) => {
                    let groups: Vec<&str> = id.split_whitespace().collect();
                    let split = groups.len().div_ceil(2).max(1);
                    let (first, second) = groups.split_at(split.min(groups.len()));
                    let text = format!("{}\n{}", first.join(" "), second.join(" "));
                    // 19 points where the card is wide enough for a line of
                    // four groups (35 characters at 0.6 em), smaller where not.
                    let size = (ui.available_width() / (35.0 * 0.62)).clamp(12.0, 19.0);
                    ui.label(
                        RichText::new(text)
                            .font(theme::font(ui.ctx(), Face::MonoMedium, size))
                            .extra_letter_spacing(0.4)
                            .line_height(Some(size * 1.6))
                            .color(t.text_primary),
                    );
                }
                None => {
                    ui.label(RichText::new("(not created yet)").color(t.text_muted));
                }
            }
            ui.horizontal(|ui| {
                let copied = form
                    .copied
                    .is_some_and(|at| now.saturating_duration_since(at) < COPIED_FOR);
                let (label, icon) = if copied {
                    ("Copied", Icon::Check)
                } else {
                    ("Copy ID", Icon::Copy)
                };
                if Button::new(Kind::Secondary, label)
                    .icon(icon)
                    .small()
                    .enabled(model.id.is_some())
                    .show(ui)
                    .clicked()
                {
                    actions.push(Action::CopyId);
                    form.copied = Some(now);
                    ui.ctx().request_repaint_after(COPIED_FOR);
                }
                ui.add(
                    egui::Label::new(
                        RichText::new("Share it only with people you want to hear from")
                            .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                            .color(t.text_muted),
                    )
                    .truncate(),
                );
            });
            divider(ui, t);
            status_line(ui, Icon::Globe, tor_line(t, &model.tor));
            status_line(ui, Icon::ShieldCheck, hosting_line(t, &model.hosting));
            needs = ui.min_rect().height() + CARD_FRAME_HEIGHT;
            ui.set_min_height((min_height - CARD_FRAME_HEIGHT).max(0.0));
        });
    needs
}

/// A thin rule across the card.
fn divider(ui: &mut Ui, t: &Tokens) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0, t.border_subtle);
}

/// A status line: an icon and the words, in the words' colour.
fn status_line(ui: &mut Ui, icon: Icon, (text, color): (String, egui::Color32)) {
    ui.horizontal_top(|ui| {
        icons::show(ui, icon, 16.0, color);
        ui.add(
            egui::Label::new(
                RichText::new(text)
                    .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                    .color(color),
            )
            // One accessibility node for the whole line (a selectable label
            // is also one node per row): what it promises reads as one.
            .selectable(false)
            .wrap(),
        );
    });
}

/// The chip beside "Your Tornect ID".
fn reachability(hosting: &Hosting) -> (Tone, &'static str) {
    match hosting {
        Hosting::Published {
            reachable: true, ..
        } => (Tone::Ok, "Reachable over Tor"),
        Hosting::Published { .. } => (Tone::Warn, "Not reachable yet"),
        Hosting::Publishing => (Tone::Warn, "Publishing…"),
        Hosting::Waiting => (Tone::Neutral, "Waiting for Tor"),
        Hosting::Off(_) => (Tone::Neutral, "Not answering requests"),
    }
}

/// The connect card: the ID field, Connect, and what pairing looks like. At
/// least `min_height` tall; returns the height its content needs.
fn connect_card(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    form: &mut Form,
    min_height: f32,
    actions: &mut Vec<Action>,
) -> f32 {
    let mut needs = 0.0;
    widgets::card_frame(t, 18, Margin::symmetric(24, 20)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        widgets::section_header(ui, "Connect to a computer");
        ui.label(
            RichText::new("Its Tornect ID (56 characters; “.onion” is optional)")
                .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                .color(t.text_muted),
        );
        let idle = matches!(model.client, ClientStage::Idle | ClientStage::Ended(_));
        let field = widgets::text_field(
            ui,
            &mut form.connect_to,
            "Paste a Tornect ID",
            true,
            ui.available_width(),
        );
        let parsed = form.connect_to.trim().parse::<TornectId>();
        let ready = model.tor.is_ready() && idle && parsed.is_ok();
        if !form.connect_to.trim().is_empty() && parsed.is_err() {
            ui.label(
                RichText::new("That is not a Tornect ID: 56 letters a–z and digits 2–7.")
                    .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                    .color(t.danger_text),
            );
        }
        let entered = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.horizontal(|ui| {
            let clicked = Button::new(Kind::Primary, "Connect")
                .icon(Icon::ArrowRight)
                .enabled(ready)
                .show(ui)
                .clicked();
            if (clicked || (entered && ready))
                && let Ok(id) = &parsed
            {
                actions.push(Action::Connect(*id));
            }
            if !model.tor.is_ready() {
                ui.label(
                    RichText::new("Connecting waits for Tor.")
                        .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                        .color(t.text_muted),
                );
            }
        });
        ui.horizontal_top(|ui| {
            icons::show(ui, Icon::Info, 15.0, t.info);
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "The first time, both screens show a 6-digit code. Pair only if they \
                         match.",
                    )
                    .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                    .color(t.text_muted),
                )
                .wrap(),
            );
        });
        needs = ui.min_rect().height() + CARD_FRAME_HEIGHT;
        ui.set_min_height((min_height - CARD_FRAME_HEIGHT).max(0.0));
    });
    needs
}

/// The Tor line, in words and colour.
fn tor_line(t: &Tokens, tor: &TorState) -> (String, egui::Color32) {
    match tor {
        TorState::Starting => ("Tor: starting…".to_owned(), t.text_muted),
        TorState::Trying { via, attempt, of } => (
            format!("Tor: connecting via {via} ({attempt}/{of})…"),
            t.text_muted,
        ),
        TorState::Progress { via, pct, blocked } => match blocked {
            Some(why) => (format!("Tor: {pct}% via {via}; stuck: {why}"), t.warn),
            None => (format!("Tor: connecting via {via}, {pct}%"), t.text_muted),
        },
        TorState::Ready { via } => (format!("Tor: connected via {via}"), t.ok),
        TorState::Failed(why) => (format!("Tor: not reachable ({why})"), t.danger_text),
    }
}

/// The hosting line, in words and colour. One label, whatever the state:
/// the promise it makes must stay true (SLICE-E E1-5).
fn hosting_line(t: &Tokens, hosting: &Hosting) -> (String, egui::Color32) {
    match hosting {
        Hosting::Waiting => (
            "Incoming requests: waiting for Tor".to_owned(),
            t.text_muted,
        ),
        Hosting::Publishing => (
            "Incoming requests: publishing this ID (the first time can take two minutes)…"
                .to_owned(),
            t.text_muted,
        ),
        // True in every state (SLICE-E E1-5): a device granted unattended
        // access starts a session without asking (PLAN §B.8).
        Hosting::Published {
            reachable: true, ..
        } => (
            "Incoming requests: reachable; paired devices ask before they see this screen, \
             unless you granted one unattended access"
                .to_owned(),
            t.ok,
        ),
        Hosting::Published {
            reachable: false,
            state,
            problem,
        } => (
            match problem {
                Some(problem) => {
                    format!("Incoming requests: not reachable yet ({state}: {problem})")
                }
                None => format!("Incoming requests: not reachable yet ({state})"),
            },
            t.warn,
        ),
        Hosting::Off(why) => (format!("Incoming requests: off ({why})"), t.text_muted),
    }
}

/// The first-run desktop grant (UI_PLAN §6.4's Wayland step, as the operator
/// decided on 2026-09-23): the dialog on the owner's own desktop, now, rather
/// than inside a viewer's wait.
fn setup_card(ui: &mut Ui, t: &Tokens, setup: &Setup, sharing: bool, actions: &mut Vec<Action>) {
    let border = if setup.granted {
        t.border_subtle
    } else {
        theme::tint(t.accent_text, 0.45)
    };
    widgets::card_frame(t, 14, Margin::symmetric(20, 16))
        .stroke(Stroke::new(1.0, border))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                let (tile, _) = ui.allocate_exact_size(vec2(40.0, 40.0), egui::Sense::hover());
                ui.painter()
                    .rect_filled(tile, 12, theme::tint(t.accent_fill, 0.16));
                icons::paint(ui, tile.center(), Icon::Monitor, 20.0, t.accent_text);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("Screen sharing on this desktop")
                            .font(theme::font(ui.ctx(), Face::Semibold, 15.0))
                            .color(t.text_primary),
                    );
                    if setup.granted {
                        ui.label(
                            RichText::new(
                                "Granted and remembered: a session starts without the \
                                 desktop's dialog.",
                            )
                            .color(t.ok),
                        );
                    } else {
                        ui.label(
                            RichText::new(
                                "Not granted yet. Grant it now, while you are here: the desktop \
                                 asks once, and later sessions never wait on its dialog. Turn on \
                                 \"Allow Remote Interaction\" in the dialog to let viewers you \
                                 allow use the keyboard and mouse.",
                            )
                            .color(t.text_secondary),
                        );
                        ui.label(
                            RichText::new(
                                "Without it, the desktop asks when a viewer's picture starts, \
                                 and someone here must answer within 30 s.",
                            )
                            .small()
                            .color(t.text_muted),
                        );
                    }
                    ui.horizontal(|ui| {
                        let (label, kind) = if setup.granted {
                            ("Grant again", Kind::Secondary)
                        } else {
                            ("Grant screen sharing", Kind::Primary)
                        };
                        if Button::new(kind, label)
                            .enabled(!setup.busy && !sharing)
                            .show(ui)
                            .clicked()
                        {
                            actions.push(Action::Grant);
                        }
                        if setup.granted
                            && Button::new(Kind::Secondary, "Revoke")
                                .enabled(!setup.busy)
                                .show(ui)
                                .clicked()
                        {
                            actions.push(Action::Revoke);
                        }
                        if setup.busy {
                            ui.spinner();
                            ui.label("Answer the desktop's dialog…");
                        }
                    });
                    ui.label(
                        RichText::new(format!(
                            "To revoke by hand, delete {} (`tornect doctor` names it too); the \
                             desktop then asks again at the next session.",
                            setup.token_file.display()
                        ))
                        .small()
                        .color(t.text_muted),
                    );
                    if let Some(note) = &setup.note {
                        ui.label(RichText::new(note).small().color(t.text_secondary));
                    }
                });
            });
        });
}

/// Where the session this computer asked for stands.
fn client_stage(ui: &mut Ui, t: &Tokens, stage: &ClientStage, actions: &mut Vec<Action>) {
    match stage {
        ClientStage::Idle => {}
        ClientStage::Reaching { id } => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!(
                    "Reaching {id} over Tor (usually 5–30 s, up to a minute)…"
                ));
            });
        }
        ClientStage::Pairing { sas } => {
            ui.label("Pairing: the host's screen now shows a code. It must be exactly");
            ui.label(
                RichText::new(sas)
                    .font(theme::font(ui.ctx(), Face::MonoSemibold, SAS_SIZE))
                    .extra_letter_spacing(2.0)
                    .color(t.accent_text),
            );
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Waiting for the host's user to compare it (up to 90 s)…");
            });
        }
        ClientStage::Asking => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Waiting for the host's user to allow the session (up to 110 s)…");
            });
        }
        ClientStage::Live(viewing) => {
            ui.horizontal_top(|ui| {
                let icon = if viewing.control {
                    Icon::MousePointer
                } else {
                    Icon::Eye
                };
                icons::show(ui, icon, 16.0, t.ok);
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "Connected to \"{}\" ({}): the picture is in its own window.",
                            viewing.host,
                            if viewing.control {
                                "control"
                            } else {
                                "view only"
                            }
                        ))
                        .color(t.ok),
                    )
                    .wrap(),
                );
            });
            if Button::new(Kind::Danger, "End the session")
                .show(ui)
                .clicked()
            {
                actions.push(Action::EndViewing);
            }
        }
        ClientStage::Ended(why) => {
            ui.horizontal_top(|ui| {
                icons::show(ui, Icon::Info, 16.0, t.text_muted);
                ui.add(egui::Label::new(RichText::new(why).color(t.text_muted)).wrap());
            });
        }
    }
}
