//! Home (the redesign's §4, as far as it works today): this computer's ID
//! with Copy, Copy invitation and its QR code, the name others see, the
//! connect field (which a `tornect:` link can fill, never dial), the
//! Tor and hosting lines, the desktop's screen-sharing grant, the client's
//! stage, the saved computers, the recent connections and what happened
//! since the window opened.

use std::time::{Duration, Instant};

use egui::{Align, Layout, Margin, RichText, Stroke, Ui, vec2};
use tornect_core::invite;
use tornect_session::INTERNET_DIRECT;
use tornect_signal::consent::TransportPolicy;

use super::super::icons::{self, Icon};
use super::super::model::{ClientStage, Computer, Failure, Hosting, Model, Setup, TorState};
use super::super::nav::Page;
use super::super::theme::{self, Face, Tokens};
use super::super::view::{Action, Form, LinkNote, LinkRow, SAS_SIZE};
use super::super::widgets::{self, Button, Kind, Tone};
use super::{day_in_sentence, day_text, id_field};

/// Home's first-run line: history is off until switched on, and the
/// session log is kept either way (F4-M1): the host side records every
/// request to this computer, the client side every unattended connection.
pub(super) const HISTORY_NOTICE: &str = "Tornect keeps no list of your recent connections \
    unless you switch history on (Address book, Recent). Pairings are always kept. The session \
    log on this computer always records connection attempts in both directions: requests to this \
    computer, and your unattended connections to others. It is never sent anywhere.";

/// The first run's question (the redesign's First run), asked before
/// anything sends this computer's name.
pub(super) const NAME_QUESTION: &str = "What should other devices call this computer?";

/// Home's sticky badge while a readiness row is not green and unattended
/// access is on (§B.8.7.1 ⑥).
pub(super) const NOT_READY: &str = "Unattended access is not ready: see Settings, Security.";

/// Home's badge of how many devices can connect without asking (§B.8.7.3).
fn without_asking(devices: usize) -> String {
    match devices {
        1 => "1 device can connect without asking".to_owned(),
        n => format!("{n} devices can connect without asking"),
    }
}

/// How long "Copied" shows after Copy ID or Copy invitation.
const COPIED_FOR: Duration = Duration::from_secs(2);
/// From this content width on, the ID and connect cards sit side by side.
const TWO_COLUMNS_FROM: f32 = 720.0;
/// The space between cards.
const GAP: f32 = 20.0;
/// How many saved computers Home shows (the address book has them all).
const SAVED_SHOWN: usize = 3;
/// How many recent connections Home shows.
const RECENT_SHOWN: usize = 4;
/// The QR code's size.
const QR_SIZE: f32 = 164.0;

pub(super) fn home(
    ui: &mut Ui,
    model: &Model,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    // SLICE-E E1-5's caveat, as the hosting line keeps it (review F-10).
    widgets::page_header(
        ui,
        "Home",
        "Reach your computers over Tor, and let paired devices ask to see this one (or \
         connect without asking, if you gave one unattended access).",
    );
    ui.add_space(14.0);

    // The first start: the name others see is asked before anything can
    // send it; until it is answered or skipped Home offers nothing else.
    // While this screen may be in a picture that leaves it, the hidden card
    // stands in its place (nothing would be saved).
    if model.name_question {
        if model.screen_shared(now) {
            super::hidden_card(ui, super::settings::WRITES_HIDDEN);
        } else {
            name_question(ui, model, form, actions);
        }
        return;
    }

    // The first run: what history keeps, said once (history is off until
    // switched on).
    if model.history_notice && !model.book.history {
        ui.horizontal_top(|ui| {
            icons::show(ui, Icon::Info, 15.0, t.info);
            ui.add(
                egui::Label::new(
                    RichText::new(HISTORY_NOTICE)
                        .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                        .color(t.text_secondary),
                )
                .wrap(),
            );
        });
        ui.add_space(GAP - 8.0);
    }

    // Unattended access as the guard says it (§B.8.7.3): how many devices
    // can connect without asking, which stays when the banner is
    // acknowledged and is not drawn while this screen is shared (how many
    // devices there are is hidden with the address book); and the sticky
    // not-ready badge while unattended access is on (§B.8.7.1 ⑥).
    if let Some(manager) = &model.manager {
        let count = manager.without_asking > 0 && !model.screen_shared(now);
        let not_ready = manager.on && manager.not_ready;
        if count || not_ready {
            ui.horizontal_wrapped(|ui| {
                if count {
                    widgets::chip(
                        ui,
                        Tone::Warn,
                        true,
                        &without_asking(manager.without_asking),
                    );
                }
                if not_ready {
                    widgets::chip(ui, Tone::Danger, true, NOT_READY);
                }
            });
            ui.add_space(GAP - 8.0);
        }
    }

    // The connection this computer asked for comes first, while it lasts.
    if !matches!(model.client, ClientStage::Idle) {
        widgets::card(ui, |ui| {
            ui.set_width(ui.available_width());
            connect_stepper(ui, t, model, now, model.screen_shared(now), actions);
        });
        ui.add_space(GAP);
    }

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
                tallest = tallest.max(connect_card(
                    ui,
                    t,
                    model,
                    form,
                    now,
                    (min, model.screen_shared(now)),
                    actions,
                ));
            });
        });
        if (tallest - min).abs() > 0.5 {
            ui.data_mut(|d| d.insert_temp(heights, tallest));
            ui.ctx().request_repaint();
        }
    } else {
        id_card(ui, t, model, form, now, 0.0, actions);
        ui.add_space(GAP - 8.0);
        connect_card(
            ui,
            t,
            model,
            form,
            now,
            (0.0, model.screen_shared(now)),
            actions,
        );
    }

    let shared = model.screen_shared(now);

    if let Some(setup) = model.setup.as_ref().filter(|s| s.granted) {
        ui.add_space(GAP - 8.0);
        setup_card(ui, t, setup, !model.sharing.is_empty(), actions);
    }

    ui.add_space(GAP);
    if shared {
        // While this screen may be in a picture that leaves it (P-M2): no
        // saved name, no ID, no day, no recent line, nothing of what
        // happened (its lines name computers and devices).
        widgets::section_header(ui, "Saved computers");
        super::hidden_card(
            ui,
            "Saved computers, recent connections and what happened since the window opened \
             come back when sharing ends.",
        );
        ui.add_space(8.0);
        return;
    }
    saved(ui, t, model, form, now, actions);
    ui.add_space(GAP);
    recent(ui, t, model);

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
            // From the top: a minimum set later would count from the cursor.
            let top = ui.cursor().top();
            ui.set_min_height((min_height - CARD_FRAME_HEIGHT).max(0.0));
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
            // The address's own words sit under it, labelled "this address"
            // (§B.6.1 item 5); none while this computer is shared (R-W2).
            let shared = model.screen_shared(now);
            if let Some(mine) = model.mine.filter(|_| !shared) {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("this address: {}", mine.address.shown()))
                            .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                            .color(t.text_muted),
                    )
                    .wrap(),
                );
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
                // The text to send someone (design `invite` §2.1): the ID in
                // groups, its link and the one download location, and nothing
                // of this computer's name or words.
                let own = model.own_id();
                let invited = form
                    .invited
                    .is_some_and(|at| now.saturating_duration_since(at) < COPIED_FOR);
                let (label, icon) = if invited {
                    ("Copied", Icon::Check)
                } else {
                    ("Copy invitation", Icon::Copy)
                };
                if Button::new(Kind::Secondary, label)
                    .icon(icon)
                    .small()
                    .enabled(own.is_some())
                    .show(ui)
                    .clicked()
                    && let Some(id) = own
                {
                    actions.push(Action::Copy(invite::invitation(&id)));
                    form.invited = Some(now);
                    ui.ctx().request_repaint_after(COPIED_FOR);
                }
                let qr = if form.qr {
                    "Hide QR code"
                } else {
                    "Show QR code"
                };
                if Button::new(Kind::Secondary, qr)
                    .icon(Icon::QrCode)
                    .small()
                    .enabled(model.id.is_some())
                    .show(ui)
                    .clicked()
                {
                    form.qr = !form.qr;
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
            if form.qr
                && !shared
                && let Some(id) = &model.id
            {
                ui.horizontal_top(|ui| {
                    // The ID as another device reads it: the onion address.
                    widgets::qr_code(ui, &format!("{}.onion", id.replace(' ', "")), QR_SIZE);
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "Scan it with another device to read this ID without typing \
                                 it. It holds the ID and nothing else.",
                            )
                            .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                            .color(t.text_muted),
                        )
                        .wrap(),
                    );
                });
            }
            divider(ui, t);
            // The home card leads with the words a host's sheet shows when
            // this computer connects (§B.6.1 item 5).
            match (model.mine, shared) {
                (Some(mine), false) => {
                    status_line(
                        ui,
                        Icon::Monitor,
                        (
                            format!(
                                "When you connect to another computer, it shows: {}",
                                mine.device.shown()
                            ),
                            t.text_primary,
                        ),
                    );
                    status_line(
                        ui,
                        Icon::Info,
                        (
                            "Device words help you recognise a device. They do not prove who it \
                             is; the code does. They identify this computer, like its ID, and \
                             are not a secret or a password."
                                .to_owned(),
                            t.text_muted,
                        ),
                    );
                }
                (Some(_), true) => status_line(
                    ui,
                    Icon::Info,
                    (
                        "Device words are hidden while this computer is shared.".to_owned(),
                        t.text_muted,
                    ),
                ),
                (None, _) => {}
            }
            if !model.device_name.is_empty() {
                // Decision 5: the name is sent to every device this computer
                // pairs with and every computer it connects to.
                status_line(
                    ui,
                    Icon::Monitor,
                    (
                        format!(
                            "Others see this computer as \u{201c}{}\u{201d}",
                            model.device_name
                        ),
                        t.text_secondary,
                    ),
                );
            }
            let retry = retry_in(model, now);
            status_line(ui, Icon::Globe, tor_line(t, &model.tor, retry));
            // The countdown is the Tor line's while Tor is down, else the
            // hosting line's (publishing this ID failed or stopped).
            let hosting_retry = retry.filter(|_| model.tor.is_ready());
            status_line(
                ui,
                Icon::ShieldCheck,
                hosting_line(t, &model.hosting, hosting_retry),
            );
            retry_button(ui, model, actions);
            needs = content_height(ui, top) + CARD_FRAME_HEIGHT;
        });
    needs
}

/// The height of what `ui` holds below `top`, whatever minimum it was given:
/// the cursor stands one item spacing below the last widget.
fn content_height(ui: &Ui, top: f32) -> f32 {
    ui.cursor().top() - top - ui.spacing().item_spacing.y
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
/// least `min_height` tall; returns the height its content needs. A link's
/// fill (design `invite` §2.2) only puts an ID in the field and says so:
/// Connect waits until its row has been seen, still, for a second.
fn connect_card(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    form: &mut Form,
    now: Instant,
    (min_height, shared): (f32, bool),
    actions: &mut Vec<Action>,
) -> f32 {
    let mut needs = 0.0;
    widgets::card_frame(t, 18, Margin::symmetric(24, 20)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let top = ui.cursor().top();
        ui.set_min_height((min_height - CARD_FRAME_HEIGHT).max(0.0));
        widgets::section_header(ui, "Connect to a computer");
        ui.add(
            egui::Label::new(
                RichText::new(
                    "Its Tornect ID or a tornect:// link (a whole invitation can be pasted)",
                )
                .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                .color(t.text_muted),
            )
            .wrap(),
        );
        let idle = matches!(model.client, ClientStage::Idle | ClientStage::Ended(_));
        let field = widgets::text_field(
            ui,
            &mut form.connect_to,
            "Paste a Tornect ID or an invitation",
            true,
            ui.available_width(),
        );
        // The ID in any written form, a link or a whole invitation (design
        // `invite` §2.2); this computer's own ID connects nowhere (B26): it
        // would ask this computer for a session with itself.
        let own = model.own_id();
        let mut checked = id_field::check(&form.connect_to, own);
        if id_field::normalize(&mut form.connect_to, &checked, field.changed()) {
            checked = id_field::check(&form.connect_to, own);
        }
        let parsed = checked.as_ref().ok().map(|found| found.id);
        let is_own = checked == Err(id_field::Problem::Own);
        form.link_seen(parsed, field.changed());
        // A link filled the field: the keyboard focus goes, so that keys
        // typed for another program never reach it (L-4).
        if std::mem::take(&mut form.unfocus_connect) {
            field.surrender_focus();
        }
        let ready = model.tor.is_ready() && idle && parsed.is_some();
        if let Err(problem) = &checked {
            id_field::problem_line(ui, t, problem);
        }
        for note in form.link_notes() {
            link_note(ui, t, note);
        }
        let entered = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        // The look-alike warning for the ID in the field (§B.6.1 item 4):
        // Connect then takes a second, deliberate click on its own button.
        // Never for this computer's own ID, which is not a different address.
        let warned = model
            .connect_warning
            .as_ref()
            .filter(|w| !is_own && parsed == Some(w.id));
        // Or it could not be compared with every saved ID (F-4).
        let unchecked = model
            .connect_unchecked
            .filter(|u| !is_own && parsed == Some(*u));
        let second_click = warned.map(|w| w.id).or(unchecked);
        if let Some(warning) = warned {
            // Never the saved name while this screen may be in a picture
            // that leaves it.
            let text = if shared {
                "Looks like a saved computer, but it is a different address.".to_owned()
            } else {
                format!(
                    "Looks like your saved \"{}\", but it is a different address.",
                    warning.name
                )
            };
            ui.add(
                egui::Label::new(
                    RichText::new(text)
                        .font(theme::font(ui.ctx(), Face::Semibold, 13.0))
                        .color(t.danger_text),
                )
                .wrap(),
            );
        } else if unchecked.is_some() {
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Could not compare it with your saved addresses: a file of saved \
                         entries could not be read.",
                    )
                    .font(theme::font(ui.ctx(), Face::Semibold, 13.0))
                    .color(t.danger_text),
                )
                .wrap(),
            );
        }
        ui.horizontal(|ui| {
            // After a link's fill, or a link that brought the window here,
            // Connect, Connect anyway and Enter wait until this row has been
            // on screen, still, for a second (L-1). While the field holds a
            // fill, only a click of the pointer presses them: a button
            // focused before the link never dials it on Space or Enter.
            let ready = ready && form.link_armed(ui, now);
            let pointer_only = form.link_filled();
            if let Some(id) = second_click {
                if Button::new(Kind::Danger, "Connect anyway")
                    .icon(Icon::ArrowRight)
                    .enabled(ready)
                    .pointer_only(pointer_only)
                    .pressed(ui)
                {
                    actions.push(Action::ConnectAnyway(id));
                }
            } else {
                let clicked = Button::new(Kind::Primary, "Connect")
                    .icon(Icon::ArrowRight)
                    .enabled(ready)
                    .pointer_only(pointer_only)
                    .pressed(ui);
                if (clicked || (entered && ready))
                    && let Some(id) = parsed
                {
                    actions.push(Action::Connect(id));
                }
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
        needs = content_height(ui, top) + CARD_FRAME_HEIGHT;
    });
    needs
}

/// What a link did to the connect field, under it (design `invite` §2.2):
/// never the ID itself.
fn link_note(ui: &mut Ui, t: &Tokens, note: LinkNote) {
    let text = match note {
        LinkNote::Filled(_) => LINK_FILLED,
        LinkNote::Refused => LINK_REFUSED,
        LinkNote::Own => LINK_OWN,
    };
    ui.horizontal_top(|ui| {
        icons::show(ui, Icon::Info, 15.0, t.info);
        ui.add(
            egui::Label::new(
                RichText::new(text)
                    .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                    .color(t.text_secondary),
            )
            .wrap(),
        );
    });
}

/// The note under the connect field after a link filled it.
pub(super) const LINK_FILLED: &str =
    "Filled in from a link: nothing connects until you press Connect.";

/// The note under the connect field after a link without a valid ID.
pub(super) const LINK_REFUSED: &str = "A tornect:// link was opened, but it held no valid \
    Tornect ID, so nothing was filled in.";

/// The note under the connect field after a link holding this computer's
/// own ID.
pub(super) const LINK_OWN: &str =
    "A tornect:// link held this computer's own ID, so nothing was filled in.";

/// The first run's question, the saved name filled in (on a fresh home the
/// neutral default), with Save and Skip.
fn name_question(ui: &mut Ui, model: &Model, form: &mut Form, actions: &mut Vec<Action>) {
    let t = theme::tokens(ui.ctx());
    widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        widgets::section_header(ui, NAME_QUESTION);
        ui.add(
            egui::Label::new(
                RichText::new(super::settings::general::NAME_NOTE)
                    .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                    .color(t.text_secondary),
            )
            .wrap(),
        );
        ui.add_space(8.0);
        let saved = &model.settings.device_name;
        let name = form.first_name.get_or_insert_with(|| saved.clone());
        let mut done = None;
        ui.horizontal_wrapped(|ui| {
            let field = widgets::text_field(ui, name, saved, false, 260.0);
            let typed = name.trim();
            let valid = !typed.is_empty() && typed.len() <= super::settings::general::NAME_MAX;
            let entered = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if Button::new(Kind::Primary, "Save")
                .enabled(valid)
                .show(ui)
                .clicked()
                || (entered && valid)
            {
                done = Some(Some(typed.to_owned()));
            }
            if Button::new(Kind::Ghost, "Skip").show(ui).clicked() {
                done = Some(None);
            }
        });
        if let Some(answer) = done {
            actions.push(Action::FirstRunName(answer));
            form.first_name = None;
        }
    });
}

/// How long until Tornect tries Tor, or publishing this ID, again by
/// itself (B02), at `now`; `None` while nothing waits for a try.
pub(super) fn retry_in(model: &Model, now: Instant) -> Option<Duration> {
    model.tor_retry.map(|at| at.saturating_duration_since(now))
}

/// "Try again" while a try waits (B02): Tor's, or publishing this ID's,
/// now rather than when it is due. The countdown beside it is redrawn
/// every second.
pub(super) fn retry_button(ui: &mut Ui, model: &Model, actions: &mut Vec<Action>) {
    if model.tor_retry.is_none() {
        return;
    }
    ui.ctx().request_repaint_after(Duration::from_secs(1));
    if Button::new(Kind::Secondary, RETRY)
        .icon(Icon::ArrowRight)
        .small()
        .show(ui)
        .clicked()
    {
        actions.push(Action::RetryTor);
    }
}

/// The retry button's words.
pub(super) const RETRY: &str = "Try again now";

/// The Tor line, in words and colour; `retry`: how long until Tornect tries
/// again by itself after Tor did not start.
pub(super) fn tor_line(
    t: &Tokens,
    tor: &TorState,
    retry: Option<Duration>,
) -> (String, egui::Color32) {
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
        TorState::Failed(why) => (
            match retry {
                Some(wait) => format!(
                    "Tor: not reachable. {why} Trying again in {}.",
                    super::super::model::wait_in_words(wait)
                ),
                None => format!("Tor: not reachable. {why}"),
            },
            t.danger_text,
        ),
    }
}

/// The hosting line, in words and colour. One label, whatever the state:
/// the promise it makes must stay true (SLICE-E E1-5). `retry`: how long
/// until publishing this ID is tried again by itself.
fn hosting_line(t: &Tokens, hosting: &Hosting, retry: Option<Duration>) -> (String, egui::Color32) {
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
        Hosting::Off(why) => (
            match retry {
                Some(wait) => format!(
                    "Incoming requests: off ({why}); trying again in {}",
                    super::super::model::wait_in_words(wait)
                ),
                None => format!("Incoming requests: off ({why})"),
            },
            t.text_muted,
        ),
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

/// The connect stepper (the redesign's §4): the four steps of the
/// connection this computer asked for, with the elapsed time, the step it is
/// on, and, when it ended without a session, why, in plain words, with Try
/// again and Back. The compare-the-code question itself is on the request
/// sheet; step 2 shows the code and points there. The dialed ID is shown,
/// never a name the host sent before pairing, and nothing of it while this
/// screen is shared.
/// The fourth step's note when the picture opens directly where it can
/// (design `direct` §3.2, Phase A; the Phase B line is keyed on
/// `INTERNET_DIRECT`).
pub(super) const OPENING_DIRECT: &str = if INTERNET_DIRECT {
    "Directly if the two computers can reach each other, otherwise relayed through Tor"
} else {
    "Directly if both computers are on the same network, otherwise relayed through Tor"
};
/// The fourth step's note when direct connections are off here (the Settings
/// switch, or a bridge in use).
pub(super) const OPENING_TOR: &str = "Relayed through Tor: private, and slower than a direct link";
/// The fourth step's note under `network.lan_only`: a session that cannot
/// connect directly ends instead of going through Tor.
pub(super) const OPENING_LAN_ONLY: &str = "Directly if both computers are on the same network, otherwise the session ends (network.lan_only)";

/// "Opening the picture" for this computer's direct-connection settings.
pub(super) fn opening_note(policy: TransportPolicy) -> &'static str {
    match policy {
        TransportPolicy::Any => OPENING_DIRECT,
        TransportPolicy::TorOnly => OPENING_TOR,
        TransportPolicy::LanOnly => OPENING_LAN_ONLY,
    }
}

fn connect_stepper(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    now: Instant,
    shared: bool,
    actions: &mut Vec<Action>,
) {
    let dial = &model.dial;
    let stage = &model.client;
    let over = matches!(stage, ClientStage::Ended(_));
    // The step the connection is on (1 ..= 4), and 5 once it is live. An
    // end that names no failure is a session's end only when one went live;
    // otherwise no step is shown as done (B25).
    let at = match stage {
        ClientStage::Idle | ClientStage::Reaching { .. } => 1,
        ClientStage::Pairing { .. } | ClientStage::Checking => 2,
        ClientStage::Asking => 3,
        ClientStage::Live(_) => 5,
        ClientStage::Ended(_) => match dial.failed {
            Some((_, step)) => step,
            None if dial.went_live => 5,
            None => 0,
        },
    };
    let failed = match stage {
        ClientStage::Ended(_) => dial.failed,
        _ => None,
    };
    let cancelled = failed.is_some_and(|(why, _)| why == Failure::Cancelled);
    ui.horizontal(|ui| {
        widgets::section_header(
            ui,
            match stage {
                ClientStage::Live(_) => "Connected",
                ClientStage::Ended(_) if failed.is_none() && dial.went_live => "The session ended",
                ClientStage::Ended(_) => "Not connected",
                _ => "Connecting to a computer",
            },
        );
        if let (Some(since), false) = (dial.since, matches!(stage, ClientStage::Ended(_))) {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let secs = now.saturating_duration_since(since).as_secs();
                ui.label(
                    RichText::new(format!("{:02}:{:02}", secs / 60, secs % 60))
                        .font(theme::font(ui.ctx(), Face::Mono, 13.0))
                        .color(t.text_muted),
                );
            });
        }
    });
    let dialed = match stage {
        ClientStage::Reaching { id } => Some(id.clone()),
        _ => dial.id.map(|id| id.display_groups()),
    };
    if let (Some(id), false) = (dialed, shared) {
        ui.label(
            RichText::new(id)
                .font(theme::font(ui.ctx(), Face::Mono, 12.0))
                .color(t.text_muted),
        );
    }
    let opening = opening_note(model.settings.direct_policy());
    // An unattended connect's own steps (§B.8.10): the password, then the
    // computer's checks, where someone there can still block (or must allow)
    // — generic, with no countdown, since the grant's policy is disclosed
    // only in the signed accept.
    let unattended_steps: [(&str, &str); 4] = [
        (
            "Reaching the computer over Tor",
            "Usually 5–30 s, up to a minute",
        ),
        (
            "Checking the password",
            "One try: nothing is tried again by itself",
        ),
        (
            "Someone at the computer can still block this, or must allow it",
            "No countdown: the computer's own settings decide",
        ),
        ("Opening the picture", opening),
    ];
    let attended_steps: [(&str, &str); 4] = [
        (
            "Reaching the computer over Tor",
            "Usually 5–30 s, up to a minute",
        ),
        (
            "Pairing: compare the code",
            if dial.paired_now || at == 2 {
                "Only the first time you connect to a computer"
            } else {
                "Paired before: no code this time"
            },
        ),
        (
            "Waiting for approval",
            "The person at the computer allows control or view only (up to 110 s)",
        ),
        ("Opening the picture", opening),
    ];
    let steps = if dial.unattended {
        unattended_steps
    } else {
        attended_steps
    };
    // While the password is checked the computer's own checks may already
    // run: both steps show as under way. Nothing is under way once over.
    let active = |n: u8| !over && (n == at || (dial.unattended && at == 2 && n == 3));
    for (n, (title, note)) in (1u8..).zip(steps) {
        let (mark, color) = if failed.is_some_and(|(_, step)| step == n) {
            (
                "✕",
                if cancelled {
                    t.text_muted
                } else {
                    t.danger_text
                },
            )
        } else if n < at || (n == 2 && at > 2 && !dial.paired_now && !dial.unattended) {
            ("✓", t.ok)
        } else if active(n) {
            ("…", t.accent_text)
        } else {
            ("·", t.text_muted)
        };
        ui.horizontal_top(|ui| {
            ui.label(
                RichText::new(format!("{mark} {n}"))
                    .font(theme::font(ui.ctx(), Face::MonoSemibold, 13.0))
                    .color(color),
            );
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(title)
                        .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                        .color(t.text_primary),
                );
                ui.label(
                    RichText::new(note)
                        .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                        .color(t.text_muted),
                );
                if active(n) {
                    match stage {
                        ClientStage::Pairing { sas } => {
                            ui.label("The computer shows a code too. The question above asks whether they match:");
                            ui.label(
                                RichText::new(sas)
                                    .font(theme::font(ui.ctx(), Face::MonoSemibold, SAS_SIZE))
                                    .extra_letter_spacing(2.0)
                                    .color(t.accent_text),
                            );
                        }
                        ClientStage::Idle
                        | ClientStage::Reaching { .. }
                        | ClientStage::Asking
                        | ClientStage::Checking => {
                            ui.spinner();
                        }
                        _ => {}
                    }
                }
            });
        });
    }
    match (stage, failed) {
        (ClientStage::Live(viewing), _) => {
            ui.horizontal_top(|ui| {
                let icon = if viewing.control {
                    Icon::MousePointer
                } else {
                    Icon::Eye
                };
                icons::show(ui, icon, 16.0, t.ok);
                // The level only from the signed accept (§B.2.1); an
                // unattended session's badge says so (§B.8.10).
                let level = if viewing.unattended {
                    crate::ua_client::badge(viewing.control, viewing.administrator)
                } else {
                    match (viewing.control, viewing.administrator) {
                        (true, true) => "Control · administrator",
                        (true, false) => "control",
                        (false, _) => "view only",
                    }
                };
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "Connected{} ({level}): the picture is in its own window.",
                            if shared {
                                String::new()
                            } else {
                                format!(" to \"{}\"", viewing.host)
                            },
                        ))
                        .color(t.ok),
                    )
                    .wrap(),
                );
            });
            if let Some(lines) = &model.ua_live {
                if let Some(summary) = &lines.fail_summary {
                    ui.label(RichText::new(summary).color(t.warn));
                }
                if lines.withheld {
                    ui.add(
                        egui::Label::new(
                            RichText::new(if shared {
                                "Administrator access unavailable at the computer: the session \
                                 runs without it."
                                    .to_owned()
                            } else {
                                format!(
                                    "Administrator access unavailable at \"{}\": the session \
                                     runs without it.",
                                    viewing.host
                                )
                            })
                            .color(t.warn),
                        )
                        .wrap(),
                    );
                }
            }
            if Button::new(Kind::Danger, "End the session")
                .show(ui)
                .clicked()
            {
                actions.push(Action::EndViewing);
            }
        }
        (ClientStage::Ended(why), failed) => {
            if let Some((failure, _)) = failed {
                ui.label(
                    RichText::new(failure.title())
                        .font(theme::font(ui.ctx(), Face::Semibold, 15.0))
                        .color(if cancelled {
                            t.text_primary
                        } else {
                            t.danger_text
                        }),
                );
                ui.add(
                    egui::Label::new(RichText::new(failure.advice()).color(t.text_secondary))
                        .wrap(),
                );
            }
            // The stage's own words, unless they name the computer while this
            // screen is shared.
            if !shared {
                ui.add(egui::Label::new(RichText::new(why).small().color(t.text_muted)).wrap());
            }
            ui.horizontal(|ui| {
                let blocked = dial.id.is_some_and(|id| model.setup_changed.contains(&id));
                if let (Some(id), true) = (dial.id, blocked) {
                    if Button::new(Kind::Secondary, "I read this")
                        .show(ui)
                        .clicked()
                    {
                        actions.push(Action::ConfirmSetupChanged(id));
                    }
                } else if let Some(id) = dial.id.filter(|_| model.tor.is_ready())
                    && Button::new(Kind::Primary, "Try again")
                        .icon(Icon::ArrowRight)
                        .show(ui)
                        .clicked()
                {
                    // One attempt per explicit action: an unattended try
                    // again opens the prompt again.
                    actions.push(if dial.unattended {
                        Action::AskPassword(id)
                    } else {
                        Action::Connect(id)
                    });
                }
                if Button::new(Kind::Secondary, "Back").show(ui).clicked() {
                    actions.push(Action::DismissConnect);
                }
            });
        }
        _ => {
            if Button::new(Kind::Secondary, "Cancel").show(ui).clicked() {
                actions.push(Action::EndViewing);
            }
        }
    }
}

/// "Saved computers": the most recently seen few, each with Connect, and a
/// way to the address book; or how a computer gets there.
fn saved(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    let book = &model.book;
    ui.horizontal(|ui| {
        widgets::section_header(ui, "Saved computers");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if Button::new(Kind::Ghost, "Open address book")
                .icon(Icon::BookUser)
                .small()
                .show(ui)
                .clicked()
            {
                form.page = Page::AddressBook;
            }
        });
    });
    if book.computers.is_empty() {
        widgets::card_frame(t, 14, Margin::symmetric(20, 16)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new("No saved computers yet")
                    .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                    .color(t.text_primary),
            );
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Connect to one by its ID above: the first time, both screens show a \
                         6-digit code, and once the codes match it is saved here. The address \
                         book can also keep an ID before the first connection.",
                    )
                    .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                    .color(t.text_secondary),
                )
                .wrap(),
            );
        });
        return;
    }
    let idle = matches!(model.client, ClientStage::Idle | ClientStage::Ended(_));
    let ready = model.tor.is_ready() && idle;
    let width = ui.available_width();
    let columns = if width >= 600.0 { SAVED_SHOWN } else { 1 };
    let card_width = ((width - GAP * (columns - 1) as f32) / columns as f32).floor();
    for row in book
        .computers
        .iter()
        .take(SAVED_SHOWN)
        .collect::<Vec<_>>()
        .chunks(columns)
    {
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = GAP;
            for computer in row {
                ui.allocate_ui_with_layout(
                    vec2(card_width, 0.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        saved_card(ui, t, model, form, computer, (ready, now), actions);
                    },
                );
            }
        });
        ui.add_space(8.0);
    }
}

/// One saved computer: its name, the start of its ID, when it was last
/// connected, and Connect. After a link brought the window to Home, its
/// actions wait until they have been in view, still, for a second (L-1,
/// [`Form::link_row_armed`]).
fn saved_card(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    form: &mut Form,
    computer: &Computer,
    (ready, now): (bool, Instant),
    actions: &mut Vec<Action>,
) {
    widgets::card_frame(t, 14, Margin::symmetric(16, 14)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            let (tile, _) = ui.allocate_exact_size(vec2(36.0, 36.0), egui::Sense::hover());
            ui.painter()
                .rect_filled(tile, 10, theme::tint(t.accent_fill, 0.16));
            icons::paint(ui, tile.center(), Icon::Laptop, 18.0, t.accent_text);
            ui.vertical(|ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(computer.title())
                            .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                            .color(t.text_primary),
                    )
                    .truncate(),
                );
                ui.label(
                    RichText::new(format!("{}…", computer.id.short()))
                        .font(theme::font(ui.ctx(), Face::Mono, 12.0))
                        .color(t.text_muted),
                );
            });
        });
        let when = match (computer.last_seen, computer.paired) {
            (Some(day), _) => format!("Last connected {}", day_in_sentence(day, model.book.today)),
            (None, Some(_)) => "Paired".to_owned(),
            (None, None) => "Saved · not paired yet".to_owned(),
        };
        ui.label(
            RichText::new(when)
                .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                .color(t.text_secondary),
        );
        ui.horizontal_wrapped(|ui| {
            let ready = ready && form.link_row_armed(ui, LinkRow::Saved(computer.id), now);
            host_actions(ui, model, computer, ready, true, actions);
        });
    });
}

/// A saved computer's connect actions (§B.8.10): **Connect** — without
/// asking, the password prompt first — is the first action once an
/// unattended session there worked, **Knock** (the person there allows)
/// otherwise; with `ask`, a paired computer's card also offers to connect
/// without asking before that (the address book offers it lower down).
/// Connect waits while its setup-changed warning is unread.
pub(super) fn host_actions(
    ui: &mut Ui,
    model: &Model,
    computer: &Computer,
    ready: bool,
    small: bool,
    actions: &mut Vec<Action>,
) {
    host_actions_with(ui, model, computer, ready, small, true, actions);
}

/// [`host_actions`], saying whether to offer "Connect without asking" here.
pub(super) fn host_actions_with(
    ui: &mut Ui,
    model: &Model,
    computer: &Computer,
    ready: bool,
    small: bool,
    ask: bool,
    actions: &mut Vec<Action>,
) {
    let id = computer.id;
    let paired = computer.paired.is_some();
    let blocked = model.setup_changed.contains(&id);
    let button = |kind, text| {
        let b = Button::new(kind, text);
        if small { b.small() } else { b }
    };
    if paired && computer.unattended.worked_before {
        if button(Kind::Primary, "Connect")
            .icon(Icon::ArrowRight)
            .enabled(ready && !blocked)
            .show(ui)
            .clicked()
        {
            actions.push(Action::AskPassword(id));
        }
        if button(Kind::Secondary, "Knock")
            .enabled(ready)
            .show(ui)
            .clicked()
        {
            actions.push(Action::Connect(id));
        }
    } else {
        if button(Kind::Primary, "Knock")
            .icon(Icon::ArrowRight)
            .enabled(ready)
            .show(ui)
            .clicked()
        {
            actions.push(Action::Connect(id));
        }
        if ask
            && paired
            && Button::new(Kind::Ghost, "Connect without asking")
                .small()
                .enabled(ready && !blocked)
                .show(ui)
                .clicked()
        {
            actions.push(Action::AskPassword(id));
        }
    }
}

/// "Recent": the last few connections from the history (days only), or
/// that none is kept.
fn recent(ui: &mut Ui, t: &Tokens, model: &Model) {
    let book = &model.book;
    ui.horizontal(|ui| {
        widgets::section_header(ui, "Recent");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new("Kept only on this computer")
                    .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                    .color(t.text_muted),
            );
        });
    });
    widgets::card_frame(t, 14, Margin::symmetric(16, 10)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        if book.recent.is_empty() {
            ui.label(
                RichText::new(if book.history {
                    "No connections yet."
                } else {
                    "History is off: no list of recent connections is kept."
                })
                .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                .color(t.text_muted),
            );
            return;
        }
        for (id, day) in book.recent.iter().take(RECENT_SHOWN) {
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
            });
        }
    });
}
