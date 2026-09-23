//! The screens (`docs/UI_PLAN.md` §5–§8), drawn from a [`Model`] alone. What
//! the user asks for comes back as [`Action`]s; nothing here touches the
//! network, a store or a channel.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use egui::{Color32, RichText};
use tornect_core::TornectId;
use tornect_signal::pairing::{PairDecision, SessionDecision};

use super::model::{
    ClientStage, Confirm, Hosting, Model, Popup, PopupKind, Setup, Sharing, TorState, Viewing,
};

/// The design system's few colours (`docs/UI_PLAN.md` §7).
mod palette {
    use egui::Color32;
    pub const ACCENT: Color32 = Color32::from_rgb(0x7d, 0x5c, 0xff);
    pub const OK: Color32 = Color32::from_rgb(0x3d, 0xdc, 0x97);
    pub const WARN: Color32 = Color32::from_rgb(0xff, 0xb4, 0x54);
    pub const SHARING: Color32 = Color32::from_rgb(0xff, 0x5c, 0x6c);
    pub const MUTED: Color32 = Color32::from_rgb(0x9a, 0xa7, 0xb4);
}

/// The SAS display size (§7: "SAS display 44 mono").
const SAS_SIZE: f32 = 44.0;

/// What the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Connect to this Tornect ID.
    Connect(TornectId),
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
    },
    /// The host user's answer to a session popup.
    Session {
        /// The popup.
        id: u64,
        /// The answer.
        decision: SessionDecision,
    },
    /// The client user's answer to the code question.
    Confirm {
        /// The question.
        id: u64,
        /// The codes matched.
        matched: bool,
    },
    /// Copy this machine's ID.
    CopyId,
}

/// What the user is typing.
#[derive(Debug, Default)]
pub struct Form {
    /// The connect field.
    pub connect_to: String,
    /// The label typed into each pairing popup.
    pub labels: HashMap<u64, String>,
}

fn countdown(deadline: Instant, now: Instant) -> u64 {
    deadline.saturating_duration_since(now).as_secs()
}

fn clock(since: Instant, now: Instant) -> String {
    let secs = now.saturating_duration_since(since).as_secs();
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

/// The main window: the sharing banner, the home screen, and the popups.
pub fn main_window(
    ui: &mut egui::Ui,
    model: &Model,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    if !model.sharing.is_empty() {
        egui::Panel::top("sharing")
            .frame(
                egui::Frame::new()
                    .fill(palette::SHARING)
                    .inner_margin(egui::Margin::symmetric(12, 8)),
            )
            .show(ui, |ui| {
                for sharing in &model.sharing {
                    sharing_banner(ui, sharing, now, actions);
                }
            });
    }
    // A label typed into a question that is gone goes with it.
    form.labels
        .retain(|id, _| model.popups.iter().any(|p| p.id == *id));
    egui::CentralPanel::default().show(ui, |ui| {
        egui::ScrollArea::vertical().show(ui, |ui| {
            // Open questions come first, one card each, so none hides
            // another's buttons.
            for popup in &model.popups {
                question(ui, |ui| host_popup(ui, popup, form, now, actions));
            }
            if let Some(confirm) = &model.confirm {
                question(ui, |ui| confirm_popup(ui, confirm, now, actions));
            }
            home(ui, model, form, actions);
        });
    });
    // Countdowns and the banner's clock move once a second.
    if !model.popups.is_empty() || model.confirm.is_some() || !model.sharing.is_empty() {
        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
}

/// A question card: framed in the accent colour, above everything else.
fn question(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::group(ui.style())
        .stroke(egui::Stroke::new(2.0, palette::ACCENT))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
    ui.add_space(8.0);
}

/// §6.3: "Sharing with `name` · 12:41 · End", for as long as a session runs.
fn sharing_banner(ui: &mut egui::Ui, sharing: &Sharing, now: Instant, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        let mode = if sharing.control {
            "can see and control this screen"
        } else {
            "can see this screen (view only)"
        };
        ui.label(
            RichText::new(format!("SHARING  \"{}\" {mode}", sharing.label))
                .strong()
                .color(Color32::WHITE),
        );
        ui.label(
            RichText::new(clock(sharing.since, now))
                .monospace()
                .color(Color32::WHITE),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button(RichText::new("Stop sharing").strong()).clicked() {
                actions.push(Action::StopSharing);
            }
        });
    });
    if sharing.capture.is_none() {
        ui.label(
            RichText::new("starting: the viewer's picture has not gone out yet")
                .small()
                .color(Color32::WHITE),
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
            .color(Color32::WHITE),
        );
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
    // Text is not selectable here: a press on it moves the window instead.
    ui.style_mut().interaction.selectable_labels = false;
    egui::CentralPanel::no_frame()
        .frame(
            egui::Frame::new()
                .fill(palette::SHARING)
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
                if ui.button(RichText::new("Stop").strong()).clicked() {
                    actions.push(Action::StopSharing);
                }
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    for s in sharing {
                        let mode = if s.control { "control" } else { "view only" };
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "SHARING  \"{}\" · {mode} · {}",
                                    s.label,
                                    clock(s.since, now)
                                ))
                                .strong()
                                .color(Color32::WHITE),
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
                            egui::Label::new(RichText::new(detail).small().color(Color32::WHITE))
                                .truncate(),
                        );
                    }
                });
            });
        });
    // The clock moves once a second.
    ui.ctx().request_repaint_after(Duration::from_millis(500));
}

fn home(ui: &mut egui::Ui, model: &Model, form: &mut Form, actions: &mut Vec<Action>) {
    ui.add_space(4.0);
    ui.heading("Tornect");
    ui.add_space(8.0);

    ui.label(RichText::new("Your Tornect ID").color(palette::MUTED));
    match &model.id {
        Some(id) => {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(id).monospace().size(15.0));
                if ui.small_button("Copy").clicked() {
                    actions.push(Action::CopyId);
                }
            });
        }
        None => {
            ui.label("(not created yet)");
        }
    }
    ui.add_space(6.0);
    tor_line(ui, &model.tor);
    hosting_line(ui, &model.hosting);

    if let Some(setup) = &model.setup {
        ui.add_space(10.0);
        setup_card(ui, setup, !model.sharing.is_empty(), actions);
    }

    ui.add_space(12.0);
    ui.separator();
    ui.label(RichText::new("Connect to another computer").strong());
    let idle = matches!(model.client, ClientStage::Idle | ClientStage::Ended(_));
    let parsed = form.connect_to.trim().parse::<TornectId>();
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut form.connect_to)
                .hint_text("its Tornect ID (56 characters, .onion optional)")
                .desired_width(ui.available_width() - 90.0)
                .font(egui::TextStyle::Monospace),
        );
        let ready = model.tor.is_ready() && idle && parsed.is_ok();
        if ui
            .add_enabled(ready, egui::Button::new("Connect"))
            .clicked()
            && let Ok(id) = &parsed
        {
            actions.push(Action::Connect(*id));
        }
    });
    if !form.connect_to.trim().is_empty() && parsed.is_err() {
        ui.label(RichText::new("That is not a Tornect ID.").color(palette::WARN));
    } else if !model.tor.is_ready() {
        ui.label(RichText::new("Connecting waits for Tor.").color(palette::MUTED));
    }
    client_stage(ui, &model.client, actions);

    if !model.events.is_empty() {
        ui.add_space(12.0);
        ui.separator();
        ui.label(RichText::new("Recent").color(palette::MUTED));
        for line in model.events.iter().rev() {
            ui.label(RichText::new(line).small());
        }
    }
}

fn tor_line(ui: &mut egui::Ui, tor: &TorState) {
    let (text, color) = match tor {
        TorState::Starting => ("Tor: starting…".to_owned(), palette::MUTED),
        TorState::Trying { via, attempt, of } => (
            format!("Tor: connecting via {via} ({attempt}/{of})…"),
            palette::MUTED,
        ),
        TorState::Progress { via, pct, blocked } => match blocked {
            Some(why) => (
                format!("Tor: {pct}% via {via}; stuck: {why}"),
                palette::WARN,
            ),
            None => (format!("Tor: connecting via {via}, {pct}%"), palette::MUTED),
        },
        TorState::Ready { via } => (format!("Tor: connected via {via}"), palette::OK),
        TorState::Failed(why) => (format!("Tor: not reachable ({why})"), palette::SHARING),
    };
    ui.label(RichText::new(text).color(color));
}

fn hosting_line(ui: &mut egui::Ui, hosting: &Hosting) {
    let (text, color) = match hosting {
        Hosting::Waiting => (
            "Incoming requests: waiting for Tor".to_owned(),
            palette::MUTED,
        ),
        Hosting::Publishing => (
            "Incoming requests: publishing this ID (the first time can take two minutes)…"
                .to_owned(),
            palette::MUTED,
        ),
        Hosting::Published {
            reachable: true, ..
        } => (
            "Incoming requests: reachable; you are asked before anyone sees this screen".to_owned(),
            palette::OK,
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
            palette::WARN,
        ),
        Hosting::Off(why) => (format!("Incoming requests: off ({why})"), palette::MUTED),
    };
    ui.label(RichText::new(text).color(color));
}

/// The first-run desktop grant (UI_PLAN §6.4's Wayland step, as the operator
/// decided on 2026-09-23): the dialog on the owner's own desktop, now, rather
/// than inside a viewer's wait.
fn setup_card(ui: &mut egui::Ui, setup: &Setup, sharing: bool, actions: &mut Vec<Action>) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.label(RichText::new("Screen sharing on this desktop").strong());
        if setup.granted {
            ui.label(
                RichText::new(
                    "Granted and remembered: a session starts without the desktop's dialog.",
                )
                .color(palette::OK),
            );
        } else {
            ui.label(
                "Not granted yet. Grant it now, while you are here: the desktop asks once, and \
                 later sessions never wait on its dialog. Turn on \"Allow Remote Interaction\" \
                 in the dialog to let viewers you allow use the keyboard and mouse.",
            );
            ui.label(
                RichText::new(
                    "Without it, the desktop asks when a viewer's picture starts, and someone \
                     here must answer within 30 s.",
                )
                .small()
                .color(palette::MUTED),
            );
        }
        ui.horizontal(|ui| {
            let label = if setup.granted {
                "Grant again"
            } else {
                "Grant screen sharing"
            };
            if ui
                .add_enabled(!setup.busy && !sharing, egui::Button::new(label))
                .clicked()
            {
                actions.push(Action::Grant);
            }
            if setup.granted
                && ui
                    .add_enabled(!setup.busy, egui::Button::new("Revoke"))
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
                "To revoke by hand, delete {} (`tornect doctor` names it too); the desktop then \
                 asks again at the next session.",
                setup.token_file.display()
            ))
            .small()
            .color(palette::MUTED),
        );
        if let Some(note) = &setup.note {
            ui.label(RichText::new(note).small());
        }
    });
}

fn client_stage(ui: &mut egui::Ui, stage: &ClientStage, actions: &mut Vec<Action>) {
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
                    .monospace()
                    .size(SAS_SIZE)
                    .color(palette::ACCENT),
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
            ui.label(
                RichText::new(format!(
                    "Connected to \"{}\" ({}): the picture is in its own window.",
                    viewing.host,
                    if viewing.control {
                        "control"
                    } else {
                        "view only"
                    }
                ))
                .color(palette::OK),
            );
            if ui.button("End the session").clicked() {
                actions.push(Action::EndViewing);
            }
        }
        ClientStage::Ended(why) => {
            ui.label(RichText::new(why).color(palette::MUTED));
        }
    }
}

fn host_popup(
    ui: &mut egui::Ui,
    popup: &Popup,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    let left = countdown(popup.deadline, now);
    let title = match popup.kind {
        PopupKind::Pairing { .. } => "Pairing request",
        PopupKind::Session { .. } => "Session request",
    };
    ui.label(RichText::new(title).heading().color(palette::ACCENT));
    ui.push_id(("popup", popup.id), |ui| match &popup.kind {
        PopupKind::Pairing {
            name,
            fingerprint,
            sas,
            pinned,
        } => {
            match pinned {
                Some(label) => ui.label(format!(
                    "A device ALREADY PAIRED as \"{label}\" asks to pair again. Refusing \
                         does not unpair it."
                )),
                None => ui.label(format!(
                    "A device calling itself \"{name}\" asks to pair with this computer."
                )),
            };
            ui.label(
                RichText::new(format!("device fingerprint {fingerprint}"))
                    .small()
                    .monospace(),
            );
            ui.add_space(6.0);
            ui.label("Code:");
            ui.label(
                RichText::new(sas)
                    .monospace()
                    .size(SAS_SIZE)
                    .color(palette::ACCENT),
            );
            ui.label(
                "The other device shows a code too. Pair only if the numbers match on both \
                     screens; if they differ, refuse: something between you changed them.",
            );
            let label = form.labels.entry(popup.id).or_default();
            ui.horizontal(|ui| {
                ui.label("Name it (optional):");
                ui.text_edit_singleline(label);
            });
            ui.horizontal(|ui| {
                if ui
                    .button(RichText::new("The codes match: pair").strong())
                    .clicked()
                {
                    let label = label.trim();
                    actions.push(Action::Pair {
                        id: popup.id,
                        decision: PairDecision::Accept {
                            label: (!label.is_empty()).then(|| label.to_owned()),
                        },
                    });
                }
                if ui.button("Refuse").clicked() {
                    actions.push(Action::Pair {
                        id: popup.id,
                        decision: PairDecision::Reject,
                    });
                }
            });
            ui.label(
                RichText::new(format!("Refused automatically in {left} s"))
                    .small()
                    .color(palette::MUTED),
            );
        }
        PopupKind::Session { label, fingerprint } => {
            ui.label(
                RichText::new(format!("\"{label}\" wants to see this screen."))
                    .strong()
                    .size(16.0),
            );
            ui.label(
                RichText::new(format!("device fingerprint {fingerprint}"))
                    .small()
                    .monospace(),
            );
            ui.add_space(4.0);
            ui.label(
                "Allow control also lets it use this computer's keyboard and mouse. View \
                     only shows the screen and nothing else. Either way it lasts for this \
                     session only, and \"Stop sharing\" ends it.",
            );
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Allow control").strong()).clicked() {
                    actions.push(Action::Session {
                        id: popup.id,
                        decision: SessionDecision::AllowOnce,
                    });
                }
                if ui.button("View only").clicked() {
                    actions.push(Action::Session {
                        id: popup.id,
                        decision: SessionDecision::AllowOnceViewOnly,
                    });
                }
                if ui.button("Deny").clicked() {
                    actions.push(Action::Session {
                        id: popup.id,
                        decision: SessionDecision::Deny,
                    });
                }
            });
            ui.label(
                RichText::new(format!("Denied automatically in {left} s"))
                    .small()
                    .color(palette::MUTED),
            );
        }
    });
}

fn confirm_popup(ui: &mut egui::Ui, confirm: &Confirm, now: Instant, actions: &mut Vec<Action>) {
    ui.label(
        RichText::new("Compare the code")
            .heading()
            .color(palette::ACCENT),
    );
    ui.push_id(("confirm", confirm.id), |ui| {
        ui.label(format!(
            "The host accepted; it calls itself \"{}\". Did its screen show this code?",
            confirm.host_name
        ));
        ui.label(
            RichText::new(&confirm.sas)
                .monospace()
                .size(SAS_SIZE)
                .color(palette::ACCENT),
        );
        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("Yes, the codes match").strong())
                .clicked()
            {
                actions.push(Action::Confirm {
                    id: confirm.id,
                    matched: true,
                });
            }
            if ui.button("No").clicked() {
                actions.push(Action::Confirm {
                    id: confirm.id,
                    matched: false,
                });
            }
        });
        ui.label(
            RichText::new(format!(
                "Refused automatically in {} s",
                countdown(confirm.deadline, now)
            ))
            .small()
            .color(palette::MUTED),
        );
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
    egui::Panel::top("stream-bar").show(ui, |ui| {
        ui.horizontal(|ui| match viewing {
            Some(v) => {
                ui.label(RichText::new(&v.host).strong());
                let (mode, color) = if v.control {
                    ("control", palette::OK)
                } else {
                    ("view only", palette::MUTED)
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
                        .color(palette::WARN),
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
                            RichText::new("Waiting for the first picture…").color(palette::MUTED),
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
            deadline: now + Duration::from_secs(50),
        });
        model.sharing = vec![Sharing {
            session_id: "0011".to_owned(),
            label: "Laptop".to_owned(),
            control: true,
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
}
