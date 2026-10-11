//! Settings, Connection: the Tor status, how Tornect reaches the Tor
//! network (automatic, direct only, obfs4 bridges, Snowflake), private
//! bridge lines and the proof-of-work defence; each applies the next time
//! Tornect starts (the configuration is read once). A private line is never
//! shown in a message, logged or put into a picture of this screen: a line
//! that does not parse is named by its number only, and while this screen
//! is shared the lines give way to the hidden card.

use egui::{RichText, Ui};
use tornect_core::config::BridgeMode;
use tornect_signal::tor::Ladder;

use super::super::super::model::{BridgeLines, Model, SettingsChange, TorChoice};
use super::super::super::theme::{self, Face};
use super::super::super::view::Action;
use super::super::super::widgets::{self, Button, Kind};
use super::{SettingsForm, line};

/// The ways to reach Tor, as the page names them.
pub(in super::super) const MODES: [(BridgeMode, &str); 4] = [
    (BridgeMode::Auto, "Automatic"),
    (BridgeMode::Off, "Tor without bridges"),
    (BridgeMode::Obfs4, "obfs4 bridges"),
    (BridgeMode::Snowflake, "Snowflake"),
];

/// When the way to Tor and the bridge lines apply.
pub(in super::super) const NEXT_START: &str = "Applies the next time Tornect starts.";

/// How a bad bridge line is named.
pub(in super::super) const BY_NUMBER: &str =
    "A line that does not parse is reported by its line number only.";

/// The proof-of-work defence's switch.
pub(in super::super) const POW: &str = "Proof-of-work defence";

/// When the defence applies.
pub(in super::super) const POW_NEXT_START: &str = "Takes effect the next time Tornect starts.";

/// The M2 note.
pub(in super::super) const NO_DIRECT: &str = "Direct connections are not available yet.";

/// The line under the field for each line that does not parse.
#[must_use]
pub(in super::super) fn bad_line(n: usize) -> String {
    format!("Line {n} does not parse.")
}

/// The Connection section.
pub(super) fn section(
    ui: &mut Ui,
    model: &Model,
    form: &mut SettingsForm,
    shared: bool,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    let stored = &model.settings.tor;
    let (status, color) = super::super::home::tor_line(t, &model.tor);
    widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(
            RichText::new(status)
                .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                .color(color),
        );
    });
    ui.add_space(16.0);
    widgets::section_header(ui, "How to reach Tor");
    if shared {
        super::super::hidden_card(ui, super::WRITES_HIDDEN);
    } else {
        let names = MODES.map(|(_, name)| name);
        let now = MODES
            .iter()
            .position(|(mode, _)| *mode == stored.bridges)
            .unwrap_or(0);
        let mut index = now;
        widgets::segmented(ui, &mut index, &names);
        if index != now
            && let Some((mode, _)) = MODES.get(index)
        {
            actions.push(Action::SaveSettings(SettingsChange::Tor(TorChoice {
                bridges: *mode,
                ..stored.clone()
            })));
        }
        line(ui, NEXT_START, t.text_muted);

        ui.add_space(16.0);
        widgets::section_header(ui, "Private bridges");
        line(ui, BY_NUMBER, t.text_secondary);
        let draft = form
            .bridge_lines
            .get_or_insert_with(|| stored.bridge_lines.0.join("\n"));
        ui.add(
            egui::TextEdit::multiline(draft)
                .font(theme::font(ui.ctx(), Face::Mono, 12.0))
                .desired_rows(3)
                .desired_width(ui.available_width()),
        );
        let lines: Vec<String> = draft.lines().map(str::to_owned).collect();
        let rejected = Ladder::rejected_lines(&lines);
        for n in &rejected {
            line(ui, &bad_line(*n), t.danger_text);
        }
        let changed = lines != stored.bridge_lines.0;
        if Button::new(Kind::Primary, "Save")
            .enabled(changed && rejected.is_empty())
            .show(ui)
            .clicked()
        {
            actions.push(Action::SaveSettings(SettingsChange::Tor(TorChoice {
                bridge_lines: BridgeLines(
                    lines.into_iter().filter(|l| !l.trim().is_empty()).collect(),
                ),
                ..stored.clone()
            })));
            form.bridge_lines = None;
        }

        ui.add_space(16.0);
        ui.horizontal(|ui| {
            let mut on = stored.pow_defense;
            if widgets::toggle(ui, &mut on, POW).clicked() {
                actions.push(Action::SaveSettings(SettingsChange::Tor(TorChoice {
                    pow_defense: on,
                    ..stored.clone()
                })));
            }
            ui.label(
                RichText::new(POW)
                    .font(theme::font(ui.ctx(), Face::Medium, 14.0))
                    .color(t.text_primary),
            );
        });
        line(ui, POW_NEXT_START, t.text_muted);
        if let Some(problem) = model.settings.problem {
            line(ui, problem, t.danger_text);
        }
    }
    ui.add_space(20.0);
    line(ui, NO_DIRECT, t.text_secondary);
}
