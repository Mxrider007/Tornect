//! Settings, General: the name others see and the theme. The name shown is
//! the saved one: the neutral default (§B.6.1) until the user chooses one,
//! never this computer's network name; a new one is sent from the next
//! start. A theme applies once it is saved.

use egui::{RichText, Ui};
use tornect_core::config::Theme;

use super::super::super::model::{Model, SettingsChange};
use super::super::super::theme::{self, Face};
use super::super::super::view::Action;
use super::super::super::widgets::{self, Button, Kind};
use super::{SettingsForm, line};

/// Under "Name others see": who is sent the name, and that the default is
/// neutral.
pub(in super::super) const NAME_NOTE: &str = "Sent to every device you pair with and every \
    computer you connect to; they show it and save it. The default is neutral. Tornect never \
    uses this computer's own network name.";

/// When a saved name is used.
pub(in super::super) const NEXT_START: &str = "Applies the next time Tornect starts.";

/// The theme's choices, in their order.
pub(in super::super) const THEMES: [(Theme, &str); 3] = [
    (Theme::Dark, "Dark"),
    (Theme::Light, "Light"),
    (Theme::System, "Match the system"),
];

/// The longest name `config.toml` keeps, in bytes.
pub(in super::super) const NAME_MAX: usize = 64;

/// The General section.
pub(super) fn section(
    ui: &mut Ui,
    model: &Model,
    form: &mut SettingsForm,
    shared: bool,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    let saved = &model.settings.device_name;
    widgets::section_header(ui, "Name others see");
    line(ui, NAME_NOTE, t.text_secondary);
    ui.add_space(8.0);
    if shared {
        super::super::hidden_card(ui, super::WRITES_HIDDEN);
        return;
    }
    let mut done = None;
    match &mut form.name {
        Some(name) => {
            ui.horizontal_wrapped(|ui| {
                let field = widgets::text_field(ui, name, saved, false, 260.0);
                let typed = name.trim();
                let valid = !typed.is_empty() && typed.len() <= NAME_MAX && typed != saved;
                let entered = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if Button::new(Kind::Primary, "Save")
                    .enabled(valid)
                    .show(ui)
                    .clicked()
                    || (entered && valid)
                {
                    done = Some(Some(typed.to_owned()));
                }
                if Button::new(Kind::Ghost, "Cancel").show(ui).clicked() {
                    done = Some(None);
                }
            });
        }
        None => {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!("\u{201c}{saved}\u{201d}"))
                        .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                        .color(t.text_primary),
                );
                if Button::new(Kind::Secondary, "Change")
                    .small()
                    .show(ui)
                    .clicked()
                {
                    form.name = Some(saved.clone());
                }
            });
        }
    }
    match done {
        Some(Some(name)) => {
            actions.push(Action::SaveSettings(SettingsChange::DeviceName(name)));
            form.name = None;
        }
        Some(None) => form.name = None,
        None => {}
    }
    line(ui, NEXT_START, t.text_muted);
    if let Some(problem) = model.settings.problem {
        line(ui, problem, t.danger_text);
    }
    ui.add_space(20.0);
    widgets::section_header(ui, "Theme");
    ui.add_space(6.0);
    let names = THEMES.map(|(_, name)| name);
    let chosen = THEMES
        .iter()
        .position(|(theme, _)| *theme == model.settings.theme)
        .unwrap_or(0);
    let mut index = chosen;
    widgets::segmented(ui, &mut index, &names);
    if index != chosen
        && let Some((theme, _)) = THEMES.get(index)
    {
        actions.push(Action::SaveSettings(SettingsChange::Theme(*theme)));
    }
}
