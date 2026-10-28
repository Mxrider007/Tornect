//! Settings, General: the name others see and the theme. The name shown is
//! the saved one: the neutral default (§B.6.1) until the user chooses one,
//! never this computer's network name; a new one is sent from the next
//! start. A theme applies once it is saved.

use egui::{RichText, Ui};
use tornect_core::config::Theme;

use super::super::super::model::{ManagerOp, Model, SettingsChange};
use super::super::super::theme::{self, Face};
use super::super::super::view::Action;
use super::super::super::widgets::{self, Button, Kind};
use super::{SettingsForm, line};

/// Under "Name others see": who is sent the name, and that the default is
/// neutral.
pub(in super::super) const NAME_NOTE: &str = "Sent to every device you pair with and every \
    computer you connect to; they show it and save it. The default is neutral. Tornect never \
    sends or shows this computer's own network name.";

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

/// The switch of §B.1.1.
pub(in super::super) const SIGN_IN: &str = "Start Tornect when I sign in";

/// What the switch says before it acts, after the command line's sentence
/// on Tor (§B.1.1, as approved).
pub(in super::super) const WHILE_IT_RUNS: &str = "While Tornect runs, devices you gave unattended \
    access can connect, new devices can ask to pair, and anyone with this computer's Tornect ID \
    can see that it is online.";

/// The answer that turns the start at sign-in on, after the text.
pub(in super::super) const TURN_ON: &str = "Turn on";

/// When what starts at sign-in cannot be read or changed here.
pub(in super::super) const SIGN_IN_UNAVAILABLE: &str =
    "What starts at sign-in cannot be read on this computer.";

/// That Tornect must be closed for its install or removal (§B.1.1).
pub(in super::super) const CLOSE_FIRST: &str = "Close Tornect before installing or removing it.";

/// How to install this copy (the final audit before the release): a copy
/// that is not installed is not on `PATH`, so the command names the program
/// in its own folder. `.\tornect` runs `tornect.exe` from cmd and from
/// PowerShell alike.
pub(in super::super) const INSTALL_HOW: &str = if cfg!(windows) {
    "To install it: open a terminal in Tornect's folder and run .\\tornect install"
} else {
    "To install it: open a terminal in Tornect's folder and run ./tornect install"
};

/// The install's state and its command. Once installed, `tornect` is on
/// `PATH` (`~/.local/bin`, the Program Files copy).
#[must_use]
pub(in super::super) fn install_lines(installed: Option<bool>) -> [&'static str; 2] {
    match installed {
        Some(true) => [
            "Installed.",
            "To remove it: tornect uninstall in a terminal.",
        ],
        Some(false) => ["Not installed.", INSTALL_HOW],
        None => [
            "Whether Tornect is installed could not be read.",
            INSTALL_HOW,
        ],
    }
}

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
    ui.add_space(20.0);
    sign_in(ui, model, form, actions);
}

/// The start at sign-in (§B.1.1): the switch, as the system says it is now;
/// turning it on first says what it means, with Cancel first; then one
/// operation of the window host's guard (the same as `tornect service
/// install`), and the switch moves only on its answer. And whether Tornect
/// is installed, with the command that installs or removes it.
fn sign_in(ui: &mut Ui, model: &Model, form: &mut SettingsForm, actions: &mut Vec<Action>) {
    let t = theme::tokens(ui.ctx());
    widgets::section_header(ui, "Start at sign-in");
    ui.add_space(6.0);
    match &model.manager {
        None => {
            form.sign_in_asking = false;
            line(ui, super::security::NO_GUARD, t.text_secondary);
        }
        Some(manager) => match manager.sign_in {
            None => {
                form.sign_in_asking = false;
                line(ui, SIGN_IN_UNAVAILABLE, t.text_secondary);
            }
            Some(registered) => {
                ui.add_enabled_ui(!model.manager_busy, |ui| {
                    ui.horizontal(|ui| {
                        let mut on = registered;
                        if widgets::toggle(ui, &mut on, SIGN_IN).changed() {
                            if on {
                                form.sign_in_asking = true;
                            } else {
                                actions.push(Action::Manager(ManagerOp::SignIn(false)));
                            }
                        }
                        ui.label(SIGN_IN);
                    });
                });
                if registered {
                    form.sign_in_asking = false;
                }
                if form.sign_in_asking {
                    line(
                        ui,
                        &format!("{} {WHILE_IT_RUNS}", crate::unattended::TOR_AT_SIGN_IN),
                        t.text_primary,
                    );
                    ui.horizontal(|ui| {
                        if Button::new(Kind::Secondary, "Cancel")
                            .small()
                            .show(ui)
                            .clicked()
                        {
                            form.sign_in_asking = false;
                        }
                        if Button::new(Kind::Primary, TURN_ON)
                            .small()
                            .enabled(!model.manager_busy)
                            .show(ui)
                            .clicked()
                        {
                            actions.push(Action::Manager(ManagerOp::SignIn(true)));
                            form.sign_in_asking = false;
                        }
                    });
                }
            }
        },
    }
    if let Some(note) = model.manager_note {
        line(ui, note, t.danger_text);
    }
    ui.add_space(20.0);
    widgets::section_header(ui, "Installation");
    ui.add_space(6.0);
    for text in install_lines(model.manager.as_ref().and_then(|m| m.installed)) {
        line(ui, text, t.text_secondary);
    }
    line(ui, CLOSE_FIRST, t.text_muted);
}
