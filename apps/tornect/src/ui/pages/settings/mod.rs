//! The Settings page (the redesign's §4): the sections built so far, each
//! drawn from the model alone. None of them offers an operation of
//! §B.8.6.2: a change goes to the tokio side as one
//! [`Action::SaveSettings`], which saves `config.toml`. Opening the page or a
//! section asks for nothing. While this screen may be in a picture that
//! leaves it, every control that writes gives way to the hidden card, and
//! what the sections say stays.

pub(super) mod general;

use egui::{RichText, Ui};

use super::super::model::Model;
use super::super::theme::{self, Face};
use super::super::view::{Action, Form};
use super::super::widgets;

/// A section of the Settings page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Section {
    /// The name others see and the theme.
    #[default]
    General,
}

impl Section {
    /// The sections the page lists, in the redesign's order: only those
    /// built.
    pub const LISTED: [Self; 1] = [Self::General];

    /// The section's name in the list.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::General => "General",
        }
    }
}

/// What the Settings page remembers from pass to pass.
#[derive(Debug, Default)]
pub struct SettingsForm {
    /// The section shown.
    pub(super) section: Section,
    /// The name others see as typed so far, while it is being changed.
    pub(super) name: Option<String>,
}

/// What a section shows in place of the controls that write while this
/// screen is shared.
pub(super) const WRITES_HIDDEN: &str = "You can change these settings again when sharing ends.";

/// The Settings page: its title, the list of its sections, the section
/// chosen.
pub(super) fn page(
    ui: &mut Ui,
    model: &Model,
    form: &mut Form,
    shared: bool,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    ui.label(
        RichText::new("Settings")
            .font(theme::font(ui.ctx(), Face::Bold, 26.0))
            .color(t.text_primary),
    );
    ui.add_space(10.0);
    let names: Vec<&str> = Section::LISTED.iter().map(|s| s.title()).collect();
    let mut index = Section::LISTED
        .iter()
        .position(|s| *s == form.settings.section)
        .unwrap_or(0);
    widgets::segmented(ui, &mut index, &names);
    form.settings.section = Section::LISTED.get(index).copied().unwrap_or_default();
    ui.add_space(18.0);
    match form.settings.section {
        Section::General => general::section(ui, model, &mut form.settings, shared, actions),
    }
}

/// A line of a section, wrapped, in `color`.
fn line(ui: &mut Ui, text: &str, color: egui::Color32) {
    ui.add(
        egui::Label::new(
            RichText::new(text)
                .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                .color(color),
        )
        .wrap(),
    );
}
