//! The Settings page (the redesign's §4): the sections built so far, each
//! drawn from the model alone. None of them offers an operation of
//! §B.8.6.2: a change goes to the tokio side as one
//! [`Action::SaveSettings`], which saves `config.toml`, and Security shows
//! unattended access as the window's guard last read it, changing nothing.
//! Opening the page or a section asks for nothing. While this screen may be
//! in a picture that leaves it, every control that writes gives way to the
//! hidden card, and what the sections say stays.

pub(super) mod about;
pub(super) mod connection;
pub(super) mod display;
pub(super) mod general;
pub(super) mod privacy;
pub(super) mod security;
pub(super) mod sharing;
pub(super) mod wizard;

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
    /// How Tornect reaches the Tor network.
    Connection,
    /// Unattended access: its state, the devices, the readiness rows.
    Security,
    /// What someone connected here may use beside the picture and input,
    /// and whether this computer offers its clipboard when it views.
    Sharing,
    /// How the stream window opens.
    Display,
    /// What others learn, what is kept here, the history switch.
    Privacy,
    /// The version, the licences and the diagnostics report.
    About,
}

impl Section {
    /// The sections the page lists, in the redesign's order: only those
    /// built.
    pub const LISTED: [Self; 7] = [
        Self::General,
        Self::Connection,
        Self::Security,
        Self::Sharing,
        Self::Display,
        Self::Privacy,
        Self::About,
    ];

    /// The section's name in the list where the page is `narrow` (below
    /// [`NARROW_BELOW`] points): shorter there, so the list fits.
    #[must_use]
    pub fn label(self, narrow: bool) -> &'static str {
        match (self, narrow) {
            (Self::Display, true) => "Display",
            _ => self.title(),
        }
    }

    /// The section's name in the list.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::General => "General",
            Self::Connection => "Connection",
            Self::Security => "Security",
            Self::Sharing => "Sharing",
            Self::Display => "Display and quality",
            Self::Privacy => "Privacy",
            Self::About => "About",
        }
    }
}

/// What the Settings page remembers from pass to pass.
#[derive(Default)]
pub struct SettingsForm {
    /// The section shown.
    pub(super) section: Section,
    /// The name others see as typed so far, while it is being changed.
    pub(super) name: Option<String>,
    /// The private bridge lines as typed so far.
    pub(super) bridge_lines: Option<String>,
    /// Security's "Revoke all…" asks its question.
    pub(super) revoke_all: bool,
    /// General's start at sign-in says what it means before it acts.
    pub(super) sign_in_asking: bool,
    /// Rotate ID's dialog is open, with the word typed so far.
    pub(super) rotate: Option<String>,
    /// The grant wizard is open, at its step, with what it chose so far.
    pub(super) wizard: Option<wizard::Wizard>,
    /// How many times the wizard's *Turn on* was pressed in this window: each
    /// press names its answer by its number.
    pub(super) attempts: u64,
    /// A press whose wizard closed before its answer came: its Done can
    /// still open ⑤a's offer (§B.8.7.1, decision M1-67) the next time
    /// Security is drawn.
    pub(super) pending: Option<u64>,
}

/// Printed with the private bridge lines typed so far as their count only:
/// a bridge's address never reaches a log or a panic message.
impl std::fmt::Debug for SettingsForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingsForm")
            .field("section", &self.section)
            .field("name", &self.name)
            .field(
                "bridge_lines",
                &self
                    .bridge_lines
                    .as_ref()
                    .map(|typed| typed.lines().count()),
            )
            .field("revoke_all", &self.revoke_all)
            .field("sign_in_asking", &self.sign_in_asking)
            .field("rotate", &self.rotate)
            .field("wizard", &self.wizard)
            .field("attempts", &self.attempts)
            .field("pending", &self.pending)
            .finish()
    }
}

impl SettingsForm {
    /// Close the grant wizard: what it chose goes, its passwords are wiped
    /// and its fields' state leaves `ctx`'s memory (the window left
    /// Settings, Security). A press of it still waiting for its answer is
    /// kept in `pending`.
    pub fn close_wizard(&mut self, ctx: &egui::Context) {
        if let Some(w) = self.wizard.take()
            && let Some(attempt) = w.attempt
            && w.step != wizard::Step::Offer
        {
            self.pending = Some(attempt);
        }
        wizard::forget_fields(ctx, true);
    }

    /// Whether the grant wizard is open: a `tornect:` link then leaves the
    /// window on Settings (design `invite` §2.4), so that a wizard in
    /// progress is never closed and its passwords never wiped.
    #[must_use]
    pub fn wizard_open(&self) -> bool {
        self.wizard.is_some()
    }
}

/// Below this page width (points) the section list uses its short names.
const NARROW_BELOW: f32 = 600.0;

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
    let narrow = ui.available_width() < NARROW_BELOW;
    // Where the page is narrow, the list takes two rows, so that every
    // name fits.
    let listed = Section::LISTED;
    let rows: Vec<&[Section]> = if narrow {
        let (first, second) = listed.split_at(3);
        vec![first, second]
    } else {
        vec![&listed[..]]
    };
    for (i, row) in rows.into_iter().enumerate() {
        if i > 0 {
            ui.add_space(6.0);
        }
        let names: Vec<&str> = row.iter().map(|s| s.label(narrow)).collect();
        // No segment of a row is selected when the section is in the other.
        let mut index = row
            .iter()
            .position(|s| *s == form.settings.section)
            .unwrap_or(usize::MAX);
        widgets::segmented(ui, &mut index, &names);
        if let Some(section) = row.get(index) {
            form.settings.section = *section;
        }
    }
    ui.add_space(18.0);
    if form.settings.section != Section::Security {
        form.settings.close_wizard(ui.ctx());
    }
    match form.settings.section {
        Section::General => general::section(ui, model, &mut form.settings, shared, actions),
        Section::Connection => {
            connection::section(ui, model, &mut form.settings, shared, actions);
        }
        Section::Security => {
            security::section(ui, model, &mut form.settings, shared, actions);
        }
        Section::Sharing => sharing::section(ui, model, shared, actions),
        Section::Display => display::section(ui, model, shared, actions),
        Section::Privacy => privacy::section(ui, model, form, shared, actions),
        Section::About => about::section(ui, model, actions),
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

#[cfg(test)]
mod tests {
    use super::SettingsForm;

    /// The form prints the private bridge lines typed so far as their count,
    /// never a line.
    #[test]
    fn the_form_prints_no_bridge_line() {
        let form = SettingsForm {
            bridge_lines: Some(
                "obfs4 192.0.2.7:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA \
                 iat-mode=0\nobfs4 198.51.100.9:80 FEDCBA9876543210FEDCBA9876543210FEDCBA98 \
                 cert=BBBB iat-mode=0"
                    .to_owned(),
            ),
            ..SettingsForm::default()
        };
        let printed = format!("{form:?}");
        assert!(printed.contains("bridge_lines: Some(2)"), "{printed}");
        for line in ["192.0.2.7", "198.51.100.9", "obfs4", "cert="] {
            assert!(!printed.contains(line), "{line}: {printed}");
        }
    }
}
