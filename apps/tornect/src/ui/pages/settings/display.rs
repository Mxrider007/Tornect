//! Settings, Display and quality: how the stream window opens for a new
//! session (the picture fitted or at its own size, in the toolbar's own
//! words; full screen or not; when the toolbar hides; whether it shows the
//! badge), each from the next session on. What this computer sends when it
//! is shared is fixed in this version.

use egui::{RichText, Ui};
use tornect_core::config::{Picture, ToolbarHides, Viewer};

use super::super::super::model::{Model, SettingsChange};
use super::super::super::theme::{self, Face};
use super::super::super::view::Action;
use super::super::super::widgets;
use super::line;

/// The picture's sizes, as the toolbar names them.
pub(in super::super) const PICTURES: [(Picture, &str); 2] =
    [(Picture::Fit, "Fit"), (Picture::OneToOne, "1:1")];

/// When the toolbar hides.
pub(in super::super) const HIDES: [(ToolbarHides, &str); 3] = [
    (ToolbarHides::After2_5s, "After 2.5 s"),
    (ToolbarHides::After5s, "After 5 s"),
    (ToolbarHides::Never, "Never"),
];

/// The switch that opens sessions full screen.
pub(in super::super) const FULLSCREEN: &str = "Open sessions in fullscreen";

/// The switch that shows the badge.
pub(in super::super) const BADGE: &str = "Show frame rate and route in the toolbar";

/// What this computer sends when it is shared.
pub(in super::super) const HOST_RATE: &str =
    "The frame rate this computer sends when it is shared is fixed in this version.";

/// What is not offered yet.
pub(in super::super) const QUALITY_LATER: &str = "Quality choices come later.";

/// Under the choices: when they take effect.
pub(in super::super) const NEXT_SESSION: &str = "Applies to the next session you open.";

/// The Display and quality section.
pub(super) fn section(ui: &mut Ui, model: &Model, shared: bool, actions: &mut Vec<Action>) {
    let t = theme::tokens(ui.ctx());
    let stored = model.settings.viewer;
    widgets::section_header(ui, "When you view another computer");
    if shared {
        super::super::hidden_card(ui, super::WRITES_HIDDEN);
    } else {
        let mut chosen = None;
        ui.add_space(6.0);
        caption(ui, "Picture size");
        let names = PICTURES.map(|(_, name)| name);
        let now = PICTURES
            .iter()
            .position(|(p, _)| *p == stored.picture)
            .unwrap_or(0);
        let mut index = now;
        widgets::segmented(ui, &mut index, &names);
        if index != now
            && let Some((picture, _)) = PICTURES.get(index)
        {
            chosen = Some(Viewer {
                picture: *picture,
                ..stored
            });
        }
        ui.add_space(10.0);
        let mut on = stored.fullscreen_at_open;
        if switch(ui, &mut on, FULLSCREEN) {
            chosen = Some(Viewer {
                fullscreen_at_open: on,
                ..stored
            });
        }
        ui.add_space(10.0);
        caption(ui, "Hide the toolbar");
        let names = HIDES.map(|(_, name)| name);
        let now = HIDES
            .iter()
            .position(|(h, _)| *h == stored.toolbar_hides)
            .unwrap_or(0);
        let mut index = now;
        widgets::segmented(ui, &mut index, &names);
        if index != now
            && let Some((hides, _)) = HIDES.get(index)
        {
            chosen = Some(Viewer {
                toolbar_hides: *hides,
                ..stored
            });
        }
        ui.add_space(10.0);
        let mut on = stored.show_badge;
        if switch(ui, &mut on, BADGE) {
            chosen = Some(Viewer {
                show_badge: on,
                ..stored
            });
        }
        if let Some(viewer) = chosen {
            actions.push(Action::SaveSettings(SettingsChange::Viewer(viewer)));
        }
        ui.add_space(6.0);
        line(ui, NEXT_SESSION, t.text_secondary);
        if let Some(problem) = model.settings.problem {
            line(ui, problem, t.danger_text);
        }
    }
    ui.add_space(20.0);
    widgets::section_header(ui, "When this computer is shared");
    line(ui, HOST_RATE, t.text_secondary);
    line(ui, QUALITY_LATER, t.text_muted);
}

/// A control's name above it.
fn caption(ui: &mut Ui, text: &str) {
    let t = theme::tokens(ui.ctx());
    ui.label(
        RichText::new(text)
            .font(theme::font(ui.ctx(), Face::Medium, 14.0))
            .color(t.text_primary),
    );
}

/// A switch with its name beside it; whether it was flipped.
fn switch(ui: &mut Ui, on: &mut bool, name: &str) -> bool {
    let t = theme::tokens(ui.ctx());
    ui.horizontal(|ui| {
        let flipped = widgets::toggle(ui, on, name).clicked();
        ui.label(
            RichText::new(name)
                .font(theme::font(ui.ctx(), Face::Medium, 14.0))
                .color(t.text_primary),
        );
        flipped
    })
    .inner
}
