//! Settings, Display and quality: the picture quality this computer asks
//! for when it views another (the quality design §3.4; a session's toolbar
//! changes it for that session) and how the stream window opens for a new
//! session (the picture fitted or at its own size, in the toolbar's own
//! words; full screen or not; when the toolbar hides; whether it shows the
//! badge), each from the next session on. When this computer is shared, the
//! person viewing it chooses the quality, within the limits of
//! `config.toml`'s `[media]`.

use egui::{RichText, Ui};
use tornect_core::config::{Picture, QualityPreset, ToolbarHides, Viewer};

use super::super::super::model::{Model, SettingsChange};
use super::super::super::theme::{self, Face};
use super::super::super::view::Action;
use super::super::super::widgets;
use super::line;

/// The presets, as the toolbar's Quality menu names them.
pub(in super::super) const QUALITIES: [(QualityPreset, &str); 3] = [
    (
        QualityPreset::BestQuality,
        super::super::viewer::quality_name(QualityPreset::BestQuality),
    ),
    (
        QualityPreset::Balanced,
        super::super::viewer::quality_name(QualityPreset::Balanced),
    ),
    (
        QualityPreset::BestPerformance,
        super::super::viewer::quality_name(QualityPreset::BestPerformance),
    ),
];

/// Under the presets: where a session changes it.
pub(in super::super) const QUALITY_HINT: &str =
    "Change it during a session from the toolbar's Quality menu.";

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

/// Who chooses the quality when this computer is shared.
pub(in super::super) const HOST_QUALITY: &str =
    "The person viewing this computer chooses the picture quality.";

/// Where the limits of what this computer sends are set.
pub(in super::super) const HOST_LIMITS: &str =
    "Limits for what this computer sends are in config.toml, [media].";

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
        caption(ui, "Picture quality");
        let names = QUALITIES.map(|(_, name)| name);
        let now = QUALITIES
            .iter()
            .position(|(q, _)| *q == stored.quality)
            .unwrap_or(1);
        let mut index = now;
        widgets::segmented(ui, &mut index, &names);
        if index != now
            && let Some((quality, _)) = QUALITIES.get(index)
        {
            chosen = Some(Viewer {
                quality: *quality,
                ..stored
            });
        }
        line(ui, QUALITY_HINT, t.text_muted);
        ui.add_space(10.0);
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
    line(ui, HOST_QUALITY, t.text_secondary);
    line(ui, HOST_LIMITS, t.text_muted);
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
