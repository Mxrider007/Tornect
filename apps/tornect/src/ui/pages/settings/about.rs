//! Settings, About: the version, the protocol, the licence, where the
//! third-party licences are, that Tornect never checks for updates, and the
//! diagnostics report (`crate::diagnostics`: it names nobody), which "Copy
//! report" copies as it is shown. Nothing here reaches the network.

use egui::{RichText, Ui};

use super::super::super::model::Model;
use super::super::super::theme::{self, Face};
use super::super::super::view::Action;
use super::super::super::widgets::{self, Button, Kind};
use super::line;

/// Where the licences of the code Tornect includes are.
pub(in super::super) const LICENCES: &str = "The licences of the code Tornect includes from \
    others are in THIRD_PARTY_LICENSES.txt, beside the program in each release.";

/// That nothing checks for updates.
pub(in super::super) const NO_UPDATES: &str = "Tornect never checks for updates by itself.";

/// Under the diagnostics report.
pub(in super::super) const REVIEW: &str = "Review it before you share it.";

/// The About section.
pub(super) fn section(ui: &mut Ui, model: &Model, actions: &mut Vec<Action>) {
    let t = theme::tokens(ui.ctx());
    widgets::section_header(ui, "Tornect");
    for fact in [
        format!("Version {}", tornect_core::VERSION),
        format!("Protocol {}", tornect_core::PROTOCOL_VERSION),
        "GPL-3.0-or-later".to_owned(),
    ] {
        line(ui, &fact, t.text_secondary);
    }
    line(ui, LICENCES, t.text_secondary);
    line(ui, NO_UPDATES, t.text_secondary);

    ui.add_space(20.0);
    widgets::section_header(ui, "Diagnostics");
    widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(
            RichText::new(if model.diagnostics.is_empty() {
                "…"
            } else {
                model.diagnostics.as_str()
            })
            .font(theme::font(ui.ctx(), Face::Mono, 12.0))
            .color(t.text_primary),
        );
    });
    ui.add_space(6.0);
    line(ui, REVIEW, t.text_muted);
    ui.add_space(4.0);
    if Button::new(Kind::Secondary, "Copy report")
        .enabled(!model.diagnostics.is_empty())
        .show(ui)
        .clicked()
    {
        actions.push(Action::Copy(model.diagnostics.clone()));
    }
}
