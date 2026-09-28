//! The widget gallery (`tornect gui --preview --page widgets`): every widget
//! of `widgets` in its states, for looking at them in both themes. The
//! sidebar does not list it; its controls change only this page.

use egui::{RichText, Ui};

use super::super::icons::{self, GLYPHS, Icon};
use super::super::theme::{self, Face};
use super::super::widgets::{self, Button, Kind, Tone};

/// What the gallery's controls hold, in the context's memory.
#[derive(Debug, Clone, Default)]
struct State {
    on: bool,
    choice: usize,
    text: String,
}

pub(super) fn gallery(ui: &mut Ui) {
    let t = theme::tokens(ui.ctx());
    let id = egui::Id::new("widget-gallery");
    let mut state = ui.data(|d| d.get_temp::<State>(id)).unwrap_or_default();
    widgets::page_header(
        ui,
        "Widgets",
        "The widget set of this version, in both themes.",
    );
    ui.add_space(12.0);
    widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        widgets::section_header(ui, "Buttons");
        ui.horizontal_wrapped(|ui| {
            Button::new(Kind::Primary, "Connect")
                .icon(Icon::ArrowRight)
                .show(ui);
            Button::new(Kind::Secondary, "Copy ID")
                .icon(Icon::Copy)
                .show(ui);
            Button::new(Kind::Ghost, "Later").show(ui);
            Button::new(Kind::Danger, "End the session").show(ui);
            Button::new(Kind::Primary, "Disabled")
                .enabled(false)
                .show(ui);
            Button::new(Kind::Secondary, "Small").small().show(ui);
        });
        ui.add_space(6.0);
        widgets::section_header(ui, "Chips");
        ui.horizontal_wrapped(|ui| {
            widgets::chip(ui, Tone::Ok, true, "Reachable over Tor");
            widgets::chip(ui, Tone::Warn, true, "Publishing…");
            widgets::chip(
                ui,
                Tone::Accent,
                false,
                "1 device can connect without asking",
            );
            widgets::chip(ui, Tone::Danger, true, "Not reachable");
            widgets::chip(ui, Tone::Neutral, false, "View only · 6 min");
        });
        widgets::section_header(ui, "Toggle, segmented control, text field");
        ui.horizontal(|ui| {
            widgets::toggle(ui, &mut state.on, "Example switch");
            ui.label(if state.on { "On" } else { "Off" });
            ui.add_space(16.0);
            widgets::segmented(
                ui,
                &mut state.choice,
                &["Dark", "Light", "Match the system"],
            );
        });
        widgets::text_field(ui, &mut state.text, "Paste a Tornect ID", true, 360.0);
        widgets::section_header(ui, "Navigation");
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(200.0, 80.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    widgets::nav_item(ui, Icon::House, "Selected", true, false);
                    widgets::nav_item(ui, Icon::History, "Not selected", false, false);
                },
            );
            ui.add_space(16.0);
            widgets::nav_item(ui, Icon::House, "Selected (rail)", true, true);
            widgets::nav_item(ui, Icon::BookUser, "Not selected (rail)", false, true);
        });
        widgets::section_header(ui, "Countdown ring, identicon");
        ui.horizontal(|ui| {
            for left in [1.0, 0.6, 0.15] {
                widgets::countdown_ring(ui, left, 40.0, t.accent_text);
            }
            ui.add_space(16.0);
            for fingerprint in [
                "3f2a 91c0 77de 0b14",
                "ef01 5a5a 1234 9876",
                "0b14 77de 91c0 3f2a",
            ] {
                widgets::identicon(ui, &widgets::fingerprint_bytes(fingerprint), 48.0);
            }
        });
        widgets::section_header(ui, "Icons (Lucide)");
        ui.horizontal_wrapped(|ui| {
            for (icon, _, _) in GLYPHS {
                icons::show(ui, icon, 20.0, t.text_secondary);
            }
        });
        widgets::caps_label(ui, "A caps label");
        ui.label(
            RichText::new("482 917")
                .font(theme::font(ui.ctx(), Face::MonoSemibold, 44.0))
                .extra_letter_spacing(2.0)
                .color(t.accent_text),
        );
    });
    ui.data_mut(|d| d.insert_temp(id, state));
}
