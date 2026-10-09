//! Settings, Privacy: what others learn of this computer, the history
//! switch (the address book's Recent tab keeps its own: one setting, two
//! switches), what is kept on this computer and for how long, the session
//! log and where screenshots go. Places are named in words, never by a path:
//! a path under the home names the account.

use egui::{RichText, Ui};

use super::super::super::icons::Icon;
use super::super::super::model::Model;
use super::super::super::nav::Page;
use super::super::super::theme::{self, Face};
use super::super::super::view::{Action, Form};
use super::super::super::widgets::{self, Button, Kind};
use super::general::NAME_NOTE;
use super::line;

/// What every computer and device this one meets learns, beside the name.
pub(in super::super) const NETWORK_LINE: &str = "Your IP address stays hidden: every session is \
    relayed through Tor. Tornect has no accounts, no telemetry and no update checks, and it \
    checks whether a saved computer is reachable only when you click \"Check if reachable\".";

/// What the history switch governs, and what it does not (§B.6).
pub(in super::super) const LOG_RECORDS: &str = "Connection attempts to this computer, and the \
    unattended connections and admin commands of this device, are always recorded in the session \
    log; the history switch governs only the address book's recent list.";

/// What this device keeps of its unattended access to other computers
/// (Part C row 10).
pub(in super::super) const UNATTENDED_KEPT: &str = "For each computer you connect to unattended, \
    this device keeps whether a password is remembered and whether your access there is control \
    or reaches administrator access; Forget removes it.";

/// The Privacy page's link to the Sessions page.
pub(in super::super) const PAST_SESSIONS: &str = "Show past sessions";

/// The session log, as §B.6's history paragraph names it.
pub(in super::super) const LOG_KEPT: &str =
    "The session log is the log of your unattended connections, always kept, never sent.";

/// Where screenshots of a remote screen go.
pub(in super::super) const SCREENSHOTS: &str =
    "Screenshots are saved in Pictures/Tornect, named by the date and time.";

/// What is kept on this computer, and for how long.
pub(in super::super) const STORED: [(&str, &str); 4] = [
    ("Saved computers", "until you forget them"),
    (
        "Recent connections",
        "until you clear them; none are added while history is off",
    ),
    (
        "Devices that can connect here",
        "the devices that paired with this computer",
    ),
    ("Your ID and keys, Tor state", "needed to keep the same ID"),
];

/// The history switch's name, the same as the Recent tab's.
const KEEP_HISTORY: &str = "Keep a list of recent connections";

/// The Privacy section.
pub(super) fn section(
    ui: &mut Ui,
    model: &Model,
    form: &mut Form,
    shared: bool,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    widgets::section_header(ui, "What others learn");
    ui.label(
        RichText::new(format!(
            "The name \u{201c}{}\u{201d}",
            model.settings.device_name
        ))
        .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
        .color(t.text_primary),
    );
    line(ui, NAME_NOTE, t.text_secondary);
    ui.add_space(4.0);
    line(ui, NETWORK_LINE, t.text_secondary);

    ui.add_space(20.0);
    widgets::section_header(ui, "History on this computer");
    if shared {
        super::super::hidden_card(ui, super::WRITES_HIDDEN);
    } else {
        ui.horizontal(|ui| {
            let mut on = model.book.history;
            if widgets::toggle(ui, &mut on, KEEP_HISTORY).clicked() {
                actions.push(Action::SetHistory(on));
            }
            ui.label(
                RichText::new(KEEP_HISTORY)
                    .font(theme::font(ui.ctx(), Face::Medium, 14.0))
                    .color(t.text_primary),
            );
        });
        ui.add_space(6.0);
        if Button::new(Kind::Danger, "Clear history")
            .icon(Icon::Trash)
            .small()
            .show(ui)
            .clicked()
        {
            actions.push(Action::ClearHistory);
        }
    }
    line(ui, LOG_RECORDS, t.text_secondary);

    ui.add_space(20.0);
    widgets::section_header(ui, "Stored only on this computer");
    for (what, how_long) in STORED {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(what)
                    .font(theme::font(ui.ctx(), Face::Medium, 13.0))
                    .color(t.text_primary),
            );
            ui.label(
                RichText::new(how_long)
                    .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                    .color(t.text_muted),
            );
        });
    }
    ui.add_space(4.0);
    line(ui, UNATTENDED_KEPT, t.text_secondary);

    ui.add_space(20.0);
    widgets::section_header(ui, "Session log");
    line(ui, LOG_KEPT, t.text_secondary);
    // The past sessions, on their own page (hidden there while shared).
    if !shared
        && Button::new(Kind::Ghost, PAST_SESSIONS)
            .small()
            .show(ui)
            .clicked()
    {
        form.page = Page::Sessions;
    }

    ui.add_space(20.0);
    widgets::section_header(ui, "Screenshots");
    line(ui, SCREENSHOTS, t.text_secondary);
}
