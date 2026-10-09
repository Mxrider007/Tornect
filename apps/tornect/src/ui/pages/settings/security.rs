//! Settings, Security: unattended access as this computer's own guard last
//! read it (§B.8.7.3): whether it is on, off or paused, the devices that can
//! connect without asking and what is known of each, and the readiness rows
//! (§B.8.7.1 ⑥). The tokio side reads all of it by itself, so opening the
//! section asks for nothing, and nothing here changes anything. While this
//! screen may be in a picture that leaves it, the devices give way to the
//! hidden card. A window without the guard (no host role here, a store that
//! did not open, another Tornect holding it) says so and shows nothing else.

use egui::{RichText, Ui};
use tornect_core::address_book::Day;
use tornect_core::session_log::Actor;
use tornect_core::unattended::readiness::{Probe, row_title};

use super::super::super::model::{GrantRow, Manager, Model};
use super::super::super::theme::{self, Face, Tokens};
use super::super::super::widgets::{self, Tone};
use super::line;

/// What the section says when this window has no guard.
pub(in super::super) const NO_GUARD: &str =
    "Unattended access cannot be changed from this window right now.";

/// The state line of a pause that lasts until unattended access is turned
/// back on.
pub(in super::super) const PAUSED_UNTIL_ON: &str = "Paused until turned back on";

/// Where no device can connect without asking (as `tornect unattended
/// status` says it).
pub(in super::super) const NO_DEVICE: &str = "No device can connect without asking.";

/// The readiness row of an account whose password is empty (§B.8.7.1 ⑥).
pub(in super::super) const EMPTY_PASSWORD: &str =
    "re-authentication cannot protect settings on this account";

/// The static advisory under the readiness rows (§B.8.7.1 ⑥).
pub(in super::super) const ADVISORY: &str = "Tornect cannot judge the strength of your OS \
    password; unattended access is only as safe as it.";

/// The Security section.
pub(super) fn section(ui: &mut Ui, model: &Model, shared: bool) {
    let t = theme::tokens(ui.ctx());
    widgets::section_header(ui, "Unattended access");
    let Some(manager) = &model.manager else {
        line(ui, NO_GUARD, t.text_secondary);
        return;
    };
    let (tone, state) = header(manager, Day::today());
    ui.add_space(4.0);
    widgets::chip(ui, tone, true, &state);
    ui.add_space(12.0);
    if shared {
        // How many devices there are, and which, is hidden with the
        // address book.
        super::super::hidden_card(ui, super::WRITES_HIDDEN);
    } else if manager.grants.is_empty() {
        line(ui, NO_DEVICE, t.text_secondary);
    } else {
        for row in &manager.grants {
            grant_row(ui, t, row);
            ui.add_space(8.0);
        }
    }
    ui.add_space(20.0);
    widgets::section_header(ui, "Readiness");
    for (name, probe) in &manager.readiness {
        let (tone, text) = readiness_line(name, probe);
        ui.horizontal_top(|ui| {
            widgets::dot(ui, tone);
            line(ui, &text, t.text_primary);
        });
    }
    ui.add_space(6.0);
    line(ui, ADVISORY, t.text_muted);
}

/// The header's state: on, off, or paused until when (UTC: this version
/// keeps no time zone of the computer), as of `today`.
#[must_use]
pub(in super::super) fn header(manager: &Manager, today: Day) -> (Tone, String) {
    match (manager.on, manager.paused_until) {
        (false, _) => (Tone::Neutral, "Off".to_owned()),
        (true, Some(u64::MAX)) => (Tone::Warn, PAUSED_UNTIL_ON.to_owned()),
        (true, Some(until)) => {
            let (h, m) = ((until % 86_400) / 3_600, (until % 3_600) / 60);
            let day = Day::from_unix(until);
            let when = if day == today {
                String::new()
            } else {
                format!(" {}", super::super::day_in_sentence(day, Some(today)))
            };
            (Tone::Warn, format!("Paused until {h:02}:{m:02} UTC{when}"))
        }
        (true, None) => (Tone::Ok, "On".to_owned()),
    }
}

/// One device's row: its pinned label, its state, its device words, who
/// gave it access, when it last connected and its failed attempts since the
/// last unlock (§B.8.7.3).
fn grant_row(ui: &mut Ui, t: &Tokens, row: &GrantRow) {
    widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(&row.label)
                    .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                    .color(t.text_primary),
            );
            let (tone, state) = state_text(&row.state);
            widgets::chip(ui, tone, true, &state);
        });
        if let Some(words) = row.words {
            line(
                ui,
                &format!("device words: {}", words.shown()),
                t.text_secondary,
            );
        }
        line(ui, &details(row, Day::today()), t.text_secondary);
    });
}

/// Who gave access, when the device last connected, its failed attempts.
#[must_use]
pub(in super::super) fn details(row: &GrantRow, today: Day) -> String {
    let by = match row.created_by {
        Some(Actor::Ui) => "Given in this window",
        Some(Actor::Cli) => "Given on the command line",
        Some(Actor::Import) => "Given by a backup import",
        Some(Actor::Restore) => "Given before a restore",
        None => "Given",
    };
    let last = match row.last_used {
        Some(at) => format!(
            "last connected {}",
            super::super::day_in_sentence(Day::from_unix(at), Some(today))
        ),
        None => "never connected".to_owned(),
    };
    let failures = match row.failures {
        1 => "1 failed attempt since the last unlock".to_owned(),
        n => format!("{n} failed attempts since the last unlock"),
    };
    format!("{by} · {last} · {failures}")
}

/// A grant's state as the manager says it (§B.8.7.3), from the label
/// `tornect unattended status` prints.
#[must_use]
pub(in super::super) fn state_text(label: &str) -> (Tone, String) {
    let (kind, rest) = label.split_once(':').unwrap_or((label, ""));
    match (kind, rest) {
        ("active", _) => (Tone::Ok, "Active".to_owned()),
        ("not_yet_active", _) => (Tone::Warn, "Not yet active".to_owned()),
        ("disabled", by) => (
            Tone::Neutral,
            match by {
                "ui" => "Disabled in this window",
                "cli" => "Disabled on the command line",
                "import" => "Disabled by a backup import",
                "restore" => "Disabled after a restore",
                _ => "Disabled",
            }
            .to_owned(),
        ),
        ("suspended", why) => (
            Tone::Warn,
            match why {
                "local_block" => "Suspended: blocked here",
                "panic" => "Suspended by the panic key",
                "admin" => "Suspended from another device",
                "local" => "Suspended here",
                _ => "Suspended",
            }
            .to_owned(),
        ),
        ("hard_locked", _) => (Tone::Danger, "Hard-locked".to_owned()),
        ("locked", secs) => {
            let minutes = secs.parse::<u64>().unwrap_or(0).div_ceil(60);
            (Tone::Danger, format!("Locked for {minutes} min"))
        }
        ("expired", _) => (Tone::Neutral, "Expired".to_owned()),
        _ => (Tone::Neutral, label.to_owned()),
    }
}

/// A readiness row as the section says it: its title and its state, in the
/// words `tornect unattended readiness` uses ("Panic key: bound /
/// unavailable", §B.8.7.4).
#[must_use]
pub(in super::super) fn readiness_line(name: &str, probe: &Probe) -> (Tone, String) {
    let title = row_title(name);
    match (name, probe) {
        ("panic_key", Probe::Ok) => (Tone::Ok, format!("{title}: bound")),
        ("panic_key", Probe::Fail(_) | Probe::Unknown) => {
            (Tone::Danger, format!("{title}: unavailable"))
        }
        ("os_password", Probe::Fail(_)) => (Tone::Danger, format!("{title}: {EMPTY_PASSWORD}")),
        (_, Probe::Ok) => (Tone::Ok, format!("{title}: ok")),
        (_, Probe::Warn(m)) => (Tone::Warn, format!("{title}: warning: {m}")),
        (_, Probe::Fail(m)) => (Tone::Danger, format!("{title}: FAIL: {m}")),
        (_, Probe::Unknown) => (Tone::Neutral, format!("{title}: unknown")),
    }
}
