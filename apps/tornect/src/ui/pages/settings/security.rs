//! Settings, Security: unattended access as this computer's own guard last
//! read it (§B.8.7.3): whether it is on, off or paused, the devices that can
//! connect without asking and what is known of each, and the readiness rows
//! (§B.8.7.1 ⑥); then the desktop's screen-sharing grant and how to stop
//! every session. The tokio side reads all of it by itself, so opening the
//! section asks for nothing. Its controls are deny-direction (§B.8.6.2):
//! each sends one operation that the window host's guard runs, and the
//! section changes only when the guard's answer is read back. A pause is
//! offered only while none runs, so no choice can end one sooner. While this
//! screen may be in a picture that leaves it, Turn off, the pause and Revoke
//! all stay (naming no device and no number) and the devices give way to the
//! hidden card. A window without the guard (no host role here, a store that
//! did not open, another Tornect holding it) says so and offers no control.
//! "Turn on for a device…" opens the grant wizard in the section's place
//! (`wizard`), offered while a paired device has no unattended access and
//! never while this screen is shared.

use egui::{RichText, Ui};
use tornect_core::DeviceId;
use tornect_core::address_book::Day;
use tornect_core::session_log::Actor;
use tornect_core::unattended::readiness::{Probe, row_title};

use super::super::super::model::{
    GrantRow, HostSetting, Manager, ManagerOp, Model, PauseEnd, Setup,
};
use super::super::super::theme::{self, Face, Tokens};
use super::super::super::view::Action;
use super::super::super::widgets::{self, Button, Kind, Tone};
use super::{SettingsForm, line};

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

/// Master off.
pub(in super::super) const TURN_OFF: &str = "Turn off";

/// Master on, which asks for the password and shows a new stop code once.
pub(in super::super) const TURN_ON: &str = "Turn on";

/// The stop code card's heading (§B.8.7.4).
pub(in super::super) const STOP_HEADING: &str = "Emergency stop code";

/// What the stop code does.
pub(in super::super) const STOP_DOES: &str = "Typed at another of your devices, it turns \
    unattended access off here and removes every grant.";

/// Under the stop code (§B.8.7.4, as the command line says it).
pub(in super::super) const WRITE_IT_DOWN: &str =
    "Write it down now: Tornect does not show it again and keeps no copy.";

/// The click that delivers the stop code.
pub(in super::super) const WRITTEN_DOWN: &str = "I have written it down";

/// A host setting as it is to be, given its switch's new state.
pub(in super::super) type SettingOf = fn(bool) -> HostSetting;

/// The host settings kept in the store, as their switches name them.
pub(in super::super) const SETTINGS: [(&str, SettingOf); 3] = [
    ("Keep this computer awake", HostSetting::KeepAwake),
    (
        "Prevent idle lock while unattended access is on",
        HostSetting::PreventIdleLock,
    ),
    ("Notify me of each unattended session", HostSetting::Notify),
];

/// The pause's ends, offered only while no pause runs (§B.8.6.2: 12 h and
/// until re-enabled; the end at 08:00 waits for the operator's ruling, as
/// this version keeps no time zone of the computer).
pub(in super::super) const PAUSE_ENDS: [(PauseEnd, &str); 2] = [
    (PauseEnd::TwelveHours, "For 12 hours"),
    (PauseEnd::UntilOn, "Until I turn it back on"),
];

/// Revoke all, which asks first.
pub(in super::super) const REVOKE_ALL: &str = "Revoke all…";

/// Revoke all's question while this screen is shared: no number.
pub(in super::super) const REVOKE_ALL_SHARED: &str = "Remove unattended access for every device?";

/// The answer of Revoke all's question that removes.
pub(in super::super) const REMOVE: &str = "Remove";

/// An operation of a device's row, given the device.
pub(in super::super) type RowOp = fn(DeviceId) -> ManagerOp;

/// What a row's button does.
#[derive(Debug, Clone, Copy)]
pub(in super::super) enum RowAction {
    /// Send this deny-direction operation for the row's device.
    Send(RowOp),
    /// Open *Change password* for the row's grant (the wizard's ④ alone).
    ChangePassword,
    /// Open *Change mode* for the row's grant.
    ChangeMode,
}

/// A row's buttons (§B.8.7.3): its deny-direction operations, then *Change
/// password…* and *Change mode…*, which open their step in the section's
/// place (each change asks for the password where it gives access).
pub(in super::super) const ROW_OPS: [(&str, RowAction); 6] = [
    ("Suspend", RowAction::Send(ManagerOp::Suspend)),
    ("Disable", RowAction::Send(ManagerOp::Disable)),
    ("Revoke unattended", RowAction::Send(ManagerOp::Revoke)),
    ("Remove device", RowAction::Send(ManagerOp::Remove)),
    ("Change password…", RowAction::ChangePassword),
    ("Change mode…", RowAction::ChangeMode),
];

/// How to end every session at once.
pub(in super::super) const STOP_LINE: &str = "To end every session now: Stop in the sharing \
    bar, or tornect panic in a terminal.";

/// Rotate ID, which asks first.
pub(in super::super) const ROTATE: &str = "Rotate ID…";

/// The word Rotate ID's dialog asks for.
pub(in super::super) const ROTATE_WORD: &str = "ROTATE";

/// Rotate ID's dialog, naming the devices whose access it removes.
#[must_use]
pub(in super::super) fn rotate_question(labels: &[&str]) -> String {
    let named = if labels.is_empty() {
        "no device".to_owned()
    } else {
        labels.join(", ")
    };
    format!(
        "This makes a new Tornect ID. Every pairing stops working, and unattended access is \
         removed for: {named}. Type ROTATE to go on. Tornect closes when it is done; start it \
         again to use the new ID."
    )
}

/// Revoke all's question naming how many devices lose their access.
#[must_use]
pub(in super::super) fn revoke_all_question(devices: usize) -> String {
    match devices {
        1 => "Remove unattended access for 1 device?".to_owned(),
        n => format!("Remove unattended access for all {n} devices?"),
    }
}

/// The Security section.
pub(super) fn section(
    ui: &mut Ui,
    model: &Model,
    form: &mut SettingsForm,
    shared: bool,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    widgets::section_header(ui, "Unattended access");
    let Some(manager) = &model.manager else {
        form.wizard = None;
        line(ui, NO_GUARD, t.text_secondary);
        stopping(ui, t);
        return;
    };
    if shared {
        // A picture that leaves this screen never shows the wizard, and its
        // passwords go with it.
        form.wizard = None;
    }
    if form.wizard.is_some() {
        super::wizard::draw(ui, model, manager, form, actions);
        return;
    }
    super::wizard::forget_fields(ui.ctx(), true);
    let (tone, state) = header(manager, Day::today());
    ui.add_space(4.0);
    widgets::chip(ui, tone, true, &state);
    ui.add_space(10.0);
    // The one stop-code card: never while this screen is shared or a sheet
    // is up (kept until the click, drawn again after).
    let sheet = !model.popups.is_empty() || model.confirm.is_some();
    if let Some(code) = model.stop_card.as_ref().filter(|_| !shared && !sheet) {
        stop_card(ui, t, &code.0, actions);
        ui.add_space(10.0);
    }
    if !shared && (!manager.on || manager.paused_until.is_some()) {
        if Button::new(Kind::Primary, TURN_ON)
            .small()
            .enabled(!model.manager_busy)
            .show(ui)
            .clicked()
        {
            actions.push(Action::Manager(ManagerOp::On));
        }
        ui.add_space(6.0);
    }
    header_controls(ui, manager, form, shared, actions);
    if let Some(note) = model.manager_note {
        line(ui, note, t.danger_text);
    }
    ui.add_space(12.0);
    if shared {
        // How many devices there are, and which, is hidden with the
        // address book; their operations go with them.
        super::super::hidden_card(ui, super::WRITES_HIDDEN);
    } else if manager.grants.is_empty() {
        line(ui, NO_DEVICE, t.text_secondary);
    } else {
        for row in &manager.grants {
            grant_row(ui, t, row, model.manager_busy, form, actions);
            ui.add_space(8.0);
        }
    }
    if !shared {
        match model.wizard.offer {
            Some(true) => {
                if Button::new(Kind::Secondary, super::wizard::OPEN)
                    .small()
                    .show(ui)
                    .clicked()
                {
                    form.wizard = Some(super::wizard::Wizard::new());
                    actions.push(Action::Manager(ManagerOp::WizardDevices));
                }
            }
            Some(false) => line(ui, super::wizard::NO_DEVICE, t.text_secondary),
            None => {}
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
    if !shared {
        ui.add_space(20.0);
        widgets::section_header(ui, "While unattended access is on");
        ui.add_enabled_ui(!model.manager_busy, |ui| {
            let now = [
                manager.keep_awake,
                manager.prevent_idle_lock,
                manager.notify,
            ];
            for ((label, setting), was) in SETTINGS.into_iter().zip(now) {
                ui.horizontal(|ui| {
                    let mut on = was;
                    if widgets::toggle(ui, &mut on, label).changed() {
                        actions.push(Action::Manager(ManagerOp::Setting(setting(on))));
                    }
                    ui.label(label);
                });
            }
        });
    }
    if let Some(setup) = &model.setup {
        ui.add_space(20.0);
        screen_sharing(ui, t, setup, !model.sharing.is_empty(), shared, actions);
    }
    stopping(ui, t);
    if shared {
        form.rotate = None;
    } else {
        rotate(ui, t, manager, form, actions);
    }
}

/// Rotate ID (§B.8.12): its dialog names the devices whose unattended access
/// it removes and asks for the typed word, Cancel first; no password (it
/// removes access, it gives none). Not offered while this screen is shared.
fn rotate(
    ui: &mut Ui,
    t: &Tokens,
    manager: &Manager,
    form: &mut SettingsForm,
    actions: &mut Vec<Action>,
) {
    ui.add_space(20.0);
    widgets::section_header(ui, "Rotate ID");
    let Some(typed) = &mut form.rotate else {
        if Button::new(Kind::Danger, ROTATE).small().show(ui).clicked() {
            form.rotate = Some(String::new());
        }
        return;
    };
    let labels: Vec<&str> = manager.grants.iter().map(|g| g.label.as_str()).collect();
    line(ui, &rotate_question(&labels), t.text_primary);
    ui.add_space(6.0);
    widgets::text_field(ui, typed, ROTATE_WORD, true, 160.0);
    let ready = typed.trim() == ROTATE_WORD;
    let mut done = false;
    ui.horizontal(|ui| {
        if Button::new(Kind::Secondary, "Cancel")
            .small()
            .show(ui)
            .clicked()
        {
            done = true;
        }
        if Button::new(Kind::Danger, "Rotate ID")
            .small()
            .enabled(ready)
            .show(ui)
            .clicked()
            && ready
        {
            actions.push(Action::Manager(ManagerOp::RotateId));
            done = true;
        }
    });
    if done {
        form.rotate = None;
    }
}

/// Turn off and the pause's ends while unattended access is on (the ends
/// only while no pause runs), and Revoke all with its question: while this
/// screen is shared too, naming no device and no number.
fn header_controls(
    ui: &mut Ui,
    manager: &Manager,
    form: &mut SettingsForm,
    shared: bool,
    actions: &mut Vec<Action>,
) {
    if manager.on {
        ui.horizontal_wrapped(|ui| {
            if Button::new(Kind::Secondary, TURN_OFF)
                .small()
                .show(ui)
                .clicked()
            {
                actions.push(Action::Manager(ManagerOp::Off));
            }
            if manager.paused_until.is_none() {
                ui.label("Pause:");
                for (end, label) in PAUSE_ENDS {
                    if Button::new(Kind::Secondary, label)
                        .small()
                        .show(ui)
                        .clicked()
                    {
                        actions.push(Action::Manager(ManagerOp::Pause(end)));
                    }
                }
            }
        });
        ui.add_space(6.0);
    }
    if !shared && manager.grants.is_empty() {
        form.revoke_all = false;
        return;
    }
    if form.revoke_all {
        let question = if shared {
            REVOKE_ALL_SHARED.to_owned()
        } else {
            revoke_all_question(manager.grants.len())
        };
        ui.label(question);
        ui.horizontal(|ui| {
            if Button::new(Kind::Secondary, "Cancel")
                .small()
                .show(ui)
                .clicked()
            {
                form.revoke_all = false;
            }
            if Button::new(Kind::Danger, REMOVE).small().show(ui).clicked() {
                actions.push(Action::Manager(ManagerOp::RevokeAll));
                form.revoke_all = false;
            }
        });
    } else if Button::new(Kind::Danger, REVOKE_ALL)
        .small()
        .show(ui)
        .clicked()
    {
        form.revoke_all = true;
    }
}

/// The desktop's screen-sharing grant (§B.2.1's first-run step): its state,
/// granting again and revoking through the step's own commands, which act
/// only while the step exists. While this screen is shared, only the state.
fn screen_sharing(
    ui: &mut Ui,
    t: &Tokens,
    setup: &Setup,
    sharing: bool,
    shared: bool,
    actions: &mut Vec<Action>,
) {
    widgets::section_header(ui, "Screen sharing on this desktop");
    if setup.granted {
        line(
            ui,
            "Granted and remembered: a session starts without the desktop's dialog.",
            t.ok,
        );
    } else {
        line(ui, "Not granted yet.", t.text_secondary);
    }
    if shared {
        return;
    }
    ui.horizontal(|ui| {
        let label = if setup.granted {
            "Grant again"
        } else {
            "Grant screen sharing"
        };
        if Button::new(Kind::Secondary, label)
            .small()
            .enabled(!setup.busy && !sharing)
            .show(ui)
            .clicked()
        {
            actions.push(Action::Grant);
        }
        if setup.granted
            && Button::new(Kind::Secondary, "Revoke")
                .small()
                .enabled(!setup.busy)
                .show(ui)
                .clicked()
        {
            actions.push(Action::Revoke);
        }
    });
    if let Some(note) = &setup.note {
        line(ui, note, t.text_secondary);
    }
}

/// How every session ends at once (§B.6), and that the panic key's state is
/// its readiness row.
fn stopping(ui: &mut Ui, t: &Tokens) {
    ui.add_space(20.0);
    widgets::section_header(ui, "Stopping a session");
    line(ui, STOP_LINE, t.text_secondary);
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
/// last unlock (§B.8.7.3), and its operations.
fn grant_row(
    ui: &mut Ui,
    t: &Tokens,
    row: &GrantRow,
    busy: bool,
    form: &mut SettingsForm,
    actions: &mut Vec<Action>,
) {
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
        ui.horizontal_wrapped(|ui| {
            // What the state lets come back, each asking for the password.
            let (kind, _) = row
                .state
                .split_once(':')
                .unwrap_or((row.state.as_str(), ""));
            let back: Option<(&str, RowOp)> = match kind {
                "disabled" => Some(("Enable", ManagerOp::Enable)),
                "locked" | "hard_locked" => Some(("Unlock", ManagerOp::Unlock)),
                "suspended" => Some(("Resume", ManagerOp::Resume)),
                _ => None,
            };
            if let Some((label, op)) = back
                && Button::new(Kind::Primary, label)
                    .small()
                    .enabled(!busy)
                    .show(ui)
                    .clicked()
            {
                actions.push(Action::Manager(op(row.device)));
            }
            for (label, action) in ROW_OPS {
                if Button::new(Kind::Secondary, label)
                    .small()
                    .show(ui)
                    .clicked()
                {
                    match action {
                        RowAction::Send(op) => actions.push(Action::Manager(op(row.device))),
                        RowAction::ChangePassword => {
                            let w = super::wizard::Wizard::change_password(
                                row.device,
                                row.label.clone(),
                            );
                            // The guard's preview of the change: whether its
                            // password can only be generated.
                            if let Some(choice) = w.change_choice() {
                                actions.push(Action::Manager(ManagerOp::Preview(Box::new(choice))));
                            }
                            form.wizard = Some(w);
                        }
                        RowAction::ChangeMode => {
                            form.wizard = Some(super::wizard::Wizard::change_mode(
                                row.device,
                                row.label.clone(),
                            ));
                        }
                    }
                }
            }
        });
    });
}

/// The one card of a new stop code: what it does, the code as text that
/// cannot be selected or copied, that it is shown once, and the click that
/// delivers it (§B.8.7.4).
fn stop_card(ui: &mut Ui, t: &Tokens, code: &str, actions: &mut Vec<Action>) {
    widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(
            RichText::new(STOP_HEADING)
                .font(theme::font(ui.ctx(), Face::Semibold, 15.0))
                .color(t.text_primary),
        );
        line(ui, STOP_DOES, t.text_secondary);
        ui.add_space(6.0);
        ui.add(
            egui::Label::new(
                RichText::new(code)
                    .font(theme::font(ui.ctx(), Face::Mono, 20.0))
                    .color(t.text_primary),
            )
            .selectable(false),
        );
        ui.add_space(6.0);
        line(ui, WRITE_IT_DOWN, t.warn);
        if Button::new(Kind::Primary, WRITTEN_DOWN).show(ui).clicked() {
            actions.push(Action::Manager(ManagerOp::StopCodeWrittenDown));
        }
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
