//! Settings, Connection: the Tor status, how Tornect reaches the Tor
//! network (automatic, direct only, obfs4 bridges, Snowflake), private
//! bridge lines and the proof-of-work defence; each applies the next time
//! Tornect starts (the configuration is read once). A private line is never
//! shown in a message, logged or put into a picture of this screen: a line
//! that does not parse is named by its number only, and while this screen
//! is shared the lines give way to the hidden card. Then direct connections
//! (design `direct` §3.3): the switch and what each computer learns, and in
//! a build whose direct connections reach the internet the STUN and router
//! switches, from the next session on.

use egui::{RichText, Ui};
use tornect_core::config::BridgeMode;
use tornect_signal::tor::Ladder;

use super::super::super::model::{BridgeLines, Model, SettingsChange, TorChoice};
use super::super::super::theme::{self, Face};
use super::super::super::view::Action;
use super::super::super::widgets::{self, Button, Kind};
use super::{SettingsForm, line};

/// The ways to reach Tor, as the page names them.
pub(in super::super) const MODES: [(BridgeMode, &str); 4] = [
    (BridgeMode::Auto, "Automatic"),
    (BridgeMode::Off, "Tor without bridges"),
    (BridgeMode::Obfs4, "obfs4 bridges"),
    (BridgeMode::Snowflake, "Snowflake"),
];

/// When the way to Tor and the bridge lines apply.
pub(in super::super) const NEXT_START: &str = "Applies the next time Tornect starts.";

/// Where private bridge lines come from (the final audit before the
/// release: the built-in bridges are what Automatic already tried).
pub(in super::super) const WHERE_BRIDGES: &str = "Where Tor is blocked, get private bridge \
    lines from bridges.torproject.org; they replace the built-in bridges of their kind.";

/// How a bad bridge line is named.
pub(in super::super) const BY_NUMBER: &str =
    "A line that does not parse is reported by its line number only.";

/// The proof-of-work defence's switch.
pub(in super::super) const POW: &str = "Proof-of-work defence";

/// When the defence applies.
pub(in super::super) const POW_NEXT_START: &str = "Takes effect the next time Tornect starts.";

/// The direct connections section's header.
pub(in super::super) const DIRECT_HEADER: &str = "Direct connections";

// Design `direct` §3.3: the switch and the lines under it while it is on
// say what this build does. A build whose direct connections stay on the
// local network (Phase A, `INTERNET_DIRECT` off) uses revision 2's words;
// one that reaches the internet uses Phase B's, with the STUN and router
// switches. The page picks them by `Settings::internet`, which is the
// constant outside tests, so that both sets are drawn and tested before
// the constant flips.

/// The switch (bound to `!network.paranoid`) in a build whose direct
/// connections stay on the local network.
pub(in super::super) const DIRECT_SWITCH_LAN: &str = "Connect directly when both computers are on \
                                                      the same local network (faster; the other \
                                                      computer learns this computer's local \
                                                      address)";

/// The switch in a build whose direct connections reach the internet.
pub(in super::super) const DIRECT_SWITCH_INTERNET: &str = "Allow direct connections (faster; the \
                                                           other computer learns your IP \
                                                           address)";

/// How a direct connection comes about, while the switch is on (local
/// network only).
pub(in super::super) const DIRECT_HOW_LAN: &str = "After the other computer accepts, the two \
                                                   computers exchange their local network \
                                                   addresses over Tor and try to reach each \
                                                   other directly for a moment. If they are not \
                                                   on the same network, the session is relayed \
                                                   through Tor.";

/// How a direct connection comes about, while the switch is on (the
/// internet too).
pub(in super::super) const DIRECT_HOW_INTERNET: &str = "After the other computer accepts, the two \
                                                        computers exchange their addresses over \
                                                        Tor and try to reach each other directly \
                                                        for up to 4 seconds. If they cannot, the \
                                                        session is relayed through Tor.";

/// What stays private, while the switch is on (local network only).
pub(in super::super) const DIRECT_PRIVATE: &str = "Only local addresses (like 192.168.1.20) are \
                                                   exchanged: no outside server is asked, your \
                                                   router is left alone, and your internet \
                                                   address stays hidden.";

/// What the other computer learns, while the switch is on (the internet
/// too).
pub(in super::super) const DIRECT_EXPOSES: &str = "A computer you connect to, or that you let \
                                                   connect here, learns this computer's local \
                                                   and internet addresses (IPv4 and IPv6), only \
                                                   after the session is accepted. Computers that \
                                                   are refused, or never paired, learn nothing.";

/// The STUN switch (bound to `network.enable_stun`), under the direct
/// switch while it is on (the internet too).
pub(in super::super) const STUN_SWITCH: &str = "Use public STUN servers";

/// Under [`STUN_SWITCH`]. The design's words, with the condition the
/// operator split holds under (decision M1-81, the review of steps B2 and
/// B3): each computer splits its own list, so two different lists can put
/// one operator in both computers' parts; and with the time of the first
/// lookup (the review of step B11): once Tor is connected, which says
/// whether it uses a bridge, not when Tornect starts.
pub(in super::super) const STUN_LINE: &str = "To find this computer's internet address, Tornect \
                                              asks one public server per session (by default \
                                              from Cloudflare, Google, Twilio or Nextcloud; the \
                                              list is in config.toml). That server sees this \
                                              computer's internet address and when a session \
                                              starts, never which computer it connects to (when \
                                              both computers use the same list, as with the \
                                              default) and never the picture. Tornect looks up \
                                              these servers' names once Tor is connected and \
                                              every 10 minutes. Off: direct connections across \
                                              routers succeed less often.";

/// The router switch: on only while `network.upnp`, `nat_pmp` and `pcp`
/// all are; it sets all three.
pub(in super::super) const ROUTER_SWITCH: &str = "Ask this network's router to open a port \
                                                  (UPnP, NAT-PMP, PCP)";

/// Under [`ROUTER_SWITCH`].
pub(in super::super) const ROUTER_LINE: &str = "The opening is for one session and shows as \
                                                \"Tornect\" in the router's settings. Tornect \
                                                closes it when the session ends; if Tornect stops \
                                                first, most routers drop it within 10 minutes, \
                                                and Tornect removes it at its next start.";

/// While the STUN or the router switch is off: neither hides this
/// computer's internet address from the other computer.
pub(in super::super) const PUBLIC_ANYWAY: &str = "With these off, the other computer still learns \
                                                  this computer's internet address from the \
                                                  direct connection itself. To keep it hidden, \
                                                  turn direct connections off.";

/// The switch's words in this build, or in the other one (`internet`):
/// also the one-time notice's switch (design `direct` §3.6).
#[must_use]
pub(in crate::ui) fn direct_switch(internet: bool) -> &'static str {
    if internet {
        DIRECT_SWITCH_INTERNET
    } else {
        DIRECT_SWITCH_LAN
    }
}

/// While the switch is off.
pub(in super::super) const DIRECT_OFF: &str = "Every session is relayed through Tor: computers you \
                                               connect to never learn this computer's address, \
                                               and pictures are slower.";

/// While Tor uses a bridge and `network.direct_with_bridges` is off
/// (decision M1-86): the switch keeps its saved value.
pub(in super::super) const BRIDGE_NOTE: &str = "Tor reaches the network through a bridge on this \
                                                computer, so direct connections are off: they \
                                                would show this network that Tornect is in use. \
                                                To allow them anyway, set \
                                                network.direct_with_bridges in config.toml.";

/// Always.
pub(in super::super) const DIRECT_TOR_STILL: &str = "Both computers still need to reach Tor: Tor \
                                                     finds the other computer and checks who it \
                                                     is, and a direct connection starts only \
                                                     after the other computer accepts.";

/// When the switch applies.
pub(in super::super) const NEXT_SESSION: &str = "Applies from the next session.";

/// On Windows only.
pub(in super::super) const DIRECT_WINDOWS: &str = "The first direct connection may make Windows \
                                                   ask whether Tornect may communicate on your \
                                                   networks. Choose \"Allow access\". If you \
                                                   cancel, or this Windows account cannot change \
                                                   the firewall, sessions are relayed through \
                                                   Tor.";

/// While `network.lan_only` is set (`config.toml` only): the switch shows
/// on and cannot be changed.
pub(in super::super) const LAN_ONLY_NOTE: &str = "config.toml limits sessions to direct \
                                                  connections on this network \
                                                  (network.lan_only), in both directions: no \
                                                  STUN server or router is asked, and a session \
                                                  that cannot connect directly ends instead of \
                                                  going through Tor.";

/// The line under the field for each line that does not parse.
#[must_use]
pub(in super::super) fn bad_line(n: usize) -> String {
    format!("Line {n} does not parse.")
}

/// The Connection section.
pub(super) fn section(
    ui: &mut Ui,
    model: &Model,
    form: &mut SettingsForm,
    shared: bool,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    let stored = &model.settings.tor;
    let retry = super::super::home::retry_in(model, std::time::Instant::now());
    let (status, color) =
        super::super::home::tor_line(t, &model.tor, retry.filter(|_| !model.tor.is_ready()));
    widgets::card(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.add(
            egui::Label::new(
                RichText::new(status)
                    .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
                    .color(color),
            )
            .wrap(),
        );
        // Tor's try only: with Tor up, the try that waits is the publishing
        // of this ID, which this card does not mention (Home does).
        if !model.tor.is_ready() {
            super::super::home::retry_button(ui, model, actions);
        }
    });
    ui.add_space(16.0);
    widgets::section_header(ui, "How to reach Tor");
    if shared {
        super::super::hidden_card(ui, super::WRITES_HIDDEN);
    } else {
        let names = MODES.map(|(_, name)| name);
        let now = MODES
            .iter()
            .position(|(mode, _)| *mode == stored.bridges)
            .unwrap_or(0);
        let mut index = now;
        widgets::segmented(ui, &mut index, &names);
        if index != now
            && let Some((mode, _)) = MODES.get(index)
        {
            actions.push(Action::SaveSettings(SettingsChange::Tor(TorChoice {
                bridges: *mode,
                ..stored.clone()
            })));
        }
        line(ui, NEXT_START, t.text_muted);

        ui.add_space(16.0);
        widgets::section_header(ui, "Private bridges");
        line(ui, WHERE_BRIDGES, t.text_secondary);
        line(ui, BY_NUMBER, t.text_secondary);
        let draft = form
            .bridge_lines
            .get_or_insert_with(|| stored.bridge_lines.0.join("\n"));
        ui.add(
            egui::TextEdit::multiline(draft)
                .font(theme::font(ui.ctx(), Face::Mono, 12.0))
                .desired_rows(3)
                .desired_width(ui.available_width()),
        );
        let lines: Vec<String> = draft.lines().map(str::to_owned).collect();
        let rejected = Ladder::rejected_lines(&lines);
        for n in &rejected {
            line(ui, &bad_line(*n), t.danger_text);
        }
        let changed = lines != stored.bridge_lines.0;
        if Button::new(Kind::Primary, "Save")
            .enabled(changed && rejected.is_empty())
            .show(ui)
            .clicked()
        {
            actions.push(Action::SaveSettings(SettingsChange::Tor(TorChoice {
                bridge_lines: BridgeLines(
                    lines.into_iter().filter(|l| !l.trim().is_empty()).collect(),
                ),
                ..stored.clone()
            })));
            form.bridge_lines = None;
        }

        ui.add_space(16.0);
        ui.horizontal(|ui| {
            let mut on = stored.pow_defense;
            if widgets::toggle(ui, &mut on, POW).clicked() {
                actions.push(Action::SaveSettings(SettingsChange::Tor(TorChoice {
                    pow_defense: on,
                    ..stored.clone()
                })));
            }
            ui.label(
                RichText::new(POW)
                    .font(theme::font(ui.ctx(), Face::Medium, 14.0))
                    .color(t.text_primary),
            );
        });
        line(ui, POW_NEXT_START, t.text_muted);
        if let Some(problem) = model.settings.problem {
            line(ui, problem, t.danger_text);
        }
    }
    ui.add_space(20.0);
    widgets::section_header(ui, DIRECT_HEADER);
    if shared {
        super::super::hidden_card(ui, super::WRITES_HIDDEN);
    } else {
        direct(ui, model, actions);
    }
}

/// The direct connections switch and what it means here (design `direct`
/// §3.3): what each computer learns while it is on, in a build whose
/// direct connections reach the internet the STUN and router switches
/// under it, why it is off while a bridge is in use, and `lan_only`'s rule,
/// which only `config.toml` sets.
fn direct(ui: &mut Ui, model: &Model, actions: &mut Vec<Action>) {
    let t = theme::tokens(ui.ctx());
    let saved = &model.settings;
    let label = direct_switch(saved.internet);
    // Under lan_only the switch shows on: sessions go direct or end.
    let mut on = saved.direct || saved.lan_only;
    ui.horizontal_top(|ui| {
        let switched = ui
            .add_enabled_ui(!saved.lan_only, |ui| {
                widgets::toggle(ui, &mut on, label).clicked()
            })
            .inner;
        if switched && !saved.lan_only {
            actions.push(Action::SaveSettings(SettingsChange::Direct(on)));
        }
        switch_label(ui, label);
    });
    ui.add_space(4.0);
    if saved.lan_only {
        line(ui, LAN_ONLY_NOTE, t.text_secondary);
    } else if saved.direct {
        if saved.internet {
            line(ui, DIRECT_HOW_INTERNET, t.text_secondary);
            line(ui, DIRECT_EXPOSES, t.text_secondary);
        } else {
            line(ui, DIRECT_HOW_LAN, t.text_secondary);
            line(ui, DIRECT_PRIVATE, t.text_secondary);
        }
        if saved.bridged_off {
            line(ui, BRIDGE_NOTE, t.warn);
        }
        if saved.internet {
            ui.add_space(8.0);
            ui.indent("direct-options", |ui| sub_switches(ui, model, actions));
        }
    } else {
        line(ui, DIRECT_OFF, t.text_secondary);
    }
    line(ui, DIRECT_TOR_STILL, t.text_muted);
    line(ui, NEXT_SESSION, t.text_muted);
    if cfg!(windows) {
        line(ui, DIRECT_WINDOWS, t.text_muted);
    }
}

/// The STUN and router switches under the direct switch, each with what it
/// does, and, while either is off, that neither hides this computer's
/// internet address from the other computer.
fn sub_switches(ui: &mut Ui, model: &Model, actions: &mut Vec<Action>) {
    let t = theme::tokens(ui.ctx());
    let saved = &model.settings;
    let mut stun = saved.stun;
    ui.horizontal_top(|ui| {
        if widgets::toggle(ui, &mut stun, STUN_SWITCH).clicked() {
            actions.push(Action::SaveSettings(SettingsChange::Stun(stun)));
        }
        switch_label(ui, STUN_SWITCH);
    });
    line(ui, STUN_LINE, t.text_secondary);
    ui.add_space(8.0);
    let mut router = saved.router;
    ui.horizontal_top(|ui| {
        if widgets::toggle(ui, &mut router, ROUTER_SWITCH).clicked() {
            actions.push(Action::SaveSettings(SettingsChange::RouterMapping(router)));
        }
        switch_label(ui, ROUTER_SWITCH);
    });
    line(ui, ROUTER_LINE, t.text_secondary);
    if !saved.stun || !saved.router {
        line(ui, PUBLIC_ANYWAY, t.text_secondary);
    }
}

/// A switch's words beside it.
fn switch_label(ui: &mut Ui, text: &str) {
    let t = theme::tokens(ui.ctx());
    ui.add(
        egui::Label::new(
            RichText::new(text)
                .font(theme::font(ui.ctx(), Face::Medium, 14.0))
                .color(t.text_primary),
        )
        .wrap(),
    );
}
