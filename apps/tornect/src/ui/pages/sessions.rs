//! The Sessions page (§B.8.13, the redesign's Sessions): the session log's
//! session lines, newest first: when, the other side's pinned label, the
//! mode, attended or unattended, and how it ended, from a fixed list of
//! endings (any other reads "ended", a field the line lacks "—"). Never a
//! device key, device words, a grant id, a path, a transport detail or other
//! free text of the log. The tokio side reads the log by itself, so opening
//! the page asks for nothing, and reading it writes nothing. While this
//! screen is shared the page shows the hidden card. "Open log folder" shows
//! the folder's path.

use std::collections::HashMap;

use egui::{RichText, Ui};
use tornect_core::session_log::{SessionEvent, SessionMode, SessionRecord};

use super::super::model::{Model, SessionRow};
use super::super::theme::{self, Face};
use super::super::view::Form;
use super::super::widgets::{self, Button, Kind};

/// The page's subtitle.
pub(super) const SUBTITLE: &str =
    "Past sessions as this computer's session log records them, newest first.";

/// What the hidden card says while this screen is shared.
pub(super) const HIDDEN: &str = "The past sessions come back when sharing ends.";

/// Before any session is recorded.
pub(super) const NONE_YET: &str = "No session is recorded yet.";

/// The button that shows the session log's folder.
pub(super) const OPEN_LOG_FOLDER: &str = "Open log folder";

/// Under the newest rows, when the log holds more.
pub(super) const OLDER: &str = "Older sessions are in the session log.";

/// Above the rows, when part of the session log could not be read.
pub(super) const PART_UNREADABLE: &str = "Part of the session log could not be read.";

/// The columns' titles.
pub(super) const COLUMNS: [&str; 5] = ["When", "With", "Mode", "Access", "How it ended"];

/// The most rows the page draws, the newest.
const MOST: usize = 500;

/// A field the line lacks.
const MISSING: &str = "—";

/// How a session ended, by its end line's detail (how the host saw it end,
/// or the handshake's error): a fixed list of words; any other "ended".
fn ending(detail: Option<&str>) -> &'static str {
    let Some(detail) = detail else {
        return MISSING;
    };
    match detail.split('(').next().unwrap_or_default() {
        "PeerBye" => "ended by the other side",
        "PeerClosed" => "connection closed",
        "PeerError" => "ended by an error",
        "Killed" => "ended here",
        "Orphaned" | "Idle" => "ended for lack of traffic",
        "aborted" => "broken off",
        "timeout" => "timed out",
        _ => "ended",
    }
}

/// When a line was written, as "YYYY-MM-DD HH:MM UTC" (its RFC 3339 time).
fn when(ts: &str) -> String {
    match (ts.get(..10), ts.get(11..16)) {
        (Some(day), Some(time)) => format!("{day} {time} UTC"),
        _ => MISSING.to_owned(),
    }
}

/// The page's rows from `records` (the rotated files' and the live file's,
/// oldest first): one per `SessionStarted`, with its `SessionEnded` found by
/// the session id, per `SessionDenied` and per client `UnattendedConnect`
/// line, newest first; only the planned fields.
pub(in super::super) fn rows(records: &[SessionRecord]) -> Vec<SessionRow> {
    let ends: HashMap<&str, Option<&str>> = records
        .iter()
        .filter(|r| r.event == SessionEvent::SessionEnded)
        .filter_map(|r| Some((r.session_id.as_deref()?, r.detail.as_deref())))
        .collect();
    let label = |r: &SessionRecord| r.peer_name.clone().unwrap_or_else(|| MISSING.to_owned());
    let mut rows: Vec<(&str, SessionRow)> = records
        .iter()
        .filter_map(|r| {
            let row = match r.event {
                SessionEvent::SessionStarted => SessionRow {
                    when: when(&r.ts),
                    label: label(r),
                    mode: r.mode,
                    unattended: Some(r.unattended),
                    ended: r
                        .session_id
                        .as_deref()
                        .and_then(|id| ends.get(id))
                        .map_or(MISSING, |detail| ending(*detail)),
                },
                SessionEvent::SessionDenied => SessionRow {
                    when: when(&r.ts),
                    label: label(r),
                    mode: None,
                    unattended: None,
                    ended: "refused",
                },
                SessionEvent::UnattendedConnect => SessionRow {
                    when: when(&r.ts),
                    label: label(r),
                    mode: r.mode,
                    unattended: Some(true),
                    // An admin command's name and whether it ran stay off
                    // the page.
                    ended: match r.reason.as_deref() {
                        Some("accepted") => "connected",
                        Some("admin") => "admin command",
                        _ => "not connected",
                    },
                },
                _ => return None,
            };
            Some((r.ts.as_str(), row))
        })
        .collect();
    // Newest first, by the lines' own times (RFC 3339 in UTC sorts as text).
    rows.sort_by(|a, b| b.0.cmp(a.0));
    rows.into_iter().map(|(_, row)| row).collect()
}

/// The Sessions page.
pub(super) fn page(ui: &mut Ui, model: &Model, form: &mut Form, shared: bool) {
    let t = theme::tokens(ui.ctx());
    widgets::page_header(ui, "Sessions", SUBTITLE);
    ui.add_space(14.0);
    if shared {
        super::hidden_card(ui, HIDDEN);
        return;
    }
    let text = |ui: &mut Ui, text: &str, color| {
        ui.label(
            RichText::new(text)
                .font(theme::font(ui.ctx(), Face::Regular, 13.0))
                .color(color),
        );
    };
    // What could be read is shown, and the part that could not be is said.
    if model.sessions_partial {
        text(ui, PART_UNREADABLE, t.warn);
    }
    match &model.sessions {
        None => {
            ui.spinner();
        }
        Some(rows) if rows.is_empty() => {
            if !model.sessions_partial {
                text(ui, NONE_YET, t.text_secondary);
            }
        }
        Some(rows) => {
            widgets::card(ui, |ui| {
                ui.set_width(ui.available_width());
                egui::Grid::new("sessions")
                    .num_columns(COLUMNS.len())
                    .spacing([18.0, 6.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for title in COLUMNS {
                            ui.label(
                                RichText::new(title)
                                    .font(theme::font(ui.ctx(), Face::Semibold, 13.0))
                                    .color(t.text_secondary),
                            );
                        }
                        ui.end_row();
                        for row in rows.iter().take(MOST) {
                            text(ui, &row.when, t.text_primary);
                            text(ui, &row.label, t.text_primary);
                            let mode = match row.mode {
                                Some(SessionMode::Control) => "Control",
                                Some(SessionMode::ViewOnly) => "View only",
                                None => MISSING,
                            };
                            text(ui, mode, t.text_primary);
                            let access = match row.unattended {
                                Some(true) => "Unattended",
                                Some(false) => "Attended",
                                None => MISSING,
                            };
                            text(ui, access, t.text_primary);
                            text(ui, row.ended, t.text_secondary);
                            ui.end_row();
                        }
                    });
            });
            if rows.len() > MOST {
                ui.add_space(6.0);
                text(ui, OLDER, t.text_muted);
            }
        }
    }
    ui.add_space(12.0);
    if form.log_folder_shown {
        text(
            ui,
            model.log_folder.as_deref().unwrap_or(MISSING),
            t.text_secondary,
        );
    } else if Button::new(Kind::Secondary, OPEN_LOG_FOLDER)
        .small()
        .show(ui)
        .clicked()
    {
        form.log_folder_shown = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tornect_core::DeviceId;

    /// §B.8.13: the rows are newest first by their lines' own times, whatever
    /// order the files hold them in; each session line pairs with its end.
    #[test]
    fn the_sessions_rows_are_newest_first() {
        let dev = DeviceId::from_bytes([1; 32]);
        let at = |ts: &str, event| {
            let mut r = SessionRecord::now(event).peer(dev, "Office laptop");
            r.ts = ts.to_owned();
            r
        };
        let records = vec![
            at("2026-10-02T09:00:00Z", SessionEvent::SessionStarted).session("b"),
            at("2026-10-01T08:00:00Z", SessionEvent::SessionStarted).session("a"),
            at("2026-10-01T08:30:00Z", SessionEvent::SessionEnded)
                .session("a")
                .detail("PeerClosed"),
            at("2026-10-03T10:15:00Z", SessionEvent::SessionDenied),
        ];
        let rows = rows(&records);
        let whens: Vec<&str> = rows.iter().map(|r| r.when.as_str()).collect();
        assert_eq!(
            whens,
            [
                "2026-10-03 10:15 UTC",
                "2026-10-02 09:00 UTC",
                "2026-10-01 08:00 UTC"
            ]
        );
        assert_eq!(
            rows.iter().map(|r| r.ended).collect::<Vec<_>>(),
            ["refused", "—", "connection closed"]
        );
    }

    /// A client's admin command to a computer (its `UnattendedConnect` line
    /// with the reason "admin") ends "admin command"; the command's name and
    /// whether it ran stay off the page.
    #[test]
    fn an_admin_command_row_says_admin_command() {
        let dev = DeviceId::from_bytes([1; 32]);
        let records = vec![
            SessionRecord::now(SessionEvent::UnattendedConnect)
                .peer(dev, "Office laptop")
                .unattended(true)
                .reason("admin")
                .op("end_session")
                .ok(false),
        ];
        let rows = rows(&records);
        assert_eq!(
            rows.iter().map(|r| r.ended).collect::<Vec<_>>(),
            ["admin command"]
        );
        let model = Model {
            sessions: Some(rows),
            ..Model::default()
        };
        let said = texts(&model);
        assert!(said.iter().any(|t| t == "admin command"), "{said:?}");
        assert!(
            !said
                .iter()
                .any(|t| t.contains("end_session") || t.contains("false")),
            "{said:?}"
        );
    }

    /// Every text the page draws over `model`, not shared, after two passes.
    fn texts(model: &Model) -> Vec<String> {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut form = Form::default();
        let mut nodes = Vec::new();
        for _ in 0..2 {
            let out = ctx.run_ui(egui::RawInput::default(), |ui| {
                page(ui, model, &mut form, false);
            });
            if let Some(update) = &out.platform_output.accesskit_update {
                nodes = update.nodes.iter().map(|(_, n)| n.clone()).collect();
            }
            out.drop_without_applying_deltas();
        }
        nodes
            .iter()
            .flat_map(|n: &egui::accesskit::Node| [n.label(), n.value()])
            .flatten()
            .map(str::to_owned)
            .collect()
    }

    /// Part of the session log could not be read: the page says so above the
    /// rows that could be, and with none it says nothing else (no spinner for
    /// ever, no "nothing recorded").
    #[test]
    fn a_log_read_in_part_says_so() {
        let dev = DeviceId::from_bytes([1; 32]);
        let records = vec![
            SessionRecord::now(SessionEvent::SessionStarted)
                .peer(dev, "Office laptop")
                .session("a"),
        ];
        let mut model = Model {
            sessions: Some(rows(&records)),
            sessions_partial: true,
            ..Model::default()
        };
        let said = texts(&model);
        assert!(said.iter().any(|t| t == PART_UNREADABLE), "{said:?}");
        assert!(said.iter().any(|t| t == "Office laptop"), "{said:?}");
        model.sessions = Some(Vec::new());
        let said = texts(&model);
        assert!(said.iter().any(|t| t == PART_UNREADABLE), "{said:?}");
        assert!(!said.iter().any(|t| t == NONE_YET), "{said:?}");
        model.sessions_partial = false;
        let said = texts(&model);
        assert!(!said.iter().any(|t| t == PART_UNREADABLE), "{said:?}");
        assert!(said.iter().any(|t| t == NONE_YET), "{said:?}");
    }
}
