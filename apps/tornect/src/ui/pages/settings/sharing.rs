//! Settings, Sharing (the services design §7.5): what someone connected to
//! this computer may use beside the picture and input (chat, the clipboard,
//! sending files here, seeing and copying files from here), and whether this
//! computer offers its own clipboard when it views another. Each switch is
//! one [`SettingsChange`] saved to `config.toml` and applies to the sessions
//! that start afterwards (§2.5); the limits and the Wayland clipboard switch
//! are only `config.toml`'s, and the section says the limits as they are.
//! Places are named in words, never by a path.

use egui::{RichText, Ui};
use tornect_core::config::Services;
use tornect_session::services::ServicesLimits;

use super::super::super::model::{Model, ServicesSettings, SettingsChange};
use super::super::super::theme::{self, Face};
use super::super::super::view::Action;
use super::super::super::widgets;
use super::super::viewer::limit_text;
use super::line;

/// The host's part.
pub(in super::super) const HOST_HEADER: &str = "When someone connects to this computer";

/// The viewer's part.
pub(in super::super) const VIEWER_HEADER: &str = "When you connect to another computer";

/// The chat switch and what it does.
pub(in super::super) const CHAT: (&str, &str) = (
    "Chat",
    "They can write to you, and you to them, in any session.",
);

/// The clipboard switch and what it does.
pub(in super::super) const CLIPBOARD: (&str, &str) = (
    "Clipboard",
    "When they control this computer, text copied here during the session can be pasted there, \
     and the other way round. Text a password manager marks as private is not shared.",
);

/// The switch for files sent here and what it does.
pub(in super::super) const RECEIVE: (&str, &str) = (
    "Receive files",
    "When they control this computer, they can send files. Files go to Downloads › Tornect and \
     never replace a file there.",
);

/// The switch for files seen and copied from here and what it does.
pub(in super::super) const BROWSE: (&str, &str) = (
    "Let them see and copy files",
    "When they control this computer, they can see and copy any file you can open here. \
     Tornect's own folders are never shown.",
);

/// What the lock does to them (§2.3).
pub(in super::super) const LOCKED: &str =
    "While this computer is locked, files and the clipboard pause.";

/// Where this computer has no Downloads folder (§2.6).
pub(in super::super) const NO_DOWNLOADS: &str =
    "This computer has no Downloads folder, so it cannot receive files.";

/// On a Wayland desktop whose clipboard no session can have yet: the
/// portal is not asked for it (`[services] wayland_clipboard` off when this
/// window started), or it refused a session (§4.2).
pub(in super::super) const NOT_SHARED_YET: &str =
    "This desktop does not share its clipboard with Tornect yet.";

/// The viewer's clipboard switch and what it does.
pub(in super::super) const SHARE_CLIPBOARD: (&str, &str) = (
    "Share my clipboard",
    "Text you copy here during a session is offered to the other computer when you return to \
     its window.",
);

/// Where downloads go.
pub(in super::super) const DOWNLOADS: &str = "Files you download go to Downloads › Tornect.";

/// The limits line, from `services` (and the fixed file count of a
/// session): "Each file up to 2 GiB, up to 8 GiB and 1,000 files in a
/// session; 1 GiB of the disk is always kept free."
#[must_use]
pub(in super::super) fn limits_line(services: &Services) -> String {
    format!(
        "Each file up to {}, up to {} and {} files in a session; {} of the disk is always kept \
         free.",
        limit_text(services.max_file_bytes()),
        limit_text(services.session_quota_bytes()),
        count_text(ServicesLimits::default().session_files.into()),
        limit_text(services.keep_free_bytes()),
    )
}

/// A count with a comma between thousands: `1,000`.
fn count_text(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The Sharing section.
pub(super) fn section(ui: &mut Ui, model: &Model, shared: bool, actions: &mut Vec<Action>) {
    let t = theme::tokens(ui.ctx());
    let stored = model.settings.services;
    widgets::section_header(ui, HOST_HEADER);
    if shared {
        super::super::hidden_card(ui, super::WRITES_HIDDEN);
    } else {
        let now = ServicesSettings::of(&stored);
        let mut next = now;
        ui.add_space(6.0);
        switch(ui, &mut next.chat, CHAT);
        switch(ui, &mut next.clipboard, CLIPBOARD);
        switch(ui, &mut next.receive_files, RECEIVE);
        switch(ui, &mut next.browse_files, BROWSE);
        if next != now {
            actions.push(Action::SaveSettings(SettingsChange::Services(next)));
        }
    }
    ui.add_space(6.0);
    line(ui, &limits_line(&stored), t.text_secondary);
    line(ui, LOCKED, t.text_secondary);
    if model.no_downloads {
        line(ui, NO_DOWNLOADS, t.text_secondary);
    }
    if model.clipboard_not_shared() {
        line(ui, NOT_SHARED_YET, t.text_secondary);
    }
    ui.add_space(20.0);
    widgets::section_header(ui, VIEWER_HEADER);
    if shared {
        super::super::hidden_card(ui, super::WRITES_HIDDEN);
    } else {
        ui.add_space(6.0);
        let now = model.settings.viewer.clipboard_sync;
        let mut on = now;
        switch(ui, &mut on, SHARE_CLIPBOARD);
        if on != now {
            actions.push(Action::SaveSettings(SettingsChange::ViewerClipboard(on)));
        }
    }
    ui.add_space(6.0);
    line(ui, DOWNLOADS, t.text_secondary);
    if !shared && let Some(problem) = model.settings.problem {
        line(ui, problem, t.danger_text);
    }
}

/// A switch with its name beside it and what it does under them.
fn switch(ui: &mut Ui, on: &mut bool, (name, what): (&str, &str)) {
    let t = theme::tokens(ui.ctx());
    ui.horizontal(|ui| {
        widgets::toggle(ui, on, name);
        ui.label(
            RichText::new(name)
                .font(theme::font(ui.ctx(), Face::Medium, 14.0))
                .color(t.text_primary),
        );
    });
    line(ui, what, t.text_secondary);
    ui.add_space(8.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The limits line says `[services]`'s limits in binary units, and the
    /// session's file count with its thousands comma.
    #[test]
    fn the_limits_line_says_the_saved_limits() {
        assert_eq!(
            limits_line(&Services::default()),
            "Each file up to 2 GiB, up to 8 GiB and 1,000 files in a session; 1 GiB of the disk \
             is always kept free."
        );
        let small = Services {
            max_file_mib: 512,
            session_quota_mib: 1536,
            keep_free_mib: 256,
            ..Services::default()
        };
        assert_eq!(
            limits_line(&small),
            "Each file up to 512 MiB, up to 1.5 GiB and 1,000 files in a session; 256 MiB of the \
             disk is always kept free."
        );
        for (n, said) in [
            (0, "0"),
            (7, "7"),
            (999, "999"),
            (1000, "1,000"),
            (65_535, "65,535"),
            (1_234_567, "1,234,567"),
        ] {
            assert_eq!(count_text(n), said);
        }
    }
}
