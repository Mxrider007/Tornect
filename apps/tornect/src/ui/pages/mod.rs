//! The main window's pages (the redesign's §4). In this version Home shows
//! what works today; the Address book, Sessions and Settings, whose content
//! comes in later versions, each show one plain line saying so, and never a
//! control that does nothing. The widget gallery is reached only from the
//! preview. Trust surfaces are not pages: the open questions are drawn above
//! the page, the banner above everything (`view`).

mod gallery;
mod home;

use std::time::Instant;

use egui::{RichText, Ui};

use super::model::Model;
use super::nav::Page;
use super::theme::{self, Face};
use super::view::{Action, Form};

/// Draw `page`.
pub fn draw(
    ui: &mut Ui,
    page: Page,
    model: &Model,
    form: &mut Form,
    now: Instant,
    actions: &mut Vec<Action>,
) {
    match page {
        Page::Home => home::home(ui, model, form, now, actions),
        Page::AddressBook => later(
            ui,
            page,
            "Saved computers and the devices paired with this one arrive in a later version; \
             until then, connect by ID on Home.",
        ),
        Page::Sessions => later(
            ui,
            page,
            "The list of past sessions arrives in a later version; each session is already \
             recorded in this computer's session log.",
        ),
        Page::Settings => later(
            ui,
            page,
            "Settings arrive in a later version; until then, the command line's help lists \
             the commands that change them.",
        ),
        Page::Widgets => gallery::gallery(ui),
    }
}

/// A page whose content comes in a later version: its title and one line.
fn later(ui: &mut Ui, page: Page, note: &str) {
    let t = theme::tokens(ui.ctx());
    ui.label(
        RichText::new(page.title())
            .font(theme::font(ui.ctx(), Face::Bold, 26.0))
            .color(t.text_primary),
    );
    ui.label(
        RichText::new(note)
            .font(theme::font(ui.ctx(), Face::Regular, 14.0))
            .color(t.text_secondary),
    );
}
