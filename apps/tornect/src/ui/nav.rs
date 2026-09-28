//! The pages and the sidebar (the redesign's §4): Home, Address book,
//! Sessions and Settings, kept in the window's UI state (`view::Form`). The
//! sidebar is 224 points wide with the brand, the pages and the Tor status;
//! under [`RAIL_BELOW`] points of window width it is a 64-point rail of
//! icons. It is drawn after the page, so that the keyboard reaches the
//! banner's Stop, the open questions and the page before the navigation.

use egui::{Align2, Color32, CornerRadius, Pos2, RichText, Sense, Stroke, Ui, Vec2, vec2};

use super::icons::Icon;
use super::model::{Model, TorState};
use super::theme::{self, Face};
use super::widgets::{self, Tone};

/// A page of the main window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Page {
    /// This computer's ID, connecting to another, what is going on.
    #[default]
    Home,
    /// Saved computers and the devices that can connect here.
    AddressBook,
    /// Past sessions.
    Sessions,
    /// Settings.
    Settings,
    /// The widget gallery: reached only from the preview (`--page widgets`),
    /// for looking at the widgets themselves.
    Widgets,
}

impl Page {
    /// The pages the sidebar lists, in its order.
    pub const LISTED: [Self; 4] = [
        Self::Home,
        Self::AddressBook,
        Self::Sessions,
        Self::Settings,
    ];

    /// The page's name, as the sidebar and its title show it.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::AddressBook => "Address book",
            Self::Sessions => "Sessions",
            Self::Settings => "Settings",
            Self::Widgets => "Widgets",
        }
    }

    /// The page's icon.
    #[must_use]
    pub fn icon(self) -> Icon {
        match self {
            Self::Home => Icon::House,
            Self::AddressBook => Icon::BookUser,
            Self::Sessions => Icon::History,
            Self::Settings | Self::Widgets => Icon::SlidersHorizontal,
        }
    }
}

/// Below this window width (points) the sidebar is the icon rail.
pub const RAIL_BELOW: f32 = 1000.0;
/// The sidebar's width.
const FULL: f32 = 224.0;
/// The rail's width.
const RAIL: f32 = 64.0;

/// The sidebar's width in a window `window_width` points wide.
#[must_use]
pub fn width(window_width: f32) -> f32 {
    if window_width < RAIL_BELOW {
        RAIL
    } else {
        FULL
    }
}

/// The sidebar's content, in `ui` (the rect reserved for it), as a `rail`
/// or at full width; a click on a page opens it.
pub fn sidebar(ui: &mut Ui, model: &Model, page: &mut Page, rail: bool) {
    let t = theme::tokens(ui.ctx());
    let rect = ui.max_rect();
    let inner = if rail {
        rect.shrink2(vec2(12.0, 18.0))
    } else {
        rect.shrink2(vec2(14.0, 18.0))
    };
    let mut ui = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("sidebar-content")
            .max_rect(inner)
            .layout(egui::Layout::top_down(if rail {
                egui::Align::Center
            } else {
                egui::Align::Min
            })),
    );
    brand(&mut ui, rail);
    ui.add_space(20.0);
    ui.spacing_mut().item_spacing.y = 2.0;
    for listed in Page::LISTED {
        if widgets::nav_item(
            &mut ui,
            listed.icon(),
            listed.title(),
            *page == listed,
            rail,
        )
        .clicked()
        {
            *page = listed;
        }
    }
    // The Tor status at the foot of the sidebar.
    let (tone, headline, detail) = tor_status(&model.tor);
    let foot = egui::Rect::from_min_max(
        Pos2::new(
            inner.left(),
            inner.bottom() - if rail { 40.0 } else { 64.0 },
        ),
        inner.max,
    );
    let mut foot_ui = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("sidebar-foot")
            .max_rect(foot),
    );
    if rail {
        let (dot, response) = foot_ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
        foot_ui
            .painter()
            .circle_filled(dot.center(), 5.0, tone.dot(t));
        response.on_hover_text(format!("{headline} ({detail})"));
        return;
    }
    widgets::card_frame(t, 12, egui::Margin::same(12)).show(&mut foot_ui, |ui| {
        ui.set_width(ui.available_width());
        ui.spacing_mut().item_spacing.y = 2.0;
        ui.horizontal(|ui| {
            widgets::dot(ui, tone);
            ui.label(
                RichText::new(headline)
                    .font(theme::font(ui.ctx(), Face::Semibold, 13.0))
                    .color(t.text_primary),
            );
        });
        ui.add(
            egui::Label::new(
                RichText::new(detail)
                    .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                    .color(t.text_muted),
            )
            .truncate(),
        );
    });
}

/// The Tor status, short, for the sidebar: its tone, headline and detail.
fn tor_status(tor: &TorState) -> (Tone, &'static str, String) {
    match tor {
        TorState::Starting => (
            Tone::Neutral,
            "Tor starting",
            "not connected yet".to_owned(),
        ),
        TorState::Trying { via, attempt, of } => (
            Tone::Warn,
            "Connecting to Tor",
            format!("via {via} ({attempt} of {of})"),
        ),
        TorState::Progress { via, pct, blocked } => (
            Tone::Warn,
            "Connecting to Tor",
            match blocked {
                Some(_) => format!("{pct}% via {via}, stuck"),
                None => format!("{pct}% via {via}"),
            },
        ),
        TorState::Ready { via } => (Tone::Ok, "Tor connected", format!("via {via}")),
        TorState::Failed(_) => (Tone::Danger, "Tor not reachable", "see Home".to_owned()),
    }
}

/// The brand: the mark on its accent square, and the name beside it.
fn brand(ui: &mut Ui, rail: bool) {
    let t = theme::tokens(ui.ctx());
    let size = if rail {
        vec2(40.0, 30.0)
    } else {
        vec2(ui.available_width(), 30.0)
    };
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let square = if rail {
        egui::Rect::from_center_size(rect.center(), Vec2::splat(30.0))
    } else {
        egui::Rect::from_min_size(rect.min + vec2(8.0, 0.0), Vec2::splat(30.0))
    };
    ui.painter()
        .rect_filled(square, CornerRadius::same(9), t.accent_fill);
    mark(ui, square, Color32::WHITE);
    if !rail {
        ui.painter().text(
            Pos2::new(square.right() + 10.0, square.center().y),
            Align2::LEFT_CENTER,
            "Tornect",
            theme::font(ui.ctx(), Face::Bold, 17.0),
            t.text_primary,
        );
    }
}

/// Tornect's mark, "layers around a signal", in `square` (drawn on the
/// design's 24-unit grid): two nodes, the link between them, and an arc
/// around each.
fn mark(ui: &Ui, square: egui::Rect, color: Color32) {
    let unit = square.width() * 0.75 / 24.0;
    let origin = square.center() - Vec2::splat(12.0 * unit);
    let at = |x: f32, y: f32| origin + vec2(x, y) * unit;
    let stroke = Stroke::new(2.0 * unit, color);
    let painter = ui.painter();
    painter.circle_stroke(at(7.0, 17.0), 2.5 * unit, stroke);
    painter.circle_stroke(at(17.0, 7.0), 2.5 * unit, stroke);
    painter.add(egui::epaint::CubicBezierShape::from_points_stroke(
        [at(8.9, 15.2), at(10.0, 11.5), at(12.0, 9.3), at(15.2, 8.4)],
        false,
        Color32::TRANSPARENT,
        stroke,
    ));
    // Quarter arcs of radius 8.5 around (12.5, 12.5) and (11.5, 11.5).
    let arc = |center: Pos2, from: f32| -> Vec<Pos2> {
        (0..=12)
            .map(|i| {
                let a = from + std::f32::consts::FRAC_PI_2 * i as f32 / 12.0;
                center + 8.5 * unit * Vec2::angled(a)
            })
            .collect()
    };
    painter.add(egui::Shape::line(
        arc(at(12.5, 12.5), std::f32::consts::PI),
        stroke,
    ));
    painter.add(egui::Shape::line(arc(at(11.5, 11.5), 0.0), stroke));
}
