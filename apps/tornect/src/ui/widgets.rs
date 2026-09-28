//! The window's widgets (the redesign's §7): buttons of four kinds, the card,
//! the chip, the toggle switch, the segmented control, the text field, the
//! navigation item, the countdown ring, the identicon and the headers. Each
//! is drawn from the theme's tokens and reports its plain label to the
//! accessibility tree. None of them answers a trust-surface question: those
//! keep their own buttons in `view` (`accept`, `refuse`).

use egui::{
    Align2, Color32, CornerRadius, Frame, InnerResponse, Margin, Pos2, Rect, Response, RichText,
    Sense, Shape, Stroke, StrokeKind, Ui, Vec2, WidgetInfo, WidgetType, vec2,
};

use super::icons::{self, Icon};
use super::theme::{self, CHIP_TINT, Face, Tokens};

/// A button's weight in its view: one primary per view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The view's main action (accent fill).
    Primary,
    /// Any other action (raised fill, 1 px border).
    Secondary,
    /// A quiet action (no fill until hovered).
    Ghost,
    /// A destructive action (red text).
    Danger,
}

/// A button: a label, an optional icon before it, in one of four [`Kind`]s,
/// 36 points tall (32 when small).
#[derive(Debug, Clone, Copy)]
pub struct Button<'a> {
    kind: Kind,
    label: &'a str,
    icon: Option<Icon>,
    small: bool,
    enabled: bool,
}

impl<'a> Button<'a> {
    /// A `kind` button labelled `label`.
    #[must_use]
    pub fn new(kind: Kind, label: &'a str) -> Self {
        Self {
            kind,
            label,
            icon: None,
            small: false,
            enabled: true,
        }
    }

    /// With `icon` before the label.
    #[must_use]
    pub fn icon(mut self, icon: Icon) -> Self {
        self.icon = Some(icon);
        self
    }

    /// 32 points tall, 13-point text.
    #[must_use]
    pub fn small(mut self) -> Self {
        self.small = true;
        self
    }

    /// Whether it can be pressed (a disabled button is dimmed and out of the
    /// Tab order).
    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Draw it; `clicked()` on the response is the press.
    pub fn show(self, ui: &mut Ui) -> Response {
        let t = theme::tokens(ui.ctx());
        let (text_size, height, pad) = if self.small {
            (13.0, 32.0, 11.0)
        } else {
            (14.0, 36.0, 14.0)
        };
        let font = theme::font(ui.ctx(), Face::Semibold, text_size);
        let galley = ui
            .painter()
            .layout_no_wrap(self.label.to_owned(), font, Color32::PLACEHOLDER);
        let icon_size = text_size + 2.0;
        let icon_room = self.icon.map_or(0.0, |_| icon_size + 8.0);
        let size = vec2(pad * 2.0 + icon_room + galley.size().x, height);
        let sense = if self.enabled {
            Sense::click()
        } else {
            Sense::hover()
        };
        let (rect, response) = ui.allocate_exact_size(size, sense);
        let (label, enabled) = (self.label, self.enabled);
        response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, enabled, label));
        if !ui.is_rect_visible(rect) {
            return response;
        }
        let hot = self.enabled && (response.hovered() || response.has_focus());
        let (fill, stroke, text) = match self.kind {
            Kind::Primary => (
                if hot { t.accent_hover } else { t.accent_fill },
                Stroke::NONE,
                t.on_accent,
            ),
            Kind::Secondary => (
                t.surface_raised,
                Stroke::new(1.0, if hot { t.border_hover } else { t.border_strong }),
                t.text_primary,
            ),
            Kind::Ghost => (
                if hot {
                    t.surface_raised
                } else {
                    Color32::TRANSPARENT
                },
                Stroke::NONE,
                t.text_secondary,
            ),
            Kind::Danger => (
                if hot {
                    theme::tint(t.danger_text, CHIP_TINT)
                } else {
                    t.surface_raised
                },
                Stroke::new(1.0, t.border_strong),
                t.danger_text,
            ),
        };
        let dim = |c: Color32| {
            if self.enabled {
                c
            } else {
                c.gamma_multiply(0.45)
            }
        };
        let radius = CornerRadius::same(if self.small { 8 } else { 10 });
        let painter = ui.painter();
        painter.rect(
            rect,
            radius,
            dim(fill),
            Stroke::new(stroke.width, dim(stroke.color)),
            StrokeKind::Inside,
        );
        focus_ring(ui, &response, rect, radius, t);
        let mut x = rect.left() + pad;
        if let Some(icon) = self.icon {
            icons::paint(
                ui,
                Pos2::new(x + icon_size / 2.0, rect.center().y),
                icon,
                icon_size,
                dim(text),
            );
            x += icon_room;
        }
        let y = rect.center().y - galley.size().y / 2.0;
        painter.galley(Pos2::new(x, y), galley, dim(text));
        response
    }
}

/// The keyboard focus ring: 2 points of the accent text colour, 2 points
/// outside the widget, only while it has the keyboard focus.
fn focus_ring(ui: &Ui, response: &Response, rect: Rect, radius: CornerRadius, t: &Tokens) {
    if response.has_focus() {
        ui.painter().rect_stroke(
            rect.expand(2.0),
            radius + 2,
            Stroke::new(2.0, t.accent_text),
            StrokeKind::Outside,
        );
    }
}

/// A card: the card surface, a 1-point border, 14-point corners and 20/24
/// points of padding (a shadow in the light theme).
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> InnerResponse<R> {
    card_frame(theme::tokens(ui.ctx()), 14, Margin::symmetric(24, 20)).show(ui, add)
}

/// A card's frame with `radius` and `margin`: 18 for the ID card, 14 for the
/// others.
pub fn card_frame(t: &Tokens, radius: u8, margin: Margin) -> Frame {
    Frame::new()
        .fill(t.surface_card)
        .stroke(Stroke::new(1.0, t.border_subtle))
        .corner_radius(CornerRadius::same(radius))
        .inner_margin(margin)
        .shadow(t.card_shadow)
}

/// What a chip or a status line says about its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Nothing to report.
    Neutral,
    /// A link or a setting.
    Accent,
    /// Connected, reachable.
    Ok,
    /// Waiting, relayed, publishing.
    Warn,
    /// Failed.
    Danger,
}

impl Tone {
    /// The tone's text colour.
    #[must_use]
    pub fn color(self, t: &Tokens) -> Color32 {
        match self {
            Self::Neutral => t.text_secondary,
            Self::Accent => t.accent_text,
            Self::Ok => t.ok,
            Self::Warn => t.warn,
            Self::Danger => t.danger_text,
        }
    }

    /// A status dot's colour.
    #[must_use]
    pub fn dot(self, t: &Tokens) -> Color32 {
        match self {
            Self::Neutral => t.text_muted,
            other => other.color(t),
        }
    }
}

/// A chip: a pill 24 points tall with 12-point text, tinted by `tone`, with
/// a status dot before the text when `dot`.
pub fn chip(ui: &mut Ui, tone: Tone, dot: bool, text: &str) -> Response {
    let t = theme::tokens(ui.ctx());
    let font = theme::font(ui.ctx(), Face::Medium, 12.0);
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, Color32::PLACEHOLDER);
    let dot_room = if dot { 14.0 } else { 0.0 };
    let size = vec2(20.0 + dot_room + galley.size().x, 24.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Label, true, text));
    let (fill, color) = match tone {
        Tone::Neutral => (t.surface_raised, t.text_secondary),
        other => (theme::tint(other.color(t), CHIP_TINT), other.color(t)),
    };
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(12), fill);
    let mut x = rect.left() + 10.0;
    if dot {
        painter.circle_filled(Pos2::new(x + 4.0, rect.center().y), 4.0, tone.dot(t));
        x += dot_room;
    }
    painter.galley(
        Pos2::new(x, rect.center().y - galley.size().y / 2.0),
        galley,
        color,
    );
    response
}

/// An 8-point status dot in `tone`'s colour.
pub fn dot(ui: &mut Ui, tone: Tone) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
    let color = tone.dot(theme::tokens(ui.ctx()));
    ui.painter().circle_filled(rect.center(), 4.0, color);
}

/// A toggle switch (36 × 20) for `on`, named `label` for the accessibility
/// tree; a click or Space flips it.
pub fn toggle(ui: &mut Ui, on: &mut bool, label: &str) -> Response {
    let t = theme::tokens(ui.ctx());
    let (rect, mut response) = ui.allocate_exact_size(vec2(36.0, 20.0), Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let value = *on;
    response.widget_info(|| WidgetInfo::selected(WidgetType::Checkbox, true, value, label));
    let how_on = ui.ctx().animate_bool_with_time(response.id, *on, 0.16);
    let track = if *on { t.accent_fill } else { t.border_strong };
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(10), track);
    let x = egui::lerp(rect.left() + 10.0..=rect.right() - 10.0, how_on);
    painter.circle_filled(Pos2::new(x, rect.center().y), 7.0, Color32::WHITE);
    focus_ring(ui, &response, rect, CornerRadius::same(10), t);
    response
}

/// A segmented control: one of `options`, `selected` by index; a click on a
/// segment selects it.
pub fn segmented(ui: &mut Ui, selected: &mut usize, options: &[&str]) -> Response {
    let t = theme::tokens(ui.ctx());
    let font = theme::font(ui.ctx(), Face::Semibold, 13.0);
    let galleys: Vec<_> = options
        .iter()
        .map(|o| {
            ui.painter()
                .layout_no_wrap((*o).to_owned(), font.clone(), Color32::PLACEHOLDER)
        })
        .collect();
    let width: f32 = galleys.iter().map(|g| g.size().x + 28.0).sum::<f32>() + 6.0;
    let (outer, response) = ui.allocate_exact_size(vec2(width, 36.0), Sense::hover());
    ui.painter().rect(
        outer,
        CornerRadius::same(10),
        t.surface_raised,
        Stroke::new(1.0, t.border_strong),
        StrokeKind::Inside,
    );
    let mut x = outer.left() + 3.0;
    for (i, galley) in galleys.into_iter().enumerate() {
        let segment = Rect::from_min_size(
            Pos2::new(x, outer.top() + 3.0),
            vec2(galley.size().x + 28.0, 30.0),
        );
        x = segment.right();
        let id = response.id.with(i);
        let seg = ui.interact(segment, id, Sense::click());
        if seg.clicked() {
            *selected = i;
        }
        let on = *selected == i;
        let label = options[i];
        seg.widget_info(|| WidgetInfo::selected(WidgetType::SelectableLabel, true, on, label));
        if on {
            ui.painter()
                .rect_filled(segment, CornerRadius::same(8), t.surface_card);
        } else if seg.hovered() {
            ui.painter().rect_filled(
                segment,
                CornerRadius::same(8),
                theme::tint(t.text_primary, 0.06),
            );
        }
        focus_ring(ui, &seg, segment, CornerRadius::same(8), t);
        let color = if on { t.text_primary } else { t.text_secondary };
        ui.painter().galley(
            Pos2::new(
                segment.left() + 14.0,
                segment.center().y - galley.size().y / 2.0,
            ),
            galley,
            color,
        );
    }
    response
}

/// A single-line text field `width` points wide, 40 tall, with `hint` while
/// empty; in JetBrains Mono when `mono` (IDs).
pub fn text_field(ui: &mut Ui, text: &mut String, hint: &str, mono: bool, width: f32) -> Response {
    let t = theme::tokens(ui.ctx());
    let face = if mono { Face::Mono } else { Face::Regular };
    let font = theme::font(ui.ctx(), face, 14.0);
    ui.add(
        egui::TextEdit::singleline(text)
            .hint_text(RichText::new(hint).color(t.text_muted).font(font.clone()))
            .font(font)
            .text_color(t.text_primary)
            .margin(vec2(12.0, 10.0))
            .desired_width(width),
    )
}

/// A page in the sidebar: its icon and name (the rail shows only the icon,
/// with the name in a tooltip and in the accessibility tree). Selected, it
/// sits on the accent tint.
pub fn nav_item(ui: &mut Ui, icon: Icon, label: &str, selected: bool, rail: bool) -> Response {
    let t = theme::tokens(ui.ctx());
    let size = if rail {
        vec2(40.0, 40.0)
    } else {
        vec2(ui.available_width(), 38.0)
    };
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    response
        .widget_info(|| WidgetInfo::selected(WidgetType::SelectableLabel, true, selected, label));
    let hovered = response.hovered();
    let radius = CornerRadius::same(10);
    let painter = ui.painter();
    if selected {
        painter.rect_filled(rect, radius, t.accent_tint);
    } else if hovered {
        painter.rect_filled(rect, radius, t.surface_raised);
    }
    focus_ring(ui, &response, rect, radius, t);
    let icon_color = if selected {
        t.accent_text
    } else if hovered {
        t.text_primary
    } else {
        t.text_secondary
    };
    if rail {
        icons::paint(ui, rect.center(), icon, 18.0, icon_color);
        return response.on_hover_text(label);
    }
    icons::paint(
        ui,
        Pos2::new(rect.left() + 21.0, rect.center().y),
        icon,
        18.0,
        icon_color,
    );
    let text = if selected || hovered {
        t.text_primary
    } else {
        t.text_secondary
    };
    ui.painter().text(
        Pos2::new(rect.left() + 42.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        theme::font(ui.ctx(), Face::Semibold, 14.0),
        text,
    );
    response
}

/// A countdown ring `size` points across: the track, and an arc for the
/// share of the time `left` (0 ..= 1), clockwise from the top.
pub fn countdown_ring(ui: &mut Ui, left: f32, size: f32, color: Color32) -> Response {
    let t = theme::tokens(ui.ctx());
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let center = rect.center();
    let radius = size / 2.0 - 2.0;
    ui.painter()
        .circle_stroke(center, radius, Stroke::new(3.0, t.border_subtle));
    let points = ring_points(center, radius, left);
    if points.len() > 1 {
        ui.painter()
            .add(Shape::line(points, Stroke::new(3.0, color)));
    }
    response
}

/// The arc of a countdown ring: `left` (clamped to 0 ..= 1) of the circle,
/// clockwise from the top, as a polyline of about one point per 6°.
#[must_use]
pub fn ring_points(center: Pos2, radius: f32, left: f32) -> Vec<Pos2> {
    let left = if left.is_finite() {
        left.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let steps = (left * 60.0).ceil() as usize;
    (0..=steps)
        .map(|i| {
            let turn = left * i as f32 / steps.max(1) as f32;
            let angle = -std::f32::consts::FRAC_PI_2 + turn * std::f32::consts::TAU;
            center + radius * Vec2::angled(angle)
        })
        .collect()
}

/// The identicon's colours: fixed here, never chosen by a peer.
pub const IDENTICON_PALETTE: [Color32; 8] = [
    Color32::from_rgb(0x6D, 0x4A, 0xFF),
    Color32::from_rgb(0x1F, 0x9D, 0x8B),
    Color32::from_rgb(0xD9, 0x7A, 0x1E),
    Color32::from_rgb(0x2F, 0x7F, 0xD6),
    Color32::from_rgb(0xC2, 0x3B, 0x7A),
    Color32::from_rgb(0x4E, 0x9A, 0x2F),
    Color32::from_rgb(0x8E, 0x5C, 0xD9),
    Color32::from_rgb(0xB8, 0x4A, 0x32),
];

/// The identicon of a key fingerprint: a 5 × 5 grid mirrored left to right
/// (15 cells from the bits of the first bytes) and a colour from
/// [`IDENTICON_PALETTE`] (the next byte). The same bytes always give the same
/// picture; it helps recognise a device, never replaces comparing its
/// fingerprint.
#[must_use]
pub fn identicon_cells(fingerprint: &[u8]) -> ([[bool; 5]; 5], usize) {
    let bit = |i: usize| {
        fingerprint
            .get(i / 8)
            .is_some_and(|byte| byte >> (i % 8) & 1 == 1)
    };
    let mut cells = [[false; 5]; 5];
    for (row, line) in cells.iter_mut().enumerate() {
        for col in 0..3 {
            let on = bit(row * 3 + col);
            line[col] = on;
            line[4 - col] = on;
        }
    }
    let colour = fingerprint.get(2).map_or(0, |b| usize::from(*b)) % IDENTICON_PALETTE.len();
    (cells, colour)
}

/// The bytes of a fingerprint written in hexadecimal groups ("3f2a 91c0 …"),
/// ignoring anything that is not a hex digit.
#[must_use]
pub fn fingerprint_bytes(fingerprint: &str) -> Vec<u8> {
    let digits: Vec<u8> = fingerprint
        .chars()
        .filter_map(|c| c.to_digit(16))
        .map(|d| d as u8)
        .collect();
    digits
        .chunks(2)
        .map(|p| p.iter().fold(0, |acc, d| acc << 4 | d))
        .collect()
}

/// Draw the identicon of `fingerprint`, `size` points square.
pub fn identicon(ui: &mut Ui, fingerprint: &[u8], size: f32) -> Response {
    let t = theme::tokens(ui.ctx());
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let (cells, colour) = identicon_cells(fingerprint);
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(12), t.surface_raised);
    let inner = rect.shrink(size * 0.18);
    let cell = inner.width() / 5.0;
    for (row, line) in cells.iter().enumerate() {
        for (col, on) in line.iter().enumerate() {
            if *on {
                let min = inner.min + vec2(col as f32 * cell, row as f32 * cell);
                painter.rect_filled(
                    Rect::from_min_size(min, Vec2::splat(cell)),
                    CornerRadius::same(1),
                    IDENTICON_PALETTE[colour],
                );
            }
        }
    }
    response
}

/// The QR code of `text` (error correction M), `size` points square with a
/// white quiet zone of four modules around it: dark modules on white in both
/// themes, as scanners expect. Empty when `text` does not fit a QR code.
pub fn qr_code(ui: &mut Ui, text: &str, size: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Image, true, "QR code"));
    let Some((width, dark)) = qr_modules(text) else {
        return response;
    };
    let quiet = 4;
    let cells = width + 2 * quiet;
    let module = (size / cells as f32).floor().max(1.0);
    let drawn = module * cells as f32;
    let origin = rect.min + Vec2::splat(((size - drawn) / 2.0).floor());
    let painter = ui.painter();
    painter.rect_filled(
        Rect::from_min_size(origin, Vec2::splat(drawn)),
        CornerRadius::same(6),
        Color32::WHITE,
    );
    for (i, _) in dark.iter().enumerate().filter(|(_, on)| **on) {
        let (x, y) = (i % width + quiet, i / width + quiet);
        painter.rect_filled(
            Rect::from_min_size(
                origin + vec2(x as f32 * module, y as f32 * module),
                Vec2::splat(module),
            ),
            0,
            Color32::BLACK,
        );
    }
    response
}

/// The modules of `text`'s QR code (error correction M): its width, and row
/// by row whether each module is dark. `None` when `text` does not fit.
#[must_use]
pub fn qr_modules(text: &str) -> Option<(usize, Vec<bool>)> {
    let code = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M).ok()?;
    let dark = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();
    Some((code.width(), dark))
}

/// A page's title (26 points, bold) and the line under it.
pub fn page_header(ui: &mut Ui, title: &str, subtitle: &str) {
    let t = theme::tokens(ui.ctx());
    ui.label(
        RichText::new(title)
            .font(theme::font(ui.ctx(), Face::Bold, 26.0))
            .color(t.text_primary),
    );
    ui.add_space(-4.0);
    ui.label(
        RichText::new(subtitle)
            .font(theme::font(ui.ctx(), Face::Regular, 13.0))
            .color(t.text_secondary),
    );
}

/// A section's title (16 points, semibold).
pub fn section_header(ui: &mut Ui, title: &str) {
    let t = theme::tokens(ui.ctx());
    ui.label(
        RichText::new(title)
            .font(theme::font(ui.ctx(), Face::Semibold, 16.0))
            .color(t.text_primary),
    );
}

/// A small upper-case label over a value ("YOUR TORNECT ID").
pub fn caps_label(ui: &mut Ui, text: &str) {
    let t = theme::tokens(ui.ctx());
    ui.label(
        RichText::new(text.to_uppercase())
            .font(theme::font(ui.ctx(), Face::Semibold, 11.0))
            .extra_letter_spacing(0.9)
            .color(t.text_muted),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The identicon is a pure function of the fingerprint, mirrored left to
    /// right, and its colour is always one of the fixed palette's.
    #[test]
    fn the_identicon_is_mirrored_and_deterministic() {
        let a = fingerprint_bytes("3f2a 91c0 77de 0b14");
        assert_eq!(a, vec![0x3f, 0x2a, 0x91, 0xc0, 0x77, 0xde, 0x0b, 0x14]);
        let (cells, colour) = identicon_cells(&a);
        assert_eq!(identicon_cells(&a), (cells, colour));
        for line in cells {
            assert_eq!(line[0], line[4]);
            assert_eq!(line[1], line[3]);
        }
        assert!(colour < IDENTICON_PALETTE.len());
        let b = fingerprint_bytes("ef01 0000 0000 0000");
        assert_ne!(identicon_cells(&b).0, cells, "another key, another picture");
        assert_eq!(identicon_cells(&[]), ([[false; 5]; 5], 0));
    }

    /// The ring's arc covers the share of time left, clamped, and starts at
    /// the top.
    #[test]
    fn the_ring_draws_the_share_left() {
        let c = Pos2::new(50.0, 50.0);
        let full = ring_points(c, 10.0, 1.0);
        assert!(
            (full[0] - Pos2::new(50.0, 40.0)).length() < 1e-3,
            "{:?}",
            full[0]
        );
        assert!(
            (*full.last().unwrap() - full[0]).length() < 1e-3,
            "a full circle"
        );
        let half = ring_points(c, 10.0, 0.5);
        assert!((*half.last().unwrap() - Pos2::new(50.0, 60.0)).length() < 1e-3);
        assert_eq!(ring_points(c, 10.0, 7.0).len(), full.len(), "clamped to 1");
        assert!(ring_points(c, 10.0, -1.0).len() <= 1);
        assert!(ring_points(c, 10.0, f32::NAN).len() <= 1);
    }

    /// What the widget test's controls hold, and where they were drawn.
    struct Controls {
        on: bool,
        choice: usize,
        pressed: usize,
        toggle: Rect,
        segments: Rect,
    }

    /// One pass of the widget test's controls with `events`.
    fn pass(ctx: &egui::Context, c: &mut Controls, events: Vec<egui::Event>) {
        let raw = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(400.0, 300.0))),
            events,
            ..egui::RawInput::default()
        };
        ctx.run_ui(raw, |ui| {
            theme::ensure(ui.ctx());
            c.toggle = toggle(ui, &mut c.on, "Switch").rect;
            c.segments = segmented(ui, &mut c.choice, &["Dark", "Light"]).rect;
            if Button::new(Kind::Primary, "Go")
                .enabled(false)
                .show(ui)
                .clicked()
            {
                c.pressed += 1;
            }
        })
        .drop_without_applying_deltas();
    }

    /// A primary click at `at`, over two passes.
    fn click(ctx: &egui::Context, c: &mut Controls, at: Pos2) {
        let button = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        pass(ctx, c, vec![egui::Event::PointerMoved(at), button(true)]);
        pass(ctx, c, vec![button(false)]);
    }

    /// A click flips the toggle; a click on a segment selects it; a
    /// disabled button does not answer.
    #[test]
    fn toggles_segments_and_buttons_answer_clicks() {
        let ctx = egui::Context::default();
        let mut c = Controls {
            on: false,
            choice: 0,
            pressed: 0,
            toggle: Rect::NOTHING,
            segments: Rect::NOTHING,
        };
        for _ in 0..2 {
            pass(&ctx, &mut c, Vec::new());
        }
        let at = c.toggle.center();
        click(&ctx, &mut c, at);
        assert!(c.on, "the toggle flipped");
        let light = Pos2::new(c.segments.right() - 20.0, c.segments.center().y);
        click(&ctx, &mut c, light);
        assert_eq!(c.choice, 1, "the second segment");
        assert_eq!(c.pressed, 0);
    }

    /// The QR code is a real one: for an onion address (62 bytes) it is a
    /// version-4 code, 33 modules wide, with the three finder patterns in
    /// their corners, the same for the same text; a text too long for any QR
    /// code gives none.
    #[test]
    fn the_qr_code_is_a_real_one() {
        let onion = tornect_core::TornectId::from_bytes([0; 32]).onion_address();
        assert_eq!(onion.len(), 62);
        let (width, dark) = qr_modules(&onion).expect("fits");
        assert_eq!(width, 33);
        assert_eq!(dark.len(), 33 * 33);
        assert_eq!(qr_modules(&onion).map(|q| q.1), Some(dark.clone()));
        let at = |x: usize, y: usize| dark[y * width + x];
        for (ox, oy) in [(0, 0), (width - 7, 0), (0, width - 7)] {
            for y in 0..7 {
                for x in 0..7 {
                    let ring = x == 0 || y == 0 || x == 6 || y == 6;
                    let core = (2..=4).contains(&x) && (2..=4).contains(&y);
                    assert_eq!(
                        at(ox + x, oy + y),
                        ring || core,
                        "finder at {ox},{oy}: {x},{y}"
                    );
                }
            }
        }
        assert!(qr_modules(&"x".repeat(3000)).is_none());
    }
}
