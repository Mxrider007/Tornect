//! Lucide's icons, drawn from its icon font (`assets/icons/lucide.ttf`, ISC):
//! the glyphs tint with any colour and stay sharp at any scale. The code
//! points come from the release's own `codepoints.json` (Lucide 1.48.0;
//! `packaging/licenses/SOURCES.md`); a test checks each against the font.
//! Icons are drawn beside a widget's text, never inside it, so every label
//! the accessibility tree carries stays plain text.

use egui::{Align2, Color32, Pos2, Sense, Ui, Vec2};

use super::theme::{self, Face};

/// An icon of the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// Home.
    House,
    /// The address book.
    BookUser,
    /// Past sessions.
    History,
    /// Settings.
    SlidersHorizontal,
    /// A computer.
    Monitor,
    /// Copy.
    Copy,
    /// Done.
    Check,
    /// The promise about who may see this screen.
    ShieldCheck,
    /// The Tor network.
    Globe,
    /// Go.
    ArrowRight,
    /// A note.
    Info,
    /// Something went wrong.
    CircleAlert,
    /// Viewing a screen.
    Eye,
    /// Control of a screen.
    MousePointer,
    /// The dark theme.
    Moon,
    /// The light theme.
    Sun,
}

/// Each icon, its name in Lucide, and its code point in the icon font (from
/// `codepoints.json` of `lucide-font-1.48.0.zip`).
pub const GLYPHS: [(Icon, &str, char); 16] = [
    (Icon::House, "house", '\u{e0f5}'),
    (Icon::BookUser, "book-user", '\u{e54d}'),
    (Icon::History, "history", '\u{e1f5}'),
    (Icon::SlidersHorizontal, "sliders-horizontal", '\u{e29a}'),
    (Icon::Monitor, "monitor", '\u{e11d}'),
    (Icon::Copy, "copy", '\u{e09e}'),
    (Icon::Check, "check", '\u{e06c}'),
    (Icon::ShieldCheck, "shield-check", '\u{e1ff}'),
    (Icon::Globe, "globe", '\u{e0e8}'),
    (Icon::ArrowRight, "arrow-right", '\u{e049}'),
    (Icon::Info, "info", '\u{e0f9}'),
    (Icon::CircleAlert, "circle-alert", '\u{e077}'),
    (Icon::Eye, "eye", '\u{e0ba}'),
    (Icon::MousePointer, "mouse-pointer-2", '\u{e1c3}'),
    (Icon::Moon, "moon", '\u{e11e}'),
    (Icon::Sun, "sun", '\u{e178}'),
];

impl Icon {
    /// The icon's code point in the icon font.
    #[must_use]
    pub fn glyph(self) -> char {
        GLYPHS
            .iter()
            .find(|(icon, _, _)| *icon == self)
            .map_or('\u{fffd}', |(_, _, c)| *c)
    }
}

/// Draw `icon` centred on `center`, `size` points tall, in `color`. Before
/// the icon font is active (a context's first pass) it draws nothing.
pub fn paint(ui: &Ui, center: Pos2, icon: Icon, size: f32, color: Color32) {
    if !theme::icons_ready(ui.ctx()) {
        return;
    }
    ui.painter().text(
        center,
        Align2::CENTER_CENTER,
        icon.glyph(),
        theme::font(ui.ctx(), Face::Icons, size),
        color,
    );
}

/// `icon` as a widget of its own, `size` points square: decoration, with no
/// entry in the accessibility tree and no interaction.
pub fn show(ui: &mut Ui, icon: Icon, size: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    paint(ui, rect.center(), icon, size, color);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every icon of the table is in the embedded font, under the code point
    /// the release's metadata gives, and no two icons share one.
    #[test]
    fn every_icon_is_in_the_font() {
        let ctx = egui::Context::default();
        for _ in 0..2 {
            ctx.run_ui(egui::RawInput::default(), |ui| theme::ensure(ui.ctx()))
                .drop_without_applying_deltas();
        }
        let font = egui::FontId::new(18.0, Face::Icons.family());
        for (icon, name, c) in GLYPHS {
            assert!(
                ctx.fonts_mut(|f| f.has_glyph(&font, c)),
                "{name} (U+{:04X}) is not in lucide.ttf",
                u32::from(c)
            );
            assert_eq!(icon.glyph(), c);
        }
        let mut points: Vec<char> = GLYPHS.iter().map(|(_, _, c)| *c).collect();
        points.sort_unstable();
        points.dedup();
        assert_eq!(points.len(), GLYPHS.len());
    }
}
