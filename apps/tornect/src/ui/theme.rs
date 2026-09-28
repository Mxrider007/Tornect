//! The window's design tokens (the redesign's "night-shift instrument": deep
//! blue-black surfaces, one violet accent for action, colour that carries
//! meaning only where it must), for a dark and a light theme, and how they
//! map onto egui's [`egui::Visuals`]; the fonts, installed once per context by
//! [`ensure`]; and the contrast every text colour must reach on every surface
//! it is drawn on (WCAG 2.x: 4.5:1, 3:1 for large text), which a test
//! computes.
//!
//! Fonts: Manrope for text (400, 500, 600, 700) and JetBrains Mono for what
//! must be compared character by character (IDs, fingerprints, codes; 400,
//! 500, 600), both SIL OFL 1.1, and Lucide's icon font (ISC), all embedded
//! whole (`apps/tornect/assets/`, `packaging/licenses/SOURCES.md`). egui's
//! own fonts stay behind them for any character they lack. A font installed
//! into a context becomes active at its next pass, so every lookup of a
//! named family goes through [`font`], which falls back to the built-in
//! families until then: a context's first pass, a test's bare
//! `egui::Context::default()` included, never names a family it does not
//! have.
//!
//! Nothing here depends on the operating system.

use egui::{
    Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Shadow, Stroke,
    TextStyle, Theme, Visuals,
};

/// Every colour the window uses, for one theme.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tokens {
    /// The window's background.
    pub bg_app: Color32,
    /// The sidebar.
    pub bg_sidebar: Color32,
    /// Cards.
    pub surface_card: Color32,
    /// Inputs, secondary buttons, hovered rows.
    pub surface_raised: Color32,
    /// Menus, popovers, tooltips.
    pub surface_overlay: Color32,
    /// 1 px borders of cards and dividers.
    pub border_subtle: Color32,
    /// 1 px borders of controls.
    pub border_strong: Color32,
    /// A control's border under the pointer.
    pub border_hover: Color32,
    /// Body text.
    pub text_primary: Color32,
    /// Descriptions.
    pub text_secondary: Color32,
    /// Captions.
    pub text_muted: Color32,
    /// Primary buttons, the selected page.
    pub accent_fill: Color32,
    /// A primary button under the pointer.
    pub accent_hover: Color32,
    /// Links, the focus ring, active icons.
    pub accent_text: Color32,
    /// Selected rows and accent chips (translucent).
    pub accent_tint: Color32,
    /// Text on [`Tokens::accent_fill`].
    pub on_accent: Color32,
    /// Connected, reachable.
    pub ok: Color32,
    /// Relayed, waiting, bootstrapping.
    pub warn: Color32,
    /// Errors, destructive actions.
    pub danger_text: Color32,
    /// The sharing banner, the indicator, End session: deep enough for white
    /// text at 4.5:1.
    pub sharing_fill: Color32,
    /// Text on [`Tokens::sharing_fill`].
    pub on_sharing: Color32,
    /// Informational notes.
    pub info: Color32,
    /// A card's shadow (none in the dark theme, where the border does it).
    pub card_shadow: Shadow,
    /// Menus and popovers.
    pub popup_shadow: Shadow,
}

const fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

/// The dark theme (the default).
pub const DARK: Tokens = Tokens {
    bg_app: rgb(0x0B0E13),
    bg_sidebar: rgb(0x0F131A),
    surface_card: rgb(0x141A22),
    surface_raised: rgb(0x1B222C),
    surface_overlay: rgb(0x212A36),
    border_subtle: rgb(0x232C38),
    border_strong: rgb(0x313C4B),
    border_hover: rgb(0x4A5667),
    text_primary: rgb(0xE9EEF4),
    text_secondary: rgb(0xA3AFBD),
    // The design's #7F8B9B reached only 4.2:1 on the overlay surface.
    text_muted: rgb(0x8793A3),
    accent_fill: rgb(0x6D4AFF),
    accent_hover: rgb(0x7B5BFF),
    accent_text: rgb(0xA58BFF),
    accent_tint: Color32::from_rgba_unmultiplied_const(109, 74, 255, 41),
    on_accent: Color32::WHITE,
    ok: rgb(0x3DDC97),
    warn: rgb(0xFFB454),
    danger_text: rgb(0xFF6B7A),
    sharing_fill: rgb(0xD42A40),
    on_sharing: Color32::WHITE,
    info: rgb(0x4FB3FF),
    card_shadow: Shadow::NONE,
    popup_shadow: Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: Color32::from_rgba_unmultiplied_const(0, 0, 0, 89),
    },
};

/// The light theme.
pub const LIGHT: Tokens = Tokens {
    bg_app: rgb(0xF4F6FA),
    bg_sidebar: rgb(0xECEFF5),
    surface_card: rgb(0xFFFFFF),
    surface_raised: rgb(0xF1F3F8),
    surface_overlay: rgb(0xFFFFFF),
    border_subtle: rgb(0xE1E5EC),
    border_strong: rgb(0xC9D0DA),
    border_hover: rgb(0xAEB7C4),
    text_primary: rgb(0x0F1722),
    text_secondary: rgb(0x4A5565),
    text_muted: rgb(0x626B7F),
    accent_fill: rgb(0x6D4AFF),
    accent_hover: rgb(0x5E3BF0),
    accent_text: rgb(0x5A3CE6),
    accent_tint: Color32::from_rgba_unmultiplied_const(109, 74, 255, 26),
    on_accent: Color32::WHITE,
    ok: rgb(0x0B7A50),
    warn: rgb(0x9A5B00),
    danger_text: rgb(0xC21F35),
    sharing_fill: rgb(0xD42A40),
    on_sharing: Color32::WHITE,
    info: rgb(0x1F6FB2),
    card_shadow: Shadow {
        offset: [0, 1],
        blur: 2,
        spread: 0,
        color: Color32::from_rgba_unmultiplied_const(16, 24, 40, 15),
    },
    popup_shadow: Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: Color32::from_rgba_unmultiplied_const(16, 24, 40, 40),
    },
};

impl Tokens {
    /// The tokens of `theme`.
    #[must_use]
    pub const fn of(theme: Theme) -> &'static Self {
        match theme {
            Theme::Dark => &DARK,
            Theme::Light => &LIGHT,
        }
    }
}

/// How opaque a chip's tint of its text colour is.
pub const CHIP_TINT: f32 = 0.12;

/// `colour` at `alpha` (0..=1), as a fill.
#[must_use]
pub fn tint(colour: Color32, alpha: f32) -> Color32 {
    let [r, g, b, _] = colour.to_srgba_unmultiplied();
    Color32::from_rgba_unmultiplied(r, g, b, (alpha.clamp(0.0, 1.0) * 255.0).round() as u8)
}

/// The tokens of the theme `ctx` draws with.
#[must_use]
pub fn tokens(ctx: &egui::Context) -> &'static Tokens {
    Tokens::of(ctx.theme())
}

/// A typeface of the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Face {
    /// Manrope 400: body text.
    Regular,
    /// Manrope 500.
    Medium,
    /// Manrope 600: buttons, titles, navigation.
    Semibold,
    /// Manrope 700.
    Bold,
    /// JetBrains Mono 400.
    Mono,
    /// JetBrains Mono 500: the ID.
    MonoMedium,
    /// JetBrains Mono 600.
    MonoSemibold,
    /// Lucide's icons.
    Icons,
}

/// The font files, as embedded.
const FONTS: [(&str, &[u8]); 8] = [
    (
        "manrope-400",
        include_bytes!("../../assets/fonts/manrope-regular.ttf"),
    ),
    (
        "manrope-500",
        include_bytes!("../../assets/fonts/manrope-medium.ttf"),
    ),
    (
        "manrope-600",
        include_bytes!("../../assets/fonts/manrope-semibold.ttf"),
    ),
    (
        "manrope-700",
        include_bytes!("../../assets/fonts/manrope-bold.ttf"),
    ),
    (
        "mono-400",
        include_bytes!("../../assets/fonts/JetBrainsMono-Regular.ttf"),
    ),
    (
        "mono-500",
        include_bytes!("../../assets/fonts/JetBrainsMono-Medium.ttf"),
    ),
    (
        "mono-600",
        include_bytes!("../../assets/fonts/JetBrainsMono-SemiBold.ttf"),
    ),
    ("lucide", include_bytes!("../../assets/icons/lucide.ttf")),
];

impl Face {
    /// The family this face is drawn with once the fonts are installed.
    #[must_use]
    pub fn family(self) -> FontFamily {
        match self {
            Self::Regular => FontFamily::Proportional,
            Self::Mono => FontFamily::Monospace,
            Self::Medium => FontFamily::Name("manrope-500".into()),
            Self::Semibold => FontFamily::Name("manrope-600".into()),
            Self::Bold => FontFamily::Name("manrope-700".into()),
            Self::MonoMedium => FontFamily::Name("mono-500".into()),
            Self::MonoSemibold => FontFamily::Name("mono-600".into()),
            Self::Icons => FontFamily::Name("icons".into()),
        }
    }

    /// The built-in family that stands in until the fonts are installed.
    #[must_use]
    pub fn fallback(self) -> FontFamily {
        match self {
            Self::Mono | Self::MonoMedium | Self::MonoSemibold => FontFamily::Monospace,
            _ => FontFamily::Proportional,
        }
    }
}

/// The window's fonts: egui's own stay behind Manrope and JetBrains Mono for
/// any character those lack.
#[must_use]
pub fn font_definitions() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    let proportional = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let monospace = fonts
        .families
        .get(&FontFamily::Monospace)
        .cloned()
        .unwrap_or_default();
    for (name, bytes) in FONTS {
        fonts
            .font_data
            .insert(name.to_owned(), FontData::from_static(bytes).into());
    }
    let with = |first: &str, rest: &[String]| {
        let mut list = vec![first.to_owned()];
        list.extend(rest.iter().cloned());
        list
    };
    fonts
        .families
        .insert(FontFamily::Proportional, with("manrope-400", &proportional));
    fonts
        .families
        .insert(FontFamily::Monospace, with("mono-400", &monospace));
    for name in ["manrope-500", "manrope-600", "manrope-700"] {
        fonts
            .families
            .insert(FontFamily::Name(name.into()), with(name, &proportional));
    }
    for name in ["mono-500", "mono-600"] {
        fonts
            .families
            .insert(FontFamily::Name(name.into()), with(name, &monospace));
    }
    // egui's fonts behind Lucide give it the replacement glyph a family needs.
    fonts.families.insert(
        FontFamily::Name("icons".into()),
        with("lucide", &proportional),
    );
    fonts
}

/// Whether `ctx`'s fonts, in this pass, have `family`.
fn has_family(ctx: &egui::Context, family: &FontFamily) -> bool {
    ctx.fonts(|f| f.definitions().families.contains_key(family))
}

/// The font of `face` at `size` points: the built-in family until the
/// window's fonts are active in `ctx` (see the module's notes).
#[must_use]
pub fn font(ctx: &egui::Context, face: Face, size: f32) -> FontId {
    let family = face.family();
    if matches!(family, FontFamily::Name(_)) && !has_family(ctx, &family) {
        return FontId::new(size, face.fallback());
    }
    FontId::new(size, family)
}

/// Whether the icon font is active in `ctx` (from its second pass on).
#[must_use]
pub fn icons_ready(ctx: &egui::Context) -> bool {
    has_family(ctx, &Face::Icons.family())
}

/// `ctx`'s visuals for `theme`, from its tokens (the redesign's §7 table).
#[must_use]
pub fn visuals(theme: Theme) -> Visuals {
    let t = Tokens::of(theme);
    let mut v = match theme {
        Theme::Dark => Visuals::dark(),
        Theme::Light => Visuals::light(),
    };
    let control = CornerRadius::same(10);
    v.override_text_color = None;
    v.weak_text_color = Some(t.text_muted);
    v.panel_fill = t.bg_app;
    v.window_fill = t.surface_overlay;
    v.window_stroke = Stroke::new(1.0, t.border_subtle);
    v.window_corner_radius = CornerRadius::same(14);
    v.window_shadow = t.popup_shadow;
    v.popup_shadow = t.popup_shadow;
    v.menu_corner_radius = control;
    v.extreme_bg_color = t.surface_raised;
    v.text_edit_bg_color = Some(t.surface_raised);
    v.faint_bg_color = t.surface_raised;
    v.code_bg_color = t.surface_raised;
    v.hyperlink_color = t.accent_text;
    v.warn_fg_color = t.warn;
    v.error_fg_color = t.danger_text;
    v.selection.bg_fill = tint(t.accent_fill, 0.35);
    v.selection.stroke = Stroke::new(1.5, t.accent_text);
    v.text_cursor.stroke = Stroke::new(2.0, t.accent_text);
    let widget = |bg: Color32, border: Stroke, text: Color32| egui::style::WidgetVisuals {
        bg_fill: bg,
        weak_bg_fill: bg,
        bg_stroke: border,
        fg_stroke: Stroke::new(1.5, text),
        corner_radius: control,
        expansion: 0.0,
    };
    v.widgets.noninteractive = widget(
        t.surface_card,
        Stroke::new(1.0, t.border_subtle),
        t.text_primary,
    );
    v.widgets.inactive = widget(
        t.surface_raised,
        Stroke::new(1.0, t.border_strong),
        t.text_primary,
    );
    v.widgets.hovered = widget(
        t.surface_raised,
        Stroke::new(1.0, t.border_hover),
        t.text_primary,
    );
    // Pressed or focused: the focus ring (2 px of the accent text colour).
    v.widgets.active = widget(
        t.surface_raised,
        Stroke::new(2.0, t.accent_text),
        t.text_primary,
    );
    v.widgets.open = v.widgets.active;
    v
}

/// The style of `theme`: its visuals, the type scale (12 caption, 14 body,
/// 20 section) on the built-in families, which Manrope and JetBrains Mono
/// lead once installed, and the 4 px spacing grid.
#[must_use]
pub fn style(theme: Theme) -> egui::Style {
    let mut style = egui::Style {
        visuals: visuals(theme),
        ..egui::Style::default()
    };
    style.text_styles = [
        (TextStyle::Small, FontId::proportional(12.0)),
        (TextStyle::Body, FontId::proportional(14.0)),
        (TextStyle::Button, FontId::proportional(14.0)),
        (TextStyle::Heading, FontId::proportional(20.0)),
        (TextStyle::Monospace, FontId::monospace(13.0)),
    ]
    .into();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    // A scroll bar with room of its own, never over a card's edge.
    style.spacing.scroll = egui::style::ScrollStyle::solid();
    style
}

/// Install the window's fonts and both themes' styles into `ctx`, once: the
/// first thing every window draws. The fonts are active from the next pass.
pub fn ensure(ctx: &egui::Context) {
    let installed = egui::Id::new("tornect-theme-installed");
    if ctx.data(|d| d.get_temp::<bool>(installed)).unwrap_or(false) {
        return;
    }
    ctx.data_mut(|d| d.insert_temp(installed, true));
    ctx.set_fonts(font_definitions());
    ctx.set_style_of(Theme::Dark, style(Theme::Dark));
    ctx.set_style_of(Theme::Light, style(Theme::Light));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    /// Every text colour with every surface it is drawn on, and whether the
    /// text is large (at least 18 px, or 14 px bold: 3:1 suffices), for the
    /// contrast test. Translucent tints are composed over the surface they
    /// sit on first.
    fn text_pairs(t: &Tokens) -> Vec<(&'static str, Color32, Color32, bool)> {
        let surfaces = [
            ("bg.app", t.bg_app),
            ("bg.sidebar", t.bg_sidebar),
            ("surface.card", t.surface_card),
            ("surface.raised", t.surface_raised),
            ("surface.overlay", t.surface_overlay),
        ];
        let texts = [
            ("text.primary", t.text_primary),
            ("text.secondary", t.text_secondary),
            ("text.muted", t.text_muted),
            ("accent.text", t.accent_text),
            ("ok", t.ok),
            ("warn", t.warn),
            ("danger.text", t.danger_text),
            ("info", t.info),
        ];
        let mut pairs = Vec::new();
        for (text_name, text) in texts {
            for (surface_name, surface) in surfaces {
                let name = leak(format!("{text_name} on {surface_name}"));
                pairs.push((name, text, surface, false));
            }
        }
        // Chips and the selected page: a tint over a card or the sidebar.
        let selected = t.bg_sidebar.blend(t.accent_tint);
        pairs.push((
            "text.primary on the selected page",
            t.text_primary,
            selected,
            false,
        ));
        pairs.push((
            "accent.text on the selected page",
            t.accent_text,
            selected,
            false,
        ));
        for (name, colour) in [
            ("accent.text on its chip", t.accent_text),
            ("ok on its chip", t.ok),
            ("warn on its chip", t.warn),
            ("danger.text on its chip", t.danger_text),
            ("text.secondary on a chip", t.text_secondary),
        ] {
            let chip = t.surface_card.blend(tint(colour, CHIP_TINT));
            let chip = if name.starts_with("text.secondary") {
                t.surface_raised
            } else {
                chip
            };
            pairs.push((name, colour, chip, false));
        }
        pairs.push(("white on accent.fill", t.on_accent, t.accent_fill, false));
        pairs.push(("white on sharing.fill", t.on_sharing, t.sharing_fill, false));
        pairs
    }

    /// WCAG 2.x relative luminance of an opaque colour.
    fn luminance(colour: Color32) -> f64 {
        let channel = |c: u8| {
            let c = f64::from(c) / 255.0;
            if c <= 0.039_28 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        let [r, g, b, _] = colour.to_srgba_unmultiplied();
        0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
    }

    /// WCAG 2.x contrast ratio of two opaque colours (1 ..= 21).
    fn contrast(a: Color32, b: Color32) -> f64 {
        let (la, lb) = (luminance(a), luminance(b));
        let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
        (hi + 0.05) / (lo + 0.05)
    }

    /// UI_PLAN §9 ("contrast AA against tokens verified by a unit test on
    /// the palette"): every text colour reaches 4.5:1 on every surface it is
    /// drawn on (3:1 for large text), in both themes, computed from the
    /// tokens; the sharing red carries white text at 4.5:1.
    #[test]
    fn every_text_pair_reaches_wcag_aa() {
        let mut failures = Vec::new();
        for (theme, tokens) in [("dark", &DARK), ("light", &LIGHT)] {
            for (name, text, surface, large) in text_pairs(tokens) {
                let ratio = contrast(text, surface);
                let needed = if large { 3.0 } else { 4.5 };
                if ratio < needed {
                    failures.push(format!("{theme}: {name} is {ratio:.2}:1 (< {needed})"));
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
        assert!(contrast(Color32::WHITE, DARK.sharing_fill) >= 4.5);
        assert!(contrast(Color32::WHITE, LIGHT.sharing_fill) >= 4.5);
    }

    /// The contrast function against WCAG's own reference points.
    #[test]
    fn contrast_matches_the_wcag_reference_points() {
        assert!((contrast(Color32::BLACK, Color32::WHITE) - 21.0).abs() < 1e-9);
        assert!((contrast(Color32::WHITE, Color32::WHITE) - 1.0).abs() < 1e-9);
        // #767676 on white is the classic 4.54:1.
        let grey = Color32::from_rgb(0x76, 0x76, 0x76);
        assert!((contrast(grey, Color32::WHITE) - 4.54).abs() < 0.01);
    }

    /// The window's fonts are active from a context's second pass: the
    /// named families exist, the body text is Manrope, and before that the
    /// lookups fall back to the built-in families (a first pass never names
    /// a family it does not have).
    #[test]
    fn the_fonts_install_on_the_second_pass_and_fall_back_before() {
        let ctx = egui::Context::default();
        let mut first = None;
        let mut second = None;
        for pass in 0..2 {
            ctx.run_ui(egui::RawInput::default(), |ui| {
                ensure(ui.ctx());
                let id = font(ui.ctx(), Face::Semibold, 14.0);
                if pass == 0 {
                    first = Some(id);
                } else {
                    second = Some(id);
                }
            })
            .drop_without_applying_deltas();
        }
        assert_eq!(first, Some(FontId::proportional(14.0)));
        assert_eq!(
            second,
            Some(FontId::new(14.0, FontFamily::Name("manrope-600".into())))
        );
        let body = ctx.fonts(|f| f.definitions().families[&FontFamily::Proportional].clone());
        assert_eq!(body.first().map(String::as_str), Some("manrope-400"));
        assert!(icons_ready(&ctx));
    }

    /// Both themes are installed; the light one draws on the light tokens.
    #[test]
    fn both_themes_map_their_tokens() {
        let ctx = egui::Context::default();
        ctx.run_ui(egui::RawInput::default(), |ui| ensure(ui.ctx()))
            .drop_without_applying_deltas();
        ctx.set_theme(Theme::Light);
        assert_eq!(ctx.global_style().visuals.panel_fill, LIGHT.bg_app);
        assert_eq!(tokens(&ctx).bg_app, LIGHT.bg_app);
        ctx.set_theme(Theme::Dark);
        assert_eq!(ctx.global_style().visuals.panel_fill, DARK.bg_app);
        assert_eq!(
            ctx.global_style().visuals.widgets.active.bg_stroke.color,
            DARK.accent_text,
            "the focus ring"
        );
    }
}
