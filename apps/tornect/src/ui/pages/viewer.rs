//! The stream window (the redesign's S6, `docs/UI_PLAN.md` §8): the picture
//! fills the window; a floating toolbar at the top centre hides itself
//! [`HIDE_AFTER`] after the pointer last moved and comes back at the top
//! edge or on the viewer's chord; the relay line stays below the picture.
//! Drawn from the session's `Viewing` and the window's own [`ViewerState`],
//! which lives in the app's stream window of one session and dies with it,
//! so nothing in it outlives the session. What the user asks for comes back
//! as actions; nothing here sends input.

use std::time::{Duration, Instant};

use egui::{Color32, CornerRadius, RichText, Stroke, vec2};

use super::super::model::Viewing;
use super::super::theme::{self, Tokens};
use super::super::view::Action;

/// How long the toolbar stays after the pointer last moved over the window
/// (the operator's default of 2026-10-07; a constant until the settings
/// page).
pub const HIDE_AFTER: Duration = Duration::from_millis(2500);

/// How near the window's top edge, in points, the pointer brings the toolbar
/// back.
const TOP_EDGE: f32 = 8.0;

/// The relay line: the picture comes through Tor (always shown).
const RELAY_LINE: &str = "Relayed via Tor: quality limited";

/// The pin's name, for the tooltip and the accessibility tree.
const PIN: &str = "Keep this bar shown";

/// One of the toolbar's own controls, as the window asks for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerAction {
    /// The pin: keep the toolbar shown (`true`), or let it hide again.
    Pin(bool),
}

/// What the stream window of one session keeps between frames.
#[derive(Debug, Default)]
pub struct ViewerState {
    /// This computer's screen may be in a picture that leaves it
    /// (`Model::screen_shared`), read every frame: the window then names
    /// nobody.
    pub shared: bool,
    /// The chord took the keyboard back from the remote computer: keys go to
    /// this window's controls until the chord again, or a press on the
    /// picture, gives it back.
    pub keyboard_local: bool,
    /// The pin keeps the toolbar shown (not stored: the operator's default).
    pub pinned: bool,
    /// The toolbar is hidden.
    hidden: bool,
    /// When the pointer last moved over the window while the toolbar showed,
    /// or the toolbar was last called back; `None` before the first frame.
    active_at: Option<Instant>,
    /// Where the pointer was in the last frame.
    pointer: Option<egui::Pos2>,
    /// What the toolbar drew over the window in the last frame, in points:
    /// no press, wheel turn or move there goes to the remote computer.
    areas: Vec<egui::Rect>,
}

impl ViewerState {
    /// Bring the toolbar back (the chord) for another [`HIDE_AFTER`].
    pub fn show_toolbar(&mut self, now: Instant) {
        self.hidden = false;
        self.active_at = Some(now);
    }

    /// Whether the toolbar showed in the last frame.
    #[cfg(test)]
    #[must_use]
    pub fn toolbar_shown(&self) -> bool {
        !self.hidden
    }

    /// What the toolbar drew over the window in the last frame, in points.
    #[must_use]
    pub fn areas(&self) -> &[egui::Rect] {
        &self.areas
    }

    /// Whether the toolbar shows this frame, given where the pointer is and
    /// the window's top edge: it hides [`HIDE_AFTER`] after the pointer last
    /// moved while it showed, unless pinned, and comes back when the pointer
    /// reaches the top edge. While it shows, how long until it may hide.
    fn follow(&mut self, pointer: Option<egui::Pos2>, top: f32, now: Instant) -> Option<Duration> {
        let moved = pointer.is_some() && pointer != self.pointer;
        self.pointer = pointer;
        // Shown when the window opens.
        self.active_at.get_or_insert(now);
        if pointer.is_some_and(|p| p.y <= top + TOP_EDGE) {
            self.show_toolbar(now);
        } else if moved && !self.hidden {
            self.active_at = Some(now);
        }
        if self.hidden {
            return None;
        }
        if self.pinned {
            self.active_at = Some(now);
            return None;
        }
        let until = self.active_at.unwrap_or(now) + HIDE_AFTER;
        if now >= until {
            self.hidden = true;
            None
        } else {
            Some(until - now)
        }
    }
}

/// The level chip's words: from the signed accept alone (`Viewing`'s
/// `control`, `administrator` and `unattended`; §B.2.1, §B.8.10), never from
/// the address book or anything the host's label says.
#[must_use]
pub fn chip_text(v: &Viewing) -> &'static str {
    if v.unattended {
        crate::ua_client::badge(v.control, v.administrator)
    } else if v.control && v.administrator {
        "Control · administrator"
    } else if v.control {
        "control"
    } else {
        "view only"
    }
}

/// The level chip's colour, from the same signed level.
fn chip_color(v: &Viewing, t: &Tokens) -> Color32 {
    if v.control && v.administrator {
        t.danger_text
    } else if v.control {
        t.ok
    } else {
        t.text_muted
    }
}

/// The stream window: the picture letterboxed over the whole window, the
/// relay line below it, and the toolbar floating over the picture. Returns
/// where the picture was drawn, in points, once there is one. The host is
/// named only while this screen is not shared (`viewer.shared`).
pub fn stream_window(
    ui: &mut egui::Ui,
    viewing: Option<&Viewing>,
    picture: Option<(egui::TextureId, (u32, u32))>,
    input_sent: u64,
    now: Instant,
    actions: &mut Vec<Action>,
    viewer: &mut ViewerState,
) -> Option<egui::Rect> {
    theme::ensure(ui.ctx());
    let t = theme::tokens(ui.ctx());
    viewer.areas.clear();
    // Outside the picture, so no press there reaches the remote computer;
    // shown whether or not the toolbar is.
    egui::Panel::bottom("viewer-relay")
        .frame(
            egui::Frame::new()
                .fill(t.bg_sidebar)
                .inner_margin(egui::Margin::symmetric(12, 4)),
        )
        .show(ui, |ui| {
            let line = if viewing.is_some() {
                RichText::new(RELAY_LINE).small().color(t.warn)
            } else {
                RichText::new("The session has ended.").small()
            };
            ui.label(line);
        });
    let mut drawn = None;
    egui::CentralPanel::no_frame()
        .frame(egui::Frame::new().fill(Color32::BLACK))
        .show(ui, |ui| {
            let avail = ui.available_rect_before_wrap();
            match picture {
                Some((texture, size)) => {
                    let (x, y, w, h) = super::super::stream::letterbox(
                        (avail.min.x, avail.min.y, avail.width(), avail.height()),
                        size,
                    );
                    let rect = egui::Rect::from_min_size(egui::pos2(x, y), vec2(w, h));
                    ui.painter().image(
                        texture,
                        rect,
                        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                        Color32::WHITE,
                    );
                    // Named for a screen reader, never by the host's name.
                    ui.allocate_rect(rect, egui::Sense::hover())
                        .widget_info(|| {
                            egui::WidgetInfo::labeled(
                                egui::WidgetType::Image,
                                true,
                                "The remote screen",
                            )
                        });
                    drawn = Some(rect);
                }
                None => {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new("Waiting for the first picture…").color(t.text_muted),
                        );
                    });
                }
            }
        });
    if let Some(v) = viewing {
        toolbar(ui.ctx(), v, input_sent, now, actions, viewer);
    }
    drawn
}

/// The floating toolbar, drawn after the picture, over it, while it shows.
fn toolbar(
    ctx: &egui::Context,
    v: &Viewing,
    input_sent: u64,
    now: Instant,
    actions: &mut Vec<Action>,
    viewer: &mut ViewerState,
) {
    // The session's clock and the input sent are not on the toolbar itself.
    let _ = (input_sent, v.since);
    let pointer = ctx.input(|i| i.pointer.latest_pos());
    let top = ctx.content_rect().top();
    if let Some(left) = viewer.follow(pointer, top, now) {
        ctx.request_repaint_after(left);
    }
    if viewer.hidden {
        return;
    }
    let t = theme::tokens(ctx);
    let area = egui::Area::new(egui::Id::new("viewer-toolbar"))
        .anchor(egui::Align2::CENTER_TOP, vec2(0.0, 8.0))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(t.surface_overlay)
                .stroke(Stroke::new(1.0, t.border_subtle))
                .corner_radius(CornerRadius::same(20))
                .shadow(t.popup_shadow)
                .inner_margin(egui::Margin::symmetric(12, 6))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if !viewer.shared {
                            ui.label(RichText::new(&v.host).strong());
                        }
                        ui.label(RichText::new("Tor relay").small().color(t.warn));
                        ui.label(RichText::new(chip_text(v)).color(chip_color(v, t)));
                        if pin(ui, viewer.pinned).clicked() {
                            actions.push(Action::Viewer(ViewerAction::Pin(!viewer.pinned)));
                        }
                        let end = egui::Button::new(
                            RichText::new("End session").color(t.on_sharing).strong(),
                        )
                        .fill(t.sharing_fill);
                        if ui.add(end).clicked() {
                            actions.push(Action::EndViewing);
                        }
                    });
                });
        });
    viewer.areas.push(area.response.rect);
}

/// The pin: a toggle that keeps the toolbar shown. Its only words are its
/// name, in the tooltip and the accessibility tree.
fn pin(ui: &mut egui::Ui, pinned: bool) -> egui::Response {
    let t = theme::tokens(ui.ctx());
    let (rect, response) = ui.allocate_exact_size(vec2(28.0, 28.0), egui::Sense::click());
    response
        .widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Checkbox, true, pinned, PIN));
    let color = if pinned {
        t.accent_text
    } else if response.hovered() {
        t.text_primary
    } else {
        t.text_secondary
    };
    let painter = ui.painter();
    if pinned {
        painter.rect_filled(rect, CornerRadius::same(6), t.accent_tint);
    }
    // A pin: its round head and its needle.
    let head = rect.center() + vec2(2.0, -3.0);
    painter.line_segment(
        [head, rect.center() + vec2(-5.0, 7.0)],
        Stroke::new(1.8, color),
    );
    painter.circle_filled(head, 4.5, color);
    response.on_hover_text(PIN)
}

/// The stream window at 1280 × 760 points, driven one pass at a time with the
/// clock and the events a test gives, as the event loop drives it; its
/// widgets found by their names in the accessibility tree.
#[cfg(test)]
pub(crate) mod testing {
    use std::time::{Duration, Instant};

    use super::{ViewerState, stream_window};
    use crate::ui::model::Viewing;
    use crate::ui::view::Action;

    /// One stream window.
    pub(crate) struct Window {
        pub(crate) ctx: egui::Context,
        pub(crate) start: Instant,
        pub(crate) viewing: Viewing,
        pub(crate) viewer: ViewerState,
        pub(crate) input_sent: u64,
        /// Where the picture was drawn in the last pass, in points.
        pub(crate) drawn: Option<egui::Rect>,
        nodes: Vec<egui::accesskit::Node>,
    }

    impl Window {
        /// A window of a session at `control`, its picture 1600 × 900.
        pub(crate) fn new(control: bool) -> Self {
            let start = Instant::now();
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            Self {
                ctx,
                start,
                viewing: Viewing {
                    host: "Desk".to_owned(),
                    control,
                    administrator: false,
                    unattended: false,
                    since: start,
                    pictures: 1,
                    size: (1600, 900),
                },
                viewer: ViewerState::default(),
                input_sent: 0,
                drawn: None,
                nodes: Vec::new(),
            }
        }

        /// One pass `at` after the window opened, with `events`: what the
        /// user asked for.
        pub(crate) fn pass(&mut self, at: Duration, events: Vec<egui::Event>) -> Vec<Action> {
            let now = self.start + at;
            let raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1280.0, 760.0),
                )),
                time: Some(at.as_secs_f64()),
                events,
                ..egui::RawInput::default()
            };
            let mut actions = Vec::new();
            let mut drawn = None;
            let (viewing, viewer, sent) = (&self.viewing, &mut self.viewer, self.input_sent);
            let out = self.ctx.run_ui(raw, |ui| {
                drawn = stream_window(
                    ui,
                    Some(viewing),
                    Some((egui::TextureId::User(0), (1600, 900))),
                    sent,
                    now,
                    &mut actions,
                    viewer,
                );
            });
            if let Some(update) = &out.platform_output.accesskit_update {
                self.nodes = update.nodes.iter().map(|(_, n)| n.clone()).collect();
            }
            out.drop_without_applying_deltas();
            self.drawn = drawn;
            actions
        }

        /// Every text of the last pass: each node's label, value and
        /// description.
        pub(crate) fn texts(&self) -> Vec<String> {
            self.nodes
                .iter()
                .flat_map(|n| [n.label(), n.value(), n.description()])
                .flatten()
                .map(str::to_owned)
                .collect()
        }

        /// Whether a node named or reading `text` was on screen.
        pub(crate) fn has(&self, text: &str) -> bool {
            self.nodes
                .iter()
                .any(|n| n.label() == Some(text) || n.value() == Some(text))
        }

        /// The centre of the widget whose name or text starts with `text`.
        pub(crate) fn centre(&self, text: &str) -> egui::Pos2 {
            let starts = |t: Option<&str>| t.is_some_and(|t| t.starts_with(text));
            let b = self
                .nodes
                .iter()
                .find(|n| starts(n.label()) || starts(n.value()))
                .and_then(egui::accesskit::Node::bounds)
                .unwrap_or_else(|| panic!("no \"{text}\" on screen"));
            egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32)
        }

        /// A click at `at` on the widget named `text`, in two passes (down,
        /// then up), as egui needs for a click.
        pub(crate) fn click(&mut self, at: Duration, text: &str) -> Vec<Action> {
            let pos = self.centre(text);
            let button = |pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let mut actions = self.pass(at, vec![egui::Event::PointerMoved(pos), button(true)]);
            actions.extend(self.pass(at, vec![button(false)]));
            actions
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::testing::Window;
    use super::*;

    fn ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    /// The toolbar shows when the window opens, hides 2.5 s after the
    /// pointer last moved, does not come back for a move over the picture,
    /// and comes back when the pointer reaches the top edge; moves then keep
    /// it for another 2.5 s.
    #[test]
    fn the_toolbar_hides_after_two_and_a_half_seconds_and_comes_back_at_the_top_edge() {
        let mut w = Window::new(true);
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        assert!(w.has("End session"));
        w.pass(ms(2400), Vec::new());
        assert!(w.has("End session"), "before 2.5 s");
        w.pass(ms(2600), Vec::new());
        assert!(!w.has("End session"), "after 2.5 s");
        assert!(!w.viewer.toolbar_shown());
        w.pass(
            ms(3000),
            vec![egui::Event::PointerMoved(egui::pos2(640.0, 400.0))],
        );
        assert!(!w.has("End session"), "a move over the picture");
        w.pass(
            ms(3100),
            vec![egui::Event::PointerMoved(egui::pos2(640.0, 4.0))],
        );
        w.pass(ms(3100), Vec::new());
        assert!(w.has("End session"), "the top edge");
        w.pass(
            ms(3200),
            vec![egui::Event::PointerMoved(egui::pos2(640.0, 400.0))],
        );
        w.pass(ms(5600), Vec::new());
        assert!(w.has("End session"), "2.4 s after the last move");
        w.pass(ms(5800), Vec::new());
        assert!(!w.has("End session"), "2.6 s after the last move");
    }

    /// The relay line stays on screen with the toolbar hidden.
    #[test]
    fn the_relay_line_shows_with_the_toolbar_hidden() {
        let mut w = Window::new(true);
        w.pass(ms(0), Vec::new());
        w.pass(ms(3000), Vec::new());
        assert!(!w.viewer.toolbar_shown());
        assert!(w.has("Relayed via Tor: quality limited"), "{:?}", w.texts());
    }

    /// End session ends the session with one click, as Stop did.
    #[test]
    fn end_session_ends_with_one_click() {
        let mut w = Window::new(true);
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        assert_eq!(w.click(ms(100), "End session"), vec![Action::EndViewing]);
    }

    /// The chip reads the signed level only: a `Viewing` whose accept did
    /// not say administrator never shows "Control · administrator", whatever
    /// its label, its pictures or its other fields say.
    #[test]
    fn the_chip_never_reads_the_address_book() {
        let mut w = Window::new(true);
        for control in [false, true] {
            for unattended in [false, true] {
                for host in ["Desk", "Control · administrator", "administrator"] {
                    let v = Viewing {
                        host: host.to_owned(),
                        control,
                        administrator: false,
                        unattended,
                        ..w.viewing.clone()
                    };
                    assert!(!chip_text(&v).contains("administrator"), "{v:?}");
                }
            }
        }
        w.viewing.host = "Control".to_owned();
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        let texts = w.texts();
        assert!(texts.iter().any(|t| t == "control"), "{texts:?}");
        assert!(
            !texts.iter().any(|t| t.contains("administrator")),
            "{texts:?}"
        );
    }
}
