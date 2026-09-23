//! The sharing indicator in a window of its own (`docs/PLAN.md` §B.6:
//! "persistent 'screen is being shared' indicator … always — including
//! unattended sessions"; `docs/UI_PLAN.md` §6.3). While any session runs,
//! attended or unattended, control or view-only, a small undecorated window
//! shows who, which mode and the clock, with Stop; it opens at the first
//! session, follows every change, and closes itself at the last end. It is a
//! window apart from the main one, so minimising the main window leaves it up;
//! the main window keeps its banner.
//!
//! The level: the window asks for `WindowLevel::AlwaysOnTop`. X11 honours it
//! through the window manager (`_NET_WM_STATE_ABOVE`, sent once the window is
//! mapped) and Windows through `HWND_TOPMOST`. Wayland lets no client put its
//! own toplevel above the others without layer-shell, which winit does not
//! speak and GNOME does not offer: there the request is ignored, the window is
//! an ordinary toplevel titled [`TITLE`] that the overview and Alt+Tab list,
//! and GNOME's own screen-cast icon shows in the top bar for as long as the
//! portal stream runs. Placement is ignored on Wayland too (the compositor
//! places toplevels); a press on the window moves it on every desktop.
//!
//! Focus: the window asks not to be activated when it opens
//! (`with_active(false)`), which Windows (and macOS) honour. winit has no such
//! request on X11 or Wayland: on X11 the window is a utility window, which
//! mutter does not focus when it maps; elsewhere the desktop's
//! focus-stealing prevention decides.

use winit::dpi::{LogicalSize, PhysicalPosition, PhysicalSize};
use winit::window::{Window, WindowAttributes, WindowLevel};

use super::model::Sharing;

/// The window's title: what Alt+Tab, the overview and the taskbar show.
pub const TITLE: &str = "Tornect: sharing";
/// Width, in logical pixels.
const WIDTH: f64 = 420.0;
/// Height of one session's two lines, in logical pixels.
const ROW: f64 = 40.0;
/// Space above and below the rows, in logical pixels.
const PAD: f64 = 8.0;
/// From the monitor's right edge, in logical pixels.
const MARGIN_RIGHT: f64 = 16.0;
/// From the monitor's top, in logical pixels: below GNOME's top bar and a
/// maximised Windows window's caption buttons, which the window would
/// otherwise cover.
const MARGIN_TOP: f64 = 48.0;

/// What the window shows of one session, but for the clock (which moves on
/// its own through egui's repaint timer, not through the model).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Shown {
    session_id: String,
    label: String,
    control: bool,
    /// Whether the viewer's input is injected, once capture has started.
    injected: Option<bool>,
}

impl Shown {
    fn of(s: &Sharing) -> Self {
        Self {
            session_id: s.session_id.clone(),
            label: s.label.clone(),
            control: s.control,
            injected: s.capture.as_ref().map(|c| c.input),
        }
    }
}

/// What the window must do after the model changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Nothing the window shows changed (or nothing is shared and no window
    /// is up).
    Keep,
    /// The first session started: open the window.
    Open,
    /// A session started or ended beside another, or one's mode or input
    /// changed: draw again, at the size for [`Indicator::rows`].
    Redraw,
    /// The last session ended: close the window.
    Close,
}

/// The indicator's state machine, fed the model's shared sessions after
/// every change (no window needed, which is what the tests drive).
#[derive(Debug, Default)]
pub struct Indicator {
    shown: Vec<Shown>,
}

impl Indicator {
    /// Take in the sessions shared now, oldest first; say what the window
    /// must do.
    pub fn sync(&mut self, sharing: &[Sharing]) -> Change {
        let now: Vec<Shown> = sharing.iter().map(Shown::of).collect();
        if now == self.shown {
            return Change::Keep;
        }
        let was_open = !self.shown.is_empty();
        self.shown = now;
        match (was_open, self.shown.is_empty()) {
            (false, _) => Change::Open,
            (true, true) => Change::Close,
            (true, false) => Change::Redraw,
        }
    }

    /// How many sessions the window shows.
    #[must_use]
    pub fn rows(&self) -> usize {
        self.shown.len()
    }
}

/// The window's size for `rows` sessions, in logical pixels (fixed: the user
/// cannot resize it).
#[must_use]
pub fn size(rows: usize) -> LogicalSize<f64> {
    LogicalSize::new(WIDTH, PAD * 2.0 + ROW * rows.max(1) as f64)
}

/// The top-right corner of a monitor at `origin`, `extent` physical pixels
/// wide and high, at `scale`, for a window of `window` logical pixels, inset
/// by the margins; never left of the monitor's own left edge.
#[must_use]
pub fn top_right(
    origin: PhysicalPosition<i32>,
    extent: PhysicalSize<u32>,
    scale: f64,
    window: LogicalSize<f64>,
) -> PhysicalPosition<i32> {
    let x = f64::from(origin.x) + f64::from(extent.width) - (window.width + MARGIN_RIGHT) * scale;
    let y = f64::from(origin.y) + MARGIN_TOP * scale;
    PhysicalPosition::new((x.round() as i32).max(origin.x), y.round() as i32)
}

/// The window as it is asked for: always on top, no decorations, a fixed
/// small size, not activated when it opens, at `position` where the desktop
/// allows placement.
#[must_use]
pub fn attributes(rows: usize, position: Option<PhysicalPosition<i32>>) -> WindowAttributes {
    let mut attrs = Window::default_attributes()
        .with_title(TITLE)
        .with_inner_size(size(rows))
        .with_resizable(false)
        .with_decorations(false)
        .with_window_level(WindowLevel::AlwaysOnTop)
        .with_active(false);
    if let Some(position) = position {
        attrs = attrs.with_position(position);
    }
    // X11: a utility window (`_NET_WM_WINDOW_TYPE_UTILITY`), which window
    // managers such as mutter do not focus when it maps and offer no
    // minimise for; Wayland ignores it.
    #[cfg(target_os = "linux")]
    {
        use winit::platform::x11::{WindowAttributesExtX11 as _, WindowType};
        attrs = attrs.with_x11_window_type(vec![WindowType::Utility]);
    }
    attrs
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use winit::dpi::{Position, Size};

    use super::super::model::CaptureNote;
    use super::super::view::{self, Action};
    use super::*;

    fn session(id: &str, label: &str, control: bool) -> Sharing {
        Sharing {
            session_id: id.to_owned(),
            label: label.to_owned(),
            control,
            since: Instant::now(),
            capture: None,
        }
    }

    fn captured(mut s: Sharing, input: bool) -> Sharing {
        s.capture = Some(CaptureNote {
            source: "wayland",
            width: 1920,
            height: 1080,
            input,
        });
        s
    }

    /// Appears at the first session, stays through the changes, disappears at
    /// the last end, and appears again for the next session.
    #[test]
    fn it_opens_at_the_first_session_and_closes_at_the_last_end() {
        let mut ind = Indicator::default();
        assert_eq!(ind.sync(&[]), Change::Keep, "nothing shared, no window");
        assert_eq!(ind.rows(), 0);

        let a = session("aa", "Laptop", true);
        assert_eq!(ind.sync(std::slice::from_ref(&a)), Change::Open);
        assert_eq!(ind.rows(), 1);
        assert_eq!(ind.sync(std::slice::from_ref(&a)), Change::Keep);

        // A second session beside it (the host serves one at a time; the
        // model may still show two while one's end is on its way).
        let b = session("bb", "Phone", false);
        assert_eq!(ind.sync(&[a.clone(), b.clone()]), Change::Redraw);
        assert_eq!(ind.rows(), 2);
        assert_eq!(ind.sync(std::slice::from_ref(&b)), Change::Redraw);
        assert_eq!(ind.rows(), 1, "one session still runs");
        assert_eq!(ind.sync(&[]), Change::Close, "the last end");
        assert_eq!(ind.rows(), 0);
        assert_eq!(ind.sync(&[]), Change::Keep);

        assert_eq!(ind.sync(&[session("cc", "Laptop", false)]), Change::Open);
    }

    /// What the window shows changes with the session's mode and with what
    /// capture reports about input; the clock alone is no change.
    #[test]
    fn it_redraws_on_a_mode_change() {
        let mut ind = Indicator::default();
        let a = session("aa", "Laptop", true);
        assert_eq!(ind.sync(std::slice::from_ref(&a)), Change::Open);
        // Capture started and injects input.
        assert_eq!(ind.sync(&[captured(a.clone(), true)]), Change::Redraw);
        // Input turned out not to reach the desktop (the grant lacked remote
        // interaction): control in name only.
        assert_eq!(ind.sync(&[captured(a.clone(), false)]), Change::Redraw);
        // The session was replaced by a view-only one without a gap.
        let b = session("bb", "Laptop", false);
        assert_eq!(ind.sync(std::slice::from_ref(&b)), Change::Redraw);
        // Time passing is not a change (the clock ticks by itself).
        let mut later = b.clone();
        later.since -= Duration::from_secs(90);
        assert_eq!(ind.sync(&[later]), Change::Keep);
    }

    /// The window asks for what the indicator needs; whether each desktop
    /// honours it is `NEEDS-DEVICE` (`docs/VERIFICATION.md`).
    #[test]
    fn the_window_is_asked_to_stay_on_top_undecorated_and_unfocused() {
        let at = PhysicalPosition::new(1484, 48);
        let attrs = attributes(1, Some(at));
        assert_eq!(attrs.title, TITLE);
        assert_eq!(attrs.window_level, WindowLevel::AlwaysOnTop);
        assert!(!attrs.decorations, "no title bar");
        assert!(!attrs.resizable, "a fixed size");
        assert!(!attrs.active, "not activated when it opens");
        assert!(attrs.visible);
        assert_eq!(attrs.inner_size, Some(Size::Logical(size(1))));
        assert_eq!(attrs.position, Some(Position::Physical(at)));
        assert_eq!(attributes(1, None).position, None);
        assert!(size(2).height > size(1).height);
        assert_eq!(size(0), size(1));
    }

    /// Top-right of the monitor, inset by the margins, at any scale and on a
    /// monitor that does not start at the origin.
    #[test]
    fn it_goes_to_the_top_right_of_the_monitor() {
        let window = size(1);
        let one = top_right(
            PhysicalPosition::new(0, 0),
            PhysicalSize::new(1920, 1080),
            1.0,
            window,
        );
        assert_eq!(one, PhysicalPosition::new(1920 - 420 - 16, 48));
        let two = top_right(
            PhysicalPosition::new(0, 0),
            PhysicalSize::new(3840, 2160),
            2.0,
            window,
        );
        assert_eq!(two, PhysicalPosition::new(3840 - 2 * (420 + 16), 96));
        let right = top_right(
            PhysicalPosition::new(1920, -200),
            PhysicalSize::new(1280, 1024),
            1.0,
            window,
        );
        assert_eq!(right, PhysicalPosition::new(1920 + 1280 - 436, -200 + 48));
        let narrow = top_right(
            PhysicalPosition::new(100, 0),
            PhysicalSize::new(300, 600),
            1.0,
            window,
        );
        assert_eq!(narrow.x, 100, "never off the monitor's left edge");
    }

    /// Every text the window drew in one pass, with where it was drawn.
    fn texts(
        ctx: &egui::Context,
        raw: egui::RawInput,
        sharing: &[Sharing],
    ) -> (Vec<(String, egui::Rect)>, Vec<Action>) {
        let mut actions = Vec::new();
        let out = ctx.run_ui(raw, |ui| {
            view::indicator(ui, sharing, Instant::now(), &mut actions);
        });
        let mut found = Vec::new();
        for clipped in &out.shapes {
            collect(&clipped.shape, &mut found);
        }
        out.drop_without_applying_deltas();
        (found, actions)
    }

    fn collect(shape: &egui::Shape, into: &mut Vec<(String, egui::Rect)>) {
        match shape {
            egui::Shape::Text(t) => {
                into.push((t.galley.text().to_owned(), t.visual_bounding_rect()))
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, into)),
            _ => {}
        }
    }

    fn window_input() -> egui::RawInput {
        let s = size(1);
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(s.width as f32, s.height as f32),
            )),
            ..egui::RawInput::default()
        }
    }

    /// The window shows who, which mode and the clock, and follows a mode
    /// change; its Stop is the banner's Stop (`StopSharing`, the host-wide
    /// kill), never the end of the session this machine views.
    #[test]
    fn it_shows_who_the_mode_and_the_clock_and_stop_stops_sharing() {
        let ctx = egui::Context::default();
        let mut a = captured(session("aa", "Laptop", true), true);
        a.since = Instant::now() - Duration::from_secs(65);
        let (drawn, actions) = texts(&ctx, window_input(), std::slice::from_ref(&a));
        assert!(actions.is_empty(), "nothing clicked");
        let all: Vec<&str> = drawn.iter().map(|(t, _)| t.as_str()).collect();
        assert!(
            all.iter().any(|t| t.contains("SHARING")
                && t.contains("\"Laptop\"")
                && t.contains("control")
                && t.contains("01:05")),
            "who, mode and clock: {all:?}"
        );
        assert!(
            all.iter().any(|t| t.contains("keyboard and mouse act")),
            "{all:?}"
        );

        // A view-only session in its place: the window says so.
        let b = captured(session("bb", "Laptop", false), true);
        let (drawn, _) = texts(&ctx, window_input(), std::slice::from_ref(&b));
        let all: Vec<&str> = drawn.iter().map(|(t, _)| t.as_str()).collect();
        assert!(all.iter().any(|t| t.contains("view only")), "{all:?}");
        assert!(
            all.iter().any(|t| t.contains("input is ignored")),
            "{all:?}"
        );
        assert!(
            !all.iter().any(|t| t.contains("act on this desktop")),
            "{all:?}"
        );

        // Click Stop: press and release over it.
        let stop = drawn
            .iter()
            .find(|(t, _)| t == "Stop")
            .map(|(_, r)| r.center())
            .expect("a Stop button");
        let click = |pressed: bool| {
            let mut raw = window_input();
            raw.events = vec![
                egui::Event::PointerMoved(stop),
                egui::Event::PointerButton {
                    pos: stop,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ];
            raw
        };
        let (_, pressed) = texts(&ctx, click(true), std::slice::from_ref(&b));
        assert!(
            pressed.is_empty(),
            "a click ends on release; the press moves nothing"
        );
        let (_, released) = texts(&ctx, click(false), std::slice::from_ref(&b));
        assert_eq!(released, vec![Action::StopSharing]);
    }

    /// A press and a drag anywhere but on Stop moves the window (it has no
    /// title bar), and stops nothing.
    #[test]
    fn a_drag_elsewhere_moves_the_window() {
        let ctx = egui::Context::default();
        let a = captured(session("aa", "Laptop", true), true);
        let (_, none) = texts(&ctx, window_input(), std::slice::from_ref(&a));
        assert!(none.is_empty());
        let at = egui::pos2(12.0, 30.0);
        let mut actions = Vec::new();
        for (i, pos) in [at, at, egui::pos2(at.x + 20.0, at.y)]
            .into_iter()
            .enumerate()
        {
            let mut raw = window_input();
            raw.events.push(egui::Event::PointerMoved(pos));
            if i == 1 {
                raw.events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                });
            }
            actions.extend(texts(&ctx, raw, std::slice::from_ref(&a)).1);
        }
        assert_eq!(actions, vec![Action::MoveIndicator]);
    }
}
