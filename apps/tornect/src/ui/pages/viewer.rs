//! The stream window (the redesign's S6, `docs/UI_PLAN.md` §8): the picture
//! fills the window; a floating toolbar at the top centre hides itself
//! [`HIDE_AFTER`] after the pointer last moved and comes back at the top
//! edge or on the viewer's chord; the relay line stays below the picture.
//! Drawn from the session's `Viewing` and the window's own [`ViewerState`],
//! which lives in the app's stream window of one session and dies with it,
//! so nothing in it outlives the session. What the user asks for comes back
//! as actions; nothing here sends input.

use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use egui::{Color32, CornerRadius, RichText, Stroke, vec2};

use tornect_signal::messages::notice;

use super::super::model::Viewing;
use super::super::screenshot;
use super::super::theme::{self, Tokens};
use super::super::view::{Action, clock};
use super::super::widgets;

/// How long the toolbar stays after the pointer last moved over the window
/// (the operator's default of 2026-10-07; a constant until the settings
/// page).
pub const HIDE_AFTER: Duration = Duration::from_millis(2500);

/// How near the window's top edge, in points, the pointer brings the toolbar
/// back.
const TOP_EDGE: f32 = 8.0;

/// The relay line: the picture comes through Tor (always shown).
const RELAY_LINE: &str = "Relayed via Tor: quality limited";

/// The strip's line while a session of this computer's own host is live:
/// the strip stays on screen in full screen too, where the window may cover
/// the sharing indicator. It names nobody.
const SHARING_LINE: &str = "This computer's screen is being shared.";

/// The pin's name, for the accessibility tree.
const PIN: &str = "Keep this bar shown";

/// The switch that pauses this computer's input, in a control session.
const PAUSE: &str = "Pause my input";

/// How far the frame rate looks back.
const FPS_OVER: Duration = Duration::from_secs(1);

/// The Screenshot button's name, for the accessibility tree.
const SCREENSHOT: &str = "Save a screenshot";

/// How long a toast stays.
const TOAST_FOR: Duration = Duration::from_millis(3500);

/// The line of a control session whose input cannot reach windows that run
/// as administrator on the host (§B.2.1), said when the host says so.
const ADMIN_WINDOWS: &str =
    "Some windows here run as administrator; your clicks cannot reach them in this session.";

/// Why Ctrl+Alt+Del is greyed towards a host that said it runs Windows.
const NOT_ON_WINDOWS: &str = "not possible on Windows computers";

/// The Fullscreen button's name, for the accessibility tree.
const FULLSCREEN: &str = "Fullscreen";

/// How a screenshot's thread says it went: where the file is, or why not.
type Saved = io::Result<PathBuf>;

/// A short message over the bottom of the picture, for [`TOAST_FOR`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Toast {
    /// A screenshot was saved: the words that say where, from the Pictures
    /// folder's own name on. Never shown while this screen is shared.
    Saved(String),
    /// A screenshot could not be saved.
    NotSaved,
    /// The host's secure Windows screen closed.
    SecureScreenGone,
    /// The window went full screen.
    Fullscreen,
    /// The window left full screen.
    Windowed,
}

impl Toast {
    fn text(&self) -> &str {
        match self {
            Self::Saved(text) => text,
            Self::NotSaved => screenshot::NOT_SAVED,
            Self::SecureScreenGone => crate::secure_screen::NOTICE_GONE,
            Self::Fullscreen => "Fullscreen. Move the pointer to the top edge for this bar.",
            Self::Windowed => "Back to a window",
        }
    }
}

/// One of the toolbar's own controls, as the window asks for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerAction {
    /// The pin: keep the toolbar shown (`true`), or let it hide again.
    Pin(bool),
    /// The connection's details: open them (`true`) or close them.
    Details(bool),
    /// The switch: pause this computer's input (`true`), or resume it.
    Pause(bool),
    /// The Send keys menu: open it (`true`) or close it.
    KeysMenu(bool),
    /// Send a key combination to the remote computer.
    SendKeys(Combo),
    /// Show the picture at its own size, one picture pixel to one pixel of
    /// the screen, with scroll bars (`true`), or fit it to the window.
    OneToOne(bool),
    /// Save the picture as it stands as a PNG on this computer.
    Screenshot,
    /// Show the window full screen (`true`), or as a window again.
    Fullscreen(bool),
}

/// A key combination the Send keys menu sends, in a control session only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Combo {
    /// Ctrl+Alt+Del: sent only to a host that said it does not run Windows
    /// (Windows never takes an injected one to its secure screen).
    CtrlAltDel,
    /// Alt+Tab.
    AltTab,
    /// The Super (Windows) key.
    Super,
    /// Print Screen.
    PrintScreen,
}

impl Combo {
    /// The menu's items, in order.
    pub const ALL: [Self; 4] = [
        Self::CtrlAltDel,
        Self::AltTab,
        Self::Super,
        Self::PrintScreen,
    ];

    /// Its keys as USB usages (`tornect_input::keymap`), pressed in this
    /// order and released in reverse: the left Control, Alt and Super.
    #[must_use]
    pub fn usages(self) -> &'static [u32] {
        match self {
            Self::CtrlAltDel => &[0x07_00e0, 0x07_00e2, 0x07_004c],
            Self::AltTab => &[0x07_00e2, 0x07_002b],
            Self::Super => &[0x07_00e3],
            Self::PrintScreen => &[0x07_0046],
        }
    }

    /// Its words in the menu.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::CtrlAltDel => "Ctrl+Alt+Del",
            Self::AltTab => "Alt+Tab",
            Self::Super => "Super (Windows key)",
            Self::PrintScreen => "Print Screen",
        }
    }
}

/// What the stream window of one session keeps between frames.
#[derive(Debug, Default)]
pub struct ViewerState {
    /// This computer's screen may be in a picture that leaves it
    /// (`Model::screen_shared`), read every frame: the window then names
    /// nobody.
    pub shared: bool,
    /// A session of this computer's own host is live (`Model::sharing` is
    /// not empty: the sharing indicator's own condition), read every frame:
    /// the strip below the picture then says this screen is being shared,
    /// in full screen too.
    pub sharing: bool,
    /// The chord took the keyboard back from the remote computer: keys go to
    /// this window's controls until the chord again, or a press on the
    /// picture, gives it back.
    pub keyboard_local: bool,
    /// The pin keeps the toolbar shown (not stored: the operator's default).
    pub pinned: bool,
    /// The connection's details are open.
    pub details: bool,
    /// The Send keys menu is open.
    pub keys_menu: bool,
    /// The picture at its own size with scroll bars, not fitted.
    pub one_to_one: bool,
    /// At its own size, the part of the window that shows the picture in
    /// the last frame, in points; `None` when fitted (all of it shows).
    visible: Option<egui::Rect>,
    /// The host's notice code (decision M1-70): `draw_stream` sets it every
    /// frame, in a control session only; `None` until the host says, so
    /// nothing is known of it in a new session.
    pub host_notice: Option<u8>,
    /// The host's secure screen showed in the last frame.
    secure_shown: bool,
    /// The window is to be full screen: the app tells the window, and
    /// nothing else of it changes (never its title).
    pub fullscreen: bool,
    /// Full screen in the last frame, for its toasts.
    was_fullscreen: bool,
    /// The forwarder's pause as it stands for this frame: `draw_stream`
    /// reads it from the forwarder, its one keeper, before every frame, and
    /// the switch and the note draw it.
    pub input_paused: bool,
    /// `(when, pictures decoded so far)`, one a frame, over the last
    /// [`FPS_OVER`]: the frame rate.
    samples: VecDeque<(Instant, u64)>,
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
    /// The Screenshot button is offered (never in the preview, which writes
    /// nothing on this computer).
    pub screenshots: bool,
    /// The toast on screen, and when it came.
    toast: Option<(Toast, Instant)>,
    /// Where screenshot threads say how they went, read at the next frame.
    saved: Option<(mpsc::Sender<Saved>, mpsc::Receiver<Saved>)>,
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

    /// The part of the window that showed the picture in the last frame, in
    /// points, where it is not all on screen.
    #[must_use]
    pub fn visible(&self) -> Option<egui::Rect> {
        self.visible
    }

    /// Whether the host said it runs Windows; `None` until it says.
    #[must_use]
    pub fn host_windows(&self) -> Option<bool> {
        self.host_notice.map(|code| code & notice::WINDOWS != 0)
    }

    /// The host says a secure Windows screen shows.
    fn secure_screen(&self) -> bool {
        self.host_notice
            .is_some_and(|code| code & notice::SECURE_SCREEN != 0)
    }

    /// The host says this session's input cannot reach its administrator
    /// windows: only ever in a control session not at the administrator
    /// level.
    fn no_admin_windows(&self, v: &Viewing) -> bool {
        v.control
            && !v.administrator
            && self
                .host_notice
                .is_some_and(|code| code & notice::NO_ADMIN_WINDOWS != 0)
    }

    /// Leave full screen (the chord does, after its ReleaseAll).
    pub fn leave_fullscreen(&mut self) {
        self.fullscreen = false;
    }

    /// Say it when the window goes full screen or comes back.
    fn follow_fullscreen(&mut self, now: Instant) {
        if self.fullscreen != self.was_fullscreen {
            let toast = if self.fullscreen {
                Toast::Fullscreen
            } else {
                Toast::Windowed
            };
            self.toast = Some((toast, now));
            self.was_fullscreen = self.fullscreen;
        }
    }

    /// Take the host's notice for this frame: none outside a control
    /// session; when its secure screen closes, the toast says so.
    fn follow_notice(&mut self, control: bool, now: Instant) {
        if !control {
            self.host_notice = None;
        }
        let secure = self.secure_screen();
        if self.secure_shown && !secure {
            self.toast = Some((Toast::SecureScreenGone, now));
        }
        self.secure_shown = secure;
    }

    /// Where a screenshot's thread says how it went: the window takes it at
    /// its next frame.
    pub fn screenshot_done(&mut self) -> mpsc::Sender<Saved> {
        self.saved.get_or_insert_with(mpsc::channel).0.clone()
    }

    /// Take what screenshot threads said since the last frame: the newest
    /// becomes the toast.
    fn collect_screenshots(&mut self, now: Instant) {
        let Some((_, done)) = &self.saved else {
            return;
        };
        while let Ok(saved) = done.try_recv() {
            let toast = match saved {
                Ok(path) => Toast::Saved(screenshot::saved_text(&path)),
                Err(_) => Toast::NotSaved,
            };
            self.toast = Some((toast, now));
        }
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
        if self.pinned || self.details || self.keys_menu {
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

    /// Note how many pictures were decoded by `now`; keep [`FPS_OVER`] of
    /// samples (and the newest one older than that).
    fn sample(&mut self, pictures: u64, now: Instant) {
        self.samples.push_back((now, pictures));
        if let Some(ago) = now.checked_sub(FPS_OVER) {
            while self.samples.get(1).is_some_and(|(at, _)| *at <= ago) {
                self.samples.pop_front();
            }
        }
    }
}

/// The frame rate: the pictures decoded over the last second, from
/// `(when, pictures decoded so far)` samples, oldest first; before a second
/// has passed, those since the oldest sample.
#[must_use]
pub fn fps(samples: &VecDeque<(Instant, u64)>, now: Instant) -> u64 {
    let Some(&(_, latest)) = samples.back() else {
        return 0;
    };
    let ago = now.checked_sub(FPS_OVER);
    let base = samples
        .iter()
        .rev()
        .find(|(at, _)| ago.is_some_and(|ago| *at <= ago))
        .or(samples.front())
        .map_or(latest, |(_, n)| *n);
    latest.saturating_sub(base)
}

/// The note under the toolbar while this computer's input is paused. The
/// host is named only while this screen is not shared.
#[must_use]
pub fn pause_note(v: &Viewing, viewer: &ViewerState) -> String {
    let whom = if viewer.shared {
        "The remote computer"
    } else {
        v.host.as_str()
    };
    format!(
        "Your input is paused: keyboard and mouse stay on this computer. {whom} still shows its \
         screen."
    )
}

/// The help line under the toolbar of a control session: where the keyboard
/// goes, and the chord that takes it back. The host is named only while this
/// screen is not shared.
#[must_use]
pub fn help_line(v: &Viewing, viewer: &ViewerState) -> String {
    if viewer.keyboard_local {
        "Your keyboard stays on this computer. Click the picture or press Ctrl+Alt+Shift+M to \
         give it back."
            .to_owned()
    } else {
        let whom = if viewer.shared {
            "the remote computer"
        } else {
            v.host.as_str()
        };
        format!(
            "While this window has the focus, your keyboard goes to {whom}. Press \
             Ctrl+Alt+Shift+M to take it back and show this bar."
        )
    }
}

/// Where the whole picture lies when shown at its own size (`shown`, in
/// points) and scrolled by `offset` inside `view`: it moves with the scroll
/// offset, and only its part inside `view` is on screen.
#[must_use]
pub fn one_to_one_rect(view: egui::Rect, offset: egui::Vec2, shown: egui::Vec2) -> egui::Rect {
    egui::Rect::from_min_size(view.min - offset, shown)
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
    viewer.visible = None;
    viewer.collect_screenshots(now);
    viewer.follow_notice(viewing.is_some_and(|v| v.control), now);
    viewer.follow_fullscreen(now);
    let sharing = viewer.sharing;
    // Outside the picture, so no press there reaches the remote computer;
    // shown whether or not the toolbar is, and in full screen.
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
            if sharing {
                ui.label(
                    RichText::new(SHARING_LINE)
                        .small()
                        .strong()
                        .color(t.danger_text),
                );
            }
        });
    let mut drawn = None;
    egui::CentralPanel::no_frame()
        .frame(egui::Frame::new().fill(Color32::BLACK))
        .show(ui, |ui| {
            let avail = ui.available_rect_before_wrap();
            match picture {
                Some((texture, size)) if viewer.one_to_one => {
                    let control = viewing.is_some_and(|v| v.control);
                    let (view, rect) = one_to_one(ui, texture, size, control);
                    // The bars, beside the part on screen, are never the host's.
                    for bar in [
                        egui::Rect::from_min_max(
                            egui::pos2(view.right(), avail.top()),
                            avail.right_bottom(),
                        ),
                        egui::Rect::from_min_max(
                            egui::pos2(avail.left(), view.bottom()),
                            avail.right_bottom(),
                        ),
                    ] {
                        if bar.is_positive() {
                            viewer.areas.push(bar);
                        }
                    }
                    viewer.visible = Some(view);
                    drawn = Some(rect);
                }
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
    if let Some(area) = toast(ui.ctx(), viewer, now, t) {
        viewer.areas.push(area);
    }
    drawn
}

/// The toast over the bottom of the picture while it lasts, whether or not
/// the toolbar shows. A saved screenshot's is decided every frame: in a
/// frame where this screen is shared it is dropped, so it never shows then.
/// Returns where it was drawn, in points.
fn toast(
    ctx: &egui::Context,
    viewer: &mut ViewerState,
    now: Instant,
    t: &Tokens,
) -> Option<egui::Rect> {
    if viewer.shared && matches!(viewer.toast, Some((Toast::Saved(_), _))) {
        viewer.toast = None;
    }
    let (toast, at) = viewer.toast.clone()?;
    let Some(left) = (at + TOAST_FOR)
        .checked_duration_since(now)
        .filter(|left| !left.is_zero())
    else {
        viewer.toast = None;
        return None;
    };
    ctx.request_repaint_after(left);
    let area = egui::Area::new(egui::Id::new("viewer-toast"))
        .anchor(egui::Align2::CENTER_BOTTOM, vec2(0.0, -40.0))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(t.surface_overlay)
                .stroke(Stroke::new(1.0, t.border_subtle))
                .corner_radius(CornerRadius::same(8))
                .shadow(t.popup_shadow)
                .inner_margin(egui::Margin::symmetric(12, 6))
                .show(ui, |ui| {
                    ui.label(toast.text());
                });
        });
    Some(area.response.rect)
}

/// The picture at its own size inside a scroll area with solid bars beside
/// it, never over it. In a control session only the bars scroll it: the
/// wheel goes to the host and a drag is a drag there. Returns the part of the
/// window that shows it and where the whole picture lies, in points.
fn one_to_one(
    ui: &mut egui::Ui,
    texture: egui::TextureId,
    size: (u32, u32),
    control: bool,
) -> (egui::Rect, egui::Rect) {
    let ppp = ui.ctx().pixels_per_point();
    let shown = vec2(size.0 as f32 / ppp, size.1 as f32 / ppp);
    let scrolled = ui
        .scope(|ui| {
            ui.spacing_mut().scroll = egui::style::ScrollStyle::solid();
            egui::ScrollArea::both()
                .id_salt("viewer-picture")
                .auto_shrink(false)
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .scroll_source(egui::scroll_area::ScrollSource {
                    scroll_bar: true,
                    drag: egui::scroll_area::DragScroll::Never,
                    mouse_wheel: !control,
                })
                .show(ui, |ui| {
                    // Named for a screen reader, never by the host's name.
                    let (_, response) = ui.allocate_exact_size(shown, egui::Sense::hover());
                    response.widget_info(|| {
                        egui::WidgetInfo::labeled(
                            egui::WidgetType::Image,
                            true,
                            "The remote screen",
                        )
                    });
                })
        })
        .inner;
    let view = scrolled.inner_rect;
    let rect = one_to_one_rect(view, scrolled.state.offset, shown);
    ui.painter_at(view).image(
        texture,
        rect,
        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
        Color32::WHITE,
    );
    (view, rect)
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
    viewer.sample(v.pictures, now);
    let pointer = ctx.input(|i| i.pointer.latest_pos());
    let top = ctx.content_rect().top();
    if let Some(left) = viewer.follow(pointer, top, now) {
        ctx.request_repaint_after(left);
    }
    let t = theme::tokens(ctx);
    if viewer.hidden {
        // The secure screen is said with the toolbar hidden too.
        if viewer.secure_screen() {
            let line = under_pill(ctx, "viewer-secure", top + 8.0, top, |ui| {
                ui.label(RichText::new(crate::secure_screen::NOTICE).color(t.warn));
            });
            viewer.areas.push(line);
        }
        return;
    }
    // The frame rate falls when pictures stop coming: draw again to say so.
    ctx.request_repaint_after(FPS_OVER);
    let rate = fps(&viewer.samples, now);
    let mut badge_clicked = false;
    let (mut keys_clicked, mut keys_at) = (false, None);
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
                        let badge = format!("Tor relay · {rate} fps · {}×{}", v.size.0, v.size.1);
                        let badge = ui.add(
                            egui::Label::new(RichText::new(badge).small().color(t.warn))
                                .sense(egui::Sense::click()),
                        );
                        if badge.clicked() {
                            badge_clicked = true;
                            actions.push(Action::Viewer(ViewerAction::Details(!viewer.details)));
                        }
                        ui.label(RichText::new(chip_text(v)).color(chip_color(v, t)));
                        if v.control {
                            ui.label(RichText::new(PAUSE).small());
                            let mut paused = viewer.input_paused;
                            if widgets::toggle(ui, &mut paused, PAUSE).changed() {
                                actions.push(Action::Viewer(ViewerAction::Pause(paused)));
                            }
                        }
                        for (one_to_one, label) in [(false, "Fit"), (true, "1:1")] {
                            let chosen = viewer.one_to_one == one_to_one;
                            if ui.selectable_label(chosen, label).clicked() && !chosen {
                                actions.push(Action::Viewer(ViewerAction::OneToOne(one_to_one)));
                            }
                        }
                        if corners(ui, viewer.fullscreen).clicked() {
                            let on = !viewer.fullscreen;
                            actions.push(Action::Viewer(ViewerAction::Fullscreen(on)));
                        }
                        if v.control {
                            let send = ui.button("Send keys");
                            if send.clicked() {
                                keys_clicked = true;
                                let open = !viewer.keys_menu;
                                actions.push(Action::Viewer(ViewerAction::KeysMenu(open)));
                            }
                            keys_at = Some(send.rect.left());
                        }
                        if viewer.screenshots && camera(ui).clicked() {
                            actions.push(Action::Viewer(ViewerAction::Screenshot));
                        }
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
    let pill = area.response.rect;
    viewer.areas.push(pill);
    let mut below = pill.bottom() + 4.0;
    if viewer.secure_screen() {
        let line = under_pill(ctx, "viewer-secure", below, top, |ui| {
            ui.label(RichText::new(crate::secure_screen::NOTICE).color(t.warn));
        });
        viewer.areas.push(line);
        below = line.bottom() + 4.0;
    }
    if v.control {
        let help = egui::Area::new(egui::Id::new("viewer-help"))
            .anchor(egui::Align2::CENTER_TOP, vec2(0.0, below - top))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(t.surface_overlay)
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(egui::Margin::symmetric(10, 4))
                    .show(ui, |ui| {
                        let line = if viewer.input_paused {
                            pause_note(v, viewer)
                        } else {
                            help_line(v, viewer)
                        };
                        ui.label(RichText::new(line).small().color(t.text_secondary));
                    });
            });
        viewer.areas.push(help.response.rect);
        below = help.response.rect.bottom() + 4.0;
    }
    let admin_windows = viewer.no_admin_windows(v);
    if admin_windows {
        let line = under_pill(ctx, "viewer-admin-windows", below, top, |ui| {
            ui.label(RichText::new(ADMIN_WINDOWS).small().color(t.warn));
        });
        viewer.areas.push(line);
        below = line.bottom() + 4.0;
    }
    if viewer.details {
        let at = egui::pos2(pill.left(), below);
        let open = details(ctx, v, input_sent, rate, now, at, admin_windows);
        viewer.areas.push(open.response.rect);
        below = open.response.rect.bottom() + 4.0;
        // A press anywhere else closes them (the badge toggles them itself).
        if open.response.clicked_elsewhere() && !badge_clicked {
            actions.push(Action::Viewer(ViewerAction::Details(false)));
        }
    }
    if viewer.keys_menu
        && let Some(left) = keys_at
    {
        let menu = keys_menu(ctx, viewer, egui::pos2(left, below), actions, t);
        viewer.areas.push(menu.response.rect);
        if menu.response.clicked_elsewhere() && !keys_clicked {
            actions.push(Action::Viewer(ViewerAction::KeysMenu(false)));
        }
    }
}

/// A line under the toolbar, `y` points below the window's `top`, centred,
/// on the toolbar's surface. Returns where it was drawn.
fn under_pill(
    ctx: &egui::Context,
    id: &str,
    y: f32,
    top: f32,
    add: impl FnOnce(&mut egui::Ui),
) -> egui::Rect {
    let t = theme::tokens(ctx);
    egui::Area::new(egui::Id::new(id))
        .anchor(egui::Align2::CENTER_TOP, vec2(0.0, y - top))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(t.surface_overlay)
                .corner_radius(CornerRadius::same(8))
                .inner_margin(egui::Margin::symmetric(10, 4))
                .show(ui, add);
        })
        .response
        .rect
}

/// The Send keys menu at `at`: Ctrl+Alt+Del is greyed until the host says
/// it does not run Windows, never sent into a silent loss; towards a host
/// that said it does, the menu says why.
fn keys_menu(
    ctx: &egui::Context,
    viewer: &ViewerState,
    at: egui::Pos2,
    actions: &mut Vec<Action>,
    t: &Tokens,
) -> egui::InnerResponse<()> {
    egui::Area::new(egui::Id::new("viewer-keys"))
        .fixed_pos(at)
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(t.surface_overlay)
                .stroke(Stroke::new(1.0, t.border_subtle))
                .corner_radius(CornerRadius::same(8))
                .shadow(t.popup_shadow)
                .inner_margin(egui::Margin::same(6))
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        for combo in Combo::ALL {
                            let sendable =
                                combo != Combo::CtrlAltDel || viewer.host_windows() == Some(false);
                            let item = egui::Button::new(combo.label()).frame(false);
                            if ui.add_enabled(sendable, item).clicked() {
                                actions.push(Action::Viewer(ViewerAction::SendKeys(combo)));
                            }
                            if combo == Combo::CtrlAltDel && viewer.host_windows() == Some(true) {
                                ui.label(RichText::new(NOT_ON_WINDOWS).small().color(t.text_muted));
                            }
                        }
                    });
                });
        })
}

/// The connection's details, under the toolbar at `at`: the route, the
/// picture, the level (with the administrator-windows line when the host
/// said it, `admin_windows`), the session's clock and, in a control session,
/// the input sent. Nothing in them names the host.
fn details(
    ctx: &egui::Context,
    v: &Viewing,
    input_sent: u64,
    rate: u64,
    now: Instant,
    at: egui::Pos2,
    admin_windows: bool,
) -> egui::InnerResponse<()> {
    let t = theme::tokens(ctx);
    let muted = |text: &str| RichText::new(text).color(t.text_muted);
    egui::Area::new(egui::Id::new("viewer-details"))
        .fixed_pos(at)
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(t.surface_overlay)
                .stroke(Stroke::new(1.0, t.border_subtle))
                .corner_radius(CornerRadius::same(10))
                .shadow(t.popup_shadow)
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| {
                    egui::Grid::new("viewer-details-rows")
                        .num_columns(2)
                        .spacing(vec2(16.0, 6.0))
                        .show(ui, |ui| {
                            ui.label(muted("Route"));
                            ui.vertical(|ui| {
                                ui.label("Relayed through Tor");
                                ui.label(muted("private, and slower than a direct link").small());
                                ui.label(RichText::new(RELAY_LINE).small().color(t.warn));
                            });
                            ui.end_row();
                            ui.label(muted("Picture"));
                            ui.label(format!("{}×{} · {rate} fps", v.size.0, v.size.1));
                            ui.end_row();
                            ui.label(muted("Mode"));
                            ui.vertical(|ui| {
                                ui.label(chip_text(v));
                                if admin_windows {
                                    ui.label(RichText::new(ADMIN_WINDOWS).small().color(t.warn));
                                }
                            });
                            ui.end_row();
                            ui.label(muted("Session"));
                            ui.label(clock(v.since, now));
                            ui.end_row();
                            if v.control {
                                ui.label(muted("Input"));
                                ui.label(format!("{input_sent} events sent"));
                                ui.end_row();
                            }
                        });
                });
        })
}

/// The pin: a toggle that keeps the toolbar shown. Its only words are its
/// name, in the accessibility tree: no tooltip, which would float over the
/// picture beyond the toolbar's areas.
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
    response
}

/// The Fullscreen button: a toggle drawn as four corners. Its only words are
/// its name, in the accessibility tree (no tooltip, as for the pin).
fn corners(ui: &mut egui::Ui, on: bool) -> egui::Response {
    let t = theme::tokens(ui.ctx());
    let (rect, response) = ui.allocate_exact_size(vec2(28.0, 28.0), egui::Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, true, on, FULLSCREEN)
    });
    let color = if on {
        t.accent_text
    } else if response.hovered() {
        t.text_primary
    } else {
        t.text_secondary
    };
    let painter = ui.painter();
    if on {
        painter.rect_filled(rect, CornerRadius::same(6), t.accent_tint);
    }
    let (c, r, arm) = (rect.center(), 7.0, 4.0);
    let stroke = Stroke::new(1.6, color);
    for (sx, sy) in [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
        let corner = c + vec2(sx * r, sy * r);
        painter.line_segment([corner, corner - vec2(sx * arm, 0.0)], stroke);
        painter.line_segment([corner, corner - vec2(0.0, sy * arm)], stroke);
    }
    response
}

/// The Screenshot button: a camera. Its only words are its name, in the
/// accessibility tree (no tooltip, as for the pin).
fn camera(ui: &mut egui::Ui) -> egui::Response {
    let t = theme::tokens(ui.ctx());
    let (rect, response) = ui.allocate_exact_size(vec2(28.0, 28.0), egui::Sense::click());
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, SCREENSHOT));
    let color = if response.hovered() {
        t.text_primary
    } else {
        t.text_secondary
    };
    let painter = ui.painter();
    let centre = rect.center() + vec2(0.0, 1.0);
    // A camera: its body, its lens and its viewfinder.
    painter.rect_stroke(
        egui::Rect::from_center_size(centre, vec2(17.0, 12.0)),
        CornerRadius::same(2),
        Stroke::new(1.6, color),
        egui::StrokeKind::Middle,
    );
    painter.circle_stroke(centre, 3.4, Stroke::new(1.6, color));
    painter.rect_filled(
        egui::Rect::from_center_size(centre + vec2(-3.5, -7.5), vec2(6.0, 2.5)),
        CornerRadius::same(1),
        color,
    );
    response
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

        /// Whether the widget named `text` was disabled in the last pass.
        pub(crate) fn disabled(&self, text: &str) -> bool {
            self.nodes
                .iter()
                .find(|n| n.label() == Some(text))
                .unwrap_or_else(|| panic!("no \"{text}\" on screen"))
                .is_disabled()
        }

        /// The centre of the widget whose name starts with `text` or, where
        /// none does, of the text that starts with it.
        pub(crate) fn centre(&self, text: &str) -> egui::Pos2 {
            let starts = |t: Option<&str>| t.is_some_and(|t| t.starts_with(text));
            let b = self
                .nodes
                .iter()
                .find(|n| starts(n.label()))
                .or_else(|| self.nodes.iter().find(|n| starts(n.value())))
                .and_then(egui::accesskit::Node::bounds)
                .unwrap_or_else(|| panic!("no \"{text}\" on screen"));
            egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32)
        }

        /// The centre of every widget whose name starts with `text`, and of
        /// every text that starts with it: each copy of a line drawn twice.
        pub(crate) fn centres(&self, text: &str) -> Vec<egui::Pos2> {
            let starts = |t: Option<&str>| t.is_some_and(|t| t.starts_with(text));
            self.nodes
                .iter()
                .filter(|n| starts(n.label()) || starts(n.value()))
                .filter_map(egui::accesskit::Node::bounds)
                .map(|b| egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32))
                .collect()
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
    use std::collections::VecDeque;
    use std::io;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

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

    /// The frame rate is the number of pictures decoded over the last
    /// second: thirty a second reads 30, a stall of two seconds 0, and
    /// before a second has passed the pictures since the window opened; the
    /// badge says it with the picture's size.
    #[test]
    fn the_frame_rate_counts_pictures_over_the_last_second() {
        let t0 = Instant::now();
        let mut v = ViewerState::default();
        for i in 0..=90u64 {
            v.sample(i, t0 + ms(i * 100 / 3));
        }
        assert_eq!(fps(&v.samples, t0 + ms(3000)), 30);
        assert!(
            v.samples.len() <= 32,
            "a second of samples: {}",
            v.samples.len()
        );
        v.sample(90, t0 + ms(5000));
        assert_eq!(fps(&v.samples, t0 + ms(5000)), 0);
        let mut v = ViewerState::default();
        for i in 0..=12u64 {
            v.sample(i, t0 + ms(i * 40));
        }
        assert_eq!(fps(&v.samples, t0 + ms(480)), 12);
        assert_eq!(fps(&VecDeque::new(), t0), 0);
        let mut w = Window::new(true);
        for k in 0..=10u64 {
            w.viewing.pictures = 1 + 3 * k;
            w.pass(ms(100 * k), Vec::new());
        }
        assert!(w.has("Tor relay · 30 fps · 1600×900"), "{:?}", w.texts());
    }

    /// The connection's details open from the badge and say the route, the
    /// picture, the level, the session's clock and the input sent; while
    /// this screen is shared nothing in them, nor in the help line, names
    /// the host. A press elsewhere closes them.
    #[test]
    fn the_details_name_no_host_while_this_screen_is_shared() {
        let mut w = Window::new(true);
        w.viewer.shared = true;
        w.input_sent = 7;
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        assert!(!w.has("Route"), "closed at first");
        let asked = w.click(ms(100), "Tor relay");
        assert_eq!(asked, vec![Action::Viewer(ViewerAction::Details(true))]);
        // As the window applies the action.
        w.viewer.details = true;
        w.pass(ms(200), Vec::new());
        w.pass(ms(200), Vec::new());
        for text in [
            "Route",
            "Relayed through Tor",
            "private, and slower than a direct link",
            "Picture",
            "Mode",
            "control",
            "Session",
            "00:00",
            "Input",
            "7 events sent",
        ] {
            assert!(w.has(text), "{text}: {:?}", w.texts());
        }
        let texts = w.texts();
        assert!(!texts.iter().any(|t| t.contains("Desk")), "{texts:?}");
        assert!(
            texts
                .iter()
                .any(|t| t.contains("your keyboard goes to the remote computer")),
            "{texts:?}"
        );
        // The details stay while open, however long the pointer rests.
        w.pass(ms(9000), Vec::new());
        assert!(w.has("Route"));
        // A press on the picture, away from them, closes them.
        let away = egui::pos2(640.0, 600.0);
        let press = |pressed| egui::Event::PointerButton {
            pos: away,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        let mut asked = w.pass(ms(9100), vec![egui::Event::PointerMoved(away), press(true)]);
        asked.extend(w.pass(ms(9100), vec![press(false)]));
        assert_eq!(asked, vec![Action::Viewer(ViewerAction::Details(false))]);
        // In a view-only session there is no input row and no help line.
        let mut w = Window::new(false);
        w.viewer.details = true;
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        assert!(w.has("Route") && !w.has("Input"), "{:?}", w.texts());
        assert!(
            !w.texts().iter().any(|t| t.contains("your keyboard")),
            "{:?}",
            w.texts()
        );
    }

    /// The switch is in the toolbar of a control session only; while paused
    /// the note replaces the help line, naming the host only while this
    /// screen is not shared.
    #[test]
    fn the_pause_switch_is_absent_in_a_view_only_session() {
        let mut w = Window::new(false);
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        assert!(!w.has(PAUSE), "{:?}", w.texts());
        let mut w = Window::new(true);
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        assert!(w.has(PAUSE), "{:?}", w.texts());
        assert_eq!(
            w.click(ms(100), PAUSE),
            vec![Action::Viewer(ViewerAction::Pause(true))]
        );
        for (shared, whom) in [(false, "Desk"), (true, "The remote computer")] {
            w.viewer.input_paused = true;
            w.viewer.shared = shared;
            w.pass(ms(200), Vec::new());
            let note = format!(
                "Your input is paused: keyboard and mouse stay on this computer. {whom} still \
                 shows its screen."
            );
            assert!(w.has(&note), "{:?}", w.texts());
            assert!(
                !w.texts()
                    .iter()
                    .any(|t| t.contains("your keyboard goes to")),
                "{:?}",
                w.texts()
            );
        }
    }

    /// The Send keys menu is in the toolbar of a control session only.
    #[test]
    fn send_keys_is_absent_in_a_view_only_session() {
        let mut w = Window::new(false);
        w.viewer.keys_menu = true;
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        for item in [
            "Send keys",
            "Ctrl+Alt+Del",
            "Alt+Tab",
            "Super (Windows key)",
            "Print Screen",
        ] {
            assert!(!w.has(item), "{item}: {:?}", w.texts());
        }
        let mut w = Window::new(true);
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        assert!(w.has("Send keys"));
        assert_eq!(
            w.click(ms(100), "Send keys"),
            vec![Action::Viewer(ViewerAction::KeysMenu(true))]
        );
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

    /// Whether any text on screen says a screenshot was saved.
    fn says_saved(w: &Window) -> bool {
        w.texts().iter().any(|t| t.contains("Screenshot saved"))
    }

    /// A saved screenshot's toast says where the file went while this
    /// screen is not shared, and goes in the first frame it is: one up when
    /// sharing begins goes and does not come back, and one that comes while
    /// shared never shows. A failure's toast names nothing and shows either
    /// way; a toast goes after 3.5 s.
    #[test]
    fn the_saved_path_is_not_shown_while_this_screen_is_shared() {
        let path = PathBuf::from(
            "/data/account/Pictures/Tornect/Tornect screenshot 2026-10-08 07-30-05.png",
        );
        let saved =
            "Screenshot saved to Pictures/Tornect/Tornect screenshot 2026-10-08 07-30-05.png";
        let mut w = Window::new(true);
        w.pass(ms(0), Vec::new());
        w.viewer.screenshot_done().send(Ok(path.clone())).unwrap();
        w.pass(ms(100), Vec::new());
        w.pass(ms(100), Vec::new());
        assert!(w.has(saved), "{:?}", w.texts());
        // Sharing begins while it is up.
        w.viewer.shared = true;
        w.pass(ms(200), Vec::new());
        w.pass(ms(200), Vec::new());
        assert!(!says_saved(&w), "{:?}", w.texts());
        w.viewer.shared = false;
        w.pass(ms(300), Vec::new());
        w.pass(ms(300), Vec::new());
        assert!(!says_saved(&w), "{:?}", w.texts());
        // Saved while shared.
        w.viewer.shared = true;
        w.viewer.screenshot_done().send(Ok(path)).unwrap();
        w.pass(ms(400), Vec::new());
        w.pass(ms(400), Vec::new());
        assert!(!says_saved(&w), "{:?}", w.texts());
        w.viewer.shared = false;
        w.pass(ms(500), Vec::new());
        w.pass(ms(500), Vec::new());
        assert!(!says_saved(&w), "{:?}", w.texts());
        // A failure, shared or not.
        w.viewer.shared = true;
        w.viewer
            .screenshot_done()
            .send(Err(io::ErrorKind::NotFound.into()))
            .unwrap();
        w.pass(ms(600), Vec::new());
        w.pass(ms(600), Vec::new());
        assert!(
            w.has("The screenshot could not be saved."),
            "{:?}",
            w.texts()
        );
        w.pass(ms(4000), Vec::new());
        assert!(w.has("The screenshot could not be saved."), "3.4 s");
        w.pass(ms(4200), Vec::new());
        assert!(!w.has("The screenshot could not be saved."), "3.6 s");
    }

    /// The saved toast names the Pictures folder by its own name, then
    /// `Tornect` and the file: never the absolute path, which holds the
    /// account's home folder.
    #[test]
    fn the_toast_names_no_absolute_path() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("Pictures")).unwrap();
        let dir = root.path().join("Pictures").join("Tornect");
        let picture = crate::ui::stream::Picture {
            width: 2,
            height: 2,
            rgba: vec![9; 16],
            fresh: false,
        };
        let at = std::time::UNIX_EPOCH + Duration::from_secs(1_791_444_605);
        let path = screenshot::save(&dir, &picture, at).unwrap();
        let mut w = Window::new(false);
        w.viewer.screenshot_done().send(Ok(path)).unwrap();
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        let want =
            "Screenshot saved to Pictures/Tornect/Tornect screenshot 2026-10-08 07-30-05.png";
        assert!(w.has(want), "{:?}", w.texts());
        let absolute = root.path().to_string_lossy().into_owned();
        let parent = root
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        for text in w.texts() {
            assert!(
                !text.contains(&absolute) && !text.contains(&parent),
                "{text}"
            );
        }
        for (path, want) in [
            ("Tornect/a.png", "Screenshot saved to Tornect/a.png"),
            ("/a.png", "Screenshot saved to a.png"),
            ("/b/c/d/e.png", "Screenshot saved to c/d/e.png"),
        ] {
            assert_eq!(screenshot::saved_text(std::path::Path::new(path)), want);
        }
    }

    /// How many of the texts on screen are `text`.
    fn times(w: &Window, text: &str) -> usize {
        w.texts().iter().filter(|t| *t == text).count()
    }

    /// The secure screen: the host's own words over the picture with the
    /// toolbar shown and hidden, their area kept from the remote computer,
    /// no host named; when it closes, the toast says so for 3.5 s.
    #[test]
    fn the_secure_screen_notice_shows_the_plans_words_and_names_no_host() {
        let notice = crate::secure_screen::NOTICE;
        assert_eq!(
            notice,
            "The computer is showing a secure Windows screen; the person there must answer it"
        );
        let mut w = Window::new(true);
        w.viewer.shared = true;
        w.viewer.host_notice = Some(0x05);
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        assert!(w.has(notice), "{:?}", w.texts());
        let texts = w.texts();
        assert!(!texts.iter().any(|t| t.contains("Desk")), "{texts:?}");
        let at = w.centre(notice);
        assert!(w.viewer.areas().iter().any(|r| r.contains(at)), "shown");
        w.pass(ms(3000), Vec::new());
        w.pass(ms(3000), Vec::new());
        assert!(!w.viewer.toolbar_shown());
        assert!(w.has(notice), "hidden: {:?}", w.texts());
        let at = w.centre(notice);
        assert!(w.viewer.areas().iter().any(|r| r.contains(at)), "hidden");
        w.viewer.host_notice = Some(0x01);
        w.pass(ms(3100), Vec::new());
        w.pass(ms(3100), Vec::new());
        assert!(!w.has(notice));
        let gone = crate::secure_screen::NOTICE_GONE;
        assert!(w.has(gone), "{:?}", w.texts());
        w.pass(ms(6500), Vec::new());
        assert!(w.has(gone), "3.4 s");
        w.pass(ms(6700), Vec::new());
        assert!(!w.has(gone), "3.6 s");
    }

    /// The administrator-windows line, under the toolbar and in the details:
    /// only in a control session not at the administrator level, and only
    /// when the host said so.
    #[test]
    fn the_administrator_windows_line_is_said_only_when_the_host_says_so() {
        for (control, administrator) in [(false, false), (true, false), (true, true)] {
            for code in [
                None,
                Some(0x00),
                Some(0x01),
                Some(0x02),
                Some(0x03),
                Some(0x07),
            ] {
                let mut w = Window::new(control);
                w.viewing.administrator = administrator;
                w.viewer.host_notice = code;
                w.pass(ms(0), Vec::new());
                w.pass(ms(0), Vec::new());
                let want = control && !administrator && code.is_some_and(|c| c & 0x02 != 0);
                let case = format!("control {control}, administrator {administrator}, {code:?}");
                assert_eq!(w.has(ADMIN_WINDOWS), want, "{case}: {:?}", w.texts());
                let under = times(&w, ADMIN_WINDOWS);
                w.viewer.details = true;
                w.pass(ms(100), Vec::new());
                w.pass(ms(100), Vec::new());
                if want {
                    assert!(
                        times(&w, ADMIN_WINDOWS) > under,
                        "{case}: in the details too"
                    );
                } else {
                    assert_eq!(times(&w, ADMIN_WINDOWS), 0, "{case}");
                }
            }
        }
    }

    /// A view-only window shows nothing a host sends, whatever the code: no
    /// notice, no line, no platform; and the model hands it none.
    #[test]
    fn a_view_only_session_shows_no_notice_whatever_the_host_sends() {
        let mut w = Window::new(false);
        w.viewer.host_notice = Some(0xff);
        w.viewer.details = true;
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        for text in [
            crate::secure_screen::NOTICE,
            ADMIN_WINDOWS,
            NOT_ON_WINDOWS,
            "Ctrl+Alt+Del",
        ] {
            assert!(
                !w.texts().iter().any(|t| t.contains(text)),
                "{text}: {:?}",
                w.texts()
            );
        }
        assert_eq!(w.viewer.host_windows(), None);
        w.viewer.host_notice = Some(0x00);
        w.pass(ms(100), Vec::new());
        w.pass(ms(100), Vec::new());
        assert!(!w.has(crate::secure_screen::NOTICE_GONE));
        let mut model = crate::ui::model::Model {
            host_notice: Some(0x07),
            ..crate::ui::model::Model::default()
        };
        model.client = crate::ui::model::ClientStage::Live(Viewing {
            control: false,
            ..w.viewing.clone()
        });
        assert_eq!(model.viewer_notice(), None);
        model.client = crate::ui::model::ClientStage::Live(Viewing {
            control: true,
            ..w.viewing.clone()
        });
        assert_eq!(model.viewer_notice(), Some(0x07));
    }

    /// Once the session is over the model hands the window no notice,
    /// whatever the host last said.
    #[test]
    fn the_notice_is_cleared_when_the_session_ends() {
        use crate::ui::model::{ClientStage, Model};
        let w = Window::new(true);
        let mut model = Model {
            host_notice: Some(0x05),
            client: ClientStage::Live(w.viewing.clone()),
            ..Model::default()
        };
        assert_eq!(model.viewer_notice(), Some(0x05));
        for after in [
            ClientStage::Ended("ended".to_owned()),
            ClientStage::Idle,
            ClientStage::Asking,
        ] {
            model.client = after;
            assert_eq!(model.viewer_notice(), None);
        }
    }

    /// While a session of this computer's own host is live, the strip below
    /// the picture says this screen is being shared, windowed and in full
    /// screen, with the toolbar shown and hidden, naming nobody; with no
    /// live session of this computer's host it does not.
    #[test]
    fn the_strip_says_this_screen_is_shared_while_this_computer_shares() {
        assert_eq!(SHARING_LINE, "This computer's screen is being shared.");
        for fullscreen in [false, true] {
            let mut w = Window::new(true);
            w.viewer.fullscreen = fullscreen;
            w.pass(ms(0), Vec::new());
            w.pass(ms(0), Vec::new());
            assert!(!w.has(SHARING_LINE), "{fullscreen}: {:?}", w.texts());
            w.viewer.sharing = true;
            w.viewer.shared = true;
            for at in [100, 3000] {
                w.pass(ms(at), Vec::new());
                w.pass(ms(at), Vec::new());
                let texts = w.texts();
                assert!(w.has(SHARING_LINE), "{fullscreen}, {at} ms: {texts:?}");
                assert!(!texts.iter().any(|t| t.contains("Desk")), "{texts:?}");
            }
            assert!(!w.viewer.toolbar_shown(), "{fullscreen}: the toolbar hid");
            w.viewer.sharing = false;
            w.viewer.shared = false;
            w.pass(ms(3100), Vec::new());
            w.pass(ms(3100), Vec::new());
            assert!(!w.has(SHARING_LINE), "{fullscreen}: {:?}", w.texts());
        }
    }
}
