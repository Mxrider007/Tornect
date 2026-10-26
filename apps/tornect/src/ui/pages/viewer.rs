//! The stream window (the redesign's S6, `docs/UI_PLAN.md` §8): the picture
//! fills the window; a floating toolbar at the top centre hides itself a
//! while after the pointer last moved (2.5 s unless Settings, Display and
//! quality says otherwise) and comes back at the top edge or on the
//! viewer's chord; the relay line stays below the picture.
//! Drawn from the session's `Viewing` and the window's own [`ViewerState`],
//! which lives in the app's stream window of one session and dies with it,
//! so nothing in it outlives the session. What the user asks for comes back
//! as actions; nothing here sends input. The Quality menu (the quality
//! design §3.2) asks the host for a preset in control and view-only
//! sessions alike; the badge and the details say what the host applies and
//! how long each stage takes (§3.3), all of it display only. The Screens
//! menu (the monitors design §2) asks the host for another of its monitors,
//! in either mode too, once the host listed two or more. The session's
//! services (the services design §7.1) add Chat, Files and the Clipboard
//! switch for what the host granted: chat in any session; files and the
//! clipboard only in a control session whose input still reaches the host
//! ([`offered`]). Their panels ([`panels`]) are the window's own areas, so
//! nothing pressed on them reaches the host, and the chat field takes the
//! keyboard from the host the way the chord does.

mod panels;

use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use egui::{Color32, CornerRadius, RichText, Stroke, vec2};

use tornect_core::config::{Picture, QualityPreset, ToolbarHides, Viewer};
use tornect_proto::services::caps;
use tornect_proto::{ALL_MONITORS, HostStats, MonitorEntry, QualityInfo, monitor_status};
use tornect_signal::messages::notice;

pub use self::panels::{FileOp, FilesTab};

use super::super::model::{Ewma, ScreenNote, ScreensView, ViewerServices, Viewing};
use super::super::screenshot;
use super::super::theme::{self, Face, Tokens};
use super::super::view::{Action, clock};
use super::super::widgets;

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

/// The line of a control session whose host said its input reaches nothing
/// there (no injector: on GNOME, the desktop's dialog left "Allow Remote
/// Interaction" off), said when the host says so.
const NO_INPUT_LINE: &str = "The remote computer did not allow control: you can watch, but your \
     mouse and keyboard reach nothing there.";

/// The line of a control session whose input ended when the host's screens
/// changed (`notice::INPUT_LOST`, the monitors design §2), said when the host
/// says so, where [`NO_INPUT_LINE`] would be.
const INPUT_LOST_LINE: &str =
    "Control stopped when the remote computer's screens changed. You can still watch.";

/// The Screens button's name, for the accessibility tree; it reads the
/// screen shown.
const SCREENS: &str = "Screens";

/// The Screens button's hover text.
const SCREENS_HINT: &str = "Show another screen of the remote computer";

/// The Screens button while a request waits for the host's answer.
const SWITCHING: &str = "Switching…";

/// The toast of a request refused as busy, or not sent while another waits.
const STILL_SWITCHING: &str = "Still switching. Try again in a moment.";

/// Why Ctrl+Alt+Del is greyed towards a host that said it runs Windows.
const NOT_ON_WINDOWS: &str = "not possible on Windows computers";

/// The Fullscreen button's name, for the accessibility tree.
const FULLSCREEN: &str = "Fullscreen";

/// The Quality button's words.
const QUALITY: &str = "Quality";

/// Under a pick on its way to the host, in the Quality menu.
const CHANGING: &str = "Changing…";

/// How long "Changing…" waits for the host to say it applies the pick: the
/// gate's interval (at most 2 s), the pictures already on their way (about
/// one Tor round trip) and one encode, with room to spare.
const CHANGING_FOR: Duration = Duration::from_secs(10);

/// A timing line before the host's first means (or this computer's first
/// picture).
const MEASURING: &str = "Measuring…";

/// The Chat button's words (with the unread count: `Chat · 2`).
const CHAT: &str = "Chat";

/// The Chat button's name, for the accessibility tree.
const CHAT_NAME: &str = "Chat with them";

/// The Files button's words.
const FILES: &str = "Files";

/// The words beside the Clipboard switch.
const CLIPBOARD: &str = "Clipboard";

/// The Clipboard switch's name, for the accessibility tree.
const SHARE_CLIPBOARD: &str = "Share the clipboard";

/// A preset's name: in the Quality menu, the badge, the details, the toast
/// and Settings, Display and quality.
#[must_use]
pub const fn quality_name(preset: QualityPreset) -> &'static str {
    match preset {
        QualityPreset::BestQuality => "Best quality",
        QualityPreset::Balanced => "Balanced",
        QualityPreset::BestPerformance => "Best performance",
    }
}

/// A preset's hint under its name in the Quality menu.
#[must_use]
pub fn quality_hint(preset: QualityPreset) -> &'static str {
    match preset {
        QualityPreset::BestQuality => "The sharpest picture; needs the fastest link",
        QualityPreset::Balanced => "A sharp picture at a steady pace",
        QualityPreset::BestPerformance => "The quickest response; a smaller picture",
    }
}

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
    /// The host applies the preset this viewer picked.
    Quality(QualityPreset),
    /// What the host said of its screens ([`screen_toast`]).
    Screens(String),
}

impl Toast {
    fn text(&self) -> &str {
        match self {
            Self::Saved(text) => text,
            Self::NotSaved => screenshot::NOT_SAVED,
            Self::SecureScreenGone => crate::secure_screen::NOTICE_GONE,
            Self::Fullscreen => "Fullscreen. Move the pointer to the top edge for this bar.",
            Self::Windowed => "Back to a window",
            Self::Quality(QualityPreset::BestQuality) => "Quality: Best quality",
            Self::Quality(QualityPreset::Balanced) => "Quality: Balanced",
            Self::Quality(QualityPreset::BestPerformance) => "Quality: Best performance",
            Self::Screens(text) => text,
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
    /// The Quality menu: open it (`true`) or close it.
    QualityMenu(bool),
    /// Ask the host for this preset: in control and view-only sessions
    /// alike, and nothing of the input path changes.
    Quality(QualityPreset),
    /// The Screens menu: open it (`true`) or close it.
    ScreensMenu(bool),
    /// Ask the host to show this monitor of its list (0: all of them): in
    /// control and view-only sessions alike, a viewing choice.
    ShowScreen(u8),
    /// The Chat panel: open it (`true`), which takes the keyboard from the
    /// host for its field, or close it.
    Chat(bool),
    /// The chat field took the focus: the keyboard comes to this window.
    ChatField,
    /// Send what the chat field holds.
    SendChat,
    /// The Files panel: open it (`true`) or close it.
    Files(bool),
    /// Show this tab of the Files panel.
    FilesTab(FilesTab),
    /// The Clipboard switch: share this computer's clipboard (`true`) or
    /// not, both ways.
    Clipboard(bool),
    /// A request of the Files panel for the session's services stream.
    File(FileOp),
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
    /// Alt+F4: the sure way to send it, whatever this computer's desktop
    /// does with the keys themselves (a close request that comes with Alt
    /// held sends F4 too, `app::on_close_request`).
    AltF4,
}

impl Combo {
    /// The menu's items, in order.
    pub const ALL: [Self; 5] = [
        Self::CtrlAltDel,
        Self::AltTab,
        Self::AltF4,
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
            Self::AltF4 => &[0x07_00e2, 0x07_003d],
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
            Self::AltF4 => "Alt+F4",
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
    /// When the toolbar hides after the pointer last moved (the settings'
    /// choice when the session opened; 2.5 s by default, the operator's
    /// default of 2026-10-07).
    pub hides: ToolbarHides,
    /// The badge (the route, the frame rate, the size) is left out of the
    /// toolbar (the settings' choice when the session opened).
    pub badge_off: bool,
    /// The connection's details are open.
    pub details: bool,
    /// The Send keys menu is open.
    pub keys_menu: bool,
    /// The Quality menu is open.
    pub quality_menu: bool,
    /// The Screens menu is open.
    pub screens_menu: bool,
    /// The last of the host's screens' news ([`ScreensView::news`]) this
    /// window took in: each is said at most once.
    screens_seen: u64,
    /// The host said, by the last frame, that this session's input ended
    /// when its screens changed.
    input_lost_shown: bool,
    /// The preset this viewer picked that the host has not said it applies
    /// yet, and when: the menu says "Changing…" under it until the host
    /// says so, or for [`CHANGING_FOR`]. Never set when the window opens.
    quality_wanted: Option<(QualityPreset, Instant)>,
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
    /// The host said, by the last frame, that this session's input reaches
    /// nothing there.
    no_input_shown: bool,
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
    /// How long writing a picture into the texture takes, in milliseconds
    /// (the details' "upload"): `draw_stream` times each.
    pub upload_ms: Ewma,
    /// The Chat panel is open.
    pub chat: bool,
    /// What the chat field holds, not sent yet.
    chat_draft: Draft,
    /// The chat field takes the focus at the next frame: the panel opened,
    /// or a message went.
    chat_focus: bool,
    /// How many of the host's chat lines (`ViewerServices::unread`) the
    /// chat panel showed: the Chat button counts the ones after.
    chat_seen: usize,
    /// The Files panel is open.
    pub files: bool,
    /// The Files panel's tab.
    pub files_tab: FilesTab,
    /// The first listing of each tab was asked for (`[their files, send
    /// files]`), while the panel is open: asked again when it opens anew,
    /// or once the host is no longer locked.
    files_asked: [bool; 2],
    /// Files dropped on this window reach it (`WindowEvent::DroppedFile`:
    /// on X11 and Windows; winit has none on Wayland): "Send files" says
    /// so.
    pub drops: bool,
}

/// What the chat field holds: its `Debug` prints its length only (chat
/// text never reaches a log).
#[derive(Clone, Default, PartialEq, Eq)]
struct Draft(String);

impl std::fmt::Debug for Draft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Draft(<{} chars>)", self.0.chars().count())
    }
}

impl ViewerState {
    /// A new session's window as the settings hold it (Settings, Display
    /// and quality): fitted or at its own size, full screen or not, when the
    /// toolbar hides and whether it shows the badge. Each default is what the
    /// window did before it could be chosen.
    #[must_use]
    pub fn opened(stored: &Viewer) -> Self {
        Self {
            one_to_one: stored.picture == Picture::OneToOne,
            fullscreen: stored.fullscreen_at_open,
            hides: stored.toolbar_hides,
            badge_off: !stored.show_badge,
            ..Self::default()
        }
    }

    /// Bring the toolbar back (the chord) for another while.
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

    /// The host says this control session's input reaches nothing there.
    fn no_input(&self, v: &Viewing) -> bool {
        v.control
            && self
                .host_notice
                .is_some_and(|code| code & notice::NO_INPUT != 0)
    }

    /// The host says this control session's input ended when its screens
    /// changed.
    fn input_lost(&self, v: &Viewing) -> bool {
        v.control
            && self
                .host_notice
                .is_some_and(|code| code & notice::INPUT_LOST != 0)
    }

    /// Take in what the host said of its screens since the last frame: the
    /// newest news that asks for words becomes the toast, once.
    fn follow_screens(&mut self, screens: Option<&ScreensView>, now: Instant) {
        let Some(view) = screens else {
            return;
        };
        if view.news == self.screens_seen {
            return;
        }
        self.screens_seen = view.news;
        if let Some(toast) = screen_toast(view) {
            self.toast = Some((toast, now));
        }
    }

    /// Leave full screen (the chord does, after its ReleaseAll).
    pub fn leave_fullscreen(&mut self) {
        self.fullscreen = false;
    }

    /// The viewer picked `preset` while the host applies `applied`: the
    /// menu closes, and a preset other than the applied one is on its way
    /// ("Changing…") from `now`. Picking the applied one leaves nothing on
    /// its way.
    pub fn pick_quality(
        &mut self,
        preset: QualityPreset,
        applied: Option<QualityPreset>,
        now: Instant,
    ) {
        self.quality_menu = false;
        self.quality_wanted = (applied != Some(preset)).then_some((preset, now));
    }

    /// The preset on its way to the host, if one is.
    #[must_use]
    pub fn changing(&self) -> Option<QualityPreset> {
        self.quality_wanted.map(|(preset, _)| preset)
    }

    /// Follow what the host applies, every frame: once it says it applies
    /// the pick on its way, the toast names the preset; one the host has not
    /// applied after [`CHANGING_FOR`] is dropped, quietly (the check mark
    /// follows the applied preset all along). While one is on its way, how
    /// long until it would be dropped.
    fn follow_quality(&mut self, applied: Option<QualityPreset>, now: Instant) -> Option<Duration> {
        let (wanted, at) = self.quality_wanted?;
        if applied == Some(wanted) {
            self.quality_wanted = None;
            self.toast = Some((Toast::Quality(wanted), now));
            return None;
        }
        let left = (at + CHANGING_FOR)
            .checked_duration_since(now)
            .filter(|left| !left.is_zero());
        if left.is_none() {
            self.quality_wanted = None;
        }
        left
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
    /// session; when its secure screen closes, the toast says so. Only a
    /// code without the bit says that: no code is the session's end, which
    /// says nothing of the host's screen. When the host first says that the
    /// session's input reaches nothing there, the toolbar comes back, so
    /// that the line under it is seen.
    fn follow_notice(&mut self, control: bool, now: Instant) {
        if !control {
            self.host_notice = None;
        }
        let secure = self.secure_screen();
        if self.secure_shown && !secure && self.host_notice.is_some() {
            self.toast = Some((Toast::SecureScreenGone, now));
        }
        self.secure_shown = secure;
        let no_input = self
            .host_notice
            .is_some_and(|code| code & notice::NO_INPUT != 0);
        if no_input && !self.no_input_shown {
            self.show_toolbar(now);
        }
        self.no_input_shown = no_input;
        // Input that ends during the session is said as soon too.
        let input_lost = self
            .host_notice
            .is_some_and(|code| code & notice::INPUT_LOST != 0);
        if input_lost && !self.input_lost_shown {
            self.show_toolbar(now);
        }
        self.input_lost_shown = input_lost;
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
    /// the window's top edge: it hides [`ViewerState::hides`] after the
    /// pointer last moved while it showed (never, if so chosen), unless
    /// pinned, and comes back when the pointer reaches the top edge. While it
    /// shows, how long until it may hide.
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
        if self.pinned
            || self.details
            || self.keys_menu
            || self.quality_menu
            || self.screens_menu
            || self.chat
            || self.files
        {
            self.active_at = Some(now);
            return None;
        }
        let until = self.active_at.unwrap_or(now) + self.hides.after()?;
        if now >= until {
            self.hidden = true;
            None
        } else {
            Some(until - now)
        }
    }

    /// The Chat button's count: the host's chat lines the panel has not
    /// shown; none while it shows them.
    fn unread(&self, services: &ViewerServices) -> usize {
        if self.chat && !self.shared {
            0
        } else {
            services.unread.saturating_sub(self.chat_seen)
        }
    }

    /// Take the keyboard from the host for this window's own field (the
    /// chat's): whatever the host holds down is let go first, as the chord
    /// does. Nothing changes in a session that sends no input.
    pub fn take_keyboard(&mut self, forwarder: &mut crate::ui::stream::Forwarder) {
        forwarder.release_all();
        if forwarder.is_open() {
            self.keyboard_local = true;
        }
    }

    /// Open the Chat panel (`true`), or close it: the Files panel closes,
    /// the field takes the focus at the next frame and the keyboard comes
    /// to this window.
    pub fn open_chat(&mut self, open: bool, forwarder: &mut crate::ui::stream::Forwarder) {
        self.chat = open;
        if open {
            self.files = false;
            self.chat_focus = true;
            self.take_keyboard(forwarder);
        }
    }

    /// Take what the chat field holds, to send; it is left empty, its focus
    /// kept for the next message.
    pub fn take_chat(&mut self) -> String {
        self.chat_focus = true;
        std::mem::take(&mut self.chat_draft.0)
    }

    /// Put `text` in the chat field, as typing it would.
    #[cfg(test)]
    pub(crate) fn write_chat(&mut self, text: &str) {
        text.clone_into(&mut self.chat_draft.0);
    }

    /// Open the Files panel (`true`) on its tab among those `offered`
    /// (`tornect_proto::services::caps`), or close it. Each opening asks
    /// for its tab's first listing anew.
    pub fn open_files(&mut self, open: bool, offered: u16) {
        self.files = open;
        self.files_asked = [false; 2];
        if open {
            self.chat = false;
            if let Some(tab) = FilesTab::shown(self.files_tab, offered) {
                self.files_tab = tab;
            }
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

/// The badge: the route, the preset the host applies once it said (from
/// `BindOk` on), the frame rate measured here and the decoded picture's
/// size: `Tor relay · Balanced · 30 fps · 1600×900`.
#[must_use]
pub fn badge_text(v: &Viewing, rate: u64) -> String {
    let (w, h) = v.size;
    match v.stream.applied_preset() {
        Some(preset) => format!(
            "Tor relay · {} · {rate} fps · {w}×{h}",
            quality_name(preset)
        ),
        None => format!("Tor relay · {rate} fps · {w}×{h}"),
    }
}

/// The details' Quality line: what the host applies, `Balanced · up to 15
/// fps · 1.5 Mbit/s`.
#[must_use]
pub fn quality_text(info: &QualityInfo) -> String {
    let name = tornect_session::quality::preset(info.preset).map(quality_name);
    format!(
        "{} · up to {} fps · {}",
        name.unwrap_or("Another preset"),
        info.max_fps,
        bitrate_text(info.kbps)
    )
}

/// A bitrate as people read it: from 1000 kbit/s in Mbit/s with one
/// decimal (`1.5 Mbit/s`), below that in kbit/s (`800 kbit/s`).
#[must_use]
pub fn bitrate_text(kbps: u32) -> String {
    if kbps >= 1000 {
        let tenths = (u64::from(kbps) + 50) / 100;
        format!("{}.{} Mbit/s", tenths / 10, tenths % 10)
    } else {
        format!("{kbps} kbit/s")
    }
}

/// The details' second Quality line, when the host's desktop (its last
/// `Stats`) is larger than the picture: `Scaled down from 2560×1440`. A
/// desktop that only lost an odd last column or row is not scaled.
#[must_use]
pub fn scaled_text(host: Option<&HostStats>, picture: (u32, u32)) -> Option<String> {
    let host = host?;
    let (w, h) = (u32::from(host.source_width), u32::from(host.source_height));
    let (shown_w, shown_h) = tornect_codec::scale::shown_region(w, h);
    let scaled = picture.0 > 0 && picture.1 > 0 && (shown_w > picture.0 || shown_h > picture.1);
    scaled.then(|| format!("Scaled down from {w}×{h}"))
}

/// The Timing row's first line: this computer's own means, `This
/// computer: decode 3.1 ms · convert 1.2 ms · upload 0.8 ms`.
#[must_use]
pub fn local_timing(decode: Ewma, convert: Ewma, upload: Ewma) -> String {
    match (decode.micros(), convert.micros(), upload.micros()) {
        (Some(decode), Some(convert), Some(upload)) => format!(
            "This computer: decode {} · convert {} · upload {}",
            duration_text(decode),
            duration_text(convert),
            duration_text(upload)
        ),
        _ => format!("This computer: {MEASURING}"),
    }
}

/// The Timing row's second line: the host's means from its last `Stats`,
/// `Remote computer: capture 4.0 ms · scale 2.1 ms · convert 1.5 ms ·
/// encode 9.8 ms · send 120 ms`; "Measuring…" before the first.
#[must_use]
pub fn remote_timing(host: Option<&HostStats>) -> String {
    let Some(s) = host else {
        return format!("Remote computer: {MEASURING}");
    };
    let d = |us: u32| duration_text(u64::from(us));
    format!(
        "Remote computer: capture {} · scale {} · convert {} · encode {} · send {}",
        d(s.grab_us),
        d(s.scale_us),
        d(s.convert_us),
        d(s.encode_us),
        d(s.send_us)
    )
}

/// The Timing row's third line: the host's mean from a picture written to
/// its acknowledgement, `Round trip: 1.1 s`; "Measuring…" before the first
/// `Stats`, and while the host's last one counted no acknowledgement.
#[must_use]
pub fn round_trip_text(host: Option<&HostStats>) -> String {
    match host {
        Some(s) if s.ack_us > 0 => {
            format!("Round trip: {}", duration_text(u64::from(s.ack_us)))
        }
        _ => format!("Round trip: {MEASURING}"),
    }
}

/// A screen as the toolbar and the toasts name it: `Screen 2`, or `All
/// screens` for [`ALL_MONITORS`].
#[must_use]
pub fn screen_name(id: u8) -> String {
    if id == ALL_MONITORS {
        "All screens".to_owned()
    } else {
        format!("Screen {id}")
    }
}

/// A monitor's size as the menu and the details say it, `1920 × 1080`;
/// `None` when the host sent 0×0 (not known).
fn monitor_size(m: &MonitorEntry) -> Option<String> {
    (m.width > 0 && m.height > 0).then(|| format!("{} × {}", m.width, m.height))
}

/// The Screens menu's row of monitor `id`: `Screen 1 · main · 2560 × 1440`;
/// "main" only on the monitor the host marked primary, and no size where
/// it is not known.
#[must_use]
pub fn screen_row(id: u8, m: &MonitorEntry) -> String {
    let mut row = screen_name(id);
    if m.primary {
        row.push_str(" · main");
    }
    if let Some(size) = monitor_size(m) {
        row.push_str(" · ");
        row.push_str(&size);
    }
    row
}

/// The details' Screen row: `Screen 2 of 3 · 1920 × 1080`, or `All 3
/// screens`.
#[must_use]
pub fn screen_detail(view: &ScreensView) -> String {
    let of = view.monitors.len();
    if view.shown == ALL_MONITORS {
        return format!("All {of} screens");
    }
    let mut line = format!("Screen {} of {of}", view.shown);
    if let Some(size) = view
        .monitors
        .get(usize::from(view.shown).wrapping_sub(1))
        .and_then(monitor_size)
    {
        line.push_str(" · ");
        line.push_str(&size);
    }
    line
}

/// What the newest of the host's screens' news says, as a toast (the
/// monitors design §2): a refusal, a request given up or not sent, or the
/// host's own change of what it shows, which includes an answer that shows
/// another screen than the one asked for. An answer that shows the screen
/// asked for, and news that changes nothing shown, say nothing: the button
/// already reads the screen.
fn screen_toast(view: &ScreensView) -> Option<Toast> {
    let text = match view.last? {
        ScreenNote::Refused { status, .. } if status == monitor_status::UNKNOWN => {
            "That screen is not on the remote computer any more.".to_owned()
        }
        ScreenNote::Refused { status, .. } if status == monitor_status::BUSY => {
            STILL_SWITCHING.to_owned()
        }
        ScreenNote::Refused { asked, .. } => {
            let to = if asked == ALL_MONITORS {
                "all screens".to_owned()
            } else {
                screen_name(asked)
            };
            format!("The remote computer could not switch to {to}.")
        }
        ScreenNote::NotSent { .. } => STILL_SWITCHING.to_owned(),
        ScreenNote::NoAnswer { .. } => "The remote computer did not switch screens.".to_owned(),
        ScreenNote::Changed { shown } => {
            let showing = if shown == ALL_MONITORS {
                "all screens".to_owned()
            } else {
                screen_name(shown)
            };
            format!("The remote computer's screens changed. Showing {showing}.")
        }
    };
    Some(Toast::Screens(text))
}

/// A time in µs as the details say it (the quality design §3.3).
fn duration_text(us: u64) -> String {
    crate::host::duration_text(us)
}

/// The services the window offers now (`tornect_proto::services::caps`):
/// what the host's stream has left, paused or not (the panels say so), and
/// the clipboard and files only in a control session whose input still
/// reaches the host: none once the host said its input reaches nothing
/// there or ended (`NO_INPUT`, `INPUT_LOST`), even before the host's `Caps`
/// takes them away. Nothing before the host's `Welcome` or once the stream
/// ended, and nothing from a host that offers no services.
#[must_use]
pub fn offered(v: &Viewing, viewer: &ViewerState) -> u16 {
    let Some(services) = v.services.as_deref() else {
        return 0;
    };
    let left = services.left();
    if v.control && !viewer.no_input(v) && !viewer.input_lost(v) {
        left
    } else {
        left & caps::CHAT
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
    viewer.follow_screens(viewing.and_then(|v| v.screens.as_ref()), now);
    let applied = viewing.and_then(|v| v.stream.applied_preset());
    if let Some(left) = viewer.follow_quality(applied, now) {
        // "Changing…" goes after its time with no picture coming either.
        ui.ctx().request_repaint_after(left);
    }
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
    // The session's services, for what the host granted; a panel whose
    // service went closes.
    let services = v.services.as_deref();
    let offer = offered(v, viewer);
    if offer & caps::CHAT == 0 {
        viewer.chat = false;
    }
    if offer & (caps::UPLOAD | caps::BROWSE) == 0 {
        viewer.files = false;
    }
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
    let (mut quality_clicked, mut quality_at) = (false, None);
    let (mut screens_clicked, mut screens_at) = (false, None);
    // The Screens button: once the host listed two or more monitors.
    let screens = v.screens.as_ref().filter(|s| s.monitors.len() >= 2);
    let mut hint = None;
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
                        if !viewer.badge_off {
                            let badge = badge_text(v, rate);
                            let badge = ui.add(
                                egui::Label::new(RichText::new(badge).small().color(t.warn))
                                    .sense(egui::Sense::click()),
                            );
                            if badge.clicked() {
                                badge_clicked = true;
                                actions
                                    .push(Action::Viewer(ViewerAction::Details(!viewer.details)));
                            }
                        }
                        let chip = RichText::new(chip_text(v)).color(chip_color(v, t));
                        if viewer.badge_off {
                            // The badge is off: the chip opens the details in
                            // its place, and toggles them as the badge does.
                            let chip = ui.add(egui::Label::new(chip).sense(egui::Sense::click()));
                            if chip.clicked() {
                                badge_clicked = true;
                                actions
                                    .push(Action::Viewer(ViewerAction::Details(!viewer.details)));
                            }
                        } else {
                            ui.label(chip);
                        }
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
                        // In control and view-only sessions alike.
                        if let Some(screens) = screens {
                            let button = screens_button(ui, screens);
                            if button.clicked() {
                                screens_clicked = true;
                                let open = !viewer.screens_menu;
                                actions.push(Action::Viewer(ViewerAction::ScreensMenu(open)));
                            }
                            screens_at = Some(button.rect.left());
                            hint = Some(button);
                        }
                        if corners(ui, viewer.fullscreen).clicked() {
                            let on = !viewer.fullscreen;
                            actions.push(Action::Viewer(ViewerAction::Fullscreen(on)));
                        }
                        // In control and view-only sessions alike.
                        let quality = ui.button(QUALITY);
                        if quality.clicked() {
                            quality_clicked = true;
                            let open = !viewer.quality_menu;
                            actions.push(Action::Viewer(ViewerAction::QualityMenu(open)));
                        }
                        quality_at = Some(quality.rect.left());
                        if v.control {
                            let send = ui.button("Send keys");
                            if send.clicked() {
                                keys_clicked = true;
                                let open = !viewer.keys_menu;
                                actions.push(Action::Viewer(ViewerAction::KeysMenu(open)));
                            }
                            keys_at = Some(send.rect.left());
                        }
                        if let Some(services) = services {
                            services_entries(ui, services, offer, actions, viewer);
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
    // The hover text floats over the picture: its area is the window's, so
    // nothing pressed there reaches the remote computer.
    if let Some(shown) = hint.and_then(|button| {
        egui::Tooltip::for_enabled(&button).show(|ui| {
            ui.set_max_width(ui.spacing().tooltip_width);
            ui.label(SCREENS_HINT);
        })
    }) {
        viewer.areas.push(shown.response.rect);
    }
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
    let no_input = viewer.no_input(v);
    if no_input {
        let line = under_pill(ctx, "viewer-no-input", below, top, |ui| {
            ui.label(RichText::new(NO_INPUT_LINE).small().color(t.warn));
        });
        viewer.areas.push(line);
        below = line.bottom() + 4.0;
    }
    // Where the no-input line would be: a control session whose input
    // ended when the host's screens changed.
    let input_lost = viewer.input_lost(v);
    if input_lost {
        let line = under_pill(ctx, "viewer-input-lost", below, top, |ui| {
            ui.label(RichText::new(INPUT_LOST_LINE).small().color(t.warn));
        });
        viewer.areas.push(line);
        below = line.bottom() + 4.0;
    }
    let admin_windows = viewer.no_admin_windows(v);
    if admin_windows {
        let line = under_pill(ctx, "viewer-admin-windows", below, top, |ui| {
            ui.label(RichText::new(ADMIN_WINDOWS).small().color(t.warn));
        });
        viewer.areas.push(line);
        below = line.bottom() + 4.0;
    }
    // The services' panels sit at the right under these lines, beside
    // whatever opens below the toolbar.
    if let Some(services) = services {
        let panel = if viewer.chat {
            Some(panels::chat(ctx, v, services, below - top, actions, viewer))
        } else if viewer.files {
            Some(panels::files(
                ctx,
                services,
                offer,
                below - top,
                actions,
                viewer,
            ))
        } else {
            None
        };
        viewer.areas.extend(panel);
    }
    if viewer.details {
        let at = egui::pos2(pill.left(), below);
        let lines = ModeLines {
            no_input,
            input_lost,
            admin_windows,
        };
        let counts = Counts {
            input_sent,
            rate,
            upload: viewer.upload_ms,
        };
        let open = details(ctx, v, counts, now, at, lines);
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
    if viewer.quality_menu
        && let Some(left) = quality_at
    {
        let applied = v.stream.applied_preset();
        let menu = quality_menu(ctx, viewer, applied, egui::pos2(left, below), actions, t);
        viewer.areas.push(menu.response.rect);
        if menu.response.clicked_elsewhere() && !quality_clicked {
            actions.push(Action::Viewer(ViewerAction::QualityMenu(false)));
        }
    }
    if viewer.screens_menu
        && let (Some(left), Some(listed)) = (screens_at, screens)
    {
        let menu = screens_menu(ctx, listed, egui::pos2(left, below), actions, t);
        viewer.areas.push(menu.response.rect);
        if menu.response.clicked_elsewhere() && !screens_clicked {
            actions.push(Action::Viewer(ViewerAction::ScreensMenu(false)));
        }
    }
}

/// The toolbar's entries for the session's services, each for what is
/// `offer`ed: Chat (with the count of the host's lines not shown yet),
/// Files, and the Clipboard switch where this window shares its clipboard.
fn services_entries(
    ui: &mut egui::Ui,
    services: &ViewerServices,
    offer: u16,
    actions: &mut Vec<Action>,
    viewer: &ViewerState,
) {
    if offer & caps::CHAT != 0 {
        let text = chat_label(viewer.unread(services));
        let chat = ui.add(egui::Button::new(text.as_str()).selected(viewer.chat));
        chat.widget_info(|| {
            let mut info = egui::WidgetInfo::labeled(egui::WidgetType::Button, true, CHAT_NAME);
            info.current_text_value = Some(text.clone());
            info
        });
        if chat.clicked() {
            actions.push(Action::Viewer(ViewerAction::Chat(!viewer.chat)));
        }
    }
    if offer & (caps::UPLOAD | caps::BROWSE) != 0
        && ui
            .add(egui::Button::new(FILES).selected(viewer.files))
            .clicked()
    {
        actions.push(Action::Viewer(ViewerAction::Files(!viewer.files)));
    }
    if offer & caps::CLIP != 0 && services.shares_clipboard {
        ui.label(RichText::new(CLIPBOARD).small());
        let mut on = services.clipboard;
        if widgets::toggle(ui, &mut on, SHARE_CLIPBOARD).changed() {
            actions.push(Action::Viewer(ViewerAction::Clipboard(on)));
        }
    }
}

/// The Chat button's words: `Chat`, or `Chat · 2` with lines of the host's
/// not shown yet.
#[must_use]
pub fn chat_label(unread: usize) -> String {
    if unread == 0 {
        CHAT.to_owned()
    } else {
        format!("{CHAT} · {unread}")
    }
}

/// The Screens button: the screen shown (`Screen 2`, `All screens`), or
/// "Switching…" with a spinner, and no click, while a request waits for the
/// host's answer. Named "Screens" in the accessibility tree, its words as
/// the value.
fn screens_button(ui: &mut egui::Ui, screens: &ScreensView) -> egui::Response {
    let switching = screens.switching.is_some();
    let text = if switching {
        SWITCHING.to_owned()
    } else {
        screen_name(screens.shown)
    };
    if switching {
        ui.add(egui::Spinner::new());
    }
    let button = ui.add_enabled(!switching, egui::Button::new(text.as_str()));
    button.widget_info(|| {
        let mut info = egui::WidgetInfo::labeled(egui::WidgetType::Button, !switching, SCREENS);
        info.current_text_value = Some(text.clone());
        info
    });
    button
}

/// The Screens menu at `at`: a row a monitor, as the host listed them, the
/// one shown checked, then "All screens" where the host offers it. A
/// choice goes to the host and touches nothing of the input path.
fn screens_menu(
    ctx: &egui::Context,
    screens: &ScreensView,
    at: egui::Pos2,
    actions: &mut Vec<Action>,
    t: &Tokens,
) -> egui::InnerResponse<()> {
    let ids = 1..=u8::try_from(screens.monitors.len()).unwrap_or(u8::MAX);
    let mut rows: Vec<(u8, String)> = ids
        .zip(&screens.monitors)
        .map(|(id, m)| (id, screen_row(id, m)))
        .collect();
    if screens.all {
        rows.push((ALL_MONITORS, screen_name(ALL_MONITORS)));
    }
    egui::Area::new(egui::Id::new("viewer-screens"))
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
                        for (id, row) in rows {
                            let on = screens.shown == id;
                            ui.horizontal(|ui| {
                                // The check mark's column, empty but for the
                                // screen shown.
                                let (mark, _) =
                                    ui.allocate_exact_size(vec2(16.0, 20.0), egui::Sense::hover());
                                if on {
                                    ui.painter().text(
                                        mark.center(),
                                        egui::Align2::CENTER_CENTER,
                                        "✓",
                                        theme::font(ui.ctx(), Face::MonoSemibold, 13.0),
                                        t.ok,
                                    );
                                }
                                let item = egui::Button::new(row).frame(false).selected(on);
                                if ui.add(item).clicked() {
                                    actions.push(Action::Viewer(ViewerAction::ShowScreen(id)));
                                }
                            });
                        }
                    });
                });
        })
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

/// The Quality menu at `at`: the three presets, the one the host applies
/// checked (`applied`), each with its hint; a pick on its way says
/// "Changing…" under it. A pick goes to the host and touches nothing of
/// the input path.
fn quality_menu(
    ctx: &egui::Context,
    viewer: &ViewerState,
    applied: Option<QualityPreset>,
    at: egui::Pos2,
    actions: &mut Vec<Action>,
    t: &Tokens,
) -> egui::InnerResponse<()> {
    egui::Area::new(egui::Id::new("viewer-quality"))
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
                        for preset in QualityPreset::ALL {
                            let on = applied == Some(preset);
                            ui.horizontal_top(|ui| {
                                // The check mark's column, empty but for the
                                // applied preset.
                                let (mark, _) =
                                    ui.allocate_exact_size(vec2(16.0, 20.0), egui::Sense::hover());
                                if on {
                                    ui.painter().text(
                                        mark.center(),
                                        egui::Align2::CENTER_CENTER,
                                        "✓",
                                        theme::font(ui.ctx(), Face::MonoSemibold, 13.0),
                                        t.ok,
                                    );
                                }
                                ui.vertical(|ui| {
                                    let item = egui::Button::new(quality_name(preset))
                                        .frame(false)
                                        .selected(on);
                                    if ui.add(item).clicked() {
                                        actions.push(Action::Viewer(ViewerAction::Quality(preset)));
                                    }
                                    ui.label(
                                        RichText::new(quality_hint(preset))
                                            .small()
                                            .color(t.text_muted),
                                    );
                                    if !on && viewer.changing() == Some(preset) {
                                        ui.label(
                                            RichText::new(CHANGING).small().color(t.text_muted),
                                        );
                                    }
                                });
                            });
                        }
                    });
                });
        })
}

/// What the details count: the input sent, the frame rate measured here,
/// and this computer's mean upload of a picture.
#[derive(Debug, Clone, Copy)]
struct Counts {
    /// Input events sent (a control session's).
    input_sent: u64,
    /// The frame rate over the last second.
    rate: u64,
    /// The mean texture upload.
    upload: Ewma,
}

/// The lines the details say under the level, each when the host said it.
#[derive(Debug, Clone, Copy)]
struct ModeLines {
    /// The session's input reaches nothing on the host.
    no_input: bool,
    /// The session's input ended when the host's screens changed.
    input_lost: bool,
    /// Its input cannot reach the host's administrator windows.
    admin_windows: bool,
}

/// The connection's details, under the toolbar at `at`: the route, the
/// picture, the screen shown once the host listed its monitors (the
/// monitors design §2), what the host applies and each stage's time (the
/// quality design §3.3; display only), the level (with the no-input, the
/// input-lost and the administrator-windows lines when the host said them,
/// `lines`), the
/// session's clock and, in a control session, the input sent. Nothing in
/// them names the host.
fn details(
    ctx: &egui::Context,
    v: &Viewing,
    counts: Counts,
    now: Instant,
    at: egui::Pos2,
    lines: ModeLines,
) -> egui::InnerResponse<()> {
    let Counts {
        input_sent,
        rate,
        upload,
    } = counts;
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
                            if let Some(screens) =
                                v.screens.as_ref().filter(|s| !s.monitors.is_empty())
                            {
                                ui.label(muted("Screen"));
                                ui.label(screen_detail(screens));
                                ui.end_row();
                            }
                            let host = v.stream.host.as_ref();
                            if let Some(applied) = &v.stream.applied {
                                ui.label(muted("Quality"));
                                ui.vertical(|ui| {
                                    ui.label(quality_text(applied));
                                    if let Some(scaled) = scaled_text(host, v.size) {
                                        ui.label(muted(&scaled).small());
                                    }
                                });
                                ui.end_row();
                            }
                            ui.label(muted("Timing"));
                            ui.vertical(|ui| {
                                // One line each: the panel takes their width,
                                // rather than growing tall with wrapped lines.
                                let line = |ui: &mut egui::Ui, text: String| {
                                    ui.add(
                                        egui::Label::new(text)
                                            .wrap_mode(egui::TextWrapMode::Extend),
                                    );
                                };
                                let (decode, convert) = (v.stream.decode_ms, v.stream.convert_ms);
                                line(ui, local_timing(decode, convert, upload));
                                line(ui, remote_timing(host));
                                line(ui, round_trip_text(host));
                            });
                            ui.end_row();
                            ui.label(muted("Mode"));
                            ui.vertical(|ui| {
                                ui.label(chip_text(v));
                                if lines.no_input {
                                    ui.label(RichText::new(NO_INPUT_LINE).small().color(t.warn));
                                }
                                if lines.input_lost {
                                    ui.label(RichText::new(INPUT_LOST_LINE).small().color(t.warn));
                                }
                                if lines.admin_windows {
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
    use crate::ui::model::{StreamInfo, ViewerServices, Viewing};
    use crate::ui::view::Action;

    /// The services of a host that granted `caps`, with a host's default
    /// limits.
    pub(crate) fn granted(caps: u16) -> Box<ViewerServices> {
        let mut services = ViewerServices::opening(true);
        services.opened(&tornect_proto::services::Welcome {
            caps,
            clip_max: 262_144,
            file_max: 2048 << 20,
            session_quota: 8192 << 20,
            session_files: 1000,
            chat_max: 8000,
            bulk_window: 256 * 1024,
            inbox: "Downloads › Tornect".into(),
        });
        Box::new(services)
    }

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
                    stream: StreamInfo::default(),
                    services: None,
                    screens: None,
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

        /// The centre of the text field whose hint is `hint`.
        pub(crate) fn field(&self, hint: &str) -> egui::Pos2 {
            let b = self
                .nodes
                .iter()
                .find(|n| n.placeholder() == Some(hint))
                .and_then(egui::accesskit::Node::bounds)
                .unwrap_or_else(|| panic!("no field \"{hint}\" on screen"));
            egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32)
        }

        /// A key pressed and let go, in one pass.
        pub(crate) fn key(&mut self, at: Duration, key: egui::Key) -> Vec<Action> {
            let event = |pressed| egui::Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            };
            self.pass(at, vec![event(true), event(false)])
        }

        /// A click at `at` at `pos`, in two passes.
        pub(crate) fn click_at(&mut self, at: Duration, pos: egui::Pos2) -> Vec<Action> {
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

        /// Whether the widget named `text` was shown as on (a toggle's
        /// state) in the last pass; `None` for one that is no toggle.
        pub(crate) fn toggled(&self, text: &str) -> Option<egui::accesskit::Toggled> {
            self.nodes
                .iter()
                .find(|n| n.label() == Some(text))
                .unwrap_or_else(|| panic!("no \"{text}\" on screen"))
                .toggled()
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

    /// With the badge off (Display and quality), a click on the level chip
    /// opens the details in its place and closes them again, and the press
    /// never reaches the host; with the badge on, the chip opens nothing.
    #[test]
    fn the_level_chip_opens_the_details_when_the_badge_is_off() {
        use crate::ui::stream::{Forwarder, PictureRect};
        use tornect_input::Button;
        let mut w = Window::new(true);
        w.viewer.badge_off = true;
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        assert!(
            !w.texts().iter().any(|t| t.contains("Tor relay")),
            "no badge"
        );
        let at = w.centre("control");
        let asked = w.click(ms(100), "control");
        assert_eq!(asked, vec![Action::Viewer(ViewerAction::Details(true))]);
        // As the window applies the action.
        w.viewer.details = true;
        w.pass(ms(200), Vec::new());
        w.pass(ms(200), Vec::new());
        assert!(w.has("Route"), "{:?}", w.texts());
        // A second click on the chip (the details show "control" too).
        let press = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        let mut asked = w.pass(ms(300), vec![egui::Event::PointerMoved(at), press(true)]);
        asked.extend(w.pass(ms(300), vec![press(false)]));
        assert_eq!(asked, vec![Action::Viewer(ViewerAction::Details(false))]);
        // The press on the chip, as the window hands it to the forwarder.
        let pixels = |r: egui::Rect| PictureRect {
            x: f64::from(r.min.x),
            y: f64::from(r.min.y),
            width: f64::from(r.width()),
            height: f64::from(r.height()),
        };
        let mut forwarder = Forwarder::new(true);
        forwarder.set_areas(
            w.drawn.map(pixels),
            w.viewer.visible().map(pixels),
            w.viewer.areas().iter().map(|r| pixels(*r)).collect(),
        );
        forwarder.moved((f64::from(at.x), f64::from(at.y)));
        forwarder.button(Button::Left, true);
        forwarder.button(Button::Left, false);
        forwarder.flush();
        assert!(forwarder.drain().is_empty());
        // The badge on: the chip is a label only.
        let mut w = Window::new(true);
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        assert!(w.click(ms(100), "control").is_empty());
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
            "Alt+F4",
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
            seq: 0,
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

    /// The no-input line, under the toolbar and in the details: only in a
    /// control session, and only when the host says the session's input
    /// reaches nothing there. Said after the toolbar hid, it brings the
    /// toolbar back once, with the line, whose area the remote computer
    /// never gets.
    #[test]
    fn the_no_input_line_is_said_only_when_the_host_says_so() {
        assert_eq!(
            NO_INPUT_LINE,
            "The remote computer did not allow control: you can watch, but your mouse and \
             keyboard reach nothing there."
        );
        for control in [false, true] {
            for code in [
                None,
                Some(0x00),
                Some(0x01),
                Some(0x07),
                Some(0x08),
                Some(0x0b),
            ] {
                let mut w = Window::new(control);
                w.viewer.host_notice = code;
                w.pass(ms(0), Vec::new());
                w.pass(ms(0), Vec::new());
                let want = control && code.is_some_and(|c| c & 0x08 != 0);
                let case = format!("control {control}, {code:?}");
                assert_eq!(w.has(NO_INPUT_LINE), want, "{case}: {:?}", w.texts());
                let under = times(&w, NO_INPUT_LINE);
                w.viewer.details = true;
                w.pass(ms(100), Vec::new());
                w.pass(ms(100), Vec::new());
                if want {
                    assert!(
                        times(&w, NO_INPUT_LINE) > under,
                        "{case}: in the details too"
                    );
                } else {
                    assert_eq!(times(&w, NO_INPUT_LINE), 0, "{case}");
                }
            }
        }
        let mut w = Window::new(true);
        w.viewer.host_notice = Some(0x00);
        for at in [0, 3000] {
            w.pass(ms(at), Vec::new());
            w.pass(ms(at), Vec::new());
        }
        assert!(!w.viewer.toolbar_shown(), "the toolbar hid");
        w.viewer.host_notice = Some(0x08);
        w.pass(ms(9000), Vec::new());
        w.pass(ms(9000), Vec::new());
        assert!(w.viewer.toolbar_shown(), "the toolbar came back");
        assert!(w.has(NO_INPUT_LINE), "{:?}", w.texts());
        let at = w.centre(NO_INPUT_LINE);
        assert!(w.viewer.areas().iter().any(|r| r.contains(at)));
        w.pass(ms(12000), Vec::new());
        w.pass(ms(12000), Vec::new());
        assert!(!w.viewer.toolbar_shown(), "called back once, not for good");
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
            NO_INPUT_LINE,
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

    /// A session that ends while the host's secure screen shows (the model
    /// then hands the window no code) says nothing of it closing; a code
    /// without the bit still says it closed.
    #[test]
    fn a_session_ending_during_a_secure_screen_says_nothing_closed() {
        let gone = crate::secure_screen::NOTICE_GONE;
        let mut w = Window::new(true);
        w.viewer.host_notice = Some(0x05);
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        assert!(w.has(crate::secure_screen::NOTICE), "{:?}", w.texts());
        w.viewer.host_notice = None;
        w.pass(ms(100), Vec::new());
        w.pass(ms(100), Vec::new());
        assert!(!w.has(gone), "the end: {:?}", w.texts());
        w.viewer.host_notice = Some(0x05);
        w.pass(ms(200), Vec::new());
        w.viewer.host_notice = Some(0x01);
        w.pass(ms(300), Vec::new());
        w.pass(ms(300), Vec::new());
        assert!(w.has(gone), "the bit cleared: {:?}", w.texts());
    }

    /// An open Send keys menu keeps the toolbar, with no move of the
    /// pointer: the pill and the menu are still shown at 0, 2.6 and 9 s.
    #[test]
    fn an_open_send_keys_menu_keeps_the_toolbar() {
        let mut w = Window::new(true);
        w.viewer.keys_menu = true;
        for at in [0, 2600, 9000] {
            w.pass(ms(at), Vec::new());
            w.pass(ms(at), Vec::new());
            assert!(w.has("End session"), "{at} ms: {:?}", w.texts());
            assert!(w.has("Alt+Tab"), "{at} ms: {:?}", w.texts());
        }
    }

    /// Settings, Display and quality: a new session's window opens as the
    /// settings hold it (here at its own size, full screen, the toolbar
    /// never hiding, no badge), and their defaults are what the window did
    /// before they could be chosen (fitted, not full screen, the toolbar
    /// hiding 2.5 s after the pointer last moved, the badge shown).
    #[test]
    fn the_viewer_opens_with_the_stored_defaults() {
        use tornect_core::config::{Picture, ToolbarHides, Viewer};
        let built = ViewerState::opened(&Viewer::default());
        assert!(!built.one_to_one && !built.fullscreen && !built.badge_off);
        assert_eq!(built.hides.after(), Some(ms(2500)));

        let mut w = Window::new(true);
        w.viewer = ViewerState::opened(&Viewer::default());
        w.pass(ms(0), Vec::new());
        assert!(w.texts().iter().any(|t| t.starts_with("Tor relay")));
        w.pass(ms(2400), Vec::new());
        assert!(w.viewer.toolbar_shown(), "before 2.5 s");
        w.pass(ms(2600), Vec::new());
        assert!(!w.viewer.toolbar_shown(), "after 2.5 s");

        let mut w = Window::new(true);
        w.viewer = ViewerState::opened(&Viewer {
            toolbar_hides: ToolbarHides::After5s,
            ..Viewer::default()
        });
        for (at, shown) in [(0, true), (4_900, true), (5_100, false)] {
            w.pass(ms(at), Vec::new());
            assert_eq!(w.viewer.toolbar_shown(), shown, "{at} ms");
        }

        let mut w = Window::new(true);
        w.viewer = ViewerState::opened(&Viewer {
            picture: Picture::OneToOne,
            fullscreen_at_open: true,
            toolbar_hides: ToolbarHides::Never,
            show_badge: false,
            quality: QualityPreset::BestPerformance,
            clipboard_sync: true,
        });
        assert!(w.viewer.one_to_one && w.viewer.fullscreen);
        for at in [0, 3_000, 10_000, 60_000] {
            w.pass(ms(at), Vec::new());
            assert!(w.viewer.toolbar_shown(), "{at} ms: never hides");
            assert!(
                !w.texts().iter().any(|t| t.starts_with("Tor relay")),
                "{at} ms: no badge"
            );
        }
        assert!(w.viewer.visible().is_some(), "at its own size");
    }

    /// What the host applies under each preset with the default caps (the
    /// quality design §3.1).
    fn applied(preset: QualityPreset) -> QualityInfo {
        let (code, max_fps, kbps, max_long, max_short) = match preset {
            QualityPreset::BestQuality => (1, 12, 4000, 3840, 2160),
            QualityPreset::Balanced => (2, 15, 1500, 1920, 1080),
            QualityPreset::BestPerformance => (3, 20, 1000, 1280, 720),
        };
        QualityInfo {
            preset: code,
            max_fps,
            kbps,
            max_long,
            max_short,
        }
    }

    /// The quality design §4.4's `Stats`.
    fn host_stats() -> HostStats {
        HostStats {
            source_width: 2560,
            source_height: 1440,
            frames: 15,
            window_ms: 1000,
            grab_us: 4000,
            age_us: 6200,
            scale_us: 2100,
            convert_us: 1500,
            encode_us: 9800,
            send_us: 120_000,
            ack_us: 1_100_000,
        }
    }

    /// The quality design §3.2: the Quality button is in the toolbar of a
    /// control and a view-only session alike, after the fullscreen corners
    /// and (in control) before Send keys; a click asks for its menu, and a
    /// second one closes it.
    #[test]
    fn the_quality_button_is_offered_in_control_and_view_only() {
        for control in [false, true] {
            let mut w = Window::new(control);
            w.pass(ms(0), Vec::new());
            w.pass(ms(0), Vec::new());
            assert!(w.has(QUALITY), "{control}: {:?}", w.texts());
            let quality = w.centre(QUALITY);
            assert!(quality.x > w.centre(FULLSCREEN).x, "{control}");
            if control {
                assert!(w.centre("Send keys").x > quality.x);
            }
            assert_eq!(
                w.click(ms(100), QUALITY),
                vec![Action::Viewer(ViewerAction::QualityMenu(true))],
                "{control}"
            );
            w.viewer.quality_menu = true;
            w.pass(ms(200), Vec::new());
            assert_eq!(
                w.click(ms(300), QUALITY),
                vec![Action::Viewer(ViewerAction::QualityMenu(false))],
                "{control}: the button toggles, the press is not one elsewhere"
            );
        }
    }

    /// The menu: the three presets in the design's words, each with its
    /// hint, the one the host applies checked (none before it said); a
    /// click on one asks for it, in both modes. The open menu keeps the
    /// toolbar, is the window's own area (no press there reaches the host),
    /// and a press elsewhere closes it.
    #[test]
    fn the_quality_menu_offers_three_presets_and_checks_the_applied_one() {
        use egui::accesskit::Toggled;
        let items = [
            (
                QualityPreset::BestQuality,
                "Best quality",
                "The sharpest picture; needs the fastest link",
            ),
            (
                QualityPreset::Balanced,
                "Balanced",
                "A sharp picture at a steady pace",
            ),
            (
                QualityPreset::BestPerformance,
                "Best performance",
                "The quickest response; a smaller picture",
            ),
        ];
        for (preset, name, hint) in items {
            assert_eq!((quality_name(preset), quality_hint(preset)), (name, hint));
        }
        for control in [false, true] {
            let mut w = Window::new(control);
            w.viewer.quality_menu = true;
            w.pass(ms(0), Vec::new());
            w.pass(ms(0), Vec::new());
            for (_, name, hint) in items {
                assert!(w.has(name) && w.has(hint), "{name}: {:?}", w.texts());
                assert_eq!(w.toggled(name), Some(Toggled::False), "nothing said yet");
            }
            w.viewing.stream.applied = Some(applied(QualityPreset::Balanced));
            for at in [100, 2600, 9000] {
                w.pass(ms(at), Vec::new());
                w.pass(ms(at), Vec::new());
                assert!(w.has("End session"), "{at} ms: the toolbar stays");
                for (preset, name, _) in items {
                    let on = if preset == QualityPreset::Balanced {
                        Toggled::True
                    } else {
                        Toggled::False
                    };
                    assert_eq!(w.toggled(name), Some(on), "{control}, {at} ms: {name}");
                }
            }
            assert!(!w.has(CHANGING));
            for (_, name, _) in items {
                let at = w.centre(name);
                assert!(w.viewer.areas().iter().any(|r| r.contains(at)), "{name}");
            }
            assert_eq!(
                w.click(ms(9100), "Best performance"),
                vec![Action::Viewer(ViewerAction::Quality(
                    QualityPreset::BestPerformance
                ))],
                "{control}"
            );
            let away = egui::pos2(640.0, 600.0);
            let press = |pressed| egui::Event::PointerButton {
                pos: away,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let mut asked = w.pass(ms(9200), vec![egui::Event::PointerMoved(away), press(true)]);
            asked.extend(w.pass(ms(9200), vec![press(false)]));
            assert_eq!(
                asked,
                vec![Action::Viewer(ViewerAction::QualityMenu(false))],
                "{control}"
            );
        }
    }

    /// "Changing…" stays under a pick other than the applied preset until
    /// the host says it applies it, when the toast names it (once, for
    /// 3.5 s), or for 10 s, after which it goes quietly; the check mark
    /// follows the applied preset throughout, and a pick of the applied
    /// preset puts nothing on its way. The window opens with none.
    #[test]
    fn changing_shows_until_the_host_applies_the_pick_or_ten_seconds_pass() {
        use egui::accesskit::Toggled;
        use tornect_core::config::QualityPreset::{Balanced, BestPerformance, BestQuality};
        assert_eq!(ViewerState::opened(&Viewer::default()).changing(), None);
        let mut w = Window::new(false);
        w.viewing.stream.applied = Some(applied(Balanced));
        w.pass(ms(0), Vec::new());
        // As the window applies the pick; the menu opened again to look.
        w.viewer.quality_menu = true;
        w.viewer
            .pick_quality(BestPerformance, Some(Balanced), w.start + ms(100));
        assert!(!w.viewer.quality_menu, "a pick closes the menu");
        assert_eq!(w.viewer.changing(), Some(BestPerformance));
        w.viewer.quality_menu = true;
        for at in [200, 10_000] {
            w.pass(ms(at), Vec::new());
            w.pass(ms(at), Vec::new());
            assert!(w.has(CHANGING), "{at} ms: {:?}", w.texts());
            let (under, changing) = (w.centre("Best performance"), w.centre(CHANGING));
            assert!(
                changing.y > under.y && changing.y - under.y < 60.0,
                "under its item"
            );
            assert_eq!(w.toggled("Balanced"), Some(Toggled::True));
            assert_eq!(w.toggled("Best performance"), Some(Toggled::False));
        }
        w.pass(ms(10_200), Vec::new());
        w.pass(ms(10_200), Vec::new());
        assert!(!w.has(CHANGING), "10.1 s after the pick: {:?}", w.texts());
        assert_eq!(w.viewer.changing(), None);
        assert!(
            !w.texts().iter().any(|t| t.starts_with("Quality:")),
            "no toast"
        );
        // A pick the host applies.
        w.viewer
            .pick_quality(BestPerformance, Some(Balanced), w.start + ms(11_000));
        w.viewer.quality_menu = true;
        w.pass(ms(11_100), Vec::new());
        w.pass(ms(11_100), Vec::new());
        assert!(w.has(CHANGING));
        w.viewing.stream.applied = Some(applied(BestPerformance));
        w.pass(ms(12_000), Vec::new());
        w.pass(ms(12_000), Vec::new());
        assert!(!w.has(CHANGING), "{:?}", w.texts());
        assert!(w.has("Quality: Best performance"), "{:?}", w.texts());
        assert_eq!(w.toggled("Best performance"), Some(Toggled::True));
        assert_eq!(w.toggled("Balanced"), Some(Toggled::False));
        w.pass(ms(15_400), Vec::new());
        assert!(w.has("Quality: Best performance"), "3.4 s");
        w.pass(ms(15_600), Vec::new());
        assert!(!w.has("Quality: Best performance"), "3.6 s");
        // The applied preset again: nothing on its way, no toast.
        w.viewer
            .pick_quality(BestPerformance, Some(BestPerformance), w.start + ms(16_000));
        assert_eq!(w.viewer.changing(), None);
        w.pass(ms(16_100), Vec::new());
        assert!(!w.texts().iter().any(|t| t.starts_with("Quality:")));
        // A pick before the host said anything is on its way too.
        w.viewer
            .pick_quality(BestQuality, None, w.start + ms(17_000));
        assert_eq!(w.viewer.changing(), Some(BestQuality));
        for (preset, toast) in [
            (BestQuality, "Quality: Best quality"),
            (Balanced, "Quality: Balanced"),
            (BestPerformance, "Quality: Best performance"),
        ] {
            assert_eq!(Toast::Quality(preset).text(), toast);
        }
    }

    /// The quality design §3.3: once the host said what it applies, the
    /// badge names the preset between the route and the frame rate; until
    /// then it reads as before.
    #[test]
    fn the_badge_names_the_applied_preset_once_the_host_said() {
        let mut w = Window::new(true);
        assert_eq!(badge_text(&w.viewing, 30), "Tor relay · 30 fps · 1600×900");
        w.viewing.stream.applied = Some(applied(QualityPreset::Balanced));
        for k in 0..=10u64 {
            w.viewing.pictures = 1 + 3 * k;
            w.pass(ms(100 * k), Vec::new());
        }
        assert!(
            w.has("Tor relay · Balanced · 30 fps · 1600×900"),
            "{:?}",
            w.texts()
        );
        // A click on it still opens the details.
        assert_eq!(
            w.click(ms(1100), "Tor relay"),
            vec![Action::Viewer(ViewerAction::Details(true))]
        );
    }

    /// The details' Quality and Timing rows (the quality design §3.3):
    /// before anything is known there is no Quality row and every Timing
    /// line reads "Measuring…"; then what the host applies, the desktop it
    /// scaled from, this computer's means and the host's, in the design's
    /// number format. Nothing in them names the host.
    #[test]
    fn the_details_say_the_quality_and_each_stages_time() {
        let mut w = Window::new(false);
        w.viewer.shared = true;
        w.viewer.details = true;
        w.pass(ms(0), Vec::new());
        w.pass(ms(0), Vec::new());
        let button_only = times(&w, "Quality");
        for text in [
            "Timing",
            "This computer: Measuring…",
            "Remote computer: Measuring…",
            "Round trip: Measuring…",
        ] {
            assert!(w.has(text), "{text}: {:?}", w.texts());
        }
        w.viewing.size = (1920, 1080);
        w.viewing.stream.applied = Some(applied(QualityPreset::Balanced));
        w.viewing.stream.decode_ms.add(3.1);
        w.viewing.stream.convert_ms.add(1.2);
        w.viewer.upload_ms.add(0.8);
        w.viewing.stream.host = Some(host_stats());
        w.pass(ms(100), Vec::new());
        w.pass(ms(100), Vec::new());
        assert!(times(&w, "Quality") > button_only, "the button and the row");
        for text in [
            "Balanced · up to 15 fps · 1.5 Mbit/s",
            "Scaled down from 2560×1440",
            "This computer: decode 3.1 ms · convert 1.2 ms · upload 0.8 ms",
            "Remote computer: capture 4.0 ms · scale 2.1 ms · convert 1.5 ms · encode 9.8 ms · \
             send 120 ms",
            "Round trip: 1.1 s",
        ] {
            assert!(w.has(text), "{text}: {:?}", w.texts());
        }
        let texts = w.texts();
        assert!(!texts.iter().any(|t| t.contains("Measuring")), "{texts:?}");
        assert!(!texts.iter().any(|t| t.contains("Desk")), "{texts:?}");
        // A desktop the picture shows whole: nothing was scaled.
        w.viewing.stream.host = Some(HostStats {
            source_width: 1921,
            source_height: 1081,
            ..host_stats()
        });
        w.pass(ms(200), Vec::new());
        w.pass(ms(200), Vec::new());
        assert!(
            !w.texts().iter().any(|t| t.starts_with("Scaled down")),
            "{:?}",
            w.texts()
        );
    }

    /// The details' numbers (the quality design §3.3): bitrates from
    /// 1000 kbit/s in Mbit/s with one decimal, below in kbit/s; times under
    /// 10 ms with one decimal, then whole milliseconds, then seconds with
    /// one decimal; every value from the wire saturates.
    #[test]
    fn the_details_numbers_read_as_the_design_words_them() {
        for (kbps, text) in [
            (1500, "1.5 Mbit/s"),
            (1000, "1.0 Mbit/s"),
            (4000, "4.0 Mbit/s"),
            (1049, "1.0 Mbit/s"),
            (1050, "1.1 Mbit/s"),
            (999, "999 kbit/s"),
            (800, "800 kbit/s"),
            (1, "1 kbit/s"),
            (u32::MAX, "4294967.3 Mbit/s"),
        ] {
            assert_eq!(bitrate_text(kbps), text, "{kbps}");
        }
        assert_eq!(
            quality_text(&applied(QualityPreset::BestQuality)),
            "Best quality · up to 12 fps · 4.0 Mbit/s"
        );
        assert_eq!(
            quality_text(&applied(QualityPreset::BestPerformance)),
            "Best performance · up to 20 fps · 1.0 Mbit/s"
        );
        let most = HostStats {
            grab_us: u32::MAX,
            scale_us: u32::MAX,
            convert_us: u32::MAX,
            encode_us: u32::MAX,
            send_us: u32::MAX,
            ack_us: u32::MAX,
            ..host_stats()
        };
        assert_eq!(
            remote_timing(Some(&most)),
            "Remote computer: capture 4295.0 s · scale 4295.0 s · convert 4295.0 s · encode \
             4295.0 s · send 4295.0 s"
        );
        assert_eq!(round_trip_text(Some(&most)), "Round trip: 4295.0 s");
        let none_acked = HostStats {
            ack_us: 0,
            ..host_stats()
        };
        assert_eq!(round_trip_text(Some(&none_acked)), "Round trip: Measuring…");
        let mut some = Ewma::default();
        some.add(12.0);
        assert_eq!(
            local_timing(some, some, Ewma::default()),
            "This computer: Measuring…"
        );
        some.add(999.6);
        assert_eq!(
            local_timing(some, some, some),
            "This computer: decode 210 ms · convert 210 ms · upload 210 ms"
        );
        let stats = host_stats();
        for (picture, scaled) in [
            ((1920, 1080), true),
            ((2560, 1440), false),
            ((2560, 1080), true),
            ((0, 0), false),
        ] {
            assert_eq!(
                scaled_text(Some(&stats), picture).is_some(),
                scaled,
                "{picture:?}"
            );
        }
        assert_eq!(scaled_text(None, (1920, 1080)), None);
    }

    /// Two monitors side by side, the first the main one, "all" offered;
    /// `shown` on show.
    fn two_screens(shown: u8) -> ScreensView {
        ScreensView {
            monitors: vec![
                MonitorEntry::saturating(true, 0, 0, 2560, 1440),
                MonitorEntry::saturating(false, 2560, 0, 1920, 1080),
            ],
            all: true,
            shown,
            list: 1,
            ..ScreensView::default()
        }
    }

    /// The monitors design §2: the Screens button is in the toolbar of a
    /// control and a view-only session alike once the host listed two or
    /// more monitors, never before or for one; after Fit and 1:1, before the
    /// fullscreen corners. It reads the screen shown, says what it does when
    /// the pointer rests on it (over the picture, in the window's own
    /// area), a click asks for its menu and a second one closes it.
    #[test]
    fn the_screens_button_shows_once_the_host_lists_two_screens() {
        let one = ScreensView {
            monitors: vec![MonitorEntry::saturating(true, 0, 0, 1920, 1080)],
            shown: 1,
            ..ScreensView::default()
        };
        for control in [false, true] {
            let mut w = Window::new(control);
            for screens in [None, Some(ScreensView::default()), Some(one.clone())] {
                w.viewing.screens = screens;
                w.pass(ms(0), Vec::new());
                w.pass(ms(0), Vec::new());
                assert!(w.has("End session"), "{control}");
                assert!(!w.has(SCREENS), "{control}: {:?}", w.texts());
            }
            for (shown, reads) in [(1, "Screen 1"), (2, "Screen 2"), (0, "All screens")] {
                w.viewing.screens = Some(two_screens(shown));
                w.pass(ms(0), Vec::new());
                w.pass(ms(0), Vec::new());
                assert!(w.has(SCREENS) && w.has(reads), "{control}: {:?}", w.texts());
                assert!(!w.disabled(SCREENS));
            }
            let screens = w.centre(SCREENS);
            assert!(screens.x > w.centre("1:1").x, "{control}");
            assert!(screens.x < w.centre(FULLSCREEN).x, "{control}");
            assert!(!w.has(SCREENS_HINT));
            w.pass(ms(100), vec![egui::Event::PointerMoved(screens)]);
            for at in [1000, 1000, 1100] {
                w.pass(ms(at), Vec::new());
            }
            assert!(w.has(SCREENS_HINT), "{control}: {:?}", w.texts());
            let hint = w.centre(SCREENS_HINT);
            assert!(w.viewer.areas().iter().any(|r| r.contains(hint)));
            assert_eq!(
                w.click(ms(1200), SCREENS),
                vec![Action::Viewer(ViewerAction::ScreensMenu(true))],
                "{control}"
            );
            w.viewer.screens_menu = true;
            w.pass(ms(1300), Vec::new());
            assert_eq!(
                w.click(ms(1400), SCREENS),
                vec![Action::Viewer(ViewerAction::ScreensMenu(false))],
                "{control}: the button toggles, the press is not one elsewhere"
            );
        }
    }

    /// The menu: a row a monitor in the host's order, "main" on the primary
    /// one and the size where it is known, then "All screens" only where the
    /// host offers it; the screen shown checked. A click on a row asks for
    /// that screen, in both modes. The open menu keeps the toolbar, is the
    /// window's own area (no press there reaches the host), and a press
    /// elsewhere closes it.
    #[test]
    fn the_screens_menu_lists_the_hosts_screens_and_checks_the_one_shown() {
        use egui::accesskit::Toggled;
        let main = MonitorEntry::saturating(true, 0, 0, 2560, 1440);
        let side = MonitorEntry::saturating(false, 2560, 0, 1920, 1080);
        let unknown = MonitorEntry::saturating(false, 0, 0, 0, 0);
        assert_eq!(screen_row(1, &main), "Screen 1 · main · 2560 × 1440");
        assert_eq!(screen_row(2, &side), "Screen 2 · 1920 × 1080");
        assert_eq!(screen_row(3, &unknown), "Screen 3");
        assert_eq!(screen_name(ALL_MONITORS), "All screens");
        let rows = [
            (1, "Screen 1 · main · 2560 × 1440"),
            (2, "Screen 2 · 1920 × 1080"),
            (ALL_MONITORS, "All screens"),
        ];
        for control in [false, true] {
            let mut w = Window::new(control);
            w.viewing.screens = Some(two_screens(2));
            w.viewer.screens_menu = true;
            for at in [0, 2600, 9000] {
                w.pass(ms(at), Vec::new());
                w.pass(ms(at), Vec::new());
                assert!(w.has("End session"), "{at} ms: the toolbar stays");
                for (id, row) in rows {
                    let on = if id == 2 {
                        Toggled::True
                    } else {
                        Toggled::False
                    };
                    assert_eq!(w.toggled(row), Some(on), "{control}, {at} ms: {row}");
                }
            }
            let ys: Vec<f32> = rows.iter().map(|(_, row)| w.centre(row).y).collect();
            assert!(
                ys.is_sorted() && ys[0] < ys[2],
                "in the host's order: {ys:?}"
            );
            for (_, row) in rows {
                let at = w.centre(row);
                assert!(w.viewer.areas().iter().any(|r| r.contains(at)), "{row}");
            }
            for (id, row) in [(ALL_MONITORS, "All screens"), (1, "Screen 1 ·")] {
                assert_eq!(
                    w.click(ms(9100), row),
                    vec![Action::Viewer(ViewerAction::ShowScreen(id))],
                    "{control}: {row}"
                );
            }
            let away = egui::pos2(640.0, 600.0);
            let press = |pressed| egui::Event::PointerButton {
                pos: away,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let mut asked = w.pass(ms(9200), vec![egui::Event::PointerMoved(away), press(true)]);
            asked.extend(w.pass(ms(9200), vec![press(false)]));
            assert_eq!(
                asked,
                vec![Action::Viewer(ViewerAction::ScreensMenu(false))],
                "{control}"
            );
            // "All screens" only where the host offers it.
            w.viewing.screens = Some(ScreensView {
                all: false,
                ..two_screens(1)
            });
            w.pass(ms(9300), Vec::new());
            w.pass(ms(9300), Vec::new());
            assert!(!w.has("All screens"), "{control}: {:?}", w.texts());
            assert_eq!(w.toggled(rows[0].1), Some(Toggled::True));
        }
    }

    /// While a request waits for the host's answer the button reads
    /// "Switching…" beside a spinner and takes no click; the answer gives
    /// it back, reading the screen shown.
    #[test]
    fn the_screens_button_waits_for_the_hosts_answer() {
        for control in [false, true] {
            let mut w = Window::new(control);
            w.viewing.screens = Some(ScreensView {
                switching: Some(2),
                ..two_screens(1)
            });
            w.pass(ms(0), Vec::new());
            w.pass(ms(0), Vec::new());
            assert!(w.has(SWITCHING), "{control}: {:?}", w.texts());
            assert!(!w.has("Screen 1"), "{control}");
            assert!(w.disabled(SCREENS), "{control}");
            assert_eq!(w.click(ms(100), SCREENS), Vec::new(), "{control}");
            w.viewing.screens = Some(two_screens(2));
            w.pass(ms(200), Vec::new());
            w.pass(ms(200), Vec::new());
            assert!(!w.has(SWITCHING), "{control}");
            assert!(w.has("Screen 2") && !w.disabled(SCREENS), "{control}");
        }
    }

    /// The monitors design §2's toasts in its words, each said once for the
    /// news that asks for it: a refusal (the screen gone, a switch under
    /// way, one that failed), a request not sent or given up, the host's own
    /// change of what it shows. The session's first list, an answer that
    /// shows the screen asked for and news that leave the screen shown say
    /// nothing.
    #[test]
    fn the_hosts_screens_news_is_said_once_in_the_designs_words() {
        use monitor_status::{BUSY, FAILED, UNKNOWN};
        let said = |last| {
            screen_toast(&ScreensView {
                last,
                ..two_screens(1)
            })
            .map(|toast| toast.text().to_owned())
        };
        let refused = |asked, status| Some(ScreenNote::Refused { asked, status });
        for (last, words) in [
            (None, None),
            (
                refused(2, UNKNOWN),
                Some("That screen is not on the remote computer any more."),
            ),
            (refused(2, BUSY), Some(STILL_SWITCHING)),
            (
                refused(2, FAILED),
                Some("The remote computer could not switch to Screen 2."),
            ),
            (
                refused(ALL_MONITORS, FAILED),
                Some("The remote computer could not switch to all screens."),
            ),
            (
                Some(ScreenNote::NotSent { asked: 2 }),
                Some(STILL_SWITCHING),
            ),
            (
                Some(ScreenNote::NoAnswer { asked: 2 }),
                Some("The remote computer did not switch screens."),
            ),
            (
                Some(ScreenNote::Changed { shown: 1 }),
                Some("The remote computer's screens changed. Showing Screen 1."),
            ),
            (
                Some(ScreenNote::Changed {
                    shown: ALL_MONITORS,
                }),
                Some("The remote computer's screens changed. Showing all screens."),
            ),
        ] {
            assert_eq!(said(last).as_deref(), words, "{last:?}");
        }
        assert_eq!(STILL_SWITCHING, "Still switching. Try again in a moment.");

        let gone = "That screen is not on the remote computer any more.";
        for control in [false, true] {
            let mut w = Window::new(control);
            // The first list: news 1, nothing to say.
            w.viewing.screens = Some(ScreensView {
                news: 1,
                ..two_screens(1)
            });
            w.pass(ms(0), Vec::new());
            w.pass(ms(0), Vec::new());
            assert!(w.viewer.toast.is_none(), "{control}: {:?}", w.viewer.toast);
            w.viewing.screens = Some(ScreensView {
                news: 2,
                last: refused(2, UNKNOWN),
                ..two_screens(1)
            });
            for at in [100, 3000] {
                w.pass(ms(at), Vec::new());
                w.pass(ms(at), Vec::new());
                assert!(w.has(gone), "{control}, {at} ms: {:?}", w.texts());
            }
            // Gone after 3.5 s, and not said again for the same news.
            w.pass(ms(3700), Vec::new());
            w.pass(ms(3700), Vec::new());
            assert!(!w.has(gone), "{control}");
            // The next news says its own words, or none.
            w.viewing.screens = Some(ScreensView {
                news: 3,
                last: None,
                ..two_screens(2)
            });
            w.pass(ms(3800), Vec::new());
            w.pass(ms(3800), Vec::new());
            assert!(w.viewer.toast.is_none(), "{control}: {:?}", w.viewer.toast);
            w.viewing.screens = Some(ScreensView {
                news: 4,
                last: Some(ScreenNote::Changed { shown: 1 }),
                ..two_screens(1)
            });
            w.pass(ms(3900), Vec::new());
            w.pass(ms(3900), Vec::new());
            assert!(
                w.has("The remote computer's screens changed. Showing Screen 1."),
                "{control}: {:?}",
                w.texts()
            );
        }
    }

    /// The input-lost line (the monitors design §2), under the toolbar and
    /// in the details: only in a control session, and only when the host
    /// says the session's input ended when its screens changed. Said after
    /// the toolbar hid, it brings the toolbar back once, with the line,
    /// whose area the remote computer never gets.
    #[test]
    fn the_input_lost_line_is_said_only_when_the_host_says_so() {
        assert_eq!(
            INPUT_LOST_LINE,
            "Control stopped when the remote computer's screens changed. You can still watch."
        );
        assert_eq!(notice::INPUT_LOST, 0x10);
        for control in [false, true] {
            for code in [
                None,
                Some(0x00),
                Some(0x08),
                Some(0x0f),
                Some(0x10),
                Some(0x18),
            ] {
                let mut w = Window::new(control);
                w.viewing.screens = Some(two_screens(1));
                w.viewer.host_notice = code;
                w.pass(ms(0), Vec::new());
                w.pass(ms(0), Vec::new());
                let want = control && code.is_some_and(|c| c & 0x10 != 0);
                let case = format!("control {control}, {code:?}");
                assert_eq!(w.has(INPUT_LOST_LINE), want, "{case}: {:?}", w.texts());
                let under = times(&w, INPUT_LOST_LINE);
                w.viewer.details = true;
                w.pass(ms(100), Vec::new());
                w.pass(ms(100), Vec::new());
                if want {
                    assert!(times(&w, INPUT_LOST_LINE) > under, "{case}: in the details");
                } else {
                    assert_eq!(times(&w, INPUT_LOST_LINE), 0, "{case}");
                }
            }
        }
        let mut w = Window::new(true);
        w.viewer.host_notice = Some(0x00);
        for at in [0, 3000] {
            w.pass(ms(at), Vec::new());
            w.pass(ms(at), Vec::new());
        }
        assert!(!w.viewer.toolbar_shown(), "the toolbar hid");
        w.viewer.host_notice = Some(0x10);
        w.pass(ms(9000), Vec::new());
        w.pass(ms(9000), Vec::new());
        assert!(w.viewer.toolbar_shown(), "the toolbar came back");
        assert!(w.has(INPUT_LOST_LINE), "{:?}", w.texts());
        let at = w.centre(INPUT_LOST_LINE);
        assert!(w.viewer.areas().iter().any(|r| r.contains(at)));
        w.pass(ms(12000), Vec::new());
        w.pass(ms(12000), Vec::new());
        assert!(!w.viewer.toolbar_shown(), "called back once, not for good");
    }

    /// The details' Screen row (the monitors design §2): the screen shown
    /// of how many, with its size where it is known, or all of them; none
    /// before the host listed a monitor. It names no monitor otherwise.
    #[test]
    fn the_details_say_the_screen_shown() {
        assert_eq!(
            screen_detail(&two_screens(1)),
            "Screen 1 of 2 · 2560 × 1440"
        );
        assert_eq!(
            screen_detail(&two_screens(2)),
            "Screen 2 of 2 · 1920 × 1080"
        );
        assert_eq!(screen_detail(&two_screens(ALL_MONITORS)), "All 2 screens");
        let unknown = ScreensView {
            monitors: vec![MonitorEntry::saturating(false, 0, 0, 0, 0)],
            shown: 1,
            ..ScreensView::default()
        };
        assert_eq!(screen_detail(&unknown), "Screen 1 of 1");
        for control in [false, true] {
            let mut w = Window::new(control);
            w.viewer.details = true;
            for screens in [None, Some(ScreensView::default())] {
                w.viewing.screens = screens;
                w.pass(ms(0), Vec::new());
                w.pass(ms(0), Vec::new());
                assert!(w.has("Round trip: Measuring…"), "the details show");
                assert!(!w.has("Screen"), "{control}: {:?}", w.texts());
            }
            for (view, line) in [
                (unknown.clone(), "Screen 1 of 1"),
                (two_screens(2), "Screen 2 of 2 · 1920 × 1080"),
                (two_screens(ALL_MONITORS), "All 2 screens"),
            ] {
                w.viewing.screens = Some(view);
                w.pass(ms(100), Vec::new());
                w.pass(ms(100), Vec::new());
                assert!(w.has("Screen") && w.has(line), "{control}: {:?}", w.texts());
            }
        }
    }
}
