//! The manual winit loop (`docs/research/slice.md` §2, decision D10): one
//! event loop on the main thread and four kinds of window, each an egui
//! context with its own egui-winit state and egui-wgpu painter: the main
//! window, the stream window of a viewed session, the sharing indicator
//! (`indicator`) while this screen is shared, and the block windows
//! (`block`) while an unattended request is in its block window. The others
//! paint on the main window's wgpu device. Never eframe: the stream window reads
//! `WindowEvent::KeyboardInput` itself, before egui, which drops the keys it
//! has no name for.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::ViewportId;
use egui_wgpu::winit::Painter;
use egui_wgpu::{
    RendererOptions, WgpuConfiguration, WgpuSetup, WgpuSetupCreateNew, WgpuSetupExisting,
};
use tokio::sync::mpsc;
use tornect_core::levels::AdminPath;
use winit::application::ApplicationHandler;
use winit::dpi::LogicalSize;
use winit::event::{ElementState, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow};
use winit::window::{UserAttentionType, Window, WindowAttributes, WindowId};

use super::backend::{Command, StreamLink};
use super::block;
use super::consent::Popups;
use super::indicator::{self, Change, Indicator};
use super::keys;
use super::model::{ClientStage, Shared, Wake};
use super::nav::Page;
use super::stream::{Forwarder, Picture, PictureRect, VideoTexture, button};
use super::view::{self, Action, Form};

/// How long closing the window waits for the goodbyes before it quits anyway.
const QUIT_WAIT: Duration = Duration::from_secs(10);
/// How long the indicator probe of a start in background mode may take to
/// draw its first frame before it counts as failed (§B.1.1).
const PROBE_WAIT: Duration = Duration::from_secs(10);
/// How often an owed `ReleaseAll` is tried again while the input queue is
/// full (`StreamLink::settle`).
const OWED_RETRY: Duration = Duration::from_millis(50);

/// What the tokio side sends the event loop.
#[derive(Debug, Clone, Copy)]
pub enum UserEvent {
    /// Something to redraw or raise.
    Wake(Wake),
}

/// The window calls a question or a session start makes: a seam, so a test
/// can record them. There is deliberately no `focus_window` here.
trait Attention {
    fn is_minimized(&self) -> Option<bool>;
    fn set_minimized(&self, minimized: bool);
    fn request_user_attention(&self, kind: Option<UserAttentionType>);
}

impl Attention for Window {
    fn is_minimized(&self) -> Option<bool> {
        Window::is_minimized(self)
    }

    fn set_minimized(&self, minimized: bool) {
        Window::set_minimized(self, minimized);
    }

    fn request_user_attention(&self, kind: Option<UserAttentionType>) {
        Window::request_user_attention(self, kind);
    }
}

/// A question opened or a session started: ask for the user's attention (a
/// flashing taskbar button, an urgency hint, GNOME's "is ready" notice) and
/// bring a minimized window back, but never take the keyboard focus
/// (`docs/UI_PLAN.md` §6.1: "dialog takes focus only on user click";
/// SLICE-E E1-1: on Windows `focus_window` forces the window to the
/// foreground, and keys typed for another program then answer the card).
/// X11's un-minimize is itself an activation request (`_NET_ACTIVE_WINDOW`),
/// so only a window known to be minimized gets it; Wayland cannot tell
/// (`None`) and cannot un-minimize. `true` when the window was brought back,
/// so its cards arm again (review N-1).
fn ask_attention(window: &impl Attention) -> bool {
    let restore = window.is_minimized() == Some(true);
    if restore {
        window.set_minimized(false);
    }
    window.request_user_attention(Some(UserAttentionType::Critical));
    restore
}

/// Background mode (§B.1.1): the main window is minimised right after it is
/// created; nothing asks for attention or takes the focus. Where the desktop
/// ignores the request (GNOME on Wayland may), it is an ordinary window.
fn start_minimised(window: &impl Attention, background: bool) {
    if background {
        window.set_minimized(true);
    }
}

/// The sharing indicator's window did not open at a session. In background
/// mode the main window is minimised, so it is brought back with the
/// attention a question asks for, and its banner shows the session (§B.1.1);
/// a window started by hand is up with its banner already. `true` when the
/// window was brought back, so its cards arm again.
fn indicator_failed(window: &impl Attention, background: bool) -> bool {
    background && ask_attention(window)
}

/// `IpcOp::Show` (a second launch, §B.1.1): the attention a question asks for
/// (a window known to be minimized is brought back, then the attention
/// request, never the keyboard focus), then `rearm`, whether or not the window
/// was brought back: a window raise re-arms every card (§B.2.1). It reaches no
/// card otherwise, so it answers, dismisses and re-orders nothing.
fn show_window(window: &impl Attention, rearm: impl FnOnce()) {
    ask_attention(window);
    rearm();
}

/// A window event after which the main window is back in view (focused, or
/// no longer hidden): its cards arm again (review N-1).
fn comes_back(event: &WindowEvent) -> bool {
    matches!(
        event,
        WindowEvent::Focused(true) | WindowEvent::Occluded(false)
    )
}

/// DX12's options for every wgpu instance this app creates: the FXC shader
/// compiler (`d3dcompiler_47.dll`, part of Windows 10 and later), never DXC,
/// whose `dxcompiler.dll` is not part of Windows and which wgpu's default
/// (`Auto`) loads by name (review finding E2-4); and nothing from the
/// `WGPU_DX12_*` variables, the Agility SDK's DLL path among them. Only the
/// Windows build has a DX12 backend; elsewhere the options are unused.
fn dx12_options() -> wgpu::Dx12BackendOptions {
    wgpu::Dx12BackendOptions {
        shader_compiler: wgpu::Dx12Compiler::Fxc,
        ..wgpu::Dx12BackendOptions::default()
    }
}

/// A new wgpu instance, adapter and device for a window, with
/// [`dx12_options`].
fn new_device(display: impl egui_wgpu::EguiDisplayHandle) -> WgpuSetup {
    let mut setup = WgpuSetupCreateNew::from_display_handle(display);
    setup.instance_descriptor.backend_options.dx12 = dx12_options();
    WgpuSetup::CreateNew(setup)
}

/// Whether the windows are Wayland's (where every window is composited).
fn wayland(el: &ActiveEventLoop) -> bool {
    #[cfg(target_os = "linux")]
    {
        use winit::platform::wayland::ActiveEventLoopExtWayland as _;
        el.is_wayland()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = el;
        false
    }
}

/// The stream window's title: it names neither the host nor its address.
pub const STREAM_TITLE: &str = "Tornect: remote screen";

/// One window with its egui context, input state and painter.
struct Surface {
    window: Arc<Window>,
    ctx: egui::Context,
    state: egui_winit::State,
    painter: Painter,
    /// When egui asked to be drawn again.
    repaint_at: Option<Instant>,
    /// What the window is cleared to before egui paints: see-through for a
    /// window the desktop composites transparently (the indicator's pill).
    clear: [f32; 4],
}

impl Surface {
    fn new(
        el: &ActiveEventLoop,
        attrs: WindowAttributes,
        setup: WgpuSetup,
        theme: egui::Theme,
        transparent: bool,
    ) -> anyhow::Result<Self> {
        let window = Arc::new(el.create_window(attrs)?);
        let ctx = egui::Context::default();
        ctx.set_theme(theme);
        let config = WgpuConfiguration {
            wgpu_setup: setup,
            ..WgpuConfiguration::default()
        };
        let mut painter = pollster::block_on(Painter::new(
            ctx.clone(),
            config,
            transparent,
            RendererOptions::default(),
        ));
        pollster::block_on(painter.set_window(ViewportId::ROOT, Some(Arc::clone(&window))))
            .map_err(|e| anyhow::anyhow!("no GPU surface for the window: {e}"))?;
        let state = egui_winit::State::new(
            ctx.clone(),
            ViewportId::ROOT,
            &*window,
            Some(window.scale_factor() as f32),
            window.theme(),
            painter.max_texture_side(),
        );
        window.request_redraw();
        Ok(Self {
            window,
            ctx,
            state,
            painter,
            repaint_at: None,
            clear: if transparent {
                [0.0, 0.0, 0.0, 0.0]
            } else {
                [0.0, 0.0, 0.0, 1.0]
            },
        })
    }

    /// Hand `event` to egui; redraw if it wants.
    fn on_event(&mut self, event: &WindowEvent) {
        let response = self.state.on_window_event(&self.window, event);
        if response.repaint {
            self.window.request_redraw();
        }
    }

    fn resized(&mut self, width: u32, height: u32) {
        if let (Some(w), Some(h)) = (NonZeroU32::new(width), NonZeroU32::new(height)) {
            self.painter.on_window_resized(ViewportId::ROOT, w, h);
        }
        self.window.request_redraw();
    }

    /// Run one egui pass with `run` and paint it.
    fn paint(&mut self, run: impl FnMut(&mut egui::Ui)) {
        let raw = self.state.take_egui_input(&self.window);
        let out = self.ctx.run_ui(raw, run);
        self.state
            .handle_platform_output(&self.window, out.platform_output);
        let clipped = self.ctx.tessellate(out.shapes, out.pixels_per_point);
        let mut textures = out.textures_delta;
        self.painter.paint_and_update_textures(
            ViewportId::ROOT,
            out.pixels_per_point,
            self.clear,
            &clipped,
            &mut textures,
            Vec::new(),
            &self.window,
        );
        self.repaint_at = out
            .viewport_output
            .get(&ViewportId::ROOT)
            .map(|v| v.repaint_delay)
            .filter(|delay| *delay < Duration::from_secs(3600))
            .map(|delay| Instant::now() + delay);
    }
}

/// One block window (§B.8.6.3): request `request`'s, on one monitor.
struct BlockSurface {
    request: u64,
    surface: Surface,
}

/// The stream window of a live session.
struct StreamView {
    surface: Surface,
    video: VideoTexture,
    picture: Picture,
    forwarder: Forwarder,
    last_flush: Instant,
    input_sent: u64,
}

/// The application: the main window, the stream window while a session is
/// viewed, the indicator window while this screen is shared, and the channels
/// to the tokio side.
pub struct App {
    shared: Arc<Shared>,
    popups: Arc<Popups>,
    link: Arc<StreamLink>,
    commands: mpsc::UnboundedSender<Command>,
    main: Option<Surface>,
    stream: Option<StreamView>,
    /// The indicator window, while this screen is shared.
    indicator: Option<Surface>,
    /// Whether the indicator should be up, and what it shows.
    shown: Indicator,
    /// The indicator is a see-through pill (the desktop composites it).
    indicator_rounded: bool,
    /// The indicator probe of a start in background mode (§B.1.1): the
    /// indicator's window, opened once right after the main window and closed
    /// at its first frame, and when it opened.
    probe: Option<(Surface, Instant)>,
    /// Background mode (§B.1.1): which host sheets have their desktop
    /// notification.
    notices: super::notice::Notices,
    /// The block windows of the requests in their block window, one per
    /// monitor each (§B.8.6.3).
    blocks: Vec<BlockSurface>,
    /// The requests whose block windows were opened (or tried: a window that
    /// failed to open is not tried again for the same request).
    blocks_opened: Vec<u64>,
    /// When the block windows were last put back on top.
    blocks_asserted: Option<Instant>,
    /// The user closed the stream window of the session still in the model.
    stream_dismissed: bool,
    form: Form,
    quit_at: Option<Instant>,
    /// Where the stream window opens (the preview puts it beside the main
    /// window; otherwise the desktop places it).
    pub stream_at: Option<(i32, i32)>,
    /// The main window's title: a connect-only instance says so, so that two
    /// instances on one desktop can be told apart.
    pub title: &'static str,
    /// The theme every window draws with.
    pub theme: egui::Theme,
    /// The main window's height (the preview opens a taller one for a card
    /// low on its page).
    pub height: f64,
    /// Started in background mode (§B.1.1): the "indicator shown" fact that
    /// the indicator probe sets. `None` for a window started by hand.
    pub background: Option<crate::host::IndicatorShown>,
    /// Why the window could not run.
    pub error: Option<anyhow::Error>,
}

impl App {
    /// Draw `shared`, answer through `popups`, view through `link`, and ask
    /// the tokio side through `commands`.
    #[must_use]
    pub fn new(
        shared: Arc<Shared>,
        popups: Arc<Popups>,
        link: Arc<StreamLink>,
        commands: mpsc::UnboundedSender<Command>,
    ) -> Self {
        Self {
            shared,
            popups,
            link,
            commands,
            main: None,
            stream: None,
            indicator: None,
            shown: Indicator::default(),
            indicator_rounded: false,
            probe: None,
            notices: super::notice::Notices::default(),
            blocks: Vec::new(),
            blocks_opened: Vec::new(),
            blocks_asserted: None,
            stream_dismissed: false,
            form: Form::default(),
            quit_at: None,
            stream_at: None,
            title: "Tornect",
            theme: egui::Theme::Dark,
            height: 760.0,
            background: None,
            error: None,
        }
    }

    /// Open the main window on `page`.
    pub fn open_page(&mut self, page: Page) {
        self.form.page = page;
    }

    /// What the window remembers of what is typed and open (the preview
    /// opens a card through it).
    pub fn form_mut(&mut self) -> &mut Form {
        &mut self.form
    }

    fn command(&self, command: Command) {
        // The tokio side outlives the window; a send can only fail after it
        // has shut down, when nothing is left to do anyway.
        let _ = self.commands.send(command);
    }

    /// Close the stream window, and forget a picture it never drew, so that
    /// the next session's window cannot show it (SLICE-E E1-3).
    fn close_stream(&mut self) {
        self.stream = None;
        self.link.slot.clear();
    }

    fn quit(&mut self, el: &ActiveEventLoop) {
        if self.quit_at.is_none() {
            self.quit_at = Some(Instant::now());
            self.command(Command::Quit);
            self.close_stream();
            self.shared
                .update(|m| m.note("closing: ending sessions and leaving Tor…"));
        }
        if self.shared.read(|m| m.closed) {
            el.exit();
        }
    }

    /// Open the stream window when a session goes live, close it when it ends.
    fn sync_stream(&mut self, el: &ActiveEventLoop) {
        let live = self.shared.read(|m| match &m.client {
            ClientStage::Live(v) => Some(v.control),
            _ => None,
        });
        match live {
            None => {
                self.close_stream();
                self.stream_dismissed = false;
            }
            Some(_) if self.stream.is_some() || self.stream_dismissed || self.quit_at.is_some() => {
            }
            Some(control) => {
                let setup = self.main_device(el);
                // A neutral title: the window manager, the taskbar, Alt+Tab
                // and screen-share pickers read it, so it names nobody (the
                // bar inside the window names the host).
                let mut attrs = Window::default_attributes()
                    .with_title(STREAM_TITLE)
                    .with_inner_size(LogicalSize::new(1280.0, 760.0));
                if let Some((x, y)) = self.stream_at {
                    attrs = attrs.with_position(winit::dpi::PhysicalPosition::new(x, y));
                }
                match Surface::new(el, attrs, setup, self.theme, false) {
                    Ok(surface) => {
                        let max = surface.painter.max_texture_side().unwrap_or(8192);
                        self.stream = Some(StreamView {
                            surface,
                            video: VideoTexture::new(u32::try_from(max).unwrap_or(8192)),
                            picture: Picture::default(),
                            forwarder: Forwarder::new(control),
                            last_flush: Instant::now(),
                            input_sent: 0,
                        });
                    }
                    Err(e) => {
                        let line = format!("the stream window did not open: {e:#}");
                        self.shared.update(|m| m.note(line));
                        self.command(Command::EndViewing);
                        self.stream_dismissed = true;
                    }
                }
            }
        }
    }

    /// The main window's wgpu device, for another window to paint on.
    fn main_device(&self, el: &ActiveEventLoop) -> WgpuSetup {
        self.main
            .as_ref()
            .and_then(|m| m.painter.render_state())
            .map_or_else(
                || new_device(el.owned_display_handle()),
                |rs| {
                    WgpuSetup::Existing(WgpuSetupExisting {
                        instance: rs.instance.clone(),
                        adapter: rs.adapter.clone(),
                        device: rs.device.clone(),
                        queue: rs.queue.clone(),
                    })
                },
            )
    }

    /// A new indicator window for `rows` sessions.
    fn open_indicator(&mut self, el: &ActiveEventLoop, rows: usize) -> anyhow::Result<Surface> {
        // Top-right of the primary monitor where the desktop has one and lets
        // a client place its window (not Wayland).
        let position = el
            .primary_monitor()
            .or_else(|| el.available_monitors().next())
            .map(|m| {
                indicator::top_right(
                    m.position(),
                    m.size(),
                    m.scale_factor(),
                    indicator::size(rows),
                )
            });
        let setup = self.main_device(el);
        // A pill where the desktop composites transparent windows, a square
        // elsewhere.
        self.indicator_rounded = indicator::rounded_here(wayland(el));
        let attrs = indicator::attributes(rows, position).with_transparent(self.indicator_rounded);
        Surface::new(el, attrs, setup, self.theme, self.indicator_rounded)
    }

    /// The indicator probe of a start in background mode (§B.1.1): the
    /// indicator's window, opened once right after the main window; its first
    /// frame sets the "indicator shown" fact and it closes at once. Where the
    /// desktop cannot keep it on top (Wayland), the compositor's own
    /// screen-sharing indicator is the plan's fallback, and the probe proves
    /// the window itself. A window started by hand runs no probe.
    fn start_probe(&mut self, el: &ActiveEventLoop) {
        if self.background.is_none() || self.probe.is_some() {
            return;
        }
        match self.open_indicator(el, 1) {
            Ok(surface) => self.probe = Some((surface, Instant::now())),
            Err(e) => self.probe_failed(&format!("{e:#}")),
        }
    }

    /// The probe's first frame: the indicator as it looks with no session
    /// (nothing on it can be pressed before it closes, so its actions are
    /// dropped), then the fact, then the window closes.
    fn draw_probe(&mut self) {
        let Some((mut surface, _)) = self.probe.take() else {
            return;
        };
        let rounded = self.indicator_rounded;
        surface.paint(|ui| {
            view::indicator_pill(
                ui,
                &[],
                &std::collections::HashSet::new(),
                Instant::now(),
                &mut Vec::new(),
                rounded,
            );
        });
        self.probe_drew();
    }

    /// The probe drew its first frame: the indicator can be shown, and the
    /// host may serve unattended sessions (§B.1.1).
    fn probe_drew(&mut self) {
        self.probe = None;
        if let Some(shown) = &self.background {
            shown.set();
        }
    }

    /// The probe did not open, or drew nothing in time: the fact stays unset,
    /// so unattended sessions stay refused, and the recent activity says so.
    fn probe_failed(&mut self, why: &str) {
        self.probe = None;
        let line = format!(
            "the sharing indicator could not be shown ({why}); unattended sessions are refused \
             until it is"
        );
        tracing::warn!("{line}");
        self.shared.update(|m| m.note(line));
    }

    /// Background mode (§B.1.1): each host sheet is mirrored by one desktop
    /// notification, shown when the sheet opens and taken down when it
    /// closes (the sheet itself raises the window through
    /// `Wake::Attention`). A window started by hand shows none: it is up,
    /// with its sheet.
    fn sync_notices(&mut self) {
        if self.background.is_none() {
            return;
        }
        let popups = self.shared.read(|m| m.popups.clone());
        for change in self.notices.sync(&popups) {
            self.command(Command::Notice(change));
        }
    }

    /// Open the indicator window at the first shared session, redraw it on a
    /// change, close it at the last end.
    fn sync_indicator(&mut self, el: &ActiveEventLoop) {
        let sharing = self.shared.read(|m| m.sharing.clone());
        match self.shown.sync(&sharing) {
            Change::Keep => {}
            Change::Open => match self.open_indicator(el, self.shown.rows()) {
                Ok(surface) => self.indicator = Some(surface),
                Err(e) => {
                    // The banner in the main window still shows the session
                    // (brought up first in background mode); the next session
                    // tries again.
                    let line = format!("the sharing indicator did not open: {e:#}");
                    tracing::warn!("{line}");
                    self.shared.update(|m| m.note(line));
                    if let Some(main) = &self.main
                        && indicator_failed(&*main.window, self.background.is_some())
                    {
                        self.form.window_came_back();
                    }
                }
            },
            Change::Redraw => {
                if let Some(surface) = &self.indicator {
                    let _ = surface
                        .window
                        .request_inner_size(indicator::size(self.shown.rows()));
                    surface.window.request_redraw();
                }
            }
            Change::Close => self.indicator = None,
        }
    }

    /// Open a block window on every monitor for each request now in its block
    /// window, and close those of the requests that ended (§B.8.6.3).
    fn sync_blocks(&mut self, el: &ActiveEventLoop) {
        let requests: Vec<u64> = self
            .shared
            .read(|m| m.blocks.iter().map(|b| b.id).collect());
        self.blocks.retain(|b| requests.contains(&b.request));
        self.blocks_opened.retain(|id| requests.contains(id));
        if self.blocks.is_empty() {
            self.blocks_asserted = None;
        }
        let on_wayland = wayland(el);
        for request in requests {
            if self.blocks_opened.contains(&request) {
                continue;
            }
            self.blocks_opened.push(request);
            // Every monitor the desktop lists, centred; one window where it
            // lists none.
            let monitors: Vec<_> = el.available_monitors().collect();
            let positions: Vec<_> = if monitors.is_empty() {
                vec![None]
            } else {
                monitors
                    .iter()
                    .map(|m| {
                        Some(block::centred(
                            m.position(),
                            m.size(),
                            m.scale_factor(),
                            block::size(),
                        ))
                    })
                    .collect()
            };
            for position in positions {
                let setup = self.main_device(el);
                match Surface::new(
                    el,
                    block::attributes(position, on_wayland),
                    setup,
                    self.theme,
                    false,
                ) {
                    Ok(surface) => {
                        // Wayland: no window stays on top; the focus is the
                        // best this window can ask for (§B.8.6.3).
                        if on_wayland {
                            surface.window.focus_window();
                        }
                        self.blocks.push(BlockSurface { request, surface });
                    }
                    Err(e) => {
                        let line = format!("a block window did not open: {e:#}");
                        tracing::warn!("{line}");
                        self.shared.update(|m| m.note(line));
                    }
                }
            }
        }
    }

    fn draw_block(&mut self, index: usize) {
        let Some(open) = self.blocks.get_mut(index) else {
            return;
        };
        let request = open.request;
        let Some(block) = self
            .shared
            .read(|m| m.blocks.iter().find(|b| b.id == request).cloned())
        else {
            return;
        };
        let mut actions = Vec::new();
        open.surface
            .paint(|ui| view::block_window(ui, &block, Instant::now(), &mut actions));
        for action in actions {
            self.act(action, None);
        }
    }

    fn block_event(&mut self, index: usize, event: &WindowEvent) {
        match event {
            // No close and no dismiss: the window lasts exactly its seconds.
            WindowEvent::CloseRequested => {
                tracing::debug!("a block window stays up until its time ends");
            }
            WindowEvent::RedrawRequested => self.draw_block(index),
            WindowEvent::Resized(size) => {
                if let Some(open) = self.blocks.get_mut(index) {
                    open.surface.resized(size.width, size.height);
                }
            }
            _ => {
                if let Some(open) = self.blocks.get_mut(index) {
                    open.surface.on_event(event);
                }
            }
        }
    }

    fn draw_indicator(&mut self) {
        let Some(surface) = &mut self.indicator else {
            return;
        };
        let (sharing, admin) = self
            .shared
            .read(|m| (m.sharing.clone(), m.admin_sessions.clone()));
        let mut actions = Vec::new();
        let rounded = self.indicator_rounded;
        surface.paint(|ui| {
            view::indicator_pill(ui, &sharing, &admin, Instant::now(), &mut actions, rounded);
        });
        for action in actions {
            self.act(action, None);
        }
    }

    fn indicator_event(&mut self, event: &WindowEvent) {
        let Some(surface) = &mut self.indicator else {
            return;
        };
        match event {
            // It stays up while the screen is shared (§B.6 "always"): Stop
            // ends the sharing, and the window goes with it.
            WindowEvent::CloseRequested => {
                tracing::debug!("the sharing indicator stays up while this screen is shared");
            }
            WindowEvent::RedrawRequested => self.draw_indicator(),
            WindowEvent::Resized(size) => surface.resized(size.width, size.height),
            _ => surface.on_event(event),
        }
    }

    fn draw_main(&mut self) {
        let Some(main) = &mut self.main else { return };
        let model = self.shared.read(Clone::clone);
        let mut actions = Vec::new();
        let form = &mut self.form;
        main.paint(|ui| view::main_window(ui, &model, form, Instant::now(), &mut actions));
        for action in actions {
            self.act(action, model.id.as_deref());
        }
    }

    fn draw_stream(&mut self) {
        let Some(view) = &mut self.stream else { return };
        if self.link.slot.take(&mut view.picture)
            && let Some(rs) = view.surface.painter.render_state()
        {
            let mut renderer = rs.renderer.write();
            view.video
                .upload(&rs.device, &rs.queue, &mut renderer, &view.picture);
        }
        let viewing = self.shared.read(|m| match &m.client {
            ClientStage::Live(v) => Some(v.clone()),
            _ => None,
        });
        let picture = view.video.id().zip(view.video.size());
        let mut actions = Vec::new();
        let mut drawn = None;
        let sent = view.input_sent;
        view.surface.paint(|ui| {
            drawn = view::stream_window(
                ui,
                viewing.as_ref(),
                picture,
                sent,
                Instant::now(),
                &mut actions,
            );
        });
        let ppp = f64::from(view.surface.ctx.pixels_per_point());
        view.forwarder.set_picture(drawn.map(|r| PictureRect {
            x: f64::from(r.min.x) * ppp,
            y: f64::from(r.min.y) * ppp,
            width: f64::from(r.width()) * ppp,
            height: f64::from(r.height()) * ppp,
        }));
        for action in actions {
            self.act(action, None);
        }
    }

    fn act(&mut self, action: Action, id: Option<&str>) {
        match action {
            Action::Connect(id) => self.command(Command::Connect(id)),
            Action::ConnectAnyway(id) => self.command(Command::ConnectAnyway(id)),
            Action::AdminConfirm { id } => {
                // Only a sheet that offers the administrator answer shows its
                // confirmation (§B.2.1).
                self.popups.shared().update(|m| {
                    if m.levels.get(&id).is_some_and(|l| {
                        matches!(l.answers.admin, Some(AdminPath::TornectConfirmation { .. }))
                    }) {
                        m.admin_confirm.insert(id);
                    }
                });
            }
            Action::AdminPrompt { id } => {
                if tornect_core::levels::ADMIN_HELPER {
                    // The answer goes to the host, which asks Windows to
                    // start the administrator helper between the answer and
                    // the accept (§B.8.7.5). Cancelled, failed or late, the
                    // sheet comes back saying administrator access was not
                    // given, with the other answers, armed anew; the window's
                    // return from Windows' prompt re-arms it too.
                    let _ = self.popups.answer_session(
                        id,
                        tornect_signal::pairing::SessionDecision::AllowOnceAdmin,
                    );
                } else {
                    // No helper in this build: the answer ends at once as a
                    // cancelled prompt does: the sheet says administrator
                    // access was not given, keeps its other answers, and arms
                    // them again, as on the prompt's return.
                    self.form.rearm(id);
                    self.popups.shared().update(|m| {
                        if m.popups.iter().any(|p| p.id == id) {
                            m.admin_not_given.insert(id);
                        }
                    });
                }
            }
            Action::StopSharing => self.command(Command::StopSharing),
            Action::MoveIndicator => {
                if let Some(surface) = &self.indicator
                    && let Err(e) = surface.window.drag_window()
                {
                    tracing::debug!(error = %e, "moving the sharing indicator");
                }
            }
            Action::EndViewing => self.command(Command::EndViewing),
            Action::DismissConnect => self.popups.shared().update(|m| {
                if matches!(m.client, ClientStage::Ended(_)) {
                    m.client = ClientStage::Idle;
                    m.dial = super::model::Dial::default();
                }
            }),
            Action::Grant => self.command(Command::Grant),
            Action::Revoke => self.command(Command::Revoke),
            Action::Pair {
                id,
                decision,
                pointer,
            } => {
                // Not the label typed: no name goes to the log.
                let accepted = matches!(
                    decision,
                    tornect_signal::pairing::PairDecision::Accept { .. }
                );
                tracing::debug!(id, accepted, pointer, "pairing question answered");
                self.popups.answer_pairing(id, decision);
                self.form.labels.remove(&id);
                self.form.codes.remove(&id);
            }
            Action::PairCode { id, code, label } => {
                // Neither the code nor the label goes to the log.
                tracing::debug!(id, "pairing code typed");
                self.popups.answer_pairing_code(id, &code, label);
                self.form.labels.remove(&id);
                self.form.codes.remove(&id);
            }
            Action::Session {
                id,
                decision,
                pointer,
            } => {
                tracing::debug!(id, ?decision, pointer, "session question answered");
                self.popups.answer_session(id, decision);
            }
            Action::Ask { id, allow, pointer } => {
                tracing::debug!(id, allow, pointer, "\"Ask before starting\" answered");
                self.popups.answer_ask(id, allow);
            }
            Action::Block { id } => {
                tracing::debug!(id, "Block pressed in a block window");
                self.popups.answer_block(id);
            }
            Action::AcknowledgeBanner => self.command(Command::AcknowledgeBanner),
            Action::Confirm {
                id,
                matched,
                pointer,
            } => {
                tracing::debug!(id, matched, pointer, "code question answered");
                self.popups.answer_confirm(id, matched);
            }
            Action::CopyId => {
                if let (Some(main), Some(id)) = (&mut self.main, id) {
                    main.state.set_clipboard_text(id.replace(' ', ""));
                }
            }
            Action::Copy(text) => {
                if let Some(main) = &mut self.main {
                    main.state.set_clipboard_text(text);
                }
            }
            Action::Ping(id) => self.command(Command::Ping(id)),
            Action::ForgetHost(id) => self.command(Command::ForgetHost(id)),
            Action::RenameHost(id, name) => self.command(Command::RenameHost(id, name)),
            Action::SaveEntry(id, name) => self.command(Command::SaveEntry(id, name)),
            Action::ClearHistory => self.command(Command::ClearHistory),
            Action::SetHistory(on) => self.command(Command::SetHistory(on)),
            Action::AskPassword(id) => {
                self.form.ua.clear();
                self.command(Command::AskPassword(id, None, None));
            }
            Action::AskAdmin(id, action) => {
                self.form.ua.clear();
                self.command(Command::AskPassword(id, Some(action), None));
            }
            Action::AskUnlock(id, device) => {
                self.form.ua.clear();
                self.command(Command::AskPassword(
                    id,
                    Some(crate::ua_client::AdminAction::Unlock),
                    Some(device),
                ));
            }
            Action::SubmitPrompt { pointer } => {
                // The accept answers the pointer only: no key sequence sends
                // a password, remembered or typed (§B.8.10).
                if !pointer {
                    return;
                }
                let Some(prompt) = self.popups.shared().read(|m| m.prompt.clone()) else {
                    self.form.ua.clear();
                    return;
                };
                let ua = &mut self.form.ua;
                let typed = std::mem::take(&mut ua.password);
                let choice = super::backend::UaChoice {
                    password: (!typed.is_empty()).then(|| super::backend::Secret(typed)),
                    view_only: ua.view_only,
                    remember: ua.remember,
                    administrator: ua.administrator && prompt.may_admin,
                };
                self.form.ua.clear();
                self.popups.shared().update(|m| m.prompt = None);
                self.command(match prompt.admin {
                    Some(action) => Command::Admin(prompt.id, action, prompt.target, choice),
                    None => Command::ConnectUnattended(prompt.id, choice),
                });
            }
            Action::ClosePrompt => {
                self.form.ua.clear();
                self.popups.shared().update(|m| m.prompt = None);
            }
            Action::ConfirmSetupChanged(id) => self.command(Command::ConfirmSetupChanged(id)),
            Action::DeviceWords(key) => self.command(Command::DeviceWords(key)),
        }
    }

    /// Send what the forwarder has ready.
    fn send_input(&mut self) {
        let Some(view) = &mut self.stream else { return };
        for event in view.forwarder.drain() {
            if self.link.send(event) {
                view.input_sent += 1;
            } else {
                tracing::debug!(
                    "an input event was not sent (no control session, or the queue is full)"
                );
            }
        }
    }

    fn stream_event(&mut self, event: WindowEvent) {
        let Some(view) = &mut self.stream else { return };
        let control = view.forwarder.is_open();
        match &event {
            WindowEvent::CloseRequested => {
                // Closing the window ends the session, with its goodbye.
                self.command(Command::EndViewing);
                self.close_stream();
                self.stream_dismissed = true;
                return;
            }
            WindowEvent::RedrawRequested => {
                self.draw_stream();
                return;
            }
            WindowEvent::Resized(size) => {
                view.surface.resized(size.width, size.height);
                return;
            }
            // Keys go to the host by physical scancode, and never to egui
            // during a control session (slice.md §2).
            WindowEvent::KeyboardInput {
                event: key,
                is_synthetic,
                ..
            } if control => {
                // Synthetic events are winit's replay of keys held when the
                // focus moved; the host lets go of those on focus loss. The
                // host's own autorepeat repeats a held key.
                if !*is_synthetic
                    && !key.repeat
                    && let Some(usb) = keys::usb_for_physical_key(key.physical_key)
                {
                    view.forwarder.key(usb, key.state == ElementState::Pressed);
                }
            }
            WindowEvent::ModifiersChanged(_) if control => {}
            WindowEvent::CursorMoved { position, .. } => {
                view.forwarder.moved((position.x, position.y));
                view.surface.on_event(&event);
            }
            WindowEvent::CursorLeft { .. } => {
                view.forwarder.left();
                view.surface.on_event(&event);
            }
            WindowEvent::MouseInput {
                state, button: b, ..
            } => {
                if let Some(b) = button(*b) {
                    view.forwarder.button(b, *state == ElementState::Pressed);
                }
                view.surface.on_event(&event);
            }
            WindowEvent::MouseWheel { delta, .. } => {
                match delta {
                    MouseScrollDelta::LineDelta(x, y) => view
                        .forwarder
                        .wheel((f64::from(*x), f64::from(*y)), (0.0, 0.0)),
                    MouseScrollDelta::PixelDelta(p) => view.forwarder.wheel((0.0, 0.0), (p.x, p.y)),
                }
                view.surface.on_event(&event);
            }
            WindowEvent::Focused(false) => {
                view.forwarder.focus_lost();
                view.surface.on_event(&event);
            }
            _ => view.surface.on_event(&event),
        }
        self.send_input();
    }
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.main.is_some() {
            return;
        }
        let attrs = Window::default_attributes()
            .with_title(self.title)
            .with_inner_size(LogicalSize::new(1200.0, self.height))
            .with_min_inner_size(LogicalSize::new(960.0, 640.0));
        match Surface::new(
            el,
            attrs,
            new_device(el.owned_display_handle()),
            self.theme,
            false,
        ) {
            Ok(surface) => {
                start_minimised(&*surface.window, self.background.is_some());
                self.main = Some(surface);
                self.start_probe(el);
                self.sync_indicator(el);
                self.sync_blocks(el);
            }
            Err(e) => {
                self.error = Some(e.context("opening the Tornect window"));
                // Nothing can be shown: shut the tokio side down and leave.
                self.quit(el);
                el.exit();
            }
        }
    }

    fn user_event(&mut self, el: &ActiveEventLoop, event: UserEvent) {
        let UserEvent::Wake(why) = event;
        match why {
            Wake::Frame => {
                if let Some(view) = &self.stream {
                    view.surface.window.request_redraw();
                }
            }
            Wake::Show => {
                if let Some(main) = &self.main {
                    let form = &mut self.form;
                    show_window(&*main.window, || form.window_came_back());
                    main.window.request_redraw();
                }
            }
            Wake::Quit => {
                tracing::info!("asked to quit by a signal: ending every session");
                self.quit(el);
                if let Some(main) = &self.main {
                    main.window.request_redraw();
                }
            }
            Wake::Model | Wake::Attention => {
                if self.quit_at.is_some() {
                    self.quit(el);
                }
                self.sync_stream(el);
                self.sync_indicator(el);
                self.sync_blocks(el);
                self.sync_notices();
                for open in &self.blocks {
                    open.surface.window.request_redraw();
                }
                if let Some(main) = &self.main {
                    if why == Wake::Attention && ask_attention(&*main.window) {
                        self.form.window_came_back();
                    }
                    main.window.request_redraw();
                }
                if let Some(view) = &self.stream {
                    view.surface.window.request_redraw();
                }
                if let Some(surface) = &self.indicator {
                    surface.window.request_redraw();
                }
            }
        }
    }

    fn window_event(&mut self, el: &ActiveEventLoop, id: WindowId, event: WindowEvent) {
        if self
            .stream
            .as_ref()
            .is_some_and(|v| v.surface.window.id() == id)
        {
            self.stream_event(event);
            return;
        }
        if self.indicator.as_ref().is_some_and(|s| s.window.id() == id) {
            self.indicator_event(&event);
            return;
        }
        if let Some(index) = self.blocks.iter().position(|b| b.surface.window.id() == id) {
            self.block_event(index, &event);
            return;
        }
        if self
            .probe
            .as_ref()
            .is_some_and(|(s, _)| s.window.id() == id)
        {
            // Its first frame is all the probe waits for.
            if matches!(event, WindowEvent::RedrawRequested) {
                self.draw_probe();
            }
            return;
        }
        let Some(main) = &mut self.main else { return };
        if main.window.id() != id {
            return;
        }
        if comes_back(&event) {
            self.form.window_came_back();
            main.window.request_redraw();
        }
        match &event {
            WindowEvent::CloseRequested => self.quit(el),
            WindowEvent::RedrawRequested => self.draw_main(),
            WindowEvent::Resized(size) => main.resized(size.width, size.height),
            _ => main.on_event(&event),
        }
    }

    fn about_to_wait(&mut self, el: &ActiveEventLoop) {
        let now = Instant::now();
        if let Some(quit_at) = self.quit_at
            && now.duration_since(quit_at) >= QUIT_WAIT
        {
            tracing::warn!("the goodbyes took too long; quitting anyway");
            el.exit();
            return;
        }
        let mut wake_at: Option<Instant> = self.quit_at.map(|at| at + QUIT_WAIT);
        let mut earliest = |at: Instant| {
            wake_at = Some(wake_at.map_or(at, |w| w.min(at)));
        };
        // Coalesced pointer moves and wheel turns go out at most every
        // `Forwarder::MOVE_EVERY`.
        let mut flushed = false;
        if let Some(view) = &mut self.stream
            && view.forwarder.has_pending()
        {
            let due = view.last_flush + Forwarder::MOVE_EVERY;
            if now >= due {
                view.forwarder.flush();
                view.last_flush = now;
                flushed = true;
            } else {
                earliest(due);
            }
        }
        if flushed {
            self.send_input();
        }
        // A release that found the input queue full is owed as a
        // `ReleaseAll` until the queue has room (SLICE-E E1-6).
        if self.stream.is_some() && self.link.settle() {
            earliest(now + OWED_RETRY);
        }
        // An indicator probe that drew nothing in time has failed.
        if let Some(due) = self.probe.as_ref().map(|(_, at)| *at + PROBE_WAIT) {
            if now >= due {
                self.probe_failed(&format!(
                    "it drew nothing within {} s",
                    PROBE_WAIT.as_secs()
                ));
            } else {
                earliest(due);
            }
        }
        // The block windows are put back on top every `block::REASSERT`.
        if !self.blocks.is_empty() {
            let due = self.blocks_asserted.map_or(now, |at| at + block::REASSERT);
            if now >= due {
                for open in &self.blocks {
                    block::reassert(&open.surface.window);
                }
                self.blocks_asserted = Some(now);
                earliest(now + block::REASSERT);
            } else {
                earliest(due);
            }
        }
        for surface in [
            self.main.as_mut(),
            self.stream.as_mut().map(|v| &mut v.surface),
            self.indicator.as_mut(),
        ]
        .into_iter()
        .flatten()
        .chain(self.blocks.iter_mut().map(|b| &mut b.surface))
        {
            if let Some(at) = surface.repaint_at {
                if at <= now {
                    surface.repaint_at = None;
                    surface.window.request_redraw();
                } else {
                    earliest(at);
                }
            }
        }
        el.set_control_flow(match wake_at {
            Some(at) => ControlFlow::WaitUntil(at),
            None => ControlFlow::Wait,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use tokio::sync::mpsc::error::TryRecvError;

    use super::super::model::Model;
    use super::*;

    /// Review finding E2-4: DX12 compiles shaders with FXC, whatever the
    /// environment says, so wgpu never looks for `dxcompiler.dll` by name, and
    /// no Agility SDK DLL path comes from `WGPU_DX12_AGILITY_SDK_PATH`.
    #[test]
    fn the_gpu_never_loads_a_shader_compiler_by_name() {
        let dx12 = dx12_options();
        assert!(
            matches!(dx12.shader_compiler, wgpu::Dx12Compiler::Fxc),
            "{:?}",
            dx12.shader_compiler
        );
        assert!(dx12.agility_sdk.is_none(), "{:?}", dx12.agility_sdk);
        /// A display that has no handle: `new_device` only stores it.
        #[derive(Debug, Clone)]
        struct NoDisplay;
        impl wgpu::rwh::HasDisplayHandle for NoDisplay {
            fn display_handle(
                &self,
            ) -> Result<wgpu::rwh::DisplayHandle<'_>, wgpu::rwh::HandleError> {
                Err(wgpu::rwh::HandleError::Unavailable)
            }
        }
        let WgpuSetup::CreateNew(setup) = new_device(NoDisplay) else {
            panic!("a window gets a new device");
        };
        assert!(matches!(
            setup
                .instance_descriptor
                .backend_options
                .dx12
                .shader_compiler,
            wgpu::Dx12Compiler::Fxc
        ));
    }

    /// A window call, as the recorder saw it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Call {
        SetMinimized(bool),
        Attention(Option<UserAttentionType>),
    }

    /// Records the calls instead of making them, for a window whose
    /// minimized state is `minimized`.
    struct Recorder {
        minimized: Option<bool>,
        calls: RefCell<Vec<Call>>,
    }

    impl Attention for Recorder {
        fn is_minimized(&self) -> Option<bool> {
            self.minimized
        }

        fn set_minimized(&self, minimized: bool) {
            self.calls.borrow_mut().push(Call::SetMinimized(minimized));
        }

        fn request_user_attention(&self, kind: Option<UserAttentionType>) {
            self.calls.borrow_mut().push(Call::Attention(kind));
        }
    }

    /// SLICE-E E1-1: a question or a session start asks for the user's
    /// attention and never takes the keyboard focus (on Windows,
    /// `focus_window` forced the window to the foreground, and the keys typed
    /// for another program then landed on the card). Only a window known to
    /// be minimized is brought back: on X11 that request is an activation
    /// too.
    #[test]
    fn the_wake_asks_for_attention_without_taking_the_focus() {
        let attention = Call::Attention(Some(UserAttentionType::Critical));
        for (minimized, expected) in [
            (Some(true), vec![Call::SetMinimized(false), attention]),
            (Some(false), vec![attention]),
            (None, vec![attention]),
        ] {
            let window = Recorder {
                minimized,
                calls: RefCell::default(),
            };
            // Review N-1: only a window brought back re-arms its cards.
            assert_eq!(ask_attention(&window), minimized == Some(true));
            assert_eq!(
                window.calls.into_inner(),
                expected,
                "minimized: {minimized:?}"
            );
        }
    }

    /// §B.1.1, §B.2.1: `Show` arms every open card again whatever the
    /// window's state, where a question's attention re-arms only a window it
    /// brought back. Shown failing first (with the question's rule, only the
    /// minimized window re-armed).
    #[test]
    fn show_rearms_every_open_sheet() {
        for minimized in [Some(true), Some(false), None] {
            let window = Recorder {
                minimized,
                calls: RefCell::default(),
            };
            let mut rearmed = 0;
            show_window(&window, || rearmed += 1);
            assert_eq!(rearmed, 1, "minimized: {minimized:?}");
        }
    }

    /// SLICE-E E1-1 for `Show`: a window known to be minimized is brought
    /// back, then the attention request; never the keyboard focus (the seam
    /// has no focus call), and nothing else.
    #[test]
    fn show_unminimises_and_asks_attention_without_focus() {
        let attention = Call::Attention(Some(UserAttentionType::Critical));
        for (minimized, expected) in [
            (Some(true), vec![Call::SetMinimized(false), attention]),
            (Some(false), vec![attention]),
            (None, vec![attention]),
        ] {
            let window = Recorder {
                minimized,
                calls: RefCell::default(),
            };
            show_window(&window, || {});
            assert_eq!(
                window.calls.into_inner(),
                expected,
                "minimized: {minimized:?}"
            );
        }
    }

    /// A window as the tests open it: the model, the popups, the link and the
    /// command channel, nothing on screen.
    fn app() -> (App, mpsc::UnboundedReceiver<Command>) {
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let popups = Popups::new(Arc::clone(&shared));
        let (tx, rx) = mpsc::unbounded_channel();
        (
            App::new(shared, popups, Arc::new(StreamLink::default()), tx),
            rx,
        )
    }

    /// §B.1.1 (decision M1-58): in background mode the row "indicator shown"
    /// passes only once the indicator probe drew its window, as the host
    /// reports it (the row of its readiness answer); until then it warns
    /// with its own text.
    #[test]
    fn the_indicator_row_passes_only_after_the_probe_drew() {
        use tornect_core::unattended::readiness::Probe;
        let (mut app, _rx) = app();
        let shown = crate::host::IndicatorShown::default();
        app.background = Some(shown.clone());
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = crate::unattended::test_context(tmp.path(), None);
        ctx.indicator = Some(shown.clone());
        let pending = Probe::Warn(tornect_platform::readiness::INDICATOR_NOT_SHOWN.to_owned());
        assert_eq!(ctx.readiness_now().consent_indicator, pending);
        assert!(!shown.is_set());
        app.probe_drew();
        assert!(shown.is_set());
        assert_eq!(ctx.readiness_now().consent_indicator, Probe::Ok);
        assert!(app.probe.is_none(), "the probe closes at its first frame");
    }

    /// A probe that cannot open, or draws nothing in time, keeps the row
    /// warning (and so the host refusing unattended sessions) and says why
    /// in the recent activity.
    #[test]
    fn a_failed_probe_keeps_the_row_failing() {
        use tornect_core::unattended::readiness::Probe;
        let (mut app, _rx) = app();
        let shown = crate::host::IndicatorShown::default();
        app.background = Some(shown.clone());
        app.probe_failed("no GPU surface for the window: lost");
        assert!(!shown.is_set());
        assert_eq!(
            shown.row(),
            Probe::Warn(tornect_platform::readiness::INDICATOR_NOT_SHOWN.to_owned())
        );
        let said = app.shared.read(|m| m.events.clone());
        assert!(
            said.iter()
                .any(|l| l.contains("the sharing indicator could not be shown")
                    && l.contains("unattended sessions are refused")),
            "{said:?}"
        );
    }

    /// §B.1.1: in background mode the main window is minimised as it opens,
    /// and nothing asks for attention; a window started by hand is left as
    /// it opens.
    #[test]
    fn background_starts_the_window_minimised() {
        for (background, expected) in [(true, vec![Call::SetMinimized(true)]), (false, vec![])] {
            let window = Recorder {
                minimized: Some(false),
                calls: RefCell::default(),
            };
            start_minimised(&window, background);
            assert_eq!(
                window.calls.into_inner(),
                expected,
                "background: {background}"
            );
        }
    }

    /// §B.1.1: in background mode, an indicator that does not open at
    /// a session brings the minimised main window back with the attention a
    /// question asks for, so its banner shows the session, and its cards arm
    /// again; never the keyboard focus. A window started by hand is left as
    /// it was (its banner is up).
    #[test]
    fn a_failed_indicator_raises_the_banner_in_background() {
        let attention = Call::Attention(Some(UserAttentionType::Critical));
        for (minimized, expected) in [
            (Some(true), vec![Call::SetMinimized(false), attention]),
            (Some(false), vec![attention]),
            (None, vec![attention]),
        ] {
            let window = Recorder {
                minimized,
                calls: RefCell::default(),
            };
            assert_eq!(
                indicator_failed(&window, true),
                minimized == Some(true),
                "minimized: {minimized:?}"
            );
            assert_eq!(window.calls.into_inner(), expected);
            let by_hand = Recorder {
                minimized,
                calls: RefCell::default(),
            };
            assert!(!indicator_failed(&by_hand, false));
            assert!(by_hand.calls.into_inner().is_empty());
        }
    }

    /// A bus that records the notifications it is asked to show and take
    /// down (Linux).
    #[cfg(target_os = "linux")]
    #[derive(Default)]
    struct FakeBus {
        shown: std::sync::Mutex<Vec<tornect_platform::notify::Notice>>,
        closed: std::sync::Mutex<Vec<u32>>,
    }

    #[cfg(target_os = "linux")]
    impl tornect_platform::notify::NotificationBus for FakeBus {
        fn actions(
            &self,
        ) -> tornect_platform::polkit::BoxFuture<
            '_,
            Result<mpsc::Receiver<(u32, String)>, tornect_platform::notify::NotifyError>,
        > {
            let (_tx, rx) = mpsc::channel(1);
            Box::pin(async move { Ok(rx) })
        }

        fn notify<'a>(
            &'a self,
            notice: &'a tornect_platform::notify::Notice,
        ) -> tornect_platform::polkit::BoxFuture<
            'a,
            Result<u32, tornect_platform::notify::NotifyError>,
        > {
            let mut shown = self.shown.lock().unwrap();
            shown.push(notice.clone());
            let id = u32::try_from(shown.len()).unwrap();
            Box::pin(async move { Ok(id) })
        }

        fn close(&self, id: u32) -> tornect_platform::polkit::BoxFuture<'_, ()> {
            self.closed.lock().unwrap().push(id);
            Box::pin(async {})
        }
    }

    /// The first host sheet on screen, once there is one.
    async fn open_sheet(popups: &Popups) -> super::super::model::Popup {
        loop {
            if let Some(p) = popups.shared().read(|m| m.popups.first().cloned()) {
                return p;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// §B.1.1 (MUST): in background mode a new sheet raises the window (the
    /// attention a question asks for, `Wake::Attention`) and mirrors one
    /// desktop notification, with a fixed text, which goes when the sheet
    /// goes, however it ends; a pairing sheet says so, any other host sheet
    /// says that a device asks to connect. A window started by hand shows
    /// none (its sheet is up).
    #[tokio::test]
    async fn a_sheet_in_background_raises_and_notifies() {
        use tornect_signal::consent::LocalAllow as _;
        use tornect_signal::fsm::host::KillSwitch;
        use tornect_signal::pairing::{Consent as _, PairDecision, PairingPeer};

        use super::super::consent::{GuiConsent, Withdraw};
        use super::super::notice::{Asks, NoticeChange};

        let woken = Arc::new(std::sync::Mutex::new(Vec::new()));
        let into = Arc::clone(&woken);
        let shared = Shared::new(
            Model::default(),
            Arc::new(move |why| into.lock().unwrap().push(why)),
        );
        let popups = Popups::new(Arc::clone(&shared));
        let (tx, mut commands) = mpsc::unbounded_channel();
        let mut app = App::new(
            Arc::clone(&shared),
            Arc::clone(&popups),
            Arc::new(StreamLink::default()),
            tx,
        );
        app.background = Some(crate::host::IndicatorShown::default());
        let (_started_tx, started) = tokio::sync::watch::channel(0u64);
        let consent = GuiConsent::new(
            Arc::clone(&popups),
            Withdraw {
                kill: KillSwitch::new(),
                started,
                live: Arc::new(|| false),
            },
        );
        // What the window hands the mirror, and the mirror on a fake bus.
        let (changes_tx, changes) = mpsc::unbounded_channel();
        #[cfg(target_os = "linux")]
        let bus = Arc::new(FakeBus::default());
        #[cfg(target_os = "linux")]
        let mirroring = {
            let bus = Arc::clone(&bus);
            tokio::spawn(super::super::notice::mirror(
                move || async move { Ok(bus as Arc<dyn tornect_platform::notify::NotificationBus>) },
                changes,
                |line| panic!("{line}"),
            ))
        };
        #[cfg(not(target_os = "linux"))]
        drop(changes);
        let mut handed = |app: &mut App| {
            app.sync_notices();
            let mut sent = Vec::new();
            while let Ok(command) = commands.try_recv() {
                let Command::Notice(change) = command else {
                    panic!("not a notification: {command:?}");
                };
                let _ = changes_tx.send(change);
                sent.push(change);
            }
            sent
        };

        // A pairing sheet: the raise, then one notification, then none more.
        let device = tornect_core::DeviceIdentity::from_seed(&[8; 32]).id();
        let peer = PairingPeer {
            device,
            name: "Phone".to_owned(),
            fingerprint: device.fingerprint(),
            pinned_label: None,
        };
        woken.lock().unwrap().clear();
        let asking = consent.pairing(&peer, "123 456");
        tokio::pin!(asking);
        let sheet = tokio::select! {
            _ = &mut asking => panic!("answered before anyone did"),
            sheet = open_sheet(&popups) => sheet,
        };
        assert!(
            woken.lock().unwrap().contains(&Wake::Attention),
            "the sheet raises the window"
        );
        assert_eq!(
            handed(&mut app),
            vec![NoticeChange::Show {
                sheet: sheet.id,
                asks: Asks::Pair
            }]
        );
        assert_eq!(handed(&mut app), vec![], "one notification per sheet");
        // Answered: the sheet goes, and its notification with it.
        assert!(popups.answer_pairing(sheet.id, PairDecision::Reject));
        assert_eq!(asking.await, PairDecision::Reject);
        assert_eq!(
            handed(&mut app),
            vec![NoticeChange::Close { sheet: sheet.id }]
        );

        // "Ask before starting", which times out: it says a device asks to
        // connect, and goes with its sheet.
        let asking = consent.ask_at(
            &[1; 8],
            "Laptop",
            tornect_core::levels::Elevation::None,
            Duration::from_millis(300),
        );
        tokio::pin!(asking);
        let ask = tokio::select! {
            _ = &mut asking => panic!("answered before its time"),
            sheet = open_sheet(&popups) => sheet,
        };
        assert_eq!(
            handed(&mut app),
            vec![NoticeChange::Show {
                sheet: ask.id,
                asks: Asks::Connect
            }]
        );
        assert!(!asking.await, "its time ran out: denied");
        assert_eq!(
            handed(&mut app),
            vec![NoticeChange::Close { sheet: ask.id }]
        );

        #[cfg(target_os = "linux")]
        {
            drop(changes_tx);
            mirroring.await.unwrap();
            let shown = bus.shown.lock().unwrap().clone();
            let texts: Vec<(&str, &str)> = shown
                .iter()
                .map(|n| (n.summary.as_str(), n.body.as_str()))
                .collect();
            assert_eq!(
                texts,
                vec![
                    (
                        "A device asks to pair with this computer.",
                        "Open Tornect to answer."
                    ),
                    (
                        "A device asks to connect to this computer.",
                        "Open Tornect to answer."
                    ),
                ]
            );
            assert!(
                shown
                    .iter()
                    .all(|n| n.actions.is_empty() && n.sound.is_none())
            );
            for _ in 0..100 {
                if bus.closed.lock().unwrap().len() == 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
            let mut closed = bus.closed.lock().unwrap().clone();
            closed.sort_unstable();
            assert_eq!(closed, vec![1, 2], "each taken down");
        }

        // A window started by hand: the sheet raises it, no notification.
        app.background = None;
        let asking = consent.pairing(&peer, "654 321");
        tokio::pin!(asking);
        let sheet = tokio::select! {
            _ = &mut asking => panic!("answered before anyone did"),
            sheet = open_sheet(&popups) => sheet,
        };
        assert!(commands.try_recv().is_err());
        app.sync_notices();
        assert!(commands.try_recv().is_err(), "no notification by hand");
        assert!(popups.answer_pairing(sheet.id, PairDecision::Reject));
        assert_eq!(asking.await, PairDecision::Reject);
    }

    /// Review N-1: the main window is back in view when it gets the focus or
    /// stops being hidden; its cards then arm again.
    #[test]
    fn focus_and_unhiding_bring_the_window_back() {
        assert!(comes_back(&WindowEvent::Focused(true)));
        assert!(comes_back(&WindowEvent::Occluded(false)));
        assert!(!comes_back(&WindowEvent::Focused(false)));
        assert!(!comes_back(&WindowEvent::Occluded(true)));
        assert!(!comes_back(&WindowEvent::RedrawRequested));
    }

    /// The indicator's Stop asks the tokio side to stop sharing, as the
    /// banner's does, and nothing else; moving it with no window up does
    /// nothing.
    /// The window titles, which the window manager, the taskbar, Alt+Tab,
    /// screen-share pickers and an attention request show, name nobody: the
    /// main window is "Tornect", the stream window "Tornect: remote screen",
    /// the indicator "Tornect: sharing". An attention request carries no
    /// text of its own (the main window's taskbar entry flashes).
    #[test]
    fn no_window_title_names_anyone() {
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let popups = Popups::new(Arc::clone(&shared));
        let (tx, _rx) = mpsc::unbounded_channel();
        let app = App::new(shared, popups, Arc::new(StreamLink::default()), tx);
        assert_eq!(app.title, "Tornect");
        assert_eq!(STREAM_TITLE, "Tornect: remote screen");
        assert_eq!(indicator::TITLE, "Tornect: sharing");
    }

    #[test]
    fn the_indicators_stop_asks_to_stop_sharing() {
        let shared = Shared::new(Model::default(), Arc::new(|_| {}));
        let popups = Popups::new(Arc::clone(&shared));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut app = App::new(shared, popups, Arc::new(StreamLink::default()), tx);
        app.act(Action::StopSharing, None);
        assert_eq!(rx.try_recv(), Ok(Command::StopSharing));
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        app.act(Action::MoveIndicator, None);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
    }
}
