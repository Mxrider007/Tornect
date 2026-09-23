//! The manual winit loop (`docs/research/slice.md` §2, decision D10): one
//! event loop on the main thread and three kinds of window, each an egui
//! context with its own egui-winit state and egui-wgpu painter: the main
//! window, the stream window of a viewed session, and the sharing indicator
//! (`indicator`) while this screen is shared. The other two paint on the main
//! window's wgpu device. Never eframe: the stream window reads
//! `WindowEvent::KeyboardInput` itself, before egui, which drops the keys it
//! has no name for.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::ViewportId;
use egui_wgpu::winit::Painter;
use egui_wgpu::{RendererOptions, WgpuConfiguration, WgpuSetup, WgpuSetupExisting};
use tokio::sync::mpsc;
use winit::application::ApplicationHandler;
use winit::dpi::LogicalSize;
use winit::event::{ElementState, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow};
use winit::window::{UserAttentionType, Window, WindowAttributes, WindowId};

use super::backend::{Command, StreamLink};
use super::consent::Popups;
use super::indicator::{self, Change, Indicator};
use super::keys;
use super::model::{ClientStage, Shared, Wake};
use super::stream::{Forwarder, Picture, PictureRect, VideoTexture, button};
use super::view::{self, Action, Form};

/// How long closing the window waits for the goodbyes before it quits anyway.
const QUIT_WAIT: Duration = Duration::from_secs(10);

/// What the tokio side sends the event loop.
#[derive(Debug, Clone, Copy)]
pub enum UserEvent {
    /// Something to redraw or raise.
    Wake(Wake),
}

/// One window with its egui context, input state and painter.
struct Surface {
    window: Arc<Window>,
    ctx: egui::Context,
    state: egui_winit::State,
    painter: Painter,
    /// When egui asked to be drawn again.
    repaint_at: Option<Instant>,
}

impl Surface {
    fn new(
        el: &ActiveEventLoop,
        attrs: WindowAttributes,
        setup: WgpuSetup,
    ) -> anyhow::Result<Self> {
        let window = Arc::new(el.create_window(attrs)?);
        let ctx = egui::Context::default();
        let config = WgpuConfiguration {
            wgpu_setup: setup,
            ..WgpuConfiguration::default()
        };
        let mut painter = pollster::block_on(Painter::new(
            ctx.clone(),
            config,
            false,
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
            [0.0, 0.0, 0.0, 1.0],
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
            stream_dismissed: false,
            form: Form::default(),
            quit_at: None,
            stream_at: None,
            title: "Tornect",
            error: None,
        }
    }

    fn command(&self, command: Command) {
        // The tokio side outlives the window; a send can only fail after it
        // has shut down, when nothing is left to do anyway.
        let _ = self.commands.send(command);
    }

    fn quit(&mut self, el: &ActiveEventLoop) {
        if self.quit_at.is_none() {
            self.quit_at = Some(Instant::now());
            self.command(Command::Quit);
            self.stream = None;
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
            ClientStage::Live(v) => Some((v.host.clone(), v.control)),
            _ => None,
        });
        match live {
            None => {
                self.stream = None;
                self.stream_dismissed = false;
            }
            Some(_) if self.stream.is_some() || self.stream_dismissed || self.quit_at.is_some() => {
            }
            Some((host, control)) => {
                let setup = self.main_device(el);
                // The title is the host's pinned label, never its onion
                // address (UI_PLAN §8: privacy on screen shares).
                let mut attrs = Window::default_attributes()
                    .with_title(host)
                    .with_inner_size(LogicalSize::new(1280.0, 760.0));
                if let Some((x, y)) = self.stream_at {
                    attrs = attrs.with_position(winit::dpi::PhysicalPosition::new(x, y));
                }
                match Surface::new(el, attrs, setup) {
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
                || WgpuSetup::from_display_handle(el.owned_display_handle()),
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

    /// Open the indicator window at the first shared session, redraw it on a
    /// change, close it at the last end.
    fn sync_indicator(&mut self, el: &ActiveEventLoop) {
        let sharing = self.shared.read(|m| m.sharing.clone());
        match self.shown.sync(&sharing) {
            Change::Keep => {}
            Change::Open => {
                let rows = self.shown.rows();
                // Top-right of the primary monitor where the desktop has one
                // and lets a client place its window (not Wayland).
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
                match Surface::new(el, indicator::attributes(rows, position), setup) {
                    Ok(surface) => self.indicator = Some(surface),
                    Err(e) => {
                        // The banner in the main window still shows the
                        // session; the next session tries again.
                        let line = format!("the sharing indicator did not open: {e:#}");
                        tracing::warn!("{line}");
                        self.shared.update(|m| m.note(line));
                    }
                }
            }
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

    fn draw_indicator(&mut self) {
        let Some(surface) = &mut self.indicator else {
            return;
        };
        let sharing = self.shared.read(|m| m.sharing.clone());
        let mut actions = Vec::new();
        surface.paint(|ui| view::indicator(ui, &sharing, Instant::now(), &mut actions));
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
            Action::StopSharing => self.command(Command::StopSharing),
            Action::MoveIndicator => {
                if let Some(surface) = &self.indicator
                    && let Err(e) = surface.window.drag_window()
                {
                    tracing::debug!(error = %e, "moving the sharing indicator");
                }
            }
            Action::EndViewing => self.command(Command::EndViewing),
            Action::Grant => self.command(Command::Grant),
            Action::Revoke => self.command(Command::Revoke),
            Action::Pair { id, decision } => {
                self.popups.answer_pairing(id, decision);
                self.form.labels.remove(&id);
            }
            Action::Session { id, decision } => {
                self.popups.answer_session(id, decision);
            }
            Action::Confirm { id, matched } => {
                self.popups.answer_confirm(id, matched);
            }
            Action::CopyId => {
                if let (Some(main), Some(id)) = (&mut self.main, id) {
                    main.state.set_clipboard_text(id.replace(' ', ""));
                }
            }
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
                self.stream = None;
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
            .with_inner_size(LogicalSize::new(560.0, 720.0));
        match Surface::new(
            el,
            attrs,
            WgpuSetup::from_display_handle(el.owned_display_handle()),
        ) {
            Ok(surface) => {
                self.main = Some(surface);
                self.sync_indicator(el);
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
            Wake::Model | Wake::Attention => {
                if self.quit_at.is_some() {
                    self.quit(el);
                }
                self.sync_stream(el);
                self.sync_indicator(el);
                if let Some(main) = &self.main {
                    if why == Wake::Attention {
                        // A popup or a session: in front of the user, as far
                        // as the desktop allows (GNOME may only flag it).
                        main.window.set_minimized(false);
                        main.window.focus_window();
                        main.window
                            .request_user_attention(Some(UserAttentionType::Critical));
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
        let Some(main) = &mut self.main else { return };
        if main.window.id() != id {
            return;
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
        for surface in [
            self.main.as_mut(),
            self.stream.as_mut().map(|v| &mut v.surface),
            self.indicator.as_mut(),
        ]
        .into_iter()
        .flatten()
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
    use tokio::sync::mpsc::error::TryRecvError;

    use super::super::model::Model;
    use super::*;

    /// The indicator's Stop asks the tokio side to stop sharing, as the
    /// banner's does, and nothing else; moving it with no window up does
    /// nothing.
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
