//! The stream window's plumbing (`docs/UI_PLAN.md` §8, `docs/research/slice.md`
//! §2): the viewer's [`FrameSink`] hands the newest picture to the UI thread,
//! [`VideoTexture`] puts it in one registered native `Rgba8Unorm` texture with
//! `queue.write_texture` (a new texture only when the size changes, never one
//! per picture), and [`Forwarder`] turns the window's pointer, wheel and keys
//! into the 16-byte input events, only for a control session. The host's
//! monitors reach the model through the same sink ([`SlotSink::screens`]),
//! and the forwarder sends no positional input made against a picture from
//! before the host's screen changed (the monitors design's V5).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use tornect_codec::DecodedFrame;
use tornect_input::{Button, InputEvent, WHEEL_NOTCH, normalize};
use tornect_proto::{HostStats, QualityInfo, monitor_status, seq_reached};
use tornect_session::{FrameSink, Screens, ScreensNews};

use super::model::{ClientStage, ScreenNote, ScreensView, Shared, Wake};

/// The newest decoded picture, from the viewer task to the UI thread. A newer
/// picture replaces one the window has not drawn yet: the window shows the
/// present, and the host's flow control has already been answered.
#[derive(Debug, Default)]
pub struct FrameSlot {
    picture: Mutex<Picture>,
}

/// One picture: tightly packed RGBA.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Picture {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// `4 × width × height` bytes.
    pub rgba: Vec<u8>,
    /// The host's `Video` seq of the picture: what the stream window drew,
    /// for its input hold (the monitors design's V5).
    pub seq: u32,
    /// Not drawn yet.
    pub fresh: bool,
}

impl FrameSlot {
    /// Put picture `seq`, `frame`, in the slot, reusing its buffer.
    pub fn put(&self, seq: u32, frame: &DecodedFrame) {
        let mut slot = self.picture.lock().unwrap_or_else(PoisonError::into_inner);
        slot.seq = seq;
        slot.width = frame.width;
        slot.height = frame.height;
        slot.rgba.clear();
        slot.rgba.extend_from_slice(&frame.rgba);
        slot.fresh = true;
    }

    /// Forget a picture not drawn yet (the buffer stays for the next one): a
    /// new session starts here, and a closed window's last picture must never
    /// reach the next session's window (SLICE-E E1-3).
    pub fn clear(&self) {
        self.picture
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fresh = false;
    }

    /// Swap the fresh picture into `into` (whose buffer the slot keeps for the
    /// next one); `false`, and `into` untouched, when nothing new came.
    pub fn take(&self, into: &mut Picture) -> bool {
        let mut slot = self.picture.lock().unwrap_or_else(PoisonError::into_inner);
        if !slot.fresh {
            return false;
        }
        std::mem::swap(&mut *slot, into);
        slot.fresh = false;
        into.fresh = false;
        true
    }
}

/// The viewer's sink in the GUI: every picture goes to the slot, the stream
/// window is woken, and the HUD's counters move.
pub struct SlotSink {
    slot: Arc<FrameSlot>,
    shared: Arc<Shared>,
    pictures: u64,
}

impl SlotSink {
    /// Feed `slot`, and count in `shared`. A sink starts a viewed session:
    /// the slot is emptied first, so a picture the previous session left in
    /// it is never shown (SLICE-E E1-3).
    #[must_use]
    pub fn new(slot: Arc<FrameSlot>, shared: Arc<Shared>) -> Self {
        slot.clear();
        Self {
            slot,
            shared,
            pictures: 0,
        }
    }
}

impl FrameSink for SlotSink {
    fn picture(&mut self, seq: u32, frame: &DecodedFrame) {
        self.pictures += 1;
        self.slot.put(seq, frame);
        // The counters change on every picture; the model lock is cheap, and
        // `Wake::Frame` redraws only the stream window.
        let (pictures, size, timing) = (self.pictures, (frame.width, frame.height), frame.timing);
        self.shared.update_quiet(|m| {
            if let ClientStage::Live(v) = &mut m.client {
                v.pictures = pictures;
                v.size = size;
                v.stream.decode_ms.add_duration(timing.decode);
                v.stream.convert_ms.add_duration(timing.convert);
            }
        });
        self.shared.wake(Wake::Frame);
    }

    /// What the host applies, display only: written without a wake, so a
    /// host cannot make the window redraw (the quality design §5 rule 12);
    /// the next picture, which follows it, shows it.
    fn quality(&mut self, width: u32, height: u32, quality: &QualityInfo) {
        let applied = *quality;
        self.shared.update_quiet(|m| {
            if let ClientStage::Live(v) = &mut m.client {
                v.stream.applied = Some(applied);
                v.stream.announced = (width, height);
            }
        });
    }

    /// The host's means (at most one call a second, the viewer's
    /// coalescing), display only and without a wake, as [`Self::quality`].
    fn host_stats(&mut self, stats: &HostStats) {
        let stats = *stats;
        self.shared.update_quiet(|m| {
            if let ClientStage::Live(v) = &mut m.client {
                v.stream.host = Some(stats);
            }
        });
    }

    /// The host's monitors and why the viewer says them now (the monitors
    /// design §5.7): into the live session's [`ScreensView`], then a wake of
    /// the stream window only, as a picture's. An answer, a request given
    /// up or one not sent ends the window's "Switching…"; a `REMAPPED` list
    /// holds input made against earlier pictures back from its seq (V5).
    fn screens(&mut self, screens: &Screens, news: ScreensNews) {
        self.shared.update_quiet(|m| {
            if let ClientStage::Live(v) = &mut m.client {
                follow_screens(
                    v.screens.get_or_insert_with(ScreensView::default),
                    screens,
                    news,
                );
            }
        });
        self.shared.wake(Wake::Frame);
    }
}

/// Take the viewer's word on the host's monitors into `view` (the window's
/// [`ScreensView`]): the list as it stands, what the newest news asks the
/// window to say ([`ScreensView::last`], counted in
/// [`ScreensView::news`]), the end of a request on its way, and the hold of
/// a `REMAPPED` list. `NoAnswer` and `NotSent` repeat the list said last:
/// they change nothing of it and hold nothing back again.
fn follow_screens(view: &mut ScreensView, screens: &Screens, news: ScreensNews) {
    // The first list says nothing: it is the session's start.
    let before = (view.news > 0 || !view.monitors.is_empty()).then_some(view.shown);
    view.monitors.clone_from(&screens.monitors);
    view.all = screens.all;
    view.shown = screens.shown;
    view.list = screens.list;
    view.last = match news {
        ScreensNews::Layout => {
            before
                .is_some_and(|was| was != screens.shown)
                .then_some(ScreenNote::Changed {
                    shown: screens.shown,
                })
        }
        ScreensNews::Answer { asked, status } if status != monitor_status::OK => {
            view.switching = None;
            Some(ScreenNote::Refused { asked, status })
        }
        // An `OK` that shows another screen than the one asked for: the
        // monitor asked for went before the host switched, and it fell back.
        // Said as the host's change, so the window does not show one screen
        // under the name of another unannounced.
        ScreensNews::Answer { asked, .. } => {
            view.switching = None;
            (screens.shown != asked).then_some(ScreenNote::Changed {
                shown: screens.shown,
            })
        }
        ScreensNews::NoAnswer { asked } => {
            view.switching = None;
            Some(ScreenNote::NoAnswer { asked })
        }
        ScreensNews::NotSent { asked } => {
            view.switching = None;
            Some(ScreenNote::NotSent { asked })
        }
    };
    if screens.remapped && matches!(news, ScreensNews::Layout | ScreensNews::Answer { .. }) {
        view.hold_from = Some(screens.seq);
    }
    view.news = view.news.wrapping_add(1);
}

/// What to do with a picture's texture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upload {
    /// Write into the texture already there.
    Write,
    /// First picture, or a new size: make a texture of this size (keeping
    /// the egui texture id), then write.
    Allocate {
        /// Width.
        width: u32,
        /// Height.
        height: u32,
    },
    /// Not a picture that can be shown: nothing is written.
    Reject(&'static str),
}

/// The picture-to-texture bookkeeping, apart from the GPU: which texture size
/// is live, and whether a picture fits it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TexturePlan {
    size: Option<(u32, u32)>,
    max_side: u32,
}

impl TexturePlan {
    /// Textures no larger than `max_side` on either side (the device's limit).
    #[must_use]
    pub fn new(max_side: u32) -> Self {
        Self {
            size: None,
            max_side,
        }
    }

    /// The size of the live texture.
    #[must_use]
    pub fn size(&self) -> Option<(u32, u32)> {
        self.size
    }

    /// Decide what a `width`×`height` picture of `len` bytes needs. Its rows
    /// are tight, `4 × width` bytes (`queue.write_texture` needs no 256-byte
    /// row alignment), so anything but `4 × width × height` bytes is refused.
    pub fn plan(&mut self, width: u32, height: u32, len: usize) -> Upload {
        if width == 0 || height == 0 {
            return Upload::Reject("an empty picture");
        }
        if width > self.max_side || height > self.max_side {
            return Upload::Reject("a picture larger than the GPU's textures");
        }
        let expected = (width as usize)
            .checked_mul(height as usize)
            .and_then(|n| n.checked_mul(4));
        if expected != Some(len) {
            return Upload::Reject("a picture whose bytes do not match its size");
        }
        if self.size == Some((width, height)) {
            Upload::Write
        } else {
            self.size = Some((width, height));
            Upload::Allocate { width, height }
        }
    }

    /// Bytes per row of a `width`-wide picture.
    #[must_use]
    pub fn bytes_per_row(width: u32) -> u32 {
        width.saturating_mul(4)
    }
}

/// The stream's one texture, registered with the egui renderer once.
pub struct VideoTexture {
    plan: TexturePlan,
    texture: Option<wgpu::Texture>,
    id: Option<egui::TextureId>,
    /// Textures made so far (the first picture, and each change of size).
    pub allocations: u64,
    /// Pictures written.
    pub writes: u64,
}

impl VideoTexture {
    /// No texture yet; none larger than `max_side`.
    #[must_use]
    pub fn new(max_side: u32) -> Self {
        Self {
            plan: TexturePlan::new(max_side),
            texture: None,
            id: None,
            allocations: 0,
            writes: 0,
        }
    }

    /// The egui id to draw with, once a picture has been uploaded.
    #[must_use]
    pub fn id(&self) -> Option<egui::TextureId> {
        self.id
    }

    /// The size of the texture.
    #[must_use]
    pub fn size(&self) -> Option<(u32, u32)> {
        self.plan.size()
    }

    /// Upload `picture`, making a new texture only when its size changed, and
    /// pointing the same egui id at it.
    pub fn upload(
        &mut self,
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        renderer: &mut egui_wgpu::Renderer,
        picture: &Picture,
    ) -> Upload {
        let (width, height) = (picture.width, picture.height);
        let upload = self.plan.plan(width, height, picture.rgba.len());
        match upload {
            Upload::Reject(why) => {
                tracing::debug!(width, height, why, "picture not shown");
                return upload;
            }
            Upload::Allocate { width, height } => {
                let texture = device.create_texture(&wgpu::TextureDescriptor {
                    label: Some("tornect-stream"),
                    size: wgpu::Extent3d {
                        width,
                        height,
                        depth_or_array_layers: 1,
                    },
                    mip_level_count: 1,
                    sample_count: 1,
                    dimension: wgpu::TextureDimension::D2,
                    format: wgpu::TextureFormat::Rgba8Unorm,
                    usage: wgpu::TextureUsages::TEXTURE_BINDING
                        | wgpu::TextureUsages::COPY_DST
                        | wgpu::TextureUsages::COPY_SRC,
                    view_formats: &[],
                });
                let view = texture.create_view(&wgpu::TextureViewDescriptor::default());
                match self.id {
                    None => {
                        self.id = Some(renderer.register_native_texture(
                            device,
                            &view,
                            wgpu::FilterMode::Linear,
                        ));
                    }
                    Some(id) => renderer.update_egui_texture_from_wgpu_texture(
                        device,
                        &view,
                        wgpu::FilterMode::Linear,
                        id,
                    ),
                }
                if let Some(old) = self.texture.replace(texture) {
                    old.destroy();
                }
                self.allocations += 1;
            }
            Upload::Write => {}
        }
        let Some(texture) = &self.texture else {
            return Upload::Reject("no texture");
        };
        queue.write_texture(
            wgpu::TexelCopyTextureInfo {
                texture,
                mip_level: 0,
                origin: wgpu::Origin3d::ZERO,
                aspect: wgpu::TextureAspect::All,
            },
            &picture.rgba,
            wgpu::TexelCopyBufferLayout {
                offset: 0,
                bytes_per_row: Some(TexturePlan::bytes_per_row(width)),
                rows_per_image: Some(height),
            },
            wgpu::Extent3d {
                width,
                height,
                depth_or_array_layers: 1,
            },
        );
        self.writes += 1;
        upload
    }

    /// The texture itself (tests read it back).
    #[cfg(test)]
    fn texture(&self) -> Option<&wgpu::Texture> {
        self.texture.as_ref()
    }
}

/// Where the picture is drawn in the window, in physical pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PictureRect {
    /// Left edge.
    pub x: f64,
    /// Top edge.
    pub y: f64,
    /// Width.
    pub width: f64,
    /// Height.
    pub height: f64,
}

impl PictureRect {
    /// Whether `pos` is on the picture.
    #[must_use]
    pub fn contains(&self, pos: (f64, f64)) -> bool {
        pos.0 >= self.x
            && pos.1 >= self.y
            && pos.0 < self.x + self.width
            && pos.1 < self.y + self.height
    }

    /// `pos` normalized over the picture (clamped to its edges): the wire's
    /// `0..=65535` on each axis, so the host needs no viewer geometry.
    #[must_use]
    pub fn normalized(&self, pos: (f64, f64)) -> (u16, u16) {
        (
            normalize(pos.0 - self.x, self.width),
            normalize(pos.1 - self.y, self.height),
        )
    }
}

/// The largest rectangle of the picture's aspect that fits `avail`, centred
/// (letterboxed, `docs/UI_PLAN.md` §8): `(x, y, width, height)`.
#[must_use]
pub fn letterbox(avail: (f32, f32, f32, f32), picture: (u32, u32)) -> (f32, f32, f32, f32) {
    let (ax, ay, aw, ah) = avail;
    if picture.0 == 0 || picture.1 == 0 || aw <= 0.0 || ah <= 0.0 {
        return (ax, ay, 0.0, 0.0);
    }
    let scale = (aw / picture.0 as f32).min(ah / picture.1 as f32);
    let (w, h) = (picture.0 as f32 * scale, picture.1 as f32 * scale);
    (ax + (aw - w) / 2.0, ay + (ah - h) / 2.0, w, h)
}

/// A winit pointer button as the wire names it.
#[must_use]
pub fn button(b: winit::event::MouseButton) -> Option<Button> {
    use winit::event::MouseButton as M;
    Some(match b {
        M::Left => Button::Left,
        M::Right => Button::Right,
        M::Middle => Button::Middle,
        M::Back => Button::Back,
        M::Forward => Button::Forward,
        M::Other(_) => return None,
    })
}

/// Pixels of a touchpad scroll per wheel notch.
const PIXELS_PER_NOTCH: f64 = 40.0;

/// The window's input, turned into the events a control session sends.
///
/// Built open only for a control session: the gate is the mode of the signed
/// `SESSION_ACCEPT` (`ClientSession::accept().mode()`), never the `BindOk` of
/// the media stream (SLICE-C2 C2-6). A closed forwarder produces nothing.
///
/// Pointer moves and wheel turns are coalesced: at most one of each goes out
/// per [`Forwarder::flush`] (the window calls it at most every
/// [`Forwarder::MOVE_EVERY`]), and any pending one goes out before a button or
/// key, so the order the host sees is the order they happened in. That keeps
/// a fast mouse well under the host's input budget (250 events/s), which a
/// key must never lose to.
#[derive(Debug, Default)]
pub struct Forwarder {
    open: bool,
    picture: Option<PictureRect>,
    /// The part of the picture on screen, where the window shows less.
    visible: Option<PictureRect>,
    /// What the window draws over the picture (its toolbar).
    blocked: Vec<PictureRect>,
    /// The viewer paused this computer's input.
    paused: bool,
    cursor: Option<(f64, f64)>,
    held: BTreeSet<Button>,
    pending_move: Option<(u16, u16)>,
    last_move: Option<(u16, u16)>,
    wheel: (f64, f64),
    /// The seq of the first picture of another part of the host's desktop,
    /// until a picture at or after it is drawn: no move, wheel turn or
    /// press goes out meanwhile (the monitors design's V5).
    hold: Option<u32>,
    /// The seq of the picture the window drew last.
    drawn: Option<u32>,
    out: Vec<InputEvent>,
}

impl Forwarder {
    /// How often coalesced pointer moves go out.
    pub const MOVE_EVERY: std::time::Duration = std::time::Duration::from_millis(16);

    /// Forward input only if `control`.
    #[must_use]
    pub fn new(control: bool) -> Self {
        Self {
            open: control,
            ..Self::default()
        }
    }

    /// Whether this session sends input at all.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Pause (`true`) or resume this computer's input. Pausing lets go of
    /// everything on the host first (only in a session that sends input),
    /// then nothing goes out until resumed; resuming gives back only what
    /// [`new`](Self::new) gave: a view-only forwarder stays closed.
    pub fn pause(&mut self, paused: bool) {
        if paused && !self.paused {
            self.release_all();
        }
        self.paused = paused;
    }

    /// Whether the viewer paused this computer's input.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Whether input goes out now: the session sends input and it is not
    /// paused.
    fn sends(&self) -> bool {
        self.open && !self.paused
    }

    /// Whether a key pressed now goes to the host: input goes out, and the
    /// first picture is in (before it, [`key`](Self::key) sends no press).
    #[must_use]
    pub fn takes_keys(&self) -> bool {
        self.sends() && self.picture.is_some()
    }

    /// Where the picture was drawn last (none before the first picture),
    /// all of it on screen and nothing over it.
    pub fn set_picture(&mut self, picture: Option<PictureRect>) {
        self.picture = picture;
        self.visible = None;
        self.blocked.clear();
    }

    /// Where the picture was drawn last, the part of it on screen (`None`:
    /// all of it), and what the window drew over it: a press, a wheel turn
    /// or a move counts only on the visible picture outside every blocked
    /// rectangle.
    pub fn set_areas(
        &mut self,
        picture: Option<PictureRect>,
        visible: Option<PictureRect>,
        blocked: Vec<PictureRect>,
    ) {
        self.set_picture(picture);
        self.visible = visible;
        self.blocked = blocked;
    }

    /// Whether the pointer is on the picture now: on its visible part and
    /// under nothing the window drew over it.
    #[must_use]
    pub fn on_picture(&self) -> bool {
        match (self.picture, self.cursor) {
            (Some(rect), Some(pos)) => {
                rect.contains(pos)
                    && self.visible.is_none_or(|v| v.contains(pos))
                    && !self.blocked.iter().any(|b| b.contains(pos))
            }
            _ => false,
        }
    }

    /// Pictures from `seq` on show another part of the host's desktop (a
    /// `REMAPPED` list, the monitors design's V5): until one of them is
    /// drawn, no move, wheel turn or press goes out, since each would be
    /// made against a picture of the part shown before; a coalesced move or
    /// wheel turn waiting to go is dropped. Releases and keys still go. A
    /// picture at or after `seq` already drawn holds nothing back.
    pub fn hold_from(&mut self, seq: u32) {
        if self.drawn.is_some_and(|drawn| seq_reached(drawn, seq)) {
            return;
        }
        self.hold = Some(seq);
        self.pending_move = None;
        self.wheel = (0.0, 0.0);
    }

    /// The window drew picture `seq`. The first at or after the hold ends
    /// it, and the pointer's position goes out again if it is on the
    /// picture, so the host places it on the part now shown.
    pub fn drawn(&mut self, seq: u32) {
        self.drawn = Some(seq);
        if !self.hold.is_some_and(|hold| seq_reached(seq, hold)) {
            return;
        }
        self.hold = None;
        self.last_move = None;
        if self.sends()
            && self.on_picture()
            && let (Some(rect), Some(pos)) = (self.picture, self.cursor)
        {
            self.pending_move = Some(rect.normalized(pos));
        }
    }

    /// Whether input made now would be made against a picture from before
    /// the host's screen changed ([`hold_from`](Self::hold_from)).
    #[must_use]
    pub fn holding(&self) -> bool {
        self.hold.is_some()
    }

    /// The pointer moved to `pos` (physical pixels in the window).
    pub fn moved(&mut self, pos: (f64, f64)) {
        self.cursor = Some(pos);
        let Some(rect) = self.picture.filter(|_| self.sends() && !self.holding()) else {
            return;
        };
        // Off the picture, a move is sent only while a button forwarded from
        // it is held (a drag), clamped to the edge.
        if self.on_picture() || !self.held.is_empty() {
            let at = rect.normalized(pos);
            if self.last_move != Some(at) {
                self.pending_move = Some(at);
            }
        }
    }

    /// The pointer left the window.
    pub fn left(&mut self) {
        self.cursor = None;
    }

    /// A button went down or up. A press counts only on the picture; the
    /// release of a forwarded press always goes out, wherever it happens.
    pub fn button(&mut self, button: Button, pressed: bool) {
        if !self.sends() {
            return;
        }
        if pressed {
            if !self.on_picture() || self.holding() {
                return;
            }
            self.flush_pending();
            self.held.insert(button);
            self.out.push(InputEvent::PointerButton {
                button,
                pressed: true,
            });
        } else if self.held.remove(&button) {
            self.flush_pending();
            self.out.push(InputEvent::PointerButton {
                button,
                pressed: false,
            });
        }
    }

    /// The wheel turned by `lines` (winit's `LineDelta`: `+y` away from the
    /// user, `+x` to the left) or, from a touchpad, by `pixels`.
    pub fn wheel(&mut self, lines: (f64, f64), pixels: (f64, f64)) {
        if !self.sends() || !self.on_picture() || self.holding() {
            return;
        }
        let unit = f64::from(WHEEL_NOTCH);
        // The wire: `dx` + = right, `dy` + = up/away, in 1/120 notch.
        self.wheel.0 += -lines.0 * unit - pixels.0 / PIXELS_PER_NOTCH * unit;
        self.wheel.1 += lines.1 * unit + pixels.1 / PIXELS_PER_NOTCH * unit;
    }

    /// A physical key, as its USB usage, went down or up. Keys go out whether
    /// or not the pointer is on the picture: the window has the keyboard. A
    /// press before the first picture is drawn is dropped: it would land on a
    /// screen the viewer has not seen (SLICE-E E1-4). A release always goes
    /// out; the host drops one for a key it never saw pressed.
    pub fn key(&mut self, usb: u32, pressed: bool) {
        if !self.sends() || (pressed && self.picture.is_none()) {
            return;
        }
        self.flush_pending();
        self.out.push(InputEvent::Key { usb, pressed });
    }

    /// The window lost the keyboard: the host lets go of everything this
    /// viewer holds (a key held while focus moved would otherwise stay down).
    pub fn focus_lost(&mut self) {
        if !self.open {
            return;
        }
        self.flush_pending();
        self.held.clear();
        self.out.push(InputEvent::ReleaseAll);
    }

    /// The viewer took the keyboard back with its chord: the host lets go of
    /// everything this viewer holds, as on focus loss. While paused nothing
    /// goes out: the pause let go of everything already.
    pub fn release_all(&mut self) {
        if !self.sends() {
            return;
        }
        self.flush_pending();
        self.held.clear();
        self.out.push(InputEvent::ReleaseAll);
    }

    /// Whether a press now goes to the host: the session sends input, it is
    /// not paused, the pointer is on the picture, and no picture of another
    /// part of the host's desktop is awaited ([`hold_from`](Self::hold_from)).
    #[must_use]
    pub fn counts_press(&self) -> bool {
        self.sends() && self.on_picture() && !self.holding()
    }

    /// A key combination, as USB usages: pressed in order, then released in
    /// reverse, with the checks of [`key`](Self::key): nothing in a
    /// view-only or paused session, nor before the first picture.
    pub fn send_combo(&mut self, usages: &[u32]) {
        if !self.sends() || self.picture.is_none() {
            return;
        }
        for &usb in usages {
            self.key(usb, true);
        }
        for &usb in usages.iter().rev() {
            self.key(usb, false);
        }
    }

    /// Let the coalesced move and wheel go out.
    pub fn flush(&mut self) {
        self.flush_pending();
    }

    fn flush_pending(&mut self) {
        if let Some(at) = self.pending_move.take() {
            self.last_move = Some(at);
            self.out.push(InputEvent::PointerMove { x: at.0, y: at.1 });
        }
        // Whole 1/120 units only; the remainder waits for the next turn.
        let (dx, dy) = (self.wheel.0.trunc(), self.wheel.1.trunc());
        if dx != 0.0 || dy != 0.0 {
            self.wheel.0 -= dx;
            self.wheel.1 -= dy;
            let bound = f64::from(100 * WHEEL_NOTCH);
            self.out.push(InputEvent::Wheel {
                dx: dx.clamp(-bound, bound) as i32,
                dy: dy.clamp(-bound, bound) as i32,
            });
        }
    }

    /// Whether a coalesced move or wheel turn is waiting for [`flush`](Self::flush).
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.pending_move.is_some() || self.wheel.0.abs() >= 1.0 || self.wheel.1.abs() >= 1.0
    }

    /// The events ready to send, oldest first.
    pub fn drain(&mut self) -> Vec<InputEvent> {
        std::mem::take(&mut self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tornect_codec::DecodeTiming;

    const RECT: PictureRect = PictureRect {
        x: 100.0,
        y: 50.0,
        width: 801.0,
        height: 451.0,
    };

    fn open() -> Forwarder {
        let mut f = Forwarder::new(true);
        f.set_picture(Some(RECT));
        f
    }

    fn key_a(pressed: bool) -> InputEvent {
        InputEvent::Key {
            usb: 0x07_0004,
            pressed,
        }
    }

    /// A view-only session sends nothing, whatever the window sees.
    #[test]
    fn a_view_only_session_sends_nothing() {
        let mut f = Forwarder::new(false);
        f.set_picture(Some(RECT));
        f.moved((500.0, 300.0));
        f.button(Button::Left, true);
        f.button(Button::Left, false);
        f.wheel((0.0, 3.0), (0.0, 0.0));
        f.key(0x07_0004, true);
        f.key(0x07_0004, false);
        f.focus_lost();
        f.flush();
        assert!(!f.is_open());
        assert!(f.drain().is_empty());
    }

    /// A control session sends the events, in order, each one's 16-byte form
    /// decoding back to itself: the pointer normalized over the picture.
    #[test]
    fn a_control_session_sends_the_16_byte_events_in_order() {
        let mut f = open();
        f.moved((100.0, 50.0)); // the picture's top-left corner
        f.button(Button::Left, true);
        f.moved((900.0, 500.0)); // its bottom-right corner
        f.button(Button::Left, false);
        f.key(0x07_0004, true);
        f.key(0x07_0004, false);
        let sent = f.drain();
        assert_eq!(
            sent,
            vec![
                InputEvent::PointerMove { x: 0, y: 0 },
                InputEvent::PointerButton {
                    button: Button::Left,
                    pressed: true
                },
                InputEvent::PointerMove {
                    x: 65_535,
                    y: 65_535
                },
                InputEvent::PointerButton {
                    button: Button::Left,
                    pressed: false
                },
                key_a(true),
                key_a(false),
            ]
        );
        for event in sent {
            let bytes = event.encode();
            assert_eq!(bytes.len(), 16);
            assert_eq!(InputEvent::decode(&bytes).unwrap(), event);
        }
    }

    /// Moves are coalesced to the last position until a flush or a button.
    #[test]
    fn moves_are_coalesced() {
        let mut f = open();
        for x in 0..50 {
            f.moved((200.0 + f64::from(x), 100.0));
        }
        assert!(f.has_pending());
        assert!(f.drain().is_empty(), "nothing goes out before the flush");
        f.flush();
        let sent = f.drain();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0],
            InputEvent::PointerMove {
                x: RECT.normalized((249.0, 100.0)).0,
                y: RECT.normalized((249.0, 100.0)).1
            }
        );
        // The same position again is not sent again.
        f.moved((249.0, 100.0));
        f.flush();
        assert!(f.drain().is_empty());
    }

    /// Off the picture, a press is not forwarded; the release of a press that
    /// was forwarded always is, and a drag off the picture is clamped.
    #[test]
    fn presses_count_on_the_picture_and_releases_always_go_out() {
        let mut f = open();
        f.moved((10.0, 10.0)); // on the window's toolbar, off the picture
        f.button(Button::Left, true);
        f.button(Button::Left, false);
        assert!(f.drain().is_empty());

        f.moved((500.0, 300.0));
        f.button(Button::Right, true);
        f.moved((2000.0, -40.0)); // dragged off the picture
        f.button(Button::Right, false);
        let sent = f.drain();
        assert_eq!(sent.len(), 4, "{sent:?}");
        assert_eq!(sent[2], InputEvent::PointerMove { x: 65_535, y: 0 });
        assert_eq!(
            sent[3],
            InputEvent::PointerButton {
                button: Button::Right,
                pressed: false
            }
        );
    }

    /// Wheel turns in 1/120 notch with the wire's signs (+y away, +x right).
    #[test]
    fn wheel_turns_use_the_wires_units_and_signs() {
        let mut f = open();
        f.moved((500.0, 300.0));
        f.wheel((0.0, 1.0), (0.0, 0.0));
        f.wheel((1.0, 0.0), (0.0, 0.0));
        f.flush();
        assert_eq!(
            f.drain(),
            vec![
                InputEvent::PointerMove {
                    x: RECT.normalized((500.0, 300.0)).0,
                    y: RECT.normalized((500.0, 300.0)).1
                },
                InputEvent::Wheel { dx: -120, dy: 120 }
            ]
        );
        // A touchpad's small scrolls add up to whole units.
        for _ in 0..4 {
            f.wheel((0.0, 0.0), (0.0, -10.0));
        }
        f.flush();
        assert_eq!(f.drain(), vec![InputEvent::Wheel { dx: 0, dy: -120 }]);
    }

    /// Losing focus releases everything on the host; keys go out even with
    /// the pointer off the picture.
    #[test]
    fn focus_loss_releases_everything() {
        let mut f = open();
        f.key(0x07_0004, true);
        f.focus_lost();
        assert_eq!(f.drain(), vec![key_a(true), InputEvent::ReleaseAll]);
    }

    /// A view-only session sends nothing through the paths the viewer's
    /// toolbar and its chord added either.
    #[test]
    fn no_new_path_sends_in_a_view_only_session() {
        let mut f = Forwarder::new(false);
        f.set_picture(Some(RECT));
        f.moved((500.0, 300.0));
        assert!(!f.counts_press());
        f.release_all();
        f.pause(true);
        f.pause(false);
        f.release_all();
        f.key(0x07_0004, true);
        f.send_combo(&[0x07_00e2, 0x07_002b]);
        f.flush();
        assert!(!f.is_open());
        assert!(f.drain().is_empty());
    }

    /// A combination goes out as its presses in order, then its releases in
    /// reverse; nothing before the first picture or while paused.
    #[test]
    fn a_combo_goes_out_as_presses_then_releases_in_reverse() {
        let key = |usb, pressed| InputEvent::Key { usb, pressed };
        let mut f = Forwarder::new(true);
        f.send_combo(&[0x07_00e2, 0x07_002b]);
        assert!(f.drain().is_empty(), "before the first picture");
        f.set_picture(Some(RECT));
        f.send_combo(&[0x07_00e0, 0x07_00e2, 0x07_004c]);
        assert_eq!(
            f.drain(),
            vec![
                key(0x07_00e0, true),
                key(0x07_00e2, true),
                key(0x07_004c, true),
                key(0x07_004c, false),
                key(0x07_00e2, false),
                key(0x07_00e0, false),
            ]
        );
        f.pause(true);
        f.drain();
        f.send_combo(&[0x07_00e3]);
        assert!(f.drain().is_empty(), "while paused");
        // The menu's combinations are rows of the key table.
        let codes: Vec<Vec<&str>> = super::super::pages::viewer::Combo::ALL
            .iter()
            .map(|c| {
                c.usages()
                    .iter()
                    .map(|u| tornect_input::keymap::by_usb(*u).map_or("?", |k| k.code))
                    .collect()
            })
            .collect();
        assert_eq!(
            codes,
            [
                vec!["ControlLeft", "AltLeft", "Delete"],
                vec!["AltLeft", "Tab"],
                vec!["AltLeft", "F4"],
                vec!["MetaLeft"],
                vec!["PrintScreen"],
            ]
        );
    }

    /// A view-only forwarder drops a combination.
    #[test]
    fn a_view_only_forwarder_drops_a_combo() {
        let mut f = Forwarder::new(false);
        f.set_picture(Some(RECT));
        for combo in [&[0x07_00e2, 0x07_002b][..], &[0x07_00e3], &[0x07_0046]] {
            f.send_combo(combo);
        }
        assert!(f.drain().is_empty());
    }

    /// Pausing lets go of everything on the host, then nothing goes out:
    /// no move, press, wheel turn, key or release, until resumed.
    #[test]
    fn pausing_releases_everything_then_sends_nothing() {
        let mut f = open();
        f.moved((500.0, 300.0));
        f.button(Button::Left, true);
        f.key(0x07_0004, true);
        f.pause(true);
        let sent = f.drain();
        assert_eq!(sent.last(), Some(&InputEvent::ReleaseAll), "{sent:?}");
        assert!(f.is_paused());
        f.moved((600.0, 300.0));
        f.button(Button::Left, false);
        f.button(Button::Right, true);
        f.wheel((0.0, 2.0), (0.0, 0.0));
        f.key(0x07_0004, false);
        f.key(0x07_0005, true);
        f.release_all();
        f.pause(true);
        f.flush();
        assert!(!f.counts_press());
        assert!(f.drain().is_empty(), "nothing while paused");
        f.pause(false);
        f.key(0x07_0005, true);
        assert_eq!(
            f.drain(),
            vec![InputEvent::Key {
                usb: 0x07_0005,
                pressed: true
            }]
        );
    }

    /// Resuming gives back only what the session was built with: a
    /// view-only forwarder stays closed and sends nothing.
    #[test]
    fn resume_never_opens_a_view_only_session() {
        let mut f = Forwarder::new(false);
        f.set_picture(Some(RECT));
        f.pause(true);
        f.pause(false);
        assert!(!f.is_open());
        f.moved((500.0, 300.0));
        f.button(Button::Left, true);
        f.key(0x07_0004, true);
        f.flush();
        assert!(f.drain().is_empty());
    }

    /// SLICE-E E1-4: keys typed while the window still waits for the first
    /// picture are not sent: they would land on a screen the viewer has not
    /// seen. Once a picture is drawn they are; a key-up always goes out (the
    /// host drops one for a key it never saw pressed).
    #[test]
    fn keys_wait_for_the_first_picture() {
        let mut f = Forwarder::new(true);
        f.key(0x07_0004, true);
        f.key(0x07_0005, true);
        assert!(f.drain().is_empty(), "nothing before the first picture");
        f.set_picture(Some(RECT));
        f.key(0x07_0004, false);
        f.key(0x07_0004, true);
        assert_eq!(f.drain(), vec![key_a(false), key_a(true)]);
    }

    /// SLICE-E E1-3: a picture of the previous session that reached the slot
    /// after its window closed is never shown: a new session's sink starts
    /// from an empty slot.
    #[test]
    fn a_new_session_never_shows_the_last_ones_picture() {
        let slot = Arc::new(FrameSlot::default());
        slot.put(
            1,
            &DecodedFrame {
                width: 1,
                height: 1,
                rgba: vec![9, 9, 9, 255],
                timing: DecodeTiming::default(),
            },
        );
        let shared = Shared::new(super::super::model::Model::default(), Arc::new(|_| {}));
        let _sink = SlotSink::new(Arc::clone(&slot), shared);
        let mut mine = Picture::default();
        assert!(!slot.take(&mut mine), "the old picture was handed over");
    }

    /// The quality design §5 rule 12: what the host says of the stream
    /// (`Quality`, `Stats`) reaches the live session's `StreamInfo` without
    /// a wake, so a host cannot make the window redraw; each picture's
    /// decode and conversion times feed the means, and the picture alone
    /// wakes (the stream window only). Outside a live session nothing is
    /// written.
    #[test]
    fn the_hosts_words_reach_the_model_quietly_and_pictures_feed_the_means() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{Duration, Instant};

        use super::super::model::{Model, StreamInfo, Viewing};

        let wakes = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&wakes);
        let live = Model {
            client: ClientStage::Live(Viewing {
                host: "Desk".to_owned(),
                control: false,
                administrator: false,
                unattended: false,
                since: Instant::now(),
                pictures: 0,
                size: (0, 0),
                stream: StreamInfo::default(),
                screens: None,
            }),
            ..Model::default()
        };
        let shared = Shared::new(live, Arc::new(move |why| seen.lock().unwrap().push(why)));
        let mut sink = SlotSink::new(Arc::new(FrameSlot::default()), Arc::clone(&shared));
        let balanced = QualityInfo {
            preset: 2,
            max_fps: 15,
            kbps: 1500,
            max_long: 1920,
            max_short: 1080,
        };
        let stats = HostStats {
            source_width: 2560,
            source_height: 1440,
            frames: 15,
            window_ms: 1000,
            grab_us: 4000,
            ..HostStats::default()
        };
        for _ in 0..100 {
            sink.quality(1920, 1080, &balanced);
            sink.host_stats(&stats);
        }
        assert!(
            wakes.lock().unwrap().is_empty(),
            "no wake for the host's words"
        );
        let read = |shared: &Shared| {
            shared.read(|m| match &m.client {
                ClientStage::Live(v) => v.stream.clone(),
                _ => panic!("not live"),
            })
        };
        let info = read(&shared);
        assert_eq!(info.applied, Some(balanced));
        assert_eq!(info.announced, (1920, 1080));
        assert_eq!(info.host, Some(stats));
        assert_eq!(info.decode_ms.ms(), None, "no picture yet");
        let ms = Duration::from_millis;
        let mut frame = |decode, convert| {
            sink.picture(
                1,
                &DecodedFrame {
                    width: 2,
                    height: 2,
                    rgba: vec![0; 16],
                    timing: DecodeTiming {
                        decode: ms(decode),
                        convert: ms(convert),
                    },
                },
            );
        };
        frame(10, 4);
        frame(20, 4);
        let info = read(&shared);
        // 10, then 10 + 0.2 · (20 − 10).
        assert!((info.decode_ms.ms().unwrap() - 12.0).abs() < 1e-9);
        assert!((info.convert_ms.ms().unwrap() - 4.0).abs() < 1e-9);
        assert_eq!(*wakes.lock().unwrap(), vec![Wake::Frame, Wake::Frame]);
        // No live session: nothing is written.
        let counted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&counted);
        let idle = Shared::new(
            Model::default(),
            Arc::new(move |_| {
                count.fetch_add(1, Ordering::Relaxed);
            }),
        );
        let mut sink = SlotSink::new(Arc::new(FrameSlot::default()), Arc::clone(&idle));
        sink.quality(1920, 1080, &balanced);
        sink.host_stats(&stats);
        assert!(idle.read(|m| matches!(m.client, ClientStage::Idle)));
        assert_eq!(counted.load(Ordering::Relaxed), 0);
    }

    /// The means weigh each new sample 0.2, start at the first sample, and
    /// ignore what is no time.
    #[test]
    fn a_mean_weighs_each_new_sample_a_fifth() {
        use super::super::model::Ewma;
        let mut e = Ewma::default();
        assert_eq!(e.ms(), None);
        assert_eq!(e.micros(), None);
        e.add(5.0);
        assert_eq!(e.ms(), Some(5.0));
        e.add(10.0);
        assert!((e.ms().unwrap() - 6.0).abs() < 1e-9);
        for bad in [f64::NAN, f64::INFINITY, -1.0] {
            e.add(bad);
            assert!((e.ms().unwrap() - 6.0).abs() < 1e-9, "{bad}");
        }
        assert_eq!(e.micros(), Some(6000));
        e.add_duration(std::time::Duration::from_micros(16_000));
        assert_eq!(e.micros(), Some(8000));
    }

    /// A live session's model, with the wakes it gave.
    fn live_shared() -> (Arc<Shared>, Arc<Mutex<Vec<Wake>>>) {
        use super::super::model::{Model, StreamInfo, Viewing};
        let wakes = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&wakes);
        let live = Model {
            client: ClientStage::Live(Viewing {
                host: "Desk".to_owned(),
                control: true,
                administrator: false,
                unattended: false,
                since: std::time::Instant::now(),
                pictures: 0,
                size: (0, 0),
                stream: StreamInfo::default(),
                screens: None,
            }),
            ..Model::default()
        };
        let shared = Shared::new(live, Arc::new(move |why| seen.lock().unwrap().push(why)));
        (shared, wakes)
    }

    /// Two monitors side by side, the first the main one, "all" offered:
    /// what the host's `Monitors` lists, showing `shown` from `seq` on.
    fn two_screens(shown: u8, seq: u32, remapped: bool) -> Screens {
        use tornect_proto::MonitorEntry;
        Screens {
            monitors: vec![
                MonitorEntry::saturating(true, 0, 0, 2560, 1440),
                MonitorEntry::saturating(false, 2560, 0, 1920, 1080),
            ],
            all: true,
            shown,
            list: 3,
            seq,
            remapped,
        }
    }

    /// The monitors design §5.7: what the viewer says of the host's
    /// screens reaches the live session's `ScreensView`, and wakes the
    /// stream window only. The first list says nothing; an answer, a
    /// request given up and one not sent end "Switching…", the last two and
    /// a refusal with words for the toast, an answer that shows the screen
    /// asked for with none; the host's news says something only when it
    /// changes the screen shown; a `REMAPPED` list holds input back from its
    /// seq, and a request given up holds nothing back again. Outside a live
    /// session nothing is written.
    #[test]
    fn the_hosts_screens_reach_the_model_and_end_a_switch() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tornect_proto::monitor_status;

        let (shared, wakes) = live_shared();
        let mut sink = SlotSink::new(Arc::new(FrameSlot::default()), Arc::clone(&shared));
        let read = |shared: &Shared| {
            shared.read(|m| match &m.client {
                ClientStage::Live(v) => v.screens.clone(),
                _ => panic!("not live"),
            })
        };
        let set_switching = |shared: &Shared, to: Option<u8>| {
            shared.update_quiet(|m| {
                if let ClientStage::Live(v) = &mut m.client {
                    v.screens.as_mut().unwrap().switching = to;
                }
            });
        };
        assert_eq!(read(&shared), None, "nothing listed yet");
        sink.screens(&two_screens(1, 0, false), ScreensNews::Layout);
        let view = read(&shared).expect("listed");
        assert_eq!(view.monitors, two_screens(1, 0, false).monitors);
        assert!(view.all);
        assert_eq!((view.shown, view.list, view.news), (1, 3, 1));
        assert_eq!(
            (view.last, view.hold_from, view.switching),
            (None, None, None)
        );
        // An answer that shows the screen asked for.
        set_switching(&shared, Some(2));
        sink.screens(
            &two_screens(2, 41, true),
            ScreensNews::Answer {
                asked: 2,
                status: monitor_status::OK,
            },
        );
        let view = read(&shared).unwrap();
        assert_eq!((view.shown, view.switching, view.last), (2, None, None));
        assert_eq!(view.hold_from, Some(41));
        assert_eq!(view.news, 2);
        // Refusals, a request given up and one not sent.
        for (news, note) in [
            (
                ScreensNews::Answer {
                    asked: 0,
                    status: monitor_status::FAILED,
                },
                ScreenNote::Refused {
                    asked: 0,
                    status: monitor_status::FAILED,
                },
            ),
            (
                ScreensNews::Answer {
                    asked: 1,
                    status: monitor_status::BUSY,
                },
                ScreenNote::Refused {
                    asked: 1,
                    status: monitor_status::BUSY,
                },
            ),
            (
                ScreensNews::NoAnswer { asked: 1 },
                ScreenNote::NoAnswer { asked: 1 },
            ),
            (
                ScreensNews::NotSent { asked: 0 },
                ScreenNote::NotSent { asked: 0 },
            ),
        ] {
            set_switching(&shared, Some(1));
            // The list said last, as the viewer repeats it.
            sink.screens(&two_screens(2, 41, true), news);
            let view = read(&shared).unwrap();
            assert_eq!(view.switching, None, "{news:?}");
            assert_eq!(view.last, Some(note), "{news:?}");
            assert_eq!(view.shown, 2, "{news:?}");
            assert_eq!(view.hold_from, Some(41), "{news:?}");
        }
        // A request given up after the hold ended holds nothing back again.
        shared.update_quiet(|m| {
            if let ClientStage::Live(v) = &mut m.client {
                v.screens.as_mut().unwrap().hold_from = None;
            }
        });
        sink.screens(
            &two_screens(2, 41, true),
            ScreensNews::NoAnswer { asked: 1 },
        );
        assert_eq!(read(&shared).unwrap().hold_from, None);
        // The host's news: the same screen says nothing, another screen
        // says which, and a remap holds input back from its seq.
        set_switching(&shared, Some(1));
        sink.screens(&two_screens(2, 50, false), ScreensNews::Layout);
        let view = read(&shared).unwrap();
        assert_eq!(view.last, None);
        assert_eq!(view.switching, Some(1), "news is no answer");
        sink.screens(&two_screens(1, 60, true), ScreensNews::Layout);
        let view = read(&shared).unwrap();
        assert_eq!(view.last, Some(ScreenNote::Changed { shown: 1 }));
        assert_eq!((view.shown, view.hold_from), (1, Some(60)));
        assert_eq!(view.news, 9);
        assert_eq!(*wakes.lock().unwrap(), vec![Wake::Frame; 9]);
        // No live session: nothing is written.
        let counted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&counted);
        let idle = Shared::new(
            super::super::model::Model::default(),
            Arc::new(move |_| {
                count.fetch_add(1, Ordering::Relaxed);
            }),
        );
        let mut sink = SlotSink::new(Arc::new(FrameSlot::default()), Arc::clone(&idle));
        sink.screens(&two_screens(1, 0, false), ScreensNews::Layout);
        assert!(idle.read(|m| matches!(m.client, ClientStage::Idle)));
    }

    /// The final review of the monitors feature: an `OK` answer that shows
    /// another screen than the one asked for (the monitor asked for went
    /// before the host switched, and it fell back to the default) ends the
    /// switch and says what is shown, as the host's own change does; one
    /// that shows what was asked, all screens included, says nothing.
    #[test]
    fn an_answer_that_shows_another_screen_says_which() {
        use tornect_proto::monitor_status;

        let (shared, _) = live_shared();
        let mut sink = SlotSink::new(Arc::new(FrameSlot::default()), Arc::clone(&shared));
        let read = |shared: &Shared| {
            shared.read(|m| match &m.client {
                ClientStage::Live(v) => v.screens.clone().unwrap(),
                _ => panic!("not live"),
            })
        };
        let switching = |shared: &Shared, to: u8| {
            shared.update_quiet(|m| {
                if let ClientStage::Live(v) = &mut m.client {
                    v.screens.as_mut().unwrap().switching = Some(to);
                }
            });
        };
        sink.screens(&two_screens(1, 0, false), ScreensNews::Layout);
        switching(&shared, 2);
        sink.screens(
            &two_screens(1, 30, false),
            ScreensNews::Answer {
                asked: 2,
                status: monitor_status::OK,
            },
        );
        let view = read(&shared);
        assert_eq!(view.switching, None);
        assert_eq!(view.last, Some(ScreenNote::Changed { shown: 1 }));
        assert_eq!(view.shown, 1);

        switching(&shared, 0);
        sink.screens(
            &two_screens(0, 40, true),
            ScreensNews::Answer {
                asked: 0,
                status: monitor_status::OK,
            },
        );
        let view = read(&shared);
        assert_eq!((view.switching, view.last), (None, None), "all, as asked");
        assert_eq!(view.hold_from, Some(40));
    }

    /// The monitors design's V5: from a `REMAPPED` list's seq until a
    /// picture at or after it is drawn, no move, wheel turn or press goes
    /// out (a coalesced move or wheel turn waiting is dropped), while the
    /// release of a button held from before, keys and combinations still
    /// go; the first such picture drawn ends the hold and sends the
    /// pointer's position again, even unmoved. A picture already drawn
    /// holds nothing back; the seqs wrap.
    #[test]
    fn positional_input_waits_for_the_first_picture_of_another_screen() {
        let mut f = open();
        let on = (500.0, 300.0);
        f.drawn(9);
        f.moved(on);
        f.button(Button::Left, true);
        f.flush();
        let at = RECT.normalized(on);
        assert_eq!(
            f.drain(),
            vec![
                InputEvent::PointerMove { x: at.0, y: at.1 },
                InputEvent::PointerButton {
                    button: Button::Left,
                    pressed: true
                }
            ]
        );
        f.moved((520.0, 310.0));
        f.wheel((0.0, 2.0), (0.0, 0.0));
        assert!(f.has_pending());
        f.hold_from(10);
        assert!(f.holding());
        assert!(!f.has_pending(), "what waited is dropped");
        f.moved((530.0, 320.0));
        f.wheel((0.0, 1.0), (0.0, 0.0));
        f.button(Button::Right, true);
        assert!(!f.counts_press());
        f.button(Button::Left, false);
        f.key(0x07_0004, true);
        f.key(0x07_0004, false);
        f.send_combo(&[0x07_00e2, 0x07_002b]);
        f.drawn(9);
        assert!(f.holding(), "the same picture again");
        f.flush();
        assert_eq!(
            f.drain(),
            vec![
                InputEvent::PointerButton {
                    button: Button::Left,
                    pressed: false
                },
                key_a(true),
                key_a(false),
                InputEvent::Key {
                    usb: 0x07_00e2,
                    pressed: true
                },
                InputEvent::Key {
                    usb: 0x07_002b,
                    pressed: true
                },
                InputEvent::Key {
                    usb: 0x07_002b,
                    pressed: false
                },
                InputEvent::Key {
                    usb: 0x07_00e2,
                    pressed: false
                },
            ],
            "no move, wheel turn or press"
        );
        // The first picture of the new screen: the pointer goes again.
        f.drawn(10);
        assert!(!f.holding());
        assert!(f.counts_press());
        f.flush();
        let at = RECT.normalized((530.0, 320.0));
        assert_eq!(
            f.drain(),
            vec![InputEvent::PointerMove { x: at.0, y: at.1 }]
        );
        // Unmoved since its last move, it still goes again after a hold.
        f.hold_from(11);
        f.drawn(12);
        f.flush();
        assert_eq!(
            f.drain(),
            vec![InputEvent::PointerMove { x: at.0, y: at.1 }]
        );
        // A hold of a picture already drawn holds nothing.
        f.hold_from(12);
        assert!(!f.holding());
        f.hold_from(5);
        assert!(!f.holding());
        // Off the picture when the hold ends: nothing goes.
        f.hold_from(13);
        f.moved((10.0, 10.0));
        f.drawn(13);
        f.flush();
        assert!(f.drain().is_empty());
        // Across the wrap of the seqs.
        f.drawn(u32::MAX - 1);
        f.hold_from(1);
        assert!(f.holding(), "1 comes after u32::MAX - 1");
        f.drawn(u32::MAX);
        assert!(f.holding());
        f.drawn(1);
        assert!(!f.holding());
        // A view-only forwarder holds and sends nothing either way.
        let mut closed = Forwarder::new(false);
        closed.set_picture(Some(RECT));
        closed.moved(on);
        closed.hold_from(3);
        closed.drawn(3);
        closed.flush();
        assert!(closed.drain().is_empty());
    }

    /// The picture keeps its aspect inside the window, centred.
    #[test]
    fn the_picture_is_letterboxed() {
        assert_eq!(
            letterbox((0.0, 40.0, 1000.0, 400.0), (1920, 1080)),
            (
                0.0 + (1000.0 - 400.0 * 1920.0 / 1080.0) / 2.0,
                40.0,
                400.0 * 1920.0 / 1080.0,
                400.0
            )
        );
        assert_eq!(
            letterbox((0.0, 0.0, 800.0, 800.0), (1600, 800)),
            (0.0, 200.0, 800.0, 400.0)
        );
        assert_eq!(letterbox((0.0, 0.0, 800.0, 600.0), (0, 0)).2, 0.0);
    }

    /// The bookkeeping: the first picture makes a texture, the same size is
    /// written in place, a new size makes a new one, and a picture whose bytes
    /// do not match its size (a stride that is not `4 × width`) is refused.
    #[test]
    fn a_new_texture_only_when_the_size_changes() {
        let mut plan = TexturePlan::new(8192);
        assert_eq!(
            plan.plan(1280, 720, 1280 * 720 * 4),
            Upload::Allocate {
                width: 1280,
                height: 720
            }
        );
        for _ in 0..3 {
            assert_eq!(plan.plan(1280, 720, 1280 * 720 * 4), Upload::Write);
        }
        assert_eq!(
            plan.plan(1920, 1080, 1920 * 1080 * 4),
            Upload::Allocate {
                width: 1920,
                height: 1080
            }
        );
        assert_eq!(plan.size(), Some((1920, 1080)));
        // A padded stride (a row of 4 × width + 64 bytes) is not tight.
        assert!(matches!(
            plan.plan(1920, 1080, (1920 * 4 + 64) * 1080),
            Upload::Reject(_)
        ));
        assert!(matches!(plan.plan(0, 1080, 0), Upload::Reject(_)));
        assert!(matches!(plan.plan(9000, 10, 9000 * 40), Upload::Reject(_)));
        // A refused picture leaves the live texture alone.
        assert_eq!(plan.size(), Some((1920, 1080)));
        assert_eq!(plan.plan(1920, 1080, 1920 * 1080 * 4), Upload::Write);
        assert_eq!(TexturePlan::bytes_per_row(1920), 7680);
    }

    /// The slot hands over the newest picture once, and swaps buffers.
    #[test]
    fn the_slot_keeps_only_the_newest_picture() {
        let slot = FrameSlot::default();
        let mut mine = Picture::default();
        assert!(!slot.take(&mut mine));
        for n in 1..=3u8 {
            slot.put(
                u32::from(n) + 40,
                &DecodedFrame {
                    width: 1,
                    height: 1,
                    rgba: vec![n, n, n, 255],
                    timing: DecodeTiming::default(),
                },
            );
        }
        assert!(slot.take(&mut mine));
        assert_eq!(mine.rgba, vec![3, 3, 3, 255]);
        assert_eq!(mine.seq, 43, "the seq comes with its picture");
        assert!(!slot.take(&mut mine), "a picture is handed over once");
    }

    /// The upload recipe on a real device (lavapipe here): pictures reach the
    /// texture byte for byte through `queue.write_texture` with tight rows, a
    /// size change makes a new texture under the same egui id, and the same
    /// size reuses it. Skipped, loudly, where no adapter exists.
    #[test]
    fn pictures_reach_the_texture_on_a_headless_device() {
        let Some((device, queue)) = headless_device() else {
            eprintln!("SKIPPED: no wgpu adapter on this machine");
            return;
        };
        let mut renderer = egui_wgpu::Renderer::new(
            &device,
            wgpu::TextureFormat::Rgba8Unorm,
            egui_wgpu::RendererOptions::default(),
        );
        let mut video = VideoTexture::new(device.limits().max_texture_dimension_2d);
        let picture = |w: u32, h: u32, seed: u8| Picture {
            width: w,
            height: h,
            rgba: (0..w * h * 4)
                .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
                .collect(),
            seq: u32::from(seed),
            fresh: true,
        };
        let first = picture(3, 2, 1);
        assert_eq!(
            video.upload(&device, &queue, &mut renderer, &first),
            Upload::Allocate {
                width: 3,
                height: 2
            }
        );
        let id = video.id().expect("registered");
        assert_eq!(
            read_back(&device, &queue, video.texture().unwrap(), 3, 2),
            first.rgba
        );
        let second = picture(3, 2, 9);
        assert_eq!(
            video.upload(&device, &queue, &mut renderer, &second),
            Upload::Write
        );
        assert_eq!(
            read_back(&device, &queue, video.texture().unwrap(), 3, 2),
            second.rgba
        );
        let bigger = picture(5, 4, 3);
        assert_eq!(
            video.upload(&device, &queue, &mut renderer, &bigger),
            Upload::Allocate {
                width: 5,
                height: 4
            }
        );
        assert_eq!(video.id(), Some(id), "the same egui id");
        assert_eq!(
            read_back(&device, &queue, video.texture().unwrap(), 5, 4),
            bigger.rgba
        );
        assert_eq!((video.allocations, video.writes), (2, 3));
    }

    fn headless_device() -> Option<(wgpu::Device, wgpu::Queue)> {
        let mut desc = wgpu::InstanceDescriptor::new_without_display_handle();
        desc.backends = wgpu::Backends::PRIMARY;
        let instance = wgpu::Instance::new(desc);
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::default(),
            force_fallback_adapter: false,
            compatible_surface: None,
            apply_limit_buckets: false,
        }))
        .ok()?;
        eprintln!("wgpu adapter: {:?}", adapter.get_info());
        pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor::default())).ok()
    }

    /// Copy a texture back to memory (rows padded to 256 bytes for the copy).
    fn read_back(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        texture: &wgpu::Texture,
        width: u32,
        height: u32,
    ) -> Vec<u8> {
        let row = width * 4;
        let padded =
            row.div_ceil(wgpu::COPY_BYTES_PER_ROW_ALIGNMENT) * wgpu::COPY_BYTES_PER_ROW_ALIGNMENT;
        let buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: None,
            size: u64::from(padded * height),
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
        encoder.copy_texture_to_buffer(
            wgpu::TexelCopyTextureInfo {
                texture,
                mip_level: 0,
                origin: wgpu::Origin3d::ZERO,
                aspect: wgpu::TextureAspect::All,
            },
            wgpu::TexelCopyBufferInfo {
                buffer: &buffer,
                layout: wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: Some(padded),
                    rows_per_image: Some(height),
                },
            },
            wgpu::Extent3d {
                width,
                height,
                depth_or_array_layers: 1,
            },
        );
        queue.submit([encoder.finish()]);
        let slice = buffer.slice(..);
        slice.map_async(wgpu::MapMode::Read, |r| r.unwrap());
        device
            .poll(wgpu::PollType::Wait {
                submission_index: None,
                timeout: Some(std::time::Duration::from_secs(10)),
            })
            .unwrap();
        let mapped = slice.get_mapped_range().unwrap();
        let mut out = Vec::with_capacity((row * height) as usize);
        for y in 0..height {
            let start = (y * padded) as usize;
            out.extend_from_slice(&mapped[start..start + row as usize]);
        }
        out
    }
}
