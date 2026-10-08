//! The stream window's plumbing (`docs/UI_PLAN.md` §8, `docs/research/slice.md`
//! §2): the viewer's [`FrameSink`] hands the newest picture to the UI thread,
//! [`VideoTexture`] puts it in one registered native `Rgba8Unorm` texture with
//! `queue.write_texture` (a new texture only when the size changes, never one
//! per picture), and [`Forwarder`] turns the window's pointer, wheel and keys
//! into the 16-byte input events, only for a control session.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use tornect_codec::DecodedFrame;
use tornect_input::{Button, InputEvent, WHEEL_NOTCH, normalize};
use tornect_session::FrameSink;

use super::model::{ClientStage, Shared, Wake};

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
    /// Not drawn yet.
    pub fresh: bool,
}

impl FrameSlot {
    /// Put `frame` in the slot, reusing its buffer.
    pub fn put(&self, frame: &DecodedFrame) {
        let mut slot = self.picture.lock().unwrap_or_else(PoisonError::into_inner);
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
    fn picture(&mut self, _seq: u32, frame: &DecodedFrame) {
        self.pictures += 1;
        self.slot.put(frame);
        // The counters change on every picture; the model lock is cheap, and
        // `Wake::Frame` redraws only the stream window.
        let (pictures, size) = (self.pictures, (frame.width, frame.height));
        self.shared.update_quiet(|m| {
            if let ClientStage::Live(v) = &mut m.client {
                v.pictures = pictures;
                v.size = size;
            }
        });
        self.shared.wake(Wake::Frame);
    }
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
    cursor: Option<(f64, f64)>,
    held: BTreeSet<Button>,
    pending_move: Option<(u16, u16)>,
    last_move: Option<(u16, u16)>,
    wheel: (f64, f64),
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

    /// Where the picture was drawn last (none before the first picture).
    pub fn set_picture(&mut self, picture: Option<PictureRect>) {
        self.picture = picture;
    }

    /// Whether the pointer is on the picture now.
    #[must_use]
    pub fn on_picture(&self) -> bool {
        match (self.picture, self.cursor) {
            (Some(rect), Some(pos)) => rect.contains(pos),
            _ => false,
        }
    }

    /// The pointer moved to `pos` (physical pixels in the window).
    pub fn moved(&mut self, pos: (f64, f64)) {
        self.cursor = Some(pos);
        let Some(rect) = self.picture.filter(|_| self.open) else {
            return;
        };
        // Off the picture, a move is sent only while a button forwarded from
        // it is held (a drag), clamped to the edge.
        if rect.contains(pos) || !self.held.is_empty() {
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
        if !self.open {
            return;
        }
        if pressed {
            if !self.on_picture() {
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
        if !self.open || !self.on_picture() {
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
        if !self.open || (pressed && self.picture.is_none()) {
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
    /// everything this viewer holds, as on focus loss.
    pub fn release_all(&mut self) {
        if !self.open {
            return;
        }
        self.flush_pending();
        self.held.clear();
        self.out.push(InputEvent::ReleaseAll);
    }

    /// Whether a press now goes to the host: the session sends input and
    /// the pointer is on the picture.
    #[must_use]
    pub fn counts_press(&self) -> bool {
        self.open && self.on_picture()
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
        f.flush();
        assert!(!f.is_open());
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
        slot.put(&DecodedFrame {
            width: 1,
            height: 1,
            rgba: vec![9, 9, 9, 255],
        });
        let shared = Shared::new(super::super::model::Model::default(), Arc::new(|_| {}));
        let _sink = SlotSink::new(Arc::clone(&slot), shared);
        let mut mine = Picture::default();
        assert!(!slot.take(&mut mine), "the old picture was handed over");
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
            slot.put(&DecodedFrame {
                width: 1,
                height: 1,
                rgba: vec![n, n, n, 255],
            });
        }
        assert!(slot.take(&mut mine));
        assert_eq!(mine.rgba, vec![3, 3, 3, 255]);
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
