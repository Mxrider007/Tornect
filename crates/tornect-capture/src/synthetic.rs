//! A synthetic test card: the capture source every machine has, for the
//! pipeline tests and for sessions on hosts without a capture backend.
//!
//! The card carries its own frame index in a strip of 32 black-or-white
//! blocks along the bottom edge, large enough to survive H.264 and a scale
//! down to a third, so a viewer can check order and loss end to end
//! ([`TestCard::read_index`], [`TestCard::read_index_scaled`]).

use std::time::{Duration, Instant};

use crate::{CaptureError, Frame, VideoSource};

/// Smallest card: the index strip needs 32 blocks of at least 8 pixels.
pub const MIN_WIDTH: u32 = 256;
/// Smallest card height.
pub const MIN_HEIGHT: u32 = 96;

/// Bits in the index strip.
const BITS: u32 = 32;
/// 75 % bars, SMPTE order (BGRx).
const BARS: [[u8; 3]; 8] = [
    [191, 191, 191],
    [0, 191, 191],
    [191, 191, 0],
    [0, 191, 0],
    [191, 0, 191],
    [0, 0, 191],
    [191, 0, 0],
    [0, 0, 0],
];
/// The grey below the bars.
const BACKGROUND: [u8; 3] = [64; 3];

/// Height of the index strip at the bottom of a card `height` rows tall: 16
/// rows up to 1080p, then a 64th of the height (33 rows at 2160p), so a
/// picture scaled down to a third still carries an 11-row strip.
fn strip(height: u32) -> u32 {
    (height / 64).max(16)
}

/// Where the parts of picture `index` of a `width`×`height` card lie.
struct Layout {
    w: usize,
    h: usize,
    bars_end: usize,
    strip_start: usize,
    square: usize,
    square_x: usize,
    square_y: usize,
    bit_w: usize,
    index: u32,
}

impl Layout {
    fn new(width: u32, height: u32, index: u32) -> Self {
        let (w, h) = (width as usize, height as usize);
        let bars_end = h * 2 / 3;
        let strip_start = h.saturating_sub(strip(height) as usize);
        let square = (h / 6).clamp(8, 64);
        let travel = w.saturating_sub(square).max(1);
        Self {
            w,
            h,
            bars_end,
            strip_start,
            square,
            square_x: (index as usize * 8) % travel,
            square_y: bars_end + strip_start.saturating_sub(bars_end).saturating_sub(square) / 2,
            bit_w: w / BITS as usize,
            index,
        }
    }

    /// The strip's colour at column `x`: white for a 1 bit, else black.
    fn strip_at(&self, x: usize) -> [u8; 3] {
        let bit = x / self.bit_w;
        let on = bit < BITS as usize && ((self.index >> (BITS as usize - 1 - bit)) & 1) == 1;
        if on { [255; 3] } else { [0; 3] }
    }
}

/// Colour bars, a moving square and the frame index, at a fixed rate.
pub struct TestCard {
    width: u32,
    height: u32,
    interval: Duration,
    next_at: Option<Instant>,
    index: u32,
    /// The bars and the background, rendered once: every picture is this
    /// with its square and strip painted over ([`paint`]). Empty until the
    /// first picture.
    base: Vec<u8>,
    /// A buffer given back ([`VideoSource::recycle`]), to paint the next
    /// picture into.
    spare: Vec<u8>,
}

impl std::fmt::Debug for TestCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCard")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("interval", &self.interval)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// The bars and the background of a `width`×`height` card, tightly packed
/// BGRx: [`TestCard::render`] without the square and the strip.
fn base(width: u32, height: u32) -> Vec<u8> {
    let (w, h) = (width as usize, height as usize);
    let bars_end = h * 2 / 3;
    let mut px = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        for x in 0..w {
            let bgr = if y < bars_end {
                BARS[x * BARS.len() / w]
            } else {
                BACKGROUND
            };
            px.extend_from_slice(&[bgr[0], bgr[1], bgr[2], 255]);
        }
    }
    px
}

/// Picture `index` into `out`: `base` (of the same card) copied, then only
/// the square and the strip painted, which gives [`TestCard::render`]'s
/// bytes without drawing every pixel again.
fn paint(base: &[u8], width: u32, height: u32, index: u32, out: &mut Vec<u8>) {
    let l = Layout::new(width, height, index);
    out.clear();
    out.extend_from_slice(base);
    let row = l.w * 4;
    // The square lies below the bars; the strip covers any part of it that
    // reaches that far, as in `render`.
    let columns = l.square_x * 4..(l.square_x + l.square).min(l.w) * 4;
    for y in l.square_y..(l.square_y + l.square).min(l.strip_start) {
        for px in out[y * row..][columns.clone()].chunks_exact_mut(4) {
            px[..3].fill(255);
        }
    }
    if l.strip_start < l.h {
        let first = l.strip_start * row;
        for (x, px) in out[first..first + row].chunks_exact_mut(4).enumerate() {
            px[..3].copy_from_slice(&l.strip_at(x));
        }
        for y in l.strip_start + 1..l.h {
            out.copy_within(first..first + row, y * row);
        }
    }
}

impl TestCard {
    /// A `width`×`height` card (raised to [`MIN_WIDTH`]×[`MIN_HEIGHT`]) at
    /// `fps` pictures per second (at least 1).
    #[must_use]
    pub fn new(width: u32, height: u32, fps: u32) -> Self {
        Self {
            width: width.max(MIN_WIDTH),
            height: height.max(MIN_HEIGHT),
            interval: Duration::from_secs(1) / fps.max(1),
            next_at: None,
            index: 0,
            base: Vec::new(),
            spare: Vec::new(),
        }
    }

    /// Picture number `index` of a `width`×`height` card, tightly packed BGRx.
    #[must_use]
    pub fn render(width: u32, height: u32, index: u32) -> Vec<u8> {
        let l = Layout::new(width, height, index);
        let (w, h) = (l.w, l.h);
        let mut px = vec![0u8; w * h * 4];
        for y in 0..h {
            for x in 0..w {
                let bgr = if y < l.bars_end {
                    BARS[x * BARS.len() / w]
                } else if y >= l.strip_start {
                    l.strip_at(x)
                } else if (l.square_x..l.square_x + l.square).contains(&x)
                    && (l.square_y..l.square_y + l.square).contains(&y)
                {
                    [255; 3]
                } else {
                    BACKGROUND
                };
                let i = (y * w + x) * 4;
                px[i..i + 3].copy_from_slice(&bgr);
                px[i + 3] = 255;
            }
        }
        px
    }

    /// The frame index a card picture carries, read from the green channel at
    /// the centre of each block (a decoded, lossy copy reads the same).
    /// `None` if `bgrx` is not a `width`×`height` BGRx picture.
    #[must_use]
    pub fn read_index(bgrx: &[u8], width: u32, height: u32) -> Option<u32> {
        Self::read_index_scaled(bgrx, width, height, width, height)
    }

    /// The frame index a picture of a `source_width`×`source_height` card
    /// carries once that card was scaled whole into `width`×`height`: each
    /// block's centre on the card, mapped into the picture, read from the
    /// green channel. That channel is at offset 1 in BGRx and in RGBA, so a
    /// scaled picture and its decoded copy read the same. `None` if `px` is
    /// not `width`×`height` pixels, or the source is smaller than a card.
    #[must_use]
    pub fn read_index_scaled(
        px: &[u8],
        width: u32,
        height: u32,
        source_width: u32,
        source_height: u32,
    ) -> Option<u32> {
        let (w, h) = (u64::from(width), u64::from(height));
        let (sw, sh) = (u64::from(source_width), u64::from(source_height));
        let len = w.checked_mul(h)?.checked_mul(4)?;
        if width == 0 || height == 0 || px.len() as u64 != len {
            return None;
        }
        if source_width < MIN_WIDTH || source_height < MIN_HEIGHT {
            return None;
        }
        let block = sw / u64::from(BITS);
        let y = (sh - u64::from(strip(source_height)) / 2) * h / sh;
        let mut index = 0u32;
        for bit in 0..u64::from(BITS) {
            let x = (bit * block + block / 2) * w / sw;
            let green = *px.get(usize::try_from((y * w + x) * 4 + 1).ok()?)?;
            index = (index << 1) | u32::from(green > 127);
        }
        Some(index)
    }
}

impl VideoSource for TestCard {
    fn name(&self) -> &'static str {
        "synthetic"
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let now = Instant::now();
        let due = self.next_at.unwrap_or(now);
        if due > now {
            let wait = due - now;
            if wait > timeout {
                std::thread::sleep(timeout);
                return Ok(None);
            }
            std::thread::sleep(wait);
        }
        let started = Instant::now();
        if self.base.is_empty() {
            self.base = base(self.width, self.height);
        }
        let mut bgrx = std::mem::take(&mut self.spare);
        paint(&self.base, self.width, self.height, self.index, &mut bgrx);
        let frame = Frame {
            width: self.width,
            height: self.height,
            bgrx,
            captured_at: Instant::now(),
            grab: started.elapsed(),
        };
        self.index = self.index.wrapping_add(1);
        // A late consumer gets the next picture one interval after this one,
        // never a burst of catch-up pictures.
        self.next_at = Some(due.max(now) + self.interval);
        Ok(Some(frame))
    }

    /// Keeps the largest buffer given back, to paint the next picture into.
    fn recycle(&mut self, bgrx: Vec<u8>) {
        if bgrx.capacity() > self.spare.capacity() {
            self.spare = bgrx;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pictures_are_tight_bgrx_and_carry_their_index() {
        for (w, h) in [(256, 96), (640, 360), (1281, 721)] {
            for index in [0, 1, 0x8000_0001, 123_456_789, u32::MAX] {
                let px = TestCard::render(w, h, index);
                assert_eq!(px.len(), (w * h * 4) as usize);
                assert!(px.chunks_exact(4).all(|p| p[3] == 255), "X is opaque");
                assert_eq!(
                    TestCard::read_index(&px, w, h),
                    Some(index),
                    "{w}x{h} #{index}"
                );
            }
        }
        assert_ne!(TestCard::render(640, 360, 7), TestCard::render(640, 360, 8));
        assert_eq!(TestCard::read_index(&[0; 16], 640, 360), None);
    }

    #[test]
    fn the_card_counts_and_keeps_its_size_floor() {
        let mut card = TestCard::new(10, 10, 1000);
        let a = card.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        let b = card.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!((a.width, a.height), (MIN_WIDTH, MIN_HEIGHT));
        assert_eq!(TestCard::read_index(&a.bgrx, a.width, a.height), Some(0));
        assert_eq!(TestCard::read_index(&b.bgrx, b.width, b.height), Some(1));
        assert_eq!(card.name(), "synthetic");
    }

    /// The strip is 16 rows up to 1080p and a 64th of the height above.
    #[test]
    fn the_strip_grows_with_the_card_past_1080p() {
        assert_eq!(strip(96), 16);
        assert_eq!(strip(720), 16);
        assert_eq!(strip(1080), 16);
        assert_eq!(strip(1081), 16);
        assert_eq!(strip(1088), 17);
        assert_eq!(strip(2160), 33);
        // At 2160p the strip's 33 rows carry the index, and the row above is
        // the card's grey.
        let (w, h) = (3840, 2160);
        let px = TestCard::render(w, h, u32::MAX);
        let row = |y: u32| &px[(y * w * 4) as usize..((y + 1) * w * 4) as usize];
        assert!(row(h - 33).chunks_exact(4).all(|p| p[..3] == [255; 3]));
        assert!(row(h - 34).chunks_exact(4).all(|p| p[..3] == BACKGROUND));
    }

    /// Painting the square and the strip over the rendered-once base gives
    /// exactly the full render, at the smallest card, at 720p and at an odd
    /// size, in a buffer that is reused from picture to picture.
    #[test]
    fn incremental_pictures_equal_the_full_render() {
        for (w, h) in [(256, 96), (1280, 720), (1921, 1081)] {
            let base = base(w, h);
            let mut out = Vec::new();
            for index in [0, 1, 77, 0x8000_0001, u32::MAX] {
                paint(&base, w, h, index, &mut out);
                assert!(
                    out == TestCard::render(w, h, index),
                    "{w}x{h} #{index} differs from the full render"
                );
            }
        }
        // And through the card itself, buffers given back included.
        let mut card = TestCard::new(1921, 1081, 1000);
        for index in 0..4 {
            let frame = card.next_frame(Duration::from_secs(1)).unwrap().unwrap();
            assert!(
                frame.bgrx == TestCard::render(1921, 1081, index),
                "#{index}"
            );
            card.recycle(frame.bgrx);
        }
    }

    /// A buffer given back is painted into next: no allocation per picture.
    /// A smaller one does not replace it.
    #[test]
    fn the_card_paints_into_a_buffer_given_back() {
        let mut card = TestCard::new(640, 360, 1000);
        let first = card.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        let at = first.bgrx.as_ptr();
        card.recycle(first.bgrx);
        card.recycle(Vec::with_capacity(16));
        let second = card.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!(second.bgrx.as_ptr(), at, "the buffer given back");
        assert_eq!(TestCard::read_index(&second.bgrx, 640, 360), Some(1));
        // Nothing given back: a new buffer, as before.
        let third = card.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        assert_ne!(third.bgrx.as_ptr(), second.bgrx.as_ptr());
    }

    /// `grab` is the card's own work, not the wait for its next picture.
    #[test]
    fn grab_is_the_paint_not_the_wait() {
        let mut card = TestCard::new(256, 96, 10);
        let first = card.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        let second = card.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        let waited = second.captured_at - first.captured_at;
        assert!(waited >= Duration::from_millis(99), "{waited:?}");
        for frame in [&first, &second] {
            assert!(frame.grab > Duration::ZERO, "{:?}", frame.grab);
            assert!(frame.grab < waited / 2, "{:?} of {waited:?}", frame.grab);
        }
    }

    /// The index is read back from the card scaled whole into the picture a
    /// host sends, before encoding (BGRx) and after decoding (RGBA), at
    /// scales 1, 2/3, 1/2 and 1/3 (with widths rounded down to a multiple of
    /// 8, so not quite exact), from 2160p down to the smallest card.
    #[test]
    fn the_index_survives_scaling_encoding_and_decoding() {
        use tornect_codec::scale::{ResolutionCap, Scaler};
        use tornect_codec::{EncoderSettings, H264Decoder, H264Encoder};
        for ((sw, sh), cap) in [
            ((1920, 1080), ResolutionCap::CODEC),
            ((1920, 1080), ResolutionCap::new(1280, 720)),
            ((1920, 1080), ResolutionCap::new(960, 540)),
            ((1920, 1080), ResolutionCap::new(640, 360)),
            ((3840, 2160), ResolutionCap::new(1280, 720)),
            ((1280, 720), ResolutionCap::new(1280, 720)),
            ((1280, 720), ResolutionCap::new(854, 480)),
            ((1280, 720), ResolutionCap::new(640, 360)),
            ((1280, 720), ResolutionCap::new(427, 240)),
            ((256, 96), ResolutionCap::new(128, 64)),
        ] {
            let mut scaler = Scaler::default();
            let mut encoder = H264Encoder::new(EncoderSettings::default()).unwrap();
            let mut decoder = H264Decoder::new().unwrap();
            for index in [0, 1, 77, 0x8000_0001, u32::MAX] {
                let card = TestCard::render(sw, sh, index);
                let fitted = scaler.fit(&card, sw, sh, cap).unwrap();
                let (w, h) = (fitted.width, fitted.height);
                let what = format!("{sw}x{sh} into {w}x{h}, #{index}");
                assert_eq!(
                    TestCard::read_index_scaled(fitted.bgrx, w, h, sw, sh),
                    Some(index),
                    "{what}: scaled"
                );
                let au = encoder.encode(fitted.bgrx, w, h).unwrap();
                let frame = decoder.decode(&au.data).unwrap().expect("a picture");
                assert_eq!((frame.width, frame.height), (w, h));
                assert_eq!(
                    TestCard::read_index_scaled(&frame.rgba, w, h, sw, sh),
                    Some(index),
                    "{what}: decoded"
                );
            }
        }
    }

    #[test]
    fn a_scaled_read_needs_a_whole_picture_of_a_card() {
        let px = TestCard::render(256, 96, 5);
        assert_eq!(TestCard::read_index_scaled(&px, 256, 96, 256, 96), Some(5));
        assert_eq!(TestCard::read_index_scaled(&px, 256, 95, 256, 96), None);
        assert_eq!(TestCard::read_index_scaled(&px, 0, 96, 256, 96), None);
        assert_eq!(TestCard::read_index_scaled(&[], 0, 0, 256, 96), None);
        assert_eq!(TestCard::read_index_scaled(&px, 256, 96, 255, 96), None);
        assert_eq!(TestCard::read_index_scaled(&px, 256, 96, 256, 95), None);
        assert_eq!(
            TestCard::read_index_scaled(&px, u32::MAX, u32::MAX, 256, 96),
            None
        );
        // A picture larger than its source is read too (the samples map).
        let big = TestCard::render(512, 192, 9);
        assert_eq!(
            TestCard::read_index_scaled(&big, 512, 192, 256, 96),
            Some(9)
        );
    }

    #[test]
    fn the_card_paces_itself_and_times_out() {
        let mut card = TestCard::new(256, 96, 20);
        let first = card.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        let second = card.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        assert!(second.captured_at - first.captured_at >= Duration::from_millis(49));
        // The third picture is due in ~50 ms: a 5 ms wait comes back empty.
        let started = Instant::now();
        assert!(card.next_frame(Duration::from_millis(5)).unwrap().is_none());
        assert!(started.elapsed() >= Duration::from_millis(5));
    }
}
