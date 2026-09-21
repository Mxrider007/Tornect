//! A synthetic test card: the capture source every machine has, for the
//! pipeline tests and for sessions on hosts without a capture backend.
//!
//! The card carries its own frame index in a strip of 32 black-or-white
//! blocks along the bottom edge, large enough to survive H.264, so a viewer
//! can check order and loss end to end ([`TestCard::read_index`]).

use std::time::{Duration, Instant};

use crate::{CaptureError, Frame, VideoSource};

/// Smallest card: the index strip needs 32 blocks of at least 8 pixels.
pub const MIN_WIDTH: u32 = 256;
/// Smallest card height.
pub const MIN_HEIGHT: u32 = 96;

/// Height of the index strip at the bottom.
const STRIP: u32 = 16;
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

/// Colour bars, a moving square and the frame index, at a fixed rate.
#[derive(Debug)]
pub struct TestCard {
    width: u32,
    height: u32,
    interval: Duration,
    next_at: Option<Instant>,
    index: u32,
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
        }
    }

    /// Picture number `index` of a `width`×`height` card, tightly packed BGRx.
    #[must_use]
    pub fn render(width: u32, height: u32, index: u32) -> Vec<u8> {
        let (w, h) = (width as usize, height as usize);
        let mut px = vec![0u8; w * h * 4];
        let bars_end = h * 2 / 3;
        let strip_start = h - STRIP as usize;
        let square = (h / 6).clamp(8, 64);
        let travel = w.saturating_sub(square).max(1);
        let square_x = (index as usize * 8) % travel;
        let square_y = bars_end + (strip_start - bars_end).saturating_sub(square) / 2;
        let bit_w = w / BITS as usize;
        for y in 0..h {
            for x in 0..w {
                let bgr = if y < bars_end {
                    BARS[x * BARS.len() / w]
                } else if y >= strip_start {
                    let bit = x / bit_w;
                    let on = bit < BITS as usize && ((index >> (BITS as usize - 1 - bit)) & 1) == 1;
                    if on { [255; 3] } else { [0; 3] }
                } else if (square_x..square_x + square).contains(&x)
                    && (square_y..square_y + square).contains(&y)
                {
                    [255; 3]
                } else {
                    [64; 3]
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
        let (w, h) = (width as usize, height as usize);
        if bgrx.len() != w * h * 4 || width < MIN_WIDTH || height < MIN_HEIGHT {
            return None;
        }
        let bit_w = w / BITS as usize;
        let y = h - STRIP as usize / 2;
        let mut index = 0u32;
        for bit in 0..BITS as usize {
            let x = bit * bit_w + bit_w / 2;
            let green = bgrx[(y * w + x) * 4 + 1];
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
        let frame = Frame {
            width: self.width,
            height: self.height,
            bgrx: Self::render(self.width, self.height, self.index),
            captured_at: Instant::now(),
        };
        self.index = self.index.wrapping_add(1);
        // A late consumer gets the next picture one interval after this one,
        // never a burst of catch-up pictures.
        self.next_at = Some(due.max(now) + self.interval);
        Ok(Some(frame))
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
