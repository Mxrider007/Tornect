//! Host-side picture sizing and downscaling (quality design §6.3): which part
//! of the desktop a picture shows, how large that picture is under a
//! resolution cap, and the cheap 2:1 box pass that does most of the scaling.
//!
//! The picture is always a uniform scale of the [`shown_region`] anchored at
//! its top-left corner, never upscaled. The input injectors map the viewer's
//! normalized pointer over that same region (§5 rule 8), so a position on the
//! picture lands on the desktop pixel it shows.

use crate::{MAX_LONG_SIDE, MAX_SHORT_SIDE};

/// The smallest edge a [`ResolutionCap::new`] keeps: no preset asks for less,
/// and a picture this small is no longer a desktop anyone can read.
const MIN_CAP_EDGE: u32 = 64;

/// The largest picture a preset allows, by its long and short edge, in either
/// orientation: a cap of 1920×1080 holds a 1080×1920 portrait screen whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionCap {
    /// The longest edge, in pixels.
    pub long: u32,
    /// The shortest edge, in pixels; at most `long`.
    pub short: u32,
}

impl ResolutionCap {
    /// The codec's own limit, 3840×2160 either way up.
    pub const CODEC: Self = Self {
        long: MAX_LONG_SIDE,
        short: MAX_SHORT_SIDE,
    };

    /// A cap of `long`×`short`, held to [`Self::CODEC`], each edge at least
    /// 64, and `short` at most `long`.
    #[must_use]
    pub const fn new(long: u32, short: u32) -> Self {
        let long = if long < MIN_CAP_EDGE {
            MIN_CAP_EDGE
        } else if long > MAX_LONG_SIDE {
            MAX_LONG_SIDE
        } else {
            long
        };
        let short = if short < MIN_CAP_EDGE {
            MIN_CAP_EDGE
        } else if short > MAX_SHORT_SIDE {
            MAX_SHORT_SIDE
        } else {
            short
        };
        let short = if short > long { long } else { short };
        Self { long, short }
    }
}

/// The part of a `w`×`h` desktop that its pictures show: all of it, but for
/// an odd last column or row (the codec takes even sides only). The injectors
/// map pointer positions over this region.
#[must_use]
pub fn shown_region(w: u32, h: u32) -> (u32, u32) {
    (w & !1, h & !1)
}

/// The size of the picture that shows `region` (a [`shown_region`]) under
/// `cap`: the region itself when it fits the cap in its own orientation,
/// otherwise the region scaled uniformly until its long edge is at most
/// `cap.long` and its short edge at most `cap.short`, never upscaled.
///
/// A scaled picture's width is rounded down to a multiple of 8 (at least 8,
/// never wider than the region), which keeps the viewer's YUV→RGBA
/// conversion on OpenH264's SIMD path; its height is rounded down to even (at
/// least 2). Either edge is then less than 8 or 2 pixels short of the exact
/// scale, so the aspect error stays under 8 pixels.
#[must_use]
pub fn picture_size(region: (u32, u32), cap: ResolutionCap) -> (u32, u32) {
    let (w, h) = region;
    let (long, short) = (w.max(h), w.min(h));
    if long <= cap.long && short <= cap.short {
        return (w, h);
    }
    let (w64, h64) = (u64::from(w), u64::from(h));
    let (long, short) = (u64::from(long), u64::from(short));
    let (cap_long, cap_short) = (u64::from(cap.long), u64::from(cap.short));
    // The smaller of cap_long/long and cap_short/short, as n/d. The divisor is
    // never 0: a region that does not fit has a long edge above cap.long, and
    // the short edge is taken only when cap_long·short exceeds 0.
    let (n, d) = if cap_long * short <= cap_short * long {
        (cap_long, long)
    } else {
        (cap_short, short)
    };
    let pw = ((w64 * n / d) & !7).max(8).min(w64);
    let ph = ((h64 * n / d) & !1).max(2).min(h64);
    (
        u32::try_from(pw).unwrap_or(w),
        u32::try_from(ph).unwrap_or(h),
    )
}

/// Copy the [`shown_region`] of a tightly packed `w`×`h` BGRx picture into
/// `out`, tightly packed: the picture without an odd last column or row. A
/// buffer shorter than `w`·`h`·4 bytes gives only the whole rows it holds.
pub fn crop_even(bgrx: &[u8], w: u32, h: u32, out: &mut Vec<u8>) {
    let (ew, eh) = shown_region(w, h);
    let (stride, row) = (w as usize * 4, ew as usize * 4);
    out.clear();
    if row == 0 {
        return;
    }
    out.reserve((bgrx.len() / stride).min(eh as usize) * row);
    for line in bgrx.chunks_exact(stride).take(eh as usize) {
        out.extend_from_slice(&line[..row]);
    }
}

/// One 2:1 box pass: the `w`×`h` BGRx picture at `src`, its rows `stride`
/// bytes apart, halved into `dst` (tightly packed, resized to fit). Each
/// output pixel's B, G and R are the rounded mean `(a+b+c+d+2)>>2` of a 2×2
/// block, X is 255, and an odd last column or row is dropped. Returns the
/// output size. `src` must hold `h` rows of `stride` bytes with
/// `stride ≥ w·4` (the last row may stop after its `w` pixels).
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Scaler::fit, the next step, is its caller")
)]
fn halve(src: &[u8], w: u32, h: u32, stride: usize, dst: &mut Vec<u8>) -> (u32, u32) {
    let (ow, oh) = (w / 2, h / 2);
    let row = ow as usize * 4;
    dst.resize(row * oh as usize, 0);
    if row == 0 {
        return (ow, oh);
    }
    for (y, out) in dst.chunks_exact_mut(row).enumerate() {
        let top = &src[2 * y * stride..][..2 * row];
        let bot = &src[(2 * y + 1) * stride..][..2 * row];
        for ((o, t), b) in out
            .chunks_exact_mut(4)
            .zip(top.chunks_exact(8))
            .zip(bot.chunks_exact(8))
        {
            for c in 0..3 {
                let sum = u16::from(t[c])
                    + u16::from(t[c + 4])
                    + u16::from(b[c])
                    + u16::from(b[c + 4])
                    + 2;
                o[c] = (sum >> 2) as u8;
            }
            o[3] = 255;
        }
    }
    (ow, oh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The presets' caps (quality design §3.1): Best quality is the codec's
    /// own, Balanced 1920×1080, Best performance 1280×720.
    const BALANCED: ResolutionCap = ResolutionCap::new(1920, 1080);
    const PERFORMANCE: ResolutionCap = ResolutionCap::new(1280, 720);

    #[test]
    fn a_cap_is_held_to_the_codec_and_kept_upright() {
        assert_eq!(ResolutionCap::new(3840, 2160), ResolutionCap::CODEC);
        assert_eq!(ResolutionCap::new(9999, 9999), ResolutionCap::CODEC);
        assert_eq!(
            ResolutionCap::new(0, 0),
            ResolutionCap {
                long: 64,
                short: 64
            }
        );
        assert_eq!(
            ResolutionCap::new(100, 3000),
            ResolutionCap {
                long: 100,
                short: 100
            },
            "short never above long"
        );
        assert_eq!(
            ResolutionCap::new(1280, 720),
            ResolutionCap {
                long: 1280,
                short: 720
            }
        );
    }

    #[test]
    fn the_shown_region_drops_an_odd_last_column_or_row() {
        assert_eq!(shown_region(1920, 1080), (1920, 1080));
        assert_eq!(shown_region(1921, 1081), (1920, 1080));
        assert_eq!(shown_region(1366, 767), (1366, 766));
        assert_eq!(shown_region(1, 1), (0, 0));
    }

    /// The design's table (§8): each desktop against the codec's cap and
    /// the three presets'. The expected sizes were computed apart from this
    /// code, with exact fractions: `floor(edge·s)` rounded down to a
    /// multiple of 8 (width) or 2 (height), `s` the smaller ratio.
    #[test]
    fn picture_sizes_follow_the_table() {
        // A desktop, then its picture at CODEC, Balanced and Best performance.
        type Row = ((u32, u32), [(u32, u32); 3]);
        let table: &[Row] = &[
            ((1920, 1080), [(1920, 1080), (1920, 1080), (1280, 720)]),
            ((2560, 1440), [(2560, 1440), (1920, 1080), (1280, 720)]),
            ((3538, 1918), [(3538, 1918), (1920, 1040), (1280, 692)]),
            ((3840, 2160), [(3840, 2160), (1920, 1080), (1280, 720)]),
            ((5120, 2880), [(3840, 2160), (1920, 1080), (1280, 720)]),
            ((7680, 4320), [(3840, 2160), (1920, 1080), (1280, 720)]),
            ((7680, 2160), [(3840, 1080), (1920, 540), (1280, 360)]),
            ((1080, 1920), [(1080, 1920), (1080, 1920), (720, 1280)]),
            ((2160, 3840), [(2160, 3840), (1080, 1920), (720, 1280)]),
            ((1440, 2560), [(1440, 2560), (1080, 1920), (720, 1280)]),
            ((1921, 1081), [(1920, 1080), (1920, 1080), (1280, 720)]),
            ((1366, 768), [(1366, 768), (1366, 768), (1280, 718)]),
            ((3, 3), [(2, 2), (2, 2), (2, 2)]),
        ];
        for &((w, h), want) in table {
            let region = shown_region(w, h);
            for (cap, want) in [ResolutionCap::CODEC, BALANCED, PERFORMANCE]
                .into_iter()
                .zip(want)
            {
                assert_eq!(picture_size(region, cap), want, "{w}x{h} at {cap:?}");
            }
        }
    }

    #[test]
    fn degenerate_regions_never_panic() {
        for region in [(0, 0), (0, 5000), (5000, 0), (2, 8192), (8192, 2), (1, 1)] {
            for cap in [
                ResolutionCap::CODEC,
                PERFORMANCE,
                ResolutionCap { long: 0, short: 0 },
                ResolutionCap { long: 0, short: 9 },
            ] {
                let (pw, ph) = picture_size(region, cap);
                assert!(pw <= region.0 && ph <= region.1, "{region:?} {cap:?}");
            }
        }
        assert_eq!(picture_size((2, 8192), PERFORMANCE), (2, 1280));
        assert_eq!(picture_size((10, 8192), PERFORMANCE), (8, 1280));
    }

    proptest! {
        /// §8: the picture fits the cap in its own orientation, a scaled
        /// width is a multiple of 8 (or the whole region when that is under
        /// 8), heights stay even, nothing exceeds the region, and each edge
        /// is less than 8 (width) or 2 (height) pixels from the exact
        /// uniform scale.
        #[test]
        fn picture_size_properties(
            w in 2u32..=8192,
            h in 2u32..=8192,
            cap_long in 0u32..=5000,
            cap_short in 0u32..=5000,
        ) {
            let cap = ResolutionCap::new(cap_long, cap_short);
            let (rw, rh) = shown_region(w, h);
            let (pw, ph) = picture_size((rw, rh), cap);
            prop_assert!(pw.max(ph) <= cap.long && pw.min(ph) <= cap.short);
            prop_assert!(pw <= rw && ph <= rh);
            prop_assert_eq!(ph % 2, 0);
            prop_assert!(pw >= 2 && ph >= 2);
            if (pw, ph) == (rw, rh) {
                prop_assert!(rw.max(rh) <= cap.long && rw.min(rh) <= cap.short);
                return Ok(());
            }
            prop_assert!(pw % 8 == 0 || (pw == rw && rw < 8), "{}", pw);
            // The exact scale is n/d; compare in integers: |p·d − r·n| ≤ e·d.
            let (long, short) = (u64::from(rw.max(rh)), u64::from(rw.min(rh)));
            let (cl, cs) = (u64::from(cap.long), u64::from(cap.short));
            let (n, d) = if cl * short <= cs * long { (cl, long) } else { (cs, short) };
            let err = |p: u32, r: u32| (u64::from(p) * d).abs_diff(u64::from(r) * n);
            prop_assert!(err(pw, rw) <= 8 * d, "width {} of {}", pw, rw);
            prop_assert!(err(ph, rh) <= 2 * d, "height {} of {}", ph, rh);
        }
    }

    #[test]
    fn crop_even_copies_the_shown_region_row_by_row() {
        let (w, h) = (5, 3);
        let src: Vec<u8> = (0..w * h * 4).map(|i| i as u8).collect();
        let mut out = vec![9; 3];
        crop_even(&src, w, h, &mut out);
        let mut want = Vec::new();
        for y in 0..2 {
            want.extend_from_slice(&src[(y * w * 4) as usize..][..16]);
        }
        assert_eq!(out, want);
        // An even picture comes back whole; nothing is left from before.
        crop_even(&src[..32], 4, 2, &mut out);
        assert_eq!(out, src[..32]);
        // Too few bytes: only the whole rows held, never a panic.
        crop_even(&src[..30], 5, 3, &mut out);
        assert_eq!(out, src[..16]);
        crop_even(&src, 1, 1, &mut out);
        assert!(out.is_empty());
        // A size the buffer cannot hold reserves nothing for it.
        crop_even(&src, 100_000, 100_000, &mut out);
        assert!(out.is_empty());
    }

    /// §8: a 2×2 checkerboard of black and white becomes mid-grey, with the
    /// rounding `(a+b+c+d+2)>>2` exact per channel, and X set to 255.
    #[test]
    fn the_box_pass_takes_rounded_means() {
        let black = [0, 0, 0, 0];
        let white = [255, 255, 255, 0];
        let board: Vec<u8> = [white, black, black, white].concat();
        let mut out = Vec::new();
        assert_eq!(halve(&board, 2, 2, 8, &mut out), (1, 1));
        assert_eq!(out, [128, 128, 128, 255], "510 + 2 >> 2");

        // Per channel: 1+2+2+2 = 7 → 9>>2 = 2; 0+0+0+1 = 1 → 3>>2 = 0;
        // 0+1+1+1 = 3 → 5>>2 = 1; 254+255+255+255 = 1019 → 1021>>2 = 255.
        let px = |b, g, r| [b, g, r, 7];
        let block: Vec<u8> = [px(1, 0, 0), px(2, 0, 1), px(2, 0, 1), px(2, 1, 1)].concat();
        assert_eq!(halve(&block, 2, 2, 8, &mut out), (1, 1));
        assert_eq!(out, [2, 0, 1, 255]);
        let top = [254u8, 255, 0, 0, 255, 255, 0, 0];
        let bot = [255u8, 255, 0, 0, 255, 255, 0, 0];
        assert_eq!(halve(&[top, bot].concat(), 2, 2, 8, &mut out), (1, 1));
        assert_eq!(out, [255, 255, 0, 255]);
    }

    /// An odd last column or row is dropped, rows are read `stride` apart
    /// (the input's odd width included), and a smooth ramp keeps its
    /// centres: output pixel `x` is the mean of input `2x` and `2x + 1`.
    #[test]
    fn the_box_pass_halves_the_region_and_drops_odd_edges() {
        let (w, h) = (7u32, 5u32);
        let stride = w as usize * 4;
        let mut src = vec![0u8; stride * h as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let p = &mut src[y * stride + x * 4..][..4];
                p.copy_from_slice(&[(x * 10) as u8, (y * 20) as u8, 50, 0]);
            }
        }
        let mut out = vec![1; 1000];
        assert_eq!(halve(&src, w, h, stride, &mut out), (3, 2));
        assert_eq!(out.len(), 3 * 2 * 4);
        for y in 0..2 {
            for x in 0..3 {
                let p = &out[(y * 3 + x) * 4..][..4];
                // The means of 20x and 20x + 10, and of 40y and 40y + 20.
                let b = (20 * x + 5) as u8;
                let g = (40 * y + 10) as u8;
                assert_eq!(p, [b, g, 50, 255], "({x}, {y})");
            }
        }
        // Too small to halve: nothing, and no panic.
        assert_eq!(halve(&src[..4], 1, 1, 4, &mut out), (0, 0));
        assert!(out.is_empty());
    }
}
