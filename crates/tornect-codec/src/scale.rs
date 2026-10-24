//! Host-side picture sizing and downscaling (quality design §6.3): which part
//! of the desktop a picture shows, how large that picture is under a
//! resolution cap, and [`Scaler`], which makes that picture: 2:1 box passes
//! while the picture is at most half the size, then one bilinear pass.
//!
//! The picture is always a uniform scale of the [`shown_region`] anchored at
//! its top-left corner, never upscaled. The input injectors map the viewer's
//! normalized pointer over that same region (§5 rule 8), so a position on the
//! picture lands on the desktop pixel it shows.

use std::time::{Duration, Instant};

use crate::{CodecError, MAX_LONG_SIDE, MAX_SHORT_SIDE};

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
            o.copy_from_slice(&box_mean(word(t), word(b)).to_le_bytes());
        }
    }
    (ow, oh)
}

/// Two BGRx pixels, the first in the low half (little-endian, whatever the
/// host's byte order).
fn word(two: &[u8]) -> u64 {
    u64::from_le_bytes(two.try_into().unwrap_or([0; 8]))
}

/// The 2:1 box mean of two pixel pairs, `top` above `bot`, as one BGRx
/// pixel with X = 255: `(a+b+c+d+2)>>2` per channel, four channels at a time
/// in 16-bit lanes of a `u64` (each lane's sum is at most 4·255+2, so no lane
/// carries into the next, and the bits a shift moves across lanes are masked
/// off).
fn box_mean(top: u64, bot: u64) -> u32 {
    const LANES: u64 = 0x00FF_00FF_00FF_00FF;
    // B and R of both pixels, then G and X, each summed over the two rows.
    let br = (top & LANES) + (bot & LANES);
    let gx = ((top >> 8) & LANES) + ((bot >> 8) & LANES);
    // The second pixel's lanes onto the first's, plus the rounding 2.
    let br = (br + (br >> 32) + 0x0002_0002) >> 2;
    let gx = (gx + (gx >> 32) + 0x0002_0002) >> 2;
    let px = (br & 0x00FF_00FF) | ((gx & 0x00FF_00FF) << 8);
    (px as u32) | 0xFF00_0000
}

/// One axis of a bilinear pass: for each output index, the two input indices
/// it blends and the weight of the second, in 1/256 (Q8). Rebuilt only when
/// the sizes change, so a steady stream reuses it.
#[derive(Debug, Default)]
struct Table {
    from: u32,
    to: u32,
    idx: Vec<(u32, u32, u16)>,
}

impl Table {
    /// The table for `from` input pixels onto `to` output pixels (`from ≥ 1`).
    /// Output pixel `x` samples the input at its centre, `(x + ½)·from/to −
    /// ½`, in Q8: `((2x+1)·from·128)/to − 128`, held to the input.
    fn update(&mut self, from: u32, to: u32) {
        if (self.from, self.to) == (from, to) && self.idx.len() == to as usize {
            return;
        }
        self.from = from;
        self.to = to;
        self.idx.clear();
        let (src, dst) = (i64::from(from), i64::from(to));
        let last = (src - 1).max(0);
        self.idx.extend((0..dst).map(|x| {
            let p = ((2 * x + 1) * src * 128 / dst - 128).clamp(0, last * 256);
            let i0 = p >> 8;
            let i1 = (i0 + 1).min(last);
            // Both are input indices (≤ last < 2^32) and p & 255 < 256.
            (
                u32::try_from(i0).unwrap_or(0),
                u32::try_from(i1).unwrap_or(0),
                (p & 255) as u16,
            )
        }));
    }
}

/// One bilinear pass in Q8 from the picture at `src` (rows `stride` bytes
/// apart) into `dst`, `xt.to`×`yt.to`, tightly packed, X = 255. Each channel
/// is `(Σ wx·wy·p + 32768) >> 16` over the four input pixels around the
/// sample, the weights in 1/256: the design's `(top·(256−fy) + bottom·fy +
/// 32768) >> 16` with the two blends taken in the other order, which gives
/// the same integers. The vertical blend of rows `y0` and `y1` goes first,
/// into `mid` (at most 255·256, so `u16`), as one straight loop over the
/// row; the horizontal blend then reads two of its pixels per output pixel.
/// `src` must hold every row the tables name, each at least `xt.from`
/// pixels long.
fn bilinear(
    src: &[u8],
    stride: usize,
    xt: &Table,
    yt: &Table,
    mid: &mut Vec<u16>,
    dst: &mut Vec<u8>,
) {
    let row = xt.idx.len() * 4;
    dst.resize(row * yt.idx.len(), 0);
    if row == 0 {
        return;
    }
    let width = xt.from as usize * 4;
    mid.resize(width, 0);
    for (out, &(y0, y1, fy)) in dst.chunks_exact_mut(row).zip(&yt.idx) {
        let top = &src[y0 as usize * stride..][..width];
        let bot = &src[y1 as usize * stride..][..width];
        let (wb, wt) = (fy, 256 - fy);
        for ((m, &t), &b) in mid.iter_mut().zip(top).zip(bot) {
            *m = u16::from(t) * wt + u16::from(b) * wb;
        }
        for (o, &(x0, x1, fx)) in out.chunks_exact_mut(4).zip(&xt.idx) {
            let (l, r) = (x0 as usize * 4, x1 as usize * 4);
            let (left, right) = (&mid[l..l + 4], &mid[r..r + 4]);
            let (wr, wl) = (u32::from(fx), 256 - u32::from(fx));
            for c in 0..3 {
                let v = u32::from(left[c]) * wl + u32::from(right[c]) * wr + 32768;
                o[c] = (v >> 16) as u8;
            }
            o[3] = 255;
        }
    }
}

/// A picture made by [`Scaler::fit`]: tightly packed BGRx, X = 255 when it
/// was scaled.
pub struct Fitted<'a> {
    /// The picture: the input itself, borrowed, when it needed nothing.
    pub bgrx: &'a [u8],
    /// Width; even, and a multiple of 8 when scaled (unless the region is
    /// narrower than 8).
    pub width: u32,
    /// Height; even.
    pub height: u32,
    /// Whether the picture is smaller than the [`shown_region`]: false when
    /// it is the input, or the input without an odd last column or row.
    pub scaled: bool,
    /// What fitting it took.
    pub took: Duration,
}

impl std::fmt::Debug for Fitted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fitted")
            .field("bytes", &self.bgrx.len())
            .field("width", &self.width)
            .field("height", &self.height)
            .field("scaled", &self.scaled)
            .field("took", &self.took)
            .finish()
    }
}

/// Makes the picture for a desktop under a [`ResolutionCap`], reusing its
/// buffers and bilinear tables from one picture to the next. Its buffers
/// only grow; in practice each holds one picture.
#[derive(Default)]
pub struct Scaler {
    /// The box passes alternate between `a` and `b`.
    a: Vec<u8>,
    b: Vec<u8>,
    /// The bilinear pass's output, or the cropped input.
    out: Vec<u8>,
    /// The bilinear pass's vertical blend of one row.
    mid: Vec<u16>,
    xt: Table,
    yt: Table,
}

impl std::fmt::Debug for Scaler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scaler")
            .field("x", &(self.xt.from, self.xt.to))
            .field("y", &(self.yt.from, self.yt.to))
            .finish_non_exhaustive()
    }
}

/// Which buffer holds the picture between passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Input,
    A,
    B,
}

impl Scaler {
    /// The picture of the tightly packed `w`×`h` BGRx desktop `bgrx` under
    /// `cap`: [`picture_size`] of its [`shown_region`].
    ///
    /// 1. A picture that needs nothing is the input, borrowed: no copy.
    /// 2. While the picture is at most half the current size both ways, a
    ///    2:1 box pass halves it (3840×2160 to 1920×1080 is exactly one).
    /// 3. If the size still differs, one bilinear pass makes it.
    /// 4. A desktop that only has an odd edge to drop is cropped.
    ///
    /// # Errors
    /// [`CodecError::Geometry`] if `bgrx` is not `w`·`h`·4 bytes;
    /// [`CodecError::PictureSize`] if the shown region is under 2×2.
    pub fn fit<'a>(
        &'a mut self,
        bgrx: &'a [u8],
        w: u32,
        h: u32,
        cap: ResolutionCap,
    ) -> Result<Fitted<'a>, CodecError> {
        let start = Instant::now();
        let want = (w as usize)
            .checked_mul(h as usize)
            .and_then(|n| n.checked_mul(4));
        if want != Some(bgrx.len()) {
            return Err(CodecError::Geometry {
                got: bgrx.len(),
                want: want.unwrap_or(usize::MAX),
                w,
                h,
            });
        }
        let (rw, rh) = shown_region(w, h);
        if rw < 2 || rh < 2 {
            return Err(CodecError::PictureSize { w, h });
        }
        let (ow, oh) = picture_size((rw, rh), cap);
        let scaled = (ow, oh) != (rw, rh);
        if (ow, oh) == (w, h) {
            return Ok(Fitted {
                bgrx,
                width: w,
                height: h,
                scaled,
                took: start.elapsed(),
            });
        }

        // The region of the input first: its rows are the input's, w·4 bytes
        // apart, so an odd last column is never read.
        let (mut held, mut cw, mut ch, mut stride) = (Held::Input, rw, rh, w as usize * 4);
        while 2 * u64::from(ow) <= u64::from(cw) && 2 * u64::from(oh) <= u64::from(ch) {
            let (src, dst, next) = match held {
                Held::Input => (bgrx, &mut self.a, Held::A),
                Held::A => (&self.a[..], &mut self.b, Held::B),
                Held::B => (&self.b[..], &mut self.a, Held::A),
            };
            (cw, ch) = halve(src, cw, ch, stride, dst);
            stride = cw as usize * 4;
            held = next;
        }
        let src = match held {
            Held::Input => bgrx,
            Held::A => &self.a[..],
            Held::B => &self.b[..],
        };
        let bgrx: &[u8] = if (cw, ch) != (ow, oh) {
            self.xt.update(cw, ow);
            self.yt.update(ch, oh);
            bilinear(
                src,
                stride,
                &self.xt,
                &self.yt,
                &mut self.mid,
                &mut self.out,
            );
            &self.out
        } else if held == Held::Input {
            crop_even(bgrx, w, h, &mut self.out);
            &self.out
        } else {
            src
        };
        Ok(Fitted {
            bgrx,
            width: ow,
            height: oh,
            scaled,
            took: start.elapsed(),
        })
    }
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

    proptest! {
        /// The lane arithmetic is the per-channel `(a+b+c+d+2)>>2` for any
        /// bytes at all, X included in the sums and then set to 255.
        #[test]
        fn box_mean_is_the_rounded_mean_per_channel(
            top in any::<[u8; 8]>(),
            bot in any::<[u8; 8]>(),
        ) {
            let got = box_mean(word(&top), word(&bot)).to_le_bytes();
            for c in 0..3 {
                let sum = u16::from(top[c])
                    + u16::from(top[c + 4])
                    + u16::from(bot[c])
                    + u16::from(bot[c + 4]);
                prop_assert_eq!(u16::from(got[c]), (sum + 2) >> 2, "channel {}", c);
            }
            prop_assert_eq!(got[3], 255);
        }
    }

    #[test]
    fn box_mean_holds_at_the_extremes() {
        assert_eq!(box_mean(u64::MAX, u64::MAX), u32::MAX);
        assert_eq!(box_mean(0, 0), 0xFF00_0000);
        // 255+255+255+254+2 = 1021 → 255; 0+0+0+1+2 = 3 → 0; 1+1+0+0+2 → 1.
        let top = word(&[255, 0, 1, 9, 255, 0, 1, 9]);
        let bot = word(&[255, 0, 0, 9, 254, 1, 0, 9]);
        assert_eq!(box_mean(top, bot).to_le_bytes(), [255, 0, 1, 255]);
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

    /// A `w`×`h` BGRx picture whose pixel is `f(x, y)`, X = 0.
    fn picture(w: u32, h: u32, f: impl Fn(u32, u32) -> [u8; 3]) -> Vec<u8> {
        let mut out = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                let [b, g, r] = f(x, y);
                out.extend_from_slice(&[b, g, r, 0]);
            }
        }
        out
    }

    /// Bilinear from `from_w`×`from_h` (tight) to `to_w`×`to_h`.
    fn resample(src: &[u8], from: (u32, u32), to: (u32, u32)) -> Vec<u8> {
        let (mut xt, mut yt) = (Table::default(), Table::default());
        xt.update(from.0, to.0);
        yt.update(from.1, to.1);
        let mut out = Vec::new();
        bilinear(
            src,
            from.0 as usize * 4,
            &xt,
            &yt,
            &mut Vec::new(),
            &mut out,
        );
        out
    }

    fn px(buf: &[u8], w: u32, x: u32, y: u32) -> [u8; 4] {
        buf[((y * w + x) * 4) as usize..][..4].try_into().unwrap()
    }

    /// §8: no access outside the input for any size from 2 to 63 onto any
    /// other, either axis (the buffers are exactly sized, so a stray index
    /// panics); a constant picture stays constant; ramps along x (B) and y
    /// (G) stay monotonic; every channel stays within the input's range.
    #[test]
    fn bilinear_stays_inside_keeps_constants_and_ramps() {
        for from in 2u32..64 {
            for to in 2u32..64 {
                for (fw, fh, tw, th) in [(from, from, to, to), (from, to, to, from)] {
                    let flat = picture(fw, fh, |_, _| [17, 200, 99]);
                    let out = resample(&flat, (fw, fh), (tw, th));
                    assert_eq!(out.len(), (tw * th * 4) as usize);
                    assert!(
                        out.chunks_exact(4).all(|p| p == [17, 200, 99, 255]),
                        "{fw}x{fh} -> {tw}x{th}"
                    );
                    let ramp = picture(fw, fh, |x, y| [(x * 4) as u8, (y * 4) as u8, 0]);
                    let out = resample(&ramp, (fw, fh), (tw, th));
                    for y in 0..th {
                        for x in 0..tw {
                            let p = px(&out, tw, x, y);
                            assert!(
                                u32::from(p[0]) <= (fw - 1) * 4 && u32::from(p[1]) <= (fh - 1) * 4
                            );
                            if x > 0 {
                                assert!(p[0] >= px(&out, tw, x - 1, y)[0], "x ramp {fw}->{tw}");
                            }
                            if y > 0 {
                                assert!(p[1] >= px(&out, tw, x, y - 1)[1], "y ramp {fh}->{th}");
                            }
                        }
                    }
                }
            }
        }
    }

    /// The design's formula, pixel by pixel: the horizontal blends of rows
    /// `y0` and `y1` first, then `(top·(256−fy) + bottom·fy + 32768) >> 16`.
    fn bilinear_as_designed(src: &[u8], from: (u32, u32), to: (u32, u32)) -> Vec<u8> {
        let (mut xt, mut yt) = (Table::default(), Table::default());
        xt.update(from.0, to.0);
        yt.update(from.1, to.1);
        let at = |x: u32, y: u32, c: usize| u32::from(src[((y * from.0 + x) * 4) as usize + c]);
        let mut out = Vec::new();
        for &(y0, y1, fy) in &yt.idx {
            let fy = u32::from(fy);
            for &(x0, x1, fx) in &xt.idx {
                let fx = u32::from(fx);
                for c in 0..3 {
                    let top = at(x0, y0, c) * (256 - fx) + at(x1, y0, c) * fx;
                    let bottom = at(x0, y1, c) * (256 - fx) + at(x1, y1, c) * fx;
                    out.push(((top * (256 - fy) + bottom * fy + 32768) >> 16) as u8);
                }
                out.push(255);
            }
        }
        out
    }

    proptest! {
        /// The vertical-first pass gives exactly the design's integers.
        #[test]
        fn bilinear_matches_the_design_formula(
            fw in 2u32..40,
            fh in 2u32..40,
            tw in 1u32..40,
            th in 1u32..40,
            seed in any::<u64>(),
        ) {
            let mut state = seed | 1;
            let src: Vec<u8> = (0..fw * fh * 4)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            prop_assert_eq!(
                resample(&src, (fw, fh), (tw, th)),
                bilinear_as_designed(&src, (fw, fh), (tw, th))
            );
        }
    }

    /// The bilinear pass samples each output pixel at its centre: scaling
    /// steep ramps (4 levels a pixel) 64 → 48 both ways gives each ramp's
    /// value at `(x + ½)·4/3 − ½`, to within rounding (half a level, plus
    /// the Q8 position's 4/256). A sample half a pixel off is 2 levels off.
    #[test]
    fn bilinear_samples_at_pixel_centres() {
        let src = picture(64, 64, |x, y| [(x * 4) as u8, (y * 4) as u8, 0]);
        let out = resample(&src, (64, 64), (48, 48));
        let centre = |i: u32| (f64::from(i) + 0.5) * 64.0 / 48.0 - 0.5;
        for y in 0..48 {
            for x in 0..48 {
                let p = px(&out, 48, x, y);
                for (got, at) in [(p[0], centre(x)), (p[1], centre(y))] {
                    let want = 4.0 * at;
                    assert!(
                        (f64::from(got) - want).abs() <= 0.5 + 4.0 / 256.0,
                        "({x}, {y}): {got} for {want}"
                    );
                }
            }
        }
    }

    /// The tables are rebuilt only for new sizes.
    #[test]
    fn a_table_is_rebuilt_only_for_new_sizes() {
        let mut t = Table::default();
        t.update(2560, 1920);
        let (ptr, first) = (t.idx.as_ptr(), t.idx.clone());
        t.update(2560, 1920);
        assert_eq!((t.idx.as_ptr(), &t.idx), (ptr, &first));
        assert_eq!(first[0], (0, 1, 42), "x 0 samples 0.1667 of the way to 1");
        assert_eq!(
            first[1919],
            (2558, 2559, 213),
            "2558.833: 213/256 of the way"
        );
        t.update(1920, 1280);
        assert_eq!(t.idx.len(), 1280);
        assert_eq!((t.from, t.to), (1920, 1280));
        // Positions outside the input are held to its edges.
        t.update(2, 4);
        assert_eq!(t.idx, [(0, 1, 0), (0, 1, 64), (0, 1, 192), (1, 1, 0)]);
    }

    /// §8: a picture that needs nothing is the input itself, borrowed.
    #[test]
    fn fit_borrows_a_picture_that_needs_nothing() {
        let mut scaler = Scaler::default();
        let src = picture(1920, 1080, |x, y| [x as u8, y as u8, 7]);
        let fitted = scaler.fit(&src, 1920, 1080, BALANCED).unwrap();
        assert_eq!(fitted.bgrx.as_ptr(), src.as_ptr(), "no copy");
        assert_eq!(
            (fitted.width, fitted.height, fitted.scaled),
            (1920, 1080, false)
        );
        let fitted = scaler.fit(&src, 1920, 1080, ResolutionCap::CODEC).unwrap();
        assert_eq!(fitted.bgrx.as_ptr(), src.as_ptr());
    }

    /// §8: an odd desktop that fits is cropped to its shown region, not
    /// scaled; the odd last column and row are what is left out.
    #[test]
    fn fit_crops_an_odd_desktop_that_fits() {
        let mut scaler = Scaler::default();
        let src = picture(1921, 1081, |x, y| [x as u8, y as u8, (x ^ y) as u8]);
        let mut want = Vec::new();
        crop_even(&src, 1921, 1081, &mut want);
        let fitted = scaler.fit(&src, 1921, 1081, ResolutionCap::CODEC).unwrap();
        assert_eq!(
            (fitted.width, fitted.height, fitted.scaled),
            (1920, 1080, false)
        );
        assert!(fitted.bgrx == want.as_slice());
    }

    /// 3840×2160 to 1920×1080 is exactly one box pass, and the picture is
    /// that pass's buffer: no further copy.
    #[test]
    fn fit_halves_4k_to_1080p_in_one_box_pass() {
        let mut scaler = Scaler::default();
        let src = picture(3840, 2160, |x, y| {
            [(x * 3) as u8, (y * 5) as u8, (x + y) as u8]
        });
        let mut want = Vec::new();
        assert_eq!(halve(&src, 3840, 2160, 3840 * 4, &mut want), (1920, 1080));
        let fitted = scaler.fit(&src, 3840, 2160, BALANCED).unwrap();
        assert_eq!(
            (fitted.width, fitted.height, fitted.scaled),
            (1920, 1080, true)
        );
        assert!(fitted.bgrx == want.as_slice());
        assert_eq!(fitted.bgrx.as_ptr(), scaler.a.as_ptr());
        assert!(scaler.out.is_empty(), "no bilinear pass and no crop");
    }

    /// Monitor design §5.1: "All screens" of two 3840×2160 screens under
    /// the codec's own cap is exactly one box pass to 3840×1080 and
    /// nothing else: no bilinear pass and no crop, and the picture is that
    /// pass's buffer.
    #[test]
    fn fit_halves_two_4k_screens_to_the_codec_cap_in_one_box_pass() {
        let mut scaler = Scaler::default();
        let src = picture(7680, 2160, |x, y| {
            [(x / 30) as u8, (y * 7) as u8, (x ^ y) as u8]
        });
        let mut want = Vec::new();
        assert_eq!(halve(&src, 7680, 2160, 7680 * 4, &mut want), (3840, 1080));
        let fitted = scaler.fit(&src, 7680, 2160, ResolutionCap::CODEC).unwrap();
        assert_eq!(
            (fitted.width, fitted.height, fitted.scaled),
            (3840, 1080, true)
        );
        assert!(fitted.bgrx == want.as_slice());
        assert_eq!(fitted.bgrx.as_ptr(), scaler.a.as_ptr());
        assert!(
            scaler.b.is_empty() && scaler.out.is_empty(),
            "one pass only"
        );
    }

    /// Monitor design §5.1: "All screens" of two 2560×1440 screens under the
    /// codec's cap is 4:3, under 2:1 either way, so no box pass runs: the
    /// one bilinear pass reads the input's region itself.
    #[test]
    fn fit_scales_two_1440p_screens_to_the_codec_cap_by_bilinear_alone() {
        let mut scaler = Scaler::default();
        let src = picture(5120, 1440, |x, y| {
            [(x / 20) as u8, (y / 6) as u8, (x ^ y) as u8]
        });
        let want = resample(&src, (5120, 1440), (3840, 1080));
        let fitted = scaler.fit(&src, 5120, 1440, ResolutionCap::CODEC).unwrap();
        assert_eq!(
            (fitted.width, fitted.height, fitted.scaled),
            (3840, 1080, true)
        );
        assert!(fitted.bgrx == want.as_slice());
        assert_eq!(fitted.bgrx.as_ptr(), scaler.out.as_ptr());
        assert!(scaler.a.is_empty(), "no box pass");
    }

    /// §8: 5120×2880 to 1920×1080 is a box pass (to 2560×1440), then one
    /// bilinear pass.
    #[test]
    fn fit_scales_5k_by_a_box_pass_then_bilinear() {
        let mut scaler = Scaler::default();
        let src = picture(5120, 2880, |x, y| {
            [(x / 7) as u8, (y / 5) as u8, (x ^ y) as u8]
        });
        let mut half = Vec::new();
        assert_eq!(halve(&src, 5120, 2880, 5120 * 4, &mut half), (2560, 1440));
        let want = resample(&half, (2560, 1440), (1920, 1080));
        let fitted = scaler.fit(&src, 5120, 2880, BALANCED).unwrap();
        assert_eq!(
            (fitted.width, fitted.height, fitted.scaled),
            (1920, 1080, true)
        );
        assert!(fitted.bgrx == want.as_slice());
        assert_eq!(fitted.bgrx.as_ptr(), scaler.out.as_ptr());
    }

    /// Two box passes, alternating buffers, end in the second; a third size
    /// then needs a bilinear pass after them.
    #[test]
    fn fit_runs_as_many_box_passes_as_fit() {
        let mut scaler = Scaler::default();
        let src = picture(3840, 2160, |x, y| [(x / 3) as u8, (y / 9) as u8, 1]);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        halve(&src, 3840, 2160, 3840 * 4, &mut a);
        assert_eq!(halve(&a, 1920, 1080, 1920 * 4, &mut b), (960, 540));
        let quarter = ResolutionCap::new(960, 540);
        let fitted = scaler.fit(&src, 3840, 2160, quarter).unwrap();
        assert_eq!((fitted.width, fitted.height), (960, 540));
        assert!(fitted.bgrx == b.as_slice());
        assert_eq!(fitted.bgrx.as_ptr(), scaler.b.as_ptr());

        let want = resample(&b, (960, 540), (640, 360));
        let fitted = scaler
            .fit(&src, 3840, 2160, ResolutionCap::new(640, 360))
            .unwrap();
        assert_eq!((fitted.width, fitted.height), (640, 360));
        assert!(fitted.bgrx == want.as_slice());
    }

    /// An odd desktop is scaled from its shown region, read with the input's
    /// own row length: the odd last column and row never reach the picture.
    #[test]
    fn fit_scales_an_odd_desktop_from_its_shown_region() {
        let mut scaler = Scaler::default();
        // The odd column and row are white; the region is a dark ramp.
        let src = picture(2561, 1441, |x, y| {
            if x == 2560 || y == 1440 {
                [255, 255, 255]
            } else {
                [(x / 20) as u8, (y / 12) as u8, 0]
            }
        });
        let mut region = Vec::new();
        crop_even(&src, 2561, 1441, &mut region);
        let want = resample(&region, (2560, 1440), (1920, 1080));
        let fitted = scaler.fit(&src, 2561, 1441, BALANCED).unwrap();
        assert_eq!((fitted.width, fitted.height), (1920, 1080));
        assert!(fitted.bgrx == want.as_slice());
        assert!(
            fitted
                .bgrx
                .chunks_exact(4)
                .all(|p| p[0] < 128 && p[1] < 128 && p[2] == 0)
        );
    }

    /// An upright desktop keeps its orientation: 1080×1920 under Best
    /// performance is a 720×1280 picture.
    #[test]
    fn fit_keeps_a_portrait_desktop_upright() {
        let mut scaler = Scaler::default();
        let src = picture(1080, 1920, |_, _| [3, 2, 1]);
        let fitted = scaler.fit(&src, 1080, 1920, PERFORMANCE).unwrap();
        assert_eq!(
            (fitted.width, fitted.height, fitted.scaled),
            (720, 1280, true)
        );
        assert!(fitted.bgrx.chunks_exact(4).all(|p| p == [3, 2, 1, 255]));
    }

    /// A steady stream reuses the scaler's buffers and tables.
    #[test]
    fn fit_reuses_its_buffers() {
        let mut scaler = Scaler::default();
        let src = picture(2560, 1440, |x, y| [x as u8, y as u8, 0]);
        let first = scaler
            .fit(&src, 2560, 1440, BALANCED)
            .unwrap()
            .bgrx
            .as_ptr();
        let table = scaler.xt.idx.as_ptr();
        let again = scaler
            .fit(&src, 2560, 1440, BALANCED)
            .unwrap()
            .bgrx
            .as_ptr();
        assert_eq!(first, again);
        assert_eq!(table, scaler.xt.idx.as_ptr());
    }

    /// §8: a buffer of the wrong length is `Geometry`; a region under 2×2
    /// is `PictureSize`.
    #[test]
    fn fit_refuses_bad_input() {
        let mut scaler = Scaler::default();
        assert!(matches!(
            scaler.fit(&[0; 15], 2, 2, BALANCED),
            Err(CodecError::Geometry {
                got: 15,
                want: 16,
                w: 2,
                h: 2
            })
        ));
        assert!(matches!(
            scaler.fit(&[], u32::MAX, u32::MAX, BALANCED),
            Err(CodecError::Geometry { got: 0, .. })
        ));
        for (w, h) in [(1, 9), (9, 1), (0, 0), (1, 1)] {
            let src = vec![0; (w * h * 4) as usize];
            assert!(
                matches!(
                    scaler.fit(&src, w, h, BALANCED),
                    Err(CodecError::PictureSize { .. })
                ),
                "{w}x{h}"
            );
        }
        let fitted = scaler.fit(&[9; 2 * 3 * 4], 2, 3, BALANCED).unwrap();
        assert_eq!((fitted.width, fitted.height), (2, 2));
    }
}
