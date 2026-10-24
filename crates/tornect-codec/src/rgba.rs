//! The viewer's I420 → RGBA conversion for a picture whose width is not a
//! multiple of 8.
//!
//! `openh264`'s `write_rgba8` converts eight pixels at a time (AVX2, or its
//! portable `wide` path) only when the width is a multiple of 8; any other
//! width takes its scalar loop, whose `f32::mul_add` per channel is a libm
//! call on a CPU target without FMA: 12–19× slower, enough for a viewer of an
//! unscaled 3538-wide desktop to fall behind the host (the quality design's
//! demo, `docs/notes/m1-media-evidence.md`). Its SIMD routine is private to
//! the crate and cannot take part of a picture, so such widths come here.
//!
//! The same limited-range BT.601 as `openh264` (its `yuv2rgb.rs`
//! constants), in Q20 fixed point: each coefficient is within 0.5/2²⁰ of
//! the float one, so a channel differs from `openh264`'s by at most 1, and
//! only where its value lies within about 0.0003 of a whole number (590 of the
//! 2²⁴ colours; black and white come out exactly). Eight pixels (four
//! chroma samples) are converted per step through fixed-size arrays, which
//! the compiler vectorizes; the last `width % 8` columns of each row are
//! converted one by one.

/// Bits of fraction in the coefficients. The largest sum,
/// `239·Y_MUL + 127·BU_MUL`, is about 2²⁹: no `i32` overflows.
const Q: u32 = 20;
/// `255 / 219` (luma's limited range spread over 0..=255).
const Y_MUL: i32 = 1_220_945;
/// `255 / 224 · 1.402`, red from V.
const RV_MUL: i32 = 1_673_555;
/// `−255 / 224 · 1.402 · 0.299 / 0.587`, green from V.
const GV_MUL: i32 = -852_458;
/// `−255 / 224 · 1.772 · 0.114 / 0.587`, green from U.
const GU_MUL: i32 = -410_793;
/// `255 / 224 · 1.772`, blue from U.
const BU_MUL: i32 = 2_115_221;

/// Writes the `w`×`h` I420 picture of planes `y`, `u`, `v` (rows `strides`
/// apart; chroma at half resolution, rounded up) into `out` as tightly
/// packed RGBA, alpha 255. `false`, with `out` untouched, when the planes or
/// `out` are too short for that geometry: the caller converts another way.
pub(crate) fn write_rgba8(
    (y, u, v): (&[u8], &[u8], &[u8]),
    (w, h): (usize, usize),
    (sy, su, sv): (usize, usize, usize),
    out: &mut [u8],
) -> bool {
    if w == 0 || h == 0 {
        return out.is_empty();
    }
    let cw = w.div_ceil(2);
    let (last, last_chroma) = (h - 1, (h - 1) / 2);
    let fits = |plane: &[u8], stride: usize, row: usize, width: usize| {
        stride >= width
            && row
                .checked_mul(stride)
                .and_then(|at| at.checked_add(width))
                .is_some_and(|end| end <= plane.len())
    };
    if !(fits(y, sy, last, w) && fits(u, su, last_chroma, cw) && fits(v, sv, last_chroma, cw))
        || w.checked_mul(h).and_then(|n| n.checked_mul(4)) != Some(out.len())
    {
        return false;
    }
    let head = w & !7;
    for (row, rgba) in out.chunks_exact_mut(w * 4).enumerate() {
        let luma = &y[row * sy..][..w];
        let (cb, cr) = (&u[(row / 2) * su..][..cw], &v[(row / 2) * sv..][..cw]);
        let (luma8, luma_tail) = luma.as_chunks::<8>();
        let (rgba8, rgba_tail) = rgba.as_chunks_mut::<32>();
        for (((y8, u4), v4), px) in luma8
            .iter()
            .zip(cb.as_chunks::<4>().0)
            .zip(cr.as_chunks::<4>().0)
            .zip(rgba8)
        {
            eight(y8, u4, v4, px);
        }
        for ((x, &luma), px) in (head..w)
            .zip(luma_tail)
            .zip(rgba_tail.as_chunks_mut::<4>().0)
        {
            *px = pixel(luma, cb[x / 2], cr[x / 2]).to_le_bytes();
        }
    }
    true
}

/// Eight pixels: `y8` their luma, `u4` and `v4` the chroma each pair
/// shares, `px` their RGBA.
#[inline(always)]
fn eight(y8: &[u8; 8], u4: &[u8; 4], v4: &[u8; 4], px: &mut [u8; 32]) {
    let mut words = [0u32; 8];
    for (i, word) in words.iter_mut().enumerate() {
        *word = pixel(y8[i], u4[i / 2], v4[i / 2]);
    }
    for (out, word) in px.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *out = word.to_le_bytes();
    }
}

/// One pixel as little-endian RGBA, alpha 255.
#[inline(always)]
fn pixel(y: u8, u: u8, v: u8) -> u32 {
    let c = (i32::from(y) - 16) * Y_MUL;
    let d = i32::from(u) - 128;
    let e = i32::from(v) - 128;
    channel(c + RV_MUL * e)
        | channel(c + GU_MUL * d + GV_MUL * e) << 8
        | channel(c + BU_MUL * d) << 16
        | 0xff00_0000
}

/// A Q20 channel floored and held to 0..=255, as `openh264` clamps a value
/// and truncates it.
#[inline(always)]
fn channel(v: i32) -> u32 {
    (v >> Q).clamp(0, 255).unsigned_abs()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `openh264` 0.9.8's scalar conversion of one pixel, verbatim
    /// (`formats/yuv2rgb.rs`, `write_yuv420_float`).
    fn reference(y: u8, u: u8, v: u8) -> [u8; 4] {
        const Y_MUL: f32 = 255.0 / 219.0;
        const RV_MUL: f32 = 255.0 / 224.0 * 1.402;
        const GV_MUL: f32 = -255.0 / 224.0 * 1.402 * 0.299 / 0.587;
        const GU_MUL: f32 = -255.0 / 224.0 * 1.772 * 0.114 / 0.587;
        const BU_MUL: f32 = 255.0 / 224.0 * 1.772;
        #[expect(clippy::cast_possible_truncation, reason = "the reference's own cast")]
        #[expect(clippy::cast_sign_loss, reason = "the reference's own cast")]
        fn to_u8(value: f32) -> u8 {
            value.clamp(0.0, 255.0) as u8
        }
        let y_value = Y_MUL * (f32::from(y) - 16.0);
        let (u_value, v_value) = (f32::from(u) - 128.0, f32::from(v) - 128.0);
        [
            to_u8(RV_MUL.mul_add(v_value, y_value)),
            to_u8(GV_MUL.mul_add(v_value, GU_MUL.mul_add(u_value, y_value))),
            to_u8(BU_MUL.mul_add(u_value, y_value)),
            255,
        ]
    }

    fn within_one(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.abs_diff(*y) <= 1)
    }

    /// Every (Y, U, V) at once: each channel within 1 of `openh264`'s, and
    /// equal for nearly all of them; alpha always 255. The extremes (black,
    /// white, out of range) come out exactly.
    #[test]
    fn every_colour_is_within_one_of_openh264s() {
        let (mut differ, mut total) = (0u64, 0u64);
        for y in 0..=255u8 {
            for u in 0..=255u8 {
                for v in 0..=255u8 {
                    let px = pixel(y, u, v).to_le_bytes();
                    let want = reference(y, u, v);
                    assert!(within_one(&px, &want), "{y} {u} {v}: {px:?} {want:?}");
                    differ += u64::from(px != want);
                    total += 1;
                }
            }
        }
        assert!(differ * 10_000 < total, "{differ} of {total} differ by one");
        for (yuv, rgba) in [
            ((16, 128, 128), [0, 0, 0, 255]),
            ((235, 128, 128), [255, 255, 255, 255]),
            ((0, 0, 0), [0, 135, 0, 255]),
            ((255, 255, 255), [255, 125, 255, 255]),
        ] {
            assert_eq!(pixel(yuv.0, yuv.1, yuv.2).to_le_bytes(), rgba, "{yuv:?}");
            assert_eq!(reference(yuv.0, yuv.1, yuv.2), rgba, "{yuv:?}");
        }
    }

    /// Planes of noise for a `w`×`h` picture, rows `pad` bytes wider than
    /// needed.
    fn planes(w: usize, h: usize, pad: usize, mut seed: u64) -> [(Vec<u8>, usize); 3] {
        let mut noise = |len: usize| {
            (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed.to_le_bytes()[0]
                })
                .collect::<Vec<u8>>()
        };
        let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
        [
            (noise((w + pad) * h), w + pad),
            (noise((cw + pad) * ch), cw + pad),
            (noise((cw + pad) * ch), cw + pad),
        ]
    }

    /// Each pixel converted from its own luma and its pair's chroma.
    fn per_pixel(planes: &[(Vec<u8>, usize); 3], w: usize, h: usize) -> Vec<u8> {
        let [(y, sy), (u, su), (v, sv)] = planes;
        let mut out = vec![0; w * h * 4];
        for row in 0..h {
            for x in 0..w {
                let at = (row * w + x) * 4;
                out[at..at + 4].copy_from_slice(&reference(
                    y[row * sy + x],
                    u[(row / 2) * su + x / 2],
                    v[(row / 2) * sv + x / 2],
                ));
            }
        }
        out
    }

    /// Widths on either side of a multiple of 8, odd ones included, and
    /// padded strides: the eight-at-a-time steps and the tail each land on
    /// their own pixels.
    #[test]
    fn any_width_converts_each_pixel_from_its_own_samples() {
        for (w, h, pad) in [
            (1, 1, 0),
            (2, 2, 0),
            (7, 3, 1),
            (8, 2, 0),
            (9, 2, 5),
            (15, 4, 0),
            (16, 4, 3),
            (17, 5, 16),
            (1366, 6, 0),
            (1366, 6, 34),
            (3538, 4, 46),
        ] {
            let planes = planes(w, h, pad, 0x9e37_79b9_7f4a_7c15 ^ (w * 31 + h) as u64);
            let mut out = vec![7; w * h * 4];
            let [(y, sy), (u, su), (v, sv)] = &planes;
            assert!(write_rgba8((y, u, v), (w, h), (*sy, *su, *sv), &mut out));
            assert!(
                within_one(&out, &per_pixel(&planes, w, h)),
                "{w}x{h} pad {pad}"
            );
        }
    }

    /// Too short a plane or a wrong output length is refused before a byte
    /// is written; an empty picture is a no-op.
    #[test]
    fn short_planes_are_refused_untouched() {
        let (w, h) = (10, 4);
        let planes = planes(w, h, 0, 1);
        let [(y, sy), (u, su), (v, sv)] = &planes;
        let strides = (*sy, *su, *sv);
        let mut out = vec![7; w * h * 4];
        for (y, u, v) in [
            (&y[..y.len() - 1], &u[..], &v[..]),
            (&y[..], &u[..u.len() - 1], &v[..]),
            (&y[..], &u[..], &v[..v.len() - 1]),
        ] {
            assert!(!write_rgba8((y, u, v), (w, h), strides, &mut out));
            assert!(out.iter().all(|&b| b == 7));
        }
        assert!(!write_rgba8((y, u, v), (w, h), (w - 1, *su, *sv), &mut out));
        assert!(!write_rgba8((y, u, v), (w, h), (*sy, 4, *sv), &mut out));
        assert!(!write_rgba8((y, u, v), (w, h), strides, &mut out[4..]));
        assert!(!write_rgba8(
            (y, u, v),
            (w, h),
            (usize::MAX, *su, *sv),
            &mut out
        ));
        assert!(out.iter().all(|&b| b == 7));
        assert!(write_rgba8((y, u, v), (0, h), strides, &mut []));
        assert!(write_rgba8((y, u, v), (w, 0), strides, &mut []));
    }
}
