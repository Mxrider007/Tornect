//! Drawing a cursor image into a captured picture (the X11 grab has none; GDI
//! draws its own with `DrawIconEx`).

/// A cursor picture placed on the screen.
#[derive(Clone, Copy)]
pub(crate) struct CursorImage<'a> {
    /// Premultiplied-alpha ARGB, one `u32` per pixel (the XFIXES / Render format).
    pub pixels: &'a [u32],
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// The image's top-left corner on the picture (it may lie partly or wholly off it).
    pub x: i32,
    /// See `x`.
    pub y: i32,
}

/// Blend `cursor` into a `width`×`height` BGRx picture.
pub(crate) fn blend(frame: &mut [u8], width: u32, height: u32, cursor: &CursorImage<'_>) {
    let CursorImage {
        pixels,
        width: cw,
        height: ch,
        x,
        y,
    } = *cursor;
    if pixels.len() < (cw as usize) * (ch as usize) || frame.len() < (width * height * 4) as usize {
        return;
    }
    for cy in 0..ch as i32 {
        let fy = y + cy;
        if fy < 0 || fy >= height as i32 {
            continue;
        }
        for cx in 0..cw as i32 {
            let fx = x + cx;
            if fx < 0 || fx >= width as i32 {
                continue;
            }
            let argb = pixels[(cy as usize) * (cw as usize) + cx as usize];
            let alpha = argb >> 24;
            if alpha == 0 {
                continue;
            }
            let i = ((fy as usize) * (width as usize) + fx as usize) * 4;
            let inv = 255 - alpha;
            for (channel, shift) in [(0, 0), (1, 8), (2, 16)] {
                let src = (argb >> shift) & 0xff;
                let dst = u32::from(frame[i + channel]);
                // src is premultiplied: out = src + dst × (1 − α), rounded.
                frame[i + channel] = (src + (dst * inv + 127) / 255).min(255) as u8;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
mod tests {
    use super::*;

    fn picture(w: u32, h: u32, bgr: [u8; 3]) -> Vec<u8> {
        (0..w * h)
            .flat_map(|_| [bgr[0], bgr[1], bgr[2], 255])
            .collect()
    }

    fn put(px: &mut [u8], w: u32, h: u32, pixels: &[u32], cw: u32, ch: u32, x: i32, y: i32) {
        let image = CursorImage {
            pixels,
            width: cw,
            height: ch,
            x,
            y,
        };
        blend(px, w, h, &image);
    }

    fn at(px: &[u8], w: u32, x: u32, y: u32) -> [u8; 3] {
        let i = ((y * w + x) * 4) as usize;
        [px[i], px[i + 1], px[i + 2]]
    }

    #[test]
    fn opaque_transparent_and_half_pixels() {
        let mut px = picture(4, 4, [100, 100, 100]);
        // 2×1 cursor: opaque red, fully transparent.
        put(&mut px, 4, 4, &[0xFFFF_0000, 0x0000_0000], 2, 1, 1, 1);
        assert_eq!(at(&px, 4, 1, 1), [0, 0, 255], "opaque replaces (BGR order)");
        assert_eq!(at(&px, 4, 2, 1), [100, 100, 100], "transparent leaves");
        // Half-transparent white, premultiplied: 0x80 alpha, 0x80 channels.
        put(&mut px, 4, 4, &[0x8080_8080], 1, 1, 0, 0);
        assert_eq!(at(&px, 4, 0, 0), [178, 178, 178]);
    }

    #[test]
    fn the_cursor_is_clipped_at_every_edge() {
        let mut px = picture(3, 3, [0, 0, 0]);
        let white = [0xFFFF_FFFF; 4];
        for (x, y) in [(-1, -1), (2, 2), (-5, 0), (3, 3), (i32::MIN / 2, 0)] {
            put(&mut px, 3, 3, &white, 2, 2, x, y);
        }
        assert_eq!(at(&px, 3, 0, 0), [255, 255, 255]);
        assert_eq!(at(&px, 3, 2, 2), [255, 255, 255]);
        assert_eq!(at(&px, 3, 1, 1), [0, 0, 0]);
        assert_eq!(at(&px, 3, 2, 0), [0, 0, 0]);
        // A short image buffer is ignored rather than read out of bounds.
        put(&mut px, 3, 3, &white[..1], 2, 2, 1, 1);
        assert_eq!(at(&px, 3, 1, 1), [0, 0, 0]);
    }
}
