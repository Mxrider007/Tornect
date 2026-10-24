//! Tornect video codecs (`docs/PLAN.md` §B.5, decision M0-5): OpenH264 built
//! from source, always compiled in — the codec every host and viewer shares.
//!
//! The host fits each desktop into a picture the codec takes (even sides, at
//! most 3840×2160 either way up) with [`scale::Scaler`], then feeds that
//! tightly packed BGRx/BGRA picture to [`H264Encoder::encode`], which crops
//! nothing. The viewer gets RGBA back ([`H264Decoder::decode`]). Both
//! converters are BT.601 limited range, so the stream is tagged BT.601 (media
//! research §2.3).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::time::{Duration, Instant};

use openh264::OpenH264API;
use openh264::decoder::Decoder;
use openh264::encoder::{
    BitRate, Complexity, Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod, QpRange,
    RateControlMode, UsageType, VuiConfig,
};
use openh264::formats::{BgraSliceU8, YUVBuffer, YUVSource as _};

pub mod scale;

/// The longest side OpenH264 encodes: 3840 wide, or 3840 tall when the
/// picture stands upright (level 5.2, `openh264` 0.9.8 `Encoder::reinit`).
pub const MAX_LONG_SIDE: u32 = 3840;
/// The shortest side OpenH264 encodes: 2160, across either axis.
pub const MAX_SHORT_SIDE: u32 = 2160;

/// The most encoder threads: OpenH264's `MAX_THREADS_NUM` (`wels_const.h:69`),
/// to which it clips any larger count.
pub const MAX_ENCODER_THREADS: u16 = 4;

/// The largest slice when the encoder runs threads, in bytes: far above
/// OpenH264's floor of 420 (`encoder_ext.cpp:626`), and with its 35 slices a
/// picture at most 8.75 MiB.
const SLICE_BYTES: u32 = 256 * 1024;

/// The quantizer range OpenH264 keeps as given: it raises a minimum below 12
/// (`GOM_MIN_QP_MODE`) and holds both ends to 51 (`encoder_ext.cpp:389-390`).
const QP_FLOOR: u8 = 12;
const QP_CEILING: u8 = 51;

/// Codec failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CodecError {
    /// OpenH264 refused the configuration or a frame.
    #[error("H.264: {0}")]
    H264(String),
    /// The frame's buffer does not match its stated geometry.
    #[error("frame is {got} bytes, expected {want} for {w}x{h} BGRx")]
    Geometry {
        /// Bytes received.
        got: usize,
        /// Bytes expected.
        want: usize,
        /// Width.
        w: u32,
        /// Height.
        h: u32,
    },
    /// A picture of a size the codec does not take: odd sides, under 2×2, or
    /// above 3840×2160 either way up.
    #[error("a {w}x{h} picture cannot be coded here (even sides, at most 3840x2160 either way up)")]
    PictureSize {
        /// Width.
        w: u32,
        /// Height.
        h: u32,
    },
}

fn h264(e: impl std::fmt::Display) -> CodecError {
    CodecError::H264(e.to_string())
}

/// Encoder settings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EncoderSettings {
    /// Target bitrate, bits per second.
    pub bitrate_bps: u32,
    /// Frame-rate cap the rate control plans for.
    pub max_fps: f32,
    /// The quantizer range `(min, max)`, sharper to smaller pictures. `None`
    /// keeps OpenH264's own, 26 to 35 for screen content. Each end is held to
    /// 12..=51 and `min` to at most `max`, the range OpenH264 keeps as given.
    pub qp: Option<(u8, u8)>,
    /// Encoder threads: 1 is one thread; 0 picks from this machine's cores
    /// (one fewer than it has, 1 to 4); 2 to 4 is that many, and more is 4.
    pub threads: u16,
}

impl Default for EncoderSettings {
    /// Sized for a Tor circuit: ~1.5 Mbit/s at 15 fps, OpenH264's own
    /// quantizer range, one thread.
    fn default() -> Self {
        Self {
            bitrate_bps: 1_500_000,
            max_fps: 15.0,
            qp: None,
            threads: 1,
        }
    }
}

/// One encoded access unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    /// Annex-B H.264.
    pub data: Vec<u8>,
    /// Starts with an IDR picture.
    pub keyframe: bool,
    /// What the BGRx → I420 conversion took.
    pub convert: Duration,
    /// What OpenH264's encode took.
    pub encode: Duration,
}

/// OpenH264 encoder for screen content (`SCREEN_CONTENT_REAL_TIME`).
pub struct H264Encoder {
    /// Kept to build a new encoder for each new picture size.
    cfg: EncoderConfig,
    enc: Encoder,
    /// The size `enc` was last asked to encode; `None` before that.
    size: Option<(u32, u32)>,
    /// The I420 picture, reused while the size holds.
    yuv: Option<YUVBuffer>,
}

impl std::fmt::Debug for H264Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H264Encoder")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// `(min, max)` held to the range OpenH264 keeps as given: `max` to 12..=51,
/// then `min` to 12..=`max`. `QpRange::new` asserts `max ≤ 51` and
/// `min ≤ max` (`openh264` 0.9.8 `encoder.rs:366-367`), which this always
/// meets; and since OpenH264 replaces a minimum of 0 or less with its
/// screen-content range (`encoder_ext.cpp:375-381`) and raises one below 12
/// (`:389`), a held range reaches it unchanged.
fn qp_range(min: u8, max: u8) -> (u8, u8) {
    let max = max.clamp(QP_FLOOR, QP_CEILING);
    (min.clamp(QP_FLOOR, max), max)
}

/// The encoder threads `threads` asks for on this machine
/// ([`EncoderSettings::threads`]).
fn encoder_threads(threads: u16) -> u16 {
    let n = if threads == 0 {
        std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1))
    } else {
        usize::from(threads)
    };
    u16::try_from(n.clamp(1, usize::from(MAX_ENCODER_THREADS))).unwrap_or(1)
}

/// OpenH264's configuration for `settings`.
fn config(settings: &EncoderSettings) -> EncoderConfig {
    let cfg = EncoderConfig::new()
        .bitrate(BitRate::from_bps(settings.bitrate_bps))
        .max_frame_rate(FrameRate::from_hz(settings.max_fps))
        .usage_type(UsageType::ScreenContentRealTime)
        .rate_control_mode(RateControlMode::Bitrate)
        .skip_frames(false)
        .intra_frame_period(IntraFramePeriod::from_num_frames(0))
        .adaptive_quantization(false)
        .background_detection(false)
        .complexity(Complexity::Low)
        .vui(VuiConfig::bt601());
    // Without a range the config keeps `EncoderConfig::new`'s 0..=51, which
    // OpenH264 replaces with 26..=35 for screen content.
    let cfg = match settings.qp {
        Some((min, max)) => {
            let (min, max) = qp_range(min, max);
            cfg.qp(QpRange::new(min, max))
        }
        None => cfg,
    };
    match encoder_threads(settings.threads) {
        1 => cfg.num_threads(1),
        // `num_threads` alone is a no-op. Without `max_slice_len` the crate
        // sets `SM_SINGLE_SLICE`/`uiSliceNum = 1` (`openh264` 0.9.8
        // `encoder.rs:1024`), and OpenH264 sets `iMultipleThreadIdc =
        // min(cores, slices) = 1` (`encoder_ext.cpp:2058`). Size-limited
        // slices give one partition per thread (`:2417-2418`, at most
        // `MAX_THREADS_NUM` = 4) and at most `MAX_SLICES_NUM` = 35 slices
        // (`svc_enc_slice_segment.h:62`); `uiMaxNalSize` must be at least 420
        // (`:626`). With threads the loop filter skips slice edges (idc 2,
        // `:2059-2061`), and rate control drops GOM (macroblock-row) QP for
        // more than one slice (`ratectl.cpp:1199-1202`): QP becomes per
        // picture.
        n => cfg.num_threads(n).max_slice_len(SLICE_BYTES),
    }
}

/// Whether the codec takes a `w`×`h` picture: even sides of at least 2, at
/// most 3840×2160 either way up.
fn codes(w: u32, h: u32) -> bool {
    w >= 2
        && h >= 2
        && w.is_multiple_of(2)
        && h.is_multiple_of(2)
        && w.max(h) <= MAX_LONG_SIDE
        && w.min(h) <= MAX_SHORT_SIDE
}

impl H264Encoder {
    /// A new encoder; [`scale::Scaler::fit`] makes the pictures it takes.
    pub fn new(settings: EncoderSettings) -> Result<Self, CodecError> {
        let cfg = config(&settings);
        let enc = Encoder::with_api_config(OpenH264API::from_source(), cfg).map_err(h264)?;
        Ok(Self {
            cfg,
            enc,
            size: None,
            yuv: None,
        })
    }

    /// Make the next access unit an IDR (viewer joined or lost sync).
    pub fn force_keyframe(&mut self) {
        self.enc.force_intra_frame();
    }

    /// Encode one tightly packed `w`×`h` BGRx picture. The first picture,
    /// and the first after a size change, comes from a new OpenH264 encoder
    /// and is an IDR; the crate's re-initialisation in place is never used.
    /// The I420 buffer is reused while the size holds.
    ///
    /// # Errors
    /// [`CodecError::PictureSize`] unless the sides are even, at least 2 and
    /// at most 3840×2160 either way up (nothing is cropped here: the caller
    /// fits the picture first); [`CodecError::Geometry`] if `bgrx` is not
    /// `w`·`h`·4 bytes; [`CodecError::H264`] if OpenH264 fails.
    pub fn encode(&mut self, bgrx: &[u8], w: u32, h: u32) -> Result<EncodedFrame, CodecError> {
        if !codes(w, h) {
            return Err(CodecError::PictureSize { w, h });
        }
        let (uw, uh) = (w as usize, h as usize);
        let want = uw * uh * 4;
        if bgrx.len() != want {
            return Err(CodecError::Geometry {
                got: bgrx.len(),
                want,
                w,
                h,
            });
        }
        if self.size.is_some_and(|size| size != (w, h)) {
            self.enc =
                Encoder::with_api_config(OpenH264API::from_source(), self.cfg).map_err(h264)?;
        }
        // Set before the encode, so that a failed one still leads to a new
        // encoder for any other size.
        self.size = Some((w, h));
        let start = Instant::now();
        if self
            .yuv
            .as_ref()
            .is_none_or(|yuv| yuv.dimensions() != (uw, uh))
        {
            self.yuv = Some(YUVBuffer::new(uw, uh));
        }
        let yuv = self.yuv.get_or_insert_with(|| YUVBuffer::new(uw, uh));
        yuv.read_bgra8(BgraSliceU8::new(bgrx, (uw, uh)));
        let converted = Instant::now();
        let bs = self.enc.encode(&*yuv).map_err(h264)?;
        let encode = converted.elapsed();
        Ok(EncodedFrame {
            data: bs.to_vec(),
            keyframe: matches!(bs.frame_type(), FrameType::IDR | FrameType::I),
            convert: converted - start,
            encode,
        })
    }

    /// The size of the last picture asked for; (0, 0) before the first.
    #[must_use]
    pub fn size(&self) -> (u32, u32) {
        self.size.unwrap_or((0, 0))
    }

    /// Where the I420 buffer's luma plane lives, to check its reuse.
    #[cfg(test)]
    fn yuv_at(&self) -> Option<*const u8> {
        self.yuv.as_ref().map(|yuv| yuv.y().as_ptr())
    }
}

/// A decoded picture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    /// Width.
    pub width: u32,
    /// Height.
    pub height: u32,
    /// Tightly packed RGBA (alpha 255).
    pub rgba: Vec<u8>,
}

/// OpenH264 decoder.
pub struct H264Decoder {
    dec: Decoder,
}

impl std::fmt::Debug for H264Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("H264Decoder")
    }
}

impl H264Decoder {
    /// A new decoder (no decoder threads: the API is unsafe with them).
    pub fn new() -> Result<Self, CodecError> {
        Ok(Self {
            dec: Decoder::new().map_err(h264)?,
        })
    }

    /// Decode one access unit; `None` while the decoder buffers (no picture yet).
    /// An error means the bitstream is corrupt: request a keyframe.
    pub fn decode(&mut self, access_unit: &[u8]) -> Result<Option<DecodedFrame>, CodecError> {
        let Some(yuv) = self.dec.decode(access_unit).map_err(h264)? else {
            return Ok(None);
        };
        let (w, h) = yuv.dimensions();
        let mut rgba = vec![0u8; w * h * 4];
        yuv.write_rgba8(&mut rgba);
        Ok(Some(DecodedFrame {
            width: u32::try_from(w).map_err(h264)?,
            height: u32::try_from(h).map_err(h264)?,
            rgba,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scale::{ResolutionCap, Scaler, picture_size, shown_region};

    /// `tornect_proto::MAX_FRAME`, the largest media frame (this crate does
    /// not see the wire), less a `Video` frame's own fields: the most an
    /// access unit may be.
    const MAX_ACCESS_UNIT: usize = 8 * 1024 * 1024 - 10;

    /// A moving BGRx test card.
    fn card(w: u32, h: u32, t: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                let bar = ((x + t * 7) / 32) % 3;
                let (b, g, r) = match bar {
                    0 => (40, 200, 40),
                    1 => (200, 40, 40),
                    _ => ((y % 256) as u8, (x % 256) as u8, 128),
                };
                out.extend_from_slice(&[b, g, r, 255]);
            }
        }
        out
    }

    /// Height of the band [`stamp`] paints.
    const BAND: u32 = 32;

    /// Paints `index` into the bottom [`BAND`] rows of a BGRx picture, as 32
    /// equal bars, most significant bit first: white for 1, black for 0.
    fn stamp(bgrx: &mut [u8], w: u32, h: u32, index: u32) {
        let bar = w / 32;
        for y in h - BAND..h {
            for x in 0..w {
                let bit = (x / bar).min(31);
                let v = if index >> (31 - bit) & 1 == 1 { 255 } else { 0 };
                let at = ((y * w + x) * 4) as usize;
                bgrx[at..at + 3].fill(v);
            }
        }
    }

    /// Reads back what [`stamp`] painted, from a decoded RGBA picture.
    fn read_stamp(rgba: &[u8], w: u32, h: u32) -> u32 {
        let bar = w / 32;
        let y = h - BAND / 2;
        (0..32).fold(0, |index, bit| {
            let x = bit * bar + bar / 2;
            let at = ((y * w + x) * 4 + 1) as usize;
            index << 1 | u32::from(rgba[at] > 128)
        })
    }

    /// Bytes no encoder can predict, X = 255.
    fn noise(w: u32, h: u32, mut seed: u64) -> Vec<u8> {
        let mut out = vec![255u8; (w * h * 4) as usize];
        for px in out.chunks_exact_mut(4) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            px[..3].copy_from_slice(&seed.to_le_bytes()[..3]);
        }
        out
    }

    #[test]
    fn encode_then_decode_round_trips_geometry_and_colour() {
        let (w, h) = (320, 240);
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        let mut dec = H264Decoder::new().unwrap();
        let mut decoded = None;
        for t in 0..5 {
            let au = enc.encode(&card(w, h, t), w, h).unwrap();
            if t == 0 {
                assert!(au.keyframe, "first access unit must be a keyframe");
            }
            assert!(!au.data.is_empty());
            if let Some(frame) = dec.decode(&au.data).unwrap() {
                decoded = Some(frame);
            }
        }
        let frame = decoded.expect("decoder produced a picture");
        assert_eq!((frame.width, frame.height), (w, h));
        assert_eq!(frame.rgba.len(), (w * h * 4) as usize);
        // The last picture is t = 4, where x = 4 falls in bar 1: BGRx
        // (200, 40, 40), i.e. blue. It must come back blue in RGBA, which also
        // proves the channel order through both converters.
        let px = &frame.rgba[(10 * w as usize + 4) * 4..][..4];
        assert!(px[2] > px[0] + 100 && px[2] > px[1] + 100, "{px:?}");
        assert_eq!(px[3], 255);
    }

    #[test]
    fn forced_keyframes_happen() {
        let (w, h) = (320, 240);
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        assert!(enc.encode(&card(w, h, 0), w, h).unwrap().keyframe);
        let p = enc.encode(&card(w, h, 1), w, h).unwrap();
        assert!(!p.keyframe);
        enc.force_keyframe();
        let k = enc.encode(&card(w, h, 2), w, h).unwrap();
        assert!(k.keyframe);
        assert!(!enc.encode(&card(w, h, 3), w, h).unwrap().keyframe);
    }

    /// Nothing is cropped inside the encoder any more: a size the codec does
    /// not take is refused, never cut down, and never allocated for.
    #[test]
    fn pictures_the_codec_cannot_take_are_refused() {
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        for (w, h) in [
            (321, 240),
            (320, 241),
            (1, 1),
            (0, 0),
            (2, 0),
            (0, 2),
            (3842, 2160),
            (3840, 2162),
            (2160, 3842),
            (2162, 3840),
            (4000, 1000),
            (1000, 4000),
            (u32::MAX - 1, 2),
            (u32::MAX - 1, u32::MAX - 1),
        ] {
            assert!(
                matches!(
                    enc.encode(&[0; 64], w, h),
                    Err(CodecError::PictureSize { w: ew, h: eh }) if (ew, eh) == (w, h)
                ),
                "{w}x{h}"
            );
        }
        assert_eq!(enc.size(), (0, 0), "nothing was encoded");
        assert_eq!(
            CodecError::PictureSize { w: 321, h: 240 }.to_string(),
            "a 321x240 picture cannot be coded here (even sides, at most 3840x2160 either way up)"
        );
    }

    #[test]
    fn wrong_buffer_sizes_are_errors() {
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        assert!(matches!(
            enc.encode(&[0; 10], 4, 4),
            Err(CodecError::Geometry {
                got: 10,
                want: 64,
                w: 4,
                h: 4
            })
        ));
        assert!(matches!(
            enc.encode(&[0; 65], 4, 4),
            Err(CodecError::Geometry { .. })
        ));
        let mut dec = H264Decoder::new().unwrap();
        // Garbage is an error or no picture — never a panic.
        let _ = dec.decode(&[0, 0, 0, 1, 0x65, 0xff, 0x00, 0x13]);
    }

    /// An odd desktop is the scaler's job now: fitted, it loses its last
    /// column and row, and the encoder sends the rest.
    #[test]
    fn an_odd_desktop_is_fitted_then_encoded_even() {
        let (w, h) = (321, 241);
        let mut scaler = Scaler::default();
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        let mut dec = H264Decoder::new().unwrap();
        let desktop = card(w, h, 0);
        let fitted = scaler.fit(&desktop, w, h, ResolutionCap::CODEC).unwrap();
        let au = enc
            .encode(fitted.bgrx, fitted.width, fitted.height)
            .unwrap();
        assert_eq!(enc.size(), (320, 240));
        let frame = dec.decode(&au.data).unwrap().expect("a picture");
        assert_eq!((frame.width, frame.height), (320, 240));
    }

    /// The codec's maximum holds in the picture's own orientation: up to
    /// 3840×2160 wide and 2160×3840 upright, so a portrait screen is never
    /// cut at row 2160. Every desktop the encoder's old crop table named
    /// fits, through the scaler, into a size the codec takes.
    #[test]
    fn the_codec_takes_either_orientation_up_to_its_maximum() {
        for ((w, h), want) in [
            ((1920, 1080), (1920, 1080)),
            ((1921, 1081), (1920, 1080)),
            ((7680, 2160), (3840, 1080)),
            ((5120, 2880), (3840, 2160)),
            ((1440, 2560), (1440, 2560)),
            ((2160, 3840), (2160, 3840)),
            ((1081, 2561), (1080, 2560)),
            ((2880, 5120), (2160, 3840)),
            ((2400, 3000), (2160, 2700)),
            ((1080, 7680), (536, 3840)),
            ((3000, 3000), (2160, 2160)),
        ] {
            let size = picture_size(shown_region(w, h), ResolutionCap::CODEC);
            assert_eq!(size, want, "{w}x{h}");
            assert!(codes(size.0, size.1), "{w}x{h} → {size:?}");
        }
        assert!(codes(3840, 2160) && codes(2160, 3840) && codes(2, 2));
        assert!(!codes(3840, 2162) && !codes(2162, 3840) && !codes(3842, 2));
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        let mut dec = H264Decoder::new().unwrap();
        for (i, (w, h)) in [(536, 3840), (3840, 1080), (2160, 3840), (3840, 2160)]
            .into_iter()
            .enumerate()
        {
            let au = enc.encode(&card(w, h, i as u32), w, h).unwrap();
            assert!(au.keyframe, "{w}x{h}: a new size starts with an IDR");
            let frame = dec.decode(&au.data).unwrap().expect("a picture");
            assert_eq!((frame.width, frame.height), (w, h));
        }
    }

    /// An upright picture taller than 2160 rows is encoded and decoded
    /// whole, and the largest upright picture is one OpenH264 takes.
    #[test]
    fn a_portrait_picture_is_encoded_whole() {
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        let mut dec = H264Decoder::new().unwrap();
        let (w, h) = (1200, 2400);
        let au = enc.encode(&card(w, h, 0), w, h).unwrap();
        assert_eq!(enc.size(), (w, h));
        let frame = dec.decode(&au.data).unwrap().expect("a picture");
        assert_eq!((frame.width, frame.height), (w, h));
        let (w, h) = (2160, 3840);
        let au = enc.encode(&card(w, h, 1), w, h).unwrap();
        assert!(au.keyframe, "a new size starts with an IDR");
        assert_eq!(enc.size(), (w, h));
    }

    /// Every preset's range (quality design §3.1: Best quality 18–32, Best
    /// performance 28–44) reaches OpenH264 as given, and no pair of bytes
    /// can make `QpRange::new` panic.
    #[test]
    fn quantizer_ranges_reach_openh264_unchanged_and_never_panic() {
        assert_eq!(qp_range(18, 32), (18, 32));
        assert_eq!(qp_range(28, 44), (28, 44));
        assert_eq!(qp_range(12, 51), (12, 51));
        assert_eq!(qp_range(0, 0), (12, 12));
        assert_eq!(qp_range(40, 20), (20, 20), "min held to max");
        assert_eq!(qp_range(255, 255), (51, 51));
        for min in 0..=u8::MAX {
            for max in 0..=u8::MAX {
                let (lo, hi) = qp_range(min, max);
                assert!((QP_FLOOR..=QP_CEILING).contains(&lo) && lo <= hi && hi <= QP_CEILING);
                let _ = QpRange::new(lo, hi);
                if (QP_FLOOR..=QP_CEILING).contains(&min) && (min..=QP_CEILING).contains(&max) {
                    assert_eq!((lo, hi), (min, max), "a range OpenH264 keeps is kept");
                }
            }
        }
        // And an encoder with each preset's range encodes.
        for qp in [Some((18, 32)), None, Some((28, 44))] {
            let mut enc = H264Encoder::new(EncoderSettings {
                qp,
                ..EncoderSettings::default()
            })
            .unwrap();
            assert!(enc.encode(&card(320, 240, 0), 320, 240).unwrap().keyframe);
        }
    }

    #[test]
    fn thread_counts_follow_the_setting() {
        assert_eq!(encoder_threads(1), 1);
        assert_eq!(encoder_threads(2), 2);
        assert_eq!(encoder_threads(4), 4);
        assert_eq!(encoder_threads(5), 4);
        assert_eq!(encoder_threads(u16::MAX), 4);
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let auto = usize::from(encoder_threads(0));
        assert_eq!(auto, (cores.saturating_sub(1)).clamp(1, 4), "{cores} cores");
    }

    /// One thread is what the encoder did before it had a setting: the
    /// crate's default thread count, auto, came down to one thread with a
    /// single slice. The same pictures give the same bytes.
    #[test]
    fn one_thread_encodes_as_before() {
        let settings = EncoderSettings::default();
        let before = config(&settings).num_threads(0);
        let mut old = Encoder::with_api_config(OpenH264API::from_source(), before).unwrap();
        let mut enc = H264Encoder::new(settings).unwrap();
        let (w, h) = (640, 360);
        for t in 0..6 {
            let picture = card(w, h, t);
            let yuv = YUVBuffer::from_bgra8_source(BgraSliceU8::new(&picture, (640, 360)));
            let want = old.encode(&yuv).unwrap().to_vec();
            let got = enc.encode(&picture, w, h).unwrap();
            assert_eq!(got.data, want, "picture {t}");
        }
    }

    /// Threads 2 to 4 (size-limited slices) encode a 1080p card that decodes
    /// intact, the index stamped into each picture included.
    #[test]
    fn two_to_four_threads_encode_a_card_that_decodes_intact() {
        let (w, h) = (1920, 1080);
        for threads in 2..=MAX_ENCODER_THREADS {
            let mut enc = H264Encoder::new(EncoderSettings {
                threads,
                ..EncoderSettings::default()
            })
            .unwrap();
            let mut dec = H264Decoder::new().unwrap();
            for t in 0..4 {
                let index = 0x9E37_79B9_u32.wrapping_mul(t + u32::from(threads));
                let mut picture = card(w, h, t);
                stamp(&mut picture, w, h, index);
                let au = enc.encode(&picture, w, h).unwrap();
                assert_eq!(au.keyframe, t == 0, "threads {threads}, picture {t}");
                let frame = dec.decode(&au.data).unwrap().expect("a picture");
                assert_eq!((frame.width, frame.height), (w, h));
                assert_eq!(
                    read_stamp(&frame.rgba, w, h),
                    index,
                    "threads {threads}, picture {t}"
                );
            }
        }
    }

    /// Best quality's settings at the codec's largest picture, on noise no
    /// encoder can compress, with four threads: one IDR that fits a media
    /// frame and decodes at full size.
    #[test]
    fn a_noisy_4k_idr_at_best_quality_with_four_threads_fits_a_frame() {
        let (w, h) = (MAX_LONG_SIDE, MAX_SHORT_SIDE);
        let mut enc = H264Encoder::new(EncoderSettings {
            bitrate_bps: 4_000_000,
            max_fps: 12.0,
            qp: Some((18, 32)),
            threads: 4,
        })
        .unwrap();
        let au = enc
            .encode(&noise(w, h, 0x2545_F491_4F6C_DD1D), w, h)
            .unwrap();
        assert!(au.keyframe);
        assert!(
            au.data.len() < MAX_ACCESS_UNIT,
            "{} bytes for one access unit",
            au.data.len()
        );
        let mut dec = H264Decoder::new().unwrap();
        let frame = dec.decode(&au.data).unwrap().expect("a picture");
        assert_eq!((frame.width, frame.height), (w, h));
    }

    /// Four threads across size changes: each new size is a new encoder
    /// whose first access unit is an IDR at that size.
    #[test]
    fn a_size_change_mid_stream_with_four_threads_starts_with_an_idr() {
        let mut enc = H264Encoder::new(EncoderSettings {
            threads: 4,
            ..EncoderSettings::default()
        })
        .unwrap();
        let mut dec = H264Decoder::new().unwrap();
        let mut t = 0;
        for (w, h) in [(1920, 1080), (1280, 720), (1920, 1080)] {
            for n in 0..2 {
                let mut picture = card(w, h, t);
                stamp(&mut picture, w, h, t);
                let au = enc.encode(&picture, w, h).unwrap();
                assert_eq!(au.keyframe, n == 0, "{w}x{h} picture {n}");
                assert_eq!(enc.size(), (w, h));
                let frame = dec.decode(&au.data).unwrap().expect("a picture");
                assert_eq!((frame.width, frame.height), (w, h), "{w}x{h} picture {n}");
                assert_eq!(read_stamp(&frame.rgba, w, h), t);
                t += 1;
            }
        }
    }

    /// A size change starts afresh: its first access unit is exactly what a
    /// new encoder makes of that picture, not the old encoder re-initialised
    /// in place, which keeps its rate control and stream state.
    #[test]
    fn a_size_change_builds_a_new_encoder() {
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        for t in 0..3 {
            enc.encode(&card(1280, 720, t), 1280, 720).unwrap();
        }
        let picture = card(640, 360, 3);
        let changed = enc.encode(&picture, 640, 360).unwrap();
        let mut fresh = H264Encoder::new(EncoderSettings::default()).unwrap();
        assert_eq!(changed, {
            let mut au = fresh.encode(&picture, 640, 360).unwrap();
            (au.convert, au.encode) = (changed.convert, changed.encode);
            au
        });
        // And it goes on as that new encoder does.
        let next = card(640, 360, 4);
        assert_eq!(
            enc.encode(&next, 640, 360).unwrap().data,
            fresh.encode(&next, 640, 360).unwrap().data
        );
    }

    /// The H.264 slices of an Annex-B access unit (NAL types 1 and 5).
    fn slices(au: &[u8]) -> usize {
        au.windows(4)
            .filter(|w| w[..3] == [0, 0, 1] && matches!(w[3] & 0x1f, 1 | 5))
            .count()
    }

    /// Threads are real: with more than one, every picture is cut into at
    /// least one slice per thread (`num_threads` alone would leave one
    /// slice, and so one thread); with one, it stays one slice.
    #[test]
    fn threads_cut_each_picture_into_slices() {
        let (w, h) = (1920, 1080);
        for threads in 1..=MAX_ENCODER_THREADS {
            let mut enc = H264Encoder::new(EncoderSettings {
                threads,
                ..EncoderSettings::default()
            })
            .unwrap();
            for t in 0..2 {
                let au = enc.encode(&card(w, h, t), w, h).unwrap();
                let n = slices(&au.data);
                if threads == 1 {
                    assert_eq!(n, 1, "picture {t}");
                } else {
                    assert!(
                        n >= usize::from(threads),
                        "threads {threads}, picture {t}: {n}"
                    );
                }
            }
        }
    }

    /// The I420 buffer is allocated once per size.
    #[test]
    fn the_yuv_buffer_is_reused_while_the_size_holds() {
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        assert_eq!(enc.yuv_at(), None);
        enc.encode(&card(320, 240, 0), 320, 240).unwrap();
        let first = enc.yuv_at().expect("a buffer");
        for t in 1..4 {
            enc.encode(&card(320, 240, t), 320, 240).unwrap();
            assert_eq!(enc.yuv_at(), Some(first), "picture {t}");
        }
        enc.encode(&card(640, 360, 4), 640, 360).unwrap();
        let second = enc.yuv_at().expect("a buffer");
        enc.encode(&card(640, 360, 5), 640, 360).unwrap();
        assert_eq!(enc.yuv_at(), Some(second));
        // A refused picture leaves it alone.
        assert!(enc.encode(&[0; 4], 3, 3).is_err());
        assert_eq!(enc.yuv_at(), Some(second));
    }

    #[test]
    fn convert_and_encode_are_timed() {
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        let au = enc.encode(&card(640, 360, 0), 640, 360).unwrap();
        assert!(au.convert > Duration::ZERO, "{:?}", au.convert);
        assert!(au.encode > Duration::ZERO, "{:?}", au.encode);
    }
}
