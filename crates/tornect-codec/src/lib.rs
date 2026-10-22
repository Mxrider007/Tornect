//! Tornect video codecs (`docs/PLAN.md` §B.5, decision M0-5): OpenH264 built
//! from source, always compiled in — the codec every host and viewer shares.
//!
//! The host feeds tightly packed BGRx/BGRA frames ([`H264Encoder::encode`]);
//! OpenH264 needs even dimensions, so an odd last row/column is dropped. The
//! viewer gets RGBA back ([`H264Decoder::decode`]). Both converters are BT.601
//! limited range, so the stream is tagged BT.601 (media research §2.3).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use openh264::OpenH264API;
use openh264::decoder::Decoder;
use openh264::encoder::{
    BitRate, Complexity, Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod,
    RateControlMode, UsageType, VuiConfig,
};
use openh264::formats::{BgraSliceU8, YUVBuffer, YUVSource as _};

/// The longest side OpenH264 encodes: 3840 wide, or 3840 tall when the
/// picture stands upright (level 5.2, `openh264` 0.9.8 `Encoder::reinit`).
pub const MAX_LONG_SIDE: u32 = 3840;
/// The shortest side OpenH264 encodes: 2160, across either axis.
pub const MAX_SHORT_SIDE: u32 = 2160;

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
}

impl Default for EncoderSettings {
    /// Sized for a Tor circuit: ~1.5 Mbit/s at 15 fps.
    fn default() -> Self {
        Self {
            bitrate_bps: 1_500_000,
            max_fps: 15.0,
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
}

/// OpenH264 encoder for screen content (`SCREEN_CONTENT_REAL_TIME`).
pub struct H264Encoder {
    enc: Encoder,
    width: u32,
    height: u32,
    /// Even-cropped copy of the input, reused across frames.
    scratch: Vec<u8>,
}

impl std::fmt::Debug for H264Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H264Encoder")
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

/// The even picture size OpenH264 encodes for a `w`×`h` source: odd edges
/// dropped, then clamped to the codec maximum in the picture's own
/// orientation, at most 3840×2160 wide and at most 2160×3840 upright. A
/// portrait screen is sent whole up to 3840 rows; clamping each axis to the
/// landscape maximum would cut off its bottom, and with it the part of the
/// screen the viewer's pointer can reach.
#[must_use]
pub fn encoded_size(w: u32, h: u32) -> (u32, u32) {
    let (w, h) = (w & !1, h & !1);
    if h > w {
        (w.min(MAX_SHORT_SIDE), h.min(MAX_LONG_SIDE))
    } else {
        (w.min(MAX_LONG_SIDE), h.min(MAX_SHORT_SIDE))
    }
}

impl H264Encoder {
    /// A new encoder; pictures are [`encoded_size`] of what is fed in.
    pub fn new(settings: EncoderSettings) -> Result<Self, CodecError> {
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
        let enc = Encoder::with_api_config(OpenH264API::from_source(), cfg).map_err(h264)?;
        Ok(Self {
            enc,
            width: 0,
            height: 0,
            scratch: Vec::new(),
        })
    }

    /// Make the next access unit an IDR (viewer joined or lost sync).
    pub fn force_keyframe(&mut self) {
        self.enc.force_intra_frame();
    }

    /// Encode one tightly packed BGRx frame of `w`×`h`. A size change re-inits
    /// the encoder, which starts with an IDR.
    pub fn encode(&mut self, bgrx: &[u8], w: u32, h: u32) -> Result<EncodedFrame, CodecError> {
        let want = (w as usize) * (h as usize) * 4;
        if bgrx.len() != want || w < 2 || h < 2 {
            return Err(CodecError::Geometry {
                got: bgrx.len(),
                want,
                w,
                h,
            });
        }
        let (ew, eh) = encoded_size(w, h);
        let src: &[u8] = if (ew, eh) == (w, h) {
            bgrx
        } else {
            crop(bgrx, w, ew, eh, &mut self.scratch);
            &self.scratch
        };
        self.width = ew;
        self.height = eh;
        let yuv = YUVBuffer::from_bgra8_source(BgraSliceU8::new(src, (ew as usize, eh as usize)));
        let bs = self.enc.encode(&yuv).map_err(h264)?;
        let keyframe = matches!(bs.frame_type(), FrameType::IDR | FrameType::I);
        Ok(EncodedFrame {
            data: bs.to_vec(),
            keyframe,
        })
    }

    /// The size of the last encoded picture.
    #[must_use]
    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

/// Copy the top-left `ew`×`eh` of a `w`-wide BGRx picture into `out`, tightly.
fn crop(src: &[u8], w: u32, ew: u32, eh: u32, out: &mut Vec<u8>) {
    let (stride, row) = (w as usize * 4, ew as usize * 4);
    out.clear();
    out.reserve(row * eh as usize);
    for y in 0..eh as usize {
        out.extend_from_slice(&src[y * stride..y * stride + row]);
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
    fn odd_sizes_are_cropped_to_even_and_forced_keyframes_happen() {
        let (w, h) = (321, 241);
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        let _ = enc.encode(&card(w, h, 0), w, h).unwrap();
        assert_eq!(enc.size(), (320, 240));
        let p = enc.encode(&card(w, h, 1), w, h).unwrap();
        assert!(!p.keyframe);
        enc.force_keyframe();
        let k = enc.encode(&card(w, h, 2), w, h).unwrap();
        assert!(k.keyframe);
    }

    /// The crop keeps the picture's orientation: a landscape picture is held
    /// to 3840×2160, an upright one to 2160×3840, so a portrait screen is not
    /// cut at row 2160.
    #[test]
    fn the_crop_is_clamped_in_the_pictures_own_orientation() {
        for ((w, h), want) in [
            ((1920, 1080), (1920, 1080)),
            ((1921, 1081), (1920, 1080)),
            ((7680, 2160), (3840, 2160)),
            ((5120, 2880), (3840, 2160)),
            ((1440, 2560), (1440, 2560)),
            ((2160, 3840), (2160, 3840)),
            ((1081, 2561), (1080, 2560)),
            ((2880, 5120), (2160, 3840)),
            ((2400, 3000), (2160, 3000)),
            ((1080, 7680), (1080, 3840)),
            ((3000, 3000), (3000, 2160)),
        ] {
            let (ew, eh) = encoded_size(w, h);
            assert_eq!((ew, eh), want, "{w}x{h}");
            assert!(ew % 2 == 0 && eh % 2 == 0, "{w}x{h}");
            assert!(ew.max(eh) <= MAX_LONG_SIDE && ew.min(eh) <= MAX_SHORT_SIDE);
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

    #[test]
    fn wrong_buffer_sizes_are_errors() {
        let mut enc = H264Encoder::new(EncoderSettings::default()).unwrap();
        assert!(matches!(
            enc.encode(&[0; 10], 4, 4),
            Err(CodecError::Geometry { .. })
        ));
        let mut dec = H264Decoder::new().unwrap();
        // Garbage is an error or no picture — never a panic.
        let _ = dec.decode(&[0, 0, 0, 1, 0x65, 0xff, 0x00, 0x13]);
    }
}
