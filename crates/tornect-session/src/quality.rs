//! The quality presets (the quality design §3.1, decision M1-74): the one
//! place their table lives. The viewer names a preset; the host maps it to a
//! picture cap, a frame-rate cap, a bitrate, a quantizer range and an ack
//! window, every number from this table and bounded by the host's own
//! `[media]` ([`QualityCaps`]). The viewer can never ask for more than the
//! host's configured maximum, which is what Best quality means.
//!
//! The Tor rows are provisional until the live per-preset measurement over
//! Tor freezes them (the design's step 19, `docs/VERIFICATION.md`).

use std::time::Duration;

use tornect_codec::EncoderSettings;
use tornect_codec::scale::ResolutionCap;
use tornect_core::config::{Media, QualityPreset};
use tornect_proto::QualityInfo;

/// How a media stream reaches the viewer. The host chooses it from the
/// listener that accepted the stream, never from anything the viewer sends.
/// The direct route's design adds its variant and its table row.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Route {
    /// Over a Tor onion stream.
    #[default]
    Tor,
}

/// How long a stream's ack window lasts at the preset's frame rate and
/// bitrate: the measured Tor round trip of 1.0–1.3 s (decisions M1-43,
/// M1-47) and a margin. Over a link slower than the preset's bitrate the
/// latency is bounded by about this span × bitrate / link rate.
pub const WINDOW_SPAN: Duration = Duration::from_millis(1500);

/// The least ack window of any preset, in access units.
pub const WINDOW_MIN_FRAMES: usize = 20;

/// The least ack window of any preset, in bytes.
pub const WINDOW_MIN_BYTES: usize = 256 * 1024;

/// The highest bitrate any preset is given, kbit/s: 1e9 bit/s stays below
/// `i32::MAX`, which OpenH264's bitrate must fit (`openh264` 0.9.8
/// `encoder.rs:972`).
const MAX_KBPS: u32 = 1_000_000;

/// The highest frame rate `[media] max_fps` may give.
const MAX_FPS: u32 = 240;

/// The most encoder threads `[media] encoder_threads` may ask for.
const MAX_THREADS: u16 = 4;

/// The host's bounds on every preset, from its `[media]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualityCaps {
    /// No preset and no capture exceeds this frame rate.
    pub max_fps: u32,
    /// Best quality's bitrate over Tor; no preset there exceeds it, kbit/s.
    pub tor_max_kbps: u32,
    /// No preset goes below this bitrate, kbit/s.
    pub min_kbps: u32,
    /// The encoder's threads (`tornect_codec::EncoderSettings::threads`).
    pub encoder_threads: u16,
}

impl QualityCaps {
    /// The caps `media` sets, each held to its range: the frame rate to 1 to
    /// 240, the Tor bitrate to 1 to 1 000 000 kbit/s, the least bitrate to 1
    /// to the Tor bitrate, the threads to 0 to 4. A config that holds a
    /// value out of range still loads (no rule was added to the keys it
    /// had), so each value held is said in one note, for the host to log.
    #[must_use]
    pub fn from_media(media: &Media) -> (Self, Vec<String>) {
        let mut notes = Vec::new();
        let max_fps = media.max_fps.clamp(1, MAX_FPS);
        if max_fps != media.max_fps {
            notes.push(format!(
                "media.max_fps ({}) is outside 1 to {MAX_FPS}: presets use {max_fps}",
                media.max_fps
            ));
        }
        let tor_max_kbps = media.tor_fallback_max_kbps.clamp(1, MAX_KBPS);
        if tor_max_kbps != media.tor_fallback_max_kbps {
            notes.push(format!(
                "media.tor_fallback_max_kbps ({}) is outside 1 to {MAX_KBPS}: presets use \
                 {tor_max_kbps}",
                media.tor_fallback_max_kbps
            ));
        }
        let min_kbps = media.min_bitrate_kbps.clamp(1, tor_max_kbps);
        if media.min_bitrate_kbps > tor_max_kbps {
            notes.push(format!(
                "media.min_bitrate_kbps ({}) is above media.tor_fallback_max_kbps \
                 ({tor_max_kbps}): presets use {min_kbps}",
                media.min_bitrate_kbps
            ));
        } else if min_kbps != media.min_bitrate_kbps {
            notes.push(format!(
                "media.min_bitrate_kbps ({}) is below 1: presets use {min_kbps}",
                media.min_bitrate_kbps
            ));
        }
        let encoder_threads = u16::from(media.encoder_threads).min(MAX_THREADS);
        if encoder_threads != u16::from(media.encoder_threads) {
            notes.push(format!(
                "media.encoder_threads ({}) is above {MAX_THREADS}: the encoder uses \
                 {encoder_threads}",
                media.encoder_threads
            ));
        }
        (
            Self {
                max_fps,
                tor_max_kbps,
                min_kbps,
                encoder_threads,
            },
            notes,
        )
    }
}

impl Default for QualityCaps {
    /// The caps of the default `[media]`: 60 fps, 4000 and 500 kbit/s, one
    /// encoder thread.
    fn default() -> Self {
        Self::from_media(&Media::default()).0
    }
}

/// What a stream runs with under one preset: its encoder settings and the cap
/// its pictures are fitted under.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StreamSettings {
    /// The preset.
    pub preset: QualityPreset,
    /// Frame rate, bitrate, quantizer range and threads.
    pub encoder: EncoderSettings,
    /// The picture cap.
    pub cap: ResolutionCap,
}

impl StreamSettings {
    /// The frame-rate cap, at least 1.
    #[must_use]
    pub fn fps(&self) -> u32 {
        // `as` saturates, and NaN gives 0.
        (self.encoder.max_fps as u32).max(1)
    }

    /// The bitrate in kbit/s, at least 1.
    #[must_use]
    pub fn kbps(&self) -> u32 {
        (self.encoder.bitrate_bps / 1000).max(1)
    }

    /// What the host says it applies (`BindOk`, `Quality`): always a
    /// `QualityInfo` the viewer accepts.
    #[must_use]
    pub fn info(&self) -> QualityInfo {
        let cap = ResolutionCap::new(self.cap.long, self.cap.short);
        let edge = |side: u32| u16::try_from(side).unwrap_or(u16::MAX);
        QualityInfo {
            preset: code(self.preset),
            max_fps: u8::try_from(self.fps()).unwrap_or(u8::MAX),
            kbps: self.kbps(),
            max_long: edge(cap.long),
            max_short: edge(cap.short),
        }
    }
}

/// One row of the table, before the host's caps.
struct Row {
    cap: ResolutionCap,
    fps: u32,
    /// `None`: the host's Tor bitrate.
    kbps: Option<u32>,
    qp: Option<(u8, u8)>,
}

/// The table (the quality design §3.1; provisional until the live Tor
/// measurement).
const fn row(preset: QualityPreset, route: Route) -> Row {
    match (route, preset) {
        (Route::Tor, QualityPreset::BestQuality) => Row {
            cap: ResolutionCap::CODEC,
            fps: 12,
            kbps: None,
            qp: Some((18, 32)),
        },
        // Today's stream, but for the 1080p cap and the derived window.
        (Route::Tor, QualityPreset::Balanced) => Row {
            cap: ResolutionCap::new(1920, 1080),
            fps: 15,
            kbps: Some(1500),
            // OpenH264's own range: 26 to 35 for screen content.
            qp: None,
        },
        (Route::Tor, QualityPreset::BestPerformance) => Row {
            cap: ResolutionCap::new(1280, 720),
            fps: 20,
            kbps: Some(1000),
            qp: Some((28, 44)),
        },
    }
}

/// What `preset` runs with on `route` under `caps`: the row's frame rate held
/// to `caps.max_fps` (at least 1); its bitrate (Best quality's is
/// `caps.tor_max_kbps`) held between `caps.min_kbps` and `caps.tor_max_kbps`;
/// its picture cap and quantizer range; the host's encoder threads.
#[must_use]
pub fn settings(preset: QualityPreset, route: Route, caps: &QualityCaps) -> StreamSettings {
    let row = row(preset, route);
    let hi = caps.tor_max_kbps.clamp(1, MAX_KBPS);
    let lo = caps.min_kbps.min(hi);
    let kbps = row.kbps.unwrap_or(hi).clamp(lo, hi);
    let fps = row.fps.min(caps.max_fps).max(1);
    StreamSettings {
        preset,
        encoder: EncoderSettings {
            bitrate_bps: kbps.saturating_mul(1000),
            // Exact: every frame rate here is a small integer.
            max_fps: fps as f32,
            qp: row.qp,
            threads: caps.encoder_threads.min(MAX_THREADS),
        },
        cap: row.cap,
    }
}

/// The rate the host captures at on `route`: the highest of any preset's
/// frame rate there, held to `caps.max_fps`. It comes from the host's config
/// and the route only, never from the viewer's pick, so every preset opens
/// capture alike, and a change of preset never reopens it (it would show the
/// desktop's dialog again); the encoder paces each preset's own rate.
#[must_use]
pub fn capture_fps(route: Route, caps: &QualityCaps) -> u32 {
    QualityPreset::ALL
        .into_iter()
        .map(|preset| settings(preset, route, caps).fps())
        .max()
        .unwrap_or(1)
}

/// The ack window `settings` run with: [`WINDOW_SPAN`] of their frame rate
/// and bitrate, at least [`WINDOW_MIN_FRAMES`] units and [`WINDOW_MIN_BYTES`]
/// bytes, and at most `frames_cap` units and `bytes_cap` bytes (the host's
/// `MediaLimits` caps). Returns `(frames, bytes)`.
#[must_use]
pub fn window(settings: &StreamSettings, frames_cap: usize, bytes_cap: usize) -> (usize, usize) {
    let span_ms = WINDOW_SPAN.as_millis() as u64;
    let frames = (u64::from(settings.fps()) * span_ms).div_ceil(1000);
    // kbit/s × 1000 / 8 bytes a second, for the span.
    let bytes = (u64::from(settings.kbps()) * span_ms).div_ceil(8);
    let frames = usize::try_from(frames)
        .unwrap_or(usize::MAX)
        .max(WINDOW_MIN_FRAMES)
        .min(frames_cap);
    let bytes = usize::try_from(bytes)
        .unwrap_or(usize::MAX)
        .max(WINDOW_MIN_BYTES)
        .min(bytes_cap);
    (frames, bytes)
}

/// The wire code of `preset` (`tornect_proto::quality`).
#[must_use]
pub const fn code(preset: QualityPreset) -> u8 {
    match preset {
        QualityPreset::BestQuality => tornect_proto::quality::BEST_QUALITY,
        QualityPreset::Balanced => tornect_proto::quality::BALANCED,
        QualityPreset::BestPerformance => tornect_proto::quality::BEST_PERFORMANCE,
    }
}

/// The preset of wire code `code`; `None` for a code no preset has.
#[must_use]
pub fn preset(code: u8) -> Option<QualityPreset> {
    QualityPreset::ALL
        .into_iter()
        .find(|&preset| self::code(preset) == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BQ: QualityPreset = QualityPreset::BestQuality;
    const BAL: QualityPreset = QualityPreset::Balanced;
    const BP: QualityPreset = QualityPreset::BestPerformance;

    /// One row as the test reads it: cap, fps, kbps, QP.
    type Read = ((u32, u32), u32, u32, Option<(u8, u8)>);

    fn row_of(s: &StreamSettings) -> Read {
        ((s.cap.long, s.cap.short), s.fps(), s.kbps(), s.encoder.qp)
    }

    /// The table of §3.1 with the default `[media]`: Best quality at the
    /// codec's cap, 12 fps and the Tor bitrate (4000); Balanced as today
    /// (15 fps, 1.5 Mbit/s, OpenH264's QP) but for its 1080p cap; Best
    /// performance at 720p, 20 fps, 1 Mbit/s; one encoder thread each.
    #[test]
    fn the_tor_table_with_the_default_caps() {
        let caps = QualityCaps::default();
        assert_eq!(
            caps,
            QualityCaps {
                max_fps: 60,
                tor_max_kbps: 4000,
                min_kbps: 500,
                encoder_threads: 1,
            }
        );
        let table = QualityPreset::ALL.map(|p| row_of(&settings(p, Route::Tor, &caps)));
        assert_eq!(
            table,
            [
                ((3840, 2160), 12, 4000, Some((18, 32))),
                ((1920, 1080), 15, 1500, None),
                ((1280, 720), 20, 1000, Some((28, 44))),
            ]
        );
        for preset in QualityPreset::ALL {
            let s = settings(preset, Route::Tor, &caps);
            assert_eq!(s.preset, preset);
            assert_eq!(s.encoder.threads, 1);
            assert_eq!(s.encoder.bitrate_bps, s.kbps() * 1000);
        }
        // Balanced is today's encoder, which `EncoderSettings::default` is.
        assert_eq!(
            settings(BAL, Route::Tor, &caps).encoder,
            EncoderSettings::default()
        );
    }

    /// Tight caps hold every preset: the frame rate to `max_fps`, the
    /// bitrate between the least and the Tor bitrate (a least bitrate above
    /// the Tor one is held to it, so all three run at 800 kbit/s here), and
    /// the threads to the host's.
    #[test]
    fn tight_caps_hold_every_preset() {
        let media = Media {
            max_fps: 10,
            tor_fallback_max_kbps: 800,
            min_bitrate_kbps: 900,
            encoder_threads: 3,
            ..Media::default()
        };
        let (caps, notes) = QualityCaps::from_media(&media);
        assert_eq!(caps.min_kbps, 800);
        assert_eq!(notes.len(), 1, "{notes:?}");
        for preset in QualityPreset::ALL {
            let s = settings(preset, Route::Tor, &caps);
            assert_eq!((s.fps(), s.kbps(), s.encoder.threads), (10, 800, 3));
        }
        // A least bitrate above a row's raises the row; the Tor bitrate still
        // caps Best quality.
        let caps = QualityCaps {
            min_kbps: 1200,
            ..QualityCaps::default()
        };
        let kbps = QualityPreset::ALL.map(|p| settings(p, Route::Tor, &caps).kbps());
        assert_eq!(kbps, [4000, 1500, 1200]);
        // Caps built by hand, out of every range, still give settings the
        // encoder and the wire take.
        let wild = QualityCaps {
            max_fps: 0,
            tor_max_kbps: u32::MAX,
            min_kbps: u32::MAX,
            encoder_threads: u16::MAX,
        };
        for preset in QualityPreset::ALL {
            let s = settings(preset, Route::Tor, &wild);
            assert_eq!(s.fps(), 1);
            assert_eq!(s.kbps(), MAX_KBPS);
            assert!(i32::try_from(s.encoder.bitrate_bps).is_ok());
            assert_eq!(s.encoder.threads, 4);
            let info = s.info();
            let msg = tornect_proto::Msg::Quality {
                width: 2,
                height: 2,
                quality: info,
            };
            assert_eq!(tornect_proto::Msg::decode(&msg.encode()[4..]).unwrap(), msg);
        }
        let none = QualityCaps {
            tor_max_kbps: 0,
            min_kbps: 0,
            ..QualityCaps::default()
        };
        assert_eq!(settings(BP, Route::Tor, &none).kbps(), 1);
    }

    /// Capture runs at the fastest preset's rate on the route (20 on Tor),
    /// held to `max_fps`, whichever preset the viewer named.
    #[test]
    fn capture_runs_at_the_fastest_presets_rate() {
        assert_eq!(capture_fps(Route::Tor, &QualityCaps::default()), 20);
        for (max_fps, want) in [(60, 20), (20, 20), (15, 15), (1, 1), (0, 1)] {
            let caps = QualityCaps {
                max_fps,
                ..QualityCaps::default()
            };
            assert_eq!(capture_fps(Route::Tor, &caps), want, "max_fps {max_fps}");
        }
    }

    /// The window of §3.1: 1.5 s of each preset's rate and bitrate, at least
    /// 20 units and 256 KiB, at most the caps (32 units and 1 MiB by
    /// default; 3 units in the window test).
    #[test]
    fn the_window_spans_each_presets_rate_and_bitrate() {
        let caps = QualityCaps::default();
        let windows =
            QualityPreset::ALL.map(|p| window(&settings(p, Route::Tor, &caps), 32, 1 << 20));
        assert_eq!(windows, [(20, 750_000), (23, 281_250), (30, 262_144)]);
        let tight = QualityPreset::ALL.map(|p| window(&settings(p, Route::Tor, &caps), 3, 512));
        assert_eq!(tight, [(3, 512); 3]);
        let wide = window(&settings(BAL, Route::Tor, &caps), 10_000, 1 << 30);
        assert_eq!(wide, (23, 281_250));
        // A fast, wide preset reaches the caps.
        let fast = StreamSettings {
            encoder: EncoderSettings {
                max_fps: 240.0,
                bitrate_bps: 1_000_000_000,
                ..EncoderSettings::default()
            },
            ..settings(BQ, Route::Tor, &caps)
        };
        assert_eq!(window(&fast, 32, 1 << 20), (32, 1 << 20));
        assert_eq!(window(&fast, usize::MAX, usize::MAX), (360, 187_500_000));
    }

    /// Each value out of its range is held, and said once.
    #[test]
    fn from_media_holds_each_value_and_says_so() {
        let (caps, notes) = QualityCaps::from_media(&Media::default());
        assert_eq!(caps, QualityCaps::default());
        assert!(notes.is_empty(), "{notes:?}");

        let (caps, notes) = QualityCaps::from_media(&Media {
            min_bitrate_kbps: 5000,
            ..Media::default()
        });
        assert_eq!(caps.min_kbps, 4000);
        assert_eq!(
            notes,
            [
                "media.min_bitrate_kbps (5000) is above media.tor_fallback_max_kbps (4000): \
              presets use 4000"
            ]
        );

        let (caps, notes) = QualityCaps::from_media(&Media {
            max_fps: 1000,
            tor_fallback_max_kbps: 0,
            min_bitrate_kbps: 0,
            encoder_threads: 9,
            ..Media::default()
        });
        assert_eq!(
            caps,
            QualityCaps {
                max_fps: 240,
                tor_max_kbps: 1,
                min_kbps: 1,
                encoder_threads: 4,
            }
        );
        assert_eq!(
            notes,
            [
                "media.max_fps (1000) is outside 1 to 240: presets use 240",
                "media.tor_fallback_max_kbps (0) is outside 1 to 1000000: presets use 1",
                "media.min_bitrate_kbps (0) is below 1: presets use 1",
                "media.encoder_threads (9) is above 4: the encoder uses 4",
            ]
        );
        let (caps, notes) = QualityCaps::from_media(&Media {
            tor_fallback_max_kbps: u32::MAX,
            max_fps: 0,
            ..Media::default()
        });
        assert_eq!((caps.tor_max_kbps, caps.max_fps), (MAX_KBPS, 1));
        assert_eq!(notes.len(), 2, "{notes:?}");
        let (caps, notes) = QualityCaps::from_media(&Media {
            encoder_threads: 0,
            ..Media::default()
        });
        assert_eq!(caps.encoder_threads, 0, "auto is kept");
        assert!(notes.is_empty());
    }

    /// The wire codes round-trip, and no other code names a preset.
    #[test]
    fn codes_map_to_presets_and_back() {
        assert_eq!(QualityPreset::ALL.map(code), [1, 2, 3]);
        for p in QualityPreset::ALL {
            assert_eq!(preset(code(p)), Some(p));
            assert!(tornect_proto::quality::known(code(p)));
        }
        for c in (0..=u8::MAX).filter(|c| !(1..=3).contains(c)) {
            assert_eq!(preset(c), None, "code {c}");
        }
    }

    /// What the host says it applies: the preset's code, frame rate,
    /// bitrate and cap, as the design's golden `BindOk` has it for Balanced.
    #[test]
    fn info_says_what_a_preset_applies() {
        let caps = QualityCaps::default();
        let infos = QualityPreset::ALL.map(|p| settings(p, Route::Tor, &caps).info());
        assert_eq!(
            infos,
            [
                QualityInfo {
                    preset: 1,
                    max_fps: 12,
                    kbps: 4000,
                    max_long: 3840,
                    max_short: 2160,
                },
                QualityInfo {
                    preset: 2,
                    max_fps: 15,
                    kbps: 1500,
                    max_long: 1920,
                    max_short: 1080,
                },
                QualityInfo {
                    preset: 3,
                    max_fps: 20,
                    kbps: 1000,
                    max_long: 1280,
                    max_short: 720,
                },
            ]
        );
        // A cap built by hand out of range still says a valid one.
        let odd = StreamSettings {
            cap: ResolutionCap {
                long: 1,
                short: 99_999,
            },
            encoder: EncoderSettings {
                max_fps: f32::NAN,
                bitrate_bps: 0,
                ..EncoderSettings::default()
            },
            preset: BP,
        };
        let msg = tornect_proto::Msg::Quality {
            width: 8,
            height: 2,
            quality: odd.info(),
        };
        assert_eq!(tornect_proto::Msg::decode(&msg.encode()[4..]).unwrap(), msg);
    }
}
