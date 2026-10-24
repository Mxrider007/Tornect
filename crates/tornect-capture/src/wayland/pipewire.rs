//! PipeWire without headers (`docs/research/slice.md` §4; the research report
//! behind it, §4.1–§4.8): `libpipewire-0.3.so.0` is opened with `dlopen`, and
//! only the functions the portal's screen cast needs are resolved.
//!
//! The layouts below mirror the PipeWire 1.6.2 headers for LP64 targets
//! (`stream.h`, `spa/buffer/buffer.h`, `spa/utils/hook.h`); the headers are
//! byte-identical up to 1.6.9, and the compile-time assertions pin every size
//! and offset this code reads. The one parameter this consumer sends is the
//! 232-byte `EnumFormat` pod of report §4.6: four 8-bit RGB formats (BGRx
//! first, as mutter offers it), a size range, and a frame-rate range that
//! includes mutter's variable rate `0/1`. It carries no `modifier`, so mutter's
//! DMA-BUF formats cannot match and buffers arrive as mapped `MemFd`s.
//!
//! Threading: a `pw_thread_loop` runs PipeWire's loop. Every call on a loop
//! object is made with the loop's lock held, and the stream callbacks run on
//! the loop thread with that lock held (`thread-loop.h`). The callbacks copy
//! each new picture into a one-picture slot ([`Shared`]) and queue the buffer
//! straight back, on every path; the capture thread takes pictures from that
//! slot. Nothing in a callback can panic across the C boundary: every read is
//! bounds-checked, and a panic there would abort the process anyway.

#![allow(unsafe_code)]

use std::ffi::{CStr, c_char, c_int, c_void};
use std::mem::{offset_of, size_of};
use std::os::fd::{IntoRawFd as _, OwnedFd};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::{CaptureError, Frame};

/// The PipeWire client library, by its soname.
pub(crate) const LIBRARY: &str = "libpipewire-0.3.so.0";

// SPA and PipeWire constants, tag 1.6.2 (research report §4.2, §4.5).
const SPA_TYPE_ID: u32 = 3;
const SPA_TYPE_RECTANGLE: u32 = 10;
const SPA_TYPE_FRACTION: u32 = 11;
const SPA_TYPE_OBJECT: u32 = 15;
const SPA_TYPE_CHOICE: u32 = 19;
const SPA_TYPE_OBJECT_FORMAT: u32 = 0x4_0003;
const SPA_PARAM_ENUM_FORMAT: u32 = 3;
const SPA_PARAM_FORMAT: u32 = 4;
const SPA_FORMAT_MEDIA_TYPE: u32 = 1;
const SPA_FORMAT_MEDIA_SUBTYPE: u32 = 2;
const SPA_FORMAT_VIDEO_FORMAT: u32 = 0x2_0001;
const SPA_FORMAT_VIDEO_MODIFIER: u32 = 0x2_0002;
const SPA_FORMAT_VIDEO_SIZE: u32 = 0x2_0003;
const SPA_FORMAT_VIDEO_FRAMERATE: u32 = 0x2_0004;
const SPA_FORMAT_VIDEO_MAX_FRAMERATE: u32 = 0x2_0005;
const SPA_MEDIA_TYPE_VIDEO: u32 = 2;
const SPA_MEDIA_SUBTYPE_RAW: u32 = 1;
const SPA_VIDEO_FORMAT_RGBX: u32 = 7;
const SPA_VIDEO_FORMAT_BGRX: u32 = 8;
const SPA_VIDEO_FORMAT_RGBA: u32 = 11;
const SPA_VIDEO_FORMAT_BGRA: u32 = 12;
const SPA_CHOICE_RANGE: u32 = 1;
const SPA_CHOICE_ENUM: u32 = 3;
const SPA_DATA_DMABUF: u32 = 3;
const SPA_CHUNK_FLAG_CORRUPTED: i32 = 1;
const PW_DIRECTION_INPUT: u32 = 0;
const PW_STREAM_FLAG_AUTOCONNECT: u32 = 1 << 0;
const PW_STREAM_FLAG_MAP_BUFFERS: u32 = 1 << 2;
const PW_VERSION_STREAM_EVENTS: u32 = 2;
const PW_STREAM_STATE_UNCONNECTED: c_int = 0;
const PW_STREAM_STATE_CONNECTING: c_int = 1;
const PW_STREAM_STATE_PAUSED: c_int = 2;
const PW_STREAM_STATE_STREAMING: c_int = 3;
/// `PW_ID_ANY`: a stream connected to it would take whatever node it finds.
pub(crate) const PW_ID_ANY: u32 = u32::MAX;

/// The largest `Format` param read (a real one is a few hundred bytes).
const MAX_PARAM: usize = 64 * 1024;
/// The largest picture accepted from the compositor: 2^27 pixels (512 MiB of
/// BGRx), the X11 grab's cap, and the pod's 8192×8192 size range within it.
const MAX_PIXELS: u64 = 1 << 27;

/// The stream's properties: a screen being captured.
const STREAM_PROPS: &CStr = c"media.type=Video media.category=Capture media.role=Screen";

// ---- Opaque PipeWire objects -------------------------------------------------

macro_rules! opaque {
    ($($name:ident),*) => {$(
        #[repr(C)]
        pub(crate) struct $name {
            _opaque: [u8; 0],
        }
    )*};
}
opaque!(
    PwThreadLoop,
    PwLoop,
    PwContext,
    PwCore,
    PwStream,
    PwProperties
);

// ---- ABI mirrors (x86_64 / aarch64 LP64; research report §4.3) ---------------
//
// Every field is laid out as in C, whether or not Rust reads it.

/// `struct spa_pod`: every pod's header.
#[repr(C)]
#[allow(dead_code)]
pub(crate) struct SpaPod {
    size: u32,
    ty: u32,
}

/// `struct spa_hook`: PipeWire links it into the stream's listener list, so it
/// stays at one heap address until `pw_stream_destroy` has returned.
#[repr(C)]
#[allow(dead_code)]
struct SpaHook {
    link_next: *mut c_void,
    link_prev: *mut c_void,
    funcs: *const c_void,
    data: *mut c_void,
    removed: *mut c_void,
    private: *mut c_void,
}

impl SpaHook {
    const fn zeroed() -> Self {
        Self {
            link_next: null_mut(),
            link_prev: null_mut(),
            funcs: null(),
            data: null_mut(),
            removed: null_mut(),
            private: null_mut(),
        }
    }
}

type Callback = unsafe extern "C" fn(*mut c_void);

/// `struct pw_stream_events`, version 2.
#[repr(C)]
#[allow(dead_code)]
struct PwStreamEvents {
    version: u32,
    destroy: Option<Callback>,
    state_changed: Option<unsafe extern "C" fn(*mut c_void, c_int, c_int, *const c_char)>,
    control_info: Option<unsafe extern "C" fn(*mut c_void, u32, *const c_void)>,
    io_changed: Option<unsafe extern "C" fn(*mut c_void, u32, *mut c_void, u32)>,
    param_changed: Option<unsafe extern "C" fn(*mut c_void, u32, *const SpaPod)>,
    add_buffer: Option<unsafe extern "C" fn(*mut c_void, *mut PwBuffer)>,
    remove_buffer: Option<unsafe extern "C" fn(*mut c_void, *mut PwBuffer)>,
    process: Option<Callback>,
    drained: Option<Callback>,
    command: Option<unsafe extern "C" fn(*mut c_void, *const c_void)>,
    trigger_done: Option<Callback>,
}

/// `struct pw_buffer`. Only `buffer` is read, so older libraries without the
/// trailing fields work too.
#[repr(C)]
#[allow(dead_code)]
struct PwBuffer {
    buffer: *mut SpaBuffer,
    user_data: *mut c_void,
    size: u64,
    requested: u64,
    time: u64,
}

/// `struct spa_buffer`.
#[repr(C)]
#[allow(dead_code)]
struct SpaBuffer {
    n_metas: u32,
    n_datas: u32,
    metas: *mut c_void,
    datas: *mut SpaData,
}

/// `struct spa_data`.
#[repr(C)]
#[allow(dead_code)]
struct SpaData {
    ty: u32,
    flags: u32,
    fd: i64,
    mapoffset: u32,
    maxsize: u32,
    data: *mut c_void,
    chunk: *mut SpaChunk,
}

/// `struct spa_chunk`: which part of `spa_data` holds the picture.
#[derive(Clone, Copy)]
#[repr(C)]
#[allow(dead_code)]
struct SpaChunk {
    offset: u32,
    size: u32,
    stride: i32,
    flags: i32,
}

// Every size and offset this file relies on, as the 1.6.2 headers lay them out.
const _: () = {
    assert!(size_of::<SpaPod>() == 8);
    assert!(size_of::<SpaHook>() == 48);
    assert!(size_of::<PwStreamEvents>() == 96);
    assert!(offset_of!(PwStreamEvents, destroy) == 8);
    assert!(offset_of!(PwStreamEvents, state_changed) == 16);
    assert!(offset_of!(PwStreamEvents, param_changed) == 40);
    assert!(offset_of!(PwStreamEvents, process) == 64);
    assert!(offset_of!(PwStreamEvents, trigger_done) == 88);
    assert!(size_of::<PwBuffer>() == 40);
    assert!(offset_of!(PwBuffer, buffer) == 0);
    assert!(size_of::<SpaBuffer>() == 24);
    assert!(offset_of!(SpaBuffer, n_datas) == 4);
    assert!(offset_of!(SpaBuffer, datas) == 16);
    assert!(size_of::<SpaData>() == 40);
    assert!(offset_of!(SpaData, fd) == 8);
    assert!(offset_of!(SpaData, mapoffset) == 16);
    assert!(offset_of!(SpaData, maxsize) == 20);
    assert!(offset_of!(SpaData, data) == 24);
    assert!(offset_of!(SpaData, chunk) == 32);
    assert!(size_of::<SpaChunk>() == 16);
    assert!(offset_of!(SpaChunk, stride) == 8);
    assert!(offset_of!(SpaChunk, flags) == 12);
};

// ---- The library -------------------------------------------------------------

type DequeueFn = unsafe extern "C" fn(*mut PwStream) -> *mut PwBuffer;
type QueueFn = unsafe extern "C" fn(*mut PwStream, *mut PwBuffer) -> c_int;

/// The functions resolved from the library (prototypes: report §4.2).
pub(crate) struct Api {
    init: unsafe extern "C" fn(*mut c_int, *mut *mut *mut c_char),
    thread_loop_new: unsafe extern "C" fn(*const c_char, *const c_void) -> *mut PwThreadLoop,
    thread_loop_destroy: unsafe extern "C" fn(*mut PwThreadLoop),
    thread_loop_get_loop: unsafe extern "C" fn(*mut PwThreadLoop) -> *mut PwLoop,
    thread_loop_start: unsafe extern "C" fn(*mut PwThreadLoop) -> c_int,
    thread_loop_stop: unsafe extern "C" fn(*mut PwThreadLoop),
    thread_loop_lock: unsafe extern "C" fn(*mut PwThreadLoop),
    thread_loop_unlock: unsafe extern "C" fn(*mut PwThreadLoop),
    context_new: unsafe extern "C" fn(*mut PwLoop, *mut PwProperties, usize) -> *mut PwContext,
    context_destroy: unsafe extern "C" fn(*mut PwContext),
    context_connect_fd:
        unsafe extern "C" fn(*mut PwContext, c_int, *mut PwProperties, usize) -> *mut PwCore,
    core_disconnect: unsafe extern "C" fn(*mut PwCore) -> c_int,
    properties_new_string: unsafe extern "C" fn(*const c_char) -> *mut PwProperties,
    stream_new:
        unsafe extern "C" fn(*mut PwCore, *const c_char, *mut PwProperties) -> *mut PwStream,
    stream_destroy: unsafe extern "C" fn(*mut PwStream),
    stream_add_listener:
        unsafe extern "C" fn(*mut PwStream, *mut SpaHook, *const PwStreamEvents, *mut c_void),
    stream_connect:
        unsafe extern "C" fn(*mut PwStream, u32, u32, u32, *mut *const SpaPod, u32) -> c_int,
    stream_disconnect: unsafe extern "C" fn(*mut PwStream) -> c_int,
    stream_dequeue_buffer: DequeueFn,
    stream_queue_buffer: QueueFn,
    /// Keeps every pointer above valid. Never unloaded: see [`api`].
    _library: libloading::Library,
}

impl Api {
    /// Open `name` and resolve every function this file calls.
    fn load(name: &str) -> Result<Self, String> {
        // SAFETY: loading the system PipeWire client library runs only its own
        // initializers, which set up PipeWire's state and touch nothing of ours.
        let library = unsafe { libloading::Library::new(name) }
            .map_err(|e| format!("cannot load {name} (is PipeWire installed?): {e}"))?;
        macro_rules! symbol {
            ($symbol:literal) => {{
                // SAFETY: the field this initializes has the symbol's C prototype
                // at PipeWire 1.6.2 (report §4.2); the pointer is only called
                // while `library` stays loaded, which is forever (see `api`).
                let symbol = unsafe { library.get(concat!($symbol, "\0").as_bytes()) }
                    .map_err(|e| format!("{name} lacks {}: {e}", $symbol))?;
                *symbol
            }};
        }
        Ok(Self {
            init: symbol!("pw_init"),
            thread_loop_new: symbol!("pw_thread_loop_new"),
            thread_loop_destroy: symbol!("pw_thread_loop_destroy"),
            thread_loop_get_loop: symbol!("pw_thread_loop_get_loop"),
            thread_loop_start: symbol!("pw_thread_loop_start"),
            thread_loop_stop: symbol!("pw_thread_loop_stop"),
            thread_loop_lock: symbol!("pw_thread_loop_lock"),
            thread_loop_unlock: symbol!("pw_thread_loop_unlock"),
            context_new: symbol!("pw_context_new"),
            context_destroy: symbol!("pw_context_destroy"),
            context_connect_fd: symbol!("pw_context_connect_fd"),
            core_disconnect: symbol!("pw_core_disconnect"),
            properties_new_string: symbol!("pw_properties_new_string"),
            stream_new: symbol!("pw_stream_new"),
            stream_destroy: symbol!("pw_stream_destroy"),
            stream_add_listener: symbol!("pw_stream_add_listener"),
            stream_connect: symbol!("pw_stream_connect"),
            stream_disconnect: symbol!("pw_stream_disconnect"),
            stream_dequeue_buffer: symbol!("pw_stream_dequeue_buffer"),
            stream_queue_buffer: symbol!("pw_stream_queue_buffer"),
            _library: library,
        })
    }
}

static API: OnceLock<Result<Api, String>> = OnceLock::new();

/// The process's PipeWire library, loaded and initialized on first use. It is
/// never unloaded: PipeWire keeps global state and support threads that would
/// outlive an unload.
pub(crate) fn api() -> Result<&'static Api, CaptureError> {
    let loaded = API.get_or_init(|| {
        let api = Api::load(LIBRARY)?;
        // SAFETY: `pw_init` accepts NULL for both arguments; `OnceLock` runs this
        // once per process.
        unsafe { (api.init)(null_mut(), null_mut()) };
        Ok(api)
    });
    loaded
        .as_ref()
        .map_err(|why| CaptureError::Unavailable(why.clone()))
}

fn unavailable(why: impl Into<String>) -> CaptureError {
    CaptureError::Unavailable(why.into())
}

// ---- The one parameter this consumer sends ------------------------------------

/// A pod in 8-byte-aligned storage (`u64` words), as PipeWire reads it. Pods
/// are padded to 8 bytes, so the words hold exactly the pod.
pub(crate) struct AlignedPod {
    words: Vec<u64>,
}

impl AlignedPod {
    /// The pod's bytes.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.words.iter().flat_map(|w| w.to_ne_bytes()).collect()
    }

    fn as_ptr(&self) -> *const SpaPod {
        self.words.as_ptr().cast()
    }
}

/// Writes pods by the SPA rules (report §4.5): native byte order, every pod
/// padded to 8 bytes, the padding not counted in its `size`.
#[derive(Default)]
struct PodWriter {
    words: Vec<u32>,
}

impl PodWriter {
    fn push(&mut self, words: &[u32]) {
        self.words.extend_from_slice(words);
    }

    /// Pad to the next 8-byte boundary.
    fn pad(&mut self) {
        if self.words.len() % 2 == 1 {
            self.words.push(0);
        }
    }

    /// `{size, Object}{object_type, id}` followed by what `props` writes.
    fn object(&mut self, object_type: u32, id: u32, props: impl FnOnce(&mut Self)) {
        let start = self.words.len();
        self.push(&[0, SPA_TYPE_OBJECT, object_type, id]);
        props(self);
        let body = (self.words.len() - start - 2) * 4;
        self.words[start] = u32::try_from(body).unwrap_or(u32::MAX);
    }

    /// A property whose value is an `Id`.
    fn prop_id(&mut self, key: u32, id: u32) {
        self.push(&[key, 0, 4, SPA_TYPE_ID, id]);
        self.pad();
    }

    /// A property whose value is a `Choice` of `elem_type` values, each
    /// `elem_words` words long, packed without per-element padding.
    fn prop_choice(
        &mut self,
        key: u32,
        choice: u32,
        elem_type: u32,
        elem_words: u32,
        values: &[u32],
    ) {
        let body = 16 + values.len() * 4;
        self.push(&[
            key,
            0,
            u32::try_from(body).unwrap_or(u32::MAX),
            SPA_TYPE_CHOICE,
            choice,
            0,
            elem_words * 4,
            elem_type,
        ]);
        self.push(values);
        self.pad();
    }

    fn finish(mut self) -> AlignedPod {
        self.pad();
        let words = self
            .words
            .chunks(2)
            .map(|pair| {
                let mut bytes = [0u8; 8];
                for (i, word) in pair.iter().enumerate() {
                    bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
                }
                u64::from_ne_bytes(bytes)
            })
            .collect();
        AlignedPod { words }
    }
}

/// The highest `maxFramerate` this consumer asks for.
pub(crate) const MAX_POD_FPS: u32 = 120;

/// The `EnumFormat` pod of report §4.6: raw video in BGRx (the default, listed
/// again as the first alternative), BGRx, BGRA, RGBx or RGBA, any size from
/// 1×1 to 8192×8192 (1920×1080 preferred), and any frame rate from `0/1` (the
/// variable rate mutter offers) to 1000/1 (30/1 preferred).
///
/// With `max_fps`, held to 1 to [`MAX_POD_FPS`], it also asks for a
/// `maxFramerate` of at most that many pictures a second: a Range of
/// fractions, `n/1` preferred, from `1/1` to `n/1` (`docs/research/wayland.md`
/// §4.6: mutter, KWin and xdg-desktop-portal-wlr offer a Range from 1/1, or
/// 0/1, to the monitor's refresh rate, and space their pictures by the rate
/// the intersection fixates on, so the PipeWire thread copies no picture the
/// encoder would drop). Without it the pod is the report's, byte for byte.
pub(crate) fn enum_format_pod(max_fps: Option<u32>) -> AlignedPod {
    let mut pod = PodWriter::default();
    pod.object(SPA_TYPE_OBJECT_FORMAT, SPA_PARAM_ENUM_FORMAT, |pod| {
        pod.prop_id(SPA_FORMAT_MEDIA_TYPE, SPA_MEDIA_TYPE_VIDEO);
        pod.prop_id(SPA_FORMAT_MEDIA_SUBTYPE, SPA_MEDIA_SUBTYPE_RAW);
        pod.prop_choice(
            SPA_FORMAT_VIDEO_FORMAT,
            SPA_CHOICE_ENUM,
            SPA_TYPE_ID,
            1,
            &[
                SPA_VIDEO_FORMAT_BGRX,
                SPA_VIDEO_FORMAT_BGRX,
                SPA_VIDEO_FORMAT_BGRA,
                SPA_VIDEO_FORMAT_RGBX,
                SPA_VIDEO_FORMAT_RGBA,
            ],
        );
        pod.prop_choice(
            SPA_FORMAT_VIDEO_SIZE,
            SPA_CHOICE_RANGE,
            SPA_TYPE_RECTANGLE,
            2,
            &[1920, 1080, 1, 1, 8192, 8192],
        );
        pod.prop_choice(
            SPA_FORMAT_VIDEO_FRAMERATE,
            SPA_CHOICE_RANGE,
            SPA_TYPE_FRACTION,
            2,
            &[30, 1, 0, 1, 1000, 1],
        );
        if let Some(fps) = max_fps {
            let fps = fps.clamp(1, MAX_POD_FPS);
            pod.prop_choice(
                SPA_FORMAT_VIDEO_MAX_FRAMERATE,
                SPA_CHOICE_RANGE,
                SPA_TYPE_FRACTION,
                2,
                &[fps, 1, 1, 1, fps, 1],
            );
        }
    });
    pod.finish()
}

// ---- The negotiated format ---------------------------------------------------

/// What a `Format` param says, before it is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Negotiated {
    /// `SPA_VIDEO_FORMAT_*`.
    pub(crate) format: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    /// A `modifier` property is present: DMA-BUF was negotiated.
    pub(crate) modifier: bool,
    /// The `maxFramerate` fraction (`num`, `denom`), when one is there and
    /// whole. For the log only: nothing is sized or paced from it.
    pub(crate) max_framerate: Option<(u32, u32)>,
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let word = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_ne_bytes(word.try_into().ok()?))
}

/// Read the video format and picture size from a `Format` object pod (report
/// §4.7). A value may be plain or wrapped in a `Choice`, whose first element is
/// the chosen one. Every offset is checked against the pod's own size and the
/// slice; anything malformed is `None`.
pub(crate) fn parse_format(pod: &[u8]) -> Option<Negotiated> {
    let size = usize::try_from(u32_at(pod, 0)?).ok()?;
    if u32_at(pod, 4)? != SPA_TYPE_OBJECT || u32_at(pod, 8)? != SPA_TYPE_OBJECT_FORMAT {
        return None;
    }
    let end = size.checked_add(8)?;
    let pod = pod.get(..end)?;
    let (mut media_type, mut subtype, mut format, mut dims, mut modifier) =
        (None, None, None, None, false);
    let mut max_framerate = None;
    let mut at: usize = 16;
    while at.checked_add(16)? <= end {
        let key = u32_at(pod, at)?;
        let value_size = usize::try_from(u32_at(pod, at + 8)?).ok()?;
        let value_type = u32_at(pod, at + 12)?;
        let body = at + 16;
        let body_end = body.checked_add(value_size)?;
        // Values are read only from this property's own bytes.
        let value = pod.get(..body_end)?;
        let (elem_type, first) = if value_type == SPA_TYPE_CHOICE {
            if value_size < 16 {
                return None;
            }
            (u32_at(value, body + 12)?, body + 16)
        } else {
            (value_type, body)
        };
        match (key, elem_type) {
            (SPA_FORMAT_MEDIA_TYPE, SPA_TYPE_ID) => media_type = u32_at(value, first),
            (SPA_FORMAT_MEDIA_SUBTYPE, SPA_TYPE_ID) => subtype = u32_at(value, first),
            (SPA_FORMAT_VIDEO_FORMAT, SPA_TYPE_ID) => format = u32_at(value, first),
            (SPA_FORMAT_VIDEO_SIZE, SPA_TYPE_RECTANGLE) => {
                dims = Some((u32_at(value, first)?, u32_at(value, first + 4)?));
            }
            (SPA_FORMAT_VIDEO_MODIFIER, _) => modifier = true,
            // A fraction cut short is left out; the format still parses.
            (SPA_FORMAT_VIDEO_MAX_FRAMERATE, SPA_TYPE_FRACTION) => {
                max_framerate = u32_at(value, first).zip(u32_at(value, first + 4));
            }
            _ => {}
        }
        // The value, then its padding to 8 bytes.
        at = body.checked_add(value_size.checked_add(7)? & !7)?;
    }
    if media_type.is_some_and(|t| t != SPA_MEDIA_TYPE_VIDEO)
        || subtype.is_some_and(|s| s != SPA_MEDIA_SUBTYPE_RAW)
    {
        return None;
    }
    let (width, height) = dims?;
    Some(Negotiated {
        format: format?,
        width,
        height,
        modifier,
        max_framerate,
    })
}

/// A pixel layout this backend reads: 4 bytes per pixel, 8 bits per channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PixelFormat {
    Bgrx,
    Bgra,
    Rgbx,
    Rgba,
}

impl PixelFormat {
    fn from_spa(id: u32) -> Option<Self> {
        Some(match id {
            SPA_VIDEO_FORMAT_BGRX => Self::Bgrx,
            SPA_VIDEO_FORMAT_BGRA => Self::Bgra,
            SPA_VIDEO_FORMAT_RGBX => Self::Rgbx,
            SPA_VIDEO_FORMAT_RGBA => Self::Rgba,
            _ => return None,
        })
    }

    /// Red first in memory: swapped into BGRx.
    fn red_first(self) -> bool {
        matches!(self, Self::Rgbx | Self::Rgba)
    }
}

/// A format this backend can read pictures in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VideoFormat {
    pub(crate) pixel: PixelFormat,
    pub(crate) width: u32,
    pub(crate) height: u32,
    /// What [`Negotiated::max_framerate`] said, for the log.
    pub(crate) max_framerate: Option<(u32, u32)>,
}

impl VideoFormat {
    pub(crate) fn check(negotiated: Negotiated) -> Result<Self, String> {
        if negotiated.modifier {
            return Err(
                "the compositor negotiated DMA-BUF buffers, which this build does not map".into(),
            );
        }
        let pixel = PixelFormat::from_spa(negotiated.format).ok_or_else(|| {
            format!(
                "the compositor negotiated pixel format {}, not an 8-bit RGB one",
                negotiated.format
            )
        })?;
        let (width, height) = (negotiated.width, negotiated.height);
        let pixels = u64::from(width) * u64::from(height);
        if pixels == 0 || pixels > MAX_PIXELS {
            return Err(format!(
                "the compositor negotiated a {width}x{height} picture"
            ));
        }
        Ok(Self {
            pixel,
            width,
            height,
            max_framerate: negotiated.max_framerate,
        })
    }
}

/// Why a buffer's picture could not be packed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackError {
    /// A picture with no pixels.
    Empty,
    /// The stride is negative or shorter than a row.
    Stride(i32),
    /// The chunk holds fewer bytes than the picture needs.
    Short { need: usize, got: usize },
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("the picture has no pixels"),
            Self::Stride(stride) => write!(f, "stride {stride} is shorter than a row"),
            Self::Short { need, got } => {
                write!(f, "the buffer holds {got} bytes, the picture needs {need}")
            }
        }
    }
}

/// Copy a `format` picture laid out `stride` bytes per row in `src` into
/// `out`, tightly packed BGRx. A stride of 0 means rows are packed. The
/// picture's own geometry is trusted only as far as `src` reaches: every row is
/// checked to lie inside it before any byte is copied.
pub(crate) fn pack(
    src: &[u8],
    stride: i32,
    format: VideoFormat,
    out: &mut Vec<u8>,
) -> Result<(), PackError> {
    let row = format.width as usize * 4;
    let height = format.height as usize;
    if row == 0 || height == 0 {
        return Err(PackError::Empty);
    }
    let stride = match usize::try_from(stride) {
        Ok(0) => row,
        Ok(stride) if stride >= row => stride,
        _ => return Err(PackError::Stride(stride)),
    };
    let need = (height - 1)
        .checked_mul(stride)
        .and_then(|n| n.checked_add(row))
        .unwrap_or(usize::MAX);
    if need > src.len() {
        return Err(PackError::Short {
            need,
            got: src.len(),
        });
    }
    out.clear();
    out.reserve(row * height);
    for line in src.chunks(stride).take(height) {
        out.extend_from_slice(line.get(..row).ok_or(PackError::Short {
            need,
            got: src.len(),
        })?);
    }
    if format.pixel.red_first() {
        for px in out.chunks_exact_mut(4) {
            px.swap(0, 2);
        }
    }
    Ok(())
}

// ---- What the callbacks and the capture thread share -------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    Connecting,
    Paused,
    Streaming,
    Failed(String),
}

/// Why a buffer carried no picture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Skip {
    /// No data plane.
    NoData,
    /// A DMA-BUF plane (not negotiated by this consumer's pod).
    DmaBuf,
    /// A plane that is not mapped.
    Unmapped,
    /// An empty chunk: mutter's cursor-only or damage-free buffer.
    Empty,
    /// The producer marked the chunk corrupted.
    Corrupted,
}

struct Inner {
    format: Option<VideoFormat>,
    status: Status,
    /// The newest picture not taken yet; a newer one replaces it.
    latest: Option<Frame>,
    /// A buffer to pack the next picture into.
    spare: Vec<u8>,
    delivered: u64,
    skipped: u64,
    /// A malformed buffer was already logged.
    warned: bool,
    /// This side closed the stream ([`Shared::close`]): no picture is kept.
    closed: bool,
}

/// The one-picture slot between the PipeWire callbacks and the capture thread.
pub(crate) struct Shared {
    inner: Mutex<Inner>,
    wake: Condvar,
    /// The negotiated picture size as `width << 32 | height`, 0 before any:
    /// read without the lock by the injector, which runs on the session's task.
    size: AtomicU64,
}

impl Shared {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                format: None,
                status: Status::Connecting,
                latest: None,
                spare: Vec::new(),
                delivered: 0,
                skipped: 0,
                warned: false,
                closed: false,
            }),
            wake: Condvar::new(),
            size: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'a>(&self, inner: MutexGuard<'a, Inner>, left: Duration) -> MutexGuard<'a, Inner> {
        self.wake
            .wait_timeout(inner, left)
            .unwrap_or_else(PoisonError::into_inner)
            .0
    }

    /// The negotiated picture size, once there is one.
    pub(crate) fn pixel_size(&self) -> Option<(u32, u32)> {
        let packed = self.size.load(Ordering::Acquire);
        (packed != 0).then_some(((packed >> 32) as u32, packed as u32))
    }

    /// The stream's state changed (`state_changed`).
    fn set_state(&self, state: c_int, error: Option<String>) {
        let status = match state {
            PW_STREAM_STATE_STREAMING => Status::Streaming,
            PW_STREAM_STATE_PAUSED => Status::Paused,
            PW_STREAM_STATE_CONNECTING => Status::Connecting,
            PW_STREAM_STATE_UNCONNECTED => Status::Failed(error.unwrap_or_else(|| {
                "the PipeWire stream was disconnected: the screen cast ended".to_owned()
            })),
            _ => Status::Failed(format!(
                "the PipeWire stream failed: {}",
                error.as_deref().unwrap_or("no reason given")
            )),
        };
        self.update(status);
    }

    fn update(&self, status: Status) {
        let mut inner = self.lock();
        // The first failure is the one worth reporting.
        if !matches!(inner.status, Status::Failed(_)) {
            if let Status::Failed(why) = &status {
                tracing::info!(reason = %why, "Wayland screen cast stopped");
            }
            inner.status = status;
        }
        drop(inner);
        self.wake.notify_all();
    }

    /// A `Format` param arrived (`param_changed`): `None` when it was cleared.
    pub(crate) fn set_format(&self, format: Result<Option<VideoFormat>, String>) {
        match format {
            Ok(format) => {
                if let Some(f) = format {
                    self.size.store(
                        (u64::from(f.width) << 32) | u64::from(f.height),
                        Ordering::Release,
                    );
                    tracing::debug!(
                        width = f.width,
                        height = f.height,
                        pixel = ?f.pixel,
                        max_framerate = ?f.max_framerate,
                        "PipeWire format negotiated"
                    );
                }
                self.lock().format = format;
                self.wake.notify_all();
            }
            Err(why) => self.update(Status::Failed(why)),
        }
    }

    /// A buffer arrived holding a picture in `plane`, `stride` bytes per row.
    pub(crate) fn offer(&self, plane: &[u8], stride: i32) {
        let mut inner = self.lock();
        // One that comes while the stream is torn down is let go of.
        if inner.closed {
            inner.skipped += 1;
            return;
        }
        let Some(format) = inner.format else {
            inner.skipped += 1;
            return;
        };
        let mut out = match inner.latest.take() {
            Some(unread) => unread.bgrx,
            None => std::mem::take(&mut inner.spare),
        };
        let started = Instant::now();
        match pack(plane, stride, format, &mut out) {
            Ok(()) => {
                let captured_at = Instant::now();
                inner.latest = Some(Frame {
                    width: format.width,
                    height: format.height,
                    bgrx: out,
                    captured_at,
                    grab: captured_at - started,
                });
                inner.delivered += 1;
                drop(inner);
                self.wake.notify_all();
            }
            Err(why) => {
                inner.spare = out;
                inner.skipped += 1;
                if !std::mem::replace(&mut inner.warned, true) {
                    tracing::warn!(%why, ?format, "a PipeWire buffer did not hold the negotiated picture; skipped");
                }
            }
        }
    }

    /// The capture thread is done with `bgrx`, a picture it took: the
    /// largest such buffer becomes the spare the next picture is packed
    /// into, so `offer` stops allocating one per picture. A closed slot
    /// keeps nothing ([`Shared::close`]): the buffer is dropped, after the
    /// lock is let go of, as is a spare it replaces.
    pub(crate) fn recycle(&self, bgrx: Vec<u8>) {
        let mut inner = self.lock();
        let unused = if inner.closed || bgrx.capacity() <= inner.spare.capacity() {
            bgrx
        } else {
            std::mem::replace(&mut inner.spare, bgrx)
        };
        drop(inner);
        drop(unused);
    }

    fn skip(&self, why: Skip) {
        let mut inner = self.lock();
        inner.skipped += 1;
        if why != Skip::Empty && !std::mem::replace(&mut inner.warned, true) {
            tracing::warn!(
                ?why,
                "a PipeWire buffer carried no readable picture; skipped"
            );
        }
    }

    /// The newest picture not taken yet, waiting at most `timeout` for one.
    /// `Ok(None)` when none came: the compositor sends a picture only when the
    /// screen changes.
    pub(crate) fn next(&self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let deadline = Instant::now().checked_add(timeout);
        let mut inner = self.lock();
        loop {
            if let Some(frame) = inner.latest.take() {
                return Ok(Some(frame));
            }
            if let Status::Failed(why) = &inner.status {
                return Err(CaptureError::Failed(why.clone()));
            }
            let left = deadline.map_or(Duration::from_secs(3600), |d| {
                d.saturating_duration_since(Instant::now())
            });
            if left.is_zero() {
                return Ok(None);
            }
            inner = self.wait(inner, left);
        }
    }

    /// Wait until a format is negotiated, the stream fails, or `timeout`.
    pub(crate) fn wait_negotiated(&self, timeout: Duration) -> Result<VideoFormat, CaptureError> {
        let deadline = Instant::now() + timeout;
        let mut inner = self.lock();
        loop {
            if let Status::Failed(why) = &inner.status {
                return Err(unavailable(why.clone()));
            }
            if let Some(format) = inner.format {
                return Ok(format);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(unavailable(format!(
                    "PipeWire negotiated no picture format within {} s (stream {:?})",
                    timeout.as_secs(),
                    inner.status
                )));
            }
            inner = self.wait(inner, left);
        }
    }

    /// This side is closing the stream: what PipeWire reports while it is torn
    /// down is not a failure worth logging, and the slot lets go of its
    /// picture and takes no other. The slot outlives the stream wherever a
    /// `WaylandInput` is kept (the session backend keeps one until the
    /// injector is built), and it must not keep the last full-size picture of
    /// the screen with it. Both happen under the slot's lock, which `offer`
    /// takes too, so no buffer can slip in between.
    fn close(&self) {
        let mut inner = self.lock();
        if !matches!(inner.status, Status::Failed(_)) {
            inner.status = Status::Failed("the screen capture was closed".to_owned());
        }
        inner.closed = true;
        let held = (inner.latest.take(), std::mem::take(&mut inner.spare));
        drop(inner);
        drop(held);
        self.wake.notify_all();
    }

    /// Whether the slot holds picture memory: an unread picture, or a buffer
    /// kept to pack the next one into.
    #[cfg(test)]
    fn holds_picture(&self) -> bool {
        let inner = self.lock();
        inner.latest.is_some() || inner.spare.capacity() > 0
    }

    /// Pictures delivered and buffers skipped so far.
    pub(crate) fn counts(&self) -> (u64, u64) {
        let inner = self.lock();
        (inner.delivered, inner.skipped)
    }
}

// ---- The callbacks -----------------------------------------------------------

/// What the callbacks are given as their `data`.
struct CallbackData {
    dequeue: DequeueFn,
    queue: QueueFn,
    stream: *mut PwStream,
    shared: Arc<Shared>,
}

static EVENTS: PwStreamEvents = PwStreamEvents {
    version: PW_VERSION_STREAM_EVENTS,
    destroy: None,
    state_changed: Some(on_state_changed),
    control_info: None,
    io_changed: None,
    param_changed: Some(on_param_changed),
    add_buffer: None,
    remove_buffer: None,
    process: Some(on_process),
    drained: None,
    command: None,
    trigger_done: None,
};

/// # Safety
///
/// `data` is the `CallbackData` this stream's listener was registered with.
unsafe fn callback_data<'a>(data: *mut c_void) -> &'a CallbackData {
    // SAFETY: the caller's contract; the data is freed only after
    // `pw_stream_destroy` returned, and PipeWire calls nothing after that.
    unsafe { &*data.cast::<CallbackData>() }
}

unsafe extern "C" fn on_state_changed(
    data: *mut c_void,
    _old: c_int,
    state: c_int,
    error: *const c_char,
) {
    // SAFETY: PipeWire passes the listener's data back unchanged.
    let data = unsafe { callback_data(data) };
    let error = (!error.is_null()).then(|| {
        // SAFETY: a non-NULL error is a NUL-terminated string valid for the call.
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    });
    data.shared.set_state(state, error);
}

unsafe extern "C" fn on_param_changed(data: *mut c_void, id: u32, param: *const SpaPod) {
    if id != SPA_PARAM_FORMAT {
        return;
    }
    // SAFETY: PipeWire passes the listener's data back unchanged.
    let data = unsafe { callback_data(data) };
    if param.is_null() {
        data.shared.set_format(Ok(None));
        return;
    }
    // SAFETY: a non-NULL param is a complete pod, valid for the call: an
    // 8-byte header followed by `size` bytes of body.
    let size = unsafe { (*param).size } as usize;
    if size > MAX_PARAM {
        data.shared.set_format(Err(format!(
            "a {size}-byte Format param is not a video format"
        )));
        return;
    }
    // SAFETY: as above; `8 + size` is the pod's whole length.
    let pod = unsafe { std::slice::from_raw_parts(param.cast::<u8>(), 8 + size) };
    let format = parse_format(pod)
        .ok_or_else(|| "the negotiated Format param is not raw video".to_owned())
        .and_then(VideoFormat::check)
        .map(Some);
    data.shared.set_format(format);
}

unsafe extern "C" fn on_process(data: *mut c_void) {
    // SAFETY: PipeWire passes the listener's data back unchanged.
    let data = unsafe { callback_data(data) };
    // SAFETY: `process` runs on the loop thread with the loop lock held, where
    // buffers may be dequeued.
    let buffer = unsafe { (data.dequeue)(data.stream) };
    if buffer.is_null() {
        return;
    }
    let held = Held { data, buffer };
    match held.plane() {
        Ok((plane, stride)) => data.shared.offer(plane, stride),
        Err(why) => data.shared.skip(why),
    }
}

/// A buffer dequeued in `on_process`. Dropping it queues the buffer back, so
/// every path through the callback returns it to the producer.
struct Held<'a> {
    data: &'a CallbackData,
    buffer: *mut PwBuffer,
}

impl Held<'_> {
    /// The mapped bytes of the buffer's first plane from its chunk's offset,
    /// and the chunk's stride.
    fn plane(&self) -> Result<(&[u8], i32), Skip> {
        // SAFETY: `buffer` was dequeued and is not queued back until `self`
        // drops; it, its `spa_buffer` and its `spa_data` array stay valid and
        // unchanged by the producer until then.
        let pw = unsafe { &*self.buffer };
        if pw.buffer.is_null() {
            return Err(Skip::NoData);
        }
        // SAFETY: as above.
        let spa = unsafe { &*pw.buffer };
        if spa.n_datas == 0 || spa.datas.is_null() {
            return Err(Skip::NoData);
        }
        // SAFETY: `datas` holds `n_datas` ≥ 1 entries.
        let plane = unsafe { &*spa.datas };
        if plane.ty == SPA_DATA_DMABUF {
            return Err(Skip::DmaBuf);
        }
        if plane.data.is_null() || plane.chunk.is_null() || plane.maxsize == 0 {
            return Err(Skip::Unmapped);
        }
        // SAFETY: the chunk is valid while the buffer is dequeued; it is copied
        // out once, so later reads cannot see it change.
        let chunk: SpaChunk = unsafe { plane.chunk.read() };
        if chunk.size == 0 {
            return Err(Skip::Empty);
        }
        if chunk.flags & SPA_CHUNK_FLAG_CORRUPTED != 0 {
            return Err(Skip::Corrupted);
        }
        let offset = (chunk.offset % plane.maxsize) as usize;
        let len = (chunk.size as usize).min(plane.maxsize as usize - offset);
        // SAFETY: `MAP_BUFFERS` mapped `maxsize` bytes at `data` (a `MemPtr`
        // plane is memory of that size already); `offset + len <= maxsize`.
        let bytes = unsafe { std::slice::from_raw_parts(plane.data.cast::<u8>().add(offset), len) };
        Ok((bytes, chunk.stride))
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        // SAFETY: the buffer was dequeued from this stream in this callback, on
        // the loop thread, and is queued back exactly once, here.
        unsafe { (self.data.queue)(self.data.stream, self.buffer) };
    }
}

// ---- The stream ----------------------------------------------------------------

/// A PipeWire stream consuming the portal's screen-cast node.
pub(crate) struct PwCapture {
    api: &'static Api,
    thread_loop: *mut PwThreadLoop,
    context: *mut PwContext,
    core: *mut PwCore,
    stream: *mut PwStream,
    hook: *mut SpaHook,
    data: *mut CallbackData,
    shared: Arc<Shared>,
}

// SAFETY: the raw pointers are PipeWire objects and two heap blocks that this
// value alone owns. The objects are used only with the thread loop's lock held,
// or after the loop has stopped, which is how PipeWire lets a thread loop's
// objects be driven from any thread (`thread-loop.h`); the heap blocks are read
// by the callbacks and freed only after `pw_stream_destroy`.
unsafe impl Send for PwCapture {}

impl PwCapture {
    /// Connect to the portal's PipeWire remote (`fd`, from
    /// `OpenPipeWireRemote`) and consume node `node`.
    /// With `max_fps`, the stream asks for at most that many pictures a
    /// second ([`enum_format_pod`]).
    pub(crate) fn connect(
        fd: OwnedFd,
        node: u32,
        max_fps: Option<u32>,
    ) -> Result<Self, CaptureError> {
        let api = api()?;
        // SAFETY: a plain constructor; a NULL property dictionary is allowed.
        let thread_loop = unsafe { (api.thread_loop_new)(c"tornect-pipewire".as_ptr(), null()) };
        if thread_loop.is_null() {
            return Err(unavailable("pw_thread_loop_new failed"));
        }
        let mut capture = Self {
            api,
            thread_loop,
            context: null_mut(),
            core: null_mut(),
            stream: null_mut(),
            hook: null_mut(),
            data: null_mut(),
            shared: Arc::new(Shared::new()),
        };
        // SAFETY: a thread loop that has not been started.
        if unsafe { (api.thread_loop_start)(thread_loop) } < 0 {
            return Err(unavailable("PipeWire's thread loop did not start"));
        }
        // SAFETY: the loop runs; the lock is released just below.
        unsafe { (api.thread_loop_lock)(thread_loop) };
        let connected = capture.connect_locked(fd, node, max_fps);
        // SAFETY: taken just above, on this thread.
        unsafe { (api.thread_loop_unlock)(thread_loop) };
        connected.map(|()| capture)
    }

    /// The part of [`Self::connect`] made with the loop lock held. On an error
    /// the caller drops `self`, which releases whatever was made.
    fn connect_locked(
        &mut self,
        fd: OwnedFd,
        node: u32,
        max_fps: Option<u32>,
    ) -> Result<(), CaptureError> {
        let api = self.api;
        // SAFETY: the loop lock is held (caller); the loop outlives the context,
        // which `Drop` destroys first.
        self.context = unsafe {
            (api.context_new)((api.thread_loop_get_loop)(self.thread_loop), null_mut(), 0)
        };
        if self.context.is_null() {
            return Err(unavailable("pw_context_new failed"));
        }
        // SAFETY: `pw_context_connect_fd` owns the descriptor from here on (it
        // closes it on disconnect or error), so Rust gives up ownership of it.
        self.core =
            unsafe { (api.context_connect_fd)(self.context, fd.into_raw_fd(), null_mut(), 0) };
        if self.core.is_null() {
            return Err(unavailable(format!(
                "cannot connect to the portal's PipeWire remote: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: a NUL-terminated string.
        let props = unsafe { (api.properties_new_string)(STREAM_PROPS.as_ptr()) };
        // SAFETY: a connected core; `pw_stream_new` takes ownership of `props`,
        // which may be NULL.
        self.stream = unsafe { (api.stream_new)(self.core, c"tornect-capture".as_ptr(), props) };
        if self.stream.is_null() {
            return Err(unavailable("pw_stream_new failed"));
        }
        self.hook = Box::into_raw(Box::new(SpaHook::zeroed()));
        self.data = Box::into_raw(Box::new(CallbackData {
            dequeue: api.stream_dequeue_buffer,
            queue: api.stream_queue_buffer,
            stream: self.stream,
            shared: Arc::clone(&self.shared),
        }));
        // SAFETY: `hook` and `data` stay allocated, at the same address, until
        // after `pw_stream_destroy` (see `Drop`); `EVENTS` is static.
        unsafe { (api.stream_add_listener)(self.stream, self.hook, &EVENTS, self.data.cast()) };
        let pod = enum_format_pod(max_fps);
        let mut params = [pod.as_ptr()];
        // SAFETY: `params` holds one valid, 8-byte-aligned pod, which PipeWire
        // copies before returning (`stream.c` 238–278).
        let result = unsafe {
            (api.stream_connect)(
                self.stream,
                PW_DIRECTION_INPUT,
                node,
                PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS,
                params.as_mut_ptr(),
                1,
            )
        };
        if result < 0 {
            return Err(unavailable(format!(
                "cannot connect a PipeWire stream to node {node}: {}",
                std::io::Error::from_raw_os_error(-result)
            )));
        }
        Ok(())
    }

    /// The slot the callbacks fill.
    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }
}

impl Drop for PwCapture {
    fn drop(&mut self) {
        let api = self.api;
        self.shared.close();
        // SAFETY: the teardown order of report §4.4. The loop object exists until
        // the last call; the stream, the core and the context are destroyed at
        // most once, each only if it was made; the loop is stopped without its
        // lock, as `thread-loop.h` requires.
        unsafe {
            (api.thread_loop_lock)(self.thread_loop);
            if !self.stream.is_null() {
                (api.stream_disconnect)(self.stream);
                (api.stream_destroy)(self.stream);
            }
            if !self.core.is_null() {
                (api.core_disconnect)(self.core);
            }
            (api.thread_loop_unlock)(self.thread_loop);
            (api.thread_loop_stop)(self.thread_loop);
            if !self.context.is_null() {
                (api.context_destroy)(self.context);
            }
            (api.thread_loop_destroy)(self.thread_loop);
        }
        // SAFETY: both came from `Box::into_raw` in `connect_locked`, and
        // `pw_stream_destroy` above removed the listener, so nothing reads them.
        unsafe {
            if !self.data.is_null() {
                drop(Box::from_raw(self.data));
            }
            if !self.hook.is_null() {
                drop(Box::from_raw(self.hook));
            }
        }
        let (delivered, skipped) = self.shared.counts();
        tracing::debug!(delivered, skipped, "PipeWire stream closed");
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// The pod of report §4.6, word by word (all fields `u32`, native order).
    const EXPECTED: [u32; 58] = [
        224, 15, // 0x00 object body size (232 − 8), SPA_TYPE_Object
        0x40003, 3, // 0x08 SPA_TYPE_OBJECT_Format, id SPA_PARAM_EnumFormat
        1, 0, // 0x10 key mediaType, flags
        4, 3, 2, 0, // 0x18 Id pod: size 4, type Id, video, padding
        2, 0, // 0x28 key mediaSubtype, flags
        4, 3, 1, 0, // 0x30 Id raw, padding
        0x20001, 0, // 0x40 key VIDEO_format, flags
        36, 19, // 0x48 Choice pod, body 8 + 8 + 5 × 4
        3, 0, // 0x50 SPA_CHOICE_Enum, choice flags
        4, 3, // 0x58 child: element size 4, type Id
        8, 8, 12, 7, 11, 0, // 0x60 BGRx (default), BGRx, BGRA, RGBx, RGBA, padding
        0x20003, 0, // 0x78 key VIDEO_size, flags
        40, 19, // 0x80 Choice, body 8 + 8 + 3 × 8
        1, 0, // 0x88 SPA_CHOICE_Range
        8, 10, // 0x90 child: element size 8, Rectangle
        1920, 1080, 1, 1, 8192, 8192, // 0x98 default, min, max
        0x20004, 0, // 0xB0 key VIDEO_framerate, flags
        40, 19, // 0xB8 Choice
        1, 0, // 0xC0 Range
        8, 11, // 0xC8 child: element size 8, Fraction
        30, 1, 0, 1, 1000, 1, // 0xD0 default 30/1, min 0/1, max 1000/1
    ];

    #[test]
    fn the_enum_format_pod_is_the_232_bytes_of_the_report() {
        let pod = enum_format_pod(None);
        let expected: Vec<u8> = EXPECTED.iter().flat_map(|w| w.to_ne_bytes()).collect();
        assert_eq!(expected.len(), 232);
        assert_eq!(pod.bytes(), expected);
        assert_eq!(
            pod.as_ptr() as usize % 8,
            0,
            "PipeWire reads pods 8-byte aligned"
        );
        // Read back, its defaults are what a fixated format would say.
        assert_eq!(
            parse_format(&pod.bytes()),
            Some(Negotiated {
                format: SPA_VIDEO_FORMAT_BGRX,
                width: 1920,
                height: 1080,
                modifier: false,
                max_framerate: None,
            })
        );
    }

    /// The report's pod with a `maxFramerate` of 20/1 appended (the quality
    /// design §6.4): 14 words more, 288 bytes.
    #[rustfmt::skip]
    const EXPECTED_MAX20: [u32; 72] = {
        let mut words = [0u32; 72];
        let mut i = 0;
        while i < 58 {
            words[i] = EXPECTED[i];
            i += 1;
        }
        words[0] = 280; // the object body grows by 56 bytes
        let tail: [u32; 14] = [
            0x20005, 0, // 0xE8 key VIDEO_maxFramerate, flags
            40, 19, // 0xF0 Choice, body 8 + 8 + 3 × 8
            1, 0, // 0xF8 Range
            8, 11, // 0x100 child: element size 8, Fraction
            20, 1, 1, 1, 20, 1, // 0x108 default 20/1, min 1/1, max 20/1
        ];
        while i < 72 {
            words[i] = tail[i - 58];
            i += 1;
        }
        words
    };

    #[test]
    fn a_frame_rate_cap_appends_max_framerate_and_nothing_else() {
        let pod = enum_format_pod(Some(20));
        let expected: Vec<u8> = EXPECTED_MAX20
            .iter()
            .flat_map(|w| w.to_ne_bytes())
            .collect();
        assert_eq!(expected.len(), 288);
        assert_eq!(pod.bytes(), expected);
        assert_eq!(pod.as_ptr() as usize % 8, 0);
        // The pod reads back whole, its cap with it.
        assert_eq!(
            parse_format(&pod.bytes()),
            Some(Negotiated {
                format: SPA_VIDEO_FORMAT_BGRX,
                width: 1920,
                height: 1080,
                modifier: false,
                max_framerate: Some((20, 1)),
            })
        );
        // Held to 1 ..= MAX_POD_FPS: the default and the maximum say it.
        for (asked, held) in [
            (0, 1),
            (1, 1),
            (60, 60),
            (120, 120),
            (121, 120),
            (u32::MAX, 120),
        ] {
            let bytes = enum_format_pod(Some(asked)).bytes();
            assert_eq!(bytes.len(), 288, "{asked}");
            let words: Vec<u32> = bytes
                .chunks_exact(4)
                .map(|w| u32::from_ne_bytes(w.try_into().unwrap()))
                .collect();
            assert_eq!(&words[66..72], &[held, 1, 1, 1, held, 1], "{asked}");
            assert_eq!(&words[..58], &EXPECTED_MAX20[..58], "{asked}");
        }
    }

    /// The mirrors, as the 1.6.2 headers lay them out on LP64 (also asserted at
    /// compile time).
    #[test]
    fn the_abi_mirrors_have_the_header_layouts() {
        assert_eq!(size_of::<PwStreamEvents>(), 96);
        assert_eq!(offset_of!(PwStreamEvents, version), 0);
        assert_eq!(offset_of!(PwStreamEvents, destroy), 8);
        assert_eq!(offset_of!(PwStreamEvents, state_changed), 16);
        assert_eq!(offset_of!(PwStreamEvents, control_info), 24);
        assert_eq!(offset_of!(PwStreamEvents, io_changed), 32);
        assert_eq!(offset_of!(PwStreamEvents, param_changed), 40);
        assert_eq!(offset_of!(PwStreamEvents, add_buffer), 48);
        assert_eq!(offset_of!(PwStreamEvents, remove_buffer), 56);
        assert_eq!(offset_of!(PwStreamEvents, process), 64);
        assert_eq!(offset_of!(PwStreamEvents, drained), 72);
        assert_eq!(offset_of!(PwStreamEvents, command), 80);
        assert_eq!(offset_of!(PwStreamEvents, trigger_done), 88);
        assert_eq!(size_of::<SpaHook>(), 48);
        assert_eq!(size_of::<SpaPod>(), 8);
        assert_eq!(
            [
                size_of::<PwBuffer>(),
                offset_of!(PwBuffer, user_data),
                offset_of!(PwBuffer, size),
                offset_of!(PwBuffer, requested),
                offset_of!(PwBuffer, time),
            ],
            [40, 8, 16, 24, 32]
        );
        assert_eq!(
            [
                size_of::<SpaBuffer>(),
                offset_of!(SpaBuffer, n_datas),
                offset_of!(SpaBuffer, metas),
                offset_of!(SpaBuffer, datas),
            ],
            [24, 4, 8, 16]
        );
        assert_eq!(
            [
                size_of::<SpaData>(),
                offset_of!(SpaData, flags),
                offset_of!(SpaData, fd),
                offset_of!(SpaData, mapoffset),
                offset_of!(SpaData, maxsize),
                offset_of!(SpaData, data),
                offset_of!(SpaData, chunk),
            ],
            [40, 4, 8, 16, 20, 24, 32]
        );
        assert_eq!(
            [
                size_of::<SpaChunk>(),
                offset_of!(SpaChunk, size),
                offset_of!(SpaChunk, stride),
                offset_of!(SpaChunk, flags),
            ],
            [16, 4, 8, 12]
        );
    }

    /// A `Format` object pod as mutter fixates it: `object` wraps the property
    /// words (each already padded to 8 bytes).
    fn object(props: &[&[u32]]) -> Vec<u8> {
        let body: Vec<u32> = [SPA_TYPE_OBJECT_FORMAT, SPA_PARAM_FORMAT]
            .into_iter()
            .chain(props.iter().flat_map(|p| p.iter().copied()))
            .collect();
        [(body.len() * 4) as u32, SPA_TYPE_OBJECT]
            .into_iter()
            .chain(body)
            .flat_map(u32::to_ne_bytes)
            .collect()
    }

    // Property words as a fixated `Format` carries them: key, flags, then the
    // value pod (size, type, body), each padded to 8 bytes.
    #[rustfmt::skip]
    const VIDEO: &[u32] = &[SPA_FORMAT_MEDIA_TYPE, 0, 4, SPA_TYPE_ID, SPA_MEDIA_TYPE_VIDEO, 0];
    #[rustfmt::skip]
    const RAW: &[u32] = &[SPA_FORMAT_MEDIA_SUBTYPE, 0, 4, SPA_TYPE_ID, SPA_MEDIA_SUBTYPE_RAW, 0];
    #[rustfmt::skip]
    const BGRX: &[u32] = &[SPA_FORMAT_VIDEO_FORMAT, 0, 4, SPA_TYPE_ID, SPA_VIDEO_FORMAT_BGRX, 0];
    const SIZE: &[u32] = &[SPA_FORMAT_VIDEO_SIZE, 0, 8, SPA_TYPE_RECTANGLE, 1280, 800];
    const RATE: &[u32] = &[SPA_FORMAT_VIDEO_FRAMERATE, 0, 8, SPA_TYPE_FRACTION, 0, 1];
    /// `maxFramerate` as mutter sends it: a Range of fractions (60/1; 1/1 to 60/1).
    #[rustfmt::skip]
    const MAX_RATE: &[u32] = &[
        0x20005, 0, 40, SPA_TYPE_CHOICE,
        SPA_CHOICE_RANGE, 0, 8, SPA_TYPE_FRACTION,
        60, 1, 1, 1, 60, 1,
    ];

    #[test]
    fn the_negotiated_size_and_format_are_read_from_the_param() {
        let pod = object(&[VIDEO, RAW, BGRX, SIZE, RATE, MAX_RATE]);
        let want = Negotiated {
            format: SPA_VIDEO_FORMAT_BGRX,
            width: 1280,
            height: 800,
            modifier: false,
            max_framerate: Some((60, 1)),
        };
        assert_eq!(parse_format(&pod), Some(want));
        assert_eq!(
            VideoFormat::check(want),
            Ok(VideoFormat {
                pixel: PixelFormat::Bgrx,
                width: 1280,
                height: 800,
                max_framerate: Some((60, 1)),
            })
        );
        let want = Negotiated {
            max_framerate: None,
            ..want
        };
        // A value wrapped in a one-element Choice (None) reads the same.
        #[rustfmt::skip]
        let size_choice: &[u32] = &[
            SPA_FORMAT_VIDEO_SIZE, 0, 24, SPA_TYPE_CHOICE,
            0, 0, 8, SPA_TYPE_RECTANGLE, // SPA_CHOICE_None, one Rectangle
            1280, 800,
        ];
        assert_eq!(
            parse_format(&object(&[VIDEO, RAW, BGRX, size_choice])),
            Some(want)
        );
        // Trailing bytes past the pod's own size are ignored.
        let mut longer = pod.clone();
        longer.extend_from_slice(&[0xAA; 24]);
        assert_eq!(
            parse_format(&longer),
            Some(Negotiated {
                max_framerate: Some((60, 1)),
                ..want
            })
        );
    }

    /// `maxFramerate` (the quality design §6.4): read from its own bytes only,
    /// plain or as a Choice; a fraction cut short, or a value of another type,
    /// leaves it out and the format still parses; one that runs past the pod
    /// is a malformed pod, as any value is.
    #[test]
    fn max_framerate_is_read_when_whole_and_never_fails_the_format() {
        let want = |max_framerate| Negotiated {
            format: SPA_VIDEO_FORMAT_BGRX,
            width: 1280,
            height: 800,
            modifier: false,
            max_framerate,
        };
        let plain: &[u32] = &[0x20005, 0, 8, SPA_TYPE_FRACTION, 20, 1];
        assert_eq!(
            parse_format(&object(&[VIDEO, RAW, BGRX, SIZE, plain])),
            Some(want(Some((20, 1))))
        );
        // The cap before the size: the order of properties does not matter.
        assert_eq!(
            parse_format(&object(&[VIDEO, MAX_RATE, RAW, BGRX, SIZE, RATE])),
            Some(want(Some((60, 1))))
        );
        // A fraction whose value holds 4 bytes, not 8: the denominator would be
        // the next property's key, so the cap is left out.
        let cut: &[u32] = &[0x20005, 0, 4, SPA_TYPE_FRACTION, 20, 0];
        assert_eq!(
            parse_format(&object(&[VIDEO, RAW, BGRX, cut, SIZE])),
            Some(want(None))
        );
        // A Range whose elements say 8 bytes but whose body holds only the
        // numerator of the first.
        #[rustfmt::skip]
        let short_choice: &[u32] = &[
            0x20005, 0, 20, SPA_TYPE_CHOICE,
            SPA_CHOICE_RANGE, 0, 8, SPA_TYPE_FRACTION,
            60, 0,
        ];
        assert_eq!(
            parse_format(&object(&[VIDEO, RAW, BGRX, short_choice, SIZE])),
            Some(want(None))
        );
        // Another type under the key is not a cap.
        let as_int: &[u32] = &[0x20005, 0, 4, 4, 20, 0];
        assert_eq!(
            parse_format(&object(&[VIDEO, RAW, BGRX, SIZE, as_int])),
            Some(want(None))
        );
        // A value that claims to run past the pod fails it, as for any key.
        let runaway: &[u32] = &[0x20005, 0, 4096, SPA_TYPE_FRACTION, 20, 1];
        assert_eq!(
            parse_format(&object(&[VIDEO, RAW, BGRX, SIZE, runaway])),
            None
        );
        // The pod cut inside the cap: malformed.
        let pod = object(&[VIDEO, RAW, BGRX, SIZE, MAX_RATE]);
        for cut in [pod.len() - 4, pod.len() - 12, pod.len() - 24] {
            assert_eq!(parse_format(&pod[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn a_malformed_or_foreign_param_is_refused() {
        let pod = object(&[VIDEO, RAW, BGRX, SIZE]);
        // Truncated anywhere: the header, a property, a value.
        for cut in [0, 7, 15, 20, pod.len() - 4] {
            assert_eq!(parse_format(&pod[..cut]), None, "cut at {cut}");
        }
        // No size, or no format.
        assert_eq!(parse_format(&object(&[VIDEO, RAW, BGRX])), None);
        assert_eq!(parse_format(&object(&[VIDEO, RAW, SIZE])), None);
        // Audio, or not an object at all.
        let audio: &[u32] = &[SPA_FORMAT_MEDIA_TYPE, 0, 4, SPA_TYPE_ID, 1, 0];
        assert_eq!(parse_format(&object(&[audio, RAW, BGRX, SIZE])), None);
        let mut not_object = pod.clone();
        not_object[4..8].copy_from_slice(&SPA_TYPE_CHOICE.to_ne_bytes());
        assert_eq!(parse_format(&not_object), None);
        // A Choice that holds no element makes the pod malformed; its "first
        // value" is never read from the property after it (here the frame
        // rate's key, which would have become the width).
        #[rustfmt::skip]
        let empty_choice: &[u32] = &[
            SPA_FORMAT_VIDEO_SIZE, 0, 16, SPA_TYPE_CHOICE,
            0, 0, 8, SPA_TYPE_RECTANGLE,
        ];
        assert_eq!(
            parse_format(&object(&[VIDEO, RAW, BGRX, empty_choice, RATE])),
            None
        );
        assert_eq!(
            parse_format(&object(&[VIDEO, RAW, BGRX, empty_choice])),
            None
        );
        // A value that claims to run past the pod.
        let runaway: &[u32] = &[SPA_FORMAT_VIDEO_SIZE, 0, 4096, SPA_TYPE_RECTANGLE, 1, 1];
        assert_eq!(parse_format(&object(&[VIDEO, RAW, BGRX, runaway])), None);
        // A modifier means DMA-BUF, which is read but refused.
        let modifier: &[u32] = &[SPA_FORMAT_VIDEO_MODIFIER, 8, 8, 5, 0, 0];
        let dmabuf = parse_format(&object(&[VIDEO, RAW, BGRX, SIZE, modifier])).unwrap();
        assert!(dmabuf.modifier);
        assert!(VideoFormat::check(dmabuf).is_err());
        // Neither an unknown pixel format nor an empty or enormous picture passes.
        let i420 = Negotiated {
            format: 2,
            ..dmabuf
        };
        assert!(
            VideoFormat::check(Negotiated {
                modifier: false,
                ..i420
            })
            .is_err()
        );
        for (width, height) in [(0, 800), (1280, 0), (65_536, 65_536)] {
            let n = Negotiated {
                format: SPA_VIDEO_FORMAT_BGRA,
                width,
                height,
                modifier: false,
                max_framerate: None,
            };
            assert!(VideoFormat::check(n).is_err(), "{width}x{height}");
        }
    }

    fn format(pixel: PixelFormat, width: u32, height: u32) -> VideoFormat {
        VideoFormat {
            pixel,
            width,
            height,
            max_framerate: None,
        }
    }

    #[test]
    fn rows_are_packed_by_the_chunk_stride_and_turned_into_bgrx() {
        // 2×2, stride 12 (4 bytes of row padding), pixels numbered.
        let src: Vec<u8> = (0..24).collect();
        let mut out = vec![0xEE; 3];
        pack(&src, 12, format(PixelFormat::Bgrx, 2, 2), &mut out).unwrap();
        assert_eq!(
            out,
            [0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15, 16, 17, 18, 19]
        );
        // Stride 0 means packed rows; BGRA keeps its bytes.
        pack(&src[..16], 0, format(PixelFormat::Bgra, 2, 2), &mut out).unwrap();
        assert_eq!(out, (0..16).collect::<Vec<u8>>());
        // RGBx and RGBA swap red and blue.
        pack(&src[..8], 8, format(PixelFormat::Rgbx, 2, 1), &mut out).unwrap();
        assert_eq!(out, [2, 1, 0, 3, 6, 5, 4, 7]);
        pack(&src[..4], 4, format(PixelFormat::Rgba, 1, 1), &mut out).unwrap();
        assert_eq!(out, [2, 1, 0, 3]);
        // The last row needs only its own bytes, not a whole stride.
        pack(&src[..20], 12, format(PixelFormat::Bgrx, 2, 2), &mut out).unwrap();
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn a_short_buffer_or_bad_stride_is_refused_before_any_copy() {
        let src = vec![7u8; 32];
        let mut out = vec![1, 2, 3];
        // 2×3 at stride 12 needs 2 × 12 + 8 = 32 bytes: exactly enough.
        assert_eq!(
            pack(&src, 12, format(PixelFormat::Bgrx, 2, 3), &mut out),
            Ok(())
        );
        assert_eq!(
            pack(&src[..31], 12, format(PixelFormat::Bgrx, 2, 3), &mut out),
            Err(PackError::Short { need: 32, got: 31 })
        );
        assert_eq!(
            pack(&src, 4, format(PixelFormat::Bgrx, 2, 2), &mut out),
            Err(PackError::Stride(4))
        );
        assert_eq!(
            pack(&src, -8, format(PixelFormat::Bgrx, 2, 2), &mut out),
            Err(PackError::Stride(-8))
        );
        assert_eq!(
            pack(&src, 8, format(PixelFormat::Bgrx, 0, 2), &mut out),
            Err(PackError::Empty)
        );
        assert_eq!(
            pack(&src, 8, format(PixelFormat::Bgrx, 2, 0), &mut out),
            Err(PackError::Empty)
        );
        // A geometry whose byte count overflows is short, not a wrap.
        let huge = format(PixelFormat::Bgrx, 1 << 16, 1 << 16);
        assert!(matches!(
            pack(&src, i32::MAX, huge, &mut out),
            Err(PackError::Short { .. })
        ));
    }

    #[test]
    fn a_missing_library_is_unavailable_and_says_which() {
        let err = Api::load("libpipewire-tornect-test-missing.so.0")
            .err()
            .unwrap();
        assert!(
            err.contains("libpipewire-tornect-test-missing.so.0"),
            "{err}"
        );
        assert!(err.contains("PipeWire"), "{err}");
    }

    /// On a machine with PipeWire (the dev VM has 1.6.2), every function this
    /// backend calls resolves by name. Nothing is initialized or connected.
    #[test]
    fn the_installed_library_has_every_function() {
        match Api::load(LIBRARY) {
            Ok(_) => {}
            Err(why) if why.starts_with("cannot load") => {} // no PipeWire here
            Err(why) => panic!("{why}"),
        }
    }

    // ---- The callbacks, against buffers built in Rust ------------------------

    thread_local! {
        /// Buffers the fake `pw_stream_dequeue_buffer` hands out, last first.
        static READY: RefCell<Vec<*mut PwBuffer>> = const { RefCell::new(Vec::new()) };
        /// Buffers the fake `pw_stream_queue_buffer` got back.
        static RETURNED: RefCell<Vec<*mut PwBuffer>> = const { RefCell::new(Vec::new()) };
    }

    unsafe extern "C" fn fake_dequeue(_: *mut PwStream) -> *mut PwBuffer {
        READY.with(|r| r.borrow_mut().pop()).unwrap_or(null_mut())
    }

    unsafe extern "C" fn fake_queue(_: *mut PwStream, buffer: *mut PwBuffer) -> c_int {
        RETURNED.with(|r| r.borrow_mut().push(buffer));
        0
    }

    fn fake_data() -> CallbackData {
        CallbackData {
            dequeue: fake_dequeue,
            queue: fake_queue,
            stream: null_mut(),
            shared: Arc::new(Shared::new()),
        }
    }

    /// One buffer of one plane, as PipeWire hands it over. The linked structs
    /// are built inside [`Fake::process`], from these fields.
    struct Fake {
        pixels: Vec<u8>,
        chunk: SpaChunk,
        ty: u32,
        mapped: bool,
        n_datas: u32,
        has_spa_buffer: bool,
    }

    impl Fake {
        fn new(pixels: Vec<u8>, chunk: SpaChunk) -> Self {
            Self {
                pixels,
                chunk,
                ty: 2, // MemFd, mapped by MAP_BUFFERS
                mapped: true,
                n_datas: 1,
                has_spa_buffer: true,
            }
        }

        /// Run `on_process` with this buffer ready; whether it was queued back.
        fn process(&mut self, data: &CallbackData) -> bool {
            let mut chunk = self.chunk;
            let mut plane = SpaData {
                ty: self.ty,
                flags: 0,
                fd: -1,
                mapoffset: 0,
                maxsize: self.pixels.len() as u32,
                data: if self.mapped {
                    self.pixels.as_mut_ptr().cast()
                } else {
                    null_mut()
                },
                chunk: &raw mut chunk,
            };
            let mut spa = SpaBuffer {
                n_metas: 0,
                n_datas: self.n_datas,
                metas: null_mut(),
                datas: &raw mut plane,
            };
            let mut pw = PwBuffer {
                buffer: if self.has_spa_buffer {
                    &raw mut spa
                } else {
                    null_mut()
                },
                user_data: null_mut(),
                size: 0,
                requested: 0,
                time: 0,
            };
            let ptr: *mut PwBuffer = &raw mut pw;
            READY.with(|r| r.borrow_mut().push(ptr));
            RETURNED.with(|r| r.borrow_mut().clear());
            let data_ptr: *const CallbackData = data;
            // SAFETY: `data` is a live `CallbackData` whose fake functions hand
            // out and take back `pw`, which outlives the call.
            unsafe { on_process(data_ptr.cast_mut().cast()) };
            RETURNED.with(|r| r.borrow().as_slice() == [ptr])
        }
    }

    fn chunk(offset: u32, size: u32, stride: i32, flags: i32) -> SpaChunk {
        SpaChunk {
            offset,
            size,
            stride,
            flags,
        }
    }

    #[test]
    fn every_buffer_goes_back_and_only_a_good_one_is_a_picture() {
        let data = fake_data();
        data.shared
            .set_format(Ok(Some(format(PixelFormat::Bgrx, 2, 2))));
        // Good: 4 bytes of leading offset, stride 12.
        let pixels: Vec<u8> = (0..28).collect();
        assert!(Fake::new(pixels.clone(), chunk(4, 24, 12, 0)).process(&data));
        let frame = data.shared.next(Duration::ZERO).unwrap().unwrap();
        assert_eq!((frame.width, frame.height), (2, 2));
        assert_eq!(
            frame.bgrx,
            [4, 5, 6, 7, 8, 9, 10, 11, 16, 17, 18, 19, 20, 21, 22, 23]
        );
        // Every other kind of buffer is queued back and yields nothing.
        let good = || Fake::new(pixels.clone(), chunk(0, 24, 12, 0));
        let cases = [
            ("empty chunk", Fake::new(pixels.clone(), chunk(0, 0, 12, 0))),
            ("corrupted", Fake::new(pixels.clone(), chunk(0, 24, 12, 1))),
            (
                // 2 × 2 at stride 12 needs 12 + 8 = 20 bytes.
                "short",
                Fake::new(pixels[..19].to_vec(), chunk(0, 19, 12, 0)),
            ),
            ("bad stride", Fake::new(pixels.clone(), chunk(0, 24, 4, 0))),
            (
                "dmabuf",
                Fake {
                    ty: SPA_DATA_DMABUF,
                    ..good()
                },
            ),
            (
                "unmapped",
                Fake {
                    mapped: false,
                    ..good()
                },
            ),
            (
                "no planes",
                Fake {
                    n_datas: 0,
                    ..good()
                },
            ),
            (
                "no spa_buffer",
                Fake {
                    has_spa_buffer: false,
                    ..good()
                },
            ),
        ];
        for (what, mut buffer) in cases {
            assert!(buffer.process(&data), "{what}: not queued back");
            assert!(
                data.shared.next(Duration::ZERO).unwrap().is_none(),
                "{what}"
            );
        }
        // A chunk offset past the mapping wraps, as PipeWire's ring does, and
        // never reads outside it.
        assert!(Fake::new(pixels, chunk(28 + 4, 24, 12, 0)).process(&data));
        assert_eq!(
            data.shared.next(Duration::ZERO).unwrap().unwrap().bgrx,
            frame.bgrx
        );
        // No buffer ready: nothing to queue back.
        RETURNED.with(|r| r.borrow_mut().clear());
        let data_ptr: *const CallbackData = &data;
        // SAFETY: as in `Fake::process`; the fake dequeue returns NULL.
        unsafe { on_process(data_ptr.cast_mut().cast()) };
        assert!(RETURNED.with(|r| r.borrow().is_empty()));
    }

    #[test]
    fn before_a_format_nothing_is_a_picture_and_the_newest_wins() {
        let data = fake_data();
        assert!(Fake::new(vec![1; 16], chunk(0, 16, 8, 0)).process(&data));
        assert!(data.shared.next(Duration::ZERO).unwrap().is_none());
        data.shared
            .set_format(Ok(Some(format(PixelFormat::Bgrx, 2, 2))));
        assert_eq!(data.shared.pixel_size(), Some((2, 2)));
        assert!(Fake::new(vec![2; 16], chunk(0, 16, 8, 0)).process(&data));
        assert!(Fake::new(vec![3; 16], chunk(0, 16, 8, 0)).process(&data));
        assert_eq!(
            data.shared.next(Duration::ZERO).unwrap().unwrap().bgrx,
            [3; 16]
        );
        assert!(
            data.shared
                .next(Duration::from_millis(20))
                .unwrap()
                .is_none()
        );
    }

    /// Once this side closes the stream the slot holds no picture, unread or
    /// spare, and takes none from a buffer that comes while the stream is
    /// torn down: what still holds the slot (a kept `WaylandInput`) holds no
    /// screen.
    #[test]
    fn a_closed_slot_keeps_no_picture() {
        let good = || Fake::new(vec![7; 16], chunk(0, 16, 8, 0));
        for spare in [false, true] {
            let data = fake_data();
            data.shared
                .set_format(Ok(Some(format(PixelFormat::Bgrx, 2, 2))));
            assert!(good().process(&data));
            if spare {
                // A buffer that does not pack hands the unread picture's
                // memory to the spare.
                assert!(Fake::new(vec![7; 24], chunk(0, 24, 4, 0)).process(&data));
                assert!(data.shared.next(Duration::ZERO).unwrap().is_none());
            }
            assert!(data.shared.holds_picture(), "spare {spare}");
            data.shared.close();
            assert!(!data.shared.holds_picture(), "spare {spare}");
            assert!(good().process(&data), "queued back");
            assert!(!data.shared.holds_picture(), "spare {spare}: after close");
            // Nor does a picture's buffer that the capture thread gives back
            // after the close.
            data.shared.recycle(vec![7; 64]);
            assert!(!data.shared.holds_picture(), "spare {spare}: recycled");
            assert!(matches!(
                data.shared.next(Duration::ZERO),
                Err(CaptureError::Failed(m)) if m.contains("closed")
            ));
        }
    }

    /// A picture's buffer that the capture thread gives back is the one the
    /// next picture is packed into: same memory, no allocation per picture.
    /// A smaller buffer does not replace it, and `grab` is the pack alone.
    #[test]
    fn a_buffer_given_back_is_packed_into_next() {
        let data = fake_data();
        data.shared
            .set_format(Ok(Some(format(PixelFormat::Bgrx, 2, 2))));
        let good = |v: u8| Fake::new(vec![v; 16], chunk(0, 16, 8, 0));
        assert!(good(1).process(&data));
        let first = data.shared.next(Duration::ZERO).unwrap().unwrap();
        let kept = (first.bgrx.as_ptr(), first.bgrx.capacity());
        data.shared.recycle(first.bgrx);
        data.shared.recycle(Vec::with_capacity(4));
        let before = Instant::now();
        assert!(good(2).process(&data));
        let took = before.elapsed();
        let second = data.shared.next(Duration::ZERO).unwrap().unwrap();
        assert_eq!(second.bgrx, [2; 16]);
        assert_eq!((second.bgrx.as_ptr(), second.bgrx.capacity()), kept);
        assert!(second.grab <= took, "{:?} of {took:?}", second.grab);
        // Nothing given back: the next picture needs memory of its own.
        assert!(good(3).process(&data));
        let third = data.shared.next(Duration::ZERO).unwrap().unwrap();
        assert_eq!(third.bgrx, [3; 16]);
        assert_ne!(third.bgrx.as_ptr(), second.bgrx.as_ptr());
    }

    #[test]
    fn the_param_and_state_callbacks_reach_the_capture_thread() {
        let data = fake_data();
        let data_ptr: *mut c_void = (&raw const data).cast_mut().cast();
        let pod = object(&[VIDEO, RAW, BGRX, SIZE, RATE, MAX_RATE]);
        let words: Vec<u64> = pod
            .chunks(8)
            .map(|c| {
                let mut b = [0u8; 8];
                b[..c.len()].copy_from_slice(c);
                u64::from_ne_bytes(b)
            })
            .collect();
        // SAFETY: `data_ptr` is a live `CallbackData`; the pod is complete and
        // 8-byte aligned; other ids are ignored.
        unsafe {
            on_param_changed(data_ptr, SPA_PARAM_ENUM_FORMAT, words.as_ptr().cast());
            assert_eq!(data.shared.pixel_size(), None);
            on_param_changed(data_ptr, SPA_PARAM_FORMAT, words.as_ptr().cast());
        }
        assert_eq!(data.shared.pixel_size(), Some((1280, 800)));
        // The pod carries mutter's 60/1 `maxFramerate` range: it is read.
        assert_eq!(
            data.shared.wait_negotiated(Duration::ZERO).unwrap(),
            VideoFormat {
                max_framerate: Some((60, 1)),
                ..format(PixelFormat::Bgrx, 1280, 800)
            }
        );
        // Streaming, then the compositor ends the cast: the capture thread hears it.
        let why = c"node removed";
        // SAFETY: as above; the message is NUL-terminated.
        unsafe {
            on_state_changed(data_ptr, 0, PW_STREAM_STATE_STREAMING, null());
            on_state_changed(data_ptr, 3, -1, why.as_ptr());
        }
        match data.shared.next(Duration::ZERO) {
            Err(CaptureError::Failed(message)) => {
                assert!(message.contains("node removed"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        // The first failure stays the reported one.
        // SAFETY: as above.
        unsafe { on_state_changed(data_ptr, -1, PW_STREAM_STATE_UNCONNECTED, null()) };
        assert!(
            matches!(data.shared.next(Duration::ZERO), Err(CaptureError::Failed(m)) if m.contains("node removed"))
        );
    }

    #[test]
    fn a_stream_that_never_negotiates_times_out_and_a_failed_one_says_why() {
        let shared = Shared::new();
        assert!(matches!(
            shared.wait_negotiated(Duration::from_millis(10)),
            Err(CaptureError::Unavailable(m)) if m.contains("no picture format")
        ));
        shared.set_format(Err("the compositor negotiated DMA-BUF buffers".into()));
        assert!(matches!(
            shared.wait_negotiated(Duration::from_secs(5)),
            Err(CaptureError::Unavailable(m)) if m.contains("DMA-BUF")
        ));
        // A failure after the format still ends capture.
        let shared = Shared::new();
        shared.set_format(Ok(Some(format(PixelFormat::Bgrx, 2, 2))));
        shared.set_state(PW_STREAM_STATE_UNCONNECTED, None);
        assert!(
            matches!(shared.next(Duration::from_secs(5)), Err(CaptureError::Failed(m)) if m.contains("screen cast ended"))
        );
    }
}
