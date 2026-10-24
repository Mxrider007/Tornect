# Video/audio codecs & FEC — research note (verified 2026-08-28)

Scope: `tornect-codec` (plan §A.2 hardware codecs, §A.3 D8/D9, §B.4 FEC/audio, §B.5
media pipeline). Everything below was checked against crate sources extracted into
`/tmp/crates-src/` (from `static.crates.io`), the crates.io API, FFmpeg 8.0 sources on
GitHub, and probe crates **compiled and run on this VM** (Ubuntu 26.04 "resolute",
Rust 1.96, 4 vCPU, no GPU, no sudo, cmake + gcc/g++ + pkg-config present, **no**
nasm/libclang-dev/FFmpeg-dev/ALSA-dev/PipeWire-dev/opus-dev headers):

| Probe | Path | Result |
|---|---|---|
| `openh264 = "=0.9.8"` (`source`) | `/tmp/probe-openh264` | **builds & runs here** (45.7 s wall incl. deps; C++ compiled by `cc`, asm silently skipped — no nasm) |
| `opus = "=0.4.0"` + `raptorq = "=2.0.1"` + `rav1e = "=0.8.1"` (no default features) | `/tmp/probe-audio` | **builds & runs here** (66 s wall first build; libopus 1.6.1 built by cmake) |
| `cpal = "=0.18.2"` | `/tmp/probe-cpal` | **fails here** in 3.4 s: `alsa-sys v0.4.0` build script → "Pkg-config failed … apt-get install libasound2-dev" |
| `ffmpeg-next = "=9.0.0"` (`codec`,`software-scaling`) | `/tmp/probe-ffmpeg` | **fails here**: `ffmpeg-sys-next v9.0.0` → "FFmpeg not found … pkg-config (libavutil not found)" |

---

## 0. TL;DR for implementers

| Item | Decision |
|---|---|
| Unified hw codec layer | `ffmpeg-next = "=9.0.0"`, `default-features = false`, `features = ["codec", "software-scaling", "non-exhaustive-enums"]` → pulls `ffmpeg-sys-next 9.0.0`, links **system FFmpeg via pkg-config** (Ubuntu 26.04 ships **FFmpeg 8.0.1**, lavc 62.11.100 — supported). CI-only build (needs `libav*-dev` + `clang`/libclang). |
| HW device/frames | **Not wrapped** by ffmpeg-next (zero hits for `hw_device_ctx`/`av_hwdevice` in `ffmpeg-next-9.0.0/src`). Use `ffmpeg_next::ffi::av_hwdevice_ctx_create`, `av_hwframe_ctx_alloc/init`, `av_hwframe_get_buffer`, `av_hwframe_transfer_data`, `av_hwframe_map` on `ctx.as_mut_ptr()` / `frame.as_mut_ptr()` (all `unsafe`, all bound by `ffmpeg-sys-next` from `libavutil/hwcontext.h` + per-API `hwcontext_*.h`). |
| Encoder options | Pass AVOptions through `encoder.open_as_with(codec, Dictionary)` (→ `avcodec_open2(..., &opts)`); `codec::Context` does **not** implement `option::Settable` (only `filter::context::Context` does). |
| Software H.264 (both directions, all OSes, buildable everywhere) | `openh264 = "=0.9.8"` (`source`, default) — BSD-2 bindings + Cisco source; **no nasm needed** (falls back to C++ automatically); measured here 1080p enc ≈ 23 ms/frame, dec ≈ 5 ms/frame with plain C++ on 4 vCPUs. |
| Software AV1 | `rav1e 0.8.1` is **not real-time**: measured ≈ 0.65 s/frame at 1080p (speed 10, low_latency, 4 tiles, `threading`, no asm) on this VM. Keep AV1 hw-only in v1; do not ship rav1e as "potato mode". No usable safe pure-Rust AV1 *decoder* crate (rav1d 1.1.0 exposes only the C `dav1d_*` ABI). |
| Audio | `opus = "=0.4.0"` (→ `opusic-sys 0.7.x`, bundles **libopus 1.6.1**, built by **cmake**, no pkg-config/bindgen). `audiopus`/`audiopus_sys` are stale (2021) — do not use. |
| Audio I/O | `cpal = "=0.18.2"`; Linux always needs `libasound2-dev` (ALSA host is unconditional); `pipewire` feature adds a PipeWire host (needs `libpipewire-0.3-dev` + libclang). CI-only build. |
| FEC | `raptorq = "=2.0.1"` (pure Rust, no deps, `no_std`-capable). `Encoder::with_defaults(&data, mtu)`, `get_encoded_packets(repair)`, `Decoder::new(oti).decode(pkt)`; OTI serializes to exactly **12 bytes**; packet = 4-byte PayloadId + symbol. Verified round-trip here. |

---

## 1. Versions, features, why

### 1.1 Latest versions (crates.io API, 2026-08-28)

| crate | latest | published | rust-version | source |
|---|---|---|---|---|
| ffmpeg-next | **9.0.0** | 2026-08-05 | – (edition 2024) | https://crates.io/api/v1/crates/ffmpeg-next |
| ffmpeg-sys-next | **9.0.0** | 2026-08-05 | – (edition 2024, uses `let`-chains) | https://crates.io/api/v1/crates/ffmpeg-sys-next |
| openh264 | **0.9.8** | 2026-08-08 | 1.85 | https://crates.io/api/v1/crates/openh264 |
| openh264-sys2 | **0.9.8** | 2026-08-08 | 1.85 | https://crates.io/api/v1/crates/openh264-sys2 |
| rav1e | **0.8.1** | 2025-06-16 | 1.83 | https://crates.io/api/v1/crates/rav1e |
| rav1d | 1.1.0 | 2025-05-07 | 1.79 | https://crates.io/api/v1/crates/rav1d |
| dav1d (bindings to C libdav1d) | 0.11.1 | 2025-11-25 | 1.78 | https://crates.io/api/v1/crates/dav1d |
| opus | **0.4.0** | 2026-08-23 | – | https://crates.io/api/v1/crates/opus |
| opusic-sys (dep of opus 0.4) | 0.7.5 | 2026-08-06 | 1.82 | https://crates.io/api/v1/crates/opusic-sys |
| audiopus | 0.3.0-rc.0 (stable 0.2.0) | 2021-04-22 | – | https://crates.io/api/v1/crates/audiopus — **stale** |
| audiopus_sys | 0.2.2 | 2021-04-22 | – | https://crates.io/api/v1/crates/audiopus_sys — **stale** |
| cpal | **0.18.2** | 2026-08-16 | 1.85 | https://crates.io/api/v1/crates/cpal |
| alsa (cpal dep) | 0.11 required by cpal; latest 0.12.1 | 2025-12-26 / 2026-07-31 | – | https://crates.io/api/v1/crates/alsa |
| alsa-sys (alsa 0.11 dep) | ^0.4.0 | 2025-12-26 | – | https://crates.io/api/v1/crates/alsa-sys |
| raptorq | **2.0.1** | 2026-03-09 | – (edition 2024) | https://crates.io/api/v1/crates/raptorq |

### 1.2 Recommended pins (Cargo.toml)

```toml
# tornect-codec (hardware + FFmpeg software paths) — CI-only build on Linux until libav*-dev is available
ffmpeg-next = { version = "=9.0.0", default-features = false, features = ["codec", "software-scaling", "non-exhaustive-enums"] }

# always-buildable software H.264 (host fallback + client fallback)
openh264 = { version = "=0.9.8", default-features = false, features = ["source"] }

# audio
opus = "=0.4.0"                      # -> opusic-sys ^0.7.3, bundled libopus 1.6.1 (cmake)
cpal = { version = "=0.18.2", default-features = false }   # add features = ["pipewire"] for a PipeWire host on Linux (CI-only)

# FEC
raptorq = { version = "=2.0.1", default-features = false, features = ["std"] }
```

Why each feature:

- `ffmpeg-next` default features are `["codec","device","filter","format","software-resampling","software-scaling"]` (`ffmpeg-next-9.0.0/Cargo.toml [features]`). We need only `codec` (`ffmpeg-sys-next/avcodec`) and `software-scaling` (`ffmpeg-sys-next/swscale`, for NV12↔RGB CPU fallback). Dropping `device`/`filter`/`format` removes the pkg-config probes for `libavdevice`, `libavfilter`, `libavformat` (`ffmpeg-sys-next-9.0.0/build.rs:1229-1250` probes each of these only if its `CARGO_FEATURE_*` is set), i.e. fewer `-dev` packages in CI.
- `non-exhaustive-enums` → bindgen `non_exhaustive` on enums (`ffmpeg-sys-next-9.0.0/build.rs:1724`), so new pixel formats / codec IDs from a newer FFmpeg don't break `match`es.
- `openh264/source` = `openh264-sys2/source` = `dep:cc, dep:walkdir, dep:nasm-rs` (`openh264-sys2-0.9.8/Cargo.toml`); `libloading` = `dep:libloading, dep:sha2 0.10.8`. Default is `source`.
- `raptorq` features: `default = ["std"]`, `serde_support`, `python`, `benchmarking` (`raptorq-2.0.1/Cargo.toml`). No runtime deps besides optional serde.
- `rav1e` — if ever used: `default = ["binaries","asm","threading","signal_support","git_version"]`; `asm = ["nasm-rs","cc"]` (**needs nasm on x86_64**, README "Dependency: NASM"); `threading = ["rayon/threads"]`. With `default-features = false` you **lose threading** — must add `features = ["threading"]` explicitly (`rav1e-0.8.1/Cargo.toml`).

---

## 2. FFmpeg via `ffmpeg-next 9.0.0` / `ffmpeg-sys-next 9.0.0`

### 2.1 Which FFmpeg majors are supported — and Ubuntu 26.04

- `ffmpeg-sys-next-9.0.0/build.rs:994-1013` version table (auto-detected from `LIBAVCODEC_VERSION_MAJOR/MINOR` at build time, exported as cfg `feature="ffmpeg_X_Y"` and `DEP_FFMPEG_*` to ffmpeg-next):
  `ffmpeg_3_0`(57.24) … `ffmpeg_7_1`(61.19), **`ffmpeg_8_0`(62.8)**, **`ffmpeg_8_1`(62.28)**, **`ffmpeg_9_0`(63.1)**.
- The **crate version tracks the FFmpeg version it was updated for** (README: "major and minor versions track major and minor versions of FFmpeg"), but the build is compatible **downward to 3.x**: the pkg-config path has no minimum-version check, only presence (`build.rs:1211`, `:1255`). Upstream CI matrix (https://github.com/zmwangx/rust-ffmpeg-sys/blob/master/.github/workflows/build.yml) tests `"6.1","7.0","7.1","8.0","8.1","9.0"` (and 3.3–6.0 in a second job). The ffmpeg-next README sentence "currently from 3.4 til 8.0" (https://github.com/zmwangx/rust-ffmpeg) is stale text.
- FFmpeg **9.0 "Lei" was released 2026-08-04** (lavc 63.1.100; 9.0.1 on 2026-08-12) — https://www.phoronix.com/news/FFmpeg-9.0-Released , https://jbkempf.com/blog/2026/ffmpeg-9.0/ . ffmpeg-sys-next 9.0.0 (2026-08-05) is the matching bump.
- **Ubuntu 26.04 ships FFmpeg 8.0.1** (`dpkg -l` on this VM: `libavcodec62 7:8.0.1-3ubuntu2`, `libavcodec.so.62.11.100`; also `libx264-165`, `libva2 2.23.0`, `libdav1d7 1.5.3` as runtime deps). ffmpeg-sys-next 9.0.0 **does build against FFmpeg 8 headers/ABI** (cfg `ffmpeg_8_0` on, `ffmpeg_8_1`/`ffmpeg_9_0` off). Because bindings are generated by bindgen at build time from the *installed* headers (`src/lib.rs:16 include!(concat!(env!("OUT_DIR"), "/bindings.rs"))`), the ABI always matches the headers you build against.
- ABI caveat: the binary you build on Ubuntu 26.04 CI links `libavcodec.so.62` etc.; a FFmpeg-9 system has `.so.63` → **not ABI compatible**. Either ship FFmpeg with the app (static `build` feature, or bundled shared libs from FFmpeg builds) or build per-distro. FFmpeg 9.0 "bumped the major version of all seven libraries which means an ABI break across the board" (https://www.linuxcompatible.org/story/ffmpeg-90-lei-released-library-bumps-and-dev-impact).

### 2.2 Build requirements

`ffmpeg-sys-next-9.0.0/Cargo.toml [build-dependencies]`: `bindgen 0.72` (`default-features = false, features = ["runtime"]` → dlopens libclang at build time), `cc 1.3`, `num_cpus`, `pkg-config 0.3`, `vcpkg` (msvc only).

Library discovery order (`build.rs:1091-1270`): `build` feature → compile FFmpeg from source; else `FFMPEG_DIR` env; else vcpkg (msvc); else **pkg-config** `libavutil` + each enabled `libav*`, `libavcodec` include paths feed bindgen. Failure text seen on this VM:

```
error: FFmpeg not found.
  1. FFMPEG_DIR environment variable (not set)
  2. vcpkg package manager (ffmpeg package not found)
  3. pkg-config (libavutil not found: … Package 'libavutil' not found
  - Enable the 'build' feature to compile FFmpeg from source
```

- **On this VM: not buildable** (no `libavutil.pc`, no `/usr/include/libavcodec`, no clang builtin headers — only `libclang-21.so.1` runtime is installed; bindgen's `runtime` feature can dlopen it but the FFmpeg headers are missing anyway).
- **CI (Ubuntu runner)**: `apt-get install -y clang libclang-dev pkg-config libavcodec-dev libavutil-dev libswscale-dev` (+ `libavformat-dev libavfilter-dev libavdevice-dev libswresample-dev` only if those features are enabled). Upstream CI uses `clang curl pkg-config` for the system-FFmpeg jobs and adds `llvm libssl-dev yasm nasm libx264-dev` for the static job (build.yml link above).
- `build` feature (`= ["static"]`): `git clone --depth=1 -b release/9.0 https://github.com/FFmpeg/FFmpeg` into `OUT_DIR` (`build.rs:161-176`, branch = crate major.minor → **always FFmpeg 9.0 for crate 9.0.0**), then `./configure --enable-static --disable-shared --disable-programs --disable-doc …` + `make` + `make install` (`build.rs:527-546, 779-797`). Requires git, make, a C toolchain, and for x86 asm nasm/yasm (FFmpeg configure). Hardware backends are opt-in features that map to `--enable-*`: `build-nvenc`, `build-nvidia`, `build-vaapi`, `build-vulkan`, `build-amf`, `build-videotoolbox`, `build-drm`, `build-lib-x264` (`--enable-libx264`, GPL → also `build-license-gpl`), `build-lib-x265`, `build-lib-dav1d`, `build-lib-openh264`, `build-lib-vpx`, `build-lib-svtav1`… (`Cargo.toml:43-104`, `build.rs:603-746`). This is the path for a self-contained release binary; it is heavy (full FFmpeg compile per CI job — cache `OUT_DIR`).
- macOS static: build.rs links the Apple frameworks incl. `VideoToolbox` automatically when `static` (`build.rs:1268-1300`). Windows: vcpkg `ffmpeg` or `FFMPEG_DIR` pointing at a gyan/BtbN build (bindgen still needs libclang → install LLVM on the runner).

### 2.3 Safe API surface that exists (from `ffmpeg-next-9.0.0/src`)

- `ffmpeg_next::init()` (`src/lib.rs:109`); `encoder::find(codec::Id::H264)` / `encoder::find_by_name("h264_nvenc")` / `decoder::find_by_name(..)` (`src/codec/encoder/mod.rs:38,52`, `src/codec/decoder/mod.rs:35,49`) → `Option<Codec>`; `Codec::name()/id()/capabilities()/is_encoder()`.
- `codec::context::Context::new_with_codec(codec)` → `.encoder()` → `.video()?` → `encoder::video::Video` with setters `set_width/height/format/gop/max_b_frames/qmin/qmax/global_quality/colorspace/color_range/color_primaries/color_transfer_characteristic/aspect_ratio`, plus on the generic `encoder::Encoder`: `set_bit_rate/set_max_bit_rate/set_tolerance/set_quality`; `Context::set_threading(threading::Config{kind: Type::Slice|Frame|None, count})`, `set_time_base`, `set_frame_rate`, `set_flags(codec::Flags::GLOBAL_HEADER|LOW_DELAY|…)`.
- Open: `Video::open()`, `open_as(codec)`, **`open_with(Dictionary)`**, **`open_as_with(codec, Dictionary)`** — the dictionary is passed to `avcodec_open2` (`src/codec/encoder/video.rs:20-77`). This is how every private encoder option (preset/tune/rc/…) is set.
- Encode loop: `encoder.send_frame(&frame)?`, `encoder.receive_packet(&mut Packet)?` (loop until `Err`), `send_eof()` (`src/codec/encoder/encoder.rs:62-77`). Packet: `data() -> Option<&[u8]>`, `is_key()`, `flags()`, `pts/dts`, `size()` (`src/codec/packet/packet.rs`).
- Decode: `Context::new_with_codec(dec).decoder().video()?` (or `.open_as_with(codec, dict)`) → `send_packet(&Packet)`, `receive_frame(&mut frame::Video)`, `send_eof()` (`src/codec/decoder/opened.rs:36-56`). `Packet::copy(&[u8])` / `Packet::borrow(&[u8])` wrap our datagram-reassembled bytes.
- Frames: `frame::Video::new(format::Pixel::NV12, w, h)` (CPU-allocated via `av_frame_get_buffer`), `data(plane)`, `data_mut(plane)`, `stride(plane)`, `set_pts`, `set_kind(picture::Type::I)` (force keyframe request at the frame level), `unsafe wrap(*mut AVFrame)`, `as_mut_ptr()` (`src/util/frame/video.rs`, `src/util/frame/mod.rs`).
- `format::Pixel` includes hardware formats: `NV12`, `P010LE`, `VAAPI`, `CUDA`, `QSV`, `VIDEOTOOLBOX`, `D3D11`, `DRM_PRIME`, `VULKAN`, `D3D12` (`src/util/format/pixel.rs:40,83,167,172,222,304,311,339,418`).
- `software::scaling::Context` (swscale) for CPU conversions.
- **Missing** (grep over `src/`): no `hw_device_ctx`, `hw_frames_ctx`, `av_hwdevice_*`, `get_format`; `option::Settable` is implemented only for `filter::context::Context` (`src/filter/context/context.rs:61-71`).

Reference encoder skeleton (adapted from `ffmpeg-next-9.0.0/examples/transcode-x264.rs:52-80`):

```rust
use ffmpeg_next as ffmpeg;
use ffmpeg::{codec, encoder, format, Dictionary, Packet, Rational};

ffmpeg::init()?;
let codec = encoder::find_by_name("libx264").ok_or(ffmpeg::Error::EncoderNotFound)?;
let mut enc = codec::context::Context::new_with_codec(codec).encoder().video()?;
enc.set_width(1920); enc.set_height(1080);
enc.set_format(format::Pixel::NV12);          // libx264 accepts nv12; use YUV444P for text mode
enc.set_time_base(Rational(1, 90_000));       // rtp_ts is 90 kHz in tornect-proto
enc.set_frame_rate(Some(Rational(60, 1)));
enc.set_gop(u32::MAX);                        // "infinite GOP + intra-refresh"
enc.set_max_b_frames(0);
enc.set_bit_rate(12_000_000); enc.set_max_bit_rate(12_000_000);
enc.set_threading(codec::threading::Config { kind: codec::threading::Type::Slice, count: 4 });
let mut opts = Dictionary::new();
opts.set("preset", "ultrafast"); opts.set("tune", "zerolatency");
opts.set("intra-refresh", "1"); opts.set("rc-lookahead", "0"); opts.set("nal-hrd", "cbr");
opts.set("x264-params", "sliced-threads=1:sync-lookahead=0:vbv-maxrate=12000:vbv-bufsize=200:aq-mode=0");
let mut enc = enc.open_as_with(codec, opts)?;   // -> avcodec_open2(ctx, codec, &opts)

// per frame
let mut frame = ffmpeg::frame::Video::new(format::Pixel::NV12, 1920, 1080);
frame.set_pts(Some(rtp_ts as i64));
enc.send_frame(&frame)?;
let mut pkt = Packet::empty();
while enc.receive_packet(&mut pkt).is_ok() {
    let bytes: &[u8] = pkt.data().unwrap();     // Annex-B for libx264/nvenc/vaapi; packetize -> datagrams
    let key = pkt.is_key();
}
```

### 2.4 Hardware device / frames contexts — raw `ffi` only

All of `libavutil/hwcontext.h` is bound (`build.rs:1806 .header("libavutil/hwcontext.h")`, plus `hwcontext_drm.h` when present at `:1857` and the per-API structs through `hwcontext_wrapper.h` at `:1865`). `hwcontext_wrapper.h` binds `AVCUDADeviceContext` (CUDA SDK stubbed via `CUDA_VERSION` define), `AVD3D11VADeviceContext`/`AVD3D12VADeviceContext` (Windows only, gated on `<d3d11.h>`/`<d3d12.h>`), `AVVideoToolbox*`, `AVVulkanDeviceContext`, `AVVAAPIDeviceContext`, `AVQSVDeviceContext` (SDK headers replaced by shims in `hwcontext_stubs/`). So the struct layouts for `hwctx` casts are available without vendor SDKs installed — but only if the FFmpeg you build against ships that `hwcontext_*.h` (`__has_include` gated).

Functions available via `ffmpeg_next::ffi::*` (exact signatures from FFmpeg 8.0 `libavutil/hwcontext.h`, fetched from GitHub):

```c
enum AVHWDeviceType av_hwdevice_find_type_by_name(const char *name);       // "vaapi","cuda","d3d11va","d3d12va","videotoolbox","vulkan","drm","amf","qsv"
int  av_hwdevice_ctx_create(AVBufferRef **device_ctx, enum AVHWDeviceType type, const char *device, AVDictionary *opts, int flags);
int  av_hwdevice_ctx_create_derived(AVBufferRef **dst_ctx, enum AVHWDeviceType type, AVBufferRef *src_ctx, int flags);
AVBufferRef *av_hwframe_ctx_alloc(AVBufferRef *device_ctx);
int  av_hwframe_ctx_init(AVBufferRef *ref);
int  av_hwframe_get_buffer(AVBufferRef *hwframe_ctx, AVFrame *frame, int flags);
int  av_hwframe_transfer_data(AVFrame *dst, const AVFrame *src, int flags);
int  av_hwframe_map(AVFrame *dst, const AVFrame *src, int flags);          // AV_HWFRAME_MAP_READ=1, WRITE=2, OVERWRITE=4, DIRECT=8
int  av_hwframe_ctx_create_derived(AVBufferRef **derived_frame_ctx, enum AVPixelFormat format, AVBufferRef *derived_device_ctx, AVBufferRef *source_frame_ctx, int flags);
AVHWFramesConstraints *av_hwdevice_get_hwframe_constraints(AVBufferRef *ref, const void *hwconfig);
```
`AVHWDeviceType` values in FFmpeg 8.0: `NONE, VDPAU, CUDA, VAAPI, DXVA2, QSV, VIDEOTOOLBOX, D3D11VA, DRM, OPENCL, MEDIACODEC, VULKAN, D3D12VA, AMF, OHCODEC`. `AVHWFramesContext` fields: `format` (hw pix fmt), `sw_format`, `width`, `height`, `initial_pool_size`, `hwctx`, `device_ref`.

Hardware-encode setup, transliterated from the FFmpeg C pattern (`doc/examples/vaapi_encode.c` semantics; **not compiled here** — no FFmpeg headers on this VM; treat as the shape to implement in `unsafe` glue and verify in CI):

```rust
use ffmpeg_next::ffi::*;
use std::ptr;

unsafe fn open_hw_encoder(name: &str, dev_type: AVHWDeviceType, dev: Option<&str>, w: i32, h: i32,
                          hw_fmt: AVPixelFormat, sw_fmt: AVPixelFormat, opts: ffmpeg_next::Dictionary)
    -> Result<(ffmpeg_next::encoder::Video, *mut AVBufferRef), ffmpeg_next::Error> {
    let codec = ffmpeg_next::encoder::find_by_name(name).ok_or(ffmpeg_next::Error::EncoderNotFound)?;
    let mut video = ffmpeg_next::codec::context::Context::new_with_codec(codec).encoder().video()?;

    // 1. device
    let mut hw_dev: *mut AVBufferRef = ptr::null_mut();
    let dev_c = dev.map(|d| std::ffi::CString::new(d).unwrap());
    let r = av_hwdevice_ctx_create(&mut hw_dev, dev_type,
            dev_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()), ptr::null_mut(), 0);
    if r < 0 { return Err(ffmpeg_next::Error::from(r)); }

    // 2. frames pool on that device
    let hw_frames = av_hwframe_ctx_alloc(hw_dev);
    let fc = (*hw_frames).data as *mut AVHWFramesContext;
    (*fc).format = hw_fmt;              // AV_PIX_FMT_VAAPI / CUDA / D3D11 / VIDEOTOOLBOX / VULKAN
    (*fc).sw_format = sw_fmt;           // AV_PIX_FMT_NV12 (P010 for 10-bit HEVC)
    (*fc).width = w; (*fc).height = h;
    (*fc).initial_pool_size = 8;
    let r = av_hwframe_ctx_init(hw_frames);
    if r < 0 { return Err(ffmpeg_next::Error::from(r)); }

    // 3. attach to the codec context before avcodec_open2
    let ctx = video.as_mut_ptr();       // pub unsafe fn on codec::Context (context.rs:34)
    (*ctx).width = w; (*ctx).height = h;
    (*ctx).pix_fmt = hw_fmt;
    (*ctx).hw_device_ctx = av_buffer_ref(hw_dev);
    (*ctx).hw_frames_ctx = av_buffer_ref(hw_frames);

    let enc = video.open_as_with(codec, opts)?;
    Ok((enc, hw_frames))
}

// per frame: get a hw surface, upload (or map a DMA-BUF/D3D11 texture into it), encode
unsafe fn upload_and_send(enc: &mut ffmpeg_next::encoder::Video, hw_frames: *mut AVBufferRef,
                          cpu_nv12: &ffmpeg_next::frame::Video, pts: i64) -> Result<(), ffmpeg_next::Error> {
    let mut hw = ffmpeg_next::frame::Video::empty();
    let r = av_hwframe_get_buffer(hw_frames, hw.as_mut_ptr(), 0);
    if r < 0 { return Err(ffmpeg_next::Error::from(r)); }
    let r = av_hwframe_transfer_data(hw.as_mut_ptr(), cpu_nv12.as_ptr(), 0); // CPU->GPU; zero-copy path uses av_hwframe_map with a DRM_PRIME/D3D11 frame instead
    if r < 0 { return Err(ffmpeg_next::Error::from(r)); }
    hw.set_pts(Some(pts));
    enc.send_frame(&hw)
}
```

Zero-copy import paths (all raw FFI, per §B.5): Linux PipeWire DMA-BUF → build an `AVFrame` with `format = AV_PIX_FMT_DRM_PRIME` whose `data[0]` is an `AVDRMFrameDescriptor` (bound from `hwcontext_drm.h`), then `av_hwframe_map(vaapi_frame, drm_frame, AV_HWFRAME_MAP_READ)` into a VAAPI frames context (or use `av_hwframe_ctx_create_derived` DRM→VAAPI). Windows WGC `ID3D11Texture2D` → `AV_PIX_FMT_D3D11` frame with `data[0] = texture`, `data[1] = array index`, on a `d3d11va` device created from *our* `ID3D11Device` (`AVD3D11VADeviceContext.device`, set before `av_hwdevice_ctx_init`) → NVENC/AMF/QSV consume it. macOS IOSurface/CVPixelBuffer → `AV_PIX_FMT_VIDEOTOOLBOX` frame with `data[3] = CVPixelBufferRef`.

### 2.5 Hardware decode — no `get_format` callback needed

FFmpeg 8.0 `libavcodec/decode.c` `avcodec_default_get_format()` (fetched verbatim from GitHub):

```c
    // If a device was supplied when the codec was opened, assume that the
    // user wants to use it.
    if (avctx->hw_device_ctx && ffcodec(avctx->codec)->hw_configs) {
        AVHWDeviceContext *device_ctx = (AVHWDeviceContext*)avctx->hw_device_ctx->data;
        for (i = 0;; i++) {
            config = &ffcodec(avctx->codec)->hw_configs[i]->public;
            if (!config) break;
            if (!(config->methods & AV_CODEC_HW_CONFIG_METHOD_HW_DEVICE_CTX)) continue;
            if (device_ctx->type != config->device_type) continue;
            for (n = 0; fmt[n] != AV_PIX_FMT_NONE; n++) {
                if (config->pix_fmt == fmt[n]) return fmt[n];
            }
        }
    }
    // ... otherwise: last element if software, else first entry without external deps
```

So for the client: create the device (`av_hwdevice_ctx_create` for `d3d11va` / `videotoolbox` / `vaapi` / `cuda`), set `(*ctx).hw_device_ctx = av_buffer_ref(dev)` on the `h264`/`hevc`/`av1` decoder context **before** `open`, and the default `get_format` selects the hwaccel format. Received frames then have `format() == Pixel::D3D11 | VIDEOTOOLBOX | VAAPI | CUDA`; either `av_hwframe_transfer_data(cpu_frame, hw_frame, 0)` to NV12/P010 for the CPU-upload render path (M-first), or map into wgpu (M7). NVDEC alternative: `decoder::find_by_name("h264_cuvid")` — a full codec, outputs `AV_PIX_FMT_CUDA` frames when `hw_device_ctx` is set, no hwaccel negotiation at all.

### 2.6 Low-latency encoder option names (verified against FFmpeg release/8.0 sources)

All are private AVOptions → set via the `Dictionary` passed to `open_as_with`. Generic `AVCodecContext` fields set through the safe setters: `bit_rate`, `rc_max_rate` (`set_max_bit_rate`), `gop_size` (`set_gop`), `max_b_frames` (`set_max_b_frames`), `qmin/qmax`, `thread_count/type` (`set_threading`), flags `LOW_DELAY`.

**libx264** (`libavcodec/libx264.c`, verbatim option lines):
```c
{ "preset", "Set the encoding preset (cf. x264 --fullhelp)", OFFSET(preset), AV_OPT_TYPE_STRING, { .str = "medium" }, 0, 0, VE},
{ "tune",   "Tune the encoding params (cf. x264 --fullhelp)", OFFSET(tune),   AV_OPT_TYPE_STRING, { 0 }, 0, 0, VE},
{ "profile", ... AV_OPT_TYPE_STRING ...}, {"level", ...},
{ "rc-lookahead",  "Number of frames to look ahead for frametype and ratecontrol", OFFSET(rc_lookahead), AV_OPT_TYPE_INT, { .i64 = -1 }, -1, INT_MAX, VE },
{ "intra-refresh", "Use Periodic Intra Refresh instead of IDR frames.", OFFSET(intra_refresh), AV_OPT_TYPE_BOOL, { .i64 = -1 }, -1, 1, VE },
{ "forced-idr",   "If forcing keyframes, force them as IDR frames.", OFFSET(forced_idr), AV_OPT_TYPE_BOOL, { .i64 = 0 }, -1, 1, VE },
{ "nal-hrd", "Signal HRD information (requires vbv-bufsize; cbr not allowed in .mp4)", OFFSET(nal_hrd), AV_OPT_TYPE_INT, { .i64 = -1 }, -1, INT_MAX, VE, .unit = "nal-hrd" },   // consts: none | vbr | cbr
{ "slice-max-size","Limit the size of each slice in bytes", OFFSET(slice_max_size), AV_OPT_TYPE_INT, { .i64 = -1 }, -1, INT_MAX, VE },
{ "aq-mode", ... }, { "mbtree", ... AV_OPT_TYPE_BOOL ...}, { "sc_threshold", "Scene change threshold", ...}, { "coder", ...}, { "b_strategy", ...}, { "crf", ...}, { "qp", ...},
{ "x264-params", "Override the x264 configuration using a :-separated list of key=value parameters", OFFSET(x264_params), AV_OPT_TYPE_DICT, { 0 }, 0, 0, VE },
```
Recommended set: `preset=ultrafast` (or `superfast`/`veryfast` if CPU allows), `tune=zerolatency` (x264's zerolatency = bframes 0, rc-lookahead 0, sync-lookahead 0, sliced-threads, no mbtree), `intra-refresh=1`, `rc-lookahead=0`, `nal-hrd=cbr` + `x264-params=vbv-maxrate=<kbit>:vbv-bufsize=<kbit/fps..kbit/4>:sliced-threads=1:sync-lookahead=0` (CBR needs `vbv-bufsize`), `forced-idr=1` so a `picture::Type::I` frame request yields a real IDR, `sc_threshold=0`, `set_max_b_frames(0)`, `set_gop(u32::MAX)`. For text mode use pix fmt `YUV444P` + `profile=high444`. **libx264 is GPL** — Ubuntu's FFmpeg links `libx264-165`; a GPL-compatible Tornect license (or dropping libx264 in favour of openh264 §3) is required to redistribute.

**NVENC** (`libavcodec/nvenc_h264.c`; same option table shape in `nvenc_hevc.c` / `nvenc_av1.c`):
```c
{ "preset", "Set the encoding preset", OFFSET(preset), AV_OPT_TYPE_INT, { .i64 = PRESET_P4 }, PRESET_DEFAULT, PRESET_P7, VE, .unit = "preset" },
  // consts: default, slow, medium, fast, hp, hq, bd, ll, llhq, llhp, lossless, losslesshp, p1 "fastest (lowest quality)" … p7 "slowest (best quality)"
{ "tune", "Set the encoding tuning info", OFFSET(tuning_info), AV_OPT_TYPE_INT, { .i64 = NV_ENC_TUNING_INFO_HIGH_QUALITY }, ..., .unit = "tune" },
{ "hq", "High quality", ... }, { "ll", "low latency", ... NV_ENC_TUNING_INFO_LOW_LATENCY }, { "ull", "Ultra low latency", ... NV_ENC_TUNING_INFO_ULTRA_LOW_LATENCY }, { "lossless", ... },
{ "rc", "Override the preset rate-control", OFFSET(rc), AV_OPT_TYPE_INT, { .i64 = -1 }, -1, INT_MAX, VE, .unit = "rc" },
{ "constqp", "Constant QP mode", ... }, { "vbr", "Variable bitrate mode", ... NV_ENC_PARAMS_RC_VBR }, { "cbr", "Constant bitrate mode", ... NV_ENC_PARAMS_RC_CBR },
{ "zerolatency", "Set 1 to indicate zero latency operation (no reordering delay)", OFFSET(zerolatency), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, VE },
{ "delay", "Delay frame output by the given amount of frames", OFFSET(async_depth), AV_OPT_TYPE_INT, { .i64 = INT_MAX }, 0, INT_MAX, VE },
{ "rc-lookahead", "Number of frames to look ahead for rate-control", OFFSET(rc_lookahead), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, VE },
{ "intra-refresh","Use Periodic Intra Refresh instead of IDR frames", ... AV_OPT_TYPE_BOOL ... },
{ "single-slice-intra-refresh", "Use single slice intra refresh", ... },
{ "forced-idr",   "If forcing keyframes, force them as IDR frames.", ... },
{ "no-scenecut",  "When lookahead is enabled, set this to 1 to disable adaptive I-frame insertion at scene cuts", ... },
{ "b_ref_mode", "Use B frames as references", ... consts disabled|each|middle }, { "multipass", ... consts disabled|qres|fullres },
{ "cq", ... }, { "surfaces", "Number of concurrent surfaces", ... }, { "gpu", "Selects which NVENC capable GPU to use…", ... },
{ "strict_gop", ... }, { "spatial-aq", ... AV_OPT_TYPE_BOOL }, { "temporal-aq", ... }, { "constrained-encoding", ... },
```
(`ldkfs`, `lookahead_level`, `tf_level` exist only under `#ifdef NVENC_HAVE_*` for newer SDKs; there is **no** boolean `cbr` option — use `rc=cbr`.) Recommended: `preset=p1` (or `p4` when headroom), `tune=ull` (or `ll`), `rc=cbr`, `zerolatency=1`, `delay=0`, `rc-lookahead=0`, `intra-refresh=1`, `forced-idr=1`, `no-scenecut=1`, `multipass=disabled`, `surfaces=4`, `bf=0` (via `set_max_b_frames(0)`), `g` huge. Device type `cuda` (`av_hwdevice_ctx_create(..., AV_HWDEVICE_TYPE_CUDA, ...)`) on Linux; `d3d11va` device works with NVENC on Windows (frames `AV_PIX_FMT_D3D11`).

**VAAPI** (`h264_vaapi` / `hevc_vaapi` / `av1_vaapi`; options from `libavcodec/vaapi_encode.h` + `hw_base_encode.h` + `vaapi_encode_h264.c`):
```c
// HW_BASE_ENCODE_COMMON_OPTIONS (hw_base_encode.h)
{ "idr_interval", "Distance (in I-frames) between key frames", OFFSET(common.base.idr_interval), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, FLAGS },
{ "b_depth", "Maximum B-frame reference depth", OFFSET(common.base.desired_b_depth), AV_OPT_TYPE_INT, { .i64 = 1 }, 1, INT_MAX, FLAGS },
{ "async_depth", "Maximum processing parallelism. Increase this to improve single channel performance.", OFFSET(common.base.async_depth), AV_OPT_TYPE_INT, { .i64 = 2 }, 1, MAX_ASYNC_DEPTH, FLAGS }
// VAAPI_ENCODE_COMMON_OPTIONS (vaapi_encode.h)
{ "low_power", "Use low-power encoding mode (only available on some platforms; may not support all encoding features)", OFFSET(common.low_power), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, FLAGS },
{ "max_frame_size", "Maximum frame size (in bytes)", OFFSET(common.max_frame_size), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, FLAGS },
// VAAPI_ENCODE_RC_OPTIONS: "rc_mode" with consts auto | CQP | CBR | VBR | ICQ | QVBR | AVBR ; "blbrc" (bool, block-level bitrate control)
// h264-specific (vaapi_encode_h264.c): "qp" (0-52), "quality" (higher = faster), "coder" cavlc|cabac|vlc|ac, "aud", "sei" flags identifier|timing|recovery_point|a53_cc, "profile" constrained_baseline|main|high|high10, "level"
// codec defaults table: b=0, bf=2, g=120, i_qfactor=1, i_qoffset=0, b_qfactor=6/5, b_qoffset=0, qmin=-1, qmax=-1
```
Recommended: `rc_mode=CBR`, `async_depth=1`, `b_depth=1` + `set_max_b_frames(0)` (default `bf=2` — must override!), `idr_interval=0`, `set_gop(...)` (default `g=120`), `low_power=1` on Intel where supported (VDENC), `quality=7` (Intel: higher = faster), `coder=cabac`. **FFmpeg's VAAPI encoder has no intra-refresh option** (none in the macros above) — periodic IDR only; to mimic refresh use large GOP + `forced` keyframes on `ctrl` requests. Device: `av_hwdevice_ctx_create(&dev, AV_HWDEVICE_TYPE_VAAPI, "/dev/dri/renderD128", NULL, 0)`. On this VM `libva2 2.23.0` is installed but there is no GPU → runtime only in CI with a GPU/`i965`/`iHD` driver.

**AMF** (`libavcodec/amfenc_h264.c`; FFmpeg 8 has `AV_HWDEVICE_TYPE_AMF` and works on Linux via Vulkan too): `usage` = `transcoding | ultralowlatency | lowlatency | webcam | high_quality | lowlatency_high_quality`; `quality` = `speed | balanced | quality`; `rc` = `cqp | cbr | vbr_peak | vbr_latency | qvbr | hqvbr | hqcbr`; bools `preencode, vbaq, enforce_hrd, filler_data, frame_skipping, latency, aud, me_half_pel, me_quarter_pel, smart_access_video, preanalysis`; ints `max_au_size, header_spacing, intra_refresh_mb, qp_i/qp_p/qp_b (−1..51), bf_delta_qp (4), bf_ref (1)`. Recommended: `usage=ultralowlatency`, `quality=speed`, `rc=cbr` (or `vbr_latency`), `latency=1`, `enforce_hrd=1`, `filler_data=0`, `intra_refresh_mb=<macroblocks per frame, e.g. width*height/256/60>` for gradual refresh, `bf=0`.

**VideoToolbox** (`libavcodec/videotoolboxenc.c`; encoders `h264_videotoolbox`, `hevc_videotoolbox`, `prores_videotoolbox`): common options `allow_sw` (bool 0), `require_sw` (bool 0), `realtime` (bool -1..1, default 0), `frames_before`, `frames_after` (bool 0), `prio_speed` (bool default −1), `power_efficient` (int −1), `spatial_aq` (int −1), `max_ref_frames` (int 0); H.264: `profile` baseline|constrained_baseline|main|high|constrained_high|extended, `level` 0..52, `coder` cavlc|vlc|cabac|ac, `a53cc` (1), `constant_bit_rate` (bool 0), `max_slice_bytes` (int −1); HEVC: `alpha_quality`. Recommended: `realtime=1`, `prio_speed=1`, `allow_sw=0` (probe hw first; retry `allow_sw=1` on failure), `constant_bit_rate=1` (Apple Silicon only; falls back to VBR otherwise), `max_ref_frames=1`, `bf=0`, `power_efficient=0`. VideoToolbox has no intra-refresh; rely on infinite GOP + forced IDR.

Runtime probing (§B.5): iterate a per-platform name list (`h264_nvenc, hevc_nvenc, av1_nvenc, h264_amf, hevc_amf, av1_amf, h264_qsv, hevc_qsv, av1_qsv, h264_vaapi, hevc_vaapi, av1_vaapi, h264_videotoolbox, hevc_videotoolbox, libx264, libopenh264`) with `encoder::find_by_name`, then try `av_hwdevice_ctx_create` + `open_as_with`; score by 3-frame warm-up time. `libopenh264` exists in FFmpeg only if the distro build enabled it — prefer the `openh264` crate (§3) for the always-available software path so we don't depend on FFmpeg build flags.

---

## 3. openh264 0.9.8 / openh264-sys2 0.9.8 (Cisco OpenH264)

### 3.1 Build (verified on this VM)

- `openh264-sys2-0.9.8/build.rs` compiles `upstream/codec/{common,processing,decoder,encoder}` as four static libs with `cc::Build` (`.cpp(true)`, `-fno-strict-aliasing -fstack-protector-all`, `.pic(true)`), i.e. **needs a C++ compiler** (g++/clang++ here; MSVC on Windows). Upstream = `https://github.com/cisco/openh264` commit `4a2615fac570c6ca1ed4f157b9fdab9466edfd80` (`upstream/VERSION`); blobs list refers to OpenH264 **2.6.0**.
- nasm handling (`build.rs try_compile_nasm`): on x86/x86_64 it tries `nasm_rs::Build::…compile_objects()`; **on failure it prints `Failed to compile NASM files, not using any assembly.` and continues with pure C++** (`let Ok(object_files) = … else { println!(…); return; }`). Env `OPENH264_NO_ASM=1` skips the attempt. Verified: the probe's build-script output (`/tmp/probe-openh264/target/release/build/openh264-sys2-*/output`) contains that line 4× and the crate still built and ran. aarch64/arm use `.S` files via `cc` (no nasm) — `HAVE_NEON_AARCH64`.
- Wall time here: 45.7 s for the whole probe (`CARGO_BUILD_JOBS=2`, release). README perf table (Ryzen 7950X3D, single thread): 1080p encode 23.7 ms without nasm vs 8.2 ms with nasm; decode 5.7 ms vs 2.8 ms. **CI should install `nasm`** for ~3× faster software H.264.
- `wide 1.1.1` dep does SIMD RGB↔YUV; `-C target-cpu=native` helps color conversion only.

### 3.2 Encoder API (`openh264-0.9.8/src/encoder.rs`)

```rust
use openh264::OpenH264API;                       // = openh264_sys2::DynamicAPI
use openh264::encoder::{Encoder, EncoderConfig, BitRate, FrameRate, RateControlMode, UsageType,
                        SpsPpsStrategy, Profile, Level, Complexity, QpRange, IntraFramePeriod, VuiConfig};
use openh264::formats::{YUVBuffer, YUVSource, RgbSliceU8, YUVSlices};

let api = OpenH264API::from_source();            // `source` feature; or DynamicAPI::from_blob_path(path)? with `libloading`
let cfg = EncoderConfig::new()                   // defaults: bitrate 120_000 bps, Quality RC, CameraVideoRealTime, threads 0(auto), intra period 0, skip_frames true
    .bitrate(BitRate::from_bps(12_000_000))
    .max_frame_rate(FrameRate::from_hz(60.0))
    .rate_control_mode(RateControlMode::Bitrate) // Quality | Bitrate | Bufferbased | Timestamp | BitrateModePostSkip | Off
    .usage_type(UsageType::ScreenContentRealTime) // CameraVideoRealTime | ScreenContentRealTime | CameraVideoNonRealTime | ScreenContentNonRealTime | InputContentTypeAll
    .skip_frames(false)                          // never drop frames for rate control in a remote-desktop stream
    .intra_frame_period(IntraFramePeriod::from_num_frames(0)) // 0 = no periodic IDR
    .sps_pps_strategy(SpsPpsStrategy::ConstantId)
    .num_threads(4)
    .complexity(Complexity::Low)
    .vui(VuiConfig::bt709());
let mut enc = Encoder::with_api_config(api, cfg)?;   // Encoder::new() = from_source + defaults (needs `source`)

// input: any `YUVSource` (I420 planes + strides). YUVBuffer::new(w,h) / from_vec / read_rgb8(RgbSliceU8::new(&rgb,(w,h))) / YUVSlices::new((y,u,v),(w,h),(sy,su,sv))
let bs = enc.encode(&yuv)?;                          // or encode_at(&yuv, Timestamp::from_millis(ms)); re-inits on dimension change
let frame_type = bs.frame_type();                    // FrameType::{IDR, I, P, Skip, IPMixed, Invalid}
for l in 0..bs.num_layers() {                        // layer 0 = SPS/PPS on IDR, then VCL
    let layer = bs.layer(l).unwrap();
    for n in 0..layer.nal_count() { let nal: &[u8] = layer.nal_unit(n).unwrap(); /* Annex-B, starts with 00 00 00 01 */ }
}
let mut out = Vec::new(); bs.write_vec(&mut out);    // or bs.to_vec(); bs.write(&mut impl Write)
enc.force_intra_frame();                             // "Forces the encoder to emit an intra frame (I-frame, "keyframe") for the next encoded frame." (encoder.rs:1046)
```
Escape hatch: `unsafe { enc.raw_api() }` → `EncoderRawAPI` (`set_option`, `get_option` on `ISVCEncoder`). Bitrate changes mid-stream currently require a new `Encoder` (no safe setter; raw `ENCODER_OPTION_BITRATE` via `raw_api().set_option`). Max slice size for MTU-aligned slices: `EncoderConfig::max_slice_len(bytes)`.

Measured here (probe, `num_threads(4)`, ScreenContentRealTime, Bitrate RC 8 Mbit/s, synthetic 1080p gradient, no nasm): **encode 23.4 ms/frame, decode 5.4 ms/frame**, 1.5 MB per 60 frames. **Correction (2026-10-24, the quality design's step 21, its risk R1): that probe ran on one thread.** `num_threads(n)` alone changes nothing: without `max_slice_len` the crate sets `SM_SINGLE_SLICE` with `uiSliceNum = 1` (`openh264-0.9.8/src/encoder.rs:1024`), and OpenH264 then sets `iMultipleThreadIdc = min(cores, slices) = 1` (`encoder_ext.cpp:2058`, upstream `4a2615f`). Threads need several slices: `max_slice_len(bytes)` selects `SM_SIZELIMITED_SLICE`, which gives one partition per thread (`:2417-2418`, at most `MAX_THREADS_NUM` = 4) and at most `MAX_SLICES_NUM` = 35 slices (`svc_enc_slice_segment.h:62`); `uiMaxNalSize` must be at least 420 (`:626`). `tornect-codec` does exactly that for `encoder_threads` 0 or 2..=4 (256 KiB slices, `SLICE_BYTES`) and keeps 1, one slice, as the default (decision M1-74 (5)). Two costs come with more than one slice: the loop filter skips slice edges (`iLoopFilterDisableIdc` 2, `:2059-2061`), and **GOM rate control is off**: `ratectl.cpp:1199-1202` drops the macroblock-row (GOM) QP adjustment when a picture has more than one slice, so QP is chosen once per picture. A configured QP range (`QpRange`) still holds either way; OpenH264 raises a minimum below 12 (`GOM_MIN_QP_MODE`) and holds both ends to 51 (`encoder_ext.cpp:389-390`). The demo's numbers with `--threads 1` and `0` are in `docs/notes/m1-media-evidence.md` ("The loopback demo"). The OpenH264 tracker was not searched for threading or size-limited-slice issues at `4a2615f`: this container's proxy refuses github.com's issue pages and its search API (`docs/VERIFICATION.md`, OPEN). Warnings printed by OpenH264 for screen content: `AdaptiveQuant … not supported yet for screen content, auto turned off`, `BackgroundDetection … auto turned off` (harmless; set `.adaptive_quantization(false).background_detection(false)` to silence).

### 3.3 Decoder API (`openh264-0.9.8/src/decoder.rs`)

```rust
use openh264::decoder::{Decoder, DecoderConfig, DecodeOptions, Flush, DecodedYUV};
use openh264::{nal_units, NalParser};
let mut dec = Decoder::new()?;                                   // = with_api_config(OpenH264API::from_source(), DecoderConfig::new())
// DecoderConfig::new().debug(false).flush_after_decode(Flush::Flush|NoFlush|Auto); unsafe num_threads(n) "will probably segfault" (decoder.rs:214-224)
let maybe: Option<DecodedYUV<'_>> = dec.decode(&annexb_bytes)?;  // accepts SPS/PPS only, headers+frames, or subsequent frames; Err on corrupt bitstream
if let Some(yuv) = maybe {
    let (w, h) = yuv.dimensions();                               // YUVSource trait: dimensions(), strides(), y(), u(), v()
    let mut rgb = vec![0u8; yuv.rgb8_len()]; yuv.write_rgb8(&mut rgb);   // or write_rgba8 (w*h*4); or upload y()/u()/v() planes to wgpu directly
    let ts = yuv.timestamp();
}
let rest: Vec<DecodedYUV<'_>> = dec.flush_remaining()?;          // at stream end
```
Error concealment is off by default (`error_concealment: 0`); no safe setter — via raw API `DECODER_OPTION_ERROR_CON_IDC` if we want conceal-on-loss (plan §B.4 says conceal/skip).

### 3.4 `libloading` mode & licensing

- Bindings: BSD-2-Clause (`openh264`, `openh264-sys2` `license = "BSD-2-Clause"`); Cisco OpenH264 source: BSD-2 (`upstream/LICENSE`). Patent note in `openh264-sys2-0.9.8/src/lib.rs:38-51` quoting Cisco's FAQ: royalty coverage only applies to **Cisco's binary module downloaded at install time**; compiling the source yourself "might or might not come with an elevated patent risk". The `source` build is technically the simplest; the legal choice (source vs. downloaded blob) is a product decision (§7 open questions).
- `libloading` feature: `DynamicAPI::from_blob_path(path)` verifies SHA-256 against `src/blobs/hashes.txt` — known files are OpenH264 **2.6.0** blobs: `libopenh264-2.6.0-linux64.8.so`, `libopenh264-2.6.0-linux-arm64.8.so`, `libopenh264-2.6.0-mac-arm64.dylib`, `libopenh264-2.6.0-mac-x64.dylib`, `libopenh264-2.6.0-android-*.8.so`, `libopenh264-2.6.0-ios.a`, plus Windows DLLs (`tests/reference/reference.txt`). `from_blob_path_unchecked` skips the hash. Blobs are downloaded from Cisco's CDN (http://ciscobinary.openh264.org/) — not bundled in the crate (`exclude = ["**/*.dll"]`). Both features can be enabled simultaneously (`DynamicAPI::{Source, Libloading}`).

---

## 4. AV1 in software: rav1e 0.8.1 (encoder) — and the decoder situation

### 4.1 API (`rav1e-0.8.1/src/api/config/{encoder,mod,speedsettings}.rs`, `src/api/context.rs`, `src/frame/mod.rs`)

```rust
use rav1e::prelude::*;   // Config, EncoderConfig, Context, Frame, Packet, FrameType, ChromaSampling, Rational, EncoderStatus, FrameParameters, FrameTypeOverride
let mut enc = EncoderConfig::with_speed_preset(10);         // 0..=10; >10 clamps to 10 (encoder.rs:137)
enc.width = 1920; enc.height = 1080;
enc.time_base = Rational::new(1, 60);
enc.chroma_sampling = ChromaSampling::Cs420; enc.bit_depth = 8;
enc.low_latency = true;                                     // "In this mode the frame reordering is disabled." (encoder.rs:80-83)
enc.set_key_frame_interval(0, 0);                           // max 0 → MAX_MAX_KEY_FRAME_INTERVAL = i32::MAX/3 = 715_827_882 (encoder.rs:23); larger values → InvalidMaxKeyFrameInterval
enc.bitrate = 8_000_000;                                    // >0 = bitrate mode; else quantizer (default 100)
enc.tiles = 4;                                              // or tile_cols/tile_rows (powers of two)
enc.speed_settings.rdo_lookahead_frames = 1;                // must be 1..=MAX_RDO_LOOKAHEAD_FRAMES
enc.error_resilient = false; enc.switch_frame_interval = 0; // switch frames require low_latency
let cfg = Config::new().with_encoder_config(enc).with_threads(4);   // threads need feature "threading"
let mut ctx: Context<u8> = cfg.new_context()?;
let mut f = ctx.new_frame();                                // v_frame::Frame<u8>; f.planes[i].data / .cfg.stride; Plane::copy_from_raw_u8(&mut self, src, src_stride, bytewidth)
ctx.send_frame((f, FrameParameters { frame_type_override: FrameTypeOverride::Key, ..Default::default() }))?; // forced keyframe; plain `ctx.send_frame(f)` otherwise
loop { match ctx.receive_packet() {
    Ok(p) => { /* p.data: Vec<u8> (OBU stream), p.frame_type: FrameType::{KEY,INTER,...}, p.input_frameno */ }
    Err(EncoderStatus::NeedMoreData) | Err(EncoderStatus::Encoded) => break,
    Err(EncoderStatus::LimitReached) => break, Err(e) => return Err(e.into()) } }
ctx.flush();  // = send_frame(None) at end of stream
```
`Config::validate()` rejects `reservoir_frame_delay` outside its range (probe hit `InvalidReservoirFrameDelay(1)`); leave it `None`. Sequence header for out-of-band signalling: `ctx.container_sequence_header()`.

### 4.2 Measured performance here (no asm, `CARGO_BUILD_JOBS=2`, release, 4 vCPU VMware, synthetic 1080p)

| config | result |
|---|---|
| `default-features=false` (⇒ **no `threading`**), speed 10, low_latency, 30 frames | 61.6 s → **2.0 s/frame** |
| + `features=["threading"]`, `with_threads(4)`, `tiles=4`, `rdo_lookahead_frames=1`, bitrate 8 Mbit | 19.4 s → **0.65 s/frame ≈ 1.5 fps**; first packet emitted only after several input frames (lookahead pipeline) |

Even allowing ~3–5× for nasm asm and a faster desktop CPU, rav1e speed 10 stays far below 30 fps at 1080p; it might reach ~15–30 fps at 480p. **Verdict: rav1e is not a viable "potato mode" encoder for Tornect; software fallback stays H.264 (openh264/x264). AV1 = hardware only (NVENC Ada+, VAAPI Arc/RDNA3+, AMF).** If a software AV1 path is ever wanted, it is SVT-AV1 preset 12 through FFmpeg (`libsvtav1`, needs a distro/static build with `--enable-libsvtav1`), not rav1e.

### 4.3 Pure-Rust AV1 decoders

- **rav1d 1.1.0** (`rav1d-1.1.0/`): Rust port of dav1d, `crate-type = ["staticlib","rlib"]`, but the public surface is the **C ABI** (`#[no_mangle] pub unsafe extern "C" fn dav1d_open(c_out: Option<NonNull<Option<Dav1dContext>>>, s: Option<NonNull<Dav1dSettings>>) -> Dav1dResult`, `src/lib.rs:323`), `default = ["asm","bitdepth_8","bitdepth_16"]`, **`asm` needs nasm on x86** (README), stable Rust OK for x86_64/aarch64. Usable only through hand-written unsafe glue (or by building it as the `libdav1d` behind the `dav1d` crate). Last release 2025-05.
- **dav1d 0.11.1** (safe bindings) → `dav1d-sys ^0.8.2` → system **libdav1d via pkg-config** (Ubuntu 26.04 has `libdav1d7 1.5.3` runtime; needs `libdav1d-dev`). Works but is a C dep like FFmpeg; FFmpeg 8's built-in `av1` decoder already uses libdav1d when built with it (Ubuntu's is), so a separate dav1d crate buys nothing while FFmpeg is our decode layer.
- Conclusion: decode AV1 via FFmpeg (`av1` hwaccel: d3d11va/vaapi/videotoolbox/cuda, or `libdav1d` software). No pure-Rust AV1 decode in v1.

---

## 5. Opus: `opus 0.4.0` → `opusic-sys 0.7.x` (libopus 1.6.1)

### 5.1 Build (verified here)

- `opus-0.4.0/Cargo.toml`: `[dependencies.opusic-sys] version = "0.7.3"` (resolves to 0.7.5). **Not** `audiopus_sys`.
- `opusic-sys` `default = ["bundled"]` → `cmake` crate builds the vendored `opus/` tree (`package_version` = **1.6.1**; `README.md`: "Target version 1.6.1", "Requirements: cmake when building with bundled"). Build output here: `-- Opus project version: 1.6.1`, producing `libopus.a`, linked `static=opus` (`build.rs`). Only **cmake + a C compiler** are required; **no pkg-config, no bindgen** (bindings are pre-generated; `build-bindgen` feature only for regenerating). Uses Ninja if present. Runtime CPU dispatch enabled by default (`OPUS_X86_MAY_HAVE_*=ON`). Optional features: `dred`, `osce` (neural DRED/enhancement, bigger binary), `fixed-point`, `no-simd`, `no-hardening`. `default-features=false` links a system `libopus` instead (`OPUS_LIB_DIR`, `OPUS_LIB_STATIC`).
- Runtime check from the probe: `opus::version()` = `"libopus 1.6.1"`.
- Licensing: libopus BSD-3 (with the Opus patent grant); `opus` crate MIT/Apache-2.0; `opusic-sys` BSD-3.

### 5.2 API (`opus-0.4.0/src/lib.rs`) — verified round-trip in `/tmp/probe-audio`

```rust
use opus::{Encoder, Decoder, Channels, Application, Bitrate, Signal, FrameSize, Bandwidth};
let mut enc = Encoder::new(48000, Channels::Stereo, Application::LowDelay)?;   // Voip | Audio | LowDelay(=OPUS_APPLICATION_RESTRICTED_LOWDELAY)
enc.set_bitrate(Bitrate::Bits(128_000))?;      // Bitrate::{Bits(i32), Max, Auto}
enc.set_vbr(true)?; enc.set_vbr_constraint(true)?;
enc.set_complexity(5)?;                        // 0..10; lower = less CPU
enc.set_inband_fec(true)?;                     // OPUS_SET_INBAND_FEC(1)
enc.set_packet_loss_perc(10)?;                 // 0..100
enc.set_signal(Signal::Music)?;                // Auto | Voice | Music
enc.set_expert_frame_duration(FrameSize::Ms10)?; // Arg (default: from input len) | Ms2_5 | Ms5 | Ms10 | Ms20 | Ms40 | Ms60 | Ms80 | Ms100 | Ms120
let lookahead = enc.get_lookahead()?;          // samples of algorithmic delay
// frame sizes @48 kHz: 2.5ms=120, 5ms=240, 10ms=480, 20ms=960 samples per channel; input slice len = frames*channels (interleaved i16 or f32)
let pcm: [i16; 480*2] = ...;                   // 10 ms stereo
let mut out = [0u8; 1500];
let n = enc.encode(&pcm, &mut out)?;           // bytes written; also encode_float(&[f32],..), encode_vec(&pcm, max_size)
// receiver
let mut dec = Decoder::new(48000, Channels::Stereo)?;
let mut pcm_out = vec![0i16; 480*2];           // MUST be sized to exactly the (expected) frame duration when using PLC/FEC (see 5.3)
let got = dec.decode(&out[..n], &mut pcm_out, false)?;   // returns samples *per channel* (480); decode_float variant exists
let got_plc = dec.decode(&[], &mut pcm_out, false)?;     // empty slice = packet lost → PLC (opus-0.4.0/src/lib.rs:709-713 "To represent packet loss, pass an empty slice")
let got_fec = dec.decode(&next_pkt, &mut pcm_out, true)?;// fec=true: decode the LBRR copy of the *previous* frame embedded in `next_pkt`
let nb = Decoder::get_nb_samples(&dec, &pkt)?;           // also opus::packet::{get_nb_frames, get_nb_samples, get_bandwidth, parse}
```
Probe output: 10 ms stereo silence → 3 bytes; `decode` / `decode(fec=true)` / PLC each returned 480 samples/ch. Encoder/Decoder are `Send` (not `Sync`); one state per stream.

### 5.3 FEC gotchas (matter for §B.4 "Opus LBRR")

- Official docs (https://opus-codec.org/docs/opus_api-1.5/group__opus__encoderctls.html): `OPUS_SET_INBAND_FEC` — 0 off; 1 "Inband FEC enabled. If the packet loss rate is sufficiently high, Opus will automatically switch to SILK even at high rates to enable use of that FEC."; 2 "Inband FEC enabled, but does not necessarily switch to SILK if we have music." **"This is only applicable to the LPC layer"** (SILK). Same note for DTX. → In-band FEC exists **only in SILK/hybrid modes**; `Application::LowDelay` (`OPUS_APPLICATION_RESTRICTED_LOWDELAY`) is CELT-only, and desktop/system audio (music, UI sounds) is coded by CELT anyway. **LBRR will be effectively inactive for Tornect's audio.** Keep `set_inband_fec(true)` + `set_packet_loss_perc` (cheap; helps when speech is dominant and app is `Voip`/`Audio`), but rely on the plan's **application-level redundancy** (piggy-back previous Opus frame in the next datagram — Opus frames are ~40–160 B at 128 kbit/10 ms so doubling is cheap) plus PLC. The `opus` crate exposes `set_inband_fec(bool)` only (values 0/1; no `2`).
- `opus_decode` docs (https://opus-codec.org/docs/opus_api-1.5/group__opus__decoder.html): `frame_size` "If this is less than the maximum packet duration (120ms; 5760 for 48kHz), this function will not be capable of decoding some packets. In the case of PLC (data==NULL) or FEC (decode_fec=1), then frame_size needs to be exactly the duration of audio that is missing … frame_size **must** be a multiple of 2.5 ms." The Rust wrapper derives `frame_size = output.len() / channels` — so pass a buffer of **exactly** one frame (e.g. 480×2) for PLC/FEC calls, and up to 5760×ch for normal decode of unknown packets. `decode_fec`: "If no such data is available, the frame is decoded as if it were lost."
- Choose `Application::Audio` (not `LowDelay`) if we want any chance of SILK/LBRR on speech; `LowDelay` saves only ~4 ms of lookahead. Frame size: 10 ms (§B.4) is fine; 5 ms increases overhead (~+20 %), 2.5 ms only exists in CELT mode.
- New in 1.5+/1.6: DRED (deep redundancy, `opusic-sys` feature `dred`, `OPUS_SET_DRED_DURATION`) — speech-only, needs `opus_decoder_dred_*` API not exposed by the `opus` crate. Ignore for v1.

---

## 6. cpal 0.18.2 (audio I/O)

- `cpal-0.18.2/Cargo.toml`: Linux/BSD deps `alsa = "0.11"` (**unconditional**), optional `alsa-sys 0.4` (`realtime`), `jack 0.13.5` (`jack`), `pipewire = { version = "0.10", features = ["v0_3_53"] }` (`pipewire`), `pulseaudio 0.3` (`pulseaudio`). Windows: `windows = "0.62"`, `windows-core = "0.62"` (WASAPI; `asio` optional). Apple: `coreaudio-rs 0.14.2`, `objc2 0.6`. Features: `default = []`, `jack`, `pipewire`, `pulseaudio`, `realtime`, `realtime-dbus`, `asio`, `audioworklet`, `custom`.
- Linux ALSA host is always compiled: `alsa 0.11` → `alsa-sys ^0.4.0` → `alsa-sys-0.4.0/build.rs` `pkg_config::Config::new().probe("alsa")` → panics `"Pkg-config failed - usually this is because alsa development headers are not installed … apt-get install libasound2-dev"`. **Verified here**: `pkg-config --exists alsa` → 1; `/tmp/probe-cpal` failed in 3.4 s with exactly that message. → **cpal cannot be built on this VM; CI needs `libasound2-dev`** (runtime needs only `libasound2` which is present: `libasound2t64 1.2.15.3`).
- `pipewire` host (`src/host/pipewire`, exported as `cpal::platform::PipeWireHost`, `HostId::PipeWire`; CHANGELOG 0.18.x lists many PipeWire fixes: xrun reporting, rtkit promotion, 24-bit mapping) → `pipewire 0.10` → `pipewire-sys` build.rs uses `system_deps` + **bindgen** (`.header("wrapper.h")`, `libpipewire` via pkg-config) → CI needs `libpipewire-0.3-dev` + `clang`/`libclang-dev`. `pkg-config --exists libpipewire-0.3` → 1 here. Runtime lib present (`libpipewire-0.3-0t64 1.6.2`). Since the capture crate already needs `pipewire` (plan §A.2), enable `cpal/pipewire` on Linux and prefer `HostId::PipeWire` when `Host::is_available()`; ALSA remains the default host (`cpal::default_host()`).
- `jack` host → `jack 0.13.5` → `jack-sys 0.5.1` default feature `dynamic_loading` (dlopen at runtime; no `libjack-dev` needed to *build*). Not needed for Tornect.
- `pulseaudio` feature is new in 0.18 (pure-Rust `pulseaudio 0.3` client).
- Timestamps monotonic across device/graph changes since 0.18.2 (CHANGELOG) — relevant for A/V sync.

---

## 7. raptorq 2.0.1 (RFC 6330 FEC) — verified here

- Pure Rust, `edition = "2024"`, no required deps; `std` feature default; `#![cfg_attr(not(feature="std"), no_std)]` (`src/lib.rs`). Apache-2.0.
- API (`src/lib.rs` re-exports; `src/encoder.rs`, `src/decoder.rs`, `src/base.rs`):

```rust
use raptorq::{Encoder, Decoder, EncodingPacket, ObjectTransmissionInformation, PayloadId, EncoderBuilder, SourceBlockEncoder, SourceBlockDecoder, SourceBlockEncodingPlan};

// sender: one RaptorQ object per video frame (or per keyframe / burst)
let enc = Encoder::with_defaults(&frame_bytes, symbol_size_u16);          // = Encoder::new(data, ObjectTransmissionInformation::with_defaults(len, mtu)) (encoder.rs:148-155)
let oti: ObjectTransmissionInformation = enc.get_config();
let oti_bytes: [u8; 12] = oti.serialize();                                 // base.rs:163-178: 5 B transfer_length (u40) | 1 B reserved | 2 B symbol_size | 1 B source_blocks | 2 B sub_blocks | 1 B alignment
let packets: Vec<EncodingPacket> = enc.get_encoded_packets(repair_per_block);   // all source symbols first, then `repair_per_block` repair symbols per block (encoder.rs:161-168)
for p in &packets { let wire: Vec<u8> = p.serialize(); /* 4-byte PayloadId (u8 block, u24 ESI) + symbol bytes */ }

// receiver
let mut dec = Decoder::new(ObjectTransmissionInformation::deserialize(&oti_bytes));
let mut done: Option<Vec<u8>> = None;
for wire in received { done = dec.decode(EncodingPacket::deserialize(&wire)); if done.is_some() { break; } }   // Some(data) once every block decodes; result truncated to transfer_length
// alternatively dec.add_new_packet(p); dec.get_result()
```
- Probe result: 20 000 B payload, MTU 1200 → 23 packets of 1204 B (17 source + 6 repair; symbol = 1200 B), OTI 12 B; dropping every 5th packet still recovered the exact data. README: reconstruction probability after K+h packets = 1 − 1/256^(h+1) → 2 extra packets ≈ 99.998 %.
- Sizing with quinn: the QUIC note found `max_datagram_size()` = **1162 B at MTU 1200** (`docs/research/quic.md`). Video datagram header (§B.4) is ~10 B, RaptorQ packet header 4 B → symbol size ≈ 1148 B (must be a multiple of `alignment`, default 8 → use 1144). Send the 12-byte OTI in the frame's first datagram header or derive it deterministically from (frame length, symbol size) on both ends via `ObjectTransmissionInformation::with_defaults(len, mtu)` — it is a pure function of those two inputs, so the OTI never needs to be transmitted if `len` is in the header.
- Performance (README, Ryzen 9950X3D): ~10–20 Gbit/s encode, ~5–7 Gbit/s decode at 1280 B symbols for 10–1000 symbols; a 1080p60 frame at 20 Mbit/s is ~42 KB ≈ 37 symbols → sub-100 µs. `SourceBlockEncodingPlan::generate(symbol_count)` can be cached per symbol count (`Encoder::new` already caches per block).
- Constraints: `transfer_length <= 942_574_504_275`, `symbol_size % alignment == 0`, ≤ 56 403 source symbols per block (asserts in `base.rs:120-146`). Systematic code: source packets are the plain fragments, so the XOR-parity path in §B.4 can share the same packetizer and the receiver can skip RaptorQ entirely when nothing was lost.

---

## 8. Compatibility constraints (version alignment)

- **rand_core / digest / sha2**: none of the codec crates depend on RustCrypto or rand at runtime. `openh264-sys2` pulls `sha2 ^0.10.8` **only with the `libloading` feature** (crypto.md standardises on the 0.11 line — two sha2 majors would coexist, harmless but duplicated; prefer `source` only). `openh264` dev-deps `rand 0.10` (tests only). `raptorq` dev-deps `rand 0.9` (tests only).
- **rustls**: no interaction (no TLS in any codec crate).
- **wgpu**: no direct coupling; NV12/P010 upload path is plain buffers from `frame::Video::data(i)`/`stride(i)` or `DecodedYUV::y()/u()/v()`. Zero-copy interop later needs matching Vulkan/D3D12/Metal handles — FFmpeg's `AV_PIX_FMT_VULKAN` (`AVVulkanDeviceContext` bound via the stub header) is the only cross-vendor route and is a v2 topic.
- **windows-rs**: `cpal 0.18.2` pins `windows = "0.62"` / `windows-core = "0.62"` — align the WGC capture crate on `windows 0.62` to avoid two copies.
- **bindgen**: `ffmpeg-sys-next` (0.72, runtime), `pipewire-sys`, `alsa-sys` (`use-bindgen` optional), `opusic-sys` (optional) — all agree on libclang at build time in CI; no version conflict (build deps are per-crate).
- **Rust**: everything builds on 1.96 stable; `ffmpeg-sys-next 9.0.0` uses edition-2024 `let`-chains (≥ 1.88); `openh264` 1.85; `cpal` 1.85; `rav1e` 1.83; `opusic-sys` 1.82.
- **libopus in two places**: if FFmpeg were ever used for audio too, avoid linking two libopus copies — we use the `opus` crate only (FFmpeg `codec` feature does not require libopus).

---

## 9. Build-requirements matrix

| Crate | Needs at build | This VM | GitHub Actions (ubuntu) | Windows / macOS notes |
|---|---|---|---|---|
| ffmpeg-next / -sys-next 9.0.0 (system FFmpeg) | `pkg-config`, `libavcodec-dev libavutil-dev libswscale-dev` (+ `libavformat/avfilter/avdevice/swresample-dev` per feature), libclang (`clang`/`libclang-dev`) for bindgen | **no** (no libav headers) | `apt-get install clang libclang-dev pkg-config libavcodec-dev libavutil-dev libswscale-dev` → FFmpeg 8.0.1 | Win: vcpkg `ffmpeg[nvcodec,amf,qsv]` or `FFMPEG_DIR` + LLVM; mac: `brew install ffmpeg llvm` |
| ffmpeg-sys-next `build` | git, make, C toolchain, nasm/yasm, `--enable-*` deps (x264 etc.) | no | yes (slow; cache OUT_DIR) | same |
| openh264 0.9.8 `source` | C++ compiler (+ optional nasm) | **yes** (verified, no nasm) | yes; add `nasm` for speed | MSVC/clang; nasm optional |
| opus 0.4.0 (opusic-sys bundled) | cmake + C compiler | **yes** (verified) | yes | yes (cmake) |
| raptorq 2.0.1 | nothing | **yes** | yes | yes |
| rav1e 0.8.1 (`default-features=false, features=["threading"]`) | nothing (asm feature needs nasm) | **yes** (verified) | yes | yes |
| cpal 0.18.2 | `libasound2-dev` (always on Linux); `libpipewire-0.3-dev` + libclang for `pipewire` | **no** (verified failure) | `apt-get install libasound2-dev libpipewire-0.3-dev clang` | Win/mac: nothing extra |

Runtime (Linux): `libavcodec62 libavutil60 libswscale9 libswresample6` (Ubuntu 26.04 package names, all `7:8.0.1-3ubuntu2` per `dpkg -l` here), `libva2` + vendor VA driver (`intel-media-va-driver`, Mesa `radeonsi`), NVIDIA driver for NVENC/CUDA, `libasound2`, `libpipewire-0.3-0`. Audio and H.264-software paths carry no runtime deps (static libopus / openh264).

---

## 10. Gotchas (collected)

1. `ffmpeg_next::codec::Context` has **no** `Settable` impl → private options only via `open_with`/`open_as_with(Dictionary)`; changing bitrate live needs raw `av_opt_set_int((*ctx).priv_data … )` or `(*ctx).bit_rate = …` + encoder-specific reconfigure (NVENC supports live `bit_rate` changes; x264 via `x264_encoder_reconfig` internally when `bit_rate`/`rc_max_rate` change before the next frame).
2. `frame::Video::new(Pixel::VAAPI, ..)` would call `av_frame_get_buffer`, which **cannot allocate hw surfaces** → always `av_hwframe_get_buffer` for hw frames (§2.4).
3. `ffmpeg-next` default features pull `libavdevice`/`libavfilter`/`libavformat` — disable them.
4. VAAPI defaults `bf=2`, `g=120` — override `max_b_frames=0`/`gop`; VAAPI has **no** intra-refresh option.
5. Ubuntu FFmpeg is a GPL build (libx264) — linking it makes the Tornect binary GPL-bound; the `openh264` crate (BSD) avoids this for the software path. Decide the app license first (§F of the plan).
6. `openh264` decoder `num_threads` is `unsafe` and "will probably segfault"; keep single-threaded (5 ms/frame at 1080p measured anyway).
7. `openh264` `Encoder::encode` re-initialises the encoder when the input dimensions change — expect an IDR and a latency spike; drive resolution ladder changes deliberately.
8. `rav1e` with `default-features=false` silently loses `threading`; add it back. Keyframe interval cap is 715 827 882 (use `set_key_frame_interval(0, 0)`).
9. Opus in-band FEC only in SILK (speech) modes; CELT (music/desktop audio) gets none → app-level redundancy. PLC/FEC decode calls need an output buffer of exactly one frame.
10. `cpal` on Linux always requires ALSA dev headers to build even when using the PipeWire host.
11. `raptorq` `symbol_size` must be a multiple of `alignment` (default 8) and the 12-byte OTI is derivable from (length, mtu) — don't waste header bytes.
12. FFmpeg ABI: binaries built against FFmpeg 8 (`.so.62`) will not load on FFmpeg 9 systems (`.so.63`) and vice versa; ship FFmpeg with the app for releases (static `build` feature or bundled libs), use the distro lib only for dev/CI.
13. `ffmpeg-sys-next` bindings are regenerated per build against local headers; `cfg(feature = "ffmpeg_8_0")`-style gates are available in *our* crate too via `DEP_FFMPEG_*` only if we replicate ffmpeg-next's `build.rs` trick (it forwards `DEP_FFMPEG_FFMPEG_8_0=true` → `cargo:rustc-cfg=feature="ffmpeg_8_0"`, `ffmpeg-next-9.0.0/build.rs`).

---

## 11. Open questions

1. **License / patent posture for H.264**: compile OpenH264 from source (BSD, simplest, "might come with elevated patent risk") vs. download Cisco's 2.6.0 blob at install time (`libloading`, covered by Cisco's MPEG-LA payment) — product/legal decision; both are supported by the same crate API (`DynamicAPI`).
2. Whether to redistribute FFmpeg (static `build` feature per platform, ~10–20 min CI per target, needs `--enable-nvenc/--enable-amf/--enable-vaapi/--enable-videotoolbox` and their headers `nv-codec-headers`, `AMF` headers) or depend on system FFmpeg on Linux only and vendor prebuilt FFmpeg DLLs/dylibs on Windows/macOS.
3. The hw-context glue in §2.4 is transliterated from the C API and **not compiled here** (no headers on this VM); the first CI job with `libavcodec-dev` should compile a `tornect-codec` smoke test that at least creates a `vaapi`/`cuda` device (expect `ENOENT`/`ENOSYS` without hardware, which still validates linking and struct layouts).
4. Zero-copy DMA-BUF→VAAPI (`AV_PIX_FMT_DRM_PRIME` + `av_hwframe_map`) and D3D11 texture import need a GPU to verify; on this VM everything is CPU-upload (`av_hwframe_transfer_data`).
5. Text-mode 4:4:4: openh264 is 4:2:0 only; x264 `high444` works; NVENC 4:4:4 needs `profile=high444p` (h264) or HEVC `rext`; VAAPI 4:4:4 is driver-specific — needs per-encoder capability probing at runtime.
6. Whether an app-level "audio redundancy" (duplicate previous Opus frame) or a RaptorQ block over a few audio frames is better under bursty loss — the former is simpler and latency-free; measure once the transport exists.
7. rav1e is excluded from v1 by the measurements above; revisit only if a CPU-only AV1 path is demanded (then via FFmpeg `libsvtav1`).
