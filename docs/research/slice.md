# Research: the vertical-slice stack (UI, codec, capture, input; Linux + Windows)

**Status:** verified 2026-09-21 by a research_verifier sub-agent against crates.io, docs.rs
and the crate sources, plus the PipeWire 1.6.2, xdg-desktop-portal 1.21.1,
xdg-desktop-portal-gnome 50.0 and mutter 50.1 sources. Full report with every citation:
`/home/mx/kore_project_V3/agents/architecture/reports/sub/2026-09-21_SUB_RESEARCH_VERIFIER_media_platform_ui.md`.
Scope ruling: operator, 2026-09-21, "vertical slice first" (decision M3-1).

## 0. Pins (workspace `Cargo.toml`)

| crate | pin | features / notes | MSRV |
|---|---|---|---|
| winit | =0.30.13 | defaults (rwh_06, x11, wayland, **wayland-dlopen**, wayland-csd-adwaita — CSD is required on GNOME) | 1.70 |
| egui / egui-winit / egui-wgpu | =0.36.2 | egui-winit: `clipboard, wayland, x11` (drops `links`); egui-wgpu: **`default-features = false`**, `winit, wayland, x11` (defaults enable every wgpu backend + webgl) | 1.95 |
| wgpu | =30.0.1 | `std, wgsl, parking_lot`; backends per target in the member crate: Linux `vulkan, gles`, Windows `dx12` (a target with no backend ⇒ `Instance::new` panics) | 1.87 |
| pollster | =1.0.1 | `block_on` for the async egui-wgpu painter calls | 1.69 |
| openh264 | =0.9.8 | `source` only (Cisco OpenH264 2.6.0 C++ built by `cc`; nasm optional — none on the VM, pure C++ then; no cmake) | 1.85 |
| ashpd | =0.13.13 | `tokio, screencast, remote_desktop`; pure Rust over zbus 5.x (compatible with the pinned zbus 5.19 / tokio); never `async-io` | 1.87 |
| libloading | =0.8.9 | dlopen `libpipewire-0.3.so.0` (no PipeWire headers or libclang on the VM) | 1.71 |
| x11rb | =0.13.2 | `xtest, xfixes` (0.13 is the copy winit already pulls; 0.14.0 exists) | 1.64 |
| windows-sys | =0.61.2 | `Win32_Foundation, Win32_Graphics_Gdi, Win32_UI_WindowsAndMessaging, Win32_UI_Input_KeyboardAndMouse, Win32_UI_HiDpi` | 1.71 |

Linux-only: ashpd, libloading, x11rb (and the already-gated zbus). Windows-only: windows-sys.
`windows` 0.62.2 (COM) only if DXGI Desktop Duplication is added later. windows-rs published
its core crates at 0.100 on 2026-09-03 but not the `windows`/`windows-sys` umbrellas — stay put.

## 1. Windows cross-build: `x86_64-pc-windows-gnullvm` + llvm-mingw

- Toolchain: llvm-mingw **20260908** (clang 23.1.1, UCRT), user-space at
  `~/.local/opt/llvm-mingw-20260908-ucrt-ubuntu-22.04-x86_64` (release asset sha256
  `2258c745e3155870c80793f3e8c80b28fbde11b9ff73c4c78783635b3440b092`, checked). Its `bin/`
  must be on `PATH` (target default linker `x86_64-w64-mingw32-clang`; `cc` uses the same
  names). No sudo, no MSVC, no Wine.
- **Blocker, fixed:** `cc` asks for `-lstdc++` on every non-MSVC target; llvm-mingw ships only
  libc++ ⇒ `CXXSTDLIB_x86_64_pc_windows_gnullvm = "c++"` (`.cargo/config.toml` `[env]`).
- `+crt-static` for the target (`.cargo/config.toml`): libunwind and libc++ link statically
  (llvm-mingw's `libc++.a` includes the ABI library), so `tornect.exe` needs no DLLs beside it.
  **Corrected 2026-09-23 (decision M1-51, `818bb8a`):** not for libc++. The first link of the whole
  app imported `libc++.dll`, because `cc` emits `rustc-link-lib=c++`, a dylib request, and lld picks
  `libc++.dll.a`. Now `CXXSTDLIB_x86_64_pc_windows_gnullvm = ""` and `-C link-arg=-l:libc++.a` in the
  target's rustflags; `tornect.exe` imports only DLLs Windows ships. (Wine 10.0 and nasm 3.01 are on
  the build VM since 2026-09-23.)
- rustc 1.96 builds `raw-dylib` import libraries itself for gnullvm — no dlltool.
- **Verified 2026-09-21:** `cargo build --target x86_64-pc-windows-gnullvm -p tornect-codec`
  compiles OpenH264's C++ with llvm-mingw clang++ and links (33 s); `tornect-input` (SendInput)
  and `tornect-proto` check clean. Arti's C dependencies (ring, bundled sqlite, zstd) on
  gnullvm: not yet built (next session).

## 2. UI (D10 egui-everywhere fallback)

- The manual winit loop receives `WindowEvent::KeyboardInput { event: KeyEvent { physical_key, .. } }`
  before it chooses to forward to `egui_winit::State::on_window_event`; egui drops keys it
  cannot map (`key_from_key_code` → `None`), so during a remote session keys bypass egui.
- `winit::platform::scancode::PhysicalKeyExtScancode::to_scancode` gives the platform code
  for free: Windows Set-1 with E0 in the high byte, Linux evdev — map it to the USB usage with
  `tornect_input::keymap::{by_win, by_evdev}`.
- Frame upload: a native `Rgba8Unorm` wgpu texture registered once with
  `renderer.write().register_native_texture(&device, &view, FilterMode::Linear)`; per frame
  `queue.write_texture(.., bytes_per_row = 4*w)` (no 256-byte alignment for `write_texture`),
  drawn with `ui.painter().image(tex_id, rect, uv 0..1, WHITE)`. Avoid `TextureHandle::set`
  for video (a new GPU texture per frame); `set_partial` is the simple fallback. Avoid BGRA
  textures on GLES.
- Painter: `Painter::new(ctx, WgpuConfiguration, bool, RendererOptions)` and `set_window` are
  async (pollster); `paint_and_update_textures(viewport, ppp, clear, &prims, &mut delta, vec![], &window)`.
- Limits: no keyboard-shortcuts-inhibit on Wayland (GNOME keeps Super, Alt+Tab); on Windows
  the shell keeps Win, Alt+Tab, Ctrl+Alt+Del.

## 3. Codec (openh264 0.9.8)

- Encoder: `EncoderConfig::new().bitrate(..).max_frame_rate(..).usage_type(ScreenContentRealTime)
  .rate_control_mode(Bitrate).skip_frames(false).intra_frame_period(0).complexity(Low)
  .vui(VuiConfig::bt601())` — **BT.601**, because the crate's RGB↔YUV converters are BT.601
  limited range (codecs.md §3.2's `bt709()` would mis-tag the colours).
- Input: tightly packed rows, **even** width and height, ≤ 3840×2160 wide or ≤ 2160×3840
  upright (the crate's `Encoder::reinit` refuses only a long side over 3840 or a short side
  over 2160; `tornect-codec` crops an odd edge and clamps in the picture's own orientation). `YUVBuffer::from_bgra8_source(BgraSliceU8::new(..))` takes BGRx directly.
- `force_intra_frame()` → next AU is an IDR. Decoder: `Decoder::new()?.decode(au)? →
  write_rgba8`; no decoder threads (unsafe API).
- Licence: bindings + Cisco source BSD-2-Clause. Cisco's patent coverage applies only to its
  binary blob; a source build "might or might not come with an elevated patent risk" — the
  plan defers that decision to M8 (§B.5).
- **Verified 2026-09-21:** encode → decode round trip on this VM (geometry, colour order,
  forced IDR), 3 tests.

## 4. Linux Wayland: RemoteDesktop portal + PipeWire (dlopen)

- One RemoteDesktop session that also selects ScreenCast sources (one consent dialog covers
  screen + keyboard + pointer): `create_session` → `select_devices(Keyboard|Pointer,
  PersistMode::ExplicitlyRevoked, restore_token)` → `select_sources(Monitor, Embedded cursor)`
  (no persistence there) → `start` (the dialog) → `pipe_wire_node_id()`, logical `size()`,
  `restore_token()` → `open_pipe_wire_remote` (an `OwnedFd`).
- Input: `notify_pointer_motion_absolute(stream, x, y)` in **logical** coordinates with
  `0 ≤ x < width`; `notify_pointer_button` with evdev codes (`BTN_LEFT` 0x110 …);
  `notify_pointer_axis_discrete(axis, steps)` (steps ≠ 0; winit `LineDelta.y` → `-y`);
  `notify_keyboard_keycode` with **evdev** codes. GNOME's portal implements all `Notify*`
  (xdg-desktop-portal-gnome 50.0). **Never call `connect_to_eis`** — it disables `Notify*`.
- PipeWire without headers: dlopen `libpipewire-0.3.so.0` (1.6.2 exports every symbol
  needed); thread loop + `pw_context_connect_fd` (takes the fd) + `pw_stream_connect(INPUT,
  node, AUTOCONNECT|MAP_BUFFERS, [EnumFormat], 1)`. Mirror structs (x86_64): `pw_stream_events`
  (version **2**, 96 bytes), `spa_hook` (48, Box-pinned until destroy), `pw_buffer`,
  `spa_buffer`, `spa_data`, `spa_chunk` — layouts and the **232-byte EnumFormat pod**
  (BGRx default + BGRx/BGRA/RGBx/RGBA, size range, framerate range **including 0/1**) are in
  report §4.3/§4.6. Mutter offers only BGRx/BGRA and variable framerate 0/1; no modifier ⇒
  MemFd buffers. Read size from the negotiated `Format` param (not the portal's logical size),
  stride from each chunk; always requeue buffers. Frames arrive only on damage.

## 5. Linux X11 fallback (x11rb 0.13.2)

- Capture: `get_image(Z_PIXMAP, root, 0, 0, w, h, !0)` (BGRx, cursor not included — add the
  XFIXES cursor image). Input: `xtest_fake_input` (motion 6, buttons 4/5, keys 2/3 with keycode
  = evdev + 8), then `flush()`. **Only on `XDG_SESSION_TYPE=x11`** — under Xwayland only X11
  windows are visible and XTEST reaches only X11 clients.

## 6. Windows capture + input (windows-sys 0.61.2)

- GDI: `GetDC(0)` → `CreateCompatibleDC` → top-down 32-bit `CreateDIBSection` →
  `BitBlt(SRCCOPY)` from the virtual-screen origin (`SM_X/YVIRTUALSCREEN`,
  `SM_CX/CYVIRTUALSCREEN`) → `GdiFlush`; cursor via `GetCursorInfo` + `DrawIconEx`. DXGI
  Desktop Duplication is the step after the slice. No `CAPTUREBLT`: it makes Windows hide and
  re-show the pointer around every blit, so the host's pointer flickers for the whole session
  (Mozilla bug 1053264, fixed in Firefox 35 by dropping the flag where DWM composes; FFmpeg's
  gdigrab thread on the same flicker). DWM, always on from Windows 8, composes layered windows
  into the screen DC already; NEEDS-DEVICE(windows) for that check.
- `SendInput`: absolute moves with `MOVE | ABSOLUTE | VIRTUALDESK` over 0..65535 (the GDI
  picture is the virtual desktop, so the normalized coordinates pass through); keys by
  `KEYEVENTF_SCANCODE` (+`EXTENDEDKEY` for E0), Pause/NumLock by VK. winit sets per-monitor
  v2 DPI awareness; a host path without winit must call `SetProcessDpiAwarenessContext` first.
- Limits: UIPI silently blocks input into elevated windows; the secure desktop (UAC, lock
  screen) cannot be captured or controlled from a user-session process.

## 7. Key table

Chromium `ui/events/keycodes/dom/dom_code_data.inc` (BSD-3-Clause; notice kept in
`crates/tornect-input/src/keymap.rs`), fetched 2026-09-21, sha256 `841e2c58…e5b2`: 181 rows
with a USB usage and an evdev or Windows code. The USB usage is what travels on the wire.

## 8. Not yet verified (NEEDS-DEVICE or next session)

GDI/SendInput at runtime (Windows machine); PipeWire negotiation with mutter on a live
session (needs a portal dialog click); the egui-wgpu build with per-target backends; Arti on
gnullvm; X11 behaviour under Xwayland.
