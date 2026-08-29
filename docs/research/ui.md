# UI / rendering / desktop-integration stack — research note (verified 2026-08-28)

Scope: plan §A.3 D10 (egui/eframe control UI, winit+wgpu stream window, tray/rfd), D11
(client-side input capture incl. raw mouse + gamepad), D13 (config dirs, keyring), and the
client render path of §B.5 (decode → wgpu NV12/P010 shader → present). Everything below was
checked against crate sources extracted into `/tmp/crates-src/<crate>-<version>/` (from
`static.crates.io`), the crates.io API, upstream GitHub files (URLs inline), and a probe crate
at `/tmp/probe-ui` that was **compiled on this VM** (Rust 1.96, Ubuntu 26.04, GNOME/Wayland,
no sudo; target dir moved to `~/.cache/tornect-probe-ui-target` because `/tmp` is a 3.7 GB
tmpfs). Line references are into the extracted sources.

Probe results are in §8 (what built here vs. what needs CI packages).

---

## 0. TL;DR for implementers

| Item | Decision |
|---|---|
| Versions | `egui`/`eframe`/`egui-wgpu`/`egui-winit`/`egui_extras` **=0.36.1**, `wgpu` **=30.0.1**, `winit` **=0.30.13** — one wgpu, one winit, everywhere. eframe 0.36.1 itself requires `wgpu = "30.0"` (via egui-wgpu) and `winit = "0.30.13"`, so no downgrade is needed (§2). |
| Renderer | eframe 0.36 **defaults to wgpu** (`glow` is opt-in) — `eframe-0.36.1/Cargo.toml:60-69`. Never enable `glow`. |
| Window architecture | **Own the winit 0.30 event loop** (`ApplicationHandler`) and drive `egui-winit::State` + `egui-wgpu::winit::Painter` yourself for *both* the control window and the stream window (§4). Reason: winit allows one event loop per process, eframe exposes no raw winit events (only `App::raw_input_hook` on `egui::RawInput`), and egui-winit **drops** physical keys it cannot map to `egui::Key` (PrintScreen, ScrollLock, Pause, NumLock, CapsLock, ContextMenu, media keys… `egui-winit-0.36.1/src/lib.rs:1656`). A remote-desktop client must forward every scancode. eframe remains fine for prototypes/tools (§3.1). |
| eframe `App` trait (if used) | 0.34+ replaced `App::update` with `fn logic(&mut self, &egui::Context, &mut Frame)` + `fn ui(&mut self, ui: &mut egui::Ui, frame: &mut Frame)` ([eframe CHANGELOG 0.34.0, #7775](https://github.com/emilk/egui/blob/0.36.1/crates/eframe/CHANGELOG.md)). `run_native(name, NativeOptions, Box<dyn FnOnce(&CreationContext) -> Result<Box<dyn App>, DynError>>) -> eframe::Result`. |
| Custom GPU blit | `egui_wgpu::CallbackTrait { prepare, finish_prepare, paint(&self, PaintCallbackInfo, &mut wgpu::RenderPass<'static>, &CallbackResources) }` + `egui_wgpu::Callback::new_paint_callback(rect, cb)` (`egui-wgpu-0.36.1/src/renderer.rs:28-120`). Device/queue come from `egui_wgpu::RenderState { instance, adapter, device, queue, target_format, renderer: Arc<RwLock<Renderer>> }` (`src/lib.rs:107-137`), reachable via `CreationContext::wgpu_render_state` / `Frame::wgpu_render_state()` (eframe) or `Painter::render_state()` (manual). Verified NV12→RGB WGSL pipeline compiles in the probe (§5.2). |
| Pointer lock | `Window::set_cursor_grab(CursorGrabMode::Locked).or_else(|_| …Confined)` + `set_cursor_visible(false)`; raw deltas from `DeviceEvent::MouseMotion { delta }` (`winit-0.30.13/src/event.rs:479-483`). Locked: unsupported on X11; Confined: unsupported on macOS (`src/window.rs:1687-1712`). Wayland uses `zwp_pointer_constraints` + `zwp_relative_pointer` (unaccelerated deltas). |
| Keyboard | `WindowEvent::KeyboardInput { event: KeyEvent { physical_key: PhysicalKey, logical_key: Key, text, state, repeat, .. }, is_synthetic }`. Send `physical_key` (`PhysicalKey::Code(KeyCode)` = layout-independent scancode) **and** `logical_key`/`text` to the host (plan §B.5). |
| Tray | `tray-icon 0.24.2` needs **GTK3 + libappindicator dev headers on Linux** and a gtk main loop on its own thread → cannot build on this VM. Feature-gate it (`tray` cargo feature, on by default only for Windows/macOS), CI installs `libgtk-3-dev libayatana-appindicator3-dev libxdo-dev`. |
| File dialogs | `rfd = "=0.17.2"`, `default-features = false`, `features = ["xdg-portal"]`. Portal backend `dlopen`s `libdbus-1` at runtime (no link-time dep, no zbus, no GTK) and falls back to `zenity`. There is **no `tokio` feature** in rfd 0.17 (features: `common-controls-v6, file-handle-inner, gtk3, wayland, xdg-portal`). |
| Clipboard | `arboard = "=3.6.1"`, `features = ["wayland-data-control", "image-data"]` (pure Rust `wl-clipboard-rs`; needs `ext-data-control-v1`/`wlr-data-control` on the compositor — GNOME Mutter does not expose them, see gotchas). egui-winit already uses `smithay-clipboard` on Wayland and arboard on X11 for its own copy/paste. |
| Gamepad | `gilrs = "=0.11.2"` (`gilrs-core 0.6.8`): Linux uses **`libudev-sys` → `pkg-config libudev`** at build time (`libudev-sys-0.1.4/build.rs`) → needs `libudev-dev`; **fails on this VM**, CI-only. Runtime is evdev (`/dev/input/event*`). |
| Notifications | `notify-rust = "=4.18.0"` default feature `z` = zbus 5 (pure Rust, `async-io`); use `default-features=false, features=["z-with-tokio"]` in a tokio app (zbus picks tokio when both enabled). |
| Secrets | Do **not** use `keyring::Entry` (v1 shim) — it force-installs the zbus Secret Service store on first use (`keyring-4.1.6/src/v1.rs:47-51,108-123`). Depend on `keyring-core = "=1.0.0"` + per-OS stores: `linux-keyutils-keyring-store =1.0.0` (pure Rust syscalls, no daemon), `zbus-secret-service-keyring-store =1.0.0` (`features=["rt-tokio-crypto-rust"]`), `apple-native-keyring-store =1.0.2`, `windows-native-keyring-store =1.1.0`. |
| Headless/software GPU | lavapipe ICD present: `/usr/share/vulkan/icd.d/lvp_icd.json` → `libvulkan_lvp.so`. Select with `WGPU_BACKEND=vulkan` + `RequestAdapterOptions { force_fallback_adapter: true, .. }` or `VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json`. `WGPU_ADAPTER_NAME=llvmpipe` also works with `wgpu::util::initialize_adapter_from_env`. |
| QR | `qrcode = "=0.14.1"`, `default-features = false` → `QrCode::new(bytes)?.to_colors()` → `egui::ColorImage::from_gray(size, &gray)` → `ctx.load_texture(name, img, TextureOptions::NEAREST)` → `egui::Image::from_texture(&tex).fit_to_exact_size(..)`. No `image` crate, no egui_extras loader needed. |
| MSRV | egui 0.36 requires **Rust 1.95** (crates.io `rust_version`); wgpu 30 = 1.87, notify-rust 4.18 = 1.89, keyring 4.1.6 = 1.88, image 0.25.10 = 1.88. Workspace `rust-version = "1.95"`. |

---

## 1. Versions (crates.io API, 2026-08-28)

| crate | pin | released | MSRV | source |
|---|---|---|---|---|
| egui | 0.36.1 | 2026-08-07 | 1.95 | https://crates.io/api/v1/crates/egui |
| eframe | 0.36.1 | 2026-08-07 | 1.95 | https://crates.io/api/v1/crates/eframe |
| egui-wgpu | 0.36.1 | 2026-08-07 | 1.95 | https://crates.io/api/v1/crates/egui-wgpu |
| egui-winit | 0.36.1 | 2026-08-07 | 1.95 | https://crates.io/api/v1/crates/egui-winit |
| egui_extras | 0.36.1 | 2026-08-07 | 1.95 | https://crates.io/api/v1/crates/egui_extras |
| epaint | 0.36.1 | — | — | https://crates.io/api/v1/crates/epaint |
| wgpu | 30.0.1 | 2026-08-22 | 1.87 | https://crates.io/api/v1/crates/wgpu (wgpu-types/-core/-hal 30.0.1) |
| winit | 0.30.13 | 2026-03-02 | 1.70 | https://crates.io/api/v1/crates/winit — 0.31.0-beta.2 (2025-11-16) is *not* stable; eframe/egui-winit pin `0.30.13` |
| tray-icon | 0.24.2 | 2026-07-27 | 1.73 | https://crates.io/api/v1/crates/tray-icon |
| muda | 0.19.3 | 2026-06-17 | 1.73 | https://crates.io/api/v1/crates/muda (pulled by tray-icon; not needed directly) |
| rfd | 0.17.2 | 2026-01-12 | — | https://crates.io/api/v1/crates/rfd |
| arboard | 3.6.1 | 2025-08-23 | 1.71 | https://crates.io/api/v1/crates/arboard |
| gilrs / gilrs-core | 0.11.2 / 0.6.8 | 2026-05-30 | 1.84 / 1.80 | https://crates.io/api/v1/crates/gilrs |
| notify-rust | 4.18.0 | 2026-06-16 | 1.89 | https://crates.io/api/v1/crates/notify-rust |
| keyring / keyring-core | 4.1.6 / 1.0.0 | 2026-08-01 | 1.88 | https://crates.io/api/v1/crates/keyring |
| linux-keyutils-keyring-store | 1.0.0 | — | — | `keyring-4.1.6/Cargo.toml:143-145` |
| zbus-secret-service-keyring-store | 1.0.0 | — | — | `keyring-4.1.6/Cargo.toml:126-129` |
| apple-native-keyring-store / windows-native-keyring-store | 1.0.2 / 1.1.0 | — | — | crates.io API |
| directories | 6.0.0 | 2025-01-12 | — | https://crates.io/api/v1/crates/directories |
| qrcode | 0.14.1 | 2024-07-05 | 1.67.1 | https://crates.io/api/v1/crates/qrcode ("passively-maintained") |
| image | 0.25.10 | 2026-03-10 | 1.88 | https://crates.io/api/v1/crates/image |
| clap | 4.6.6 | 2026-08-06 | 1.85 | https://crates.io/api/v1/crates/clap |
| toml | 1.1.4+spec-1.1.0 | 2026-07-28 | 1.85 | https://crates.io/api/v1/crates/toml |
| tracing-subscriber | 0.3.23 | 2026-03-13 | 1.65 | https://crates.io/api/v1/crates/tracing-subscriber |
| tracing-appender | 0.2.5 | 2026-04-17 | 1.63 | https://crates.io/api/v1/crates/tracing-appender |

---

## 2. Version alignment (one wgpu, one winit, one rwh)

From the real manifests:

* `eframe-0.36.1/Cargo.toml:225-232` — `egui-wgpu = "0.36.1"`, `default-features = false`, features `["winit", "capture"]`; `:234-237` `egui-winit = "0.36.1"` features `["clipboard"]`; `:266-269` `winit = "0.30.13"` features `["rwh_06"]`, `default-features = false`; `:356-360` a direct `wgpu = "30.0"` dep exists **only for wasm32** — native eframe reaches wgpu through `egui_wgpu::wgpu` (`egui-wgpu-0.36.1/src/lib.rs:19 pub use wgpu;`).
* `egui-wgpu-0.36.1/Cargo.toml:120-126` — `wgpu = "30.0"`, features `["std", "wgsl"]`, `default-features = false`; `:128-131` `winit = "0.30.13"` optional.
* `egui-winit-0.36.1/Cargo.toml:131-133` — `winit = "0.30.13"`, `default-features = false`; `:144-148` `arboard = "3.6"` features `["image-data"]`; `:135-137` `smithay-clipboard = "0.7.2"` (Linux, optional via `clipboard`).
* `rfd-0.17.2/Cargo.toml:79-80` — `raw-window-handle = "0.6"` → `FileDialog::set_parent(&window)` accepts a winit 0.30 `Window` (rwh 0.6) directly.
* `wgpu-30.0.1/Cargo.toml:173-199` — `naga 30.0.0`, `wgpu-core 30.0.0`, `wgpu-types 30.0.0` (resolve to 30.0.1).
* Re-exports to use so versions never diverge: `eframe::egui`, `eframe::egui_wgpu`, `eframe::egui_wgpu::wgpu`, `eframe::egui_winit`, `eframe::egui_winit::winit` (`egui-winit-0.36.1/src/lib.rs:21 pub use winit;`). In the manual-winit layout, depend directly on `wgpu =30.0.1` and `winit =0.30.13` and let cargo unify — the probe lockfile resolved to exactly one copy of each.
* `rand_core`/`digest`: none of these crates touch `rand_core`. `secret-service 5.1.0` (behind the zbus keyring store, `crypto-rust`) pulls `sha2 0.10` + `hkdf 0.12` + `aes 0.8` (`secret-service-5.1.0/Cargo.toml:73-113`) while the crypto note uses `sha2 0.11`/`hkdf 0.13` — that is a harmless duplicate-major (two `sha2` copies), not a conflict.
* `rustls`: not involved in this stack. `ehttp` (egui_extras `http` loader) is **not** enabled.
* `zbus 5.19.0` is shared by notify-rust, ashpd, accesskit_unix and the zbus keyring store; with both `async-io` and `tokio` features unified, zbus uses **tokio** (`zbus-5.19.0/src/abstractions/executor.rs:47-50`, `cfg(all(feature = "async-io", not(feature = "tokio")))`).

---

## 3. Feature flags (from the real `[features]` tables)

### 3.1 eframe (`eframe-0.36.1/Cargo.toml:55-116`)

```
default = ["accesskit", "default_fonts", "links", "wayland", "web_screen_reader", "wgpu", "winit/default", "x11"]
glow     = ["dep:egui_glow", "dep:glow", "dep:glutin-winit", "dep:glutin"]      # NOT default
wgpu     = ["wgpu_no_default_features", "egui-wgpu/default"]                   # egui-wgpu/default = wgpu/default (all backends) + webgl
wgpu_no_default_features = ["dep:wgpu", "dep:egui-wgpu", "dep:pollster"]        # use this + your own `wgpu` features to trim backends
persistence = ["egui-winit/serde", "egui/persistence", "ron", "serde"]
wayland  = ["egui-winit/wayland", "egui-wgpu?/wayland", ...]   x11 = ["egui-winit/x11", "egui-wgpu?/x11", ...]
```

* `Renderer::default()` is `Wgpu` when `glow` is off (`src/epi.rs:598-613`); `NativeOptions.renderer` only exists with `glow` or `wgpu_no_default_features`.
* Recommended: `eframe = { version = "=0.36.1", default-features = false, features = ["accesskit", "default_fonts", "wgpu", "wayland", "x11", "persistence"] }` (probe used exactly this + `"links"`). Note `"winit/default"` cannot be written from a *dependent's* feature list (cargo rejects `dep/feature` there); enable winit defaults via your own `winit` dependency instead.
* Default eframe features also enable `accesskit` → `accesskit_winit` → on Linux `accesskit_unix` (zbus/atspi, pure Rust).

### 3.2 egui-wgpu (`egui-wgpu-0.36.1/Cargo.toml`)

`default = ["fragile-send-sync-non-atomic-wasm", "macos-window-resize-jitter-fix", "wgpu/default", "wgpu/webgl"]`; `winit = ["dep:winit", "winit/rwh_06", "dep:egui", "capture"]`; `wayland = ["winit?/wayland"]`; `x11 = ["winit?/x11"]`. For the manual path: `egui-wgpu = { version = "=0.36.1", features = ["winit", "wayland", "x11"] }`.

### 3.3 egui-winit (`egui-winit-0.36.1/Cargo.toml`)

`default = ["clipboard", "links", "wayland", "winit/default", "x11"]`; `clipboard = ["arboard", "bytemuck", "smithay-clipboard"]`; `accesskit = ["dep:accesskit_winit"]`; `serde`. Clipboard backend selection: Wayland display handle → `smithay_clipboard`, else `arboard` (`src/clipboard.rs:31-60,174-188`).

### 3.4 wgpu 30 (`wgpu-30.0.1/Cargo.toml`)

`default = ["std", "parking_lot", "dx12", "metal", "gles", "vulkan", "wgsl", "webgpu"]`. Backends are per-feature: `vulkan`, `gles`, `dx12`, `metal`, plus `noop`, `spirv`, `glsl`, `serde`, `trace`, `static-dxc`, `vulkan-portability`. Recommended native set: `wgpu = { version = "=30.0.1", default-features = false, features = ["std", "wgsl", "vulkan", "gles", "dx12", "metal"] }` (drop `webgpu`/`webgl`). `Instance::new` **panics** if no backend feature is enabled for the target (`src/api/instance.rs:63-68`).

Link-time deps on Linux: none. `wgpu-hal` loads Vulkan via `ash 0.38` (`loaded`, dlopen) and EGL via `khronos-egl 6` with `features = ["dynamic"]` + `libloading` (`wgpu-hal-30.0.1/Cargo.toml:328-345`). Only runtime `libvulkan.so.1` / `libEGL.so.1` are needed (both present here).

### 3.5 winit 0.30.13 (`winit-0.30.13/Cargo.toml`)

`default = ["rwh_06", "x11", "wayland", "wayland-dlopen", "wayland-csd-adwaita"]`.
`wayland = [wayland-client, wayland-backend(client_system), wayland-protocols, wayland-protocols-plasma, sctk 0.19, ahash, memmap2]`; `wayland-dlopen = ["wayland-backend/dlopen"]` (dlopen `libwayland-client.so.0` at runtime — no `libwayland-dev` needed); `x11 = [x11-dl, x11rb 0.13 with "dl-libxcb", xkbcommon-dl/x11, bytemuck, percent-encoding]` (all dlopen). `wayland-csd-adwaita` = pure-Rust client-side decorations (`sctk-adwaita` + `ab_glyph`). Keep all defaults; they are link-free.

### 3.6 Desktop-integration crates

| crate | features table | recommendation |
|---|---|---|
| rfd 0.17.2 | `default = ["xdg-portal", "wayland"]`, `gtk3 = [gtk-sys, glib-sys, gobject-sys]`, `wayland = [wayland-backend(client_system), wayland-client, wayland-protocols]`, `xdg-portal = ["pollster"]`, `common-controls-v6`, `file-handle-inner` (`rfd-0.17.2/Cargo.toml:50-58`) | `default-features = false, features = ["xdg-portal"]`. The `wayland` feature only serves `set_parent` window identifiers; it links `wayland-backend/client_system` and, if `dlopen` is not unified from winit, `-lwayland-client` — omit it unless winit's `wayland-dlopen` is guaranteed in the graph (it is in our workspace, but the probe omitted it anyway). |
| arboard 3.6.1 | `default = ["image-data"]`, `wayland-data-control = ["wl-clipboard-rs"]`, `image = ["dep:image"]`, `core-graphics` | `default-features = false, features = ["image-data", "wayland-data-control"]`. Linux deps: `x11rb 0.13` (dlopen xcb), `wl-clipboard-rs 0.9` (pure Rust), `image 0.25` png-only (`Cargo.toml:78-98`). |
| gilrs 0.11.2 | `default = ["wgi"]` (Windows.Gaming.Input), `xinput`, `serde-serialize` | defaults. Linux deps in gilrs-core: `libudev-sys 0.1.4`, `inotify 0.11`, `nix 0.31`, `libc` (`gilrs-core-0.6.8/Cargo.toml:70-89`). |
| notify-rust 4.18.0 | `default = ["z"]`; `z = ["zbus", "serde", "async"]` where `async = ["zbus/async-io"]`; `z-with-tokio = ["zbus", "serde", "tokio"]` (`tokio = ["zbus/tokio"]`); `d`/`d_vendored` = libdbus (C); `images` (`Cargo.toml`) | `default-features = false, features = ["z-with-tokio"]`. zbus dep is `version = "5"`, `default-features = false` (`:140-143`). `image_path()` needs no `images` feature. |
| keyring 4.1.6 | `default = ["v1"]`; `v1 = [apple-native-keyring-store/keychain, windows-native-keyring-store, zbus-secret-service-keyring-store]`; `cli` (everything). Optional deps usable as features: `linux-keyutils-keyring-store`, `dbus-secret-service-keyring-store` (libdbus C, `vendored`), `db-keystore` (`Cargo.toml:105-148`). There is **no** `linux-native`/`sync-secret-service` feature in 4.x. | Skip `keyring` and use `keyring-core` + stores (§5.9). |
| qrcode 0.14.1 | `default = ["image", "svg", "pic"]` | `default-features = false` (only `to_colors()`/`render::<..>()` on own types needed). |
| image 0.25.10 | `default = ["rayon", "default-formats"]` (avif, exr, tiff, webp… heavy); `nasm = ["ravif?/asm"]` | `default-features = false, features = ["png"]` (app icon / tray icon). Never enable `nasm`/`avif` (needs nasm). |
| egui_extras 0.36.1 | `default = ["dep:mime_guess2"]`, `image = ["dep:image"]`, `svg`, `all_loaders`, `http`, `syntect`, `datepicker` | Only if you use `egui::Image::from_bytes`/URIs: `default-features = false, features = ["image"]` + `egui_extras::install_image_loaders(&ctx)` (`src/loaders.rs:58`). Not needed for the QR path. |
| clap 4.6.6 | `default = [std, color, help, usage, error-context, suggestions]`, `derive`, `env`, `cargo`, `unicode`, `string` | `features = ["derive", "env"]`. |
| toml 1.1.4 | `default = ["std", "serde", "parse", "display"]`, `preserve_order`, `fast_hash` | defaults. API: `toml::from_str`, `toml::to_string_pretty`, `toml::Value`, `toml::Table` (`src/lib.rs:184-194`). |
| tracing-subscriber 0.3.23 | `default = [smallvec, fmt, ansi, tracing-log, std]`, `env-filter`, `json`, `local-time` | `features = ["env-filter", "fmt", "json"]`. |
| tracing-appender 0.2.5 | none | `rolling::Builder::new().rotation(Rotation::DAILY).filename_prefix(..).filename_suffix("log").max_log_files(7).build(dir)` + `tracing_appender::non_blocking(appender) -> (NonBlocking, WorkerGuard)` (`src/rolling/builder.rs:84-298`, `src/lib.rs:195`). Keep the guard alive for the process lifetime. |
| directories 6.0.0 | none | `ProjectDirs::from("", "", "Tornect")` → `config_dir()`, `data_local_dir()`, `cache_dir()`, `state_dir()` (Linux only), `runtime_dir()` (`src/lib.rs:428-522`). |

---

## 4. Architecture decision: eframe vs. own winit loop

Facts that drive it:

1. **One event loop per process.** eframe's `run_native` owns the `winit::EventLoop` (`eframe-0.36.1/src/native/run.rs`). The plan wants a control window *and* a GPU stream window in the same binary; they must share that loop. Inside eframe the only way to get a second OS window is an egui *viewport* (`Context::show_viewport_deferred(id, ViewportBuilder, impl Fn(&mut Ui, ViewportClass) + Send + Sync)`, `egui-0.36.1/src/context.rs:4059`). That works with `PaintCallback`s (egui-wgpu's `Painter` is multi-viewport), but:
2. **eframe exposes no raw winit events.** The `App` trait has `logic`, `ui`, `save`, `on_exit`, `raw_input_hook(&mut self, &egui::Context, &mut egui::RawInput)` only (`src/epi.rs:152-280`); no `window_event`/`device_event` hook exists (grep of `epi.rs`/`lib.rs`).
3. **egui-winit's key translation is lossy.** `key_from_key_code` (`egui-winit-0.36.1/src/lib.rs:1524-1660`) maps ~113 `KeyCode`s onto the 96-variant `egui::Key` and ends in `_ => return None` (line 1656): `PrintScreen`, `ScrollLock`, `Pause`, `NumLock`, `CapsLock`, `ContextMenu`, `MetaLeft`, `Convert`/`KanaMode`/`Lang1`, `AudioVolumeUp`… produce **no event at all**. `egui::Event::Key { key, physical_key: Option<egui::Key>, pressed, repeat, modifiers }` (`egui-0.36.1/src/data/input/event.rs:37`) therefore cannot carry a faithful scancode stream.
4. **Raw mouse deltas do reach egui** — eframe forwards `DeviceEvent::MouseMotion` to `egui_winit::State::on_mouse_motion`, which pushes `egui::Event::MouseMoved(Vec2)` when the pointer is in the window or a button is down and the focused viewport has focus (`src/native/wgpu_integration.rs:494-525`, `egui-winit src/lib.rs:767-778`). Pointer lock is reachable via `ctx.send_viewport_cmd(ViewportCommand::CursorGrab(CursorGrab::Locked))` / `ViewportCommand::CursorVisible(false)` (`egui-0.36.1/src/viewport.rs:1045,1187-1191`; handled at `egui-winit src/lib.rs:1923-1932`). So eframe *can* do gaming-mode mouse, but not full keyboard.
5. **Frame pacing.** eframe repaints on `request_repaint()`; present-on-arrival is possible (`ctx.request_repaint()` from the decode thread) but you do not control `RedrawRequested` ordering or the surface `present_mode` per window beyond `SurfaceConfig`.

**Recommendation:** the `tornect` app owns the winit loop (§5.3 skeleton, compiled in the probe). One `egui::Context` per window, `egui_winit::State` per window, one `egui_wgpu::winit::Painter` (multi-viewport; call `set_window(viewport_id, Some(window))` per window). The stream window paints the video with a full-rect `egui_wgpu::Callback` (or a plain render pass before egui's) and the HUD with egui on top; unconsumed `WindowEvent`s (`EventResponse::consumed == false`, `egui-winit src/lib.rs:64-72`) and all `DeviceEvent`s go to `tornect-input`. Persistence (window geometry, egui memory) is a few lines with `ron`/`toml` + `directories`; accessibility can be added later with `egui_winit::State::init_accesskit` (`src/lib.rs:197`).

eframe stays useful for throwaway tools and for the very first milestone UI (§5.1) — everything in it is compatible with the manual path because both use the same `egui-winit`/`egui-wgpu` crates underneath.

---

## 5. API usage (all snippets compiled in `/tmp/probe-ui` unless marked)

### 5.1 eframe 0.36 app (control-window prototype) — `/tmp/probe-ui/src/main.rs`

```rust
use eframe::egui_wgpu::{self, wgpu};

struct App { /* ... */ }

impl eframe::App for App {
    // 0.34+: `logic` runs before `ui` and also while hidden (epi.rs:152-169)
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {}
    // 0.34+: `ui` replaces `update`; the Ui covers the whole viewport with no margin (epi.rs:171-182)
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| { ui.label("Tornect"); });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Tornect").with_inner_size([640.0, 480.0]).with_app_id("tornect"),
        renderer: eframe::Renderer::Wgpu,
        wgpu_options: egui_wgpu::WgpuConfiguration {
            wgpu_setup: egui_wgpu::WgpuSetupCreateNew {
                instance_descriptor: wgpu::InstanceDescriptor {
                    backends: wgpu::Backends::from_env().unwrap_or(wgpu::Backends::PRIMARY | wgpu::Backends::GL),
                    ..wgpu::InstanceDescriptor::new_without_display_handle()
                },
                power_preference: wgpu::PowerPreference::from_env().unwrap_or(wgpu::PowerPreference::HighPerformance),
                ..egui_wgpu::WgpuSetupCreateNew::without_display_handle()
            }.into(),
            surface: egui_wgpu::SurfaceConfig { present_mode: wgpu::PresentMode::AutoNoVsync, desired_maximum_frame_latency: Some(1) },
            ..Default::default()
        },
        ..Default::default()
    };
    eframe::run_native("Tornect", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
```

Signatures (`eframe-0.36.1/src/lib.rs:288-294`, `src/epi.rs:49-50`):
`pub fn run_native(app_name: &str, native_options: NativeOptions, app_creator: AppCreator<'_>) -> Result` with
`type AppCreator<'app> = Box<dyn 'app + FnOnce(&CreationContext<'_>) -> Result<Box<dyn 'app + App>, DynError>>`;
`pub type Result<T = (), E = Error> = std::result::Result<T, E>` (`lib.rs:617`).
`NativeOptions` fields (`epi.rs:296-402`): `viewport: egui::ViewportBuilder`, `multisampling: u16`, `depth_buffer: u8`, `stencil_buffer: u8`, `renderer: Renderer`, `run_and_return: bool`, `event_loop_builder: Option<EventLoopBuilderHook>`, `window_builder: Option<WindowBuilderHook>`, `centered: bool`, `wgpu_options: egui_wgpu::WgpuConfiguration`, `persist_window: bool`, `persistence_path: Option<PathBuf>`, `dithering: bool`.
`CreationContext` (`epi.rs:53-97`): `egui_ctx`, `integration_info`, `storage: Option<&dyn Storage>`, `wgpu_render_state: Option<egui_wgpu::RenderState>`, `winit_window() -> Option<&Arc<winit::window::Window>>`; it implements `HasWindowHandle + HasDisplayHandle` (→ `rfd::FileDialog::set_parent(cc)`).
`Frame` (`epi.rs:661-823`): `wgpu_render_state() -> Option<&RenderState>`, `wgpu_surface_config()`, `set_wgpu_surface_config(SurfaceConfig)` (runtime vsync toggle, added in 0.35 #8114), `storage_mut()`, `winit_window()`.
`WgpuConfiguration` (`egui-wgpu-0.36.1/src/lib.rs:334-340`): `surface: SurfaceConfig`, `wgpu_setup: WgpuSetup`, `on_surface_status: Arc<dyn Fn(wgpu::CurrentSurfaceTexture) -> SurfaceErrorAction>`; `Default` = `SurfaceConfig::HIGH_THROUGHPUT` (AutoVsync, latency 2) — `SurfaceConfig::LOW_LATENCY` = AutoVsync, latency 1 (`lib.rs:71-90`).
`WgpuSetupCreateNew` (`src/setup.rs:169-200`): `instance_descriptor`, `display_handle: Option<Box<dyn EguiDisplayHandle>>`, `power_preference`, `native_adapter_selector: Option<Arc<dyn Fn(&[wgpu::Adapter], Option<&wgpu::Surface>) -> Result<wgpu::Adapter, String> + Send + Sync>>`, `device_descriptor: Arc<dyn Fn(&wgpu::Adapter) -> wgpu::DeviceDescriptor<'static> + Send + Sync>`; constructors `from_display_handle(event_loop.owned_display_handle())` / `without_display_handle()`; `WgpuSetup::Existing(WgpuSetupExisting { instance, adapter, device, queue })` (`setup.rs:323-328`) lets you hand egui a device you created (e.g. shared with the FFmpeg/Vulkan decoder).
`storage_dir(app_id)` on Linux = `$XDG_DATA_HOME|~/.local/share/<app_id lowercased>` (`src/native/file_storage.rs:17-29`).

### 5.2 NV12 → RGB custom paint callback (compiled; adapted from upstream `custom3d_wgpu.rs`)

Upstream reference: https://github.com/emilk/egui/blob/0.36.1/crates/egui_demo_app/src/apps/custom3d_wgpu.rs (fetched; pipeline creation with `immediate_size: 0`, `multiview_mask: None`, `entry_point: Some("fs_main")`, `targets: &[Some(render_state.target_format.into())]`, resources stored in `renderer.write().callback_resources`).

```rust
struct StreamResources { pipeline: wgpu::RenderPipeline, bind_group: wgpu::BindGroup, sampler: wgpu::Sampler }

struct StreamCallback;
impl egui_wgpu::CallbackTrait for StreamCallback {
    fn prepare(&self, _device: &wgpu::Device, queue: &wgpu::Queue, _screen: &egui_wgpu::ScreenDescriptor,
               _enc: &mut wgpu::CommandEncoder, res: &mut egui_wgpu::CallbackResources) -> Vec<wgpu::CommandBuffer> {
        // upload the newest decoded frame here: queue.write_texture(.. y plane ..); queue.write_texture(.. uv plane ..)
        Vec::new()
    }
    fn paint(&self, _info: egui::PaintCallbackInfo, rp: &mut wgpu::RenderPass<'static>, res: &egui_wgpu::CallbackResources) {
        let r: &StreamResources = res.get().unwrap();
        rp.set_pipeline(&r.pipeline); rp.set_bind_group(0, &r.bind_group, &[]); rp.draw(0..3, 0..1); // full-screen triangle
    }
}
// in ui():
let rect = ui.available_rect_before_wrap();
ui.painter().add(egui_wgpu::Callback::new_paint_callback(rect, StreamCallback));
```

Setup once (from `RenderState`): textures `R8Unorm` (Y, WxH) + `Rg8Unorm` (UV, W/2xH/2) with `TEXTURE_BINDING | COPY_DST`; for P010 use `R16Unorm`/`Rg16Unorm`. Bind group layout: two `BindingType::Texture { sample_type: Float { filterable: true }, view_dimension: D2, multisampled: false }` + one `BindingType::Sampler(SamplerBindingType::Filtering)`. WGSL (BT.709 limited range):

```wgsl
@group(0) @binding(0) var y_tex: texture_2d<f32>;
@group(0) @binding(1) var uv_tex: texture_2d<f32>;
@group(0) @binding(2) var samp: sampler;
struct VOut { @builtin(position) pos: vec4<f32>, @location(0) uv: vec2<f32> };
@vertex fn vs_main(@builtin(vertex_index) i: u32) -> VOut {
  var p = array<vec2<f32>,3>(vec2(-1.0,-1.0), vec2(3.0,-1.0), vec2(-1.0,3.0));
  var o: VOut; o.pos = vec4(p[i], 0.0, 1.0); o.uv = vec2(p[i].x*0.5+0.5, 1.0-(p[i].y*0.5+0.5)); return o;
}
@fragment fn fs_main(i: VOut) -> @location(0) vec4<f32> {
  let y = textureSample(y_tex, samp, i.uv).r; let uv = textureSample(uv_tex, samp, i.uv).rg;
  let yy = 1.1643*(y-0.0625); let u = uv.r-0.5; let v = uv.g-0.5;
  return vec4(yy+1.7927*v, yy-0.2132*u-0.5329*v, yy+2.1124*u, 1.0);
}
```

The callback's render pass targets egui's surface texture with `target_format` (sRGB or not depending on the surface); the paint rect is clipped/scissored for you (`renderer.rs` sets viewport/scissor from `PaintCallbackInfo`). Everything in `prepare` runs before egui's own pass and all command buffers are submitted together (`renderer.rs:43-83`).

### 5.3 Manual winit 0.30 loop + egui-winit + egui-wgpu — `/tmp/probe-ui/src/bin/winit_manual.rs` (compiled)

```rust
use std::{num::NonZeroU32, sync::Arc};
use egui_wgpu::{wgpu, winit::Painter, RendererOptions, WgpuConfiguration};
use winit::{application::ApplicationHandler, event::{DeviceEvent, DeviceId, ElementState, WindowEvent},
            event_loop::{ActiveEventLoop, ControlFlow, DeviceEvents, EventLoop},
            keyboard::{KeyCode, PhysicalKey}, window::{CursorGrabMode, Window, WindowId}};

enum UserEvent { FrameDecoded }
struct Win { window: Arc<Window>, state: egui_winit::State }
struct App { ctx: egui::Context, painter: Option<Painter>, win: Option<Win>, locked: bool }

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {                       // create windows here (application.rs:83)
        if self.win.is_some() { return; }
        let attrs = Window::default_attributes().with_title("Tornect stream")
            .with_inner_size(winit::dpi::LogicalSize::new(1280.0, 720.0));
        let window = Arc::new(event_loop.create_window(attrs).expect("window"));   // event_loop.rs:307
        let config = WgpuConfiguration {
            wgpu_setup: egui_wgpu::WgpuSetupCreateNew::from_display_handle(event_loop.owned_display_handle()).into(),
            surface: egui_wgpu::SurfaceConfig { present_mode: wgpu::PresentMode::AutoNoVsync, desired_maximum_frame_latency: Some(1) },
            ..Default::default()
        };
        let mut painter = pollster::block_on(Painter::new(self.ctx.clone(), config, false, RendererOptions::default())); // winit.rs:60
        pollster::block_on(painter.set_window(egui::ViewportId::ROOT, Some(window.clone()))).expect("surface");          // winit.rs:188
        let state = egui_winit::State::new(self.ctx.clone(), egui::ViewportId::ROOT, &window,
            Some(window.scale_factor() as f32), window.theme(), painter.max_texture_side());                              // lib.rs:138-145
        self.painter = Some(painter); self.win = Some(Win { window, state });
    }
    fn user_event(&mut self, _: &ActiveEventLoop, _ev: UserEvent) {
        if let Some(w) = &self.win { w.window.request_redraw(); }                 // present-on-arrival: decode thread → EventLoopProxy::send_event
    }
    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        let Some(w) = self.win.as_mut() else { return };
        let resp = w.state.on_window_event(&w.window, &event);                   // lib.rs:295 → EventResponse { consumed, repaint }
        if resp.repaint { w.window.request_redraw(); }
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::Resized(size) => if let (Some(p), Some(wd), Some(ht)) =
                (self.painter.as_mut(), NonZeroU32::new(size.width), NonZeroU32::new(size.height)) {
                p.on_window_resized(egui::ViewportId::ROOT, wd, ht);            // winit.rs:447
            },
            WindowEvent::KeyboardInput { event: key, is_synthetic: false, .. } if !resp.consumed => {
                // key.physical_key: PhysicalKey::Code(KeyCode) | Unidentified(NativeKeyCode)  (keyboard.rs:225-233)
                // key.logical_key: Key::Named(NamedKey) | Character(SmolStr) | ..;  key.text: Option<SmolStr>
                if key.physical_key == PhysicalKey::Code(KeyCode::KeyL) && key.state == ElementState::Pressed && !key.repeat {
                    let lock = !self.locked; self.set_pointer_lock(lock);
                }
            }
            WindowEvent::Focused(false) => self.set_pointer_lock(false),
            WindowEvent::RedrawRequested => {
                let raw_input = w.state.take_egui_input(&w.window);                // lib.rs:264
                let mut full = self.ctx.run_ui(raw_input, |ui| { /* HUD */ });   // context.rs:793 (Context::run was replaced by run_ui)
                w.state.handle_platform_output_with_event_loop(&w.window, event_loop, full.platform_output); // lib.rs:1093
                let clipped = self.ctx.tessellate(full.shapes, full.pixels_per_point);                          // context.rs:2856
                if let Some(p) = self.painter.as_mut() {
                    p.paint_and_update_textures(egui::ViewportId::ROOT, full.pixels_per_point, [0.0; 4],
                        &clipped, &mut full.textures_delta, Vec::new(), &w.window);                              // winit.rs:475-484
                }
            }
            _ => {}
        }
    }
    fn device_event(&mut self, _: &ActiveEventLoop, _dev: DeviceId, event: DeviceEvent) {
        if let DeviceEvent::MouseMotion { delta } = event {                       // raw, unaccelerated (event.rs:479-483)
            /* forward delta to host as relative motion when locked */
            if let Some(w) = self.win.as_mut() { let _ = w.state.on_mouse_motion(delta); }
        }
    }
}
impl App {
    fn set_pointer_lock(&mut self, lock: bool) {
        let Some(w) = &self.win else { return };
        if lock {
            w.window.set_cursor_grab(CursorGrabMode::Locked)
                .or_else(|_| w.window.set_cursor_grab(CursorGrabMode::Confined)).ok();   // window.rs:1468-1490
            w.window.set_cursor_visible(false);                                            // window.rs:1505
        } else { w.window.set_cursor_grab(CursorGrabMode::None).ok(); w.window.set_cursor_visible(true); }
        self.locked = lock;
    }
}
fn main() {
    let event_loop = EventLoop::<UserEvent>::with_user_event().build().expect("event loop"); // event_loop.rs:215,115
    event_loop.set_control_flow(ControlFlow::Wait);
    event_loop.listen_device_events(DeviceEvents::WhenFocused);                              // event_loop.rs:286,597-605
    let proxy = event_loop.create_proxy();                                                   // EventLoopProxy<UserEvent>: Send
    let mut app = App { ctx: egui::Context::default(), painter: None, win: None, locked: false };
    event_loop.run_app(&mut app).expect("run");                                               // event_loop.rs:264
}
```

`ApplicationHandler<T>` methods (`winit-0.30.13/src/application.rs:8-222`): `new_events(StartCause)`, `resumed` (required), `user_event(T)`, `window_event(&ActiveEventLoop, WindowId, WindowEvent)` (required), `device_event(&ActiveEventLoop, DeviceId, DeviceEvent)`, `about_to_wait`, `suspended`, `exiting`, `memory_warning`. `WindowAttributes` builders: `with_inner_size`, `with_title`, `with_fullscreen`, `with_decorations`, `with_window_level`, `with_window_icon`, `with_transparent`, `with_content_protected`, `with_cursor` … (`src/window.rs:200-453`). Relevant `WindowEvent`s: `CursorMoved{position}`, `MouseInput{state,button}`, `MouseWheel{delta,phase}`, `KeyboardInput{event,is_synthetic}`, `ModifiersChanged`, `Ime`, `Focused(bool)`, `ScaleFactorChanged`, `Occluded`, `RedrawRequested`, `DroppedFile` (`src/event.rs:158-437`). `DeviceEvent`: `MouseMotion{delta:(f64,f64)}`, `MouseWheel{delta}`, `Motion{axis,value}`, `Button{button,state}`, `Key(RawKeyEvent{physical_key,state})` (`event.rs:472-518`).

Pointer-lock implementation per platform (verified in `src/platform_impl`):
* Wayland: `Locked` → `zwp_pointer_constraints_v1.lock_pointer`, `Confined` → `confine_pointer` (`linux/wayland/window/state.rs:889-917`); `DeviceEvent::MouseMotion` comes from `zwp_relative_pointer_v1` unaccelerated deltas and is bound for every pointer, lock or not (`linux/wayland/seat/pointer/relative_pointer.rs:34-47`, `seat/mod.rs:118`). The compositor hides/locks only while the surface has focus.
* X11: `Locked` returns `NotSupported` (`window.rs:1709`); use `Confined` + recentre with `set_cursor_position`; raw motion via XInput2 `XI_RawMotion` (`linux/x11/event_processor.rs:287,1473`).
* Windows: `Locked` = `ClipCursor` to a 1×1 rect at the current position (`windows/window_state.rs:478-500`); raw deltas from `WM_INPUT`.
* macOS: `Locked` = `CGAssociateMouseAndMouseCursorPosition(false)`; `Confined` is `NotSupported` (`macos/window_delegate.rs:1123-1127`, `window.rs:1698`); `set_cursor_visible(false)` hides while focused even outside the window (`window.rs:1497-1503`).

### 5.4 wgpu 30: instance / adapter / backend selection / software rendering — `/tmp/probe-ui/src/bin/headless.rs`

```rust
let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
    backends: wgpu::Backends::from_env().unwrap_or(wgpu::Backends::VULKAN | wgpu::Backends::GL),
    flags: wgpu::InstanceFlags::from_build_config().with_env(),
    ..wgpu::InstanceDescriptor::new_without_display_handle()      // wgpu-types instance.rs:27-67
});
let adapters = pollster::block_on(instance.enumerate_adapters(wgpu::Backends::all()));   // api/instance.rs:145 (async in 30)
let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {  // api/instance.rs:167
    power_preference: wgpu::PowerPreference::None,
    force_fallback_adapter: std::env::var_os("TORNECT_SOFTWARE_GPU").is_some(),         // "only a fallback/software adapter" (adapter.rs:37-56)
    compatible_surface: None, ..Default::default()
}))?;                                                                                     // Result<Adapter, RequestAdapterError>
let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor { label: Some("tornect"), ..Default::default() }))?;
// … render pass with `depth_slice: None` on RenderPassColorAttachment; `device.poll(wgpu::PollType::wait_indefinitely())`
```

* `InstanceDescriptor { backends, flags, memory_budget_thresholds, backend_options, display: Option<Box<dyn WgpuHasDisplayHandle>> }` (`wgpu-types-30.0.1/src/instance.rs:27-61`); `InstanceDescriptor::from_env_or_default()` (`:278`). A display handle is required on Wayland+GLES (egui-wgpu docs `setup.rs:159-166`) — pass `event_loop.owned_display_handle()`.
* Env vars honoured by wgpu/egui-wgpu: `WGPU_BACKEND` = `vulkan|vk`, `dx12`, `metal`, `opengl|gles|gl`, `webgpu`, `noop` (`wgpu-types src/backend.rs:177-190`), `WGPU_POWER_PREF` = `low|high|none` (`src/adapter.rs:89-91`), `WGPU_ADAPTER_NAME` (substring match, `wgpu/src/util/init.rs:6-44`, used by `wgpu::util::initialize_adapter_from_env[_or_default]`), `WGPU_VALIDATION`, `WGPU_DEBUG`, `WGPU_GPU_BASED_VALIDATION`, `WGPU_ALLOW_UNDERLYING_NONCOMPLIANT_ADAPTER` (`egui-wgpu setup.rs:48-57`).
* `Backends::PRIMARY = VULKAN|METAL|DX12|BROWSER_WEBGPU`, `Backends::SECONDARY = GL` (`backend.rs:97-130`). `AdapterInfo.device_type ∈ {Other, IntegratedGpu, DiscreteGpu, VirtualGpu, Cpu}`.
* Software rendering on this VM: lavapipe (`/usr/share/vulkan/icd.d/lvp_icd.json` → `libvulkan_lvp.so`, api 1.4.335). For headless tests set `WGPU_BACKEND=vulkan VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json` (or `VK_DRIVER_FILES=` on newer loaders) and/or `force_fallback_adapter: true`; for GL, `LIBGL_ALWAYS_SOFTWARE=1` (llvmpipe). Add a `wgpu::Backends::NOOP` feature (`noop`) build for pure-logic unit tests if desired.

### 5.5 QR code into egui (compiled)

```rust
fn qr_texture(ctx: &egui::Context, data: &str) -> egui::TextureHandle {
    let code = qrcode::QrCode::new(data.as_bytes()).unwrap();          // qrcode src/lib.rs:75 (EcLevel::M default)
    let w = code.width(); let quiet = 4; let n = w + 2 * quiet;         // 4-module quiet zone per spec
    let mut gray = vec![255u8; n * n];
    for (i, c) in code.to_colors().iter().enumerate() {                 // lib.rs:218 → Vec<qrcode::Color>
        let (x, y) = (i % w + quiet, i / w + quiet);
        if *c == qrcode::Color::Dark { gray[y * n + x] = 0; }
    }
    ctx.load_texture("tornect-id-qr", egui::ColorImage::from_gray([n, n], &gray), egui::TextureOptions::NEAREST) // epaint image.rs:146, textures.rs:191
}
// ui.add(egui::Image::from_texture(&tex).fit_to_exact_size(egui::Vec2::splat(200.0)));   // egui widgets/image.rs:101,176
```

Alternative with zero allocation per frame: `ui.painter().rect_filled(..)` per dark module (fine for ≤ 57×57 modules). `qrcode::QrCode::with_error_correction_level(data, EcLevel::Q)` for print/QR-scan robustness (`lib.rs:92`).

### 5.6 Clipboard (arboard 3.6.1)

```rust
let mut cb = arboard::Clipboard::new()?;                 // src/lib.rs:81
cb.set_text("tornect://…")?;  let s = cb.get_text()?;   // :90,:99
let img = cb.get_image()?;    cb.set_image(arboard::ImageData { width, height, bytes: bytes.into() })?; // :129,:146 (feature image-data)
cb.get().file_list()?;        cb.set().file_list(&paths)?;   // :205,:251
```

Linux extensions: `arboard::LinuxClipboardKind::{Clipboard, Primary}` via `GetExtLinux`/`SetExtLinux` (`src/platform/linux/mod.rs:101-112,194,301`); `SetExtLinux::wait()` keeps the process serving the selection (needed for X11 when you exit right after copying). The Wayland data-control backend is only used when `WAYLAND_DISPLAY` is set **and** the feature is on; otherwise X11 via XWayland (`src/lib.rs:433-445`).

### 5.7 File dialogs (rfd 0.17.2, xdg-portal)

```rust
// async (preferred, in tokio task — the portal call is done on a helper thread + pollster inside rfd)
let picked: Option<std::path::PathBuf> = rfd::AsyncFileDialog::new()
    .set_title("Send file").add_filter("any", &["*"]).set_directory(dirs.home_dir())
    .pick_file().await.map(|h| h.path().to_path_buf());          // file_dialog.rs:187-328; FileHandle::path()
// sync: rfd::FileDialog::new().pick_file() -> Option<PathBuf>       // :35-172
// parent window: .set_parent(&window)  (HasWindowHandle + HasDisplayHandle, rwh 0.6)
```

Runtime requirements on Linux: `libdbus-1.so.3` (dlopen'd via `libloading`, `src/backend/xdg_desktop_portal/portal/{libdbus.rs,ffi.rs}`) **or** `zenity`; a portal backend (`xdg-desktop-portal-gnome`/`-gtk`/`-kde`) — all present on this VM (`src/lib.rs:55-78`). `rfd::MessageDialog` on Linux uses zenity (`lib.rs:73`) — use egui modals instead.

### 5.8 Notifications (notify-rust 4.18.0)

```rust
notify_rust::Notification::new().appname("Tornect").summary("Incoming connection")
    .body("alice-laptop wants to control this machine").icon("tornect")
    .action("accept", "Accept").action("deny", "Deny")             // notification.rs:451
    .timeout(notify_rust::Timeout::Milliseconds(30_000)).urgency(notify_rust::Urgency::Critical)
    .show()?                                                      // -> xdg::NotificationHandle (blocking; uses zbus::block_on, xdg/mod.rs:8,413)
    .wait_for_action(|action| match action { "accept" => {..}, _ => {} });   // xdg/mod.rs:99 — blocking, run on a std thread
```

`show()` blocks on a D-Bus round trip — call it from a blocking thread, not from the winit thread. `image_path()` needs no extra feature. macOS backend = `mac-notification-sys` (subset), Windows = `winrt-notification` (`README.md:71-81`).

### 5.9 Secrets (keyring-core 1.0.0 + stores)

```rust
// Cargo: keyring-core = "=1.0.0"
// [target.'cfg(target_os = "linux")'.dependencies] linux-keyutils-keyring-store = "=1.0.0"
//                                                   zbus-secret-service-keyring-store = { version = "=1.0.0", features = ["rt-tokio-crypto-rust"] }
// [target.'cfg(target_os = "macos")'.dependencies]  apple-native-keyring-store = { version = "=1.0.2", features = ["keychain"] }
// [target.'cfg(windows)'.dependencies]             windows-native-keyring-store = "=1.1.0"
fn init_keystore() -> keyring_core::Result<()> {
    #[cfg(target_os = "linux")]
    let store = zbus_secret_service_keyring_store::Store::new()                 // store.rs:31 (GNOME Keyring / KWallet via Secret Service)
        .or_else(|_| linux_keyutils_keyring_store::Store::new())?;              // store.rs:34 (kernel keyring: session-scoped, not persisted across reboot)
    #[cfg(target_os = "macos")]  let store = apple_native_keyring_store::keychain::Store::new()?;
    #[cfg(windows)]              let store = windows_native_keyring_store::Store::new()?;
    keyring_core::set_default_store(store);                                      // keyring-core lib.rs:65 — call once at startup
    Ok(())
}
let e = keyring_core::Entry::new("tornect", "host-identity")?;                  // lib.rs:130
e.set_secret(&key_bytes)?; let k = e.get_secret()?; e.delete_credential()?;    // lib.rs:236,281,358
```

Why not `keyring::Entry`: `keyring-4.1.6/src/v1.rs:47-51` — `Entry::new` evaluates `SET_CREDENTIAL_STORE_RESULT`, a `LazyLock` that on Linux calls `zbus_secret_service_keyring_store::Store::new()` and `keyring_core::set_default_store(store)` (`v1.rs:108-123`), overriding whatever store you configured. `linux-keyutils 0.2.5` is pure Rust (`bitflags` + `libc` syscalls, `linux-keyutils-0.2.5/Cargo.toml`); the keyutils store is therefore buildable here but keys live in the kernel **session keyring only** (lost at logout) — good as a fallback, not as primary storage. The kernel keyring is per-user-session; the app should still support the plan's "file-based 0600" fallback when both stores fail (headless servers, `zbus-secret-service-keyring-store-1.0.0/src/lib.rs:60-80` on headless issues).

### 5.10 Gamepad (gilrs 0.11.2) — CI-only build on Linux

```rust
let mut gilrs = gilrs::GilrsBuilder::new().set_update_state(false).build()?;   // gamepad.rs:635-708; Error::NotImplemented(g) on unsupported OS
while let Some(gilrs::Event { id, event, time, .. }) = gilrs.next_event() {     // gamepad.rs:159 (non-blocking) / next_event_blocking(timeout) :170
    match event { gilrs::EventType::ButtonPressed(btn, code) | gilrs::EventType::ButtonReleased(btn, code) => {..},
                  gilrs::EventType::AxisChanged(axis, value, code) => {..}, gilrs::EventType::Connected | gilrs::EventType::Disconnected => {..}, _ => {} }
}
for (id, gp) in gilrs.gamepads() { gp.name(); gp.uuid(); gp.is_connected(); }   // gamepad.rs:505,807-850
```

`gilrs` is not `Send` on all platforms; poll it from the input thread (or the winit loop on `about_to_wait`). Users need r/w access to `/dev/input/event*` (README "Linux/BSD (evdev)").

### 5.11 Tray (tray-icon 0.24.2) — CI-only on Linux; feature-gate

Upstream example (fetched): https://github.com/tauri-apps/tray-icon/blob/tray-icon-v0.24.2/examples/winit.rs

```rust
use tray_icon::{menu::{Menu, MenuEvent, MenuItem}, TrayIconBuilder, TrayIconEvent};
// forward events into the winit loop
let proxy = event_loop.create_proxy();
TrayIconEvent::set_event_handler(Some(move |e| { let _ = proxy.send_event(UserEvent::Tray(e)); }));
let proxy = event_loop.create_proxy();
MenuEvent::set_event_handler(Some(move |e| { let _ = proxy.send_event(UserEvent::Menu(e)); }));
fn build_tray() -> tray_icon::TrayIcon {
    let menu = Menu::new(); menu.append(&MenuItem::with_id("quit", "Quit Tornect", true, None)).unwrap();
    TrayIconBuilder::new().with_menu(Box::new(menu)).with_tooltip("Tornect")
        .with_icon(tray_icon::Icon::from_rgba(rgba, w, h).unwrap()).build().unwrap()
}
#[cfg(target_os = "linux")] std::thread::spawn(|| { gtk::init().unwrap(); let _tray = build_tray(); gtk::main(); });   // tray needs a gtk loop on its own thread
#[cfg(not(target_os = "linux"))] /* create in ApplicationHandler::new_events when cause == StartCause::Init (macOS needs a running loop) */
```

Linux build deps (`tray-icon-0.24.2/README.md:21-35`, `src/lib.rs:20-34`): `libgtk-3-dev libxdo-dev libappindicator3-dev` (or `libayatana-appindicator3-dev`). `libappindicator-sys 0.9.0` depends on `gtk-sys 0.18` (pkg-config `gtk+-3.0` at build time) and `libloading` (appindicator itself is dlopen'd, `libappindicator-sys-0.9.0/Cargo.toml:24-27`); `muda` `gtk` feature pulls `gtk 0.18`. Linux platform impl is unconditionally `gtk/mod.rs` (`src/platform_impl/mod.rs:8-16`) — there is no GTK-free Linux backend. Linux caveats from `src/lib.rs`: tooltip unsupported; once a menu is set it cannot be removed; icon may not show without a menu; `menu_on_left_click` unsupported. On GNOME an AppIndicator extension is required for any tray icon to be visible at all — treat the tray as best-effort on Linux and keep a normal window as the primary surface.

### 5.12 Config/state dirs, logging, CLI

```rust
let dirs = directories::ProjectDirs::from("", "", "Tornect").ok_or(..)?;      // Linux ~/.config/tornect ; Win %APPDATA%\Tornect\config ; mac ~/Library/Application Support/Tornect
let cfg: Config = toml::from_str(&std::fs::read_to_string(dirs.config_dir().join("config.toml"))?)?;
let appender = tracing_appender::rolling::Builder::new().rotation(tracing_appender::rolling::Rotation::DAILY)
    .filename_prefix("tornect").filename_suffix("log").max_log_files(7).build(dirs.data_local_dir())?;
let (nb, _guard) = tracing_appender::non_blocking(appender);                      // keep _guard alive
tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
    .with_writer(nb).with_ansi(false).init();                                       // fmt/mod.rs:957,1057,633,518
#[derive(clap::Parser)] #[command(name = "tornect", version)] struct Cli { #[arg(long, env = "TORNECT_HEADLESS")] headless: bool }
```

`directories 6` on Linux: `config_dir()` = `$XDG_CONFIG_HOME/tornect`, `data_local_dir()` = `$XDG_DATA_HOME/tornect`, `state_dir()` = `$XDG_STATE_HOME/tornect` (Linux only, `Option`), `runtime_dir()` = `$XDG_RUNTIME_DIR/tornect` (`src/lib.rs:443-522`). Note the lowercased project name on Linux vs `Tornect` on Windows/macOS — matches plan D13.

---

## 6. Build requirements (Linux) — this VM vs CI

| crate | build-time system deps | runtime deps | this VM (no sudo) | CI (`ubuntu-latest`, apt) |
|---|---|---|---|---|
| egui / eframe (wgpu) / egui-wgpu / egui-winit / wgpu / winit | **none** (Vulkan via `ash` dlopen, EGL via `khronos-egl dynamic`, Wayland via `wayland-backend/dlopen`, X11 via `x11-dl`/`x11rb dl-libxcb`, xkb via `xkbcommon-dl`) | `libvulkan.so.1`, `libEGL.so.1`, `libwayland-client.so.0`, `libxkbcommon.so.0`, `libX11.so.6`/`libxcb.so.1` | builds & links | nothing to install; run tests with lavapipe (`mesa-vulkan-drivers`) + `xvfb`/`weston --headless` for windowed tests |
| accesskit (eframe default) | none (zbus) | at-spi bus optional | builds | — |
| rfd (`xdg-portal`) | none | `libdbus-1.so.3` (dlopen) or `zenity`; portal backend | builds | — |
| arboard (`wayland-data-control`) | none | compositor `ext-data-control-v1`/`wlr-data-control` for Wayland path; else X11 | builds | — |
| notify-rust (`z`/`z-with-tokio`) | none | notification daemon | builds | — |
| keyring-core + linux-keyutils store | none | kernel keyrings | builds | — |
| zbus-secret-service store | none | Secret Service daemon (gnome-keyring) | builds | `gnome-keyring` + `dbus-run-session` for tests |
| gilrs | **`pkg-config` + `libudev.pc`** (`libudev-sys-0.1.4/build.rs: pkg_config::find_library("libudev").unwrap()`) | `libudev.so.1`, evdev nodes | **fails** (`pkg-config libudev` → not found here) | `apt-get install libudev-dev` |
| tray-icon / muda (`gtk`, `libxdo`) | **`libgtk-3-dev`, `libayatana-appindicator3-dev` (or `libappindicator3-dev`), `libxdo-dev`** | `libgtk-3.so.0`, `libayatana-appindicator3.so.1`, `libxdo.so.3` (dlopen) | **fails** (`pkg-config gtk+-3.0` → not found) | apt-get the three packages |
| image (png), qrcode, clap, toml, tracing-*, directories | none | — | builds | — |

pkg-config check on this VM (all "no"): `gtk+-3.0 ayatana-appindicator3-0.1 appindicator3-0.1 libudev wayland-client xkbcommon x11 xcb vulkan libdbus-1 egl gl libsecret-1`. Runtime `.so.N` files for all of them **are** present (`/usr/lib/x86_64-linux-gnu/`), which is why dlopen-based crates work and pkg-config/`#[link]` crates do not. No `nasm`, no `libclang-dev` needed by any crate in this note (no bindgen in the graph).

Workspace layout suggestion (Cargo features on `apps/tornect`):

```toml
[features]
default = ["tray"]            # CI and release builds
tray = ["dep:tray-icon"]      # Linux dev VMs without gtk headers: cargo build --no-default-features
gamepad = ["dep:gilrs"]       # same: needs libudev-dev on Linux
```

and `cfg(all(target_os = "linux", feature = "tray"))` around the gtk thread. Document in `CLAUDE.md` that on this VM the app is built with `--no-default-features --features ""` and that CI runs the full set.

---

## 7. Gotchas

1. **`App::update` is gone** (0.34, #7775): implement `fn ui(&mut self, ui: &mut egui::Ui, frame: &mut Frame)`; the `Ui` has no margin/background, wrap in `CentralPanel`. `App::logic` is called even when the window is hidden.
2. **`egui::Context::run` was replaced by `run_ui(RawInput, impl FnMut(&mut Ui)) -> FullOutput`** (`context.rs:793`); `begin_pass`/`end_pass` still exist (`:961`, `:2440`). `RawInput.modifiers` was removed in 0.36 (now `egui::Event::Modifiers`, #8336).
3. **`WgpuConfiguration.present_mode` moved into `surface: SurfaceConfig`** (0.35, #8114); `on_surface_error` became `on_surface_status: Fn(wgpu::CurrentSurfaceTexture)`. `Default` is `HIGH_THROUGHPUT`; use `LOW_LATENCY` or `AutoNoVsync` + `Some(1)` for the stream window. Vsync can be changed at runtime via `Frame::set_wgpu_surface_config` / `RenderState.surface_config`.
4. **wgpu 30 API differences vs older code:** `enumerate_adapters` is async; `request_adapter` returns `Result<Adapter, RequestAdapterError>`; `request_device` takes one `&DeviceDescriptor`; `PipelineLayoutDescriptor.immediate_size: u32` replaces push-constant ranges; `RenderPipelineDescriptor.multiview_mask`; `RenderPassColorAttachment.depth_slice`; `device.poll(PollType)`; `Instance::new(desc)` takes the descriptor **by value**.
5. **`InstanceDescriptor` is not `Clone`**; egui-wgpu therefore stores the display handle separately (`setup.rs:166-168`). Always pass `event_loop.owned_display_handle()` (needed for Wayland+GLES fallback).
6. **Do not mix `winit/default` in a dependent's feature list** — cargo error "feature `winit/default` in dependency `eframe` is not allowed to contain slashes" (hit in the probe). Put `winit = { version = "=0.30.13", features = [...] }` in your own manifest instead.
7. **Wayland raw motion arrives without a lock** (relative-pointer is always bound), but the compositor will still move the visible cursor unless you `Locked` it; and on GNOME the lock is only granted while the surface is focused. Also GNOME emits `Focused(false)` on lock loss — always unlock on focus loss (skeleton does).
8. **Keyboard on Wayland:** `KeyEvent.physical_key` is derived from evdev keycodes via `xkbcommon-dl`; `logical_key`/`text` respect the client layout. Send both; the host's `reis` backend needs evdev codes (physical) for games and keysyms for typing (plan §B.5). `KeyEvent.repeat` marks auto-repeat — do not forward repeats as new presses.
9. **egui consumes Tab always** (`EventResponse` docs, `lib.rs:71`); when the stream window is in "captured" mode, bypass `State::on_window_event` for keyboard/mouse entirely and only feed egui pointer events when the HUD is open.
10. **arboard on GNOME Wayland:** Mutter does not implement `wlr-data-control`/`ext-data-control`, so `wayland-data-control` falls back to X11 (via XWayland) which only sees XWayland clients' clipboard. For Wayland-native clipboard in the *client* window use the `smithay-clipboard` egui-winit already owns (`State::clipboard_text()/set_clipboard_text()`, `lib.rs:219-224`), and on the *host* use the RemoteDesktop portal Clipboard (wayland note). `arboard` remains the right choice for X11/Windows/macOS and for images.
11. **rfd `MessageDialog` on Linux shells out to zenity** — use egui modals for consent/errors.
12. **notify-rust `show()` blocks** on D-Bus (`zbus::block_on`); never call it on the winit thread. The `Notification` builder methods take `&mut self` and return `&mut Self` (chain then `.show()`).
13. **keyring v1 shim overrides your store** (§5.9). Also the Secret Service store requires an unlocked keyring; on headless CI start `gnome-keyring-daemon --unlock` (`zbus-secret-service-keyring-store/src/lib.rs:60-80`).
14. **`secret-service` uses `sha2 0.10`/`hkdf 0.12`** — expect duplicate `sha2` majors in `Cargo.lock` alongside the crypto stack's 0.11; don't try to unify.
15. **eframe `persistence` + `with_app_id("tornect")`** stores `app.ron` under `~/.local/share/tornect` — same dir `directories` gives for `data_local_dir()`; pick one owner for that directory.
16. **tray on GNOME needs an AppIndicator shell extension**; without it the icon is simply not shown (no error).
17. **`image` default features** pull `ravif`/`exr`/`tiff` etc. (big compile, and `nasm` feature needs nasm). Always `default-features = false, features = ["png"]`.
18. **`/tmp` on this VM is a 3.7 GB tmpfs** — a wgpu/egui debug `target/` exceeds it. Build with `CARGO_TARGET_DIR` on `/home` (46 GB free) and `CARGO_PROFILE_DEV_DEBUG=0`; put this in the workspace `.cargo/config.toml` guidance for the VM.
19. **winit 0.31** is still beta (0.31.0-beta.2); do not track it until egui moves.

---

## 8. Probe results (this VM)

Probe crate: `/tmp/probe-ui` (sources: `src/main.rs` eframe app + NV12 callback + QR + clipboard + keyring + notify + rfd + logging/clap/toml; `src/bin/headless.rs` wgpu adapter/lavapipe test; `src/bin/winit_manual.rs` the §5.3 skeleton). Target dir: `/home/mx/.cache/tornect-probe-ui-target` (≈ several GB, safe to delete). Built with `CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0`. Logs: `/tmp/probe-ui/{build-base,build-gilrs,build-tray,run}.log`.

| step | features / deps | outcome on this VM |
|---|---|---|
| `cargo build --bins` | eframe 0.36.1 (`accesskit, default_fonts, wgpu, wayland, x11, persistence, links`), egui/egui-wgpu(`winit,wayland,x11`)/egui-winit/egui_extras(`image`) 0.36.1, wgpu 30.0.1 (`std,wgsl,vulkan,gles,dx12,metal`), winit 0.30.13 (defaults), rfd 0.17.2 (`xdg-portal` only), arboard 3.6.1 (`image-data,wayland-data-control`), notify-rust 4.18.0 (`z`), keyring 4.1.6 (`v1,linux-keyutils-keyring-store`) + keyring-core 1.0.0 + linux-keyutils-keyring-store 1.0.0, directories 6.0.0, qrcode 0.14.1 (no default features), image 0.25.10 (`png`), clap 4.6.6 (`derive,env`), toml 1.1.4, tracing-subscriber 0.3.23 (`env-filter,fmt,json`), tracing-appender 0.2.5, pollster, bytemuck | **OK** — compiles **and links** all three binaries with zero `-dev` packages (one dead-code warning in my code). ~17 min cold with 2 jobs. |
| `cargo tree -i wgpu/winit/raw-window-handle/egui/zbus/arboard` | — | exactly one copy each: `wgpu 30.0.1`, `winit 0.30.13`, `raw-window-handle 0.6.2`, `egui 0.36.1`, `zbus 5.19.0`, `arboard 3.6.1`. Duplicate majors that do exist and are harmless: `smithay-client-toolkit 0.19.2` (winit) + `0.20.0` (smithay-clipboard), `pollster 0.4` (rfd) + `1.0` (eframe), `calloop 0.13/0.14`, `thiserror 1/2`, `rustix 0.38/1`, `hashbrown 0.15/0.16/0.17`. |
| `headless` (no env) | `Backends::from_env().unwrap_or(VULKAN\|GL)`, `request_adapter(PowerPreference::None)` | **OK**: enumerated `llvmpipe (LLVM 21.1.8, 256 bits)` backend=Vulkan type=**Cpu** driver=llvmpipe and `SVGA3D; build: RELEASE; LLVM;` backend=Gl type=Other (VMware via EGL); selected llvmpipe; `request_device` + clear render pass + `device.poll(PollType::wait_indefinitely())` → `render pass OK`. |
| `headless` with `TORNECT_SOFTWARE_GPU=1 WGPU_BACKEND=vulkan` | `force_fallback_adapter: true` | **OK**: only the Vulkan/llvmpipe adapter enumerated and selected; render pass OK. This is the recipe for CI/headless tests. |
| `probe-ui --headless` | logging → `~/.local/share/tornect/tornect.YYYY-MM-DD.log`, toml round-trip, `linux_keyutils_keyring_store::Store::new()` + `keyring::Entry::new` | **OK** (exit 0): log shows `config_dir=/home/mx/.config/tornect` and `keyring entry entry_ok=true` (note: `keyring::Entry::new` replaced the keyutils default store with the zbus Secret Service store, per §5.9 — the entry succeeded because GNOME Keyring is running in this session). |
| `probe-ui` (GUI, 8 s timeout) | eframe wgpu on live GNOME 50 Wayland session | **runs** until killed by `timeout` (no crash). egui_wgpu log: "There are 2 available wgpu adapters" (llvmpipe Vulkan Cpu, SVGA3D GL). arboard log: "Tried to initialize the wayland data control protocol clipboard, but failed. Falling back to the X11 clipboard protocol… (ext-data-control, or wlr-data-control version 1) is not supported by the compositor" — confirms gotcha 10 empirically. |
| `winit_manual` (GUI, 8 s timeout) | winit 0.30 `ApplicationHandler` + `egui_winit::State` + `egui_wgpu::winit::Painter`, `AutoNoVsync`, latency 1 | **runs** until killed (window + surface + egui frame loop OK on Wayland/lavapipe). Pointer-lock toggle (L key) not exercised non-interactively. |
| `cargo build --features gilrs` | + gilrs 0.11.2 / gilrs-core 0.6.8 | **FAILS** in `libudev-sys-0.1.4/build.rs:38`: `pkg-config … libudev` → "Package libudev was not found". CI: `apt-get install libudev-dev`. |
| `cargo build --features tray` | + tray-icon 0.24.2 (`gtk`, `libxdo`) → muda 0.19.3 → gtk 0.18 | **FAILS** in `glib-sys` build script: `pkg-config … glib-2.0` → "Package glib-2.0 was not found" (gtk+-3.0 / appindicator would fail next). CI: `apt-get install libgtk-3-dev libayatana-appindicator3-dev libxdo-dev`. |

Not probed: Windows/macOS builds (no cross toolchain here); pointer lock semantics interactively; `zbus-secret-service-keyring-store` with `rt-tokio-crypto-rust` (keyring's `v1` uses `crypto-rust` + notify-rust's `zbus/async-io` here — in the real workspace the unified `tokio` feature will be selected by zbus, §2).

---

## 9. Open questions

1. Zero-copy decode → wgpu on Linux (VAAPI DMA-BUF → Vulkan external memory) needs `wgpu-hal` Vulkan access (`wgpu::Device::as_hal`) and `VK_EXT_external_memory_dma_buf`; not researched here (plan marks it M7).
2. HDR/P010 surface formats: which `wgpu::TextureFormat`/`PresentMode` combos winit+wgpu expose on Windows (`Rgba16Float` swapchains) — verify in the codec note.
3. Whether a GNOME AppIndicator-less tray is acceptable for v1 on Linux, or whether "background window + notifications" is the Linux UX.
4. `gilrs` `Send`-ness / threading model for the input thread — confirm when wiring `tornect-input`.
5. Wayland `Confined` vs `Locked` behaviour under KDE/Sway (only GNOME 50 available here).
6. Accessibility (`accesskit`) in the manual-winit path is deferred; decide whether M0 needs it.
