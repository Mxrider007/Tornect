# Linux/Wayland capture & input (portals + PipeWire + libei) — research note (verified 2026-08-28)

Scope: the `pw` capture backend and the `reis`/RemoteDesktop-portal input backend from
plan §A.2 ("Linux/Wayland"), §A.3 D8/D11, §B.5. Everything below was checked against
the crate sources extracted into `/tmp/crates-src/<crate>-<version>/` (downloaded from
`static.crates.io`), against live upstream docs/sources (URLs cited inline), and
against three probe crates compiled **on this VM** (Rust 1.96, Ubuntu 26.04, no sudo):

| probe | what | outcome |
|---|---|---|
| `/tmp/probe-wayland` | `ashpd =0.13.13` (tokio, screencast, remote_desktop, clipboard) + `reis =0.7.1` (tokio); full RemoteDesktop+ScreenCast session code path + EIS handshake | `cargo check` **OK**; `cargo run --bin versions` **ran** against the live portal (output §4.4) |
| `/tmp/probe-pw` | `pipewire =0.10.1` (`v1_0_0`) | `cargo check` **FAILS here** in `libspa-sys` build.rs: `pkg-config … libpipewire-0.3 not found` (no `libpipewire-0.3-dev`) — expected; CI-only |
| `/tmp/probe-xkb` | `xkbcommon =0.9.0` (`default-features=false`) | compiles, **link fails**: `rust-lld: error: unable to find library -lxkbcommon` (only `libxkbcommon.so.0` present, no dev symlink) — CI-only |

---

## 0. TL;DR for implementers

| Item | Decision |
|---|---|
| Portals | `ashpd = "=0.13.13"`, `default-features = false`, features `["tokio", "screencast", "remote_desktop", "clipboard"]`. Pure Rust (zbus 5.19). Do **not** enable `pipewire`, `wayland`, `gtk4`, `raw_handle` features (they pull C links / bindgen). |
| Session model | **ONE** portal session created by `RemoteDesktop::create_session`, then `RemoteDesktop::select_devices(...)` **and** `Screencast::select_sources(&same_session, ...)`, then `RemoteDesktop::start(...)`. The `SelectedDevices` response carries both `devices()` and `streams()` (+ `restore_token()`). Persistence/restore token is set **only** via `SelectDevicesOptions` (spec forbids ScreenCast persist options on a RemoteDesktop session). |
| Video | `Screencast::open_pipe_wire_remote(&session, …) -> OwnedFd` → `pipewire::context::ContextBox::connect_fd(fd, None)` → `StreamBox::connect(Direction::Input, Some(node_id), AUTOCONNECT\|MAP_BUFFERS, &mut [EnumFormat pods])`. |
| Input | `RemoteDesktop::connect_to_eis(&session, …) -> OwnedFd` (portal v2) → `reis::ei::Context::new(UnixStream::from(fd))` → `ctx.handshake_tokio(name, ContextType::Sender)` → bind seat capabilities → per device: `start_emulating` / `key`/`motion_*`/`button`/`scroll*` / `frame` / `stop_emulating`. **After ConnectToEIS the `notify_*` D-Bus methods return errors** (spec) — they are only the fallback when `RemoteDesktop.version() < 2`. |
| PipeWire | `pipewire = "=0.10.1"` + `libspa = "=0.10.1"`, features `["v1_0_0"]` (max that still builds on `ubuntu-latest` = 24.04, libpipewire 1.0.5; the VM/26.04 has 1.6.2). Needs `libpipewire-0.3-dev libspa-0.2-dev libclang-dev clang pkg-config` (bindgen 0.72 `runtime`). **Cannot build on this VM.** |
| Keymap | `xkbcommon = "=0.9.0"` (`default-features=false` unless you need `new_from_fd` → feature `wayland`/memmap2) links `-lxkbcommon` via `#[link]` → needs `libxkbcommon-dev`. **Cannot link on this VM.** Only needed for keysym→keycode reverse mapping; keep it in the `linux-input` feature/crate. |
| `wayland-client` | Not needed directly. ashpd's `wayland` feature (parented dialogs / `WindowIdentifier::from_wayland*`) pulls `wayland-backend` `client_system` → pkg-config `wayland-client` → `libwayland-dev`. Pass `identifier: None` to `start()` in v1. |
| GNOME on Ubuntu 26.04 (this VM) | xdg-desktop-portal 1.21.1, xdg-desktop-portal-gnome 50.0, gnome-shell 50.1, mutter 50.1, pipewire 1.6.2, libei/libeis 1.5.0. Live portal versions: **RemoteDesktop v2, ScreenCast v5, Clipboard v1**; all device/source/cursor types advertised. |
| Locked screen | gnome-shell inhibits mutter remote access whenever the session mode has `allowScreencast: false` (`unlock-dialog`/`gdm` inherit `false`). Mutter then **closes every existing screencast/remote-desktop session and refuses new ones ("Session creation inhibited")**. Restore tokens do not help while locked. See §7. |

---

## 1. Versions, features and why

### 1.1 Latest versions (crates.io API, 2026-08-28)

| crate | latest stable | created | MSRV | notes |
|---|---|---|---|---|
| ashpd | **0.13.13** | 2026-07-17 | 1.87 | https://crates.io/api/v1/crates/ashpd — `[dependencies.zbus] version = "5.13"` (locks to 5.19.0), `tokio = "1.43"` optional (`ashpd-0.13.13/Cargo.toml:255-258, 282-284`) |
| pipewire | **0.10.1** | 2026-08-19 | 1.80 | https://crates.io/api/v1/crates/pipewire |
| libspa | **0.10.1** | 2026-08-19 | 1.80 | https://crates.io/api/v1/crates/libspa |
| pipewire-sys / libspa-sys | 0.10.1 | 2026-08-19 | 1.80 | bindgen `0.72.0` with `features=["runtime"]`, `system-deps 7.0.5` (`pipewire-sys-0.10.1/Cargo.toml:59-66`) |
| reis | **0.7.1** | 2026-07-30 | 1.71.1 | https://crates.io/api/v1/crates/reis ; 0.7.0 2026-06-16, 0.6.1 2026-02-17, 0.5.0 2025-03-31 (versions API). Protocol snapshot = libei **1.6.0** (`reis-0.7.1/LIBEI_VERSION`) |
| xkbcommon | **0.9.0** | 2025-08-09 | — | https://crates.io/api/v1/crates/xkbcommon |
| wayland-client | 0.31.15 | 2026-07-22 | — | depends on `wayland-backend 0.3.15+` (`wayland-client-0.31.15/Cargo.toml:77-78`) |
| wayland-backend / wayland-sys | 0.3.17 / 0.31.11 | — | — | `wayland-sys/build.rs`: links via `pkg_config::Config::new().probe("wayland-client")` unless feature `dlopen` |

Note: ashpd's own dev-dependency is `pipewire = "0.9.0"` and `reis = "0.6"` (`ashpd-0.13.13/Cargo.toml:290-298`), yet its example compiles against the same `MainLoopBox/ContextBox/StreamBox` API that pipewire 0.10.1 exposes (verified by reading `pipewire-0.10.1/src/{main_loop,context,stream}/box_.rs`). reis 0.7.1's own dev-dep is `ashpd = "0.13.3"` with `async-io` (`reis-0.7.1/Cargo.toml`), i.e. the two crates are co-tested upstream.

### 1.2 Feature lists (crates.io `/crates/<name>/<version>`)

**ashpd 0.13.13**: `default = ["tokio"]`; `tokio = ["zbus/tokio", "dep:tokio"]`; `async-io = ["zbus/async-io", "futures-util/io"]`; `screencast = ["dep:serde_repr"]`; `remote_desktop = ["dep:serde_repr"]`; `clipboard = []`; `input_capture`; `pipewire = ["dep:pipewire", "dep:futures-channel"]`; `wayland = ["wayland-client","wayland-protocols","wayland-backend"]`; `raw_handle = ["raw-window-handle"]`; `gtk4*`, `glib`, `backend`, `tracing`.
README (`ashpd-0.13.13/README.md:45-46`): "tokio — Enable tokio runtime on zbus dependency (default Yes); async-io — Enable the use of the async-io crates, compatible with runtimes such smol or glib (No)". Pick exactly one; Tornect is tokio → `tokio`. zbus with `tokio` must be driven from inside a tokio runtime (the probe uses `#[tokio::main]`).

**pipewire 0.10.1** version features (cumulative): `v0_3_32 … v0_3_77, v1_0_0 = ["spa/v1_0_0","v0_3_77"], v1_2_0 = ["spa/v1_2_0","v1_0_0"]`. **libspa 0.10.1**: `v0_3_21 … v0_3_75, v1_0_0, v1_2_0, v1_6_0`. Things we need that are gated: `PropertyFlags::DONT_FIXATE` (`#[cfg(feature="v0_3_33")]`, `libspa/src/pod/mod.rs:1490`), `VideoFlags::MODIFIER` (`v0_3_65`) and `MODIFIER_FIXATION_REQUIRED` (`v0_3_75`) (`libspa/src/param/video/raw.rs:163-169`), `StreamFlags::TRIGGER` (`v0_3_41`), `Buffer::requested()` (`v0_3_49`). `MetaSyncTimeline` needs `v1_2_0` (not needed). → `features = ["v1_0_0"]` covers all of ours and matches `ubuntu-latest`.

**reis 0.7.1**: `tokio = ["dep:tokio","dep:futures-util"]`, `async-io`, `calloop`; `tokio` dep is `1.31 features=["net"]`; deps are only `enumflags2`, `log`, `rustix` (`reis-0.7.1/Cargo.toml`). `#![forbid(unsafe_code)]`, no build.rs → **pure Rust**.

**xkbcommon 0.9.0**: `default = ["wayland"]`, `wayland = ["memmap2"]` (adds `Keymap::new_from_fd`), `x11`. No build.rs; links with `#[link(name = "xkbcommon")] extern "C"` (`xkbcommon-0.9.0/src/xkb/ffi.rs:114`). Deps: `libc`, `xkeysym 0.2`.

### 1.3 Recommended pins

```toml
# crates/tornect-capture (linux) and crates/tornect-input (linux)
[target.'cfg(target_os = "linux")'.dependencies]
ashpd    = { version = "=0.13.13", default-features = false, features = ["tokio", "screencast", "remote_desktop", "clipboard"] }
reis     = { version = "=0.7.1", features = ["tokio"] }
enumflags2 = "0.7"            # BitFlags<SourceType>/<DeviceType>/<DeviceCapability> (ashpd & reis re-export it: `reis::enumflags2`)
futures-util = "0.3"          # StreamExt for Request/Session signals and the EIS event stream
tokio    = { version = "1", features = ["rt-multi-thread", "macros", "net", "sync"] }

# only behind a cargo feature `pipewire-capture` (needs system headers, CI-only build here)
pipewire = { version = "=0.10.1", features = ["v1_0_0"], optional = true }
libspa   = { version = "=0.10.1", features = ["v1_0_0"], optional = true }   # also reachable as `pipewire::spa`

# only behind feature `xkb` (needs libxkbcommon-dev to link)
xkbcommon = { version = "=0.9.0", default-features = false, features = ["wayland"], optional = true }
```

Locked transitive versions from the probe (`/tmp/probe-wayland/Cargo.lock`): zbus 5.19.0, zvariant 5.15.0, tokio 1.53.1, rustix 1.1.4, enumflags2 0.7.12, futures-util 0.3.34.

---

## 2. Portal API (ashpd 0.13.13) — exact signatures

All from `/tmp/crates-src/ashpd-0.13.13/src/desktop/{screencast.rs,remote_desktop.rs,session.rs,request.rs,mod.rs}`.

### 2.1 Shared types

```rust
// src/desktop/mod.rs:170-181
pub enum PersistMode { DoNot = 0, Application = 1, ExplicitlyRevoked = 2 }   // #[default] DoNot

// src/desktop/session.rs:24-26, 70-85
pub struct Session<T: SessionPortal>(Proxy<'static>, PhantomData<T>);
impl<T: SessionPortal> Session<T> {
    pub async fn receive_closed(&self) -> Result<impl Stream<Item = HashMap<String, OwnedValue>>, Error>;
    pub async fn close(&self) -> Result<(), Error>;
}
// src/desktop/session.rs:166-171 — both handle tokens are auto-generated; Default is all you need
pub struct CreateSessionOptions { handle_token, session_handle_token }

// src/desktop/request.rs:266, 276
impl<T> Request<T> { pub fn response(&self) -> Result<T, Error>; pub async fn close(&self) -> Result<(), Error>; }
```
`Request<T>` is returned by every `*_request` call **after** the D-Bus `Response` signal has already been received (`prepare_response`, request.rs:245-263), so `.await?.response()?` is synchronous. A user "Cancel" in the dialog surfaces as `Error::Response(ResponseError::Cancelled)` ("Portal request was cancelled", `src/error.rs:79`). A missing portal is `Error::PortalNotFound`; a too-old portal is `Error::RequiresVersion(required, current)` (`src/error.rs:62,93`).

Session type unification (`remote_desktop.rs:760-765`):
```rust
impl SessionPortal for RemoteDesktop {}
impl crate::desktop::clipboard::IsClipboardSession for RemoteDesktop {}     // feature "clipboard"
impl crate::desktop::screencast::IsScreencastSession for RemoteDesktop {}   // feature "screencast"
```
→ `Screencast::select_sources`, `Screencast::open_pipe_wire_remote` and `Clipboard::*` all accept `&Session<RemoteDesktop>`. `Screencast::start` also accepts it but **must not be called** on a RemoteDesktop session; call `RemoteDesktop::start`.

### 2.2 ScreenCast (`src/desktop/screencast.rs`)

```rust
#[bitflags] #[repr(u32)] pub enum SourceType { Monitor, Window, Virtual }              // :64-74
#[bitflags] #[repr(u32)] pub enum CursorMode { Hidden, Embedded, Metadata }            // :81-92

pub struct SelectSourcesOptions { /* handle_token, types, multiple, cursor_mode, restore_token, restore_data, persist_mode */ }
impl SelectSourcesOptions {                                                            // :124-193
    pub fn set_multiple(self, multiple: impl Into<Option<bool>>) -> Self;
    pub fn set_cursor_mode(self, cursor_mode: impl Into<Option<CursorMode>>) -> Self;
    pub fn set_sources(self, types: impl Into<Option<BitFlags<SourceType>>>) -> Self;  // NOTE: BitFlags, not SourceType
    pub fn set_persist_mode(self, persist_mode: impl Into<Option<PersistMode>>) -> Self;
    pub fn set_restore_token<'a>(self, token: impl Into<Option<&'a str>>) -> Self;
}
pub struct StartCastOptions { handle_token }                                           // :198-201 (Default)
pub struct OpenPipeWireRemoteOptions {}                                                // :97

pub struct Streams { .. }                                                              // :206-217
impl Streams { pub fn restore_token(&self) -> Option<&str>; pub fn streams(&self) -> &[Stream]; }
pub struct Stream(u32, StreamProperties);                                              // :297
impl Stream {                                                                          // :299-338
    pub fn pipe_wire_node_id(&self) -> u32;
    pub fn position(&self) -> Option<(i32, i32)>;     // compositor coords, monitors only
    pub fn size(&self) -> Option<(i32, i32)>;         // compositor coords (may differ from pixel size)
    pub fn source_type(&self) -> Option<SourceType>;
    pub fn id(&self) -> Option<&str>;                 // opaque, persisted across restored sessions
    pub fn mapping_id(&self) -> Option<&str>;         // matches reis::event::Region::mapping_id
}

pub struct Screencast(Proxy<'static>);
impl Screencast {
    pub async fn new() -> Result<Self, Error>;                                          // :442
    pub async fn with_connection(connection: zbus::Connection) -> Result<Self, Error>;  // :448
    pub fn version(&self) -> u32;                                                       // :456
    pub async fn create_session(&self, options: CreateSessionOptions) -> Result<Session<Self>, Error>;                 // :467
    pub async fn open_pipe_wire_remote(&self, session: &Session<impl IsScreencastSession>,
                                       options: OpenPipeWireRemoteOptions) -> Result<OwnedFd, Error>;                  // :499
    pub async fn select_sources(&self, session: &Session<impl IsScreencastSession>,
                                options: SelectSourcesOptions) -> Result<Request<()>, Error>;                          // :531
    pub async fn start(&self, session: &Session<impl IsScreencastSession>, identifier: Option<&WindowIdentifier>,
                       options: StartCastOptions) -> Result<Request<Streams>, Error>;                                  // :562
    pub async fn available_cursor_modes(&self) -> Result<BitFlags<CursorMode>, Error>;   // :584 (portal v2+)
    pub async fn available_source_types(&self) -> Result<BitFlags<SourceType>, Error>;   // :594
}
```
Stand-alone screencast flow (module doc, `screencast.rs:8-39`):
```rust
let proxy = Screencast::new().await?;
let session = proxy.create_session(Default::default()).await?;
proxy.select_sources(&session, SelectSourcesOptions::default()
        .set_cursor_mode(CursorMode::Metadata)
        .set_sources(SourceType::Monitor | SourceType::Window)
        .set_multiple(true)
        .set_persist_mode(PersistMode::DoNot)).await?;
let response = proxy.start(&session, None, Default::default()).await?.response()?;
for stream in response.streams() { stream.pipe_wire_node_id(); stream.size(); stream.position(); }
```
Note (`screencast.rs:513-516, 546`): "An application may only attempt to select sources once per session" and "can only attempt start a session once" — invalid input closes the session.

### 2.3 RemoteDesktop (`src/desktop/remote_desktop.rs`)

```rust
#[repr(u32)] pub enum KeyState { Pressed = 1, Released = 0 }                            // :114-121
#[bitflags] #[repr(u32)] pub enum DeviceType { Keyboard, Pointer, Touchscreen }         // :128-138
#[repr(u32)] pub enum Axis { Vertical = 0, Horizontal = 1 }                             // :146-153

pub struct SelectDevicesOptions { /* handle_token, types, restore_token, persist_mode */ }   // :221-230
impl SelectDevicesOptions {                                                             // :232-250
    pub fn set_devices(self, types: impl Into<Option<BitFlags<DeviceType>>>) -> Self;
    pub fn set_persist_mode(self, persist_mode: impl Into<Option<PersistMode>>) -> Self;
    pub fn set_restore_token<'a>(self, token: impl Into<Option<&'a str>>) -> Self;
}
pub struct StartOptions { handle_token }                                                // :255-258
pub struct SelectedDevices { devices, streams, restore_token, clipboard_enabled }       // :263-272
impl SelectedDevices {                                                                  // :274-294
    pub fn devices(&self) -> BitFlags<DeviceType>;
    pub fn streams(&self) -> &[Stream];             // "if a ScreenCast portal is used on the same session"
    pub fn restore_token(&self) -> Option<&str>;
    pub fn is_clipboard_enabled(&self) -> bool;
}
pub struct ConnectToEISOptions {}                                                       // :299

pub struct RemoteDesktop(Proxy<'static>);
impl RemoteDesktop {
    pub async fn new() -> Result<Self, Error>;                                                                  // :310
    pub async fn with_connection(connection: zbus::Connection) -> Result<Self, Error>;                          // :316
    pub fn version(&self) -> u32;                                                                               // :324
    pub async fn create_session(&self, options: CreateSessionOptions) -> Result<Session<Self>, Error>;          // :337
    pub async fn select_devices(&self, session: &Session<Self>, options: SelectDevicesOptions) -> Result<Request<()>, Error>;  // :365
    pub async fn start(&self, session: &Session<Self>, identifier: Option<&WindowIdentifier>, options: StartOptions)
        -> Result<Request<SelectedDevices>, Error>;                                                             // :391
    // legacy D-Bus injection (usable only when connect_to_eis is NOT used / portal v1):
    pub async fn notify_keyboard_keycode(&self, session: &Session<Self>, keycode: i32, state: KeyState, options: NotifyKeyboardKeycodeOptions) -> Result<(), Error>;   // :423
    pub async fn notify_keyboard_keysym (&self, session: &Session<Self>, keysym: i32,  state: KeyState, options: NotifyKeyboardKeysymOptions)  -> Result<(), Error>;   // :451
    pub async fn notify_touch_up(&self, session, slot: u32, options) -> Result<(), Error>;                                                 // :478
    pub async fn notify_touch_down(&self, session, stream: u32, slot: u32, x: f64, y: f64, options) -> Result<(), Error>;                  // :509
    pub async fn notify_touch_motion(&self, session, stream: u32, slot: u32, x: f64, y: f64, options) -> Result<(), Error>;                // :543
    pub async fn notify_pointer_motion_absolute(&self, session, stream: u32, x: f64, y: f64, options) -> Result<(), Error>;                // :573
    pub async fn notify_pointer_motion(&self, session, dx: f64, dy: f64, options) -> Result<(), Error>;                                    // :604
    pub async fn notify_pointer_button(&self, session, button: i32 /* evdev BTN_* */, state: KeyState, options) -> Result<(), Error>;      // :634
    pub async fn notify_pointer_axis_discrete(&self, session, axis: Axis, steps: i32, options) -> Result<(), Error>;                       // :661
    pub async fn notify_pointer_axis(&self, session, dx: f64, dy: f64, options: NotifyPointerAxisOptions /* .set_finish(bool) */) -> Result<(), Error>;  // :697
    pub async fn connect_to_eis(&self, session: &Session<Self>, options: ConnectToEISOptions) -> Result<OwnedFd, Error>;   // :729 — call_versioned(.., 2): Err(RequiresVersion) if portal < 2
    pub async fn available_device_types(&self) -> Result<BitFlags<DeviceType>, Error>;                          // :747
}
```

### 2.4 Combined RemoteDesktop + ScreenCast in ONE session (the Tornect host flow)

Verbatim from ashpd's module doc (`remote_desktop.rs:35-85`), plus what the probe compiled (`/tmp/probe-wayland/src/main.rs`):

```rust
use ashpd::desktop::{
    CreateSessionOptions, PersistMode,
    remote_desktop::{ConnectToEISOptions, DeviceType, RemoteDesktop, SelectDevicesOptions, StartOptions},
    screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType},
};
use enumflags2::BitFlags;

let remote_desktop = RemoteDesktop::new().await?;
let screencast = Screencast::new().await?;
let session = remote_desktop.create_session(CreateSessionOptions::default()).await?;

remote_desktop.select_devices(&session, SelectDevicesOptions::default()
        .set_devices(DeviceType::Keyboard | DeviceType::Pointer)
        .set_persist_mode(PersistMode::ExplicitlyRevoked)      // persistence lives HERE for combined sessions
        .set_restore_token(saved_token.as_deref()))            // None on first run
    .await?;                                                   // Request<()> — nothing to read
screencast.select_sources(&session, SelectSourcesOptions::default()
        .set_cursor_mode(CursorMode::Metadata)
        .set_sources(BitFlags::from(SourceType::Monitor))      // or Monitor | Window
        .set_multiple(false))                                  // do NOT set persist_mode/restore_token here (spec, §2.5)
    .await?;

let resp = remote_desktop.start(&session, None, StartOptions::default()).await?.response()?;
let devices = resp.devices();                 // BitFlags<DeviceType>
let streams = resp.streams();                 // &[Stream] with pipe_wire_node_id()/size()/position()/mapping_id()
let new_token = resp.restore_token();         // persist it (single-use!) — replaces the old one
let pw_fd  = screencast.open_pipe_wire_remote(&session, Default::default()).await?;  // OwnedFd
let eis_fd = remote_desktop.connect_to_eis(&session, ConnectToEISOptions::default()).await?;  // OwnedFd, needs v2

// keep `session` alive for the whole stream; poll `session.receive_closed().await?` (lock screen closes it, §7)
// tear down with `session.close().await?`
```
Gotcha found by the probe: `set_sources(SourceType::Monitor)` does **not** compile (`SourceType: !Into<Option<BitFlags<SourceType>>>`, E0277) — wrap a single flag in `BitFlags::from(..)` or OR two flags.

### 2.5 What the portal spec says (xdg-desktop-portal docs, fetched 2026-08-28)

From https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html (interface **version 2**):
- `SelectDevices` options: `types` (u, "Default is all"), `restore_token` (s, v2, "The restore token is invalidated after using it once."), `persist_mode` (u, v2; 0/1/2 as ashpd `PersistMode`).
- `Start` results: `devices` (u), `streams` (a(ua{sv})), `clipboard_enabled` (b, v2), `restore_token` (s, v2, single-use).
- `ConnectToEIS`: "This method was added in version 2 of this interface." "This method must be called after org.freedesktop.portal.RemoteDesktop.Start". **"Once an EIS connection is established, input events must be sent exclusively via the EIS connection. Any events submitted via NotifyPointerMotion, NotifyKeyboardKeycode and other Notify* methods will return an error."**
- Combined sessions: "Call SelectSources() and OpenPipeWireRemote() with the remote desktop session to capture screen content alongside input control." and **"Persistence for combined remote desktop and screen cast sessions is managed exclusively through this portal; the persistence options in org.freedesktop.portal.ScreenCast.SelectSources must not be used with a remote desktop session."**

From https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html (interface **version 6** in current docs; **5** on this VM):
- `SelectSources`: `types` (default MONITOR), `multiple` (default no), `cursor_mode` (v2, default Hidden, must be one of `AvailableCursorModes`), `restore_token` (v4, "invalidated after using it once"), `persist_mode` (v4).
- `Start` → `streams` entries: `id` (v4), `position` (ii), `size` (ii), `source_type` (v3), `mapping_id` (v5), `pipewire-serial` (t, v6 — not exposed by ashpd 0.13.13's `StreamProperties`, `screencast.rs:354-365`).
- `OpenPipeWireRemote`: "Open a file descriptor to the PipeWire remote where the screen cast streams are available".

### 2.6 Clipboard on the same session (feature `clipboard`, `src/desktop/clipboard.rs`)

`Clipboard::new()`, `.request(&session, options)` (must be called **before** `start`; `clipboard_enabled` in `SelectedDevices` tells whether the user allowed it), `.set_selection`, `.selection_write` / `.selection_write_done`, `.selection_read`, `.receive_selection_owner_changed`, `.receive_selection_transfer` — all generic over `IsClipboardSession` (which `RemoteDesktop` implements). Portal version on this VM = 1. xdg-desktop-portal-gnome NEWS: Clipboard portal implemented in 45.beta; "50.0: Make the Clipboard portal return errors instead of succeeding" (https://gitlab.gnome.org/GNOME/xdg-desktop-portal-gnome/-/raw/main/NEWS). Treat clipboard as best-effort in v1.

### 2.7 Window identifier

`Screencast::start`/`RemoteDesktop::start` take `Option<&WindowIdentifier>`. `WindowIdentifier::from_raw_handle(&RawWindowHandle, Option<&RawDisplayHandle>)` (feature `raw_handle`) only handles Wayland handles when feature `wayland` is also on (`src/window_identifier/mod.rs:168-195`), and `wayland` links `libwayland-client` via pkg-config (`wayland-sys-0.31.11/build.rs`). X11 XIDs work without it. **v1: pass `None`** (dialog is not parented; that is what the ashpd examples do).

---

## 3. reis 0.7.1 — libei client API (input injection)

Sources: `/tmp/crates-src/reis-0.7.1/src/{ei.rs,tokio.rs,event.rs,handshake.rs,eiproto_ei.rs,eiproto_enum.rs}` and `examples/{receive.rs,list-devices.rs,type-text-ei.rs}`.

### 3.1 Context + tokio handshake

```rust
// src/ei.rs
pub struct Context(pub(crate) Backend);                       // Clone
impl Context {
    pub fn new(socket: UnixStream) -> io::Result<Self>;       // :56  ← UnixStream::from(OwnedFd from connect_to_eis)
    pub fn connect_to_env() -> io::Result<Option<Self>>;      // :75  ($LIBEI_SOCKET; dev convenience only)
    pub fn read(&self) -> io::Result<usize>;                  // :103
    pub fn pending_event(&self) -> Option<PendingRequestResult<Event>>;  // :109
    pub fn handshake(&self) -> handshake::Handshake;          // :116
    pub fn flush(&self) -> rustix::io::Result<()>;            // :125  ← MUST be called after queuing requests
}
// src/tokio.rs (feature "tokio")
pub struct EiEventStream(AsyncFd<ei::Context>);               // Stream<Item = io::Result<PendingRequestResult<ei::Event>>>
impl EiEventStream { pub fn new(context: ei::Context) -> io::Result<Self>; }
pub async fn ei_handshake(events: &mut EiEventStream, name: &str, context_type: ei::handshake::ContextType) -> Result<HandshakeResp, Error>;
impl ei::Context {
    pub async fn handshake_tokio(&self, name: &str, context_type: ei::handshake::ContextType)
        -> Result<(crate::event::Connection, EiConvertEventStream), Error>;   // high-level path
}
pub struct EiConvertEventStream(..);                          // Stream<Item = Result<event::EiEvent, Error>>
// src/eiproto_enum.rs:22-27
pub enum ContextType { Receiver = 1, Sender = 2 }             // Tornect host = Sender
```
`handshake_tokio` performs the version/interface negotiation for you (`EiHandshaker`, `src/handshake.rs:71-93`), so you do not hand-roll the `INTERFACES` table used by the calloop example.

### 3.2 High-level events and wrappers (`src/event.rs`)

```rust
pub struct Connection(..);   // :79
impl Connection { pub fn connection(&self) -> &ei::Connection; pub fn flush(&self) -> rustix::io::Result<()>; pub fn serial(&self) -> u32 /* last server serial */; }

#[enumflags2::bitflags] #[repr(u64)]
pub enum DeviceCapability { Pointer=1<<0, PointerAbsolute=1<<1, Keyboard=1<<2, Touch=1<<3, Scroll=1<<4, Button=1<<5, Text=1<<6 }   // :782-799

pub struct Seat(..);   impl Seat { pub fn name(&self) -> Option<&str>; pub fn bind_capabilities(&self, capabilities: BitFlags<DeviceCapability>); }  // :893-908
pub struct Region { pub x: u32, pub y: u32, pub width: u32, pub height: u32, pub scale: f32, pub mapping_id: Option<String> }   // :754-767
pub struct Keymap { pub fd: OwnedFd, pub size: u32, pub type_: ei::keyboard::KeymapType /* Xkb = 1 */ }                          // :771-777
pub struct Device(..);
impl Device {                                                               // :946-1024
    pub fn seat(&self) -> &Seat;
    pub fn device(&self) -> &ei::Device;                                    // low-level proxy: start_emulating/frame/stop_emulating
    pub fn name(&self) -> Option<&str>;
    pub fn device_type(&self) -> ei::device::DeviceType;                    // Virtual = 1 | Physical = 2
    pub fn dimensions(&self) -> Option<(u32, u32)>;
    pub fn regions(&self) -> &[Region];                                     // absolute-pointer regions; mapping_id ↔ portal Stream::mapping_id()
    pub fn keymap(&self) -> Option<&Keymap>;
    pub fn interface<T: ei::Interface>(&self) -> Option<T>;                 // e.g. interface::<ei::Keyboard>()
    pub fn has_capability(&self, capability: DeviceCapability) -> bool;
}
pub enum EiEvent {                                                          // :1039-1067
    Disconnected(..), SeatAdded(SeatAdded{seat}), SeatRemoved, DeviceAdded(DeviceAdded{device}), DeviceRemoved,
    DevicePaused, DeviceResumed(DeviceResumed{device, serial}), KeyboardModifiers{device, serial, depressed, latched, locked, group},
    Frame, DeviceStartEmulating, DeviceStopEmulating, PointerMotion, PointerMotionAbsolute, Button, ScrollDelta, ScrollStop,
    ScrollCancel, ScrollDiscrete, KeyboardKey{device,time,key,state}, TouchDown, TouchUp, TouchMotion, TouchCancel, TextKeysym, TextUtf8,
}
```

### 3.3 Low-level request proxies (generated, `src/eiproto_ei.rs`; all return `()` and only queue — `flush()` sends)

```rust
ei::Seat::bind(&self, capabilities: u64)                                        // prefer event::Seat::bind_capabilities
ei::Device::start_emulating(&self, last_serial: u32, sequence: u32)             // sequence must increase by ≥1 per call
ei::Device::stop_emulating(&self, last_serial: u32)
ei::Device::frame(&self, last_serial: u32, timestamp: u64)                      // µs of CLOCK_MONOTONIC; applies to all events since last frame
ei::Pointer::motion_relative(&self, x: f32, y: f32)
ei::PointerAbsolute::motion_absolute(&self, x: f32, y: f32)                     // logical pixels; must be inside a device region or silently dropped; max 1 per frame
ei::Button::button(&self, button: u32 /* BTN_* from linux/input-event-codes.h */, state: ei::button::ButtonState /* Released=0, Press=1 */)
ei::Scroll::scroll(&self, x: f32, y: f32)                                       // smooth, logical pixels
ei::Scroll::scroll_discrete(&self, x: i32, y: i32)                              // 120 = one wheel click; don't mix with scroll() in same frame
ei::Scroll::scroll_stop(&self, x: u32, y: u32, is_cancel: u32)
ei::Keyboard::key(&self, key: u32 /* evdev KEY_* code, per the device keymap */, state: ei::keyboard::KeyState /* Released=0, Press=1 */)  // ≤1 request per key per frame; release before stop_emulating
ei::Text::keysym(&self, keysym: u32, state: KeyState);  ei::Text::utf8(&self, text: &str)   // ei_text, libei ≥ 1.6.0 servers only
ei::Connection::sync(&self, version: u32) -> ei::Callback;  ei::Connection::disconnect(&self)
```
Doc comments quoted in-line come from `eiproto_ei.rs` (pointer_absolute :70-86, scroll :100-162, keyboard :70-92, device :90-170).

### 3.4 Minimal sender loop (adapted from `examples/receive.rs` + `examples/type-text-ei.rs`; compiled in the probe)

```rust
use futures_util::StreamExt;
use reis::{ei, event::{DeviceCapability, EiEvent}};
use std::os::unix::net::UnixStream;

let ctx = ei::Context::new(UnixStream::from(eis_fd))?;
let (conn, mut events) = ctx.handshake_tokio("tornect-host", ei::handshake::ContextType::Sender).await?;
let mut seq: u32 = 0;
while let Some(ev) = events.next().await {
    match ev? {
        EiEvent::SeatAdded(e) => {
            e.seat.bind_capabilities(DeviceCapability::Pointer | DeviceCapability::PointerAbsolute
                | DeviceCapability::Keyboard | DeviceCapability::Scroll | DeviceCapability::Button);
            conn.flush()?;
        }
        EiEvent::DeviceAdded(e) => { /* stash e.device; inspect e.device.regions() / keymap() / interface::<ei::Keyboard>() */ }
        EiEvent::DeviceResumed(e) => { /* device usable now; e.serial is the latest serial */ }
        EiEvent::DevicePaused(_) | EiEvent::DeviceRemoved(_) => { /* stop sending to it */ }
        EiEvent::Disconnected(_) => break,
        _ => {}
    }
}
// injecting one pointer click at absolute (x,y) on `dev: reis::event::Device`:
let now_us = /* clock_gettime(CLOCK_MONOTONIC) in µs */;
seq += 1;
dev.device().start_emulating(conn.serial(), seq);
dev.interface::<ei::PointerAbsolute>().unwrap().motion_absolute(x, y);
dev.device().frame(conn.serial(), now_us);
dev.interface::<ei::Button>().unwrap().button(0x110 /* BTN_LEFT */, ei::button::ButtonState::Press);
dev.device().frame(conn.serial(), now_us);
dev.interface::<ei::Button>().unwrap().button(0x110, ei::button::ButtonState::Released);
dev.device().frame(conn.serial(), now_us);
dev.device().stop_emulating(conn.serial());
conn.flush()?;
```
GNOME hands out *separate virtual devices* per capability (keyboard / pointer / abs-pointer / touch) — select the device by `has_capability` before calling `interface::<T>()`.

### 3.5 Keymap → keycodes

`ei_keyboard.keymap` gives an xkb keymap fd (`event::Keymap{fd,size,type_: Xkb}`). To type keysyms/characters you need the reverse map keysym→(keycode, level): `xkbcommon::xkb::Keymap::new_from_fd(&ctx, fd, size, KEYMAP_FORMAT_TEXT_V1, KEYMAP_COMPILE_NO_FLAGS)` (unsafe, feature `wayland`/memmap2, `xkbcommon-0.9.0/src/xkb/mod.rs:742-750`) then `Keymap::key_get_syms_by_level` (`:1033`) / `State::key_get_one_sym` (`:1419`). `ei_keyboard.key` takes **evdev** codes (`KEY_A = 30`), i.e. xkb keycode − 8. The plan's "send scancode + keysym" strategy maps directly: scancode → `key()` verbatim; keysym → lookup via keymap → `key()`; and, only when the server advertises `DeviceCapability::Text` (libei ≥ 1.6; this VM's libeis is 1.5.0 → **not** available), `ei::Text::keysym/utf8`.

---

## 4. PipeWire 0.10.1 / libspa 0.10.1 — consuming the portal video stream

Sources: `/tmp/crates-src/pipewire-0.10.1/src/{lib.rs,main_loop,thread_loop,context,core,stream,buffer.rs,keys.rs,properties}`, `/tmp/crates-src/libspa-0.10.1/src/{pod,param,buffer,utils}`, `ashpd-0.13.13/examples/screen_cast_pw.rs`, `pipewire-0.10.1/examples/streams.rs`. Upstream DMA-BUF procedure: https://raw.githubusercontent.com/PipeWire/pipewire/master/doc/dox/internals/dma-buf.dox.

### 4.1 Object model (0.10 = "Box"/"Rc" smart pointers; `pipewire/src/lib.rs:17-50`)

```rust
pipewire::init();                                                     // lib.rs:180 (ThreadLoopBox::new calls it for you)
let mainloop = pw::main_loop::MainLoopBox::new(None)?;                // main_loop/box_.rs:22 ; .loop_() -> &Loop ; .run() / .quit()
let context  = pw::context::ContextBox::new(mainloop.loop_(), None)?; // context/box_.rs:22  (properties: Option<PropertiesBox>)
let core     = context.connect_fd(fd /* OwnedFd from open_pipe_wire_remote */, None)?;   // context/mod.rs:71-85 -> CoreBox<'_>
// Rc flavour: MainLoopRc::new(None), ContextRc::new(&mainloop, None), context.connect_fd_rc(fd, None) (context/rc.rs:48,91)
// Thread flavour (own thread, lock-based): unsafe { pw::thread_loop::ThreadLoopBox::new(Some("tornect-pw"), None)? }  (thread_loop/box_.rs:24 — marked unsafe with "Safety: TODO")
//   .start() / .stop() / .lock() -> ThreadLoopLockGuard / .wait() / .signal(bool)   (thread_loop/mod.rs:46-145)
```
All PipeWire calls (stream creation, `connect`, `update_params`, listener registration) must happen on the loop thread or under `ThreadLoop::lock()`. Recommended for Tornect: spawn a dedicated std thread that owns `MainLoopBox`+`ContextBox`+`CoreBox`+`StreamBox` and talk to it via `Loop::add_event` (`loop_/mod.rs:286`) / channels; the frame callback hands out frames over a bounded channel.

### 4.2 Stream creation + listener (from `ashpd examples/screen_cast_pw.rs:48-133`, identical in `pipewire examples/streams.rs`)

```rust
use pipewire as pw; use pw::{properties::properties, spa};
struct UserData { format: spa::param::video::VideoInfoRaw }

let stream = pw::stream::StreamBox::new(&core, "tornect-capture", properties! {
    *pw::keys::MEDIA_TYPE => "Video", *pw::keys::MEDIA_CATEGORY => "Capture", *pw::keys::MEDIA_ROLE => "Screen",
})?;                                                                   // stream/box_.rs:27-36 ; properties! is properties/box_.rs:174-184
let _listener = stream.add_local_listener_with_user_data(UserData { format: Default::default() })   // stream/mod.rs:164
    .state_changed(|_stream, _ud, old, new| { /* StreamState::{Error(String),Unconnected,Connecting,Paused,Streaming} (stream/mod.rs:26-32) */ })
    .param_changed(|stream, ud, id, param| {                            // F: FnMut(&Stream, &mut D, u32, Option<&spa::pod::Pod>) (stream/mod.rs:773-779)
        let Some(param) = param else { return };
        if id != spa::param::ParamType::Format.as_raw() { return }
        let Ok((mt, mst)) = spa::param::format_utils::parse_format(param) else { return };   // param/format_utils.rs:13
        if mt != spa::param::format::MediaType::Video || mst != spa::param::format::MediaSubtype::Raw { return }
        ud.format.parse(param).expect("VideoInfoRaw::parse");            // param/video/raw.rs:378
        // ud.format.format() / .size() (Rectangle{width,height}) / .framerate() (Fraction{num,denom}) / .modifier() (u64) / .flags()
        // → here: decide DMA-BUF vs SHM, then stream.update_params(&mut [buffers_pod, meta_pods…]) (§4.4)
    })
    .process(|stream, ud| {                                            // F: FnMut(&Stream, &mut D) (stream/mod.rs:860-866)
        let Some(mut buffer) = stream.dequeue_buffer() else { return };  // stream/mod.rs:252 ; Buffer is re-queued on Drop (buffer.rs:85-91)
        let datas = buffer.datas_mut();                                  // &mut [spa::buffer::Data] (buffer.rs:23-40)
        // for each Data d: d.type_() -> DataType::{MemPtr,MemFd,DmaBuf,MemId}; d.fd() -> RawFd; d.data() -> Option<&mut [u8]> (only mapped with MAP_BUFFERS & non-DmaBuf);
        //   d.chunk().offset()/.size()/.stride()   (libspa/src/buffer/mod.rs:70-110, 143-163)
        // buffer.find_meta::<spa::buffer::meta::MetaHeader>()  → .pts() / .seq() / .flags()
        // buffer.find_meta::<spa::buffer::meta::MetaCursor>()  → .id()!=0 && .is_valid(); .position(); .hotspot(); .bitmap() -> Option<&MetaBitmap>{format,size,stride,bitmap_data()}
        // buffer.find_meta::<spa::buffer::meta::MetaVideoDamage>() → .iter() over &MetaRegion (dirty rects)
        // buffer.find_meta::<spa::buffer::meta::MetaVideoCrop>()
    })
    .register()?;                                                       // -> StreamListener<D>; keep it alive
```

### 4.3 EnumFormat pods for `connect()` — SHM and DMA-BUF

SHM/MemFd-only pod (verbatim shape from `screen_cast_pw.rs:137-202`):
```rust
let obj = spa::pod::object!(
    spa::utils::SpaTypes::ObjectParamFormat, spa::param::ParamType::EnumFormat,
    spa::pod::property!(spa::param::format::FormatProperties::MediaType, Id, spa::param::format::MediaType::Video),
    spa::pod::property!(spa::param::format::FormatProperties::MediaSubtype, Id, spa::param::format::MediaSubtype::Raw),
    spa::pod::property!(spa::param::format::FormatProperties::VideoFormat, Choice, Enum, Id,
        spa::param::video::VideoFormat::BGRx,           // default first, then alternatives
        spa::param::video::VideoFormat::BGRx, spa::param::video::VideoFormat::BGRA,
        spa::param::video::VideoFormat::RGBx, spa::param::video::VideoFormat::RGBA),
    spa::pod::property!(spa::param::format::FormatProperties::VideoSize, Choice, Range, Rectangle,
        spa::utils::Rectangle { width: 1920, height: 1080 }, spa::utils::Rectangle { width: 1, height: 1 }, spa::utils::Rectangle { width: 8192, height: 8192 }),
    spa::pod::property!(spa::param::format::FormatProperties::VideoFramerate, Choice, Range, Fraction,
        spa::utils::Fraction { num: 60, denom: 1 }, spa::utils::Fraction { num: 0, denom: 1 }, spa::utils::Fraction { num: 1000, denom: 1 }),
);
let bytes: Vec<u8> = spa::pod::serialize::PodSerializer::serialize(std::io::Cursor::new(Vec::new()), &spa::pod::Value::Object(obj))
    .unwrap().0.into_inner();
let shm_pod = spa::pod::Pod::from_bytes(&bytes).unwrap();               // pod/mod.rs:111
```
DMA-BUF pod — the `property!` macro's `Choice, Enum, <type>` arm expands to `$crate::utils::<type>` and there is **no** `utils::Long` (only `Id`, `Rectangle`, `Fraction`, `Fd`; `libspa/src/pod/mod.rs:1548-1560`, `utils/mod.rs`), and the macro always sets `flags: PropertyFlags::empty()`. So build the modifier property by hand (fields are `pub`, `pod/mod.rs:1451-1468`; `ChoiceValue::Long(Choice<i64>)` serializes fine, `pod/serialize.rs:197`):
```rust
use spa::pod::{Property, PropertyFlags, Value, ChoiceValue};
use spa::utils::{Choice, ChoiceEnum, ChoiceFlags};
const DRM_FORMAT_MOD_INVALID: i64 = 0x00ff_ffff_ffff_ffff;   // <drm_fourcc.h>: ((1ULL<<56)-1)
const DRM_FORMAT_MOD_LINEAR:  i64 = 0;
let modifiers: Vec<i64> = encoder_supported_modifiers_for(fourcc);  // from VA-API/EGL query; include INVALID if implicit-modifier alloc works
let modifier_prop = Property {
    key: spa::param::format::FormatProperties::VideoModifier.as_raw(),           // param/format.rs:220
    flags: PropertyFlags::MANDATORY | PropertyFlags::DONT_FIXATE,               // pod/mod.rs:1486-1491 (DONT_FIXATE needs feature v0_3_33+)
    value: Value::Choice(ChoiceValue::Long(Choice(ChoiceFlags::empty(),
            ChoiceEnum::Enum { default: modifiers[0], alternatives: modifiers.clone() }))),
};
let mut dmabuf_obj = /* same object!() as above but with a SINGLE VideoFormat Id (one pod per format) */;
dmabuf_obj.properties.insert(2, modifier_prop);   // right after MediaSubtype, before VideoSize
// serialize → dmabuf_pod
let mut params = [dmabuf_pod, shm_pod];           // DMA-BUF variants FIRST (upstream: "Place DMA-BUF formats with modifiers first to prioritize them")
stream.connect(spa::utils::Direction::Input, Some(node_id),
    pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS, &mut params)?;   // stream/mod.rs:188-215
```
`StreamFlags` available: `AUTOCONNECT, INACTIVE, MAP_BUFFERS, DRIVER, RT_PROCESS, NO_CONVERT, EXCLUSIVE, DONT_RECONNECT, ALLOC_BUFFERS, TRIGGER(v0_3_41)` (`stream/mod.rs:947-960`). `MAP_BUFFERS` mmaps MemFd data into `Data::data()`; it is harmless for DmaBuf (PipeWire does not map DmaBuf unless asked; consume via `Data::fd()` + `chunk().stride()/offset()` and the negotiated `modifier`).

### 4.4 Fixation + buffer params in `param_changed` (upstream dma-buf.dox, consumer side)

Upstream text (fetched): "Consumers: Parse the resulting SPA_PARAM_Format using spa_format_video_raw_parse() to extract format and modifier information." "Use spa_pod_find_prop(param, NULL, SPA_FORMAT_VIDEO_modifier) to check whether modifiers were negotiated." "If modifiers negotiated: SPA_PARAM_BUFFERS_dataType = 1 << SPA_DATA_DmaBuf. If not: 1 << SPA_DATA_MemFd, 1 << SPA_DATA_MemPtr, or both." With `DONT_FIXATE` the producer (mutter) is the one that fixates: it answers with a `Format` whose modifier is a single Long (`VideoInfoRaw::flags()` then lacks `MODIFIER_FIXATION_REQUIRED`, `raw.rs:168`). Rust:
```rust
// inside param_changed after ud.format.parse(param):
let has_modifier = param.as_object().ok()
    .and_then(|o| o.find_prop(spa::utils::Id(spa::param::format::FormatProperties::VideoModifier.as_raw())))
    .is_some();                                                           // pod/mod.rs:433, 598
let data_type_mask: i32 = if has_modifier { 1 << spa::buffer::DataType::DmaBuf.as_raw() }
                          else { (1 << spa::buffer::DataType::MemFd.as_raw()) | (1 << spa::buffer::DataType::MemPtr.as_raw()) };
let buffers = spa::pod::object!(
    spa::utils::SpaTypes::ObjectParamBuffers, spa::param::ParamType::Buffers,   // utils/mod.rs:148 ; param/mod.rs:31
    Property { key: spa_sys::SPA_PARAM_BUFFERS_dataType, flags: PropertyFlags::empty(),
               value: Value::Choice(ChoiceValue::Int(Choice(ChoiceFlags::empty(), ChoiceEnum::Flags { default: data_type_mask, flags: vec![data_type_mask] }))) },
    // optionally SPA_PARAM_BUFFERS_buffers (Range Int 4 .. 2..8), SPA_PARAM_BUFFERS_blocks (planes)
);
let meta_cursor = spa::pod::object!(spa::utils::SpaTypes::ObjectParamMeta, spa::param::ParamType::Meta,
    Property::new(spa_sys::SPA_PARAM_META_type, Value::Id(spa::utils::Id(spa_sys::SPA_META_Cursor))),
    Property::new(spa_sys::SPA_PARAM_META_size, Value::Int(/* CURSOR_META_SIZE(w,h) = sizeof(spa_meta_cursor)+sizeof(spa_meta_bitmap)+w*h*4, e.g. for 384x384 */)));
let meta_damage = /* same with SPA_META_VideoDamage, size Range Int sizeof(spa_meta_region)*N */;
let meta_header = /* SPA_META_Header, sizeof(spa_meta_header) */;
// serialize each, then:
stream.update_params(&mut [&buffers_pod, &meta_header_pod, &meta_cursor_pod, &meta_damage_pod])?;   // stream/mod.rs:217
```
`SPA_PARAM_BUFFERS_*`, `SPA_PARAM_META_*`, `SPA_META_Cursor` etc. are not wrapped by libspa (only `SpaTypes::ObjectParamBuffers/Meta` and `MetaCursor: Metadata { META_TYPE = SPA_META_Cursor }` are, `utils/mod.rs:148-149`, `buffer/meta.rs:329-331`) — use the `spa_sys` constants (re-exported as `pipewire::spa::sys`). Cursor metadata is only delivered when the portal session was created with `CursorMode::Metadata` **and** a `SPA_META_Cursor` param was negotiated; `MetaCursor::id() == 0` means "no new cursor data" (`meta.rs:270`).

Negotiated format reading: `VideoInfoRaw::{format(), size(), framerate(), max_framerate(), modifier(), flags()}` (`raw.rs:249-373`). `VideoFormat` constants include `BGRx, BGRA, RGBx, RGBA, xRGB, ARGB, NV12, xRGB_210LE/…102LE (10-bit), RGBA_F16` (`raw.rs:27-117`).

### 4.5 Live portal probe on this VM (`cargo run --bin versions`, `/tmp/probe-wayland/src/bin/versions.rs`)

```
org.freedesktop.portal.RemoteDesktop version = 2
org.freedesktop.portal.ScreenCast   version = 5
org.freedesktop.portal.Clipboard    version = 1
AvailableDeviceTypes = Keyboard | Pointer | Touchscreen
AvailableSourceTypes = Monitor | Window | Virtual
AvailableCursorModes = Hidden | Embedded | Metadata
```
(The full session flow in `src/main.rs` compiles but was **not run** — it opens an interactive consent dialog.)

### 4.6 `maxFramerate` in the consumer's `EnumFormat` (verified 2026-10-24, the quality design's step 20)

Question: does a consumer that adds `SPA_FORMAT_VIDEO_maxFramerate` (key `0x20005`) to its
`EnumFormat` pod as a Range of fractions `[n/1 default, 1/1 min, n/1 max]` make the
compositor deliver at most `n` pictures a second, and can the property break negotiation?
Sources read (upstream code at the tags named, fetched through their GitHub mirrors):

- **PipeWire 1.6.2** `spa/include/spa/pod/filter.h` (`spa_pod_filter_prop`, identical in
  1.4.0 for the Range∩Range branch): two Ranges intersect to `[max(min1, min2),
  min(max1, max2)]`, an empty intersection is `-EINVAL`, and the default is the second
  pod's if it lies in the new range, else the first's, else the new minimum. A property
  only one side carries is copied as it is unless it is `MANDATORY` (it is then
  `-EINVAL`), so a producer that offers no `maxFramerate` still negotiates, and fixation
  takes our default `n/1`.
- **mutter 50.0** `src/backends/meta-screen-cast-stream-src.c`: every format object carries
  `SPA_FORMAT_VIDEO_framerate` fixed at `0/1` (variable) and, when the stream has a
  frame rate, `SPA_FORMAT_VIDEO_maxFramerate` as `SPA_POD_CHOICE_RANGE_Fraction(def =
  refresh, min = 1/1, max = refresh)` (`push_format_object` ~326–337, the format list
  ~1470–1495; neither property is mandatory). `maybe_record_frame_with_timestamp`
  (~1339–1357) skips a frame that comes sooner than `G_USEC_PER_SEC ×
  max_framerate.denom / max_framerate.num` after the last one, queues a follow-up and
  keeps the damage, so the next frame carries what changed: the cap throttles without
  losing content. The range has been negotiable since mutter MR 134 (2018, "screen-cast-src:
  Allow negotiating the framerate": "Allow letting the sink clamp the framerate range").
- **KWin** (`master` and `v6.0.0`) `src/plugins/screencast/screencaststream.cpp`:
  `buildFormat` offers `framerate` `0/1` and `maxFramerate` as a Range `(refresh, 0/1,
  refresh)`; the negotiated `m_videoFormat.max_framerate` sets the stream's frame interval
  (6.0: `frameInterval = 1000 × denom / num`) or its `VsyncSource` rate (`master`,
  `framerate()`). It throttles.
- **xdg-desktop-portal-wlr** (`master`, `v0.7.1`) `src/screencast/pipewire_screencast.c`:
  offers `framerate` `0/1` and, when its rate is above 0 (the lower of its `max_fps` setting
  and the output's refresh), `maxFramerate` as a Range `(rate, 1/1, rate)`; on
  `param_changed` it sets `cast->framerate = max_framerate.num / denom`, and
  `wlr_screencast.c` paces with `fps_limit_measure_end(&cast->fps_limit, cast->framerate)`.
  It throttles. (It has no RemoteDesktop portal, so a Tornect host cannot use it today.)
- **libwebrtc** (Chrome, Firefox; `webrtc-sdk/webrtc` `m125_release`)
  `modules/desktop_capture/linux/wayland/screencast_stream_utils.cc` `BuildFormat`: the
  consumer adds both `framerate` and `maxFramerate` as `SPA_POD_CHOICE_RANGE_Fraction(rate,
  0/1, rate)`, against all three compositors above: the same consumer-side cap has shipped in
  the browsers for years.

**Verdict: favourable.** The capture crate asks for `maxFramerate` `[n/1, 1/1, n/1]` with
`n` = `SourceRequest.max_fps` (`quality::capture_fps`, 20 over Tor by default; from the
host's config only), held to 1 to 120 (`WaylandOptions.max_fps`, `enum_format_pod(Some(n))`);
`None` keeps the 232-byte pod of §4.3/report §4.6 byte for byte. A compositor whose refresh
is below `n` keeps its own maximum (the intersection), one that offers no `maxFramerate`
gets ours copied and fixated at `n/1`, and none of the three marks the property mandatory.
What it saves is the copy of every picture the encoder would drop (the PipeWire thread's
`pack()` per frame); encoder pacing and the ack credits bound the rate either way.
`parse_format` reads the negotiated `maxFramerate` (a fraction, plain or the first of a
Choice, from the property's own bytes; one cut short is left out without failing the format)
for the debug lines "PipeWire format negotiated" and "Wayland screen cast negotiated".
Not verified live here (no desktop in this container): GNOME on the build VM, KDE and a
wlroots compositor are `NEEDS-DEVICE` rows in `docs/VERIFICATION.md` (*Quality presets*).
Fallback if a compositor ever refuses the property: `max_fps: None` for that desktop.

---

## 5. Compatibility constraints

- **Async runtime**: ashpd `tokio` ⇒ zbus `tokio`; reis `tokio` uses `tokio::io::unix::AsyncFd` (`reis/src/tokio.rs`). Both need a live tokio runtime; `current_thread` flavour is fine (reis examples use it). Never enable ashpd `async-io` together with `tokio`.
- **enumflags2 0.7** is the shared bitflag type between ashpd (`SourceType`, `DeviceType`, `CursorMode`) and reis (`DeviceCapability`); reis re-exports it (`reis/src/lib.rs`: `pub use enumflags2;`). Lock resolved to 0.7.12.
- **rustix**: reis uses `rustix 1.x` (`features = ["event","fs","net","time"]`); pipewire's `ThreadLoop::get_time` uses `rustix::time::Timespec`. quinn-udp/tokio also use rustix 1 — one copy. No rand_core/digest/rustls/wgpu coupling in this stack (ashpd/reis/pipewire pull none of them).
- **PipeWire ABI/version gates**: `ubuntu-latest` = Ubuntu 24.04 (https://github.com/actions/runner-images README: "ubuntu-latest or ubuntu-24.04"; 26.04 is "Preview") ships `libpipewire-0.3-dev 1.0.5-1ubuntu3.3` (https://packages.ubuntu.com/noble/libpipewire-0.3-dev) → do **not** enable `v1_2_0`/`v1_6_0`; `system-deps` only checks `>= 0.3` (`pipewire-sys/Cargo.toml:46-48`) so a too-new feature fails at bindgen/compile time, not at probe time. This VM / `ubuntu-26.04` runner: pipewire 1.6.2.
- **Portal versions required**: RemoteDesktop ≥ 2 for `connect_to_eis`/persist/restore/clipboard_enabled; ScreenCast ≥ 4 for restore tokens, ≥ 5 for `mapping_id` (needed to correlate EIS regions ↔ streams on multi-monitor). Ubuntu 26.04 = RD 2 / SC 5 (probe). xdg-desktop-portal-gnome NEWS: "42.rc: Implement screencast restoration", "45.beta: Implement restoration of remote desktop sessions", "45.beta: Remote desktop: add the ability to communicate via an EIS socket", "45.beta: Implement the Clipboard portal". Mutter NEWS: "45.beta: Support input capture and emulated input with libei", "45.0: Fix input in multi-monitor remote desktop sessions with libei", "42.beta: Announce DMA-BUF support via pipewire", "42.alpha: Don't limit DMA buffer screen casting only to Intel", "46.beta: screencast: Set correct stride when using dmabufs", "50.alpha: Query screen cast format modifiers via CoglRenderer" (https://gitlab.gnome.org/GNOME/mutter/-/raw/main/NEWS). ⇒ **minimum supported GNOME for Tornect Linux host = 45** (EIS + RD restore); anything older gets the `notify_*` fallback without persistence.
- **libei protocol vs server**: reis speaks libei 1.6.0 interfaces; GNOME 50 on this VM has `libeis1 1.5.0` → `ei_text` absent; `handshake_tokio` negotiates versions so only `DeviceCapability::Text` is missing.
- **Edition 2024 / Rust 1.96**: all crates compiled (ashpd MSRV 1.87, pipewire 1.80, reis 1.71.1).

---

## 6. Build requirements (VM vs CI)

| crate | native requirement | this VM (no sudo) | GitHub Actions `ubuntu-24.04`/`26.04` |
|---|---|---|---|
| ashpd (tokio, screencast, remote_desktop, clipboard) | none (zbus over unix socket) — runtime needs a session bus + `xdg-desktop-portal` | **builds & runs** (verified) | builds; runtime tests need a portal backend (not available headless — mark portal tests `#[ignore]`) |
| reis (tokio) | none | **builds** (verified) | builds |
| pipewire / libspa (-sys) | `libpipewire-0.3.pc` + `libspa-0.2.pc` + headers, `libclang` for bindgen 0.72 (`runtime` feature = dlopen of libclang), a C compiler (`cc` for `static_fns.c` + 4 wrapper .c files, `libspa-sys/build.rs:60-80`) | **fails** at `libspa-sys` build.rs (verified: "Package libpipewire-0.3 was not found") | `sudo apt-get install -y libpipewire-0.3-dev libspa-0.2-dev libclang-dev clang pkg-config` |
| xkbcommon | `libxkbcommon.so` dev symlink (`#[link(name="xkbcommon")]`) | **link fails** (verified: `unable to find library -lxkbcommon`; only `libxkbcommon.so.0` installed) | `sudo apt-get install -y libxkbcommon-dev` |
| ashpd `wayland` feature / wayland-client (system backend) | `wayland-client.pc` (`wayland-sys/build.rs`) unless `dlopen` | not installed (`pkg-config wayland-client` fails) | `libwayland-dev` — but we don't need it in v1 |

Cargo layout consequence: keep `pipewire`/`libspa`/`xkbcommon` behind cargo features (`linux-pipewire`, `linux-xkb`) so `cargo check --workspace` stays green on this VM; the CI job `linux-full` enables them. No cmake, no nasm anywhere in this stack.

---

## 7. Behaviour when the screen is locked (sourced)

- gnome-shell `js/ui/main.js` `_sessionUpdated()` (https://gitlab.gnome.org/GNOME/gnome-shell/-/raw/main/js/ui/main.js): `if (sessionMode.allowScreencast && _remoteAccessInhibited) remoteAccessController.uninhibit_remote_access(); else if (!sessionMode.allowScreencast && !_remoteAccessInhibited) remoteAccessController.inhibit_remote_access();`
- gnome-shell `js/ui/sessionMode.js`: `restrictive` (default) has `allowScreencast: false`; `user` has `allowScreencast: true`; `unlock-dialog` and `gdm` do not override it → **false when locked**.
- mutter `src/backends/meta-remote-access-controller.c` `meta_remote_access_controller_inhibit_remote_access`: "Inhibits remote access sessions from being created and running. **Any active remote access session will be terminated.**" It calls `meta_dbus_session_manager_inhibit()` on every session manager (screen cast + remote desktop).
- mutter `src/backends/meta-dbus-session-manager.c`: on the first inhibit all existing sessions are closed; while `inhibit_count > 0` `CreateSession` fails with **"Session creation inhibited"**.
- Consequences for Tornect (GNOME): (1) the moment the host locks, the portal `Session` emits `Closed` (`session.receive_closed()`), the PipeWire stream node disappears and the EIS socket is closed — the capture/input backends must treat this as a recoverable "host locked" state, not a crash; (2) you cannot re-`Start` (even with a restore token) until the session mode returns to `user`, i.e. someone unlocks locally — **remote unlock through the portal path is impossible by design**; (3) the only ways around it are GNOME Remote Desktop's system-level RDP "Remote Login" (privileged mutter API, not portal — out of scope, cf. https://gitlab.gnome.org/GNOME/mutter/-/work_items/3494) or the third-party shell extension "Allow Locked Remote Desktop" (https://extensions.gnome.org/extension/4338/allow-locked-remote-desktop/). Document this in §A.4-style honest constraints ("Linux host must be unlocked").
- KDE/wlroots behaviour: **unverified** (KDE's portal issue tracker shows ConnectToEIS/InputCapture work at https://invent.kde.org/plasma/xdg-desktop-portal-kde/-/issues/12; lock-screen policy not checked).

---

## 8. Gotchas

1. `SelectSourcesOptions::set_sources` takes `BitFlags<SourceType>` — `BitFlags::from(SourceType::Monitor)` (probe E0277).
2. Restore tokens are single-use (both portals) — persist the **new** token from every `Start` response before reusing; a crash between `Start` and persisting the token costs one consent dialog. Store per host monitor selection (`Stream::id()` is stable across restores).
3. With a RemoteDesktop session, set `persist_mode`/`restore_token` **only** on `SelectDevicesOptions`; setting them on `SelectSourcesOptions` violates the spec ("must not be used with a remote desktop session").
4. Known xdg-desktop-portal-gnome 45 bug: restoring a multi-monitor selection could pick the wrong monitor (https://github.com/flatpak/xdg-desktop-portal/issues/1371, closed; mutter #4155 referenced). Validate `Stream::position()/size()` after restore and fall back to a fresh dialog if it mismatches the saved selection.
5. After `connect_to_eis` succeeds, never call `notify_*` (they error). Detect version with `RemoteDesktop::version() >= 2` (or catch `Error::RequiresVersion`) to choose the D-Bus fallback path.
6. libei protocol rules (from `eiproto_ei.rs` docs): `start_emulating` before the first event, `frame` after each logical event group with a CLOCK_MONOTONIC µs timestamp, at most one `motion_absolute` / one request per key per frame, don't mix `scroll` and `scroll_discrete` for the same axis in one frame, release keys before `stop_emulating`, sequence number strictly increases. `motion_absolute` outside a `Region` is **silently discarded** — map client coordinates into the region whose `mapping_id` matches the stream's `mapping_id()`.
7. All reis requests only buffer; forgetting `Context::flush()` / `Connection::flush()` means nothing is sent (both examples end their event handler with `let _ = context.flush();`).
8. pipewire-rs 0.10 `ThreadLoopBox::new` is `unsafe` with an unfinished safety doc (`thread_loop/box_.rs:24-30`); the safe, documented path is `MainLoopBox` on a dedicated std thread.
9. `pipewire::init()` is process-global; `Buffer` re-queues itself on drop — never hold a `Buffer` across the process callback (copy or dup the DMA-BUF fd with `fcntl(F_DUPFD_CLOEXEC)` if the encoder needs it beyond the callback).
10. `libspa` `property!` cannot express `Long` choices or property flags → build `Property` structs manually for the DMA-BUF modifier (`MANDATORY | DONT_FIXATE`) and for `SPA_PARAM_Buffers`/`SPA_PARAM_Meta` objects (use `spa_sys` constants).
11. `StreamProperties` in ashpd 0.13.13 ignores the v6 `pipewire-serial` key (fine — we connect by node id).
12. The VM (VMware, no GPU encoder) can only be used to test the **SHM** path and the portal/EIS plumbing; DMA-BUF with real modifiers needs CI hardware or a developer box with VA-API.
13. `pkill -f <script>` inside a Claude Bash call kills the call's own wrapper (exit 144) — irrelevant to product code, but it bit the probe run.

---

## 9. Open questions

1. Does mutter on this VMware VM (llvmpipe/vmwgfx) offer DMA-BUF formats at all, and does the SHM fallback negotiation (no-modifier pod second) work end-to-end? Needs the interactive `/tmp/probe-wayland` main flow + a pipewire build (CI or a box with headers).
2. `SPA_PARAM_Buffers.dataType` on the consumer side: upstream doc phrases it for producers; confirm mutter honours a consumer-supplied `Buffers` param or whether simply omitting it (as ashpd's example does) already yields MemFd buffers.
3. Multi-monitor: verify GNOME populates `Stream::mapping_id()` (ScreenCast v5) and `reis::event::Region::mapping_id` consistently for RemoteDesktop sessions on GNOME 50 (mutter 45.0 fixed "input in multi-monitor remote desktop sessions with libei").
4. Whether `PersistMode::ExplicitlyRevoked` on a RemoteDesktop session skips the dialog entirely on restore under xdg-desktop-portal-gnome 50 (45.beta implemented it; no regression check done).
5. KDE Plasma (xdg-desktop-portal-kde) and wlroots (xdg-desktop-portal-wlr — no RemoteDesktop at all) coverage: not researched; Tornect Linux host v1 should state "GNOME ≥ 45 or KDE Plasma 6 with ConnectToEIS" and gate on `RemoteDesktop::version()`.
6. Audio capture via PipeWire (plan D9) is a plain `Audio/Capture` stream on the default sink monitor — same crate, not researched here.
