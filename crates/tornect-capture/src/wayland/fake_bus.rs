//! A fake desktop portal on a D-Bus of its own (a private `dbus-daemon`),
//! for the tests that check, through ashpd and zbus as a session uses them,
//! which calls a portal session makes in which order, and the clipboard's
//! signals and pipes end to end. It answers `RemoteDesktop`, `ScreenCast`,
//! `Session` and (unless told not to) `Clipboard`, and records every method
//! call. The tests using it are `#[ignore]`d, since they need `dbus-daemon`:
//!
//! ```text
//! cargo test -p tornect-capture -- --ignored fake_bus
//! ```

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ashpd::zbus::zvariant::{self, ObjectPath, OwnedObjectPath, OwnedValue, Value};
use ashpd::zbus::{self, interface, message::Header};

const DESKTOP: &str = "/org/freedesktop/portal/desktop";
const CLIPBOARD: &str = "org.freedesktop.portal.Clipboard";
/// The restore token every `Start` returns.
pub(super) const FRESH_TOKEN: &str = "fresh-token";

/// How the fake answers.
#[derive(Debug, Clone)]
pub(super) struct Script {
    /// Serve the `Clipboard` interface at all.
    pub(super) has_clipboard: bool,
    /// Answer `clipboard_enabled: true` to a `Start` after `RequestClipboard`.
    pub(super) clipboard_enabled: bool,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            has_clipboard: true,
            clipboard_enabled: true,
        }
    }
}

/// What the fake saw.
#[derive(Debug, Default)]
struct Record {
    /// Method calls in order, as `Interface.Method` and what tells them apart.
    calls: Vec<String>,
    /// A `Clipboard` proxy read the interface's version (ashpd does at
    /// creation).
    clipboard_proxy: bool,
    requested_clipboard: bool,
    /// The path of the session `CreateSession` made.
    session: Option<String>,
    /// What `SelectionRead` answers.
    selection: Vec<u8>,
    /// What each paste got, by serial.
    pasted: Vec<(u32, Vec<u8>)>,
}

type Shared = Arc<Mutex<Record>>;

fn lock(shared: &Shared) -> MutexGuard<'_, Record> {
    shared.lock().unwrap()
}

fn note(shared: &Shared, call: impl Into<String>) {
    lock(shared).calls.push(call.into());
}

/// The fake portal and its bus. Dropping it stops both.
pub(super) struct FakeBus {
    /// The bus address a [`super::portal::Setup`] connects to.
    pub(super) address: String,
    shared: Shared,
    connection: zbus::Connection,
    runtime: Option<tokio::runtime::Runtime>,
    daemon: Child,
    _dir: tempfile::TempDir,
}

impl FakeBus {
    /// Start a `dbus-daemon` and the fake portal on it.
    pub(super) fn start(script: Script) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let listen = format!("unix:path={}", dir.path().join("bus").display());
        let mut daemon = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .arg(format!("--address={listen}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("dbus-daemon runs (the fake portal's tests need it on the PATH)");
        let mut line = String::new();
        BufReader::new(daemon.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let address = line.trim().to_owned();
        assert!(address.starts_with("unix:"), "{address:?}");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let shared = Shared::default();
        let connection = runtime
            .block_on(async {
                let mut builder = zbus::connection::Builder::address(address.as_str())?
                    .name("org.freedesktop.portal.Desktop")?
                    .serve_at(
                        DESKTOP,
                        Remote {
                            shared: Arc::clone(&shared),
                            script: script.clone(),
                        },
                    )?
                    .serve_at(
                        DESKTOP,
                        Cast {
                            shared: Arc::clone(&shared),
                        },
                    )?;
                if script.has_clipboard {
                    builder = builder.serve_at(
                        DESKTOP,
                        Clip {
                            shared: Arc::clone(&shared),
                        },
                    )?;
                }
                builder.build().await
            })
            .unwrap();
        Self {
            address,
            shared,
            connection,
            runtime: Some(runtime),
            daemon,
            _dir: dir,
        }
    }

    /// The method calls so far.
    pub(super) fn calls(&self) -> Vec<String> {
        lock(&self.shared).calls.clone()
    }

    /// Whether a `Clipboard` proxy was made.
    pub(super) fn clipboard_proxy(&self) -> bool {
        lock(&self.shared).clipboard_proxy
    }

    /// The path of the session the portal made.
    pub(super) fn session(&self) -> String {
        lock(&self.shared).session.clone().expect("a session")
    }

    /// What `SelectionRead` answers from now on.
    pub(super) fn select(&self, text: &str) {
        lock(&self.shared).selection = text.as_bytes().to_vec();
    }

    /// What the paste of `serial` got, once it has.
    pub(super) fn pasted(&self, serial: u32) -> Option<Vec<u8>> {
        lock(&self.shared)
            .pasted
            .iter()
            .find(|(s, _)| *s == serial)
            .map(|(_, bytes)| bytes.clone())
    }

    /// Announce a new owner of the clipboard to `session`.
    pub(super) fn owner_changed(&self, session: &str, mime_types: &[&str], session_is_owner: bool) {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("mime_types", Value::from(mime_types.to_vec()));
        options.insert("session_is_owner", Value::from(session_is_owner));
        let body = (ObjectPath::try_from(session).unwrap(), options);
        self.runtime()
            .block_on(self.connection.emit_signal(
                None::<&str>,
                DESKTOP,
                CLIPBOARD,
                "SelectionOwnerChanged",
                &body,
            ))
            .unwrap();
    }

    /// The desktop ends `session` itself (`Session.Closed`).
    pub(super) fn close_session(&self, session: &str) {
        let details: HashMap<&str, Value<'_>> = HashMap::new();
        self.runtime()
            .block_on(self.connection.emit_signal(
                None::<&str>,
                session,
                "org.freedesktop.portal.Session",
                "Closed",
                &details,
            ))
            .unwrap();
    }

    /// Someone pastes what `session` set.
    pub(super) fn transfer(&self, session: &str, mime_type: &str, serial: u32) {
        let body = (ObjectPath::try_from(session).unwrap(), mime_type, serial);
        self.runtime()
            .block_on(self.connection.emit_signal(
                None::<&str>,
                DESKTOP,
                CLIPBOARD,
                "SelectionTransfer",
                &body,
            ))
            .unwrap();
    }

    fn runtime(&self) -> &tokio::runtime::Runtime {
        self.runtime.as_ref().unwrap()
    }

    /// Wait up to 5 s for `done`, checking every 10 ms.
    pub(super) fn wait_for(&self, what: &str, mut done: impl FnMut(&Self) -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !done(self) {
            assert!(
                std::time::Instant::now() < deadline,
                "{what}: not within 5 s; calls {:?}",
                self.calls()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for FakeBus {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

/// `sender`'s unique name as portal paths spell it (`:1.42` is `1_42`).
fn sender_id(header: &Header<'_>) -> String {
    header
        .sender()
        .map(|s| s.trim_start_matches(':').replace('.', "_"))
        .unwrap_or_default()
}

fn text(options: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    match options.get(key).map(|v| &**v) {
        Some(Value::Str(s)) => Some(s.as_str().to_owned()),
        _ => None,
    }
}

/// Answer a request-style call: the `Response` of its `Request` object
/// (`results`), sent before the method's reply, which is that object's path.
async fn respond(
    connection: &zbus::Connection,
    header: &Header<'_>,
    options: &HashMap<String, OwnedValue>,
    results: HashMap<&str, Value<'_>>,
) -> zbus::fdo::Result<OwnedObjectPath> {
    let token = text(options, "handle_token").unwrap_or_default();
    let path =
        OwnedObjectPath::try_from(format!("{DESKTOP}/request/{}/{token}", sender_id(header)))
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
    connection
        .emit_signal(
            header.sender().map(|s| s.to_string()),
            &path,
            "org.freedesktop.portal.Request",
            "Response",
            &(0u32, results),
        )
        .await
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
    Ok(path)
}

fn null_fd() -> zvariant::OwnedFd {
    OwnedFd::from(std::fs::File::open("/dev/null").unwrap()).into()
}

struct Remote {
    shared: Shared,
    script: Script,
}

#[interface(name = "org.freedesktop.portal.RemoteDesktop", crate = "ashpd::zbus")]
impl Remote {
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        2
    }

    #[zbus(property)]
    fn available_device_types(&self) -> u32 {
        3
    }

    async fn create_session(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        note(&self.shared, "RemoteDesktop.CreateSession");
        let token = text(&options, "session_handle_token").unwrap_or_default();
        let session = format!("{DESKTOP}/session/{}/{token}", sender_id(&header));
        connection
            .object_server()
            .at(
                session.as_str(),
                PortalSession {
                    shared: Arc::clone(&self.shared),
                },
            )
            .await?;
        lock(&self.shared).session = Some(session.clone());
        let results = HashMap::from([("session_handle", Value::from(session))]);
        respond(connection, &header, &options, results).await
    }

    async fn select_devices(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        _session: OwnedObjectPath,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let restore = text(&options, "restore_token");
        note(
            &self.shared,
            format!("RemoteDesktop.SelectDevices restore={restore:?}"),
        );
        respond(connection, &header, &options, HashMap::new()).await
    }

    async fn start(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        _session: OwnedObjectPath,
        _parent_window: String,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        note(&self.shared, "RemoteDesktop.Start");
        let stream = HashMap::from([("size", Value::from((1280i32, 800i32)))]);
        let mut results = HashMap::from([
            ("devices", Value::from(3u32)),
            ("streams", Value::from(vec![(42u32, stream)])),
            ("restore_token", Value::from(FRESH_TOKEN)),
        ]);
        if lock(&self.shared).requested_clipboard {
            results.insert(
                "clipboard_enabled",
                Value::from(self.script.clipboard_enabled),
            );
        }
        respond(connection, &header, &options, results).await
    }

    fn notify_keyboard_keycode(
        &self,
        _session: OwnedObjectPath,
        _options: HashMap<String, OwnedValue>,
        keycode: i32,
        state: u32,
    ) {
        note(
            &self.shared,
            format!("RemoteDesktop.NotifyKeyboardKeycode {keycode} {state}"),
        );
    }
}

struct Cast {
    shared: Shared,
}

#[interface(name = "org.freedesktop.portal.ScreenCast", crate = "ashpd::zbus")]
impl Cast {
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        4
    }

    async fn select_sources(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        _session: OwnedObjectPath,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        note(&self.shared, "ScreenCast.SelectSources");
        respond(connection, &header, &options, HashMap::new()).await
    }

    fn open_pipe_wire_remote(
        &self,
        _session: OwnedObjectPath,
        _options: HashMap<String, OwnedValue>,
    ) -> zvariant::OwnedFd {
        note(&self.shared, "ScreenCast.OpenPipeWireRemote");
        null_fd()
    }
}

struct PortalSession {
    shared: Shared,
}

#[interface(name = "org.freedesktop.portal.Session", crate = "ashpd::zbus")]
impl PortalSession {
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        1
    }

    fn close(&self) {
        note(&self.shared, "Session.Close");
    }
}

struct Clip {
    shared: Shared,
}

#[interface(name = "org.freedesktop.portal.Clipboard", crate = "ashpd::zbus")]
impl Clip {
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        lock(&self.shared).clipboard_proxy = true;
        1
    }

    fn request_clipboard(&self, _session: OwnedObjectPath, _options: HashMap<String, OwnedValue>) {
        note(&self.shared, "Clipboard.RequestClipboard");
        lock(&self.shared).requested_clipboard = true;
    }

    fn set_selection(&self, _session: OwnedObjectPath, options: HashMap<String, OwnedValue>) {
        let types = match options.get("mime_types").map(|v| &**v) {
            Some(Value::Array(types)) => types
                .iter()
                .filter_map(|t| match t {
                    Value::Str(s) => Some(s.as_str().to_owned()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(","),
            _ => String::new(),
        };
        note(&self.shared, format!("Clipboard.SetSelection {types}"));
    }

    fn selection_read(&self, _session: OwnedObjectPath, mime_type: String) -> zvariant::OwnedFd {
        note(&self.shared, format!("Clipboard.SelectionRead {mime_type}"));
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(&lock(&self.shared).selection).unwrap();
        OwnedFd::from(reader).into()
    }

    fn selection_write(&self, _session: OwnedObjectPath, serial: u32) -> zvariant::OwnedFd {
        note(&self.shared, format!("Clipboard.SelectionWrite {serial}"));
        let (mut reader, writer) = std::io::pipe().unwrap();
        let shared = Arc::clone(&self.shared);
        std::thread::spawn(move || {
            let mut got = Vec::new();
            let _ = reader.read_to_end(&mut got);
            lock(&shared).pasted.push((serial, got));
        });
        OwnedFd::from(writer).into()
    }

    fn selection_write_done(&self, _session: OwnedObjectPath, serial: u32, success: bool) {
        note(
            &self.shared,
            format!("Clipboard.SelectionWriteDone {serial} {success}"),
        );
    }
}
