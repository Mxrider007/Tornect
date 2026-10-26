//! What the app gives the session services (design `services` §6.1, §8):
//! this computer's places and deny-list, the host's inbox, the viewer's
//! downloads folder, the lock watcher that pauses the services while the
//! host is locked (§2.3), and the `sessions.log` lines of what they did
//! (§2.5). The window host serves the services stream
//! ([`tornect_session::services::ServicesHost`]); the terminal host serves it
//! offering nothing (`ServicesHost::offering_nothing`: every stream answered
//! as a window host with every switch off answers it, so the port does not
//! tell the two apart), and the terminal viewer never opens it (§1).
//!
//! Nothing here logs a file name, a path or any text through `tracing`: only
//! kinds, counts and reason codes. `sessions.log` records the stored name of
//! each file received and this computer's own path of each file sent.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tornect_core::DeviceId;
use tornect_core::Paths;
use tornect_core::config::Services;
use tornect_core::files;
use tornect_core::session_log::{ServicesCounts, SessionEvent, SessionRecord};
use tornect_proto::services::{caps, reason};
use tornect_session::services::{
    Access, Direction, FreeSpaceFn, HostEvent, ServicesEnv, ServicesLimits, ServicesOutcome,
    ServicesPolicy, TransferState, ViewerClip, ViewerLocal, system_denied, tornect_denied,
};

/// How many folder names the inbox's display words keep: "Downloads ›
/// Tornect" (`Welcome.inbox`, never a path).
const INBOX_NAMES: usize = 2;

/// What a host with no Downloads folder calls its inbox (it offers no
/// uploads then, so the words are never shown as a destination).
const NO_INBOX: &str = "Downloads › Tornect";

/// The places a viewer may browse on this computer, and the folders it never
/// may (design §5.2): the user's folders (Home, Desktop, Documents,
/// Downloads) plus `/` (Linux, macOS) or each fixed drive's root
/// (Windows); never Tornect's own folders (this instance's `paths`,
/// `Paths::discover()`'s and `Paths::platform()`'s, so the platform's
/// folders are denied while `TORNECT_HOME` is in use) nor Linux's system
/// folders. The same rules judge what this computer's viewer sends.
/// Blocking: every place and denied folder is canonicalised.
pub(crate) fn access(paths: &Paths) -> Access {
    let mut places = files::user_places();
    places.extend(roots());
    let mut denied = tornect_denied(paths);
    for other in [Paths::discover(), Paths::platform()].into_iter().flatten() {
        denied.extend(tornect_denied(&other));
    }
    denied.extend(system_denied());
    Access::new(places, denied)
}

/// The roots this computer offers besides the user's folders: each fixed
/// drive on Windows (`C:`, ...), `/` elsewhere.
fn roots() -> Vec<(String, PathBuf)> {
    #[cfg(windows)]
    {
        tornect_platform::disk::drives()
            .into_iter()
            .map(|root| {
                let name = root.to_string_lossy().trim_end_matches('\\').to_owned();
                (name, root)
            })
            .collect()
    }
    #[cfg(not(windows))]
    {
        vec![("Computer".to_owned(), PathBuf::from("/"))]
    }
}

/// The free space this user may still fill on the disk of a folder
/// (`tornect_platform::disk::available`).
fn free_space() -> FreeSpaceFn {
    Arc::new(|dir: &Path| tornect_platform::disk::available(dir))
}

/// The inbox in display words: its last two folder names, such as
/// "Downloads › Tornect" (the Downloads folder's own, possibly translated,
/// name); never a path.
fn inbox_words(inbox: Option<&Path>) -> String {
    inbox.map_or_else(|| NO_INBOX.to_owned(), |dir| files::shown(dir, INBOX_NAMES))
}

/// Where the window host's services act (design §6.1): uploads land in
/// `<Downloads>/Tornect` (none without a Downloads folder), and what a viewer
/// may list and copy is [`access`]'s. Blocking ([`access`]).
pub(crate) fn host_env(paths: &Paths) -> ServicesEnv {
    let inbox = files::downloads_dir();
    ServicesEnv {
        inbox_words: inbox_words(inbox.as_deref()),
        inbox,
        free_space: free_space(),
        access: Arc::new(access(paths)),
    }
}

/// What the window's viewer works with on this computer (design §6.1):
/// downloads go to its own `<Downloads>/Tornect`, within its own
/// `[services] max_file_mib` and `keep_free_mib`; what it sends passes its
/// own [`access`]; `clip` is the stream window's clipboard (`None`: the
/// window shares none, and the host is never asked to). Blocking
/// ([`access`]).
pub(crate) fn viewer_local(paths: &Paths, cfg: &Services, clip: Option<ViewerClip>) -> ViewerLocal {
    let policy = ServicesPolicy::from_config(cfg);
    ViewerLocal {
        downloads: files::downloads_dir(),
        access: Arc::new(access(paths)),
        free_space: free_space(),
        max_file: policy.max_file,
        keep_free: policy.keep_free,
        limits: ServicesLimits::default(),
        clip,
    }
}

/// The stderr line of a services stream that bound a session and was
/// refused before any service (`Refused{reason}`): its session and the
/// reason's name, nothing of the peer. A stream that never bound is not
/// told (any peer can open one; the services host rate-limits its own
/// lines), and one that was served is told by its observer.
#[must_use]
pub(crate) fn describe_outcome(outcome: &ServicesOutcome) -> Option<String> {
    match outcome {
        ServicesOutcome::Refused { session_id, reason } => Some(format!(
            "chat and files were not opened for session {session_id} ({})",
            reason_name(*reason)
        )),
        ServicesOutcome::NotBound | ServicesOutcome::Served { .. } => None,
    }
}

// --- The lock watcher (design §2.3) -----------------------------------------

/// How often the lock is read while a services stream is open.
pub(crate) const LOCK_EVERY: Duration = Duration::from_secs(1);

/// How long a host whose lock source could not be found waits before it
/// looks for one again.
#[cfg(target_os = "linux")]
const FIND_AGAIN: Duration = Duration::from_secs(30);

/// Where the host reads whether it is locked: `None` when that could not
/// be read this time (it then changes nothing).
pub(crate) trait LockSource: Send {
    /// One reading.
    fn read(&mut self) -> impl Future<Output = Option<bool>> + Send;
}

/// Read `source` every `every` while `open()` says a services stream is
/// open, and hand each change to `set` (`ServicesHost::set_locked`): a host
/// starts unlocked, and a reading that could not be taken changes nothing
/// (`tornect_platform::lock::LockWatch`). Nothing is read while no stream
/// is open. Runs until dropped.
pub(crate) async fn watch_lock<L, O, S>(mut source: L, open: O, set: S, every: Duration)
where
    L: LockSource,
    O: Fn() -> usize,
    S: Fn(bool),
{
    let mut watch = tornect_platform::lock::LockWatch::new();
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if open() == 0 {
            continue;
        }
        if let Some(locked) = watch.read(source.read().await) {
            tracing::info!(locked, "the services follow the host's lock");
            set(locked);
        }
    }
}

/// This computer's lock: logind's `LockedHint` on Linux (found once, looked
/// for again every [`FIND_AGAIN`] while it cannot be had), the secure
/// desktop on Windows, nothing elsewhere.
#[derive(Default)]
pub(crate) struct SystemLock {
    #[cfg(target_os = "linux")]
    hint: Option<tornect_platform::lock::LockedHint>,
    #[cfg(target_os = "linux")]
    looked: Option<tokio::time::Instant>,
}

impl LockSource for SystemLock {
    async fn read(&mut self) -> Option<bool> {
        #[cfg(target_os = "linux")]
        {
            let due = self.looked.is_none_or(|at| at.elapsed() >= FIND_AGAIN);
            if self.hint.is_none() && due {
                self.looked = Some(tokio::time::Instant::now());
                self.hint = tornect_platform::lock::LockedHint::connect().await;
            }
            match &self.hint {
                Some(hint) => hint.read().await,
                None => None,
            }
        }
        #[cfg(windows)]
        {
            tokio::task::spawn_blocking(tornect_platform::lock::locked_now)
                .await
                .ok()
                .flatten()
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            None
        }
    }
}

// --- sessions.log (design §2.5, §8) -----------------------------------------

/// A reason code as `sessions.log` and the evidence lines name it.
#[must_use]
pub(crate) fn reason_name(code: u16) -> &'static str {
    match code {
        reason::BAD_BIND => "bad_bind",
        reason::NOT_OFFERED => "not_offered",
        reason::TOO_LARGE => "too_large",
        reason::QUOTA => "quota",
        reason::NO_SPACE => "no_space",
        reason::BUSY => "busy",
        reason::BAD_NAME => "bad_name",
        reason::NOT_FOUND => "not_found",
        reason::DENIED => "denied",
        reason::NOT_A_FILE => "not_a_file",
        reason::IO => "io",
        reason::CORRUPT => "corrupt",
        reason::CHANGED => "changed",
        reason::BY_HOST => "by_host",
        reason::BY_VIEWER => "by_viewer",
        reason::SESSION_OVER => "session_over",
        reason::PROTOCOL => "protocol",
        reason::TURNED_OFF => "turned_off",
        reason::ENDED_BY_HOST => "ended_by_host",
        reason::LOCKED => "locked",
        reason::CAPTURE_STOPPED => "capture_stopped",
        reason::NOT_LIVE => "not_live",
        _ => "unknown",
    }
}

/// The caps a host user can turn off, as `services_turned_off` names them
/// (the `[services]` keys), in a fixed order and joined by commas; chat is
/// never turned off (design §2.5).
#[must_use]
pub(crate) fn turned_off_names(off: u16) -> String {
    [
        (caps::CLIP, "clipboard"),
        (caps::UPLOAD, "receive_files"),
        (caps::BROWSE, "browse_files"),
    ]
    .into_iter()
    .filter(|(cap, _)| off & cap != 0)
    .map(|(_, name)| name)
    .collect::<Vec<_>>()
    .join(",")
}

/// The peer of a session, for its services lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Peer {
    /// The session.
    pub session_id: String,
    /// Its device.
    pub device: DeviceId,
    /// Its pinned label.
    pub label: String,
}

/// The peers of the sessions served lately, by session id: a services
/// stream can report after its session ended (its summary, a file whose
/// rename outlasted the stream's end), so a few ended ones are kept.
#[derive(Debug, Default)]
pub(crate) struct Peers(Mutex<Vec<Peer>>);

/// Sessions whose peer is kept (one is served at a time).
const PEERS_KEPT: usize = 8;

impl Peers {
    /// Session `peer.session_id` started.
    pub(crate) fn started(&self, peer: Peer) {
        let mut peers = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        peers.retain(|p| p.session_id != peer.session_id);
        peers.push(peer);
        let extra = peers.len().saturating_sub(PEERS_KEPT);
        peers.drain(..extra);
    }

    /// The peer of session `session_id`, if it is kept.
    pub(crate) fn of(&self, session_id: &str) -> Option<Peer> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|p| p.session_id == session_id)
            .cloned()
    }
}

/// A record of session `session_id` with its peer, when known.
fn record(event: SessionEvent, session_id: &str, peer: Option<&Peer>) -> SessionRecord {
    let record = SessionRecord::now(event).session(session_id);
    match peer {
        Some(peer) => record.peer(peer.device, peer.label.clone()),
        None => record,
    }
}

/// The `sessions.log` line `event` of session `session_id` makes, if any
/// (design §2.5, §8): `file_received` for a file the viewer sent once it is
/// in place (its stored, sanitised name and size, never the folder),
/// `file_sent` for a file the viewer copied whole (this computer's path and
/// size), `services_summary` at the stream's end (counts and its reason
/// only). Chat, the clipboard, caps and rows that did not end in place make
/// none.
#[must_use]
pub(crate) fn log_record(
    session_id: &str,
    peer: Option<&Peer>,
    event: &HostEvent,
) -> Option<SessionRecord> {
    match event {
        HostEvent::Transfer(row) => match (&row.dir, &row.state) {
            (Direction::ToHost, TransferState::Done { stored }) => Some(
                record(SessionEvent::FileReceived, session_id, peer)
                    .path(stored.as_str())
                    .bytes(row.size),
            ),
            _ => None,
        },
        HostEvent::FileSent { path, bytes, .. } => Some(
            record(SessionEvent::FileSent, session_id, peer)
                .path(path.as_path().to_string_lossy())
                .bytes(*bytes),
        ),
        HostEvent::Closed { reason, summary } => {
            let counts = ServicesCounts {
                clip_in: summary.clip_in,
                clip_out: summary.clip_out,
                files_in: summary.files_in,
                bytes_in: summary.bytes_in,
                files_out: summary.files_out,
                bytes_out: summary.bytes_out,
                chat_in: summary.chat_in,
                chat_out: summary.chat_out,
            };
            Some(
                record(SessionEvent::ServicesSummary, session_id, peer)
                    .reason(reason_name(*reason))
                    .detail(counts.detail()),
            )
        }
        HostEvent::Opened { .. }
        | HostEvent::Caps { .. }
        | HostEvent::Chat(_)
        | HostEvent::ClipIn { .. }
        | HostEvent::ClipOut { .. } => None,
    }
}

/// The `services_turned_off` line of the host user turning `off` off for
/// session `session_id` (written where the turn-off is asked for: the
/// stream raises no event of its own for it).
#[must_use]
pub(crate) fn turned_off_record(session_id: &str, peer: Option<&Peer>, off: u16) -> SessionRecord {
    record(SessionEvent::ServicesTurnedOff, session_id, peer).op(turned_off_names(off))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tornect_core::session_log::SessionLog;
    use tornect_session::services::{ServicesSummary, TransferRow, Untrusted};

    use super::*;

    /// Readings from a script; each one counted.
    struct Scripted {
        readings: VecDeque<Option<bool>>,
        read: Arc<AtomicUsize>,
    }

    impl LockSource for Scripted {
        async fn read(&mut self) -> Option<bool> {
            self.read.fetch_add(1, Ordering::SeqCst);
            self.readings.pop_front().flatten()
        }
    }

    /// Design §2.3 and the step 19 obligation: the watcher hands
    /// `set_locked` each change of the readings and nothing else: an
    /// unreadable reading keeps the last state (locked or not), the same
    /// reading twice is one change, and a host starts unlocked.
    #[tokio::test(start_paused = true)]
    async fn the_lock_watcher_hands_on_changes_of_real_readings_only() {
        let read = Arc::new(AtomicUsize::new(0));
        let source = Scripted {
            readings: [
                None,
                Some(false),
                Some(true),
                None,
                Some(true),
                Some(false),
                None,
                Some(false),
                Some(true),
            ]
            .into(),
            read: Arc::clone(&read),
        };
        let set = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&set);
        let task = tokio::spawn(watch_lock(
            source,
            || 1,
            move |locked| seen.lock().unwrap().push(locked),
            LOCK_EVERY,
        ));
        tokio::time::sleep(LOCK_EVERY * 12).await;
        task.abort();
        assert_eq!(*set.lock().unwrap(), [true, false, true]);
        assert!(read.load(Ordering::SeqCst) >= 9, "one reading a second");
    }

    /// Nothing is read while no services stream is open, and reading starts
    /// once one opens.
    #[tokio::test(start_paused = true)]
    async fn the_lock_is_read_only_while_a_stream_is_open() {
        let read = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicUsize::new(0));
        let source = Scripted {
            readings: [Some(true); 64].into(),
            read: Arc::clone(&read),
        };
        let set = Arc::new(Mutex::new(Vec::new()));
        let (seen, streams) = (Arc::clone(&set), Arc::clone(&open));
        let task = tokio::spawn(watch_lock(
            source,
            move || streams.load(Ordering::SeqCst),
            move |locked| seen.lock().unwrap().push(locked),
            LOCK_EVERY,
        ));
        tokio::time::sleep(LOCK_EVERY * 5).await;
        assert_eq!(read.load(Ordering::SeqCst), 0, "no stream, no reading");
        assert!(set.lock().unwrap().is_empty());
        open.store(1, Ordering::SeqCst);
        tokio::time::sleep(LOCK_EVERY * 3).await;
        task.abort();
        assert!(read.load(Ordering::SeqCst) >= 2);
        assert_eq!(*set.lock().unwrap(), [true]);
    }

    fn peer() -> Peer {
        Peer {
            session_id: "abcd".to_owned(),
            device: DeviceId::from_bytes([3; 32]),
            label: "Laptop".to_owned(),
        }
    }

    fn row(dir: Direction, state: TransferState) -> TransferRow {
        TransferRow {
            xfer: 7,
            dir,
            name: Untrusted::file_name("../../report.pdf"),
            size: 12_345,
            done: 12_345,
            state,
        }
    }

    /// Design §8 and §10 (`apps/tornect`): a file the viewer sent is
    /// recorded once it is in place, under its stored, sanitised name and
    /// its size, never a folder of this computer; nothing else of a
    /// transfer, nor chat, the clipboard or caps, is written.
    #[test]
    fn a_received_file_is_logged_by_its_stored_name_only() {
        let dir = tempfile::tempdir().unwrap();
        let log = SessionLog::new(dir.path().join("sessions.log"));
        let peer = peer();
        let stored = Untrusted::file_name("report (2).pdf");
        let done = HostEvent::Transfer(row(
            Direction::ToHost,
            TransferState::Done {
                stored: stored.clone(),
            },
        ));
        let record = log_record("abcd", Some(&peer), &done).expect("a received file is logged");
        log.append(&record).unwrap();
        let line = log.read_lines().unwrap().remove(0);
        assert!(line.contains(r#""event":"file_received""#), "{line}");
        assert!(line.contains(r#""path":"report (2).pdf""#), "{line}");
        assert!(line.contains(r#""detail":"12345 bytes""#), "{line}");
        assert!(line.contains(r#""peer_name":"Laptop""#), "{line}");
        assert!(!line.contains("Downloads") && !line.contains('/'), "{line}");
        for quiet in [
            HostEvent::Transfer(row(Direction::ToHost, TransferState::Running)),
            HostEvent::Transfer(row(Direction::ToHost, TransferState::Stalled)),
            HostEvent::Transfer(row(
                Direction::ToHost,
                TransferState::Failed(reason::CORRUPT),
            )),
            HostEvent::Transfer(row(
                Direction::ToHost,
                TransferState::Cancelled(reason::BY_HOST),
            )),
            HostEvent::Transfer(row(
                Direction::FromHost,
                TransferState::Done {
                    stored: stored.clone(),
                },
            )),
            HostEvent::Opened {
                caps: caps::CHAT,
                input: false,
                clipboard_refused: false,
            },
            HostEvent::Caps { caps: 1, paused: 0 },
            HostEvent::ClipIn { chars: 3 },
            HostEvent::ClipOut { chars: 3 },
        ] {
            assert!(
                log_record("abcd", Some(&peer), &quiet).is_none(),
                "{quiet:?}"
            );
        }
    }

    /// Design `services` §8: a file this computer sent is logged with its
    /// path on this computer (the host user's own file) and its size; a
    /// line whose session's peer is no longer known still names the session.
    #[test]
    fn a_sent_file_is_logged_by_its_path_on_this_computer() {
        let dir = tempfile::tempdir().unwrap();
        let log = SessionLog::new(dir.path().join("sessions.log"));
        let sent = HostEvent::FileSent {
            xfer: 3,
            path: tornect_session::services::HostPath::new(
                ["home", "u", "plan.odt"].iter().collect(),
            ),
            bytes: 2048,
        };
        let peer = peer();
        for known in [Some(&peer), None] {
            let record = log_record("abcd", known, &sent).expect("a sent file is logged");
            log.append(&record).unwrap();
        }
        let lines = log.read_lines().unwrap();
        let path: PathBuf = ["home", "u", "plan.odt"].iter().collect();
        let path = serde_json::to_string(&path.to_string_lossy()).unwrap();
        for line in &lines {
            assert!(line.contains(r#""event":"file_sent""#), "{line}");
            assert!(line.contains(&format!(r#""path":{path}"#)), "{line}");
            assert!(line.contains(r#""detail":"2048 bytes""#), "{line}");
            assert!(line.contains(r#""session_id":"abcd""#), "{line}");
        }
        assert!(lines[0].contains(r#""peer_name":"Laptop""#), "{}", lines[0]);
        assert!(!lines[1].contains("peer_name"), "{}", lines[1]);
    }

    /// The summary line holds counts and the reason's name, nothing else;
    /// the turn-off line names what was turned off by its `[services]` key.
    #[test]
    fn the_summary_and_the_turn_off_lines_hold_no_text() {
        let peer = peer();
        let summary = ServicesSummary {
            clip_in: 1,
            files_in: 2,
            bytes_in: 300,
            chat_in: 4,
            ..ServicesSummary::default()
        };
        let closed = HostEvent::Closed {
            reason: reason::CAPTURE_STOPPED,
            summary,
        };
        let line =
            serde_json::to_string(&log_record("abcd", Some(&peer), &closed).unwrap()).unwrap();
        assert!(line.contains(r#""event":"services_summary""#), "{line}");
        assert!(line.contains(r#""reason":"capture_stopped""#), "{line}");
        assert!(
            line.contains(
                r#""detail":"clip_in=1 clip_out=0 files_in=2 bytes_in=300 files_out=0 bytes_out=0 chat_in=4 chat_out=0""#
            ),
            "{line}"
        );
        let off = serde_json::to_string(&turned_off_record(
            "abcd",
            None,
            caps::CLIP | caps::UPLOAD | caps::BROWSE,
        ))
        .unwrap();
        assert!(off.contains(r#""event":"services_turned_off""#), "{off}");
        assert!(
            off.contains(r#""op":"clipboard,receive_files,browse_files""#),
            "{off}"
        );
        assert_eq!(turned_off_names(caps::BROWSE | caps::CHAT), "browse_files");
        assert_eq!(turned_off_names(caps::CHAT), "");
        for code in 1..=22 {
            assert_ne!(reason_name(code), "unknown", "{code}");
        }
        assert_eq!(reason_name(999), "unknown");
    }

    /// The peers of ended sessions are kept for their late lines, a few at
    /// most.
    #[test]
    fn the_peers_of_a_few_sessions_are_kept() {
        let peers = Peers::default();
        for n in 0..12u8 {
            peers.started(Peer {
                session_id: format!("s{n}"),
                device: DeviceId::from_bytes([n; 32]),
                label: format!("Device {n}"),
            });
        }
        assert!(peers.of("s0").is_none());
        assert_eq!(peers.of("s11").unwrap().label, "Device 11");
        assert_eq!(peers.of("s4").unwrap().label, "Device 4");
    }

    /// The deny-list holds this instance's Tornect folders: nothing of its
    /// home is listed or sent, and the inbox's words are folder names, not a
    /// path.
    #[test]
    fn this_computers_access_denies_its_own_tornect_home() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().join("home"));
        paths.ensure().unwrap();
        let access = access(&paths);
        let key = paths.state_dir.join("device.key");
        std::fs::write(&key, b"secret").unwrap();
        assert_eq!(access.check(&key), Err(reason::DENIED));
        assert_eq!(access.check(&paths.config_dir), Err(reason::DENIED));
        let words = inbox_words(Some(Path::new("/home/someone/Downloads/Tornect")));
        assert_eq!(words, "Downloads › Tornect");
        assert_eq!(inbox_words(None), NO_INBOX);
    }
}
