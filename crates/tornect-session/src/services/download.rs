//! The download protocol, both ends (the services design §3.5): the viewer
//! copies a file of the host's.
//!
//! 1. The viewer sends `Get{xfer, handle}` with a file's handle from a
//!    `Listing`. The host checks, in order, that browsing is not paused
//!    (`LOCKED`), that fewer than [`MAX_DOWNLOADS`] hold a place (`BUSY`),
//!    and that the handle names a path (`NOT_FOUND` for one unknown or
//!    evicted, `NOT_A_FILE` for the places'); then, on a blocking thread and
//!    within `read_timeout` (`IO` past it), [`open_file`] judges the path by
//!    the host's [`Access`] and opens the canonical one read-only
//!    (`DENIED`, `NOT_FOUND`, `NOT_A_FILE`, `IO`), and the file must be
//!    within the host's largest (`TOO_LARGE`). The host answers
//!    `Sending{xfer, name, size}` or `Cancel{xfer, reason}`.
//! 2. The host sends exactly `size` bytes as contiguous `Data` within the
//!    bulk window, each chunk read within `read_timeout` (`Cancel{IO}` past
//!    it, the read abandoned), then `Done{sha256}`; a file whose length
//!    changed while it was read is `Cancel{CHANGED}`. The viewer writes what
//!    arrives on its receiving worker, into its downloads folder through the
//!    same inbox as the host's (`super::store`: a reserved name, a private
//!    part file, on Windows the mark of the web, this computer's own largest
//!    file and free-space floor), and credits what it wrote.
//! 3. The viewer checks the length and the hash, puts the file in place and
//!    answers `Complete`, or `Cancel{CORRUPT}` and deletes it. The host
//!    counts a file sent only when the viewer credited all of it and then
//!    said `Complete`, and then tells it ([`HostEvent::FileSent`]: the
//!    `file_sent` record of `sessions.log`).
//! 4. Either end may `Cancel` at any point; the viewer deletes what it
//!    wrote.
//!
//! While the host is locked (§2.3) downloads stall instead of failing: its
//! window is paused, so no more `Data` goes out until it is unlocked; their
//! rows say `Stalled`. A file still opening at the lock is refused once
//! open (`Cancel{LOCKED}`). The viewer fails the `Get`s still unanswered
//! with `LOCKED` (the host may have skipped them unread), answers a
//! `Sending` that still comes for one of them with `Cancel`, and holds its
//! queued files until the host is unlocked.
//!
//! An open abandoned at its timeout (a path swapped for a pipe between the
//! check and the open, design §5.2) holds its place until its thread
//! returns. The viewer runs at most [`MAX_DOWNLOADS`] downloads and queues
//! the others. Nothing here logs a file name or a path.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tornect_proto::services::{Cancel, Complete, Done, Get, Sending, SvcMsg, reason};

use super::browse::{Access, open_file};
use super::store::{Fed, Inbox, Receiving, Work, Worked, WorkerEvent, spawn_receiver};
use super::transfer::{
    Abandoned, Direction, HostPath, Ids, MAX_DOWNLOADS, Outgoing, SendFailed, TransferRow,
    TransferState, Untrusted, ViewerShared, late,
};
use super::window::{Inflow, Window};
use super::writer::Outbox;
use super::{HostEvent, ServicesObserver, ViewerEvent};

// --- The host's end ----------------------------------------------------------

/// An open running.
const OPENING: u8 = 0;
/// The open returned.
const RETURNED: u8 = 1;
/// The open was given up (its timeout, or its download stopped) while its
/// thread still ran: the thread holds a place until it returns.
const ABANDONED: u8 = 2;

/// Called on each open's blocking thread before the file is opened (tests
/// only).
#[cfg(test)]
pub(crate) type OpenHook = Arc<dyn Fn() + Send + Sync>;

/// One open of a file to send, on a blocking thread.
#[derive(Debug)]
struct Open {
    state: Arc<AtomicU8>,
    abandoned: Arc<AtomicUsize>,
}

impl Open {
    /// Give the open up: from now until its thread returns, that thread
    /// counts among the abandoned ones.
    fn abandon(&self) {
        abandon(&self.state, &self.abandoned);
    }
}

fn abandon(state: &AtomicU8, abandoned: &AtomicUsize) {
    abandoned.fetch_add(1, Ordering::SeqCst);
    if state
        .compare_exchange(OPENING, ABANDONED, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        abandoned.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Marks its open returned when the thread ends, however it ends.
struct Returned {
    state: Arc<AtomicU8>,
    abandoned: Arc<AtomicUsize>,
}

impl Drop for Returned {
    fn drop(&mut self) {
        if self
            .state
            .compare_exchange(OPENING, RETURNED, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.abandoned.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Where one of the host's downloads stands.
enum Phase {
    /// The file is being opened.
    Opening(Open),
    /// `Sending` went out: the file is being sent (dropping the
    /// [`Outgoing`] stops it), from this canonical path.
    Sending {
        #[expect(dead_code, reason = "held for its drop, which stops the sending")]
        out: Outgoing,
        path: PathBuf,
    },
}

/// One of the host's downloads.
struct Down {
    name: Untrusted,
    size: u64,
    credited: u64,
    phase: Phase,
}

/// What an open reports.
#[derive(Debug)]
pub(crate) struct Opened {
    xfer: u32,
    result: Result<(File, u64, PathBuf), u16>,
}

/// What the host's opens and sending tasks report to its loop.
pub(crate) struct HostDownloadReports {
    /// Files opened, or why not.
    pub(crate) opened: mpsc::UnboundedReceiver<Opened>,
    /// Sending tasks that failed.
    pub(crate) failed: mpsc::UnboundedReceiver<SendFailed>,
}

/// The host's downloads on one services stream.
pub(crate) struct HostDownloads {
    session_id: String,
    access: Arc<Access>,
    observer: Arc<dyn ServicesObserver>,
    outbox: Outbox,
    window: Arc<Window>,
    ids: Ids,
    file_max: u64,
    chunk: usize,
    read_timeout: Duration,
    running: HashMap<u32, Down>,
    /// Opens given up whose threads still run.
    abandoned: Arc<AtomicUsize>,
    opened: mpsc::UnboundedSender<Opened>,
    failed: mpsc::UnboundedSender<SendFailed>,
    /// The host is locked: its window is paused.
    paused: bool,
    #[cfg(test)]
    hook: Option<OpenHook>,
    /// Files the viewer completed, and their bytes.
    pub(crate) files_out: u32,
    pub(crate) bytes_out: u64,
}

/// What the host's downloads on one stream are made of.
pub(crate) struct HostDownloadParts {
    pub(crate) session_id: String,
    pub(crate) access: Arc<Access>,
    pub(crate) observer: Arc<dyn ServicesObserver>,
    pub(crate) outbox: Outbox,
    /// The host's sending window.
    pub(crate) window: Arc<Window>,
    /// The stream's transfer ids, shared with its uploads.
    pub(crate) ids: Ids,
    /// The largest file sent (`Welcome.file_max`).
    pub(crate) file_max: u64,
    pub(crate) chunk: usize,
    pub(crate) read_timeout: Duration,
    /// Called by each open before it opens the file (tests only).
    #[cfg(test)]
    pub(crate) hook: Option<OpenHook>,
}

impl HostDownloads {
    /// The downloads of a stream made of `parts`; what the opens and the
    /// sending tasks report comes on the receivers returned.
    pub(crate) fn new(parts: HostDownloadParts) -> (Self, HostDownloadReports) {
        let HostDownloadParts {
            session_id,
            access,
            observer,
            outbox,
            window,
            ids,
            file_max,
            chunk,
            read_timeout,
            #[cfg(test)]
            hook,
        } = parts;
        let (opened, opened_rx) = mpsc::unbounded_channel();
        let (failed, failed_rx) = mpsc::unbounded_channel();
        (
            Self {
                session_id,
                access,
                observer,
                outbox,
                window,
                ids,
                file_max,
                chunk: chunk.max(1),
                read_timeout,
                running: HashMap::new(),
                abandoned: Arc::new(AtomicUsize::new(0)),
                opened,
                failed,
                paused: false,
                #[cfg(test)]
                hook,
                files_out: 0,
                bytes_out: 0,
            },
            HostDownloadReports {
                opened: opened_rx,
                failed: failed_rx,
            },
        )
    }

    /// The places taken: downloads running, and opens given up whose
    /// threads still run.
    fn places(&self) -> usize {
        self.running.len() + self.abandoned.load(Ordering::SeqCst)
    }

    /// The viewer's `Get` of the file whose handle names `path` (`None`: an
    /// unknown or evicted handle); `paused` while a lock pauses browsing.
    /// `Err` with the `Close` reason.
    pub(crate) fn get(&mut self, get: Get, path: Option<PathBuf>, paused: bool) -> Result<(), u16> {
        let Get { xfer, handle } = get;
        if !self.ids.fresh(xfer) {
            return Err(reason::PROTOCOL);
        }
        let refused = if paused {
            Err(reason::LOCKED)
        } else if self.places() >= MAX_DOWNLOADS {
            Err(reason::BUSY)
        } else if handle == 0 {
            Err(reason::NOT_A_FILE)
        } else {
            path.ok_or(reason::NOT_FOUND)
        };
        let path = match refused {
            Ok(path) => path,
            Err(code) => {
                self.ids.end(xfer);
                tracing::debug!(session = %self.session_id, reason = code, "a download was refused");
                return self.ctrl(SvcMsg::Cancel(Cancel { xfer, reason: code }));
            }
        };
        let state = Arc::new(AtomicU8::new(OPENING));
        let returned = Returned {
            state: Arc::clone(&state),
            abandoned: Arc::clone(&self.abandoned),
        };
        let access = Arc::clone(&self.access);
        #[cfg(test)]
        let hook = self.hook.clone();
        let job = tokio::task::spawn_blocking(move || {
            let _returned = returned;
            #[cfg(test)]
            if let Some(hook) = hook {
                hook();
            }
            open_file(&access, &path)
        });
        let (opened, timeout) = (self.opened.clone(), self.read_timeout);
        let (shared, abandoned) = (Arc::clone(&state), Arc::clone(&self.abandoned));
        tokio::spawn(async move {
            let result = match tokio::time::timeout(timeout, job).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(reason::IO),
                Err(_) => {
                    abandon(&shared, &abandoned);
                    Err(reason::IO)
                }
            };
            let _ = opened.send(Opened { xfer, result });
        });
        self.running.insert(
            xfer,
            Down {
                name: Untrusted::file_name(""),
                size: 0,
                credited: 0,
                phase: Phase::Opening(Open {
                    state,
                    abandoned: Arc::clone(&self.abandoned),
                }),
            },
        );
        Ok(())
    }

    /// An open's report: `Sending`, and the file goes; or `Cancel`.
    pub(crate) fn on_opened(&mut self, opened: Opened) -> Result<(), u16> {
        let Opened { xfer, result } = opened;
        if !matches!(
            self.running.get(&xfer).map(|down| &down.phase),
            Some(Phase::Opening(_))
        ) {
            // Stopped meanwhile: the file closes here.
            return Ok(());
        }
        let opened = match result {
            // Asked for before a lock, which the viewer gave up: nothing is
            // sent while the host is locked.
            Ok(_) if self.paused => Err(reason::LOCKED),
            Ok((_, size, _)) if size > self.file_max => Err(reason::TOO_LARGE),
            other => other,
        };
        let (file, size, path) = match opened {
            Ok(opened) => opened,
            Err(code) => {
                // Refused before anything was sent: no row.
                self.running.remove(&xfer);
                self.ids.end(xfer);
                tracing::debug!(session = %self.session_id, reason = code, "a download was refused");
                return self.ctrl(SvcMsg::Cancel(Cancel { xfer, reason: code }));
            }
        };
        let raw = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = Untrusted::file_name(&raw);
        self.ctrl(SvcMsg::Sending(Sending {
            xfer,
            name: name.as_str().to_owned(),
            size,
        }))?;
        self.window.open(xfer);
        let out = Outgoing::start(
            xfer,
            file,
            size,
            self.chunk,
            Arc::clone(&self.window),
            self.outbox.clone(),
            self.read_timeout,
            self.failed.clone(),
        );
        let down = Down {
            name,
            size,
            credited: 0,
            phase: Phase::Sending { out, path },
        };
        self.tell(row(xfer, &down, TransferState::Running));
        self.running.insert(xfer, down);
        Ok(())
    }

    /// The viewer's `Credit` of a download.
    pub(crate) fn credit(&mut self, xfer: u32, upto: u64) -> Result<(), u16> {
        let Some(down) = self.running.get_mut(&xfer) else {
            return late(&self.ids, xfer);
        };
        if !matches!(down.phase, Phase::Sending { .. }) {
            return Err(reason::PROTOCOL);
        }
        self.window
            .credit(xfer, upto)
            .map_err(|_| reason::PROTOCOL)?;
        down.credited = upto;
        let row = row(xfer, down, TransferState::moving(self.paused));
        self.tell(row);
        Ok(())
    }

    /// The host is locked (`true`; the stream pauses its window, so no more
    /// `Data` goes out) or unlocked: the rows of the files being sent say
    /// `Stalled`, or `Running` again.
    pub(crate) fn set_paused(&mut self, paused: bool) {
        if self.paused == paused {
            return;
        }
        self.paused = paused;
        let mut xfers: Vec<u32> = self.running.keys().copied().collect();
        xfers.sort_unstable();
        for xfer in xfers {
            let down = &self.running[&xfer];
            if matches!(down.phase, Phase::Sending { .. }) {
                self.tell(row(xfer, down, TransferState::moving(paused)));
            }
        }
    }

    /// The viewer's `Complete`: the file is in place there. Only a file the
    /// viewer credited whole is complete.
    pub(crate) fn complete(&mut self, complete: Complete) -> Result<(), u16> {
        let xfer = complete.xfer;
        let Some(down) = self.running.get(&xfer) else {
            return late(&self.ids, xfer);
        };
        if !matches!(down.phase, Phase::Sending { .. }) || down.credited != down.size {
            return Err(reason::PROTOCOL);
        }
        let Some(down) = self.running.remove(&xfer) else {
            return Err(reason::PROTOCOL);
        };
        self.ids.end(xfer);
        self.window.release(xfer);
        self.files_out = self.files_out.saturating_add(1);
        self.bytes_out = self.bytes_out.saturating_add(down.size);
        tracing::info!(session = %self.session_id, bytes = down.size, "a file was sent");
        let mut done = row(
            xfer,
            &down,
            TransferState::Done {
                stored: down.name.clone(),
            },
        );
        done.done = down.size;
        self.tell(done);
        if let Phase::Sending { path, .. } = down.phase {
            self.observer.event(
                &self.session_id,
                HostEvent::FileSent {
                    xfer,
                    path: HostPath::new(path),
                    bytes: down.size,
                },
            );
        }
        Ok(())
    }

    /// The viewer's `Cancel` of a download; `Ok(false)` when it names none.
    pub(crate) fn cancelled(&mut self, cancel: Cancel) -> Result<bool, u16> {
        // The viewer's own reasons (its disk, its check, its stop); anything
        // else counts as its stop.
        let code = match cancel.reason {
            reason::NO_SPACE
            | reason::CORRUPT
            | reason::TOO_LARGE
            | reason::IO
            | reason::BAD_NAME
            | reason::QUOTA => cancel.reason,
            _ => reason::BY_VIEWER,
        };
        Ok(self.end(cancel.xfer, code))
    }

    /// A sending task failed (`CHANGED`, `IO`): the viewer hears `Cancel`.
    pub(crate) fn send_failed(&mut self, failed: SendFailed) -> Result<(), u16> {
        if !self.running.contains_key(&failed.xfer) {
            return Ok(());
        }
        tracing::debug!(session = %self.session_id, reason = failed.reason, "a download failed");
        // Queued before the window is released, so that no byte another
        // download sends in its room reaches the viewer before it.
        self.ctrl(SvcMsg::Cancel(Cancel {
            xfer: failed.xfer,
            reason: failed.reason,
        }))?;
        self.end(failed.xfer, failed.reason);
        Ok(())
    }

    /// The host's user, or the end of browsing (`TURNED_OFF`), stops
    /// download `xfer`, telling the viewer: `Ok(false)` when no such
    /// download runs.
    pub(crate) fn cancel(&mut self, xfer: u32, code: u16) -> Result<bool, u16> {
        if !self.running.contains_key(&xfer) {
            return Ok(false);
        }
        self.ctrl(SvcMsg::Cancel(Cancel { xfer, reason: code }))?;
        self.end(xfer, code);
        Ok(true)
    }

    /// Stop every download with `code`, telling the viewer.
    pub(crate) fn cancel_all(&mut self, code: u16) -> Result<(), u16> {
        let mut xfers: Vec<u32> = self.running.keys().copied().collect();
        xfers.sort_unstable();
        for xfer in xfers {
            self.cancel(xfer, code)?;
        }
        Ok(())
    }

    /// The stream ends with `code`: every download stops, and nothing is
    /// sent.
    pub(crate) fn stop(&mut self, code: u16) {
        let xfers: Vec<u32> = self.running.keys().copied().collect();
        for xfer in xfers {
            self.end(xfer, code);
        }
    }

    /// Download `xfer` ended with `code`: its sending stops (or its open is
    /// given up), its window is released, and the host's user is told, if it
    /// had begun. `false` when no such download runs.
    fn end(&mut self, xfer: u32, code: u16) -> bool {
        let Some(down) = self.running.remove(&xfer) else {
            return false;
        };
        self.ids.end(xfer);
        self.window.release(xfer);
        match &down.phase {
            Phase::Opening(open) => open.abandon(),
            Phase::Sending { .. } => self.tell(row(xfer, &down, TransferState::ended(code))),
        }
        true
    }

    fn ctrl(&self, msg: SvcMsg) -> Result<(), u16> {
        if self.outbox.ctrl(msg) {
            Ok(())
        } else {
            // The viewer stopped reading (§3.4).
            Err(reason::PROTOCOL)
        }
    }

    fn tell(&self, row: TransferRow) {
        self.observer
            .event(&self.session_id, HostEvent::Transfer(row));
    }
}

/// The host's row of download `xfer`.
fn row(xfer: u32, down: &Down, state: TransferState) -> TransferRow {
    TransferRow {
        xfer,
        dir: Direction::FromHost,
        name: down.name.clone(),
        size: down.size,
        done: down.credited,
        state,
    }
}

// --- The viewer's end --------------------------------------------------------

/// Where one of the viewer's downloads stands.
enum Fetch {
    /// Waiting for one of the host's places.
    Queued,
    /// `Get` sent under this wire id.
    Asked(u32),
    /// The host is sending it under this wire id.
    Receiving(u32, Box<Incoming>),
}

/// A file arriving.
struct Incoming {
    receiving: Receiving,
    /// The stored name, once the downloads folder took the file.
    stored: Option<String>,
    /// Bytes that arrived.
    arrived: u64,
    /// Arrived bytes not yet handed to the worker (less than a chunk).
    buffered: Vec<u8>,
    /// `Done` arrived.
    done: bool,
}

/// One of the viewer's downloads.
struct Dl {
    handle: u32,
    name: Untrusted,
    size: u64,
    credited: u64,
    fetch: Fetch,
}

/// What [`ViewerDownloads`] keeps of this computer.
pub(crate) struct DownloadsFolder {
    /// Where files land (the viewer's `<Downloads>/Tornect`), with this
    /// computer's own limits; `None` without a Downloads folder.
    pub(crate) inbox: Option<Inbox>,
    /// Bytes of content in one `Data`.
    pub(crate) chunk: usize,
}

/// The viewer's downloads on one services stream.
pub(crate) struct ViewerDownloads {
    shared: ViewerShared,
    inbox: Option<Inbox>,
    inflow: Inflow,
    chunk: usize,
    depth: usize,
    downloads: HashMap<u32, Dl>,
    /// Row ids waiting for a place, in the order they were asked for.
    queue: VecDeque<u32>,
    /// Wire id → row id.
    wire: HashMap<u32, u32>,
    workers: JoinSet<()>,
    reports: mpsc::UnboundedSender<WorkerEvent>,
    /// The downloads folder's stale partial files were swept.
    swept: bool,
    /// The host is locked: nothing is asked for.
    paused: bool,
    /// `Get`s given up at a lock whose answer may still come.
    abandoned: Abandoned,
}

impl ViewerDownloads {
    /// The downloads of a stream whose host keeps to `window` bytes in
    /// flight, into `folder`; the receiving workers' reports come on the
    /// receiver returned.
    pub(crate) fn new(
        shared: ViewerShared,
        folder: DownloadsFolder,
        window: u32,
    ) -> (Self, mpsc::UnboundedReceiver<WorkerEvent>) {
        let (reports, reports_rx) = mpsc::unbounded_channel();
        let chunk = folder.chunk.max(1);
        (
            Self {
                shared,
                inbox: folder.inbox,
                inflow: Inflow::new(window),
                chunk,
                // A host that keeps to its window never fills it: the
                // window's chunks and `Finish`.
                depth: usize::try_from(window).unwrap_or(usize::MAX) / chunk + 1,
                downloads: HashMap::new(),
                queue: VecDeque::new(),
                wire: HashMap::new(),
                workers: JoinSet::new(),
                reports,
                swept: false,
                paused: false,
                abandoned: Abandoned::default(),
            },
            reports_rx,
        )
    }

    /// Copy the host's file with handle `handle`, whose name and size its
    /// listing gave (`known`). Without `BROWSE` (`allowed` false) its row
    /// fails at once with `NOT_OFFERED`, and without a downloads folder
    /// with `IO`; otherwise it waits for a place.
    pub(crate) fn download(
        &mut self,
        handle: u32,
        known: Option<(Untrusted, u64)>,
        allowed: bool,
    ) -> Result<(), u16> {
        let Some(id) = self.shared.rows.next() else {
            return Ok(());
        };
        let (name, size) = known.unwrap_or_else(|| (Untrusted::file_name(""), 0));
        let dl = Dl {
            handle,
            name,
            size,
            credited: 0,
            fetch: Fetch::Queued,
        };
        let refused = if !allowed {
            Some(reason::NOT_OFFERED)
        } else if self.inbox.is_none() {
            Some(reason::IO)
        } else {
            None
        };
        if let Some(code) = refused {
            self.emit(row_of(id, &dl, TransferState::Failed(code)));
            return Ok(());
        }
        self.sweep();
        self.emit(row_of(id, &dl, TransferState::Queued));
        self.downloads.insert(id, dl);
        self.queue.push_back(id);
        self.pump()
    }

    /// At the first download, the partial files a crashed instance left in
    /// the downloads folder are swept (on a blocking thread).
    fn sweep(&mut self) {
        if std::mem::replace(&mut self.swept, true) {
            return;
        }
        if let Some(dir) = self.inbox.as_ref().map(|inbox| inbox.dir().to_path_buf()) {
            tokio::task::spawn_blocking(move || {
                if let Err(e) =
                    tornect_core::files::sweep_stale(&dir, tornect_core::files::STALE_AFTER)
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::debug!(
                        error_kind = ?e.kind(),
                        "the downloads folder's stale partial files were not swept"
                    );
                }
            });
        }
    }

    /// Ask for queued files, in order, while fewer than [`MAX_DOWNLOADS`]
    /// are asked for or arriving.
    fn pump(&mut self) -> Result<(), u16> {
        // The host skips `Get`s while it is locked.
        while !self.paused && self.active() < MAX_DOWNLOADS {
            let Some(id) = self.queue.pop_front() else {
                return Ok(());
            };
            let Some(dl) = self.downloads.get_mut(&id) else {
                continue;
            };
            let Some(xfer) = self.shared.ids.next() else {
                self.downloads.remove(&id);
                continue;
            };
            dl.fetch = Fetch::Asked(xfer);
            let handle = dl.handle;
            self.wire.insert(xfer, id);
            self.ctrl(SvcMsg::Get(Get { xfer, handle }))?;
            let row = row_of(id, &self.downloads[&id], TransferState::Running);
            self.emit(row);
        }
        Ok(())
    }

    /// Downloads asked for or arriving.
    fn active(&self) -> usize {
        self.downloads
            .values()
            .filter(|dl| !matches!(dl.fetch, Fetch::Queued))
            .count()
    }

    /// The row id of wire id `xfer`, or what its frame does ([`late`]:
    /// `Ok(None)` to drop it).
    fn by_wire(&self, xfer: u32) -> Result<Option<u32>, u16> {
        match self.wire.get(&xfer) {
            Some(&id) => Ok(Some(id)),
            None => late(&self.shared.ids, xfer).map(|()| None),
        }
    }

    /// The host's `Sending`: the file starts arriving, on a receiving worker
    /// that takes it into the downloads folder (or refuses it: `Cancel`); or,
    /// for a `Get` given up at a lock, it is stopped.
    pub(crate) fn sending(&mut self, sending: Sending) -> Result<(), u16> {
        let Sending { xfer, name, size } = sending;
        if self.abandoned.answered(xfer) {
            return self.ctrl(SvcMsg::Cancel(Cancel {
                xfer,
                reason: reason::BY_VIEWER,
            }));
        }
        let Some(id) = self.by_wire(xfer)? else {
            return Ok(());
        };
        let (Some(dl), Some(inbox)) = (self.downloads.get_mut(&id), self.inbox.clone()) else {
            return Err(reason::PROTOCOL);
        };
        if !matches!(dl.fetch, Fetch::Asked(_)) {
            return Err(reason::PROTOCOL);
        }
        dl.name = Untrusted::file_name(&name);
        dl.size = size;
        let receiving = spawn_receiver(
            &mut self.workers,
            xfer,
            inbox,
            name,
            size,
            self.depth,
            self.reports.clone(),
        );
        dl.fetch = Fetch::Receiving(
            xfer,
            Box::new(Incoming {
                receiving,
                stored: None,
                arrived: 0,
                buffered: Vec::new(),
                done: false,
            }),
        );
        let row = row_of(id, dl, TransferState::moving(self.paused));
        self.emit(row);
        Ok(())
    }

    /// The arriving file of wire id `xfer`, or what its frame does.
    fn incoming(&mut self, xfer: u32) -> Result<Option<&mut Incoming>, u16> {
        let Some(id) = self.by_wire(xfer)? else {
            return Ok(None);
        };
        match self.downloads.get_mut(&id).map(|dl| &mut dl.fetch) {
            Some(Fetch::Receiving(_, incoming)) => Ok(Some(incoming)),
            _ => Err(reason::PROTOCOL),
        }
    }

    /// Whether the host keeps to its window with `extra` bytes of its
    /// clipboard text in flight beside its downloads'.
    pub(crate) fn admits(&self, extra: u64) -> bool {
        self.inflow.admits(self.in_flight().saturating_add(extra))
    }

    /// Bytes of downloads that arrived and were not yet credited: what the
    /// host holds in its window for them.
    fn in_flight(&self) -> u64 {
        self.downloads
            .values()
            .map(|dl| match &dl.fetch {
                Fetch::Receiving(_, incoming) => incoming.arrived - dl.credited,
                _ => 0,
            })
            .sum()
    }

    /// The host's `Data`: bytes in order, never past the size, within the
    /// window, in which `extra` bytes of the host's clipboard text are as
    /// well.
    pub(crate) fn data(
        &mut self,
        xfer: u32,
        offset: u64,
        bytes: Vec<u8>,
        extra: u64,
    ) -> Result<(), u16> {
        let Some(id) = self.by_wire(xfer)? else {
            return Ok(());
        };
        let size = self.downloads.get(&id).map_or(0, |dl| dl.size);
        let chunk = self.chunk;
        let Some(incoming) = self.incoming(xfer)? else {
            return Ok(());
        };
        let len = bytes.len() as u64;
        if incoming.done || offset != incoming.arrived || len > size - incoming.arrived {
            return Err(reason::PROTOCOL);
        }
        incoming.arrived += len;
        let last = incoming.arrived == size;
        if !self.admits(extra) {
            return Err(reason::PROTOCOL);
        }
        let Some(incoming) = self.incoming(xfer)? else {
            return Err(reason::PROTOCOL);
        };
        // Handed on in chunks, so that the worker's queue counts chunks of
        // the window whatever sizes the host sends.
        if incoming.buffered.is_empty() && (bytes.len() == chunk || last) {
            return feed(&incoming.receiving, Work::Write(bytes));
        }
        incoming.buffered.extend_from_slice(&bytes);
        if incoming.buffered.len() >= chunk {
            let rest = incoming.buffered.split_off(chunk);
            let full = std::mem::replace(&mut incoming.buffered, rest);
            feed(&incoming.receiving, Work::Write(full))?;
        }
        if last && !incoming.buffered.is_empty() {
            let rest = std::mem::take(&mut incoming.buffered);
            feed(&incoming.receiving, Work::Write(rest))?;
        }
        Ok(())
    }

    /// The host's `Done`: the worker checks the length and the hash.
    pub(crate) fn done(&mut self, done: Done) -> Result<(), u16> {
        let Done { xfer, sha256 } = done;
        let Some(incoming) = self.incoming(xfer)? else {
            return Ok(());
        };
        if incoming.done {
            return Err(reason::PROTOCOL);
        }
        incoming.done = true;
        if !incoming.buffered.is_empty() {
            let rest = std::mem::take(&mut incoming.buffered);
            feed(&incoming.receiving, Work::Write(rest))?;
        }
        feed(&incoming.receiving, Work::Finish(sha256))
    }

    /// A receiving worker's report. A file put in place is told before its
    /// `Complete` is queued.
    pub(crate) fn on_worker(&mut self, event: WorkerEvent) -> Result<(), u16> {
        let WorkerEvent { xfer, what } = event;
        let Some(&id) = self.wire.get(&xfer) else {
            // Stopped meanwhile: its worker deletes what it wrote.
            return Ok(());
        };
        let Some(dl) = self.downloads.get_mut(&id) else {
            return Ok(());
        };
        let Fetch::Receiving(_, incoming) = &mut dl.fetch else {
            return Ok(());
        };
        match what {
            Worked::Began(Ok(stored)) => incoming.stored = Some(stored),
            Worked::Began(Err(code)) | Worked::Finished(Err(code)) | Worked::Failed(code) => {
                self.ctrl(SvcMsg::Cancel(Cancel { xfer, reason: code }))?;
                self.finish(id, xfer, TransferState::Failed(code));
                return self.pump();
            }
            Worked::Written(upto) => {
                if self.inflow.due(upto, dl.credited, dl.size) {
                    dl.credited = upto;
                    let row = row_of(id, dl, TransferState::moving(self.paused));
                    self.ctrl(SvcMsg::Credit { xfer, upto })?;
                    self.emit(row);
                }
            }
            Worked::Finished(Ok(())) => {
                let stored = Untrusted::file_name(incoming.stored.as_deref().unwrap_or_default());
                self.finish(id, xfer, TransferState::Done { stored });
                self.ctrl(SvcMsg::Complete(Complete { xfer }))?;
                return self.pump();
            }
        }
        Ok(())
    }

    /// The host's `Cancel` of a download; `Ok(false)` when it names none. A
    /// file already being put in place lands all the same.
    pub(crate) fn cancelled(&mut self, cancel: Cancel) -> Result<bool, u16> {
        if self.abandoned.answered(cancel.xfer) {
            return Ok(true);
        }
        let Some(&id) = self.wire.get(&cancel.xfer) else {
            return Ok(false);
        };
        if self.stop_worker(id) {
            self.finish(id, cancel.xfer, TransferState::ended(cancel.reason));
        }
        self.pump()?;
        Ok(true)
    }

    /// The viewer's user stops download `id` (a row id); one whose file is
    /// already being put in place lands all the same.
    pub(crate) fn cancel(&mut self, id: u32) -> Result<bool, u16> {
        let Some(dl) = self.downloads.get(&id) else {
            return Ok(false);
        };
        match dl.fetch {
            Fetch::Queued => {
                self.queue.retain(|q| *q != id);
                if let Some(dl) = self.downloads.remove(&id) {
                    self.emit(row_of(id, &dl, TransferState::Cancelled(reason::BY_VIEWER)));
                }
            }
            Fetch::Asked(xfer) | Fetch::Receiving(xfer, _) => {
                if self.stop_worker(id) {
                    self.ctrl(SvcMsg::Cancel(Cancel {
                        xfer,
                        reason: reason::BY_VIEWER,
                    }))?;
                    self.finish(id, xfer, TransferState::Cancelled(reason::BY_VIEWER));
                }
            }
        }
        self.pump()?;
        Ok(true)
    }

    /// Stop download `id`'s receiving worker, if it has one: `false` when
    /// it is too late (its file is being put in place).
    fn stop_worker(&mut self, id: u32) -> bool {
        match self.downloads.get_mut(&id).map(|dl| &mut dl.fetch) {
            Some(Fetch::Receiving(_, incoming)) => incoming.receiving.cancel(),
            _ => true,
        }
    }

    /// The host paused browsing (it is locked): `Get`s still unanswered
    /// fail with `LOCKED` and are given up (the host may have skipped them;
    /// a `Sending` that comes for one is answered with `Cancel`), files
    /// arriving stall (the host sends nothing meanwhile), and queued files
    /// wait. Or it resumed it: they move again, and queued files are asked
    /// for.
    pub(crate) fn set_paused(&mut self, paused: bool) -> Result<(), u16> {
        if self.paused == paused {
            return Ok(());
        }
        self.paused = paused;
        let mut ids: Vec<u32> = self.downloads.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            let Some(dl) = self.downloads.get(&id) else {
                continue;
            };
            match dl.fetch {
                Fetch::Asked(xfer) if paused => {
                    self.abandoned.add(xfer);
                    self.finish(id, xfer, TransferState::Failed(reason::LOCKED));
                }
                Fetch::Receiving(..) => self.emit(row_of(id, dl, TransferState::moving(paused))),
                Fetch::Queued | Fetch::Asked(_) => {}
            }
        }
        self.pump()
    }

    /// The host turned browsing off (`Caps` without `BROWSE`): every
    /// download ends here with `TURNED_OFF`, and nothing is sent.
    pub(crate) fn turned_off(&mut self) {
        self.end_all(reason::TURNED_OFF);
    }

    /// Every download ends with `code` and nothing is sent; a file already
    /// being put in place lands, and its row comes from [`Self::join`].
    pub(crate) fn end_all(&mut self, code: u16) {
        let mut ids: Vec<u32> = self.downloads.keys().copied().collect();
        ids.sort_unstable();
        self.queue.clear();
        for id in ids {
            let Some(dl) = self.downloads.get(&id) else {
                continue;
            };
            match dl.fetch {
                Fetch::Queued => {
                    if let Some(dl) = self.downloads.remove(&id) {
                        self.emit(row_of(id, &dl, TransferState::ended(code)));
                    }
                }
                Fetch::Asked(xfer) | Fetch::Receiving(xfer, _) => {
                    if self.stop_worker(id) {
                        self.finish(id, xfer, TransferState::ended(code));
                    }
                }
            }
        }
    }

    /// Wait up to `within` for the receiving workers to end (each deletes
    /// its partial files, or puts a file it verified in place), handling
    /// their `reports`; nothing more goes to the host.
    pub(crate) async fn join(
        &mut self,
        reports: &mut mpsc::UnboundedReceiver<WorkerEvent>,
        within: Duration,
    ) {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            tokio::select! {
                biased;
                Some(report) = reports.recv() => {
                    // The writer is closing: a `Complete` no longer goes out.
                    let _ = self.on_worker(report);
                }
                joined = self.workers.join_next() => {
                    if joined.is_none() {
                        break;
                    }
                }
                () = tokio::time::sleep_until(deadline) => break,
            }
        }
        while let Ok(report) = reports.try_recv() {
            let _ = self.on_worker(report);
        }
    }

    /// Download `id` (wire id `xfer`) ended in `state`: the row says so.
    fn finish(&mut self, id: u32, xfer: u32, state: TransferState) {
        self.wire.remove(&xfer);
        self.shared.ids.end(xfer);
        if let Some(dl) = self.downloads.remove(&id) {
            let mut row = row_of(id, &dl, state);
            if matches!(row.state, TransferState::Done { .. }) {
                row.done = dl.size;
            }
            self.emit(row);
        }
    }

    fn ctrl(&self, msg: SvcMsg) -> Result<(), u16> {
        if self.shared.outbox.ctrl(msg) {
            Ok(())
        } else {
            // The host stopped reading (§3.4).
            Err(reason::PROTOCOL)
        }
    }

    fn emit(&self, row: TransferRow) {
        if self
            .shared
            .events
            .try_send(ViewerEvent::Transfer(row))
            .is_err()
        {
            tracing::debug!("a transfer event was dropped: nothing reads them");
        }
    }
}

/// Hand `work` to a download's worker: a full queue is a host beyond its
/// window; a worker that is gone failed, and its report is on its way.
fn feed(receiving: &Receiving, work: Work) -> Result<(), u16> {
    match receiving.feed(work) {
        Ok(()) | Err(Fed::Gone) => Ok(()),
        Err(Fed::Full) => Err(reason::PROTOCOL),
    }
}

/// The viewer's row of download `id`.
fn row_of(id: u32, dl: &Dl, state: TransferState) -> TransferRow {
    TransferRow {
        xfer: id,
        dir: Direction::FromHost,
        name: dl.name.clone(),
        size: dl.size,
        done: dl.credited,
        state,
    }
}
