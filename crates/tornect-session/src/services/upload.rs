//! The upload protocol, both ends (the services design §3.5): the viewer
//! sends a file into the host's inbox.
//!
//! 1. The viewer sends `Offer{xfer, name, size}`; the host checks, in
//!    order, that uploads are not paused (`LOCKED`), that fewer than
//!    [`MAX_UPLOADS`] are running (`BUSY`), then the size, the session's
//!    file count and quota, the free space and the name in its inbox
//!    ([`Inbox::begin`], on the transfer's blocking worker), and answers
//!    `Accepted{xfer, stored name}` or `Cancel{xfer, reason}`.
//! 2. The viewer sends the file as contiguous `Data`, within the bulk window
//!    ([`Window`]); the host writes it on the worker and credits what it
//!    wrote (`Credit{xfer, upto}`, every [`credit_step`] bytes and at the
//!    end). Bytes out of order, past the size, before `Accepted` or beyond
//!    the window end the stream with `Close{PROTOCOL}`.
//! 3. The viewer sends `Done{xfer, sha256}` behind its last `Data`; the host
//!    checks the length and the hash, puts the file in place and answers
//!    `Complete`, or `Cancel{CORRUPT}` and deletes it.
//! 4. Either end may `Cancel` at any point; the host deletes what it wrote.
//!
//! The viewer runs at most [`MAX_UPLOADS`] uploads and queues the others.
//! It gives each upload two ids: the row's, from the moment it is asked for
//! (what [`ViewerOp::Cancel`](super::ViewerOp::Cancel) names), and the wire
//! id of its `Offer`, given when the offer goes out, so that the ids on the
//! wire always count up whatever order the files open in.
//!
//! Nothing here logs a file name or a path.
//!
//! [`credit_step`]: super::window::credit_step

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tornect_proto::services::{
    Accepted, Cancel, Complete, Done, MAX_NAME_BYTES, Offer, SvcMsg, Welcome, reason,
};

use super::browse::{Access, code_of};
use super::store::{Fed, Inbox, Receiving, Work, Worked, WorkerEvent, spawn_receiver};
use super::transfer::{
    Direction, Ids, Known, MAX_UPLOADS, Outgoing, SendFailed, TransferRow, TransferState, Untrusted,
};
use super::window::{Inflow, Window};
use super::writer::Outbox;
use super::{HostEvent, ServicesLimits, ServicesObserver, ViewerEvent};

/// What a frame for transfer `xfer`, which no running upload has, does: a
/// late frame of one that ended is dropped, anything else is a protocol
/// error.
fn late(ids: &Ids, xfer: u32) -> Result<(), u16> {
    match ids.known(xfer) {
        Known::Ended => Ok(()),
        Known::Unknown => Err(reason::PROTOCOL),
    }
}

// --- The host's end ----------------------------------------------------------

/// An upload the host is taking.
struct Upload {
    receiving: Receiving,
    size: u64,
    /// The stored name, once the inbox took the file (`Accepted` went out).
    stored: Option<String>,
    /// Bytes that arrived.
    arrived: u64,
    /// Arrived bytes not yet handed to the worker (less than a chunk).
    buffered: Vec<u8>,
    /// Bytes credited.
    credited: u64,
    /// `Done` arrived.
    done: bool,
}

/// The host's uploads on one services stream.
pub(crate) struct HostUploads {
    session_id: String,
    inbox: Option<Inbox>,
    observer: Arc<dyn ServicesObserver>,
    outbox: Outbox,
    inflow: Inflow,
    chunk: usize,
    depth: usize,
    /// Uploads offered and not ended, an upload whose file is being put in
    /// place included (a stop no longer takes it).
    running: HashMap<u32, Upload>,
    /// The workers of uploads stopped before they ended on their own, until
    /// they are joined: they count toward [`MAX_UPLOADS`], so that offers
    /// and cancels sent at stream speed cannot pile workers up.
    stopping: HashSet<tokio::task::Id>,
    ids: Ids,
    workers: JoinSet<()>,
    events: mpsc::UnboundedSender<WorkerEvent>,
    /// Files put in place, and their bytes.
    pub(crate) files_in: u32,
    pub(crate) bytes_in: u64,
}

impl HostUploads {
    /// The uploads of session `session_id` into `inbox` (`None` without
    /// `UPLOAD`), whose viewer keeps to `window`; the workers' reports come
    /// on the receiver returned.
    pub(crate) fn new(
        session_id: &str,
        inbox: Option<Inbox>,
        observer: Arc<dyn ServicesObserver>,
        outbox: Outbox,
        window: u32,
        limits: &ServicesLimits,
    ) -> (Self, mpsc::UnboundedReceiver<WorkerEvent>) {
        let (events, reports) = mpsc::unbounded_channel();
        let chunk = limits.chunk.max(1);
        (
            Self {
                session_id: session_id.to_owned(),
                inbox,
                observer,
                outbox,
                inflow: Inflow::new(window),
                chunk,
                // A sender that keeps to its window never fills it: the
                // window's chunks and `Finish`.
                depth: usize::try_from(window).unwrap_or(usize::MAX) / chunk + 1,
                running: HashMap::new(),
                stopping: HashSet::new(),
                ids: Ids::default(),
                workers: JoinSet::new(),
                events,
                files_in: 0,
                bytes_in: 0,
            },
            reports,
        )
    }

    /// The viewer's `Offer`; `paused` while a lock pauses uploads. `Err` with
    /// the `Close` reason.
    pub(crate) fn offer(&mut self, offer: Offer, paused: bool) -> Result<(), u16> {
        let Offer { xfer, name, size } = offer;
        if !self.ids.fresh(xfer) {
            return Err(reason::PROTOCOL);
        }
        self.reap();
        let refused = if paused {
            Some(reason::LOCKED)
        } else if self.running.len() + self.stopping.len() >= MAX_UPLOADS {
            Some(reason::BUSY)
        } else if self.inbox.is_none() {
            Some(reason::NOT_OFFERED)
        } else {
            None
        };
        if let Some(code) = refused {
            self.ids.end(xfer);
            return self.ctrl(SvcMsg::Cancel(Cancel { xfer, reason: code }));
        }
        let Some(inbox) = self.inbox.clone() else {
            return Err(reason::PROTOCOL);
        };
        let receiving = spawn_receiver(
            &mut self.workers,
            xfer,
            inbox,
            name,
            size,
            self.depth,
            self.events.clone(),
        );
        self.running.insert(
            xfer,
            Upload {
                receiving,
                size,
                stored: None,
                arrived: 0,
                buffered: Vec::new(),
                credited: 0,
                done: false,
            },
        );
        Ok(())
    }

    /// The viewer's `Data`.
    pub(crate) fn data(&mut self, xfer: u32, offset: u64, bytes: Vec<u8>) -> Result<(), u16> {
        let Some(up) = self.running.get_mut(&xfer) else {
            return late(&self.ids, xfer);
        };
        let len = bytes.len() as u64;
        if up.stored.is_none() || up.done || offset != up.arrived || len > up.size - up.arrived {
            return Err(reason::PROTOCOL);
        }
        up.arrived += len;
        let arrived: u64 = self.running.values().map(|u| u.arrived - u.credited).sum();
        if !self.inflow.admits(arrived) {
            return Err(reason::PROTOCOL);
        }
        let chunk = self.chunk;
        let Some(up) = self.running.get_mut(&xfer) else {
            return Err(reason::PROTOCOL);
        };
        let last = up.arrived == up.size;
        // Handed on in chunks, so that the worker's queue counts chunks of
        // the window whatever sizes the viewer sends.
        if up.buffered.is_empty() && (bytes.len() == chunk || last) {
            return feed(&up.receiving, Work::Write(bytes));
        }
        up.buffered.extend_from_slice(&bytes);
        if up.buffered.len() >= chunk {
            let rest = up.buffered.split_off(chunk);
            let full = std::mem::replace(&mut up.buffered, rest);
            feed(&up.receiving, Work::Write(full))?;
        }
        if last && !up.buffered.is_empty() {
            let rest = std::mem::take(&mut up.buffered);
            feed(&up.receiving, Work::Write(rest))?;
        }
        Ok(())
    }

    /// The viewer's `Done`: the worker checks the length and the hash.
    pub(crate) fn done(&mut self, done: Done) -> Result<(), u16> {
        let Done { xfer, sha256 } = done;
        let Some(up) = self.running.get_mut(&xfer) else {
            return late(&self.ids, xfer);
        };
        if up.stored.is_none() || up.done {
            return Err(reason::PROTOCOL);
        }
        up.done = true;
        if !up.buffered.is_empty() {
            let rest = std::mem::take(&mut up.buffered);
            feed(&up.receiving, Work::Write(rest))?;
        }
        feed(&up.receiving, Work::Finish(sha256))
    }

    /// The viewer's `Cancel` of an upload; `Ok(false)` when it names no
    /// upload (the stream may know it otherwise). One that came too late,
    /// once the file was being put in place, changes nothing: its `Complete`
    /// follows.
    pub(crate) fn cancelled(&mut self, cancel: Cancel) -> Result<bool, u16> {
        if !self.running.contains_key(&cancel.xfer) {
            return Ok(false);
        }
        // The viewer's own reasons (it stopped it, its file changed, its
        // read failed); anything else counts as the viewer's stop.
        let code = match cancel.reason {
            reason::CHANGED | reason::IO => cancel.reason,
            _ => reason::BY_VIEWER,
        };
        if let Some(up) = self.take(cancel.xfer) {
            self.ended(cancel.xfer, &up, code);
        }
        Ok(true)
    }

    /// Whether `xfer` is an id this end saw end lately, or `Err(PROTOCOL)`.
    pub(crate) fn late(&self, xfer: u32) -> Result<(), u16> {
        late(&self.ids, xfer)
    }

    /// A transfer this build does not serve yet (a download's `Get`) takes
    /// `xfer`: it must be new, and it ends at once.
    pub(crate) fn unserved(&mut self, xfer: u32) -> Result<(), u16> {
        if !self.ids.fresh(xfer) {
            return Err(reason::PROTOCOL);
        }
        self.ids.end(xfer);
        Ok(())
    }

    /// The host's user stops upload `xfer`: `Ok(false)` when no such upload
    /// runs, or when its file is already being put in place (it is left to
    /// land, and its row and `Complete` follow).
    pub(crate) fn cancel(&mut self, xfer: u32, code: u16) -> Result<bool, u16> {
        let Some(up) = self.take(xfer) else {
            return Ok(false);
        };
        self.ended(xfer, &up, code);
        self.ctrl(SvcMsg::Cancel(Cancel { xfer, reason: code }))?;
        Ok(true)
    }

    /// Stop every upload with `code` (`TURNED_OFF`), telling the viewer; one
    /// whose file is being put in place is left to land.
    pub(crate) fn cancel_all(&mut self, code: u16) -> Result<(), u16> {
        let mut xfers: Vec<u32> = self.running.keys().copied().collect();
        xfers.sort_unstable();
        for xfer in xfers {
            self.cancel(xfer, code)?;
        }
        Ok(())
    }

    /// A worker's report. A file put in place is told and counted before its
    /// `Complete` is queued, so that a stream ending there (its viewer
    /// stopped reading, or it is closing) still records it.
    pub(crate) fn on_worker(&mut self, event: WorkerEvent) -> Result<(), u16> {
        let WorkerEvent { xfer, what } = event;
        self.reap();
        let Some(up) = self.running.get_mut(&xfer) else {
            // Stopped meanwhile: its worker deletes what it wrote, and a
            // stopped worker never puts its file in place.
            return Ok(());
        };
        match what {
            Worked::Began(Ok(stored)) => {
                up.stored = Some(stored.clone());
                let row = row(xfer, up, TransferState::Running);
                self.ctrl(SvcMsg::Accepted(Accepted { xfer, name: stored }))?;
                self.tell(row);
            }
            Worked::Began(Err(code)) => {
                // Refused before anything was written: no row.
                self.running.remove(&xfer);
                self.ids.end(xfer);
                tracing::debug!(session = %self.session_id, reason = code, "an upload was refused");
                self.ctrl(SvcMsg::Cancel(Cancel { xfer, reason: code }))?;
            }
            Worked::Written(upto) => {
                if self.inflow.due(upto, up.credited, up.size) {
                    up.credited = upto;
                    let row = row(xfer, up, TransferState::Running);
                    self.ctrl(SvcMsg::Credit { xfer, upto })?;
                    self.tell(row);
                }
            }
            Worked::Finished(Ok(())) => {
                let Some(up) = self.running.remove(&xfer) else {
                    return Ok(());
                };
                self.ids.end(xfer);
                self.files_in = self.files_in.saturating_add(1);
                self.bytes_in = self.bytes_in.saturating_add(up.size);
                let stored = Untrusted::file_name(up.stored.as_deref().unwrap_or_default());
                let mut done = row(xfer, &up, TransferState::Done { stored });
                done.done = up.size;
                tracing::info!(session = %self.session_id, bytes = up.size, "an upload was received");
                self.tell(done);
                self.ctrl(SvcMsg::Complete(Complete { xfer }))?;
            }
            Worked::Finished(Err(code)) | Worked::Failed(code) => {
                let Some(up) = self.running.remove(&xfer) else {
                    return Ok(());
                };
                self.ids.end(xfer);
                self.ended(xfer, &up, code);
                self.ctrl(SvcMsg::Cancel(Cancel { xfer, reason: code }))?;
            }
        }
        Ok(())
    }

    /// Stop every worker: each deletes what it wrote. Nothing is sent. An
    /// upload whose file is being put in place is kept, for its report.
    pub(crate) fn stop(&mut self) {
        let xfers: Vec<u32> = self.running.keys().copied().collect();
        for xfer in xfers {
            self.take(xfer);
        }
    }

    /// Stop every worker, then wait up to `within` for them to end (each has
    /// deleted its partial files once it ended), handling their `reports`:
    /// a file that was being put in place lands or fails, and its row says
    /// which, and counts. Nothing more goes to the viewer. `false` when a
    /// worker is still running: one stuck in a write, which reports nothing
    /// more, or one still putting its file in place ([`Self::landing`]).
    pub(crate) async fn join(
        &mut self,
        reports: &mut mpsc::UnboundedReceiver<WorkerEvent>,
        within: Duration,
    ) -> bool {
        self.stop();
        let deadline = tokio::time::Instant::now() + within;
        let settled = loop {
            tokio::select! {
                biased;
                Some(report) = reports.recv() => {
                    // The writer is closing: a `Complete` no longer goes out.
                    let _ = self.on_worker(report);
                }
                joined = self.workers.join_next() => {
                    if joined.is_none() {
                        break true;
                    }
                }
                () = tokio::time::sleep_until(deadline) => break false,
            }
        };
        while let Ok(report) = reports.try_recv() {
            let _ = self.on_worker(report);
        }
        settled
    }

    /// Whether an upload is still putting its file in place after
    /// [`Self::join`] gave up waiting: its row is still to come.
    pub(crate) fn landing(&self) -> bool {
        !self.running.is_empty()
    }

    /// Wait as long as it takes for the uploads still putting their files
    /// in place, handling their `reports`, so that a file that lands is told
    /// even when its rename outlasted [`Self::join`]'s wait. Its row then
    /// comes after the stream's `Closed`.
    pub(crate) async fn settle(mut self, mut reports: mpsc::UnboundedReceiver<WorkerEvent>) {
        while self.landing() {
            tokio::select! {
                biased;
                Some(report) = reports.recv() => {
                    let _ = self.on_worker(report);
                }
                joined = self.workers.join_next() => {
                    if joined.is_none() {
                        // A worker that ended without its report panicked.
                        while let Ok(report) = reports.try_recv() {
                            let _ = self.on_worker(report);
                        }
                        return;
                    }
                }
            }
        }
    }

    /// Stop upload `xfer`'s worker and take it off the running ones, its id
    /// ended: `None` when no such upload runs, or when it is too late (its
    /// file is being put in place; its worker reports whether it landed).
    fn take(&mut self, xfer: u32) -> Option<Upload> {
        if !self.running.get_mut(&xfer)?.receiving.cancel() {
            return None;
        }
        let up = self.running.remove(&xfer)?;
        self.stopping.insert(up.receiving.worker());
        self.ids.end(xfer);
        Some(up)
    }

    /// Join the workers that ended: a stopped one no longer counts toward
    /// [`MAX_UPLOADS`].
    fn reap(&mut self) {
        while let Some(joined) = self.workers.try_join_next_with_id() {
            let id = match joined {
                Ok((id, ())) => id,
                Err(e) => e.id(),
            };
            self.stopping.remove(&id);
        }
    }

    /// Upload `xfer` ended with `code`, its worker stopped: the host's user
    /// is told, if it had begun.
    fn ended(&self, xfer: u32, up: &Upload, code: u16) {
        tracing::debug!(session = %self.session_id, reason = code, "an upload ended");
        if up.stored.is_some() {
            self.tell(row(xfer, up, TransferState::ended(code)));
        }
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

/// Hand `work` to an upload's worker: a full queue is a sender beyond its
/// window; a worker that is gone failed, and its report is on its way.
fn feed(receiving: &Receiving, work: Work) -> Result<(), u16> {
    match receiving.feed(work) {
        Ok(()) | Err(Fed::Gone) => Ok(()),
        Err(Fed::Full) => Err(reason::PROTOCOL),
    }
}

/// The host's row of upload `xfer`.
fn row(xfer: u32, up: &Upload, state: TransferState) -> TransferRow {
    TransferRow {
        xfer,
        dir: Direction::ToHost,
        name: Untrusted::file_name(up.stored.as_deref().unwrap_or_default()),
        size: up.size,
        done: up.credited,
        state,
    }
}

// --- The viewer's end --------------------------------------------------------

/// Where one of the viewer's uploads stands.
enum Phase {
    /// The file is being opened.
    Opening,
    /// Open, waiting for a place.
    Queued(File),
    /// `Offer` sent under this wire id.
    Offered(u32, File),
    /// Accepted under this wire id and stored name: being sent (dropping
    /// the [`Outgoing`] stops the sending).
    Sending(
        u32,
        #[expect(dead_code, reason = "held for its drop, which stops the sending")] Outgoing,
        Untrusted,
    ),
}

/// One of the viewer's uploads.
struct Up {
    name: Untrusted,
    size: u64,
    credited: u64,
    phase: Phase,
}

/// What the viewer's blocking work tells its loop.
#[derive(Debug)]
pub(crate) enum Job {
    /// The file of upload `id` opened: it and its size, or why not.
    Opened {
        /// The upload's row id.
        id: u32,
        /// The file and its size, or a reason code.
        result: Result<(File, u64), u16>,
    },
}

/// What the viewer's blocking work and sending tasks report to its loop.
pub(crate) struct ViewerReports {
    /// Files opened.
    pub(crate) jobs: mpsc::UnboundedReceiver<Job>,
    /// Sending tasks that failed.
    pub(crate) failed: mpsc::UnboundedReceiver<SendFailed>,
}

/// The viewer's uploads on one services stream.
pub(crate) struct ViewerUploads {
    outbox: Outbox,
    events: mpsc::Sender<ViewerEvent>,
    window: Arc<Window>,
    /// What may be sent: every file passes it before it is opened.
    access: Arc<Access>,
    file_max: u64,
    chunk: usize,
    read_timeout: Duration,
    /// Row ids, counting up.
    next_id: u32,
    /// Wire ids.
    ids: Ids,
    uploads: HashMap<u32, Up>,
    /// Row ids waiting for a place, in the order they were asked for.
    queue: VecDeque<u32>,
    /// Wire id → row id.
    wire: HashMap<u32, u32>,
    jobs: mpsc::UnboundedSender<Job>,
    failed: mpsc::UnboundedSender<SendFailed>,
}

impl ViewerUploads {
    /// The uploads of a stream the host welcomed with `welcome`, of files
    /// `access` lets through; what the blocking work and the sending tasks
    /// report comes on the receivers returned.
    pub(crate) fn new(
        outbox: Outbox,
        events: mpsc::Sender<ViewerEvent>,
        window: Arc<Window>,
        access: Arc<Access>,
        welcome: &Welcome,
        chunk: usize,
        read_timeout: Duration,
    ) -> (Self, ViewerReports) {
        let (jobs, jobs_rx) = mpsc::unbounded_channel();
        let (failed, failed_rx) = mpsc::unbounded_channel();
        (
            Self {
                outbox,
                events,
                window,
                access,
                file_max: welcome.file_max,
                chunk: chunk.max(1),
                read_timeout,
                next_id: 0,
                ids: Ids::default(),
                uploads: HashMap::new(),
                queue: VecDeque::new(),
                wire: HashMap::new(),
                jobs,
                failed,
            },
            ViewerReports {
                jobs: jobs_rx,
                failed: failed_rx,
            },
        )
    }

    /// Send the file at `path`: on a blocking thread it must pass the
    /// viewer's [`Access`] (so that a slip never offers Tornect's own files),
    /// be a regular file within the host's largest file, and open; then it
    /// waits for a place. Without `UPLOAD` (`allowed` false) the row fails at
    /// once. Nothing goes to the host for a file refused here.
    pub(crate) fn upload_path(&mut self, path: PathBuf, allowed: bool) {
        let Some(id) = self.next_id.checked_add(1) else {
            return;
        };
        self.next_id = id;
        let raw = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let up = Up {
            name: Untrusted::file_name(&raw),
            size: 0,
            credited: 0,
            phase: Phase::Opening,
        };
        if !allowed {
            self.emit(row_of(id, &up, TransferState::Failed(reason::NOT_OFFERED)));
            return;
        }
        self.emit(row_of(id, &up, TransferState::Queued));
        self.uploads.insert(id, up);
        self.queue.push_back(id);
        let jobs = self.jobs.clone();
        let access = Arc::clone(&self.access);
        tokio::task::spawn_blocking(move || {
            let result = open_upload(&access, &path);
            let _ = jobs.send(Job::Opened { id, result });
        });
    }

    /// A file to send that cannot be named (a local handle that is unknown
    /// or evicted): its row fails at once with `code`, and nothing is sent.
    pub(crate) fn refuse(&mut self, code: u16) {
        let Some(id) = self.next_id.checked_add(1) else {
            return;
        };
        self.next_id = id;
        let up = Up {
            name: Untrusted::file_name(""),
            size: 0,
            credited: 0,
            phase: Phase::Opening,
        };
        self.emit(row_of(id, &up, TransferState::Failed(code)));
    }

    /// What the blocking work reports.
    pub(crate) fn on_job(&mut self, job: Job) -> Result<(), u16> {
        let Job::Opened { id, result } = job;
        let Some(up) = self.uploads.get_mut(&id) else {
            // Cancelled meanwhile: the file closes here.
            return Ok(());
        };
        if !matches!(up.phase, Phase::Opening) {
            return Ok(());
        }
        let refused = match result {
            Ok((_, size)) if size > self.file_max => Some((reason::TOO_LARGE, size)),
            Ok((file, size)) => {
                up.size = size;
                up.phase = Phase::Queued(file);
                let row = row_of(id, up, TransferState::Queued);
                self.emit(row);
                None
            }
            Err(code) => Some((code, 0)),
        };
        if let Some((code, size)) = refused {
            self.queue.retain(|q| *q != id);
            if let Some(mut up) = self.uploads.remove(&id) {
                up.size = size;
                self.emit(row_of(id, &up, TransferState::Failed(code)));
            }
        }
        self.pump()
    }

    /// Offer queued files, in the order they were asked for, while fewer
    /// than [`MAX_UPLOADS`] run; a file still opening holds the ones behind
    /// it, so that offers go out in order.
    fn pump(&mut self) -> Result<(), u16> {
        while self.active() < MAX_UPLOADS {
            let Some(&id) = self.queue.front() else {
                return Ok(());
            };
            let Some(up) = self.uploads.get_mut(&id) else {
                self.queue.pop_front();
                continue;
            };
            if matches!(up.phase, Phase::Opening) {
                return Ok(());
            }
            self.queue.pop_front();
            let Phase::Queued(file) = std::mem::replace(&mut up.phase, Phase::Opening) else {
                continue;
            };
            let Some(xfer) = self.ids.next() else {
                self.uploads.remove(&id);
                continue;
            };
            up.phase = Phase::Offered(xfer, file);
            self.wire.insert(xfer, id);
            let name = up.name.as_str().to_owned();
            let size = up.size;
            self.ctrl(SvcMsg::Offer(Offer { xfer, name, size }))?;
            let up = &self.uploads[&id];
            self.emit(row_of(id, up, TransferState::Running));
        }
        Ok(())
    }

    /// Uploads offered or being sent.
    fn active(&self) -> usize {
        self.uploads
            .values()
            .filter(|up| matches!(up.phase, Phase::Offered(..) | Phase::Sending(..)))
            .count()
    }

    /// The row id of wire id `xfer`, or what its frame does
    /// ([`late`]: `Ok(None)` to drop it).
    fn by_wire(&self, xfer: u32) -> Result<Option<u32>, u16> {
        match self.wire.get(&xfer) {
            Some(&id) => Ok(Some(id)),
            None => late(&self.ids, xfer).map(|()| None),
        }
    }

    /// The host's `Accepted`: send the file.
    pub(crate) fn accepted(&mut self, accepted: Accepted) -> Result<(), u16> {
        let Some(id) = self.by_wire(accepted.xfer)? else {
            return Ok(());
        };
        let Some(up) = self.uploads.get_mut(&id) else {
            return Err(reason::PROTOCOL);
        };
        let Phase::Offered(xfer, file) = std::mem::replace(&mut up.phase, Phase::Opening) else {
            return Err(reason::PROTOCOL);
        };
        self.window.open(xfer);
        let out = Outgoing::start(
            xfer,
            file,
            up.size,
            self.chunk,
            Arc::clone(&self.window),
            self.outbox.clone(),
            self.read_timeout,
            self.failed.clone(),
        );
        up.phase = Phase::Sending(xfer, out, Untrusted::file_name(&accepted.name));
        Ok(())
    }

    /// The host's `Credit` of an upload (transfer 0, the clipboard's, is not
    /// one).
    pub(crate) fn credit(&mut self, xfer: u32, upto: u64) -> Result<(), u16> {
        let Some(id) = self.by_wire(xfer)? else {
            return Ok(());
        };
        let Some(up) = self.uploads.get_mut(&id) else {
            return Err(reason::PROTOCOL);
        };
        if !matches!(up.phase, Phase::Sending(..)) {
            return Err(reason::PROTOCOL);
        }
        self.window
            .credit(xfer, upto)
            .map_err(|_| reason::PROTOCOL)?;
        up.credited = upto;
        let row = row_of(id, up, TransferState::Running);
        self.emit(row);
        Ok(())
    }

    /// The host's `Complete`: the file is in place.
    pub(crate) fn complete(&mut self, complete: Complete) -> Result<(), u16> {
        let Some(id) = self.by_wire(complete.xfer)? else {
            return Ok(());
        };
        let Some(up) = self.uploads.get(&id) else {
            return Err(reason::PROTOCOL);
        };
        let Phase::Sending(_, _, stored) = &up.phase else {
            return Err(reason::PROTOCOL);
        };
        let state = TransferState::Done {
            stored: stored.clone(),
        };
        self.finish(id, complete.xfer, state);
        self.pump()
    }

    /// The host's `Cancel` of an upload; `Ok(false)` when it names none.
    pub(crate) fn cancelled(&mut self, cancel: Cancel) -> Result<bool, u16> {
        let Some(&id) = self.wire.get(&cancel.xfer) else {
            return Ok(false);
        };
        self.finish(id, cancel.xfer, TransferState::ended(cancel.reason));
        self.pump()?;
        Ok(true)
    }

    /// Whether wire id `xfer` ended lately, or `Err(PROTOCOL)`.
    pub(crate) fn late(&self, xfer: u32) -> Result<(), u16> {
        late(&self.ids, xfer)
    }

    /// A sending task failed: the host hears `Cancel` with its reason.
    pub(crate) fn send_failed(&mut self, failed: SendFailed) -> Result<(), u16> {
        let Some(&id) = self.wire.get(&failed.xfer) else {
            return Ok(());
        };
        // Queued before the window is released: the host counts the bytes
        // in flight until it hears the `Cancel`, so no byte the release lets
        // another upload send may reach it first.
        self.ctrl(SvcMsg::Cancel(Cancel {
            xfer: failed.xfer,
            reason: failed.reason,
        }))?;
        self.finish(id, failed.xfer, TransferState::Failed(failed.reason));
        self.pump()
    }

    /// The viewer's user stops upload `id` (a row id).
    pub(crate) fn cancel(&mut self, id: u32) -> Result<(), u16> {
        let Some(up) = self.uploads.get(&id) else {
            return Ok(());
        };
        let wire = match up.phase {
            Phase::Offered(xfer, _) | Phase::Sending(xfer, ..) => Some(xfer),
            Phase::Opening | Phase::Queued(_) => None,
        };
        match wire {
            Some(xfer) => {
                // Before the window is released, as in `send_failed`.
                self.ctrl(SvcMsg::Cancel(Cancel {
                    xfer,
                    reason: reason::BY_VIEWER,
                }))?;
                self.finish(id, xfer, TransferState::Cancelled(reason::BY_VIEWER));
            }
            None => {
                self.queue.retain(|q| *q != id);
                if let Some(up) = self.uploads.remove(&id) {
                    self.emit(row_of(id, &up, TransferState::Cancelled(reason::BY_VIEWER)));
                }
            }
        }
        self.pump()
    }

    /// The host turned uploads off (`Caps` without `UPLOAD`): every upload
    /// ends here with `TURNED_OFF`, and nothing is sent (the host ended its
    /// side, and skips upload frames from now on).
    pub(crate) fn turned_off(&mut self) {
        self.end_all(reason::TURNED_OFF);
    }

    /// Every upload ends with `code` and nothing is sent: uploads were
    /// turned off, or the stream ended (its reason).
    pub(crate) fn end_all(&mut self, code: u16) {
        let mut ids: Vec<u32> = self.uploads.keys().copied().collect();
        ids.sort_unstable();
        self.queue.clear();
        for id in ids {
            let Some(up) = self.uploads.get(&id) else {
                continue;
            };
            match up.phase {
                Phase::Offered(xfer, _) | Phase::Sending(xfer, ..) => {
                    self.finish(id, xfer, TransferState::ended(code));
                }
                Phase::Opening | Phase::Queued(_) => {
                    if let Some(up) = self.uploads.remove(&id) {
                        self.emit(row_of(id, &up, TransferState::ended(code)));
                    }
                }
            }
        }
    }

    /// Upload `id` (wire id `xfer`) ended in `state`: its sending stops, its
    /// window is released, and the row says so.
    fn finish(&mut self, id: u32, xfer: u32, state: TransferState) {
        self.wire.remove(&xfer);
        self.ids.end(xfer);
        self.window.release(xfer);
        if let Some(up) = self.uploads.remove(&id) {
            let mut row = row_of(id, &up, state);
            if matches!(row.state, TransferState::Done { .. }) {
                row.done = up.size;
            }
            self.emit(row);
        }
    }

    fn ctrl(&self, msg: SvcMsg) -> Result<(), u16> {
        if self.outbox.ctrl(msg) {
            Ok(())
        } else {
            // The host stopped reading (§3.4).
            Err(reason::PROTOCOL)
        }
    }

    fn emit(&self, row: TransferRow) {
        if self.events.try_send(ViewerEvent::Transfer(row)).is_err() {
            tracing::debug!("a transfer event was dropped: nothing reads them");
        }
    }
}

/// The viewer's row of upload `id`.
fn row_of(id: u32, up: &Up, state: TransferState) -> TransferRow {
    TransferRow {
        xfer: id,
        dir: Direction::ToHost,
        name: up.name.clone(),
        size: up.size,
        done: up.credited,
        state,
    }
}

/// Open the file at `path` to send it: it must pass `access` (the design's
/// §5.2 rules: `NOT_FOUND`, `DENIED`), and the canonical path that passed is
/// the one opened: a regular file (checked before the open, so that a pipe
/// never blocks it, and again on the open file), and its size; a name over
/// the wire's bound is cut later by the name's sanitising.
fn open_upload(access: &Access, path: &Path) -> Result<(File, u64), u16> {
    let code = |e: io::Error| code_of(&e);
    let canonical = access.check(path)?;
    if !std::fs::metadata(&canonical).map_err(code)?.is_file() {
        return Err(reason::NOT_A_FILE);
    }
    let file = File::open(&canonical).map_err(code)?;
    let meta = file.metadata().map_err(code)?;
    if !meta.is_file() {
        return Err(reason::NOT_A_FILE);
    }
    Ok((file, meta.len()))
}

// The name the viewer offers is its own file's, sanitised: never more than
// the wire's bound.
const _: () = assert!(tornect_core::files::MAX_NAME_BYTES <= MAX_NAME_BYTES);
