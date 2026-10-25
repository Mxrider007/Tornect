//! Files a services stream receives (the services design §5.1): the folder
//! they land in, its limits, and the file being written.
//!
//! - [`Inbox::begin`] takes one file: it checks the size, the session's file
//!   count and byte quota and the disk's free space, sanitises the name, then
//!   **reserves** the final name with an empty private file (the next free
//!   `name (n).ext` when it is taken) and creates `<final>.tornect-part`
//!   beside it, where the bytes go. On Windows the part file is marked as
//!   downloaded from the Internet (its `Zone.Identifier` stream, which moves
//!   with the rename); a mark that cannot be written fails the file before a
//!   byte is taken.
//! - [`Incoming::write`] takes the bytes in order, never past the announced
//!   size, hashing them; it re-reads the free space every
//!   [`InboxLimits::recheck_every`] bytes.
//! - [`Incoming::verify`] syncs the part file and checks its length and
//!   SHA-256 against the sender's; [`Verified::put_in_place`] then renames it
//!   over the reservation: the rename only ever replaces our own empty file.
//! - An [`Incoming`] (or a [`Verified`]) dropped unfinished deletes its part
//!   file and its reservation, whatever ended it (a cancel, a protocol error,
//!   the session's end, the kill switch, capture stopping, a panic). What a
//!   crash leaves is swept at the next start (`tornect_core::files::sweep_stale`).
//!
//! The part file and the reservation are taken by their name, and on Unix
//! also by their inode: a rename or a deletion that would take a file this
//! transfer did not make (another instance's, after a sweep) fails instead.
//! A worker waiting for bytes touches its part file every [`TOUCH_EVERY`], so
//! that the stale sweep, which takes a part file untouched for ten minutes,
//! never takes a live one.
//!
//! A file's charge against the session's quota and file count is taken at
//! `begin` and given back when it is not finished: the quota bounds what a
//! session leaves on this disk.
//!
//! Each transfer's file I/O runs on one blocking worker ([`spawn_receiver`])
//! that owns its [`Incoming`] and is fed through a bounded channel. A stop
//! ([`Receiving::cancel`]) takes the file until the worker has verified it
//! and committed to putting it in place; from then on the file lands (or its
//! rename fails), and the worker's report says which: a transfer the host
//! stopped never lands, and one that lands is always reported. Nothing here
//! logs a name or a path.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;
use tornect_core::files::{
    create_new_private, is_part_name, nth, part_of, sanitize_name, user_folder,
};
use tornect_proto::services::reason;

/// How much free space a folder's disk has for this user, in bytes:
/// `tornect_platform::disk::available` on a real host, a fake in tests.
pub type FreeSpaceFn = Arc<dyn Fn(&Path) -> io::Result<u64> + Send + Sync>;

/// The free space every [`FreeSpaceFn`] of a default
/// [`ServicesEnv`](super::ServicesEnv) reports: none known, so nothing is
/// received.
pub(crate) fn unknown_free_space() -> FreeSpaceFn {
    Arc::new(|_: &Path| Err(io::Error::from(io::ErrorKind::Unsupported)))
}

/// The bytes written between two readings of the free space (design §5.1).
pub const RECHECK_FREE_EVERY: u64 = 64 << 20;

/// The highest `n` tried for a free `name (n).ext`.
const MAX_NTH: u32 = 999;

/// How often a receiving worker that waits for bytes touches its part file:
/// well within `tornect_core::files::STALE_AFTER` (ten minutes), after which
/// the sweep of another instance sharing the inbox would take it for a
/// crash's leftover. An upload paused by a lock, or whose viewer went quiet,
/// waits that long.
pub(crate) const TOUCH_EVERY: Duration = Duration::from_secs(60);

/// What names a file whatever its path: its device and inode. Only Unix has
/// it in `std`; elsewhere a file is taken at its name (decision M1-76).
type FileId = (u64, u64);

#[cfg(unix)]
fn file_id(meta: &fs::Metadata) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt as _;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn file_id(_: &fs::Metadata) -> Option<FileId> {
    None
}

/// Whether `meta` is of the file `id` names (any file where ids are not
/// known).
fn is_same(meta: &fs::Metadata, id: Option<FileId>) -> bool {
    id.is_none() || file_id(meta) == id
}

/// Whether `path` still names the regular file `id`, without following a
/// link, and, with `empty`, whether that file is empty.
fn still_names(path: &Path, id: Option<FileId>, empty: bool) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|m| m.file_type().is_file() && is_same(&m, id) && (!empty || m.len() == 0))
}

/// Where a worker finishing a file stands, for a test's hold on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Finishing {
    /// Synced and its hash checked; a stop still takes it.
    Verified,
    /// Committed: it is renamed into place next, whatever happens.
    Landing,
}

/// A test's hold on the workers finishing files.
#[cfg(test)]
pub(crate) type FinishHook = Arc<dyn Fn(Finishing) + Send + Sync>;

/// What a Windows Explorer download writes into a file's `Zone.Identifier`
/// stream: zone 3, the Internet. SmartScreen and Office's Protected View
/// read it.
#[cfg(any(windows, test))]
pub(crate) const ZONE_IDENTIFIER: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\n";

/// What an inbox takes (design §2.6, §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InboxLimits {
    /// The largest file, in bytes.
    pub(crate) max_file: u64,
    /// The bytes the session's files may hold in all.
    pub(crate) quota: u64,
    /// The files a session may leave.
    pub(crate) files: u32,
    /// The bytes the disk always keeps free.
    pub(crate) keep_free: u64,
    /// What a file counts toward `quota` at least, however small.
    pub(crate) min_charge: u64,
    /// Bytes written between two readings of the free space.
    pub(crate) recheck_every: u64,
}

/// What the files of a session took so far: charged at `begin`, given back
/// for a file that is not finished.
#[derive(Debug, Default)]
struct Tally {
    bytes: u64,
    files: u32,
}

/// One file's share of its session's [`Tally`], given back on drop unless
/// [`Charge::keep`] was called.
#[derive(Debug)]
struct Charge {
    tally: Arc<Mutex<Tally>>,
    bytes: u64,
    kept: bool,
}

impl Charge {
    fn keep(&mut self) {
        self.kept = true;
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        if !self.kept {
            let mut tally = lock(&self.tally);
            tally.bytes = tally.bytes.saturating_sub(self.bytes);
            tally.files = tally.files.saturating_sub(1);
        }
    }
}

/// Writes a file's mark of origin: the Windows `Zone.Identifier` stream, or
/// nothing elsewhere.
type MarkFn = fn(&Path) -> io::Result<()>;

/// The folder a session's files land in, with its limits (one per services
/// stream, so per session). Clones share the session's tally.
#[derive(Clone)]
pub(crate) struct Inbox {
    dir: PathBuf,
    limits: InboxLimits,
    free_space: FreeSpaceFn,
    tally: Arc<Mutex<Tally>>,
    mark: MarkFn,
    /// How often a waiting worker touches its part file ([`TOUCH_EVERY`]).
    touch_every: Duration,
    #[cfg(test)]
    finishing: Option<FinishHook>,
}

impl std::fmt::Debug for Inbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tally = lock(&self.tally);
        f.debug_struct("Inbox")
            .field("limits", &self.limits)
            .field("bytes", &tally.bytes)
            .field("files", &tally.files)
            .finish_non_exhaustive()
    }
}

impl Inbox {
    /// Files land in `dir` (made by [`Inbox::begin`] when missing), within
    /// `limits`, the disk's free space read through `free_space`.
    pub(crate) fn new(dir: PathBuf, limits: InboxLimits, free_space: FreeSpaceFn) -> Self {
        Self {
            dir,
            limits,
            free_space,
            tally: Arc::new(Mutex::new(Tally::default())),
            mark: mark_of_the_web,
            touch_every: TOUCH_EVERY,
            #[cfg(test)]
            finishing: None,
        }
    }

    /// The same inbox, with `mark` writing each part file's mark of origin.
    #[cfg(test)]
    pub(crate) fn with_mark(mut self, mark: MarkFn) -> Self {
        self.mark = mark;
        self
    }

    /// The same inbox, its waiting workers touching their part files every
    /// `every`.
    #[cfg(test)]
    pub(crate) fn with_touch_every(mut self, every: Duration) -> Self {
        self.touch_every = every;
        self
    }

    /// The same inbox, its workers calling `hook` as they finish a file.
    #[cfg(test)]
    pub(crate) fn with_finishing(mut self, hook: Option<FinishHook>) -> Self {
        self.finishing = hook;
        self
    }

    /// A worker finishing a file is at `stage` (a test may hold it there).
    fn at(&self, stage: Finishing) {
        #[cfg(test)]
        if let Some(hook) = &self.finishing {
            hook(stage);
        }
        #[cfg(not(test))]
        let _ = stage;
    }

    /// The session's files and bytes so far (charged ones included).
    #[cfg(test)]
    pub(crate) fn tally(&self) -> (u32, u64) {
        let tally = lock(&self.tally);
        (tally.files, tally.bytes)
    }

    /// Take a file the peer named `raw_name` of exactly `size` bytes, or say
    /// why not (a `tornect_proto::services::reason` code), in the design's
    /// order (§3.5): `TOO_LARGE` over the largest file; `QUOTA` past the
    /// session's file count or bytes (a file counts as
    /// [`InboxLimits::min_charge`] at least); `IO` when the folder is not a
    /// folder of this user or the free space cannot be read; `NO_SPACE` when
    /// the file would leave less than [`InboxLimits::keep_free`];
    /// `BAD_NAME` when nothing of the name is left once sanitised, or it is a
    /// part file's; `IO` when no name is free or a file cannot be made.
    /// Nothing is written before every check passed. Blocking: run it on the
    /// transfer's worker.
    pub(crate) fn begin(&self, raw_name: &str, size: u64) -> Result<Incoming, u16> {
        let limits = self.limits;
        if size > limits.max_file {
            return Err(reason::TOO_LARGE);
        }
        let charged = size.max(limits.min_charge);
        let charge = {
            let mut tally = lock(&self.tally);
            if tally.files >= limits.files
                || tally
                    .bytes
                    .checked_add(charged)
                    .is_none_or(|bytes| bytes > limits.quota)
            {
                return Err(reason::QUOTA);
            }
            tally.files += 1;
            tally.bytes += charged;
            Charge {
                tally: Arc::clone(&self.tally),
                bytes: charged,
                kept: false,
            }
        };
        // The free space is read of the folder itself (Windows reads it of a
        // folder only), so the folder is made, or checked, first.
        user_folder(&self.dir).map_err(|_| reason::IO)?;
        let free = (self.free_space)(&self.dir).map_err(|_| reason::IO)?;
        if free
            .checked_sub(size)
            .is_none_or(|left| left < limits.keep_free)
        {
            return Err(reason::NO_SPACE);
        }
        // A part file's name would be taken for a crash's leftover by
        // `sweep_stale`, and is never listed: such a name is not stored.
        let name = sanitize_name(raw_name)
            .filter(|name| !is_part_name(OsStr::new(name)))
            .ok_or(reason::BAD_NAME)?;
        let Reserved {
            final_path,
            final_id,
            reservation,
            part,
            file,
        } = reserve(&self.dir, &name)?;
        // Kept open on Unix, so that its inode stays its own while the
        // transfer lives; Windows would refuse the rename over an open file.
        #[cfg(not(unix))]
        drop(reservation);
        let stored = final_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let part_id = file.metadata().ok().and_then(|m| file_id(&m));
        let incoming = Incoming {
            file: Some(file),
            part,
            part_id,
            final_path,
            final_id,
            #[cfg(unix)]
            _reservation: reservation,
            stored,
            size,
            written: 0,
            hasher: Sha256::new(),
            dir: self.dir.clone(),
            keep_free: limits.keep_free,
            recheck_every: limits.recheck_every.max(1),
            next_check: limits.recheck_every.max(1),
            free_space: Arc::clone(&self.free_space),
            charge,
            finished: false,
        };
        // Fail closed: a file that cannot carry its mark is not taken. The
        // incoming's drop deletes both files.
        (self.mark)(&incoming.part).map_err(|_| reason::IO)?;
        Ok(incoming)
    }
}

/// A reserved name and the part file beside it.
struct Reserved {
    final_path: PathBuf,
    /// The reservation's id, taken from the file it made.
    final_id: Option<FileId>,
    /// The reservation, still open.
    reservation: File,
    part: PathBuf,
    file: File,
}

/// Reserve the first free name of `name`'s series in `dir` (`name`,
/// `name (2)`, … `name (999)`) with an empty private file, and create its
/// part file beside it.
fn reserve(dir: &Path, name: &str) -> Result<Reserved, u16> {
    for n in 1..=MAX_NTH {
        let final_path = dir.join(nth(name, n));
        let reservation = match create_new_private(&final_path) {
            Ok(reservation) => reservation,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(reason::IO),
        };
        let final_id = reservation.metadata().ok().and_then(|m| file_id(&m));
        let part = part_of(&final_path);
        match create_new_private(&part) {
            Ok(file) => {
                return Ok(Reserved {
                    final_path,
                    final_id,
                    reservation,
                    part,
                    file,
                });
            }
            Err(e) => {
                drop(reservation);
                let _ = fs::remove_file(&final_path);
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(reason::IO);
                }
            }
        }
    }
    Err(reason::IO)
}

/// Where Windows keeps a file's mark of origin: its `Zone.Identifier`
/// alternate data stream.
#[cfg(any(windows, test))]
pub(crate) fn zone_stream(part: &Path) -> PathBuf {
    let mut stream = part.as_os_str().to_os_string();
    stream.push(":Zone.Identifier");
    PathBuf::from(stream)
}

/// Mark the part file as downloaded from the Internet ([`ZONE_IDENTIFIER`]
/// in [`zone_stream`]). It fails on a volume without alternate data streams
/// (FAT, exFAT) or when an antivirus holds the file.
#[cfg(windows)]
fn mark_of_the_web(part: &Path) -> io::Result<()> {
    let mut stream = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(zone_stream(part))?;
    stream.write_all(ZONE_IDENTIFIER)
}

/// Only Windows has a mark of origin that moves with a file.
#[cfg(not(windows))]
fn mark_of_the_web(_: &Path) -> io::Result<()> {
    Ok(())
}

/// A file being received: written to its part file in order, then checked
/// ([`Incoming::verify`]) and put in place ([`Verified::put_in_place`]).
/// Dropped unfinished, it deletes its part file and its reservation (the
/// files it made, never another's) and gives its charge back.
pub(crate) struct Incoming {
    /// The part file, open until it is verified (on Unix until it is in
    /// place, so that its inode stays its own).
    file: Option<File>,
    part: PathBuf,
    part_id: Option<FileId>,
    final_path: PathBuf,
    final_id: Option<FileId>,
    /// The reservation, open while the transfer lives (Unix).
    #[cfg(unix)]
    _reservation: File,
    stored: String,
    size: u64,
    written: u64,
    hasher: Sha256,
    dir: PathBuf,
    keep_free: u64,
    recheck_every: u64,
    next_check: u64,
    free_space: FreeSpaceFn,
    charge: Charge,
    finished: bool,
}

impl std::fmt::Debug for Incoming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Incoming")
            .field("size", &self.size)
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

impl Incoming {
    /// The name the file is stored under (sanitised, numbered when taken).
    pub(crate) fn stored(&self) -> &str {
        &self.stored
    }

    /// The bytes written so far.
    #[cfg(test)]
    pub(crate) fn written(&self) -> u64 {
        self.written
    }

    /// Write `bytes`, which start at `offset` of the file: the bytes written
    /// so far, or `PROTOCOL` when they do not follow on or go past the size;
    /// `NO_SPACE` when the disk is full, or when a re-reading of the free
    /// space finds less than the file still needs on top of what the disk
    /// keeps free; `IO` for any other failure.
    pub(crate) fn write(&mut self, offset: u64, bytes: &[u8]) -> Result<u64, u16> {
        let len = bytes.len() as u64;
        if offset != self.written || len > self.size - self.written {
            return Err(reason::PROTOCOL);
        }
        let file = self.file.as_mut().ok_or(reason::IO)?;
        file.write_all(bytes).map_err(|e| match e.kind() {
            io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => reason::NO_SPACE,
            _ => reason::IO,
        })?;
        self.hasher.update(bytes);
        self.written += len;
        if self.written >= self.next_check && self.written < self.size {
            self.next_check = self.written.saturating_add(self.recheck_every);
            let free = (self.free_space)(&self.dir).map_err(|_| reason::IO)?;
            if free
                .checked_sub(self.size - self.written)
                .is_none_or(|left| left < self.keep_free)
            {
                return Err(reason::NO_SPACE);
            }
        }
        Ok(self.written)
    }

    /// Move the part file's modification time to now: a part file whose
    /// time moves is never taken for a crash's leftover (`sweep_stale`).
    /// Best effort.
    fn touch(&self) {
        if let Some(file) = &self.file {
            let _ = file.set_modified(SystemTime::now());
        }
    }

    /// Once the sender said it sent everything with this SHA-256: sync the
    /// part file and check its length and hash. `CORRUPT` when either is
    /// not the sender's, `IO` when the sync fails; the files are deleted
    /// then.
    pub(crate) fn verify(mut self, sha256: &[u8; 32]) -> Result<Verified, u16> {
        if self.written != self.size {
            return Err(reason::CORRUPT);
        }
        let file = self.file.as_ref().ok_or(reason::IO)?;
        file.sync_all().map_err(|_| reason::IO)?;
        // Windows has no file id to keep: the part file is closed once
        // synced.
        #[cfg(not(unix))]
        drop(self.file.take());
        let hasher = std::mem::take(&mut self.hasher);
        let got: [u8; 32] = hasher.finalize().into();
        if &got != sha256 {
            return Err(reason::CORRUPT);
        }
        Ok(Verified(self))
    }

    /// [`Self::verify`], then [`Verified::put_in_place`].
    #[cfg(test)]
    pub(crate) fn finish(self, sha256: &[u8; 32]) -> Result<PathBuf, u16> {
        self.verify(sha256)?.put_in_place()
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Closed first on Windows, which deletes an open file only once it
        // is closed. On Unix the files stay open until they are deleted, so
        // that no other file can take their inodes before the checks.
        #[cfg(not(unix))]
        drop(self.file.take());
        // Only the files this transfer made: the reservation still empty.
        if still_names(&self.part, self.part_id, false) {
            let _ = fs::remove_file(&self.part);
        }
        if still_names(&self.final_path, self.final_id, true) {
            let _ = fs::remove_file(&self.final_path);
        }
    }
}

/// A file synced, whose length and hash are the sender's. Dropped, it
/// deletes its files as an unfinished [`Incoming`] does.
pub(crate) struct Verified(Incoming);

impl std::fmt::Debug for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Verified").field(&self.0).finish()
    }
}

impl Verified {
    /// Rename the part file over the reservation: the final path, or `IO`
    /// when the rename fails or either path no longer names the file this
    /// transfer made (the reservation still empty); the files it made are
    /// deleted then.
    pub(crate) fn put_in_place(mut self) -> Result<PathBuf, u16> {
        let incoming = &mut self.0;
        if !still_names(&incoming.part, incoming.part_id, false)
            || !still_names(&incoming.final_path, incoming.final_id, true)
        {
            return Err(reason::IO);
        }
        fs::rename(&incoming.part, &incoming.final_path).map_err(|_| reason::IO)?;
        incoming.finished = true;
        incoming.charge.keep();
        Ok(incoming.final_path.clone())
    }
}

/// What the loop gives a receiving worker.
#[derive(Debug)]
pub(crate) enum Work {
    /// Bytes that follow on.
    Write(Vec<u8>),
    /// The sender sent everything, with this SHA-256.
    Finish([u8; 32]),
}

/// What a receiving worker tells the loop.
#[derive(Debug)]
pub(crate) struct WorkerEvent {
    /// The transfer.
    pub(crate) xfer: u32,
    /// What happened.
    pub(crate) what: Worked,
}

/// What happened on a receiving worker.
#[derive(Debug)]
pub(crate) enum Worked {
    /// The file was taken under this stored name, or refused with this
    /// reason (nothing was written).
    Began(Result<String, u16>),
    /// Bytes written so far.
    Written(u64),
    /// The file is in place, or it failed and was deleted (the reason).
    Finished(Result<(), u16>),
    /// Writing failed with this reason; the files are deleted.
    Failed(u16),
}

/// A worker runs: a stop takes its file.
const RUNNING: u8 = 0;
/// Stopped: the worker writes nothing more and deletes what it wrote.
const STOPPED: u8 = 1;
/// Past the point of no return: the worker puts the file in place, and its
/// report says whether it landed.
const LANDING: u8 = 2;

/// A receiving worker's handle, kept by the loop.
#[derive(Debug)]
pub(crate) struct Receiving {
    feed: Option<std::sync::mpsc::SyncSender<Work>>,
    /// [`RUNNING`], [`STOPPED`] or [`LANDING`], shared with the worker.
    state: Arc<AtomicU8>,
    worker: tokio::task::Id,
}

impl Receiving {
    /// Hand the worker `work` without waiting: `false` when its queue is full
    /// (the sender did not keep to its window) or the worker is gone.
    pub(crate) fn feed(&self, work: Work) -> Result<(), Fed> {
        let Some(feed) = &self.feed else {
            return Err(Fed::Gone);
        };
        feed.try_send(work).map_err(|e| match e {
            std::sync::mpsc::TrySendError::Full(_) => Fed::Full,
            std::sync::mpsc::TrySendError::Disconnected(_) => Fed::Gone,
        })
    }

    /// Stop the worker: it writes at most the chunk it is writing, then drops
    /// its file, which deletes the partial files; it reports nothing more.
    /// `false` when it is too late: the worker verified the file and is
    /// putting it in place, and its `Finished` report says whether it landed.
    pub(crate) fn cancel(&mut self) -> bool {
        self.feed = None;
        match self
            .state
            .compare_exchange(RUNNING, STOPPED, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => true,
            Err(now) => now == STOPPED,
        }
    }

    /// The worker's task, as its [`tokio::task::JoinSet`] names it.
    pub(crate) fn worker(&self) -> tokio::task::Id {
        self.worker
    }
}

impl Drop for Receiving {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Why a [`Receiving::feed`] did not hand its work over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fed {
    /// The worker's queue is full.
    Full,
    /// The worker ended (it failed, or was cancelled).
    Gone,
}

/// Start the blocking worker of transfer `xfer`: it begins `raw_name` of
/// `size` bytes in `inbox` and reports `Began`, then writes what it is fed
/// (at most `depth` items queued), reporting `Written` after each write,
/// until `Finish` (`Finished`), a failure (`Failed`, after the files were
/// deleted), its stop, or its feed's end. While it waits for work it touches
/// its part file every [`TOUCH_EVERY`]. On `Finish` it verifies the file,
/// then commits to putting it in place unless it was stopped meanwhile: from
/// that point a stop no longer takes the file, and `Finished` is always
/// reported. Spawned on `workers`, so that the loop can wait for it at its
/// end.
pub(crate) fn spawn_receiver(
    workers: &mut tokio::task::JoinSet<()>,
    xfer: u32,
    inbox: Inbox,
    raw_name: String,
    size: u64,
    depth: usize,
    events: mpsc::UnboundedSender<WorkerEvent>,
) -> Receiving {
    let (feed, work) = std::sync::mpsc::sync_channel(depth.max(1));
    let state = Arc::new(AtomicU8::new(RUNNING));
    let shared = Arc::clone(&state);
    let worker = workers
        .spawn_blocking(move || {
            let report = |what: Worked| {
                let _ = events.send(WorkerEvent { xfer, what });
            };
            let stopped = || shared.load(Ordering::SeqCst) == STOPPED;
            let mut incoming = match inbox.begin(&raw_name, size) {
                Ok(incoming) => incoming,
                Err(code) => return report(Worked::Began(Err(code))),
            };
            if stopped() {
                return;
            }
            report(Worked::Began(Ok(incoming.stored().to_owned())));
            loop {
                let work = match work.recv_timeout(inbox.touch_every) {
                    Ok(work) => work,
                    Err(RecvTimeoutError::Timeout) => {
                        incoming.touch();
                        continue;
                    }
                    Err(RecvTimeoutError::Disconnected) => return,
                };
                if stopped() {
                    return;
                }
                match work {
                    Work::Write(bytes) => {
                        let offset = incoming.written;
                        match incoming.write(offset, &bytes) {
                            Ok(upto) => report(Worked::Written(upto)),
                            Err(code) => {
                                drop(incoming);
                                return report(Worked::Failed(code));
                            }
                        }
                    }
                    Work::Finish(sha256) => {
                        let verified = match incoming.verify(&sha256) {
                            Ok(verified) => verified,
                            Err(code) => return report(Worked::Finished(Err(code))),
                        };
                        inbox.at(Finishing::Verified);
                        // A stop that came first takes the file: dropped, it
                        // deletes what it wrote, and nothing is reported.
                        if shared
                            .compare_exchange(RUNNING, LANDING, Ordering::SeqCst, Ordering::SeqCst)
                            .is_err()
                        {
                            return;
                        }
                        inbox.at(Finishing::Landing);
                        return report(Worked::Finished(verified.put_in_place().map(drop)));
                    }
                }
            }
        })
        .id();
    Receiving {
        feed: Some(feed),
        state,
        worker,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64};

    use tornect_core::files::{STALE_AFTER, sweep_stale};

    use super::*;

    const LIMITS: InboxLimits = InboxLimits {
        max_file: 1 << 20,
        quota: 4 << 20,
        files: 1000,
        keep_free: 1 << 20,
        min_charge: 4096,
        recheck_every: RECHECK_FREE_EVERY,
    };

    /// A disk with `free` bytes free, whatever is written.
    fn disk(free: &Arc<AtomicU64>) -> FreeSpaceFn {
        let free = Arc::clone(free);
        Arc::new(move |_: &Path| Ok(free.load(Ordering::SeqCst)))
    }

    fn plenty() -> FreeSpaceFn {
        Arc::new(|_: &Path| Ok(u64::MAX / 2))
    }

    /// An inbox in `home`. Its part files get no mark of origin: Wine,
    /// which runs these tests' Windows build, has no alternate data streams
    /// and makes a separate `…:Zone.Identifier` file instead, which NTFS
    /// never does; the real mark has its own test on NTFS
    /// (`the_mark_moves_with_the_file`).
    fn inbox_in(home: &tempfile::TempDir, limits: InboxLimits, free: FreeSpaceFn) -> Inbox {
        Inbox::new(home.path().join("Tornect"), limits, free).with_mark(|_| Ok(()))
    }

    /// The names in `dir`, sorted.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn sha(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// A file arrives in order under its sanitised name: reserved and
    /// written beside it as a private part file, then renamed over the
    /// reservation once its hash is the sender's.
    #[test]
    fn a_file_is_reserved_written_verified_and_put_in_place() {
        let home = tempfile::tempdir().unwrap();
        let inbox = inbox_in(&home, LIMITS, plenty());
        let dir = home.path().join("Tornect");
        let mut incoming = inbox.begin("../../etc/my\u{202e}notes.txt", 10).unwrap();
        assert_eq!(incoming.stored(), "mynotes.txt");
        assert!(dir.is_dir(), "the folder is made");
        assert_eq!(names(&dir), ["mynotes.txt", "mynotes.txt.tornect-part"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for name in ["mynotes.txt", "mynotes.txt.tornect-part"] {
                let mode = fs::metadata(dir.join(name)).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{name}");
            }
            let mode = fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        assert_eq!(incoming.write(0, b"hello").unwrap(), 5);
        assert_eq!(incoming.write(5, b"world").unwrap(), 10);
        assert_eq!(incoming.written(), 10);
        let path = incoming.finish(&sha(b"helloworld")).unwrap();
        assert_eq!(path, dir.join("mynotes.txt"));
        assert_eq!(fs::read(&path).unwrap(), b"helloworld");
        assert_eq!(names(&dir), ["mynotes.txt"]);
        assert_eq!(inbox.tally(), (1, 4096), "a small file counts 4 KiB");

        // The same name again: the next free one in the series.
        let second = inbox.begin("mynotes.txt", 0).unwrap();
        assert_eq!(second.stored(), "mynotes (2).txt");
        let third = inbox.begin("mynotes.txt", 0).unwrap();
        assert_eq!(third.stored(), "mynotes (3).txt");
        drop(second);
        assert_eq!(
            names(&dir),
            [
                "mynotes (3).txt",
                "mynotes (3).txt.tornect-part",
                "mynotes.txt"
            ]
        );
        assert_eq!(
            third.finish(&sha(b"")).unwrap(),
            dir.join("mynotes (3).txt")
        );
        assert_eq!(inbox.tally(), (2, 8192));
    }

    /// Bytes out of order or past the size are a protocol error; a length or
    /// a hash that is not the sender's is `CORRUPT`, and the files go.
    #[test]
    fn order_size_length_and_hash_are_checked() {
        let home = tempfile::tempdir().unwrap();
        let inbox = inbox_in(&home, LIMITS, plenty());
        let dir = home.path().join("Tornect");

        let mut incoming = inbox.begin("a.bin", 4).unwrap();
        assert_eq!(incoming.write(1, b"x"), Err(reason::PROTOCOL));
        assert_eq!(incoming.write(0, b"abcde"), Err(reason::PROTOCOL));
        assert_eq!(incoming.write(0, b"ab").unwrap(), 2);
        assert_eq!(incoming.write(0, b"ab"), Err(reason::PROTOCOL));
        assert_eq!(incoming.finish(&sha(b"ab")), Err(reason::CORRUPT));
        assert_eq!(names(&dir), Vec::<String>::new());

        let mut incoming = inbox.begin("a.bin", 4).unwrap();
        incoming.write(0, b"abcd").unwrap();
        assert_eq!(incoming.finish(&sha(b"abce")), Err(reason::CORRUPT));
        assert_eq!(names(&dir), Vec::<String>::new());
        assert_eq!(inbox.tally(), (0, 0), "nothing left, nothing charged");
    }

    /// The design's order of refusals, each before anything is written.
    #[test]
    fn refusals_come_before_any_byte() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("Tornect");
        let free = Arc::new(AtomicU64::new(3 << 20));
        let inbox = inbox_in(&home, LIMITS, disk(&free));

        assert_eq!(
            inbox.begin("big", LIMITS.max_file + 1).err(),
            Some(reason::TOO_LARGE)
        );
        assert!(!dir.exists(), "nothing made for a refusal by size");
        // 3 MiB free, 1 MiB kept: 2 MiB may be written.
        assert_eq!(inbox.begin("x", 1 << 20).map(|_| ()).err(), None);
        free.store((2 << 20) - 1, Ordering::SeqCst);
        assert_eq!(inbox.begin("x", 1 << 20).err(), Some(reason::NO_SPACE));
        free.store(10, Ordering::SeqCst);
        assert_eq!(inbox.begin("x", 0).err(), Some(reason::NO_SPACE));
        free.store(u64::MAX / 2, Ordering::SeqCst);
        for bad in [
            "",
            "...",
            " / ",
            "\u{202e}\u{200b}",
            "x.tornect-part",
            "X.TORNECT-PART",
        ] {
            assert_eq!(inbox.begin(bad, 1).err(), Some(reason::BAD_NAME), "{bad:?}");
        }
        assert_eq!(names(&dir), Vec::<String>::new());
        assert_eq!(inbox.tally(), (0, 0), "refused files charge nothing");

        // The free space cannot be read: refused, not guessed.
        let unknown = inbox_in(&home, LIMITS, unknown_free_space());
        assert_eq!(unknown.begin("x", 1).err(), Some(reason::IO));

        // The folder is a link: refused.
        #[cfg(unix)]
        {
            let elsewhere = tempfile::tempdir().unwrap();
            let link = home.path().join("Linked");
            std::os::unix::fs::symlink(elsewhere.path(), &link).unwrap();
            let linked = Inbox::new(link, LIMITS, plenty()).with_mark(|_| Ok(()));
            assert_eq!(linked.begin("x", 1).err(), Some(reason::IO));
            assert_eq!(names(elsewhere.path()), Vec::<String>::new());
        }
    }

    /// The session's quota counts each file at 4 KiB at least, and the file
    /// count stops at its limit; files not finished give their charge back.
    #[test]
    fn the_quota_and_the_file_count_hold() {
        let home = tempfile::tempdir().unwrap();
        let limits = InboxLimits {
            quota: 3 * 4096 + 100,
            ..LIMITS
        };
        let inbox = inbox_in(&home, limits, plenty());
        let held: Vec<Incoming> = (0..3)
            .map(|n| inbox.begin(&format!("f{n}"), 1).unwrap())
            .collect();
        assert_eq!(inbox.begin("f3", 1).err(), Some(reason::QUOTA));
        assert_eq!(inbox.tally(), (3, 3 * 4096));
        drop(held);
        assert_eq!(inbox.tally(), (0, 0));
        // Larger files count their size: 3 × 4 KiB of the 3 × 4 KiB + 100
        // taken, no file fits.
        let big = inbox.begin("big", 3 * 4096).unwrap();
        assert_eq!(inbox.begin("f", 1).err(), Some(reason::QUOTA));
        drop(big);
        let roomy = inbox_in(
            &home,
            InboxLimits {
                quota: 4 * 4096,
                ..LIMITS
            },
            plenty(),
        );
        let _big = roomy.begin("big", 3 * 4096).unwrap();
        assert_eq!(roomy.begin("f", 4097).err(), Some(reason::QUOTA));
        assert!(roomy.begin("f", 4096).is_ok());

        let few = inbox_in(&home, InboxLimits { files: 2, ..LIMITS }, plenty());
        let mut a = few.begin("a", 1).unwrap();
        a.write(0, b"a").unwrap();
        a.finish(&sha(b"a")).unwrap();
        let _b = few.begin("b", 1).unwrap();
        assert_eq!(few.begin("c", 1).err(), Some(reason::QUOTA));
    }

    /// While a file is written the free space is read again every
    /// `recheck_every` bytes: when what is left of the file would take the
    /// disk below what it keeps free, the file fails with `NO_SPACE`.
    #[test]
    fn the_free_space_is_read_again_while_writing() {
        let home = tempfile::tempdir().unwrap();
        let free = Arc::new(AtomicU64::new(10 << 20));
        let limits = InboxLimits {
            recheck_every: 4,
            ..LIMITS
        };
        let inbox = inbox_in(&home, limits, disk(&free));
        let mut incoming = inbox.begin("f", 12).unwrap();
        assert_eq!(incoming.write(0, b"abc").unwrap(), 3);
        // Something else filled the disk: 1 MiB + 7 bytes free and, once the
        // fourth byte is written, 8 to come.
        free.store((1 << 20) + 7, Ordering::SeqCst);
        assert_eq!(incoming.write(3, b"d"), Err(reason::NO_SPACE));
        drop(incoming);
        assert_eq!(names(&home.path().join("Tornect")), Vec::<String>::new());

        free.store((1 << 20) + 8, Ordering::SeqCst);
        let mut incoming = inbox.begin("g", 8).unwrap();
        incoming.write(0, b"abcd").unwrap();
        incoming.write(4, b"efgh").unwrap();
        incoming.finish(&sha(b"abcdefgh")).unwrap();
    }

    /// A part file that cannot carry its mark of origin fails the file before
    /// a byte, and leaves nothing behind (fail closed).
    #[test]
    fn a_file_whose_mark_cannot_be_written_is_refused_and_removed() {
        let home = tempfile::tempdir().unwrap();
        let inbox = inbox_in(&home, LIMITS, plenty())
            .with_mark(|_| Err(io::Error::from(io::ErrorKind::Unsupported)));
        assert_eq!(inbox.begin("setup.exe", 10).err(), Some(reason::IO));
        assert_eq!(names(&home.path().join("Tornect")), Vec::<String>::new());
        assert_eq!(inbox.tally(), (0, 0));
    }

    /// The mark of origin's stream and its contents.
    #[test]
    fn the_mark_of_the_web_names_the_internet_zone() {
        assert_eq!(
            zone_stream(Path::new("inbox/setup.exe.tornect-part")),
            PathBuf::from("inbox/setup.exe.tornect-part:Zone.Identifier")
        );
        assert_eq!(ZONE_IDENTIFIER, b"[ZoneTransfer]\r\nZoneId=3\r\n");
    }

    /// On Windows the part file carries its mark, and it moves with the
    /// rename (needs NTFS: not under Wine).
    #[cfg(windows)]
    #[test]
    #[ignore = "needs an NTFS volume (Windows); see docs/VERIFICATION.md"]
    fn the_mark_moves_with_the_file() {
        let home = tempfile::tempdir().unwrap();
        let inbox = Inbox::new(home.path().join("Tornect"), LIMITS, plenty());
        let mut incoming = inbox.begin("setup.exe", 2).unwrap();
        incoming.write(0, b"MZ").unwrap();
        let path = incoming.finish(&sha(b"MZ")).unwrap();
        assert_eq!(fs::read(zone_stream(&path)).unwrap(), ZONE_IDENTIFIER);
    }

    /// A taken name whose part file is somehow there already moves on to the
    /// next name; a user's file of the same name is never touched.
    #[test]
    fn taken_names_and_stray_part_files_are_skipped() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("Tornect");
        user_folder(&dir).unwrap();
        fs::write(dir.join("r.txt"), b"mine").unwrap();
        fs::write(dir.join("r (2).txt.tornect-part"), b"stray").unwrap();
        let inbox = inbox_in(&home, LIMITS, plenty());
        let incoming = inbox.begin("r.txt", 1).unwrap();
        assert_eq!(incoming.stored(), "r (3).txt");
        drop(incoming);
        assert_eq!(names(&dir), ["r (2).txt.tornect-part", "r.txt"]);
        assert_eq!(fs::read(dir.join("r.txt")).unwrap(), b"mine");
    }

    /// The worker begins, writes what it is fed and reports it, finishes;
    /// cancelled or left without a feed, it deletes the partial files; a
    /// refusal is reported before anything is written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_receiving_worker_writes_reports_and_cleans_up() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("Tornect");
        let inbox = inbox_in(&home, LIMITS, plenty());
        let mut workers = tokio::task::JoinSet::new();
        let (tx, mut events) = mpsc::unbounded_channel();

        let mut next = async || events.recv().await.unwrap();
        let receiver = spawn_receiver(
            &mut workers,
            1,
            inbox.clone(),
            "a.txt".into(),
            6,
            4,
            tx.clone(),
        );
        let ev = next().await;
        assert_eq!(ev.xfer, 1);
        assert!(matches!(ev.what, Worked::Began(Ok(ref name)) if name == "a.txt"));
        receiver.feed(Work::Write(b"abc".to_vec())).unwrap();
        receiver.feed(Work::Write(b"def".to_vec())).unwrap();
        receiver.feed(Work::Finish(sha(b"abcdef"))).unwrap();
        assert!(matches!(next().await.what, Worked::Written(3)));
        assert!(matches!(next().await.what, Worked::Written(6)));
        assert!(matches!(next().await.what, Worked::Finished(Ok(_))));
        assert_eq!(fs::read(dir.join("a.txt")).unwrap(), b"abcdef");
        drop(receiver);

        // Refused by size: reported, nothing made.
        let _refused = spawn_receiver(
            &mut workers,
            2,
            inbox.clone(),
            "b".into(),
            1 << 30,
            4,
            tx.clone(),
        );
        assert!(matches!(
            next().await.what,
            Worked::Began(Err(reason::TOO_LARGE))
        ));

        // Bytes past the size fail the file, which is deleted before that
        // is told.
        let past = spawn_receiver(&mut workers, 6, inbox.clone(), "e".into(), 2, 4, tx.clone());
        assert!(matches!(next().await.what, Worked::Began(Ok(_))));
        past.feed(Work::Write(b"abc".to_vec())).unwrap();
        assert!(matches!(
            next().await.what,
            Worked::Failed(reason::PROTOCOL)
        ));
        assert_eq!(names(&dir), ["a.txt"]);
        drop(past);

        // Cancelled mid-way, and dropped mid-way: the partials go.
        for (xfer, cancel) in [(3, true), (4, false)] {
            let mut receiver = spawn_receiver(
                &mut workers,
                xfer,
                inbox.clone(),
                "c".into(),
                10,
                4,
                tx.clone(),
            );
            assert!(matches!(next().await.what, Worked::Began(Ok(_))));
            receiver.feed(Work::Write(b"12345".to_vec())).unwrap();
            assert!(matches!(next().await.what, Worked::Written(5)));
            if cancel {
                receiver.cancel();
                assert_eq!(receiver.feed(Work::Write(b"6".to_vec())), Err(Fed::Gone));
            } else {
                drop(receiver);
            }
            while workers.try_join_next().is_some() {}
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while names(&dir) != ["a.txt"] {
                assert!(std::time::Instant::now() < deadline, "{:?}", names(&dir));
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        // A full queue says so: the feed is bounded.
        let (gate_tx, gate) = std::sync::mpsc::channel::<()>();
        let (entered_tx, entered) = std::sync::mpsc::channel::<()>();
        let gate = Arc::new(Mutex::new((gate, entered_tx)));
        let blocked: FreeSpaceFn = {
            let calls = Arc::new(AtomicU64::new(0));
            Arc::new(move |_: &Path| {
                // The first reading (at `begin`) answers; the next waits.
                if calls.fetch_add(1, Ordering::SeqCst) > 0 {
                    let gate = lock(&gate);
                    let _ = gate.1.send(());
                    let _ = gate.0.recv();
                }
                Ok(u64::MAX / 2)
            })
        };
        let slow = inbox_in(
            &home,
            InboxLimits {
                recheck_every: 1,
                ..LIMITS
            },
            blocked,
        );
        let receiving = spawn_receiver(&mut workers, 5, slow, "d".into(), 100, 2, tx.clone());
        assert!(matches!(next().await.what, Worked::Began(Ok(_))));
        // The first write waits on the free space; two more fill the queue.
        receiving.feed(Work::Write(vec![1])).unwrap();
        tokio::task::spawn_blocking(move || entered.recv().unwrap())
            .await
            .unwrap();
        receiving.feed(Work::Write(vec![1])).unwrap();
        receiving.feed(Work::Write(vec![1])).unwrap();
        assert_eq!(receiving.feed(Work::Write(vec![1])), Err(Fed::Full));
        drop(receiving);
        drop(gate_tx);
        while workers.join_next().await.is_some() {}
        assert_eq!(names(&dir), ["a.txt"]);
    }

    /// A stop takes the file until its worker has verified it and committed
    /// to putting it in place, and nothing is reported then; once committed,
    /// the stop says it is too late, the file lands and `Finished` is
    /// reported, so that the loop never claims a cancel for a file that
    /// lands.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stop_takes_the_file_until_its_worker_commits() {
        for at in [Finishing::Verified, Finishing::Landing] {
            let home = tempfile::tempdir().unwrap();
            let dir = home.path().join("Tornect");
            let hold = Arc::new(AtomicBool::new(true));
            let (entered_tx, entered) = std::sync::mpsc::channel::<()>();
            let hook: FinishHook = {
                let hold = Arc::clone(&hold);
                Arc::new(move |stage| {
                    if stage == at {
                        let _ = entered_tx.send(());
                        while hold.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                })
            };
            let inbox = inbox_in(&home, LIMITS, plenty()).with_finishing(Some(hook));
            let mut workers = tokio::task::JoinSet::new();
            let (tx, mut events) = mpsc::unbounded_channel();
            let mut receiving = spawn_receiver(&mut workers, 1, inbox, "f.txt".into(), 3, 4, tx);
            assert!(matches!(
                events.recv().await.unwrap().what,
                Worked::Began(Ok(_))
            ));
            receiving.feed(Work::Write(b"abc".to_vec())).unwrap();
            receiving.feed(Work::Finish(sha(b"abc"))).unwrap();
            assert!(matches!(
                events.recv().await.unwrap().what,
                Worked::Written(3)
            ));
            tokio::task::spawn_blocking(move || entered.recv().unwrap())
                .await
                .unwrap();
            let stopped = receiving.cancel();
            assert_eq!(stopped, at == Finishing::Verified, "{at:?}");
            hold.store(false, Ordering::SeqCst);
            while workers.join_next().await.is_some() {}
            if stopped {
                assert!(events.try_recv().is_err(), "nothing reported");
                assert_eq!(names(&dir), Vec::<String>::new());
            } else {
                assert!(matches!(
                    events.try_recv().unwrap().what,
                    Worked::Finished(Ok(()))
                ));
                assert_eq!(names(&dir), ["f.txt"]);
                assert_eq!(fs::read(dir.join("f.txt")).unwrap(), b"abc");
            }
            assert_eq!(receiving.cancel(), stopped, "a second stop: the same");
        }
    }

    /// A worker waiting for bytes touches its part file, so that the stale
    /// sweep of another instance sharing the inbox never takes it, however
    /// long the sender is quiet (a lock pauses it, its viewer stalls).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_waiting_worker_keeps_its_part_file_fresh() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("Tornect");
        let inbox = inbox_in(&home, LIMITS, plenty()).with_touch_every(Duration::from_millis(20));
        let mut workers = tokio::task::JoinSet::new();
        let (tx, mut events) = mpsc::unbounded_channel();
        let receiving = spawn_receiver(&mut workers, 1, inbox, "q.txt".into(), 10, 4, tx);
        assert!(matches!(
            events.recv().await.unwrap().what,
            Worked::Began(Ok(_))
        ));
        let part = dir.join("q.txt.tornect-part");
        // As a sweep would find a part file left an hour ago.
        fs::OpenOptions::new()
            .write(true)
            .open(&part)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        let fresh = || {
            fs::metadata(&part)
                .unwrap()
                .modified()
                .unwrap()
                .elapsed()
                .is_ok_and(|age| age < Duration::from_secs(60))
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !fresh() {
            assert!(std::time::Instant::now() < deadline, "never touched");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(sweep_stale(&dir, STALE_AFTER).unwrap(), 0);
        assert_eq!(names(&dir), ["q.txt", "q.txt.tornect-part"]);
        drop(receiving);
        while workers.join_next().await.is_some() {}
        assert_eq!(names(&dir), Vec::<String>::new());
    }

    /// The files a transfer made are taken by their inode: once a sweep took
    /// them and another transfer reserved the same name, the first neither
    /// renames its file over the other's reservation nor deletes the other's
    /// files, whether it finishes or is dropped.
    #[cfg(unix)]
    #[test]
    fn a_transfer_takes_only_the_files_it_made() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("Tornect");
        let inbox = inbox_in(&home, LIMITS, plenty());
        let sweep = |name: &str| {
            fs::remove_file(dir.join(format!("{name}.tornect-part"))).unwrap();
            fs::remove_file(dir.join(name)).unwrap();
        };

        let mut first = inbox.begin("x.txt", 3).unwrap();
        first.write(0, b"old").unwrap();
        sweep("x.txt");
        let mut second = inbox.begin("x.txt", 3).unwrap();
        assert_eq!(second.stored(), "x.txt");
        second.write(0, b"new").unwrap();
        assert_eq!(first.finish(&sha(b"old")), Err(reason::IO));
        assert_eq!(names(&dir), ["x.txt", "x.txt.tornect-part"], "left alone");
        assert_eq!(second.finish(&sha(b"new")).unwrap(), dir.join("x.txt"));
        assert_eq!(fs::read(dir.join("x.txt")).unwrap(), b"new");

        let third = inbox.begin("y.txt", 1).unwrap();
        sweep("y.txt");
        let fourth = inbox.begin("y.txt", 1).unwrap();
        drop(third);
        assert_eq!(names(&dir), ["x.txt", "y.txt", "y.txt.tornect-part"]);
        drop(fourth);
        assert_eq!(names(&dir), ["x.txt"]);
        assert_eq!(inbox.tally(), (1, 4096), "only the file in place counts");
    }
}
