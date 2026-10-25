//! What both ends keep of a file transfer (the services design §3.1, §3.5,
//! §6.1): the rows they report, the transfer ids, and the sending side, which
//! reads a file on a blocking worker and sends it within the bulk window.
//!
//! Transfer ids are the viewer's, for both directions, counting up from 1;
//! 0 is the clipboard's credit. A frame for a transfer that ended lately
//! (one of the last [`ENDED_KEPT`]) was in flight and is dropped; one for an
//! id never seen, or a new transfer under an id already used, ends the
//! stream with `Close{PROTOCOL}`.

use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tornect_core::files::sanitize_name;
use tornect_proto::services::{Done, SvcMsg, reason};

use super::window::Window;
use super::writer::Outbox;

/// Ended transfers whose late frames are dropped rather than refused.
pub(crate) const ENDED_KEPT: usize = 64;

/// Uploads the host runs at once in a session (design §3.4): a third offer
/// gets `Cancel{BUSY}`, so the viewer keeps further ones queued.
pub const MAX_UPLOADS: usize = 2;

/// What a name shows when nothing of it is left once sanitised.
const NO_NAME: &str = "file";

/// A name from a file system or the other computer, fit to show: built only
/// through `tornect_core::files::sanitize_name`, so it holds no folder, no
/// control or invisible character and at most 200 bytes. Shown as plain text;
/// its `Debug` prints its length only (design §2.5: `tracing` never carries
/// a file name).
#[derive(Clone, PartialEq, Eq)]
pub struct Untrusted(String);

impl Untrusted {
    /// `raw` sanitised as a file name, or the word "file" when nothing of it
    /// is left.
    #[must_use]
    pub fn file_name(raw: &str) -> Self {
        Self(sanitize_name(raw).unwrap_or_else(|| NO_NAME.to_owned()))
    }

    /// The name, plain.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Its length in characters.
    #[must_use]
    pub fn chars(&self) -> usize {
        self.0.chars().count()
    }
}

impl fmt::Debug for Untrusted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Untrusted(<{} chars>)", self.chars())
    }
}

/// Which way a file goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The viewer sends it to the host (an upload).
    ToHost,
    /// The host sends it to the viewer (a download).
    FromHost,
}

/// Where a transfer stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferState {
    /// Waiting on the viewer for one of the host's [`MAX_UPLOADS`] places:
    /// nothing was sent yet.
    Queued,
    /// Offered, or moving.
    Running,
    /// In place on the receiving side, under this name (the host's stored,
    /// sanitised name for an upload).
    Done {
        /// The name it is stored under.
        stored: Untrusted,
    },
    /// It failed, with this `tornect_proto::services::reason` code; nothing
    /// of it is left on the receiving side.
    Failed(u16),
    /// A person stopped it (`BY_VIEWER`, `BY_HOST`, `TURNED_OFF`); nothing of
    /// it is left on the receiving side.
    Cancelled(u16),
}

impl TransferState {
    /// The end of a transfer stopped with `code`: cancelled when a person
    /// stopped it, failed otherwise.
    #[must_use]
    pub fn ended(code: u16) -> Self {
        match code {
            reason::BY_VIEWER | reason::BY_HOST | reason::TURNED_OFF => Self::Cancelled(code),
            _ => Self::Failed(code),
        }
    }
}

/// One transfer as either end shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRow {
    /// The transfer's id.
    pub xfer: u32,
    /// Which way it goes.
    pub dir: Direction,
    /// The file's name, sanitised.
    pub name: Untrusted,
    /// Its size in bytes.
    pub size: u64,
    /// The bytes the receiver has written (credited), so far.
    pub done: u64,
    /// Where it stands.
    pub state: TransferState,
}

/// The transfer ids one end has seen, and the ones that ended lately.
#[derive(Debug, Default)]
pub(crate) struct Ids {
    highest: u32,
    ended: VecDeque<u32>,
}

/// What a frame's transfer id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Known {
    /// A transfer that ended lately: the frame was in flight, and is dropped.
    Ended,
    /// No transfer this end knows: the peer broke the protocol.
    Unknown,
}

impl Ids {
    /// A new transfer under `xfer`, which must be above every id seen.
    pub(crate) fn fresh(&mut self, xfer: u32) -> bool {
        if xfer <= self.highest {
            return false;
        }
        self.highest = xfer;
        true
    }

    /// The next id this end gives out (the viewer's); `None` once they ran
    /// out.
    pub(crate) fn next(&mut self) -> Option<u32> {
        let next = self.highest.checked_add(1)?;
        self.highest = next;
        Some(next)
    }

    /// Transfer `xfer` ended.
    pub(crate) fn end(&mut self, xfer: u32) {
        if self.ended.len() == ENDED_KEPT {
            self.ended.pop_front();
        }
        self.ended.push_back(xfer);
    }

    /// What a frame for `xfer`, which no running transfer has, names.
    pub(crate) fn known(&self, xfer: u32) -> Known {
        if xfer != 0 && xfer <= self.highest && self.ended.contains(&xfer) {
            Known::Ended
        } else {
            Known::Unknown
        }
    }
}

/// What a sending worker reads.
#[derive(Debug)]
enum ReadOut {
    /// The next bytes of the file.
    Chunk(Vec<u8>),
    /// Every byte was read, with this SHA-256.
    End([u8; 32]),
    /// Reading stopped: `CHANGED` (the file is not of its announced size any
    /// more), `IO`.
    Failed(u16),
}

/// A sending task's failure: the loop cancels the transfer with this
/// reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SendFailed {
    /// The transfer.
    pub(crate) xfer: u32,
    /// The `Cancel` reason.
    pub(crate) reason: u16,
}

/// Chunks a sending worker reads ahead.
const READ_AHEAD: usize = 2;

/// A file being sent: a blocking worker reads it in chunks and hashes it, a
/// task sends each chunk once the window has room, then `Done` (behind the
/// last chunk, on the same queue). Dropping it stops both: the task at
/// once, the worker at its next chunk.
#[derive(Debug)]
pub(crate) struct Outgoing {
    task: JoinHandle<()>,
    cancel: Arc<AtomicBool>,
}

impl Outgoing {
    /// Send `size` bytes of `file` as transfer `xfer` (opened in `window`
    /// already) in chunks of `chunk` bytes, each read within
    /// `read_timeout`; a failure is told on `failed`.
    pub(crate) fn start(
        xfer: u32,
        file: File,
        size: u64,
        chunk: usize,
        window: Arc<Window>,
        outbox: Outbox,
        read_timeout: Duration,
        failed: mpsc::UnboundedSender<SendFailed>,
    ) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel(READ_AHEAD);
        let stop = Arc::clone(&cancel);
        tokio::task::spawn_blocking(move || read_file(file, size, chunk.max(1), &tx, &stop));
        let task = tokio::spawn(send_file(xfer, rx, window, outbox, read_timeout, failed));
        Self { task, cancel }
    }
}

impl Drop for Outgoing {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        self.task.abort();
    }
}

/// Read `size` bytes of `file` into `tx`, then its SHA-256; a file shorter
/// or longer than `size` is `CHANGED`.
fn read_file(
    mut file: File,
    size: u64,
    chunk: usize,
    tx: &mpsc::Sender<ReadOut>,
    cancel: &AtomicBool,
) {
    let mut hasher = Sha256::new();
    let mut left = size;
    while left > 0 {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let want = usize::try_from(left).map_or(chunk, |left| left.min(chunk));
        let mut buf = vec![0u8; want];
        match fill(&mut file, &mut buf) {
            Ok(got) if got == want => {}
            Ok(_) => {
                let _ = tx.blocking_send(ReadOut::Failed(reason::CHANGED));
                return;
            }
            Err(_) => {
                let _ = tx.blocking_send(ReadOut::Failed(reason::IO));
                return;
            }
        }
        hasher.update(&buf);
        left -= want as u64;
        if tx.blocking_send(ReadOut::Chunk(buf)).is_err() {
            return;
        }
    }
    // Nothing may follow the announced size.
    let out = match fill(&mut file, &mut [0u8; 1]) {
        Ok(0) => ReadOut::End(hasher.finalize().into()),
        Ok(_) => ReadOut::Failed(reason::CHANGED),
        Err(_) => ReadOut::Failed(reason::IO),
    };
    let _ = tx.blocking_send(out);
}

/// Read into `buf` until it is full or the file ends: the bytes read.
fn fill(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match file.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// Send what the reader gives as `Data`, each chunk once the window takes
/// it, then `Done` on the same queue, so that it follows the last chunk.
async fn send_file(
    xfer: u32,
    mut rx: mpsc::Receiver<ReadOut>,
    window: Arc<Window>,
    outbox: Outbox,
    read_timeout: Duration,
    failed: mpsc::UnboundedSender<SendFailed>,
) {
    let fail = |reason: u16| {
        let _ = failed.send(SendFailed { xfer, reason });
    };
    let mut offset = 0u64;
    loop {
        let out = match tokio::time::timeout(read_timeout, rx.recv()).await {
            Ok(Some(out)) => out,
            // The reader stalled, or stopped without a word (it panicked).
            Ok(None) | Err(_) => return fail(reason::IO),
        };
        match out {
            ReadOut::Chunk(bytes) => {
                let n = bytes.len() as u64;
                if !window.take(xfer, n).await {
                    return;
                }
                if !outbox
                    .data(SvcMsg::Data {
                        xfer,
                        offset,
                        bytes,
                    })
                    .await
                {
                    return;
                }
                offset += n;
            }
            ReadOut::End(sha256) => {
                let _ = outbox.data(SvcMsg::Done(Done { xfer, sha256 })).await;
                return;
            }
            ReadOut::Failed(code) => return fail(code),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use tornect_proto::services::{CHUNK, read_body_max, read_header};

    use super::*;
    use crate::services::writer::spawn_writer;

    #[test]
    fn untrusted_names_are_sanitised_and_hidden_from_debug() {
        let name = Untrusted::file_name("../x/secret\u{202e}fdp.exe");
        assert_eq!(name.as_str(), "secretfdp.exe");
        assert_eq!(format!("{name:?}"), "Untrusted(<13 chars>)");
        assert_eq!(Untrusted::file_name("..").as_str(), "file");
        assert_eq!(
            TransferState::ended(reason::BY_HOST),
            TransferState::Cancelled(reason::BY_HOST)
        );
        assert_eq!(
            TransferState::ended(reason::NO_SPACE),
            TransferState::Failed(reason::NO_SPACE)
        );
    }

    /// Ids count up; a reused id is refused; the last 64 ended ones are
    /// known as ended, older ones and unseen ones are not.
    #[test]
    fn ids_count_up_and_remember_the_last_ended_ones() {
        let mut ids = Ids::default();
        assert!(ids.fresh(1));
        assert!(!ids.fresh(1));
        assert!(ids.fresh(5));
        assert!(!ids.fresh(3), "below the highest");
        assert_eq!(ids.known(5), Known::Unknown, "running, not ended");
        ids.end(5);
        assert_eq!(ids.known(5), Known::Ended);
        assert_eq!(ids.known(6), Known::Unknown, "never seen");
        assert_eq!(ids.known(0), Known::Unknown);
        for n in 6..6 + ENDED_KEPT as u32 {
            assert!(ids.fresh(n));
            ids.end(n);
        }
        assert_eq!(ids.known(5), Known::Unknown, "ended too long ago");
        assert_eq!(ids.known(6), Known::Ended);

        let mut mine = Ids::default();
        assert_eq!(mine.next(), Some(1));
        assert_eq!(mine.next(), Some(2));
    }

    async fn next_msg(rd: &mut tokio::io::DuplexStream) -> Option<SvcMsg> {
        let header = read_header(rd).await.unwrap()?;
        let body = read_body_max(rd, header, 1 << 16).await.unwrap();
        Some(SvcMsg::decode(header.ty, &body).unwrap())
    }

    /// A file goes out in chunks within the window, then `Done` with its
    /// hash, behind the last chunk.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_goes_out_in_chunks_then_done() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let content: Vec<u8> = (0..(2 * CHUNK + 10)).map(|n| (n % 251) as u8).collect();
        std::fs::write(&path, &content).unwrap();
        let (mut rd, wr) = tokio::io::duplex(1 << 20);
        let (outbox, _writer) = spawn_writer(wr);
        let window = Arc::new(Window::new(u32::try_from(4 * CHUNK).unwrap()));
        window.open(7);
        let (failed, mut failures) = mpsc::unbounded_channel();
        let _out = Outgoing::start(
            7,
            File::open(&path).unwrap(),
            content.len() as u64,
            CHUNK,
            Arc::clone(&window),
            outbox,
            Duration::from_secs(5),
            failed,
        );
        let mut got = Vec::new();
        loop {
            match next_msg(&mut rd).await.unwrap() {
                SvcMsg::Data {
                    xfer: 7,
                    offset,
                    bytes,
                } => {
                    assert_eq!(offset, got.len() as u64);
                    got.extend_from_slice(&bytes);
                }
                SvcMsg::Done(done) => {
                    assert_eq!(done.xfer, 7);
                    assert_eq!(done.sha256, <[u8; 32]>::from(Sha256::digest(&content)));
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(got, content);
        assert_eq!(window.in_flight(), content.len() as u64);
        assert!(failures.try_recv().is_err());
    }

    /// A file that is not of its announced size any more is `CHANGED`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_that_changed_size_fails() {
        let dir = tempfile::tempdir().unwrap();
        for (written, announced) in [(10usize, 20u64), (30, 20)] {
            let path = dir.path().join(format!("f{written}"));
            let mut file = File::create(&path).unwrap();
            file.write_all(&vec![1; written]).unwrap();
            let (_rd, wr) = tokio::io::duplex(1 << 20);
            let (outbox, _writer) = spawn_writer(wr);
            let window = Arc::new(Window::new(u32::try_from(CHUNK).unwrap()));
            window.open(1);
            let (failed, mut failures) = mpsc::unbounded_channel();
            let _out = Outgoing::start(
                1,
                File::open(&path).unwrap(),
                announced,
                CHUNK,
                window,
                outbox,
                Duration::from_secs(5),
                failed,
            );
            assert_eq!(
                failures.recv().await,
                Some(SendFailed {
                    xfer: 1,
                    reason: reason::CHANGED
                }),
                "{written} bytes announced as {announced}"
            );
        }
    }
}
