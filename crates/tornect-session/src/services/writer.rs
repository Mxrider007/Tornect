//! The services writer (the services design §3.4): one task per stream owns
//! its write half and drains four queues in a fixed order, so that a chat
//! line or a `Cancel` never waits behind file data:
//!
//! 1. `close`: the stream's end, which drops whatever is still queued;
//! 2. `ctrl` ([`CTRL_DEPTH`], never awaited: a full queue means the peer
//!    stopped reading, and the stream ends with `Close{PROTOCOL}`):
//!    `Welcome`, `Refused`, `Caps`, `Chat`, `Accepted`, `Sending`, `Done`,
//!    `Complete`, `Cancel`, `Credit`, `ListFailed`;
//! 3. `list` ([`LIST_DEPTH`], awaited): `Listing` pages, one at a time;
//! 4. `clip` and `data` ([`BULK_DEPTH`] each, awaited): `ClipStart`,
//!    `ClipChunk` and `Data`, which a sender queues only once its bulk window
//!    lets it.
//!
//! A frame being written is not interrupted by a queued one; it is by the
//! stream's end, which then writes nothing more (a frame cut short leaves
//! the stream unframed: the media stream's `torn` rule).

use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tornect_proto::services::{SvcMsg, write_msg};

/// Control frames queued at most.
pub(crate) const CTRL_DEPTH: usize = 64;
/// `Listing` pages queued at most.
pub(crate) const LIST_DEPTH: usize = 1;
/// Clipboard frames, and file data, queued at most.
pub(crate) const BULK_DEPTH: usize = 2;
/// Bound on the last frame (`Close`) and the shutdown, written to a peer that
/// may not be reading.
pub(crate) const LAST_WRITE: Duration = Duration::from_secs(5);

/// Where a stream's frames are queued for its writer.
#[derive(Debug, Clone)]
pub(crate) struct Outbox {
    ctrl: mpsc::Sender<SvcMsg>,
    // The listing, clipboard and file queues are fed by the later services
    // steps (the design's steps 15–18); the writer drains them already.
    #[cfg_attr(not(test), allow(dead_code))]
    list: mpsc::Sender<SvcMsg>,
    #[cfg_attr(not(test), allow(dead_code))]
    clip: mpsc::Sender<SvcMsg>,
    #[cfg_attr(not(test), allow(dead_code))]
    data: mpsc::Sender<SvcMsg>,
}

impl Outbox {
    /// Queue a control frame without waiting; `false` when the queue is full
    /// (the peer stopped reading) or the writer is gone.
    pub(crate) fn ctrl(&self, msg: SvcMsg) -> bool {
        self.ctrl.try_send(msg).is_ok()
    }

    /// Queue a `Listing` page, waiting for the one before it to be written.
    #[cfg(test)]
    pub(crate) async fn list(&self, msg: SvcMsg) -> bool {
        self.list.send(msg).await.is_ok()
    }

    /// Queue a clipboard frame, waiting for room.
    #[cfg(test)]
    pub(crate) async fn clip(&self, msg: SvcMsg) -> bool {
        self.clip.send(msg).await.is_ok()
    }

    /// Queue a `Data` frame, waiting for room.
    #[cfg(test)]
    pub(crate) async fn data(&self, msg: SvcMsg) -> bool {
        self.data.send(msg).await.is_ok()
    }
}

/// How a writer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriterEnd {
    /// Told to end between frames: the `Close` asked for (if any) was
    /// written, or tried within [`LAST_WRITE`], and the stream shut down.
    Closed,
    /// Told to end while a frame was being written: nothing more was
    /// written, and the stream shut down.
    Torn,
    /// A write failed: the peer reset or stalled the stream.
    Broken,
}

/// The stream's writer task.
#[derive(Debug)]
pub(crate) struct Writer {
    close: Option<oneshot::Sender<Option<u16>>>,
    task: Option<JoinHandle<WriterEnd>>,
}

/// The receiving ends of an [`Outbox`].
struct Queues {
    ctrl: mpsc::Receiver<SvcMsg>,
    list: mpsc::Receiver<SvcMsg>,
    clip: mpsc::Receiver<SvcMsg>,
    data: mpsc::Receiver<SvcMsg>,
}

/// Start the writer of `wr`.
pub(crate) fn spawn_writer<W>(wr: W) -> (Outbox, Writer)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (ctrl, ctrl_rx) = mpsc::channel(CTRL_DEPTH);
    let (list, list_rx) = mpsc::channel(LIST_DEPTH);
    let (clip, clip_rx) = mpsc::channel(BULK_DEPTH);
    let (data, data_rx) = mpsc::channel(BULK_DEPTH);
    let (close, close_rx) = oneshot::channel();
    let queues = Queues {
        ctrl: ctrl_rx,
        list: list_rx,
        clip: clip_rx,
        data: data_rx,
    };
    let task = tokio::spawn(write_frames(wr, queues, close_rx));
    (
        Outbox {
            ctrl,
            list,
            clip,
            data,
        },
        Writer {
            close: Some(close),
            task: Some(task),
        },
    )
}

impl Writer {
    /// Resolves once the writer stopped on its own (a write failed); never
    /// while it runs. Cancel-safe: the loop selects on it.
    pub(crate) async fn stopped(&mut self) -> WriterEnd {
        let Some(task) = self.task.as_mut() else {
            return std::future::pending().await;
        };
        let end = task.await.unwrap_or(WriterEnd::Broken);
        self.task = None;
        end
    }

    /// End the stream: `Close{reason}` after the frame being written, if any
    /// (none when `reason` is `None`), then shut down. Waits for the writer
    /// within twice [`LAST_WRITE`] and then abandons it.
    pub(crate) async fn close(mut self, reason: Option<u16>) -> WriterEnd {
        if let Some(close) = self.close.take() {
            let _ = close.send(reason);
        }
        let Some(mut task) = self.task.take() else {
            return WriterEnd::Broken;
        };
        match tokio::time::timeout(2 * LAST_WRITE, &mut task).await {
            Ok(end) => end.unwrap_or(WriterEnd::Broken),
            Err(_) => {
                task.abort();
                WriterEnd::Broken
            }
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn write_frames<W>(
    mut wr: W,
    mut queues: Queues,
    mut close: oneshot::Receiver<Option<u16>>,
) -> WriterEnd
where
    W: AsyncWrite + Unpin,
{
    loop {
        let msg = tokio::select! {
            biased;
            reason = &mut close => return finish(&mut wr, reason.ok().flatten()).await,
            Some(msg) = queues.ctrl.recv() => msg,
            Some(msg) = queues.list.recv() => msg,
            Some(msg) = queues.clip.recv() => msg,
            Some(msg) = queues.data.recv() => msg,
        };
        tokio::select! {
            biased;
            written = write_msg(&mut wr, &msg) => {
                if written.is_err() {
                    return WriterEnd::Broken;
                }
            }
            _ = &mut close => {
                let _ = tokio::time::timeout(LAST_WRITE, wr.shutdown()).await;
                return WriterEnd::Torn;
            }
        }
    }
}

/// Write `Close{reason}` (if any) and shut down, each within [`LAST_WRITE`].
async fn finish<W: AsyncWrite + Unpin>(wr: &mut W, reason: Option<u16>) -> WriterEnd {
    if let Some(reason) = reason {
        let _ = tokio::time::timeout(LAST_WRITE, write_msg(wr, &SvcMsg::Close { reason })).await;
    }
    let _ = tokio::time::timeout(LAST_WRITE, wr.shutdown()).await;
    WriterEnd::Closed
}

#[cfg(test)]
mod tests {
    use tokio::io::simplex;
    use tornect_proto::services::{CHUNK, Caps, Chat, read_body_max, read_header, ty};

    use super::*;

    fn data(xfer: u32, offset: u64) -> SvcMsg {
        SvcMsg::Data {
            xfer,
            offset,
            bytes: vec![7; CHUNK],
        }
    }

    async fn next<R: tokio::io::AsyncRead + Unpin>(rd: &mut R) -> Option<SvcMsg> {
        let header = read_header(rd).await.unwrap()?;
        let body = read_body_max(rd, header, 1 << 16).await.unwrap();
        Some(SvcMsg::decode(header.ty, &body).unwrap())
    }

    /// The services design's test 11: a `Chat` queued behind three `Data`
    /// chunks is written right after the chunk being written, before the
    /// second one.
    #[tokio::test]
    async fn a_chat_line_overtakes_queued_file_data() {
        // Room for a few bytes: the first chunk's write waits for the reader.
        let (mut rd, wr) = simplex(64);
        let (outbox, writer) = spawn_writer(wr);
        assert!(outbox.data(data(1, 0)).await);
        assert!(outbox.data(data(1, CHUNK as u64)).await);
        // Taken only once the writer took the first chunk, and so is
        // writing it.
        assert!(outbox.data(data(2, 0)).await);
        assert!(outbox.ctrl(SvcMsg::Chat(Chat { text: "now".into() })));
        let mut order = Vec::new();
        for _ in 0..4 {
            order.push(match next(&mut rd).await.unwrap() {
                SvcMsg::Data { xfer, offset, .. } => format!("data {xfer}@{offset}"),
                SvcMsg::Chat(_) => "chat".to_owned(),
                other => panic!("{other:?}"),
            });
        }
        assert_eq!(order, ["data 1@0", "chat", "data 1@16384", "data 2@0"]);
        assert_eq!(writer.close(Some(16)).await, WriterEnd::Closed);
        assert_eq!(next(&mut rd).await, Some(SvcMsg::Close { reason: 16 }));
        assert_eq!(next(&mut rd).await, None);
    }

    /// Control before listings before clipboard before data, whatever the
    /// order they were queued in.
    #[tokio::test]
    async fn queues_are_drained_in_priority_order() {
        let (mut rd, wr) = simplex(1 << 20);
        let (outbox, writer) = spawn_writer(wr);
        // Hold the writer back: everything is queued before it first runs
        // on this single-threaded runtime.
        assert!(outbox.data(data(3, 0)).await);
        assert!(
            outbox
                .clip(SvcMsg::ClipStart(tornect_proto::services::ClipStart {
                    seq: 1,
                    len: 5
                }))
                .await
        );
        assert!(
            outbox
                .list(SvcMsg::ListFailed(tornect_proto::services::ListFailed {
                    req: 1,
                    reason: 9
                }))
                .await
        );
        assert!(outbox.ctrl(SvcMsg::Caps(Caps { caps: 1, paused: 0 })));
        let mut types = Vec::new();
        for _ in 0..4 {
            types.push(next(&mut rd).await.unwrap().ty());
        }
        assert_eq!(types, [ty::CAPS, ty::LIST_FAILED, ty::CLIP_START, ty::DATA]);
        drop(writer);
    }

    /// The end drops what is still queued; an end while a frame is being
    /// written leaves the frame as far as it got and writes nothing more.
    #[tokio::test]
    async fn the_end_drops_the_queue_and_a_cut_frame_ends_the_writing() {
        let (mut rd, wr) = simplex(1 << 20);
        let (outbox, writer) = spawn_writer(wr);
        assert!(outbox.data(data(1, 0)).await);
        assert!(outbox.data(data(1, CHUNK as u64)).await);
        // Both queued before the writer ran; the end comes first.
        assert_eq!(writer.close(Some(21)).await, WriterEnd::Closed);
        assert_eq!(next(&mut rd).await, Some(SvcMsg::Close { reason: 21 }));
        assert_eq!(next(&mut rd).await, None);

        let (mut rd, wr) = simplex(64);
        let (outbox, writer) = spawn_writer(wr);
        assert!(outbox.data(data(1, 0)).await);
        assert!(outbox.data(data(1, CHUNK as u64)).await);
        // Taken once the first chunk is being written.
        assert!(outbox.data(data(1, 2 * CHUNK as u64)).await);
        assert_eq!(writer.close(Some(21)).await, WriterEnd::Torn);
        let mut cut = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut rd, &mut cut)
            .await
            .unwrap();
        assert!(cut.len() < 5 + 12 + CHUNK, "{} bytes", cut.len());
    }

    /// A full control queue says so: the peer stopped reading.
    #[tokio::test]
    async fn a_full_control_queue_is_refused_not_awaited() {
        let (_rd, wr) = simplex(16);
        let (outbox, _writer) = spawn_writer(wr);
        let mut taken = 0;
        while outbox.ctrl(SvcMsg::Caps(Caps { caps: 1, paused: 0 })) {
            taken += 1;
            assert!(taken <= CTRL_DEPTH + 1, "the queue never filled");
        }
        assert!(taken >= CTRL_DEPTH);
    }
}
