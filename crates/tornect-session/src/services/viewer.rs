//! The viewer's end of a services stream (the services design §6.1).
//!
//! The viewer opens the stream only when the host's signed `HELLO_ACK`
//! carries `svc1` and only after its media stream's `BindOk`, binds it with
//! a [`ServicesBinding`], and reads the host's `Welcome` (or its `Refused`).
//! [`ServicesViewer::run`] then serves it until the host closes it, the
//! viewer's session ends (its `stop`), or something breaks; its end never
//! ends the session.
//!
//! The viewer's reader applies the mirror of the host's gate: a frame only
//! the viewer sends ends the stream with `Close{PROTOCOL}`, one for a cap
//! never granted with `Close{NOT_OFFERED}`, both before the body is read. A
//! `Caps` may only take caps away; one that adds any is a protocol error.
//!
//! A `Caps` with `paused` says the host is locked (§2.3): it skips new
//! requests for those caps unread, so the viewer fails its own unanswered
//! ones with `LOCKED` (offers, `Get`s, the `List` outstanding) and sends no
//! more until a `Caps` resumes them; its queued files wait, and the files
//! under way stall. Its clipboard stops both ways, and its switch is told
//! again at the resume.
//!
//! Files go to the host through [`ViewerOp::UploadPath`] (the upload
//! protocol, §3.5): at most [`MAX_UPLOADS`](super::MAX_UPLOADS) are offered at
//! once and the others wait, in order; each is read on a blocking worker and
//! sent within the host's bulk window, and reported as
//! [`ViewerEvent::Transfer`] rows under ids of their own. Every file sent,
//! a dropped one included, first passes the viewer's own
//! [`Access`](super::Access) ([`ViewerLocal::access`]): a slip never offers
//! Tornect's own files, and nothing goes to the host for a file refused
//! there. "Send files" browses the viewer's own folders through the same
//! rules ([`ViewerOp::OpenLocal`], [`ViewerOp::UploadLocal`]), with handles
//! of its own.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tornect_proto::services::{
    Bind, CHUNK, Chat, Side, SvcError, SvcMsg, Welcome, caps, read_body_max, read_header, reason,
    services_bind_mac, services_bind_mac_direct, ty, write_msg,
};
use tornect_signal::consent::SessionToken;

use super::browse::{Access, ListingView, LocalFiles};
use super::chat::{self, ChatGate, ChatText, sanitize_peer_text};
use super::clip::{ClipInflow, ClipSender, ViewerClip, ViewerClipSync, text_of};
use super::download::{DownloadsFolder, ViewerDownloads};
use super::listing::{Answer, ViewerListings};
use super::reader::{CapState, Inbound, ReadEnd, read_frames};
use super::store::{FreeSpaceFn, Inbox, InboxLimits, unknown_free_space};
use super::transfer::{Ids, RowIds, TransferRow, ViewerShared, late};
use super::upload::ViewerUploads;
use super::window::{CLIPBOARD, Window};
use super::writer::{Outbox, spawn_writer};
use super::{ServicesLimits, ServicesPolicy};

/// Decoded frames held between the viewer's reader and its loop.
const INBOUND_DEPTH: usize = 8;

/// What the viewer's end of a services stream works with on its own
/// computer (the design's §5.1, §5.2, §6.1).
pub struct ViewerLocal {
    /// Where downloads land: `<Downloads>/Tornect`
    /// (`tornect_core::files::downloads_dir`); `None` when this computer
    /// has no Downloads folder.
    pub downloads: Option<PathBuf>,
    /// What may be sent, and what "Send files" lists: this computer's own
    /// places and deny-list (its Tornect folders, both `TORNECT_HOME`'s and
    /// the platform's, and on Linux the system folders).
    pub access: Arc<Access>,
    /// The free space of the downloads folder's disk
    /// (`tornect_platform::disk::available`).
    pub free_space: FreeSpaceFn,
    /// The largest file downloaded, in bytes (this computer's own
    /// `[services] max_file_mib`).
    pub max_file: u64,
    /// Downloading stops before the disk has less than this free, in bytes
    /// (`[services] keep_free_mib`).
    pub keep_free: u64,
    /// The bounds of the local listing and of the transfers: `chunk`,
    /// `read_timeout`, `max_entries`, `list_timeout`, `max_handles`,
    /// `recheck_free_every` and `workers_wait` count here.
    pub limits: ServicesLimits,
    /// The window's clipboard (§4.3); `None`: this window shares no
    /// clipboard, and the host is never asked to.
    pub clip: Option<ViewerClip>,
}

impl Default for ViewerLocal {
    /// Nothing to send and nowhere to download to: an [`Access`] that
    /// refuses every path, no Downloads folder, no free space known, and
    /// the default policy's limits.
    fn default() -> Self {
        let policy = ServicesPolicy::default();
        Self {
            downloads: None,
            access: Arc::new(Access::none()),
            free_space: unknown_free_space(),
            max_file: policy.max_file,
            keep_free: policy.keep_free,
            limits: ServicesLimits::default(),
            clip: None,
        }
    }
}

impl std::fmt::Debug for ViewerLocal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewerLocal")
            .field("downloads", &self.downloads.is_some())
            .field("access", &self.access)
            .field("max_file", &self.max_file)
            .field("keep_free", &self.keep_free)
            .field("clip", &self.clip)
            .finish_non_exhaustive()
    }
}

/// What the viewer binds its services stream with: the session's id and the
/// services MAC over the handshake's final transcript (§3.3). Its `Debug`
/// never prints the MAC.
#[derive(Clone)]
pub struct ServicesBinding {
    session_id: String,
    mac: [u8; 32],
}

impl ServicesBinding {
    /// The binding of the session whose token is `token` and whose handshake
    /// ended at `th_final` (`ClientSession::session_token` and `th`).
    #[must_use]
    pub fn new(token: &SessionToken, th_final: &[u8; 32]) -> Self {
        Self {
            session_id: token.session_id(),
            mac: services_bind_mac(token.bytes(), th_final),
        }
    }

    /// The binding of the same session's services stream on its direct
    /// connection (the direct design §6.7), whose TLS exporter output is
    /// `ekm` (`tornect_net::Established::binding_secret`): the MAC covers
    /// the connection too, so it binds no other connection, and neither the
    /// onion services MAC nor the direct media MAC binds this stream.
    #[must_use]
    pub fn direct(token: &SessionToken, th_final: &[u8; 32], ekm: &[u8; 32]) -> Self {
        Self {
            session_id: token.session_id(),
            mac: services_bind_mac_direct(token.bytes(), th_final, ekm),
        }
    }

    /// The session id.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The `Bind` frame.
    pub(crate) fn msg(&self) -> SvcMsg {
        SvcMsg::Bind(Bind {
            session_id: self.session_id.clone(),
            mac: self.mac,
        })
    }
}

impl std::fmt::Debug for ServicesBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServicesBinding")
            .field("session_id", &self.session_id)
            .field("mac", &"<redacted>")
            .finish()
    }
}

/// Why a services stream did not open. The session goes on either way.
#[derive(Debug, thiserror::Error)]
pub enum ServicesBindError {
    /// The host refused: a [`reason`] code (`NOT_OFFERED` from a host with
    /// no services, `NOT_LIVE` when capture did not start, ...).
    #[error("the other computer offers no chat or files in this session (reason {0})")]
    Refused(u16),
    /// The stream failed or closed before the answer.
    #[error("the services stream failed: {0}")]
    Io(#[from] std::io::Error),
    /// No answer in time.
    #[error("no answer on the services stream in time")]
    Timeout,
    /// The answer was neither `Welcome` nor `Refused`, or malformed.
    #[error("the other computer answered the services bind with something else")]
    Protocol,
}

/// What the viewer's user asks of the services stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewerOp {
    /// Write to the host's user.
    Chat(ChatText),
    /// The window's "Clipboard" switch: off means neither direction (the
    /// host deactivates its link), on shares it again.
    ClipSwitch(bool),
    /// Send the file at this path to the host's inbox (a file dropped on
    /// the window). It is reported as a [`ViewerEvent::Transfer`] row under
    /// an id of its own; without `UPLOAD` the row fails at once with
    /// `NOT_OFFERED`, and a file [`ViewerLocal::access`] refuses fails with
    /// its reason (`DENIED`, `NOT_FOUND`), nothing sent.
    UploadPath(PathBuf),
    /// List this computer's folder with this local handle ("Send files"; 0:
    /// this computer's places): a [`ViewerEvent::Listing`] with `remote`
    /// false, or a [`ViewerEvent::ListFailed`].
    OpenLocal(u32),
    /// Send this computer's file with this local handle, as
    /// [`ViewerOp::UploadPath`] does; an unknown handle fails its row with
    /// `NOT_FOUND`.
    UploadLocal(u32),
    /// List the host's folder with this handle (0: the host's places): its
    /// pages come as [`ViewerEvent::Listing`] with `remote` true, each next
    /// one asked for without a word from the user, or a
    /// [`ViewerEvent::ListFailed`]. A folder opened while another is being
    /// listed replaces it: only the last one opened is shown. While the host
    /// is locked it fails at once with `LOCKED`, nothing sent.
    OpenRemote(u32),
    /// Copy the host's file with this handle into [`ViewerLocal::downloads`],
    /// reported as [`ViewerEvent::Transfer`] rows (`Direction::FromHost`)
    /// under an id of its own. At most
    /// [`MAX_DOWNLOADS`](super::MAX_DOWNLOADS) are asked for at once and the
    /// others wait, in order (and all of them while the host is locked).
    /// Without `BROWSE` the row fails at once with `NOT_OFFERED`, and
    /// without a downloads folder with `IO`.
    Download(u32),
    /// Stop the transfer whose row has this id.
    Cancel(u32),
}

/// What [`ServicesViewer::run`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewerEvent {
    /// The caps left, or the ones paused, changed.
    Caps {
        /// The caps left.
        caps: u16,
        /// The caps paused.
        paused: u16,
    },
    /// The host's user wrote, sanitised ([`sanitize_peer_text`]).
    Chat(ChatText),
    /// A transfer was asked for, moved on or ended. Its `xfer` is the row's
    /// id ([`ViewerOp::Cancel`] takes it), not the wire's.
    Transfer(TransferRow),
    /// A page of a folder's listing: the other computer's (`remote`), or
    /// this computer's own for "Send files".
    Listing {
        /// Whether it is the other computer's folder.
        remote: bool,
        /// The page.
        view: ListingView,
    },
    /// A folder could not be listed, with this [`reason`] code: `NOT_FOUND`
    /// (gone, or a handle too old: list again), `DENIED` (Tornect's own
    /// folders, or not readable), `IO`, `BUSY`; for the other computer's
    /// also `NOT_OFFERED`, `TURNED_OFF` (browsing went) and `LOCKED` (it is
    /// locked: list again once it is not).
    ListFailed {
        /// Whether it was the other computer's folder.
        remote: bool,
        /// Why.
        reason: u16,
    },
    /// The stream ended with this [`reason`] code: the host's `Close`, or the
    /// viewer's own (`PROTOCOL`, `IO`). Not sent when the viewer stopped it.
    Closed(u16),
}

/// How [`ServicesViewer::run`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerServicesEnd {
    /// `stop` resolved: `Close{SESSION_OVER}` was sent.
    Stopped,
    /// The host closed the stream with this reason.
    Closed(u16),
    /// The viewer closed it with this reason: the host broke the protocol
    /// (`PROTOCOL`), or sent a frame for a cap never granted
    /// (`NOT_OFFERED`).
    Refused(u16),
    /// The stream failed.
    Io,
}

/// A bound services stream, viewer side.
pub struct ServicesViewer<S> {
    rd: ReadHalf<S>,
    wr: WriteHalf<S>,
    welcome: Welcome,
}

impl<S> std::fmt::Debug for ServicesViewer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServicesViewer")
            .field("welcome", &self.welcome)
            .finish_non_exhaustive()
    }
}

impl<S> ServicesViewer<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Send the `Bind` on `stream` and wait up to `wait` for the host's
    /// answer: the stream and its `Welcome`, or why there are no services.
    /// The host answers once the session's capture is live and its caps are
    /// known, which can take its live wait and its clipboard's open.
    pub async fn bind(
        stream: S,
        binding: &ServicesBinding,
        wait: Duration,
    ) -> Result<(Self, Welcome), ServicesBindError> {
        let (mut rd, mut wr) = tokio::io::split(stream);
        // The terminal host answers without reading the `Bind` and closes:
        // its `Refused` can be waiting when the `Bind` no longer goes out.
        let sent = write_msg(&mut wr, &binding.msg()).await;
        let answer = match (sent, tokio::time::timeout(wait, read_answer(&mut rd)).await) {
            (_, Ok(Ok(answer))) => answer,
            (Err(e), _) => return Err(svc(e)),
            (Ok(()), Ok(Err(e))) => return Err(e),
            (Ok(()), Err(_)) => return Err(ServicesBindError::Timeout),
        };
        match answer {
            SvcMsg::Welcome(welcome) => Ok((
                Self {
                    rd,
                    wr,
                    welcome: welcome.clone(),
                },
                welcome,
            )),
            SvcMsg::Refused { reason } => Err(ServicesBindError::Refused(reason)),
            _ => Err(ServicesBindError::Protocol),
        }
    }

    /// What the host granted.
    #[must_use]
    pub fn welcome(&self) -> &Welcome {
        &self.welcome
    }

    /// Serve the stream until the host closes it, `stop` resolves (then
    /// `Close{SESSION_OVER}` is sent: the viewer's session is over), or it
    /// breaks: the user's requests come on `ops`, and what happens goes out
    /// on `events` (dropped while `events` is full: its reader is stuck,
    /// and the end is also returned); `local` is what it works with on this
    /// computer. Transfers still running at the end are reported ended with
    /// the stream's reason.
    pub async fn run<F>(
        self,
        mut ops: mpsc::Receiver<ViewerOp>,
        events: mpsc::Sender<ViewerEvent>,
        local: ViewerLocal,
        stop: F,
    ) -> ViewerServicesEnd
    where
        F: Future<Output = ()>,
    {
        let Self { rd, wr, welcome } = self;
        let ViewerLocal {
            downloads: downloads_dir,
            access,
            free_space,
            max_file,
            keep_free,
            limits,
            clip: window_clip,
        } = local;
        let state = Arc::new(CapState::new(welcome.caps));
        let (outbox, mut writer) = spawn_writer(wr);
        let (tx, mut inbound) = mpsc::channel(INBOUND_DEPTH);
        let reader = tokio::spawn(read_frames(rd, Side::Host, Arc::clone(&state), tx));
        let mut chat_gate = ChatGate::new(chat::now());
        let window = Arc::new(Window::new(welcome.bulk_window));
        let chunk = limits.chunk.clamp(1, CHUNK);
        let shared = ViewerShared {
            outbox: outbox.clone(),
            events: events.clone(),
            rows: RowIds::default(),
            ids: Ids::default(),
        };
        let (mut files, mut local_done) = LocalFiles::new(Arc::clone(&access), &limits);
        let (mut uploads, mut reports) = ViewerUploads::new(
            shared.clone(),
            Arc::clone(&window),
            access,
            &welcome,
            chunk,
            limits.read_timeout,
        );
        let inbox = downloads_dir.map(|dir| {
            Inbox::new(
                dir,
                InboxLimits {
                    max_file,
                    // The viewer's user chose each file: only this computer's
                    // own largest file and free-space floor hold.
                    quota: u64::MAX,
                    files: u32::MAX,
                    keep_free,
                    min_charge: 0,
                    recheck_every: limits.recheck_free_every,
                },
                free_space,
            )
        });
        let (mut downloads, mut arriving) = ViewerDownloads::new(
            shared.clone(),
            DownloadsFolder { inbox, chunk },
            welcome.bulk_window,
        );
        let mut remote = ViewerListings::new(outbox.clone(), limits.max_entries);
        let clip_granted = welcome.caps & caps::CLIP != 0;
        let sender = (clip_granted && window_clip.is_some())
            .then(|| ClipSender::spawn(Arc::clone(&window), outbox.clone(), chunk, None));
        let mut clip = ViewerClipSync::new(
            window_clip,
            clip_granted,
            sender,
            ClipInflow::new(welcome.clip_max, chat::now()),
        );
        let ids = shared.ids;
        let emit = |event: ViewerEvent| {
            if events.try_send(event).is_err() {
                tracing::debug!("a services event was dropped: nothing reads them");
            }
        };
        tokio::pin!(stop);
        // The window's switch, which the host waits for before its link
        // goes active. The control queue is empty yet, so it takes it unless
        // the writer is gone already, which ends the loop at once.
        if let Some(msg) = clip.first() {
            let _ = outbox.ctrl(msg);
        }
        let (end, close) = loop {
            // `Err(code)`: the stream ends with `Close{code}`.
            let step: Result<(), u16> = tokio::select! {
                biased;
                () = &mut stop => break (ViewerServicesEnd::Stopped, Some(reason::SESSION_OVER)),
                _ = writer.stopped() => break (ViewerServicesEnd::Io, None),
                Some(inbound) = inbound.recv() => match inbound {
                    Inbound::Frame(SvcMsg::Close { reason }) => {
                        break (ViewerServicesEnd::Closed(reason), None);
                    }
                    Inbound::Frame(SvcMsg::Caps(news)) => {
                        // Caps only shrink (§3.1): what the host turned off
                        // is skipped from now on, and it never returns.
                        if news.caps & !state.left() != 0 {
                            break (
                                ViewerServicesEnd::Refused(reason::PROTOCOL),
                                Some(reason::PROTOCOL),
                            );
                        }
                        state.turn_off(!news.caps);
                        let paused = state.set_paused(news.paused);
                        let mut step = Ok(());
                        let mut listing = None;
                        if news.caps & caps::CLIP == 0 {
                            clip.turned_off();
                        } else if let Some(msg) = clip.set_paused(paused & caps::CLIP != 0)
                            && !outbox.ctrl(msg)
                        {
                            // The host stopped reading (§3.4).
                            step = Err(reason::PROTOCOL);
                        }
                        if news.caps & caps::UPLOAD == 0 {
                            uploads.turned_off();
                        } else {
                            step = step.and(uploads.set_paused(paused & caps::UPLOAD != 0));
                        }
                        if news.caps & caps::BROWSE == 0 {
                            downloads.turned_off();
                            listing = remote.turned_off().then_some(reason::TURNED_OFF);
                        } else {
                            let pause = paused & caps::BROWSE != 0;
                            step = step.and(downloads.set_paused(pause));
                            if pause && remote.pause() {
                                listing = Some(reason::LOCKED);
                            }
                        }
                        emit(ViewerEvent::Caps {
                            caps: news.caps,
                            paused,
                        });
                        if let Some(reason) = listing {
                            emit(ViewerEvent::ListFailed {
                                remote: true,
                                reason,
                            });
                        }
                        step
                    }
                    Inbound::Frame(SvcMsg::Chat(Chat { text })) => {
                        if chat_gate.admit(chat::now())
                            && let Some(text) = sanitize_peer_text(&text)
                        {
                            emit(ViewerEvent::Chat(text));
                        }
                        Ok(())
                    }
                    Inbound::Frame(SvcMsg::Accepted(accepted)) => uploads.accepted(accepted),
                    Inbound::Frame(SvcMsg::Credit { xfer, upto }) => {
                        if xfer == CLIPBOARD {
                            // The viewer's clipboard text.
                            window.credit(CLIPBOARD, upto).map_err(|_| reason::PROTOCOL)
                        } else {
                            uploads.credit(xfer, upto)
                        }
                    }
                    Inbound::Frame(SvcMsg::Complete(complete)) => uploads.complete(complete),
                    Inbound::Frame(SvcMsg::Cancel(cancel)) => match uploads.cancelled(cancel) {
                        Ok(false) => match downloads.cancelled(cancel) {
                            // One that ended lately, or none.
                            Ok(false) => late(&ids, cancel.xfer),
                            other => other.map(drop),
                        },
                        other => other.map(drop),
                    },
                    Inbound::Frame(SvcMsg::Sending(sending)) => downloads.sending(sending),
                    Inbound::Frame(SvcMsg::Data {
                        xfer,
                        offset,
                        bytes,
                    }) => downloads.data(xfer, offset, bytes, clip.inflow.owed()),
                    Inbound::Frame(SvcMsg::Done(done)) => downloads.done(done),
                    Inbound::Frame(SvcMsg::Listing(listing)) => {
                        remote.listing(&listing).map(|answer| match answer {
                            Answer::Page(view) => emit(ViewerEvent::Listing { remote: true, view }),
                            Answer::Failed(reason) => {
                                emit(ViewerEvent::ListFailed { remote: true, reason });
                            }
                            Answer::Stale => {}
                        })
                    }
                    Inbound::Frame(SvcMsg::ListFailed(failed)) => {
                        remote.failed(failed).map(|answer| match answer {
                            Answer::Failed(reason) => {
                                emit(ViewerEvent::ListFailed { remote: true, reason });
                            }
                            Answer::Page(_) | Answer::Stale => {}
                        })
                    }
                    Inbound::Frame(SvcMsg::ClipStart(start)) => clip
                        .inflow
                        .start(start, clip.wants(), chat::now())
                        .map(drop),
                    Inbound::Frame(SvcMsg::ClipChunk { seq, offset, bytes }) => {
                        match clip.inflow.chunk(seq, offset, &bytes) {
                            Ok(whole) => clip_read(&mut clip, &downloads, state.left(), &outbox)
                                .map(|()| {
                                    if let Some(text) = whole.and_then(text_of) {
                                        clip.apply(text);
                                    }
                                }),
                            Err(code) => Err(code),
                        }
                    }
                    Inbound::Skipped { ty, len } => {
                        clip.inflow.skipped(ty, len);
                        clip_read(&mut clip, &downloads, state.left(), &outbox)
                    }
                    // Frames only the viewer sends never get here: the reader
                    // ends the stream at their header.
                    Inbound::Frame(other) => {
                        tracing::trace!(ty = other.ty(), "services frame not served");
                        Ok(())
                    }
                    Inbound::End(ReadEnd::Eof | ReadEnd::Io) => break (ViewerServicesEnd::Io, None),
                    Inbound::End(ReadEnd::Refuse(code)) => {
                        break (ViewerServicesEnd::Refused(code), Some(code));
                    }
                },
                Some(done) = local_done.recv() => {
                    match files.done(done) {
                        Some(Ok(view)) => emit(ViewerEvent::Listing {
                            remote: false,
                            view,
                        }),
                        Some(Err(reason)) => emit(ViewerEvent::ListFailed {
                            remote: false,
                            reason,
                        }),
                        None => {}
                    }
                    Ok(())
                }
                text = clip.window() => {
                    clip.copied(text);
                    Ok(())
                }
                Some(job) = reports.jobs.recv() => uploads.on_job(job),
                Some(failed) = reports.failed.recv() => uploads.send_failed(failed),
                Some(report) = arriving.recv() => downloads.on_worker(report),
                Some(op) = ops.recv() => match op {
                    ViewerOp::Chat(text) => {
                        if state.left() & caps::CHAT == 0 {
                            continue;
                        }
                        let Some(text) = text.within(usize::from(welcome.chat_max)) else {
                            continue;
                        };
                        if outbox.ctrl(SvcMsg::Chat(Chat {
                            text: text.as_str().to_owned(),
                        })) {
                            Ok(())
                        } else {
                            // The host stopped reading (§3.4).
                            Err(reason::PROTOCOL)
                        }
                    }
                    ViewerOp::ClipSwitch(on) => match clip.switch(on) {
                        // The host stopped reading (§3.4).
                        Some(msg) => outbox.ctrl(msg).then_some(()).ok_or(reason::PROTOCOL),
                        None => Ok(()),
                    },
                    ViewerOp::UploadPath(path) => {
                        uploads.upload_path(path, state.left() & caps::UPLOAD != 0);
                        Ok(())
                    }
                    ViewerOp::OpenLocal(handle) => {
                        if let Err(reason) = files.open(handle) {
                            emit(ViewerEvent::ListFailed {
                                remote: false,
                                reason,
                            });
                        }
                        Ok(())
                    }
                    ViewerOp::UploadLocal(handle) => {
                        match files.path_of(handle) {
                            Some(path) => {
                                uploads.upload_path(path, state.left() & caps::UPLOAD != 0);
                            }
                            None => uploads.refuse(reason::NOT_FOUND),
                        }
                        Ok(())
                    }
                    ViewerOp::OpenRemote(folder) => {
                        // The host skips a `List` while it is locked.
                        let refused = if state.left() & caps::BROWSE == 0 {
                            Some(reason::NOT_OFFERED)
                        } else if state.paused() & caps::BROWSE != 0 {
                            Some(reason::LOCKED)
                        } else {
                            None
                        };
                        match refused {
                            Some(reason) => {
                                emit(ViewerEvent::ListFailed {
                                    remote: true,
                                    reason,
                                });
                                Ok(())
                            }
                            None => remote.open(folder),
                        }
                    }
                    ViewerOp::Download(handle) => downloads.download(
                        handle,
                        remote.file(handle).cloned(),
                        state.left() & caps::BROWSE != 0,
                    ),
                    // Row ids are shared: one of the two has it.
                    ViewerOp::Cancel(id) => uploads
                        .cancel(id)
                        .and_then(|()| downloads.cancel(id).map(drop)),
                },
            };
            if let Err(code) = step {
                break (ViewerServicesEnd::Refused(code), Some(code));
            }
        };
        reader.abort();
        let ended = match end {
            ViewerServicesEnd::Stopped => reason::SESSION_OVER,
            ViewerServicesEnd::Closed(code) | ViewerServicesEnd::Refused(code) => code,
            ViewerServicesEnd::Io => reason::IO,
        };
        // Stops every sending task before the writer's end drops their
        // queued data, and every receiving worker: each deletes what it
        // wrote, and is waited for, so that no partial file of the stream is
        // left once `run` returns (a file already being put in place lands).
        uploads.end_all(ended);
        drop(uploads);
        downloads.end_all(ended);
        let _ = writer.close(close).await;
        downloads.join(&mut arriving, limits.workers_wait).await;
        if end != ViewerServicesEnd::Stopped {
            emit(ViewerEvent::Closed(ended));
        }
        end
    }
}

/// The host's clipboard bytes were read (decoded or skipped): they must be
/// within its window beside its downloads', and are credited (`Credit{0}`),
/// or written off when the host can no longer read a credit (`left` holds
/// neither the clipboard nor browsing).
fn clip_read(
    clip: &mut ViewerClipSync,
    downloads: &ViewerDownloads,
    left: u16,
    outbox: &Outbox,
) -> Result<(), u16> {
    if !downloads.admits(clip.inflow.owed()) {
        return Err(reason::PROTOCOL);
    }
    match clip.inflow.credit() {
        Some(upto) if left & (caps::CLIP | caps::BROWSE) != 0 => {
            if outbox.ctrl(SvcMsg::Credit {
                xfer: CLIPBOARD,
                upto,
            }) {
                Ok(())
            } else {
                // The host stopped reading (§3.4).
                Err(reason::PROTOCOL)
            }
        }
        _ => Ok(()),
    }
}

/// The host's answer to the `Bind`: a `Welcome` or a `Refused`, read only
/// if its type is one of the two.
async fn read_answer<R: AsyncRead + Unpin>(rd: &mut R) -> Result<SvcMsg, ServicesBindError> {
    let header = read_header(rd).await.map_err(svc)?.ok_or_else(|| {
        ServicesBindError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    })?;
    if !matches!(header.ty, ty::WELCOME | ty::REFUSED) {
        return Err(ServicesBindError::Protocol);
    }
    let max = ty::max_body(header.ty).unwrap_or(0);
    let body = read_body_max(rd, header, max).await.map_err(svc)?;
    SvcMsg::decode(header.ty, &body).map_err(|_| ServicesBindError::Protocol)
}

fn svc(e: SvcError) -> ServicesBindError {
    match e {
        SvcError::Io(e) => ServicesBindError::Io(e),
        _ => ServicesBindError::Protocol,
    }
}
