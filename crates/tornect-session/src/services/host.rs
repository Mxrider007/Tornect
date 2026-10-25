//! The host's end of a services stream (the services design §6.3).
//!
//! 1. **Bind.** The first frame must be a `Bind`, read at its fixed size
//!    ([`tornect_proto::services::read_bind`], 53 bytes with its prefix)
//!    within the media stream's bind deadline. It binds through the media
//!    layer's registry, once per session, under the services MAC; nothing
//!    waits for a session that is not registered (the viewer opens this
//!    stream only after its media stream's `BindOk`). A refusal is
//!    `Refused{BAD_BIND}`; a first frame that is no `Bind`,
//!    `Refused{PROTOCOL}`.
//! 2. **Live.** Nothing is answered before the session's capture is live
//!    ([`CaptureState::Live`]), for up to [`ServicesLimits::live_wait`]:
//!    capture that stops first, or is not live in time, is
//!    `Refused{NOT_LIVE}`; a session that ends first, `Refused` with its end
//!    (`SESSION_OVER`, or `ENDED_BY_HOST` after the kill switch).
//! 3. **Caps.** The session's policy snapshot, its signed mode and whether
//!    its viewer's input reaches the desktop give [`eligible`]; the
//!    desktop's clipboard is opened (on a blocking thread, within
//!    [`ServicesLimits::clipboard_wait`]) only when the clipboard is
//!    eligible, and the inbox checked only when uploads are; [`granted`]
//!    gives the caps. The capture state is read once more after those waits:
//!    input lost meanwhile (`INPUT_LOST`) takes the clipboard and files back
//!    and drops a link opened then, and capture stopped meanwhile is
//!    `Refused{CAPTURE_STOPPED}`. No caps is `Refused{NOT_OFFERED}`; else
//!    `Welcome`.
//! 4. **Serve**, until the session ends (`Close{SESSION_OVER}` or
//!    `Close{ENDED_BY_HOST}`), capture stops (`Close{CAPTURE_STOPPED}`), the
//!    viewer closes or breaks the protocol (`Close{PROTOCOL}`, or the
//!    reader's `Close{NOT_OFFERED}` for a frame never granted), or the
//!    stream fails. Chat and uploads into the inbox are served (the upload
//!    protocol: [`super::upload`]). When the viewer's input is lost
//!    mid-session the clipboard and files are turned off for good (running
//!    uploads get `Cancel{TURNED_OFF}`, then `Caps`; the link is dropped;
//!    their frames decoded before that are dropped, an `Offer` included),
//!    and a stream left with nothing ends with `Close{NOT_OFFERED}`.
//! 5. **End.** Every upload's worker is stopped, `Close` is written, and the
//!    workers are waited for, within [`ServicesLimits::workers_wait`] (5 s):
//!    once `serve` returns, no partial file of the stream is left, whatever
//!    ended it, unless a worker is stuck in one write longer (its files go
//!    when it ends, or with the stale sweep at a later start). An upload
//!    whose file was verified and was being put in place when the stream
//!    ended is past stopping: it lands (or its rename fails), and its row
//!    and the summary's count record it; a rename that outlasts the wait is
//!    still told when it lands, after `Closed`.
//!
//! The services stream ending never ends the session.
//!
//! [`ServicesLimits::live_wait`]: super::ServicesLimits::live_wait
//! [`ServicesLimits::clipboard_wait`]: super::ServicesLimits::clipboard_wait
//! [`ServicesLimits::workers_wait`]: super::ServicesLimits::workers_wait

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, watch};
use tornect_input::clipboard::ClipboardLink;
use tornect_proto::services::{
    CHUNK, Caps, Chat, MAX_BULK_WINDOW, MAX_CHAT_BYTES, MAX_CLIP, MAX_FILE, MAX_INBOX_CHARS, Side,
    SvcError, SvcMsg, Welcome, caps, read_bind, reason, write_msg,
};
use tornect_signal::fsm::host::LiveSession;

use super::chat::{self, ChatGate, ChatText, sanitize_peer_text};
use super::download::{HostDownloadParts, HostDownloads};
use super::listing::HostListings;
use super::reader::{CapState, Inbound, ReadEnd, ReaderCounts, read_frames};
use super::store::{Inbox, InboxLimits};
use super::transfer::{Ids, late};
use super::upload::HostUploads;
use super::window::{CLIPBOARD, Window};
use super::writer::{LAST_WRITE, Outbox, spawn_writer};
use super::{
    HostEvent, ServicesEnv, ServicesLimits, ServicesObserver, ServicesPolicy, ServicesSummary,
    eligible, granted,
};
use crate::flow::LineBudget;
use crate::host::{CaptureState, MediaHost, ServicesClaim};

/// At most [`PRE_BIND_LINES`] log lines in each [`PRE_BIND_WINDOW`] about
/// streams that have not bound a session: any peer that reaches the
/// services port can open streams.
const PRE_BIND_LINES: u32 = 20;
const PRE_BIND_WINDOW: Duration = Duration::from_secs(60);
/// The host user's requests queued for one stream at most.
const OPS_DEPTH: usize = 16;
/// How long making the inbox ready may take.
const INBOX_WAIT: Duration = Duration::from_secs(5);

/// How [`ServicesHost::serve`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServicesOutcome {
    /// No `Bind` in time, or a refused one (`Refused{BAD_BIND}`, or
    /// `Refused{PROTOCOL}` for a first frame that is no `Bind`).
    NotBound,
    /// Bound, and refused before any service (`Refused{reason}` was sent).
    Refused {
        /// The session.
        session_id: String,
        /// The `Refused` reason.
        reason: u16,
    },
    /// Served until `reason`.
    Served {
        /// The session.
        session_id: String,
        /// The `Close` reason written or received.
        reason: u16,
        /// What the stream carried.
        summary: ServicesSummary,
        /// What the stream's reader decoded and skipped.
        frames: ReaderCounts,
    },
}

/// What the host's user asks of a stream.
enum HostOp {
    /// Write to the viewer.
    Chat(ChatText),
    /// Stop transfer `xfer` (`Cancel{BY_HOST}`).
    Cancel(u32),
}

/// The host's end of the services streams of every session (the services
/// design §6.1, §6.3).
///
/// Call [`Self::on_start`] when a session goes live (before the media
/// layer's own `on_start`) and [`Self::on_end`] when it ends, and hand it
/// every stream accepted on `tornect_signal::SERVICES_PORT`
/// ([`Self::serve`]).
pub struct ServicesHost {
    media: Arc<MediaHost>,
    observer: Arc<dyn ServicesObserver>,
    policy: watch::Receiver<ServicesPolicy>,
    /// Each live session's policy, taken at its start (§2.5).
    snapshots: Mutex<HashMap<String, ServicesPolicy>>,
    env: ServicesEnv,
    limits: ServicesLimits,
    /// Each open stream's queue of the host user's requests.
    controls: Mutex<HashMap<String, mpsc::Sender<HostOp>>>,
    /// Streams bound and not yet ended.
    open: Arc<AtomicUsize>,
    /// The lines streams without a bound session can cause.
    pre_bind: Mutex<LineBudget>,
}

impl std::fmt::Debug for ServicesHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServicesHost")
            .field("open", &self.open_streams())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// A bound stream's place among the open ones, given up when it ends.
struct OpenStream(Arc<AtomicUsize>);

impl OpenStream {
    fn new(open: &Arc<AtomicUsize>) -> Self {
        open.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(open))
    }
}

impl Drop for OpenStream {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A stream that passed its live wait and got its caps.
struct Opened {
    end: watch::Receiver<Option<u16>>,
    capture: watch::Receiver<CaptureState>,
    input: bool,
    caps: u16,
    link: Option<ClipboardLink>,
    clipboard_refused: bool,
    welcome: Welcome,
    /// Where uploads land, with `UPLOAD`.
    inbox: Option<Inbox>,
}

impl ServicesHost {
    /// The services of the sessions `media` binds, with the policy `policy`
    /// holds (each session takes it at its start), in `env`. The desktop's
    /// clipboard is opened through `media`'s own backend.
    #[must_use]
    pub fn new(
        media: Arc<MediaHost>,
        observer: Arc<dyn ServicesObserver>,
        policy: watch::Receiver<ServicesPolicy>,
        env: ServicesEnv,
        limits: ServicesLimits,
    ) -> Self {
        Self {
            media,
            observer,
            policy,
            snapshots: Mutex::new(HashMap::new()),
            env,
            limits,
            controls: Mutex::new(HashMap::new()),
            open: Arc::new(AtomicUsize::new(0)),
            pre_bind: Mutex::new(LineBudget::new(PRE_BIND_WINDOW, PRE_BIND_LINES)),
        }
    }

    /// Session `session` is live: take its policy as the host's settings
    /// hold it now (§2.5). Call it right after the accept or the block
    /// window, before the media layer's `on_start`.
    pub fn on_start(&self, session: &LiveSession<'_>) {
        let policy = self.policy.borrow().clone();
        lock(&self.snapshots).insert(session.session_id.to_owned(), policy);
    }

    /// Session `session_id` is over. Its stream, if one is open, ends through
    /// the media layer's end (call this after the media layer's `on_end`).
    pub fn on_end(&self, session_id: &str) {
        lock(&self.snapshots).remove(session_id);
    }

    /// Services streams bound and not yet ended (a lock watcher reads the
    /// lock only while there are some).
    #[must_use]
    pub fn open_streams(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }

    /// Write `text` to the viewer of session `session_id`; `false` when it
    /// has no services stream open.
    pub fn send_chat(&self, session_id: &str, text: ChatText) -> bool {
        self.op(session_id, HostOp::Chat(text))
    }

    /// Stop transfer `xfer` of session `session_id`, as the host's user asks
    /// (`Cancel{BY_HOST}`; what was received of it is deleted); `false` when
    /// the session has no services stream open. A transfer that already
    /// ended is left as it is.
    pub fn cancel(&self, session_id: &str, xfer: u32) -> bool {
        self.op(session_id, HostOp::Cancel(xfer))
    }

    fn op(&self, session_id: &str, op: HostOp) -> bool {
        lock(&self.controls)
            .get(session_id)
            .is_some_and(|ops| ops.try_send(op).is_ok())
    }

    /// Serve one stream accepted on the onion service's services port, from
    /// its `Bind` to its end.
    pub async fn serve<S>(&self, stream: S) -> ServicesOutcome
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let bind = match tokio::time::timeout(self.media.bind_deadline(), read_bind(&mut rd)).await
        {
            Ok(Ok(bind)) => bind,
            Ok(Err(SvcError::Io(_))) | Err(_) => {
                if let Some(left_out) = self.line() {
                    tracing::debug!(left_out, "services stream sent no bind");
                }
                return ServicesOutcome::NotBound;
            }
            Ok(Err(e)) => {
                if let Some(left_out) = self.line() {
                    tracing::debug!(
                        error = %e,
                        left_out,
                        "services stream opened with something other than a bind"
                    );
                }
                refuse_with(&mut wr, reason::PROTOCOL).await;
                return ServicesOutcome::NotBound;
            }
        };
        let session_id = bind.session_id;
        let Some(claim) = self.media.claim_services(&session_id, &bind.mac) else {
            if let Some(left_out) = self.line() {
                tracing::info!(session = %session_id, left_out, "services bind refused");
            }
            refuse_with(&mut wr, reason::BAD_BIND).await;
            return ServicesOutcome::NotBound;
        };
        let _open = OpenStream::new(&self.open);
        match self.open_services(&session_id, claim).await {
            Err(code) => {
                tracing::info!(session = %session_id, reason = code, "services refused");
                refuse_with(&mut wr, code).await;
                ServicesOutcome::Refused {
                    session_id,
                    reason: code,
                }
            }
            Ok(opened) => self.run(session_id, opened, rd, wr).await,
        }
    }

    /// Steps 2 and 3: wait for capture, then fix the caps; `Err` with the
    /// `Refused` reason.
    async fn open_services(&self, session_id: &str, claim: ServicesClaim) -> Result<Opened, u16> {
        let ServicesClaim {
            mode,
            label: _,
            mut end,
            mut capture,
        } = claim;
        // Nothing before the first picture (§2.2): capture follows the accept
        // and the unattended block window, so services never come before
        // consent.
        let live = tokio::select! {
            biased;
            code = ended(&mut end) => return Err(code),
            live = tokio::time::timeout(
                self.limits.live_wait,
                capture.wait_for(|state| *state != CaptureState::Pending),
            ) => match live {
                Ok(Ok(state)) => *state,
                // The session's registration is gone.
                Ok(Err(_)) => CaptureState::Stopped,
                Err(_) => return Err(reason::NOT_LIVE),
            },
        };
        let CaptureState::Live { mut input } = live else {
            return Err(reason::NOT_LIVE);
        };
        let policy = self.snapshot(session_id);
        let mut eligible = eligible(&policy, mode, input);

        let mut link = None;
        if eligible & caps::CLIP != 0 {
            let backend = self.media.backend();
            let sid = session_id.to_owned();
            let open = tokio::task::spawn_blocking(move || backend.open_clipboard(&sid));
            // A link that opens after the wait, or after the session ended,
            // is dropped with the task's output, which stops its backend.
            link = tokio::select! {
                biased;
                code = ended(&mut end) => return Err(code),
                opened = tokio::time::timeout(self.limits.clipboard_wait, open) => match opened {
                    Ok(Ok(link)) => link,
                    Ok(Err(_)) => {
                        tracing::warn!(session = %session_id, "opening the clipboard failed");
                        None
                    }
                    Err(_) => {
                        tracing::warn!(
                            session = %session_id,
                            "the desktop's clipboard did not open in time"
                        );
                        None
                    }
                },
            };
        }
        let inbox_usable = eligible & caps::UPLOAD != 0 && self.inbox_ready(session_id).await;

        // What happened during those waits (the step 8–9 obligation): input
        // lost meanwhile takes the clipboard and files back, and a link that
        // opened meanwhile is dropped; capture that stopped refuses. The
        // state is marked seen, so the loop hears every later change.
        if end.borrow().is_some() {
            return Err(end_reason(&end));
        }
        match *capture.borrow_and_update() {
            CaptureState::Live { input: true } => {}
            CaptureState::Live { input: false } => {
                if input {
                    tracing::info!(
                        session = %session_id,
                        "the viewer's input was lost before services opened"
                    );
                }
                input = false;
                eligible = super::eligible(&policy, mode, false);
            }
            CaptureState::Pending | CaptureState::Stopped => return Err(reason::CAPTURE_STOPPED),
        }
        if eligible & caps::CLIP == 0 {
            link = None;
        }
        let caps = granted(eligible, link.is_some(), inbox_usable);
        if caps == 0 {
            return Err(reason::NOT_OFFERED);
        }
        let welcome = self.welcome(caps, &policy);
        let inbox = match &self.env.inbox {
            Some(dir) if caps & caps::UPLOAD != 0 => Some(Inbox::new(
                dir.clone(),
                InboxLimits {
                    max_file: welcome.file_max,
                    quota: policy.session_quota,
                    files: u32::from(self.limits.session_files),
                    keep_free: policy.keep_free,
                    min_charge: self.limits.min_file_charge,
                    recheck_every: self.limits.recheck_free_every,
                },
                Arc::clone(&self.env.free_space),
            )),
            _ => None,
        };
        #[cfg(test)]
        let inbox = inbox.map(|inbox| inbox.with_finishing(self.env.finishing.clone()));
        Ok(Opened {
            end,
            capture,
            input,
            caps,
            clipboard_refused: eligible & caps::CLIP != 0 && link.is_none(),
            link,
            welcome,
            inbox,
        })
    }

    /// The session's policy as it started, or the host's now for a session
    /// that started before this host heard of it.
    fn snapshot(&self, session_id: &str) -> ServicesPolicy {
        lock(&self.snapshots)
            .get(session_id)
            .cloned()
            .unwrap_or_else(|| self.policy.borrow().clone())
    }

    /// Whether uploads can land: the inbox is known and is (or now is) a
    /// private folder of this user; partial files of a crashed instance are
    /// swept from it.
    async fn inbox_ready(&self, session_id: &str) -> bool {
        let Some(inbox) = self.env.inbox.clone() else {
            return false;
        };
        let ready = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            tornect_core::files::user_folder(&inbox)?;
            if let Err(e) =
                tornect_core::files::sweep_stale(&inbox, tornect_core::files::STALE_AFTER)
            {
                tracing::debug!(error_kind = ?e.kind(), "the inbox's stale partial files were not swept");
            }
            Ok(())
        });
        match tokio::time::timeout(INBOX_WAIT, ready).await {
            Ok(Ok(Ok(()))) => true,
            Ok(Ok(Err(e))) => {
                tracing::warn!(
                    session = %session_id,
                    error_kind = ?e.kind(),
                    "the inbox cannot take files: uploads are not offered"
                );
                false
            }
            Ok(Err(_)) | Err(_) => {
                tracing::warn!(
                    session = %session_id,
                    "the inbox was not ready in time: uploads are not offered"
                );
                false
            }
        }
    }

    /// `Welcome` for `caps` under `policy`, every number within the wire's
    /// bounds.
    fn welcome(&self, caps: u16, policy: &ServicesPolicy) -> Welcome {
        let inbox = if caps & caps::UPLOAD != 0 {
            self.env.inbox_words.chars().take(MAX_INBOX_CHARS).collect()
        } else {
            String::new()
        };
        Welcome {
            caps,
            clip_max: MAX_CLIP,
            file_max: policy.max_file.clamp(1, MAX_FILE),
            session_quota: policy.session_quota,
            session_files: self.limits.session_files,
            chat_max: u16::try_from(MAX_CHAT_BYTES).unwrap_or(u16::MAX),
            bulk_window: self
                .limits
                .bulk_window
                .clamp(u32::try_from(CHUNK).unwrap_or(u32::MAX), MAX_BULK_WINDOW),
            inbox,
        }
    }

    /// Step 4: serve until the stream ends.
    async fn run<R, W>(&self, session_id: String, opened: Opened, rd: R, wr: W) -> ServicesOutcome
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let Opened {
            mut end,
            mut capture,
            mut input,
            caps,
            mut link,
            clipboard_refused,
            welcome,
            inbox,
        } = opened;
        let state = Arc::new(CapState::new(caps));
        let (outbox, mut writer) = spawn_writer(wr);
        let ids = Ids::default();
        let (uploads, mut reports) = HostUploads::new(
            &session_id,
            inbox,
            Arc::clone(&self.observer),
            outbox.clone(),
            welcome.bulk_window,
            ids.clone(),
            &self.limits,
        );
        let window = Arc::new(Window::new(welcome.bulk_window));
        let (downloads, mut sends) = HostDownloads::new(HostDownloadParts {
            session_id: session_id.clone(),
            access: Arc::clone(&self.env.access),
            observer: Arc::clone(&self.observer),
            outbox: outbox.clone(),
            window: Arc::clone(&window),
            ids: ids.clone(),
            file_max: welcome.file_max,
            chunk: self.limits.chunk.clamp(1, CHUNK),
            read_timeout: self.limits.read_timeout,
            #[cfg(test)]
            hook: self.env.open_hook.clone(),
        });
        let (listings, mut listed) =
            HostListings::new(Arc::clone(&self.env.access), outbox.clone(), &self.limits);
        #[cfg(test)]
        let listings = listings.with_hook(self.env.list_hook.clone());
        // The first frame: nothing else is queued yet.
        outbox.ctrl(SvcMsg::Welcome(welcome));
        let (tx, mut inbound) = mpsc::channel(self.limits.inbound_depth.max(1));
        let reader = tokio::spawn(read_frames(rd, Side::Viewer, Arc::clone(&state), tx));
        let (ops_tx, mut ops) = mpsc::channel(OPS_DEPTH);
        lock(&self.controls).insert(session_id.clone(), ops_tx);
        tracing::info!(session = %session_id, caps, input, clipboard_refused, "services opened");
        self.observer.event(
            &session_id,
            HostEvent::Opened {
                caps,
                input,
                clipboard_refused,
            },
        );

        let mut served = Served {
            session_id: &session_id,
            observer: self.observer.as_ref(),
            state: &state,
            outbox: &outbox,
            chat: ChatGate::new(chat::now()),
            summary: ServicesSummary::default(),
            ids,
            window,
            uploads,
            downloads,
            listings,
        };
        // The `Close` reason, and whether to write it (not to a viewer that
        // closed, nor on a stream that failed).
        let (code, write_close) = loop {
            tokio::select! {
                biased;
                code = ended(&mut end) => break (code, true),
                changed = capture.changed() => {
                    match changed.map(|()| *capture.borrow_and_update()) {
                        Ok(CaptureState::Live { input: false }) if input => {
                            input = false;
                            // The clipboard goes with the viewer's input.
                            link = None;
                            if let Some(code) = served.input_lost() {
                                break (code, true);
                            }
                        }
                        Ok(CaptureState::Live { .. }) => {}
                        Ok(CaptureState::Pending | CaptureState::Stopped) | Err(_) => {
                            break (reason::CAPTURE_STOPPED, true);
                        }
                    }
                }
                _ = writer.stopped() => break (reason::IO, false),
                Some(report) = reports.recv() => {
                    if let Err(code) = served.uploads.on_worker(report) {
                        break (code, true);
                    }
                }
                Some(opened) = sends.opened.recv() => {
                    if let Err(code) = served.downloads.on_opened(opened) {
                        break (code, true);
                    }
                }
                Some(failed) = sends.failed.recv() => {
                    if let Err(code) = served.downloads.send_failed(failed) {
                        break (code, true);
                    }
                }
                Some(done) = listed.recv() => {
                    if let Err(code) = served.listings.done(done) {
                        break (code, true);
                    }
                }
                Some(op) = ops.recv() => {
                    if let Some(code) = served.on_op(op) {
                        break (code, true);
                    }
                }
                Some(inbound) = inbound.recv() => match inbound {
                    Inbound::Frame(msg) => {
                        if let Some(ended) = served.on_frame(msg) {
                            break ended;
                        }
                    }
                    Inbound::End(ReadEnd::Eof) => break (reason::BY_VIEWER, false),
                    Inbound::End(ReadEnd::Io) => break (reason::IO, false),
                    Inbound::End(ReadEnd::Refuse(code)) => break (code, true),
                },
            }
        };
        let Served {
            mut summary,
            mut uploads,
            mut downloads,
            mut listings,
            ..
        } = served;

        lock(&self.controls).remove(&session_id);
        // Every worker stops first: each deletes what it wrote. One that is
        // putting a verified file in place is past stopping: it lands or
        // fails, and its report is still handled below. Files being sent
        // stop at their next chunk, and a listing at its next entry.
        uploads.stop();
        downloads.stop(code);
        listings.stop();
        drop(link);
        reader.abort();
        let _ = writer.close(write_close.then_some(code)).await;
        let settled = uploads.join(&mut reports, self.limits.workers_wait).await;
        summary.files_in = uploads.files_in;
        summary.bytes_in = uploads.bytes_in;
        summary.files_out = downloads.files_out;
        summary.bytes_out = downloads.bytes_out;
        let frames = state.counts();
        tracing::info!(
            session = %session_id,
            reason = code,
            chat_in = summary.chat_in,
            chat_out = summary.chat_out,
            files_in = summary.files_in,
            bytes_in = summary.bytes_in,
            files_out = summary.files_out,
            bytes_out = summary.bytes_out,
            dropped = summary.dropped,
            decoded = frames.decoded,
            skipped = frames.skipped,
            "services closed"
        );
        self.observer.event(
            &session_id,
            HostEvent::Closed {
                reason: code,
                summary,
            },
        );
        if !settled && uploads.landing() {
            // A rename that outlasted the wait: the file's row is still
            // told when it lands, after `Closed`.
            tokio::spawn(uploads.settle(reports));
        }
        ServicesOutcome::Served {
            session_id,
            reason: code,
            summary,
            frames,
        }
    }

    /// Whether a line about a stream without a bound session may be logged
    /// now: how many were left out before it, or `None`.
    fn line(&self) -> Option<u64> {
        lock(&self.pre_bind).take(tokio::time::Instant::now().into_std())
    }
}

/// What the loop of one open stream keeps.
struct Served<'a> {
    session_id: &'a str,
    observer: &'a dyn ServicesObserver,
    state: &'a CapState,
    outbox: &'a Outbox,
    chat: ChatGate,
    summary: ServicesSummary,
    /// The transfer ids, shared by the uploads and the downloads.
    ids: Ids,
    /// The host's sending window: downloads (and the clipboard's text).
    window: Arc<Window>,
    uploads: HostUploads,
    downloads: HostDownloads,
    listings: HostListings,
}

impl Served<'_> {
    /// A frame from the viewer, which the reader let through: `Some` with
    /// the `Close` reason and whether to write it when the stream ends.
    fn on_frame(&mut self, msg: SvcMsg) -> Option<(u16, bool)> {
        if !self.state.serves(msg.ty(), Side::Viewer) {
            // Decoded before its caps were turned off (the viewer's input
            // was lost), and queued: dropped, as the reader now skips it. A
            // dropped `Offer` takes no id and starts nothing; the viewer
            // ended its uploads when it heard the caps.
            tracing::trace!(
                session = %self.session_id,
                ty = msg.ty(),
                "a services frame queued before its caps were turned off was dropped"
            );
            return None;
        }
        match msg {
            SvcMsg::Chat(Chat { text }) => {
                if !self.chat.admit(chat::now()) {
                    self.summary.dropped = self.summary.dropped.saturating_add(1);
                    return None;
                }
                match sanitize_peer_text(&text) {
                    Some(text) => {
                        self.summary.chat_in = self.summary.chat_in.saturating_add(1);
                        self.observer.event(self.session_id, HostEvent::Chat(text));
                    }
                    None => self.summary.dropped = self.summary.dropped.saturating_add(1),
                }
                None
            }
            // The viewer ends the stream: nothing more is written to it.
            SvcMsg::Close { reason } => Some((reason, false)),
            SvcMsg::Offer(offer) => {
                let paused = self.state.paused() & caps::UPLOAD != 0;
                self.uploads
                    .offer(offer, paused)
                    .err()
                    .map(|code| (code, true))
            }
            SvcMsg::Data {
                xfer,
                offset,
                bytes,
            } => self
                .uploads
                .data(xfer, offset, bytes)
                .err()
                .map(|code| (code, true)),
            SvcMsg::Done(done) => self.uploads.done(done).err().map(|code| (code, true)),
            SvcMsg::Cancel(cancel) => {
                let ended = match self.uploads.cancelled(cancel) {
                    Ok(false) => match self.downloads.cancelled(cancel) {
                        // One that ended lately, or none.
                        Ok(false) => late(&self.ids, cancel.xfer),
                        other => other.map(drop),
                    },
                    other => other.map(drop),
                };
                ended.err().map(|code| (code, true))
            }
            SvcMsg::Get(get) => {
                let paused = self.state.paused() & caps::BROWSE != 0;
                let path = self.listings.path_of(get.handle);
                self.downloads
                    .get(get, path, paused)
                    .err()
                    .map(|code| (code, true))
            }
            SvcMsg::Credit { xfer, upto } => {
                let credited = if xfer == CLIPBOARD {
                    // The host's clipboard text (the design's step 18):
                    // nothing of it is sent yet, so only a credit of nothing
                    // is in range.
                    self.window
                        .credit(CLIPBOARD, upto)
                        .map_err(|_| reason::PROTOCOL)
                } else {
                    self.downloads.credit(xfer, upto)
                };
                credited.err().map(|code| (code, true))
            }
            SvcMsg::Complete(complete) => self
                .downloads
                .complete(complete)
                .err()
                .map(|code| (code, true)),
            SvcMsg::List(list) => {
                let paused = self.state.paused() & caps::BROWSE != 0;
                self.listings
                    .list(list, paused)
                    .err()
                    .map(|code| (code, true))
            }
            // The clipboard is served from the design's step 18 on; until
            // then a granted frame of its is read and left unanswered.
            other => {
                tracing::trace!(
                    session = %self.session_id,
                    ty = other.ty(),
                    "services frame not served by this build"
                );
                None
            }
        }
    }

    /// A request of the host's user: `Some` with the `Close` reason when the
    /// stream must end.
    fn on_op(&mut self, op: HostOp) -> Option<u16> {
        match op {
            HostOp::Chat(text) => {
                if self.state.left() & caps::CHAT == 0 {
                    return None;
                }
                let text = text.within(MAX_CHAT_BYTES)?;
                if !self.outbox.ctrl(SvcMsg::Chat(Chat {
                    text: text.as_str().to_owned(),
                })) {
                    // The viewer stopped reading (§3.4).
                    return Some(reason::PROTOCOL);
                }
                self.summary.chat_out = self.summary.chat_out.saturating_add(1);
                None
            }
            HostOp::Cancel(xfer) => match self.uploads.cancel(xfer, reason::BY_HOST) {
                Ok(false) => self.downloads.cancel(xfer, reason::BY_HOST).err(),
                other => other.err(),
            },
        }
    }

    /// The viewer's input no longer reaches the desktop (`INPUT_LOST`): the
    /// clipboard and files are turned off for the rest of the stream, which
    /// the viewer hears in a `Caps`. `Some` with the `Close` reason when
    /// nothing is left, or the viewer stopped reading.
    fn input_lost(&mut self) -> Option<u16> {
        let before = self.state.left();
        let left = self.state.turn_off(caps::PAUSABLE);
        tracing::info!(
            session = %self.session_id,
            caps = left,
            "the viewer's input was lost: the clipboard and files are off"
        );
        if left == before {
            return None;
        }
        // Running transfers end before the viewer hears the caps, so that
        // each gets its own reason; a listing being read stops.
        if let Err(code) = self.uploads.cancel_all(reason::TURNED_OFF) {
            return Some(code);
        }
        if let Err(code) = self.downloads.cancel_all(reason::TURNED_OFF) {
            return Some(code);
        }
        self.listings.stop();
        if left == 0 {
            return Some(reason::NOT_OFFERED);
        }
        let paused = self.state.paused() & left;
        if !self.outbox.ctrl(SvcMsg::Caps(Caps { caps: left, paused })) {
            return Some(reason::PROTOCOL);
        }
        self.observer
            .event(self.session_id, HostEvent::Caps { caps: left, paused });
        None
    }
}

/// Answer a services stream with `Refused{NOT_OFFERED}` and close it: the
/// terminal host (`tornect host`) has no services, and advertises `svc1` all
/// the same so that a viewer's choice of port does not tell the two hosts
/// apart (§0).
pub async fn refuse<S: AsyncWrite + Unpin>(mut stream: S) {
    refuse_with(&mut stream, reason::NOT_OFFERED).await;
}

/// Write `Refused{code}` and shut down, each within [`LAST_WRITE`].
async fn refuse_with<W: AsyncWrite + Unpin>(wr: &mut W, code: u16) {
    let _ =
        tokio::time::timeout(LAST_WRITE, write_msg(wr, &SvcMsg::Refused { reason: code })).await;
    let _ = tokio::time::timeout(LAST_WRITE, wr.shutdown()).await;
}

/// The services `Close` reason for a session that ended. The media layer
/// sets the session's end with its media stream's reason
/// (`tornect_proto::reason`), whose codes are not the services stream's: a
/// killed session (`ENDED_BY_HOST`) is `ENDED_BY_HOST` here, any other end,
/// and a media host that went away, `SESSION_OVER`.
fn services_reason(media: Option<u16>) -> u16 {
    match media {
        Some(tornect_proto::reason::ENDED_BY_HOST) => reason::ENDED_BY_HOST,
        _ => reason::SESSION_OVER,
    }
}

/// The `Close` reason for the session's end as it stands
/// ([`services_reason`]).
fn end_reason(end: &watch::Receiver<Option<u16>>) -> u16 {
    services_reason(*end.borrow())
}

/// Wait for the session's end, then its `Close` reason
/// ([`services_reason`]).
async fn ended(end: &mut watch::Receiver<Option<u16>>) -> u16 {
    match end.wait_for(Option::is_some).await {
        Ok(code) => services_reason(*code),
        Err(_) => reason::SESSION_OVER,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
