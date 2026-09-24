//! The RemoteDesktop portal session (`docs/research/slice.md` §4; research
//! report §3): one session that casts a monitor and takes keyboard and pointer
//! input, so one consent dialog covers both.
//!
//! The call sequence is the report's: `CreateSession`, `SelectDevices`
//! (keyboard and pointer, persistence "until revoked" with the stored restore
//! token), `SelectSources` (one monitor, the cursor embedded in the picture),
//! `Start` (the dialog), then `OpenPipeWireRemote`. Input goes through the
//! `Notify*` methods; `ConnectToEIS` is never called, because once it is, every
//! `Notify*` call fails (RemoteDesktop.xml 446–448).
//!
//! ashpd speaks D-Bus through zbus, and zbus runs its connection on the tokio
//! runtime it was created on, for as long as the connection lives. The session
//! therefore lives on a thread of its own, with a current-thread runtime and a
//! connection of its own (never ashpd's process-wide one, which would outlive
//! this runtime). Input reaches that thread through a bounded queue, so an
//! injector never blocks the session's task on a D-Bus round trip.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use ashpd::desktop::remote_desktop::{
    Axis, DeviceType, KeyState, RemoteDesktop, SelectDevicesOptions, StartOptions,
};
use ashpd::desktop::screencast::{
    CursorMode, OpenPipeWireRemoteOptions, Screencast, SelectSourcesOptions, SourceType,
};
use ashpd::desktop::{CreateSessionOptions, PersistMode, ResponseError, Session};
use ashpd::enumflags2::BitFlags;
use ashpd::zbus;
use futures::StreamExt as _;
use tokio::sync::{mpsc, watch};
use tornect_input::InputError;

use super::pipewire::PW_ID_ANY;
use crate::CaptureError;

/// How long one portal call may take (the dialog aside).
const STEP_WAIT: Duration = Duration::from_secs(10);
/// Portal calls made before the dialog, each bounded by [`STEP_WAIT`].
const STEPS: u32 = 6;
/// How long closing the session may take.
const CLOSE_WAIT: Duration = Duration::from_secs(2);
/// How long one input call may take before it is given up.
const INPUT_WAIT: Duration = Duration::from_secs(1);
/// Input calls queued for the portal thread; one beyond that is dropped.
/// Above the session's input burst (500 events, up to two calls each).
const INPUT_QUEUE: usize = 1024;
/// The longest restore token read back (the portal's are UUIDs).
const MAX_TOKEN: usize = 256;

/// The D-Bus the portal is reached on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Bus {
    /// The desktop's session bus (`DBUS_SESSION_BUS_ADDRESS`).
    #[default]
    Session,
    /// A bus at this D-Bus address.
    Address(String),
}

/// What opening a portal session needs.
#[derive(Debug, Clone)]
pub(crate) struct Setup {
    pub(crate) bus: Bus,
    /// Where the restore token lives; `None` keeps nothing and asks every time.
    pub(crate) token_file: Option<PathBuf>,
    /// How long the user has to answer the dialog.
    pub(crate) dialog_wait: Duration,
    /// Turns `true` when the session this is for is over before it started.
    pub(crate) cancel: Option<watch::Receiver<bool>>,
}

/// A started session, as the capture side needs it.
#[derive(Debug)]
pub(crate) struct Opened {
    /// The screen cast's PipeWire node.
    pub(crate) node_id: u32,
    /// The stream's size in the compositor's logical coordinates, which is what
    /// absolute pointer motion is expressed in (not pixels).
    pub(crate) logical: Option<(u32, u32)>,
    /// Keyboard and pointer were both granted.
    pub(crate) input: bool,
    /// The PipeWire remote the node is reachable on.
    pub(crate) fd: OwnedFd,
}

/// The screen cast the portal started, before it is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StreamInfo {
    pub(crate) node_id: u32,
    pub(crate) logical: Option<(u32, u32)>,
}

/// The first stream of a `Start` response, refused if it cannot be consumed
/// safely: no stream, or a node id that would let PipeWire pick any node.
pub(crate) fn choose_stream(
    streams: impl IntoIterator<Item = (u32, Option<(i32, i32)>)>,
) -> Result<StreamInfo, CaptureError> {
    let (node_id, size) = streams.into_iter().next().ok_or_else(|| {
        unavailable("the portal started the session but shared no screen (no PipeWire stream)")
    })?;
    if node_id == 0 || node_id == PW_ID_ANY {
        return Err(unavailable(format!(
            "the portal returned PipeWire node {node_id}, which names no screen cast"
        )));
    }
    let positive = |v: i32| u32::try_from(v).ok().filter(|&v| v > 0);
    let logical = size.and_then(|(w, h)| Some((positive(w)?, positive(h)?)));
    Ok(StreamInfo { node_id, logical })
}

/// A scroll axis, as `NotifyPointerAxisDiscrete` numbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScrollAxis {
    Vertical,
    Horizontal,
}

/// One `Notify*` call.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Call {
    /// `NotifyPointerMotionAbsolute`, in the stream's logical coordinates.
    Motion { x: f64, y: f64 },
    /// `NotifyPointerButton`, an evdev button code.
    Button { code: i32, pressed: bool },
    /// `NotifyPointerAxisDiscrete`; `steps` is never 0.
    Scroll { axis: ScrollAxis, steps: i32 },
    /// `NotifyKeyboardKeycode`, an evdev key code.
    Key { code: i32, pressed: bool },
}

impl Call {
    /// What kind of call this is, for logs: never the key, which could be part
    /// of a password being typed.
    fn kind(&self) -> &'static str {
        match self {
            Self::Motion { .. } => "pointer motion",
            Self::Button { .. } => "pointer button",
            Self::Scroll { .. } => "scroll",
            Self::Key { .. } => "key",
        }
    }
}

/// A live portal session, owned by its thread. Dropping the last handle closes
/// the session: the desktop's sharing indicator goes away, and the compositor
/// releases whatever the session's virtual devices still hold.
pub(crate) struct Portal {
    calls: Option<mpsc::Sender<Call>>,
    /// Set once the session is over, whoever ended it.
    over: Arc<AtomicBool>,
    /// Disconnects when the thread has finished.
    finished: Mutex<Option<Receiver<()>>>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Portal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Portal")
            .field("over", &self.is_over())
            .finish_non_exhaustive()
    }
}

fn unavailable(why: impl Into<String>) -> CaptureError {
    CaptureError::Unavailable(why.into())
}

impl Portal {
    /// Start a session, asking the user unless a stored restore token still
    /// holds. Blocks until it is started, refused, or out of time.
    pub(crate) fn open(setup: Setup) -> Result<(Self, Opened), CaptureError> {
        let (opened_tx, opened_rx) = std::sync::mpsc::sync_channel(1);
        let (calls_tx, calls_rx) = mpsc::channel(INPUT_QUEUE);
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel::<()>(0);
        let over = Arc::new(AtomicBool::new(false));
        // Every step on the thread is bounded, so this only guards against a
        // thread that is stuck anyway.
        let wait = setup.dialog_wait + STEP_WAIT * (STEPS + 1);
        let thread = std::thread::Builder::new()
            .name("tornect-portal".to_owned())
            .spawn({
                let over = Arc::clone(&over);
                move || {
                    let _finished = finished_tx;
                    let _over = SetOnDrop(Arc::clone(&over));
                    run(&setup, &opened_tx, calls_rx, &over);
                }
            })
            .map_err(|e| unavailable(format!("cannot start the portal thread: {e}")))?;
        let portal = Self {
            calls: Some(calls_tx),
            over,
            finished: Mutex::new(Some(finished_rx)),
            thread: Some(thread),
        };
        match opened_rx.recv_timeout(wait) {
            Ok(Ok(opened)) => Ok((portal, opened)),
            Ok(Err(e)) => Err(e),
            Err(RecvTimeoutError::Timeout) => Err(unavailable(format!(
                "the screen-sharing portal did not answer within {} s",
                wait.as_secs()
            ))),
            Err(RecvTimeoutError::Disconnected) => Err(unavailable(
                "the portal thread stopped before the session started",
            )),
        }
    }

    /// Whether the session is over (closed here, by the desktop, or failed).
    pub(crate) fn is_over(&self) -> bool {
        self.over.load(Ordering::SeqCst)
    }

    /// Queue one call; never blocks.
    pub(crate) fn send(&self, call: Call) -> Result<(), InputError> {
        if self.is_over() {
            return Err(InputError::Inject(
                "the remote-desktop session is over".to_owned(),
            ));
        }
        let Some(calls) = &self.calls else {
            return Err(InputError::Inject(
                "the remote-desktop session is closing".to_owned(),
            ));
        };
        calls.try_send(call).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => InputError::Inject(
                "the desktop is not keeping up with the viewer's input; an event was dropped"
                    .to_owned(),
            ),
            mpsc::error::TrySendError::Closed(_) => {
                InputError::Inject("the remote-desktop session is over".to_owned())
            }
        })
    }
}

impl Drop for Portal {
    fn drop(&mut self) {
        // The queue ends, so the thread closes the session and returns.
        drop(self.calls.take());
        let finished = self
            .finished
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let done = finished.is_some_and(|f| {
            matches!(
                f.recv_timeout(CLOSE_WAIT + STEP_WAIT),
                Err(RecvTimeoutError::Disconnected) | Ok(())
            )
        });
        match self.thread.take() {
            Some(thread) if done => {
                let _ = thread.join();
            }
            Some(_) => tracing::warn!("the portal thread did not finish; left to end on its own"),
            None => {}
        }
    }
}

#[cfg(test)]
impl Portal {
    /// A handle with no session or thread behind it: its calls land in the
    /// receiver.
    pub(crate) fn detached(capacity: usize) -> (Self, mpsc::Receiver<Call>) {
        let (calls, rx) = mpsc::channel(capacity);
        let portal = Self {
            calls: Some(calls),
            over: Arc::new(AtomicBool::new(false)),
            finished: Mutex::new(None),
            thread: None,
        };
        (portal, rx)
    }
}

/// Marks the session over when the portal thread ends, however it ends.
struct SetOnDrop(Arc<AtomicBool>);

impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// The portal thread: start the session, report it, then pass input calls on
/// until every handle is gone or the desktop closes the session.
fn run(
    setup: &Setup,
    opened: &SyncSender<Result<Opened, CaptureError>>,
    mut calls: mpsc::Receiver<Call>,
    over: &AtomicBool,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = opened.send(Err(unavailable(format!("no runtime for the portal: {e}"))));
            return;
        }
    };
    runtime.block_on(async {
        let started = match start(setup).await {
            Ok(started) => started,
            Err(e) => {
                let _ = opened.send(Err(e));
                return;
            }
        };
        let Started {
            remote,
            session,
            reply,
        } = started;
        let node_id = reply.node_id;
        let mut closed = match session.receive_closed().await {
            Ok(signal) => Some(Box::pin(signal)),
            Err(e) => {
                tracing::debug!(error = %e, "cannot watch the portal session for its end");
                None
            }
        };
        if opened.send(Ok(reply)).is_err() {
            // The opener stopped waiting: nobody will use this session.
            close(&session).await;
            return;
        }
        loop {
            let call = tokio::select! {
                call = calls.recv() => call,
                () = ended(&mut closed) => {
                    over.store(true, Ordering::SeqCst);
                    tracing::info!("the desktop ended the screen-sharing session");
                    return;
                }
            };
            let Some(call) = call else { break };
            match tokio::time::timeout(INPUT_WAIT, notify(&remote, &session, node_id, call)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, kind = call.kind(), "the portal refused an input event");
                }
                Err(_) => tracing::debug!(kind = call.kind(), "an input event timed out at the portal"),
            }
        }
        over.store(true, Ordering::SeqCst);
        close(&session).await;
    });
}

/// Resolves when the session's `Closed` signal arrives (or its stream ends).
async fn ended<S: futures::Stream + Unpin>(closed: &mut Option<S>) {
    match closed {
        Some(signal) => {
            signal.next().await;
        }
        None => std::future::pending::<()>().await,
    }
}

async fn close(session: &Session<RemoteDesktop>) {
    match tokio::time::timeout(CLOSE_WAIT, session.close()).await {
        Ok(Ok(())) => tracing::debug!("portal session closed"),
        Ok(Err(e)) => tracing::debug!(error = %e, "closing the portal session failed"),
        Err(_) => tracing::debug!("closing the portal session timed out"),
    }
}

async fn notify(
    remote: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    node_id: u32,
    call: Call,
) -> Result<(), ashpd::Error> {
    let state = |pressed| {
        if pressed {
            KeyState::Pressed
        } else {
            KeyState::Released
        }
    };
    match call {
        Call::Motion { x, y } => {
            remote
                .notify_pointer_motion_absolute(session, node_id, x, y, Default::default())
                .await
        }
        Call::Button { code, pressed } => {
            remote
                .notify_pointer_button(session, code, state(pressed), Default::default())
                .await
        }
        Call::Scroll { axis, steps } => {
            let axis = match axis {
                ScrollAxis::Vertical => Axis::Vertical,
                ScrollAxis::Horizontal => Axis::Horizontal,
            };
            remote
                .notify_pointer_axis_discrete(session, axis, steps, Default::default())
                .await
        }
        Call::Key { code, pressed } => {
            remote
                .notify_keyboard_keycode(session, code, state(pressed), Default::default())
                .await
        }
    }
}

struct Started {
    remote: RemoteDesktop,
    session: Session<RemoteDesktop>,
    reply: Opened,
}

/// A portal call bounded by [`STEP_WAIT`], its errors made `Unavailable`.
async fn step<T>(
    what: &str,
    call: impl Future<Output = Result<T, ashpd::Error>>,
) -> Result<T, CaptureError> {
    match tokio::time::timeout(STEP_WAIT, call).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(unavailable(format!(
            "the screen-sharing portal ({what}): {e}"
        ))),
        Err(_) => Err(unavailable(format!(
            "the screen-sharing portal did not answer {what} within {} s",
            STEP_WAIT.as_secs()
        ))),
    }
}

async fn connect(bus: &Bus) -> zbus::Result<zbus::Connection> {
    match bus {
        Bus::Session => zbus::Connection::session().await,
        Bus::Address(address) => {
            zbus::connection::Builder::address(address.as_str())?
                .build()
                .await
        }
    }
}

async fn start(setup: &Setup) -> Result<Started, CaptureError> {
    let connection = match tokio::time::timeout(STEP_WAIT, connect(&setup.bus)).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(e)) => {
            return Err(unavailable(format!(
                "cannot reach the desktop's D-Bus session bus, so there is no screen-sharing \
                 portal: {e}"
            )));
        }
        Err(_) => return Err(unavailable("the D-Bus session bus did not answer")),
    };
    let remote = step(
        "RemoteDesktop",
        RemoteDesktop::with_connection(connection.clone()),
    )
    .await?;
    let screencast = step("ScreenCast", Screencast::with_connection(connection)).await?;
    let session = step(
        "CreateSession",
        remote.create_session(CreateSessionOptions::default()),
    )
    .await?;
    match negotiate(setup, &remote, &screencast, &session).await {
        Ok(reply) => Ok(Started {
            remote,
            session,
            reply,
        }),
        Err(e) => {
            close(&session).await;
            Err(e)
        }
    }
}

async fn negotiate(
    setup: &Setup,
    remote: &RemoteDesktop,
    screencast: &Screencast,
    session: &Session<RemoteDesktop>,
) -> Result<Opened, CaptureError> {
    // Persistence belongs on SelectDevices (RemoteDesktop v2), never on
    // SelectSources for a remote-desktop session (ScreenCast.xml 125–140).
    let token_file = setup
        .token_file
        .as_deref()
        .filter(|_| remote.version() >= 2);
    let token = token_file.and_then(read_token);
    let mut devices =
        SelectDevicesOptions::default().set_devices(DeviceType::Keyboard | DeviceType::Pointer);
    if token_file.is_some() {
        devices = devices
            .set_persist_mode(PersistMode::ExplicitlyRevoked)
            .set_restore_token(token.as_deref());
    }
    step("SelectDevices", remote.select_devices(session, devices))
        .await?
        .response()
        .map_err(|e| {
            unavailable(format!(
                "the screen-sharing portal refused SelectDevices: {e}"
            ))
        })?;
    let sources = SelectSourcesOptions::default()
        .set_sources(BitFlags::from(SourceType::Monitor))
        .set_cursor_mode(CursorMode::Embedded)
        .set_multiple(false);
    step("SelectSources", screencast.select_sources(session, sources))
        .await?
        .response()
        .map_err(|e| {
            unavailable(format!(
                "the screen-sharing portal refused SelectSources: {e}"
            ))
        })?;
    tracing::info!(
        restore = token.is_some(),
        "asking the desktop to share the screen and take input (a dialog unless it was allowed before)"
    );
    let answer = dialog(
        remote.start(session, None, StartOptions::default()),
        setup.dialog_wait,
        setup.cancel.as_ref(),
    )
    .await;
    let started = match answer {
        Dialog::Answered(Ok(answer)) => answer.response(),
        Dialog::Answered(Err(e)) => Err(e),
        Dialog::TimedOut | Dialog::Cancelled => {
            // A token is spent once used, whatever the outcome.
            if let Some(file) = token_file {
                forget_token(file);
            }
            return Err(unavailable(if matches!(answer, Dialog::Cancelled) {
                "the session ended while the screen-sharing dialog was open".to_owned()
            } else {
                format!(
                    "nobody answered the screen-sharing dialog within {} s",
                    setup.dialog_wait.as_secs()
                )
            }));
        }
    };
    let started = match started {
        Ok(started) => started,
        Err(e) => {
            if let Some(file) = token_file {
                forget_token(file);
            }
            return Err(match e {
                ashpd::Error::Response(ResponseError::Cancelled) => {
                    unavailable("screen sharing was declined at the desktop's dialog")
                }
                e => unavailable(format!(
                    "the screen-sharing portal did not start the session: {e}"
                )),
            });
        }
    };
    if !settle_token(token_file, started.restore_token(), setup.cancel.as_ref()) {
        return Err(unavailable(
            "the session ended while the screen-sharing dialog was open",
        ));
    }
    let stream = choose_stream(
        started
            .streams()
            .iter()
            .map(|s| (s.pipe_wire_node_id(), s.size())),
    )?;
    let input = started
        .devices()
        .contains(DeviceType::Keyboard | DeviceType::Pointer);
    let fd = step(
        "OpenPipeWireRemote",
        screencast.open_pipe_wire_remote(session, OpenPipeWireRemoteOptions::default()),
    )
    .await?;
    tracing::info!(
        node = stream.node_id,
        logical = ?stream.logical,
        input,
        remembered = started.restore_token().is_some(),
        "the desktop is shared"
    );
    Ok(Opened {
        node_id: stream.node_id,
        logical: stream.logical,
        input,
        fd,
    })
}

/// How the wait for the desktop's dialog ended.
#[derive(Debug, PartialEq, Eq)]
enum Dialog<T> {
    /// The portal answered.
    Answered(T),
    /// Nobody answered in time.
    TimedOut,
    /// The session this was for ended first.
    Cancelled,
}

/// Wait up to `wait` for the dialog's `answer`, unless `cancel` turns `true`
/// first: then the caller closes the portal session, which takes the dialog
/// down (the slice-D review's addendum, Q3).
async fn dialog<F: Future>(
    answer: F,
    wait: Duration,
    cancel: Option<&watch::Receiver<bool>>,
) -> Dialog<F::Output> {
    tokio::select! {
        biased;
        () = cancelled(cancel) => Dialog::Cancelled,
        answer = tokio::time::timeout(wait, answer) => match answer {
            Ok(answer) => Dialog::Answered(answer),
            Err(_) => Dialog::TimedOut,
        },
    }
}

/// Resolves once `cancel` is `true`; never without one, or once its sender is
/// gone without cancelling.
async fn cancelled(cancel: Option<&watch::Receiver<bool>>) {
    let Some(cancel) = cancel else {
        return std::future::pending().await;
    };
    let mut cancel = cancel.clone();
    if cancel.wait_for(|cancelled| *cancelled).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Keep the token a started session returned, for the next one; `false`, and
/// nothing kept, when the session this was for is already over. The token the
/// start was given is spent either way.
fn settle_token(
    file: Option<&Path>,
    token: Option<&str>,
    cancel: Option<&watch::Receiver<bool>>,
) -> bool {
    let wanted = !cancel.is_some_and(|cancel| *cancel.borrow());
    if let Some(file) = file {
        if wanted {
            remember_token(file, token);
        } else {
            forget_token(file);
        }
    }
    wanted
}

// ---- The restore token -------------------------------------------------------
//
// With it, a later session starts without the dialog until the user revokes
// the permission. It grants the screen and input to whoever presents it, so it
// is kept like a key: a 0600 file in the private state directory, never
// logged, and neither is its path (`tornect doctor` names it to the owner).
// Each token is good for one start, and every start returns the next.

fn valid_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= MAX_TOKEN && token.bytes().all(|b| b.is_ascii_graphic())
}

/// The stored token, if there is a well-formed one.
pub(crate) fn read_token(file: &Path) -> Option<String> {
    use std::io::Read as _;
    let mut text = String::new();
    match std::fs::File::open(file) {
        Ok(f) => {
            if let Err(e) = f.take(MAX_TOKEN as u64 + 2).read_to_string(&mut text) {
                tracing::warn!(error = %e, "the portal restore token is unreadable; the desktop will ask again");
                return None;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(error = %e, "cannot open the portal restore token; the desktop will ask again");
            return None;
        }
    }
    let token = text.trim();
    if valid_token(token) {
        Some(token.to_owned())
    } else {
        tracing::warn!("the portal restore token is malformed; ignored");
        None
    }
}

/// Keep `token` for the next session, or forget the old one when there is none.
pub(crate) fn remember_token(file: &Path, token: Option<&str>) {
    let Some(token) = token.filter(|t| valid_token(t)) else {
        forget_token(file);
        return;
    };
    if let Some(dir) = file.parent()
        && !dir.exists()
        && let Err(e) = tornect_core::keystore::create_private_dir(dir)
    {
        cannot_keep(&e);
        return;
    }
    if let Err(e) = tornect_core::keystore::write_private_file(file, token.as_bytes()) {
        cannot_keep(&e);
    }
}

/// Say that the token could not be kept, with the error's kind and never its
/// text: the keystore's errors come from fs-err, which puts the file's path in
/// the text (slice-G G1-2).
fn cannot_keep(e: &tornect_core::CoreError) {
    match e {
        tornect_core::CoreError::Io(io) => tracing::warn!(
            kind = ?io.kind(),
            "cannot keep the portal restore token; the desktop will ask again"
        ),
        _ => tracing::warn!("cannot keep the portal restore token; the desktop will ask again"),
    }
}

pub(crate) fn forget_token(file: &Path) {
    match std::fs::remove_file(file) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(error = %e, "cannot remove a spent portal restore token")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn a_session_without_a_usable_stream_is_refused() {
        match choose_stream([]) {
            Err(CaptureError::Unavailable(why)) => {
                assert!(why.contains("no PipeWire stream"), "{why}")
            }
            other => panic!("{other:?}"),
        }
        for node in [0, PW_ID_ANY] {
            match choose_stream([(node, Some((1920, 1080)))]) {
                Err(CaptureError::Unavailable(why)) => {
                    assert!(why.contains("names no screen cast"), "{why}")
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(
            choose_stream([(47, Some((1280, 800))), (48, Some((1920, 1080)))]).unwrap(),
            StreamInfo {
                node_id: 47,
                logical: Some((1280, 800))
            }
        );
        // A size that is missing, empty or negative is no size.
        for size in [None, Some((0, 800)), Some((1280, -1))] {
            assert_eq!(
                choose_stream([(47, size)]).unwrap().logical,
                None,
                "{size:?}"
            );
        }
    }

    /// No session bus, no portal: an honest `Unavailable`, quickly, and no
    /// dialog anywhere.
    #[test]
    fn an_unreachable_bus_is_unavailable_not_a_panic() {
        let started = Instant::now();
        let setup = Setup {
            bus: Bus::Address("unix:path=/nonexistent/tornect-test/bus".to_owned()),
            token_file: None,
            dialog_wait: Duration::from_secs(1),
            cancel: None,
        };
        match Portal::open(setup) {
            Err(CaptureError::Unavailable(why)) => assert!(why.contains("D-Bus"), "{why}"),
            Ok(_) => panic!("a bus that does not exist opened a session"),
            Err(e) => panic!("{e}"),
        }
        assert!(started.elapsed() < STEP_WAIT, "{:?}", started.elapsed());
    }

    #[test]
    fn the_restore_token_is_kept_private_and_read_back_only_when_sound() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("state").join("portal-restore-token");
        assert_eq!(read_token(&file), None);
        remember_token(&file, Some("0bf6c3a4-2f3e-4f7e-9d7c-6b1a2e3f4a5b"));
        assert_eq!(
            read_token(&file).as_deref(),
            Some("0bf6c3a4-2f3e-4f7e-9d7c-6b1a2e3f4a5b")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let dir_mode = std::fs::metadata(file.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
        }
        // A start that returned no token forgets the spent one.
        remember_token(&file, None);
        assert!(!file.exists());
        // Nothing malformed is written or read back.
        for bad in ["", "two words", "tab\there", &"x".repeat(MAX_TOKEN + 1)] {
            remember_token(&file, Some(bad));
            assert!(!file.exists(), "{bad:?} was written");
            std::fs::write(&file, bad).unwrap();
            assert_eq!(read_token(&file), None, "{bad:?} was read back");
        }
        // Surrounding whitespace (an editor's newline) is not part of it.
        std::fs::write(&file, "abc-123\n").unwrap();
        assert_eq!(read_token(&file).as_deref(), Some("abc-123"));
        forget_token(&file);
        forget_token(&file);
        assert!(!file.exists());
    }

    /// Addendum Q3: a session that ends while the desktop's dialog is open
    /// ends the wait at once (the caller then closes the portal session, which
    /// takes the dialog down), and a grant answered after that end is not kept:
    /// no restore token is left that no session asked for.
    #[tokio::test(start_paused = true)]
    async fn a_session_that_ends_during_the_dialog_keeps_no_grant() {
        let (end, cancel) = watch::channel(false);
        let started = tokio::time::Instant::now();
        let wait = dialog(
            std::future::pending::<()>(),
            Duration::from_secs(30),
            Some(&cancel),
        );
        let ended = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            end.send_replace(true);
        };
        let (outcome, ()) = tokio::join!(wait, ended);
        assert_eq!(outcome, Dialog::Cancelled);
        assert_eq!(started.elapsed(), Duration::from_secs(1));

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("portal-restore-token");
        std::fs::write(&file, "spent-token").unwrap();
        assert!(!settle_token(Some(&file), Some("new-token"), Some(&cancel)));
        assert!(!file.exists(), "a grant nobody asked for was kept");

        // A session that is still wanted keeps the new token.
        let (_live, wanted) = watch::channel(false);
        assert!(settle_token(Some(&file), Some("new-token"), Some(&wanted)));
        assert_eq!(read_token(&file).as_deref(), Some("new-token"));
        let answered = dialog(async { 7 }, Duration::from_secs(30), Some(&wanted)).await;
        assert_eq!(answered, Dialog::Answered(7));
        let timed_out = dialog(std::future::pending::<()>(), Duration::from_secs(2), None).await;
        assert_eq!(timed_out, Dialog::TimedOut);
    }

    /// Records every event's fields as text.
    struct Recorder(Arc<Mutex<Vec<String>>>);

    struct Text<'a>(&'a mut String);

    impl tracing::field::Visit for Text<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value:?} ", field.name());
        }
    }

    impl tracing::Subscriber for Recorder {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut line = String::new();
            event.record(&mut Text(&mut line));
            self.0.lock().unwrap().push(line);
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// The restore token's file stays out of every log line (the slice-D
    /// review's addendum): a log can travel where the state directory does not,
    /// and the path says where the bearer grant lies. That includes a token
    /// that cannot be written, whose error names the file (slice-G G1-2).
    #[test]
    fn no_log_line_names_the_restore_token_file() {
        let dir = tempfile::tempdir().unwrap();
        let malformed = dir.path().join("portal-restore-token");
        let unreadable = dir.path().join("a-directory");
        std::fs::write(&malformed, "two words").unwrap();
        std::fs::create_dir(&unreadable).unwrap();
        let lines = Arc::new(Mutex::new(Vec::new()));
        tracing::subscriber::with_default(Recorder(Arc::clone(&lines)), || {
            assert_eq!(read_token(&malformed), None);
            assert_eq!(read_token(&unreadable), None);
            forget_token(&unreadable);
            // The file is a directory: it cannot be opened for writing.
            remember_token(&unreadable, Some("a-token"));
            // Its directory would lie under a regular file: it cannot be made.
            remember_token(
                &malformed.join("sub").join("portal-restore-token"),
                Some("a-token"),
            );
        });
        let lines = lines.lock().unwrap();
        assert_eq!(lines.len(), 5, "{lines:?}");
        let root = dir.path().display().to_string();
        for line in lines.iter() {
            assert!(!line.contains(&root), "{line}");
        }
    }

    /// A call queued after the session is over is refused, not lost silently.
    #[test]
    fn input_after_the_session_is_over_is_refused() {
        let (portal, _rx) = Portal::detached(1);
        let key = Call::Key {
            code: 30,
            pressed: true,
        };
        portal.send(key).unwrap();
        // The queue is full (capacity 1): dropped, and said so.
        assert!(
            matches!(portal.send(key), Err(InputError::Inject(m)) if m.contains("not keeping up"))
        );
        portal.over.store(true, Ordering::SeqCst);
        assert!(matches!(portal.send(key), Err(InputError::Inject(m)) if m.contains("over")));
    }
}
