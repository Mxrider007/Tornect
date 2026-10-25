//! The portal's clipboard on the RemoteDesktop session (design `services`
//! §4.2, `docs/research/services.md` R1): the backend contract of
//! `tornect_input::clipboard` kept over the portal's signals and pipes, so a
//! GNOME Wayland host shares clipboard text under the grant its owner gave at
//! the desktop's dialog. It runs on the portal thread, beside the input calls,
//! only for a session started with `[services] wayland_clipboard` on and
//! `clipboard_enabled` in the `Start` results.
//!
//! - **Reported** on `from_desktop`: text another owner put on the clipboard
//!   after the latest activation, announced more than [`BASELINE_GRACE`] after
//!   `Start` returned (the desktop announces the owner from before the session
//!   shortly after `Start`, R1.2), offering `text/plain;charset=utf-8` or
//!   `text/plain`, and without `x-kde-passwordManagerHint`. Each such owner is
//!   read once. The text on the clipboard at an activation (its baseline, kept
//!   by fingerprint), this session's own text and text reported already never
//!   cross again, whatever owner change brings them back.
//! - **mutter's clipboard manager** takes the selection over when its owner
//!   goes away, offering one of those two types and nothing else, so a
//!   password's hint is lost on the way (R1.5). Such a takeover (one text
//!   type, announced right after "no owner") keeps the verdict of the owner
//!   before it: a private owner's text, this session's own, the baseline and
//!   text of an unknown owner are not read.
//! - **Set** (only while active): the text is offered with the KDE hint, so
//!   clipboard managers that honour it keep no copy, and served to every paste
//!   until another owner comes or the link turns inactive; a paste the backend
//!   does not serve is closed unwritten at once.
//! - **At the end** (the link dropped, or the portal session closing) a
//!   clipboard that still holds our text is cleared: the session becomes the
//!   owner of one Tornect-only type, which mutter's manager does not copy, so
//!   nothing of the text is left once the session goes.
//!
//! Reads go one at a time (mutter refuses parallel reads); a read given up
//! closes its pipe at once. Nothing logged names the text, a type or a path.

use std::collections::VecDeque;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ashpd::desktop::Session;
use ashpd::desktop::clipboard::{Clipboard, SelectionOwnerChanged, SetSelectionOptions};
use ashpd::desktop::remote_desktop::RemoteDesktop;
use ashpd::zbus;
use ashpd::zbus::zvariant::{self, OwnedObjectPath};
use futures::{FutureExt as _, Stream, StreamExt as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::time::Instant;
use tornect_input::clipboard::{CLIP_MAX, ClipText, DesktopEnds};
use zeroize::Zeroizing;

/// Owner changes announced this soon after `Start` returned are never
/// reported: the desktop announces the owner from before the session at
/// clipboard enable, relayed after the `Start` results (R1.2). Gate G2
/// measures that delay on the desktop; raise this to the measured bound plus
/// 1 s if it can be longer.
pub(super) const BASELINE_GRACE: Duration = Duration::from_secs(2);
/// How long reading or writing one selection may take.
const IO_WAIT: Duration = Duration::from_secs(2);
/// How long one clipboard call to the portal may take.
pub(super) const CALL_WAIT: Duration = Duration::from_secs(2);

/// UTF-8 text, the type read first and offered first.
pub(super) const UTF8: &str = "text/plain;charset=utf-8";
/// Text of the locale's charset, read when UTF-8 is not offered (and then
/// refused unless it is valid UTF-8).
pub(super) const PLAIN: &str = "text/plain";
/// The password managers' mark (KeePassXC, KDE); offered with received text.
pub(super) const HINT: &str = "x-kde-passwordManagerHint";
/// What the hint's type holds.
const HINT_VALUE: &[u8] = b"secret";
/// The one type the session owns once it cleared its text: no application
/// pastes it and mutter's clipboard manager does not copy it.
pub(super) const CLEARED: &str = "application/x-tornect-cleared";
/// What received text is offered as.
pub(super) const OFFERED: [&str; 3] = [UTF8, PLAIN, HINT];

/// One clipboard signal of the portal, as the loop needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Signal {
    /// `SelectionOwnerChanged`: an empty `mime_types` with no
    /// `session_is_owner` says the owner went away.
    Owner {
        session: String,
        mime_types: Vec<String>,
        session_is_owner: Option<bool>,
    },
    /// `SelectionTransfer`: someone pastes what this session set.
    Transfer {
        session: String,
        mime_type: String,
        serial: u32,
    },
}

/// A clipboard call the portal refused or that failed. The text is the
/// portal's error, which names no clipboard content.
#[derive(Debug)]
pub(super) struct CallFailed(pub(super) String);

impl std::fmt::Display for CallFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The portal's clipboard calls, for one session.
pub(super) trait ClipCalls {
    /// `SelectionRead`: the read end of a pipe the owner writes `mime_type` into.
    async fn read(&self, mime_type: &str) -> Result<OwnedFd, CallFailed>;
    /// `SetSelection`: this session owns `mime_types` from now on.
    async fn set(&self, mime_types: &[&str]) -> Result<(), CallFailed>;
    /// `SelectionWrite`: the write end of the pipe a paste reads.
    async fn write(&self, serial: u32) -> Result<OwnedFd, CallFailed>;
    /// `SelectionWriteDone`.
    async fn done(&self, serial: u32, ok: bool) -> Result<(), CallFailed>;
}

/// The clipboard calls of a real portal session.
pub(super) struct PortalCalls<'a> {
    pub(super) clipboard: Clipboard,
    pub(super) session: &'a Session<RemoteDesktop>,
}

fn failed(e: ashpd::Error) -> CallFailed {
    CallFailed(e.to_string())
}

impl ClipCalls for PortalCalls<'_> {
    async fn read(&self, mime_type: &str) -> Result<OwnedFd, CallFailed> {
        self.clipboard
            .selection_read(self.session, mime_type)
            .await
            .map(OwnedFd::from)
            .map_err(failed)
    }

    async fn set(&self, mime_types: &[&str]) -> Result<(), CallFailed> {
        self.clipboard
            .set_selection(
                self.session,
                SetSelectionOptions::default().set_mime_types(mime_types),
            )
            .await
            .map_err(failed)
    }

    async fn write(&self, serial: u32) -> Result<OwnedFd, CallFailed> {
        self.clipboard
            .selection_write(self.session, serial)
            .await
            .map(OwnedFd::from)
            .map_err(failed)
    }

    async fn done(&self, serial: u32, ok: bool) -> Result<(), CallFailed> {
        self.clipboard
            .selection_write_done(self.session, serial, ok)
            .await
            .map_err(failed)
    }
}

/// The clipboard signals, in the order the portal sent them.
pub(super) type Signals = Pin<Box<dyn Stream<Item = Signal>>>;

/// Subscribes to the clipboard's signals on the `Clipboard` proxy itself:
/// ashpd's own streams build a session proxy for every signal (a round trip
/// each) and hide its path, which the loop compares (R1.3). One stream for
/// both signals keeps their order. Subscribed before `Start`, so the
/// announcement of the owner from before the session is not missed.
pub(super) async fn subscribe(clipboard: &Clipboard) -> zbus::Result<Signals> {
    let all = clipboard.receive_all_signals().await?;
    Ok(Box::pin(all.filter_map(|message| {
        std::future::ready(signal_of(&message))
    })))
}

/// The clipboard signal a message carries, if it is one the loop knows.
fn signal_of(message: &zbus::Message) -> Option<Signal> {
    let header = message.header();
    match header.member()?.as_str() {
        "SelectionOwnerChanged" => {
            let (session, changed) = message
                .body()
                .deserialize::<(OwnedObjectPath, SelectionOwnerChanged)>()
                .ok()?;
            Some(Signal::Owner {
                session: session.as_str().to_owned(),
                mime_types: changed.mime_types().to_vec(),
                session_is_owner: changed.session_is_owner(),
            })
        }
        "SelectionTransfer" => {
            let (session, mime_type, serial) = message
                .body()
                .deserialize::<(OwnedObjectPath, String, u32)>()
                .ok()?;
            Some(Signal::Transfer {
                session: session.as_str().to_owned(),
                mime_type,
                serial,
            })
        }
        _ => None,
    }
}

/// The object path of `session`, as its signals name it. ashpd keeps the
/// path private; a session serialises as its path.
pub(super) fn session_path(session: &Session<RemoteDesktop>) -> Option<String> {
    let context = zvariant::serialized::Context::new_dbus(zvariant::LE, 0);
    let data = zvariant::to_bytes(context, session).ok()?;
    let (path, _) = data.deserialize::<OwnedObjectPath>().ok()?;
    Some(path.as_str().to_owned())
}

/// What the loop knows of the clipboard's owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    /// Nothing announced yet.
    Unknown,
    /// The owner went away. A takeover by mutter's clipboard manager inherits
    /// what that owner was.
    Gone(Verdict),
    /// This session's own selection.
    Ours,
    /// Another owner.
    Other {
        /// The text type to read, if it offers one.
        mime: Option<&'static str>,
        verdict: Verdict,
    },
}

/// What may be done with an owner's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Verdict {
    /// It may be read on this computer at all (for the baseline, or to
    /// report): it offers text, is not marked private, and is not the takeover
    /// of an owner whose text may not be read.
    readable: bool,
    /// It may cross: readable, announced while active, after the grace, and
    /// not the takeover of an owner whose text may not cross.
    reportable: bool,
}

impl Verdict {
    const CLOSED: Self = Self {
        readable: false,
        reportable: false,
    };
}

impl Owner {
    /// What a takeover of this owner inherits.
    fn verdict(self) -> Verdict {
        match self {
            // Nothing known of it: neither read nor sent.
            Self::Unknown => Verdict::CLOSED,
            Self::Gone(verdict) | Self::Other { verdict, .. } => verdict,
            // Our own text: harmless to read, never sent back.
            Self::Ours => Verdict {
                readable: true,
                reportable: false,
            },
        }
    }
}

/// Why a read gave no text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unread {
    Call,
    NotAPipe,
    TooLarge,
    TimedOut,
    Io,
    NotUtf8,
    Unfit,
}

/// The loop of one portal session's clipboard.
pub(super) struct Clip<C, S> {
    calls: C,
    signals: S,
    /// Signals taken off the stream early (while checking for a newer owner
    /// change after a read), handled before the stream's next.
    pending: VecDeque<Signal>,
    signals_ended: bool,
    ends: DesktopEnds,
    /// This session's object path: other sessions' signals are ignored.
    path: String,
    /// When `Start` returned.
    started: Instant,
    /// The delay of the first owner announcement after `Start` (gate G2).
    announced: Arc<OnceLock<Duration>>,
    active: bool,
    owner: Owner,
    /// Fingerprint of the text on the clipboard at the latest activation.
    base: Option<[u8; 32]>,
    /// Fingerprint of the text this session set last.
    own: Option<[u8; 32]>,
    /// Fingerprint of the text reported last.
    reported: Option<[u8; 32]>,
    /// The text this session serves to pastes, while active and the owner.
    held: Option<ClipText>,
    /// This session's selection is the clipboard's, as far as known: set by a
    /// set that succeeded and by an announcement of our own, cleared by
    /// another owner.
    ours: bool,
    finished: bool,
}

impl<C: ClipCalls, S: Stream<Item = Signal> + Unpin> Clip<C, S> {
    pub(super) fn new(
        calls: C,
        signals: S,
        ends: DesktopEnds,
        path: String,
        started: Instant,
        announced: Arc<OnceLock<Duration>>,
    ) -> Self {
        Self {
            calls,
            signals,
            pending: VecDeque::new(),
            signals_ended: false,
            ends,
            path,
            started,
            announced,
            active: false,
            owner: Owner::Unknown,
            base: None,
            own: None,
            reported: None,
            held: None,
            ours: false,
            finished: false,
        }
    }

    /// Serve the link until it is dropped, then clear what is still ours.
    /// Cancel-safe: dropped at any await, it leaves the state for
    /// [`Clip::finish`], and every text it held is wiped.
    pub(super) async fn run(&mut self) {
        loop {
            tokio::select! {
                biased;
                // `active` before the text, so that text sent around a switch
                // is seen with the switch and dropped.
                changed = self.ends.active.changed() => match changed {
                    Ok(()) => self.switch().await,
                    Err(_) => break,
                },
                changed = self.ends.to_desktop.changed() => match changed {
                    Ok(()) => self.take_text().await,
                    Err(_) => break,
                },
                () = self.ends.from_desktop.closed() => break,
                signal = next_signal(&mut self.pending, &mut self.signals, self.signals_ended) => {
                    match signal {
                        Some(signal) => self.on_signal(signal).await,
                        None => self.signals_ended = true,
                    }
                }
            }
        }
        self.finish().await;
    }

    /// At the end: clear the clipboard if it still holds our text. Runs once.
    pub(super) async fn finish(&mut self) {
        if std::mem::replace(&mut self.finished, true) {
            return;
        }
        // Owner changes already here count: a copy made after ours is not
        // cleared.
        self.collect_ready();
        while let Some(signal) = self.pending.pop_front() {
            if let Signal::Owner {
                session,
                mime_types,
                session_is_owner,
            } = signal
                && session == self.path
            {
                self.ours = owner_kind(&mime_types, session_is_owner) == Kind::Ours;
            }
        }
        self.held = None;
        if !self.ours {
            return;
        }
        match tokio::time::timeout(CALL_WAIT, self.calls.set(&[CLEARED])).await {
            Ok(Ok(())) => tracing::debug!("clipboard: our text cleared at the end"),
            Ok(Err(e)) => tracing::debug!(error = %e, "clipboard: our text not cleared"),
            Err(_) => tracing::debug!("clipboard: clearing our text timed out"),
        }
    }

    /// A value was sent on `active`. Every value counts: `true` takes a fresh
    /// baseline even over an earlier `true`, and text sent with the switch is
    /// dropped (it may have been sent before it).
    async fn switch(&mut self) {
        let on = *self.ends.active.borrow_and_update();
        if self.ends.to_desktop.has_changed().unwrap_or(false) {
            drop(self.ends.to_desktop.borrow_and_update());
        }
        if on {
            self.activate().await;
        } else {
            self.active = false;
            self.base = None;
            self.held = None;
        }
    }

    async fn activate(&mut self) {
        self.active = true;
        self.base = None;
        self.reported = None;
        // The owner announced so far is the activation's baseline: never
        // reported, and its text (read here if it may be) never crosses while
        // this activation lasts.
        if let Owner::Other { mime, verdict } = &mut self.owner {
            verdict.reportable = false;
            if let (Some(mime), true) = (*mime, verdict.readable) {
                self.base = self.read(mime).await.ok().map(|t| t.fingerprint());
            }
        }
    }

    async fn take_text(&mut self) {
        let text = self.ends.to_desktop.borrow_and_update().clone();
        let Some(text) = text else { return };
        if !self.active {
            return;
        }
        let fingerprint = text.fingerprint();
        let bytes = text.byte_len();
        self.held = Some(text);
        match tokio::time::timeout(CALL_WAIT, self.calls.set(&OFFERED)).await {
            Ok(Ok(())) => {
                self.own = Some(fingerprint);
                self.ours = true;
                // What is copied next replaces this text, even if it was
                // reported before.
                self.reported = None;
                tracing::debug!(bytes, "clipboard: received text set");
            }
            Ok(Err(e)) => {
                self.held = None;
                tracing::debug!(error = %e, "clipboard: received text not set");
            }
            Err(_) => {
                self.held = None;
                tracing::debug!("clipboard: setting received text timed out");
            }
        }
    }

    async fn on_signal(&mut self, signal: Signal) {
        match signal {
            Signal::Owner {
                session,
                mime_types,
                session_is_owner,
            } if session == self.path => self.owner_changed(&mime_types, session_is_owner).await,
            Signal::Transfer {
                session,
                mime_type,
                serial,
            } if session == self.path => self.serve(&mime_type, serial).await,
            // Another session's.
            _ => {}
        }
    }

    async fn owner_changed(&mut self, mime_types: &[String], session_is_owner: Option<bool>) {
        let now = Instant::now();
        let _ = self
            .announced
            .set(now.saturating_duration_since(self.started));
        let settled = now >= self.started + BASELINE_GRACE;
        let previous = self.owner;
        self.owner = match owner_kind(mime_types, session_is_owner) {
            Kind::Ours => Owner::Ours,
            Kind::Gone => Owner::Gone(match previous {
                // A second "no owner" keeps what the last owner was.
                Owner::Gone(verdict) => verdict,
                other => other.verdict(),
            }),
            Kind::Other => {
                let takeover = matches!(previous, Owner::Gone(_)) && is_takeover(mime_types);
                let inherited = if takeover {
                    previous.verdict()
                } else {
                    Verdict {
                        readable: true,
                        reportable: true,
                    }
                };
                let mime = text_type(mime_types);
                let readable = inherited.readable && mime.is_some() && !offers(mime_types, HINT);
                Owner::Other {
                    mime,
                    verdict: Verdict {
                        readable,
                        reportable: readable && inherited.reportable && self.active && settled,
                    },
                }
            }
        };
        if self.owner != Owner::Ours {
            // Another owner (or none): our text is no longer what a paste gets.
            self.ours = false;
            self.held = None;
        } else {
            self.ours = true;
        }
        let Owner::Other {
            mime: Some(mime),
            verdict,
        } = self.owner
        else {
            return;
        };
        if !self.active || !verdict.readable {
            if self.active && offers(mime_types, HINT) {
                tracing::debug!("clipboard: copied text is marked private; not shared");
            }
            return;
        }
        if !settled {
            // Announced within the grace, while active: the owner from before
            // the session, announced late. It is the baseline.
            if let Ok(text) = self.read(mime).await {
                self.base = Some(text.fingerprint());
            }
            return;
        }
        if verdict.reportable {
            self.report(mime).await;
        }
    }

    /// Read the owner's text and report it, unless it is ours, the baseline,
    /// reported already, or a newer owner change came meanwhile.
    async fn report(&mut self, mime: &str) {
        let text = match self.read(mime).await {
            Ok(text) => text,
            Err(why) => {
                tracing::debug!(?why, "clipboard: copied text not shared");
                return;
            }
        };
        // The read is of whoever owns the clipboard now: a newer owner change
        // already here may have been for that one, so this text is dropped
        // and the newer change is judged on its own (R1.4).
        if self.collect_ready() {
            tracing::debug!("clipboard: the clipboard changed while it was read; read again");
            return;
        }
        let fingerprint = text.fingerprint();
        if self.own == Some(fingerprint) {
            return;
        }
        self.own = None;
        if self.base == Some(fingerprint) || self.reported == Some(fingerprint) {
            return;
        }
        self.reported = Some(fingerprint);
        tracing::debug!(bytes = text.byte_len(), "clipboard: copied text reported");
        self.ends.from_desktop.send_replace(Some(text));
    }

    /// Take the signals that are already here off the stream, without
    /// waiting; `true` if one is an owner change of this session.
    fn collect_ready(&mut self) -> bool {
        while !self.signals_ended {
            match self.signals.next().now_or_never() {
                Some(Some(signal)) => self.pending.push_back(signal),
                Some(None) => self.signals_ended = true,
                None => break,
            }
        }
        self.pending
            .iter()
            .any(|s| matches!(s, Signal::Owner { session, .. } if *session == self.path))
    }

    /// One read of the current owner's `mime` text, bounded in time and size.
    async fn read(&self, mime: &str) -> Result<ClipText, Unread> {
        let fd = match tokio::time::timeout(CALL_WAIT, self.calls.read(mime)).await {
            Ok(Ok(fd)) => fd,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "clipboard: the portal did not read the clipboard");
                return Err(Unread::Call);
            }
            Err(_) => return Err(Unread::Call),
        };
        let bytes = read_capped(fd).await?;
        let text = String::from_utf8(bytes.to_vec()).map_err(|e| {
            drop(Zeroizing::new(e.into_bytes()));
            Unread::NotUtf8
        })?;
        ClipText::new(text).map_err(|_| Unread::Unfit)
    }

    /// Answer a paste of what this session set: the text while it is active
    /// and holds some, the hint's value, or nothing (closed at once).
    async fn serve(&self, mime_type: &str, serial: u32) {
        let payload: Option<&[u8]> = match (&self.held, mime_type) {
            (Some(text), UTF8 | PLAIN) if self.active => Some(text.as_str().as_bytes()),
            (Some(_), HINT) if self.active => Some(HINT_VALUE),
            _ => None,
        };
        let ok = match tokio::time::timeout(CALL_WAIT, self.calls.write(serial)).await {
            Ok(Ok(fd)) => match payload {
                Some(bytes) => write_all(fd, bytes).await,
                // Closed unwritten: the paste gets nothing now, rather than
                // after the desktop's 15 s cleanup (R1.4).
                None => false,
            },
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "clipboard: the portal did not take a paste");
                false
            }
            Err(_) => false,
        };
        if payload.is_some() {
            tracing::debug!(ok, "clipboard: a paste of received text served");
        }
        if let Ok(Err(e)) = tokio::time::timeout(CALL_WAIT, self.calls.done(serial, ok)).await {
            tracing::debug!(error = %e, "clipboard: the portal refused the end of a paste");
        }
    }
}

/// Serve `clip` until its link is dropped, then nothing: it never returns,
/// so the portal thread's other work decides when the session ends.
pub(super) async fn serve<C: ClipCalls, S: Stream<Item = Signal> + Unpin>(
    clip: Option<&mut Clip<C, S>>,
) -> std::convert::Infallible {
    if let Some(clip) = clip {
        clip.run().await;
    }
    std::future::pending().await
}

/// The next signal: one taken off early, else the stream's (never, once it
/// ended).
async fn next_signal<S: Stream<Item = Signal> + Unpin>(
    pending: &mut VecDeque<Signal>,
    signals: &mut S,
    ended: bool,
) -> Option<Signal> {
    if let Some(signal) = pending.pop_front() {
        return Some(signal);
    }
    if ended {
        return std::future::pending().await;
    }
    signals.next().await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ours,
    Gone,
    Other,
}

fn owner_kind(mime_types: &[String], session_is_owner: Option<bool>) -> Kind {
    match (session_is_owner, mime_types.is_empty()) {
        (Some(true), _) => Kind::Ours,
        (None, true) => Kind::Gone,
        _ => Kind::Other,
    }
}

fn offers(mime_types: &[String], mime: &str) -> bool {
    mime_types.iter().any(|m| m == mime)
}

/// The text type to read: UTF-8 first.
fn text_type(mime_types: &[String]) -> Option<&'static str> {
    [UTF8, PLAIN].into_iter().find(|t| offers(mime_types, t))
}

/// Whether an owner announced right after "no owner" is mutter's clipboard
/// manager taking the selection over: it offers one of the two text types it
/// keeps, and nothing else (R1.5).
fn is_takeover(mime_types: &[String]) -> bool {
    matches!(mime_types, [only] if only == UTF8 || only == PLAIN)
}

/// Read a pipe to its end within [`IO_WAIT`], at most [`CLIP_MAX`] bytes, into
/// a buffer that is never reallocated and is wiped when dropped.
async fn read_capped(fd: OwnedFd) -> Result<Zeroizing<Vec<u8>>, Unread> {
    let mut pipe =
        tokio::net::unix::pipe::Receiver::from_owned_fd(fd).map_err(|_| Unread::NotAPipe)?;
    let mut buf = Zeroizing::new(vec![0u8; CLIP_MAX + 1]);
    let filled = tokio::time::timeout(IO_WAIT, async {
        let mut filled = 0;
        while filled < buf.len() {
            match pipe.read(&mut buf[filled..]).await {
                Ok(0) => return Ok(filled),
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Unread::Io),
            }
        }
        Err(Unread::TooLarge)
    })
    .await
    .map_err(|_| Unread::TimedOut)??;
    buf.truncate(filled);
    Ok(buf)
}

/// Write `bytes` into a paste's pipe within [`IO_WAIT`] and close it.
async fn write_all(fd: OwnedFd, bytes: &[u8]) -> bool {
    let Ok(mut pipe) = tokio::net::unix::pipe::Sender::from_owned_fd(fd) else {
        return false;
    };
    matches!(
        tokio::time::timeout(IO_WAIT, pipe.write_all(bytes)).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::sync::Mutex;

    use futures::channel::mpsc;
    use tornect_input::clipboard::ClipboardLink;

    use super::*;

    /// What a pipe holds before its writer blocks (Linux's default, 16 pages).
    const PIPE_BUFFER: usize = 65_536;

    const OURS: &str = "/org/freedesktop/portal/desktop/session/1_42/tornect";
    const THEIRS: &str = "/org/freedesktop/portal/desktop/session/1_43/other";

    /// What the next read of the fake clipboard answers.
    #[derive(Clone)]
    enum Answer {
        Bytes(Vec<u8>),
        /// The owner never writes nor closes.
        Hang,
        /// The portal refuses the read.
        Refuse,
    }

    #[derive(Default)]
    struct Desk {
        /// What a read answers, by type; a type not here is refused.
        answers: Vec<(String, Answer)>,
        calls: Vec<String>,
        /// What each paste read, by serial.
        pasted: Vec<(u32, Vec<u8>)>,
        /// Writers of hanging reads, kept open.
        hanging: Vec<std::io::PipeWriter>,
        /// Owner changes to put on the stream while a read runs (the race).
        during_read: Vec<Signal>,
    }

    #[derive(Clone, Default)]
    struct Fake {
        desk: Arc<Mutex<Desk>>,
        signals: Arc<Mutex<Option<mpsc::UnboundedSender<Signal>>>>,
    }

    impl Fake {
        fn desk(&self) -> std::sync::MutexGuard<'_, Desk> {
            self.desk.lock().unwrap()
        }

        fn answer(&self, mime: &str, answer: Answer) {
            let mut desk = self.desk();
            desk.answers.retain(|(m, _)| m != mime);
            desk.answers.push((mime.to_owned(), answer));
        }

        fn calls(&self) -> Vec<String> {
            self.desk().calls.clone()
        }

        fn reads(&self) -> usize {
            self.calls()
                .iter()
                .filter(|c| c.starts_with("read"))
                .count()
        }
    }

    impl ClipCalls for Fake {
        async fn read(&self, mime_type: &str) -> Result<OwnedFd, CallFailed> {
            let mut desk = self.desk();
            desk.calls.push(format!("read {mime_type}"));
            let during = std::mem::take(&mut desk.during_read);
            if let Some(tx) = &*self.signals.lock().unwrap() {
                for signal in during {
                    tx.unbounded_send(signal).unwrap();
                }
            }
            let answer = desk
                .answers
                .iter()
                .find(|(m, _)| m == mime_type)
                .map(|(_, a)| a.clone());
            let (reader, mut writer) = std::io::pipe().unwrap();
            match answer {
                // Written whole before the read starts, so the paused clock
                // cannot run out while a writer thread is still on its way.
                Some(Answer::Bytes(bytes)) if bytes.len() <= PIPE_BUFFER => {
                    writer.write_all(&bytes).unwrap();
                }
                // Larger than the pipe's buffer: written apart.
                Some(Answer::Bytes(bytes)) => {
                    std::thread::spawn(move || {
                        let _ = writer.write_all(&bytes);
                    });
                }
                Some(Answer::Hang) => desk.hanging.push(writer),
                Some(Answer::Refuse) | None => {
                    return Err(CallFailed("No selection owner available".to_owned()));
                }
            }
            Ok(OwnedFd::from(reader))
        }

        async fn set(&self, mime_types: &[&str]) -> Result<(), CallFailed> {
            self.desk()
                .calls
                .push(format!("set {}", mime_types.join(",")));
            Ok(())
        }

        async fn write(&self, serial: u32) -> Result<OwnedFd, CallFailed> {
            self.desk().calls.push(format!("write {serial}"));
            let (mut reader, writer) = std::io::pipe().unwrap();
            let desk = Arc::clone(&self.desk);
            std::thread::spawn(move || {
                let mut got = Vec::new();
                let _ = reader.read_to_end(&mut got);
                desk.lock().unwrap().pasted.push((serial, got));
            });
            Ok(OwnedFd::from(writer))
        }

        async fn done(&self, serial: u32, ok: bool) -> Result<(), CallFailed> {
            self.desk().calls.push(format!("done {serial} {ok}"));
            Ok(())
        }
    }

    struct Rig {
        fake: Fake,
        tx: mpsc::UnboundedSender<Signal>,
        link: ClipboardLink,
        clip: Clip<Fake, mpsc::UnboundedReceiver<Signal>>,
    }

    /// A loop whose session started now.
    fn rig() -> Rig {
        rig_started(Instant::now())
    }

    fn rig_started(started: Instant) -> Rig {
        let fake = Fake::default();
        let (tx, rx) = mpsc::unbounded();
        *fake.signals.lock().unwrap() = Some(tx.clone());
        let (link, ends) = ClipboardLink::pair();
        let clip = Clip::new(
            fake.clone(),
            rx,
            ends,
            OURS.to_owned(),
            started,
            Arc::new(OnceLock::new()),
        );
        Rig {
            fake,
            tx,
            link,
            clip,
        }
    }

    fn owner(session: &str, mime_types: &[&str]) -> Signal {
        Signal::Owner {
            session: session.to_owned(),
            mime_types: mime_types.iter().map(|m| (*m).to_owned()).collect(),
            session_is_owner: (!mime_types.is_empty()).then_some(false),
        }
    }

    fn ours() -> Signal {
        Signal::Owner {
            session: OURS.to_owned(),
            mime_types: OFFERED.iter().map(|m| (*m).to_owned()).collect(),
            session_is_owner: Some(true),
        }
    }

    fn gone() -> Signal {
        Signal::Owner {
            session: OURS.to_owned(),
            mime_types: Vec::new(),
            session_is_owner: None,
        }
    }

    fn transfer(session: &str, mime: &str, serial: u32) -> Signal {
        Signal::Transfer {
            session: session.to_owned(),
            mime_type: mime.to_owned(),
            serial,
        }
    }

    /// A GTK copy's types.
    const GTK: [&str; 5] = [UTF8, "UTF8_STRING", "TEXT", "STRING", PLAIN];

    impl Rig {
        /// Run the loop until it has handled everything sent so far.
        async fn settle(&mut self) {
            let _ = tokio::time::timeout(Duration::from_millis(50), self.clip.run()).await;
        }

        async fn send(&mut self, signal: Signal) {
            self.tx.unbounded_send(signal).unwrap();
            self.settle().await;
        }

        /// Someone copies `text` (a GTK application).
        async fn copy(&mut self, text: &str) {
            self.fake
                .answer(UTF8, Answer::Bytes(text.as_bytes().to_vec()));
            self.send(owner(OURS, &GTK)).await;
        }

        async fn activate(&mut self) {
            self.link.active.send_replace(true);
            self.settle().await;
        }

        async fn past_grace(&mut self) {
            tokio::time::sleep(BASELINE_GRACE).await;
        }

        /// The text reported since the last call.
        fn reported(&mut self) -> Option<String> {
            if !self.link.from_desktop.has_changed().unwrap() {
                return None;
            }
            self.link
                .from_desktop
                .borrow_and_update()
                .as_ref()
                .map(|t| t.as_str().to_owned())
        }
    }

    /// The report path: text copied while active and after the grace is read
    /// once (UTF-8) and reported once; the same text again is not reported.
    #[tokio::test(start_paused = true)]
    async fn a_copy_after_the_activation_and_the_grace_crosses_once() {
        let mut rig = rig();
        rig.past_grace().await;
        rig.activate().await;
        rig.copy("hello there").await;
        assert_eq!(rig.reported().as_deref(), Some("hello there"));
        assert_eq!(rig.fake.calls(), [format!("read {UTF8}")]);
        // The same text from another owner: read, not reported again.
        rig.copy("hello there").await;
        assert_eq!(rig.reported(), None);
        rig.copy("next").await;
        assert_eq!(rig.reported().as_deref(), Some("next"));
        // An owner offering only `text/plain` is read as that.
        rig.fake.answer(PLAIN, Answer::Bytes(b"plain".to_vec()));
        rig.send(owner(OURS, &["STRING", PLAIN])).await;
        assert_eq!(rig.reported().as_deref(), Some("plain"));
        assert_eq!(rig.fake.calls().last().unwrap(), &format!("read {PLAIN}"));
        // No text type: nothing is read.
        let before = rig.fake.reads();
        rig.send(owner(OURS, &["image/png"])).await;
        assert_eq!(rig.fake.reads(), before);
        assert_eq!(rig.reported(), None);
    }

    /// Another session's signals are not ours: no read, no paste served.
    #[tokio::test(start_paused = true)]
    async fn another_sessions_signals_are_ignored() {
        let mut rig = rig();
        rig.past_grace().await;
        rig.activate().await;
        rig.fake.answer(UTF8, Answer::Bytes(b"theirs".to_vec()));
        rig.send(owner(THEIRS, &GTK)).await;
        rig.send(transfer(THEIRS, UTF8, 9)).await;
        assert!(rig.fake.calls().is_empty(), "{:?}", rig.fake.calls());
        assert_eq!(rig.reported(), None);
    }

    /// Our own selection announced, and the password hint, are never read.
    #[tokio::test(start_paused = true)]
    async fn our_own_selection_and_private_text_are_not_read() {
        let mut rig = rig();
        rig.past_grace().await;
        rig.activate().await;
        rig.fake.answer(UTF8, Answer::Bytes(b"x".to_vec()));
        rig.send(ours()).await;
        // KeePassXC's copy.
        rig.send(owner(OURS, &[UTF8, PLAIN, HINT])).await;
        assert_eq!(rig.fake.reads(), 0);
        assert_eq!(rig.reported(), None);
    }

    /// The baseline race (design §4.2): the owner from before the session,
    /// announced after the activation but within the grace, is not reported;
    /// it is read for the baseline only, so its text never crosses later,
    /// even when an owner change brings it back.
    #[tokio::test(start_paused = true)]
    async fn a_late_announcement_within_the_grace_is_the_baseline() {
        let mut rig = rig();
        rig.activate().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        rig.copy("password from before").await;
        assert_eq!(rig.reported(), None);
        assert_eq!(rig.fake.reads(), 1, "read for the baseline only");
        rig.past_grace().await;
        // A clipboard manager re-owning the same text (many types, so not a
        // takeover by mutter): read, and not reported.
        rig.copy("password from before").await;
        assert_eq!(rig.reported(), None);
        rig.copy("new").await;
        assert_eq!(rig.reported().as_deref(), Some("new"));
    }

    /// Owner changes before the activation, or within the grace while
    /// inactive, are never read for a report; the owner at the activation is
    /// read for its baseline and never crosses during that activation.
    #[tokio::test(start_paused = true)]
    async fn the_owner_at_the_activation_never_crosses() {
        let mut rig = rig();
        rig.copy("before the session").await;
        rig.past_grace().await;
        rig.copy("copied while off").await;
        assert_eq!(rig.fake.reads(), 0, "inactive: nothing is read");
        rig.activate().await;
        assert_eq!(rig.fake.reads(), 1, "the baseline");
        assert_eq!(rig.reported(), None);
        // The same text brought back by another owner: not reported.
        rig.copy("copied while off").await;
        assert_eq!(rig.reported(), None);
        // A fresh activation over the first takes a fresh baseline: the text
        // on the clipboard then is the new baseline.
        rig.copy("third").await;
        assert_eq!(rig.reported().as_deref(), Some("third"));
        rig.activate().await;
        rig.copy("third").await;
        assert_eq!(
            rig.reported(),
            None,
            "the baseline of the second activation"
        );
    }

    /// Inactive means no reads, and text sent while off is not set.
    #[tokio::test(start_paused = true)]
    async fn inactive_reads_and_sets_nothing() {
        let mut rig = rig();
        rig.past_grace().await;
        rig.activate().await;
        rig.link.active.send_replace(false);
        rig.settle().await;
        rig.copy("while paused").await;
        rig.link
            .to_desktop
            .send_replace(Some(ClipText::new("from them".to_owned()).unwrap()));
        rig.settle().await;
        assert!(rig.fake.calls().is_empty(), "{:?}", rig.fake.calls());
        assert_eq!(rig.reported(), None);
    }

    /// Received text is set with the hint and served to pastes (the text
    /// types and the hint's value); our own announcement is not read back;
    /// once another owner comes, or the link turns inactive, a paste gets
    /// nothing, closed at once and answered `false`.
    #[tokio::test(start_paused = true)]
    async fn received_text_is_set_and_served_until_another_owner_comes() {
        let mut rig = rig();
        rig.past_grace().await;
        rig.activate().await;
        rig.link
            .to_desktop
            .send_replace(Some(ClipText::new("from them".to_owned()).unwrap()));
        rig.settle().await;
        assert_eq!(rig.fake.calls(), [format!("set {UTF8},{PLAIN},{HINT}")]);
        rig.send(ours()).await;
        rig.send(transfer(OURS, UTF8, 1)).await;
        rig.send(transfer(OURS, HINT, 2)).await;
        rig.send(transfer(OURS, "image/png", 3)).await;
        let pasted = wait_pasted(&rig.fake, 3).await;
        assert_eq!(
            pasted,
            [
                (1, b"from them".to_vec()),
                (2, b"secret".to_vec()),
                (3, Vec::new())
            ]
        );
        let calls = rig.fake.calls();
        assert!(calls.contains(&"done 1 true".to_owned()), "{calls:?}");
        assert!(calls.contains(&"done 2 true".to_owned()), "{calls:?}");
        assert!(calls.contains(&"done 3 false".to_owned()), "{calls:?}");
        assert_eq!(rig.fake.reads(), 0, "our own text is not read back");
        // Another owner: our text is no longer served.
        rig.copy("theirs now").await;
        rig.send(transfer(OURS, UTF8, 4)).await;
        assert_eq!(wait_pasted(&rig.fake, 4).await[3], (4, Vec::new()));
        assert!(rig.fake.calls().contains(&"done 4 false".to_owned()));
        // Set again, then switched off: the held text is dropped.
        rig.link
            .to_desktop
            .send_replace(Some(ClipText::new("again".to_owned()).unwrap()));
        rig.settle().await;
        rig.send(ours()).await;
        rig.link.active.send_replace(false);
        rig.settle().await;
        rig.send(transfer(OURS, UTF8, 5)).await;
        assert_eq!(wait_pasted(&rig.fake, 5).await[4], (5, Vec::new()));
        assert!(rig.fake.calls().contains(&"done 5 false".to_owned()));
    }

    async fn wait_pasted(fake: &Fake, n: usize) -> Vec<(u32, Vec<u8>)> {
        for _ in 0..500 {
            let mut pasted = fake.desk().pasted.clone();
            if pasted.len() >= n {
                pasted.sort_by_key(|(serial, _)| *serial);
                return pasted;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("{n} pastes not read: {:?}", fake.desk().pasted);
    }

    /// Our own text read back (an echo through another owner, such as a
    /// clipboard manager re-owning it) is not reported.
    #[tokio::test(start_paused = true)]
    async fn our_own_text_read_back_is_not_reported() {
        let mut rig = rig();
        rig.past_grace().await;
        rig.activate().await;
        rig.link
            .to_desktop
            .send_replace(Some(ClipText::new("echo me".to_owned()).unwrap()));
        rig.settle().await;
        rig.send(ours()).await;
        rig.copy("echo me").await;
        assert_eq!(rig.reported(), None);
        assert_eq!(rig.fake.reads(), 1);
    }

    /// mutter's clipboard manager takes over when an owner quits, offering
    /// only one text type and losing the password hint (R1.5): the takeover
    /// keeps the verdict of the owner before it.
    #[tokio::test(start_paused = true)]
    async fn a_takeover_keeps_the_verdict_of_the_owner_before() {
        let mut rig = rig();
        rig.past_grace().await;
        rig.activate().await;
        rig.fake
            .answer(UTF8, Answer::Bytes(b"the password".to_vec()));
        // KeePassXC's copy, then KeePassXC quits and mutter takes over.
        rig.send(owner(OURS, &[UTF8, PLAIN, HINT])).await;
        rig.send(gone()).await;
        rig.send(owner(OURS, &[UTF8])).await;
        assert_eq!(
            rig.fake.reads(),
            0,
            "the takeover of a private copy is not read"
        );
        // Our own text taken over: not read either.
        rig.send(ours()).await;
        rig.send(gone()).await;
        rig.send(owner(OURS, &[UTF8])).await;
        assert_eq!(rig.fake.reads(), 0);
        // An owner from before the activation, taken over: not read.
        let mut rig2 = rig_with_owner_before().await;
        rig2.send(gone()).await;
        let reads = rig2.fake.reads();
        rig2.send(owner(OURS, &[PLAIN])).await;
        assert_eq!(rig2.fake.reads(), reads);
        assert_eq!(rig2.reported(), None);
        // An open copy taken over: read, and not reported twice.
        rig.copy("open text").await;
        assert_eq!(rig.reported().as_deref(), Some("open text"));
        rig.send(gone()).await;
        rig.send(owner(OURS, &[UTF8])).await;
        assert_eq!(rig.reported(), None);
        // A single-type owner that does not follow "no owner" is an ordinary
        // copy.
        rig.fake.answer(UTF8, Answer::Bytes(b"single".to_vec()));
        rig.send(owner(OURS, &[UTF8])).await;
        assert_eq!(rig.reported().as_deref(), Some("single"));
    }

    async fn rig_with_owner_before() -> Rig {
        let mut rig = rig();
        rig.copy("from before").await;
        rig.past_grace().await;
        rig.activate().await;
        rig
    }

    /// A read over the cap, one that never ends, one refused, non-UTF-8 and
    /// text with a NUL give nothing; the loop goes on.
    #[tokio::test(start_paused = true)]
    async fn unfit_reads_are_dropped() {
        let mut rig = rig();
        rig.past_grace().await;
        rig.activate().await;
        for answer in [
            Answer::Bytes(vec![b'x'; CLIP_MAX + 1]),
            Answer::Hang,
            Answer::Refuse,
            Answer::Bytes(vec![0xff, 0xfe, b'a']),
            Answer::Bytes(b"a\0b".to_vec()),
            Answer::Bytes(Vec::new()),
        ] {
            rig.fake.answer(UTF8, answer);
            rig.tx.unbounded_send(owner(OURS, &GTK)).unwrap();
            let _ = tokio::time::timeout(IO_WAIT * 2, rig.clip.run()).await;
            assert_eq!(rig.reported(), None);
        }
        assert_eq!(rig.fake.reads(), 6);
    }

    /// Text of exactly the cap crosses; one byte more does not (on the real
    /// clock: the writer of a text larger than a pipe's buffer is a thread).
    #[tokio::test]
    async fn text_of_exactly_the_cap_crosses() {
        let mut rig = rig_started(Instant::now() - BASELINE_GRACE * 2);
        rig.activate().await;
        rig.fake.answer(UTF8, Answer::Bytes(vec![b'y'; CLIP_MAX]));
        rig.tx.unbounded_send(owner(OURS, &GTK)).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while !rig.link.from_desktop.has_changed().unwrap() {
                let _ = tokio::time::timeout(Duration::from_millis(20), rig.clip.run()).await;
            }
        })
        .await;
        assert_eq!(rig.reported().map(|t| t.len()), Some(CLIP_MAX));

        let pipe = |bytes: Vec<u8>| {
            let (reader, mut writer) = std::io::pipe().unwrap();
            std::thread::spawn(move || {
                let _ = writer.write_all(&bytes);
            });
            OwnedFd::from(reader)
        };
        assert_eq!(
            read_capped(pipe(vec![b'z'; CLIP_MAX]))
                .await
                .map(|b| b.len()),
            Ok(CLIP_MAX)
        );
        assert_eq!(
            read_capped(pipe(vec![b'z'; CLIP_MAX + 1]))
                .await
                .map(|b| b.len()),
            Err(Unread::TooLarge)
        );
        // Not a pipe: refused before any read.
        let file = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(
            read_capped(OwnedFd::from(file)).await.map(|b| b.len()),
            Err(Unread::NotAPipe)
        );
    }

    /// A newer owner change already here when a read returns may have been
    /// the owner the read reached: the read is dropped and the newer change
    /// judged on its own (here KeePassXC's, which is not read).
    #[tokio::test(start_paused = true)]
    async fn a_read_raced_by_a_newer_owner_change_is_dropped() {
        let mut rig = rig();
        rig.past_grace().await;
        rig.activate().await;
        rig.fake
            .answer(UTF8, Answer::Bytes(b"the password".to_vec()));
        rig.fake.desk().during_read = vec![owner(OURS, &[UTF8, PLAIN, HINT])];
        rig.send(owner(OURS, &GTK)).await;
        assert_eq!(rig.reported(), None);
        assert_eq!(rig.fake.reads(), 1);
        // Another session's change during a read does not count.
        rig.fake.answer(UTF8, Answer::Bytes(b"fine".to_vec()));
        rig.fake.desk().during_read = vec![owner(THEIRS, &GTK)];
        rig.send(owner(OURS, &GTK)).await;
        assert_eq!(rig.reported().as_deref(), Some("fine"));
    }

    /// Every value on `active` is a switch, and text sent with a switch is
    /// dropped (it may have been sent before it).
    #[tokio::test(start_paused = true)]
    async fn text_sent_with_a_switch_is_dropped() {
        let mut rig = rig();
        rig.past_grace().await;
        rig.link
            .to_desktop
            .send_replace(Some(ClipText::new("too early".to_owned()).unwrap()));
        rig.link.active.send_replace(true);
        rig.settle().await;
        assert!(rig.fake.calls().is_empty(), "{:?}", rig.fake.calls());
        rig.copy("on the clipboard").await;
        assert_eq!(rig.reported().as_deref(), Some("on the clipboard"));
        // Off and on again before the loop looks: one fresh activation, whose
        // baseline is the text on the clipboard then.
        rig.link.active.send_replace(false);
        rig.link.active.send_replace(true);
        rig.settle().await;
        assert_eq!(rig.fake.reads(), 2, "the new baseline");
        rig.copy("on the clipboard").await;
        assert_eq!(rig.reported(), None);
    }

    /// The link dropped while the clipboard holds our text: it is cleared
    /// (the Tornect-only type), once; not when someone copied after us.
    #[tokio::test(start_paused = true)]
    async fn the_end_clears_only_our_own_text() {
        let mut rig = rig();
        rig.past_grace().await;
        rig.activate().await;
        rig.link
            .to_desktop
            .send_replace(Some(ClipText::new("ours".to_owned()).unwrap()));
        rig.settle().await;
        rig.send(ours()).await;
        let Rig {
            fake,
            link,
            mut clip,
            ..
        } = rig;
        drop(link);
        clip.run().await;
        clip.finish().await;
        let calls = fake.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|c| **c == format!("set {CLEARED}"))
                .count(),
            1,
            "{calls:?}"
        );

        // Someone copied after us, announced before the end: left alone.
        let mut rig = self::rig();
        rig.past_grace().await;
        rig.activate().await;
        rig.link
            .to_desktop
            .send_replace(Some(ClipText::new("ours".to_owned()).unwrap()));
        rig.settle().await;
        rig.tx.unbounded_send(owner(OURS, &GTK)).unwrap();
        rig.clip.finish().await;
        assert!(
            !rig.fake.calls().contains(&format!("set {CLEARED}")),
            "{:?}",
            rig.fake.calls()
        );
    }

    /// The delay of the first announcement after `Start` is kept (gate G2).
    #[tokio::test(start_paused = true)]
    async fn the_first_announcement_delay_is_kept() {
        let mut rig = rig();
        // `send` runs the loop for 50 ms of the paused clock.
        rig.send(owner(THEIRS, &GTK)).await;
        assert_eq!(rig.clip.announced.get(), None, "another session's");
        tokio::time::sleep(Duration::from_millis(70)).await;
        rig.send(owner(OURS, &GTK)).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        rig.send(gone()).await;
        assert_eq!(rig.clip.announced.get(), Some(&Duration::from_millis(120)));
    }

    /// End to end over D-Bus, through ashpd and zbus as a session uses them
    /// (the fake portal): the signals are read off the bus and matched to the
    /// session by its path, the owner from before the session is the
    /// baseline, a copy after the grace crosses, received text is set with
    /// the hint and served to a paste through the portal's pipe, and it is
    /// cleared before the session closes.
    #[test]
    #[ignore = "starts a dbus-daemon: cargo test -p tornect-capture -- --ignored fake_bus"]
    fn fake_bus_the_clipboard_end_to_end() {
        use super::super::fake_bus::{FakeBus, Script};
        use super::super::portal::{Bus, Portal, Setup};

        let bus = FakeBus::start(Script::default());
        bus.select("copied before the session");
        let (portal, opened) = Portal::open(Setup {
            bus: Bus::Address(bus.address.clone()),
            token_file: None,
            dialog_wait: Duration::from_secs(5),
            cancel: None,
            spare_remote: false,
            clipboard: true,
        })
        .unwrap();
        assert!(opened.clipboard);
        let session = bus.session();
        let reads = |bus: &FakeBus| {
            bus.calls()
                .iter()
                .filter(|c| c.starts_with("Clipboard.SelectionRead"))
                .count()
        };
        // The owner from before the session, announced after `Start` (R1.2).
        bus.owner_changed(&session, &GTK, false);
        let mut link = portal.take_clip_link().unwrap();
        link.active.send_replace(true);
        bus.wait_for("the baseline read", |bus| reads(bus) == 1);
        // Another session's owner: not this session's clipboard.
        bus.owner_changed(
            "/org/freedesktop/portal/desktop/session/1_99/other",
            &GTK,
            false,
        );
        std::thread::sleep(BASELINE_GRACE);
        bus.select("copied on the host");
        bus.owner_changed(&session, &GTK, false);
        bus.wait_for("the copy to cross", |_| {
            link.from_desktop.has_changed().unwrap()
        });
        assert_eq!(
            link.from_desktop
                .borrow_and_update()
                .as_ref()
                .map(ClipText::as_str),
            Some("copied on the host")
        );
        assert_eq!(reads(&bus), 2, "{:?}", bus.calls());
        assert!(
            portal
                .announced_after_start()
                .is_some_and(|after| after < BASELINE_GRACE),
            "{:?}",
            portal.announced_after_start()
        );

        link.to_desktop
            .send_replace(Some(ClipText::new("from the viewer".to_owned()).unwrap()));
        let set = format!("Clipboard.SetSelection {UTF8},{PLAIN},{HINT}");
        bus.wait_for("the set", |bus| bus.calls().contains(&set));
        bus.owner_changed(&session, &OFFERED, true);
        bus.transfer(&session, UTF8, 7);
        bus.wait_for("the paste", |bus| {
            bus.pasted(7).is_some()
                && bus
                    .calls()
                    .contains(&"Clipboard.SelectionWriteDone 7 true".to_owned())
        });
        assert_eq!(bus.pasted(7).unwrap(), b"from the viewer");
        assert_eq!(reads(&bus), 2, "our own text is not read back");

        drop(opened);
        drop(portal);
        let calls = bus.calls();
        assert_eq!(
            calls[calls.len() - 2..],
            [
                format!("Clipboard.SetSelection {CLEARED}"),
                "Session.Close".to_owned()
            ],
            "{calls:?}"
        );
        drop(link);
    }

    #[test]
    fn owner_kinds_and_takeovers() {
        let types = |t: &[&str]| t.iter().map(|m| (*m).to_owned()).collect::<Vec<_>>();
        assert_eq!(owner_kind(&types(&GTK), Some(true)), Kind::Ours);
        assert_eq!(owner_kind(&[], None), Kind::Gone);
        assert_eq!(owner_kind(&types(&GTK), Some(false)), Kind::Other);
        assert_eq!(owner_kind(&types(&GTK), None), Kind::Other);
        assert!(is_takeover(&types(&[UTF8])));
        assert!(is_takeover(&types(&[PLAIN])));
        assert!(!is_takeover(&types(&["image/png"])));
        assert!(!is_takeover(&types(&[UTF8, PLAIN])));
        assert_eq!(text_type(&types(&[PLAIN, UTF8])), Some(UTF8));
        assert_eq!(text_type(&types(&["STRING"])), None);
    }
}
