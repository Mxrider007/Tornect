//! Clipboard text over a services stream, both ends (the services design
//! §3.4, §3.5, §4.3, §4.4).
//!
//! **Sending.** A [`ClipSender`] task sends the newest text it is handed: a
//! `ClipStart{seq, len}` with a `seq` above every one before, then the text
//! in `ClipChunk`s, each queued only once the stream's bulk window took its
//! bytes (the clipboard's flight, [`CLIPBOARD`], credited by the receiver
//! with `Credit{0, upto}`). A newer text, or a stop, abandons the one being
//! sent after the chunk going out; texts handed over less than
//! [`CLIP_EVERY`] after the last start wait, and only the newest of them
//! goes (coalescing).
//!
//! **Receiving.** A [`ClipInflow`] takes the peer's texts through
//! `tornect_proto::services::ClipAssembly` (in order, contiguous, within
//! `clip_max`; anything else ends the stream with `Close{PROTOCOL}`), at most
//! [`CLIP_RATE`] a second ([`CLIP_BURST`] at once; more are dropped and
//! counted), and credits every byte of the peer's clipboard frames it read,
//! decoded or skipped (a cap turned off or paused while they were on their
//! way), so that the sender's window never loses room to frames that were
//! not taken. A whole text becomes clipboard text only through
//! `ClipText::from_peer` ([`text_of`]): valid UTF-8, no NUL, control
//! characters removed; anything else is dropped and counted.
//!
//! **The host** ([`HostClip`]) holds the desktop's [`ClipboardLink`]. The
//! link is active, so that the backend reads and sets the clipboard, only
//! while the viewer's switch is on (`ClipSwitch`; off until the viewer says),
//! the host is not locked, and the clipboard was not turned off; `active` is
//! sent on only when that changes (each value sent is a switch, and a `true`
//! takes a fresh baseline: only text copied after it crosses). Text from the
//! desktop is sent only while active and only when its fingerprint differs
//! from the last text sent or applied; text from the viewer is applied only
//! while active.
//!
//! **The viewer** ([`ViewerClipSync`]) takes the text its window read
//! ([`ViewerClip::outbound`]) and gives the window the host's
//! ([`ViewerClip::inbound`]), only while its switch is on; it tells the host
//! its switch at the start and whenever it changes, and again when a pause
//! ends (a `ClipSwitch` sent while the host was locked is skipped there).
//! The window keeps its own baseline: it never hands over the text that was
//! on the clipboard when the stream went live (§4.3).
//!
//! Nothing here logs clipboard text: only counts and lengths.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};
use tornect_input::clipboard::{ClipText, ClipboardLink};
use tornect_proto::services::{
    CLIP_CHUNK_HEAD, ClipAssembly, ClipStart, ClipSwitch, SvcMsg, reason, ty,
};
use zeroize::{Zeroize as _, Zeroizing};

use super::window::{CLIPBOARD, Window};
use super::writer::Outbox;
use crate::flow::TokenBucket;

/// Clipboard texts a receiver takes per second on average; more are dropped
/// and counted.
pub const CLIP_RATE: u32 = 2;

/// Clipboard texts a receiver takes at once.
pub const CLIP_BURST: u32 = 2;

/// The least time a sender leaves between the starts of two texts: texts
/// handed over meanwhile wait, and only the newest goes ("one update per
/// 500 ms each way", design §3.4).
pub const CLIP_EVERY: Duration = Duration::from_millis(500);

// --- Sending ---------------------------------------------------------------

/// The task that sends one end's clipboard texts. Dropping it ends the task
/// once the chunk it is queueing went out: a chunk whose bytes the window
/// took is always queued, so the window never counts bytes that were not
/// sent.
#[derive(Debug)]
pub(crate) struct ClipSender {
    newest: watch::Sender<Option<ClipText>>,
}

impl ClipSender {
    /// Send texts on `outbox` within `window`, in chunks of `chunk` bytes;
    /// each text sent whole is told on `sent` (its length in characters).
    pub(crate) fn spawn(
        window: Arc<Window>,
        outbox: Outbox,
        chunk: usize,
        sent: Option<mpsc::UnboundedSender<usize>>,
    ) -> Self {
        let (newest, rx) = watch::channel(None);
        tokio::spawn(send_clips(rx, window, outbox, chunk.max(1), sent));
        Self { newest }
    }

    /// Send `text`, abandoning the text being sent.
    pub(crate) fn send(&self, text: ClipText) {
        self.newest.send_replace(Some(text));
    }

    /// Abandon the text being sent, and any text waiting.
    pub(crate) fn stop(&self) {
        self.newest
            .send_if_modified(|newest| newest.take().is_some());
        // A text being sent is abandoned at its next chunk.
        self.newest.send_modify(|_| {});
    }
}

/// The sending task: the newest text on `newest`, one at a time, spaced by
/// [`CLIP_EVERY`].
async fn send_clips(
    mut newest: watch::Receiver<Option<ClipText>>,
    window: Arc<Window>,
    outbox: Outbox,
    chunk: usize,
    sent: Option<mpsc::UnboundedSender<usize>>,
) {
    let mut seq = 0u32;
    let mut started: Option<tokio::time::Instant> = None;
    // A change seen while a text was being sent, not yet taken.
    let mut pending = false;
    loop {
        if !pending && newest.changed().await.is_err() {
            return;
        }
        pending = false;
        if let Some(at) = started {
            // Whatever comes meanwhile replaces what waits.
            tokio::time::sleep_until(at + CLIP_EVERY).await;
        }
        let Some(text) = newest.borrow_and_update().clone() else {
            continue;
        };
        let Some(next) = seq.checked_add(1) else {
            return;
        };
        seq = next;
        started = Some(tokio::time::Instant::now());
        let len = u32::try_from(text.byte_len()).unwrap_or(u32::MAX);
        if !outbox.clip(SvcMsg::ClipStart(ClipStart { seq, len })).await {
            return;
        }
        let mut offset = 0u32;
        let mut whole = true;
        for piece in text.as_str().as_bytes().chunks(chunk) {
            match newest.has_changed() {
                Ok(false) => {}
                Ok(true) => {
                    pending = true;
                    whole = false;
                    break;
                }
                Err(_) => return,
            }
            let n = piece.len() as u64;
            tokio::select! {
                biased;
                changed = newest.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    pending = true;
                    whole = false;
                    break;
                }
                taken = window.take(CLIPBOARD, n) => {
                    if !taken {
                        return;
                    }
                }
            }
            // Taken: queued whatever comes, so that the window counts only
            // bytes that went out.
            let msg = SvcMsg::ClipChunk {
                seq,
                offset,
                bytes: Zeroizing::new(piece.to_vec()),
            };
            if !outbox.clip(msg).await {
                return;
            }
            offset += u32::try_from(piece.len()).unwrap_or(u32::MAX);
        }
        if whole && let Some(sent) = &sent {
            let _ = sent.send(text.chars());
        }
    }
}

// --- Receiving -------------------------------------------------------------

/// What a receiver did with a `ClipStart`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Started {
    /// The text is being received.
    Taken,
    /// The text is dropped: the receiver does not take text now.
    NotWanted,
    /// The text is dropped: over the receiver's rate (counted).
    OverRate,
}

/// One end's receiving of the peer's clipboard texts.
#[derive(Debug)]
pub(crate) struct ClipInflow {
    assembly: ClipAssembly,
    gate: TokenBucket,
    clip_max: u32,
    /// Bytes of text in the peer's clipboard frames read, decoded or skipped.
    received: u64,
    /// The bytes accounted for: credited, or written off where no credit can
    /// be read.
    credited: u64,
}

impl ClipInflow {
    /// A receiver of texts of at most `clip_max` bytes, its rate full at
    /// `now`.
    pub(crate) fn new(clip_max: u32, now: Instant) -> Self {
        Self {
            assembly: ClipAssembly::default(),
            gate: TokenBucket::new(CLIP_RATE, CLIP_BURST, now),
            clip_max,
            received: 0,
            credited: 0,
        }
    }

    /// The peer's `ClipStart`: taken when `wanted` and within the rate.
    /// `Err` with the `Close` reason.
    pub(crate) fn start(
        &mut self,
        start: ClipStart,
        wanted: bool,
        now: Instant,
    ) -> Result<Started, u16> {
        let started = if !wanted {
            Started::NotWanted
        } else if self.gate.take(now) {
            Started::Taken
        } else {
            Started::OverRate
        };
        self.assembly
            .start(start, started == Started::Taken, self.clip_max)
            .map_err(|_| reason::PROTOCOL)?;
        Ok(started)
    }

    /// The peer's `ClipChunk`: the text's bytes once it is whole. `Err` with
    /// the `Close` reason.
    pub(crate) fn chunk(
        &mut self,
        seq: u32,
        offset: u32,
        bytes: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, u16> {
        self.received = self.received.saturating_add(bytes.len() as u64);
        self.assembly
            .chunk(seq, offset, bytes)
            .map_err(|_| reason::PROTOCOL)
    }

    /// The reader skipped a clipboard frame of type `t` whose body is `len`
    /// bytes: the text it belonged to is dropped, and a chunk's bytes count
    /// as read.
    pub(crate) fn skipped(&mut self, t: u8, len: usize) {
        if t == ty::CLIP_CHUNK {
            let text = len.saturating_sub(CLIP_CHUNK_HEAD) as u64;
            self.received = self.received.saturating_add(text);
        }
        if matches!(t, ty::CLIP_START | ty::CLIP_CHUNK) {
            self.assembly.ignore_rest();
        }
    }

    /// The receiver stops taking text: the text being received is dropped.
    pub(crate) fn drop_text(&mut self) {
        if self.assembly.receiving() {
            self.assembly.ignore_rest();
        }
    }

    /// Bytes read and not yet accounted for: what the peer has in flight
    /// that this end holds it to.
    pub(crate) fn owed(&self) -> u64 {
        self.received - self.credited
    }

    /// The credit due (`Credit{0, upto}`), now accounted for; `None` when
    /// every byte read was.
    pub(crate) fn credit(&mut self) -> Option<u64> {
        (self.received > self.credited).then(|| {
            self.credited = self.received;
            self.received
        })
    }
}

/// A whole text received as clipboard text: valid UTF-8 through
/// `ClipText::from_peer` (no NUL, control characters but TAB, LF and CR
/// removed, something left); `None` otherwise. The bytes are wiped either
/// way.
pub(crate) fn text_of(mut bytes: Zeroizing<Vec<u8>>) -> Option<ClipText> {
    let raw = std::mem::take(&mut *bytes);
    match String::from_utf8(raw) {
        Ok(text) => ClipText::from_peer(text).ok(),
        Err(e) => {
            e.into_bytes().zeroize();
            None
        }
    }
}

// --- The host --------------------------------------------------------------

/// The host's clipboard on one services stream.
pub(crate) struct HostClip {
    link: Option<ClipboardLink>,
    sender: Option<ClipSender>,
    pub(crate) inflow: ClipInflow,
    /// The viewer's switch: off until its first `ClipSwitch`.
    viewer_on: bool,
    /// A lock pauses the clipboard.
    paused: bool,
    /// What was last sent on the link's `active`.
    active: bool,
    /// The fingerprint of the last text sent or applied.
    last: Option<[u8; 32]>,
}

impl std::fmt::Debug for HostClip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostClip")
            .field("link", &self.link.is_some())
            .field("viewer_on", &self.viewer_on)
            .field("paused", &self.paused)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl HostClip {
    /// The clipboard of a stream granted `link` (`None` without `CLIP`), its
    /// texts sent by `sender`, received through `inflow`.
    pub(crate) fn new(
        link: Option<ClipboardLink>,
        sender: Option<ClipSender>,
        inflow: ClipInflow,
    ) -> Self {
        Self {
            sender: link.as_ref().and(sender),
            link,
            inflow,
            viewer_on: false,
            paused: false,
            active: false,
            last: None,
        }
    }

    /// Whether the backend reads and sets the clipboard now.
    pub(crate) fn active(&self) -> bool {
        self.active
    }

    /// The desktop's newest text, once its backend reports one. Never
    /// resolves without a link, nor once its backend stopped. Cancel-safe.
    pub(crate) async fn desktop(&mut self) -> Option<ClipText> {
        let Some(link) = self.link.as_mut() else {
            return std::future::pending().await;
        };
        if link.from_desktop.changed().await.is_err() {
            return std::future::pending().await;
        }
        link.from_desktop.borrow_and_update().clone()
    }

    /// Text copied on the desktop: sent while active, unless it is the text
    /// sent or applied last.
    pub(crate) fn copied(&mut self, text: Option<ClipText>) {
        let (Some(text), true) = (text, self.active) else {
            return;
        };
        let print = text.fingerprint();
        if self.last == Some(print) {
            return;
        }
        self.last = Some(print);
        if let Some(sender) = &self.sender {
            sender.send(text);
        }
    }

    /// A whole text from the viewer: put on the desktop while active (its
    /// length in characters), dropped otherwise (`None`).
    pub(crate) fn apply(&mut self, text: ClipText) -> Option<usize> {
        let link = self.link.as_ref().filter(|_| self.active)?;
        let chars = text.chars();
        self.last = Some(text.fingerprint());
        link.to_desktop.send_replace(Some(text));
        Some(chars)
    }

    /// The viewer's `ClipSwitch`.
    pub(crate) fn switch(&mut self, on: bool) {
        self.viewer_on = on;
        self.sync();
    }

    /// The host was locked (`true`, §2.3): the link goes inactive, the text
    /// being sent is abandoned and the one arriving dropped. Or unlocked: the
    /// link is active again while the viewer's switch is on, which
    /// re-baselines it (the text copied meanwhile is not sent).
    pub(crate) fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
        self.sync();
    }

    /// The clipboard goes for the rest of the stream: the link is dropped
    /// (its backend stops, and clears the clipboard if it still holds the
    /// text it set), the text being sent is abandoned.
    pub(crate) fn turn_off(&mut self) {
        self.active = false;
        self.link = None;
        if let Some(sender) = self.sender.take() {
            sender.stop();
        }
        self.inflow.drop_text();
    }

    /// Send on `active` when what it should be changed, and only then.
    fn sync(&mut self) {
        let want = self.link.is_some() && self.viewer_on && !self.paused;
        if want == self.active {
            return;
        }
        self.active = want;
        if let Some(link) = &self.link {
            link.active.send_replace(want);
        }
        if !want {
            if let Some(sender) = &self.sender {
                sender.stop();
            }
            self.inflow.drop_text();
        }
    }
}

// --- The viewer ------------------------------------------------------------

/// The viewer window's clipboard as its services stream sees it (design
/// §4.3, the app's `StreamLink::clip`).
pub struct ViewerClip {
    /// Text the window read from this computer's clipboard that may go to
    /// the host (newest wins). The window reads only after it gained the
    /// keyboard focus, never while this computer shares its own screen, and
    /// never hands over the text that was on the clipboard when the stream
    /// went live (its baseline), text over the cap or text a password manager
    /// marked private.
    pub outbound: watch::Receiver<Option<ClipText>>,
    /// Text the host sent, for the window to put on this computer's
    /// clipboard when it has the keyboard focus (newest wins).
    pub inbound: watch::Sender<Option<ClipText>>,
    /// The window's "Clipboard" switch at the start (`[viewer]
    /// clipboard_sync`); [`super::ViewerOp::ClipSwitch`] changes it.
    pub on: bool,
}

impl std::fmt::Debug for ViewerClip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewerClip")
            .field("on", &self.on)
            .finish_non_exhaustive()
    }
}

/// The window's ends of its clipboard: the text it read, the text it is
/// to set.
type WindowEnds = (
    watch::Receiver<Option<ClipText>>,
    watch::Sender<Option<ClipText>>,
);

/// The viewer's clipboard on one services stream.
pub(crate) struct ViewerClipSync {
    ends: Option<WindowEnds>,
    sender: Option<ClipSender>,
    pub(crate) inflow: ClipInflow,
    /// The window's switch.
    on: bool,
    /// The host granted the clipboard and did not turn it off.
    granted: bool,
    /// The host is locked.
    paused: bool,
    /// The switch the host was last told, `None` when it may not have heard
    /// it (at the start, and after a pause).
    told: Option<bool>,
    /// The fingerprint of the last text sent or applied.
    last: Option<[u8; 32]>,
}

impl std::fmt::Debug for ViewerClipSync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewerClipSync")
            .field("ends", &self.ends.is_some())
            .field("on", &self.on)
            .field("granted", &self.granted)
            .field("paused", &self.paused)
            .finish_non_exhaustive()
    }
}

impl ViewerClipSync {
    /// The clipboard of a stream that `granted` it (or not), with the
    /// window's `clip` (`None`: the window shares no clipboard, and the host
    /// is never asked to), its texts sent by `sender` (`None` when there is
    /// nothing to send), received through `inflow`.
    pub(crate) fn new(
        clip: Option<ViewerClip>,
        granted: bool,
        sender: Option<ClipSender>,
        inflow: ClipInflow,
    ) -> Self {
        let (ends, on) = match clip {
            Some(clip) => (Some((clip.outbound, clip.inbound)), clip.on),
            None => (None, false),
        };
        let granted = granted && ends.is_some();
        Self {
            sender: sender.filter(|_| granted),
            ends,
            inflow,
            on,
            granted,
            paused: false,
            told: None,
            last: None,
        }
    }

    /// Whether texts go both ways now.
    fn sharing(&self) -> bool {
        self.granted && self.on && !self.paused
    }

    /// The window's newest text, once it hands one over. Never resolves
    /// without the window's clipboard, nor once the window let it go.
    /// Cancel-safe.
    pub(crate) async fn window(&mut self) -> Option<ClipText> {
        let Some((outbound, _)) = self.ends.as_mut() else {
            return std::future::pending().await;
        };
        if outbound.changed().await.is_err() {
            return std::future::pending().await;
        }
        outbound.borrow_and_update().clone()
    }

    /// Text the window read: sent while sharing, unless it is the text sent
    /// or applied last, or longer than the host takes (`Welcome.clip_max`;
    /// the window says so before it hands such text over).
    pub(crate) fn copied(&mut self, text: Option<ClipText>) {
        let Some(text) = text.filter(|_| self.sharing()) else {
            return;
        };
        if text.byte_len() > self.inflow.clip_max as usize {
            tracing::debug!(
                bytes = text.byte_len(),
                "clipboard text over the host's cap was not sent"
            );
            return;
        }
        let print = text.fingerprint();
        if self.last == Some(print) {
            return;
        }
        self.last = Some(print);
        if let Some(sender) = &self.sender {
            sender.send(text);
        }
    }

    /// Whether a text the host starts is taken.
    pub(crate) fn wants(&self) -> bool {
        self.sharing()
    }

    /// A whole text from the host: given to the window while sharing.
    pub(crate) fn apply(&mut self, text: ClipText) -> bool {
        let Some((_, inbound)) = self.ends.as_ref().filter(|_| self.sharing()) else {
            return false;
        };
        self.last = Some(text.fingerprint());
        inbound.send_replace(Some(text));
        true
    }

    /// The window's switch: the `ClipSwitch` to send, if the host is to hear
    /// it now.
    pub(crate) fn switch(&mut self, on: bool) -> Option<SvcMsg> {
        self.on = on;
        if !on {
            self.quiet();
        }
        self.tell()
    }

    /// The host paused the clipboard (it is locked): nothing goes either
    /// way, and the switch last sent may not have been heard (the host skips
    /// `ClipSwitch` while paused). Or it resumed it: the `ClipSwitch` to
    /// send, so that the host hears the switch as it is now.
    pub(crate) fn set_paused(&mut self, paused: bool) -> Option<SvcMsg> {
        if paused == self.paused {
            return None;
        }
        self.paused = paused;
        if paused {
            self.told = None;
            self.quiet();
            None
        } else {
            self.tell()
        }
    }

    /// The host turned the clipboard off: nothing more goes either way.
    pub(crate) fn turned_off(&mut self) {
        self.granted = false;
        self.quiet();
        if let Some(sender) = self.sender.take() {
            sender.stop();
        }
    }

    /// The `ClipSwitch` to send at the start of the stream, if any.
    pub(crate) fn first(&mut self) -> Option<SvcMsg> {
        self.tell()
    }

    /// Texts stop going: the one being sent is abandoned, the one arriving
    /// dropped.
    fn quiet(&mut self) {
        if let Some(sender) = &self.sender {
            sender.stop();
        }
        self.inflow.drop_text();
    }

    fn tell(&mut self) -> Option<SvcMsg> {
        if !self.granted || self.paused || self.told == Some(self.on) {
            return None;
        }
        self.told = Some(self.on);
        Some(SvcMsg::ClipSwitch(ClipSwitch { on: self.on }))
    }
}

#[cfg(test)]
mod tests {
    use tornect_proto::services::{CHUNK, read_body_max, read_header};

    use super::*;
    use crate::services::writer::spawn_writer;

    fn text(s: &str) -> ClipText {
        ClipText::new(s.to_owned()).unwrap()
    }

    async fn next(rd: &mut tokio::io::DuplexStream) -> SvcMsg {
        let header = tokio::time::timeout(Duration::from_secs(5), read_header(rd))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let body = read_body_max(rd, header, 1 << 16).await.unwrap();
        SvcMsg::decode(header.ty, &body).unwrap()
    }

    /// Received bytes become text only through `ClipText::from_peer`:
    /// control characters go, NUL and invalid UTF-8 are dropped.
    #[test]
    fn received_bytes_become_text_only_through_from_peer() {
        let text = text_of(Zeroizing::new(b"a\x1b[201~b\r\n\tc\x7f".to_vec())).unwrap();
        assert_eq!(text.as_str(), "a[201~b\r\n\tc");
        assert!(text_of(Zeroizing::new(b"a\0b".to_vec())).is_none());
        assert!(text_of(Zeroizing::new(vec![0xff, 0xfe])).is_none());
        assert!(text_of(Zeroizing::new(b"\x1b\x07".to_vec())).is_none());
    }

    /// A text goes out as a start and chunks within the window; a credit of
    /// the clipboard's flight lets the next chunk go; each whole text is
    /// told; the starts are spaced by `CLIP_EVERY` and only the newest of the
    /// texts handed over meanwhile goes.
    #[tokio::test(start_paused = true)]
    async fn texts_go_in_chunks_within_the_window_spaced_and_coalesced() {
        let (mut rd, wr) = tokio::io::duplex(1 << 20);
        let (outbox, _writer) = spawn_writer(wr);
        let window = Arc::new(Window::new(u32::try_from(CHUNK).unwrap()));
        let (sent, mut told) = mpsc::unbounded_channel();
        let sender = ClipSender::spawn(Arc::clone(&window), outbox, CHUNK, Some(sent));
        let long = "x".repeat(CHUNK + 10);
        sender.send(text(&long));
        assert_eq!(
            next(&mut rd).await,
            SvcMsg::ClipStart(ClipStart {
                seq: 1,
                len: u32::try_from(long.len()).unwrap()
            })
        );
        let SvcMsg::ClipChunk {
            seq: 1,
            offset: 0,
            bytes,
        } = next(&mut rd).await
        else {
            panic!("a chunk");
        };
        assert_eq!(bytes.len(), CHUNK);
        // The window is full until the receiver credits.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(told.try_recv().is_err());
        window
            .credit(CLIPBOARD, u64::try_from(CHUNK).unwrap())
            .unwrap();
        assert_eq!(
            next(&mut rd).await,
            SvcMsg::ClipChunk {
                seq: 1,
                offset: u32::try_from(CHUNK).unwrap(),
                bytes: Zeroizing::new(vec![b'x'; 10]),
            }
        );
        assert_eq!(told.recv().await, Some(long.len()));
        window
            .credit(CLIPBOARD, u64::try_from(CHUNK + 10).unwrap())
            .unwrap();

        // Three texts at once, more than `CLIP_EVERY` after the last start:
        // the first goes now, the newest of the other two after the spacing.
        let at = tokio::time::Instant::now();
        sender.send(text("one"));
        tokio::task::yield_now().await;
        sender.send(text("two"));
        sender.send(text("three"));
        let mut got = Vec::new();
        while got.len() < 4 {
            got.push(next(&mut rd).await);
        }
        assert_eq!(got[0], SvcMsg::ClipStart(ClipStart { seq: 2, len: 3 }));
        assert_eq!(got[2], SvcMsg::ClipStart(ClipStart { seq: 3, len: 5 }));
        assert_eq!(
            got[3],
            SvcMsg::ClipChunk {
                seq: 3,
                offset: 0,
                bytes: Zeroizing::new(b"three".to_vec()),
            }
        );
        assert!(at.elapsed() >= CLIP_EVERY);
        assert_eq!(told.recv().await, Some(3));
        assert_eq!(told.recv().await, Some(5));
    }

    /// A stop abandons a text waiting on the window, which is never told as
    /// sent; what the window took was sent.
    #[tokio::test(start_paused = true)]
    async fn a_stop_abandons_a_text_waiting_on_the_window() {
        let (mut rd, wr) = tokio::io::duplex(1 << 20);
        let (outbox, _writer) = spawn_writer(wr);
        let window = Arc::new(Window::new(16));
        let (sent, mut told) = mpsc::unbounded_channel();
        let sender = ClipSender::spawn(Arc::clone(&window), outbox, 16, Some(sent));
        sender.send(text(&"y".repeat(40)));
        assert!(matches!(next(&mut rd).await, SvcMsg::ClipStart(_)));
        assert!(matches!(next(&mut rd).await, SvcMsg::ClipChunk { .. }));
        sender.stop();
        tokio::time::sleep(Duration::from_secs(1)).await;
        window.credit(CLIPBOARD, 16).unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(told.try_recv().is_err());
        assert_eq!(window.in_flight(), 0, "nothing more was taken");
    }

    /// The receiver: in order or `PROTOCOL`, taken only when wanted, over
    /// the rate dropped; every byte read, skipped ones included, is owed
    /// until credited.
    #[test]
    fn the_receiver_counts_and_credits_every_byte_it_read() {
        let now = Instant::now();
        let mut inflow = ClipInflow::new(64, now);
        assert_eq!(
            inflow.start(ClipStart { seq: 1, len: 4 }, true, now),
            Ok(Started::Taken)
        );
        assert_eq!(inflow.chunk(1, 0, b"ab"), Ok(None));
        assert_eq!(inflow.owed(), 2);
        assert_eq!(
            inflow
                .chunk(1, 2, b"cd")
                .unwrap()
                .as_deref()
                .map(Vec::as_slice),
            Some(&b"abcd"[..])
        );
        assert_eq!(inflow.credit(), Some(4));
        assert_eq!(inflow.credit(), None);
        assert_eq!(
            inflow.start(ClipStart { seq: 3, len: 4 }, false, now),
            Ok(Started::NotWanted)
        );
        assert_eq!(inflow.chunk(3, 0, b"zzzz"), Ok(None));
        assert_eq!(
            inflow.start(ClipStart { seq: 4, len: 1 }, true, now),
            Ok(Started::Taken)
        );
        // The burst is spent.
        assert_eq!(
            inflow.start(ClipStart { seq: 5, len: 1 }, true, now),
            Ok(Started::OverRate)
        );
        assert_eq!(inflow.chunk(5, 0, b"q"), Ok(None));
        // Over `clip_max`, taken or not.
        assert_eq!(
            inflow.start(ClipStart { seq: 6, len: 65 }, true, now),
            Err(reason::PROTOCOL)
        );
        // A skipped chunk of 8 + 100 bytes counts its 100.
        inflow.skipped(ty::CLIP_CHUNK, CLIP_CHUNK_HEAD + 100);
        inflow.skipped(ty::CLIP_START, 9);
        assert_eq!(inflow.owed(), 4 + 1 + 100);
        assert_eq!(inflow.credit(), Some(4 + 4 + 1 + 100));
        // After a skip, a chunk of the skipped start is dropped, not refused.
        assert_eq!(inflow.chunk(9, 0, b"r"), Ok(None));
        assert_eq!(
            inflow.chunk(1, 9, b"r"),
            Ok(None),
            "still ignoring until the next start"
        );
        assert_eq!(
            inflow.start(ClipStart { seq: 4, len: 1 }, true, now),
            Err(reason::PROTOCOL),
            "seq only rises"
        );
    }
}
