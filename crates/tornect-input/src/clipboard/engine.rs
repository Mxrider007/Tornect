//! The thread of the arboard backends (design §4.2): the backend
//! [contract](super) kept over a [`Desktop`], so that the activation baseline,
//! the echo guards and the end-of-session clear are tested against a fake
//! desktop. The OS halves are `windows.rs` and `x11.rs`.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::{ClipText, ClipboardError, DesktopEnds};

/// How often the thread looks at its link (and, at most this often, at its
/// desktop).
pub(crate) const TICK: Duration = Duration::from_millis(100);

/// One look at the clipboard's text. Not `Debug`: it holds the text, which
/// is wiped wherever the look is dropped.
pub(crate) enum Read {
    /// Text that is not marked private.
    Text(Zeroizing<String>),
    /// A password manager marked it private.
    Private,
    /// Whether it is private could not be checked: not shared either.
    Unchecked,
    /// Over the cap, found before or while reading it (Windows sizes the
    /// text block first; X11 reads at most the cap and one unit more).
    TooLarge,
    /// No text (empty, an image, no owner) or the read failed.
    Nothing,
    /// The clipboard changed while it was checked and read. The desktop
    /// reports a change at its next [`Desktop::changed`], so it is read again.
    Raced,
}

/// What a desktop found on the clipboard at an activation.
pub(crate) enum Baseline {
    /// Text, by its [`fingerprint`](super::fingerprint): never reported while
    /// this activation lasts, whatever owner change brings it back.
    Text([u8; 32]),
    /// Nothing that could be reported: no text, or text that is private,
    /// cannot be checked or is over the cap (and was therefore not read).
    Nothing,
    /// The clipboard could not be looked at now (Windows: another program
    /// held it open). The activation waits and is tried again at the next
    /// tick; until then nothing is read or set.
    #[cfg_attr(all(not(windows), not(test)), allow(dead_code))]
    Busy,
}

/// What the thread asks of an OS clipboard.
pub(crate) trait Desktop {
    /// The baseline of an activation: forget every change seen so far, and
    /// say what text the clipboard holds now. Reports nothing; the text read
    /// for it stays on this computer. An error ends the backend.
    fn baseline(&mut self) -> Result<Baseline, ClipboardError>;
    /// Whether the clipboard changed since the last call or the baseline.
    /// Reads no content. An error ends the backend.
    fn changed(&mut self) -> Result<bool, ClipboardError>;
    /// Whether the clipboard as last seen by [`Desktop::changed`] is the one
    /// this backend's last set left (Windows' sequence number); `false` where
    /// that is not known (X11, whose own sets are private by their hint).
    fn is_own(&self) -> bool;
    /// The clipboard's text unless it is marked private, cannot be checked,
    /// is over the cap or changed while being read.
    fn read(&mut self) -> Read;
    /// Put `text` on the clipboard, kept out of clipboard histories.
    fn write(&mut self, text: &ClipText) -> Result<(), ClipboardError>;
    /// At the end: clear the clipboard if it still holds the text this
    /// backend set last (`own`, its fingerprint), and only then.
    fn release(&mut self, own: Option<&[u8; 32]>);
}

/// The backend contract over one desktop and one link's far ends.
pub(crate) struct Engine<D> {
    desktop: D,
    ends: DesktopEnds,
    /// Activated, with a baseline taken: only then is anything read or set.
    active: bool,
    /// Fingerprint of the text on the clipboard at the latest activation.
    /// Unlike `reported` it outlives our own sets: the text from before the
    /// activation never crosses, even when an owner change brings it back.
    base: Option<[u8; 32]>,
    /// Fingerprint of the text this backend set last.
    own: Option<[u8; 32]>,
    /// Fingerprint of the text reported last: one change read twice (an
    /// event and a retry) is reported once.
    reported: Option<[u8; 32]>,
    poll_every: Duration,
    next_poll: Option<Instant>,
}

impl<D: Desktop> Engine<D> {
    pub(crate) fn new(desktop: D, ends: DesktopEnds, poll_every: Duration) -> Self {
        Self {
            desktop,
            ends,
            active: false,
            base: None,
            own: None,
            reported: None,
            poll_every,
            next_poll: None,
        }
    }

    /// Turn every [`TICK`] until the link is dropped or the desktop fails,
    /// then clear what is still ours.
    #[cfg(any(windows, target_os = "linux"))]
    pub(crate) fn run(mut self) {
        while self.turn(Instant::now()) {
            std::thread::sleep(TICK);
        }
        self.finish();
    }

    /// Clear the clipboard if it still holds the text set last.
    pub(crate) fn finish(mut self) {
        self.desktop.release(self.own.as_ref());
    }

    /// One tick at `now`: `false` once the link is gone or the desktop
    /// failed.
    pub(crate) fn turn(&mut self, now: Instant) -> bool {
        if self.ends.from_desktop.is_closed() {
            return false;
        }
        // `switched`: a value was sent on `active` since the last tick. Every
        // value counts, so an off and on again within one tick is seen.
        let (Ok(switched), Ok(text_changed)) = (
            self.ends.active.has_changed(),
            self.ends.to_desktop.has_changed(),
        ) else {
            return false;
        };
        let on = *self.ends.active.borrow_and_update();
        if !on {
            self.active = false;
            self.base = None;
        } else if switched || !self.active {
            // An activation, also over an earlier one (a fresh baseline for
            // each), or one the busy clipboard held back at an earlier tick.
            self.active = false;
            match self.desktop.baseline() {
                Err(e) => {
                    tracing::debug!(error = %e, "clipboard: no baseline; the backend stops");
                    return false;
                }
                Ok(Baseline::Busy) => {
                    if switched {
                        tracing::debug!("clipboard: busy at activation; tried again every tick");
                    }
                }
                Ok(found) => {
                    self.base = match found {
                        Baseline::Text(fingerprint) => Some(fingerprint),
                        Baseline::Nothing | Baseline::Busy => None,
                    };
                    self.active = true;
                    self.reported = None;
                    self.next_poll = None;
                }
            }
        }

        if text_changed {
            let text = self.ends.to_desktop.borrow_and_update().clone();
            // Text sent while off, or in a tick that also switched `active`
            // (it may have been sent before the switch), is dropped, not held
            // for later.
            if let (true, false, Some(text)) = (self.active, switched, text) {
                self.apply(&text);
            }
        }

        if self.next_poll.is_some_and(|at| now < at) {
            return true;
        }
        self.next_poll = Some(now + self.poll_every);
        match self.desktop.changed() {
            Err(e) => {
                tracing::debug!(error = %e, "clipboard: the desktop failed; the backend stops");
                false
            }
            // While off the change detector is only kept current (X11's
            // events drained); nothing is read.
            Ok(true) if self.active => {
                self.look();
                true
            }
            Ok(_) => true,
        }
    }

    fn apply(&mut self, text: &ClipText) {
        match self.desktop.write(text) {
            Ok(()) => {
                self.own = Some(text.fingerprint());
                // What is copied next replaced this text, even if it was
                // reported before.
                self.reported = None;
                tracing::debug!(bytes = text.byte_len(), "clipboard: received text set");
            }
            Err(e) => tracing::debug!(error = %e, "clipboard: received text not set"),
        }
    }

    fn look(&mut self) {
        if self.desktop.is_own() {
            return;
        }
        let raw = match self.desktop.read() {
            Read::Text(mut raw) => std::mem::take(&mut *raw),
            Read::Private => {
                tracing::debug!("clipboard: copied text is marked private; not shared");
                return;
            }
            Read::Unchecked => {
                tracing::debug!("clipboard: copied text could not be checked; not shared");
                return;
            }
            Read::TooLarge => {
                tracing::debug!("clipboard: copied text is over the cap; not shared");
                return;
            }
            Read::Nothing | Read::Raced => return,
        };
        let text = match ClipText::new(raw) {
            Ok(text) => text,
            Err(e) => {
                tracing::debug!(reason = %e, "clipboard: copied text not shared");
                return;
            }
        };
        let fingerprint = text.fingerprint();
        // Our own set read back (the second echo guard).
        if self.own == Some(fingerprint) {
            return;
        }
        // Someone else's text replaced ours.
        self.own = None;
        // The text from before the activation brought back (a clipboard
        // manager taking over from an owner that quit, a delayed rendering),
        // or one change seen twice.
        if self.base == Some(fingerprint) || self.reported == Some(fingerprint) {
            return;
        }
        self.reported = Some(fingerprint);
        tracing::debug!(bytes = text.byte_len(), "clipboard: copied text reported");
        self.ends.from_desktop.send_replace(Some(text));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, MutexGuard};

    use super::*;
    use crate::clipboard::{CLIP_MAX, ClipboardLink, fingerprint};

    /// A clipboard whose version plays Windows' sequence number.
    #[derive(Default)]
    struct State {
        text: Option<String>,
        private: bool,
        version: u64,
        seen: u64,
        own_version: Option<u64>,
        /// Windows-like: the desktop knows its own set by its version.
        knows_own: bool,
        /// X11-like: the backend's own sets carry the private hint.
        hint_own: bool,
        /// Store CRLF as LF, as a Linux toolkit hands text back.
        lf_only: bool,
        race_once: bool,
        /// What the next reads answer instead of the text.
        refuse: Option<fn() -> Read>,
        fail: bool,
        /// How many baselines in a row find the clipboard busy.
        busy: u32,
        reads: u32,
        writes: Vec<String>,
        baselines: u32,
        released: Option<bool>,
    }

    impl State {
        /// Someone on this computer copies `text`.
        fn copy(&mut self, text: &str, private: bool) {
            self.text = Some(text.to_owned());
            self.private = private;
            self.version += 1;
        }

        /// The clipboard changes but its text does not: a delayed rendering
        /// done (Windows), or a clipboard manager taking the text over from
        /// an owner that quit (X11).
        fn bump(&mut self) {
            self.version += 1;
        }
    }

    struct Fake(Arc<Mutex<State>>);

    impl Fake {
        fn state(&self) -> MutexGuard<'_, State> {
            self.0.lock().unwrap()
        }
    }

    impl Desktop for Fake {
        fn baseline(&mut self) -> Result<Baseline, ClipboardError> {
            let mut s = self.state();
            s.baselines += 1;
            s.seen = s.version;
            if s.busy > 0 {
                s.busy -= 1;
                return Ok(Baseline::Busy);
            }
            // Private text is not read, as the real desktops do.
            Ok(match (&s.text, s.private) {
                (Some(text), false) => Baseline::Text(fingerprint(text)),
                _ => Baseline::Nothing,
            })
        }

        fn changed(&mut self) -> Result<bool, ClipboardError> {
            let mut s = self.state();
            if s.fail {
                return Err(ClipboardError::Unavailable("the display went away"));
            }
            let changed = s.version != s.seen;
            s.seen = s.version;
            Ok(changed)
        }

        fn is_own(&self) -> bool {
            let s = self.state();
            s.knows_own && s.own_version == Some(s.seen)
        }

        fn read(&mut self) -> Read {
            let mut s = self.state();
            s.reads += 1;
            if s.race_once {
                s.race_once = false;
                s.version += 1;
                return Read::Raced;
            }
            if s.private {
                return Read::Private;
            }
            if let Some(refuse) = s.refuse {
                return refuse();
            }
            match &s.text {
                Some(text) => Read::Text(Zeroizing::new(text.clone())),
                None => Read::Nothing,
            }
        }

        fn write(&mut self, text: &ClipText) -> Result<(), ClipboardError> {
            let mut s = self.state();
            let stored = if s.lf_only {
                text.as_str().replace("\r\n", "\n")
            } else {
                text.as_str().to_owned()
            };
            s.writes.push(text.as_str().to_owned());
            s.text = Some(stored);
            s.private = s.hint_own;
            s.version += 1;
            s.own_version = Some(s.version);
            Ok(())
        }

        fn release(&mut self, own: Option<&[u8; 32]>) {
            let mut s = self.state();
            let ours = if s.knows_own {
                s.own_version == Some(s.version)
            } else {
                own.is_some_and(|own| s.text.as_deref().map(fingerprint) == Some(*own))
            };
            if ours {
                s.text = None;
                s.version += 1;
            }
            s.released = Some(ours);
        }
    }

    struct Rig {
        engine: Engine<Fake>,
        link: ClipboardLink,
        state: Arc<Mutex<State>>,
        now: Instant,
    }

    impl Rig {
        fn new(knows_own: bool, hint_own: bool) -> Self {
            Self::with_poll(knows_own, hint_own, Duration::ZERO)
        }

        fn with_poll(knows_own: bool, hint_own: bool, poll_every: Duration) -> Self {
            let state = Arc::new(Mutex::new(State {
                knows_own,
                hint_own,
                ..State::default()
            }));
            let (link, ends) = ClipboardLink::pair();
            Self {
                engine: Engine::new(Fake(Arc::clone(&state)), ends, poll_every),
                link,
                state,
                now: Instant::now(),
            }
        }

        fn s(&self) -> MutexGuard<'_, State> {
            self.state.lock().unwrap()
        }

        fn turn(&mut self) -> bool {
            self.now += TICK;
            self.engine.turn(self.now)
        }

        fn turns(&mut self, n: usize) {
            for _ in 0..n {
                assert!(self.turn());
            }
        }

        fn activate(&mut self, on: bool) {
            self.link.active.send_replace(on);
        }

        fn send(&mut self, text: &str) {
            let text = ClipText::new(text.to_owned()).unwrap();
            self.link.to_desktop.send_replace(Some(text));
        }

        /// What the backend reported since the last call.
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

    /// The three ways a backend knows its own set: the sequence number
    /// (Windows), the private hint (X11), the fingerprint alone.
    const KINDS: [(bool, bool); 3] = [(true, false), (false, true), (false, false)];

    #[test]
    fn nothing_is_read_or_set_while_inactive() {
        for (knows_own, hint_own) in KINDS {
            let mut rig = Rig::new(knows_own, hint_own);
            rig.s().copy("copied while off", false);
            rig.send("sent while off");
            rig.turns(5);
            assert_eq!(rig.s().reads, 0);
            assert!(rig.s().writes.is_empty());
            assert_eq!(rig.reported(), None);
            // Turned on, neither the earlier copy nor the earlier text moves:
            // the copy is behind the baseline, the text was dropped.
            rig.activate(true);
            rig.turns(3);
            assert_eq!(rig.s().reads, 0);
            assert!(rig.s().writes.is_empty());
            assert_eq!(rig.reported(), None);
            // Text sent and the link turned off before the next turn: dropped.
            rig.send("sent then off");
            rig.activate(false);
            rig.turns(2);
            assert!(rig.s().writes.is_empty());
        }
    }

    #[test]
    fn only_text_copied_after_activation_crosses() {
        let mut rig = Rig::new(true, false);
        rig.s().copy("a password from before", false);
        rig.activate(true);
        rig.turns(3);
        assert_eq!(rig.reported(), None);
        assert_eq!(rig.s().baselines, 1);
        rig.s().copy("copied during the session", false);
        rig.turn();
        assert_eq!(rig.reported().as_deref(), Some("copied during the session"));
    }

    #[test]
    fn every_activation_takes_a_fresh_baseline() {
        let mut rig = Rig::new(true, false);
        rig.activate(true);
        rig.turn();
        rig.s().copy("one", false);
        rig.turn();
        assert_eq!(rig.reported().as_deref(), Some("one"));
        rig.activate(false);
        rig.turn();
        rig.s().copy("two, while paused", false);
        rig.turns(2);
        rig.activate(true);
        rig.turns(2);
        assert_eq!(rig.reported(), None);
        assert_eq!(rig.s().baselines, 2);
        rig.s().copy("three", false);
        rig.turn();
        assert_eq!(rig.reported().as_deref(), Some("three"));
        // Text reported before a pause may be reported again after it, once
        // the clipboard held something else at the re-activation.
        rig.activate(false);
        rig.turn();
        rig.s().copy("four, while paused", false);
        rig.turn();
        rig.activate(true);
        rig.turn();
        rig.s().copy("three", false);
        rig.turn();
        assert_eq!(rig.reported().as_deref(), Some("three"));
        // Still the clipboard's text at a re-activation, it is that
        // activation's baseline: copying it again does not cross.
        rig.activate(false);
        rig.turn();
        rig.activate(true);
        rig.turn();
        rig.s().copy("three", false);
        rig.turn();
        assert_eq!(rig.reported(), None);
        assert_eq!(rig.s().baselines, 4);
    }

    #[test]
    fn the_text_from_before_the_activation_never_crosses() {
        for (knows_own, hint_own) in KINDS {
            let mut rig = Rig::new(knows_own, hint_own);
            rig.s().copy("a password from before", false);
            rig.activate(true);
            rig.turn();
            // An owner change that keeps the text (a delayed rendering, a
            // clipboard manager taking over): read, compared, not reported.
            rig.s().bump();
            rig.turn();
            assert_eq!(rig.s().reads, 1);
            assert_eq!(rig.reported(), None, "kinds {knows_own} {hint_own}");
            // Copied again during the session: still the baseline's text.
            rig.s().copy("a password from before", false);
            rig.turn();
            assert_eq!(rig.reported(), None);
            // Our own set in between does not lift it.
            rig.send("from the viewer");
            rig.turn();
            rig.s().copy("a password from before", false);
            rig.turn();
            assert_eq!(rig.reported(), None);
            // A real copy crosses; the baseline's text after it still does
            // not.
            rig.s().copy("copied during the session", false);
            rig.turn();
            assert_eq!(rig.reported().as_deref(), Some("copied during the session"));
            rig.s().copy("a password from before", false);
            rig.turn();
            assert_eq!(rig.reported(), None);
        }
    }

    #[test]
    fn text_sent_in_the_tick_of_a_switch_is_dropped() {
        for (knows_own, hint_own) in KINDS {
            let mut rig = Rig::new(knows_own, hint_own);
            // Sent while off, and the link turned on before the next tick.
            rig.send("sent while off");
            rig.activate(true);
            rig.turns(3);
            assert!(rig.s().writes.is_empty(), "kinds {knows_own} {hint_own}");
            // Off and on again around a send, within one tick.
            rig.activate(false);
            rig.send("sent around a pause");
            rig.activate(true);
            rig.turns(2);
            assert!(rig.s().writes.is_empty(), "kinds {knows_own} {hint_own}");
            // Sent while on: set.
            rig.send("sent while on");
            rig.turn();
            assert_eq!(rig.s().writes, ["sent while on"]);
        }
    }

    #[test]
    fn off_and_on_within_one_tick_takes_a_fresh_baseline() {
        for (knows_own, hint_own) in KINDS {
            let mut rig = Rig::new(knows_own, hint_own);
            rig.activate(true);
            rig.turn();
            assert_eq!(rig.s().baselines, 1);
            // Off, a copy, and on again, all between two ticks.
            rig.activate(false);
            rig.s().copy("copied while off", false);
            rig.activate(true);
            rig.turns(2);
            assert_eq!(rig.s().baselines, 2);
            assert_eq!(rig.reported(), None, "kinds {knows_own} {hint_own}");
            // Every `true` sent is an activation, also one sent over an
            // earlier `true` (the session sends only changes): a copy made
            // just before it is behind its baseline, the safe direction.
            rig.s().copy("copied before a repeated on", false);
            rig.activate(true);
            rig.turn();
            assert_eq!(rig.s().baselines, 3);
            assert_eq!(rig.reported(), None);
            rig.s().copy("copied after", false);
            rig.turn();
            assert_eq!(rig.reported().as_deref(), Some("copied after"));
            rig.turns(3);
            assert_eq!(rig.s().baselines, 3);
        }
    }

    #[test]
    fn a_busy_clipboard_holds_the_activation_back() {
        let mut rig = Rig::new(true, false);
        rig.s().copy("a password from before", false);
        rig.s().busy = 2;
        rig.activate(true);
        rig.turn();
        // Held back: nothing read or set; text sent meanwhile is dropped and
        // a copy meanwhile is not read.
        rig.s().copy("copied while held back", false);
        rig.send("sent while held back");
        rig.turn();
        assert_eq!(rig.s().baselines, 2);
        assert_eq!(rig.s().reads, 0);
        assert!(rig.s().writes.is_empty());
        assert_eq!(rig.reported(), None);
        // The third try takes, with the clipboard's text then as the
        // baseline.
        rig.turn();
        assert_eq!(rig.s().baselines, 3);
        assert_eq!(rig.reported(), None);
        assert!(rig.s().writes.is_empty());
        rig.s().copy("copied once on", false);
        rig.turn();
        assert_eq!(rig.reported().as_deref(), Some("copied once on"));
        // No more baselines without a switch.
        rig.turns(3);
        assert_eq!(rig.s().baselines, 3);
    }

    #[test]
    fn the_backends_own_set_is_not_echoed() {
        for (knows_own, hint_own) in KINDS {
            let mut rig = Rig::new(knows_own, hint_own);
            rig.activate(true);
            rig.turn();
            rig.send("from the viewer");
            rig.turns(3);
            assert_eq!(rig.s().writes, ["from the viewer"]);
            assert_eq!(rig.reported(), None, "kinds {knows_own} {hint_own}");
            // The sequence number spares the read.
            assert_eq!(rig.s().reads, u32::from(!knows_own));
            // Someone else copying the same text later is not echoed either
            // (the fingerprint guard; the session's own guard does the same).
            rig.s().copy("from the viewer", false);
            rig.turn();
            assert_eq!(rig.reported(), None, "kinds {knows_own} {hint_own}");
            rig.s().copy("something else", false);
            rig.turn();
            assert_eq!(rig.reported().as_deref(), Some("something else"));
        }
    }

    #[test]
    fn a_crlf_text_read_back_as_lf_is_still_our_own() {
        let mut rig = Rig::new(false, false);
        rig.s().lf_only = true;
        rig.activate(true);
        rig.turn();
        rig.send("line one\r\nline two\r\n");
        rig.turns(2);
        assert_eq!(rig.s().text.as_deref(), Some("line one\nline two\n"));
        assert_eq!(rig.s().reads, 1);
        assert_eq!(rig.reported(), None);
    }

    #[test]
    fn private_and_unfit_text_does_not_cross() {
        let mut rig = Rig::new(true, false);
        rig.activate(true);
        rig.turn();
        let big = "x".repeat(CLIP_MAX + 1);
        for (text, private) in [
            ("a password", true),
            ("", false),
            ("nul\0inside", false),
            (big.as_str(), false),
        ] {
            rig.s().copy(text, private);
            rig.turn();
            assert_eq!(rig.reported(), None);
        }
        // Unchecked (X11: the owner listed no formats; Windows: the
        // clipboard did not open) and sized over the cap before reading.
        for refuse in [|| Read::Unchecked, || Read::TooLarge] {
            rig.s().refuse = Some(refuse);
            rig.s().copy("a plain text", false);
            rig.turn();
            assert_eq!(rig.reported(), None);
        }
        rig.s().refuse = None;
        let full = "y".repeat(CLIP_MAX);
        rig.s().copy(&full, false);
        rig.turn();
        assert_eq!(rig.reported().map(|t| t.len()), Some(CLIP_MAX));
    }

    #[test]
    fn the_newest_text_wins_both_ways() {
        let mut rig = Rig::new(true, false);
        rig.activate(true);
        rig.turn();
        for text in ["a", "b", "c"] {
            rig.send(text);
        }
        for text in ["x", "y", "z"] {
            rig.s().copy(text, false);
        }
        rig.turn();
        // One write of the newest; the copies before it are behind our set.
        assert_eq!(rig.s().writes, ["c"]);
        assert_eq!(rig.reported(), None);
        assert_eq!(rig.s().reads, 0);
        for text in ["p", "q", "r"] {
            rig.s().copy(text, false);
        }
        rig.turn();
        // One read, of the newest.
        assert_eq!(rig.reported().as_deref(), Some("r"));
        assert_eq!(rig.s().reads, 1);
    }

    #[test]
    fn a_raced_read_is_tried_again_and_a_change_is_reported_once() {
        let mut rig = Rig::new(true, false);
        rig.activate(true);
        rig.turn();
        rig.s().copy("copied", false);
        rig.s().race_once = true;
        rig.turn();
        assert_eq!(rig.reported(), None);
        rig.turn();
        assert_eq!(rig.reported().as_deref(), Some("copied"));
        assert_eq!(rig.s().reads, 2);
        // No change, no read.
        rig.turns(3);
        assert_eq!(rig.s().reads, 2);
        // The same text copied again right after is reported once.
        rig.s().copy("copied", false);
        rig.turn();
        assert_eq!(rig.reported(), None);
        // Once text from the viewer replaced it, copying it again crosses.
        rig.send("from the viewer");
        rig.turn();
        rig.s().copy("copied", false);
        rig.turn();
        assert_eq!(rig.reported().as_deref(), Some("copied"));
    }

    #[test]
    fn the_desktop_is_polled_at_its_interval() {
        let mut rig = Rig::with_poll(true, false, Duration::from_millis(250));
        rig.activate(true);
        rig.turn(); // baseline and the first poll
        rig.s().copy("copied", false);
        rig.turn(); // +100 ms
        rig.turn(); // +200 ms
        assert_eq!(rig.s().reads, 0);
        rig.turn(); // +300 ms: due at +250
        assert_eq!(rig.reported().as_deref(), Some("copied"));
        // Sets do not wait for the poll.
        rig.send("from the viewer");
        rig.turn();
        assert_eq!(rig.s().writes, ["from the viewer"]);
    }

    #[test]
    fn dropping_the_link_stops_and_clears_only_our_text() {
        for (knows_own, hint_own) in KINDS {
            // Ours is still there: cleared.
            let mut rig = Rig::new(knows_own, hint_own);
            rig.activate(true);
            rig.turn();
            rig.send("from the viewer");
            rig.turn();
            let Rig {
                mut engine,
                link,
                state,
                now,
            } = rig;
            drop(link);
            assert!(!engine.turn(now + TICK));
            engine.finish();
            let s = state.lock().unwrap();
            assert_eq!(s.released, Some(true));
            assert_eq!(s.text, None);
            drop(s);

            // Someone copied after us: left alone.
            let mut rig = Rig::new(knows_own, hint_own);
            rig.activate(true);
            rig.turn();
            rig.send("from the viewer");
            rig.turn();
            rig.s().copy("the user's own", false);
            rig.turn();
            assert_eq!(rig.reported().as_deref(), Some("the user's own"));
            let Rig {
                mut engine,
                link,
                state,
                now,
            } = rig;
            drop(link);
            assert!(!engine.turn(now + TICK));
            engine.finish();
            let s = state.lock().unwrap();
            assert_eq!(s.released, Some(false));
            assert_eq!(s.text.as_deref(), Some("the user's own"));
        }
    }

    #[test]
    fn each_dropped_channel_stops_the_backend() {
        for which in 0..3 {
            let (link, ends) = ClipboardLink::pair();
            let state = Arc::new(Mutex::new(State::default()));
            let mut engine = Engine::new(Fake(Arc::clone(&state)), ends, Duration::ZERO);
            let ClipboardLink {
                to_desktop,
                from_desktop,
                active,
            } = link;
            assert!(engine.turn(Instant::now()));
            match which {
                0 => drop(to_desktop),
                1 => drop(from_desktop),
                _ => drop(active),
            }
            assert!(!engine.turn(Instant::now()), "channel {which}");
        }
    }

    #[test]
    fn a_failing_desktop_stops_the_backend() {
        let mut rig = Rig::new(true, false);
        rig.activate(true);
        rig.turn();
        rig.s().fail = true;
        assert!(!rig.turn());
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn run_returns_once_the_link_is_dropped() {
        let state = Arc::new(Mutex::new(State {
            knows_own: true,
            ..State::default()
        }));
        let (link, ends) = ClipboardLink::pair();
        let engine = Engine::new(Fake(Arc::clone(&state)), ends, Duration::ZERO);
        let thread = std::thread::spawn(move || engine.run());
        link.active.send_replace(true);
        // Text sent in the tick that switches the link on is dropped: wait
        // for the activation first.
        let deadline = Instant::now() + Duration::from_secs(5);
        while state.lock().unwrap().baselines == 0 {
            assert!(Instant::now() < deadline, "the link never turned on");
            std::thread::sleep(Duration::from_millis(10));
        }
        link.to_desktop
            .send_replace(Some(ClipText::new("set".to_owned()).unwrap()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while state.lock().unwrap().writes.is_empty() {
            assert!(Instant::now() < deadline, "the text was never set");
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(link);
        thread.join().unwrap();
        assert_eq!(state.lock().unwrap().released, Some(true));
    }
}
