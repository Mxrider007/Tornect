//! The stream window's own clipboard as the viewed session's services use it
//! (the services design §2.4, §4.3, §4.4): when it reads this computer's
//! clipboard, which text it hands to the services stream, and when it puts
//! the host's text on this computer's clipboard.
//!
//! **Reads are rare and never in a loop.** The window reads its clipboard
//! on the UI thread (smithay-clipboard's `load` has no timeout and answers
//! "no focus" until its own worker saw the keyboard enter), so it reads only
//! [`READ_AFTER_FOCUS`] after it gained the keyboard focus, and once more at
//! the first key it routes to the host within [`KEY_RETRY_FOR`] when that
//! read found nothing; at most one read every [`READ_EVERY`], and none while
//! this computer's own screen is shared (the read could stall the window
//! that holds the sharing indicator and Stop).
//!
//! **Only text copied after sharing started crosses.** Each time the window
//! starts sharing its clipboard (the services' `Welcome`, the switch turned
//! back on, the host no longer locked), its next read takes the baseline:
//! that text is never handed over while sharing lasts, nor is the text it
//! handed over or applied last. A password copied before the session never
//! leaves this computer; the cost is that text copied before the first read
//! after sharing started (with the window in the background since) is not
//! sent either, the safe direction.
//!
//! **The host's text waits for the focus.** It is put on this computer's
//! clipboard only while the window has the keyboard focus (Wayland needs a
//! fresh serial, and smithay drops a store without focus), after the read of
//! a focus-in: when that read finds text copied here meanwhile, the local
//! text wins, goes to the host, and the host's waiting text is dropped.
//!
//! Nothing here logs clipboard text, or its length.

use std::time::{Duration, Instant};

use tornect_input::clipboard::{CLIP_MAX, ClipText, ClipboardError, shareable};

/// How long after the window gained the keyboard focus it reads its
/// clipboard (the design's smithay focus race: one read, delayed, rather
/// than one that fails and a retry).
pub const READ_AFTER_FOCUS: Duration = Duration::from_millis(200);

/// How long after a focus-in read that found nothing the first key routed
/// to the host reads again.
pub const KEY_RETRY_FOR: Duration = Duration::from_secs(2);

/// The least time between two reads.
pub const READ_EVERY: Duration = Duration::from_millis(250);

/// This computer's clipboard as the stream window reaches it: egui-winit's
/// (smithay-clipboard on Wayland, arboard on X11 and Windows), a fake in the
/// tests.
pub trait Board {
    /// The text on this computer's clipboard, if any (a blocking read on the
    /// UI thread).
    fn read(&mut self) -> Option<String>;

    /// Put `text` on this computer's clipboard (on Windows kept out of the
    /// clipboard history and the cloud clipboard).
    fn set(&mut self, text: &ClipText);
}

/// The window's ends of the session's clipboard channels
/// (`StreamLink::offer_clip`, `StreamLink::take_clip`).
pub trait Ends {
    /// Hand `text` to the session's services (newest wins); whether a
    /// session took it.
    fn offer(&self, text: ClipText) -> bool;

    /// The host's text not yet put on this computer's clipboard, taken.
    fn take(&self) -> Option<ClipText>;
}

/// What the window may do with its clipboard now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sharing {
    /// The session's services share this window's clipboard: the window
    /// shares one, the host granted the clipboard and did not take it away
    /// or pause it, input reaches the host, and the switch is on.
    pub on: bool,
    /// The longest text the host takes, in bytes (`Welcome.clip_max`).
    pub clip_max: u32,
    /// This computer's screen is not shared: the window may read its
    /// clipboard.
    pub may_read: bool,
}

/// What a [`WindowClip::sync`] asks the window to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Said {
    /// Nothing.
    Nothing,
    /// Text copied here was over the host's cap and was not shared; the cap
    /// in bytes.
    TooLarge(u32),
}

/// The stream window's clipboard state for one session (it lives and dies
/// with the window).
#[derive(Debug, Default)]
pub struct WindowClip {
    /// Sharing at the last sync.
    on: bool,
    /// The window has the keyboard focus.
    focused: bool,
    /// The next read takes the baseline (sharing started and no read took
    /// it yet).
    baseline_due: bool,
    /// The fingerprint of the text on the clipboard at the read that took
    /// the baseline; `None` when that text could not be read whole.
    baseline: Option<[u8; 32]>,
    /// The fingerprint of the text last handed over or applied.
    last: Option<[u8; 32]>,
    /// When the read of a focus-in is due.
    read_at: Option<Instant>,
    /// Until when the first key routed to the host reads again (the
    /// focus-in read found nothing); the host's text waits meanwhile.
    retry_until: Option<Instant>,
    /// A key routed to the host asked for that read.
    retry_now: bool,
    /// When the clipboard was last read.
    read_last: Option<Instant>,
    /// The last read found text over [`CLIP_MAX`] (refused before it is
    /// read whole, so it has no fingerprint): said once, not at every
    /// focus-in while it stays there.
    big: bool,
    /// The fingerprint of the last text over the host's own cap that was
    /// said: said once too.
    refused: Option<[u8; 32]>,
}

impl WindowClip {
    /// The window gained (`true`) or lost the keyboard focus at `now`.
    pub fn focus(&mut self, focused: bool, now: Instant) {
        self.focused = focused;
        if focused {
            if self.on {
                self.read_at = Some(now + READ_AFTER_FOCUS);
            }
        } else {
            self.read_at = None;
            self.retry_now = false;
        }
    }

    /// A key went to the host at `now`: it reads again if the focus-in read
    /// found nothing within [`KEY_RETRY_FOR`].
    pub fn key_to_host(&mut self, now: Instant) {
        if self.retry_until.is_some_and(|until| now <= until) {
            self.retry_until = None;
            self.retry_now = true;
        }
    }

    /// The window shares its clipboard (as of the last sync).
    #[cfg(test)]
    #[must_use]
    pub fn sharing(&self) -> bool {
        self.on
    }

    /// When the window should sync again by itself: a read due, or the
    /// host's text waiting for the end of the key retry.
    #[must_use]
    pub fn due(&self) -> Option<Instant> {
        if !self.on {
            return None;
        }
        let rate = self.read_last.map(|at| at + READ_EVERY);
        let read = match (self.read_at, self.retry_now) {
            (Some(at), _) => Some(rate.map_or(at, |r| r.max(at))),
            (None, true) => rate,
            (None, false) => None,
        };
        let waits = self
            .retry_until
            .map(|until| until + Duration::from_millis(1));
        match (read, waits) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Follow `sharing` at `now`: a read due is done (through `board`, its
    /// text handed to `ends`), and the host's text from `ends` is put on
    /// `board` once the window may. Returns what the window should say.
    pub fn sync(
        &mut self,
        now: Instant,
        sharing: Sharing,
        board: &mut dyn Board,
        ends: &dyn Ends,
    ) -> Said {
        if sharing.on != self.on {
            self.on = sharing.on;
            // Text the host sent before the switch is not applied after it.
            drop(ends.take());
            self.read_at = None;
            self.retry_until = None;
            self.retry_now = false;
            if sharing.on {
                self.baseline_due = true;
                self.baseline = None;
                self.big = false;
                self.refused = None;
                if self.focused {
                    self.read_at = Some(now + READ_AFTER_FOCUS);
                }
            }
        }
        if !self.on {
            return Said::Nothing;
        }
        let mut said = Said::Nothing;
        let due = self.retry_now || self.read_at.is_some_and(|at| now >= at);
        if due && !sharing.may_read {
            // No read while this screen is shared: the next focus-in reads.
            self.read_at = None;
            self.retry_now = false;
        } else if due && self.read_last.is_none_or(|at| now >= at + READ_EVERY) {
            let retried = std::mem::take(&mut self.retry_now);
            self.read_at = None;
            self.read_last = Some(now);
            said = self.read(now, retried, sharing.clip_max, board, ends);
        }
        if self.retry_until.is_some_and(|until| now > until) {
            self.retry_until = None;
        }
        let read_waits = self.read_at.is_some() || self.retry_now || self.retry_until.is_some();
        if self.focused
            && !read_waits
            && let Some(text) = ends.take()
        {
            self.last = Some(text.fingerprint());
            board.set(&text);
        }
        said
    }

    /// One read of the clipboard (`retried`: at a key, after a focus-in
    /// read found nothing).
    fn read(
        &mut self,
        now: Instant,
        retried: bool,
        clip_max: u32,
        board: &mut dyn Board,
        ends: &dyn Ends,
    ) -> Said {
        let cap = clip_max.min(u32::try_from(CLIP_MAX).unwrap_or(u32::MAX));
        match shareable(|| board.read()) {
            Ok(Some(text)) => {
                self.retry_until = None;
                self.big = false;
                let print = text.fingerprint();
                if std::mem::take(&mut self.baseline_due) {
                    self.baseline = Some(print);
                    return Said::Nothing;
                }
                if [self.last, self.baseline, self.refused].contains(&Some(print)) {
                    return Said::Nothing;
                }
                // Copied here meanwhile: it wins over the host's text.
                drop(ends.take());
                if text.byte_len() > clip_max as usize {
                    self.refused = Some(print);
                    return Said::TooLarge(cap);
                }
                self.last = Some(print);
                ends.offer(text);
                Said::Nothing
            }
            Ok(None) => {
                // Nothing to read (or not yet: the focus race); a key retries.
                self.retry_until = (!retried).then_some(now + KEY_RETRY_FOR);
                Said::Nothing
            }
            Err(ClipboardError::TooLarge) => {
                self.retry_until = None;
                let was_big = std::mem::replace(&mut self.big, true);
                if std::mem::take(&mut self.baseline_due) {
                    self.baseline = None;
                    return Said::Nothing;
                }
                if was_big {
                    return Said::Nothing;
                }
                drop(ends.take());
                Said::TooLarge(cap)
            }
            Err(_) => {
                // Text that cannot cross (a NUL): nothing goes, and it takes
                // the baseline's place.
                self.retry_until = None;
                if std::mem::take(&mut self.baseline_due) {
                    self.baseline = None;
                }
                Said::Nothing
            }
        }
    }
}

/// The toast of text over the host's cap of `cap` bytes: "Clipboard text
/// over 256 KiB was not shared." at the default cap.
#[must_use]
pub fn too_large_text(cap: u32) -> String {
    let size = if cap >= 1024 && cap.is_multiple_of(1024) {
        format!("{} KiB", cap / 1024)
    } else {
        format!("{cap} bytes")
    };
    format!("Clipboard text over {size} was not shared.")
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// A clipboard whose text the test sets, counting the reads and keeping
    /// what the window put on it.
    #[derive(Default)]
    struct Fake {
        text: Option<String>,
        reads: usize,
        set: Vec<String>,
    }

    impl Board for Fake {
        fn read(&mut self) -> Option<String> {
            self.reads += 1;
            self.text.clone()
        }

        fn set(&mut self, text: &ClipText) {
            self.text = Some(text.as_str().to_owned());
            self.set.push(text.as_str().to_owned());
        }
    }

    /// Ends that record what the window handed over and hold the host's
    /// text the test gives.
    #[derive(Default)]
    struct Pipe {
        offered: RefCell<Vec<String>>,
        host: RefCell<Option<ClipText>>,
    }

    impl Pipe {
        fn host_sends(&self, text: &str) {
            *self.host.borrow_mut() = Some(clip(text));
        }

        fn offered(&self) -> Vec<String> {
            self.offered.borrow().clone()
        }
    }

    impl Ends for Pipe {
        fn offer(&self, text: ClipText) -> bool {
            self.offered.borrow_mut().push(text.as_str().to_owned());
            true
        }

        fn take(&self) -> Option<ClipText> {
            self.host.borrow_mut().take()
        }
    }

    fn clip(text: &str) -> ClipText {
        ClipText::new(text.to_owned()).unwrap()
    }

    const ON: Sharing = Sharing {
        on: true,
        clip_max: 262_144,
        may_read: true,
    };

    fn ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    /// Sharing starts with the window focused: the read 200 ms later takes
    /// the baseline and sends nothing (the text copied before the session);
    /// text copied afterwards goes at the next focus-in, once, and the same
    /// text is not sent again. No read happens before the 200 ms, nor while
    /// the window is in the background.
    #[test]
    fn only_text_copied_after_sharing_started_goes_at_a_focus_in() {
        let t0 = Instant::now();
        let (mut board, pipe) = (
            Fake {
                text: Some("secret from before".into()),
                ..Fake::default()
            },
            Pipe::default(),
        );
        let mut w = WindowClip::default();
        w.focus(true, t0);
        assert_eq!(w.sync(t0, ON, &mut board, &pipe), Said::Nothing);
        assert_eq!(board.reads, 0, "no read at once");
        assert_eq!(w.due(), Some(t0 + READ_AFTER_FOCUS));
        w.sync(t0 + ms(150), ON, &mut board, &pipe);
        assert_eq!(board.reads, 0);
        w.sync(t0 + ms(200), ON, &mut board, &pipe);
        assert_eq!(board.reads, 1, "the baseline's read");
        assert!(pipe.offered().is_empty(), "the baseline is never sent");
        // Away, a copy, back.
        w.focus(false, t0 + ms(1000));
        board.text = Some("copied here".into());
        w.sync(t0 + ms(1500), ON, &mut board, &pipe);
        assert_eq!(board.reads, 1, "no read in the background");
        w.focus(true, t0 + ms(2000));
        w.sync(t0 + ms(2200), ON, &mut board, &pipe);
        assert_eq!(pipe.offered(), ["copied here"]);
        // The same text at the next focus-in is not sent again; nor is the
        // baseline brought back.
        w.focus(false, t0 + ms(3000));
        w.focus(true, t0 + ms(3100));
        w.sync(t0 + ms(3300), ON, &mut board, &pipe);
        board.text = Some("secret from before".into());
        w.focus(false, t0 + ms(4000));
        w.focus(true, t0 + ms(4100));
        w.sync(t0 + ms(4300), ON, &mut board, &pipe);
        assert_eq!(pipe.offered(), ["copied here"]);
        assert_eq!(board.reads, 4);
    }

    /// Sharing that starts with the window in the background takes its
    /// baseline at the first focus-in's read; a CRLF copy of the baseline
    /// counts as the same text.
    #[test]
    fn the_baseline_waits_for_the_first_read_and_crlf_is_the_same_text() {
        let t0 = Instant::now();
        let mut board = Fake {
            text: Some("a\r\nb".into()),
            ..Fake::default()
        };
        let pipe = Pipe::default();
        let mut w = WindowClip::default();
        w.sync(t0, ON, &mut board, &pipe);
        w.sync(t0 + ms(5000), ON, &mut board, &pipe);
        assert_eq!(board.reads, 0);
        w.focus(true, t0 + ms(6000));
        w.sync(t0 + ms(6200), ON, &mut board, &pipe);
        assert_eq!(board.reads, 1);
        board.text = Some("a\nb".into());
        w.focus(false, t0 + ms(7000));
        w.focus(true, t0 + ms(7100));
        w.sync(t0 + ms(7300), ON, &mut board, &pipe);
        assert!(pipe.offered().is_empty(), "{:?}", pipe.offered());
    }

    /// A focus-in read that finds nothing is tried once more at the first
    /// key routed to the host within 2 s, never later; the host's text
    /// waits for that read (the local text could still win), and is put on
    /// the clipboard once the retry ends.
    #[test]
    fn a_read_that_found_nothing_is_tried_again_at_the_first_key_within_two_seconds() {
        let t0 = Instant::now();
        let mut board = Fake::default();
        let pipe = Pipe::default();
        let mut w = WindowClip::default();
        w.focus(true, t0);
        w.sync(t0, ON, &mut board, &pipe);
        w.sync(t0 + ms(200), ON, &mut board, &pipe);
        assert_eq!(board.reads, 1, "the baseline's read found nothing");
        // It is still due: text here now is the baseline.
        board.text = Some("old".into());
        w.key_to_host(t0 + ms(500));
        w.sync(t0 + ms(500), ON, &mut board, &pipe);
        assert_eq!(board.reads, 2);
        assert!(pipe.offered().is_empty());
        // A focus-in read that finds nothing; the host's text waits.
        w.focus(false, t0 + ms(1000));
        board.text = None;
        pipe.host_sends("from the host");
        w.focus(true, t0 + ms(1100));
        w.sync(t0 + ms(1300), ON, &mut board, &pipe);
        assert_eq!(board.reads, 3);
        assert!(board.set.is_empty(), "the host's text waits for the retry");
        board.text = Some("copied here".into());
        // The key comes before 250 ms passed since that read: the read waits
        // its turn.
        w.key_to_host(t0 + ms(1400));
        w.sync(t0 + ms(1400), ON, &mut board, &pipe);
        assert_eq!(board.reads, 3);
        assert_eq!(w.due(), Some(t0 + ms(1550)));
        w.sync(t0 + ms(1550), ON, &mut board, &pipe);
        assert_eq!(board.reads, 4);
        assert_eq!(pipe.offered(), ["copied here"]);
        assert!(board.set.is_empty(), "the local text won");
        // A retry window that passes without a key lets the host's text in.
        w.focus(false, t0 + ms(2000));
        board.text = None;
        w.focus(true, t0 + ms(2100));
        w.sync(t0 + ms(2300), ON, &mut board, &pipe);
        pipe.host_sends("later");
        w.sync(t0 + ms(3000), ON, &mut board, &pipe);
        assert!(board.set.is_empty());
        assert_eq!(w.due(), Some(t0 + ms(4301)));
        w.key_to_host(t0 + ms(4400));
        w.sync(t0 + ms(4400), ON, &mut board, &pipe);
        assert_eq!(board.reads, 5, "a key after 2 s reads nothing");
        assert_eq!(board.set, ["later"]);
    }

    /// The host's text goes on the clipboard only while the window has the
    /// focus, once its focus-in read is done; local text copied meanwhile
    /// wins and the host's text is dropped; what was applied is not sent
    /// back (the echo guard).
    #[test]
    fn the_hosts_text_waits_for_the_focus_and_local_text_copied_meanwhile_wins() {
        let t0 = Instant::now();
        let mut board = Fake {
            text: Some("base".into()),
            ..Fake::default()
        };
        let pipe = Pipe::default();
        let mut w = WindowClip::default();
        w.focus(true, t0);
        w.sync(t0, ON, &mut board, &pipe);
        w.sync(t0 + ms(200), ON, &mut board, &pipe);
        pipe.host_sends("from the host");
        w.sync(t0 + ms(300), ON, &mut board, &pipe);
        assert_eq!(board.set, ["from the host"], "applied while focused");
        // Not sent back at the next focus-in.
        w.focus(false, t0 + ms(400));
        w.focus(true, t0 + ms(500));
        w.sync(t0 + ms(700), ON, &mut board, &pipe);
        assert!(pipe.offered().is_empty());
        // In the background: it waits; then the focus-in's read decides.
        w.focus(false, t0 + ms(1000));
        pipe.host_sends("second");
        w.sync(t0 + ms(1100), ON, &mut board, &pipe);
        assert_eq!(board.set.len(), 1, "not without the focus");
        w.focus(true, t0 + ms(1200));
        w.sync(t0 + ms(1300), ON, &mut board, &pipe);
        assert_eq!(board.set.len(), 1, "not before the focus-in's read");
        w.sync(t0 + ms(1400), ON, &mut board, &pipe);
        assert_eq!(board.set, ["from the host", "second"]);
        // A copy here while the host's text waits: the copy goes, the
        // host's text is dropped.
        w.focus(false, t0 + ms(2000));
        pipe.host_sends("third");
        board.text = Some("mine".into());
        w.focus(true, t0 + ms(2100));
        w.sync(t0 + ms(2300), ON, &mut board, &pipe);
        assert_eq!(pipe.offered(), ["mine"]);
        assert_eq!(board.set.len(), 2);
        assert!(pipe.take().is_none(), "dropped");
    }

    /// No read while this computer's screen is shared, and none more than
    /// every 250 ms; the host's text is still applied.
    #[test]
    fn no_read_while_this_screen_is_shared_nor_more_often_than_every_quarter_second() {
        let t0 = Instant::now();
        let mut board = Fake::default();
        let pipe = Pipe::default();
        let shared = Sharing {
            may_read: false,
            ..ON
        };
        let mut w = WindowClip::default();
        w.focus(true, t0);
        w.sync(t0, shared, &mut board, &pipe);
        w.sync(t0 + ms(200), shared, &mut board, &pipe);
        assert_eq!(board.reads, 0);
        pipe.host_sends("from the host");
        w.sync(t0 + ms(300), shared, &mut board, &pipe);
        assert_eq!(board.set, ["from the host"]);
        // Two focus-ins 100 ms apart: one read, the second waits its turn.
        w.focus(false, t0 + ms(1000));
        w.focus(true, t0 + ms(1000));
        w.sync(t0 + ms(1200), ON, &mut board, &pipe);
        assert_eq!(board.reads, 1);
        w.focus(false, t0 + ms(1100));
        w.focus(true, t0 + ms(1100));
        w.sync(t0 + ms(1300), ON, &mut board, &pipe);
        assert_eq!(board.reads, 1, "250 ms after the last");
        assert_eq!(w.due(), Some(t0 + ms(1450)));
        w.sync(t0 + ms(1450), ON, &mut board, &pipe);
        assert_eq!(board.reads, 2);
    }

    /// Text over the host's cap is not sent and is said once, not at every
    /// focus-in while it stays; text that was too large at the start is
    /// never said; a NUL never crosses.
    #[test]
    fn text_over_the_cap_is_said_once_and_never_sent() {
        let t0 = Instant::now();
        let mut board = Fake {
            text: Some("x".repeat(CLIP_MAX + 1)),
            ..Fake::default()
        };
        let pipe = Pipe::default();
        let mut w = WindowClip::default();
        w.focus(true, t0);
        w.sync(t0, ON, &mut board, &pipe);
        assert_eq!(w.sync(t0 + ms(200), ON, &mut board, &pipe), Said::Nothing);
        let back = |w: &mut WindowClip, board: &mut Fake, at: u64| {
            w.focus(false, t0 + ms(at));
            w.focus(true, t0 + ms(at));
            w.sync(t0 + ms(at + 200), ON, board, &pipe)
        };
        assert_eq!(back(&mut w, &mut board, 1000), Said::Nothing);
        board.text = Some("small".into());
        assert_eq!(back(&mut w, &mut board, 2000), Said::Nothing);
        board.text = Some("y".repeat(CLIP_MAX + 1));
        assert_eq!(back(&mut w, &mut board, 3000), Said::TooLarge(262_144));
        assert_eq!(back(&mut w, &mut board, 4000), Said::Nothing, "once");
        // Over a host's smaller cap.
        let small = Sharing {
            clip_max: 4096,
            ..ON
        };
        board.text = Some("z".repeat(5000));
        w.focus(false, t0 + ms(5000));
        w.focus(true, t0 + ms(5000));
        assert_eq!(
            w.sync(t0 + ms(5200), small, &mut board, &pipe),
            Said::TooLarge(4096)
        );
        board.text = Some("a\0b".into());
        assert_eq!(back(&mut w, &mut board, 6000), Said::Nothing);
        assert_eq!(pipe.offered(), ["small"]);
        assert_eq!(
            too_large_text(262_144),
            "Clipboard text over 256 KiB was not shared."
        );
        assert_eq!(
            too_large_text(1000),
            "Clipboard text over 1000 bytes was not shared."
        );
    }

    /// Sharing that stops (the switch off, the host locked, the clipboard
    /// taken away) reads and applies nothing; the host's text sent before
    /// it is dropped; sharing again takes a fresh baseline, so text copied
    /// while it was off does not go.
    #[test]
    fn sharing_again_takes_a_fresh_baseline() {
        let t0 = Instant::now();
        let mut board = Fake {
            text: Some("base".into()),
            ..Fake::default()
        };
        let pipe = Pipe::default();
        let off = Sharing { on: false, ..ON };
        let mut w = WindowClip::default();
        w.focus(true, t0);
        w.sync(t0, ON, &mut board, &pipe);
        w.sync(t0 + ms(200), ON, &mut board, &pipe);
        assert!(w.sharing());
        pipe.host_sends("before the switch");
        w.sync(t0 + ms(300), off, &mut board, &pipe);
        assert!(!w.sharing());
        assert!(board.set.is_empty());
        assert!(pipe.take().is_none(), "dropped at the switch");
        board.text = Some("copied while off".into());
        w.focus(false, t0 + ms(400));
        w.focus(true, t0 + ms(500));
        w.sync(t0 + ms(700), off, &mut board, &pipe);
        assert_eq!(board.reads, 1, "no read while off");
        assert_eq!(w.due(), None);
        w.sync(t0 + ms(800), ON, &mut board, &pipe);
        w.sync(t0 + ms(1000), ON, &mut board, &pipe);
        assert_eq!(board.reads, 2, "the fresh baseline's read");
        assert!(pipe.offered().is_empty());
    }
}
