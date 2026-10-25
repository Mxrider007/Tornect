//! The host's clipboard on an X11 session (design §4.2,
//! `docs/research/services.md` R2.3–R2.4): a separate connection follows the
//! owner changes of `CLIPBOARD` through XFixes, asks owners for their
//! `TARGETS` and reads the text itself; arboard sets the text and serves it.
//!
//! - **Changes** are `XfixesSelectionNotify` events for `CLIPBOARD` on a 1×1
//!   `InputOnly` window: no polling, which would make every owner serve its
//!   selection on a timer.
//! - **Private text.** Before reading, the owner's `TARGETS` are asked for; a
//!   list with `x-kde-passwordManagerHint` (KeePassXC, Bitwarden), a refusal,
//!   no answer within 2 s or a list over 1024 atoms is not read (fail
//!   closed). The design names the hint for the Wayland portal; X11 password
//!   managers set it too.
//! - **Reads are bounded.** Each request (the formats, the text) goes out on a
//!   window made for that one request, so a late answer to an earlier one can
//!   never be taken for it, and gets 2 s, a deadline checked on every pass of
//!   the wait, also while events stream in (an owner set again and again); a
//!   look at the event queue takes at most 256 events. The text is asked for
//!   as `UTF8_STRING` only and taken from one answer of at most [`CLIP_MAX`]
//!   bytes: a longer one, or an incremental (`INCR`) answer, which owners use
//!   only for what does not fit one request of theirs, is not read. arboard's
//!   `get_text` is not used for reading: it waits up to 4 s for each of six
//!   formats and gathers an incremental answer whole before any cap applies
//!   (R2.3).
//! - **Baseline.** At each activation the selection's text, unless private,
//!   unchecked or not offered as `UTF8_STRING`, is read and kept by its
//!   fingerprint, so that a clipboard manager taking the same text over later
//!   (from an owner that quit) does not make it cross.
//! - **Races.** An owner change while the targets are checked or the text is
//!   read shows up as another event; the read is then dropped and done again.
//! - **Own sets** carry the hint (arboard's `exclude_from_history`), so they
//!   are never read back as new text and clipboard managers keep no copy.
//! - **Release.** At the end the selection is given up only while it is still
//!   ours, and with the time of the newest owner change seen, which the X
//!   server ignores if anyone took the selection after it.
//!
//! arboard's X11 context is one per process, shared with egui-winit's
//! clipboard in the window app (R2.3). x11rb's buffer of a reply is not
//! wiped, like arboard's copy of the text it serves.

use std::thread;
use std::time::{Duration, Instant};

use arboard::SetExtLinux as _;
use x11rb::connection::Connection as _;
use x11rb::errors::{ConnectionError, ReplyError, ReplyOrIdError};
use x11rb::protocol::Event;
use x11rb::protocol::xfixes::{ConnectionExt as _, SelectionEventMask};
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ConnectionExt as _, CreateWindowAux, GetPropertyReply, Timestamp, Window,
    WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::{COPY_DEPTH_FROM_PARENT, COPY_FROM_PARENT, CURRENT_TIME, NONE};
use zeroize::Zeroizing;

use super::engine::{Baseline, Read};
use super::{CLIP_MAX, ClipText, ClipboardError, fingerprint};

/// How long an owner has to answer one request (its formats, its text).
const ANSWER_WAIT: Duration = Duration::from_secs(2);
/// The most formats an owner may list, in atoms.
const MAX_TARGETS: u32 = 1024;
/// The text asked for, in 32-bit units: the cap and one unit more, so that
/// a longer text shows as more than the cap or as bytes left after it.
const TEXT_UNITS: u32 = (CLIP_MAX / 4 + 1) as u32;
/// The most queued events one look takes.
const DRAIN_MAX: usize = 256;
/// The hint password managers put beside their text (`x-kde-passwordManagerHint`
/// = `secret`, the KDE convention, R2.2).
const PRIVATE_HINT: &[u8] = b"x-kde-passwordManagerHint";

fn gone(_: impl std::fmt::Display) -> ClipboardError {
    ClipboardError::Unavailable("the X11 connection failed")
}

struct Atoms {
    clipboard: Atom,
    targets: Atom,
    utf8_string: Atom,
    incr: Atom,
    hint: Atom,
    /// Where owners put their answer, on the request's window.
    property: Atom,
}

/// What an owner's `TARGETS` say.
struct Formats {
    /// The private hint is listed.
    private: bool,
    /// `UTF8_STRING` is listed.
    utf8: bool,
}

/// The X11 half of the backend.
pub(super) struct Desktop {
    clipboard: arboard::Clipboard,
    conn: RustConnection,
    root: Window,
    window: Window,
    atoms: Atoms,
    /// An owner change seen outside [`changed`](super::engine::Desktop::changed)
    /// (during a read), or events left in the queue.
    pending: bool,
    /// The selection time of the newest owner change seen.
    latest: Option<Timestamp>,
}

impl Desktop {
    /// Every tick: events are queued, so looking costs no round trip.
    pub(super) const POLL: Duration = Duration::ZERO;

    pub(super) fn open() -> Result<Self, ClipboardError> {
        let clipboard = arboard::Clipboard::new()
            .map_err(|_| ClipboardError::Unavailable("arboard found no X11 clipboard"))?;
        let (conn, screen) =
            x11rb::connect(None).map_err(|_| ClipboardError::Unavailable("no X display"))?;
        let root = conn
            .setup()
            .roots
            .get(screen)
            .ok_or(ClipboardError::Unavailable(
                "the X server reported no screen",
            ))?
            .root;
        conn.xfixes_query_version(5, 0)
            .map_err(gone)?
            .reply()
            .map_err(|_| ClipboardError::Unavailable("the X server has no XFIXES"))?;
        let atoms = Atoms {
            clipboard: intern(&conn, b"CLIPBOARD")?,
            targets: intern(&conn, b"TARGETS")?,
            utf8_string: intern(&conn, b"UTF8_STRING")?,
            incr: intern(&conn, b"INCR")?,
            hint: intern(&conn, PRIVATE_HINT)?,
            property: intern(&conn, b"TORNECT_CLIPBOARD")?,
        };
        let window = input_window(&conn, root).map_err(gone)?;
        conn.xfixes_select_selection_input(
            window,
            atoms.clipboard,
            SelectionEventMask::SET_SELECTION_OWNER,
        )
        .map_err(gone)?;
        conn.sync().map_err(gone)?;
        Ok(Self {
            clipboard,
            conn,
            root,
            window,
            atoms,
            pending: false,
            latest: None,
        })
    }

    /// Note an event: whether it is an owner change of `CLIPBOARD`.
    fn note(&mut self, event: &Event) -> bool {
        match event {
            Event::XfixesSelectionNotify(e) if e.selection == self.atoms.clipboard => {
                self.latest = Some(e.selection_timestamp);
                true
            }
            _ => false,
        }
    }

    /// Take the queued events, at most [`DRAIN_MAX`], so that a stream of
    /// them cannot hold the thread: whether one was an owner change, and
    /// `true` as well when the cap was reached (the rest wait for the next
    /// look).
    fn drain(&mut self) -> Result<bool, ConnectionError> {
        let mut changed = false;
        for _ in 0..DRAIN_MAX {
            let Some(event) = self.conn.poll_for_event()? else {
                return Ok(changed);
            };
            changed |= self.note(&event);
        }
        Ok(true)
    }

    /// One `ConvertSelection` of `CLIPBOARD` to `target`, on a window made
    /// for it: the property the owner answered with, at most `units` 32-bit
    /// units of it; `None` when the owner refused, answered for another
    /// target, or did not answer within [`ANSWER_WAIT`].
    fn convert(
        &mut self,
        target: Atom,
        units: u32,
    ) -> Result<Option<GetPropertyReply>, ReplyOrIdError> {
        let requestor = input_window(&self.conn, self.root)?;
        let answer = self.answer(requestor, target, units);
        // Destroyed before an error is passed on, so no window is left over;
        // the answer's property goes with it.
        let destroyed = self.conn.destroy_window(requestor);
        let answer = answer?;
        destroyed?;
        self.conn.flush()?;
        Ok(answer)
    }

    fn answer(
        &mut self,
        requestor: Window,
        target: Atom,
        units: u32,
    ) -> Result<Option<GetPropertyReply>, ReplyOrIdError> {
        self.conn.convert_selection(
            requestor,
            self.atoms.clipboard,
            target,
            self.atoms.property,
            CURRENT_TIME,
        )?;
        self.conn.flush()?;
        let deadline = Instant::now() + ANSWER_WAIT;
        // Checked on every pass: events that keep coming (an owner set again
        // and again) cannot hold the thread past the deadline.
        while Instant::now() < deadline {
            let Some(event) = self.conn.poll_for_event()? else {
                thread::sleep(Duration::from_millis(2));
                continue;
            };
            if self.note(&event) {
                self.pending = true;
                continue;
            }
            let Event::SelectionNotify(e) = event else {
                continue;
            };
            if e.requestor != requestor || e.selection != self.atoms.clipboard {
                continue;
            }
            if e.property == NONE || e.target != target {
                return Ok(None);
            }
            // Not deleted: deleting an `INCR` answer would start the transfer
            // this backend does not take.
            let reply = self
                .conn
                .get_property(false, requestor, e.property, AtomEnum::ANY, 0, units)?
                .reply()?;
            return Ok(Some(reply));
        }
        Ok(None)
    }

    /// The current owner's formats: `None` when it refused, did not answer
    /// in time, listed too many, answered in another format, or when there is
    /// no owner.
    fn targets(&mut self) -> Result<Option<Vec<Atom>>, ReplyOrIdError> {
        let Some(reply) = self.convert(self.atoms.targets, MAX_TARGETS)? else {
            return Ok(None);
        };
        // A list of atoms, whole: anything else (an `INCR` answer, a list
        // cut short) cannot be checked.
        let atom = u32::from(AtomEnum::ATOM);
        if reply.bytes_after != 0 || (reply.type_ != atom && reply.type_ != self.atoms.targets) {
            return Ok(None);
        }
        Ok(reply.value32().map(Iterator::collect))
    }

    /// What the owner's formats say: `None` when that cannot be told.
    fn formats(&mut self) -> Option<Formats> {
        match self.targets() {
            Ok(Some(list)) => Some(Formats {
                private: list.contains(&self.atoms.hint),
                utf8: list.contains(&self.atoms.utf8_string),
            }),
            Ok(None) => None,
            Err(e) => {
                tracing::debug!(error = %e, "clipboard: the owner's formats were not read");
                None
            }
        }
    }

    /// The selection as `UTF8_STRING`, from one answer of at most
    /// [`CLIP_MAX`] bytes: [`Read::TooLarge`] for a longer one or an
    /// incremental answer that announces more; [`Read::Nothing`] for an
    /// incremental answer within the cap, a refusal, no answer in time,
    /// another type, or bytes that are not UTF-8.
    fn text(&mut self) -> Read {
        let mut reply = match self.convert(self.atoms.utf8_string, TEXT_UNITS) {
            Ok(Some(reply)) => reply,
            Ok(None) => return Read::Nothing,
            Err(e) => {
                tracing::debug!(error = %e, "clipboard: the text was not read");
                return Read::Nothing;
            }
        };
        if reply.type_ == self.atoms.incr {
            // Its value is a lower bound of the size.
            let announced = reply.value32().and_then(|mut v| v.next()).unwrap_or(0);
            if u64::from(announced) > CLIP_MAX as u64 {
                return Read::TooLarge;
            }
            tracing::debug!("clipboard: the owner answered in pieces; not read");
            return Read::Nothing;
        }
        let mut value = Zeroizing::new(std::mem::take(&mut reply.value));
        if reply.type_ != self.atoms.utf8_string || reply.format != 8 {
            return Read::Nothing;
        }
        if reply.bytes_after != 0 || value.len() > CLIP_MAX {
            return Read::TooLarge;
        }
        match String::from_utf8(std::mem::take(&mut *value)) {
            Ok(text) => Read::Text(Zeroizing::new(text)),
            Err(e) => {
                drop(Zeroizing::new(e.into_bytes()));
                Read::Nothing
            }
        }
    }

    /// Whether the selection changed since the last look, after a round trip
    /// so that every change the server made before now is counted.
    fn changed_by_now(&mut self) -> bool {
        let synced = self.conn.sync().is_ok();
        let changed = self.drain().unwrap_or(true);
        !synced || changed || std::mem::take(&mut self.pending)
    }
}

impl super::engine::Desktop for Desktop {
    fn baseline(&mut self) -> Result<Baseline, ClipboardError> {
        self.conn.sync().map_err(gone)?;
        self.drain().map_err(gone)?;
        self.pending = false;
        // The text now, unless the owner marks it private, cannot be checked
        // or offers no `UTF8_STRING`: such text is never reported, and is not
        // read. An owner change during these reads leaves `pending` set, so
        // the next look compares the text then with this one.
        let found = match self.formats() {
            Some(Formats {
                private: false,
                utf8: true,
            }) => match self.text() {
                Read::Text(text) => Baseline::Text(fingerprint(&text)),
                _ => Baseline::Nothing,
            },
            _ => Baseline::Nothing,
        };
        Ok(found)
    }

    fn changed(&mut self) -> Result<bool, ClipboardError> {
        let drained = self.drain().map_err(gone)?;
        Ok(std::mem::take(&mut self.pending) || drained)
    }

    fn is_own(&self) -> bool {
        false
    }

    fn read(&mut self) -> Read {
        match self.formats() {
            None => return Read::Unchecked,
            Some(Formats { private: true, .. }) => return Read::Private,
            Some(Formats { utf8: false, .. }) => return Read::Nothing,
            Some(_) => {}
        }
        let text = self.text();
        if self.changed_by_now() {
            // Read again at the next turn, against the new owner's formats;
            // what was read is wiped as it drops.
            self.pending = true;
            return Read::Raced;
        }
        text
    }

    fn write(&mut self, text: &ClipText) -> Result<(), ClipboardError> {
        self.clipboard
            .set()
            .exclude_from_history()
            .text(text.as_str())
            .map_err(|_| ClipboardError::Refused)
    }

    fn release(&mut self, own: Option<&[u8; 32]>) {
        let Some(own) = own else {
            return;
        };
        // The newest change's time, counting every change made by now.
        let _ = self.changed_by_now();
        let Some(time) = self.latest else {
            return;
        };
        // Ours is hinted, and holds the text set last.
        if !matches!(self.formats(), Some(Formats { private: true, .. })) {
            return;
        }
        let Read::Text(text) = self.text() else {
            return;
        };
        if fingerprint(&text) != *own {
            return;
        }
        // Ignored by the server if the selection changed after `time`.
        let cleared = self
            .conn
            .set_selection_owner(NONE, self.atoms.clipboard, time)
            .map_err(ReplyError::from)
            .and_then(|_| self.conn.sync());
        match cleared {
            Ok(()) => tracing::debug!("clipboard: the text set last was cleared"),
            Err(e) => tracing::debug!(error = %e, "clipboard: the text set last was not cleared"),
        }
    }
}

impl Drop for Desktop {
    fn drop(&mut self) {
        // The connection's end would destroy it too; this says so first.
        let _ = self.conn.destroy_window(self.window);
        let _ = self.conn.flush();
    }
}

fn intern(conn: &RustConnection, name: &[u8]) -> Result<Atom, ClipboardError> {
    Ok(conn
        .intern_atom(false, name)
        .map_err(gone)?
        .reply()
        .map_err(gone)?
        .atom)
}

/// A 1×1 `InputOnly` window: it receives events and holds properties, and is
/// never shown.
fn input_window(conn: &RustConnection, root: Window) -> Result<Window, ReplyOrIdError> {
    let window = conn.generate_id()?;
    conn.create_window(
        COPY_DEPTH_FROM_PARENT,
        window,
        root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_ONLY,
        COPY_FROM_PARENT,
        &CreateWindowAux::new(),
    )?;
    Ok(window)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    use x11rb::protocol::xproto::{
        EventMask, PropMode, SELECTION_NOTIFY_EVENT, SelectionNotifyEvent,
    };

    use super::*;
    use crate::clipboard::engine::Desktop as _;
    use crate::clipboard::{ClipboardLink, arboard_link, link_on};

    /// The X clipboard is one per display: the tests that use it take turns.
    static DISPLAY: Mutex<()> = Mutex::new(());

    /// The display to themselves, on an X11 session (`arboard_link` opens
    /// only there).
    fn display() -> MutexGuard<'static, ()> {
        assert_eq!(
            std::env::var("XDG_SESSION_TYPE").as_deref(),
            Ok("x11"),
            "run under `env XDG_SESSION_TYPE=x11`"
        );
        DISPLAY.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait_for(link: &mut ClipboardLink, within: Duration) -> Option<String> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if link.from_desktop.has_changed().unwrap_or(false) {
                return link
                    .from_desktop
                    .borrow_and_update()
                    .as_ref()
                    .map(|t| t.as_str().to_owned());
            }
            thread::sleep(Duration::from_millis(20));
        }
        None
    }

    /// Copies as another X client would: a plain text, or one a password
    /// manager marks private.
    fn copy(text: &str, private: bool) {
        let mut clipboard = arboard::Clipboard::new().unwrap();
        let set = clipboard.set();
        let set = if private {
            set.exclude_from_history()
        } else {
            set
        };
        set.text(text.to_owned()).unwrap();
    }

    fn current() -> Option<String> {
        arboard::Clipboard::new().unwrap().get_text().ok()
    }

    /// How a test [`Owner`] answers a request for `UTF8_STRING`.
    #[derive(Clone, Copy)]
    enum Serve {
        /// The text in one property.
        Whole,
        /// An `INCR` answer announcing the text's length, and nothing after.
        Incr,
        /// No answer at all.
        Never,
    }

    /// Another X client that owns `CLIPBOARD` until dropped and serves
    /// `TARGETS` (`UTF8_STRING`, no hint) and its text: a clipboard manager
    /// that took a text over, or an owner that misbehaves.
    struct Owner {
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl Owner {
        fn take(text: &[u8], serve: Serve) -> Self {
            let (conn, screen) = x11rb::connect(None).unwrap();
            let root = conn.setup().roots[screen].root;
            let window = input_window(&conn, root).unwrap();
            let clipboard = intern(&conn, b"CLIPBOARD").unwrap();
            let targets = intern(&conn, b"TARGETS").unwrap();
            let utf8 = intern(&conn, b"UTF8_STRING").unwrap();
            let incr = intern(&conn, b"INCR").unwrap();
            conn.set_selection_owner(window, clipboard, CURRENT_TIME)
                .unwrap();
            conn.sync().unwrap();
            let text = text.to_vec();
            let stop = Arc::new(AtomicBool::new(false));
            let thread = thread::spawn({
                let stop = Arc::clone(&stop);
                move || {
                    while !stop.load(Ordering::Relaxed) {
                        let Ok(Some(event)) = conn.poll_for_event() else {
                            thread::sleep(Duration::from_millis(2));
                            continue;
                        };
                        let Event::SelectionRequest(r) = event else {
                            continue;
                        };
                        let property = if r.target == targets {
                            conn.change_property32(
                                PropMode::REPLACE,
                                r.requestor,
                                r.property,
                                AtomEnum::ATOM,
                                &[targets, utf8],
                            )
                            .unwrap();
                            r.property
                        } else if r.target == utf8 {
                            match serve {
                                Serve::Whole => conn.change_property8(
                                    PropMode::REPLACE,
                                    r.requestor,
                                    r.property,
                                    utf8,
                                    &text,
                                ),
                                Serve::Incr => conn.change_property32(
                                    PropMode::REPLACE,
                                    r.requestor,
                                    r.property,
                                    incr,
                                    &[u32::try_from(text.len()).unwrap()],
                                ),
                                Serve::Never => continue,
                            }
                            .unwrap();
                            r.property
                        } else {
                            NONE
                        };
                        let _ = conn.send_event(
                            false,
                            r.requestor,
                            EventMask::NO_EVENT,
                            SelectionNotifyEvent {
                                response_type: SELECTION_NOTIFY_EVENT,
                                sequence: 0,
                                time: r.time,
                                requestor: r.requestor,
                                selection: r.selection,
                                target: r.target,
                                property,
                            },
                        );
                        let _ = conn.flush();
                    }
                }
            });
            Self {
                stop,
                thread: Some(thread),
            }
        }
    }

    impl Drop for Owner {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// Under an X server: `xvfb-run -a env XDG_SESSION_TYPE=x11 cargo test -p
    /// tornect-input --lib clipboard::x11 -- --ignored`. The tests take turns
    /// on the display.
    #[test]
    #[ignore = "needs an X server (Xvfb)"]
    fn two_links_on_one_display_keep_the_contract() {
        let _display = display();
        let quiet = Duration::from_millis(600);
        // arboard's X11 context is one per process and goes with its last
        // handle; the window app's egui-winit keeps one, and so does this
        // test, so that only the backend's own release can clear anything.
        let _app = arboard::Clipboard::new().expect("an X display");
        let mut a = arboard_link().expect("an X display");
        let mut b = arboard_link().expect("an X display");

        // A copy made before activation is never reported, nor is the same
        // text served by another client after it (a clipboard manager taking
        // over from an owner that quit).
        copy("copied before the session", false);
        thread::sleep(quiet);
        a.active.send_replace(true);
        b.active.send_replace(true);
        assert_eq!(wait_for(&mut a, quiet), None);
        assert_eq!(wait_for(&mut b, quiet), None);
        let manager = Owner::take(b"copied before the session", Serve::Whole);
        assert_eq!(wait_for(&mut a, quiet), None);
        assert_eq!(wait_for(&mut b, quiet), None);
        drop(manager);

        // A plain copy after activation reaches both.
        copy("copied during the session", false);
        assert_eq!(
            wait_for(&mut a, Duration::from_secs(5)).as_deref(),
            Some("copied during the session")
        );
        assert_eq!(
            wait_for(&mut b, Duration::from_secs(5)).as_deref(),
            Some("copied during the session")
        );

        // A password manager's copy reaches neither.
        copy("a password", true);
        assert_eq!(wait_for(&mut a, quiet), None);
        assert_eq!(wait_for(&mut b, quiet), None);

        // Text a link sets is pasteable, is not echoed by that link, and is
        // private to the other one (it carries the hint).
        a.to_desktop
            .send_replace(Some(ClipText::new("from the viewer".to_owned()).unwrap()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while current().as_deref() != Some("from the viewer") {
            assert!(Instant::now() < deadline, "the text was never set");
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(wait_for(&mut a, quiet), None);
        assert_eq!(wait_for(&mut b, quiet), None);

        // While off nothing is reported, and turning on again takes a new
        // baseline.
        b.active.send_replace(false);
        thread::sleep(quiet);
        copy("copied while b was off", false);
        assert_eq!(
            wait_for(&mut a, Duration::from_secs(5)).as_deref(),
            Some("copied while b was off")
        );
        b.active.send_replace(true);
        assert_eq!(wait_for(&mut b, quiet), None);

        // Dropping a link clears the text it set, but only while it is there.
        b.to_desktop
            .send_replace(Some(ClipText::new("set by b".to_owned()).unwrap()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while current().as_deref() != Some("set by b") {
            assert!(Instant::now() < deadline, "the text was never set");
            thread::sleep(Duration::from_millis(20));
        }
        drop(b);
        let deadline = Instant::now() + Duration::from_secs(5);
        while current().is_some() {
            assert!(Instant::now() < deadline, "b's text was not cleared");
            thread::sleep(Duration::from_millis(20));
        }
        a.to_desktop
            .send_replace(Some(ClipText::new("set by a".to_owned()).unwrap()));
        thread::sleep(quiet);
        copy("the user's own copy", false);
        assert_eq!(
            wait_for(&mut a, Duration::from_secs(5)).as_deref(),
            Some("the user's own copy")
        );
        drop(a);
        thread::sleep(quiet);
        assert_eq!(current().as_deref(), Some("the user's own copy"));
    }

    /// The text is read in one answer of at most `CLIP_MAX` bytes, within
    /// 2 s: a longer answer, an incremental one and no answer are not read,
    /// and none of them holds the backend.
    #[test]
    #[ignore = "needs an X server (Xvfb)"]
    fn only_a_whole_answer_within_the_cap_is_read() {
        let _display = display();
        let quiet = Duration::from_millis(600);
        let mut link = arboard_link().expect("an X display");
        link.active.send_replace(true);
        thread::sleep(quiet);

        let over = vec![b'x'; CLIP_MAX + 1];
        let full = vec![b'y'; CLIP_MAX];
        for (text, serve) in [
            (&over, Serve::Whole),
            (&over, Serve::Incr),
            (&full, Serve::Incr),
            (&full, Serve::Never),
        ] {
            let owner = Owner::take(text, serve);
            // The 2 s an owner gets, and the time to see that it is over.
            assert_eq!(wait_for(&mut link, Duration::from_secs(3)), None);
            drop(owner);
        }
        // The backend still follows the clipboard: a whole answer of
        // exactly the cap crosses.
        let owner = Owner::take(&full, Serve::Whole);
        assert_eq!(
            wait_for(&mut link, Duration::from_secs(5)).map(|t| t.len()),
            Some(CLIP_MAX)
        );
        drop(owner);

        // Read directly: each refusal comes within the owner's 2 s.
        let mut desktop = Desktop::open().expect("an X display");
        for (text, serve, wanted) in [
            (&over, Serve::Whole, "over"),
            (&over, Serve::Incr, "over"),
            (&full, Serve::Incr, "nothing"),
            (&full, Serve::Never, "nothing"),
        ] {
            let owner = Owner::take(text, serve);
            // The owner change seen first, as the engine sees it before it
            // reads.
            assert!(desktop.changed_by_now());
            let started = Instant::now();
            let got = match desktop.read() {
                Read::TooLarge => "over",
                Read::Nothing => "nothing",
                Read::Text(_) => "text",
                Read::Private => "private",
                Read::Unchecked => "unchecked",
                Read::Raced => "raced",
            };
            assert_eq!(got, wanted);
            assert!(started.elapsed() < ANSWER_WAIT + Duration::from_millis(500));
            drop(owner);
        }
    }

    /// Owner changes that keep coming do not hold a read past its deadline,
    /// nor a look at the queue.
    #[test]
    #[ignore = "needs an X server (Xvfb)"]
    fn a_stream_of_owner_changes_holds_nothing() {
        let _display = display();
        let mut desktop = Desktop::open().expect("an X display");
        let stop = Arc::new(AtomicBool::new(false));
        // A client that takes the selection again and again and answers
        // nothing.
        let flood = thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                let (conn, screen) = x11rb::connect(None).unwrap();
                let root = conn.setup().roots[screen].root;
                let window = input_window(&conn, root).unwrap();
                let clipboard = intern(&conn, b"CLIPBOARD").unwrap();
                let mut sent = 0_u64;
                while !stop.load(Ordering::Relaxed) {
                    conn.set_selection_owner(window, clipboard, CURRENT_TIME)
                        .unwrap();
                    sent += 1;
                    if sent.is_multiple_of(64) {
                        conn.sync().unwrap();
                    }
                }
                sent
            }
        });
        thread::sleep(Duration::from_millis(200));
        for _ in 0..3 {
            let started = Instant::now();
            assert!(matches!(desktop.read(), Read::Unchecked | Read::Raced));
            assert!(
                started.elapsed() < ANSWER_WAIT + Duration::from_millis(500),
                "{:?}",
                started.elapsed()
            );
            let started = Instant::now();
            assert!(desktop.changed().unwrap());
            assert!(started.elapsed() < Duration::from_millis(500));
        }
        stop.store(true, Ordering::Relaxed);
        assert!(flood.join().unwrap() > 0);
    }

    /// Without `DISPLAY` the backend does not open, and says so at once.
    /// (With one, the ignored tests above cover it.)
    #[test]
    fn no_display_no_backend() {
        if std::env::var_os("DISPLAY").is_some() {
            return;
        }
        let started = Instant::now();
        let refused = link_on(Some(std::ffi::OsStr::new("x11"))).unwrap_err();
        assert!(matches!(refused, ClipboardError::Unavailable(_)));
        assert_ne!(
            refused,
            ClipboardError::Unavailable("not an X11 session"),
            "an X11 session gets as far as the display"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
