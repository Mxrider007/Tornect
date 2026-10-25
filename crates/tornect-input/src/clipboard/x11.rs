//! The host's clipboard on an X11 session (design §4.2,
//! `docs/research/services.md` R2.3–R2.4): arboard reads and sets the
//! `CLIPBOARD` selection; a separate connection follows its owner changes
//! through XFixes and asks owners for their `TARGETS`.
//!
//! - **Changes** are `XfixesSelectionNotify` events for `CLIPBOARD` on a 1×1
//!   `InputOnly` window: no polling, which would make every owner serve its
//!   selection on a timer.
//! - **Private text.** Before reading, the owner's `TARGETS` are asked for on a
//!   window made for that one request (so a late answer to an earlier request
//!   can never be taken for this one); a list with `x-kde-passwordManagerHint`
//!   (KeePassXC, Bitwarden), a refusal, no answer within 2 s or a list over
//!   1024 atoms is not read (fail closed). The design names the hint for the
//!   Wayland portal; X11 password managers set it too.
//! - **Races.** An owner change while the targets are checked or the text is
//!   read shows up as another event; the read is then dropped and done again.
//! - **Own sets** carry the hint (arboard's `exclude_from_history`), so they
//!   are never read back as new text and clipboard managers keep no copy.
//! - **Release.** At the end the selection is given up only while it is still
//!   ours, and with the time of the newest owner change seen, which the X
//!   server ignores if anyone took the selection after it.
//!
//! arboard's X11 context is one per process, shared with egui-winit's
//! clipboard in the window app (R2.3).

use std::thread;
use std::time::{Duration, Instant};

use arboard::SetExtLinux as _;
use x11rb::connection::Connection as _;
use x11rb::errors::{ConnectionError, ReplyError, ReplyOrIdError};
use x11rb::protocol::Event;
use x11rb::protocol::xfixes::{ConnectionExt as _, SelectionEventMask};
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ConnectionExt as _, CreateWindowAux, Timestamp, Window, WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::{COPY_DEPTH_FROM_PARENT, COPY_FROM_PARENT, CURRENT_TIME, NONE};
use zeroize::Zeroizing;

use super::engine::Read;
use super::{ClipText, ClipboardError, fingerprint};

/// How long an owner has to list its formats.
const TARGETS_WAIT: Duration = Duration::from_secs(2);
/// The most formats an owner may list, in atoms.
const MAX_TARGETS: u32 = 1024;
/// The hint password managers put beside their text (`x-kde-passwordManagerHint`
/// = `secret`, the KDE convention, R2.2).
const PRIVATE_HINT: &[u8] = b"x-kde-passwordManagerHint";

fn gone(_: impl std::fmt::Display) -> ClipboardError {
    ClipboardError::Unavailable("the X11 connection failed")
}

struct Atoms {
    clipboard: Atom,
    targets: Atom,
    hint: Atom,
    /// Where owners put their `TARGETS` answer, on the request's window.
    property: Atom,
}

/// The X11 half of the backend.
pub(super) struct Desktop {
    clipboard: arboard::Clipboard,
    conn: RustConnection,
    root: Window,
    window: Window,
    atoms: Atoms,
    /// An owner change seen outside [`changed`](super::engine::Desktop::changed)
    /// (during a read).
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
            hint: intern(&conn, PRIVATE_HINT)?,
            property: intern(&conn, b"TORNECT_CLIPBOARD_TARGETS")?,
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

    /// Take every queued event; whether one was an owner change.
    fn drain(&mut self) -> Result<bool, ConnectionError> {
        let mut changed = false;
        while let Some(event) = self.conn.poll_for_event()? {
            changed |= self.note(&event);
        }
        Ok(changed)
    }

    /// The current owner's formats: `None` when it refused, did not answer
    /// in time, listed too many, answered in another format, or when there is
    /// no owner.
    fn targets(&mut self) -> Result<Option<Vec<Atom>>, ReplyOrIdError> {
        let requestor = input_window(&self.conn, self.root)?;
        let answer = self.ask_targets(requestor);
        // Destroyed before an error is passed on, so no window is left over.
        let destroyed = self.conn.destroy_window(requestor);
        let answer = answer?;
        destroyed?;
        self.conn.flush()?;
        Ok(answer)
    }

    fn ask_targets(&mut self, requestor: Window) -> Result<Option<Vec<Atom>>, ReplyOrIdError> {
        self.conn.convert_selection(
            requestor,
            self.atoms.clipboard,
            self.atoms.targets,
            self.atoms.property,
            CURRENT_TIME,
        )?;
        self.conn.flush()?;
        let deadline = Instant::now() + TARGETS_WAIT;
        loop {
            let Some(event) = self.conn.poll_for_event()? else {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
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
            if e.property == NONE || e.target != self.atoms.targets {
                return Ok(None);
            }
            let reply = self
                .conn
                .get_property(true, requestor, e.property, AtomEnum::ANY, 0, MAX_TARGETS)?
                .reply()?;
            // A list of atoms, whole: anything else (an `INCR` answer, a list
            // cut short) cannot be checked.
            let atom = u32::from(AtomEnum::ATOM);
            if reply.bytes_after != 0 || (reply.type_ != atom && reply.type_ != self.atoms.targets)
            {
                return Ok(None);
            }
            return Ok(reply.value32().map(Iterator::collect));
        }
    }

    /// Whether the selection is marked private: `None` when that cannot be
    /// told.
    fn private(&mut self) -> Option<bool> {
        match self.targets() {
            Ok(Some(list)) => Some(list.contains(&self.atoms.hint)),
            Ok(None) => None,
            Err(e) => {
                tracing::debug!(error = %e, "clipboard: the owner's formats were not read");
                None
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
    fn baseline(&mut self) -> Result<(), ClipboardError> {
        self.conn.sync().map_err(gone)?;
        self.drain().map_err(gone)?;
        self.pending = false;
        Ok(())
    }

    fn changed(&mut self) -> Result<bool, ClipboardError> {
        let drained = self.drain().map_err(gone)?;
        Ok(std::mem::take(&mut self.pending) || drained)
    }

    fn is_own(&self) -> bool {
        false
    }

    fn read(&mut self) -> Read {
        match self.private() {
            Some(true) => return Read::Private,
            Some(false) => {}
            None => return Read::Unchecked,
        }
        let mut text = match self.clipboard.get_text() {
            Ok(text) => Zeroizing::new(text),
            Err(arboard::Error::ContentNotAvailable) => return Read::Nothing,
            Err(e) => {
                tracing::debug!(error = %e, "clipboard: the text was not read");
                return Read::Nothing;
            }
        };
        if self.changed_by_now() {
            // Read again at the next turn, against the new owner's formats.
            self.pending = true;
            return Read::Raced;
        }
        Read::Text(std::mem::take(&mut *text))
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
        if self.private() != Some(true) {
            return;
        }
        let Ok(text) = self.clipboard.get_text().map(Zeroizing::new) else {
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
    use super::*;
    use crate::clipboard::{ClipboardLink, arboard_link};

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

    /// Under an X server: `xvfb-run -a cargo test -p tornect-input --lib
    /// clipboard::x11 -- --ignored`. One test, as the X clipboard is one per
    /// display.
    #[test]
    #[ignore = "needs an X server (Xvfb)"]
    fn two_links_on_one_display_keep_the_contract() {
        let quiet = Duration::from_millis(600);
        // arboard's X11 context is one per process and goes with its last
        // handle; the window app's egui-winit keeps one, and so does this
        // test, so that only the backend's own release can clear anything.
        let _app = arboard::Clipboard::new().expect("an X display");
        let mut a = arboard_link().expect("an X display");
        let mut b = arboard_link().expect("an X display");

        // A copy made before activation is never reported.
        copy("copied before the session", false);
        thread::sleep(quiet);
        a.active.send_replace(true);
        b.active.send_replace(true);
        assert_eq!(wait_for(&mut a, quiet), None);
        assert_eq!(wait_for(&mut b, quiet), None);

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

    /// Without a display the backend does not open, and says so at once.
    /// (With one, the ignored test above covers it.)
    #[test]
    fn no_display_no_backend() {
        if std::env::var_os("DISPLAY").is_some() {
            return;
        }
        let started = Instant::now();
        assert!(matches!(
            arboard_link(),
            Err(ClipboardError::Unavailable(_))
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
