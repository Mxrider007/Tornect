//! The clipboard text a session shares (design `services` §4, decision M1-76):
//! the shared types, the contract every clipboard backend keeps, and the
//! host's backend on X11 and Windows ([`arboard_link`]). The GNOME Wayland
//! backend (the portal's Clipboard) lives in `tornect-capture` and keeps the
//! same contract through the same [`ClipboardLink`].
//!
//! **The backend contract.** A backend holds the far ends ([`DesktopEnds`]) of
//! one [`ClipboardLink`]. On `from_desktop` it reports only text that
//! - **changed, as content, after the latest activation**: the text on the
//!   clipboard when `active` turned true (the baseline, kept by its
//!   [`fingerprint`]) is never reported while that activation lasts, even
//!   when an owner change brings it back (a clipboard manager taking it over
//!   from an owner that quit, a delayed rendering done late), and every
//!   activation takes a fresh baseline. A password copied before the session,
//!   or while the link was off, never leaves the machine. Text that is private
//!   or cannot be checked is not read for the baseline: it is never reported
//!   anyway;
//! - it did not set itself (Windows: the clipboard sequence number its set
//!   left; X11: its own sets carry the private hint below; both: the
//!   [`fingerprint`] of its last set);
//! - is not marked private by a password manager (Windows: the formats
//!   [`excluded`] checks; X11: `x-kde-passwordManagerHint`), and when that
//!   cannot be checked, is not reported either;
//! - is a valid [`ClipText`]: non-empty UTF-8 of at most [`CLIP_MAX`] bytes
//!   with no NUL.
//!
//! While `active` is false a backend reads and sets nothing, and text sent on
//! `to_desktop` meanwhile is dropped, not held for later. Every value sent on
//! `active` counts as a switch, even one equal to the last (so an off and on
//! again shorter than the backend's tick is still seen): a `true` takes a
//! fresh baseline, and text sent in the tick of a switch is dropped as well,
//! since it may have been sent before it. The session therefore sends on
//! `active` only when its state changes, and sends text only while the link
//! is on (the viewer's next focus sends it again). Text it sets is kept
//! out of clipboard histories (Windows: the history and cloud exclusions;
//! X11: the KDE hint, which clipboard managers honour). Dropping the link
//! stops the backend, which then clears the clipboard if it still holds the
//! text the backend set last.
//!
//! **Logging.** Never the text: only kinds, byte counts and error kinds
//! (design §2.5). [`ClipText`] and the link print lengths only.
//!
//! Copies of the text that Tornect does not own are not wiped: arboard keeps
//! one in its X11 store while it serves the selection, Windows keeps one in
//! the clipboard's global memory (`docs/research/services.md` R2.3).

#[cfg(any(windows, target_os = "linux", test))]
mod engine;
#[cfg(target_os = "linux")]
mod x11;

// FFI (Win32 DataExchange): opts in to `unsafe` with a `// SAFETY:` comment
// on every block.
#[cfg(windows)]
mod windows;

use std::fmt;

use sha2::{Digest, Sha256};
use tokio::sync::watch;
use zeroize::Zeroizing;

/// The most clipboard text a session shares, in bytes of UTF-8 (256 KiB;
/// `tornect_proto::services::MAX_CLIP` on the wire).
pub const CLIP_MAX: usize = 262_144;

/// Clipboard text that may cross: non-empty UTF-8 of at most [`CLIP_MAX`]
/// bytes and free of NUL. It is wiped when dropped, and its `Debug` prints its
/// length only.
#[derive(Clone)]
pub struct ClipText(Zeroizing<String>);

impl ClipText {
    /// Check `text` and keep it. The refused text is wiped too.
    pub fn new(text: String) -> Result<Self, ClipboardError> {
        let text = Zeroizing::new(text);
        if text.is_empty() {
            return Err(ClipboardError::Empty);
        }
        if text.len() > CLIP_MAX {
            return Err(ClipboardError::TooLarge);
        }
        if text.contains('\0') {
            return Err(ClipboardError::Nul);
        }
        Ok(Self(text))
    }

    /// Text the peer sent, checked as [`ClipText::new`] checks it, with every
    /// control character removed but TAB, LF and CR: C0, DEL and C1 (Unicode's
    /// `Cc`, [`char::is_control`]). A host could otherwise put an escape
    /// sequence on the viewer's clipboard, such as the end of a bracketed
    /// paste followed by a command, which a terminal that does not filter
    /// what is pasted would then run. Text received from the services stream
    /// becomes a `ClipText` only through here, in both directions (decision
    /// M1-76). Other invisible characters stay: emoji sequences, right-to-left
    /// text and several scripts need the zero-width joiners and the direction
    /// marks. Text that held only removed characters is [`Empty`].
    ///
    /// [`Empty`]: ClipboardError::Empty
    pub fn from_peer(text: String) -> Result<Self, ClipboardError> {
        let text = Self::new(text)?;
        if !text.0.chars().any(removed_from_peer) {
            return Ok(text);
        }
        // As long as the text, so no reallocation leaves an unwiped copy.
        let mut kept = Zeroizing::new(String::with_capacity(text.0.len()));
        kept.extend(text.0.chars().filter(|&c| !removed_from_peer(c)));
        if kept.is_empty() {
            return Err(ClipboardError::Empty);
        }
        Ok(Self(kept))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Its length in bytes (never 0).
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }

    /// Its length in characters, as the host's lines count it ("… (12
    /// characters)").
    #[must_use]
    pub fn chars(&self) -> usize {
        self.0.chars().count()
    }

    /// Its [`fingerprint`].
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint(&self.0)
    }
}

/// Whether [`ClipText::from_peer`] removes `c`: a control character other
/// than TAB, LF and CR. NUL never gets here: the text is refused first.
fn removed_from_peer(c: char) -> bool {
    c.is_control() && !matches!(c, '\t' | '\n' | '\r')
}

impl fmt::Debug for ClipText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClipText({} bytes)", self.0.len())
    }
}

/// SHA-256 of `text` with every CRLF taken as LF, so that the same text seen
/// through Windows (CRLF) and through a Linux toolkit (LF) compares equal. A
/// lone CR is kept. Echo guards compare these, never the text.
#[must_use]
pub fn fingerprint(text: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    let mut parts = text.split("\r\n");
    if let Some(first) = parts.next() {
        hash.update(first.as_bytes());
    }
    for part in parts {
        hash.update(b"\n");
        hash.update(part.as_bytes());
    }
    hash.finalize().into()
}

/// The session's end of a clipboard backend. Each channel keeps only its
/// newest value. A new link is inactive.
pub struct ClipboardLink {
    /// Text to put on this computer's clipboard (newest wins).
    pub to_desktop: watch::Sender<Option<ClipText>>,
    /// Text copied on this computer that may cross (newest wins).
    pub from_desktop: watch::Receiver<Option<ClipText>>,
    /// `false`: the backend reads and sets nothing. Each `false → true` edge
    /// takes a fresh baseline.
    pub active: watch::Sender<bool>,
}

/// The backend's end of a [`ClipboardLink`].
pub struct DesktopEnds {
    /// What the session wants on the clipboard.
    pub to_desktop: watch::Receiver<Option<ClipText>>,
    /// Where the backend reports new text.
    pub from_desktop: watch::Sender<Option<ClipText>>,
    /// Whether the backend may read and set.
    pub active: watch::Receiver<bool>,
}

impl ClipboardLink {
    /// A new, inactive link and the ends its backend holds.
    #[must_use]
    pub fn pair() -> (Self, DesktopEnds) {
        let (to_tx, to_rx) = watch::channel(None);
        let (from_tx, from_rx) = watch::channel(None);
        let (active_tx, active_rx) = watch::channel(false);
        (
            Self {
                to_desktop: to_tx,
                from_desktop: from_rx,
                active: active_tx,
            },
            DesktopEnds {
                to_desktop: to_rx,
                from_desktop: from_tx,
                active: active_rx,
            },
        )
    }
}

// The channels' own `Debug` prints the value they hold, which is text.
impl fmt::Debug for ClipboardLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClipboardLink")
            .field("active", &*self.active.borrow())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DesktopEnds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DesktopEnds")
            .field("active", &*self.active.borrow())
            .finish_non_exhaustive()
    }
}

/// Why clipboard text was refused or a backend did not open. No variant
/// carries any of the text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClipboardError {
    /// The text is empty.
    #[error("the clipboard text is empty")]
    Empty,
    /// The text is longer than [`CLIP_MAX`] bytes.
    #[error("the clipboard text is longer than {CLIP_MAX} bytes")]
    TooLarge,
    /// The text holds a NUL character.
    #[error("the clipboard text holds a NUL character")]
    Nul,
    /// No clipboard can be opened here.
    #[error("no clipboard can be opened here: {0}")]
    Unavailable(&'static str),
    /// The backend did not open in time.
    #[error("the clipboard did not open in time")]
    Timeout,
    /// The clipboard refused the text.
    #[error("the clipboard refused the text")]
    Refused,
}

/// Whether the text on this computer's clipboard is marked private by a
/// password manager (design §2.4): on Windows, `Clipboard Viewer Ignore` or
/// `ExcludeClipboardContentFromMonitorProcessing` present, or
/// `CanIncludeInClipboardHistory` / `CanUploadToCloudClipboard` holding the
/// DWORD 0 (`docs/research/services.md` R2.2). `true` as well when the
/// clipboard could not be checked. Always `false` elsewhere: a Linux viewer
/// sees no formats through its toolkit (design §12).
///
/// Prefer [`shareable`], which also closes the race between this check and
/// the read.
#[must_use]
pub fn excluded() -> bool {
    #[cfg(windows)]
    {
        let look = windows::inspect();
        look.private || look.unchecked
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// The clipboard text the viewer may send, read through `read` (the stream
/// window's own clipboard access): `Ok(None)` when there is none, when it is
/// marked private ([`excluded`]), or when the clipboard changed while it was
/// checked and read (Windows; the caller reads again at its next chance);
/// [`ClipboardError::TooLarge`] (then the window says so) or
/// [`ClipboardError::Nul`] when the text cannot cross. On Windows text over
/// [`CLIP_MAX`] is refused before `read` runs.
pub fn shareable(
    read: impl FnOnce() -> Option<String>,
) -> Result<Option<ClipText>, ClipboardError> {
    #[cfg(windows)]
    let before = {
        let before = windows::sequence_number();
        let look = windows::inspect();
        if look.private || look.unchecked {
            return Ok(None);
        }
        if look.too_large {
            return Err(ClipboardError::TooLarge);
        }
        before
    };
    let Some(text) = read() else {
        return Ok(None);
    };
    let text = ClipText::new(text);
    #[cfg(windows)]
    if windows::sequence_number() != before {
        return Ok(None);
    }
    match text {
        Ok(text) => Ok(Some(text)),
        Err(ClipboardError::Empty) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Put `text` on this computer's clipboard kept out of the clipboard history
/// and the cloud clipboard (arboard's `exclude_from_cloud` and
/// `exclude_from_history`): the Windows viewer's way of applying text the host
/// sent (design §2.4, §4.3).
#[cfg(windows)]
pub fn set_private(text: &ClipText) -> Result<(), ClipboardError> {
    windows::set_private(text)
}

/// This computer's clipboard sequence number (`GetClipboardSequenceNumber`;
/// 0 without clipboard access). It changes with every change of the
/// clipboard, so equal numbers before and after a read mean the read saw one
/// clipboard.
#[cfg(windows)]
#[must_use]
pub fn sequence_number() -> u32 {
    windows::sequence_number()
}

/// The host's clipboard backend on an X11 session and on Windows (design
/// §4.2): a thread named `tornect-clipboard` that owns one
/// `arboard::Clipboard` and keeps the [contract](self) through the returned
/// link. It ticks every 100 ms; Windows polls the sequence number every
/// 250 ms, X11 follows XFixes selection events on its own connection.
///
/// On Linux it opens only on an X11 session (`XDG_SESSION_TYPE=x11`) and
/// refuses at once otherwise with [`ClipboardError::Unavailable`]: under
/// GNOME Wayland `$DISPLAY` names Xwayland, which mirrors the Wayland
/// clipboard without the portal's grant, and that grant is what a Wayland
/// host's clipboard needs (design §4.2, `[services] wayland_clipboard`). The
/// caller gates it as well: only for a session whose X11 injector exists (a
/// local `DISPLAY`). Waits at most 5 s for the backend to open.
#[cfg(any(windows, target_os = "linux"))]
pub fn arboard_link() -> Result<ClipboardLink, ClipboardError> {
    #[cfg(target_os = "linux")]
    {
        link_on(std::env::var_os("XDG_SESSION_TYPE").as_deref())
    }
    #[cfg(windows)]
    {
        spawn_link()
    }
}

/// [`arboard_link`] on a session whose `XDG_SESSION_TYPE` is `session_type`.
#[cfg(target_os = "linux")]
fn link_on(session_type: Option<&std::ffi::OsStr>) -> Result<ClipboardLink, ClipboardError> {
    if session_type != Some(std::ffi::OsStr::new("x11")) {
        return Err(ClipboardError::Unavailable("not an X11 session"));
    }
    spawn_link()
}

/// The backend's thread, once the session type allows it.
#[cfg(any(windows, target_os = "linux"))]
fn spawn_link() -> Result<ClipboardLink, ClipboardError> {
    use std::sync::mpsc;
    use std::time::Duration;

    const OPEN_WAIT: Duration = Duration::from_secs(5);

    #[cfg(windows)]
    use windows::Desktop;
    #[cfg(target_os = "linux")]
    use x11::Desktop;

    let (link, ends) = ClipboardLink::pair();
    let (ready, opened) = mpsc::sync_channel::<Result<(), ClipboardError>>(1);
    std::thread::Builder::new()
        .name("tornect-clipboard".to_owned())
        .spawn(move || {
            let desktop = match Desktop::open() {
                Ok(desktop) => desktop,
                Err(e) => {
                    let _ = ready.send(Err(e));
                    return;
                }
            };
            // The caller gave up waiting: its link is gone already.
            if ready.send(Ok(())).is_err() {
                return;
            }
            engine::Engine::new(desktop, ends, Desktop::POLL).run();
        })
        .map_err(|_| ClipboardError::Unavailable("the clipboard thread did not start"))?;
    match opened.recv_timeout(OPEN_WAIT) {
        Ok(Ok(())) => Ok(link),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ClipboardError::Timeout),
    }
}

/// Whether a registered format that holds a DWORD marks the clipboard private
/// (`CanIncludeInClipboardHistory`, `CanUploadToCloudClipboard`): the value 0
/// does, 1 asks for the opposite, and data that cannot be read or is shorter
/// than a DWORD counts as private (`docs/research/services.md` R2.2).
#[cfg(any(windows, test))]
fn dword_marks_private(data: Option<&[u8]>) -> bool {
    match data {
        Some(&[a, b, c, d, ..]) => u32::from_le_bytes([a, b, c, d]) == 0,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn clip_text_holds_only_what_may_cross() {
        assert_eq!(
            ClipText::new(String::new()).unwrap_err(),
            ClipboardError::Empty
        );
        assert_eq!(
            ClipText::new("a\0b".to_owned()).unwrap_err(),
            ClipboardError::Nul
        );
        assert_eq!(
            ClipText::new("x".repeat(CLIP_MAX + 1)).unwrap_err(),
            ClipboardError::TooLarge
        );
        let full = ClipText::new("x".repeat(CLIP_MAX)).unwrap();
        assert_eq!(full.byte_len(), CLIP_MAX);
        // The cap counts bytes, not characters.
        let wide = "é".repeat(CLIP_MAX / 2);
        assert_eq!(ClipText::new(wide.clone()).unwrap().chars(), CLIP_MAX / 2);
        assert_eq!(
            ClipText::new(format!("{wide}x")).unwrap_err(),
            ClipboardError::TooLarge
        );
        let text = ClipText::new("hello\r\nworld".to_owned()).unwrap();
        assert_eq!(text.as_str(), "hello\r\nworld");
        assert_eq!(text.chars(), 12);
    }

    #[test]
    fn nothing_prints_the_text() {
        let text = ClipText::new("hunter2 secret".to_owned()).unwrap();
        assert_eq!(format!("{text:?}"), "ClipText(14 bytes)");
        let (link, ends) = ClipboardLink::pair();
        link.to_desktop.send_replace(Some(text.clone()));
        ends.from_desktop.send_replace(Some(text));
        for shown in [format!("{link:?}"), format!("{ends:?}")] {
            assert!(!shown.contains("hunter2"), "{shown}");
            assert!(shown.contains("active: false"), "{shown}");
        }
        for e in [
            ClipboardError::Empty,
            ClipboardError::TooLarge,
            ClipboardError::Nul,
            ClipboardError::Unavailable("no X display"),
            ClipboardError::Timeout,
            ClipboardError::Refused,
        ] {
            assert!(!e.to_string().contains("hunter2"));
        }
    }

    #[test]
    fn a_new_link_is_inactive_and_empty() {
        let (link, ends) = ClipboardLink::pair();
        assert!(!*link.active.borrow());
        assert!(!*ends.active.borrow());
        assert!(link.from_desktop.borrow().is_none());
        assert!(ends.to_desktop.borrow().is_none());
        link.active.send_replace(true);
        assert!(*ends.active.borrow());
        // Dropping the link closes every channel the backend watches.
        drop(link);
        assert!(ends.from_desktop.is_closed());
        assert!(ends.to_desktop.has_changed().is_err());
        assert!(ends.active.has_changed().is_err());
    }

    #[test]
    fn text_from_the_peer_loses_its_control_characters() {
        // ESC (the end of a bracketed paste and a command after it), BEL and
        // the C1 CSI go; TAB, LF and CR stay.
        let text =
            ClipText::from_peer("a\u{1b}[201~rm -rf ~\u{7}\tb\r\nc\u{9b}31m".to_owned()).unwrap();
        assert_eq!(text.as_str(), "a[201~rm -rf ~\tb\r\nc31m");
        // Every C0 but those three, DEL and every C1.
        let controls: String = ('\u{1}'..='\u{1f}').chain('\u{7f}'..='\u{9f}').collect();
        assert_eq!(
            ClipText::from_peer(format!("x{controls}y"))
                .unwrap()
                .as_str(),
            "x\t\n\ry"
        );
        // Format characters that text needs stay: a ZWJ emoji sequence with a
        // variation selector, a ZWNJ, the direction marks.
        let kept = "\u{1F469}\u{200D}\u{2764}\u{FE0F}\u{200D}\u{1F468} \u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645} \u{200E}a\u{200F}";
        assert_eq!(ClipText::from_peer(kept.to_owned()).unwrap().as_str(), kept);
        // Text without them is kept as it is.
        assert_eq!(
            ClipText::from_peer("plain text\n".to_owned())
                .unwrap()
                .as_str(),
            "plain text\n"
        );
        // The rules of `new` first: NUL is refused, not removed; so is text
        // over the cap, counted before the removal.
        assert_eq!(
            ClipText::from_peer("a\0b".to_owned()).unwrap_err(),
            ClipboardError::Nul
        );
        assert_eq!(
            ClipText::from_peer(format!("{}\u{1b}", "x".repeat(CLIP_MAX))).unwrap_err(),
            ClipboardError::TooLarge
        );
        // Nothing left is empty.
        assert_eq!(
            ClipText::from_peer("\u{1b}\u{9b}".to_owned()).unwrap_err(),
            ClipboardError::Empty
        );
    }

    /// Only an X11 session opens the arboard backend, whatever `$DISPLAY`
    /// names: run under Xvfb too, where a display is there.
    #[cfg(target_os = "linux")]
    #[test]
    fn only_an_x11_session_opens_the_host_backend() {
        use std::ffi::OsStr;
        for session in [
            Some("wayland"),
            Some("tty"),
            Some("X11"),
            Some(""),
            Some("x11 "),
            None,
        ] {
            let started = std::time::Instant::now();
            assert_eq!(
                link_on(session.map(OsStr::new)).unwrap_err(),
                ClipboardError::Unavailable("not an X11 session"),
                "{session:?}"
            );
            assert!(started.elapsed() < std::time::Duration::from_millis(100));
        }
        // What the process runs under decides `arboard_link` itself.
        if std::env::var("XDG_SESSION_TYPE").as_deref() != Ok("x11") {
            assert_eq!(
                arboard_link().unwrap_err(),
                ClipboardError::Unavailable("not an X11 session")
            );
        }
    }

    #[test]
    fn crlf_and_lf_have_one_fingerprint() {
        assert_eq!(fingerprint("a\r\nb\r\n"), fingerprint("a\nb\n"));
        assert_ne!(fingerprint("a\rb"), fingerprint("a\nb"));
        assert_ne!(fingerprint("a\r\nb"), fingerprint("ab"));
        // Each CRLF once: CR CR LF is CR LF, not LF.
        let cr_lf: [u8; 32] = Sha256::digest(b"\r\n").into();
        assert_eq!(fingerprint("\r\r\n"), cr_lf);
        assert_ne!(fingerprint("\r\r\n"), fingerprint("\n"));
        // SHA-256("") and SHA-256("a\nb"), computed apart from this code with
        // Python's `hashlib`.
        assert_eq!(
            hex(&fingerprint("")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&fingerprint("a\r\nb")),
            "7e18f737311b2dc3b2f269dd78396b0351f14fb66efa879f768cb23181883c78"
        );
        let text = ClipText::new("a\r\nb".to_owned()).unwrap();
        assert_eq!(text.fingerprint(), fingerprint("a\nb"));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_dword_format_marks_private_only_at_zero() {
        assert!(dword_marks_private(Some(&[0, 0, 0, 0])));
        assert!(!dword_marks_private(Some(&[1, 0, 0, 0])));
        // Little-endian: 1 << 24 is not 0.
        assert!(!dword_marks_private(Some(&[0, 0, 0, 1])));
        // A longer block is read for its first DWORD.
        assert!(dword_marks_private(Some(&[0, 0, 0, 0, 7])));
        assert!(!dword_marks_private(Some(&[1, 0, 0, 0, 0])));
        // What cannot be read fails closed.
        assert!(dword_marks_private(Some(&[1, 0, 0])));
        assert!(dword_marks_private(Some(&[])));
        assert!(dword_marks_private(None));
    }

    #[test]
    fn shareable_text_follows_the_rules() {
        assert_eq!(shareable(|| None).unwrap().map(|t| t.byte_len()), None);
        assert_eq!(
            shareable(|| Some(String::new()))
                .unwrap()
                .map(|t| t.byte_len()),
            None
        );
        assert_eq!(
            shareable(|| Some("x".repeat(CLIP_MAX + 1))).unwrap_err(),
            ClipboardError::TooLarge
        );
        assert_eq!(
            shareable(|| Some("a\0".to_owned())).unwrap_err(),
            ClipboardError::Nul
        );
        assert_eq!(
            shareable(|| Some("copied".to_owned()))
                .unwrap()
                .map(|t| t.as_str().to_owned()),
            Some("copied".to_owned())
        );
    }

    proptest! {
        #[test]
        fn text_from_the_peer_keeps_all_but_control_characters(
            text in "\\PC{0,20}|[a\t\n\r\u{1}-\u{1f}\u{7f}-\u{9f}\u{200d}]{1,40}",
        ) {
            let expected: String = text
                .chars()
                .filter(|&c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
                .collect();
            match ClipText::from_peer(text.clone()) {
                Ok(kept) => prop_assert_eq!(kept.as_str(), expected.as_str()),
                Err(e) => {
                    prop_assert_eq!(e, ClipboardError::Empty);
                    prop_assert!(expected.is_empty());
                }
            }
        }

        #[test]
        fn the_fingerprint_is_sha256_of_the_text_with_lf_endings(
            text in "[a-c\r\n]{0,40}|\\PC{0,40}",
        ) {
            let expected: [u8; 32] = Sha256::digest(text.replace("\r\n", "\n").as_bytes()).into();
            prop_assert_eq!(fingerprint(&text), expected);
        }
    }
}
