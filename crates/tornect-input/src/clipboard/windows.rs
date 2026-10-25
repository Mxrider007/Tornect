//! The clipboard on Windows (design §2.4, §4.2; `docs/research/services.md`
//! R2.1–R2.3): the private-text check, the sequence number, arboard's
//! history-excluded set, and the host's half of the backend.
//!
//! - **Changes** are a sequence number that differs from the one seen last,
//!   polled every 250 ms, and the number right after our own set marks that
//!   set. A number is not content: a delayed rendering bumps it when the
//!   text is first pasted, or when its owner renders everything as it quits,
//!   so the activation baseline is the text as well (R2.1). In one opening
//!   the private formats are checked and, unless they mark it, the
//!   `CF_UNICODETEXT` text is fingerprinted, which renders a delayed text now;
//!   the number is read after that opening.
//! - **Private text** is checked before reading, in one opening of the
//!   clipboard ([`inspect`]); a read counts only when the number before the
//!   check equals the one after the read, so a password copied in between is
//!   never taken for the text that was checked.
//! - **At the end** the clipboard is emptied only while it still holds our
//!   last set: its number and its text compared and the clipboard emptied in
//!   one opening, during which no other process can change it.
//! - A set by another process in the instant between ours and the reading of
//!   the number is taken for ours: it is not reported (fail safe), and it is
//!   not cleared at the end, where the text is compared as well.
#![allow(unsafe_code)]

use std::marker::PhantomData;
use std::sync::OnceLock;
use std::time::Duration;

use arboard::SetExtWindows as _;
use windows_sys::Win32::Foundation::HGLOBAL;
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
    IsClipboardFormatAvailable, OpenClipboard, RegisterClipboardFormatW,
};
use windows_sys::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};

use zeroize::Zeroizing;

use super::engine::{Baseline, Read};
use super::{CLIP_MAX, ClipText, ClipboardError, dword_marks_private, fingerprint};

/// `CF_UNICODETEXT` (winuser.h; standard clipboard formats). Its feature,
/// `Win32_System_Ole`, is not otherwise needed.
const CF_UNICODETEXT: u32 = 13;

/// The largest `CF_UNICODETEXT` block that can hold [`CLIP_MAX`] bytes of
/// UTF-8: as many UTF-16 units at most, plus the terminator (R2.2).
const MAX_UNICODE_BYTES: usize = 2 * (CLIP_MAX + 1);

/// Formats whose presence marks the clipboard private, then those whose
/// DWORD 0 does.
const PRESENT: [&str; 2] = [
    "ExcludeClipboardContentFromMonitorProcessing",
    "Clipboard Viewer Ignore",
];
const DWORD: [&str; 2] = ["CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"];

/// The formats' registered numbers, `PRESENT` then `DWORD`; `None` when one
/// could not be registered (then nothing is shared).
fn formats() -> Option<[u32; 4]> {
    static FORMATS: OnceLock<Option<[u32; 4]>> = OnceLock::new();
    *FORMATS.get_or_init(|| {
        let mut out = [0; 4];
        for (slot, name) in out.iter_mut().zip(PRESENT.iter().chain(&DWORD)) {
            let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            // SAFETY: `wide` is a NUL-terminated UTF-16 string that lives for
            // the call; the function only reads it.
            *slot = unsafe { RegisterClipboardFormatW(wide.as_ptr()) };
            if *slot == 0 {
                return None;
            }
        }
        Some(out)
    })
}

/// `GetClipboardSequenceNumber`: 0 without clipboard access.
pub(super) fn sequence_number() -> u32 {
    // SAFETY: no arguments and no preconditions; it only reads.
    unsafe { GetClipboardSequenceNumber() }
}

/// The clipboard opened by this thread, closed on drop; never sent to
/// another thread, which could not close it.
struct Opened(PhantomData<*const ()>);

impl Opened {
    /// Open it as arboard does: five tries 5 ms apart, since other processes
    /// hold it briefly all the time.
    fn new() -> Option<Self> {
        Self::trying(5)
    }

    /// Open it within `tries` tries 5 ms apart.
    fn trying(tries: u32) -> Option<Self> {
        for attempt in 0..tries {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
            // SAFETY: a NULL owner window is allowed; the clipboard is then
            // opened for this thread and `Drop` closes it.
            if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                return Some(Self(PhantomData));
            }
        }
        None
    }

    fn has(&self, format: u32) -> bool {
        // SAFETY: plain query with a format number; no pointers.
        unsafe { IsClipboardFormatAvailable(format) != 0 }
    }

    /// A format's data block: its handle, `None` when there is none.
    fn data(&self, format: u32) -> Option<HGLOBAL> {
        // SAFETY: the clipboard is open on this thread (`self`); the handle
        // belongs to the clipboard and is only read, never freed.
        let handle = unsafe { GetClipboardData(format) };
        (!handle.is_null()).then_some(handle)
    }

    /// The size of a format's data block in bytes.
    fn size(&self, format: u32) -> Option<usize> {
        let handle = self.data(format)?;
        // SAFETY: `handle` is a global memory handle the clipboard holds,
        // valid while it is open (`self`).
        Some(unsafe { GlobalSize(handle) })
    }

    /// `f` over a format's data block, locked for the call; `None` when there
    /// is no block or it cannot be locked.
    fn locked<R>(&self, format: u32, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let handle = self.data(format)?;
        // SAFETY: as in `size`.
        let size = unsafe { GlobalSize(handle) };
        // SAFETY: as in `size`; NULL means the block cannot be locked.
        let block = unsafe { GlobalLock(handle) }.cast::<u8>();
        if block.is_null() {
            return None;
        }
        // SAFETY: the locked block is `size` bytes long and stays locked, and
        // the clipboard open, until `f` returns; `R` cannot borrow the slice.
        let out = f(unsafe { std::slice::from_raw_parts(block, size) });
        // SAFETY: balances the `GlobalLock` above on the same handle.
        unsafe { GlobalUnlock(handle) };
        Some(out)
    }

    /// A format's first four bytes, or fewer when its block is shorter;
    /// `None` when the data cannot be had.
    fn head(&self, format: u32) -> Option<Vec<u8>> {
        self.locked(format, |block| block[..block.len().min(4)].to_vec())
    }

    /// The [`fingerprint`] of the `CF_UNICODETEXT` text, read inside this
    /// opening (a delayed text is rendered by it); `None` when there is none
    /// or it is over the cap. Decoded as arboard's read decodes it
    /// (`WideCharToMultiByte` to UTF-8, which puts U+FFFD for a lone
    /// surrogate, up to the first NUL), so a text read later through arboard
    /// has the same fingerprint.
    fn text_fingerprint(&self) -> Option<[u8; 32]> {
        self.locked(CF_UNICODETEXT, |block| {
            if block.len() > MAX_UNICODE_BYTES {
                return None;
            }
            let units = block
                .chunks_exact(2)
                .map(|unit| u16::from_ne_bytes([unit[0], unit[1]]))
                .take_while(|&unit| unit != 0);
            // Three bytes of UTF-8 at most per unit: no reallocation leaves
            // an unwiped copy behind.
            let mut text = Zeroizing::new(String::with_capacity(block.len() / 2 * 3));
            text.extend(
                char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)),
            );
            Some(fingerprint(&text))
        })
        .flatten()
    }

    /// Whether a password manager marked the clipboard private (R2.2):
    /// `formats` as [`formats`] gives them.
    fn private(&self, [exclude, ignore, history, cloud]: [u32; 4]) -> bool {
        self.has(exclude)
            || self.has(ignore)
            || [history, cloud]
                .into_iter()
                .any(|format| self.has(format) && dword_marks_private(self.head(format).as_deref()))
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        // SAFETY: this thread opened the clipboard (`Opened::new`).
        unsafe { CloseClipboard() };
    }
}

/// What [`inspect`] found, without reading the text.
pub(super) struct Look {
    /// A password manager marked the clipboard private.
    pub(super) private: bool,
    /// The clipboard could not be checked (it did not open, or a format could
    /// not be registered): not shared either.
    pub(super) unchecked: bool,
    /// The text block is too large to be text within the cap.
    pub(super) too_large: bool,
}

/// Check the clipboard for the private formats (R2.2) and size its text, in
/// one opening.
pub(super) fn inspect() -> Look {
    let unchecked = Look {
        private: false,
        unchecked: true,
        too_large: false,
    };
    let Some(formats) = formats() else {
        return unchecked;
    };
    let Some(open) = Opened::new() else {
        return unchecked;
    };
    let private = open.private(formats);
    let too_large = !private
        && open.has(CF_UNICODETEXT)
        && open
            .size(CF_UNICODETEXT)
            .is_some_and(|size| size > MAX_UNICODE_BYTES);
    Look {
        private,
        unchecked: false,
        too_large,
    }
}

/// `text` on the clipboard, kept out of the clipboard history and the cloud
/// clipboard.
pub(super) fn set_private(text: &ClipText) -> Result<(), ClipboardError> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|_| ClipboardError::Unavailable("arboard found no clipboard"))?;
    clipboard
        .set()
        .exclude_from_cloud()
        .exclude_from_history()
        .text(text.as_str())
        .map_err(|_| ClipboardError::Refused)
}

/// The Windows half of the host's backend.
pub(super) struct Desktop {
    clipboard: arboard::Clipboard,
    /// The sequence number seen last.
    seen: u32,
    /// The sequence number our last set left.
    own: Option<u32>,
}

impl Desktop {
    /// The design's 250 ms poll of the sequence number.
    pub(super) const POLL: Duration = Duration::from_millis(250);

    pub(super) fn open() -> Result<Self, ClipboardError> {
        let seen = sequence_number();
        if seen == 0 {
            return Err(ClipboardError::Unavailable("no access to the clipboard"));
        }
        let clipboard = arboard::Clipboard::new()
            .map_err(|_| ClipboardError::Unavailable("arboard found no clipboard"))?;
        Ok(Self {
            clipboard,
            seen,
            own: None,
        })
    }
}

impl super::engine::Desktop for Desktop {
    fn baseline(&mut self) -> Result<Baseline, ClipboardError> {
        let found = match formats() {
            // Nothing is ever read without the formats: nothing to keep out.
            None => Baseline::Nothing,
            // Up to half a second, as at the end; then the engine tries again
            // at its next tick.
            Some(formats) => match Opened::trying(100) {
                None => Baseline::Busy,
                Some(open) if open.private(formats) => Baseline::Nothing,
                Some(open) => open
                    .text_fingerprint()
                    .map_or(Baseline::Nothing, Baseline::Text),
            },
        };
        // After the opening: a rendering it caused is not a change.
        self.seen = sequence_number();
        Ok(found)
    }

    fn changed(&mut self) -> Result<bool, ClipboardError> {
        let now = sequence_number();
        if now == 0 {
            return Err(ClipboardError::Unavailable("no access to the clipboard"));
        }
        let changed = now != self.seen;
        self.seen = now;
        Ok(changed)
    }

    fn is_own(&self) -> bool {
        self.own == Some(self.seen)
    }

    fn read(&mut self) -> Read {
        let before = sequence_number();
        let look = inspect();
        if look.unchecked {
            return Read::Unchecked;
        }
        if look.private {
            return Read::Private;
        }
        if look.too_large {
            return Read::TooLarge;
        }
        let text = match self.clipboard.get_text() {
            Ok(text) => Zeroizing::new(text),
            Err(arboard::Error::ContentNotAvailable) => return Read::Nothing,
            Err(e) => {
                tracing::debug!(error = %e, "clipboard: the text was not read");
                return Read::Nothing;
            }
        };
        // Another number than at the check: the next poll sees it differ
        // from the one seen last and reads again.
        if sequence_number() != before {
            return Read::Raced;
        }
        Read::Text(text)
    }

    fn write(&mut self, text: &ClipText) -> Result<(), ClipboardError> {
        self.clipboard
            .set()
            .exclude_from_cloud()
            .exclude_from_history()
            .text(text.as_str())
            .map_err(|_| ClipboardError::Refused)?;
        self.own = Some(sequence_number());
        Ok(())
    }

    fn release(&mut self, own: Option<&[u8; 32]>) {
        let (Some(number), Some(own)) = (self.own, own) else {
            return;
        };
        // Once per session, off the session's path: up to half a second for a
        // clipboard history or another viewer that holds it after a change.
        let Some(open) = Opened::trying(100) else {
            tracing::debug!("clipboard: not opened at the end; the text set last stays");
            return;
        };
        // Still the number our set left, and still the text it set.
        if sequence_number() != number || open.text_fingerprint().as_ref() != Some(own) {
            return;
        }
        // SAFETY: the clipboard is open on this thread (`open`).
        if unsafe { EmptyClipboard() } == 0 {
            tracing::debug!("clipboard: the text set last was not cleared");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::clipboard::{ClipboardLink, arboard_link, excluded, shareable};

    fn set_plain(text: &str) {
        arboard::Clipboard::new().unwrap().set_text(text).unwrap();
    }

    fn current() -> Option<String> {
        arboard::Clipboard::new().unwrap().get_text().ok()
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
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    /// The real clipboard: under Wine on the build VM (`wine <test exe>
    /// clipboard::windows -- --ignored --test-threads 1`) and on a Windows
    /// desktop. One test, as the clipboard is one per session.
    #[test]
    #[ignore = "uses this session's clipboard"]
    fn the_windows_clipboard_keeps_the_contract() {
        let quiet = Duration::from_millis(800);

        // Plain text is shareable; private text is not; the number moves.
        let first = sequence_number();
        assert_ne!(first, 0);
        set_plain("plain text");
        assert_ne!(sequence_number(), first);
        assert!(!excluded());
        // The end-of-session check reads the text inside its own opening.
        set_plain("line one\r\nline two");
        let open = Opened::new().unwrap();
        assert_eq!(
            open.text_fingerprint(),
            Some(fingerprint("line one\nline two"))
        );
        drop(open);
        set_plain("plain text");
        assert_eq!(
            shareable(current).unwrap().map(|t| t.as_str().to_owned()),
            Some("plain text".to_owned())
        );
        set_private(&ClipText::new("secret text".to_owned()).unwrap()).unwrap();
        assert_eq!(current().as_deref(), Some("secret text"));
        assert!(excluded());
        assert!(shareable(current).unwrap().is_none());

        // The host's backend: a copy before activation is never reported,
        // nor is the same text put back later under a new sequence number
        // (as a delayed rendering done late bumps it, R2.1).
        let mut link = arboard_link().unwrap();
        set_plain("copied before the session");
        std::thread::sleep(quiet);
        link.active.send_replace(true);
        assert_eq!(wait_for(&mut link, quiet), None);
        set_plain("copied before the session");
        assert_eq!(wait_for(&mut link, quiet), None);
        set_plain("copied during the session");
        assert_eq!(
            wait_for(&mut link, Duration::from_secs(5)).as_deref(),
            Some("copied during the session")
        );
        // A password manager's copy is not.
        set_private(&ClipText::new("a password".to_owned()).unwrap()).unwrap();
        assert_eq!(wait_for(&mut link, quiet), None);
        // Text it sets is not echoed, is private, and is cleared at the end.
        link.to_desktop
            .send_replace(Some(ClipText::new("from the viewer".to_owned()).unwrap()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while current().as_deref() != Some("from the viewer") {
            assert!(Instant::now() < deadline, "the text was never set");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(excluded());
        assert_eq!(wait_for(&mut link, quiet), None);
        drop(link);
        let deadline = Instant::now() + Duration::from_secs(5);
        while current().is_some() {
            assert!(
                Instant::now() < deadline,
                "the text set last was not cleared"
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        // A copy made after the backend's set is left at the end.
        let mut link = arboard_link().unwrap();
        link.active.send_replace(true);
        std::thread::sleep(quiet);
        link.to_desktop.send_replace(Some(
            ClipText::new("set by the backend".to_owned()).unwrap(),
        ));
        std::thread::sleep(quiet);
        set_plain("the user's own copy");
        assert_eq!(
            wait_for(&mut link, Duration::from_secs(5)).as_deref(),
            Some("the user's own copy")
        );
        drop(link);
        std::thread::sleep(quiet);
        assert_eq!(current().as_deref(), Some("the user's own copy"));
    }
}
