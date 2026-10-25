//! Chat text and its rate (the services design §3.4, §6.1): what either end
//! receives is sanitised before anything shows it, and each end takes at
//! most [`CHAT_RATE`] messages a second from the other.

use std::fmt;
use std::time::Instant;

use tornect_core::trusted::is_invisible_or_control;
use tornect_proto::services::{MAX_CHAT_CHARS, MAX_CHAT_LINES};

use crate::flow::TokenBucket;

/// Chat messages a receiver takes per second on average; more are dropped
/// and counted.
pub const CHAT_RATE: u32 = 4;

/// Chat messages a receiver takes at once.
pub const CHAT_BURST: u32 = 8;

/// A chat message fit to show and to send: built only by
/// [`sanitize_peer_text`], so it holds no control or invisible character but
/// line breaks, at most [`MAX_CHAT_CHARS`] characters on at most
/// [`MAX_CHAT_LINES`] lines, and something visible. Its `Debug` prints its
/// length only (design §2.5: `tracing` never carries chat text).
#[derive(Clone, PartialEq, Eq)]
pub struct ChatText(String);

impl ChatText {
    /// The text, plain: shown as it is, never as markup or links.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Its length in characters.
    #[must_use]
    pub fn chars(&self) -> usize {
        self.0.chars().count()
    }

    /// The text cut to at most `max` bytes of UTF-8 on a character boundary
    /// (a peer's `Welcome.chat_max`); `None` when nothing visible is left.
    pub(crate) fn within(&self, max: usize) -> Option<Self> {
        if self.0.len() <= max {
            return Some(self.clone());
        }
        let mut end = max;
        while !self.0.is_char_boundary(end) {
            end -= 1;
        }
        sanitize_peer_text(&self.0[..end])
    }
}

impl fmt::Debug for ChatText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChatText(<{} chars>)", self.chars())
    }
}

/// Chat text as it may be shown, from whatever the peer (or this computer's
/// user) wrote: every character [`is_invisible_or_control`] matches is
/// dropped but the line break (C0 and C1 controls, DEL, tabs and carriage
/// returns, the bidirectional overrides and isolates, zero-width and other
/// invisible characters), the text is cut after [`MAX_CHAT_LINES`] lines and
/// [`MAX_CHAT_CHARS`] characters, and line breaks at either end are trimmed.
/// `None` when nothing visible is left. Applied on receipt and again before
/// display; applying it twice gives what applying it once gave.
#[must_use]
pub fn sanitize_peer_text(raw: &str) -> Option<ChatText> {
    let mut kept = String::with_capacity(raw.len().min(4 * MAX_CHAT_CHARS));
    let (mut chars, mut lines) = (0usize, 1usize);
    for c in raw.chars() {
        if c == '\n' {
            if lines == MAX_CHAT_LINES {
                break;
            }
            lines += 1;
        } else if is_invisible_or_control(c) {
            continue;
        }
        if chars == MAX_CHAT_CHARS {
            break;
        }
        kept.push(c);
        chars += 1;
    }
    let text = kept.trim_matches('\n');
    if text.trim().is_empty() {
        return None;
    }
    Some(ChatText(text.to_owned()))
}

/// What a receiver takes of the peer's chat: [`CHAT_RATE`] a second,
/// [`CHAT_BURST`] at once.
#[derive(Debug)]
pub(crate) struct ChatGate(TokenBucket);

impl ChatGate {
    /// A full gate at `now`.
    pub(crate) fn new(now: Instant) -> Self {
        Self(TokenBucket::new(CHAT_RATE, CHAT_BURST, now))
    }

    /// Whether a message read at `now` is taken.
    pub(crate) fn admit(&mut self, now: Instant) -> bool {
        self.0.take(now)
    }
}

/// The time the chat gates count in: tokio's clock, which tests pause.
pub(crate) fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use proptest::prelude::*;

    use super::*;

    fn clean(raw: &str) -> Option<String> {
        sanitize_peer_text(raw).map(|t| t.as_str().to_owned())
    }

    /// The services design's test 10, the text half: invisible, bidi and
    /// control characters are dropped and line breaks kept; nothing visible
    /// is nothing.
    #[test]
    fn invisible_bidi_and_control_characters_are_dropped() {
        assert_eq!(clean("hello").as_deref(), Some("hello"));
        assert_eq!(clean("two\nlines").as_deref(), Some("two\nlines"));
        // A right-to-left override that would show "exe.gpj" as "jpg.exe",
        // and the isolates and marks around it.
        assert_eq!(
            clean("photo\u{202e}gpj.exe\u{2066}\u{200f}").as_deref(),
            Some("photogpj.exe")
        );
        // Zero-width space, joiner and non-joiner, the BOM, a soft hyphen.
        assert_eq!(
            clean("a\u{200b}b\u{200d}c\u{200c}d\u{feff}e\u{ad}f").as_deref(),
            Some("abcdef")
        );
        // C0 (an escape sequence, a tab, a carriage return), DEL and C1.
        assert_eq!(
            clean("x\u{1b}[31my\tz\r\u{7f}\u{85}\u{9b}!").as_deref(),
            Some("x[31myz!")
        );
        // The Hangul fillers that render as blanks.
        assert_eq!(clean("\u{115f}\u{3164}hi").as_deref(), Some("hi"));
        assert_eq!(clean(""), None);
        assert_eq!(clean("\u{200b}\u{202e}"), None);
        assert_eq!(clean("\n\n \n"), None);
        assert_eq!(clean("\n\nhi\n\n").as_deref(), Some("hi"));
        assert_eq!(clean("  indented").as_deref(), Some("  indented"));
    }

    /// Test 10, the bounds: at most 40 lines and 2000 characters.
    #[test]
    fn lines_and_characters_are_capped() {
        let many = (1..=60)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let kept = clean(&many).unwrap();
        assert_eq!(kept.lines().count(), MAX_CHAT_LINES);
        assert_eq!(kept.lines().last(), Some("40"));

        let long = "é".repeat(MAX_CHAT_CHARS + 50);
        let kept = sanitize_peer_text(&long).unwrap();
        assert_eq!(kept.chars(), MAX_CHAT_CHARS);
        // Dropped characters do not count.
        let padded = format!("{}{}", "\u{200b}".repeat(500), "a".repeat(MAX_CHAT_CHARS));
        assert_eq!(sanitize_peer_text(&padded).unwrap().chars(), MAX_CHAT_CHARS);
    }

    /// The text is never printed by `Debug`.
    #[test]
    fn debug_prints_the_length_only() {
        let text = sanitize_peer_text("my secret plan").unwrap();
        let shown = format!("{text:?}");
        assert_eq!(shown, "ChatText(<14 chars>)");
        assert!(!shown.contains("secret"));
    }

    /// A message longer than the peer takes is cut on a character boundary.
    #[test]
    fn a_message_is_cut_to_what_the_peer_takes() {
        let text = sanitize_peer_text("aé€😀").unwrap();
        assert_eq!(text.within(100).unwrap().as_str(), "aé€😀");
        assert_eq!(text.within(7).unwrap().as_str(), "aé€");
        assert_eq!(text.within(5).unwrap().as_str(), "aé");
        assert_eq!(text.within(1).unwrap().as_str(), "a");
        assert_eq!(text.within(0), None);
    }

    /// Test 10, the rate: eight at once, the ninth dropped, then four a
    /// second.
    #[test]
    fn the_ninth_of_a_burst_is_dropped() {
        let start = Instant::now();
        let mut gate = ChatGate::new(start);
        for n in 0..CHAT_BURST {
            assert!(gate.admit(start), "message {n} of the burst");
        }
        assert!(!gate.admit(start), "the ninth");
        assert!(!gate.admit(start + Duration::from_millis(200)));
        assert!(gate.admit(start + Duration::from_millis(300)));
        assert!(!gate.admit(start + Duration::from_millis(310)));
        assert!(gate.admit(start + Duration::from_millis(550)));
    }

    proptest! {
        /// Whatever arrives: no character `is_invisible_or_control` matches
        /// but `\n`, within the bounds, never blank, and stable when applied
        /// again (it is applied on receipt and before display).
        #[test]
        fn sanitized_text_is_bounded_visible_and_stable(raw in "\\PC{0,64}|[\\x00-\\x7f\u{200b}-\u{202e}\u{2066}-\u{2069}\n]{0,3000}") {
            if let Some(text) = sanitize_peer_text(&raw) {
                let s = text.as_str();
                prop_assert!(s.chars().all(|c| c == '\n' || !is_invisible_or_control(c)));
                prop_assert!(s.chars().count() <= MAX_CHAT_CHARS);
                prop_assert!(s.lines().count() <= MAX_CHAT_LINES);
                prop_assert!(!s.trim().is_empty());
                prop_assert!(!s.starts_with('\n') && !s.ends_with('\n'));
                let again = sanitize_peer_text(s);
                prop_assert_eq!(again.as_ref(), Some(&text));
            }
        }
    }
}
