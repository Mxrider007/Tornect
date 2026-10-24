//! Invitations and `tornect:` links (design `invite` §4.1–§4.2).
//!
//! An invitation is the short text a user shares so that someone else can reach
//! this computer: the grouped ID, a `tornect://` link and the one download location.
//! What comes back (a clicked link, a pasted invitation, a typed ID) is read by the
//! strict parsers here, which only ever *name* a [`TornectId`]: nothing in this
//! module does I/O, and a link never carries anything Tornect acts on. A link with
//! anything besides the ID is refused whole, so no parameter is ever read (L-2);
//! every input is size-bounded before any other work.

use crate::id::{IdError, ONION_V3_ADDR_LEN, TornectId, is_b32, strip_suffix_ignore_case};

/// The URI scheme of Tornect links (`tornect://<ID>`).
pub const SCHEME: &str = "tornect";

/// Where Tornect is downloaded, the one location invitations and the README name.
/// Derived from the workspace `repository` field so the two can never disagree.
pub const DOWNLOAD_URL: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/releases");

/// The longest link [`parse_link`] reads, in bytes. A generated link is 66 bytes;
/// the bound leaves room for `.onion/`, case and whitespace, never for parameters.
pub const MAX_LINK: usize = 128;

/// The longest text [`find_id`] reads, in bytes: an invitation is about 350.
pub const MAX_TEXT: usize = 4096;

const ONION: &str = ".onion";

/// Format characters chat and mail clients insert so long tokens can wrap. Bidi
/// controls are deliberately absent: they stay outside the alphabet and are refused.
const INVISIBLE: [char; 6] = [
    '\u{00AD}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}',
];

/// Characters that, inside a link, mean it carries something besides the ID.
const LINK_EXTRAS: [char; 12] = ['?', '#', '@', ':', '%', '&', '=', ';', '+', '/', '-', '.'];

/// Punctuation trimmed from both ends of a free-text token (quotes, brackets, the
/// full stop ending a sentence).
const TOKEN_TRIM: [char; 22] = [
    '<', '>', '(', ')', '[', ']', '{', '}', '"', '\'', '.', ',', ';', '!', '?', '*', '“', '”', '‘',
    '’', '«', '»',
];

/// A text of at most this many whitespace-separated tokens may be one typed ID.
const MAX_TYPED_TOKENS: usize = 8;

/// The [`TornectId::display_groups`] form: seven groups of eight characters.
const GROUP_LEN: usize = 8;
const GROUPS: usize = ONION_V3_ADDR_LEN / GROUP_LEN;

/// How [`find_id`] found the ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The text is the ID itself, bare, grouped, hyphenated or with `.onion`.
    Typed,
    /// The text is one `tornect:` link.
    Link,
    /// The ID was picked out of a longer text, such as a whole invitation.
    Text,
}

/// An ID found in field text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found {
    /// The ID, a valid ed25519 key.
    pub id: TornectId,
    /// Where in the text it was.
    pub source: Source,
    /// Whether invisible format characters were removed from the text first.
    pub stripped: bool,
}

impl Found {
    /// Whether a field holding the text should be rewritten to the ID's groups:
    /// the ID came out of a link or a longer text, or invisible characters were
    /// removed. A cleanly typed ID is left as it is, so the cursor never jumps.
    #[must_use]
    pub fn rewrite(&self) -> bool {
        self.source != Source::Typed || self.stripped
    }
}

/// Why no ID could be taken from a link or a text. The `Display` texts are the
/// command line's; a window adds a final full stop. None of them echoes the input,
/// except one character in [`IdProblem::NotAlphabet`], and only a printable ASCII one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdProblem {
    /// Nothing but whitespace (a window shows no line for it).
    #[error("No Tornect ID was given")]
    Empty,
    /// Fewer than 56 characters.
    #[error("{found} of 56 characters")]
    Short {
        /// How many characters there were.
        found: usize,
    },
    /// More than 56 characters.
    #[error("{found} of 56 characters: {} too many", .found.saturating_sub(ONION_V3_ADDR_LEN))]
    Long {
        /// How many characters there were.
        found: usize,
    },
    /// A `0`, `1`, `8` or `9`, which base32 leaves out.
    #[error("IDs never contain 0, 1, 8 or 9 (perhaps the letter o, i, l, b or g)")]
    NeverDigit,
    /// Another character outside the alphabet; the character is kept only when it
    /// is printable ASCII, so no bidi, control or invisible character is rendered.
    #[error("IDs hold only the letters a–z and the digits 2–7{}", never_clause(.0))]
    NotAlphabet(Option<char>),
    /// An onion address of a version other than 3.
    #[error("That is an onion address of another version, not a Tornect ID")]
    Version,
    /// The checksum does not match: a typo.
    #[error("A character is wrong somewhere: compare the ID again, character by character")]
    Checksum,
    /// The right shape, but the 32 bytes are no ed25519 key.
    #[error("That ID has the right shape but is no computer's key: check for a typo")]
    NotAKey,
    /// No `tornect:` scheme.
    #[error("That is not a tornect:// link")]
    NotALink,
    /// A link holding more than the ID (parameters, a path, a port, a user, …).
    #[error("That link holds more than a Tornect ID; Tornect takes only tornect://<ID>")]
    LinkExtras,
    /// A text holding more than one distinct ID.
    #[error("That text holds more than one Tornect ID: paste only the one you want")]
    Several,
    /// A longer text without an ID in it.
    #[error("No Tornect ID in that text")]
    NoId,
    /// More than [`MAX_TEXT`] bytes.
    #[error("That text is too long to hold an invitation")]
    TooLong,
}

impl IdProblem {
    /// A static name for logs, which never carry the link or the text itself.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Short { .. } => "short",
            Self::Long { .. } => "long",
            Self::NeverDigit => "never_digit",
            Self::NotAlphabet(_) => "not_alphabet",
            Self::Version => "version",
            Self::Checksum => "checksum",
            Self::NotAKey => "not_a_key",
            Self::NotALink => "not_a_link",
            Self::LinkExtras => "link_extras",
            Self::Several => "several",
            Self::NoId => "no_id",
            Self::TooLong => "too_long",
        }
    }
}

fn never_clause(c: &Option<char>) -> String {
    match c {
        Some(c) if c.is_ascii_graphic() => format!(", never “{c}”"),
        _ => String::new(),
    }
}

/// The link of `id`: `tornect://` and the 56 lowercase characters.
#[must_use]
pub fn link(id: &TornectId) -> String {
    format!("{SCHEME}://{}", id.base32())
}

/// The text Copy invitation copies and `tornect id --invitation` prints: the ID in
/// groups (the fallback where a chat does not make `tornect://` clickable), its link
/// and the download location, with LF line endings and no final newline. It carries
/// no device name and no device words (§B.6.1 item 9).
#[must_use]
pub fn invitation(id: &TornectId) -> String {
    format!(
        "Connect to my computer with Tornect.\n\
         \n\
         My Tornect ID: {groups}\n\
         Link: {link}\n\
         \n\
         No Tornect yet? Get it for Linux or Windows: {DOWNLOAD_URL}\n\
         The first time you connect, both screens show a 6-digit code: go on only if they match.",
        groups = id.display_groups(),
        link = link(id),
    )
}

/// The ID of a `tornect:` link, strictly (§4.1):
///
/// ```text
/// link     = scheme ":" [ "//" ] onion-id [ ".onion" ] [ "/" ]
/// scheme   = "tornect"                       ; ASCII case-insensitive
/// onion-id = 56 b32                          ; A–Z a–z 2–7
/// ```
///
/// ASCII whitespace around the link is ignored; anything else besides the ID is
/// [`IdProblem::LinkExtras`] (or the alphabet problem of its first stray character),
/// never a parameter that is read. Nothing invisible is removed here: a link the
/// OS hands over must be exactly a link.
pub fn parse_link(s: &str) -> Result<TornectId, IdProblem> {
    if s.len() > MAX_LINK {
        return Err(IdProblem::LinkExtras);
    }
    let s = s.trim_matches(|c: char| c.is_ascii_whitespace());
    let (scheme, rest) = s.split_once(':').ok_or(IdProblem::NotALink)?;
    if !scheme.eq_ignore_ascii_case(SCHEME) {
        return Err(IdProblem::NotALink);
    }
    let rest = rest.strip_prefix("//").unwrap_or(rest);
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let body = strip_suffix_ignore_case(rest, ONION).unwrap_or(rest);
    check_body(body, outside_link)
}

/// The ID in what a user put into an ID field (§4.2), in this order:
///
/// 1. more than [`MAX_TEXT`] bytes is [`IdProblem::TooLong`];
/// 2. the invisible format characters chat clients insert (U+00AD, U+200B, U+200C,
///    U+200D, U+2060, U+FEFF) are removed, never bidi controls;
/// 3. surrounding whitespace is trimmed; nothing left is [`IdProblem::Empty`];
/// 4. one `tornect:` token is a link, read by [`parse_link`];
/// 5. at most eight tokens without `:` or `/` are a typed ID, read without its
///    whitespace and hyphens and with one optional `.onion`;
/// 6. otherwise, and when step 5 failed, the text is searched: `tornect:` tokens
///    (any malformed one fails the whole text), 56-character tokens and seven
///    consecutive 8-character groups. Exactly one distinct ID is the answer; more
///    is [`IdProblem::Several`], so an invitation whose visible ID and link differ
///    is refused.
///
/// Without an ID the answer is the typed reading's problem, else the first failing
/// candidate's, else [`IdProblem::NoId`]. A found ID is always a valid key.
pub fn find_id(text: &str) -> Result<Found, IdProblem> {
    if text.len() > MAX_TEXT {
        return Err(IdProblem::TooLong);
    }
    let cleaned: String = text.chars().filter(|c| !INVISIBLE.contains(c)).collect();
    let stripped = cleaned.len() != text.len();
    let text = cleaned.trim();
    if text.is_empty() {
        return Err(IdProblem::Empty);
    }
    let found = |id, source| Found {
        id,
        source,
        stripped,
    };
    if !text.contains(char::is_whitespace) && has_scheme(text) {
        return parse_link(text).map(|id| found(id, Source::Link));
    }
    let typed_err = if typed_shape(text) {
        match typed(text) {
            Ok(id) => return Ok(found(id, Source::Typed)),
            Err(problem) => Some(problem),
        }
    } else {
        None
    };
    let scan = scan(text)?;
    match scan.ids.as_slice() {
        [id] => Ok(found(*id, Source::Text)),
        [] => Err(typed_err.or(scan.first_failure).unwrap_or(IdProblem::NoId)),
        [_, _, ..] => Err(IdProblem::Several),
    }
}

/// Whether `s` starts with `tornect:`, in any ASCII case. Compared as bytes, so a
/// multi-byte character across the eighth byte is a plain mismatch.
fn has_scheme(s: &str) -> bool {
    const PREFIX: &[u8] = b"tornect:";
    s.as_bytes()
        .get(..PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(PREFIX))
}

/// Step 5's condition: few enough tokens, none of them part of a URL.
fn typed_shape(text: &str) -> bool {
    text.split_whitespace().nth(MAX_TYPED_TOKENS).is_none() && !text.contains([':', '/'])
}

/// Step 5: the text as one typed ID.
fn typed(text: &str) -> Result<TornectId, IdProblem> {
    let body: String = text
        .chars()
        .filter(|&c| !c.is_whitespace() && c != '-')
        .collect();
    let body = strip_suffix_ignore_case(&body, ONION).unwrap_or(&body);
    check_body(body, outside_id)
}

/// What step 6 found in a free text.
#[derive(Default)]
struct Scan {
    /// The distinct valid IDs, sorted.
    ids: Vec<TornectId>,
    /// The problem of the first candidate that had an ID's shape but was none.
    first_failure: Option<IdProblem>,
}

impl Scan {
    fn note(&mut self, candidate: Result<TornectId, IdProblem>) {
        match candidate {
            Ok(id) => {
                if let Err(at) = self.ids.binary_search(&id) {
                    self.ids.insert(at, id);
                }
            }
            Err(problem) => {
                self.first_failure.get_or_insert(problem);
            }
        }
    }
}

/// Step 6: every candidate in a free text. A malformed link fails the whole text.
fn scan(text: &str) -> Result<Scan, IdProblem> {
    let tokens: Vec<&str> = text
        .split_whitespace()
        .map(|t| t.trim_matches(|c| TOKEN_TRIM.contains(&c)))
        .collect();
    let mut scan = Scan::default();
    for (i, token) in tokens.iter().enumerate() {
        if has_scheme(token) {
            scan.note(Ok(parse_link(token)?));
        } else if let Some(body) = bare_id(token) {
            scan.note(check_body(&body, outside_id));
        }
        if let Some(window) = tokens.get(i..i + GROUPS)
            && window.iter().all(|t| is_group(t))
        {
            scan.note(check_body(&window.concat(), outside_id));
        }
    }
    Ok(scan)
}

/// A token that is 56 alphabet characters once hyphens and one `.onion` are gone.
fn bare_id(token: &str) -> Option<String> {
    if token.len() < ONION_V3_ADDR_LEN {
        return None;
    }
    let body: String = token.chars().filter(|&c| c != '-').collect();
    let body = strip_suffix_ignore_case(&body, ONION).unwrap_or(&body);
    (body.len() == ONION_V3_ADDR_LEN && body.chars().all(is_b32)).then(|| body.to_owned())
}

/// One group of [`TornectId::display_groups`]: eight alphabet characters.
fn is_group(token: &str) -> bool {
    token.len() == GROUP_LEN && token.chars().all(is_b32)
}

/// The shared tail of every reading: the first character outside the alphabet
/// (classified by `outside`), then the length, then version and checksum, then the
/// curve point.
fn check_body(body: &str, outside: fn(char) -> IdProblem) -> Result<TornectId, IdProblem> {
    if let Some(c) = body.chars().find(|&c| !is_b32(c)) {
        return Err(outside(c));
    }
    if body.len() != ONION_V3_ADDR_LEN {
        return Err(wrong_length(body.len()));
    }
    let id: TornectId = body.parse().map_err(|e| match e {
        IdError::Version(_) => IdProblem::Version,
        IdError::Checksum => IdProblem::Checksum,
        IdError::PublicKey => IdProblem::NotAKey,
        // Unreachable after the two checks above; kept total rather than panicking.
        IdError::Length { found, .. } => wrong_length(found),
        IdError::Base32 => IdProblem::NotAlphabet(None),
    })?;
    id.verifying_key().map_err(|_| IdProblem::NotAKey)?;
    Ok(id)
}

fn wrong_length(found: usize) -> IdProblem {
    if found < ONION_V3_ADDR_LEN {
        IdProblem::Short { found }
    } else {
        IdProblem::Long { found }
    }
}

/// A character outside the alphabet in a typed ID or a free-text candidate.
fn outside_id(c: char) -> IdProblem {
    if matches!(c, '0' | '1' | '8' | '9') {
        IdProblem::NeverDigit
    } else {
        IdProblem::NotAlphabet(Some(c).filter(char::is_ascii_graphic))
    }
}

/// A character outside the alphabet in a link: URL syntax or whitespace means the
/// link carries something besides the ID.
fn outside_link(c: char) -> IdProblem {
    if c.is_whitespace() || LINK_EXTRAS.contains(&c) {
        IdProblem::LinkExtras
    } else {
        outside_id(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE32_NOPAD;
    use ed25519_dalek::SigningKey;

    /// The ID of the ed25519 key with this seed: always a valid curve point.
    fn key_id(seed: [u8; 32]) -> TornectId {
        TornectId::from_public_key(&SigningKey::from_bytes(&seed).verifying_key())
    }

    fn a() -> TornectId {
        key_id([1; 32])
    }

    fn b() -> TornectId {
        key_id([2; 32])
    }

    /// The right shape and checksum, but 32 bytes that decode to no curve point.
    fn not_a_key() -> TornectId {
        (0..=u8::MAX)
            .map(|i| TornectId::from_bytes([i; 32]))
            .find(|id| id.verifying_key().is_err())
            .expect("some repeated byte is no curve point")
    }

    /// `id`'s key with version byte 2 (the checksum is not reached).
    fn version_2(id: &TornectId) -> String {
        let mut raw = [0u8; 35];
        raw[..32].copy_from_slice(id.public_key_bytes());
        raw[34] = 2;
        BASE32_NOPAD.encode(&raw).to_ascii_lowercase()
    }

    /// `id` with its first character changed: another key, so the checksum fails.
    fn checksum_typo(id: &TornectId) -> String {
        let body = id.base32();
        let first = if body.starts_with('a') { "b" } else { "a" };
        let typo = format!("{first}{}", &body[1..]);
        assert_eq!(typo.parse::<TornectId>(), Err(IdError::Checksum));
        typo
    }

    fn typed(id: TornectId, stripped: bool) -> Result<Found, IdProblem> {
        Ok(Found {
            id,
            source: Source::Typed,
            stripped,
        })
    }

    fn text(id: TornectId) -> Result<Found, IdProblem> {
        Ok(Found {
            id,
            source: Source::Text,
            stripped: false,
        })
    }

    fn linked(id: TornectId) -> Result<Found, IdProblem> {
        Ok(Found {
            id,
            source: Source::Link,
            stripped: false,
        })
    }

    #[test]
    fn the_fixtures_are_what_they_claim() {
        assert_ne!(a(), b());
        assert!(a().verifying_key().is_ok() && b().verifying_key().is_ok());
        assert!(not_a_key().verifying_key().is_err());
        assert!(not_a_key().base32().parse::<TornectId>().is_ok());
        assert_eq!(
            version_2(&a()).parse::<TornectId>(),
            Err(IdError::Version(2))
        );
    }

    #[test]
    fn a_link_is_the_scheme_and_the_lowercase_id() {
        let id = a();
        assert_eq!(link(&id), format!("tornect://{}", id.base32()));
        assert_eq!(link(&id).len(), 66);
        assert!(link(&id).len() <= MAX_LINK);
        assert_eq!(parse_link(&link(&id)), Ok(id));
    }

    #[test]
    fn parse_link_accepts_the_grammar() {
        let id = a();
        let body = id.base32();
        let upper = body.to_ascii_uppercase();
        for ok in [
            format!("tornect://{body}"),
            format!("tornect:{body}"),
            format!("tornect://{body}/"),
            format!("tornect:{body}.onion"),
            format!("tornect://{body}.onion/"),
            format!("TORNECT://{upper}.ONION/"),
            format!("ToRnEcT:{upper}"),
            format!("  tornect://{body}\n"),
            format!("\t\r\ntornect://{body} \x0c"),
        ] {
            assert_eq!(parse_link(&ok), Ok(id), "{ok:?}");
        }
    }

    #[test]
    fn parse_link_refuses_everything_else_with_its_problem() {
        use IdProblem::*;
        let id = a();
        let body = id.base32();
        let (head, tail) = body.split_at(8);
        let zero = format!("{}0{}", &body[..20], &body[21..]);
        let padded = format!("tornect://{body}{}", " ".repeat(MAX_LINK + 1 - 66));
        assert_eq!(padded.len(), MAX_LINK + 1);
        let cases: Vec<(String, IdProblem)> = vec![
            (format!("tornect://{body}?x=1"), LinkExtras),
            (format!("tornect://{body}#f"), LinkExtras),
            (format!("tornect://user@{body}"), LinkExtras),
            (format!("tornect://{body}:443"), LinkExtras),
            (format!("tornect://%41{}", &body[1..]), LinkExtras),
            (format!("tornect://{body}/extra"), LinkExtras),
            (format!("tornect:///{body}"), LinkExtras),
            (format!("tornect://{body}//"), LinkExtras),
            (format!("tornect://{body}.onion.onion"), LinkExtras),
            (format!("tornect://{head} {tail}"), LinkExtras),
            (format!("tornect://{head}-{tail}"), LinkExtras),
            (format!("tornect://{head}\u{a0}{tail}"), LinkExtras),
            (padded, LinkExtras),
            (format!("http://{body}"), NotALink),
            (format!("https://{body}.onion/"), NotALink),
            (format!("tornect//{body}"), NotALink),
            (format!("{body}.onion"), NotALink),
            ("tornect".to_owned(), NotALink),
            (String::new(), NotALink),
            (format!("tornect://{zero}"), NeverDigit),
            (format!("tornect://{}", checksum_typo(&id)), Checksum),
            (format!("tornect://{}", version_2(&id)), Version),
            (format!("tornect://{}", not_a_key().base32()), NotAKey),
            (format!("tornect://{}", &body[..55]), Short { found: 55 }),
            (format!("tornect://{body}a"), Long { found: 57 }),
            ("tornect:".to_owned(), Short { found: 0 }),
            (format!("tornect://{body}!"), NotAlphabet(Some('!'))),
            (format!("tornect://{body}é"), NotAlphabet(None)),
            (format!("tornect://{head}\u{200b}{tail}"), NotAlphabet(None)),
            (format!("tornect://{head}\u{202e}{tail}"), NotAlphabet(None)),
            (format!("tornect://{body}\0"), NotAlphabet(None)),
            ("tornect:x€onion".to_owned(), NotAlphabet(None)),
            ("tornect:€.onion".to_owned(), NotAlphabet(None)),
        ];
        for (input, problem) in cases {
            assert_eq!(parse_link(&input), Err(problem), "{input:?}");
        }
    }

    /// The size bound comes first: an over-long input is refused as a link with
    /// extras before trimming, so a padded valid link is refused too.
    #[test]
    fn parse_link_bounds_its_input_before_any_work() {
        let body = a().base32();
        let fits = format!("{}tornect://{body}", " ".repeat(MAX_LINK - 66));
        assert_eq!(fits.len(), MAX_LINK);
        assert_eq!(parse_link(&fits), Ok(a()));
        assert_eq!(parse_link(&format!(" {fits}")), Err(IdProblem::LinkExtras));
        assert_eq!(parse_link(&"€".repeat(1000)), Err(IdProblem::LinkExtras));
    }

    #[test]
    fn find_id_reads_a_typed_id_in_every_written_form() {
        let id = a();
        let body = id.base32();
        let groups = id.display_groups();
        for input in [
            body.clone(),
            body.to_ascii_uppercase(),
            format!("{body}.onion"),
            format!("{body}.ONION"),
            groups.clone(),
            groups.replace(' ', "-"),
            groups.replace(' ', "\u{a0}"),
            format!("  {groups}\n"),
            format!("{groups}.onion"),
            format!("{}\n{}", &body[..28], &body[28..]),
        ] {
            assert_eq!(find_id(&input), typed(id, false), "{input:?}");
        }
    }

    #[test]
    fn find_id_names_each_problem_of_a_typed_id() {
        use IdProblem::*;
        let id = a();
        let body = id.base32();
        let groups = id.display_groups();
        let cases: Vec<(String, IdProblem)> = vec![
            (String::new(), Empty),
            (" \t\n ".to_owned(), Empty),
            ("\u{200b}\u{feff}".to_owned(), Empty),
            ("abc".to_owned(), Short { found: 3 }),
            (groups[..30].to_owned(), Short { found: 27 }),
            (format!("{body}a"), Long { found: 57 }),
            (format!("{groups}abcd"), Long { found: 60 }),
            (format!("{}0{}", &body[..5], &body[6..]), NeverDigit),
            (format!("{}8", &body[..10]), NeverDigit),
            (format!("{body}$"), NotAlphabet(Some('$'))),
            (
                format!("{}.{}", &body[..10], &body[11..]),
                NotAlphabet(Some('.')),
            ),
            (
                format!("{}é{}", &body[..10], &body[11..]),
                NotAlphabet(None),
            ),
            (format!("{body}.onion.onion"), NotAlphabet(Some('.'))),
            ("x€onion".to_owned(), NotAlphabet(None)),
            ("€.onion".to_owned(), NotAlphabet(None)),
            ("tornect€x".to_owned(), NotAlphabet(None)),
            ("abcde€".to_owned(), NotAlphabet(None)),
            (version_2(&id), Version),
            (checksum_typo(&id), Checksum),
            (not_a_key().display_groups(), NotAKey),
        ];
        for (input, problem) in cases {
            assert_eq!(find_id(&input), Err(problem), "{input:?}");
        }
    }

    #[test]
    fn find_id_reads_one_link() {
        use IdProblem::*;
        let id = a();
        let body = id.base32();
        assert_eq!(find_id(&link(&id)), linked(id));
        assert_eq!(find_id(&format!(" TORNECT:{body}.onion/ ")), linked(id));
        assert_eq!(find_id(&format!("tornect://{body}?x=1")), Err(LinkExtras));
        assert_eq!(find_id(&format!("tornect://{body}.")), Err(LinkExtras));
        assert_eq!(find_id("tornect:"), Err(Short { found: 0 }));
        assert_eq!(
            find_id(&format!("tornect://{}", checksum_typo(&id))),
            Err(Checksum)
        );
    }

    #[test]
    fn find_id_takes_the_id_out_of_an_invitation_or_a_sentence() {
        let id = a();
        let body = id.base32();
        let groups = id.display_groups();
        for input in [
            invitation(&id),
            invitation(&id).replace('\n', "\r\n"),
            format!("my id {body}"),
            format!("My ID is {body}.onion, see you"),
            format!("here: {groups}. Thanks!"),
            format!("“{body}”"),
            format!("(tornect://{body})"),
            format!("Click <tornect://{body}> or type {groups}"),
            format!("{body} and again {body}.onion and {}", link(&id)),
            format!("abcdefgh {groups} abcdefgh"),
            format!("{groups} abcd"),
            format!("{body}!"),
        ] {
            assert_eq!(find_id(&input), text(id), "{input:?}");
        }
    }

    /// The whole text of a sentence long enough to leave the typed reading: its
    /// problem is the first broken candidate's, or that there is none.
    #[test]
    fn find_id_says_why_a_text_holds_no_id() {
        use IdProblem::*;
        let id = a();
        let filler = "please connect to this one when you have a moment";
        assert_eq!(find_id(filler), Err(NoId));
        assert_eq!(find_id("see https://example.org/x"), Err(NoId));
        assert_eq!(
            find_id(&format!("{filler} {}", checksum_typo(&id))),
            Err(Checksum)
        );
        assert_eq!(
            find_id(&format!(
                "{filler} {} {}",
                version_2(&id),
                checksum_typo(&id)
            )),
            Err(Version)
        );
        assert_eq!(
            find_id(&format!("{filler}: {}", not_a_key().display_groups())),
            Err(NotAKey)
        );
        // Few tokens and no URL: the typed reading's problem wins.
        assert_eq!(
            find_id(&format!("my id {}", checksum_typo(&id))),
            Err(Long { found: 60 })
        );
    }

    #[test]
    fn find_id_refuses_a_text_with_two_ids_or_a_broken_link() {
        use IdProblem::*;
        let (ida, idb) = (a(), b());
        let mismatched = invitation(&ida).replace(&link(&ida), &link(&idb));
        assert_eq!(find_id(&mismatched), Err(Several));
        assert_eq!(
            find_id(&format!("{} or {}", ida.base32(), idb.display_groups())),
            Err(Several)
        );
        let broken = invitation(&ida).replace(&link(&ida), &format!("{}?x=1", link(&ida)));
        assert_eq!(find_id(&broken), Err(LinkExtras));
        let broken = invitation(&ida).replace(&link(&ida), &format!("{}/x", link(&ida)));
        assert_eq!(find_id(&broken), Err(LinkExtras));
        let foreign = invitation(&ida).replace(&link(&ida), "tornect://abc");
        assert_eq!(find_id(&foreign), Err(Short { found: 3 }));
    }

    #[test]
    fn find_id_removes_invisible_characters_and_never_bidi_controls() {
        let id = a();
        let body = id.base32();
        let (head, tail) = body.split_at(20);
        for c in INVISIBLE {
            let input = format!("{head}{c}{tail}");
            assert_eq!(find_id(&input), typed(id, true), "{c:?}");
            assert!(find_id(&input).unwrap().rewrite());
            let input = format!("tornect://{head}{c}{tail}");
            let found = find_id(&input).unwrap();
            assert_eq!(
                (found.id, found.source, found.stripped),
                (id, Source::Link, true)
            );
            assert_eq!(parse_link(&input), Err(IdProblem::NotAlphabet(None)));
        }
        for c in [
            '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            assert_eq!(
                find_id(&format!("{head}{c}{tail}")),
                Err(IdProblem::NotAlphabet(None)),
                "{c:?}"
            );
        }
    }

    #[test]
    fn find_id_bounds_its_input_before_any_work() {
        let id = a();
        let groups = id.display_groups();
        let fits = format!("{groups}{}", " ".repeat(MAX_TEXT - groups.len()));
        assert_eq!(fits.len(), MAX_TEXT);
        assert_eq!(find_id(&fits), typed(id, false));
        assert_eq!(find_id(&format!("{fits} ")), Err(IdProblem::TooLong));
        assert_eq!(find_id(&"a".repeat(MAX_TEXT + 1)), Err(IdProblem::TooLong));
        assert_eq!(find_id(&"\u{200b}".repeat(1366)), Err(IdProblem::TooLong));
    }

    #[test]
    fn rewrite_is_for_links_texts_and_stripped_characters() {
        let found = |source, stripped| Found {
            id: a(),
            source,
            stripped,
        };
        assert!(!found(Source::Typed, false).rewrite());
        assert!(found(Source::Typed, true).rewrite());
        assert!(found(Source::Link, false).rewrite());
        assert!(found(Source::Text, false).rewrite());
    }

    #[test]
    fn the_invitation_is_the_designed_text() {
        let id = a();
        let expected = format!(
            "Connect to my computer with Tornect.\n\
             \n\
             My Tornect ID: {}\n\
             Link: tornect://{}\n\
             \n\
             No Tornect yet? Get it for Linux or Windows: \
             https://github.com/Mxrider007/Tornect/releases\n\
             The first time you connect, both screens show a 6-digit code: go on only if \
             they match.",
            id.display_groups(),
            id.base32(),
        );
        assert_eq!(invitation(&id), expected);
        assert_eq!(invitation(&id).lines().count(), 7);
        assert!(!invitation(&id).contains('\r'));
    }
}
