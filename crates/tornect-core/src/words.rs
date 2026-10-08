//! Device words: the names people read (`docs/PLAN.md` §B.6.1, decision
//! M1-63).
//!
//! A 32-byte public key — an onion address's key (role [`Role::Onion`]) or a
//! client device's key ([`Role::Device`]) — is stretched with Argon2id into
//! `h` ([`Stretched`], 8 bytes):
//!
//! `h = Argon2id(password = key32, salt = "tornect/v1/words/" || role,
//! m = 64 MiB, t = 1, p = 1, version 0x13, 8-byte output)`
//!
//! The first 44 bits of `h` (big-endian) are four 11-bit indices into the
//! BIP39 English list ([`Words`], shown `arctic · crisp · lamp · orbit`);
//! the identicon is drawn from `h` too ([`Identicon`]). The parameters are
//! **frozen** (the operator's ruling of 2026-09-27): every client, on every
//! platform, must reproduce the committed golden vectors
//! (`data/words-golden-vectors.tsv`), and a change after the first release
//! needs a new salt.
//!
//! **Recognition only.** Words never authenticate anything: no lookup, pin,
//! grant, saved-name display or connect is keyed on them, on `h`, on the
//! identicon or on a part of an address (W-B1); a saved name is shown only
//! when all 32 bytes of a key equal a pinned key. They are a stable pseudonym
//! of the key, so they are never sent, never logged, never put in a window
//! title, a notification or a diagnostic (W-B4): [`Stretched`], [`Words`]
//! and [`Identicon`] print as `<redacted>` in `Debug` and have no `Display`.
//!
//! **Cost.** One derivation fills 64 MiB and takes a noticeable fraction of
//! a second, so the process runs one at a time, and a key nobody saved (a
//! pairing request's) is derived only through a [`Pacer`]: at most one per
//! second, for the sheet on screen, after the pairing rate limiter admitted
//! the request (W-B5).
//!
//! [`look_alike`] is the machine-run alarm: an unpinned key whose words,
//! identicon or declared name come close to a saved entry's (§B.6.1 item 4).

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use unicode_normalization::UnicodeNormalization as _;
use unicode_normalization::char::is_combining_mark;

/// The salt's prefix; the role's name follows it.
pub const SALT_PREFIX: &str = "tornect/v1/words/";
/// Argon2id memory, in KiB: 64 MiB (frozen).
pub const MEMORY_KIB: u32 = 64 * 1024;
/// Argon2id passes (frozen).
pub const PASSES: u32 = 1;
/// Argon2id lanes (frozen).
pub const LANES: u32 = 1;
/// Length of `h`, in bytes (frozen).
pub const H_LEN: usize = 8;
/// Words shown per key.
pub const WORDS: usize = 4;
/// Bits of `h` per word: a BIP39 index.
pub const BITS_PER_WORD: u32 = 11;
/// SHA-256 of the embedded BIP39 English list (`bitcoin/bips`,
/// `bip-0039/english.txt`; `packaging/licenses/SOURCES.md`).
pub const WORDLIST_SHA256: &str =
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
/// How many colours an identicon picks from (the window's palette has as
/// many).
pub const IDENTICON_COLOURS: usize = 8;
/// A [`Pacer`] starts at most one derivation per this long.
pub const UNKNOWN_EVERY: Duration = Duration::from_secs(1);

/// The BIP39 English list, 2048 words, one per line.
const LIST: &str = include_str!("../data/bip39-english.txt");

/// The 2048 words, in list order.
#[must_use]
pub fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| LIST.lines().collect())
}

/// Whose key it is: the salt differs, so one key gives different words in
/// each role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// An onion address's key (a host's Tornect ID).
    Onion,
    /// A client device's key (what a host's sheet names).
    Device,
}

impl Role {
    /// The role's name, as the salt and the cache spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Onion => "onion",
            Self::Device => "device",
        }
    }

    /// The role named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "onion" => Some(Self::Onion),
            "device" => Some(Self::Device),
            _ => None,
        }
    }
}

/// `h`: a key stretched for its words and its identicon.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Stretched([u8; H_LEN]);

impl fmt::Debug for Stretched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Stretched(<redacted>)")
    }
}

impl Stretched {
    /// The four words: the first 44 bits of `h`, big-endian, as 11-bit
    /// indices into the list.
    #[must_use]
    pub fn words(&self) -> Words {
        let n = u64::from_be_bytes(self.0);
        let mut indices = [0u16; WORDS];
        for (i, index) in indices.iter_mut().enumerate() {
            let shift = 64 - BITS_PER_WORD * (i as u32 + 1);
            *index = ((n >> shift) & 0x7ff) as u16;
        }
        Words(indices)
    }

    /// The identicon: drawn from the last three bytes of `h`.
    #[must_use]
    pub fn identicon(&self) -> Identicon {
        Identicon([self.0[5], self.0[6], self.0[7]])
    }

    /// `h` in hexadecimal (the golden vectors).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Four words from the BIP39 English list: recognition only.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Words([u16; WORDS]);

impl fmt::Debug for Words {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Words(<redacted>)")
    }
}

impl Words {
    /// The words, in order.
    #[must_use]
    pub fn get(&self) -> [&'static str; WORDS] {
        let list = wordlist();
        self.0.map(|i| list[usize::from(i)])
    }

    /// As a sheet shows them: `arctic · crisp · lamp · orbit`.
    #[must_use]
    pub fn shown(&self) -> String {
        self.get().join(" · ")
    }

    /// As the address book's cache keeps them: `arctic crisp lamp orbit`.
    #[must_use]
    pub fn cached(&self) -> String {
        self.get().join(" ")
    }

    /// Words read back from [`Words::cached`]: exactly four words of the
    /// list, one space apart.
    #[must_use]
    pub fn from_cached(text: &str) -> Option<Self> {
        let list = wordlist();
        let mut indices = [0u16; WORDS];
        let mut parts = text.split(' ');
        for index in &mut indices {
            let word = parts.next()?;
            let at = list.binary_search(&word).ok()?;
            *index = u16::try_from(at).ok()?;
        }
        parts.next().is_none().then_some(Self(indices))
    }
}

/// An identicon: a 5 × 5 grid mirrored left to right (15 cells) and a
/// colour, drawn from `h`. Shown only next to a saved name, never beside an
/// unpinned key (W-B8).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Identicon([u8; 3]);

impl fmt::Debug for Identicon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Identicon(<redacted>)")
    }
}

impl Identicon {
    /// An identicon from its three bytes: cell `i` (row-major over the three
    /// left columns) is bit `i % 8` of byte `i / 8`, the colour is the third
    /// byte modulo [`IDENTICON_COLOURS`].
    #[must_use]
    pub const fn from_seed(seed: [u8; 3]) -> Self {
        Self(seed)
    }

    /// The three bytes it is drawn from.
    #[must_use]
    pub const fn seed(&self) -> [u8; 3] {
        self.0
    }

    /// What a person sees: the 15 cells as bits, and the colour's index.
    #[must_use]
    pub fn picture(&self) -> (u16, usize) {
        let cells = u16::from_le_bytes([self.0[0], self.0[1]]) & 0x7fff;
        (cells, usize::from(self.0[2]) % IDENTICON_COLOURS)
    }
}

/// One derivation at a time in this process: each fills 64 MiB.
static DERIVING: Mutex<()> = Mutex::new(());

/// Stretch `key` in `role` (Argon2id at the frozen parameters). Slow and
/// memory-hungry: call it off the network task; for a key nobody saved,
/// only through a [`Pacer`].
#[must_use]
pub fn derive(key: &[u8; 32], role: Role) -> Stretched {
    let _one = DERIVING.lock().unwrap_or_else(PoisonError::into_inner);
    let params = Params::new(MEMORY_KIB, PASSES, LANES, Some(H_LEN))
        .expect("the frozen parameters are valid Argon2 parameters");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = format!("{SALT_PREFIX}{}", role.as_str());
    let mut h = [0u8; H_LEN];
    argon
        .hash_password_into(key, salt.as_bytes(), &mut h)
        .expect("a 32-byte password, a long salt and an 8-byte output are accepted");
    Stretched(h)
}

/// The derivations of keys this computer saved (its own, its address book's,
/// its paired devices'), kept for the process's lifetime: each is derived
/// once.
#[derive(Default)]
pub struct Known {
    derived: Mutex<HashMap<(Role, [u8; 32]), Stretched>>,
}

impl fmt::Debug for Known {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Known").finish_non_exhaustive()
    }
}

impl Known {
    /// `key`'s stretch in `role`, derived now if it was not yet (blocks).
    #[must_use]
    pub fn get(&self, key: &[u8; 32], role: Role) -> Stretched {
        if let Some(found) = self.cached(key, role) {
            return found;
        }
        let derived = derive(key, role);
        self.remember(key, role, derived);
        derived
    }

    /// `key`'s stretch in `role`, if it was derived already.
    #[must_use]
    pub fn cached(&self, key: &[u8; 32], role: Role) -> Option<Stretched> {
        self.derived
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(role, *key))
            .copied()
    }

    /// Keep `stretched` as `key`'s in `role`.
    pub fn remember(&self, key: &[u8; 32], role: Role, stretched: Stretched) {
        self.derived
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((role, *key), stretched);
    }
}

/// The bound on deriving keys nobody saved (W-B5): one derivation at a time,
/// each starting at least [`UNKNOWN_EVERY`] after the one before. A host has
/// one, used only for the sheet about to be shown.
#[derive(Debug, Default)]
pub struct Pacer {
    last: Mutex<Option<Instant>>,
    runs: AtomicU64,
}

impl Pacer {
    /// A pacer that has run nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `work` once the previous run started [`UNKNOWN_EVERY`] ago, and
    /// never beside another run of this pacer (blocks meanwhile).
    pub fn run<T>(&self, work: impl FnOnce() -> T) -> T {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        wait_after(*last);
        *last = Some(Instant::now());
        self.runs.fetch_add(1, Ordering::Relaxed);
        work()
    }

    /// Run `work` as [`Self::run`] does, unless `gone` is set by the time its
    /// turn comes: the request it was queued for was withdrawn or timed out
    /// while it waited, so nothing is derived for a sheet that will never be
    /// shown (`None`). Checked once the lock is held and again after the
    /// wait, before `work` starts; a run already started finishes.
    pub fn run_unless<T>(&self, gone: &AtomicBool, work: impl FnOnce() -> T) -> Option<T> {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if gone.load(Ordering::Acquire) {
            return None;
        }
        wait_after(*last);
        if gone.load(Ordering::Acquire) {
            return None;
        }
        *last = Some(Instant::now());
        self.runs.fetch_add(1, Ordering::Relaxed);
        Some(work())
    }

    /// How many runs this pacer has started.
    #[must_use]
    pub fn runs(&self) -> u64 {
        self.runs.load(Ordering::Relaxed)
    }

    /// Stretch a key nobody saved, paced (blocks).
    #[must_use]
    pub fn derive(&self, key: &[u8; 32], role: Role) -> Stretched {
        self.run(|| derive(key, role))
    }

    /// Stretch a key nobody saved, paced, unless `gone` is set before its
    /// turn comes ([`Self::run_unless`]; blocks).
    #[must_use]
    pub fn derive_unless(
        &self,
        gone: &AtomicBool,
        key: &[u8; 32],
        role: Role,
    ) -> Option<Stretched> {
        self.run_unless(gone, || derive(key, role))
    }
}

/// Sleep until [`UNKNOWN_EVERY`] has passed since `last` started.
fn wait_after(last: Option<Instant>) {
    if let Some(at) = last {
        let wait = UNKNOWN_EVERY.saturating_sub(at.elapsed());
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
    }
}

/// A saved entry the alarm compares an unpinned key with: its name (a saved
/// name, a pinned label, or this computer's own), its words and identicon.
#[derive(Clone, PartialEq, Eq)]
pub struct Saved {
    /// The name people know it by.
    pub name: String,
    /// Its words.
    pub words: Words,
    /// Its identicon.
    pub identicon: Identicon,
}

impl fmt::Debug for Saved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Saved").finish_non_exhaustive()
    }
}

/// Why an unpinned key looks like a saved one (§B.6.1 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Likeness {
    /// Its first word is the saved entry's first word.
    FirstWord,
    /// Two or more of its four words are the saved entry's, in any position.
    SharedWords,
    /// Its identicon is the saved entry's.
    SameIdenticon,
    /// The name it declared reads like the saved name ([`skeleton`]).
    DeclaredName,
    /// One of its words is a word of the saved name (case-folded).
    WordOfTheName,
    /// The name it declared holds a word of the saved entry's words
    /// (case-folded, or by skeleton): words put where a name goes.
    DeclaredWords,
}

/// The key the alarm looks at: an unpinned key's words and identicon, and
/// the name it declared, if any.
#[derive(Clone, Copy)]
pub struct Candidate<'a> {
    /// Its words.
    pub words: Words,
    /// Its identicon.
    pub identicon: Identicon,
    /// The name it declared (a pairing request's), if any.
    pub declared: Option<&'a str>,
}

impl fmt::Debug for Candidate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate").finish_non_exhaustive()
    }
}

/// The look-alike alarm: the first saved entry (its index in `saved`) the
/// unpinned key `candidate` comes close to, and why. It fires on the same
/// first word; two or more shared words in any position; the same
/// identicon; a declared name whose [`skeleton`] equals a saved name's; a
/// word equal to a word of a saved name (case-folded, or by skeleton); a
/// declared name that holds a word of a saved entry's words; or a declared
/// name whose skeleton holds a saved name's (of three characters or more)
/// with anything before or after it ("Office PC 2", "My Office PC"). An
/// entry known by several names is passed once per name.
#[must_use]
pub fn look_alike(candidate: &Candidate<'_>, saved: &[Saved]) -> Option<(usize, Likeness)> {
    let words = candidate.words.get();
    let declared = candidate.declared.map(skeleton).filter(|s| !s.is_empty());
    saved.iter().enumerate().find_map(|(at, entry)| {
        let theirs = entry.words.get();
        let likeness = if words[0] == theirs[0] {
            Some(Likeness::FirstWord)
        } else if shared(&words, &theirs) >= 2 {
            Some(Likeness::SharedWords)
        } else if candidate.identicon.picture() == entry.identicon.picture() {
            Some(Likeness::SameIdenticon)
        } else if declared
            .as_deref()
            .is_some_and(|d| d == skeleton(&entry.name))
        {
            Some(Likeness::DeclaredName)
        } else if word_of_the_name(&words, &entry.name) {
            Some(Likeness::WordOfTheName)
        } else if candidate
            .declared
            .is_some_and(|d| word_of_the_name(&theirs, d))
        {
            Some(Likeness::DeclaredWords)
        } else if declared
            .as_deref()
            .is_some_and(|d| holds_the_name(d, &skeleton(&entry.name)))
        {
            Some(Likeness::DeclaredName)
        } else {
            None
        };
        likeness.map(|l| (at, l))
    })
}

/// How many of `a`'s words are among `b`'s (each of `b`'s counted once).
fn shared(a: &[&str; WORDS], b: &[&str; WORDS]) -> usize {
    let mut left: Vec<&str> = b.to_vec();
    a.iter()
        .filter(|w| {
            left.iter()
                .position(|x| x == *w)
                .map(|at| left.swap_remove(at))
                .is_some()
        })
        .count()
}

/// Whether one of `words` is a word of `name`: case-folded, or by skeleton.
fn word_of_the_name(words: &[&str; WORDS], name: &str) -> bool {
    let folded = name.to_lowercase();
    folded
        .split(|c: char| !c.is_alphanumeric())
        .filter(|part| !part.is_empty())
        .any(|part| {
            let part_skeleton = skeleton(part);
            words
                .iter()
                .any(|w| *w == part || skeleton(w) == part_skeleton)
        })
}

/// Whether the skeleton of a declared name holds a saved name's skeleton
/// with anything before or after it: the saved name with a number, a word or
/// a mark added. Saved skeletons shorter than three characters never match
/// this way (they would match too much).
fn holds_the_name(declared: &str, saved: &str) -> bool {
    saved.chars().count() >= 3 && declared.contains(saved)
}

/// The [`skeleton`] of every word of the list, computed once.
fn list_skeletons() -> &'static std::collections::HashSet<String> {
    static SKELETONS: OnceLock<std::collections::HashSet<String>> = OnceLock::new();
    SKELETONS.get_or_init(|| wordlist().iter().map(|w| skeleton(w)).collect())
}

/// How many words of the list a label may not hold (M-UI-3 F-3): three of a
/// device's four words already read as its words in the name slot.
pub const LABEL_LIST_WORDS: usize = 3;

/// The quotation marks a label may not hold ([`label_refusal`]): a sheet
/// quotes a name between them, and one inside the name could close the
/// quote early. A sheet strips them from a name it quotes.
pub const QUOTATION_MARKS: [char; 5] = ['"', '\u{201c}', '\u{201d}', '\u{201e}', '\u{ff02}'];

/// The middle dots a label may not hold ([`label_refusal`]): they could
/// imitate a sheet's own separators. A sheet strips them from a name it
/// quotes.
pub const MIDDLE_DOTS: [char; 6] = ['·', '•', '∙', '⋅', '\u{2027}', '\u{30fb}'];

/// Why `label` may not be pinned as a device's or a computer's name, if it
/// may not (§B.6.1 item 7: a label never puts words in the name slot, and
/// never imitates a sheet's own lines): it holds a quotation mark or a
/// middle dot, or it reads as device words — it holds
/// [`LABEL_LIST_WORDS`] or more words of the list (case-folded, or by
/// [`skeleton`]), however they are separated, whatever else it holds (a
/// number after them, a word before them). A label pinned before this rule
/// is not checked again when a sheet shows it.
#[must_use]
pub fn label_refusal(label: &str) -> Option<&'static str> {
    if label.contains(QUOTATION_MARKS) {
        return Some("it holds a quotation mark");
    }
    if label.contains(MIDDLE_DOTS) {
        return Some("it holds a middle dot");
    }
    let list = wordlist();
    let listed =
        |part: &str| list.contains(&part) || list_skeletons().contains(skeleton(part).as_str());
    let folded = label.to_lowercase();
    let parts: Vec<&str> = folded
        .split(|c: char| !c.is_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect();
    if parts.iter().filter(|part| listed(part)).count() >= LABEL_LIST_WORDS {
        return Some("three of its words are device words");
    }
    None
}

/// Whether two Tornect IDs (base32, 56 characters) share their first or their
/// last four characters: the client's connect field warns about such a
/// pasted ID (§B.6.1 item 4; people compare the ends).
#[must_use]
pub fn ends_look_alike(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() >= 4 && b.len() >= 4 && (a[..4] == b[..4] || a[a.len() - 4..] == b[b.len() - 4..])
}

/// A name's confusable form, for comparing names people read: compatibility
/// decomposition (full-width and mathematical letters become plain ones),
/// accents and other combining marks dropped, lower case, the common
/// Cyrillic and Greek look-alikes of Latin letters and the digits and marks
/// that pass for letters mapped to those letters, `rn` read as `m` and `vv` as
/// `w`, spaces and separators dropped.
///
/// A subset of Unicode's skeleton (UTS #39): the full confusables table is
/// in no crate this build uses, so whole-script look-alikes outside the
/// letters mapped here are not caught.
#[must_use]
pub fn skeleton(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.nfkd() {
        if is_combining_mark(c) {
            continue;
        }
        for lower in c.to_lowercase() {
            if lower.is_whitespace() || matches!(lower, '-' | '_' | '.' | '·' | '\'' | '’') {
                continue;
            }
            match confusable(lower) {
                Some(latin) => out.push_str(latin),
                None => out.push(lower),
            }
        }
    }
    out.replace("rn", "m").replace("vv", "w")
}

/// The Latin letters a lower-cased character passes for.
fn confusable(c: char) -> Option<&'static str> {
    Some(match c {
        // Cyrillic.
        'а' => "a",
        'в' => "b",
        'ь' => "b",
        'с' => "c",
        'ԁ' => "d",
        'е' | 'ё' => "e",
        'һ' | 'н' => "h",
        'і' | 'ї' | 'ӏ' => "l",
        'ј' => "j",
        'к' => "k",
        'м' => "m",
        'п' => "n",
        'о' => "o",
        'р' => "p",
        'ԛ' => "q",
        'г' => "r",
        'ѕ' => "s",
        'т' => "t",
        'ц' | 'џ' => "u",
        'ѵ' => "v",
        'ԝ' | 'ш' => "w",
        'х' => "x",
        'у' | 'ү' => "y",
        'з' => "3",
        // Greek.
        'α' => "a",
        'β' => "b",
        'ε' => "e",
        'ζ' => "z",
        'η' => "h",
        'ι' | 'ί' => "l",
        'κ' => "k",
        'μ' => "m",
        'ν' => "v",
        'ο' | 'ό' => "o",
        'ρ' => "p",
        'τ' => "t",
        'υ' => "y",
        'χ' => "x",
        'γ' => "y",
        'ω' => "w",
        // Latin that passes for other Latin, digits and marks.
        'ı' | 'ɩ' | 'i' | '1' | '|' | '!' => "l",
        'ɡ' => "g",
        'ß' => "ss",
        'æ' => "ae",
        'œ' => "oe",
        '0' => "o",
        '5' => "s",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    /// The committed golden vectors: `key<TAB>role<TAB>h<TAB>words`.
    const GOLDEN: &str = include_str!("../data/words-golden-vectors.tsv");

    fn key(hex_key: &str) -> [u8; 32] {
        hex::decode(hex_key).unwrap().try_into().unwrap()
    }

    /// The embedded list is BIP39's English list, byte for byte: its SHA-256
    /// is pinned, 2048 words, sorted, unique, lower-case ASCII of 3 to 8
    /// letters whose first four letters tell them apart.
    #[test]
    fn the_list_is_bip39_english() {
        assert_eq!(hex::encode(Sha256::digest(LIST)), WORDLIST_SHA256);
        let list = wordlist();
        assert_eq!(list.len(), 2048);
        assert!(list.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
        assert!(
            list.iter()
                .all(|w| (3..=8).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase()))
        );
        let mut prefixes: Vec<&str> = list.iter().map(|w| &w[..w.len().min(4)]).collect();
        prefixes.dedup();
        assert_eq!(prefixes.len(), 2048, "the first four letters are unique");
    }

    /// The frozen derivation reproduces every committed golden vector: `h`
    /// and the words, for invented keys in both roles (W-B6). Any other
    /// platform must reproduce the same file.
    #[test]
    fn the_golden_vectors_hold() {
        let mut keys = Vec::new();
        let mut roles = Vec::new();
        let mut rows = 0;
        for line in GOLDEN
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let cols: Vec<&str> = line.split('\t').collect();
            assert_eq!(cols.len(), 4, "{line}");
            let (k, role) = (key(cols[0]), Role::parse(cols[1]).unwrap());
            let h = derive(&k, role);
            assert_eq!(h.to_hex(), cols[2], "h of {} as {}", cols[0], cols[1]);
            assert_eq!(h.words().cached(), cols[3], "words of {}", cols[0]);
            assert_eq!(Words::from_cached(cols[3]), Some(h.words()));
            keys.push(k);
            roles.push(role);
            rows += 1;
        }
        keys.sort_unstable();
        keys.dedup();
        assert!(keys.len() >= 4, "at least four keys");
        assert!(roles.contains(&Role::Onion) && roles.contains(&Role::Device));
        assert_eq!(rows, keys.len() * 2, "every key in both roles");
    }

    /// The parameters are the frozen ones (decision M1-63): changing any of
    /// them needs a new salt after the release.
    #[test]
    fn the_parameters_are_the_frozen_ones() {
        assert_eq!(
            (SALT_PREFIX, MEMORY_KIB, PASSES, LANES, H_LEN),
            ("tornect/v1/words/", 65536, 1, 1, 8)
        );
        assert_eq!(WORDS as u32 * BITS_PER_WORD, 44);
        assert!(Params::new(MEMORY_KIB, PASSES, LANES, Some(H_LEN)).is_ok());
    }

    /// One key, two roles, two unrelated sets of words.
    #[test]
    fn the_roles_give_other_words() {
        let k = [7u8; 32];
        let (onion, device) = (derive(&k, Role::Onion), derive(&k, Role::Device));
        assert_ne!(onion, device);
        assert_ne!(onion.words(), device.words());
    }

    /// `Debug` shows none of it: no word, no byte of `h`, no identicon seed.
    #[test]
    fn debug_shows_none_of_it() {
        let h = derive(&[0u8; 32], Role::Onion);
        let text = format!(
            "{h:?} {:?} {:?} {:?}",
            h.words(),
            h.identicon(),
            Saved {
                name: "Office PC".to_owned(),
                words: h.words(),
                identicon: h.identicon(),
            }
        );
        for word in h.words().get() {
            assert!(!text.contains(word), "{text}");
        }
        assert!(!text.contains(&h.to_hex()[..4]), "{text}");
        assert!(!text.contains("Office"), "{text}");
    }

    /// How long one derivation takes on this machine (printed, not
    /// asserted; `cargo test --workspace -- --nocapture derivation_time`).
    #[test]
    #[allow(clippy::print_stderr)]
    fn derivation_time() {
        let started = Instant::now();
        let _ = derive(&[0x42; 32], Role::Device);
        eprintln!(
            "device words: one Argon2id derivation (64 MiB, t = 1, p = 1) took {} ms",
            started.elapsed().as_millis()
        );
    }

    /// W-B5: a pacer never runs two derivations at once, and starts each at
    /// least a second after the one before.
    #[test]
    fn a_pacer_starts_one_derivation_per_second() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let pacer = Arc::new(Pacer::new());
        let busy = Arc::new(AtomicBool::new(false));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let runs: Vec<_> = (0..3)
            .map(|_| {
                let (pacer, busy, starts) =
                    (Arc::clone(&pacer), Arc::clone(&busy), Arc::clone(&starts));
                std::thread::spawn(move || {
                    pacer.run(|| {
                        assert!(!busy.swap(true, Ordering::SeqCst), "two at once");
                        starts.lock().unwrap().push(Instant::now());
                        std::thread::sleep(Duration::from_millis(50));
                        busy.store(false, Ordering::SeqCst);
                    });
                })
            })
            .collect();
        for run in runs {
            run.join().unwrap();
        }
        let mut starts = starts.lock().unwrap().clone();
        starts.sort();
        assert_eq!(starts.len(), 3);
        for pair in starts.windows(2) {
            assert!(
                pair[1] - pair[0] >= UNKNOWN_EVERY,
                "{:?}",
                pair[1] - pair[0]
            );
        }
    }

    /// F-3: a run whose request went away while it queued derives nothing,
    /// and a run already started is not cut short.
    #[test]
    fn a_pacer_skips_a_run_whose_request_is_gone() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let pacer = Arc::new(Pacer::new());
        pacer.run(|| ());
        assert_eq!(pacer.runs(), 1);
        // Queued behind the first run's second, then withdrawn.
        let gone = Arc::new(AtomicBool::new(false));
        let ran = Arc::new(AtomicBool::new(false));
        let queued = {
            let (pacer, gone, ran) = (Arc::clone(&pacer), Arc::clone(&gone), Arc::clone(&ran));
            std::thread::spawn(move || {
                pacer.run_unless(&gone, || ran.store(true, Ordering::SeqCst))
            })
        };
        std::thread::sleep(Duration::from_millis(200));
        gone.store(true, Ordering::Release);
        assert_eq!(queued.join().unwrap(), None);
        assert!(
            !ran.load(Ordering::SeqCst),
            "a withdrawn request's derivation ran"
        );
        assert_eq!(pacer.runs(), 1);
        // Already gone before it queued: nothing waits, nothing runs.
        let started = Instant::now();
        assert_eq!(pacer.derive_unless(&gone, &[7u8; 32], Role::Device), None);
        assert!(started.elapsed() < UNKNOWN_EVERY);
        // Not gone: it runs, a second after the last run that started.
        let kept = AtomicBool::new(false);
        assert_eq!(pacer.run_unless(&kept, || 5), Some(5));
        assert_eq!(pacer.runs(), 2);
    }

    /// Cached words read back only when they are four words of the list.
    #[test]
    fn cached_words_read_back_only_when_whole() {
        let w = derive(&[1u8; 32], Role::Onion).words();
        assert_eq!(Words::from_cached(&w.cached()), Some(w));
        for bad in [
            "",
            "abandon ability able",
            "abandon ability able about above",
            "abandon  ability able about",
            "Abandon ability able about",
            "abandon ability able notaword",
            "abandon-ability-able-about",
        ] {
            assert_eq!(Words::from_cached(bad), None, "{bad}");
        }
    }

    fn words(text: &str) -> Words {
        Words::from_cached(text).unwrap()
    }

    fn saved(name: &str, text: &str, seed: [u8; 3]) -> Saved {
        Saved {
            name: name.to_owned(),
            words: words(text),
            identicon: Identicon::from_seed(seed),
        }
    }

    /// Each rule of the alarm fires on its own, and a key that meets none of
    /// them does not fire it.
    #[test]
    fn the_alarm_fires_on_each_rule_and_only_then() {
        let book = [
            saved("Office PC", "arctic crisp lamp orbit", [1, 2, 3]),
            saved("Laptop", "zone zoo yard wrist", [9, 9, 9]),
        ];
        let calm = words("absurd citizen dinner harvest");
        let look = |w: Words, seed: [u8; 3], declared: Option<&str>| {
            look_alike(
                &Candidate {
                    words: w,
                    identicon: Identicon::from_seed(seed),
                    declared,
                },
                &book,
            )
        };
        // Nothing alike: silent, whatever it calls itself.
        assert_eq!(look(calm, [4, 5, 6], Some("Kitchen")), None);
        assert_eq!(look(calm, [4, 5, 6], None), None);
        // The same first word.
        assert_eq!(
            look(words("arctic citizen dinner harvest"), [4, 5, 6], None),
            Some((0, Likeness::FirstWord))
        );
        // Two shared words, in other positions.
        assert_eq!(
            look(words("absurd orbit lamp harvest"), [4, 5, 6], None),
            Some((0, Likeness::SharedWords))
        );
        // One shared word elsewhere than first is not enough.
        assert_eq!(
            look(words("absurd citizen lamp harvest"), [4, 5, 6], None),
            None
        );
        // The same picture: the same cells and colour (the colour byte
        // modulo the palette).
        assert_eq!(
            look(calm, [9, 9, 9 + IDENTICON_COLOURS as u8], None),
            Some((1, Likeness::SameIdenticon))
        );
        assert_eq!(look(calm, [9, 9, 10], None), None, "another colour");
        // A declared name that reads like a saved one.
        for declared in [
            "Office PC",
            "office-pc",
            "Оffice РС",
            "OFFICE  PC",
            "Offíce PC",
        ] {
            assert_eq!(
                look(calm, [4, 5, 6], Some(declared)),
                Some((0, Likeness::DeclaredName)),
                "{declared}"
            );
        }
        assert_eq!(look(calm, [4, 5, 6], Some("Office Mac")), None);
        // A word of a saved name among its words.
        let named = [saved("Office desk", "zone zoo yard wrist", [9, 9, 9])];
        assert_eq!(
            look_alike(
                &Candidate {
                    words: words("absurd office dinner harvest"),
                    identicon: Identicon::from_seed([4, 5, 6]),
                    declared: None,
                },
                &named,
            ),
            Some((0, Likeness::WordOfTheName))
        );
    }

    /// A declared name that carries a saved entry's words, or a saved name
    /// with something added before or after it, fires the alarm; a declared
    /// name unlike every saved one still does not, and a saved name shorter
    /// than three characters is not matched inside longer names.
    #[test]
    fn a_declared_name_cannot_carry_words_or_a_near_name() {
        let book = [
            saved("Office PC", "arctic crisp lamp orbit", [1, 2, 3]),
            saved("Laptop", "zone zoo yard wrist", [9, 9, 9]),
            saved("PC", "zebra zero yellow youth", [7, 7, 7]),
        ];
        let calm = words("absurd citizen dinner harvest");
        let look = |declared: &str| {
            look_alike(
                &Candidate {
                    words: calm,
                    identicon: Identicon::from_seed([4, 5, 6]),
                    declared: Some(declared),
                },
                &book,
            )
        };
        for declared in ["arctic crisp lamp orbit", "Arctic·Crisp", "lamp", "Zoo"] {
            let at = usize::from(declared.eq_ignore_ascii_case("zoo"));
            assert_eq!(
                look(declared),
                Some((at, Likeness::DeclaredWords)),
                "{declared}"
            );
        }
        for declared in [
            "Office PC 2",
            "Office PC (2)",
            "My Office PC",
            "Office PC new",
            "Office PC,",
            "\"Office PC\"",
        ] {
            assert_eq!(
                look(declared),
                Some((0, Likeness::DeclaredName)),
                "{declared}"
            );
        }
        assert_eq!(look("Old laptop"), Some((1, Likeness::DeclaredName)));
        for calm_name in ["Kitchen", "Office Mac", "Office", "My PC 2"] {
            assert_eq!(look(calm_name), None, "{calm_name}");
        }
    }

    /// A label that holds a quotation mark or a middle dot, or reads as four
    /// words of the list, is refused at pin time; ordinary names pass.
    #[test]
    fn labels_that_would_put_words_in_the_name_slot_are_refused() {
        for (label, why) in [
            (
                "arctic crisp lamp orbit",
                "three of its words are device words",
            ),
            (
                "Arctic-Crisp-Lamp-Orbit",
                "three of its words are device words",
            ),
            (
                "аrctic crisp lamp orbit",
                "three of its words are device words",
            ),
            ("arctic crisp lamp", "three of its words are device words"),
            (
                "arctic crisp lamp orbit zoo",
                "three of its words are device words",
            ),
            ("Ana\" · view only", "it holds a quotation mark"),
            ("Laptop \u{201c}2\u{201d}", "it holds a quotation mark"),
            ("Laptop · 2", "it holds a middle dot"),
        ] {
            assert_eq!(label_refusal(label), Some(why), "{label}");
        }
        for label in [
            "Laptop",
            "Office PC",
            "Family room",
            "arctic crisp",
            "Laptop (2)",
        ] {
            assert_eq!(label_refusal(label), None, "{label}");
        }
    }

    /// Every spelling of `label` a device could declare: as typed, in capitals,
    /// and with a Cyrillic `а` and a zero standing in for letters.
    fn spellings(label: &str) -> [String; 3] {
        [
            label.to_owned(),
            label.to_uppercase(),
            label.replacen('a', "\u{430}", 1).replacen('o', "0", 1),
        ]
    }

    /// M-UI-3 F-3: four device words with a number after them are refused.
    #[test]
    fn four_words_and_a_number_are_refused() {
        for label in spellings("arctic crisp lamp orbit 2") {
            assert_eq!(
                label_refusal(&label),
                Some("three of its words are device words"),
                "{label}"
            );
        }
    }

    /// M-UI-3 F-3: four device words with a count in brackets after them
    /// (the style of a second device's name) are refused.
    #[test]
    fn four_words_and_a_count_are_refused() {
        for label in spellings("arctic crisp lamp orbit (2)") {
            assert_eq!(
                label_refusal(&label),
                Some("three of its words are device words"),
                "{label}"
            );
        }
    }

    /// M-UI-3 F-3: four device words after a word of another kind are
    /// refused.
    #[test]
    fn a_word_and_four_words_are_refused() {
        for label in spellings("my arctic crisp lamp orbit") {
            assert_eq!(
                label_refusal(&label),
                Some("three of its words are device words"),
                "{label}"
            );
        }
    }

    /// M-UI-3 F-3: three device words are refused, alone or among other
    /// words; two pass.
    #[test]
    fn three_words_are_refused() {
        for label in [
            "arctic crisp lamp",
            "arctic-crisp-lamp PC",
            "PC of arctic crisp lamp",
        ] {
            for label in spellings(label) {
                assert_eq!(
                    label_refusal(&label),
                    Some("three of its words are device words"),
                    "{label}"
                );
            }
        }
        for label in spellings("arctic crisp PC") {
            assert_eq!(label_refusal(&label), None, "{label}");
        }
    }

    /// The skeleton reads look-alike letters as the letters they pass for,
    /// and keeps different names apart.
    #[test]
    fn the_skeleton_reads_look_alikes_as_one() {
        let office = skeleton("Office PC");
        for alike in [
            "office pc",
            "Оffice PC",
            "Office РС",
            "Ｏｆｆｉｃｅ ＰＣ",
            "Öffice PC",
            "0ffice PC",
            "Offlce PC",
        ] {
            assert_eq!(skeleton(alike), office, "{alike}");
        }
        assert_eq!(skeleton("modern"), skeleton("rnodern"));
        assert_eq!(skeleton("wolf"), skeleton("vvolf"));
        assert_ne!(skeleton("Office PC"), skeleton("Office Mac"));
        assert_ne!(skeleton("Laptop"), skeleton("Desktop"));
    }

    /// Two IDs whose first or last four characters match look alike at the
    /// ends; others do not.
    #[test]
    fn ids_alike_at_the_ends() {
        let a = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwd";
        assert!(ends_look_alike(
            a,
            &format!("abcd{}", &a[4..].replace('e', "f"))
        ));
        assert!(ends_look_alike(a, &format!("zzzz{}", &a[4..])));
        let other = "zzzzefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuxxx";
        assert!(!ends_look_alike(a, other));
    }
}
