//! The address book (the redesign's §4): the computers this one connects to,
//! with the names the user gave them, in a small private TOML file next to
//! `known-hosts.toml`, on this computer only (`docs/PLAN.md` §B.8.9's rules
//! for local state: `0600`, atomic replace, refused whole when it is wrong).
//!
//! [`AddressBook`] at [`address_book_file`] (`address-book.toml`, schema
//! `version = 1`) holds, per computer: the host key its saved name was given
//! against, the saved name, the name the computer declared when last seen,
//! the first and the last day it was seen, and a `later` table for what
//! arrives with the spec amendment; and whether history is kept.
//!
//! It holds no secret: no private key, no password, no credential. A
//! `later.credential_ref` may only name the OS keychain entry that would hold
//! a remembered password (`tornect/unattended/<onion>`), never a password.
//!
//! **Next to `known-hosts.toml`, not wrapping it.** The pin stays where the
//! pairing code keeps it: `known-hosts.toml` is written when a computer is
//! paired or forgotten, and a refused or damaged address book never makes this
//! computer forget a pin. The address book only names pinned computers: a
//! saved name applies while the key it was given against equals, in full, the
//! host key pinned in `known-hosts.toml` ([`Entry::name_for`]); after a re-pair
//! with another key it is not shown until the computer is named again. The
//! consent questions never show it: they show the pinned label.
//!
//! **Days, never times** ([`Day`], UTC): all the precision history keeps.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{CoreError, Result};
use crate::id::TornectId;
use crate::keystore::{create_private_dir, write_private_file};
use crate::paths::Paths;
use crate::trusted;

/// The schema version this build reads and writes.
pub const VERSION: u32 = 1;

/// Most characters of the device words.
pub const MAX_WORDS_CHARS: usize = 160;

/// What a credential reference starts with: the OS keychain entry of a
/// remembered unattended password is `tornect/unattended/<onion>`
/// (`docs/PLAN.md` §B.8.9).
pub const CREDENTIAL_PREFIX: &str = "tornect/unattended/";

/// Where the address book lives: `<state>/address-book.toml`, next to
/// `known-hosts.toml`.
#[must_use]
pub fn address_book_file(paths: &Paths) -> PathBuf {
    paths.state_dir.join("address-book.toml")
}

/// A calendar day in UTC: all the precision the address book keeps of when
/// something happened. Written `YYYY-MM-DD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Day(i64);

impl Day {
    /// The day that many days after 1970-01-01.
    #[must_use]
    pub const fn from_days(days: i64) -> Self {
        Self(days)
    }

    /// The day of a Unix time.
    #[must_use]
    pub const fn from_unix(secs: u64) -> Self {
        // u64 seconds / 86 400 is below 2^48: it fits.
        Self((secs / 86_400) as i64)
    }

    /// Today (UTC).
    #[must_use]
    pub fn today() -> Self {
        Self::from_unix(trusted::unix_now())
    }

    /// Days since 1970-01-01.
    #[must_use]
    pub const fn days(self) -> i64 {
        self.0
    }

    /// The day `year`-`month`-`day` of the proleptic Gregorian calendar, if it
    /// exists (years 1970 to 9999).
    #[must_use]
    pub fn from_ymd(year: i64, month: u32, day: u32) -> Option<Self> {
        if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) || day == 0 {
            return None;
        }
        // Howard Hinnant's days_from_civil.
        let y = if month <= 2 { year - 1 } else { year };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let m = i64::from(month);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let found = Self(era * 146_097 + doe - 719_468);
        // A day past the month's end lands in the next month.
        (found.ymd() == (year, month, day)).then_some(found)
    }

    /// Year, month (1–12) and day of the month (1–31).
    #[must_use]
    pub fn ymd(self) -> (i64, u32, u32) {
        // Howard Hinnant's civil_from_days.
        let z = self.0 + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        // Both are in range by construction (1–12, 1–31).
        (
            year,
            u32::try_from(month).unwrap_or(1),
            u32::try_from(day).unwrap_or(1),
        )
    }
}

impl fmt::Display for Day {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, m, d) = self.ymd();
        write!(f, "{y:04}-{m:02}-{d:02}")
    }
}

impl FromStr for Day {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let bad = || format!("{s:?} is not a day (YYYY-MM-DD)");
        let b = s.as_bytes();
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return Err(bad());
        }
        let digits = |r: std::ops::Range<usize>| {
            s.get(r)
                .filter(|p| p.bytes().all(|c| c.is_ascii_digit()))
                .and_then(|p| p.parse::<u32>().ok())
        };
        let (Some(y), Some(m), Some(d)) = (digits(0..4), digits(5..7), digits(8..10)) else {
            return Err(bad());
        };
        Self::from_ymd(i64::from(y), m, d).ok_or_else(bad)
    }
}

impl Serialize for Day {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Day {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// A name for the address book, ready to store: control, bidi and other
/// invisible characters stripped and whitespace collapsed
/// ([`trusted::sanitize_label`], the pinned labels' own rule), at most
/// [`trusted::MAX_LABEL_CHARS`] characters; `None` when nothing visible is left.
/// Look-alike letters are noted ([`mixes_scripts`]), never refused: a saved
/// name is a local convenience, never the trust anchor.
#[must_use]
pub fn clean_name(raw: &str) -> Option<String> {
    raw.chars()
        .any(|c| !c.is_whitespace() && !trusted::is_invisible_or_control(c))
        .then(|| trusted::sanitize_label(raw))
}

/// The alphabets whose letters look alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Greek,
    Cyrillic,
    Armenian,
    Cherokee,
    /// Full-width and mathematical letters: Latin shapes that are not Latin.
    Imitation,
}

fn script(c: char) -> Option<Script> {
    if !c.is_alphabetic() {
        return None;
    }
    match c {
        'A'..='Z' | 'a'..='z' | '\u{00C0}'..='\u{024F}' | '\u{1E00}'..='\u{1EFF}' => {
            Some(Script::Latin)
        }
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Some(Script::Greek),
        '\u{0400}'..='\u{052F}'
        | '\u{1C80}'..='\u{1C8F}'
        | '\u{2DE0}'..='\u{2DFF}'
        | '\u{A640}'..='\u{A69F}' => Some(Script::Cyrillic),
        '\u{0530}'..='\u{058F}' => Some(Script::Armenian),
        '\u{13A0}'..='\u{13FF}' | '\u{AB70}'..='\u{ABBF}' => Some(Script::Cherokee),
        '\u{FF21}'..='\u{FF3A}' | '\u{FF41}'..='\u{FF5A}' | '\u{1D400}'..='\u{1D7FF}' => {
            Some(Script::Imitation)
        }
        _ => None,
    }
}

/// Whether `name` mixes letters of alphabets with look-alike shapes (Latin,
/// Greek, Cyrillic, Armenian, Cherokee), as "Pаypal" with a Cyrillic "а"
/// does, or uses the full-width or mathematical letters that imitate Latin
/// ones. The window notes it beside the name; nothing is refused. A name
/// written wholly in one other alphabet is not caught (that needs Unicode's
/// confusables table).
#[must_use]
pub fn mixes_scripts(name: &str) -> bool {
    let mut first = None;
    for s in name.chars().filter_map(script) {
        if s == Script::Imitation {
            return true;
        }
        match first {
            None => first = Some(s),
            Some(f) if f != s => return true,
            Some(_) => {}
        }
    }
    false
}

/// Fields that arrive with the spec amendment. Only these two exist in
/// schema version 1, and neither can hold a secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Later {
    /// Where a remembered unattended password would be kept: the name of its
    /// OS keychain entry, `tornect/unattended/<onion>` for this computer's
    /// ID. A reference, never the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    /// The ID's pronounceable word form: lower-case words, one space or
    /// hyphen between them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub words: Option<String>,
}

impl Later {
    /// Nothing set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credential_ref.is_none() && self.words.is_none()
    }

    /// Whether the fields are what they must be for the computer `id`.
    fn check(&self, id: &TornectId) -> std::result::Result<(), String> {
        if let Some(reference) = &self.credential_ref
            && *reference != credential_ref(id)
        {
            return Err("later.credential_ref must name this computer's keychain entry".to_owned());
        }
        if let Some(words) = &self.words {
            let shaped = words.len() <= MAX_WORDS_CHARS
                && !words.is_empty()
                && words
                    .split([' ', '-'])
                    .all(|w| !w.is_empty() && w.bytes().all(|c| c.is_ascii_lowercase()));
            if !shaped {
                return Err("later.words must be lower-case words".to_owned());
            }
        }
        Ok(())
    }
}

/// The keychain entry name of the computer `id`'s remembered password: the
/// only value `later.credential_ref` may hold.
#[must_use]
pub fn credential_ref(id: &TornectId) -> String {
    format!("{CREDENTIAL_PREFIX}{}", id.base32())
}

/// One computer in the address book.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The host key its saved name was given against (the host device key
    /// pinned in `known-hosts.toml` then), or none for a computer saved before
    /// it was paired.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex32")]
    pub key: Option<[u8; 32]>,
    /// The name the user gave it: local, never sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The name it declared when last seen: a suggestion; the label pinned in
    /// `known-hosts.toml` stays the trust anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<String>,
    /// The first day a session with it started (history).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<Day>,
    /// The last day a session with it started (history).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<Day>,
    /// Fields that arrive with the spec amendment.
    #[serde(default, skip_serializing_if = "Later::is_empty")]
    pub later: Later,
}

impl Entry {
    /// The saved name, if it applies to the computer as it is pinned now:
    /// the key it was given against equals `pinned` in full, or neither
    /// exists (saved before pairing, not paired yet).
    #[must_use]
    pub fn name_for(&self, pinned: Option<&[u8; 32]>) -> Option<&str> {
        if self.key.as_ref() == pinned {
            self.name.as_deref()
        } else {
            None
        }
    }

    fn check(&self, id: &TornectId) -> std::result::Result<(), String> {
        for (what, text) in [("name", &self.name), ("declared", &self.declared)] {
            if let Some(text) = text
                && clean_name(text).as_ref() != Some(text)
            {
                return Err(format!("{what} holds characters a name may not"));
            }
        }
        if let (Some(first), Some(last)) = (self.first_seen, self.last_seen)
            && first > last
        {
            return Err("first_seen is after last_seen".to_owned());
        }
        self.later.check(id)
    }
}

/// The address book (`address-book.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBook {
    /// The schema version, [`VERSION`].
    pub version: u32,
    /// Whether recent connections are kept (the history switch).
    #[serde(default = "keep_history")]
    pub history: bool,
    /// The computers, by ID.
    #[serde(default)]
    pub hosts: BTreeMap<TornectId, Entry>,
}

fn keep_history() -> bool {
    true
}

impl Default for AddressBook {
    fn default() -> Self {
        Self {
            version: VERSION,
            history: keep_history(),
            hosts: BTreeMap::new(),
        }
    }
}

impl AddressBook {
    /// Load the file, or an empty book when there is none. A file that does
    /// not parse, has another schema version, or holds a value this version
    /// would never write is refused whole.
    pub fn load(path: &Path) -> Result<Self> {
        let Some(text) = read_if_there(path)? else {
            return Ok(Self::default());
        };
        let book: Self = parse(path, &text)?;
        if book.version != VERSION {
            return Err(invalid(
                path,
                &format!(
                    "schema version {} (this build reads {VERSION})",
                    book.version
                ),
            ));
        }
        for (id, entry) in &book.hosts {
            entry
                .check(id)
                .map_err(|why| invalid(path, &format!("{}: {why}", id.short())))?;
        }
        Ok(book)
    }

    /// Write the file atomically with private permissions.
    pub fn save(&self, path: &Path) -> Result<()> {
        save_private_toml(path, self)
    }

    /// The entries, the most recently seen first (never seen last, then by
    /// ID).
    #[must_use]
    pub fn by_last_seen(&self) -> Vec<(&TornectId, &Entry)> {
        let mut all: Vec<_> = self.hosts.iter().collect();
        all.sort_by(|a, b| b.1.last_seen.cmp(&a.1.last_seen).then(a.0.cmp(b.0)));
        all
    }
}

/// The address book on disk, and every change the window makes to it. Each
/// change reads the file, changes one thing and writes it back.
#[derive(Debug, Clone)]
pub struct Store {
    book: PathBuf,
}

impl Store {
    /// The store of the Tornect home `paths`.
    #[must_use]
    pub fn new(paths: &Paths) -> Self {
        Self::at(address_book_file(paths))
    }

    /// A store whose address book is `book`.
    #[must_use]
    pub fn at(book: PathBuf) -> Self {
        Self { book }
    }

    /// The address book's file.
    #[must_use]
    pub fn book_path(&self) -> &Path {
        &self.book
    }

    /// The address book.
    pub fn load(&self) -> Result<AddressBook> {
        AddressBook::load(&self.book)
    }

    /// Name the computer `id` (saving it if it is new), bound to the host key
    /// `pinned` now (none: not paired yet); an empty name removes the saved
    /// one. Returns the name kept.
    pub fn name(
        &self,
        id: TornectId,
        pinned: Option<[u8; 32]>,
        name: &str,
    ) -> Result<Option<String>> {
        let mut book = self.load()?;
        let entry = book.hosts.entry(id).or_default();
        entry.name = clean_name(name);
        entry.key = pinned;
        let kept = entry.name.clone();
        book.save(&self.book)?;
        Ok(kept)
    }

    /// Bind the name of a computer saved before it was paired to the host key
    /// just pinned for it. Writes only when there is such a name.
    pub fn bind(&self, id: TornectId, pinned: [u8; 32]) -> Result<bool> {
        let mut book = self.load()?;
        match book.hosts.get_mut(&id) {
            Some(entry) if entry.key.is_none() && entry.name.is_some() => {
                entry.key = Some(pinned);
                book.save(&self.book)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Remove the computer `id` from the address book; whether it was there.
    pub fn forget(&self, id: &TornectId) -> Result<bool> {
        let mut book = self.load()?;
        let removed = book.hosts.remove(id).is_some();
        if removed {
            book.save(&self.book)?;
        }
        Ok(removed)
    }
}

fn read_if_there(path: &Path) -> Result<Option<String>> {
    match fs_err::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn parse<T: serde::de::DeserializeOwned>(path: &Path, text: &str) -> Result<T> {
    toml::from_str(text).map_err(|source| CoreError::ConfigParse {
        path: path.to_owned(),
        source: Box::new(crate::error::TomlError::new(text, &source)),
    })
}

fn invalid(path: &Path, why: &str) -> CoreError {
    CoreError::ConfigInvalid(format!("{}: {why}", path.display()))
}

/// Serialize `value` as TOML into `path` via a private temporary file and an
/// atomic rename, creating the parent directory with private permissions.
fn save_private_toml<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let text = toml::to_string(value)?;
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let tmp = path.with_extension("toml.tmp");
    write_private_file(&tmp, text.as_bytes())?;
    fs_err::rename(&tmp, path)?;
    Ok(())
}

/// `Option<[u8; 32]>` as a 64-character hex string in TOML.
mod opt_hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_str(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let text = String::deserialize(d)?;
        let raw = hex::decode(&text).map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(raw)
            .map(Some)
            .map_err(|v| serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> TornectId {
        TornectId::from_bytes([seed; 32])
    }

    fn day(s: &str) -> Day {
        s.parse().unwrap()
    }

    fn mode(path: &Path) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            0o600
        }
    }

    fn sample() -> AddressBook {
        let mut book = AddressBook::default();
        book.hosts.insert(
            id(1),
            Entry {
                key: Some([3; 32]),
                name: Some("Office PC".to_owned()),
                declared: Some("Linux PC".to_owned()),
                first_seen: Some(day("2026-09-12")),
                last_seen: Some(day("2026-09-27")),
                later: Later {
                    credential_ref: Some(credential_ref(&id(1))),
                    words: Some("amber-canyon-fox".to_owned()),
                },
            },
        );
        book.hosts.insert(
            id(2),
            Entry {
                name: Some("Studio laptop".to_owned()),
                ..Entry::default()
            },
        );
        book
    }

    /// The book goes to a 0600 file and comes back as it was, with its schema
    /// version and without a temporary file left behind; a missing file is an
    /// empty book that keeps history.
    #[test]
    fn a_book_round_trips_through_a_private_file() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let path = address_book_file(&paths);
        assert_eq!(path, paths.state_dir.join("address-book.toml"));
        let empty = AddressBook::load(&path).unwrap();
        assert_eq!(empty, AddressBook::default());
        assert!(empty.history && empty.hosts.is_empty());

        let book = sample();
        book.save(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert!(!path.with_extension("toml.tmp").exists());
        assert_eq!(AddressBook::load(&path).unwrap(), book);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("version = 1\nhistory = true\n"), "{text}");
        assert!(text.contains("last_seen = \"2026-09-27\""), "{text}");
        assert!(text.contains(&hex::encode([3u8; 32])), "{text}");
    }

    /// A file that is not what this version writes is refused whole, never
    /// half-read: not TOML, cut short, another schema version, an unknown
    /// field (a password among them), a key that is not 32 bytes, a name
    /// with a control character, a credential that is not a reference, a
    /// day that does not exist.
    #[test]
    fn a_damaged_file_is_refused_not_half_read() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("address-book.toml");
        sample().save(&path).unwrap();
        let good = std::fs::read_to_string(&path).unwrap();
        let onion = id(1).onion_address();
        let cases = [
            "this is not toml [".to_owned(),
            good[..good.len() / 2].to_owned(),
            good.replace("version = 1", "version = 2"),
            good.replace("history = true", "history = true\ntheme = \"dark\""),
            format!("version = 1\n[hosts.\"{onion}\"]\npassword = \"hunter2\"\n"),
            format!("version = 1\n[hosts.\"{onion}\"]\nkey = \"abcd\"\n"),
            format!("version = 1\n[hosts.\"{onion}\"]\nname = \"a\\u0007b\"\n"),
            format!("version = 1\n[hosts.\"{onion}\"]\nname = \"evil\\u202Etxt\"\n"),
            format!("version = 1\n[hosts.\"{onion}\".later]\ncredential_ref = \"hunter2\"\n"),
            format!("version = 1\n[hosts.\"{onion}\".later]\npassword = \"hunter2\"\n"),
            format!("version = 1\n[hosts.\"{onion}\".later]\nwords = \"Amber Fox!\"\n"),
            format!("version = 1\n[hosts.\"{onion}\"]\nlast_seen = \"2026-02-30\"\n"),
            format!(
                "version = 1\n[hosts.\"{onion}\"]\nfirst_seen = \"2026-09-28\"\nlast_seen = \"2026-09-27\"\n"
            ),
            "version = 1\n[hosts.\"not-an-id.onion\"]\n".to_owned(),
        ];
        for case in cases {
            std::fs::write(&path, &case).unwrap();
            let err = AddressBook::load(&path).expect_err(&case);
            assert!(
                matches!(
                    err,
                    CoreError::ConfigParse { .. } | CoreError::ConfigInvalid(_)
                ),
                "{case}: {err}"
            );
            assert!(!err.to_string().contains("hunter2"), "{err}");
        }
    }

    /// Names lose control, bidi and other invisible characters, collapse
    /// their whitespace and keep at most 64 characters; one with nothing
    /// visible left is no name. Look-alike letters are noted, not refused.
    #[test]
    fn names_are_cleaned_and_look_alikes_noted() {
        assert_eq!(clean_name("  Office\tPC \n").as_deref(), Some("Office PC"));
        assert_eq!(
            clean_name("evil\u{202E}txt.exe").as_deref(),
            Some("eviltxt.exe")
        );
        assert_eq!(
            clean_name("a\u{0007}b\u{200B}c\u{FEFF}d").as_deref(),
            Some("abcd")
        );
        assert_eq!(clean_name("\u{200E}\u{202A} \t"), None);
        assert_eq!(clean_name(""), None);
        let long = clean_name(&"é".repeat(100)).unwrap();
        assert_eq!(long.chars().count(), trusted::MAX_LABEL_CHARS);

        // Cyrillic "а" in a Latin name: kept as typed, and noted.
        let lookalike = "P\u{0430}ypal";
        assert_eq!(clean_name(lookalike).as_deref(), Some(lookalike));
        assert!(mixes_scripts(lookalike));
        assert!(mixes_scripts("\u{FF2F}ffice"), "full-width O");
        assert!(mixes_scripts("\u{0396}eus server"), "Greek Z");
        for plain in [
            "Office PC",
            "Αθήνα",
            "Москва",
            "Café 2",
            "东京 box",
            "server-01",
        ] {
            assert!(!mixes_scripts(plain), "{plain}");
        }
    }

    /// A saved name applies only to the host key it was given against, in
    /// full: after a re-pair with another key it is not shown. A computer
    /// saved before pairing shows its name until it is paired; the pairing
    /// binds the name to the key just pinned.
    #[test]
    fn a_saved_name_applies_only_to_the_key_it_was_given_against() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::at(tmp.path().join("address-book.toml"));
        let (a, mut b) = ([0xa1; 32], [0xa1; 32]);
        b[31] ^= 1;
        store.name(id(1), Some(a), "Office PC").unwrap();
        let book = store.load().unwrap();
        let entry = &book.hosts[&id(1)];
        assert_eq!(entry.name_for(Some(&a)), Some("Office PC"));
        assert_eq!(entry.name_for(Some(&b)), None, "one bit differs");
        assert_eq!(entry.name_for(None), None, "no longer paired");

        store.name(id(2), None, "Studio laptop").unwrap();
        let entry = store.load().unwrap().hosts[&id(2)].clone();
        assert_eq!(entry.name_for(None), Some("Studio laptop"));
        assert_eq!(entry.name_for(Some(&a)), None, "paired, not bound yet");
        assert!(store.bind(id(2), a).unwrap());
        let entry = store.load().unwrap().hosts[&id(2)].clone();
        assert_eq!(entry.name_for(Some(&a)), Some("Studio laptop"));
        assert!(!store.bind(id(2), b).unwrap(), "a bound name stays bound");
        assert!(!store.bind(id(3), a).unwrap(), "nothing to bind");
        assert_eq!(store.load().unwrap().hosts.get(&id(3)), None);
    }

    /// Rename replaces the saved name (cleaned), an empty one removes it;
    /// forget removes the computer and says whether it was there.
    #[test]
    fn rename_and_forget() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::at(tmp.path().join("state").join("address-book.toml"));
        let key = Some([7; 32]);
        assert_eq!(
            store.name(id(1), key, "Desk").unwrap().as_deref(),
            Some("Desk")
        );
        assert_eq!(
            store
                .name(id(1), key, " Desk\u{202E} 2 ")
                .unwrap()
                .as_deref(),
            Some("Desk 2")
        );
        assert_eq!(
            store.load().unwrap().hosts[&id(1)].name.as_deref(),
            Some("Desk 2")
        );
        assert_eq!(store.name(id(1), key, " \u{200B} ").unwrap(), None);
        assert_eq!(store.load().unwrap().hosts[&id(1)].name, None);
        assert_eq!(mode(store.book_path()), 0o600);
        assert!(store.forget(&id(1)).unwrap());
        assert!(!store.forget(&id(1)).unwrap());
        assert!(store.load().unwrap().hosts.is_empty());
    }

    /// The most recently seen come first; never seen last, by ID.
    #[test]
    fn entries_order_by_last_seen() {
        let mut book = AddressBook::default();
        for (seed, last) in [
            (1, None),
            (2, Some("2026-09-20")),
            (3, Some("2026-09-27")),
            (4, None),
            (5, Some("2025-12-31")),
        ] {
            book.hosts.insert(
                id(seed),
                Entry {
                    last_seen: last.map(day),
                    ..Entry::default()
                },
            );
        }
        let order: Vec<TornectId> = book.by_last_seen().into_iter().map(|(i, _)| *i).collect();
        assert_eq!(order, vec![id(3), id(2), id(5), id(1), id(4)]);
    }

    /// Days are UTC calendar days, written and read as `YYYY-MM-DD`; a day
    /// that does not exist is refused.
    #[test]
    fn days_are_dates() {
        assert_eq!(Day::from_unix(0).to_string(), "1970-01-01");
        assert_eq!(Day::from_unix(86_399), Day::from_unix(0));
        assert_eq!(Day::from_unix(86_400).to_string(), "1970-01-02");
        // 2026-09-27T12:00:00Z.
        assert_eq!(Day::from_unix(1_790_510_400).to_string(), "2026-09-27");
        assert_eq!(day("2024-02-29").ymd(), (2024, 2, 29));
        assert_eq!(day("2024-03-01").days() - day("2024-02-28").days(), 2);
        for bad in [
            "2023-02-29",
            "2026-13-01",
            "2026-00-10",
            "26-09-27",
            "2026-9-27",
            "2026-09-27T10:00",
            "1969-12-31",
        ] {
            assert!(bad.parse::<Day>().is_err(), "{bad}");
        }
        for n in (0..30_000).step_by(7) {
            let d = Day::from_days(n);
            assert_eq!(d.to_string().parse::<Day>().unwrap(), d);
        }
    }
}
