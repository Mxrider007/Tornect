//! The address book and the recent connections (the redesign's §4): the
//! computers this one connects to, with the names the user gave them, in two
//! small private TOML files next to `known-hosts.toml`, on this computer only
//! (`docs/PLAN.md` §B.8.9's rules for local state: `0600`, atomic replace,
//! refused whole when it is wrong).
//!
//! * [`AddressBook`] at [`address_book_file`] (`address-book.toml`, schema
//!   `version = 1`) holds, per computer: the host key its saved name was given
//!   against, the saved name, the name the computer declared when last seen,
//!   the first and the last day it was seen, and a `later` table for what
//!   arrives with the spec amendment; and whether history is kept.
//! * [`Recent`] at [`recent_file`] (`recent.toml`, `version = 1`): the recent
//!   connections, one line per computer and day, newest first.
//!
//! It holds no secret and no reference to one: no private key, no password,
//! no credential, no keychain entry name (a keychain entry's name is derived
//! from the pinned key when it is used, never read from this file). The
//! `later` table's own keys are [`LATER_KEYS`]; any other key found there
//! (a later version's) is kept as it is and never read (§B.8.9.1).
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
//! **History** keeps days, never times ([`Day`], UTC). While it is off,
//! recording a visit changes nothing and opens no file for writing
//! ([`Store::record_visit`]); [`Store::clear_history`] deletes the recent
//! list, the days in the address book and the last-seen times the handshake
//! keeps in `known-hosts.toml`. Nothing here is ever sent anywhere.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{CoreError, Result};
use crate::id::TornectId;
use crate::keystore::{create_private_dir, write_private_file};
use crate::paths::Paths;
use crate::trusted::{self, KnownHosts};
use crate::words::{Identicon, Role, Stretched, Words};

/// The schema version this build reads and writes.
pub const VERSION: u32 = 1;

/// Most characters of the device words.
pub const MAX_WORDS_CHARS: usize = 160;

/// The keys of the `later` table this version reads and writes in schema
/// version 1: fields that arrive with the spec amendment and hold no secret.
/// Any other key found there is kept for forward compatibility, written back
/// as it was, and never read (§B.8.9.1): this version writes no other key.
pub const LATER_KEYS: [&str; 1] = ["words"];

/// Most recent connections kept (one per computer and day).
pub const MAX_VISITS: usize = 200;

/// Where the address book lives: `<state>/address-book.toml`, next to
/// `known-hosts.toml`.
#[must_use]
pub fn address_book_file(paths: &Paths) -> PathBuf {
    paths.state_dir.join("address-book.toml")
}

/// Where the recent connections live: `<state>/recent.toml`.
#[must_use]
pub fn recent_file(paths: &Paths) -> PathBuf {
    paths.state_dir.join("recent.toml")
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

/// Fields that arrive with the spec amendment: the keys of [`LATER_KEYS`],
/// none of which can hold a secret or point to one, and whatever a later
/// version put beside them ([`Kept`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Later {
    /// The device-words cache of the computer's ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub words: Option<WordsCache>,
    /// Keys this version does not know: kept, never read.
    #[serde(flatten)]
    pub kept: Kept,
}

/// The keys of a `later` table that this version does not know (a later
/// version's, §B.8.9.1): kept so that writing the file again loses nothing,
/// and never interpreted. `Debug` names the keys only, never a value.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Kept(BTreeMap<String, toml::Value>);

// TOML values compare by value; a NaN float, the one value unequal to itself,
// only makes two books that hold one compare unequal.
impl Eq for Kept {}

impl fmt::Debug for Kept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

impl Kept {
    /// No such key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The keys kept, in order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

impl Later {
    /// Nothing set, nothing kept.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.is_none() && self.kept.is_empty()
    }

    /// Whether the fields are what they must be.
    fn check(&self) -> std::result::Result<(), String> {
        match &self.words {
            Some(cache) if cache.read().is_none() => {
                Err("later.words is not a device-words cache".to_owned())
            }
            _ => Ok(()),
        }
    }
}

/// The device-words cache of an address-book entry (§B.6.1 item 2, the
/// privacy requirement R-W3): the words and identicon derived from `key` in
/// `role`. A cache only: used while its role and key are the entry's own
/// ([`Entry::cached_words`]), dropped by Forget with the entry, never
/// exported, and never trusted to decide anything (any program of the user
/// can edit this file). `Debug` shows none of it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WordsCache {
    /// Whose key: `onion` (an address) or `device`.
    pub role: String,
    /// The key the words were derived from, in hexadecimal.
    pub key: String,
    /// The four words, one space apart.
    pub words: String,
    /// The identicon's three bytes, in hexadecimal.
    pub identicon: String,
}

impl fmt::Debug for WordsCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WordsCache(<redacted>)")
    }
}

impl WordsCache {
    /// The cache of `stretched`, derived from `key` in `role`.
    #[must_use]
    pub fn of(key: &[u8; 32], role: Role, stretched: &Stretched) -> Self {
        Self {
            role: role.as_str().to_owned(),
            key: hex::encode(key),
            words: stretched.words().cached(),
            identicon: hex::encode(stretched.identicon().seed()),
        }
    }

    /// Its role, key, words and identicon, when each is well formed.
    fn read(&self) -> Option<(Role, [u8; 32], Words, Identicon)> {
        let role = Role::parse(&self.role)?;
        let key: [u8; 32] = hex::decode(&self.key).ok()?.try_into().ok()?;
        let words = Words::from_cached(&self.words)?;
        let seed: [u8; 3] = hex::decode(&self.identicon).ok()?.try_into().ok()?;
        (hex::encode(key) == self.key && hex::encode(seed) == self.identicon).then_some((
            role,
            key,
            words,
            Identicon::from_seed(seed),
        ))
    }
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
    /// The cached words and identicon of `key` in `role`: only when the
    /// cache was made from exactly that key, in that role.
    #[must_use]
    pub fn cached_words(&self, key: &[u8; 32], role: Role) -> Option<(Words, Identicon)> {
        let (r, k, words, identicon) = self.later.words.as_ref()?.read()?;
        (r == role && k == *key).then_some((words, identicon))
    }

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

    fn check(&self) -> std::result::Result<(), String> {
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
        self.later.check()
    }
}

/// The address book (`address-book.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBook {
    /// The schema version, [`VERSION`].
    pub version: u32,
    /// Whether recent connections are kept (the history switch): off
    /// unless switched on. A file keeps the value it holds (every save
    /// writes the key).
    #[serde(default = "history_by_default")]
    pub history: bool,
    /// The computers, by ID.
    #[serde(default)]
    pub hosts: BTreeMap<TornectId, Entry>,
}

/// History is off until it is switched on (the operator's ruling of
/// 2026-09-28): on a new Tornect home nothing about past connections is
/// written — no recent list, no last-connected days, no last-seen times.
fn history_by_default() -> bool {
    false
}

impl Default for AddressBook {
    fn default() -> Self {
        Self {
            version: VERSION,
            history: history_by_default(),
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
                .check()
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

/// One recent connection: which computer, which day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Visit {
    /// The computer.
    pub id: TornectId,
    /// The day a session with it started.
    pub day: Day,
}

/// The recent connections (`recent.toml`): one line per computer and day,
/// newest first, at most [`MAX_VISITS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recent {
    /// The schema version, [`VERSION`].
    pub version: u32,
    /// The connections, newest first.
    #[serde(default)]
    pub visits: Vec<Visit>,
}

impl Default for Recent {
    fn default() -> Self {
        Self {
            version: VERSION,
            visits: Vec::new(),
        }
    }
}

impl Recent {
    /// Load the file, or an empty list when there is none; a file that is
    /// not what this version writes is refused whole.
    pub fn load(path: &Path) -> Result<Self> {
        let Some(text) = read_if_there(path)? else {
            return Ok(Self::default());
        };
        let recent: Self = parse(path, &text)?;
        if recent.version != VERSION {
            return Err(invalid(
                path,
                &format!(
                    "schema version {} (this build reads {VERSION})",
                    recent.version
                ),
            ));
        }
        if recent.visits.len() > MAX_VISITS {
            return Err(invalid(path, "more visits than this version keeps"));
        }
        Ok(recent)
    }

    /// Write the file atomically with private permissions.
    pub fn save(&self, path: &Path) -> Result<()> {
        save_private_toml(path, self)
    }

    /// Add a visit to `id` on `day`: one line per computer and day, the
    /// newest first, the oldest dropped beyond [`MAX_VISITS`].
    pub fn add(&mut self, id: TornectId, day: Day) {
        self.visits.retain(|v| !(v.id == id && v.day == day));
        self.visits.insert(0, Visit { id, day });
        self.visits.sort_by_key(|v| std::cmp::Reverse(v.day));
        self.visits.truncate(MAX_VISITS);
    }
}

/// The address book and the recent list on disk, and every change the window
/// makes to them. Each change reads the file, changes one thing and writes it
/// back.
#[derive(Debug, Clone)]
pub struct Store {
    book: PathBuf,
    recent: PathBuf,
}

impl Store {
    /// The store of the Tornect home `paths`.
    #[must_use]
    pub fn new(paths: &Paths) -> Self {
        Self::at(address_book_file(paths))
    }

    /// A store whose address book is `book`, with `recent.toml` beside it.
    #[must_use]
    pub fn at(book: PathBuf) -> Self {
        let recent = book.with_file_name("recent.toml");
        Self { book, recent }
    }

    /// The address book's file.
    #[must_use]
    pub fn book_path(&self) -> &Path {
        &self.book
    }

    /// The recent list's file.
    #[must_use]
    pub fn recent_path(&self) -> &Path {
        &self.recent
    }

    /// The address book.
    pub fn load(&self) -> Result<AddressBook> {
        AddressBook::load(&self.book)
    }

    /// The recent connections.
    pub fn recent(&self) -> Result<Recent> {
        Recent::load(&self.recent)
    }

    /// Whether history is kept. An address book that cannot be read keeps
    /// none: nothing is written until it can be.
    #[must_use]
    pub fn keeps_history(&self) -> bool {
        self.load().is_ok_and(|book| book.history)
    }

    /// Turn history on or off. Turning it off keeps what was kept until it
    /// is cleared ([`Store::clear_history`]).
    pub fn set_history(&self, on: bool) -> Result<()> {
        let mut book = self.load()?;
        if book.history != on {
            book.history = on;
            book.save(&self.book)?;
        }
        Ok(())
    }

    /// A session with the computer `id` started on `day`, its host key
    /// pinned as `pinned`, calling itself `declared`. With history on: its
    /// entry's first and last day and declared name, and a line in the recent
    /// list. With history off: nothing, and no file is opened for writing.
    /// Whether anything was kept.
    pub fn record_visit(
        &self,
        id: TornectId,
        pinned: [u8; 32],
        declared: &str,
        day: Day,
    ) -> Result<bool> {
        let mut book = self.load()?;
        if !book.history {
            return Ok(false);
        }
        let entry = book.hosts.entry(id).or_default();
        if entry.key.is_none() && entry.name.is_none() {
            entry.key = Some(pinned);
        }
        if let Some(declared) = clean_name(declared) {
            entry.declared = Some(declared);
        }
        entry.first_seen = Some(entry.first_seen.map_or(day, |d| d.min(day)));
        entry.last_seen = Some(entry.last_seen.map_or(day, |d| d.max(day)));
        book.save(&self.book)?;
        let mut recent = self.recent()?;
        recent.add(id, day);
        recent.save(&self.recent)?;
        Ok(true)
    }

    /// Clear the history, whether it is on or off: the recent list's file is
    /// overwritten and deleted, every computer loses its first and last day
    /// (its name and key stay), and with `known_hosts` the last-seen times the
    /// handshake keeps in `known-hosts.toml` go back to the pairing time (the
    /// pins stay). Older copies that the atomic writes left in freed blocks
    /// of the file system are beyond reach here.
    pub fn clear_history(&self, known_hosts: Option<&Path>) -> Result<()> {
        wipe(&self.recent)?;
        if self.book.exists() {
            let mut book = self.load()?;
            let mut changed = false;
            for entry in book.hosts.values_mut() {
                changed |= entry.first_seen.take().is_some();
                changed |= entry.last_seen.take().is_some();
            }
            if changed {
                book.save(&self.book)?;
            }
        }
        if let Some(path) = known_hosts
            && path.exists()
        {
            let mut hosts = KnownHosts::load(path)?;
            let mut changed = false;
            for host in hosts.hosts.values_mut() {
                if host.last_seen != host.paired_at {
                    host.last_seen = host.paired_at;
                    changed = true;
                }
            }
            if changed {
                hosts.save(path)?;
            }
        }
        Ok(())
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

    /// Keep each computer's words in its entry's cache (`derived`: its ID's
    /// key stretched in the role `onion`); a computer that has no entry gets
    /// none. Writes only when a cache changed; whether it did.
    pub fn cache_words(&self, derived: &[(TornectId, Stretched)]) -> Result<bool> {
        let mut book = self.load()?;
        let mut changed = false;
        for (id, stretched) in derived {
            if let Some(entry) = book.hosts.get_mut(id) {
                let cache = WordsCache::of(id.public_key_bytes(), Role::Onion, stretched);
                if entry.later.words.as_ref() != Some(&cache) {
                    entry.later.words = Some(cache);
                    changed = true;
                }
            }
        }
        if changed {
            book.save(&self.book)?;
        }
        Ok(changed)
    }

    /// Remove the computer `id` from the address book, and its lines from
    /// the recent list; whether it was in the address book.
    pub fn forget(&self, id: &TornectId) -> Result<bool> {
        let mut book = self.load()?;
        let removed = book.hosts.remove(id).is_some();
        if removed {
            book.save(&self.book)?;
        }
        if self.recent.exists() {
            let mut recent = self.recent()?;
            let before = recent.visits.len();
            recent.visits.retain(|v| v.id != *id);
            if recent.visits.len() != before {
                recent.save(&self.recent)?;
            }
        }
        Ok(removed)
    }
}

/// Overwrite `path` with zeros, flush that to disk and delete the file;
/// nothing when there is no such file.
fn wipe(path: &Path) -> Result<()> {
    use std::io::Write as _;
    let len = match fs_err::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    {
        let mut file = fs_err::OpenOptions::new().write(true).open(path)?;
        file.write_all(&vec![0; usize::try_from(len).unwrap_or(0)])?;
        file.sync_all()?;
    }
    fs_err::remove_file(path)?;
    Ok(())
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

    /// A words cache as `Store::cache_words` writes it, for the ID
    /// `id(seed)`, with invented words.
    fn cache(seed: u8) -> WordsCache {
        WordsCache {
            role: "onion".to_owned(),
            key: hex::encode(id(seed).public_key_bytes()),
            words: "arctic crisp lamp orbit".to_owned(),
            identicon: "0a0b0c".to_owned(),
        }
    }

    /// A book with history switched on, two computers, days kept.
    fn sample() -> AddressBook {
        let mut book = AddressBook {
            history: true,
            ..AddressBook::default()
        };
        book.hosts.insert(
            id(1),
            Entry {
                key: Some([3; 32]),
                name: Some("Office PC".to_owned()),
                declared: Some("Linux PC".to_owned()),
                first_seen: Some(day("2026-09-12")),
                last_seen: Some(day("2026-09-27")),
                later: Later {
                    words: Some(cache(1)),
                    ..Later::default()
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
    /// empty book that keeps no history (off until switched on).
    #[test]
    fn a_book_round_trips_through_a_private_file() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let path = address_book_file(&paths);
        assert_eq!(path, paths.state_dir.join("address-book.toml"));
        let empty = AddressBook::load(&path).unwrap();
        assert_eq!(empty, AddressBook::default());
        assert!(!empty.history && empty.hosts.is_empty());

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
    /// with a control or bidi character, words that are not words, a day that
    /// does not exist. (Unknown keys of the `later` table are kept instead:
    /// `unknown_later_keys_are_kept_and_never_read`.)
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

    /// The `later` table writes exactly its own keys: a full one writes
    /// those and no other.
    #[test]
    fn the_later_table_writes_only_its_own_keys() {
        let full = Later {
            words: Some(cache(1)),
            ..Later::default()
        };
        let table: toml::Table = toml::from_str(&toml::to_string(&full).unwrap()).unwrap();
        let keys: Vec<&str> = table.keys().map(String::as_str).collect();
        assert_eq!(keys, LATER_KEYS.to_vec());
    }

    /// §B.8.9.1: keys of the `later` table this version does not know (a
    /// later version's `remembered` flag, or anything else) are kept, never
    /// read: the book loads, no field takes their values, `Debug` and errors
    /// never show a value, and writing the book again keeps them as they were.
    #[test]
    fn unknown_later_keys_are_kept_and_never_read() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let store = Store::new(&paths);
        let onion = id(1).onion_address();
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        std::fs::write(
            store.book_path(),
            format!(
                "version = 1\n[hosts.\"{onion}\"]\nname = \"Office PC\"\n\
                 [hosts.\"{onion}\".later]\nremembered = true\npassword = \"hunter2\"\n\
                 [hosts.\"{onion}\".later.display]\norder = 3\n"
            ),
        )
        .unwrap();
        let book = store.load().unwrap();
        let entry = &book.hosts[&id(1)];
        assert_eq!(entry.later.words, None);
        assert_eq!(
            entry.later.kept.keys().collect::<Vec<_>>(),
            ["display", "password", "remembered"]
        );
        let shown = format!("{book:?}");
        assert!(!shown.contains("hunter2"), "{shown}");

        // A rename writes the book again: the kept keys go back as they were.
        store.name(id(1), None, "Studio PC").unwrap();
        let again = store.load().unwrap();
        assert_eq!(again.hosts[&id(1)].later, entry.later);
        assert_eq!(again.hosts[&id(1)].name.as_deref(), Some("Studio PC"));
        let text = std::fs::read_to_string(store.book_path()).unwrap();
        let table: toml::Table = toml::from_str(&text).unwrap();
        let later = &table["hosts"][onion.as_str()]["later"];
        assert_eq!(later["remembered"].as_bool(), Some(true));
        assert_eq!(later["password"].as_str(), Some("hunter2"));
        assert_eq!(later["display"]["order"].as_integer(), Some(3));
    }

    /// R-W3: the words cache is used only for the key and role it was made
    /// from, is dropped by Forget with the entry, and a cache that is not
    /// one (not four words of the list, a key that is not 32 bytes, an
    /// unknown role) makes the file refused like any other damage.
    #[test]
    fn the_words_cache_is_bound_to_its_key_and_role() {
        use crate::words::derive;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let store = Store::new(&paths);
        store.name(id(1), None, "Office PC").unwrap();
        let stretched = derive(id(1).public_key_bytes(), Role::Onion);
        assert!(
            store
                .cache_words(&[(id(1), stretched), (id(2), stretched)])
                .unwrap()
        );
        assert!(
            !store.cache_words(&[(id(1), stretched)]).unwrap(),
            "unchanged"
        );
        let book = store.load().unwrap();
        assert!(!book.hosts.contains_key(&id(2)), "no entry, no cache");
        let entry = &book.hosts[&id(1)];
        let first = id(1);
        let key = first.public_key_bytes();
        assert_eq!(
            entry.cached_words(key, Role::Onion),
            Some((stretched.words(), stretched.identicon()))
        );
        assert_eq!(entry.cached_words(key, Role::Device), None, "another role");
        assert_eq!(
            entry.cached_words(&[9; 32], Role::Onion),
            None,
            "another key"
        );
        assert!(!format!("{entry:?}").contains(stretched.words().get()[0]));

        // Forget drops it with the entry.
        assert!(store.forget(&id(1)).unwrap());
        let text = std::fs::read_to_string(store.book_path()).unwrap();
        assert!(!text.contains(&stretched.words().cached()), "{text}");

        // A cache that is not one is damage.
        let onion = id(1).onion_address();
        let good = hex::encode(key);
        for (role, k, words, identicon) in [
            ("host", good.as_str(), "arctic crisp lamp orbit", "0a0b0c"),
            ("onion", "abcd", "arctic crisp lamp orbit", "0a0b0c"),
            ("onion", good.as_str(), "arctic crisp lamp", "0a0b0c"),
            (
                "onion",
                good.as_str(),
                "arctic crisp lamp notaword",
                "0a0b0c",
            ),
            ("onion", good.as_str(), "arctic crisp lamp orbit", "0a0b"),
        ] {
            std::fs::write(
                store.book_path(),
                format!(
                    "version = 1\n[hosts.\"{onion}\".later.words]\nrole = \"{role}\"\n\
                     key = \"{k}\"\nwords = \"{words}\"\nidenticon = \"{identicon}\"\n"
                ),
            )
            .unwrap();
            assert!(store.load().is_err(), "{role} {k} {words} {identicon}");
        }
    }

    /// W-B1: the stores are looked up by the full key and nothing else. A
    /// saved name follows the 32 bytes of the pinned key: a key one byte
    /// off gets none, whatever words or identicon a planted cache gives it,
    /// and the only lookups take a whole ID or key.
    #[test]
    fn names_follow_the_full_key_never_the_words() {
        use crate::id::DeviceId;
        use crate::trusted::{KnownHost, TrustedDevice, TrustedDevices};

        // The lookups there are, by their types: whole IDs and keys only.
        let _: for<'a, 'b> fn(&'a KnownHosts, &'b TornectId) -> Option<&'a KnownHost> =
            KnownHosts::get;
        let _: for<'a, 'b> fn(&'a TrustedDevices, &'b DeviceId) -> Option<&'a TrustedDevice> =
            TrustedDevices::get;
        let _: for<'a, 'b> fn(&'a Entry, Option<&'b [u8; 32]>) -> Option<&'a str> = Entry::name_for;
        let _: fn(&AddressBook) -> Vec<(&TornectId, &Entry)> = AddressBook::by_last_seen;

        let pinned = [3u8; 32];
        let mut near = pinned;
        near[31] ^= 1;
        let mut entry = Entry {
            key: Some(pinned),
            name: Some("Office PC".to_owned()),
            ..Entry::default()
        };
        // The cache planted with the words of the key one byte off.
        entry.later.words = Some(WordsCache::of(
            &near,
            Role::Device,
            &crate::words::derive(&near, Role::Device),
        ));
        assert_eq!(entry.name_for(Some(&pinned)), Some("Office PC"));
        assert_eq!(entry.name_for(Some(&near)), None);
        assert_eq!(entry.name_for(None), None);
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

    /// Every file under `dir` with its bytes and modification time, and the
    /// directory's own modification time (a file made or removed moves it).
    type Snapshot = (
        Vec<(PathBuf, Vec<u8>, std::time::SystemTime)>,
        std::time::SystemTime,
    );

    fn snapshot(dir: &Path) -> Snapshot {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::metadata(&path).unwrap();
            files.push((
                path.clone(),
                std::fs::read(&path).unwrap(),
                meta.modified().unwrap(),
            ));
        }
        files.sort();
        (files, std::fs::metadata(dir).unwrap().modified().unwrap())
    }

    /// Set `path`'s modification time to a fixed one long ago, so that any
    /// write shows.
    fn age(path: &Path) {
        let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(old)
            .unwrap();
    }

    /// Every file under `dir`, as text.
    fn read_all(dir: &Path) -> String {
        snapshot(dir)
            .0
            .iter()
            .map(|(_, bytes, _)| String::from_utf8_lossy(bytes).into_owned())
            .collect()
    }

    /// With history off, a visit writes nothing: the address book and the
    /// recent list keep their bytes and their modification times, no file
    /// appears or goes, and the directory is not touched, for a computer in
    /// the book as for a new one.
    #[test]
    fn with_history_off_a_visit_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        let store = Store::at(dir.join("address-book.toml"));
        store.name(id(1), Some([3; 32]), "Office PC").unwrap();
        store.set_history(true).unwrap();
        assert!(
            store
                .record_visit(id(1), [3; 32], "Linux PC", day("2026-09-20"))
                .unwrap()
        );
        store.set_history(false).unwrap();
        assert!(!store.keeps_history());
        age(store.book_path());
        age(store.recent_path());
        let before = snapshot(&dir);
        std::thread::sleep(std::time::Duration::from_millis(20));
        for d in ["2026-09-27", "2026-09-28"] {
            assert!(
                !store
                    .record_visit(id(1), [3; 32], "Linux PC", day(d))
                    .unwrap()
            );
            assert!(!store.record_visit(id(2), [4; 32], "Tower", day(d)).unwrap());
        }
        assert_eq!(snapshot(&dir), before);
        // Switched back on, the next visit is kept.
        store.set_history(true).unwrap();
        assert!(
            store
                .record_visit(id(1), [3; 32], "Linux PC", day("2026-09-29"))
                .unwrap()
        );
        assert_eq!(store.recent().unwrap().visits[0].day, day("2026-09-29"));
    }

    /// History is off until it is switched on: a new Tornect home's visit
    /// writes no file at all, and a stored value, on or off, is kept as it
    /// is by every later load.
    #[test]
    fn history_is_off_until_switched_on() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        let store = Store::at(dir.join("address-book.toml"));
        assert!(!store.keeps_history());
        assert!(
            !store
                .record_visit(id(1), [3; 32], "Linux PC", day("2026-09-28"))
                .unwrap()
        );
        assert!(
            !dir.exists(),
            "a visit wrote a file with history never switched on"
        );
        store.set_history(true).unwrap();
        assert!(store.keeps_history(), "a stored on stays on");
        let text = std::fs::read_to_string(store.book_path()).unwrap();
        assert!(text.contains("history = true"), "{text}");
        store.set_history(false).unwrap();
        assert!(!store.keeps_history(), "a stored off stays off");
    }

    /// With history on, a visit keeps the day and nothing finer: the entry's
    /// first and last day and the name the computer declared (cleaned), and
    /// one line per computer and day in the recent list, newest first, at
    /// most `MAX_VISITS`. Forgetting a computer removes its lines.
    #[test]
    fn with_history_on_a_visit_keeps_the_day_only() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::at(tmp.path().join("address-book.toml"));
        store.set_history(true).unwrap();
        for (who, key, name, d) in [
            (1, [3; 32], "Linux\u{202E} PC", "2026-09-26"),
            (1, [3; 32], "Linux PC", "2026-09-27"),
            (1, [3; 32], "Linux PC", "2026-09-27"),
            (2, [4; 32], "Tower", "2026-09-27"),
        ] {
            assert!(store.record_visit(id(who), key, name, day(d)).unwrap());
        }
        let book = store.load().unwrap();
        let entry = &book.hosts[&id(1)];
        assert_eq!(entry.first_seen, Some(day("2026-09-26")));
        assert_eq!(entry.last_seen, Some(day("2026-09-27")));
        assert_eq!(entry.declared.as_deref(), Some("Linux PC"));
        assert_eq!(entry.key, Some([3; 32]));
        let visits = store.recent().unwrap().visits;
        let expected =
            [(2, "2026-09-27"), (1, "2026-09-27"), (1, "2026-09-26")].map(|(who, d)| Visit {
                id: id(who),
                day: day(d),
            });
        assert_eq!(visits, expected.to_vec());
        assert_eq!(mode(store.recent_path()), 0o600);
        let text = std::fs::read_to_string(store.recent_path()).unwrap();
        assert!(text.contains("day = \"2026-09-27\""), "{text}");
        assert!(
            !text.contains(':') && !text.contains('T'),
            "no time of day: {text}"
        );

        assert!(store.forget(&id(2)).unwrap());
        assert!(store.recent().unwrap().visits.iter().all(|v| v.id != id(2)));

        let mut recent = Recent::default();
        for n in 0..(MAX_VISITS as i64 + 20) {
            recent.add(id(5), Day::from_days(20_000 + n));
        }
        assert_eq!(recent.visits.len(), MAX_VISITS);
        assert_eq!(
            recent.visits[0].day,
            Day::from_days(20_000 + MAX_VISITS as i64 + 19)
        );
    }

    /// Clear removes the history and nothing else: the recent list's file is
    /// gone, the address book keeps its computers and names without a day,
    /// and `known-hosts.toml` keeps its pins with the last-seen time back at
    /// the pairing time. No file holds the visits' days any more.
    #[test]
    fn clear_wipes_the_history() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        let store = Store::at(dir.join("address-book.toml"));
        let known = dir.join("known-hosts.toml");
        let mut hosts = KnownHosts::default();
        hosts.pin(id(1), "Linux PC", [3; 32], 1_790_000_000);
        hosts.touch(&id(1), 1_790_510_400);
        hosts.save(&known).unwrap();
        store.name(id(1), Some([3; 32]), "Office PC").unwrap();
        store.set_history(true).unwrap();
        for d in ["2026-09-26", "2026-09-27"] {
            assert!(
                store
                    .record_visit(id(1), [3; 32], "Linux PC", day(d))
                    .unwrap()
            );
        }
        assert!(read_all(&dir).contains("2026-09-27"));

        store.clear_history(Some(&known)).unwrap();
        assert!(!store.recent_path().exists());
        let all = read_all(&dir);
        for gone in ["2026-09-26", "2026-09-27", "first_seen", "1790510400"] {
            assert!(!all.contains(gone), "{gone} is still on disk: {all}");
        }
        let entry = store.load().unwrap().hosts[&id(1)].clone();
        assert_eq!(entry.name.as_deref(), Some("Office PC"));
        assert_eq!(
            (entry.key, entry.first_seen, entry.last_seen),
            (Some([3; 32]), None, None)
        );
        let pinned = KnownHosts::load(&known)
            .unwrap()
            .get(&id(1))
            .unwrap()
            .clone();
        assert_eq!(pinned.host_device_pk, [3; 32]);
        assert_eq!(pinned.last_seen, pinned.paired_at);
        // Again, with nothing left to clear: fine, and nothing is created.
        store.clear_history(Some(&known)).unwrap();
        assert!(!store.recent_path().exists());
    }
}
