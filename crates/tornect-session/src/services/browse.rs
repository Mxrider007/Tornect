//! What a services stream may show and send of a computer's files (the
//! services design §5.2): the place allowlist, the deny-list, the handles a
//! listing gives out, and the listing worker.
//!
//! **The viewer never sends a path.** The host lists folders and gives the
//! viewer a handle (a `u32`) for every folder and file it shows; a `List` or
//! a `Get` names a handle, and the host looks its path up in the stream's
//! `Handles` (`0` is the places). An unknown or evicted handle is
//! `NOT_FOUND`, and the viewer lists again.
//!
//! **[`Access::check`]** runs on every `List` and `Get`, and on every entry
//! of a listing:
//!
//! 1. `std::fs::canonicalize`, which resolves links, junctions and `..`;
//! 2. the form: on Windows only a verbatim drive path `\\?\X:\…`
//!    ([`windows_drive_root`]), which refuses Volume Shadow Copies
//!    (`\\?\GLOBALROOT\…`), shares and mapped drives (`\\?\UNC\…`), volume
//!    names (`\\?\Volume{…}\…`) and device paths (`\\.\…`); elsewhere an
//!    absolute path;
//! 3. the allowlist: under the canonical root of a place (on Windows the
//!    fixed drives, on Linux `/`, plus the user's folders);
//! 4. the deny-list (`DENIED`): never under Tornect's own folders (both the
//!    `TORNECT_HOME` ones and the platform's, [`tornect_denied`]) nor, on
//!    Linux, `/proc`, `/sys`, `/dev` and `$XDG_RUNTIME_DIR`
//!    ([`system_denied`]);
//! 5. the marker: no folder from the path up to its place's root holds
//!    `tornect_core::files::PRIVATE_MARKER`, so any Tornect home, another
//!    `TORNECT_HOME` included, is `DENIED`;
//! 6. part files (`*.tornect-part`) are `DENIED`, matched when asked, so
//!    files made after the start are covered;
//! 7. the canonical path that passed is the one opened, never the one asked.
//!
//! A listing omits what fails steps 4–6; for a folder entry the marker check
//! costs one `stat`, since the folder listed passed already.
//!
//! **TOCTOU.** A local process that swaps a path between the check and the
//! open is out of scope (a compromised endpoint, PLAN §B.6). Were it to swap
//! in a FIFO, the open could block that one listing or transfer worker; the
//! stream's place then stays `BUSY` until it returns. A file is checked to be
//! a regular file before it is opened, and again on the open file.
//!
//! Nothing here logs a name or a path; [`Access`] and `Handles` print
//! counts only.

use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tornect_core::Paths;
use tornect_core::files::{PRIVATE_MARKER, is_part_name};
use tornect_proto::services::{Entry, MAX_NAME_BYTES, MAX_TITLE_BYTES, kind, reason};

use super::ServicesLimits;
use super::transfer::Untrusted;

/// A place a listing starts from: its name and its canonical root.
#[derive(Clone)]
struct Place {
    name: String,
    root: PathBuf,
}

/// Which paths of this computer a services stream may list and send, and
/// which it never touches (the module docs). Its `Debug` prints counts only.
pub struct Access {
    places: Vec<Place>,
    denied: Vec<PathBuf>,
}

impl fmt::Debug for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Access")
            .field("places", &self.places.len())
            .field("denied", &self.denied.len())
            .finish()
    }
}

/// Whether a folder holds the private marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    Absent,
    Present,
    /// The folder cannot be searched: nothing in it can be reached either.
    Unknown,
}

impl Access {
    /// Access to `places` (a name for display and a folder: the user's
    /// folders, and `/` on Linux or each fixed drive's root on Windows),
    /// never under `denied` ([`tornect_denied`], [`system_denied`]). Each
    /// place and each denied folder is canonicalised now; a place that does
    /// not resolve, or does not have the platform's form, is left out, and a
    /// denied folder that does not resolve is kept as given. Blocking: it
    /// reads the file system.
    #[must_use]
    pub fn new(places: Vec<(String, PathBuf)>, denied: Vec<PathBuf>) -> Self {
        let mut deny: Vec<PathBuf> = Vec::new();
        for dir in denied {
            if let Ok(canonical) = fs::canonicalize(&dir)
                && !deny.contains(&canonical)
            {
                deny.push(canonical);
            }
            if dir.is_absolute() && !deny.contains(&dir) {
                deny.push(dir);
            }
        }
        let mut kept: Vec<Place> = Vec::new();
        for (name, root) in places {
            let Ok(root) = fs::canonicalize(&root) else {
                continue;
            };
            if form_ok(&root) && !kept.iter().any(|place| place.root == root) {
                kept.push(Place { name, root });
            }
        }
        Self {
            places: kept,
            denied: deny,
        }
    }

    /// Access to nothing: every path is `DENIED`.
    #[must_use]
    pub fn none() -> Self {
        Self {
            places: Vec::new(),
            denied: Vec::new(),
        }
    }

    /// Check `path` against every rule (the module docs): its canonical path,
    /// the one to open, or a `tornect_proto::services::reason` code:
    /// `NOT_FOUND` when it does not resolve, `DENIED` when a rule refuses it
    /// or it cannot be read, `IO` otherwise. Blocking.
    pub fn check(&self, path: &Path) -> Result<PathBuf, u16> {
        if path.file_name().is_some_and(is_part_name) {
            return Err(reason::DENIED);
        }
        let canonical = fs::canonicalize(path).map_err(|e| code_of(&e))?;
        self.check_canonical(&canonical)?;
        Ok(canonical)
    }

    /// Steps 2–6 for a path canonicalised already.
    fn check_canonical(&self, canonical: &Path) -> Result<(), u16> {
        if !form_ok(canonical) {
            return Err(reason::DENIED);
        }
        let root = self.outermost(canonical).ok_or(reason::DENIED)?;
        if self.is_denied(canonical) || canonical.file_name().is_some_and(is_part_name) {
            return Err(reason::DENIED);
        }
        // The path itself, when it is a folder, then every folder above it
        // up to the place's root.
        if fs::metadata(canonical).is_ok_and(|m| m.is_dir()) && marker(canonical) != Marker::Absent
        {
            return Err(reason::DENIED);
        }
        for dir in canonical.ancestors().skip(1) {
            if marker(dir) != Marker::Absent {
                return Err(reason::DENIED);
            }
            if dir == root {
                break;
            }
        }
        Ok(())
    }

    /// The root of the outermost place `canonical` lies under.
    fn outermost(&self, canonical: &Path) -> Option<&Path> {
        self.places
            .iter()
            .filter(|place| canonical.starts_with(&place.root))
            .map(|place| place.root.as_path())
            .min_by_key(|root| root.components().count())
    }

    /// Whether `path` is a denied folder or lies under one.
    fn is_denied(&self, path: &Path) -> bool {
        self.denied.iter().any(|dir| path.starts_with(dir))
    }

    /// What a listing of folder `folder` (canonical, checked) shows of
    /// `entry`: `None` for what the rules omit (a part file, a denied path,
    /// a folder with the marker, a link to any of them). A link takes its
    /// kind, size and time from what it points to; one that does not resolve
    /// is shown as "other".
    fn entry(
        &self,
        folder: &Path,
        raw: OsString,
        file_type: Option<fs::FileType>,
        own: impl FnOnce() -> Option<fs::Metadata>,
    ) -> Option<Found> {
        if is_part_name(&raw) {
            return None;
        }
        let path = folder.join(&raw);
        if self.is_denied(&path) {
            return None;
        }
        let meta = match file_type {
            Some(ft) if ft.is_symlink() => match self.check(&path) {
                Ok(target) => fs::metadata(target).ok(),
                Err(reason::DENIED) => return None,
                Err(_) => None,
            },
            Some(ft) if ft.is_dir() => {
                if marker(&path) == Marker::Present {
                    return None;
                }
                own()
            }
            Some(_) => own(),
            None => None,
        };
        Some(Found::of(raw, None, meta.as_ref()))
    }

    /// The places, in their order, each that passes the rules now.
    fn places_now(&self) -> Vec<Found> {
        self.places
            .iter()
            .filter(|place| self.check_canonical(&place.root).is_ok())
            .map(|place| Found {
                raw: OsString::from(&place.name),
                at: Some(place.root.clone()),
                kind: kind::FOLDER,
                size: None,
                mtime: None,
            })
            .collect()
    }
}

/// Whether a canonical path has the platform's form: on Windows a verbatim
/// drive path, elsewhere an absolute path.
fn form_ok(canonical: &Path) -> bool {
    #[cfg(windows)]
    {
        windows_drive_root(&canonical.to_string_lossy()).is_some()
    }
    #[cfg(not(windows))]
    {
        canonical.is_absolute()
    }
}

/// The drive letter of a verbatim drive path, `\\?\X:\…` (what
/// `std::fs::canonicalize` gives for a file on a lettered drive), upper-case;
/// `None` for every other form: `\\?\GLOBALROOT\…` (Volume Shadow Copies),
/// `\\?\UNC\…` (shares, `\\localhost\C$`, mapped drives, `\\wsl$`),
/// `\\?\Volume{…}\…`, `\\.\…` device paths, and paths that are not verbatim
/// (`C:\x`, `C:x`). Pure, so that it is tested on every platform.
#[must_use]
pub fn windows_drive_root(path: &str) -> Option<char> {
    let rest = path.strip_prefix(r"\\?\")?;
    let mut chars = rest.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    (chars.next() == Some(':') && chars.next() == Some('\\')).then(|| letter.to_ascii_uppercase())
}

/// Tornect's own folders of `paths`: what a host never lists or sends. A
/// host passes both `Paths::discover()` and `Paths::platform()`, so that the
/// platform's folders stay denied while `TORNECT_HOME` is in use.
#[must_use]
pub fn tornect_denied(paths: &Paths) -> Vec<PathBuf> {
    paths
        .all()
        .iter()
        .map(|(_, dir)| dir.to_path_buf())
        .collect()
}

/// The system folders a Linux host never lists or sends: `/proc`, `/sys`,
/// `/dev` and `$XDG_RUNTIME_DIR` (when set to an absolute path). Empty
/// elsewhere.
#[must_use]
pub fn system_denied() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let mut dirs: Vec<PathBuf> = ["/proc", "/sys", "/dev"]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
            && runtime.is_absolute()
        {
            dirs.push(runtime);
        }
        dirs
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// Whether `dir` holds the private marker, without following a link of
/// that name.
fn marker(dir: &Path) -> Marker {
    match fs::symlink_metadata(dir.join(PRIVATE_MARKER)) {
        Ok(_) => Marker::Present,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Marker::Absent
        }
        Err(_) => Marker::Unknown,
    }
}

/// The `tornect_proto::services::reason` code of a failed file-system call.
pub(crate) fn code_of(e: &io::Error) -> u16 {
    match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => reason::NOT_FOUND,
        io::ErrorKind::PermissionDenied => reason::DENIED,
        _ => reason::IO,
    }
}

// --- Handles ----------------------------------------------------------------

/// The handles a services stream gave out (the module docs): `u32 → path`,
/// `0` the places, the others counting up from 1. One path keeps one handle
/// while it is in the table; past `max` handles the oldest goes first. Its
/// `Debug` prints counts only.
pub(crate) struct Handles {
    max: usize,
    next: u32,
    by_handle: HashMap<u32, Arc<Path>>,
    by_path: HashMap<Arc<Path>, u32>,
    order: VecDeque<u32>,
}

impl fmt::Debug for Handles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handles")
            .field("held", &self.by_handle.len())
            .field("max", &self.max)
            .finish()
    }
}

impl Handles {
    /// A table of at most `max` handles (at least one).
    pub(crate) fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            next: 0,
            by_handle: HashMap::new(),
            by_path: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// The handle of `path`: the one it has, or a new one (the oldest handle
    /// goes when the table is full).
    pub(crate) fn issue(&mut self, path: &Path) -> u32 {
        if let Some(&handle) = self.by_path.get(path) {
            return handle;
        }
        while self.by_handle.len() >= self.max {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            if let Some(path) = self.by_handle.remove(&old) {
                self.by_path.remove(&path);
            }
        }
        let handle = loop {
            self.next = self.next.wrapping_add(1);
            if self.next != 0 && !self.by_handle.contains_key(&self.next) {
                break self.next;
            }
        };
        let path: Arc<Path> = Arc::from(path);
        self.by_handle.insert(handle, Arc::clone(&path));
        self.by_path.insert(path, handle);
        self.order.push_back(handle);
        handle
    }

    /// The path of `handle`; `None` for 0, an unknown or an evicted one.
    pub(crate) fn get(&self, handle: u32) -> Option<&Path> {
        self.by_handle.get(&handle).map(AsRef::as_ref)
    }
}

// --- The listing worker -----------------------------------------------------

/// One entry a listing found.
#[derive(Clone)]
pub(crate) struct Found {
    /// Its name in the folder (for a place, the place's name).
    raw: OsString,
    /// Its path when it is not the folder's path joined with `raw` (a place).
    at: Option<PathBuf>,
    kind: u8,
    size: Option<u64>,
    mtime: Option<i64>,
}

impl Found {
    fn of(raw: OsString, at: Option<PathBuf>, meta: Option<&fs::Metadata>) -> Self {
        let kind = meta.map_or(kind::OTHER, |m| {
            if m.is_dir() {
                kind::FOLDER
            } else if m.is_file() {
                kind::FILE
            } else {
                kind::OTHER
            }
        });
        Self {
            raw,
            at,
            kind,
            size: meta.filter(|_| kind == kind::FILE).map(fs::Metadata::len),
            mtime: meta.and_then(|m| m.modified().ok()).map(seconds),
        }
    }

    /// Its path, in folder `folder`.
    pub(crate) fn path(&self, folder: Option<&Path>) -> PathBuf {
        match (&self.at, folder) {
            (Some(at), _) => at.clone(),
            (None, Some(folder)) => folder.join(&self.raw),
            (None, None) => PathBuf::from(&self.raw),
        }
    }

    /// Its name for display, at most [`MAX_NAME_BYTES`], and whether that is
    /// only an approximation: the name was not valid Unicode, or was cut.
    pub(crate) fn shown_name(&self) -> (String, bool) {
        let lossy = self.raw.to_string_lossy();
        let approximate = self.raw.to_str().is_none();
        let cut = cut_end(&lossy, MAX_NAME_BYTES);
        let shortened = cut.len() < lossy.len();
        (cut, approximate || shortened)
    }
}

/// `time` in seconds since 1970 UTC (negative before).
fn seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_secs()).map_or(i64::MIN, |s| -s),
    }
}

/// A folder as the listing worker read it, or the places.
pub(crate) struct Folder {
    /// The folder's canonical path; `None` for the places.
    pub(crate) path: Option<PathBuf>,
    /// The folder for display (its path, cut at the front to
    /// [`MAX_TITLE_BYTES`]); empty for the places.
    pub(crate) title: String,
    /// The folder above, when it passes the rules; `None` for the places
    /// and for a folder with nothing above it that may be shown.
    pub(crate) parent: Option<PathBuf>,
    /// What it holds that may be shown: folders first, then by name, case
    /// ignored.
    pub(crate) entries: Vec<Found>,
    /// It holds more than the worker read.
    pub(crate) truncated: bool,
}

impl fmt::Debug for Folder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Folder")
            .field("places", &self.path.is_none())
            .field("entries", &self.entries.len())
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

/// The listing worker (design §3.5): read folder `path` through `access`,
/// at most `max` entries (stopping there and saying `truncated`), checking
/// `cancel` between entries (`IO` once it is set), then sort what may be
/// shown, folders first and then by name, case ignored. `None` for `path`
/// gives the places. A `tornect_proto::services::reason` code when the
/// folder may not be listed (`DENIED`), is not there or is no folder
/// (`NOT_FOUND`), or cannot be read (`IO`). Blocking: run it on a blocking
/// thread, within the listing's timeout.
pub(crate) fn read_folder(
    access: &Access,
    path: Option<&Path>,
    max: usize,
    cancel: &AtomicBool,
) -> Result<Folder, u16> {
    let Some(path) = path else {
        return Ok(Folder {
            path: None,
            title: String::new(),
            parent: None,
            entries: access.places_now(),
            truncated: false,
        });
    };
    let canonical = access.check(path)?;
    if !fs::metadata(&canonical).map_err(|e| code_of(&e))?.is_dir() {
        return Err(reason::NOT_FOUND);
    }
    let reader = fs::read_dir(&canonical).map_err(|e| code_of(&e))?;
    let (mut entries, truncated) = collect(reader, max, cancel, |item| {
        let entry = item.ok()?;
        access.entry(
            &canonical,
            entry.file_name(),
            entry.file_type().ok(),
            || entry.metadata().ok(),
        )
    })?;
    entries.sort_by_cached_key(|found| {
        (
            found.kind != kind::FOLDER,
            found.raw.to_string_lossy().to_lowercase(),
            found.raw.clone(),
        )
    });
    let parent = canonical
        .parent()
        .filter(|parent| access.check_canonical(parent).is_ok())
        .map(Path::to_path_buf);
    Ok(Folder {
        title: cut_front(&display_path(&canonical), MAX_TITLE_BYTES),
        path: Some(canonical),
        parent,
        entries,
        truncated,
    })
}

/// Take at most `max` items of `items` through `keep`, checking `cancel`
/// before each: what was kept, and whether more items were there (the
/// `max + 1`th is taken from `items` to know, and goes no further).
fn collect<I, T>(
    items: I,
    max: usize,
    cancel: &AtomicBool,
    mut keep: impl FnMut(T) -> Option<Found>,
) -> Result<(Vec<Found>, bool), u16>
where
    I: IntoIterator<Item = T>,
{
    let mut found = Vec::new();
    for (read, item) in items.into_iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            return Err(reason::IO);
        }
        if read == max {
            return Ok((found, true));
        }
        if let Some(entry) = keep(item) {
            found.push(entry);
        }
    }
    Ok((found, false))
}

/// A canonical path for display: on Windows without the verbatim prefix of
/// a drive path.
fn display_path(canonical: &Path) -> String {
    let shown = canonical.to_string_lossy();
    if windows_drive_root(&shown).is_some() {
        shown[4..].to_owned()
    } else {
        shown.into_owned()
    }
}

/// `text` cut to at most `max` bytes at its front, on a character boundary,
/// with "…" where it was cut.
pub(crate) fn cut_front(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let keep = max.saturating_sub('…'.len_utf8());
    let mut start = text.len() - keep;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    format!("…{}", &text[start..])
}

/// `text` cut to at most `max` bytes at its end, on a character boundary.
pub(crate) fn cut_end(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

// --- What the viewer shows ----------------------------------------------------

/// What an entry of a listing is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A folder (it opens).
    Folder,
    /// A regular file (it downloads, or is sent).
    File,
    /// Anything else: a device, a pipe, a link that does not resolve, an
    /// entry whose details could not be read.
    Other,
}

impl EntryKind {
    fn of(code: u8) -> Self {
        match code {
            kind::FOLDER => Self::Folder,
            kind::FILE => Self::File,
            _ => Self::Other,
        }
    }
}

/// One entry of a listing, as the viewer shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryView {
    /// Its name, for display only: without control or invisible characters,
    /// at most 255 bytes. The handle names the real file.
    pub name: Untrusted,
    /// What [`super::ViewerOp`] names it by: a remote handle
    /// (`OpenRemote`, `Download`) or a local one (`OpenLocal`,
    /// `UploadLocal`).
    pub handle: u32,
    /// What it is.
    pub kind: EntryKind,
    /// Its size in bytes, for a file.
    pub size: Option<u64>,
    /// When it was modified, in seconds since 1970 UTC, when known.
    pub mtime: Option<i64>,
    /// The name is shown approximately: it was not valid Unicode, was cut,
    /// or held characters that are not shown.
    pub lossy: bool,
}

impl EntryView {
    /// An entry as a listing says it, its name made fit to show.
    pub(crate) fn of(entry: &Entry) -> Self {
        let name = Untrusted::shown(&entry.name, MAX_NAME_BYTES);
        let changed = name.as_str() != entry.name;
        Self {
            name,
            handle: entry.handle,
            kind: EntryKind::of(entry.kind),
            size: entry.size,
            mtime: entry.mtime,
            lossy: entry.lossy || changed,
        }
    }
}

/// One page of a folder's listing, as the viewer shows it: a page whose
/// [`ListingView::from`] is 0 starts the folder, and later ones add to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingView {
    /// The folder's handle; 0 for the places.
    pub folder: u32,
    /// Where the folder is, for display only: its path on that computer,
    /// cut at the front; empty for the places.
    pub title: Untrusted,
    /// The handle of the folder above ("Up"); 0 when that is the places,
    /// `None` at the places.
    pub parent: Option<u32>,
    /// The index of this page's first entry.
    pub from: u32,
    /// This page's entries: folders first, then by name.
    pub entries: Vec<EntryView>,
    /// More pages follow (they are asked for without a word from the user).
    pub more: bool,
    /// The folder holds more entries than are listed: "Only the first
    /// 10,000 items are shown."
    pub truncated: bool,
}

/// The view of the whole of a local `folder`, its handles issued from
/// `handles`.
pub(crate) fn local_view(folder: &Folder, handle: u32, handles: &mut Handles) -> ListingView {
    let entries = folder
        .entries
        .iter()
        .map(|found| {
            let (name, lossy) = found.shown_name();
            EntryView::of(&Entry {
                handle: handles.issue(&found.path(folder.path.as_deref())),
                name,
                kind: found.kind,
                size: found.size,
                mtime: found.mtime,
                lossy,
            })
        })
        .collect();
    ListingView {
        folder: handle,
        title: Untrusted::shown(&folder.title, MAX_TITLE_BYTES),
        parent: folder.path.as_ref().map(|_| {
            folder
                .parent
                .as_deref()
                .map_or(0, |parent| handles.issue(parent))
        }),
        from: 0,
        entries,
        more: false,
        truncated: folder.truncated,
    }
}

// --- The viewer's own files -------------------------------------------------

/// What a local listing reports: the request it answers, the folder's
/// handle, and the folder or why not.
#[derive(Debug)]
pub(crate) struct LocalDone {
    seq: u64,
    folder: u32,
    result: Result<Folder, u16>,
}

/// The viewer's own files, as "Send files" browses them (design §5.2): the
/// same rules over the viewer's own places and deny-list, and handles of its
/// own. One listing runs at a time: a newer one stops the one before, whose
/// answer is dropped.
pub(crate) struct LocalFiles {
    access: Arc<Access>,
    handles: Handles,
    max_entries: usize,
    timeout: Duration,
    seq: u64,
    cancel: Option<Arc<AtomicBool>>,
    done: mpsc::UnboundedSender<LocalDone>,
}

impl fmt::Debug for LocalFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalFiles")
            .field("access", &self.access)
            .field("handles", &self.handles)
            .finish_non_exhaustive()
    }
}

impl LocalFiles {
    /// The viewer's files under `access`, listed within `limits`' bounds
    /// (`max_entries`, `list_timeout`, `max_handles`); the listings' answers
    /// come on the receiver returned.
    pub(crate) fn new(
        access: Arc<Access>,
        limits: &ServicesLimits,
    ) -> (Self, mpsc::UnboundedReceiver<LocalDone>) {
        let (done, answers) = mpsc::unbounded_channel();
        (
            Self {
                access,
                handles: Handles::new(limits.max_handles),
                max_entries: limits.max_entries,
                timeout: limits.list_timeout,
                seq: 0,
                cancel: None,
                done,
            },
            answers,
        )
    }

    /// List folder `handle` (0: the places) on a blocking thread, within the
    /// listing's timeout (`IO` past it): its answer comes on the receiver.
    /// `Err(NOT_FOUND)` at once for a handle this viewer never gave, or gave
    /// too long ago.
    pub(crate) fn open(&mut self, handle: u32) -> Result<(), u16> {
        let path = match handle {
            0 => None,
            _ => Some(
                self.handles
                    .get(handle)
                    .ok_or(reason::NOT_FOUND)?
                    .to_path_buf(),
            ),
        };
        if let Some(older) = self.cancel.take() {
            older.store(true, Ordering::SeqCst);
        }
        self.seq += 1;
        let (seq, cancel) = (self.seq, Arc::new(AtomicBool::new(false)));
        self.cancel = Some(Arc::clone(&cancel));
        let (access, max, timeout, done) = (
            Arc::clone(&self.access),
            self.max_entries,
            self.timeout,
            self.done.clone(),
        );
        let stop = Arc::clone(&cancel);
        let worker =
            tokio::task::spawn_blocking(move || read_folder(&access, path.as_deref(), max, &stop));
        tokio::spawn(async move {
            let result = match tokio::time::timeout(timeout, worker).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(reason::IO),
                Err(_) => {
                    cancel.store(true, Ordering::SeqCst);
                    Err(reason::IO)
                }
            };
            let _ = done.send(LocalDone {
                seq,
                folder: handle,
                result,
            });
        });
        Ok(())
    }

    /// The path of local handle `handle`, for sending it.
    pub(crate) fn path_of(&self, handle: u32) -> Option<PathBuf> {
        self.handles.get(handle).map(Path::to_path_buf)
    }

    /// A listing's answer: the view to show, or why not; `None` for one a
    /// newer listing replaced.
    pub(crate) fn done(&mut self, done: LocalDone) -> Option<Result<ListingView, u16>> {
        if done.seq != self.seq {
            return None;
        }
        self.cancel = None;
        Some(
            done.result
                .map(|folder| local_view(&folder, done.folder, &mut self.handles)),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// A home with Tornect's state folder in it (marked as `Paths::ensure`
    /// marks it), a second Tornect home elsewhere that only its marker
    /// names, and a folder of the user's.
    struct Tree {
        _top: tempfile::TempDir,
        home: PathBuf,
        state: PathBuf,
        other: PathBuf,
        docs: PathBuf,
    }

    fn tree() -> Tree {
        let top = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(top.path()).unwrap().join("home");
        let state = home.join(".local").join("state").join("tornect");
        let other = home.join("elsewhere").join("h2");
        let docs = home.join("Documents");
        for dir in [&state, &other, &docs] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(state.join(PRIVATE_MARKER), b"").unwrap();
        fs::write(state.join("device.key"), b"secret").unwrap();
        fs::write(other.join(PRIVATE_MARKER), b"").unwrap();
        fs::write(other.join("device.key"), b"secret").unwrap();
        fs::write(docs.join("notes.txt"), b"hello").unwrap();
        Tree {
            _top: top,
            home,
            state,
            other,
            docs,
        }
    }

    fn access(tree: &Tree) -> Access {
        Access::new(
            vec![("Home".into(), tree.home.clone())],
            vec![tree.state.clone()],
        )
    }

    /// The design's test 7, its access part: a folder of the user's and a
    /// file in it pass, and the canonical path is the one returned; a
    /// denied folder, anything under it, another Tornect home (by its marker
    /// alone), a part file, a path outside every place and a path that is
    /// not there do not.
    #[test]
    fn the_rules_pass_the_users_files_and_nothing_of_tornects() {
        let tree = tree();
        let access = access(&tree);
        assert_eq!(access.check(&tree.docs), Ok(tree.docs.clone()));
        let notes = tree.docs.join("notes.txt");
        assert_eq!(access.check(&notes), Ok(notes.clone()));
        // `..` resolves first.
        assert_eq!(
            access.check(
                &tree
                    .state
                    .join("..")
                    .join("..")
                    .join("..")
                    .join("Documents")
            ),
            Ok(tree.docs.clone())
        );
        for denied in [
            tree.state.clone(),
            tree.state.join("device.key"),
            tree.other.clone(),
            tree.other.join("device.key"),
        ] {
            assert_eq!(access.check(&denied), Err(reason::DENIED), "{denied:?}");
        }
        // A part file, found by its name whatever its case.
        fs::write(tree.docs.join("x.bin.tornect-part"), b"").unwrap();
        fs::write(tree.docs.join("y.TORNECT-PART"), b"").unwrap();
        for part in ["x.bin.tornect-part", "y.TORNECT-PART"] {
            assert_eq!(access.check(&tree.docs.join(part)), Err(reason::DENIED));
        }
        // Outside every place.
        let outside = tree.home.parent().unwrap().to_path_buf();
        assert_eq!(access.check(&outside), Err(reason::DENIED));
        assert_eq!(
            access.check(&tree.docs.join("missing")),
            Err(reason::NOT_FOUND)
        );
        // A marker made after the start counts at once.
        fs::write(tree.docs.join(PRIVATE_MARKER), b"").unwrap();
        assert_eq!(access.check(&notes), Err(reason::DENIED));
        assert_eq!(access.check(&tree.docs), Err(reason::DENIED));
        assert_eq!(Access::none().check(&tree.home), Err(reason::DENIED));
        assert_eq!(format!("{access:?}"), "Access { places: 1, denied: 1 }");
    }

    /// A link is followed before the rules apply: a link into the state
    /// folder, or to a part file, is denied; a link to a file of the user's
    /// passes as that file.
    #[cfg(unix)]
    #[test]
    fn links_are_judged_by_what_they_point_to() {
        use std::os::unix::fs::symlink;

        let tree = tree();
        let access = access(&tree);
        let into_state = tree.docs.join("innocent.txt");
        symlink(tree.state.join("device.key"), &into_state).unwrap();
        assert_eq!(access.check(&into_state), Err(reason::DENIED));
        let into_folder = tree.docs.join("folder");
        symlink(&tree.state, &into_folder).unwrap();
        assert_eq!(access.check(&into_folder), Err(reason::DENIED));
        fs::write(tree.docs.join("p.tornect-part"), b"").unwrap();
        let to_part = tree.docs.join("plain.txt");
        symlink(tree.docs.join("p.tornect-part"), &to_part).unwrap();
        assert_eq!(access.check(&to_part), Err(reason::DENIED));
        let fine = tree.docs.join("fine.txt");
        symlink(tree.docs.join("notes.txt"), &fine).unwrap();
        assert_eq!(access.check(&fine), Ok(tree.docs.join("notes.txt")));
        // A link out of every place.
        let out = tempfile::tempdir().unwrap();
        fs::write(out.path().join("o.txt"), b"o").unwrap();
        let away = tree.docs.join("away.txt");
        symlink(out.path().join("o.txt"), &away).unwrap();
        assert_eq!(access.check(&away), Err(reason::DENIED));
    }

    /// Linux's system folders, and `/proc/self/fd/<n>` of an open key file
    /// (which resolves to the file), are denied even under `/`.
    #[cfg(target_os = "linux")]
    #[test]
    fn proc_and_its_fd_links_are_denied() {
        use std::os::fd::AsRawFd as _;

        let tree = tree();
        let mut denied = system_denied();
        assert!(denied.contains(&PathBuf::from("/proc")));
        denied.push(tree.state.clone());
        let access = Access::new(vec![("Computer".into(), PathBuf::from("/"))], denied);
        for path in ["/proc", "/proc/self/environ", "/sys", "/dev/null"] {
            assert_eq!(access.check(Path::new(path)), Err(reason::DENIED), "{path}");
        }
        let key = fs::File::open(tree.state.join("device.key")).unwrap();
        let fd = PathBuf::from(format!("/proc/self/fd/{}", key.as_raw_fd()));
        assert_eq!(access.check(&fd), Err(reason::DENIED));
        assert_eq!(
            access.check(&tree.docs.join("notes.txt")),
            Ok(tree.docs.join("notes.txt"))
        );
    }

    /// The pure form check of Windows paths.
    #[test]
    fn only_verbatim_drive_paths_have_the_windows_form() {
        assert_eq!(windows_drive_root(r"\\?\C:\x"), Some('C'));
        assert_eq!(windows_drive_root(r"\\?\d:\"), Some('D'));
        assert_eq!(windows_drive_root(r"\\?\C:\Users\Bob\file.txt"), Some('C'));
        for refused in [
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\x",
            r"\\?\UNC\localhost\C$\x",
            r"\\?\UNC\wsl$\Ubuntu\home",
            r"\\?\Volume{1b3b1146-4076-11e1-84aa-806e6f6e6963}\x",
            r"\\.\PhysicalDrive0",
            r"\\.\C:\x",
            r"C:x",
            r"C:\x",
            r"\\?\C:",
            r"\\?\C:x",
            r"\\?\1:\x",
            r"//?/C:/x",
            "",
        ] {
            assert_eq!(windows_drive_root(refused), None, "{refused}");
        }
        assert_eq!(display_path(Path::new(r"\\?\C:\Users")), r"C:\Users");
    }

    /// Handles: 0 is never given, one path keeps its handle, the oldest goes
    /// first past the bound, and an evicted handle is unknown.
    #[test]
    fn handles_count_up_and_the_oldest_go_first() {
        let mut handles = Handles::new(2);
        let a = handles.issue(Path::new("/a"));
        let b = handles.issue(Path::new("/b"));
        assert_eq!((a, b), (1, 2));
        assert_eq!(
            handles.issue(Path::new("/a")),
            a,
            "the same path, the same handle"
        );
        assert_eq!(handles.get(0), None);
        let c = handles.issue(Path::new("/c"));
        assert_eq!(c, 3);
        assert_eq!(handles.get(a), None, "evicted");
        assert_eq!(handles.get(b), Some(Path::new("/b")));
        assert_eq!(handles.get(c), Some(Path::new("/c")));
        assert_eq!(
            handles.issue(Path::new("/a")),
            4,
            "a new handle once evicted"
        );
        assert_eq!(format!("{handles:?}"), "Handles { held: 2, max: 2 }");
        // Past `u32::MAX` the count goes round, skipping 0 and handles held.
        let mut handles = Handles::new(4);
        handles.next = u32::MAX - 1;
        assert_eq!(handles.issue(Path::new("/x")), u32::MAX);
        assert_eq!(handles.issue(Path::new("/y")), 1);
    }

    /// The worker lists what may be shown, folders first and then by name
    /// with case ignored, omitting denied folders, folders with the marker
    /// and part files; it names the folder above when that may be shown.
    #[test]
    fn a_folder_lists_what_may_be_shown() {
        let tree = tree();
        let access = access(&tree);
        for name in ["b.txt", "A.txt", "c.tornect-part"] {
            fs::write(tree.home.join(name), b"xy").unwrap();
        }
        fs::create_dir(tree.home.join("Zeta")).unwrap();
        let cancel = AtomicBool::new(false);
        let folder = read_folder(&access, Some(&tree.home), 100, &cancel).unwrap();
        let names: Vec<String> = folder
            .entries
            .iter()
            .map(|found| found.shown_name().0)
            .collect();
        // `.local` holds the state folder but is not one itself.
        assert_eq!(
            names,
            [".local", "Documents", "elsewhere", "Zeta", "A.txt", "b.txt"]
        );
        assert_eq!(folder.entries[4].kind, kind::FILE);
        assert_eq!(folder.entries[4].size, Some(2));
        assert!(folder.entries[4].mtime.is_some());
        assert_eq!(folder.entries[0].size, None);
        assert!(!folder.truncated);
        assert_eq!(folder.parent, None, "the place's root has nothing above");
        assert_eq!(folder.path.as_deref(), Some(tree.home.as_path()));
        assert!(folder.title.ends_with("home"));

        let state_parent = tree.state.parent().unwrap();
        let inner = read_folder(&access, Some(state_parent), 100, &cancel).unwrap();
        assert!(inner.entries.is_empty(), "the state folder is omitted");
        assert_eq!(inner.parent.as_deref(), state_parent.parent());
        let elsewhere =
            read_folder(&access, Some(&tree.home.join("elsewhere")), 100, &cancel).unwrap();
        assert!(elsewhere.entries.is_empty(), "the marked home is omitted");

        assert_eq!(
            read_folder(&access, Some(&tree.state), 100, &cancel).err(),
            Some(reason::DENIED)
        );
        assert_eq!(
            read_folder(&access, Some(&tree.docs.join("notes.txt")), 100, &cancel).err(),
            Some(reason::NOT_FOUND),
            "a file is no folder"
        );
        cancel.store(true, Ordering::SeqCst);
        assert_eq!(
            read_folder(&access, Some(&tree.home), 100, &cancel).err(),
            Some(reason::IO),
            "a cancelled worker stops"
        );
    }

    /// The places are listed in their order, each once, each only while it
    /// passes the rules.
    #[test]
    fn the_places_are_those_that_pass() {
        let tree = tree();
        let access = Access::new(
            vec![
                ("Home".into(), tree.home.clone()),
                ("Documents".into(), tree.docs.clone()),
                ("Again".into(), tree.docs.join("..").join("Documents")),
                ("Gone".into(), tree.home.join("missing")),
                ("State".into(), tree.state.clone()),
            ],
            vec![tree.state.clone()],
        );
        let cancel = AtomicBool::new(false);
        let places = read_folder(&access, None, 100, &cancel).unwrap();
        let names: Vec<String> = places.entries.iter().map(|f| f.shown_name().0).collect();
        assert_eq!(names, ["Home", "Documents"]);
        assert_eq!(places.entries[1].path(None), tree.docs);
        assert!(places.path.is_none() && places.parent.is_none() && places.title.is_empty());
    }

    /// The worker reads at most `max` entries (and one more, to know there
    /// were more), and no further.
    #[test]
    fn the_worker_reads_no_further_than_its_bound() {
        let pulled = AtomicUsize::new(0);
        let items = (0..100).inspect(|_| {
            pulled.fetch_add(1, Ordering::SeqCst);
        });
        let cancel = AtomicBool::new(false);
        let keep = |n: i32| {
            (n % 2 == 0).then(|| Found {
                raw: OsString::from(n.to_string()),
                at: None,
                kind: kind::FILE,
                size: Some(0),
                mtime: None,
            })
        };
        let (found, truncated) = collect(items, 10, &cancel, keep).unwrap();
        assert!(truncated);
        assert_eq!(found.len(), 5, "omitted entries count as read");
        assert_eq!(pulled.load(Ordering::SeqCst), 11);
        let (found, truncated) = collect(0..10, 10, &cancel, keep).unwrap();
        assert!(!truncated);
        assert_eq!(found.len(), 5);
    }

    /// A folder of 10 000 entries lists the first ones only, and says so.
    #[test]
    fn a_huge_folder_is_truncated() {
        let tree = tree();
        let big = tree.home.join("big");
        fs::create_dir(&big).unwrap();
        for n in 0..60 {
            fs::write(big.join(format!("f{n:03}")), b"").unwrap();
        }
        let cancel = AtomicBool::new(false);
        let folder = read_folder(&access(&tree), Some(&big), 50, &cancel).unwrap();
        assert!(folder.truncated);
        assert_eq!(folder.entries.len(), 50);
    }

    /// A non-UTF-8 name is shown approximately and its path is the real one;
    /// a name over 255 bytes is cut and shown approximately.
    #[cfg(unix)]
    #[test]
    fn odd_names_are_shown_approximately() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        let tree = tree();
        let raw = OsStr::from_bytes(b"caf\xe9.txt");
        fs::write(tree.docs.join(raw), b"latin-1").unwrap();
        let cancel = AtomicBool::new(false);
        let folder = read_folder(&access(&tree), Some(&tree.docs), 100, &cancel).unwrap();
        let odd = folder
            .entries
            .iter()
            .find(|found| found.raw.as_bytes() == raw.as_bytes())
            .unwrap();
        assert_eq!(odd.shown_name(), ("caf\u{fffd}.txt".to_owned(), true));
        assert_eq!(odd.path(folder.path.as_deref()), tree.docs.join(raw));
        let long = Found {
            raw: OsString::from("é".repeat(200)),
            at: None,
            kind: kind::FILE,
            size: Some(0),
            mtime: None,
        };
        let (name, lossy) = long.shown_name();
        assert!(lossy);
        assert_eq!(name.len(), 254, "cut on a character boundary");
    }

    /// Titles are cut at the front, names at the end, on character
    /// boundaries.
    #[test]
    fn cuts_keep_character_boundaries() {
        assert_eq!(cut_front("abcdef", 6), "abcdef");
        assert_eq!(cut_front("abcdef", 5), "…ef");
        assert_eq!(cut_front("ééééé", 7), "…éé");
        assert_eq!(cut_front("ééééé", 8), "…éé", "never inside a character");
        assert_eq!(cut_end("ééé", 5), "éé");
        assert_eq!(cut_end("abc", 3), "abc");
    }
}
