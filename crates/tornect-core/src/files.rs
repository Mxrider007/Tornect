//! Files Tornect writes for the user and the names it gives them (design
//! `services` §5.1): the folder a file goes into, a new private file, the
//! next free name, the words a toast shows for a path, the folders a host
//! offers to browse, the leftovers of a transfer cut short, and the name a
//! file sent by the other computer is stored under.
//!
//! The rules every caller relies on:
//! - A folder Tornect writes into is made this user's only (`0700` on Unix),
//!   and one already there is used only when the entry itself is a folder
//!   (never a link or a junction) of this user (the owner is checked where
//!   the process can know it, on Linux).
//! - A file is always new (`create_new`), never written over, and this
//!   user's only (`0600` on Unix).
//! - What a person is shown names the last few folders of a path, never the
//!   absolute path, which holds the account's home folder.
//! - A name from the other computer passes [`sanitize_name`] before it
//!   touches the disk.
//! - Nothing here logs a path or a name.
//!
//! The stream window's screenshots use the folder, file and name helpers;
//! the services' inbox and the viewer's downloads use all of them.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use directories::UserDirs;

use crate::trusted::is_invisible_or_control;

/// The empty file that marks a folder as Tornect's own: [`Paths::ensure`]
/// writes it into each of the four Tornect directories at every start, so
/// any Tornect home (another `TORNECT_HOME` included) marks itself, and the
/// host never lists or serves a path under a folder that holds it.
///
/// [`Paths::ensure`]: crate::paths::Paths::ensure
pub const PRIVATE_MARKER: &str = ".tornect-private";

/// The suffix of a file still being received: `<final name>.tornect-part`
/// beside the empty reservation of its final name.
pub const PART_SUFFIX: &str = ".tornect-part";

/// The longest name [`sanitize_name`] gives, in bytes. With [`nth`]'s
/// `" (999)"` it stays within the 255 bytes most file systems allow.
pub const MAX_NAME_BYTES: usize = 200;

/// The longest extension, dot included, that [`sanitize_name`] keeps when it
/// cuts a long name and that [`nth`] numbers before; a longer "extension" is
/// part of the name.
pub const MAX_EXTENSION_BYTES: usize = 16;

/// How long a part file must have been left untouched before
/// [`sweep_stale`] takes it for a crash's leftover (design §5.1: writes
/// touch the file, and a transfer that stalls 30 s is ended).
pub const STALE_AFTER: Duration = Duration::from_secs(600);

/// The words between the folders [`shown`] names.
pub const SHOWN_SEPARATOR: &str = " › ";

/// Where files the other computer sends, and files this viewer downloads,
/// go: `Tornect` in the platform's Downloads folder (Linux
/// `XDG_DOWNLOAD_DIR`, macOS `~/Downloads`, Windows `FOLDERID_Downloads`);
/// `None` when the platform names none. `TORNECT_HOME` does not move it: a
/// received file is the user's, not Tornect's state.
#[must_use]
pub fn downloads_dir() -> Option<PathBuf> {
    let user = UserDirs::new()?;
    Some(user.download_dir()?.join("Tornect"))
}

/// The folders a host offers first when the other computer browses, and the
/// viewer's own "Send files" list starts from: Home, Desktop, Documents and
/// Downloads, as far as the platform names them, each an absolute path to a
/// folder that is there now, and each folder once (the first name wins, so a
/// Downloads folder set to the home folder is listed as Home only). The
/// caller adds `/` or the fixed drives.
#[must_use]
pub fn user_places() -> Vec<(String, PathBuf)> {
    let Some(user) = UserDirs::new() else {
        return Vec::new();
    };
    places(&[
        ("Home", Some(user.home_dir())),
        ("Desktop", user.desktop_dir()),
        ("Documents", user.document_dir()),
        ("Downloads", user.download_dir()),
    ])
    .into_iter()
    .filter(|(_, path)| path.is_dir())
    .collect()
}

/// The places named in `found`, in order, without the ones the platform did
/// not name, relative paths, and repeats of an earlier place's path.
fn places(found: &[(&str, Option<&Path>)]) -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    for (name, path) in found {
        let Some(path) = path else { continue };
        if !path.is_absolute() || out.iter().any(|(_, seen)| seen == path) {
            continue;
        }
        out.push(((*name).to_owned(), path.to_path_buf()));
    }
    out
}

/// Where `name`'s extension starts: its last dot, when that dot is not the
/// first character and the extension, dot included, is at most
/// [`MAX_EXTENSION_BYTES`] long.
fn extension_at(name: &str) -> Option<usize> {
    let at = name.rfind('.')?;
    (at > 0 && name.len() - at <= MAX_EXTENSION_BYTES).then_some(at)
}

/// The `n`th name for a file first named `first`: `first` itself for 1 (and
/// 0), then `"name (2).ext"`, `"name (3).ext"` …, the number before the
/// extension (see [`MAX_EXTENSION_BYTES`]) or at the end when there is none.
/// A caller tries 1, 2, … until a new file can be made.
#[must_use]
pub fn nth(first: &str, n: u32) -> String {
    if n <= 1 {
        return first.to_owned();
    }
    match extension_at(first) {
        Some(at) => format!("{} ({n}){}", &first[..at], &first[at..]),
        None => format!("{first} ({n})"),
    }
}

/// Make the folder `dir` if it is missing (on Unix this user's only:
/// `0700`), or take the one there: only a real folder, never a link or a
/// junction, and on Unix one of this user (the owner is checked where it is
/// known, on Linux); never re-moded. Its parent must be there already:
/// nothing else is made.
pub fn user_folder(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    let made = {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new().mode(0o700).create(dir)
    };
    #[cfg(not(unix))]
    let made = fs::create_dir(dir);
    match made {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => existing(dir),
        Err(e) => Err(e),
    }
}

/// A folder that is already there: the entry itself (so never what a link
/// points to) must be a folder and, on Unix, this user's.
fn existing(dir: &Path) -> io::Result<()> {
    let found = fs::symlink_metadata(dir)?;
    #[cfg(unix)]
    let fits = {
        use std::os::unix::fs::MetadataExt as _;
        may_hold(found.file_type().is_dir(), found.uid(), this_user()?)
    };
    // On Windows a symbolic link or a junction is not `is_dir` here (it is a
    // name-surrogate reparse point), so neither is followed.
    #[cfg(not(unix))]
    let fits = found.file_type().is_dir();
    if fits {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not a folder of this user",
        ))
    }
}

/// Whether a folder found where files go may hold them: a folder itself
/// (`is_dir` of the entry, not of what a link points to) owned by this user
/// (`me`), where this user is known.
#[cfg(unix)]
fn may_hold(is_dir: bool, owner: u32, me: Option<u32>) -> bool {
    is_dir && me.is_none_or(|me| me == owner)
}

/// This process's user: on Linux the owner of `/proc/self` (proc(5)); an
/// error when it cannot be read, so nothing is written then.
#[cfg(target_os = "linux")]
fn this_user() -> io::Result<Option<u32>> {
    use std::os::unix::fs::MetadataExt as _;
    fs::metadata("/proc/self").map(|m| Some(m.uid()))
}

/// This process's user, on a Unix system without `/proc/self`: not known,
/// so only the link check holds there.
#[cfg(all(unix, not(target_os = "linux")))]
fn this_user() -> io::Result<Option<u32>> {
    Ok(None)
}

/// A new file at `path` for writing, never over another one (an entry
/// already there, a link included, is `AlreadyExists`); on Unix this
/// user's only (`0600`).
pub fn create_new_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Write [`PRIVATE_MARKER`] into `dir` (an empty file, `0600` on Unix),
/// unless an entry of that name is there already, which is left as it is.
pub fn mark_private(dir: &Path) -> io::Result<()> {
    match create_new_private(&dir.join(PRIVATE_MARKER)) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// The names of the last `keep` folders and file of `path`, outermost
/// first: only its plain names, never a root, a drive or `..`.
#[must_use]
pub fn last_names(path: &Path, keep: usize) -> Vec<String> {
    let names: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    names[names.len().saturating_sub(keep)..].to_vec()
}

/// The words for where `path` is: its last `keep` names joined with
/// [`SHOWN_SEPARATOR`], such as "Downloads › Tornect › report.pdf"; never
/// the absolute path, which holds the account's home folder.
#[must_use]
pub fn shown(path: &Path, keep: usize) -> String {
    last_names(path, keep).join(SHOWN_SEPARATOR)
}

/// Where the file that will be `final_path` is written while it arrives:
/// the same name with [`PART_SUFFIX`].
#[must_use]
pub fn part_of(final_path: &Path) -> PathBuf {
    let mut name = final_path.as_os_str().to_os_string();
    name.push(PART_SUFFIX);
    PathBuf::from(name)
}

/// Whether `name` is a part file's name: it ends with [`PART_SUFFIX`],
/// ASCII case ignored (a case-insensitive file system holds the same file
/// under any case). The host never lists or serves one.
#[must_use]
pub fn is_part_name(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    bytes.len() >= PART_SUFFIX.len()
        && bytes[bytes.len() - PART_SUFFIX.len()..].eq_ignore_ascii_case(PART_SUFFIX.as_bytes())
}

/// Delete the leftovers of transfers a crash cut short in `dir`: every
/// regular file named `X.tornect-part` (exactly that suffix) not modified
/// for longer than `older_than` ([`STALE_AFTER`]), and with it `X` when `X`
/// is an empty regular file that old too, the reservation the pair made.
/// A part file still being written (its time moves with every write), a
/// user's own empty file without a part file, links and folders are kept.
/// `dir` itself must be a real folder (not a link); the caller checks it is
/// this user's with [`user_folder`] first. Returns how many part files went;
/// one that cannot be deleted is skipped.
pub fn sweep_stale(dir: &Path, older_than: Duration) -> io::Result<usize> {
    sweep_stale_at(dir, older_than, SystemTime::now())
}

/// [`sweep_stale`] at the time `now`.
fn sweep_stale_at(dir: &Path, older_than: Duration, now: SystemTime) -> io::Result<usize> {
    if !fs::symlink_metadata(dir)?.file_type().is_dir() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a folder"));
    }
    let old = |meta: &fs::Metadata| {
        meta.modified()
            .ok()
            .and_then(|at| now.duration_since(at).ok())
            .is_some_and(|age| age > older_than)
    };
    let mut removed = 0;
    for entry in fs::read_dir(dir)?.flatten() {
        let name = entry.file_name();
        let Some(reserved) = name.to_str().and_then(|n| n.strip_suffix(PART_SUFFIX)) else {
            continue;
        };
        // `DirEntry::metadata` does not follow a link.
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.file_type().is_file() || !old(&meta) || fs::remove_file(entry.path()).is_err() {
            continue;
        }
        removed += 1;
        if reserved.is_empty() {
            continue;
        }
        let reservation = dir.join(reserved);
        if let Ok(meta) = fs::symlink_metadata(&reservation)
            && meta.file_type().is_file()
            && meta.len() == 0
            && old(&meta)
        {
            let _ = fs::remove_file(&reservation);
        }
    }
    Ok(removed)
}

/// Windows device names: a file named one of them, with or without an
/// extension, opens the device instead.
const RESERVED_STEMS: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];

/// Whether `name` would be a Windows device: the part before its first dot,
/// trailing spaces ignored, is `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`,
/// `CONOUT$`, or `COM`/`LPT` with one digit 0–9 or a superscript ¹ ² ³, in
/// any ASCII case.
fn reserved_on_windows(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    if RESERVED_STEMS.contains(&upper.as_str()) {
        return true;
    }
    let Some(number) = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
    else {
        return false;
    };
    let mut chars = number.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some('0'..='9' | '¹' | '²' | '³'), None)
    )
}

/// The longest prefix of `s` that is at most `max` bytes and ends on a
/// character boundary.
fn cut_at(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Whether `c` is trimmed from both ends of a name: a dot (a leading one
/// hides the file, a trailing one Windows drops) or white space.
fn trimmed(c: char) -> bool {
    c == '.' || c.is_whitespace()
}

/// `name`, trimmed at both ends already, cut to at most `max` bytes on a
/// character boundary when it is longer, keeping an extension of at most
/// [`MAX_EXTENSION_BYTES`], with dots and white space the cut leaves at its
/// end trimmed. `max` is more than an extension, so the result is never
/// empty and starts as `name` does.
fn fit(name: &str, max: usize) -> String {
    if name.len() <= max {
        return name.to_owned();
    }
    match extension_at(name) {
        // The stem is longer than the room left, so the cut is inside it,
        // and the extension's end was trimmed already.
        Some(at) => {
            let extension = &name[at..];
            let stem = cut_at(&name[..at], max - extension.len());
            format!("{stem}{extension}")
        }
        None => cut_at(name, max).trim_end_matches(trimmed).to_owned(),
    }
}

/// The name a file sent by the other computer is stored under, or `None`
/// (the services' `BAD_NAME`) when nothing is left. In this order:
/// 1. the last part after a `/` or `\`, so no folder of the name is used;
/// 2. every character [`is_invisible_or_control`] matches is dropped (C0
///    and C1 controls, bidi controls, zero-width and other invisible
///    characters, U+FEFF);
/// 3. `< > : " | ? *` become `_`;
/// 4. dots and white space are trimmed at both ends, so no name is hidden,
///    `.` or `..`, or aliased by a trailing dot on Windows;
/// 5. a name over [`MAX_NAME_BYTES`] is cut there on a character boundary,
///    keeping an extension of at most [`MAX_EXTENSION_BYTES`], and dots and
///    white space the cut leaves at the end are trimmed;
/// 6. when the cut name is a Windows device name (`CON`, `PRN`, `AUX`,
///    `NUL`, `CONIN$`, `CONOUT$`, `COM0`–`COM9`, `LPT0`–`LPT9`, `COM¹²³`,
///    `LPT¹²³`, any case, with or without an extension), the name is cut
///    one byte shorter instead and gets a leading `_`.
///
/// The device check runs on the cut name because the cut and its trim can
/// make one: `"CON"`, 300 spaces and `"x"` is cut to `"CON"`. Applying it to
/// its own result gives that result again.
#[must_use]
pub fn sanitize_name(raw: &str) -> Option<String> {
    let last = raw.rsplit(['/', '\\']).next().unwrap_or_default();
    let visible: String = last
        .chars()
        .filter(|c| !is_invisible_or_control(*c))
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c => c,
        })
        .collect();
    let name = visible.trim_matches(trimmed);
    if name.is_empty() {
        return None;
    }
    let fitted = fit(name, MAX_NAME_BYTES);
    if !reserved_on_windows(&fitted) {
        return Some(fitted);
    }
    // A name that starts with `_` is never a device name, so the prefixed
    // result passes again unchanged.
    Some(format!("_{}", fit(name, MAX_NAME_BYTES - 1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    /// Every file and folder under `root`, relative to it, sorted.
    fn listing(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut todo = vec![root.to_path_buf()];
        while let Some(dir) = todo.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if fs::symlink_metadata(&path).unwrap().is_dir() {
                    todo.push(path.clone());
                }
                out.push(path.strip_prefix(root).unwrap().to_path_buf());
            }
        }
        out.sort();
        out
    }

    /// The design's §10 cases: no folder of the name survives, nothing
    /// invisible, no Windows device, nothing hidden, and long names are cut
    /// keeping their extension.
    #[test]
    fn names_from_the_other_computer_are_made_safe() {
        for (raw, want) in [
            ("../x", Some("x")),
            ("..\\x", Some("x")),
            ("/etc/passwd", Some("passwd")),
            ("C:\\Windows\\x", Some("x")),
            ("C:x", Some("C_x")),
            ("CON", Some("_CON")),
            ("con.txt", Some("_con.txt")),
            ("Con .tar.gz", Some("_Con .tar.gz")),
            ("COM¹.log", Some("_COM¹.log")),
            ("lpt9", Some("_lpt9")),
            ("COM0", Some("_COM0")),
            ("conin$", Some("_conin$")),
            ("COM10", Some("COM10")),
            ("CONSOLE.txt", Some("CONSOLE.txt")),
            ("NULL", Some("NULL")),
            (".bashrc", Some("bashrc")),
            ("a\u{202e}gpj.exe", Some("agpj.exe")),
            ("a\u{200b}b", Some("ab")),
            ("\u{115F}x", Some("x")),
            ("\u{feff}report.pdf", Some("report.pdf")),
            ("line\nbreak\t.txt", Some("linebreak.txt")),
            ("name. . ", Some("name")),
            ("  name.txt  ", Some("name.txt")),
            ("a<b>c:d\"e|f?g*h", Some("a_b_c_d_e_f_g_h")),
            ("file.txt:Zone.Identifier", Some("file.txt_Zone.Identifier")),
            ("", None),
            (".", None),
            ("..", None),
            ("...", None),
            (" . ", None),
            ("dir/", None),
            ("\u{202e}\u{200b}", None),
            ("x/\u{feff}", None),
        ] {
            assert_eq!(sanitize_name(raw).as_deref(), want, "{raw:?}");
        }

        // A long name the cut and the trim turn into a device name: the
        // check runs on the cut name, the prefix still fits, and the result
        // is its own sanitised form.
        let spaces = |n: usize| " ".repeat(n);
        for (raw, want) in [
            (format!("CON{}x", spaces(300)), "_CON".to_owned()),
            (format!("NUL{}x", spaces(250)), "_NUL".to_owned()),
            (
                format!("COM1{}x.thisisaverylongextension", spaces(200)),
                "_COM1".to_owned(),
            ),
            (
                format!("aux{}{}", spaces(197), "z".repeat(20)),
                "_aux".to_owned(),
            ),
            (format!("CON{}x", "\u{3000}".repeat(100)), "_CON".to_owned()),
            (
                format!("CON{}x.txt", spaces(240)),
                format!("_CON{}.txt", spaces(192)),
            ),
            (
                format!("COM3{}x.log", spaces(200)),
                format!("_COM3{}.log", spaces(191)),
            ),
            (format!("CON{}x", spaces(197)), "_CON".to_owned()),
            // 200 bytes: not cut, and not a device name as it is.
            (
                format!("CON{}x", spaces(196)),
                format!("CON{}x", spaces(196)),
            ),
        ] {
            let name = sanitize_name(&raw).unwrap();
            assert_eq!(name, want, "{raw:?}");
            assert!(name.len() <= MAX_NAME_BYTES, "{name:?}");
            assert!(!reserved_on_windows(&name), "{name:?}");
            assert_eq!(sanitize_name(&name), Some(name.clone()), "{name:?}");
        }
    }

    /// A name over 200 bytes is cut on a character boundary and keeps an
    /// extension of at most 16 bytes; a longer one is cut like the rest.
    #[test]
    fn long_names_are_cut_keeping_the_extension() {
        let long = format!("{}.tar.gz", "a".repeat(300));
        let cut = sanitize_name(&long).unwrap();
        assert_eq!(cut.len(), MAX_NAME_BYTES);
        assert!(cut.ends_with("a.gz"), "{cut}");
        assert_eq!(cut, format!("{}.gz", "a".repeat(197)));

        // Four-byte characters: the cut never splits one.
        let wide = format!("{}.txt", "😀".repeat(80));
        let cut = sanitize_name(&wide).unwrap();
        assert!(
            cut.len() <= MAX_NAME_BYTES && cut.ends_with("😀.txt"),
            "{cut}"
        );
        assert_eq!(cut, format!("{}.txt", "😀".repeat(49)));

        // No extension worth keeping: cut, and a trailing space or dot left
        // at the cut is trimmed.
        let odd = format!("{}.{}", "b".repeat(150), "c".repeat(100));
        let cut = sanitize_name(&odd).unwrap();
        assert_eq!(cut.len(), MAX_NAME_BYTES);
        assert!(cut.starts_with(&"b".repeat(150)), "{cut}");
        let spaced = format!("{} {}", "d".repeat(199), "e".repeat(50));
        assert_eq!(sanitize_name(&spaced).unwrap(), "d".repeat(199));

        // 300 bytes of a device name's extension: the prefix, then the cut.
        let device = format!("CON.{}", "f".repeat(300));
        let cut = sanitize_name(&device).unwrap();
        assert!(cut.starts_with("_CON.ff"), "{cut}");
        assert_eq!(cut.len(), MAX_NAME_BYTES);
        assert_eq!(sanitize_name(&cut).as_deref(), Some(cut.as_str()));
    }

    /// `nth` numbers before an extension of at most 16 bytes, at the end
    /// otherwise, and leaves the first name as it is.
    #[test]
    fn nth_keeps_the_extension() {
        assert_eq!(nth("report.pdf", 1), "report.pdf");
        assert_eq!(nth("report.pdf", 0), "report.pdf");
        assert_eq!(nth("report.pdf", 2), "report (2).pdf");
        assert_eq!(nth("archive.tar.gz", 3), "archive.tar (3).gz");
        assert_eq!(nth("README", 999), "README (999)");
        assert_eq!(nth("bashrc", 2), "bashrc (2)");
        assert_eq!(nth(".hidden", 2), ".hidden (2)");
        assert_eq!(
            nth("notes.a very long extension", 2),
            "notes.a very long extension (2)"
        );
        assert_eq!(
            nth("Tornect screenshot 2026-10-08 07-30-05.png", 4),
            "Tornect screenshot 2026-10-08 07-30-05 (4).png"
        );
        let longest = sanitize_name(&"g".repeat(400)).unwrap();
        assert!(nth(&longest, 999).len() <= 255);
    }

    /// `shown` and `last_names` name the last folders and the file only,
    /// never a root, a drive or the absolute path.
    #[test]
    fn shown_names_no_absolute_path() {
        let path = Path::new("/home/someone/Downloads/Tornect/report.pdf");
        assert_eq!(shown(path, 3), "Downloads › Tornect › report.pdf");
        assert_eq!(shown(path, 2), "Tornect › report.pdf");
        assert_eq!(last_names(path, 3), ["Downloads", "Tornect", "report.pdf"]);
        assert_eq!(shown(Path::new("/a.png"), 3), "a.png");
        assert_eq!(shown(Path::new("Tornect/a.png"), 3), "Tornect › a.png");
        assert_eq!(shown(Path::new("/"), 3), "");
        assert_eq!(shown(Path::new("/a/../b/c"), 3), "a › b › c");
        assert!(!shown(path, 3).contains("someone"));
        assert!(!shown(path, 3).contains('/'));
    }

    /// The places: in order, each named once, the ones not named and
    /// relative paths left out.
    #[test]
    fn places_are_absolute_and_listed_once() {
        let home = std::env::temp_dir().join("u");
        let docs = home.join("Documents");
        let found = places(&[
            ("Home", Some(home.as_path())),
            ("Desktop", None),
            ("Documents", Some(docs.as_path())),
            ("Downloads", Some(home.as_path())),
            ("Odd", Some(Path::new("relative/dir"))),
        ]);
        assert_eq!(
            found,
            [
                ("Home".to_owned(), home.clone()),
                ("Documents".to_owned(), docs)
            ]
        );
        // The real ones, where this machine names any: absolute folders.
        for (name, path) in user_places() {
            assert!(path.is_absolute() && path.is_dir(), "{name}");
        }
        if let Some(dir) = downloads_dir() {
            assert!(dir.ends_with("Tornect"));
        }
    }

    /// `user_folder` makes a missing folder this user's only, takes a real
    /// folder of this user as it is, and refuses a link (even to a folder of
    /// this user), a file and a missing parent, writing nothing.
    #[test]
    fn a_user_folder_is_made_private_or_must_be_a_real_folder() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Tornect");
        user_folder(&dir).unwrap();
        assert!(dir.is_dir());
        user_folder(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
            user_folder(&dir).unwrap();
            assert_eq!(mode(&dir), 0o750, "never re-moded");

            let elsewhere = root.path().join("elsewhere");
            fs::create_dir(&elsewhere).unwrap();
            let link = root.path().join("link");
            std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
            assert!(user_folder(&link).is_err());
        }
        let file = root.path().join("file");
        fs::write(&file, b"x").unwrap();
        assert!(user_folder(&file).is_err());
        let before = listing(root.path());
        assert!(user_folder(&root.path().join("missing").join("Tornect")).is_err());
        assert_eq!(listing(root.path()), before);
    }

    /// The owner rule of an existing folder (moved here with the
    /// screenshot's folder check).
    #[cfg(unix)]
    #[test]
    fn only_a_folder_of_this_user_may_hold_files() {
        assert!(may_hold(true, 1000, Some(1000)));
        assert!(may_hold(true, 1000, None));
        assert!(!may_hold(true, 1001, Some(1000)), "another user's");
        assert!(!may_hold(false, 1000, Some(1000)), "a link or a file");
    }

    /// A new private file is new: never over a file or through a link, and
    /// on Unix `0600`.
    #[test]
    fn a_new_private_file_is_never_written_over() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("a.txt");
        create_new_private(&path).unwrap();
        let again = create_new_private(&path).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let target = root.path().join("target");
            let link = root.path().join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let through = create_new_private(&link).unwrap_err();
            assert_eq!(through.kind(), io::ErrorKind::AlreadyExists);
            assert!(!target.exists(), "nothing made through the link");
        }
    }

    /// The marker is an empty private file, made once: a second call, or
    /// one where the name is taken, changes nothing.
    #[test]
    fn the_marker_is_written_once() {
        let root = tempfile::tempdir().unwrap();
        mark_private(root.path()).unwrap();
        let marker = root.path().join(PRIVATE_MARKER);
        assert_eq!(fs::read(&marker).unwrap(), b"");
        fs::write(&marker, b"kept").unwrap();
        mark_private(root.path()).unwrap();
        assert_eq!(fs::read(&marker).unwrap(), b"kept");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&marker).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(mark_private(&root.path().join("missing")).is_err());
    }

    /// The part file's name and its check.
    #[test]
    fn part_files_are_named_and_known_by_their_suffix() {
        let part = part_of(Path::new("/in/report.pdf"));
        assert_eq!(part, Path::new("/in/report.pdf.tornect-part"));
        assert!(is_part_name(part.file_name().unwrap()));
        assert!(is_part_name(OsStr::new("x.TORNECT-PART")));
        assert!(is_part_name(OsStr::new(".tornect-part")));
        assert!(!is_part_name(OsStr::new("x.tornect-par")));
        assert!(!is_part_name(OsStr::new("x.tornect-part.txt")));
        assert!(!is_part_name(OsStr::new("")));
        // A name never sanitises into the suffix's own form.
        assert_eq!(
            sanitize_name("a.tornect-part").as_deref(),
            Some("a.tornect-part")
        );
    }

    /// Set the modification time of `path` to `at`.
    fn touch(path: &Path, at: SystemTime) {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(at)
            .unwrap();
    }

    /// The sweep removes an old part file and its empty reservation, and
    /// keeps a fresh pair, a lone empty file of the user, a reservation
    /// that is not empty, an old part file's link and folder, and anything
    /// that only looks like a part file.
    #[test]
    fn the_sweep_removes_only_stale_pairs() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Tornect");
        user_folder(&dir).unwrap();
        let now = SystemTime::now();
        let old = now - Duration::from_secs(3600);
        let file = |name: &str, bytes: &[u8], at: SystemTime| {
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap();
            touch(&path, at);
        };
        file("stale.pdf", b"", old);
        file("stale.pdf.tornect-part", b"half", old);
        file("fresh.pdf", b"", old);
        file(
            "fresh.pdf.tornect-part",
            b"half",
            now - Duration::from_secs(60),
        );
        file("mine.txt", b"", old);
        file("full.pdf", b"theirs", old);
        file("full.pdf.tornect-part", b"half", old);
        file("lone.bin.tornect-part", b"half", old);
        file("young.txt", b"", now);
        file("young.txt.tornect-part", b"half", old);
        file("x.tornect-part.txt", b"", old);
        fs::create_dir(dir.join("folder.tornect-part")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("mine.txt"), dir.join("link.tornect-part")).unwrap();

        let removed = sweep_stale_at(&dir, STALE_AFTER, now).unwrap();
        assert_eq!(removed, 4);
        let left: Vec<String> = listing(&dir)
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let mut want = vec![
            "folder.tornect-part",
            "fresh.pdf",
            "fresh.pdf.tornect-part",
            "full.pdf",
            "mine.txt",
            "x.tornect-part.txt",
            "young.txt",
        ];
        if cfg!(unix) {
            want.push("link.tornect-part");
        }
        want.sort_unstable();
        assert_eq!(left, want);
        assert_eq!(fs::read(dir.join("full.pdf")).unwrap(), b"theirs");

        // A time in the future is never stale; nor is the real clock's now.
        file("ahead.tornect-part", b"", now + Duration::from_secs(3600));
        assert_eq!(sweep_stale(&dir, STALE_AFTER).unwrap(), 0);
        assert!(dir.join("ahead.tornect-part").exists());
    }

    /// The sweep refuses a folder that is a link, or a file, and deletes
    /// nothing through it.
    #[test]
    fn the_sweep_needs_a_real_folder() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        fs::write(&file, b"").unwrap();
        assert!(sweep_stale(&file, Duration::ZERO).is_err());
        assert!(sweep_stale(&root.path().join("missing"), Duration::ZERO).is_err());
        #[cfg(unix)]
        {
            let real = root.path().join("real");
            fs::create_dir(&real).unwrap();
            let part = real.join("x.tornect-part");
            fs::write(&part, b"").unwrap();
            touch(&part, SystemTime::now() - Duration::from_secs(3600));
            let link = root.path().join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert!(sweep_stale(&link, Duration::ZERO).is_err());
            assert!(part.exists());
        }
    }

    /// Names as the other computer might send them: any characters, the
    /// characters the rules act on, device names with odd endings, and
    /// device names padded past the cut.
    fn raw_names() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::collection::vec(any::<char>(), 0..80).prop_map(String::from_iter),
            "[./\\\\ a-zA-Z0-9\u{202e}\u{200b}\u{feff}\u{a0}\n:*<|¹$]{0,300}",
            "(CON|con|COM¹|LPT3|NUL|conin\\$|Aux)[ .]{0,3}(\\.[a-z ]{0,5}){0,2}",
            "(CON|NUL|COM1|aux|LPT¹)[ \u{3000}\u{a0}.]{150,260}[a-z]{0,30}(\\.[a-z]{1,4})?",
        ]
    }

    proptest! {
        /// The properties of §10: no separator, nothing invisible, at most
        /// 200 bytes, never `.` or `..` or hidden, no Windows device, and
        /// the same result again when applied to its own result.
        #[test]
        fn sanitized_names_hold_their_rules(raw in raw_names()) {
            if let Some(name) = sanitize_name(&raw) {
                prop_assert!(!name.is_empty());
                prop_assert!(name.len() <= MAX_NAME_BYTES);
                prop_assert!(!name.contains(['/', '\\', '<', '>', ':', '"', '|', '?', '*']));
                prop_assert!(!name.chars().any(is_invisible_or_control));
                prop_assert!(!name.starts_with(trimmed) && !name.ends_with(trimmed));
                prop_assert!(name != "." && name != "..");
                prop_assert!(!reserved_on_windows(&name));
                prop_assert_eq!(sanitize_name(&name), Some(name.clone()));
            }
        }

        /// Arbitrary long names, many of them with extensions and wide
        /// characters, stay within the bound and are idempotent.
        #[test]
        fn long_sanitized_names_are_idempotent(
            stem in "[a-zé😀 .]{150,260}",
            ext in "[a-z]{0,20}",
        ) {
            let raw = format!("{stem}.{ext}");
            if let Some(name) = sanitize_name(&raw) {
                prop_assert!(name.len() <= MAX_NAME_BYTES);
                prop_assert_eq!(sanitize_name(&name), Some(name.clone()));
            }
        }
    }
}
