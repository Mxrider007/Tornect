//! The stream window's screenshot: the last decoded picture as a PNG in the
//! `Tornect` folder of the Pictures folder, named by the time alone,
//! "Tornect screenshot YYYY-MM-DD HH-MM-SS.png" in UTC (the address book's
//! days are UTC too), never by the host's name or ID. Nothing but the picture
//! goes into the file: no text, time or Exif chunk. The window saves on a
//! thread of its own and says where the file went from the Pictures folder's
//! own name on, never the absolute path (it holds the account's home folder),
//! and nothing while this screen is shared. Nothing here logs the folder, the
//! path or the name. The folder, the file and the names come from
//! `tornect_core::files`: on Unix the folder it makes and every file are this
//! user's only (`0700`, `0600`); a folder already there is used only when it
//! is a real folder, not a link (nor, on Windows, a junction), of this user
//! (the owner is checked on Linux); on Windows the folder inherits the
//! account's permissions.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tornect_core::address_book::Day;
use tornect_core::files;

use super::stream::Picture;

/// The toast when a screenshot could not be saved: it names nothing.
pub const NOT_SAVED: &str = "The screenshot could not be saved.";

/// How many files one second may name: the first, then " (2)" up to this.
const SAME_SECOND: u32 = 1000;

/// The name of a screenshot taken at `now`: the time in UTC and nothing else.
#[must_use]
pub fn file_name(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let of_day = secs % 86_400;
    let (h, m, s) = (of_day / 3600, of_day / 60 % 60, of_day % 60);
    format!(
        "Tornect screenshot {} {h:02}-{m:02}-{s:02}.png",
        Day::from_unix(secs)
    )
}

/// Save `picture` into `dir` as a new PNG file, never over another one:
/// 8-bit RGBA with every pixel opaque, and nothing else in it. `dir` is made
/// if missing; its parent, the Pictures folder, must be there already, and
/// nothing is written anywhere else; a `dir` already there must be one this
/// user may write screenshots into ([`files::user_folder`]). Returns where
/// the file went.
pub fn save(dir: &Path, picture: &Picture, now: SystemTime) -> io::Result<PathBuf> {
    let size = u64::from(picture.width) * u64::from(picture.height) * 4;
    if size == 0 || usize::try_from(size).ok() != Some(picture.rgba.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no picture to save",
        ));
    }
    files::user_folder(dir)?;
    let first = file_name(now);
    for n in 1..=SAME_SECOND {
        let path = dir.join(files::nth(&first, n));
        let file = match files::create_new_private(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        return match write(file, picture) {
            Ok(()) => Ok(path),
            Err(e) => {
                // Half a picture is no screenshot.
                let _ = fs::remove_file(&path);
                Err(e)
            }
        };
    }
    Err(io::ErrorKind::AlreadyExists.into())
}

/// `picture` as a PNG into `file`: the signature, IHDR, the image data and
/// IEND, no other chunk.
fn write(file: File, picture: &Picture) -> io::Result<()> {
    let mut rgba = picture.rgba.clone();
    for pixel in rgba.chunks_exact_mut(4) {
        pixel[3] = u8::MAX;
    }
    let mut out = BufWriter::new(file);
    let mut encoder = png::Encoder::new(&mut out, picture.width, picture.height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    writer.write_image_data(&rgba)?;
    writer.finish()?;
    out.flush()
}

/// The toast's words for a screenshot saved at `path`: the Pictures folder's
/// own name, `Tornect` and the file's name, never the absolute path.
#[must_use]
pub fn saved_text(path: &Path) -> String {
    format!(
        "Screenshot saved to {}",
        files::last_names(path, 3).join("/")
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// 2026-10-08 07:30:05 UTC.
    fn at() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_791_444_605)
    }

    /// A 3 × 2 picture, its pixels all different, few of them opaque.
    fn picture() -> Picture {
        Picture {
            width: 3,
            height: 2,
            rgba: (0..24u8).map(|i| i.wrapping_mul(37)).collect(),
            seq: 0,
            fresh: false,
        }
    }

    /// The chunks of a PNG file after its signature: each one's type and
    /// data.
    fn chunks(png: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut rest = &png[8..];
        let mut out = Vec::new();
        while rest.len() >= 12 {
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            let kind = String::from_utf8_lossy(&rest[4..8]).into_owned();
            out.push((kind, rest[8..8 + len].to_vec()));
            rest = &rest[12 + len..];
        }
        assert!(rest.is_empty(), "bytes after the last chunk");
        out
    }

    /// Every file and folder under `root`, relative to it, sorted.
    fn listing(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut todo = vec![root.to_path_buf()];
        while let Some(dir) = todo.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    todo.push(path.clone());
                }
                out.push(path.strip_prefix(root).unwrap().to_path_buf());
            }
        }
        out.sort();
        out
    }

    /// A Pictures folder in a temporary directory, and the folder the
    /// screenshots go to inside it (not made yet).
    fn pictures() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("Pictures")).unwrap();
        let dir = root.path().join("Pictures").join("Tornect");
        (root, dir)
    }

    /// The file is a PNG of the picture as it is, every pixel opaque, with
    /// no chunk but IHDR, IDAT and IEND (no text, time or Exif), and its name
    /// is the time in UTC alone.
    #[test]
    fn a_screenshot_is_a_png_of_the_picture_with_a_neutral_name() {
        let (_root, dir) = pictures();
        let path = save(&dir, &picture(), at()).unwrap();
        assert_eq!(path.parent(), Some(dir.as_path()));
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "Tornect screenshot 2026-10-08 07-30-05.png");
        assert!(!name.contains("Desk"));
        let bytes = fs::read(&path).unwrap();
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
        let chunks = chunks(&bytes);
        let kinds: Vec<&str> = chunks.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(kinds.first(), Some(&"IHDR"), "{kinds:?}");
        assert_eq!(kinds.last(), Some(&"IEND"), "{kinds:?}");
        assert!(
            kinds[1..kinds.len() - 1].iter().all(|k| *k == "IDAT"),
            "{kinds:?}"
        );
        // 3 × 2, 8 bits, RGBA, not interlaced.
        assert_eq!(chunks[0].1, [0, 0, 0, 3, 0, 0, 0, 2, 8, 6, 0, 0, 0]);
        let mut reader = png::Decoder::new(io::Cursor::new(&bytes))
            .read_info()
            .unwrap();
        let mut pixels = vec![0; reader.output_buffer_size().unwrap()];
        let frame = reader.next_frame(&mut pixels).unwrap();
        let mut want = picture().rgba;
        for pixel in want.chunks_exact_mut(4) {
            pixel[3] = 255;
        }
        assert_eq!(&pixels[..frame.buffer_size()], want.as_slice());
        // Any time of any day reads the same way.
        for (secs, want) in [
            (0, "Tornect screenshot 1970-01-01 00-00-00.png"),
            (951_868_799, "Tornect screenshot 2000-02-29 23-59-59.png"),
            (1_791_417_600, "Tornect screenshot 2026-10-08 00-00-00.png"),
        ] {
            assert_eq!(file_name(UNIX_EPOCH + Duration::from_secs(secs)), want);
        }
    }

    /// Saving makes the screenshots' folder and one file in it, and touches
    /// nothing else; with no Pictures folder, or no picture yet, it writes
    /// nothing at all.
    #[test]
    fn nothing_is_written_outside_the_given_folder() {
        let (root, dir) = pictures();
        let theirs = root.path().join("Pictures").join("holiday.png");
        fs::write(&theirs, b"not a screenshot").unwrap();
        let before = listing(root.path());
        save(&dir, &picture(), at()).unwrap();
        let after = listing(root.path());
        let added: Vec<&PathBuf> = after.iter().filter(|p| !before.contains(p)).collect();
        let tornect = Path::new("Pictures").join("Tornect");
        assert_eq!(
            added,
            [
                &tornect,
                &tornect.join("Tornect screenshot 2026-10-08 07-30-05.png")
            ]
        );
        assert_eq!(fs::read(&theirs).unwrap(), b"not a screenshot");
        assert!(save(&dir, &Picture::default(), at()).is_err());
        let torn = Picture {
            rgba: vec![0; 5],
            ..picture()
        };
        assert!(save(&dir, &torn, at()).is_err());
        assert_eq!(listing(root.path()), after);
        let bare = tempfile::tempdir().unwrap();
        let missing = bare.path().join("Pictures").join("Tornect");
        assert!(save(&missing, &picture(), at()).is_err());
        assert!(listing(bare.path()).is_empty());
    }

    /// Screenshots of one second get " (2)", " (3)" before `.png`, and a
    /// file already there is never written over.
    #[test]
    fn two_screenshots_in_one_second_get_two_names() {
        let (_root, dir) = pictures();
        let first = save(&dir, &picture(), at()).unwrap();
        let second = save(&dir, &picture(), at() + Duration::from_millis(900)).unwrap();
        fs::write(
            dir.join("Tornect screenshot 2026-10-08 07-30-05 (3).png"),
            b"kept",
        )
        .unwrap();
        let fourth = save(&dir, &picture(), at()).unwrap();
        let names: Vec<&str> = [&first, &second, &fourth]
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "Tornect screenshot 2026-10-08 07-30-05.png",
                "Tornect screenshot 2026-10-08 07-30-05 (2).png",
                "Tornect screenshot 2026-10-08 07-30-05 (4).png",
            ]
        );
        assert_eq!(
            fs::read(dir.join("Tornect screenshot 2026-10-08 07-30-05 (3).png")).unwrap(),
            b"kept"
        );
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    }

    /// On Unix the folder a screenshot makes and its file are this user's
    /// only (`0700`, `0600`); a folder already there keeps its mode.
    #[cfg(unix)]
    #[test]
    fn the_folder_and_the_file_are_this_users_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let (_root, dir) = pictures();
        let path = save(&dir, &picture(), at()).unwrap();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&path), 0o600);
        let (_root, dir) = pictures();
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        save(&dir, &picture(), at()).unwrap();
        assert_eq!(mode(&dir), 0o750, "never re-moded");
    }

    /// On Unix a screenshots' folder that is a link (even to a folder of
    /// this user) or a file is refused, and nothing is written anywhere; so
    /// is a folder of another user.
    #[cfg(unix)]
    #[test]
    fn a_folder_that_is_a_link_or_not_this_users_is_refused() {
        let (root, dir) = pictures();
        let elsewhere = root.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
        let before = listing(root.path());
        assert!(save(&dir, &picture(), at()).is_err());
        assert_eq!(listing(root.path()), before);
        assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
        let (root, dir) = pictures();
        fs::write(&dir, b"not a folder").unwrap();
        let before = listing(root.path());
        assert!(save(&dir, &picture(), at()).is_err());
        assert_eq!(listing(root.path()), before);
        // The owner rule moved with the folder check to
        // `tornect_core::files` (`only_a_folder_of_this_user_may_hold_files`).
    }
}
