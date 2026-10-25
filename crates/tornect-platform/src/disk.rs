//! Free space and the fixed drives, for the session services (design
//! `services` §5): the inbox's room for an upload, and the places a viewer may
//! browse on a Windows host.

use std::io;
use std::path::{Path, PathBuf};

/// The bytes on the file system that holds `path` which this user may still
/// write: on Linux `statvfs`'s `f_bavail × f_frsize` (blocks free to an
/// unprivileged user, not the root reserve); on Windows
/// `GetDiskFreeSpaceExW`'s figure for the caller, which counts per-user
/// quotas (`docs/research/services.md` R2.5). `path` is a folder on it, not
/// necessarily its root (Windows refuses a file: `ERROR_DIRECTORY`).
/// Elsewhere `Unsupported`.
pub fn available(path: &Path) -> io::Result<u64> {
    #[cfg(target_os = "linux")]
    {
        let fs = rustix::fs::statvfs(path).map_err(io::Error::from)?;
        Ok(fs.f_bavail.saturating_mul(fs.f_frsize))
    }
    #[cfg(windows)]
    {
        crate::win::free_bytes_for_caller(path)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "free space is not read on this OS yet",
        ))
    }
}

/// The root (`C:\`) of each fixed local drive, in letter order: what a
/// Windows host offers to browse besides the user's folders. Removable, CD,
/// network and RAM drives are never listed (`GetDriveTypeW` must say
/// `DRIVE_FIXED`; a USB disk that reports fixed media is listed, R2.5). Empty
/// on every other OS, where `/` is the place.
#[must_use]
pub fn drives() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        fixed_roots(crate::win::logical_drives(), crate::win::drive_type)
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// `GetDriveTypeW`'s `DRIVE_FIXED` (Microsoft's documented value; windows-sys
/// has it under a feature this crate does not otherwise need).
const DRIVE_FIXED: u32 = 3;

/// The roots of the drives in `mask` (`GetLogicalDrives`: bit 0 is `A:`) whose
/// `drive_type` is `DRIVE_FIXED`.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn fixed_roots(mask: u32, drive_type: impl Fn(&str) -> u32) -> Vec<PathBuf> {
    (0..26u8)
        .filter(|bit| mask & (1 << bit) != 0)
        .map(|bit| format!("{}:\\", char::from(b'A' + bit)))
        .filter(|root| drive_type(root) == DRIVE_FIXED)
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// Only fixed drives are places, in letter order; the type is asked of
    /// each present drive by its root with the trailing backslash, and of no
    /// other.
    #[test]
    fn only_fixed_drives_are_listed() {
        // A: removable, C: fixed, D: CD, E: fixed, Z: network; B absent.
        let mask = 1 | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 25);
        let asked = RefCell::new(Vec::new());
        let roots = fixed_roots(mask, |root| {
            asked.borrow_mut().push(root.to_owned());
            match root {
                "C:\\" | "E:\\" => DRIVE_FIXED,
                "A:\\" => 2,
                "D:\\" => 5,
                "Z:\\" => 4,
                other => panic!("asked about {other}"),
            }
        });
        assert_eq!(roots, [PathBuf::from("C:\\"), PathBuf::from("E:\\")]);
        assert_eq!(*asked.borrow(), ["A:\\", "C:\\", "D:\\", "E:\\", "Z:\\"]);
        assert!(fixed_roots(0, |_| DRIVE_FIXED).is_empty());
        assert_eq!(fixed_roots(u32::MAX, |_| DRIVE_FIXED).len(), 26);
    }

    /// Off Windows there are no drives to list.
    #[cfg(not(windows))]
    #[test]
    fn there_are_no_drives_off_windows() {
        assert!(drives().is_empty());
    }

    /// On Windows the system drive is a fixed drive.
    #[cfg(windows)]
    #[test]
    fn the_system_drive_is_listed() {
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
        assert!(
            drives().contains(&PathBuf::from(format!("{system}\\"))),
            "{:?}",
            drives()
        );
    }

    /// A temp folder's file system has some room, a folder in it reads the
    /// same, and a path that does not exist is an error, not 0.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn free_space_of_a_temp_folder() {
        let dir = tempfile::tempdir().unwrap();
        let free = available(dir.path()).unwrap();
        assert!(free > 0, "no room in {:?}", dir.path());
        let inner = dir.path().join("x");
        std::fs::create_dir(&inner).unwrap();
        let again = available(&inner).unwrap();
        // Another process may write meanwhile; the same volume is seen.
        assert!(again.abs_diff(free) < 1 << 30, "{free} then {again}");
        assert!(available(&dir.path().join("missing/deeper")).is_err());
        assert!(available(Path::new("a\0b")).is_err(), "a NUL was cut off");
    }
}
