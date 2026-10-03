//! Installing Tornect (`docs/PLAN.md` §B.1.1, r7): the file work of
//! `tornect install` and `tornect uninstall`. The command runs it only after
//! the mutation guard's operation (access-increasing, §B.8.6.2: a fresh OS
//! re-authentication, no remote session for 60 s, logged); this module
//! performs the effect and nothing else.
//!
//! **Linux** ([`LinuxInstall`]): a per-user install without root. The
//! executable is copied to `~/.local/bin/tornect` and a menu entry is written
//! to `~/.local/share/applications/tornect.desktop`, with the keys `Type`,
//! `Name` and `Exec` only, `Exec` quoted by
//! [`desktop_exec`](crate::autostart::desktop_exec), the function the
//! start-at-sign-in entry uses. Before anything is written, the folder of the
//! executable passes the start at login's location rule
//! ([`unix_exe_location_ok`](crate::autostart::unix_exe_location_ok): neither
//! it nor a folder above it can be changed by another account, and none is a
//! link). Each file is written to a new temporary file in its folder and
//! renamed over its name, so a link found at either name is replaced, never
//! followed. Uninstalling removes exactly these two files, and only where they
//! are regular files.
//!
//! The folders come from the caller ([`LinuxInstall::new`]) or from `HOME`
//! ([`LinuxInstall::for_this_user`]), never from Tornect's data directory or
//! `--home`, which hold state, not programs. What starts at sign-in is not
//! this module's: the command registers it through the start-at-login
//! backend, and removes it the same way.
//!
//! **Windows** ([`install_in_program_files`], [`uninstall_from_program_files`]):
//! the Program Files install as checked steps over [`WindowsSystem`], which a
//! recording fake implements in the tests. This program's image is held open
//! (share mode read only) and hashed from that handle before the guard's
//! dialog, and held to the end; the folder is `FOLDERID_ProgramFiles`'s
//! `Tornect`, and an existing one is refused, before the dialog and again
//! after it, when it holds anything but `tornect.exe`, when it or that
//! `tornect.exe` is a reparse point, or when the ACL rule below fails; after
//! the copy (elevated) the folder and the copy are checked for reparse
//! points, then the copy is hashed and compared with the held image, then
//! checked with the administrator helper task's ACL rule ([`admin_only`]),
//! all before anything points at it; then this user's Start-menu entry,
//! then the Apps-and-features entry (elevated), whose command is the quoted
//! path with the fixed argument `uninstall`. A failure undoes what was done,
//! newest first, but a folder found unsafe is never deleted as
//! administrator, and only a program in Program Files or the system folder
//! ever runs elevated. This build has not the calls that make these steps on
//! Windows, where `windows_system` refuses.

use crate::autostart::location_under;
use crate::helper_task::{Install as HelperInstall, Security, admin_only, guarded_paths};

/// The name the installed program's entries show: the Linux menu entry, and
/// on Windows the Start-menu entry and Apps and features.
pub const ENTRY_NAME: &str = "Tornect";

/// Why an install or an uninstall did not happen, or did not finish.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// Not possible in this build or on this computer; nothing was changed.
    #[error("{0}")]
    Unavailable(String),
    /// A check refused it: nothing was written, or what was written was
    /// undone, as the message says.
    #[error("{0}")]
    Refused(String),
    /// Windows' administrator prompt (UAC) was dismissed: the message says
    /// what is left, if anything.
    #[error("{0}")]
    Cancelled(String),
    /// A file could not be written, read or removed.
    #[error("{0}")]
    Failed(String),
}

// ---------------------------------------------------------------------------
// Windows: Program Files, as checked steps
// ---------------------------------------------------------------------------

/// The Program Files subfolder Tornect is installed in.
pub const WINDOWS_FOLDER: &str = "Tornect";

/// The installed executable's file name.
pub const WINDOWS_EXE: &str = "tornect.exe";

/// The Start-menu entry's file name, in this user's Start-menu programs
/// folder.
pub const START_MENU_ENTRY: &str = "Tornect.lnk";

/// The uninstall entry's key, under
/// `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall`.
pub const UNINSTALL_KEY: &str = "Tornect";

/// The uninstall command's fixed argument (§B.1.1).
pub const UNINSTALL_ARGUMENT: &str = "uninstall";

/// Why `tornect install` and `uninstall` refuse on Windows in this build:
/// the calls that make the steps below on Windows are not in it.
pub const PROGRAM_FILES_UNAVAILABLE: &str =
    "Installing in Program Files is not available in this build.";

/// The installed copy is not the file that was held and hashed.
pub const SOURCE_SWAPPED: &str = "Something else replaced the Tornect file while it was being \
     copied, so nothing was installed.";

/// The administrator prompt of an install was cancelled.
pub const INSTALL_NEEDS_APPROVAL: &str =
    "Installing needs administrator approval; nothing was installed.";

/// The installed copy failed the ACL check: it is left, with nothing
/// pointing at it, and not deleted as administrator (an account that can
/// change its folder could have made the folder a link to another place).
pub const COPY_NOT_ADMIN_ONLY: &str = "The installed copy could be changed by accounts other than \
     administrators, so nothing points at it and Tornect was not installed. It was not deleted as \
     administrator either, since another account could have changed what would be deleted: delete \
     the Tornect folder in Program Files by hand.";

/// One step that needs administrator rights, run through Windows' prompt
/// (UAC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Elevated {
    /// Copy the held image at `from` to `to`, creating the folder.
    Copy {
        /// The held image's path.
        from: String,
        /// The installed executable.
        to: String,
    },
    /// Write the uninstall entry.
    WriteEntry(UninstallEntry),
    /// Delete the uninstall entry `key`.
    DeleteEntry {
        /// Its key.
        key: String,
    },
    /// Delete the install folder and what it holds.
    RemoveFolder {
        /// The folder.
        folder: String,
    },
}

/// The Apps-and-features entry, written under HKLM (§B.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallEntry {
    /// The key's name.
    pub key: String,
    /// `DisplayName`.
    pub display_name: String,
    /// `DisplayVersion`: this build's version.
    pub display_version: String,
    /// `UninstallString`: the installed executable's absolute path in quotes
    /// and the fixed argument.
    pub uninstall_string: String,
}

/// This program's image, held open: its path, and its bytes read from the
/// held handle. Dropping it closes the handle.
pub trait HeldImage: std::io::Read {
    /// Where it is.
    fn path(&self) -> &str;
}

/// This computer as the Program Files install needs it; a recording fake in
/// the tests. Every folder comes from the OS (never from the environment,
/// which whoever starts Tornect controls); every change that needs
/// administrator rights is one [`Elevated`] step. The reads act on the path
/// itself: [`Self::is_reparse_point`], [`Self::read_file`] and
/// [`Self::security`] never follow a reparse point at the path (on Windows,
/// `FILE_FLAG_OPEN_REPARSE_POINT`), so a link put at a checked path is seen,
/// never looked through.
pub trait WindowsSystem {
    /// `FOLDERID_ProgramFiles`.
    fn program_files(&self) -> Result<String, InstallError>;
    /// The Windows system folder (System32).
    fn system_directory(&self) -> Result<String, InstallError>;
    /// This user's Start-menu programs folder (`FOLDERID_Programs`).
    fn start_menu_programs(&self) -> Result<String, InstallError>;
    /// This program's own image, opened for reading with share mode read
    /// only: while it is held nobody can write, rename or delete it.
    fn open_own_image(&self) -> Result<Box<dyn HeldImage + '_>, InstallError>;
    /// The names `folder` holds; `None` when there is no such folder.
    fn folder_entries(&self, folder: &str) -> Result<Option<Vec<String>>, InstallError>;
    /// Whether `path` itself is a reparse point (a junction, a mount point or
    /// a link); none is followed to answer.
    fn is_reparse_point(&self, path: &str) -> Result<bool, InstallError>;
    /// The file at `path`, for reading; a reparse point at `path` is never
    /// followed.
    fn read_file(&self, path: &str) -> Result<Box<dyn std::io::Read + '_>, InstallError>;
    /// The owner and the DACL of `path` itself, a file or a folder; a
    /// reparse point at `path` is read itself, never followed.
    fn security(&self, path: &str) -> Result<Security, InstallError>;
    /// The program that would run `step` elevated (checked before any step
    /// runs: only a program in Program Files or the system folder may be).
    fn elevated_program(&self, step: &Elevated) -> String;
    /// Run `step` through Windows' prompt: [`InstallError::Cancelled`] when
    /// the prompt was dismissed and nothing ran.
    fn run_elevated(&self, step: &Elevated) -> Result<(), InstallError>;
    /// Whether the uninstall entry `key` exists.
    fn uninstall_entry_exists(&self, key: &str) -> Result<bool, InstallError>;
    /// Whether a file is at `path`.
    fn file_exists(&self, path: &str) -> Result<bool, InstallError>;
    /// Write this user's Start-menu entry `link`, which starts `target`.
    fn write_shortcut(&self, link: &str, target: &str) -> Result<(), InstallError>;
    /// Remove this user's Start-menu entry `link`.
    fn remove_shortcut(&self, link: &str) -> Result<(), InstallError>;
}

/// This computer for the Program Files install. The calls that would make
/// the steps below on Windows are not in this build, so `tornect install`
/// and `uninstall` refuse there before anything is asked.
#[cfg(windows)]
pub fn windows_system() -> Result<Box<dyn WindowsSystem>, InstallError> {
    Err(InstallError::Unavailable(
        PROGRAM_FILES_UNAVAILABLE.to_owned(),
    ))
}

/// `dir\name`.
fn windows_join(dir: &str, name: &str) -> String {
    format!("{}\\{name}", dir.trim_end_matches(['\\', '/']))
}

/// The uninstall entry's command (§B.1.1): the installed executable's
/// absolute path in quotes, then the fixed argument. Refused: a path that is
/// not absolute on a drive, or that holds a control character, `"` (not a
/// legal file-name character) or `%` (which Windows may read as a
/// variable).
pub fn uninstall_command(exe: &str) -> Result<String, InstallError> {
    let bytes = exe.as_bytes();
    let on_a_drive =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    if !on_a_drive {
        return Err(InstallError::Unavailable(format!(
            "{exe:?} is not an absolute path on a drive, which Windows' uninstall entry needs"
        )));
    }
    if let Some(c) = exe
        .chars()
        .find(|c| c.is_control() || *c == '"' || *c == '%')
    {
        return Err(InstallError::Unavailable(format!(
            "{exe:?} contains {c:?}, which Windows' uninstall entry cannot hold in its command"
        )));
    }
    Ok(format!("\"{exe}\" {UNINSTALL_ARGUMENT}"))
}

/// Where the Program Files install goes: from the known folders only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsTarget {
    /// `FOLDERID_ProgramFiles`.
    pub program_files: String,
    /// The system folder.
    pub system_directory: String,
    /// `<Program Files>\Tornect`.
    pub folder: String,
    /// `<Program Files>\Tornect\tornect.exe`.
    pub exe: String,
    /// `<Start-menu programs>\Tornect.lnk`.
    pub start_menu_entry: String,
    /// The uninstall entry.
    pub entry: UninstallEntry,
}

impl WindowsTarget {
    /// The target on this computer; refused when the executable's path
    /// cannot be written into the uninstall entry's command.
    pub fn of(sys: &dyn WindowsSystem) -> Result<Self, InstallError> {
        let program_files = sys.program_files()?;
        let system_directory = sys.system_directory()?;
        let folder = windows_join(&program_files, WINDOWS_FOLDER);
        let exe = windows_join(&folder, WINDOWS_EXE);
        let start_menu_entry = windows_join(&sys.start_menu_programs()?, START_MENU_ENTRY);
        let entry = UninstallEntry {
            key: UNINSTALL_KEY.to_owned(),
            display_name: ENTRY_NAME.to_owned(),
            display_version: env!("CARGO_PKG_VERSION").to_owned(),
            uninstall_string: uninstall_command(&exe)?,
        };
        Ok(Self {
            program_files,
            system_directory,
            folder,
            exe,
            start_menu_entry,
            entry,
        })
    }

    /// Refused unless `step` would run elevated through a program in
    /// Program Files or the system folder (decision M1-65: an executable
    /// another program of this user can replace is never elevated).
    fn elevation_ok(&self, sys: &dyn WindowsSystem, step: &Elevated) -> Result<(), InstallError> {
        let program = sys.elevated_program(step);
        let trusted = [self.program_files.clone(), self.system_directory.clone()];
        if location_under(&program, &trusted) {
            return Ok(());
        }
        Err(InstallError::Unavailable(format!(
            "Tornect runs nothing as administrator from {program}: only a program in Program \
             Files or the Windows system folder, which other accounts cannot change"
        )))
    }

    /// The ACL check of §B.1.1 (the helper task's, H6): the executable and
    /// every folder above it up to Program Files carry no write, delete or
    /// owner-change entry for anyone but administrators. `with_exe`: whether
    /// the executable is there to check.
    fn admin_only(&self, sys: &dyn WindowsSystem, with_exe: bool) -> Result<(), String> {
        let install = HelperInstall {
            exe: self.exe.clone(),
            folder: self.folder.clone(),
            program_files: self.program_files.clone(),
            // Not read by `guarded_paths`.
            sid: String::new(),
        };
        let paths = guarded_paths(&install).map_err(|e| e.to_string())?;
        for path in paths.iter().skip(usize::from(!with_exe)) {
            admin_only(path, &sys.security(path).map_err(|e| e.to_string())?)?;
        }
        Ok(())
    }
}

/// The SHA-256 of what `read` yields.
fn sha256_of<R: std::io::Read + ?Sized>(read: &mut R) -> std::io::Result<[u8; 32]> {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match read.read(&mut buf) {
            Ok(0) => return Ok(hasher.finalize().into()),
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// This program, held open from before the guard's dialog until the
/// install ends, and its SHA-256, read from the held handle.
pub struct HeldSource<'a> {
    image: Box<dyn HeldImage + 'a>,
    sha256: [u8; 32],
}

impl<'a> HeldSource<'a> {
    /// Open this program's image (share mode read only) and hash it.
    pub fn hold(sys: &'a dyn WindowsSystem) -> Result<Self, InstallError> {
        let mut image = sys.open_own_image()?;
        let sha256 = sha256_of(&mut *image)
            .map_err(|e| InstallError::Failed(format!("reading {}: {e}", image.path())))?;
        Ok(Self { image, sha256 })
    }

    /// Where the held image is.
    #[must_use]
    pub fn path(&self) -> &str {
        self.image.path()
    }
}

/// What a finished install in Program Files holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The install folder.
    pub folder: String,
    /// The installed executable.
    pub exe: String,
}

/// What an install did so far, undone in reverse on a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Done {
    /// The copy is in the install folder (or part of it may be).
    Copied,
    /// The Start-menu entry is written.
    StartMenuEntry,
}

/// Undo `done`, newest first: the Start-menu entry, then the copy (an
/// elevated step, run only after a reparse check of its own: the folder and
/// the copy in it must not be reparse points, or the delete would act on
/// another place). What could not be undone is added to `error`'s message.
/// A copy whose folder failed the ACL check never comes here: it is not
/// deleted as administrator at all.
fn undo(
    sys: &dyn WindowsSystem,
    target: &WindowsTarget,
    done: &[Done],
    error: InstallError,
) -> InstallError {
    let mut failed = Vec::new();
    for step in done.iter().rev() {
        let undone = match step {
            Done::StartMenuEntry => sys.remove_shortcut(&target.start_menu_entry),
            Done::Copied => not_a_link(sys, target).and_then(|()| {
                sys.run_elevated(&Elevated::RemoveFolder {
                    folder: target.folder.clone(),
                })
            }),
        };
        if let Err(e) = undone {
            failed.push(match step {
                Done::StartMenuEntry => format!("removing {}: {e}", target.start_menu_entry),
                Done::Copied => format!("removing {}: {e}", target.folder),
            });
        }
    }
    if failed.is_empty() {
        return error;
    }
    let tail = format!(" Undoing it did not finish ({}).", failed.join("; "));
    match error {
        InstallError::Unavailable(m) => InstallError::Unavailable(format!("{m}{tail}")),
        InstallError::Refused(m) => InstallError::Refused(format!("{m}{tail}")),
        InstallError::Cancelled(m) => InstallError::Cancelled(format!("{m}{tail}")),
        InstallError::Failed(m) => InstallError::Failed(format!("{m}{tail}")),
    }
}

/// Refused when the install folder or the executable in it is a reparse
/// point, as read right before the undo's elevated delete: nothing is
/// deleted as administrator through one.
fn not_a_link(sys: &dyn WindowsSystem, target: &WindowsTarget) -> Result<(), InstallError> {
    for path in [&target.folder, &target.exe] {
        if sys.is_reparse_point(path)? {
            return Err(InstallError::Refused(format!(
                "{path} is a link to another place, so Tornect did not remove it as \
                 administrator; nothing points at it"
            )));
        }
    }
    Ok(())
}

/// Refused when the install folder exists and holds anything but
/// `tornect.exe`, when it or the `tornect.exe` in it is a reparse point, or
/// when accounts other than administrators can change it, that
/// `tornect.exe` or a folder above it up to Program Files: the elevated copy
/// must not write into a place another account controls (decision M1-65).
/// Run before the dialog and again right after it.
fn existing_folder_ok(sys: &dyn WindowsSystem, target: &WindowsTarget) -> Result<(), InstallError> {
    let folder = &target.folder;
    let Some(entries) = sys.folder_entries(folder)? else {
        return Ok(());
    };
    if sys.is_reparse_point(folder)? {
        return Err(InstallError::Refused(format!(
            "{folder} is a link to another place, so Tornect was not installed there."
        )));
    }
    if !entries.iter().all(|e| e.eq_ignore_ascii_case(WINDOWS_EXE)) {
        return Err(InstallError::Refused(format!(
            "{folder} already holds other files, so Tornect was not installed there."
        )));
    }
    let with_exe = !entries.is_empty();
    if with_exe && sys.is_reparse_point(&target.exe)? {
        return Err(InstallError::Refused(format!(
            "{} is a link to another place, so Tornect was not installed there.",
            target.exe
        )));
    }
    target.admin_only(sys, with_exe).map_err(|why| {
        InstallError::Refused(format!(
            "{folder} could be changed by accounts other than administrators, so Tornect was \
             not installed there ({why})."
        ))
    })
}

/// `tornect install` on Windows (§B.1.1), step by step:
///
/// 1. this program's image, held open (share mode read only) and hashed from
///    that handle, before anything else and until the end;
/// 2. the target from the known folders; refused when its path cannot be
///    quoted into the uninstall command, when `<Program Files>\Tornect`
///    exists and fails `existing_folder_ok` (anything but `tornect.exe` in
///    it, a reparse point, or an ACL that lets another account change it),
///    or when a step would run elevated through a program outside Program
///    Files and the system folder;
/// 3. `authorize`, the mutation guard's operation (re-authentication, no
///    remote session for 60 s, logged): nothing before it changes anything;
///    then the folder checked again, as the dialog may have stayed open for
///    long;
/// 4. the copy (elevated);
/// 5. the folder and the copy checked for reparse points, then the copy
///    hashed and compared with the held image, then the ACL check, all
///    before anything points at the copy;
/// 6. this user's Start-menu entry;
/// 7. the uninstall entry (elevated).
///
/// A failure after the copy undoes what was done, newest first, but a copy
/// whose folder failed the ACL check, or became a reparse point, is never
/// deleted as administrator: it is left, with nothing pointing at it, and
/// the refusal says so. A cancelled prompt is [`InstallError::Cancelled`].
pub fn install_in_program_files(
    sys: &dyn WindowsSystem,
    authorize: &mut dyn FnMut() -> Result<(), InstallError>,
) -> Result<Installed, InstallError> {
    let source = HeldSource::hold(sys)?;
    let target = WindowsTarget::of(sys)?;
    existing_folder_ok(sys, &target)?;
    let copy = Elevated::Copy {
        from: source.path().to_owned(),
        to: target.exe.clone(),
    };
    let write = Elevated::WriteEntry(target.entry.clone());
    let remove = Elevated::RemoveFolder {
        folder: target.folder.clone(),
    };
    for step in [&copy, &write, &remove] {
        target.elevation_ok(sys, step)?;
    }
    authorize()?;
    existing_folder_ok(sys, &target)?;
    match sys.run_elevated(&copy) {
        Ok(()) => {}
        Err(InstallError::Cancelled(_)) => {
            return Err(InstallError::Cancelled(INSTALL_NEEDS_APPROVAL.to_owned()));
        }
        Err(e) => return Err(undo(sys, &target, &[Done::Copied], e)),
    }
    let mut done = vec![Done::Copied];
    // The copy is read where it was written, not through a link put there
    // during the copy.
    for path in [&target.folder, &target.exe] {
        match sys.is_reparse_point(path) {
            Ok(false) => {}
            Ok(true) => {
                return Err(undo(
                    sys,
                    &target,
                    &done,
                    InstallError::Refused(format!(
                        "{path} became a link to another place while Tornect was copied, so \
                         nothing was installed."
                    )),
                ));
            }
            Err(e) => return Err(undo(sys, &target, &done, e)),
        }
    }
    let copied = sys.read_file(&target.exe).and_then(|mut file| {
        sha256_of(&mut *file)
            .map_err(|e| InstallError::Failed(format!("reading {}: {e}", target.exe)))
    });
    match copied {
        Ok(hash) if hash == source.sha256 => {}
        Ok(_) => {
            return Err(undo(
                sys,
                &target,
                &done,
                InstallError::Refused(SOURCE_SWAPPED.to_owned()),
            ));
        }
        Err(e) => return Err(undo(sys, &target, &done, e)),
    }
    if let Err(why) = target.admin_only(sys, true) {
        tracing::warn!(%why, "the installed copy failed the ACL check");
        // Not deleted as administrator: an account that can change the
        // folder could have turned it into a link to another place first.
        return Err(InstallError::Refused(COPY_NOT_ADMIN_ONLY.to_owned()));
    }
    if let Err(e) = sys.write_shortcut(&target.start_menu_entry, &target.exe) {
        return Err(undo(sys, &target, &done, e));
    }
    done.push(Done::StartMenuEntry);
    match sys.run_elevated(&write) {
        Ok(()) => {}
        Err(InstallError::Cancelled(_)) => {
            return Err(undo(
                sys,
                &target,
                &done,
                InstallError::Cancelled(INSTALL_NEEDS_APPROVAL.to_owned()),
            ));
        }
        Err(e) => return Err(undo(sys, &target, &done, e)),
    }
    // Held to here: released only once nothing more is written.
    drop(source);
    Ok(Installed {
        folder: target.folder,
        exe: target.exe,
    })
}

/// What an uninstall from Program Files removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WindowsRemoval {
    /// The uninstall entry.
    pub uninstall_entry: bool,
    /// This user's Start-menu entry.
    pub start_menu_entry: bool,
    /// The install folder.
    pub folder: bool,
}

/// Whether the install folder is there, refused when it is but may not be
/// deleted as administrator: a reparse point, or an owner or entry other than
/// administrators on it, on the executable in it or on a folder above it up
/// to Program Files.
fn removable_folder(sys: &dyn WindowsSystem, target: &WindowsTarget) -> Result<bool, InstallError> {
    let Some(entries) = sys.folder_entries(&target.folder)? else {
        return Ok(false);
    };
    if sys.is_reparse_point(&target.folder)? {
        return Err(InstallError::Refused(format!(
            "{} is a link to another place, so Tornect did not remove it.",
            target.folder
        )));
    }
    let with_exe = entries.iter().any(|e| e.eq_ignore_ascii_case(WINDOWS_EXE));
    target.admin_only(sys, with_exe).map_err(|why| {
        InstallError::Refused(format!(
            "{} could be changed by accounts other than administrators, so Tornect did not \
             remove it as administrator ({why}).",
            target.folder
        ))
    })?;
    Ok(true)
}

/// `tornect uninstall` on Windows (§B.1.1): the target from the known
/// folders only (never this program's own path or the environment), the
/// install folder checked (not a reparse point, administrators only) before
/// `authorize`, the mutation guard's operation, and again right before its
/// elevated delete; then the uninstall entry (elevated), this user's
/// Start-menu entry and the folder (elevated), each only where it exists.
/// Nothing there: nothing asked.
pub fn uninstall_from_program_files(
    sys: &dyn WindowsSystem,
    authorize: &mut dyn FnMut() -> Result<(), InstallError>,
) -> Result<WindowsRemoval, InstallError> {
    let target = WindowsTarget::of(sys)?;
    let folder = removable_folder(sys, &target)?;
    let entry = sys.uninstall_entry_exists(&target.entry.key)?;
    let link = sys.file_exists(&target.start_menu_entry)?;
    if !(folder || entry || link) {
        return Ok(WindowsRemoval::default());
    }
    let delete_entry = Elevated::DeleteEntry {
        key: target.entry.key.clone(),
    };
    let remove_folder = Elevated::RemoveFolder {
        folder: target.folder.clone(),
    };
    for (step, needed) in [(&delete_entry, entry), (&remove_folder, folder)] {
        if needed {
            target.elevation_ok(sys, step)?;
        }
    }
    authorize()?;
    let mut removed = WindowsRemoval::default();
    let cancelled = |removed: &WindowsRemoval| {
        InstallError::Cancelled(if *removed == WindowsRemoval::default() {
            format!(
                "Removing Tornect needs administrator approval; it stays installed in {}.",
                target.folder
            )
        } else {
            format!(
                "Removing Tornect needs administrator approval; {} still holds a copy, and \
                 nothing points at it.",
                target.folder
            )
        })
    };
    if entry {
        match sys.run_elevated(&delete_entry) {
            Ok(()) => removed.uninstall_entry = true,
            Err(InstallError::Cancelled(_)) => return Err(cancelled(&removed)),
            Err(e) => return Err(e),
        }
    }
    if link {
        sys.remove_shortcut(&target.start_menu_entry)?;
        removed.start_menu_entry = true;
    }
    if folder {
        if !removable_folder(sys, &target)? {
            return Ok(removed);
        }
        match sys.run_elevated(&remove_folder) {
            Ok(()) => removed.folder = true,
            Err(InstallError::Cancelled(_)) => return Err(cancelled(&removed)),
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

#[cfg(target_os = "linux")]
pub use linux::{FOLDER_OTHERS_CAN_CHANGE, LINUX_EXE, LinuxInstall, MENU_ENTRY, Removal};

/// The per-user install on Linux.
#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::io::{ErrorKind, Write as _};
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use super::{ENTRY_NAME, InstallError};
    use crate::autostart::{
        AutostartError, PathFacts, desktop_exec, parse_status_ids, unix_exe_location_ok,
    };

    /// The installed executable's name in the bin folder.
    pub const LINUX_EXE: &str = "tornect";

    /// The menu entry's file name in the applications folder.
    pub const MENU_ENTRY: &str = "tornect.desktop";

    /// Why the bin folder cannot take the copy: it, or a folder above it,
    /// fails the location rule; the rule's own reason follows.
    pub const FOLDER_OTHERS_CAN_CHANGE: &str =
        "This folder can be changed by other accounts, so Tornect cannot start from it.";

    /// What the location rule reads of the file system: this user's ids and a
    /// `stat` that does not follow links.
    #[derive(Clone, Copy)]
    struct Facts {
        uid: u32,
        gid: u32,
        stat: fn(&Path) -> std::io::Result<PathFacts>,
    }

    /// `stat` without following a link, as the location rule needs it.
    fn real_stat(path: &Path) -> std::io::Result<PathFacts> {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::symlink_metadata(path).map(|m| PathFacts {
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            symlink: m.file_type().is_symlink(),
        })
    }

    /// The per-user install: the executable in `bin_dir`, the menu entry in
    /// `apps_dir`.
    #[derive(Clone)]
    pub struct LinuxInstall {
        bin_dir: PathBuf,
        apps_dir: PathBuf,
        /// The tests' file facts; elsewhere this process's, always.
        #[cfg(test)]
        facts: Option<Facts>,
    }

    impl std::fmt::Debug for LinuxInstall {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LinuxInstall")
                .field("bin_dir", &self.bin_dir)
                .field("apps_dir", &self.apps_dir)
                .finish_non_exhaustive()
        }
    }

    /// What [`LinuxInstall::uninstall`] did.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub struct Removal {
        /// Removed, in this order.
        pub removed: Vec<PathBuf>,
        /// Found at an install's name but not a regular file (a link, a
        /// folder): not what `install` wrote, so left as it is.
        pub left: Vec<PathBuf>,
    }

    impl LinuxInstall {
        /// The install into `bin_dir` (the executable) and `apps_dir` (the
        /// menu entry), both absolute.
        #[must_use]
        pub fn new(bin_dir: PathBuf, apps_dir: PathBuf) -> Self {
            Self {
                bin_dir,
                apps_dir,
                #[cfg(test)]
                facts: None,
            }
        }

        /// This user's install (§B.1.1): `$HOME/.local/bin` and
        /// `$HOME/.local/share/applications`.
        pub fn for_this_user() -> Result<Self, InstallError> {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .ok_or_else(|| {
                    InstallError::Unavailable(
                        "HOME does not name this user's home folder, so Tornect does not know \
                         where to install"
                            .to_owned(),
                    )
                })?;
            Ok(Self::new(
                home.join(".local").join("bin"),
                home.join(".local").join("share").join("applications"),
            ))
        }

        /// The same install with the tests' file facts (the location rule
        /// itself still runs).
        #[cfg(test)]
        fn with_facts(
            mut self,
            uid: u32,
            gid: u32,
            stat: fn(&Path) -> std::io::Result<PathFacts>,
        ) -> Self {
            self.facts = Some(Facts { uid, gid, stat });
            self
        }

        /// The installed executable.
        #[must_use]
        pub fn exe(&self) -> PathBuf {
            self.bin_dir.join(LINUX_EXE)
        }

        /// The menu entry.
        #[must_use]
        pub fn menu_entry(&self) -> PathBuf {
            self.apps_dir.join(MENU_ENTRY)
        }

        /// The menu entry's text: the keys `Type`, `Name` and `Exec` only,
        /// `Exec` opening the installed window, with `--home` when the
        /// install is for a custom home (absolute).
        pub fn menu_entry_text(&self, home: Option<&Path>) -> Result<String, InstallError> {
            let mut args = Vec::new();
            if let Some(home) = home {
                if !home.is_absolute() {
                    return Err(InstallError::Unavailable(format!(
                        "the home {} is not an absolute path",
                        home.display()
                    )));
                }
                args.push(OsString::from("--home"));
                args.push(home.as_os_str().to_owned());
            }
            let exec = desktop_exec(&self.exe(), &args)
                .map_err(|e| InstallError::Unavailable(e.to_string()))?;
            Ok(format!(
                "# Written by `tornect install`; `tornect uninstall` removes it.\n\
                 [Desktop Entry]\n\
                 Type=Application\n\
                 Name={ENTRY_NAME}\n\
                 Exec={exec}\n"
            ))
        }

        /// Checks what [`Self::install`] would write, writing nothing: both
        /// folders are absolute, the menu entry's `Exec` quotes, and the bin
        /// folder (while it does not exist, the nearest folder above it that
        /// does) passes the location rule.
        pub fn preflight(&self, home: Option<&Path>) -> Result<(), InstallError> {
            for dir in [&self.bin_dir, &self.apps_dir] {
                if !dir.is_absolute() {
                    return Err(InstallError::Unavailable(format!(
                        "{} is not an absolute path",
                        dir.display()
                    )));
                }
            }
            self.menu_entry_text(home)?;
            self.location_ok(nearest_existing(&self.bin_dir))
        }

        /// Copy `source` (this program, read from the handle the command
        /// opened first) to [`Self::exe`] and write the menu entry. Refused
        /// before anything is written by [`Self::preflight`]'s checks; the bin
        /// folder is checked again once it exists. A menu entry that cannot
        /// be written removes the copy again; a folder this call created and
        /// a refusal left empty is removed too.
        pub fn install(
            &self,
            source: &mut dyn std::io::Read,
            home: Option<&Path>,
        ) -> Result<(), InstallError> {
            self.preflight(home)?;
            let entry = self.menu_entry_text(home)?;
            let mut created = create_dirs(&self.bin_dir)?;
            let copied = self.location_ok(&self.bin_dir).and_then(|()| {
                write_new(&self.bin_dir, LINUX_EXE, 0o755, &mut |f| {
                    std::io::copy(&mut *source, f).map(drop)
                })
            });
            if let Err(e) = copied {
                remove_empty(&created);
                return Err(e);
            }
            let written = create_dirs(&self.apps_dir).and_then(|dirs| {
                created.extend(dirs);
                write_new(&self.apps_dir, MENU_ENTRY, 0o644, &mut |f| {
                    f.write_all(entry.as_bytes())
                })
            });
            if let Err(e) = written {
                let _ = std::fs::remove_file(self.exe());
                remove_empty(&created);
                return Err(e);
            }
            Ok(())
        }

        /// Whether anything [`Self::install`] writes is at its name.
        #[must_use]
        pub fn installed(&self) -> bool {
            [self.menu_entry(), self.exe()]
                .iter()
                .any(|p| std::fs::symlink_metadata(p).is_ok())
        }

        /// Remove the menu entry, then the executable: regular files only,
        /// anything else at those names left and reported. Removing nothing
        /// changes nothing.
        pub fn uninstall(&self) -> Result<Removal, InstallError> {
            let mut done = Removal::default();
            for path in [self.menu_entry(), self.exe()] {
                match std::fs::symlink_metadata(&path) {
                    Ok(m) if m.file_type().is_file() => {
                        std::fs::remove_file(&path).map_err(|e| {
                            InstallError::Failed(format!("removing {}: {e}", path.display()))
                        })?;
                        done.removed.push(path);
                    }
                    Ok(_) => done.left.push(path),
                    Err(e) if e.kind() == ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(InstallError::Failed(format!(
                            "reading {}: {e}",
                            path.display()
                        )));
                    }
                }
            }
            Ok(done)
        }

        /// This process's ids and the real `stat`, or the tests'.
        fn facts(&self) -> Result<Facts, InstallError> {
            #[cfg(test)]
            if let Some(facts) = self.facts {
                return Ok(facts);
            }
            let status = std::fs::read_to_string("/proc/self/status").map_err(|e| {
                InstallError::Unavailable(format!("could not read who this process runs as: {e}"))
            })?;
            let (uid, gid) = parse_status_ids(&status).ok_or_else(|| {
                InstallError::Unavailable("/proc/self/status names no user or group".to_owned())
            })?;
            Ok(Facts {
                uid,
                gid,
                stat: real_stat,
            })
        }

        /// The location rule of the start at login for `dir` and every
        /// folder above it.
        fn location_ok(&self, dir: &Path) -> Result<(), InstallError> {
            let facts = self.facts()?;
            unix_exe_location_ok(dir, facts.uid, facts.gid, &facts.stat).map_err(|e| {
                let why = match &e {
                    AutostartError::Unavailable(why)
                    | AutostartError::Unquotable(why)
                    | AutostartError::Failed(why) => why.clone(),
                    AutostartError::Cancelled => e.to_string(),
                };
                InstallError::Refused(format!("{FOLDER_OTHERS_CAN_CHANGE} ({why})"))
            })
        }
    }

    /// `dir`, or the nearest folder above it that exists.
    fn nearest_existing(dir: &Path) -> &Path {
        dir.ancestors()
            .find(|p| std::fs::symlink_metadata(p).is_ok())
            .unwrap_or(dir)
    }

    /// Create `dir` and the folders above it that are missing (mode 0755
    /// before the umask); the ones created, from the top.
    fn create_dirs(dir: &Path) -> Result<Vec<PathBuf>, InstallError> {
        let missing: Vec<&Path> = dir
            .ancestors()
            .take_while(|p| std::fs::symlink_metadata(p).is_err())
            .collect();
        let mut created = Vec::new();
        for path in missing.into_iter().rev() {
            if let Err(e) = std::fs::DirBuilder::new().mode(0o755).create(path) {
                remove_empty(&created);
                return Err(InstallError::Failed(format!(
                    "creating {}: {e}",
                    path.display()
                )));
            }
            created.push(path.to_path_buf());
        }
        Ok(created)
    }

    /// Remove the folders `create_dirs` made, deepest first, where still
    /// empty.
    fn remove_empty(created: &[PathBuf]) {
        for path in created.iter().rev() {
            let _ = std::fs::remove_dir(path);
        }
    }

    /// Write `name` in `dir` with `mode`: into a new temporary file beside it
    /// (never one that exists, so never through a link), then renamed over
    /// the name, which replaces a link there rather than following it.
    fn write_new(
        dir: &Path,
        name: &str,
        mode: u32,
        fill: &mut dyn FnMut(&mut std::fs::File) -> std::io::Result<()>,
    ) -> Result<(), InstallError> {
        let target = dir.join(name);
        let tmp = dir.join(format!(".{name}.tmp"));
        let failed =
            |e: std::io::Error| InstallError::Failed(format!("writing {}: {e}", target.display()));
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(failed(e)),
        }
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .and_then(|mut f| {
                fill(&mut f)?;
                f.set_permissions(std::fs::Permissions::from_mode(mode))?;
                f.sync_all()
            });
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(failed(e));
        }
        std::fs::rename(&tmp, &target).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            failed(e)
        })
    }

    #[cfg(test)]
    mod tests {
        use std::collections::BTreeSet;
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        use super::*;

        const UID: u32 = 1000;
        const GID: u32 = 1000;
        const PROGRAM: &[u8] = b"\x7fELF the program";

        /// Every folder this user's, 0755.
        fn owned(_: &Path) -> std::io::Result<PathFacts> {
            Ok(PathFacts {
                uid: UID,
                gid: GID,
                mode: 0o40755,
                symlink: false,
            })
        }

        /// As [`owned`], but every folder named `.local` can be changed by
        /// every account.
        fn others_can_write_local(path: &Path) -> std::io::Result<PathFacts> {
            let mut facts = owned(path)?;
            if path.file_name().is_some_and(|n| n == ".local") {
                facts.mode = 0o40777;
            }
            Ok(facts)
        }

        struct Tree {
            _tmp: tempfile::TempDir,
            root: PathBuf,
        }

        impl Tree {
            fn new() -> Self {
                let tmp = tempfile::tempdir().unwrap();
                let root = tmp.path().to_path_buf();
                Self { _tmp: tmp, root }
            }

            fn install(&self) -> LinuxInstall {
                LinuxInstall::new(
                    self.root.join("home/.local/bin"),
                    self.root.join("home/.local/share/applications"),
                )
                .with_facts(UID, GID, owned)
            }

            /// Every file and link under the root, relative to it.
            fn files(&self) -> BTreeSet<String> {
                fn walk(dir: &Path, root: &Path, out: &mut BTreeSet<String>) {
                    for entry in std::fs::read_dir(dir).unwrap() {
                        let path = entry.unwrap().path();
                        let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
                        if kind.is_dir() {
                            walk(&path, root, out);
                        } else {
                            out.insert(path.strip_prefix(root).unwrap().display().to_string());
                        }
                    }
                }
                let mut out = BTreeSet::new();
                walk(&self.root, &self.root, &mut out);
                out
            }
        }

        fn set(items: &[&str]) -> BTreeSet<String> {
            items.iter().map(|s| (*s).to_owned()).collect()
        }

        /// §B.1.1: the Linux install writes the executable into the bin
        /// folder it was given and the menu entry into the applications
        /// folder it was given, and nothing else anywhere; the entry holds
        /// the keys `Type`, `Name` and `Exec` only.
        #[test]
        fn linux_install_writes_only_the_injected_dirs() {
            let tree = Tree::new();
            let install = tree.install();
            install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
                .unwrap();
            assert_eq!(
                tree.files(),
                set(&[
                    "home/.local/bin/tornect",
                    "home/.local/share/applications/tornect.desktop"
                ])
            );
            assert_eq!(std::fs::read(install.exe()).unwrap(), PROGRAM);
            let mode = std::fs::metadata(install.exe())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o755, "{mode:o}");
            let entry = std::fs::read_to_string(install.menu_entry()).unwrap();
            let exe = install.exe();
            assert_eq!(
                entry,
                format!(
                    "# Written by `tornect install`; `tornect uninstall` removes it.\n\
                     [Desktop Entry]\nType=Application\nName=Tornect\nExec=\"{}\"\n",
                    exe.display()
                )
            );
            let keys: Vec<&str> = entry
                .lines()
                .filter(|l| !l.starts_with('#') && !l.starts_with('['))
                .filter_map(|l| l.split_once('=').map(|(k, _)| k))
                .collect();
            assert_eq!(keys, ["Type", "Name", "Exec"]);
            assert!(install.installed());
        }

        /// The location rule of the start at login (M1-53): a bin folder that
        /// another account can change, or one below such a folder, is refused
        /// before anything is written or created.
        #[test]
        fn an_install_others_can_write_is_refused() {
            let tree = Tree::new();
            std::fs::create_dir_all(tree.root.join("home/.local")).unwrap();
            let install = tree.install().with_facts(UID, GID, others_can_write_local);
            let refused = |install: &LinuxInstall| match install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
            {
                Err(InstallError::Refused(why)) => {
                    assert!(why.starts_with(FOLDER_OTHERS_CAN_CHANGE), "{why}");
                    assert!(why.contains("can be changed by every account"), "{why}");
                }
                other => panic!("installed below a folder others can change: {other:?}"),
            };
            // The bin folder not there yet: the folder above it is checked.
            refused(&install);
            assert!(!tree.root.join("home/.local/bin").exists());
            assert!(tree.files().is_empty(), "{:?}", tree.files());
            // The bin folder there.
            std::fs::create_dir_all(tree.root.join("home/.local/bin")).unwrap();
            refused(&install);
            assert!(tree.files().is_empty(), "{:?}", tree.files());
            assert!(matches!(
                install.preflight(None),
                Err(InstallError::Refused(_))
            ));
        }

        /// A link at the executable's name, at the menu entry's name or at
        /// the temporary file's name is replaced, never followed: what it
        /// points at stays as it was. Uninstalling leaves a link where the
        /// executable was, and says so.
        #[test]
        fn an_existing_link_is_never_followed() {
            let tree = Tree::new();
            let install = tree.install();
            let bin = tree.root.join("home/.local/bin");
            let apps = tree.root.join("home/.local/share/applications");
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::create_dir_all(&apps).unwrap();
            for victim in ["victim-exe", "victim-entry", "victim-tmp", "victim-tmp2"] {
                std::fs::write(tree.root.join(victim), b"victim").unwrap();
            }
            symlink(tree.root.join("victim-exe"), bin.join("tornect")).unwrap();
            symlink(tree.root.join("victim-entry"), apps.join("tornect.desktop")).unwrap();
            symlink(tree.root.join("victim-tmp"), bin.join(".tornect.tmp")).unwrap();
            symlink(
                tree.root.join("victim-tmp2"),
                apps.join(".tornect.desktop.tmp"),
            )
            .unwrap();
            install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
                .unwrap();
            for victim in ["victim-exe", "victim-entry", "victim-tmp", "victim-tmp2"] {
                assert_eq!(std::fs::read(tree.root.join(victim)).unwrap(), b"victim");
            }
            for path in [install.exe(), install.menu_entry()] {
                let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
                assert!(kind.is_file(), "{} is not a regular file", path.display());
            }
            assert_eq!(std::fs::read(install.exe()).unwrap(), PROGRAM);
            assert!(!bin.join(".tornect.tmp").exists());
            std::fs::remove_file(install.exe()).unwrap();
            symlink(tree.root.join("victim-exe"), install.exe()).unwrap();
            let removal = install.uninstall().unwrap();
            assert_eq!(removal.removed, [install.menu_entry()]);
            assert_eq!(removal.left, [install.exe()]);
            assert_eq!(
                std::fs::read(tree.root.join("victim-exe")).unwrap(),
                b"victim"
            );
        }

        /// The menu entry's `Exec` goes through the start-at-sign-in entry's
        /// quoting: every item quoted, `%` written `%%`, a custom home
        /// carried as `--home`; a control character in a path, or a relative
        /// home, refuses the install before anything is written or created.
        #[test]
        fn the_menu_entry_exec_is_quoted_or_refused() {
            let tree = Tree::new();
            let install = LinuxInstall::new(
                tree.root.join("home/50% off/bin"),
                tree.root.join("home/apps"),
            )
            .with_facts(UID, GID, owned);
            let home = tree.root.join("my home");
            install
                .install(&mut std::io::Cursor::new(PROGRAM), Some(&home))
                .unwrap();
            let entry = std::fs::read_to_string(install.menu_entry()).unwrap();
            let exec = format!(
                "Exec=\"{}/home/50%% off/bin/tornect\" \"--home\" \"{}/my home\"",
                tree.root.display(),
                tree.root.display()
            );
            assert!(entry.lines().any(|l| l == exec), "{entry}");
            let bad = LinuxInstall::new(
                tree.root.join("home/new\nline/bin"),
                tree.root.join("home/apps2"),
            )
            .with_facts(UID, GID, owned);
            match bad.install(&mut std::io::Cursor::new(PROGRAM), None) {
                Err(InstallError::Unavailable(why)) => {
                    assert!(why.contains("control character"), "{why}");
                }
                other => panic!("an unquotable path was written: {other:?}"),
            }
            for dir in ["home/new\nline", "home/apps2"] {
                assert!(!tree.root.join(dir).exists(), "{dir:?} was created");
            }
            let relative = LinuxInstall::new(tree.root.join("home/bin3"), tree.root.join("a3"))
                .with_facts(UID, GID, owned);
            assert!(matches!(
                relative.install(
                    &mut std::io::Cursor::new(PROGRAM),
                    Some(Path::new("relative/home"))
                ),
                Err(InstallError::Unavailable(_))
            ));
            assert!(!tree.root.join("home/bin3").exists());
        }

        /// Uninstalling removes the menu entry and the executable it wrote,
        /// and nothing else in either folder.
        #[test]
        fn uninstall_removes_exactly_what_install_wrote() {
            let tree = Tree::new();
            let install = tree.install();
            install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
                .unwrap();
            std::fs::write(tree.root.join("home/.local/bin/other-tool"), b"x").unwrap();
            std::fs::write(
                tree.root
                    .join("home/.local/share/applications/other.desktop"),
                b"x",
            )
            .unwrap();
            let removal = install.uninstall().unwrap();
            assert_eq!(removal.removed, [install.menu_entry(), install.exe()]);
            assert!(removal.left.is_empty());
            assert_eq!(
                tree.files(),
                set(&[
                    "home/.local/bin/other-tool",
                    "home/.local/share/applications/other.desktop"
                ])
            );
            assert!(!install.installed());
        }

        /// Uninstalling where nothing was installed removes nothing and
        /// creates nothing.
        #[test]
        fn uninstalling_nothing_is_a_no_op() {
            let tree = Tree::new();
            let install = tree.install();
            assert!(!install.installed());
            assert_eq!(install.uninstall().unwrap(), Removal::default());
            assert_eq!(std::fs::read_dir(&tree.root).unwrap().count(), 0);
        }
    }
}

/// The Program Files steps over a recording fake of Windows (every system).
#[cfg(test)]
mod windows_tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    const PF: &str = "C:\\Program Files";
    const SYSTEM32: &str = "C:\\Windows\\System32";
    const PROGRAMS: &str =
        "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs";
    const IMAGE: &str = "C:\\Users\\u\\Downloads\\tornect\\tornect.exe";
    const PROGRAM: &[u8] = b"MZ the program";

    /// What the fake was asked, in order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Ev {
        OpenImage,
        ReadImage,
        CloseImage,
        Authorize,
        Elevated(Elevated),
        WriteShortcut(String),
        RemoveShortcut(String),
        Security(String),
    }

    /// Owner Administrators; SYSTEM and Administrators full control,
    /// Users read and execute.
    fn admin_only_security() -> Security {
        Security {
            owner: "S-1-5-32-544".to_owned(),
            dacl: vec![
                crate::helper_task::Ace {
                    sid: "S-1-5-18".to_owned(),
                    allow: true,
                    mask: 0x001F_01FF,
                    flags: 0,
                },
                crate::helper_task::Ace {
                    sid: "S-1-5-32-544".to_owned(),
                    allow: true,
                    mask: 0x001F_01FF,
                    flags: 0,
                },
                crate::helper_task::Ace {
                    sid: "S-1-5-32-545".to_owned(),
                    allow: true,
                    mask: 0x0012_00A9,
                    flags: 0,
                },
            ],
        }
    }

    /// Windows as the steps see it: files, folders, Start-menu entries and
    /// uninstall entries in memory; every call recorded.
    struct Fake {
        events: RefCell<Vec<Ev>>,
        program_files: String,
        image: Vec<u8>,
        /// What a copy writes instead of the held image (a swap).
        copy_writes: Option<Vec<u8>>,
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        folders: RefCell<BTreeSet<String>>,
        reparse: BTreeSet<String>,
        shortcuts: RefCell<BTreeMap<String, String>>,
        entries: RefCell<BTreeMap<String, UninstallEntry>>,
        /// Paths whose DACL lets Users write.
        writable_by_users: BTreeSet<String>,
        /// Paths owned by an ordinary account.
        owned_by_users: BTreeSet<String>,
        /// Paths that became reparse points while the steps ran.
        reparse_now: RefCell<BTreeSet<String>>,
        /// Paths whose DACL came to let Users write while the steps ran.
        writable_now: RefCell<BTreeSet<String>>,
        /// A path that becomes a reparse point when the copy runs.
        on_copy_link: Option<String>,
        /// A path that becomes a reparse point when the Start-menu entry is
        /// written.
        on_shortcut_link: Option<String>,
        /// Elevated steps cancelled at the prompt (by kind), once each.
        cancel: RefCell<Vec<&'static str>>,
        /// Elevated steps that fail (by kind).
        fail: Vec<&'static str>,
        /// The program that would run a step elevated, by kind; System32's
        /// otherwise.
        runner: BTreeMap<&'static str, String>,
    }

    fn kind(step: &Elevated) -> &'static str {
        match step {
            Elevated::Copy { .. } => "copy",
            Elevated::WriteEntry(_) => "write",
            Elevated::DeleteEntry { .. } => "delete",
            Elevated::RemoveFolder { .. } => "remove",
        }
    }

    fn key(path: &str) -> String {
        path.to_lowercase()
    }

    impl Fake {
        fn new() -> Self {
            Self {
                events: RefCell::new(Vec::new()),
                program_files: PF.to_owned(),
                image: PROGRAM.to_vec(),
                copy_writes: None,
                files: RefCell::new(BTreeMap::new()),
                folders: RefCell::new(BTreeSet::new()),
                reparse: BTreeSet::new(),
                shortcuts: RefCell::new(BTreeMap::new()),
                entries: RefCell::new(BTreeMap::new()),
                writable_by_users: BTreeSet::new(),
                owned_by_users: BTreeSet::new(),
                reparse_now: RefCell::new(BTreeSet::new()),
                writable_now: RefCell::new(BTreeSet::new()),
                on_copy_link: None,
                on_shortcut_link: None,
                cancel: RefCell::new(Vec::new()),
                fail: Vec::new(),
                runner: BTreeMap::new(),
            }
        }

        fn folder(&self) -> String {
            format!("{}\\Tornect", self.program_files)
        }

        fn exe(&self) -> String {
            format!("{}\\Tornect\\tornect.exe", self.program_files)
        }

        fn link() -> String {
            format!("{PROGRAMS}\\Tornect.lnk")
        }

        fn events(&self) -> Vec<Ev> {
            self.events.borrow().clone()
        }

        fn elevated(&self) -> Vec<Elevated> {
            self.events()
                .into_iter()
                .filter_map(|e| match e {
                    Ev::Elevated(step) => Some(step),
                    _ => None,
                })
                .collect()
        }

        fn record(&self, ev: Ev) {
            self.events.borrow_mut().push(ev);
        }

        /// Nothing of an install anywhere: no install folder or file in it,
        /// no Start-menu entry, no uninstall entry.
        fn assert_nothing_installed(&self) {
            let folder = key(&self.folder());
            assert!(
                !self.folders.borrow().contains(&folder),
                "the folder is left"
            );
            assert!(
                !self.files.borrow().keys().any(|f| f.starts_with(&folder)),
                "{:?}",
                self.files.borrow().keys()
            );
            assert!(
                self.shortcuts.borrow().is_empty(),
                "{:?}",
                self.shortcuts.borrow()
            );
            assert!(
                self.entries.borrow().is_empty(),
                "{:?}",
                self.entries.borrow()
            );
        }

        /// An install as `install_in_program_files` leaves it.
        fn installed(&self) {
            self.folders.borrow_mut().insert(key(&self.folder()));
            self.files
                .borrow_mut()
                .insert(key(&self.exe()), self.image.clone());
            self.shortcuts
                .borrow_mut()
                .insert(key(&Self::link()), self.exe());
            let target = WindowsTarget::of(self).unwrap();
            self.entries
                .borrow_mut()
                .insert(UNINSTALL_KEY.to_owned(), target.entry);
        }
    }

    struct FakeImage<'a> {
        fake: &'a Fake,
        at: usize,
    }

    impl std::io::Read for FakeImage<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.fake.record(Ev::ReadImage);
            let rest = &self.fake.image[self.at..];
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.at += n;
            Ok(n)
        }
    }

    impl HeldImage for FakeImage<'_> {
        fn path(&self) -> &str {
            IMAGE
        }
    }

    impl Drop for FakeImage<'_> {
        fn drop(&mut self) {
            self.fake.record(Ev::CloseImage);
        }
    }

    impl WindowsSystem for Fake {
        fn program_files(&self) -> Result<String, InstallError> {
            Ok(self.program_files.clone())
        }

        fn system_directory(&self) -> Result<String, InstallError> {
            Ok(SYSTEM32.to_owned())
        }

        fn start_menu_programs(&self) -> Result<String, InstallError> {
            Ok(PROGRAMS.to_owned())
        }

        fn open_own_image(&self) -> Result<Box<dyn HeldImage + '_>, InstallError> {
            self.record(Ev::OpenImage);
            Ok(Box::new(FakeImage { fake: self, at: 0 }))
        }

        fn folder_entries(&self, folder: &str) -> Result<Option<Vec<String>>, InstallError> {
            let folder = key(folder);
            if !self.folders.borrow().contains(&folder) {
                return Ok(None);
            }
            let prefix = format!("{folder}\\");
            Ok(Some(
                self.files
                    .borrow()
                    .keys()
                    .filter_map(|f| f.strip_prefix(&prefix).map(str::to_owned))
                    .collect(),
            ))
        }

        fn is_reparse_point(&self, path: &str) -> Result<bool, InstallError> {
            Ok(self.reparse.contains(&key(path)) || self.reparse_now.borrow().contains(&key(path)))
        }

        fn read_file(&self, path: &str) -> Result<Box<dyn std::io::Read + '_>, InstallError> {
            let bytes = self
                .files
                .borrow()
                .get(&key(path))
                .cloned()
                .ok_or_else(|| InstallError::Failed(format!("{path}: not found")))?;
            Ok(Box::new(std::io::Cursor::new(bytes)))
        }

        fn security(&self, path: &str) -> Result<Security, InstallError> {
            self.record(Ev::Security(path.to_owned()));
            let mut security = admin_only_security();
            if self.writable_by_users.contains(&key(path))
                || self.writable_now.borrow().contains(&key(path))
            {
                security.dacl[2].mask |= 0x2;
            }
            if self.owned_by_users.contains(&key(path)) {
                security.owner = "S-1-5-21-1-2-3-1001".to_owned();
            }
            Ok(security)
        }

        fn elevated_program(&self, step: &Elevated) -> String {
            self.runner
                .get(kind(step))
                .cloned()
                .unwrap_or_else(|| format!("{SYSTEM32}\\robocopy.exe"))
        }

        fn run_elevated(&self, step: &Elevated) -> Result<(), InstallError> {
            let mut cancel = self.cancel.borrow_mut();
            if let Some(at) = cancel.iter().position(|k| *k == kind(step)) {
                cancel.remove(at);
                return Err(InstallError::Cancelled(
                    "the prompt was dismissed".to_owned(),
                ));
            }
            drop(cancel);
            self.record(Ev::Elevated(step.clone()));
            if self.fail.contains(&kind(step)) {
                return Err(InstallError::Failed(format!("{} failed", kind(step))));
            }
            match step {
                Elevated::Copy { to, .. } => {
                    let folder = to.rsplit_once('\\').unwrap().0;
                    self.folders.borrow_mut().insert(key(folder));
                    let bytes = self
                        .copy_writes
                        .clone()
                        .unwrap_or_else(|| self.image.clone());
                    self.files.borrow_mut().insert(key(to), bytes);
                    if let Some(link) = &self.on_copy_link {
                        self.reparse_now.borrow_mut().insert(key(link));
                    }
                }
                Elevated::WriteEntry(entry) => {
                    self.entries
                        .borrow_mut()
                        .insert(entry.key.clone(), entry.clone());
                }
                Elevated::DeleteEntry { key: k } => {
                    self.entries.borrow_mut().remove(k);
                }
                Elevated::RemoveFolder { folder } => {
                    let folder = key(folder);
                    let prefix = format!("{folder}\\");
                    self.files
                        .borrow_mut()
                        .retain(|f, _| !f.starts_with(&prefix));
                    self.folders.borrow_mut().remove(&folder);
                }
            }
            Ok(())
        }

        fn uninstall_entry_exists(&self, k: &str) -> Result<bool, InstallError> {
            Ok(self.entries.borrow().contains_key(k))
        }

        fn file_exists(&self, path: &str) -> Result<bool, InstallError> {
            Ok(self.shortcuts.borrow().contains_key(&key(path))
                || self.files.borrow().contains_key(&key(path)))
        }

        fn write_shortcut(&self, link: &str, target: &str) -> Result<(), InstallError> {
            self.record(Ev::WriteShortcut(link.to_owned()));
            self.shortcuts
                .borrow_mut()
                .insert(key(link), target.to_owned());
            if let Some(path) = &self.on_shortcut_link {
                self.reparse_now.borrow_mut().insert(key(path));
            }
            Ok(())
        }

        fn remove_shortcut(&self, link: &str) -> Result<(), InstallError> {
            self.record(Ev::RemoveShortcut(link.to_owned()));
            self.shortcuts.borrow_mut().remove(&key(link));
            Ok(())
        }
    }

    /// The guard's operation as the steps see it: recorded, allowed.
    fn allow(fake: &Fake) -> impl FnMut() -> Result<(), InstallError> + '_ {
        move || {
            fake.record(Ev::Authorize);
            Ok(())
        }
    }

    fn position(events: &[Ev], wanted: impl Fn(&Ev) -> bool) -> usize {
        events
            .iter()
            .position(wanted)
            .unwrap_or_else(|| panic!("not found in {events:?}"))
    }

    /// The source is held and hashed before the guard's dialog and the
    /// first prompt, and held to the end: a file swapped during the dialog
    /// cannot be what is hashed as the source.
    #[test]
    fn the_source_is_held_and_hashed_before_the_reauth() {
        let fake = Fake::new();
        install_in_program_files(&fake, &mut allow(&fake)).unwrap();
        let events = fake.events();
        let open = position(&events, |e| *e == Ev::OpenImage);
        let authorize = position(&events, |e| *e == Ev::Authorize);
        let copy = position(&events, |e| {
            matches!(e, Ev::Elevated(Elevated::Copy { .. }))
        });
        let reads = events[..authorize]
            .iter()
            .filter(|e| **e == Ev::ReadImage)
            .count();
        assert_eq!(open, 0, "{events:?}");
        assert!(
            reads >= 2,
            "the whole image read before the dialog: {events:?}"
        );
        assert!(
            !events[authorize..].contains(&Ev::ReadImage),
            "the image read after the dialog: {events:?}"
        );
        assert!(authorize < copy, "{events:?}");
        assert_eq!(
            events.last(),
            Some(&Ev::CloseImage),
            "held to the end: {events:?}"
        );
        assert_eq!(events.iter().filter(|e| **e == Ev::CloseImage).count(), 1);
    }

    /// Program Files is the known folder the system gives, never anything
    /// else: every path the steps write, check or register is under it.
    #[test]
    fn program_files_comes_from_the_known_folder_never_the_environment() {
        let mut fake = Fake::new();
        fake.program_files = "K:\\Known Apps".to_owned();
        let installed = install_in_program_files(&fake, &mut allow(&fake)).unwrap();
        assert_eq!(installed.folder, "K:\\Known Apps\\Tornect");
        assert_eq!(installed.exe, "K:\\Known Apps\\Tornect\\tornect.exe");
        for ev in fake.events() {
            match ev {
                Ev::Elevated(Elevated::Copy { from, to }) => {
                    assert_eq!(from, IMAGE);
                    assert_eq!(to, installed.exe);
                }
                Ev::Elevated(Elevated::WriteEntry(entry)) => assert_eq!(
                    entry.uninstall_string,
                    "\"K:\\Known Apps\\Tornect\\tornect.exe\" uninstall"
                ),
                Ev::Security(path) => assert!(path.starts_with("K:\\Known Apps"), "{path}"),
                Ev::Elevated(other) => panic!("{other:?}"),
                _ => {}
            }
        }
        let text = format!("{:?}", fake.events());
        assert!(!text.contains("C:\\\\Program Files"), "{text}");
    }

    /// A copy that is not the held image (the source replaced while it was
    /// copied) is found by its hash before anything points at it, and
    /// removed again: no Start-menu entry, no uninstall entry.
    #[test]
    fn a_swapped_source_is_detected_and_nothing_points_at_it() {
        let mut fake = Fake::new();
        fake.copy_writes = Some(b"MZ another program".to_vec());
        match install_in_program_files(&fake, &mut allow(&fake)) {
            Err(InstallError::Refused(why)) => assert_eq!(why, SOURCE_SWAPPED),
            other => panic!("not refused as a swapped source: {other:?}"),
        }
        let events = fake.events();
        assert!(
            !events.iter().any(|e| matches!(
                e,
                Ev::WriteShortcut(_) | Ev::Elevated(Elevated::WriteEntry(_)) | Ev::Security(_)
            )),
            "{events:?}"
        );
        assert_eq!(
            fake.elevated().last(),
            Some(&Elevated::RemoveFolder {
                folder: fake.folder()
            })
        );
        fake.assert_nothing_installed();
    }

    /// An existing `<Program Files>\Tornect` that holds anything but
    /// `tornect.exe`, or is a reparse point, is refused before the dialog
    /// and before any prompt; one that holds only `tornect.exe` (an earlier
    /// install, or one cut short) is installed over, and checked again.
    #[test]
    fn a_non_empty_existing_folder_is_refused() {
        let fake = Fake::new();
        fake.folders.borrow_mut().insert(key(&fake.folder()));
        for name in ["tornect.exe", "version.dll"] {
            fake.files
                .borrow_mut()
                .insert(key(&format!("{}\\{name}", fake.folder())), b"x".to_vec());
        }
        match install_in_program_files(&fake, &mut allow(&fake)) {
            Err(InstallError::Refused(why)) => assert_eq!(
                why,
                "C:\\Program Files\\Tornect already holds other files, so Tornect was not \
                 installed there."
            ),
            other => panic!("installed beside other files: {other:?}"),
        }
        assert!(
            !fake
                .events()
                .iter()
                .any(|e| matches!(e, Ev::Authorize | Ev::Elevated(_))),
            "{:?}",
            fake.events()
        );
        let mut junction = Fake::new();
        let folder = key(&junction.folder());
        junction.folders.borrow_mut().insert(folder.clone());
        junction.reparse.insert(folder);
        assert!(matches!(
            install_in_program_files(&junction, &mut allow(&junction)),
            Err(InstallError::Refused(why)) if why.contains("is a link to another place")
        ));
        assert!(junction.elevated().is_empty());
        let earlier = Fake::new();
        earlier.folders.borrow_mut().insert(key(&earlier.folder()));
        earlier
            .files
            .borrow_mut()
            .insert(key(&earlier.exe()), b"old".to_vec());
        install_in_program_files(&earlier, &mut allow(&earlier)).unwrap();
        assert_eq!(
            earlier.files.borrow().get(&key(&earlier.exe())),
            Some(&PROGRAM.to_vec())
        );
    }

    /// The uninstall entry failing after the copy undoes the install: the
    /// Start-menu entry and the copy are removed, newest first.
    #[test]
    fn a_write_entry_after_the_copy_undoes_the_install() {
        let mut fake = Fake::new();
        fake.fail = vec!["write"];
        match install_in_program_files(&fake, &mut allow(&fake)) {
            Err(InstallError::Failed(why)) => assert_eq!(why, "write failed"),
            other => panic!("{other:?}"),
        }
        let events = fake.events();
        let write = position(&events, |e| {
            matches!(e, Ev::Elevated(Elevated::WriteEntry(_)))
        });
        assert_eq!(
            events[write + 1..],
            [
                Ev::RemoveShortcut(Fake::link()),
                Ev::Elevated(Elevated::RemoveFolder {
                    folder: fake.folder()
                }),
                Ev::CloseImage,
            ]
        );
        fake.assert_nothing_installed();
    }

    /// The uninstall entry runs the installed executable by its quoted
    /// absolute path with the fixed argument, and names Tornect with this
    /// build's version and no publisher.
    #[test]
    fn the_uninstall_command_is_quoted_with_its_fixed_argument() {
        let fake = Fake::new();
        install_in_program_files(&fake, &mut allow(&fake)).unwrap();
        let entries = fake.entries.borrow();
        let entry = entries.get(UNINSTALL_KEY).unwrap();
        assert_eq!(
            entry,
            &UninstallEntry {
                key: "Tornect".to_owned(),
                display_name: "Tornect".to_owned(),
                display_version: env!("CARGO_PKG_VERSION").to_owned(),
                uninstall_string: "\"C:\\Program Files\\Tornect\\tornect.exe\" uninstall"
                    .to_owned(),
            }
        );
        assert_eq!(
            uninstall_command("D:\\Apps\\Tornect\\tornect.exe").unwrap(),
            "\"D:\\Apps\\Tornect\\tornect.exe\" uninstall"
        );
    }

    /// A Program Files path that cannot be written into the uninstall
    /// command (not absolute on a drive; a control character, `"` or `%`)
    /// refuses the install before the dialog and before any prompt.
    #[test]
    fn an_unquotable_path_is_refused() {
        for bad in [
            "Program Files",
            "\\\\server\\share",
            "C:\\Pro\"gram",
            "C:\\Program%PATH%",
            "C:\\Pro\ngram",
        ] {
            let mut fake = Fake::new();
            fake.program_files = bad.to_owned();
            match install_in_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Unavailable(why)) => {
                    assert!(why.contains("uninstall entry"), "{bad:?}: {why}");
                }
                other => panic!("{bad:?}: {other:?}"),
            }
            assert!(
                !fake
                    .events()
                    .iter()
                    .any(|e| matches!(e, Ev::Authorize | Ev::Elevated(_))),
                "{bad:?}: {:?}",
                fake.events()
            );
            assert!(
                uninstall_command(&format!("{bad}\\tornect.exe")).is_err(),
                "{bad:?}"
            );
        }
    }

    /// A cancelled prompt leaves nothing: at the copy nothing was done; at
    /// the uninstall entry, the Start-menu entry and the copy are removed.
    #[test]
    fn a_cancelled_uac_leaves_nothing() {
        for at in ["copy", "write"] {
            let fake = Fake::new();
            fake.cancel.borrow_mut().push(at);
            match install_in_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Cancelled(why)) => {
                    assert_eq!(why, INSTALL_NEEDS_APPROVAL, "{at}");
                }
                other => panic!("{at}: {other:?}"),
            }
            fake.assert_nothing_installed();
        }
    }

    /// Uninstalling reverses every step of the install: the uninstall
    /// entry, the Start-menu entry, then the folder, after the guard's
    /// operation; nothing is left.
    #[test]
    fn uninstall_reverses_every_step() {
        let fake = Fake::new();
        install_in_program_files(&fake, &mut allow(&fake)).unwrap();
        fake.events.borrow_mut().clear();
        let removed = uninstall_from_program_files(&fake, &mut allow(&fake)).unwrap();
        assert_eq!(
            removed,
            WindowsRemoval {
                uninstall_entry: true,
                start_menu_entry: true,
                folder: true
            }
        );
        let events = fake.events();
        let authorize = position(&events, |e| *e == Ev::Authorize);
        let changes: Vec<Ev> = events[authorize + 1..]
            .iter()
            .filter(|e| !matches!(e, Ev::Security(_)))
            .cloned()
            .collect();
        assert_eq!(
            changes,
            [
                Ev::Elevated(Elevated::DeleteEntry {
                    key: "Tornect".to_owned()
                }),
                Ev::RemoveShortcut(Fake::link()),
                Ev::Elevated(Elevated::RemoveFolder {
                    folder: fake.folder()
                }),
            ]
        );
        fake.assert_nothing_installed();
        // Nothing left: nothing asked.
        fake.events.borrow_mut().clear();
        assert_eq!(
            uninstall_from_program_files(&fake, &mut allow(&fake)).unwrap(),
            WindowsRemoval::default()
        );
        assert!(!fake.events().contains(&Ev::Authorize));
    }

    /// The uninstall's target is `<Program Files>\Tornect` from the known
    /// folder, whatever this program's own path is; a target that is a
    /// reparse point, or that accounts other than administrators can change,
    /// is refused before any elevated delete.
    #[test]
    fn uninstall_targets_only_the_known_folder() {
        let fake = Fake::new();
        fake.installed();
        let decoy = "c:\\users\\u\\downloads\\tornect".to_owned();
        fake.folders.borrow_mut().insert(decoy.clone());
        uninstall_from_program_files(&fake, &mut allow(&fake)).unwrap();
        let folders: Vec<String> = fake
            .elevated()
            .into_iter()
            .filter_map(|s| match s {
                Elevated::RemoveFolder { folder } => Some(folder),
                _ => None,
            })
            .collect();
        assert_eq!(folders, [fake.folder()]);
        assert!(fake.folders.borrow().contains(&decoy));
        for broken in ["reparse", "acl"] {
            let mut fake = Fake::new();
            fake.installed();
            let folder = key(&fake.folder());
            if broken == "reparse" {
                fake.reparse.insert(folder);
            } else {
                fake.writable_by_users.insert(folder);
            }
            match uninstall_from_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Refused(why)) => {
                    assert!(why.contains("did not remove it"), "{broken}: {why}");
                }
                other => panic!("{broken}: {other:?}"),
            }
            assert!(fake.elevated().is_empty(), "{broken}: {:?}", fake.events());
            assert!(!fake.events().contains(&Ev::Authorize), "{broken}");
        }
    }

    /// No step, of the uninstall or of the install, runs elevated through a
    /// program outside Program Files and the system folder (this program's
    /// own copy in Downloads included): refused before the dialog.
    #[test]
    fn uninstall_never_elevates_a_copy_outside_program_files() {
        for step in ["delete", "remove"] {
            let mut fake = Fake::new();
            fake.installed();
            fake.runner.insert(step, IMAGE.to_owned());
            match uninstall_from_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Unavailable(why)) => {
                    assert!(why.contains(IMAGE), "{why}");
                }
                other => panic!("{step}: {other:?}"),
            }
            assert!(fake.elevated().is_empty(), "{step}: {:?}", fake.events());
            assert!(!fake.events().contains(&Ev::Authorize));
            assert!(fake.entries.borrow().contains_key(UNINSTALL_KEY));
        }
        let mut fake = Fake::new();
        fake.runner.insert("copy", IMAGE.to_owned());
        assert!(matches!(
            install_in_program_files(&fake, &mut allow(&fake)),
            Err(InstallError::Unavailable(_))
        ));
        assert!(fake.elevated().is_empty());
        // The installed copy itself may run a step: it is in Program Files.
        let mut fake = Fake::new();
        fake.installed();
        let exe = fake.exe();
        fake.runner.insert("delete", exe);
        uninstall_from_program_files(&fake, &mut allow(&fake)).unwrap();
    }

    /// An existing `<Program Files>\Tornect` is checked as the copy will be,
    /// before the dialog: a folder, a `tornect.exe` in it or Program Files
    /// that accounts other than administrators can change, or a
    /// `tornect.exe` that is a reparse point, is refused before anything is
    /// asked or run (an empty folder too).
    #[test]
    fn an_existing_folder_is_checked_before_the_dialog() {
        for broken in ["folder", "exe", "program files", "exe link"] {
            let mut fake = Fake::new();
            let folder = key(&fake.folder());
            fake.folders.borrow_mut().insert(folder.clone());
            if broken != "folder" {
                fake.files
                    .borrow_mut()
                    .insert(key(&fake.exe()), PROGRAM.to_vec());
            }
            match broken {
                "folder" => {
                    fake.writable_by_users.insert(folder);
                }
                "exe" => {
                    fake.writable_by_users.insert(key(&fake.exe()));
                }
                "program files" => {
                    fake.writable_by_users.insert(key(PF));
                }
                _ => {
                    fake.reparse.insert(key(&fake.exe()));
                }
            }
            match install_in_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Refused(why)) => assert!(
                    why.contains("could be changed by accounts other than administrators")
                        || (broken == "exe link" && why.contains("is a link to another place")),
                    "{broken}: {why}"
                ),
                other => panic!("{broken}: installed: {other:?}"),
            }
            assert!(
                !fake
                    .events()
                    .iter()
                    .any(|e| matches!(e, Ev::Authorize | Ev::Elevated(_))),
                "{broken}: {:?}",
                fake.events()
            );
        }
    }

    /// The dialog can stay open for long: the folder is checked again after
    /// it. One that became, while it was open, a reparse point that other
    /// accounts can change, or that appeared as one, is refused before the
    /// copy: nothing runs elevated.
    #[test]
    fn a_folder_changed_during_the_dialog_is_refused_before_the_copy() {
        for existed in [true, false] {
            let fake = Fake::new();
            let folder = key(&fake.folder());
            if existed {
                fake.folders.borrow_mut().insert(folder.clone());
            }
            let mut turn_into_a_link = || {
                fake.record(Ev::Authorize);
                fake.folders.borrow_mut().insert(folder.clone());
                fake.reparse_now.borrow_mut().insert(folder.clone());
                fake.writable_now.borrow_mut().insert(folder.clone());
                Ok(())
            };
            match install_in_program_files(&fake, &mut turn_into_a_link) {
                Err(InstallError::Refused(why)) => {
                    assert!(
                        why.contains("is a link to another place"),
                        "existed {existed}: {why}"
                    );
                }
                other => panic!("existed {existed}: installed: {other:?}"),
            }
            assert!(fake.events().contains(&Ev::Authorize));
            assert!(
                fake.elevated().is_empty(),
                "existed {existed}: {:?}",
                fake.events()
            );
            assert!(fake.shortcuts.borrow().is_empty() && fake.entries.borrow().is_empty());
        }
    }

    /// After the copy, the folder and the copy are checked for reparse
    /// points before the copy is read and hashed (here the copy is also not
    /// the held image, and the link is what is reported): nothing points at
    /// it, and the folder, now a link to another place, is never deleted as
    /// administrator; the refusal says what was left.
    #[test]
    fn the_copy_is_never_read_or_removed_through_a_link() {
        for at in ["folder", "exe"] {
            let mut fake = Fake::new();
            fake.copy_writes = Some(b"MZ another program".to_vec());
            fake.on_copy_link = Some(if at == "folder" {
                fake.folder()
            } else {
                fake.exe()
            });
            match install_in_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Refused(why)) => {
                    assert!(why.contains("link to another place"), "{at}: {why}");
                    assert!(
                        why.contains("did not remove it as administrator"),
                        "{at}: {why}"
                    );
                }
                other => panic!("{at}: {other:?}"),
            }
            assert!(
                matches!(fake.elevated().as_slice(), [Elevated::Copy { .. }]),
                "{at}: {:?}",
                fake.events()
            );
            assert!(fake.shortcuts.borrow().is_empty() && fake.entries.borrow().is_empty());
        }
    }

    /// The undo deletes the install folder as administrator only after a
    /// reparse check of its own, and never a folder found unsafe: a copy
    /// that failed the ACL check is left where it is (nothing points at it,
    /// and the refusal says so), and a folder that became a reparse point
    /// before an undo is not deleted through it.
    #[test]
    fn an_install_never_deletes_as_administrator_a_folder_found_unsafe() {
        let mut fake = Fake::new();
        fake.writable_by_users.insert(key(&fake.folder()));
        match install_in_program_files(&fake, &mut allow(&fake)) {
            Err(InstallError::Refused(why)) => assert_eq!(why, COPY_NOT_ADMIN_ONLY),
            other => panic!("{other:?}"),
        }
        assert!(
            matches!(fake.elevated().as_slice(), [Elevated::Copy { .. }]),
            "{:?}",
            fake.events()
        );
        assert!(fake.shortcuts.borrow().is_empty() && fake.entries.borrow().is_empty());

        let mut fake = Fake::new();
        fake.fail = vec!["write"];
        fake.on_shortcut_link = Some(fake.folder());
        match install_in_program_files(&fake, &mut allow(&fake)) {
            Err(InstallError::Failed(why)) => {
                assert!(why.starts_with("write failed"), "{why}");
                assert!(why.contains("did not remove it as administrator"), "{why}");
            }
            other => panic!("{other:?}"),
        }
        assert!(
            !fake
                .elevated()
                .iter()
                .any(|s| matches!(s, Elevated::RemoveFolder { .. })),
            "{:?}",
            fake.events()
        );
        assert!(fake.shortcuts.borrow().is_empty() && fake.entries.borrow().is_empty());
    }

    /// The ACL check after the copy (§B.1.1: no write, delete or owner-change
    /// entry for a non-administrator, before anything points at the copy):
    /// a copy that the executable's, the folder's or Program Files' DACL
    /// lets other accounts change, or whose owner is an ordinary account, is
    /// refused each time. Nothing points at it (no Start-menu entry, no
    /// uninstall entry), and nothing runs elevated after the copy: it is not
    /// deleted as administrator, and the refusal says to delete it by hand.
    #[test]
    fn a_copy_others_can_change_is_refused_and_nothing_points_at_it() {
        for broken in ["exe", "folder", "program files", "owner"] {
            let mut fake = Fake::new();
            match broken {
                "exe" => {
                    fake.writable_by_users.insert(key(&fake.exe()));
                }
                "folder" => {
                    fake.writable_by_users.insert(key(&fake.folder()));
                }
                "program files" => {
                    fake.writable_by_users.insert(key(PF));
                }
                _ => {
                    fake.owned_by_users.insert(key(&fake.exe()));
                }
            }
            match install_in_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Refused(why)) => {
                    assert_eq!(why, COPY_NOT_ADMIN_ONLY, "{broken}");
                }
                other => panic!("{broken}: installed: {other:?}"),
            }
            let events = fake.events();
            assert!(
                !events.iter().any(|e| matches!(
                    e,
                    Ev::WriteShortcut(_) | Ev::Elevated(Elevated::WriteEntry(_))
                )),
                "{broken}: {events:?}"
            );
            assert!(
                matches!(fake.elevated().as_slice(), [Elevated::Copy { .. }]),
                "{broken}: {events:?}"
            );
            assert!(fake.shortcuts.borrow().is_empty(), "{broken}");
            assert!(fake.entries.borrow().is_empty(), "{broken}");
        }
    }

    /// Where the ACL check runs in an install that passes it: its reads of
    /// the executable, the folder and Program Files come after the copy and
    /// before the first entry that points at the copy, and no read comes
    /// anywhere else.
    #[test]
    fn the_acl_check_runs_after_the_copy_and_before_any_entry() {
        let fake = Fake::new();
        install_in_program_files(&fake, &mut allow(&fake)).unwrap();
        let events = fake.events();
        let copy = position(&events, |e| {
            matches!(e, Ev::Elevated(Elevated::Copy { .. }))
        });
        let first_entry = position(&events, |e| {
            matches!(
                e,
                Ev::WriteShortcut(_) | Ev::Elevated(Elevated::WriteEntry(_))
            )
        });
        let reads: Vec<(usize, String)> = events
            .iter()
            .enumerate()
            .filter_map(|(at, e)| match e {
                Ev::Security(path) => Some((at, key(path))),
                _ => None,
            })
            .collect();
        for wanted in [fake.exe(), fake.folder(), PF.to_owned()] {
            assert!(
                reads
                    .iter()
                    .any(|(at, path)| *path == key(&wanted) && copy < *at && *at < first_entry),
                "{wanted} not read between the copy and the first entry: {events:?}"
            );
        }
        assert!(
            reads.iter().all(|(at, _)| copy < *at && *at < first_entry),
            "{events:?}"
        );
    }
}
