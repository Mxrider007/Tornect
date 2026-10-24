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
//! start-at-sign-in entry uses. Beside it goes the link entry
//! `tornect-link.desktop`, the handler of `tornect:` links (design `invite`
//! §4.5): `NoDisplay=true`, `MimeType=x-scheme-handler/tornect;`, and an
//! `Exec` that runs `open-link -- %u`, its items bare where they can be
//! ([`desktop_exec_bare`](crate::autostart::desktop_exec_bare)). Before
//! anything is written, the folder of the executable passes the start at
//! login's location rule
//! ([`unix_exe_location_ok`](crate::autostart::unix_exe_location_ok): neither
//! it nor a folder above it can be changed by another account, and none is a
//! link). Each file is written to a new temporary file in its folder and
//! renamed over its name, so a link found at any of the names is replaced,
//! never followed. Last, since GIO finds no handler from `MimeType=` alone,
//! the link entry is named for `x-scheme-handler/tornect` in this user's
//! `mimeapps.list` (`$XDG_CONFIG_HOME`, else `~/.config`): our lines only,
//! every other byte kept, never through a link, and never over the user's
//! own removal or another program's default; that step reports
//! ([`LinkHandler`]) and never fails the install. Uninstalling takes those
//! lines out again and removes exactly the three files, and only where they
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
//! then this user's registration of `tornect:` links
//! (`HKEY_CURRENT_USER\Software\Classes\tornect`, no elevation; design
//! `invite` §4.5), written only where no such key was there before the
//! dialog: a leftover with this install's own command is kept and never
//! undone, and any other key is left as it is and reported
//! ([`WindowsLinks`]); then the Apps-and-features entry (elevated), whose
//! command is the quoted path with the fixed argument `uninstall`. A failure
//! undoes what was done, newest first, but a folder found unsafe is never
//! deleted as administrator, and a registration this install did not write
//! is never deleted. Each elevated step runs only through its own program
//! ([`elevated_command`]): the system folder's robocopy, reg and cmd for the
//! copy, the entry's delete and the folder's removal, and the installed copy,
//! after its checks, for the entry and for its own removal at the next
//! restart, which an uninstall run from that copy asks for instead of
//! deleting the folder it runs from; the held image must be named
//! `tornect.exe`, since the copy keeps the name. The Windows calls are those
//! of the `win_install` module.

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

/// Where the uninstall entry's key is, under HKLM.
pub const UNINSTALL_ROOT: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

/// The subcommand an opened `tornect:` link runs: the OS's registration
/// writes it, then `--`, then the link, so the link stays one positional
/// argument whatever it holds (design `invite` §4.5, L-3).
pub const LINK_ARGUMENT: &str = "open-link";

/// This user's registration of `tornect:` links, under `HKEY_CURRENT_USER`
/// (design `invite` §4.5): written without elevation, and in
/// `HKEY_CLASSES_ROOT` it wins over an HKLM key of the same name.
pub const URL_SCHEME_KEY: &str = "Software\\Classes\\tornect";

/// The default value of [`URL_SCHEME_KEY`]: the `URL:` name Windows shows.
pub const URL_SCHEME_NAME: &str = "URL:Tornect link";

/// Why an install stopped when a registration of `tornect:` links appeared
/// between its check before the dialog and its write: nothing is written over
/// it, and a second install leaves it as it is.
pub const URL_KEY_APPEARED: &str = "Another program registered tornect:// links meanwhile \
     (HKEY_CURRENT_USER\\Software\\Classes\\tornect), so Tornect was not installed. Run tornect \
     install again: it leaves that registration as it is.";

/// Added to an undone install's message when the registration of `tornect:`
/// links it wrote was changed by another program before the undo: the undo
/// left it (L-6).
pub const URL_KEY_CHANGED_MEANWHILE: &str = " Another program changed \
     HKEY_CURRENT_USER\\Software\\Classes\\tornect meanwhile; Tornect left it as it is.";

/// What [`URL_SCHEME_KEY`] holds, as [`WindowsSystem::url_handler`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlKey {
    /// No such key.
    Absent,
    /// The key, with the default value of its `shell\open\command`.
    Command(String),
    /// The key, without a command that can be read: no
    /// `shell\open\command`, or a default value of another type or too long.
    Other,
}

/// What an install did about `tornect:` links (design `invite` §4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsLinks {
    /// This user's registration runs the installed copy: written by this
    /// install, or a leftover of an earlier one with the same command, kept.
    Registered,
    /// A registration that is not Tornect's is there: left as it is.
    OtherProgram,
}

/// The installed copy's internal step that writes the uninstall entry: its
/// only argument (§B.1.1, the CLI list).
pub const ENTRY_STEP_ARGUMENT: &str = "install-entry";

/// The installed copy's internal step that marks itself and its folder for
/// removal at the next restart: its only argument (§B.1.1, the CLI list).
pub const RESTART_STEP_ARGUMENT: &str = "remove-at-restart";

/// Why an image not named `tornect.exe` is not installed: the copy keeps
/// the file's name, and the installed program is `tornect.exe`.
pub const SOURCE_NOT_NAMED_TORNECT_EXE: &str = "Tornect can be installed only from a file named \
     tornect.exe. Rename this copy to tornect.exe and run it again.";

/// The installed copy is not the file that was held and hashed.
pub const SOURCE_SWAPPED: &str = "Something else replaced the Tornect file while it was being \
     copied, so nothing was installed.";

/// Why an install over an earlier install is refused (the operator's
/// words): an upgrade is `tornect uninstall`, then `tornect install`.
#[must_use]
pub fn already_installed(folder: &str) -> String {
    format!("Tornect is already installed in {folder}. Run tornect uninstall first.")
}

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
/// (UAC), each only through its own program ([`elevated_command`]).
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
    /// Have the installed copy, which an uninstall runs from, delete
    /// anything else in its folder and mark itself and then the folder for
    /// removal at the next restart.
    RemoveAtRestart {
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
    /// runs: only the step's own program, [`elevated_command`]'s, may be).
    fn elevated_program(&self, step: &Elevated) -> String;
    /// Run `step` through Windows' prompt: [`InstallError::Cancelled`] when
    /// the prompt was dismissed and nothing ran.
    fn run_elevated(&self, step: &Elevated) -> Result<(), InstallError>;
    /// Whether the uninstall entry `key` exists.
    fn uninstall_entry_exists(&self, key: &str) -> Result<bool, InstallError>;
    /// Whether a file is at `path`.
    fn file_exists(&self, path: &str) -> Result<bool, InstallError>;
    /// This program's own path: the final path of its image, resolved as
    /// [`Self::open_own_image`] resolves the image it holds.
    fn own_path(&self) -> Result<String, InstallError>;
    /// Every string of Windows' list of renames and deletes at the next
    /// restart (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`,
    /// value `PendingFileRenameOperations`), as stored: pairs of a source and
    /// a destination, a delete with an empty destination, the paths with the
    /// `\??\` prefix. An empty list when the value does not exist; an error
    /// when it cannot be read. Only read, never written.
    fn pending_removals(&self) -> Result<Vec<String>, InstallError>;
    /// Write this user's Start-menu entry `link`, which starts `target`.
    fn write_shortcut(&self, link: &str, target: &str) -> Result<(), InstallError>;
    /// Remove this user's Start-menu entry `link`.
    fn remove_shortcut(&self, link: &str) -> Result<(), InstallError>;
    /// This user's registration of `tornect:` links,
    /// `HKEY_CURRENT_USER\`[`URL_SCHEME_KEY`]: absent, its command, or a key
    /// whose command cannot be read. Only read.
    fn url_handler(&self) -> Result<UrlKey, InstallError>;
    /// Write that registration, without elevation: the key with its default
    /// value [`URL_SCHEME_NAME`] and an empty `URL Protocol`, then
    /// `shell\open\command` with `command`. When the key is already there as
    /// it is created (it appeared since [`Self::url_handler`]), nothing is
    /// written and the error is [`URL_KEY_APPEARED`]; a key it created and
    /// could not finish is deleted again.
    fn write_url_handler(&self, command: &str) -> Result<(), InstallError>;
    /// Delete that registration, the key and everything under it; a key
    /// that is not there is no error.
    fn remove_url_handler(&self) -> Result<(), InstallError>;
}

/// This computer for the Program Files install: its known folders and the
/// calls that make the steps below ([`crate::win_install::RealWindows`]).
#[cfg(windows)]
pub fn windows_system() -> Result<Box<dyn WindowsSystem>, InstallError> {
    Ok(Box::new(crate::win_install::RealWindows::of_this_computer()))
}

/// The system folder's copy program.
const ROBOCOPY: &str = "robocopy.exe";

/// The system folder's registry program.
const REG: &str = "reg.exe";

/// The system folder's command interpreter.
const CMD: &str = "cmd.exe";

/// The program that runs `step` elevated and its parameters: the only
/// program [`WindowsSystem::elevated_program`] may name for it (decision
/// M1-65).
///
/// - The copy: the system folder's `robocopy.exe`, from the held image's
///   folder into `<Program Files>\Tornect`, the file `tornect.exe` only, with
///   no retry and no option that copies owners or ACLs, moves or mirrors
///   (robocopy keeps the file's name, so the source is named `tornect.exe`);
///   its data, attributes and times only (`/COPY:DATX`), never an alternate
///   data stream such as a download's mark, which every account could read
///   there.
/// - The entry's delete: the system folder's `reg.exe`, in the 64-bit view.
/// - The folder's removal: the system folder's `cmd.exe`, with `/d` (no
///   AutoRun command) and `/v:off` (no delayed expansion).
/// - The entry's write: the installed copy, `tornect.exe install-entry`,
///   which takes nothing else and computes the entry itself.
/// - The removal at the next restart: the installed copy,
///   `tornect.exe remove-at-restart`, which takes nothing else and marks
///   only itself and its own folder.
///
/// Every path is quoted, and none ends in `\` before its closing quote.
pub fn elevated_command(step: &Elevated, target: &WindowsTarget) -> (String, String) {
    let system = |name: &str| windows_join(&target.system_directory, name);
    match step {
        Elevated::Copy { from, to } => (
            system(ROBOCOPY),
            format!(
                "\"{}\" \"{}\" {WINDOWS_EXE} /R:0 /W:0 /COPY:DATX",
                quotable_folder(parent_of(from)),
                quotable_folder(parent_of(to)),
            ),
        ),
        Elevated::DeleteEntry { key } => (
            system(REG),
            format!("delete \"HKLM\\{UNINSTALL_ROOT}\\{key}\" /f /reg:64"),
        ),
        Elevated::RemoveFolder { folder } => (
            system(CMD),
            format!("/d /v:off /c rmdir /s /q \"{}\"", quotable_folder(folder)),
        ),
        Elevated::WriteEntry(_) => (target.exe.clone(), ENTRY_STEP_ARGUMENT.to_owned()),
        Elevated::RemoveAtRestart { .. } => (target.exe.clone(), RESTART_STEP_ARGUMENT.to_owned()),
    }
}

/// Whether `step`'s program ended as a success: robocopy only with 1 (the
/// file was copied; with 0 nothing was, and since the folder holds no other
/// file, 2 to 7 do not mean success either), every other one only with 0.
#[must_use]
pub fn step_succeeded(step: &Elevated, exit_code: u32) -> bool {
    match step {
        Elevated::Copy { .. } => exit_code == 1,
        _ => exit_code == 0,
    }
}

/// The folder `path` is in: what comes before its last `\` (or `/`).
fn parent_of(path: &str) -> &str {
    path.rfind(['\\', '/']).map_or("", |at| &path[..at])
}

/// `folder` as it goes between quotes: without a trailing `\`, which would
/// escape the closing quote, and a drive's root as `X:\.`, never `X:`
/// (that drive's current folder).
fn quotable_folder(folder: &str) -> String {
    let trimmed = folder.trim_end_matches(['\\', '/']);
    let bytes = trimmed.as_bytes();
    if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        format!("{trimmed}\\.")
    } else {
        trimmed.to_owned()
    }
}

/// Whether `a` and `b` are the same path as they are compared here: `/`
/// read as `\`, ASCII letters in either case; nothing else is resolved, so
/// another spelling of the same file is refused.
fn same_path(a: &str, b: &str) -> bool {
    a.replace('/', "\\")
        .eq_ignore_ascii_case(&b.replace('/', "\\"))
}

/// Refused unless the held image can be the copy's source: robocopy keeps
/// the file's name, so it must be `tornect.exe` (in any case), and its path
/// goes quoted into robocopy's parameters, so it holds no `%`, `"` or
/// control character.
fn source_ok(path: &str) -> Result<(), InstallError> {
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    if !name.eq_ignore_ascii_case(WINDOWS_EXE) {
        return Err(InstallError::Refused(
            SOURCE_NOT_NAMED_TORNECT_EXE.to_owned(),
        ));
    }
    if path.chars().any(|c| c.is_control() || c == '"' || c == '%') {
        return Err(InstallError::Refused(format!(
            "{path:?} holds a character Windows' copy cannot take (%, \" or a control \
             character), so Tornect was not installed from it."
        )));
    }
    Ok(())
}

/// `dir\name`.
fn windows_join(dir: &str, name: &str) -> String {
    format!("{}\\{name}", dir.trim_end_matches(['\\', '/']))
}

/// Refused unless `exe` can go quoted into a command Windows keeps (`what`
/// names it): a path absolute on a drive, holding no control character, `"`
/// (not a legal file-name character) or `%` (which Windows may read as a
/// variable).
fn command_path_ok(exe: &str, what: &str) -> Result<(), InstallError> {
    let bytes = exe.as_bytes();
    let on_a_drive =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    if !on_a_drive {
        return Err(InstallError::Unavailable(format!(
            "{exe:?} is not an absolute path on a drive, which {what} needs"
        )));
    }
    if let Some(c) = exe
        .chars()
        .find(|c| c.is_control() || *c == '"' || *c == '%')
    {
        return Err(InstallError::Unavailable(format!(
            "{exe:?} contains {c:?}, which {what} cannot hold in its command"
        )));
    }
    Ok(())
}

/// The uninstall entry's command (§B.1.1): the installed executable's
/// absolute path in quotes, then the fixed argument. Refused: a path that is
/// not absolute on a drive, or that holds a control character, `"` (not a
/// legal file-name character) or `%` (which Windows may read as a
/// variable).
pub fn uninstall_command(exe: &str) -> Result<String, InstallError> {
    command_path_ok(exe, "Windows' uninstall entry")?;
    Ok(format!("\"{exe}\" {UNINSTALL_ARGUMENT}"))
}

/// The command of this user's registration of `tornect:` links (design
/// `invite` §4.5): the installed executable's absolute path in quotes,
/// [`LINK_ARGUMENT`], `--`, then the link as Windows puts it in, `"%1"`.
/// Whatever a link holds, a `"` included, lands after `--`: positionals,
/// never an option or a subcommand (L-3). Refused as [`uninstall_command`]
/// refuses.
pub fn url_handler_command(exe: &str) -> Result<String, InstallError> {
    command_path_ok(exe, "Windows' registration of tornect:// links")?;
    Ok(format!("\"{exe}\" {LINK_ARGUMENT} -- \"%1\""))
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
    /// The command of this user's registration of `tornect:` links
    /// ([`url_handler_command`]).
    pub url_command: String,
}

impl WindowsTarget {
    /// The target on this computer; refused when the executable's path
    /// cannot be written into the uninstall entry's command (nor, then, into
    /// the link registration's).
    pub fn of(sys: &dyn WindowsSystem) -> Result<Self, InstallError> {
        let mut target = Self::entry_of(sys)?;
        target.system_directory = sys.system_directory()?;
        target.start_menu_entry = windows_join(&sys.start_menu_programs()?, START_MENU_ENTRY);
        target.url_command = url_handler_command(&target.exe)?;
        Ok(target)
    }

    /// The Program Files part of the target only, from `FOLDERID_ProgramFiles`
    /// alone: the folder, the executable and the uninstall entry, with no
    /// system folder, no Start-menu entry and no link registration (left
    /// empty: the account an elevated step runs as may not have this user's
    /// folders or registry). What the installed copy's own elevated steps
    /// use, and nothing else.
    pub fn entry_of(sys: &dyn WindowsSystem) -> Result<Self, InstallError> {
        let program_files = sys.program_files()?;
        let folder = windows_join(&program_files, WINDOWS_FOLDER);
        let exe = windows_join(&folder, WINDOWS_EXE);
        let entry = UninstallEntry {
            key: UNINSTALL_KEY.to_owned(),
            display_name: ENTRY_NAME.to_owned(),
            display_version: env!("CARGO_PKG_VERSION").to_owned(),
            uninstall_string: uninstall_command(&exe)?,
        };
        Ok(Self {
            program_files,
            system_directory: String::new(),
            folder,
            exe,
            start_menu_entry: String::new(),
            entry,
            url_command: String::new(),
        })
    }

    /// Refused unless `step` would run elevated through its own program,
    /// [`elevated_command`]'s, and no other (decision M1-65: an executable
    /// another program of this user can replace is never elevated, nor a
    /// system program a step does not need, such as PowerShell).
    fn elevation_ok(&self, sys: &dyn WindowsSystem, step: &Elevated) -> Result<(), InstallError> {
        let program = sys.elevated_program(step);
        let (own, _) = elevated_command(step, self);
        if same_path(&program, &own) {
            return Ok(());
        }
        Err(InstallError::Unavailable(format!(
            "Tornect runs nothing as administrator from {program}: this step runs only {own}, \
             which other accounts cannot change."
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

/// Refused unless this program, `own` (the final path of its image), is the
/// installed copy `target.exe` as paths compare, neither that copy nor its
/// folder is a reparse point, and the ACL check passes for both and every
/// folder up to Program Files: the checks the installed copy makes before it
/// changes anything as administrator.
fn own_copy_ok(
    sys: &dyn WindowsSystem,
    target: &WindowsTarget,
    own: &str,
) -> Result<(), InstallError> {
    if !same_path(own, &target.exe) {
        return Err(InstallError::Refused(format!(
            "{own} is not the installed copy {}, so it changes nothing as administrator",
            target.exe
        )));
    }
    for path in [&target.folder, &target.exe] {
        if sys.is_reparse_point(path)? {
            return Err(InstallError::Refused(format!(
                "{path} is a link to another place, so the installed copy changes nothing"
            )));
        }
    }
    target.admin_only(sys, true).map_err(|why| {
        InstallError::Refused(format!(
            "the installed copy could be changed by accounts other than administrators \
             ({why}), so it changes nothing"
        ))
    })
}

/// `tornect install-entry` (§B.1.1): the installed copy's own elevated
/// step, the second prompt of `tornect install`. Refused unless this
/// program, `own`, is the installed copy from the known folder, neither that
/// copy nor its folder is a reparse point, and the ACL check passes; then
/// `write` writes the uninstall entry of [`WindowsTarget::entry_of`],
/// computed here, and nothing else. Nothing comes from the command line, and
/// this user's folders are never asked.
pub fn write_own_entry(
    sys: &dyn WindowsSystem,
    own: &str,
    write: &dyn Fn(&UninstallEntry) -> Result<(), InstallError>,
) -> Result<(), InstallError> {
    let target = WindowsTarget::entry_of(sys)?;
    own_copy_ok(sys, &target, own)?;
    write(&target.entry)
}

/// `tornect remove-at-restart` (§B.1.1): the installed copy's own elevated
/// step, the second prompt of an uninstall run from it. Refused unless this
/// program, `own`, is the installed copy from the known folder, neither that
/// copy nor its folder is a reparse point, and the ACL check passes; then
/// every entry of its folder other than `tornect.exe` goes at once
/// (`delete`: a file, a folder with what it holds, or a link as a link,
/// never followed), and only then the copy and then its folder are marked
/// for removal at the next restart (`mark`), in that order, since Windows
/// removes a folder at the restart only when it is empty by then. A refusal
/// or a failed delete marks nothing. Nothing comes from the command line.
pub fn mark_own_folder_for_restart(
    sys: &dyn WindowsSystem,
    own: &str,
    delete: &dyn Fn(&str) -> Result<(), InstallError>,
    mark: &dyn Fn(&str) -> Result<(), InstallError>,
) -> Result<(), InstallError> {
    let target = WindowsTarget::entry_of(sys)?;
    own_copy_ok(sys, &target, own)?;
    let entries = sys
        .folder_entries(&target.folder)?
        .ok_or_else(|| InstallError::Failed(format!("{} is not there", target.folder)))?;
    for name in entries
        .iter()
        .filter(|name| !name.eq_ignore_ascii_case(WINDOWS_EXE))
    {
        delete(&windows_join(&target.folder, name))?;
    }
    mark(&target.exe)?;
    mark(&target.folder)
}

/// Whether this program is the installed copy,
/// `<Program Files>\Tornect\tornect.exe` from the known folder, as paths
/// compare: an uninstall run from it (as Apps and features runs it) has that
/// copy mark itself and its folder for removal at the next restart instead
/// of deleting the folder it runs from.
pub fn runs_from_install(sys: &dyn WindowsSystem) -> Result<bool, InstallError> {
    let target = WindowsTarget::entry_of(sys)?;
    Ok(same_path(&sys.own_path()?, &target.exe))
}

/// What a finished install in Program Files holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The install folder.
    pub folder: String,
    /// The installed executable.
    pub exe: String,
    /// What `tornect:` links open here.
    pub links: WindowsLinks,
}

/// What an install did so far, undone in reverse on a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Done {
    /// The copy is in the install folder (or part of it may be).
    Copied,
    /// The Start-menu entry is written.
    StartMenuEntry,
    /// The link registration is written by this install (a leftover it found
    /// is never here, so never undone).
    UrlHandler,
}

/// Undo `done`, newest first: the link registration this install wrote, the
/// Start-menu entry, then the copy (an elevated step, run only after a
/// reparse check of its own: the folder and the copy in it must not be
/// reparse points, or the delete would act on another place). The
/// registration is read again first, since the prompt before the undo may
/// have stayed open for long: it is removed only while its command is still
/// the installed copy's (L-6), and one another program put in its place
/// meanwhile is left and named in the message. What could not be undone is
/// added to `error`'s message, after its reason; when the copy itself
/// stayed, the message says that Tornect was not installed and that the
/// folder may still hold a copy that nothing points at.
/// A copy whose folder failed the ACL check never comes here: it is not
/// deleted as administrator at all.
fn undo(
    sys: &dyn WindowsSystem,
    target: &WindowsTarget,
    done: &[Done],
    error: InstallError,
) -> InstallError {
    let mut failed = Vec::new();
    let mut copy_left = false;
    let mut url_left = false;
    for step in done.iter().rev() {
        let undone = match step {
            Done::UrlHandler => match sys.url_handler() {
                Ok(UrlKey::Command(command)) if command == target.url_command => {
                    sys.remove_url_handler()
                }
                Ok(UrlKey::Absent) => Ok(()),
                Ok(UrlKey::Command(_) | UrlKey::Other) => {
                    url_left = true;
                    Ok(())
                }
                Err(e) => Err(e),
            },
            Done::StartMenuEntry => sys.remove_shortcut(&target.start_menu_entry),
            Done::Copied => not_a_link(sys, target).and_then(|()| {
                sys.run_elevated(&Elevated::RemoveFolder {
                    folder: target.folder.clone(),
                })
            }),
        };
        if let Err(e) = undone {
            copy_left |= *step == Done::Copied;
            failed.push(match step {
                Done::UrlHandler => format!("removing HKEY_CURRENT_USER\\{URL_SCHEME_KEY}: {e}"),
                Done::StartMenuEntry => format!("removing {}: {e}", target.start_menu_entry),
                Done::Copied => format!("removing {}: {e}", target.folder),
            });
        }
    }
    if failed.is_empty() && !url_left {
        return error;
    }
    let details = failed.join("; ");
    let mut tail = if failed.is_empty() {
        String::new()
    } else if copy_left {
        format!(
            " Tornect was not installed, and undoing it did not finish ({details}): {} may still \
             hold a copy, and nothing points at it.",
            target.folder
        )
    } else {
        format!(" Undoing it did not finish ({details}).")
    };
    if url_left {
        tail.push_str(URL_KEY_CHANGED_MEANWHILE);
    }
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
/// Then, folder or no folder: refused while Windows is to remove the folder
/// at the next restart, or cannot say ([`no_removal_pending`]), and over an
/// earlier install ([`no_earlier_install`]). Run before the dialog and again
/// right after it.
fn existing_folder_ok(sys: &dyn WindowsSystem, target: &WindowsTarget) -> Result<(), InstallError> {
    let folder = &target.folder;
    let Some(entries) = sys.folder_entries(folder)? else {
        // Either can be left without the folder: a removal at the next
        // restart, and an entry that would point at the new copy.
        no_removal_pending(sys, target)?;
        return no_earlier_install(sys, target);
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
    })?;
    no_removal_pending(sys, target)?;
    no_earlier_install(sys, target)
}

/// Refused while Windows' list of renames and deletes at the next restart
/// names the install folder or a path under it ([`names_folder`]), since a
/// copy put there now would be deleted then; refused too while that list
/// cannot be read, since such a removal cannot be ruled out. Only the
/// value's own absence (an empty list) lets the install go on.
fn no_removal_pending(sys: &dyn WindowsSystem, target: &WindowsTarget) -> Result<(), InstallError> {
    let folder = &target.folder;
    let pending = sys.pending_removals().map_err(|why| {
        InstallError::Refused(format!(
            "Tornect cannot read whether Windows is to remove {folder} at the next restart \
             ({why}), so it was not installed: a copy put there now could be deleted then."
        ))
    })?;
    if pending.iter().any(|entry| names_folder(entry, folder)) {
        return Err(InstallError::Refused(format!(
            "Windows is still to remove {folder} at the next restart, so Tornect was not \
             installed: a copy put there now would be deleted then. Restart the computer, then \
             run tornect install again."
        )));
    }
    Ok(())
}

/// Whether `entry`, one string of the list of renames and deletes at the
/// next restart, names `folder` or a path under it: with a leading `!` and
/// then a leading `\??\` taken off, it is `folder` itself or `folder`
/// followed by `\`, ASCII letters in either case. An empty string (a
/// delete's destination) names nothing; an 8.3 short name is not resolved
/// (Tornect's own marks use the long path).
fn names_folder(entry: &str, folder: &str) -> bool {
    let path = entry.strip_prefix('!').unwrap_or(entry);
    let path = path.strip_prefix(r"\??\").unwrap_or(path);
    !path.is_empty()
        && path
            .get(..folder.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(folder))
        && path[folder.len()..]
            .chars()
            .next()
            .is_none_or(|c| c == '\\')
}

/// Refused when an earlier install is there: its program
/// `<Program Files>\Tornect\tornect.exe`, its uninstall entry or this user's
/// Start-menu entry. Nothing is replaced in place (the operator's ruling):
/// an upgrade is `tornect uninstall`, then `tornect install`.
fn no_earlier_install(sys: &dyn WindowsSystem, target: &WindowsTarget) -> Result<(), InstallError> {
    if sys.file_exists(&target.exe)?
        || sys.uninstall_entry_exists(&target.entry.key)?
        || sys.file_exists(&target.start_menu_entry)?
    {
        return Err(InstallError::Refused(already_installed(&target.folder)));
    }
    Ok(())
}

/// `tornect install` on Windows (§B.1.1), step by step:
///
/// 1. this program's image, held open (share mode read only) and hashed from
///    that handle, before anything else and until the end; refused when its
///    file is not named `tornect.exe` or its path holds `%`, `"` or a
///    control character (the copy keeps the name and takes the path quoted);
/// 2. the target from the known folders; refused when its path cannot be
///    quoted into the uninstall command, when `<Program Files>\Tornect`
///    exists and fails `existing_folder_ok` (anything but `tornect.exe` in
///    it, a reparse point, or an ACL that lets another account change it),
///    while Windows is to remove that folder at the next restart (or cannot
///    say), over an earlier install (its program, its uninstall entry or
///    this user's Start-menu entry, folder or no folder), or when a step
///    would run elevated through any program but its own
///    ([`elevated_command`]); then this user's registration of `tornect:`
///    links read ([`WindowsSystem::url_handler`], design `invite` §4.5):
///    only an absent key is written below; one whose command is this
///    install's own ([`url_handler_command`]) is a leftover of it, kept and
///    never undone; any other is left as it is
///    ([`WindowsLinks::OtherProgram`]), and the install goes on;
/// 3. `authorize`, the mutation guard's operation (re-authentication, no
///    remote session for 60 s, logged): nothing before it changes anything;
///    then the folder checked again, as the dialog may have stayed open for
///    long;
/// 4. the copy (elevated);
/// 5. the folder and the copy checked for reparse points, then the copy
///    hashed and compared with the held image, then the ACL check, all
///    before anything points at the copy;
/// 6. this user's Start-menu entry, then (6b) the link registration, where
///    step 2 found none (no elevation; a key that appeared meanwhile is never
///    written over: [`URL_KEY_APPEARED`]);
/// 7. the uninstall entry (elevated): a prompt cancelled there undoes 6b
///    and 6 too.
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
    source_ok(source.path())?;
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
    let url_key = sys.url_handler()?;
    let links = match &url_key {
        UrlKey::Absent => WindowsLinks::Registered,
        UrlKey::Command(command) if *command == target.url_command => WindowsLinks::Registered,
        UrlKey::Command(_) | UrlKey::Other => WindowsLinks::OtherProgram,
    };
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
    // Before the elevated entry, so that a prompt cancelled there undoes it.
    if url_key == UrlKey::Absent {
        if let Err(e) = sys.write_url_handler(&target.url_command) {
            return Err(undo(sys, &target, &done, e));
        }
        done.push(Done::UrlHandler);
    }
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
        links,
    })
}

/// What an uninstall from Program Files removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WindowsRemoval {
    /// The uninstall entry.
    pub uninstall_entry: bool,
    /// This user's Start-menu entry.
    pub start_menu_entry: bool,
    /// This user's registration of `tornect:` links, whose command ran the
    /// installed copy.
    pub url_handler: bool,
    /// The install folder: removed, or, for an uninstall run from the
    /// installed copy, marked by that copy for removal at the next restart.
    pub folder: bool,
    /// A registration of `tornect:` links that is not Tornect's (another
    /// command, or none that can be read) is there: left as it is.
    pub url_handler_left: bool,
}

impl WindowsRemoval {
    /// Whether anything was removed (a registration left alone is not).
    fn removed_anything(&self) -> bool {
        self.uninstall_entry || self.start_menu_entry || self.url_handler || self.folder
    }
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
/// elevated step; then the uninstall entry (elevated), this user's
/// Start-menu entry, this user's registration of `tornect:` links and the
/// folder (elevated), each only where it exists. The registration is
/// removed only while its command is the installed copy's
/// ([`url_handler_command`]), read before `authorize` and again right before
/// the removal (design `invite` L-6); any other is left as it is and
/// reported ([`WindowsRemoval::url_handler_left`]).
/// Run from the installed copy ([`runs_from_install`]), the folder's step is
/// that copy's own `remove-at-restart`, waited for like every other: it
/// marks the copy and the folder for removal at the next restart, so no
/// elevated program outlives the uninstall; from any other copy the folder
/// is deleted at once. Nothing there: nothing asked.
pub fn uninstall_from_program_files(
    sys: &dyn WindowsSystem,
    authorize: &mut dyn FnMut() -> Result<(), InstallError>,
) -> Result<WindowsRemoval, InstallError> {
    let target = WindowsTarget::of(sys)?;
    let folder = removable_folder(sys, &target)?;
    let entry = sys.uninstall_entry_exists(&target.entry.key)?;
    let link = sys.file_exists(&target.start_menu_entry)?;
    let ours = UrlKey::Command(target.url_command.clone());
    let url_key = sys.url_handler()?;
    let url_ours = url_key == ours;
    let mut removed = WindowsRemoval {
        url_handler_left: !url_ours && url_key != UrlKey::Absent,
        ..WindowsRemoval::default()
    };
    if !(folder || entry || link || url_ours) {
        return Ok(removed);
    }
    let delete_entry = Elevated::DeleteEntry {
        key: target.entry.key.clone(),
    };
    // The folder an uninstall runs from cannot be deleted while it runs:
    // the installed copy marks it for the next restart instead.
    let remove_folder = if folder && runs_from_install(sys)? {
        Elevated::RemoveAtRestart {
            folder: target.folder.clone(),
        }
    } else {
        Elevated::RemoveFolder {
            folder: target.folder.clone(),
        }
    };
    for (step, needed) in [(&delete_entry, entry), (&remove_folder, folder)] {
        if needed {
            target.elevation_ok(sys, step)?;
        }
    }
    authorize()?;
    let cancelled = |removed: &WindowsRemoval| {
        InstallError::Cancelled(if !removed.removed_anything() {
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
    if url_ours {
        // The dialog may have stayed open for long: what is deleted is what
        // runs the installed copy now.
        match sys.url_handler()? {
            now if now == ours => {
                sys.remove_url_handler()?;
                removed.url_handler = true;
            }
            UrlKey::Absent => {}
            UrlKey::Command(_) | UrlKey::Other => removed.url_handler_left = true,
        }
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
pub use linux::{
    Association, FOLDER_OTHERS_CAN_CHANGE, LINK_ENTRY, LINK_MIME, LINUX_EXE, LinkHandler,
    LinuxInstall, MENU_ENTRY, MIMEAPPS, Removal,
};

/// The `mimeapps.list` edit of the Linux install: pure text.
#[cfg(target_os = "linux")]
mod mimeapps;

/// The per-user install on Linux.
#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::io::{ErrorKind, Write as _};
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use super::{ENTRY_NAME, InstallError, LINK_ARGUMENT, mimeapps};
    use crate::autostart::{
        AutostartError, PathFacts, desktop_exec, desktop_exec_bare, parse_status_ids,
        unix_exe_location_ok,
    };

    /// The installed executable's name in the bin folder.
    pub const LINUX_EXE: &str = "tornect";

    /// The menu entry's file name in the applications folder.
    pub const MENU_ENTRY: &str = "tornect.desktop";

    /// The link entry's file name in the applications folder: the handler of
    /// `tornect:` links, a desktop entry of its own (design `invite` §4.5),
    /// since a link runs `open-link -- <link>`, never the hosting window, and
    /// the entry never shows in menus (`NoDisplay=true`).
    pub const LINK_ENTRY: &str = "tornect-link.desktop";

    /// The MIME type a `tornect:` link has for the desktop: GIO looks a
    /// scheme's handler up as `x-scheme-handler/<scheme>`.
    pub const LINK_MIME: &str = "x-scheme-handler/tornect";

    /// The per-user list of the XDG MIME Applications spec, in the
    /// configuration folder: where `xdg-mime default` writes, and what GIO,
    /// KService and `xdg-mime` read first after a desktop's own list.
    pub const MIMEAPPS: &str = "mimeapps.list";

    /// The largest `mimeapps.list` the install edits.
    const MIMEAPPS_MAX: u64 = 256 * 1024;

    /// How many times the edit of `mimeapps.list` is made when another
    /// program keeps changing the file meanwhile.
    const MIMEAPPS_TRIES: usize = 3;

    /// How much of a `mimeapps.list` the uninstall reads to tell whether one
    /// it cannot edit still names the link entry.
    const MIMEAPPS_SCAN: u64 = 1024 * 1024;

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

    /// The per-user install: the executable in `bin_dir`, the menu entry
    /// and the link entry in `apps_dir`, the association of `tornect:` links
    /// in `config_dir`'s `mimeapps.list`.
    #[derive(Clone)]
    pub struct LinuxInstall {
        bin_dir: PathBuf,
        apps_dir: PathBuf,
        config_dir: PathBuf,
        /// The tests' file facts; elsewhere this process's, always.
        #[cfg(test)]
        facts: Option<Facts>,
    }

    impl std::fmt::Debug for LinuxInstall {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LinuxInstall")
                .field("bin_dir", &self.bin_dir)
                .field("apps_dir", &self.apps_dir)
                .field("config_dir", &self.config_dir)
                .finish_non_exhaustive()
        }
    }

    /// What `tornect install` did about `tornect:` links in this user's
    /// `mimeapps.list` (design `invite` §4.5). The install never fails over
    /// it: the program is installed and pasting an invitation always works.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum LinkHandler {
        /// The file names the link entry for `x-scheme-handler/tornect`, and
        /// as the default: links open Tornect.
        Registered,
        /// A `[Default Applications]` line names another program first for
        /// these links; Tornect left it as it is.
        OtherDefault,
        /// `[Removed Associations]` lists the link entry for these links: the
        /// user turned it off, so nothing was written.
        TurnedOff,
        /// The file was not changed, for this reason.
        NotChanged(String),
    }

    /// What [`LinuxInstall::uninstall`] did about `tornect:` links in this
    /// user's `mimeapps.list`. The uninstall never fails over it.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub enum Association {
        /// Nothing there named the link entry (or there is no such file).
        #[default]
        NotThere,
        /// The link entry was taken out of it.
        Removed,
        /// It still names the link entry: it was not changed, for this
        /// reason.
        Left(String),
    }

    /// What [`LinuxInstall::uninstall`] did.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub struct Removal {
        /// Removed, in this order.
        pub removed: Vec<PathBuf>,
        /// Found at an install's name but not a regular file (a link, a
        /// folder): not what `install` wrote, so left as it is.
        pub left: Vec<PathBuf>,
        /// The association of `tornect:` links in `mimeapps.list`.
        pub association: Association,
    }

    impl LinuxInstall {
        /// The install into `bin_dir` (the executable), `apps_dir` (the menu
        /// entry and the link entry) and `config_dir` (its `mimeapps.list`),
        /// all absolute.
        #[must_use]
        pub fn new(bin_dir: PathBuf, apps_dir: PathBuf, config_dir: PathBuf) -> Self {
            Self {
                bin_dir,
                apps_dir,
                config_dir,
                #[cfg(test)]
                facts: None,
            }
        }

        /// This user's install (§B.1.1): `$HOME/.local/bin`,
        /// `$HOME/.local/share/applications`, and the configuration folder:
        /// `$XDG_CONFIG_HOME` when it is absolute, else `$HOME/.config` (the
        /// XDG Base Directory spec).
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
            let config_dir = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(".config"));
            Ok(Self::new(
                home.join(".local").join("bin"),
                home.join(".local").join("share").join("applications"),
                config_dir,
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

        /// The link entry: the handler of `tornect:` links.
        #[must_use]
        pub fn link_entry(&self) -> PathBuf {
            self.apps_dir.join(LINK_ENTRY)
        }

        /// This user's `mimeapps.list`, where the install names the link
        /// entry for `tornect:` links.
        #[must_use]
        pub fn mimeapps(&self) -> PathBuf {
            self.config_dir.join(MIMEAPPS)
        }

        /// The menu entry's text: the keys `Type`, `Name` and `Exec` only,
        /// `Exec` opening the installed window, with `--home` when the
        /// install is for a custom home (absolute).
        pub fn menu_entry_text(&self, home: Option<&Path>) -> Result<String, InstallError> {
            let exec = desktop_exec(&self.exe(), &home_args(home)?)
                .map_err(|e| InstallError::Unavailable(e.to_string()))?;
            Ok(format!(
                "# Written by `tornect install`; `tornect uninstall` removes it.\n\
                 [Desktop Entry]\n\
                 Type=Application\n\
                 Name={ENTRY_NAME}\n\
                 Exec={exec}\n"
            ))
        }

        /// The link entry's text (design `invite` §4.5): `NoDisplay=true`,
        /// `MimeType=x-scheme-handler/tornect;`, and an `Exec` that runs the
        /// installed executable with `--home` as the menu entry does, then
        /// `open-link --` and the link as its one argument, `%u`, unquoted and
        /// last (the specification forbids a quoted field code). Each item is
        /// bare unless it needs quotes ([`desktop_exec_bare`]): generic
        /// `xdg-open` runs no program written in quotes
        /// (`docs/research/links.md` finding 1).
        pub fn link_entry_text(&self, home: Option<&Path>) -> Result<String, InstallError> {
            let mut args = home_args(home)?;
            args.push(OsString::from(LINK_ARGUMENT));
            args.push(OsString::from("--"));
            let exec = desktop_exec_bare(&self.exe(), &args)
                .map_err(|e| InstallError::Unavailable(e.to_string()))?;
            Ok(format!(
                "# Written by `tornect install`; `tornect uninstall` removes it.\n\
                 [Desktop Entry]\n\
                 Type=Application\n\
                 Name={ENTRY_NAME}\n\
                 NoDisplay=true\n\
                 MimeType={LINK_MIME};\n\
                 Exec={exec} %u\n"
            ))
        }

        /// Checks what [`Self::install`] would write, writing nothing: both
        /// folders are absolute, the `Exec` of the menu entry and of the link
        /// entry can be written, and the bin folder (while it does not exist,
        /// the nearest folder above it that does) passes the location rule.
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
            self.link_entry_text(home)?;
            self.location_ok(nearest_existing(&self.bin_dir))
        }

        /// Copy `source` (this program, read from the handle the command
        /// opened first) to [`Self::exe`], then write the menu entry, then the
        /// link entry, then name the link entry for `tornect:` links in
        /// [`Self::mimeapps`]. Refused before anything is written by
        /// [`Self::preflight`]'s checks; the bin folder is checked again once
        /// it exists. A menu entry that cannot be written removes the copy
        /// again, and a link entry that cannot be written removes the menu
        /// entry and the copy; a folder this call created and a failure left
        /// empty is removed too. The `mimeapps.list` step never fails the
        /// install: what it did is the answer (the rules of `edit_mimeapps`).
        pub fn install(
            &self,
            source: &mut dyn std::io::Read,
            home: Option<&Path>,
        ) -> Result<LinkHandler, InstallError> {
            self.preflight(home)?;
            let entry = self.menu_entry_text(home)?;
            let link_entry = self.link_entry_text(home)?;
            let mut created = create_dirs(&self.bin_dir, 0o755)?;
            let copied = self.location_ok(&self.bin_dir).and_then(|()| {
                write_new(
                    &self.bin_dir,
                    LINUX_EXE,
                    0o755,
                    &mut |f| std::io::copy(&mut *source, f).map(drop),
                    &|| true,
                )
                .map_err(InstallError::from)
            });
            if let Err(e) = copied {
                remove_empty(&created);
                return Err(e);
            }
            let written = create_dirs(&self.apps_dir, 0o755).and_then(|dirs| {
                created.extend(dirs);
                write_new(
                    &self.apps_dir,
                    MENU_ENTRY,
                    0o644,
                    &mut |f| f.write_all(entry.as_bytes()),
                    &|| true,
                )
                .map_err(InstallError::from)
            });
            if let Err(e) = written {
                let _ = std::fs::remove_file(self.exe());
                remove_empty(&created);
                return Err(e);
            }
            let linked = write_new(
                &self.apps_dir,
                LINK_ENTRY,
                0o644,
                &mut |f| f.write_all(link_entry.as_bytes()),
                &|| true,
            );
            if let Err(e) = linked {
                let _ = std::fs::remove_file(self.menu_entry());
                let _ = std::fs::remove_file(self.exe());
                remove_empty(&created);
                return Err(e.into());
            }
            Ok(
                match edit_mimeapps(&self.config_dir, &mimeapps::add, &|| {}) {
                    Ok((handler, _)) => handler,
                    Err(why) => LinkHandler::NotChanged(why),
                },
            )
        }

        /// Whether anything [`Self::install`] writes is at its name (an
        /// association left alone in `mimeapps.list` is not: GIO skips an
        /// entry that is not there).
        #[must_use]
        pub fn installed(&self) -> bool {
            [self.menu_entry(), self.link_entry(), self.exe()]
                .iter()
                .any(|p| std::fs::symlink_metadata(p).is_ok())
        }

        /// Take the link entry out of [`Self::mimeapps`] (never failing the
        /// uninstall: [`Association`]), then remove the menu entry, the link
        /// entry and the executable: regular files only, anything else at
        /// those names left and reported. Removing nothing changes nothing.
        pub fn uninstall(&self) -> Result<Removal, InstallError> {
            let mut done = Removal {
                association: self.dissociate(),
                ..Removal::default()
            };
            for path in [self.menu_entry(), self.link_entry(), self.exe()] {
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

        /// Take the link entry out of [`Self::mimeapps`]; a file that cannot
        /// be edited is reported only while it still names the link entry.
        fn dissociate(&self) -> Association {
            match edit_mimeapps(
                &self.config_dir,
                &|text| (mimeapps::remove(text), ()),
                &|| {},
            ) {
                Ok(((), true)) => Association::Removed,
                Ok(((), false)) => Association::NotThere,
                Err(why) if may_name_link_entry(&self.mimeapps()) => Association::Left(why),
                Err(_) => Association::NotThere,
            }
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

    /// `--home <home>` for an install for a custom home (absolute), else
    /// nothing.
    fn home_args(home: Option<&Path>) -> Result<Vec<OsString>, InstallError> {
        let Some(home) = home else {
            return Ok(Vec::new());
        };
        if !home.is_absolute() {
            return Err(InstallError::Unavailable(format!(
                "the home {} is not an absolute path",
                home.display()
            )));
        }
        Ok(vec![OsString::from("--home"), home.as_os_str().to_owned()])
    }

    /// `dir`, or the nearest folder above it that exists.
    fn nearest_existing(dir: &Path) -> &Path {
        dir.ancestors()
            .find(|p| std::fs::symlink_metadata(p).is_ok())
            .unwrap_or(dir)
    }

    /// Create `dir` and the folders above it that are missing, with `mode`
    /// before the umask (0755 for the program's folders, 0700 for a
    /// configuration folder, as the XDG Base Directory spec asks); the ones
    /// created, from the top.
    fn create_dirs(dir: &Path, mode: u32) -> Result<Vec<PathBuf>, InstallError> {
        let missing: Vec<&Path> = dir
            .ancestors()
            .take_while(|p| std::fs::symlink_metadata(p).is_err())
            .collect();
        let mut created = Vec::new();
        for path in missing.into_iter().rev() {
            if let Err(e) = std::fs::DirBuilder::new().mode(mode).create(path) {
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

    /// Why [`write_new`] put nothing in place.
    #[derive(Debug)]
    enum WriteError {
        /// `unchanged` said the file changed since it was read: nothing was
        /// replaced.
        Changed,
        /// The write failed.
        Failed(InstallError),
    }

    impl From<WriteError> for InstallError {
        fn from(e: WriteError) -> Self {
            match e {
                WriteError::Changed => {
                    Self::Failed("another program changed the file meanwhile".to_owned())
                }
                WriteError::Failed(e) => e,
            }
        }
    }

    /// Write `name` in `dir` with `mode`: into a new temporary file beside it
    /// (never one that exists, so never through a link), then renamed over
    /// the name, which replaces a link there rather than following it.
    /// `unchanged` is asked just before the rename; `false` removes the
    /// temporary file and replaces nothing ([`WriteError::Changed`]).
    fn write_new(
        dir: &Path,
        name: &str,
        mode: u32,
        fill: &mut dyn FnMut(&mut std::fs::File) -> std::io::Result<()>,
        unchanged: &dyn Fn() -> bool,
    ) -> Result<(), WriteError> {
        let target = dir.join(name);
        let tmp = dir.join(format!(".{name}.tmp"));
        let failed = |e: std::io::Error| {
            WriteError::Failed(InstallError::Failed(format!(
                "writing {}: {e}",
                target.display()
            )))
        };
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
        if !unchanged() {
            let _ = std::fs::remove_file(&tmp);
            return Err(WriteError::Changed);
        }
        std::fs::rename(&tmp, &target).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            failed(e)
        })
    }

    /// A `mimeapps.list` as read for an edit: its text and its permission
    /// bits; `None` when there is no such file.
    type Snapshot = Option<(String, u32)>;

    /// Read `path` for an edit. Refused, with the reason: a link (never
    /// written through or replaced: dotfile managers use them), anything but
    /// a regular file, more than 256 KiB, text that is not UTF-8, or a file
    /// replaced between its check and its opening.
    fn read_mimeapps(path: &Path) -> Result<Snapshot, String> {
        use std::io::Read as _;
        use std::os::unix::fs::MetadataExt as _;
        let unreadable = |e: std::io::Error| format!("it could not be read: {e}");
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(unreadable(e)),
        };
        if meta.file_type().is_symlink() {
            return Err(
                "it is a link to another file, which Tornect never writes through".to_owned(),
            );
        }
        if !meta.is_file() {
            return Err("it is not a regular file".to_owned());
        }
        let too_large = || "it is larger than 256 KiB".to_owned();
        if meta.len() > MIMEAPPS_MAX {
            return Err(too_large());
        }
        let file = std::fs::File::open(path).map_err(unreadable)?;
        let opened = file.metadata().map_err(unreadable)?;
        if (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
            return Err("another program replaced it while it was read".to_owned());
        }
        let mut bytes = Vec::new();
        file.take(MIMEAPPS_MAX + 1)
            .read_to_end(&mut bytes)
            .map_err(unreadable)?;
        if bytes.len() as u64 > MIMEAPPS_MAX {
            return Err(too_large());
        }
        let text = String::from_utf8(bytes).map_err(|_| "it is not UTF-8 text".to_owned())?;
        Ok(Some((text, meta.mode() & 0o777)))
    }

    /// Edit `config_dir`'s `mimeapps.list` with `edit` (design `invite`
    /// §4.5), which answers the new text (`None`: no change) and what to
    /// report. A missing file is created (mode 0644) and a missing
    /// configuration folder with it (mode 0700); an existing file keeps its
    /// mode, and one left empty is removed. The new text goes in with
    /// [`write_new`]: the file is read again just before the rename (after
    /// `meanwhile`, the tests' other program) and, when another program
    /// changed it, the edit starts over from the new text, at most three
    /// times. Refused (the reason, nothing changed): what [`read_mimeapps`]
    /// refuses, a failed write, or a file that kept changing. A writer that
    /// acts between the last read and the rename can still lose its change:
    /// nothing locks this file, GIO included.
    fn edit_mimeapps<T>(
        config_dir: &Path,
        edit: &dyn Fn(&str) -> (Option<String>, T),
        meanwhile: &dyn Fn(),
    ) -> Result<(T, bool), String> {
        if !config_dir.is_absolute() {
            return Err(format!("{} is not an absolute path", config_dir.display()));
        }
        let path = config_dir.join(MIMEAPPS);
        let mut created = Vec::new();
        let result = (|| {
            for _ in 0..MIMEAPPS_TRIES {
                let before = read_mimeapps(&path)?;
                let (new, answer) = edit(before.as_ref().map_or("", |(text, _)| text.as_str()));
                let Some(new) = new else {
                    return Ok((answer, false));
                };
                let unchanged = || {
                    meanwhile();
                    read_mimeapps(&path).is_ok_and(|now| now == before)
                };
                let done = if new.is_empty() {
                    if unchanged() {
                        std::fs::remove_file(&path).map_err(|e| {
                            WriteError::Failed(InstallError::Failed(format!(
                                "removing {}: {e}",
                                path.display()
                            )))
                        })
                    } else {
                        Err(WriteError::Changed)
                    }
                } else {
                    created.extend(create_dirs(config_dir, 0o700).map_err(|e| e.to_string())?);
                    let mode = before.as_ref().map_or(0o644, |(_, mode)| *mode);
                    write_new(
                        config_dir,
                        MIMEAPPS,
                        mode,
                        &mut |f| f.write_all(new.as_bytes()),
                        &unchanged,
                    )
                };
                match done {
                    Ok(()) => return Ok((answer, true)),
                    Err(WriteError::Changed) => {}
                    Err(WriteError::Failed(e)) => return Err(e.to_string()),
                }
            }
            Err("another program kept changing it".to_owned())
        })();
        if result.is_err() {
            remove_empty(&created);
        }
        result
    }

    /// Whether the file at `path`, read through a link if it is one, may
    /// still name the link entry: a regular file whose first MiB holds its
    /// name, or one that cannot be read or is larger. Anything else (no
    /// file, a folder, a link to nothing) does not.
    fn may_name_link_entry(path: &Path) -> bool {
        use std::io::Read as _;
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_file() => {}
            _ => return false,
        }
        let mut bytes = Vec::new();
        let read = std::fs::File::open(path)
            .and_then(|f| f.take(MIMEAPPS_SCAN + 1).read_to_end(&mut bytes));
        read.is_err()
            || bytes.len() as u64 > MIMEAPPS_SCAN
            || bytes
                .windows(LINK_ENTRY.len())
                .any(|w| w == LINK_ENTRY.as_bytes())
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
                    self.root.join("home/.config"),
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
            assert_eq!(
                install
                    .install(&mut std::io::Cursor::new(PROGRAM), None)
                    .unwrap(),
                LinkHandler::Registered
            );
            assert_eq!(
                tree.files(),
                set(&[
                    "home/.config/mimeapps.list",
                    "home/.local/bin/tornect",
                    "home/.local/share/applications/tornect-link.desktop",
                    "home/.local/share/applications/tornect.desktop"
                ])
            );
            assert_eq!(
                install.mimeapps(),
                tree.root.join("home/.config/mimeapps.list")
            );
            assert_eq!(
                std::fs::read_to_string(install.mimeapps()).unwrap(),
                BOTH_GROUPS
            );
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&install.mimeapps()), 0o644);
            assert_eq!(mode(&tree.root.join("home/.config")), 0o700);
            assert_eq!(std::fs::read(install.exe()).unwrap(), PROGRAM);
            let mode = std::fs::metadata(install.exe())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o755, "{mode:o}");
            for entry in [install.menu_entry(), install.link_entry()] {
                let mode = std::fs::metadata(&entry).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o644, "{}: {mode:o}", entry.display());
            }
            assert_eq!(
                std::fs::read_to_string(install.link_entry()).unwrap(),
                install.link_entry_text(None).unwrap()
            );
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
            let victims = [
                "victim-exe",
                "victim-entry",
                "victim-link",
                "victim-tmp",
                "victim-tmp2",
                "victim-tmp3",
            ];
            for victim in victims {
                std::fs::write(tree.root.join(victim), b"victim").unwrap();
            }
            symlink(tree.root.join("victim-exe"), bin.join("tornect")).unwrap();
            symlink(tree.root.join("victim-entry"), apps.join("tornect.desktop")).unwrap();
            symlink(
                tree.root.join("victim-link"),
                apps.join("tornect-link.desktop"),
            )
            .unwrap();
            symlink(tree.root.join("victim-tmp"), bin.join(".tornect.tmp")).unwrap();
            symlink(
                tree.root.join("victim-tmp2"),
                apps.join(".tornect.desktop.tmp"),
            )
            .unwrap();
            symlink(
                tree.root.join("victim-tmp3"),
                apps.join(".tornect-link.desktop.tmp"),
            )
            .unwrap();
            install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
                .unwrap();
            for victim in victims {
                assert_eq!(std::fs::read(tree.root.join(victim)).unwrap(), b"victim");
            }
            for path in [install.exe(), install.menu_entry(), install.link_entry()] {
                let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
                assert!(kind.is_file(), "{} is not a regular file", path.display());
            }
            assert_eq!(std::fs::read(install.exe()).unwrap(), PROGRAM);
            assert_eq!(
                std::fs::read_to_string(install.link_entry()).unwrap(),
                install.link_entry_text(None).unwrap()
            );
            assert!(!bin.join(".tornect.tmp").exists());
            assert!(!apps.join(".tornect-link.desktop.tmp").exists());
            std::fs::remove_file(install.exe()).unwrap();
            symlink(tree.root.join("victim-exe"), install.exe()).unwrap();
            let removal = install.uninstall().unwrap();
            assert_eq!(
                removal.removed,
                [install.menu_entry(), install.link_entry()]
            );
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
                tree.root.join("home/config"),
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
                tree.root.join("home/config2"),
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
            let relative = LinuxInstall::new(
                tree.root.join("home/bin3"),
                tree.root.join("a3"),
                tree.root.join("c3"),
            )
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

        /// The link entry (design `invite` §4.5) is exactly this text, with
        /// and without a custom home; its `Exec` items are bare
        /// (`docs/research/links.md` finding 1) and `%u` comes last,
        /// unquoted.
        #[test]
        fn the_link_entry_is_the_designed_text() {
            let install = LinuxInstall::new(
                PathBuf::from("/home/u/.local/bin"),
                PathBuf::from("/home/u/.local/share/applications"),
                PathBuf::from("/home/u/.config"),
            );
            assert_eq!(
                install.link_entry(),
                Path::new("/home/u/.local/share/applications/tornect-link.desktop")
            );
            let head = "# Written by `tornect install`; `tornect uninstall` removes it.\n\
                        [Desktop Entry]\n\
                        Type=Application\n\
                        Name=Tornect\n\
                        NoDisplay=true\n\
                        MimeType=x-scheme-handler/tornect;\n";
            assert_eq!(
                install.link_entry_text(None).unwrap(),
                format!("{head}Exec=/home/u/.local/bin/tornect open-link -- %u\n")
            );
            assert_eq!(
                install
                    .link_entry_text(Some(Path::new("/srv/tornect/h1")))
                    .unwrap(),
                format!(
                    "{head}Exec=/home/u/.local/bin/tornect --home /srv/tornect/h1 open-link -- %u\n"
                )
            );
            assert_eq!(LINK_ENTRY, "tornect-link.desktop");
            assert_eq!(LINK_MIME, "x-scheme-handler/tornect");
            assert_eq!(LINK_ARGUMENT, "open-link");
        }

        /// An item of the link entry's `Exec` that needs quotes gets them, as
        /// the menu entry's do (`%` as `%%`); `%u` stays unquoted and last.
        /// A control character in a path, or a relative home, refuses the
        /// install before anything is written, through the link entry too.
        #[test]
        fn the_link_entry_exec_quotes_only_what_needs_it() {
            let tree = Tree::new();
            let install = LinuxInstall::new(
                tree.root.join("home/50% off/bin"),
                tree.root.join("home/apps"),
                tree.root.join("home/config"),
            )
            .with_facts(UID, GID, owned);
            let home = tree.root.join("my home");
            install
                .install(&mut std::io::Cursor::new(PROGRAM), Some(&home))
                .unwrap();
            let entry = std::fs::read_to_string(install.link_entry()).unwrap();
            let exec = format!(
                "Exec=\"{}/home/50%% off/bin/tornect\" --home \"{}/my home\" open-link -- %u",
                tree.root.display(),
                tree.root.display()
            );
            assert!(entry.lines().any(|l| l == exec), "{entry}");
            assert_eq!(entry.lines().last(), Some(exec.as_str()));
            for (home, item) in [
                ("/srv/it's", "\"/srv/it's\""),
                ("/srv/$x", "\"/srv/\\\\$x\""),
                ("/srv/[a]", "\"/srv/[a]\""),
                ("/srv/~x", "\"/srv/~x\""),
                ("/srv/josé", "/srv/josé"),
            ] {
                let text = install.link_entry_text(Some(Path::new(home))).unwrap();
                let last = text.lines().last().unwrap();
                assert!(
                    last.ends_with(&format!(" --home {item} open-link -- %u")),
                    "{home:?}: {last}"
                );
            }
            let bad = LinuxInstall::new(
                tree.root.join("home/new\nline/bin"),
                tree.root.join("home/apps2"),
                tree.root.join("home/config2"),
            )
            .with_facts(UID, GID, owned);
            assert!(matches!(
                bad.link_entry_text(None),
                Err(InstallError::Unavailable(_))
            ));
            assert!(matches!(
                install.link_entry_text(Some(Path::new("relative/home"))),
                Err(InstallError::Unavailable(_))
            ));
            assert!(matches!(
                install.link_entry_text(Some(&tree.root.join("tab\there"))),
                Err(InstallError::Unavailable(_))
            ));
        }

        /// A link entry that cannot be written (here a folder stands at its
        /// name, so the rename fails) removes the menu entry and the copy
        /// written before it, and the folders the install created.
        #[test]
        fn a_failed_link_entry_removes_the_other_two() {
            let tree = Tree::new();
            let install = tree.install();
            std::fs::create_dir_all(install.link_entry()).unwrap();
            match install.install(&mut std::io::Cursor::new(PROGRAM), None) {
                Err(InstallError::Failed(why)) => {
                    assert!(why.contains("tornect-link.desktop"), "{why}");
                }
                other => panic!("installed without its link entry: {other:?}"),
            }
            assert!(tree.files().is_empty(), "{:?}", tree.files());
            assert!(!tree.root.join("home/.local/bin").exists());
            assert!(!install.exe().exists());
            assert!(!install.menu_entry().exists());
            assert!(install.link_entry().is_dir());
        }

        /// The link entry alone counts as an install, so `uninstall` removes
        /// it.
        #[test]
        fn the_link_entry_alone_is_an_install() {
            let tree = Tree::new();
            let install = tree.install();
            let apps = tree.root.join("home/.local/share/applications");
            std::fs::create_dir_all(&apps).unwrap();
            std::fs::write(install.link_entry(), b"x").unwrap();
            assert!(install.installed());
            let removal = install.uninstall().unwrap();
            assert_eq!(removal.removed, [install.link_entry()]);
            assert!(!install.installed());
        }

        /// Uninstalling removes the menu entry, the link entry and the
        /// executable it wrote, and nothing else in either folder.
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
            assert_eq!(
                removal.removed,
                [install.menu_entry(), install.link_entry(), install.exe()]
            );
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

        /// `mimeapps.list` after an install into an empty configuration
        /// folder.
        const BOTH_GROUPS: &str = "[Added Associations]\n\
                                   x-scheme-handler/tornect=tornect-link.desktop;\n\
                                   \n\
                                   [Default Applications]\n\
                                   x-scheme-handler/tornect=tornect-link.desktop;\n";

        /// The user's own `mimeapps.list`: CRLF, comments, other groups.
        const USERS_OWN: &str = "# mine\r\n\
                                 [Default Applications]\r\n\
                                 text/html=firefox.desktop;\r\n\
                                 \r\n\
                                 [Added Associations]\r\n\
                                 x-scheme-handler/tornect=other.desktop;\r\n";

        /// Uninstalling gives back the user's `mimeapps.list` byte for byte,
        /// and its mode; one the install created goes again, and the
        /// configuration folder stays.
        #[test]
        fn uninstall_gives_back_the_mimeapps_list() {
            let tree = Tree::new();
            let install = tree.install();
            let config = tree.root.join("home/.config");
            std::fs::create_dir_all(&config).unwrap();
            std::fs::write(install.mimeapps(), USERS_OWN).unwrap();
            std::fs::set_permissions(install.mimeapps(), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            assert_eq!(
                install
                    .install(&mut std::io::Cursor::new(PROGRAM), None)
                    .unwrap(),
                LinkHandler::Registered
            );
            assert_eq!(
                std::fs::read_to_string(install.mimeapps()).unwrap(),
                "# mine\r\n\
                 [Default Applications]\r\n\
                 text/html=firefox.desktop;\r\n\
                 x-scheme-handler/tornect=tornect-link.desktop;\r\n\
                 \r\n\
                 [Added Associations]\r\n\
                 x-scheme-handler/tornect=other.desktop;tornect-link.desktop;\r\n"
            );
            let mode = || {
                std::fs::metadata(install.mimeapps())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(), 0o600);
            let removal = install.uninstall().unwrap();
            assert_eq!(removal.association, Association::Removed);
            assert_eq!(
                std::fs::read_to_string(install.mimeapps()).unwrap(),
                USERS_OWN
            );
            assert_eq!(mode(), 0o600);
            assert!(!config.join(".mimeapps.list.tmp").exists());

            // Created by the install: removed by the uninstall.
            std::fs::remove_file(install.mimeapps()).unwrap();
            install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
                .unwrap();
            assert_eq!(
                std::fs::read_to_string(install.mimeapps()).unwrap(),
                BOTH_GROUPS
            );
            assert_eq!(
                install.uninstall().unwrap().association,
                Association::Removed
            );
            assert!(tree.files().is_empty(), "{:?}", tree.files());
            assert!(config.is_dir());
            // Nothing left to take out.
            assert_eq!(install.uninstall().unwrap(), Removal::default());
        }

        /// What the install says about links follows the user's file: another
        /// program's default is left (`OtherDefault`), a removal the user
        /// wrote writes nothing (`TurnedOff`); the program is installed in
        /// both cases.
        #[test]
        fn the_install_reports_what_links_do() {
            let tree = Tree::new();
            let install = tree.install();
            std::fs::create_dir_all(tree.root.join("home/.config")).unwrap();
            let other = "[Default Applications]\nx-scheme-handler/tornect=other.desktop;\n";
            std::fs::write(install.mimeapps(), other).unwrap();
            assert_eq!(
                install
                    .install(&mut std::io::Cursor::new(PROGRAM), None)
                    .unwrap(),
                LinkHandler::OtherDefault
            );
            assert_eq!(
                std::fs::read_to_string(install.mimeapps()).unwrap(),
                format!(
                    "{other}\n[Added Associations]\nx-scheme-handler/tornect=tornect-link.desktop;\n"
                )
            );
            install.uninstall().unwrap();
            assert_eq!(std::fs::read_to_string(install.mimeapps()).unwrap(), other);

            let off = "[Removed Associations]\nx-scheme-handler/tornect=tornect-link.desktop;\n";
            std::fs::write(install.mimeapps(), off).unwrap();
            assert_eq!(
                install
                    .install(&mut std::io::Cursor::new(PROGRAM), None)
                    .unwrap(),
                LinkHandler::TurnedOff
            );
            assert!(install.exe().is_file() && install.link_entry().is_file());
            assert_eq!(std::fs::read_to_string(install.mimeapps()).unwrap(), off);
            let removal = install.uninstall().unwrap();
            assert_eq!(removal.association, Association::NotThere);
            assert_eq!(std::fs::read_to_string(install.mimeapps()).unwrap(), off);
        }

        /// A `mimeapps.list` that is a link (a dotfile manager's) is never
        /// written through or replaced: the install says so and goes on, the
        /// link and its target stay as they were. The uninstall reports it
        /// only while the target names the link entry.
        #[test]
        fn a_linked_mimeapps_list_is_never_written() {
            let tree = Tree::new();
            let install = tree.install();
            let config = tree.root.join("home/.config");
            std::fs::create_dir_all(&config).unwrap();
            let target = tree.root.join("dotfiles-mimeapps.list");
            std::fs::write(&target, USERS_OWN).unwrap();
            symlink(&target, install.mimeapps()).unwrap();
            match install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
                .unwrap()
            {
                LinkHandler::NotChanged(why) => assert!(why.contains("link"), "{why}"),
                other => panic!("wrote through a link: {other:?}"),
            }
            let still_a_link = || {
                std::fs::symlink_metadata(install.mimeapps())
                    .unwrap()
                    .file_type()
                    .is_symlink()
            };
            assert!(still_a_link());
            assert_eq!(std::fs::read_to_string(&target).unwrap(), USERS_OWN);
            assert!(!config.join(".mimeapps.list.tmp").exists());
            assert!(install.exe().is_file() && install.link_entry().is_file());
            // The target names no link entry: nothing to report.
            assert_eq!(
                install.uninstall().unwrap().association,
                Association::NotThere
            );
            // The user added the line to the target by hand: reported.
            install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
                .unwrap();
            let by_hand = format!(
                "{USERS_OWN}[Default Applications]\r\nx-scheme-handler/tornect=tornect-link.desktop;\r\n"
            );
            std::fs::write(&target, &by_hand).unwrap();
            match install.uninstall().unwrap().association {
                Association::Left(why) => assert!(why.contains("link"), "{why}"),
                other => panic!("{other:?}"),
            }
            assert!(still_a_link());
            assert_eq!(std::fs::read_to_string(&target).unwrap(), by_hand);
        }

        /// A `mimeapps.list` that is not UTF-8, larger than 256 KiB, or not a
        /// regular file is not changed, and the install goes on.
        #[test]
        fn an_unreadable_mimeapps_list_is_not_changed() {
            let large = format!("# {}\n", "x".repeat(256 * 1024));
            let not_utf8: &[u8] = b"[Added Associations]\ntext/plain=\xff.desktop;\n";
            for (content, why) in [
                (Some(not_utf8.to_vec()), "not UTF-8"),
                (Some(large.into_bytes()), "larger than 256 KiB"),
                (None, "not a regular file"),
            ] {
                let tree = Tree::new();
                let install = tree.install();
                std::fs::create_dir_all(tree.root.join("home/.config")).unwrap();
                match &content {
                    Some(bytes) => std::fs::write(install.mimeapps(), bytes).unwrap(),
                    None => std::fs::create_dir(install.mimeapps()).unwrap(),
                }
                match install
                    .install(&mut std::io::Cursor::new(PROGRAM), None)
                    .unwrap()
                {
                    LinkHandler::NotChanged(got) => assert!(got.contains(why), "{got}"),
                    other => panic!("{why}: {other:?}"),
                }
                match &content {
                    Some(bytes) => assert_eq!(&std::fs::read(install.mimeapps()).unwrap(), bytes),
                    None => assert!(install.mimeapps().is_dir()),
                }
                assert!(install.exe().is_file(), "{why}");
                // None of them names the link entry: nothing reported.
                assert_eq!(
                    install.uninstall().unwrap().association,
                    Association::NotThere,
                    "{why}"
                );
            }
        }

        /// Another program that changes `mimeapps.list` between the read and
        /// the rename: the edit starts over from its text, so both changes
        /// are in the file; one that keeps changing it gets the file left
        /// with its own change only, after three tries.
        #[test]
        fn a_mimeapps_list_changed_meanwhile_is_edited_again() {
            use std::cell::Cell;
            let tmp = tempfile::tempdir().unwrap();
            let config = tmp.path().join("config");
            std::fs::create_dir(&config).unwrap();
            let path = config.join(MIMEAPPS);
            std::fs::write(&path, "[Default Applications]\ntext/html=a.desktop;\n").unwrap();
            let other = "[Added Associations]\ntext/plain=b.desktop;\n";
            let calls = Cell::new(0);
            let once = || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    let mut text = std::fs::read_to_string(&path).unwrap();
                    text.push_str(other);
                    std::fs::write(&path, text).unwrap();
                }
            };
            let (handler, written) = edit_mimeapps(&config, &mimeapps::add, &once).unwrap();
            assert_eq!((handler, written), (LinkHandler::Registered, true));
            assert_eq!(calls.get(), 2);
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                "[Default Applications]\n\
                 text/html=a.desktop;\n\
                 x-scheme-handler/tornect=tornect-link.desktop;\n\
                 [Added Associations]\n\
                 text/plain=b.desktop;\n\
                 x-scheme-handler/tornect=tornect-link.desktop;\n"
            );

            std::fs::write(&path, "k=v\n").unwrap();
            let always = || {
                let mut text = std::fs::read_to_string(&path).unwrap();
                text.push_str("# again\n");
                std::fs::write(&path, text).unwrap();
            };
            assert_eq!(
                edit_mimeapps(&config, &mimeapps::add, &always),
                Err("another program kept changing it".to_owned())
            );
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                "k=v\n# again\n# again\n# again\n"
            );
            assert!(!config.join(".mimeapps.list.tmp").exists());
        }

        /// A missing configuration folder (and the folders above it) is
        /// created owner-only, 0700, with the file 0644 in it; a relative
        /// configuration folder changes nothing.
        #[test]
        fn a_missing_config_folder_is_created_owner_only() {
            let tmp = tempfile::tempdir().unwrap();
            let config = tmp.path().join("xdg/config");
            let (handler, written) = edit_mimeapps(&config, &mimeapps::add, &|| {}).unwrap();
            assert_eq!((handler, written), (LinkHandler::Registered, true));
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&tmp.path().join("xdg")), 0o700);
            assert_eq!(mode(&config), 0o700);
            assert_eq!(mode(&config.join(MIMEAPPS)), 0o644);
            assert_eq!(
                std::fs::read_to_string(config.join(MIMEAPPS)).unwrap(),
                BOTH_GROUPS
            );
            // A removal never creates the folder.
            let other = tmp.path().join("nowhere/config");
            assert_eq!(
                edit_mimeapps(&other, &|t| (mimeapps::remove(t), ()), &|| {}),
                Ok(((), false))
            );
            assert!(!tmp.path().join("nowhere").exists());
            assert!(matches!(
                edit_mimeapps(Path::new("relative/config"), &mimeapps::add, &|| {}),
                Err(why) if why.contains("not an absolute path")
            ));
            assert!(!Path::new("relative").exists());
        }

        /// GIO (`/usr/bin/gio`, GLib) opens a `tornect:` link with the
        /// installed link entry, with the URI as the one argument after
        /// `open-link --`, and finds no handler once uninstalled; also with a
        /// custom home that needs quotes. Isolated `HOME` and `XDG_*`; the
        /// installed program is a shell script that records its arguments.
        #[test]
        #[ignore = "needs /usr/bin/gio"]
        fn gio_opens_a_link_with_the_installed_entry() {
            use std::process::Command;
            let tree = Tree::new();
            let home = tree.root.join("home");
            let runtime = tree.root.join("run");
            for dir in ["data", "conf", "run"] {
                std::fs::create_dir(tree.root.join(dir)).unwrap();
            }
            std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
            let out = tree.root.join("argv");
            let program = format!(
                "#!/bin/sh\nfor a in \"$@\"; do printf '[%s]' \"$a\"; done > '{0}.tmp'\nmv '{0}.tmp' '{0}'\n",
                out.display()
            );
            let gio = |args: &[&str]| {
                let output = Command::new("/usr/bin/gio")
                    .args(args)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("HOME", &home)
                    .env("XDG_DATA_HOME", home.join(".local/share"))
                    .env("XDG_CONFIG_HOME", home.join(".config"))
                    .env("XDG_DATA_DIRS", tree.root.join("data"))
                    .env("XDG_CONFIG_DIRS", tree.root.join("conf"))
                    .env("XDG_RUNTIME_DIR", &runtime)
                    .env("XDG_CURRENT_DESKTOP", "")
                    .env("DBUS_SESSION_BUS_ADDRESS", "disabled:")
                    .env("GIO_USE_VFS", "local")
                    .output()
                    .expect("/usr/bin/gio runs");
                (
                    output.status.success(),
                    String::from_utf8_lossy(&output.stdout).into_owned(),
                )
            };
            let id = tornect_core::keys::HostIdentity::from_seed(&[7; 32]).id();
            let link = tornect_core::invite::link(&id);
            let custom = tree.root.join("my home");
            for (custom_home, expected) in [
                (None, format!("[open-link][--][{link}]")),
                (
                    Some(custom.as_path()),
                    format!("[--home][{}][open-link][--][{link}]", custom.display()),
                ),
            ] {
                let install = tree.install();
                assert_eq!(
                    install
                        .install(&mut std::io::Cursor::new(program.clone()), custom_home)
                        .unwrap(),
                    LinkHandler::Registered
                );
                let (ok, mime) = gio(&["mime", LINK_MIME]);
                assert!(ok, "{mime}");
                assert!(
                    mime.lines().next().is_some_and(
                        |l| l.starts_with("Default application") && l.ends_with(LINK_ENTRY)
                    ),
                    "{mime}"
                );
                let _ = std::fs::remove_file(&out);
                let (ok, said) = gio(&["open", &link]);
                assert!(ok, "gio open failed: {said}");
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !out.exists() && std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                assert_eq!(std::fs::read_to_string(&out).unwrap(), expected);
                install.uninstall().unwrap();
                let (_, mime) = gio(&["mime", LINK_MIME]);
                assert!(mime.starts_with("No default applications"), "{mime}");
                assert!(!mime.contains(LINK_ENTRY), "{mime}");
            }
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
    const ALREADY_INSTALLED: &str =
        "Tornect is already installed in C:\\Program Files\\Tornect. Run tornect uninstall first.";
    const AWAITS_REMOVAL: &str = "Windows is still to remove C:\\Program Files\\Tornect at the \
         next restart, so Tornect was not installed: a copy put there now would be deleted then. \
         Restart the computer, then run tornect install again.";

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
        WriteUrl(String),
        RemoveUrl,
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
        /// Where the held image is.
        image_path: String,
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
        /// The program that would run a step elevated, by kind; otherwise
        /// the step's own (the system folder's robocopy, reg or cmd; the
        /// installed copy for the entry).
        runner: BTreeMap<&'static str, String>,
        /// Windows' list of removals at the next restart, or why it cannot
        /// be read.
        pending: RefCell<Result<Vec<String>, String>>,
        /// This user's Start-menu folder cannot be found.
        no_start_menu: bool,
        /// This program's own path.
        own: String,
        /// This user's registration of `tornect:` links.
        url: RefCell<UrlKey>,
        /// Writing the link registration fails.
        fail_url: bool,
        /// What another program puts in the link registration while the
        /// prompt of an elevated step (by kind) is open, once.
        url_during_prompt: RefCell<Option<(&'static str, UrlKey)>>,
    }

    fn kind(step: &Elevated) -> &'static str {
        match step {
            Elevated::Copy { .. } => "copy",
            Elevated::WriteEntry(_) => "write",
            Elevated::DeleteEntry { .. } => "delete",
            Elevated::RemoveFolder { .. } => "remove",
            Elevated::RemoveAtRestart { .. } => "restart",
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
                image_path: IMAGE.to_owned(),
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
                pending: RefCell::new(Ok(Vec::new())),
                no_start_menu: false,
                own: IMAGE.to_owned(),
                url: RefCell::new(UrlKey::Absent),
                fail_url: false,
                url_during_prompt: RefCell::new(None),
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

        /// The link registration's command for the installed copy.
        fn url_command(&self) -> String {
            format!("\"{}\" open-link -- \"%1\"", self.exe())
        }

        fn url(&self) -> UrlKey {
            self.url.borrow().clone()
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
            assert_ne!(self.url(), UrlKey::Command(self.url_command()));
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
            *self.url.borrow_mut() = UrlKey::Command(self.url_command());
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
            &self.fake.image_path
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
            if self.no_start_menu {
                return Err(InstallError::Unavailable("no Start menu here".to_owned()));
            }
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
                .unwrap_or_else(|| match step {
                    Elevated::Copy { .. } => system("robocopy.exe"),
                    Elevated::DeleteEntry { .. } => system("reg.exe"),
                    Elevated::RemoveFolder { .. } => system("cmd.exe"),
                    Elevated::WriteEntry(_) | Elevated::RemoveAtRestart { .. } => self.exe(),
                })
        }

        fn run_elevated(&self, step: &Elevated) -> Result<(), InstallError> {
            let during = self.url_during_prompt.borrow().clone();
            if let Some((at, now)) = during
                && at == kind(step)
            {
                *self.url_during_prompt.borrow_mut() = None;
                *self.url.borrow_mut() = now;
            }
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
                // Marked: the folder stays until the restart.
                Elevated::RemoveAtRestart { .. } => {}
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

        fn pending_removals(&self) -> Result<Vec<String>, InstallError> {
            self.pending.borrow().clone().map_err(InstallError::Failed)
        }

        fn own_path(&self) -> Result<String, InstallError> {
            Ok(self.own.clone())
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

        fn url_handler(&self) -> Result<UrlKey, InstallError> {
            Ok(self.url())
        }

        /// As `RegCreateKeyExW`'s disposition tells it: a key already there
        /// is not written.
        fn write_url_handler(&self, command: &str) -> Result<(), InstallError> {
            self.record(Ev::WriteUrl(command.to_owned()));
            if self.url() != UrlKey::Absent {
                return Err(InstallError::Refused(URL_KEY_APPEARED.to_owned()));
            }
            if self.fail_url {
                return Err(InstallError::Failed("the registry refused".to_owned()));
            }
            *self.url.borrow_mut() = UrlKey::Command(command.to_owned());
            Ok(())
        }

        fn remove_url_handler(&self) -> Result<(), InstallError> {
            self.record(Ev::RemoveUrl);
            *self.url.borrow_mut() = UrlKey::Absent;
            Ok(())
        }
    }

    /// The system folder's program `name`.
    fn system(name: &str) -> String {
        format!("{SYSTEM32}\\{name}")
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
                Ev::WriteUrl(command) => assert_eq!(
                    command,
                    "\"K:\\Known Apps\\Tornect\\tornect.exe\" open-link -- \"%1\""
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
                Ev::WriteShortcut(_)
                    | Ev::WriteUrl(_)
                    | Ev::Elevated(Elevated::WriteEntry(_))
                    | Ev::Security(_)
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
    /// and before any prompt.
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
        match install_in_program_files(&earlier, &mut allow(&earlier)) {
            Err(InstallError::Refused(why)) => assert_eq!(why, ALREADY_INSTALLED),
            other => panic!("installed over an earlier install: {other:?}"),
        }
        assert!(
            !earlier
                .events()
                .iter()
                .any(|e| matches!(e, Ev::Authorize | Ev::Elevated(_))),
            "{:?}",
            earlier.events()
        );
        assert_eq!(
            earlier.files.borrow().get(&key(&earlier.exe())),
            Some(&b"old".to_vec())
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
                Ev::RemoveUrl,
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
            assert!(
                url_handler_command(&format!("{bad}\\tornect.exe")).is_err(),
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

    /// When the undo of an install cannot remove the copy (here its prompt
    /// dismissed too, after the entry's prompt was), the error keeps the reason
    /// the install stopped as its first words, then says that Tornect was not
    /// installed, what did not finish, and that the folder may still hold a copy
    /// that nothing points at (§B.1.1).
    #[test]
    fn an_undo_that_left_the_copy_says_so_after_the_reason() {
        let fake = Fake::new();
        fake.cancel.borrow_mut().extend(["write", "remove"]);
        let folder = fake.folder();
        match install_in_program_files(&fake, &mut allow(&fake)) {
            Err(InstallError::Cancelled(why)) => assert_eq!(
                why,
                format!(
                    "{INSTALL_NEEDS_APPROVAL} Tornect was not installed, and undoing it did not \
                     finish (removing {folder}: the prompt was dismissed): {folder} may still \
                     hold a copy, and nothing points at it."
                )
            ),
            other => panic!("{other:?}"),
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
                url_handler: true,
                folder: true,
                url_handler_left: false,
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
                Ev::RemoveUrl,
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
        // Not the installed copy either: the entry's delete runs only
        // through the system folder's reg.
        let mut fake = Fake::new();
        fake.installed();
        let exe = fake.exe();
        fake.runner.insert("delete", exe.clone());
        match uninstall_from_program_files(&fake, &mut allow(&fake)) {
            Err(InstallError::Unavailable(why)) => assert!(why.contains(&exe), "{why}"),
            other => panic!("the installed copy deleted the entry: {other:?}"),
        }
        assert!(fake.elevated().is_empty(), "{:?}", fake.events());
        assert!(!fake.events().contains(&Ev::Authorize));
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
                    Ev::WriteShortcut(_) | Ev::WriteUrl(_) | Ev::Elevated(Elevated::WriteEntry(_))
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
                Ev::WriteShortcut(_) | Ev::WriteUrl(_) | Ev::Elevated(Elevated::WriteEntry(_))
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

    /// Each elevated step runs only through its own program (decision
    /// M1-65): the copy through the system folder's `robocopy.exe`, the
    /// entry's delete through its `reg.exe`, the folder's removal through
    /// its `cmd.exe`. Any other program is refused before the dialog, with
    /// nothing run elevated and a refusal that names it and the step's own:
    /// another program in Program Files, the installed copy, this copy in
    /// Downloads, PowerShell, another step's system program.
    #[test]
    fn each_elevated_step_runs_only_its_own_program() {
        let own = [
            ("copy", system("robocopy.exe")),
            ("delete", system("reg.exe")),
            ("remove", system("cmd.exe")),
        ];
        for (step, program) in &own {
            let mut runners = vec![
                format!("{PF}\\Other\\other.exe"),
                format!("{PF}\\Tornect\\tornect.exe"),
                IMAGE.to_owned(),
                system("WindowsPowerShell\\v1.0\\powershell.exe"),
            ];
            runners.extend(
                own.iter()
                    .filter(|(s, _)| s != step)
                    .map(|(_, p)| p.clone()),
            );
            for runner in runners {
                let mut fake = Fake::new();
                if *step != "copy" {
                    fake.installed();
                }
                fake.runner.insert(step, runner.clone());
                let done = if *step == "copy" {
                    install_in_program_files(&fake, &mut allow(&fake)).map(drop)
                } else {
                    uninstall_from_program_files(&fake, &mut allow(&fake)).map(drop)
                };
                match done {
                    Err(InstallError::Unavailable(why)) => {
                        assert!(why.contains(&runner), "{step} {runner}: {why}");
                        assert!(why.contains(program.as_str()), "{step} {runner}: {why}");
                    }
                    other => panic!("{step} through {runner}: {other:?}"),
                }
                assert!(
                    fake.elevated().is_empty(),
                    "{step} {runner}: {:?}",
                    fake.events()
                );
                assert!(!fake.events().contains(&Ev::Authorize), "{step} {runner}");
            }
        }
    }

    /// The uninstall entry is written only by the installed copy: a write
    /// through robocopy, reg, another program in Program Files or this copy
    /// in Downloads is refused before the dialog, and nothing is left.
    #[test]
    fn the_entry_is_written_only_by_the_installed_copy() {
        for runner in [
            system("robocopy.exe"),
            system("reg.exe"),
            format!("{PF}\\Other\\tornect.exe"),
            IMAGE.to_owned(),
        ] {
            let mut fake = Fake::new();
            fake.runner.insert("write", runner.clone());
            match install_in_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Unavailable(why)) => {
                    assert!(why.contains(&runner), "{runner}: {why}");
                    assert!(why.contains(&fake.exe()), "{runner}: {why}");
                }
                other => panic!("written through {runner}: {other:?}"),
            }
            assert!(fake.elevated().is_empty(), "{runner}: {:?}", fake.events());
            assert!(!fake.events().contains(&Ev::Authorize), "{runner}");
            fake.assert_nothing_installed();
        }
        let fake = Fake::new();
        install_in_program_files(&fake, &mut allow(&fake)).unwrap();
        assert!(fake.entries.borrow().contains_key(UNINSTALL_KEY));
    }

    /// The installed copy runs as administrator only after its ACL check
    /// passed in this run: a copy that fails it is refused, the copy is the
    /// only elevated step, and the entry is never written.
    #[test]
    fn the_installed_copy_runs_nothing_after_a_failed_acl_check() {
        for broken in ["exe", "folder", "owner"] {
            let mut fake = Fake::new();
            match broken {
                "exe" => {
                    fake.writable_by_users.insert(key(&fake.exe()));
                }
                "folder" => {
                    fake.writable_by_users.insert(key(&fake.folder()));
                }
                _ => {
                    fake.owned_by_users.insert(key(&fake.exe()));
                }
            }
            match install_in_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Refused(why)) => assert_eq!(why, COPY_NOT_ADMIN_ONLY, "{broken}"),
                other => panic!("{broken}: {other:?}"),
            }
            let elevated = fake.elevated();
            assert!(
                matches!(elevated.as_slice(), [Elevated::Copy { .. }]),
                "{broken}: {elevated:?}"
            );
        }
    }

    /// Every elevated step's program and parameters, built from the step
    /// and the known folders only: robocopy copies the held file's folder's
    /// `tornect.exe` into `<Program Files>\Tornect` with no retry and
    /// nothing that copies owners or ACLs, moves or mirrors; reg deletes
    /// the entry in the 64-bit view; cmd removes the folder with no AutoRun
    /// command and no delayed expansion; the installed copy writes the
    /// entry. No quoted path ends in `\` before its closing quote, and a
    /// source at a drive root is never that drive's current folder.
    #[test]
    fn each_elevated_step_has_its_fixed_program_and_arguments() {
        let fake = Fake::new();
        let target = WindowsTarget::of(&fake).unwrap();
        let copy = Elevated::Copy {
            from: IMAGE.to_owned(),
            to: target.exe.clone(),
        };
        let root = Elevated::Copy {
            from: "D:\\tornect.exe".to_owned(),
            to: target.exe.clone(),
        };
        let delete = Elevated::DeleteEntry {
            key: UNINSTALL_KEY.to_owned(),
        };
        let remove = Elevated::RemoveFolder {
            folder: target.folder.clone(),
        };
        let write = Elevated::WriteEntry(target.entry.clone());
        let restart = Elevated::RemoveAtRestart {
            folder: target.folder.clone(),
        };
        let built = [
            (
                &copy,
                "C:\\Windows\\System32\\robocopy.exe",
                "\"C:\\Users\\u\\Downloads\\tornect\" \"C:\\Program Files\\Tornect\" tornect.exe \
                 /R:0 /W:0 /COPY:DATX",
            ),
            (
                &root,
                "C:\\Windows\\System32\\robocopy.exe",
                "\"D:\\.\" \"C:\\Program Files\\Tornect\" tornect.exe /R:0 /W:0 /COPY:DATX",
            ),
            (
                &delete,
                "C:\\Windows\\System32\\reg.exe",
                "delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Tornect\" \
                 /f /reg:64",
            ),
            (
                &remove,
                "C:\\Windows\\System32\\cmd.exe",
                "/d /v:off /c rmdir /s /q \"C:\\Program Files\\Tornect\"",
            ),
            (
                &write,
                "C:\\Program Files\\Tornect\\tornect.exe",
                "install-entry",
            ),
            (
                &restart,
                "C:\\Program Files\\Tornect\\tornect.exe",
                "remove-at-restart",
            ),
        ];
        for (step, program, parameters) in built {
            let (got_program, got_parameters) = elevated_command(step, &target);
            assert_eq!(got_program, program, "{step:?}");
            assert_eq!(got_parameters, parameters, "{step:?}");
            assert!(!got_parameters.contains("\\\""), "{got_parameters}");
            let upper = got_parameters.to_uppercase();
            for flag in ["/SEC", "/COPYALL", "/MOV", "/MIR", "/PURGE"] {
                assert!(!upper.contains(flag), "{flag}: {got_parameters}");
            }
        }
    }

    /// Robocopy succeeds only with exit code 1 (the file was copied): 0
    /// copied nothing, 2 to 7 met other files (the folder holds none), 8 and
    /// above failed. Every other step's program succeeds only with 0.
    #[test]
    fn robocopy_succeeds_only_when_it_copied_the_file() {
        let target = WindowsTarget::of(&Fake::new()).unwrap();
        let copy = Elevated::Copy {
            from: IMAGE.to_owned(),
            to: target.exe.clone(),
        };
        assert!(step_succeeded(&copy, 1));
        for code in [0, 2, 3, 4, 5, 6, 7, 8, 16, u32::MAX] {
            assert!(!step_succeeded(&copy, code), "{code}");
        }
        for step in [
            Elevated::DeleteEntry {
                key: UNINSTALL_KEY.to_owned(),
            },
            Elevated::RemoveFolder {
                folder: target.folder.clone(),
            },
            Elevated::WriteEntry(target.entry.clone()),
        ] {
            assert!(step_succeeded(&step, 0), "{step:?}");
            for code in [1, 2, 5, 16, u32::MAX] {
                assert!(!step_succeeded(&step, code), "{step:?}: {code}");
            }
        }
    }

    /// Robocopy keeps the file's name, so the held image must be named
    /// `tornect.exe` (in any case), and its path goes quoted into robocopy's
    /// parameters, so it may hold no `%`, `"` or control character: anything
    /// else is refused right after the image is held, before anything is
    /// asked or run.
    #[test]
    fn a_source_not_named_tornect_exe_is_refused_before_anything_is_asked() {
        let only_held = |fake: &Fake, path: &str| {
            let events = fake.events();
            assert!(
                events
                    .iter()
                    .all(|e| matches!(e, Ev::OpenImage | Ev::ReadImage | Ev::CloseImage)),
                "{path}: {events:?}"
            );
            assert_eq!(events.last(), Some(&Ev::CloseImage), "{path}");
        };
        for path in [
            "C:\\Users\\u\\Downloads\\tornect-copy.exe",
            "C:\\Users\\u\\Downloads\\tornect.exe.exe",
            "C:\\Users\\u\\Downloads\\tornect",
            "C:\\Users\\u\\Downloads\\tornect.exe\\other.exe",
        ] {
            let mut fake = Fake::new();
            fake.image_path = path.to_owned();
            match install_in_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Refused(why)) => {
                    assert_eq!(why, SOURCE_NOT_NAMED_TORNECT_EXE, "{path}");
                }
                other => panic!("{path}: {other:?}"),
            }
            only_held(&fake, path);
        }
        for path in [
            "C:\\Users\\u\\100%\\tornect.exe",
            "C:\\Users\\u\\a\"b\\tornect.exe",
            "C:\\Users\\u\\a\u{1b}b\\tornect.exe",
        ] {
            let mut fake = Fake::new();
            fake.image_path = path.to_owned();
            match install_in_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Refused(why)) => assert_eq!(
                    why,
                    format!(
                        "{path:?} holds a character Windows' copy cannot take (%, \" or a \
                         control character), so Tornect was not installed from it."
                    ),
                    "{path}"
                ),
                other => panic!("{path:?}: {other:?}"),
            }
            only_held(&fake, path);
        }
        let mut fake = Fake::new();
        fake.image_path = "C:\\Users\\u\\Downloads\\TORNECT.EXE".to_owned();
        install_in_program_files(&fake, &mut allow(&fake)).unwrap();
    }

    /// One guard operation covers both prompts: the dialog comes once,
    /// before the copy's prompt and before the entry's.
    #[test]
    fn one_guard_operation_covers_both_prompts() {
        let fake = Fake::new();
        install_in_program_files(&fake, &mut allow(&fake)).unwrap();
        let events = fake.events();
        assert_eq!(
            events.iter().filter(|e| **e == Ev::Authorize).count(),
            1,
            "{events:?}"
        );
        let authorize = position(&events, |e| *e == Ev::Authorize);
        let copy = position(&events, |e| {
            matches!(e, Ev::Elevated(Elevated::Copy { .. }))
        });
        let write = position(&events, |e| {
            matches!(e, Ev::Elevated(Elevated::WriteEntry(_)))
        });
        assert!(authorize < copy && copy < write, "{events:?}");
        assert_eq!(fake.elevated().len(), 2, "{events:?}");
    }

    /// Nothing is asked and nothing runs: no dialog, no prompt, no entry.
    fn assert_nothing_asked(fake: &Fake, what: &str) {
        assert!(
            !fake
                .events()
                .iter()
                .any(|e| matches!(e, Ev::Authorize | Ev::Elevated(_) | Ev::WriteShortcut(_))),
            "{what}: {:?}",
            fake.events()
        );
    }

    /// An earlier install is refused before anything is asked, in the
    /// operator's words, and nothing of it is replaced: its program, its
    /// uninstall entry or this user's Start-menu entry, each alone; the
    /// entry and the Start-menu entry also with no folder left.
    #[test]
    fn an_earlier_install_is_refused_before_anything_is_asked() {
        for found in [
            "program",
            "entry",
            "start menu",
            "entry, no folder",
            "start menu, no folder",
        ] {
            let fake = Fake::new();
            if !found.ends_with("no folder") {
                fake.folders.borrow_mut().insert(key(&fake.folder()));
            }
            if found == "program" {
                fake.files
                    .borrow_mut()
                    .insert(key(&fake.exe()), b"old".to_vec());
            } else if found.starts_with("entry") {
                let entry = WindowsTarget::of(&fake).unwrap().entry;
                fake.entries
                    .borrow_mut()
                    .insert(UNINSTALL_KEY.to_owned(), entry);
            } else {
                fake.shortcuts
                    .borrow_mut()
                    .insert(key(&Fake::link()), fake.exe());
            }
            match install_in_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Refused(why)) => assert_eq!(why, ALREADY_INSTALLED, "{found}"),
                other => panic!("{found}: installed over it: {other:?}"),
            }
            assert_nothing_asked(&fake, found);
        }
    }

    /// While Windows' list of removals at the next restart names the install
    /// folder or a path under it (a delete, or a rename's destination), the
    /// install is refused with a text that says to restart, folder present
    /// or absent, before anything is asked; and after the dialog, before the
    /// copy, when the list came to name it while the dialog was open.
    #[test]
    fn an_install_is_refused_while_its_folder_awaits_removal_at_the_restart() {
        for list in [
            vec![
                "\\??\\C:\\Program Files\\Tornect\\tornect.exe".to_owned(),
                String::new(),
            ],
            vec!["\\??\\C:\\PROGRAM FILES\\TORNECT".to_owned()],
            vec![
                "\\??\\C:\\Temp\\a".to_owned(),
                "!\\??\\C:\\Program Files\\Tornect\\tornect.exe".to_owned(),
            ],
        ] {
            for folder in [true, false] {
                let fake = Fake::new();
                if folder {
                    fake.folders.borrow_mut().insert(key(&fake.folder()));
                }
                *fake.pending.borrow_mut() = Ok(list.clone());
                let what = format!("{list:?}, folder {folder}");
                match install_in_program_files(&fake, &mut allow(&fake)) {
                    Err(InstallError::Refused(why)) => assert_eq!(why, AWAITS_REMOVAL, "{what}"),
                    other => panic!("{what}: {other:?}"),
                }
                assert_nothing_asked(&fake, &what);
            }
        }
        let fake = Fake::new();
        let mut named_meanwhile = || {
            fake.record(Ev::Authorize);
            *fake.pending.borrow_mut() = Ok(vec![
                "\\??\\C:\\Program Files\\Tornect".to_owned(),
                String::new(),
            ]);
            Ok(())
        };
        match install_in_program_files(&fake, &mut named_meanwhile) {
            Err(InstallError::Refused(why)) => assert_eq!(why, AWAITS_REMOVAL),
            other => panic!("{other:?}"),
        }
        assert!(fake.events().contains(&Ev::Authorize));
        assert!(fake.elevated().is_empty(), "{:?}", fake.events());
    }

    /// A removal at the next restart of anything but the install folder or
    /// a path under it refuses nothing: a folder whose name only begins
    /// with `Tornect`, another folder named `Tornect`, a rename elsewhere.
    #[test]
    fn a_removal_pending_elsewhere_does_not_refuse_the_install() {
        let fake = Fake::new();
        *fake.pending.borrow_mut() = Ok(vec![
            "\\??\\C:\\Program Files\\Tornect2\\tornect.exe".to_owned(),
            String::new(),
            "\\??\\C:\\Program Files\\Other\\Tornect".to_owned(),
            String::new(),
            "\\??\\C:\\Temp\\a".to_owned(),
            "!\\??\\C:\\Temp\\b".to_owned(),
        ]);
        install_in_program_files(&fake, &mut allow(&fake)).unwrap();
        assert!(fake.events().contains(&Ev::Authorize));
        assert!(fake.entries.borrow().contains_key(UNINSTALL_KEY));
    }

    /// A list of removals at the next restart that cannot be read refuses
    /// the install, which could be deleted then: nothing is asked or run.
    #[test]
    fn an_unreadable_restart_list_refuses_the_install() {
        let fake = Fake::new();
        *fake.pending.borrow_mut() = Err("access denied".to_owned());
        match install_in_program_files(&fake, &mut allow(&fake)) {
            Err(InstallError::Refused(why)) => assert_eq!(
                why,
                "Tornect cannot read whether Windows is to remove C:\\Program Files\\Tornect at \
                 the next restart (access denied), so it was not installed: a copy put there now \
                 could be deleted then."
            ),
            other => panic!("{other:?}"),
        }
        assert_nothing_asked(&fake, "unreadable");
    }

    /// What the installed copy's entry step was given to write.
    type Written = RefCell<Vec<UninstallEntry>>;

    /// The entry step's writer: records the entry, writes nothing.
    fn record(written: &Written) -> impl Fn(&UninstallEntry) -> Result<(), InstallError> + '_ {
        move |entry| {
            written.borrow_mut().push(entry.clone());
            Ok(())
        }
    }

    /// The copy as the first prompt leaves it: the folder and `tornect.exe`.
    fn copied(fake: &Fake) {
        fake.folders.borrow_mut().insert(key(&fake.folder()));
        fake.files
            .borrow_mut()
            .insert(key(&fake.exe()), PROGRAM.to_vec());
    }

    /// The installed copy's entry step changes nothing unless it is the
    /// installed copy and passes its checks: run as this copy in Downloads
    /// or as another program in Program Files, with the ACL check failing,
    /// or with the folder or the copy a reparse point, nothing is written.
    #[test]
    fn the_entry_step_refuses_outside_program_files() {
        for broken in [
            "downloads",
            "another program",
            "acl",
            "folder link",
            "exe link",
        ] {
            let mut fake = Fake::new();
            copied(&fake);
            let own = match broken {
                "downloads" => IMAGE.to_owned(),
                "another program" => format!("{PF}\\Other\\tornect.exe"),
                _ => fake.exe(),
            };
            match broken {
                "acl" => {
                    fake.writable_by_users.insert(key(&fake.folder()));
                }
                "folder link" => {
                    fake.reparse.insert(key(&fake.folder()));
                }
                "exe link" => {
                    fake.reparse.insert(key(&fake.exe()));
                }
                _ => {}
            }
            let written = Written::default();
            let done = write_own_entry(&fake, &own, &record(&written));
            assert!(
                matches!(done, Err(InstallError::Refused(_))),
                "{broken}: {done:?}"
            );
            assert!(written.borrow().is_empty(), "{broken}");
            assert!(fake.elevated().is_empty(), "{broken}");
        }
    }

    /// The entry step writes exactly the entry computed from Program Files,
    /// whatever case its own path is in, and never asks for this user's
    /// Start menu, which the elevated account may not have.
    #[test]
    fn the_entry_step_writes_exactly_its_values() {
        let mut fake = Fake::new();
        fake.no_start_menu = true;
        copied(&fake);
        let written = Written::default();
        write_own_entry(&fake, &fake.exe().to_uppercase(), &record(&written)).unwrap();
        assert_eq!(
            *written.borrow(),
            [UninstallEntry {
                key: "Tornect".to_owned(),
                display_name: "Tornect".to_owned(),
                display_version: env!("CARGO_PKG_VERSION").to_owned(),
                uninstall_string: "\"C:\\Program Files\\Tornect\\tornect.exe\" uninstall"
                    .to_owned(),
            }]
        );
        assert!(fake.elevated().is_empty());
    }

    /// What the restart step was given to delete and to mark, in order.
    type Done = RefCell<Vec<String>>;

    /// An uninstall run from the installed copy (as Apps and features runs
    /// it) removes the entry (reg) and the Start-menu entry at once, checks
    /// the folder again and then has that copy mark itself and its folder
    /// for removal at the next restart: never the cmd removal of the folder
    /// it runs from. Through any program but the installed copy (cmd,
    /// PowerShell) that step is refused before the dialog.
    #[test]
    fn an_uninstall_run_from_the_installed_copy_marks_its_folder_for_the_restart() {
        let mut fake = Fake::new();
        fake.installed();
        fake.own = fake.exe();
        let removed = uninstall_from_program_files(&fake, &mut allow(&fake)).unwrap();
        assert_eq!(
            removed,
            WindowsRemoval {
                uninstall_entry: true,
                start_menu_entry: true,
                url_handler: true,
                folder: true,
                url_handler_left: false,
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
                Ev::RemoveUrl,
                Ev::Elevated(Elevated::RemoveAtRestart {
                    folder: fake.folder()
                }),
            ]
        );
        let shortcut = position(&events, |e| matches!(e, Ev::RemoveShortcut(_)));
        let step = position(&events, |e| {
            matches!(e, Ev::Elevated(Elevated::RemoveAtRestart { .. }))
        });
        assert!(
            events[shortcut..step]
                .iter()
                .any(|e| matches!(e, Ev::Security(_))),
            "the folder was not checked again: {events:?}"
        );
        for runner in [
            system("cmd.exe"),
            system("WindowsPowerShell\\v1.0\\powershell.exe"),
        ] {
            let mut fake = Fake::new();
            fake.installed();
            fake.own = fake.exe();
            fake.runner.insert("restart", runner.clone());
            match uninstall_from_program_files(&fake, &mut allow(&fake)) {
                Err(InstallError::Unavailable(why)) => {
                    assert!(why.contains(&runner), "{runner}: {why}");
                    assert!(why.contains(&fake.exe()), "{runner}: {why}");
                }
                other => panic!("{runner}: {other:?}"),
            }
            assert!(fake.elevated().is_empty(), "{runner}: {:?}", fake.events());
            assert!(!fake.events().contains(&Ev::Authorize), "{runner}");
        }
    }

    /// The installed copy's restart step changes nothing unless it is the
    /// installed copy and passes its checks: run as this copy in Downloads
    /// or as another program in Program Files, with the ACL check failing,
    /// or with the folder or the copy a reparse point, nothing is deleted
    /// and nothing marked.
    #[test]
    fn the_restart_step_refuses_outside_program_files() {
        for broken in [
            "downloads",
            "another program",
            "acl",
            "folder link",
            "exe link",
        ] {
            let mut fake = Fake::new();
            copied(&fake);
            fake.files
                .borrow_mut()
                .insert(key(&format!("{}\\left.log", fake.folder())), b"x".to_vec());
            let own = match broken {
                "downloads" => IMAGE.to_owned(),
                "another program" => format!("{PF}\\Other\\tornect.exe"),
                _ => fake.exe(),
            };
            match broken {
                "acl" => {
                    fake.writable_by_users.insert(key(&fake.exe()));
                }
                "folder link" => {
                    fake.reparse.insert(key(&fake.folder()));
                }
                "exe link" => {
                    fake.reparse.insert(key(&fake.exe()));
                }
                _ => {}
            }
            let done = Done::default();
            let deleted = |path: &str| {
                done.borrow_mut().push(format!("delete {path}"));
                Ok(())
            };
            let marked = |path: &str| {
                done.borrow_mut().push(format!("mark {path}"));
                Ok(())
            };
            let result = mark_own_folder_for_restart(&fake, &own, &deleted, &marked);
            assert!(
                matches!(result, Err(InstallError::Refused(_))),
                "{broken}: {result:?}"
            );
            assert!(done.borrow().is_empty(), "{broken}: {:?}", done.borrow());
        }
    }

    /// The restart step deletes every other entry of its folder first, then
    /// marks the copy and then the folder, in that order; a delete that
    /// fails marks nothing.
    #[test]
    fn the_restart_step_marks_the_copy_then_its_folder() {
        let fake = Fake::new();
        copied(&fake);
        fake.files
            .borrow_mut()
            .insert(key(&format!("{}\\left.log", fake.folder())), b"x".to_vec());
        let done = Done::default();
        let deleted = |path: &str| {
            done.borrow_mut().push(format!("delete {path}"));
            Ok(())
        };
        let marked = |path: &str| {
            done.borrow_mut().push(format!("mark {path}"));
            Ok(())
        };
        mark_own_folder_for_restart(&fake, &fake.exe(), &deleted, &marked).unwrap();
        assert_eq!(
            *done.borrow(),
            [
                format!("delete {}\\left.log", fake.folder()),
                format!("mark {}", fake.exe()),
                format!("mark {}", fake.folder()),
            ]
        );
        let done = Done::default();
        let in_use = |path: &str| Err(InstallError::Failed(format!("{path} is in use")));
        let marked = |path: &str| {
            done.borrow_mut().push(format!("mark {path}"));
            Ok(())
        };
        let result = mark_own_folder_for_restart(&fake, &fake.exe(), &in_use, &marked);
        assert!(matches!(result, Err(InstallError::Failed(_))), "{result:?}");
        assert!(done.borrow().is_empty(), "{:?}", done.borrow());
    }

    /// Another program's registration of `tornect:` links.
    fn theirs() -> UrlKey {
        UrlKey::Command("\"C:\\Program Files\\Other\\other.exe\" \"%1\"".to_owned())
    }

    /// Whether the link registration was written or removed.
    fn url_touched(fake: &Fake) -> bool {
        fake.events()
            .iter()
            .any(|e| matches!(e, Ev::WriteUrl(_) | Ev::RemoveUrl))
    }

    /// Design `invite` §4.5: the link registration's command is the
    /// installed copy's path in quotes, `open-link`, `--`, then `"%1"`; the
    /// target carries it, and the installed copy's own elevated steps, which
    /// never touch this user's registry, leave it empty. A path the command
    /// cannot hold is refused as the uninstall entry's is.
    #[test]
    fn the_link_command_is_quoted_with_its_fixed_arguments() {
        let command = "\"C:\\Program Files\\Tornect\\tornect.exe\" open-link -- \"%1\"";
        assert_eq!(
            url_handler_command("C:\\Program Files\\Tornect\\tornect.exe").unwrap(),
            command
        );
        assert_eq!(
            WindowsTarget::of(&Fake::new()).unwrap().url_command,
            command
        );
        assert_eq!(
            WindowsTarget::entry_of(&Fake::new()).unwrap().url_command,
            ""
        );
        for bad in [
            "tornect.exe",
            "\\\\server\\share\\tornect.exe",
            "C:/Tornect/tornect.exe",
            "C:\\a\"b\\tornect.exe",
            "C:\\100%\\tornect.exe",
            "C:\\a\u{7}b\\tornect.exe",
            "C:\\a\u{85}b\\tornect.exe",
        ] {
            match url_handler_command(bad) {
                Err(InstallError::Unavailable(why)) => assert!(
                    why.contains("Windows' registration of tornect:// links"),
                    "{bad:?}: {why}"
                ),
                other => panic!("{bad:?}: {other:?}"),
            }
        }
        assert_eq!(URL_SCHEME_KEY, "Software\\Classes\\tornect");
        assert_eq!(URL_SCHEME_NAME, "URL:Tornect link");
    }

    /// Design `invite` §4.5, step 6b: with no registration there, the
    /// install writes exactly the installed copy's command, once, after the
    /// Start-menu entry and before the elevated uninstall entry, and links
    /// open Tornect.
    #[test]
    fn the_link_registration_is_written_after_the_shortcut_and_before_the_entry() {
        let fake = Fake::new();
        let installed = install_in_program_files(&fake, &mut allow(&fake)).unwrap();
        assert_eq!(installed.links, WindowsLinks::Registered);
        let events = fake.events();
        let writes: Vec<&Ev> = events
            .iter()
            .filter(|e| matches!(e, Ev::WriteUrl(_)))
            .collect();
        assert_eq!(
            writes,
            [&Ev::WriteUrl(
                "\"C:\\Program Files\\Tornect\\tornect.exe\" open-link -- \"%1\"".to_owned()
            )]
        );
        let authorize = position(&events, |e| *e == Ev::Authorize);
        let shortcut = position(&events, |e| matches!(e, Ev::WriteShortcut(_)));
        let url = position(&events, |e| matches!(e, Ev::WriteUrl(_)));
        let entry = position(&events, |e| {
            matches!(e, Ev::Elevated(Elevated::WriteEntry(_)))
        });
        assert!(
            authorize < shortcut && shortcut < url && url < entry,
            "{events:?}"
        );
        assert!(!events.contains(&Ev::RemoveUrl), "{events:?}");
        assert_eq!(fake.url(), UrlKey::Command(fake.url_command()));
    }

    /// A second prompt (the uninstall entry's) cancelled or failed undoes the
    /// registration this install wrote, newest first: before the Start-menu
    /// entry and the copy. A registration whose own write failed was not
    /// kept, so the undo starts at the Start-menu entry.
    #[test]
    fn a_cancelled_second_prompt_undoes_the_link_registration() {
        for at in ["cancel", "fail"] {
            let mut fake = Fake::new();
            if at == "cancel" {
                fake.cancel.borrow_mut().push("write");
            } else {
                fake.fail = vec!["write"];
            }
            assert!(
                install_in_program_files(&fake, &mut allow(&fake)).is_err(),
                "{at}"
            );
            let events = fake.events();
            let url = position(&events, |e| matches!(e, Ev::WriteUrl(_)));
            let after: Vec<Ev> = events[url + 1..]
                .iter()
                .filter(|e| !matches!(e, Ev::Elevated(Elevated::WriteEntry(_))))
                .cloned()
                .collect();
            assert_eq!(
                after,
                [
                    Ev::RemoveUrl,
                    Ev::RemoveShortcut(Fake::link()),
                    Ev::Elevated(Elevated::RemoveFolder {
                        folder: fake.folder()
                    }),
                    Ev::CloseImage,
                ],
                "{at}"
            );
            assert_eq!(fake.url(), UrlKey::Absent, "{at}");
            fake.assert_nothing_installed();
        }
        let mut fake = Fake::new();
        fake.fail_url = true;
        match install_in_program_files(&fake, &mut allow(&fake)) {
            Err(InstallError::Failed(why)) => assert_eq!(why, "the registry refused"),
            other => panic!("{other:?}"),
        }
        let events = fake.events();
        let url = position(&events, |e| matches!(e, Ev::WriteUrl(_)));
        assert_eq!(
            events[url + 1..],
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

    /// L-6: the undo of a second prompt cancelled or failed reads the
    /// registration again before removing it, since that prompt may have
    /// stayed open for long: one another program put in its place meanwhile
    /// is left, and the message says so; one already gone is not reported.
    /// The rest is undone as before.
    #[test]
    fn the_undo_leaves_a_link_registration_changed_during_the_second_prompt() {
        for (now, reported) in [
            (theirs(), true),
            (UrlKey::Other, true),
            (UrlKey::Absent, false),
        ] {
            for at in ["cancel", "fail"] {
                let mut fake = Fake::new();
                if at == "cancel" {
                    fake.cancel.borrow_mut().push("write");
                } else {
                    fake.fail = vec!["write"];
                }
                *fake.url_during_prompt.borrow_mut() = Some(("write", now.clone()));
                let why = match install_in_program_files(&fake, &mut allow(&fake)) {
                    Err(InstallError::Cancelled(why)) if at == "cancel" => why,
                    Err(InstallError::Failed(why)) if at == "fail" => why,
                    other => panic!("{now:?} {at}: {other:?}"),
                };
                assert_eq!(
                    why.ends_with(URL_KEY_CHANGED_MEANWHILE),
                    reported,
                    "{now:?} {at}: {why}"
                );
                let events = fake.events();
                assert!(!events.contains(&Ev::RemoveUrl), "{now:?} {at}: {events:?}");
                assert_eq!(fake.url(), now, "{at}");
                let url = position(&events, |e| matches!(e, Ev::WriteUrl(_)));
                let after: Vec<Ev> = events[url + 1..]
                    .iter()
                    .filter(|e| !matches!(e, Ev::Elevated(Elevated::WriteEntry(_))))
                    .cloned()
                    .collect();
                assert_eq!(
                    after,
                    [
                        Ev::RemoveShortcut(Fake::link()),
                        Ev::Elevated(Elevated::RemoveFolder {
                            folder: fake.folder()
                        }),
                        Ev::CloseImage,
                    ],
                    "{now:?} {at}"
                );
                fake.assert_nothing_installed();
            }
        }
        // Still this install's own command: removed, and nothing is added.
        let fake = Fake::new();
        fake.cancel.borrow_mut().push("write");
        *fake.url_during_prompt.borrow_mut() = Some(("write", UrlKey::Command(fake.url_command())));
        match install_in_program_files(&fake, &mut allow(&fake)) {
            Err(InstallError::Cancelled(why)) => assert_eq!(why, INSTALL_NEEDS_APPROVAL),
            other => panic!("{other:?}"),
        }
        assert!(fake.events().contains(&Ev::RemoveUrl));
        assert_eq!(fake.url(), UrlKey::Absent);
    }

    /// Design `invite` §4.5, L-6: a registration that is not this install's
    /// (another program's command, a near miss of Tornect's, or a key without
    /// a command that can be read) is never written over and never undone: the
    /// install goes on and says so, and a cancel undoes only what it wrote.
    #[test]
    fn a_foreign_link_registration_is_left_and_reported() {
        for key in [
            theirs(),
            UrlKey::Command(
                "\"C:\\Program Files\\Tornect\\tornect.exe\" open-link -- \"%1\" --home C:\\x"
                    .to_owned(),
            ),
            UrlKey::Other,
        ] {
            let fake = Fake::new();
            *fake.url.borrow_mut() = key.clone();
            let installed = install_in_program_files(&fake, &mut allow(&fake)).unwrap();
            assert_eq!(installed.links, WindowsLinks::OtherProgram, "{key:?}");
            assert_eq!(fake.url(), key);
            assert!(!url_touched(&fake), "{key:?}: {:?}", fake.events());
            assert!(fake.entries.borrow().contains_key(UNINSTALL_KEY), "{key:?}");

            let fake = Fake::new();
            *fake.url.borrow_mut() = key.clone();
            fake.cancel.borrow_mut().push("write");
            assert!(
                matches!(
                    install_in_program_files(&fake, &mut allow(&fake)),
                    Err(InstallError::Cancelled(_))
                ),
                "{key:?}"
            );
            assert_eq!(fake.url(), key);
            assert!(!url_touched(&fake), "{key:?}: {:?}", fake.events());
            fake.assert_nothing_installed();
        }
    }

    /// Design `invite` §4.5: a registration whose command is this install's
    /// own is a leftover of it (an earlier install of this computer's
    /// Program Files copy): kept, links open Tornect, nothing is written, and
    /// a cancelled prompt never deletes it.
    #[test]
    fn a_leftover_with_this_installs_command_is_kept_and_never_undone() {
        let fake = Fake::new();
        *fake.url.borrow_mut() = UrlKey::Command(fake.url_command());
        let installed = install_in_program_files(&fake, &mut allow(&fake)).unwrap();
        assert_eq!(installed.links, WindowsLinks::Registered);
        assert!(!url_touched(&fake), "{:?}", fake.events());
        assert_eq!(fake.url(), UrlKey::Command(fake.url_command()));

        let fake = Fake::new();
        *fake.url.borrow_mut() = UrlKey::Command(fake.url_command());
        fake.cancel.borrow_mut().push("write");
        assert!(matches!(
            install_in_program_files(&fake, &mut allow(&fake)),
            Err(InstallError::Cancelled(_))
        ));
        assert!(!url_touched(&fake), "{:?}", fake.events());
        assert_eq!(fake.url(), UrlKey::Command(fake.url_command()));
        assert!(fake.shortcuts.borrow().is_empty() && fake.entries.borrow().is_empty());
    }

    /// A registration that appears while the dialog is open is never written
    /// over: the write finds it (`REG_OPENED_EXISTING_KEY` on Windows), and
    /// the install stops with [`URL_KEY_APPEARED`], what it did undone and
    /// the other program's key as it was.
    #[test]
    fn a_link_registration_that_appears_during_the_dialog_is_not_written_over() {
        let fake = Fake::new();
        let mut appears = || {
            fake.record(Ev::Authorize);
            *fake.url.borrow_mut() = theirs();
            Ok(())
        };
        match install_in_program_files(&fake, &mut appears) {
            Err(InstallError::Refused(why)) => assert_eq!(why, URL_KEY_APPEARED),
            other => panic!("{other:?}"),
        }
        assert_eq!(fake.url(), theirs());
        let events = fake.events();
        assert!(!events.contains(&Ev::RemoveUrl), "{events:?}");
        assert!(
            !fake
                .elevated()
                .iter()
                .any(|s| matches!(s, Elevated::WriteEntry(_))),
            "{events:?}"
        );
        fake.assert_nothing_installed();
    }

    /// L-6: an uninstall removes this user's registration only while its
    /// command is the installed copy's; another program's, or one without a
    /// readable command, is left and reported, installed or not (with
    /// nothing else there nothing is asked).
    #[test]
    fn uninstall_removes_only_this_installs_link_registration() {
        for key in [theirs(), UrlKey::Other] {
            let fake = Fake::new();
            fake.installed();
            *fake.url.borrow_mut() = key.clone();
            let removed = uninstall_from_program_files(&fake, &mut allow(&fake)).unwrap();
            assert_eq!(
                removed,
                WindowsRemoval {
                    uninstall_entry: true,
                    start_menu_entry: true,
                    url_handler: false,
                    folder: true,
                    url_handler_left: true,
                },
                "{key:?}"
            );
            assert_eq!(fake.url(), key);
            assert!(!url_touched(&fake), "{key:?}");

            let fake = Fake::new();
            *fake.url.borrow_mut() = key.clone();
            let removed = uninstall_from_program_files(&fake, &mut allow(&fake)).unwrap();
            assert_eq!(
                removed,
                WindowsRemoval {
                    url_handler_left: true,
                    ..WindowsRemoval::default()
                },
                "{key:?}"
            );
            assert!(!fake.events().contains(&Ev::Authorize), "{key:?}");
            assert!(!url_touched(&fake), "{key:?}");
            assert_eq!(fake.url(), key);
        }
    }

    /// A registration with the installed copy's command, left with nothing
    /// else of an install, is still Tornect's: the uninstall asks the guard,
    /// then removes it and nothing else.
    #[test]
    fn a_leftover_link_registration_alone_is_removed_after_the_dialog() {
        let fake = Fake::new();
        *fake.url.borrow_mut() = UrlKey::Command(fake.url_command());
        let removed = uninstall_from_program_files(&fake, &mut allow(&fake)).unwrap();
        assert_eq!(
            removed,
            WindowsRemoval {
                url_handler: true,
                ..WindowsRemoval::default()
            }
        );
        let events = fake.events();
        let authorize = position(&events, |e| *e == Ev::Authorize);
        assert_eq!(events[authorize + 1..], [Ev::RemoveUrl], "{events:?}");
        assert!(!events[..authorize].contains(&Ev::RemoveUrl));
        assert_eq!(fake.url(), UrlKey::Absent);
    }

    /// The registration is read again right before its removal, since the
    /// dialog may stay open for long: one another program put in its place
    /// meanwhile is left and reported, one already gone is neither removed
    /// nor reported; the rest of the uninstall goes on.
    #[test]
    fn a_link_registration_changed_during_the_dialog_is_not_removed() {
        for (now, left) in [
            (theirs(), true),
            (UrlKey::Other, true),
            (UrlKey::Absent, false),
        ] {
            let fake = Fake::new();
            fake.installed();
            let mut changes = || {
                fake.record(Ev::Authorize);
                *fake.url.borrow_mut() = now.clone();
                Ok(())
            };
            let removed = uninstall_from_program_files(&fake, &mut changes).unwrap();
            assert_eq!(
                removed,
                WindowsRemoval {
                    uninstall_entry: true,
                    start_menu_entry: true,
                    url_handler: false,
                    folder: true,
                    url_handler_left: left,
                },
                "{now:?}"
            );
            assert!(!url_touched(&fake), "{now:?}: {:?}", fake.events());
            assert_eq!(fake.url(), now);
        }
    }
}
