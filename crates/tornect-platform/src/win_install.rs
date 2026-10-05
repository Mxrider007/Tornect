//! The Win32 side of the Program Files install of [`crate::install`]
//! (§B.1.1): the known folders, this program's image held open with share
//! mode read only and named by the held handle's own final path, reads that
//! never follow a reparse point (`FILE_FLAG_OPEN_REPARSE_POINT`, the owner
//! and the DACL through `GetSecurityInfo` on such a handle), the uninstall
//! entry and Windows' list of removals at the next restart, both read in the
//! registry's 64-bit view, the Start-menu entry (`IShellLinkW` and
//! `IPersistFile`, declared here in the order of `shobjidl_core.h` and
//! `objidl.h`, since `windows-sys` has none), and each elevated step through
//! Windows' prompt with the program and parameters of
//! [`elevated_command`]. Type-checked only: NEEDS-DEVICE(windows).
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, HLOCAL, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileAttributesW,
    GetFinalPathNameByHandleW, INVALID_FILE_ATTRIBUTES, READ_CONTROL, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY,
    REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, RRF_RT_REG_MULTI_SZ, RegCloseKey,
    RegCreateKeyExW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
};
use windows_sys::Win32::UI::Shell::ShellLink;
use windows_sys::core::GUID;

use crate::helper_task::{Ace, Security};
use crate::install::{
    Elevated, HeldImage, InstallError, UNINSTALL_ROOT, UninstallEntry, WindowsSystem,
    WindowsTarget, elevated_command, step_succeeded,
};
use crate::win::{ElevateError, KnownFolder, wide};
use crate::win_task::{Com, Hresult, check};

/// The key of Windows' list of renames and deletes at the next restart.
const SESSION_MANAGER: &str = "SYSTEM\\CurrentControlSet\\Control\\Session Manager";

/// The value that holds that list.
const PENDING_RENAMES: &str = "PendingFileRenameOperations";

/// How many times the list is read when it grows between the size and the
/// read.
const PENDING_READS: usize = 3;

/// `IID_IShellLinkW` (shobjidl_core.h).
const IID_ISHELL_LINK_W: GUID = GUID::from_u128(0x000214f9_0000_0000_c000_000000000046);

/// `IID_IPersistFile` (objidl.h).
const IID_IPERSIST_FILE: GUID = GUID::from_u128(0x0000010b_0000_0000_c000_000000000046);

/// `IShellLinkW`: IUnknown, then its own methods up to `SetPath`.
#[repr(C)]
struct ShellLinkVtbl {
    query_interface:
        unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> Hresult,
    add_ref: usize,
    release: usize,
    get_path: usize,
    get_id_list: usize,
    set_id_list: usize,
    get_description: usize,
    set_description: usize,
    get_working_directory: usize,
    set_working_directory: usize,
    get_arguments: usize,
    set_arguments: usize,
    get_hotkey: usize,
    set_hotkey: usize,
    get_show_cmd: usize,
    set_show_cmd: usize,
    get_icon_location: usize,
    set_icon_location: usize,
    set_relative_path: usize,
    resolve: usize,
    set_path: unsafe extern "system" fn(*mut c_void, *const u16) -> Hresult,
}

/// `IPersistFile`: IUnknown, `IPersist::GetClassID`, then its own methods
/// up to `Save`.
#[repr(C)]
struct PersistFileVtbl {
    query_interface: usize,
    add_ref: usize,
    release: usize,
    get_class_id: usize,
    is_dirty: usize,
    load: usize,
    save: unsafe extern "system" fn(*mut c_void, *const u16, i32) -> Hresult,
}

/// This computer for the Program Files install: the calls of
/// [`WindowsSystem`], with each known folder asked of the OS (never of the
/// environment) when it is first needed and kept from then on, so the
/// program a step is checked with is the one it runs, and a step that needs
/// no Start menu never asks for one.
#[derive(Debug, Default)]
pub struct RealWindows {
    program_files: OnceLock<Result<String, String>>,
    system_directory: OnceLock<Result<String, String>>,
    start_menu_programs: OnceLock<Result<String, String>>,
}

impl RealWindows {
    /// This computer, with no folder asked yet.
    #[must_use]
    pub fn of_this_computer() -> Self {
        Self::default()
    }
}

/// A folder the OS gave, as text, or why it is not there.
fn folder(found: io::Result<PathBuf>, what: &str) -> Result<String, String> {
    let path = found.map_err(|e| format!("Tornect cannot find {what}: {e}"))?;
    path.into_os_string().into_string().map_err(|p| {
        format!(
            "{what} ({}) is not a path Tornect can use",
            p.to_string_lossy()
        )
    })
}

/// `found` as the steps take it; one that could not be had refuses what
/// needs it.
fn given(found: &Result<String, String>) -> Result<String, InstallError> {
    found.clone().map_err(InstallError::Unavailable)
}

/// This program's image, held open with share mode read only.
struct Image {
    file: std::fs::File,
    path: String,
}

impl io::Read for Image {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.file, buf)
    }
}

impl HeldImage for Image {
    fn path(&self) -> &str {
        &self.path
    }
}

/// This program's image, opened with share mode read only (from
/// `own_image`, never argv[0]), and the final path of that handle.
fn held_own_image() -> io::Result<(std::fs::File, String)> {
    let own = crate::win_helper::own_image()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&own)?;
    let path = final_path_of(&file)?;
    Ok((file, path))
}

/// This program's own path as the installed copy's steps compare it: the
/// final path of its image, resolved as the install resolves the image it
/// holds.
pub fn own_path() -> Result<String, InstallError> {
    held_own_image()
        .map(|(_, path)| path)
        .map_err(|e| InstallError::Failed(format!("finding this program: {e}")))
}

/// Write `entry` under HKLM in the 64-bit view: its key and the three
/// values `DisplayName`, `DisplayVersion` and `UninstallString` (REG_SZ),
/// nothing else. The installed copy's elevated step; unelevated, the key
/// cannot be opened for writing and nothing is written.
pub fn write_uninstall_entry(entry: &UninstallEntry) -> Result<(), InstallError> {
    let failed = |e: io::Error| {
        InstallError::Failed(format!("writing Tornect's entry in Apps and features: {e}"))
    };
    let path = wide(format!("{UNINSTALL_ROOT}\\{}", entry.key));
    let mut key: HKEY = null_mut();
    // SAFETY: `path` is NUL-terminated; no class, no security attributes;
    // `key` receives an open key on success; no disposition asked.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            null(),
            &mut key,
            null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(failed(io::Error::from_raw_os_error(status as i32)));
    }
    let key = Key(key);
    for (name, value) in [
        ("DisplayName", &entry.display_name),
        ("DisplayVersion", &entry.display_version),
        ("UninstallString", &entry.uninstall_string),
    ] {
        let name = wide(name);
        let data = wide(value);
        let bytes = u32::try_from(data.len() * 2)
            .map_err(|_| failed(io::Error::other("a value is too long")))?;
        // SAFETY: `key` is open with KEY_SET_VALUE; `name` and `data` are
        // NUL-terminated and `data` is `bytes` long, its NUL included.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast::<u8>(),
                bytes,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(failed(io::Error::from_raw_os_error(status as i32)));
        }
    }
    Ok(())
}

/// The final path of the open file `file` (`GetFinalPathNameByHandleW`, the
/// DOS form, `\\?\` taken off and `\\?\UNC\` written `\\`): the file that is
/// held, whatever path reached it.
fn final_path_of(file: &std::fs::File) -> io::Result<String> {
    let mut buf = vec![0u16; 32768];
    let cap = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: `file` is open; `buf` is writable for `cap` characters.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buf.as_mut_ptr(),
            cap,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if len == 0 || len >= cap {
        return Err(io::Error::last_os_error());
    }
    let full = String::from_utf16(&buf[..len as usize])
        .map_err(|_| io::Error::other("the path is not valid UTF-16"))?;
    Ok(match full.strip_prefix(r"\\?\UNC\") {
        Some(unc) => format!(r"\\{unc}"),
        None => full.strip_prefix(r"\\?\").unwrap_or(&full).to_owned(),
    })
}

/// The owner and the DACL of `path` itself, read from a handle opened with
/// `READ_CONTROL` that never follows a reparse point at `path`. An entry of
/// a type other than allow or deny counts as an allow of every right that
/// applies to the object itself (so the check refuses), as the helper
/// task's reader counts it.
fn security_of(path: &str) -> io::Result<Security> {
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let mut owner: PSID = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `file` is open with READ_CONTROL; on success `sd` is a
    // descriptor allocated with `LocalAlloc` (freed below), and `owner` and
    // `acl` point into it.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut sd,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let mut out = Vec::new();
    let read = if owner.is_null() {
        Err(io::Error::other("it has no owner"))
    } else if acl.is_null() {
        // A null DACL grants everyone everything.
        Err(io::Error::other(
            "it has no DACL (everyone has full access)",
        ))
    } else {
        // SAFETY: `acl` points to a valid ACL inside `sd`.
        let count = unsafe { (*acl).AceCount };
        let mut failed = None;
        for i in 0..u32::from(count) {
            let mut ace: *mut c_void = null_mut();
            // SAFETY: `i` is below the ACL's entry count; `ace` receives a
            // pointer into the ACL.
            if unsafe { GetAce(acl, i, &mut ace) } == 0 || ace.is_null() {
                failed = Some(io::Error::last_os_error());
                break;
            }
            // SAFETY: every ACE starts with an ACE_HEADER.
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            match header.AceType {
                0 | 1 => {
                    // SAFETY: types 0 and 1 are ACCESS_ALLOWED_ACE and
                    // ACCESS_DENIED_ACE, the same layout: the SID starts at
                    // `SidStart`.
                    let entry = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
                    let sid = (&raw const entry.SidStart).cast_mut().cast::<c_void>();
                    match crate::win::sid_string(sid) {
                        Ok(sid) => out.push(Ace {
                            sid,
                            allow: header.AceType == 0,
                            mask: entry.Mask,
                            flags: header.AceFlags,
                        }),
                        Err(e) => {
                            failed = Some(e);
                            break;
                        }
                    }
                }
                _ => out.push(Ace {
                    sid: "an entry of another type".to_owned(),
                    allow: true,
                    mask: u32::MAX,
                    flags: 0,
                }),
            }
        }
        failed.map_or(Ok(()), Err)
    };
    // The owner's SID points into `sd`: read it before `sd` is freed.
    let owner = read.and_then(|()| crate::win::sid_string(owner));
    // SAFETY: allocated by `GetSecurityInfo`, freed once, after the last
    // read of `owner` and `acl` above.
    unsafe { LocalFree(sd as HLOCAL) };
    owner.map(|owner| Security { owner, dacl: out })
}

/// A registry key, closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key was opened by `RegOpenKeyExW` and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// `HKLM\<path>` opened with `access` in the 64-bit view; `None` when it
/// does not exist.
fn open_hklm(path: &str, access: REG_SAM_FLAGS) -> io::Result<Option<Key>> {
    let name = wide(path);
    let mut key: HKEY = null_mut();
    // SAFETY: `name` is NUL-terminated; `key` receives an open key on success.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            access | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    match status {
        ERROR_SUCCESS => Ok(Some(Key(key))),
        ERROR_FILE_NOT_FOUND => Ok(None),
        e => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

/// Windows' list of renames and deletes at the next restart, every string
/// as stored; empty when the value does not exist. The key exists on every
/// Windows, so a key that cannot be opened is an error, as is a value of
/// another type or an odd byte count. The value is asked for its size, read
/// into a buffer of that size, and asked again when it grew in between, at
/// most [`PENDING_READS`] times. The whole length read is split at each NUL,
/// so an empty string (a delete's destination) never ends the list.
fn pending_renames() -> io::Result<Vec<String>> {
    let key = open_hklm(SESSION_MANAGER, KEY_QUERY_VALUE)?
        .ok_or_else(|| io::Error::other("the Session Manager key is missing"))?;
    let value = wide(PENDING_RENAMES);
    for _ in 0..PENDING_READS {
        let mut size = 0u32;
        // SAFETY: the value's size only: no type, no buffer.
        let status = unsafe {
            RegGetValueW(
                key.0,
                null(),
                value.as_ptr(),
                RRF_RT_REG_MULTI_SZ,
                null_mut(),
                null_mut(),
                &mut size,
            )
        };
        match status {
            ERROR_SUCCESS => {}
            ERROR_FILE_NOT_FOUND => return Ok(Vec::new()),
            e => return Err(io::Error::from_raw_os_error(e as i32)),
        }
        if !size.is_multiple_of(2) {
            return Err(io::Error::other("the list has an odd byte count"));
        }
        let mut units = vec![0u16; size as usize / 2];
        let mut read = size;
        // SAFETY: `units` is writable for `read` bytes; no type asked.
        let status = unsafe {
            RegGetValueW(
                key.0,
                null(),
                value.as_ptr(),
                RRF_RT_REG_MULTI_SZ,
                null_mut(),
                units.as_mut_ptr().cast::<c_void>(),
                &mut read,
            )
        };
        match status {
            ERROR_SUCCESS => {
                if !read.is_multiple_of(2) || read > size {
                    return Err(io::Error::other("the list has an odd byte count"));
                }
                units.truncate(read as usize / 2);
                return Ok(units
                    .split(|unit| *unit == 0)
                    .map(String::from_utf16_lossy)
                    .collect());
            }
            ERROR_MORE_DATA => {}
            ERROR_FILE_NOT_FOUND => return Ok(Vec::new()),
            e => return Err(io::Error::from_raw_os_error(e as i32)),
        }
    }
    Err(io::Error::other("the list kept growing while it was read"))
}

/// The Start-menu entry `link`, which starts `target` and nothing else (no
/// arguments, no icon), saved through `IPersistFile`; every interface
/// released and COM's start balanced.
fn shortcut(link: &str, target: &str) -> io::Result<()> {
    // SAFETY: plain call; balanced by `CoUninitialize` below when it succeeds.
    let com = unsafe {
        CoInitializeEx(
            null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    let result = (|| {
        let mut shell_link: *mut c_void = null_mut();
        // SAFETY: the CLSID is ShellLink's and the IID IShellLinkW's;
        // `shell_link` receives the interface on success.
        let hr = unsafe {
            CoCreateInstance(
                &ShellLink,
                null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_ISHELL_LINK_W,
                &mut shell_link,
            )
        };
        check(hr, "creating the Start-menu entry")?;
        let shell_link = Com(shell_link);
        let program = wide(target);
        // SAFETY: `shell_link` is an IShellLinkW; `program` is NUL-terminated
        // and outlives the call.
        let hr = unsafe {
            (shell_link.vtbl::<ShellLinkVtbl>().set_path)(shell_link.0, program.as_ptr())
        };
        check(hr, "setting the Start-menu entry's program")?;
        let mut persist: *mut c_void = null_mut();
        // SAFETY: `shell_link` is an IShellLinkW, asked for its IPersistFile;
        // `persist` receives it on success and stays null otherwise.
        let hr = unsafe {
            (shell_link.vtbl::<ShellLinkVtbl>().query_interface)(
                shell_link.0,
                &IID_IPERSIST_FILE,
                &mut persist,
            )
        };
        let persist = Com(persist);
        check(hr, "opening the Start-menu entry for saving")?;
        let file = wide(link);
        // SAFETY: `persist` is an IPersistFile; `file` is NUL-terminated and
        // outlives the call; TRUE makes it the object's current file.
        let hr = unsafe { (persist.vtbl::<PersistFileVtbl>().save)(persist.0, file.as_ptr(), 1) };
        check(hr, "saving the Start-menu entry")
    })();
    if com >= 0 {
        // SAFETY: balances the successful `CoInitializeEx` above, after every
        // interface was released.
        unsafe { CoUninitialize() };
    }
    result
}

/// Why `step` failed with `code`.
fn step_failed(step: &Elevated, target: &WindowsTarget, code: u32) -> String {
    match step {
        Elevated::Copy { .. } => format!(
            "Windows' copy into {} failed (robocopy exit code {code}), so nothing was installed.",
            target.folder
        ),
        Elevated::WriteEntry(_) => format!(
            "The installed copy could not write Tornect's entry in Apps and features (exit code \
             {code}), so nothing was installed."
        ),
        Elevated::DeleteEntry { .. } => {
            format!("Removing Tornect's entry in Apps and features failed (reg exit code {code}).")
        }
        Elevated::RemoveFolder { folder } => {
            format!("{folder} could not be removed (cmd exit code {code}).")
        }
    }
}

impl WindowsSystem for RealWindows {
    fn program_files(&self) -> Result<String, InstallError> {
        given(self.program_files.get_or_init(|| {
            folder(
                crate::win::known_folder(KnownFolder::ProgramFiles),
                "Program Files",
            )
        }))
    }

    fn system_directory(&self) -> Result<String, InstallError> {
        given(
            self.system_directory.get_or_init(|| {
                folder(crate::win::system_directory(), "the Windows system folder")
            }),
        )
    }

    fn start_menu_programs(&self) -> Result<String, InstallError> {
        given(self.start_menu_programs.get_or_init(|| {
            folder(
                crate::win::known_folder(KnownFolder::Programs),
                "the Start menu's programs folder",
            )
        }))
    }

    fn open_own_image(&self) -> Result<Box<dyn HeldImage + '_>, InstallError> {
        let (file, path) = held_own_image()
            .map_err(|e| InstallError::Failed(format!("opening this program: {e}")))?;
        Ok(Box::new(Image { file, path }))
    }

    fn folder_entries(&self, folder: &str) -> Result<Option<Vec<String>>, InstallError> {
        let failed = |e: io::Error| InstallError::Failed(format!("reading {folder}: {e}"));
        let entries = match std::fs::read_dir(folder) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(failed(e)),
        };
        entries
            .map(|entry| {
                entry
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .map_err(failed)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    fn is_reparse_point(&self, path: &str) -> Result<bool, InstallError> {
        let name = wide(path);
        // SAFETY: `name` is NUL-terminated; the attributes of `path` itself.
        let attributes = unsafe { GetFileAttributesW(name.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(InstallError::Failed(format!("reading what {path} is: {e}")));
        }
        Ok(attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }

    fn read_file(&self, path: &str) -> Result<Box<dyn io::Read + '_>, InstallError> {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map(|file| Box::new(file) as Box<dyn io::Read>)
            .map_err(|e| InstallError::Failed(format!("reading {path}: {e}")))
    }

    fn security(&self, path: &str) -> Result<Security, InstallError> {
        security_of(path)
            .map_err(|e| InstallError::Failed(format!("reading who may change {path}: {e}")))
    }

    fn elevated_program(&self, step: &Elevated) -> String {
        // Without the target nothing can run: an empty name passes no check.
        WindowsTarget::of(self)
            .map(|target| elevated_command(step, &target).0)
            .unwrap_or_default()
    }

    fn run_elevated(&self, step: &Elevated) -> Result<(), InstallError> {
        let target = WindowsTarget::of(self)?;
        let (program, parameters) = elevated_command(step, &target);
        match crate::win::run_elevated(Path::new(&program), &parameters) {
            Ok(code) if step_succeeded(step, code) => Ok(()),
            Ok(code) => Err(InstallError::Failed(step_failed(step, &target, code))),
            Err(ElevateError::Cancelled) => Err(InstallError::Cancelled(
                "Windows' administrator prompt was dismissed".to_owned(),
            )),
            Err(ElevateError::Failed(why)) => Err(InstallError::Failed(why)),
        }
    }

    fn uninstall_entry_exists(&self, key: &str) -> Result<bool, InstallError> {
        open_hklm(&format!("{UNINSTALL_ROOT}\\{key}"), KEY_READ)
            .map(|found| found.is_some())
            .map_err(|e| {
                InstallError::Failed(format!("reading Tornect's entry in Apps and features: {e}"))
            })
    }

    fn file_exists(&self, path: &str) -> Result<bool, InstallError> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(InstallError::Failed(format!("reading {path}: {e}"))),
        }
    }

    fn pending_removals(&self) -> Result<Vec<String>, InstallError> {
        pending_renames().map_err(|e| InstallError::Failed(e.to_string()))
    }

    fn write_shortcut(&self, link: &str, target: &str) -> Result<(), InstallError> {
        shortcut(link, target).map_err(|e| InstallError::Failed(format!("writing {link}: {e}")))
    }

    fn remove_shortcut(&self, link: &str) -> Result<(), InstallError> {
        match std::fs::remove_file(link) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(InstallError::Failed(format!("removing {link}: {e}"))),
        }
    }
}
