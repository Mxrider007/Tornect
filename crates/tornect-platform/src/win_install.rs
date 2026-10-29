//! The Win32 side of the Program Files install of [`crate::install`]
//! (§B.1.1): the known folders, this program's image held open with share
//! mode read only and named by the held handle's own final path (the
//! lyrebird beside it held the same way, decision M1-88 (2)), reads that
//! never follow a reparse point (`FILE_FLAG_OPEN_REPARSE_POINT`, the owner
//! and the DACL through `GetSecurityInfo` on such a handle), the uninstall
//! entry and Windows' list of removals at the next restart, both read in the
//! registry's 64-bit view, the Start-menu entry (`IShellLinkW` and
//! `IPersistFile`, declared here in the order of `shobjidl_core.h` and
//! `objidl.h`, since `windows-sys` has none), this user's registration of
//! `tornect:` links under `HKEY_CURRENT_USER` (design `invite` §4.5: read,
//! written only where `RegCreateKeyExW` created the key, deleted with
//! `RegDeleteTreeW` and `RegDeleteKeyW`), and each elevated step through
//! Windows' prompt with the program and parameters of [`elevated_command`].
//! The registration's calls run in this crate's Windows tests (under Wine
//! here, on a key of the test's own); the rest is type-checked only:
//! NEEDS-DEVICE(windows).
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS,
    ERROR_UNSUPPORTED_TYPE, HLOCAL, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileAttributesW, GetFinalPathNameByHandleW, INVALID_FILE_ATTRIBUTES,
    MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW, READ_CONTROL, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_CREATE_SUB_KEY, KEY_QUERY_VALUE, KEY_READ,
    KEY_SET_VALUE, KEY_WOW64_64KEY, REG_CREATE_KEY_DISPOSITION, REG_CREATED_NEW_KEY,
    REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, RRF_NOEXPAND, RRF_RT_REG_MULTI_SZ,
    RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteTreeW, RegGetValueW,
    RegOpenKeyExW, RegSetValueExW,
};
use windows_sys::Win32::UI::Shell::ShellLink;
use windows_sys::core::GUID;

use crate::helper_task::{Ace, Security};
use crate::install::{
    Elevated, HeldImage, InstallError, UNINSTALL_ROOT, URL_KEY_APPEARED, URL_SCHEME_KEY,
    URL_SCHEME_NAME, UninstallEntry, UrlKey, WindowsSystem, WindowsTarget, elevated_command,
    step_succeeded,
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

/// The link registration's subkey that holds its command.
const URL_COMMAND_KEY: &str = "shell\\open\\command";

/// The longest command of a link registration that is read, in bytes, its
/// NUL included: Tornect's own is far shorter, so a longer one is not
/// Tornect's.
const URL_COMMAND_MAX: u32 = 4096;

/// How many times that command is read when it grows between the size and
/// the read.
const URL_COMMAND_READS: usize = 3;

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

/// The file at `path` opened for reading with share mode read only, as the
/// image is held: while the handle is open no one can write, rename or
/// delete it. A reparse point at `path` is opened itself, never followed.
fn held_file(path: &str) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
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
        set_string(&key, Some(name), value).map_err(failed)?;
    }
    Ok(())
}

/// Set the `REG_SZ` value `name` of `key`, open with `KEY_SET_VALUE`, to
/// `value`; `None` is the key's default value.
fn set_string(key: &Key, name: Option<&str>, value: &str) -> io::Result<()> {
    let name = name.map(wide);
    let data = wide(value);
    let bytes =
        u32::try_from(data.len() * 2).map_err(|_| io::Error::other("a value is too long"))?;
    // SAFETY: `key` is open with KEY_SET_VALUE; the name is NUL-terminated or
    // null (the default value); `data` is NUL-terminated and `bytes` long,
    // its NUL included.
    let status = unsafe {
        RegSetValueExW(
            key.0,
            name.as_ref().map_or(null(), |n| n.as_ptr()),
            0,
            REG_SZ,
            data.as_ptr().cast::<u8>(),
            bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// `parent\path` created, or opened when it is there, with `access`: the key
/// and whether it was created (`REG_CREATED_NEW_KEY`) or opened.
fn create_key(
    parent: HKEY,
    path: &str,
    access: REG_SAM_FLAGS,
) -> io::Result<(Key, REG_CREATE_KEY_DISPOSITION)> {
    let name = wide(path);
    let mut key: HKEY = null_mut();
    let mut disposition: REG_CREATE_KEY_DISPOSITION = 0;
    // SAFETY: `parent` is open (or predefined); `name` is NUL-terminated; no
    // class, no security attributes; `key` receives an open key and
    // `disposition` what was done, on success.
    let status = unsafe {
        RegCreateKeyExW(
            parent,
            name.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            access,
            null(),
            &mut key,
            &mut disposition,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok((Key(key), disposition))
}

/// This user's registration of `tornect:` links at `HKCU\<path>` (design
/// `invite` §4.5; `path` is [`URL_SCHEME_KEY`] but in the tests): absent
/// when the key is not there; else the default value of its
/// `shell\open\command`, a `REG_SZ` (a `REG_EXPAND_SZ` is not expanded and
/// counts as another type) without its trailing NULs, asked for its size and
/// read, again when it grew in between, at most [`URL_COMMAND_READS`] times.
/// A key that cannot be opened for reading, or a command that is missing, of
/// another type, longer than [`URL_COMMAND_MAX`], cannot be read or is not
/// UTF-16, is [`UrlKey::Other`]: a registration left as it is.
fn url_key_at(path: &str) -> io::Result<UrlKey> {
    let name = wide(path);
    let mut key: HKEY = null_mut();
    // SAFETY: `name` is NUL-terminated; `key` receives an open key on success.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            name.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    let key = match status {
        ERROR_SUCCESS => Key(key),
        ERROR_FILE_NOT_FOUND => return Ok(UrlKey::Absent),
        ERROR_ACCESS_DENIED => return Ok(UrlKey::Other),
        e => return Err(io::Error::from_raw_os_error(e as i32)),
    };
    let command = wide(URL_COMMAND_KEY);
    let flags = RRF_RT_REG_SZ | RRF_NOEXPAND;
    for _ in 0..URL_COMMAND_READS {
        let mut size = 0u32;
        // SAFETY: `key` is open with KEY_QUERY_VALUE; `command` is
        // NUL-terminated; the default value's size only: no type, no buffer.
        let status = unsafe {
            RegGetValueW(
                key.0,
                command.as_ptr(),
                null(),
                flags,
                null_mut(),
                null_mut(),
                &mut size,
            )
        };
        match status {
            ERROR_SUCCESS => {}
            ERROR_FILE_NOT_FOUND | ERROR_UNSUPPORTED_TYPE | ERROR_ACCESS_DENIED => {
                return Ok(UrlKey::Other);
            }
            e => return Err(io::Error::from_raw_os_error(e as i32)),
        }
        if !(2..=URL_COMMAND_MAX).contains(&size) || !size.is_multiple_of(2) {
            return Ok(UrlKey::Other);
        }
        let mut units = vec![0u16; size as usize / 2];
        let mut read = size;
        // SAFETY: as above; `units` is writable for `read` bytes; no type
        // asked.
        let status = unsafe {
            RegGetValueW(
                key.0,
                command.as_ptr(),
                null(),
                flags,
                null_mut(),
                units.as_mut_ptr().cast::<c_void>(),
                &mut read,
            )
        };
        match status {
            ERROR_SUCCESS => {
                if read > size || !read.is_multiple_of(2) {
                    return Ok(UrlKey::Other);
                }
                units.truncate(read as usize / 2);
                let end = units
                    .iter()
                    .rposition(|unit| *unit != 0)
                    .map_or(0, |at| at + 1);
                units.truncate(end);
                return Ok(String::from_utf16(&units).map_or(UrlKey::Other, UrlKey::Command));
            }
            ERROR_MORE_DATA => {}
            ERROR_FILE_NOT_FOUND | ERROR_UNSUPPORTED_TYPE | ERROR_ACCESS_DENIED => {
                return Ok(UrlKey::Other);
            }
            e => return Err(io::Error::from_raw_os_error(e as i32)),
        }
    }
    Ok(UrlKey::Other)
}

/// Write this user's registration of `tornect:` links at `HKCU\<path>`
/// (design `invite` §4.5): the key, created by this call or nothing is
/// written ([`URL_KEY_APPEARED`]: one that is there, whoever made it, is
/// never written to); its default value [`URL_SCHEME_NAME`] and an empty
/// `URL Protocol`; then `shell\open\command` with `command` as its default
/// value. A failure after the key was created deletes it again with all it
/// holds.
fn write_url_key_at(path: &str, command: &str) -> Result<(), InstallError> {
    let failed = |e: &dyn std::fmt::Display| {
        InstallError::Failed(format!("writing HKEY_CURRENT_USER\\{path}: {e}"))
    };
    let (key, disposition) =
        create_key(HKEY_CURRENT_USER, path, KEY_SET_VALUE | KEY_CREATE_SUB_KEY)
            .map_err(|e| failed(&e))?;
    if disposition != REG_CREATED_NEW_KEY {
        // There since the check before the dialog: not Tornect's to write.
        return Err(InstallError::Refused(URL_KEY_APPEARED.to_owned()));
    }
    let written = (|| {
        set_string(&key, None, URL_SCHEME_NAME)?;
        set_string(&key, Some("URL Protocol"), "")?;
        let (open, _) = create_key(key.0, URL_COMMAND_KEY, KEY_SET_VALUE)?;
        set_string(&open, None, command)
    })();
    // Closed before a delete.
    drop(key);
    let Err(e) = written else {
        return Ok(());
    };
    match delete_key_tree_at(path) {
        Ok(()) => Err(failed(&e)),
        Err(left) => Err(failed(&format!(
            "{e}; deleting the key it created again failed too ({left}), so it is left half \
             written"
        ))),
    }
}

/// Delete `HKCU\<path>` with everything under it: `RegDeleteTreeW` with the
/// subkey's name, then `RegDeleteKeyW` for the key itself in case the tree
/// delete left it (Microsoft does not say whether it does; Wine deletes it,
/// `docs/research/links.md` §4.3). A key that is not there, at either call,
/// is no error.
fn delete_key_tree_at(path: &str) -> io::Result<()> {
    let name = wide(path);
    // SAFETY: HKEY_CURRENT_USER is a predefined key, which RegDeleteTreeW
    // takes as it is; `name` is NUL-terminated.
    let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, name.as_ptr()) };
    if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    // SAFETY: as above.
    let status = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, name.as_ptr()) };
    if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// Delete `path`, an entry of the install folder other than the installed
/// copy, at once: a file, a folder with what it holds, or a link (a
/// junction, a mount point or a symbolic link) as a link, never followed.
/// The installed copy's restart step, elevated.
pub fn delete_in_folder(path: &str) -> Result<(), InstallError> {
    let failed = |e: io::Error| InstallError::Failed(format!("removing {path}: {e}"));
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated; the attributes of `path` itself.
    let attributes = unsafe { GetFileAttributesW(name.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(failed(io::Error::last_os_error()));
    }
    let directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let link = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    match (link, directory) {
        // The link itself: `remove_dir` and `remove_file` never follow one.
        (true, true) => std::fs::remove_dir(path),
        (_, false) => std::fs::remove_file(path),
        // `remove_dir_all` removes a link inside as a link, never its target.
        (false, true) => std::fs::remove_dir_all(path),
    }
    .map_err(failed)
}

/// Mark `path` for removal at the next restart
/// (`MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)`, which needs
/// administrator rights): the installed copy's restart step, elevated, for
/// the copy and then its folder.
pub fn mark_for_removal_at_restart(path: &str) -> Result<(), InstallError> {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated; no new name: a delete at the restart.
    if unsafe { MoveFileExW(name.as_ptr(), null(), MOVEFILE_DELAY_UNTIL_REBOOT) } == 0 {
        return Err(InstallError::Failed(format!(
            "marking {path} for removal at the next restart: {}",
            io::Error::last_os_error()
        )));
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
        // SAFETY: the key was opened by `RegOpenKeyExW` or `RegCreateKeyExW`
        // and is closed once.
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
        Elevated::RemoveAtRestart { folder } => format!(
            "The installed copy could not mark {folder} for removal at the next restart (exit \
             code {code}); it stays, and nothing points at it."
        ),
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

    fn hold_file(&self, path: &str) -> Result<Box<dyn io::Read + '_>, InstallError> {
        held_file(path)
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

    fn own_path(&self) -> Result<String, InstallError> {
        own_path()
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

    fn url_handler(&self) -> Result<UrlKey, InstallError> {
        url_key_at(URL_SCHEME_KEY).map_err(|e| {
            InstallError::Failed(format!("reading HKEY_CURRENT_USER\\{URL_SCHEME_KEY}: {e}"))
        })
    }

    fn write_url_handler(&self, command: &str) -> Result<(), InstallError> {
        write_url_key_at(URL_SCHEME_KEY, command)
    }

    fn remove_url_handler(&self) -> Result<(), InstallError> {
        delete_key_tree_at(URL_SCHEME_KEY).map_err(|e| {
            InstallError::Failed(format!("removing HKEY_CURRENT_USER\\{URL_SCHEME_KEY}: {e}"))
        })
    }
}

/// Whether what this process writes goes anywhere: to the console it was started from
/// (attached at the start, `crate::attach_parent_console`), or to an output redirected to a
/// file or a pipe. `tornect.exe` is a window-subsystem program, so one started with neither,
/// as Apps and features starts the uninstall entry's command, writes its lines nowhere
/// (§B.1.1).
#[must_use]
pub fn has_output() -> bool {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};
    // SAFETY: plain call.
    let out = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    !out.is_null() && out != INVALID_HANDLE_VALUE
}

/// Show `text` in one message box titled "Tornect", with a warning icon when `warning` (an
/// error or a refusal), and wait until it is closed: what `tornect install` and `tornect
/// uninstall` said where nothing else shows it (§B.1.1).
pub fn show_message(text: &str, warning: bool) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND, MessageBoxW,
    };
    let text = wide(text);
    let title = wide("Tornect");
    let icon = if warning {
        MB_ICONWARNING
    } else {
        MB_ICONINFORMATION
    };
    // SAFETY: both strings are NUL-terminated and outlive the call; no owner window.
    unsafe {
        MessageBoxW(
            null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | icon | MB_SETFOREGROUND,
        )
    };
}

/// The link registration's calls on real registry keys (run under Wine here,
/// and on Windows), each test on a key of its own under
/// `HKEY_CURRENT_USER\Software\TornectTest`, never on a registration of
/// `tornect:` links; what a test leaves is deleted when it ends. The hold of
/// a file on a file of the test's own.
#[cfg(test)]
mod tests {
    use windows_sys::Win32::System::Registry::{REG_DWORD, REG_EXPAND_SZ, REG_VALUE_TYPE};

    use super::*;

    /// Where every test key is.
    const TEST_ROOT: &str = "Software\\TornectTest";

    /// A key of the test's own, `<TEST_ROOT>\<pid>-<name>\tornect`, and its
    /// parent, deleted with what it holds before the test and after it.
    struct TestKey {
        parent: String,
        path: String,
    }

    impl TestKey {
        fn new(name: &str) -> Self {
            let parent = format!("{TEST_ROOT}\\{}-{name}", std::process::id());
            let _ = delete_key_tree_at(&parent);
            Self {
                path: format!("{parent}\\tornect"),
                parent,
            }
        }

        fn command_key(&self) -> String {
            format!("{}\\{URL_COMMAND_KEY}", self.path)
        }
    }

    impl Drop for TestKey {
        fn drop(&mut self) {
            let _ = delete_key_tree_at(&self.parent);
            let root = wide(TEST_ROOT);
            // SAFETY: a predefined key and a NUL-terminated name; the root
            // goes only once no other test holds a key under it (else the
            // call fails, and the result is not needed).
            unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, root.as_ptr()) };
        }
    }

    /// The string value `name` (`None`: the default value) of `HKCU\<path>`,
    /// without its trailing NULs; `None` when it cannot be read.
    fn read_string(path: &str, name: Option<&str>) -> Option<String> {
        let path = wide(path);
        let name = name.map(wide);
        let mut units = vec![0u16; 1024];
        let mut size = u32::try_from(units.len() * 2).unwrap();
        // SAFETY: a predefined key; the path NUL-terminated, the name
        // NUL-terminated or null; `units` is writable for `size` bytes.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                name.as_ref().map_or(null(), |n| n.as_ptr()),
                RRF_RT_REG_SZ,
                null_mut(),
                units.as_mut_ptr().cast::<c_void>(),
                &mut size,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        units.truncate(size as usize / 2);
        while units.last() == Some(&0) {
            units.pop();
        }
        Some(String::from_utf16(&units).unwrap())
    }

    /// Set the default value of `key` to `data` as type `kind`.
    fn set_raw(key: &Key, kind: REG_VALUE_TYPE, data: &[u8]) {
        // SAFETY: `key` is open with KEY_SET_VALUE; `data` is `data.len()`
        // bytes; the default value (no name).
        let status = unsafe {
            RegSetValueExW(
                key.0,
                null(),
                0,
                kind,
                data.as_ptr(),
                u32::try_from(data.len()).unwrap(),
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
    }

    /// `text` as a NUL-terminated UTF-16 value, in bytes.
    fn utf16_bytes(text: &str) -> Vec<u8> {
        wide(text)
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    }

    /// Design `invite` §4.5: an absent key reads `Absent`; a write creates
    /// it with exactly its name, an empty `URL Protocol` and the command,
    /// which reads back as it was written; a second write finds the key there
    /// and writes nothing (the `REG_OPENED_EXISTING_KEY` refusal); the delete
    /// takes the key with all it holds, and a second delete is no error.
    #[test]
    fn a_link_registration_is_written_read_and_deleted() {
        let key = TestKey::new("roundtrip");
        assert_eq!(url_key_at(&key.path).unwrap(), UrlKey::Absent);
        let command = "\"C:\\Program Files\\Tornect\\tornect.exe\" open-link -- \"%1\"";
        write_url_key_at(&key.path, command).unwrap();
        assert_eq!(
            url_key_at(&key.path).unwrap(),
            UrlKey::Command(command.to_owned())
        );
        assert_eq!(
            read_string(&key.path, None).as_deref(),
            Some("URL:Tornect link")
        );
        assert_eq!(
            read_string(&key.path, Some("URL Protocol")).as_deref(),
            Some("")
        );
        assert_eq!(
            read_string(&key.command_key(), None).as_deref(),
            Some(command)
        );
        match write_url_key_at(&key.path, "\"C:\\Other\\other.exe\" \"%1\"") {
            Err(InstallError::Refused(why)) => assert_eq!(why, URL_KEY_APPEARED),
            other => panic!("written over: {other:?}"),
        }
        assert_eq!(
            url_key_at(&key.path).unwrap(),
            UrlKey::Command(command.to_owned())
        );
        delete_key_tree_at(&key.path).unwrap();
        assert_eq!(url_key_at(&key.path).unwrap(), UrlKey::Absent);
        assert_eq!(read_string(&key.path, None), None);
        delete_key_tree_at(&key.path).unwrap();
    }

    /// A key whose command cannot be read as one is `Other`, a registration
    /// left as it is: no `shell\open\command`, one without a default value,
    /// a `REG_EXPAND_SZ` command (never expanded, so never mistaken for
    /// Tornect's), a `REG_DWORD`, and a command longer than 4 KiB; a long
    /// command within the bound reads whole.
    #[test]
    fn a_key_without_a_readable_command_is_other() {
        let key = TestKey::new("other");
        let _ = create_key(HKEY_CURRENT_USER, &key.path, KEY_SET_VALUE).unwrap();
        assert_eq!(url_key_at(&key.path).unwrap(), UrlKey::Other);
        let (command, _) =
            create_key(HKEY_CURRENT_USER, &key.command_key(), KEY_SET_VALUE).unwrap();
        assert_eq!(url_key_at(&key.path).unwrap(), UrlKey::Other);
        set_raw(
            &command,
            REG_EXPAND_SZ,
            &utf16_bytes("\"%ProgramFiles%\\Tornect\\tornect.exe\" open-link -- \"%1\""),
        );
        assert_eq!(url_key_at(&key.path).unwrap(), UrlKey::Other);
        set_raw(&command, REG_DWORD, &1u32.to_le_bytes());
        assert_eq!(url_key_at(&key.path).unwrap(), UrlKey::Other);
        set_string(&command, None, &"x".repeat(3000)).unwrap();
        assert_eq!(url_key_at(&key.path).unwrap(), UrlKey::Other);
        let long = "x".repeat(1500);
        set_string(&command, None, &long).unwrap();
        assert_eq!(url_key_at(&key.path).unwrap(), UrlKey::Command(long));
    }

    /// A file the install holds (the lyrebird beside the image, decision
    /// M1-88 (2)) cannot be written, renamed or deleted while it is held,
    /// so nothing can be swapped in before the elevated copy reads it;
    /// another reader, as robocopy is, can still open it. Once let go it
    /// can be deleted.
    #[test]
    fn a_held_file_cannot_be_changed_renamed_or_deleted_but_can_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lyrebird.exe");
        std::fs::write(&path, b"MZ the bridge helper").unwrap();
        let text = path.to_str().unwrap();
        let windows = RealWindows::of_this_computer();
        let mut held = windows.hold_file(text).unwrap();
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, dir.path().join("moved.exe")).is_err());
        assert!(std::fs::remove_file(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"MZ the bridge helper");
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut held, &mut bytes).unwrap();
        assert_eq!(bytes, b"MZ the bridge helper");
        drop(held);
        std::fs::remove_file(&path).unwrap();
    }
}
