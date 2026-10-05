//! The Win32 calls behind [`crate::autostart`] (the task's paths, SID and UAC
//! prompt), [`crate::reauth`] (the secure credential prompt and `LogonUserW`)
//! and the process-wide DLL search restriction. Every `unsafe` block is a
//! plain FFI call whose preconditions are stated next to it; the logic that
//! decides what to do with the answers lives in the cross-platform modules,
//! where it is tested on every OS.
#![allow(unsafe_code)]

use std::ffi::{CStr, OsStr, OsString, c_void};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, ERROR_LOGON_FAILURE, FreeLibrary, GetLastError, HANDLE, HLOCAL,
    HMODULE, LocalFree, NO_ERROR,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_PACK_FLAGS, CRED_PACK_PROTECTED_CREDENTIALS, CREDUI_INFOW,
    CREDUI_MAX_DOMAIN_TARGET_LENGTH, CREDUI_MAX_USERNAME_LENGTH, CREDUIWIN_FLAGS,
    CREDUIWIN_SECURE_PROMPT,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, EqualSid, GetTokenInformation,
    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW, LookupAccountNameW,
    SECURITY_MAX_SID_SIZE, SID_NAME_USE, TOKEN_ELEVATION_TYPE, TOKEN_LINKED_TOKEN, TOKEN_QUERY,
    TOKEN_USER, TokenElevationType, TokenElevationTypeFull, TokenElevationTypeLimited,
    TokenLinkedToken, TokenUser, WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW, SetDefaultDllDirectories,
};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_ProgramFiles, FOLDERID_Programs,
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, SHGetKnownFolderPath,
    ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows_sys::core::{BOOL, PWSTR};

/// Attach to the parent's console when the standard output has no handle
/// (a window-subsystem program started from a terminal); a redirected
/// output keeps its handle. Fails harmlessly without a parent console.
pub(crate) fn attach_parent_console() {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_OUTPUT_HANDLE,
    };
    // SAFETY: plain call.
    let out = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if !out.is_null() && out != INVALID_HANDLE_VALUE {
        return;
    }
    // SAFETY: plain call.
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
}

/// `s` as a NUL-terminated UTF-16 string.
pub(crate) fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// Restrict every run-time DLL load of this process that names no folder to
/// the system directory: `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`
/// (review finding E2-4). Such a load then never searches the executable's
/// folder, the current directory or `PATH`. Load-time imports are resolved
/// before `main` and are not affected (see `CredUi`).
pub(crate) fn restrict_dll_search() -> std::io::Result<()> {
    // SAFETY: plain call with one of the documented flag values.
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// A DLL loaded at run time from the system directory, freed on drop.
struct SystemModule {
    handle: HMODULE,
    name: &'static str,
}

impl SystemModule {
    /// `name` from the system directory only: `LOAD_LIBRARY_SEARCH_SYSTEM32`
    /// covers the DLL's own dependencies too, and never searches the
    /// executable's folder, the current directory or `PATH` (review note P-2).
    fn load(name: &'static str) -> std::io::Result<Self> {
        let file = wide(name);
        // SAFETY: `file` is NUL-terminated and outlives the call; the reserved
        // file handle is null, as the API requires.
        let handle =
            unsafe { LoadLibraryExW(file.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { handle, name })
    }

    /// The address of the export `symbol`.
    fn export(&self, symbol: &CStr) -> std::io::Result<unsafe extern "system" fn() -> isize> {
        // SAFETY: `self.handle` is a module loaded by `load` and freed only on
        // drop; `symbol` is NUL-terminated and outlives the call.
        unsafe { GetProcAddress(self.handle, symbol.as_ptr().cast()) }.ok_or_else(|| {
            std::io::Error::other(format!(
                "{} has no export {}: {}",
                self.name,
                symbol.to_string_lossy(),
                std::io::Error::last_os_error()
            ))
        })
    }
}

impl Drop for SystemModule {
    fn drop(&mut self) {
        // SAFETY: the module was loaded by `load` and is freed exactly once,
        // here; its owner drops it after its last call into it.
        unsafe { FreeLibrary(self.handle) };
    }
}

/// A handle closed on drop.
pub(crate) struct OwnedHandle(pub(crate) HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle was returned open by the call that filled it and
            // is closed exactly once, here.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// The Windows system directory (`C:\Windows\System32`), from the OS rather
/// than from `%SystemRoot%` or `PATH`.
pub(crate) fn system_directory() -> std::io::Result<PathBuf> {
    let mut buf = vec![0u16; 260];
    loop {
        let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `buf` is writable for `cap` UTF-16 units; the call writes at
        // most that many and returns the length written (without the NUL), or
        // the size needed (with it) when the buffer is too small.
        let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), cap) } as usize;
        if n == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n < buf.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buf[..n])));
        }
        buf.resize(n, 0);
    }
}

/// The folders Tornect asks the OS for.
#[derive(Debug, Clone, Copy)]
pub(crate) enum KnownFolder {
    /// `FOLDERID_Profile`: `C:\Users\<name>`.
    Profile,
    /// `FOLDERID_ProgramFiles`: `C:\Program Files` for this 64-bit program.
    ProgramFiles,
    /// `FOLDERID_LocalAppData`: `C:\Users\<name>\AppData\Local`.
    LocalAppData,
    /// `FOLDERID_Programs`: this user's Start-menu programs folder.
    Programs,
}

/// A known folder of this user, from the OS (`SHGetKnownFolderPath`) rather
/// than from the environment, which whoever starts Tornect controls (review
/// finding F1-4).
pub(crate) fn known_folder(which: KnownFolder) -> std::io::Result<PathBuf> {
    let id = match which {
        KnownFolder::Profile => &FOLDERID_Profile,
        KnownFolder::ProgramFiles => &FOLDERID_ProgramFiles,
        KnownFolder::LocalAppData => &FOLDERID_LocalAppData,
        KnownFolder::Programs => &FOLDERID_Programs,
    };
    let mut path: *mut u16 = null_mut();
    // SAFETY: `id` points to a constant GUID; no flags; a null token means
    // this process's user; `path` receives a `CoTaskMemAlloc` string, or
    // null.
    let hr = unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut path) };
    let found = if hr >= 0 && !path.is_null() {
        // SAFETY: on success `path` is NUL-terminated; count up to the NUL.
        let len = (0..).take_while(|&i| unsafe { *path.add(i) } != 0).count();
        // SAFETY: `len` units precede the NUL, all initialized.
        let units = unsafe { std::slice::from_raw_parts(path, len) };
        Ok(PathBuf::from(OsString::from_wide(units)))
    } else {
        Err(std::io::Error::other(format!(
            "SHGetKnownFolderPath failed: HRESULT {hr:#010x}"
        )))
    };
    // SAFETY: the API requires the string freed even when it fails; null is
    // accepted; freed exactly once, after its last use above.
    unsafe { CoTaskMemFree(path.cast()) };
    found
}

/// The `TOKEN_USER` of `token`, in a buffer the caller keeps alive while it
/// reads the SID inside.
pub(crate) fn token_user(token: HANDLE) -> std::io::Result<Vec<u64>> {
    let mut needed = 0u32;
    // SAFETY: a size query: no buffer, the needed size written to `needed`.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // u64 elements: the SID inside is read through a pointer, so keep the
    // buffer aligned for `TOKEN_USER`.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    let len = u32::try_from(buf.len() * 8).unwrap_or(u32::MAX);
    // SAFETY: `buf` is writable for `len` bytes, at least `needed`.
    let ok =
        unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut needed) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(buf)
}

/// The SID in a buffer filled by [`token_user`].
pub(crate) fn sid_of(token_user: &[u64]) -> *mut c_void {
    // SAFETY: `token_user` holds a `TOKEN_USER` written by `GetTokenInformation`
    // and is 8-byte aligned; reading its first field is in bounds.
    unsafe { (*token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
}

/// This process's access token, for queries.
pub(crate) fn process_token() -> std::io::Result<OwnedHandle> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
    // closing; `token` receives a real handle on success.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(OwnedHandle(token))
}

/// Whether this account is an administrator, counting the filtered token an
/// administrator's programs get under UAC (slice-F review §3.2, decided
/// 2026-09-24: the elevated task was refused to a standard account; the
/// administrator helper's pipe reads it too).
///
/// `CheckTokenMembership` against the well-known Administrators SID
/// (`WinBuiltinAdministratorsSid`; domain and nested memberships reach it
/// through the token's groups) answers the question, but in a filtered token
/// that group is deny-only, so it would say no for every administrator not
/// running elevated. `TokenElevationType` tells the cases apart: `Limited` is
/// the filtered half of a split token, whose linked token is the full one, and
/// that one is asked; `Full` (running elevated) and `Default` (a standard
/// account, or any account with UAC off) ask the process token itself. The
/// elevation type alone would not do: `Default` is both a standard account
/// and an administrator with UAC off, and `Limited` also covers the filtered
/// tokens of groups such as Backup Operators, who are not administrators.
pub(crate) fn is_administrator() -> std::io::Result<bool> {
    let token = process_token()?;
    let mut kind: TOKEN_ELEVATION_TYPE = 0;
    let mut len = 0u32;
    // SAFETY: `kind` is writable for the size passed; `len` receives the
    // size written.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevationType,
            (&raw mut kind).cast(),
            u32::try_from(size_of::<TOKEN_ELEVATION_TYPE>()).unwrap_or(0),
            &mut len,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let linked = if kind == TokenElevationTypeLimited {
        let mut info = TOKEN_LINKED_TOKEN {
            LinkedToken: null_mut(),
        };
        // SAFETY: as above, for a `TOKEN_LINKED_TOKEN`; on success its handle
        // is open and owned here (closed by `OwnedHandle`).
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenLinkedToken,
                (&raw mut info).cast(),
                u32::try_from(size_of::<TOKEN_LINKED_TOKEN>()).unwrap_or(0),
                &mut len,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Some(OwnedHandle(info.LinkedToken))
    } else {
        None
    };
    // A SID's sub-authorities are `u32`s: keep the buffer aligned for them.
    let mut sid = [0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)];
    let mut sid_len = SECURITY_MAX_SID_SIZE;
    // SAFETY: `sid` is writable for `sid_len` bytes, the largest a SID takes;
    // a builtin alias needs no domain SID.
    let ok = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            null_mut(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut member: BOOL = 0;
    // SAFETY: the token is the linked one (an identification-level
    // impersonation token, which the call accepts) or null (the calling
    // thread's token, duplicated for the call); `sid` holds the SID written
    // above; `member` is a live local.
    let ok = unsafe {
        CheckTokenMembership(
            linked.as_ref().map_or(null_mut(), |t| t.0),
            sid.as_mut_ptr().cast(),
            &mut member,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(member != 0)
}

/// The UAC values of the session levels (§B.2.1), read from
/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` with
/// `RegGetValueW`, `REG_DWORD` only. A value that is absent, of another type
/// or unreadable is `None`: Windows' default applies (NEEDS-DEVICE(windows)).
pub(crate) struct PolicyRegistry;

/// The first read of the five UAC values that failed for another reason
/// than the value being absent (`ERROR_FILE_NOT_FOUND`, which takes Windows'
/// default); `None` when every value was read or is absent (M-UI-3 review
/// F-12: an unreadable value never falls back to UAC's defaults).
pub(crate) fn policy_unreadable() -> Option<std::io::Error> {
    use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
    let key = wide(crate::levels::POLICY_KEY);
    for name in crate::levels::POLICY_VALUES {
        let value = wide(name);
        let mut data = 0u32;
        let mut size = u32::try_from(size_of::<u32>()).unwrap_or(4);
        // SAFETY: as in `PolicyRegistry::dword`.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_DWORD,
                null_mut(),
                (&raw mut data).cast(),
                &mut size,
            )
        };
        if status != NO_ERROR && status != ERROR_FILE_NOT_FOUND {
            return Some(std::io::Error::from_raw_os_error(status as i32));
        }
    }
    None
}

impl crate::levels::PolicyValues for PolicyRegistry {
    fn dword(&self, name: &str) -> Option<u32> {
        let key = wide(crate::levels::POLICY_KEY);
        let value = wide(name);
        let mut data = 0u32;
        let mut size = u32::try_from(size_of::<u32>()).unwrap_or(4);
        // SAFETY: both names are NUL-terminated UTF-16 buffers that outlive
        // the call; `data` is writable for `size` bytes; no type is asked
        // for (null), and `RRF_RT_REG_DWORD` refuses any other type.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_DWORD,
                null_mut(),
                (&raw mut data).cast(),
                &mut size,
            )
        };
        (status == NO_ERROR).then_some(data)
    }
}

/// The account facts of the session levels (§B.2.1): whether the executable
/// lies under Program Files, whether the account is an administrator (see
/// [`is_administrator`]), whether it is the built-in Administrator (a local
/// account SID ending in RID 500), and whether this process runs elevated
/// (`TokenElevationTypeFull`: the full half of a split token).
pub(crate) fn level_account() -> Result<crate::levels::Account, crate::levels::Unreadable> {
    let blind = |error| crate::levels::Unreadable {
        elevated: None,
        error,
    };
    let token = process_token().map_err(blind)?;
    let mut kind: TOKEN_ELEVATION_TYPE = 0;
    let mut len = 0u32;
    // SAFETY: `kind` is writable for the size passed; `len` receives the
    // size written.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevationType,
            (&raw mut kind).cast(),
            u32::try_from(size_of::<TOKEN_ELEVATION_TYPE>()).unwrap_or(0),
            &mut len,
        )
    };
    if ok == 0 {
        return Err(blind(std::io::Error::last_os_error()));
    }
    let elevated = kind == TokenElevationTypeFull;
    // From here on a failure still says whether this process runs elevated.
    let rest = || -> std::io::Result<crate::levels::Account> {
        let sid = current_user_sid()?;
        let exe = std::env::current_exe()?;
        let program_files = known_folder(KnownFolder::ProgramFiles)?;
        let installed = match (exe.to_str(), program_files.to_str()) {
            (Some(exe), Some(folder)) => {
                crate::autostart::location_under(exe, &[folder.to_owned()])
            }
            _ => false,
        };
        Ok(crate::levels::Account {
            installed,
            administrator: is_administrator()?,
            builtin_administrator: sid.starts_with("S-1-5-21-") && sid.ends_with("-500"),
            elevated,
        })
    };
    rest().map_err(|error| crate::levels::Unreadable {
        elevated: Some(elevated),
        error,
    })
}

/// This process's user, as a string SID (`S-1-5-21-…`).
pub(crate) fn current_user_sid() -> std::io::Result<String> {
    let token = process_token()?;
    let user = token_user(token.0)?;
    sid_string(sid_of(&user))
}

/// The string SID of the account `name` as `LookupAccountNameW` resolves it
/// (`DOMAIN\user` and the other forms it takes), for a task's principal that
/// the Task Scheduler prints as a name.
pub(crate) fn sid_of_account_name(name: &str) -> std::io::Result<String> {
    let name = wide(name);
    let mut sid_len = 0u32;
    let mut domain_len = 0u32;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: a size query: null buffers with zero lengths; the sizes needed
    // are written to `sid_len` and `domain_len`; `name` is NUL-terminated.
    unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            null_mut(),
            &mut sid_len,
            null_mut(),
            &mut domain_len,
            &mut kind,
        )
    };
    if sid_len == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // A SID's sub-authorities are `u32`s: keep the buffer aligned for them.
    let mut sid = vec![0u32; (sid_len as usize).div_ceil(4)];
    let mut domain = vec![0u16; domain_len as usize + 1];
    let mut domain_len = u32::try_from(domain.len()).unwrap_or(0);
    // SAFETY: `sid` is writable for at least `sid_len` bytes and `domain` for
    // `domain_len` characters; `name` is NUL-terminated; all outlive the call.
    let ok = unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    sid_string(sid.as_mut_ptr().cast())
}

/// `sid` as a string (`S-1-…`).
pub(crate) fn sid_string(sid: *mut c_void) -> std::io::Result<String> {
    let mut text: *mut u16 = null_mut();
    // SAFETY: the caller's `sid` is a valid SID alive for this call; on
    // success `text` is a NUL-terminated string allocated with `LocalAlloc`.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut text) };
    if ok == 0 || text.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `text` is NUL-terminated (above); count up to the NUL.
    let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    // SAFETY: `len` units precede the NUL, all initialized.
    let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
    // SAFETY: `text` came from `LocalAlloc` inside the call and is freed once.
    unsafe { LocalFree(text as HLOCAL) };
    Ok(sid)
}

/// Why an elevated run did not happen.
#[derive(Debug)]
pub(crate) enum ElevateError {
    /// The user dismissed the UAC prompt.
    Cancelled,
    /// Anything else.
    Failed(String),
}

/// Run `exe` with `params` through the UAC prompt (`ShellExecuteExW`, verb
/// `runas`), hidden, and wait for its exit code.
pub(crate) fn run_elevated(exe: &Path, params: &str) -> Result<u32, ElevateError> {
    let verb = wide("runas");
    let file = wide(exe);
    let params = wide(params);
    // SAFETY: plain call; balanced by `CoUninitialize` below when it succeeds.
    // ShellExecuteEx may hand the verb to COM-based shell extensions.
    let com = unsafe {
        CoInitializeEx(
            null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    // SAFETY: all-zero is a valid "unset" `SHELLEXECUTEINFOW` (null pointers
    // and handles, zero flags); the fields used are set below.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = u32::try_from(size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_HIDE;
    // SAFETY: `info` is initialized and its strings are NUL-terminated and
    // outlive the call.
    let ok = unsafe { ShellExecuteExW(&mut info) };
    // SAFETY: plain call.
    let err = unsafe { GetLastError() };
    if com >= 0 {
        // SAFETY: balances the successful `CoInitializeEx` above.
        unsafe { CoUninitialize() };
    }
    if ok == 0 {
        return Err(if err == ERROR_CANCELLED {
            ElevateError::Cancelled
        } else {
            ElevateError::Failed(format!("ShellExecuteExW(runas) failed: error {err}"))
        });
    }
    if info.hProcess.is_null() {
        return Err(ElevateError::Failed(
            "the elevated process gave no handle to wait on".to_owned(),
        ));
    }
    let process = OwnedHandle(info.hProcess);
    // SAFETY: `process.0` is the open handle `SEE_MASK_NOCLOSEPROCESS` returned.
    unsafe { WaitForSingleObject(process.0, INFINITE) };
    let mut code = 0u32;
    // SAFETY: as above; `code` receives the exit status.
    if unsafe { GetExitCodeProcess(process.0, &mut code) } == 0 {
        return Err(ElevateError::Failed(format!(
            "reading the elevated process's exit code: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(code)
}

/// A file created new under a random name in a directory the caller names,
/// and deleted on drop.
pub(crate) struct TempFile(PathBuf);

impl TempFile {
    /// Write `bytes` to a new `<dir>\<prefix>-<random><suffix>`.
    pub(crate) fn write(
        dir: &Path,
        prefix: &str,
        suffix: &str,
        bytes: &[u8],
    ) -> std::io::Result<Self> {
        use std::io::Write as _;
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(std::io::Error::other)?;
        let path = dir.join(format!(
            "{prefix}-{}{suffix}",
            data_encoding::HEXLOWER.encode(&nonce)
        ));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let file = Self(path);
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(file)
    }

    /// Where it is.
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Re-authentication: the secure credential prompt, then LogonUserW
// ---------------------------------------------------------------------------

use zeroize::{Zeroize as _, Zeroizing};

use crate::reauth::{
    CredentialPrompt, LogonCheck, LogonOutcome, PromptOutcome, PromptedCredential,
};

/// `CREDUI_MAX_PASSWORD_LENGTH` of `wincred.h` (not in `windows-sys`).
const MAX_PASSWORD_CHARS: usize = (CRED_MAX_CREDENTIAL_BLOB_SIZE / 2) as usize;

/// `CredUIPromptForWindowsCredentialsW`, as `credui.dll` exports it
/// (`wincred.h`; the declaration windows-sys generates for it).
type CredUiPromptFn = unsafe extern "system" fn(
    *const CREDUI_INFOW,
    u32,
    *mut u32,
    *const c_void,
    u32,
    *mut *mut c_void,
    *mut u32,
    *mut BOOL,
    CREDUIWIN_FLAGS,
) -> u32;

/// `CredUnPackAuthenticationBufferW`, as `credui.dll` exports it.
type CredUnpackFn = unsafe extern "system" fn(
    CRED_PACK_FLAGS,
    *const c_void,
    u32,
    PWSTR,
    *mut u32,
    PWSTR,
    *mut u32,
    PWSTR,
    *mut u32,
) -> BOOL;

/// CredUI's two entry points, from `credui.dll` loaded out of the system
/// directory for one prompt (review note P-2). As a load-time import the
/// loader resolved `credui.dll`, which is not a KnownDLL, from the
/// executable's folder first, before `main` could restrict anything, and it
/// was loaded into every `tornect.exe`, the start-at-login host included.
struct CredUi {
    prompt: CredUiPromptFn,
    unpack: CredUnpackFn,
    /// Freed last, when the prompt is done with the entry points above.
    _module: SystemModule,
}

impl CredUi {
    fn load() -> std::io::Result<Self> {
        let module = SystemModule::load("credui.dll")?;
        let prompt = module.export(c"CredUIPromptForWindowsCredentialsW")?;
        let unpack = module.export(c"CredUnPackAuthenticationBufferW")?;
        // SAFETY: the two exports have exactly these signatures (`wincred.h`),
        // and a function pointer becomes a function pointer of the same size.
        let (prompt, unpack) = unsafe {
            (
                std::mem::transmute::<unsafe extern "system" fn() -> isize, CredUiPromptFn>(prompt),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, CredUnpackFn>(unpack),
            )
        };
        Ok(Self {
            prompt,
            unpack,
            _module: module,
        })
    }
}

/// The prompt's output buffer: wiped, then freed with `CoTaskMemFree`.
struct CredBlob {
    ptr: *mut c_void,
    len: u32,
}

impl Drop for CredBlob {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        // SAFETY: `ptr` is the buffer `CredUIPromptForWindowsCredentialsW`
        // allocated with `CoTaskMemAlloc`, `len` bytes long, owned here alone.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.cast::<u8>(), self.len as usize) }
            .zeroize();
        // SAFETY: as above; freed exactly once.
        unsafe { CoTaskMemFree(self.ptr) };
    }
}

/// The UTF-16 before the first NUL.
fn until_nul(buf: &[u16]) -> &[u16] {
    &buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())]
}

/// `CredUIPromptForWindowsCredentialsW` with `CREDUIWIN_SECURE_PROMPT`: the
/// dialog runs on the secure desktop, like the UAC prompt.
pub(crate) struct SecurePrompt;

impl CredentialPrompt for SecurePrompt {
    fn prompt(&self, purpose: &str) -> PromptOutcome {
        let credui = match CredUi::load() {
            Ok(c) => c,
            Err(e) => {
                return PromptOutcome::Failed(format!(
                    "loading the Windows credential prompt (credui.dll from the system \
                     directory): {e}"
                ));
            }
        };
        let caption = wide("Tornect");
        let message = wide(format!("Tornect needs your Windows password to {purpose}."));
        let info = CREDUI_INFOW {
            cbSize: u32::try_from(size_of::<CREDUI_INFOW>()).unwrap_or(0),
            hwndParent: null_mut(),
            pszMessageText: message.as_ptr(),
            pszCaptionText: caption.as_ptr(),
            hbmBanner: null_mut(),
        };
        let mut package = 0u32;
        let mut out: *mut c_void = null_mut();
        let mut out_len = 0u32;
        let mut save = 0;
        // SAFETY: `info` and its strings outlive the call; no input buffer;
        // every out-pointer is a live local. The call blocks until the user
        // answers; on success `out` is a `CoTaskMemAlloc` buffer of `out_len`
        // bytes that `CredBlob` wipes and frees.
        let rc = unsafe {
            (credui.prompt)(
                &info,
                0,
                &mut package,
                null(),
                0,
                &mut out,
                &mut out_len,
                &mut save,
                CREDUIWIN_SECURE_PROMPT,
            )
        };
        let blob = CredBlob {
            ptr: out,
            len: out_len,
        };
        if rc == ERROR_CANCELLED {
            return PromptOutcome::Cancelled;
        }
        if rc != NO_ERROR || blob.ptr.is_null() {
            return PromptOutcome::Failed(format!(
                "the Windows credential prompt failed: error {rc}"
            ));
        }
        // Protected (encrypted) first, as the secure prompt returns it; then
        // plain, for a provider that returned it unprotected.
        let mut last = 0;
        for flags in [CRED_PACK_PROTECTED_CREDENTIALS, 0] {
            let mut user = vec![0u16; CREDUI_MAX_USERNAME_LENGTH as usize + 1];
            let mut domain = vec![0u16; CREDUI_MAX_DOMAIN_TARGET_LENGTH as usize + 1];
            let mut password = Zeroizing::new(vec![0u16; MAX_PASSWORD_CHARS + 1]);
            let mut user_len = u32::try_from(user.len()).unwrap_or(0);
            let mut domain_len = u32::try_from(domain.len()).unwrap_or(0);
            let mut password_len = u32::try_from(password.len()).unwrap_or(0);
            // SAFETY: `blob` is the prompt's buffer (above); each output buffer
            // is writable for the length passed with it, in characters.
            let ok = unsafe {
                (credui.unpack)(
                    flags,
                    blob.ptr,
                    blob.len,
                    user.as_mut_ptr(),
                    &mut user_len,
                    domain.as_mut_ptr(),
                    &mut domain_len,
                    password.as_mut_ptr(),
                    &mut password_len,
                )
            };
            if ok != 0 {
                return PromptOutcome::Entered(PromptedCredential::new(
                    String::from_utf16_lossy(until_nul(&user)),
                    String::from_utf16_lossy(until_nul(&domain)),
                    password,
                ));
            }
            // SAFETY: plain call.
            last = unsafe { GetLastError() };
        }
        PromptOutcome::Failed(format!(
            "reading the Windows credential prompt's answer failed: error {last}"
        ))
    }
}

/// `LogonUserW(LOGON32_LOGON_INTERACTIVE)`, then the logon token's user SID
/// compared with this process's.
pub(crate) struct LogonUserCheck;

impl LogonCheck for LogonUserCheck {
    fn verify(&self, credential: &PromptedCredential) -> LogonOutcome {
        let (user, domain) = crate::reauth::logon_names(credential.user(), credential.domain());
        let user = wide(user);
        let domain = domain.map(wide);
        let mut token: HANDLE = null_mut();
        // SAFETY: every string is NUL-terminated and outlives the call (the
        // password's buffer is the credential's, NUL-terminated by
        // `PromptedCredential::new`); `token` receives a handle on success.
        let ok = unsafe {
            LogonUserW(
                user.as_ptr(),
                domain.as_ref().map_or(null(), |d| d.as_ptr()),
                credential.password_wide().as_ptr(),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        };
        if ok == 0 {
            // SAFETY: plain call.
            let err = unsafe { GetLastError() };
            return if err == ERROR_LOGON_FAILURE {
                LogonOutcome::Rejected
            } else {
                LogonOutcome::Failed(format!("LogonUserW failed: error {err}"))
            };
        }
        let token = OwnedHandle(token);
        let theirs = match token_user(token.0) {
            Ok(t) => t,
            Err(e) => return LogonOutcome::Failed(format!("reading the logon's user: {e}")),
        };
        let ours = match process_token().and_then(|t| token_user(t.0)) {
            Ok(t) => t,
            Err(e) => return LogonOutcome::Failed(format!("reading this process's user: {e}")),
        };
        // SAFETY: both SIDs point into buffers alive for this call.
        if unsafe { EqualSid(sid_of(&theirs), sid_of(&ours)) } != 0 {
            LogonOutcome::CurrentUser
        } else {
            LogonOutcome::OtherUser
        }
    }
}
