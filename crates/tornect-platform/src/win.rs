//! The Win32 calls behind [`crate::autostart`] (and, later in this file, the
//! re-authentication prompt of [`crate::reauth`]). Every `unsafe` block is a
//! plain FFI call whose preconditions are stated next to it; the logic that
//! decides what to do with the answers lives in the cross-platform modules,
//! where it is tested on every OS.
#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString, c_void};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, GetLastError, HANDLE, HLOCAL, LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// `s` as a NUL-terminated UTF-16 string.
pub(crate) fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
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

/// This process's user, as a string SID (`S-1-5-21-…`).
pub(crate) fn current_user_sid() -> std::io::Result<String> {
    let token = process_token()?;
    let user = token_user(token.0)?;
    let mut text: *mut u16 = null_mut();
    // SAFETY: the SID points into `user`, alive for this call; on success
    // `text` is a NUL-terminated string allocated with `LocalAlloc`.
    let ok = unsafe { ConvertSidToStringSidW(sid_of(&user), &mut text) };
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

/// A file in this user's temporary directory, created new under a random name
/// and deleted on drop.
pub(crate) struct TempFile(PathBuf);

impl TempFile {
    /// Write `bytes` to a new `<prefix>-<random><suffix>`.
    pub(crate) fn write(prefix: &str, suffix: &str, bytes: &[u8]) -> std::io::Result<Self> {
        use std::io::Write as _;
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(std::io::Error::other)?;
        let path = std::env::temp_dir().join(format!(
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
