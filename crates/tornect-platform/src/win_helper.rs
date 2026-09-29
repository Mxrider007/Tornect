//! The Win32 calls behind [`crate::helper`] (§B.8.7.5): the per-session
//! named pipe with its explicit DACL, overlapped reads and writes (a read
//! pending on one thread never blocks a write on another), the process facts
//! both ends check, the UAC launch, the host-exit watch, the helper's
//! panic-chord hook, and the input desktop probe of §B.8.8. Every `unsafe`
//! block is one FFI call whose preconditions are stated next to it; the
//! decisions live in [`crate::helper`], tested on every system. Type-checked
//! on the build machine only: NEEDS-DEVICE(windows).
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_CANCELLED, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE,
    GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
    TokenElevation,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    GetFinalPathNameByHandleW, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_READOBJECTS, GetUserObjectInformationW, OpenInputDesktop, UOI_NAME,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentProcessId, GetProcessId, INFINITE, OpenProcess,
    OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    VK_CONTROL, VK_END, VK_LCONTROL, VK_LMENU, VK_MENU, VK_RCONTROL, VK_RMENU,
};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GetMessageW, HC_ACTION, KBDLLHOOKSTRUCT, LLKHF_INJECTED,
    LLKHF_LOWER_IL_INJECTED, MSG, SW_HIDE, SetWindowsHookExW, WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP,
    WM_SYSKEYDOWN, WM_SYSKEYUP,
};

use crate::helper::{ClientFacts, ServerFacts};
use crate::win::{OwnedHandle, wide};

/// One end of a helper pipe, opened for overlapped I/O: each read and each
/// write waits on its own event, so the reader thread's pending read never
/// holds up a write from another thread.
pub(crate) struct Pipe {
    handle: OwnedHandle,
}

// SAFETY: a pipe handle may be used from any thread; every call on it below
// passes its own OVERLAPPED and event.
unsafe impl Send for Pipe {}
// SAFETY: as above: concurrent overlapped calls on one handle are allowed.
unsafe impl Sync for Pipe {}

/// A manual-reset event, closed on drop.
fn event() -> std::io::Result<OwnedHandle> {
    // SAFETY: plain call: default security, manual reset, not signalled,
    // unnamed.
    let h = unsafe { CreateEventW(null(), 1, 0, null()) };
    if h.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(OwnedHandle(h))
}

impl Pipe {
    /// Run one overlapped call and wait for it; `op` issues the call with
    /// the OVERLAPPED it is given and returns its BOOL.
    fn overlapped(&self, op: impl FnOnce(*mut OVERLAPPED) -> i32) -> std::io::Result<u32> {
        let ev = event()?;
        // SAFETY: all-zero is a valid OVERLAPPED (offsets 0, no event).
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = ev.0;
        let ok = op(&raw mut ov);
        if ok == 0 {
            // SAFETY: plain call.
            let err = unsafe { GetLastError() };
            if err != ERROR_IO_PENDING {
                return Err(std::io::Error::from_raw_os_error(err as i32));
            }
        }
        let mut n = 0u32;
        // SAFETY: `ov` stays alive and unmoved until the wait returns, which
        // it does only when the operation completed or was cancelled.
        if unsafe { GetOverlappedResult(self.handle.0, &raw const ov, &mut n, 1) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n)
    }

    /// Read exactly one frame; `None` when the pipe closed before its first
    /// byte, an error for a frame cut short.
    pub(crate) fn read_frame(&self) -> std::io::Result<Option<[u8; 16]>> {
        let mut frame = [0u8; 16];
        let mut got = 0usize;
        while got < frame.len() {
            let want = u32::try_from(frame.len() - got).unwrap_or(0);
            let buf = frame[got..].as_mut_ptr();
            let read = self.overlapped(|ov| {
                // SAFETY: `buf` is writable for `want` bytes and outlives the
                // call and its wait (in `overlapped`).
                unsafe { ReadFile(self.handle.0, buf, want, null_mut(), ov) }
            });
            match read {
                Ok(0) | Err(_) if got == 0 => return Ok(None),
                Ok(0) | Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "a frame cut short",
                    ));
                }
                Ok(n) => got += n as usize,
            }
        }
        Ok(Some(frame))
    }

    /// Write one frame whole.
    pub(crate) fn write_frame(&self, frame: &[u8; 16]) -> std::io::Result<()> {
        let n = self.overlapped(|ov| {
            // SAFETY: `frame` is readable for 16 bytes and outlives the call
            // and its wait.
            unsafe { WriteFile(self.handle.0, frame.as_ptr(), 16, null_mut(), ov) }
        })?;
        if n == 16 {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "a frame written in part",
            ))
        }
    }

    /// End every read and write pending on this handle (they return an
    /// error); the handle itself closes on drop.
    pub(crate) fn cancel(&self) {
        // SAFETY: plain call on an open handle; a null OVERLAPPED cancels all
        // of this process's I/O on it.
        unsafe { CancelIoEx(self.handle.0, null()) };
    }

    /// Cancel what is pending and, on the server's end, disconnect the
    /// client (its reads then fail); on the client's end the disconnect
    /// fails harmlessly and the handle closes with the process.
    pub(crate) fn close(&self) {
        self.cancel();
        // SAFETY: plain call on an open handle.
        unsafe { DisconnectNamedPipe(self.handle.0) };
    }

    /// The server's process id, as the client sees it.
    fn server_pid(&self) -> std::io::Result<u32> {
        let mut pid = 0u32;
        // SAFETY: `pid` is writable.
        if unsafe { GetNamedPipeServerProcessId(self.handle.0, &mut pid) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(pid)
    }

    /// The client's process id, as the server sees it.
    fn client_pid(&self) -> std::io::Result<u32> {
        let mut pid = 0u32;
        // SAFETY: `pid` is writable.
        if unsafe { GetNamedPipeClientProcessId(self.handle.0, &mut pid) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(pid)
    }
}

/// A security descriptor made from SDDL, freed on drop.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    fn from_sddl(sddl: &str) -> std::io::Result<Self> {
        let text = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `text` is NUL-terminated; on success `sd` receives a
        // descriptor allocated with `LocalAlloc`, freed on drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 || sd.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(sd))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the conversion above, freed once.
        unsafe { LocalFree(self.0 as HLOCAL) };
    }
}

/// The host's pipe for one session (H4): an explicit DACL — this user, and
/// the Administrators group when `administrators` (the standard-account path,
/// where the helper runs as the administrator whose password was typed) —
/// never the default descriptor; one instance, created first
/// (`FILE_FLAG_FIRST_PIPE_INSTANCE`: a pipe that already exists fails the
/// creation); remote clients refused.
pub(crate) fn create_server(name: &str, administrators: bool) -> std::io::Result<Pipe> {
    let user = crate::win::current_user_sid()?;
    // Protected DACL (no inherited entries): full access for the user, and
    // for Administrators on the standard-account path; nobody else.
    let sddl = if administrators {
        format!("D:P(A;;GA;;;{user})(A;;GA;;;BA)")
    } else {
        format!("D:P(A;;GA;;;{user})")
    };
    let sd = Descriptor::from_sddl(&sddl)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let name = wide(name);
    // SAFETY: `name` is NUL-terminated; `sa` and the descriptor it points to
    // outlive the call; one instance, 4 KiB buffers.
    let h = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            &raw const sa,
        )
    };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Pipe {
        handle: OwnedHandle(h),
    })
}

/// Wait up to `wait` for the one client of `pipe`; `false` when none came
/// (the pending connect is cancelled).
pub(crate) fn accept(pipe: &Pipe, wait: Duration) -> std::io::Result<bool> {
    let ev = event()?;
    // SAFETY: all-zero is a valid OVERLAPPED.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = ev.0;
    // SAFETY: `ov` outlives the operation: it is waited for or cancelled and
    // then waited for below before it goes out of scope.
    let ok = unsafe { ConnectNamedPipe(pipe.handle.0, &raw mut ov) };
    if ok == 0 {
        // SAFETY: plain call.
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => return Ok(true),
            ERROR_IO_PENDING => {}
            err => return Err(std::io::Error::from_raw_os_error(err as i32)),
        }
    }
    let ms = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: `ev` is an open event handle.
    let waited = unsafe { WaitForSingleObject(ev.0, ms) };
    let mut n = 0u32;
    if waited != WAIT_OBJECT_0 {
        pipe.cancel();
        // SAFETY: waits for the cancelled operation to finish with `ov`.
        unsafe { GetOverlappedResult(pipe.handle.0, &raw const ov, &mut n, 1) };
        return Ok(false);
    }
    // SAFETY: the operation completed; this reads its result.
    Ok(unsafe { GetOverlappedResult(pipe.handle.0, &raw const ov, &mut n, 0) } != 0)
}

/// Open the host's pipe `name` as its client, for overlapped I/O, allowing
/// the server to identify this process but never to impersonate it
/// (`SECURITY_IDENTIFICATION`).
pub(crate) fn connect(name: &str) -> std::io::Result<Pipe> {
    let name = wide(name);
    // SAFETY: `name` is NUL-terminated; no security attributes, no template.
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Pipe {
        handle: OwnedHandle(h),
    })
}

/// A process opened for queries (and waiting), closed on drop.
fn open_process(pid: u32, rights: u32) -> std::io::Result<OwnedHandle> {
    // SAFETY: plain call; the handle is closed on drop.
    let h = unsafe { OpenProcess(rights, 0, pid) };
    if h.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(OwnedHandle(h))
}

/// The full path of `process`'s executable.
fn image_of(process: HANDLE) -> std::io::Result<String> {
    let mut buf = vec![0u16; 32768];
    let mut len = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: `buf` is writable for `len` characters; `len` receives the
    // length written.
    let ok = unsafe {
        QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

/// The Windows session `pid` runs in.
fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: `session` is writable.
    (unsafe { ProcessIdToSessionId(pid, &mut session) } != 0).then_some(session)
}

/// Whether `process`'s token is elevated (`TokenElevation`).
fn elevated(process: HANDLE) -> Option<bool> {
    let mut token: HANDLE = null_mut();
    // SAFETY: `token` receives an open handle on success, closed below.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let token = OwnedHandle(token);
    let mut info = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: `info` is writable for its size; `len` receives the size.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&raw mut info).cast(),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
            &mut len,
        )
    };
    (ok != 0).then_some(info.TokenIsElevated != 0)
}

/// What the host reads about its pipe's client.
pub(crate) fn client_facts(pipe: &Pipe) -> std::io::Result<ClientFacts> {
    let pid = pipe.client_pid()?;
    let process = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok();
    Ok(ClientFacts {
        pid,
        image: process.as_ref().and_then(|p| image_of(p.0).ok()),
        elevated: process.as_ref().and_then(|p| elevated(p.0)),
        session: session_of(pid),
    })
}

/// What the helper reads about its pipe's server.
pub(crate) fn server_facts(pipe: &Pipe) -> std::io::Result<ServerFacts> {
    let pid = pipe.server_pid()?;
    let process = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok();
    let image = process.as_ref().and_then(|p| image_of(p.0).ok());
    let same_file = image.as_deref().and_then(|theirs| {
        let mine = own_image().ok()?;
        Some(file_id(theirs).ok()? == file_id(&mine).ok()?)
    });
    Ok(ServerFacts {
        pid,
        image,
        session: session_of(pid),
        same_file,
    })
}

/// A file opened for its attributes only (no read, write or execute
/// access), sharing everything; closed on drop.
fn open_attributes(path: &str) -> std::io::Result<OwnedHandle> {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated; no security attributes, no template.
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(OwnedHandle(h))
}

/// The volume serial number and file index of `path`: the file itself,
/// whatever path reached it (review F-10).
fn file_id(path: &str) -> std::io::Result<(u32, u64)> {
    let file = open_attributes(path)?;
    // SAFETY: all-zero is a valid structure to fill.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `file` is open; `info` is writable.
    if unsafe { GetFileInformationByHandle(file.0, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

/// `path` as its open file resolves it (`GetFinalPathNameByHandleW`, the
/// DOS form, `\\?\` taken off): links, mount points and substituted
/// drives followed (review F-10).
pub(crate) fn final_path(path: &str) -> std::io::Result<String> {
    let file = open_attributes(path)?;
    let mut buf = vec![0u16; 32768];
    let cap = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: `buf` is writable for `cap` characters; flags 0 are
    // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS.
    let len = unsafe { GetFinalPathNameByHandleW(file.0, buf.as_mut_ptr(), cap, 0) };
    if len == 0 || len >= cap {
        return Err(std::io::Error::last_os_error());
    }
    let full = String::from_utf16_lossy(&buf[..len as usize]);
    Ok(match full.strip_prefix(r"\\?\UNC\") {
        Some(unc) => format!(r"\\{unc}"),
        None => full.strip_prefix(r"\\?\").unwrap_or(&full).to_owned(),
    })
}

/// This process's executable, its session and id.
pub(crate) fn own_image() -> std::io::Result<String> {
    // SAFETY: `GetCurrentProcess` is a pseudo-handle that needs no closing.
    image_of(unsafe { GetCurrentProcess() })
}

/// This process's Windows session.
pub(crate) fn own_session() -> std::io::Result<u32> {
    // SAFETY: plain call.
    session_of(unsafe { GetCurrentProcessId() }).ok_or_else(std::io::Error::last_os_error)
}

/// This process's id.
pub(crate) fn own_pid() -> u32 {
    // SAFETY: plain call.
    unsafe { GetCurrentProcessId() }
}

/// Call `exited` once process `pid` has exited (a thread waits on its
/// handle); `Err` when it cannot be opened (it may be gone already).
pub(crate) fn when_exits(pid: u32, exited: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    /// A process handle moved to the waiting thread.
    struct Waited(OwnedHandle);
    // SAFETY: a process handle may be waited on from any thread.
    unsafe impl Send for Waited {}
    let process = Waited(open_process(pid, PROCESS_SYNCHRONIZE)?);
    std::thread::Builder::new()
        .name("host-exit".to_owned())
        .spawn(move || {
            let process = process;
            // SAFETY: `process` is an open handle with SYNCHRONIZE, closed
            // when this thread drops it after the wait.
            unsafe { WaitForSingleObject(process.0.0, INFINITE) };
            exited();
        })?;
    Ok(())
}

/// A process started through Windows' prompt.
pub(crate) struct Launched {
    process: OwnedHandle,
    /// Its id.
    pub(crate) pid: u32,
}

// SAFETY: a process handle may be used from any thread.
unsafe impl Send for Launched {}

impl Launched {
    /// End it (best effort: whether a handle from an elevated launch carries
    /// the right to terminate is NEEDS-DEVICE(windows); the helper also ends
    /// itself at the pipe's close and the missed heartbeat).
    pub(crate) fn terminate(&self) {
        // SAFETY: plain call on the handle `ShellExecuteExW` returned.
        unsafe { TerminateProcess(self.process.0, 1) };
    }
}

/// Why an elevated launch did not happen.
#[derive(Debug)]
pub(crate) enum LaunchError {
    /// The person cancelled Windows' prompt.
    Cancelled,
    /// Anything else (a wrong password, policy, the file).
    Failed(String),
}

/// Start `exe` with `params` through Windows' prompt (`ShellExecuteExW`,
/// verb `runas`), hidden, without waiting for it: the call returns once the
/// prompt was answered and the process started.
pub(crate) fn start_elevated(exe: &Path, params: &str) -> Result<Launched, LaunchError> {
    let verb = wide("runas");
    let file = wide(exe);
    let params = wide(params);
    // SAFETY: plain call; balanced by `CoUninitialize` below when it succeeds.
    let com = unsafe {
        CoInitializeEx(
            null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    // SAFETY: all-zero is a valid "unset" `SHELLEXECUTEINFOW`.
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
            LaunchError::Cancelled
        } else {
            LaunchError::Failed(format!("ShellExecuteExW(runas) failed: error {err}"))
        });
    }
    if info.hProcess.is_null() {
        return Err(LaunchError::Failed(
            "Windows gave no handle for the started helper".to_owned(),
        ));
    }
    let process = OwnedHandle(info.hProcess);
    // SAFETY: plain call on the open handle.
    let pid = unsafe { GetProcessId(process.0) };
    Ok(Launched { process, pid })
}

/// The panic chord's state in the hook: only whether Ctrl and Alt are down.
static CTRL: AtomicBool = AtomicBool::new(false);
static ALT: AtomicBool = AtomicBool::new(false);
/// Told once when the chord is pressed.
static PANIC: Mutex<Option<Box<dyn FnOnce() + Send>>> = Mutex::new(None);

/// The helper's own watch for the physical panic chord Ctrl+Alt+End
/// (§B.8.7.5, amendment §1.10 (a)): a low-level keyboard hook on its own
/// thread, run by the elevated helper so that it sees keys while an elevated
/// window has focus. It ignores injected events, matches only the chord and
/// keeps no keystroke (two flags). `pressed` is called once.
pub(crate) fn watch_panic_chord(pressed: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    *PANIC.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(pressed));
    let (set, hooked) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("panic-chord".to_owned())
        .spawn(move || {
            // SAFETY: the module handle of this executable; the hook
            // procedure lives in it and stays valid while it runs.
            let module = unsafe { GetModuleHandleW(null()) };
            // SAFETY: a global low-level hook needs the module handle and
            // thread id 0; it is called on this thread's message loop.
            let hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(chord_hook), module, 0) };
            if hook.is_null() {
                let _ = set.send(Err(std::io::Error::last_os_error()));
                return;
            }
            let _ = set.send(Ok(()));
            // SAFETY: all-zero is a valid MSG to fill.
            let mut msg: MSG = unsafe { std::mem::zeroed() };
            // The hook runs inside this loop; it ends with the process.
            // SAFETY: `msg` is writable; any window of this thread.
            while unsafe { GetMessageW(&mut msg, null_mut(), 0, 0) } > 0 {}
        })?;
    hooked
        .recv()
        .map_err(|_| std::io::Error::other("the panic-chord thread ended"))?
}

unsafe extern "system" fn chord_hook(code: i32, wparam: usize, lparam: isize) -> isize {
    if code == HC_ACTION as i32 && lparam != 0 {
        // SAFETY: for `HC_ACTION` a low-level keyboard hook's `lparam` points
        // to a KBDLLHOOKSTRUCT valid during this call.
        let key = unsafe { &*(lparam as *const KBDLLHOOKSTRUCT) };
        let injected = key.flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED) != 0;
        if !injected {
            let down = matches!(wparam as u32, WM_KEYDOWN | WM_SYSKEYDOWN);
            let up = matches!(wparam as u32, WM_KEYUP | WM_SYSKEYUP);
            let vk = key.vkCode as u16;
            if vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL {
                if down || up {
                    CTRL.store(down, Ordering::SeqCst);
                }
            } else if vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU {
                if down || up {
                    ALT.store(down, Ordering::SeqCst);
                }
            } else if vk == VK_END
                && down
                && CTRL.load(Ordering::SeqCst)
                && ALT.load(Ordering::SeqCst)
            {
                let told = PANIC.lock().unwrap_or_else(PoisonError::into_inner).take();
                if let Some(told) = told {
                    told();
                }
            }
        }
    }
    // SAFETY: passes the event on unchanged, as a hook must.
    unsafe { CallNextHookEx(null_mut(), code, wparam, lparam) }
}

/// Whether the input desktop is one this session's processes cannot open or
/// is not the user's `Default` desktop: the secure desktop of a UAC prompt,
/// the Ctrl+Alt+Del screen or the lock screen (§B.8.8). `None` when the
/// answer could not be read.
pub(crate) fn secure_desktop_shown() -> Option<bool> {
    // SAFETY: plain call; the desktop handle is closed below.
    let desk = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
    if desk.is_null() {
        // Winlogon's desktops refuse a user-session process.
        return Some(true);
    }
    let mut name = [0u16; 64];
    let mut needed = 0u32;
    // SAFETY: `name` is writable for its size in bytes; `needed` receives the
    // size needed.
    let ok = unsafe {
        GetUserObjectInformationW(
            desk as HANDLE,
            UOI_NAME,
            name.as_mut_ptr().cast::<c_void>(),
            u32::try_from(size_of_val(&name)).unwrap_or(0),
            &mut needed,
        )
    };
    // SAFETY: opened above, closed once.
    unsafe { CloseDesktop(desk) };
    if ok == 0 {
        return None;
    }
    let len = name.iter().position(|c| *c == 0).unwrap_or(name.len());
    Some(!String::from_utf16_lossy(&name[..len]).eq_ignore_ascii_case("Default"))
}
