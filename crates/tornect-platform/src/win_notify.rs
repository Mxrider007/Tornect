//! Windows: the notification that mirrors a request's sheet while Tornect
//! runs in background mode (`docs/PLAN.md` §B.1.1; §B.8.7.3: never a
//! notification alone). Each sheet gets a notification-area icon of this
//! process that shows one balloon with the sheet's fixed text
//! (`Shell_NotifyIconW`: `NIM_ADD` with `NIF_INFO`), and the icon goes when the
//! sheet goes (`NIM_DELETE`). Windows 10 and 11 show such a balloon as a toast
//! (NEEDS-DEVICE(windows)). The icons belong to a hidden top-level window of
//! a class of its own that a thread of their own creates and keeps: a
//! top-level window, since Explorer, when it starts again, tells only those
//! that the taskbar is back (the registered message `TaskbarCreated`), and
//! the icons are then added again. An icon the shell did not take is kept
//! and added again at the next request and at that message. The calls are
//! type-checked, and no test makes them.
#![allow(unsafe_code)]

use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{ERROR_CLASS_ALREADY_EXISTS, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, IDI_APPLICATION, LoadIconW,
    MSG, PM_REMOVE, PeekMessageW, RegisterClassExW, RegisterWindowMessageW, TranslateMessage,
    WNDCLASSEXW,
};

/// How often the thread empties its window's queue between requests.
const PUMP_EVERY: Duration = Duration::from_millis(250);

/// The icon's tooltip: the program, nothing about the request.
const TIP: &str = "Tornect";

/// The class of the notices' window.
const CLASS: &str = "TornectNotices";

/// The message Explorer sends every top-level window when the taskbar is
/// created again; 0 until it is registered.
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);

/// How many times that message came: each notices' thread adds its icons
/// again once for every time.
static TASKBAR_RESTARTS: AtomicU64 = AtomicU64::new(0);

/// One notification asked for: what it shows, and whether the shell took
/// its icon.
struct Notice {
    id: u32,
    title: String,
    text: String,
    up: bool,
}

/// What the thread is asked to do.
enum Op {
    /// Show notification `id`.
    Show {
        id: u32,
        title: String,
        text: String,
    },
    /// Take notification `id` down.
    Remove { id: u32 },
}

/// The notifications of this process. Dropped, every one still up is taken
/// down, the window is destroyed and the thread ends.
#[derive(Debug)]
pub struct Notices {
    ops: mpsc::Sender<Op>,
}

impl Notices {
    /// Start the notifications' thread and its window; an error when the
    /// window cannot be created.
    pub fn start() -> std::io::Result<Self> {
        let (ops, requests) = mpsc::channel();
        let (started_tx, started) = mpsc::channel();
        std::thread::Builder::new()
            .name("notices".to_owned())
            // An explicit size: std then never reads `RUST_MIN_STACK`.
            .stack_size(256 * 1024)
            .spawn(move || run(&requests, &started_tx))?;
        started
            .recv()
            .map_err(|_| std::io::Error::other("the notifications' thread ended"))??;
        Ok(Self { ops })
    }

    /// Show notification `id` with `title` and `text`, each shortened to what
    /// the balloon holds.
    pub fn show(&self, id: u32, title: &str, text: &str) {
        let _ = self.ops.send(Op::Show {
            id,
            title: title.to_owned(),
            text: text.to_owned(),
        });
    }

    /// Take notification `id` down.
    pub fn remove(&self, id: u32) {
        let _ = self.ops.send(Op::Remove { id });
    }
}

/// The notices' window procedure: counts Explorer's `TaskbarCreated` and
/// leaves every other message to Windows.
unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let created = TASKBAR_CREATED.load(Ordering::Relaxed);
    if created != 0 && message == created {
        TASKBAR_RESTARTS.fetch_add(1, Ordering::Relaxed);
        return 0;
    }
    // SAFETY: the arguments are the ones Windows passed to this procedure.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

/// The notices' hidden top-level window, of the class whose procedure is
/// [`window_proc`]; Explorer's `TaskbarCreated` registered first.
fn notices_window() -> std::io::Result<HWND> {
    let taskbar = crate::win::wide("TaskbarCreated");
    // SAFETY: `taskbar` is NUL-terminated; every process gets the same id.
    let created = unsafe { RegisterWindowMessageW(taskbar.as_ptr()) };
    TASKBAR_CREATED.store(created, Ordering::Relaxed);
    // SAFETY: plain call; the module handle of this executable.
    let module = unsafe { GetModuleHandleW(null()) };
    let class = crate::win::wide(CLASS);
    let info = WNDCLASSEXW {
        cbSize: u32::try_from(size_of::<WNDCLASSEXW>()).unwrap_or(0),
        lpfnWndProc: Some(window_proc),
        hInstance: module,
        lpszClassName: class.as_ptr(),
        ..WNDCLASSEXW::default()
    };
    // SAFETY: `info` holds its size, this module, the procedure above and a
    // NUL-terminated class name that outlives the call.
    if unsafe { RegisterClassExW(&info) } == 0 {
        let e = std::io::Error::last_os_error();
        // A second notices' thread of this process uses the same class.
        if e.raw_os_error() != Some(ERROR_CLASS_ALREADY_EXISTS as i32) {
            return Err(e);
        }
    }
    // SAFETY: a top-level window (no parent) that is never shown (no
    // `WS_VISIBLE`), of the class above; no menu, no creation data; `class`
    // is NUL-terminated and outlives the call.
    let window = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            null(),
            0,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            module,
            null(),
        )
    };
    if window.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(window)
}

/// Add every notice whose icon the shell has not taken yet.
fn add_missing(window: HWND, notices: &mut [Notice]) {
    for notice in notices.iter_mut().filter(|n| !n.up) {
        notice.up = add(window, notice.id, &notice.title, &notice.text);
    }
}

/// The thread: the window, then the requests until the sender is gone.
fn run(requests: &mpsc::Receiver<Op>, started: &mpsc::Sender<std::io::Result<()>>) {
    let window = match notices_window() {
        Ok(window) => window,
        Err(e) => {
            let _ = started.send(Err(e));
            return;
        }
    };
    let _ = started.send(Ok(()));
    let mut notices: Vec<Notice> = Vec::new();
    let mut restarts = TASKBAR_RESTARTS.load(Ordering::Relaxed);
    loop {
        match requests.recv_timeout(PUMP_EVERY) {
            Ok(Op::Show { id, title, text }) => {
                if !notices.iter().any(|n| n.id == id) {
                    notices.push(Notice {
                        id,
                        title,
                        text,
                        up: false,
                    });
                }
                add_missing(window, &mut notices);
            }
            Ok(Op::Remove { id }) => {
                if let Some(at) = notices.iter().position(|n| n.id == id) {
                    notices.remove(at);
                    delete(window, id);
                }
                add_missing(window, &mut notices);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        pump(window);
        let now = TASKBAR_RESTARTS.load(Ordering::Relaxed);
        if now != restarts {
            restarts = now;
            // A new taskbar holds none of the icons: each is added again (an
            // icon the shell still holds is taken down first).
            for notice in &mut notices {
                delete(window, notice.id);
                notice.up = false;
            }
            add_missing(window, &mut notices);
        }
    }
    for notice in &notices {
        delete(window, notice.id);
    }
    // SAFETY: this thread created `window`.
    unsafe { DestroyWindow(window) };
}

/// Empty the window's queue: its procedure sees each message, Explorer's
/// `TaskbarCreated` included.
fn pump(window: HWND) {
    let mut msg = MSG::default();
    // SAFETY: `msg` is writable; only messages for this thread's window.
    while unsafe { PeekMessageW(&mut msg, window, 0, 0, PM_REMOVE) } != 0 {
        // SAFETY: `msg` was filled by `PeekMessageW`.
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// The identity of notification `id`: the window and the id.
fn icon(window: HWND, id: u32) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: u32::try_from(size_of::<NOTIFYICONDATAW>()).unwrap_or(0),
        hWnd: window,
        uID: id,
        ..NOTIFYICONDATAW::default()
    }
}

/// Add notification `id`: the program's stock icon, its tooltip, and the
/// balloon; whether the shell took it.
fn add(window: HWND, id: u32, title: &str, text: &str) -> bool {
    let mut data = icon(window, id);
    data.uFlags = NIF_ICON | NIF_TIP | NIF_INFO;
    // SAFETY: a stock icon of the system (no module): shared, never destroyed.
    data.hIcon = unsafe { LoadIconW(null_mut(), IDI_APPLICATION) };
    copy(&mut data.szTip, TIP);
    copy(&mut data.szInfoTitle, title);
    copy(&mut data.szInfo, text);
    data.dwInfoFlags = NIIF_INFO;
    // SAFETY: `data` is a filled NOTIFYICONDATAW with its size; the shell
    // copies what it needs during the call.
    let added = unsafe { Shell_NotifyIconW(NIM_ADD, &data) } != 0;
    if !added {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "the desktop notification of a request could not be shown"
        );
    }
    added
}

/// Take notification `id` down.
fn delete(window: HWND, id: u32) {
    let data = icon(window, id);
    // SAFETY: as in `add`; only the icon's identity is read.
    if unsafe { Shell_NotifyIconW(NIM_DELETE, &data) } == 0 {
        tracing::debug!(
            error = %std::io::Error::last_os_error(),
            "a notification was already gone"
        );
    }
}

/// `text` in a fixed UTF-16 field, shortened so that its NUL fits.
fn copy<const N: usize>(field: &mut [u16; N], text: &str) {
    let mut end = 0;
    for (slot, unit) in field
        .iter_mut()
        .zip(text.encode_utf16().take(N.saturating_sub(1)))
    {
        *slot = unit;
        end += 1;
    }
    if let Some(nul) = field.get_mut(end) {
        *nul = 0;
    }
}
