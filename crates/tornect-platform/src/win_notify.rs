//! Windows: the notification that mirrors a request's sheet while Tornect
//! runs in background mode (`docs/PLAN.md` §B.1.1; §B.8.7.3: never a
//! notification alone). Each sheet gets a notification-area icon of this
//! process that shows one balloon with the sheet's fixed text
//! (`Shell_NotifyIconW`: `NIM_ADD` with `NIF_INFO`), and the icon goes when the
//! sheet goes (`NIM_DELETE`). Windows 10 and 11 show such a balloon as a toast
//! (NEEDS-DEVICE(windows)). The icons belong to a hidden message-only window
//! that a thread of their own creates and keeps; the calls are type-checked,
//! and no test makes them.
#![allow(unsafe_code)]

use std::ptr::{null, null_mut};
use std::sync::mpsc;
use std::time::Duration;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, DispatchMessageW, HWND_MESSAGE, IDI_APPLICATION, LoadIconW,
    MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
};

/// How often the thread empties its window's queue between requests.
const PUMP_EVERY: Duration = Duration::from_millis(250);

/// The icon's tooltip: the program, nothing about the request.
const TIP: &str = "Tornect";

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

/// The thread: the window, then the requests until the sender is gone.
fn run(requests: &mpsc::Receiver<Op>, started: &mpsc::Sender<std::io::Result<()>>) {
    let class = crate::win::wide("STATIC");
    // SAFETY: plain call; the module handle of this executable.
    let module = unsafe { GetModuleHandleW(null()) };
    // SAFETY: a message-only window (parent `HWND_MESSAGE`) of the predefined
    // STATIC class, no menu, no creation data; `class` is NUL-terminated and
    // outlives the call.
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
            HWND_MESSAGE,
            null_mut(),
            module,
            null(),
        )
    };
    if window.is_null() {
        let _ = started.send(Err(std::io::Error::last_os_error()));
        return;
    }
    let _ = started.send(Ok(()));
    let mut shown: Vec<u32> = Vec::new();
    loop {
        match requests.recv_timeout(PUMP_EVERY) {
            Ok(Op::Show { id, title, text }) => {
                if !shown.contains(&id) && add(window, id, &title, &text) {
                    shown.push(id);
                }
            }
            Ok(Op::Remove { id }) => {
                if let Some(at) = shown.iter().position(|s| *s == id) {
                    shown.remove(at);
                    delete(window, id);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        pump(window);
    }
    for id in shown {
        delete(window, id);
    }
    // SAFETY: this thread created `window`.
    unsafe { DestroyWindow(window) };
}

/// Empty the window's queue (nothing in it is acted on).
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
