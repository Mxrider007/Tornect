//! The panic key (`docs/PLAN.md` §B.8.7.4): a physical key chord, the
//! setting `security.panic_key` (Ctrl+Alt+End by default), watched off the UI
//! thread (D10), so a hung window never stops it. Each press is told to the
//! caller's `pressed`, on a thread of this module's own; nothing else of the
//! keyboard is kept.
//!
//! - **Windows**: a low-level keyboard hook (`WH_KEYBOARD_LL`) on its own
//!   thread, with its own message loop, that ignores injected events
//!   (`LLKHF_INJECTED`, `LLKHF_LOWER_IL_INJECTED`): only physical keys press
//!   it. The hook only signals; a second thread calls `pressed`, so the hook
//!   returns at once (NEEDS-DEVICE(windows)).
//! - **Linux**: the GlobalShortcuts portal of xdg-desktop-portal (through
//!   `ashpd`) where the desktop offers it: the chord is the shortcut's
//!   preferred trigger, and the desktop may ask the person to confirm or
//!   change it (NEEDS-DEVICE(gnome)). Where the portal is missing or refuses,
//!   the key is not bound.
//!
//! Where the key is not bound the readiness row says so ("Panic key:
//! unavailable", [`KeyState::row`]); the indicator's End, the tray and
//! `tornect panic` work either way. Changing the chord is a setting, and
//! settings that touch the panic key are access-increasing (re-authentication,
//! §B.8.6.2): this module only reads it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

/// One press of the panic key, told on the watcher's own thread.
pub type Pressed = Arc<dyn Fn() + Send + Sync>;

/// The keys a chord may end with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// End (the default).
    End,
    /// Pause / Break.
    Pause,
    /// Delete.
    Delete,
    /// Home.
    Home,
    /// Insert.
    Insert,
    /// F1 to F24.
    F(u8),
}

impl Key {
    fn parse(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "end" => Self::End,
            "pause" | "break" => Self::Pause,
            "delete" | "del" => Self::Delete,
            "home" => Self::Home,
            "insert" | "ins" => Self::Insert,
            other => {
                let n: u8 = other.strip_prefix('f')?.parse().ok()?;
                if !(1..=24).contains(&n) {
                    return None;
                }
                Self::F(n)
            }
        })
    }

    /// The key's name in the XDG shortcut format (an XKB keysym name).
    fn xkb(self) -> String {
        match self {
            Self::End => "End".to_owned(),
            Self::Pause => "Pause".to_owned(),
            Self::Delete => "Delete".to_owned(),
            Self::Home => "Home".to_owned(),
            Self::Insert => "Insert".to_owned(),
            Self::F(n) => format!("F{n}"),
        }
    }
}

/// The chord of `security.panic_key`: modifiers and one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chord {
    /// Ctrl held.
    pub ctrl: bool,
    /// Alt held.
    pub alt: bool,
    /// Shift held.
    pub shift: bool,
    /// The key pressed with them.
    pub key: Key,
}

impl Chord {
    /// Parse `Ctrl+Alt+End` and its kind: `+`-separated, any case, the
    /// modifiers Ctrl, Alt and Shift, at least one of Ctrl or Alt, and one key
    /// of [`Key`].
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut chord = Self {
            ctrl: false,
            alt: false,
            shift: false,
            key: Key::End,
        };
        let mut key = None;
        for part in text.split('+').map(str::trim) {
            match part.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => chord.ctrl = true,
                "alt" => chord.alt = true,
                "shift" => chord.shift = true,
                _ if key.is_none() => {
                    key =
                        Some(Key::parse(part).ok_or_else(|| {
                            format!("\"{part}\" is not a key the panic key can use")
                        })?);
                }
                _ => return Err(format!("\"{text}\" names more than one key")),
            }
        }
        chord.key = key.ok_or_else(|| format!("\"{text}\" names no key"))?;
        if !(chord.ctrl || chord.alt) {
            return Err(format!("\"{text}\" needs Ctrl or Alt"));
        }
        Ok(chord)
    }

    /// The chord as the GlobalShortcuts portal's preferred trigger (the XDG
    /// shortcut format: `CTRL+ALT+End`).
    #[must_use]
    pub fn portal_trigger(&self) -> String {
        let mut parts = Vec::new();
        if self.ctrl {
            parts.push("CTRL".to_owned());
        }
        if self.alt {
            parts.push("ALT".to_owned());
        }
        if self.shift {
            parts.push("SHIFT".to_owned());
        }
        parts.push(self.key.xkb());
        parts.join("+")
    }
}

/// Whether the panic key is bound: the readiness row of §B.8.7.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Not tried yet (no host has started it).
    NotTried,
    /// Watched.
    Bound,
    /// Not bound: no portal, the portal refused, the chord could not be
    /// parsed, or the hook could not be set.
    Unavailable,
}

impl KeyState {
    /// The readiness row's text (§B.8.7.4, PLAN "Panic key: bound /
    /// unavailable").
    #[must_use]
    pub fn row(self) -> &'static str {
        match self {
            Self::Bound => "Panic key: bound",
            Self::NotTried | Self::Unavailable => "Panic key: unavailable",
        }
    }
}

/// This process's panic key: one watch per process.
static STATE: AtomicU8 = AtomicU8::new(0);

fn set_state(state: KeyState) {
    STATE.store(
        match state {
            KeyState::NotTried => 0,
            KeyState::Bound => 1,
            KeyState::Unavailable => 2,
        },
        Ordering::SeqCst,
    );
}

/// Whether this process's panic key is bound.
#[must_use]
pub fn state() -> KeyState {
    match STATE.load(Ordering::SeqCst) {
        1 => KeyState::Bound,
        2 => KeyState::Unavailable,
        _ => KeyState::NotTried,
    }
}

/// What the portal answered, as the key's state: bound only when it listed
/// the shortcut back.
#[cfg(any(target_os = "linux", test))]
fn portal_state(listed: Result<bool, String>) -> KeyState {
    match listed {
        Ok(true) => KeyState::Bound,
        Ok(false) => {
            tracing::info!("the GlobalShortcuts portal did not bind the panic key");
            KeyState::Unavailable
        }
        Err(e) => {
            tracing::info!(error = %e, "no GlobalShortcuts portal: the panic key is not bound");
            KeyState::Unavailable
        }
    }
}

/// Watch for `chord`, telling `pressed` of each press on a thread of this
/// module's own, never the caller's; the state it ends in (also
/// [`state`]). Linux binds through the portal, which needs a tokio runtime.
pub async fn bind(chord: Chord, pressed: Pressed) -> KeyState {
    let state = bind_here(chord, pressed).await;
    set_state(state);
    state
}

#[cfg(windows)]
async fn bind_here(chord: Chord, pressed: Pressed) -> KeyState {
    match win::watch(chord, pressed) {
        Ok(()) => KeyState::Bound,
        Err(e) => {
            tracing::warn!(error = %e, "the panic key's hook could not be set");
            KeyState::Unavailable
        }
    }
}

#[cfg(target_os = "linux")]
async fn bind_here(chord: Chord, pressed: Pressed) -> KeyState {
    use std::pin::pin;

    use ashpd::desktop::CreateSessionOptions;
    use ashpd::desktop::global_shortcuts::{BindShortcutsOptions, GlobalShortcuts, NewShortcut};
    use zbus::export::futures_core::Stream;

    const ID: &str = "tornect-panic";
    let bound = async {
        let portal = GlobalShortcuts::new().await.map_err(|e| e.to_string())?;
        let session = portal
            .create_session(CreateSessionOptions::default())
            .await
            .map_err(|e| e.to_string())?;
        let trigger = chord.portal_trigger();
        let shortcut = NewShortcut::new(ID, "End every session Tornect shares")
            .preferred_trigger(trigger.as_str());
        let answer = portal
            .bind_shortcuts(&session, &[shortcut], None, BindShortcutsOptions::default())
            .await
            .map_err(|e| e.to_string())?
            .response()
            .map_err(|e| e.to_string())?;
        let listed = answer.shortcuts().iter().any(|s| s.id() == ID);
        Ok::<_, String>((portal, session, listed))
    }
    .await;
    let (portal, session, listed) = match bound {
        Ok(bound) => bound,
        Err(e) => return portal_state(Err(e)),
    };
    let state = portal_state(Ok(listed));
    if state != KeyState::Bound {
        return state;
    }
    let activated = match portal.receive_activated().await {
        Ok(activated) => activated,
        Err(e) => return portal_state(Err(e.to_string())),
    };
    tokio::spawn(async move {
        // The session lives as long as the watch.
        let _session = session;
        let mut activated = pin!(activated);
        while let Some(event) = std::future::poll_fn(|cx| activated.as_mut().poll_next(cx)).await {
            if event.shortcut_id() == ID {
                // Off the portal's task: `pressed` may write the store.
                let pressed = Arc::clone(&pressed);
                tokio::task::spawn_blocking(move || pressed());
            }
        }
        set_state(KeyState::Unavailable);
        tracing::warn!("the GlobalShortcuts portal stopped: the panic key is no longer bound");
    });
    state
}

#[cfg(not(any(windows, target_os = "linux")))]
async fn bind_here(_: Chord, _: Pressed) -> KeyState {
    KeyState::Unavailable
}

#[cfg(windows)]
#[allow(unsafe_code)] // the hook's FFI; each block says why it is sound
mod win {
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
    use std::sync::{Mutex, PoisonError, mpsc};

    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        VK_CONTROL, VK_DELETE, VK_END, VK_F1, VK_HOME, VK_INSERT, VK_LCONTROL, VK_LMENU, VK_LSHIFT,
        VK_MENU, VK_PAUSE, VK_RCONTROL, VK_RMENU, VK_RSHIFT, VK_SHIFT,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, GetMessageW, HC_ACTION, KBDLLHOOKSTRUCT, LLKHF_INJECTED,
        LLKHF_LOWER_IL_INJECTED, MSG, SetWindowsHookExW, WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP,
        WM_SYSKEYDOWN, WM_SYSKEYUP,
    };

    use super::{Chord, Key, Pressed};

    /// The chord's state in the hook: which modifiers are down.
    static CTRL: AtomicBool = AtomicBool::new(false);
    static ALT: AtomicBool = AtomicBool::new(false);
    static SHIFT: AtomicBool = AtomicBool::new(false);
    /// The chord watched: its key and modifiers (set once, before the hook).
    static KEY: AtomicU16 = AtomicU16::new(0);
    static WANT: AtomicU16 = AtomicU16::new(0);
    /// Where a press is signalled: a thread outside the hook calls `pressed`.
    static PRESSES: Mutex<Option<mpsc::Sender<()>>> = Mutex::new(None);

    fn vk(key: Key) -> u16 {
        match key {
            Key::End => VK_END,
            Key::Pause => VK_PAUSE,
            Key::Delete => VK_DELETE,
            Key::Home => VK_HOME,
            Key::Insert => VK_INSERT,
            Key::F(n) => VK_F1 + u16::from(n) - 1,
        }
    }

    pub(super) fn watch(chord: Chord, pressed: Pressed) -> std::io::Result<()> {
        KEY.store(vk(chord.key), Ordering::SeqCst);
        WANT.store(
            u16::from(chord.ctrl) | u16::from(chord.alt) << 1 | u16::from(chord.shift) << 2,
            Ordering::SeqCst,
        );
        let (tx, rx) = mpsc::channel();
        *PRESSES.lock().unwrap_or_else(PoisonError::into_inner) = Some(tx);
        std::thread::Builder::new()
            .name("panic-key".to_owned())
            .spawn(move || {
                while rx.recv().is_ok() {
                    pressed();
                }
            })?;
        let (set, hooked) = mpsc::channel();
        std::thread::Builder::new()
            .name("panic-key-hook".to_owned())
            // An explicit size: std then never reads `RUST_MIN_STACK`.
            .stack_size(256 * 1024)
            .spawn(move || {
                // SAFETY: the module handle of this executable; the hook
                // procedure lives in it and stays valid while it runs.
                let module = unsafe { GetModuleHandleW(null()) };
                // SAFETY: a global low-level hook needs the module handle and
                // thread id 0; it is called on this thread's message loop.
                let hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook), module, 0) };
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
            .map_err(|_| std::io::Error::other("the panic key's hook thread ended"))?
    }

    unsafe extern "system" fn hook(code: i32, wparam: usize, lparam: isize) -> isize {
        if code == HC_ACTION as i32 && lparam != 0 {
            // SAFETY: for `HC_ACTION` a low-level keyboard hook's `lparam`
            // points to a KBDLLHOOKSTRUCT valid during this call.
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
                } else if vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT {
                    if down || up {
                        SHIFT.store(down, Ordering::SeqCst);
                    }
                } else if down && vk == KEY.load(Ordering::SeqCst) {
                    let held = u16::from(CTRL.load(Ordering::SeqCst))
                        | u16::from(ALT.load(Ordering::SeqCst)) << 1
                        | u16::from(SHIFT.load(Ordering::SeqCst)) << 2;
                    if held == WANT.load(Ordering::SeqCst)
                        && let Some(tx) = PRESSES
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .as_ref()
                    {
                        let _ = tx.send(());
                    }
                }
            }
        }
        // SAFETY: passes the event on unchanged, as a hook must.
        unsafe { CallNextHookEx(null_mut(), code, wparam, lparam) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `security.panic_key` as the setting writes it: the default and its kind,
    /// any case and spacing; a chord without Ctrl or Alt, an unknown key or two
    /// keys are refused (the key is then not bound).
    #[test]
    fn the_chord_is_read_from_the_setting() {
        let chord = Chord::parse("Ctrl+Alt+End").unwrap();
        assert_eq!(
            chord,
            Chord {
                ctrl: true,
                alt: true,
                shift: false,
                key: Key::End
            }
        );
        assert_eq!(chord.portal_trigger(), "CTRL+ALT+End");
        assert_eq!(
            Chord::parse(" ctrl + shift + f12 ")
                .unwrap()
                .portal_trigger(),
            "CTRL+SHIFT+F12"
        );
        for bad in [
            "End",
            "Shift+End",
            "Ctrl+Alt+Q",
            "Ctrl+End+Home",
            "Ctrl+Alt",
            "Ctrl+F25",
        ] {
            assert!(Chord::parse(bad).is_err(), "{bad}");
        }
    }

    /// Without the portal (or a portal that does not list the shortcut back), the
    /// key is not bound and the readiness row says "Panic key: unavailable".
    #[test]
    fn unavailable_without_the_portal() {
        assert_eq!(
            portal_state(Err(
                "org.freedesktop.portal.GlobalShortcuts: no such interface".into()
            )),
            KeyState::Unavailable
        );
        assert_eq!(portal_state(Ok(false)), KeyState::Unavailable);
        assert_eq!(portal_state(Ok(true)), KeyState::Bound);
        assert_eq!(KeyState::Unavailable.row(), "Panic key: unavailable");
        assert_eq!(KeyState::NotTried.row(), "Panic key: unavailable");
        assert_eq!(KeyState::Bound.row(), "Panic key: bound");
    }
}
