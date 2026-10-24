//! The panic key (`docs/PLAN.md` §B.8.7.4): a physical key chord, the
//! setting `security.panic_key` (Ctrl+Alt+End by default), watched off the UI
//! thread (D10), so a hung window never stops it. Each press is told to the
//! caller's `pressed`, on a thread of this module's own; nothing else of the
//! keyboard is kept.
//!
//! - **Windows**: a low-level keyboard hook (`WH_KEYBOARD_LL`) on its own
//!   thread, with its own message loop, that ignores injected events
//!   (`LLKHF_INJECTED`, `LLKHF_LOWER_IL_INJECTED`): only physical keys press
//!   it. A modifier the hook saw go down counts only while the system's key
//!   state still has it down (the `Modifiers` state), and every switch of
//!   the input desktop forgets them (`EVENT_SYSTEM_DESKTOPSWITCH`), so one
//!   let go on the secure desktop never lingers. The hook only signals; a
//!   second thread calls `pressed`, so the hook returns at once
//!   (NEEDS-DEVICE(windows)).
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

    /// The chord's modifiers as [`Modifiers`] bits.
    #[cfg(any(windows, test))]
    pub(crate) fn modifier_bits(&self) -> u8 {
        (if self.ctrl { Modifiers::CTRL } else { 0 })
            | (if self.alt { Modifiers::ALT } else { 0 })
            | (if self.shift { Modifiers::SHIFT } else { 0 })
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

/// What a low-level keyboard hook knows of a chord's modifiers (Windows: this
/// module's hook and the administrator helper's; plain logic, tested on every
/// OS).
///
/// A hook sees a modifier go down and up only while its desktop takes the
/// input. The key-ups of Ctrl+Alt+Del, and any key let go while a UAC prompt
/// or the lock screen is up, happen on the secure desktop and never reach it,
/// so what the hook saw alone kept Ctrl and Alt held after they were let go,
/// and a later Ctrl+End, or a bare End, pressed the panic key (audit B08). So
/// when the chord's key goes down, the system's own key state is read as
/// well, and a modifier the hook saw go down counts only while the system
/// still has it down; one the system has up is forgotten.
///
/// Only physical keys press the panic key: injected events never make a
/// modifier count by themselves. They do move the system's key state,
/// though, so an injected key-up can make it say "up" for a key someone
/// holds; after an injected event of a modifier, what the hook saw stands
/// until that modifier's next physical event, so a remote viewer's injected
/// key-ups cannot hold the panic key off. The price: injected events of a
/// modifier keep a stale one (its key-up missed) counted until that
/// modifier's next physical event. So every switch of the input desktop,
/// where key-ups go missing, also forgets all the hook saw
/// ([`Modifiers::desktop_switched`]): after Ctrl+Alt+Del, a viewer's Ctrl+C
/// and Alt+Tab no longer turn the owner's bare End into the chord.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Modifiers {
    /// The modifiers whose last physical event was a key-down.
    down: u8,
    /// The modifiers with an injected event since their last physical one.
    injected: u8,
}

#[cfg(any(windows, test))]
impl Modifiers {
    /// Ctrl, either side.
    pub(crate) const CTRL: u8 = 1;
    /// Alt, either side.
    pub(crate) const ALT: u8 = 2;
    /// Shift, either side.
    pub(crate) const SHIFT: u8 = 4;
    /// Nothing seen yet.
    pub(crate) const NONE: Self = Self {
        down: 0,
        injected: 0,
    };

    /// A key-down or key-up of the modifier `bit`, physical or injected.
    pub(crate) fn key(&mut self, bit: u8, down: bool, injected: bool) {
        if injected {
            self.injected |= bit;
            return;
        }
        self.injected &= !bit;
        if down {
            self.down |= bit;
        } else {
            self.down &= !bit;
        }
    }

    /// The modifiers held as the chord's key goes down, `system` being those
    /// the system's key state has down now (`GetAsyncKeyState`): each the
    /// hook saw go down physically and the system still has down, or whose
    /// system state an injected event has moved since. One the system has up
    /// otherwise was let go where the hook could not see it, and is forgotten.
    pub(crate) fn held(&mut self, system: u8) -> u8 {
        self.down &= system | self.injected;
        self.down
    }

    /// The input desktop switched (the secure desktop of Ctrl+Alt+Del, a UAC
    /// prompt or the lock screen came or went): the hook saw none of the
    /// key-ups there, so all it saw is forgotten, injected events included.
    /// A modifier held across the switch counts again at its next physical
    /// key-down: the chord pressed afresh works at once; one begun before the
    /// switch and finished after it does not, which errs toward not pressing
    /// the panic key rather than pressing it by mistake.
    pub(crate) fn desktop_switched(&mut self) {
        *self = Self::NONE;
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
pub(crate) mod win {
    use std::cell::Cell;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicU8, AtomicU16, Ordering};
    use std::sync::{Mutex, PoisonError, mpsc};

    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Accessibility::{HWINEVENTHOOK, SetWinEventHook};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VK_CONTROL, VK_DELETE, VK_END, VK_F1, VK_HOME, VK_INSERT, VK_LCONTROL,
        VK_LMENU, VK_LSHIFT, VK_MENU, VK_PAUSE, VK_RCONTROL, VK_RMENU, VK_RSHIFT, VK_SHIFT,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, EVENT_SYSTEM_DESKTOPSWITCH, GetMessageW, HC_ACTION, KBDLLHOOKSTRUCT,
        LLKHF_INJECTED, LLKHF_LOWER_IL_INJECTED, MSG, SetWindowsHookExW, WH_KEYBOARD_LL,
        WINEVENT_OUTOFCONTEXT, WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
    };

    use super::{Chord, Key, Modifiers, Pressed};

    thread_local! {
        /// The chord's modifiers as this thread's hook saw them: the panic
        /// key's hook here, the administrator helper's chord hook there. A
        /// low-level hook, and an out-of-context WinEvent hook, run on the
        /// thread that set them, so only that thread touches its own.
        pub(crate) static MODS: Cell<Modifiers> = const { Cell::new(Modifiers::NONE) };
    }
    /// The chord watched: its key and modifiers (set once, before the hook).
    static KEY: AtomicU16 = AtomicU16::new(0);
    static WANT: AtomicU8 = AtomicU8::new(0);
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

    /// The modifier a virtual-key code is (either side's code or the generic
    /// one), as a [`Modifiers`] bit.
    fn modifier_of(vk: u16) -> Option<u8> {
        match vk {
            VK_CONTROL | VK_LCONTROL | VK_RCONTROL => Some(Modifiers::CTRL),
            VK_MENU | VK_LMENU | VK_RMENU => Some(Modifiers::ALT),
            VK_SHIFT | VK_LSHIFT | VK_RSHIFT => Some(Modifiers::SHIFT),
            _ => None,
        }
    }

    /// The modifiers the system's key state has down now, either side.
    fn system_modifiers() -> u8 {
        let down = |vk: u16| {
            // SAFETY: plain call with a virtual-key code; it takes no
            // pointer.
            let state = unsafe { GetAsyncKeyState(i32::from(vk)) };
            // The high bit (a negative answer) means down now.
            state < 0
        };
        [
            (VK_CONTROL, Modifiers::CTRL),
            (VK_MENU, Modifiers::ALT),
            (VK_SHIFT, Modifiers::SHIFT),
        ]
        .into_iter()
        .filter(|&(vk, _)| down(vk))
        .fold(0, |bits, (_, bit)| bits | bit)
    }

    /// One event of a low-level keyboard hook, kept in `mods`: a modifier's
    /// is recorded, an injected one too ([`Modifiers::key`]); the physical
    /// key-down of `trigger` answers the modifiers held with it
    /// ([`Modifiers::held`], against the system's key state). This module's
    /// hook and the administrator helper's both use it.
    pub(crate) fn chord_event(
        mods: &Cell<Modifiers>,
        key: &KBDLLHOOKSTRUCT,
        wparam: usize,
        trigger: u16,
    ) -> Option<u8> {
        let injected = key.flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED) != 0;
        let down = matches!(wparam as u32, WM_KEYDOWN | WM_SYSKEYDOWN);
        let up = matches!(wparam as u32, WM_KEYUP | WM_SYSKEYUP);
        let vk = key.vkCode as u16;
        let mut state = mods.get();
        let held = match modifier_of(vk) {
            Some(bit) => {
                if down || up {
                    state.key(bit, down, injected);
                }
                None
            }
            None if down && !injected && vk == trigger => Some(state.held(system_modifiers())),
            None => None,
        };
        mods.set(state);
        held
    }

    /// Forget this thread's [`MODS`] at every switch of the input desktop
    /// ([`Modifiers::desktop_switched`]): an out-of-context WinEvent hook for
    /// `EVENT_SYSTEM_DESKTOPSWITCH`, called on this thread's message loop,
    /// which the caller runs (a keyboard hook's thread). It lives as long as
    /// the thread. Where it cannot be set, the system's key state still
    /// clears what was let go unseen ([`Modifiers::held`]), short of a
    /// viewer's injected events of that modifier.
    pub(crate) fn forget_on_desktop_switch() {
        // SAFETY: an out-of-context hook (no module: nothing is loaded into
        // other processes) for one system event from every process and
        // thread; `desktop_switched` has the WINEVENTPROC signature and lives
        // as long as the program.
        let hook = unsafe {
            SetWinEventHook(
                EVENT_SYSTEM_DESKTOPSWITCH,
                EVENT_SYSTEM_DESKTOPSWITCH,
                null_mut(),
                Some(desktop_switched),
                0,
                0,
                WINEVENT_OUTOFCONTEXT,
            )
        };
        if hook.is_null() {
            tracing::warn!(
                "desktop switches cannot be watched; the panic key relies on the system's key state alone"
            );
        }
    }

    unsafe extern "system" fn desktop_switched(
        _hook: HWINEVENTHOOK,
        _event: u32,
        _window: HWND,
        _object: i32,
        _child: i32,
        _thread: u32,
        _time: u32,
    ) {
        let _ = MODS.try_with(|mods| {
            let mut state = mods.get();
            state.desktop_switched();
            mods.set(state);
        });
    }

    pub(super) fn watch(chord: Chord, pressed: Pressed) -> std::io::Result<()> {
        KEY.store(vk(chord.key), Ordering::SeqCst);
        WANT.store(chord.modifier_bits(), Ordering::SeqCst);
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
                forget_on_desktop_switch();
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
            let held = MODS
                .try_with(|mods| chord_event(mods, key, wparam, KEY.load(Ordering::SeqCst)))
                .ok()
                .flatten();
            if held == Some(WANT.load(Ordering::SeqCst))
                && let Some(tx) = PRESSES
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_ref()
            {
                let _ = tx.send(());
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

    /// The chord's modifiers as the hook compares them.
    #[test]
    fn the_chord_names_its_modifier_bits() {
        let bits = |text: &str| Chord::parse(text).unwrap().modifier_bits();
        assert_eq!(bits("Ctrl+Alt+End"), Modifiers::CTRL | Modifiers::ALT);
        assert_eq!(bits("Ctrl+Shift+F12"), Modifiers::CTRL | Modifiers::SHIFT);
        assert_eq!(
            bits("Alt+Shift+Ctrl+Pause"),
            Modifiers::CTRL | Modifiers::ALT | Modifiers::SHIFT
        );
    }

    /// Audit B08: Ctrl+Alt+Del's key-ups happen on the secure desktop, which
    /// the hook never sees; afterwards the system has both keys up. A later
    /// Ctrl+End, or a bare End, is not the panic chord: the modifiers the
    /// system has up are forgotten. What the hook saw alone (the old rule)
    /// would have held Ctrl and Alt and pressed the panic key, twice for a
    /// double press, which turns unattended access off.
    #[test]
    fn a_modifier_let_go_on_the_secure_desktop_does_not_linger() {
        const WANT: u8 = Modifiers::CTRL | Modifiers::ALT;
        let mut mods = Modifiers::NONE;
        // Ctrl and Alt go down; Del switches to the secure desktop.
        mods.key(Modifiers::CTRL, true, false);
        mods.key(Modifiers::ALT, true, false);
        // Back on the desktop, Ctrl+End: the system has only Ctrl down.
        mods.key(Modifiers::CTRL, true, false);
        assert_ne!(mods.held(Modifiers::CTRL), WANT);
        assert_eq!(mods.held(Modifiers::CTRL), Modifiers::CTRL, "Alt forgotten");
        mods.key(Modifiers::CTRL, false, false);
        // A bare End, twice.
        assert_eq!(mods.held(0), 0);
        assert_eq!(mods.held(0), 0);

        // The same, nothing pressed between: a bare End is no chord.
        let mut mods = Modifiers::NONE;
        mods.key(Modifiers::CTRL, true, false);
        mods.key(Modifiers::ALT, true, false);
        assert_eq!(mods.held(0), 0);

        // The real chord still presses it, afterwards and before.
        mods.key(Modifiers::CTRL, true, false);
        mods.key(Modifiers::ALT, true, false);
        assert_eq!(mods.held(WANT), WANT);
        assert_eq!(mods.held(WANT), WANT, "held for a second press");
        let mut fresh = Modifiers::default();
        fresh.key(Modifiers::ALT, true, false);
        fresh.key(Modifiers::CTRL, true, false);
        assert_eq!(fresh.held(WANT | Modifiers::SHIFT), WANT);
        fresh.key(Modifiers::ALT, false, false);
        assert_eq!(fresh.held(WANT), Modifiers::CTRL, "a key-up the hook saw");
    }

    /// Only physical keys press the panic key, and injected input never holds
    /// it off: injected modifiers count for nothing, even with the system's
    /// key state down; injected key-ups, which put the system's state up,
    /// leave a physically held modifier counted until its next physical
    /// event.
    #[test]
    fn injected_modifiers_neither_press_nor_hold_off_the_panic_key() {
        const WANT: u8 = Modifiers::CTRL | Modifiers::ALT;
        let mut mods = Modifiers::NONE;
        mods.key(Modifiers::CTRL, true, true);
        mods.key(Modifiers::ALT, true, true);
        assert_eq!(mods.held(WANT), 0, "injected keys pressed it");

        let mut mods = Modifiers::NONE;
        mods.key(Modifiers::CTRL, true, false);
        mods.key(Modifiers::ALT, true, false);
        mods.key(Modifiers::CTRL, false, true);
        mods.key(Modifiers::ALT, false, true);
        assert_eq!(mods.held(0), WANT, "injected key-ups held it off");
        // Down again, injected, and up: still held physically.
        mods.key(Modifiers::ALT, true, true);
        mods.key(Modifiers::ALT, false, true);
        assert_eq!(mods.held(Modifiers::CTRL), WANT);
        // The next physical events decide again.
        mods.key(Modifiers::ALT, false, false);
        assert_eq!(mods.held(0), Modifiers::CTRL);
        mods.key(Modifiers::CTRL, true, false);
        assert_eq!(mods.held(0), 0, "the system has Ctrl up");
    }

    /// Audit B08, the case the system's key state cannot settle: Ctrl+Alt+Del
    /// leaves Ctrl and Alt stale, then a viewer's Ctrl+C and Alt+Tab
    /// (injected) put both out of the system state's reach. A bare End at the
    /// host would match the chord, and a double press turns unattended access
    /// off. The desktop switches of Ctrl+Alt+Del forget them first, so it
    /// does not; the chord pressed afresh still does, and injected input
    /// still never makes a modifier count.
    #[test]
    fn a_desktop_switch_forgets_modifiers_injected_input_kept_stale() {
        const WANT: u8 = Modifiers::CTRL | Modifiers::ALT;
        let viewer_copies_and_switches = |mods: &mut Modifiers| {
            for bit in [Modifiers::CTRL, Modifiers::ALT] {
                mods.key(bit, true, true);
                mods.key(bit, false, true);
            }
        };

        // Without the switches the hook would miss: what the reset fixes.
        let mut mods = Modifiers::NONE;
        mods.key(Modifiers::CTRL, true, false);
        mods.key(Modifiers::ALT, true, false);
        viewer_copies_and_switches(&mut mods);
        assert_eq!(mods.held(0), WANT, "the stale case the reset is for");

        // Ctrl and Alt go down; Del switches to the secure desktop, Cancel
        // switches back; the key-ups happened there.
        let mut mods = Modifiers::NONE;
        mods.key(Modifiers::CTRL, true, false);
        mods.key(Modifiers::ALT, true, false);
        mods.desktop_switched();
        mods.desktop_switched();
        viewer_copies_and_switches(&mut mods);
        assert_eq!(mods.held(0), 0, "a bare End pressed the panic key");
        assert_eq!(mods.held(0), 0, "a second bare End pressed it");
        mods.key(Modifiers::CTRL, true, false);
        assert_eq!(mods.held(Modifiers::CTRL), Modifiers::CTRL, "Ctrl+End");

        // Injected modifiers after a switch count for nothing.
        let mut mods = Modifiers::NONE;
        mods.desktop_switched();
        mods.key(Modifiers::CTRL, true, true);
        mods.key(Modifiers::ALT, true, true);
        assert_eq!(mods.held(WANT), 0);

        // The real chord, pressed after the switch, still presses it.
        let mut mods = Modifiers::NONE;
        mods.key(Modifiers::CTRL, true, false);
        mods.key(Modifiers::ALT, true, false);
        mods.desktop_switched();
        mods.key(Modifiers::CTRL, true, false);
        mods.key(Modifiers::ALT, true, false);
        assert_eq!(mods.held(WANT), WANT);
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
