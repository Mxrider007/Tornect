//! Keys by physical scancode (`docs/research/slice.md` §2): the stream window
//! reads `WindowEvent::KeyboardInput` itself, before egui sees it (egui drops
//! every key it has no name for: PrintScreen, NumLock, media keys…), takes the
//! platform scancode from winit's `PhysicalKeyExtScancode::to_scancode`, and
//! maps it to the USB HID usage that travels on the wire, with
//! `tornect_input::keymap::by_win` on Windows (Set-1, E0 in the high byte) and
//! `by_evdev` on Linux (X11 and Wayland keycodes minus 8).
//!
//! Every key goes through the viewer's own chord first, Ctrl+Alt+Shift+M
//! (decision M1-70): it takes the keyboard back from the remote computer, and
//! its M never reaches it.

use std::collections::BTreeSet;

use tornect_input::keymap;

/// Whose scancodes a number is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPlatform {
    /// A Windows Set-1 scancode, `0xE0xx` for an extended key.
    Windows,
    /// A Linux evdev code (an X11 or Wayland keycode minus 8).
    Linux,
}

impl KeyPlatform {
    /// This build's platform, where winit gives scancodes the key table knows.
    pub const HERE: Option<Self> = if cfg!(windows) {
        Some(Self::Windows)
    } else if cfg!(target_os = "linux") {
        Some(Self::Linux)
    } else {
        None
    };
}

/// The USB usage of `scancode` on `platform`, or `None` for a key the table
/// has no row for (the key is then not sent).
#[must_use]
pub fn usb_from_scancode(platform: KeyPlatform, scancode: u32) -> Option<u32> {
    let code = u16::try_from(scancode).ok()?;
    let key = match platform {
        KeyPlatform::Windows => keymap::by_win(code),
        KeyPlatform::Linux => keymap::by_evdev(code),
    }?;
    Some(key.usb)
}

/// The USB usage of a physical key as winit reports it on this platform.
#[cfg(any(windows, target_os = "linux"))]
#[must_use]
pub fn usb_for_physical_key(key: winit::keyboard::PhysicalKey) -> Option<u32> {
    use winit::platform::scancode::PhysicalKeyExtScancode as _;
    usb_from_scancode(KeyPlatform::HERE?, key.to_scancode()?)
}

/// No scancodes on this platform: no key is sent.
#[cfg(not(any(windows, target_os = "linux")))]
#[must_use]
pub fn usb_for_physical_key(_: winit::keyboard::PhysicalKey) -> Option<u32> {
    None
}

/// Whether `key` is the layout's M, the chord's letter, whatever the
/// modifiers and Caps Lock say.
#[cfg(any(windows, target_os = "linux"))]
#[must_use]
pub fn is_m(key: &winit::event::KeyEvent) -> bool {
    use winit::keyboard::Key;
    use winit::platform::modifier_supplement::KeyEventExtModifierSupplement as _;
    matches!(key.key_without_modifiers(), Key::Character(c) if c.eq_ignore_ascii_case("m"))
}

/// Where winit gives no key without its modifiers: the physical M.
#[cfg(not(any(windows, target_os = "linux")))]
#[must_use]
pub fn is_m(key: &winit::event::KeyEvent) -> bool {
    use winit::keyboard::{KeyCode, PhysicalKey};
    key.physical_key == PhysicalKey::Code(KeyCode::KeyM)
}

/// The chord's modifiers by USB usage, the left and the right key of each.
const CONTROL: [u32; 2] = [0x07_00e0, 0x07_00e4];
const ALT: [u32; 2] = [0x07_00e2, 0x07_00e6];
const SHIFT: [u32; 2] = [0x07_00e1, 0x07_00e5];

/// Whether `usb` is one of the chord's modifiers.
fn is_modifier(usb: u32) -> bool {
    [CONTROL, ALT, SHIFT].iter().any(|pair| pair.contains(&usb))
}

/// One physical key event as plain values (a winit `KeyEvent` cannot be
/// built in a test).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyInput {
    /// The key's USB usage, if the key table has a row for it.
    pub usb: Option<u32>,
    /// Down (`true`) or up.
    pub pressed: bool,
    /// The platform's repeat of a held key.
    pub repeat: bool,
    /// winit's replay of a key held when the window got or lost the focus.
    pub synthetic: bool,
    /// The layout's M.
    pub is_m: bool,
}

/// What a key event is to the chord.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChordKey {
    /// Not the chord's.
    Other,
    /// The chord: a fresh M press while Control, Alt and Shift are held.
    Chord,
    /// A later event of the M that made the chord: a repeat, or its release.
    Swallow,
}

/// Follows Control, Alt and Shift, either side, from the physical keys it is
/// fed, and tells the chord. Only a fresh M press makes it: not a repeat,
/// and not winit's replay of a held key, which updates the modifiers only.
#[derive(Debug, Default)]
pub struct Chord {
    /// The modifiers held, by USB usage.
    held: BTreeSet<u32>,
    /// The M that made the chord is down.
    m_down: bool,
    /// That M's USB usage.
    m_usb: Option<u32>,
}

impl Chord {
    /// Feed one key event.
    pub fn feed(&mut self, key: KeyInput) -> ChordKey {
        if let Some(usb) = key.usb
            && is_modifier(usb)
        {
            if key.pressed {
                self.held.insert(usb);
            } else {
                self.held.remove(&usb);
            }
        }
        if self.m_down && key.is_m && key.usb == self.m_usb {
            if !key.pressed {
                self.m_down = false;
            }
            return ChordKey::Swallow;
        }
        if key.pressed && !key.repeat && !key.synthetic && key.is_m && self.modifiers_held() {
            self.m_down = true;
            self.m_usb = key.usb;
            return ChordKey::Chord;
        }
        ChordKey::Other
    }

    /// The window lost the focus: a modifier let go of elsewhere is not
    /// remembered as held.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    fn modifiers_held(&self) -> bool {
        [CONTROL, ALT, SHIFT]
            .iter()
            .all(|pair| pair.iter().any(|usb| self.held.contains(usb)))
    }

    /// Whether an Alt key, either side, is held: a close request that comes
    /// meanwhile is the desktop's or Windows' Alt+F4, whose F4 the window
    /// never sees as a key.
    #[must_use]
    pub fn alt_held(&self) -> bool {
        ALT.iter().any(|usb| self.held.contains(usb))
    }
}

/// F4's USB usage: the key of an Alt+F4 that a close request stands for.
pub const F4: u32 = 0x07_003d;

/// Where a key event of the stream window goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// To the remote computer.
    Host {
        /// The key's USB usage.
        usb: u32,
        /// Down (`true`) or up.
        pressed: bool,
    },
    /// To the window's own controls.
    Window,
    /// Nowhere.
    Nowhere,
    /// The chord with the keyboard on the remote computer: everything held
    /// there is let go of first, then the keyboard stays here.
    TakeBack,
    /// The chord with the keyboard here: it goes back to the remote computer.
    GiveBack,
}

/// Where `key` goes, the chord seeing it first, in control (`open`) and
/// view-only sessions alike. While the keyboard is here (`local`), and in a
/// view-only session, keys go to the window's controls, never to the remote
/// computer. Otherwise a key with a usage goes there, but not winit's replay
/// of a key held when the focus moved (the host lets go of those on focus
/// loss) nor the platform's repeat (the host repeats a held key itself).
#[must_use]
pub fn key_route(chord: &mut Chord, local: bool, open: bool, key: KeyInput) -> Route {
    match chord.feed(key) {
        ChordKey::Chord if open && local => Route::GiveBack,
        ChordKey::Chord => Route::TakeBack,
        ChordKey::Swallow => Route::Nowhere,
        ChordKey::Other if !open || local => Route::Window,
        ChordKey::Other => match key.usb {
            Some(usb) if !key.synthetic && !key.repeat => Route::Host {
                usb,
                pressed: key.pressed,
            },
            _ => Route::Nowhere,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(W3C code, evdev, Windows Set-1, USB usage)`: the letters and digits,
    /// the keys egui has no name for, and the extended (E0) keys whose Windows
    /// scancodes differ from their unextended twins only by the prefix.
    const ROWS: &[(&str, u32, u32, u32)] = &[
        ("KeyA", 0x1e, 0x001e, 0x07_0004),
        ("KeyZ", 0x2c, 0x002c, 0x07_001d),
        ("Digit1", 0x02, 0x0002, 0x07_001e),
        ("Digit0", 0x0b, 0x000b, 0x07_0027),
        ("Enter", 0x1c, 0x001c, 0x07_0028),
        ("NumpadEnter", 0x60, 0xe01c, 0x07_0058),
        ("Escape", 0x01, 0x0001, 0x07_0029),
        ("Backspace", 0x0e, 0x000e, 0x07_002a),
        ("Tab", 0x0f, 0x000f, 0x07_002b),
        ("Space", 0x39, 0x0039, 0x07_002c),
        ("F1", 0x3b, 0x003b, 0x07_003a),
        ("F12", 0x58, 0x0058, 0x07_0045),
        ("PrintScreen", 0x63, 0xe037, 0x07_0046),
        ("ScrollLock", 0x46, 0x0046, 0x07_0047),
        ("Pause", 0x77, 0x0045, 0x07_0048),
        ("Insert", 0x6e, 0xe052, 0x07_0049),
        ("Home", 0x66, 0xe047, 0x07_004a),
        ("Delete", 0x6f, 0xe053, 0x07_004c),
        ("ArrowRight", 0x6a, 0xe04d, 0x07_004f),
        ("ArrowLeft", 0x69, 0xe04b, 0x07_0050),
        ("ArrowDown", 0x6c, 0xe050, 0x07_0051),
        ("ArrowUp", 0x67, 0xe048, 0x07_0052),
        ("NumLock", 0x45, 0xe045, 0x07_0053),
        ("Numpad7", 0x47, 0x0047, 0x07_005f),
        ("IntlBackslash", 0x56, 0x0056, 0x07_0064),
        ("ControlLeft", 0x1d, 0x001d, 0x07_00e0),
        ("ShiftLeft", 0x2a, 0x002a, 0x07_00e1),
        ("AltLeft", 0x38, 0x0038, 0x07_00e2),
        ("MetaLeft", 0x7d, 0xe05b, 0x07_00e3),
        ("ControlRight", 0x61, 0xe01d, 0x07_00e4),
        ("AltRight", 0x64, 0xe038, 0x07_00e6),
        ("MediaPlayPause", 0xa4, 0xe022, 0x0c_00cd),
    ];

    /// The table test for both platforms, on any machine: every row maps from
    /// its evdev code on Linux and from its Set-1 scancode on Windows to the
    /// same USB usage, which is the key's row in the shared table.
    #[test]
    fn scancodes_map_to_the_same_usage_on_both_platforms() {
        for &(code, evdev, win, usb) in ROWS {
            assert_eq!(
                usb_from_scancode(KeyPlatform::Linux, evdev),
                Some(usb),
                "{code} from evdev 0x{evdev:x}"
            );
            assert_eq!(
                usb_from_scancode(KeyPlatform::Windows, win),
                Some(usb),
                "{code} from Set-1 0x{win:04x}"
            );
            assert_eq!(keymap::by_usb(usb).map(|k| k.code), Some(code));
        }
    }

    /// An extended key is not its unextended twin: E0 1D is the right Control,
    /// 1D the left one; E0 1C is the keypad's Enter, 1C the main one.
    #[test]
    fn the_e0_prefix_picks_the_extended_key() {
        let win = |sc| usb_from_scancode(KeyPlatform::Windows, sc);
        assert_eq!(win(0x001d), Some(0x07_00e0));
        assert_eq!(win(0xe01d), Some(0x07_00e4));
        assert_eq!(win(0x001c), Some(0x07_0028));
        assert_eq!(win(0xe01c), Some(0x07_0058));
    }

    /// Codes with no row, and codes too wide to be one, send nothing.
    #[test]
    fn unknown_scancodes_send_nothing() {
        for platform in [KeyPlatform::Linux, KeyPlatform::Windows] {
            assert_eq!(usb_from_scancode(platform, 0), None);
            assert_eq!(usb_from_scancode(platform, 0x1_0000), None);
            assert_eq!(usb_from_scancode(platform, u32::MAX), None);
        }
        // evdev 240 is KEY_UNKNOWN, what winit reports for an unidentified key.
        assert_eq!(usb_from_scancode(KeyPlatform::Linux, 240), None);
    }

    const CTRL: u32 = 0x07_00e0;
    const ALT_L: u32 = 0x07_00e2;
    const SHIFT_L: u32 = 0x07_00e1;
    const KEY_M: u32 = 0x07_0010;
    const KEY_G: u32 = 0x07_000a;
    const END: u32 = 0x07_004d;

    fn press(usb: u32) -> KeyInput {
        KeyInput {
            usb: Some(usb),
            pressed: true,
            repeat: false,
            synthetic: false,
            is_m: usb == KEY_M,
        }
    }

    fn release(usb: u32) -> KeyInput {
        KeyInput {
            pressed: false,
            ..press(usb)
        }
    }

    /// Control, Alt and Shift on either side, in any mix, then M: the chord.
    #[test]
    fn either_side_of_each_modifier_makes_the_chord() {
        for control in CONTROL {
            for alt in ALT {
                for shift in SHIFT {
                    let mut chord = Chord::default();
                    for usb in [control, alt, shift] {
                        assert_eq!(chord.feed(press(usb)), ChordKey::Other);
                    }
                    assert_eq!(
                        chord.feed(press(KEY_M)),
                        ChordKey::Chord,
                        "{control:x} {alt:x} {shift:x}"
                    );
                }
            }
        }
    }

    /// The panic key (Ctrl+Alt+End), gaming mode's exit (Ctrl+Alt+G) and
    /// Ctrl+Alt+M without Shift are not the chord.
    #[test]
    fn the_panic_key_and_the_gaming_chord_are_not_the_chord() {
        for keys in [
            [CTRL, ALT_L, END],
            [CTRL, ALT_L, KEY_G],
            [CTRL, ALT_L, KEY_M],
        ] {
            let mut chord = Chord::default();
            for usb in keys {
                assert_eq!(chord.feed(press(usb)), ChordKey::Other, "{keys:x?}");
            }
        }
    }

    /// winit's replay of held keys when the window gets the focus updates
    /// the modifiers but never makes the chord itself.
    #[test]
    fn a_synthetic_press_never_makes_the_chord() {
        let replayed = |usb| KeyInput {
            synthetic: true,
            ..press(usb)
        };
        let mut chord = Chord::default();
        for usb in [CTRL, ALT_L, SHIFT_L] {
            chord.feed(press(usb));
        }
        assert_eq!(chord.feed(replayed(KEY_M)), ChordKey::Other);
        assert_eq!(chord.feed(release(KEY_M)), ChordKey::Other);
        // Modifiers held when the focus came back count for a real M.
        let mut chord = Chord::default();
        for usb in [CTRL, ALT_L, SHIFT_L] {
            assert_eq!(chord.feed(replayed(usb)), ChordKey::Other);
        }
        assert_eq!(chord.feed(press(KEY_M)), ChordKey::Chord);
    }

    /// The chord's M makes it once; its repeats and its release are
    /// swallowed, so a held chord never flips the keyboard twice.
    #[test]
    fn holding_the_chord_does_not_flip_the_keyboard() {
        let mut chord = Chord::default();
        for usb in [CTRL, ALT_L, SHIFT_L] {
            chord.feed(press(usb));
        }
        let mut seen = vec![chord.feed(press(KEY_M))];
        for _ in 0..10 {
            seen.push(chord.feed(KeyInput {
                repeat: true,
                ..press(KEY_M)
            }));
        }
        seen.push(chord.feed(release(KEY_M)));
        assert_eq!(seen[0], ChordKey::Chord);
        assert!(
            seen[1..].iter().all(|k| *k == ChordKey::Swallow),
            "{seen:?}"
        );
        // The route: the keyboard comes here once; nothing goes anywhere else.
        let mut chord = Chord::default();
        let mut routes = Vec::new();
        let mut local = false;
        for key in [press(CTRL), press(ALT_L), press(SHIFT_L), press(KEY_M)]
            .into_iter()
            .chain((0..10).map(|_| KeyInput {
                repeat: true,
                ..press(KEY_M)
            }))
            .chain([release(KEY_M)])
        {
            let route = key_route(&mut chord, local, true, key);
            if route == Route::TakeBack {
                local = true;
            }
            routes.push(route);
        }
        assert_eq!(
            routes.iter().filter(|r| **r == Route::TakeBack).count(),
            1,
            "{routes:?}"
        );
        assert!(!routes.contains(&Route::GiveBack), "{routes:?}");
        assert!(
            routes[4..].iter().all(|r| *r == Route::Nowhere),
            "{routes:?}"
        );
        assert!(local);
    }

    /// On this machine, through winit itself: each key's physical code goes
    /// through `to_scancode` and the table to the usage whose W3C name is the
    /// winit key's name (winit's `SuperLeft` is W3C `MetaLeft`).
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn winit_physical_keys_map_through_their_scancode() {
        use winit::keyboard::{KeyCode, PhysicalKey};
        let keys = [
            KeyCode::KeyA,
            KeyCode::KeyQ,
            KeyCode::Digit5,
            KeyCode::Enter,
            KeyCode::NumpadEnter,
            KeyCode::Escape,
            KeyCode::F5,
            KeyCode::PrintScreen,
            KeyCode::ScrollLock,
            KeyCode::Pause,
            KeyCode::NumLock,
            KeyCode::ArrowUp,
            KeyCode::PageDown,
            KeyCode::ControlLeft,
            KeyCode::ControlRight,
            KeyCode::AltRight,
            KeyCode::SuperLeft,
            KeyCode::IntlBackslash,
            KeyCode::NumpadAdd,
        ];
        for key in keys {
            let usb = usb_for_physical_key(PhysicalKey::Code(key))
                .unwrap_or_else(|| panic!("{key:?} maps to no usage"));
            let name = format!("{key:?}");
            assert_eq!(
                keymap::by_usb(usb).map(|k| k.code),
                keymap::by_code(&name).map(|k| k.code),
                "{key:?}"
            );
        }
    }
}
