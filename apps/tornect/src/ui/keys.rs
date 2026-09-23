//! Keys by physical scancode (`docs/research/slice.md` §2): the stream window
//! reads `WindowEvent::KeyboardInput` itself, before egui sees it (egui drops
//! every key it has no name for: PrintScreen, NumLock, media keys…), takes the
//! platform scancode from winit's `PhysicalKeyExtScancode::to_scancode`, and
//! maps it to the USB HID usage that travels on the wire, with
//! `tornect_input::keymap::by_win` on Windows (Set-1, E0 in the high byte) and
//! `by_evdev` on Linux (X11 and Wayland keycodes minus 8).

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
