//! USB HID usage ↔ Linux evdev ↔ Windows Set-1 scancode ↔ W3C `code`, generated
//! from Chromium's `ui/events/keycodes/dom/dom_code_data.inc` (fetched 2026-09-21,
//! sha256 `841e2c58e6388f14736717eb6e365c8b8e9767788e36339bf1d35a37ab48e5b2`,
//! 612 lines) by keeping every row with a USB usage and an evdev or Windows code.
//! The wire carries the USB usage (page in the high 16 bits: 0x07 keyboard,
//! 0x0C consumer); hosts map it to evdev (portal `NotifyKeyboardKeycode`,
//! XTEST as evdev + 8) or to the Set-1 scancode (`SendInput`, E0 in the high
//! byte ⇒ `KEYEVENTF_EXTENDEDKEY`).
//!
//! Derived from Chromium under its BSD-3-Clause licence (notice below, and in
//! `THIRD_PARTY_NOTICES.md` shipped with binaries).

//
// Copyright 2015 The Chromium Authors
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google LLC nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/// One key: USB HID usage (page << 16 | id), Linux evdev code (0 = none),
/// Windows Set-1 scancode with the E0 prefix in the high byte (0 = none),
/// W3C `KeyboardEvent.code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    /// USB HID usage, page in the high 16 bits.
    pub usb: u32,
    /// Linux evdev code, 0 when the key has none.
    pub evdev: u16,
    /// Windows Set-1 scancode (`0xE0xx` = extended), 0 when the key has none.
    pub win: u16,
    /// W3C `KeyboardEvent.code` name.
    pub code: &'static str,
}

/// Every key, sorted by USB usage.
pub static KEYS: &[Key] = &[
    Key {
        usb: 0x010082,
        evdev: 0x008e,
        win: 0xe05f,
        code: "Sleep",
    },
    Key {
        usb: 0x010083,
        evdev: 0x008f,
        win: 0xe063,
        code: "WakeUp",
    },
    Key {
        usb: 0x010097,
        evdev: 0x01d0,
        win: 0x0000,
        code: "Fn",
    },
    Key {
        usb: 0x0100b5,
        evdev: 0x00e3,
        win: 0x0000,
        code: "DisplayToggleIntExt",
    },
    Key {
        usb: 0x070004,
        evdev: 0x001e,
        win: 0x001e,
        code: "KeyA",
    },
    Key {
        usb: 0x070005,
        evdev: 0x0030,
        win: 0x0030,
        code: "KeyB",
    },
    Key {
        usb: 0x070006,
        evdev: 0x002e,
        win: 0x002e,
        code: "KeyC",
    },
    Key {
        usb: 0x070007,
        evdev: 0x0020,
        win: 0x0020,
        code: "KeyD",
    },
    Key {
        usb: 0x070008,
        evdev: 0x0012,
        win: 0x0012,
        code: "KeyE",
    },
    Key {
        usb: 0x070009,
        evdev: 0x0021,
        win: 0x0021,
        code: "KeyF",
    },
    Key {
        usb: 0x07000a,
        evdev: 0x0022,
        win: 0x0022,
        code: "KeyG",
    },
    Key {
        usb: 0x07000b,
        evdev: 0x0023,
        win: 0x0023,
        code: "KeyH",
    },
    Key {
        usb: 0x07000c,
        evdev: 0x0017,
        win: 0x0017,
        code: "KeyI",
    },
    Key {
        usb: 0x07000d,
        evdev: 0x0024,
        win: 0x0024,
        code: "KeyJ",
    },
    Key {
        usb: 0x07000e,
        evdev: 0x0025,
        win: 0x0025,
        code: "KeyK",
    },
    Key {
        usb: 0x07000f,
        evdev: 0x0026,
        win: 0x0026,
        code: "KeyL",
    },
    Key {
        usb: 0x070010,
        evdev: 0x0032,
        win: 0x0032,
        code: "KeyM",
    },
    Key {
        usb: 0x070011,
        evdev: 0x0031,
        win: 0x0031,
        code: "KeyN",
    },
    Key {
        usb: 0x070012,
        evdev: 0x0018,
        win: 0x0018,
        code: "KeyO",
    },
    Key {
        usb: 0x070013,
        evdev: 0x0019,
        win: 0x0019,
        code: "KeyP",
    },
    Key {
        usb: 0x070014,
        evdev: 0x0010,
        win: 0x0010,
        code: "KeyQ",
    },
    Key {
        usb: 0x070015,
        evdev: 0x0013,
        win: 0x0013,
        code: "KeyR",
    },
    Key {
        usb: 0x070016,
        evdev: 0x001f,
        win: 0x001f,
        code: "KeyS",
    },
    Key {
        usb: 0x070017,
        evdev: 0x0014,
        win: 0x0014,
        code: "KeyT",
    },
    Key {
        usb: 0x070018,
        evdev: 0x0016,
        win: 0x0016,
        code: "KeyU",
    },
    Key {
        usb: 0x070019,
        evdev: 0x002f,
        win: 0x002f,
        code: "KeyV",
    },
    Key {
        usb: 0x07001a,
        evdev: 0x0011,
        win: 0x0011,
        code: "KeyW",
    },
    Key {
        usb: 0x07001b,
        evdev: 0x002d,
        win: 0x002d,
        code: "KeyX",
    },
    Key {
        usb: 0x07001c,
        evdev: 0x0015,
        win: 0x0015,
        code: "KeyY",
    },
    Key {
        usb: 0x07001d,
        evdev: 0x002c,
        win: 0x002c,
        code: "KeyZ",
    },
    Key {
        usb: 0x07001e,
        evdev: 0x0002,
        win: 0x0002,
        code: "Digit1",
    },
    Key {
        usb: 0x07001f,
        evdev: 0x0003,
        win: 0x0003,
        code: "Digit2",
    },
    Key {
        usb: 0x070020,
        evdev: 0x0004,
        win: 0x0004,
        code: "Digit3",
    },
    Key {
        usb: 0x070021,
        evdev: 0x0005,
        win: 0x0005,
        code: "Digit4",
    },
    Key {
        usb: 0x070022,
        evdev: 0x0006,
        win: 0x0006,
        code: "Digit5",
    },
    Key {
        usb: 0x070023,
        evdev: 0x0007,
        win: 0x0007,
        code: "Digit6",
    },
    Key {
        usb: 0x070024,
        evdev: 0x0008,
        win: 0x0008,
        code: "Digit7",
    },
    Key {
        usb: 0x070025,
        evdev: 0x0009,
        win: 0x0009,
        code: "Digit8",
    },
    Key {
        usb: 0x070026,
        evdev: 0x000a,
        win: 0x000a,
        code: "Digit9",
    },
    Key {
        usb: 0x070027,
        evdev: 0x000b,
        win: 0x000b,
        code: "Digit0",
    },
    Key {
        usb: 0x070028,
        evdev: 0x001c,
        win: 0x001c,
        code: "Enter",
    },
    Key {
        usb: 0x070029,
        evdev: 0x0001,
        win: 0x0001,
        code: "Escape",
    },
    Key {
        usb: 0x07002a,
        evdev: 0x000e,
        win: 0x000e,
        code: "Backspace",
    },
    Key {
        usb: 0x07002b,
        evdev: 0x000f,
        win: 0x000f,
        code: "Tab",
    },
    Key {
        usb: 0x07002c,
        evdev: 0x0039,
        win: 0x0039,
        code: "Space",
    },
    Key {
        usb: 0x07002d,
        evdev: 0x000c,
        win: 0x000c,
        code: "Minus",
    },
    Key {
        usb: 0x07002e,
        evdev: 0x000d,
        win: 0x000d,
        code: "Equal",
    },
    Key {
        usb: 0x07002f,
        evdev: 0x001a,
        win: 0x001a,
        code: "BracketLeft",
    },
    Key {
        usb: 0x070030,
        evdev: 0x001b,
        win: 0x001b,
        code: "BracketRight",
    },
    Key {
        usb: 0x070031,
        evdev: 0x002b,
        win: 0x002b,
        code: "Backslash",
    },
    Key {
        usb: 0x070033,
        evdev: 0x0027,
        win: 0x0027,
        code: "Semicolon",
    },
    Key {
        usb: 0x070034,
        evdev: 0x0028,
        win: 0x0028,
        code: "Quote",
    },
    Key {
        usb: 0x070035,
        evdev: 0x0029,
        win: 0x0029,
        code: "Backquote",
    },
    Key {
        usb: 0x070036,
        evdev: 0x0033,
        win: 0x0033,
        code: "Comma",
    },
    Key {
        usb: 0x070037,
        evdev: 0x0034,
        win: 0x0034,
        code: "Period",
    },
    Key {
        usb: 0x070038,
        evdev: 0x0035,
        win: 0x0035,
        code: "Slash",
    },
    Key {
        usb: 0x070039,
        evdev: 0x003a,
        win: 0x003a,
        code: "CapsLock",
    },
    Key {
        usb: 0x07003a,
        evdev: 0x003b,
        win: 0x003b,
        code: "F1",
    },
    Key {
        usb: 0x07003b,
        evdev: 0x003c,
        win: 0x003c,
        code: "F2",
    },
    Key {
        usb: 0x07003c,
        evdev: 0x003d,
        win: 0x003d,
        code: "F3",
    },
    Key {
        usb: 0x07003d,
        evdev: 0x003e,
        win: 0x003e,
        code: "F4",
    },
    Key {
        usb: 0x07003e,
        evdev: 0x003f,
        win: 0x003f,
        code: "F5",
    },
    Key {
        usb: 0x07003f,
        evdev: 0x0040,
        win: 0x0040,
        code: "F6",
    },
    Key {
        usb: 0x070040,
        evdev: 0x0041,
        win: 0x0041,
        code: "F7",
    },
    Key {
        usb: 0x070041,
        evdev: 0x0042,
        win: 0x0042,
        code: "F8",
    },
    Key {
        usb: 0x070042,
        evdev: 0x0043,
        win: 0x0043,
        code: "F9",
    },
    Key {
        usb: 0x070043,
        evdev: 0x0044,
        win: 0x0044,
        code: "F10",
    },
    Key {
        usb: 0x070044,
        evdev: 0x0057,
        win: 0x0057,
        code: "F11",
    },
    Key {
        usb: 0x070045,
        evdev: 0x0058,
        win: 0x0058,
        code: "F12",
    },
    Key {
        usb: 0x070046,
        evdev: 0x0063,
        win: 0xe037,
        code: "PrintScreen",
    },
    Key {
        usb: 0x070047,
        evdev: 0x0046,
        win: 0x0046,
        code: "ScrollLock",
    },
    Key {
        usb: 0x070048,
        evdev: 0x0077,
        win: 0x0045,
        code: "Pause",
    },
    Key {
        usb: 0x070049,
        evdev: 0x006e,
        win: 0xe052,
        code: "Insert",
    },
    Key {
        usb: 0x07004a,
        evdev: 0x0066,
        win: 0xe047,
        code: "Home",
    },
    Key {
        usb: 0x07004b,
        evdev: 0x0068,
        win: 0xe049,
        code: "PageUp",
    },
    Key {
        usb: 0x07004c,
        evdev: 0x006f,
        win: 0xe053,
        code: "Delete",
    },
    Key {
        usb: 0x07004d,
        evdev: 0x006b,
        win: 0xe04f,
        code: "End",
    },
    Key {
        usb: 0x07004e,
        evdev: 0x006d,
        win: 0xe051,
        code: "PageDown",
    },
    Key {
        usb: 0x07004f,
        evdev: 0x006a,
        win: 0xe04d,
        code: "ArrowRight",
    },
    Key {
        usb: 0x070050,
        evdev: 0x0069,
        win: 0xe04b,
        code: "ArrowLeft",
    },
    Key {
        usb: 0x070051,
        evdev: 0x006c,
        win: 0xe050,
        code: "ArrowDown",
    },
    Key {
        usb: 0x070052,
        evdev: 0x0067,
        win: 0xe048,
        code: "ArrowUp",
    },
    Key {
        usb: 0x070053,
        evdev: 0x0045,
        win: 0xe045,
        code: "NumLock",
    },
    Key {
        usb: 0x070054,
        evdev: 0x0062,
        win: 0xe035,
        code: "NumpadDivide",
    },
    Key {
        usb: 0x070055,
        evdev: 0x0037,
        win: 0x0037,
        code: "NumpadMultiply",
    },
    Key {
        usb: 0x070056,
        evdev: 0x004a,
        win: 0x004a,
        code: "NumpadSubtract",
    },
    Key {
        usb: 0x070057,
        evdev: 0x004e,
        win: 0x004e,
        code: "NumpadAdd",
    },
    Key {
        usb: 0x070058,
        evdev: 0x0060,
        win: 0xe01c,
        code: "NumpadEnter",
    },
    Key {
        usb: 0x070059,
        evdev: 0x004f,
        win: 0x004f,
        code: "Numpad1",
    },
    Key {
        usb: 0x07005a,
        evdev: 0x0050,
        win: 0x0050,
        code: "Numpad2",
    },
    Key {
        usb: 0x07005b,
        evdev: 0x0051,
        win: 0x0051,
        code: "Numpad3",
    },
    Key {
        usb: 0x07005c,
        evdev: 0x004b,
        win: 0x004b,
        code: "Numpad4",
    },
    Key {
        usb: 0x07005d,
        evdev: 0x004c,
        win: 0x004c,
        code: "Numpad5",
    },
    Key {
        usb: 0x07005e,
        evdev: 0x004d,
        win: 0x004d,
        code: "Numpad6",
    },
    Key {
        usb: 0x07005f,
        evdev: 0x0047,
        win: 0x0047,
        code: "Numpad7",
    },
    Key {
        usb: 0x070060,
        evdev: 0x0048,
        win: 0x0048,
        code: "Numpad8",
    },
    Key {
        usb: 0x070061,
        evdev: 0x0049,
        win: 0x0049,
        code: "Numpad9",
    },
    Key {
        usb: 0x070062,
        evdev: 0x0052,
        win: 0x0052,
        code: "Numpad0",
    },
    Key {
        usb: 0x070063,
        evdev: 0x0053,
        win: 0x0053,
        code: "NumpadDecimal",
    },
    Key {
        usb: 0x070064,
        evdev: 0x0056,
        win: 0x0056,
        code: "IntlBackslash",
    },
    Key {
        usb: 0x070065,
        evdev: 0x007f,
        win: 0xe05d,
        code: "ContextMenu",
    },
    Key {
        usb: 0x070066,
        evdev: 0x0074,
        win: 0xe05e,
        code: "Power",
    },
    Key {
        usb: 0x070067,
        evdev: 0x0075,
        win: 0x0059,
        code: "NumpadEqual",
    },
    Key {
        usb: 0x070068,
        evdev: 0x00b7,
        win: 0x0064,
        code: "F13",
    },
    Key {
        usb: 0x070069,
        evdev: 0x00b8,
        win: 0x0065,
        code: "F14",
    },
    Key {
        usb: 0x07006a,
        evdev: 0x00b9,
        win: 0x0066,
        code: "F15",
    },
    Key {
        usb: 0x07006b,
        evdev: 0x00ba,
        win: 0x0067,
        code: "F16",
    },
    Key {
        usb: 0x07006c,
        evdev: 0x00bb,
        win: 0x0068,
        code: "F17",
    },
    Key {
        usb: 0x07006d,
        evdev: 0x00bc,
        win: 0x0069,
        code: "F18",
    },
    Key {
        usb: 0x07006e,
        evdev: 0x00bd,
        win: 0x006a,
        code: "F19",
    },
    Key {
        usb: 0x07006f,
        evdev: 0x00be,
        win: 0x006b,
        code: "F20",
    },
    Key {
        usb: 0x070070,
        evdev: 0x00bf,
        win: 0x006c,
        code: "F21",
    },
    Key {
        usb: 0x070071,
        evdev: 0x00c0,
        win: 0x006d,
        code: "F22",
    },
    Key {
        usb: 0x070072,
        evdev: 0x00c1,
        win: 0x006e,
        code: "F23",
    },
    Key {
        usb: 0x070073,
        evdev: 0x00c2,
        win: 0x0076,
        code: "F24",
    },
    Key {
        usb: 0x070074,
        evdev: 0x0086,
        win: 0x0000,
        code: "Open",
    },
    Key {
        usb: 0x070075,
        evdev: 0x008a,
        win: 0xe03b,
        code: "Help",
    },
    Key {
        usb: 0x070077,
        evdev: 0x0084,
        win: 0x0000,
        code: "Select",
    },
    Key {
        usb: 0x070079,
        evdev: 0x0081,
        win: 0x0000,
        code: "Again",
    },
    Key {
        usb: 0x07007a,
        evdev: 0x0083,
        win: 0xe008,
        code: "Undo",
    },
    Key {
        usb: 0x07007b,
        evdev: 0x0089,
        win: 0xe017,
        code: "Cut",
    },
    Key {
        usb: 0x07007c,
        evdev: 0x0085,
        win: 0xe018,
        code: "Copy",
    },
    Key {
        usb: 0x07007d,
        evdev: 0x0087,
        win: 0xe00a,
        code: "Paste",
    },
    Key {
        usb: 0x07007e,
        evdev: 0x0088,
        win: 0x0000,
        code: "Find",
    },
    Key {
        usb: 0x07007f,
        evdev: 0x0071,
        win: 0xe020,
        code: "AudioVolumeMute",
    },
    Key {
        usb: 0x070080,
        evdev: 0x0073,
        win: 0xe030,
        code: "AudioVolumeUp",
    },
    Key {
        usb: 0x070081,
        evdev: 0x0072,
        win: 0xe02e,
        code: "AudioVolumeDown",
    },
    Key {
        usb: 0x070085,
        evdev: 0x0079,
        win: 0x007e,
        code: "NumpadComma",
    },
    Key {
        usb: 0x070087,
        evdev: 0x0059,
        win: 0x0073,
        code: "IntlRo",
    },
    Key {
        usb: 0x070088,
        evdev: 0x005d,
        win: 0x0070,
        code: "KanaMode",
    },
    Key {
        usb: 0x070089,
        evdev: 0x007c,
        win: 0x007d,
        code: "IntlYen",
    },
    Key {
        usb: 0x07008a,
        evdev: 0x005c,
        win: 0x0079,
        code: "Convert",
    },
    Key {
        usb: 0x07008b,
        evdev: 0x005e,
        win: 0x007b,
        code: "NonConvert",
    },
    Key {
        usb: 0x070090,
        evdev: 0x007a,
        win: 0x0072,
        code: "Lang1",
    },
    Key {
        usb: 0x070091,
        evdev: 0x007b,
        win: 0x0071,
        code: "Lang2",
    },
    Key {
        usb: 0x070092,
        evdev: 0x005a,
        win: 0x0078,
        code: "Lang3",
    },
    Key {
        usb: 0x070093,
        evdev: 0x005b,
        win: 0x0077,
        code: "Lang4",
    },
    Key {
        usb: 0x070094,
        evdev: 0x0055,
        win: 0x0000,
        code: "Lang5",
    },
    Key {
        usb: 0x0700b6,
        evdev: 0x00b3,
        win: 0x0000,
        code: "NumpadParenLeft",
    },
    Key {
        usb: 0x0700b7,
        evdev: 0x00b4,
        win: 0x0000,
        code: "NumpadParenRight",
    },
    Key {
        usb: 0x0700e0,
        evdev: 0x001d,
        win: 0x001d,
        code: "ControlLeft",
    },
    Key {
        usb: 0x0700e1,
        evdev: 0x002a,
        win: 0x002a,
        code: "ShiftLeft",
    },
    Key {
        usb: 0x0700e2,
        evdev: 0x0038,
        win: 0x0038,
        code: "AltLeft",
    },
    Key {
        usb: 0x0700e3,
        evdev: 0x007d,
        win: 0xe05b,
        code: "MetaLeft",
    },
    Key {
        usb: 0x0700e4,
        evdev: 0x0061,
        win: 0xe01d,
        code: "ControlRight",
    },
    Key {
        usb: 0x0700e5,
        evdev: 0x0036,
        win: 0x0036,
        code: "ShiftRight",
    },
    Key {
        usb: 0x0700e6,
        evdev: 0x0064,
        win: 0xe038,
        code: "AltRight",
    },
    Key {
        usb: 0x0700e7,
        evdev: 0x007e,
        win: 0xe05c,
        code: "MetaRight",
    },
    Key {
        usb: 0x0c006f,
        evdev: 0x00e1,
        win: 0x0000,
        code: "BrightnessUp",
    },
    Key {
        usb: 0x0c0070,
        evdev: 0x00e0,
        win: 0x0000,
        code: "BrightnessDown",
    },
    Key {
        usb: 0x0c00b0,
        evdev: 0x00cf,
        win: 0x0000,
        code: "MediaPlay",
    },
    Key {
        usb: 0x0c00b1,
        evdev: 0x00c9,
        win: 0x0000,
        code: "MediaPause",
    },
    Key {
        usb: 0x0c00b2,
        evdev: 0x00a7,
        win: 0x0000,
        code: "MediaRecord",
    },
    Key {
        usb: 0x0c00b3,
        evdev: 0x00d0,
        win: 0x0000,
        code: "MediaFastForward",
    },
    Key {
        usb: 0x0c00b4,
        evdev: 0x00a8,
        win: 0x0000,
        code: "MediaRewind",
    },
    Key {
        usb: 0x0c00b5,
        evdev: 0x00a3,
        win: 0xe019,
        code: "MediaTrackNext",
    },
    Key {
        usb: 0x0c00b6,
        evdev: 0x00a5,
        win: 0xe010,
        code: "MediaTrackPrevious",
    },
    Key {
        usb: 0x0c00b7,
        evdev: 0x00a6,
        win: 0xe024,
        code: "MediaStop",
    },
    Key {
        usb: 0x0c00b8,
        evdev: 0x00a1,
        win: 0xe02c,
        code: "Eject",
    },
    Key {
        usb: 0x0c00cd,
        evdev: 0x00a4,
        win: 0xe022,
        code: "MediaPlayPause",
    },
    Key {
        usb: 0x0c0183,
        evdev: 0x00ab,
        win: 0xe06d,
        code: "MediaSelect",
    },
    Key {
        usb: 0x0c018a,
        evdev: 0x009b,
        win: 0xe06c,
        code: "LaunchMail",
    },
    Key {
        usb: 0x0c0192,
        evdev: 0x008c,
        win: 0xe021,
        code: "LaunchApp2",
    },
    Key {
        usb: 0x0c0194,
        evdev: 0x0090,
        win: 0xe06b,
        code: "LaunchApp1",
    },
    Key {
        usb: 0x0c019f,
        evdev: 0x0243,
        win: 0x0000,
        code: "LaunchControlPanel",
    },
    Key {
        usb: 0x0c01a2,
        evdev: 0x0244,
        win: 0x0000,
        code: "SelectTask",
    },
    Key {
        usb: 0x0c01b1,
        evdev: 0x0245,
        win: 0x0000,
        code: "LaunchScreenSaver",
    },
    Key {
        usb: 0x0c01cb,
        evdev: 0x0247,
        win: 0x0000,
        code: "LaunchAssistant",
    },
    Key {
        usb: 0x0c0221,
        evdev: 0x00d9,
        win: 0xe065,
        code: "BrowserSearch",
    },
    Key {
        usb: 0x0c0223,
        evdev: 0x00ac,
        win: 0xe032,
        code: "BrowserHome",
    },
    Key {
        usb: 0x0c0224,
        evdev: 0x009e,
        win: 0xe06a,
        code: "BrowserBack",
    },
    Key {
        usb: 0x0c0225,
        evdev: 0x009f,
        win: 0xe069,
        code: "BrowserForward",
    },
    Key {
        usb: 0x0c0226,
        evdev: 0x0080,
        win: 0xe068,
        code: "BrowserStop",
    },
    Key {
        usb: 0x0c0227,
        evdev: 0x00ad,
        win: 0xe067,
        code: "BrowserRefresh",
    },
    Key {
        usb: 0x0c022a,
        evdev: 0x009c,
        win: 0xe066,
        code: "BrowserFavorites",
    },
    Key {
        usb: 0x0c0232,
        evdev: 0x0174,
        win: 0x0000,
        code: "ZoomToggle",
    },
    Key {
        usb: 0x0c0289,
        evdev: 0x00e8,
        win: 0x0000,
        code: "MailReply",
    },
    Key {
        usb: 0x0c028b,
        evdev: 0x00e9,
        win: 0x0000,
        code: "MailForward",
    },
    Key {
        usb: 0x0c028c,
        evdev: 0x00e7,
        win: 0x0000,
        code: "MailSend",
    },
    Key {
        usb: 0x0c029d,
        evdev: 0x0248,
        win: 0x0000,
        code: "KeyboardLayoutSelect",
    },
    Key {
        usb: 0x0c029f,
        evdev: 0x0078,
        win: 0x0000,
        code: "ShowAllWindows",
    },
];

/// The key with USB usage `usb`.
#[must_use]
pub fn by_usb(usb: u32) -> Option<&'static Key> {
    KEYS.binary_search_by_key(&usb, |k| k.usb)
        .ok()
        .map(|i| &KEYS[i])
}

/// The key a Linux evdev code stands for.
#[must_use]
pub fn by_evdev(evdev: u16) -> Option<&'static Key> {
    if evdev == 0 {
        return None;
    }
    KEYS.iter().find(|k| k.evdev == evdev)
}

/// The key a Windows Set-1 scancode (`0xE0xx` = extended) stands for.
#[must_use]
pub fn by_win(win: u16) -> Option<&'static Key> {
    if win == 0 {
        return None;
    }
    KEYS.iter().find(|k| k.win == win)
}

/// The key with W3C code `code` (winit's `SuperLeft`/`SuperRight` are the
/// W3C `MetaLeft`/`MetaRight`).
#[must_use]
pub fn by_code(code: &str) -> Option<&'static Key> {
    let code = match code {
        "SuperLeft" => "MetaLeft",
        "SuperRight" => "MetaRight",
        other => other,
    };
    KEYS.iter().find(|k| k.code == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique_by_usb() {
        assert!(KEYS.windows(2).all(|w| w[0].usb < w[1].usb));
    }

    #[test]
    fn spot_checks_against_the_chromium_rows() {
        let a = by_usb(0x070004).unwrap();
        assert_eq!((a.evdev, a.win, a.code), (0x1e, 0x1e, "KeyA"));
        let enter = by_code("NumpadEnter").unwrap();
        assert_eq!(
            (enter.usb, enter.evdev, enter.win),
            (0x070058, 0x60, 0xe01c)
        );
        let meta = by_code("SuperLeft").unwrap();
        assert_eq!((meta.usb, meta.evdev, meta.win), (0x0700e3, 0x7d, 0xe05b));
        assert_eq!(by_evdev(0x1e).unwrap().code, "KeyA");
        assert_eq!(by_win(0xe01c).unwrap().code, "NumpadEnter");
        assert!(by_evdev(0).is_none() && by_win(0).is_none());
    }
}
