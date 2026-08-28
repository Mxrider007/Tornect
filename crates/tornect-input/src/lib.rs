//! Tornect input (`docs/PLAN.md` §A.3 D11, §B.5): the fixed 16-byte packed input
//! event format, client-side capture/mapping (winit raw events, gamepads), and
//! host-side injection backends (`sendinput`, `cgevent`, `libei` features).
//!
//! Milestone 5 fills this crate in. `unsafe` is allowed only at FFI edges, each
//! block with a `// SAFETY:` comment.

#![deny(unsafe_code)]
