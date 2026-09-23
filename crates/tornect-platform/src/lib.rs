//! OS session services for Tornect (`docs/PLAN.md` §B.8.8).
//!
//! Three modules so far:
//!
//! - [`ipc`] — the owner-only local endpoint of §B.8.7.4 (Unix socket / Windows
//!   named pipe) that the CLI talks to and the host serves.
//! - [`reauth`] — the OS implementations of
//!   [`tornect_core::unattended::guard::ReAuth`]: polkit on Linux, the secure
//!   credential prompt plus `LogonUserW` on Windows.
//! - [`autostart`] — start at login (§B.8.7.5): a systemd user unit on Linux, a
//!   Task Scheduler at-logon task on Windows, and the readiness row that
//!   reports it.
//!
//! Everything else in §B.8.8 — presence, lock state, keep-awake, wake hooks,
//! global hotkeys, capture-excluded windows and the other readiness probes —
//! lands at M6. This crate deliberately holds no stubs for them: an absent
//! module is honest, a stub that answers `Ok` is not.
//!
//! **Direction.** `tornect-platform` depends on `tornect-core` and never the
//! reverse: core *defines* the traits (`ReAuth`, `Presence`,
//! `RemoteSessionActivity`) and this crate implements them (§B.8.14
//! *Ownership*). It does not depend on `tornect-signal`.
//!
//! **Unsafe code** is denied everywhere but in the Windows FFI module, which
//! opts in and carries a `SAFETY:` comment on every block.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod autostart;
pub mod ipc;
pub mod reauth;
#[cfg(windows)]
mod win;
