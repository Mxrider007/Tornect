//! OS session services for Tornect (`docs/PLAN.md` §B.8.8).
//!
//! Ten modules so far:
//!
//! - [`ipc`] — the owner-only local endpoint of §B.8.7.4 (Unix socket / Windows
//!   named pipe) that the CLI talks to and the host serves.
//! - [`reauth`] — the OS implementations of
//!   [`tornect_core::unattended::guard::ReAuth`]: polkit on Linux, the secure
//!   credential prompt plus `LogonUserW` on Windows.
//! - [`autostart`] — start at login (§B.8.7.5): a systemd user unit on Linux, a
//!   Task Scheduler at-logon task on Windows, and the readiness row that
//!   reports it.
//! - [`levels`] — the availability probe of the session levels (§B.2.1): the
//!   row of the table this computer is in (Windows: the location, the UAC
//!   values and the token; Linux: one row).
//! - [`polkit`] — Linux: revoke polkit's remembered approvals of this session
//!   when a Control session starts and whenever the authority reports a
//!   change during it (§B.2.1).
//! - [`helper`] — Windows: the administrator helper's per-session pipe, its
//!   launch through Windows' prompt, and the checks each end makes of the
//!   other (§B.8.7.5; the decisions tested everywhere, the calls Windows-only).
//! - [`helper_task`] — Windows: the on-demand administrator helper task of
//!   unattended administrator sessions: its lifetime, registration, read-back
//!   and ACL checks (§B.8.7.5).
//! - `notify` — Linux: a desktop notification with one action over the session
//!   D-Bus, the block window's best effort where no window can stay on top
//!   (§B.8.6.3).
//! - [`hotkey`] — the panic key (§B.8.7.4), off the UI thread: Windows' low-level
//!   keyboard hook, the GlobalShortcuts portal on Linux.
//! - [`readiness`] — the readiness rows of §B.8.7.1 ⑥ that can be read here; the
//!   others stay `Unknown`.
//!
//! Everything else in §B.8.8 — presence, lock state, keep-awake, wake hooks,
//! capture-excluded windows and the readiness rows not read yet —
//! lands at M6. This crate deliberately holds no stubs for them: an absent
//! module is honest, a stub that answers `Ok` is not.
//!
//! **Direction.** `tornect-platform` depends on `tornect-core` and never the
//! reverse: core *defines* the traits (`ReAuth`, `Presence`,
//! `RemoteSessionActivity`) and this crate implements them (§B.8.14
//! *Ownership*). It does not depend on `tornect-signal`.
//!
//! **Unsafe code** is denied everywhere but in the Windows FFI modules and the
//! Windows half of [`ipc`] (the pipe's descriptor and its peers' accounts),
//! which opt in and carry a `SAFETY:` comment on every block.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod autostart;
pub mod helper;
pub mod helper_task;
pub mod hotkey;
pub mod ipc;
pub mod levels;
#[cfg(target_os = "linux")]
pub mod notify;
pub mod polkit;
pub mod readiness;
pub mod reauth;
#[cfg(windows)]
mod win;
#[cfg(windows)]
mod win_helper;
#[cfg(windows)]
mod win_task;

/// Restrict this process's run-time DLL loads that name no folder to the
/// Windows system directory (review finding E2-4), so none searches the
/// current directory, `PATH` or the executable's folder. `main` calls it
/// first.
#[cfg(windows)]
pub fn restrict_dll_search() -> std::io::Result<()> {
    win::restrict_dll_search()
}

/// Print to the console of the program that started this one, if it has one
/// and the standard output goes nowhere yet: `tornect.exe` is a
/// window-subsystem program, so the window starts no console, and the command
/// line borrows its terminal's (NEEDS-DEVICE(windows)).
#[cfg(windows)]
pub fn attach_parent_console() {
    win::attach_parent_console();
}

/// This user's profile folder (`FOLDERID_Profile`, `C:\Users\<name>`), from
/// the OS rather than from the environment, which whoever starts Tornect
/// controls (review findings E2-2 and F1-4).
#[cfg(windows)]
pub fn user_profile() -> std::io::Result<std::path::PathBuf> {
    win::known_folder(win::KnownFolder::Profile)
}
