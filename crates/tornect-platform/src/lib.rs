//! OS session services for Tornect (`docs/PLAN.md` §B.8.8).
//!
//! M1 scaffolds two modules and nothing else, per the §B.8.14 M1 row:
//!
//! - [`ipc`] — the owner-only local endpoint of §B.8.7.4 (Unix socket / Windows
//!   named pipe) that the CLI talks to and the host serves.
//! - [`reauth`] — the OS implementation of [`tornect_core::unattended::guard::ReAuth`].
//!
//! Everything else in §B.8.8 — presence, lock state, keep-awake, autostart
//! installers, wake hooks, global hotkeys, capture-excluded windows and the
//! readiness probes — lands at M6. This crate deliberately holds no stubs for
//! them: an absent module is honest, a stub that answers `Ok` is not.
//!
//! **Direction.** `tornect-platform` depends on `tornect-core` and never the
//! reverse: core *defines* the traits (`ReAuth`, `Presence`,
//! `RemoteSessionActivity`) and this crate implements them (§B.8.14
//! *Ownership*). It does not depend on `tornect-signal`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ipc;
pub mod reauth;
