//! Unattended access (`docs/PLAN.md` §B.8): the encrypted grant store, the attempt
//! limiter, the mutation guard, the readiness snapshot, the schedule evaluator, the
//! password policy, the client-side host records and the IPC message types — no
//! networking, no Arti, no I/O beyond the state directory.
//!
//! | Module | Plan | What |
//! |---|---|---|
//! | [`grant`] | §B.8.9 | `UnattendedStore`, `UnattendedGrant`, `FailState`, presets, options merge |
//! | [`codec`] | §B.8.9 | AEAD file format, `K_master` / `K_unatt` / `K_log`, machine-id hash |
//! | [`store`] | §B.8.9, §B.8.13 | `GrantStore`: load rules, write classes, anchor, lock, CRUD, log head |
//! | [`limiter`] | §B.8.5 | `AttemptLimiter`: gate / charge / settle, decay twins, post-F2 helpers |
//! | [`guard`] | §B.8.6.2 | `MutationGuard` + the `ReAuth` / `RemoteSessionActivity` / `Presence` traits |
//! | [`schedule`] | §B.8.7.1 ⑤ | `LocalTz`, windows, DST rules, `next_open_in_s` |
//! | [`readiness`] | §B.8.14 | `ReadinessSnapshot` / `Probe`, the `HOST_NOT_READY` rule, CBOR form |
//! | [`ipc`] | §B.8.7.4 | IPC message types, CBOR codec, `E_*` / `G_*` codes |
//! | [`password`] | §B.8.7.2 | password policy |
//! | [`hosts`] | §B.8.9 | client-side `hosts.toml` |
//! | [`clock`] | §B.8.5.3 | `Clock`, `SystemClock`, `FakeClock` |
//! | `keyring` | §B.8.9 | `K_master` in an OS keychain (`keyring` feature) |

pub mod clock;
pub mod codec;
pub mod grant;
pub mod guard;
pub mod hosts;
pub mod ipc;
#[cfg(feature = "keyring")]
pub mod keyring;
pub mod limiter;
pub mod password;
pub mod readiness;
pub mod schedule;
pub mod store;

pub use crate::session_log::{Actor, BlockEvidence, SessionMode, TransportKind};
pub use clock::{Clock, FakeClock, SystemClock};
pub use codec::{MasterKey, StoreLoadError, derive_k_log, derive_k_unatt, machine_id_hash};
pub use grant::{
    AuthRecord, FailState, FailSummary, GrantId, GrantOptionsError, GrantState, LastUsed, Preset,
    PresetDefaults, SuspendReason, TransportConflict, TransportPolicy, UnattendedGrant,
    UnattendedStore, Window,
};
pub use guard::{
    AdminEffect, AdminOp, AdminOutcome, AllowAllPaired, AllowAllReAuth, AttendedHistory,
    DenyAllReAuth, ExternalOp, FilePairedDevices, GuardError, HostSettings, MasterOnOk,
    MutationGuard, NoServerSetupSource, NoSessionActivity, PairedDevices, Presence, PresenceState,
    RandomServerSetupSource, ReAuth, ReAuthError, RegFinishOutcome, RegStartOk,
    RemoteSessionActivity, ScriptedActivity, ServerSetupSource, SessionLogHistory, SuspendOutcome,
    UnknownPresence, stop_token,
};
pub use ipc::GrantOptions;
pub use limiter::{
    AttemptLimiter, Charged, FailKind, GateOk, GateView, HostTransport, LimiterError, PostF2Ok,
    PostF2Reject, Reject, Settle, gate, ladder_lock_secs, reject_codes,
};
pub use readiness::{Probe, ReadinessSnapshot};
pub use schedule::{FixedOffset, LocalTz, TableTz};
pub use store::{GrantStore, LoadMode, StoreError, StoreStatus, WriteClass};

#[cfg(test)]
mod tests;
