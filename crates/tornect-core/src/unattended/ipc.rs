//! The local IPC message set of `docs/PLAN.md` §B.8.7.4 — types and their CBOR codec,
//! **no I/O** (the socket / pipe endpoint is `tornect-platform::ipc`'s, the dispatch
//! loop `apps/tornect`'s; fuzz target F4 drives [`decode_request`] / [`decode_response`]
//! with raw bytes).
//!
//! Wire shapes (all maps use integer keys; unknown keys are skipped):
//!
//! ```text
//! IpcRequest  = { 0: id u64, 1: op }
//! IpcResponse = { 0: id u64, 1: ok bool, 2: code u16, 3: detail tstr?, 4: payload bstr? (≤ 60 KiB) }
//! op          = [ tag u32, { fields… } ]      — unknown tags decode to IpcOp::Unknown(tag)
//! ```
//!
//! Every string from the wire is bounded to [`MAX_STRING`] characters, a `Log` page to
//! [`MAX_LINES`] lines, a payload to [`MAX_PAYLOAD`] bytes, `RegFinish.upload` to exactly
//! 192 bytes; a violation is [`IpcCodecError`] with the matching `E_*` code.

use core::fmt;

use minicbor::data::Type;
use minicbor::decode::Decoder;
use minicbor::encode::{Encoder, Write};
use minicbor::{Decode, Encode};

use crate::id::DeviceId;
use crate::session_log::SessionMode;

use super::grant::{GrantId, Window};
use super::readiness::ReadinessSnapshot;

/// Largest `IpcResponse.payload`.
pub const MAX_PAYLOAD: usize = 60 * 1024;
/// Largest frame (§B.3 framing).
pub const MAX_FRAME: usize = 64 * 1024;
/// Longest string from the wire (characters).
pub const MAX_STRING: usize = 256;
/// Longest log line carried in a `LogPage` (characters).
pub const MAX_LINE: usize = 4096;
/// Most lines per `LogPage`.
pub const MAX_LINES: usize = 1024;
/// Most `user_inputs` in a `PolicyInputsPayload`.
pub const MAX_USER_INPUTS: usize = 64;
/// Most windows in `GrantOptions.schedule`.
pub const MAX_WINDOWS: usize = 64;
/// Most grants in a `StatusReport`.
pub const MAX_GRANTS: usize = 1024;
/// Length of `RegFinish.upload` (`RegistrationUpload::serialize()`).
pub const UPLOAD_LEN: usize = 192;

/// Error and guard codes carried in `IpcResponse.code` (`0` = ok).
pub mod codes {
    /// §B.8.4.1 `E_BAD_STATE`.
    pub const E_BAD_STATE: u16 = 0x0001;
    /// §B.8.4.1 `E_BAD_SIG`.
    pub const E_BAD_SIG: u16 = 0x0002;
    /// §B.8.4.1 `E_BAD_MSG_ID`.
    pub const E_BAD_MSG_ID: u16 = 0x0003;
    /// §B.8.4.1 `E_TOO_LARGE`.
    pub const E_TOO_LARGE: u16 = 0x0004;
    /// §B.8.4.1 `E_UNKNOWN_KIND` (an unknown `IpcOp`).
    pub const E_UNKNOWN_KIND: u16 = 0x0005;
    /// §B.8.4.1 `E_VERSION`.
    pub const E_VERSION: u16 = 0x0006;
    /// §B.8.4.1 `E_BAD_LEN`.
    pub const E_BAD_LEN: u16 = 0x0007;
    /// OS re-authentication failed or was refused.
    pub const G_REAUTH_FAILED: u16 = 0x0100;
    /// A remote session is live or ended < 60 s ago.
    pub const G_REMOTE_SESSION_ACTIVE: u16 = 0x0101;
    /// A precondition failed (no grant, attended precondition, options refused…).
    pub const G_PRECONDITION: u16 = 0x0102;
    /// Reserved (was `G_WEAK_PASSWORD`; the CLI enforces the policy via `PolicyInputs`).
    pub const G_RESERVED_0103: u16 = 0x0103;
    /// `K_master` unreadable / unwritable right now.
    pub const G_KEYSTORE_LOCKED: u16 = 0x0104;
    /// Another process holds the store lock.
    pub const G_STORE_LOCKED: u16 = 0x0105;
    /// `RegFinish` without a live `reg_txn`.
    pub const G_NO_TXN: u16 = 0x0106;
}

/// Codec failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpcCodecError {
    /// Not decodable as the expected CBOR shape.
    #[error("malformed IPC message: {0}")]
    Malformed(String),
    /// A collection or string exceeds its bound.
    #[error("{what} too large: {len} > {max}")]
    TooLarge {
        /// Which field.
        what: &'static str,
        /// Observed size.
        len: usize,
        /// Bound.
        max: usize,
    },
    /// A fixed-size byte field has the wrong length.
    #[error("{what}: expected {expected} bytes, found {found}")]
    BadLen {
        /// Which field.
        what: &'static str,
        /// Required length.
        expected: usize,
        /// Observed length.
        found: usize,
    },
}

impl IpcCodecError {
    /// The `E_*` code to answer with.
    #[must_use]
    pub fn code(&self) -> u16 {
        match self {
            Self::Malformed(_) => codes::E_BAD_LEN,
            Self::TooLarge { .. } => codes::E_TOO_LARGE,
            Self::BadLen { .. } => codes::E_BAD_LEN,
        }
    }
}

impl From<minicbor::decode::Error> for IpcCodecError {
    fn from(e: minicbor::decode::Error) -> Self {
        Self::Malformed(e.to_string())
    }
}

/// A request from the CLI / UI to the host.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct IpcRequest {
    /// Correlation id echoed in the response.
    #[n(0)]
    pub id: u64,
    /// The operation.
    #[n(1)]
    pub op: IpcOp,
}

/// The host's answer.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct IpcResponse {
    /// Echo of the request id.
    #[n(0)]
    pub id: u64,
    /// Success flag.
    #[n(1)]
    pub ok: bool,
    /// `0` = ok; else an `E_*` or `G_*` code ([`codes`]).
    #[n(2)]
    pub code: u16,
    /// Human-readable detail (rendered as untrusted text).
    #[n(3)]
    pub detail: Option<String>,
    /// CBOR payload per op (≤ 60 KiB).
    #[n(4)]
    #[cbor(with = "minicbor::bytes")]
    pub payload: Option<Vec<u8>>,
}

impl IpcResponse {
    /// A success without payload.
    #[must_use]
    pub fn ok(id: u64) -> Self {
        Self {
            id,
            ok: true,
            code: 0,
            detail: None,
            payload: None,
        }
    }

    /// A success with a payload.
    #[must_use]
    pub fn ok_with(id: u64, payload: Vec<u8>) -> Self {
        Self {
            id,
            ok: true,
            code: 0,
            detail: None,
            payload: Some(payload),
        }
    }

    /// A failure with a code and detail. The detail is cut to [`MAX_STRING`]
    /// characters: nested error texts (a failed-closed load, refused options) can
    /// exceed the wire bound, and a response the host cannot encode would leave the
    /// CLI without an answer — the decoder enforces the same bound.
    #[must_use]
    pub fn fail(id: u64, code: u16, detail: impl Into<String>) -> Self {
        let detail: String = detail.into();
        let detail = if detail.chars().count() > MAX_STRING {
            detail.chars().take(MAX_STRING).collect()
        } else {
            detail
        };
        Self {
            id,
            ok: false,
            code,
            detail: Some(detail),
            payload: None,
        }
    }
}

/// The policy subset of `UnattendedGrant` (§B.8.7.4); also the argument type of
/// `MutationGuard::create_grant` / `set_options`. A `None` field keeps the current /
/// preset value; `expires_at = Some(0)` means *never*; `max_session_secs = Some(0)`
/// means *no limit*; `schedule = Some([])` clears the schedule.
#[derive(Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct GrantOptions {
    /// Pinned label.
    #[n(0)]
    pub label: Option<String>,
    /// Session mode.
    #[n(1)]
    pub mode: Option<SessionMode>,
    /// Weekly windows.
    #[n(2)]
    pub schedule: Option<Vec<Window>>,
    /// Expiry (unix; `0` = never).
    #[n(3)]
    pub expires_at: Option<u64>,
    /// Auto-renew on use.
    #[n(4)]
    pub auto_renew: Option<bool>,
    /// Maximum session length (`0` = none).
    #[n(5)]
    pub max_session_secs: Option<u32>,
    /// Block window (0–30 s).
    #[n(6)]
    pub block_window_s: Option<u8>,
    /// "Ask before starting".
    #[n(7)]
    pub ask_before_start: Option<bool>,
    /// Refuse while a local user is present.
    #[n(8)]
    pub require_absent: Option<bool>,
    /// Media over Tor only.
    #[n(9)]
    pub require_tor_only: Option<bool>,
    /// Lock the host session at teardown.
    #[n(10)]
    pub lock_on_disconnect: Option<bool>,
    /// Consecutive hard-lock threshold (`0` = off, warned).
    #[n(11)]
    pub hard_lock_after: Option<u32>,
    /// `--waive-attended-check` (warned and logged).
    #[n(12)]
    #[cbor(default)]
    pub waive_attended_precondition: bool,
}

impl GrantOptions {
    /// Enforce the wire bounds.
    pub fn validate(&self) -> Result<(), IpcCodecError> {
        check_str("label", self.label.as_deref())?;
        if let Some(ws) = &self.schedule {
            if ws.len() > MAX_WINDOWS {
                return Err(IpcCodecError::TooLarge {
                    what: "schedule",
                    len: ws.len(),
                    max: MAX_WINDOWS,
                });
            }
            for w in ws {
                check_str("window.tz", Some(&w.tz))?;
            }
        }
        Ok(())
    }
}

/// The operations of §B.8.7.4. `Debug` redacts the registration material: `reg_txn`
/// is the 120 s capability that lets a `RegFinish` land and `upload` / `reg_request`
/// are password-derived OPAQUE bytes (offline-attack material, T4 / A14), so an IPC
/// trace never carries them.
// `RegFinish` carries the 192-byte upload inline: one message per registration, never
// stored in bulk, so the size skew is irrelevant.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq)]
pub enum IpcOp {
    /// → `StatusReport`.
    Status,
    /// Master on (access-increasing).
    On,
    /// Master off (deny-direction).
    Off,
    /// Pause until a unix time (deny-direction).
    Pause {
        /// Unix time.
        until: u64,
    },
    /// Revoke one grant (deny-direction).
    Revoke {
        /// The device.
        device: DeviceId,
    },
    /// Revoke every grant (deny-direction).
    RevokeAll,
    /// Reset a grant's `FailState` (access-increasing).
    Unlock {
        /// The device.
        device: DeviceId,
    },
    /// `Active | Suspended{Admin}` → `Suspended{Local{by: Cli}}` (deny-direction).
    Suspend {
        /// The device.
        device: DeviceId,
    },
    /// Clear any `Suspended{..}` (access-increasing).
    Resume {
        /// The device.
        device: DeviceId,
    },
    /// `Disabled` → `Active` (access-increasing).
    Enable {
        /// The device.
        device: DeviceId,
    },
    /// `Active` → `Disabled{by: Cli}` (deny-direction).
    Disable {
        /// The device.
        device: DeviceId,
    },
    /// `tornect service install` (access-increasing; no store write).
    ServiceInstall {
        /// Windows opt-in elevated task (§B.8.7.5).
        elevated: bool,
    },
    /// `tornect service uninstall` (access-increasing; no store write).
    ServiceUninstall,
    /// → `ReadinessSnapshot`.
    Readiness,
    /// → `LogPage`.
    Log {
        /// Substring filter (empty = all).
        filter: String,
        /// Cursor from the previous page.
        after: Option<u64>,
    },
    /// `tornect panic` (deny-direction).
    Panic,
    /// Backup export (access-increasing).
    BackupExport {
        /// Destination path.
        path: String,
    },
    /// Backup import (access-increasing).
    BackupImport {
        /// Source path.
        path: String,
    },
    /// → `PolicyInputsPayload`.
    PolicyInputs,
    /// Registration start: re-auth here → `RegStartPayload`.
    RegStart {
        /// The device.
        device: DeviceId,
        /// `RegistrationRequest::serialize()`.
        reg_request: [u8; 32],
    },
    /// Registration finish (grant when none exists, set-password otherwise).
    RegFinish {
        /// The device.
        device: DeviceId,
        /// The single-use transaction from `RegStart`.
        reg_txn: [u8; 16],
        /// `RegistrationUpload::serialize()` (192 bytes).
        upload: [u8; UPLOAD_LEN],
        /// `Preset::wire()`.
        preset: u8,
        /// Policy options.
        options: GrantOptions,
    },
    /// An op tag this build does not know (answered `E_UNKNOWN_KIND`).
    Unknown(u32),
}

impl fmt::Debug for IpcOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status
            | Self::On
            | Self::Off
            | Self::RevokeAll
            | Self::ServiceUninstall
            | Self::Readiness
            | Self::Panic
            | Self::PolicyInputs => f.write_str(self.name()),
            Self::Pause { until } => f.debug_struct("Pause").field("until", until).finish(),
            Self::Revoke { device }
            | Self::Unlock { device }
            | Self::Suspend { device }
            | Self::Resume { device }
            | Self::Enable { device }
            | Self::Disable { device } => {
                f.debug_struct(self.name()).field("device", device).finish()
            }
            Self::ServiceInstall { elevated } => f
                .debug_struct("ServiceInstall")
                .field("elevated", elevated)
                .finish(),
            Self::Log { filter, after } => f
                .debug_struct("Log")
                .field("filter", filter)
                .field("after", after)
                .finish(),
            Self::BackupExport { path } | Self::BackupImport { path } => {
                f.debug_struct(self.name()).field("path", path).finish()
            }
            Self::RegStart {
                device,
                reg_request,
            } => f
                .debug_struct("RegStart")
                .field("device", device)
                .field(
                    "reg_request",
                    &format_args!("<{} bytes>", reg_request.len()),
                )
                .finish(),
            Self::RegFinish {
                device,
                reg_txn: _,
                upload,
                preset,
                options,
            } => f
                .debug_struct("RegFinish")
                .field("device", device)
                .field("reg_txn", &format_args!("<redacted>"))
                .field("upload", &format_args!("<{} bytes>", upload.len()))
                .field("preset", preset)
                .field("options", options)
                .finish(),
            Self::Unknown(tag) => f.debug_tuple("Unknown").field(tag).finish(),
        }
    }
}

impl IpcOp {
    /// The wire tag.
    #[must_use]
    pub fn tag(&self) -> u32 {
        match self {
            Self::Status => 0,
            Self::On => 1,
            Self::Off => 2,
            Self::Pause { .. } => 3,
            Self::Revoke { .. } => 4,
            Self::RevokeAll => 5,
            Self::Unlock { .. } => 6,
            Self::Suspend { .. } => 7,
            Self::Resume { .. } => 8,
            Self::Enable { .. } => 9,
            Self::Disable { .. } => 10,
            Self::ServiceInstall { .. } => 11,
            Self::ServiceUninstall => 12,
            Self::Readiness => 13,
            Self::Log { .. } => 14,
            Self::Panic => 15,
            Self::BackupExport { .. } => 16,
            Self::BackupImport { .. } => 17,
            Self::PolicyInputs => 18,
            Self::RegStart { .. } => 19,
            Self::RegFinish { .. } => 20,
            Self::Unknown(t) => *t,
        }
    }

    /// The CLI verb / log `op` name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::On => "on",
            Self::Off => "off",
            Self::Pause { .. } => "pause",
            Self::Revoke { .. } => "revoke",
            Self::RevokeAll => "revoke_all",
            Self::Unlock { .. } => "unlock",
            Self::Suspend { .. } => "suspend",
            Self::Resume { .. } => "resume",
            Self::Enable { .. } => "enable",
            Self::Disable { .. } => "disable",
            Self::ServiceInstall { .. } => "service_install",
            Self::ServiceUninstall => "service_uninstall",
            Self::Readiness => "readiness",
            Self::Log { .. } => "log",
            Self::Panic => "panic",
            Self::BackupExport { .. } => "backup_export",
            Self::BackupImport { .. } => "backup_import",
            Self::PolicyInputs => "policy_inputs",
            Self::RegStart { .. } => "reg_start",
            Self::RegFinish { .. } => "reg_finish",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Enforce the wire bounds.
    pub fn validate(&self) -> Result<(), IpcCodecError> {
        match self {
            Self::Log { filter, .. } => check_str("filter", Some(filter)),
            Self::BackupExport { path } | Self::BackupImport { path } => {
                check_str("path", Some(path))
            }
            Self::RegFinish { options, .. } => options.validate(),
            _ => Ok(()),
        }
    }
}

fn check_str(what: &'static str, s: Option<&str>) -> Result<(), IpcCodecError> {
    if let Some(s) = s {
        let len = s.chars().count();
        if len > MAX_STRING {
            return Err(IpcCodecError::TooLarge {
                what,
                len,
                max: MAX_STRING,
            });
        }
    }
    Ok(())
}

fn field_count(op: &IpcOp) -> u64 {
    match op {
        IpcOp::Pause { .. }
        | IpcOp::Revoke { .. }
        | IpcOp::Unlock { .. }
        | IpcOp::Suspend { .. }
        | IpcOp::Resume { .. }
        | IpcOp::Enable { .. }
        | IpcOp::Disable { .. }
        | IpcOp::ServiceInstall { .. }
        | IpcOp::BackupExport { .. }
        | IpcOp::BackupImport { .. } => 1,
        IpcOp::Log { after, .. } => 1 + u64::from(after.is_some()),
        IpcOp::RegStart { .. } => 2,
        IpcOp::RegFinish { .. } => 5,
        _ => 0,
    }
}

impl<C> Encode<C> for IpcOp {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?.u32(self.tag())?.map(field_count(self))?;
        match self {
            Self::Pause { until } => {
                e.u32(0)?.u64(*until)?;
            }
            Self::Revoke { device }
            | Self::Unlock { device }
            | Self::Suspend { device }
            | Self::Resume { device }
            | Self::Enable { device }
            | Self::Disable { device } => {
                e.u32(0)?;
                device.encode(e, ctx)?;
            }
            Self::ServiceInstall { elevated } => {
                e.u32(0)?.bool(*elevated)?;
            }
            Self::Log { filter, after } => {
                e.u32(0)?.str(filter)?;
                if let Some(a) = after {
                    e.u32(1)?.u64(*a)?;
                }
            }
            Self::BackupExport { path } | Self::BackupImport { path } => {
                e.u32(0)?.str(path)?;
            }
            Self::RegStart {
                device,
                reg_request,
            } => {
                e.u32(0)?;
                device.encode(e, ctx)?;
                e.u32(1)?.bytes(reg_request)?;
            }
            Self::RegFinish {
                device,
                reg_txn,
                upload,
                preset,
                options,
            } => {
                e.u32(0)?;
                device.encode(e, ctx)?;
                e.u32(1)?.bytes(reg_txn)?;
                e.u32(2)?.bytes(upload)?;
                e.u32(3)?.u8(*preset)?;
                e.u32(4)?;
                options.encode(e, ctx)?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Iterate the entries of a (definite or indefinite) map, handing each key to `f`.
fn for_each_entry<'b>(
    d: &mut Decoder<'b>,
    mut f: impl FnMut(u32, &mut Decoder<'b>) -> Result<(), minicbor::decode::Error>,
) -> Result<(), minicbor::decode::Error> {
    let n = d.map()?;
    let mut seen = 0u64;
    loop {
        match n {
            Some(n) if seen >= n => break,
            None if d.datatype()? == Type::Break => {
                d.skip()?;
                break;
            }
            _ => {}
        }
        seen += 1;
        let key = d.u32()?;
        f(key, d)?;
    }
    Ok(())
}

fn fixed<const N: usize>(
    d: &mut Decoder<'_>,
    what: &'static str,
) -> Result<[u8; N], minicbor::decode::Error> {
    let p = d.position();
    let b = d.bytes()?;
    b.try_into().map_err(|_| {
        minicbor::decode::Error::message(what)
            .with_message("wrong length")
            .at(p)
    })
}

fn bounded_str(d: &mut Decoder<'_>, what: &'static str) -> Result<String, minicbor::decode::Error> {
    let p = d.position();
    let s = d.str()?;
    if s.chars().count() > MAX_STRING {
        return Err(minicbor::decode::Error::message(what)
            .with_message("too long")
            .at(p));
    }
    Ok(s.to_owned())
}

fn missing(what: &'static str) -> minicbor::decode::Error {
    minicbor::decode::Error::message(what).with_message("missing field")
}

impl<'b, C> Decode<'b, C> for IpcOp {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let p = d.position();
        if d.array()? != Some(2) {
            return Err(minicbor::decode::Error::message("op must be [tag, fields]").at(p));
        }
        let tag = d.u32()?;
        let mut device: Option<DeviceId> = None;
        let mut until: Option<u64> = None;
        let mut flag: Option<bool> = None;
        let mut text: Option<String> = None;
        let mut after: Option<u64> = None;
        let mut b32: Option<[u8; 32]> = None;
        let mut b16: Option<[u8; 16]> = None;
        let mut upload: Option<[u8; UPLOAD_LEN]> = None;
        let mut preset: Option<u8> = None;
        let mut options: Option<GrantOptions> = None;
        match tag {
            0..=2 | 5 | 12 | 13 | 15 | 18 => {
                d.skip()?;
            }
            3 => for_each_entry(d, |k, d| {
                match k {
                    0 => until = Some(d.u64()?),
                    _ => d.skip()?,
                }
                Ok(())
            })?,
            4 | 6..=10 => for_each_entry(d, |k, d| {
                match k {
                    0 => device = Some(DeviceId::decode(d, ctx)?),
                    _ => d.skip()?,
                }
                Ok(())
            })?,
            11 => for_each_entry(d, |k, d| {
                match k {
                    0 => flag = Some(d.bool()?),
                    _ => d.skip()?,
                }
                Ok(())
            })?,
            14 => for_each_entry(d, |k, d| {
                match k {
                    0 => text = Some(bounded_str(d, "filter")?),
                    1 => after = Some(d.u64()?),
                    _ => d.skip()?,
                }
                Ok(())
            })?,
            16 | 17 => for_each_entry(d, |k, d| {
                match k {
                    0 => text = Some(bounded_str(d, "path")?),
                    _ => d.skip()?,
                }
                Ok(())
            })?,
            19 => for_each_entry(d, |k, d| {
                match k {
                    0 => device = Some(DeviceId::decode(d, ctx)?),
                    1 => b32 = Some(fixed::<32>(d, "reg_request")?),
                    _ => d.skip()?,
                }
                Ok(())
            })?,
            20 => for_each_entry(d, |k, d| {
                match k {
                    0 => device = Some(DeviceId::decode(d, ctx)?),
                    1 => b16 = Some(fixed::<16>(d, "reg_txn")?),
                    2 => upload = Some(fixed::<UPLOAD_LEN>(d, "upload")?),
                    3 => preset = Some(d.u8()?),
                    4 => options = Some(GrantOptions::decode(d, ctx)?),
                    _ => d.skip()?,
                }
                Ok(())
            })?,
            _ => {
                d.skip()?;
                return Ok(Self::Unknown(tag));
            }
        }
        Ok(match tag {
            0 => Self::Status,
            1 => Self::On,
            2 => Self::Off,
            3 => Self::Pause {
                until: until.ok_or_else(|| missing("until"))?,
            },
            4 => Self::Revoke {
                device: device.ok_or_else(|| missing("device"))?,
            },
            5 => Self::RevokeAll,
            6 => Self::Unlock {
                device: device.ok_or_else(|| missing("device"))?,
            },
            7 => Self::Suspend {
                device: device.ok_or_else(|| missing("device"))?,
            },
            8 => Self::Resume {
                device: device.ok_or_else(|| missing("device"))?,
            },
            9 => Self::Enable {
                device: device.ok_or_else(|| missing("device"))?,
            },
            10 => Self::Disable {
                device: device.ok_or_else(|| missing("device"))?,
            },
            11 => Self::ServiceInstall {
                elevated: flag.ok_or_else(|| missing("elevated"))?,
            },
            12 => Self::ServiceUninstall,
            13 => Self::Readiness,
            14 => Self::Log {
                filter: text.ok_or_else(|| missing("filter"))?,
                after,
            },
            15 => Self::Panic,
            16 => Self::BackupExport {
                path: text.ok_or_else(|| missing("path"))?,
            },
            17 => Self::BackupImport {
                path: text.ok_or_else(|| missing("path"))?,
            },
            18 => Self::PolicyInputs,
            19 => Self::RegStart {
                device: device.ok_or_else(|| missing("device"))?,
                reg_request: b32.ok_or_else(|| missing("reg_request"))?,
            },
            20 => Self::RegFinish {
                device: device.ok_or_else(|| missing("device"))?,
                reg_txn: b16.ok_or_else(|| missing("reg_txn"))?,
                upload: upload.ok_or_else(|| missing("upload"))?,
                preset: preset.ok_or_else(|| missing("preset"))?,
                options: options.unwrap_or_default(),
            },
            _ => Self::Unknown(tag),
        })
    }
}

/// `Status` payload.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct StatusReport {
    /// Master switch.
    #[n(0)]
    pub enabled: bool,
    /// Pause end, if paused.
    #[n(1)]
    pub paused_until: Option<u64>,
    /// One summary per grant.
    #[n(2)]
    pub grants: Vec<GrantSummary>,
    /// Current readiness.
    #[n(3)]
    pub readiness: ReadinessSnapshot,
    /// `0` os_keychain · `1` file.
    #[n(4)]
    pub keystore_kind: u8,
}

/// One grant as shown by `tornect unattended status` (§B.8.7.3 state list).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct GrantSummary {
    /// Grant id.
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub id: GrantId,
    /// Device.
    #[n(1)]
    pub device: DeviceId,
    /// Pinned label.
    #[n(2)]
    pub label: String,
    /// `Preset::wire()`.
    #[n(3)]
    pub preset: u8,
    /// `SessionMode::wire()`.
    #[n(4)]
    pub mode: u8,
    /// `active` · `not_yet_active` · `disabled:<by>` · `suspended:<reason>` ·
    /// `locked:<secs>` · `hard_locked` · `expired`.
    #[n(5)]
    pub state: String,
    /// Expiry.
    #[n(6)]
    pub expires_at: Option<u64>,
    /// Last successful use.
    #[n(7)]
    pub last_used: Option<u64>,
    /// `FailState.since_unlock`.
    #[n(8)]
    pub failures_since_unlock: u32,
}

impl GrantSummary {
    /// Summarize a grant for `Status` at `now`, given its running lock (seconds).
    #[must_use]
    pub fn from_grant(
        grant: &super::grant::UnattendedGrant,
        now: u64,
        lock_remaining_s: u32,
    ) -> Self {
        Self {
            id: grant.id,
            device: grant.device,
            label: grant.label.clone(),
            preset: grant.preset.wire(),
            mode: grant.mode.wire(),
            state: state_label(grant, now, lock_remaining_s),
            expires_at: grant.expires_at,
            last_used: grant.last_used.map(|l| l.at),
            failures_since_unlock: grant.fail.since_unlock,
        }
    }
}

/// The manager's state label of §B.8.7.3, in precedence order: `disabled:<by>` ·
/// `expired` · `suspended:<reason>` · `hard_locked` · `locked:<secs>` · `not_yet_active`
/// · `active`.
#[must_use]
pub fn state_label(
    grant: &super::grant::UnattendedGrant,
    now: u64,
    lock_remaining_s: u32,
) -> String {
    use super::grant::GrantState;
    match grant.state {
        GrantState::Disabled { by, .. } => return format!("disabled:{}", actor_label(by)),
        GrantState::Suspended { reason, .. } if grant.expired_at(now) => {
            let _ = reason;
            return "expired".to_owned();
        }
        GrantState::Suspended { reason, .. } => return format!("suspended:{}", reason.log_name()),
        GrantState::Active => {}
    }
    if grant.expired_at(now) {
        "expired".to_owned()
    } else if grant.fail.hard_locked {
        "hard_locked".to_owned()
    } else if lock_remaining_s > 0 {
        format!("locked:{lock_remaining_s}")
    } else if now < grant.active_from {
        "not_yet_active".to_owned()
    } else {
        "active".to_owned()
    }
}

fn actor_label(a: crate::session_log::Actor) -> &'static str {
    use crate::session_log::Actor;
    match a {
        Actor::Ui => "ui",
        Actor::Cli => "cli",
        Actor::Import => "import",
        Actor::Restore => "restore",
    }
}

/// `Log` payload (paged, ≤ 60 KiB per response).
#[derive(Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct LogPage {
    /// Raw log lines.
    #[n(0)]
    pub lines: Vec<String>,
    /// Cursor for the following `Log { after }`.
    #[n(1)]
    pub next: Option<u64>,
}

/// `PolicyInputs` payload (§B.8.7.2 inputs; the CLI runs `zxcvbn` locally).
#[derive(Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct PolicyInputsPayload {
    /// Host name, device labels, onion address, OS user name, "tornect".
    #[n(0)]
    pub user_inputs: Vec<String>,
    /// 3, or 4 on a file-keystore host.
    #[n(1)]
    pub min_score: u8,
}

/// `On` payload: the emergency stop card of §B.8.7.4, shown once and never stored.
///
/// It travels as a payload rather than in `IpcResponse.detail` because `detail`
/// is a human-readable string that ends up in error messages and logs; a
/// 16-byte secret must not. `Debug` redacts it for the same reason, and it is
/// wiped on drop (§B.8.7.2, A14).
#[derive(Clone, PartialEq, Eq, Encode, Decode, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cbor(map)]
pub struct MasterOnPayload {
    /// The stop code, shown once at enable time (§B.8.7.4).
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub stop_code: [u8; 16],
}

impl fmt::Debug for MasterOnPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterOnPayload")
            .field("stop_code", &format_args!("<redacted>"))
            .finish()
    }
}

/// `RegStart` payload. `Debug` redacts both members (A14: no KE bytes or capabilities
/// in traces), and both are wiped on drop.
#[derive(Clone, PartialEq, Eq, Encode, Decode, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cbor(map)]
pub struct RegStartPayload {
    /// `RegistrationResponse::serialize()` (64 bytes).
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub reg_response: [u8; 64],
    /// Single-use transaction (≤ 120 s, bound to the device).
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub reg_txn: [u8; 16],
}

impl fmt::Debug for RegStartPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegStartPayload")
            .field(
                "reg_response",
                &format_args!("<{} bytes>", self.reg_response.len()),
            )
            .field("reg_txn", &format_args!("<redacted>"))
            .finish()
    }
}

/// Encode a request.
pub fn encode_request(req: &IpcRequest) -> Result<Vec<u8>, IpcCodecError> {
    req.op.validate()?;
    let bytes = minicbor::to_vec(req).map_err(|e| IpcCodecError::Malformed(e.to_string()))?;
    check_frame(bytes)
}

/// Decode a request (bounds enforced; unknown ops decode to [`IpcOp::Unknown`]).
pub fn decode_request(bytes: &[u8]) -> Result<IpcRequest, IpcCodecError> {
    if bytes.len() > MAX_FRAME {
        return Err(IpcCodecError::TooLarge {
            what: "frame",
            len: bytes.len(),
            max: MAX_FRAME,
        });
    }
    let req: IpcRequest = minicbor::decode(bytes)?;
    req.op.validate()?;
    Ok(req)
}

/// Encode a response.
pub fn encode_response(resp: &IpcResponse) -> Result<Vec<u8>, IpcCodecError> {
    check_response(resp)?;
    let bytes = minicbor::to_vec(resp).map_err(|e| IpcCodecError::Malformed(e.to_string()))?;
    check_frame(bytes)
}

/// Decode a response (bounds enforced).
pub fn decode_response(bytes: &[u8]) -> Result<IpcResponse, IpcCodecError> {
    if bytes.len() > MAX_FRAME {
        return Err(IpcCodecError::TooLarge {
            what: "frame",
            len: bytes.len(),
            max: MAX_FRAME,
        });
    }
    let resp: IpcResponse = minicbor::decode(bytes)?;
    check_response(&resp)?;
    Ok(resp)
}

fn check_response(resp: &IpcResponse) -> Result<(), IpcCodecError> {
    check_str("detail", resp.detail.as_deref())?;
    if let Some(p) = &resp.payload
        && p.len() > MAX_PAYLOAD
    {
        return Err(IpcCodecError::TooLarge {
            what: "payload",
            len: p.len(),
            max: MAX_PAYLOAD,
        });
    }
    Ok(())
}

fn check_frame(bytes: Vec<u8>) -> Result<Vec<u8>, IpcCodecError> {
    if bytes.len() > MAX_FRAME {
        return Err(IpcCodecError::TooLarge {
            what: "frame",
            len: bytes.len(),
            max: MAX_FRAME,
        });
    }
    Ok(bytes)
}

/// Encode a payload struct (≤ 60 KiB).
pub fn encode_payload<T: Encode<()>>(value: &T) -> Result<Vec<u8>, IpcCodecError> {
    let bytes = minicbor::to_vec(value).map_err(|e| IpcCodecError::Malformed(e.to_string()))?;
    if bytes.len() > MAX_PAYLOAD {
        return Err(IpcCodecError::TooLarge {
            what: "payload",
            len: bytes.len(),
            max: MAX_PAYLOAD,
        });
    }
    Ok(bytes)
}

/// Decode a payload struct.
pub fn decode_payload<'b, T: Decode<'b, ()>>(bytes: &'b [u8]) -> Result<T, IpcCodecError> {
    if bytes.len() > MAX_PAYLOAD {
        return Err(IpcCodecError::TooLarge {
            what: "payload",
            len: bytes.len(),
            max: MAX_PAYLOAD,
        });
    }
    Ok(minicbor::decode(bytes)?)
}

impl StatusReport {
    /// Enforce the wire bounds.
    pub fn validate(&self) -> Result<(), IpcCodecError> {
        if self.grants.len() > MAX_GRANTS {
            return Err(IpcCodecError::TooLarge {
                what: "grants",
                len: self.grants.len(),
                max: MAX_GRANTS,
            });
        }
        for g in &self.grants {
            check_str("label", Some(&g.label))?;
            check_str("state", Some(&g.state))?;
        }
        Ok(())
    }
}

impl LogPage {
    /// Enforce the wire bounds.
    pub fn validate(&self) -> Result<(), IpcCodecError> {
        if self.lines.len() > MAX_LINES {
            return Err(IpcCodecError::TooLarge {
                what: "lines",
                len: self.lines.len(),
                max: MAX_LINES,
            });
        }
        for l in &self.lines {
            let len = l.chars().count();
            if len > MAX_LINE {
                return Err(IpcCodecError::TooLarge {
                    what: "line",
                    len,
                    max: MAX_LINE,
                });
            }
        }
        Ok(())
    }

    /// Build a page from `lines` starting after cursor `after`, filling at most
    /// [`MAX_LINES`] lines / ~[`MAX_PAYLOAD`] bytes; `next` is set when more remain.
    #[must_use]
    pub fn page(lines: &[String], filter: &str, after: Option<u64>) -> Self {
        let start = after.map_or(0, |a| {
            usize::try_from(a.saturating_add(1)).unwrap_or(usize::MAX)
        });
        let mut out = Self::default();
        let mut bytes = 0usize;
        for (i, line) in lines.iter().enumerate().skip(start) {
            if !filter.is_empty() && !line.contains(filter) {
                continue;
            }
            let l: String = line.chars().take(MAX_LINE).collect();
            if out.lines.len() >= MAX_LINES || bytes + l.len() + 8 > MAX_PAYLOAD - 1024 {
                out.next = Some(u64::try_from(i.saturating_sub(1)).unwrap_or(u64::MAX));
                break;
            }
            bytes += l.len() + 8;
            out.lines.push(l);
        }
        out
    }
}

impl PolicyInputsPayload {
    /// Enforce the wire bounds.
    pub fn validate(&self) -> Result<(), IpcCodecError> {
        if self.user_inputs.len() > MAX_USER_INPUTS {
            return Err(IpcCodecError::TooLarge {
                what: "user_inputs",
                len: self.user_inputs.len(),
                max: MAX_USER_INPUTS,
            });
        }
        for s in &self.user_inputs {
            check_str("user_input", Some(s))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn dev(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 32])
    }

    fn all_ops() -> Vec<IpcOp> {
        vec![
            IpcOp::Status,
            IpcOp::On,
            IpcOp::Off,
            IpcOp::Pause {
                until: 1_700_000_000,
            },
            IpcOp::Revoke { device: dev(1) },
            IpcOp::RevokeAll,
            IpcOp::Unlock { device: dev(2) },
            IpcOp::Suspend { device: dev(3) },
            IpcOp::Resume { device: dev(4) },
            IpcOp::Enable { device: dev(5) },
            IpcOp::Disable { device: dev(6) },
            IpcOp::ServiceInstall { elevated: true },
            IpcOp::ServiceUninstall,
            IpcOp::Readiness,
            IpcOp::Log {
                filter: "grant".into(),
                after: Some(17),
            },
            IpcOp::Log {
                filter: String::new(),
                after: None,
            },
            IpcOp::Panic,
            IpcOp::BackupExport {
                path: "/tmp/x".into(),
            },
            IpcOp::BackupImport {
                path: "/tmp/y".into(),
            },
            IpcOp::PolicyInputs,
            IpcOp::RegStart {
                device: dev(7),
                reg_request: [9; 32],
            },
            IpcOp::RegFinish {
                device: dev(8),
                reg_txn: [1; 16],
                upload: [2; UPLOAD_LEN],
                preset: 2,
                options: GrantOptions {
                    label: Some("Laptop".into()),
                    mode: Some(SessionMode::ViewOnly),
                    schedule: Some(vec![Window {
                        days: 0x1F,
                        start_min: 540,
                        end_min: 1020,
                        tz: "UTC+01:00".into(),
                    }]),
                    expires_at: Some(0),
                    max_session_secs: Some(3600),
                    waive_attended_precondition: true,
                    ..GrantOptions::default()
                },
            },
            IpcOp::Unknown(99),
        ]
    }

    #[test]
    fn every_op_roundtrips_with_its_tag() {
        for (i, op) in all_ops().into_iter().enumerate() {
            let req = IpcRequest {
                id: u64::try_from(i).unwrap(),
                op: op.clone(),
            };
            let bytes = encode_request(&req).unwrap();
            let back = decode_request(&bytes).unwrap();
            assert_eq!(back, req, "{op:?}");
            assert_eq!(back.op.tag(), op.tag());
        }
    }

    #[test]
    fn unknown_tags_and_unknown_keys_are_tolerated() {
        // tag 77 with a body: decodes to Unknown(77)
        let mut e = Encoder::new(Vec::new());
        e.map(2)
            .unwrap()
            .u32(0)
            .unwrap()
            .u64(5)
            .unwrap()
            .u32(1)
            .unwrap()
            .array(2)
            .unwrap()
            .u32(77)
            .unwrap()
            .map(1)
            .unwrap()
            .u32(0)
            .unwrap()
            .str("whatever")
            .unwrap();
        let req = decode_request(&e.into_writer()).unwrap();
        assert_eq!(req.op, IpcOp::Unknown(77));
        assert_eq!(req.op.tag(), 77);
        // an unknown key inside a known op body is skipped
        let mut e = Encoder::new(Vec::new());
        e.map(2)
            .unwrap()
            .u32(0)
            .unwrap()
            .u64(6)
            .unwrap()
            .u32(1)
            .unwrap()
            .array(2)
            .unwrap()
            .u32(3)
            .unwrap()
            .map(2)
            .unwrap()
            .u32(9)
            .unwrap()
            .str("future")
            .unwrap()
            .u32(0)
            .unwrap()
            .u64(42)
            .unwrap();
        let req = decode_request(&e.into_writer()).unwrap();
        assert_eq!(req.op, IpcOp::Pause { until: 42 });
        // an unknown key in the request map itself
        let mut e = Encoder::new(Vec::new());
        e.map(3)
            .unwrap()
            .u32(0)
            .unwrap()
            .u64(7)
            .unwrap()
            .u32(1)
            .unwrap()
            .array(2)
            .unwrap()
            .u32(0)
            .unwrap()
            .map(0)
            .unwrap()
            .u32(5)
            .unwrap()
            .bool(true)
            .unwrap();
        assert_eq!(decode_request(&e.into_writer()).unwrap().op, IpcOp::Status);
    }

    #[test]
    fn bounds_are_enforced() {
        let long = "x".repeat(MAX_STRING + 1);
        let req = IpcRequest {
            id: 1,
            op: IpcOp::Log {
                filter: long.clone(),
                after: None,
            },
        };
        assert!(matches!(
            encode_request(&req),
            Err(IpcCodecError::TooLarge { what: "filter", .. })
        ));
        // the same bound on decode: build the frame by hand
        let mut e = Encoder::new(Vec::new());
        e.map(2)
            .unwrap()
            .u32(0)
            .unwrap()
            .u64(1)
            .unwrap()
            .u32(1)
            .unwrap()
            .array(2)
            .unwrap()
            .u32(16)
            .unwrap()
            .map(1)
            .unwrap()
            .u32(0)
            .unwrap()
            .str(&long)
            .unwrap();
        let err = decode_request(&e.into_writer()).unwrap_err();
        assert_eq!(err.code(), codes::E_BAD_LEN);
        // wrong upload length
        let mut e = Encoder::new(Vec::new());
        e.map(2)
            .unwrap()
            .u32(0)
            .unwrap()
            .u64(1)
            .unwrap()
            .u32(1)
            .unwrap()
            .array(2)
            .unwrap()
            .u32(20)
            .unwrap()
            .map(4)
            .unwrap()
            .u32(0)
            .unwrap()
            .bytes(&[1; 32])
            .unwrap()
            .u32(1)
            .unwrap()
            .bytes(&[1; 16])
            .unwrap()
            .u32(2)
            .unwrap()
            .bytes(&[1; 191])
            .unwrap()
            .u32(3)
            .unwrap()
            .u8(0)
            .unwrap();
        assert!(decode_request(&e.into_writer()).is_err());
        // payload bound
        let resp = IpcResponse::ok_with(1, vec![0; MAX_PAYLOAD + 1]);
        assert!(matches!(
            encode_response(&resp),
            Err(IpcCodecError::TooLarge {
                what: "payload",
                ..
            })
        ));
        let resp = IpcResponse::fail(1, codes::G_NO_TXN, "no txn");
        let bytes = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&bytes).unwrap(), resp);
        // a nested error text longer than the bound is cut, never unencodable
        let resp = IpcResponse::fail(2, codes::G_PRECONDITION, "é".repeat(300));
        assert_eq!(
            resp.detail.as_deref().map(|d| d.chars().count()),
            Some(MAX_STRING)
        );
        let bytes = encode_response(&resp).unwrap();
        assert_eq!(decode_response(&bytes).unwrap(), resp);
        let raw = IpcResponse {
            id: 3,
            ok: false,
            code: codes::G_PRECONDITION,
            detail: Some("x".repeat(MAX_STRING + 1)),
            payload: None,
        };
        assert!(matches!(
            encode_response(&raw),
            Err(IpcCodecError::TooLarge { what: "detail", .. })
        ));
        assert!(decode_request(&vec![0u8; MAX_FRAME + 1]).is_err());
        assert!(decode_request(b"\xff\xff").is_err());
        assert!(decode_request(b"").is_err());
    }

    #[test]
    fn debug_output_redacts_registration_material() {
        let req = IpcRequest {
            id: 9,
            op: IpcOp::RegFinish {
                device: dev(8),
                reg_txn: [0x5a; 16],
                upload: [0xab; UPLOAD_LEN],
                preset: 0,
                options: GrantOptions::default(),
            },
        };
        let s = format!("{req:?}");
        assert!(!s.contains("90"), "{s}");
        assert!(!s.contains("171"), "{s}");
        assert!(!s.contains(&hex::encode([0x5a; 16])));
        assert!(s.contains("reg_txn: <redacted>"), "{s}");
        assert!(s.contains("upload: <192 bytes>"), "{s}");
        let start = IpcOp::RegStart {
            device: dev(7),
            reg_request: [0x33; 32],
        };
        let s = format!("{start:?}");
        assert!(!s.contains("51"), "{s}");
        assert!(s.contains("reg_request: <32 bytes>"), "{s}");
        let payload = RegStartPayload {
            reg_response: [0x44; 64],
            reg_txn: [0x55; 16],
        };
        let s = format!("{payload:?}");
        assert!(!s.contains("68") && !s.contains("85"), "{s}");
        assert!(s.contains("<64 bytes>") && s.contains("<redacted>"), "{s}");
        // the plain ops keep a readable form
        assert_eq!(format!("{:?}", IpcOp::Status), "status");
        assert_eq!(
            format!("{:?}", IpcOp::Pause { until: 7 }),
            "Pause { until: 7 }"
        );
    }

    #[test]
    fn payload_structs_roundtrip_and_page() {
        let status = StatusReport {
            enabled: true,
            paused_until: Some(5),
            grants: vec![GrantSummary {
                id: [3; 8],
                device: dev(1),
                label: "Laptop".into(),
                preset: 0,
                mode: 0,
                state: "locked:120".into(),
                expires_at: Some(9),
                last_used: None,
                failures_since_unlock: 4,
            }],
            readiness: ReadinessSnapshot::unknown(),
            keystore_kind: 1,
        };
        status.validate().unwrap();
        let bytes = encode_payload(&status).unwrap();
        assert_eq!(decode_payload::<StatusReport>(&bytes).unwrap(), status);
        let inputs = PolicyInputsPayload {
            user_inputs: vec!["host".into(), "tornect".into()],
            min_score: 4,
        };
        let bytes = encode_payload(&inputs).unwrap();
        assert_eq!(
            decode_payload::<PolicyInputsPayload>(&bytes).unwrap(),
            inputs
        );
        let rs = RegStartPayload {
            reg_response: [4; 64],
            reg_txn: [5; 16],
        };
        let bytes = encode_payload(&rs).unwrap();
        assert_eq!(decode_payload::<RegStartPayload>(&bytes).unwrap(), rs);
        let lines: Vec<String> = (0..3000)
            .map(|i| format!("{{\"n\":{i},\"event\":\"grant_created\"}}"))
            .collect();
        let page = LogPage::page(&lines, "", None);
        page.validate().unwrap();
        assert_eq!(page.lines.len(), MAX_LINES);
        assert_eq!(page.next, Some(1023));
        let page2 = LogPage::page(&lines, "", page.next);
        assert_eq!(page2.lines[0], lines[1024]);
        let filtered = LogPage::page(&lines, "\"n\":29,", None);
        assert_eq!(filtered.lines.len(), 1);
        assert_eq!(filtered.lines[0], lines[29]);
        assert_eq!(filtered.next, None);
        let bytes = encode_payload(&page).unwrap();
        assert!(bytes.len() <= MAX_PAYLOAD);
        assert_eq!(decode_payload::<LogPage>(&bytes).unwrap(), page);
    }

    fn arb_device() -> impl Strategy<Value = DeviceId> {
        any::<[u8; 32]>().prop_map(DeviceId::from_bytes)
    }

    fn arb_options() -> impl Strategy<Value = GrantOptions> {
        (
            proptest::option::of("[a-z]{0,20}"),
            proptest::option::of(prop_oneof![
                Just(SessionMode::Control),
                Just(SessionMode::ViewOnly)
            ]),
            proptest::option::of(proptest::collection::vec(
                (0u8..=0x7f, 0u16..1440, 0u16..=1440, "[A-Za-z/+:0-9]{1,16}").prop_map(
                    |(days, s, e, tz)| Window {
                        days,
                        start_min: s,
                        end_min: e,
                        tz,
                    },
                ),
                0..4,
            )),
            proptest::option::of(any::<u64>()),
            proptest::option::of(any::<bool>()),
            proptest::option::of(any::<u32>()),
            proptest::option::of(any::<u8>()),
            proptest::option::of(any::<bool>()),
            proptest::option::of(any::<u32>()),
            any::<bool>(),
        )
            .prop_map(
                |(
                    label,
                    mode,
                    schedule,
                    expires_at,
                    auto_renew,
                    max_session_secs,
                    block_window_s,
                    ask,
                    hard,
                    waive,
                )| GrantOptions {
                    label,
                    mode,
                    schedule,
                    expires_at,
                    auto_renew,
                    max_session_secs,
                    block_window_s,
                    ask_before_start: ask,
                    require_absent: None,
                    require_tor_only: auto_renew,
                    lock_on_disconnect: ask,
                    hard_lock_after: hard,
                    waive_attended_precondition: waive,
                },
            )
    }

    fn arb_op() -> impl Strategy<Value = IpcOp> {
        prop_oneof![
            Just(IpcOp::Status),
            Just(IpcOp::On),
            Just(IpcOp::Off),
            any::<u64>().prop_map(|until| IpcOp::Pause { until }),
            arb_device().prop_map(|device| IpcOp::Revoke { device }),
            Just(IpcOp::RevokeAll),
            arb_device().prop_map(|device| IpcOp::Unlock { device }),
            arb_device().prop_map(|device| IpcOp::Suspend { device }),
            arb_device().prop_map(|device| IpcOp::Resume { device }),
            arb_device().prop_map(|device| IpcOp::Enable { device }),
            arb_device().prop_map(|device| IpcOp::Disable { device }),
            any::<bool>().prop_map(|elevated| IpcOp::ServiceInstall { elevated }),
            Just(IpcOp::ServiceUninstall),
            Just(IpcOp::Readiness),
            ("[a-z ]{0,30}", proptest::option::of(any::<u64>()))
                .prop_map(|(filter, after)| IpcOp::Log { filter, after }),
            Just(IpcOp::Panic),
            "[a-z/]{1,40}".prop_map(|path| IpcOp::BackupExport { path }),
            "[a-z/]{1,40}".prop_map(|path| IpcOp::BackupImport { path }),
            Just(IpcOp::PolicyInputs),
            (arb_device(), any::<[u8; 32]>()).prop_map(|(device, reg_request)| IpcOp::RegStart {
                device,
                reg_request
            }),
            (
                arb_device(),
                any::<[u8; 16]>(),
                any::<u8>(),
                any::<u8>(),
                arb_options()
            )
                .prop_map(|(device, reg_txn, fill, preset, options)| {
                    IpcOp::RegFinish {
                        device,
                        reg_txn,
                        upload: [fill; UPLOAD_LEN],
                        preset,
                        options,
                    }
                }),
            (21u32..).prop_map(IpcOp::Unknown),
        ]
    }

    proptest! {
        #[test]
        fn request_roundtrip(id in any::<u64>(), op in arb_op()) {
            let req = IpcRequest { id, op };
            let bytes = encode_request(&req).unwrap();
            prop_assert_eq!(decode_request(&bytes).unwrap(), req);
        }

        #[test]
        fn response_roundtrip(id in any::<u64>(), ok in any::<bool>(), code in any::<u16>(),
                              detail in proptest::option::of("[ -~]{0,64}"),
                              payload in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..512))) {
            let resp = IpcResponse { id, ok, code, detail, payload };
            let bytes = encode_response(&resp).unwrap();
            prop_assert_eq!(decode_response(&bytes).unwrap(), resp);
        }

        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode_request(&bytes);
            let _ = decode_response(&bytes);
            let _ = decode_payload::<StatusReport>(&bytes);
            let _ = decode_payload::<LogPage>(&bytes);
            let _ = decode_payload::<GrantOptions>(&bytes);
        }
    }
}
