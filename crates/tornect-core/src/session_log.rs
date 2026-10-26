//! Local, append-only audit log of consent and session events
//! (`docs/PLAN.md` §B.6: "all session starts/ends logged locally"; §B.8.13 for the
//! unattended events, the hash chain and the rotation).
//!
//! One JSON object per line so it is greppable and survives partial writes. Every
//! line written by this module carries two chain members appended *after* the
//! record's own fields: `prev` (SHA-256 of the previous line, `null` for the first
//! line ever) and `tag` (`HMAC-SHA256(K_log, line_without_tag)`, `null` while no
//! `K_master` exists). Readers of [`SessionRecord`] ignore both members (serde skips
//! unknown keys), so the record types stay independent of the chain.
//!
//! Ordering rule (§B.8.13): a line is appended and fsynced *before* the store head
//! is written; [`SessionLog::append_chained`] returns the line hash for that write.

use std::io::{BufRead as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hmac::{Hmac, KeyInit as _, Mac as _};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::id::DeviceId;

/// Rotate `sessions.log` once it reaches this size (§B.8.13: 10 MiB × 10).
pub const ROTATE_AT_BYTES: u64 = 10 * 1024 * 1024;
/// Number of rotated files kept (`sessions.log.1` … `sessions.log.9` plus the live file).
pub const ROTATE_KEEP: u32 = 9;
/// Bytes read from the end of the file to find its last line before every append (a
/// line is a few hundred bytes; a longer tail falls back to a full read).
const TAIL_WINDOW: u64 = 64 * 1024;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEvent {
    /// A device asked to pair.
    PairRequested,
    /// The user accepted a pairing (SAS confirmed).
    PairAccepted,
    /// The user rejected a pairing.
    PairRejected,
    /// A paired device was removed on this host (*Remove device*; `by`, the
    /// peer and its pinned label): it pairs again, comparing a code, before
    /// another session.
    DeviceUnpaired,
    /// A paired device asked for a session.
    SessionRequested,
    /// A session began streaming.
    SessionStarted,
    /// A session ended (either side, or error).
    SessionEnded,
    /// The user (or policy) denied a session.
    SessionDenied,
    /// An unattended-access authentication attempt failed (post-PAKE, per attempt).
    UnattendedAuthFailed,
    /// An unattended-access authentication succeeded (post-PAKE, per attempt).
    UnattendedAuthSucceeded,
    /// A grant entered hard lock (consecutive ladder or lifetime budget, §B.8.5.1).
    UnattendedHardLock,
    /// The host user hit the panic key.
    PanicDisconnect,
    /// The host identity was rotated; all pairings invalidated.
    HostIdRotated,
    /// A pre-PAKE reject (rate-aggregated: one line per reason per device per 60 s, `count`).
    UnattendedRejected,
    /// `AUTH_CHALLENGE` written after a charge (§B.8.5.1).
    UnattendedChallengeIssued,
    /// A grant was unlocked (locally with re-auth, or by a remote admin `unlock`).
    UnattendedUnlock,
    /// A grant was suspended (`reason`: `local_block` · `panic` · `admin` · `local`; `by` for `local`).
    UnattendedSuspended,
    /// A grant was resumed locally (re-auth).
    UnattendedResumed,
    /// The local user pressed **Block** during the block window.
    UnattendedBlockedByLocalUser,
    /// A grant was created.
    GrantCreated,
    /// A grant's policy changed.
    GrantChanged,
    /// A disabled grant was enabled again (re-auth).
    GrantEnabled,
    /// A grant was disabled (`by`: ui · cli · import · restore).
    GrantDisabled,
    /// A grant was revoked.
    GrantRevoked,
    /// A grant expired.
    GrantExpired,
    /// An expired grant's auth record was pruned (30 d after expiry).
    GrantPruned,
    /// Autostart was installed or removed (`by`).
    AutostartChanged,
    /// Unattended access was turned on host-wide.
    UnattendedEnabled,
    /// Unattended access was turned off host-wide (master off).
    UnattendedDisabled,
    /// Unattended access was paused (`detail` carries the end).
    UnattendedPaused,
    /// A grant password was set or changed (new OPAQUE registration).
    PasswordSet,
    /// A remote admin request was executed or refused (`op`, `ok`).
    AdminRequest,
    /// The emergency stop code was presented: master off + revoke all.
    EmergencyStop,
    /// A backup was exported (`by`, `path`).
    BackupExported,
    /// A consent popup was suppressed because a remote session was live.
    PopupSuppressedRemoteSession,
    /// The mutation guard refused an operation (`code` = the `G_*` code).
    GrantMutationRefused,
    /// The unattended store failed to load (fail closed).
    StoreLoadFailed,
    /// The wall clock went backwards (rate-aggregated).
    ClockAnomaly,
    /// A post-PAKE session was refused because the host is not ready (`cause`).
    HostNotReady,
    /// A session is about to end (`in_s`, `reason`).
    SessionEndingSoon,
    /// The administrator helper of a session connected and passed its
    /// checks (§B.8.7.5; r7, M-FEAT-3).
    AdminHelperStarted,
    /// The administrator helper of a session stopped (`reason`).
    AdminHelperStopped,
    /// The administrator helper could not be started or attached
    /// (`reason`): the session got no administrator access.
    AdminHelperFailed,
    /// Client side: one unattended connect or admin command of this device
    /// (§B.8.10): the host's pinned device and label, the outcome (`reason`),
    /// and for a session its id, mode and `elevation`; for a command `op`, `ok`.
    UnattendedConnect,
    /// `tornect install` (§B.1.1; `by`): logged by the guard before the first
    /// file is written.
    Installed,
    /// `tornect uninstall` (§B.1.1; `by`): logged by the guard before the first
    /// file is removed.
    Uninstalled,
    /// Host side: a file the other computer sent was verified and put in
    /// place (design `services` §2.5): `path` holds the name it was stored
    /// under (sanitised, no folder), `detail` its size ([`SessionRecord::bytes`]).
    /// The Sessions page does not show it.
    FileReceived,
    /// Host side: the other computer copied a file of this computer: `path`
    /// holds this computer's own path of it, `detail` its size. The Sessions
    /// page does not show it.
    FileSent,
    /// Host side: this computer's user turned services off for one session
    /// (one way): `op` holds what was turned off, the `[services]` key names
    /// `clipboard`, `receive_files` and `browse_files` joined by commas.
    ServicesTurnedOff,
    /// Host side: a session's services ended: `detail` holds the counts
    /// ([`ServicesCounts::detail`]), `reason` the services stream's closing
    /// reason; never a name or any text.
    ServicesSummary,
}

/// What a session's services carried, for its `services_summary` line:
/// counts and byte totals only, never a file name or any text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServicesCounts {
    /// Clipboard texts this computer received.
    pub clip_in: u32,
    /// Clipboard texts this computer sent.
    pub clip_out: u32,
    /// Files received.
    pub files_in: u32,
    /// Bytes of the files received.
    pub bytes_in: u64,
    /// Files sent.
    pub files_out: u32,
    /// Bytes of the files sent.
    pub bytes_out: u64,
    /// Chat messages received.
    pub chat_in: u32,
    /// Chat messages sent.
    pub chat_out: u32,
}

impl ServicesCounts {
    /// The counts as one `detail` value, every count named, in a fixed
    /// order: `clip_in=0 clip_out=0 files_in=0 bytes_in=0 files_out=0
    /// bytes_out=0 chat_in=0 chat_out=0`.
    #[must_use]
    pub fn detail(&self) -> String {
        let Self {
            clip_in,
            clip_out,
            files_in,
            bytes_in,
            files_out,
            bytes_out,
            chat_in,
            chat_out,
        } = self;
        format!(
            "clip_in={clip_in} clip_out={clip_out} files_in={files_in} bytes_in={bytes_in} \
             files_out={files_out} bytes_out={bytes_out} chat_in={chat_in} chat_out={chat_out}"
        )
    }
}

/// What the client may do.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    minicbor::Encode,
    minicbor::Decode,
)]
#[serde(rename_all = "snake_case")]
#[cbor(index_only)]
pub enum SessionMode {
    /// View and control.
    #[n(0)]
    Control,
    /// View only; input is dropped host-side.
    #[n(1)]
    ViewOnly,
}

impl SessionMode {
    /// The more restrictive of two modes (§B.8.4.1: `want_mode` is clamped host-side;
    /// a view-only grant plus a Control request yields view-only, never Control).
    #[must_use]
    pub fn most_restrictive(a: Self, b: Self) -> Self {
        if a == Self::ViewOnly || b == Self::ViewOnly {
            Self::ViewOnly
        } else {
            Self::Control
        }
    }

    /// Wire encoding of §B.8.4.1 (`0` control, `1` view-only).
    #[must_use]
    pub fn wire(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::ViewOnly => 1,
        }
    }

    /// Decode the §B.8.4.1 wire byte.
    #[must_use]
    pub fn from_wire(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Control),
            1 => Some(Self::ViewOnly),
            _ => None,
        }
    }
}

/// How media flowed.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    minicbor::Encode,
    minicbor::Decode,
)]
#[serde(rename_all = "snake_case")]
#[cbor(index_only)]
pub enum TransportKind {
    /// Direct hole-punched QUIC.
    #[n(0)]
    Direct,
    /// Same LAN.
    #[n(1)]
    Lan,
    /// Relayed through the Tor circuit.
    #[n(2)]
    TorRelay,
}

/// What a session's direct-path phase came to, as the host records it (design
/// `direct` §3.6 and §8.1, decision M1-82: the measured punch success). Names,
/// a kind and a time only: no address or port is ever in it (decision M1-83).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathSummary {
    /// `direct`, the name of the viewer's `TOR_FALLBACK` reason, `old-viewer`,
    /// `pin-refused` or `bind-refused` (fixed words, never peer text).
    pub outcome: String,
    /// The kind of the remote candidate that won (`host`, `srflx`, `mapped`,
    /// `prflx`); none when the session did not go direct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winner: Option<String>,
    /// Whether the direct route is IPv6.
    #[serde(default)]
    pub ipv6: bool,
    /// Milliseconds from the accept to the direct claim or to `TOR_FALLBACK`.
    #[serde(default)]
    pub ms: u32,
}

/// Who performed a local change (§B.8.9 `created_by`, §B.8.13 `by`).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    minicbor::Encode,
    minicbor::Decode,
)]
#[serde(rename_all = "snake_case")]
#[cbor(index_only)]
pub enum Actor {
    /// The desktop app.
    #[n(0)]
    Ui,
    /// `tornect unattended …` (over IPC or offline).
    #[n(1)]
    Cli,
    /// A backup import (§B.8.9: imported grants arrive disabled).
    #[n(2)]
    Import,
    /// The machine-id check of a moved state dir (§B.8.12: only ever *disables*).
    #[n(3)]
    Restore,
}

/// Block-window evidence carried by `session_started` lines (§B.8.13 `block`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockEvidence {
    /// The window elapsed without a Block.
    Elapsed,
    /// The local user pressed Block.
    Blocked,
    /// `block_window_s = 0`.
    Skipped,
}

/// One log line (the record part; the chain members `prev`/`tag` are appended by
/// [`SessionLog`] and ignored on read).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// Event kind.
    pub event: SessionEvent,
    /// Session identifier (hex), if the event belongs to a session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The remote device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_device: Option<DeviceId>,
    /// The remote device's pinned pairing label (never the self-declared HELLO name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_name: Option<String>,
    /// Session mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<SessionMode>,
    /// The administrator level signed in `SESSION_ACCEPT` (r7, §B.8.13):
    /// written only for an administrator session, so a line at none reads as
    /// it did before the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elevation: Option<crate::levels::Elevation>,
    /// Whether this was an unattended (popup-less) session.
    #[serde(default)]
    pub unattended: bool,
    /// Media transport, once known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportKind>,
    /// Free-text detail (reason, error, duration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Grant id (hex, distinct from `peer_device`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    /// Who performed a local change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<Actor>,
    /// Reason code or name (suspension reason, `BYE` reason, ending reason).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Failure counter snapshot (consecutive failures).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<u32>,
    /// Lock length armed by a failure, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_secs: Option<u32>,
    /// Aggregated count (`unattended_rejected`, `clock_anomaly`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    /// Block-window evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<BlockEvidence>,
    /// Who ended a session (`user` · `panic` · `admin` · `policy` · …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_by: Option<String>,
    /// Whether a remote session was live while this happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub during_remote_session: Option<bool>,
    /// Error code (`G_*` for `grant_mutation_refused`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
    /// Cause byte (`host_not_ready`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<u8>,
    /// Seconds until the event (`session_ending_soon`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_s: Option<u32>,
    /// Operation name (`admin_request`, `grant_mutation_refused`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    /// Whether the operation succeeded (`admin_request`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    /// File path (`backup_exported`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// What a session's direct-path phase came to (`session_ended`; design
    /// `direct` §8.1, which names it `path`: that key already holds
    /// `backup_exported`'s file path, so this one is `path_summary`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_summary: Option<PathSummary>,
}

impl SessionRecord {
    /// A record for `event` stamped with the current UTC time.
    #[must_use]
    pub fn now(event: SessionEvent) -> Self {
        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        Self::with_ts(ts, event)
    }

    /// A record for `event` stamped with the given unix time (aggregated lines
    /// carry the time of their first occurrence).
    #[must_use]
    pub fn at(unix: u64, event: SessionEvent) -> Self {
        let ts = i64::try_from(unix)
            .ok()
            .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
            .and_then(|t| t.format(&Rfc3339).ok())
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned());
        Self::with_ts(ts, event)
    }

    fn with_ts(ts: String, event: SessionEvent) -> Self {
        Self {
            ts,
            event,
            session_id: None,
            peer_device: None,
            peer_name: None,
            mode: None,
            elevation: None,
            unattended: false,
            transport: None,
            detail: None,
            grant: None,
            by: None,
            reason: None,
            failures: None,
            lock_secs: None,
            count: None,
            block: None,
            ended_by: None,
            during_remote_session: None,
            code: None,
            cause: None,
            in_s: None,
            op: None,
            ok: None,
            path: None,
            path_summary: None,
        }
    }

    /// Attach the peer device.
    #[must_use]
    pub fn peer(mut self, device: DeviceId, name: impl Into<String>) -> Self {
        self.peer_device = Some(device);
        self.peer_name = Some(name.into());
        self
    }

    /// Attach the peer device without a label.
    #[must_use]
    pub fn device(mut self, device: DeviceId) -> Self {
        self.peer_device = Some(device);
        self
    }

    /// Attach the session id.
    #[must_use]
    pub fn session(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Attach the mode.
    #[must_use]
    pub fn mode(mut self, mode: SessionMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Attach the administrator level: written only when it is
    /// [`Elevation::Admin`](crate::levels::Elevation::Admin).
    #[must_use]
    pub fn elevation(mut self, elevation: crate::levels::Elevation) -> Self {
        self.elevation = (elevation != crate::levels::Elevation::None).then_some(elevation);
        self
    }

    /// Mark as unattended.
    #[must_use]
    pub fn unattended(mut self, yes: bool) -> Self {
        self.unattended = yes;
        self
    }

    /// Attach the transport.
    #[must_use]
    pub fn transport(mut self, t: TransportKind) -> Self {
        self.transport = Some(t);
        self
    }

    /// Attach free-text detail.
    #[must_use]
    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }

    /// Attach the grant id (hex).
    #[must_use]
    pub fn grant(mut self, id: &[u8; 8]) -> Self {
        self.grant = Some(hex::encode(id));
        self
    }

    /// Attach the actor.
    #[must_use]
    pub fn by(mut self, actor: Actor) -> Self {
        self.by = Some(actor);
        self
    }

    /// Attach a reason.
    #[must_use]
    pub fn reason(mut self, r: impl Into<String>) -> Self {
        self.reason = Some(r.into());
        self
    }

    /// Attach the failure counter.
    #[must_use]
    pub fn failures(mut self, n: u32) -> Self {
        self.failures = Some(n);
        self
    }

    /// Attach the armed lock length.
    #[must_use]
    pub fn lock_secs(mut self, s: u32) -> Self {
        self.lock_secs = Some(s);
        self
    }

    /// Attach an aggregated count.
    #[must_use]
    pub fn count(mut self, n: u32) -> Self {
        self.count = Some(n);
        self
    }

    /// Attach block-window evidence.
    #[must_use]
    pub fn block(mut self, b: BlockEvidence) -> Self {
        self.block = Some(b);
        self
    }

    /// Attach who ended the session.
    #[must_use]
    pub fn ended_by(mut self, who: impl Into<String>) -> Self {
        self.ended_by = Some(who.into());
        self
    }

    /// Attach whether a remote session was live.
    #[must_use]
    pub fn during_remote_session(mut self, yes: bool) -> Self {
        self.during_remote_session = Some(yes);
        self
    }

    /// Attach an error code.
    #[must_use]
    pub fn code(mut self, c: u16) -> Self {
        self.code = Some(c);
        self
    }

    /// Attach a cause byte.
    #[must_use]
    pub fn cause(mut self, c: u8) -> Self {
        self.cause = Some(c);
        self
    }

    /// Attach the seconds-until value.
    #[must_use]
    pub fn in_s(mut self, s: u32) -> Self {
        self.in_s = Some(s);
        self
    }

    /// Attach an operation name.
    #[must_use]
    pub fn op(mut self, op: impl Into<String>) -> Self {
        self.op = Some(op.into());
        self
    }

    /// Attach the outcome flag.
    #[must_use]
    pub fn ok(mut self, ok: bool) -> Self {
        self.ok = Some(ok);
        self
    }

    /// Attach a file path.
    #[must_use]
    pub fn path(mut self, p: impl Into<String>) -> Self {
        self.path = Some(p.into());
        self
    }

    /// Attach the direct-path summary of a session's end.
    #[must_use]
    pub fn path_summary(mut self, p: PathSummary) -> Self {
        self.path_summary = Some(p);
        self
    }

    /// Attach a size as `detail`: `"<n> bytes"` (`file_received`,
    /// `file_sent`).
    #[must_use]
    pub fn bytes(mut self, n: u64) -> Self {
        self.detail = Some(format!("{n} bytes"));
        self
    }
}

/// SHA-256 of one log line (without its trailing newline): the `prev` link.
#[must_use]
pub fn line_hash(line: &[u8]) -> [u8; 32] {
    Sha256::digest(line).into()
}

/// `tag = HMAC-SHA256(K_log, line_without_tag)` (§B.8.13).
#[must_use]
pub fn line_tag(k_log: &[u8; 32], line_without_tag: &[u8]) -> [u8; 32] {
    // A 32-byte key is always a valid HMAC key length.
    let mut mac = Hmac::<Sha256>::new_from_slice(k_log).unwrap_or_else(|_| unreachable!());
    mac.update(line_without_tag);
    mac.finalize().into_bytes().into()
}

/// The chain members parsed off one raw line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineChain {
    /// `prev` member (`None` = JSON `null`).
    pub prev: Option<[u8; 32]>,
    /// `tag` member (`None` = JSON `null`).
    pub tag: Option<[u8; 32]>,
    /// The line without its `tag` member (what the tag authenticates).
    pub without_tag: Vec<u8>,
}

const TAG_KEY: &str = ",\"tag\":";
const PREV_KEY: &str = ",\"prev\":";

fn parse_hex32(s: &str) -> Option<Option<[u8; 32]>> {
    if s == "null" {
        return Some(None);
    }
    let inner = s.strip_prefix('"')?.strip_suffix('"')?;
    if inner.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(inner, &mut out).ok()?;
    Some(Some(out))
}

/// Split the chain members off a raw line. `None` when the line carries no chain
/// suffix (a pre-chain line written by an M0 build, or a foreign line).
#[must_use]
pub fn parse_line_chain(line: &str) -> Option<LineChain> {
    let line = line.trim_end_matches(['\n', '\r']);
    let body = line.strip_suffix('}')?;
    let tag_at = body.rfind(TAG_KEY)?;
    let tag = parse_hex32(&body[tag_at + TAG_KEY.len()..])?;
    let before_tag = &body[..tag_at];
    let prev_at = before_tag.rfind(PREV_KEY)?;
    let prev = parse_hex32(&before_tag[prev_at + PREV_KEY.len()..])?;
    let mut without_tag = before_tag.as_bytes().to_vec();
    without_tag.push(b'}');
    Some(LineChain {
        prev,
        tag,
        without_tag,
    })
}

/// Outcome of the startup verifier (§B.8.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// Every link and tag verified and the head matched a line.
    Valid,
    /// The chain is valid but no head was stored (warning badge).
    MissingHead,
    /// The log was modified or truncated; `line` counts across the rotated files in order.
    Broken {
        /// File the failure was found in.
        file: String,
        /// 1-based line number within that file.
        line: usize,
        /// What failed.
        reason: String,
    },
}

/// Report of [`SessionLog::verify_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// Verdict.
    pub status: ChainStatus,
    /// Lines examined.
    pub lines: usize,
    /// Hash of the last line, if any (the head to store).
    pub last_hash: Option<[u8; 32]>,
    /// Validly tagged lines found beyond the stored head (each one is accepted and the
    /// head must be advanced to [`ChainReport::last_hash`]).
    pub tagged_beyond_head: usize,
    /// Tagged lines at or before the key-epoch boundary: prev-linked, but tagged under
    /// a `K_log` that no longer exists (*Rotate ID* / store reset), so unverifiable.
    pub previous_epoch_lines: usize,
    /// Fragments torn by a crash mid-append and tolerated (a chained successor links to
    /// them, or they end the file); readers skip them as malformed lines.
    pub torn_lines: usize,
}

/// The walking state of [`SessionLog::verify_chain`].
struct Walk {
    total: usize,
    prev_hash: Option<[u8; 32]>,
    tagged_beyond_head: usize,
    previous_epoch_lines: usize,
    torn_lines: usize,
}

impl Walk {
    fn broken(&self, file: &str, line: usize, reason: &str) -> ChainReport {
        ChainReport {
            status: ChainStatus::Broken {
                file: file.to_owned(),
                line,
                reason: reason.to_owned(),
            },
            lines: self.total,
            last_hash: self.prev_hash,
            tagged_beyond_head: self.tagged_beyond_head,
            previous_epoch_lines: self.previous_epoch_lines,
            torn_lines: self.torn_lines,
        }
    }
}

/// Whether `line` is a complete JSON object: a fragment torn by a crash mid-append never
/// is (it is a strict prefix of one), so a members-less line that parses is a foreign
/// record, not a torn one.
fn is_json_object(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line).is_ok_and(|v| v.is_object())
}

struct ChainState {
    /// Hash of the last line this handle wrote or saw (`None` until the first append);
    /// compared with the file's real tail before every append, so two handles on one
    /// file — or another process — never fork the chain.
    last_hash: Option<Option<[u8; 32]>>,
    key: Option<Zeroizing<[u8; 32]>>,
}

/// Append-only writer/reader for `sessions.log`. Clones share one chain state; every
/// append re-reads the file's tail under the chain mutex before linking, so
/// independently constructed handles on the same path stay on one chain (a fresh
/// handle is nevertheless the expensive form — prefer cloning the host's).
#[derive(Clone)]
pub struct SessionLog {
    path: PathBuf,
    chain: Arc<Mutex<ChainState>>,
}

impl std::fmt::Debug for SessionLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLog")
            .field("path", &self.path)
            .field("keyed", &self.chain.lock().key.is_some())
            .finish()
    }
}

impl SessionLog {
    /// Use the log at `path` (created on first append).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            chain: Arc::new(Mutex::new(ChainState {
                last_hash: None,
                key: None,
            })),
        }
    }

    /// The file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Install (or remove) `K_log`; lines appended from now on carry a tag.
    pub fn set_log_key(&self, k_log: Option<Zeroizing<[u8; 32]>>) {
        self.chain.lock().key = k_log;
    }

    /// Whether a `K_log` is installed.
    #[must_use]
    pub fn has_log_key(&self) -> bool {
        self.chain.lock().key.is_some()
    }

    /// Path of the `n`-th rotated file (`sessions.log.n`).
    #[must_use]
    pub fn rotated_path(&self, n: u32) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(|s| s.to_os_string())
            .unwrap_or_default();
        name.push(format!(".{n}"));
        self.path.with_file_name(name)
    }

    /// The last non-empty line of `path` (without its newline), read from a bounded
    /// tail window; `None` for a missing or empty file.
    fn last_line_of(path: &Path) -> Result<Option<Vec<u8>>> {
        use std::io::Seek as _;
        let mut f = match fs_err::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let len = f.metadata()?.len();
        let mut start = len.saturating_sub(TAIL_WINDOW);
        loop {
            f.seek(std::io::SeekFrom::Start(start))?;
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes)?;
            let mut end = bytes.len();
            while end > 0 && (bytes[end - 1] == b'\n' || bytes[end - 1] == b'\r') {
                end -= 1;
            }
            if end == 0 {
                if start == 0 {
                    return Ok(None);
                }
                // Only newlines in the window: widen.
                start = 0;
                continue;
            }
            match bytes[..end].iter().rposition(|b| *b == b'\n') {
                Some(p) => return Ok(Some(bytes[p + 1..end].to_vec())),
                None if start == 0 => return Ok(Some(bytes[..end].to_vec())),
                // The last line began before the window: read the whole file.
                None => start = 0,
            }
        }
    }

    /// Hash of the line the next append will link to: the live file's last line, or
    /// the rotated file's when the live one is empty or missing; `None` for an empty
    /// log. The store records it at bootstrap as the epoch boundary of a fresh `K_log`
    /// (§B.8.13 key rotation, [`Self::verify_chain`]).
    pub fn tail_hash(&self) -> Result<Option<[u8; 32]>> {
        let last = match Self::last_line_of(&self.path)? {
            Some(l) => Some(l),
            None => Self::last_line_of(&self.rotated_path(1))?,
        };
        Ok(last.map(|l| line_hash(&l)))
    }

    /// Whether the live file ends without a newline (a crash between `write_all` and
    /// `sync_all` left a torn last line); `false` for a missing or empty file.
    fn ends_without_newline(path: &Path) -> Result<bool> {
        use std::io::Seek as _;
        let mut f = match fs_err::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        let len = f.metadata()?.len();
        if len == 0 {
            return Ok(false);
        }
        f.seek(std::io::SeekFrom::Start(len - 1))?;
        let mut last = [0u8; 1];
        f.read_exact(&mut last)?;
        Ok(last[0] != b'\n')
    }

    fn rotate_if_needed(&self) -> Result<()> {
        let size = match fs_err::metadata(&self.path) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if size < ROTATE_AT_BYTES {
            return Ok(());
        }
        let oldest = self.rotated_path(ROTATE_KEEP);
        match fs_err::remove_file(&oldest) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        for n in (1..ROTATE_KEEP).rev() {
            let from = self.rotated_path(n);
            if from.exists() {
                fs_err::rename(&from, self.rotated_path(n + 1))?;
            }
        }
        fs_err::rename(&self.path, self.rotated_path(1))?;
        tracing::info!(path = %self.path.display(), "rotated sessions.log");
        Ok(())
    }

    /// Append one record and flush (chain members added; see [`Self::append_chained`]).
    pub fn append(&self, record: &SessionRecord) -> Result<()> {
        self.append_chained(record).map(|_| ())
    }

    /// Append one record with `prev`/`tag`, fsync, and return the line hash — the
    /// value to store as `log_chain_head` *after* this call returns (§B.8.13).
    pub fn append_chained(&self, record: &SessionRecord) -> Result<[u8; 32]> {
        if let Some(parent) = self.path.parent() {
            crate::keystore::create_private_dir(parent)?;
        }
        let mut st = self.chain.lock();
        self.rotate_if_needed()?;
        // Link to the file's real tail, not to a cached one: another handle or process
        // may have appended since (the cache only tells us whether that happened).
        let prev = self.tail_hash()?;
        if let Some(cached) = st.last_hash
            && cached != prev
        {
            tracing::warn!(
                path = %self.path.display(),
                "sessions.log was appended to by another writer; chain re-synced to the file"
            );
        }
        // A torn last line (crash mid-append) becomes its own line: `prev` already
        // hashes the fragment, so the chain stays intact and the verifier tolerates it.
        let heal = Self::ends_without_newline(&self.path)?;
        if heal {
            tracing::warn!(
                path = %self.path.display(),
                "sessions.log ends with a torn line; terminating it before appending"
            );
        }

        let body = serde_json::to_string(record)
            .map_err(|e| CoreError::SessionLog(format!("serialize: {e}")))?;
        let Some(open) = body.strip_suffix('}') else {
            return Err(CoreError::SessionLog("record is not a JSON object".into()));
        };
        let mut without_tag = String::with_capacity(body.len() + 96);
        without_tag.push_str(open);
        without_tag.push_str(PREV_KEY);
        match prev {
            Some(h) => {
                without_tag.push('"');
                without_tag.push_str(&hex::encode(h));
                without_tag.push('"');
            }
            None => without_tag.push_str("null"),
        }
        without_tag.push('}');
        let tag = st.key.as_ref().map(|k| line_tag(k, without_tag.as_bytes()));
        let mut line = without_tag;
        // `without_tag` ends with `}`; splice the tag member in before it.
        line.pop();
        line.push_str(TAG_KEY);
        match tag {
            Some(t) => {
                line.push('"');
                line.push_str(&hex::encode(t));
                line.push('"');
            }
            None => line.push_str("null"),
        }
        line.push('}');
        let hash = line_hash(line.as_bytes());
        line.push('\n');
        if heal {
            line.insert(0, '\n');
        }

        let mut opts = fs_err::OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        {
            use fs_err::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.path)?;
        f.write_all(line.as_bytes())?;
        f.sync_all()?;
        st.last_hash = Some(Some(hash));
        Ok(hash)
    }

    /// Read every well-formed record of the live file; malformed lines are skipped
    /// with a warning.
    pub fn read_all(&self) -> Result<Vec<SessionRecord>> {
        Self::read_records_of(&self.path)
    }

    /// Every well-formed record of the retained rotated files (oldest first) and the
    /// live file — the view a per-device history needs once a 10 MiB rotation has
    /// moved older sessions out of the live file.
    pub fn read_all_including_rotated(&self) -> Result<Vec<SessionRecord>> {
        let mut out = Vec::new();
        for n in (1..=ROTATE_KEEP).rev() {
            out.extend(Self::read_records_of(&self.rotated_path(n))?);
        }
        out.extend(Self::read_records_of(&self.path)?);
        Ok(out)
    }

    /// Every well-formed record that could be read from the retained rotated files
    /// (oldest first) and the live file, and whether all of them could be: a line that
    /// is not UTF-8 is skipped, and a file that cannot be read to its end keeps the
    /// records read before the error, which the log names without the file's path
    /// (the window's Sessions page and device cards, §B.8.13).
    pub fn read_all_readable(&self) -> (Vec<SessionRecord>, bool) {
        let mut out = Vec::new();
        let mut whole = true;
        let files = (1..=ROTATE_KEEP)
            .rev()
            .map(|n| self.rotated_path(n))
            .chain([self.path.clone()]);
        for path in files {
            match Self::read_records_into(&path, &mut out) {
                Ok(read) => whole &= read,
                Err(_) => {
                    tracing::warn!("part of the session log could not be read");
                    whole = false;
                }
            }
        }
        (out, whole)
    }

    fn read_records_of(path: &Path) -> Result<Vec<SessionRecord>> {
        let mut out = Vec::new();
        Self::read_records_into(path, &mut out)?;
        Ok(out)
    }

    /// The well-formed records of the file at `path`, appended to `out` as they are
    /// read, line by line as bytes: a line that does not parse is skipped as malformed,
    /// and so is one that is not UTF-8 (then `false`). An I/O error ends the read, the
    /// records before it in `out`.
    fn read_records_into(path: &Path, out: &mut Vec<SessionRecord>) -> Result<bool> {
        let file = match fs_err::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(e) => return Err(e.into()),
        };
        let mut whole = true;
        for (n, line) in std::io::BufReader::new(file).split(b'\n').enumerate() {
            let line = line?;
            let Ok(line) = std::str::from_utf8(&line) else {
                tracing::warn!(line = n + 1, "skipping sessions.log line that is not UTF-8");
                whole = false;
                continue;
            };
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<SessionRecord>(line) {
                Ok(r) => out.push(r),
                Err(e) => {
                    tracing::warn!(line = n + 1, error = %e, "skipping malformed sessions.log line")
                }
            }
        }
        Ok(whole)
    }

    /// Raw lines of the live file (no rotated files), for the paged `Log` IPC op.
    pub fn read_lines(&self) -> Result<Vec<String>> {
        let file = match fs_err::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in std::io::BufReader::new(file).lines() {
            let line = line?;
            if !line.trim().is_empty() {
                out.push(line);
            }
        }
        Ok(out)
    }

    /// The startup verifier (§B.8.13): walk the rotated files oldest first, then the
    /// live file, checking every `prev` link and — once a tagged line was seen — every
    /// tag against the installed `K_log`; the stored `head` must equal the hash of some
    /// line, and every line after it must carry a valid tag (then it is accepted and the
    /// caller advances the head to [`ChainReport::last_hash`]). A missing head with a
    /// valid chain is [`ChainStatus::MissingHead`] (warning); anything else is
    /// [`ChainStatus::Broken`] ("log modified or truncated at line N").
    ///
    /// Three refinements of the plain rule:
    ///
    /// * **Key epochs.** `epoch` is the hash of the last line written before the
    ///   current `K_log`'s first tagged line (recorded by the store at bootstrap). Lines
    ///   up to and including it were tagged under a key that *Rotate ID* or a store
    ///   reset wiped: they are checked for their `prev` links only and counted in
    ///   [`ChainReport::previous_epoch_lines`]; tag verification starts after that line.
    ///   Tampering before the boundary still breaks a `prev` link, because the boundary
    ///   line's hash is inside the first current-epoch line, whose tag covers it. An
    ///   epoch line that rotation has already discarded is never reached, so every
    ///   retained line is then treated as the previous epoch — safe, because the chain
    ///   from the stored head backwards pins every earlier line anyway, and lines beyond
    ///   the head are still required to carry a valid tag.
    /// * **Front truncation.** While the retention window has never overflowed (no
    ///   `sessions.log.9`), the first retained line must be the first line ever written:
    ///   a pre-chain (M0) line, or a chained line with `prev = null`. Deleting a prefix
    ///   of the log is therefore "log truncated at the front"; once rotation has
    ///   discarded files the check is bounded to the retained window (10 × 10 MiB).
    /// * **Torn lines.** A members-less line that is not a complete JSON object (or
    ///   not UTF-8 at all: the cut fell inside a multi-byte character) is a
    ///   fragment torn by a crash between `write_all` and `sync_all`. It is tolerated —
    ///   counted in [`ChainReport::torn_lines`] — when the next line is chained and links
    ///   to it (the keyed writer vouched for it by hashing it into `prev`; [`Self::append_chained`]
    ///   terminates such a fragment with a newline first) or when it ends the log (the
    ///   crash state itself). A members-less line that *is* a complete JSON object is a
    ///   foreign record and breaks the chain.
    pub fn verify_chain(
        &self,
        head: Option<&[u8; 32]>,
        epoch: Option<&[u8; 32]>,
    ) -> Result<ChainReport> {
        let key = self.chain.lock().key.clone();
        self.walk(key.as_deref(), head, epoch)
    }

    /// [`Self::verify_chain`] without a key, a head or a key epoch, whatever key the
    /// handle holds: the `prev` links, the front and torn lines are checked, no tag
    /// is. What can be checked where the store that keeps the head and the epoch
    /// could not be read: a key without its epoch would judge lines tagged under a
    /// wiped key as forged.
    pub fn verify_links(&self) -> Result<ChainReport> {
        self.walk(None, None, None)
    }

    fn walk(
        &self,
        key: Option<&[u8; 32]>,
        head: Option<&[u8; 32]>,
        epoch: Option<&[u8; 32]>,
    ) -> Result<ChainReport> {
        let mut files: Vec<PathBuf> = (1..=ROTATE_KEEP)
            .rev()
            .map(|n| self.rotated_path(n))
            .filter(|p| p.exists())
            .collect();
        let front_checkable = !self.rotated_path(ROTATE_KEEP).exists();
        files.push(self.path.clone());

        let mut w = Walk {
            total: 0,
            prev_hash: None,
            tagged_beyond_head: 0,
            previous_epoch_lines: 0,
            torn_lines: 0,
        };
        let mut first_line_seen = false;
        let mut chained_seen = false;
        let mut tagged_started = false;
        let mut head_found = head.is_none();
        let mut epoch_passed = epoch.is_none();
        // A torn candidate waiting for the next line to vouch for it: (file, line).
        let mut pending_torn: Option<(String, usize)> = None;

        for file in &files {
            let f = match fs_err::File::open(file) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let name = file
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut reader = std::io::BufReader::new(f);
            let mut raw = Vec::new();
            for n in 0usize.. {
                raw.clear();
                if reader.read_until(b'\n', &mut raw)? == 0 {
                    break;
                }
                // The framing of `BufRead::lines`: the newline, and a CR before it,
                // are not part of the line.
                if raw.last() == Some(&b'\n') {
                    raw.pop();
                    if raw.last() == Some(&b'\r') {
                        raw.pop();
                    }
                }
                // A crash mid-append can cut a multi-byte character: such a fragment
                // is not UTF-8, cannot be a JSON object, and is judged as a torn line
                // below (hashed as the bytes the next append links to), not an error
                // that would fail every later start.
                let text = std::str::from_utf8(&raw).ok();
                if text.is_some_and(|t| t.trim().is_empty()) {
                    continue;
                }
                w.total += 1;
                let hash = line_hash(&raw);
                let parsed = text.and_then(parse_line_chain);
                if let Some((tf, tl)) = pending_torn.take() {
                    let vouched = parsed.as_ref().is_some_and(|c| c.prev == w.prev_hash);
                    if !vouched {
                        return Ok(w.broken(&tf, tl, "line without chain members"));
                    }
                    w.torn_lines += 1;
                }
                let mut valid_tag = false;
                match &parsed {
                    None => {
                        if chained_seen {
                            if text.is_some_and(is_json_object) {
                                return Ok(w.broken(&name, n + 1, "line without chain members"));
                            }
                            // Torn by a crash mid-append: the next line must link to it.
                            pending_torn = Some((name.clone(), n + 1));
                        }
                        // else: a pre-chain (M0) line, allowed before the chain starts.
                    }
                    Some(chain) => {
                        if !first_line_seen && front_checkable && chain.prev.is_some() {
                            return Ok(w.broken(
                                &name,
                                n + 1,
                                "log truncated at the front: the first line links to a missing predecessor",
                            ));
                        }
                        if first_line_seen && chain.prev != w.prev_hash {
                            return Ok(w.broken(
                                &name,
                                n + 1,
                                "prev link does not match the previous line",
                            ));
                        }
                        match (key, chain.tag) {
                            (Some(k), Some(tag)) => {
                                let expected = line_tag(k, &chain.without_tag);
                                let verifies = bool::from(subtle::ConstantTimeEq::ct_eq(
                                    &expected[..],
                                    &tag[..],
                                ));
                                if epoch_passed {
                                    if !verifies {
                                        return Ok(w.broken(&name, n + 1, "tag does not verify"));
                                    }
                                    tagged_started = true;
                                }
                                if !epoch_passed {
                                    w.previous_epoch_lines += 1;
                                }
                                valid_tag = verifies;
                            }
                            (Some(_), None) => {
                                if epoch_passed && tagged_started {
                                    return Ok(w.broken(
                                        &name,
                                        n + 1,
                                        "untagged line after the chain started",
                                    ));
                                }
                            }
                            (None, _) => {}
                        }
                    }
                }
                if pending_torn.is_none() {
                    if head_found && head.is_some() {
                        if !valid_tag {
                            return Ok(w.broken(
                                &name,
                                n + 1,
                                "line beyond the stored head without a valid tag",
                            ));
                        }
                        w.tagged_beyond_head += 1;
                    } else if !head_found && head == Some(&hash) {
                        head_found = true;
                    }
                } else if !head_found && head == Some(&hash) {
                    // The head may sit on a fragment: a verifier run accepted it as the
                    // trailing torn line and advanced the head to it.
                    head_found = true;
                }
                if !epoch_passed && epoch == Some(&hash) {
                    epoch_passed = true;
                }
                w.prev_hash = Some(hash);
                first_line_seen = true;
                chained_seen |= parsed.is_some();
            }
        }
        if pending_torn.is_some() {
            // The crash state itself: nothing was appended after the torn line yet.
            w.torn_lines += 1;
        }

        let status = if !head_found {
            ChainStatus::Broken {
                file: String::new(),
                line: w.total,
                reason: "stored head matches no line (truncated log)".into(),
            }
        } else if head.is_none() && w.total > 0 {
            ChainStatus::MissingHead
        } else {
            ChainStatus::Valid
        };
        Ok(ChainReport {
            status,
            lines: w.total,
            last_hash: w.prev_hash,
            tagged_beyond_head: w.tagged_beyond_head,
            previous_epoch_lines: w.previous_epoch_lines,
            torn_lines: w.torn_lines,
        })
    }
}

/// One aggregated pre-PAKE reject line (§B.8.13: one line per reason per device per 60 s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedReject {
    /// The rejected device.
    pub device: DeviceId,
    /// The §B.8.4.6 reject code.
    pub reason: u16,
    /// Rejects inside the window.
    pub count: u32,
    /// Wall time of the first reject in the window.
    pub first_at: u64,
}

/// Rate aggregation for pre-PAKE rejects: buckets per `(device, reason)` collect for
/// 60 s (monotonic) and are emitted once, with `count`, when the window closes.
#[derive(Debug, Default)]
pub struct RejectAggregator {
    buckets: Vec<Bucket>,
}

#[derive(Debug)]
struct Bucket {
    device: DeviceId,
    reason: u16,
    count: u32,
    first_mono: std::time::Duration,
    first_wall: u64,
}

impl RejectAggregator {
    /// Aggregation window.
    pub const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

    /// Note one reject; returns the lines whose windows closed (to be logged now).
    pub fn note(
        &mut self,
        device: DeviceId,
        reason: u16,
        mono: std::time::Duration,
        wall: u64,
    ) -> Vec<AggregatedReject> {
        let closed = self.drain(mono);
        if let Some(b) = self
            .buckets
            .iter_mut()
            .find(|b| b.device == device && b.reason == reason)
        {
            b.count = b.count.saturating_add(1);
        } else {
            self.buckets.push(Bucket {
                device,
                reason,
                count: 1,
                first_mono: mono,
                first_wall: wall,
            });
        }
        closed
    }

    /// Emit every bucket whose window has closed at `mono`.
    pub fn drain(&mut self, mono: std::time::Duration) -> Vec<AggregatedReject> {
        let mut out = Vec::new();
        self.buckets.retain(|b| {
            if mono.saturating_sub(b.first_mono) >= Self::WINDOW {
                out.push(AggregatedReject {
                    device: b.device,
                    reason: b.reason,
                    count: b.count,
                    first_at: b.first_wall,
                });
                false
            } else {
                true
            }
        });
        out
    }

    /// Emit every bucket regardless of its window (shutdown).
    pub fn flush_all(&mut self) -> Vec<AggregatedReject> {
        self.buckets
            .drain(..)
            .map(|b| AggregatedReject {
                device: b.device,
                reason: b.reason,
                count: b.count,
                first_at: b.first_wall,
            })
            .collect()
    }

    /// Open buckets.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buckets.len()
    }
}

/// How many of `device`'s admin commands ran nothing (§B.8.6.1, decision M1-67), over
/// `records` in their order (the rotated files' and the live file's, oldest first, as
/// [`SessionLog::read_all_including_rotated`] returns them): its `AdminRequest` lines
/// answered `ok` false (a refused command, an unknown one included), and its
/// `end_session` commands logged while it had no session open (a `SessionStarted` of it
/// whose `SessionEnded` had not come). A command answered `ok` that changed nothing
/// cannot be told from one that acted, and one refused before its grant was read wrote
/// no line: neither is counted. It reads only the records given; nothing is logged.
#[must_use]
pub fn admin_commands_that_ran_nothing(records: &[SessionRecord], device: &DeviceId) -> usize {
    let mut open: Vec<&str> = Vec::new();
    let mut count = 0;
    for r in records {
        let of_device = r.peer_device.as_ref() == Some(device);
        match r.event {
            SessionEvent::SessionStarted if of_device => {
                if let Some(id) = r.session_id.as_deref() {
                    open.push(id);
                }
            }
            SessionEvent::SessionEnded => {
                if let Some(id) = r.session_id.as_deref() {
                    open.retain(|o| *o != id);
                }
            }
            SessionEvent::AdminRequest if of_device => {
                let refused = r.ok == Some(false);
                let end_without_session = r.op.as_deref() == Some("end_session") && open.is_empty();
                if refused || end_without_session {
                    count += 1;
                }
            }
            _ => {}
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let log = SessionLog::new(dir.path().join("logs").join("sessions.log"));
        assert!(log.read_all().unwrap().is_empty());

        let dev = DeviceId::from_bytes([1u8; 32]);
        let r1 = SessionRecord::now(SessionEvent::PairAccepted).peer(dev, "Laptop");
        let r2 = SessionRecord::now(SessionEvent::SessionStarted)
            .peer(dev, "Laptop")
            .session("abcd")
            .mode(SessionMode::Control)
            .unattended(true)
            .transport(TransportKind::Direct);
        log.append(&r1).unwrap();
        log.append(&r2).unwrap();

        // a corrupt line must not poison the reader
        std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap()
            .write_all(b"{not json\n")
            .unwrap();

        let all = log.read_all().unwrap();
        assert_eq!(all, vec![r1, r2.clone()]);
        assert!(all[1].unattended);
        assert!(all[0].ts.ends_with('Z'));
        assert_eq!(r2.transport, Some(TransportKind::Direct));
    }

    /// §B.8.13 (r7): a `session_started` line carries `elevation` only for an
    /// administrator session, so a line at none is the line it always was;
    /// the helper's three events have their names (M-UI-3 Security F-16).
    /// So do the two of `tornect install` and `uninstall` (§B.1.1), and the
    /// removal of a paired device.
    #[test]
    fn the_level_and_the_helper_events_reach_the_log() {
        use crate::levels::Elevation;
        let dev = DeviceId::from_bytes([1u8; 32]);
        let started = |e| {
            SessionRecord::at(1_700_000_000, SessionEvent::SessionStarted)
                .peer(dev, "Laptop")
                .session("abcd")
                .mode(SessionMode::Control)
                .elevation(e)
        };
        let admin = serde_json::to_string(&started(Elevation::Admin)).unwrap();
        assert!(admin.contains(r#""elevation":"admin""#), "{admin}");
        let none = serde_json::to_string(&started(Elevation::None)).unwrap();
        assert!(!none.contains("elevation"), "{none}");
        let back: SessionRecord = serde_json::from_str(&admin).unwrap();
        assert_eq!(back.elevation, Some(Elevation::Admin));
        let old: SessionRecord = serde_json::from_str(&none).unwrap();
        assert_eq!(old.elevation, None);
        for (event, name) in [
            (SessionEvent::AdminHelperStarted, "admin_helper_started"),
            (SessionEvent::AdminHelperStopped, "admin_helper_stopped"),
            (SessionEvent::AdminHelperFailed, "admin_helper_failed"),
            (SessionEvent::Installed, "installed"),
            (SessionEvent::Uninstalled, "uninstalled"),
            (SessionEvent::DeviceUnpaired, "device_unpaired"),
        ] {
            let line = serde_json::to_string(&SessionRecord::at(0, event).reason("late")).unwrap();
            assert!(line.contains(&format!(r#""event":"{name}""#)), "{line}");
        }
    }

    /// Design `direct` §8.1: a `session_ended` line carries the media route
    /// and the direct-path summary when they are known and reads back as
    /// written; without them it is the line it always was, and such a line
    /// reads back with neither. A summary has names, a flag and a time only.
    #[test]
    fn a_session_end_carries_its_route_and_path_summary() {
        let dev = DeviceId::from_bytes([1u8; 32]);
        let ended = SessionRecord::at(1_700_000_000, SessionEvent::SessionEnded)
            .peer(dev, "Laptop")
            .session("abcd")
            .detail("PeerBye(1)");
        let plain = serde_json::to_string(&ended).unwrap();
        assert!(
            !plain.contains("transport") && !plain.contains("path_summary"),
            "{plain}"
        );
        let summary = PathSummary {
            outcome: "direct".into(),
            winner: Some("host".into()),
            ipv6: false,
            ms: 412,
        };
        let full = ended
            .clone()
            .transport(TransportKind::Lan)
            .path_summary(summary);
        let line = serde_json::to_string(&full).unwrap();
        assert!(line.contains(r#""transport":"lan""#), "{line}");
        assert!(
            line.contains(
                r#""path_summary":{"outcome":"direct","winner":"host","ipv6":false,"ms":412}"#
            ),
            "{line}"
        );
        let back: SessionRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(back, full);
        let old: SessionRecord = serde_json::from_str(&plain).unwrap();
        assert_eq!((old.transport, old.path_summary), (None, None));

        let fallback = PathSummary {
            outcome: "NO_PATH".into(),
            winner: None,
            ipv6: false,
            ms: 4000,
        };
        assert_eq!(
            serde_json::to_string(&fallback).unwrap(),
            r#"{"outcome":"NO_PATH","ipv6":false,"ms":4000}"#
        );
        let minimal: PathSummary = serde_json::from_str(r#"{"outcome":"old-viewer"}"#).unwrap();
        assert_eq!(
            minimal,
            PathSummary {
                outcome: "old-viewer".into(),
                winner: None,
                ipv6: false,
                ms: 0,
            }
        );
    }

    /// Design `services` §8: the four services events have their names; a
    /// received file's line holds its stored name and size, a sent file's
    /// line this computer's path and size, the turn-off line what was
    /// turned off, and the summary line counts alone; each reads back as
    /// written. The Sessions page's rows and the admin-command count pass
    /// over them.
    #[test]
    fn the_services_events_reach_the_log() {
        for (event, name) in [
            (SessionEvent::FileReceived, "file_received"),
            (SessionEvent::FileSent, "file_sent"),
            (SessionEvent::ServicesTurnedOff, "services_turned_off"),
            (SessionEvent::ServicesSummary, "services_summary"),
        ] {
            let line = serde_json::to_string(&SessionRecord::at(0, event)).unwrap();
            assert!(line.contains(&format!(r#""event":"{name}""#)), "{line}");
        }
        let dir = tempfile::tempdir().unwrap();
        let log = SessionLog::new(dir.path().join("sessions.log"));
        let dev = DeviceId::from_bytes([3u8; 32]);
        let received = SessionRecord::at(1_700_000_000, SessionEvent::FileReceived)
            .peer(dev, "Laptop")
            .session("abcd")
            .path("report (2).pdf")
            .bytes(12_345);
        let sent = SessionRecord::at(1_700_000_001, SessionEvent::FileSent)
            .peer(dev, "Laptop")
            .session("abcd")
            .path("/home/u/Documents/plan.odt")
            .bytes(0);
        let off = SessionRecord::at(1_700_000_002, SessionEvent::ServicesTurnedOff)
            .session("abcd")
            .op("clipboard,receive_files,browse_files");
        let counts = ServicesCounts {
            clip_in: 1,
            clip_out: 2,
            files_in: 3,
            bytes_in: 4_294_967_296,
            files_out: 5,
            bytes_out: 6,
            chat_in: 7,
            chat_out: 8,
        };
        let summary = SessionRecord::at(1_700_000_003, SessionEvent::ServicesSummary)
            .session("abcd")
            .reason("session_over")
            .detail(counts.detail());
        for record in [&received, &sent, &off, &summary] {
            log.append(record).unwrap();
        }
        let lines = log.read_lines().unwrap();
        assert!(
            lines[0].contains(r#""detail":"12345 bytes""#)
                && lines[0].contains(r#""path":"report (2).pdf""#),
            "{}",
            lines[0]
        );
        assert!(lines[1].contains(r#""detail":"0 bytes""#), "{}", lines[1]);
        assert!(
            lines[3].contains(
                r#""detail":"clip_in=1 clip_out=2 files_in=3 bytes_in=4294967296 files_out=5 bytes_out=6 chat_in=7 chat_out=8""#
            ),
            "{}",
            lines[3]
        );
        assert_eq!(
            ServicesCounts::default().detail(),
            "clip_in=0 clip_out=0 files_in=0 bytes_in=0 files_out=0 bytes_out=0 chat_in=0 \
             chat_out=0"
        );
        let all = log.read_all().unwrap();
        assert_eq!(all, [received, sent, off, summary]);
        assert_eq!(admin_commands_that_ran_nothing(&all, &dev), 0);
        assert_eq!(log.verify_links().unwrap().status, ChainStatus::MissingHead);
    }

    #[test]
    fn most_restrictive_is_monotone_toward_view_only() {
        use SessionMode::*;
        assert_eq!(SessionMode::most_restrictive(Control, Control), Control);
        assert_eq!(SessionMode::most_restrictive(Control, ViewOnly), ViewOnly);
        assert_eq!(SessionMode::most_restrictive(ViewOnly, Control), ViewOnly);
        assert_eq!(SessionMode::most_restrictive(ViewOnly, ViewOnly), ViewOnly);
        assert_eq!(SessionMode::from_wire(1), Some(ViewOnly));
        assert_eq!(SessionMode::from_wire(7), None);
    }

    #[test]
    fn chain_links_and_tags_verify_and_tamper_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let log = SessionLog::new(dir.path().join("sessions.log"));
        // two untagged lines (attended-only), then a key, then tagged lines
        let h1 = log
            .append_chained(&SessionRecord::now(SessionEvent::PairAccepted))
            .unwrap();
        let h2 = log
            .append_chained(&SessionRecord::now(SessionEvent::SessionStarted))
            .unwrap();
        assert_ne!(h1, h2);
        log.set_log_key(Some(Zeroizing::new([9u8; 32])));
        let h3 = log
            .append_chained(&SessionRecord::now(SessionEvent::GrantCreated))
            .unwrap();
        let h4 = log
            .append_chained(&SessionRecord::now(SessionEvent::UnattendedEnabled))
            .unwrap();

        let lines = log.read_lines().unwrap();
        assert_eq!(lines.len(), 4);
        let c1 = parse_line_chain(&lines[0]).unwrap();
        assert_eq!(c1.prev, None);
        assert_eq!(c1.tag, None);
        let c2 = parse_line_chain(&lines[1]).unwrap();
        assert_eq!(c2.prev, Some(h1));
        let c3 = parse_line_chain(&lines[2]).unwrap();
        assert_eq!(c3.prev, Some(h2));
        assert!(c3.tag.is_some());
        assert_eq!(line_hash(lines[3].as_bytes()), h4);

        // head at the last line: valid
        let rep = log.verify_chain(Some(&h4), None).unwrap();
        assert_eq!(rep.status, ChainStatus::Valid);
        assert_eq!(rep.lines, 4);
        assert_eq!(rep.last_hash, Some(h4));
        assert_eq!(rep.tagged_beyond_head, 0);

        // head one behind: the tagged line beyond it is accepted and counted
        let rep = log.verify_chain(Some(&h3), None).unwrap();
        assert_eq!(rep.status, ChainStatus::Valid);
        assert_eq!(rep.tagged_beyond_head, 1);
        assert_eq!(rep.last_hash, Some(h4));

        // no head at all: warning
        let rep = log.verify_chain(None, None).unwrap();
        assert_eq!(rep.status, ChainStatus::MissingHead);

        // a foreign head: truncated
        let rep = log.verify_chain(Some(&[0xaa; 32]), None).unwrap();
        assert!(matches!(rep.status, ChainStatus::Broken { .. }));

        // a line appended without the key beyond the head is refused
        std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap()
            .write_all(
                format!(
                    "{{\"ts\":\"x\",\"event\":\"grant_revoked\",\"prev\":\"{}\",\"tag\":null}}\n",
                    hex::encode(h4)
                )
                .as_bytes(),
            )
            .unwrap();
        let rep = log.verify_chain(Some(&h4), None).unwrap();
        assert!(
            matches!(rep.status, ChainStatus::Broken { line: 5, .. }),
            "{rep:?}"
        );

        // tampering with an earlier line breaks the chain there
        let mut text = std::fs::read_to_string(log.path()).unwrap();
        text = text.replacen("grant_created", "grant_revoked", 1);
        std::fs::write(log.path(), text).unwrap();
        let rep = log.verify_chain(Some(&h4), None).unwrap();
        assert!(matches!(rep.status, ChainStatus::Broken { line: 3, .. }));
    }

    #[test]
    fn rotation_keeps_the_chain_across_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.log");
        let log = SessionLog::new(&path);
        log.set_log_key(Some(Zeroizing::new([1u8; 32])));
        let h1 = log
            .append_chained(&SessionRecord::now(SessionEvent::GrantCreated))
            .unwrap();
        // grow the live file past the rotation threshold with one (foreign) padding line
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            let big = vec![b'x'; ROTATE_AT_BYTES as usize];
            f.write_all(&big).unwrap();
            f.write_all(b"\n").unwrap();
        }
        let padding_hash = {
            let text = std::fs::read_to_string(&path).unwrap();
            line_hash(text.lines().last().unwrap().as_bytes())
        };
        // a fresh handle (as after a restart) picks the tail up from the file
        let log2 = SessionLog::new(&path);
        log2.set_log_key(Some(Zeroizing::new([1u8; 32])));
        let h2 = log2
            .append_chained(&SessionRecord::now(SessionEvent::GrantRevoked))
            .unwrap();
        assert!(log2.rotated_path(1).exists(), "rotation happened");
        let live = log2.read_lines().unwrap();
        assert_eq!(live.len(), 1);
        let c = parse_line_chain(&live[0]).unwrap();
        assert_eq!(
            c.prev,
            Some(padding_hash),
            "prev = last line of the rotated file"
        );
        assert_ne!(h1, h2);
        // a second rotation shifts .1 to .2
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            let big = vec![b'y'; ROTATE_AT_BYTES as usize];
            f.write_all(&big).unwrap();
            f.write_all(b"\n").unwrap();
        }
        log2.append(&SessionRecord::now(SessionEvent::GrantPruned))
            .unwrap();
        assert!(log2.rotated_path(2).exists());
        let one = std::fs::read_to_string(log2.rotated_path(2)).unwrap();
        assert!(one.starts_with('{'), "oldest file holds the first line");
    }

    #[test]
    fn two_handles_on_one_file_keep_a_single_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.log");
        let a = SessionLog::new(&path);
        let b = SessionLog::new(&path);
        let key = Zeroizing::new([4u8; 32]);
        a.set_log_key(Some(key.clone()));
        b.set_log_key(Some(key));
        let mut hashes = Vec::new();
        for i in 0..6 {
            let handle = if i % 2 == 0 { &a } else { &b };
            hashes.push(
                handle
                    .append_chained(&SessionRecord::now(SessionEvent::GrantChanged))
                    .unwrap(),
            );
        }
        let lines = a.read_lines().unwrap();
        assert_eq!(lines.len(), 6);
        for (i, line) in lines.iter().enumerate().skip(1) {
            let c = parse_line_chain(line).unwrap();
            assert_eq!(
                c.prev,
                Some(hashes[i - 1]),
                "line {i} links to its predecessor"
            );
        }
        let rep = a.verify_chain(Some(&hashes[5]), None).unwrap();
        assert_eq!(rep.status, ChainStatus::Valid, "{rep:?}");
        let rep = b.verify_chain(Some(&hashes[2]), None).unwrap();
        assert_eq!(rep.status, ChainStatus::Valid);
        assert_eq!(rep.tagged_beyond_head, 3);
        // a long last line (beyond the tail window) is still found
        let long = SessionRecord::now(SessionEvent::GrantChanged).detail("y".repeat(70_000));
        let h_long = a.append_chained(&long).unwrap();
        let h_next = b
            .append_chained(&SessionRecord::now(SessionEvent::GrantRevoked))
            .unwrap();
        let lines = a.read_lines().unwrap();
        assert_eq!(parse_line_chain(&lines[7]).unwrap().prev, Some(h_long));
        assert_eq!(
            a.verify_chain(Some(&h_next), None).unwrap().status,
            ChainStatus::Valid
        );
    }

    #[test]
    fn reject_aggregator_emits_one_line_per_window() {
        use std::time::Duration;
        let dev = DeviceId::from_bytes([3u8; 32]);
        let mut agg = RejectAggregator::default();
        assert!(
            agg.note(dev, 0x0010, Duration::from_secs(0), 100)
                .is_empty()
        );
        assert!(
            agg.note(dev, 0x0010, Duration::from_secs(10), 110)
                .is_empty()
        );
        assert!(
            agg.note(dev, 0x0011, Duration::from_secs(20), 120)
                .is_empty()
        );
        assert_eq!(agg.pending(), 2);
        let out = agg.note(dev, 0x0010, Duration::from_secs(61), 161);
        assert_eq!(
            out,
            vec![AggregatedReject {
                device: dev,
                reason: 0x0010,
                count: 2,
                first_at: 100
            }]
        );
        assert_eq!(agg.pending(), 2);
        let out = agg.drain(Duration::from_secs(200));
        assert_eq!(out.len(), 2);
        assert!(agg.flush_all().is_empty());
    }

    #[test]
    fn record_at_formats_unix_time() {
        let r = SessionRecord::at(1_700_000_000, SessionEvent::ClockAnomaly).count(3);
        assert_eq!(r.ts, "2023-11-14T22:13:20Z");
        assert_eq!(r.count, Some(3));
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"event\":\"clock_anomaly\""));
        assert!(!json.contains("grant"));
    }

    #[test]
    fn torn_last_line_is_healed_by_the_next_append_and_tolerated_by_the_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.log");
        let log = SessionLog::new(&path);
        log.set_log_key(Some(Zeroizing::new([2u8; 32])));
        let h1 = log
            .append_chained(&SessionRecord::now(SessionEvent::GrantCreated))
            .unwrap();
        log.append_chained(&SessionRecord::now(SessionEvent::UnattendedEnabled))
            .unwrap();
        // a crash between write_all and sync_all: the last line loses its tail
        let text = std::fs::read_to_string(&path).unwrap();
        let cut = text.len() - 40;
        std::fs::write(&path, &text.as_bytes()[..cut]).unwrap();
        let fragment = std::fs::read_to_string(&path).unwrap();
        let fragment = fragment.lines().last().unwrap().to_owned();
        assert!(parse_line_chain(&fragment).is_none());
        // the crash state itself: tolerated as the trailing torn line
        let rep = log.verify_chain(Some(&h1), None).unwrap();
        assert_eq!(rep.status, ChainStatus::Valid, "{rep:?}");
        assert_eq!(rep.torn_lines, 1);
        assert_eq!(rep.tagged_beyond_head, 0);
        // the next append terminates the fragment and links to it
        let log2 = SessionLog::new(&path);
        log2.set_log_key(Some(Zeroizing::new([2u8; 32])));
        let h3 = log2
            .append_chained(&SessionRecord::now(SessionEvent::GrantRevoked))
            .unwrap();
        let lines = log2.read_lines().unwrap();
        assert_eq!(lines.len(), 3, "the fragment is its own line");
        assert_eq!(lines[1], fragment);
        assert_eq!(
            parse_line_chain(&lines[2]).unwrap().prev,
            Some(line_hash(fragment.as_bytes()))
        );
        let rep = log2.verify_chain(Some(&h1), None).unwrap();
        assert_eq!(rep.status, ChainStatus::Valid, "{rep:?}");
        assert_eq!(rep.torn_lines, 1);
        assert_eq!(
            rep.tagged_beyond_head, 1,
            "the vouching line is beyond the head"
        );
        assert_eq!(rep.last_hash, Some(h3));
        assert_eq!(
            log2.verify_chain(Some(&h3), None).unwrap().status,
            ChainStatus::Valid
        );
        // readers skip the fragment
        assert_eq!(log2.read_all().unwrap().len(), 2);
        // a foreign record without chain members is not a torn line
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"ts\":\"x\",\"event\":\"session_ended\"}\n")
            .unwrap();
        let rep = log2.verify_chain(Some(&h3), None).unwrap();
        assert!(
            matches!(rep.status, ChainStatus::Broken { line: 4, .. }),
            "{rep:?}"
        );
    }

    /// B13: a crash that cuts the last line inside a multi-byte character leaves
    /// bytes that are not UTF-8. The verifier read lines as text and failed with an
    /// I/O error, which, run at every host start, would have failed every start
    /// after it; the fragment is now a torn line like any other, tolerated at the
    /// end and once the next append links to it, and the chain still verifies.
    #[test]
    fn a_line_cut_inside_a_character_is_a_torn_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.log");
        let log = SessionLog::new(&path);
        log.set_log_key(Some(Zeroizing::new([4u8; 32])));
        let h1 = log
            .append_chained(&SessionRecord::now(SessionEvent::GrantCreated))
            .unwrap();
        log.append_chained(
            &SessionRecord::now(SessionEvent::GrantChanged).detail("Zoë's laptop, 東京"),
        )
        .unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let cut = bytes.windows(2).rposition(|w| w == "ë".as_bytes()).unwrap() + 1;
        std::fs::write(&path, &bytes[..cut]).unwrap();
        let fragment =
            bytes[bytes[..cut].iter().rposition(|b| *b == b'\n').unwrap() + 1..cut].to_vec();
        assert!(std::str::from_utf8(&fragment).is_err(), "cut inside the ë");

        let rep = log.verify_chain(Some(&h1), None).unwrap();
        assert_eq!(rep.status, ChainStatus::Valid, "{rep:?}");
        assert_eq!((rep.lines, rep.torn_lines), (2, 1));
        assert_eq!(rep.last_hash, Some(line_hash(&fragment)));

        let log2 = SessionLog::new(&path);
        log2.set_log_key(Some(Zeroizing::new([4u8; 32])));
        let h3 = log2
            .append_chained(&SessionRecord::now(SessionEvent::GrantRevoked))
            .unwrap();
        let rep = log2.verify_chain(Some(&h1), None).unwrap();
        assert_eq!(rep.status, ChainStatus::Valid, "{rep:?}");
        assert_eq!(
            (rep.lines, rep.torn_lines, rep.tagged_beyond_head),
            (3, 1, 1)
        );
        assert_eq!(rep.last_hash, Some(h3));
        assert_eq!(
            log2.read_all().unwrap().len(),
            2,
            "readers skip the fragment"
        );

        // Bytes that are not UTF-8 and that no chained line vouches for still break it.
        let mut forged = std::fs::read(&path).unwrap();
        forged.extend_from_slice(b"\xff\xfe{\n");
        forged.extend_from_slice(
            b"{\"ts\":\"x\",\"event\":\"grant_created\",\"prev\":null,\"tag\":null}\n",
        );
        std::fs::write(&path, &forged).unwrap();
        let rep = log2.verify_chain(Some(&h3), None).unwrap();
        assert!(
            matches!(rep.status, ChainStatus::Broken { line: 4, .. }),
            "{rep:?}"
        );
    }

    #[test]
    fn front_truncation_is_detected_while_the_window_never_overflowed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.log");
        let log = SessionLog::new(&path);
        log.set_log_key(Some(Zeroizing::new([3u8; 32])));
        let mut last = [0u8; 32];
        for _ in 0..4 {
            last = log
                .append_chained(&SessionRecord::now(SessionEvent::GrantChanged))
                .unwrap();
        }
        assert_eq!(
            log.verify_chain(Some(&last), None).unwrap().status,
            ChainStatus::Valid
        );
        // delete the first line: the head still matches, but the front is gone
        let text = std::fs::read_to_string(&path).unwrap();
        let rest: String = text.lines().skip(1).map(|l| format!("{l}\n")).collect();
        std::fs::write(&path, rest).unwrap();
        let rep = log.verify_chain(Some(&last), None).unwrap();
        assert!(
            matches!(&rep.status, ChainStatus::Broken { line: 1, reason, .. } if reason.contains("front")),
            "{rep:?}"
        );
        // once the retention window overflowed the check is bounded to the window
        std::fs::write(log.rotated_path(ROTATE_KEEP), "").unwrap();
        assert_eq!(
            log.verify_chain(Some(&last), None).unwrap().status,
            ChainStatus::Valid
        );
    }

    #[test]
    fn key_epoch_skips_tags_of_a_wiped_key_but_keeps_the_links() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.log");
        let log = SessionLog::new(&path);
        // epoch 1 under K1
        log.set_log_key(Some(Zeroizing::new([1u8; 32])));
        log.append_chained(&SessionRecord::now(SessionEvent::GrantCreated))
            .unwrap();
        log.append_chained(&SessionRecord::now(SessionEvent::UnattendedEnabled))
            .unwrap();
        // Rotate ID: the key is gone, the marker line is untagged
        log.set_log_key(None);
        let boundary = log
            .append_chained(&SessionRecord::now(SessionEvent::HostIdRotated))
            .unwrap();
        assert_eq!(log.tail_hash().unwrap(), Some(boundary));
        // epoch 2 under K2
        log.set_log_key(Some(Zeroizing::new([2u8; 32])));
        let h4 = log
            .append_chained(&SessionRecord::now(SessionEvent::UnattendedEnabled))
            .unwrap();
        let h5 = log
            .append_chained(&SessionRecord::now(SessionEvent::GrantCreated))
            .unwrap();
        // without the epoch the K1 tags cannot verify under K2
        let rep = log.verify_chain(Some(&h5), None).unwrap();
        assert!(
            matches!(&rep.status, ChainStatus::Broken { line: 1, reason, .. } if reason == "tag does not verify"),
            "{rep:?}"
        );
        // with it the K1 lines are prev-linked only and the K2 lines verified
        let rep = log.verify_chain(Some(&h5), Some(&boundary)).unwrap();
        assert_eq!(rep.status, ChainStatus::Valid, "{rep:?}");
        assert_eq!(rep.previous_epoch_lines, 2);
        assert_eq!(rep.lines, 5);
        let rep = log.verify_chain(Some(&h4), Some(&boundary)).unwrap();
        assert_eq!(rep.status, ChainStatus::Valid);
        assert_eq!(rep.tagged_beyond_head, 1);
        // an epoch line that rotation discarded: every retained line is treated as
        // the previous epoch, and a forged line beyond the head is still refused
        let rep = log.verify_chain(Some(&h5), Some(&[0x42; 32])).unwrap();
        assert_eq!(rep.status, ChainStatus::Valid, "{rep:?}");
        assert_eq!(rep.previous_epoch_lines, 4);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(
                format!(
                    "{{\"ts\":\"x\",\"event\":\"grant_revoked\",\"prev\":\"{}\",\"tag\":null}}\n",
                    hex::encode(h5)
                )
                .as_bytes(),
            )
            .unwrap();
        let rep = log.verify_chain(Some(&h5), Some(&[0x42; 32])).unwrap();
        assert!(
            matches!(rep.status, ChainStatus::Broken { line: 6, .. }),
            "{rep:?}"
        );
        // tampering before the boundary breaks a prev link, tampering at the boundary too
        let text = std::fs::read_to_string(&path).unwrap();
        let text = text.replacen("grant_created", "grant_revoked", 1);
        std::fs::write(&path, text).unwrap();
        let rep = log.verify_chain(Some(&h5), Some(&boundary)).unwrap();
        assert!(
            matches!(rep.status, ChainStatus::Broken { line: 2, .. }),
            "{rep:?}"
        );
    }

    /// §B.8.6.1 (decision M1-67): the device card's count rises for each admin command
    /// of the device that ran nothing: one refused, one unknown (refused too), an
    /// `end_session` while it had no session open; not for an `end_session` during its
    /// open session, an executed `revoke`, another device's commands, or after its
    /// session ended for nothing but a later `end_session`.
    #[test]
    fn the_card_count_rises_for_an_admin_command_that_ran_nothing() {
        let dev = DeviceId::from_bytes([1u8; 32]);
        let other = DeviceId::from_bytes([2u8; 32]);
        let admin = |device, op: &str, ok: bool| {
            SessionRecord::at(1_700_000_000, SessionEvent::AdminRequest)
                .device(device)
                .op(op)
                .ok(ok)
                .unattended(true)
        };
        let started = SessionRecord::at(1_700_000_000, SessionEvent::SessionStarted)
            .peer(dev, "Laptop")
            .session("s1")
            .mode(SessionMode::Control)
            .unattended(true);
        let ended = SessionRecord::at(1_700_000_100, SessionEvent::SessionEnded)
            .peer(dev, "Laptop")
            .session("s1");
        let mut records = Vec::new();
        let count = |records: &[SessionRecord]| admin_commands_that_ran_nothing(records, &dev);
        assert_eq!(count(&records), 0);
        records.push(admin(dev, "suspend", false));
        assert_eq!(count(&records), 1, "refused");
        records.push(admin(dev, "unknown", false));
        assert_eq!(count(&records), 2, "unknown");
        records.push(admin(dev, "end_session", true));
        assert_eq!(count(&records), 3, "no session open");
        records.push(started);
        records.push(admin(dev, "end_session", true));
        assert_eq!(count(&records), 3, "its session was open");
        records.push(ended);
        records.push(admin(dev, "revoke", true));
        assert_eq!(count(&records), 3, "an executed revoke");
        records.push(admin(other, "suspend", false));
        records.push(admin(other, "end_session", true));
        assert_eq!(count(&records), 3, "another device's");
        records.push(admin(dev, "end_session", true));
        assert_eq!(count(&records), 4, "its session had ended");
    }

    /// Counting reads the records only: the live file and a rotated one are
    /// byte-identical before and after.
    #[test]
    fn counting_writes_nothing_to_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = SessionLog::new(dir.path().join("logs").join("sessions.log"));
        let dev = DeviceId::from_bytes([1u8; 32]);
        let refused = SessionRecord::now(SessionEvent::AdminRequest)
            .device(dev)
            .op("suspend")
            .ok(false);
        log.append(&refused).unwrap();
        let rotated = log.rotated_path(1);
        std::fs::copy(log.path(), &rotated).unwrap();
        log.append(&refused).unwrap();
        let before = (
            std::fs::read(log.path()).unwrap(),
            std::fs::read(&rotated).unwrap(),
        );
        let records = log.read_all_including_rotated().unwrap();
        assert_eq!(admin_commands_that_ran_nothing(&records, &dev), 3);
        let after = (
            std::fs::read(log.path()).unwrap(),
            std::fs::read(&rotated).unwrap(),
        );
        assert_eq!(before, after);
    }

    /// A line that is not UTF-8 is skipped as malformed, and the records around it
    /// are read; the window's reader says that part could not be read.
    #[test]
    fn a_line_that_is_not_utf8_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let log = SessionLog::new(dir.path().join("logs").join("sessions.log"));
        let dev = DeviceId::from_bytes([1u8; 32]);
        let r1 = SessionRecord::now(SessionEvent::PairAccepted).peer(dev, "Laptop");
        let r2 = SessionRecord::now(SessionEvent::PairRejected).peer(dev, "Laptop");
        log.append(&r1).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap()
            .write_all(b"{\"event\":\"\xff\xfe\"}\n")
            .unwrap();
        log.append(&r2).unwrap();
        assert_eq!(log.read_all().unwrap(), vec![r1.clone(), r2.clone()]);
        assert_eq!(log.read_all_readable(), (vec![r1, r2], false));
    }

    /// A file that cannot be read keeps what the other files hold: the window's reader
    /// returns the records it could read and says that part could not be.
    #[test]
    fn a_file_that_cannot_be_read_keeps_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let log = SessionLog::new(dir.path().join("logs").join("sessions.log"));
        let dev = DeviceId::from_bytes([1u8; 32]);
        let r1 = SessionRecord::now(SessionEvent::PairAccepted).peer(dev, "Laptop");
        log.append(&r1).unwrap();
        std::fs::rename(log.path(), log.rotated_path(1)).unwrap();
        // A directory where the live file is: it opens, but cannot be read.
        std::fs::create_dir(log.path()).unwrap();
        assert!(log.read_all_including_rotated().is_err());
        assert_eq!(log.read_all_readable(), (vec![r1], false));
    }
}
