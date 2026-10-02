//! The normative store and grant records of `docs/PLAN.md` §B.8.9, their presets
//! (§B.8.1 story table, §B.8.6.1) and the policy-option merge used by the mutation
//! guard (`GrantOptions`, §B.8.7.4).
//!
//! CBOR: every struct is a map with the documented integer keys (`#[n(..)]`), every
//! enum a two-element array `[variant index, map]` or a bare index for field-less
//! enums; unknown keys are skipped on decode (`minicbor-derive`), so fields can be
//! added under a new key without a `schema_version` bump.

use core::fmt;

use minicbor::{Decode, Encode};
use zeroize::Zeroizing;

use crate::id::DeviceId;
use crate::levels::Elevation;
use crate::session_log::{Actor, SessionMode, TransportKind};

use super::ipc::GrantOptions;

/// Current `UnattendedStore.schema_version`.
pub const SCHEMA_VERSION: u16 = 1;

/// `UnattendedGrant.id`: random at creation, hex in logs (distinct from `device`).
pub type GrantId = [u8; 8];

/// Lifetime failure budget per local unlock (§B.8.5.1): `since_unlock ≥ 60` ⇒ hard lock.
pub const LIFETIME_BUDGET: u32 = 60;
/// Wizard default for `hard_lock_after`.
pub const DEFAULT_HARD_LOCK_AFTER: u32 = 20;
/// `hard_lock_after` of the *Helping someone* and *Headless box* presets.
pub const HELPER_HARD_LOCK_AFTER: u32 = 10;
/// Longest block window (§B.8.1: 0–30 s).
pub const MAX_BLOCK_WINDOW_S: u8 = 30;
/// Shortest block window of the *Helping someone* preset.
pub const HELPER_MIN_BLOCK_WINDOW_S: u8 = 5;
/// 90 days, the own-device expiry and the cap on file-keystore hosts (§B.8.6.1).
pub const EXPIRY_90D_S: u64 = 90 * 86_400;
/// 7 days, the helper expiry.
pub const EXPIRY_7D_S: u64 = 7 * 86_400;
/// Expired auth records are pruned this long after expiry (§B.8.6.1).
pub const PRUNE_AFTER_EXPIRY_S: u64 = 30 * 86_400;
/// Cooling-off of the *Helping someone* preset (`active_from = created_at + 12 h`).
pub const HELPER_COOLING_OFF_S: u64 = 12 * 3600;

/// `Zeroizing<Vec<u8>>` as a CBOR byte string (decoded straight into a zeroizing buffer).
pub mod zbytes {
    use minicbor::decode::Decoder;
    use minicbor::encode::{Encoder, Write};
    use zeroize::Zeroizing;

    /// Encode as a definite-length byte string.
    pub fn encode<C, W: Write>(
        v: &Zeroizing<Vec<u8>>,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(v)?.ok()
    }

    /// Decode a definite-length byte string into a zeroizing buffer.
    pub fn decode<C>(
        d: &mut Decoder<'_>,
        _: &mut C,
    ) -> Result<Zeroizing<Vec<u8>>, minicbor::decode::Error> {
        Ok(Zeroizing::new(d.bytes()?.to_vec()))
    }
}

/// Everything policy-relevant lives here; `config.toml` has no `[unattended]` table.
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct UnattendedStore {
    /// Schema version (currently [`SCHEMA_VERSION`]); a newer one fails closed at load.
    #[n(0)]
    pub schema_version: u16,
    /// Master switch.
    #[n(1)]
    pub enabled: bool,
    /// Paused until this unix time (12 h / until 08:00 / until re-enabled).
    #[n(2)]
    pub paused_until: Option<u64>,
    /// `opaque-ke` `ServerSetup::serialize()` (128 B); created at the first unattended
    /// enable, kept across off/on cycles, wiped only by *Rotate ID*.
    #[n(3)]
    #[cbor(with = "zbytes")]
    pub server_setup: Zeroizing<Vec<u8>>,
    /// `SHA-256("tornect/v1/stop\0" || host_onion_pk || stop_code)` — never the code (§B.8.7.4).
    #[n(4)]
    #[cbor(with = "minicbor::bytes")]
    pub stop_token: Option<[u8; 32]>,
    /// Wizard default for new grants (20).
    #[n(5)]
    pub default_hard_lock_after: u32,
    /// Host-wide keep-awake (§B.8.7.5).
    #[n(6)]
    pub keep_awake: bool,
    /// "Prevent idle lock while unattended access is on".
    #[n(7)]
    pub prevent_idle_lock: bool,
    /// Per-start notifications.
    #[n(8)]
    pub notify: bool,
    /// One grant per `device`.
    #[n(9)]
    pub grants: Vec<UnattendedGrant>,
    /// Revocations survive imports (merged); against a restored file the anchor rule,
    /// not this list, is the guarantee (§B.8.9).
    #[n(10)]
    pub tombstones: Vec<(DeviceId, u64)>,
    /// SHA-256 of the last accepted `sessions.log` line (all zero = none yet, §B.8.13).
    #[n(11)]
    #[cbor(with = "minicbor::bytes")]
    pub log_chain_head: [u8; 32],
    /// Monotone: `max(stored, now, anchors)` at every write (§B.8.5.3).
    #[n(12)]
    pub last_seen_unix: u64,
    /// Generation of the last policy write; the keychain anchor is raised to it at that
    /// write or, if the keychain was unwritable then, at the next start/mutation (§B.8.9).
    #[n(13)]
    pub pending_anchor: u64,
    /// `SHA-256("tornect/v1/machine-id\0" || OS machine id)`; mismatch at load ⇒ every
    /// grant `Disabled{by: Restore}` (§B.8.12); `None` = id unavailable, check skipped.
    #[n(14)]
    #[cbor(with = "minicbor::bytes")]
    pub machine_id_hash: Option<[u8; 32]>,
    /// Hash of the last `sessions.log` line written before the first line tagged with
    /// this store's `K_log` (set at bootstrap): the verifier checks tags from the next
    /// line on and accepts earlier tagged lines as prev-linked but unverifiable — their
    /// key was wiped by *Rotate ID* or a store reset (§B.8.13). `None` when the log was
    /// empty at bootstrap.
    #[n(15)]
    #[cbor(with = "minicbor::bytes")]
    pub log_chain_epoch: Option<[u8; 32]>,
}

impl UnattendedStore {
    /// The store created by the first unattended enable (§B.8.9 bootstrap).
    #[must_use]
    pub fn bootstrap(
        server_setup: Zeroizing<Vec<u8>>,
        machine_id_hash: Option<[u8; 32]>,
        now: u64,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            enabled: false,
            paused_until: None,
            server_setup,
            stop_token: None,
            default_hard_lock_after: DEFAULT_HARD_LOCK_AFTER,
            keep_awake: true,
            prevent_idle_lock: false,
            notify: true,
            grants: Vec::new(),
            tombstones: Vec::new(),
            log_chain_head: [0u8; 32],
            last_seen_unix: now,
            pending_anchor: 1,
            machine_id_hash,
            log_chain_epoch: None,
        }
    }

    /// The grant for `device`, if any.
    #[must_use]
    pub fn grant(&self, device: &DeviceId) -> Option<&UnattendedGrant> {
        self.grants.iter().find(|g| &g.device == device)
    }

    /// Mutable access to the grant for `device`.
    pub fn grant_mut(&mut self, device: &DeviceId) -> Option<&mut UnattendedGrant> {
        self.grants.iter_mut().find(|g| &g.device == device)
    }

    /// Whether the master switch is on and no pause is active at `now`.
    #[must_use]
    pub fn active_at(&self, now: u64) -> bool {
        self.enabled && self.paused_until.is_none_or(|until| now >= until)
    }

    /// Constant-time comparison of a presented `HELLO.stop_token` (§B.8.7.4). One
    /// 32-byte compare runs whatever the host holds: without a token the compare is
    /// against zeros and its result is masked, so the unpaired path stays uniform
    /// (§B.8.16, T5) instead of branching on the presence of a token.
    #[must_use]
    pub fn stop_token_matches(&self, presented: &[u8; 32]) -> bool {
        use subtle::{Choice, ConstantTimeEq as _};
        let stored = self.stop_token.unwrap_or([0u8; 32]);
        let equal = stored.ct_eq(presented);
        bool::from(equal & Choice::from(u8::from(self.stop_token.is_some())))
    }

    /// `log_chain_head` as an `Option` (all-zero = none).
    #[must_use]
    pub fn chain_head(&self) -> Option<[u8; 32]> {
        (self.log_chain_head != [0u8; 32]).then_some(self.log_chain_head)
    }
}

impl fmt::Debug for UnattendedStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnattendedStore")
            .field("schema_version", &self.schema_version)
            .field("enabled", &self.enabled)
            .field("paused_until", &self.paused_until)
            .field(
                "server_setup",
                &format_args!("<{} bytes>", self.server_setup.len()),
            )
            .field("stop_token", &self.stop_token.map(|_| "<redacted>"))
            .field("default_hard_lock_after", &self.default_hard_lock_after)
            .field("keep_awake", &self.keep_awake)
            .field("prevent_idle_lock", &self.prevent_idle_lock)
            .field("notify", &self.notify)
            .field("grants", &self.grants)
            .field("tombstones", &self.tombstones)
            .field("log_chain_head", &hex::encode(self.log_chain_head))
            .field("last_seen_unix", &self.last_seen_unix)
            .field("pending_anchor", &self.pending_anchor)
            .field("machine_id_hash", &self.machine_id_hash.map(hex::encode))
            .field("log_chain_epoch", &self.log_chain_epoch.map(hex::encode))
            .finish()
    }
}

/// Preset of the §B.8.1 story table; decides the admin scope (§B.8.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
#[cbor(index_only)]
pub enum Preset {
    /// Own devices: Control, block 3 s, 90 d auto-renewed, hard lock after 20.
    #[n(0)]
    MyMachines,
    /// Headless media/gaming box: Control, block 0, hard lock after 10, keep-awake on,
    /// expiry ≤ 90 d, waives the attended precondition.
    #[n(1)]
    HeadlessBox,
    /// Helping a relative: view-only, 7 d, block 10 s (min 5), hard lock after 10,
    /// ask before starting, active 12 h after creation, max session 4 h, cooldown 10 min.
    #[n(2)]
    HelpingSomeone,
}

impl Preset {
    /// Wire byte (`RegFinish.preset`, `GrantSummary.preset`).
    #[must_use]
    pub fn wire(self) -> u8 {
        match self {
            Self::MyMachines => 0,
            Self::HeadlessBox => 1,
            Self::HelpingSomeone => 2,
        }
    }

    /// Decode the wire byte.
    #[must_use]
    pub fn from_wire(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::MyMachines),
            1 => Some(Self::HeadlessBox),
            2 => Some(Self::HelpingSomeone),
            _ => None,
        }
    }

    /// The preset's defaults (§B.8.1 story table, §B.8.6.1).
    #[must_use]
    pub fn defaults(self) -> PresetDefaults {
        match self {
            Self::MyMachines => PresetDefaults {
                mode: SessionMode::Control,
                block_window_s: 3,
                min_block_window_s: 0,
                expiry_span_s: Some(EXPIRY_90D_S),
                expiry_cap_s: None,
                auto_renew: true,
                hard_lock_after: DEFAULT_HARD_LOCK_AFTER,
                lock_on_disconnect: false,
                lock_on_disconnect_allowed: true,
                keep_awake: false,
                ask_before_start: false,
                active_from_delay_s: 0,
                max_session_secs: None,
                reconnect_cooldown_s: 0,
                waives_attended_precondition: false,
            },
            Self::HeadlessBox => PresetDefaults {
                mode: SessionMode::Control,
                block_window_s: 0,
                min_block_window_s: 0,
                expiry_span_s: Some(EXPIRY_90D_S),
                expiry_cap_s: Some(EXPIRY_90D_S),
                auto_renew: true,
                hard_lock_after: HELPER_HARD_LOCK_AFTER,
                lock_on_disconnect: false,
                lock_on_disconnect_allowed: false,
                keep_awake: true,
                ask_before_start: false,
                active_from_delay_s: 0,
                max_session_secs: None,
                reconnect_cooldown_s: 0,
                waives_attended_precondition: true,
            },
            Self::HelpingSomeone => PresetDefaults {
                mode: SessionMode::ViewOnly,
                block_window_s: 10,
                min_block_window_s: HELPER_MIN_BLOCK_WINDOW_S,
                expiry_span_s: Some(EXPIRY_7D_S),
                expiry_cap_s: None,
                auto_renew: false,
                hard_lock_after: HELPER_HARD_LOCK_AFTER,
                lock_on_disconnect: false,
                lock_on_disconnect_allowed: true,
                keep_awake: false,
                ask_before_start: true,
                active_from_delay_s: HELPER_COOLING_OFF_S,
                max_session_secs: Some(4 * 3600),
                reconnect_cooldown_s: 600,
                waives_attended_precondition: false,
            },
        }
    }
}

/// What a [`Preset`] fixes before the user's options are applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetDefaults {
    /// Session mode.
    pub mode: SessionMode,
    /// Block window.
    pub block_window_s: u8,
    /// Lowest block window the preset allows.
    pub min_block_window_s: u8,
    /// Expiry span from creation (`None` = never).
    pub expiry_span_s: Option<u64>,
    /// Longest expiry the preset allows (`None` = unbounded).
    pub expiry_cap_s: Option<u64>,
    /// Auto-renew on successful use.
    pub auto_renew: bool,
    /// Consecutive hard-lock threshold.
    pub hard_lock_after: u32,
    /// Lock-on-disconnect default.
    pub lock_on_disconnect: bool,
    /// Whether lock-on-disconnect may be enabled at all (refused for *Headless box*).
    pub lock_on_disconnect_allowed: bool,
    /// Whether the preset turns host-wide keep-awake on (presets never turn it off).
    pub keep_awake: bool,
    /// "Ask before starting".
    pub ask_before_start: bool,
    /// Cooling-off: `active_from = created_at + delay`.
    pub active_from_delay_s: u64,
    /// Maximum session length.
    pub max_session_secs: Option<u32>,
    /// Reconnect cooldown after `max_session_secs`.
    pub reconnect_cooldown_s: u32,
    /// Whether the ≥ 1 completed attended session precondition is auto-waived.
    pub waives_attended_precondition: bool,
}

/// The stored PAKE material of one grant (§B.8.9).
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub enum AuthRecord {
    /// Suite 1: the 192-byte `opaque-ke` `ServerRegistration` (no password-equivalent).
    #[n(0)]
    Opaque {
        /// `ServerRegistration::serialize()`.
        #[n(0)]
        #[cbor(with = "zbytes")]
        record: Zeroizing<Vec<u8>>,
    },
    /// Suite 2 (fallback, present but unused at M1): Argon2id salt + `w` wrapped under `K_unatt`.
    #[n(1)]
    Spake2 {
        /// Argon2id salt.
        #[n(0)]
        #[cbor(with = "minicbor::bytes")]
        salt: [u8; 16],
        /// Wrapped password-equivalent scalar.
        #[n(1)]
        #[cbor(with = "zbytes")]
        wrapped_w: Zeroizing<Vec<u8>>,
    },
    /// Zeroized and pruned 30 d after expiry (§B.8.6.1); the grant stays visible as
    /// *Expired* until it is revoked and can never authenticate.
    #[n(2)]
    Pruned,
}

impl AuthRecord {
    /// Length of the stored secret material (0 when pruned).
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Opaque { record } => record.len(),
            Self::Spake2 { wrapped_w, .. } => wrapped_w.len(),
            Self::Pruned => 0,
        }
    }

    /// Whether no material is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The suite this record belongs to (1 OPAQUE, 2 SPAKE2, 0 pruned).
    #[must_use]
    pub fn suite(&self) -> u8 {
        match self {
            Self::Opaque { .. } => 1,
            Self::Spake2 { .. } => 2,
            Self::Pruned => 0,
        }
    }
}

impl fmt::Debug for AuthRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opaque { record } => write!(f, "AuthRecord::Opaque(<{} bytes>)", record.len()),
            Self::Spake2 { wrapped_w, .. } => {
                write!(f, "AuthRecord::Spake2(<salt>, <{} bytes>)", wrapped_w.len())
            }
            Self::Pruned => f.write_str("AuthRecord::Pruned"),
        }
    }
}

/// Why a grant is suspended (§B.8.6.3; the local reasons outrank `Admin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
#[cbor(map)]
pub enum SuspendReason {
    /// The local user pressed **Block** during the block window.
    #[n(0)]
    LocalBlock,
    /// The panic key ended an unattended session.
    #[n(1)]
    Panic,
    /// A remote `suspend(pk)` from a *My machines* Control grant.
    #[n(2)]
    Admin,
    /// A local *Suspend* (manager button, `tornect unattended suspend`, `IpcOp::Suspend`).
    #[n(3)]
    Local {
        /// Who suspended it.
        #[n(0)]
        by: Actor,
    },
}

impl SuspendReason {
    /// Whether this reason can only be cleared by a local *Resume* (never remotely).
    #[must_use]
    pub fn is_local(self) -> bool {
        !matches!(self, Self::Admin)
    }

    /// `SESSION_REJECT.cause` for `SUSPENDED` (§B.8.4.1): 1 local · 2 admin.
    #[must_use]
    pub fn reject_cause(self) -> u8 {
        if self.is_local() { 1 } else { 2 }
    }

    /// Log name (§B.8.13 `reason`).
    #[must_use]
    pub fn log_name(self) -> &'static str {
        match self {
            Self::LocalBlock => "local_block",
            Self::Panic => "panic",
            Self::Admin => "admin",
            Self::Local { .. } => "local",
        }
    }
}

/// Grant state (§B.8.9; *Expired* / *Not yet active* are derived, not stored).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
#[cbor(map)]
pub enum GrantState {
    /// Usable.
    #[n(0)]
    Active,
    /// Refused pre-PAKE with `SUSPENDED` until cleared per §B.8.6.3.
    #[n(1)]
    Suspended {
        /// Why.
        #[n(0)]
        reason: SuspendReason,
        /// When (unix).
        #[n(1)]
        since: u64,
    },
    /// Refused pre-PAKE with `NOT_GRANTED`; leaves only through *enable* (§B.8.6.1).
    #[n(2)]
    Disabled {
        /// When (unix).
        #[n(0)]
        since: u64,
        /// `Import` · `Restore` · `Ui` · `Cli`.
        #[n(1)]
        by: Actor,
    },
}

/// Transport policy signed into `SESSION_ACCEPT` (§B.8.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
#[cbor(index_only)]
pub enum TransportPolicy {
    /// Direct, LAN or Tor fallback.
    #[n(0)]
    Any,
    /// No candidates either way; media over the Tor tunnel.
    #[n(1)]
    TorOnly,
    /// Link-local candidates only, no Tor media fallback.
    #[n(2)]
    LanOnly,
}

impl TransportPolicy {
    /// Wire byte (`0 any, 1 tor_only, 2 lan_only`).
    #[must_use]
    pub fn wire(self) -> u8 {
        match self {
            Self::Any => 0,
            Self::TorOnly => 1,
            Self::LanOnly => 2,
        }
    }

    /// Decode the wire byte.
    #[must_use]
    pub fn from_wire(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Any),
            1 => Some(Self::TorOnly),
            2 => Some(Self::LanOnly),
            _ => None,
        }
    }
}

/// Last successful use of a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct LastUsed {
    /// Unix time of the accept.
    #[n(0)]
    pub at: u64,
    /// Transport the session ended up on.
    #[n(1)]
    pub transport: TransportKind,
    /// Session length once known (0 while live / unknown).
    #[n(2)]
    pub duration_secs: u32,
}

/// One weekly schedule window in the host's local time (§B.8.7.1 ⑤).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encode, Decode)]
#[cbor(map)]
pub struct Window {
    /// Day bitmask, bit 0 = Monday … bit 6 = Sunday (the day the window *starts*).
    #[n(0)]
    pub days: u8,
    /// Start, minutes after local midnight (0..1440).
    #[n(1)]
    pub start_min: u16,
    /// End, minutes after local midnight (0..=1440); `end ≤ start` wraps past midnight.
    #[n(2)]
    pub end_min: u16,
    /// Time-zone snapshot the window was defined in (IANA name or `UTC±HH:MM`); a
    /// mismatch with the host's zone is surfaced as a warning (§B.8.7.1 ⑤).
    #[n(3)]
    pub tz: String,
}

/// The §B.8.5.1 counters, persisted inside the grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(map)]
pub struct FailState {
    /// Consecutive failures (decays one per 24 h without attempts).
    #[n(0)]
    pub consecutive: u32,
    /// Settled failures since the last local unlock (decays one per 7 d without failures).
    #[n(1)]
    pub since_unlock: u32,
    /// Charged, not yet settled (settled as fail on load).
    #[n(2)]
    pub pending: bool,
    /// Unix time of the last settled failure.
    #[n(3)]
    pub last_fail_at: Option<u64>,
    /// Remaining lock at `flushed_at`.
    #[n(4)]
    pub lock_remaining_s: u32,
    /// Unix time of the last write of this record (monotone).
    #[n(5)]
    pub flushed_at: u64,
    /// Refuses every challenge until unlocked (never cleared by decay).
    #[n(6)]
    pub hard_locked: bool,
    /// Anchor of the consecutive decay (24 h period; never decreases).
    #[n(7)]
    pub decay_anchor: u64,
    /// Anchor of the lifetime decay (7 d period; never decreases).
    #[n(8)]
    pub lifetime_decay_anchor: u64,
}

/// What `settle(ok)` reports into `SESSION_ACCEPT.fail_summary` (§B.8.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailSummary {
    /// Consecutive failures before this success (the own charge excluded).
    pub since_success: u32,
    /// When the last of them happened (`Some` whenever `since_success > 0`).
    pub last_fail_at: Option<u64>,
}

/// Host-local record for one paired device (§B.8.9).
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct UnattendedGrant {
    /// Random at creation; hex in logs.
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub id: GrantId,
    /// Must exist in `trusted-devices.toml`; unpair cascades.
    #[n(1)]
    pub device: DeviceId,
    /// Pinned label (NFKC, control characters stripped, ≤ 64 chars).
    #[n(2)]
    pub label: String,
    /// `Ui | Cli | Import` — never `Restore` (a restore only disables).
    #[n(3)]
    pub created_by: Actor,
    /// Unix time of creation.
    #[n(4)]
    pub created_at: u64,
    /// Cooling-off end (12 h after creation for *Helping someone*).
    #[n(5)]
    pub active_from: u64,
    /// Decides the admin scope (§B.8.4.1).
    #[n(6)]
    pub preset: Preset,
    /// PAKE suite (1 OPAQUE, 2 SPAKE2).
    #[n(7)]
    pub suite: u8,
    /// PAKE material.
    #[n(8)]
    pub auth: AuthRecord,
    /// Session mode (clamped with `want_mode`, §B.8.4.1).
    #[n(9)]
    pub mode: SessionMode,
    /// Weekly windows (`None` = always).
    #[n(10)]
    pub schedule: Option<Vec<Window>>,
    /// Expiry (`None` = never — an explicit choice, refused on file-keystore hosts).
    #[n(11)]
    pub expires_at: Option<u64>,
    /// Renew the expiry on successful use.
    #[n(12)]
    pub auto_renew: bool,
    /// Maximum session length.
    #[n(13)]
    pub max_session_secs: Option<u32>,
    /// Reconnect cooldown after `max_session_secs` (§B.8.6.4).
    #[n(14)]
    pub reconnect_cooldown_s: u32,
    /// Block window (0–30 s).
    #[n(15)]
    pub block_window_s: u8,
    /// Allow/Deny popup between F2 and the block window.
    #[n(16)]
    pub ask_before_start: bool,
    /// Refuse post-F2 while a local user is present (`LOCAL_USER_PRESENT`).
    #[n(17)]
    pub require_absent: bool,
    /// Media over Tor only (`transport_policy = tor_only`).
    #[n(18)]
    pub require_tor_only: bool,
    /// Lock the host session when the remote session ends.
    #[n(19)]
    pub lock_on_disconnect: bool,
    /// 20; 10 for helpers / headless; 0 = no consecutive hard lock (lifetime budget still applies).
    #[n(20)]
    pub hard_lock_after: u32,
    /// Stored state (Expired / NotYetActive are derived).
    #[n(21)]
    pub state: GrantState,
    /// Last successful use.
    #[n(22)]
    pub last_used: Option<LastUsed>,
    /// Limiter counters.
    #[n(23)]
    pub fail: FailState,
    /// The administrator level the grant holds (§B.8.7.1; decision M1-67, D9). Absent =
    /// none, and none is never written, so a grant at none encodes as before; an older
    /// build that rewrites the store drops the key, which lowers the grant.
    #[n(24)]
    #[cbor(with = "elevation_key", skip_if = "elevation_key::is_none")]
    pub elevation: Elevation,
    /// Its password is *not* marked "answered 0" (decision M1-67, D9, D11). Absent or
    /// false = marked; only a registration sent as generated sets it, and false is
    /// never written, so a marked grant encodes as before.
    #[n(25)]
    #[cbor(skip_if = "is_false")]
    pub unmarked: bool,
}

/// `skip_if` of [`UnattendedGrant::unmarked`]: false is never written.
fn is_false(v: &bool) -> bool {
    !*v
}

/// [`UnattendedGrant::elevation`] as store key 24: the §B.8.4.1 code (`0` none,
/// `1` administrator). A code this build does not know reads as none, the lower level.
mod elevation_key {
    use minicbor::decode::Decoder;
    use minicbor::encode::{Encoder, Write};

    use crate::levels::Elevation;

    /// Encode as the code.
    pub fn encode<C, W: Write>(
        v: &Elevation,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.u8(v.code())?.ok()
    }

    /// Decode a code; one this build does not know is none.
    pub fn decode<C>(d: &mut Decoder<'_>, _: &mut C) -> Result<Elevation, minicbor::decode::Error> {
        Ok(Elevation::from_code(d.u8()?).unwrap_or(Elevation::None))
    }

    /// `skip_if`: none is never written.
    pub fn is_none(v: &Elevation) -> bool {
        *v == Elevation::None
    }
}

impl fmt::Debug for UnattendedGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnattendedGrant")
            .field("id", &hex::encode(self.id))
            .field("device", &self.device)
            .field("label", &self.label)
            .field("created_by", &self.created_by)
            .field("created_at", &self.created_at)
            .field("active_from", &self.active_from)
            .field("preset", &self.preset)
            .field("suite", &self.suite)
            .field("auth", &self.auth)
            .field("mode", &self.mode)
            .field("schedule", &self.schedule)
            .field("expires_at", &self.expires_at)
            .field("auto_renew", &self.auto_renew)
            .field("max_session_secs", &self.max_session_secs)
            .field("reconnect_cooldown_s", &self.reconnect_cooldown_s)
            .field("block_window_s", &self.block_window_s)
            .field("ask_before_start", &self.ask_before_start)
            .field("require_absent", &self.require_absent)
            .field("require_tor_only", &self.require_tor_only)
            .field("lock_on_disconnect", &self.lock_on_disconnect)
            .field("hard_lock_after", &self.hard_lock_after)
            .field("state", &self.state)
            .field("last_used", &self.last_used)
            .field("fail", &self.fail)
            .field("elevation", &self.elevation)
            .field("unmarked", &self.unmarked)
            .finish()
    }
}

/// Why a grant's options were refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantOptionsError {
    /// The block window is outside the allowed range for the preset.
    #[error("block window {0} s is outside {1}..={2} s for this preset")]
    BlockWindow(u8, u8, u8),
    /// Lock-on-disconnect is refused with *Headless box*.
    #[error("lock-on-disconnect is refused with the Headless box preset")]
    LockOnDisconnectRefused,
    /// "Never expires" or an expiry beyond 90 d on a file-keystore host / capped preset.
    #[error("expiry must be at most {0} days from now on this host")]
    ExpiryTooLong(u64),
    /// The expiry lies in the past.
    #[error("expiry lies in the past")]
    ExpiryInPast,
    /// A schedule window is malformed.
    #[error("schedule window invalid: {0}")]
    Window(String),
    /// The label is empty, too long or contains control characters.
    #[error("label invalid: {0}")]
    Label(String),
    /// A widening change was attempted where only narrowing is allowed.
    #[error("options widen the grant ({0}); use set_options (access-increasing)")]
    Widens(&'static str),
}

/// Sanitize a pinned label (§B.8.7.3: NFKC, bidi/control characters stripped, ≤ 64 chars).
/// The strip table is the pairing store's [`crate::trusted::is_invisible_or_control`] —
/// controls, bidi overrides and every default-ignorable code point (zero-width joiners,
/// the word joiner, the BOM, soft hyphen, variation selectors, tag characters) — so two
/// labels that render alike cannot differ by an invisible character and defeat the
/// duplicate-suffix rule.
pub fn sanitize_label(raw: &str) -> Result<String, GrantOptionsError> {
    use unicode_normalization::UnicodeNormalization as _;
    let s: String = raw
        .nfkc()
        .filter(|c| !crate::trusted::is_invisible_or_control(*c))
        .collect();
    let s = s.trim().to_owned();
    if s.is_empty() {
        return Err(GrantOptionsError::Label("empty".into()));
    }
    if s.chars().count() > 64 {
        return Err(GrantOptionsError::Label("longer than 64 characters".into()));
    }
    Ok(s)
}

fn validate_windows(ws: &[Window]) -> Result<(), GrantOptionsError> {
    if ws.len() > 64 {
        return Err(GrantOptionsError::Window("more than 64 windows".into()));
    }
    for w in ws {
        if w.days == 0 || w.days > 0x7F {
            return Err(GrantOptionsError::Window(format!(
                "days mask {:#x}",
                w.days
            )));
        }
        if w.start_min >= 1440 || w.end_min > 1440 {
            return Err(GrantOptionsError::Window(format!(
                "minutes {}..{} out of range",
                w.start_min, w.end_min
            )));
        }
        if w.tz.is_empty() || w.tz.len() > 64 || w.tz.chars().any(char::is_control) {
            return Err(GrantOptionsError::Window("tz name invalid".into()));
        }
    }
    Ok(())
}

/// Whether `new` opens strictly more time than `old` (§B.8.6.2 "widen schedule").
/// Conservative: a window not contained in one old window with the same zone counts
/// as widening.
#[must_use]
pub fn schedule_widens(old: Option<&[Window]>, new: Option<&[Window]>) -> bool {
    match (old, new) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(old), Some(new)) => new.iter().any(|n| {
            !old.iter().any(|o| {
                o.tz == n.tz && (n.days & !o.days) == 0 && {
                    let (os, oe) = (u32::from(o.start_min), span_end(o));
                    let (ns, ne) = (u32::from(n.start_min), span_end(n));
                    ns >= os && ne <= oe
                }
            })
        }),
    }
}

/// End of a window as minutes after the *start day's* midnight (wraps add 1440).
fn span_end(w: &Window) -> u32 {
    let (s, e) = (u32::from(w.start_min), u32::from(w.end_min));
    if e <= s { e + 1440 } else { e }
}

impl UnattendedGrant {
    /// A new grant from a preset (§B.8.1 defaults), before options are applied.
    pub fn from_preset(
        id: GrantId,
        device: DeviceId,
        label: &str,
        created_by: Actor,
        preset: Preset,
        suite: u8,
        auth: AuthRecord,
        now: u64,
    ) -> Result<Self, GrantOptionsError> {
        let d = preset.defaults();
        Ok(Self {
            id,
            device,
            label: sanitize_label(label)?,
            created_by,
            created_at: now,
            active_from: now.saturating_add(d.active_from_delay_s),
            preset,
            suite,
            auth,
            mode: d.mode,
            schedule: None,
            expires_at: d.expiry_span_s.map(|s| now.saturating_add(s)),
            auto_renew: d.auto_renew,
            max_session_secs: d.max_session_secs,
            reconnect_cooldown_s: d.reconnect_cooldown_s,
            block_window_s: d.block_window_s,
            ask_before_start: d.ask_before_start,
            require_absent: false,
            require_tor_only: false,
            lock_on_disconnect: d.lock_on_disconnect,
            hard_lock_after: d.hard_lock_after,
            state: GrantState::Active,
            last_used: None,
            fail: FailState {
                decay_anchor: now,
                lifetime_decay_anchor: now,
                flushed_at: now,
                ..FailState::default()
            },
            elevation: Elevation::None,
            unmarked: false,
        })
    }

    /// Apply `options` (a `None` field keeps the current value) and validate against
    /// the preset and host constraints. Returns the list of widening changes so the
    /// caller can classify the mutation (§B.8.6.2).
    pub fn apply_options(
        &mut self,
        options: &GrantOptions,
        now: u64,
        file_keystore: bool,
    ) -> Result<Vec<&'static str>, GrantOptionsError> {
        let d = self.preset.defaults();
        let mut widened = Vec::new();
        if let Some(label) = &options.label {
            self.label = sanitize_label(label)?;
        }
        if let Some(mode) = options.mode
            && mode != self.mode
        {
            if mode == SessionMode::Control {
                widened.push("mode");
            }
            self.mode = mode;
        }
        // The administrator level (r7, §B.8.7.1): raising it widens, lowering it is
        // deny-direction (decision M1-67). Whether this host may give it at all is the
        // guard's to decide.
        if let Some(elevation) = options.elevation
            && elevation != self.elevation
        {
            if elevation == Elevation::Admin {
                widened.push("elevation");
            }
            self.elevation = elevation;
        }
        if let Some(schedule) = &options.schedule {
            let new = if schedule.is_empty() {
                None
            } else {
                validate_windows(schedule)?;
                Some(schedule.clone())
            };
            if schedule_widens(self.schedule.as_deref(), new.as_deref()) {
                widened.push("schedule");
            }
            self.schedule = new;
        }
        if let Some(exp) = options.expires_at {
            let new = if exp == 0 { None } else { Some(exp) };
            if let Some(e) = new
                && e <= now
            {
                return Err(GrantOptionsError::ExpiryInPast);
            }
            let later = match (self.expires_at, new) {
                (Some(_), None) => true,
                (Some(o), Some(n)) => n > o,
                (None, _) => false,
            };
            if later {
                widened.push("expires_at");
            }
            self.expires_at = new;
        }
        if let Some(v) = options.auto_renew {
            if v && !self.auto_renew {
                widened.push("auto_renew");
            }
            self.auto_renew = v;
        }
        if let Some(m) = options.max_session_secs {
            let new = if m == 0 { None } else { Some(m) };
            let longer = match (self.max_session_secs, new) {
                (Some(_), None) => true,
                (Some(o), Some(n)) => n > o,
                (None, _) => false,
            };
            if longer {
                widened.push("max_session_secs");
            }
            self.max_session_secs = new;
        }
        if let Some(b) = options.block_window_s {
            if b < self.block_window_s {
                widened.push("block_window_s");
            }
            self.block_window_s = b;
        }
        if let Some(v) = options.ask_before_start {
            if !v && self.ask_before_start {
                widened.push("ask_before_start");
            }
            self.ask_before_start = v;
        }
        if let Some(v) = options.require_absent {
            if !v && self.require_absent {
                widened.push("require_absent");
            }
            self.require_absent = v;
        }
        if let Some(v) = options.require_tor_only {
            if !v && self.require_tor_only {
                widened.push("require_tor_only");
            }
            self.require_tor_only = v;
        }
        if let Some(v) = options.lock_on_disconnect {
            if !v && self.lock_on_disconnect {
                widened.push("lock_on_disconnect");
            }
            self.lock_on_disconnect = v;
        }
        if let Some(h) = options.hard_lock_after {
            // 0 (off) or a higher threshold loosens an enabled consecutive hard lock
            let looser = self.hard_lock_after != 0 && (h == 0 || h > self.hard_lock_after);
            if looser {
                widened.push("hard_lock_after");
            }
            self.hard_lock_after = h;
        }

        // preset / host constraints
        if self.block_window_s > MAX_BLOCK_WINDOW_S || self.block_window_s < d.min_block_window_s {
            return Err(GrantOptionsError::BlockWindow(
                self.block_window_s,
                d.min_block_window_s,
                MAX_BLOCK_WINDOW_S,
            ));
        }
        if self.lock_on_disconnect && !d.lock_on_disconnect_allowed {
            return Err(GrantOptionsError::LockOnDisconnectRefused);
        }
        let cap = match (file_keystore, d.expiry_cap_s) {
            (true, Some(c)) => Some(c.min(EXPIRY_90D_S)),
            (true, None) => Some(EXPIRY_90D_S),
            (false, c) => c,
        };
        if let Some(cap) = cap {
            match self.expires_at {
                None => return Err(GrantOptionsError::ExpiryTooLong(cap / 86_400)),
                Some(e) if e > now.saturating_add(cap) => {
                    return Err(GrantOptionsError::ExpiryTooLong(cap / 86_400));
                }
                _ => {}
            }
        }
        Ok(widened)
    }

    /// Whether the grant has expired at `now`.
    #[must_use]
    pub fn expired_at(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|e| now >= e)
    }

    /// The span used when `auto_renew` extends `expires_at` on successful use.
    #[must_use]
    pub fn renew_span_s(&self) -> Option<u64> {
        self.preset.defaults().expiry_span_s
    }

    /// Whether the grant is currently in a suspended state.
    #[must_use]
    pub fn is_suspended(&self) -> bool {
        matches!(self.state, GrantState::Suspended { .. })
    }

    /// Whether this grant's password is marked "answered 0" (decision M1-67, D9, D11):
    /// store key 25 absent or false. A marked password never gets a session that can
    /// reach the administrator level.
    #[must_use]
    pub fn marked(&self) -> bool {
        !self.unmarked
    }

    /// Whether this grant holds the administrator level (store key 24, decision M1-67).
    #[must_use]
    pub fn holds_level(&self) -> bool {
        self.elevation == Elevation::Admin
    }

    /// Whether this grant holds the cross-grant admin scope of §B.8.4.1.
    #[must_use]
    pub fn has_admin_scope(&self) -> bool {
        self.preset == Preset::MyMachines
            && self.mode == SessionMode::Control
            && self.state == GrantState::Active
    }

    /// The transport policy this grant signs into `SESSION_ACCEPT` given the host's
    /// privacy mode (§B.8.11). Tor-only (the grant's `require_tor_only` or the host's
    /// *Paranoid* mode) and a LAN-only host contradict each other — neither promise can
    /// be kept — so that combination is the post-F2 `TRANSPORT_UNAVAILABLE` reject
    /// (§B.8.4.6), never a silently downgraded `lan_only`.
    pub fn transport_policy(
        &self,
        host_paranoid: bool,
        host_lan_only: bool,
    ) -> Result<TransportPolicy, TransportConflict> {
        let tor_only = self.require_tor_only || host_paranoid;
        match (tor_only, host_lan_only) {
            (true, true) => Err(TransportConflict),
            (true, false) => Ok(TransportPolicy::TorOnly),
            (false, true) => Ok(TransportPolicy::LanOnly),
            (false, false) => Ok(TransportPolicy::Any),
        }
    }
}

/// The grant requires Tor-only media but the host is configured LAN-only (§B.8.11):
/// answered post-F2 with `TRANSPORT_UNAVAILABLE` (§B.8.4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("grant requires Tor-only media but the host is LAN-only")]
pub struct TransportConflict;

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(preset: Preset) -> UnattendedGrant {
        UnattendedGrant::from_preset(
            [1; 8],
            DeviceId::from_bytes([2; 32]),
            "Laptop",
            Actor::Ui,
            preset,
            1,
            AuthRecord::Opaque {
                record: Zeroizing::new(vec![7u8; 192]),
            },
            1_000_000,
        )
        .unwrap()
    }

    #[test]
    fn presets_match_the_story_table() {
        let g = grant(Preset::MyMachines);
        assert_eq!(g.mode, SessionMode::Control);
        assert_eq!(g.block_window_s, 3);
        assert_eq!(g.expires_at, Some(1_000_000 + EXPIRY_90D_S));
        assert!(g.auto_renew);
        assert_eq!(g.hard_lock_after, 20);
        assert!(!g.lock_on_disconnect);
        assert_eq!(g.active_from, 1_000_000);

        let g = grant(Preset::HeadlessBox);
        assert_eq!(g.block_window_s, 0);
        assert_eq!(g.hard_lock_after, 10);
        assert!(Preset::HeadlessBox.defaults().keep_awake);
        assert!(Preset::HeadlessBox.defaults().waives_attended_precondition);

        let g = grant(Preset::HelpingSomeone);
        assert_eq!(g.mode, SessionMode::ViewOnly);
        assert_eq!(g.expires_at, Some(1_000_000 + EXPIRY_7D_S));
        assert_eq!(g.block_window_s, 10);
        assert_eq!(g.hard_lock_after, 10);
        assert!(g.ask_before_start);
        assert_eq!(g.active_from, 1_000_000 + 12 * 3600);
        assert_eq!(g.max_session_secs, Some(4 * 3600));
        assert_eq!(g.reconnect_cooldown_s, 600);
    }

    #[test]
    fn options_are_validated_and_widening_is_reported() {
        let mut g = grant(Preset::HelpingSomeone);
        let err = g
            .apply_options(
                &GrantOptions {
                    block_window_s: Some(4),
                    ..GrantOptions::default()
                },
                1_000_000,
                false,
            )
            .unwrap_err();
        assert_eq!(err, GrantOptionsError::BlockWindow(4, 5, 30));

        let mut g = grant(Preset::HeadlessBox);
        assert_eq!(
            g.apply_options(
                &GrantOptions {
                    lock_on_disconnect: Some(true),
                    ..GrantOptions::default()
                },
                1_000_000,
                false
            ),
            Err(GrantOptionsError::LockOnDisconnectRefused)
        );

        let mut g = grant(Preset::MyMachines);
        assert_eq!(
            g.apply_options(
                &GrantOptions {
                    expires_at: Some(0),
                    ..GrantOptions::default()
                },
                1_000_000,
                true
            ),
            Err(GrantOptionsError::ExpiryTooLong(90))
        );
        let mut g = grant(Preset::MyMachines);
        let w = g
            .apply_options(
                &GrantOptions {
                    expires_at: Some(0),
                    block_window_s: Some(1),
                    ask_before_start: Some(false),
                    hard_lock_after: Some(0),
                    ..GrantOptions::default()
                },
                1_000_000,
                false,
            )
            .unwrap();
        assert_eq!(w, vec!["expires_at", "block_window_s", "hard_lock_after"]);
        assert_eq!(g.expires_at, None);

        let mut g = grant(Preset::HelpingSomeone);
        let w = g
            .apply_options(
                &GrantOptions {
                    mode: Some(SessionMode::Control),
                    schedule: Some(vec![Window {
                        days: 0b0011111,
                        start_min: 540,
                        end_min: 1020,
                        tz: "UTC+01:00".into(),
                    }]),
                    ..GrantOptions::default()
                },
                1_000_000,
                false,
            )
            .unwrap();
        assert_eq!(w, vec!["mode"]);
        // narrowing the schedule is not widening; dropping it is
        let w = g
            .apply_options(
                &GrantOptions {
                    schedule: Some(vec![Window {
                        days: 0b0000001,
                        start_min: 600,
                        end_min: 700,
                        tz: "UTC+01:00".into(),
                    }]),
                    ..GrantOptions::default()
                },
                1_000_000,
                false,
            )
            .unwrap();
        assert!(w.is_empty());
        let w = g
            .apply_options(
                &GrantOptions {
                    schedule: Some(vec![]),
                    ..GrantOptions::default()
                },
                1_000_000,
                false,
            )
            .unwrap();
        assert_eq!(w, vec!["schedule"]);
    }

    #[test]
    fn labels_are_sanitized() {
        assert_eq!(
            sanitize_label("  Ana\u{202e}'s\tLaptop ").unwrap(),
            "Ana'sLaptop"
        );
        assert!(sanitize_label("   ").is_err());
        assert!(sanitize_label(&"x".repeat(65)).is_err());
        // zero-width / default-ignorable look-alikes collapse onto the visible label
        for invisible in [
            "\u{200B}",
            "\u{200C}",
            "\u{200D}",
            "\u{2060}",
            "\u{FEFF}",
            "\u{00AD}",
            "\u{180E}",
            "\u{2061}",
            "\u{2064}",
            "\u{FE0F}",
            "\u{E0001}",
            "\u{034F}",
        ] {
            let raw = format!("Lap{invisible}top");
            assert_eq!(sanitize_label(&raw).unwrap(), "Laptop", "{raw:?}");
        }
        assert!(
            sanitize_label("\u{200B}\u{FEFF}").is_err(),
            "only invisibles: empty"
        );
    }

    mod label_props {
        use proptest::prelude::*;

        use super::super::sanitize_label;
        use crate::trusted::is_invisible_or_control;

        fn invisible() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("\u{200B}"),
                Just("\u{200D}"),
                Just("\u{2060}"),
                Just("\u{FEFF}"),
                Just("\u{00AD}"),
                Just("\u{202E}"),
                Just("\u{E0041}"),
                Just("\u{FE0F}"),
                Just("\u{3164}"),
            ]
            .prop_map(str::to_owned)
        }

        proptest! {
            /// A sanitized label never carries a control, bidi or default-ignorable
            /// code point, whatever mix of visible text and invisibles it was built
            /// from, and equals the label of the visible characters alone.
            #[test]
            fn sanitized_labels_carry_no_invisible_code_point(
                parts in proptest::collection::vec(
                    prop_oneof!["[a-zA-Z0-9 ]{1,6}", invisible()],
                    1..12,
                ),
            ) {
                let raw: String = parts.concat();
                if let Ok(s) = sanitize_label(&raw) {
                    prop_assert!(s.chars().all(|c| !is_invisible_or_control(c)), "{s:?}");
                    prop_assert!(!s.is_empty() && s.chars().count() <= 64);
                    let visible: String = raw
                        .chars()
                        .filter(|c| !is_invisible_or_control(*c))
                        .collect();
                    prop_assert_eq!(sanitize_label(&visible).unwrap(), s);
                }
            }
        }
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let g = grant(Preset::MyMachines);
        let s = format!("{g:?}");
        assert!(!s.contains("7, 7, 7"));
        assert!(s.contains("AuthRecord::Opaque(<192 bytes>)"));
        let store = UnattendedStore::bootstrap(Zeroizing::new(vec![0xAB; 128]), None, 5);
        let s = format!("{store:?}");
        assert!(!s.contains("171"));
        assert!(s.contains("<128 bytes>"));
    }

    #[test]
    fn stop_token_compare_and_active_at() {
        let mut store = UnattendedStore::bootstrap(Zeroizing::new(vec![]), None, 5);
        assert!(!store.stop_token_matches(&[0; 32]));
        store.stop_token = Some([9; 32]);
        assert!(store.stop_token_matches(&[9; 32]));
        assert!(!store.stop_token_matches(&[8; 32]));
        assert!(!store.active_at(10));
        store.enabled = true;
        assert!(store.active_at(10));
        store.paused_until = Some(20);
        assert!(!store.active_at(10));
        assert!(store.active_at(20));
    }
}
