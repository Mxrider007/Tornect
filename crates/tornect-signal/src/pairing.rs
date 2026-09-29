//! Pairing (`docs/PLAN.md` §B.2, §B.3, §B.6): the SAS code, the consent seam
//! the host UI implements, the host-side pairing policy (one in-flight
//! request per unpaired peer, token buckets, persisted temp-bans) and the
//! thread-safe stores around [`TrustedDevices`] / [`KnownHosts`].
//!
//! **SAS** (decision M1-8, `docs/PLAN.md` §B.3):
//!
//! ```text
//! SAS = u32::from_be_bytes(HKDF-SHA256(ikm = th_after(PAIR_REQUEST), salt = "tornect/v1/sas", info = "sas-v1")[0..4]) % 1_000_000
//! ```
//!
//! rendered as two zero-padded three-digit groups (`481 923`). Both sides can
//! compute it the moment `PAIR_REQUEST` is sent / received: that transcript
//! state already commits to the dialed onion key, the client device key, both
//! nonces and both signatures, so a proxied rendezvous yields different codes
//! on the two screens.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hkdf::Hkdf;
use sha2::Sha256;
use tokio::time::Instant;
use tornect_core::levels::Availability;
use tornect_core::trusted::{self, BanPolicy, KnownHosts, TrustedDevice, TrustedDevices};
use tornect_core::{DeviceId, TornectId};
use unicode_normalization::UnicodeNormalization as _;

use crate::messages::Caps;

/// A boxed `Send` future, the shape every UI seam in this crate uses
/// (`docs/PLAN.md` §B.8.14: never bare `async fn` in traits, so the FSM can
/// hold `Arc<dyn Trait>` and cross `tokio::spawn`).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// HKDF salt of the SAS derivation.
pub const SAS_SALT: &[u8] = b"tornect/v1/sas";
/// HKDF info of the SAS derivation.
pub const SAS_INFO: &[u8] = b"sas-v1";
/// Domain separator of the `HELLO.sas_commit` commitment (§B.3).
pub const SAS_COMMIT_DOMAIN: &[u8] = b"tornect/v1/sas-commit\0";

/// The commitment a client publishes in `HELLO` for the SAS nonce it reveals in
/// `PAIR_REQUEST` (§B.3).
#[must_use]
pub fn sas_commit(sas_nonce: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = Sha256::new();
    h.update(SAS_COMMIT_DOMAIN);
    h.update(sas_nonce);
    h.finalize().into()
}

/// A six-digit short authentication string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sas(u32);

impl Sas {
    /// Derive the code from `th_after(HELLO_ACK)` and the revealed SAS nonce (§B.3).
    ///
    /// Both inputs are fixed-length and neither is attacker-malleable at the moment
    /// the peer must choose its own contribution: `th_after(HELLO_ACK)` covers only
    /// signed frames, and `sas_nonce` is pinned by the `HELLO.sas_commit` commitment.
    /// Deliberately **not** `th_after(PAIR_REQUEST)`: `PAIR_REQUEST` is unsigned, its
    /// `client_auth_pk` is discarded by the host, and `decode_body` ignores unknown
    /// map keys — together that is unlimited grinding material against a 20-bit code.
    #[must_use]
    pub fn derive(th_after_hello_ack: &[u8; 32], sas_nonce: &[u8; 32]) -> Self {
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(th_after_hello_ack);
        ikm[32..].copy_from_slice(sas_nonce);
        let hk = Hkdf::<Sha256>::new(Some(SAS_SALT), &ikm);
        let mut okm = [0u8; 4];
        // 4 bytes ≤ 255 × 32, so `expand` cannot fail.
        let _ = hk.expand(SAS_INFO, &mut okm);
        Self(u32::from_be_bytes(okm) % 1_000_000)
    }

    /// The numeric value, `0..1_000_000`.
    #[must_use]
    pub fn value(self) -> u32 {
        self.0
    }

    /// `"481 923"`: two zero-padded three-digit groups.
    #[must_use]
    pub fn render(self) -> String {
        format!("{:03} {:03}", self.0 / 1000, self.0 % 1000)
    }
}

impl core::fmt::Display for Sas {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.render())
    }
}

/// NFKC-normalize and sanitize a peer-declared name into a pinnable label
/// (`tornect_core::trusted::sanitize_label` does the stripping and bounding).
#[must_use]
pub fn normalize_label(raw: &str) -> String {
    let nfkc: String = raw.nfkc().collect();
    trusted::sanitize_label(&nfkc)
}

/// What the pairing popup shows about a peer asking to pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingPeer {
    /// The peer's device key.
    pub device: DeviceId,
    /// The name it declared in `HELLO`, normalized — a suggestion for the label, nothing more.
    pub name: String,
    /// `DeviceId::fingerprint()`, for the popup.
    pub fingerprint: String,
    /// The pinned label when this key is *already* trusted (a re-pair,
    /// decision M1-32) — the popup says "already paired as `<label>` — pair
    /// again?": `HELLO` is replayable, so a re-pair request is no evidence
    /// that the trusted device itself is asking, and a Deny here never counts
    /// toward the temp-ban.
    pub pinned_label: Option<String>,
}

/// The host user's answer to the pairing popup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairDecision {
    /// Pin the device; `label` overrides the declared name when given.
    Accept {
        /// The label to pin (normalized by the store), or `None` for the declared name.
        label: Option<String>,
    },
    /// Do not pin; the reject counts toward the temp-ban.
    Reject,
}

/// A pinned device, as the session popup shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPeer {
    /// The peer's device key.
    pub device: DeviceId,
    /// The pinned label.
    pub label: String,
}

/// What an attended `SESSION_REQUEST` asks for, for the session popup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequestSummary {
    /// The requested caps.
    pub caps: Caps,
}

/// The host user's answer to the session popup (§B.2: never an "always allow").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDecision {
    /// Allow once, full control.
    AllowOnce,
    /// Allow once, view-only.
    AllowOnceViewOnly,
    /// Allow once, control as administrator (r7, §B.2.1; Windows). Taken only
    /// where the host's [`tornect_core::levels::Availability`] offers it: the
    /// host FSM refuses it anywhere else, never lowers it.
    AllowOnceAdmin,
    /// Deny.
    Deny,
}

/// The consent popups (`docs/PLAN.md` §B.2), implemented by the host UI —
/// the CLI prompt at M1, the app at M4+. The FSM applies the popup timeout.
pub trait Consent: Send + Sync {
    /// "`name` wants to pair. Code: `sas`" — Allow (with an optional label) / Deny.
    fn pairing<'a>(&'a self, peer: &'a PairingPeer, sas: &'a str) -> BoxFuture<'a, PairDecision>;

    /// "`label` wants to start a session" — Allow once / Allow once (view-only) / Deny.
    fn session<'a>(
        &'a self,
        peer: &'a TrustedPeer,
        req: &'a SessionRequestSummary,
    ) -> BoxFuture<'a, SessionDecision>;

    /// The session popup on a host in the row `levels` of the §B.2.1 table
    /// (r7): a sheet offers the answers of `levels.offered()` and carries
    /// `levels.sentence`. What the FSM calls. The default is [`Self::session`],
    /// the three-answer sheet, which never answers `AllowOnceAdmin`.
    fn session_at<'a>(
        &'a self,
        peer: &'a TrustedPeer,
        req: &'a SessionRequestSummary,
        levels: &'a Availability,
    ) -> BoxFuture<'a, SessionDecision> {
        let _ = levels;
        self.session(peer, req)
    }

    /// The session popup again, after its administrator answer ended without
    /// administrator access (§B.2.1: Windows' prompt cancelled or failed, or
    /// the administrator helper not ready in time): the sheet says
    /// "Administrator access was not given", keeps the other answers, and has
    /// `left` of the popup's time. The session never starts at a lower level
    /// by itself: the person answers again. The default asks as
    /// [`Self::session_at`] does.
    fn session_again<'a>(
        &'a self,
        peer: &'a TrustedPeer,
        req: &'a SessionRequestSummary,
        levels: &'a Availability,
        left: Duration,
    ) -> BoxFuture<'a, SessionDecision> {
        let _ = left;
        self.session_at(peer, req, levels)
    }
}

/// Denies everything: the headless default and the safe fallback when no UI is attached.
#[derive(Debug, Clone, Copy, Default)]
pub struct AutoDeny;

impl Consent for AutoDeny {
    fn pairing<'a>(&'a self, _: &'a PairingPeer, _: &'a str) -> BoxFuture<'a, PairDecision> {
        Box::pin(async { PairDecision::Reject })
    }

    fn session<'a>(
        &'a self,
        _: &'a TrustedPeer,
        _: &'a SessionRequestSummary,
    ) -> BoxFuture<'a, SessionDecision> {
        Box::pin(async { SessionDecision::Deny })
    }
}

/// A scripted pairing answer for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairScript {
    /// Answer immediately.
    Decide(PairDecision),
    /// Never answer (drives the popup timeout).
    Hang,
}

/// A scripted session answer for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionScript {
    /// Answer immediately.
    Decide(SessionDecision),
    /// Never answer (drives the popup timeout).
    Hang,
}

/// A [`Consent`] that answers from queues and records what it was shown —
/// a test helper (the SAS strings it saw, the peers it was asked about).
/// Empty queues fall back to Deny / Reject.
#[derive(Debug, Default)]
pub struct ScriptedConsent {
    pairing: Mutex<Vec<PairScript>>,
    session: Mutex<Vec<SessionScript>>,
    /// SAS strings shown, in order.
    pub shown_sas: Mutex<Vec<String>>,
    /// Peers the pairing popup was shown for.
    pub pairing_peers: Mutex<Vec<PairingPeer>>,
    /// Peers the session popup was shown for.
    pub session_peers: Mutex<Vec<TrustedPeer>>,
}

impl ScriptedConsent {
    /// An empty script (answers Reject / Deny).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a pairing answer.
    pub fn push_pairing(&self, s: PairScript) {
        lock(&self.pairing).push(s);
    }

    /// Queue a session answer.
    pub fn push_session(&self, s: SessionScript) {
        lock(&self.session).push(s);
    }

    /// The SAS strings shown so far.
    #[must_use]
    pub fn sas_shown(&self) -> Vec<String> {
        lock(&self.shown_sas).clone()
    }

    /// How many session popups were shown.
    #[must_use]
    pub fn session_popups(&self) -> usize {
        lock(&self.session_peers).len()
    }
}

impl Consent for ScriptedConsent {
    fn pairing<'a>(&'a self, peer: &'a PairingPeer, sas: &'a str) -> BoxFuture<'a, PairDecision> {
        lock(&self.shown_sas).push(sas.to_owned());
        lock(&self.pairing_peers).push(peer.clone());
        let script = {
            let mut q = lock(&self.pairing);
            if q.is_empty() {
                PairScript::Decide(PairDecision::Reject)
            } else {
                q.remove(0)
            }
        };
        Box::pin(async move {
            match script {
                PairScript::Decide(d) => d,
                PairScript::Hang => std::future::pending().await,
            }
        })
    }

    fn session<'a>(
        &'a self,
        peer: &'a TrustedPeer,
        _: &'a SessionRequestSummary,
    ) -> BoxFuture<'a, SessionDecision> {
        lock(&self.session_peers).push(peer.clone());
        let script = {
            let mut q = lock(&self.session);
            if q.is_empty() {
                SessionScript::Decide(SessionDecision::Deny)
            } else {
                q.remove(0)
            }
        };
        Box::pin(async move {
            match script {
                SessionScript::Decide(d) => d,
                SessionScript::Hang => std::future::pending().await,
            }
        })
    }
}

/// Lock a mutex, recovering the data from a poisoned lock (the guarded data
/// here is plain bookkeeping that stays consistent across a panic).
pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Bounds of the host-side pairing policy (`docs/PLAN.md` §B.3) — and, in a
/// second [`PairingPolicy`], of the attended session popup
/// ([`PairingLimits::sessions`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingLimits {
    /// Burst of pairing requests one peer key may make.
    pub per_peer_burst: u32,
    /// Time to earn one more request for a peer key.
    pub per_peer_refill: Duration,
    /// Burst of pairing requests the host answers across all peers.
    pub host_burst: u32,
    /// Time to earn one more host-wide request.
    pub host_refill: Duration,
    /// Most per-peer buckets kept; beyond it full buckets are evicted, and if
    /// none is, the request is rate-limited.
    pub max_tracked_peers: usize,
    /// When rejects become bans.
    pub ban: BanPolicy,
}

impl Default for PairingLimits {
    /// 3 per peer per 5 min (burst 3), 20 host-wide per 10 min (burst 20),
    /// 4096 tracked peers, default [`BanPolicy`].
    fn default() -> Self {
        Self {
            per_peer_burst: 3,
            per_peer_refill: Duration::from_secs(100),
            host_burst: 20,
            host_refill: Duration::from_secs(30),
            max_tracked_peers: 4096,
            ban: BanPolicy::default(),
        }
    }
}

impl PairingLimits {
    /// The attended session popup budget: one popup in flight per paired
    /// device, 6 per device per 5 min (a legitimate user retrying after
    /// popup timeouts stays inside it), 20 host-wide per 10 min; a refusal is
    /// `SESSION_REJECT{BUSY}`. `ban` is unused — a session popup Deny never
    /// bans a paired device.
    #[must_use]
    pub fn sessions() -> Self {
        Self {
            per_peer_burst: 6,
            per_peer_refill: Duration::from_secs(50),
            ..Self::default()
        }
    }
}

/// Why a `PAIR_REQUEST` is refused before any popup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairRefusal {
    /// Another request from this key is already at the popup.
    InFlight,
    /// The per-peer or host-wide bucket is empty.
    RateLimited,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u32,
    last: Instant,
}

impl Bucket {
    fn full(burst: u32, now: Instant) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }

    fn refill(&mut self, burst: u32, per: Duration, now: Instant) {
        if per.is_zero() {
            self.tokens = burst;
            self.last = now;
            return;
        }
        let elapsed = now.saturating_duration_since(self.last);
        let earned = elapsed.as_nanos() / per.as_nanos();
        if earned > 0 {
            let earned_u32 = u32::try_from(earned).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(earned_u32).min(burst);
            // Advance by whole periods only, so fractional credit carries over.
            let advance = per.saturating_mul(earned_u32);
            self.last = self.last.checked_add(advance).unwrap_or(now);
            if self.tokens == burst {
                self.last = now;
            }
        }
    }

    fn take(&mut self) -> bool {
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
struct PolicyState {
    in_flight: HashSet<[u8; 32]>,
    per_peer: HashMap<[u8; 32], Bucket>,
    host: Bucket,
}

/// The host-wide pairing policy: exactly one in-flight `PAIR_REQUEST` per
/// unpaired peer key, a token bucket per peer key and one host-wide. A
/// second instance with [`PairingLimits::sessions`] budgets the attended
/// session popup the same way.
///
/// Bans live in [`TrustedDeviceStore`] (persisted); this state is in-memory.
#[derive(Debug)]
pub struct PairingPolicy {
    limits: PairingLimits,
    state: Mutex<PolicyState>,
}

impl PairingPolicy {
    /// A policy with the given limits.
    #[must_use]
    pub fn new(limits: PairingLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(PolicyState {
                in_flight: HashSet::new(),
                per_peer: HashMap::new(),
                host: Bucket::full(limits.host_burst, Instant::now()),
            }),
        }
    }

    /// The limits in force.
    #[must_use]
    pub fn limits(&self) -> &PairingLimits {
        &self.limits
    }

    /// Admit a `PAIR_REQUEST` from `pk`; the returned guard holds the
    /// in-flight slot until dropped.
    pub fn admit(self: &Arc<Self>, pk: [u8; 32]) -> Result<InFlight, PairRefusal> {
        let now = Instant::now();
        let limits = self.limits;
        let mut st = lock(&self.state);
        if st.in_flight.contains(&pk) {
            return Err(PairRefusal::InFlight);
        }
        st.host.refill(limits.host_burst, limits.host_refill, now);
        if st.host.tokens == 0 {
            return Err(PairRefusal::RateLimited);
        }
        if !st.per_peer.contains_key(&pk) && st.per_peer.len() >= limits.max_tracked_peers {
            // Evict buckets that carry no information (full again).
            let burst = limits.per_peer_burst;
            let per = limits.per_peer_refill;
            st.per_peer.retain(|_, b| {
                b.refill(burst, per, now);
                b.tokens < burst
            });
            if st.per_peer.len() >= limits.max_tracked_peers {
                return Err(PairRefusal::RateLimited);
            }
        }
        let peer = st
            .per_peer
            .entry(pk)
            .or_insert_with(|| Bucket::full(limits.per_peer_burst, now));
        peer.refill(limits.per_peer_burst, limits.per_peer_refill, now);
        if peer.tokens == 0 {
            return Err(PairRefusal::RateLimited);
        }
        peer.take();
        st.host.take();
        st.in_flight.insert(pk);
        Ok(InFlight {
            policy: Arc::clone(self),
            pk,
        })
    }

    /// How many pairing requests are at a popup right now.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        lock(&self.state).in_flight.len()
    }

    fn release(&self, pk: &[u8; 32]) {
        lock(&self.state).in_flight.remove(pk);
    }
}

/// The in-flight slot of one `PAIR_REQUEST`; released on drop.
#[derive(Debug)]
pub struct InFlight {
    policy: Arc<PairingPolicy>,
    pk: [u8; 32],
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.policy.release(&self.pk);
    }
}

/// Whether last-seen times are kept right now: the address book's history
/// switch, read at each use.
pub type KeepHistory = Arc<dyn Fn() -> bool + Send + Sync>;

/// Persisted [`TrustedDevices`] behind a lock: every trust change (a pin, an
/// unpairing, a reject count) is written through to `trusted-devices.toml`
/// before it takes effect for other streams (an
/// [`ephemeral`](Self::ephemeral) store keeps everything in memory).
///
/// A [`shared`](Self::shared) store (the host's handshakes) merges each
/// change into the file as it is at that moment, so a device unpaired by
/// another process stays unpaired, and writes a device's last-seen time only
/// while its history switch says so (`docs/PLAN.md` §B.8.9.1: history off
/// means no `last_seen` updates); trust changes are written either way.
pub struct TrustedDeviceStore {
    path: Option<PathBuf>,
    inner: Mutex<TrustedDevices>,
    history: Option<KeepHistory>,
}

impl std::fmt::Debug for TrustedDeviceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedDeviceStore")
            .field("path", &self.path)
            .field("shared", &self.history.is_some())
            .finish_non_exhaustive()
    }
}

impl TrustedDeviceStore {
    /// Load (or start empty) from `path`.
    pub fn open(path: PathBuf) -> tornect_core::Result<Self> {
        let inner = TrustedDevices::load(&path)?;
        Ok(Self {
            path: Some(path),
            inner: Mutex::new(inner),
            history: None,
        })
    }

    /// Load (or start empty) from `path`, sharing the file with the rest of
    /// the app: each trust change is merged into the file as it is then, and
    /// a last-seen time is written only while `keep` says history is kept.
    pub fn shared(path: PathBuf, keep: KeepHistory) -> tornect_core::Result<Self> {
        let inner = TrustedDevices::load(&path)?;
        Ok(Self {
            path: Some(path),
            inner: Mutex::new(inner),
            history: Some(keep),
        })
    }

    /// Start from `devices` and persist every mutation to `path` (tests that
    /// check the file).
    #[must_use]
    pub fn with(path: PathBuf, devices: TrustedDevices) -> Self {
        Self {
            path: Some(path),
            inner: Mutex::new(devices),
            history: None,
        }
    }

    /// An in-memory store that never touches the disk (tests, the fuzz
    /// targets).
    #[must_use]
    pub fn ephemeral(devices: TrustedDevices) -> Self {
        Self {
            path: None,
            inner: Mutex::new(devices),
            history: None,
        }
    }

    /// Where the store persists, if it does.
    #[must_use]
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// Whether last-seen times are written: always for a store that is not
    /// shared, else as its history switch says now.
    fn keeps_history(&self) -> bool {
        self.history.as_ref().is_none_or(|keep| keep())
    }

    /// Write a change through: the whole copy `devices` (a store that is not
    /// shared), or `change` made to the file as it is now (a shared one).
    fn persist(
        &self,
        devices: &TrustedDevices,
        change: impl FnOnce(&mut TrustedDevices),
    ) -> tornect_core::Result<()> {
        match (&self.path, &self.history) {
            (None, _) => Ok(()),
            (Some(path), None) => devices.save(path),
            (Some(path), Some(_)) => {
                let mut file = TrustedDevices::load(path)?;
                change(&mut file);
                file.save(path)
            }
        }
    }

    /// The pinned record for `device`.
    #[must_use]
    pub fn get(&self, device: &DeviceId) -> Option<TrustedDevice> {
        lock(&self.inner).get(device).cloned()
    }

    /// A snapshot of the whole file.
    #[must_use]
    pub fn snapshot(&self) -> TrustedDevices {
        lock(&self.inner).clone()
    }

    /// Pin `device` and persist; returns the pinned label (an already pinned
    /// device keeps its label).
    pub fn pin(&self, device: DeviceId, label: &str) -> tornect_core::Result<String> {
        let mut t = lock(&self.inner);
        let now = trusted::unix_now();
        let pinned = t.pin(device, label, now).label.clone();
        let keep = self.keeps_history();
        self.persist(&t, |file| {
            if file.is_trusted(&device) {
                // A re-pair: the pin stays as it is; only its reject history
                // goes, and its last-seen time moves only with history on.
                file.bans.retain(|b| b.device != device);
                if keep {
                    file.touch(&device, now);
                }
            } else {
                file.pin(device, &pinned, now);
            }
        })?;
        Ok(pinned)
    }

    /// Record a fresh, signed `SESSION_REQUEST` from a paired device (best
    /// effort; a write failure is logged, not fatal — nothing
    /// security-relevant changed). Never called for a bare `HELLO`, which is
    /// replayable (§B.8.4.5).
    ///
    /// A shared store keeps the time in memory only while history is off.
    pub fn touch(&self, device: &DeviceId) {
        let mut t = lock(&self.inner);
        let now = trusted::unix_now();
        t.touch(device, now);
        if !self.keeps_history() {
            return;
        }
        if let Err(e) = self.persist(&t, |file| file.touch(device, now)) {
            tracing::warn!(error = %e, "could not persist trusted-devices last_seen");
        }
    }

    /// Unpair `device` and persist.
    pub fn remove(&self, device: &DeviceId) -> tornect_core::Result<bool> {
        let mut t = lock(&self.inner);
        let removed = t.remove(device);
        if removed {
            self.persist(&t, |file| {
                file.remove(device);
            })?;
        }
        Ok(removed)
    }

    /// Until when `device` is temp-banned (Unix seconds), if it is.
    #[must_use]
    pub fn banned_until(&self, device: &DeviceId) -> Option<u64> {
        lock(&self.inner).banned_until(device, trusted::unix_now())
    }

    /// Count a human reject and persist; returns the ban deadline if one started.
    pub fn record_reject(
        &self,
        device: DeviceId,
        policy: &BanPolicy,
    ) -> tornect_core::Result<Option<u64>> {
        let mut t = lock(&self.inner);
        let now = trusted::unix_now();
        let until = t.record_reject(device, now, policy);
        self.persist(&t, |file| {
            file.record_reject(device, now, policy);
        })?;
        Ok(until)
    }
}

/// Persisted [`KnownHosts`] behind a lock (client side).
#[derive(Debug)]
pub struct KnownHostStore {
    path: Option<PathBuf>,
    inner: Mutex<KnownHosts>,
}

impl KnownHostStore {
    /// Load (or start empty) from `path`.
    pub fn open(path: PathBuf) -> tornect_core::Result<Self> {
        let inner = KnownHosts::load(&path)?;
        Ok(Self {
            path: Some(path),
            inner: Mutex::new(inner),
        })
    }

    /// Start from `hosts` and persist every mutation to `path` (tests that
    /// check the file).
    #[must_use]
    pub fn with(path: PathBuf, hosts: KnownHosts) -> Self {
        Self {
            path: Some(path),
            inner: Mutex::new(hosts),
        }
    }

    /// An in-memory store that never touches the disk (tests, the fuzz
    /// targets).
    #[must_use]
    pub fn ephemeral(hosts: KnownHosts) -> Self {
        Self {
            path: None,
            inner: Mutex::new(hosts),
        }
    }

    /// Where the store persists, if it does.
    #[must_use]
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    fn persist(&self, hosts: &KnownHosts) -> tornect_core::Result<()> {
        match &self.path {
            Some(path) => hosts.save(path),
            None => Ok(()),
        }
    }

    /// The record for `host`.
    #[must_use]
    pub fn get(&self, host: &TornectId) -> Option<trusted::KnownHost> {
        lock(&self.inner).get(host).cloned()
    }

    /// Whether `host` is known.
    #[must_use]
    pub fn is_known(&self, host: &TornectId) -> bool {
        lock(&self.inner).get(host).is_some()
    }

    /// Pin `host` and persist.
    pub fn pin(
        &self,
        host: TornectId,
        label: &str,
        host_device_pk: [u8; 32],
    ) -> tornect_core::Result<()> {
        let mut k = lock(&self.inner);
        k.pin(host, label, host_device_pk, trusted::unix_now());
        self.persist(&k)
    }

    /// Record a completed handshake (best effort).
    pub fn touch(&self, host: &TornectId) {
        let mut k = lock(&self.inner);
        k.touch(host, trusted::unix_now());
        if let Err(e) = self.persist(&k) {
            tracing::warn!(error = %e, "could not persist known-hosts last_seen");
        }
    }

    /// Forget `host` and persist.
    pub fn remove(&self, host: &TornectId) -> tornect_core::Result<bool> {
        let mut k = lock(&self.inner);
        let removed = k.remove(host);
        if removed {
            self.persist(&k)?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_is_six_digits_zero_padded_and_deterministic() {
        let a = Sas::derive(&[1u8; 32], &[9u8; 32]);
        let b = Sas::derive(&[1u8; 32], &[9u8; 32]);
        assert_eq!(a, b);
        assert!(a.value() < 1_000_000);
        assert_eq!(a.render().len(), 7);
        assert_eq!(&a.render()[3..4], " ");
        assert_ne!(a, Sas::derive(&[2u8; 32], &[9u8; 32]));
        // the revealed nonce is an independent input
        assert_ne!(a, Sas::derive(&[1u8; 32], &[8u8; 32]));
        assert_eq!(Sas(7).render(), "000 007");
        assert_eq!(Sas(481_923).render(), "481 923");
        assert_eq!(Sas(999_999).to_string(), "999 999");
        // Manual derivation over the two-part ikm of §B.3.
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(&[1u8; 32]);
        ikm[32..].copy_from_slice(&[9u8; 32]);
        let hk = Hkdf::<Sha256>::new(Some(b"tornect/v1/sas"), &ikm);
        let mut okm = [0u8; 4];
        hk.expand(b"sas-v1", &mut okm).unwrap();
        assert_eq!(a.value(), u32::from_be_bytes(okm) % 1_000_000);
    }

    #[test]
    fn normalize_label_applies_nfkc_then_sanitizes() {
        // Fullwidth "Ａ" → "A"; ligature "ﬁ" → "fi"; bidi override stripped.
        assert_eq!(normalize_label("Ａna ﬁle\u{202E}"), "Ana file");
        assert_eq!(normalize_label("   "), "device");
    }

    #[test]
    fn session_limits_are_more_generous_per_peer_than_pairing() {
        let s = PairingLimits::sessions();
        let p = PairingLimits::default();
        assert!(s.per_peer_burst > p.per_peer_burst);
        assert!(s.per_peer_refill < p.per_peer_refill);
        assert_eq!(s.host_burst, p.host_burst);
        assert_eq!(s.max_tracked_peers, p.max_tracked_peers);
    }

    #[test]
    fn policy_enforces_in_flight_and_buckets() {
        let limits = PairingLimits {
            per_peer_burst: 2,
            per_peer_refill: Duration::from_secs(60),
            host_burst: 3,
            host_refill: Duration::from_secs(60),
            max_tracked_peers: 2,
            ban: BanPolicy::default(),
        };
        let p = Arc::new(PairingPolicy::new(limits));
        let a = [1u8; 32];
        let b = [2u8; 32];
        let g1 = p.admit(a).unwrap();
        assert_eq!(p.admit(a).unwrap_err(), PairRefusal::InFlight);
        assert_eq!(p.in_flight(), 1);
        drop(g1);
        assert_eq!(p.in_flight(), 0);
        let g2 = p.admit(a).unwrap();
        drop(g2);
        assert_eq!(
            p.admit(a).unwrap_err(),
            PairRefusal::RateLimited,
            "peer bucket empty"
        );
        let g3 = p.admit(b).unwrap();
        drop(g3);
        // Host bucket (3) is now empty: a third peer is refused even with a fresh peer bucket.
        assert_eq!(p.admit([3u8; 32]).unwrap_err(), PairRefusal::RateLimited);
        assert_eq!(p.limits().host_burst, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn buckets_refill_over_time_and_tracked_peers_are_bounded() {
        let limits = PairingLimits {
            per_peer_burst: 1,
            per_peer_refill: Duration::from_secs(10),
            host_burst: 100,
            host_refill: Duration::from_secs(1),
            max_tracked_peers: 2,
            ban: BanPolicy::default(),
        };
        let p = Arc::new(PairingPolicy::new(limits));
        drop(p.admit([1u8; 32]).unwrap());
        drop(p.admit([2u8; 32]).unwrap());
        // Two tracked, both empty: a third peer cannot be tracked ⇒ limited.
        assert_eq!(p.admit([3u8; 32]).unwrap_err(), PairRefusal::RateLimited);
        assert_eq!(p.admit([1u8; 32]).unwrap_err(), PairRefusal::RateLimited);
        tokio::time::advance(Duration::from_secs(10)).await;
        // Refilled buckets are evicted to make room, and peer 1 has a token again.
        drop(p.admit([3u8; 32]).unwrap());
        drop(p.admit([1u8; 32]).unwrap());
        assert_eq!(p.admit([1u8; 32]).unwrap_err(), PairRefusal::RateLimited);
    }

    #[test]
    fn stores_persist_through_their_files() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TrustedDeviceStore::open(tmp.path().join("t.toml")).unwrap();
        let dev = DeviceId::from_bytes([5u8; 32]);
        assert!(store.get(&dev).is_none());
        assert_eq!(
            store.record_reject(dev, &BanPolicy::default()).unwrap(),
            None
        );
        let label = store.pin(dev, "Ｌaptop\u{200B}").unwrap();
        assert_eq!(label, "Ｌaptop"); // the store sanitizes; NFKC is the caller's job
        let again = TrustedDeviceStore::open(store.path().unwrap().to_owned()).unwrap();
        assert_eq!(again.get(&dev).unwrap().label, "Ｌaptop");
        assert!(again.snapshot().bans.is_empty());
        assert!(again.remove(&dev).unwrap());
        assert!(!again.remove(&dev).unwrap());

        let hosts = KnownHostStore::open(tmp.path().join("k.toml")).unwrap();
        let host = TornectId::from_bytes([9u8; 32]);
        assert!(!hosts.is_known(&host));
        hosts.pin(host, "Desk", [1u8; 32]).unwrap();
        hosts.touch(&host);
        let again = KnownHostStore::open(hosts.path().unwrap().to_owned()).unwrap();
        assert_eq!(again.get(&host).unwrap().host_device_pk, [1u8; 32]);
        assert!(again.remove(&host).unwrap());

        // Ephemeral stores mutate in memory only.
        let eph = TrustedDeviceStore::ephemeral(TrustedDevices::default());
        assert_eq!(eph.pin(dev, "x").unwrap(), "x");
        eph.touch(&dev);
        assert!(eph.path().is_none());
        assert!(eph.get(&dev).is_some());
        let eph = KnownHostStore::ephemeral(KnownHosts::default());
        eph.pin(host, "h", [2u8; 32]).unwrap();
        assert!(eph.is_known(&host));
        assert!(eph.path().is_none());
    }

    #[tokio::test]
    async fn scripted_consent_answers_in_order_then_denies() {
        let c = ScriptedConsent::new();
        c.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
        c.push_session(SessionScript::Decide(SessionDecision::AllowOnceViewOnly));
        let peer = PairingPeer {
            device: DeviceId::from_bytes([1u8; 32]),
            name: "n".into(),
            fingerprint: "f".into(),
            pinned_label: None,
        };
        assert_eq!(
            c.pairing(&peer, "000 001").await,
            PairDecision::Accept { label: None }
        );
        assert_eq!(c.pairing(&peer, "000 002").await, PairDecision::Reject);
        assert_eq!(c.sas_shown(), vec!["000 001", "000 002"]);
        let tp = TrustedPeer {
            device: peer.device,
            label: "n".into(),
        };
        let req = SessionRequestSummary {
            caps: Caps::default(),
        };
        assert_eq!(
            c.session(&tp, &req).await,
            SessionDecision::AllowOnceViewOnly
        );
        assert_eq!(c.session(&tp, &req).await, SessionDecision::Deny);
        assert_eq!(c.session_popups(), 2);
        let deny = AutoDeny;
        assert_eq!(deny.pairing(&peer, "x").await, PairDecision::Reject);
        assert_eq!(deny.session(&tp, &req).await, SessionDecision::Deny);
    }

    /// A shared store (the host's handshakes) writes every trust change the
    /// moment it happens, merged into the file as it is then, and a
    /// last-seen time only while its history switch is on.
    #[test]
    fn a_shared_store_writes_trust_through_and_last_seen_only_with_history() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("trusted-devices.toml");
        let load = || TrustedDevices::load(&path).unwrap();
        let dev = |b: u8| DeviceId::from_bytes([b; 32]);
        let mut start = TrustedDevices::default();
        start.pin(dev(1), "Laptop", 1000);
        start.save(&path).unwrap();
        let history = Arc::new(AtomicBool::new(false));
        let switch = Arc::clone(&history);
        let store = TrustedDeviceStore::shared(
            path.clone(),
            Arc::new(move || switch.load(Ordering::SeqCst)),
        )
        .unwrap();

        // History off: a session request's time stays in memory.
        store.touch(&dev(1));
        assert_eq!(load().get(&dev(1)).unwrap().last_seen, 1000);
        assert!(store.get(&dev(1)).unwrap().last_seen > 1000);
        // Trust changes are written at once all the same.
        store.pin(dev(2), "Phone").unwrap();
        let phone = load().get(&dev(2)).cloned().expect("the pin is on disk");
        assert_eq!(phone.last_seen, phone.paired_at);
        store.record_reject(dev(3), &BanPolicy::default()).unwrap();
        assert_eq!(load().bans[0].reject_count, 1);
        store.pin(dev(1), "Laptop").unwrap();
        assert_eq!(load().get(&dev(1)).unwrap().last_seen, 1000, "a re-pair");
        assert!(store.remove(&dev(2)).unwrap());
        assert!(load().get(&dev(2)).is_none());

        // History on: the time is written too.
        history.store(true, Ordering::SeqCst);
        store.touch(&dev(1));
        assert!(load().get(&dev(1)).unwrap().last_seen > 1000);

        // Merged into the file as it is: a device unpaired by another process
        // stays unpaired through a touch and another device's pin.
        let mut file = load();
        file.remove(&dev(1));
        file.save(&path).unwrap();
        store.touch(&dev(1));
        store.pin(dev(4), "Tablet").unwrap();
        let file = load();
        assert!(file.get(&dev(1)).is_none());
        assert!(file.get(&dev(4)).is_some());
    }
}
