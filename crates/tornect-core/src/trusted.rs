//! Trusted (SAS-paired) devices and known hosts (`docs/PLAN.md` §B.3, §B.6).
//!
//! Two small TOML files, both private (`0600`, atomic replace):
//!
//! * **Host side** — [`TrustedDevices`] at [`Paths::trusted_devices_file`]: the
//!   client device keys pinned at pairing, each with the label the host user
//!   confirmed at the consent popup, plus the §B.3 temp-ban list for *unpaired*
//!   peers whose pairing requests were repeatedly rejected. Unattended grants
//!   live in the encrypted store of §B.8.9, never here.
//! * **Client side** — [`KnownHosts`] at [`known_hosts_file`]: the hosts this
//!   device paired with, keyed by onion address, with the host's device key
//!   from `PAIR_ACCEPT` and the host name learned there (decision M1-12).
//!
//! Labels are *pinned*: the string stored at pairing is what every later popup
//! and log line shows, never the name a peer declares afterwards
//! (§B.8.16 "pinned label only"). [`sanitize_label`] strips what a hostile
//! name could use to spoof UI (control, bidi and other format characters),
//! collapses whitespace and bounds the length; Unicode NFKC normalization is
//! applied by the caller (`tornect-signal`, which owns the `unicode-normalization`
//! dependency) before the string reaches this module.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::id::{DeviceId, TornectId};
use crate::keystore::{create_private_dir, write_private_file};
use crate::paths::Paths;

/// Longest pinned label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;

/// Label used when a peer's declared name is empty after sanitization.
pub const FALLBACK_LABEL: &str = "device";

/// Most temp-ban records kept; the oldest are evicted beyond it so random keys
/// cannot grow the file without bound.
pub const MAX_BAN_RECORDS: usize = 1024;

/// Seconds since the Unix epoch, saturating at zero on a pre-1970 clock.
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Remove characters a peer could use to spoof or hide text, collapse
/// whitespace, and bound the length to [`MAX_LABEL_CHARS`] characters.
///
/// Dropped: everything [`is_invisible_or_control`] matches — control
/// characters, every Unicode *default-ignorable* code point (bidi and joiner
/// controls, variation selectors, tag characters, Hangul fillers, …) and the
/// remaining format (`Cf`) characters. Runs of whitespace become one ASCII
/// space; leading and trailing whitespace is trimmed. An empty result becomes
/// [`FALLBACK_LABEL`].
#[must_use]
pub fn sanitize_label(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(4 * MAX_LABEL_CHARS));
    let mut pending_space = false;
    let mut chars = 0;
    for c in raw.chars() {
        if c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if is_invisible_or_control(c) {
            continue;
        }
        if chars >= MAX_LABEL_CHARS {
            break;
        }
        if pending_space {
            if chars + 1 >= MAX_LABEL_CHARS {
                break;
            }
            out.push(' ');
            chars += 1;
            pending_space = false;
        }
        out.push(c);
        chars += 1;
    }
    if out.is_empty() {
        FALLBACK_LABEL.to_owned()
    } else {
        out
    }
}

/// Whether `c` renders as nothing (or only alters how its neighbours render)
/// and therefore must never reach a pinned label, a popup or a log line.
///
/// Matches every control character (`Cc`), the Unicode 16.0
/// `Default_Ignorable_Code_Point` set (`DerivedCoreProperties.txt`: U+00AD,
/// U+034F, U+061C, U+115F–U+1160, U+17B4–U+17B5, U+180B–U+180F,
/// U+200B–U+200F, U+202A–U+202E, U+2060–U+206F, U+3164, U+FE00–U+FE0F,
/// U+FEFF, U+FFA0, U+FFF0–U+FFF8, U+1BCA0–U+1BCA3, U+1D173–U+1D17A,
/// U+E0000–U+E0FFF — tag characters and the variation-selector supplement
/// included) and the remaining `Cf` format characters that prefix or annotate
/// text (U+0600–U+0605, U+06DD, U+070F, U+0890–U+0891, U+08E2, U+FFF9–U+FFFB,
/// U+110BD, U+110CD, U+13430–U+1343F). `tornect-signal` applies the same
/// predicate to every string it accepts from the wire.
#[must_use]
pub fn is_invisible_or_control(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{115F}'..='\u{1160}'
                | '\u{17B4}'..='\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF0}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E0FFF}'
        )
}

/// Make `wanted` unique among `existing` labels by suffixing the first nine
/// characters of the device fingerprint (`" (abcd-ef01)"`), keeping the result
/// within [`MAX_LABEL_CHARS`].
///
/// Two paired devices with the same declared name ("Laptop") would otherwise
/// be indistinguishable in every later popup. Existing labels are compared
/// after [`sanitize_label`], so a label pinned under an older strip table can
/// never hide behind an invisible suffix either.
#[must_use]
pub fn unique_label<'a>(
    existing: impl IntoIterator<Item = &'a str>,
    wanted: &str,
    device: &DeviceId,
) -> String {
    if !existing.into_iter().any(|l| sanitize_label(l) == wanted) {
        return wanted.to_owned();
    }
    let fp = device.fingerprint();
    let suffix = format!(" ({})", fp.get(..9).unwrap_or(&fp));
    let keep = MAX_LABEL_CHARS.saturating_sub(suffix.chars().count());
    let mut base: String = wanted.chars().take(keep).collect();
    while base.ends_with(' ') {
        base.pop();
    }
    base.push_str(&suffix);
    base
}

/// One pinned client device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDevice {
    /// The device's ed25519 public key.
    pub device: DeviceId,
    /// Pinned label (sanitized, unique, ≤ [`MAX_LABEL_CHARS`]).
    pub label: String,
    /// Unix seconds of the pairing.
    pub paired_at: u64,
    /// Unix seconds of the last *fresh, signed* `SESSION_REQUEST` from this
    /// device. A verified `HELLO` does not count: it is replayable by design
    /// (§B.8.4.5), so it is no evidence that the device is live.
    pub last_seen: u64,
}

/// Reject history of an *unpaired* peer key (`docs/PLAN.md` §B.3: "repeated
/// rejects ⇒ temp-ban list persisted per client pk").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBan {
    /// The peer's public key.
    pub device: DeviceId,
    /// Pairing requests the host user rejected.
    pub reject_count: u32,
    /// Unix seconds of the last reject.
    pub last_reject_at: u64,
    /// Until when (Unix seconds) pairing requests are refused without a popup.
    pub temp_ban_until: Option<u64>,
}

/// When rejects turn into a temp-ban and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanPolicy {
    /// Rejects (lifetime, until the peer is paired) before the first ban.
    pub after_rejects: u32,
    /// Length of the first ban in seconds; each further reject doubles it.
    pub base_secs: u64,
    /// Longest ban in seconds.
    pub max_secs: u64,
}

impl Default for BanPolicy {
    /// Three rejects ⇒ 1 h, doubling per further reject up to 24 h.
    fn default() -> Self {
        Self {
            after_rejects: 3,
            base_secs: 3600,
            max_secs: 86_400,
        }
    }
}

impl BanPolicy {
    /// Ban length after `reject_count` rejects, if any.
    #[must_use]
    pub fn ban_secs(&self, reject_count: u32) -> Option<u64> {
        if reject_count < self.after_rejects {
            return None;
        }
        let extra = reject_count - self.after_rejects;
        let secs = self
            .base_secs
            .checked_shl(extra.min(31))
            .unwrap_or(self.max_secs);
        Some(secs.min(self.max_secs))
    }
}

/// The host's pinned devices and temp-ban list (`trusted-devices.toml`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDevices {
    /// Paired devices, in pairing order.
    #[serde(default)]
    pub devices: Vec<TrustedDevice>,
    /// Reject history of unpaired peers.
    #[serde(default)]
    pub bans: Vec<PeerBan>,
}

impl TrustedDevices {
    /// Load the file, or an empty set when it does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        match fs_err::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|source| CoreError::ConfigParse {
                path: path.to_owned(),
                source: Box::new(source),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Write the file atomically with private permissions.
    pub fn save(&self, path: &Path) -> Result<()> {
        save_private_toml(path, self)
    }

    /// The pinned record for `device`, if paired.
    #[must_use]
    pub fn get(&self, device: &DeviceId) -> Option<&TrustedDevice> {
        self.devices.iter().find(|d| d.device == *device)
    }

    /// Whether `device` is paired.
    #[must_use]
    pub fn is_trusted(&self, device: &DeviceId) -> bool {
        self.get(device).is_some()
    }

    /// Pin `device` under `label` (sanitized and made unique here), clearing
    /// any temp-ban record. Pinning an already trusted device only refreshes
    /// `last_seen`: the pinned label never changes through the protocol.
    pub fn pin(&mut self, device: DeviceId, label: &str, now: u64) -> &TrustedDevice {
        self.bans.retain(|b| b.device != device);
        if let Some(idx) = self.devices.iter().position(|d| d.device == device) {
            self.devices[idx].last_seen = now;
            return &self.devices[idx];
        }
        let wanted = sanitize_label(label);
        let label = unique_label(
            self.devices.iter().map(|d| d.label.as_str()),
            &wanted,
            &device,
        );
        self.devices.push(TrustedDevice {
            device,
            label,
            paired_at: now,
            last_seen: now,
        });
        // Just pushed, so the last element exists.
        self.devices.last().unwrap_or_else(|| unreachable!())
    }

    /// Record a fresh, signed `SESSION_REQUEST` from a paired device.
    pub fn touch(&mut self, device: &DeviceId, now: u64) {
        if let Some(d) = self.devices.iter_mut().find(|d| d.device == *device) {
            d.last_seen = now;
        }
    }

    /// Unpair `device`; returns whether it was paired.
    pub fn remove(&mut self, device: &DeviceId) -> bool {
        let before = self.devices.len();
        self.devices.retain(|d| d.device != *device);
        self.devices.len() != before
    }

    /// Until when `device` is temp-banned, if it is.
    #[must_use]
    pub fn banned_until(&self, device: &DeviceId, now: u64) -> Option<u64> {
        self.bans
            .iter()
            .find(|b| b.device == *device)
            .and_then(|b| b.temp_ban_until)
            .filter(|&until| until > now)
    }

    /// Count a rejected pairing request; returns the ban deadline if the
    /// policy now bans the peer. Keeps at most [`MAX_BAN_RECORDS`] records.
    pub fn record_reject(&mut self, device: DeviceId, now: u64, policy: &BanPolicy) -> Option<u64> {
        let idx = match self.bans.iter().position(|b| b.device == device) {
            Some(i) => i,
            None => {
                if self.bans.len() >= MAX_BAN_RECORDS {
                    self.evict_oldest_ban();
                }
                self.bans.push(PeerBan {
                    device,
                    reject_count: 0,
                    last_reject_at: now,
                    temp_ban_until: None,
                });
                self.bans.len() - 1
            }
        };
        let ban = &mut self.bans[idx];
        ban.reject_count = ban.reject_count.saturating_add(1);
        ban.last_reject_at = now;
        ban.temp_ban_until = policy
            .ban_secs(ban.reject_count)
            .map(|secs| now.saturating_add(secs));
        ban.temp_ban_until
    }

    fn evict_oldest_ban(&mut self) {
        if let Some((idx, _)) = self
            .bans
            .iter()
            .enumerate()
            .min_by_key(|(_, b)| b.last_reject_at)
        {
            self.bans.remove(idx);
        }
    }
}

/// A host this device paired with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownHost {
    /// The host name learned from `PAIR_ACCEPT` (sanitized), pinned.
    pub label: String,
    /// The host's device key from `PAIR_ACCEPT` (hex).
    #[serde(with = "hex32")]
    pub host_device_pk: [u8; 32],
    /// Unix seconds of the pairing.
    pub paired_at: u64,
    /// Unix seconds of the last completed handshake.
    pub last_seen: u64,
}

/// The client's paired hosts (`known-hosts.toml`), keyed by onion address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownHosts {
    /// Hosts by onion address.
    #[serde(default)]
    pub hosts: BTreeMap<TornectId, KnownHost>,
}

impl KnownHosts {
    /// Load the file, or an empty set when it does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        match fs_err::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|source| CoreError::ConfigParse {
                path: path.to_owned(),
                source: Box::new(source),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Write the file atomically with private permissions.
    pub fn save(&self, path: &Path) -> Result<()> {
        save_private_toml(path, self)
    }

    /// The record for `host`, if paired.
    #[must_use]
    pub fn get(&self, host: &TornectId) -> Option<&KnownHost> {
        self.hosts.get(host)
    }

    /// Pin `host` (a re-pair replaces the record: the user just confirmed a
    /// fresh SAS for it).
    pub fn pin(&mut self, host: TornectId, label: &str, host_device_pk: [u8; 32], now: u64) {
        self.hosts.insert(
            host,
            KnownHost {
                label: sanitize_label(label),
                host_device_pk,
                paired_at: now,
                last_seen: now,
            },
        );
    }

    /// Record a completed handshake with `host`.
    pub fn touch(&mut self, host: &TornectId, now: u64) {
        if let Some(h) = self.hosts.get_mut(host) {
            h.last_seen = now;
        }
    }

    /// Forget `host`; returns whether it was known.
    pub fn remove(&mut self, host: &TornectId) -> bool {
        self.hosts.remove(host).is_some()
    }
}

/// Where the client keeps its known hosts: `<state>/known-hosts.toml`
/// (decision M1-12; moves to a `Paths` method when the CLI track lands).
#[must_use]
pub fn known_hosts_file(paths: &Paths) -> PathBuf {
    paths.state_dir.join("known-hosts.toml")
}

/// Serialize `value` as TOML into `path` via a private temporary file and an
/// atomic rename, creating the parent directory with private permissions.
fn save_private_toml<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let text = toml::to_string(value)?;
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let tmp = path.with_extension("toml.tmp");
    write_private_file(&tmp, text.as_bytes())?;
    fs_err::rename(&tmp, path)?;
    Ok(())
}

/// `[u8; 32]` as a 64-character hex string in TOML.
mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        let raw = hex::decode(&text).map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(raw)
            .map_err(|v| serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(seed: u8) -> DeviceId {
        DeviceId::from_bytes([seed; 32])
    }

    #[test]
    fn sanitize_strips_controls_bidi_and_bounds_length() {
        assert_eq!(sanitize_label("  Ana's\tLaptop \n"), "Ana's Laptop");
        assert_eq!(sanitize_label("evil\u{202E}txt.exe"), "eviltxt.exe");
        assert_eq!(sanitize_label("a\u{0007}b\u{200B}c\u{FEFF}d"), "abcd");
        assert_eq!(sanitize_label("\u{200E}\u{202A}"), FALLBACK_LABEL);
        assert_eq!(sanitize_label(""), FALLBACK_LABEL);
        let long = "x".repeat(200);
        assert_eq!(sanitize_label(&long).chars().count(), MAX_LABEL_CHARS);
        let spaced = "ab ".repeat(40);
        let s = sanitize_label(&spaced);
        assert!(s.chars().count() <= MAX_LABEL_CHARS, "{s}");
        assert!(!s.ends_with(' '));
        // Multi-byte characters count as one each.
        let emoji = "é".repeat(100);
        assert_eq!(sanitize_label(&emoji).chars().count(), MAX_LABEL_CHARS);
    }

    #[test]
    fn sanitize_strips_every_default_ignorable_code_point() {
        // CGJ, variation selector, tag character, Hangul filler, Khmer
        // inherent vowel, shorthand format, language tag, Egyptian format.
        let hidden =
            "a\u{034F}b\u{FE0F}c\u{E0041}d\u{3164}e\u{17B4}f\u{1BCA0}g\u{E0001}h\u{13430}i";
        assert_eq!(sanitize_label(hidden), "abcdefghi");
        assert_eq!(sanitize_label("\u{E0041}\u{E0042}\u{FFA0}"), FALLBACK_LABEL);
        for c in [
            '\u{00AD}',
            '\u{180F}',
            '\u{2065}',
            '\u{FFF0}',
            '\u{E0FFF}',
            '\u{1D17A}',
            '\u{0600}',
            '\u{110BD}',
        ] {
            assert!(is_invisible_or_control(c), "{c:?}");
        }
        for c in ['a', 'é', '中', '🦀', ' ', '\u{0301}'] {
            assert!(!is_invisible_or_control(c), "{c:?}");
        }
    }

    #[test]
    fn invisible_suffixes_do_not_defeat_label_uniqueness() {
        let mut t = TrustedDevices::default();
        t.pin(dev(1), "Laptop", 10);
        let second = t.pin(dev(2), "Laptop\u{E0041}", 11).label.clone();
        assert_ne!(second, "Laptop");
        assert!(second.starts_with("Laptop ("), "{second}");
        // A label pinned before the strip table grew is still compared stripped.
        let existing = ["Desk\u{200B}"];
        let unique = unique_label(existing, "Desk", &dev(3));
        assert!(unique.starts_with("Desk ("), "{unique}");
    }

    #[test]
    fn duplicate_labels_get_a_fingerprint_suffix() {
        let mut t = TrustedDevices::default();
        t.pin(dev(1), "Laptop", 10);
        let second = t.pin(dev(2), "Laptop", 11).label.clone();
        assert_ne!(second, "Laptop");
        assert!(second.starts_with("Laptop ("), "{second}");
        assert!(second.chars().count() <= MAX_LABEL_CHARS);
        let long = "L".repeat(64);
        let third = t.pin(dev(3), &long, 12).label.clone();
        t.pin(dev(4), &long, 13);
        let fourth = t.get(&dev(4)).unwrap().label.clone();
        assert_ne!(third, fourth);
        assert!(fourth.chars().count() <= MAX_LABEL_CHARS, "{fourth}");
    }

    #[test]
    fn pin_is_idempotent_and_keeps_the_pinned_label() {
        let mut t = TrustedDevices::default();
        t.pin(dev(1), "Laptop", 10);
        t.pin(dev(1), "Renamed by the peer", 20);
        assert_eq!(t.devices.len(), 1);
        assert_eq!(t.get(&dev(1)).unwrap().label, "Laptop");
        assert_eq!(t.get(&dev(1)).unwrap().last_seen, 20);
        assert_eq!(t.get(&dev(1)).unwrap().paired_at, 10);
        assert!(t.remove(&dev(1)));
        assert!(!t.remove(&dev(1)));
    }

    #[test]
    fn rejects_escalate_into_bans_and_pairing_clears_them() {
        let policy = BanPolicy::default();
        let mut t = TrustedDevices::default();
        assert_eq!(t.record_reject(dev(9), 100, &policy), None);
        assert_eq!(t.record_reject(dev(9), 101, &policy), None);
        assert_eq!(t.banned_until(&dev(9), 101), None);
        assert_eq!(t.record_reject(dev(9), 102, &policy), Some(102 + 3600));
        assert_eq!(t.banned_until(&dev(9), 103), Some(102 + 3600));
        assert_eq!(t.banned_until(&dev(9), 102 + 3600), None);
        assert_eq!(t.record_reject(dev(9), 200, &policy), Some(200 + 7200));
        for i in 0..40 {
            t.record_reject(dev(9), 300 + i, &policy);
        }
        let until = t.banned_until(&dev(9), 340).unwrap();
        assert_eq!(until, 339 + 86_400, "capped at 24 h");
        t.pin(dev(9), "now trusted", 400);
        assert!(t.bans.is_empty());
        assert_eq!(t.banned_until(&dev(9), 400), None);
    }

    #[test]
    fn ban_records_are_bounded() {
        let policy = BanPolicy::default();
        let mut t = TrustedDevices::default();
        for i in 0..(MAX_BAN_RECORDS as u64 + 50) {
            let mut pk = [0u8; 32];
            pk[..8].copy_from_slice(&i.to_be_bytes());
            t.record_reject(DeviceId::from_bytes(pk), i, &policy);
        }
        assert_eq!(t.bans.len(), MAX_BAN_RECORDS);
        // The oldest were evicted.
        assert!(t.bans.iter().all(|b| b.last_reject_at >= 50));
    }

    #[test]
    fn trusted_devices_roundtrip_through_toml_with_private_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state").join("trusted-devices.toml");
        assert_eq!(
            TrustedDevices::load(&path).unwrap(),
            TrustedDevices::default()
        );
        let mut t = TrustedDevices::default();
        t.pin(dev(1), "Laptop of Ana", 10);
        t.record_reject(dev(2), 11, &BanPolicy::default());
        t.save(&path).unwrap();
        let back = TrustedDevices::load(&path).unwrap();
        assert_eq!(back, t);
        assert!(!path.with_extension("toml.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::write(&path, "devices = 3\n").unwrap();
        assert!(matches!(
            TrustedDevices::load(&path).unwrap_err(),
            CoreError::ConfigParse { .. }
        ));
    }

    #[test]
    fn known_hosts_roundtrip_and_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let path = known_hosts_file(&paths);
        assert_eq!(path, paths.state_dir.join("known-hosts.toml"));
        let host = TornectId::from_bytes([7u8; 32]);
        let mut k = KnownHosts::default();
        k.pin(host, "Desk\u{202E}top", [3u8; 32], 5);
        k.touch(&host, 6);
        k.save(&path).unwrap();
        let back = KnownHosts::load(&path).unwrap();
        assert_eq!(back, k);
        let rec = back.get(&host).unwrap();
        assert_eq!(rec.label, "Desktop");
        assert_eq!(rec.host_device_pk, [3u8; 32]);
        assert_eq!(rec.last_seen, 6);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&hex::encode([3u8; 32])), "{text}");
        let mut k2 = back;
        assert!(k2.remove(&host));
        assert!(k2.get(&host).is_none());
    }

    #[test]
    fn ban_policy_schedule() {
        let p = BanPolicy::default();
        assert_eq!(p.ban_secs(0), None);
        assert_eq!(p.ban_secs(2), None);
        assert_eq!(p.ban_secs(3), Some(3600));
        assert_eq!(p.ban_secs(4), Some(7200));
        assert_eq!(p.ban_secs(8), Some(86_400));
        assert_eq!(p.ban_secs(u32::MAX), Some(86_400));
    }
}
