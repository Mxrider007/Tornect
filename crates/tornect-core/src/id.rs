//! Tornect identifiers.
//!
//! A [`TornectId`] *is* a Tor onion v3 address: the base32 encoding of the host's
//! ed25519 public key plus a checksum and a version byte (Tor rend-spec-v3 §6).
//! The address is therefore self-authenticating — whoever can prove possession of
//! the private key *is* that host — and needs no registry (`docs/PLAN.md` §A.3 D3).
//!
//! A [`DeviceId`] identifies a client device by its own ed25519 public key.

use core::fmt;
use core::str::FromStr;

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use sha3::Sha3_256;

/// Onion service protocol version encoded in every v3 address.
pub const ONION_V3_VERSION: u8 = 3;
/// Length of the base32 body of a v3 address (35 bytes → 56 base32 chars).
pub const ONION_V3_ADDR_LEN: usize = 56;
/// Length of the base32 rendering of a [`DeviceId`] (32 bytes → 52 chars).
pub const DEVICE_ID_LEN: usize = 52;

const ONION_SUFFIX: &str = ".onion";
const CHECKSUM_PREFIX: &[u8] = b".onion checksum";

/// Why an identifier string was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// Wrong number of characters after normalization.
    #[error("expected {expected} base32 characters, found {found}")]
    Length {
        /// Expected length.
        expected: usize,
        /// Length actually seen.
        found: usize,
    },
    /// Not valid base32 (RFC 4648 alphabet, case-insensitive).
    #[error("not valid base32")]
    Base32,
    /// The trailing version byte is not `3`.
    #[error("unsupported onion address version {0}")]
    Version(u8),
    /// The two checksum bytes do not match the public key.
    #[error("checksum mismatch (typo in the ID?)")]
    Checksum,
    /// The 32 bytes are not a valid ed25519 public key (not a curve point).
    #[error("not a valid ed25519 public key")]
    PublicKey,
}

/// A host identity: an onion v3 address, i.e. a 32-byte ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TornectId {
    pk: [u8; 32],
}

impl TornectId {
    /// Build the ID for an ed25519 public key.
    #[must_use]
    pub fn from_public_key(pk: &VerifyingKey) -> Self {
        Self { pk: pk.to_bytes() }
    }

    /// Build the ID from raw public-key bytes.
    ///
    /// No curve-point validation is performed here (Tor itself does not require it
    /// for addressing); call [`TornectId::verifying_key`] when you need a usable key.
    #[must_use]
    pub const fn from_bytes(pk: [u8; 32]) -> Self {
        Self { pk }
    }

    /// The raw public-key bytes.
    #[must_use]
    pub const fn public_key_bytes(&self) -> &[u8; 32] {
        &self.pk
    }

    /// The ed25519 verifying key, if the bytes are a valid curve point.
    pub fn verifying_key(&self) -> Result<VerifyingKey, IdError> {
        VerifyingKey::from_bytes(&self.pk).map_err(|_| IdError::PublicKey)
    }

    /// Two-byte checksum per rend-spec-v3: `SHA3-256(".onion checksum" || pk || 0x03)[0..2]`.
    fn checksum(pk: &[u8; 32]) -> [u8; 2] {
        let mut h = Sha3_256::new();
        h.update(CHECKSUM_PREFIX);
        h.update(pk);
        h.update([ONION_V3_VERSION]);
        let d = h.finalize();
        [d[0], d[1]]
    }

    /// The 56-character base32 body without the `.onion` suffix.
    #[must_use]
    pub fn base32(&self) -> String {
        let mut raw = [0u8; 35];
        raw[..32].copy_from_slice(&self.pk);
        raw[32..34].copy_from_slice(&Self::checksum(&self.pk));
        raw[34] = ONION_V3_VERSION;
        let mut s = BASE32_NOPAD.encode(&raw);
        s.make_ascii_lowercase();
        s
    }

    /// The full `<56 chars>.onion` address.
    #[must_use]
    pub fn onion_address(&self) -> String {
        let mut s = self.base32();
        s.push_str(ONION_SUFFIX);
        s
    }

    /// The address split into seven groups of eight characters, for ID cards.
    #[must_use]
    pub fn display_groups(&self) -> String {
        let s = self.base32();
        s.as_bytes()
            .chunks(8)
            .map(|c| core::str::from_utf8(c).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// First eight characters, for logs and compact UI.
    #[must_use]
    pub fn short(&self) -> String {
        self.base32()[..8].to_owned()
    }
}

impl fmt::Display for TornectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.onion_address())
    }
}

impl fmt::Debug for TornectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TornectId({}…)", self.short())
    }
}

impl FromStr for TornectId {
    type Err = IdError;

    /// Accepts the bare 56-char body or the full `.onion` form, any case, with
    /// optional whitespace/hyphen grouping (as produced by [`TornectId::display_groups`]).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut body: String = s
            .trim()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        if let Some(stripped) = strip_suffix_ignore_case(&body, ONION_SUFFIX) {
            body = stripped.to_owned();
        }
        if body.len() != ONION_V3_ADDR_LEN {
            return Err(IdError::Length {
                expected: ONION_V3_ADDR_LEN,
                found: body.len(),
            });
        }
        body.make_ascii_uppercase();
        let raw = BASE32_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| IdError::Base32)?;
        if raw.len() != 35 {
            return Err(IdError::Length {
                expected: ONION_V3_ADDR_LEN,
                found: body.len(),
            });
        }
        let version = raw[34];
        if version != ONION_V3_VERSION {
            return Err(IdError::Version(version));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&raw[..32]);
        let expected = Self::checksum(&pk);
        if raw[32..34] != expected {
            return Err(IdError::Checksum);
        }
        Ok(Self { pk })
    }
}

impl Serialize for TornectId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.onion_address())
    }
}

impl<'de> Deserialize<'de> for TornectId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A client device identity: its ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId {
    pk: [u8; 32],
}

impl DeviceId {
    /// Build from a verifying key.
    #[must_use]
    pub fn from_public_key(pk: &VerifyingKey) -> Self {
        Self { pk: pk.to_bytes() }
    }

    /// Build from raw bytes (no curve validation; see [`DeviceId::verifying_key`]).
    #[must_use]
    pub const fn from_bytes(pk: [u8; 32]) -> Self {
        Self { pk }
    }

    /// Raw public-key bytes.
    #[must_use]
    pub const fn public_key_bytes(&self) -> &[u8; 32] {
        &self.pk
    }

    /// The verifying key, if valid.
    pub fn verifying_key(&self) -> Result<VerifyingKey, IdError> {
        VerifyingKey::from_bytes(&self.pk).map_err(|_| IdError::PublicKey)
    }

    /// Lowercase base32 rendering (52 characters).
    #[must_use]
    pub fn base32(&self) -> String {
        let mut s = BASE32_NOPAD.encode(&self.pk);
        s.make_ascii_lowercase();
        s
    }

    /// Human-checkable fingerprint: first 8 bytes of SHA-256(pk) as `xxxx-xxxx-xxxx-xxxx`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let d = Sha256::digest(self.pk);
        let h = hex::encode(&d[..8]);
        format!("{}-{}-{}-{}", &h[0..4], &h[4..8], &h[8..12], &h[12..16])
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base32())
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.fingerprint())
    }
}

impl FromStr for DeviceId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut body: String = s
            .trim()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        if body.len() != DEVICE_ID_LEN {
            return Err(IdError::Length {
                expected: DEVICE_ID_LEN,
                found: body.len(),
            });
        }
        body.make_ascii_uppercase();
        let raw = BASE32_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| IdError::Base32)?;
        let pk: [u8; 32] = raw.try_into().map_err(|_| IdError::Length {
            expected: DEVICE_ID_LEN,
            found: body.len(),
        })?;
        Ok(Self { pk })
    }
}

impl Serialize for DeviceId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.base32())
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// CBOR form of a [`DeviceId`]: a 32-byte string (`docs/PLAN.md` §B.3, §B.8.9).
impl<C> minicbor::Encode<C> for DeviceId {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(&self.pk)?.ok()
    }
}

impl<'b, C> minicbor::Decode<'b, C> for DeviceId {
    fn decode(d: &mut minicbor::Decoder<'b>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        let p = d.position();
        let b = d.bytes()?;
        let pk: [u8; 32] = b
            .try_into()
            .map_err(|_| minicbor::decode::Error::message("device id must be 32 bytes").at(p))?;
        Ok(Self { pk })
    }
}

/// CBOR form of a [`TornectId`]: the raw 32-byte public key.
impl<C> minicbor::Encode<C> for TornectId {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(&self.pk)?.ok()
    }
}

impl<'b, C> minicbor::Decode<'b, C> for TornectId {
    fn decode(d: &mut minicbor::Decoder<'b>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        let p = d.position();
        let b = d.bytes()?;
        let pk: [u8; 32] = b
            .try_into()
            .map_err(|_| minicbor::decode::Error::message("tornect id must be 32 bytes").at(p))?;
        Ok(Self { pk })
    }
}

/// Whether `c` belongs to the RFC 4648 base32 alphabet an onion address is written in,
/// in either case: `A`–`Z`, `a`–`z`, `2`–`7`. Never `0`, `1`, `8` or `9`.
pub(crate) fn is_b32(c: char) -> bool {
    matches!(c, 'A'..='Z' | 'a'..='z' | '2'..='7')
}

/// `s` without a case-insensitive ASCII `suffix`. Typed or pasted text can hold any
/// character, so the cut point may fall inside a multi-byte one: `get` answers `None`
/// there instead of the panic a range index would raise (such a tail cannot equal an
/// ASCII suffix anyway). Crate-visible so the invitation parser strips `.onion` the
/// same boundary-safe way.
pub(crate) fn strip_suffix_ignore_case<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    let cut = s.len().checked_sub(suffix.len())?;
    let tail = s.get(cut..)?;
    if tail.eq_ignore_ascii_case(suffix) {
        s.get(..cut)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Real, publicly known onion v3 addresses. Parsing one succeeds only if our
    /// checksum algorithm matches Tor's, so these double as spec conformance tests.
    const KNOWN: &[&str] = &[
        "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
        "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
        "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion",
    ];

    #[test]
    fn parses_known_real_world_addresses() {
        for addr in KNOWN {
            let id: TornectId = addr.parse().unwrap_or_else(|e| panic!("{addr}: {e}"));
            assert_eq!(id.onion_address(), *addr);
            assert_eq!(id.base32().len(), ONION_V3_ADDR_LEN);
        }
    }

    #[test]
    fn accepts_grouped_uppercase_and_bare_forms() {
        let id: TornectId = KNOWN[0].parse().unwrap();
        let grouped = id.display_groups();
        assert_eq!(grouped.split(' ').count(), 7);
        assert_eq!(grouped.parse::<TornectId>().unwrap(), id);
        assert_eq!(id.base32().to_uppercase().parse::<TornectId>().unwrap(), id);
        assert_eq!(
            format!("  {}.ONION \n", id.base32())
                .parse::<TornectId>()
                .unwrap(),
            id
        );
    }

    #[test]
    fn rejects_typos() {
        let good = KNOWN[0].to_owned();
        let mut chars: Vec<char> = good.chars().collect();
        // flip one character inside the key body
        chars[10] = if chars[10] == 'a' { 'b' } else { 'a' };
        let bad: String = chars.into_iter().collect();
        assert_eq!(bad.parse::<TornectId>(), Err(IdError::Checksum));
        assert!(matches!(
            "tooshort".parse::<TornectId>(),
            Err(IdError::Length { .. })
        ));
        let mut not_b32 = good.clone();
        not_b32.replace_range(0..1, "1"); // '1' is not in the RFC 4648 base32 alphabet
        assert_eq!(not_b32.parse::<TornectId>(), Err(IdError::Base32));
    }

    #[test]
    fn rejects_wrong_version_byte() {
        let id: TornectId = KNOWN[0].parse().unwrap();
        let mut raw = [0u8; 35];
        raw[..32].copy_from_slice(id.public_key_bytes());
        raw[32..34].copy_from_slice(&TornectId::checksum(id.public_key_bytes()));
        raw[34] = 2;
        let s = BASE32_NOPAD.encode(&raw).to_lowercase();
        assert_eq!(s.parse::<TornectId>(), Err(IdError::Version(2)));
    }

    #[test]
    fn serde_roundtrip_as_string() {
        let id: TornectId = KNOWN[1].parse().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", KNOWN[1]));
        let back: TornectId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn device_id_roundtrip_and_fingerprint() {
        let dev = DeviceId::from_bytes([7u8; 32]);
        let s = dev.to_string();
        assert_eq!(s.len(), DEVICE_ID_LEN);
        assert_eq!(s.parse::<DeviceId>().unwrap(), dev);
        let fp = dev.fingerprint();
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.matches('-').count(), 3);
        assert_eq!(format!("{dev:?}"), format!("DeviceId({fp})"));
    }

    #[test]
    fn cbor_forms_are_32_byte_strings() {
        let dev = DeviceId::from_bytes([5u8; 32]);
        let bytes = minicbor::to_vec(dev).unwrap();
        assert_eq!(bytes.len(), 34, "bstr header (2) + 32 bytes");
        assert_eq!(bytes[0], 0x58);
        assert_eq!(minicbor::decode::<DeviceId>(&bytes).unwrap(), dev);
        assert!(minicbor::decode::<DeviceId>(&bytes[..20]).is_err());
        let id = TornectId::from_bytes([6u8; 32]);
        assert_eq!(
            minicbor::decode::<TornectId>(&minicbor::to_vec(id).unwrap()).unwrap(),
            id
        );
        let short = minicbor::to_vec(minicbor::bytes::ByteVec::from(vec![1u8; 31])).unwrap();
        assert!(minicbor::decode::<TornectId>(&short).is_err());
    }

    /// A field is parsed on every frame while someone types into it, so each prefix
    /// of a name with a two- or three-byte character reaches the parser; the six
    /// bytes before the end used to be sliced without a char-boundary check.
    #[test]
    fn non_ascii_text_is_an_error_not_a_panic() {
        for text in [
            "é12345",
            "Zoë's lap",
            "Joãoport",
            "東京のパソコン",
            "x東京.onion",
            "ë.onion",
        ] {
            assert!(text.parse::<TornectId>().is_err(), "{text}");
            assert!(text.parse::<DeviceId>().is_err(), "{text}");
        }
        for typed in ["Zoë's laptop", "João-portátil", "東京のパソコン-1"] {
            let mut prefix = String::new();
            for c in typed.chars() {
                prefix.push(c);
                assert!(prefix.parse::<TornectId>().is_err(), "{prefix}");
                assert!(prefix.parse::<DeviceId>().is_err(), "{prefix}");
            }
        }
        assert_eq!(strip_suffix_ignore_case("é12345", ONION_SUFFIX), None);
        assert_eq!(
            strip_suffix_ignore_case("ab.ONION", ONION_SUFFIX),
            Some("ab")
        );
        assert_eq!(strip_suffix_ignore_case("ë.onion", ONION_SUFFIX), Some("ë"));
        assert_eq!(strip_suffix_ignore_case("onion", ONION_SUFFIX), None);
    }

    /// The cases the invitation design names: six bytes before the end of `x€onion`
    /// fall inside the `€` (the slice that used to panic), while `€.onion` and a
    /// combining accent before `.onion` cut on a boundary and strip to a short body.
    #[test]
    fn a_cut_inside_a_character_is_an_error_not_a_panic() {
        for text in ["x€onion", "€.onion", "ab\u{301}.onion"] {
            assert!(text.parse::<TornectId>().is_err(), "{text}");
            assert!(text.parse::<DeviceId>().is_err(), "{text}");
        }
        assert_eq!(strip_suffix_ignore_case("x€onion", ONION_SUFFIX), None);
        assert_eq!(strip_suffix_ignore_case("€.onion", ONION_SUFFIX), Some("€"));
        assert_eq!(
            strip_suffix_ignore_case("ab\u{301}.onion", ONION_SUFFIX),
            Some("ab\u{301}")
        );
        assert_eq!(
            strip_suffix_ignore_case("x€.OnIoN", ONION_SUFFIX),
            Some("x€")
        );
    }

    /// The alphabet `base32()` writes in, and nothing else: every character of a
    /// rendered address passes, the four digits base32 leaves out and any other
    /// character do not.
    #[test]
    fn is_b32_is_the_onion_alphabet() {
        let all: String = ('\0'..='\u{7f}').filter(|&c| is_b32(c)).collect();
        assert_eq!(
            all,
            "234567ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        );
        for c in [
            '0', '1', '8', '9', '-', '.', ' ', 'é', 'Ａ', '\u{200b}', '\u{202e}',
        ] {
            assert!(!is_b32(c), "{c:?}");
        }
        for addr in KNOWN {
            let id: TornectId = addr.parse().unwrap();
            assert!(id.base32().chars().all(is_b32), "{addr}");
        }
    }

    proptest! {
        /// Any text a field can hold is answered, never a panic (B05).
        #[test]
        fn from_str_never_panics(s in any::<String>()) {
            let _ = s.parse::<TornectId>();
            let _ = s.parse::<DeviceId>();
        }

        /// The same with the suffix appended and a real ID's body mixed in, so the
        /// strip and the length checks see non-ASCII next to the cut point.
        #[test]
        fn from_str_never_panics_near_the_suffix(
            head in "\\PC{0,8}",
            pk in any::<[u8; 32]>(),
            tail in "\\PC{0,3}",
        ) {
            let body = TornectId::from_bytes(pk).base32();
            let _ = format!("{head}{tail}.onion").parse::<TornectId>();
            let _ = format!("{head}{body}{tail}").parse::<TornectId>();
            let _ = format!("{tail}{body}.onion").parse::<TornectId>();
            let _ = format!("{head}{}", &body[..52]).parse::<DeviceId>();
        }

        #[test]
        fn tornect_id_roundtrips(pk in any::<[u8; 32]>()) {
            let id = TornectId::from_bytes(pk);
            let s = id.to_string();
            prop_assert_eq!(s.len(), ONION_V3_ADDR_LEN + ONION_SUFFIX.len());
            let back: TornectId = s.parse().unwrap();
            prop_assert_eq!(back, id);
            prop_assert_eq!(back.public_key_bytes(), &pk);
        }

        #[test]
        fn device_id_roundtrips(pk in any::<[u8; 32]>()) {
            let d = DeviceId::from_bytes(pk);
            let back: DeviceId = d.to_string().parse().unwrap();
            prop_assert_eq!(back, d);
        }
    }
}
