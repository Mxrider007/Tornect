//! The on-disk form of the unattended store (`docs/PLAN.md` §B.8.9): key derivation,
//! the AEAD file format and the machine-id hash.
//!
//! ```text
//! unattended.bin = "TNUA" || u8 fmt || u64be generation || nonce[24]
//!                  || XChaCha20-Poly1305(K_unatt, nonce, CBOR(UnattendedStore), aad = header)
//! keystore entry "unattended-master.key" = K_master[32] || u64be anchor
//! K_unatt = HKDF-SHA256(ikm = K_master, salt = "tornect/v1/keystore", info = "unattended-store", 32)
//! K_log   = HKDF-SHA256(ikm = K_master, salt = "tornect/v1/keystore", info = "log", 32)
//! machine_id_hash = SHA-256("tornect/v1/machine-id\0" || id)
//! ```

use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::CoreError;

use super::grant::{SCHEMA_VERSION, UnattendedStore};

/// File magic.
pub const MAGIC: &[u8; 4] = b"TNUA";
/// File format byte.
pub const FORMAT: u8 = 1;
/// Nonce length (XChaCha20).
pub const NONCE_LEN: usize = 24;
/// Header length: magic (4) + fmt (1) + generation (8) + nonce (24).
pub const HEADER_LEN: usize = 4 + 1 + 8 + NONCE_LEN;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Keystore entry holding `K_master || u64be anchor`.
pub const MASTER_KEY_ENTRY: &str = "unattended-master.key";
/// HKDF salt shared by both derivations.
pub const KEYSTORE_SALT: &[u8] = b"tornect/v1/keystore";
/// HKDF info of `K_unatt`.
pub const STORE_INFO: &[u8] = b"unattended-store";
/// HKDF info of `K_log`.
pub const LOG_INFO: &[u8] = b"log";
/// Prefix of the machine-id hash.
pub const MACHINE_ID_PREFIX: &[u8] = b"tornect/v1/machine-id\0";
/// Largest store file we are willing to decrypt (a few grants are a few KiB).
pub const MAX_FILE_LEN: usize = 4 * 1024 * 1024;

/// Why the store could not be loaded — every variant fails closed (§B.8.9: unattended
/// off + notification, never a silent reset).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreLoadError {
    /// A store file exists but `unattended-master.key` does not.
    #[error("unattended store present but its master key is missing from the keystore")]
    MissingKey,
    /// The master key exists but cannot be read right now (locked keychain).
    #[error("keystore locked: {0}")]
    KeystoreLocked(String),
    /// The keystore entry has the wrong length.
    #[error("unattended master key entry is corrupt")]
    CorruptKey,
    /// An anchor exists in the keystore but no store file.
    #[error("unattended store file missing while its anchor exists (generation {0})")]
    AnchorWithoutFile(u64),
    /// Bad magic, format byte or length.
    #[error("unattended store header invalid")]
    BadHeader,
    /// AEAD tag verification failed (tampered, wrong key, or truncated).
    #[error("unattended store authentication failed")]
    BadTag,
    /// The plaintext is not a valid store.
    #[error("unattended store decode failed: {0}")]
    Decode(String),
    /// Written by a newer build.
    #[error("unattended store schema {0} is newer than this build's {SCHEMA_VERSION}")]
    NewerSchema(u16),
    /// A rolled-back file: its generation is below the keychain anchor.
    #[error("unattended store generation {generation} is older than the anchor {anchor}")]
    OlderThanAnchor {
        /// Generation in the file header.
        generation: u64,
        /// Anchor in the keystore entry.
        anchor: u64,
    },
    /// Filesystem failure.
    #[error("unattended store I/O: {0}")]
    Io(String),
}

/// `K_master` plus the anti-rollback anchor, as stored in the keystore entry.
pub struct MasterKey {
    key: Zeroizing<[u8; 32]>,
    anchor: u64,
}

impl MasterKey {
    /// A fresh random key with anchor 0 (raised to 1 by the bootstrap policy write).
    pub fn generate() -> Result<Self, CoreError> {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut_slice()).map_err(|e| CoreError::Rng(e.to_string()))?;
        Ok(Self { key, anchor: 0 })
    }

    /// Rebuild from known material (tests, golden vectors).
    #[must_use]
    pub fn from_parts(key: [u8; 32], anchor: u64) -> Self {
        Self {
            key: Zeroizing::new(key),
            anchor,
        }
    }

    /// Parse the 40-byte keystore entry.
    pub fn parse(entry: &[u8]) -> Result<Self, StoreLoadError> {
        if entry.len() != 40 {
            return Err(StoreLoadError::CorruptKey);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&entry[..32]);
        let anchor = u64::from_be_bytes(
            entry[32..40]
                .try_into()
                .map_err(|_| StoreLoadError::CorruptKey)?,
        );
        Ok(Self { key, anchor })
    }

    /// The keystore entry bytes.
    #[must_use]
    pub fn to_entry(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(40));
        v.extend_from_slice(self.key.as_slice());
        v.extend_from_slice(&self.anchor.to_be_bytes());
        v
    }

    /// The anti-rollback anchor.
    #[must_use]
    pub fn anchor(&self) -> u64 {
        self.anchor
    }

    /// Raise the anchor (never lowers it).
    pub fn raise_anchor(&mut self, to: u64) {
        self.anchor = self.anchor.max(to);
    }

    /// `K_unatt`.
    #[must_use]
    pub fn k_unatt(&self) -> Zeroizing<[u8; 32]> {
        derive_key(&self.key, STORE_INFO)
    }

    /// `K_log`.
    #[must_use]
    pub fn k_log(&self) -> Zeroizing<[u8; 32]> {
        derive_key(&self.key, LOG_INFO)
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey")
            .field("key", &"<redacted>")
            .field("anchor", &self.anchor)
            .finish()
    }
}

/// `HKDF-SHA256(ikm = K_master, salt = "tornect/v1/keystore", info, 32)`.
#[must_use]
pub fn derive_key(k_master: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(KEYSTORE_SALT), k_master);
    let mut okm = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below the 255 × 32 expand limit.
    hk.expand(info, okm.as_mut_slice())
        .unwrap_or_else(|_| unreachable!("32-byte HKDF output is always valid"));
    okm
}

/// `K_unatt` from `K_master`.
#[must_use]
pub fn derive_k_unatt(k_master: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    derive_key(k_master, STORE_INFO)
}

/// `K_log` from `K_master`.
#[must_use]
pub fn derive_k_log(k_master: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    derive_key(k_master, LOG_INFO)
}

/// `SHA-256("tornect/v1/machine-id\0" || id)`.
#[must_use]
pub fn machine_id_hash(id: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MACHINE_ID_PREFIX);
    h.update(id);
    h.finalize().into()
}

/// This machine's stable id: `/etc/machine-id` on Linux (trimmed), `None` when
/// unavailable (containers) or on platforms whose id source lands with
/// `tornect-platform` at M6 (`MachineGuid`, `IOPlatformUUID`).
#[must_use]
pub fn local_machine_id() -> Option<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/etc/machine-id").ok()?;
        let t = s.trim();
        (!t.is_empty()).then(|| t.as_bytes().to_vec())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Encrypt `store` at `generation` with a fresh random nonce.
pub fn seal(
    k_unatt: &[u8; 32],
    generation: u64,
    store: &UnattendedStore,
) -> Result<Vec<u8>, CoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| CoreError::Rng(e.to_string()))?;
    seal_with_nonce(k_unatt, generation, &nonce, store)
}

/// Encrypt with an explicit nonce (tests and golden vectors).
pub fn seal_with_nonce(
    k_unatt: &[u8; 32],
    generation: u64,
    nonce: &[u8; NONCE_LEN],
    store: &UnattendedStore,
) -> Result<Vec<u8>, CoreError> {
    let plain = Zeroizing::new(
        minicbor::to_vec(store).map_err(|e| CoreError::Store(format!("store encode: {e}")))?,
    );
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT);
    header.extend_from_slice(&generation.to_be_bytes());
    header.extend_from_slice(nonce);
    let cipher = XChaCha20Poly1305::new(k_unatt.into());
    let ct = cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: &plain,
                aad: &header,
            },
        )
        .map_err(|_| CoreError::Store("store encrypt failed".into()))?;
    let mut out = header;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Parse the header of a store file: `(generation, nonce)`.
pub fn parse_header(bytes: &[u8]) -> Result<(u64, [u8; NONCE_LEN]), StoreLoadError> {
    if bytes.len() < HEADER_LEN + TAG_LEN || bytes.len() > MAX_FILE_LEN {
        return Err(StoreLoadError::BadHeader);
    }
    if &bytes[..4] != MAGIC || bytes[4] != FORMAT {
        return Err(StoreLoadError::BadHeader);
    }
    let generation = u64::from_be_bytes(
        bytes[5..13]
            .try_into()
            .map_err(|_| StoreLoadError::BadHeader)?,
    );
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[13..HEADER_LEN]);
    Ok((generation, nonce))
}

/// Decrypt and decode a store file: `(generation, store)`.
pub fn open(k_unatt: &[u8; 32], bytes: &[u8]) -> Result<(u64, UnattendedStore), StoreLoadError> {
    let (generation, nonce) = parse_header(bytes)?;
    let cipher = XChaCha20Poly1305::new(k_unatt.into());
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &bytes[HEADER_LEN..],
                    aad: &bytes[..HEADER_LEN],
                },
            )
            .map_err(|_| StoreLoadError::BadTag)?,
    );
    let store: UnattendedStore =
        minicbor::decode(&plain).map_err(|e| StoreLoadError::Decode(e.to_string()))?;
    if store.schema_version > SCHEMA_VERSION {
        return Err(StoreLoadError::NewerSchema(store.schema_version));
    }
    Ok((generation, store))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u6_hkdf_golden_vectors_k_unatt_k_log() {
        // K_master = 00 01 02 … 1f (the vectors are committed in docs/notes/m1-golden-vector-core.md)
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let k_unatt = derive_k_unatt(&k);
        let k_log = derive_k_log(&k);
        // Cross-checked against an independent HKDF (Python hmac/hashlib, 2026-08-29)
        // and pinned in docs/notes/m1-golden-vector-core.md.
        assert_eq!(hex::encode(*k_unatt), K_UNATT_HEX);
        assert_eq!(hex::encode(*k_log), K_LOG_HEX);
        assert_ne!(k_unatt, k_log);
        let mk = MasterKey::from_parts(k, 7);
        assert_eq!(*mk.k_unatt(), *k_unatt);
        assert_eq!(*mk.k_log(), *k_log);
        // the log tag over a fixed line
        let tag = crate::session_log::line_tag(
            &k_log,
            b"{\"ts\":\"2026-08-29T00:00:00Z\",\"event\":\"grant_created\",\"prev\":null}",
        );
        assert_eq!(hex::encode(tag), LOG_TAG_HEX);
        // a fixed store sealed under K_unatt with a fixed nonce
        let store = UnattendedStore::bootstrap(
            Zeroizing::new(vec![0x11u8; 16]),
            Some([0x22u8; 32]),
            1_756_425_600,
        );
        let cbor = minicbor::to_vec(&store).unwrap();
        assert_eq!(hex::encode(&cbor), STORE_CBOR_HEX);
        let sealed = seal_with_nonce(&k_unatt, 1, &[0x33u8; NONCE_LEN], &store).unwrap();
        assert_eq!(hex::encode(&sealed), SEALED_HEX);
        assert_eq!(open(&k_unatt, &sealed).unwrap(), (1, store));
    }

    /// Pinned outputs for `K_master = 00..1f` (see `docs/notes/m1-golden-vector-core.md`).
    const K_UNATT_HEX: &str = "6dd4bffa8cb4208c2ad98419052248708e1f8c11a173c74ea856c11177d00c96";
    const K_LOG_HEX: &str = "443b6fc2e74166d8657e8a4b3e96d2b1ad1d4714b8e850e66857e4f629a7d06b";
    const LOG_TAG_HEX: &str = "ac00659ea167af7414b63d2c1635155915f16c2b82414cf95c6aed7a0d5812e0";
    const STORE_CBOR_HEX: &str = "ad000101f4035011111111111111111111111111111111051406f507f408f509800a800b582000000000000000000000000000000000000000000000000000000000000000000c1a68b0ed800d010e58202222222222222222222222222222222222222222222222222222222222222222";
    const SEALED_HEX: &str = "544e55410100000000000000013333333333333333333333333333333333333333333333332e3699eb190527c237f9145eee2d939d00f5624076666efb0c3f64ec3028e20ae1e94202e1f3ac14c96a41d35bf2833e92a3f9d917f4bac9d0280597e3b156b1032b8d22f3ceabf9e79cbe7199d8bfb85e7123cbdb134a04e25dbba1b3f8dc870baa6e48cda6a14680a55bde55547110ab2fcae487c044dd6bbbf7e74b350bd1d7";

    #[test]
    fn master_key_entry_roundtrips_and_redacts() {
        let mk = MasterKey::from_parts([3u8; 32], 42);
        let entry = mk.to_entry();
        assert_eq!(entry.len(), 40);
        let back = MasterKey::parse(&entry).unwrap();
        assert_eq!(back.anchor(), 42);
        assert_eq!(*back.k_unatt(), *mk.k_unatt());
        assert!(matches!(
            MasterKey::parse(&entry[..39]),
            Err(StoreLoadError::CorruptKey)
        ));
        let dbg = format!("{mk:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("3, 3, 3"));
    }

    #[test]
    fn u4_seal_open_roundtrip_and_header_checks() {
        let store = UnattendedStore::bootstrap(Zeroizing::new(vec![1u8; 128]), Some([2u8; 32]), 99);
        let k = [5u8; 32];
        let bytes = seal(&k, 3, &store).unwrap();
        assert_eq!(&bytes[..4], b"TNUA");
        assert_eq!(bytes[4], FORMAT);
        let (generation, back) = open(&k, &bytes).unwrap();
        assert_eq!(generation, 3);
        assert_eq!(back, store);
        assert_eq!(open(&[6u8; 32], &bytes), Err(StoreLoadError::BadTag));
        assert_eq!(
            open(&k, &bytes[..HEADER_LEN + TAG_LEN - 1]),
            Err(StoreLoadError::BadHeader)
        );
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert_eq!(open(&k, &bad), Err(StoreLoadError::BadHeader));
        let mut newer = store.clone();
        newer.schema_version = SCHEMA_VERSION + 1;
        let bytes = seal(&k, 3, &newer).unwrap();
        assert_eq!(
            open(&k, &bytes),
            Err(StoreLoadError::NewerSchema(SCHEMA_VERSION + 1))
        );
    }

    #[test]
    fn u4_tamper_of_any_byte_fails_closed() {
        let store = UnattendedStore::bootstrap(Zeroizing::new(vec![1u8; 16]), None, 99);
        let k = [5u8; 32];
        let bytes = seal_with_nonce(&k, 1, &[7u8; NONCE_LEN], &store).unwrap();
        for i in 0..bytes.len() {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            let r = open(&k, &t);
            assert!(r.is_err(), "byte {i} flipped must fail");
            if i >= 13 {
                // nonce, ciphertext or tag: the AEAD catches it (header AAD covers the
                // generation too, so a generation flip is BadTag as well)
                assert_eq!(r, Err(StoreLoadError::BadTag), "byte {i}");
            }
        }
        // generation is authenticated through the AAD
        let mut t = bytes.clone();
        t[12] ^= 1;
        assert_eq!(open(&k, &t), Err(StoreLoadError::BadTag));
    }

    #[test]
    fn machine_id_hash_is_prefixed() {
        let h = machine_id_hash(b"abc");
        let mut d = Sha256::new();
        d.update(b"tornect/v1/machine-id\0abc");
        assert_eq!(h, <[u8; 32]>::from(d.finalize()));
        let _ = local_machine_id();
    }
}
