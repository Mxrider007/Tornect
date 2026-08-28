//! Long-term ed25519 identities.
//!
//! * [`HostIdentity`] — the key behind a machine's [`TornectId`] (its onion v3
//!   address). At M1 the same seed derives the Arti onion-service identity key.
//! * [`DeviceIdentity`] — a client device's key, pinned by hosts at pairing.
//!
//! Secrets are zeroized on drop and never appear in `Debug` output.

use core::fmt;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::id::{DeviceId, TornectId};

/// 32-byte ed25519 seed, zeroized on drop.
pub type Seed = Zeroizing<[u8; 32]>;

fn random_seed() -> Result<Seed> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice()).map_err(|e| CoreError::Rng(e.to_string()))?;
    Ok(seed)
}

/// The host's long-term identity key.
pub struct HostIdentity {
    key: SigningKey,
}

impl HostIdentity {
    /// Generate a fresh identity from the OS RNG.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(&*random_seed()?))
    }

    /// Rebuild an identity from its 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// The secret seed (for the keystore). Zeroized on drop.
    #[must_use]
    pub fn seed(&self) -> Seed {
        Zeroizing::new(self.key.to_bytes())
    }

    /// The public Tornect ID (onion v3 address).
    #[must_use]
    pub fn id(&self) -> TornectId {
        TornectId::from_public_key(&self.key.verifying_key())
    }

    /// The ed25519 verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Borrow the signing key (needed to derive the Arti onion-service key).
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// Sign a message.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.key.sign(msg)
    }
}

impl fmt::Debug for HostIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostIdentity")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

/// A client device's long-term identity key.
pub struct DeviceIdentity {
    key: SigningKey,
}

impl DeviceIdentity {
    /// Generate a fresh identity from the OS RNG.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(&*random_seed()?))
    }

    /// Rebuild from the 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// The secret seed (for the keystore). Zeroized on drop.
    #[must_use]
    pub fn seed(&self) -> Seed {
        Zeroizing::new(self.key.to_bytes())
    }

    /// The public device ID.
    #[must_use]
    pub fn id(&self) -> DeviceId {
        DeviceId::from_public_key(&self.key.verifying_key())
    }

    /// The ed25519 verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign a message.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.key.sign(msg)
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

/// Verify an ed25519 signature over `msg` with the given public key.
#[must_use]
pub fn verify(pk: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
    pk.verify(msg, sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sign_verify_roundtrip() {
        let host = HostIdentity::generate().unwrap();
        let sig = host.sign(b"hello");
        assert!(verify(&host.verifying_key(), b"hello", &sig));
        assert!(!verify(&host.verifying_key(), b"hellp", &sig));

        let again = HostIdentity::from_seed(&host.seed());
        assert_eq!(again.id(), host.id());
        assert_eq!(host.id().to_string().len(), 56 + 6);
    }

    #[test]
    fn two_generated_identities_differ() {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn debug_output_never_contains_the_seed() {
        let host = HostIdentity::generate().unwrap();
        let seed_hex = hex::encode(*host.seed());
        let dbg = format!("{host:?}");
        assert!(!dbg.contains(&seed_hex));
        assert!(dbg.starts_with("HostIdentity"));
    }
}
