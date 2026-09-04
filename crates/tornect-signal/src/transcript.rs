//! Transcript hash and envelope signatures (`docs/PLAN.md` §B.8.4.3).
//!
//! ```text
//! th_0   = SHA-256("tornect/v1/transcript\0" || host_onion_pk[32])
//! th_i   = SHA-256(th_{i-1} || wire_frame_i)          // exact bytes incl. the u32-BE length
//! digest = SHA-256(u8 v || u64-BE msg_id || u8 kind || body)
//! sig    = Ed25519(sk, "tornect/v1/sig/" || KIND_NAME || "\0" || th_{i-1} || digest)
//! ```
//!
//! Only handshake frames in protocol order are absorbed (§B.8.4.5); the
//! caller ([`crate::fsm`]) decides which — this module just hashes. The client
//! seeds `th_0` with the public key of the address the user *dialed*, never a
//! host-sent value, which is what binds every later signature to that host.
//!
//! Signatures are verified with `verify_strict` (docs/research/crypto.md §4).

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use tornect_core::{DeviceIdentity, HostIdentity};

use crate::envelope::{Envelope, Kind};
use crate::framing::HEADER_LEN;

/// Domain separator of `th_0`.
pub const TRANSCRIPT_LABEL: &[u8] = b"tornect/v1/transcript\0";
/// Prefix of every signature input.
pub const SIG_PREFIX: &[u8] = b"tornect/v1/sig/";

/// The running transcript hash `th`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    th: [u8; 32],
}

impl Transcript {
    /// `th_0` for a host onion public key.
    #[must_use]
    pub fn new(host_onion_pk: &[u8; 32]) -> Self {
        let th = Sha256::new()
            .chain_update(TRANSCRIPT_LABEL)
            .chain_update(host_onion_pk)
            .finalize()
            .into();
        Self { th }
    }

    /// The current `th_i`.
    #[must_use]
    pub fn current(&self) -> [u8; 32] {
        self.th
    }

    /// Absorb one frame given as its exact wire bytes (length prefix included).
    pub fn absorb_wire(&mut self, wire_frame: &[u8]) {
        self.th = Sha256::new()
            .chain_update(self.th)
            .chain_update(wire_frame)
            .finalize()
            .into();
    }

    /// Absorb one frame given as its payload; the `u32`-BE length prefix that
    /// [`crate::framing::write_frame`] puts on the wire is hashed in front of it.
    pub fn absorb_payload(&mut self, payload: &[u8]) {
        let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        self.th = Sha256::new()
            .chain_update(self.th)
            .chain_update(len.to_be_bytes())
            .chain_update(payload)
            .finalize()
            .into();
    }
}

/// The frame exactly as it went over the wire, from its payload.
#[must_use]
pub fn wire_bytes(payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// `digest = SHA-256(u8 v || u64-BE msg_id || u8 kind || body)`.
#[must_use]
pub fn digest(v: u8, msg_id: u64, kind: Kind, body: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update([v])
        .chain_update(msg_id.to_be_bytes())
        .chain_update([kind.code()])
        .chain_update(body)
        .finalize()
        .into()
}

/// The bytes that are signed: `"tornect/v1/sig/" || KIND_NAME || "\0" || th_prev || digest`.
#[must_use]
pub fn signing_input(kind: Kind, th_prev: &[u8; 32], digest: &[u8; 32]) -> Vec<u8> {
    let name = kind.name().as_bytes();
    let mut out = Vec::with_capacity(SIG_PREFIX.len() + name.len() + 1 + 64);
    out.extend_from_slice(SIG_PREFIX);
    out.extend_from_slice(name);
    out.push(0);
    out.extend_from_slice(th_prev);
    out.extend_from_slice(digest);
    out
}

/// A key that signs envelopes: the host's onion identity key on `HELLO_ACK`,
/// `SESSION_ACCEPT` and `ADMIN_RESULT`, the client's device key on `HELLO` and
/// `SESSION_REQUEST` (the trait is named for the host role, as the plan does;
/// [`DeviceIdentity`] implements it too).
///
/// Decision M1-11: `tornect_core::HostIdentity` signs with ed25519-dalek from
/// the seed, which yields byte-identical signatures to Arti's
/// `ExpandedKeypair` built from the same seed (RFC 8032 is deterministic and
/// both derive the same clamped scalar and nonce prefix; proven by
/// `expanded_keypair_signs_identically`), so no Arti type is needed here.
pub trait HostSigner: Send + Sync {
    /// Sign `msg` (a [`signing_input`]).
    fn sign(&self, msg: &[u8]) -> [u8; 64];
    /// The 32-byte public key the peer verifies with.
    fn public_key(&self) -> [u8; 32];
}

impl HostSigner for HostIdentity {
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        HostIdentity::sign(self, msg).to_bytes()
    }

    fn public_key(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }
}

impl HostSigner for DeviceIdentity {
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        DeviceIdentity::sign(self, msg).to_bytes()
    }

    fn public_key(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }
}

/// Sign `env` over `th_prev` (the transcript *before* this frame) and store
/// the signature in it.
pub fn sign_envelope(signer: &dyn HostSigner, th_prev: &[u8; 32], env: &mut Envelope) {
    let d = digest(env.v, env.msg_id, env.kind, &env.body);
    env.sig = Some(signer.sign(&signing_input(env.kind, th_prev, &d)));
}

/// Why an envelope signature was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SigError {
    /// A signed kind arrived without a signature.
    #[error("signature missing")]
    Missing,
    /// The signature does not verify under the expected key.
    #[error("signature does not verify")]
    Invalid,
}

/// Verify `env`'s signature under `pk` over `th_prev`.
pub fn verify_envelope(
    pk: &VerifyingKey,
    th_prev: &[u8; 32],
    env: &Envelope,
) -> Result<(), SigError> {
    let sig = env.sig.as_ref().ok_or(SigError::Missing)?;
    let d = digest(env.v, env.msg_id, env.kind, &env.body);
    let input = signing_input(env.kind, th_prev, &d);
    pk.verify_strict(&input, &Signature::from_bytes(sig))
        .map_err(|_| SigError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tor_llcrypto::pk::ed25519::ExpandedKeypair;

    use crate::tor::identity_expand_seed;

    #[test]
    fn th0_is_domain_separated_and_absorption_matches_wire_bytes() {
        let pk = [7u8; 32];
        let t = Transcript::new(&pk);
        let expected: [u8; 32] = Sha256::new()
            .chain_update(b"tornect/v1/transcript\0")
            .chain_update(pk)
            .finalize()
            .into();
        assert_eq!(t.current(), expected);
        assert_ne!(t, Transcript::new(&[8u8; 32]));

        let payload = b"payload".to_vec();
        let mut a = t.clone();
        a.absorb_payload(&payload);
        let mut b = t.clone();
        b.absorb_wire(&wire_bytes(&payload));
        assert_eq!(a, b);
        let manual: [u8; 32] = Sha256::new()
            .chain_update(t.current())
            .chain_update(7u32.to_be_bytes())
            .chain_update(&payload)
            .finalize()
            .into();
        assert_eq!(a.current(), manual);
        assert_eq!(&wire_bytes(&payload)[..4], &[0, 0, 0, 7]);
    }

    #[test]
    fn digest_and_signing_input_layout() {
        let d = digest(1, 2, Kind::SessionAccept, b"body");
        let manual: [u8; 32] = Sha256::new()
            .chain_update([1u8])
            .chain_update(2u64.to_be_bytes())
            .chain_update([7u8])
            .chain_update(b"body")
            .finalize()
            .into();
        assert_eq!(d, manual);
        let th = [3u8; 32];
        let input = signing_input(Kind::SessionAccept, &th, &d);
        let mut expected = b"tornect/v1/sig/SESSION_ACCEPT\0".to_vec();
        expected.extend_from_slice(&th);
        expected.extend_from_slice(&d);
        assert_eq!(input, expected);
    }

    #[test]
    fn sign_and_verify_with_both_identities() {
        let host = HostIdentity::from_seed(&[1u8; 32]);
        let device = DeviceIdentity::from_seed(&[2u8; 32]);
        let th = Transcript::new(&HostSigner::public_key(&host)).current();
        for (signer, pk) in [
            (&host as &dyn HostSigner, host.verifying_key()),
            (&device as &dyn HostSigner, device.verifying_key()),
        ] {
            let mut env = Envelope::new(1, 1, Kind::Hello, vec![0xa0]);
            assert_eq!(
                verify_envelope(&pk, &th, &env).unwrap_err(),
                SigError::Missing
            );
            sign_envelope(signer, &th, &mut env);
            verify_envelope(&pk, &th, &env).unwrap();
            // Any change to the covered fields breaks it.
            let mut other = env.clone();
            other.msg_id = 2;
            assert_eq!(
                verify_envelope(&pk, &th, &other).unwrap_err(),
                SigError::Invalid
            );
            let mut other = env.clone();
            other.kind = Kind::HelloAck;
            assert!(verify_envelope(&pk, &th, &other).is_err());
            let mut other = env.clone();
            other.v = 2;
            assert!(verify_envelope(&pk, &th, &other).is_err());
            let mut other = env.clone();
            other.body.push(0);
            assert!(verify_envelope(&pk, &th, &other).is_err());
            assert!(verify_envelope(&pk, &[9u8; 32], &env).is_err());
            let wrong_key = DeviceIdentity::from_seed(&[3u8; 32]).verifying_key();
            assert!(verify_envelope(&wrong_key, &th, &env).is_err());
        }
    }

    /// Decision M1-11: Arti signs onion-service material with the *expanded*
    /// key it derived from the same seed (`tor::identity`); the host signs
    /// envelopes with ed25519-dalek from the seed. RFC 8032 signing is
    /// deterministic, so the two must agree byte for byte — otherwise the
    /// host side would have to sign with the expanded keypair instead.
    #[test]
    fn expanded_keypair_signs_identically() {
        for seed in [[0u8; 32], [0x42u8; 32], [0xffu8; 32], [7u8; 32]] {
            let host = HostIdentity::from_seed(&seed);
            let expanded = identity_expand_seed(&seed);
            let kp = ExpandedKeypair::from_secret_key_bytes(*expanded).expect("valid key");
            assert_eq!(kp.public().to_bytes(), HostSigner::public_key(&host));
            for msg in [&b""[..], b"tornect", &[0u8; 200]] {
                let dalek = HostSigner::sign(&host, msg);
                let arti = kp.sign(msg).to_bytes();
                assert_eq!(dalek, arti, "seed {seed:02x?}");
                host.verifying_key()
                    .verify_strict(msg, &Signature::from_bytes(&arti))
                    .unwrap();
            }
        }
    }
}
