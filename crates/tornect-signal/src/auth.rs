//! Unattended-access authentication (`docs/PLAN.md` §B.8.4.3, §B.8.4.4).
//!
//! The suite is OPAQUE-3DH over ristretto255 with Argon2id as the KSF
//! (`suite = 1`, `"ua1"`), verified against `opaque-ke` 4.0.1 in
//! `docs/research/crypto.md` §8. Everything the protocol binds — the dialed
//! host key, the client device key, the signed transcript, the suite and the
//! intent — enters through `context` and `identifiers`, so a `session_key`
//! exists only if the same device-transcript and the same password met in
//! *this* stream.
//!
//! Nothing here touches the wire or the store: [`HostLogin`] and
//! [`ClientLogin`] are pure state machines over the byte strings that
//! `AUTH_CHALLENGE` / `AUTH_RESPONSE` carry, and the key schedule is a set of
//! free functions. The FSM branch that drives them lives in
//! [`crate::fsm::host`] / [`crate::fsm::client`].

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac as _};
use opaque_ke::{
    ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters,
    CredentialFinalization, CredentialRequest, CredentialResponse, Identifiers,
    RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Wire sizes of the suite-1 messages (`crypto.md` §8.3–8.4; the
/// [`crate::messages`] bodies are fixed-size arrays of exactly these lengths).
pub mod sizes {
    /// `CredentialRequest` (KE1), `AUTH_CHALLENGE` precursor.
    pub const KE1: usize = 96;
    /// `CredentialResponse` (KE2), carried by `AUTH_CHALLENGE`.
    pub const KE2: usize = 320;
    /// `CredentialFinalization` (KE3), carried by `AUTH_RESPONSE`.
    pub const KE3: usize = 64;
    /// A serialized `ServerSetup` (host-wide, in the AEAD store).
    pub const SERVER_SETUP: usize = 128;
    /// A serialized `ServerRegistration` record (per grant, in the AEAD store).
    pub const RECORD: usize = 192;
    /// `RegistrationRequest`.
    pub const REG_REQUEST: usize = 32;
    /// `RegistrationResponse`.
    pub const REG_RESPONSE: usize = 64;
    /// The OPAQUE `session_key` and `export_key` (`Output<Sha512>`).
    pub const KEY: usize = 64;
}

/// `suite = 1` — OPAQUE-3DH / ristretto255 / Argon2id (`"ua1"`).
pub const SUITE_OPAQUE: u8 = 1;

/// Argon2id parameters of the suite: 64 MiB, t = 3, p = 1 (§B.8.4.4).
///
/// A suite constant, not a tunable: it is an input to the KSF and therefore to
/// every stored record. `ksf: None` (the crate default, 19 MiB / t = 2) is
/// forbidden — it would silently produce records this build cannot reproduce.
pub const KSF_PARAMS: (u32, u32, u32) = (64 * 1024, 3, 1);

/// The OPAQUE cipher suite (`crypto.md` §8.2, probe-verified).
///
/// The KE hash **must** be a `digest 0.10` type: the workspace `sha2` is 0.11,
/// whose `Sha512` does not satisfy `opaque_ke::hash::Hash`. Hence `sha2_010`.
/// The KSF **must** be named through `opaque_ke::argon2` (argon2 0.5); the
/// workspace also carries argon2 0.6, which does not implement `Ksf`.
#[derive(Debug, Clone, Copy)]
pub struct TornectOpaque;

impl opaque_ke::CipherSuite for TornectOpaque {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_010::Sha512>;
    type Ksf = opaque_ke::argon2::Argon2<'static>;
}

/// The suite's KSF instance.
fn ksf() -> opaque_ke::argon2::Argon2<'static> {
    use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(KSF_PARAMS.0, KSF_PARAMS.1, KSF_PARAMS.2, None)
        .expect("suite KSF parameters are constants");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// An `opaque-ke` (rand 0.8) RNG over the OS entropy source.
///
/// `opaque-ke` takes `R: rand::CryptoRng + rand::RngCore` from **rand 0.8**,
/// while the workspace is on the rand 0.10 stack; rather than pull a second
/// full `rand` in, this fills straight from `getrandom` (`crypto.md` §3.4).
pub struct OpaqueRng;

impl opaque_ke::rand::RngCore for OpaqueRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("OS entropy source unavailable");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), opaque_ke::rand::Error> {
        getrandom::fill(dest).map_err(opaque_ke::rand::Error::new)
    }
}

// SAFETY-of-contract: `getrandom` is a cryptographically secure OS source, which
// is exactly what this marker trait asserts.
impl opaque_ke::rand::CryptoRng for OpaqueRng {}

// ---------------------------------------------------------------- key schedule

/// Domain separators of §B.8.4.3. Each is a distinct HKDF salt or HMAC prefix,
/// so no two derivations of the schedule can ever collide.
mod domain {
    /// `context` prefix.
    pub const CTX: &[u8] = b"tornect/v1/unattended/ctx\0";
    /// `session_token` HKDF salt.
    pub const TOKEN_SALT: &[u8] = b"tornect/v1/unattended/st";
    /// `session_token` HKDF info prefix.
    pub const TOKEN_INFO: &[u8] = b"token\0";
    /// `confirm_key` HKDF salt.
    pub const CONFIRM_KEY_SALT: &[u8] = b"tornect/v1/unattended/confirm-key";
    /// `token_confirm` HMAC message prefix.
    pub const CONFIRM_MSG: &[u8] = b"tornect/v1/unattended/confirm\0";
    /// `proof_fp` HKDF salt.
    pub const PROOF_FP_SALT: &[u8] = b"tornect/v1/unattended/proof-fp";
}

/// `context = "tornect/v1/unattended/ctx\0" || th_after(SESSION_REQUEST) || u8(suite) || u8(intent)`.
///
/// This is what chains the PAKE to the *signed* transcript: `th_after(SESSION_REQUEST)`
/// commits to the dialed onion pk, the client device pk, both nonces, the caps and
/// the client's signature over all of it. The KE2/KE3 MACs cover `context`, so a
/// `session_key` cannot be transplanted between streams, suites or intents.
#[must_use]
pub fn context(th_after_request: &[u8; 32], suite: u8, intent: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain::CTX.len() + 34);
    out.extend_from_slice(domain::CTX);
    out.extend_from_slice(th_after_request);
    out.push(suite);
    out.push(intent);
    out
}

/// `identifiers = { client: client_device_pk, server: host_onion_pk }` — identical
/// at registration and at login (§B.8.4.3). The host builds these from the
/// signature-verified key, never from a later body field.
#[must_use]
pub fn identifiers<'a>(
    client_device_pk: &'a [u8; 32],
    host_onion_pk: &'a [u8; 32],
) -> Identifiers<'a> {
    Identifiers {
        client: Some(client_device_pk),
        server: Some(host_onion_pk),
    }
}

/// `session_token = HKDF-SHA256(ikm = session_key, salt = "…/st", info = "token\0" || th)[0..32]`.
#[must_use]
pub fn session_token(session_key: &[u8], th_after_response: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(domain::TOKEN_INFO.len() + 32);
    info.extend_from_slice(domain::TOKEN_INFO);
    info.extend_from_slice(th_after_response);
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(domain::TOKEN_SALT), session_key)
        .expand(&info, out.as_mut())
        .expect("32 bytes is within HKDF-SHA256's output bound");
    out
}

/// `confirm_key = HKDF-SHA256(ikm = session_key, salt = "…/confirm-key", info = th)[0..32]`.
///
/// Deliberately never the token itself: the token is the QUIC exporter context
/// of the `BIND` check (§B.6), and reusing it as an HMAC key would cross those
/// two uses.
#[must_use]
pub fn confirm_key(session_key: &[u8], th_after_response: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(domain::CONFIRM_KEY_SALT), session_key)
        .expand(th_after_response, out.as_mut())
        .expect("32 bytes is within HKDF-SHA256's output bound");
    out
}

/// `token_confirm = HMAC-SHA256(confirm_key, "…/confirm\0" || th_after(AUTH_RESPONSE))`.
#[must_use]
pub fn token_confirm(confirm_key: &[u8; 32], th_after_response: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(confirm_key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
    mac.update(domain::CONFIRM_MSG);
    mac.update(th_after_response);
    mac.finalize().into_bytes().into()
}

/// `proof_fp = HKDF-SHA256(session_key, salt = "…/proof-fp", info = "")[0..8]` — the
/// short fingerprint a `ConsentProof::Unattended` carries into the log.
#[must_use]
pub fn proof_fp(session_key: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    Hkdf::<Sha256>::new(Some(domain::PROOF_FP_SALT), session_key)
        .expand(&[], &mut out)
        .expect("8 bytes is within HKDF-SHA256's output bound");
    out
}

// ------------------------------------------------------------------ host login

/// The host half of one OPAQUE login: `ServerLogin::start` → KE2, then
/// `finish(KE3)` → `session_key` (§B.8.4.4).
///
/// `ServerLoginParameters` are passed on **both** calls, as the crate requires;
/// dropping them on either would leave `context` and `identifiers` out of the
/// MACs and unbind the PAKE from the transcript.
pub struct HostLogin {
    state: ServerLogin<TornectOpaque>,
}

impl HostLogin {
    /// Answer a KE1 with KE2, holding the state for [`HostLogin::finish`].
    ///
    /// `record` is the grant's stored `ServerRegistration`. It is always `Some`
    /// here: a missing grant is refused **pre-PAKE** with `NOT_GRANTED`
    /// (§B.8.4.5), so the dummy-record path of RFC 9807 is deliberately unused
    /// (decision UA3) — the gate, not the PAKE, hides which devices are granted.
    pub fn start(
        setup: &ServerSetup<TornectOpaque>,
        record: &ServerRegistration<TornectOpaque>,
        ke1: &[u8; sizes::KE1],
        credential_identifier: &[u8],
        ctx: &[u8],
        ids: Identifiers<'_>,
    ) -> Result<(Self, [u8; sizes::KE2]), AuthError> {
        let request = CredentialRequest::deserialize(ke1).map_err(|_| AuthError::BadMessage)?;
        let started = ServerLogin::start(
            &mut OpaqueRng,
            setup,
            Some(record.clone()),
            request,
            credential_identifier,
            ServerLoginParameters {
                context: Some(ctx),
                identifiers: ids,
            },
        )
        .map_err(|_| AuthError::Protocol)?;
        let ke2: [u8; sizes::KE2] = started
            .message
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::Protocol)?;
        Ok((
            Self {
                state: started.state,
            },
            ke2,
        ))
    }

    /// Verify KE3 and yield the `session_key`.
    ///
    /// A wrong password, a wrong `context` or wrong `identifiers` all land here
    /// as [`AuthError::Rejected`] — indistinguishable by construction, and all
    /// answered on the wire with the single code `AUTH_FAILED` (§B.8.4.6).
    pub fn finish(
        self,
        ke3: &[u8; sizes::KE3],
        ctx: &[u8],
        ids: Identifiers<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        let finalization =
            CredentialFinalization::deserialize(ke3).map_err(|_| AuthError::BadMessage)?;
        let result = self
            .state
            .finish(
                finalization,
                ServerLoginParameters {
                    context: Some(ctx),
                    identifiers: ids,
                },
            )
            .map_err(|_| AuthError::Rejected)?;
        Ok(Zeroizing::new(result.session_key.to_vec()))
    }
}

// ---------------------------------------------------------------- client login

/// What a completed client login yields.
pub struct ClientLoginOutput {
    /// KE3, to travel in `AUTH_RESPONSE`.
    pub ke3: [u8; sizes::KE3],
    /// The shared `session_key` (the ikm of the §B.8.4.3 schedule).
    pub session_key: Zeroizing<Vec<u8>>,
    /// The host's static public key, to check against the `hosts.toml` TOFU pin.
    pub server_s_pk: [u8; 32],
}

/// The client half of one OPAQUE login (§B.8.4.4).
pub struct ClientLogin {
    state: opaque_ke::ClientLogin<TornectOpaque>,
}

impl ClientLogin {
    /// Begin a login. A **fresh** `ClientLogin::start` per stream — reusing one
    /// would reuse the OPRF blind.
    pub fn start(password: &str) -> Result<(Self, [u8; sizes::KE1]), AuthError> {
        let started =
            opaque_ke::ClientLogin::<TornectOpaque>::start(&mut OpaqueRng, password.as_bytes())
                .map_err(|_| AuthError::Protocol)?;
        let ke1: [u8; sizes::KE1] = started
            .message
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::Protocol)?;
        Ok((
            Self {
                state: started.state,
            },
            ke1,
        ))
    }

    /// Consume KE2 and produce KE3 plus the derived material.
    ///
    /// `export_key` is intentionally **not** returned: it is password-derived
    /// and identical across logins, so it is dropped and zeroized inside this
    /// call and never persisted or logged (A14). The keychain-remembered
    /// password is M8 work and does not go through here.
    pub fn finish(
        self,
        password: &str,
        ke2: &[u8; sizes::KE2],
        ctx: &[u8],
        ids: Identifiers<'_>,
    ) -> Result<ClientLoginOutput, AuthError> {
        let response = CredentialResponse::deserialize(ke2).map_err(|_| AuthError::BadMessage)?;
        let finished = self
            .state
            .finish(
                &mut OpaqueRng,
                password.as_bytes(),
                response,
                ClientLoginFinishParameters::new(Some(ctx), ids, Some(&ksf())),
            )
            .map_err(|_| AuthError::Rejected)?;
        let ke3: [u8; sizes::KE3] = finished
            .message
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::Protocol)?;
        let server_s_pk: [u8; 32] = finished
            .server_s_pk
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::Protocol)?;
        Ok(ClientLoginOutput {
            ke3,
            session_key: Zeroizing::new(finished.session_key.to_vec()),
            server_s_pk,
        })
    }
}

// ----------------------------------------------------------------- registration

/// Run the whole OPAQUE registration in-process, both roles (§B.8.4.4 "enable
/// flow"): the host is the only party involved, because a grant password is set
/// locally on the host by the owner, never over the wire.
///
/// Returns the serialized `ServerRegistration` record to store under the grant.
pub fn register_locally(
    setup: &ServerSetup<TornectOpaque>,
    password: &str,
    credential_identifier: &[u8],
    ids: Identifiers<'_>,
) -> Result<[u8; sizes::RECORD], AuthError> {
    let pw = password.as_bytes();
    let start = ClientRegistration::<TornectOpaque>::start(&mut OpaqueRng, pw)
        .map_err(|_| AuthError::Protocol)?;
    let server = ServerRegistration::<TornectOpaque>::start(
        setup,
        RegistrationRequest::deserialize(start.message.serialize().as_slice())
            .map_err(|_| AuthError::Protocol)?,
        credential_identifier,
    )
    .map_err(|_| AuthError::Protocol)?;
    let finish = start
        .state
        .finish(
            &mut OpaqueRng,
            pw,
            RegistrationResponse::deserialize(server.message.serialize().as_slice())
                .map_err(|_| AuthError::Protocol)?,
            ClientRegistrationFinishParameters::new(ids, Some(&ksf())),
        )
        .map_err(|_| AuthError::Protocol)?;
    let record = ServerRegistration::<TornectOpaque>::finish(
        RegistrationUpload::deserialize(finish.message.serialize().as_slice())
            .map_err(|_| AuthError::Protocol)?,
    );
    record
        .serialize()
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::Protocol)
}

/// Create the host-wide `ServerSetup` (once per host, stored in the AEAD store).
#[must_use]
pub fn new_server_setup() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        ServerSetup::<TornectOpaque>::new(&mut OpaqueRng)
            .serialize()
            .to_vec(),
    )
}

/// Parse a stored `ServerSetup`.
pub fn parse_server_setup(bytes: &[u8]) -> Result<ServerSetup<TornectOpaque>, AuthError> {
    ServerSetup::deserialize(bytes).map_err(|_| AuthError::BadMessage)
}

/// Parse a stored grant record.
pub fn parse_record(bytes: &[u8]) -> Result<ServerRegistration<TornectOpaque>, AuthError> {
    ServerRegistration::deserialize(bytes).map_err(|_| AuthError::BadMessage)
}

/// What can go wrong in the PAKE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// A message did not deserialize (wrong length or not a group element).
    #[error("malformed PAKE message")]
    BadMessage,
    /// The peer failed the PAKE: wrong password, `context` or `identifiers`.
    /// All three are one code on the wire (`AUTH_FAILED`, §B.8.4.6).
    #[error("PAKE authentication failed")]
    Rejected,
    /// A library-level failure that is not attributable to the peer.
    #[error("PAKE protocol error")]
    Protocol,
}

// Deliberately no `From<AuthError> for HandshakeError`: a PAKE failure is not a
// transport violation. §B.8.4.5 answers every one of these the same way — settle
// the charge as a failure and send `SESSION_REJECT{AUTH_FAILED}` — and that
// mapping belongs to the FSM branch, which owns the limiter, not to this module.

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_PK: [u8; 32] = [0x11; 32];
    const HOST_PK: [u8; 32] = [0x22; 32];
    const TH_REQ: [u8; 32] = [0x33; 32];
    const TH_RESP: [u8; 32] = [0x44; 32];
    const PW: &str = "quiet verdant otter lantern zephyr";
    const INTENT_SESSION: u8 = 0;

    /// `(host session_key, client session_key)` — equal on success.
    type SessionKeys = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

    struct Fixture {
        setup: ServerSetup<TornectOpaque>,
        record: [u8; sizes::RECORD],
    }

    fn fixture() -> Fixture {
        let setup = parse_server_setup(&new_server_setup()).unwrap();
        let record =
            register_locally(&setup, PW, &CLIENT_PK, identifiers(&CLIENT_PK, &HOST_PK)).unwrap();
        Fixture { setup, record }
    }

    /// One full login: both sides must reach the *same* `session_key`, and the
    /// wire messages must be exactly the sizes the `messages` bodies declare.
    fn login(
        f: &Fixture,
        password: &str,
        client_ctx: &[u8],
        host_ctx: &[u8],
        client_ids: Identifiers<'_>,
        host_ids: Identifiers<'_>,
    ) -> Result<SessionKeys, AuthError> {
        let (client, ke1) = ClientLogin::start(password)?;
        let (host, ke2) = HostLogin::start(
            &f.setup,
            &parse_record(&f.record)?,
            &ke1,
            &CLIENT_PK,
            host_ctx,
            host_ids,
        )?;
        let out = client.finish(password, &ke2, client_ctx, client_ids)?;
        let host_key = host.finish(&out.ke3, host_ctx, host_ids)?;
        Ok((host_key, out.session_key))
    }

    #[test]
    fn opaque_round_trip_agrees_on_the_session_key_and_the_wire_sizes() {
        let f = fixture();
        let ctx = context(&TH_REQ, SUITE_OPAQUE, INTENT_SESSION);
        let ids = identifiers(&CLIENT_PK, &HOST_PK);
        let (host_key, client_key) = login(&f, PW, &ctx, &ctx, ids, ids).unwrap();
        assert_eq!(host_key.as_slice(), client_key.as_slice());
        assert_eq!(host_key.len(), sizes::KEY);
        // The sizes docs/research/crypto.md §8.3–8.4 pin, which the CBOR bodies
        // encode as fixed-length arrays.
        assert_eq!(f.record.len(), sizes::RECORD);
        assert_eq!(new_server_setup().len(), sizes::SERVER_SETUP);
    }

    #[test]
    fn a_wrong_password_is_rejected() {
        let f = fixture();
        let ctx = context(&TH_REQ, SUITE_OPAQUE, INTENT_SESSION);
        let ids = identifiers(&CLIENT_PK, &HOST_PK);
        assert_eq!(
            login(
                &f,
                "quiet verdant otter lantern zephyx",
                &ctx,
                &ctx,
                ids,
                ids
            )
            .unwrap_err(),
            AuthError::Rejected
        );
    }

    /// The whole point of `context`: a `session_key` may not exist unless both
    /// sides ran over the *same signed transcript*, suite and intent. Each of
    /// the three inputs is checked independently.
    #[test]
    fn a_context_mismatch_is_rejected_for_transcript_suite_and_intent() {
        let f = fixture();
        let ids = identifiers(&CLIENT_PK, &HOST_PK);
        let host_ctx = context(&TH_REQ, SUITE_OPAQUE, INTENT_SESSION);
        for client_ctx in [
            context(&[0x99; 32], SUITE_OPAQUE, INTENT_SESSION), // another transcript
            context(&TH_REQ, 2, INTENT_SESSION),                // another suite
            context(&TH_REQ, SUITE_OPAQUE, 1),                  // admin intent
        ] {
            assert_eq!(
                login(&f, PW, &client_ctx, &host_ctx, ids, ids).unwrap_err(),
                AuthError::Rejected,
            );
        }
    }

    /// `identifiers` bind the record to one device key and one host key.
    #[test]
    fn an_identifier_mismatch_is_rejected() {
        let f = fixture();
        let ctx = context(&TH_REQ, SUITE_OPAQUE, INTENT_SESSION);
        let other_device = [0xEE; 32];
        let other_host = [0xFF; 32];
        for bad in [
            identifiers(&other_device, &HOST_PK),
            identifiers(&CLIENT_PK, &other_host),
        ] {
            assert_eq!(
                login(&f, PW, &ctx, &ctx, bad, bad).unwrap_err(),
                AuthError::Rejected
            );
        }
    }

    #[test]
    fn malformed_wire_messages_are_reported_as_bad_messages() {
        let f = fixture();
        let ctx = context(&TH_REQ, SUITE_OPAQUE, INTENT_SESSION);
        let ids = identifiers(&CLIENT_PK, &HOST_PK);
        // `.err()` rather than `unwrap_err()`: the Ok half carries `HostLogin`,
        // which holds `ServerLogin` and is deliberately not `Debug`.
        assert_eq!(
            HostLogin::start(
                &f.setup,
                &parse_record(&f.record).unwrap(),
                &[0u8; sizes::KE1],
                &CLIENT_PK,
                &ctx,
                ids,
            )
            .err(),
            Some(AuthError::BadMessage)
        );
        assert_eq!(parse_record(&[0u8; 8]).unwrap_err(), AuthError::BadMessage);
        assert_eq!(
            parse_server_setup(&[0u8; 8]).unwrap_err(),
            AuthError::BadMessage
        );
    }

    /// The §B.8.4.3 schedule: deterministic, domain-separated, and every input
    /// actually reaches the output.
    #[test]
    fn the_key_schedule_is_deterministic_and_domain_separated() {
        let key = [7u8; 64];
        let st = session_token(&key, &TH_RESP);
        let ck = confirm_key(&key, &TH_RESP);
        let tc = token_confirm(&ck, &TH_RESP);
        let fp = proof_fp(&key);

        assert_eq!(session_token(&key, &TH_RESP).as_ref(), st.as_ref());
        assert_eq!(confirm_key(&key, &TH_RESP).as_ref(), ck.as_ref());
        assert_eq!(token_confirm(&ck, &TH_RESP), tc);
        assert_eq!(proof_fp(&key), fp);

        // Distinct salts ⇒ the token, the confirm key and the fingerprint are
        // independent values, never one another's prefix.
        assert_ne!(st.as_ref(), ck.as_ref());
        assert_ne!(&st[..8], &fp[..]);
        assert_ne!(&ck[..], &tc[..]);

        // Every input moves every output.
        let other_key = [8u8; 64];
        assert_ne!(session_token(&other_key, &TH_RESP).as_ref(), st.as_ref());
        assert_ne!(session_token(&key, &[0x55; 32]).as_ref(), st.as_ref());
        assert_ne!(confirm_key(&key, &[0x55; 32]).as_ref(), ck.as_ref());
        assert_ne!(token_confirm(&ck, &[0x55; 32]), tc);
        assert_ne!(proof_fp(&other_key), fp);
    }

    #[test]
    fn context_is_the_documented_byte_string() {
        let c = context(&TH_REQ, SUITE_OPAQUE, 1);
        assert_eq!(&c[..26], b"tornect/v1/unattended/ctx\0");
        assert_eq!(&c[26..58], &TH_REQ[..]);
        assert_eq!(c[58], SUITE_OPAQUE);
        assert_eq!(c[59], 1);
        assert_eq!(c.len(), 60);
    }

    /// The params test above only inspects the object. This proves the KSF is
    /// actually *in the loop*: a record registered under the suite KSF cannot be
    /// opened by a login that omits it (`ksf: None` ⇒ argon2's 19 MiB / t=2
    /// default), so a silent regression to the crate default cannot pass.
    #[test]
    fn the_suite_ksf_is_actually_applied_not_silently_defaulted() {
        let f = fixture();
        let ctx = context(&TH_REQ, SUITE_OPAQUE, INTENT_SESSION);
        let ids = identifiers(&CLIENT_PK, &HOST_PK);

        let (client, ke1) = ClientLogin::start(PW).unwrap();
        let (_host, ke2) = HostLogin::start(
            &f.setup,
            &parse_record(&f.record).unwrap(),
            &ke1,
            &CLIENT_PK,
            &ctx,
            ids,
        )
        .unwrap();
        // The same password and the same context, but the default KSF.
        let out = client.state.finish(
            &mut OpaqueRng,
            PW.as_bytes(),
            CredentialResponse::deserialize(&ke2).unwrap(),
            ClientLoginFinishParameters::new(Some(&ctx), ids, None),
        );
        assert!(
            out.is_err(),
            "a login without the suite KSF opened a record registered with it: \
             the KSF is not reaching the OPAQUE flow"
        );
    }

    #[test]
    fn the_suite_ksf_is_the_plan_constant_not_the_crate_default() {
        // 64 MiB / t=3 / p=1 (§B.8.4.4). `ksf: None` would silently be argon2's
        // 19 MiB / t=2 default and produce records this build cannot reproduce.
        assert_eq!(KSF_PARAMS, (64 * 1024, 3, 1));
        let k = ksf();
        assert_eq!(k.params().m_cost(), 64 * 1024);
        assert_eq!(k.params().t_cost(), 3);
        assert_eq!(k.params().p_cost(), 1);
    }
}
