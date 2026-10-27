//! The direct link's QUIC (design `direct` §6.5, §9.4; decisions M1-80,
//! M1-81): TLS 1.3 with RFC 7250 raw public keys pinned both ways, the
//! device keys signing through [`DeviceKeySigner`], no ALPN, no SNI, no
//! resumption and no 0-RTT, over the session socket ([`PunchSocket`]).
//!
//! - **Identity.** Each side presents its device key's
//!   `SubjectPublicKeyInfo` ([`spki`]) as its raw public key, signed by
//!   [`DeviceKeySigner`], which holds the zeroizing ed25519-dalek
//!   [`DeviceIdentity`]: ring never sees a private key and no PKCS#8 is
//!   built. The key is the one each side already pinned through Tor (the
//!   viewer the host's `SESSION_ACCEPT.quic_spki`, the host the paired
//!   device).
//! - **Pins.** [`PinnedVerifier`] accepts exactly one presented key, the
//!   peer's, both as a server verifier and as a client verifier; client
//!   authentication is mandatory, TLS 1.2 is refused.
//! - **Who accepts.** The controlled side [`accept`]s only a connection
//!   attempt whose source a probe round trip validated and the remote filter
//!   admits, and starts a handshake only for an attempt that also proved,
//!   through a QUIC Retry, that it receives at that source; it keeps
//!   accepting until one passes [`check_peer`], and only then turns its
//!   server configuration off. An off-path spoofer forging the validated
//!   address never sees the Retry, so its Initials, sent before, during or
//!   after the real dialler's, take no handshake slot and cannot lock the
//!   real dialler out. The controlling side [`dial`]s once.
//! - **Binding.** [`exporter`] derives the keying material the media `Bind`
//!   and `BindProof` MACs cover (design §6.6), so a connection is bound to
//!   the Tor-borne session token.
//! - **Closing.** A pin refusal by the peer's TLS closes the connection
//!   with a TLS alert, which [`is_crypto_close`] recognises (the viewer's
//!   one fallback after its commit point, decision M1-79). A host that
//!   refuses a `Bind` flushes its refusal first ([`refuse`]).
//!
//! The device key also signs Tornect envelopes. The two kinds of signed
//! message cannot be confused (design §9.4, `docs/research/quic.md` §3.5):
//! TLS 1.3 signs `0x20 × 64 ‖ "TLS 1.3, server CertificateVerify" | "TLS
//! 1.3, client CertificateVerify" ‖ 0x00 ‖ transcript hash` (RFC 8446
//! §4.4.3), whose first byte is a space, and every Tornect envelope
//! signature covers `"tornect/v1/sig/" ‖ …`, whose first byte is `t`.
//!
//! Nothing here logs. rustls writes both device keys at `trace` and quinn
//! writes addresses; both targets are in `QUIET_TARGETS` (decision M1-83).
//! No `Debug` here prints a key or an address, and no error carries one.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::client::Resumption;
use quinn::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use quinn::rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key};
use quinn::rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use quinn::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use quinn::rustls::server::{AlwaysResolvesServerRawPublicKeys, NoServerSessionStorage};
use quinn::rustls::sign::{CertifiedKey, Signer, SigningKey};
use quinn::rustls::{
    self, CertificateError, DigitallySignedStruct, DistinguishedName, PeerIncompatible,
    SignatureAlgorithm, SignatureScheme,
};
use quinn::{ConnectionError, IdleTimeout, VarInt};
use subtle::ConstantTimeEq;
use tornect_core::DeviceIdentity;
use zeroize::Zeroizing;

use crate::TornectRole;
use crate::addr::{RemoteFilter, canon, to_socket_family};
use crate::udp::PunchSocket;

/// The DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410 §4):
/// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused bits) }`.
/// The same bytes as `tornect-signal`'s `SPKI_PREFIX`, which builds
/// `SESSION_ACCEPT.quic_spki`.
pub const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The length of an Ed25519 `SubjectPublicKeyInfo`.
pub const SPKI_LEN: usize = 44;

/// The server name a dial passes to quinn. Never sent (SNI is off) and
/// never checked (the pin authenticates).
pub const SERVER_NAME: &str = "tornect";

/// The TLS exporter label of the session binding (RFC 5705 §4, RFC 8446
/// §7.5; design §6.6); the context is the session token.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-tornect/v1/session-binding";

/// How long a refusing host waits for its refusal to be acknowledged (or
/// the connection to close) before it closes the connection itself (design
/// §6.5).
pub const REFUSAL_FLUSH: Duration = Duration::from_millis(500);

/// A connection with nothing received for this long is dead (design §6.5).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// The keep-alive interval; it also keeps NAT state alive.
pub const KEEP_ALIVE: Duration = Duration::from_secs(2);

/// The round-trip time assumed before one is measured.
pub const INITIAL_RTT: Duration = Duration::from_millis(100);

/// The receive window of one stream.
pub const STREAM_WINDOW: u32 = 4 << 20;

/// The receive and send window of the whole connection.
pub const CONNECTION_WINDOW: u32 = 16 << 20;

/// How many connection attempts the controlled side's quinn holds before
/// it ignores more (`ServerConfig::max_incoming`).
pub const MAX_INCOMING: usize = 4;

/// The bytes quinn buffers for one connection attempt not yet accepted.
pub const INCOMING_BUFFER: u64 = 64 << 10;

/// How many handshakes [`accept`] runs at once. A further attempt is
/// ignored while they run; none is ever dropped for a newer one.
pub const MAX_PENDING_HANDSHAKES: usize = 4;

/// The bidirectional streams a viewer may open to the host: the media
/// stream. Design §6.5 gives 2 (media and services) once the services
/// stream rides the direct connection (design §6.7, step B10).
pub const HOST_STREAMS: u32 = 1;

/// The application close code of a connection that failed [`check_peer`];
/// its peer is not the device this side pinned, so no Tornect reason
/// applies.
pub const PEER_REFUSED: u32 = 0;

/// The `SubjectPublicKeyInfo` of an Ed25519 public key: the raw public key
/// each side presents and pins.
#[must_use]
pub fn spki(pk: &[u8; 32]) -> [u8; SPKI_LEN] {
    let mut out = [0; SPKI_LEN];
    out[..SPKI_PREFIX.len()].copy_from_slice(&SPKI_PREFIX);
    out[SPKI_PREFIX.len()..].copy_from_slice(pk);
    out
}

/// What can go wrong in this module. No message names an address or a key,
/// and no third-party error value is carried (decision M1-83).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum QuicError {
    /// The TLS or QUIC configuration could not be built (the crypto
    /// provider lacks what QUIC needs).
    #[error("the QUIC configuration could not be built")]
    Config,
    /// quinn could not start its endpoint on the session socket.
    #[error("the QUIC endpoint could not start")]
    Endpoint,
    /// quinn refused the dial before sending anything.
    #[error("the QUIC dial was refused")]
    Dial,
    /// The handshake failed; `crypto` when it ended with a TLS alert
    /// ([`is_crypto_close`]).
    #[error("the QUIC handshake failed")]
    Handshake {
        /// The handshake ended with a TLS alert.
        crypto: bool,
    },
    /// The connection completed but its peer is not the pinned device or
    /// address ([`check_peer`]).
    #[error("the QUIC peer is not the expected device or address")]
    Peer(PeerRefusal),
    /// The endpoint closed before a connection completed.
    #[error("the QUIC endpoint closed")]
    Closed,
    /// The TLS exporter refused the request.
    #[error("the QUIC keying material could not be exported")]
    Exporter,
}

/// Why [`check_peer`] refused a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRefusal {
    /// The peer did not present exactly the pinned raw public key.
    Key,
    /// The connection's remote address does not pass the remote filter.
    Address,
}

/// The device key as rustls's signing key (design §6.5): offers Ed25519
/// only and signs with the zeroizing ed25519-dalek key. The same value is
/// its own [`Signer`].
#[derive(Clone)]
pub struct DeviceKeySigner(Arc<DeviceIdentity>);

impl DeviceKeySigner {
    /// The signer of `identity`.
    #[must_use]
    pub fn new(identity: Arc<DeviceIdentity>) -> Self {
        Self(identity)
    }

    /// The device's public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

impl fmt::Debug for DeviceKeySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The identity's own `Debug` prints its device ID.
        f.debug_struct("DeviceKeySigner").finish_non_exhaustive()
    }
}

impl SigningKey for DeviceKeySigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(
            spki(&self.public_key_bytes()).to_vec(),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

impl Signer for DeviceKeySigner {
    /// PureEdDSA over `message` (RFC 8032; RFC 8446 §4.2.3: Ed25519 hashes
    /// internally).
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// Accepts exactly one raw public key, the peer's (design §6.5): as the
/// client's server verifier and as the server's client verifier. Client
/// authentication is mandatory; TLS 1.2 is refused; only Ed25519
/// signatures are accepted.
pub struct PinnedVerifier {
    peer_spki: [u8; SPKI_LEN],
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedVerifier {
    /// A verifier pinned to the device key `peer_pk`.
    #[must_use]
    pub fn new(peer_pk: &[u8; 32]) -> Self {
        Self {
            peer_spki: spki(peer_pk),
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }

    /// The presented chain is exactly the pinned key (compared in constant
    /// time).
    fn pinned(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> bool {
        intermediates.is_empty() && bool::from(end_entity.as_ref().ct_eq(&self.peer_spki[..]))
    }

    fn check(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), rustls::Error> {
        if self.pinned(end_entity, intermediates) {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    /// The `CertificateVerify` signature, checked against the pinned key
    /// itself rather than the presented one.
    fn signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.check(cert, &[])?;
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(rustls::Error::PeerIncompatible(
                PeerIncompatible::NoSignatureSchemesInCommon,
            ));
        }
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(&self.peer_spki[..]),
            dss,
            &self.algorithms,
        )
    }
}

impl fmt::Debug for PinnedVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedVerifier").finish_non_exhaustive()
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for PinnedVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// This side's QUIC identity: the device key as a raw public key, and the
/// pinned configurations built from it.
#[derive(Clone)]
pub struct QuicIdentity {
    key: Arc<CertifiedKey>,
    public: [u8; 32],
}

impl QuicIdentity {
    /// The QUIC identity of this device.
    #[must_use]
    pub fn new(identity: Arc<DeviceIdentity>) -> Self {
        let signer = DeviceKeySigner::new(identity);
        let public = signer.public_key_bytes();
        Self::with_key(Arc::new(signer), public)
    }

    /// The identity of an arbitrary signing key presenting `public` (tests
    /// observe what is signed through it).
    pub(crate) fn with_key(signer: Arc<dyn SigningKey>, public: [u8; 32]) -> Self {
        let raw = CertificateDer::from(spki(&public).to_vec());
        Self {
            key: Arc::new(CertifiedKey::new(vec![raw], signer)),
            public,
        }
    }

    /// The device public key this side presents.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// The controlled side's configuration (design §6.5): TLS 1.3, this
    /// key served as a raw public key, the client's key pinned to `peer_pk`
    /// and mandatory, no ALPN, no tickets, no 0-RTT; no migration, at most
    /// [`MAX_INCOMING`] attempts of [`INCOMING_BUFFER`] bytes each, no
    /// address validation tokens.
    ///
    /// # Errors
    ///
    /// [`QuicError::Config`] if the crypto provider lacks what QUIC needs
    /// (never with ring).
    pub fn server_config(
        &self,
        peer_pk: &[u8; 32],
        role: TornectRole,
    ) -> Result<quinn::ServerConfig, QuicError> {
        let tls = server_tls(Arc::clone(&self.key), peer_pk)?;
        let crypto = QuicServerConfig::try_from(tls).map_err(|_| QuicError::Config)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let mut tokens = quinn::ValidationTokenConfig::default();
        tokens.sent(0).log(Arc::new(quinn::NoneTokenLog));
        config
            .transport_config(Arc::new(transport(role)))
            .validation_token_config(tokens)
            .migration(false)
            .max_incoming(MAX_INCOMING)
            .incoming_buffer_size(INCOMING_BUFFER)
            .incoming_buffer_size_total(INCOMING_BUFFER * MAX_INCOMING as u64);
        Ok(config)
    }

    /// The controlling side's configuration (design §6.5): TLS 1.3, the
    /// server's key pinned to `peer_pk`, this key offered as a raw public
    /// key, no ALPN, no SNI, no resumption, no early data, no address
    /// validation tokens kept.
    ///
    /// # Errors
    ///
    /// As [`server_config`](Self::server_config).
    pub fn client_config(
        &self,
        peer_pk: &[u8; 32],
        role: TornectRole,
    ) -> Result<quinn::ClientConfig, QuicError> {
        let tls = client_tls(Arc::clone(&self.key), peer_pk)?;
        let crypto = QuicClientConfig::try_from(tls).map_err(|_| QuicError::Config)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config
            .transport_config(Arc::new(transport(role)))
            .token_store(Arc::new(quinn::NoneTokenStore));
        Ok(config)
    }
}

impl fmt::Debug for QuicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicIdentity").finish_non_exhaustive()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The rustls side of [`QuicIdentity::server_config`].
pub(crate) fn server_tls(
    key: Arc<CertifiedKey>,
    peer_pk: &[u8; 32],
) -> Result<rustls::ServerConfig, QuicError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| QuicError::Config)?
        .with_client_cert_verifier(Arc::new(PinnedVerifier::new(peer_pk)))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(key)));
    tls.alpn_protocols = Vec::new();
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    tls.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(tls)
}

/// The rustls side of [`QuicIdentity::client_config`].
pub(crate) fn client_tls(
    key: Arc<CertifiedKey>,
    peer_pk: &[u8; 32],
) -> Result<rustls::ClientConfig, QuicError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| QuicError::Config)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier::new(peer_pk)))
        .with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(key),
        ));
    tls.alpn_protocols = Vec::new();
    tls.resumption = Resumption::disabled();
    tls.enable_early_data = false;
    tls.enable_sni = false;
    Ok(tls)
}

/// quinn's endpoint configuration on both sides: the QUIC bit is never
/// greased, so every QUIC packet has `0x40` set and never looks like a
/// probe (design §6.2, §6.3).
#[must_use]
pub fn endpoint_config() -> quinn::EndpointConfig {
    let mut config = quinn::EndpointConfig::default();
    config.grease_quic_bit(false);
    config
}

/// The transport parameters of `role` (design §6.5): idle 10 s, keep-alive
/// 2 s, initial RTT 100 ms, no spin bit, no datagrams, no unidirectional
/// streams; the viewer opens the bidirectional streams ([`HOST_STREAMS`]
/// to the host, none the other way); 4 MiB per stream, 16 MiB per
/// connection.
#[must_use]
pub fn transport(role: TornectRole) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    let bidi = match role {
        TornectRole::Host => HOST_STREAMS,
        TornectRole::Viewer => 0,
    };
    transport
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(
            u32::try_from(IDLE_TIMEOUT.as_millis()).unwrap_or(u32::MAX),
        ))))
        .keep_alive_interval(Some(KEEP_ALIVE))
        .initial_rtt(INITIAL_RTT)
        .allow_spin(false)
        .datagram_receive_buffer_size(None)
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .max_concurrent_bidi_streams(VarInt::from_u32(bidi))
        .stream_receive_window(VarInt::from_u32(STREAM_WINDOW))
        .receive_window(VarInt::from_u32(CONNECTION_WINDOW))
        .send_window(u64::from(CONNECTION_WINDOW));
    transport
}

/// quinn's endpoint on the session socket. `server` is the controlled
/// side's configuration; the controlling side has none.
///
/// # Errors
///
/// [`QuicError::Endpoint`] if quinn cannot start (outside a tokio runtime,
/// or the socket has no local address).
pub fn endpoint(
    socket: &Arc<PunchSocket>,
    server: Option<quinn::ServerConfig>,
) -> Result<quinn::Endpoint, QuicError> {
    quinn::Endpoint::new_with_abstract_socket(
        endpoint_config(),
        server,
        Arc::clone(socket) as Arc<dyn quinn::AsyncUdpSocket>,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|_| QuicError::Endpoint)
}

/// After a handshake (design §6.5): the peer presented exactly the pinned
/// key `peer_pk` (compared in constant time), and the connection's remote
/// address passes `filter`.
///
/// # Errors
///
/// The first check that fails.
pub fn check_peer(
    conn: &quinn::Connection,
    peer_pk: &[u8; 32],
    filter: &RemoteFilter,
) -> Result<(), PeerRefusal> {
    let pinned = spki(peer_pk);
    let presented = conn
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok());
    let key = match presented.as_deref().map(Vec::as_slice) {
        Some([only]) => bool::from(only.as_ref().ct_eq(&pinned[..])),
        _ => false,
    };
    if !key {
        return Err(PeerRefusal::Key);
    }
    if !filter.admit(canon(conn.remote_address())) {
        return Err(PeerRefusal::Address);
    }
    Ok(())
}

/// The controlling side's one dial (design §6.5): to `to` in the socket's
/// family, then [`check_peer`]. A connection that fails the check is
/// closed.
///
/// # Errors
///
/// [`QuicError::Dial`], [`QuicError::Handshake`] or [`QuicError::Peer`].
pub async fn dial(
    endpoint: &quinn::Endpoint,
    config: quinn::ClientConfig,
    to: SocketAddr,
    dual_stack: bool,
    peer_pk: &[u8; 32],
    filter: &RemoteFilter,
) -> Result<quinn::Connection, QuicError> {
    let connecting = endpoint
        .connect_with(config, to_socket_family(canon(to), dual_stack), SERVER_NAME)
        .map_err(|_| QuicError::Dial)?;
    let conn = connecting.await.map_err(|e| QuicError::Handshake {
        crypto: is_crypto_close(&e),
    })?;
    if let Err(refusal) = check_peer(&conn, peer_pk, filter) {
        conn.close(VarInt::from_u32(PEER_REFUSED), b"");
        return Err(QuicError::Peer(refusal));
    }
    Ok(conn)
}

/// The controlled side's accept (design §6.5). A connection attempt is
/// taken in three gates:
///
/// 1. its source is `validated` (a probe round trip) and passes `filter`;
///    anything else is ignored, which sends nothing;
/// 2. it proved it receives at that source: an attempt without a Retry
///    token is answered with a QUIC Retry (RFC 9000 §8.1.2; a datagram
///    smaller than the Initial that drew it, to the validated source only),
///    and only the dialler's next Initial, which carries the token, goes on;
/// 3. fewer than [`MAX_PENDING_HANDSHAKES`] handshakes are running;
///    otherwise it is ignored, and the dialler's retransmission tries again.
///
/// Handshakes run concurrently until one passes [`check_peer`]; only then
/// is the endpoint's server configuration turned off and every other
/// handshake dropped. A handshake that fails or stalls leaves its slot at
/// the latest after the idle timeout; none is replaced by a newer attempt.
///
/// So an off-path spoofer that forges Initials from the validated address
/// cannot lock out the real dialler, whether it sends them before, during
/// or after the real handshake: the Retry and every reply go to the real
/// peer, so a spoofed attempt never gets past gate 2 and never takes a
/// slot. Only a sender that receives at a validated address (the peer, or
/// an on-path attacker, who can block the path anyway) can fill the slots.
///
/// Cancel safe: dropping the future drops the handshakes in progress and
/// loses no connection attempt quinn still holds.
///
/// # Errors
///
/// [`QuicError::Closed`] once the endpoint closes.
pub async fn accept(
    endpoint: &quinn::Endpoint,
    validated: impl Fn(SocketAddr) -> bool,
    peer_pk: &[u8; 32],
    filter: &RemoteFilter,
) -> Result<quinn::Connection, QuicError> {
    accept_noting(endpoint, validated, peer_pk, filter, || {}).await
}

/// [`accept`], calling `refused` for each handshake that ended with a TLS
/// alert ([`is_crypto_close`]): this side's pin refused the dialler's key,
/// or the dialler refused this side's. A direct link counts them, so the
/// host can say a pin refused the viewer (design §6.5 "Pin refused by the
/// host's TLS"); nothing about the dialler is passed on.
///
/// # Errors
///
/// [`QuicError::Closed`] once the endpoint closes.
pub async fn accept_noting(
    endpoint: &quinn::Endpoint,
    validated: impl Fn(SocketAddr) -> bool,
    peer_pk: &[u8; 32],
    filter: &RemoteFilter,
    refused: impl Fn(),
) -> Result<quinn::Connection, QuicError> {
    let mut pending: Vec<Pin<Box<quinn::Connecting>>> = Vec::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    return Err(QuicError::Closed);
                };
                let from = canon(incoming.remote_address());
                if !(validated(from) && filter.admit(from)) {
                    incoming.ignore();
                    continue;
                }
                if !incoming.remote_address_validated() {
                    // quinn guarantees `may_retry()` for an attempt that is
                    // not validated; were the Retry refused, it is ignored.
                    if let Err(refused) = incoming.retry() {
                        refused.into_incoming().ignore();
                    }
                    continue;
                }
                if pending.len() >= MAX_PENDING_HANDSHAKES {
                    incoming.ignore();
                    continue;
                }
                if let Ok(connecting) = incoming.accept() {
                    pending.push(Box::pin(connecting));
                }
            }
            done = first_handshake(&mut pending), if !pending.is_empty() => {
                let conn = match done {
                    Ok(conn) => conn,
                    Err(error) => {
                        if is_crypto_close(&error) {
                            refused();
                        }
                        continue;
                    }
                };
                if check_peer(&conn, peer_pk, filter).is_ok() {
                    endpoint.set_server_config(None);
                    return Ok(conn);
                }
                conn.close(VarInt::from_u32(PEER_REFUSED), b"");
            }
        }
    }
}

/// The first of `pending` to finish, removed from it.
async fn first_handshake(
    pending: &mut Vec<Pin<Box<quinn::Connecting>>>,
) -> Result<quinn::Connection, ConnectionError> {
    std::future::poll_fn(|cx| {
        for i in 0..pending.len() {
            if let Poll::Ready(done) = pending[i].as_mut().poll(cx) {
                pending.remove(i);
                return Poll::Ready(done);
            }
        }
        Poll::Pending
    })
    .await
}

/// The keying material of the session binding (design §6.6): 32 bytes
/// exported under [`EXPORTER_LABEL`] with the session token as context,
/// equal on both ends of one connection and different on any other.
///
/// # Errors
///
/// [`QuicError::Exporter`] if the handshake has not completed.
pub fn exporter(
    conn: &quinn::Connection,
    session_token: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, QuicError> {
    let mut ekm = Zeroizing::new([0; 32]);
    conn.export_keying_material(ekm.as_mut_slice(), EXPORTER_LABEL, session_token)
        .map_err(|_| QuicError::Exporter)?;
    Ok(ekm)
}

/// Whether a connection ended with a TLS alert (QUIC `CRYPTO_ERROR`, codes
/// 0x0100–0x01FF, RFC 9001 §4.8), sent by the peer or raised here. A peer
/// that refused this side's key closes this way, and since TLS 1.3 lets the
/// client finish before the server checks the client's key, the viewer may
/// see it only after its handshake completed (design §6.5).
#[must_use]
pub fn is_crypto_close(error: &ConnectionError) -> bool {
    let code = match error {
        ConnectionError::ConnectionClosed(close) => close.error_code,
        ConnectionError::TransportError(error) => error.code,
        _ => return false,
    };
    (0x100..=0x1ff).contains(&u64::from(code))
}

/// The host's refusal on the direct path (design §6.5): writes `frame` (an
/// encoded `BindRefused`), finishes the stream, waits up to
/// [`REFUSAL_FLUSH`] for the viewer to acknowledge it or the connection to
/// close, then closes the connection with `code` (a `tornect_proto::reason`
/// code), so the viewer reads the reason before the close.
///
/// Bounded by [`REFUSAL_FLUSH`], and the close does not depend on the
/// future finishing: a caller may race it against the kill or stop future
/// (design §9.1 invariant 10, kill liveness) and drop it, and dropping it
/// mid-flush closes the connection with `code` at once. The flush is then
/// cut short, so the viewer may see the close without the frame; it still
/// ends with `code`.
pub async fn refuse(
    conn: &quinn::Connection,
    mut send: quinn::SendStream,
    frame: &[u8],
    code: u16,
) {
    let _close = CloseOnDrop { conn, code };
    let flush = async {
        if send.write_all(frame).await.is_err() || send.finish().is_err() {
            return;
        }
        tokio::select! {
            _ = send.stopped() => {}
            _ = conn.closed() => {}
        }
    };
    let _ = tokio::time::timeout(REFUSAL_FLUSH, flush).await;
}

/// Closes `conn` with `code` when dropped: at the end of [`refuse`], or
/// when its future is dropped before then.
struct CloseOnDrop<'a> {
    conn: &'a quinn::Connection,
    code: u16,
}

impl Drop for CloseOnDrop<'_> {
    fn drop(&mut self) {
        self.conn.close(VarInt::from(self.code), b"");
    }
}

#[cfg(test)]
mod tests;
