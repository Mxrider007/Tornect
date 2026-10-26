use super::*;

use std::collections::VecDeque;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, Weak};
use std::task::{Context, Waker};

use netdev::ipnet::IpNet;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use crate::addr::Scope;
use crate::env::{NetEnv, RealNet};
use crate::socket::bind_media_socket;
use crate::udp::{BoundUdp, ProbeGate};

const TOKEN: [u8; 32] = [0x42; 32];

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

fn device(seed: u8) -> Arc<DeviceIdentity> {
    Arc::new(DeviceIdentity::from_seed(&[seed; 32]))
}

fn pk(seed: u8) -> [u8; 32] {
    device(seed).verifying_key().to_bytes()
}

fn identity(seed: u8) -> QuicIdentity {
    QuicIdentity::new(device(seed))
}

const HOST: u8 = 1;
const VIEWER: u8 = 2;
const STRANGER: u8 = 3;

/// The remote filter of a side on 192.168.1.0/24 (same-site scope).
fn lan_filter(dual_stack: bool) -> RemoteFilter {
    RemoteFilter {
        scope: Scope::SameSite,
        on_link: vec!["192.168.1.0/24".parse::<IpNet>().expect("a prefix")],
        own_ula48: None,
        local_nets: Vec::new(),
        have_v4: true,
        have_v6: false,
        dual_stack,
        global_families: (false, false),
        own: Vec::new(),
        admit_loopback: false,
    }
}

/// The remote filter of a side on another network: 192.168.1.0/24 is not
/// on its site.
fn elsewhere_filter() -> RemoteFilter {
    RemoteFilter {
        on_link: vec!["10.0.0.0/8".parse::<IpNet>().expect("a prefix")],
        ..lan_filter(false)
    }
}

/// The remote filter of a test environment on loopback.
fn loopback_filter(dual_stack: bool) -> RemoteFilter {
    RemoteFilter {
        scope: Scope::SameSite,
        on_link: Vec::new(),
        own_ula48: None,
        local_nets: Vec::new(),
        have_v4: true,
        have_v6: false,
        dual_stack,
        global_families: (false, false),
        own: Vec::new(),
        admit_loopback: true,
    }
}

/// One datagram on the in-memory wire.
#[derive(Debug, Clone)]
struct Datagram {
    from: SocketAddr,
    to: SocketAddr,
    bytes: Vec<u8>,
}

/// An in-memory network: every socket registered at its address, and a log
/// of every datagram (after any spoofing, before delivery).
#[derive(Default)]
struct Hub {
    sockets: Mutex<Vec<(SocketAddr, Weak<Mem>)>>,
    wire: Mutex<Vec<Datagram>>,
}

impl Hub {
    fn new() -> Arc<Self> {
        Arc::default()
    }

    fn deliver(&self, from: SocketAddr, to: SocketAddr, bytes: Vec<u8>) {
        self.wire.lock().expect("the wire").push(Datagram {
            from,
            to,
            bytes: bytes.clone(),
        });
        let target = self
            .sockets
            .lock()
            .expect("the sockets")
            .iter()
            .find(|(at, _)| *at == to)
            .and_then(|(_, socket)| socket.upgrade());
        if let Some(target) = target
            && !target.deaf.load(Ordering::SeqCst)
        {
            target.arrive(from, bytes);
        }
    }

    fn wire(&self) -> Vec<Datagram> {
        self.wire.lock().expect("the wire").clone()
    }
}

/// Whether a datagram is a QUIC Retry packet (RFC 9000 §17.2.5: a long
/// header of type 3; the type bits are never header-protected).
fn is_retry(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|b| b & 0xb0 == 0xb0)
}

/// What a [`Mem`] holds back (in flight, delayed) until [`Mem::release`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hold {
    /// Nothing.
    Nothing,
    /// Every arriving datagram but a Retry: the peer's replies are in
    /// flight.
    Arriving,
    /// Nothing until a datagram other than a Retry arrives (the server's
    /// first flight), then every datagram this socket sends: its answer
    /// (the client's `Finished`) is in flight.
    SentOnceAnswered,
    /// Every datagram this socket sends.
    Sent,
}

/// An in-memory session socket (one segment per datagram). A dual-stack
/// one reports IPv4 peers v4-mapped and refuses a plain IPv4 destination
/// with `InvalidInput`, as Windows and macOS do; an IPv4 one refuses any
/// IPv6 destination.
struct Mem {
    hub: Arc<Hub>,
    addr: SocketAddr,
    dual_stack: bool,
    spoof: Mutex<Option<SocketAddr>>,
    deaf: AtomicBool,
    hold: Mutex<Hold>,
    held_in: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
    held_out: Mutex<Vec<Datagram>>,
    inbox: Mutex<VecDeque<(SocketAddr, Vec<u8>)>>,
    waker: Mutex<Option<Waker>>,
    refused: AtomicUsize,
}

impl Mem {
    fn new(hub: &Arc<Hub>, addr: SocketAddr, dual_stack: bool) -> Arc<Self> {
        let mem = Arc::new(Self {
            hub: Arc::clone(hub),
            addr,
            dual_stack,
            spoof: Mutex::new(None),
            deaf: AtomicBool::new(false),
            hold: Mutex::new(Hold::Nothing),
            held_in: Mutex::default(),
            held_out: Mutex::default(),
            inbox: Mutex::default(),
            waker: Mutex::default(),
            refused: AtomicUsize::new(0),
        });
        hub.sockets
            .lock()
            .expect("the sockets")
            .push((addr, Arc::downgrade(&mem)));
        mem
    }

    fn bound(self: &Arc<Self>) -> BoundUdp {
        BoundUdp {
            inner: Arc::clone(self) as Arc<dyn AsyncUdpSocket>,
            dual_stack: self.dual_stack,
            errors: Arc::default(),
        }
    }

    fn hold(&self, hold: Hold) {
        *self.hold.lock().expect("the hold") = hold;
    }

    /// A datagram from the wire, unless it is held back.
    fn arrive(&self, from: SocketAddr, bytes: Vec<u8>) {
        {
            let mut hold = self.hold.lock().expect("the hold");
            if !is_retry(&bytes) {
                match *hold {
                    Hold::Arriving => {
                        self.held_in.lock().expect("held").push((from, bytes));
                        return;
                    }
                    Hold::SentOnceAnswered => *hold = Hold::Sent,
                    Hold::Nothing | Hold::Sent => {}
                }
            }
        }
        self.inbox
            .lock()
            .expect("the inbox")
            .push_back((from, bytes));
        if let Some(waker) = self.waker.lock().expect("the waker").take() {
            waker.wake();
        }
    }

    /// Ends the hold: what arrived is received and what was sent leaves, in
    /// their order.
    fn release(&self) {
        self.hold(Hold::Nothing);
        let arrived = std::mem::take(&mut *self.held_in.lock().expect("held"));
        for (from, bytes) in arrived {
            self.arrive(from, bytes);
        }
        let sent = std::mem::take(&mut *self.held_out.lock().expect("held"));
        for datagram in sent {
            self.hub.deliver(datagram.from, datagram.to, datagram.bytes);
        }
    }

    /// How many datagrams are held back, (arrived, sent).
    fn held(&self) -> (usize, usize) {
        (
            self.held_in.lock().expect("held").len(),
            self.held_out.lock().expect("held").len(),
        )
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl fmt::Debug for Mem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mem").finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for Mem {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if self.dual_stack == transmit.destination.is_ipv4() {
            self.refused.fetch_add(1, Ordering::SeqCst);
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let from = self.spoof.lock().expect("the spoof").unwrap_or(self.addr);
        let to = canon(transmit.destination);
        let size = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        let held = *self.hold.lock().expect("the hold") == Hold::Sent;
        for segment in transmit.contents.chunks(size) {
            if held {
                self.held_out.lock().expect("held").push(Datagram {
                    from,
                    to,
                    bytes: segment.to_vec(),
                });
            } else {
                self.hub.deliver(from, to, segment.to_vec());
            }
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut inbox = self.inbox.lock().expect("the inbox");
        if inbox.is_empty() {
            *self.waker.lock().expect("the waker") = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            let Some((from, data)) = inbox.pop_front() else {
                break;
            };
            let len = data.len().min(bufs[n].len());
            bufs[n][..len].copy_from_slice(&data[..len]);
            meta[n] = RecvMeta {
                addr: to_socket_family(from, self.dual_stack),
                len,
                stride: len,
                ..RecvMeta::default()
            };
            n += 1;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        let ip = if self.dual_stack {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        Ok(SocketAddr::new(ip, self.addr.port()))
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// One side of a session on the in-memory network.
struct Side {
    addr: SocketAddr,
    mem: Arc<Mem>,
    punch: Arc<PunchSocket>,
    quic: QuicIdentity,
    seed: u8,
}

impl Side {
    fn new(hub: &Arc<Hub>, at: &str, dual_stack: bool, seed: u8) -> Self {
        Self::with_identity(hub, at, dual_stack, seed, identity(seed))
    }

    fn with_identity(
        hub: &Arc<Hub>,
        at: &str,
        dual_stack: bool,
        seed: u8,
        quic: QuicIdentity,
    ) -> Self {
        let addr = addr(at);
        let mem = Mem::new(hub, addr, dual_stack);
        let (punch, _tees) = PunchSocket::new(mem.bound(), ProbeGate::new());
        Self {
            addr,
            mem,
            punch,
            quic,
            seed,
        }
    }

    /// The probe round trip with `peer` validated it.
    fn validate(&self, peer: &Self) {
        assert!(self.punch.gate().admit(peer.addr));
    }

    fn filter(&self) -> RemoteFilter {
        lan_filter(self.mem.dual_stack)
    }

    /// The controlled side's endpoint, pinned to `peer`.
    fn server(&self, peer: &Self, role: TornectRole) -> quinn::Endpoint {
        let config = self
            .quic
            .server_config(&pk(peer.seed), role)
            .expect("a server config");
        endpoint(&self.punch, Some(config)).expect("an endpoint")
    }

    /// The controlling side's endpoint.
    fn client(&self) -> quinn::Endpoint {
        endpoint(&self.punch, None).expect("an endpoint")
    }

    async fn dial(
        &self,
        endpoint: &quinn::Endpoint,
        peer: &Self,
        role: TornectRole,
    ) -> Result<quinn::Connection, QuicError> {
        let config = self
            .quic
            .client_config(&pk(peer.seed), role)
            .expect("a client config");
        dial(
            endpoint,
            config,
            peer.addr,
            self.mem.dual_stack,
            &pk(peer.seed),
            &self.filter(),
        )
        .await
    }

    /// Accepts on `endpoint` in a task, `peer` pinned and validated by the
    /// gate.
    fn accept_task(
        &self,
        endpoint: &quinn::Endpoint,
        peer: &Self,
    ) -> tokio::task::JoinHandle<Result<quinn::Connection, QuicError>> {
        let endpoint = endpoint.clone();
        let gate = self.punch.gate().clone();
        let peer_pk = pk(peer.seed);
        let filter = self.filter();
        tokio::spawn(
            async move { accept(&endpoint, |from| gate.admits(from), &peer_pk, &filter).await },
        )
    }
}

/// A whole session's worth of a direct link, in memory: the controlled
/// side accepts, the controlling side dials once.
async fn connect(
    controlled: &Side,
    controlled_role: TornectRole,
    controlling: &Side,
    controlling_role: TornectRole,
) -> (
    quinn::Endpoint,
    quinn::Connection,
    quinn::Endpoint,
    quinn::Connection,
) {
    controlled.validate(controlling);
    controlling.validate(controlled);
    let server = controlled.server(controlling, controlled_role);
    let accepting = controlled.accept_task(&server, controlling);
    let client = controlling.client();
    let dialled = controlling
        .dial(&client, controlled, controlling_role)
        .await
        .expect("the dial");
    let accepted = tokio::time::timeout(Duration::from_secs(5), accepting)
        .await
        .expect("the accept within 5 s")
        .expect("the accept task")
        .expect("the accepted connection");
    (server, accepted, client, dialled)
}

/// A `CertificateVerify` body as it arrives on the wire. rustls builds the
/// type only from the wire; its hidden codec is the one way to make one here
/// (rustls is pinned to one version, and only tests use it).
fn dss(scheme: SignatureScheme, signature: &[u8]) -> DigitallySignedStruct {
    use quinn::rustls::internal::msgs::codec::Codec as _;
    let mut bytes = scheme.to_array().to_vec();
    bytes.extend(u16::try_from(signature.len()).expect("short").to_be_bytes());
    bytes.extend(signature);
    DigitallySignedStruct::read_bytes(&bytes).expect("a signed struct")
}

fn handshake_data(conn: &quinn::Connection) -> quinn::crypto::rustls::HandshakeData {
    *conn
        .handshake_data()
        .expect("handshake data")
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .expect("rustls handshake data")
}

fn presented(conn: &quinn::Connection) -> Vec<CertificateDer<'static>> {
    *conn
        .peer_identity()
        .expect("a peer identity")
        .downcast::<Vec<CertificateDer<'static>>>()
        .expect("raw public keys")
}

/// The RFC 8410 §10.1 example key encodes to the example's SPKI, which is
/// also what rustls derives and what the device signer presents.
#[test]
fn spki_is_the_rfc8410_encoding() {
    let example: [u8; 32] = [
        0x19, 0xbf, 0x44, 0x09, 0x69, 0x84, 0xcd, 0xfe, 0x85, 0x41, 0xba, 0xc1, 0x67, 0xdc, 0x3b,
        0x96, 0xc8, 0x50, 0x86, 0xaa, 0x30, 0xb6, 0xb6, 0xcb, 0x0c, 0x5c, 0x38, 0xad, 0x70, 0x31,
        0x66, 0xe1,
    ];
    let der = spki(&example);
    assert_eq!(der.len(), SPKI_LEN);
    assert_eq!(der[..12], SPKI_PREFIX);
    assert_eq!(der[12..], example);
    assert_eq!(
        rustls::sign::public_key_to_spki(&rustls::pki_types::alg_id::ED25519, example).as_ref(),
        &der[..]
    );
    let signer = DeviceKeySigner::new(device(HOST));
    assert_eq!(signer.public_key_bytes(), pk(HOST));
    assert_eq!(
        SigningKey::public_key(&signer).expect("an SPKI").as_ref(),
        &spki(&pk(HOST))[..]
    );
    assert_eq!(identity(HOST).public_key(), pk(HOST));
}

/// The device signer offers Ed25519 only, and ring verifies what the
/// ed25519-dalek key signs (design §12.1 "`DeviceKeySigner` signatures
/// verify").
#[test]
fn device_key_signatures_verify_with_ring() {
    let signer = DeviceKeySigner::new(device(HOST));
    assert_eq!(SigningKey::algorithm(&signer), SignatureAlgorithm::ED25519);
    assert!(
        signer
            .choose_scheme(&[
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256
            ])
            .is_none(),
        "only Ed25519 is offered"
    );
    let chosen = signer
        .choose_scheme(&[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ])
        .expect("Ed25519");
    assert_eq!(chosen.scheme(), SignatureScheme::ED25519);
    let message = b"TLS 1.3, server CertificateVerify";
    let signature = chosen.sign(message).expect("a signature");
    assert_eq!(signature.len(), 64);
    let algorithms = rustls::crypto::ring::default_provider().signature_verification_algorithms;
    let der = spki(&pk(HOST));
    let verify = |message: &[u8], signature: Vec<u8>| {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(&der[..]),
            &dss(SignatureScheme::ED25519, &signature),
            &algorithms,
        )
    };
    assert!(verify(message, signature.clone()).is_ok());
    assert!(verify(b"another message", signature.clone()).is_err());
    let mut flipped = signature;
    flipped[0] ^= 1;
    assert!(verify(message, flipped).is_err());
}

/// The verifier takes exactly the pinned key, alone, in both roles, and
/// only with a `CertificateVerify` signature that key made over the
/// transcript; it refuses TLS 1.2 and any scheme but Ed25519, and requires
/// a client key.
#[test]
fn the_pinned_verifier_accepts_only_its_key() {
    let verifier = PinnedVerifier::new(&pk(VIEWER));
    let pinned = CertificateDer::from(spki(&pk(VIEWER)).to_vec());
    let other = CertificateDer::from(spki(&pk(STRANGER)).to_vec());
    let short = CertificateDer::from(spki(&pk(VIEWER))[..43].to_vec());
    let mut longer = spki(&pk(VIEWER)).to_vec();
    longer.push(0);
    let longer = CertificateDer::from(longer);
    let name = ServerName::try_from(SERVER_NAME).expect("a name");
    let now = UnixTime::now();

    assert!(
        verifier
            .verify_server_cert(&pinned, &[], &name, &[], now)
            .is_ok()
    );
    assert!(verifier.verify_client_cert(&pinned, &[], now).is_ok());
    for refused in [&other, &short, &longer] {
        assert!(
            verifier
                .verify_server_cert(refused, &[], &name, &[], now)
                .is_err()
        );
        assert!(verifier.verify_client_cert(refused, &[], now).is_err());
    }
    let chain = [other.clone()];
    assert!(
        verifier
            .verify_server_cert(&pinned, &chain, &name, &[], now)
            .is_err(),
        "a chain is not a raw public key"
    );
    assert!(verifier.verify_client_cert(&pinned, &chain, now).is_err());

    let signer = DeviceKeySigner::new(device(VIEWER));
    let message = b"handshake transcript";
    let signature = signer.sign(message).expect("a signature");
    let signed = dss(SignatureScheme::ED25519, &signature);
    assert!(
        ServerCertVerifier::verify_tls13_signature(&verifier, message, &pinned, &signed).is_ok()
    );
    assert!(
        ClientCertVerifier::verify_tls13_signature(&verifier, message, &pinned, &signed).is_ok()
    );
    assert!(
        ServerCertVerifier::verify_tls13_signature(&verifier, message, &other, &signed).is_err(),
        "a signature is checked against the pinned key only"
    );
    // Possession: the pinned key is public (it travels in `PAIR_ACCEPT` and
    // `SESSION_ACCEPT.quic_spki`), so presenting it proves nothing without
    // a signature only its private key makes.
    let by_stranger = DeviceKeySigner::new(device(STRANGER))
        .sign(message)
        .expect("a signature");
    let over_another = signer.sign(b"another transcript").expect("a signature");
    let flipped = |at: usize| {
        let mut bytes = signature.clone();
        bytes[at] ^= 1;
        bytes
    };
    for (what, forged) in [
        ("signed by another key", by_stranger),
        ("signed over another message", over_another),
        ("a bit flipped in R", flipped(0)),
        ("a bit flipped in S", flipped(32)),
    ] {
        let forged = dss(SignatureScheme::ED25519, &forged);
        assert!(
            ServerCertVerifier::verify_tls13_signature(&verifier, message, &pinned, &forged)
                .is_err(),
            "server verifier: {what}"
        );
        assert!(
            ClientCertVerifier::verify_tls13_signature(&verifier, message, &pinned, &forged)
                .is_err(),
            "client verifier: {what}"
        );
    }
    let ecdsa = dss(SignatureScheme::ECDSA_NISTP256_SHA256, &signature);
    assert!(
        ServerCertVerifier::verify_tls13_signature(&verifier, message, &pinned, &ecdsa).is_err()
    );
    assert!(
        ServerCertVerifier::verify_tls12_signature(&verifier, message, &pinned, &signed).is_err()
    );
    assert!(
        ClientCertVerifier::verify_tls12_signature(&verifier, message, &pinned, &signed).is_err()
    );
    assert_eq!(
        ServerCertVerifier::supported_verify_schemes(&verifier),
        [SignatureScheme::ED25519]
    );
    assert_eq!(
        ClientCertVerifier::supported_verify_schemes(&verifier),
        [SignatureScheme::ED25519]
    );
    assert!(ServerCertVerifier::requires_raw_public_keys(&verifier));
    assert!(ClientCertVerifier::requires_raw_public_keys(&verifier));
    assert!(verifier.offer_client_auth() && verifier.client_auth_mandatory());
    assert!(ClientCertVerifier::root_hint_subjects(&verifier).is_empty());
}

/// The TLS configurations carry no ALPN, no SNI, no tickets and no early
/// data (design §6.5); every transport parameter is the design's.
#[test]
fn the_configurations_are_the_designs() {
    let key = Arc::clone(&identity(HOST).key);
    let server = server_tls(Arc::clone(&key), &pk(VIEWER)).expect("a server TLS config");
    assert!(server.alpn_protocols.is_empty());
    assert_eq!(server.max_early_data_size, 0);
    assert_eq!(server.send_tls13_tickets, 0);
    assert!(!server.session_storage.can_cache());
    let client = client_tls(key, &pk(VIEWER)).expect("a client TLS config");
    assert!(client.alpn_protocols.is_empty());
    assert!(!client.enable_sni);
    assert!(!client.enable_early_data);
    let resumption = format!("{:?}", client.resumption);
    assert!(
        resumption.contains("store: NoClientSessionStorage")
            && resumption.contains("tls12_resumption: Disabled"),
        "{resumption}"
    );

    let host = format!("{:?}", transport(TornectRole::Host));
    let viewer = format!("{:?}", transport(TornectRole::Viewer));
    for (field, value) in [
        ("max_concurrent_uni_streams", "0"),
        ("keep_alive_interval", "Some(2s)"),
        ("initial_rtt", "100ms"),
        ("allow_spin", "false"),
        ("datagram_receive_buffer_size", "None"),
        ("stream_receive_window", "4194304"),
        ("receive_window", "16777216"),
        ("send_window", "16777216"),
    ] {
        for printed in [&host, &viewer] {
            assert!(
                printed.contains(&format!("{field}: {value}")),
                "{field} in {printed}"
            );
        }
    }
    assert!(host.contains("max_concurrent_bidi_streams: 1"), "{host}");
    assert!(
        viewer.contains("max_concurrent_bidi_streams: 0"),
        "{viewer}"
    );
    assert!(host.contains("max_idle_timeout: Some(10000)"), "{host}");

    let config = identity(HOST)
        .server_config(&pk(VIEWER), TornectRole::Host)
        .expect("a server config");
    let printed = format!("{config:?}");
    assert!(printed.contains("migration: false"), "{printed}");
    assert!(printed.contains("max_incoming: 4"), "{printed}");
    assert!(printed.contains("incoming_buffer_size: 65536"), "{printed}");
    assert!(
        printed.contains("incoming_buffer_size_total: 262144"),
        "{printed}"
    );
    assert!(printed.contains("sent: 0"), "{printed}");
    assert!(
        format!("{:?}", endpoint_config()).contains("grease_quic_bit: false"),
        "the QUIC bit is never greased"
    );
}

/// A TLS alert, the peer's or our own, is a crypto close; nothing else is.
#[test]
fn only_tls_alerts_are_crypto_closes() {
    let closed = |code: quinn::TransportErrorCode| {
        ConnectionError::ConnectionClosed(quinn::ConnectionClose {
            error_code: code,
            frame_type: None,
            reason: Default::default(),
        })
    };
    let raised = |code: quinn::TransportErrorCode| {
        // quinn does not re-export quinn-proto's `TransportError`; its
        // `From<TransportErrorCode>` builds one.
        ConnectionError::TransportError(code.into())
    };
    for alert in [0x00, 0x28, 0x2a, 0x30, 0x31, 0x74, 0xff] {
        assert!(is_crypto_close(&closed(quinn::TransportErrorCode::crypto(
            alert
        ))));
        assert!(is_crypto_close(&raised(quinn::TransportErrorCode::crypto(
            alert
        ))));
    }
    for other in [
        closed(quinn::TransportErrorCode::PROTOCOL_VIOLATION),
        closed(quinn::TransportErrorCode::NO_ERROR),
        raised(quinn::TransportErrorCode::CONNECTION_REFUSED),
        ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: VarInt::from_u32(0x130),
            reason: Default::default(),
        }),
        ConnectionError::TimedOut,
        ConnectionError::Reset,
        ConnectionError::LocallyClosed,
        ConnectionError::VersionMismatch,
    ] {
        assert!(!is_crypto_close(&other), "{other:?}");
    }
}

/// No `Debug` here prints a key, a device ID or a seed.
#[test]
fn no_debug_prints_a_key() {
    let quic = identity(HOST);
    let printed = format!(
        "{quic:?} {:?} {:?} {:?} {:?}",
        DeviceKeySigner::new(device(HOST)),
        PinnedVerifier::new(&pk(VIEWER)),
        QuicError::Peer(PeerRefusal::Key),
        quic.server_config(&pk(VIEWER), TornectRole::Host)
            .expect("a server config")
    );
    let id = device(HOST).id().to_string();
    for secret in [
        hex(&pk(HOST)),
        hex(&pk(VIEWER)),
        hex(&[HOST; 32]),
        id.clone(),
        id[..16].to_string(),
    ] {
        assert!(!printed.contains(&secret), "{secret} in {printed}");
    }
    for byte in pk(HOST).iter().take(4) {
        assert!(!printed.contains(&format!("{byte}, ")), "{printed}");
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The pinned handshake in memory, each role dialling once (design §12.1
/// "quic"): both peers pass `check_peer`, present exactly their pinned
/// keys, negotiate no ALPN and send no SNI; the exporters agree on one
/// connection and differ across connections and tokens; the viewer opens
/// the one stream the host allows and the host can open none; every QUIC
/// datagram has the fixed bit set.
#[tokio::test(start_paused = true)]
async fn the_pinned_handshake_completes_with_either_side_dialling() {
    let hub = Hub::new();
    let mut exported = Vec::new();
    let mut refused = 0;
    for (host_dials, port) in [(false, 50000), (true, 50010)] {
        // Fresh sockets per round: one quinn endpoint per session socket.
        let host = Side::new(&hub, &format!("192.168.1.20:{port}"), false, HOST);
        let viewer = Side::new(&hub, &format!("192.168.1.30:{}", port + 1), false, VIEWER);
        let (host_conn, viewer_conn) = if host_dials {
            let (_viewer_ep, viewer_conn, _host_ep, host_conn) =
                connect(&viewer, TornectRole::Viewer, &host, TornectRole::Host).await;
            (host_conn, viewer_conn)
        } else {
            let (_host_ep, host_conn, _viewer_ep, viewer_conn) =
                connect(&host, TornectRole::Host, &viewer, TornectRole::Viewer).await;
            (host_conn, viewer_conn)
        };
        assert_eq!(check_peer(&host_conn, &pk(VIEWER), &host.filter()), Ok(()));
        assert_eq!(
            check_peer(&viewer_conn, &pk(HOST), &viewer.filter()),
            Ok(())
        );
        assert_eq!(
            check_peer(&viewer_conn, &pk(STRANGER), &viewer.filter()),
            Err(PeerRefusal::Key)
        );
        assert_eq!(
            check_peer(&viewer_conn, &pk(HOST), &elsewhere_filter()),
            Err(PeerRefusal::Address)
        );
        assert_eq!(
            presented(&host_conn),
            [CertificateDer::from(spki(&pk(VIEWER)).to_vec())]
        );
        assert_eq!(
            presented(&viewer_conn),
            [CertificateDer::from(spki(&pk(HOST)).to_vec())]
        );
        let server_side = if host_dials { &viewer_conn } else { &host_conn };
        let client_side = if host_dials { &host_conn } else { &viewer_conn };
        let server_data = handshake_data(server_side);
        assert_eq!(server_data.protocol, None, "no ALPN");
        assert_eq!(server_data.server_name, None, "no SNI");
        assert_eq!(handshake_data(client_side).protocol, None);

        let host_ekm = exporter(&host_conn, &TOKEN).expect("the host's keying material");
        let viewer_ekm = exporter(&viewer_conn, &TOKEN).expect("the viewer's keying material");
        assert_eq!(*host_ekm, *viewer_ekm);
        assert_ne!(
            *exporter(&host_conn, &[0x43; 32]).expect("keying material"),
            *host_ekm
        );
        exported.push(*host_ekm);

        let (mut send, mut recv) = viewer_conn.open_bi().await.expect("the media stream");
        send.write_all(b"bind").await.expect("a write");
        let (mut host_send, mut host_recv) =
            tokio::time::timeout(Duration::from_secs(5), host_conn.accept_bi())
                .await
                .expect("the stream within 5 s")
                .expect("the media stream");
        let mut got = [0; 4];
        host_recv.read_exact(&mut got).await.expect("the bytes");
        assert_eq!(&got, b"bind");
        host_send.write_all(b"proof").await.expect("a write");
        host_send.finish().expect("finished");
        assert_eq!(recv.read_to_end(64).await.expect("the reply"), b"proof");
        assert!(
            tokio::time::timeout(Duration::from_secs(1), host_conn.open_bi())
                .await
                .is_err(),
            "the viewer allows the host no stream"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), viewer_conn.open_bi())
                .await
                .is_err(),
            "the host allows the viewer one stream"
        );
        host_conn.close(VarInt::from_u32(0), b"");
        viewer_conn.close(VarInt::from_u32(0), b"");
        refused +=
            viewer.mem.refused.load(Ordering::SeqCst) + host.mem.refused.load(Ordering::SeqCst);
    }
    assert_ne!(
        exported[0], exported[1],
        "keying material is per connection"
    );
    let wire = hub.wire();
    assert!(wire.len() > 8);
    assert!(
        wire.iter().all(|d| d.bytes[0] & 0x40 != 0),
        "a QUIC datagram without the fixed bit"
    );
    assert_eq!(refused, 0);
}

/// A host and a viewer at fresh in-memory addresses (`port` and
/// `port + 1`), each validated by the other; `dual` says which socket is
/// dual-stack (host, viewer).
fn fresh(hub: &Arc<Hub>, port: u16, dual: (bool, bool)) -> (Side, Side) {
    let host = Side::new(hub, &format!("192.168.1.20:{port}"), dual.0, HOST);
    let viewer = Side::new(hub, &format!("192.168.1.30:{}", port + 1), dual.1, VIEWER);
    host.validate(&viewer);
    viewer.validate(&host);
    (host, viewer)
}

async fn within<T>(secs: u64, what: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(secs), what)
        .await
        .expect("in time")
}

/// A quinn client configuration around a rustls one the test changed.
fn quinn_client(tls: rustls::ClientConfig) -> quinn::ClientConfig {
    let crypto = QuicClientConfig::try_from(tls).expect("a QUIC client config");
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport(TornectRole::Viewer)));
    config
}

/// The datagrams `from` sent to `to`.
fn sent(hub: &Hub, from: SocketAddr, to: SocketAddr) -> usize {
    hub.wire()
        .iter()
        .filter(|d| d.from == from && d.to == to)
        .count()
}

/// A dialler that pinned another key refuses the server's with a TLS
/// alert (design §6.5); the controlled side keeps accepting, and the
/// pinned dial from the same socket then completes.
#[tokio::test(start_paused = true)]
async fn a_server_key_that_is_not_the_pin_fails_with_an_alert() {
    let hub = Hub::new();
    let (host, viewer) = fresh(&hub, 50100, (false, false));
    let server = host.server(&viewer, TornectRole::Host);
    let accepting = host.accept_task(&server, &viewer);
    let client = viewer.client();
    let wrong = viewer
        .quic
        .client_config(&pk(STRANGER), TornectRole::Viewer)
        .expect("a client config");
    let refused = dial(
        &client,
        wrong,
        host.addr,
        false,
        &pk(STRANGER),
        &viewer.filter(),
    )
    .await;
    assert_eq!(refused.err(), Some(QuicError::Handshake { crypto: true }));

    let conn = viewer
        .dial(&client, &host, TornectRole::Viewer)
        .await
        .expect("the pinned dial");
    let accepted = within(5, accepting)
        .await
        .expect("the accept task")
        .expect("the accepted connection");
    assert_eq!(check_peer(&accepted, &pk(VIEWER), &host.filter()), Ok(()));
    assert_eq!(
        *exporter(&accepted, &TOKEN).expect("keying material"),
        *exporter(&conn, &TOKEN).expect("keying material")
    );
}

/// The controlled side refuses a dialler that presents another key, no
/// key at all, or the pinned key with an ALPN: each refusal is a TLS alert
/// the dialler recognises (TLS 1.3 lets the client finish before the
/// server checks its key, so the alert may follow the dialler's own
/// completion, `docs/research/quic.md` §12 item 3). None is accepted, no
/// stream byte crosses, and the pinned viewer is accepted afterwards.
#[tokio::test(start_paused = true)]
async fn a_dialler_without_the_pinned_key_is_refused_with_an_alert() {
    let hub = Hub::new();
    let (host, viewer) = fresh(&hub, 50200, (false, false));
    let impostor = Side::with_identity(
        &hub,
        "192.168.1.31:50202",
        false,
        VIEWER,
        identity(STRANGER),
    );
    host.validate(&impostor);
    impostor.validate(&host);
    let server = host.server(&viewer, TornectRole::Host);
    let mut accepting = host.accept_task(&server, &viewer);

    let keyless = quinn_client(
        rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier::new(&pk(HOST))))
            .with_no_client_auth(),
    );
    let mut alpn = client_tls(Arc::clone(&viewer.quic.key), &pk(HOST)).expect("a TLS config");
    alpn.alpn_protocols = vec![b"h3".to_vec()];
    let alpn = quinn_client(alpn);
    let other_key = impostor
        .quic
        .client_config(&pk(HOST), TornectRole::Viewer)
        .expect("a client config");
    let client = impostor.client();
    for (what, config) in [
        ("another key", other_key),
        ("no key", keyless),
        ("an ALPN", alpn),
    ] {
        let crypto = match dial(
            &client,
            config,
            host.addr,
            false,
            &pk(HOST),
            &impostor.filter(),
        )
        .await
        {
            Err(QuicError::Handshake { crypto }) => crypto,
            Err(other) => panic!("{what}: {other:?}"),
            Ok(conn) => {
                let mut send = conn.open_bi().await.map(|(send, _)| send).ok();
                if let Some(send) = send.as_mut() {
                    let _ = send.write_all(b"bind").await;
                }
                is_crypto_close(&within(5, conn.closed()).await)
            }
        };
        assert!(crypto, "{what}: the refusal is a TLS alert");
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(1), &mut accepting)
            .await
            .is_err(),
        "a refused dialler was accepted"
    );

    let viewer_client = viewer.client();
    let conn = viewer
        .dial(&viewer_client, &host, TornectRole::Viewer)
        .await
        .expect("the pinned dial");
    let accepted = within(5, accepting)
        .await
        .expect("the accept task")
        .expect("the accepted connection");
    assert_eq!(check_peer(&accepted, &pk(VIEWER), &host.filter()), Ok(()));
    assert_eq!(accepted.remote_address(), viewer.addr);
    assert_eq!(
        *exporter(&accepted, &TOKEN).expect("keying material"),
        *exporter(&conn, &TOKEN).expect("keying material")
    );
}

/// A QUIC identity that presents the device key `presented` but signs with
/// the device key of `signs`: it holds the public key (which is no secret)
/// and not the private one.
fn forged(presented: u8, signs: u8) -> QuicIdentity {
    QuicIdentity::with_key(Arc::new(DeviceKeySigner::new(device(signs))), pk(presented))
}

/// A dialler that presents the pinned viewer key without holding it (its
/// `CertificateVerify` is signed by another device key) is refused with a
/// TLS alert (design §6.5: the signature is checked against the pinned key
/// itself). The host's accept yields nothing, no stream byte crosses, and
/// the genuine viewer is accepted afterwards.
#[tokio::test(start_paused = true)]
async fn a_dialler_presenting_the_pinned_key_without_holding_it_is_refused() {
    let hub = Hub::new();
    let (host, viewer) = fresh(&hub, 50250, (false, false));
    let impostor = Side::with_identity(
        &hub,
        "192.168.1.31:50252",
        false,
        VIEWER,
        forged(VIEWER, STRANGER),
    );
    host.validate(&impostor);
    impostor.validate(&host);
    let server = host.server(&viewer, TornectRole::Host);
    let mut accepting = host.accept_task(&server, &viewer);

    let client = impostor.client();
    let crypto = match impostor.dial(&client, &host, TornectRole::Viewer).await {
        Err(QuicError::Handshake { crypto }) => crypto,
        Err(other) => panic!("{other:?}"),
        // TLS 1.3 lets the client finish before the server checks its key.
        Ok(conn) => {
            let mut send = conn.open_bi().await.map(|(send, _)| send).ok();
            if let Some(send) = send.as_mut() {
                let _ = send.write_all(b"bind").await;
            }
            is_crypto_close(&within(5, conn.closed()).await)
        }
    };
    assert!(crypto, "the refusal is a TLS alert");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), &mut accepting)
            .await
            .is_err(),
        "the forged viewer was accepted"
    );

    let viewer_client = viewer.client();
    let conn = viewer
        .dial(&viewer_client, &host, TornectRole::Viewer)
        .await
        .expect("the pinned dial");
    let accepted = within(5, accepting)
        .await
        .expect("the accept task")
        .expect("the accepted connection");
    assert_eq!(accepted.remote_address(), viewer.addr);
    assert_eq!(
        *exporter(&accepted, &TOKEN).expect("keying material"),
        *exporter(&conn, &TOKEN).expect("keying material")
    );
}

/// A controlled side that presents the pinned host key without holding it
/// is refused by the dialler's own verifier: the dial fails with a TLS
/// alert before any stream exists, and the forged side's accept yields
/// nothing.
#[tokio::test(start_paused = true)]
async fn a_host_presenting_the_pinned_key_without_holding_it_is_refused() {
    let hub = Hub::new();
    let host = Side::with_identity(
        &hub,
        "192.168.1.20:50260",
        false,
        HOST,
        forged(HOST, STRANGER),
    );
    let viewer = Side::new(&hub, "192.168.1.30:50261", false, VIEWER);
    host.validate(&viewer);
    viewer.validate(&host);
    let server = host.server(&viewer, TornectRole::Host);
    let mut accepting = host.accept_task(&server, &viewer);

    let client = viewer.client();
    let dialled = viewer.dial(&client, &host, TornectRole::Viewer).await;
    assert_eq!(dialled.err(), Some(QuicError::Handshake { crypto: true }));
    assert!(
        tokio::time::timeout(Duration::from_secs(1), &mut accepting)
            .await
            .is_err(),
        "the forged host completed a handshake"
    );
}

/// A client ticket store that counts what it is given and hands out.
#[derive(Debug)]
struct Tickets {
    cache: rustls::client::ClientSessionMemoryCache,
    inserted: AtomicUsize,
    handed_out: AtomicUsize,
}

impl Tickets {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cache: rustls::client::ClientSessionMemoryCache::new(8),
            inserted: AtomicUsize::new(0),
            handed_out: AtomicUsize::new(0),
        })
    }
}

impl rustls::client::ClientSessionStore for Tickets {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: rustls::NamedGroup) {
        self.cache.set_kx_hint(server_name, group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.cache.kx_hint(server_name)
    }

    fn set_tls12_session(
        &self,
        server_name: ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        self.inserted.fetch_add(1, Ordering::SeqCst);
        self.cache.set_tls12_session(server_name, value);
    }

    fn tls12_session(
        &self,
        server_name: &ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        let value = self.cache.tls12_session(server_name);
        if value.is_some() {
            self.handed_out.fetch_add(1, Ordering::SeqCst);
        }
        value
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.cache.remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.inserted.fetch_add(1, Ordering::SeqCst);
        self.cache.insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        let value = self.cache.take_tls13_ticket(server_name);
        if value.is_some() {
            self.handed_out.fetch_add(1, Ordering::SeqCst);
        }
        value
    }
}

/// No resumption and no 0-RTT (design §6.5): the controlled side issues
/// no session ticket, so even a dialler that keeps tickets and wants early
/// data has none; each of its dials is a full handshake without 0-RTT. A
/// server that does issue tickets fills the same store, so the store would
/// have seen one.
#[tokio::test(start_paused = true)]
async fn no_ticket_is_issued_so_no_dial_resumes_or_sends_early_data() {
    let hub = Hub::new();
    let greedy = |viewer: &Side, tickets: &Arc<Tickets>| {
        let mut tls = client_tls(Arc::clone(&viewer.quic.key), &pk(HOST)).expect("a TLS config");
        tls.resumption =
            Resumption::store(Arc::clone(tickets) as Arc<dyn rustls::client::ClientSessionStore>);
        tls.enable_early_data = true;
        quinn_client(tls)
    };
    let tickets = Tickets::new();
    for port in [50300, 50310] {
        let (host, viewer) = fresh(&hub, port, (false, false));
        let server = host.server(&viewer, TornectRole::Host);
        let accepting = host.accept_task(&server, &viewer);
        let client = viewer.client();
        let connecting = client
            .connect_with(greedy(&viewer, &tickets), host.addr, SERVER_NAME)
            .expect("a dial");
        let Err(connecting) = connecting.into_0rtt() else {
            panic!("0-RTT");
        };
        let conn = within(5, connecting).await.expect("a full handshake");
        let accepted = within(5, accepting)
            .await
            .expect("the accept task")
            .expect("the accepted connection");
        assert_eq!(check_peer(&accepted, &pk(VIEWER), &host.filter()), Ok(()));
        // A ticket would follow the handshake.
        tokio::time::sleep(Duration::from_secs(1)).await;
        conn.close(VarInt::from_u32(0), b"");
    }
    assert_eq!(
        tickets.inserted.load(Ordering::SeqCst),
        0,
        "a ticket was issued"
    );
    assert_eq!(tickets.handed_out.load(Ordering::SeqCst), 0);

    let control = Tickets::new();
    let (host, viewer) = fresh(&hub, 50320, (false, false));
    let mut tls = server_tls(Arc::clone(&host.quic.key), &pk(VIEWER)).expect("a TLS config");
    tls.send_tls13_tickets = 2;
    tls.session_storage = rustls::server::ServerSessionMemoryCache::new(8);
    let crypto = QuicServerConfig::try_from(tls).expect("a QUIC server config");
    let server = endpoint(
        &host.punch,
        Some(quinn::ServerConfig::with_crypto(Arc::new(crypto))),
    )
    .expect("an endpoint");
    let accepting = host.accept_task(&server, &viewer);
    let client = viewer.client();
    let _conn = within(
        5,
        client
            .connect_with(greedy(&viewer, &control), host.addr, SERVER_NAME)
            .expect("a dial"),
    )
    .await
    .expect("a handshake");
    let _accepted = within(5, accepting).await.expect("the accept task");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        control.inserted.load(Ordering::SeqCst) > 0,
        "the store records the tickets it is given"
    );
}

/// An off-path spoofer racing Initials from the viewer's validated address
/// before the viewer dials cannot lock the viewer out (design §6.5): the
/// host answers each with a Retry only, to the address the spoofer forged,
/// so no spoofed attempt starts a handshake or takes a slot; the host
/// keeps accepting until a handshake passes `check_peer`; once the
/// viewer's connection passes, the server configuration is off and a
/// further Initial starts nothing. (Spoofs during and after the viewer's
/// handshake: the two tests that follow.)
#[tokio::test(start_paused = true)]
async fn a_spoofed_initial_cannot_lock_the_viewer_out() {
    let hub = Hub::new();
    let (host, viewer) = fresh(&hub, 50400, (false, false));
    let spoofer = Side::new(&hub, "192.168.1.66:50466", false, STRANGER);
    spoofer.validate(&host);
    *spoofer.mem.spoof.lock().expect("the spoof") = Some(viewer.addr);
    let server = host.server(&viewer, TornectRole::Host);
    let accepting = host.accept_task(&server, &viewer);

    let spoofing = spoofer.client();
    let spoof = || {
        let config = spoofer
            .quic
            .client_config(&pk(HOST), TornectRole::Viewer)
            .expect("a client config");
        spoofing
            .connect_with(config, host.addr, SERVER_NAME)
            .expect("a spoofed dial")
    };
    let attempts: Vec<_> = (0..6).map(|_| spoof()).collect();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        sent(&hub, host.addr, viewer.addr) > 0,
        "the host answered the spoofed Initials, to the forged address"
    );
    // quinn itself ignores the Initials of a burst beyond `MAX_INCOMING`.
    let (retries, flights) = retries_and_others(&hub, host.addr, viewer.addr);
    assert_eq!(retries.len(), MAX_INCOMING);
    assert_eq!(
        flights, 0,
        "the host answered with Retries only and started no handshake"
    );

    let client = viewer.client();
    let conn = viewer
        .dial(&client, &host, TornectRole::Viewer)
        .await
        .expect("the viewer's dial");
    let accepted = within(5, accepting)
        .await
        .expect("the accept task")
        .expect("the viewer's connection");
    assert_eq!(check_peer(&accepted, &pk(VIEWER), &host.filter()), Ok(()));
    assert_eq!(
        *exporter(&accepted, &TOKEN).expect("keying material"),
        *exporter(&conn, &TOKEN).expect("keying material")
    );

    let _late = spoof();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), server.accept())
            .await
            .is_err(),
        "an Initial after the accept became a connection attempt"
    );
    for attempt in attempts {
        assert!(
            within(30, attempt).await.is_err(),
            "a spoofed handshake completed"
        );
    }
    assert_eq!(sent(&hub, host.addr, spoofer.addr), 0);
}

/// The Retry datagrams `from` sent to `to` (their sizes), and how many
/// other datagrams it sent there.
fn retries_and_others(hub: &Hub, from: SocketAddr, to: SocketAddr) -> (Vec<usize>, usize) {
    let mut retries = Vec::new();
    let mut others = 0;
    for datagram in hub.wire().iter().filter(|d| d.from == from && d.to == to) {
        if is_retry(&datagram.bytes) {
            retries.push(datagram.bytes.len());
        } else {
            others += 1;
        }
    }
    (retries, others)
}

/// An off-path spoofer at `at` whose datagrams claim to come from `forged`,
/// with the endpoint it dials the host from (its own stranger key).
fn spoofer(hub: &Arc<Hub>, at: &str, forged: SocketAddr, host: &Side) -> (Side, quinn::Endpoint) {
    let spoofer = Side::new(hub, at, false, STRANGER);
    spoofer.validate(host);
    *spoofer.mem.spoof.lock().expect("the spoof") = Some(forged);
    let endpoint = spoofer.client();
    (spoofer, endpoint)
}

/// A dial from `side`'s `endpoint` to the host, with `side`'s own key: its
/// Initial and their retransmissions.
fn attempt(side: &Side, endpoint: &quinn::Endpoint, host: &Side) -> quinn::Connecting {
    let config = side
        .quic
        .client_config(&pk(host.seed), TornectRole::Viewer)
        .expect("a client config");
    endpoint
        .connect_with(config, host.addr, SERVER_NAME)
        .expect("a spoofed dial")
}

/// `n` dials from the spoofer, a millisecond apart, so that each Initial
/// reaches [`accept`] (quinn ignores the Initials of one burst beyond
/// [`MAX_INCOMING`]).
async fn spoof_each(
    n: usize,
    spoofer: &Side,
    endpoint: &quinn::Endpoint,
    host: &Side,
) -> Vec<quinn::Connecting> {
    let mut attempts = Vec::new();
    for _ in 0..n {
        attempts.push(attempt(spoofer, endpoint, host));
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    attempts
}

/// Twice the handshake cap of spoofed Initials, from the viewer's
/// validated address, while the viewer's own handshake is in flight (the
/// host's replies to it not yet arrived), cannot evict it (design §6.5,
/// critique S8(b)): each spoofed Initial draws only a Retry, smaller than
/// the Initial and sent to the forged address, so none takes a handshake
/// slot; the viewer's handshake then completes and is the one accepted.
#[tokio::test(start_paused = true)]
async fn spoofed_initials_during_the_viewers_handshake_cannot_evict_it() {
    let hub = Hub::new();
    let (host, viewer) = fresh(&hub, 50410, (false, false));
    let (spoofer, spoofing) = spoofer(&hub, "192.168.1.66:50476", viewer.addr, &host);
    let server = host.server(&viewer, TornectRole::Host);
    let accepting = host.accept_task(&server, &viewer);

    viewer.mem.hold(Hold::Arriving);
    let client = viewer.client();
    let dial = viewer.dial(&client, &host, TornectRole::Viewer);
    tokio::pin!(dial);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut dial)
            .await
            .is_err(),
        "the dial completed while the host's replies were in flight"
    );
    let (retries, flight) = retries_and_others(&hub, host.addr, viewer.addr);
    assert_eq!(retries.len(), 1, "the viewer's first Initial drew a Retry");
    assert!(flight > 0, "the host started the viewer's handshake");
    assert!(viewer.mem.held().0 > 0);

    let attempts = spoof_each(2 * MAX_PENDING_HANDSHAKES, &spoofer, &spoofing, &host).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (retries, _) = retries_and_others(&hub, host.addr, viewer.addr);
    assert_eq!(
        retries.len(),
        1 + 2 * MAX_PENDING_HANDSHAKES,
        "each spoofed Initial drew a Retry, to the forged address"
    );
    let smallest_initial = hub
        .wire()
        .iter()
        .filter(|d| d.from == viewer.addr && d.to == host.addr)
        .map(|d| d.bytes.len())
        .min()
        .expect("Initials");
    assert!(smallest_initial >= 1200);
    assert!(
        retries.iter().all(|&len| len < smallest_initial),
        "a Retry is smaller than the Initial that drew it: {retries:?}"
    );

    viewer.mem.release();
    let conn = within(5, &mut dial).await.expect("the viewer's dial");
    let accepted = within(5, accepting)
        .await
        .expect("the accept task")
        .expect("the viewer's connection");
    assert_eq!(accepted.remote_address(), viewer.addr);
    assert_eq!(check_peer(&accepted, &pk(VIEWER), &host.filter()), Ok(()));
    assert_eq!(
        *exporter(&accepted, &TOKEN).expect("keying material"),
        *exporter(&conn, &TOKEN).expect("keying material")
    );
    for attempt in attempts {
        assert!(
            within(30, attempt).await.is_err(),
            "a spoofed handshake completed"
        );
    }
    assert_eq!(sent(&hub, host.addr, spoofer.addr), 0);
}

/// Spoofed Initials after the viewer completed its side of the handshake
/// (TLS 1.3 lets the client finish first) and while its `Finished` is still
/// on its way to the host cannot close the viewer's connection: a viewer
/// that had already written its `Bind` would otherwise end the session
/// instead of falling back (decision M1-79). The viewer's connection
/// survives, is the one accepted, and carries the media stream.
#[tokio::test(start_paused = true)]
async fn spoofed_initials_after_the_viewer_finished_cannot_close_it() {
    let hub = Hub::new();
    let (host, viewer) = fresh(&hub, 50420, (false, false));
    let (spoofer, spoofing) = spoofer(&hub, "192.168.1.66:50486", viewer.addr, &host);
    let server = host.server(&viewer, TornectRole::Host);
    let mut accepting = host.accept_task(&server, &viewer);

    viewer.mem.hold(Hold::SentOnceAnswered);
    let client = viewer.client();
    let conn = within(5, viewer.dial(&client, &host, TornectRole::Viewer))
        .await
        .expect("the viewer's side completes first");
    assert!(
        viewer.mem.held().1 > 0,
        "the viewer's Finished is in flight"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut accepting)
            .await
            .is_err(),
        "the host completed without the viewer's Finished"
    );

    let attempts = spoof_each(2 * MAX_PENDING_HANDSHAKES, &spoofer, &spoofing, &host).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        retries_and_others(&hub, host.addr, viewer.addr).0.len(),
        1 + 2 * MAX_PENDING_HANDSHAKES,
        "each spoofed Initial drew a Retry"
    );
    assert_eq!(
        conn.close_reason(),
        None,
        "a spoofed Initial closed the viewer's connection"
    );

    viewer.mem.release();
    let accepted = within(5, accepting)
        .await
        .expect("the accept task")
        .expect("the viewer's connection");
    assert_eq!(accepted.remote_address(), viewer.addr);
    assert_eq!(
        *exporter(&accepted, &TOKEN).expect("keying material"),
        *exporter(&conn, &TOKEN).expect("keying material")
    );
    let (mut send, _recv) = conn.open_bi().await.expect("the media stream");
    send.write_all(b"bind").await.expect("a write");
    let (_host_send, mut host_recv) = within(5, accepted.accept_bi())
        .await
        .expect("the media stream");
    let mut got = [0; 4];
    within(5, host_recv.read_exact(&mut got))
        .await
        .expect("the bytes");
    assert_eq!(&got, b"bind");
    assert_eq!(conn.close_reason(), None);
    for attempt in attempts {
        assert!(
            within(30, attempt).await.is_err(),
            "a spoofed handshake completed"
        );
    }
    assert_eq!(sent(&hub, host.addr, spoofer.addr), 0);
}

/// At most [`MAX_PENDING_HANDSHAKES`] handshakes run at once, and none is
/// dropped for a newer attempt (design §6.5): with the viewer's handshake
/// and three more from validated addresses stalled (the host's replies in
/// flight), two further diallers at validated addresses get their Retry
/// and then no handshake at all; the viewer's handshake, the oldest, then
/// completes and is the one accepted.
#[tokio::test(start_paused = true)]
async fn the_handshake_cap_ignores_further_attempts_and_evicts_none() {
    let hub = Hub::new();
    let (host, viewer) = fresh(&hub, 50430, (false, false));
    let server = host.server(&viewer, TornectRole::Host);
    let accepting = host.accept_task(&server, &viewer);

    viewer.mem.hold(Hold::Arriving);
    let client = viewer.client();
    let dial = viewer.dial(&client, &host, TornectRole::Viewer);
    tokio::pin!(dial);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut dial)
            .await
            .is_err()
    );

    let others: Vec<Side> = (0..MAX_PENDING_HANDSHAKES + 1)
        .map(|i| {
            let other = Side::new(
                &hub,
                &format!("192.168.1.{}:50440", 40 + i),
                false,
                STRANGER,
            );
            host.validate(&other);
            other.validate(&host);
            other.mem.hold(Hold::Arriving);
            other
        })
        .collect();
    let mut attempts = Vec::new();
    for other in &others {
        let endpoint = other.client();
        attempts.push((attempt(other, &endpoint, &host), endpoint));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (stalled, beyond) = others.split_at(MAX_PENDING_HANDSHAKES - 1);
    for other in stalled {
        let (retries, flight) = retries_and_others(&hub, host.addr, other.addr);
        assert_eq!(retries.len(), 1);
        assert!(flight > 0, "a handshake within the cap did not start");
    }
    for other in beyond {
        let (retries, flight) = retries_and_others(&hub, host.addr, other.addr);
        assert_eq!(retries.len(), 1, "the dialler proved its address");
        assert_eq!(flight, 0, "a handshake beyond the cap started");
        assert!(
            sent(&hub, other.addr, host.addr) >= 2,
            "the Initial with the Retry token reached the host"
        );
    }

    viewer.mem.release();
    let conn = within(5, &mut dial).await.expect("the viewer's dial");
    let accepted = within(5, accepting)
        .await
        .expect("the accept task")
        .expect("the viewer's connection");
    assert_eq!(accepted.remote_address(), viewer.addr);
    assert_eq!(
        *exporter(&accepted, &TOKEN).expect("keying material"),
        *exporter(&conn, &TOKEN).expect("keying material")
    );
    drop(attempts);
}

/// The controlled side takes a connection attempt only from a source a
/// probe round trip validated and the remote filter admits (design §6.5):
/// an unvalidated on-site source and a validated source off the session's
/// site each draw nothing at all, and the viewer is then accepted.
#[tokio::test(start_paused = true)]
async fn the_controlled_side_answers_only_validated_admitted_sources() {
    let hub = Hub::new();
    let (host, viewer) = fresh(&hub, 50500, (false, false));
    let unvalidated = Side::new(&hub, "192.168.1.40:50540", false, VIEWER);
    let off_site = Side::new(&hub, "10.0.0.5:50505", false, VIEWER);
    host.validate(&off_site);
    assert!(!host.filter().admit(off_site.addr));
    let server = host.server(&viewer, TornectRole::Host);
    let accepting = host.accept_task(&server, &viewer);

    for dialler in [&unvalidated, &off_site] {
        dialler.validate(&host);
        let client = dialler.client();
        let dialled = dialler.dial(&client, &host, TornectRole::Viewer).await;
        assert_eq!(dialled.err(), Some(QuicError::Handshake { crypto: false }));
        assert!(sent(&hub, dialler.addr, host.addr) > 0);
        assert_eq!(sent(&hub, host.addr, dialler.addr), 0, "the host answered");
    }
    assert!(host.punch.counters().gated > 0);

    let client = viewer.client();
    viewer
        .dial(&client, &host, TornectRole::Viewer)
        .await
        .expect("the viewer's dial");
    let accepted = within(5, accepting)
        .await
        .expect("the accept task")
        .expect("the viewer's connection");
    assert_eq!(accepted.remote_address(), viewer.addr);
}

/// The host does not follow a migrating viewer (design §6.5: migration
/// off): once the viewer's endpoint moves to another socket, even one the
/// host's gate validated, the host takes none of its packets and sends
/// nothing there.
#[tokio::test(start_paused = true)]
async fn the_host_does_not_follow_a_migrating_viewer() {
    let hub = Hub::new();
    let (host, viewer) = fresh(&hub, 50600, (false, false));
    let (_server, host_conn, client, viewer_conn) =
        connect(&host, TornectRole::Host, &viewer, TornectRole::Viewer).await;
    let moved = Side::new(&hub, "192.168.1.30:50609", false, VIEWER);
    moved.validate(&host);
    host.validate(&moved);
    client
        .rebind_abstract(Arc::clone(&moved.punch) as Arc<dyn AsyncUdpSocket>)
        .expect("a rebind");
    let (mut send, _recv) = viewer_conn.open_bi().await.expect("a stream");
    send.write_all(b"bind").await.expect("a write");
    assert!(
        tokio::time::timeout(Duration::from_secs(3), host_conn.accept_bi())
            .await
            .is_err(),
        "the host followed the viewer"
    );
    assert!(sent(&hub, moved.addr, host.addr) > 0);
    assert_eq!(sent(&hub, host.addr, moved.addr), 0);
}

/// A connected pair whose viewer opened the media stream: (host
/// connection, its stream ends, viewer connection, its stream ends).
async fn with_stream(
    host: &Side,
    viewer: &Side,
) -> (
    quinn::Endpoint,
    quinn::Connection,
    quinn::SendStream,
    quinn::RecvStream,
    quinn::Endpoint,
    quinn::Connection,
    quinn::RecvStream,
) {
    let (server, host_conn, client, viewer_conn) =
        connect(host, TornectRole::Host, viewer, TornectRole::Viewer).await;
    let (mut send, recv) = viewer_conn.open_bi().await.expect("the media stream");
    send.write_all(b"bind").await.expect("a write");
    let (host_send, mut host_recv) = within(5, host_conn.accept_bi())
        .await
        .expect("the media stream");
    let mut got = [0; 4];
    host_recv.read_exact(&mut got).await.expect("the bytes");
    (
        server,
        host_conn,
        host_send,
        host_recv,
        client,
        viewer_conn,
        recv,
    )
}

/// The refusal flush (design §6.5): the viewer reads the whole refusal,
/// then sees the host's close with the refusal's reason code; the host
/// closes as soon as the refusal is acknowledged.
#[tokio::test(start_paused = true)]
async fn a_refusal_is_read_before_the_close_that_carries_its_reason() {
    let hub = Hub::new();
    let (host, viewer) = fresh(&hub, 50700, (false, false));
    let (_server, host_conn, host_send, _host_recv, _client, viewer_conn, mut recv) =
        with_stream(&host, &viewer).await;
    let started = tokio::time::Instant::now();
    let refusing = tokio::spawn(async move {
        refuse(&host_conn, host_send, b"refused: version", 8).await;
        host_conn
    });
    assert_eq!(
        within(5, recv.read_to_end(64)).await.expect("the refusal"),
        b"refused: version"
    );
    let host_conn = within(5, refusing).await.expect("the refusal task");
    assert!(
        started.elapsed() < REFUSAL_FLUSH,
        "the host waited out the flush"
    );
    match within(5, viewer_conn.closed()).await {
        ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code, VarInt::from_u32(8));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        host_conn.close_reason(),
        Some(ConnectionError::LocallyClosed)
    );
}

/// A viewer that never acknowledges holds the refusal no longer than
/// [`REFUSAL_FLUSH`].
#[tokio::test(start_paused = true)]
async fn a_deaf_viewer_holds_a_refusal_no_longer_than_the_flush() {
    let hub = Hub::new();
    let (host, viewer) = fresh(&hub, 50710, (false, false));
    let (_server, host_conn, host_send, _host_recv, _client, _viewer_conn, _recv) =
        with_stream(&host, &viewer).await;
    viewer.mem.deaf.store(true, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    refuse(&host_conn, host_send, b"refused: version", 8).await;
    let waited = started.elapsed();
    assert!(
        waited >= REFUSAL_FLUSH && waited < REFUSAL_FLUSH + Duration::from_millis(50),
        "{waited:?}"
    );
    assert_eq!(
        host_conn.close_reason(),
        Some(ConnectionError::LocallyClosed)
    );
}

/// Zero `InvalidInput` refusals over whole sessions on sockets that
/// refuse the wrong family (design §6.3 family rule, §12.1 "family"):
/// dual-stack on both sides, on either side, each role dialling; every
/// IPv4 send from a dual-stack socket leaves v4-mapped.
#[tokio::test(start_paused = true)]
async fn whole_sessions_on_strict_sockets_see_no_family_refusal() {
    let hub = Hub::new();
    let mut port = 50800;
    for dual in [(true, true), (true, false), (false, true)] {
        for host_dials in [false, true] {
            let (host, viewer) = fresh(&hub, port, dual);
            port += 10;
            let (_ends, host_conn, viewer_conn) = if host_dials {
                let (viewer_ep, viewer_conn, host_ep, host_conn) =
                    connect(&viewer, TornectRole::Viewer, &host, TornectRole::Host).await;
                ((viewer_ep, host_ep), host_conn, viewer_conn)
            } else {
                let (host_ep, host_conn, viewer_ep, viewer_conn) =
                    connect(&host, TornectRole::Host, &viewer, TornectRole::Viewer).await;
                ((host_ep, viewer_ep), host_conn, viewer_conn)
            };
            let (mut send, mut recv) = viewer_conn.open_bi().await.expect("the media stream");
            send.write_all(b"bind").await.expect("a write");
            let (mut host_send, _host_recv) = within(5, host_conn.accept_bi())
                .await
                .expect("the media stream");
            let media = vec![0x5a; 256 << 10];
            host_send.write_all(&media).await.expect("the media");
            host_send.finish().expect("finished");
            assert_eq!(
                within(10, recv.read_to_end(1 << 20))
                    .await
                    .expect("the media"),
                media
            );
            // Keep-alives over the rest of a session.
            tokio::time::sleep(Duration::from_secs(30)).await;
            assert!(host_conn.close_reason().is_none(), "the session died");
            host_conn.close(VarInt::from_u32(0), b"");
            for side in [&host, &viewer] {
                assert_eq!(side.mem.refused.load(Ordering::SeqCst), 0, "{dual:?}");
                let counters = side.punch.counters();
                assert_eq!(counters.inner_errors, 0);
                assert_eq!(counters.send_gated, 0);
                assert_eq!(counters.v4_mapped_sends > 0, side.mem.dual_stack);
            }
        }
    }
}

/// A signing key that records every message it signs.
#[derive(Debug)]
struct Recording {
    inner: DeviceKeySigner,
    signed: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[derive(Debug)]
struct RecordingSigner {
    inner: Box<dyn Signer>,
    signed: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl SigningKey for Recording {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.inner.choose_scheme(offered).map(|inner| {
            Box::new(RecordingSigner {
                inner,
                signed: Arc::clone(&self.signed),
            }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
}

impl Signer for RecordingSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.signed
            .lock()
            .expect("the record")
            .push(message.to_vec());
        self.inner.sign(message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.inner.scheme()
    }
}

/// What the device key signs through TLS cannot be taken for a Tornect
/// envelope signature (design §9.4, `docs/research/quic.md` §3.5): every
/// TLS 1.3 `CertificateVerify` content starts with 64 spaces and its
/// role's context string (RFC 8446 §4.4.3), every envelope signature with
/// `tornect/v1/sig/` (`tornect_signal::transcript::SIG_PREFIX`).
#[tokio::test(start_paused = true)]
async fn tls_signatures_cannot_be_taken_for_envelope_signatures() {
    const ENVELOPE: &[u8] = b"tornect/v1/sig/";
    let recording = |seed: u8| {
        let signed = Arc::new(Mutex::new(Vec::new()));
        let key = Recording {
            inner: DeviceKeySigner::new(device(seed)),
            signed: Arc::clone(&signed),
        };
        (QuicIdentity::with_key(Arc::new(key), pk(seed)), signed)
    };
    let (host_quic, host_signed) = recording(HOST);
    let (viewer_quic, viewer_signed) = recording(VIEWER);
    let hub = Hub::new();
    let side = |at: &str, seed: u8, quic: &QuicIdentity| {
        Side::with_identity(&hub, at, false, seed, quic.clone())
    };
    let host = side("192.168.1.20:50900", HOST, &host_quic);
    let viewer = side("192.168.1.30:50901", VIEWER, &viewer_quic);
    let _first = connect(&host, TornectRole::Host, &viewer, TornectRole::Viewer).await;
    let host = side("192.168.1.20:50910", HOST, &host_quic);
    let viewer = side("192.168.1.30:50911", VIEWER, &viewer_quic);
    let _second = connect(&viewer, TornectRole::Viewer, &host, TornectRole::Host).await;

    let context = |role: &str| {
        let mut bytes = vec![0x20; 64];
        bytes.extend(format!("TLS 1.3, {role} CertificateVerify\0").as_bytes());
        bytes
    };
    let (server, client) = (context("server"), context("client"));
    for (signed, roles) in [
        (host_signed, [&server, &client]),
        (viewer_signed, [&client, &server]),
    ] {
        let signed = signed.lock().expect("the record").clone();
        assert_eq!(signed.len(), 2, "one signature per handshake");
        for (message, context) in signed.iter().zip(roles) {
            assert!(message.starts_with(context));
            assert!(
                matches!(message.len() - context.len(), 32 | 48),
                "the rest is one transcript hash"
            );
            assert_ne!(message[0], ENVELOPE[0]);
        }
    }
}

/// One real session socket, as the link binds it.
struct RealSide {
    punch: Arc<PunchSocket>,
    port: u16,
    _tees: crate::udp::Tees,
}

impl RealSide {
    fn ipv4() -> Self {
        Self::on(RealNet::new().bind(None).expect("a session socket"))
    }

    fn on(bound: BoundUdp) -> Self {
        let port = bound.inner.local_addr().expect("its address").port();
        let (punch, tees) = PunchSocket::new(bound, ProbeGate::new());
        Self {
            punch,
            port,
            _tees: tees,
        }
    }

    fn filter(&self) -> RemoteFilter {
        loopback_filter(self.punch.dual_stack())
    }
}

/// A real session between `host` and `viewer` over `loopback`: the side
/// that does not dial accepts. Returns (host, viewer) connections and the
/// endpoints that carry them.
async fn real_session(
    host: &RealSide,
    viewer: &RealSide,
    host_dials: bool,
    loopback: IpAddr,
) -> (quinn::Connection, quinn::Connection, [quinn::Endpoint; 2]) {
    let host_at = SocketAddr::new(loopback, host.port);
    let viewer_at = SocketAddr::new(loopback, viewer.port);
    assert!(host.punch.gate().admit(viewer_at));
    assert!(viewer.punch.gate().admit(host_at));
    let (controlled, controlled_seed, controlled_role, controlling, controlling_seed, target) =
        if host_dials {
            (viewer, VIEWER, TornectRole::Viewer, host, HOST, viewer_at)
        } else {
            (host, HOST, TornectRole::Host, viewer, VIEWER, host_at)
        };
    let server = endpoint(
        &controlled.punch,
        Some(
            identity(controlled_seed)
                .server_config(&pk(controlling_seed), controlled_role)
                .expect("a server config"),
        ),
    )
    .expect("an endpoint");
    let accepting = {
        let server = server.clone();
        let gate = controlled.punch.gate().clone();
        let filter = controlled.filter();
        let peer = pk(controlling_seed);
        tokio::spawn(async move { accept(&server, |from| gate.admits(from), &peer, &filter).await })
    };
    let client = endpoint(&controlling.punch, None).expect("an endpoint");
    let controlling_role = if host_dials {
        TornectRole::Host
    } else {
        TornectRole::Viewer
    };
    let dialled = dial(
        &client,
        identity(controlling_seed)
            .client_config(&pk(controlled_seed), controlling_role)
            .expect("a client config"),
        target,
        controlling.punch.dual_stack(),
        &pk(controlled_seed),
        &controlling.filter(),
    )
    .await
    .expect("the dial");
    let accepted = within(5, accepting)
        .await
        .expect("the accept task")
        .expect("the accepted connection");
    if host_dials {
        (dialled, accepted, [server, client])
    } else {
        (accepted, dialled, [server, client])
    }
}

/// 1 MiB from host to viewer on the media stream, and the binding secret
/// both ends agree on.
async fn media_crosses(host_conn: &quinn::Connection, viewer_conn: &quinn::Connection) {
    let (mut send, mut recv) = viewer_conn.open_bi().await.expect("the media stream");
    send.write_all(b"bind").await.expect("a write");
    let (mut host_send, mut host_recv) = within(5, host_conn.accept_bi())
        .await
        .expect("the media stream");
    let mut got = [0; 4];
    host_recv.read_exact(&mut got).await.expect("the bytes");
    let media: Vec<u8> = (0..1 << 20).map(|i: u32| (i % 251) as u8).collect();
    host_send.write_all(&media).await.expect("the media");
    host_send.finish().expect("finished");
    assert_eq!(
        within(10, recv.read_to_end(2 << 20))
            .await
            .expect("the media"),
        media
    );
    assert_eq!(
        *exporter(host_conn, &TOKEN).expect("keying material"),
        *exporter(viewer_conn, &TOKEN).expect("keying material")
    );
}

fn no_send_failed(sides: [&RealSide; 2]) {
    for side in sides {
        let counters = side.punch.counters();
        assert_eq!(
            (
                counters.os_errors,
                counters.os_too_large,
                counters.inner_errors
            ),
            (0, 0, 0),
            "{counters:?}"
        );
    }
}

/// The pinned handshake on real loopback session sockets (the raw public
/// key gate of design step A9, `docs/research/quic.md` §3.3): each role
/// dials once, 1 MiB crosses the media stream, the exporters agree, and
/// no send fails. IPv4 loopback, so it runs everywhere.
#[tokio::test]
async fn the_pinned_handshake_runs_on_real_loopback_sockets() {
    for host_dials in [false, true] {
        let host = RealSide::ipv4();
        let viewer = RealSide::ipv4();
        let (host_conn, viewer_conn, _endpoints) =
            real_session(&host, &viewer, host_dials, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        assert_eq!(check_peer(&host_conn, &pk(VIEWER), &host.filter()), Ok(()));
        assert_eq!(
            check_peer(&viewer_conn, &pk(HOST), &viewer.filter()),
            Ok(())
        );
        media_crosses(&host_conn, &viewer_conn).await;
        no_send_failed([&host, &viewer]);
        host_conn.close(VarInt::from_u32(0), b"");
    }
}

/// The dual-stack handshake (design §12.2 "dual-stack", gate [VM]/[CI]):
/// on dual-stack session sockets the viewer dials the host over IPv4
/// (`127.0.0.1`, sent v4-mapped) and the host dials the viewer over IPv6
/// (`::1`); both complete, media crosses, and no send fails. Skipped, with
/// the reason printed, where the OS has no IPv6 (this container); with
/// `TORNECT_REQUIRE_IPV6` set (the dev VM and CI recipe), a skip is a
/// failure instead.
#[tokio::test]
#[allow(clippy::print_stderr)] // the skip says why
async fn the_dual_stack_handshake_runs_over_ipv4_and_ipv6() {
    let required = std::env::var_os("TORNECT_REQUIRE_IPV6").is_some();
    let socket = || bind_media_socket(None).expect("a session socket");
    let host_socket = socket();
    if !host_socket.dual_stack {
        assert!(!required, "TORNECT_REQUIRE_IPV6: no dual-stack socket");
        eprintln!(
            "skipped: no IPv6 socket on this machine (no AF_INET6), so the session socket \
             is IPv4 only; this test runs on the dev VM and in CI"
        );
        return;
    }
    let real = |bound| RealSide::on(BoundUdp::quiet(bound).expect("quiet"));
    let host = real(host_socket);
    let viewer = real(socket());
    let (host_conn, viewer_conn, _endpoints) =
        real_session(&host, &viewer, false, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    media_crosses(&host_conn, &viewer_conn).await;
    no_send_failed([&host, &viewer]);
    assert!(viewer.punch.counters().v4_mapped_sends > 0);
    host_conn.close(VarInt::from_u32(0), b"");

    if std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).is_err() {
        assert!(!required, "TORNECT_REQUIRE_IPV6: no IPv6 loopback address");
        eprintln!("skipped the ::1 half: no IPv6 loopback address on this machine");
        return;
    }
    let host = real(socket());
    let viewer = real(socket());
    let (host_conn, viewer_conn, _endpoints) =
        real_session(&host, &viewer, true, IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    media_crosses(&host_conn, &viewer_conn).await;
    no_send_failed([&host, &viewer]);
    host_conn.close(VarInt::from_u32(0), b"");
}
