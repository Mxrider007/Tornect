# QUIC transport with key-pinned TLS — research note (verified 2026-08-28)

Scope: `tornect-net` QUIC layer (plan §A.3 D5/D6, §B.2, §B.4, §B.6). Everything
below was checked against the crate sources extracted into `/tmp/crates-src/`
(from `static.crates.io`) and a probe crate at `/tmp/probe-quic` that was
**compiled and run on this VM** (Rust 1.96, no sudo, no cmake/nasm/libclang
needed). Line references are into the extracted sources.

### Pin refresh (2026-10-26, design `direct` step A1; decision M1-81)

The pins below replace §0 and §1.2 where they differ; the rest of this note was written
against the 2026-08-28 versions and its line numbers point there unless a line says
otherwise. Re-read in the registry sources
(`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`) on 2026-10-26.

| crate | pinned / locked | note |
|---|---|---|
| quinn | `=0.11.12` (2026-09-14, rust-version 1.85), `default-features = false`, features `["rustls-ring", "runtime-tokio"]` | **no `log`** (its `log` feature only forwards `tracing` events to the `log` crate) and no `rustls-log`; the defaults `platform-verifier` (OS trust stores) and `bloom` stay off. In the workspace `Cargo.toml`; only `tornect-net` names it |
| quinn-proto | 0.11.19 (2026-09-30), locked | quinn 0.11.12 requires `^0.11.18` |
| quinn-udp | 0.5.16 (2026-09-30), locked, feature `tracing` (quinn sets it) | 0.6.3 exists; quinn 0.11 stays on `^0.5` |
| rustls | `=0.23.46` (existing pin, decision M1-3), `ring` + `std` | in the app graph it also has `logging` and `tls12` through Arti's `futures-rustls` |
| rustls-webpki / rustls-pki-types / ring | 0.103.16 / 1.15.1 / 0.17.14, locked | unchanged by quinn |
| socket2 | `=0.6.5` | already in the lock through tokio; now a direct dependency of `tornect-net` |
| rcgen | not added | the design takes the raw-public-key option (§3.3) |

References re-checked in the new versions (used by the design's steps):
`quinn-0.11.12/src/endpoint.rs` `new_with_abstract_socket` :133, `connect_with` :208,
`set_server_config` :275, `ensure_ipv6` :631 (called at :222), the receive loop
:798–799, `ConnectionReset` ignored :845; `src/connection.rs` `peer_identity` :589,
`export_keying_material` :625; `src/runtime.rs` (`AsyncUdpSocket`, `UdpPoller`) and
`src/runtime/tokio.rs` ≈ :51–102. `quinn-proto-0.11.19/src/crypto/rustls.rs`
`configured_provider` :582 (ring when `rustls-ring` is the only provider feature),
`QuicServerConfig` `TryFrom` :492/:500; `src/config/mod.rs` `grease_quic_bit` :132,
`migration` :292, `max_incoming` :324, `incoming_buffer_size` :340; the fixed-bit check
`src/packet.rs:585`; packets from an unexpected remote dropped in
`src/connection/mod.rs` :1131 and :2294. `quinn-udp-0.5.16/src/lib.rs` `Transmit` :135
(`src_ip` :146), `log_sendmsg_error` :158 (compiled with the `tracing` feature, so always
here); `src/unix.rs` `try_send` :223 and `IPV6_PKTINFO` :671; `src/windows.rs`
`try_send` :168 and `IPV6_PKTINFO` :371. `rustls-0.23.46/src/server/handy.rs:187`
`AlwaysResolvesServerRawPublicKeys`, `src/client/handy.rs:235`
`AlwaysResolvesClientRawPublicKeys`, `src/webpki/verify.rs:213`
`verify_tls13_signature_with_raw_key` (re-exported from `crypto`, `src/crypto/mod.rs:15`),
`src/crypto/signer.rs` `SigningKey` :59 / `Signer` :77.

What logs addresses or keys (input to design DIRECT-6, decision M1-83, step A7):
- `quinn_udp::log_sendmsg_error` writes the destination and source addresses of a failed
  send at `warn` (target `quinn_udp`), at most once a minute; quinn-proto logs connection
  IDs and remote addresses at `debug`/`trace` (target `quinn_proto`; for example
  "discarding packet from unrecognized peer {remote}", `src/connection/mod.rs:1132`, and
  `initial_dcid`, `src/endpoint.rs:356`).
- rustls logs through the `log` crate when its `logging` feature is on (it is, in the
  app): at `trace` the client logs the server's certificate chain
  (`src/client/tls13.rs:1178`) and the server the certificate it sends
  (`src/server/tls13.rs:799`). With raw public keys that is an Ed25519
  SubjectPublicKeyInfo, a device key. The app's `tracing-subscriber` has its `tracing-log`
  feature on (through the existing graph), so such records can reach Tornect's layers.
- Step A7's filter drops these targets before any layer formats them; nothing in A1 runs
  quinn, so nothing is logged yet.

### Step A9 results (2026-10-26, design `direct` step A9; `crates/tornect-net/src/quic.rs`)

- **The raw-public-key gate holds.** The pinned RPK handshake of §3.3 completes on
  rustls 0.23.46 and quinn 0.11.12 with the device key signing through
  `DeviceKeySigner` (no PKCS#8, ring never holds the private key): in memory under paused
  time with either side dialling, and on real IPv4 loopback session sockets
  (`quic::tests::the_pinned_handshake_runs_on_real_loopback_sockets`). The X.509 fallback
  of §3.4 is not used, so rcgen stays out of the lock.
- **How each pin failure looks to the dialler** (observed in
  `a_dialler_without_the_pinned_key_is_refused_with_an_alert` and
  `a_server_key_that_is_not_the_pin_fails_with_an_alert`):
  - the dialler pinned another server key: its own verifier refuses, the dial fails with a
    locally raised `TransportError` `crypto(0x31)` (access_denied, from
    `CertificateError::ApplicationVerificationFailure`);
  - the server pinned another client key: the client's handshake **completes** (gotcha 3
    in §12), then a `ConnectionClosed` `crypto(0x31)` arrives whose reason phrase is
    `invalid peer certificate: ApplicationVerificationFailure` (rustls's error text: the
    kind only, no key); the server never yields the connection, so no stream byte is read;
  - a client with no key at all, and a client with the pinned key that offers an ALPN
    (`server/hs.rs:122–138`: in QUIC an offered ALPN the server cannot match is refused
    with `no_application_protocol`), fail their dials with a crypto close.
  All of these are `is_crypto_close`.
- **No tickets.** With `send_tls13_tickets = 0` and `NoServerSessionStorage` a client that
  keeps tickets and enables early data receives none (a counting `ClientSessionStore`), so
  `Connecting::into_0rtt` fails on every dial. The control: the same store under a server
  with `send_tls13_tickets = 2` and a `ServerSessionMemoryCache` records tickets.
- **Debug forms the tests read** (they are not API; a version bump may change them):
  `Resumption { store: NoClientSessionStorage, tls12_resumption: Disabled }`;
  `TransportConfig { max_concurrent_bidi_streams: 1, max_concurrent_uni_streams: 0,
  max_idle_timeout: Some(10000), stream_receive_window: 4194304, receive_window: 16777216,
  send_window: 16777216, …, initial_rtt: 100ms, …, keep_alive_interval: Some(2s), …,
  allow_spin: false, datagram_receive_buffer_size: None, … }`; `ServerConfig { …,
  validation_token: ServerValidationTokenConfig { lifetime: 1209600s, sent: 0, .. },
  migration: false, …, max_incoming: 4, incoming_buffer_size: 65536,
  incoming_buffer_size_total: 262144, .. }`; `EndpointConfig { …, grease_quic_bit: false,
  .. }`.
- **API facts met on the way.** `rustls::DigitallySignedStruct::new` is `pub(crate)`; the
  tests build one from wire bytes through the hidden
  `rustls::internal::msgs::codec::Codec::read_bytes` (tests only; rustls is pinned
  exactly). quinn does not re-export quinn-proto's `TransportError`; `From<TransportErrorCode>`
  builds one. `quinn::Endpoint::accept` pops an `Incoming` only when it returns it, so
  dropping it in a `select!` loses no attempt. An endpoint without a server configuration
  answers an Initial for an unknown connection with a stateless reset
  (`quinn-proto-0.11.19/src/endpoint.rs:445–448`), rate-limited and smaller than the
  datagram that caused it: after `set_server_config(None)` a further Initial starts no
  `Incoming`, and the real viewer's endpoint answers the host's replies to spoofed Initials
  this way, which the tests show harms neither connection.

---

## 0. TL;DR for implementers

| Item | Decision |
|---|---|
| QUIC | `quinn = "=0.11.11"`, `default-features = false`, features `["rustls-ring", "runtime-tokio", "log"]` (add `"rustls-log"` in debug builds) |
| TLS | `rustls = "=0.23.43"`, `default-features = false`, features `["ring", "std"]` — **never** default features (they pull `aws-lc-rs` + `prefer-post-quantum`) |
| Crypto provider | **ring** (`rustls::crypto::ring::default_provider()`), passed explicitly via `builder_with_provider` |
| Cert format on the wire | **Prefer RFC 7250 raw public keys (RPK)**: the "certificate" is the 44-byte Ed25519 SPKI, no X.509, no rcgen, no parser. Verified working over quinn. Keep X.509 (rcgen self-signed) as documented fallback (also verified). |
| Pinning | Custom `ServerCertVerifier` + `ClientCertVerifier` (mutual) comparing the presented SPKI DER to the pinned SPKI (constant-time), `supported_verify_schemes = [ED25519]` |
| Session binding | `Connection::export_keying_material(out, b"EXPORTER-tornect-session", session_token)` — identical on both ends, distinct per connection (verified) |
| Datagram payload | `max_datagram_size()`: **1162 B at MTU 1200, 1312 B at 1350, 1414 B at 1452** (8-byte CIDs, 16-byte AEAD tag). Formula below. |
| One socket, both roles | `Endpoint::new(EndpointConfig::default(), Some(server_cfg), std_udp_socket, Arc::new(TokioRuntime))` + `set_default_client_config(client_cfg)`; simultaneous open on both sides verified (yields 2 connections → tie-break needed) |
| Hole punching | Do it **outside** QUIC (own STUN/punch on the same socket via a custom `AsyncUdpSocket` demux). Upstream quinn has **no** NAT-traversal extension; the IETF draft is expired (individual, -02, 2024-03-03); only iroh's fork `noq` implements a variant. |
| Tor fallback | Run the session protocol directly over the onion stream (do **not** tunnel QUIC through Tor). Rationale §9. |

---

## 1. Versions, features, and why

### 1.1 Latest versions (crates.io API, 2026-08-28)

| crate | latest stable | notes |
|---|---|---|
| quinn | **0.11.11** (2026-06-22) | https://crates.io/api/v1/crates/quinn — rust-version 1.85 |
| quinn-proto | **0.11.17** (2026-08-17) | https://crates.io/api/v1/crates/quinn-proto — quinn 0.11.11 requires `quinn-proto ^0.11.15` (`quinn-0.11.11/Cargo.toml` `[dependencies.proto] version = "0.11.15"`) |
| quinn-udp | 0.5.15 (2026-07-04) is what quinn 0.11.11 uses (`[dependencies.udp] version = "0.5"`); **0.6.x is NOT used by quinn 0.11** | https://crates.io/api/v1/crates/quinn-udp |
| rustls | **0.23.43** (2026-07-29); 0.24.0-dev.1 exists, ignore | https://crates.io/api/v1/crates/rustls — quinn requires `rustls ^0.23.5` |
| rustls-pki-types | **1.15.1** (2026-07-23) | https://crates.io/api/v1/crates/rustls-pki-types |
| rustls-webpki | 0.103.15 (2026-08-21); rustls 0.23.43 depends on `^0.103.5` (`rustls-0.23.43/Cargo.toml:163-167`) | needed only for X.509 mode SPKI extraction |
| rcgen | **0.14.9** (2026-08-10), rust-version **1.88** | https://crates.io/api/v1/crates/rcgen — only for X.509 mode |
| socket2 | **0.6.5** (2026-07-13) | https://crates.io/api/v1/crates/socket2 |
| ring | 0.17.14 (2025-03-11) | pulled transitively |
| aws-lc-rs / aws-lc-sys | 1.18.0 / 0.44.0 | NOT used |

### 1.2 Recommended pins

```toml
[dependencies]
quinn = { version = "=0.11.11", default-features = false, features = ["rustls-ring", "runtime-tokio", "log"] }
rustls = { version = "=0.23.43", default-features = false, features = ["ring", "std"] }
rustls-pki-types = "=1.15.1"
socket2 = "=0.6.5"
tokio = { version = "1", features = ["rt-multi-thread", "net", "time", "sync", "macros"] }
bytes = "1"
subtle = "2"                      # constant-time SPKI compare (already in tree via rustls)

# Only if we keep the X.509 (rcgen self-signed) path:
rcgen = { version = "=0.14.9", default-features = false, features = ["ring", "crypto"] }
rustls-webpki = { version = "=0.103.15", default-features = false, features = ["ring", "alloc", "std"] }
```

Resolved tree of the probe (`cargo tree`, `/tmp/probe-quic`): `quinn 0.11.11`,
`quinn-proto 0.11.17`, `quinn-udp 0.5.15`, `rustls 0.23.43`, `rustls-webpki 0.103.15`,
`rustls-pki-types 1.15.1`, `ring 0.17.14`, `rcgen 0.14.9`, `socket2 0.6.5` —
**no `aws-lc-sys`, no `cmake`, no `bindgen` anywhere in the tree.**

### 1.3 quinn 0.11.11 feature flags (from `quinn-0.11.11/Cargo.toml` `[features]`)

```
default          = ["log", "platform-verifier", "runtime-tokio", "rustls-ring", "bloom"]
rustls-ring      = ["dep:rustls", "ring", "proto/rustls-ring", "proto/ring"]
rustls-aws-lc-rs = ["dep:rustls", "aws-lc-rs", "proto/rustls-aws-lc-rs", "proto/aws-lc-rs"]
rustls-aws-lc-rs-fips, aws-lc-rs, aws-lc-rs-fips, ring   (crypto-only variants, no TLS glue)
rustls           = ["rustls-ring"]          # legacy alias
rustls-log       = ["rustls?/logging"]      # rustls' own debug logging
log              = ["tracing/log", "proto/log", "udp/log"]
platform-verifier= ["proto/platform-verifier"]   # pulls rustls-platform-verifier 0.7 (OS trust stores) — NOT needed by Tornect
runtime-tokio | runtime-async-std | runtime-smol
bloom            = ["proto/bloom"]          # fastbloom-based token log for address-validation tokens
qlog             = ["proto/qlog"]
lock_tracking    = []
```

* quinn's default TLS provider is **ring** (`default` includes `rustls-ring`;
  `quinn-proto-0.11.17/src/crypto/rustls.rs` `configured_provider()`:
  `#[cfg(feature = "rustls-ring")] rustls::crypto::ring::default_provider()`, aws-lc-rs only
  when `rustls-aws-lc-rs && !rustls-ring`).
* rustls' **own** default is **aws-lc-rs** (`rustls-0.23.43/Cargo.toml`:
  `default = ["aws_lc_rs", "logging", "prefer-post-quantum", "std", "tls12"]`). If any crate in
  the workspace depends on `rustls` with default features you get *both* providers compiled,
  and `CryptoProvider::get_default_or_install_from_crate_features()` panics with
  "need to call CryptoProvider::install_default()" (`rustls-0.23.43/src/crypto/mod.rs:242,265-286`:
  `from_crate_features()` returns `None` when both `ring` and `aws_lc_rs` are on).
  Mitigation: (a) `default-features = false` everywhere we name rustls; (b) call
  `rustls::crypto::ring::default_provider().install_default().ok()` once at startup so any
  third-party crate (arti's `tor-rtcompat` rustls feature, reqwest, …) that uses
  `ClientConfig::builder()` gets ring; (c) our own configs always use `builder_with_provider`.
* We drop `platform-verifier` (we never verify against OS roots) and `bloom` is harmless but
  unnecessary (only matters when the server sends NEW_TOKEN / validation tokens; keep it off
  or on — it does not affect the API).

---

## 2. Build requirements (this VM vs CI)

| Provider | Needs | This VM | CI |
|---|---|---|---|
| **ring 0.17.14** | C compiler only ("ring currently requires a C (but not C++) toolchain"; packaged crate ships **precompiled object files for Windows x86/x86-64** so no nasm; Perl only for git builds) — https://github.com/briansmith/ring/blob/main/BUILDING.md | ✅ built here in 40 s | ✅ ubuntu/windows/macos runners all have a C toolchain |
| aws-lc-rs 1.18 / aws-lc-sys 0.44 (non-FIPS) | C/C++ compiler; "CMake is never required", "Bindgen is never required (pre-generated bindings are provided)", `prebuilt-nasm` feature "only affects builds for Windows x86-64" — https://github.com/aws/aws-lc-rs/blob/main/aws-lc-rs/README.md | would probably build, but adds C++ compile time and a second crypto lib | fine but pointless |

Verdict: **ring**. Simpler, faster to build, no cmake/nasm/libclang, and quinn already
defaults to it. rcgen's `ring` feature and rustls-webpki's `ring` feature align with it
(`rcgen-0.14.9/Cargo.toml` `default = ["crypto","pem","ring"]`).

Probe build here: `CARGO_BUILD_JOBS=2 cargo build` → `Finished dev profile in 40.58s`, run →
`ALL OK` (see §11 for the full output).

---

## 3. Identity & keys: Ed25519 end to end

### 3.1 Does rustls+ring do Ed25519 in TLS 1.3?

Yes, both directions:

* Verification: ring provider's `SUPPORTED_SIG_ALGS.mapping` contains
  `(SignatureScheme::ED25519, &[webpki_algs::ED25519])` (`rustls-0.23.43/src/crypto/ring/mod.rs:139`).
* Signing: `any_supported_type()` → `any_eddsa_type()` → `Ed25519SigningKey` built from PKCS#8
  (`rustls-0.23.43/src/crypto/ring/sign.rs:21,73,357-397`); `SigningKey::public_key()` returns the
  SPKI (`sign.rs:390-392`, `public_key_to_spki(&alg_id::ED25519, …)`).
* TLS 1.3 only in QUIC; quinn's `QuicClientConfig::inner` / `QuicServerConfig::inner` use
  `.with_protocol_versions(&[&rustls::version::TLS13])` (`crypto/rustls.rs`). So
  `verify_tls12_signature` is dead code for us — return an error from it.

### 3.2 From a 32-byte Ed25519 seed to what rustls/rcgen want (verified)

Tornect's device keys are ed25519 (onion key / per-device key). rustls' ring provider loads
`PrivateKeyDer::Pkcs8`; ring's `Ed25519KeyPair::from_pkcs8_maybe_unchecked` accepts PKCS#8 v1
(seed only) or v2. The probe hand-builds v1 (RFC 8410 §7) and the SPKI (RFC 8410 §4) and
cross-checks them against rcgen's public key, webpki's SPKI parse and rustls' `public_key()` —
all three agree:

```rust
/// PKCS#8 v1 for an Ed25519 seed: 302e 020100 3005 0603 2b6570 0422 0420 || seed
fn ed25519_seed_to_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20];
    v.extend_from_slice(seed); v
}
/// SPKI DER for an Ed25519 public key: 302a 3005 0603 2b6570 0321 00 || pk   (44 bytes)
fn ed25519_pk_to_spki(pk: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00];
    v.extend_from_slice(pk); v
}
```

(If we use `ed25519-dalek` with its `pkcs8` feature, `SigningKey::to_pkcs8_der()` gives an
equivalent DER; `VerifyingKey::to_public_key_der()` gives the same SPKI. Either works — the
44-byte SPKI is *the* pin value we store at pairing.)

Loading into rustls:

```rust
let provider = Arc::new(rustls::crypto::ring::default_provider());
let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));          // rustls_pki_types
let sk: Arc<dyn rustls::sign::SigningKey> = provider.key_provider.load_private_key(key.clone_key())?;
let my_spki: SubjectPublicKeyInfoDer<'_> = sk.public_key().unwrap();           // == ed25519_pk_to_spki(pk)
```

### 3.3 Option A (recommended): TLS raw public keys (RFC 7250) — no X.509 at all

rustls 0.23 supports RPK for both server and client certs
(`rustls-0.23.43/src/server/handy.rs:174-186` `AlwaysResolvesServerRawPublicKeys`,
`src/client/handy.rs:217-235` `AlwaysResolvesClientRawPublicKeys`, verifier hook
`requires_raw_public_keys()` in `src/verify.rs:143,272`, helper
`rustls::crypto::verify_tls13_signature_with_raw_key` in `src/webpki/verify.rs:209-226`).
Pattern copied from rustls' own tests (`src/server/test.rs:244-262`, `src/client/test.rs:449-470`)
and verified over quinn in the probe:

```rust
// "certificate" = our SPKI
let spki_as_cert = CertificateDer::from(sk.public_key().unwrap().as_ref().to_vec());
let ck = Arc::new(rustls::sign::CertifiedKey::new(vec![spki_as_cert], sk));

let server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_client_cert_verifier(verifier.clone())                 // Arc<dyn ClientCertVerifier>, requires_raw_public_keys() == true
    .with_cert_resolver(Arc::new(rustls::server::AlwaysResolvesServerRawPublicKeys::new(ck.clone())));

let client_tls = rustls::ClientConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .dangerous()
    .with_custom_certificate_verifier(verifier.clone())          // Arc<dyn ServerCertVerifier>, requires_raw_public_keys() == true
    .with_client_cert_resolver(Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(ck)));
```

In RPK mode the `end_entity: &CertificateDer` handed to the verifier **is the peer's SPKI DER**
(44 bytes for Ed25519; probe printed `peer_identity_len=44`), so pinning is a byte compare.
Benefits: no certificate generation/parsing code in the security boundary, no validity dates,
no rcgen/webpki/yasna/time deps, smaller handshake. Both peers are Tornect, so no interop concern.

### 3.4 Option B: self-signed X.509 via rcgen 0.14 from the EXISTING key (also verified)

```rust
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519, SanType};
// KeyPair from existing PKCS#8 (rcgen-0.14.9/src/key_pair.rs:232)
let kp = KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(pkcs8.as_slice()), &PKCS_ED25519)?;
// (alternatives: KeyPair::try_from(&PrivateKeyDer) / try_from(&[u8]) infer the algorithm, key_pair.rs:502-540)
let mut params = CertificateParams::default();       // not_before 1975-01-01, not_after 4096-01-01 (certificate.rs:82-85) → no clock dependence
params.distinguished_name = DistinguishedName::new();
params.distinguished_name.push(DnType::CommonName, "tornect");
params.subject_alt_names = vec![SanType::DnsName("tornect".try_into()?)];
let cert: rcgen::Certificate = params.self_signed(&kp)?;   // certificate.rs:154
let cert_der: CertificateDer<'static> = cert.der().clone(); // 256 bytes in the probe
let raw_pk: &[u8] = kp.public_key_raw();                    // 32 bytes (key_pair.rs:412)
```

SPKI extraction from a peer's X.509 cert (for pinning) via webpki, no x509-parser needed:

```rust
fn spki_of_cert(cert: &CertificateDer<'_>) -> Result<SubjectPublicKeyInfoDer<'static>, rustls::Error> {
    let ee = webpki::EndEntityCert::try_from(cert)          // rustls-webpki-0.103.15/src/end_entity.rs:63
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    Ok(ee.subject_public_key_info())                        // Deref → Cert::subject_public_key_info (cert.rs:234), includes outer SEQUENCE
}
```

Server/client config then use `.with_single_cert(vec![cert_der], key)` /
`.with_client_auth_cert(vec![cert_der], key)` (`rustls-0.23.43/src/server/builder.rs:65`,
`src/client/builder.rs:146`).

### 3.5 One device key, two kinds of signed message (design `direct` §9.4; step A9)

The ed25519 device key signs two kinds of message, and no signature made in one context
verifies as a signature of the other:

- **Tornect envelopes**: `"tornect/v1/sig/" ‖ KIND_NAME ‖ 0x00 ‖ th_prev ‖ digest`
  (`tornect-signal/src/transcript.rs:7`, `SIG_PREFIX` :27). That is the only Tornect
  signing call site.
- **TLS 1.3 `CertificateVerify`** (the direct link's QUIC, `DeviceKeySigner`):
  `0x20 × 64 ‖ "TLS 1.3, server CertificateVerify" | "TLS 1.3, client CertificateVerify" ‖
  0x00 ‖ transcript hash` (RFC 8446 §4.4.3).

The first byte differs (`t` = 0x74 against 0x20), so neither message can be the other, and
Ed25519 (PureEdDSA, RFC 8032) signs the message itself, not a hash an attacker could
steer. `quic::tests::tls_signatures_cannot_be_taken_for_envelope_signatures` records what
the device key signs through rustls in both roles: each message starts with 64 spaces and
its role's context string, followed by one SHA-256 or SHA-384 transcript hash. **Any new
signing context must keep a prefix distinct from both.** The same note belongs in the C1
threat-model text.

---

## 4. The pinning verifiers (rustls 0.23 trait signatures, exact)

From `rustls-0.23.43/src/verify.rs`:

```rust
pub trait ServerCertVerifier: Debug + Send + Sync {                       // line 69
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>, ocsp_response: &[u8], now: UnixTime) -> Result<ServerCertVerified, Error>;
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, Error>;
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, Error>;
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;
    fn requires_raw_public_keys(&self) -> bool { false }                   // line 143
    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> { None }  // line 153
}
pub trait ClientCertVerifier: Debug + Send + Sync {                       // line 160
    fn offer_client_auth(&self) -> bool { true }                           // line 163
    fn client_auth_mandatory(&self) -> bool { self.offer_client_auth() }   // line 170
    fn root_hint_subjects(&self) -> &[DistinguishedName];                  // line 203 (required, no default)
    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], now: UnixTime)
        -> Result<ClientCertVerified, Error>;                              // line 219
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, Error>;                         // line 241
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, Error>;                         // line 257
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>;            // line 268
    fn requires_raw_public_keys(&self) -> bool { false }                   // line 272
}
```

Paths: `rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid}`,
`rustls::server::danger::{ClientCertVerifier, ClientCertVerified}`, helpers
`rustls::crypto::{verify_tls12_signature, verify_tls13_signature, verify_tls13_signature_with_raw_key}`
(`src/crypto/mod.rs:14-15`), signature-scheme list from
`provider.signature_verification_algorithms.supported_schemes()` (`src/webpki/verify.rs:87`).

Verified implementation (one struct implements both traits; `rpk` toggles A/B mode):

```rust
#[derive(Debug)]
struct PinnedVerifier { expected_spki: Vec<u8>, provider: Arc<CryptoProvider>, rpk: bool }

impl PinnedVerifier {
    fn check(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>]) -> Result<(), rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer));
        }
        let presented = if self.rpk { end_entity.as_ref().to_vec() } else { spki_of_cert(end_entity)?.as_ref().to_vec() };
        // use subtle::ConstantTimeEq in production (ring::constant_time::verify_slices_are_equal is deprecated)
        if presented.len() != self.expected_spki.len() || !bool::from(presented.ct_eq(&self.expected_spki)) {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer));
        }
        Ok(())
    }
    fn sig13(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        if self.rpk {
            rustls::crypto::verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(cert.as_ref()), dss,
                &self.provider.signature_verification_algorithms)
        } else {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
        }
    }
}
impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(&self, ee: &CertificateDer<'_>, im: &[CertificateDer<'_>], _sn: &ServerName<'_>, _ocsp: &[u8], _now: UnixTime)
        -> Result<ServerCertVerified, rustls::Error> { self.check(ee, im)?; Ok(ServerCertVerified::assertion()) }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered)) }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { self.sig13(m, c, d) }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { vec![SignatureScheme::ED25519] }
    fn requires_raw_public_keys(&self) -> bool { self.rpk }
}
impl ClientCertVerifier for PinnedVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] { &[] }   // empty list = "send any client cert you have"
    fn verify_client_cert(&self, ee: &CertificateDer<'_>, im: &[CertificateDer<'_>], _now: UnixTime)
        -> Result<ClientCertVerified, rustls::Error> { self.check(ee, im)?; Ok(ClientCertVerified::assertion()) }
    fn verify_tls12_signature(/* same as above */) …
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { self.sig13(m, c, d) }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { vec![SignatureScheme::ED25519] }
    fn requires_raw_public_keys(&self) -> bool { self.rpk }
    // offer_client_auth()/client_auth_mandatory() keep their `true` defaults → client cert is REQUIRED
}
```

Notes:
* `supported_verify_schemes = [ED25519]` restricts what the peer may sign with; the peer's
  `CertificateVerify` with any other scheme fails `verify_tls13_signature` (rustls checks
  `dss.scheme.supported_in_tls13()` then `convert_scheme`).
* The server name passed to `Endpoint::connect(addr, "tornect")` must parse as a
  `ServerName` (quinn maps failure to `ConnectError::InvalidServerName`, `crypto/rustls.rs`). A
  constant label is fine — the verifier ignores it. It is sent as SNI in the ClientHello; use a
  constant, not the onion address.
* `Connection::peer_identity()` after the handshake downcasts to `Vec<CertificateDer<'static>>`
  (`quinn-proto crypto/rustls.rs` `peer_identity`) — in RPK mode element 0 is the peer SPKI
  (probe asserts equality). Use it for a belt-and-braces post-handshake check.
* `Connection::handshake_data()` downcasts to `quinn::crypto::rustls::HandshakeData { protocol, server_name }`
  → ALPN check (`protocol == Some(b"tornect/1")`).

### 4.1 Wrapping into quinn

```rust
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};   // re-export of quinn_proto::crypto::rustls
server_tls.alpn_protocols = vec![b"tornect/1".to_vec()];
server_tls.max_early_data_size = u32::MAX;      // QUIC requires 0 or u32::MAX (doc on QuicServerConfig); u32::MAX enables 0-RTT accept
let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls)?));   // TryFrom<rustls::ServerConfig> and TryFrom<Arc<…>>
server_config.transport_config(transport.clone());
server_config.migration(true);                   // default true; keeps NAT-rebinding clients alive

client_tls.alpn_protocols = vec![b"tornect/1".to_vec()];
client_tls.enable_early_data = true;
let mut client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls)?));
client_config.transport_config(transport);
```

`try_from` fails with `NoInitialCipherSuite` only if the provider lacks
`TLS13_AES_128_GCM_SHA256` (ring's does have it) and the config must be TLS 1.3-only
(`quinn-proto crypto/rustls.rs` docs + `initial_suite_from_provider`).

---

## 5. One socket, both roles; simultaneous open; rebind

`quinn-0.11.11/src/endpoint.rs`:

```rust
pub fn new(config: EndpointConfig, server_config: Option<ServerConfig>, socket: std::net::UdpSocket, runtime: Arc<dyn Runtime>) -> io::Result<Self>   // line 119
pub fn new_with_abstract_socket(config: EndpointConfig, server_config: Option<ServerConfig>, socket: Arc<dyn AsyncUdpSocket>, runtime: Arc<dyn Runtime>) -> io::Result<Self>   // line 133
pub fn set_default_client_config(&mut self, config: ClientConfig)                          // line 182
pub fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<Connecting, ConnectError>          // line 194
pub fn connect_with(&self, config: ClientConfig, addr: SocketAddr, server_name: &str) -> Result<Connecting, ConnectError>   // line 208 (per-peer pin!)
pub fn accept(&self) -> Accept<'_>                                                          // line 174 → Option<Incoming>
pub fn rebind(&self, socket: std::net::UdpSocket) -> io::Result<()>                         // line 243
pub fn rebind_abstract(&self, socket: Arc<dyn AsyncUdpSocket>) -> io::Result<()>            // line 253
pub fn set_server_config(&self, server_config: Option<ServerConfig>)                        // line 275 (new incoming only)
pub fn local_addr(&self) -> io::Result<SocketAddr>; pub fn close(&self, VarInt, &[u8]); pub async fn wait_idle(&self)
```

Verified pattern (socket2 → std socket → quinn):

```rust
let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;  // socket2-0.6.5/src/socket.rs:115
sock.set_reuse_address(true)?;                 // socket.rs:1125   (set_reuse_port is unix-only, sys/unix.rs:2247)
sock.set_recv_buffer_size(4 << 20).ok();       // socket.rs:1081
sock.set_send_buffer_size(4 << 20).ok();       // socket.rs:1152
sock.bind(&addr.into())?;                      // socket.rs:168
let std_sock: std::net::UdpSocket = sock.into();
let mut ep = quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server_config), std_sock, Arc::new(quinn::TokioRuntime))?;
ep.set_default_client_config(client_config);
```

`Endpoint::client()` itself uses socket2 and, for IPv6 binds, `set_only_v6(false)` to get a
dual-stack socket (`endpoint.rs:75-90`). Do the same if we bind `[::]:0`; note
`connect_with` rejects an IPv6 target on a v4-only endpoint (`ConnectError::InvalidRemoteAddress`)
and maps v4 targets to v4-mapped-v6 on a v6 endpoint (`endpoint.rs:220-226`).

* **Simultaneous open works**: in the probe both endpoints `connect()` to each other while both
  `accept()` — all four futures resolve (`A->B side=Client / B accepted side=Server` and vice
  versa). Result: **two** connections. Tornect needs a deterministic tie-break (e.g. keep the
  connection whose *client* has the lexicographically smaller device pubkey; close the other with
  an app error code) — or simply assign roles from signaling (host = QUIC server, client dials) and
  only use the client→host direction, with *both* sides sending punch packets first (§8).
* Per-peer pins: use `connect_with(client_config_for_peer, addr, "tornect")` so each outgoing
  attempt carries a verifier pinned to *that* peer; on the server side use
  `Incoming::accept_with(Arc<ServerConfig>)` (`incoming.rs:35`) to pin the expected client for the
  session, or have the verifier consult the pairing store (host accepts any *paired* device).
* **`rebind()` verified**: after `ep_a.rebind(new_std_socket)` the existing connection kept
  working and the peer saw the new address (`B now sees A at 127.0.0.1:40210`). Migration is
  enabled by default on the server (`ServerConfig.migration = true`,
  `quinn-proto config/mod.rs:292`).
* **Gotcha (verified):** quinn 0.11 does *not* progress an incoming handshake until the
  application takes the `Incoming` (`accept()`/`accept_with()`/`refuse()`/`retry()`/`ignore()`,
  `incoming.rs:27-66`). If nothing polls `endpoint.accept()`, the client hangs until
  `max_idle_timeout` (`TimedOut`). Always run an accept loop for the lifetime of the endpoint.
  Limits: `ServerConfig::max_incoming` (default 65536), `incoming_buffer_size` (10 MiB),
  `incoming_buffer_size_total` (100 MiB) (`config/mod.rs:233-258`). For Tornect set
  `max_incoming` small (e.g. 8) and `refuse()` anything not expected by signaling.
* Wrong pin fails fast when the server is accepting: client got
  `ConnectionError::TransportError(crypto(0x30) "invalid peer certificate: UnknownIssuer")` in
  <1 ms, server got `ConnectionError::ConnectionClosed(…"aborted by peer"…)`; server-side rejection of
  the client cert: server gets `TransportError crypto(0x30)`, client's `Connecting` **succeeds**
  (Client-Finished already sent) and the resulting `Connection` closes immediately — so the client
  must treat `connection.closed()` shortly after handshake as auth failure too.

`ConnectionError` variants (`quinn-proto connection/mod.rs:3839`): `VersionMismatch`,
`TransportError`, `ConnectionClosed`, `ApplicationClosed`, `Reset`, `TimedOut`, `LocallyClosed`,
`CidsExhausted`. `ConnectError` (`endpoint.rs:1253`): `EndpointStopping`, `CidsExhausted`,
`InvalidServerName`, `InvalidRemoteAddress`, `NoDefaultClientConfig`, `UnsupportedVersion`.

---

## 6. Exporter for `session_token` binding (verified)

```rust
pub fn export_keying_material(&self, output: &mut [u8], label: &[u8], context: &[u8])
    -> Result<(), quinn_proto::crypto::ExportKeyingMaterialError>            // quinn-0.11.11/src/connection.rs:608
```

Backed by `rustls::quic::Connection::export_keying_material(output, label, Some(context))`
(`quinn-proto crypto/rustls.rs`, `rustls-0.23.43/src/quic.rs:116-128`; RFC 5705 / RFC 8446 §7.5).
Error only if output is too long. Probe: 32-byte output with
`label = b"EXPORTER-tornect-session"`, `context = session_token` equal on both ends of a
connection and different across connections. Proposed use: both sides compute
`ekm = EKM(32, label, session_token)`, then the client sends `HMAC(ekm, "client")` on the `ctrl`
stream as its first message and the host answers `HMAC(ekm, "host")`; mismatch ⇒ close. This binds
the QUIC connection to the specific signaling exchange (plan §B.3). Prefix the label with
`EXPORTER-` per RFC 5705 §4 conventions.

---

## 7. Datagrams and MTU

API (`quinn-0.11.11/src/connection.rs`):

```rust
pub fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError>   // line 436; drops OLDEST queued datagrams if buffer full
pub fn send_datagram_wait(&self, data: Bytes) -> SendDatagram<'_>           // line 464; waits for buffer space instead
pub fn read_datagram(&self) -> ReadDatagram<'_>                              // line 352 → Result<Bytes, ConnectionError>, one datagram per await
pub fn max_datagram_size(&self) -> Option<usize>                             // line 483; None = disabled locally or unsupported by peer; varies with path MTU
pub fn datagram_send_buffer_space(&self) -> usize                            // line 496; >0 ⇒ sending ≤ this size drops nothing
pub fn rtt(&self) -> Duration; pub fn stats(&self) -> ConnectionStats        // stats().path.{rtt,cwnd,lost_packets,current_mtu,black_holes_detected,…}
```

`SendDatagramError`: `UnsupportedByPeer | Disabled | TooLarge | ConnectionLost(ConnectionError)`.

Payload budget (`quinn-proto connection/datagrams.rs:70-84`):
`max_size = current_mtu − predict_1rtt_overhead(None) − Datagram::SIZE_BOUND`, where
overhead = `1 + peer_cid_len + 4 (pn upper bound) + 16 (AEAD tag)` (`connection/mod.rs:3696-3719`),
`Datagram::SIZE_BOUND = 1 + 8` (`frame.rs:901-903`), and peer CID length is 8 with quinn's default
`HashedConnectionIdGenerator` (`cid_generator.rs:95-103`). Also capped by the peer's
`max_datagram_frame_size` transport parameter (quinn advertises its
`datagram_receive_buffer_size`).

| path MTU (UDP payload) | max datagram payload | measured |
|---|---|---|
| 1200 (QUIC minimum, `initial_mtu` default) | 1200 − 29 − 9 = **1162** | ✅ `Some(1162)` with discovery off |
| 1350 (`initial_mtu(1350)`) | **1312** | ✅ `Some(1312)` |
| 1452 (`MtuDiscoveryConfig::upper_bound` default) | **1414** | ✅ `Some(1414)` after DPLPMTUD on loopback |

So plan §B.4 "payload fits datagram MTU ~1200 B" should read: **video/audio datagram payload
≤ 1162 bytes before MTU discovery finishes (≈ first 1–2 RTT), then read
`max_datagram_size()` on every frame-packetize and re-fragment dynamically** — it can also shrink
(black-hole detection resets to `min_mtu` 1200). Never hardcode; leave ~10 bytes for our own
header inside the payload.

MTU knobs (`quinn-proto config/transport.rs`):
* `initial_mtu(u16)` (≥1200, default 1200; line 184), `min_mtu(u16)` (default 1200; line 206 —
  do **not** raise on the internet), `mtu_discovery_config(Option<MtuDiscoveryConfig>)` (enabled by
  default; `None` disables, line 214).
* `MtuDiscoveryConfig` (line ~690): `interval` (600 s), `upper_bound` (1452, max 65527),
  `minimum_change` (20), `black_hole_cooldown` (60 s). DPLPMTUD binary search, first run right
  after handshake; peers discover independently per direction.
* For LAN (jumbo/1500) we can raise `upper_bound` to 1472 (Ethernet) — gains ~20 B/packet.
* `EndpointConfig::max_udp_payload_size` default 1472 (`config/mod.rs:60`, "Ethernet MTU minus
  IP + UDP headers") — the receive-side cap we advertise.
* `pad_to_mtu(bool)` (default false) — traffic-analysis mitigation; costs bandwidth; off for media.

---

## 8. TransportConfig for low-latency media

Defaults (`config/transport.rs` `impl Default`, tuned for 100 Mbps × 100 ms):
`max_concurrent_bidi/uni_streams = 100`, `max_idle_timeout = 30 s`,
`stream_receive_window = 1.25 MB`, `receive_window = VarInt::MAX`, `send_window = 10 MB`,
`packet_threshold = 3`, `time_threshold = 9/8`, `initial_rtt = 333 ms`, `initial_mtu = min_mtu = 1200`,
`keep_alive_interval = None`, `datagram_receive_buffer_size = Some(1.25 MB)`,
`datagram_send_buffer_size = 1 MiB`, congestion = **Cubic**, `enable_segmentation_offload = true`,
`ack_frequency_config = None`, `allow_spin = true`.

Recommended (verified to compile/run in the probe):

```rust
let mut t = quinn::TransportConfig::default();
t.max_idle_timeout(Some(Duration::from_secs(10).try_into()?));  // IdleTimeout: TryFrom<Duration> (transport.rs:101)
t.keep_alive_interval(Some(Duration::from_secs(2)));            // only one side needs it; must be < both idle timeouts (line 259)
t.initial_rtt(Duration::from_millis(100));                       // faster PTO for first Initial retransmit during punching (default 333 ms)
t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));   // or CubicConfig/NewRenoConfig
t.datagram_receive_buffer_size(Some(4 << 20));                   // also sets the max_datagram_frame_size we advertise
t.datagram_send_buffer_size(4 << 20);                            // oldest-drop queue; keep small-ish so stale video is dropped, not delayed
t.max_concurrent_bidi_streams(8u8.into());
t.max_concurrent_uni_streams(8u8.into());
t.stream_receive_window((4u32 << 20).into());                    // control/input/clipboard streams; media is datagrams
t.send_window(8 << 20);
t.allow_spin(false);                                             // privacy: no RTT spin bit for observers
let mut ack = quinn::AckFrequencyConfig::default();              // draft-ietf-quic-ack-frequency-04 (transport.rs:470+)
ack.max_ack_delay(Some(Duration::from_millis(5)));               // clamped to ≥ peer min_ack_delay, ≤ max(RTT, 25 ms)
t.ack_frequency_config(Some(ack));
let transport = Arc::new(t);
```

* **BBR** is `pub struct Bbr` / `BbrConfig` in `quinn::congestion` (re-exported from quinn-proto
  `congestion.rs:12-14`), marked **"Experimental! Use at your own risk."** (`congestion/bbr/mod.rs:19`,
  port of Chromium's `bbr_sender.cc`). Only knob: `BbrConfig::initial_window(u64)`. Keep Cubic as
  the default and make BBR a setting; our GCC-style ABR (plan §B.4) is the real rate governor —
  QUIC CC only bounds bursts. With datagrams, when cwnd is exhausted quinn just queues (and drops
  oldest), so a pacer + ABR *below* the CC estimate is essential.
* `Connection::congestion_state()` returns the live `Box<dyn Controller>` (`window()`, metrics)
  and `stats().path.cwnd/rtt/lost_packets` feed the ABR (`connection/stats.rs:136-160`).
* `enable_segmentation_offload` (GSO) stays on; quinn-udp auto-disables when unsupported, with a
  possible burst of spurious loss at startup (transport.rs:344 doc) — VMware vmxnet3 in this VM is a
  candidate for that; expose a config toggle.
* Runtime tuning: `Connection::set_receive_window / set_send_window / set_max_concurrent_*`
  (`connection.rs:626-651`).

---

## 9. AsyncUdpSocket / Runtime abstraction; QUIC over Tor?

`quinn-0.11.11/src/runtime.rs`:

```rust
pub trait Runtime: Send + Sync + Debug + 'static {
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>>;
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>);
    fn wrap_udp_socket(&self, t: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>>;
    fn now(&self) -> Instant { Instant::now() }
}
pub trait AsyncUdpSocket: Send + Sync + Debug + 'static {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>>;              // poll_writable
    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()>;              // Transmit { destination, ecn, contents, segment_size, src_ip } (quinn-udp-0.5.15/src/lib.rs:135)
    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [udp::RecvMeta]) -> Poll<io::Result<usize>>;  // RecvMeta { addr, len, stride, ecn, dst_ip } (lib.rs:96)
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn max_transmit_segments(&self) -> usize { 1 }   // GSO
    fn max_receive_segments(&self) -> usize { 1 }    // GRO
    fn may_fragment(&self) -> bool { true }
}
```

Reference impl: `runtime/tokio.rs` wraps `tokio::net::UdpSocket` + `quinn_udp::UdpSocketState`
(`UdpSocketState::new((&sock).into())`, `send`, `recv`, `max_gso_segments`, `gro_segments`,
`may_fragment`). quinn-udp 0.5 types are re-exported as `quinn::udp`.

**Use for Tornect: the "magic socket" demux.** Wrap tokio's `UdpSocket` in our own
`AsyncUdpSocket` that (a) lets the punch/STUN engine `sendto` arbitrary bytes on the same socket
and (b) in `poll_recv` diverts non-QUIC datagrams to a side channel: QUIC packets always have the
fixed bit `0x40` set in byte 0 (RFC 9000 §17) while STUN's first two bits are `00` (RFC 9443
demux) — our own punch probes can also start with `0x00`. `Endpoint::new_with_abstract_socket`
exists exactly for this ("Useful when `socket` has additional state (e.g. sidechannels)
attached", `endpoint.rs:133` doc). iroh does the same in its magicsock. This is how STUN keepalives
and bidirectional punch probes coexist with a live QUIC endpoint on one port, which is required
for NAT mappings to stay consistent (same 4-tuple for STUN, punch and QUIC).

**QUIC over a Tor stream: don't.** Technically possible (an `AsyncUdpSocket` impl that length-
prefixes datagrams over the onion stream and fabricates a `SocketAddr`), but: TCP-like reliable
stream underneath ⇒ QUIC's loss recovery/CC fights Tor's (double congestion control, HoL blocking
makes datagrams pointless); quinn pads Initials to ≥1200 B and runs DPLPMTUD probes that are just
wasted bytes; extra TLS handshake RTTs over 0.5–1.5 s circuits. Plan D7's choice — run the same
session protocol (CBOR control + framed media) directly over the length-framed onion stream, with
the Tor circuit's own E2E auth plus the ed25519 transcript signatures — is right. Keep the
`AsyncUdpSocket` route only as a future experiment (arti-client provides no UDP anyway).

---

## 10. NAT traversal inside QUIC — status (2026-08-28)

* **draft-seemann-quic-nat-traversal**: individual draft, latest **-02 dated 2024-03-03,
  "Expired & archived", "not endorsed by the IETF", no WG adoption, no replacement draft** —
  https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/ . Design: server sends
  `ADD_ADDRESS` frames, client picks pairs and sends `PUNCH_ME_NOW`; both then send probes on the
  new path (Seemann, https://seemann.io/posts/2024-10-26---p2p-quic/).
* Companion **draft-seemann-quic-address-discovery** (QAD, server reports observed address) has an
  **open, unmerged** upstream PR in quinn-rs/quinn (#2043, opened 2024-11-14, last reviewed
  2025-05-21) — https://github.com/quinn-rs/quinn/pull/2043 . No NAT-traversal PR upstream;
  `grep nat_traversal|address_discovery` over `quinn-proto-0.11.17/src` finds nothing.
* **iroh**: originally forked quinn ("Why we forked Quinn", 2024-05-20,
  https://www.iroh.computer/blog/why-we-forked-quinn ; crates `iroh-quinn 0.16.1` /
  `iroh-quinn-proto 0.15.1`). With iroh 0.97 (2026-03-16) the fork became a separate project
  **`noq`** (crates.io `noq 1.2.0`, 2026-08-24, rust 1.88; features mirror quinn's:
  `rustls-ring`, `rustls-aws-lc-rs`, `platform-verifier`, `qlog`, `fast-apple-datapath`) with
  "QUIC Multipath, QUIC Address Discovery (QAD), Using QUIC to traverse NATs (QNT)" —
  https://github.com/n0-computer/noq , https://www.iroh.computer/blog/iroh-0-97-0-custom-transports-and-noq .
  `iroh 1.1.0` (2026-08-25) depends on `noq` and exposes `unstable-custom-transports`.
* Conclusion for Tornect: with upstream quinn we **cannot** punch "inside QUIC"; we punch
  **outside** it (ICE-lite candidate pairs exchanged over Tor, bidirectional probes from the same
  socket, then `connect_with()` to the pair that got a reply — or fire `connect_with()` to *all*
  candidate pairs concurrently on the one Endpoint and keep the first to complete). This matches
  plan D6/§B.2. Switching to `noq` later would buy QNT+multipath at the cost of tracking a fork;
  keep it as the documented plan-B, not v1.

---

## 11. Probe evidence (`/tmp/probe-quic`, compiled and run here)

`CARGO_BUILD_JOBS=2 cargo build` → `Finished dev profile in 40.58s`. Run output:

```
crypto provider default installed? false
[rpk=false] A->B client conn side=Client; B accepted side=Server
[rpk=false] B->A client conn side=Client; A accepted side=Server
[rpk=false] alpn=Some("tornect/1") peer_identity_len=256
[rpk=false] exporter OK (32 bytes, equal on both ends, distinct per connection)
[rpk=false] max_datagram_size right after handshake: Some(1414) (initial_mtu=1200)
[rpk=false] max_datagram_size after MTU discovery: Some(1414) (upper_bound default 1452)
[rpk=false] rtt=763.791µs path_mtu=1452 cc=248422
[rpk=false] rebind OK; B now sees A at 127.0.0.1:40210
[rpk=true] A->B client conn side=Client; B accepted side=Server
[rpk=true] B->A client conn side=Client; A accepted side=Server
[rpk=true] alpn=Some("tornect/1") peer_identity_len=44
[rpk=true] exporter OK (32 bytes, equal on both ends, distinct per connection)
[rpk=true] max_datagram_size right after handshake: Some(1351) (initial_mtu=1200)
[rpk=true] max_datagram_size after MTU discovery: Some(1414) (upper_bound default 1452)
[rpk=true] rebind OK; B now sees A at 127.0.0.1:54270
[extra] client pins wrong server key -> client got Some(TransportError(Error { code: Code::crypto(30), frame: None, reason: "invalid peer certificate: UnknownIssuer" })) after 894.877µs; server got Ok(Err("aborted by peer: the cryptographic handshake failed: error 48: invalid peer certificate: UnknownIssuer"))
[extra] server pins wrong client key -> client got None after 895.168µs; server got Ok(Err("the cryptographic handshake failed: error 48: invalid peer certificate: UnknownIssuer"))
[extra] initial_mtu=1350, discovery off: max_datagram_size=Some(1312) path_mtu=1350
[extra] initial_mtu=1200, discovery off: max_datagram_size=Some(1162) path_mtu=1200
ALL OK
```

What the probe exercises: seed→PKCS#8→rcgen KeyPair→self-signed Ed25519 X.509; SPKI equality
across hand-built/webpki/rustls; mutual pinned TLS in X.509 and RPK modes; one socket2-bound
socket per endpoint with server+client roles; simultaneous open; ALPN; `peer_identity()`
downcast; `export_keying_material`; max-size datagram send/receive; `TooLarge` on +1 byte;
bi-stream; `rebind()` mid-connection; BBR + keep-alive + idle timeout; wrong-pin failure timing.
Source: `/tmp/probe-quic/src/main.rs` (temporary; the snippets above are lifted from it).

---

## 12. Gotchas (collected)

1. **Two crypto providers = panic.** Any `rustls` with default features in the workspace pulls
   `aws-lc-rs`; rustls then refuses to pick a default provider. Use `default-features = false,
   features = ["ring","std"]` everywhere, `builder_with_provider` in our code, and
   `ring::default_provider().install_default()` at startup for third parties. Check with
   `cargo tree -i aws-lc-sys` in CI (should be empty).
2. **Server must poll `accept()` and take each `Incoming`**, else clients hang to
   `max_idle_timeout`. Also `refuse()` unexpected peers early (before TLS) to save CPU.
3. Server-side client-cert rejection is **not** visible in the client's `Connecting` result —
   the client sees a connection that closes right after it was established.
4. `send_datagram` silently **drops the oldest** queued datagrams when
   `datagram_send_buffer_size` is exceeded — good for video (stale frames die), but check
   `datagram_send_buffer_space()` and pace; `send_datagram_wait` instead back-pressures.
5. `max_datagram_size()` changes over the connection (DPLPMTUD up, black-hole down). Re-read per
   frame. Peer-advertised `max_datagram_frame_size` is derived from *their*
   `datagram_receive_buffer_size`; `None` there disables datagrams entirely.
6. Simultaneous open produces two connections; define a tie-break.
7. `rustls-log` feature (quinn) / `logging` (rustls) is needed to see rustls' own debug logs; the
   probe had it off and TLS failures appeared only as quinn-proto "closing connection due to
   transport error".
8. `Endpoint::client("[::]:0")` = dual-stack only if the OS allows; Windows wildcard v6 is not
   dual-stack by default (`endpoint.rs:100-104` doc). Bind per family or two endpoints.
9. `ring::constant_time::verify_slices_are_equal` is deprecated (compiler warning); use
   `subtle::ConstantTimeEq`.
10. rcgen 0.14.9 requires **Rust 1.88** (fine here) and its default `pem` feature pulls `pem`;
    drop it. rcgen `CertificateParams::default()` already uses 1975→4096 validity, so no clock
    issues even in X.509 mode.
11. `quinn-udp` GSO on VMware/vmxnet3 or under packet-inspecting tools may cause a startup loss
    burst; keep `enable_segmentation_offload` configurable.
12. `keep_alive_interval` only needs one side, but for NAT bindings during idle (e.g. paused
    stream) 2 s is a reasonable value; `max_idle_timeout` must exceed it on **both** peers.
13. `TransportConfig::initial_rtt` lower than the real RTT causes spurious PTO retransmits of the
    Initial — 100 ms is a fair compromise; the punch engine, not QUIC, should decide when to
    retry across candidate pairs.
14. Plan §B.2 says "paced bidirectional QUIC Initial+padding to all candidate pairs": with quinn
    this means concurrent `connect_with()` per pair (each is a separate connection attempt with its
    own random CIDs — fine) — but *the server-side* attempts also need the accept loop. Simpler
    and NAT-safer: send **non-QUIC** punch probes both ways first (§9 demux), then dial only the
    validated pair.

---

## 13. Open questions

1. **RPK vs X.509 final call.** RPK is strictly simpler and verified; the only argument for X.509
   is future interop with non-Tornect clients (browsers can't do either with self-signed pins
   anyway). Recommend RPK; keep the rcgen path in a feature flag until M2 proves nothing needs it.
2. Tie-break / role assignment for simultaneous open (or make the host always the QUIC server
   and use only client→host, with both sides pre-punching). Needs a decision in §B.2.
3. Whether to implement the STUN/punch demux `AsyncUdpSocket` in M1 or start with two sockets
   (STUN socket separate — breaks NAT-mapping consistency on symmetric NATs; only OK for a demo).
4. Do we want 0-RTT for reconnects (`enable_early_data`/`max_early_data_size = u32::MAX` are set;
   quinn's `Connecting::into_0rtt()` exists) — replay-safety of our `ctrl` messages must be
   reviewed first; keep off in v1.
5. BBR vs Cubic default for media — needs the netem harness (§D.5) to decide; BBR is flagged
   experimental upstream.
6. Datagram receive path performance at 100k pps (`read_datagram` returns one `Bytes` per await
   through a mutex-protected state) — measure in M3; if insufficient, drive `quinn-proto`
   directly (sans-IO) instead of `quinn`.
7. QAD/QNT via `noq`: re-evaluate after M4 if direct-connect rates disappoint.
