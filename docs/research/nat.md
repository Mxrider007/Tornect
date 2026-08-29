# NAT traversal helpers — research note (verified 2026-08-28)

Scope: `tornect-net` candidate gathering + port mapping + STUN + hole punch (plan §A.3 D6,
§A.4 items 3/5, §B.2 CANDIDATES/punch, §C M2, §D.5 netem harness). Everything below was
checked against crate sources extracted into `/tmp/crates-src/<crate>-<ver>/` (downloaded
from `static.crates.io`) and a probe crate at `/tmp/probe-nat` that was **compiled and run on
this VM** (Rust 1.96, no sudo, no cmake/nasm/libclang needed). Line references are into the
extracted sources. Companion note: `docs/research/quic.md` (same-socket demux, quinn
`AsyncUdpSocket`).

---

## 0. TL;DR for implementers

| Item | Decision |
|---|---|
| UPnP IGD | `igd-next = "=0.17.1"`, `features = ["aio_tokio"]`, `default-features = false`. `igd_next::aio::tokio::search_gateway(SearchOptions)` → `Gateway<Tokio>` with `get_external_ip()`, `add_any_port()`, `add_port()`, `remove_port()`. Verified live against the VM's router. |
| NAT-PMP + PCP | **`crab_nat = "=0.8.1"`** (pure Rust, tokio, PCP-first with NAT-PMP fallback, proper timeouts, nonce, renew, delete). **Do not use `natpmp 0.5.0`**: no PCP, its async `read_response_or_retry()` has no timeout, and it drags `netdev 0.31` (netlink/winapi) in. Gateway IP discovery is *not* part of crab_nat — see §2.2.4. |
| STUN | `stun = "=0.17.2"` (webrtc-rs) used **sans-IO**: build `Message` → send `msg.raw` on our own `tokio::net::UdpSocket` → `Message::unmarshal_binary` → `XorMappedAddress::get_from`. Do **not** use its `Client` (it needs `webrtc-util::Conn` + its own recv loop and would steal the socket from the QUIC/punch demux). It hard-depends on tokio + ring 0.17.14 + rand 0.9 (all already in tree). Leaner alternative: `stun_codec 0.4.0` (§2.3.4). |
| Local addresses | `if-addrs = "=0.15.0"` (default features; the `link-local` feature *enables* returning fe80::/169.254 — leave it off). Filter: `!is_loopback() && is_oper_up() && !is_p2p()` (+ optional v6 ULA/temporary filtering). `IfChangeNotifier` for Wi‑Fi→Ethernet migration (not on macOS). |
| Socket | `socket2 = "=0.6.5"` (feature `"all"` only if `set_reuse_port` is wanted). `Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))` → `set_nonblocking(true)` → `bind` → `std::net::UdpSocket::from` → `tokio::net::UdpSocket::from_std`. **Do not set `SO_REUSEADDR`** on the media socket (Windows port-hijack semantics, and we don't need it: one socket for STUN + punch + QUIC). |
| STUN servers (default, user-editable) | `stun.l.google.com:19302` (Google), `stun.cloudflare.com:3478` (Cloudflare), `global.stun.twilio.com:3478` (Twilio), `stun.nextcloud.com:443` (Nextcloud GmbH). Both returned identical reflexive `ip:port` for one socket on this VM (EIM NAT). |
| Punch pacing | Mirror ICE: one probe per **Ta = 50 ms** (never faster than 5 ms), STUN-style retransmit **RTO ≥ 500 ms doubling** (Rc = 7), ≤ 100 candidate pairs, keepalive every **15–25 s** once connected (NAT UDP timeouts: RFC 4787 says ≥ 2 min; Tailscale reports 30 s in practice). Budget: 4 s per plan §B.2 then Tor fallback. |
| draft-seemann-quic-nat-traversal | **Expired individual draft, -02 (2024-03-03)**, never adopted by the QUIC WG; no `draft-ietf-quic-nat-traversal`. It specifies *no* probe pacing — it delegates to QUIC path validation (PATH_CHALLENGE) and a server-set concurrency limit. Usable as design reference only (§4). |
| Test harness | Linux `ip netns` + `veth` + `tc qdisc … netem` + `iptables -t nat -j MASQUERADE [--random-fully]`. **Requires root/CAP_NET_ADMIN → not runnable on this VM; GitHub Actions `ubuntu-latest` runners have passwordless sudo.** Commands in §7. |

---

## 1. Versions, features, and why

### 1.1 Latest versions (crates.io API, 2026-08-28)

| crate | latest | date | rust-version | notes / source |
|---|---|---|---|---|
| igd-next | **0.17.1** | 2026-06-01 | 1.75 | https://crates.io/api/v1/crates/igd-next — features `{"aio_tokio": ["futures","tokio","hyper","hyper-util","http-body-util","bytes","http"], "default": []}` |
| natpmp | 0.5.0 | 2024-11-06 | — | https://crates.io/api/v1/crates/natpmp — features `{"default":["tokio"],"tokio":["dep:tokio"],"async-std":[...],"all":[...]}`; unmaintained since 2024-11 |
| crab_nat | **0.8.1** | 2026-07-06 | — | https://crates.io/api/v1/crates/crab_nat — no features except optional `tracing`; repo https://github.com/ryco117/crab_nat |
| stun (webrtc-rs) | **0.17.2** | 2026-07-20 | — | https://crates.io/api/v1/crates/stun — features `{"bench":[],"default":[]}`; note version jump 0.9.0 → 0.17.0 (2026-01-31) to align with the webrtc-rs workspace |
| stun_codec | 0.4.0 | 2025-05-06 | — | https://crates.io/api/v1/crates/stun_codec — no features |
| stunclient | 0.4.2 | 2025-12-09 | — | https://crates.io/api/v1/crates/stunclient — features `{"async":["tokio"],"default":["async"]}` |
| if-addrs | **0.15.0** | 2026-02-08 | — | https://crates.io/api/v1/crates/if-addrs — features `{"link-local": []}` |
| socket2 | **0.6.5** | 2026-07-13 | 1.70 | https://crates.io/api/v1/crates/socket2 — features `{"all": []}` |
| netdev | 0.46.1 | 2026-08-14 | — | https://crates.io/api/v1/crates/netdev — candidate for default-gateway discovery (NOT extracted/verified here; see §2.2.4 and open questions) |
| pcp | 0.2.0 | 2016-09-18 | — | https://crates.io/api/v1/crates/pcp — dead (2016), ignore |

### 1.2 Recommended pins

```toml
[dependencies]
# UPnP IGD (WANIPConnection:1/2). aio_tokio pulls hyper 1 + hyper-util (HTTP/1.1 client, no TLS).
igd-next = { version = "=0.17.1", default-features = false, features = ["aio_tokio"] }
# NAT-PMP (RFC 6886) + PCP (RFC 6887), tokio-native, pure Rust.
crab_nat = { version = "=0.8.1" }                 # add features = ["tracing"] for retry logs
# STUN codec (RFC 8489). Used sans-IO; its Client is not used.
stun = { version = "=0.17.2", default-features = false }
# Local interface enumeration + change notifier.
if-addrs = { version = "=0.15.0" }                # do NOT enable "link-local"
# Socket construction.
socket2 = { version = "=0.6.5" }                  # add features = ["all"] only if set_reuse_port is needed
tokio = { version = "1", features = ["rt-multi-thread", "net", "time", "sync", "macros"] }
rand = "0.10"                                     # our own randomness (stun uses rand 0.9 internally, fine)
```

Do **not** add `natpmp`, `stunclient`, or `pcp`.

### 1.3 Why these

- **igd-next** is the maintained fork of `igd` (same author lineage: "Darius C, Simon Bernier St-Pierre", `igd-next-0.17.1/Cargo.toml:17-20`), actively released (0.17.0 2026-03, 0.17.1 2026-06), 13.9 M downloads. The `aio_tokio` feature gives a `Gateway<Tokio>` whose methods are `async fn` (`src/aio/gateway.rs`). The sync API (`igd_next::search_gateway`, `src/search.rs`) uses blocking `std::net::UdpSocket` + `attohttpc` — never call it from the tokio runtime.
- **crab_nat** implements both RFC 6886 and RFC 6887 with `tokio::time::timeout` around every UDP exchange (`src/lib.rs:429-499` `try_send_until_response`), PCP nonce validation (`src/pcp/mod.rs:1094-1101`), and a `PortMapping` handle with `renew()` / `try_drop()` (`src/lib.rs:248-321`). Deps: `bytes 1.12`, `displaydoc 0.2`, `num_enum 0.7`, `rand 0.10.2`, `thiserror 2`, `tokio 1.52 [io-util, net, time]` (`crab_nat-0.8.1/Cargo.toml:37-59`) — all already in the Tornect tree or trivial.
- **natpmp 0.5.0** rejected: (a) NAT-PMP only, no PCP (`src/lib.rs:1-4`); (b) async `read_response_or_retry()` loops `self.s.recv(&mut buf).await` with **no timeout** and increments `retries` only on *socket error* — if the gateway silently drops (no ICMP), it blocks forever (`src/asynchronous.rs:147-208`); (c) IPv4-only; (d) depends on `netdev 0.31.0` which on Linux pulls `netlink-packet-core/route/utils`, `netlink-sys`, on macOS `system-configuration`, on Windows `winapi` + `windows-sys 0.52/0.59` (`natpmp-0.5.0/Cargo.lock`); (e) lists `cc` as a build-dependency with `build = false` (`Cargo.toml:77-78`) — harmless but a smell; (f) last release 2024-11-06.
- **stun 0.17.2** is the webrtc-rs codec: `Message` with zero-copy `raw: Vec<u8>` (`src/message.rs:60-66`), `XorMappedAddress` getter/setter (`src/xoraddr.rs:65-168`), `is_message()` for demux (`src/message.rs:50-52`), `TransactionId` (`src/agent.rs:85-95`). Downsides: hard deps on `tokio` with `["fs","io-util","io-std","macros","net","parking_lot","rt","rt-multi-thread","sync","time"]`, `webrtc-util 0.17 [conn]`, `ring 0.17.14`, `rand 0.9`, `thiserror 1`, `md-5`, `crc 3`, `base64 0.22`, `lazy_static` (`stun-0.17.2/Cargo.toml:53-99`). `ring 0.17.14` is the exact version quinn/rustls already use (quic.md §1.1), so no duplicate.
- **stun_codec 0.4.0** (sile) is the lean alternative: deps `bytecodec 0.5`, `byteorder`, `crc 3`, `hmac 0.12.1`, `md5 0.7`, `sha1 0.10.6`, `trackable 1` (`stun_codec-0.4.0/Cargo.toml:35-54`) — no tokio, no ring. It also has RFC 5780 attributes (`src/rfc5780/attributes.rs`: `ChangeRequest`, `ResponseOrigin`, `OtherAddress`, `ResponsePort`) for NAT-behaviour discovery. Note `hmac 0.12` / `sha1 0.10` are the *old* RustCrypto generation; Tornect's crypto stack is on `digest 0.11` / `hmac 0.13` / `sha2 0.11` (see `/tmp/crates-src/hmac-0.13.0`), so stun_codec would add a second RustCrypto generation to the tree (compile-time only, but it is dup-crate noise). `stun 0.17.2` uses `md-5 0.10` (same old generation) — equally dup. Neither affects correctness.
- **stunclient 0.4.2** is a 300-line convenience wrapper over stun_codec that creates its own request/retry loop and needs exclusive `recv_from` on the socket (`src/lib.rs:165-221, 224-251`) — incompatible with a shared demuxed socket. Skip.
- **if-addrs 0.15.0**: `get_if_addrs() -> io::Result<Vec<Interface>>` with `oper_status`, `is_p2p`, `index` (`src/lib.rs:84-140`), no deps beyond `libc` (posix) / `windows-sys 0.61.2` (Windows) (`Cargo.toml:66-79`). 26 M downloads.
- **socket2 0.6.5**: the standard; `quinn` already depends on it (quic.md §1.2).

---

## 2. API usage (copied/adapted from real sources)

### 2.1 igd-next 0.17.1 (`aio_tokio`)

Public surface (`src/lib.rs:8-36`): `SearchOptions`, `PortMappingEntry`, errors
`{AddAnyPortError, AddPortError, GetExternalIpError, GetGenericPortMappingEntryError, RemovePortError, RequestError, SearchError, Error, Result}`,
`Gateway` (sync), `search_gateway` (sync), `pub mod aio` (behind `aio_tokio`), and
`enum PortMappingProtocol { TCP, UDP }`.

`SearchOptions` (`src/common/options.rs:25-45`):

```rust
pub struct SearchOptions {
    pub bind_addr: SocketAddr,          // default 0.0.0.0:0
    pub broadcast_address: SocketAddr,  // default 239.255.255.250:1900
    pub timeout: Option<Duration>,      // whole search, default 10 s (DEFAULT_TIMEOUT)
    pub single_search_timeout: Option<Duration>, // per SSDP response, default 5 s (RESPONSE_TIMEOUT)
}
```

Async gateway (`src/aio/tokio.rs:47-57`, `src/aio/gateway.rs:14-27, 37, 57, 80, 217, 242, 264`):

```rust
pub async fn search_gateway(options: SearchOptions) -> Result<Gateway<Tokio>, SearchError>;

pub struct Gateway<P> { pub addr: SocketAddr, pub root_url: String, pub control_url: String,
                        pub control_schema_url: String, pub control_schema: HashMap<String, Vec<String>>, pub provider: P }

impl<P: Provider> Gateway<P> {
    pub async fn get_external_ip(&self) -> Result<IpAddr, GetExternalIpError>;
    pub async fn get_any_address(&self, protocol: PortMappingProtocol, local_addr: SocketAddr,
                                 lease_duration: u32, description: &str) -> Result<SocketAddr, AddAnyPortError>;
    pub async fn add_any_port(&self, protocol: PortMappingProtocol, local_addr: SocketAddr,
                              lease_duration: u32, description: &str) -> Result<u16, AddAnyPortError>;
    pub async fn add_port(&self, protocol: PortMappingProtocol, external_port: u16, local_addr: SocketAddr,
                          lease_duration: u32, description: &str) -> Result<(), AddPortError>;
    pub async fn remove_port(&self, protocol: PortMappingProtocol, external_port: u16) -> Result<(), RemovePortError>;
    pub async fn get_generic_port_mapping_entry(&self, index: u32) -> Result<PortMappingEntry, GetGenericPortMappingEntryError>;
}
```

`lease_duration` is **seconds; 0 = infinite** (`src/aio/gateway.rs:52, 74, 216`).

Adapted from `examples/aio_tokio.rs:34-63` (verified on this VM, see §8):

```rust
use igd_next::{aio::tokio::search_gateway, PortMappingProtocol, SearchOptions};

let opts = SearchOptions {
    timeout: Some(Duration::from_secs(3)),                // don't block candidate gathering for 10 s
    single_search_timeout: Some(Duration::from_secs(2)),
    ..Default::default()
};
let gw = search_gateway(opts).await?;                     // SearchError::NoResponseWithinTimeout if none
let ext_ip = gw.get_external_ip().await?;                 // IpAddr
// local_addr = the *interface* IP that reaches the gateway + our QUIC socket port
let ext_port = gw.add_any_port(PortMappingProtocol::UDP, local_addr, 7200, "Tornect").await?;
// candidate: SocketAddr::new(ext_ip, ext_port)
// on shutdown / session end:
gw.remove_port(PortMappingProtocol::UDP, ext_port).await.ok();
```

Behaviour details worth knowing (all from source):

- SSDP `M-SEARCH` uses `ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1`, `MX:3` (`src/common/messages.rs:5-9`); SOAP actions target `WANIPConnection:1` (`messages.rs:11-13`). The search loop takes the **first** device that yields control URLs + schema and returns (`src/aio/tokio.rs:66-114`); multi-homed hosts should set `bind_addr` to the LAN interface IP (default binds `0.0.0.0` and the multicast goes out the default route).
- `add_any_port` first tries `AddAnyPortMapping` (IGD v2) if present in `control_schema`, else falls back to `AddPortMapping` with a random external port, retrying up to 20 times on conflict, and once with same-port on error 724 (`src/aio/gateway.rs:86-185`).
- UPnP error-code mapping (`src/common/parsing.rs:243-306`): 606 → `ActionNotAuthorized`, 605 → `DescriptionTooLong`, 718 → `PortInUse` / `ExternalPortInUse` / `NoPortsAvailable`, 724 → `SamePortValuesRequired`, 725 → `OnlyPermanentLeasesSupported`, 728 → `NoPortsAvailable`, 714 → `NoSuchPortMapping`. **Anything else surfaces as `RequestError::ErrorCode(u16, String)`** — the VM's router answered `501: Action Failed` (§8), which is the generic UPnP "internal error"; treat any `Err` as "no UPnP candidate", log at debug, move on.
- On 725 (`OnlyPermanentLeasesSupported`) retry once with `lease_duration = 0` and make sure `remove_port` runs at shutdown.
- HTTP: the tokio provider builds a fresh `hyper_util::client::legacy::Client` per request, plain `http://`, POST with `SOAPAction` header (`src/aio/tokio.rs:26-43`). `attohttpc 0.30` (sync path) is compiled in regardless of features but with `default-features = false` → **no TLS backend is pulled** (verified: no `native-tls`/`rustls`/`openssl` in the probe `Cargo.lock`).
- Error types implement `std::error::Error` + `Display` (`src/errors.rs`). There is a catch-all `igd_next::Error` with `From` impls for each (`errors.rs:465-545`).

### 2.2 NAT-PMP + PCP

#### 2.2.1 crab_nat 0.8.1 (recommended)

Top-level API (`src/lib.rs`):

```rust
pub const GATEWAY_PORT: u16 = 5351;                                  // lib.rs:50
pub const RECOMMENDED_MAPPING_LIFETIME_SECONDS: u32 = 7200;          // lib.rs:53
pub enum InternetProtocol { Udp = 1, Tcp }                            // lib.rs:80-86
pub enum GatewayAddress { IpV4(Ipv4Addr), IpV6(Ipv6Addr, Option<u32>) } // lib.rs:110-116, From<IpAddr>/From<Ipv4Addr>
pub struct TimeoutConfig { pub initial_timeout: Duration, pub max_retries: usize, pub max_retry_timeout: Option<Duration> } // lib.rs:146-156
#[derive(Default)] pub struct PortMappingOptions { pub external_port: Option<NonZeroU16>, pub lifetime_seconds: Option<u32>, pub timeout_config: Option<TimeoutConfig> } // lib.rs:160-169
pub struct PortMapping { .. }                                         // lib.rs:173-202
impl PortMapping {
    pub async fn new(gateway: GatewayAddress, client: IpAddr, protocol: InternetProtocol,
                     internal_port: NonZeroU16, mapping_options: PortMappingOptions) -> Result<Self, MappingFailure>; // lib.rs:212 — PCP first, NAT-PMP fallback only on UnsupportedVersion(NatPmp)
    pub async fn renew(&mut self) -> Result<(), MappingFailure>;      // lib.rs:248
    pub async fn try_drop(self) -> Result<(), (MappingFailure, Self)>; // lib.rs:291
    pub fn gateway(&self) -> GatewayAddress; pub fn protocol(&self) -> InternetProtocol;
    pub fn internal_port(&self) -> NonZeroU16; pub fn external_port(&self) -> NonZeroU16;
    pub fn lifetime(&self) -> u32; pub fn expiration(&self) -> Instant; pub fn gateway_epoch(&self) -> u32;
    pub fn mapping_type(&self) -> PortMappingType;                     // NatPmp | Pcp { client, nonce, external_ip }
}
pub enum MappingFailure { NatPmp(natpmp::Failure), Pcp(pcp::Failure) } // lib.rs:504-510
// modules:
pub async fn natpmp::external_address(gateway: GatewayAddress, timeout_config: Option<TimeoutConfig>) -> Result<Ipv4Addr, natpmp::Failure>; // natpmp/mod.rs:178
pub async fn natpmp::port_mapping(gateway, protocol, internal_port: NonZeroU16, mapping_options) -> Result<PortMapping, natpmp::Failure>;  // natpmp/mod.rs:250
pub async fn natpmp::try_drop_mapping(gateway, protocol, local_port: Option<NonZeroU16>, timeout_config) -> Result<(), natpmp::Failure>; // natpmp/mod.rs:282 (None = drop all)
pub async fn pcp::port_mapping(base: pcp::BaseMapRequest, session_nonce: Option<Nonce>, suggested_external_ip: Option<IpAddr>, mapping_options) -> Result<PortMapping, pcp::Failure>; // pcp/mod.rs:279
pub async fn pcp::peer_mapping(base, session_nonce, suggested_external_ip, remote_address: SocketAddr, mapping_options) -> Result<PeerMapping, pcp::Failure>; // pcp/mod.rs:524 (PEER opcode — useful later for pinholing a known peer)
```

Adapted from `src/lib.rs:8-34` (doc example) and `examples/client.rs:146-197`:

```rust
use crab_nat::{InternetProtocol, PortMapping, PortMappingOptions, TimeoutConfig};
use std::num::NonZeroU16;

let mapping = PortMapping::new(
    gateway_ip.into(),                     // GatewayAddress: default gateway (see 2.2.4)
    local_ip,                              // our IP as seen by the gateway (PCP puts it in the header; server checks it → ADDRESS_MISMATCH)
    InternetProtocol::Udp,
    NonZeroU16::new(quic_port).unwrap(),
    PortMappingOptions {
        lifetime_seconds: Some(7200),
        timeout_config: Some(TimeoutConfig {   // defaults: PCP 1 s ×2 ×2 ×2 (3 retries), NAT-PMP 250 ms doubling (3 retries)
            initial_timeout: Duration::from_millis(500),
            max_retries: 2,
            max_retry_timeout: Some(Duration::from_secs(2)),
        }),
        ..Default::default()
    },
).await?;
// candidate = SocketAddr::new(external_ip, mapping.external_port().get())
//   external_ip: for PCP it's in mapping.mapping_type() (PortMappingType::Pcp { external_ip, .. });
//   for NAT-PMP call crab_nat::natpmp::external_address(gateway, None).await
// renewal: sleep(lifetime/2) then mapping.renew().await   (examples/client.rs:180-184, RFC 6886 §3.3)
// teardown: mapping.try_drop().await
```

Failure semantics observed on this VM (§8): a gateway that runs neither protocol answers with ICMP port-unreachable, and because crab_nat `connect()`s the socket (`src/lib.rs:384-409`) `recv` returns `Failure::Socket(ConnectionRefused)` **immediately** — a fast negative, no 3-second wait. A silently-dropping gateway yields `Failure::Timeout` after the configured retries.

Missing per README (`crab_nat-0.8.1/README.md:41-47`): no listening for NAT-PMP address-change announcements (224.0.0.1:5350), no PCP options, no ANNOUNCE. Fine for us.

#### 2.2.2 natpmp 0.5.0 (documented for completeness, not recommended)

```rust
pub fn get_default_gateway() -> Result<Ipv4Addr>;                                   // lib.rs:54 (netdev)
pub async fn new_tokio_natpmp() -> Result<NatpmpAsync<tokio::net::UdpSocket>>;       // a_tokio.rs:37
pub async fn new_tokio_natpmp_with(gateway: Ipv4Addr) -> Result<NatpmpAsync<UdpSocket>>; // a_tokio.rs:55
impl<S: AsyncUdpSocket> NatpmpAsync<S> {
    pub async fn send_public_address_request(&mut self) -> Result<()>;               // asynchronous.rs:59
    pub async fn send_port_mapping_request(&self, protocol: Protocol, private_port: u16, public_port: u16, lifetime: u32) -> Result<()>; // asynchronous.rs:84
    pub async fn read_response_or_retry(&self) -> Result<Response>;                  // asynchronous.rs:147 — NO TIMEOUT, does not resend
}
pub enum Response { Gateway(GatewayResponse), UDP(MappingResponse), TCP(MappingResponse) } // lib.rs:134
```

If it is ever used, wrap every `read_response_or_retry()` in `tokio::time::timeout` (the probe did; it timed out cleanly).

#### 2.2.3 PCP on the wire (RFC 6887) — in case we ever need to hand-roll

Source: https://www.rfc-editor.org/rfc/rfc6887.html (§7.1, §7.2, §7.4, §8.1.1, §9, §11.1) and crab_nat's encoder `src/pcp/mod.rs:927-956, 863-891, 959-1050`.

```
UDP to <gateway>:5351, max payload 1100 octets (§7). All addresses are 128-bit; IPv4 as ::ffff:a.b.c.d (§5).
Request header (24 B, §7.1):
  u8  version = 2          | u8 R(0)|opcode(7)   | u16 reserved = 0
  u32 requested lifetime (s)
  u8[16] PCP client's IP address (must equal the IP source address the server sees → else ADDRESS_MISMATCH=12)
MAP opcode body (36 B, §11.1):
  u8[12] mapping nonce (random, keep for renew/delete)
  u8  protocol (IANA: 17 UDP, 6 TCP; 0 = all)  | u8[3] reserved
  u16 internal port | u16 suggested external port (0 = any)
  u8[16] suggested external IP (:: = any)
Response header (24 B, §7.2): version=2 | R(1)|opcode | reserved | u8 result code | u32 lifetime | u32 epoch time | u8[12] reserved
MAP response body (36 B): nonce | protocol | reserved[3] | internal port | ASSIGNED external port | ASSIGNED external IP
Result codes (§7.4): 0 SUCCESS, 1 UNSUPP_VERSION, 2 NOT_AUTHORIZED, 3 MALFORMED_REQUEST, 4 UNSUPP_OPCODE, 5 UNSUPP_OPTION,
  6 MALFORMED_OPTION, 7 NETWORK_FAILURE, 8 NO_RESOURCES, 9 UNSUPP_PROTOCOL, 10 USER_EX_QUOTA, 11 CANNOT_PROVIDE_EXTERNAL,
  12 ADDRESS_MISMATCH, 13 EXCESSIVE_REMOTE_PEERS
Retransmission (§8.1.1): IRT 3 s, RT = (1+RAND)*IRT, then RT = 2*RTprev*(1+RAND), RAND ∈ [-0.1,+0.1], MRT 1024 s, MRC 0 (unbounded) — crab_nat uses 1 s initial and 3 retries (pcp/mod.rs:16-33).
Version fallback (§9): "If the version number in the UNSUPP_VERSION response is zero then that means this is a NAT-PMP server" → retry with NAT-PMP; the NAT-PMP and PCP headers share the first 4 bytes, which is how crab_nat detects it (pcp/mod.rs:963-989).
Delete: same MAP with lifetime 0, suggested port 0, suggested IP :: (§15.1; crab_nat pcp/mod.rs:433-477).
```

NAT-PMP (RFC 6886, https://www.rfc-editor.org/rfc/rfc6886.txt): port 5351; external-address request = 2 bytes `[0, 0]`, response 12 bytes; MAP request 12 bytes `[0, op(1=UDP,2=TCP), 0,0, private_port u16, public_port u16, lifetime u32]`, response 16 bytes (natpmp `src/lib.rs:344-371, 373-441`); retry 250 ms doubling, 9 attempts ≈ 64 s ("…after sending its ninth attempt (and then waiting for 64 seconds)… SHOULD conclude that this gateway does not support NAT-PMP"); recommended lifetime 7200 s, renew at half; result codes 0–5; the "Seconds Since Start of Epoch" field going backwards ⇒ gateway rebooted ⇒ "the client MUST immediately renew all its active port mapping leases"; announcements to multicast 224.0.0.1:5350.

#### 2.2.4 Default-gateway discovery (needed by crab_nat; not provided by it)

crab_nat README: "Crab NAT does not determine the gateway address or the local client address… I recommend using netdev" (`README.md:36`); its example uses `netdev::get_default_gateway()` and `netdev::interface::get_default_interface()` (`examples/client.rs:60-123`, dev-dep `netdev 0.45.0`). Latest is `netdev 0.46.1` (2026-08-14). **Not extracted/verified in this session** — before pinning, check its dependency tree on all three OSes (the 0.31 version natpmp uses pulls netlink on Linux, system-configuration on macOS, winapi/windows-sys on Windows). Zero-dependency alternatives per OS: Linux parse `/proc/net/route` (flags & RTF_GATEWAY, dest 00000000); macOS `route -n get default` / `PF_ROUTE` sysctl; Windows `GetBestRoute2`/`GetIpForwardTable2` via `windows-sys`. Cheap heuristic that covers most home routers: for each `if-addrs` IPv4 interface, try `<network>.1` and `<network>.254` — acceptable as a *fallback* only.

### 2.3 STUN

#### 2.3.1 stun 0.17.2 sans-IO (verified in probe; same bytes worked against Google and Cloudflare)

Key items: `Message { pub typ: MessageType, pub length: u32, pub transaction_id: TransactionId, pub attributes: Attributes, pub raw: Vec<u8> }` (`src/message.rs:60-66`);
`Message::new()` pre-allocates a 20-byte header (`message.rs:117-126`); `build(&mut self, setters: &[Box<dyn Setter>])` (`message.rs:424`); `unmarshal_binary(&mut self, data: &[u8])` (`message.rs:136`); `is_message(b: &[u8]) -> bool` = len ≥ 20 && magic cookie at bytes 4..8 (`message.rs:50-52`); `BINDING_REQUEST`, `BINDING_SUCCESS`, `BINDING_ERROR` (`message.rs:525-539`); `TransactionId(pub [u8; 12])` with `TransactionId::new()` = random via `rand::rng().fill` (`src/agent.rs:85-95`); `XorMappedAddress { pub ip: IpAddr, pub port: u16 }` implementing `Getter::get_from(&mut self, m: &Message)` (`src/xoraddr.rs:68-107`); `TextAttribute::new(ATTR_SOFTWARE, String)` (`src/textattrs.rs:38, 77`); `ATTR_XORMAPPED_ADDRESS = 0x0020`, `ATTR_MAPPED_ADDRESS = 0x0001`, `ATTR_SOFTWARE = 0x8022`, `ATTR_FINGERPRINT = 0x8028`, `ATTR_OTHER_ADDRESS = 0x802C`, `ATTR_CHANGE_REQUEST = 0x0003`, `ATTR_RESPONSE_ORIGIN = 0x802b` (`src/attributes.rs:94-131`).

```rust
use stun::agent::TransactionId;
use stun::attributes::ATTR_SOFTWARE;
use stun::message::{is_message, Getter, Message, BINDING_REQUEST, BINDING_SUCCESS};
use stun::textattrs::TextAttribute;
use stun::xoraddr::XorMappedAddress;

// build (adapted from examples/stun_client.rs:50-51 — but see the TransactionId gotcha below)
let tid = TransactionId::new();                              // RANDOM 96-bit id; Box::<TransactionId>::default() is all zeros!
let mut req = Message::new();
req.build(&[Box::new(tid), Box::new(BINDING_REQUEST),
            Box::new(TextAttribute::new(ATTR_SOFTWARE, "Tornect".to_owned()))])?;
sock.send_to(&req.raw, server_addr).await?;                  // 40 bytes with SOFTWARE, 20 without

// parse (in the socket demux: first byte 0..=3 and is_message() ⇒ STUN, else QUIC — RFC 9443)
let mut m = Message::new();
if is_message(&buf[..n]) {
    m.unmarshal_binary(&buf[..n])?;                          // Err on bad cookie / truncated
    if m.typ == BINDING_SUCCESS && m.transaction_id == tid {
        let mut x = XorMappedAddress::default();
        x.get_from(&m)?;                                     // needs `use stun::message::Getter`
        let reflexive = SocketAddr::new(x.ip, x.port);
    }
}
```

`examples/stun_client.rs:48-62` shows the built-in tokio `Client` (`ClientBuilder::new().with_conn(Arc<dyn util::Conn + Send + Sync>).build()`, `client.send(&msg, Some(Arc::new(handler_tx))).await`) — it spawns its own reader on the `Conn`; **we don't use it** because our socket is shared with the punch engine and quinn (quic.md §7).

Also available for RFC 5780 NAT-behaviour probing (optional, v2): `ATTR_OTHER_ADDRESS`/`ATTR_CHANGE_REQUEST`/`ATTR_RESPONSE_ORIGIN` constants exist but only `MappedAddress`/`XorMappedAddress` have typed getters; decode `OTHER-ADDRESS` with `MappedAddress::get_from_as(&m, ATTR_OTHER_ADDRESS)` (`src/addr.rs:61`).

#### 2.3.2 What the STUN request/response looks like (RFC 8489, https://www.rfc-editor.org/rfc/rfc8489.txt)

- Header: 2 bits zero + 14-bit type, 16-bit length, magic cookie `0x2112A442`, 96-bit transaction id (§5: "The most significant 2 bits of every STUN message MUST be zeroes", "The Magic Cookie field MUST contain the fixed value 0x2112A442 in network byte order").
- XOR-MAPPED-ADDRESS (§14.2): "X-Port is computed by XOR'ing the mapped port with the most significant 16 bits of the magic cookie"; IPv4 "X-Address is computed by XOR'ing the mapped IP address with the magic cookie"; IPv6 "…with the concatenation of the magic cookie and the 96-bit transaction ID". Implemented in `stun-0.17.2/src/xoraddr.rs:131-167`.
- Retransmission over UDP (§6.2.1): "retransmit … starting with an interval of RTO, doubling after each retransmission"; "The initial value for RTO SHOULD be greater than or equal to 500 ms"; Rc default 7, Rm default 16; example timeline 0, 500, 1500, 3500, 7500, 15500, 31500 ms, failure at 39500 ms. For candidate gathering we cap far lower (see §5).

#### 2.3.3 Multiple servers, one socket

Send the Binding Request to every configured server **from the same socket** we will punch and run QUIC on (Tailscale: "you have to send and receive STUN packets from the socket that you intend to use for communication" — https://tailscale.com/blog/how-nat-traversal-works/). Use a *different* transaction id per server and keep a `HashMap<TransactionId, server>`. If all servers return the same `ip:port` → endpoint-independent mapping (EIM, good); if they differ → address-(and-port-)dependent mapping (symmetric) → use port prediction (§6). Observed on this VM: Google and Cloudflare both reported `179.190.140.7:61573` (run 1) / `:63230` (run 2) — EIM, new mapping per socket.

#### 2.3.4 stun_codec 0.4.0 (alternative codec, no tokio)

From `stun_codec-0.4.0/README.md:16-43`:

```rust
use bytecodec::{DecodeExt, EncodeExt, Error};
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId};
use stun_codec::rfc5389::{attributes::Software, methods::BINDING, Attribute};

let mut message = Message::new(MessageClass::Request, BINDING, TransactionId::new([3; 12])); // supply your own random 12 bytes
message.add_attribute(Attribute::Software(Software::new("foo".to_owned())?));
let bytes = MessageEncoder::new().encode_into_bytes(message.clone())?;
let decoded = MessageDecoder::<Attribute>::new().decode_from_bytes(&bytes)?.map_err(Error::from)?;
// stunclient-0.4.2/src/lib.rs:149-155: decoded.get_attribute::<XorMappedAddress>().map(|x| x.address())
```

### 2.4 if-addrs 0.15.0

```rust
pub fn get_if_addrs() -> io::Result<Vec<Interface>>;             // src/lib.rs:360 (posix) / :512 (windows)
pub struct Interface { pub name: String, pub addr: IfAddr, pub index: Option<u32>, pub oper_status: IfOperStatus,
                       pub is_p2p: bool, #[cfg(windows)] pub adapter_name: String }   // src/lib.rs:86-108
impl Interface { pub const fn is_loopback(&self) -> bool; pub const fn is_link_local(&self) -> bool;
                 pub const fn ip(&self) -> IpAddr; pub fn is_oper_up(&self) -> bool; pub fn is_p2p(&self) -> bool } // :110-140
pub enum IfAddr { V4(Ifv4Addr), V6(Ifv6Addr) }   // Ifv4Addr { ip, netmask, prefixlen, broadcast }, Ifv6Addr { ip, netmask, prefixlen, broadcast } (:180-218)
pub struct IfChangeNotifier; impl IfChangeNotifier { pub fn new() -> io::Result<Self>;
                 pub fn wait(&mut self, timeout: Option<Duration>) -> io::Result<Vec<IfChangeType>> } // :562-615, NOT on macOS/iOS/BSD/illumos
```

Host-candidate filter (verified in probe; output in §8):

```rust
let host_candidates: Vec<IpAddr> = if_addrs::get_if_addrs()?
    .into_iter()
    .filter(|i| !i.is_loopback() && !i.is_link_local() && i.is_oper_up() && !i.is_p2p())
    .map(|i| i.ip())
    // extra, recommended: drop IPv6 ULA (fc00::/7) unless peer is on the same LAN; drop 100.64.0.0/10 for
    // "public" purposes but KEEP it as a host candidate (it works within the same CGNAT / VPN).
    .collect();
```

Notes: without the `link-local` feature the crate itself already drops `fe80::/10` (posix + windows) and `169.254/16` (windows) at parse time (`src/sockaddr.rs:47-49, 63-66, 73-76`); on posix `oper_status` is derived from `IFF_RUNNING` only (`src/lib.rs:337-341`), on Windows from the real oper status + `DadState == IpDadStatePreferred` (`:380`). `IfChangeNotifier::wait` is **blocking** — run it on `tokio::task::spawn_blocking` and re-gather candidates / trigger QUIC path migration (quic.md) on `Added`/`Removed`.

### 2.5 socket2 0.6.5 → tokio UdpSocket (verified in probe)

```rust
use socket2::{Domain, Protocol, Socket, Type};

fn make_udp(bind: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    let s = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))?; // socket.rs:115
    s.set_nonblocking(true)?;                            // socket.rs:384 — REQUIRED before tokio from_std (tokio udp.rs:220)
    s.set_recv_buffer_size(4 << 20)?;                    // socket.rs:1081 — media bursts; quinn also bumps this
    s.set_send_buffer_size(4 << 20)?;                    // socket.rs:1152
    // s.set_only_v6(false)?  (socket.rs:2080) only if you want one dual-stack v6 socket; simpler: one v4 + one v6 socket
    s.bind(&bind.into())?;                               // socket.rs:168; From<SocketAddr> for SockAddr (sockaddr.rs:340)
    let std_sock: std::net::UdpSocket = s.into();        // From<Socket> for UdpSocket
    tokio::net::UdpSocket::from_std(std_sock)            // tokio-1.53.1/src/net/udp.rs:227
}
```

- `set_reuse_address` (`socket.rs:1125`, SO_REUSEADDR) and `set_reuse_port` (`sys/unix.rs:2237-2255`, **needs feature `"all"`**, not on Solaris/illumos/cygwin) exist. **Don't set them on the media socket.** On Windows SO_REUSEADDR "allows a socket to forcibly bind to a port in use by another socket… A malicious program can use SO_REUSEADDR to forcibly bind sockets already in use… No special privileges are required" (https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse). We only need it for the *TCP* simultaneous-open trick, which we don't do; UDP hole punching uses a single socket for STUN + punch + QUIC.
- To hand the same socket to quinn: `Endpoint::new(EndpointConfig, Some(server_cfg), std_udp_socket, Arc::new(TokioRuntime))` (quic.md §0/§7) — so create it with socket2 as above, keep a `try_clone()`d std handle (or wrap in a custom `AsyncUdpSocket`) for the STUN/punch engine.

---

## 3. Public STUN servers (default list; user-editable; may be emptied)

| Server | Operator | Source | Notes |
|---|---|---|---|
| `stun.l.google.com:19302` (also `stun1`–`stun4.l.google.com:19302`) | Google | Default entry in the official WebRTC samples: `option.value = '{"urls":["stun:stun.l.google.com:19302"]}'` (https://raw.githubusercontent.com/webrtc/samples/gh-pages/src/content/peerconnection/trickle-ice/js/main.js line 41); also the default in `stun-0.17.2/examples/stun_client.rs:26` and `stunclient-0.4.2/src/lib.rs:87` | Non-standard port 19302; no published ToS for standalone use — it has been the de-facto public server for 10+ years. Answered from `74.125.250.129` in our probe. |
| `stun.cloudflare.com:3478` (alt `:53`) | Cloudflare | https://developers.cloudflare.com/realtime/turn/ — "STUN over UDP \| stun.cloudflare.com \| 3478/udp \| 53/udp"; "Use of alternate port 53 only by itself is not recommended. Port 53 is blocked by many ISPs…" | STUN documented as free alongside Realtime SFU/TURN; TURN is metered ($0.05/GB) and needs credentials, STUN does not. Answered from `162.159.207.0` (anycast) in our probe. |
| `global.stun.twilio.com:3478` | Twilio | https://www.twilio.com/docs/stun-turn — listed as `stun:global.stun.twilio.com:3478` with no credential fields (TURN entries have them) | Not verified live here. |
| `stun.nextcloud.com:443` and `:3478` | Nextcloud GmbH (Talk high-performance backend default) | Present in the hourly-refreshed reachable list https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_hosts.txt (fetched 2026-08-28, 84 hosts) | Port 443/UDP is useful on networks that filter 3478. Not verified live here. |
| `stun.sip.us:3478`, `stun.voip.blackberry.com:3478`, `stun.freeswitch.org:3478` | various (SIP providers / FreeSWITCH project) | same list | Community/SIP servers — fine as extra entries, lower priority. |

Curated live list for the settings UI's "restore defaults" / docs link: https://github.com/pradt2/always-online-stun (`valid_hosts.txt`, `valid_ipv4s.txt`, `valid_ipv6s.txt`, `geoip_cache.txt`, refreshed hourly; removal policy: "My server is on your list, and I don't like it… Open an issue, and it will be removed… within 24 hours"). Do **not** fetch this list at runtime (it would be a third-party dependency / phone-home; plan says no telemetry) — ship a snapshot in the default config.

Etiquette (all stateless, unauthenticated Binding Requests):

1. One request per server per gathering, from the one socket we'll use; retransmit at most 2–3 times with RTO ≥ 500 ms doubling (RFC 8489 §6.2.1) and a hard 2–3 s gathering budget — never the full 39.5 s.
2. Only query when a session is being set up (and for keepalive/re-check on network change), never periodically in the background. Keepalives to the *peer* (not to STUN) keep the NAT mapping alive once connected (RFC 8445 §11: "Agents SHOULD use a Tr value of 15 seconds… MUST NOT use a value smaller than 15 seconds").
3. Send `SOFTWARE = "Tornect/<ver>"` so operators can identify traffic; do not send FINGERPRINT/MESSAGE-INTEGRITY (not needed for plain Binding, saves bytes; servers ignore them).
4. Query ≥ 2 servers in parallel (resilience + detects mapping behaviour, §2.3.3); prefer hostnames (operators rotate IPs), resolve both A and AAAA, query IPv6 servers from the v6 socket.
5. Honour the user's list verbatim, allow empty (§A.4 item 3): with no STUN we still have host + UPnP/NAT-PMP/PCP candidates + Tor fallback.
6. Never use the servers for anything but Binding (no TURN allocation attempts).

---

## 4. draft-seemann-quic-nat-traversal — status and mechanics

**Status (IETF datatracker, fetched 2026-08-28, https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/):** revision **-02**, dated **2024-03-03**, "Expired & archived", "Expired Internet-Draft (individual)", authors Marten Seemann and Eric Kinnear; RFC stream/intended status "(None)"; "not endorsed by the IETF and has no formal standing". Only revisions 00/01/02 exist; **`draft-ietf-quic-nat-traversal` does not exist (404)**. The editor's repo https://github.com/marten-seemann/draft-seemann-quic-nat-traversal has 12 open issues and no newer published revision. iroh: the Aug-2025 post https://www.iroh.computer/blog/iroh-on-QUIC-multipath says "QUIC-NAT-TRAVERSAL is highly experimental and we don't expect to follow it exactly"; press coverage of iroh 1.0 (June 2026) says it ships a NAT-traversal extension based on the draft (via their quinn fork, see quic.md). Upstream quinn has nothing (quic.md §0). Conclusion unchanged from quic.md: **do the punch outside QUIC, then hand the socket to quinn.**

**Mechanics (from https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-02.html):**

- Negotiation: transport parameter `nat_traversal (0x3d7e9f0bca12fea6)`; client sends it empty, server sends a varint **concurrency limit** (>0) = max simultaneous punch attempts.
- Frames (all ack-eliciting): `ADD_ADDRESS (0x3d7e90/0x3d7e91)` server→client `{Sequence Number (i), IPv4|IPv6, Port(16)}`; `PUNCH_ME_NOW (0x3d7e92/0x3d7e93)` client→server `{Round (i), Paired With Sequence Number (i), IPv4|IPv6 address, Port(16)}`; `REMOVE_ADDRESS (0x3d7e94)` server→client `{Sequence Number (i)}`.
- Address advertisement: only the server advertises (trickle style — "It SHOULD NOT wait until address candidate discovery has finished, instead, it SHOULD send address candidates as soon as they become available"); "Since address matching is run on the client side, address candidates are only sent from the server to the client"; pairing "similar to ICE Section 5.1" but endpoints need not agree on the algorithm.
- Punch: client sends `PUNCH_ME_NOW` for a pair and "SHOULD start path validation immediately after sending"; server "SHOULD start path validation immediately upon receipt" — i.e. **the probes are QUIC PATH_CHALLENGE/PATH_RESPONSE packets on the new 4-tuple** (RFC 9000 §8.2), sent by *both* sides at once = simultaneous open.
- Rounds/concurrency: "For every round, the client MUST NOT send more PUNCH_ME_NOW frames than allowed by the server's transport parameter"; "A new round is started when a PUNCH_ME_NOW frame with a higher Round value is received. This immediately cancels all path probes in progress"; "To speed up NAT traversal, the client SHOULD send address pairs as soon as they become available."
- **Pacing: not specified.** No inter-probe timing; amplification mitigation is literally "TODO" (§4.4.2). So for "mirroring the pacing outside QUIC" the only normative source is ICE (§5 below); the draft contributes the *structure*: trickle addresses, explicit round numbers to cancel stale probes, and a peer-declared concurrency cap.

How Tornect mirrors it over the Tor signaling channel: `CANDIDATES{seq, addr, kind}` (trickle, both directions since we are symmetric), `CANDIDATES_DONE`, plus a small `PUNCH{round, pairs[]}` message from the *initiating* side (tie-break: lower device pubkey = "client" role) carrying its chosen pairs; both sides start probing the listed pairs immediately, higher `round` cancels prior probes; cap concurrent pairs (e.g. 8 in flight).

---

## 5. Simultaneous-open UDP hole punching — procedure and pacing

Sources: RFC 8445 (ICE, https://www.rfc-editor.org/rfc/rfc8445.txt), RFC 8489 §6.2.1, RFC 4787, Tailscale write-up, RFC 9443 demux.

1. **Gather** (in parallel, ≤ 3 s budget): host addrs (if-addrs) → server-reflexive via STUN from the media socket → mapped (crab_nat PCP/NAT-PMP first since it is fastest, then igd-next UPnP; both from the same local port). Trickle each candidate over Tor as soon as it appears (`CANDIDATES`), then `CANDIDATES_DONE`.
2. **Pair & prioritise** (ICE §6.1.2.3 formula `2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)`; type preferences host > reflexive/mapped): same address family only; drop pairs where local is loopback/link-local; order: LAN host↔host, IPv6 host↔host, mapped/reflexive↔reflexive. "The default limit of candidate pairs for the checklist set is 100, but the value MUST be configurable" (RFC 8445 §6.1.2.5).
3. **Probe, paced by Ta**: "ICE agents SHOULD use a default Ta value, 50 ms" and "the combination of all transactions from all agents … MUST NOT be sent more often than once every 5 ms" (§14.2). Every Ta tick take the triggered-check queue first, else the highest-priority Waiting pair (§6.1.4.2 steps 1–4). Retransmit a pair's probe with `RTO = MAX(500 ms, Ta * N * (Num-Waiting + Num-In-Progress))`, doubling, "Agents MUST NOT use an RTO value smaller than 500 ms" (§14.3). With ≤ 20 pairs and 50 ms pacing the first full sweep takes 1 s; the plan's **4 s** window allows ~3 retransmits per pair (0 / 0.5 / 1.5 / 3.5 s) — matches RFC 8489's timeline.
4. **Both sides send at the same time** — the first outbound packet on a pair opens *our* NAT/firewall's mapping/filter for that remote `ip:port` and is normally dropped by the *peer's* NAT (RFC 4787 address-and-port-dependent filtering) unless the peer already sent to us; the peer's packet then passes because ours created the filter entry. Tailscale: "Both endpoints must attempt communication at roughly the same time, so that all the intermediate firewalls open up while both peers are still around." Coordinate start with a `PUNCH{round, t0}` message over Tor (Tor RTT 0.4–1.5 s is fine; probes keep retrying for 4 s).
5. **Probe packet**: either (a) STUN Binding Request/Response with a per-pair transaction id and USERNAME = `session_token`-derived (ICE-lite style; response's XOR-MAPPED-ADDRESS reveals peer-reflexive candidates — RFC 8445 §7.2.5.3.1), or (b) as plan §B.2 says, directly the QUIC Initial (≥ 1200 B padded), letting quinn's handshake *be* the probe. (a) is cheaper (20–40 B), detects prflx candidates, and works before we know which pair to hand to quinn; (b) saves one RTT. Recommended: (a) for the sweep, then start quinn `connect()` on the first pair that gets a valid response (triggered check → nominate), keep probing others for 500 ms as backup. Demux on the shared socket per RFC 9443: first byte 0–3 → STUN (and `stun::message::is_message`), 64–79 (no TURN in use → QUIC), 80–127 and 192–255 → QUIC; "Endpoints that wish to demultiplex QUIC MUST NOT send the grease_quic_bit transport parameter" (quinn doesn't grease by default; quic.md §7).
6. **Role tie-break**: both sides may succeed on different pairs or on the same pair with two QUIC connections (quic.md §0 "simultaneous open… yields 2 connections"). Deterministic rule: the side with the numerically lower device public key is the QUIC *client* and dials; the other only listens. Nominate the first pair whose STUN check succeeded in *both* directions.
7. **Keepalive & mobility**: once connected send a keepalive (QUIC PING or 1-byte datagram) every **15–25 s** ("common value for UDP is 30 seconds" — Tailscale; RFC 4787 REQ-5 "A NAT UDP mapping timer MUST NOT expire in less than two minutes", recommended ≥ 5 min; ICE Tr = 15 s); on `IfChangeNotifier` events re-gather and let quinn migrate (`server_config.migration(true)` default — quic.md).
8. **Give up** at 4 s (plan §B.2) → `TOR_FALLBACK`. Keep probing in the background for another ~10 s and upgrade to direct if a late pair succeeds (optional v1.1).

---

## 6. NAT behaviours and port prediction

Definitions (RFC 4787 §4.1/§5, https://www.rfc-editor.org/rfc/rfc4787.txt):

- **Endpoint-Independent Mapping (EIM)** — "The NAT reuses the port mapping for subsequent packets sent from the same internal IP address and port (X:x) to any external IP address and port." REQ-1: "A NAT MUST have an 'Endpoint-Independent Mapping' behavior." → the STUN-discovered `ip:port` is what the peer must hit. Filtering then decides how hard it is: Endpoint-Independent ("full cone") — peer can send first; Address-Dependent ("restricted") — we must have sent to the peer's *IP* first; Address-and-Port-Dependent ("port-restricted") — we must have sent to the exact `ip:port` first. Simultaneous open with correct candidates solves all three.
- **Address-Dependent / Address-and-Port-Dependent Mapping ("symmetric")** — new external port per destination; the STUN-reported port is *not* the port the peer will see. Detect: two STUN servers report different ports (§2.3.3). Many NATs still allocate ports **sequentially** or **port-preserving** (RFC 4787 §4.2.1 "port preservation"; §4.2.2 "port parity"), so:
  - **Port prediction (easy symmetric)**: query two STUN servers back-to-back; if `port2 = port1 + Δ` with small Δ, advertise `port2 + Δ, +2Δ, … +kΔ` (k ≈ 8–16) as extra reflexive candidates; the peer probes all of them (paced by Ta).
  - **Birthday attack (hard symmetric vs EIM peer)** — Tailscale numbers: the EIM side opens N sockets/ports (e.g. 256) and the symmetric side probes random ports on the EIM side's public IP; probability of a collision: 174 probes → 50 %, 256 → 64 %, 1024 → 98 %, 2048 → 99.9 %; "At 100 packets/sec, half the time we'll get through in under 2 seconds." Symmetric-vs-symmetric: "after 20 seconds… our chance of success is… 0.01 %" → go straight to Tor fallback (plan §A.4 item 5).
  - Our budget (4 s at 20 pps effective with Ta = 50 ms) makes only the Δ-prediction variant realistic in v1; the birthday variant needs a burst mode (~100–200 pps for ≤ 2 s from a *separate* set of sockets, so the media socket's mapping is untouched) — defer to v1.1 behind a config flag; document in "Network" settings.
- **Hairpinning** (REQ-9) — two peers behind the same NAT must be able to use each other's reflexive address; not all NATs do it → always include host (LAN) candidates.
- **CGNAT**: this VM sits behind one — UPnP `GetExternalIPAddress` returned `100.112.128.254` (100.64.0.0/10, RFC 6598) while STUN saw `179.190.140.7` (§8). Consequence: the UPnP/PCP-mapped candidate is only reachable *inside* the ISP's CGNAT; still worth advertising (peer on the same ISP), but rank it below the STUN reflexive candidate, and detect the CGNAT case (`mapped_ip ∈ 100.64/10 || mapped_ip != reflexive_ip`) to show "ISP shares your address (CGNAT)" in the diagnostics UI.

---

## 7. Test harness — Linux netns + tc netem (root/CAP_NET_ADMIN required)

`ip netns` creates "logically another copy of the network stack, with its own routes, firewall rules, and network devices" (https://man7.org/linux/man-pages/man8/ip-netns.8.html). All of `ip netns add`, `ip link add … type veth`, `tc qdisc add`, `iptables -t nat` need CAP_NET_ADMIN → **cannot run on this VM (no sudo)**; it runs on GitHub Actions `ubuntu-latest` (passwordless sudo) — make `tests/netem/run.sh` `exec sudo -n "$0"` itself when not root and `skip` gracefully otherwise. netem syntax from https://man7.org/linux/man-pages/man8/tc-netem.8.html: `delay TIME [JITTER [CORRELATION]] [distribution {uniform|normal|pareto|paretonormal}]`, `loss {random PERCENT [CORRELATION] | gemodel p [r [1-h [1-k]]]}`, `duplicate PERCENT`, `reorder PERCENT [CORRELATION] [gap DISTANCE]`, `corrupt PERCENT`, `rate RATE [PACKETOVERHEAD [CELLSIZE [CELLOVERHEAD]]]`.

Topology: `hostA ─ natA ─ (wan bridge) ─ natB ─ hostB` — four namespaces; each NAT namespace masquerades its LAN. Sketch (`tests/netem/run.sh`, to be finished by qa-engineer):

```bash
set -euo pipefail
# --- namespaces
for ns in hostA natA natB hostB; do ip netns add $ns; ip netns exec $ns ip link set lo up; done
# --- links: hostA<->natA, natA<->natB (WAN), natB<->hostB
ip link add a0 type veth peer name a1;  ip link set a0 netns hostA; ip link set a1 netns natA
ip link add w0 type veth peer name w1;  ip link set w0 netns natA;  ip link set w1 netns natB
ip link add b0 type veth peer name b1;  ip link set b0 netns natB;  ip link set b1 netns hostB
ip netns exec hostA ip addr add 10.1.0.2/24 dev a0;  ip netns exec natA ip addr add 10.1.0.1/24 dev a1
ip netns exec natA  ip addr add 198.51.100.1/24 dev w0; ip netns exec natB ip addr add 198.51.100.2/24 dev w1
ip netns exec natB  ip addr add 10.2.0.1/24 dev b0;  ip netns exec hostB ip addr add 10.2.0.2/24 dev b1
for ns in hostA natA natB hostB; do ip netns exec $ns sh -c 'for d in $(ls /sys/class/net); do ip link set $d up; done'; done
ip netns exec hostA ip route add default via 10.1.0.1;  ip netns exec hostB ip route add default via 10.2.0.1
ip netns exec natA sysctl -qw net.ipv4.ip_forward=1;    ip netns exec natB sysctl -qw net.ipv4.ip_forward=1
# --- NAT behaviour profiles (iptables-nft or nftables)
#   port-restricted cone (EIM + address-and-port-dependent filtering) = default MASQUERADE + conntrack:
ip netns exec natA iptables -t nat -A POSTROUTING -o w0 -j MASQUERADE
ip netns exec natA iptables -A FORWARD -i w0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip netns exec natA iptables -A FORWARD -i w0 -j DROP
#   "symmetric" (new random port per flow) = --random-fully (nf_nat NF_NAT_RANGE_PROTO_RANDOM_FULLY):
ip netns exec natB iptables -t nat -A POSTROUTING -o w1 -j MASQUERADE --random-fully
ip netns exec natB iptables -A FORWARD -i w1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip netns exec natB iptables -A FORWARD -i w1 -j DROP
#   shorten the UDP mapping timeout to exercise keepalives (default 30 s unreplied / 180 s stream):
ip netns exec natA sysctl -qw net.netfilter.nf_conntrack_udp_timeout=30 net.netfilter.nf_conntrack_udp_timeout_stream=30
# --- impairment on the WAN link (both directions: apply on w0 and w1 egress)
PROFILE=${1:-fiber}
case $PROFILE in
  fiber)      NETEM="delay 5ms 1ms distribution normal loss random 0.01%" ;;
  flaky-wifi) NETEM="delay 30ms 15ms distribution normal loss random 1% reorder 2% 50% rate 20mbit" ;;
  hotel)      NETEM="delay 120ms 40ms distribution normal loss gemodel 3% 30% rate 4mbit" ;;
esac
ip netns exec natA tc qdisc add dev w0 root netem $NETEM
ip netns exec natB tc qdisc add dev w1 root netem $NETEM
# --- a STUN "server" on the WAN for reflexive discovery: run our own tiny binding responder in natA/natB (or a 5th ns 'internet')
# --- run
ip netns exec hostA target/debug/tornect --headless host  --stun 198.51.100.9:3478 --stats-json /tmp/a.json &
ip netns exec hostB target/debug/tornect --headless client --stun 198.51.100.9:3478 --stats-json /tmp/b.json
# --- teardown
for ns in hostA natA natB hostB; do ip netns del $ns; done
```

Notes: iptables `MASQUERADE --random-fully` is the standard way to emulate address-and-port-dependent mapping; conntrack-based FORWARD rules give address-and-port-dependent filtering (port-restricted); to emulate a *full-cone* NAT use `DNAT` static rules instead. Verify the emulated behaviour with our own RFC 5780-style check (two STUN responders on different WAN IPs) before trusting the matrix. Double-NAT/CGNAT = add a third NAT namespace in front of natA. Signaling in the harness: the Tor onion path is replaced by a direct localhost mock (plan §B.1 `tests/integration/… signaling-over-localhost-tor mocks`).

---

## 8. Probe results on this VM (`/tmp/probe-nat`, built + run 2026-08-28)

`cargo build` (debug, `CARGO_BUILD_JOBS=2`) with `igd-next 0.17.1 [aio_tokio]`, `natpmp 0.5.0 [tokio]`, `crab_nat 0.8.1`, `stun 0.17.2`, `if-addrs 0.15.0`, `socket2 0.6.5 [all]`, `tokio 1.53.1`, `rand 0.10.2`: **success**, no C toolchain requirements beyond what `ring 0.17.14` (already required by rustls) needs. Dependency tree highlights (`cargo tree`): `hyper 1.11.1`, `hyper-util 0.1.20`, `attohttpc 0.30.1` (no TLS), `webrtc-util 0.17.2`, `ring 0.17.14`, `rand 0.9.5` **and** `rand 0.10.2` (both; from stun/stunclient vs igd-next/crab_nat), `thiserror 1.0.69` and `2.0.20` (both), `netdev 0.31.0` (from natpmp only — disappears when natpmp is dropped).

Run output (abridged):

```
if ens33  192.168.15.50                          up=true p2p=false usable=true
if ens33  2804:2140:e807:a300:20c:29ff:fee7:26ce up=true p2p=false usable=true   (lo/::1 filtered out)
bound 0.0.0.0:56859
stun request 40 bytes, tid=TransactionId([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])   <-- Box::<TransactionId>::default() bug, see §9
stun encode/decode roundtrip ok
stun.l.google.com:19302 (74.125.250.129:19302): reflexive 179.190.140.7:61573
stun.cloudflare.com:3478 (162.159.207.0:3478):   reflexive 179.190.140.7:61573     <-- same mapping ⇒ EIM
igd gateway 192.168.15.1:52869 ctrl /upnp/control/WANIPConn1
igd external ip 100.112.128.254                                                    <-- CGNAT (100.64/10) behind the home router
igd add_any_port err Request error. Gateway response error 501: Action Failed     <-- router refuses mappings
natpmp default gateway 192.168.15.1
natpmp timeout (no NAT-PMP on gateway)                                             <-- only because we wrapped it in timeout()
crab_nat err PCP(UDP socket error: Connection refused (os error 111))              <-- ICMP unreachable ⇒ instant negative
```

Second run gave `179.190.140.7:63230` from both servers (new socket ⇒ new mapping, still EIM).

---

## 9. Gotchas

1. **`Box::<TransactionId>::default()` (as in `stun-0.17.2/examples/stun_client.rs:51`) produces an all-zero transaction id** (`#[derive(Default)]` on `TransactionId(pub [u8; 12])`, `src/agent.rs:84-85`). Use `TransactionId::new()` (random) or `msg.new_transaction_id()` (`src/message.rs:145`). Servers still answer, but you cannot match responses to requests and it is trivially spoofable.
2. `stun::xoraddr::XorMappedAddress::get_from` needs the `stun::message::Getter` trait in scope (compile error E0599 otherwise — hit in the probe).
3. `stun` 0.17.2 forces tokio features `fs, io-std, parking_lot, rt-multi-thread, …` on the whole workspace's tokio (feature unification) and pulls `webrtc-util [conn]` (`buffer`, `sync` — `webrtc-util-0.17.2/Cargo.toml:30-35`). Acceptable; switch to `stun_codec` if binary size/compile time matter.
4. `stun` uses `rand 0.9`, `igd-next`/`crab_nat` use `rand 0.10` → two `rand` versions in the tree (no conflict; `rand_core` 0.9 vs 0.10 likewise). Tornect's own code uses `rand 0.10` / `rand_core 0.10` (see crypto note).
5. `igd_next::search_gateway` (sync) blocks on std sockets + `attohttpc` — never call it on a tokio worker; use `igd_next::aio::tokio::search_gateway`. Default search timeout is 10 s — always override (`SearchOptions { timeout: Some(3 s), single_search_timeout: Some(2 s), .. }`).
6. UPnP lease semantics: `lease_duration` seconds, `0` = permanent; some IGDs return 725 `OnlyPermanentLeasesSupported` → retry with 0 and *always* `remove_port` on exit; some return generic 501 (this VM). IGD v1 routers may reject non-matching internal/external ports (724 → `SamePortValuesRequired`) — `add_any_port` already handles it.
7. The UPnP/PCP external IP may be a CGNAT address (100.64/10) — compare with the STUN reflexive IP; mapped candidates are then only useful intra-ISP.
8. `natpmp 0.5.0` async `read_response_or_retry()` never times out and never resends (`src/asynchronous.rs:147-208`); its sync API is nonblocking-polling with 250 ms×2^n retries (`src/lib.rs:475-500`). Prefer crab_nat.
9. crab_nat `PortMapping::new` falls back to NAT-PMP **only** on `pcp::Failure::UnsupportedVersion(VersionCode::NatPmp)` (`src/lib.rs:231-236`); on `Timeout`/`Socket` it returns immediately — that is the desired fast-fail. If you want NAT-PMP after a PCP timeout, call `crab_nat::natpmp::port_mapping` explicitly.
10. crab_nat PCP requires the *correct* client IP (the one the gateway sees) or the server answers `ADDRESS_MISMATCH` (12) (`src/pcp/mod.rs:1042`); derive it by `UdpSocket::connect(gateway:5351)` + `local_addr()` on a throwaway socket rather than "first interface".
11. crab_nat creates a **new** UDP socket per request (`src/lib.rs:384-409`) — fine (it's the control channel, not the media socket).
12. `if-addrs` with feature `link-local` *includes* `fe80::`/`169.254.` addresses (`src/sockaddr.rs:47-76`) — keep it off. `oper_status` on Linux is only `IFF_RUNNING`-derived; a VPN tun (`is_p2p`) or docker bridge will show up as `Up` — filter `is_p2p()` and, for candidates, prefer interfaces that carry the default route.
13. `IfChangeNotifier::wait` blocks and is unavailable on macOS/iOS (`src/lib.rs:516-541`) — on macOS poll `get_if_addrs()` every few seconds or use `SCNetworkReachability` later.
14. `tokio::net::UdpSocket::from_std` requires the socket to be nonblocking (`tokio-1.53.1/src/net/udp.rs:220`) — set it via socket2 before converting.
15. Windows: `SO_REUSEADDR` allows port hijacking; `SO_EXCLUSIVEADDRUSE` is the secure default (Microsoft doc above). Don't set reuse on the media socket; bind port 0 (ephemeral) unless the user pins a port in settings.
16. RFC 9443 demux: don't enable QUIC grease-bit; STUN first byte is 0–3; both stun crates check the magic cookie (`stun::message::is_message`).
17. Draft-seemann is expired and pacing-free; don't let anyone "implement the draft" inside quinn — the socket-level punch + quinn `Endpoint::new(.., socket, ..)` is the plan.
18. netns/netem harness needs root — not runnable here; keep the harness `skip`-able and run it in CI Linux only.

---

## 10. Open questions

1. **Default-gateway discovery crate**: verify `netdev 0.46.1`'s dependency tree and API (`get_default_gateway()`, `get_default_interface()`) on Linux/macOS/Windows, or write the 3 small OS-specific routines (§2.2.4). Not verified in this session.
2. **STUN codec choice**: `stun 0.17.2` (webrtc-rs, tokio-coupled) vs `stun_codec 0.4.0` (lean, RFC 5780 attrs, old RustCrypto generation). Either works sans-IO; pick once the `tornect-net` demux is written. A 60-line hand-rolled Binding codec (RFC 8489 §5/§14.2) is also viable and would remove both.
3. **Probe packet**: STUN Binding sweep then QUIC (recommended, §5.5) vs QUIC Initial as probe (plan §B.2 wording). Decide in M2; both are compatible with the same-socket demux.
4. **Birthday-attack burst mode** for symmetric NATs (§6): v1.1, needs multi-socket burst + rate cap; measure real-world success first (plan §E: local-only stats).
5. **Twilio / Nextcloud STUN terms**: Twilio lists the server without credentials but without explicit "free for anyone" wording; Nextcloud's is the Talk default. Keep them in the default list but behind Google/Cloudflare, and re-check before 1.0.
6. **IPv6**: with global v6 on both ends (this VM has one), host↔host v6 pairs usually connect with no NAT at all (only stateful firewalls, simultaneous open still needed). Confirm quinn dual-stack handling vs two sockets (quic.md) before M2.
7. **RFC 5780 behaviour discovery** (OTHER-ADDRESS/CHANGE-REQUEST): useful for diagnostics UI ("your NAT: EIM / symmetric"); needs servers that support it (`valid_nat_testing_*` files in always-online-stun). Optional.
