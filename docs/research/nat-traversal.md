# Direct connections: interfaces, STUN, port mapping — research note (started 2026-10-26)

Scope: `tornect-net` local candidates for direct connections (design `direct` revision 4,
§7.1–§7.2; decisions M1-78 and M1-81). Step A1 writes §1 (netdev, which Phase A uses to
read the interface list). Step B1 adds §2 (STUN per RFC 8489 with the RFC 5769 vectors,
the STUN operators and their terms), §3 (crab_nat), §4 (igd-next), §5 (the default
gateway: `GetBestRoute2` and netdev's `gateway` feature), §6 (the Windows firewall) and
§7 (netdev 0.47.0). Everything in §1 was read in the crate sources that cargo unpacked into
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/netdev-0.46.3/` (checksum in
`Cargo.lock`); line numbers point there. Nothing in §1 was run against a live interface
list yet; the rows that need one are NEEDS-DEVICE in `docs/VERIFICATION.md`.

This note supersedes `docs/research/nat.md` §2.4 (if-addrs 0.15.0) for host candidates:
if-addrs gives a name, an address, an index, an oper status and a point-to-point bit,
and nothing else. It has no IPv6 address flags (temporary, deprecated, tentative), no
interface type and no adapter description, which design §7.1 needs to skip VPNs and
to offer a temporary IPv6 address (if-addrs 0.15.0, `src/lib.rs` 86–108, read
2026-10-26).

---

## 0. TL;DR for implementers

| Item | Decision |
|---|---|
| Crate | `netdev = { version = "=0.46.3", default-features = false }` (MIT). 0.47.0 came out on 2026-10-25 and is not adopted (§7) |
| Features | defaults `gateway`, `apple-system-configuration-extra`, `android-extra` all **off**. Since step B1 `gateway` is on for `cfg(not(windows))` only (§1.6, §5.2); Windows reads the gateway with `GetBestRoute2` (§5.1) |
| STUN | hand-written RFC 8489 Binding codec, 20-byte request, no SOFTWARE (§2); vectors in §2.5 |
| Router mapping | crab_nat 0.8.1 (PCP, NAT-PMP; logs nothing; own nonce; never `renew`, §3) and igd-next 0.18.0 `aio_tokio` (UPnP; `#[non_exhaustive]` options; never display its errors; target `igd_next` quiet, §4) |
| Call | `netdev::get_interfaces() -> Vec<Interface>`, synchronous, in `spawn_blocking` under `IFACE_READ_TIMEOUT` (1 s); never `get_default_interface` (needs `gateway`) |
| Kind | `if_type` + `flags` (`IFF_POINTOPOINT`, `IFF_LOOPBACK`) + name/description markers (design §7.1). Windows Wintun and WireGuard-NT are `ProprietaryVirtual` (IF_TYPE 53) with **no** point-to-point flag, so `if_type` must be read; Linux bridges, veth, docker and TAP all report `Ethernet`, so the name lists must be read; Linux WireGuard and `tun` (`ARPHRD_NONE`), `sit` and `gre` report `UnknownWithValue(n)` (§1.3), which "anything else" and `IFF_POINTOPOINT` both put in Tunnel |
| IPv6 flags | `Interface.ipv6_addr_flags[i]` pairs with `Interface.ipv6[i]`; skip `deprecated`, `tentative`, `duplicated`; prefer `temporary`. **No EUI-64 flag**: test `ip[11] == 0xff && ip[12] == 0xfe` |
| Linux flags lost | if netlink fails, netdev falls back to `getifaddrs` and every IPv6 flag reads `false` (§1.3). A `false` temporary flag must never be read as "stable and safe": only the EUI-64 test and the route-source rule decide |
| Windows temporary | `temporary = SuffixOrigin == IpSuffixOriginRandom` (`os/windows/interface.rs:338`). Whether Windows' stable-privacy "Public" address also reports `IpSuffixOriginRandom` is open: NEEDS-DEVICE(windows-ipv6), design row 8 |
| Writes to stderr | `eprintln!` in `os/linux/mtu.rs` 11, 25, 41 (interface names) and `os/windows/flags.rs` 40 (an index); `os/unix/dns.rs` 25 is behind `gateway`. No `log`/`tracing` dependency at all (§1.7) |
| Packets | none with `gateway` off: Linux netlink dumps, macOS `getifaddrs` + ioctls + plist reads, Windows `GetAdaptersAddresses`. The Windows `gateway` path can send ARP (`SendARP`), which is why it is never compiled |

---

## 1. netdev 0.46.3

### 1.1 Version, features, dependencies

- Version 0.46.3 (crates.io), MIT, `LICENSE` in the package; rust-version none declared,
  edition 2024; builds on the workspace's 1.95.
- `[features]` (`Cargo.toml` 30–): `default = ["gateway", "apple-system-configuration-extra",
  "android-extra"]`; `gateway = []`; `android-extra = ["dep:jni", "dep:ndk-context"]`;
  `apple-system-configuration-extra` pulls the optional `objc2`, `objc2-core-wlan` and
  `objc2-foundation` (macOS Wi-Fi names); `serde` is optional. With
  `default-features = false` none of them is on.
- `gateway` gates `src/route` (default route lookups), `get_default_interface()`,
  `get_default_gateway()`, and the `Interface` fields `gateway`, `dns_servers` and
  `default` (they do not exist without it, so code that names them does not compile in
  Phase A).
- Dependencies per target (`Cargo.toml` 94–170): `ipnet` 2.12 and `mac-addr` 0.3
  everywhere; `libc` on `cfg(unix)`; Linux/Android `netlink-packet-core` 0.9,
  `netlink-packet-route` 0.33, `netlink-sys` 0.9; macOS/iOS `objc2-core-foundation` 0.3,
  `objc2-system-configuration` 0.3 (feature `SCNetworkConfiguration`), `plist` 1.10;
  Android `dlopen2` 0.8.2, `once_cell`; iOS `block2`, `dispatch2`; Windows `windows-sys`
  0.61 (`Win32_Foundation`, `Win32_NetworkManagement_IpHelper`, `Win32_Networking_WinSock`
  and neighbours). `build.rs` links the SystemConfiguration framework on macOS and iOS.
- The lock entries this adds are listed in `docs/DEPENDENCIES.md` (Milestone 2 table) and
  the step A1 row of `docs/VERIFICATION.md`.

### 1.2 The API Tornect uses

```rust
pub fn get_interfaces() -> Vec<Interface>;                         // src/interface/mod.rs:27
pub struct Interface {                                              // src/interface/interface.rs:21-128
    pub index: u32,
    pub name: String,               // Windows: the adapter GUID, e.g. "{6B29FC40-...}"
    pub friendly_name: Option<String>,   // Windows "Ethernet 2"; macOS the SystemConfiguration name
    pub description: Option<String>,     // Windows "Wintun Userspace Tunnel", "Hyper-V Virtual Ethernet Adapter"
    pub if_type: InterfaceType,
    pub mac_addr: Option<MacAddr>,
    pub ipv4: Vec<Ipv4Net>,
    pub ipv6: Vec<Ipv6Net>,
    pub ipv6_scope_ids: Vec<u32>,
    pub ipv6_addr_flags: Vec<Ipv6AddrFlags>,  // same order and length as `ipv6`
    pub flags: u32,                 // IFF_* bits; synthesized on Windows (§1.5)
    pub oper_state: OperState,
    pub transmit_speed: Option<u64>, pub receive_speed: Option<u64>,
    pub stats: Option<InterfaceStats>,
    pub mtu: Option<u32>,
    // `gateway`, `dns_servers`, `default`: only with feature `gateway`
    ..
}
impl Interface {
    pub fn is_up(&self) -> bool;            // IFF_UP
    pub fn is_loopback(&self) -> bool;      // IFF_LOOPBACK
    pub fn is_point_to_point(&self) -> bool;// IFF_POINTOPOINT
    pub fn is_tun(&self) -> bool;
    pub fn is_running(&self) -> bool;       // Unix IFF_RUNNING; Windows OperStatus Up
}
pub struct Ipv6AddrFlags {                                          // src/interface/ipv6_addr_flags.rs:22
    pub deprecated: bool, pub temporary: bool, pub tentative: bool,
    pub duplicated: bool, pub permanent: bool,
}
pub enum InterfaceType { Unknown, Ethernet, TokenRing, Fddi, ..., Ppp, Loopback, ...,
    Wireless80211, Tunnel, ..., ProprietaryVirtual /* 53, types.rs:148 */, ...,
    Wwanpp, Wwanpp2, Bridge, Can, PeerToPeerWireless, UnknownWithValue(u32) } // src/interface/types.rs
```

- `get_interfaces()` lists every interface the OS reports, up or down, with or without
  addresses; the caller filters. On Windows the `TryFrom` of each adapter never fails, so
  nothing is dropped silently.
- `ipv6_addr_flags` is filled in the same loop as `ipv6`, one entry per address. No
  platform path makes the two lengths differ; a reader that zips them should still treat
  a mismatch as "flags unknown" and skip the interface's IPv6 addresses.
- There is no EUI-64 flag on any platform. The design's test is on the address bytes:
  `ip.octets()[11] == 0xff && ip.octets()[12] == 0xfe` (the modified EUI-64 `ff:fe` in the
  middle of the interface ID).
- `InterfaceType` is a plain enum whose `TryFrom<u32>` never fails: a number it does not
  know becomes `UnknownWithValue(n)` (`types.rs:313`). The numbers are the OS's own:
  `InterfaceType::value()` has one table per target (`types.rs` 133–168 Windows IANA
  ifType, 173–194 Linux `ARPHRD_*`, then the Apple/BSD one), and `try_from` matches against
  it. Design §7.1's "anything else counts as Tunnel" covers `UnknownWithValue`, and also
  `Bridge` (macOS `bridge*`) and `PeerToPeerWireless` (macOS `awdl*`).

### 1.3 Linux: netlink, sysfs, flags

- **Path.** `os/linux/netlink.rs` 20–60 opens a `NETLINK_ROUTE` socket (`netlink-sys`,
  `bind_auto`), sends `RTM_GETLINK` and `RTM_GETADDR` dump requests and parses the replies;
  `collect_interfaces` (`:237`) merges links and addresses by index. Unprivileged; no
  packet leaves the host. The socket is closed when the call returns.
- **IPv6 flags.** From the `IFA_FLAGS` attribute when present, else the 8-bit
  `ifa_flags` in the message header (`ip_from_addr`, ≈ `:123`), mapped in
  `os/linux/ipv6_addr_flags.rs`: `IFA_F_TEMPORARY` 0x01 → temporary, `IFA_F_DADFAILED`
  0x08 → duplicated, `IFA_F_DEPRECATED` 0x20 → deprecated, `IFA_F_TENTATIVE` 0x40 →
  tentative, `IFA_F_PERMANENT` 0x80 → permanent. (A temporary address that has outlived its
  preferred lifetime is `deprecated` too, so "temporary and not deprecated" is the
  preference.)
- **Fallback.** If netlink fails, `get_interfaces` falls back to `getifaddrs`; then
  `Ipv6AddrFlags` is `Default` (all `false`) for every address
  (`interface/ipv6_addr_flags.rs` 57–62). The selection rules stay safe: EUI-64 is decided
  on the bytes, and a global IPv6 is offered only from the v6 route-source interface.
- **Type.** `os/linux/sysfs.rs` 69–93: `Wireless80211` if `uevent` has `DEVTYPE=wlan` or
  the `wireless`/`phy80211` directories exist; `Wwan` for `DEVTYPE=wwan` or the name
  prefixes `wwan`, `wwp`, `rmnet`, `ccmni`; otherwise the number in
  `/sys/class/net/<if>/type`: `ARPHRD_ETHER` (1) → `Ethernet`, so `br0`, `docker0`,
  `virbr0`, `veth*` and TAP devices all read `Ethernet`; every other value goes through
  `InterfaceType::try_from` against the Linux table (`sysfs.rs` 88–92, `types.rs`
  173–194): `ARPHRD_LOOPBACK` (772) → `Loopback`, `ARPHRD_PPP` (512) → `Ppp`,
  `ARPHRD_TUNNEL` (768, `ipip`) → `Tunnel`; WireGuard and `tun` (`ARPHRD_NONE`, 65534),
  `sit` (776) and `gre` (778) → `UnknownWithValue(n)`, which design §7.1 counts as Tunnel
  (fail closed). `ppp`, WireGuard and `tun` also set `IFF_POINTOPOINT`.
- **Probe (build container, 2026-10-26).** A throwaway binary outside the workspace
  (`netdev = { version = "=0.46.3", default-features = false }`, the workspace's lock,
  printing each interface) ran here as root:
  `lo index=1 if_type=Loopback flags=0x10049 up=true loopback=true p2p=false running=true v4=1 v6=0`,
  `eth0 index=4 if_type=Ethernet flags=0x11043 up=true ... running=true v4=1 v6=0`,
  `ifb0`/`ifb1 if_type=Ethernet flags=0x82 up=false running=false`. The container has no
  IPv6 address, no Wi-Fi, no VPN and no bridge, so the flag, Tunnel and Virtual paths are
  still NEEDS-DEVICE (docs/VERIFICATION.md).
- **Other files read.** `/sys/class/net/<if>/{statistics/*,speed,mtu}`; the
  systemd-networkd state `/run/systemd/netif/{links,leases}/<index>` and NetworkManager
  files under `/run/NetworkManager` and `/etc/NetworkManager/system-connections` for the
  `dhcp` field (`os/linux/dhcp.rs`). The `system-connections` keyfiles hold Wi-Fi keys and
  are readable by root only; Tornect never runs as root on Linux, so the read fails and
  `dhcp` stays `None`. Tornect does not use the field. The MTU fallback is a
  `SIOCGIFMTU` ioctl on a datagram socket (`os/linux/mtu.rs`), with no packet sent.

### 1.4 macOS

- `getifaddrs` for names, flags and addresses; per IPv6 address one `SIOCGIFAFLAG_IN6`
  ioctl on an `AF_INET6` datagram socket (`os/darwin/ipv6_addr_flags.rs`):
  `IN6_IFF_TEMPORARY` 0x80, `IN6_IFF_DEPRECATED` 0x10, `IN6_IFF_TENTATIVE` 0x02,
  `IN6_IFF_DUPLICATED` 0x04. No packet.
- Type: `SIOCGIFFUNCTIONALTYPE` (Wi-Fi, wired, cellular), then name rules
  (`os/darwin/types.rs` 96–110): `utun*`, `gif*`, `stf*` → `Tunnel`; `bridge*` → `Bridge`;
  `awdl*` → `PeerToPeerWireless`. `utun` also has `IFF_POINTOPOINT`.
- Friendly names: `/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist` and
  `preferences.plist` through `plist` (hence `plist`, `quick-xml` and `base64` in the macOS
  graph), with `SCNetworkInterfaceCopyAll` as the fallback. World-readable files; nothing is
  written.
- With `gateway` (Phase B) the default route comes from a routing `sysctl`
  (`os/darwin/route.rs`) and the neighbour table; no packet.
- Not built or run here: `cargo check --target aarch64-apple-darwin` stops in ring's C
  build without an Apple SDK (the existing ledger note); NEEDS-DEVICE(macos).

### 1.5 Windows: `GetAdaptersAddresses`, type, flags, temporary

- **Call.** `os/windows/interface.rs:232`: `GetAdaptersAddresses(AF_UNSPEC,
  GAA_FLAG_INCLUDE_GATEWAYS, ...)` with the usual grow-and-retry buffer. The
  `INCLUDE_GATEWAYS` flag only asks for the gateway list in the reply; nothing is sent.
  `name` is the adapter GUID (`AdapterName`), `friendly_name` the
  `FriendlyName` ("Wi-Fi", "Ethernet 2"), `description` the `Description`
  ("Wintun Userspace Tunnel", "WireGuard Tunnel", "TAP-Windows Adapter V9",
  "Hyper-V Virtual Ethernet Adapter").
- **Type.** `IfType` (the IANA ifType) through `InterfaceType::try_from` (`types.rs` 287–):
  6 `Ethernet`, 71 `Wireless80211`, 23 `Ppp`, 131 `Tunnel`, 24 `Loopback`,
  53 `ProprietaryVirtual` (`types.rs:148`), others `UnknownWithValue`. Wintun and
  WireGuard-NT adapters are 53; TAP-Windows is 6 (`Ethernet`), so only the description
  markers ("tap-windows", "tap-win32", "openvpn") catch it.
- **Flags are synthesized** (`:269–290`): `IFF_UP` when `OperStatus` is Up; `BROADCAST |
  MULTICAST` for Ethernet, TokenRing, Wireless80211 and HighPerformanceSerialBus;
  `POINTOPOINT | MULTICAST` for `Ppp` and `Tunnel`; `BROADCAST | POINTOPOINT | MULTICAST`
  for `Atm`; `LOOPBACK | MULTICAST` for Loopback; **nothing** for every other type,
  including `ProprietaryVirtual`. So on Windows `is_point_to_point()` never catches
  Wintun/WireGuard-NT; the `if_type` rule does.
- **IPv6 flags** (`:334–340`): `deprecated` = `DadState == IpDadStateDeprecated`,
  `tentative` = `IpDadStateTentative`, `duplicated` = `IpDadStateDuplicate`,
  `temporary` = `SuffixOrigin == IpSuffixOriginRandom` (`:338`), `permanent` always
  false. Open question (design NEEDS-DEVICE row 8): Windows 10/11 also generate the
  stable "Public" address with a randomized interface ID (RFC 7217-like,
  `RandomizeIdentifiers` on by default); if that address reports
  `IpSuffixOriginRandom` too, netdev marks both as temporary and Tornect cannot tell
  them apart from netdev alone. The design's preference for the v6 route source
  (Windows' source selection picks the temporary address, RFC 6724 rule 7) keeps the
  offered address the one Windows itself sends from. `netsh interface ipv6 show
  addresses` and `Get-NetIPAddress` (`SuffixOrigin`, `PrefixOrigin`) settle it.
- **The `gateway` path and `SendARP`.** With `gateway` on, for each gateway of an up
  adapter netdev first reads the neighbour cache (`get_neighbor_mac`, `GetIpNetEntry2`
  resolved at run time with `GetProcAddress`, `:130–163`), and when the cache has no
  entry falls back to `get_mac_through_arp` (`:47–68`, called at `:361–365`), which calls
  `SendARP(dst, src, ...)`: a blocking ARP request on the LAN, up to the OS's ARP timeout
  (seconds), on every enumeration. That is a packet Tornect must never send and a stall
  inside `get_interfaces`, so `gateway` is never enabled on Windows; Phase B reads the
  gateway with `GetBestRoute2` in `tornect-platform` (design §8.6).
- **Is-connector check.** `Interface::is_physical()` (`interface/interface.rs:202`) calls
  `os/windows/flags.rs` `is_connector_present`, which calls `GetIfEntry2` and
  `eprintln!`s the index when it fails (`:40`). `get_interfaces` does not call it, and
  Tornect does not call `is_physical()` (design §7.1 has its own Physical rule).

### 1.6 What the Phase B `gateway` feature changes (for B1)

`[target.'cfg(not(windows))'.dependencies] netdev = { workspace = true, features =
["gateway"] }` adds `Interface.gateway` (Linux: netlink `RTM_GETROUTE` dump and the
neighbour table; macOS: routing sysctl), `dns_servers` (`/etc/resolv.conf` on Unix,
`os/unix/dns.rs`, with an `eprintln!` of a bad line at `:25`) and `default`. No packet
on either. B1 re-read these paths and turned it on: §5.2.

### 1.7 Logging and output

- netdev has no `log` or `tracing` dependency, so decision M1-83's quiet-target filter
  (`QUIET_TARGETS`, target `netdev` and `netlink_*`) has nothing to drop from netdev
  itself; `netlink-packet-*` and `netlink-sys` depend on `log` (target names
  `netlink_packet_route`, `netlink_sys`), which the filter covers.
- The `eprintln!` calls write to the process's stderr, outside `tracing`: interface names
  (`os/linux/mtu.rs` 11, 25, 41, on an MTU ioctl failure or a name over `IFNAMSIZ`) and an
  interface index (`os/windows/flags.rs:40`). Names and indexes are not addresses, but
  they are local configuration; step A7 records this as a residual (the GUI has no
  console on Windows; the CLI's stderr is the user's own terminal): docs/VERIFICATION.md,
  "Step A7: netdev's own stderr lines".

### 1.8 Not used, and why

- `get_default_interface()` / `get_default_gateway()`: need `gateway`; the design finds the
  route source with a UDP `connect()` to a documentation address and `local_addr()`.
- `Interface.mac_addr`, `stats`, `dhcp`, speeds: not read; a MAC address must never reach
  a log or the wire.
- if-addrs 0.15.0 (nat.md §2.4): see the introduction.
- netdev 0.47.0 (2026-10-25): a day old at A1; diffed at B1 and not adopted (§7).

---

## 2. STUN (RFC 8489, RFC 5769): what the step B2 codec implements

Read 2026-10-27 at rfc-editor.org and datatracker.ietf.org (RFC 8489, February 2020;
RFC 5769, April 2010) and in the IANA "STUN Attributes" registry (last updated
2024-12-20). Design §6.4 is the codec; this section is its reference.

### 2.1 Message (RFC 8489 §5)

- 20-byte header: two zero bits, a 14-bit type, a 16-bit length, the magic cookie, a
  96-bit transaction ID. "The most significant 2 bits of every STUN message MUST be
  zeroes." "The Magic Cookie field MUST contain the fixed value 0x2112A442 in network byte
  order." The length "MUST contain the size of the message in bytes, not including the
  20-byte STUN header", and "Since all STUN attributes are padded to a multiple of 4
  bytes" its last two bits are zero.
- The class is two bits spread through the type: "A class of 0b00 is a request, a class of
  0b01 is an indication, a class of 0b10 is a success response, and a class of 0b11 is an
  error response." The Binding method is 0x001, so the types are request `0x0001`,
  success `0x0101`, error `0x0111`; byte 0 of any Binding message is `0x00` or `0x01`,
  inside the RFC 9443 STUN range 0–3 that design §6.3 demultiplexes on.
- Tornect's request is the bare header: `00 01 | 00 00 | 21 12 A4 42 | txid[12]`, 20 bytes,
  no attributes (§2.6).

### 2.2 Sending over UDP (RFC 8489 §6.2.1)

- "the initial value for RTO SHOULD be greater than or equal to 500 ms"; "Rc SHOULD be
  configurable and SHOULD have a default of 7"; "Rm SHOULD be configurable and SHOULD have
  a default of 16"; "Ti SHOULD be configurable and SHOULD have a default of 39.5 s".
- Design §7.3: `STUN_RTO = 500 ms` (the floor), a second server only if the first is silent
  at 750 ms, at most 4 requests to at most 2 servers per session, all inside
  `GATHER_BUDGET`. Rc, Rm and Ti are "configurable" defaults, so a shorter transaction is
  within the RFC; giving up early only loses the srflx candidate.

### 2.3 Receiving (RFC 8489 §6.3, §6.3.3, §6.3.4)

- Success response (§6.3.3): "If the success response contains unknown
  comprehension-required attributes, the response is discarded and the transaction is
  considered to have failed."
- Error response (§6.3.4): with unknown comprehension-required attributes, or without
  ERROR-CODE, "the transaction is simply considered to have failed". Design §6.4 reads any
  `0x0111` as `ErrorResponse` and never retries that server, so the ERROR-CODE value is not
  needed.
- **Citation.** Design §6.4 cites "RFC 8489 §7.3.3" for the discard rule. That is the
  RFC 5389 numbering (RFC 5389 §7.3.3 "Processing a Success Response"); in RFC 8489 the
  section is **§6.3.3**. Step B2's code cites §6.3.3.

### 2.4 Attributes (RFC 8489 §14, §18.3; IANA registry)

- TLV: 16-bit type, 16-bit length (of the value, before padding), the value padded to a
  multiple of 4. "Attributes with type values between 0x0000 and 0x7FFF are
  comprehension-required attributes"; those in 0x8000–0xFFFF are comprehension-optional:
  an implementation that does not understand one may ignore it.
- MAPPED-ADDRESS `0x0001` (§14.1): one zero byte, the family ("0x01:IPv4", "0x02:IPv6"), the
  port, then 4 or 16 address bytes (value length 8 or 20).
- XOR-MAPPED-ADDRESS `0x0020` (§14.2): the same layout; X-Port is the port XOR the top 16
  bits of the cookie (`0x2112`); the IPv4 address is XOR the cookie, the IPv6 address XOR
  cookie ‖ transaction ID. (The fetched text broke off inside §14.2; the XOR rule was
  checked by decoding both RFC 5769 responses, §2.5.)
- Registry values the codec names: `0x0004` Reserved (formerly SOURCE-ADDRESS), `0x0005`
  Reserved (formerly CHANGED-ADDRESS), `0x0006` USERNAME, `0x0008` MESSAGE-INTEGRITY,
  `0x0009` ERROR-CODE, `0x001C` MESSAGE-INTEGRITY-SHA256, `0x0020` XOR-MAPPED-ADDRESS,
  `0x8022` SOFTWARE, `0x8028` FINGERPRINT (also `0x802B` RESPONSE-ORIGIN and `0x802C`
  OTHER-ADDRESS, RFC 5780, comprehension-optional and skipped).
- Design §6.4 skips the required-range types `0x0004`, `0x0005`, `0x0006`, `0x0008`,
  `0x0009` and `0x001C` instead of discarding the response. Strictly, an RFC 8489
  implementation "does not understand" the two reserved ones; skipping them keeps RFC 3489
  era servers usable, and none of the six carries an address. `0x0008` must be skipped for the
  RFC 5769 vectors to parse: both responses carry MESSAGE-INTEGRITY.

### 2.5 RFC 5769 test vectors

Responses (both to the §2.1 request; transaction ID `b7 e7 a7 01 bc 34 d6 86 fa 87 df ae`;
SOFTWARE "test vector "; MESSAGE-INTEGRITY keyed with the short-term password
`VOkJxbRl1RmTxUk/WvJxBt`; FINGERPRINT last):

```
§2.2 IPv4 response (80 bytes)          → 192.0.2.1:32853
01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
00 20 00 08 00 01 a1 47 e1 12 a6 43
00 08 00 14 2b 91 f5 99 fd 9e 90 c3 8c 74 89 f9 2a f9 ba 53 f0 6b e7 d7
80 28 00 04 c0 7d 4c 96

§2.3 IPv6 response (92 bytes)          → [2001:db8:1234:5678:11:2233:4455:6677]:32853
01 01 00 48 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
00 20 00 14 00 02 a1 47 01 13 a9 fa a5 d3 f1 79 bc 25 f4 b5 be d2 b9 d9
00 08 00 14 a3 82 95 4e 4b e6 7b f1 17 84 c9 7c 82 92 c2 75 bf e3 ed 41
80 28 00 04 c8 fb 0b 4c
```

- **Checked by computation (2026-10-27).** A Python script outside the repository walked
  both dumps as transcribed above, recomputed MESSAGE-INTEGRITY (HMAC-SHA1 over the message
  up to the attribute, with the length field covering it) and FINGERPRINT (CRC-32 XOR
  `0x5354554e`), and decoded XOR-MAPPED-ADDRESS: both integrity values and both
  fingerprints (`c07d4c96`, `c8fb0b4c`) match and the addresses are the RFC's. The
  transcription is therefore byte-exact.
- §2.1 (sample request, header `00 01 00 58`, 108 bytes) and §2.4 (request with long-term
  authentication, header `00 01 00 60`, transaction ID `78 ad 34 33 c6 ad 72 c0 29 da 41
  2e`) are Binding **requests**: `parse_response` refuses them on the class, before any
  attribute is read, so their headers are enough for that test. Copy the full dumps from
  the RFC text if a test wants them byte-exact; they were not transcribed here.
- Port `0xa147 ^ 0x2112 = 0x8055 = 32853`; IPv4 `e112a643 ^ 2112a442 = c0000201`.

### 2.6 No SOFTWARE, no FINGERPRINT (deviation from `docs/research/nat.md` §3)

The research etiquette (`nat.md` §3, the list at line 390, item 3) said to send
`SOFTWARE = "Tornect/<ver>"`. Design §5.3 and §16.3 decline it: the attribute would name
Tornect in cleartext to every on-path observer and to the STUN operator, against the
fingerprint reduction of decision M1-86. SOFTWARE is comprehension-optional (`0x8022`), a
Binding request with no attributes is a complete request, and operators police abuse by
rate (Tornect sends at most 4 requests per session). FINGERPRINT (§7) only separates STUN
from other protocols sharing a port; the codec demultiplexes on byte 0, the cookie, the
transaction ID and an exact source match instead. `nat.md` carries the annotation.

### 2.7 The default servers, their operators and their terms (design §5.4)

Operator key = registrable domain (design §5.3 `STUN_OPERATORS`). Terms read 2026-10-27.

| Entry | Operator | What the operator publishes | Live check |
|---|---|---|---|
| `stun.cloudflare.com:3478` | Cloudflare, Inc. (`cloudflare.com`) | "Cloudflare's STUN service at `stun.cloudflare.com` is free and unlimited." (developers.cloudflare.com/realtime/turn/faq/, Pricing). Service table: "STUN over UDP", `stun.cloudflare.com`, `3478/udp` (developers.cloudflare.com/realtime/turn/). No credentials; no restriction on third-party use stated. | answered in revision 1's probe (`nat.md` §3); not repeated here |
| `stun.l.google.com:19302` | Google LLC (`google.com`) | **No published terms** for the standalone server (searched 2026-10-27). It is the default in the WebRTC project's samples (`nat.md` §3) and has been used as a public server for over a decade. | answered in revision 1's probe; not repeated here |
| `global.stun.twilio.com:3478` | Twilio Inc. (`twilio.com`) | "Twilio provides unlimited highly reliable STUN lookups for free, so your peer‑to‑peer calls are always free"; "Free usage of STUN, and pay‑as‑you‑go pricing for TURN metered by bandwidth usage" (twilio.com/en-us/stun-turn). The Network Traversal docs list `"urls": "stun:global.stun.twilio.com:3478"` with no username or credential, while the TURN entries have both (twilio.com/docs/stun-turn). Whether STUN use needs a Twilio account is not stated; Twilio's general Terms of Service (twilio.com/en-us/legal/tos) were not read in full. | **not verified** (no UDP egress here) |
| `stun.nextcloud.com:443` | Nextcloud GmbH (`nextcloud.com`) | Only: "there is one preconfigured for Nextcloud Talk that is operated by Nextcloud GmbH" (nextcloud-talk.readthedocs.io/en/latest/TURN/). **No usage policy** for third parties is published; the Nextcloud forum describes it only as Talk's default fallback. | **not verified** (no UDP egress here) |

- **Reading.** Cloudflare and Twilio state in writing that their STUN service is free (and
  Cloudflare "unlimited"); neither restricts it to customers. Google and Nextcloud publish
  nothing either way: no permission, no prohibition. Design §5.4 replaces an entry that
  "fails either check" at step B12; whether "no published terms" fails the terms check is
  the owner's call at B12 (docs/VERIFICATION.md, Phase B, OPEN row). Nothing here forbids
  the four entries.
- **Live check** (design §13 row 15, dev VM with UDP egress; this container has none). It
  prints the response type and whether the transaction ID matched, never the mapped
  address:

  ```bash
  for s in stun.cloudflare.com:3478 stun.l.google.com:19302 global.stun.twilio.com:3478 stun.nextcloud.com:443; do
    python3 -I -c 'import os,socket,sys
  h,p=sys.argv[1].rsplit(":",1); t=os.urandom(12)
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
  s.sendto(b"\x00\x01\x00\x00\x21\x12\xa4\x42"+t,(h,int(p)))
  try: d=s.recv(548); print(sys.argv[1],"type",d[:2].hex(),"txid","ok" if d[8:20]==t else "BAD")
  except OSError as e: print(sys.argv[1],"no answer",type(e).__name__)' "$s"
  done
  ```

  Expected: `type 0101 txid ok` for each. Record the four lines in the Phase B ledger row.

---

## 3. crab_nat 0.8.1 (PCP and NAT-PMP)

Read in `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/crab_nat-0.8.1/`
(checksum in `Cargo.lock`), 2026-10-27.

### 3.1 Package

- `license = "MIT"` (`Cargo.toml:25`), repository github.com/ryco117/crab_nat. The package
  ships **no licence file**, so `xtask/src/licences.rs` maps it to the canonical
  `packaging/licenses/MIT.txt` (the `canonical` mark, design §10).
- Dependencies: `bytes` 1.12, `displaydoc` 0.2.6, `num_enum` 0.7.6, `rand` 0.10.2,
  `thiserror` 2.0.18, `tokio` 1.52.3 (`io-util`, `net`, …); `tracing` 0.1.44 is optional
  behind the crate's `tracing` feature. Tornect pins `default-features = false` and turns
  nothing on, so the one log call (`lib.rs:491`, a retry notice) is compiled out:
  **crab_nat logs nothing**.
- Pure Rust over tokio; on Windows it is tokio's UDP over windows-sys (no unsafe of its own
  on our path).

### 3.2 API used (design §7.4)

```rust
pub const GATEWAY_PORT: u16 = 5351;                                  // lib.rs:50
pub const RECOMMENDED_MAPPING_LIFETIME_SECONDS: u32 = 7200;           // lib.rs:53 (used when lifetime is None)
pub enum PortMappingType { NatPmp, Pcp { client, nonce, external_ip } }   // lib.rs:90
pub struct TimeoutConfig { initial_timeout, max_retries, max_retry_timeout }  // lib.rs:146
pub struct PortMappingOptions { external_port: Option<NonZeroU16>,
    lifetime_seconds: Option<u32>, timeout_config: Option<TimeoutConfig> }    // lib.rs:160
pub enum MappingFailure { NatPmp(natpmp::Failure), Pcp(pcp::Failure) }      // lib.rs:504

pub type pcp::Nonce = [u32; 3];                                       // pcp/mod.rs:36
pub enum pcp::Failure { .., UnsupportedVersion(VersionCode), .. }     // pcp/mod.rs:166, :185
pub async fn pcp::port_mapping(base: BaseMapRequest, session_nonce: Option<Nonce>,
    suggested_external_ip: Option<IpAddr>, options: PortMappingOptions)
    -> Result<PortMapping, Failure>;                                  // pcp/mod.rs:279
pub enum pcp::DropMappingRange { Single { internal_port, protocol }, .. }  // pcp/mod.rs:417
pub async fn pcp::try_drop_mapping(gateway, client, nonce: Nonce, range: DropMappingRange,
    timeout_config: Option<TimeoutConfig>) -> Result<(), Failure>;   // pcp/mod.rs:433

pub async fn natpmp::external_address(gateway, timeout_config) -> Result<Ipv4Addr, Failure>;  // natpmp/mod.rs:178
pub async fn natpmp::port_mapping(gateway, protocol, internal_port, options)
    -> Result<PortMapping, Failure>;                                  // natpmp/mod.rs:250
pub async fn natpmp::try_drop_mapping(gateway, protocol, local_port: Option<NonZeroU16>,
    timeout_config) -> Result<(), Failure>;                          // natpmp/mod.rs:282
```

- **`PortMapping::new`** (`lib.rs:212`) tries PCP and falls back to NAT-PMP only on
  `pcp::Failure::UnsupportedVersion(VersionCode::NatPmp)` (`lib.rs:232`). Design §7.4 calls
  the two modules directly to honour `MapProtocols` and to pass its own nonce; it applies
  the same fallback rule.
- **Nonce.** `pcp::Nonce = [u32; 3]` (96 bits). With `session_nonce: None` crab_nat draws
  `[rand::random(), rand::random(), rand::random()]` (`pcp/mod.rs:537`, `:730`). Design §7.4
  passes `Some(nonce)` from `getrandom`, written to the ledger **before** the request, so a
  crash leaves a record `try_drop_mapping` can use. Replies whose nonce differs are refused
  (`validate_nonce`, `pcp/mod.rs:1095`).
- **Lease 0.** A debug-build `assert!` (`pcp/mod.rs:708`) panics when `lifetime_seconds` is
  `Some(0)` together with a suggested external port or address (RFC 6887 §15.1 allows
  lifetime 0 only for deletes). Tornect never requests 0 (design §16.3, E7); deletes go
  through `try_drop_mapping`.
- **`renew` keeps the granted lifetime.** `PortMapping::renew` re-requests
  `lifetime_seconds: Some(self.lifetime())` (`lib.rs:248–253`), where `lifetime()`
  (`lib.rs:355`) is what the router granted. A router that once grants 120 s is asked for
  120 s forever. Design §7.4 therefore renews by calling `port_mapping` again with 600 s
  (and, for PCP, the same nonce and `Some(external_ip)`), not `renew`.
- **`try_drop`** (`lib.rs:291`) deletes and hands the mapping back on failure.
  `natpmp::try_drop_mapping` with `local_port: None` "will remove all port mappings for our
  client with the given protocol" (`natpmp/mod.rs` doc at `:282`); Tornect always passes
  `Some(internal_port)`.

### 3.3 Sockets and timing

- `new_socket` (`lib.rs:384–406`) binds a fresh `0.0.0.0:0` UDP socket and `connect`s it to
  `gateway:5351`, so the kernel delivers only datagrams from the gateway's address and
  port: an off-path spoofer must forge that source and guess the ephemeral port. Each
  request uses its own socket; nothing listens on 5350 (the multicast announcements are
  ignored).
- NAT-PMP: `FIRST_TIMEOUT_MILLIS = 250` (`natpmp/mod.rs:13`), doubling per retry; PCP:
  `FIRST_TIMEOUT_SECONDS = 1`, `MAX_TIMEOUT_SECONDS = 1024` (`pcp/mod.rs:19–29`). Tornect
  passes its own `TimeoutConfig` sized to what remains of the deadline, and the caller's
  `tokio::time::timeout` bounds the call whatever the config says.
- Datagrams: NAT-PMP requests 12 bytes, responses 16; PCP up to 1100 bytes
  (`MAX_DATAGRAM_SIZE`, `pcp/mod.rs:26`).

---

## 4. igd-next 0.18.0 (UPnP IGD), feature `aio_tokio`

Read in `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/igd-next-0.18.0/`,
2026-10-27. MIT (`LICENSE` in the package).

### 4.1 Features and dependencies

- `default = ["io_sync"]` pulls `attohttpc`; Tornect pins `default-features = false,
  features = ["aio_tokio"]` (decision M1-81: no attohttpc). `aio_tokio = ["futures",
  "tokio", "hyper", "hyper-util", "http-body-util", "bytes", "http"]`; `ipv6` is off (no
  `WANIPv6FirewallControl` search target, design §1 non-goals).
- hyper 1 with `client`, `http1`, `http2` and **no TLS**; hyper-util 0.1 `client-legacy`
  (`Client::builder(TokioExecutor).build_http()`, `aio/tokio.rs:53`). Hence `h2`, `want`,
  `try-lock`, `tower-service`, `http-body` in the lock (docs/DEPENDENCIES.md, Phase B).
  Also `log` 0.4, `rand` 0.10, `thiserror` 2.0.18, `url` 2, `xml-rs` 0.8, `xmltree` 0.10.

### 4.2 Search

```rust
#[non_exhaustive]                                                   // common/options.rs:34
pub struct SearchOptions { pub bind_addr: SocketAddr, pub broadcast_address: SocketAddr,
    pub timeout: Option<Duration>, pub single_search_timeout: Option<Duration>,
    pub gateway_ip_version: GatewayIpVersion, pub allowed_gateway_ips: Vec<IpAddr> }
pub async fn aio::tokio::search_gateway(options: SearchOptions)
    -> Result<Gateway<Tokio>, SearchError>;                          // aio/tokio.rs:81
```

- `#[non_exhaustive]`: build with `SearchOptions::default()` and assign fields (a struct
  literal does not compile outside the crate). Defaults (`options.rs:51–61`): bind
  `0.0.0.0:0`, `239.255.255.250:1900`, `timeout` 10 s (`DEFAULT_TIMEOUT`), single response
  5 s (`RESPONSE_TIMEOUT`), `GatewayIpVersion::Both`, no allowed IPs.
- One M-SEARCH per search target (`common/messages.rs:5–25`), `MX:3`, targets
  `InternetGatewayDevice:1`, `WANIPConnection:1`, `WANPPPConnection:1` (the
  `WANIPv6FirewallControl:1` target only with `ipv6`). They go to `broadcast_address`, which
  design §7.4 sets to `(gateway, 1900)` first (unicast) and to the multicast group only if
  the unicast search got no answer.
- The loop (`aio/tokio.rs:127–200`) reads answers until `timeout`; a bad or slow answer is
  skipped, not fatal. For each answer: the `LOCATION` URL must be `http`, carry an IP
  literal host (a name is refused, `endpoint.rs` `endpoint_from_url`, so **no DNS
  lookup** is ever made), a non-zero port, and that IP must equal the responder's source IP
  (`validate_location`, `endpoint.rs:28–34`; `trusted_ip`, `:117–121`, also refuses
  loopback, unspecified and multicast unless listed in `allowed_gateway_ips`). Control and
  schema URLs from the description pass the same check (`resolve_reference`).
- **Residual.** igd-next fetches the description (`get_control_urls`, an HTTP GET to the
  responder) **before** Tornect sees `gateway.addr` and checks it equals the gateway. In the
  multicast fallback any LAN device that answers is contacted once over HTTP; in the unicast
  search only a device that answers on our ephemeral port. The fetch is bounded (1 MiB,
  10 s, see 4.4) and carries nothing about the session; the result is still dropped unless
  `addr.ip() == gw` (design §7.4).
- Tests against a FakeIgd on `127.0.0.1` need `allowed_gateway_ips = vec![127.0.0.1]`
  (loopback is otherwise untrusted); production keeps the list empty.

### 4.3 Mapping calls (`aio/gateway.rs`)

- `get_external_ip()` (`:73`); `add_port(protocol, external_port, local_addr, lease, desc)`
  (`:255`, refuses port 0 on either side); `add_any_port(..)` (`:116`): `AddAnyPortMapping`
  with a random port when the router lists it, else `AddPortMapping` with random ports, up
  to 20 tries on 718, once with equal ports on 724; `remove_port(protocol,
  external_port)` (`:280`). "The lease_duration parameter is in seconds. A value of 0 is
  infinite." Tornect always passes 600.
- Error mapping (`common/parsing.rs:418–449`): `AddPortError` 605 `DescriptionTooLong`, 606
  `ActionNotAuthorized`, 718 `PortInUse`, 724 `SamePortValuesRequired`, 725
  `OnlyPermanentLeasesSupported`; `AddAnyPortError` 718 `NoPortsAvailable` /
  `ExternalPortInUse`, 725 `OnlyPermanentLeasesSupported`. Design §7.4: `PortInUse` →
  `add_any_port`; 725 → `MapFail::PermanentOnly`, never retried with lease 0.
- **Never display igd-next errors.** `RequestError::ErrorCode(u16, String)` and
  `InvalidResponse(String)` (`errors.rs:11–36`) carry router-supplied text; `IoError` and
  the hyper errors can carry addresses. `RealMapper` maps every error to a `MapFail`
  variant (fixed text, no address) and drops the original.

### 4.4 Requests and logging

- Every HTTP request is wrapped in `timeout(DEFAULT_REQUEST_TIMEOUT)` (10 s,
  `aio/tokio.rs:49`, `:76`) and every body in `Limited::new(.., MAX_RESPONSE_BYTES)` (1 MiB,
  `:67`, `:272`, `:304`, `:349`); XML depth is checked (`parsing.rs:22`, `:344`). Tornect's
  deadline bounds the whole call anyway.
- Logging is through `log` (target `igd_next`): `debug!` lines print the responder's
  address and the URIs it requested (`aio/tokio.rs:141–312`), and `log::warn!("Unknown
  argument: ..")` prints router-supplied SOAP argument names (`messages.rs:99`, `:137`,
  `:167`). hyper-util's `client` feature turns on its `tracing` dependency, and its
  connector logs `debug!("connecting to {}", addr)` and `connected to` with the gateway's
  address and port (`hyper-util-0.1.21/src/client/legacy/connect/http.rs` 786–793); `h2`
  logs through `tracing` unconditionally; `hyper`'s own `tracing` is an unstable feature
  that stays off. Decision M1-83's `QUIET_TARGETS` already drops `igd_next`, `hyper`,
  `hyper_util`, `h2`, `xmltree` and `xml` (step A7).

---

## 5. The default gateway

### 5.1 Windows: `GetBestRoute2` (`tornect-platform::route`)

Read 2026-10-27 at learn.microsoft.com (`netioapi.h`, `GetBestRoute2` and
`MIB_IPFORWARD_ROW2`).

```c
NETIOAPI_API GetBestRoute2(
  [in, optional] NET_LUID *InterfaceLuid, [in] NET_IFINDEX InterfaceIndex,
  [in] const SOCKADDR_INET *SourceAddress, [in] const SOCKADDR_INET *DestinationAddress,
  [in] ULONG AddressSortOptions, [out] PMIB_IPFORWARD_ROW2 BestRoute,
  [out] SOCKADDR_INET *BestSourceAddress);
```

- "If no value was set for the *InterfaceLuid* member (the values of this member was set
  to zero), then the *InterfaceIndex* member is next used to determine the interface."
  *SourceAddress* "may be omitted and passed as a **NULL** pointer"; *AddressSortOptions*
  "is not currently used". Returns `NO_ERROR`, `ERROR_INVALID_PARAMETER` (a null
  destination, route or source pointer, or a destination that is not IPv4/IPv6),
  `ERROR_FILE_NOT_FOUND` ("the network interface specified by the *InterfaceLuid* or
  *InterfaceIndex* parameter could not be found"), `ERROR_NOT_SUPPORTED` (no stack for that
  family). "defined on Windows Vista and later."
- `MIB_IPFORWARD_ROW2.NextHop`: "For a remote route, the IP address of the next system or
  gateway en route. If the route is to a local loopback address or an IP address on the
  local link, the next hop is unspecified (all zeros)."
- The function reads the routing table; the documentation describes no network traffic,
  and none is needed to answer (no neighbour resolution is involved, unlike netdev's
  `SendARP` path, §1.5).
- **Use** (`crates/tornect-platform/src/route_windows.rs`): `InterfaceLuid = NULL`, the
  interface's index, `SourceAddress = NULL`, destination `192.0.2.1` (TEST-NET-1,
  `ROUTE_PROBE_DEST`: any non-local IPv4 address selects the interface's default route),
  `AddressSortOptions = 0`. The answer counts only with `NO_ERROR`, `NextHop.si_family ==
  AF_INET`, and a next hop that is not unspecified, loopback, multicast or broadcast
  (`route::usable_gateway`). One unsafe block, one `SAFETY` comment; windows-sys 0.61.2
  features `Win32_NetworkManagement_IpHelper`, `Win32_NetworkManagement_Ndis` (`NET_LUID`
  in the signature) and `Win32_Networking_WinSock` (`SOCKADDR_INET`).
- **Wine 9.0** (this container's Wine): `GetBestRoute2` is a stub that prints `fixme:
  ... stub` and fails, so under Wine every index reads as "no gateway". The unit test there
  only checks index 0 and an unknown index. The real lookup is NEEDS-DEVICE(windows),
  design §13 row 13 (recipe in docs/VERIFICATION.md, Phase B).
- `RealNet::with_gateway_lookup` calls it once per non-loopback interface index that netdev
  left without a gateway (`local::fill_gateways`), right after the netdev read and inside
  the `interfaces()` future, not on the blocking pool: one routing-table read per interface.
  The device run times it (NEEDS-DEVICE(windows)).

### 5.2 Linux and macOS: netdev's `gateway` feature, re-read for B1

With `[target.'cfg(not(windows))'.dependencies] netdev = { features = ["gateway"] }`:

- **Linux** (`os/linux/interface.rs:108–133`): `netlink::collect_routes()`
  (`os/linux/netlink.rs:292`) dumps the routing table (`RTM_GETROUTE`) and the neighbour
  table (`dump_neigh`, `RTM_GETNEIGH`, `:85`) over the same unprivileged `NETLINK_ROUTE`
  socket kind as the interface read; on failure it falls back to `/proc/net/route`
  (`os/linux/procfs.rs:8`). The gateway's MAC comes from the kernel's existing neighbour
  entries: **no ARP or neighbour solicitation is sent**. Tornect reads only
  `gateway.ipv4` and never the MAC.
- Then (`interface.rs:155–163`) `net::ip::get_local_ipaddr()` (`net/ip.rs:61`) binds a UDP
  socket and `connect`s it to `10.254.254.254:1`, falling back to `[fdff:ffff:…:ffff]:1`, to
  read the source address: a `connect()` on UDP sends nothing (the same technique as
  `local::route_sources`). The socket is dropped at once.
- For the default interface it reads `/etc/resolv.conf` (`os/unix/dns.rs:6–30`): each
  `nameserver` value goes through `format!("{}:53").to_socket_addrs()`. A literal address
  (the only valid form in that file) resolves without a query; a malformed line hits
  `eprintln!("Invalid IP address format: {}")` at `:25`, which writes that line's value to
  stderr (the same class of residual as the MTU lines, §1.7). A host name there would be
  looked up through the system resolver: resolv.conf allows only addresses, so this needs a
  broken file. Tornect does not read `dns_servers`.
- **macOS** (`os/darwin/route.rs`): routing `sysctl` with `NET_RT_DUMP` (`:570`) and the
  neighbour table with `NET_RT_FLAGS` (`:500`); no packet.
- **This container (2026-10-27).** The ignored device check
  `cargo test -p tornect-net --lib local::tests::print_this_machines_reading -- --ignored
  --nocapture` prints each `IfaceAddr` of `local::read_interfaces` through its redacted
  `Debug`: `lo` (index 1) had `gateway_v4: None`, `eth0` (index 4, `Physical`) had
  `gateway_v4: Some(v4 unusable)`, the default route's next hop, which `/proc/net/route`
  shows in TEST-NET-1 like `eth0`'s own address. Nothing else reached stderr. The unit test
  `the_netdev_gateway_reaches_every_address_of_its_interface` checks the mapping on a
  synthetic interface: every address carries the first usable IPv4 gateway, and an
  unspecified or broadcast one is none.

---

## 6. Windows Defender Firewall (design §3.7)

Read 2026-10-27: learn.microsoft.com "Windows Firewall rules" and the Rebex blog post
"Beware pressing Cancel on Windows Firewall Security Alert".

- "If there's no active application or administrator-defined allow rule(s), a dialog box
  prompts the user to either allow or block an application's packets the first time the
  app is launched or tries to communicate in the network: If the user has admin
  permissions, they're prompted. If they respond *No* or cancel the prompt, block rules are
  created. Two rules are typically created, one each for TCP and UDP traffic. If the user
  isn't a local admin and they are prompted, block rules are created. It doesn't matter
  what option is selected."
- "once the rules are added, they must be deleted to generate the prompt again. If not, the
  traffic continues to be blocked." With notifications disabled, "No Allow rules are
  created, the traffic is blocked by the default block rule."
- Rebex: after **Allow access** with only one profile ticked, "'Allow' rules have been
  created for 'Domain networks'" and "'Block' rules have been created for 'Public
  networks'"; after **Cancel**, "only 'Block' rules are created even for the most privileged
  'Domain' profile", and "the 'Windows Security Alert' will be never shown again for this
  application." (Windows version not stated.)
- Rules are per executable path, so a zip extracted elsewhere asks again (design §11).
- **Not documented anywhere read:** whether inbound UDP that answers an outbound flow (a
  punched path) passes despite the block rules. That is design §3.7's open question and
  §13 row 1 (NEEDS-DEVICE(windows+linux, one LAN)); MemNet's `InboundRule::{Stateful,
  Blocked}` covers both answers.
- An installer-created rule is M2.x (no installer yet).

---

## 7. netdev 0.47.0 (not adopted)

Published 2026-10-25T14:56Z. A source diff against 0.46.3 (1584 changed lines, read
2026-10-27) shows illumos support, the Linux netlink code moved into `netlink_data.rs`, the
Windows `GetAdaptersAddresses` buffer allocated with the structure's alignment, and the
`SendARP` buffer typed `[u32; 2]`. The `SendARP` change is on the `gateway` path Tornect
never compiles on Windows. The `GetAdaptersAddresses` alignment change is on Tornect's
Windows interface read, whose real-Windows run is NEEDS-DEVICE (design §13 row 13) on
either version, so adopting 0.47 should come with that device run. The pin stays `=0.46.3`; revisit at step C2.
