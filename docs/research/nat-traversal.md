# Direct connections: interfaces, STUN, port mapping — research note (started 2026-10-26)

Scope: `tornect-net` local candidates for direct connections (design `direct` revision 4,
§7.1–§7.2; decisions M1-78 and M1-81). Step A1 writes §1 (netdev, which Phase A uses to
read the interface list). Step B1 adds §2 (STUN per RFC 8489 with the RFC 5769 vectors,
crab_nat and igd-next, `GetBestRoute2`, the STUN operators and their terms, the Windows
firewall). Everything in §1 was read in the crate sources that cargo unpacked into
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
| Crate | `netdev = { version = "=0.46.3", default-features = false }` (MIT). 0.47.0 came out on 2026-10-25 and is not adopted (one day old; the design reads 0.46.3) |
| Features | defaults `gateway`, `apple-system-configuration-extra`, `android-extra` all **off**. Phase B turns `gateway` on for `cfg(not(windows))` only (§1.6) |
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
on either. B1 re-reads these paths before turning it on.

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
- netdev 0.47.0 (2026-10-25): a day old at A1; revisit with a source diff at B1.

---

## 2. Phase B topics (step B1)

Not written yet: STUN (RFC 8489 §5–§7 and §14, RFC 5769 test vectors), crab_nat 0.8.1 and
igd-next 0.18.0 (design §7.4, including crab_nat's `renew` lifetime and
`pcp::Nonce = [u32; 3]`), `GetBestRoute2`, the STUN operator list with each operator's
terms and the live check, and the Windows firewall behaviour (NEEDS-DEVICE). The research
etiquette's "send SOFTWARE" item (`docs/research/nat.md:390`) gets the design's deviation
(no SOFTWARE attribute) at the same step.
