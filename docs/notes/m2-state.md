# M2 state: direct connections, Phases A and B and the close (hand-off, 2026-10-28)

Phase A of design `direct` (revision 4, `/mnt/project-files/designs/direct.md`), LAN-direct sessions
with Tor kept as the fallback, is implemented: steps A1 to A21 and the in-container half of
checkpoint A22. **`m2a` is not tagged.** It waits for evidence that only the dev VM and real
machines can give (the list below); the ledger rows for it are in `docs/VERIFICATION.md` under
"Direct connections, Phase A", each with its recipe. Phase B (internet direct, steps B1 to B13)
is implemented in this container: B1 to B7 (2026-10-27), B8 to B13 (2026-10-28; "OPEN, owned by
Phase B steps" below). **`INTERNET_DIRECT` is `true` since step B12 (`a4af339f`).** No tag was
made; what the dev VM and real networks still owe is listed under B12 and B13 below. **The close
is done (2026-10-28):** C1 wrote the final text of decisions M1-77 to M1-86 and the plan's final
words (the threat model included), C2 reviewed the whole feature's security and found no code
defect (the C1 and C2 entries at the end of "OPEN, owned by Phase B steps"); the review of C1 and
C2 corrected the live demos' expected lines for two instances on one VM, which never go direct on
the site (decision M1-82 item 11). The feature's final review (security and correctness) found three
minor defects, fixed in `cc985c3c`, `ce9fb274` and `cdc83520` (the last entry but one of "OPEN,
owned by Phase B steps"). The closing pass (the whole workspace's gates and a ledger audit against
the design's acceptance items) fixed one more gap, the second unique-local address offered but never
usable (`446af445`), and corrected eleven stale ledger statuses (the last entry). What is left
before `m2` is the owner's: the three blockers below, then the tag.

## Blockers: no release zip to users, no `m2` tag

Since `a4af339f` every default-configured session sends this computer's IP address and the
session's time to one public STUN server of its part of the default list (design §5.3, §5.4;
decision M1-81). Two of the four operators (Twilio, Nextcloud) were never checked live, and
whether Google's and Nextcloud's lack of published terms for third-party use fails §5.4's terms
check is the owner's call. Until both are settled:

1. **The owner decides the terms question** (`docs/research/nat-traversal.md` §2.7; ledger row
   "Step B1: the default STUN servers' operators and published terms", OPEN).
2. **The `live_stun` run is pasted** from the dev VM (`cargo test -p tornect-net --test live_stun
   -- --ignored --nocapture`; ledger row "Step B12: the live STUN check"): four lines, each
   `srflx` or `no-nat`.
3. **The Accept demo is pasted** from the dev VM and two machines on one LAN (design §15 step C2
   [VM]; ledger row "C2: the Accept demo on the dev VM", which runs the live demos of both phases
   with one build of the close's head). Two instances on one VM give `ROUTE tor no-path` (or
   `ROUTE direct internet` through routers that hairpin), never `ROUTE direct lan`: each refuses
   the other's addresses as its own (design §7.7, decision M1-82 item 11), so the same-site lines
   come from two machines (case (1) of the ledger row "Step A15: the direct bind between two real
   machines").

No zip from `cargo xtask dist` goes to users and no `m2` tag is made before all three. If the owner
rejects "no published terms", or an entry is silent in the run (asked, nothing global back), the
entry is replaced with one of another operator as §5.4 says: `DEFAULT_STUN` and `config.rs`'s
default-list test, the migration (saved configs hold today's four entries), `STUN_LINE`'s
operator names, the release README and M1-81's note. A name that did not resolve in the run is
checked against the resolver first; it is no reason by itself to replace a server.

## What Phase A does

- After `SESSION_ACCEPT` both sides send `CANDIDATES` over the onion channel: same-site scope only
  (`INTERNET_DIRECT = false`), so a side offers its private IPv4 and unique-local IPv6 addresses
  and nothing else (no public address, no STUN, no router mapping). The remote filter refuses
  anything off site, below port 1024, or one of this computer's own addresses.
- One UDP socket per side (`[::]` dual-stack where the OS allows), authenticated punch probes
  through the checklist, then QUIC with both device keys pinned as raw public keys (no CA, no
  tickets, no 0-RTT, no migration); the controlling side is the lower device key.
- The media binds on the direct stream with `BindProof` (an exporter-bound MAC the viewer checks in
  constant time) and runs on it to the end; Tor carries the media when the punch fails within
  `network.punch_timeout_ms` (4 s by default, 1 to 10 s allowed), when either side's policy is
  Tor-only (`network.paranoid`, Tor through a bridge unless `network.direct_with_bridges`,
  `connect --tor-only`), or when the peer is an old version. `network.lan_only` refuses the Tor
  fallback and ends the session `NO_LAN_PATH`. Once the viewer commits to the direct path it never
  falls back (decision M1-79): a dead LAN ends the media about 10 s later (QUIC idle timeout).
- Seen by people: `ROUTE` and `PATH` lines in `connect`, `SESSION ROUTE` on the host, `doctor`'s
  `direct connections:` and `network:` lines (kinds of address, never an address), the window's
  route badge and details, Settings > Connection "Direct connections", the consent sheet's and the
  CLI prompt's disclosure line, the grant sheet's Tor-only help, the Privacy line;
  `sessions.log` gains `transport`, `path_summary` and `router_port` (Phase B writes the last).
- Logs: third-party network crates (quinn, quinn-proto, quinn-udp, rustls, netdev, …: the 13
  `QUIET_TARGETS`) are dropped unless `TORNECT_LOG_IDENTIFIERS=1`, and the file log drops them
  always; the redaction e2e proves it over a whole session at `trace`.

## Commits

Seventy-odd commits from `acf9b112` (A1, the pins) to the docs commit of checkpoint A22, built in
the design's §15 order: A1 pins and decision rows M1-77 to M1-86; A2/A3 the cancel-safe channel;
A4 the signal wire (`CANDIDATES`, `CANDIDATES_DONE`, `TOR_FALLBACK`, `dir1`); A5/A6 the path seam
and the transport knob; A7 telemetry quiet targets and the address classes and filters; A8 the
session socket (`QuietUdp`, `PunchSocket`); A9 the pinned QUIC; A10/A11 probes and the checklist;
A12/A13 `DirectLink`, `LoopbackNet`, `MemNet`; A14/A15 `BindProof` and the direct bind; A16
`DirectHost`; A17 `choose_path`; A18/A19 the binaries; A20/A21 the window, the switch and the
consent copy; each followed by its ledger commit and, for A9, A14/A15, A17 and A18/A19, a security
review and its fixes. `git log --oneline acf9b112^..HEAD` lists them.

Checkpoint A22 (this session, base `406627b4`):

- `e5403c22` fix(core): `punch_timeout_ms` must be 1000 to 10000 and a fixed `direct_port` 1024 or
  above (`Config::validate`).
- `2e60d8e9` test(fuzz): `to_wire`/`from_wire` moved into `direct/wire.rs`, which the `candidates`
  target compiles through `#[path]` and drives into `RemoteFilter::admit`.
- `423b3158` feat(xtask): `dist` refuses a release graph that enables `tornect-net`'s
  `test-support`.
- `678d8cb2` test(session): whole direct sessions on loopback sockets, the redaction e2e and
  `direct_loopback_stats` (`quinn` became a dev-dependency of tornect-session for the raw send).
- `7cc9f0e7` fix(session): a doc link the wire move broke (only rustdoc saw it).
- `22b387b3` feat(session): the link's counters at debug (`direct path open` on the viewer,
  `direct link closed` on the host) so design §13 rows 2 and 11 can be read off a live session.
- the docs commit: decision notes on M1-79, M1-82, M1-83, the ledger rows, this note.

The security review of the Phase A diff found no defect (ledger row "Checkpoint A22: the security
review of the Phase A diff" lists what was judged).

The final security and correctness reviews of the whole Phase A diff (fixes after `61708b3f`;
ledger rows "Final review: …"):

- `50e23d45` fix(session): an onion `Bind` is told `TRANSPORT` only after its MAC verified.
- `26c86437` fix(session): a kill lets live direct media end through its teardown (within
  `DIRECT_DRAIN`) before the link closes.
- `ed3ccd24` fix(signal): `departure` reads one byte past an early frame, so B04 holds again for a
  requester that sent one frame and left.
- `36961bb2` fix(signal): the viewer's `ping` queues at most a session's worth of host path frames.
- `557e041c` docs(net): the session socket's port is not exclusive on Windows or macOS
  (`SO_EXCLUSIVEADDRUSE` not set; device check added to §13 rows 12 and 13).
- `a0634442` docs: decisions cited by their M1 rows.
- the docs commit: ledger rows, the B04 and A2 residual, decision notes on M1-79 and M1-80.

## Before `m2a` (all [VM] or device; recipes in the ledger)

1. The live Phase A demo on the dev VM (design §12.5): two instances on one VM → `ROUTE tor
   no-path`, `PATH -`, `MEDIA`, `SESSION ROUTE … tor`, `--tor-only`, `paranoid`, `--no-video`, the
   `ss -uanp` check before the connect and the `sessions.log` lines. Row "Checkpoint A22: the live
   Phase A demo on the dev VM" (corrected at the review of steps C1 and C2: it expected `ROUTE
   direct lan`, which the own-address rule refuses on one machine). The same-site lines (`ROUTE
   direct lan`, `PATH host`, `SESSION ROUTE … lan`, one UDP socket per process) need two machines
   on one LAN: case (1) of the row "Step A15: the direct bind between two real machines".
2. The 10-minute fuzz campaigns: `candidates`, `probe`, `framing`, `envelope`, `media` (nightly and
   cargo-fuzz are not in this container). Row "Checkpoint A22: the 10-minute fuzz campaigns".
3. `cargo xtask dist` with the feature check, the licence texts in both zips, and `doctor` from the
   unpacked Windows zip under Wine. Row "Checkpoint A22: the release zips".
4. The 1 GiB loopback transfer rerun on the VM (row "Step A12: 1 GiB over the loopback pair").
5. The dual-stack tests with `TORNECT_REQUIRE_IPV6=1` (rows of steps A8 and A9): this container
   has no `AF_INET6`.

Then tag `m2a` at the commit the evidence was taken on.

## NEEDS-DEVICE after `m2a` (design §13; rows in the ledger)

Row 1 (a Windows host and a Linux viewer on one LAN: the firewall prompt, Allow/Cancel, a standard
account, `kill` of the host), row 2 (dual-stack IPv4 on Windows and macOS, read through the new
debug counters), row 12 (macOS firewall and `ROUTE direct lan`), row 13 (Windows: a dead candidate
and `WSAECONNRESET`, `doctor`, the 1 s interface read, a same-account `SO_REUSEADDR` bind of the
fixed port; row 12 has the macOS one), row 14 (roaming), the two-machine run of
the row "Step A15: the direct bind between two real machines", the final review's two device rows
(a UPnP router with a neighbour's mapping; a WireGuard full tunnel with the host's address
excluded) and its `ledger` ASan campaign, `LoopbackNet` and the loopback link
tests on macOS and Windows, msvc and darwin builds of the crates above ring (only `tornect-core`
and the crates below ring check here).

## OPEN, owned by Phase B steps

- B1 (done 2026-10-27; `docs/VERIFICATION.md`, Phase B): the pins (igd-next, crab_nat, netdev
  `gateway` off Windows, the windows-sys IpHelper features), `nat-traversal.md` §2 to §7, the
  Windows route lookup (`tornect_platform::route::default_gateway_v4`, handed to `RealNet` by
  `direct::real_net`), `NetEnv::resolve` and `NetEnv::mapper` with `mapping.rs`'s types and
  `NoMapper` everywhere. Left from it: the Windows `GetBestRoute2` run, the netdev gateway on a
  desktop and on macOS, the live STUN check (NEEDS-DEVICE rows) and the owner's call on the Google
  and Nextcloud terms (OPEN until B12).
- B2 (done 2026-10-27, `5d52585b`): the Binding codec (`tornect_net::stun`, the bare 20-byte
  request, `parse_response` with the RFC 8489 §6.3.3 discard rule), all four RFC 5769 vectors
  transcribed and recomputed, the `stun` fuzz target with its seeds. Left from it: the 10-minute
  campaign on the dev VM (NEEDS-DEVICE row, recipe in the ledger and in the target's header).
- B3 (done 2026-10-27, `bff44b6a`, `bb142b38`, `a2b19d0c`): the four-operator default list, its
  migration and its bounds (`tornect-core` config), `stun::partition`, `gather::ask_stun` (random
  first server, a second at 750 ms of another operator where there is one, RTO 500 ms, at most 2
  servers and 4 requests in the 1500 ms budget, replies only from the address asked under its
  transaction ID), `gather::stun_base` (a CGNAT base asks), `StunDns` with `RealNet::resolve`
  cache-first and `RealNet::prefetch`, fake STUN servers on loopback. Done at B6 (below): what was
  left for B6: the link's gathering task reading `tees.stun` and calling `ask_stun` with this role's
  part, `stun_base` combined with the scope, `enable_stun` and the mapping's head start, the
  `DirectParams`/`DirectOptions` STUN fields (the second ULA design gap was listed here as well,
  but B6 did not take it up: settled at the feature's close, `446af445`, one ULA offered). Left
  for B11/B12: the
  app's `RealNet::prefetch` call, with a list that is empty whenever STUN may not run (design
  §5.3: `INTERNET_DIRECT`, policy `Any`, `enable_stun`, not bridged); B11 wired it (`e464d2b7`,
  `RouterPorts::follow_stun`), B12 turns the list on.
- B2/B3 review fixes (2026-10-27, `1d2cd2d1`, `6ef7861c`, `c6e86c1c`, `3b4ce607`; ledger rows
  "Review of steps B2 and B3", decision M1-81's review note): `RealNet::resolve` looks a name up
  at session time only while `StunDns::refreshed()` is false (no round since the cache was made or
  cleared); after a round a miss is `NotFound` at once. The operator split is only disjoint when
  both computers use the same list (docs and a residual test). In VPN mode `ask_stun` asks a server
  only when `NetEnv::route_source_to(server)` is the tunnel's source (`StunAsk::tunnel`).
  `fuzz/Cargo.lock` is complete again. Owed by later steps: B6 passes
  `tunnel: vpn.then_some(base)`; B11 restarts `prefetch` on every settings save and every change of
  the bridge state (a cleared cache stays cold, and a newly listed name is answered only after the
  next round), words `STUN_LINE` with "when both computers use the same list" (and may add a doctor
  note when the list is not the default) — all three done at B11 (`e464d2b7`; the refresh restarts
  when its names change, which a save or a bootstrap may do); C1 puts the same-list condition into
  M1-81's final text and the plan's threat model, and §13 rows 10/11 (B13) include the
  split-tunnel case whose recipe is in the ledger.
- B4/B5 (done 2026-10-27, `2116049f`, `4ec31098`, `269f34cd`; ledger rows "Step B4", "Step B5" and
  "Steps B4 and B5", decision M1-81's step note): `RealMapper` (PCP with our own nonce and NAT-PMP
  through crab_nat, UPnP-IGD through igd-next with the unicast search first and the gateway check),
  `MappingLedger` under `Paths::router_ports_dir()` (one locked list per running process),
  `renewal_delay` and `Mapping::keep_renewed`, release on drop through `ReleaseTracker`,
  `RealMapper::sweep`, `RealNet::with_router` and `RealNet::sweep_leftovers`, `FakePcp` and
  `FakeIgd` (`tornect_net::mapping::fake`, also under `test-support` for B9). Done at B6 (below),
  what was owed by B6 (or B11): the app's
  `RealNet::with_router(paths.router_ports_dir(), <sessions.log router_port sink>)` once per
  process, `sweep_leftovers()` at GUI, `host` and `connect` start, `releases().wait(
  SHUTDOWN_RELEASE_WAIT)` at exit, and the link holding the `Mapping` with `keep_renewed` beside
  the session. Left as NEEDS-DEVICE: the `FakePcp` tests on Windows (Wine cannot run them) and on
  macOS (`lo0` aliases), and real routers (design §13 row 4, after B12).
- B6/B7 (done 2026-10-27, `8f31bab4`, `ca430487`, `cd5e6ca0`; review fixes 2026-10-28, `cc4304e7`,
  `c0954777`, `f6d19142`; ledger rows "Step B6", "Step B7" and "Steps B6 and B7", "Review of steps
  B6 and B7", decision M1-81's notes): `gather::plan` (`GatherConfig` in `DirectParams`, from
  `DirectOptions::gather(role)`: this role's part of the STUN list, `enable_stun`, the router
  switches) and the gathering task (`gather::Gatherer`): router from the bind, STUN after the 250 ms
  head start (skipped on a global mapping inside it, at once when the router answers without one),
  one batch per gathered candidate, `Done` at both ends or 1500 ms; the task holds and renews the
  `Mapping` until `LinkInner::shut` aborts it, the shut first holding the mapper's release tracker
  until the task is gone, so a release counts from the link's end. A side with no host candidate
  still gathers; `NoAddresses` only with nothing to gather. The driver feeds
  `Checklist::set_local_public` (global hosts, then each gathered address), so the §7.6 ranks apply;
  a proptest pins them. The app builds one `RouterPorts` per process (`RealNet` with the ledger, the
  `RouterPortLog` sink, the sweep): the host's wiring hands the sink its one keyed handle on
  `sessions.log` and then starts the sweep; `connect` and a window without its host role start it
  themselves and key their lines from the keystore (`ua_client::append_keyed`, one lock for every
  own append); `on_event` only queues (64, then drop and count) for a writer thread; the exit
  (`router_lifecycle`, `RouterPorts::wind_down`) waits up to 1 s for releases and up to 1 s for the
  lines. Deviations (commit bodies, M1-81): the mapping lives in the gathering task, not
  `LinkInner`; `plan`'s signature; events through the app's mapper, not a `DirectHost` field.
  Residuals: a viewer with no host candidate and nothing gathered sends only `CANDIDATES_DONE` and
  falls back at its punch timeout (settled at B9 by decision M1-87, below); two processes on one `TORNECT_HOME` write
  `sessions.log` through two handles with no lock between them (OPEN row; the unattended connect
  lines already did). Left as NEEDS-DEVICE: the real router run of the sweep and the release, on a
  home with unattended access on (after B12).
- B8 (done 2026-10-28, `e2bf7fda`; ledger rows "Step B8"): `NatBox` in `MemNet` (EIM/ADM/APDM
  mapping, EIF/ADF/APDF filtering, port preservation, hairpin, forwards, the 30 s timeout,
  `translate: false` firewalls, boxes in a row, the fates `NoMapping`/`NatFiltered`/`NoHairpin`,
  `WireRecord.seen_from`, `MemUdp::spoof_as`), `MemStun` (honest, lying, silent), `MemNet::name`,
  `MemMapper` (`Ok`, `Grant(d)`, `Lie(ip)`, `Refuse`, `PermanentOnly`, off; `router_log()`,
  `forwards()`) and `MachineSpec::gateway`; all test-only (`cfg(test)` or `test-support`).
- B9 (done 2026-10-28, `cb0a3284`, `af012e61`, `ac2c8ee2`, `b694627d`, `c8291f30`; ledger rows "Step
  B9", decisions M1-82, M1-83 and M1-87): `ViewerDirect::with_internet` and
  `DirectHost::with_internet` (`cfg(test)`; release builds keep `INTERNET_DIRECT`); the design §12.4
  matrix in `tornect-session` `tests::direct_nat` (23 tests: both FSMs, a 500 ms `LaggedDuplex`,
  both key orders, each row asserting the route or Tor reason, the time from `T0`, the host's
  `PathSummary` and both `CountingEnv` counts), the amplification, spoofed-Initial and
  policy-source rows among them; the decision cells of `direct_path` in both scopes; the
  ten-minute `Grant(120 s)` row at the link (`tornect-net` `link::tests::nat`); the redaction e2e
  through the real mapper against `FakePcp` and `FakeIgd`; and the step B6 residual settled
  (M1-87: a viewer that offered nothing falls back `NO_ADDRESSES` at the gathering budget, and the
  host's network is never touched). Deviations (commit bodies, ledger): the ten minutes at the
  link, not a ten-minute session; the e2e's mapping beside its session, not in its gathering;
  the 1.5 s row's viewer-dials order falls back `Quic` by `T0` + 4.2 s, not `HostSilent` at
  exactly 4.0 s; the `lan_only` viewer's winner is `Prflx`. Its three OPEN rows were settled on
  2026-10-28 (decision M1-82's notes, ledger rows "Step B9: residual, …"): one NAT with two
  subnets is read as the code behaves (the viewer's label stays internet, the host's same-site;
  never relabelled, never inferred from the address class); 20 % loss is stated as a rate (at
  least 3 of 8 seeds direct; measured 4 of 8, the rest `Quic` by 4.2 s or `NoPath` at 4.0 s), the
  real rate measured at B13; the `BYE` racing `TOR_FALLBACK` is fixed (`10d37234`,
  `PathExchange::heard`). C1's wording for the 1.5 s row is in M1-82's notes. Left as
  NEEDS-DEVICE: the matrix between real networks (design §13 rows 3 to 11), with one recipe per
  row in the ledger ("Step B13 recipe: design §13 row N", 2026-10-28).
- B10 (done 2026-10-28, `46339a2c`, `3bfb2670`, `a1b892a8`, `a6b15bbc`; ledger rows "Step B10";
  decisions M1-74, M1-76, M1-84 and M1-85's notes): quality: `Route::Direct`, the direct row of the
  presets (Balanced 1080p30 at 6 Mbit/s, Best performance 720p60 at 4 Mbit/s, Best quality 30 fps
  at 12 Mbit/s or `[media] max_bitrate_kbps`), picked by the host from the claimed path, a 300 ms
  ack window; `direct_loopback_stats` now reads 29.8 fps. Services: the second bidi stream of the
  direct connection (the host's limit is the media stream alone, `HOST_STREAMS` 1, until a host with
  services raises it to `HOST_STREAMS_WITH_SERVICES` 2 on the one connection whose media was claimed),
  bound by `ServicesHost::serve_direct` through
  `DirectHost`'s `SecondStream` hook under its own MAC once the media is claimed on the same path
  by the pinned device; 4 MiB bulk window; priorities media 1, services 0; the host refuses the
  onion services port while the media is direct; the app's `ServicesSlot` (set once the services
  host exists) and the viewer's `run_direct_services` (5 s open bound); the onion stream-count test
  on the Tor route. Deviations (commit bodies, the decisions' notes): `SecondStream::serve` takes
  the peer and the path; the claim check under the registry lock; the late-bound slot; the 5 s
  bound; `services_bind_mac_direct`; the quantizer ranges, window floors and least bitrate of the
  Tor rows; the stream-count test's composition. Left as NEEDS-DEVICE: the direct row and the
  4 MiB window measured on real paths (ledger rows, after B12). `a6b15bbc` fixed a `cargo doc`
  failure `3bfb2670` brought in (a public doc linking a crate-private constant). Review fixes
  (2026-10-28, ledger rows "Step B10 review fix"): the services stream runs on a task of its own and
  its end (services design §6.3 step 5: `Close{code}`, the summary, controls and workers) runs at
  every host end, a kill and a device end included (`49f61bb7`); the viewer's services handle comes
  with the bound media only (`DirectBound`) and a failed bind shuts the link before `TOR_FALLBACK`
  (`6ded0551`); the second stream's credit is given per connection, after the claim, by a host with
  services (`b49474a8`); a kill seen as the port closes still takes the kill's goodbye (`e7c616fc`);
  a viewer whose write fails after the host's end ends as the host's `Close` says (`a7a2b116`).
- B11 (done 2026-10-28, `80543d4e`, `e464d2b7`, `e581196b`; ledger rows "Step B11"; decisions
  M1-81 and M1-84's notes): every Phase B word is written and drawn, picked by `Settings::internet`
  (the constant outside tests) or an `internet` argument, so this build still shows Phase A's and
  B12's flip changes no test. Settings, Connection: the Phase B switch, `DIRECT_HOW_INTERNET`,
  `DIRECT_EXPOSES`, the STUN switch (`SettingsChange::Stun`) and the router switch
  (`SettingsChange::RouterMapping`, all three protocols) with their lines and `PUBLIC_ANYWAY`.
  `Settings::reveals` drives the Privacy line (`NETWORK_LINE_LAN`/`NETWORK_LINE_INTERNET`), the
  consent sheet and the CLI note ("internet address" only for policy `Any` in an internet build;
  `lan_only` stays "local address"); the grant help line, Home's opening note and the viewer's
  no-path reason follow the build. The one-time notice: `general.direct_notice_seen`,
  `Settings::direct_notice_due` read once at the window's start into `Model::direct_notice`, a card
  above the page with the switch and OK (`DirectNoticeSeen`). `host` prints `NOTICE direct
  connections are on: …` after the bootstrap while an accept reveals the IP address; `doctor` has
  the STUN, router and leftover-ports lines (off unless a session would ask; a note when the STUN
  list is not the default). The STUN names' refresh: `RouterPorts::follow_stun` at the start of
  the window, `host` and `connect`, after each bootstrap and each save, restarted only when
  `direct::stun_names` changed (empty in this build, so nothing is looked up). `STUN_LINE` and
  `NETWORK_LINE_INTERNET` carry the same-list condition (a deviation from the design's words; C1
  puts it in M1-81's final text). The two tests the B10 review left (`lan_only` services on the
  link; a second stream while `ServicesSlot` is unset) are written. Left as NEEDS-DEVICE: the
  window's Phase B page, notice and consent line on a desktop after B12 (ledger row).
  Review fixes (2026-10-28, `e171ea28`, `78e797d7`, `4bac2603`, `94d2923f`, `c9e8b2e5`; ledger
  rows "Review of step B11"; decisions M1-81, M1-84 and M1-86's notes): the STUN names'
  refresh no longer starts when a process starts (a config with `tor.bridges = "auto"` reads as
  plain Tor before the bootstrap): `DirectKnobs::tor_known` is false until the first
  `bootstrapped`, `stun_names` is empty and `follow_stun` starts nothing
  until then, and the window (`tor_started`), `host` and `connect` start it through
  `direct::tor_bootstrapped`; `STUN_LINE` says "once Tor is connected". Until the notice's OK the
  window host signs unattended sessions `tor_only` (`TransportKnob::hold_unattended`, read by
  `host_transport`), which covers background mode. The notice card keeps the page's widget ids
  (it takes the prompt's id slot). The placement of the bootstrap calls in `run_host`,
  `run_connect` and the window's Tor arm is by inspection (they need Tor); the gate holds
  whatever the call site. One flake seen once in the full app suite
  (`the_terminal_hosts_services_leave_the_session_without_them`, OPEN row).
- B12 (done 2026-10-28, `3f29a872`, `ab3bea07`, `a4af339f`; ledger rows "Step B12"; decision
  M1-78's note): `INTERNET_DIRECT = true`, flipped once the full MemNet suite and the redaction
  e2e were green on the base `3d8f8b0a` (tornect-net 306 passed, tornect-session 388 passed, the
  23 matrix rows and the e2e among them) and again after the flip (tornect-session 389 passed with
  the new row `this_build_goes_direct_over_the_internet`, which runs the halves as the app builds
  them; the app's tests 880 passed as `tester`). Two tests that pinned the Phase A scope through
  the constant were adapted, keeping what they protect (the commit body). `direct_loopback_stats`
  after the flip reads 29.8 fps, `BindOk` 118 ms after the accept. New: the ignored
  `tornect-net` integration test `live_stun` (design §12.5 Phase B), run on the dev VM. The plan's
  M2 text says Phase B is built (a minimal edit; C1 writes the final text). The leftover flake of
  the B11 review is settled (`3f29a872`: the count was read before the refused stream's task
  ended; 100 runs in four parallel copies clean). Left as NEEDS-DEVICE (ledger rows, recipes):
  the live STUN run, two instances on one VM (`ROUTE tor no-path`, or `direct internet` through
  a hairpinning router, since the review of steps C1 and C2), the bridge demo, the `host`
  `NOTICE` line after a real bootstrap, the B11 review's strace and background-mode checks, the
  B11 desktop row. OPEN:
  the owner's call on the Google and Nextcloud STUN terms (`nat-traversal.md` §2.7; the list is
  unchanged), a blocker with the live STUN run ("Blockers" above).
- B13 (done in this container 2026-10-28; ledger rows "Step B13"): the gnullvm cross-clippy of the
  three crates the flip touched, `tornect-core` on msvc and darwin (ring still stops the crates
  above it there), the licences and `dist` feature-check tests, the ten fuzz targets' clippy with
  `fuzz/Cargo.lock` unchanged, 10-minute uninstrumented stable runs of `stun`, `candidates`,
  `probe`, `framing` and `envelope` (no crash; no coverage feedback, so no evidence: the review
  below replaced them with coverage-guided runs), and `doctor` from a
  gnullvm build under Wine 9.0 with the internet lines (`direct connections: on (local network and
  internet)`). Wine still reads "VPN mode", which with the internet half on would send every
  internet session of a real Windows machine misread that way to Tor: a NEEDS-DEVICE(windows) row
  checks it before design §13 rows 8 and 11. Design §13 rows 3 to 11, 15 and 16 are runnable (one
  summary row points at each recipe). Left: the [VM] and [DEV] runs of those rows, the nightly
  fuzz campaigns, `cargo xtask dist` (this container's proxy refuses archive.torproject.org, so
  lyrebird cannot be fetched); no tag (the design tags `m2a` and `m2`; tags are the owner's).
- Review of steps B12 and B13 (2026-10-28, `ab775a7c`, `53961f16`, `d5b2732f`, `2336b251`; ledger
  rows "Review of steps B12 and B13"; decision M1-81's note): one major, four minor, all
  addressed. The release README in every zip, `README.md` and both plan copies said the internet
  path was off and named the Phase A switch: the README's "Direct connections" now says what an
  accepted peer, a STUN server, the resolver, the router and the ISP learn and how to stay on Tor,
  and an xtask test reads the switch labels and `INTERNET_DIRECT` from source so the README
  cannot drift again (the plan edits are minimal; C1 writes the final text). The fuzz runs are now
  coverage-guided (cargo-fuzz's sancov flags on stable, no ASan): `stun`, `candidates`, `probe`,
  `framing`, `envelope`, `media` and `services`, 10 minutes each, no crash, corpora 161 to 3412
  inputs; the ASan campaigns stay on the dev VM. `live_stun` runs one refresh round first and
  tells a silent server from a name that did not resolve. The STUN list's checks are now the
  "Blockers" at the top of this note. The tautological nine-cell loop in `decide`'s test became a
  check of `decide` against the internet-scope table (fails with the constant off).
- C1 (done 2026-10-28; ledger rows "C1: …" in *Direct connections, the close*): decisions M1-77
  to M1-86 open with their final text ("**Final text (step C1, 2026-10-28).**": numbered items,
  deviations, residuals and what is open), the placeholder and every step's note kept after it as
  history; M1-81's carries the STUN operator split's same-list condition, M1-82's the 1.5 s row
  in the words the B9 leftovers settled. The plan (both copies identical) has its final words: D6,
  §A.4 item 4, the §B.2 diagram's candidates, §B.6's privacy modes and *The direct path* (the
  threat model of design §9.3: a malicious accepted peer, the STUN servers with the same-list
  condition, the resolver, the router and its ledger, a VPN user's physical address, the LAN
  device that spoofs the gateway; §9.4's two signing contexts were already there), the §B.8.4.3
  note, the §B.8.14 M2 row, Part C M2 (the fallback's timing, the close), the release's limits
  ("relayed through Tor (≈ 16 fps cap) unless the two computers can reach each other directly",
  the third parties, NEEDS-DEVICE), the roadmap entry, Part E's direct row and Part G. §B.8.6.4,
  §B.8.11 and §B.8.17 item 7 already said the final thing and were left. `README.md` (privacy
  modes, the M2 row) and the release README's limits follow. Three stale rows of the Phase A
  ledger section were corrected. No release notes file was written: the notes of the next
  pre-release are written at its dist run (`docs/RELEASING.md`) from the zipped README.
- C2 (done 2026-10-28; `9edb4e07`; ledger rows "C2: …"): the security review of the whole
  direct-connection diff (`e9ef4735..` the close; signal, net, session, platform, proto,
  core, the app, the consent copy, the router mapping), judged against design §9.1's invariants
  and the security invariants of `docs/PLAN.md` §B.6 and §B.8: no defect. One coverage gap closed: a view-only
  session bound on the direct path never decodes or injects input
  (`tests::direct_bind::a_view_only_direct_session_never_decodes_or_injects_input`; switching it
  to control makes it fail). The Accept demo on the dev VM is NEEDS-DEVICE with its recipe
  (blocker 3); no tag was made (the design's C2 tags `m2`; tags are the owner's).
- Review of steps C1 and C2 (2026-10-28; ledger rows "Review of steps C1 and C2"; decision M1-82
  item 11): one major, four minor, all addressed. Major: the live recipes (checkpoint A22 part
  (1), step B12 part (1), the B11 review's background-mode check, the Accept demo) expected
  `ROUTE direct lan` from two instances on one VM, after design §12.5; the own-address rule of
  design §7.7 refuses every address of this computer, so two instances on one machine never go
  direct on the site. The rule stays (a reflection guard); the recipes now expect `ROUTE tor
  no-path` there (or `direct internet` through hairpinning routers), the same-site lines moved to
  the two-machine row, and four tests pin it (`tornect-net`: two links on one `MemHost`, on one
  `127.0.0.x`, and on one machine behind a router with and without hairpinning; `tornect-session`:
  the whole session on one machine in both scopes). Minor: the plan's §B.8.4.3 note (the Tor
  fallback as built; nothing gathered before `SESSION_ACCEPT`) and D6 (when same-site candidates
  are offered), the "release README" in §B.6, `README.md`'s privacy bullet (the same-list
  condition, the router), the Phase A close row's dated prefix and `netdev` in the C2 row.
- The feature's final review (2026-10-28; ledger section "Direct connections, the final review";
  decision M1-81's history): five minor findings, three defects, all fixed. (1) `cc985c3c`: the
  ledger loader looped over a list's declared length, so a crafted or corrupt list in
  `<state>/router-ports/` hung the sweep's blocking thread, the exit and `doctor`; a full list
  now stops reading, and a `ledger` fuzz target ran 10 coverage-guided minutes here (12.8 M runs,
  clean; the ASan campaign is the dev VM's). (2) `ce9fb274`: every UPnP delete (a release, a
  sweep, the removal after a cut add) first reads the router's table
  (`GetGenericPortMappingEntry`, at most 32 entries) and deletes only the entry that forwards to
  this computer's address and port as `Tornect`; a router that hides its table still gets a
  release's or a sweep's delete, never the cut add's. `FakeIgd` now keeps a table and answers
  one request at a time. (3) `cdc83520`: in VPN mode a peer's global address passes only when
  `NetEnv::route_source_to` toward it returns the tunnel's source (`RemoteFilter.tunnel_route`;
  `local::remote_filter` takes `Option<RouteLookup>` in place of the `vpn` flag), so a split
  tunnel's excluded prefix gets nothing. The reviewers' alternative of recording residuals was
  not taken for any of the three.
- The closing pass (2026-10-28; ledger section "Direct connections, closing the feature"): the
  whole workspace's gates on `af9d71df` and again on the final code (`cargo xtask verify`, which
  stops at the app's tests under root by design; `cargo test --workspace --no-fail-fast`; the
  app's tests as `tester`, 880 passed; `cargo doc` with `-D warnings`; the Windows cross-clippy of
  the whole workspace), all green. The audit against the design's acceptance items found: (1) the
  step A12 gap of the second unique-local address, which B6 never took up although the B3 entry
  above listed it as B6's: fixed in `446af445` (one ULA offered, `local::MAX_ULA` = 1, a deviation
  from design §7.1's two; `link::tests::offered`; decision M1-78 item (2)); (2) eleven ledger rows
  still OPEN on steps that had run (statuses corrected, evidence unchanged); (3) no
  `docs/DEPENDENCIES.md` row for the fuzz manifest's `tornect-net` path dependency (added).
  Nothing else is left that this container can run: the list is the ledger row "What of design
  `direct` is still not done".

## Gotchas found at this checkpoint

- A fuzz run without coverage instrumentation proves nothing: libFuzzer finds no features, keeps
  no input (`corp: 1/1b`) and never gets past a magic number. Without nightly, build the fuzz
  manifest with cargo-fuzz's flags minus ASan: `RUSTFLAGS="--cfg fuzzing -Cpasses=sancov-module
  -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters
  -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares
  -Cdebug-assertions -Coverflow-checks" CARGO_TARGET_DIR=target cargo build --manifest-path
  fuzz/Cargo.toml --locked --release --target x86_64-unknown-linux-gnu --bin <t>` (the explicit
  `--target` keeps build scripts uninstrumented), then run `target/x86_64-unknown-linux-gnu/
  release/<t> <fresh corpus> <seeds> -max_total_time=600`; about 3 GB of disk, removed after.
- A UPnP release reads the router's table before its delete: a mapping test that pins a whole
  control sequence sees `IgdHeard::MappingEntry { index }` before `DeletePort`, and a `FakeIgd`
  answers one control request at a time, so a slowed `AddPortMapping` (`add_delay`) holds the
  lookups behind it, as a router's single control thread does.
- The release README is shipped in every zip; a change of the direct switch's words or of
  `INTERNET_DIRECT` fails `cargo test -p xtask` until the README follows.

- `cargo xtask verify --no-tests` runs no rustdoc. Run `RUSTDOCFLAGS="-D warnings" cargo doc
  --workspace --no-deps` too: a moved `use` broke an intra-doc link that clippy and the tests did
  not see.
- `tornect-net` logs nothing at all; its counters reach a log only through the session's debug
  lines (`RUST_LOG=tornect_session=debug`).
- rustls logs both certificates at TRACE (`sending certificate`), which are the two device keys:
  never take `rustls` out of `QUIET_TARGETS`.
- The redaction e2e re-runs its own test binary as a child; run the session tests through cargo or
  the built binary, not through a wrapper that changes `current_exe()`.
- The loopback session tests use `127.0.0.20` to `.47`; macOS needs `lo0` aliases for those.
- The mapping tests give each fake router its own `127.0.0.N` from `.40` up (crab_nat always
  sends to port 5351); under Wine they fail (shared loopback port, answers from `127.0.0.1`).
- The app's tests still run as `tester` (copy the binary from `cargo test -p tornect --no-run` to
  `/home/tester`, run with `runuser`, delete it afterwards).
- The QUIC transport lets the viewer open one bidi stream (`HOST_STREAMS` is 1, the media), and two
  only once a host with services raised it on that connection after the claim
  (`Established::allow_second_stream`, since the B10 review fixes): a test that opens one more than
  the limit waits forever, and in paused time that shows as a hang with growing memory, not a
  timeout. Bound such an open with a timeout, as `quic::tests` and `direct_loopback` do.
- `DirectHost` can see the FSM's port close before the kill that caused it (the select's kill branch
  was polled just before the kill): a closed port checks the kill guard first. Races like this show
  only under parallel load; loop a module in four processes (`target/debug/deps/tornect_session-*
  direct_loopback:: --skip a_direct_session_logs_no_address_port_or_key`, the redaction e2e's fake
  routers sit on fixed ports) before calling an end-order test settled.
- A public doc that links a `pub(crate)` item fails `cargo doc -D warnings`
  (`rustdoc::private-intra-doc-links`) while clippy and the tests pass: run the doc build before
  committing (B10 found one, fixed in `a6b15bbc`).
- A dual-stack `MemUdp` refuses a plain IPv4 destination (`InvalidInput`, as the OS does), forged
  sends through `spoof_as` included: give it the v4-mapped form (`direct_nat::forge`).
- The redaction e2e's fake routers sit on `127.0.0.171` (PCP) and `127.0.0.172` (UPnP-IGD), beside
  the loopback session's `127.0.0.20` to `.47` and the mapping tests' `.40` up; macOS needs `lo0`
  aliases for them too.
- `pkill -f <pattern>` with a pattern from the running command line also kills the shell that runs
  it: stop a hung test binary by its PID.
- `cargo test -p <crate>` resolves features for that package alone (no `test-support` from the
  other crates' dev-dependencies, Arti's features unified differently), so it builds its own copy
  of the crate and of what sits below it beside the workspace's: on this container's disk each
  such run costs about 1 GB. Run the workspace's tests for the record, and delete a per-package
  test binary (`target/debug/deps/<crate>-<hash>`) once its run is pasted.
