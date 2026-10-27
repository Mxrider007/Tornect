# M2 state: direct connections, Phase A (interim hand-off, 2026-10-27)

Phase A of design `direct` (revision 4, `/mnt/project-files/designs/direct.md`), LAN-direct sessions
with Tor kept as the fallback, is implemented: steps A1 to A21 and the in-container half of
checkpoint A22. **`m2a` is not tagged.** It waits for evidence that only the dev VM and real
machines can give (the list below); the ledger rows for it are in `docs/VERIFICATION.md` under
"Direct connections, Phase A", each with its recipe. Phase B (internet direct, steps B1 to B13)
is under way: B1 to B3 are done (2026-10-27; "OPEN, owned by Phase B steps" below).

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

Seventy-odd commits from `34e5bfbd` (A1, the pins) to the docs commit of checkpoint A22, built in
the design's §15 order: A1 pins and decision rows M1-77 to M1-86; A2/A3 the cancel-safe channel;
A4 the signal wire (`CANDIDATES`, `CANDIDATES_DONE`, `TOR_FALLBACK`, `dir1`); A5/A6 the path seam
and the transport knob; A7 telemetry quiet targets and the address classes and filters; A8 the
session socket (`QuietUdp`, `PunchSocket`); A9 the pinned QUIC; A10/A11 probes and the checklist;
A12/A13 `DirectLink`, `LoopbackNet`, `MemNet`; A14/A15 `BindProof` and the direct bind; A16
`DirectHost`; A17 `choose_path`; A18/A19 the binaries; A20/A21 the window, the switch and the
consent copy; each followed by its ledger commit and, for A9, A14/A15, A17 and A18/A19, a security
review and its fixes. `git log --oneline 34e5bfbd^..HEAD` lists them.

Checkpoint A22 (this session, base `6a4bc7c9`):

- `68df1347` fix(core): `punch_timeout_ms` must be 1000 to 10000 and a fixed `direct_port` 1024 or
  above (`Config::validate`).
- `5b4c6921` test(fuzz): `to_wire`/`from_wire` moved into `direct/wire.rs`, which the `candidates`
  target compiles through `#[path]` and drives into `RemoteFilter::admit`.
- `4286c96d` feat(xtask): `dist` refuses a release graph that enables `tornect-net`'s
  `test-support`.
- `45f49a35` test(session): whole direct sessions on loopback sockets, the redaction e2e and
  `direct_loopback_stats` (`quinn` became a dev-dependency of tornect-session for the raw send).
- `4f82c0fb` fix(session): a doc link the wire move broke (only rustdoc saw it).
- `cea42a1c` feat(session): the link's counters at debug (`direct path open` on the viewer,
  `direct link closed` on the host) so design §13 rows 2 and 11 can be read off a live session.
- the docs commit: decision notes on M1-79, M1-82, M1-83, the ledger rows, this note.

The security review of the Phase A diff found no defect (ledger row "Checkpoint A22: the security
review of the Phase A diff" lists what was judged).

The final security and correctness reviews of the whole Phase A diff (fixes after `d6adb5a4`;
ledger rows "Final review: …"):

- `8e15f2d4` fix(session): an onion `Bind` is told `TRANSPORT` only after its MAC verified.
- `3f68da92` fix(session): a kill lets live direct media end through its teardown (within
  `DIRECT_DRAIN`) before the link closes.
- `83df7047` fix(signal): `departure` reads one byte past an early frame, so B04 holds again for a
  requester that sent one frame and left.
- `6c96c327` fix(signal): the viewer's `ping` queues at most a session's worth of host path frames.
- `82b539a0` docs(net): the session socket's port is not exclusive on Windows or macOS
  (`SO_EXCLUSIVEADDRUSE` not set; device check added to §13 rows 12 and 13).
- `dd76eadf` docs: decisions cited by their M1 rows.
- the docs commit: ledger rows, the B04 and A2 residual, decision notes on M1-79 and M1-80.

## Before `m2a` (all [VM] or device; recipes in the ledger)

1. The live Phase A demo on the dev VM (design §12.5): `ROUTE direct lan`, `PATH host`, `MEDIA`,
   `SESSION ROUTE … lan`, `--tor-only`, `paranoid`, `--no-video`, the `ss -uanp` socket check and
   the `sessions.log` lines. Row "Checkpoint A22: the live Phase A demo on the dev VM".
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
the row "Step A15: the direct bind between two real machines", `LoopbackNet` and the loopback link
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
- B2 (done 2026-10-27, `322fda87`): the Binding codec (`tornect_net::stun`, the bare 20-byte
  request, `parse_response` with the RFC 8489 §6.3.3 discard rule), all four RFC 5769 vectors
  transcribed and recomputed, the `stun` fuzz target with its seeds. Left from it: the 10-minute
  campaign on the dev VM (NEEDS-DEVICE row, recipe in the ledger and in the target's header).
- B3 (done 2026-10-27, `a6cf881f`, `9f04aae2`, `b88a7048`): the four-operator default list, its
  migration and its bounds (`tornect-core` config), `stun::partition`, `gather::ask_stun` (random
  first server, a second at 750 ms of another operator where there is one, RTO 500 ms, at most 2
  servers and 4 requests in the 1500 ms budget, replies only from the address asked under its
  transaction ID), `gather::stun_base` (a CGNAT base asks), `StunDns` with `RealNet::resolve`
  cache-first and `RealNet::prefetch`, fake STUN servers on loopback. Nothing calls them yet. Left
  for B6: the link's gathering task reading `tees.stun` and calling `ask_stun` with this role's
  part, `stun_base` combined with the scope, `enable_stun` and the mapping's head start, the
  `DirectParams`/`DirectOptions` STUN fields, and the second ULA design gap. Left for B11/B12: the
  app's `RealNet::prefetch` call, with a list that is empty whenever STUN may not run (design
  §5.3: `INTERNET_DIRECT`, policy `Any`, `enable_stun`, not bridged).
- B2/B3 review fixes (2026-10-27, `d59f0c15`, `25e4161f`, `f8e7bea3`, `d7fa045c`; ledger rows
  "Review of steps B2 and B3", decision M1-81's review note): `RealNet::resolve` looks a name up
  at session time only while `StunDns::refreshed()` is false (no round since the cache was made or
  cleared); after a round a miss is `NotFound` at once. The operator split is only disjoint when
  both computers use the same list (docs and a residual test). In VPN mode `ask_stun` asks a server
  only when `NetEnv::route_source_to(server)` is the tunnel's source (`StunAsk::tunnel`).
  `fuzz/Cargo.lock` is complete again. Owed by later steps: B6 passes
  `tunnel: vpn.then_some(base)`; B11 restarts `prefetch` on every settings save and every change of
  the bridge state (a cleared cache stays cold, and a newly listed name is answered only after the
  next round), words `STUN_LINE` with "when both computers use the same list" (and may add a doctor
  note when the list is not the default); C1 puts the same-list condition into M1-81's final text
  and the plan's threat model, and §13 rows 10/11 (B13) include the split-tunnel case whose recipe
  is in the ledger.
- B4/B5: router mapping (UPnP, PCP, NAT-PMP) as `RealMapper` in place of `NoMapper`, the `router_port` ledger sweep.
- B7/B8: the internet-scope ranks in `MemNet`; `NatBox`, `MemStun`, `MemMapper`.
- B9: the NAT matrix on `MemNet`; the redaction e2e with `FakeIgd` and `FakePcp`.
- B10: `MediaLimits::encoder_direct` (a direct session still encodes with the Tor preset's table:
  `direct_loopback_stats` shows 15 fps), the `SecondStream` hook (services on a direct session
  still go over the onion service) and the onion stream-count test.
- B11: the Phase B copy and settings (STUN, router mapping).
- B12: `INTERNET_DIRECT = true`.
- B13: the internet checkpoint, the `stun` fuzz target, the device rows 3 to 11, 15 and 16
  (row 16, measured punch success, already reads the Phase A runs), tag `m2b`.
- C1: the final text of decision rows M1-77 to M1-86 (still placeholders with step notes) and of
  the plan: `docs/PLAN.md` describes Phase A since the Phase A close (Part C M2 amended, §B.2,
  §B.6, §B.8.6.4, §B.8.17 item 7, Parts E and G), in words C1 replaces with the final ones.
- C2: the security-reviewer pass over the whole feature, the Accept demo, tag `m2`.

## Gotchas found at this checkpoint

- `cargo xtask verify --no-tests` runs no rustdoc. Run `RUSTDOCFLAGS="-D warnings" cargo doc
  --workspace --no-deps` too: a moved `use` broke an intra-doc link that clippy and the tests did
  not see.
- `tornect-net` logs nothing at all; its counters reach a log only through the session's debug
  lines (`RUST_LOG=tornect_session=debug`).
- rustls logs both certificates at TRACE (`sending certificate`), which are the two device keys:
  never take `rustls` out of `QUIET_TARGETS`.
- The redaction e2e re-runs its own test binary as a child; run the session tests through cargo or
  the built binary, not through a wrapper that changes `current_exe()`.
- The loopback session tests use `127.0.0.20` to `.41`; macOS needs `lo0` aliases for those.
- The app's tests still run as `tester` (copy the binary from `cargo test -p tornect --no-run` to
  `/home/tester`, run with `runuser`, delete it afterwards).
