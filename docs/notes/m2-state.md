# M2 state: direct connections, Phase A (interim hand-off, 2026-10-27)

Phase A of design `direct` (revision 4, `/mnt/project-files/designs/direct.md`), LAN-direct sessions
with Tor kept as the fallback, is implemented: steps A1 to A21 and the in-container half of
checkpoint A22. **`m2a` is not tagged.** It waits for evidence that only the dev VM and real
machines can give (the list below); the ledger rows for it are in `docs/VERIFICATION.md` under
"Direct connections, Phase A", each with its recipe. Phase B (internet direct, steps B1 to B13)
has not started.

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
and `WSAECONNRESET`, `doctor`, the 1 s interface read), row 14 (roaming), the two-machine run of
the row "Step A15: the direct bind between two real machines", `LoopbackNet` and the loopback link
tests on macOS and Windows, msvc and darwin builds of the crates above ring (only `tornect-core`
and the crates below ring check here).

## OPEN, owned by Phase B steps

- B3/B6: server-reflexive candidates (a CGNAT-only computer), the second ULA design gap (B6).
- B4/B5: router mapping (UPnP, PCP, NAT-PMP), `default_gateway_v4`, the `router_port` ledger sweep.
- B7: the internet-scope ranks in `MemNet`.
- B9: the NAT matrix on `MemNet`; the redaction e2e with `FakeIgd` and `FakePcp`.
- B10: `MediaLimits::encoder_direct` (a direct session still encodes with the Tor preset's table:
  `direct_loopback_stats` shows 15 fps) and the `SecondStream` hook.
- B11: the Phase B copy and settings (STUN, router mapping).
- B13: the internet checkpoint, the `stun` fuzz target, tag `m2b`.
- C1: the final text of decision rows M1-77 to M1-86 (still placeholders with step notes).

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
